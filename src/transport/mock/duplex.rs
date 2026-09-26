// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Concurrent scenarios between a real client and server on bounded byte pipes.
//! Gates let tests wait for I/O to block before injecting faults or reconnecting.
//! Scripted clock advances exercise deadline recovery without closing the stream.

use super::self_attestation;
use crate::transport::{Client, Closer, Error, Event, Read, Sender, Server, Stream, Write};
use darkbio_clock::sync::{Condvar, Mutex, MutexGuard};
use darkbio_clock::{Clock, TestClock};
use darkbio_crypto::xdsa;
use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Clock budget for deliberately stalled output.
const FAULT_TIMEOUT: Duration = Duration::from_millis(250);

/// Budget for ordinary output during the concurrent scenarios.
const WRITE_TIMEOUT: Duration = Duration::from_secs(2);

/// Non-default handshake budget advanced by the scenario driver.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

/// Enough space for reset and HostHello before the client starts reading.
const HANDSHAKE_CAPACITY: usize = 64 * 1024;

/// One bounded concurrency or timeout scenario, independently repeatable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum Scenario {
    // Handshake failures and recovery.
    /// Fail reset output or the following reply read, then retry on the same
    /// stream. Each phase runs sequentially without a companion operation.
    FailedPrelude { read: bool },
    /// Fail ArkHello or HostAck output, then retry. Lost replies must expire
    /// the client's handshake without another fault to rescue its read.
    HandshakeFailure {
        ack: bool,
        flush: bool,
        timeout: bool,
    },
    /// Alternate read and write failures across reconnect attempts.
    RepeatedAttempts(u8),
    /// Retry an abandoned handshake while its old ArkHello is still blocked,
    /// draining that reply so the server can consume the replacement hello.
    AbandonedHello,
    /// Reset without Hello, or Hello without ACK, must expire and allow retry.
    SilentHandshake { ack: bool },
    /// Continuous resets on the server or junk on the client must not refresh
    /// the handshake deadline. Stop the noise and recover on the same stream.
    HandshakeNoise { server: bool },

    // Established sessions and reconnects.
    /// Reconnect while server output is blocked, optionally with client output
    /// blocked too. Old writes may time out before the sequential handshake.
    Reconnect { both_directions: bool },
    /// Drain at least 33 legitimate old messages before a new handshake.
    Backlog(u8),
    /// A server message times out during its write or flush, then the stream recovers.
    ServerTimeout { flush: bool },

    /// Either peer closes while both are reading, during a handshake or session.
    Shutdown { handshake: bool, server: bool },
}

/// Adapter operation addressed by a test gate or a one-shot fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Operation {
    /// Read from the pipe's queued input.
    Read,
    /// Append bytes to its bounded output queue.
    Write,
    /// Flush after an output buffer has been queued.
    Flush,
}

impl Operation {
    /// Index of the operation's gate and waiting count.
    fn index(self) -> usize {
        match self {
            Self::Read => 0,
            Self::Write => 1,
            Self::Flush => 2,
        }
    }
}

/// Failure injected once the selected operation becomes eligible.
#[derive(Clone, Copy, Debug)]
pub(crate) enum FaultKind {
    /// Return the specified error without consuming bytes.
    Error(io::ErrorKind),
    /// Wait until the supplied absolute deadline and return TimedOut.
    Timeout,
}

/// A one-shot fault activated after a given number of successful flushes.
#[derive(Clone, Copy, Debug)]
struct Fault {
    operation: Operation,
    after_flushes: usize,
    kind: FaultKind,
}

/// Queued bytes, gates and observations of one bounded unidirectional pipe.
#[derive(Debug, Default)]
struct State {
    bytes: VecDeque<u8>,
    closed: bool,
    paused: [bool; 3],
    waiting: [usize; 3],
    flushes: usize,
    delimiters: usize,
    read_deadline: Option<Instant>, // Last installed deadline, observed while the read is blocked
    read_error: Option<io::ErrorKind>, // One failed deadline installation, before any bytes are read
    faults: VecDeque<Fault>,
    #[cfg(test)]
    fault_waiters: usize, // Scenario threads waiting for the armed faults to be taken
}

/// Bounded byte pipe with deadline-aware I/O.
/// Blocked calls release the state lock, so closing can acquire it and wake them.
#[derive(Debug)]
pub(crate) struct Pipe {
    /// Clock used by every adapter and gate on this pipe.
    clock: Clock,
    capacity: usize,
    state: Mutex<State>,
    changed: Condvar,
}

impl Pipe {
    /// Creates a bounded queue with no pending operations or faults.
    pub(crate) fn new(capacity: usize, clock: &Clock) -> Arc<Self> {
        Arc::new(Self {
            clock: clock.clone(),
            capacity,
            state: Mutex::new(State::default()),
            changed: Condvar::new(clock),
        })
    }

    /// Permanently closes this test adapter, waking every blocked call.
    pub(crate) fn close(&self) {
        self.state.lock().unwrap().closed = true;
        self.changed.notify_all();
    }

    /// Holds or releases the selected operation independently of buffer capacity.
    pub(crate) fn pause(&self, operation: Operation, paused: bool) {
        self.state.lock().unwrap().paused[operation.index()] = paused;
        self.changed.notify_all();
    }

    /// Makes the next `set_read_deadline()` fail. Unlike a timeout from `read()`,
    /// this error is returned immediately by the framer without retrying.
    pub(crate) fn fail_read_deadline(&self, error: io::ErrorKind) {
        self.state.lock().unwrap().read_error = Some(error);
    }

    /// Arms a one-shot fault and wakes a matching call already waiting in I/O.
    pub(crate) fn fault(&self, operation: Operation, after_flushes: usize, kind: FaultKind) {
        self.state.lock().unwrap().faults.push_back(Fault {
            operation,
            after_flushes,
            kind,
        });
        self.changed.notify_all();
    }

    /// Waits for an adapter call to block, so scenarios depend on an observed
    /// operation rather than a scheduling delay.
    pub(crate) fn wait_blocked(&self, operation: Operation) {
        let mut state = self.state.lock().unwrap();
        while state.waiting[operation.index()] == 0 {
            state = self.changed.wait(state).unwrap();
        }
    }

    /// Waits until adapter calls have taken every armed fault, so a scenario
    /// can move time only after the failure it injected has happened.
    pub(crate) fn wait_faults_taken(&self) {
        // Let tests observe the wait before it starts
        let mut state = self.state.lock().unwrap();
        #[cfg(test)]
        {
            state.fault_waiters += 1;
            self.changed.notify_all();
        }

        // Wait for adapter calls to take every armed fault
        while !state.faults.is_empty() {
            state = self.changed.wait(state).unwrap();
        }
        #[cfg(test)]
        {
            state.fault_waiters -= 1;
        }
    }

    /// Waits until a scenario waits for the armed faults to be taken, or until
    /// the clock reaches `deadline`. Returns whether that waiter came first.
    #[cfg(test)]
    pub(crate) fn wait_fault_waiter(&self, deadline: Instant) -> bool {
        let mut state = self.state.lock().unwrap();
        while state.fault_waiters == 0 {
            let (next, timeout) = self.changed.wait_deadline(state, deadline).unwrap();
            state = next;
            if timeout.timed_out() {
                return state.fault_waiters != 0;
            }
        }
        true
    }

    /// Waits for the reader to consume a complete scripted batch of bytes.
    fn wait_drained(&self) {
        let mut state = self.state.lock().unwrap();
        while !state.bytes.is_empty() {
            state = self.changed.wait(state).unwrap();
        }
    }

    /// Waits once and tracks the operation in the blocked-call count.
    fn wait<'a>(
        &self,
        mut state: MutexGuard<'a, State>,
        operation: Operation,
        deadline: Option<Instant>,
    ) -> io::Result<MutexGuard<'a, State>> {
        state.waiting[operation.index()] += 1;
        self.changed.notify_all();
        let (mut state, timed_out) = match deadline {
            Some(deadline) => {
                let (state, timeout) = self.changed.wait_deadline(state, deadline).unwrap();
                (state, timeout.timed_out())
            }
            None => (self.changed.wait(state).unwrap(), false),
        };
        state.waiting[operation.index()] -= 1;
        self.changed.notify_all();
        if timed_out && !state.closed {
            Err(io::ErrorKind::TimedOut.into())
        } else {
            Ok(state)
        }
    }

    /// Consumes a matching fault, including one targeting a call already paused.
    fn take_fault(state: &mut State, operation: Operation) -> Option<FaultKind> {
        let index = state.faults.iter().position(|fault| {
            fault.operation == operation && fault.after_flushes <= state.flushes
        })?;
        Some(state.faults.remove(index).unwrap().kind)
    }

    /// Returns an injected error or waits for its deadline to expire.
    /// Closing the pipe wakes even an intentionally stalled operation.
    fn fail(
        &self,
        mut state: MutexGuard<'_, State>,
        operation: Operation,
        kind: FaultKind,
        deadline: Option<Instant>,
    ) -> io::Result<usize> {
        // Wake scenarios waiting for the fault to be taken
        self.changed.notify_all();
        match kind {
            FaultKind::Error(kind) => Err(kind.into()),
            FaultKind::Timeout => loop {
                if state.closed {
                    return Err(io::ErrorKind::BrokenPipe.into());
                }
                if deadline.is_some_and(|deadline| self.clock.now() >= deadline) {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                state = self.wait(state, operation, deadline)?;
            },
        }
    }
}

/// A cloneable endpoint used as either the reader or writer of its pipe.
/// Each clone configures its own deadlines, independently of the shared bytes.
#[derive(Clone, Debug)]
pub(crate) struct Adapter {
    pipe: Arc<Pipe>,
    read_deadline: Option<Instant>,
    write_deadline: Instant,
}

impl Adapter {
    /// Creates an endpoint whose I/O deadlines must be configured before use.
    pub(crate) fn new(pipe: Arc<Pipe>) -> Self {
        let now = pipe.clock.now();
        Self {
            pipe,
            read_deadline: None,
            write_deadline: now,
        }
    }
}

impl Read for Adapter {
    fn clock(&self) -> Clock {
        self.pipe.clock.clone()
    }

    fn set_read_deadline(&mut self, deadline: Option<Instant>) -> io::Result<()> {
        self.read_deadline = deadline;
        let mut state = self.pipe.state.lock().unwrap();
        state.read_deadline = deadline;
        if let Some(error) = state.read_error.take() {
            return Err(error.into());
        }
        Ok(())
    }
}

impl io::Read for Adapter {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let deadline = self.read_deadline;
        let mut state = self.pipe.state.lock().unwrap();
        loop {
            if deadline.is_some_and(|deadline| self.pipe.clock.now() >= deadline) {
                return Err(io::ErrorKind::TimedOut.into());
            }
            if state.closed {
                return Ok(0);
            }
            if let Some(fault) = Pipe::take_fault(&mut state, Operation::Read) {
                return self.pipe.fail(state, Operation::Read, fault, deadline);
            }
            if !state.paused[Operation::Read.index()] && !state.bytes.is_empty() {
                let len = buf.len().min(state.bytes.len());
                for byte in &mut buf[..len] {
                    *byte = state.bytes.pop_front().unwrap();
                }
                self.pipe.changed.notify_all();
                return Ok(len);
            }
            state = self.pipe.wait(state, Operation::Read, deadline)?;
        }
    }
}

impl Write for Adapter {
    fn clock(&self) -> Clock {
        self.pipe.clock.clone()
    }

    fn set_write_deadline(&mut self, deadline: Instant) -> io::Result<()> {
        self.write_deadline = deadline;
        Ok(())
    }
}

impl io::Write for Adapter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let deadline = self.write_deadline;
        let mut state = self.pipe.state.lock().unwrap();
        loop {
            if self.pipe.clock.now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            if state.closed {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            if let Some(fault) = Pipe::take_fault(&mut state, Operation::Write) {
                return self
                    .pipe
                    .fail(state, Operation::Write, fault, Some(deadline));
            }
            if !state.paused[Operation::Write.index()] && state.bytes.len() < self.pipe.capacity {
                let len = bytes.len().min(self.pipe.capacity - state.bytes.len());
                state.bytes.extend(&bytes[..len]);
                state.delimiters += bytes[..len].iter().filter(|byte| **byte == 0).count();
                self.pipe.changed.notify_all();
                return Ok(len);
            }
            state = self.pipe.wait(state, Operation::Write, Some(deadline))?;
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let deadline = self.write_deadline;
        let mut state = self.pipe.state.lock().unwrap();
        loop {
            if self.pipe.clock.now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            if state.closed {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            if let Some(fault) = Pipe::take_fault(&mut state, Operation::Flush) {
                return self
                    .pipe
                    .fail(state, Operation::Flush, fault, Some(deadline))
                    .map(|_| ());
            }
            if !state.paused[Operation::Flush.index()] {
                state.flushes += 1;
                return Ok(());
            }
            state = self.pipe.wait(state, Operation::Flush, Some(deadline))?;
        }
    }
}

/// Two real transport peers and the cleanup needed if a scenario assertion fails.
struct Peers {
    /// Sole driver of both peers' monotonic and wall times.
    tester: TestClock,
    client: Client<Adapter, Adapter>,
    identity: xdsa::PublicKey,
    incoming: Arc<Pipe>,
    outgoing: Arc<Pipe>,
    events: mpsc::Receiver<Result<Event<Adapter>, Error>>,
    closer: Closer,
    server_closer: Closer,
    server: Option<JoinHandle<()>>,
    senders: Vec<JoinHandle<()>>,
}

impl Peers {
    /// Starts a server that keeps consuming its stream after recoverable errors.
    fn new(outgoing_capacity: usize, incoming_capacity: usize, write_timeout: Duration) -> Self {
        // Connect both gated pipes on one paused clock
        let tester = crate::transport::testing::test_clock();
        let incoming = Pipe::new(incoming_capacity, &tester.clock());
        let outgoing = Pipe::new(outgoing_capacity, &tester.clock());
        let stream = |reader: &Arc<Pipe>, writer: &Arc<Pipe>| {
            Stream::new(
                Adapter::new(reader.clone()),
                Adapter::new(writer.clone()),
                {
                    let incoming = incoming.clone();
                    let outgoing = outgoing.clone();
                    move || {
                        incoming.close();
                        outgoing.close();
                    }
                },
            )
            .set_write_timeout(write_timeout)
        };
        let client_stream = stream(&incoming, &outgoing);
        let server_stream = stream(&outgoing, &incoming);
        let closer = client_stream.closer();
        let server_closer = server_stream.closer();

        // Run the server reader until physical shutdown ends the stream
        let signer = xdsa::SecretKey::generate();
        let identity = signer.public_key();
        let attestation = self_attestation(&signer);
        let (sent, events) = mpsc::channel();
        let server = thread::spawn(move || {
            let mut server = Server::new(server_stream, signer, attestation)
                .set_handshake_timeout(HANDSHAKE_TIMEOUT);
            loop {
                let result = server.recv();
                if matches!(result, Err(Error::Terminated)) {
                    break;
                }
                if sent.send(result).is_err() {
                    break;
                }
            }
        });

        // Retain the sole clock driver and the peers' cleanup handles
        Self {
            tester,
            client: Client::new(client_stream).set_handshake_timeout(HANDSHAKE_TIMEOUT),
            identity,
            incoming,
            outgoing,
            events,
            closer,
            server_closer,
            server: Some(server),
            senders: Vec::new(),
        }
    }

    /// Connects and waits for the server's new connection event.
    /// Discards preceding disconnection and message events from the old session.
    fn connect(&mut self) -> (Sender<Adapter>, Sender<Adapter>) {
        let (client, _) = self.client.connect(&self.identity).unwrap();
        loop {
            match self.event() {
                Event::Connected(server) => return (client, server),
                Event::Disconnected | Event::Message(_) => {}
            }
        }
    }

    /// Retries after a failed attempt and verifies fresh traffic and old-sender
    /// rejection. An already delivered ACK may leave an older Connected queued.
    fn recover(&mut self, old: &[Sender<Adapter>]) {
        let (client, _) = self.client.connect(&self.identity).unwrap();
        for sender in old {
            assert!(matches!(
                sender.send(b"old"),
                Err(Error::EncryptionFailed(_))
            ));
        }
        client.send(b"fresh ping").unwrap();
        let mut server = None;
        loop {
            match self.events.recv().unwrap() {
                Ok(Event::Connected(sender)) => server = Some(sender),
                Ok(Event::Message(bytes)) => {
                    assert_eq!(bytes, b"fresh ping");
                    break;
                }
                Ok(Event::Disconnected) | Err(Error::RecvFailed(_) | Error::SendFailed(_)) => {}
                event => panic!("unexpected server event: {event:?}"),
            }
        }
        let server = server.expect("fresh connection event before fresh message");
        self.round_trip(&client, &server);
    }

    /// Receives one server event, requiring transport success.
    fn event(&self) -> Event<Adapter> {
        self.events.recv().unwrap().unwrap()
    }

    /// Sends in the background and optionally releases server input afterwards.
    /// This can make a blocked client send wait for a server send to finish.
    fn send(
        &mut self,
        sender: Sender<Adapter>,
        bytes: Vec<u8>,
        release_input: bool,
    ) -> mpsc::Receiver<Result<(), Error>> {
        let (sent, result) = mpsc::channel();
        let outgoing = self.outgoing.clone();
        self.senders.push(thread::spawn(move || {
            let result = sender.send(&bytes);
            if release_input {
                outgoing.pause(Operation::Read, false);
            }
            let _ = sent.send(result);
        }));
        result
    }

    /// Proves that both directions work after recovery and neither stream was closed.
    fn round_trip(&mut self, client: &Sender<Adapter>, server: &Sender<Adapter>) {
        client.send(b"ping").unwrap();
        assert!(matches!(self.event(), Event::Message(bytes) if bytes == b"ping"));
        server.send(b"pong").unwrap();
        assert_eq!(self.client.recv().unwrap(), b"pong");
        assert!(!self.incoming.state.lock().unwrap().closed);
        assert!(!self.outgoing.state.lock().unwrap().closed);
    }

    /// Fails one handshake phase after it reaches adapter I/O. Read failures
    /// happen after reset/Hello complete; write failures must return without
    /// starting a read. Releasing the phase leaves the stream reusable.
    fn fail_prelude(&mut self, read: bool) {
        let pipe = if read {
            self.incoming.clone()
        } else {
            self.outgoing.clone()
        };
        let operation = if read {
            Operation::Read
        } else {
            Operation::Write
        };
        pipe.pause(operation, true);
        let client = &mut self.client;
        let identity = &self.identity;
        let result = thread::scope(|scope| {
            let connecting = scope.spawn(|| client.connect(identity));
            pipe.wait_blocked(operation);
            pipe.fault(operation, 0, FaultKind::Error(io::ErrorKind::Other));
            pipe.pause(operation, false);
            connecting.join().unwrap()
        });
        match result {
            Err(Error::RecvFailed(err)) if read => assert_eq!(err.kind(), io::ErrorKind::Other),
            Err(Error::SendFailed(err)) if !read => assert_eq!(err.kind(), io::ErrorKind::Other),
            result => panic!("unexpected prelude failure: {:?}", result.map(|_| ())),
        }
        assert!(!self.incoming.state.lock().unwrap().closed);
        assert!(!self.outgoing.state.lock().unwrap().closed);
    }
}

impl Drop for Peers {
    /// Closes the adapters before joining workers, even after an assertion fails.
    /// This keeps blocked peers and helper threads from being left behind.
    fn drop(&mut self) {
        self.closer.close();
        self.server_closer.close();
        for sender in self.senders.drain(..) {
            let result = sender.join();
            if !thread::panicking() {
                result.unwrap();
            }
        }
        let result = self.server.take().unwrap().join();
        if !thread::panicking() {
            result.unwrap();
        }
    }
}

/// Runs one concurrency scenario and checks progress, errors and session isolation.
/// Recovery must leave the same stream usable. Any mismatch panics.
pub fn run(scenario: Scenario) {
    #[cfg(feature = "fuzz")]
    super::seed::seed(super::seed::TRANSPORT_DUPLEX, &[scenario]);

    match scenario {
        Scenario::FailedPrelude { read } => {
            let mut peers = Peers::new(HANDSHAKE_CAPACITY, 64, FAULT_TIMEOUT);
            peers.fail_prelude(read);
            let (client, server) = peers.connect();
            peers.round_trip(&client, &server);
        }
        Scenario::HandshakeFailure {
            ack,
            flush,
            timeout,
        } => {
            let mut peers = Peers::new(HANDSHAKE_CAPACITY, HANDSHAKE_CAPACITY, FAULT_TIMEOUT);
            let (client, server) = peers.connect();
            let mut old = vec![client, server];
            let operation = if flush {
                Operation::Flush
            } else {
                Operation::Write
            };
            let pipe = if ack {
                peers.outgoing.clone()
            } else {
                peers.incoming.clone()
            };
            let after_flushes = pipe.state.lock().unwrap().flushes + if ack { 2 } else { 0 };
            let kind = if timeout {
                FaultKind::Timeout
            } else {
                FaultKind::Error(io::ErrorKind::Other)
            };
            pipe.fault(operation, after_flushes, kind);
            let lost_reply = !ack && (timeout || !flush);
            if lost_reply {
                // Model a reply the client cannot read, even if all bytes were
                // accepted before flush failed. Only its own deadline releases it.
                peers.incoming.pause(Operation::Read, true);
            }
            // Let the selected fault park before advancing its output deadline
            let started = peers.tester.clock().now();
            let first = thread::scope(|scope| {
                let connecting = scope.spawn(|| peers.client.connect(&peers.identity));
                if timeout {
                    pipe.wait_blocked(operation);
                    peers.tester.wait_blocked(2);
                    peers.tester.advance(FAULT_TIMEOUT);
                }
                if !ack {
                    // Settle failed server output before expiring the client's own read
                    assert!(matches!(
                        peers.events.recv().unwrap().unwrap(),
                        Event::Disconnected
                    ));
                    let expected = if timeout {
                        io::ErrorKind::TimedOut
                    } else {
                        io::ErrorKind::Other
                    };
                    assert!(
                        matches!(peers.events.recv().unwrap(), Err(Error::SendFailed(err)) if err.kind() == expected)
                    );
                    if lost_reply {
                        peers.incoming.wait_blocked(Operation::Read);
                        peers.tester.wait_blocked(2);
                        peers.tester.advance_to(started + HANDSHAKE_TIMEOUT);
                    }
                }
                connecting.join().unwrap()
            });
            if ack {
                let expected = if timeout {
                    io::ErrorKind::TimedOut
                } else {
                    io::ErrorKind::Other
                };
                assert!(matches!(first, Err(Error::SendFailed(ref err)) if err.kind() == expected));
            } else if timeout || !flush {
                assert!(
                    matches!(first, Err(Error::RecvFailed(ref err)) if err.kind() == io::ErrorKind::TimedOut)
                );
            } else {
                // ArkHello can arrive before its flush fails; local connect
                // success does not imply that the server accepted the ACK.
                assert!(
                    first.is_ok()
                        || matches!(first, Err(Error::RecvFailed(ref err)) if err.kind() == io::ErrorKind::TimedOut)
                );
            }
            if let Ok((sender, _)) = first {
                old.push(sender);
            }
            if ack {
                assert!(matches!(peers.event(), Event::Disconnected));
            }
            peers.incoming.pause(Operation::Read, false);
            peers.recover(&old);
        }
        Scenario::RepeatedAttempts(count) => {
            let mut peers = Peers::new(HANDSHAKE_CAPACITY, 64, FAULT_TIMEOUT);
            for attempt in 0..2 + usize::from(count % 3) {
                peers.fail_prelude(attempt % 2 == 0);
                let (client, server) = peers.connect();
                peers.round_trip(&client, &server);
            }
        }
        Scenario::AbandonedHello => {
            let mut peers = Peers::new(HANDSHAKE_CAPACITY, 64, WRITE_TIMEOUT);
            peers.incoming.pause(Operation::Read, true);
            let client = &mut peers.client;
            let identity = &peers.identity;
            let incoming = &peers.incoming;
            thread::scope(|scope| {
                let connecting = scope.spawn(|| client.connect(identity));
                incoming.wait_blocked(Operation::Write);
                incoming.fault(Operation::Read, 0, FaultKind::Error(io::ErrorKind::Other));
                incoming.pause(Operation::Read, false);
                assert!(matches!(
                    connecting.join().unwrap(),
                    Err(Error::RecvFailed(err)) if err.kind() == io::ErrorKind::Other
                ));
            });

            // The server is still sending ArkHello to the abandoned client keys.
            // That output must drain before the server can read the new hello.
            let (client, server) = peers.connect();
            assert_eq!(peers.incoming.state.lock().unwrap().flushes, 2);
            peers.round_trip(&client, &server);
        }
        Scenario::SilentHandshake { ack } => {
            let mut peers = Peers::new(HANDSHAKE_CAPACITY, HANDSHAKE_CAPACITY, FAULT_TIMEOUT);
            let (client, server) = peers.connect();
            let started = peers.tester.clock().now();
            if ack {
                let after_flushes = peers.outgoing.state.lock().unwrap().flushes + 2;
                peers.outgoing.fault(
                    Operation::Write,
                    after_flushes,
                    FaultKind::Error(io::ErrorKind::Other),
                );
                assert!(matches!(
                    peers.client.connect(&peers.identity),
                    Err(Error::SendFailed(_))
                ));
            } else {
                peers.client.send_frame_blob(&[]).unwrap();
            }
            assert!(matches!(peers.event(), Event::Disconnected));
            // Check the deadline the server installs on its pipe. Taking the ACK's
            // fault notifies the pipe, and the clock unlists a wait while it wakes.
            peers.outgoing.wait_blocked(Operation::Read);
            assert_eq!(
                peers.outgoing.state.lock().unwrap().read_deadline,
                Some(started + HANDSHAKE_TIMEOUT)
            );
            peers.tester.advance_to(started + HANDSHAKE_TIMEOUT);
            assert!(
                matches!(peers.events.recv().unwrap(), Err(Error::RecvFailed(ref err)) if err.kind() == io::ErrorKind::TimedOut)
            );
            assert_eq!(peers.tester.clock().elapsed(started), HANDSHAKE_TIMEOUT);
            peers.recover(&[client, server]);
        }
        Scenario::HandshakeNoise { server } => {
            let mut peers = Peers::new(HANDSHAKE_CAPACITY, HANDSHAKE_CAPACITY, FAULT_TIMEOUT);
            let (old_client, old_server) = peers.connect();
            let started = peers.tester.clock().now();
            if server {
                peers.client.send_frame_blob(&[]).unwrap();
                assert!(matches!(peers.event(), Event::Disconnected));
                // Feed resets between clock advances while retaining the first deadline
                for _ in 0..4 {
                    peers.client.send_frame_blob(&[]).unwrap();
                    peers.outgoing.wait_drained();
                    peers.outgoing.wait_blocked(Operation::Read);
                    peers.tester.wait_blocked(1);
                    assert_eq!(
                        peers.tester.next_deadline(),
                        Some(started + HANDSHAKE_TIMEOUT)
                    );
                    peers.tester.advance(HANDSHAKE_TIMEOUT / 4);
                }
                assert!(
                    matches!(peers.events.recv().unwrap(), Err(Error::RecvFailed(ref err)) if err.kind() == io::ErrorKind::TimedOut)
                );
            } else {
                // Hold the real server before it can read reset/Hello, while a
                // raw peer supplies notifications and malformed stale packets.
                peers.outgoing.pause(Operation::Read, true);
                let mut junk = Adapter::new(peers.incoming.clone());
                thread::scope(|scope| {
                    let connecting = scope.spawn(|| peers.client.connect(&peers.identity));
                    // Drain each noise batch before moving closer to the original deadline
                    for _ in 0..4 {
                        junk.set_write_deadline(peers.tester.clock().now() + FAULT_TIMEOUT)
                            .unwrap();
                        io::Write::write_all(&mut junk, &[0, 1, 0, 2, 42, 0]).unwrap();
                        peers.incoming.wait_drained();
                        peers.incoming.wait_blocked(Operation::Read);
                        peers.tester.wait_blocked(2);
                        assert_eq!(
                            peers.tester.next_deadline(),
                            Some(started + HANDSHAKE_TIMEOUT)
                        );
                        peers.tester.advance(HANDSHAKE_TIMEOUT / 4);
                    }
                    let result = connecting.join().unwrap();
                    assert!(
                        matches!(result, Err(Error::RecvFailed(ref err)) if err.kind() == io::ErrorKind::TimedOut)
                    );
                });
                peers.outgoing.pause(Operation::Read, false);
            }
            assert_eq!(peers.tester.clock().elapsed(started), HANDSHAKE_TIMEOUT);
            peers.recover(&[old_client, old_server]);
        }
        Scenario::Reconnect { both_directions } => {
            let mut peers = Peers::new(HANDSHAKE_CAPACITY, HANDSHAKE_CAPACITY, FAULT_TIMEOUT);
            let (old_client, old_server) = peers.connect();
            let client_send = if both_directions {
                peers.outgoing.pause(Operation::Read, true);
                let sent = peers.send(old_client.clone(), vec![1; 3 * HANDSHAKE_CAPACITY], false);
                peers.outgoing.wait_blocked(Operation::Write);
                Some(sent)
            } else {
                None
            };
            let server_send = peers.send(
                old_server.clone(),
                vec![2; 3 * HANDSHAKE_CAPACITY],
                both_directions,
            );
            peers.incoming.wait_blocked(Operation::Write);
            let (client, server) = if both_directions {
                // Park reconnect behind the old send before expiring both blocked writes
                let waiting = peers.client.watch_writer();
                let client = thread::scope(|scope| {
                    let connecting = scope.spawn(|| peers.client.connect(&peers.identity));
                    waiting();
                    peers.tester.wait_blocked(3);
                    peers.tester.advance(FAULT_TIMEOUT);
                    connecting.join().unwrap().unwrap().0
                });

                // Receive the new binding after any old-session events
                let server = loop {
                    if let Event::Connected(server) = peers.event() {
                        break server;
                    }
                };
                (client, server)
            } else {
                peers.connect()
            };
            let sent = server_send.recv().unwrap();
            if both_directions {
                assert!(
                    matches!(sent, Err(Error::SendFailed(err)) if err.kind() == io::ErrorKind::TimedOut)
                );
            } else {
                sent.unwrap();
            }
            if let Some(sent) = client_send {
                assert!(
                    matches!(sent.recv().unwrap(), Err(Error::SendFailed(err)) if err.kind() == io::ErrorKind::TimedOut)
                );
            }
            assert!(matches!(
                old_client.send(b"old"),
                Err(Error::EncryptionFailed(_))
            ));
            assert!(matches!(
                old_server.send(b"old"),
                Err(Error::EncryptionFailed(_))
            ));
            peers.round_trip(&client, &server);
        }
        Scenario::Backlog(extra) => {
            let mut peers = Peers::new(HANDSHAKE_CAPACITY, HANDSHAKE_CAPACITY, WRITE_TIMEOUT);
            let (old_client, old_server) = peers.connect();
            for id in 0..33 + usize::from(extra) {
                old_server.send(&[id as u8]).unwrap();
            }
            let (client, server) = peers.connect();
            assert!(matches!(
                old_client.send(b"old"),
                Err(Error::EncryptionFailed(_))
            ));
            assert!(matches!(
                old_server.send(b"old"),
                Err(Error::EncryptionFailed(_))
            ));
            peers.round_trip(&client, &server);
        }
        Scenario::ServerTimeout { flush } => {
            let mut peers = Peers::new(HANDSHAKE_CAPACITY, 64, FAULT_TIMEOUT);
            let (_, old_server) = peers.connect();
            let before = peers.incoming.state.lock().unwrap().delimiters;
            if flush {
                peers
                    .incoming
                    .fault(Operation::Flush, 0, FaultKind::Timeout);
            }
            let sent = peers.send(
                old_server.clone(),
                vec![3; if flush { 8 } else { 4096 }],
                false,
            );
            peers.incoming.wait_blocked(if flush {
                Operation::Flush
            } else {
                Operation::Write
            });
            peers.tester.wait_blocked(2);
            peers.tester.advance(FAULT_TIMEOUT);
            assert!(matches!(
                sent.recv().unwrap(),
                Err(Error::SendFailed(err)) if err.kind() == io::ErrorKind::TimedOut
            ));
            assert_eq!(
                peers.incoming.state.lock().unwrap().delimiters,
                before + usize::from(flush)
            );
            assert!(matches!(
                old_server.send(b"old"),
                Err(Error::EncryptionFailed(_))
            ));
            let (client, server) = peers.connect();
            peers.round_trip(&client, &server);
        }
        Scenario::Shutdown { handshake, server } => {
            let mut peers = Peers::new(HANDSHAKE_CAPACITY, HANDSHAKE_CAPACITY, WRITE_TIMEOUT);
            let (old_client, old_server) = peers.connect();
            if handshake {
                peers.outgoing.pause(Operation::Read, true);
            }
            let closer = if server {
                peers.server_closer.clone()
            } else {
                peers.closer.clone()
            };
            let client = &mut peers.client;
            let identity = &peers.identity;
            let incoming = &peers.incoming;
            let outgoing = &peers.outgoing;
            thread::scope(|scope| {
                let (sent, received) = mpsc::channel();
                scope.spawn(move || {
                    let result = if handshake {
                        client.connect(identity).map(|_| ())
                    } else {
                        client.recv().map(|_| ())
                    };
                    sent.send(result).unwrap();
                });
                incoming.wait_blocked(Operation::Read);
                outgoing.wait_blocked(Operation::Read);
                // Ordinary receives must clear the preceding handshake deadline.
                assert_eq!(
                    incoming.state.lock().unwrap().read_deadline.is_some(),
                    handshake
                );
                assert_eq!(outgoing.state.lock().unwrap().read_deadline, None);
                let (closed, closure) = mpsc::channel();
                scope.spawn(move || {
                    closer.close();
                    closed.send(()).unwrap();
                });
                // Shutdown releases both reads while the clock remains paused
                closure.recv().unwrap();
                assert!(matches!(received.recv().unwrap(), Err(Error::Terminated)));
            });
            // The server driver exits on EOF and drops its event sender.
            assert!(matches!(peers.events.recv(), Err(mpsc::RecvError)));
            assert!(old_client.send(b"old").is_err());
            assert!(old_server.send(b"old").is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Output errors and timeouts, including flush after complete peer delivery.
    #[test]
    fn test_handshake_output_failure_retry() {
        // Fail every output phase and recover on the same paused stream
        for ack in [false, true] {
            for flush in [false, true] {
                for timeout in [false, true] {
                    run(Scenario::HandshakeFailure {
                        ack,
                        flush,
                        timeout,
                    });
                }
            }
        }
    }

    // A reset without a hello expires on the server's original deadline.
    #[test]
    fn test_server_deadline_before_hello() {
        // Advance the parked handshake without supplying a hello
        run(Scenario::SilentHandshake { ack: false });
    }

    // A hello without an acknowledgment expires on the server's original deadline.
    #[test]
    fn test_server_deadline_before_ack() {
        // Advance the parked handshake after withholding its acknowledgment
        run(Scenario::SilentHandshake { ack: true });
    }

    // Repeated resets preserve the server's first handshake deadline.
    #[test]
    fn test_reset_stream_keeps_one_deadline() {
        // Feed resets between explicit advances to the original deadline
        run(Scenario::HandshakeNoise { server: true });
    }

    // Junk frames preserve the client's first handshake deadline.
    #[test]
    fn test_client_junk_keeps_one_deadline() {
        // Feed junk between explicit advances to the original deadline
        run(Scenario::HandshakeNoise { server: false });
    }

    // Closing either peer releases both reads during handshakes and sessions.
    #[test]
    fn test_shutdown_releases_peer_reads() {
        // Close each side while both adapter reads are parked
        for handshake in [false, true] {
            for server in [false, true] {
                run(Scenario::Shutdown { handshake, server });
            }
        }
    }

    // Tests reconnect with old output in one or both directions. Old writes
    // can time out; the fresh session must work and refuse the old senders.
    #[test]
    fn test_reconnect_drains_bounded_output() {
        // Reconnect with old output blocked in each direction
        for both_directions in [false, true] {
            run(Scenario::Reconnect { both_directions });
        }
    }

    // Tests reconnect with more than 32 queued messages from the old session.
    // All must drain, and old senders must fail after the new session starts.
    #[test]
    fn test_reconnect_drains_stale_backlog() {
        // Recover after draining both small and large old-session backlogs
        for extra in [0, 63] {
            run(Scenario::Backlog(extra));
        }
    }

    // Tests that a blocked server write or flush times out without another
    // notification attempt. The same open stream must accept a new session.
    #[test]
    fn test_server_timeout_preserves_stream() {
        // Advance blocked writes and flushes before reconnecting
        for flush in [false, true] {
            run(Scenario::ServerTimeout { flush });
        }
    }

    // Tests read and write failures in sequential handshake phases. Each
    // failure must return and leave the stream open for the next attempt.
    #[test]
    fn test_prelude_failure_preserves_stream() {
        // Inject each prelude failure before reconnecting on the same stream
        for read in [false, true] {
            run(Scenario::FailedPrelude { read });
        }
    }

    // Tests alternating read and write failures followed by successful retries.
    // A failed earlier attempt must not affect a later handshake.
    #[test]
    fn test_repeated_attempts_preserve_stream() {
        // Alternate faults across consecutive handshakes
        run(Scenario::RepeatedAttempts(2));
    }

    // Tests immediate retry while an abandoned ArkHello is still blocked in a
    // 64-byte inbound pipe, with room for HostHello in the opposite direction.
    // Both old and new replies must flush successfully, so recovery
    // cannot rely on the old response reaching its output deadline first.
    #[test]
    fn test_reconnect_drains_abandoned_hello() {
        // Drain the abandoned reply before starting the replacement handshake
        run(Scenario::AbandonedHello);
    }
}
