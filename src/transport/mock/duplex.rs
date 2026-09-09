// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Concurrent scenarios between a real client and server on bounded byte pipes.
//! Gates let tests wait for I/O to block before injecting faults or reconnecting.
//! Deadlines exercise recovery without closing the stream. A watchdog closes
//! both peers if the scenario hangs.

use super::self_attestation;
use crate::transport::{Client, Closer, Error, Event, Read, Sender, Server, Stream, Write};
use darkbio_crypto::xdsa;
use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Maximum wait before a hung scenario fails and releases blocked operations.
const PATIENCE: Duration = Duration::from_secs(8);

/// Budget for deliberately stalled output, long enough for ordinary handshakes.
const FAULT_TIMEOUT: Duration = Duration::from_millis(250);

/// Budget for ordinary output during the concurrent scenarios.
const WRITE_TIMEOUT: Duration = Duration::from_secs(2);

/// A non-default handshake budget, longer than shutdown's completion bound.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

/// Enough space for reset and HostHello before the client starts reading.
const HANDSHAKE_CAPACITY: usize = 64 * 1024;

/// One bounded concurrency or timeout scenario, independently repeatable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum Scenario {
    /// Reconnect while server output is blocked, optionally with client output
    /// blocked too. Old writes may time out before the sequential handshake.
    Reconnect { both_directions: bool },
    /// Drain at least 33 legitimate old messages before a new handshake.
    Backlog(u8),
    /// A server message times out during its write or flush, then the stream recovers.
    ServerTimeout { flush: bool },
    /// Fail ArkHello or HostAck output, then retry. Lost replies must expire
    /// the client's handshake without another fault to rescue its read.
    HandshakeFailure {
        ack: bool,
        flush: bool,
        timeout: bool,
    },
    /// Fail reset output or the following reply read, then retry on the same
    /// stream. Each phase runs sequentially without a companion operation.
    FailedPrelude { read: bool },
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
}

/// Bounded byte pipe with deadline-aware I/O.
/// Blocked calls release the state lock, so closing can acquire it and wake them.
#[derive(Debug)]
pub(crate) struct Pipe {
    capacity: usize,
    state: Mutex<State>,
    changed: Condvar,
}

impl Pipe {
    /// Creates a bounded queue with no pending operations or faults.
    pub(crate) fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            capacity,
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
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
    #[cfg(test)]
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
        let deadline = Instant::now() + PATIENCE;
        let mut state = self.state.lock().unwrap();
        while state.waiting[operation.index()] == 0 {
            if Instant::now() >= deadline {
                // Do not poison the pipe on assertion failure: the watchdog and
                // peer cleanup still need its lock to release blocked calls.
                drop(state);
                panic!("{operation:?} never blocked");
            }
            state = self
                .changed
                .wait_timeout(state, deadline.saturating_duration_since(Instant::now()))
                .unwrap()
                .0;
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
                let (state, timeout) = self
                    .changed
                    .wait_timeout(state, deadline.saturating_duration_since(Instant::now()))
                    .unwrap();
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
        match kind {
            FaultKind::Error(kind) => Err(kind.into()),
            FaultKind::Timeout => loop {
                if state.closed {
                    return Err(io::ErrorKind::BrokenPipe.into());
                }
                if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
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
        let now = Instant::now();
        Self {
            pipe,
            read_deadline: None,
            write_deadline: now,
        }
    }
}

impl Read for Adapter {
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
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
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
            if Instant::now() >= deadline {
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
            if Instant::now() >= deadline {
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
    client: Client<Adapter, Adapter>,
    identity: xdsa::PublicKey,
    incoming: Arc<Pipe>,
    outgoing: Arc<Pipe>,
    events: mpsc::Receiver<Result<Event<Adapter>, Error>>,
    closer: Closer,
    server_closer: Closer,
    server: Option<JoinHandle<()>>,
    senders: Vec<JoinHandle<()>>,
    watchdog: Option<JoinHandle<()>>,
    stop_watchdog: Option<mpsc::Sender<()>>,
    expired: Arc<AtomicBool>,
}

impl Peers {
    /// Starts a server that keeps consuming its stream after recoverable errors.
    fn new(outgoing_capacity: usize, incoming_capacity: usize, write_timeout: Duration) -> Self {
        let incoming = Pipe::new(incoming_capacity);
        let outgoing = Pipe::new(outgoing_capacity);
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
        let expired = Arc::new(AtomicBool::new(false));
        let (stop_watchdog, stopped) = mpsc::channel();
        let watchdog = thread::spawn({
            let expired = expired.clone();
            let closer = closer.clone();
            let server_closer = server_closer.clone();
            move || {
                if stopped.recv_timeout(PATIENCE).is_err() {
                    expired.store(true, Ordering::Release);
                    closer.close();
                    server_closer.close();
                }
            }
        });
        Self {
            client: Client::new(client_stream).set_handshake_timeout(HANDSHAKE_TIMEOUT),
            identity,
            incoming,
            outgoing,
            events,
            closer,
            server_closer,
            server: Some(server),
            senders: Vec::new(),
            watchdog: Some(watchdog),
            stop_watchdog: Some(stop_watchdog),
            expired,
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
            match self.events.recv_timeout(PATIENCE).unwrap() {
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

    /// Receives one server event. Panics on timeout or a transport error.
    fn event(&self) -> Event<Adapter> {
        self.events.recv_timeout(PATIENCE).unwrap().unwrap()
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
        assert!(
            !self.expired.load(Ordering::Acquire),
            "scenario watchdog expired"
        );
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
        let _ = self.stop_watchdog.take().unwrap().send(());
        self.watchdog.take().unwrap().join().unwrap();
    }
}

/// Runs one concurrency scenario and checks progress, errors and session isolation.
/// Recovery must leave the same stream usable. Any mismatch panics.
pub fn run(scenario: Scenario) {
    #[cfg(feature = "fuzz")]
    super::seed::seed(super::seed::TRANSPORT_DUPLEX, &[scenario]);

    match scenario {
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
            let (client, server) = peers.connect();
            let sent = server_send.recv_timeout(PATIENCE).unwrap();
            if both_directions {
                assert!(
                    matches!(sent, Err(Error::SendFailed(err)) if err.kind() == io::ErrorKind::TimedOut)
                );
            } else {
                sent.unwrap();
            }
            if let Some(sent) = client_send {
                assert!(
                    matches!(sent.recv_timeout(PATIENCE).unwrap(), Err(Error::SendFailed(err)) if err.kind() == io::ErrorKind::TimedOut)
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
            assert!(matches!(
                sent.recv_timeout(PATIENCE).unwrap(),
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
                &peers.outgoing
            } else {
                &peers.incoming
            };
            let after_flushes = pipe.state.lock().unwrap().flushes + if ack { 2 } else { 0 };
            let kind = if timeout {
                FaultKind::Timeout
            } else {
                FaultKind::Error(io::ErrorKind::Other)
            };
            pipe.fault(operation, after_flushes, kind);
            if timeout && !ack {
                // Model a reply the client cannot read, even if all bytes were
                // accepted before flush failed. Only its own deadline releases it.
                peers.incoming.pause(Operation::Read, true);
            }
            let first = peers.client.connect(&peers.identity);
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
            assert!(matches!(peers.event(), Event::Disconnected));
            if !ack {
                let expected = if timeout {
                    io::ErrorKind::TimedOut
                } else {
                    io::ErrorKind::Other
                };
                assert!(matches!(
                    peers.events.recv_timeout(PATIENCE).unwrap(),
                    Err(Error::SendFailed(err)) if err.kind() == expected
                ));
            }
            peers.incoming.pause(Operation::Read, false);
            peers.recover(&old);
        }
        Scenario::FailedPrelude { read } => {
            let mut peers = Peers::new(HANDSHAKE_CAPACITY, 64, FAULT_TIMEOUT);
            peers.fail_prelude(read);
            let (client, server) = peers.connect();
            peers.round_trip(&client, &server);
        }
        Scenario::RepeatedAttempts(count) => {
            let mut peers = Peers::new(HANDSHAKE_CAPACITY, 64, FAULT_TIMEOUT);
            for attempt in 0..2 + usize::from(count % 3) {
                peers.fail_prelude(attempt % 2 == 0);
                let (client, server) = peers.connect();
                peers.round_trip(&client, &server);
            }
        }
        Scenario::SilentHandshake { ack } => {
            let mut peers = Peers::new(HANDSHAKE_CAPACITY, HANDSHAKE_CAPACITY, FAULT_TIMEOUT);
            let (client, server) = peers.connect();
            let started = Instant::now();
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
            assert!(
                matches!(peers.events.recv_timeout(PATIENCE).unwrap(), Err(Error::RecvFailed(ref err)) if err.kind() == io::ErrorKind::TimedOut)
            );
            assert!(
                (HANDSHAKE_TIMEOUT..HANDSHAKE_TIMEOUT + Duration::from_secs(2))
                    .contains(&started.elapsed()),
                "server did not use its configured handshake budget"
            );
            peers.recover(&[client, server]);
        }
        Scenario::HandshakeNoise { server } => {
            let mut peers = Peers::new(HANDSHAKE_CAPACITY, HANDSHAKE_CAPACITY, FAULT_TIMEOUT);
            let (old_client, old_server) = peers.connect();
            let stopped = AtomicBool::new(false);
            let started = Instant::now();
            if server {
                peers.client.send_frame_blob(&[]).unwrap();
                assert!(matches!(peers.event(), Event::Disconnected));
                let client = &mut peers.client;
                let events = &peers.events;
                thread::scope(|scope| {
                    let sending = scope.spawn(|| {
                        while !stopped.load(Ordering::Relaxed) {
                            client.send_frame_blob(&[]).unwrap();
                            thread::sleep(Duration::from_millis(1));
                        }
                    });
                    let result = events.recv_timeout(PATIENCE);
                    stopped.store(true, Ordering::Relaxed);
                    sending.join().unwrap();
                    assert!(
                        matches!(result.unwrap(), Err(Error::RecvFailed(ref err)) if err.kind() == io::ErrorKind::TimedOut)
                    );
                });
            } else {
                // Hold the real server before it can read reset/Hello, while a
                // raw peer supplies notifications and malformed stale packets.
                peers.outgoing.pause(Operation::Read, true);
                let mut junk = Adapter::new(peers.incoming.clone());
                thread::scope(|scope| {
                    let sending = scope.spawn(|| {
                        while !stopped.load(Ordering::Relaxed) {
                            junk.set_write_deadline(Instant::now() + FAULT_TIMEOUT)
                                .unwrap();
                            io::Write::write_all(&mut junk, &[0, 1, 0, 2, 42, 0]).unwrap();
                            thread::sleep(Duration::from_millis(1));
                        }
                    });
                    let result = peers.client.connect(&peers.identity);
                    stopped.store(true, Ordering::Relaxed);
                    sending.join().unwrap();
                    assert!(
                        matches!(result, Err(Error::RecvFailed(ref err)) if err.kind() == io::ErrorKind::TimedOut)
                    );
                });
                peers.outgoing.pause(Operation::Read, false);
            }
            assert!(
                (HANDSHAKE_TIMEOUT..HANDSHAKE_TIMEOUT + Duration::from_secs(2))
                    .contains(&started.elapsed()),
                "noise changed the configured handshake budget"
            );
            peers.recover(&[old_client, old_server]);
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
                // These reads must finish through shutdown, before the configured
                // handshake deadline or the scenario watchdog can release them.
                closure.recv_timeout(Duration::from_secs(1)).unwrap();
                assert!(matches!(
                    received.recv_timeout(Duration::from_secs(1)).unwrap(),
                    Err(Error::Terminated)
                ));
            });
            // The server driver exits on EOF and drops its event sender.
            assert!(matches!(
                peers.events.recv_timeout(Duration::from_secs(1)),
                Err(mpsc::RecvTimeoutError::Disconnected)
            ));
            assert!(old_client.send(b"old").is_err());
            assert!(old_server.send(b"old").is_err());
            assert!(!peers.expired.load(Ordering::Acquire));
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Output errors and timeouts, including flush after complete peer delivery.
    #[test]
    fn test_handshake_output_failure_retry() {
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

    #[test]
    fn test_server_deadline_before_hello() {
        run(Scenario::SilentHandshake { ack: false });
    }

    #[test]
    fn test_server_deadline_before_ack() {
        run(Scenario::SilentHandshake { ack: true });
    }

    #[test]
    fn test_reset_stream_keeps_one_deadline() {
        run(Scenario::HandshakeNoise { server: true });
    }

    #[test]
    fn test_client_junk_keeps_one_deadline() {
        run(Scenario::HandshakeNoise { server: false });
    }

    #[test]
    fn test_shutdown_releases_peer_reads() {
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
        for both_directions in [false, true] {
            run(Scenario::Reconnect { both_directions });
        }
    }

    // Tests reconnect with more than 32 queued messages from the old session.
    // All must drain, and old senders must fail after the new session starts.
    #[test]
    fn test_reconnect_drains_stale_backlog() {
        for extra in [0, 63] {
            run(Scenario::Backlog(extra));
        }
    }

    // Tests that a blocked server write or flush times out without another
    // notification attempt. The same open stream must accept a new session.
    #[test]
    fn test_server_timeout_preserves_stream() {
        for flush in [false, true] {
            run(Scenario::ServerTimeout { flush });
        }
    }

    // Tests read and write failures in sequential handshake phases. Each
    // failure must return and leave the stream open for the next attempt.
    #[test]
    fn test_prelude_failure_preserves_stream() {
        for read in [false, true] {
            run(Scenario::FailedPrelude { read });
        }
    }

    // Tests alternating read and write failures followed by successful retries.
    // A failed earlier attempt must not affect a later handshake.
    #[test]
    fn test_repeated_attempts_preserve_stream() {
        run(Scenario::RepeatedAttempts(2));
    }

    // Tests immediate retry while an abandoned ArkHello is still blocked in a
    // 64-byte inbound pipe, with room for HostHello in the opposite direction.
    // Both old and new replies must flush successfully, so recovery
    // cannot rely on the old response reaching its output deadline first.
    #[test]
    fn test_reconnect_drains_abandoned_hello() {
        run(Scenario::AbandonedHello);
    }
}
