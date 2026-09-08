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

/// Budget for healthy transfers that must complete through concurrent draining.
const WRITE_TIMEOUT: Duration = Duration::from_secs(2);

/// One bounded concurrency or timeout scenario, independently repeatable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum Scenario {
    /// Reconnect while server output is blocked, optionally with client output
    /// blocked too. Input must drain before reconnect waits for the old send.
    Reconnect { both_directions: bool },
    /// Drain at least 33 legitimate old messages before a new handshake.
    Backlog(u8),
    /// A server message times out during its write or flush, then the stream recovers.
    ServerTimeout { flush: bool },
    /// ArkHello or HostAck times out in its write or flush. The ArkHello case
    /// deliberately aborts the client's read because peer replies have no timeout.
    HandshakeTimeout { ack: bool, flush: bool },
    /// Fail a read while reset output is blocked, or fail output during an idle
    /// read. Cancellation must release the other operation and allow a retry.
    FailedPrelude { read: bool },
    /// Alternate read and write failures across reconnect attempts.
    RepeatedAttempts(u8),
    /// Retry an abandoned handshake while its old ArkHello is still blocked,
    /// draining that reply so the server can consume the replacement hello.
    AbandonedHello,
}

/// Adapter operation addressed by a test gate or a one-shot fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operation {
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
enum FaultKind {
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
    faults: VecDeque<Fault>,
}

/// Bounded byte pipe with deadline-aware I/O.
/// Blocked calls release the state lock, so closing can acquire it and wake them.
#[derive(Debug)]
struct Pipe {
    capacity: usize,
    state: Mutex<State>,
    changed: Condvar,
}

impl Pipe {
    /// Creates a bounded queue with no pending operations or faults.
    fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            capacity,
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
        })
    }

    /// Permanently closes this test adapter, waking every blocked call.
    fn close(&self) {
        self.state.lock().unwrap().closed = true;
        self.changed.notify_all();
    }

    /// Holds or releases the selected operation independently of buffer capacity.
    fn pause(&self, operation: Operation, paused: bool) {
        self.state.lock().unwrap().paused[operation.index()] = paused;
        self.changed.notify_all();
    }

    /// Arms a one-shot fault and wakes a matching call already waiting in I/O.
    fn fault(&self, operation: Operation, after_flushes: usize, kind: FaultKind) {
        self.state.lock().unwrap().faults.push_back(Fault {
            operation,
            after_flushes,
            kind,
        });
        self.changed.notify_all();
    }

    /// Waits for an adapter call to block, so scenarios depend on an observed
    /// operation rather than a scheduling delay.
    fn wait_blocked(&self, operation: Operation) {
        let deadline = Instant::now() + PATIENCE;
        let mut state = self.state.lock().unwrap();
        while state.waiting[operation.index()] == 0 {
            let (next, timeout) = self
                .changed
                .wait_timeout(state, deadline.saturating_duration_since(Instant::now()))
                .unwrap();
            state = next;
            assert!(!timeout.timed_out(), "{operation:?} never blocked");
        }
    }

    /// Waits once and tracks the operation in the blocked-call count.
    fn wait<'a>(
        &self,
        mut state: MutexGuard<'a, State>,
        operation: Operation,
        deadline: Instant,
    ) -> io::Result<MutexGuard<'a, State>> {
        state.waiting[operation.index()] += 1;
        self.changed.notify_all();
        let (mut state, timeout) = self
            .changed
            .wait_timeout(state, deadline.saturating_duration_since(Instant::now()))
            .unwrap();
        state.waiting[operation.index()] -= 1;
        self.changed.notify_all();
        if timeout.timed_out() && !state.closed {
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
        deadline: Instant,
    ) -> io::Result<usize> {
        match kind {
            FaultKind::Error(kind) => Err(kind.into()),
            FaultKind::Timeout => loop {
                if state.closed {
                    return Err(io::ErrorKind::BrokenPipe.into());
                }
                state = self.wait(state, operation, deadline)?;
            },
        }
    }
}

/// A cloneable endpoint used as either the reader or writer of its pipe.
/// Each clone configures its own deadlines, independently of the shared bytes.
#[derive(Clone, Debug)]
struct Adapter {
    pipe: Arc<Pipe>,
    read_deadline: Instant,
    write_deadline: Instant,
}

impl Adapter {
    /// Creates an endpoint whose I/O deadlines must be configured before use.
    fn new(pipe: Arc<Pipe>) -> Self {
        let now = Instant::now();
        Self {
            pipe,
            read_deadline: now,
            write_deadline: now,
        }
    }
}

impl Read for Adapter {
    fn set_read_deadline(&mut self, deadline: Instant) -> io::Result<()> {
        self.read_deadline = deadline;
        Ok(())
    }
}

impl io::Read for Adapter {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let deadline = self.read_deadline;
        let mut state = self.pipe.state.lock().unwrap();
        loop {
            if Instant::now() >= deadline {
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
                return self.pipe.fail(state, Operation::Write, fault, deadline);
            }
            if !state.paused[Operation::Write.index()] && state.bytes.len() < self.pipe.capacity {
                let len = bytes.len().min(self.pipe.capacity - state.bytes.len());
                state.bytes.extend(&bytes[..len]);
                state.delimiters += bytes[..len].iter().filter(|byte| **byte == 0).count();
                self.pipe.changed.notify_all();
                return Ok(len);
            }
            state = self.pipe.wait(state, Operation::Write, deadline)?;
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
                    .fail(state, Operation::Flush, fault, deadline)
                    .map(|_| ());
            }
            if !state.paused[Operation::Flush.index()] {
                state.flushes += 1;
                return Ok(());
            }
            state = self.pipe.wait(state, Operation::Flush, deadline)?;
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
    fn new(capacity: usize, write_timeout: Duration) -> Self {
        let incoming = Pipe::new(capacity);
        let outgoing = Pipe::new(capacity);
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
            let mut server = Server::new(server_stream, signer, attestation);
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
            client: Client::new(client_stream),
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

    /// Waits for the handshake's read and write to block, then fails one of them.
    /// Checks that cancellation releases the other operation without closing.
    fn fail_prelude(&mut self, read: bool) {
        self.outgoing.pause(Operation::Write, true);
        let client = &mut self.client;
        let identity = &self.identity;
        let incoming = &self.incoming;
        let outgoing = &self.outgoing;
        let result = thread::scope(|scope| {
            let connecting = scope.spawn(|| client.connect(identity));
            outgoing.wait_blocked(Operation::Write);
            incoming.wait_blocked(Operation::Read);
            if read {
                incoming.fault(Operation::Read, 0, FaultKind::Error(io::ErrorKind::Other));
            } else {
                outgoing.fault(Operation::Write, 0, FaultKind::Error(io::ErrorKind::Other));
                outgoing.pause(Operation::Write, false);
            }
            connecting.join().unwrap()
        });
        self.outgoing.pause(Operation::Write, false);
        match result {
            Err(Error::RecvFailed(err)) if read => assert_eq!(err.kind(), io::ErrorKind::Other),
            Err(Error::SendFailed(err)) if !read => assert_eq!(err.kind(), io::ErrorKind::Other),
            result => panic!("unexpected companion failure: {:?}", result.map(|_| ())),
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
            let mut peers = Peers::new(64, WRITE_TIMEOUT);
            let (old_client, old_server) = peers.connect();
            let client_send = if both_directions {
                peers.outgoing.pause(Operation::Read, true);
                let sent = peers.send(old_client.clone(), vec![1; 4096], false);
                peers.outgoing.wait_blocked(Operation::Write);
                Some(sent)
            } else {
                None
            };
            let server_send = peers.send(old_server.clone(), vec![2; 4096], both_directions);
            peers.incoming.wait_blocked(Operation::Write);
            let (client, server) = peers.connect();
            server_send.recv_timeout(PATIENCE).unwrap().unwrap();
            if let Some(sent) = client_send {
                sent.recv_timeout(PATIENCE).unwrap().unwrap();
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
            let mut peers = Peers::new(65536, WRITE_TIMEOUT);
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
            let mut peers = Peers::new(64, FAULT_TIMEOUT);
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
        Scenario::HandshakeTimeout { ack, flush } => {
            let mut peers = Peers::new(65536, FAULT_TIMEOUT);
            let operation = if flush {
                Operation::Flush
            } else {
                Operation::Write
            };
            if ack {
                peers.outgoing.fault(operation, 2, FaultKind::Timeout);
                assert!(matches!(
                    peers.client.connect(&peers.identity),
                    Err(Error::SendFailed(err)) if err.kind() == io::ErrorKind::TimedOut
                ));
                // A flush failure may occur after the peer accepted HostAck.
                if flush {
                    assert!(matches!(peers.event(), Event::Connected(_)));
                }
            } else {
                peers.incoming.pause(Operation::Read, true);
                peers.incoming.fault(operation, 0, FaultKind::Timeout);
                let client = &mut peers.client;
                let identity = &peers.identity;
                let incoming = &peers.incoming;
                let events = &peers.events;
                thread::scope(|scope| {
                    let connecting = scope.spawn(|| client.connect(identity));
                    assert!(matches!(
                        events.recv_timeout(PATIENCE).unwrap(),
                        Err(Error::SendFailed(err)) if err.kind() == io::ErrorKind::TimedOut
                    ));
                    assert_eq!(
                        incoming.state.lock().unwrap().delimiters,
                        usize::from(flush)
                    );
                    // The failed send may leave ArkHello incomplete. Waiting
                    // for a reply has no deadline, so abort this read to retry.
                    incoming.fault(Operation::Read, 0, FaultKind::Error(io::ErrorKind::Other));
                    incoming.pause(Operation::Read, false);
                    assert!(matches!(
                        connecting.join().unwrap(),
                        Err(Error::RecvFailed(_))
                    ));
                });
            }
            let (client, server) = peers.connect();
            peers.round_trip(&client, &server);
        }
        Scenario::FailedPrelude { read } => {
            let mut peers = Peers::new(64, FAULT_TIMEOUT);
            peers.fail_prelude(read);
            let (client, server) = peers.connect();
            peers.round_trip(&client, &server);
        }
        Scenario::RepeatedAttempts(count) => {
            let mut peers = Peers::new(64, FAULT_TIMEOUT);
            for attempt in 0..2 + usize::from(count % 3) {
                peers.fail_prelude(attempt % 2 == 0);
                let (client, server) = peers.connect();
                peers.round_trip(&client, &server);
            }
        }
        Scenario::AbandonedHello => {
            let mut peers = Peers::new(64, WRITE_TIMEOUT);
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

    // Tests that reconnect drains bounded server output before waiting for old
    // local output, including when both directions initially contain blocked sends.
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

    // Tests ArkHello and HostAck timeout recovery, including failed flush after
    // complete delivery. After ArkHello fails, the test aborts the client read:
    // waiting for a peer reply has no overall deadline.
    #[test]
    fn test_handshake_timeout_recovery() {
        for ack in [false, true] {
            for flush in [false, true] {
                run(Scenario::HandshakeTimeout { ack, flush });
            }
        }
    }

    // Tests that failed handshake reads cancel blocked output and failed output
    // cancels an idle read. The stream must remain open for the next attempt.
    #[test]
    fn test_companion_failure_preserves_stream() {
        for read in [false, true] {
            run(Scenario::FailedPrelude { read });
        }
    }

    // Tests alternating read and write failures followed by successful retries.
    // Cancellation from an earlier attempt must not affect a later handshake.
    #[test]
    fn test_repeated_attempts_have_independent_cancellation() {
        run(Scenario::RepeatedAttempts(2));
    }

    // Tests immediate retry while an abandoned ArkHello is still blocked in a
    // 64-byte pipe. Both old and new replies must flush successfully, so recovery
    // cannot rely on the old response reaching its output deadline first.
    #[test]
    fn test_reconnect_drains_abandoned_hello() {
        run(Scenario::AbandonedHello);
    }
}
