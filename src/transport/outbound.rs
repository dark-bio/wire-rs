// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Output and session boundaries of one byte stream.
//!
//! The writer lock orders frames, handshakes and session ending. A separate
//! binding lock orders receive completion against those boundaries without
//! waiting for output.

use super::framing::FrameWriter;
use super::{Closer, Error, Sender, Write};
use crate::LogId;
use darkbio_clock::Clock;
use darkbio_crypto::xhpke;
use std::io;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};
use tracing::{trace, warn};

/// Side of the wire served by the writer, determining how failures are signaled.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Side {
    /// Client side, which notifies no failures and starts every handshake with
    /// a reset instead.
    Client,
    /// Server side, which answers a failed send or a local disconnect with an
    /// empty frame.
    ///
    /// A failed send's notification uses the frame's remaining budget, and a
    /// timeout skips it.
    Server,
}

impl Side {
    /// Returns the name of this side's outgoing messages in traces.
    fn label(self) -> &'static str {
        match self {
            Self::Client => "host-to-ark",
            Self::Server => "ark-to-host",
        }
    }
}

/// Shared output, session binding and permanent closure of a byte stream.
///
/// The binding identifies the encryption context allowed to use the stream.
/// The client or server owns this value and its crypto contexts. Idle senders
/// hold weak references. Active sends temporarily retain the output and the
/// sending context.
///
/// Every binding change holds the writer lock first, then the binding lock.
/// Receive completion takes only the binding lock. That lock is never held
/// during crypto, I/O, or acquisition of another lock. Encryption can therefore
/// overlap a preceding write, and receiving can progress during blocked output.
/// Panics and poisoned locks are fatal to this transport. It must not be reused.
pub(crate) struct Outbound<W: Write> {
    /// Count of calls waiting to acquire the writer, with its wakeup, for
    /// concurrency tests.
    #[cfg(any(test, feature = "fuzz"))]
    writer_waits: (Mutex<usize>, std::sync::Condvar),
    /// Frame writer whose lock serializes complete writes, flushes and binding
    /// changes.
    writer: Mutex<FrameWriter<W>>,
    /// Weak reference to the current session's sending context, the sole
    /// record of which session may write and accept messages.
    binding: Mutex<Weak<Mutex<xhpke::Sender>>>,
    /// Time budget for each frame, covering partial writes and flush.
    timeout: Duration,
    /// Side of the wire, deciding whether a failed send needs an empty frame
    /// notification.
    side: Side,
    /// Shutdown handle that takes none of the encryption, writer or binding
    /// locks.
    closer: Closer,
    /// Clock of the stream, which the handshakes read too.
    pub(super) clock: Clock,
}

impl<W: Write> Outbound<W> {
    /// Creates an unbound writer around the byte stream's writing half.
    pub(crate) fn new(writer: W, side: Side, closer: Closer, timeout: Duration) -> Self {
        Self {
            #[cfg(any(test, feature = "fuzz"))]
            writer_waits: (Mutex::new(0), std::sync::Condvar::new()),
            clock: writer.clock(),
            writer: Mutex::new(FrameWriter::new(writer, closer.clone())),
            binding: Mutex::new(Weak::new()),
            timeout,
            side,
            closer,
        }
    }

    /// Binds a sending context under the writer lock and returns its sender.
    ///
    /// Replacing the binding ends the previous session before new messages can
    /// be written or accepted. The caller retains the context. The binding and
    /// idle senders hold weak references. This performs no crypto or stream I/O.
    /// Each handshake must supply a fresh allocation. Rebinding an ended context
    /// would revive its old sender handles and is forbidden. Every binding takes
    /// the next log label, which the sender carries for its log lines.
    pub(crate) fn bind(self: &Arc<Self>, sealer: &Arc<Mutex<xhpke::Sender>>) -> Sender<W> {
        self.lock().bind(sealer);
        Sender::new(
            Arc::downgrade(self),
            Arc::downgrade(sealer),
            crate::next_log_id(),
        )
    }

    /// Ends this context's session while leaving any replacement session alone.
    ///
    /// Always waits for the writer lock, including on repeated or obsolete calls.
    /// Once this returns, no write or flush for the context remains in progress
    /// or can start. Sealing may still finish, but its packet will be refused.
    ///
    /// Sends that obtain the writer first may finish before ending takes effect.
    /// The lock wait has no overall timeout. This leaves the stream open and
    /// sends no signal.
    pub(crate) fn end(&self, sealer: &Arc<Mutex<xhpke::Sender>>) {
        self.lock().end(sealer);
    }

    /// Ends the session that `sealer` identifies and, on the server, sends an
    /// empty frame to notify the client.
    ///
    /// Both happen under the writer lock, so a handshake cannot start between
    /// removing the binding and sending the notification. An obsolete sealer
    /// changes nothing.
    pub(crate) fn disconnect(&self, sealer: &Arc<Mutex<xhpke::Sender>>) -> Result<(), Error> {
        let mut writer = self.lock();
        if writer.end(sealer) && self.side == Side::Server {
            writer
                .framer
                .send_dropped(self.clock.now() + self.timeout)?;
        }
        Ok(())
    }

    /// Removes any binding, waiting for earlier writes.
    pub(super) fn unbind(&self) {
        self.lock().unbind();
    }

    /// Completes a decrypted receive under the binding lock, accepting the
    /// supplied result only for the current binding.
    ///
    /// An obsolete binding returns an ended-session error instead. On any error,
    /// the caller must end its session and release its crypto contexts.
    ///
    /// Reading and decryption happen before acquiring this lock. Acceptance is
    /// ordered with session ending and replacement. An accepted result may reach
    /// its caller after another thread ends the session, but its acceptance
    /// happened before that ending.
    pub(crate) fn finish_receive(
        &self,
        sealer: &Arc<Mutex<xhpke::Sender>>,
        result: Result<Vec<u8>, Error>,
    ) -> Result<Vec<u8>, Error> {
        let binding = self.binding.lock().expect("binding lock not poisoned");
        if Weak::ptr_eq(&Arc::downgrade(sealer), &binding) {
            result
        } else {
            Err(Error::EncryptionFailed("session ended".into()))
        }
    }

    /// Refuses an oversized message without waiting for the writer or ending the
    /// session.
    ///
    /// Sealing has not advanced its sequence. Returns the size error only while
    /// this binding is current. An obsolete sender receives an ended-session
    /// error instead.
    pub(super) fn refuse_oversized(
        &self,
        sealer: &Arc<Mutex<xhpke::Sender>>,
        size: usize,
    ) -> Result<(), Error> {
        let binding = self.binding.lock().expect("binding lock not poisoned");
        if Weak::ptr_eq(&Arc::downgrade(sealer), &binding) {
            Err(Error::PacketTooLarge(size))
        } else {
            Err(Error::EncryptionFailed("session ended".into()))
        }
    }

    /// Returns the stream's shutdown handle without taking any send lock.
    pub(crate) fn closer(&self) -> Closer {
        self.closer.clone()
    }

    /// Permanently closes the byte stream and waits for adapter shutdown.
    ///
    /// Takes no send lock, so it can cancel I/O that blocks session ending.
    /// Buffered receives remain available. Closure alone does not remove the
    /// binding.
    pub(crate) fn close(&self) {
        self.closer.close();
    }

    /// Removes the binding and sends a reset under the writer lock.
    ///
    /// Old sends cannot write after the reset. The deadline can shorten the
    /// frame's write budget.
    pub(super) fn send_reset(&self, deadline: Instant) -> Result<(), Error> {
        let mut writer = self.lock();
        writer.unbind();
        writer
            .framer
            .send_reset(deadline.min(self.clock.now() + self.timeout))
    }

    /// Removes the binding and sends an empty frame notification.
    ///
    /// The frame uses the configured write budget, which an optional deadline
    /// can shorten.
    pub(crate) fn send_dropped(&self, limit: Option<Instant>) -> Result<(), Error> {
        let mut writer = self.lock();
        writer.unbind();
        let budget = self.clock.now() + self.timeout;
        let deadline = limit.map_or(budget, |limit| limit.min(budget));
        writer.framer.send_dropped(deadline)
    }

    /// Writes an unsealed packet after the owner has removed the binding.
    ///
    /// The optional deadline can shorten the write budget, which also bounds any
    /// best-effort failure notification.
    pub(super) fn send_packet(&self, packet: &[u8], limit: Option<Instant>) -> Result<(), Error> {
        let mut writer = self.lock();
        let budget = self.clock.now() + self.timeout;
        let deadline = limit.map_or(budget, |limit| limit.min(budget));
        let result = writer.framer.send_packet(packet, deadline);
        if let Err(err @ Error::SendFailed(_)) = &result {
            writer.notify_failure(err, deadline);
        }
        result
    }

    /// Writes an encoded frame for tests, benchmarks and fuzzing.
    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(super) fn send_frame_blob(&self, frame: &[u8]) -> Result<(), Error> {
        let mut writer = self.lock();
        writer
            .framer
            .send_frame_blob(frame, self.clock.now() + self.timeout)
    }

    /// Acquires exclusive output ownership.
    ///
    /// A sender retains its encryption guard until this returns, preserving
    /// sealing order through the handoff. A poisoned writer is an
    /// implementation failure and is not recovered.
    pub(super) fn lock(&self) -> Writer<'_, W> {
        // Let tests fence writer acquisition while another call owns the lock
        #[cfg(any(test, feature = "fuzz"))]
        {
            *self.writer_waits.0.lock().unwrap() += 1;
            self.writer_waits.1.notify_all();
        }
        let framer = self.writer.lock().expect("writer lock not poisoned");
        #[cfg(any(test, feature = "fuzz"))]
        {
            *self.writer_waits.0.lock().unwrap() -= 1;
        }

        // Keep the frame guard through any binding changes
        Writer {
            outbound: self,
            framer,
        }
    }

    /// Waits for calls to reach writer acquisition while a test holds that writer.
    #[cfg(any(test, feature = "fuzz"))]
    pub(super) fn wait_writers(&self, count: usize) {
        let mut waiting = self.writer_waits.0.lock().unwrap();
        while *waiting < count {
            waiting = self.writer_waits.1.wait(waiting).unwrap();
        }
    }
}

/// Guard over the frame writer that allows changes to the binding.
///
/// Other operations cannot change the binding while this guard exists, even
/// when the binding mutex is unlocked. Dropping the guard only releases the
/// writer lock.
pub(super) struct Writer<'a, W: Write> {
    /// Transport whose binding this guard may change.
    outbound: &'a Outbound<W>,
    /// Held lock on the transport's frame writer.
    framer: MutexGuard<'a, FrameWriter<W>>,
}

impl<W: Write> Writer<'_, W> {
    /// Replaces the binding while owning the writer, ending the previous session.
    fn bind(&mut self, sealer: &Arc<Mutex<xhpke::Sender>>) {
        *self
            .outbound
            .binding
            .lock()
            .expect("binding lock not poisoned") = Arc::downgrade(sealer);
    }

    /// Removes any binding while owning the writer.
    fn unbind(&mut self) {
        *self
            .outbound
            .binding
            .lock()
            .expect("binding lock not poisoned") = Weak::new();
    }

    /// Removes this context's binding while owning the writer.
    ///
    /// Returns true only when it removed the binding, which allows one failure
    /// notification under this guard. Returns false if the session had already
    /// ended or been replaced.
    pub(super) fn end(&mut self, sealer: &Arc<Mutex<xhpke::Sender>>) -> bool {
        let mut binding = self
            .outbound
            .binding
            .lock()
            .expect("binding lock not poisoned");
        if Weak::ptr_eq(&Arc::downgrade(sealer), &binding) {
            *binding = Weak::new();
            true
        } else {
            false
        }
    }

    /// Writes and flushes a sealed message only into its matching binding.
    ///
    /// Releases the binding lock before I/O. The writer guard still prevents
    /// binding changes until the complete write and flush have finished.
    /// On failure, removes the binding while still holding the writer. A server
    /// then attempts notification using the failed frame's remaining budget.
    /// Timeouts skip notification. The original write error is preserved.
    pub(super) fn send(
        &mut self,
        sealer: &Arc<Mutex<xhpke::Sender>>,
        packet: &[u8],
        log_id: LogId,
    ) -> Result<(), Error> {
        // Refuse a packet sealed for an ended or replaced session
        {
            let binding = self
                .outbound
                .binding
                .lock()
                .expect("binding lock not poisoned");
            if !Weak::ptr_eq(&Arc::downgrade(sealer), &binding) {
                return Err(Error::EncryptionFailed("session ended".into()));
            }
        }

        // Write within a fresh frame budget, ending the session on failure
        let deadline = self.outbound.clock.now() + self.outbound.timeout;
        if let Err(err) = self.framer.send_packet(packet, deadline) {
            if self.end(sealer) {
                warn!("ending session {}: {}", log_id, err);
                self.notify_failure(&err, deadline);
            }
            return Err(err);
        }
        trace!(
            "sent {} message ({} bytes)",
            self.outbound.side.label(),
            packet.len()
        );
        Ok(())
    }

    /// Notifies a client about failed server output within the frame's remaining
    /// budget.
    ///
    /// Skips notification after any timeout, including one reported before the
    /// local clock reaches the deadline. For other failures, the framer
    /// terminates any partial frame before sending the signal. Notification
    /// errors never replace the original operation's error.
    fn notify_failure(&mut self, error: &Error, deadline: Instant) {
        if self.outbound.side == Side::Server
            && !matches!(error, Error::SendFailed(err) if err.kind() == io::ErrorKind::TimedOut)
            && let Err(err) = self.framer.send_dropped(deadline)
        {
            warn!("failed to signal dropped session: {}", err);
        }
    }
}

/// Tests of session binding, receive acceptance and failure notification.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::testing;
    use crate::transport::DEFAULT_WRITE_TIMEOUT;
    use crate::transport::framing::FrameReader;
    use crate::transport::testing::{Memory, test_clock};
    use crate::transport::{mock::payload, sealing};
    use std::io;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Instant;

    /// Writer exposing its bytes for assertions about frame and notification order.
    #[derive(Clone)]
    struct Collector(
        /// Bytes accepted by the adapter.
        Arc<Mutex<Vec<u8>>>,
        /// Clock governing output deadlines.
        Clock,
    );

    impl Write for Collector {
        fn clock(&self) -> Clock {
            self.1.clone()
        }

        fn set_write_deadline(&mut self, deadline: Instant) -> io::Result<()> {
            testing::remaining(&self.1, deadline)?;
            Ok(())
        }
    }

    impl io::Write for Collector {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Creates matching encryption contexts for one direction of a test session.
    fn contexts() -> (xhpke::Sender, xhpke::Receiver) {
        let key = xhpke::SecretKey::generate();
        let (sender, encap) = key.public_key().new_sender(b"test").unwrap();
        (sender, key.new_receiver(&encap, b"test").unwrap())
    }

    /// Tests that a failure notification keeps the failed frame's deadline, for
    /// both session data and handshake output.
    ///
    /// The adapter records exact deadlines after a partial write, so a fresh
    /// notification budget cannot go unnoticed.
    #[test]
    fn test_failure_notification_keeps_frame_deadline() {
        /// Writer that records adapter deadlines and fails the second partial
        /// write once.
        struct Probe {
            /// Clock used by the outgoing transport under test.
            clock: Clock,
            /// Deadline in force at each write and flush, in call order.
            calls: Arc<Mutex<Vec<Instant>>>,
            /// Latest installed write deadline.
            deadline: Option<Instant>,
        }

        impl Write for Probe {
            fn clock(&self) -> Clock {
                self.clock.clone()
            }

            fn set_write_deadline(&mut self, deadline: Instant) -> io::Result<()> {
                self.deadline = Some(deadline);
                Ok(())
            }
        }

        impl io::Write for Probe {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                let mut calls = self.calls.lock().unwrap();
                calls.push(self.deadline.expect("write deadline installed"));
                match calls.len() {
                    1 => Ok(1),
                    2 => Err(io::Error::new(io::ErrorKind::BrokenPipe, "frame failed")),
                    3 => {
                        assert_eq!(bytes, [0, 0]); // resynchronization and notification together
                        Ok(bytes.len())
                    }
                    _ => panic!("unexpected additional write"),
                }
            }

            fn flush(&mut self) -> io::Result<()> {
                self.calls
                    .lock()
                    .unwrap()
                    .push(self.deadline.expect("write deadline installed"));
                Ok(())
            }
        }

        for handshake in [false, true] {
            // Fail output on a paused clock and record each adapter deadline
            let tester = test_clock();
            let clock = tester.clock();
            let calls = Arc::new(Mutex::new(Vec::new()));
            let outbound = Arc::new(Outbound::new(
                Probe {
                    clock: clock.clone(),
                    calls: calls.clone(),
                    deadline: None,
                },
                Side::Server,
                Closer::new(&clock, || {}),
                DEFAULT_WRITE_TIMEOUT,
            ));
            let sealer = Arc::new(Mutex::new(contexts().0));
            let sender = outbound.bind(&sealer);
            let result = if handshake {
                outbound.unbind();
                outbound.send_packet(b"hello", None)
            } else {
                sender.send(b"message")
            };
            assert!(
                matches!(result, Err(Error::SendFailed(err)) if err.kind() == io::ErrorKind::BrokenPipe)
            );

            // Require failure notification to retain the original deadline
            let calls = calls.lock().unwrap();
            assert_eq!(calls.len(), 4); // partial write, failure, resync with signal, flush
            assert!(calls.iter().all(|deadline| *deadline == calls[0]));
            drop(calls);
            assert!(matches!(
                sender.send(b"late"),
                Err(Error::EncryptionFailed(_))
            ));
        }
    }

    /// Tests that failing to install the frame deadline ends the session before
    /// any byte I/O.
    #[test]
    fn test_deadline_setter_failure_ends_session() {
        /// Writer that rejects every deadline and counts the attempts, accepting
        /// no bytes.
        struct Refused(
            /// Number of deadline installation attempts.
            Arc<Mutex<usize>>,
            /// Clock shared with the outgoing transport.
            Clock,
        );

        impl Write for Refused {
            fn clock(&self) -> Clock {
                self.1.clone()
            }

            fn set_write_deadline(&mut self, _: Instant) -> io::Result<()> {
                *self.0.lock().unwrap() += 1;
                Err(io::Error::new(io::ErrorKind::TimedOut, "deadline refused"))
            }
        }

        impl io::Write for Refused {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                panic!("write after deadline setter failed")
            }

            fn flush(&mut self) -> io::Result<()> {
                panic!("flush after deadline setter failed")
            }
        }

        // Refuse deadline installation before any byte reaches the adapter
        let tester = test_clock();
        let clock = tester.clock();
        let settings = Arc::new(Mutex::new(0));
        let outbound = Arc::new(Outbound::new(
            Refused(settings.clone(), clock.clone()),
            Side::Server,
            Closer::new(&clock, || {}),
            DEFAULT_WRITE_TIMEOUT,
        ));
        let sealer = Arc::new(Mutex::new(contexts().0));
        let sender = outbound.bind(&sealer);
        assert!(matches!(
            sender.send(b"message"),
            Err(Error::SendFailed(err))
                if err.kind() == io::ErrorKind::TimedOut && err.to_string() == "deadline refused"
        ));

        // Refuse the ended session's later sends and receive completions, with
        // no further deadline attempt
        assert!(matches!(
            sender.send(b"late"),
            Err(Error::EncryptionFailed(_))
        ));
        assert!(matches!(
            outbound.finish_receive(&sealer, Ok(Vec::new())),
            Err(Error::EncryptionFailed(_))
        ));
        assert_eq!(*settings.lock().unwrap(), 1);
    }

    /// Tests that a receive accepted before a send failure stands, while one
    /// presented for acceptance after it is refused.
    #[test]
    fn test_receive_acceptance_after_send_failure() {
        // Prepare a send failure on a paused clock
        testing::init_tracing();
        let tester = test_clock();
        let clock = tester.clock();
        let outbound = Arc::new(Outbound::new(
            Memory::new(io::Cursor::new([0u8; 0]), &clock),
            Side::Client,
            Closer::new(&clock, || {}),
            DEFAULT_WRITE_TIMEOUT,
        ));
        let sealer = Arc::new(Mutex::new(contexts().0));
        let sender = outbound.bind(&sealer);
        let (mut peer, mut receiver) = contexts();

        // Accept one receive and retain another before the send fails
        let packet = sealing::seal(&mut peer, &payload(1)).unwrap();
        let accepted = outbound.finish_receive(&sealer, sealing::open(&mut receiver, &packet));
        let packet = sealing::seal(&mut peer, &payload(2)).unwrap();
        let pending = sealing::open(&mut receiver, &packet);
        assert!(pending.is_ok());

        // Keep the accepted result and refuse completion after the failure
        assert!(matches!(
            sender.send(&payload(3)),
            Err(Error::SendFailed(_))
        ));
        assert_eq!(accepted.unwrap(), payload(1));
        assert!(matches!(
            outbound.finish_receive(&sealer, pending),
            Err(Error::EncryptionFailed(_))
        ));
    }

    /// Tests that ending a session does not wait for the encryption lock.
    #[test]
    fn test_end_while_sealing() {
        // Retain the encryption lock while session ending runs
        testing::init_tracing();
        let tester = test_clock();
        let clock = tester.clock();
        let outbound = Arc::new(Outbound::new(
            Memory::new(Vec::new(), &clock),
            Side::Client,
            Closer::new(&clock, || {}),
            DEFAULT_WRITE_TIMEOUT,
        ));
        let sealer = Arc::new(Mutex::new(contexts().0));
        let sender = outbound.bind(&sealer);
        let sealing = sealer.lock().unwrap();
        let (done_tx, done) = mpsc::channel();
        let ending = {
            let outbound = outbound.clone();
            let sealer = sealer.clone();
            thread::spawn(move || {
                outbound.end(&sealer);
                done_tx.send(()).unwrap();
            })
        };

        // Require completion before releasing encryption
        let result = done.recv();
        drop(sealing);
        ending.join().unwrap();
        result.unwrap();
        assert!(matches!(
            sender.send(&payload(1)),
            Err(Error::EncryptionFailed(_))
        ));
    }

    /// Tests that repeated end calls wait for the writer's holder even after it
    /// removed the binding.
    ///
    /// The holder models a writer still sending a notification. Both callers
    /// must remain blocked until the test releases it.
    #[test]
    fn test_repeated_end_waits_for_writer() {
        // End the binding while retaining writer ownership
        testing::init_tracing();
        let tester = test_clock();
        let clock = tester.clock();
        let outbound = Arc::new(Outbound::new(
            Memory::new(Vec::new(), &clock),
            Side::Client,
            Closer::new(&clock, || {}),
            DEFAULT_WRITE_TIMEOUT,
        ));
        let sealer = Arc::new(Mutex::new(contexts().0));
        outbound.bind(&sealer);
        let release = testing::Gate::new(&clock);
        let (held, holding) = mpsc::channel();
        let owner = thread::spawn({
            let outbound = outbound.clone();
            let sealer = sealer.clone();
            let release = release.clone();
            move || {
                let mut writer = outbound.lock();
                assert!(writer.end(&sealer));
                held.send(()).unwrap();
                release.wait(None).unwrap();
            }
        });
        holding.recv().unwrap();

        // Start two end calls behind the held writer
        let (started_tx, started) = mpsc::channel();
        let (done_tx, done) = mpsc::channel();
        let ending: Vec<_> = (0..2)
            .map(|_| {
                let outbound = outbound.clone();
                let sealer = sealer.clone();
                let started_tx = started_tx.clone();
                let done_tx = done_tx.clone();
                thread::spawn(move || {
                    started_tx.send(()).unwrap();
                    outbound.end(&sealer);
                    done_tx.send(()).unwrap();
                })
            })
            .collect();
        for _ in 0..2 {
            started.recv().unwrap();
        }

        // Fence both writer acquisitions before checking that neither returned
        outbound.wait_writers(2);
        tester.wait_blocked(1);
        assert!(done.try_recv().is_err());

        // Release the writer and await both end calls
        release.open();
        owner.join().unwrap();
        for ending in ending {
            ending.join().unwrap();
        }
        for _ in 0..2 {
            done.recv().unwrap();
        }
    }

    /// Tests that a delayed failure notification cannot enter a later handshake
    /// or session, and that repeated failures notify once.
    ///
    /// Retaining the old context models an operation delayed beyond session
    /// replacement.
    #[test]
    fn test_old_notification_cannot_cross_handshake() {
        // Record output on a paused clock while retaining the old context
        testing::init_tracing();
        let tester = test_clock();
        let clock = tester.clock();
        let collector = Collector(Arc::default(), clock.clone());
        let outbound = Arc::new(Outbound::new(
            collector.clone(),
            Side::Server,
            Closer::new(&clock, || {}),
            DEFAULT_WRITE_TIMEOUT,
        ));
        let old = Arc::new(Mutex::new(contexts().0));
        outbound.bind(&old);
        let delayed = old.clone();
        let fail = || {
            let mut writer = outbound.lock();
            if writer.end(&delayed) {
                writer.notify_failure(
                    &Error::SendFailed(io::Error::other("injected failure")),
                    clock.now() + DEFAULT_WRITE_TIMEOUT,
                );
            }
        };
        fail();
        fail();

        // Only the first failure notifies, and none can cross the new handshake
        assert_eq!(*collector.0.lock().unwrap(), [0]);
        outbound.unbind();
        outbound.send_packet(b"hello", None).unwrap();
        fail();

        // Fail the old context again once a replacement session is bound
        let (crypto, mut peer) = contexts();
        let replacement = Arc::new(Mutex::new(crypto));
        let sender = outbound.bind(&replacement);
        fail();
        drop(old);
        sender.send(&payload(1)).unwrap();

        // Require exactly the notification, the hello and the replacement's
        // message, in that order
        let bytes = collector.0.lock().unwrap().clone();
        let mut reader =
            FrameReader::new(Memory::new(&bytes[..], &clock), Closer::new(&clock, || {}));
        assert!(reader.next_packet(None).unwrap().is_none());
        assert_eq!(reader.next_packet(None).unwrap(), Some(&b"hello"[..]));
        let packet = reader.next_packet(None).unwrap().unwrap();
        assert_eq!(sealing::open(&mut peer, packet).unwrap(), payload(1));
        assert!(matches!(reader.next_packet(None), Err(Error::Terminated)));
    }
}
