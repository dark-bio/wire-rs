// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Serialized output and session boundaries of one byte stream. The writer
//! orders frames, handshakes and ending; a separate, short-held binding lock
//! orders receive completion with those boundaries without waiting for I/O.

use super::framing::FrameWriter;
use super::{Closer, Error, Sender, Write};
use darkbio_crypto::xhpke;
use std::io;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};
use tracing::{trace, warn};

/// Side of the wire served by the writer. A server announces failed sends with
/// an empty frame; a client signals a reset when it initiates another handshake.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Side {
    Client,
    Server,
}

impl Side {
    /// Name of this direction's messages in traces.
    fn label(self) -> &'static str {
        match self {
            Self::Client => "host-to-ark",
            Self::Server => "ark-to-host",
        }
    }
}

/// Shared output, session binding and permanent closure of a byte stream.
/// The client/server owns this value and its crypto contexts; idle senders
/// hold weak references and active sends temporarily retain them.
///
/// Every binding change holds the writer lock first, then the binding lock.
/// Receive completion takes only the binding lock. That lock is never held
/// during crypto, I/O, or acquisition of another lock. Encryption can therefore
/// overlap a preceding write, and receiving can progress during blocked output.
/// Panics and poisoned locks are not recovered; the transport must not be reused.
pub(crate) struct Outbound<W: Write> {
    writer: Mutex<FrameWriter<W>>, // Serializes complete writes, flushes and binding changes
    binding: Mutex<Weak<Mutex<xhpke::Sender>>>, // Sole authority for the current session
    timeout: Duration, // Absolute budget for each frame, including partial writes and flush
    side: Side,        // Whether a failed send needs an empty frame notification
    closer: Closer,    // Shutdown independent of encryption, writer and binding locks
}

impl<W: Write> Outbound<W> {
    /// Creates an unbound writer around the byte stream's writing half.
    pub(crate) fn new(writer: W, side: Side, closer: Closer, timeout: Duration) -> Self {
        Self {
            writer: Mutex::new(FrameWriter::new(writer, closer.clone())),
            binding: Mutex::new(Weak::new()),
            side,
            closer,
            timeout,
        }
    }

    /// Binds a sending context and issues its sender under the writer lock.
    /// Replacing the binding ends the previous session before new messages can
    /// be written or accepted. The caller retains the context; the binding and
    /// idle senders hold weak references. This performs no crypto or stream I/O.
    /// Each handshake must supply a fresh allocation; an ended context must
    /// never be rebound, which would revive handles issued for that context.
    pub(crate) fn bind(self: &Arc<Self>, sealer: &Arc<Mutex<xhpke::Sender>>) -> Sender<W> {
        self.lock().bind(sealer);
        Sender::new(Arc::downgrade(self), Arc::downgrade(sealer))
    }

    /// Ends this context's session, waiting for the writer even on repeated or
    /// obsolete calls. Once returned, no write or flush for it remains in progress
    /// or can start. A replacement is left alone. Sealing may still finish, but
    /// its packet will be refused. Sends that obtain the writer first may finish
    /// before ending takes effect. This leaves the stream open and sends no signal.
    pub(crate) fn end(&self, sealer: &Arc<Mutex<xhpke::Sender>>) {
        self.lock().end(sealer);
    }

    /// Retires any binding before another handshake, waiting for earlier writes.
    pub(super) fn unbind(&self) {
        self.lock().unbind();
    }

    /// Completes a decrypted receive in order with binding replacement or ending.
    /// The supplied result is accepted only for the current binding; otherwise
    /// the message is discarded and an ended-session error is returned. A caller
    /// receiving an error then ends its session and releases its crypto contexts.
    ///
    /// Takes only the binding lock, with all reading and decryption already done.
    /// Success is a completed receive, not permission to perform later work.
    /// An accepted result may reach its caller after another thread ends the
    /// session; transport acceptance itself precedes that ending.
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

    /// Completes a size refusal without waiting for the writer or ending the
    /// session. Sealing has not advanced its sequence. Matching under the binding
    /// lock preserves an ended-session error for an obsolete sender instead of
    /// returning a size error for a session that no longer accepts its messages.
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
    /// Takes no send lock, so it can cancel I/O blocking session ending. Buffered
    /// receives remain available; stream closure alone does not remove the binding.
    pub(crate) fn close(&self) {
        self.closer.close();
    }

    /// Retires the old binding and writes the client's reset and fresh hello.
    /// The caller drains incoming traffic concurrently, including while this
    /// waits for a previous send. Holding the writer throughout prevents old
    /// output from entering between the reset and hello. Each frame has its own
    /// deadline; cancellation refuses further adapter calls for this attempt.
    pub(super) fn begin_handshake(&self, hello: &[u8], canceled: &AtomicBool) -> Result<(), Error> {
        let mut writer = self.lock();
        writer.unbind();
        writer
            .framer
            .send_reset(Instant::now() + self.timeout, Some(canceled))?;
        writer
            .framer
            .send_packet(hello, Instant::now() + self.timeout, Some(canceled))
    }

    /// Retires the binding and tells the client that the server has no session.
    /// Explicit responses to incoming traffic send the signal even if unbound.
    pub(crate) fn send_dropped(&self) -> Result<(), Error> {
        let mut writer = self.lock();
        writer.unbind();
        writer
            .framer
            .send_dropped(Instant::now() + self.timeout, None)
    }

    /// Writes a handshake packet through the same framer as session messages.
    /// The owner retires its old binding before starting the handshake.
    pub(super) fn send_packet(&self, packet: &[u8]) -> Result<(), Error> {
        let mut writer = self.lock();
        let deadline = Instant::now() + self.timeout;
        let result = writer.framer.send_packet(packet, deadline, None);
        if let Err(err @ Error::SendFailed(_)) = &result {
            writer.notify_failure(err, deadline);
        }
        result
    }

    /// Test and benchmark helper writing an already encoded frame.
    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(super) fn send_frame_blob(&self, frame: &[u8]) -> Result<(), Error> {
        let mut writer = self.lock();
        writer
            .framer
            .send_frame_blob(frame, Instant::now() + self.timeout, None)
    }

    /// Acquires exclusive output ownership. A sender retains its encryption
    /// guard until this returns, preserving sealing order through the handoff.
    /// A poisoned writer is an implementation failure and is not recovered.
    pub(super) fn lock(&self) -> Writer<'_, W> {
        Writer {
            outbound: self,
            framer: self.writer.lock().expect("writer lock not poisoned"),
        }
    }
}

/// Exclusive ownership of the framer and the right to change its binding.
/// Keeping this guard alive prevents any other operation from replacing or
/// removing the binding, including while its short-lived mutex is unlocked.
/// Dropping the guard releases the writer; it performs no I/O or session cleanup.
pub(super) struct Writer<'a, W: Write> {
    outbound: &'a Outbound<W>,
    framer: MutexGuard<'a, FrameWriter<W>>,
}

impl<W: Write> Writer<'_, W> {
    /// Replaces the binding while owning the writer, ending its predecessor.
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

    /// Removes this binding while owning the writer. True reports an actual
    /// removal, allowing its failure notification under the same writer guard.
    /// False means the session had already ended or been replaced.
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
    /// The binding lock is released before I/O, but this writer guard prevents
    /// any binding change until the complete write and flush have finished.
    /// Failure retires the binding and notifies the client before releasing
    /// the writer, preserving the original write error.
    pub(super) fn send(
        &mut self,
        sealer: &Arc<Mutex<xhpke::Sender>>,
        packet: &[u8],
    ) -> Result<(), Error> {
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
        let deadline = Instant::now() + self.outbound.timeout;
        if let Err(err) = self.framer.send_packet(packet, deadline, None) {
            if self.end(sealer) {
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

    /// Notifies a client about failed output within that frame's remaining
    /// budget. A timeout leaves no notification budget, even when reported by
    /// the adapter before the local clock reaches the deadline. Other failures
    /// may leave a partial frame, which the framer terminates before its signal.
    /// Notification errors never replace the original operation's error.
    fn notify_failure(&mut self, error: &Error, deadline: Instant) {
        if self.outbound.side == Side::Server
            && !matches!(error, Error::SendFailed(err) if err.kind() == io::ErrorKind::TimedOut)
            && let Err(err) = self.framer.send_dropped(deadline, None)
        {
            warn!("failed to notify client of ended session: {}", err);
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::testing;
    use crate::transport::DEFAULT_WRITE_TIMEOUT;
    use crate::transport::framing::FrameReader;
    use crate::transport::testing::Memory;
    use crate::transport::{mock::payload, sealing};
    use std::io;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    /// Writer exposing its bytes for assertions about frame and notification order.
    #[derive(Clone, Default)]
    struct Collector(Arc<Mutex<Vec<u8>>>);

    impl Write for Collector {
        fn set_write_deadline(&mut self, deadline: Instant) -> io::Result<()> {
            testing::remaining(deadline)?;
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

    /// Matching encryption contexts for one direction of a test session.
    fn contexts() -> (xhpke::Sender, xhpke::Receiver) {
        let key = xhpke::SecretKey::generate();
        let (sender, encap) = key.public_key().new_sender(b"test").unwrap();
        (sender, key.new_receiver(&encap, b"test").unwrap())
    }

    // Tests the budget across an output failure and its notification, for both
    // session data and handshake output. The adapter records exact deadlines
    // after a partial write so a fresh notification budget cannot go unnoticed.
    #[test]
    fn test_failure_notification_keeps_frame_deadline() {
        /// Records adapter deadlines and fails the second partial write once.
        struct Probe {
            calls: Arc<Mutex<Vec<Instant>>>,
            deadline: Option<Instant>,
        }

        impl Write for Probe {
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
                        assert_eq!(bytes, [0, 0]); // Resynchronization and notification together.
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
            let calls = Arc::new(Mutex::new(Vec::new()));
            let outbound = Arc::new(Outbound::new(
                Probe {
                    calls: calls.clone(),
                    deadline: None,
                },
                Side::Server,
                Closer::new(|| {}),
                DEFAULT_WRITE_TIMEOUT,
            ));
            let sealer = Arc::new(Mutex::new(contexts().0));
            let sender = outbound.bind(&sealer);
            let result = if handshake {
                outbound.unbind();
                outbound.send_packet(b"hello")
            } else {
                sender.send(b"message")
            };
            assert!(
                matches!(result, Err(Error::SendFailed(err)) if err.kind() == io::ErrorKind::BrokenPipe)
            );
            let calls = calls.lock().unwrap();
            assert_eq!(calls.len(), 4); // Partial write, failure, resync with signal, flush.
            assert!(calls.iter().all(|deadline| *deadline == calls[0]));
            drop(calls);
            assert!(matches!(
                sender.send(b"late"),
                Err(Error::EncryptionFailed(_))
            ));
        }
    }

    // Tests that failing to install the frame deadline ends the session before
    // adapter I/O. The sender reports the original error and retained handles
    // cannot send or accept a received message after that failure.
    #[test]
    fn test_deadline_setter_failure_ends_session() {
        /// Rejects output configuration and records attempts without accepting bytes.
        struct Refused(Arc<Mutex<usize>>);

        impl Write for Refused {
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

        let settings = Arc::new(Mutex::new(0));
        let outbound = Arc::new(Outbound::new(
            Refused(settings.clone()),
            Side::Server,
            Closer::new(|| {}),
            DEFAULT_WRITE_TIMEOUT,
        ));
        let sealer = Arc::new(Mutex::new(contexts().0));
        let sender = outbound.bind(&sealer);
        assert!(matches!(
            sender.send(b"message"),
            Err(Error::SendFailed(err))
                if err.kind() == io::ErrorKind::TimedOut && err.to_string() == "deadline refused"
        ));
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

    // Tests both orders of receive acceptance and a send failure. A message
    // accepted first remains a completed result. Another already decrypted
    // message, representing a receiver paused before acceptance, is refused
    // after the write fails even though its crypto operation succeeded.
    #[test]
    fn test_receive_acceptance_after_send_failure() {
        testing::init_tracing();

        let outbound = Arc::new(Outbound::new(
            Memory::new(io::Cursor::new([0u8; 0])),
            Side::Client,
            Closer::new(|| {}),
            DEFAULT_WRITE_TIMEOUT,
        ));
        let sealer = Arc::new(Mutex::new(contexts().0));
        let sender = outbound.bind(&sealer);
        let (mut peer, mut receiver) = contexts();

        let packet = sealing::seal(&mut peer, &payload(1)).unwrap();
        let accepted = outbound.finish_receive(&sealer, sealing::open(&mut receiver, &packet));
        let packet = sealing::seal(&mut peer, &payload(2)).unwrap();
        let pending = sealing::open(&mut receiver, &packet);
        assert!(pending.is_ok());

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

    // Tests that ending does not wait for crypto. The sending context remains
    // locked until ending completes, after which its sender cannot write.
    #[test]
    fn test_end_while_sealing() {
        testing::init_tracing();

        let outbound = Arc::new(Outbound::new(
            Memory::new(Vec::new()),
            Side::Client,
            Closer::new(|| {}),
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
        let result = done.recv_timeout(Duration::from_secs(5));
        drop(sealing);
        ending.join().unwrap();
        result.unwrap();
        assert!(matches!(
            sender.send(&payload(1)),
            Err(Error::EncryptionFailed(_))
        ));
    }

    // Tests that repeated end calls wait for the winning writer even after it
    // removes the binding, as when that writer is still sending a notification.
    // Both callers must remain blocked until the test releases that writer.
    #[test]
    fn test_repeated_end_waits_for_writer() {
        testing::init_tracing();

        let outbound = Arc::new(Outbound::new(
            Memory::new(Vec::new()),
            Side::Client,
            Closer::new(|| {}),
            DEFAULT_WRITE_TIMEOUT,
        ));
        let sealer = Arc::new(Mutex::new(contexts().0));
        outbound.bind(&sealer);
        let mut writer = outbound.lock();
        assert!(writer.end(&sealer));
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
            started.recv_timeout(Duration::from_secs(5)).unwrap();
        }
        let early = done.recv_timeout(Duration::from_millis(50));
        drop(writer);
        for ending in ending {
            ending.join().unwrap();
        }
        assert!(matches!(early, Err(mpsc::RecvTimeoutError::Timeout)));
        for _ in 0..2 {
            done.recv_timeout(Duration::from_secs(5)).unwrap();
        }
    }

    // Tests that a delayed failure notification cannot enter a subsequent
    // handshake or session, and repeated failures notify only once. Retaining
    // the old context models an operation delayed beyond session replacement.
    #[test]
    fn test_old_notification_cannot_cross_handshake() {
        testing::init_tracing();

        let collector = Collector::default();
        let outbound = Arc::new(Outbound::new(
            collector.clone(),
            Side::Server,
            Closer::new(|| {}),
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
                    Instant::now() + DEFAULT_WRITE_TIMEOUT,
                );
            }
        };
        fail();
        fail();

        // Only the first failure notifies, and none can cross the new handshake.
        assert_eq!(*collector.0.lock().unwrap(), [0]);
        outbound.unbind();
        outbound.send_packet(b"hello").unwrap();
        fail();

        let (crypto, mut peer) = contexts();
        let replacement = Arc::new(Mutex::new(crypto));
        let sender = outbound.bind(&replacement);
        fail();
        drop(old);
        sender.send(&payload(1)).unwrap();

        let bytes = collector.0.lock().unwrap().clone();
        let mut reader = FrameReader::new(Memory::new(&bytes[..]), Closer::new(|| {}));
        assert!(reader.next_packet(None).unwrap().is_none());
        assert_eq!(reader.next_packet(None).unwrap(), Some(&b"hello"[..]));
        let packet = reader.next_packet(None).unwrap().unwrap();
        assert_eq!(sealing::open(&mut peer, packet).unwrap(), payload(1));
        assert!(matches!(reader.next_packet(None), Err(Error::Terminated)));
    }
}
