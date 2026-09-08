// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Serialized output of one byte stream. The client/server owns encryption;
//! the writer orders its frames with handshake traffic and reset notifications.

use super::framing::FrameWriter;
use super::{Closer, Error, Sender};
use darkbio_crypto::xhpke;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
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

/// Output and permanent closure of a byte stream, owned by its client or server.
/// Senders hold weak references and active sends temporarily retain it. The
/// encryption contexts belong to the client/server and share this writer.
pub(crate) struct Outbound<W: Write> {
    writer: Mutex<Writer<W>>, // Frames and session boundaries serialized together
    closer: Closer,           // Shutdown independent of the writer lock
}

impl<W: Write> Outbound<W> {
    /// Creates an unbound writer around the byte stream's writing half.
    pub(crate) fn new(writer: W, side: Side, closer: Closer) -> Self {
        Self {
            writer: Mutex::new(Writer {
                framer: FrameWriter::new(writer, closer.clone()),
                binding: Weak::new(),
                ended: Weak::new(),
                side,
            }),
            closer,
        }
    }

    /// Binds a sending context and its fresh termination flag, issuing a sender
    /// under the same lock used to write frames. The caller retains both; the
    /// writer and idle senders hold weak references. Previous senders are
    /// invalidated before the new session can write.
    pub(crate) fn bind(
        self: &Arc<Self>,
        sealer: &Arc<Mutex<xhpke::Sender>>,
        ended: &Arc<AtomicBool>,
    ) -> Sender<W> {
        let mut writer = self.lock();
        writer.unbind();
        writer.binding = Arc::downgrade(sealer);
        writer.ended = Arc::downgrade(ended);
        Sender::new(
            Arc::downgrade(self),
            Arc::downgrade(sealer),
            Arc::downgrade(ended),
        )
    }

    /// Retires the writer's binding before a server starts another handshake.
    /// Delayed failure notifications from the previous session are then ignored.
    pub(super) fn unbind(&self) {
        self.lock().unbind();
    }

    /// Returns the stream's shutdown handle without taking the writer lock.
    pub(crate) fn closer(&self) -> Closer {
        self.closer.clone()
    }

    /// Permanently closes the byte stream and waits for adapter shutdown.
    /// Takes no writer lock; session operations observe closure through I/O.
    pub(crate) fn close(&self) {
        self.closer.close();
    }

    /// Retires the session binding and sends the client's reset as one ordered
    /// operation. No old frame or notification can follow it onto the stream.
    pub(super) fn send_reset(&self) -> Result<(), Error> {
        let mut writer = self.lock();
        writer.unbind();
        writer.framer.send_reset()
    }

    /// Retires the binding and tells the client that the server has no session.
    pub(crate) fn send_dropped(&self) -> Result<(), Error> {
        let mut writer = self.lock();
        writer.unbind();
        writer.framer.send_dropped()
    }

    /// Writes a handshake packet through the same framer as session messages.
    /// The owner retires its old binding before starting the handshake.
    pub(super) fn send_packet(&self, packet: &[u8]) -> Result<(), Error> {
        self.lock().framer.send_packet(packet)
    }

    /// Test and benchmark helper writing an already encoded frame.
    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(super) fn send_frame_blob(&self, frame: &[u8]) -> Result<(), Error> {
        self.lock().framer.send_frame_blob(frame)
    }

    /// Notifies the client that a failed send ended this session by writing an
    /// empty frame. The caller must mark the session ended before calling this.
    ///
    /// Takes the writer lock, then checks that this is the server side and the
    /// same session is still bound. A notification delayed past unbinding or a
    /// replacement is skipped, so it cannot interrupt a later handshake or
    /// session. The client side signals its reset when starting another handshake.
    /// Notification failures are logged, preserving the original send error.
    pub(super) fn notify_session_ended(&self, sealer: &Arc<Mutex<xhpke::Sender>>) {
        self.lock().notify_session_ended(sealer);
    }

    /// Locks the writer, ending its bound session if a previous write panicked.
    /// The framer retains its buffer and resynchronizes before the next write.
    pub(super) fn lock(&self) -> MutexGuard<'_, Writer<W>> {
        self.writer.lock().unwrap_or_else(|poisoned| {
            let writer = poisoned.into_inner();
            if let Some(ended) = writer.ended.upgrade() {
                ended.store(true, Ordering::Release);
            }
            self.writer.clear_poison();
            writer
        })
    }
}

/// Framer and its session binding, protected by the output lock. Checking the
/// binding and writing a frame or failure notification form one operation.
pub(super) struct Writer<W: Write> {
    framer: FrameWriter<W>, // Reused across handshakes, retaining framing recovery state
    binding: Weak<Mutex<xhpke::Sender>>, // Encryption allocation whose frames may be written
    ended: Weak<AtomicBool>, // Termination flag of the bound encryption context
    side: Side,             // Whether failed sends need an empty frame notification
}

impl<W: Write> Writer<W> {
    /// Whether this allocation owns the wire, checked only under the writer lock.
    fn bound_to(&self, sealer: &Arc<Mutex<xhpke::Sender>>) -> bool {
        Weak::ptr_eq(&Arc::downgrade(sealer), &self.binding)
    }

    /// Ends and removes the current binding while holding the writer lock.
    fn unbind(&mut self) {
        if let Some(ended) = self.ended.upgrade() {
            ended.store(true, Ordering::Release);
        }
        self.binding = Weak::new();
        self.ended = Weak::new();
    }

    /// Checks the session after its send acquires the writer lock, then writes
    /// its sealed frame. A write failure ends that session and notifies the client
    /// before any handshake or other message can acquire the writer.
    pub(super) fn send(
        &mut self,
        sealer: &Arc<Mutex<xhpke::Sender>>,
        packet: &[u8],
    ) -> Result<(), Error> {
        if !self.bound_to(sealer) {
            return Err(Error::EncryptionFailed("session ended".into()));
        }
        let ended = self
            .ended
            .upgrade()
            .ok_or_else(|| Error::EncryptionFailed("session ended".into()))?;
        if ended.load(Ordering::Acquire) {
            return Err(Error::EncryptionFailed("session ended".into()));
        }
        if let Err(err) = self.framer.send_packet(packet) {
            ended.store(true, Ordering::Release);
            self.notify_session_ended(sealer);
            return Err(err);
        }
        trace!(
            "sent {} message ({} bytes)",
            self.side.label(),
            packet.len()
        );
        Ok(())
    }

    /// Writes and flushes an empty frame on the server side if the ended session
    /// still matches this writer's binding. The caller has already ended the
    /// session and holds the writer lock, keeping this check and notification
    /// ordered with handshakes and other sends. Client-side and obsolete-session
    /// calls do nothing; write failures are logged instead of replacing the
    /// original send error. The binding itself is left in place.
    fn notify_session_ended(&mut self, sealer: &Arc<Mutex<xhpke::Sender>>) {
        if self.side == Side::Server
            && self.bound_to(sealer)
            && let Err(err) = self.framer.send_dropped()
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
    use crate::transport::framing::FrameReader;
    use crate::transport::{mock::payload, sealing};
    use std::io;

    /// Writer exposing its bytes for assertions about frame and notification order.
    #[derive(Clone, Default)]
    struct Collector(Arc<Mutex<Vec<u8>>>);

    impl Write for Collector {
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

    // Tests that a delayed failure notification cannot enter a subsequent
    // handshake or session. Retaining the old binding models a send that already
    // failed but has not yet acquired the writer to notify the client.
    #[test]
    fn test_old_notification_cannot_cross_handshake() {
        testing::init_tracing();

        let collector = Collector::default();
        let outbound = Arc::new(Outbound::new(
            collector.clone(),
            Side::Server,
            Closer::new(|| {}),
        ));
        let old = Arc::new(Mutex::new(contexts().0));
        let old_ended = Arc::new(AtomicBool::new(false));
        outbound.bind(&old, &old_ended);
        let delayed = outbound.lock().binding.upgrade().unwrap();
        old_ended.store(true, Ordering::Release);
        outbound.notify_session_ended(&delayed);

        // The old session can notify until the writer starts the new handshake.
        assert_eq!(*collector.0.lock().unwrap(), [0]);
        outbound.unbind();
        outbound.send_packet(b"hello").unwrap();
        outbound.notify_session_ended(&delayed);

        let (crypto, mut peer) = contexts();
        let replacement = Arc::new(Mutex::new(crypto));
        let ended = Arc::new(AtomicBool::new(false));
        let sender = outbound.bind(&replacement, &ended);
        outbound.notify_session_ended(&delayed);
        drop(old);
        sender.send(&payload(1)).unwrap();

        let bytes = collector.0.lock().unwrap().clone();
        let mut reader = FrameReader::new(&bytes[..], Closer::new(|| {}));
        assert!(reader.next_packet().unwrap().is_none());
        assert_eq!(reader.next_packet().unwrap(), Some(&b"hello"[..]));
        let packet = reader.next_packet().unwrap().unwrap();
        assert_eq!(sealing::open(&mut peer, packet).unwrap(), payload(1));
        assert!(matches!(reader.next_packet(), Err(Error::Terminated)));
    }
}
