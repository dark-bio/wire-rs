// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Session-bound handles for sending messages. All senders share one outbound
//! side, which seals and writes their messages onto the wire in order, every sender
//! getting its own result. Sealing and writing overlap, the next message
//! sealing while the one before it is written, the wire order never differing
//! from the sealing order. A sender is bound to the session it was made in
//! and holds the outbound side only as long as the owner does.

use crate::transport::framing::FrameWriter;
use crate::transport::sealing;
use crate::transport::{Closer, Error};
use darkbio_crypto::xhpke;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError, Weak};
use tracing::{trace, warn};

/// Session number used when no outgoing session is installed.
const NONE: u64 = 0;

/// Side of the wire the outgoing transport serves. After a failed send, the
/// server tells the client with an empty frame that its session is gone. The
/// client initiates reconnection itself, sending a reset before the handshake,
/// so it needs no separate failure notification to the server.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Side {
    Client,
    Server,
}

impl Side {
    /// Whether a failed send is followed by the frame telling the peer its
    /// session is gone.
    fn announces_drops(self) -> bool {
        self == Self::Server
    }

    /// Name of the messages the side sends, for the traces.
    fn label(self) -> &'static str {
        match self {
            Self::Client => "host-to-ark",
            Self::Server => "ark-to-host",
        }
    }
}

/// Sealing phase of the outbound side, the context fixing the sequence.
struct Sealer {
    sender: Option<xhpke::Sender>, // Context sealing the live session's messages, none without one
    sessions: u64,                 // Number of sessions established so far, the live one's number
}

/// Outgoing side of the transport, owned by a client or a server and shared with
/// the senders they hand out, which hold it weakly. It holds the outbound
/// HPKE context and the frame writer, and every send passes through it, so
/// all senders share one sequence and one stream.
///
/// Sessions are numbered as they are established and a send is accepted only
/// into the live one, a message of an earlier session refused rather than
/// delivered to the wrong peer. A send that fails after sealing ends the
/// session, as the peer cannot follow the sequence past the gap. On the
/// server's side, which serves clients across sessions, the empty frame
/// telling the client its session is gone follows, so the client handshakes
/// again. The client's side recovers by starting that handshake and sends
/// nothing. Ending a session takes no send lock. Closing the outbound side cancels
/// adapter I/O and waits for it to return, also without taking a send lock.
/// The outbound side goes with its owner and the sends in progress, the transport
/// with it.
///
/// Sealing and writing run under two locks taken hand over hand, the write
/// lock before the seal lock is released, which keeps the wire order equal to
/// the sealing order while the next message seals behind the one going out.
pub(crate) struct Outbound<W: Write> {
    sealer: Mutex<Sealer>,         // Sealing phase, taken first
    framer: Mutex<FrameWriter<W>>, // Writing phase, taken second
    session: AtomicU64,            // Number of the live session, NONE without
    closer: Closer,                // Permanent closure of the underlying stream

    side: Side, // Side of the wire served, deciding what follows a failed send
}

impl<W: Write> Outbound<W> {
    /// Creates the outbound side around a low level writer, without a session
    /// until a handshake establishes one.
    pub fn new(writer: W, side: Side, close: Closer) -> Self {
        let framer = FrameWriter::new(writer, close.clone());
        Self {
            sealer: Mutex::new(Sealer {
                sender: None,
                sessions: 0,
            }),
            framer: Mutex::new(framer),
            session: AtomicU64::new(NONE),
            closer: close,
            side,
        }
    }

    /// Installs the context of a freshly established session, the next one by
    /// number, returning a handle bound to it. Sends go out from here on.
    pub fn establish_session(self: &Arc<Self>, sender: xhpke::Sender) -> Sender<W> {
        let mut sealer = self.lock(&self.sealer);
        sealer.sender = Some(sender);

        // The count reaches the reserved numbers after 2^64 handshakes, each a
        // few milliseconds of lattice cryptography and a round trip, half a
        // billion years at a thousand a second, so nothing guards against it
        sealer.sessions += 1;
        self.session.store(sealer.sessions, Ordering::Release);
        Sender::new(Arc::downgrade(self), sealer.sessions)
    }

    /// Ends the session for the sends, the handles made in it refused from
    /// here on, the next handshake handing out new ones. Takes no lock, so a
    /// send stuck in the transport cannot hold it up, the context going once
    /// the sealer is free.
    pub fn drop_session(&self) {
        self.end_session();
        if let Some(mut sealer) = self.try_lock(&self.sealer) {
            sealer.sender = None;
        }
    }

    /// Whether a session is installed for sends. Stream closure is observed
    /// through I/O; this does not report whether the stream is open.
    pub fn has_session(&self) -> bool {
        self.session.load(Ordering::Acquire) != NONE
    }

    /// Mock helper exposing the installed session number, or zero without one.
    /// Closing the stream alone does not clear the session.
    #[cfg(any(test, feature = "fuzz"))]
    pub fn session_id(&self) -> u64 {
        self.session.load(Ordering::Acquire)
    }

    /// Handle ending the underlying stream without taking either send lock.
    pub fn closer(&self) -> Closer {
        self.closer.clone()
    }

    /// Permanently closes the byte stream and waits for adapter shutdown.
    /// Sends observe closure through their write results. The outbound side itself
    /// goes with the owner's reference and the sends in progress, the
    /// framer and the transport with it, so a sender outliving its owner
    /// holds nothing, its weak reference failing to upgrade.
    pub fn close(&self) {
        self.closer.close();
    }

    /// Seals a message with the session and sends it. Fails unless the session
    /// is the live one. A message too large is rejected before sealing and
    /// leaves the session alone, a failure after sealing ends it, as the peer's
    /// HPKE sequence can no longer be caught up with.
    pub fn send(&self, session: u64, message: &[u8]) -> Result<(), Error> {
        // Refuse before taking any lock what the locks would refuse anyway, so
        // a send does not queue behind one stuck in the transport for nothing
        self.check(session)?;

        // Seal under the seal lock, fixing the message's place in the sequence
        let mut sealer = self.lock(&self.sealer);
        self.check(session)?;

        let sender = sealer
            .sender
            .as_mut()
            .expect("live session has its context");

        let packet = match sealing::seal(sender, message) {
            Err(err @ Error::EncryptionFailed(_)) => {
                self.end_session();
                drop(sealer);
                self.announce_dropped();
                return Err(err);
            }
            Err(err) => return Err(err),
            Ok(packet) => packet,
        };
        // Take the write lock before letting go of the seal lock, so the wire
        // order is the sealing order, the next sender sealing meanwhile
        let mut framer = self.lock(&self.framer);
        drop(sealer);

        // A session that ended while the message waited for its turn cannot
        // carry it anymore, the peer will not follow the sequence
        self.check(session)?;
        self.write(&mut framer, &packet)
    }

    /// Signals a session reset, see `FrameWriter::send_reset`.
    pub fn send_reset(&self) -> Result<(), Error> {
        self.with_framer(|framer| framer.send_reset())
    }

    /// Signals a dropped session, see `FrameWriter::send_dropped`.
    pub fn send_dropped(&self) -> Result<(), Error> {
        self.with_framer(|framer| framer.send_dropped())
    }

    /// Sends a packet outside the session, the handshake's own, see
    /// `FrameWriter::send_packet`.
    pub fn send_packet(&self, packet: &[u8]) -> Result<(), Error> {
        self.with_framer(|framer| framer.send_packet(packet))
    }

    /// Test and benchmark helper exposing the framer's `send_frame`.
    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn send_frame_blob(&self, frame: &[u8]) -> Result<(), Error> {
        self.with_framer(|framer| framer.send_frame_blob(frame))
    }

    /// Writes a sealed packet, a failure ending the session and, on the
    /// server's side, telling the client so.
    fn write(&self, framer: &mut FrameWriter<W>, packet: &[u8]) -> Result<(), Error> {
        if let Err(err) = framer.send_packet(packet) {
            self.end_session();
            if self.side.announces_drops()
                && let Err(err) = framer.send_dropped()
            {
                warn!("failed to announce dropped session: {}", err);
            }
            return Err(err);
        }
        trace!(
            "sent {} message ({} bytes)",
            self.side.label(),
            packet.len()
        );
        Ok(())
    }

    /// Runs a write of the owner's own under the write lock, the handshake's
    /// packets and the frames signaling a session's fate.
    fn with_framer(
        &self,
        write: impl FnOnce(&mut FrameWriter<W>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut framer = self.lock(&self.framer);
        write(&mut framer)
    }

    /// Checks that the session is the live one, a message of any other refused
    /// as the peer would not follow its sequence.
    fn check(&self, session: u64) -> Result<(), Error> {
        match self.session.load(Ordering::Acquire) {
            NONE => Err(Error::EncryptionFailed("no active session".into())),
            live if live == session => Ok(()),
            _ => Err(Error::EncryptionFailed("session ended".into())),
        }
    }

    /// Ends the live session. Permanent closure belongs to the byte stream.
    fn end_session(&self) {
        self.session.store(NONE, Ordering::Release);
    }

    /// Tells the client the session is gone if this is the server's side,
    /// logging an announcement that cannot be sent.
    fn announce_dropped(&self) {
        if self.side.announces_drops()
            && let Err(err) = self.send_dropped()
        {
            warn!("failed to announce dropped session: {}", err);
        }
    }

    /// Locks one of the outbound side's mutexes. A poisoned one means a send panicked
    /// midway, the message it sealed never written, so the peer cannot follow
    /// the sequence anymore and the session ends. The state itself stays
    /// usable, the framer keeping its buffer through a panic.
    fn lock<'a, T>(&self, mutex: &'a Mutex<T>) -> MutexGuard<'a, T> {
        mutex.lock().unwrap_or_else(|poisoned| {
            self.end_session();
            mutex.clear_poison();
            poisoned.into_inner()
        })
    }

    /// Locks one of the outbound side's mutexes if nobody holds it, a poisoned one
    /// handled as in `lock`.
    fn try_lock<'a, T>(&self, mutex: &'a Mutex<T>) -> Option<MutexGuard<'a, T>> {
        match mutex.try_lock() {
            Ok(guard) => Some(guard),
            Err(TryLockError::Poisoned(poisoned)) => {
                self.end_session();
                mutex.clear_poison();
                Some(poisoned.into_inner())
            }
            Err(TryLockError::WouldBlock) => None,
        }
    }
}

/// Cloneable handle for sending messages into a session from any thread.
/// Delivered by [`Client::connect`](super::Client::connect) or a server's
/// [`Event::Connected`](super::Event::Connected) event.
/// Sends share one encryption sequence and are written in that order, each
/// waiting for its own frame and getting its own result. The
/// handle is bound to the session it was made in and refused once that ended,
/// whether by a failure, a new handshake or the owner going, so a message
/// meant for one peer never reaches the next. A new session needs a new
/// handle from the owner. The handle keeps nothing alive on its own, once the
/// owner is gone only a send in progress holds the transport, until it
/// returns.
#[derive(Debug)]
pub struct Sender<W: Write> {
    outbound: Weak<Outbound<W>>, // Outgoing transport, kept alive by the owner and active sends
    session: u64,                // Number of the session the handle sends into
}

impl<W: Write> Sender<W> {
    /// Creates a handle onto an outbound side, bound to the session.
    fn new(outbound: Weak<Outbound<W>>, session: u64) -> Self {
        Self { outbound, session }
    }

    /// Seals the message and writes and flushes its complete frame. Concurrent
    /// sends take turns in encryption order, each waiting for its own write.
    /// An oversized message is refused without ending the session; encryption
    /// or write failure ends it. Stream closure is observed through write
    /// failure; an overlapping send may succeed. Returns [`Error::Terminated`]
    /// if the owner is gone, and refuses a handle from an ended session.
    pub fn send(&self, message: &[u8]) -> Result<(), Error> {
        let outbound = self.outbound.upgrade().ok_or(Error::Terminated)?;
        outbound.send(self.session, message)
    }
}

impl<W: Write> Clone for Sender<W> {
    fn clone(&self) -> Self {
        Self::new(self.outbound.clone(), self.session)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::testing;
    use crate::transport::framing::FrameReader;
    use crate::transport::mock::payload;
    use std::io;
    use std::panic::{self, AssertUnwindSafe};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    /// A pair of contexts standing in for an established session.
    fn contexts() -> (xhpke::Sender, xhpke::Receiver) {
        let secret = xhpke::SecretKey::generate();
        let (sender, encap) = secret.public_key().new_sender(b"test").unwrap();
        let receiver = secret.new_receiver(&encap, b"test").unwrap();
        (sender, receiver)
    }

    /// Writer collecting everything written into a shared buffer.
    #[derive(Clone, Default)]
    struct Collector(Arc<Mutex<Vec<u8>>>);

    impl Write for Collector {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Writer holding its first write until released, then failing it or
    /// panicking inside it, the ones after passing, and reporting its drop.
    struct Gate {
        entered: mpsc::Sender<()>,
        release: Option<mpsc::Receiver<()>>,
        dropped: mpsc::Sender<()>,
        panics: bool,
    }

    impl Gate {
        /// Creates the gate along with the channel telling that a write is
        /// held, the one releasing it and the one telling that the gate was
        /// dropped.
        fn new() -> (
            Self,
            mpsc::Receiver<()>,
            mpsc::Sender<()>,
            mpsc::Receiver<()>,
        ) {
            let (entered_tx, entered) = mpsc::channel();
            let (release, release_rx) = mpsc::channel();
            let (dropped_tx, dropped) = mpsc::channel();
            let gate = Self {
                entered: entered_tx,
                release: Some(release_rx),
                dropped: dropped_tx,
                panics: false,
            };
            (gate, entered, release, dropped)
        }
    }

    impl Write for Gate {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            match self.release.take() {
                Some(release) => {
                    let _ = self.entered.send(());
                    let _ = release.recv();
                    if self.panics {
                        panic!("injected panic");
                    }
                    Err(io::Error::other("gate closed"))
                }
                None => Ok(buf.len()),
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Drop for Gate {
        fn drop(&mut self) {
            let _ = self.dropped.send(());
        }
    }

    /// Writer panicking on its first write and collecting the ones after.
    struct Panicky {
        armed: bool,
        written: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for Panicky {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if std::mem::take(&mut self.armed) {
                panic!("injected panic");
            }
            self.written.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    // Tests that messages sent from many threads at once go out in the order
    // they were sealed, every one opening in sequence on the receiving side.
    #[test]
    fn test_send_order() {
        testing::init_tracing();

        let (sender, mut receiver) = contexts();
        let collector = Collector::default();
        let outbound = Arc::new(Outbound::new(
            collector.clone(),
            Side::Client,
            Closer::new(|| {}),
        ));
        let sender = outbound.establish_session(sender);

        let threads: Vec<_> = (0..8)
            .map(|thread| {
                let sender = sender.clone();
                thread::spawn(move || {
                    for i in 0..20 {
                        sender.send(&payload(thread * 100 + i)).unwrap();
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }

        // Every frame must open in the order written, or the sequence is off
        let written = collector.0.lock().unwrap().clone();
        let mut reader = FrameReader::new(&written[..], Closer::new(|| {}));
        let mut messages = Vec::new();
        loop {
            let packet = match reader.next_packet() {
                Err(Error::Terminated) => break,
                result => result.unwrap().unwrap(),
            };
            messages.push(sealing::open(&mut receiver, packet).unwrap());
        }
        messages.sort_unstable();
        let mut expected: Vec<Vec<u8>> = (0..8)
            .flat_map(|thread| (0..20).map(move |i| payload(thread * 100 + i)))
            .collect();
        expected.sort_unstable();
        assert_eq!(messages, expected);
    }

    // Tests that a failed write is reported to the sender it failed, that a
    // message sealed behind it is refused rather than written, and that every
    // later one is refused before sealing.
    #[test]
    fn test_send_failure_attribution() {
        testing::init_tracing();

        let (gate, entered, release, _) = Gate::new();
        let (sender, _) = contexts();
        let outbound = Arc::new(Outbound::new(gate, Side::Client, Closer::new(|| {})));
        let sender: Sender<Gate> = outbound.establish_session(sender);

        // The first sender blocks inside its write, the second seals behind it
        // and waits for the write lock. The wait gives it time to get there,
        // though it is refused the same if it only seals after the failure.
        let first = {
            let sender = sender.clone();
            thread::spawn(move || sender.send(&payload(1)))
        };
        entered.recv().unwrap();
        let second = {
            let sender = sender.clone();
            thread::spawn(move || sender.send(&payload(2)))
        };
        thread::sleep(Duration::from_millis(50));

        // The write fails, taking the session with it
        release.send(()).unwrap();
        let result = first.join().unwrap();
        assert!(matches!(result, Err(Error::SendFailed(_))), "{result:?}");
        let result = second.join().unwrap();
        assert!(
            matches!(result, Err(Error::EncryptionFailed(_))),
            "{result:?}"
        );
        let result = sender.send(&payload(3));
        assert!(
            matches!(result, Err(Error::EncryptionFailed(_))),
            "{result:?}"
        );
        assert!(!outbound.has_session());
    }

    // Tests that sends are refused without a session, after one ended, once
    // the owner closed the outbound side and once it is gone, and that a handle stays
    // bound to the session it was made in while a fresh one sends into the
    // new session.
    #[test]
    fn test_send_refusals() {
        testing::init_tracing();

        let outbound = Arc::new(Outbound::new(Vec::new(), Side::Client, Closer::new(|| {})));
        let detached = Sender::new(Arc::downgrade(&outbound), NONE);
        let result = detached.send(&payload(1));
        assert!(
            matches!(&result, Err(Error::EncryptionFailed(msg)) if msg == "no active session"),
            "{result:?}"
        );

        // A session established, only a handle made in it sends
        let (sender, _) = contexts();
        let first: Sender<Vec<u8>> = outbound.establish_session(sender);
        first.send(&payload(2)).unwrap();
        let result = detached.send(&payload(3));
        assert!(
            matches!(&result, Err(Error::EncryptionFailed(msg)) if msg == "session ended"),
            "{result:?}"
        );

        // The session ended, nothing sends without one
        outbound.drop_session();
        assert!(!outbound.has_session());
        let result = first.send(&payload(4));
        assert!(
            matches!(&result, Err(Error::EncryptionFailed(msg)) if msg == "no active session"),
            "{result:?}"
        );

        // The next session refuses the handle of the previous one
        let (sender, _) = contexts();
        let second = outbound.establish_session(sender);
        assert!(outbound.has_session());
        let result = first.send(&payload(5));
        assert!(
            matches!(&result, Err(Error::EncryptionFailed(msg)) if msg == "session ended"),
            "{result:?}"
        );
        second.send(&payload(6)).unwrap();

        // Closure is observed by the next write, which ends the session.
        outbound.close();
        assert_eq!(outbound.session_id(), second.session);
        let result = second.send(&payload(7));
        assert!(
            matches!(&result, Err(Error::SendFailed(err)) if err.kind() == io::ErrorKind::NotConnected),
            "{result:?}"
        );
        assert!(!outbound.has_session());
        drop(outbound);
        let result = second.send(&payload(8));
        assert!(matches!(&result, Err(Error::Terminated)), "{result:?}");
    }

    // Tests that closing cancels a blocked write without taking the send locks,
    // including when a second sender holds the sealer while waiting for the
    // writer. Both senders finish and a surviving sender refuses new sends.
    #[test]
    fn test_close_with_stuck_sends() {
        testing::init_tracing();

        let (gate, entered, release, dropped) = Gate::new();
        let (sender, _) = contexts();
        let closer = Closer::new(move || {
            let _ = release.send(());
        });
        let outbound = Arc::new(Outbound::new(gate, Side::Client, closer));
        let sender = outbound.establish_session(sender);

        let first = {
            let sender = sender.clone();
            thread::spawn(move || sender.send(&payload(1)))
        };
        entered.recv_timeout(Duration::from_secs(5)).unwrap();
        let second = {
            let sender = sender.clone();
            thread::spawn(move || sender.send(&payload(2)))
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        while !matches!(outbound.sealer.try_lock(), Err(TryLockError::WouldBlock)) {
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }

        let (closed_tx, closed) = mpsc::channel();
        let owner = {
            let outbound = outbound.clone();
            thread::spawn(move || {
                outbound.close();
                closed_tx.send(()).unwrap();
            })
        };
        closed.recv_timeout(Duration::from_secs(5)).unwrap();
        owner.join().unwrap();
        assert!(matches!(first.join().unwrap(), Err(Error::SendFailed(_))));
        assert!(matches!(
            second.join().unwrap(),
            Err(Error::EncryptionFailed(_))
        ));
        assert!(!outbound.has_session());
        assert!(matches!(
            sender.send(&payload(3)),
            Err(Error::EncryptionFailed(_))
        ));
        drop(outbound);
        dropped.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(matches!(sender.send(&payload(4)), Err(Error::Terminated)));
    }

    // Tests that an I/O panic releases its admission charge, allowing shutdown
    // to complete and the last active send to release the transport writer.
    #[test]
    fn test_close_with_panicking_send() {
        testing::init_tracing();

        let (mut gate, entered, release, dropped) = Gate::new();
        gate.panics = true;
        let (sender, _) = contexts();
        let closer = Closer::new(move || {
            let _ = release.send(());
        });
        let outbound = Arc::new(Outbound::new(gate, Side::Client, closer));
        let sender = outbound.establish_session(sender);

        let sending = thread::spawn(move || {
            panic::catch_unwind(AssertUnwindSafe(|| sender.send(&payload(1))))
        });
        entered.recv_timeout(Duration::from_secs(5)).unwrap();
        outbound.close();
        assert!(sending.join().unwrap().is_err());
        drop(outbound);
        dropped.recv_timeout(Duration::from_secs(5)).unwrap();
    }

    // Tests that a transport panicking inside a write ends the session, the
    // sealed message never having gone out, while the framer stays usable for
    // the next session.
    #[test]
    fn test_writer_panic() {
        testing::init_tracing();

        let written = Arc::new(Mutex::new(Vec::new()));
        let (sender, _) = contexts();
        let outbound = Arc::new(Outbound::new(
            Panicky {
                armed: true,
                written: written.clone(),
            },
            Side::Client,
            Closer::new(|| {}),
        ));
        let sender: Sender<Panicky> = outbound.establish_session(sender);

        let result = panic::catch_unwind(AssertUnwindSafe(|| sender.send(&payload(1))));
        assert!(result.is_err());

        // The session is gone, refused on the next send at the latest
        let result = sender.send(&payload(2));
        assert!(
            matches!(result, Err(Error::EncryptionFailed(_))),
            "{result:?}"
        );
        assert!(!outbound.has_session());
        assert!(written.lock().unwrap().is_empty());

        // The next session sends, the framer having kept its buffer and first
        // terminating whatever the panic left behind
        let (sender, mut receiver) = contexts();
        let sender: Sender<Panicky> = outbound.establish_session(sender);
        sender.send(&payload(3)).unwrap();

        let written = written.lock().unwrap().clone();
        let mut reader = FrameReader::new(&written[..], Closer::new(|| {}));
        assert!(reader.next_packet().unwrap().is_none());
        let packet = reader.next_packet().unwrap().unwrap();
        let opened = sealing::open(&mut receiver, packet).unwrap();
        assert_eq!(opened, payload(3));
    }
}
