// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Funnel of a session's sends. Its owner and any number of emitters, the
//! handles other threads send through, all send into the one funnel, which
//! seals and writes their messages onto the wire in order, every sender
//! getting its own result. Sealing and writing overlap, the next message
//! sealing while the one before it is written, the wire order never differing
//! from the sealing order.

use crate::framing::FrameWriter;
use crate::sealing;
use crate::{Error, MAX_MESSAGE_SIZE};
use darkbio_crypto::xhpke;
use prost::Message;
use std::io::Write;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use tracing::{trace, warn};

/// Session number of a funnel without a session, none established yet or the
/// last one ended.
const NONE: u64 = 0;

/// Session number of a funnel whose owner is gone, never to have one again.
const CLOSED: u64 = u64::MAX;

/// Side of the wire a funnel sends for. The server lives across sessions,
/// clients come and go on it, so after a failed send it tells the client with
/// an empty frame that its session is gone and a handshake is due. A client
/// is made per connection and recovers by starting that handshake itself, so
/// it never has to tell the server anything.
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

/// Sealing phase of the funnel, the context fixing the sequence and the
/// scratch space the protobuf encoding goes through.
struct Sealer {
    sender: Option<xhpke::Sender>, // Outbound context of the session (if handshake completed)
    scratch: Vec<u8>,              // Scratch for protobuf encoding a message before sealing
    sessions: u64,                 // Number of sessions established so far
}

/// Sending side of a session, shared between its owner and the emitters the
/// owner hands out. It holds the outbound HPKE context and the frame writer,
/// and every send passes through it, so all senders share one sequence and
/// one stream. Sessions are numbered as they are established and a send is
/// accepted only into the live one, a message of an earlier session refused
/// rather than delivered to the wrong peer. A send that fails after sealing
/// ends the session, as the peer cannot follow the sequence past the gap. On
/// the server's side, which serves clients across sessions, the empty frame
/// telling the client its session is gone follows, so the client handshakes
/// again. The client's side recovers by starting that handshake and sends
/// nothing. Ending a session or closing the funnel never waits for a send
/// stuck in the transport.
///
/// Sealing and writing run under two locks taken hand over hand, the write
/// lock before the seal lock is released, which keeps the wire order equal to
/// the sealing order while the next message seals behind the one going out.
pub(crate) struct Funnel<W: Write> {
    sealer: Mutex<Sealer>,                 // Sealing phase, taken first
    framer: Mutex<Option<FrameWriter<W>>>, // Writing phase, taken second
    session: AtomicU64,                    // Number of the live session, NONE or CLOSED without

    side: Side, // Side of the wire the funnel sends for, deciding what follows a failed send
}

impl<W: Write> Funnel<W> {
    /// Creates the funnel around a low level writer, without a session until a
    /// handshake establishes one.
    pub fn new(writer: W, side: Side) -> Self {
        let framing = FrameWriter::new(writer);
        Self {
            sealer: Mutex::new(Sealer {
                sender: None,
                scratch: Vec::with_capacity(MAX_MESSAGE_SIZE),
                sessions: 0,
            }),
            framer: Mutex::new(Some(framing)),
            session: AtomicU64::new(NONE),
            side,
        }
    }

    /// Creates a handle sending into the live session, refused once that one
    /// ended, and refused outright without a session.
    pub fn emitter<M: Message>(self: &Arc<Self>) -> Emitter<W, M> {
        Emitter::new(self.clone(), self.session.load(Ordering::Acquire))
    }

    /// Installs the context of a freshly established session, the next one by
    /// number, sends going out from here on.
    pub fn establish_session(&self, sender: xhpke::Sender) {
        let mut sealer = self.lock(&self.sealer);
        sealer.sender = Some(sender);

        // The count reaches the reserved numbers after 2^64 handshakes, each a
        // few milliseconds of lattice cryptography and a round trip, half a
        // billion years at a thousand a second, so nothing guards against it
        sealer.sessions += 1;
        self.session.store(sealer.sessions, Ordering::Release);
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

    /// Whether there is a live session for the sends, none established or the
    /// last one ended by a failed send or by the owner being the alternatives.
    pub fn has_session(&self) -> bool {
        !matches!(self.session.load(Ordering::Acquire), NONE | CLOSED)
    }

    /// Ends the sessions for good and lets go of the framer, the transport
    /// underneath closing with it, so emitters outliving their owner hold
    /// nothing open. A send stuck in the transport is not waited for, the
    /// framer going with it once it returns.
    pub fn close(&self) {
        self.session.store(CLOSED, Ordering::Release);
        if let Some(mut sealer) = self.try_lock(&self.sealer) {
            sealer.clear();
        }
        if let Some(mut framing) = self.try_lock(&self.framer) {
            framing.take();
        }
    }

    /// Protobuf encodes a message, seals it with the session and sends it.
    /// Fails unless the session is the live one. A message too large or
    /// refusing to encode is rejected before sealing and leaves the session
    /// alone, a failure after sealing ends it, as the peer's HPKE sequence can
    /// no longer be caught up with.
    pub fn send<M: Message>(&self, session: u64, msg: &M) -> Result<(), Error> {
        // Seal under the seal lock, fixing the message's place in the sequence
        let mut sealer = self.lock(&self.sealer);
        if let Err(err) = self.check(session) {
            // Nothing seals anymore once the owner is gone, the buffers can go
            if self.session.load(Ordering::Acquire) == CLOSED {
                sealer.clear();
            }
            return Err(err);
        }
        let Sealer {
            sender, scratch, ..
        } = &mut *sealer;
        let sender = sender
            .as_mut()
            .ok_or_else(|| Error::EncryptionFailed("no active session".into()))?;

        let packet = match sealing::seal(sender, msg, scratch) {
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
        let mut framing = self.lock(&self.framer);
        drop(sealer);

        // A session that ended while the message waited for its turn cannot
        // carry it anymore, the peer will not follow the sequence
        let result = match framing.as_mut() {
            Some(framing) => match self.check(session) {
                Ok(()) => self.write(framing, &packet),
                Err(err) => Err(err),
            },
            None => Err(Error::EncryptionFailed("no active session".into())),
        };
        // The owner gone while the write held the framer, it goes now
        if self.session.load(Ordering::Acquire) == CLOSED {
            framing.take();
        }
        result
    }

    /// Signals a session reset, see `FrameWriter::send_reset`.
    pub fn send_reset(&self) -> Result<(), Error> {
        self.with_writer(|framing| framing.send_reset())
    }

    /// Signals a dropped session, see `FrameWriter::send_dropped`.
    pub fn send_dropped(&self) -> Result<(), Error> {
        self.with_writer(|framing| framing.send_dropped())
    }

    /// Sends a packet outside the session, the handshake's own, see
    /// `FrameWriter::send_packet`.
    pub fn send_packet(&self, packet: &[u8]) -> Result<(), Error> {
        self.with_writer(|framing| framing.send_packet(packet))
    }

    /// Test and benchmark helper exposing the framer's `send_frame`.
    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn send_frame_blob(&self, frame: &[u8]) -> Result<(), Error> {
        self.with_writer(|framing| framing.send_frame_blob(frame))
    }

    /// Writes a sealed packet, a failure ending the session and, on the
    /// server's side, telling the client so.
    fn write(&self, framing: &mut FrameWriter<W>, packet: &[u8]) -> Result<(), Error> {
        if let Err(err) = framing.send_packet(packet) {
            self.end_session();
            if self.side.announces_drops()
                && let Err(err) = framing.send_dropped()
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

    /// Runs a write under the write lock, a framer already let go of failing
    /// it as a session that is gone.
    fn with_writer(
        &self,
        write: impl FnOnce(&mut FrameWriter<W>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut framing = self.lock(&self.framer);
        let Some(framing) = framing.as_mut() else {
            return Err(Error::EncryptionFailed("no active session".into()));
        };
        write(framing)
    }

    /// Checks that the session is the live one, a message of any other refused
    /// as the peer would not follow its sequence.
    fn check(&self, session: u64) -> Result<(), Error> {
        match self.session.load(Ordering::Acquire) {
            NONE | CLOSED => Err(Error::EncryptionFailed("no active session".into())),
            live if live == session => Ok(()),
            _ => Err(Error::EncryptionFailed("session ended".into())),
        }
    }

    /// Ends the live session if there is one, a closed funnel staying closed.
    fn end_session(&self) {
        let _ = self
            .session
            .try_update(Ordering::AcqRel, Ordering::Acquire, |session| {
                (session != CLOSED).then_some(NONE)
            });
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

    /// Locks one of the funnel's mutexes. A poisoned one means a send panicked
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

    /// Locks one of the funnel's mutexes if nobody holds it, a poisoned one
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

impl Sealer {
    /// Lets go of the context and the scratch, nothing sealing anymore.
    fn clear(&mut self) {
        self.sender = None;
        self.scratch = Vec::new();
    }
}

/// Handle for sending messages into a session from any thread, cloned for
/// every sender there is. Sends are serialized with the owner's own and with
/// each other, each waiting for its own frame and getting its own result. The
/// handle is bound to the session it was made in and refused once that ended,
/// whether by a failure, a new handshake or the owner going, so a message
/// meant for one peer never reaches the next. A new session needs a new
/// handle from the owner.
pub struct Emitter<W: Write, M: Message> {
    funnel: Arc<Funnel<W>>,          // Funnel of the session's sends
    session: u64,                    // Number of the session the handle sends into
    message: PhantomData<fn() -> M>, // Type of the messages the handle sends
}

impl<W: Write, M: Message> Emitter<W, M> {
    /// Creates a handle onto a funnel, bound to the session.
    fn new(funnel: Arc<Funnel<W>>, session: u64) -> Self {
        Self {
            funnel,
            session,
            message: PhantomData,
        }
    }

    /// Protobuf encodes a message, seals it with the session and sends it,
    /// see `Funnel::send`.
    pub fn send_message(&self, msg: M) -> Result<(), Error> {
        self.funnel.send(self.session, &msg)
    }
}

impl<W: Write, M: Message> Clone for Emitter<W, M> {
    fn clone(&self) -> Self {
        Self::new(self.funnel.clone(), self.session)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::framing::FrameReader;
    use crate::protocol::HostToArk;
    use crate::testing;
    use std::io;
    use std::panic::{self, AssertUnwindSafe};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    /// A pair of contexts standing in for an established session.
    fn contexts() -> (xhpke::Sender, xhpke::Receiver) {
        let secret = xhpke::SecretKey::generate();
        let (sender, encap) = secret.public_key().new_sender(b"test").unwrap();
        let receiver = secret.new_receiver(&encap, b"test").unwrap();
        (sender, receiver)
    }

    /// A message with the id.
    fn message(id: u64) -> HostToArk {
        HostToArk {
            id: Some(id),
            ..Default::default()
        }
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

    /// Writer holding its first write until released, then failing it, the
    /// ones after passing.
    struct Gate {
        entered: mpsc::Sender<()>,
        release: Option<mpsc::Receiver<()>>,
    }

    impl Gate {
        /// Creates the gate along with the channel telling that a write is
        /// held and the one releasing it.
        fn new() -> (Self, mpsc::Receiver<()>, mpsc::Sender<()>) {
            let (entered_tx, entered) = mpsc::channel();
            let (release, release_rx) = mpsc::channel();
            let gate = Self {
                entered: entered_tx,
                release: Some(release_rx),
            };
            (gate, entered, release)
        }
    }

    impl Write for Gate {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            match self.release.take() {
                Some(release) => {
                    let _ = self.entered.send(());
                    let _ = release.recv();
                    Err(io::Error::other("gate closed"))
                }
                None => Ok(buf.len()),
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
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
        let funnel = Arc::new(Funnel::new(collector.clone(), Side::Client));
        funnel.establish_session(sender);

        let threads: Vec<_> = (0..8)
            .map(|thread| {
                let emitter: Emitter<Collector, HostToArk> = funnel.emitter();
                thread::spawn(move || {
                    for i in 0..20 {
                        emitter.send_message(message(thread * 100 + i)).unwrap();
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }

        // Every frame must open in the order written, or the sequence is off
        let written = collector.0.lock().unwrap().clone();
        let mut reader = FrameReader::new(&written[..]);
        let mut ids = Vec::new();
        loop {
            let packet = match reader.next_packet() {
                Err(Error::Terminated) => break,
                result => result.unwrap().unwrap(),
            };
            let msg: HostToArk = sealing::open(&mut receiver, packet).unwrap();
            ids.push(msg.id.unwrap());
        }
        ids.sort_unstable();
        let mut expected: Vec<u64> = (0..8)
            .flat_map(|thread| (0..20).map(move |i| thread * 100 + i))
            .collect();
        expected.sort_unstable();
        assert_eq!(ids, expected);
    }

    // Tests that a failed write is reported to the sender it failed, that a
    // message sealed behind it is refused rather than written, and that every
    // later one is refused before sealing.
    #[test]
    fn test_send_failure_attribution() {
        testing::init_tracing();

        let (gate, entered, release) = Gate::new();
        let (sender, _) = contexts();
        let funnel = Arc::new(Funnel::new(gate, Side::Client));
        funnel.establish_session(sender);
        let emitter: Emitter<Gate, HostToArk> = funnel.emitter();

        // The first sender blocks inside its write, the second seals behind it
        // and waits for the write lock. The wait gives it time to get there,
        // though it is refused the same if it only seals after the failure.
        let first = {
            let emitter = emitter.clone();
            thread::spawn(move || emitter.send_message(message(1)))
        };
        entered.recv().unwrap();
        let second = {
            let emitter = emitter.clone();
            thread::spawn(move || emitter.send_message(message(2)))
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
        let result = emitter.send_message(message(3));
        assert!(
            matches!(result, Err(Error::EncryptionFailed(_))),
            "{result:?}"
        );
        assert!(!funnel.has_session());
    }

    // Tests that sends are refused without a session, after one ended and once
    // the owner let go of the framer, and that a handle stays bound to the
    // session it was made in while a fresh one sends into the new session.
    #[test]
    fn test_send_refusals() {
        testing::init_tracing();

        let funnel = Arc::new(Funnel::new(Vec::new(), Side::Client));
        let detached: Emitter<Vec<u8>, HostToArk> = funnel.emitter();
        let result = detached.send_message(message(1));
        assert!(
            matches!(&result, Err(Error::EncryptionFailed(msg)) if msg == "no active session"),
            "{result:?}"
        );

        // A session established, only a handle made in it sends
        let (sender, _) = contexts();
        funnel.establish_session(sender);
        let first: Emitter<Vec<u8>, HostToArk> = funnel.emitter();
        first.send_message(message(2)).unwrap();
        let result = detached.send_message(message(3));
        assert!(
            matches!(&result, Err(Error::EncryptionFailed(msg)) if msg == "session ended"),
            "{result:?}"
        );

        // The session ended, nothing sends without one
        funnel.drop_session();
        assert!(!funnel.has_session());
        let result = first.send_message(message(4));
        assert!(
            matches!(&result, Err(Error::EncryptionFailed(msg)) if msg == "no active session"),
            "{result:?}"
        );

        // The next session refuses the handle of the previous one
        let (sender, _) = contexts();
        funnel.establish_session(sender);
        assert!(funnel.has_session());
        let result = first.send_message(message(5));
        assert!(
            matches!(&result, Err(Error::EncryptionFailed(msg)) if msg == "session ended"),
            "{result:?}"
        );
        let second: Emitter<Vec<u8>, HostToArk> = funnel.emitter();
        second.send_message(message(6)).unwrap();

        // The owner gone, nothing sends ever again
        funnel.close();
        assert!(!funnel.has_session());
        let result = second.send_message(message(7));
        assert!(
            matches!(&result, Err(Error::EncryptionFailed(msg)) if msg == "no active session"),
            "{result:?}"
        );
        let result = funnel.send_dropped();
        assert!(
            matches!(result, Err(Error::EncryptionFailed(_))),
            "{result:?}"
        );
    }

    // Tests that ending the session and closing the funnel never wait for a
    // send stuck in the transport, the framer going once that send returns
    // and the one sealed behind it refused.
    #[test]
    fn test_end_never_waits() {
        testing::init_tracing();

        let (gate, entered, release) = Gate::new();
        let (sender, _) = contexts();
        let funnel = Arc::new(Funnel::new(gate, Side::Client));
        funnel.establish_session(sender);
        let emitter: Emitter<Gate, HostToArk> = funnel.emitter();

        // The first sender is stuck inside its write holding the framer, the
        // second seals behind it and waits for the framer holding the sealer
        let first = {
            let emitter = emitter.clone();
            thread::spawn(move || emitter.send_message(message(1)))
        };
        entered.recv().unwrap();
        let second = {
            let emitter = emitter.clone();
            thread::spawn(move || emitter.send_message(message(2)))
        };
        thread::sleep(Duration::from_millis(50));

        // The owner ends the session and goes, waiting for neither
        let (ended_tx, ended) = mpsc::channel();
        let owner = {
            let funnel = funnel.clone();
            thread::spawn(move || {
                funnel.drop_session();
                assert!(!funnel.has_session());
                funnel.close();
                ended_tx.send(()).unwrap();
            })
        };
        ended.recv_timeout(Duration::from_secs(5)).unwrap();
        owner.join().unwrap();

        // The stuck write fails once released, the framer going with it, and
        // the one behind it finds no framer
        release.send(()).unwrap();
        let result = first.join().unwrap();
        assert!(matches!(result, Err(Error::SendFailed(_))), "{result:?}");
        let result = second.join().unwrap();
        assert!(
            matches!(result, Err(Error::EncryptionFailed(_))),
            "{result:?}"
        );
        assert!(funnel.framer.lock().unwrap().is_none());
    }

    // Tests that a transport panicking inside a write ends the session, the
    // sealed message never having gone out, while the framer stays usable for
    // the next session.
    #[test]
    fn test_writer_panic() {
        testing::init_tracing();

        let written = Arc::new(Mutex::new(Vec::new()));
        let (sender, _) = contexts();
        let funnel = Arc::new(Funnel::new(
            Panicky {
                armed: true,
                written: written.clone(),
            },
            Side::Client,
        ));
        funnel.establish_session(sender);
        let emitter: Emitter<Panicky, HostToArk> = funnel.emitter();

        let result = panic::catch_unwind(AssertUnwindSafe(|| emitter.send_message(message(1))));
        assert!(result.is_err());

        // The session is gone, refused on the next send at the latest
        let result = emitter.send_message(message(2));
        assert!(
            matches!(result, Err(Error::EncryptionFailed(_))),
            "{result:?}"
        );
        assert!(!funnel.has_session());
        assert!(written.lock().unwrap().is_empty());

        // The next session sends, the framer having kept its buffer and first
        // terminating whatever the panic left behind
        let (sender, mut receiver) = contexts();
        funnel.establish_session(sender);
        let emitter: Emitter<Panicky, HostToArk> = funnel.emitter();
        emitter.send_message(message(3)).unwrap();

        let written = written.lock().unwrap().clone();
        let mut reader = FrameReader::new(&written[..]);
        assert!(reader.next_packet().unwrap().is_none());
        let packet = reader.next_packet().unwrap().unwrap();
        let msg: HostToArk = sealing::open(&mut receiver, packet).unwrap();
        assert_eq!(msg.id, Some(3));
    }
}
