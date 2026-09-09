// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Mock peer driving one real side of the multiplexer through arbitrary
//! sequences of calls and messages. A script decides what the driver asks of
//! the multiplexer and what the peer answers. A model of the protocol's state
//! machine predicts every result, every message going out and every session
//! ending, and a run panics at the first divergence between the two. The
//! scenario tests and the message level fuzzers share this, so a fuzzer
//! finding replays as a test.
//!
//! The transport underneath is the mock's own, the real outbound side over a sink
//! that can be made to fail. The messages the multiplexer sends are sealed and
//! framed as on the wire, while the peer decides what comes back and when. The
//! driver waits for everything the reader and the worker threads do, so a run
//! is the same every time.

pub mod peer;
#[cfg(feature = "fuzz")]
pub mod seed;

use crate::protocol::envelope::Side;
use crate::protocol::mux::Writer;
use crate::protocol::switchboard::Source;
use crate::transport::testing::Memory;
use crate::transport::{self, Closer, Event, Outbound, Sender, Stream, Write};
use darkbio_crypto::xhpke;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Most steps a script is run for. It bounds the runtime of a fuzz iteration
/// along with the floods a script may ask for.
pub const MAX_STEPS: usize = 64;

/// How long the driver waits for the reader and the worker threads to reach
/// where the model says they are. It is never spent when the two agree, so it
/// is generous enough for a loaded machine.
pub const PATIENCE: Duration = Duration::from_secs(10);

/// HPKE info string of the mock's own session contexts. Nothing but the mock
/// speaks it, the transport's handshake being out of the picture here.
pub const CRYPTO_DOMAIN_MOCK: &[u8] = b"wire-mock";

/// Payload the mock hangs on a message, the tag as eight big endian bytes
/// padded to the size with zeros. Only the tag tells the messages apart, the
/// padding standing in for bulk.
pub fn payload(tag: u8, size: usize) -> Vec<u8> {
    let mut payload = transport::mock::payload(tag as u64);
    payload.resize(payload_len(size), 0);
    payload
}

/// Length of a payload asked for the size, never shorter than the tag it
/// starts with.
pub fn payload_len(size: usize) -> usize {
    size.max(8)
}

/// Tag a payload carries, its leading eight bytes.
pub fn tag(payload: &[u8]) -> u64 {
    let mut head = [0u8; 8];
    let len = head.len().min(payload.len());
    head[..len].copy_from_slice(&payload[..len]);
    u64::from_be_bytes(head)
}

/// What a read of the mock transport hands the reader thread.
pub(crate) enum Delivery {
    /// A message of the peer's, opened by the transport that is not there.
    Message(Vec<u8>),
    /// The session the read side held ended, ahead of the handshake that
    /// follows.
    Disconnected,
    /// A handshake opened the next session.
    Connected(Sender<Writer>),
    /// The read fails, ending the transport under the multiplexer.
    Failed(transport::Error),
}

/// Frames the multiplexer wrote, drained by the mock peer. The writes can be
/// made to fail, standing in for a transport that died, and the closer the
/// multiplexer runs breaks them for good, as shutting a socket down would.
#[derive(Clone)]
pub(crate) struct Sink {
    bytes: Arc<Mutex<Vec<u8>>>,
    broken: Arc<AtomicBool>,
    closed: Arc<AtomicBool>,
    writes: mpsc::Sender<()>, // Tells the driver that a write attempt finished
    deadline: Option<Instant>, // Fixed budget shared by this writer's frame operations
}

impl Sink {
    /// Creates the sink along with the channel telling that a write attempt
    /// finished, one per send of the outbound side whether it got out or not.
    pub(crate) fn new() -> (Self, mpsc::Receiver<()>) {
        let (writes, attempts) = mpsc::channel();
        let sink = Self {
            bytes: Arc::default(),
            broken: Arc::default(),
            closed: Arc::default(),
            writes,
            deadline: None,
        };
        (sink, attempts)
    }

    /// Takes the frames written so far, delimiters stripped. Every write goes
    /// out whole or not at all, so the stream never ends mid frame.
    pub(crate) fn take_frames(&self) -> Vec<Vec<u8>> {
        let mut bytes = self.bytes.lock().expect("sink not poisoned");
        let mut frames: Vec<Vec<u8>> = bytes.split(|&byte| byte == 0).map(<[u8]>::to_vec).collect();
        let tail = frames.pop().expect("split yields at least one piece");
        assert!(tail.is_empty(), "multiplexer left a frame unterminated");
        bytes.clear();
        frames
    }

    /// Makes every write fail from here on, or work again.
    pub(crate) fn set_broken(&self, broken: bool) {
        self.broken.store(broken, Ordering::Release);
    }

    /// Ends the transport for good, as the closer of the multiplexer does.
    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }

    /// Whether a write fails, on a broken or an ended transport.
    fn failing(&self) -> bool {
        self.broken.load(Ordering::Acquire) || self.closed.load(Ordering::Acquire)
    }
}

impl io::Write for Sink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            let _ = self.writes.send(());
            return Err(io::ErrorKind::TimedOut.into());
        }
        if self.failing() {
            let _ = self.writes.send(());
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        self.bytes
            .lock()
            .expect("sink not poisoned")
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let _ = self.writes.send(());
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok(())
    }
}

impl Write for Sink {
    fn set_write_deadline(&mut self, deadline: Instant) -> io::Result<()> {
        self.deadline = Some(deadline);
        Ok(())
    }
}

/// Sending half of the mock transport, the outbound side the multiplexer's messages
/// go through and the handle of the session they go into. The peer opens the
/// sessions, the reader thread hands the handle out.
pub(crate) struct Link {
    outbound: Arc<Outbound<Writer>>,
    session: Mutex<LinkSession>, // Session owner and the model's own ordinal
}

/// Session retained by the mock receive side, with an ordinal for model assertions.
/// The counter belongs to the mock; production transport uses object identity.
struct LinkSession {
    current: Option<Arc<Mutex<xhpke::Sender>>>, // Retained until receiving observes its end
    generation: u64,                            // Number of sessions the mock has created
}

impl Link {
    /// Creates the link of a side over the sink, without a session until the
    /// peer opens one.
    pub(super) fn new(side: Side, stream: Stream<Memory<io::Empty>, Writer>) -> Arc<Self> {
        let (_, writer, close, write_timeout) = stream.into_parts();
        let side = match side {
            Side::Client => transport::Side::Client,
            Side::Server => transport::Side::Server,
        };
        let outbound = Arc::new(Outbound::new(writer, side, close, write_timeout));
        Arc::new(Self {
            outbound,
            session: Mutex::new(LinkSession {
                current: None,
                generation: 0,
            }),
        })
    }

    /// Opens a session, the one before it dropped, and hands back the context
    /// opening what the multiplexer seals into it.
    pub(crate) fn create_session(self: &Arc<Self>) -> (Sender<Writer>, xhpke::Receiver) {
        let secret = xhpke::SecretKey::generate();
        let (sender, encap) = secret
            .public_key()
            .new_sender(CRYPTO_DOMAIN_MOCK)
            .expect("mock session sealing context");
        let receiver = secret
            .new_receiver(&encap, CRYPTO_DOMAIN_MOCK)
            .expect("mock session opening context");

        // Only sending runs through the real transport; the model handles
        // inbound messages directly and needs no receive crypto context.
        let current = Arc::new(Mutex::new(sender));
        let sender = self.outbound.bind(&current);
        let mut session = self.session.lock().expect("link not poisoned");
        session.current = Some(current);
        session.generation += 1;
        (sender, receiver)
    }

    /// Model ordinal of the live session, or zero once either direction ends.
    pub(crate) fn generation(&self) -> u64 {
        let session = self.session.lock().expect("link not poisoned");
        match &session.current {
            Some(current) => self
                .outbound
                .finish_receive(current, Ok(Vec::new()))
                .map(|_| session.generation)
                .unwrap_or(0),
            _ => 0,
        }
    }

    /// Whether the read side holds a session, one whose end a transport
    /// server's read would report.
    pub(crate) fn held(&self) -> bool {
        self.session
            .lock()
            .expect("link not poisoned")
            .current
            .is_some()
    }

    /// Drops the session, the read side letting go of it too, as a transport
    /// server does on the peer's reset.
    pub(crate) fn end_session(&self) {
        let mut session = self.session.lock().expect("link not poisoned");
        if let Some(current) = session.current.as_ref() {
            self.outbound.end(current);
        }
        session.current = None;
    }
}

impl Drop for Link {
    /// Ends the mock's current session before releasing its context, including
    /// when an active send temporarily keeps that context and the writer alive.
    fn drop(&mut self) {
        let session = self.session.get_mut().expect("link not poisoned");
        if let Some(current) = session.current.as_ref() {
            self.outbound.end(current);
        }
    }
}

/// Reading half of the mock transport, the source the multiplexer's reader
/// thread pulls from. Every read tells the driver that the reader is back for
/// more, the first one that it started and the ones after it that the message
/// before them is routed, so a run never races the reader.
pub(crate) struct Feed {
    link: Arc<Link>,
    deliveries: mpsc::Receiver<Delivery>,
    routed: mpsc::SyncSender<()>,
    finished: mpsc::Sender<()>,
}

impl Feed {
    /// Creates the source of a link along with the channel delivering into it,
    /// the one telling that a delivery is routed and the one telling that the
    /// reader thread wound down.
    pub(super) fn new(
        side: Side,
        sink: Sink,
    ) -> (
        Self,
        mpsc::Sender<Delivery>,
        mpsc::Receiver<()>,
        mpsc::Receiver<()>,
    ) {
        let (deliveries, inbound) = mpsc::channel();
        let (routed, routes) = mpsc::sync_channel(0);
        let (finished, ends) = mpsc::channel();
        let stream = Stream::new(
            Memory::new(io::empty()),
            Box::new(sink.clone()) as Writer,
            {
                let deliveries = deliveries.clone();
                move || {
                    sink.close();
                    let _ = deliveries.send(Delivery::Failed(transport::Error::Terminated));
                }
            },
        );
        let link = Link::new(side, stream);
        let feed = Self {
            link,
            deliveries: inbound,
            routed,
            finished,
        };
        (feed, deliveries, routes, ends)
    }
}

impl Source for Feed {
    fn closer(&self) -> Closer {
        self.link.outbound.closer()
    }
    fn recv(&mut self) -> Result<Event<Writer>, transport::Error> {
        // Tell the driver that the reader is back for more, which on the first
        // read means it started and took down the session it starts from, and
        // on every later one that the message before it is routed
        let _ = self.routed.send(());
        match self.deliveries.recv() {
            Ok(Delivery::Message(message)) => Ok(Event::Message(message)),
            Ok(Delivery::Disconnected) => Ok(Event::Disconnected),
            Ok(Delivery::Connected(sender)) => Ok(Event::Connected(sender)),
            Ok(Delivery::Failed(err)) => Err(err),
            Err(_) => Err(transport::Error::Terminated),
        }
    }

    fn disconnect(&mut self) {
        self.link.end_session();
        let _ = self.link.outbound.send_dropped(None);
    }
}

impl Drop for Feed {
    fn drop(&mut self) {
        self.link.outbound.close();
        let _ = self.finished.send(());
    }
}
