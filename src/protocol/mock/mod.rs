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
//! The transport underneath is the mock's own, the real funnel over a sink
//! that can be made to fail. The messages the multiplexer sends are sealed and
//! framed as on the wire, while the peer decides what comes back and when. The
//! driver waits for everything the reader and the worker threads do, so a run
//! is the same every time.

pub mod peer;
#[cfg(feature = "fuzz")]
pub mod seed;

use crate::protocol::mux::Writer;
use crate::protocol::switchboard::Source;
use crate::transport::{self, Emitter, Funnel, Side};
use darkbio_crypto::xhpke;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
    let mut payload = crate::transport::mock::payload(tag as u64);
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
    /// The session the read side held ended, the peer having reset it,
    /// reported ahead of the handshake that follows.
    Reset,
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
}

impl Sink {
    /// Creates the sink along with the channel telling that a write attempt
    /// finished, one per send of the funnel whether it got out or not.
    pub(crate) fn new() -> (Self, mpsc::Receiver<()>) {
        let (writes, attempts) = mpsc::channel();
        let sink = Self {
            bytes: Arc::default(),
            broken: Arc::default(),
            closed: Arc::default(),
            writes,
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

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
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
        Ok(())
    }
}

/// Sending half of the mock transport, the funnel the multiplexer's messages
/// go through and the handle of the session they go into. The peer opens the
/// sessions, the reader thread hands the handle out.
pub(crate) struct Link {
    funnel: Arc<Funnel<Writer>>,
    emitter: Mutex<Emitter<Writer>>, // Handle of the live session, as a transport caches it
    held: AtomicBool,                // Whether the read side holds a session, its end reported
}

impl Link {
    /// Creates the link of a side over the sink, without a session until the
    /// peer opens one.
    pub(crate) fn new(side: Side, sink: Sink) -> Arc<Self> {
        let funnel = Arc::new(Funnel::new(Box::new(sink) as Writer, side));
        let emitter = Mutex::new(funnel.emitter());
        Arc::new(Self {
            funnel,
            emitter,
            held: AtomicBool::new(false),
        })
    }

    /// Opens a session, the one before it dropped, and hands back the context
    /// opening what the multiplexer seals into it.
    pub(crate) fn open_session(&self) -> xhpke::Receiver {
        let secret = xhpke::SecretKey::generate();
        let (sender, encap) = secret
            .public_key()
            .new_sender(CRYPTO_DOMAIN_MOCK)
            .expect("mock session sealing context");
        let receiver = secret
            .new_receiver(&encap, CRYPTO_DOMAIN_MOCK)
            .expect("mock session opening context");

        self.funnel.establish_session(sender);
        *self.emitter.lock().expect("link not poisoned") = self.funnel.emitter();
        self.held.store(true, Ordering::Release);
        receiver
    }

    /// Number of the live session, or zero without one.
    pub(crate) fn session(&self) -> u64 {
        self.funnel.session()
    }

    /// Whether the read side holds a session, one whose end a transport
    /// server's read would report.
    pub(crate) fn held(&self) -> bool {
        self.held.load(Ordering::Acquire)
    }

    /// Drops the session, the read side letting go of it too, as a transport
    /// server does on the peer's reset.
    pub(crate) fn drop_session(&self) {
        self.held.store(false, Ordering::Release);
        self.funnel.drop_session();
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
    pub(crate) fn new(
        link: Arc<Link>,
    ) -> (
        Self,
        mpsc::Sender<Delivery>,
        mpsc::Receiver<()>,
        mpsc::Receiver<()>,
    ) {
        let (deliveries, inbound) = mpsc::channel();
        let (routed, routes) = mpsc::sync_channel(0);
        let (finished, ends) = mpsc::channel();
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
    fn next_message(&mut self) -> Result<Vec<u8>, transport::Error> {
        // Tell the driver that the reader is back for more, which on the first
        // read means it started and took down the session it starts from, and
        // on every later one that the message before it is routed
        let _ = self.routed.send(());
        match self.deliveries.recv() {
            Ok(Delivery::Message(message)) => Ok(message),
            Ok(Delivery::Reset) => Err(transport::Error::SessionReset),
            Ok(Delivery::Failed(err)) => Err(err),
            Err(_) => Err(transport::Error::Terminated),
        }
    }

    fn session(&self) -> u64 {
        self.link.session()
    }

    fn emitter(&self) -> Emitter<Writer> {
        self.link.emitter.lock().expect("link not poisoned").clone()
    }

    fn reset_session(&mut self) {
        self.link.drop_session();
        let _ = self.link.funnel.send_dropped();
    }
}

impl Drop for Feed {
    fn drop(&mut self) {
        let _ = self.finished.send(());
    }
}
