// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Mock peer driving a real multiplexer, either side of it. A script is a
//! sequence of steps, each a call the driver makes into the multiplexer or a
//! message the peer sends it. The peer decides what comes back and when, and
//! opens everything the multiplexer writes with the session's own context.
//!
//! The model tracks the state the multiplexer should be in, the requests it
//! holds of the window, the ones of the peer's ahead of its worker and the
//! messages it should write. Every call is checked against what the model
//! predicts, as is every message going out and every session ending. Any
//! divergence panics.
//!
//! The reader and the worker threads are waited for at every step, the reader
//! telling when a message is routed and the handler when it takes a request,
//! so a run never races them and comes out the same every time. The handler
//! stays plugged in for the whole run, which leaves the multiplexer's own
//! refusal of a request nobody serves to the tests of the multiplexer.

use super::{Delivery, Feed, Link, MAX_STEPS, PATIENCE, Sink, payload, payload_len, tag as tagged};
use crate::protocol::envelope::Side;
use crate::protocol::mux::{ANSWERS, CHARGE, Error, INBOX, Mux, Pending, Responder, WINDOW};
use crate::protocol::{self, ArkToHost, Envelope, HostToArk, ark_to_host, host_to_ark};
use crate::transport::mock::unframe;
use crate::transport::{self, MAX_MESSAGE_SIZE};
use darkbio_crypto::xhpke;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Payload of the requests that fill the window and the inbox, as large as
/// the wire carries once the envelope is wrapped around it. Eight fill the
/// window, thirty two the inbox.
pub const BULK: usize = MAX_MESSAGE_SIZE - 64;

/// Floods a script is run for, the rest skipped. Each one pushes an inbox
/// worth of requests through the multiplexer, which is by far the priciest
/// thing a step can ask for, and two cover a peer overrunning its window and
/// doing it again over the session after.
pub const MAX_FLOODS: usize = 2;

/// Tag of the requests a flood is made of, and of the one too large to seal,
/// neither of which the driver ever waits for an answer to.
const HOUSEKEEPING: u8 = 0xff;

/// Code and message the peer fails a request of the multiplexer's with, told
/// apart from the handler's own so neither passes for the other.
const REJECTION: (u64, &str) = (13, "peer said no");

/// Code and message the mock's handler fails a request of the peer's with.
const REFUSAL: (u64, &str) = (7, "handler said no");

/// Failure the multiplexer answers a request it cannot read with.
const NOT_UNDERSTOOD: (u64, &str) = (0, "request not understood");

/// Failure the multiplexer answers a request the handler let go with.
const UNANSWERED: (u64, &str) = (0, "request left unanswered");

/// One step of a script, either a call the driver makes into the multiplexer
/// or a message the mock peer sends it. Steps needing a request, a session or
/// a request in the handler that is not there are skipped, so any sequence of
/// steps is a valid script.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum Step {
    /// The driver sends a request tagged by the byte, keeping its answer to
    /// wait for later. Nothing if one with the tag is still around.
    Request(u8),
    /// The driver sends a request tagged by the byte whose payload nearly
    /// fills a frame, eight of them filling the window and the ninth waiting
    /// for room. A request waiting for room holds the driver, so the ones
    /// after it are skipped until an answer or a fault frees it.
    Bulk(u8),
    /// The driver sends a request too large for the wire, refused before it
    /// is sealed.
    Oversized,
    /// The driver waits for the answer of the request tagged by the byte,
    /// without giving it any time. Nothing if it holds no such answer.
    Wait(u8),
    /// The driver drops the answer of the request tagged by the byte without
    /// waiting for it. Nothing if it holds no such answer.
    Forget(u8),
    /// The driver closes the multiplexer.
    Close,
    /// The peer answers the request tagged by the byte, echoing its tag.
    /// Nothing if no such request is outstanding.
    Answer(u8),
    /// The peer fails the request tagged by the byte. Nothing if no such
    /// request is outstanding.
    Fail(u8),
    /// The peer answers a request nobody made, which is dropped.
    Stray,
    /// The peer answers with neither content nor error, which is the protocol
    /// broken.
    Void,
    /// The peer sends bytes that are no envelope, which is the protocol
    /// broken.
    Junk,
    /// The peer sends a request of its own tagged by the byte.
    Ask(u8),
    /// The peer sends a request of its own the multiplexer cannot read, which
    /// it fails on the spot.
    AskVoid,
    /// The peer sends requests until the inbox is past its limit, which is
    /// the window overrun. Nothing once a script ran its floods.
    Flood,
    /// The handler answers the request it holds with its payload echoed.
    Reply,
    /// The handler fails the request it holds.
    Refuse,
    /// The handler lets the request it holds go unanswered.
    Ignore,
    /// The handler answers the request it holds with more than the wire
    /// carries, which never reaches the peer, then answers again with the
    /// payload echoed, the request still being its to answer.
    Bloat,
    /// The peer opens a session, the one before it reset. Nothing on a client,
    /// whose transport is its session.
    Reset,
    /// The transport ends under the reader.
    Unplug,
    /// The multiplexer's writes fail from here on, as on a transport that
    /// died.
    Break,
    /// The multiplexer's writes work again.
    Heal,
    /// The peer answers the request tagged by the byte with a payload nearly
    /// filling a frame, however small the request was. Nothing if no such
    /// request is outstanding.
    Blast(u8),
}

/// Error kinds the model distinguishes in the multiplexer's results.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `Error::Timeout`, no answer within the wait.
    Timeout,
    /// `Error::Flooded`, the peer overran its window.
    Flooded,
    /// `Error::Malformed`, the peer broke the protocol.
    Malformed,
    /// `Error::Closed`, the multiplexer closed by its owner.
    Closed,
    /// `Error::TooLarge`, a message the wire cannot carry.
    TooLarge,
    /// `Error::Disconnected` over `transport::Error::Terminated`.
    Terminated,
    /// `Error::Disconnected` over `transport::Error::SessionReset`.
    Reset,
    /// `Error::Disconnected` over `transport::Error::SendFailed`.
    SendFailed,
    /// `Error::Disconnected` over `transport::Error::EncryptionFailed`, a
    /// send without a live session.
    NoSession,
}

/// Maps a multiplexer error onto the kind the model predicts.
fn kind(err: Error) -> Kind {
    match err {
        Error::Timeout => Kind::Timeout,
        Error::Flooded => Kind::Flooded,
        Error::Malformed => Kind::Malformed,
        Error::Closed => Kind::Closed,
        Error::TooLarge(_) => Kind::TooLarge,
        Error::Remote(err) => panic!("peer failure outside an answer: {err:?}"),
        Error::Disconnected(err) => match *err {
            transport::Error::Terminated => Kind::Terminated,
            transport::Error::SessionReset => Kind::Reset,
            transport::Error::SendFailed(_) => Kind::SendFailed,
            transport::Error::EncryptionFailed(_) => Kind::NoSession,
            ref err => panic!("unexpected transport error from the multiplexer: {err}"),
        },
    }
}

/// Counts of what a run observed, for scenario tests to assert on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub sent: usize,        // Requests of the driver's that went out
    pub refused: usize,     // Requests of the driver's the multiplexer refused
    pub answered: usize,    // Answers the driver took
    pub failed: usize,      // Requests of the driver's the driver saw fail
    pub served: usize,      // Requests of the peer's the handler took
    pub declined: usize,    // Requests of the peer's the multiplexer failed on its own
    pub disconnects: usize, // Times the disconnect handler was told
    pub sessions: usize,    // Sessions the peer opened
    pub closed: bool,       // Whether the multiplexer stopped taking calls
}

/// Envelope of a direction, with the develop content the mock carries its
/// payloads in. The two directions are the only envelopes there are, so the
/// mock drives either side with the same code.
pub trait Tagged: Envelope {
    /// The develop content carrying the payload.
    fn develop(payload: Vec<u8>) -> Self::Content;

    /// Payload of a develop content, the only content the mock builds.
    fn payload(content: Self::Content) -> Vec<u8>;
}

impl Tagged for HostToArk {
    fn develop(payload: Vec<u8>) -> Self::Content {
        host_to_ark::Content::Develop(payload)
    }

    fn payload(content: Self::Content) -> Vec<u8> {
        match content {
            host_to_ark::Content::Develop(payload) => payload,
            other => panic!("unexpected host-to-ark content: {other:?}"),
        }
    }
}

impl Tagged for ArkToHost {
    fn develop(payload: Vec<u8>) -> Self::Content {
        ark_to_host::Content::Develop(payload)
    }

    fn payload(content: Self::Content) -> Vec<u8> {
        match content {
            ark_to_host::Content::Develop(payload) => payload,
            other => panic!("unexpected ark-to-host content: {other:?}"),
        }
    }
}

/// Short account of an envelope, for a run that diverges to name what it saw
/// without printing megabytes of payload.
fn describe<E: Tagged>(message: &[u8]) -> String {
    let Ok(envelope) = E::decode(message) else {
        return format!("{} bytes that are no envelope", message.len());
    };
    let (id, err, content) = envelope.into_parts();
    let payload = content.map(E::payload);
    let carried = match &payload {
        None => "nothing".to_string(),
        Some(payload) => format!("tag {} of {} bytes", tagged(payload), payload.len()),
    };
    format!("id {id}, error {err:?}, carrying {carried}")
}

/// Whether the multiplexer still takes calls, and if not, why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Session live, calls taken.
    Open,
    /// Session ended for the reason, calls refused with it.
    Failed(Kind),
    /// Closed by the owner, calls refused.
    Closed,
}

/// A request of the driver's registered with the multiplexer, held under the
/// id the multiplexer allocated for it as the registry itself holds it.
#[derive(Clone, Copy)]
struct Track {
    tag: Option<u8>, // Tag it is kept under, none for one no answer is due for
    bytes: usize,    // Bytes it holds of the window
    forgotten: bool, // Whether the driver gave up on its answer
}

/// A request of the peer's ahead of the worker or in the handler.
#[derive(Clone, Copy)]
struct Queued {
    id: u64,         // Id the peer chose for it
    tag: Option<u8>, // Tag of its payload, none for a request that carries none
    size: usize,     // Size its payload was asked for
    bytes: usize,    // Bytes it holds of the inbox
    handle: u64,     // Session its responder answers into
}

/// Answer the driver is due for a request of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    /// The peer answered, echoing the tag in a payload of the size.
    Payload(usize),
    /// The peer failed the request.
    Rejected,
    /// The session ended under it, with the reason.
    Fault(Kind),
}

/// What the peer answers a request of the driver's with.
#[derive(Clone, Copy)]
enum Answer {
    /// A payload echoing the tag, of the size.
    Echo(usize),
    /// A failure.
    Reject,
}

/// An answer of the peer's arrived, the outcome the driver should see and
/// the bytes it holds of the answers budget until taken or dropped.
#[derive(Clone, Copy)]
struct Settled {
    outcome: Outcome,
    bytes: usize,
}

/// What a wait hands back, the model's prediction and the multiplexer's
/// result compared as one.
#[derive(Debug, PartialEq, Eq)]
enum Expect {
    /// The payload the peer echoed.
    Payload(Vec<u8>),
    /// The peer failed the request, with the code and message it sent.
    Rejected(u64, String),
    /// The wait failed for the reason.
    Failed(Kind),
}

/// Frame the model expects the multiplexer to write.
enum Emit {
    /// The empty frame, a session gone or the delimiter terminating what a
    /// failed write left behind.
    Dropped,
    /// A message, the envelope it encodes to.
    Message(Vec<u8>),
}

impl fmt::Debug for Emit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Emit::Dropped => write!(f, "Dropped"),
            Emit::Message(message) => write!(f, "Message({} bytes)", message.len()),
        }
    }
}

/// What the handler does with the request it holds.
#[derive(Clone, Copy)]
enum Order {
    Reply,
    Refuse,
    Ignore,
    Bloat,
}

/// A request waiting for room in the window, made on a thread of its own so
/// the driver goes on. It returns once an answer or a fault frees the room,
/// or the session it waits in ends, which refuses it.
struct Blocked<In: Envelope> {
    tag: Option<u8>,     // Tag it is kept under, none for one too large to seal
    id: u64,             // Id the multiplexer allocated for it
    bytes: usize,        // Bytes it takes of the window
    message: Vec<u8>,    // The envelope it sends
    ended: Option<Kind>, // Reason the session ended for under the wait, refusing it
    result: mpsc::Receiver<Result<Pending<In::Content>, Error>>,
    call: JoinHandle<()>, // The thread making the call
}

/// Mock peer along with the model of the multiplexer it drives.
struct Peer<Out: Tagged, In: Tagged> {
    steps: VecDeque<Step>,
    mux: Arc<Mux<Out, In>>,
    link: Arc<Link>,                   // Transport under the multiplexer
    sink: Sink,                        // Frames it wrote
    receiver: Option<xhpke::Receiver>, // Opens the messages of the live session

    deliveries: mpsc::Sender<Delivery>, // Messages handed to the reader
    routes: mpsc::Receiver<()>,         // Tells that a delivery is routed
    ends: mpsc::Receiver<()>,           // Tells that the reader wound down
    attempts: mpsc::Receiver<()>,       // Tells that a write attempt finished
    entered: mpsc::Receiver<Vec<u8>>,   // Payload of the request the handler took
    orders: Option<mpsc::Sender<Order>>, // What the handler does with it
    notices: mpsc::Receiver<Kind>,      // Reasons the disconnect handler was told

    side: Side,   // Side of the wire the multiplexer serves
    state: State, // Whether the multiplexer still takes calls
    ending: bool, // Whether the reader is winding down, to be waited for
    broken: bool, // Whether the transport refuses writes
    closed: bool, // Whether the closer ended the transport for good
    resync: bool, // Whether the last write failed, the next starting with a delimiter

    live: u64,           // Session the outbound side carries, zero without one
    handle: u64,         // Session the multiplexer's handle sends into
    ended: Option<Kind>, // Last session failure, returned to work with no current session

    ids: u64,  // Next id the multiplexer hands out
    asks: u64, // Next id the peer hands out

    pending: HashMap<u64, Track>, // Requests of the driver's still registered
    inflight: usize,              // Bytes they hold of the window
    waiting: HashMap<u8, Pending<In::Content>>, // Answers the driver has yet to take
    settled: HashMap<u8, Settled>, // What those answers should be, with their charges
    buffered: usize,              // Bytes the answers arrived hold of the answers budget
    blocked: Option<Blocked<In>>, // Request waiting for room in the window

    inbox: VecDeque<Queued>, // Requests of the peer's ahead of the worker
    queued: usize,           // Bytes they hold of the inbox
    held: Option<Queued>,    // Request the handler holds
    floods: usize,           // Floods the script may still ask for

    emits: Vec<Emit>, // Frames the multiplexer should have written
    writes: usize,    // Write attempts it should have made
    told: Vec<Kind>,  // Reasons the disconnect handler should have been told

    summary: Summary,
}

impl<Out: Tagged, In: Tagged> Peer<Out, In> {
    /// Executes one step, applying the model's transitions for it and checking
    /// the multiplexer against them.
    fn execute(&mut self, step: Step) {
        match step {
            Step::Request(tag) => self.request(tag, 0),
            Step::Bulk(tag) => self.request(tag, BULK),
            Step::Oversized => self.issue(None, payload(HOUSEKEEPING, MAX_MESSAGE_SIZE + 1)),
            Step::Wait(tag) => self.wait(tag),
            Step::Forget(tag) => self.forget(tag),
            Step::Close => self.close(),
            Step::Answer(tag) => self.answer(tag),
            Step::Blast(tag) => self.blast(tag),
            Step::Fail(tag) => self.reject(tag),
            Step::Stray => self.stray(true),
            Step::Void => self.stray(false),
            Step::Junk => self.junk(),
            Step::Ask(tag) => self.ask(tag, 0),
            Step::AskVoid => self.ask_void(),
            Step::Flood => self.flood(),
            Step::Reply => self.serve(Order::Reply),
            Step::Refuse => self.serve(Order::Refuse),
            Step::Ignore => self.serve(Order::Ignore),
            Step::Bloat => self.serve(Order::Bloat),
            Step::Reset => self.reconnect(),
            Step::Unplug => self.unplug(),
            Step::Break => self.set_broken(true),
            Step::Heal => self.set_broken(false),
        }
    }

    /// Sends a request of the driver's, kept under its tag for the peer to
    /// answer. Two requests never share a tag, so a second one is skipped.
    fn request(&mut self, tag: u8, size: usize) {
        if self.waiting.contains_key(&tag) || self.outstanding(tag).is_some() {
            return;
        }
        self.issue(Some(tag), payload(tag, size));
    }

    /// Sends a request carrying the payload, on a thread of its own if the
    /// window has no room for it. The multiplexer allocates an id whatever
    /// becomes of the request, so the model does too.
    fn issue(&mut self, tag: Option<u8>, payload: Vec<u8>) {
        // A request already waiting for room holds the driver, so the ones
        // after it are skipped rather than racing it for the room that frees
        if self.blocked.is_some() {
            return;
        }
        let id = self.ids;
        self.ids += 2;

        let message = Out::request(id, Out::develop(payload.clone())).encode_to_vec();
        let bytes = message.len().max(CHARGE);
        let content = Out::develop(payload);

        // Refused outright once the multiplexer stopped taking calls
        if !self.open() {
            let refusal = self.refusal();
            let result = self.mux.request(content);
            self.called(tag, result, Some(refusal));
            return;
        }
        // Refused ahead of the window if the wire cannot carry it, never
        // waiting for room it could not use
        if bytes > MAX_MESSAGE_SIZE {
            let result = self.mux.request(content);
            self.called(tag, result, Some(Kind::TooLarge));
            return;
        }
        // Waiting for room, made on a thread the model joins once an answer
        // or a fault frees it
        if self.inflight + bytes > WINDOW {
            let (results, result) = mpsc::channel();
            let mux = self.mux.clone();
            let call = thread::Builder::new()
                .name("mock-caller".into())
                .spawn(move || {
                    let _ = results.send(mux.request(content));
                })
                .expect("failed to spawn the calling thread");

            // Wait for the thread to park on the window, so it is there by
            // the time a later step frees the room or ends the session,
            // rather than still on its way and finding either done
            let deadline = Instant::now() + PATIENCE;
            while self.mux.waiting() == 0 {
                assert!(
                    Instant::now() < deadline,
                    "request thread parking on the window"
                );
                thread::sleep(Duration::from_millis(1));
            }

            self.blocked = Some(Blocked {
                tag,
                id,
                bytes,
                message,
                ended: None,
                result,
                call,
            });
            return;
        }
        let refusal = self.admit(tag, id, bytes, message);
        let result = self.mux.request(content);
        self.called(tag, result, refusal);
    }

    /// Registers a request with its bytes and applies its send, handing back
    /// what the call fails with, if it does. A failed send withdraws it, the
    /// window freed again.
    fn admit(&mut self, tag: Option<u8>, id: u64, bytes: usize, message: Vec<u8>) -> Option<Kind> {
        self.inflight += bytes;
        self.pending.insert(
            id,
            Track {
                tag,
                bytes,
                forgotten: false,
            },
        );
        let refusal = match self.send(self.handle, message) {
            None => return None,
            Some(Kind::TooLarge) => Kind::TooLarge,
            Some(kind) => self.disconnected(self.handle, kind),
        };
        // The withdrawal finds nothing when the failure already drained the
        // registry, which is a client ending with its session
        if let Some(track) = self.pending.remove(&id) {
            self.inflight -= track.bytes;
        }
        if let Some(tag) = tag {
            self.settled.remove(&tag);
        }
        Some(refusal)
    }

    /// Checks a request of the driver's against the model, keeping its answer
    /// to wait for when it went out.
    fn called(
        &mut self,
        tag: Option<u8>,
        result: Result<Pending<In::Content>, Error>,
        refusal: Option<Kind>,
    ) {
        match (result.map_err(kind), refusal) {
            (Ok(pending), None) => {
                if let Some(tag) = tag {
                    self.waiting.insert(tag, pending);
                }
                self.summary.sent += 1;
            }
            (Err(got), Some(want)) => {
                assert_eq!(got, want);
                self.summary.refused += 1;
            }
            (Ok(_), Some(want)) => panic!("request went out, model expected {want:?}"),
            (Err(got), None) => panic!("request refused with {got:?}, model expected it out"),
        }
    }

    /// Waits for the answer of a request without giving it any time, which
    /// times out unless the answer already arrived. A timed out request stays
    /// registered, its bytes held until the peer answers it.
    fn wait(&mut self, tag: u8) {
        let Some(pending) = self.waiting.remove(&tag) else {
            return;
        };
        let expected = match self.settled.remove(&tag) {
            Some(Settled {
                outcome: Outcome::Payload(size),
                bytes,
            }) => {
                self.buffered -= bytes;
                Expect::Payload(payload(tag, size))
            }
            Some(Settled {
                outcome: Outcome::Rejected,
                bytes,
            }) => {
                self.buffered -= bytes;
                Expect::Rejected(REJECTION.0, REJECTION.1.into())
            }
            Some(Settled {
                outcome: Outcome::Fault(kind),
                ..
            }) => Expect::Failed(kind),
            None => Expect::Failed(Kind::Timeout),
        };
        let result = match pending.wait(Duration::ZERO) {
            Ok(content) => Expect::Payload(In::payload(content)),
            Err(Error::Remote(err)) => Expect::Rejected(err.code, err.msg),
            Err(err) => Expect::Failed(kind(err)),
        };
        assert_eq!(result, expected);
        match expected {
            Expect::Payload(_) => self.summary.answered += 1,
            _ => self.summary.failed += 1,
        }
        if expected == Expect::Failed(Kind::Timeout) {
            self.give_up(tag);
        }
    }

    /// Drops the answer of a request, which stays registered and holds its
    /// bytes of the window until the peer answers it. One already arrived is
    /// dropped with it, its charge of the answers budget freed.
    fn forget(&mut self, tag: u8) {
        if self.waiting.remove(&tag).is_none() {
            return;
        }
        if let Some(settled) = self.settled.remove(&tag) {
            self.buffered -= settled.bytes;
        }
        self.give_up(tag);
    }

    /// Id of the request outstanding under the tag, if there is one. Two
    /// requests never share a tag, so at most one answers to it.
    fn outstanding(&self, tag: u8) -> Option<u64> {
        self.pending
            .iter()
            .find(|(_, track)| track.tag == Some(tag))
            .map(|(id, _)| *id)
    }

    /// Marks the request outstanding under the tag as one the driver no longer
    /// waits for, its answer discarded on arrival.
    fn give_up(&mut self, tag: u8) {
        if let Some(id) = self.outstanding(tag)
            && let Some(track) = self.pending.get_mut(&id)
        {
            track.forgotten = true;
        }
    }

    /// Closes the multiplexer, every pending request failed as closed and the
    /// transport ended under the reader.
    fn close(&mut self) {
        if self.open() {
            self.end(State::Closed);
        }
        self.mux.close();
    }

    /// Answers a request of the driver's with its payload echoed.
    fn answer(&mut self, tag: u8) {
        self.deliver_answer(tag, Answer::Echo(0))
    }

    /// Answers a request of the driver's with a payload nearly filling a
    /// frame, however small the request was.
    fn blast(&mut self, tag: u8) {
        self.deliver_answer(tag, Answer::Echo(BULK))
    }

    /// Fails a request of the driver's.
    fn reject(&mut self, tag: u8) {
        self.deliver_answer(tag, Answer::Reject)
    }

    /// Delivers the answer to a request of the driver's, charging its bytes
    /// of the answers budget while the driver holds it untaken. A peer
    /// stockpiling more than the budget overran it, its session ended.
    fn deliver_answer(&mut self, tag: u8, answer: Answer) {
        if !self.open() {
            return;
        }
        let Some(id) = self.outstanding(tag) else {
            return;
        };
        let (message, outcome) = match answer {
            Answer::Echo(size) => (
                In::response(id, Some(In::develop(payload(tag, size))), None),
                Outcome::Payload(size),
            ),
            Answer::Reject => (
                In::response(
                    id,
                    None,
                    Some(protocol::Error {
                        code: REJECTION.0,
                        msg: REJECTION.1.into(),
                    }),
                ),
                Outcome::Rejected,
            ),
        };
        let message = message.encode_to_vec();
        let bytes = message.len().max(CHARGE);
        if !self.deliver(Delivery::Message(message)) {
            return;
        }

        // A reset ahead of the answer already drained the request, leaving
        // the answer to no request at all. A forgotten one is delivered to
        // nobody, its charge freed with it.
        let Some(track) = self.pending.remove(&id) else {
            return;
        };
        self.inflight -= track.bytes;
        if track.forgotten {
            return;
        }
        if self.buffered + bytes > ANSWERS {
            self.fault(Kind::Flooded);
            return;
        }
        self.buffered += bytes;
        self.settled.insert(tag, Settled { outcome, bytes });
    }

    /// Answers an id nobody asked under, either carrying a payload, which is
    /// dropped, or carrying nothing, which is the protocol broken.
    fn stray(&mut self, carried: bool) {
        if !self.open() {
            return;
        }
        let id = match self.side {
            Side::Client => u64::MAX,
            Side::Server => u64::MAX - 1,
        };
        let content = carried.then(|| In::develop(payload(0, 0)));
        if self.deliver(Delivery::Message(
            In::response(id, content, None).encode_to_vec(),
        )) && !carried
        {
            self.fault(Kind::Malformed);
        }
    }

    /// Sends bytes that are no envelope at all.
    fn junk(&mut self) {
        if !self.open() {
            return;
        }
        if self.deliver(Delivery::Message(vec![0x07])) {
            self.fault(Kind::Malformed);
        }
    }

    /// Sends a request of the peer's, which the worker takes if it is free
    /// and the inbox holds otherwise.
    fn ask(&mut self, tag: u8, size: usize) {
        if !self.open() {
            return;
        }
        let id = self.asks;
        self.asks += 2;

        let message = In::request(id, In::develop(payload(tag, size))).encode_to_vec();
        let bytes = message.len().max(CHARGE);
        if !self.deliver(Delivery::Message(message)) {
            return;
        }

        // A peer filling the inbox past its limit overran its window
        if self.queued + bytes > INBOX {
            self.fault(Kind::Flooded);
            return;
        }
        self.queued += bytes;
        self.inbox.push_back(Queued {
            id,
            tag: Some(tag),
            size,
            bytes,
            handle: self.handle,
        });
    }

    /// Sends a request of the peer's the multiplexer cannot read, which it
    /// queues like any other and its worker fails, the reader never waiting
    /// on the write.
    fn ask_void(&mut self) {
        if !self.open() {
            return;
        }
        let id = self.asks;
        self.asks += 2;

        // A request with no content at all, which the envelope allows and the
        // multiplexer cannot make anything of
        let message = In::response(id, None, None).encode_to_vec();
        let bytes = message.len().max(CHARGE);
        if !self.deliver(Delivery::Message(message)) {
            return;
        }

        // A peer filling the inbox past its limit overran its window
        if self.queued + bytes > INBOX {
            self.fault(Kind::Flooded);
            return;
        }
        self.queued += bytes;
        self.inbox.push_back(Queued {
            id,
            tag: None,
            size: 0,
            bytes,
            handle: self.handle,
        });
    }

    /// Sends requests until the inbox is past its limit, the worker holding
    /// the first one so the rest pile up behind it.
    fn flood(&mut self) {
        if self.floods == 0 {
            return;
        }
        self.floods -= 1;

        for _ in 0..INBOX / BULK + 2 {
            if !self.open() {
                return;
            }
            self.ask(HOUSEKEEPING, BULK);
            self.dispatch();
            if self.told.contains(&Kind::Flooded) {
                return;
            }
        }
    }

    /// Has the handler act on the request it holds, the answer going into the
    /// session that request arrived in.
    fn serve(&mut self, order: Order) {
        let Some(held) = self.held.take() else {
            return;
        };
        let orders = self.orders.as_ref().expect("handler still plugged in");
        orders.send(order).expect("worker running the handler");

        // The handler answers through the switchboard, its send refused with
        // no write once the multiplexer no longer takes calls, and a failed
        // write ending the session the side's way
        if !self.open() {
            return;
        }
        let failed = match order {
            Order::Reply => {
                let content = Some(Out::develop(payload(
                    held.tag.expect("the handler holds only what it can read"),
                    held.size,
                )));
                let message = Out::response(held.id, content, None);
                self.send(held.handle, message.encode_to_vec())
            }
            Order::Refuse => self.failure(held.handle, held.id, REFUSAL),
            Order::Ignore => self.failure(held.handle, held.id, UNANSWERED),
            // An answer the wire cannot carry is refused before it is sealed
            // and never reaches the peer, so only the one after it does
            Order::Bloat => {
                let content = Some(Out::develop(payload(
                    held.tag.expect("the handler holds only what it can read"),
                    held.size,
                )));
                let message = Out::response(held.id, content, None);
                self.send(held.handle, message.encode_to_vec())
            }
        };
        if let Some(kind) = failed {
            self.disconnected(held.handle, kind);
        }
    }

    /// Opens a session, the one before it dropped. A client's transport is
    /// its session, so it never sees another.
    fn reconnect(&mut self) {
        if self.side == Side::Client || !self.open() {
            return;
        }
        // A server's read reports the session it held ending at once, ahead
        // of the handshake that follows, and that handshake opening the next
        // one, so the multiplexer follows without a message of the peer's
        if self.link.held() {
            self.link.end_session();
            self.live = 0;
            self.deliver(Delivery::Disconnected);
        }
        let (sender, receiver) = self.link.create_session();
        self.receiver = Some(receiver);
        self.live = self.link.generation();
        self.summary.sessions += 1;
        self.deliver(Delivery::Connected(sender));
    }

    /// Ends the transport under the reader, which ends the multiplexer with
    /// it.
    fn unplug(&mut self) {
        if !self.open() {
            return;
        }
        self.deliveries
            .send(Delivery::Failed(transport::Error::Terminated))
            .expect("reader thread reading");
        self.fail(Kind::Terminated);
    }

    /// Makes the multiplexer's writes fail, or work again. An ended transport
    /// stays broken whatever is asked of it.
    fn set_broken(&mut self, broken: bool) {
        self.sink.set_broken(broken);
        self.broken = broken || self.closed;
    }

    /// Hands a delivery to the reader and waits for it to be dealt with, so
    /// the step after it never races the reader. Applies the transition the
    /// reader makes for it and tells whether a message would be routed at
    /// all, a session ending or a message arriving without one routing
    /// nothing.
    fn deliver(&mut self, delivery: Delivery) -> bool {
        // A transport hands no message up without a session, so one sent
        // into a session that ended never reaches the multiplexer at all
        if matches!(delivery, Delivery::Message(_)) && self.live == 0 {
            return false;
        }
        let session = match delivery {
            Delivery::Disconnected => Some(false),
            Delivery::Connected(_) => Some(true),
            _ => None,
        };
        self.deliveries
            .send(delivery)
            .expect("reader thread reading");
        self.routes
            .recv_timeout(PATIENCE)
            .expect("reader thread back for more");
        match session {
            Some(false) => self.reset(Kind::Reset),
            Some(true) => self.handle = self.live,
            None => {}
        }
        self.open()
    }

    /// Applies a peer breaking the protocol, which on a client is the
    /// multiplexer's end and on a server the session's alone, the next peer
    /// served after it.
    fn fault(&mut self, reason: Kind) {
        match self.side {
            Side::Client => self.fail(reason),
            Side::Server => {
                self.live = 0;
                self.write(Emit::Dropped);
                self.reset(reason);
            }
        }
    }

    /// Ends the session the multiplexer is bound to, every pending request
    /// failed with the reason, a request waiting for room refused with it,
    /// the queued ones dropped and the disconnect handler told. A session it
    /// already moved off ends nothing, a failed write having ended it first.
    fn reset(&mut self, reason: Kind) {
        if self.handle == 0 {
            return;
        }
        self.drain(reason);
        if let Some(blocked) = self.blocked.as_mut() {
            blocked.ended = Some(reason);
        }
        self.handle = self.live;
        self.ended = Some(reason);
        self.inbox.clear();
        self.queued = 0;
        self.told.push(reason);
    }

    /// Ends the multiplexer for the reason, telling the disconnect handler if
    /// it was open until now.
    fn fail(&mut self, reason: Kind) {
        if self.end(State::Failed(reason)) {
            self.told.push(reason);
        }
    }

    /// Ends the multiplexer in the state, every pending request failed
    /// accordingly, the queued ones dropped and the transport ended by the
    /// closer. Tells whether it was open until now.
    fn end(&mut self, state: State) -> bool {
        if !self.open() {
            return false;
        }
        self.state = state;
        let refusal = self.refusal();
        self.drain(refusal);
        self.inbox.clear();
        self.queued = 0;
        self.closed = true;
        self.broken = true;
        self.ending = true;
        true
    }

    /// Fails every pending request with the reason, freeing the window. The
    /// answers already delivered are the driver's to take or drop, their
    /// charges untouched by the session's end.
    fn drain(&mut self, reason: Kind) {
        self.inflight = 0;
        for track in std::mem::take(&mut self.pending).into_values() {
            if let Some(tag) = track.tag
                && !track.forgotten
            {
                self.settled.insert(
                    tag,
                    Settled {
                        outcome: Outcome::Fault(reason),
                        bytes: 0,
                    },
                );
            }
        }
    }

    /// Applies the multiplexer's reaction to a send failing, a client ending
    /// with its session and a server ending the session the send belonged to,
    /// the thread that wrote seeing it die before the reader would. A send
    /// into a session the multiplexer already moved off ends nothing.
    fn disconnected(&mut self, handle: u64, reason: Kind) -> Kind {
        match self.side {
            Side::Client => self.fail(reason),
            Side::Server if handle != 0 && handle == self.handle => self.reset(reason),
            Side::Server => {}
        }
        reason
    }

    /// Applies the multiplexer failing a request of the peer's on its own
    /// account, which is never reported anywhere but the log.
    fn failure(&mut self, handle: u64, id: u64, failure: (u64, &str)) -> Option<Kind> {
        let message = Out::response(
            id,
            None,
            Some(protocol::Error {
                code: failure.0,
                msg: failure.1.into(),
            }),
        );
        self.send(handle, message.encode_to_vec())
    }

    /// Applies a send of the multiplexer through the handle of a session,
    /// handing back what it fails with, if it does. The mux refuses work from
    /// an ended session with its last failure; otherwise the outbound side
    /// refuses a send into any but the live session before the transport is
    /// touched, a message too large refused before sealing, and a failed write
    /// ending the session and, on a server, telling the peer.
    fn send(&mut self, handle: u64, message: Vec<u8>) -> Option<Kind> {
        if self.handle == 0 || self.handle != handle {
            return Some(self.ended.unwrap_or(Kind::Reset));
        }
        if self.live == 0 || self.live != handle {
            return Some(Kind::NoSession);
        }
        if message.len() > MAX_MESSAGE_SIZE {
            return Some(Kind::TooLarge);
        }
        if self.write(Emit::Message(message)) {
            return None;
        }
        self.live = 0;
        if self.side == Side::Server {
            self.write(Emit::Dropped);
        }
        Some(Kind::SendFailed)
    }

    /// Applies a write of the multiplexer, telling whether it got out. A write
    /// after a failed one starts with a delimiter terminating what the failure
    /// left behind, which forms an empty frame of its own.
    fn write(&mut self, emit: Emit) -> bool {
        self.writes += 1;
        if self.broken {
            self.resync = true;
            return false;
        }
        if std::mem::take(&mut self.resync) {
            self.emits.push(Emit::Dropped);
        }
        self.emits.push(emit);
        true
    }

    /// Hands the next request to the worker if the handler is free, waiting
    /// for it to be taken.
    fn dispatch(&mut self) {
        while self.held.is_none() {
            let Some(queued) = self.inbox.pop_front() else {
                return;
            };
            self.queued -= queued.bytes;

            // One the multiplexer cannot read never reaches the handler, the
            // worker failing it for the peer and going straight on to the
            // next, so a run of them leaves the queue in one go
            let Some(tag) = queued.tag else {
                if let Some(kind) = self.failure(queued.handle, queued.id, NOT_UNDERSTOOD) {
                    self.disconnected(queued.handle, kind);
                }
                self.summary.declined += 1;
                continue;
            };
            let taken = self
                .entered
                .recv_timeout(PATIENCE)
                .expect("handler taking the request");
            assert_eq!(
                (tagged(&taken), taken.len()),
                (u64::from(tag), payload_len(queued.size))
            );
            self.summary.served += 1;
            self.held = Some(queued);
        }
    }

    /// Joins the request waiting for room in the window once an answer or a
    /// fault freed it, or its session ended under it, checking the call
    /// against the model.
    fn unblock(&mut self) {
        let Some(blocked) = self.blocked.as_ref() else {
            return;
        };
        if self.open() && blocked.ended.is_none() && self.inflight + blocked.bytes > WINDOW {
            return;
        }
        let blocked = self.blocked.take().expect("checked just above");
        let refusal = match (self.open(), blocked.ended) {
            (false, _) => Some(self.refusal()),
            (true, Some(ended)) => Some(ended),
            (true, None) => self.admit(blocked.tag, blocked.id, blocked.bytes, blocked.message),
        };
        let result = blocked
            .result
            .recv_timeout(PATIENCE)
            .expect("request thread returning once the window frees");
        blocked.call.join().expect("request thread");
        self.called(blocked.tag, result, refusal);
    }

    /// Whether the multiplexer still takes calls, its reader still reading.
    fn open(&self) -> bool {
        self.state == State::Open
    }

    /// The error every call gets once calls are no longer taken, the fault
    /// that ended the session or plain closed.
    fn refusal(&self) -> Kind {
        match self.state {
            State::Failed(reason) => reason,
            State::Open | State::Closed => Kind::Closed,
        }
    }

    /// Waits for everything the model said the multiplexer would do and checks
    /// it against what actually happened, run after every step.
    fn settle(&mut self) {
        for _ in 0..std::mem::take(&mut self.writes) {
            self.attempts
                .recv_timeout(PATIENCE)
                .expect("write attempt the model expected");
        }
        // A failed write reports back from inside the write, and the outbound side
        // ends its session only after that, on the thread that wrote, so wait
        // for the outbound side to catch up with the model before the next step
        // reads the session off it
        let deadline = Instant::now() + PATIENCE;
        while self.link.generation() != self.live {
            assert!(
                Instant::now() < deadline,
                "outbound side in session {} where the model has {}",
                self.link.generation(),
                self.live
            );
            thread::sleep(Duration::from_millis(1));
        }
        if std::mem::take(&mut self.ending) {
            self.ends
                .recv_timeout(PATIENCE)
                .expect("reader thread winding down");
        }
        for reason in std::mem::take(&mut self.told) {
            let told = self
                .notices
                .recv_timeout(PATIENCE)
                .expect("disconnect the model expected");
            assert_eq!(told, reason);
            self.summary.disconnects += 1;
        }
        self.sync();
    }

    /// Checks the frames the multiplexer wrote against the ones the model
    /// expected, opening each with the context of the session it went into.
    fn sync(&mut self) {
        let frames = self.sink.take_frames();
        let emits = std::mem::take(&mut self.emits);
        assert_eq!(frames.len(), emits.len(), "model expected {emits:?}");

        for (frame, emit) in frames.iter().zip(emits) {
            match emit {
                Emit::Dropped => assert!(
                    frame.is_empty(),
                    "expected an empty frame, multiplexer wrote {} bytes",
                    frame.len()
                ),
                Emit::Message(want) => {
                    assert!(
                        !frame.is_empty(),
                        "expected a message, multiplexer wrote an empty frame"
                    );
                    let receiver = self
                        .receiver
                        .as_mut()
                        .expect("message written without a session");
                    let opened = receiver
                        .open(&unframe(frame), &[])
                        .expect("message failed to open");
                    assert!(
                        opened == want,
                        "multiplexer wrote {}, model expected {}",
                        describe::<Out>(&opened),
                        describe::<Out>(&want)
                    );
                }
            }
        }
    }
}

/// Runs a script against a real multiplexer of the side, panicking on any
/// divergence from the model, and reports what the run observed.
fn run<Out: Tagged, In: Tagged>(side: Side, steps: &[Step]) -> Summary {
    let (sink, attempts) = Sink::new();
    let (feed, deliveries, routes, ends) = Feed::new(side, sink.clone());
    let link = feed.link.clone();

    // A client's transport hands over the session its handshake opened, a
    // server's waits for a peer to open the first one
    let (sender, receiver) = match side {
        Side::Client => {
            let (sender, receiver) = link.create_session();
            (Some(sender), Some(receiver))
        }
        Side::Server => (None, None),
    };
    let session = link.generation();

    let mux = Arc::new(Mux::<Out, In>::mocked(side, feed, sender));

    // Wait for the reader to reach its first read, which is where it takes
    // down the session it starts from, so no step can move that under it
    routes
        .recv_timeout(PATIENCE)
        .expect("reader thread starting up");

    let (told, notices) = mpsc::channel();
    mux.on_disconnect(move |reason| {
        let _ = told.send(kind(reason));
    });

    // The handler tells the driver what it took and waits for the order
    // deciding what it answers, so the worker never runs ahead of the model
    let (taken, entered) = mpsc::channel();
    let (orders, ordered) = mpsc::channel();
    mux.on_request(move |content, mut responder: Responder<Out>| {
        let payload = In::payload(content);
        let _ = taken.send(payload.clone());
        match ordered.recv() {
            Ok(Order::Reply) => {
                let _ = responder.reply(Out::develop(payload));
            }
            Ok(Order::Refuse) => {
                let _ = responder.fail(protocol::Error {
                    code: REFUSAL.0,
                    msg: REFUSAL.1.into(),
                });
            }
            Ok(Order::Bloat) => {
                let bloated = super::payload(HOUSEKEEPING, MAX_MESSAGE_SIZE + 1);
                let _ = responder.reply(Out::develop(bloated));
                let _ = responder.reply(Out::develop(payload));
            }
            Ok(Order::Ignore) | Err(_) => drop(responder),
        }
    });

    let mut peer = Peer::<Out, In> {
        steps: steps.iter().take(MAX_STEPS).cloned().collect(),
        mux,
        link,
        sink,
        receiver,
        deliveries,
        routes,
        ends,
        attempts,
        entered,
        orders: Some(orders),
        notices,
        side,
        state: State::Open,
        ending: false,
        broken: false,
        closed: false,
        resync: false,
        live: session,
        handle: session,
        ended: None,
        ids: match side {
            Side::Client => 1,
            Side::Server => 2,
        },
        asks: match side {
            Side::Client => 2,
            Side::Server => 1,
        },
        pending: HashMap::new(),
        inflight: 0,
        waiting: HashMap::new(),
        settled: HashMap::new(),
        buffered: 0,
        blocked: None,
        inbox: VecDeque::new(),
        queued: 0,
        held: None,
        floods: MAX_FLOODS,
        emits: Vec::new(),
        writes: 0,
        told: Vec::new(),
        summary: Summary::default(),
    };

    while let Some(step) = peer.steps.pop_front() {
        peer.execute(step);
        peer.dispatch();
        peer.unblock();
        peer.settle();
    }
    peer.summary.closed = !peer.open();
    let summary = peer.summary;

    // Nothing beyond what the model expected may be in flight by now, the
    // last step having waited for all of it
    assert!(
        peer.attempts.try_recv().is_err(),
        "unexpected write attempt"
    );
    assert!(peer.notices.try_recv().is_err(), "unexpected disconnect");

    // Wind the threads down, the close ending the reader and freeing any
    // request still waiting for room, the orders going with the handler
    peer.mux.close();
    peer.orders = None;
    if let Some(blocked) = peer.blocked.take() {
        let _ = blocked.result.recv_timeout(PATIENCE);
        blocked.call.join().expect("request thread");
    }
    summary
}

/// Runs a script against a real client multiplexer, what a host holds.
pub fn run_client(steps: &[Step]) -> Summary {
    #[cfg(feature = "fuzz")]
    super::seed::seed(super::seed::PROTOCOL_CLIENT, steps);

    run::<HostToArk, ArkToHost>(Side::Client, steps)
}

/// Runs a script against a real server multiplexer, what an Ark holds.
pub fn run_server(steps: &[Step]) -> Summary {
    #[cfg(feature = "fuzz")]
    super::seed::seed(super::seed::PROTOCOL_SERVER, steps);

    run::<ArkToHost, HostToArk>(Side::Server, steps)
}

#[cfg(test)]
mod tests;
