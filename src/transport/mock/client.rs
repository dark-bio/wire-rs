// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Mock client driving a real `Server`. Script steps provide incoming frames,
//! inject I/O failures, or ask the driver to call a server method. The driver
//! receives events in a loop and replies to each tagged request. The read adapter
//! advances the script after the server consumes the previous step's bytes.
//!
//! A separate model predicts the server's state, outgoing frames, and receive
//! events. Before providing more input, the mock checks the server's output
//! against those predictions. Any difference panics.

use super::{
    CutPoint, MAX_STEPS, OVERSIZED_MESSAGE, Outbox, SCRIPT_HANDSHAKE_TIMEOUT, TIMESTAMP, frame,
    self_attestation, unframe, would_block,
};
use crate::transport::Read;
use crate::transport::handshake;
use crate::transport::mock::payload;
use crate::transport::sealing;
use crate::transport::{
    Attestation, CRYPTO_DOMAIN_WIRE, CRYPTO_DOMAIN_WIRE_ARK_TO_HOST,
    CRYPTO_DOMAIN_WIRE_HOST_TO_ARK, Error, Event, MAX_FRAME_SIZE, Sender,
};
use darkbio_crypto::{cbor, cose, xdsa, xhpke};
use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Message id of the probes the driver sends on the server's behalf.
const PROBE_ID: u64 = u64::MAX;

/// One scripted input, I/O fault, or driver action. A step that needs a missing
/// session or ArkHello sends junk instead, so arbitrary step sequences are valid.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum Step {
    // Handshake input.
    /// A lone zero, one empty frame.
    Reset,
    /// Two zeros, matching [`Client::connect`](crate::transport::Client::connect).
    ResetPair,
    /// A valid HostHello with fresh ephemeral keys.
    Hello,
    /// The last HostHello sent, repeated. Nothing if none was sent yet.
    HelloReplay,
    /// A HostHello carrying an encryption key that fails validation.
    HelloBadKey,
    /// A valid HostAck for the ArkHello last received. Junk if there is none.
    Ack,
    /// The last HostAck sent, repeated. Nothing if none was sent yet.
    AckReplay,
    /// A HostAck for the ArkHello last received with a flipped ciphertext
    /// byte. Junk if there is none.
    AckTampered,
    /// A HostAck bound to the wrong server key. Junk without a pending ArkHello.
    AckBadAuth,
    /// A HostAck signed by a key absent from the HostHello. Junk without a
    /// pending ArkHello.
    AckBadSigner,
    /// A HostAck for the ArkHello last received whose sealed payload is not
    /// an ack at all. Junk if there is none.
    AckBadPayload,
    /// A HostAck for the ArkHello last received with an encapsulated key of
    /// the wrong size. Junk if there is none.
    AckBadEncap,

    // Session input.
    /// A sealed request tagged by the byte. Junk without a session.
    Request(u8),
    /// The last sealed request sent, repeated. Nothing if none was sent yet.
    RequestReplay,
    /// A sealed request with a flipped ciphertext byte. Junk without a
    /// session.
    RequestTampered,
    /// A sealed packet that is not a protobuf message. Junk without a session.
    Garbage,

    // Malformed and partial frames.
    /// Arbitrary frame bytes, with zeros replaced and an empty input padded.
    /// The model expects rejection during framing, key validation, or decryption.
    Junk(Vec<u8>),
    /// The last valid frame sent cut short, keeping at least one byte. Nothing
    /// if no valid frame was sent yet.
    Truncated(u8),
    /// A valid HostHello without its delimiter. A following zero completes the
    /// hello; any other frame merges into its bytes and makes it invalid.
    Partial,
    /// A frame past the size limit, delimiter included. The server rejects it
    /// as soon as the limit is exceeded, ending any session or handshake. Its
    /// remaining bytes and any partial hello in front are discarded together.
    Oversized,

    // Calls through the server and its senders.
    /// Retains the server's current sender separately, replacing any previously
    /// retained handle. Without a current sender, clears the retained slot.
    Retain,
    /// Sends a message through the server's current sender, without a request.
    Send(u8),
    /// Sends through the retained sender, including after its session ends.
    /// Without a retained handle, checks the same refusal as a missing sender.
    SendRetained(u8),
    /// Sends a message one byte over the conservative send limit.
    SendOversized,
    /// Ends the server's session locally and signals the client. No local
    /// disconnection event is expected; the stream can establish another session.
    Disconnect,

    // Read scheduling and faults.
    /// Limits each read to this many bytes. Zero removes the limit.
    Chunk(u8),
    /// Batches up to this many steps into one read. Stops at a step that produces
    /// a receive event, so the driver handles it before the model advances again.
    /// A step that queues no frames also ends the batch.
    Batch(u8),
    /// The read fails with `WouldBlock`, handing control back to the driver.
    Yield,
    /// The read returns `Interrupted`. Framing retries without a server event.
    Interrupt,
    /// An adapter read returns an early timeout; the server keeps waiting without a transition.
    ReadTimeout,

    // Write faults.
    /// The server's writes fail until a Heal step.
    Break,
    /// The server's writes work again.
    Heal,
    /// Cuts the next matching server write. If requested, all later writes fail
    /// until a Heal step.
    Cut { point: CutPoint, then_broken: bool },
    /// The next matching output operation expires after the selected prefix,
    /// leaving no budget for a failure notification on that operation.
    Timeout(CutPoint),
}

impl Step {
    /// Whether the driver must act on the server or one of its sender handles.
    fn is_action(&self) -> bool {
        matches!(
            self,
            Self::Retain
                | Self::Send(_)
                | Self::SendRetained(_)
                | Self::SendOversized
                | Self::Disconnect
        )
    }

    /// Whether this step can join an input batch without driver or I/O changes.
    fn queues_frames(&self) -> bool {
        !self.is_action()
            && !matches!(
                self,
                Step::Yield
                    | Step::Interrupt
                    | Step::Break
                    | Step::Heal
                    | Step::Cut { .. }
                    | Step::Chunk(_)
                    | Step::Batch(_)
                    | Step::Timeout(_)
                    | Step::ReadTimeout
            )
    }
}

/// Server state predicted by the model.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum State {
    /// No session and no handshake in progress.
    #[default]
    Idle,
    /// A reset arrived; the server is waiting for HostHello.
    AwaitHello,
    /// ArkHello was sent; the server is waiting for HostAck.
    AwaitAck,
    /// A session is live in both directions.
    Established,
}

/// Final model state and observed counts for scenario assertions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub state: State,      // State the server ended up in
    pub dropped: usize,    // Empty frames the server emitted
    pub fragments: usize,  // Frames the server left cut short, terminated later
    pub handshakes: usize, // ArkHellos the server emitted
    pub delivered: usize,  // Requests the server delivered
    pub replies: usize,    // Replies and probes that reached the client
    pub reads: usize,      // Reads that handed the server bytes
}

/// Meaning of an incoming frame in the model.
enum Frame {
    /// The empty frame, a reset.
    Empty,
    /// A valid HostHello announcing the keys.
    Hello(Box<Keys>),
    /// A valid HostAck for the ArkHello last received.
    Ack,
    /// A request with the id, sealed in the session.
    Request(u64),
    /// Sealed bytes outside the tagged request format, still valid transport data.
    Garbage,
    /// Anything else, refused in every state.
    Junk,
}

/// Unterminated input retained until the next frame delimiter.
enum Partial {
    /// The stream is at a frame boundary.
    None,
    /// A hello completed successfully only if the next byte is a delimiter.
    Hello(Box<Keys>),
    /// Bytes no delimiter can complete into anything valid.
    Junk,
}

/// Expected server frame and the data needed to verify it.
enum Emit {
    /// An empty frame from a session-end signal or an unused recovery delimiter.
    Dropped,
    /// The prefix of a frame cut short, meaning nothing to the client.
    Fragment,
    /// The handshake reply sealed to these client keys.
    ArkHello(Box<Keys>),
    /// A sealed tagged reply and the receiver needed to open it.
    Reply(u64, Arc<Mutex<xhpke::Receiver>>),
}

impl fmt::Debug for Emit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Emit::Dropped => write!(f, "Dropped"),
            Emit::Fragment => write!(f, "Fragment"),
            Emit::ArkHello(_) => write!(f, "ArkHello"),
            Emit::Reply(id, _) => write!(f, "Reply({id})"),
        }
    }
}

/// Unterminated server output left by a failed send. The next recovery delimiter
/// completes it.
enum Tail {
    /// A prefix of the body, decoding to nothing the client accepts.
    Fragment,
    /// A complete body that becomes a valid frame when its delimiter arrives.
    Body(Emit),
}

/// Server output whose success or failure the model must predict.
enum Payload {
    /// A frame expected by the output verifier.
    Frame(Emit),
    /// The signal that the server has no session, a lone delimiter.
    Signal,
}

/// What the model expects `recv` to surface for the last step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    /// The server keeps reading.
    Absorbed,
    /// A request with this tag is delivered.
    Message(u64),
    /// Untagged bytes are delivered without ending the session.
    Garbage,
    /// [`Event::Disconnected`] after a reset or invalid frame ends the session.
    Ended,
    /// [`Event::Connected`] after HostAck establishes a session.
    Opened,
    /// [`Error::RecvFailed`] carrying `WouldBlock`.
    Yield,
    /// [`Error::SendFailed`], an ArkHello whose write or flush failed.
    SendFailed,
    /// [`Error::Terminated`] after the script runs out.
    Terminated,
}

/// Ephemeral keys of a HostHello.
#[derive(Clone)]
struct Keys {
    signer: xdsa::SecretKey,
    crypto: xhpke::SecretKey,
}

impl Keys {
    /// Generates fresh signing and encryption keys for one HostHello.
    fn generate() -> Self {
        Self {
            signer: xdsa::SecretKey::generate(),
            crypto: xhpke::SecretKey::generate(),
        }
    }

    /// Encodes a HostHello announcing these public keys.
    fn hello(&self) -> Vec<u8> {
        cbor::encode(&handshake::HostHello {
            host_signer: self.signer.public_key(),
            host_crypto: self.crypto.public_key(),
        })
        .unwrap()
    }
}

/// One defect to introduce into an otherwise valid HostAck.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AckFlaw {
    /// A flipped ciphertext byte prevents decryption.
    Tampered,
    /// Bound to another server key than the one that answered.
    Auth,
    /// Signed by a key other than the hello's.
    Signer,
    /// A sealed payload that is not an ack at all.
    Payload,
    /// An encapsulated key of the wrong size.
    Encap,
}

/// Client keys and server response needed to create HostAck. Kept only while
/// the model expects the server to accept that ack.
struct Pending {
    keys: Keys,
    ark_crypto: xhpke::PublicKey,
    receiver: xhpke::Receiver,
}

impl Pending {
    /// Creates HostAck and the client's two contexts for the new session.
    fn ack(self, identity: &xdsa::PublicKey) -> (Vec<u8>, xhpke::Sender, xhpke::Receiver) {
        let (sender, encap) = self
            .ark_crypto
            .new_sender(CRYPTO_DOMAIN_WIRE_HOST_TO_ARK)
            .unwrap();
        let ack = cose::seal_at(
            &handshake::HostAck {
                h2a_encap: encap.to_vec(),
            },
            &handshake::HostAckAuth {
                ark_signer: identity.clone(),
                ark_crypto: self.ark_crypto.clone(),
            },
            &self.keys.signer,
            &self.ark_crypto,
            CRYPTO_DOMAIN_WIRE,
            TIMESTAMP,
        )
        .unwrap();
        (ack, sender, self.receiver)
    }

    /// Creates HostAck with the selected defect and no other intentional faults.
    fn bad_ack(&self, identity: &xdsa::PublicKey, flaw: AckFlaw) -> Vec<u8> {
        let (_, encap) = self
            .ark_crypto
            .new_sender(CRYPTO_DOMAIN_WIRE_HOST_TO_ARK)
            .unwrap();
        let auth = handshake::HostAckAuth {
            ark_signer: identity.clone(),
            ark_crypto: match flaw {
                AckFlaw::Auth => xhpke::SecretKey::generate().public_key(),
                _ => self.ark_crypto.clone(),
            },
        };
        let stranger = xdsa::SecretKey::generate();
        let signer = match flaw {
            AckFlaw::Signer => &stranger,
            _ => &self.keys.signer,
        };
        let mut sealed = match flaw {
            AckFlaw::Payload => cose::seal_at(
                &(vec![1u8], vec![2u8]),
                &auth,
                signer,
                &self.ark_crypto,
                CRYPTO_DOMAIN_WIRE,
                TIMESTAMP,
            ),
            _ => cose::seal_at(
                &handshake::HostAck {
                    h2a_encap: match flaw {
                        AckFlaw::Encap => vec![0x42; 3],
                        _ => encap.to_vec(),
                    },
                },
                &auth,
                signer,
                &self.ark_crypto,
                CRYPTO_DOMAIN_WIRE,
                TIMESTAMP,
            ),
        }
        .unwrap();
        if flaw == AckFlaw::Tampered {
            *sealed.last_mut().unwrap() ^= 0xff;
        }
        sealed
    }
}

/// Mock client along with the model of the server it drives.
pub struct Client {
    steps: VecDeque<Step>,
    action: Option<Step>,      // Driver action that interrupted a receive call
    identity: xdsa::PublicKey, // The server's identity, verifying its hellos
    outbox: Outbox,            // Frames the server wrote
    bytes: Vec<u8>,            // Current input batch, retained until fully delivered
    offset: usize,             // Position within the current input batch
    chunk: usize,              // Maximum bytes per read; zero means unlimited
    batch: usize,              // Steps remaining in the current input batch
    broken: bool,              // Whether the server's writes fail
    cut: Option<CutPoint>,     // Cut armed for the next matching server write
    timeout: bool,             // Whether the armed cut expires the operation budget
    timed_out: bool,           // Whether the last modeled send exhausted that budget

    state: State,       // State the server should be in
    partial: Partial,   // Unterminated frame in front of the server
    resync: bool,       // Failed output requires a recovery delimiter before the next send
    tail: Option<Tail>, // Unterminated frame the server left behind
    emits: Vec<Emit>,   // Frames the server should have emitted since the last sync
    outcome: Outcome,   // What recv should surface for the last step
    held: bool,         // Receive side owes a Disconnected event when this session ends

    pending: Option<Pending>, // ArkHello received, awaiting the client's ack
    sender: Option<xhpke::Sender>, // Seals client requests in the current session
    receiver: Option<Arc<Mutex<xhpke::Receiver>>>, // Opens replies, including those awaiting verification

    last_hello: Option<(Vec<u8>, Keys)>, // Last HostHello sent, framed
    last_ack: Option<Vec<u8>>,           // Last HostAck sent, framed
    last_request: Option<Vec<u8>>,       // Last request sent, framed
    last_valid: Option<Vec<u8>>,         // Last valid frame sent, delimiter stripped

    summary: Summary,
}

impl Client {
    /// Starts an idle model with a bounded script and the server's output queue.
    fn new(steps: &[Step], identity: xdsa::PublicKey, outbox: Outbox) -> Self {
        Self {
            steps: steps.iter().take(MAX_STEPS).cloned().collect(),
            action: None,
            identity,
            outbox,
            bytes: Vec::new(),
            offset: 0,
            chunk: 0,
            batch: 0,
            broken: false,
            cut: None,
            timeout: false,
            timed_out: false,
            state: State::Idle,
            partial: Partial::None,
            resync: false,
            tail: None,
            emits: Vec::new(),
            outcome: Outcome::Absorbed,
            held: false,
            pending: None,
            sender: None,
            receiver: None,
            last_hello: None,
            last_ack: None,
            last_request: None,
            last_valid: None,
            summary: Summary::default(),
        }
    }

    /// Takes an action at the current script position, before another receive
    /// can consume frames. Actions encountered inside a receive are saved by Feed.
    fn next_action(&mut self) -> Option<Step> {
        if self.action.is_some() {
            return self.action.take();
        }
        if self.bytes.is_empty() && self.steps.front().is_some_and(Step::is_action) {
            self.sync();
            return self.steps.pop_front();
        }
        None
    }

    /// Queues one step's input and predicts the server's reaction to its frames.
    fn execute(&mut self, step: Step) {
        match step {
            Step::Reset => {
                self.deliver(Frame::Empty);
                self.bytes.push(0x00);
            }
            Step::ResetPair => {
                self.deliver(Frame::Empty);
                self.deliver(Frame::Empty);
                self.bytes.extend([0x00, 0x00]);
            }
            Step::Hello => {
                let keys = Keys::generate();
                let framed = frame(&keys.hello());
                self.record(&framed);
                self.last_hello = Some((framed.clone(), keys.clone()));
                self.deliver(Frame::Hello(Box::new(keys)));
                self.bytes.extend(framed);
            }
            Step::HelloReplay => {
                if let Some((framed, keys)) = self.last_hello.clone() {
                    self.deliver(Frame::Hello(Box::new(keys)));
                    self.bytes.extend(framed);
                }
            }
            Step::HelloBadKey => {
                let signer = xdsa::SecretKey::generate().public_key().to_bytes().to_vec();
                let hello = cbor::encode(&(signer, vec![0xffu8; xhpke::PUBLIC_KEY_SIZE])).unwrap();
                self.junk(&hello);
            }
            Step::Ack => match self.pending.take() {
                Some(pending) => {
                    let (ack, sender, receiver) = pending.ack(&self.identity);
                    let framed = frame(&ack);
                    self.record(&framed);
                    self.last_ack = Some(framed.clone());
                    self.sender = Some(sender);
                    self.receiver = Some(Arc::new(Mutex::new(receiver)));
                    self.deliver(Frame::Ack);
                    self.bytes.extend(framed);
                }
                None => self.junk(b"ack without a pending server hello"),
            },
            Step::AckReplay => {
                if let Some(framed) = self.last_ack.clone() {
                    self.deliver(Frame::Junk);
                    self.bytes.extend(framed);
                }
            }
            Step::AckTampered => self.bad_ack(AckFlaw::Tampered),
            Step::AckBadAuth => self.bad_ack(AckFlaw::Auth),
            Step::AckBadSigner => self.bad_ack(AckFlaw::Signer),
            Step::AckBadPayload => self.bad_ack(AckFlaw::Payload),
            Step::AckBadEncap => self.bad_ack(AckFlaw::Encap),
            Step::Request(tag) => match self.sender.as_mut() {
                Some(sender) => {
                    let id = tag as u64;
                    let packet = sealing::seal(sender, &payload(id)).unwrap();
                    let framed = frame(&packet);
                    self.record(&framed);
                    self.last_request = Some(framed.clone());
                    self.deliver(Frame::Request(id));
                    self.bytes.extend(framed);
                }
                None => self.junk(b"request without a session"),
            },
            Step::RequestReplay => {
                if let Some(framed) = self.last_request.clone() {
                    self.deliver(Frame::Junk);
                    self.bytes.extend(framed);
                }
            }
            Step::RequestTampered => match self.sender.as_mut() {
                Some(sender) => {
                    let mut packet = sealing::seal(sender, &payload(0)).unwrap();
                    *packet.last_mut().unwrap() ^= 0xff;
                    self.junk(&packet);
                }
                None => self.junk(b"tampered request without a session"),
            },
            Step::Garbage => match self.sender.as_mut() {
                Some(sender) => {
                    let packet = sender.seal(&[0x07], &[]).unwrap();
                    let framed = frame(&packet);
                    self.record(&framed);
                    self.deliver(Frame::Garbage);
                    self.bytes.extend(framed);
                }
                None => self.junk(b"garbage without a session"),
            },
            Step::Junk(mut junk) => {
                for byte in junk.iter_mut() {
                    if *byte == 0 {
                        *byte = 1;
                    }
                }
                if junk.is_empty() {
                    junk.push(1);
                }
                self.deliver(Frame::Junk);
                self.bytes.extend(junk);
                self.bytes.push(0x00);
            }
            Step::Truncated(n) => {
                if let Some(valid) = self.last_valid.clone() {
                    let keep = match valid.len() {
                        0..=1 => 1,
                        len => 1 + n as usize % (len - 1),
                    };
                    self.deliver(Frame::Junk);
                    self.bytes.extend(&valid[..keep]);
                    self.bytes.push(0x00);
                }
            }
            Step::Partial => {
                let keys = Keys::generate();
                let mut framed = frame(&keys.hello());
                framed.pop();
                self.bytes.extend(framed);
                self.partial = match self.partial {
                    Partial::None => Partial::Hello(Box::new(keys)),
                    _ => Partial::Junk,
                };
            }
            Step::Oversized => {
                self.partial = Partial::None;
                // Rejection precedes draining the tail and delimiter. An ended
                // session stops batching here, so the driver sees its event
                // before any later step changes the model again.
                self.deliver(Frame::Junk);
                self.bytes.resize(self.bytes.len() + MAX_FRAME_SIZE + 1, 1);
                self.bytes.push(0x00);
            }
            Step::Chunk(n) => self.chunk = n as usize,
            Step::Batch(n) => self.batch = n as usize,
            Step::Break => self.set_broken(true),
            Step::Heal => self.set_broken(false),
            Step::Cut { point, then_broken } => {
                self.cut = Some(point);
                self.timeout = false;
                self.outbox.set_cut(point);
                if then_broken {
                    self.set_broken(true);
                }
            }
            Step::Timeout(point) => {
                self.cut = Some(point);
                self.timeout = true;
                self.outbox.set_timeout(point);
            }
            Step::Yield
            | Step::Interrupt
            | Step::ReadTimeout
            | Step::Retain
            | Step::Send(_)
            | Step::SendRetained(_)
            | Step::SendOversized
            | Step::Disconnect => {
                unreachable!("control steps are handled by the reader and driver")
            }
        }
    }

    /// Queues a defective HostAck, or junk if no ArkHello is pending. Both should
    /// make the server reject the handshake.
    fn bad_ack(&mut self, flaw: AckFlaw) {
        match self.pending.as_ref() {
            Some(pending) => {
                let ack = pending.bad_ack(&self.identity, flaw);
                self.junk(&ack);
            }
            None => self.junk(b"bad ack without a pending server hello"),
        }
    }

    /// Queues a valid COBS frame of content the server refuses.
    fn junk(&mut self, text: &[u8]) {
        self.deliver(Frame::Junk);
        self.bytes.extend(frame(text));
    }

    /// Remembers the frame as the last valid one, for truncating later.
    fn record(&mut self, framed: &[u8]) {
        self.last_valid = Some(framed[..framed.len() - 1].to_vec());
    }

    /// Makes the server's writes fail, or work again.
    fn set_broken(&mut self, broken: bool) {
        self.outbox.set_broken(broken);
        self.broken = broken;
    }

    /// Predicts the server's response to an incoming frame. A preceding partial
    /// hello is valid only if this frame supplies its missing delimiter. Other
    /// combinations of partial input and new bytes become junk.
    fn deliver(&mut self, frame: Frame) {
        let frame = match std::mem::replace(&mut self.partial, Partial::None) {
            Partial::None => frame,
            Partial::Hello(keys) => match frame {
                Frame::Empty => Frame::Hello(keys),
                _ => Frame::Junk,
            },
            Partial::Junk => Frame::Junk,
        };
        match (self.state, frame) {
            // A reset starts a handshake in every state without a wire reply.
            // Report any old session's end before continuing the handshake.
            (_, Frame::Empty) => {
                if std::mem::take(&mut self.held) {
                    self.outcome = Outcome::Ended;
                }
                self.forget();
                self.state = State::AwaitHello;
            }
            // Failed ArkHello output aborts the handshake. A non-timeout failure
            // also attempts a session-end signal with the remaining budget.
            (State::AwaitHello, Frame::Hello(keys)) => {
                if self.send(Payload::Frame(Emit::ArkHello(keys))) {
                    self.state = State::AwaitAck;
                } else {
                    self.forget();
                    self.state = State::Idle;
                    if !self.timed_out {
                        self.send(Payload::Signal);
                    }
                    self.outcome = Outcome::SendFailed;
                }
            }
            // Deliver the new sender as soon as HostAck completes the handshake.
            (State::AwaitAck, Frame::Ack) => {
                self.state = State::Established;
                self.held = true;
                self.outcome = Outcome::Opened;
            }
            (State::Established, Frame::Request(id)) => {
                self.outcome = Outcome::Message(id);
            }
            // Transport delivers opaque bytes without inspecting their format.
            (State::Established, Frame::Garbage) => {
                self.outcome = Outcome::Garbage;
            }
            // Invalid input abandons the handshake or session and attempts a
            // wire signal. An existing session also produces Disconnected.
            _ => {
                self.forget();
                self.state = State::Idle;
                self.send(Payload::Signal);
                if std::mem::take(&mut self.held) {
                    self.outcome = Outcome::Ended;
                }
            }
        }
    }

    /// Predicts one server send, including its recovery delimiter in the same
    /// write as the frame. An applicable cut fires before a broken stream;
    /// a middle cut at zero can accept only recovery, leaving no new fragment.
    fn send(&mut self, payload: Payload) -> bool {
        let frame = matches!(&payload, Payload::Frame(_));
        let cut = match self.cut {
            Some(CutPoint::Start) => self.cut.take(),
            Some(CutPoint::Middle(_)) if frame => self.cut.take(),
            Some(CutPoint::Delimiter | CutPoint::Flush) if frame || self.resync => self.cut.take(),
            _ => None,
        };
        self.timed_out = cut.is_some() && std::mem::take(&mut self.timeout);
        let sent = match cut {
            Some(CutPoint::Start) => false,
            None if self.broken => false,
            _ => {
                if self.resync {
                    self.zero_out();
                }
                match (payload, cut) {
                    (Payload::Frame(_), Some(CutPoint::Middle(n))) => {
                        if !self.resync || n != 0 {
                            self.tail = Some(Tail::Fragment);
                        }
                        false
                    }
                    (Payload::Frame(emit), Some(CutPoint::Delimiter)) => {
                        self.tail = Some(Tail::Body(emit));
                        false
                    }
                    (Payload::Frame(emit), _) => {
                        self.emits.push(emit);
                        cut != Some(CutPoint::Flush)
                    }
                    (Payload::Signal, Some(CutPoint::Delimiter)) => false,
                    (Payload::Signal, _) => {
                        self.zero_out();
                        cut != Some(CutPoint::Flush)
                    }
                }
            }
        };
        self.resync = !sent;
        sent
    }

    /// Predicts a delimiter reaching the wire. It completes any pending tail,
    /// or creates an empty frame when no tail exists.
    fn zero_out(&mut self) {
        self.emits.push(match self.tail.take() {
            None => Emit::Dropped,
            Some(Tail::Fragment) => Emit::Fragment,
            Some(Tail::Body(emit)) => emit,
        });
    }

    /// Clears the model's current session and pending handshake. Expected replies
    /// retain their receiver until the output verifier checks them.
    fn forget(&mut self) {
        self.sender = None;
        self.receiver = None;
        self.pending = None;
    }

    /// Predicts a read error or EOF. It aborts an unfinished handshake; an
    /// established session remains until the server reports its end.
    fn interrupt(&mut self, outcome: Outcome) {
        if matches!(self.state, State::AwaitHello | State::AwaitAck) {
            self.forget();
            self.state = State::Idle;
        }
        self.outcome = outcome;
    }

    /// Checks the receive result, then clears the expectation for the next step.
    fn surfaced(&mut self, outcome: Outcome) {
        assert_eq!(self.outcome, outcome, "model vs server");
        self.outcome = Outcome::Absorbed;
    }

    /// Checks output against all predictions so far. Runs before the next input
    /// batch and at the end of the script.
    fn sync(&mut self) {
        assert_eq!(
            self.outcome,
            Outcome::Absorbed,
            "server read on past a step it should have surfaced"
        );
        let frames = self.outbox.take_frames();
        let emits = std::mem::take(&mut self.emits);
        assert_eq!(frames.len(), emits.len(), "model expected {emits:?}");
        assert_eq!(
            self.outbox.has_tail(),
            self.tail.is_some(),
            "unterminated frame"
        );
        for (frame, emit) in frames.iter().zip(emits) {
            match emit {
                Emit::Dropped => {
                    assert!(
                        frame.is_empty(),
                        "expected an empty frame, server emitted {} bytes",
                        frame.len()
                    );
                    self.summary.dropped += 1;
                }
                Emit::Fragment => {
                    assert!(
                        !frame.is_empty(),
                        "expected a cut frame, server emitted an empty one"
                    );
                    self.summary.fragments += 1;
                }
                Emit::ArkHello(keys) => {
                    self.receive_hello(frame, *keys);
                    self.summary.handshakes += 1;
                }
                Emit::Reply(id, receiver) => {
                    let opened = sealing::open(&mut receiver.lock().unwrap(), &unframe(frame))
                        .expect("reply failed to open");
                    assert_eq!(opened, payload(id));
                    self.summary.replies += 1;
                }
            }
        }
    }

    /// Verifies ArkHello against the client keys and pinned server identity.
    /// Saves the response for HostAck only while the handshake is still active.
    fn receive_hello(&mut self, frame: &[u8], keys: Keys) {
        let auth = handshake::ArkHelloAuth {
            host_signer: keys.signer.public_key(),
            host_crypto: keys.crypto.public_key(),
        };
        let sign1 = cose::decrypt(&unframe(frame), &auth, &keys.crypto, CRYPTO_DOMAIN_WIRE)
            .expect("server hello failed to decrypt");
        let hello: handshake::ArkHello =
            cose::verify(&sign1, &auth, &self.identity, CRYPTO_DOMAIN_WIRE, None)
                .expect("server hello signature invalid");
        let encap: [u8; xhpke::ENCAP_KEY_SIZE] = hello
            .a2h_encap
            .try_into()
            .expect("server hello encap size invalid");
        let receiver = keys
            .crypto
            .new_receiver(&encap, CRYPTO_DOMAIN_WIRE_ARK_TO_HOST)
            .unwrap();
        if self.state == State::AwaitAck {
            self.pending = Some(Pending {
                keys,
                ark_crypto: hello.ark_crypto,
                receiver,
            });
        }
    }
}

/// Read adapter that advances the mock client's script as the server reads.
struct Feed(Arc<Mutex<Client>>);

impl Read for Feed {
    fn set_read_deadline(&mut self, _deadline: Option<Instant>) -> io::Result<()> {
        // Every read completes immediately according to the script.
        Ok(())
    }
}

impl io::Read for Feed {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut client = self.0.lock().unwrap();
        if client.bytes.is_empty() {
            // Verify the previous batch's output before advancing the script.
            client.sync();
            client.batch = 0;
            loop {
                match client.steps.pop_front() {
                    None => {
                        client.interrupt(Outcome::Terminated);
                        return Ok(0);
                    }
                    Some(Step::Yield) => {
                        client.interrupt(Outcome::Yield);
                        return Err(would_block());
                    }
                    Some(Step::Interrupt) => return Err(io::ErrorKind::Interrupted.into()),
                    Some(Step::ReadTimeout) => return Err(io::ErrorKind::TimedOut.into()),
                    Some(step) if step.is_action() => {
                        client.action = Some(step);
                        client.interrupt(Outcome::Yield);
                        return Err(would_block());
                    }
                    Some(step) => client.execute(step),
                }
                if !client.bytes.is_empty() {
                    break;
                }
            }
            // Batch later frames into this read. Stop when the driver must
            // handle a receive event or the next step needs a separate action.
            while client.batch > 1
                && client.outcome == Outcome::Absorbed
                && client.steps.front().is_some_and(Step::queues_frames)
            {
                let step = client.steps.pop_front().unwrap();
                client.execute(step);
                client.batch -= 1;
            }
        }
        let mut n = buf.len().min(client.bytes.len() - client.offset);
        if client.chunk > 0 {
            n = n.min(client.chunk);
        }
        buf[..n].copy_from_slice(&client.bytes[client.offset..client.offset + n]);
        client.offset += n;
        if client.offset == client.bytes.len() {
            client.bytes.clear();
            client.offset = 0;
        }
        client.summary.reads += 1;
        Ok(n)
    }
}

/// The server under test, reading the script and writing into the outbox.
type Server = crate::transport::Server<Feed, Outbox, Attestation>;

/// Checks that the current sender is usable exactly when the model expects a
/// session. An oversized send checks admission without sealing or writing bytes.
fn check_session(sender: Option<&Sender<Outbox>>, client: &Client) {
    let established = client.state == State::Established;
    let refused = super::send(sender, OVERSIZED_MESSAGE);
    match refused {
        Err(Error::PacketTooLarge(_)) => {
            assert!(established, "server has a session the model does not")
        }
        Err(Error::EncryptionFailed(_)) => {
            assert!(!established, "server lacks the session the model has")
        }
        other => panic!("unexpected oversized send result: {other:?}"),
    }
}

/// Sends a tagged message and checks its result against the model. A failed send
/// ends the sending session and attempts a wire signal unless it timed out. The
/// receive side reports the session's end when it next handles a frame or EOF.
fn send(sender: Option<&Sender<Outbox>>, client: &mut Client, id: u64) {
    // Predict whether the reply reaches the client and whether failure should
    // attempt a wire signal.
    let established = client.state == State::Established;
    let expected = established.then(|| {
        let receiver = client
            .receiver
            .clone()
            .expect("established without a session");
        let sent = client.send(Payload::Frame(Emit::Reply(id, receiver)));
        if !sent {
            client.forget();
            client.state = State::Idle;
            if !client.timed_out {
                client.send(Payload::Signal);
            }
        }
        sent
    });
    let sent = super::send(sender, &payload(id));
    match (expected, sent) {
        (Some(true), Ok(())) => {}
        (Some(false), Err(Error::SendFailed(_))) => {}
        (None, Err(Error::EncryptionFailed(_))) => {}
        (expected, sent) => panic!("model expected {expected:?}, server returned {sent:?}"),
    }
}

/// Runs a script against a real server and returns the observed counts. Panics
/// if server output or receive results differ from the model.
pub fn run(steps: &[Step]) -> Summary {
    #[cfg(feature = "fuzz")]
    super::seed::seed(super::seed::TRANSPORT_SERVER, steps);

    let signer = xdsa::SecretKey::generate();
    let attestation = self_attestation(&signer);
    let outbox = Outbox::default();
    let client = Arc::new(Mutex::new(Client::new(
        steps,
        signer.public_key(),
        outbox.clone(),
    )));
    let mut server = Server::new_at(
        crate::transport::Stream::new(Feed(client.clone()), outbox, || {}),
        signer,
        attestation,
        TIMESTAMP,
    )
    .set_handshake_timeout(SCRIPT_HANDSHAKE_TIMEOUT);

    let mut sender = None;
    let mut retained = None;
    let mut generation = 0u64;
    let mut retained_generation = None;
    loop {
        let action = client.lock().unwrap().next_action();
        if let Some(action) = action {
            let mut client = client.lock().unwrap();
            match action {
                Step::Retain => {
                    retained = sender.clone();
                    retained_generation =
                        (client.state == State::Established).then_some(generation);
                }
                Step::Send(tag) => send(sender.as_ref(), &mut client, tag as u64),
                Step::SendRetained(tag) => {
                    if client.state == State::Established && retained_generation == Some(generation)
                    {
                        send(retained.as_ref(), &mut client, tag as u64);
                    } else {
                        assert!(matches!(
                            super::send(retained.as_ref(), &payload(tag as u64)),
                            Err(Error::EncryptionFailed(_))
                        ));
                    }
                }
                Step::SendOversized => check_session(sender.as_ref(), &client),
                Step::Disconnect => {
                    client.forget();
                    // A reset already surfaced leaves the next handshake
                    // scheduled even if the owner disconnects before receiving.
                    if client.state != State::AwaitHello {
                        client.state = State::Idle;
                    }
                    client.held = false;
                    client.send(Payload::Signal);
                    server.disconnect();
                }
                _ => unreachable!("only owner actions reach the driver"),
            }
            check_session(sender.as_ref(), &client);
            client.sync();
            continue;
        }
        match server.recv() {
            // Reply to each tagged request predicted by the model. Untagged
            // bytes are delivered too, but need no reply.
            Ok(Event::Message(message)) => {
                let mut client = client.lock().unwrap();
                match client.outcome {
                    Outcome::Message(id) if message == payload(id) => {
                        client.surfaced(Outcome::Message(id));
                        client.summary.delivered += 1;
                        send(sender.as_ref(), &mut client, id);
                    }
                    _ if message == [0x07] => client.surfaced(Outcome::Garbage),
                    outcome => {
                        panic!("server delivered {message:?} where the model has {outcome:?}")
                    }
                }
            }
            // A reset or invalid frame ended the previous session.
            Ok(Event::Disconnected) => {
                let mut client = client.lock().unwrap();
                client.surfaced(Outcome::Ended);
                check_session(sender.as_ref(), &client);
            }
            // The new sender is usable immediately after the handshake.
            Ok(Event::Connected(opened)) => {
                sender = Some(opened);
                let mut client = client.lock().unwrap();
                client.surfaced(Outcome::Opened);
                generation += 1;
                check_session(sender.as_ref(), &client);
            }
            // Probe sending whenever the script yields control to the driver.
            Err(Error::RecvFailed(err)) if err.kind() == io::ErrorKind::WouldBlock => {
                let mut client = client.lock().unwrap();
                client.surfaced(Outcome::Yield);
                check_session(sender.as_ref(), &client);
                if client.action.is_none() {
                    send(sender.as_ref(), &mut client, PROBE_ID);
                }
            }
            Err(Error::Terminated) => {
                client.lock().unwrap().surfaced(Outcome::Terminated);
                break;
            }
            Err(Error::SendFailed(_)) => {
                client.lock().unwrap().surfaced(Outcome::SendFailed);
            }
            Err(err) => panic!("unexpected error from the server: {err}"),
        }
    }
    let mut client = client.lock().unwrap();
    client.sync();
    check_session(sender.as_ref(), &client);
    client.summary.state = client.state;
    client.summary
}

#[cfg(test)]
mod tests;
