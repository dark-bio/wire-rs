// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Mock client driving a real `Server`. A script is a sequence of steps,
//! each putting the bytes of some frames in front of the server or handing
//! control back to the driver. The driver calls `next_message` in a loop and
//! replies to whatever it delivers. The read half hands over the bytes of one
//! step at a time, moving the script forward once they are consumed.
//!
//! The model tracks the state the server should be in, the frames it should emit
//! and what `next_message` should surface for the last step. Whenever the server
//! asks for more input, the frames it wrote are checked against the emissions
//! expected. Any divergence panics.

use super::{
    CutPoint, MAX_STEPS, Outbox, TIMESTAMP, frame, self_attestation, unframe, would_block,
};
use crate::handshake;
use crate::protocol::{ArkToHost, HostToArk, ark_to_host};
use crate::session::Session;
use crate::{
    Attestation, CRYPTO_DOMAIN_WIRE, CRYPTO_DOMAIN_WIRE_ARK_TO_HOST,
    CRYPTO_DOMAIN_WIRE_HOST_TO_ARK, Error, MAX_FRAME_SIZE, MAX_MESSAGE_SIZE,
};
use darkbio_crypto::{cbor, cose, xdsa, xhpke};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::fmt;
use std::io::{self, Read};
use std::rc::Rc;

/// Message id of the probes the driver sends on the server's behalf.
const PROBE_ID: u64 = u64::MAX;

/// One step of the mock client, each putting zero or more frames in front
/// of the server or handing control back to the driver. Frames needing a session
/// or an ArkHello the client does not have degrade into junk the server refuses,
/// so any sequence of steps is a valid script.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum Step {
    /// A lone zero, one empty frame.
    Reset,
    /// Two zeros, the reset as `Client::handshake` sends it.
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
    /// A HostAck for the ArkHello last received bound to another server key than
    /// the one that answered. Junk if there is none.
    AckBadAuth,
    /// A HostAck for the ArkHello last received signed by a key other than
    /// the hello's. Junk if there is none.
    AckBadSigner,
    /// A HostAck for the ArkHello last received whose sealed payload is not
    /// an ack at all. Junk if there is none.
    AckBadPayload,
    /// A HostAck for the ArkHello last received with an encapsulated key of
    /// the wrong size. Junk if there is none.
    AckBadEncap,
    /// A sealed request tagged by the byte. Junk without a session.
    Request(u8),
    /// The last sealed request sent, repeated. Nothing if none was sent yet.
    RequestReplay,
    /// A sealed request with a flipped ciphertext byte. Junk without a
    /// session.
    RequestTampered,
    /// A sealed packet that is not a protobuf message. Junk without a session.
    Garbage,
    /// The bytes as a frame, zeros mapped away and at least one byte long.
    /// Never a valid hello, the public keys one carries not surviving
    /// validation when made of arbitrary bytes.
    Junk(Vec<u8>),
    /// The last valid frame sent cut short, keeping at least one byte. Nothing
    /// if no valid frame was sent yet.
    Truncated(u8),
    /// A valid HostHello without its delimiter. The next frame's bytes merge
    /// into it, a lone delimiter completing it into the valid hello it is.
    Partial,
    /// A frame past the size limit, delimiter included. The framing throws it
    /// away before the server sees it, a partial hello in front going with it.
    Oversized,
    /// The read fails with `WouldBlock`, handing control back to the driver.
    Yield,
    /// The read fails with `Interrupted`, which the framing retries with the
    /// Server none the wiser.
    Interrupt,
    /// The server's writes fail from here on, as on a transport that died.
    Break,
    /// The server's writes work again.
    Heal,
    /// The server's next write the point applies to is cut there, the transport
    /// staying broken afterwards if told to, until healed.
    Cut { point: CutPoint, then_broken: bool },
    /// Caps what a single read hands the server at the byte count, so frames
    /// arrive in pieces. Zero lifts the cap.
    Chunk(u8),
    /// Puts the frames of the next steps in front of the server in one read, up
    /// to the count. A step the server surfaces something for ends the batch
    /// early, the driver acting on it before the server reads on, as does any
    /// step not queuing frames.
    Batch(u8),
}

impl Step {
    /// Whether the step only puts frames in front of the server, as opposed to
    /// handing control back or changing the transport.
    fn queues_frames(&self) -> bool {
        !matches!(
            self,
            Step::Yield
                | Step::Interrupt
                | Step::Break
                | Step::Heal
                | Step::Cut { .. }
                | Step::Chunk(_)
                | Step::Batch(_)
        )
    }
}

/// State the model expects the server to be in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum State {
    /// No session and no handshake in progress.
    #[default]
    Idle,
    /// A reset arrived, a HostHello is awaited.
    AwaitHello,
    /// The ArkHello went out, a HostAck is awaited.
    AwaitAck,
    /// A session is live in both directions.
    Established,
}

/// Counts of what a run observed, for scenario tests to assert on.
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

/// A frame put in front of the server, as the model sees it.
enum Frame {
    /// The empty frame, a reset.
    Empty,
    /// A valid HostHello announcing the keys.
    Hello(Box<Keys>),
    /// A valid HostAck for the ArkHello last received.
    Ack,
    /// A request with the id, sealed in the session.
    Request(u64),
    /// A packet sealed in the session that is not a message.
    Garbage,
    /// Anything else, refused in every state.
    Junk,
}

/// Bytes of an unterminated frame in front of the server, waiting for the
/// delimiter that completes them into a frame.
enum Partial {
    /// The stream is at a frame boundary.
    None,
    /// A hello lacking only its delimiter, valid if the next byte is one.
    Hello(Box<Keys>),
    /// Bytes no delimiter can complete into anything valid.
    Junk,
}

/// Frame the model expects the server to emit, along with what verifies it.
enum Emit {
    /// The empty frame, the signal that the server has no session or a resync
    /// delimiter with nothing to terminate.
    Dropped,
    /// The prefix of a frame cut short, meaning nothing to the client.
    Fragment,
    /// The handshake reply, sealed to the hello with the keys.
    ArkHello(Box<Keys>),
    /// A sealed ArkToHost with the id, opening in the session.
    Reply(u64, Rc<RefCell<Session>>),
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

/// A frame the server left unterminated, a send having failed under it. The
/// delimiter of the next send completes it.
enum Tail {
    /// A prefix of the body, decoding to nothing the client accepts.
    Fragment,
    /// The whole body, completing into the frame it was meant to be.
    Body(Emit),
}

/// What a send of the server carries.
enum Payload {
    /// A frame, the emission it is expected as.
    Frame(Emit),
    /// The signal that the server has no session, a lone delimiter.
    Signal,
}

/// What the model expects `next_message` to surface for the last step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    /// The server keeps reading.
    Absorbed,
    /// A HostToArk with the id is delivered.
    Message(u64),
    /// `Error::PacketDecodingFailed`, the session staying intact.
    Undecodable,
    /// `Error::RecvFailed` carrying `WouldBlock`.
    Yield,
    /// `Error::Terminated`, the script having run out.
    Terminated,
}

/// Ephemeral keys of a HostHello.
#[derive(Clone)]
struct Keys {
    signer: xdsa::SecretKey,
    crypto: xhpke::SecretKey,
}

impl Keys {
    fn generate() -> Self {
        Self {
            signer: xdsa::SecretKey::generate(),
            crypto: xhpke::SecretKey::generate(),
        }
    }

    /// The HostHello announcing the keys.
    fn hello(&self) -> Vec<u8> {
        cbor::encode(&handshake::HostHello {
            host_signer: self.signer.public_key(),
            host_crypto: self.crypto.public_key(),
        })
        .unwrap()
    }
}

/// What is wrong with a HostAck crafted to be refused, in the order the server
/// finds them.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AckFlaw {
    /// A ciphertext byte flipped, the seal failing to open.
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

/// An ArkHello received, everything needed to ack it. Only kept while the server
/// awaits that ack.
struct Pending {
    keys: Keys,
    ark_crypto: xhpke::PublicKey,
    receiver: xhpke::Receiver,
}

impl Pending {
    /// The HostAck completing the handshake, along with the session it opens
    /// on the client's side.
    fn ack(self, identity: &xdsa::PublicKey) -> (Vec<u8>, Session) {
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
        let session = Session {
            sender,
            receiver: self.receiver,
        };
        (ack, session)
    }

    /// A HostAck flawed as requested, so the server refuses it for that one
    /// reason.
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
    identity: xdsa::PublicKey, // The server's identity, verifying its hellos
    outbox: Outbox,            // Frames the server wrote
    bytes: Vec<u8>,            // Bytes of executed steps not yet read by the server
    chunk: usize,              // Most bytes a read hands over, zero for all
    batch: usize,              // Steps left to put in front of the server in one read
    broken: bool,              // Whether the server's writes fail
    cut: Option<CutPoint>,     // Cut armed for the next write of the server it applies to
    flush_fails: bool,         // Whether the flush of the send in progress fails

    state: State,       // State the server should be in
    partial: Partial,   // Unterminated frame in front of the server
    resync: bool,       // Whether the server's last send failed, the next starting with a delimiter
    tail: Option<Tail>, // Unterminated frame the server left behind
    emits: Vec<Emit>,   // Frames the server should have emitted since the last sync
    outcome: Outcome,   // What next_message should surface for the last step

    pending: Option<Pending>, // ArkHello received, awaiting the client's ack
    session: Option<Rc<RefCell<Session>>>, // Live session of the client, shared with its replies

    last_hello: Option<(Vec<u8>, Keys)>, // Last HostHello sent, framed
    last_ack: Option<Vec<u8>>,           // Last HostAck sent, framed
    last_request: Option<Vec<u8>>,       // Last request sent, framed
    last_valid: Option<Vec<u8>>,         // Last valid frame sent, delimiter stripped

    summary: Summary,
}

impl Client {
    fn new(steps: &[Step], identity: xdsa::PublicKey, outbox: Outbox) -> Self {
        Self {
            steps: steps.iter().take(MAX_STEPS).cloned().collect(),
            identity,
            outbox,
            bytes: Vec::new(),
            chunk: 0,
            batch: 0,
            broken: false,
            cut: None,
            flush_fails: false,
            state: State::Idle,
            partial: Partial::None,
            resync: false,
            tail: None,
            emits: Vec::new(),
            outcome: Outcome::Absorbed,
            pending: None,
            session: None,
            last_hello: None,
            last_ack: None,
            last_request: None,
            last_valid: None,
            summary: Summary::default(),
        }
    }

    /// Executes one step, queuing its bytes for the server and applying the
    /// model's transitions for the frames they make up.
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
                    let (ack, session) = pending.ack(&self.identity);
                    let framed = frame(&ack);
                    self.record(&framed);
                    self.last_ack = Some(framed.clone());
                    self.session = Some(Rc::new(RefCell::new(session)));
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
            Step::Request(tag) => match self.session.as_ref() {
                Some(session) => {
                    let id = tag as u64;
                    let request = HostToArk {
                        id: Some(id),
                        content: None,
                    };
                    let packet = session
                        .borrow_mut()
                        .seal(&request, &mut Vec::new())
                        .unwrap();
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
            Step::RequestTampered => match self.session.as_ref() {
                Some(session) => {
                    let request = HostToArk {
                        id: Some(0),
                        content: None,
                    };
                    let mut packet = session
                        .borrow_mut()
                        .seal(&request, &mut Vec::new())
                        .unwrap();
                    *packet.last_mut().unwrap() ^= 0xff;
                    self.junk(&packet);
                }
                None => self.junk(b"tampered request without a session"),
            },
            Step::Garbage => match self.session.as_ref() {
                Some(session) => {
                    let packet = session.borrow_mut().sender.seal(&[0x07], &[]).unwrap();
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
                self.bytes.resize(self.bytes.len() + MAX_FRAME_SIZE + 1, 1);
                self.bytes.push(0x00);
            }
            Step::Yield | Step::Interrupt => {
                unreachable!("yields and interrupts are handled by the reader")
            }
            Step::Break => self.set_broken(true),
            Step::Heal => self.set_broken(false),
            Step::Cut { point, then_broken } => {
                self.cut = Some(point);
                self.outbox.set_cut(point);
                if then_broken {
                    self.set_broken(true);
                }
            }
            Step::Chunk(n) => self.chunk = n as usize,
            Step::Batch(n) => self.batch = n as usize,
        }
    }

    /// Queues a flawed HostAck for the ArkHello last received. The server refuses
    /// it either way, so it is junk to the model.
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

    /// Applies the model's transition for a frame arriving at the server. An
    /// unterminated frame in front swallows it, a lone delimiter completing a
    /// partial hello into a valid one and anything else into junk.
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
            // A reset restarts the handshake in every state, the client having
            // asked for it, so nothing is signaled
            (_, Frame::Empty) => {
                self.forget();
                self.state = State::AwaitHello;
            }
            // The ArkHello failing to get out has the server give up on the
            // handshake and signal so
            (State::AwaitHello, Frame::Hello(keys)) => {
                if self.send(Payload::Frame(Emit::ArkHello(keys))) {
                    self.state = State::AwaitAck;
                } else {
                    self.forget();
                    self.state = State::Idle;
                    self.send(Payload::Signal);
                }
            }
            (State::AwaitAck, Frame::Ack) => {
                self.state = State::Established;
            }
            (State::Established, Frame::Request(id)) => {
                self.outcome = Outcome::Message(id);
            }
            // Garbage surfaces as an error but leaves the session intact
            (State::Established, Frame::Garbage) => {
                self.outcome = Outcome::Undecodable;
            }
            // Anything else drops whatever the server had, the client told so
            _ => {
                self.forget();
                self.state = State::Idle;
                self.send(Payload::Signal);
            }
        }
    }

    /// Applies the model's transition for a send of the server, returning whether
    /// it goes through. It mirrors the framing, a send after a failed one
    /// starting with a delimiter that terminates the tail the failure left
    /// behind, and its flush failing the send after every byte went out.
    fn send(&mut self, payload: Payload) -> bool {
        let mut sent = !self.resync || self.write_zero();
        if sent {
            sent = match payload {
                Payload::Frame(emit) => self.write_frame(emit),
                Payload::Signal => self.write_zero(),
            };
        }
        if sent {
            sent = !std::mem::take(&mut self.flush_fails);
        }
        self.resync = !sent;
        sent
    }

    /// A lone delimiter written, the resync ahead of a send or the signal,
    /// returning whether it got out. Only a cut at the start applies to it,
    /// the other points waiting for a write with a body.
    fn write_zero(&mut self) -> bool {
        if self.cut == Some(CutPoint::Start) {
            self.cut = None;
            return false;
        }
        if self.broken {
            return false;
        }
        self.zero_out();
        true
    }

    /// A frame written, returning whether it got out whole. An armed cut
    /// fires on it, ahead of a broken transport.
    fn write_frame(&mut self, emit: Emit) -> bool {
        match self.cut.take() {
            Some(CutPoint::Start) => false,
            Some(CutPoint::Middle(_)) => {
                self.tail = Some(Tail::Fragment);
                false
            }
            Some(CutPoint::Delimiter) => {
                self.tail = Some(Tail::Body(emit));
                false
            }
            Some(CutPoint::Flush) => {
                self.flush_fails = true;
                self.emits.push(emit);
                true
            }
            None if self.broken => false,
            None => {
                self.emits.push(emit);
                true
            }
        }
    }

    /// A lone delimiter reaching the stream, terminating the tail into the
    /// frame it was cut from or forming an empty frame without one.
    fn zero_out(&mut self) {
        self.emits.push(match self.tail.take() {
            None => Emit::Dropped,
            Some(Tail::Fragment) => Emit::Fragment,
            Some(Tail::Body(emit)) => emit,
        });
    }

    /// Forgets any session or handshake in progress. A session stays with the
    /// replies still to be checked against it.
    fn forget(&mut self) {
        self.session = None;
        self.pending = None;
    }

    /// Applies a read failing, which aborts a handshake in progress but leaves
    /// a session untouched.
    fn interrupt(&mut self, outcome: Outcome) {
        if matches!(self.state, State::AwaitHello | State::AwaitAck) {
            self.forget();
            self.state = State::Idle;
        }
        self.outcome = outcome;
    }

    /// Checks that `next_message` surfaced what the model expected and arms
    /// the model for the next step.
    fn surfaced(&mut self, outcome: Outcome) {
        assert_eq!(self.outcome, outcome, "model vs server");
        self.outcome = Outcome::Absorbed;
    }

    /// Checks the server's reactions to everything delivered so far, run whenever
    /// the server asks for more input and once the run ends.
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
                Emit::Reply(id, session) => {
                    let msg: ArkToHost = session
                        .borrow_mut()
                        .open(&unframe(frame))
                        .expect("reply failed to open");
                    assert_eq!(msg.id, Some(id));
                    self.summary.replies += 1;
                }
            }
        }
    }

    /// Opens and verifies an ArkHello sealed to the keys, keeping what is
    /// needed to ack it as long as the server is still awaiting that ack.
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

/// Read half handed to the server, pulling the script forward as the server reads.
struct Feed(Rc<RefCell<Client>>);

impl Read for Feed {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut client = self.0.borrow_mut();
        if client.bytes.is_empty() {
            // Everything handed over was consumed, check the reactions to it
            // before moving the script forward
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
                    Some(step) => client.execute(step),
                }
                if !client.bytes.is_empty() {
                    break;
                }
            }
            // A batch queues the frames of the steps after too, so they arrive
            // in one read. It ends at a step the server surfaces something for,
            // the driver acting on that before the server reads on, and at any
            // step not queuing frames
            while client.batch > 1
                && client.outcome == Outcome::Absorbed
                && client.steps.front().is_some_and(Step::queues_frames)
            {
                let step = client.steps.pop_front().unwrap();
                client.execute(step);
                client.batch -= 1;
            }
        }
        let mut n = buf.len().min(client.bytes.len());
        if client.chunk > 0 {
            n = n.min(client.chunk);
        }
        buf[..n].copy_from_slice(&client.bytes[..n]);
        client.bytes.drain(..n);
        client.summary.reads += 1;
        Ok(n)
    }
}

/// The server under test, reading the script and writing into the outbox.
type Server = crate::Server<Feed, Outbox, Attestation>;

/// Checks that the server has a session exactly when the model says so. An
/// oversized message is refused before sealing, so it probes the session
/// without any frame going out.
fn check_session(server: &mut Server, client: &Client) {
    let established = client.state == State::Established;
    let oversized = vec![0x42; MAX_MESSAGE_SIZE + 1];
    let refused = server.send_message(ArkToHost {
        id: Some(PROBE_ID),
        err: None,
        content: Some(ark_to_host::Content::Develop(oversized)),
    });
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

/// Sends a message on the server's behalf, checking that the send path works
/// exactly in a session and fails exactly when the transport does. A failed
/// send takes the session down with it, the server signaling so.
fn send(server: &mut Server, client: &mut Client, id: u64) {
    // Predict the send, a reply going out in a session unless the transport
    // fails it, in which case the server drops the session and signals
    let established = client.state == State::Established;
    let expected = established.then(|| {
        let session = client
            .session
            .clone()
            .expect("established without a session");
        let sent = client.send(Payload::Frame(Emit::Reply(id, session)));
        if !sent {
            client.forget();
            client.state = State::Idle;
            client.send(Payload::Signal);
        }
        sent
    });
    let sent = server.send_message(ArkToHost {
        id: Some(id),
        err: None,
        content: None,
    });
    match (expected, sent) {
        (Some(true), Ok(())) => {}
        (Some(false), Err(Error::SendFailed(_))) => {}
        (None, Err(Error::EncryptionFailed(_))) => {}
        (expected, sent) => panic!("model expected {expected:?}, server returned {sent:?}"),
    }
}

/// Runs a script against a real server, panicking on any divergence from the
/// model, and reports what the run observed.
pub fn run(steps: &[Step]) -> Summary {
    #[cfg(feature = "fuzz")]
    super::seed::seed(super::seed::SERVER_PROTOCOL, steps);

    let signer = xdsa::SecretKey::generate();
    let attestation = self_attestation(&signer);
    let outbox = Outbox::default();
    let client = Rc::new(RefCell::new(Client::new(
        steps,
        signer.public_key(),
        outbox.clone(),
    )));
    let mut server = Server::new_at(Feed(client.clone()), outbox, signer, attestation, TIMESTAMP);

    loop {
        match server.next_message() {
            // Reply to every request delivered, as a server would
            Ok(msg) => {
                let id = msg.id.expect("delivered message without an id");
                let mut client = client.borrow_mut();
                client.surfaced(Outcome::Message(id));
                client.summary.delivered += 1;
                send(&mut server, &mut client, id);
            }
            Err(Error::PacketDecodingFailed(_)) => {
                client.borrow_mut().surfaced(Outcome::Undecodable);
            }
            // Probe the send path whenever the script hands control back
            Err(Error::RecvFailed(err)) if err.kind() == io::ErrorKind::WouldBlock => {
                let mut client = client.borrow_mut();
                client.surfaced(Outcome::Yield);
                check_session(&mut server, &client);
                send(&mut server, &mut client, PROBE_ID);
            }
            Err(Error::Terminated) => {
                client.borrow_mut().surfaced(Outcome::Terminated);
                break;
            }
            Err(err) => panic!("unexpected error from the server: {err}"),
        }
    }
    let mut client = client.borrow_mut();
    client.sync();
    check_session(&mut server, &client);
    client.summary.state = client.state;
    client.summary
}

#[cfg(test)]
mod tests;
