// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Scripted host driving a real `ArkSide`. A script is a sequence of steps,
//! each putting the bytes of some frames in front of the Ark or handing
//! control back to the driver. The driver calls `next_message` in a loop and
//! replies to whatever it delivers. The read half hands over the bytes of one
//! step at a time, moving the script forward once they are consumed.
//!
//! The model tracks the state the Ark should be in, the frames it should emit
//! and what `next_message` should surface for the last step. Whenever the Ark
//! asks for more input, the frames it wrote are checked against the emissions
//! expected. Any divergence panics.

use super::{MAX_STEPS, Outbox, frame, self_attestation, unframe, would_block};
use crate::handshake;
use crate::protocol::{ArkToHost, HostToArk, ark_to_host};
use crate::session::Session;
use crate::{
    ArkSide, Attestation, CRYPTO_DOMAIN_WIRE, CRYPTO_DOMAIN_WIRE_ARK_TO_HOST,
    CRYPTO_DOMAIN_WIRE_HOST_TO_ARK, Error, MAX_MESSAGE_SIZE,
};
use darkbio_crypto::{cbor, cose, xdsa, xhpke};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{self, Read};
use std::rc::Rc;

/// Message id of the probes the driver sends on the Ark's behalf.
const PROBE_ID: u64 = u64::MAX;

/// One step of the scripted host, each putting zero or more frames in front
/// of the Ark or handing control back to the driver. Frames needing a session
/// or an ArkHello the host does not have degrade into junk the Ark refuses,
/// so any sequence of steps is a valid script.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum Step {
    /// A lone zero, one empty frame.
    Reset,
    /// Two zeros, the reset as `HostSide::handshake` sends it.
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
    /// A HostAck for the ArkHello last received bound to another Ark key than
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
    /// The read fails with `WouldBlock`, handing control back to the driver.
    Yield,
    /// The Ark's writes fail from here on, as on a transport that died.
    Break,
    /// The Ark's writes work again.
    Heal,
    /// Caps what a single read hands the Ark at the byte count, so frames
    /// arrive in pieces. Zero lifts the cap.
    Chunk(u8),
}

/// State the model expects the Ark to be in.
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
    pub state: State,      // State the Ark ended up in
    pub dropped: usize,    // Empty frames the Ark emitted
    pub handshakes: usize, // ArkHellos the Ark emitted
    pub delivered: usize,  // Requests the Ark delivered
    pub replies: usize,    // Replies and probes the Ark sealed
}

/// A frame put in front of the Ark, as the model sees it.
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

/// Bytes of an unterminated frame in front of the Ark, waiting for the
/// delimiter that completes them into a frame.
enum Partial {
    /// The stream is at a frame boundary.
    None,
    /// A hello lacking only its delimiter, valid if the next byte is one.
    Hello(Box<Keys>),
    /// Bytes no delimiter can complete into anything valid.
    Junk,
}

/// Frame the model expects the Ark to emit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Emit {
    /// The empty frame signaling that the Ark has no session.
    Dropped,
    /// The handshake reply, sealed to the hello being answered.
    ArkHello,
    /// A sealed ArkToHost with the id, sent by the driver on the Ark's behalf.
    Reply(u64),
}

/// What the model expects `next_message` to surface for the last step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    /// The Ark keeps reading.
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

/// What is wrong with a HostAck crafted to be refused, in the order the Ark
/// finds them.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AckFlaw {
    Tampered,
    Auth,
    Signer,
    Payload,
    Encap,
}

/// An ArkHello received, everything needed to ack it. Only kept while the Ark
/// awaits that ack.
struct Pending {
    keys: Keys,
    ark_crypto: xhpke::PublicKey,
    receiver: xhpke::Receiver,
}

impl Pending {
    /// The HostAck completing the handshake, along with the session it opens
    /// on the host's side.
    fn ack(self, identity: &xdsa::PublicKey) -> (Vec<u8>, Session) {
        let (sender, encap) = self
            .ark_crypto
            .new_sender(CRYPTO_DOMAIN_WIRE_HOST_TO_ARK)
            .unwrap();
        let ack = cose::seal(
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
        )
        .unwrap();
        let session = Session {
            sender,
            receiver: self.receiver,
        };
        (ack, session)
    }

    /// A HostAck flawed as requested, so the Ark refuses it for that one
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
            AckFlaw::Payload => cose::seal(
                &(vec![1u8], vec![2u8]),
                &auth,
                signer,
                &self.ark_crypto,
                CRYPTO_DOMAIN_WIRE,
            ),
            _ => cose::seal(
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
            ),
        }
        .unwrap();
        if flaw == AckFlaw::Tampered {
            *sealed.last_mut().unwrap() ^= 0xff;
        }
        sealed
    }
}

/// Scripted host along with the model of the Ark it drives.
pub struct Host {
    steps: VecDeque<Step>,
    identity: xdsa::PublicKey, // The Ark's identity, verifying its hellos
    outbox: Outbox,            // Frames the Ark wrote
    bytes: Vec<u8>,            // Bytes of executed steps not yet read by the Ark
    chunk: usize,              // Most bytes a read hands over, zero for all
    broken: bool,              // Whether the Ark's writes fail

    state: State,     // State the Ark should be in
    partial: Partial, // Unterminated frame in front of the Ark
    emits: Vec<Emit>, // Frames the Ark should have emitted since the last sync
    outcome: Outcome, // What next_message should surface for the last step

    awaiting: Option<Keys>,   // Keys of the hello an ArkHello is expected for
    pending: Option<Pending>, // ArkHello received, awaiting the host's ack
    session: Option<Session>, // Live session on the host's side

    last_hello: Option<(Vec<u8>, Keys)>, // Last HostHello sent, framed
    last_ack: Option<Vec<u8>>,           // Last HostAck sent, framed
    last_request: Option<Vec<u8>>,       // Last request sent, framed
    last_valid: Option<Vec<u8>>,         // Last valid frame sent, delimiter stripped

    summary: Summary,
}

impl Host {
    fn new(steps: &[Step], identity: xdsa::PublicKey, outbox: Outbox) -> Self {
        Self {
            steps: steps.iter().take(MAX_STEPS).cloned().collect(),
            identity,
            outbox,
            bytes: Vec::new(),
            chunk: 0,
            broken: false,
            state: State::Idle,
            partial: Partial::None,
            emits: Vec::new(),
            outcome: Outcome::Absorbed,
            awaiting: None,
            pending: None,
            session: None,
            last_hello: None,
            last_ack: None,
            last_request: None,
            last_valid: None,
            summary: Summary::default(),
        }
    }

    /// Executes one step, queuing its bytes for the Ark and applying the
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
                    self.session = Some(session);
                    self.deliver(Frame::Ack);
                    self.bytes.extend(framed);
                }
                None => self.junk(b"ack without a pending ark hello"),
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
            Step::Request(tag) => match self.session.as_mut() {
                Some(session) => {
                    let id = tag as u64;
                    let request = HostToArk {
                        id: Some(id),
                        content: None,
                    };
                    let packet = session.seal(&request, &mut Vec::new()).unwrap();
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
            Step::RequestTampered => match self.session.as_mut() {
                Some(session) => {
                    let request = HostToArk {
                        id: Some(0),
                        content: None,
                    };
                    let mut packet = session.seal(&request, &mut Vec::new()).unwrap();
                    *packet.last_mut().unwrap() ^= 0xff;
                    self.junk(&packet);
                }
                None => self.junk(b"tampered request without a session"),
            },
            Step::Garbage => match self.session.as_mut() {
                Some(session) => {
                    let packet = session.sender.seal(&[0x07], &[]).unwrap();
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
            Step::Yield => unreachable!("yields are handled by the reader"),
            Step::Break => self.set_broken(true),
            Step::Heal => self.set_broken(false),
            Step::Chunk(n) => self.chunk = n as usize,
        }
    }

    /// Queues a flawed HostAck for the ArkHello last received. The Ark refuses
    /// it either way, so it is junk to the model.
    fn bad_ack(&mut self, flaw: AckFlaw) {
        match self.pending.as_ref() {
            Some(pending) => {
                let ack = pending.bad_ack(&self.identity, flaw);
                self.junk(&ack);
            }
            None => self.junk(b"bad ack without a pending ark hello"),
        }
    }

    /// Queues a valid COBS frame of content the Ark refuses.
    fn junk(&mut self, text: &[u8]) {
        self.deliver(Frame::Junk);
        self.bytes.extend(frame(text));
    }

    /// Remembers the frame as the last valid one, for truncating later.
    fn record(&mut self, framed: &[u8]) {
        self.last_valid = Some(framed[..framed.len() - 1].to_vec());
    }

    /// Makes the Ark's writes fail, or work again.
    fn set_broken(&mut self, broken: bool) {
        self.outbox.set_broken(broken);
        self.broken = broken;
    }

    /// Applies the model's transition for a frame arriving at the Ark. An
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
            // A reset restarts the handshake in every state, the host having
            // asked for it, so nothing is signaled
            (_, Frame::Empty) => {
                self.forget();
                self.state = State::AwaitHello;
            }
            // The ArkHello never gets out on a broken transport, the Ark
            // giving up on the handshake
            (State::AwaitHello, Frame::Hello(_)) if self.broken => {
                self.forget();
                self.state = State::Idle;
            }
            (State::AwaitHello, Frame::Hello(keys)) => {
                self.awaiting = Some(*keys);
                self.state = State::AwaitAck;
                self.emit(Emit::ArkHello);
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
            // Anything else drops whatever the Ark had, the host told so
            _ => {
                self.forget();
                self.state = State::Idle;
                self.emit(Emit::Dropped);
            }
        }
    }

    /// Expects the Ark to emit a frame, unless its transport is broken and
    /// the frame is lost.
    fn emit(&mut self, emit: Emit) {
        if !self.broken {
            self.emits.push(emit);
        }
    }

    /// Forgets any session or handshake in progress. The keys of a hello the
    /// Ark already answered stay until its ArkHello is checked, the Ark having
    /// emitted it before the handshake was abandoned.
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
        assert_eq!(self.outcome, outcome, "model vs ark");
        self.outcome = Outcome::Absorbed;
    }

    /// Checks the Ark's reactions to everything delivered so far, run whenever
    /// the Ark asks for more input and once the run ends.
    fn sync(&mut self) {
        assert_eq!(
            self.outcome,
            Outcome::Absorbed,
            "ark read on past a step it should have surfaced"
        );
        let frames = self.outbox.take_frames();
        let emits = std::mem::take(&mut self.emits);
        assert_eq!(frames.len(), emits.len(), "model expected {emits:?}");
        for (frame, emit) in frames.iter().zip(emits) {
            match emit {
                Emit::Dropped => {
                    assert!(
                        frame.is_empty(),
                        "expected an empty frame, ark emitted {} bytes",
                        frame.len()
                    );
                    self.summary.dropped += 1;
                }
                Emit::ArkHello => {
                    self.receive_hello(frame);
                    self.summary.handshakes += 1;
                }
                Emit::Reply(id) => {
                    let msg: ArkToHost = self
                        .session
                        .as_mut()
                        .expect("reply without a session")
                        .open(&unframe(frame))
                        .expect("reply failed to open");
                    assert_eq!(msg.id, Some(id));
                    self.summary.replies += 1;
                }
            }
        }
    }

    /// Opens and verifies an ArkHello, keeping what is needed to ack it as long
    /// as the Ark is still awaiting that ack.
    fn receive_hello(&mut self, frame: &[u8]) {
        let keys = self
            .awaiting
            .take()
            .expect("ark hello without a hello awaiting it");
        let auth = handshake::ArkHelloAuth {
            host_signer: keys.signer.public_key(),
            host_crypto: keys.crypto.public_key(),
        };
        let sign1 = cose::decrypt(&unframe(frame), &auth, &keys.crypto, CRYPTO_DOMAIN_WIRE)
            .expect("ark hello failed to decrypt");
        let hello: handshake::ArkHello =
            cose::verify(&sign1, &auth, &self.identity, CRYPTO_DOMAIN_WIRE, None)
                .expect("ark hello signature invalid");
        let encap: [u8; xhpke::ENCAP_KEY_SIZE] = hello
            .a2h_encap
            .try_into()
            .expect("ark hello encap size invalid");
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

/// Read half handed to the Ark, pulling the script forward as the Ark reads.
struct Feed(Rc<RefCell<Host>>);

impl Read for Feed {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut host = self.0.borrow_mut();
        if host.bytes.is_empty() {
            // Everything handed over was consumed, check the reactions to it
            // before moving the script forward
            host.sync();
            loop {
                match host.steps.pop_front() {
                    None => {
                        host.interrupt(Outcome::Terminated);
                        return Ok(0);
                    }
                    Some(Step::Yield) => {
                        host.interrupt(Outcome::Yield);
                        return Err(would_block());
                    }
                    Some(step) => host.execute(step),
                }
                if !host.bytes.is_empty() {
                    break;
                }
            }
        }
        let mut n = buf.len().min(host.bytes.len());
        if host.chunk > 0 {
            n = n.min(host.chunk);
        }
        buf[..n].copy_from_slice(&host.bytes[..n]);
        host.bytes.drain(..n);
        Ok(n)
    }
}

/// The Ark under test, reading the script and writing into the outbox.
type Ark = ArkSide<Feed, Outbox, Attestation>;

/// Checks that the Ark has a session exactly when the model says so. An
/// oversized message is refused before sealing, so it probes the session
/// without any frame going out.
fn check_session(ark: &mut Ark, host: &Host) {
    let established = host.state == State::Established;
    let oversized = vec![0x42; MAX_MESSAGE_SIZE + 1];
    let refused = ark.send_message(ArkToHost {
        id: Some(PROBE_ID),
        err: None,
        content: Some(ark_to_host::Content::Develop(oversized)),
    });
    match refused {
        Err(Error::PacketTooLarge(_)) => {
            assert!(established, "ark has a session the model does not")
        }
        Err(Error::EncryptionFailed(_)) => {
            assert!(!established, "ark lacks the session the model has")
        }
        other => panic!("unexpected oversized send result: {other:?}"),
    }
}

/// Sends a message on the Ark's behalf, checking that the send path works
/// exactly in a session on a working transport. A failed send takes the
/// session down with it.
fn send(ark: &mut Ark, host: &mut Host, id: u64) {
    let established = host.state == State::Established;
    let sent = ark.send_message(ArkToHost {
        id: Some(id),
        err: None,
        content: None,
    });
    match sent {
        Ok(()) => {
            assert!(established, "ark sent a message without a session");
            assert!(!host.broken, "ark sent on a broken transport");
            host.emits.push(Emit::Reply(id));
        }
        Err(Error::SendFailed(_)) => {
            assert!(
                established && host.broken,
                "ark failed a send it should not have"
            );
            host.forget();
            host.state = State::Idle;
        }
        Err(Error::EncryptionFailed(_)) => {
            assert!(!established, "ark refused to send in a session");
        }
        Err(err) => panic!("unexpected send error: {err}"),
    }
}

/// Runs a script against a real Ark, panicking on any divergence from the
/// model, and reports what the run observed.
pub fn run(steps: &[Step]) -> Summary {
    let signer = xdsa::SecretKey::generate();
    let attestation = self_attestation(&signer);
    let outbox = Outbox::default();
    let host = Rc::new(RefCell::new(Host::new(
        steps,
        signer.public_key(),
        outbox.clone(),
    )));
    let mut ark = Ark::new(Feed(host.clone()), outbox, signer, attestation);

    loop {
        match ark.next_message() {
            // Reply to every request delivered, as an Ark would
            Ok(msg) => {
                let id = msg.id.expect("delivered message without an id");
                let mut host = host.borrow_mut();
                host.surfaced(Outcome::Message(id));
                host.summary.delivered += 1;
                send(&mut ark, &mut host, id);
            }
            Err(Error::PacketDecodingFailed(_)) => {
                host.borrow_mut().surfaced(Outcome::Undecodable);
            }
            // Probe the send path whenever the script hands control back
            Err(Error::RecvFailed(err)) if err.kind() == io::ErrorKind::WouldBlock => {
                let mut host = host.borrow_mut();
                host.surfaced(Outcome::Yield);
                check_session(&mut ark, &host);
                send(&mut ark, &mut host, PROBE_ID);
            }
            Err(Error::Terminated) => {
                host.borrow_mut().surfaced(Outcome::Terminated);
                break;
            }
            Err(err) => panic!("unexpected error from the ark: {err}"),
        }
    }
    let mut host = host.borrow_mut();
    host.sync();
    check_session(&mut ark, &host);
    host.summary.state = host.state;
    host.summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::side_host::MAX_STALE_FRAMES;
    use crate::testing;

    /// Runs a script with logging enabled.
    fn run_logged(steps: &[Step]) -> Summary {
        testing::init_tracing();
        run(steps)
    }

    // Tests the happy path of the state machine, a handshake followed by
    // requests round tripping through the session.
    #[test]
    fn test_scripted_round_trip() {
        let summary = run_logged(&[
            Step::ResetPair,
            Step::Hello,
            Step::Ack,
            Step::Request(1),
            Step::Request(2),
        ]);
        assert_eq!(
            summary,
            Summary {
                state: State::Established,
                dropped: 0,
                handshakes: 1,
                delivered: 2,
                replies: 2,
            }
        );
    }

    // Tests that a reset in every state restarts the handshake without the
    // Ark signaling anything, the host having asked for it. A session does
    // not survive one, a request into it earning a signal.
    #[test]
    fn test_scripted_reset_restarts() {
        let summary = run_logged(&[
            Step::Reset,
            Step::Reset,
            Step::Reset,
            Step::Hello,
            Step::Ack,
        ]);
        assert_eq!(summary.state, State::Established);
        assert_eq!(summary.handshakes, 1);
        assert_eq!(summary.dropped, 0);

        let summary = run_logged(&[
            Step::Reset,
            Step::Hello,
            Step::Reset,
            Step::Hello,
            Step::Ack,
        ]);
        assert_eq!(summary.state, State::Established);
        assert_eq!(summary.handshakes, 2);
        assert_eq!(summary.dropped, 0);

        let summary = run_logged(&[
            Step::Reset,
            Step::Hello,
            Step::Ack,
            Step::ResetPair,
            Step::Hello,
            Step::Ack,
            Step::Request(1),
        ]);
        assert_eq!(summary.state, State::Established);
        assert_eq!(summary.handshakes, 2);
        assert_eq!(summary.delivered, 1);
        assert_eq!(summary.dropped, 0);

        let summary = run_logged(&[
            Step::Reset,
            Step::Hello,
            Step::Ack,
            Step::Reset,
            Step::Request(1),
        ]);
        assert_eq!(summary.state, State::Idle);
        assert_eq!(summary.delivered, 0);
        assert_eq!(summary.dropped, 1);
    }

    // Tests that frames arriving outside the state expecting them are junk,
    // a handshake only ever starting with a reset.
    #[test]
    fn test_scripted_frames_outside_state() {
        let summary = run_logged(&[Step::Hello]);
        assert_eq!(summary.state, State::Idle);
        assert_eq!(summary.handshakes, 0);
        assert_eq!(summary.dropped, 1);

        let summary = run_logged(&[Step::Reset, Step::Hello, Step::Hello]);
        assert_eq!(summary.state, State::Idle);
        assert_eq!(summary.dropped, 1);

        let summary = run_logged(&[Step::Reset, Step::Ack]);
        assert_eq!(summary.state, State::Idle);
        assert_eq!(summary.dropped, 1);

        let summary = run_logged(&[Step::Reset, Step::Hello, Step::Request(1)]);
        assert_eq!(summary.state, State::Idle);
        assert_eq!(summary.handshakes, 1);
        assert_eq!(summary.dropped, 1);

        let summary = run_logged(&[Step::Reset, Step::Hello, Step::Ack, Step::Hello]);
        assert_eq!(summary.state, State::Idle);
        assert_eq!(summary.dropped, 1);
    }

    // Tests that frames failing the handshake's crypto for one specific
    // reason each are refused with the dropped session signal. That is a
    // hello with an invalid key, acks tampered with, bound or signed wrongly,
    // malformed or carrying a bad encapsulation, and a tampered request in a
    // session.
    #[test]
    fn test_scripted_bad_crypto_frames() {
        let summary = run_logged(&[Step::Reset, Step::HelloBadKey]);
        assert_eq!(summary.state, State::Idle);
        assert_eq!(summary.handshakes, 0);
        assert_eq!(summary.dropped, 1);

        for step in [
            Step::AckTampered,
            Step::AckBadAuth,
            Step::AckBadSigner,
            Step::AckBadPayload,
            Step::AckBadEncap,
        ] {
            let summary = run_logged(&[Step::Reset, Step::Hello, step.clone()]);
            assert_eq!(summary.state, State::Idle, "{step:?}");
            assert_eq!(summary.handshakes, 1, "{step:?}");
            assert_eq!(summary.dropped, 1, "{step:?}");

            // Without an ArkHello to answer the frame is plain junk
            let summary = run_logged(&[Step::Reset, step.clone()]);
            assert_eq!(summary.state, State::Idle, "{step:?}");
            assert_eq!(summary.dropped, 1, "{step:?}");
        }

        let summary = run_logged(&[
            Step::Reset,
            Step::Hello,
            Step::Ack,
            Step::RequestTampered,
            Step::Request(1),
        ]);
        assert_eq!(summary.state, State::Idle);
        assert_eq!(summary.delivered, 0);
        assert_eq!(summary.dropped, 2);
    }

    // Tests that replayed frames are refused, except a replayed hello which is
    // a valid hello in its own right and can be acked with its old keys.
    #[test]
    fn test_scripted_replays() {
        let summary = run_logged(&[Step::Reset, Step::Hello, Step::Ack, Step::AckReplay]);
        assert_eq!(summary.state, State::Idle);
        assert_eq!(summary.dropped, 1);

        let summary = run_logged(&[
            Step::Reset,
            Step::Hello,
            Step::Ack,
            Step::Request(1),
            Step::RequestReplay,
        ]);
        assert_eq!(summary.state, State::Idle);
        assert_eq!(summary.delivered, 1);
        assert_eq!(summary.dropped, 1);

        let summary = run_logged(&[
            Step::Reset,
            Step::Hello,
            Step::Ack,
            Step::Reset,
            Step::Hello,
            Step::AckReplay,
        ]);
        assert_eq!(summary.state, State::Idle);
        assert_eq!(summary.handshakes, 2);
        assert_eq!(summary.dropped, 1);

        let summary = run_logged(&[
            Step::Reset,
            Step::Hello,
            Step::Ack,
            Step::Reset,
            Step::HelloReplay,
            Step::Ack,
            Step::Request(3),
        ]);
        assert_eq!(summary.state, State::Established);
        assert_eq!(summary.handshakes, 2);
        assert_eq!(summary.delivered, 1);
        assert_eq!(summary.dropped, 0);
    }

    // Tests that a packet decrypting into something that is not a message
    // surfaces as an error but leaves the session usable.
    #[test]
    fn test_scripted_garbage_keeps_session() {
        let summary = run_logged(&[
            Step::Reset,
            Step::Hello,
            Step::Ack,
            Step::Garbage,
            Step::Request(1),
        ]);
        assert_eq!(summary.state, State::Established);
        assert_eq!(summary.delivered, 1);
        assert_eq!(summary.dropped, 0);
    }

    // Tests that junk in every state drops the Ark back to idle with the host
    // told about it through an empty frame, and that a fresh handshake
    // recovers from it.
    #[test]
    fn test_scripted_junk_signals_dropped() {
        let junk = || Step::Junk(vec![0xde, 0xad, 0xbe, 0xef]);

        let summary = run_logged(&[junk()]);
        assert_eq!(summary.state, State::Idle);
        assert_eq!(summary.dropped, 1);

        let summary = run_logged(&[Step::Reset, junk()]);
        assert_eq!(summary.state, State::Idle);
        assert_eq!(summary.dropped, 1);

        let summary = run_logged(&[Step::Reset, Step::Hello, junk()]);
        assert_eq!(summary.state, State::Idle);
        assert_eq!(summary.handshakes, 1);
        assert_eq!(summary.dropped, 1);

        let summary = run_logged(&[Step::Reset, Step::Hello, Step::Ack, junk()]);
        assert_eq!(summary.state, State::Idle);
        assert_eq!(summary.dropped, 1);

        // Undecodable COBS is junk like any other, as is an empty packet in
        // a frame that is not empty
        let summary = run_logged(&[
            Step::Reset,
            Step::Hello,
            Step::Ack,
            Step::Junk(vec![0xff, 0x01]),
        ]);
        assert_eq!(summary.state, State::Idle);
        assert_eq!(summary.dropped, 1);

        let summary = run_logged(&[Step::Reset, Step::Hello, Step::Ack, Step::Junk(vec![])]);
        assert_eq!(summary.state, State::Idle);
        assert_eq!(summary.dropped, 1);

        // A fresh handshake recovers, whether the junk hit a session or a
        // handshake in progress
        let summary = run_logged(&[
            Step::Reset,
            Step::Hello,
            Step::Ack,
            junk(),
            Step::Reset,
            Step::Hello,
            Step::Ack,
            Step::Request(1),
        ]);
        assert_eq!(summary.state, State::Established);
        assert_eq!(summary.delivered, 1);
        assert_eq!(summary.dropped, 1);

        let summary = run_logged(&[
            Step::Reset,
            junk(),
            Step::Reset,
            Step::Hello,
            Step::Ack,
            Step::Request(1),
        ]);
        assert_eq!(summary.state, State::Established);
        assert_eq!(summary.delivered, 1);
        assert_eq!(summary.dropped, 1);
    }

    // Tests that every request into a session the Ark no longer has earns a
    // signal of its own. A host pipelining a stale bound's worth of them
    // queues up as many in front of its next handshake.
    #[test]
    fn test_scripted_requests_into_dead_session() {
        let mut steps = vec![
            Step::Reset,
            Step::Hello,
            Step::Ack,
            Step::Junk(vec![0xde, 0xad]),
        ];
        steps.extend((0..MAX_STALE_FRAMES as u8).map(Step::Request));
        let summary = run_logged(&steps);
        assert_eq!(summary.state, State::Idle);
        assert_eq!(summary.delivered, 0);
        assert_eq!(summary.dropped, MAX_STALE_FRAMES + 1);
    }

    // Tests that truncated copies of valid frames are junk in every state.
    #[test]
    fn test_scripted_truncated_frames() {
        for cut in [0u8, 1, 7, 255] {
            let summary = run_logged(&[Step::Reset, Step::Hello, Step::Truncated(cut)]);
            assert_eq!(summary.state, State::Idle, "cut {cut}");
            assert_eq!(summary.dropped, 1, "cut {cut}");

            let summary = run_logged(&[
                Step::Reset,
                Step::Hello,
                Step::Ack,
                Step::Request(1),
                Step::Truncated(cut),
            ]);
            assert_eq!(summary.state, State::Idle, "cut {cut}");
            assert_eq!(summary.dropped, 1, "cut {cut}");
        }
    }

    // Tests how an unterminated frame merges with what follows it. Bytes
    // swallow the next frame into junk, while a lone delimiter completes a
    // partial hello into a valid one. Only the second zero of a reset pair
    // gets through as a reset.
    #[test]
    fn test_scripted_partial_frames() {
        let summary = run_logged(&[Step::Partial, Step::Reset, Step::Hello]);
        assert_eq!(summary.state, State::Idle);
        assert_eq!(summary.handshakes, 0);
        assert_eq!(summary.dropped, 2);

        let summary = run_logged(&[Step::Reset, Step::Partial, Step::Reset, Step::Ack]);
        assert_eq!(summary.state, State::Established);
        assert_eq!(summary.handshakes, 1);
        assert_eq!(summary.dropped, 0);

        let summary = run_logged(&[
            Step::Reset,
            Step::Partial,
            Step::ResetPair,
            Step::Hello,
            Step::Ack,
        ]);
        assert_eq!(summary.state, State::Established);
        assert_eq!(summary.handshakes, 2);
        assert_eq!(summary.dropped, 0);

        let summary = run_logged(&[Step::Reset, Step::Partial, Step::Partial, Step::Reset]);
        assert_eq!(summary.state, State::Idle);
        assert_eq!(summary.dropped, 1);

        let summary = run_logged(&[Step::Partial, Step::ResetPair, Step::Hello, Step::Ack]);
        assert_eq!(summary.state, State::Established);
        assert_eq!(summary.dropped, 1);

        let summary = run_logged(&[
            Step::Reset,
            Step::Hello,
            Step::Ack,
            Step::Partial,
            Step::Request(1),
        ]);
        assert_eq!(summary.state, State::Idle);
        assert_eq!(summary.delivered, 0);
        assert_eq!(summary.dropped, 1);
    }

    // Tests that a read failing aborts a handshake in progress without a
    // signal to the host, but leaves an established session intact.
    #[test]
    fn test_scripted_yield() {
        let summary = run_logged(&[Step::Yield]);
        assert_eq!(summary.state, State::Idle);
        assert_eq!(summary.replies, 0);

        let summary = run_logged(&[Step::Reset, Step::Yield, Step::Hello]);
        assert_eq!(summary.state, State::Idle);
        assert_eq!(summary.handshakes, 0);
        assert_eq!(summary.dropped, 1);

        let summary = run_logged(&[Step::Reset, Step::Hello, Step::Yield, Step::Ack]);
        assert_eq!(summary.state, State::Idle);
        assert_eq!(summary.handshakes, 1);
        assert_eq!(summary.dropped, 1);

        let summary = run_logged(&[
            Step::Reset,
            Step::Hello,
            Step::Ack,
            Step::Yield,
            Step::Request(1),
        ]);
        assert_eq!(summary.state, State::Established);
        assert_eq!(summary.delivered, 1);
        assert_eq!(summary.replies, 2);
    }

    // Tests a transport failing under the Ark's writes. A failed reply drops
    // the session, the signals it would send are lost and a handshake whose
    // ArkHello cannot go out is given up. A healed transport recovers.
    #[test]
    fn test_scripted_broken_transport() {
        let summary = run_logged(&[
            Step::Reset,
            Step::Hello,
            Step::Ack,
            Step::Request(1),
            Step::Break,
            Step::Request(2),
            Step::Request(3),
            Step::Heal,
            Step::Reset,
            Step::Hello,
            Step::Ack,
            Step::Request(4),
        ]);
        assert_eq!(summary.state, State::Established);
        assert_eq!(summary.delivered, 3);
        assert_eq!(summary.replies, 2);
        assert_eq!(summary.dropped, 0);

        let summary = run_logged(&[
            Step::Reset,
            Step::Break,
            Step::Hello,
            Step::Heal,
            Step::Ack,
            Step::Reset,
            Step::Hello,
            Step::Ack,
        ]);
        assert_eq!(summary.state, State::Established);
        assert_eq!(summary.handshakes, 1);
        assert_eq!(summary.dropped, 1);

        let summary = run_logged(&[
            Step::Reset,
            Step::Hello,
            Step::Ack,
            Step::Break,
            Step::Yield,
            Step::Heal,
            Step::Request(1),
        ]);
        assert_eq!(summary.state, State::Idle);
        assert_eq!(summary.delivered, 0);
        assert_eq!(summary.replies, 0);
        assert_eq!(summary.dropped, 1);
    }

    // Tests that frames arriving in pieces, down to a byte per read, are
    // reassembled and served like whole ones. A partial hello completes
    // across reads the same way.
    #[test]
    fn test_scripted_chunked_reads() {
        for chunk in [1u8, 7, 254, 255] {
            let summary = run_logged(&[
                Step::Chunk(chunk),
                Step::Reset,
                Step::Hello,
                Step::Ack,
                Step::Request(1),
                Step::Junk(vec![1; 300]),
                Step::Reset,
                Step::Hello,
                Step::Ack,
                Step::Request(2),
            ]);
            assert_eq!(summary.state, State::Established, "chunk {chunk}");
            assert_eq!(summary.delivered, 2, "chunk {chunk}");
            assert_eq!(summary.dropped, 1, "chunk {chunk}");

            let summary = run_logged(&[
                Step::Chunk(chunk),
                Step::Reset,
                Step::Partial,
                Step::Reset,
                Step::Ack,
            ]);
            assert_eq!(summary.state, State::Established, "chunk {chunk}");
            assert_eq!(summary.handshakes, 1, "chunk {chunk}");
        }
    }

    // Tests that steps with nothing to replay or truncate yet are no-ops.
    #[test]
    fn test_scripted_noops() {
        let summary = run_logged(&[
            Step::HelloReplay,
            Step::AckReplay,
            Step::RequestReplay,
            Step::Truncated(3),
            Step::Reset,
            Step::Hello,
            Step::Ack,
        ]);
        assert_eq!(summary.state, State::Established);
        assert_eq!(summary.dropped, 0);
    }
}
