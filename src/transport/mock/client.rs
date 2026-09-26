// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Mock client driving a real [`Server`](crate::transport::Server).
//!
//! Script steps provide incoming frames, inject I/O failures, or ask the driver
//! to call a server method. The driver receives events in a loop and replies to
//! each tagged request. The read adapter advances the script after the server
//! consumes the previous step's bytes.
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

/// One scripted input, I/O fault, or driver action.
///
/// A step that needs a missing session or ArkHello sends junk instead, so
/// arbitrary step sequences are valid.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum Step {
    /// A lone zero, one empty frame that starts a handshake.
    Reset,
    /// Two zeros, matching [`Client::connect`](crate::transport::Client::connect).
    ResetPair,
    /// A valid HostHello with fresh ephemeral keys.
    Hello,
    /// The last HostHello sent, repeated.
    ///
    /// Nothing is sent if there was none yet.
    HelloReplay,
    /// A HostHello carrying an encryption key that fails validation.
    HelloBadKey,
    /// A valid HostAck for the pending ArkHello.
    ///
    /// The step sends junk without a pending ArkHello.
    Ack,
    /// The last HostAck sent, repeated.
    ///
    /// Nothing is sent if there was none yet.
    AckReplay,
    /// A HostAck for the pending ArkHello with a flipped ciphertext byte.
    ///
    /// The step sends junk without a pending ArkHello.
    AckTampered,
    /// A HostAck bound to the wrong server key.
    ///
    /// The step sends junk without a pending ArkHello.
    AckBadAuth,
    /// A HostAck signed by a key absent from the HostHello.
    ///
    /// The step sends junk without a pending ArkHello.
    AckBadSigner,
    /// A HostAck for the pending ArkHello whose sealed payload is not an ack
    /// at all.
    ///
    /// The step sends junk without a pending ArkHello.
    AckBadPayload,
    /// A HostAck for the pending ArkHello with an encapsulated key of the
    /// wrong size.
    ///
    /// The step sends junk without a pending ArkHello.
    AckBadEncap,

    /// A request sealed in the session, tagged by the byte.
    ///
    /// The step sends junk without a session.
    Request(u8),
    /// The last sealed request sent, repeated.
    ///
    /// Nothing is sent if there was none yet.
    RequestReplay,
    /// A sealed request with a flipped ciphertext byte.
    ///
    /// The step sends junk without a session.
    RequestTampered,
    /// A sealed packet that is not a protobuf message.
    ///
    /// The step sends junk without a session.
    Garbage,

    /// Arbitrary frame bytes, with zeros replaced and an empty input padded.
    ///
    /// The model expects rejection during framing, key validation, or
    /// decryption.
    Junk(Vec<u8>),
    /// The last valid frame sent, cut short but keeping at least one byte.
    ///
    /// Nothing is sent if there was no valid frame yet.
    Truncated(u8),
    /// A valid HostHello without its delimiter.
    ///
    /// A following zero completes the hello. So does a frame encoding the empty
    /// packet when the hello's encoding ends in a full run, as COBS implies no
    /// zero after one. Any other frame merges into its bytes and makes it
    /// invalid.
    Partial,
    /// A frame past [`MAX_FRAME_SIZE`], delimiter included.
    ///
    /// The server rejects it as soon as the limit is exceeded, ending any
    /// session or handshake. Its remaining bytes and any partial hello in front
    /// are discarded together.
    Oversized,

    /// Driver action keeping a copy of the server's current sender, replacing
    /// any retained one.
    ///
    /// Without a current sender, it clears the retained slot.
    Retain,
    /// Driver action sending a tagged message through the server's current
    /// sender, without a request.
    Send(u8),
    /// Driver action sending a tagged message through the retained sender,
    /// even after its session ends.
    ///
    /// Without a retained sender, it checks the same refusal as a missing
    /// sender.
    SendRetained(u8),
    /// Driver action sending a message one byte over the conservative send
    /// limit.
    SendOversized,
    /// Driver action ending the server's session locally, which signals the
    /// client.
    ///
    /// No local disconnection event is expected, and the stream can establish
    /// another session.
    Disconnect,

    /// Limit of this many bytes on each later read, where zero removes it.
    Chunk(u8),
    /// Batch of up to this many steps delivered in the next read.
    ///
    /// The batch stops at a step that produces a receive event, so the driver
    /// handles it before the model advances again. A step that queues no
    /// frames also ends the batch.
    Batch(u8),
    /// Read failure with `WouldBlock`, handing control back to the driver.
    Yield,
    /// Read failure with `Interrupted`, which framing retries without a server
    /// event.
    Interrupt,
    /// Early adapter read timeout, after which the server keeps waiting
    /// without a transition.
    ReadTimeout,

    /// Persistent failure of the server's writes, until a [`Step::Heal`].
    Break,
    /// Recovery from persistent write failure, so the server's writes work
    /// again.
    Heal,
    /// Cut of the next server write this point applies to.
    Cut {
        /// Point in the write where it fails.
        point: CutPoint,
        /// Whether all later writes fail too, until a [`Step::Heal`].
        then_broken: bool,
    },
    /// Timeout that the next matching output operation reports after the
    /// selected prefix.
    ///
    /// The transport skips the failure notification after this error.
    Timeout(CutPoint),
}

impl Step {
    /// Checks whether the driver must act on the server or one of its senders.
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

    /// Checks whether this step can join an input batch without driver or I/O
    /// changes.
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
    /// Wait for a HostHello after a reset.
    AwaitHello,
    /// Wait for a HostAck after the ArkHello went out.
    AwaitAck,
    /// Live session in both directions.
    Established,
}

/// Final model state and observed counts for scenario assertions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    /// State the server ended up in.
    pub state: State,
    /// Empty frames the server emitted.
    pub dropped: usize,
    /// Frames the server left cut short and terminated later.
    pub fragments: usize,
    /// ArkHellos the server emitted.
    pub handshakes: usize,
    /// Requests the server delivered.
    pub delivered: usize,
    /// Messages from the server that reached the client, such as replies and
    /// probes.
    pub replies: usize,
    /// Reads that handed the server bytes.
    pub reads: usize,
}

/// Meaning of an incoming frame in the model.
enum Frame {
    /// The empty frame, a reset.
    Empty,
    /// A valid HostHello announcing the keys.
    Hello(Box<Keys>),
    /// A valid HostAck for the pending ArkHello.
    Ack,
    /// A request with the id, sealed in the session.
    Request(u64),
    /// Sealed bytes outside the tagged request format, still valid transport data.
    Garbage,
    /// A frame encoding the empty packet, refused like junk on its own.
    EmptyPacket,
    /// Anything else, refused in every state.
    Junk,
}

/// Unterminated input retained until the next frame delimiter.
enum Partial {
    /// No unterminated input, with the stream at a frame boundary.
    None,
    /// A hello that completes only if the next byte is a delimiter.
    ///
    /// With the flag set, its encoding ends in a full run, so a frame encoding
    /// the empty packet decodes to nothing and completes it too.
    Hello(Box<Keys>, bool),
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

/// Unterminated server output left by a failed send.
///
/// The next recovery delimiter completes it.
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

/// Result the model expects [`recv`](crate::transport::Server::recv) to
/// surface for the last step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    /// No result, as the server keeps reading.
    Absorbed,
    /// Delivery of the request with this tag.
    Message(u64),
    /// Delivery of untagged bytes, without ending the session.
    Garbage,
    /// [`Event::Disconnected`] after a reset or invalid frame ends the session.
    Ended,
    /// [`Event::Connected`] after HostAck establishes a session.
    Opened,
    /// [`Error::RecvFailed`] carrying `WouldBlock`.
    Yield,
    /// [`Error::SendFailed`] from an ArkHello whose write or flush failed.
    SendFailed,
    /// [`Error::Terminated`] after the script runs out.
    Terminated,
}

/// Ephemeral keys of a HostHello.
#[derive(Clone)]
struct Keys {
    /// Signing key announced in the HostHello, which signs the HostAck.
    signer: xdsa::SecretKey,
    /// Encryption key announced in the HostHello, which the ArkHello is sealed
    /// to.
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
    /// A flipped ciphertext byte, which prevents decryption.
    Tampered,
    /// Authenticated data naming another server key than the one that
    /// answered.
    Auth,
    /// A signature by a key other than the hello's.
    Signer,
    /// A sealed payload that is not an ack at all.
    Payload,
    /// An encapsulated key of the wrong size.
    Encap,
}

/// Client keys and server response needed to create HostAck.
///
/// The model keeps it only while it expects the server to accept that ack.
struct Pending {
    /// Keys of the HostHello the ArkHello answered.
    keys: Keys,
    /// Server's ephemeral encryption key from the ArkHello.
    ark_crypto: xhpke::PublicKey,
    /// Context opening the server's messages in the new session.
    receiver: xhpke::Receiver,
}

impl Pending {
    /// Creates the HostAck and the client's two contexts for the new session.
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

    /// Creates a HostAck whose only intentional fault is the selected defect.
    fn bad_ack(&self, identity: &xdsa::PublicKey, flaw: AckFlaw) -> Vec<u8> {
        // Encapsulate a fresh key, as a valid ack would carry
        let (_, encap) = self
            .ark_crypto
            .new_sender(CRYPTO_DOMAIN_WIRE_HOST_TO_ARK)
            .unwrap();

        // Swap in the flawed authenticated data or signer, if selected
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

        // Seal the ack, with a bad payload or encapsulated key if selected
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

        // Flip the last ciphertext byte of a tampered ack
        if flaw == AckFlaw::Tampered {
            *sealed.last_mut().unwrap() ^= 0xff;
        }
        sealed
    }
}

/// Mock client along with the model of the server it drives.
pub struct Client {
    /// Script steps not yet run.
    steps: VecDeque<Step>,
    /// Driver action that interrupted a receive call.
    action: Option<Step>,
    /// Server's identity key, verifying its ArkHellos.
    identity: xdsa::PublicKey,
    /// Output adapter holding the frames the server wrote.
    outbox: Outbox,
    /// Current input batch, kept until fully delivered.
    bytes: Vec<u8>,
    /// Read position within the current input batch.
    offset: usize,
    /// Maximum bytes per read, or zero for no limit.
    chunk: usize,
    /// Steps remaining in the current input batch.
    batch: usize,
    /// Whether the server's writes fail persistently.
    broken: bool,
    /// Cut armed for the next matching server write.
    cut: Option<CutPoint>,
    /// Whether the armed cut returns `TimedOut`.
    timeout: bool,
    /// Whether the last modeled send reported `TimedOut`.
    timed_out: bool,

    /// State the server should be in.
    state: State,
    /// Unterminated input in front of the server.
    partial: Partial,
    /// Whether failed output requires a recovery delimiter before the next
    /// send.
    resync: bool,
    /// Unterminated frame the server left behind.
    tail: Option<Tail>,
    /// Frames the server should have emitted since the last output check.
    emits: Vec<Emit>,
    /// Result `recv` should surface for the last step.
    outcome: Outcome,
    /// Whether the receive side owes a [`Event::Disconnected`] when this
    /// session ends.
    held: bool,

    /// Answered ArkHello awaiting the client's HostAck.
    pending: Option<Pending>,
    /// Context sealing the client's requests in the current session.
    sender: Option<xhpke::Sender>,
    /// Context opening the server's replies, shared with the replies awaiting
    /// verification.
    receiver: Option<Arc<Mutex<xhpke::Receiver>>>,

    /// Last HostHello sent, framed, with its keys.
    last_hello: Option<(Vec<u8>, Keys)>,
    /// Last HostAck sent, framed.
    last_ack: Option<Vec<u8>>,
    /// Last request sent, framed.
    last_request: Option<Vec<u8>>,
    /// Last valid frame sent, delimiter stripped.
    last_valid: Option<Vec<u8>>,

    /// Counts observed so far, returned when the script ends.
    summary: Summary,
}

impl Client {
    /// Creates an idle model with the script cut to [`MAX_STEPS`] and the
    /// server's output adapter.
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

    /// Takes the driver action due at the current script position, if any.
    ///
    /// An action runs before another receive can consume frames, after the
    /// output so far is checked. Actions met inside a receive are saved by
    /// [`Feed`] instead.
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
                self.raw(&junk);
            }
            Step::Truncated(n) => {
                if let Some(valid) = self.last_valid.clone() {
                    let keep = match valid.len() {
                        0..=1 => 1,
                        len => 1 + n as usize % (len - 1),
                    };
                    self.raw(&valid[..keep]);
                }
            }
            Step::Partial => {
                let keys = Keys::generate();
                let hello = keys.hello();
                let mut framed = frame(&hello);
                framed.pop();

                // An encoding ending in a full run has no implied zero to
                // restore, so the empty packet's `0x01` leaves the hello intact
                let full_run = unframe(&[framed.as_slice(), &[0x01]].concat()) == hello;
                self.bytes.extend(framed);
                self.partial = match self.partial {
                    Partial::None => Partial::Hello(Box::new(keys), full_run),
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

    /// Queues a defective HostAck, or junk if no ArkHello is pending.
    ///
    /// The model expects the server to refuse either one.
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

    /// Queues raw frame bytes and their delimiter, refused by the server on
    /// their own.
    ///
    /// A lone `0x01` encodes the empty packet, which can complete a partial
    /// hello.
    fn raw(&mut self, body: &[u8]) {
        self.deliver(match body {
            [0x01] => Frame::EmptyPacket,
            _ => Frame::Junk,
        });
        self.bytes.extend(body);
        self.bytes.push(0x00);
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

    /// Predicts the server's response to an incoming frame.
    ///
    /// A preceding partial hello is valid only if this frame supplies its
    /// missing delimiter, or if it encodes the empty packet right after a full
    /// run. Other combinations of partial input and new bytes become junk.
    fn deliver(&mut self, frame: Frame) {
        // Merge any unterminated input in front into this frame
        let frame = match std::mem::replace(&mut self.partial, Partial::None) {
            Partial::None => frame,
            Partial::Hello(keys, full_run) => match frame {
                Frame::Empty => Frame::Hello(keys),
                Frame::EmptyPacket if full_run => Frame::Hello(keys),
                _ => Frame::Junk,
            },
            Partial::Junk => Frame::Junk,
        };

        // Advance the state machine on the resulting frame
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
            // Deliver the new sender as soon as HostAck completes the handshake
            (State::AwaitAck, Frame::Ack) => {
                self.state = State::Established;
                self.held = true;
                self.outcome = Outcome::Opened;
            }
            (State::Established, Frame::Request(id)) => {
                self.outcome = Outcome::Message(id);
            }
            // Transport delivers opaque bytes without inspecting their format
            (State::Established, Frame::Garbage) => {
                self.outcome = Outcome::Garbage;
            }
            // Invalid input abandons the handshake or session and attempts a
            // wire signal. An existing session also produces `Disconnected`.
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

    /// Predicts one server send and returns whether it succeeds.
    ///
    /// Any recovery delimiter goes out in the same write as the output it
    /// precedes. An applicable cut fires before a broken stream, and a middle
    /// cut at zero accepts only the recovery delimiter, leaving no new fragment.
    fn send(&mut self, payload: Payload) -> bool {
        // Take the armed cut if it applies to this output
        let frame = matches!(&payload, Payload::Frame(_));
        let cut = match self.cut {
            Some(CutPoint::Start) => self.cut.take(),
            Some(CutPoint::Middle(_)) if frame => self.cut.take(),
            Some(CutPoint::Delimiter | CutPoint::Flush) if frame || self.resync => self.cut.take(),
            _ => None,
        };
        self.timed_out = cut.is_some() && std::mem::take(&mut self.timeout);

        // Predict the bytes that reach the wire and whether the send succeeds
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

        // Any failure requires a recovery delimiter before the next output
        self.resync = !sent;
        sent
    }

    /// Predicts a delimiter reaching the wire.
    ///
    /// It completes any pending tail, or creates an empty frame when no tail
    /// exists.
    fn zero_out(&mut self) {
        self.emits.push(match self.tail.take() {
            None => Emit::Dropped,
            Some(Tail::Fragment) => Emit::Fragment,
            Some(Tail::Body(emit)) => emit,
        });
    }

    /// Clears the model's current session and pending handshake.
    ///
    /// Expected replies keep their receiver until the output check opens them.
    fn forget(&mut self) {
        self.sender = None;
        self.receiver = None;
        self.pending = None;
    }

    /// Predicts a read error or EOF.
    ///
    /// It aborts an unfinished handshake, while an established session remains
    /// until the server reports its end.
    fn interrupt(&mut self, outcome: Outcome) {
        if matches!(self.state, State::AwaitHello | State::AwaitAck) {
            self.forget();
            self.state = State::Idle;
        }
        self.outcome = outcome;
    }

    /// Checks a receive result against the model, then clears the expectation
    /// for the next step.
    fn surfaced(&mut self, outcome: Outcome) {
        assert_eq!(self.outcome, outcome, "model vs server");
        self.outcome = Outcome::Absorbed;
    }

    /// Checks output against all predictions so far.
    ///
    /// It runs before each input batch, after driver actions and at the end of
    /// the script.
    fn sync(&mut self) {
        // The server must have surfaced every predicted receive result
        assert_eq!(
            self.outcome,
            Outcome::Absorbed,
            "server read on past a step it should have surfaced"
        );

        // Match the captured frames and any unfinished tail with the predictions
        let frames = self.outbox.take_frames();
        let emits = std::mem::take(&mut self.emits);
        assert_eq!(frames.len(), emits.len(), "model expected {emits:?}");
        assert_eq!(
            self.outbox.has_tail(),
            self.tail.is_some(),
            "unterminated frame"
        );

        // Verify each frame's contents and count it
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
    ///
    /// It saves the response for HostAck only while the handshake is still
    /// active.
    fn receive_hello(&mut self, frame: &[u8], keys: Keys) {
        // Open the ArkHello and derive the context for the server's messages
        let auth = handshake::ArkHelloAuth {
            host_signer: keys.signer.public_key(),
            host_crypto: keys.crypto.public_key(),
        };
        let sign1 = cose::decrypt(&unframe(frame), &auth, &keys.crypto, CRYPTO_DOMAIN_WIRE)
            .expect("server hello failed to decrypt");
        let hello: handshake::ArkHello = cose::verify_at(
            &sign1,
            &auth,
            &self.identity,
            CRYPTO_DOMAIN_WIRE,
            None,
            TIMESTAMP,
        )
        .expect("server hello signature invalid");
        let encap: [u8; xhpke::ENCAP_KEY_SIZE] = hello
            .a2h_encap
            .try_into()
            .expect("server hello encap size invalid");
        let receiver = keys
            .crypto
            .new_receiver(&encap, CRYPTO_DOMAIN_WIRE_ARK_TO_HOST)
            .unwrap();

        // Keep the response for a HostAck only if the server still waits for one
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
    fn clock(&self) -> darkbio_clock::Clock {
        self.0.lock().unwrap().outbox.clock.clone()
    }

    fn set_read_deadline(&mut self, _deadline: Option<Instant>) -> io::Result<()> {
        // Every read completes immediately according to the script
        Ok(())
    }
}

impl io::Read for Feed {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut client = self.0.lock().unwrap();
        if client.bytes.is_empty() {
            // Verify the previous batch's output before advancing the script
            client.sync();
            client.batch = 0;

            // Run steps until one queues input or ends this read
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

        // Hand out the current batch, limited by the chunk size
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

/// Server under test, reading the script and writing into the outbox.
type Server = crate::transport::Server<Feed, Outbox, Attestation>;

/// Checks that the current sender is usable exactly when the model expects a
/// session.
///
/// An oversized send checks admission without sealing or writing bytes.
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

/// Sends a tagged message and checks its result against the model.
///
/// A failed send ends the sending session and attempts a wire signal unless it
/// timed out. The receive side reports the session's end when it next handles
/// a frame or EOF.
fn send(sender: Option<&Sender<Outbox>>, client: &mut Client, id: u64) {
    // Predict whether the reply reaches the client and whether failure should
    // attempt a wire signal
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

    // Send through the real sender and compare the result with the prediction
    let sent = super::send(sender, &payload(id));
    match (expected, sent) {
        (Some(true), Ok(())) => {}
        (Some(false), Err(Error::SendFailed(_))) => {}
        (None, Err(Error::EncryptionFailed(_))) => {}
        (expected, sent) => panic!("model expected {expected:?}, server returned {sent:?}"),
    }
}

/// Runs a script against a real server and returns the observed counts.
///
/// # Panics
///
/// Panics if server output or receive results differ from the model.
pub fn run(steps: &[Step]) -> Summary {
    // Save the script as a fuzz seed when seeding is on
    #[cfg(feature = "fuzz")]
    super::seed::seed(super::seed::TRANSPORT_SERVER, steps);

    // Start a real server over the scripted adapters, with the model beside it
    let signer = xdsa::SecretKey::generate();
    let attestation = self_attestation(&signer);
    let tester = crate::transport::testing::test_clock();
    let outbox = Outbox::new(&tester.clock());
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

    // Track the delivered and retained senders and their sessions
    let mut sender = None;
    let mut retained = None;
    let mut generation = 0u64;
    let mut retained_generation = None;
    loop {
        // Run any owner action due before the next receive
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
                    // scheduled even if the owner disconnects before receiving
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

        // Otherwise receive, checking each result against the model
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
            // A reset or invalid frame ends the previous session
            Ok(Event::Disconnected) => {
                let mut client = client.lock().unwrap();
                client.surfaced(Outcome::Ended);
                check_session(sender.as_ref(), &client);
            }
            // The new sender is usable immediately after the handshake
            Ok(Event::Connected(opened)) => {
                sender = Some(opened);
                let mut client = client.lock().unwrap();
                client.surfaced(Outcome::Opened);
                generation += 1;
                check_session(sender.as_ref(), &client);
            }
            // Probe sending whenever the script yields control to the driver
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

    // Check the final output and session against the model
    let mut client = client.lock().unwrap();
    client.sync();
    check_session(sender.as_ref(), &client);
    client.summary.state = client.state;
    client.summary
}

#[cfg(test)]
mod tests;
