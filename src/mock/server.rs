// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Mock server driving a real `Client`. A script mixes calls the driver
//! makes into the client with frames the mock server puts in front of it. The
//! frames queue up until a call reads them, the read half handing them over
//! one at a time and moving the script forward as the client reads. The
//! mock server parses everything the client writes, answering hellos and
//! opening requests with real keys.
//!
//! The model predicts the result of every call from the frames it consumed,
//! tracking the session the client should have. Any divergence panics.

use super::{
    CutPoint, MAX_STEPS, Outbox, cloud_attestation, frame, self_attestation, unframe, would_block,
};
use crate::client::MAX_STALE_FRAMES;
use crate::handshake;
use crate::protocol::{ArkToHost, HostToArk, host_to_ark};
use crate::{
    Attestation, CRYPTO_DOMAIN_WIRE, CRYPTO_DOMAIN_WIRE_ARK_TO_HOST,
    CRYPTO_DOMAIN_WIRE_HOST_TO_ARK, Error, MAX_FRAME_SIZE, MAX_MESSAGE_SIZE,
};
use darkbio_cobs as cobs;
use darkbio_crypto::{cbor, cose, xdsa, xhpke};
use prost::Message;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{self, Read};
use std::rc::Rc;

/// Message id of the probes the driver sends on the client's behalf.
const PROBE_ID: u64 = u64::MAX;

/// One step of a script, either a call the driver makes into the client or a
/// frame the mock server puts in front of it. Frames needing a session or a
/// HostHello the server does not have degrade into junk, so any sequence of
/// steps is a valid script.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum Step {
    /// The client runs a handshake.
    Handshake,
    /// The client sends a request tagged by the byte.
    Send(u8),
    /// The client reads the next message.
    Recv,
    /// A valid ArkHello answering the latest HostHello. Junk if there was none.
    Hello,
    /// An ArkHello sealed to a key the client never had. Junk if there was no
    /// hello to bind it to.
    HelloStale,
    /// An ArkHello for the latest HostHello with a flipped ciphertext byte.
    /// Junk if there was no hello.
    HelloTampered,
    /// An ArkHello for the latest HostHello bound to another client's keys, as
    /// one substituted by a man in the middle would be. Junk if there was no
    /// hello.
    HelloBadAuth,
    /// An ArkHello for the latest HostHello signed by a key other than the
    /// Server's identity. Junk if there was no hello.
    HelloBadSigner,
    /// An ArkHello for the latest HostHello whose sealed payload is not an
    /// ArkHello at all. Junk if there was no hello.
    HelloBadPayload,
    /// An ArkHello for the latest HostHello carrying an encryption key that
    /// fails validation. Junk if there was no hello.
    HelloBadKey,
    /// An ArkHello for the latest HostHello with an encapsulated key of the
    /// wrong size. Junk if there was no hello.
    HelloBadEncap,
    /// An ArkHello for the latest HostHello carrying a well formed attestation
    /// of the wrong shape, a cloud one. Junk if there was no hello.
    HelloBadAttest,
    /// A sealed reply tagged by the byte. Junk without a session.
    Reply(u8),
    /// The last sealed reply, repeated. Nothing if none was sent yet.
    ReplyReplay,
    /// A sealed reply with a flipped ciphertext byte. Junk without a session.
    ReplyTampered,
    /// A sealed packet that is not a protobuf message. Junk without a session.
    Garbage,
    /// The empty frame signaling a dropped session.
    Dropped,
    /// The bytes COBS encoded into a frame, decodable but meaningless.
    Junk(Vec<u8>),
    /// A frame failing COBS decoding.
    Undecodable,
    /// The last valid frame produced cut short, keeping at least one byte.
    /// Nothing if none was produced yet.
    Truncated(u8),
    /// A valid ArkHello without its delimiter. The next frame's bytes merge
    /// into it, a lone delimiter completing it into the valid hello it is.
    Partial,
    /// A frame past the size limit, delimiter included. The framing throws it
    /// away before the client sees it, a partial ArkHello in front going with
    /// it.
    Oversized,
    /// The read fails with `WouldBlock`.
    Yield,
    /// The read fails with `Interrupted`, which the framing retries with the
    /// client none the wiser.
    Interrupt,
    /// The client's writes fail from here on, as on a transport that died.
    Break,
    /// The client's writes work again.
    Heal,
    /// The client's next write the point applies to is cut there, the transport
    /// staying broken afterwards if told to, until healed.
    Cut { point: CutPoint, then_broken: bool },
    /// Caps what a single read hands the client at the byte count, so frames
    /// arrive in pieces. Zero lifts the cap.
    Chunk(u8),
    /// Hands the next frames to the client in one read, up to the count. The
    /// frame settling the call in progress ends the batch early, the client
    /// acting on it before reading on, as does any step not queuing a frame.
    Batch(u8),
}

impl Step {
    /// Whether the step is a call into the client rather than a server frame.
    fn is_call(&self) -> bool {
        matches!(self, Step::Handshake | Step::Send(_) | Step::Recv)
    }

    /// Whether the step only puts a frame in front of the client, as opposed to
    /// a call, a yield or a change to the transport.
    fn queues_frame(&self) -> bool {
        !matches!(
            self,
            Step::Handshake
                | Step::Send(_)
                | Step::Recv
                | Step::Yield
                | Step::Interrupt
                | Step::Break
                | Step::Heal
                | Step::Cut { .. }
                | Step::Chunk(_)
                | Step::Batch(_)
        )
    }
}

/// Fuzz target driving the real client through this mock's scripts, which
/// seed its corpus. Keep it in step with the binary in fuzz/Cargo.toml, the
/// seeds make target checks that every target listed there gets seeds.
#[cfg(feature = "fuzz")]
pub const FUZZ_TARGET: &str = "client-protocol";

#[cfg(feature = "fuzz")]
impl super::Seedable for Step {
    fn seed(&self, seed: &mut super::Seed) {
        const COUNT: u32 = 29;
        match self {
            Step::Handshake => seed.variant(0, COUNT),
            Step::Send(tag) => {
                seed.variant(1, COUNT);
                seed.byte(*tag);
            }
            Step::Recv => seed.variant(2, COUNT),
            Step::Hello => seed.variant(3, COUNT),
            Step::HelloStale => seed.variant(4, COUNT),
            Step::HelloTampered => seed.variant(5, COUNT),
            Step::HelloBadAuth => seed.variant(6, COUNT),
            Step::HelloBadSigner => seed.variant(7, COUNT),
            Step::HelloBadPayload => seed.variant(8, COUNT),
            Step::HelloBadKey => seed.variant(9, COUNT),
            Step::HelloBadEncap => seed.variant(10, COUNT),
            Step::HelloBadAttest => seed.variant(11, COUNT),
            Step::Reply(tag) => {
                seed.variant(12, COUNT);
                seed.byte(*tag);
            }
            Step::ReplyReplay => seed.variant(13, COUNT),
            Step::ReplyTampered => seed.variant(14, COUNT),
            Step::Garbage => seed.variant(15, COUNT),
            Step::Dropped => seed.variant(16, COUNT),
            Step::Junk(bytes) => {
                seed.variant(17, COUNT);
                seed.bytes(bytes);
            }
            Step::Undecodable => seed.variant(18, COUNT),
            Step::Truncated(n) => {
                seed.variant(19, COUNT);
                seed.byte(*n);
            }
            Step::Partial => seed.variant(20, COUNT),
            Step::Oversized => seed.variant(21, COUNT),
            Step::Yield => seed.variant(22, COUNT),
            Step::Interrupt => seed.variant(23, COUNT),
            Step::Break => seed.variant(24, COUNT),
            Step::Heal => seed.variant(25, COUNT),
            Step::Cut { point, then_broken } => {
                seed.variant(26, COUNT);
                point.seed(seed);
                seed.flag(*then_broken);
            }
            Step::Chunk(n) => {
                seed.variant(27, COUNT);
                seed.byte(*n);
            }
            Step::Batch(n) => {
                seed.variant(28, COUNT);
                seed.byte(*n);
            }
        }
    }
}

/// Error kinds the model distinguishes in the client's results.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `Error::PacketDecodingFailed`, a packet opening but not decoding.
    PacketDecoding,
    /// `Error::FrameDecodingFailed`, a frame failing COBS decoding.
    FrameDecoding,
    /// `Error::SendFailed`, the transport refusing a write.
    Send,
    /// `Error::RecvFailed`, the transport failing a read.
    Recv,
    /// `Error::Terminated`, the transport ending.
    Terminated,
    /// `Error::SessionReset`, the server signaling that it has no session.
    SessionReset,
    /// `Error::InvalidAttestation`, an attestation of the wrong shape.
    InvalidAttestation,
    /// `Error::HandshakeFailed`, a handshake refused or given up on.
    Handshake,
    /// `Error::EncryptionFailed`, a packet failing to open or no session to
    /// send in.
    Encryption,
}

/// Counts of what a run observed, for scenario tests to assert on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub established: bool, // Whether the client ended up with a session
    pub handshakes: usize, // Handshakes that succeeded
    pub messages: usize,   // Messages the client read
    pub resets: usize,     // Session resets the client surfaced
    pub failures: usize,   // Other errors the client surfaced
    pub reads: usize,      // Reads that handed the client bytes
}

/// What is wrong with an ArkHello crafted to be refused, in the order the
/// client finds them. A stale one is not refused but skipped, answering no
/// hello of the client's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flaw {
    /// Nothing, a valid ArkHello.
    None,
    /// Sealed to a key the client never had.
    Stale,
    /// A ciphertext byte flipped, the seal failing to open.
    Tampered,
    /// Bound to another client's keys, as a substituted hello would be.
    Auth,
    /// Signed by a key other than the server's identity.
    Signer,
    /// A sealed payload that is not an ArkHello at all.
    Payload,
    /// An encryption key failing validation.
    Key,
    /// An encapsulated key of the wrong size.
    Encap,
    /// A well formed attestation of the wrong shape.
    Attest,
}

/// A frame put in front of the client, as the model sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Frame {
    /// An ArkHello answering the hello of the generation, flawed or not.
    ArkHello { generation: u64, flaw: Flaw },
    /// A packet sealed in the server's session with the sequence number.
    Sealed {
        session: u64,
        seq: u64,
        tag: u8,
        garbage: bool,
    },
    /// The empty frame.
    Dropped,
    /// A decodable frame meaning nothing.
    Junk,
    /// A frame failing COBS decoding.
    Undecodable,
}

/// Bytes of an unterminated frame in front of the client, waiting for the
/// delimiter that completes them into a frame.
enum Partial {
    /// The stream is at a frame boundary.
    None,
    /// An ArkHello answering the hello of the generation, lacking only its
    /// delimiter, valid if the next byte is one.
    Hello(u64, Vec<u8>),
    /// Bytes no delimiter can complete into anything valid.
    Junk(Vec<u8>),
}

/// Call in progress on the client, consuming the frames read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Call {
    /// No call in progress, a frame read now being a bug.
    None,
    /// A handshake awaiting the ArkHello of the generation, having skipped
    /// the count of stale frames so far.
    Handshake { generation: u64, stale: usize },
    /// A read of the next message.
    Recv,
}

/// Predicted result of a client call, the message id for a read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expect {
    /// The call succeeds, with the message id if it was a read.
    Ok(Option<u64>),
    /// The call fails with the error kind.
    Err(Kind),
}

/// ArkHello handed out, awaiting the client's ack.
struct Outstanding {
    generation: u64,
    crypto: xhpke::SecretKey,
    sender: xhpke::Sender,
    host_signer: xdsa::PublicKey,
}

/// Session on the mock server's side.
struct ServerSession {
    id: u64, // Generation of the hello it answered
    sender: xhpke::Sender,
    receiver: xhpke::Receiver,
    seq: u64, // Packets sealed so far
}

/// Mock server along with the model of the client it drives.
pub struct Server {
    steps: VecDeque<Step>,
    identity: xdsa::SecretKey,
    attestation: Attestation,
    outbox: Outbox,                            // Frames the client wrote
    queue: VecDeque<(Vec<u8>, Option<Frame>)>, // Bytes produced, not yet read by the client, unterminated ones without a frame
    bytes: Vec<u8>,                            // Bytes of the frame being handed over
    chunk: usize,                              // Most bytes a read hands over, zero for all
    batch: usize,                              // Frames left to hand to the client in one read
    broken: bool,                              // Whether the client's writes fail
    cut: Option<CutPoint>, // Cut armed for the next write of the client it applies to
    fragment: bool,        // Whether a frame cut in the middle awaits its terminator
    partial: Partial,      // Unterminated frame in front of the client

    call: Call,                  // Call the frames read feed into
    expect: Option<Expect>,      // Its predicted result once settled
    client_session: Option<u64>, // Generation of the client's live session
    client_seq: u64,             // Packets the client opened in it

    generation: u64, // Hellos parsed from the outbox
    latest_hello: Option<(xdsa::PublicKey, xhpke::PublicKey)>, // Keys of the last one
    outstanding: Vec<Outstanding>, // ArkHellos awaiting an ack
    session: Option<ServerSession>, // Live session on the server's side
    last_reply: Option<(Vec<u8>, Frame)>, // Last sealed reply, framed
    last_valid: Option<Vec<u8>>, // Last valid frame produced, delimiter stripped

    summary: Summary,
}

impl Server {
    fn new(steps: &[Step], outbox: Outbox) -> Self {
        let identity = xdsa::SecretKey::generate();
        let attestation = self_attestation(&identity);
        Self {
            steps: steps.iter().take(MAX_STEPS).cloned().collect(),
            identity,
            attestation,
            outbox,
            queue: VecDeque::new(),
            bytes: Vec::new(),
            chunk: 0,
            batch: 0,
            broken: false,
            cut: None,
            fragment: false,
            partial: Partial::None,
            call: Call::None,
            expect: None,
            client_session: None,
            client_seq: 0,
            generation: 0,
            latest_hello: None,
            outstanding: Vec::new(),
            session: None,
            last_reply: None,
            last_valid: None,
            summary: Summary::default(),
        }
    }

    /// Executes one server step, queuing the frame it produces in front of the
    /// client. The client's writes are taken in first, an ArkHello answering the
    /// latest hello and a reply sealing in the session the latest ack opened.
    fn execute(&mut self, step: Step) {
        self.ingest();
        let produced = match step {
            Step::Hello => self.ark_hello(Flaw::None),
            Step::HelloStale => self.ark_hello(Flaw::Stale),
            Step::HelloTampered => self.ark_hello(Flaw::Tampered),
            Step::HelloBadAuth => self.ark_hello(Flaw::Auth),
            Step::HelloBadSigner => self.ark_hello(Flaw::Signer),
            Step::HelloBadPayload => self.ark_hello(Flaw::Payload),
            Step::HelloBadKey => self.ark_hello(Flaw::Key),
            Step::HelloBadEncap => self.ark_hello(Flaw::Encap),
            Step::HelloBadAttest => self.ark_hello(Flaw::Attest),
            Step::Reply(tag) => self.reply(Some(tag)),
            Step::ReplyReplay => match self.last_reply.clone() {
                Some(replay) => replay,
                None => return,
            },
            Step::ReplyTampered => self.tampered_reply(),
            Step::Garbage => self.reply(None),
            Step::Dropped => (vec![0x00], Frame::Dropped),
            Step::Junk(bytes) => (frame(&bytes), Frame::Junk),
            Step::Undecodable => (vec![0xff, 0x01, 0x00], Frame::Undecodable),
            Step::Truncated(n) => match self.last_valid.clone() {
                Some(valid) => {
                    let keep = match valid.len() {
                        0..=1 => 1,
                        len => 1 + n as usize % (len - 1),
                    };
                    let mut bytes = valid[..keep].to_vec();
                    bytes.push(0x00);
                    (bytes, classify(&valid[..keep]))
                }
                None => return,
            },
            Step::Partial => {
                let (mut bytes, frame) = self.ark_hello(Flaw::None);
                bytes.pop();
                self.partial = match std::mem::replace(&mut self.partial, Partial::None) {
                    Partial::None => match frame {
                        Frame::ArkHello { generation, .. } => {
                            Partial::Hello(generation, bytes.clone())
                        }
                        _ => Partial::Junk(bytes.clone()),
                    },
                    Partial::Hello(_, mut prior) | Partial::Junk(mut prior) => {
                        prior.extend_from_slice(&bytes);
                        Partial::Junk(prior)
                    }
                };
                self.queue.push_back((bytes, None));
                return;
            }
            Step::Oversized => {
                self.partial = Partial::None;
                let mut bytes = vec![1u8; MAX_FRAME_SIZE + 1];
                bytes.push(0x00);
                self.queue.push_back((bytes, None));
                return;
            }
            Step::Break => {
                self.set_broken(true);
                return;
            }
            Step::Heal => {
                self.set_broken(false);
                return;
            }
            Step::Cut { point, then_broken } => {
                self.cut = Some(point);
                self.outbox.set_cut(point);
                if then_broken {
                    self.set_broken(true);
                }
                return;
            }
            Step::Chunk(n) => {
                self.chunk = n as usize;
                return;
            }
            Step::Batch(n) => {
                self.batch = n as usize;
                return;
            }
            Step::Handshake | Step::Send(_) | Step::Recv | Step::Yield | Step::Interrupt => {
                unreachable!(
                    "calls, yields and interrupts are handled by the driver and the reader"
                )
            }
        };
        // An unterminated frame in front of the client swallows the one
        // produced, a lone delimiter completing a partial hello into the valid
        // one and anything else merging into junk, decodable or not
        let (bytes, frame) = produced;
        let frame = match std::mem::replace(&mut self.partial, Partial::None) {
            Partial::None => frame,
            Partial::Hello(generation, _) if frame == Frame::Dropped => Frame::ArkHello {
                generation,
                flaw: Flaw::None,
            },
            Partial::Hello(_, prior) | Partial::Junk(prior) => {
                let mut merged = prior;
                merged.extend_from_slice(&bytes[..bytes.len() - 1]);
                classify(&merged)
            }
        };
        self.queue.push_back((bytes, Some(frame)));
    }

    /// An ArkHello answering the latest HostHello, flawed as requested.
    fn ark_hello(&mut self, flaw: Flaw) -> (Vec<u8>, Frame) {
        let Some((host_signer, host_crypto)) = self.latest_hello.clone() else {
            return self.junk(b"server hello without a client hello");
        };
        let crypto = xhpke::SecretKey::generate();
        let (sender, encap) = host_crypto
            .new_sender(CRYPTO_DOMAIN_WIRE_ARK_TO_HOST)
            .unwrap();

        let payload = handshake::ArkHello {
            ark_attest: match flaw {
                Flaw::Attest => cloud_attestation(&self.identity),
                _ => self.attestation.as_bytes().to_vec(),
            },
            ark_crypto: crypto.public_key(),
            a2h_encap: match flaw {
                Flaw::Encap => vec![0x42; 3],
                _ => encap.to_vec(),
            },
        };
        let auth = handshake::ArkHelloAuth {
            host_signer: match flaw {
                Flaw::Auth => xdsa::SecretKey::generate().public_key(),
                _ => host_signer.clone(),
            },
            host_crypto: host_crypto.clone(),
        };
        let stranger_signer = xdsa::SecretKey::generate();
        let signer = match flaw {
            Flaw::Signer => &stranger_signer,
            _ => &self.identity,
        };
        let stranger_crypto = xhpke::SecretKey::generate().public_key();
        let recipient = match flaw {
            Flaw::Stale => &stranger_crypto,
            _ => &host_crypto,
        };
        let mut sealed = match flaw {
            Flaw::Payload => cose::seal(
                &handshake::HostAck {
                    h2a_encap: vec![1, 2, 3],
                },
                &auth,
                signer,
                recipient,
                CRYPTO_DOMAIN_WIRE,
            ),
            Flaw::Key => cose::seal(
                &(
                    self.attestation.as_bytes().to_vec(),
                    vec![0xffu8; xhpke::PUBLIC_KEY_SIZE],
                    encap.to_vec(),
                ),
                &auth,
                signer,
                recipient,
                CRYPTO_DOMAIN_WIRE,
            ),
            _ => cose::seal(&payload, &auth, signer, recipient, CRYPTO_DOMAIN_WIRE),
        }
        .unwrap();
        if flaw == Flaw::Tampered {
            *sealed.last_mut().unwrap() ^= 0xff;
        }

        // A stale hello answers nobody, everything else the latest generation
        let generation = match flaw {
            Flaw::Stale => 0,
            _ => self.generation,
        };
        if flaw == Flaw::None {
            self.outstanding.push(Outstanding {
                generation,
                crypto,
                sender,
                host_signer,
            });
        }
        let framed = frame(&sealed);
        if flaw == Flaw::None {
            self.record(&framed);
        }
        (framed, Frame::ArkHello { generation, flaw })
    }

    /// A packet sealed in the server's session, a tagged reply or garbage.
    fn reply(&mut self, tag: Option<u8>) -> (Vec<u8>, Frame) {
        let Some(session) = self.session.as_mut() else {
            return self.junk(b"reply without a session");
        };
        let plaintext = match tag {
            Some(tag) => ArkToHost {
                id: Some(tag as u64),
                err: None,
                content: None,
            }
            .encode_to_vec(),
            None => vec![0x07],
        };
        let packet = session.sender.seal(&plaintext, &[]).unwrap();
        let sealed = Frame::Sealed {
            session: session.id,
            seq: session.seq,
            tag: tag.unwrap_or_default(),
            garbage: tag.is_none(),
        };
        session.seq += 1;

        let produced = (frame(&packet), sealed);
        self.record(&produced.0);
        self.last_reply = Some(produced.clone());
        produced
    }

    /// Remembers the frame as the last valid one, for truncating later.
    fn record(&mut self, framed: &[u8]) {
        self.last_valid = Some(framed[..framed.len() - 1].to_vec());
    }

    /// A reply sealed in the server's session with a flipped ciphertext byte,
    /// meaning nothing to the client anymore.
    fn tampered_reply(&mut self) -> (Vec<u8>, Frame) {
        let Some(session) = self.session.as_mut() else {
            return self.junk(b"tampered reply without a session");
        };
        let plaintext = ArkToHost {
            id: Some(0),
            err: None,
            content: None,
        }
        .encode_to_vec();
        let mut packet = session.sender.seal(&plaintext, &[]).unwrap();
        session.seq += 1;
        *packet.last_mut().unwrap() ^= 0xff;
        (frame(&packet), Frame::Junk)
    }

    /// A valid COBS frame of meaningless content.
    fn junk(&self, text: &[u8]) -> (Vec<u8>, Frame) {
        (frame(text), Frame::Junk)
    }

    /// Makes the client's writes fail, or work again.
    fn set_broken(&mut self, broken: bool) {
        self.outbox.set_broken(broken);
        self.broken = broken;
    }

    /// Parses everything the client wrote since the last look, tracking its
    /// hellos, acks and requests on the server's side of the model.
    fn ingest(&mut self) {
        for framed in self.outbox.take_frames() {
            // Client resets carry nothing to track
            if framed.is_empty() {
                continue;
            }
            // The frame a failed send left cut short, terminated by the reset
            // of the handshake after it, means nothing
            if std::mem::take(&mut self.fragment) {
                continue;
            }
            let packet = unframe(&framed);
            if let Ok(hello) = cbor::decode::<handshake::HostHello>(&packet) {
                self.generation += 1;
                self.latest_hello = Some((hello.host_signer, hello.host_crypto));
                continue;
            }
            if self.ack(&packet) {
                continue;
            }
            if let Some(session) = self.session.as_mut()
                && let Ok(plain) = session.receiver.open(&packet, &[])
            {
                HostToArk::decode(&plain[..]).expect("client request undecodable");
                continue;
            }
            panic!(
                "client wrote a frame the server cannot interpret ({} bytes)",
                packet.len()
            );
        }
    }

    /// Opens a client ack against the outstanding ArkHellos, establishing the
    /// session of the one it answers.
    fn ack(&mut self, packet: &[u8]) -> bool {
        for i in (0..self.outstanding.len()).rev() {
            let out = &self.outstanding[i];
            let auth = handshake::HostAckAuth {
                ark_signer: self.identity.public_key(),
                ark_crypto: out.crypto.public_key(),
            };
            let Ok(ack) = cose::open::<handshake::HostAck, _>(
                packet,
                &auth,
                &out.crypto,
                &out.host_signer,
                CRYPTO_DOMAIN_WIRE,
                None,
            ) else {
                continue;
            };
            let encap: [u8; xhpke::ENCAP_KEY_SIZE] = ack
                .h2a_encap
                .try_into()
                .expect("client ack encap size invalid");
            let receiver = out
                .crypto
                .new_receiver(&encap, CRYPTO_DOMAIN_WIRE_HOST_TO_ARK)
                .unwrap();
            let out = self.outstanding.remove(i);
            self.session = Some(ServerSession {
                id: out.generation,
                sender: out.sender,
                receiver,
                seq: 0,
            });
            return true;
        }
        false
    }

    /// Applies the model's transition for a frame the client reads, settling
    /// the call in progress once the frame decides its result.
    fn consume(&mut self, frame: Frame) {
        match self.call {
            Call::Handshake { generation, stale } => {
                let result = match frame {
                    Frame::ArkHello {
                        generation: answered,
                        flaw,
                    } if answered == generation => match flaw {
                        // The ack fails to get out on a broken transport, or
                        // on one cutting it
                        Flaw::None if self.broken || self.cut.is_some() => {
                            self.apply_cut();
                            Expect::Err(Kind::Send)
                        }
                        Flaw::None => Expect::Ok(None),
                        Flaw::Tampered
                        | Flaw::Auth
                        | Flaw::Signer
                        | Flaw::Payload
                        | Flaw::Key
                        | Flaw::Encap => Expect::Err(Kind::Handshake),
                        Flaw::Attest => Expect::Err(Kind::InvalidAttestation),
                        Flaw::Stale => unreachable!("stale hellos answer no generation"),
                    },
                    // Anything else is skipped as stale, up to the bound
                    _ => {
                        if stale < MAX_STALE_FRAMES {
                            self.call = Call::Handshake {
                                generation,
                                stale: stale + 1,
                            };
                            return;
                        }
                        Expect::Err(Kind::Handshake)
                    }
                };
                if result == Expect::Ok(None) {
                    self.client_session = Some(generation);
                    self.client_seq = 0;
                }
                self.settle(result);
            }
            Call::Recv => {
                let result = match (self.client_session, frame) {
                    (_, Frame::Dropped) => {
                        self.client_session = None;
                        Expect::Err(Kind::SessionReset)
                    }
                    (_, Frame::Undecodable) => {
                        self.client_session = None;
                        Expect::Err(Kind::FrameDecoding)
                    }
                    // The session check comes after the read
                    (None, _) => Expect::Err(Kind::Encryption),
                    (
                        Some(id),
                        Frame::Sealed {
                            session,
                            seq,
                            tag,
                            garbage,
                        },
                    ) if session == id && seq == self.client_seq => {
                        self.client_seq += 1;
                        if garbage {
                            Expect::Err(Kind::PacketDecoding)
                        } else {
                            Expect::Ok(Some(tag as u64))
                        }
                    }
                    // Anything the session cannot open ends it
                    (Some(_), _) => {
                        self.client_session = None;
                        Expect::Err(Kind::Encryption)
                    }
                };
                self.settle(result);
            }
            Call::None => panic!("client read a frame outside a call"),
        }
    }

    /// Consumes the armed cut for the client's next write with a body, one cut
    /// in the middle leaving junk behind for the next reset to terminate. The
    /// other points leave nothing, or a frame the server takes as it is.
    fn apply_cut(&mut self) {
        if let Some(CutPoint::Middle(_)) = self.cut.take() {
            self.fragment = true;
        }
    }

    /// Applies a read failing, which ends the call in progress with the
    /// error, a session not surviving it on the client's side.
    fn interrupt(&mut self, kind: Kind) {
        match self.call {
            Call::Handshake { .. } => self.settle(Expect::Err(kind)),
            Call::Recv => {
                self.client_session = None;
                self.settle(Expect::Err(kind));
            }
            Call::None => panic!("client read outside a call"),
        }
    }

    /// Records the predicted result of the call in progress.
    fn settle(&mut self, result: Expect) {
        assert!(self.expect.is_none(), "call settled twice");
        self.expect = Some(result);
        self.call = Call::None;
    }

    /// Checks a finished call against the model's prediction and takes in
    /// whatever the client wrote during it.
    fn finish(&mut self, result: Result<Option<u64>, Kind>) {
        let expected = self
            .expect
            .take()
            .expect("call returned before the model settled it");
        let actual = match result {
            Ok(id) => Expect::Ok(id),
            Err(kind) => Expect::Err(kind),
        };
        assert_eq!(actual, expected);
        self.call = Call::None;
        self.ingest();
    }

    /// Moves the script forward to the next call into the client, executing the
    /// Server steps before it. Their frames queue up in front of the client, yields
    /// and interrupts outside a read mean nothing.
    fn next_call(&mut self) -> Option<Step> {
        loop {
            match self.steps.pop_front() {
                None => return None,
                Some(step) if step.is_call() => return Some(step),
                Some(Step::Yield) | Some(Step::Interrupt) => {}
                Some(step) => self.execute(step),
            }
        }
    }
}

/// Read half handed to the client, pulling the script forward as the client reads.
struct Feed(Rc<RefCell<Server>>);

impl Read for Feed {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut server = self.0.borrow_mut();
        loop {
            // Hand over the frames in progress, in pieces if capped
            if !server.bytes.is_empty() {
                let mut n = buf.len().min(server.bytes.len());
                if server.chunk > 0 {
                    n = n.min(server.chunk);
                }
                buf[..n].copy_from_slice(&server.bytes[..n]);
                server.bytes.drain(..n);
                server.summary.reads += 1;
                return Ok(n);
            }
            // Start on the next frame queued, the model consuming it whole,
            // unterminated bytes carrying no frame to consume yet. A batch
            // appends the frames after it, the script moved forward for them
            // while it yields frames, until one settles the call
            if let Some((bytes, frame)) = server.queue.pop_front() {
                if let Some(frame) = frame {
                    server.consume(frame);
                }
                server.bytes = bytes;
                while server.batch > 1 && server.expect.is_none() {
                    if server.queue.is_empty() {
                        match server.steps.front() {
                            Some(step) if step.queues_frame() => {
                                let step = server.steps.pop_front().unwrap();
                                server.execute(step);
                                continue;
                            }
                            _ => break,
                        }
                    }
                    let (bytes, frame) = server.queue.pop_front().unwrap();
                    if let Some(frame) = frame {
                        server.consume(frame);
                        server.batch -= 1;
                    }
                    server.bytes.extend(bytes);
                }
                server.batch = 0;
                continue;
            }
            // Move the script forward until a frame is queued, a call or a
            // yield failing the read instead
            match server.steps.front() {
                None => {
                    server.interrupt(Kind::Terminated);
                    return Ok(0);
                }
                Some(step) if step.is_call() => {
                    server.interrupt(Kind::Recv);
                    return Err(would_block());
                }
                Some(Step::Yield) => {
                    server.steps.pop_front();
                    server.interrupt(Kind::Recv);
                    return Err(would_block());
                }
                Some(Step::Interrupt) => {
                    server.steps.pop_front();
                    return Err(io::ErrorKind::Interrupted.into());
                }
                Some(_) => {
                    let step = server.steps.pop_front().unwrap();
                    server.execute(step);
                }
            }
        }
    }
}

/// The client under test, reading the script and writing into the outbox.
type Client = crate::Client<Feed, Outbox>;

/// The frame the bytes of a frame cut short or merged with another make,
/// junk if they still decode and undecodable if not, neither meaning
/// anything to the client.
fn classify(bytes: &[u8]) -> Frame {
    let mut buf = vec![0u8; cobs::decode_buffer(bytes.len())];
    match cobs::decode(bytes, &mut buf) {
        Ok(_) => Frame::Junk,
        Err(_) => Frame::Undecodable,
    }
}

/// Maps a client error onto the kind the model predicts.
fn kind(err: Error) -> Kind {
    match err {
        Error::PacketDecodingFailed(_) => Kind::PacketDecoding,
        Error::FrameDecodingFailed(_) => Kind::FrameDecoding,
        Error::SendFailed(_) => Kind::Send,
        Error::RecvFailed(_) => Kind::Recv,
        Error::Terminated => Kind::Terminated,
        Error::SessionReset => Kind::SessionReset,
        Error::InvalidAttestation => Kind::InvalidAttestation,
        Error::HandshakeFailed(_) => Kind::Handshake,
        Error::EncryptionFailed(_) => Kind::Encryption,
        err => panic!("unexpected error from the client: {err}"),
    }
}

/// Checks that the client has a session exactly when the model says so. An
/// oversized message is refused before sealing, so it probes the session
/// without any frame going out.
fn check_session(client: &mut Client, established: bool) {
    let oversized = vec![0x42; MAX_MESSAGE_SIZE + 1];
    let refused = client.send_message(HostToArk {
        id: Some(PROBE_ID),
        content: Some(host_to_ark::Content::Develop(oversized)),
    });
    match refused {
        Err(Error::PacketTooLarge(_)) => {
            assert!(established, "client has a session the model does not")
        }
        Err(Error::EncryptionFailed(_)) => {
            assert!(!established, "client lacks the session the model has")
        }
        other => panic!("unexpected oversized send result: {other:?}"),
    }
}

/// Runs a script against a real client, panicking on any divergence from the
/// model, and reports what the run observed.
pub fn run(steps: &[Step]) -> Summary {
    #[cfg(feature = "fuzz")]
    super::seed(FUZZ_TARGET, steps);

    let outbox = Outbox::default();
    let server = Rc::new(RefCell::new(Server::new(steps, outbox.clone())));
    let identity = server.borrow().identity.public_key();
    let mut client = Client::new(Feed(server.clone()), outbox);

    loop {
        let call = server.borrow_mut().next_call();
        let Some(call) = call else { break };

        match call {
            Step::Handshake => {
                // On a broken transport not even the reset gets out, and a cut
                // takes the reset or the hello, the client failing before reading
                // anything either way
                let failing = {
                    let server = server.borrow();
                    server.broken || server.cut.is_some()
                };
                if failing {
                    let result = client.handshake(&identity).map(|_| ());
                    assert!(matches!(result, Err(Error::SendFailed(_))), "{result:?}");
                    let mut server = server.borrow_mut();
                    server.client_session = None;
                    server.summary.failures += 1;
                    server.apply_cut();
                    continue;
                }
                {
                    let mut server = server.borrow_mut();
                    server.client_session = None;
                    server.call = Call::Handshake {
                        generation: server.generation + 1,
                        stale: 0,
                    };
                }
                let result = client.handshake(&identity).map(|_| None).map_err(kind);
                let mut server = server.borrow_mut();
                match result {
                    Ok(_) => server.summary.handshakes += 1,
                    Err(_) => server.summary.failures += 1,
                }
                server.finish(result);
            }
            Step::Send(tag) => {
                let established = server.borrow().client_session.is_some();
                check_session(&mut client, established);

                // A failed send takes the session down with it, a cut firing
                // ahead of a broken transport
                let expected: Result<Option<u64>, Kind> = {
                    let mut server = server.borrow_mut();
                    match (established, server.broken || server.cut.is_some()) {
                        (true, false) => Ok(None),
                        (true, true) => {
                            server.client_session = None;
                            server.apply_cut();
                            Err(Kind::Send)
                        }
                        (false, _) => Err(Kind::Encryption),
                    }
                };
                let result = client
                    .send_message(HostToArk {
                        id: Some(tag as u64),
                        content: None,
                    })
                    .map(|_| None)
                    .map_err(kind);
                assert_eq!(result, expected);
                server.borrow_mut().ingest();
            }
            Step::Recv => {
                server.borrow_mut().call = Call::Recv;
                let result = client.next_message().map(|msg| msg.id).map_err(kind);
                let mut server = server.borrow_mut();
                match result {
                    Ok(_) => server.summary.messages += 1,
                    Err(Kind::SessionReset) => server.summary.resets += 1,
                    Err(_) => server.summary.failures += 1,
                }
                server.finish(result);
            }
            _ => unreachable!("only calls reach the driver"),
        }
    }
    let mut server = server.borrow_mut();
    server.ingest();
    check_session(&mut client, server.client_session.is_some());
    server.summary.established = server.client_session.is_some();
    server.summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;

    /// Runs a script with logging enabled.
    fn run_logged(steps: &[Step]) -> Summary {
        testing::init_tracing();
        run(steps)
    }

    // Tests the happy path of the state machine, a handshake followed by
    // requests and replies through the session, one at a time and pipelined.
    #[test]
    fn test_scripted_round_trip() {
        let summary = run_logged(&[
            Step::Handshake,
            Step::Hello,
            Step::Send(1),
            Step::Reply(1),
            Step::Recv,
            Step::Send(2),
            Step::Send(3),
            Step::Reply(2),
            Step::Reply(3),
            Step::Recv,
            Step::Recv,
        ]);
        assert_eq!(
            summary,
            Summary {
                established: true,
                handshakes: 1,
                messages: 3,
                resets: 0,
                failures: 0,
                reads: 4,
            }
        );
    }

    // Tests that flawed hellos fail the handshake once found, each with its
    // own error, leaving the client without a session. That is a hello tampered
    // with, bound or signed wrongly, malformed, carrying a bad key or
    // encapsulation, or an attestation of the wrong shape.
    #[test]
    fn test_scripted_flawed_hellos() {
        for flaw in [
            Step::HelloTampered,
            Step::HelloBadAuth,
            Step::HelloBadSigner,
            Step::HelloBadPayload,
            Step::HelloBadKey,
            Step::HelloBadEncap,
            Step::HelloBadAttest,
        ] {
            let summary = run_logged(&[Step::Handshake, flaw.clone(), Step::Send(1)]);
            assert!(!summary.established, "{flaw:?}");
            assert_eq!(summary.failures, 1, "{flaw:?}");

            // Without a hello to answer the frame is plain junk
            let summary = run_logged(&[flaw.clone(), Step::Recv]);
            assert!(!summary.established, "{flaw:?}");
            assert_eq!(summary.failures, 1, "{flaw:?}");
        }
    }

    // Tests that frames not meant for the handshake in progress are skipped
    // as stale, up to the bound.
    #[test]
    fn test_scripted_stale_skipping() {
        let summary = run_logged(&[
            Step::Dropped,
            Step::Junk(vec![1, 2, 3]),
            Step::Handshake,
            Step::HelloStale,
            Step::Dropped,
            Step::Junk(vec![]),
            Step::Hello,
        ]);
        assert!(summary.established);
        assert_eq!(summary.failures, 0);

        // A reply left unread from the previous session is stale too
        let summary = run_logged(&[
            Step::Handshake,
            Step::Hello,
            Step::Send(1),
            Step::Reply(1),
            Step::Handshake,
            Step::Hello,
            Step::Send(2),
            Step::Reply(2),
            Step::Recv,
        ]);
        assert_eq!(summary.handshakes, 2);
        assert_eq!(summary.messages, 1);
        assert_eq!(summary.failures, 0);

        // An old ArkHello left over from a completed handshake is stale too
        let summary = run_logged(&[
            Step::Handshake,
            Step::Hello,
            Step::Hello,
            Step::Handshake,
            Step::Hello,
        ]);
        assert_eq!(summary.handshakes, 2);
        assert!(summary.established);

        let mut steps = vec![Step::Handshake];
        steps.extend(std::iter::repeat_n(Step::Dropped, MAX_STALE_FRAMES));
        steps.push(Step::Hello);
        let summary = run_logged(&steps);
        assert!(summary.established);

        let mut steps = vec![Step::Handshake];
        steps.extend(std::iter::repeat_n(Step::Dropped, MAX_STALE_FRAMES + 1));
        steps.push(Step::Hello);
        let summary = run_logged(&steps);
        assert!(!summary.established);
        assert_eq!(summary.failures, 1);

        // A frame failing to decode, the leftover of a transfer cut short, is
        // stale like any other
        let summary = run_logged(&[Step::Handshake, Step::Undecodable, Step::Hello]);
        assert!(summary.established);
        assert_eq!(summary.failures, 0);
    }

    // Tests that a read failing and the transport ending both abort a
    // handshake with their own errors.
    #[test]
    fn test_scripted_handshake_interrupted() {
        let summary = run_logged(&[Step::Handshake, Step::Yield, Step::Send(1)]);
        assert!(!summary.established);
        assert_eq!(summary.failures, 1);

        let summary = run_logged(&[Step::Handshake]);
        assert!(!summary.established);
        assert_eq!(summary.failures, 1);
    }

    // Tests that a packet decrypting into something that is not a message
    // surfaces as an error but leaves the session usable.
    #[test]
    fn test_scripted_garbage_keeps_session() {
        let summary = run_logged(&[
            Step::Handshake,
            Step::Hello,
            Step::Garbage,
            Step::Recv,
            Step::Reply(2),
            Step::Recv,
        ]);
        assert!(summary.established);
        assert_eq!(summary.messages, 1);
        assert_eq!(summary.failures, 1);
    }

    // Tests that packets the session cannot open drop it. That is a replayed
    // reply, one from an earlier session, a tampered one, junk, a leftover
    // ArkHello and an undecodable frame.
    #[test]
    fn test_scripted_undecryptable_drops_session() {
        let summary = run_logged(&[
            Step::Handshake,
            Step::Hello,
            Step::Reply(1),
            Step::ReplyReplay,
            Step::Recv,
            Step::Recv,
            Step::Send(1),
        ]);
        assert!(!summary.established);
        assert_eq!(summary.messages, 1);
        assert_eq!(summary.failures, 1);

        let summary = run_logged(&[
            Step::Handshake,
            Step::Hello,
            Step::Reply(1),
            Step::Recv,
            Step::Handshake,
            Step::Hello,
            Step::ReplyReplay,
            Step::Recv,
        ]);
        assert!(!summary.established);
        assert_eq!(summary.handshakes, 2);
        assert_eq!(summary.messages, 1);
        assert_eq!(summary.failures, 1);

        let summary = run_logged(&[
            Step::Handshake,
            Step::Hello,
            Step::ReplyTampered,
            Step::Recv,
        ]);
        assert!(!summary.established);

        let summary = run_logged(&[
            Step::Handshake,
            Step::Hello,
            Step::Junk(vec![7]),
            Step::Recv,
        ]);
        assert!(!summary.established);

        let summary = run_logged(&[Step::Handshake, Step::Hello, Step::Hello, Step::Recv]);
        assert!(!summary.established);

        let summary = run_logged(&[Step::Handshake, Step::Hello, Step::Undecodable, Step::Recv]);
        assert!(!summary.established);
    }

    // Tests that the server signaling a dropped session surfaces as a reset and
    // drops the client's session, sends failing until a new handshake. A
    // request sent before the signal is read still goes out.
    #[test]
    fn test_scripted_dropped_signal() {
        let summary = run_logged(&[
            Step::Handshake,
            Step::Hello,
            Step::Dropped,
            Step::Recv,
            Step::Send(1),
            Step::Handshake,
            Step::Hello,
            Step::Send(2),
        ]);
        assert!(summary.established);
        assert_eq!(summary.handshakes, 2);
        assert_eq!(summary.resets, 1);
        assert_eq!(summary.failures, 0);

        let summary = run_logged(&[
            Step::Handshake,
            Step::Hello,
            Step::Dropped,
            Step::Send(1),
            Step::Recv,
            Step::Send(2),
        ]);
        assert!(!summary.established);
        assert_eq!(summary.resets, 1);
        assert_eq!(summary.failures, 0);

        // Without a session the signal still surfaces as a reset, so a request
        // the server answered with a signal of its own shows up as a second reset
        let summary = run_logged(&[Step::Dropped, Step::Recv]);
        assert_eq!(summary.resets, 1);

        let summary = run_logged(&[
            Step::Handshake,
            Step::Hello,
            Step::Dropped,
            Step::Dropped,
            Step::Recv,
            Step::Recv,
        ]);
        assert!(!summary.established);
        assert_eq!(summary.resets, 2);
    }

    // Tests that reads without a session consume a frame and fail with the
    // error matching the frame, the session check coming after the read.
    #[test]
    fn test_scripted_recv_without_session() {
        let summary = run_logged(&[Step::Junk(vec![1]), Step::Recv]);
        assert_eq!(summary.failures, 1);

        let summary = run_logged(&[Step::Undecodable, Step::Recv]);
        assert_eq!(summary.failures, 1);

        let summary = run_logged(&[Step::Recv]);
        assert_eq!(summary.failures, 1);

        let summary = run_logged(&[Step::Send(1)]);
        assert_eq!(summary.failures, 0);
    }

    // Tests that a read failing in a session drops the session, the client not
    // knowing what it missed. So does the transport ending.
    #[test]
    fn test_scripted_read_failure_drops_session() {
        let summary = run_logged(&[Step::Handshake, Step::Hello, Step::Recv, Step::Send(1)]);
        assert!(!summary.established);
        assert_eq!(summary.failures, 1);

        let summary = run_logged(&[Step::Handshake, Step::Hello, Step::Recv]);
        assert!(!summary.established);
        assert_eq!(summary.failures, 1);
    }

    // Tests a transport failing under the client's writes. A send fails and
    // drops the session, a handshake fails at its reset or at its ack, and a
    // healed transport recovers.
    #[test]
    fn test_scripted_broken_transport() {
        let summary = run_logged(&[
            Step::Handshake,
            Step::Hello,
            Step::Break,
            Step::Send(1),
            Step::Send(2),
            Step::Handshake,
            Step::Heal,
            Step::Handshake,
            Step::Hello,
            Step::Send(3),
        ]);
        assert!(summary.established);
        assert_eq!(summary.handshakes, 2);
        assert_eq!(summary.failures, 1);

        let summary = run_logged(&[
            Step::Handshake,
            Step::Break,
            Step::Hello,
            Step::Heal,
            Step::Handshake,
            Step::Hello,
        ]);
        assert!(summary.established);
        assert_eq!(summary.handshakes, 1);
        assert_eq!(summary.failures, 1);
    }

    // Tests the client's sends cut short. A cut request fails the send and
    // drops the session, the reset of the next handshake terminating what got
    // out, junk or the request itself, ahead of its hello. A cut reset, hello
    // or ack fails the handshake before anything is read, a fresh handshake
    // recovering either way.
    #[test]
    fn test_scripted_cut_sends() {
        for point in [
            CutPoint::Start,
            CutPoint::Middle(5),
            CutPoint::Delimiter,
            CutPoint::Flush,
        ] {
            let cut = Step::Cut {
                point,
                then_broken: false,
            };

            let summary = run_logged(&[
                Step::Handshake,
                Step::Hello,
                cut.clone(),
                Step::Send(1),
                Step::Handshake,
                Step::Hello,
                Step::Send(2),
            ]);
            assert!(summary.established, "{point:?}");
            assert_eq!(summary.handshakes, 2, "{point:?}");
            assert_eq!(summary.failures, 0, "{point:?}");

            let summary = run_logged(&[cut.clone(), Step::Handshake, Step::Handshake, Step::Hello]);
            assert!(summary.established, "{point:?}");
            assert_eq!(summary.handshakes, 1, "{point:?}");
            assert_eq!(summary.failures, 1, "{point:?}");

            let summary = run_logged(&[
                Step::Handshake,
                cut,
                Step::Hello,
                Step::Handshake,
                Step::Hello,
            ]);
            assert!(summary.established, "{point:?}");
            assert_eq!(summary.handshakes, 1, "{point:?}");
            assert_eq!(summary.failures, 1, "{point:?}");
        }

        // A transport staying broken after the cut heals into a working
        // handshake, the fragment waiting on the stream until then
        let summary = run_logged(&[
            Step::Handshake,
            Step::Hello,
            Step::Cut {
                point: CutPoint::Middle(5),
                then_broken: true,
            },
            Step::Send(1),
            Step::Handshake,
            Step::Heal,
            Step::Handshake,
            Step::Hello,
        ]);
        assert!(summary.established);
        assert_eq!(summary.handshakes, 2);
        assert_eq!(summary.failures, 1);
    }

    // Tests that frames arriving in pieces, down to a byte per read, are
    // reassembled and read like whole ones.
    #[test]
    fn test_scripted_chunked_reads() {
        for chunk in [1u8, 7, 254, 255] {
            let summary = run_logged(&[
                Step::Chunk(chunk),
                Step::Handshake,
                Step::Hello,
                Step::Send(1),
                Step::Reply(1),
                Step::Recv,
                Step::Junk(vec![1; 300]),
                Step::Recv,
                Step::Handshake,
                Step::Hello,
            ]);
            assert!(summary.established, "chunk {chunk}");
            assert_eq!(summary.messages, 1, "chunk {chunk}");
            assert_eq!(summary.handshakes, 2, "chunk {chunk}");
        }
    }

    // Tests that frames batched into one read are read like frames arriving
    // one per read, the batch ending at the frame settling the call, so a
    // read never takes in more than its call consumes.
    #[test]
    fn test_scripted_batched_reads() {
        let summary = run_logged(&[
            Step::Handshake,
            Step::Batch(3),
            Step::Dropped,
            Step::Junk(vec![1]),
            Step::Hello,
        ]);
        assert!(summary.established);
        assert_eq!(summary.reads, 1);

        let summary = run_logged(&[
            Step::Handshake,
            Step::Batch(2),
            Step::Undecodable,
            Step::Hello,
        ]);
        assert!(summary.established);
        assert_eq!(summary.reads, 1);

        let summary = run_logged(&[
            Step::Handshake,
            Step::Hello,
            Step::Send(1),
            Step::Send(2),
            Step::Batch(2),
            Step::Reply(1),
            Step::Reply(2),
            Step::Recv,
            Step::Recv,
        ]);
        assert!(summary.established);
        assert_eq!(summary.messages, 2);
        assert_eq!(summary.reads, 3);

        for chunk in [1u8, 7] {
            let summary = run_logged(&[
                Step::Chunk(chunk),
                Step::Handshake,
                Step::Batch(3),
                Step::Dropped,
                Step::Junk(vec![1]),
                Step::Hello,
                Step::Send(1),
            ]);
            assert!(summary.established, "chunk {chunk}");
        }
    }

    // Tests frames cut short and unterminated ones in front of the client. A
    // truncated ArkHello or reply is stale to a handshake and drops a
    // session, whether its prefix still decodes or not. A partial ArkHello
    // swallows the frame after it into junk, a lone delimiter completing it
    // into the valid ArkHello it is instead.
    #[test]
    fn test_scripted_interrupted_frames() {
        for cut in [0u8, 1, 7, 255] {
            let summary = run_logged(&[
                Step::Handshake,
                Step::Hello,
                Step::Handshake,
                Step::Truncated(cut),
                Step::Hello,
            ]);
            assert!(summary.established, "cut {cut}");
            assert_eq!(summary.handshakes, 2, "cut {cut}");
            assert_eq!(summary.failures, 0, "cut {cut}");

            let summary = run_logged(&[
                Step::Handshake,
                Step::Hello,
                Step::Send(1),
                Step::Reply(1),
                Step::Recv,
                Step::Truncated(cut),
                Step::Recv,
                Step::Send(2),
            ]);
            assert!(!summary.established, "cut {cut}");
            assert_eq!(summary.messages, 1, "cut {cut}");
            assert_eq!(summary.failures, 1, "cut {cut}");
        }

        let summary = run_logged(&[Step::Handshake, Step::Partial, Step::Dropped]);
        assert!(summary.established);
        assert_eq!(summary.reads, 2);

        let summary = run_logged(&[
            Step::Handshake,
            Step::Partial,
            Step::Junk(vec![1]),
            Step::Hello,
        ]);
        assert!(summary.established);
        assert_eq!(summary.failures, 0);

        let summary = run_logged(&[
            Step::Handshake,
            Step::Partial,
            Step::Partial,
            Step::Dropped,
            Step::Hello,
        ]);
        assert!(summary.established);
        assert_eq!(summary.failures, 0);

        let summary = run_logged(&[
            Step::Handshake,
            Step::Hello,
            Step::Send(1),
            Step::Partial,
            Step::Reply(1),
            Step::Recv,
            Step::Send(2),
        ]);
        assert!(!summary.established);
        assert_eq!(summary.failures, 1);

        let summary = run_logged(&[
            Step::Handshake,
            Step::Hello,
            Step::Partial,
            Step::Dropped,
            Step::Recv,
        ]);
        assert!(!summary.established);
        assert_eq!(summary.failures, 1);

        for chunk in [1u8, 7] {
            let summary = run_logged(&[
                Step::Chunk(chunk),
                Step::Handshake,
                Step::Partial,
                Step::Dropped,
            ]);
            assert!(summary.established, "chunk {chunk}");
        }
    }

    // Tests that a read interrupted by a signal is retried by the framing, in
    // a handshake and in a session alike, the client none the wiser.
    #[test]
    fn test_scripted_interrupted_reads() {
        let summary = run_logged(&[
            Step::Handshake,
            Step::Interrupt,
            Step::Hello,
            Step::Send(1),
            Step::Recv,
            Step::Interrupt,
            Step::Reply(1),
        ]);
        assert!(summary.established);
        assert_eq!(summary.messages, 1);
        assert_eq!(summary.failures, 0);
    }

    // Tests that frames past the size limit vanish in the framing, in a
    // handshake and in a session alike, a partial ArkHello in front of one
    // vanishing with it.
    #[test]
    fn test_scripted_oversized_frames() {
        let summary = run_logged(&[
            Step::Handshake,
            Step::Oversized,
            Step::Hello,
            Step::Send(1),
            Step::Oversized,
            Step::Reply(1),
            Step::Recv,
        ]);
        assert!(summary.established);
        assert_eq!(summary.messages, 1);
        assert_eq!(summary.failures, 0);

        let summary = run_logged(&[Step::Handshake, Step::Partial, Step::Oversized, Step::Hello]);
        assert!(summary.established);
    }

    // Tests that server frames, yields and interrupts outside a read queue up or
    // vanish, and that replies before a session are junk, as is truncating
    // with no valid frame yet.
    #[test]
    fn test_scripted_noops() {
        let summary = run_logged(&[
            Step::Yield,
            Step::Interrupt,
            Step::ReplyReplay,
            Step::Truncated(3),
            Step::Reply(1),
            Step::Hello,
            Step::Handshake,
            Step::Hello,
        ]);
        assert!(summary.established);
        assert_eq!(summary.handshakes, 1);
    }
}
