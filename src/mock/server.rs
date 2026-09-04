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

use super::vector::{Event, ReadError, Vector};
use super::{
    CutPoint, MAX_STEPS, Outbox, Recorder, TIMESTAMP, cloud_attestation, frame, self_attestation,
    trace, unframe, would_block,
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
use std::io::{self, Read, Write};
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
    recorder: Recorder,                        // Transcript of the run, if recorded
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
    fn new(steps: &[Step], outbox: Outbox, recorder: Recorder) -> Self {
        let identity = xdsa::SecretKey::generate();
        let attestation = self_attestation(&identity);
        Self {
            steps: steps.iter().take(MAX_STEPS).cloned().collect(),
            identity,
            attestation,
            outbox,
            recorder,
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
        if let Some(vector) = self.recorder.borrow_mut().as_mut() {
            vector.server_key(crypto.to_bytes().to_vec());
        }
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
            Flaw::Payload => cose::seal_at(
                &handshake::HostAck {
                    h2a_encap: vec![1, 2, 3],
                },
                &auth,
                signer,
                recipient,
                CRYPTO_DOMAIN_WIRE,
                TIMESTAMP,
            ),
            Flaw::Key => cose::seal_at(
                &(
                    self.attestation.as_bytes().to_vec(),
                    vec![0xffu8; xhpke::PUBLIC_KEY_SIZE],
                    encap.to_vec(),
                ),
                &auth,
                signer,
                recipient,
                CRYPTO_DOMAIN_WIRE,
                TIMESTAMP,
            ),
            _ => cose::seal_at(
                &payload,
                &auth,
                signer,
                recipient,
                CRYPTO_DOMAIN_WIRE,
                TIMESTAMP,
            ),
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

    /// Logs an event into the transcript, if the run is recorded.
    fn trace(&self, event: impl FnOnce() -> Event) {
        trace(&self.recorder, event);
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
                server.trace(|| Event::Read {
                    bytes: server.bytes.clone(),
                    chunk: server.chunk,
                });
                continue;
            }
            // Move the script forward until a frame is queued, a call or a
            // yield failing the read instead
            match server.steps.front() {
                None => {
                    server.interrupt(Kind::Terminated);
                    server.trace(|| Event::ReadFailed {
                        error: ReadError::Eof,
                    });
                    return Ok(0);
                }
                Some(step) if step.is_call() => {
                    server.interrupt(Kind::Recv);
                    server.trace(|| Event::ReadFailed {
                        error: ReadError::Failed,
                    });
                    return Err(would_block());
                }
                Some(Step::Yield) => {
                    server.steps.pop_front();
                    server.interrupt(Kind::Recv);
                    server.trace(|| Event::ReadFailed {
                        error: ReadError::Failed,
                    });
                    return Err(would_block());
                }
                Some(Step::Interrupt) => {
                    server.steps.pop_front();
                    server.trace(|| Event::ReadFailed {
                        error: ReadError::Interrupted,
                    });
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
pub(super) fn check_session<R: Read, W: Write>(
    client: &mut crate::Client<R, W>,
    established: bool,
) {
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
    super::seed::seed(super::seed::CLIENT_PROTOCOL, steps);

    // Name the run up front when transcribing it, the deterministic randomness
    // of the vector builds restarting from the name ahead of the first key.
    // The fuzzers restart it per input themselves.
    let scenario = super::vector::scenario();
    #[cfg(all(test, feature = "fuzz", getrandom_backend = "custom"))]
    if let Some(scenario) = &scenario {
        super::random::reseed(scenario);
    }

    let recorder = Recorder::default();
    let outbox = Outbox {
        recorder: recorder.clone(),
        ..Outbox::default()
    };
    let server = Rc::new(RefCell::new(Server::new(
        steps,
        outbox.clone(),
        recorder.clone(),
    )));
    let identity = server.borrow().identity.public_key();
    let mut client = Client::new(Feed(server.clone()), outbox);

    // Transcribe the run for other implementations of the client to replay,
    // flagging the writes failing on purpose for the ones unable to
    let steps = &steps[..steps.len().min(MAX_STEPS)];
    let write_failures = steps
        .iter()
        .any(|step| matches!(step, Step::Break | Step::Cut { .. }));
    *recorder.borrow_mut() = Vector::open(
        scenario,
        steps,
        write_failures,
        identity.to_bytes().to_vec(),
        server.borrow().attestation.as_bytes().to_vec(),
    );

    loop {
        let call = server.borrow_mut().next_call();
        let Some(call) = call else { break };

        match call {
            Step::Handshake => {
                // On a broken transport not even the reset gets out, and a cut
                // takes the reset or the hello, the client failing before reading
                // anything either way
                let signer = xdsa::SecretKey::generate();
                let crypto = xhpke::SecretKey::generate();
                trace(&recorder, || Event::Handshake {
                    xdsa: signer.to_bytes().to_vec(),
                    xhpke: crypto.to_bytes().to_vec(),
                });
                let failing = {
                    let server = server.borrow();
                    server.broken || server.cut.is_some()
                };
                if failing {
                    let result = client
                        .handshake_with_keys(&identity, signer, crypto, TIMESTAMP)
                        .map(|_| ());
                    assert!(matches!(result, Err(Error::SendFailed(_))), "{result:?}");
                    trace(&recorder, || Event::Err {
                        kind: "SendFailed".into(),
                    });
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
                let result = client.handshake_with_keys(&identity, signer, crypto, TIMESTAMP);
                trace(&recorder, || match &result {
                    Ok(_) => Event::Ok { message: None },
                    Err(err) => Event::Err {
                        kind: <&str>::from(err).into(),
                    },
                });
                let result = result.map(|_| None).map_err(kind);
                let mut server = server.borrow_mut();
                match result {
                    Ok(_) => server.summary.handshakes += 1,
                    Err(_) => server.summary.failures += 1,
                }
                server.finish(result);
            }
            Step::Send(tag) => {
                let established = server.borrow().client_session.is_some();
                trace(&recorder, || Event::Session { established });
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
                let request = HostToArk {
                    id: Some(tag as u64),
                    content: None,
                };
                trace(&recorder, || Event::Send {
                    message: request.encode_to_vec(),
                });
                let result = client.send_message(request);
                trace(&recorder, || match &result {
                    Ok(_) => Event::Ok { message: None },
                    Err(err) => Event::Err {
                        kind: <&str>::from(err).into(),
                    },
                });
                let result = result.map(|_| None).map_err(kind);
                assert_eq!(result, expected);
                server.borrow_mut().ingest();
            }
            Step::Recv => {
                server.borrow_mut().call = Call::Recv;
                trace(&recorder, || Event::Recv);
                let result = client.next_message();
                trace(&recorder, || match &result {
                    Ok(msg) => Event::Ok {
                        message: Some(msg.encode_to_vec()),
                    },
                    Err(err) => Event::Err {
                        kind: <&str>::from(err).into(),
                    },
                });
                let result = result.map(|msg| msg.id).map_err(kind);
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
    let established = server.client_session.is_some();
    trace(&recorder, || Event::Session { established });
    check_session(&mut client, established);
    server.summary.established = established;

    if let Some(vector) = recorder.borrow().as_ref() {
        vector.write();
        #[cfg(test)]
        {
            assert!(
                super::vector::replay::parse(&vector.json()) == *vector,
                "transcript does not survive its encoding"
            );
            super::vector::replay::run(vector);
        }
    }
    server.summary
}

#[cfg(test)]
mod tests;
