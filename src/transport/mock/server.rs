// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Mock server driving a real `Client`. Script steps call client methods,
//! queue incoming frames, or inject I/O failures. The read adapter advances the
//! script as the client consumes its input. The mock parses every client write,
//! answers HostHellos, and decrypts requests with real keys.
//!
//! A separate model predicts each call's result and the client's session state
//! from the frames delivered to it. Any difference from those predictions panics.

use super::vector::{Event, ReadError, Vector};
use super::{
    CutPoint, MAX_STEPS, OVERSIZED_MESSAGE, Outbox, Recorder, TIMESTAMP, cloud_attestation, frame,
    self_attestation, trace, unframe, would_block,
};
use crate::transport::handshake;
use crate::transport::mock::payload;
use crate::transport::{
    Attestation, CRYPTO_DOMAIN_WIRE, CRYPTO_DOMAIN_WIRE_ARK_TO_HOST,
    CRYPTO_DOMAIN_WIRE_HOST_TO_ARK, Error, MAX_FRAME_SIZE, Sender,
};
use crate::transport::{Read, Write};
use darkbio_cobs as cobs;
use darkbio_crypto::{cbor, cose, xdsa, xhpke};
use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// One scripted client call, incoming frame, or I/O fault. A step that needs a
/// missing session or HostHello sends junk instead, so arbitrary sequences are valid.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum Step {
    // Calls through the client and its senders.
    /// The client runs a handshake.
    Handshake,
    /// The client sends a request tagged by the byte.
    Send(u8),
    /// Sends a message one byte over the conservative send limit.
    SendOversized,
    /// The client reads the next message.
    Recv,
    /// Retains the current sender separately, replacing any previously retained
    /// handle. With no sender, clears the retained slot.
    Retain,
    /// Sends through the retained handle, which may belong to an earlier session.
    /// Without a retained sender, the driver models refusal before any I/O.
    SendRetained(u8),

    // Handshake input.
    /// A valid ArkHello answering the latest HostHello. Junk if there was none.
    Hello,
    /// An ArkHello sealed to a key the client never had. Junk without a HostHello.
    HelloStale,
    /// An ArkHello for the latest HostHello with a flipped ciphertext byte.
    /// Junk if there was no hello.
    HelloTampered,
    /// An ArkHello bound to another client's keys, simulating a substituted
    /// HostHello. Junk without a HostHello to answer.
    HelloBadAuth,
    /// An ArkHello signed by a key other than the server's pinned identity.
    /// Junk without a HostHello to answer.
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
    /// An ArkHello carrying a cloud attestation instead of a device attestation.
    /// Junk without a HostHello to answer.
    HelloBadAttest,

    // Session input.
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

    // Malformed and partial frames.
    /// The bytes COBS encoded into a frame, decodable but meaningless.
    Junk(Vec<u8>),
    /// A frame failing COBS decoding.
    Undecodable,
    /// The last valid frame produced cut short, keeping at least one byte.
    /// Nothing if none was produced yet.
    Truncated(u8),
    /// A valid ArkHello without its delimiter. A following zero completes the
    /// hello; any other frame merges into its bytes and makes it invalid.
    Partial,
    /// A frame past the size limit, delimiter included. Receiving it ends a
    /// session; a handshake drains it and continues waiting for its ArkHello.
    /// Any preceding partial ArkHello belongs to the same oversized frame.
    Oversized,

    // Read scheduling and faults.
    /// Limits each read to this many bytes. Zero removes the limit.
    Chunk(u8),
    /// Batches up to this many frames into one read. Stops when a frame determines
    /// the current call's result, or the next step needs a separate action.
    Batch(u8),
    /// The read fails with `WouldBlock`.
    Yield,
    /// The read returns `Interrupted`. Framing retries without ending the call.
    Interrupt,
    /// An adapter read returns an early timeout. Receiving retries without ending the session.
    ReadTimeout,

    // Write faults.
    /// The client's writes fail until a Heal step.
    Break,
    /// The client's writes work again.
    Heal,
    /// Cuts the next matching client write. If requested, all later writes fail
    /// until a Heal step.
    Cut { point: CutPoint, then_broken: bool },
    /// The next matching output operation expires after the selected prefix.
    /// The stream remains reusable after the failed send or handshake.
    Timeout(CutPoint),
}

impl Step {
    /// Whether the step is a call into the client rather than a server frame.
    fn is_call(&self) -> bool {
        matches!(
            self,
            Step::Handshake
                | Step::Send(_)
                | Step::Recv
                | Step::Retain
                | Step::SendRetained(_)
                | Step::SendOversized
        )
    }

    /// Whether this step can join an input batch without driver or I/O changes.
    fn queues_frame(&self) -> bool {
        !matches!(
            self,
            Step::Handshake
                | Step::Send(_)
                | Step::Recv
                | Step::Retain
                | Step::SendRetained(_)
                | Step::SendOversized
                | Step::Yield
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

/// Error kinds the model distinguishes in the client's results.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// [`Error::FrameTooLarge`], a frame exceeding the receive limit.
    FrameTooLarge,
    /// [`Error::FrameDecodingFailed`], a frame failing COBS decoding.
    FrameDecoding,
    /// [`Error::SendFailed`], a failed output operation or deadline setup.
    Send,
    /// [`Error::RecvFailed`], the transport failing a read.
    Recv,
    /// [`Error::Terminated`], the transport ending.
    Terminated,
    /// [`Error::SessionReset`], the server signaling that it has no session.
    SessionReset,
    /// [`Error::InvalidAttestation`], an attestation of the wrong shape.
    InvalidAttestation,
    /// [`Error::HandshakeFailed`], a handshake refused or given up on.
    Handshake,
    /// [`Error::EncryptionFailed`], from failed decryption or an ended session.
    Encryption,
}

/// Final session state and observed counts for scenario assertions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub established: bool, // Whether the client ended up with a session
    pub handshakes: usize, // Handshakes that succeeded
    pub messages: usize,   // Messages the client read
    pub resets: usize,     // Session resets the client surfaced
    pub failures: usize,   // Failed handshakes and receives, excluding session resets
    pub reads: usize,      // Reads that handed the client bytes
}

/// Defect to introduce into ArkHello. A stale recipient makes the client skip
/// the frame; other defects in its own reply make it reject the handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flaw {
    /// Nothing, a valid ArkHello.
    None,
    /// Sealed to a key the client never had.
    Stale,
    /// A flipped ciphertext byte prevents decryption.
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

/// Meaning of incoming bytes in the model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Frame {
    /// The first byte exceeding the frame limit, reported before its delimiter.
    Oversized,
    /// An ArkHello for this handshake generation, with the selected defect.
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

/// Unterminated input retained until the next frame delimiter.
enum Partial {
    /// The stream is at a frame boundary.
    None,
    /// An ArkHello for this generation, completed successfully only if the next
    /// byte is a delimiter.
    Hello(u64, Vec<u8>),
    /// Bytes no delimiter can complete into anything valid.
    Junk(Vec<u8>),
    /// The size failure was already reported; remaining bytes are discarded
    /// through the next delimiter without reporting another frame.
    Discarding,
}

/// Client call whose result the incoming frames must determine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Call {
    /// No active call. Reading a frame in this state is a bug.
    None,
    /// A handshake awaiting the ArkHello of the generation. Older frames are
    /// drained regardless of their count until the matching hello arrives.
    Handshake { generation: u64 },
    /// A read of the next message.
    Recv,
}

/// Predicted client result, including the delivered bytes for a successful read.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Expect {
    /// The call succeeds, with the message if it was a read.
    Ok(Option<Vec<u8>>),
    /// The call fails with the error kind.
    Err(Kind),
}

/// Keys and sending context retained until a HostAck answers this ArkHello.
struct Outstanding {
    generation: u64,
    crypto: xhpke::SecretKey,
    sender: xhpke::Sender,
    host_signer: xdsa::PublicKey,
}

/// Mock server's session contexts and outgoing sequence count.
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
    queue: VecDeque<(Vec<u8>, Option<Frame>)>, // Input bytes and optional modeled result, including early size errors
    bytes: Vec<u8>,                            // Bytes of the frame being handed over
    offset: usize,                             // Position within the current input batch
    chunk: usize,                              // Maximum bytes per read; zero means unlimited
    batch: usize,                              // Frames remaining in the current input batch
    broken: bool,                              // Whether the client's writes fail
    cut: Option<CutPoint>,                     // Cut armed for the next matching client write
    fragment: bool,   // Whether a frame cut in the middle awaits its terminator
    partial: Partial, // Unterminated frame in front of the client

    call: Call,                  // Active client call consuming incoming frames
    expect: Option<Expect>,      // Predicted result once a frame determines it
    client_session: Option<u64>, // Generation of the client's live session
    client_receiver: bool,       // Receive context retained even after a local send failure
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
    /// Starts an idle model with a bounded script, fresh identity, and transcript.
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
            offset: 0,
            chunk: 0,
            batch: 0,
            broken: false,
            cut: None,
            fragment: false,
            partial: Partial::None,
            call: Call::None,
            expect: None,
            client_session: None,
            client_receiver: false,
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

    /// Executes one server step and queues any resulting input. Processes client
    /// output first, so a response uses the latest HostHello or established session.
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
                let mut overflow = None;
                self.partial = match std::mem::replace(&mut self.partial, Partial::None) {
                    Partial::None => match frame {
                        Frame::ArkHello { generation, .. } => {
                            Partial::Hello(generation, bytes.clone())
                        }
                        _ => Partial::Junk(bytes.clone()),
                    },
                    Partial::Hello(_, mut prior) | Partial::Junk(mut prior) => {
                        prior.extend_from_slice(&bytes);
                        if prior.len() > MAX_FRAME_SIZE {
                            overflow = Some(Frame::Oversized);
                            Partial::Discarding
                        } else {
                            Partial::Junk(prior)
                        }
                    }
                    Partial::Discarding => Partial::Discarding,
                };
                self.queue.push_back((bytes, overflow));
                return;
            }
            Step::Oversized => {
                let mut bytes = vec![1u8; MAX_FRAME_SIZE + 1];
                bytes.push(0x00);
                (bytes, Frame::Oversized)
            }
            Step::Chunk(n) => {
                self.chunk = n as usize;
                return;
            }
            Step::Batch(n) => {
                self.batch = n as usize;
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
            Step::Timeout(point) => {
                self.cut = Some(point);
                self.outbox.set_timeout(point);
                return;
            }
            Step::Handshake
            | Step::Send(_)
            | Step::Recv
            | Step::Yield
            | Step::Interrupt
            | Step::ReadTimeout
            | Step::Retain
            | Step::SendRetained(_)
            | Step::SendOversized => {
                unreachable!(
                    "calls, yields and interrupts are handled by the driver and the reader"
                )
            }
        };
        // Combine this frame with any earlier partial input. A lone delimiter
        // completes a pending hello. Other combinations become invalid or too large.
        let (bytes, frame) = produced;
        let frame = match std::mem::replace(&mut self.partial, Partial::None) {
            Partial::None => Some(if bytes.len() - 1 > MAX_FRAME_SIZE {
                Frame::Oversized
            } else {
                frame
            }),
            Partial::Hello(generation, _) if frame == Frame::Dropped => Some(Frame::ArkHello {
                generation,
                flaw: Flaw::None,
            }),
            Partial::Hello(_, prior) | Partial::Junk(prior) => {
                let mut merged = prior;
                merged.extend_from_slice(&bytes[..bytes.len() - 1]);
                Some(classify(&merged))
            }
            Partial::Discarding => None,
        };
        self.queue.push_back((bytes, frame));
    }

    /// Creates ArkHello for the latest HostHello with the selected defect.
    fn ark_hello(&mut self, flaw: Flaw) -> (Vec<u8>, Frame) {
        let Some((host_signer, host_crypto)) = self.latest_hello.clone() else {
            return self.junk(b"server hello without a client hello");
        };
        let crypto = xhpke::SecretKey::generate();
        if let Some(vector) = self.recorder.lock().unwrap().as_mut() {
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

        // Generation zero cannot match any client handshake.
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

    /// Seals a tagged reply or untagged bytes in the mock server's session.
    fn reply(&mut self, tag: Option<u8>) -> (Vec<u8>, Frame) {
        let Some(session) = self.session.as_mut() else {
            return self.junk(b"reply without a session");
        };
        let plaintext = match tag {
            Some(tag) => payload(tag as u64),
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

    /// Seals a reply, then flips a ciphertext byte so the client cannot open it.
    fn tampered_reply(&mut self) -> (Vec<u8>, Frame) {
        let Some(session) = self.session.as_mut() else {
            return self.junk(b"tampered reply without a session");
        };
        let plaintext = payload(0);
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

    /// Parses new client output, tracking HostHellos and HostAcks and verifying
    /// that requests open in the mock server's session.
    fn ingest(&mut self) {
        for framed in self.outbox.take_frames() {
            // Empty reset frames carry no keys or request bytes to track.
            if framed.is_empty() {
                continue;
            }
            // The next reset terminates a failed send's partial frame. Ignore
            // that fragment without trying to decode it.
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
                && session.receiver.open(&packet, &[]).is_ok()
            {
                continue;
            }
            panic!(
                "client wrote a frame the server cannot interpret ({} bytes)",
                packet.len()
            );
        }
    }

    /// Tries pending ArkHello keys against HostAck. A match establishes the mock
    /// server's session and removes that pending response.
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

    /// Predicts the client's reaction to incoming bytes. Records the call's
    /// result once a frame determines it.
    fn consume(&mut self, frame: Frame) {
        match self.call {
            Call::Handshake { generation } => {
                let result = match frame {
                    Frame::ArkHello {
                        generation: answered,
                        flaw,
                    } if answered == generation => match flaw {
                        // Valid ArkHello still fails the call if HostAck cannot
                        // be written and flushed successfully.
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
                    // Old output may contain any number of frames. Keep
                    // draining until the hello for this attempt arrives.
                    _ => return,
                };
                if result == Expect::Ok(None) {
                    self.client_session = Some(generation);
                    self.client_receiver = true;
                    self.client_seq = 0;
                }
                self.settle(result);
            }
            Call::Recv => {
                let result = match (self.client_session, frame) {
                    (_, Frame::Oversized) => {
                        self.client_session = None;
                        Expect::Err(Kind::FrameTooLarge)
                    }
                    (_, Frame::Dropped) => {
                        self.client_session = None;
                        Expect::Err(Kind::SessionReset)
                    }
                    (_, Frame::Undecodable) => {
                        self.client_session = None;
                        Expect::Err(Kind::FrameDecoding)
                    }
                    // A local send failure leaves the receive context present,
                    // so framing errors still take precedence in that case.
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
                        // Transport delivers opaque bytes without inspecting their format.
                        if garbage {
                            Expect::Ok(Some(vec![0x07]))
                        } else {
                            Expect::Ok(Some(payload(tag as u64)))
                        }
                    }
                    // Failed decryption ends the session.
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

    /// Consumes a cut applied to client output. A middle cut leaves a fragment
    /// for the next reset to terminate. Other cuts leave no bytes or a complete
    /// body that the server can verify once its delimiter arrives.
    fn apply_cut(&mut self) {
        if let Some(CutPoint::Middle(_)) = self.cut.take() {
            self.fragment = true;
        }
    }

    /// Predicts a read error or EOF ending the active call and client session.
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

    /// Checks a completed call against its prediction, then processes its output.
    fn finish(&mut self, result: Result<Option<Vec<u8>>, Kind>) {
        let expected = self
            .expect
            .take()
            .expect("call returned before the model settled it");
        let actual = match result {
            Ok(message) => Expect::Ok(message),
            Err(kind) => Expect::Err(kind),
        };
        assert_eq!(actual, expected);
        self.call = Call::None;
        self.ingest();
    }

    /// Advances to the next client call, executing earlier server steps to queue
    /// input. Read faults have no effect while no client call is reading.
    fn next_call(&mut self) -> Option<Step> {
        loop {
            match self.steps.pop_front() {
                None => return None,
                Some(step) if step.is_call() => return Some(step),
                Some(Step::Yield) | Some(Step::Interrupt) | Some(Step::ReadTimeout) => {}
                Some(step) => self.execute(step),
            }
        }
    }
}

/// Read adapter that advances the mock server's script as the client reads.
struct Feed {
    server: Arc<Mutex<Server>>,
}

impl Read for Feed {
    fn set_read_deadline(&mut self, _deadline: Option<Instant>) -> io::Result<()> {
        Ok(())
    }
}

impl io::Read for Feed {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut server = self.server.lock().unwrap();
        loop {
            // Deliver the current batch, respecting any per-read size limit.
            if !server.bytes.is_empty() {
                let mut n = buf.len().min(server.bytes.len() - server.offset);
                if server.chunk > 0 {
                    n = n.min(server.chunk);
                }
                buf[..n].copy_from_slice(&server.bytes[server.offset..server.offset + n]);
                server.offset += n;
                if server.offset == server.bytes.len() {
                    server.bytes.clear();
                    server.offset = 0;
                }
                server.summary.reads += 1;
                return Ok(n);
            }
            // Predict the next queued input's result before delivering its bytes.
            // Oversized input ends a receive before its remainder is drained;
            // ordinary partial input has no result until completed or oversized.
            // Batch later frames only while the current call still needs input.
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
            // Advance until a step queues input or ends this read with an error.
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
                Some(Step::ReadTimeout) => {
                    server.steps.pop_front();
                    server.trace(|| Event::ReadFailed {
                        error: ReadError::TimedOut,
                    });
                    return Err(io::ErrorKind::TimedOut.into());
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
type Client = crate::transport::Client<Feed, Outbox>;

/// Classifies truncated or merged input by size and COBS validity. Input that
/// still decodes is junk to the client; it cannot form a valid encrypted packet.
fn classify(bytes: &[u8]) -> Frame {
    if bytes.len() > MAX_FRAME_SIZE {
        return Frame::Oversized;
    }
    let mut buf = vec![0u8; cobs::decode_buffer(bytes.len())];
    match cobs::decode(bytes, &mut buf) {
        Ok(_) => Frame::Junk,
        Err(_) => Frame::Undecodable,
    }
}

/// Maps a client error onto the kind the model predicts.
fn kind(err: Error) -> Kind {
    match err {
        Error::FrameTooLarge(_) => Kind::FrameTooLarge,
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

/// Checks that the current sender is usable exactly when the model expects a
/// session. An oversized send checks admission without sealing or writing bytes.
pub(super) fn check_session<W: Write>(sender: Option<&Sender<W>>, established: bool) {
    let refused = super::send(sender, OVERSIZED_MESSAGE);
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

/// Runs a script against a real client and returns the observed counts. Panics
/// if client output or method results differ from the model.
pub fn run(steps: &[Step]) -> Summary {
    #[cfg(feature = "fuzz")]
    super::seed::seed(super::seed::TRANSPORT_CLIENT, steps);

    // Vector builds seed deterministic randomness from the scenario name before
    // generating any keys. Fuzz targets reseed once per input themselves.
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
    let server = Arc::new(Mutex::new(Server::new(
        steps,
        outbox.clone(),
        recorder.clone(),
    )));
    let identity = server.lock().unwrap().identity.public_key();
    let mut client = Client::new(crate::transport::Stream::new(
        Feed {
            server: server.clone(),
        },
        outbox,
        || {},
    ));

    // Record the script for other client implementations to replay. Flag
    // intentional output failures for consumers that cannot inject them.
    let steps = &steps[..steps.len().min(MAX_STEPS)];
    let write_failures = steps
        .iter()
        .any(|step| matches!(step, Step::Break | Step::Cut { .. } | Step::Timeout(_)));
    *recorder.lock().unwrap() = Vector::open(
        scenario,
        steps,
        write_failures,
        identity.to_bytes().to_vec(),
        server.lock().unwrap().attestation.as_bytes().to_vec(),
    );

    let mut sender = None;
    let mut retained = None;
    let mut retained_session = None; // Model identity captured with the retained handle
    loop {
        let call = server.lock().unwrap().next_call();
        let Some(call) = call else { break };

        match call {
            Step::Handshake => {
                sender = None;
                server.lock().unwrap().client_receiver = false;
                // Scripted output faults fail the reset or HostHello. The read
                // phase starts after both writes, so no scripted input is consumed.
                let signer = xdsa::SecretKey::generate();
                let crypto = xhpke::SecretKey::generate();
                trace(&recorder, || Event::Handshake {
                    xdsa: signer.to_bytes().to_vec(),
                    xhpke: crypto.to_bytes().to_vec(),
                });
                let failing = {
                    let server = server.lock().unwrap();
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
                    let mut server = server.lock().unwrap();
                    server.client_session = None;
                    server.summary.failures += 1;

                    // The reset may have terminated an earlier fragment. Take
                    // it in before marking this attempt's newly cut hello, so
                    // each fragment is discarded at its own boundary.
                    server.ingest();

                    // The two-byte reset cannot trigger a middle cut. If the
                    // reset fails because writes are broken, that cut remains
                    // armed for a later write.
                    let survives = server.broken && matches!(server.cut, Some(CutPoint::Middle(_)));
                    if !survives {
                        server.apply_cut();
                    }
                    continue;
                }
                {
                    let mut server = server.lock().unwrap();
                    server.client_session = None;
                    server.call = Call::Handshake {
                        generation: server.generation + 1,
                    };
                }
                let result = client.handshake_with_keys(&identity, signer, crypto, TIMESTAMP);
                trace(&recorder, || match &result {
                    Ok(_) => Event::Ok { message: None },
                    Err(err) => Event::Err {
                        kind: <&str>::from(err).into(),
                    },
                });
                let result = result
                    .map(|(opened, _)| {
                        sender = Some(opened);
                        None
                    })
                    .map_err(kind);
                let mut server = server.lock().unwrap();
                match result {
                    Ok(_) => server.summary.handshakes += 1,
                    Err(_) => server.summary.failures += 1,
                }
                server.finish(result);
            }
            Step::Retain => {
                retained = sender.clone();
                retained_session = server.lock().unwrap().client_session;
                trace(&recorder, || Event::Retain);
            }
            Step::SendOversized => {
                let established = server.lock().unwrap().client_session.is_some();
                trace(&recorder, || Event::Send {
                    message: OVERSIZED_MESSAGE.to_vec(),
                });
                let result = super::send(sender.as_ref(), OVERSIZED_MESSAGE);
                trace(&recorder, || Event::Err {
                    kind: <&str>::from(result.as_ref().unwrap_err()).into(),
                });
                match result {
                    Err(Error::PacketTooLarge(size)) if established => {
                        assert_eq!(size, OVERSIZED_MESSAGE.len())
                    }
                    Err(Error::EncryptionFailed(_)) if !established => {}
                    other => panic!("unexpected oversized send result: {other:?}"),
                }
                check_session(sender.as_ref(), established);
                server.lock().unwrap().ingest();
            }
            Step::Send(tag) | Step::SendRetained(tag) => {
                let established = server.lock().unwrap().client_session.is_some();
                trace(&recorder, || Event::Session { established });
                check_session(sender.as_ref(), established);

                let use_retained = matches!(call, Step::SendRetained(_));
                let admitted = established
                    && (!use_retained || retained_session == server.lock().unwrap().client_session);
                let sending = if use_retained {
                    retained.as_ref()
                } else {
                    sender.as_ref()
                };

                // A failed send ends the session. An armed cut takes precedence
                // over the adapter's persistent write failure.
                let expected: Result<Option<u64>, Kind> = {
                    let mut server = server.lock().unwrap();
                    match (admitted, server.broken || server.cut.is_some()) {
                        (true, false) => Ok(None),
                        (true, true) => {
                            server.client_session = None;
                            server.apply_cut();
                            Err(Kind::Send)
                        }
                        (false, _) => Err(Kind::Encryption),
                    }
                };
                let request = payload(tag as u64);
                trace(&recorder, || {
                    if use_retained {
                        Event::SendRetained {
                            message: request.clone(),
                        }
                    } else {
                        Event::Send {
                            message: request.clone(),
                        }
                    }
                });
                let result = super::send(sending, &request);
                trace(&recorder, || match &result {
                    Ok(_) => Event::Ok { message: None },
                    Err(err) => Event::Err {
                        kind: <&str>::from(err).into(),
                    },
                });
                let result = result.map(|_| None).map_err(kind);
                assert_eq!(result, expected);
                server.lock().unwrap().ingest();
            }
            Step::Recv => {
                {
                    let mut server = server.lock().unwrap();
                    server.call = Call::Recv;
                    if !server.client_receiver {
                        server.settle(Expect::Err(Kind::Encryption));
                    }
                }
                trace(&recorder, || Event::Recv);
                let result = client.recv();
                trace(&recorder, || match &result {
                    Ok(message) => Event::Ok {
                        message: Some(message.clone()),
                    },
                    Err(err) => Event::Err {
                        kind: <&str>::from(err).into(),
                    },
                });
                let result = result.map(Some).map_err(kind);
                let mut server = server.lock().unwrap();
                if result.is_err() {
                    server.client_receiver = false;
                }
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
    let mut server = server.lock().unwrap();
    server.ingest();
    let established = server.client_session.is_some();
    trace(&recorder, || Event::Session { established });
    check_session(sender.as_ref(), established);
    server.summary.established = established;

    if let Some(vector) = recorder.lock().unwrap().as_ref() {
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
