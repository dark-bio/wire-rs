// wire-rs: encrypted protocol between Ark and host
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Server side of the transport, with the device attestation it presents and
//! the events it reports.

use crate::LogId;
use crate::transport::DEFAULT_HANDSHAKE_TIMEOUT;
use crate::transport::framing::FrameReader;
use crate::transport::handshake;
use crate::transport::io::check_deadline;
use crate::transport::outbound::{Outbound, Side};
use crate::transport::sealing;
use crate::transport::sender::Sender;
use crate::transport::{
    CRYPTO_DOMAIN_WIRE, CRYPTO_DOMAIN_WIRE_ARK_TO_HOST, CRYPTO_DOMAIN_WIRE_HOST_TO_ARK, Closer,
    Error, Read, Stream, Write,
};
use darkbio_crypto::{cbor, cose, cwt, xdsa, xhpke};
use darkbio_trust as trust;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, info, trace, warn};

/// Device attestation that a server presents during the handshake.
///
/// The CWT must carry hardware or emulator claims, as defined in
/// [`trust::device`]. Construction checks that shape, and the client's
/// [`Verifier`](crate::transport::Verifier) decides whether to trust it.
#[derive(Clone)]
pub struct Attestation(
    /// Encoded CWT whose claim shape was checked at construction.
    Vec<u8>,
);

impl Attestation {
    /// Wraps a CWT after checking that it decodes as a device attestation.
    pub fn new(cwt: Vec<u8>) -> Result<Self, Error> {
        if cwt::peek::<trust::device::HardwareClaims>(&cwt).is_err()
            && cwt::peek::<trust::device::EmulatorClaims>(&cwt).is_err()
        {
            return Err(Error::InvalidAttestation);
        }
        Ok(Self(cwt))
    }

    /// Returns the attestation's CWT bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Unwraps the attestation into its CWT bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for Attestation {
    /// Shows the size of the CWT, never its bytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Attestation")
            .field("len", &self.0.len())
            .finish()
    }
}

/// Source of the server's device attestation, asked on every handshake.
///
/// Asking every time lets the server pick up a new attestation after onboarding
/// without recreating the transport.
pub trait Attester {
    /// Returns the device attestation to present to the client.
    ///
    /// It can be a root-signed CWT read from disk, or a self-signed fallback for
    /// a device that has not been onboarded. The identity key it embeds must
    /// match the signer passed to [`Server::new`].
    fn attest(&mut self) -> Attestation;
}

/// A fixed attestation, presented as is on every handshake.
impl Attester for Attestation {
    fn attest(&mut self) -> Attestation {
        self.clone()
    }
}

/// Decrypted message or session transition returned by [`Server::recv`].
///
/// Events arrive in receive order and refer to sessions over the same byte
/// stream. Permanent stream closure produces no event, since [`Server::recv`]
/// returns an error for it.
pub enum Event<W: Write> {
    /// Completed handshake, with the sender of the encrypted session it
    /// established.
    ///
    /// The sender belongs to that session and cannot send into a later
    /// replacement. Stream closure from another thread can make it unusable
    /// before the caller handles the event.
    Connected(Sender<W>),

    /// End of the session that the last [`Event::Connected`] opened.
    ///
    /// A peer reset, invalid incoming data or a failed send ends it, and a
    /// failed send is reported once receiving progresses. After a peer reset,
    /// the next receive call runs the handshake. A local [`Server::disconnect`]
    /// emits no such event, and permanent stream closure is reported as an
    /// error instead.
    Disconnected,

    /// A decrypted message from the client.
    Message(Vec<u8>),
}

impl<W: Write> fmt::Debug for Event<W> {
    /// Names the event, showing the sender or the message length.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connected(sender) => f.debug_tuple("Connected").field(sender).finish(),
            Self::Disconnected => f.write_str("Disconnected"),
            Self::Message(message) => f.debug_tuple("Message").field(&message.len()).finish(),
        }
    }
}

/// Server side of the wire, accepting encrypted sessions over a supplied byte
/// stream.
///
/// [`Server::recv`] handles client resets and handshakes. Each successful
/// handshake returns a sender through [`Event::Connected`]. Later reads deliver
/// decrypted messages or report that the session ended.
/// [`Server::disconnect`] ends a session while leaving the stream available for
/// another; [`Server::close`] permanently closes the stream.
///
/// On a local disconnect, a session failure, a failed handshake or data received
/// outside a session, the server attempts an empty frame notification. A client
/// receiving it drops its old session. Notifications are best effort and bounded
/// by an output deadline. A failed write's own notification uses only its
/// remaining budget and is skipped after timeout. Later incoming traffic can
/// prompt a standalone notification.
///
/// An [`Attester`] supplies the device attestation. Transport forwards it to the
/// client, whose [`Verifier`](crate::transport::Verifier) decides whether to
/// trust it.
pub struct Server<R: Read, W: Write, A: Attester> {
    /// COBS frame reader for the data the client sends.
    reader: FrameReader<R>,
    /// Outgoing transport, which the senders reach through weak references.
    outbound: Arc<Outbound<W>>,

    /// Server's identity key, which signs the ArkHello.
    signer: xdsa::SecretKey,
    /// Source of the device attestation for each handshake.
    attester: A,

    /// Receive context of the current session, used only by this server.
    receiver: Option<xhpke::Receiver>,
    /// Send context of the current session, shared with active sends.
    sealer: Option<Arc<Mutex<xhpke::Sender>>>,

    /// Budget for each new handshake attempt.
    handshake_timeout: Duration,
    /// Deadline of the handshake that a received reset requested, unset while
    /// none is pending.
    handshake_deadline: Option<Instant>,
    /// Label of the latest session in log lines, zero before the first one.
    log_id: LogId,

    /// Fixed ArkHello signing time for test vectors, unset to read the clock.
    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    timestamp: Option<i64>,
}

impl<R: Read, W: Write, A: Attester> Server<R, W, A> {
    /// Creates a server that owns the byte stream and its shutdown operation.
    ///
    /// The signer is the server's identity key. It must match the key embedded
    /// in the device attestation. Output uses the stream's configured write
    /// timeout. The stream's [`Read`] and [`Write`] adapters must enforce
    /// deadlines and let shutdown cancel blocked I/O.
    pub fn new(stream: Stream<R, W>, signer: xdsa::SecretKey, attester: A) -> Self {
        let (reader, writer, close, timeout) = stream.into_parts();
        let outbound = Arc::new(Outbound::new(writer, Side::Server, close.clone(), timeout));
        Self {
            reader: FrameReader::new(reader, close),
            outbound,
            signer,
            attester,
            receiver: None,
            sealer: None,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            handshake_deadline: None,
            log_id: LogId::default(),
            #[cfg(any(test, feature = "bench", feature = "fuzz"))]
            timestamp: None,
        }
    }

    /// Sets the budget for each later handshake, counted from the reset that
    /// requests it.
    ///
    /// Defaults to [`DEFAULT_HANDSHAKE_TIMEOUT`]. Output and peer replies share
    /// one deadline; progress and repeated resets within the attempt do not
    /// refresh it. An already pending handshake keeps its deadline. Each
    /// outgoing frame is also limited by the stream's write timeout. Waiting for
    /// locks and attester callbacks can extend the call beyond the deadline.
    /// Time between [`Server::recv`] calls also consumes the budget.
    ///
    /// Zero expires attempts immediately. A duration too large to add to an
    /// [`Instant`] panics when the next handshake's deadline is constructed.
    pub fn set_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Returns a handle that permanently closes the stream from another thread.
    pub fn closer(&self) -> Closer {
        self.outbound.closer()
    }

    /// Permanently closes the stream and waits for adapter shutdown.
    ///
    /// Senders observe closure through write failure, and buffered messages
    /// remain readable. See [`Closer::close`].
    pub fn close(&self) {
        self.outbound.close();
    }

    /// Creates a server that signs every ArkHello at a fixed time, for vector
    /// replay.
    ///
    /// It exists for test vectors and is not part of the normal transport API.
    #[doc(hidden)]
    #[inline]
    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn new_at(
        stream: Stream<R, W>,
        signer: xdsa::SecretKey,
        attester: A,
        timestamp: i64,
    ) -> Self {
        let mut server = Self::new(stream, signer, attester);
        server.timestamp = Some(timestamp);
        server
    }

    /// Receives the next decrypted message or session transition.
    ///
    /// A client reset starts a handshake, whose completion returns
    /// [`Event::Connected`] with a sender before any messages from that session
    /// are delivered.
    ///
    /// A client reset or invalid incoming data ends the current session and
    /// returns [`Event::Disconnected`]. Oversized frames count as invalid data.
    /// A send failure also ends the session, but does not wake a blocked read.
    /// It is reported once receiving progresses. Sessions ended by a local
    /// disconnect are not reported again.
    ///
    /// The handshake after a reset runs under one configured deadline, starting
    /// at that reset. It runs in the same call, or in the next one when the
    /// reset ended a session. Repeated resets within the attempt do not refresh
    /// the deadline. Expiry returns a `TimedOut` I/O error, as
    /// [`Error::SendFailed`] while writing and as [`Error::RecvFailed`]
    /// otherwise. A fresh reset can start another attempt.
    ///
    /// After decryption, message acceptance is ordered with session ending
    /// without waiting for the writer. A concurrent send failure can cause a
    /// decrypted message to be discarded before acceptance. An accepted message
    /// may reach the caller after another thread ends the session. Reporting
    /// a session's end waits for outgoing writes to finish.
    ///
    /// Junk outside a session and handshake protocol or authentication failures
    /// are logged, answered with a best-effort empty frame and skipped. Handshake
    /// write failures surface as errors; calling again waits for a new reset on
    /// the same stream. Adapter read failures and EOF also surface as errors,
    /// without removing the binding. The caller can retry a transient read error,
    /// disconnect the session or close the stream. Outside a handshake, reads
    /// wait for data or adapter shutdown without a session timeout.
    ///
    /// Outgoing frames and standalone empty notifications use the stream's
    /// configured write timeout. A notification sent while handling a failed
    /// write shares that frame's remaining budget and is skipped after timeout.
    /// These output failures do not themselves close the byte stream.
    ///
    /// # Panics
    ///
    /// Panics if a handshake or write timeout is too large to add to an
    /// [`Instant`], or if a handshake reads a wall time before the Unix epoch
    /// from the stream's clock.
    pub fn recv(&mut self) -> Result<Event<W>, Error> {
        // Continue until a message, session transition or I/O error is ready.
        // Empty frames request a handshake on the next pass.
        loop {
            // If a reset just arrived, run the handshake
            if let Some(deadline) = self.handshake_deadline.take() {
                match self.handshake(deadline) {
                    // Transport errors propagate immediately
                    Err(Error::Terminated) => return Err(Error::Terminated),
                    Err(Error::RecvFailed(err)) => return Err(Error::RecvFailed(err)),
                    // Outbound already attempted a notification within the failed
                    // frame's budget, and another attempt here could block again
                    Err(Error::SendFailed(err)) => return Err(Error::SendFailed(err)),

                    // Notify the client that the handshake established no session
                    Err(err) => {
                        warn!("dropping wire handshake: {}", err);
                        if let Err(err) = self.outbound.send_dropped(Some(deadline)) {
                            warn!("failed to signal dropped handshake: {}", err);
                        }
                        // Do not swallow an attempt deadline exhausted during
                        // authentication or its failure notification
                        check_deadline(&self.outbound.clock, deadline)
                            .map_err(Error::RecvFailed)?;
                    }
                    // Report the completed handshake before reading messages.
                    // The caller can send at once, without waiting for a client
                    // request.
                    Ok((sender, receiver)) => {
                        let sender = self.new_session(sender, receiver);
                        info!("wire session {} established", self.log_id);
                        return Ok(Event::Connected(sender));
                    }
                }
                continue;
            }

            // Retrieve the next COBS encoded packet
            let packet = match self.reader.next_packet(None) {
                // Transport errors propagate immediately
                Err(Error::Terminated) => return Err(Error::Terminated),
                Err(Error::RecvFailed(err)) => return Err(Error::RecvFailed(err)),

                // A reset can terminate a partial frame and cause a framing error.
                // The frame may also have carried a sealed message. End any active
                // session, since its encryption sequence cannot be followed past it.
                Err(err) => {
                    let ended = self.end_session();
                    if ended {
                        warn!("ending session {}: {}", self.log_id, err);
                    } else {
                        debug!("discarding invalid frame outside session: {}", err);
                    }
                    self.send_dropped();
                    if ended {
                        return Ok(Event::Disconnected);
                    }
                    continue;
                }
                // A reset ends any active session. Run the handshake on the next
                // receive call if this one returns an event, or on the next pass.
                Ok(None) => {
                    self.handshake_deadline =
                        Some(self.outbound.clock.now() + self.handshake_timeout);
                    if self.end_session() {
                        info!("wire session {} reset by host", self.log_id);
                        return Ok(Event::Disconnected);
                    }
                    debug!("wire reset received, awaiting handshake");
                    continue;
                }
                // Valid COBS packet
                Ok(Some(packet)) => packet,
            };

            // Answer data outside a session with an empty frame and skip it
            let receiver = match self.receiver.as_mut() {
                None => {
                    debug!("discarding data outside session");
                    self.send_dropped();
                    continue;
                }
                Some(receiver) => receiver,
            };

            // Finish after decrypting, ordering message acceptance with a send
            // failure without ever waiting for the writer on a successful receive
            let sealer = self
                .sealer
                .as_ref()
                .expect("receiver has a sending context");
            let opened = sealing::open(receiver, packet);
            let undecryptable = opened.is_err();
            let message = match self.outbound.finish_receive(sealer, opened) {
                Err(err) => {
                    if undecryptable {
                        warn!("ending session {}: {}", self.log_id, err);
                    } else {
                        debug!(
                            "discarding message read after session {} ended",
                            self.log_id
                        );
                    }
                    self.end_session();
                    self.send_dropped();
                    return Ok(Event::Disconnected);
                }
                Ok(message) => message,
            };
            trace!("received host-to-ark message ({} bytes)", packet.len());
            return Ok(Event::Message(message));
        }
    }

    /// Stores the negotiated contexts and returns a sender for the new session.
    ///
    /// The sending context's allocation identifies the session. The server owns
    /// both contexts and shares the sending context with active sends. Idle
    /// senders hold weak references and keep neither context nor stream alive.
    ///
    /// Takes the writer lock, then the binding lock. An old write that already
    /// holds the writer lock may finish first. Once the binding is replaced,
    /// old sends cannot write and old received messages cannot be accepted.
    /// This method performs no handshake, crypto or stream I/O.
    fn new_session(&mut self, sender: xhpke::Sender, receiver: xhpke::Receiver) -> Sender<W> {
        let sealer = Arc::new(Mutex::new(sender));
        let sender = self.outbound.bind(&sealer);
        self.log_id = sender.log_id();
        self.receiver = Some(receiver);
        self.sealer = Some(sealer);
        sender
    }

    /// Ends the current binding before releasing the server's crypto contexts.
    ///
    /// Waits for the writer while a session exists. After this returns, no
    /// write or flush for that session is running or can start. A send that
    /// gets the writer first may finish. A send still sealing after removal
    /// cannot write its packet. This takes no encryption lock and does not wait
    /// for crypto work.
    ///
    /// This does not close the stream or send a notification. An active write
    /// may delay ending until its frame deadline. Another thread can use a
    /// [`Closer`] to cancel I/O without taking the writer lock.
    ///
    /// Returns true if it removed a receive context, even if a send failure
    /// already ended the binding. The receive loop uses this removal to emit
    /// [`Event::Disconnected`] once. Local disconnect uses the result only for
    /// its log line, since its caller already knows the session ended.
    fn end_session(&mut self) -> bool {
        if let Some(sealer) = self.sealer.as_ref() {
            self.outbound.end(sealer);
        }
        self.sealer = None;
        self.receiver.take().is_some()
    }

    /// Sends an empty frame to notify the client that it has no session,
    /// logging any failure.
    fn send_dropped(&self) {
        if let Err(err) = self.outbound.send_dropped(None) {
            warn!("failed to signal dropped session: {}", err);
        }
    }

    /// Ends the current session, if any, and notifies the client with an empty
    /// frame.
    ///
    /// The stream remains available for the client to connect again.
    /// Notification failures are logged. This produces no
    /// [`Event::Disconnected`], since the caller already knows the session
    /// ended.
    ///
    /// Waits for the current writer and its flush, then retires the binding.
    /// The notification gets its own frame budget. Another thread can use a
    /// [`Closer`] to cancel output earlier.
    pub fn disconnect(&mut self) {
        if self.end_session() {
            debug!("wire session {} dropped locally", self.log_id);
        }
        self.send_dropped();
    }

    /// Responds to the handshake after a session reset, establishing the HPKE
    /// contexts of both directions.
    ///
    /// The exchange takes three messages:
    ///
    /// ```text
    /// 1. Client -> Server: HostHello { host_signer, host_crypto }           (plain CBOR)
    /// 2. Server -> Client: ArkHello  { ark_attest, ark_crypto, a2h_encap }  (cose::seal)
    /// 3. Client -> Server: HostAck   { h2a_encap }                          (cose::seal)
    /// ```
    ///
    /// Empty frames before the HostHello are skipped, and one in place of the
    /// HostAck restarts the exchange. All steps share one deadline.
    fn handshake(&mut self, deadline: Instant) -> Result<(xhpke::Sender, xhpke::Receiver), Error> {
        // Wait for earlier writes and drop any binding before answering
        self.outbound.unbind();
        loop {
            // Message 1: Read the HostHello (skip any trailing empty reset frames)
            let packet = loop {
                if let Some(packet) = self.reader.next_packet(Some(deadline))? {
                    break packet;
                }
            };
            let host_hello: handshake::HostHello = cbor::decode(packet)
                .map_err(|err| Error::HandshakeFailed(format!("invalid client hello: {}", err)))?;

            // Generate ephemeral keys and set up server-to-client encryption
            let ark_crypto_key = xhpke::SecretKey::generate();
            let ark_crypto_pub = ark_crypto_key.public_key();
            let (sender, a2h_encap) = host_hello
                .host_crypto
                .new_sender(CRYPTO_DOMAIN_WIRE_ARK_TO_HOST)
                .map_err(|err| {
                    Error::HandshakeFailed(format!("server sender setup failed: {}", err))
                })?;

            // Message 2: Seal and send the ArkHello
            let ark_hello = handshake::ArkHello {
                ark_attest: self.attester.attest().into_bytes(),
                ark_crypto: ark_crypto_pub.clone(),
                a2h_encap: a2h_encap.to_vec(),
            };
            let auth = handshake::ArkHelloAuth {
                host_signer: host_hello.host_signer.clone(),
                host_crypto: host_hello.host_crypto.clone(),
            };
            // Sign at the clock's wall time, unless a test fixed the signing time
            #[cfg(not(any(test, feature = "bench", feature = "fuzz")))]
            let timestamp = handshake::timestamp(&self.outbound.clock);
            #[cfg(any(test, feature = "bench", feature = "fuzz"))]
            let timestamp = self
                .timestamp
                .unwrap_or_else(|| handshake::timestamp(&self.outbound.clock));
            let sealed = cose::seal_at(
                &ark_hello,
                &auth,
                &self.signer,
                &host_hello.host_crypto,
                CRYPTO_DOMAIN_WIRE,
                timestamp,
            );
            let ark_hello = sealed.map_err(|err| {
                Error::HandshakeFailed(format!("failed to seal server hello: {}", err))
            })?;
            self.outbound.send_packet(&ark_hello, Some(deadline))?;

            // Message 3: Read and open HostAck. An empty frame is another reset;
            // discard this attempt and wait for the next HostHello.
            let Some(packet) = self.reader.next_packet(Some(deadline))? else {
                debug!("wire reset received during handshake");
                continue;
            };
            let host_ack: handshake::HostAck = cose::open_at(
                packet,
                &handshake::HostAckAuth {
                    ark_signer: self.signer.public_key(),
                    ark_crypto: ark_crypto_pub.clone(),
                },
                &ark_crypto_key,
                &host_hello.host_signer,
                CRYPTO_DOMAIN_WIRE,
                None, // clock possibly unset, ephemeral keys guarantee freshness
                0,    // unused without a drift check, so the clock is not read
            )
            .map_err(|err| Error::HandshakeFailed(format!("invalid client ack: {}", err)))?;

            // Set up client-to-server decryption
            let enc_h2a: [u8; xhpke::ENCAP_KEY_SIZE] = host_ack
                .h2a_encap
                .try_into()
                .map_err(|_| Error::HandshakeFailed("invalid h2a_encap size".into()))?;
            let receiver = ark_crypto_key
                .new_receiver(&enc_h2a, CRYPTO_DOMAIN_WIRE_HOST_TO_ARK)
                .map_err(|err| {
                    Error::HandshakeFailed(format!("server receiver setup failed: {}", err))
                })?;

            // Hand back the contexts unless the exchange finished past its deadline
            check_deadline(&self.outbound.clock, deadline).map_err(Error::RecvFailed)?;
            return Ok((sender, receiver));
        }
    }
}

impl<R: Read, W: Write, A: Attester> Drop for Server<R, W, A> {
    /// Closes the stream to cancel blocked I/O, then ends the binding before
    /// releasing the contexts.
    ///
    /// Shutdown must come before waiting for the writer, which a blocked write
    /// could otherwise hold until its deadline. Idle senders hold weak
    /// references and cannot extend the stream's lifetime.
    fn drop(&mut self) {
        self.outbound.close();
        self.end_session();
    }
}

impl<R: Read, W: Write, A: Attester> fmt::Debug for Server<R, W, A> {
    /// Shows the session label, whether a session is established and the
    /// handshake budget, never the adapters, the keys or the encryption contexts.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Server")
            .field("session", &self.log_id)
            .field("connected", &self.sealer.is_some())
            .field("handshake_timeout", &self.handshake_timeout)
            .finish_non_exhaustive()
    }
}

/// Tests of the server, its attestation and its sessions with the real client.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::transport::mock::payload;
    use crate::transport::testing::{Memory, test_clock};
    use crate::transport::{Client, MAX_FRAME_SIZE, Verifier};
    use crate::{memory, testing};
    use darkbio_clock::Clock;
    use darkbio_cobs as cobs;

    /// Issues a self-signed attestation for a device that has not been
    /// onboarded.
    fn self_attestation(signer: &xdsa::SecretKey) -> Attestation {
        use darkbio_crypto::cwt::claims::{self, eat};

        let claims = darkbio_trust::device::HardwareClaims {
            sub: claims::Subject { sub: "".into() },
            cnf: claims::Confirm::new(signer.public_key()),
            nbf: claims::NotBefore { nbf: 0 },
            iat: claims::IssuedAt { iat: 0 },
            oem: eat::Oemid::new_pen(0),
            hwm: eat::HwModel { hw_model: vec![] },
            hwv: eat::HwVersion::new("".into()),
        };
        let cwt = cwt::issue_at(
            &claims,
            signer,
            darkbio_trust::CRYPTO_DOMAIN_DEVICE_ATTESTATION,
            crate::transport::mock::TIMESTAMP,
        )
        .unwrap();
        Attestation::new(cwt).unwrap()
    }

    /// COBS-encodes data and appends the frame delimiter.
    fn cobs_frame(data: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; cobs::encode_buffer(data.len())];
        let n = cobs::encode(data, &mut buf).unwrap();
        buf.truncate(n);
        buf.push(0x00);
        buf
    }

    /// Tests that an oversized server hello produces one failure notification.
    ///
    /// The hello never reaches adapter I/O, so the handshake owns that
    /// notification, and the writer must not emit another with its own budget.
    /// Dummy attestation bytes isolate the framing limit, since the server
    /// forwards them without parsing.
    #[test]
    fn test_oversized_hello_notifies_once() {
        // Prepare an oversized server hello on a paused clock
        testing::init_tracing();
        let tester = test_clock();
        let clock = tester.clock();
        let hello = cbor::encode(&handshake::HostHello {
            host_signer: xdsa::SecretKey::generate().public_key(),
            host_crypto: xhpke::SecretKey::generate().public_key(),
        })
        .unwrap();
        let mut input = vec![0, 0];
        input.extend_from_slice(&cobs_frame(&hello));
        let mut output = Vec::new();
        let mut server = Server::new(
            Stream::new(
                Memory::new(&input[..], &clock),
                Memory::new(&mut output, &clock),
                || {},
            ),
            xdsa::SecretKey::generate(),
            Attestation(vec![0; MAX_FRAME_SIZE]),
        );

        // Require exactly one failure notification before EOF
        assert!(matches!(server.recv(), Err(Error::Terminated)));
        drop(server);
        assert_eq!(output, [0]);
    }

    /// Tests that the real client and server exchange messages, and that a fresh
    /// handshake recovers from a dropped session.
    #[test]
    fn test_message_round_trip() {
        // Connect both peers on one paused in-memory stream
        testing::init_tracing();
        let tester = test_clock();
        let signer_key = xdsa::SecretKey::generate();
        let signer_pub = signer_key.public_key();
        let attestation = self_attestation(&signer_key);
        let presented = attestation.clone();
        let (host, ark) = memory::duplex(64 * 1024, &tester.clock());

        // Receive two messages on the Ark side across two sessions, echoing each
        let ark_thread = std::thread::spawn(move || {
            let mut server = Server::new(ark, signer_key, attestation);
            let mut sender = None;
            let mut requests = Vec::new();
            for _ in 0..2 {
                let req = testing::served(&mut server, &mut sender).unwrap();
                sender.as_ref().unwrap().send(&req).unwrap();
                requests.push(req);
            }
            requests
        });

        // Open the first session, check the attestation and exchange one message
        let mut client = Client::new(host);
        let (sender, attest) = client.connect(&signer_pub).unwrap();
        assert_eq!(attest.as_bytes(), presented.as_bytes());
        sender.send(&payload(1)).unwrap();
        assert_eq!(client.recv().unwrap(), payload(1));

        // Inject a frame the server cannot decrypt. It drops the session and
        // signals it. The client's next read reports a reset, and its old sender
        // cannot send again.
        client.send_packet_blob(b"interrupted transfer").unwrap();
        let result = client.recv();
        assert!(matches!(result, Err(Error::SessionReset)), "{result:?}");
        let result = sender.send(&payload(2));
        assert!(
            matches!(result, Err(Error::EncryptionFailed(_))),
            "{result:?}"
        );

        // Open a second session on the same stream and exchange one message
        let (sender, _) = client.connect(&signer_pub).unwrap();
        sender.send(&payload(2)).unwrap();
        assert_eq!(client.recv().unwrap(), payload(2));

        // Require the server to have received both messages in order
        let requests = ark_thread.join().unwrap();
        assert_eq!(requests, vec![payload(1), payload(2)]);
    }

    /// Tests that an untrusting verifier rejects the session on the client side.
    #[test]
    fn test_verifier_rejects() {
        testing::init_tracing();

        /// Verifier refusing every attestation.
        struct Untrusting;

        impl Verifier for Untrusting {
            type Info = ();

            fn verify(
                &self,
                _: &Attestation,
                _: std::time::SystemTime,
            ) -> Result<(xdsa::PublicKey, Self::Info), String> {
                Err("attestation rejected".into())
            }
        }

        // Connect both peers on one paused in-memory stream
        let signer_key = xdsa::SecretKey::generate();
        let tester = test_clock();
        let (host, ark) = memory::duplex(64 * 1024, &tester.clock());

        // Serve handshakes on the Ark side until the transport drops. The client
        // aborts mid-handshake, so the server never delivers a message.
        let ark_thread = std::thread::spawn(move || {
            let attestation = self_attestation(&signer_key);
            let mut server = Server::new(ark, signer_key, attestation);
            let mut sender = None;
            testing::served(&mut server, &mut sender)
        });

        // Refuse the attestation in the client's verifier
        let mut client = Client::new(host);
        let result = client.connect(&Untrusting);
        assert!(result.is_err());

        // Dropping the client tears down the transport, unblocking the server
        drop(client);
        assert!(ark_thread.join().unwrap().is_err());
    }

    /// Tests that the roots verifier accepts attestations under the trusted
    /// roots and refuses the others.
    #[test]
    fn test_roots_verifier() {
        testing::init_tracing();

        use crate::transport::Roots;
        use darkbio_crypto::cwt;
        use darkbio_crypto::cwt::claims::{self, eat};
        use darkbio_trust::device::{EmulatorClaims, HardwareClaims};
        use darkbio_trust::{CRYPTO_DOMAIN_DEVICE_ATTESTATION, Realm};
        use std::time::UNIX_EPOCH;

        // Issue every attestation at the paused clock's wall time
        let tester = test_clock();
        let clock = tester.clock();
        let now = clock
            .system_time()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        /// Runs a handshake with the given attestation and trusted roots,
        /// returning the client's verification result.
        fn handshake(
            clock: &Clock,
            signer_key: xdsa::SecretKey,
            attestation: Attestation,
            hardware: &[xdsa::PublicKey],
            emulator: &[xdsa::PublicKey],
        ) -> Result<darkbio_trust::device::Device, Error> {
            // Serve a fresh stream on the Ark side while the client verifies
            // the attestation through the roots
            let (host, ark) = memory::duplex(64 * 1024, clock);
            let ark_thread = std::thread::spawn(move || {
                let mut server = Server::new(ark, signer_key, attestation);
                let mut sender = None;
                testing::served(&mut server, &mut sender)
            });
            let mut client = Client::new(host);
            let result = client
                .connect(&Roots { hardware, emulator })
                .map(|(_, info)| info);

            // Dropping the client tears down the transport, unblocking the server
            drop(client);
            let _ = ark_thread.join().unwrap();
            result
        }

        // Trust one hardware root and one emulator root
        let hardware_root = xdsa::SecretKey::generate();
        let emulator_root = xdsa::SecretKey::generate();
        let hardware_roots = [hardware_root.public_key()];
        let emulator_roots = [emulator_root.public_key()];

        // A hardware server attested by a hardware root is accepted with its
        // identity
        let signer_key = xdsa::SecretKey::generate();
        let attestation = cwt::issue_at(
            &HardwareClaims {
                sub: claims::Subject {
                    sub: "ark-1234".into(),
                },
                cnf: claims::Confirm::new(signer_key.public_key()),
                nbf: claims::NotBefore { nbf: now - 10 },
                iat: claims::IssuedAt { iat: now - 10 },
                oem: eat::Oemid::new_pen(65145),
                hwm: eat::HwModel {
                    hw_model: b"Ark I".to_vec(),
                },
                hwv: eat::HwVersion::new("Ark I - 1.0.0".into()),
            },
            &hardware_root,
            CRYPTO_DOMAIN_DEVICE_ATTESTATION,
            now as i64,
        )
        .map(|cwt| Attestation::new(cwt).unwrap())
        .unwrap();
        let device = handshake(
            &clock,
            signer_key,
            attestation.clone(),
            &hardware_roots,
            &[],
        )
        .unwrap();
        assert_eq!(device.realm, Realm::Hardware);
        assert_eq!(device.serial, "ark-1234");

        // A hardware attestation is refused when only emulator roots are trusted
        let signer_key = xdsa::SecretKey::generate();
        assert!(handshake(&clock, signer_key, attestation, &[], &emulator_roots).is_err());

        // An emulated server attested by an emulator root is accepted with its
        // expiry
        let signer_key = xdsa::SecretKey::generate();
        let attestation = cwt::issue_at(
            &EmulatorClaims {
                sub: claims::Subject {
                    sub: "emu-1234".into(),
                },
                cnf: claims::Confirm::new(signer_key.public_key()),
                nbf: claims::NotBefore { nbf: now - 10 },
                exp: claims::Expiration { exp: now + 1000 },
                iat: claims::IssuedAt { iat: now - 10 },
                oem: eat::Oemid::new_pen(65145),
                hwm: eat::HwModel {
                    hw_model: b"Ark I".to_vec(),
                },
                hwv: eat::HwVersion::new("Ark I - 1.0.0".into()),
            },
            &emulator_root,
            CRYPTO_DOMAIN_DEVICE_ATTESTATION,
            now as i64,
        )
        .map(|cwt| Attestation::new(cwt).unwrap())
        .unwrap();
        let device = handshake(
            &clock,
            signer_key,
            attestation,
            &hardware_roots,
            &emulator_roots,
        )
        .unwrap();
        assert_eq!(device.realm, Realm::Emulator);
        assert_eq!(device.expiry, Some(now + 1000));

        // A never onboarded server presenting a self-signed attestation is refused
        let signer_key = xdsa::SecretKey::generate();
        let attestation = cwt::issue_at(
            &HardwareClaims {
                sub: claims::Subject { sub: "".into() },
                cnf: claims::Confirm::new(signer_key.public_key()),
                nbf: claims::NotBefore { nbf: 0 },
                iat: claims::IssuedAt { iat: 0 },
                oem: eat::Oemid::new_pen(0),
                hwm: eat::HwModel { hw_model: vec![] },
                hwv: eat::HwVersion::new("".into()),
            },
            &signer_key,
            CRYPTO_DOMAIN_DEVICE_ATTESTATION,
            now as i64,
        )
        .map(|cwt| Attestation::new(cwt).unwrap())
        .unwrap();
        assert!(
            handshake(
                &clock,
                signer_key,
                attestation,
                &hardware_roots,
                &emulator_roots
            )
            .is_err()
        );
    }

    /// Tests that attestation construction accepts hardware and emulator claims
    /// and rejects junk or CWTs carrying other claim types.
    #[test]
    fn test_attestation_shapes() {
        use darkbio_crypto::cwt::claims;
        use darkbio_trust::CRYPTO_DOMAIN_DEVICE_ATTESTATION;

        // Accept hardware claims through the self-signed helper
        let signer = xdsa::SecretKey::generate();
        let _ = self_attestation(&signer);

        // Accept emulator claims
        let emulator = darkbio_trust::device::EmulatorClaims {
            sub: claims::Subject { sub: "".into() },
            cnf: claims::Confirm::new(signer.public_key()),
            nbf: claims::NotBefore { nbf: 0 },
            exp: claims::Expiration { exp: u64::MAX },
            iat: claims::IssuedAt { iat: 0 },
            oem: claims::eat::Oemid::new_pen(0),
            hwm: claims::eat::HwModel { hw_model: vec![] },
            hwv: claims::eat::HwVersion::new("".into()),
        };
        let cwt = cwt::issue_at(
            &emulator,
            &signer,
            CRYPTO_DOMAIN_DEVICE_ATTESTATION,
            crate::transport::mock::TIMESTAMP,
        )
        .unwrap();
        Attestation::new(cwt).expect("emulator attestation refused");

        // Refuse the claims of a cloud signer and bytes that are no CWT at all
        let cloud = darkbio_trust::cloud::SignerClaims {
            iss: claims::Issuer { iss: "".into() },
            sub: claims::Subject { sub: "".into() },
            nbf: claims::NotBefore { nbf: 0 },
            exp: claims::Expiration { exp: 1 },
            cnf: claims::Confirm::new(signer.public_key()),
        };
        let cwt = cwt::issue_at(
            &cloud,
            &signer,
            CRYPTO_DOMAIN_DEVICE_ATTESTATION,
            crate::transport::mock::TIMESTAMP,
        )
        .unwrap();
        let result = Attestation::new(cwt).map(|_| ());
        assert!(
            matches!(result, Err(Error::InvalidAttestation)),
            "{result:?}"
        );
        let result = Attestation::new(b"junk".to_vec()).map(|_| ());
        assert!(
            matches!(result, Err(Error::InvalidAttestation)),
            "{result:?}"
        );
    }

    /// Tests that other threads can send while the server blocks in a read.
    ///
    /// The client must receive every message in encryption order to decrypt it.
    #[test]
    fn test_senders() {
        testing::init_tracing();

        // Connect both peers on one paused in-memory stream
        let signer_key = xdsa::SecretKey::generate();
        let signer_pub = signer_key.public_key();
        let attestation = self_attestation(&signer_key);
        let tester = test_clock();
        let (host, ark) = memory::duplex(64 * 1024, &tester.clock());

        // After the first request, push messages on the Ark side from a few
        // threads while the server waits for the second request
        let ark_thread = std::thread::spawn(move || {
            let mut server = Server::new(ark, signer_key, attestation);
            let mut sender = None;
            testing::served(&mut server, &mut sender).unwrap();

            let pushers: Vec<_> = (0..4)
                .map(|thread| {
                    let sender = sender.as_ref().unwrap().clone();
                    std::thread::spawn(move || {
                        for i in 0..25 {
                            sender.send(&payload(thread * 100 + i)).unwrap();
                        }
                    })
                })
                .collect();
            let stop = testing::served(&mut server, &mut sender).unwrap();
            for pusher in pushers {
                pusher.join().unwrap();
            }
            stop
        });

        // Request the push from the client
        let mut client = Client::new(host);
        let (sender, _) = client.connect(&signer_pub).unwrap();
        sender.send(&payload(1)).unwrap();

        // Receive every pushed message, whichever thread sent it
        let mut pushed: Vec<Vec<u8>> = (0..100).map(|_| client.recv().unwrap()).collect();
        pushed.sort_unstable();
        let mut expected: Vec<Vec<u8>> = (0..4)
            .flat_map(|thread| (0..25).map(move |i| payload(thread * 100 + i)))
            .collect();
        expected.sort_unstable();
        assert_eq!(pushed, expected);

        // Request the stop, which the server returns once its pushers finish
        sender.send(&payload(2)).unwrap();
        assert_eq!(ark_thread.join().unwrap(), payload(2));
    }
}
