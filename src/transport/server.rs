// wire-rs: encrypted protocol between Ark and host
// Copyright 2025 Dark Bio AG. All rights reserved.

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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{info, trace, warn};

/// Device attestation presented during the handshake. The CWT must contain
/// hardware or emulator claims as defined by darkbio-trust. Construction checks
/// that shape; the client's verifier decides whether to trust the attestation.
#[derive(Clone)]
pub struct Attestation(Vec<u8>);

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

    /// CWT bytes of the attestation.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Unwraps the attestation into its CWT bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// Supplies the server's device attestation on every handshake. This lets the
/// server pick up a new attestation after onboarding without recreating transport.
pub trait Attester {
    /// Returns the device attestation to present to the client (e.g. a root-signed
    /// CWT read from disk, or a self-signed fallback for pre-onboarding devices).
    /// The identity key it embeds must be the one signing the wire's handshake.
    fn attest(&mut self) -> Attestation;
}

/// A fixed attestation, presented as is on every handshake.
impl Attester for Attestation {
    fn attest(&mut self) -> Attestation {
        self.clone()
    }
}

/// A decrypted message or encrypted session transition returned by [`Server::recv`].
/// Events arrive in receive order and refer to sessions over the existing byte
/// stream. Permanent stream closure is observed through I/O results.
#[derive(Debug)]
pub enum Event<W: Write> {
    /// A handshake completed and established an encrypted session. The sender
    /// belongs to that session and cannot send into a later replacement.
    /// Concurrent send failure or stream closure may make it unusable before
    /// the caller handles the event.
    Connected(Sender<W>),

    /// The previously opened session ended through a peer reset, invalid
    /// incoming data or an observed send failure. After a peer reset, the next
    /// receive call runs the handshake. A local [`Server::disconnect`] does not emit this
    /// event. Permanent stream closure is reported through I/O results instead.
    Disconnected,

    /// A decrypted message from the client.
    Message(Vec<u8>),
}

/// Server side of the wire, accepting encrypted sessions over a supplied byte
/// stream. [`Server::recv`] handles client resets and handshakes. Each successful
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
/// client, whose verifier decides whether to trust it.
pub struct Server<R: Read, W: Write, A: Attester> {
    reader: FrameReader<R>,     // COBS framed transport for ingress data
    outbound: Arc<Outbound<W>>, // Outgoing transport, shared with the senders

    signer: xdsa::SecretKey, // Server's identity key, signing the ArkHello
    attester: A,             // Source of the device attestation for handshakes

    receiver: Option<xhpke::Receiver>, // Receive context used exclusively by this server
    sealer: Option<Arc<Mutex<xhpke::Sender>>>, // Send context shared with active sends

    handshake_timeout: Duration, // Budget for each new handshake attempt
    handshake_deadline: Option<Instant>, // Deadline of the handshake requested by a reset

    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    timestamp: Option<i64>, // Test signing time for ArkHello; otherwise use the clock
}

impl<R: Read, W: Write, A: Attester> Server<R, W, A> {
    /// Creates a server owning the byte stream and its shutdown operation.
    /// The signer is the server's identity key. It must match the key embedded
    /// in the device attestation. Output uses the stream's configured write
    /// timeout. The adapter must enforce deadlines and shutdown cancellation.
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
            #[cfg(any(test, feature = "bench", feature = "fuzz"))]
            timestamp: None,
        }
    }

    /// Sets the budget for each subsequent handshake, starting when a reset is
    /// received. Defaults to [`DEFAULT_HANDSHAKE_TIMEOUT`]. Output and peer
    /// replies share one deadline; progress and repeated resets within the attempt
    /// do not refresh it. An already pending handshake keeps its deadline. Each
    /// outgoing frame is also limited by the stream's write timeout. Waiting for
    /// locks and attester callbacks can extend the call beyond the deadline.
    /// Time between recv calls also consumes the budget.
    ///
    /// Zero expires attempts immediately. A duration too large to add to an
    /// [`Instant`] panics when the next handshake's deadline is constructed.
    pub fn set_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// A handle that permanently closes the stream from another thread.
    pub fn closer(&self) -> Closer {
        self.outbound.closer()
    }

    /// Permanently closes the stream and waits for adapter shutdown. Senders
    /// observe closure through write failure; buffered messages remain readable.
    /// See [`Closer::close`].
    pub fn close(&self) {
        self.outbound.close();
    }

    /// Creates a test server with a fixed ArkHello signing time for vector replay.
    /// Not part of the normal transport API.
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

    /// Receives a decrypted message or a session transition. A client reset
    /// starts a handshake, whose completion returns [`Event::Connected`] with
    /// a sender before any messages from that session are delivered.
    ///
    /// A client reset or invalid incoming data ends the current session and
    /// returns [`Event::Disconnected`]. Oversized frames count as invalid data.
    /// After a reset, the next call runs the handshake under one configured
    /// deadline starting at that reset. Repeated resets within that attempt do
    /// not refresh it. Expiry returns `RecvFailed(TimedOut)` and a fresh reset
    /// can start another attempt. A send failure also ends
    /// the session, but does not wake a blocked read. It is reported once
    /// receiving progresses. Sessions ended by a local disconnect are not
    /// reported again.
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
                    // Outbound already attempted notification within the failed
                    // frame's budget; a fresh attempt here could block again.
                    Err(Error::SendFailed(err)) => return Err(Error::SendFailed(err)),

                    // Tell the client that the handshake did not establish a session
                    Err(err) => {
                        warn!("wire handshake failed: {}", err);
                        if let Err(err) = self.outbound.send_dropped(Some(deadline)) {
                            warn!("failed to signal dropped handshake: {}", err);
                        }
                        // Do not swallow an attempt deadline exhausted during
                        // authentication or its failure notification.
                        check_deadline(deadline).map_err(Error::RecvFailed)?;
                    }
                    // Report the completed handshake before reading messages.
                    // The caller can now send without waiting for a client request.
                    Ok((sender, receiver)) => {
                        info!("new wire session established");
                        let sender = self.new_session(sender, receiver);
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
                // session because its encryption sequence can no longer be trusted.
                Err(err) => {
                    let ended = self.end_session();
                    if ended {
                        warn!("invalid frame, resetting session: {}", err);
                    } else {
                        warn!("invalid frame: {}", err);
                    }
                    self.send_dropped();
                    if ended {
                        return Ok(Event::Disconnected);
                    }
                    continue;
                }
                // A reset ends any active session. Run the handshake on the next
                // receive call if we return an event, or on the next loop pass.
                Ok(None) => {
                    self.handshake_deadline = Some(Instant::now() + self.handshake_timeout);
                    if self.end_session() {
                        return Ok(Event::Disconnected);
                    }
                    continue;
                }
                // Valid COBS packet
                Ok(Some(packet)) => packet,
            };
            let receiver = match self.receiver.as_mut() {
                None => {
                    warn!("dropping data outside session");
                    self.send_dropped();
                    continue;
                }
                Some(receiver) => receiver,
            };
            // Finish after decrypting, ordering message acceptance with a send
            // failure without ever waiting for the writer on a successful receive.
            let sealer = self
                .sealer
                .as_ref()
                .expect("receiver has a sending context");
            let opened = sealing::open(receiver, packet);
            let message = match self.outbound.finish_receive(sealer, opened) {
                Err(err) => {
                    warn!("session receive failed, resetting session: {}", err);
                    self.end_session();
                    self.send_dropped();
                    return Ok(Event::Disconnected);
                }
                Ok(message) => message,
            };
            trace!(
                "read host-to-ark message ({} bytes encrypted)",
                packet.len()
            );
            return Ok(Event::Message(message));
        }
    }

    /// Stores the negotiated contexts and returns a sender for the new session.
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
        self.receiver = Some(receiver);
        self.sealer = Some(sealer);
        sender
    }

    /// Ends the current binding before releasing the server's crypto contexts.
    /// Waits for the writer. After this returns, no write or flush for that
    /// session is running or can start. A send that gets the writer first may
    /// finish. A send still sealing after removal cannot write its packet.
    /// This takes no encryption lock and does not wait for crypto work.
    ///
    /// This does not close the stream or send a notification. An active write
    /// may delay ending until its frame deadline. Another thread can use the
    /// Closer to cancel I/O without taking the writer lock.
    ///
    /// Returns true if it removed a receive context, even if a send failure
    /// already ended the binding. The receive loop uses this removal to emit
    /// Disconnected once. Local disconnect ignores the result because its caller
    /// already knows the session ended.
    fn end_session(&mut self) -> bool {
        if let Some(sealer) = self.sealer.as_ref() {
            self.outbound.end(sealer);
        }
        self.sealer = None;
        self.receiver.take().is_some()
    }

    /// Sends an empty frame to tell the client it has no session. Logs failures.
    fn send_dropped(&self) {
        if let Err(err) = self.outbound.send_dropped(None) {
            warn!("failed to signal dropped session: {}", err);
        }
    }

    /// Ends the encrypted session and tells the client with an empty frame.
    /// The stream remains available for the client to connect again. Notification
    /// failures are logged. This does not produce a Disconnected event because
    /// the caller already knows the session ended.
    ///
    /// Waits for the current writer and its flush, then retires the binding.
    /// The notification gets its own frame budget. Another thread can use the
    /// Closer to cancel output earlier.
    pub fn disconnect(&mut self) {
        self.end_session();
        self.send_dropped();
    }

    /// Responds to the handshake after a session reset, establishing the
    /// HPKE contexts of both directions:
    ///
    ///   1. Client -> Server: HostHello { host_signer, host_crypto }           (plain CBOR)
    ///   2. Server -> Client: ArkHello  { ark_attest, ark_crypto, a2h_encap }  (cose::seal)
    ///   3. Client -> Server: HostAck   { h2a_encap }                          (cose::seal)
    fn handshake(&mut self, deadline: Instant) -> Result<(xhpke::Sender, xhpke::Receiver), Error> {
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
            #[cfg(not(any(test, feature = "bench", feature = "fuzz")))]
            let sealed = cose::seal(
                &ark_hello,
                &auth,
                &self.signer,
                &host_hello.host_crypto,
                CRYPTO_DOMAIN_WIRE,
            );
            #[cfg(any(test, feature = "bench", feature = "fuzz"))]
            let sealed = match self.timestamp {
                Some(timestamp) => cose::seal_at(
                    &ark_hello,
                    &auth,
                    &self.signer,
                    &host_hello.host_crypto,
                    CRYPTO_DOMAIN_WIRE,
                    timestamp,
                ),
                None => cose::seal(
                    &ark_hello,
                    &auth,
                    &self.signer,
                    &host_hello.host_crypto,
                    CRYPTO_DOMAIN_WIRE,
                ),
            };
            let ark_hello = sealed.map_err(|err| {
                Error::HandshakeFailed(format!("failed to seal server hello: {}", err))
            })?;

            self.outbound.send_packet(&ark_hello, Some(deadline))?;

            // Message 3: Read and open HostAck. An empty frame is another reset;
            // discard this attempt and wait for the next HostHello.
            let Some(packet) = self.reader.next_packet(Some(deadline))? else {
                warn!("session reset during handshake");
                continue;
            };
            let host_ack: handshake::HostAck = cose::open(
                packet,
                &handshake::HostAckAuth {
                    ark_signer: self.signer.public_key(),
                    ark_crypto: ark_crypto_pub.clone(),
                },
                &ark_crypto_key,
                &host_hello.host_signer,
                CRYPTO_DOMAIN_WIRE,
                None, // clock possibly unset, ephemeral keys guarantee freshness
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

            // Session established
            check_deadline(deadline).map_err(Error::RecvFailed)?;
            return Ok((sender, receiver));
        }
    }
}

impl<R: Read, W: Write, A: Attester> Drop for Server<R, W, A> {
    /// Closes the stream to cancel blocked I/O, then ends the binding before
    /// releasing the contexts. Shutdown must precede waiting for the writer.
    /// Idle senders hold weak references and cannot extend the stream's lifetime.
    fn drop(&mut self) {
        self.outbound.close();
        self.end_session();
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    #[cfg(unix)]
    use crate::testing::Socket;
    use crate::transport::mock::payload;
    use crate::transport::testing::Memory;
    use crate::transport::{Client, MAX_FRAME_SIZE, Verifier};
    use crate::{memory, testing};
    use darkbio_cobs as cobs;
    #[cfg(unix)]
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::net::UnixStream;

    /// Self-signed attestation for a device that has not been onboarded.
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
        let cwt = cwt::issue(
            &claims,
            signer,
            darkbio_trust::CRYPTO_DOMAIN_DEVICE_ATTESTATION,
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

    // Tests that an oversized server hello produces one failure notification.
    // It never reaches adapter I/O, so the handshake owns that notification;
    // the writer must not emit another one with its own budget. Dummy attestation
    // bytes isolate the framing limit: the server forwards them without parsing.
    #[test]
    fn test_oversized_hello_notifies_once() {
        testing::init_tracing();

        let hello = cbor::encode(&handshake::HostHello {
            host_signer: xdsa::SecretKey::generate().public_key(),
            host_crypto: xhpke::SecretKey::generate().public_key(),
        })
        .unwrap();
        let mut input = vec![0, 0];
        input.extend_from_slice(&cobs_frame(&hello));
        let mut output = Vec::new();
        let mut server = Server::new(
            Stream::new(Memory::new(&input[..]), Memory::new(&mut output), || {}),
            xdsa::SecretKey::generate(),
            Attestation(vec![0; MAX_FRAME_SIZE]),
        );

        assert!(matches!(server.recv(), Err(Error::Terminated)));
        drop(server);
        assert_eq!(output, [0]);
    }

    // Tests the two real sides against each other. The handshake hands the
    // attestation to the client's verifier unchanged and a request gets its
    // response. The server's signal for a dropped session then surfaces on the
    // client as a reset, which a fresh handshake recovers from.
    #[test]
    #[cfg(unix)]
    fn test_message_round_trip() {
        testing::init_tracing();

        let signer_key = xdsa::SecretKey::generate();
        let signer_pub = signer_key.public_key();
        let attestation = self_attestation(&signer_key);
        let presented = attestation.clone();

        let (host_sock, ark_sock) = UnixStream::pair().unwrap();
        let ark_reader = Socket::new(ark_sock.try_clone().unwrap());
        let ark_writer = Socket::new(ark_sock);

        // Server side: receive two messages (across two sessions), echo each back.
        let ark_thread = std::thread::spawn(move || {
            let mut server = Server::new(
                Stream::new(ark_reader, ark_writer, || {}),
                signer_key,
                attestation,
            );
            let mut sender = None;
            let mut requests = Vec::new();
            for _ in 0..2 {
                let req = testing::served(&mut server, &mut sender).unwrap();
                sender.as_ref().unwrap().send(&req).unwrap();
                requests.push(req);
            }
            requests
        });

        // Raw handle to inject bytes past the client side.
        let mut raw_sock = host_sock.try_clone().unwrap();

        // Session 1: handshake, checking the attestation, exchange one message.
        let mut client = Client::new(Stream::new(
            Socket::new(host_sock.try_clone().unwrap()),
            Socket::new(host_sock),
            || {},
        ));
        let (sender, attest) = client.connect(&signer_pub).unwrap();
        assert_eq!(attest.as_bytes(), presented.as_bytes());
        sender.send(&payload(1)).unwrap();
        assert_eq!(client.recv().unwrap(), payload(1));

        // Inject a frame the server cannot decrypt. It drops the session and
        // signals it. The client's next read reports a reset, and its old sender
        // cannot send again.
        raw_sock
            .write_all(&cobs_frame(b"interrupted transfer"))
            .unwrap();
        let result = client.recv();
        assert!(matches!(result, Err(Error::SessionReset)), "{result:?}");
        let result = sender.send(&payload(2));
        assert!(
            matches!(result, Err(Error::EncryptionFailed(_))),
            "{result:?}"
        );

        // Session 2: new handshake on the same wire, exchange one message.
        let (sender, _) = client.connect(&signer_pub).unwrap();
        sender.send(&payload(2)).unwrap();
        assert_eq!(client.recv().unwrap(), payload(2));

        let requests = ark_thread.join().unwrap();
        assert_eq!(requests, vec![payload(1), payload(2)]);
    }

    // Tests that an untrusting verifier rejects the session on the client side.
    #[test]
    fn test_verifier_rejects() {
        testing::init_tracing();

        /// Verifier refusing every attestation.
        struct Untrusting;

        impl Verifier for Untrusting {
            type Info = ();

            fn verify(&self, _: &Attestation) -> Result<(xdsa::PublicKey, Self::Info), String> {
                Err("attestation rejected".into())
            }
        }

        let signer_key = xdsa::SecretKey::generate();

        let (host, ark) = memory::duplex(64 * 1024);

        // Server side: serve handshakes until the transport drops. The client aborts
        // mid-handshake, so the server never delivers a message.
        let ark_thread = std::thread::spawn(move || {
            let attestation = self_attestation(&signer_key);
            let mut server = Server::new(ark, signer_key, attestation);
            let mut sender = None;
            testing::served(&mut server, &mut sender)
        });

        // Client side: refuse the attestation in the verifier.
        let mut client = Client::new(host);
        let result = client.connect(&Untrusting);
        assert!(result.is_err());

        // Dropping the client tears down the transport, unblocking the server.
        drop(client);
        assert!(ark_thread.join().unwrap().is_err());
    }

    // Tests that the roots verifier accepts hardware and emulator attestations
    // under the configured roots and returns the verified identity. Unknown
    // roots and self-signed attestations are refused.
    #[test]
    fn test_roots_verifier() {
        testing::init_tracing();

        use crate::transport::Roots;
        use darkbio_crypto::cwt;
        use darkbio_crypto::cwt::claims::{self, eat};
        use darkbio_trust::device::{EmulatorClaims, HardwareClaims};
        use darkbio_trust::{CRYPTO_DOMAIN_DEVICE_ATTESTATION, Realm};
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        /// Runs a handshake with the given attestation and trusted roots.
        /// Returns the client's verification result.
        fn handshake(
            signer_key: xdsa::SecretKey,
            attestation: Attestation,
            hardware: &[xdsa::PublicKey],
            emulator: &[xdsa::PublicKey],
        ) -> Result<darkbio_trust::device::Device, Error> {
            let (host, ark) = memory::duplex(64 * 1024);

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

        let hardware_root = xdsa::SecretKey::generate();
        let emulator_root = xdsa::SecretKey::generate();
        let hardware_roots = [hardware_root.public_key()];
        let emulator_roots = [emulator_root.public_key()];

        // A hardware server attested by a hardware root is accepted with its identity
        let signer_key = xdsa::SecretKey::generate();
        let attestation = cwt::issue(
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
        )
        .map(|cwt| Attestation::new(cwt).unwrap())
        .unwrap();
        let device = handshake(signer_key, attestation.clone(), &hardware_roots, &[]).unwrap();
        assert_eq!(device.realm, Realm::Hardware);
        assert_eq!(device.serial, "ark-1234");

        // A hardware attestation is refused when only emulator roots are trusted
        let signer_key = xdsa::SecretKey::generate();
        assert!(handshake(signer_key, attestation, &[], &emulator_roots).is_err());

        // An emulated server attested by an emulator root is accepted with its expiry
        let signer_key = xdsa::SecretKey::generate();
        let attestation = cwt::issue(
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
        )
        .map(|cwt| Attestation::new(cwt).unwrap())
        .unwrap();
        let device = handshake(signer_key, attestation, &hardware_roots, &emulator_roots).unwrap();
        assert_eq!(device.realm, Realm::Emulator);
        assert_eq!(device.expiry, Some(now + 1000));

        // A never onboarded server presenting a self-signed attestation is refused
        let signer_key = xdsa::SecretKey::generate();
        let attestation = cwt::issue(
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
        )
        .map(|cwt| Attestation::new(cwt).unwrap())
        .unwrap();
        assert!(handshake(signer_key, attestation, &hardware_roots, &emulator_roots).is_err());
    }

    // Tests that attestation construction accepts hardware and emulator claims
    // and rejects junk or CWTs containing other claim types.
    #[test]
    fn test_attestation_shapes() {
        use darkbio_crypto::cwt::claims;
        use darkbio_trust::CRYPTO_DOMAIN_DEVICE_ATTESTATION;

        let signer = xdsa::SecretKey::generate();
        let _ = self_attestation(&signer);

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
        let cwt = cwt::issue(&emulator, &signer, CRYPTO_DOMAIN_DEVICE_ATTESTATION).unwrap();
        Attestation::new(cwt).expect("emulator attestation refused");

        let cloud = darkbio_trust::cloud::SignerClaims {
            iss: claims::Issuer { iss: "".into() },
            sub: claims::Subject { sub: "".into() },
            nbf: claims::NotBefore { nbf: 0 },
            exp: claims::Expiration { exp: 1 },
            cnf: claims::Confirm::new(signer.public_key()),
        };
        let cwt = cwt::issue(&cloud, &signer, CRYPTO_DOMAIN_DEVICE_ATTESTATION).unwrap();
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

    // Tests sending from other threads while the server blocks in a read.
    // The client must receive every message in encryption order to decrypt it.
    #[test]
    fn test_senders() {
        testing::init_tracing();

        let signer_key = xdsa::SecretKey::generate();
        let signer_pub = signer_key.public_key();
        let attestation = self_attestation(&signer_key);

        let (host, ark) = memory::duplex(64 * 1024);

        // Server side: on the first request, push messages from a few threads
        // while waiting for the second request.
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

        // Client side: request the push, receive it all, then request the stop.
        let mut client = Client::new(host);
        let (sender, _) = client.connect(&signer_pub).unwrap();
        sender.send(&payload(1)).unwrap();

        let mut pushed: Vec<Vec<u8>> = (0..100).map(|_| client.recv().unwrap()).collect();
        pushed.sort_unstable();
        let mut expected: Vec<Vec<u8>> = (0..4)
            .flat_map(|thread| (0..25).map(move |i| payload(thread * 100 + i)))
            .collect();
        expected.sort_unstable();
        assert_eq!(pushed, expected);

        sender.send(&payload(2)).unwrap();
        assert_eq!(ark_thread.join().unwrap(), payload(2));
    }
}
