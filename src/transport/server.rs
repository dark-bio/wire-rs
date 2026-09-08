// wire-rs: encrypted protocol between Ark and host
// Copyright 2025 Dark Bio AG. All rights reserved.

use crate::transport::framing::FrameReader;
use crate::transport::handshake;
use crate::transport::outbound::{Outbound, Side};
use crate::transport::sealing;
use crate::transport::sender::{EndOnPanic, Sender};
use crate::transport::{
    CRYPTO_DOMAIN_WIRE, CRYPTO_DOMAIN_WIRE_ARK_TO_HOST, CRYPTO_DOMAIN_WIRE_HOST_TO_ARK, Closer,
    Error, Stream,
};
use darkbio_crypto::{cbor, cose, cwt, xdsa, xhpke};
use darkbio_trust as trust;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tracing::{info, trace, warn};

/// Device attestation a server presents in the handshake, a CWT in one of the
/// shapes darkbio-trust defines (hardware or emulator claims). Only the shape
/// is checked, so an obviously wrong blob is refused up front; whether it is
/// accepted is the client's decision.
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

/// Source of the device attestation the server presents in the handshake; queried
/// on every handshake, so a freshly onboarded attestation can be picked up
/// without recreating the wire.
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
    /// An encrypted session was established. The sender stays bound to it, even
    /// after it ends and another session opens. This reports a completed handshake;
    /// concurrent sending or stream closure may make the sender unusable before
    /// the event is handled.
    Connected(Sender<W>),

    /// The previously opened session ended through a peer reset, invalid
    /// incoming data or an observed send failure. A peer reset leaves a handshake
    /// for the next read to run. A local [`Server::disconnect`] does not emit this
    /// event. Permanent stream closure is reported through I/O results instead.
    Disconnected,

    /// A message of the client's, decrypted.
    Message(Vec<u8>),
}

/// Server side of the wire, accepting encrypted sessions over a supplied byte
/// stream. [`Server::recv`] handles client resets and handshakes, returning
/// [`Event::Connected`] with a [`Sender`] for each established session. Subsequent
/// reads deliver decrypted messages or report that the session ended.
/// [`Server::disconnect`] ends a session while leaving the stream available for
/// another; [`Server::close`] permanently closes the stream.
///
/// On a local disconnect, a session failure, a failed handshake or data received
/// outside a session, the server sends an empty frame. A client still holding a
/// session thus learns it is gone instead of having to time out.
///
/// The device attestation is not interpreted by the wire, it is provided by an
/// [`Attester`] and forwarded to the client verbatim.
pub struct Server<R: Read, W: Write, A: Attester> {
    reader: FrameReader<R>,     // COBS framed transport for ingress data
    outbound: Arc<Outbound<W>>, // Outgoing transport, shared with the senders

    signer: xdsa::SecretKey, // Server's identity key, signing the ArkHello
    attester: A,             // Source of the device attestation for handshakes

    receiver: Option<xhpke::Receiver>, // Receive context used exclusively by this server
    sealer: Option<Arc<Mutex<xhpke::Sender>>>, // Send context shared with active sends
    ended: Arc<AtomicBool>,            // Termination flag shared with the sender and writer

    handshaking: bool, // Whether a reset arrived, the handshake it calls for still to run

    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    timestamp: Option<i64>, // Signing time of the ArkHello pinned by a test, the clock otherwise
}

impl<R: Read, W: Write, A: Attester> Server<R, W, A> {
    /// Creates a server owning the byte stream and its shutdown operation. The signer is
    /// the server's identity key, which signs the handshake. The client verifies that
    /// signature against the key it extracts from the attestation, so the two
    /// must match. I/O deadlines and cancellation bounds are supplied by the
    /// stream adapter.
    pub fn new(stream: Stream<R, W>, signer: xdsa::SecretKey, attester: A) -> Self {
        let (reader, writer, close) = stream.into_parts();
        let outbound = Arc::new(Outbound::new(writer, Side::Server, close.clone()));
        Self {
            reader: FrameReader::new(reader, close),
            outbound,
            signer,
            attester,
            receiver: None,
            sealer: None,
            ended: Arc::new(AtomicBool::new(true)),
            handshaking: false,
            #[cfg(any(test, feature = "bench", feature = "fuzz"))]
            timestamp: None,
        }
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

    /// Test helper creating a server side signing its ArkHellos at the given
    /// time instead of the clock, so a run of it is the same every time. Not
    /// part of the API.
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
    /// A client reset, invalid incoming data or an observed send failure ends
    /// the current session and returns [`Event::Disconnected`]. After a reset,
    /// the next call runs the handshake. A send failure does not wake a blocked
    /// read; it is observed when receiving progresses. A session ended locally
    /// by [`Server::disconnect`] is not reported again.
    ///
    /// Junk outside a session and failed handshakes are logged, answered with
    /// an empty frame and skipped. Transport receive failures surface as errors.
    pub fn recv(&mut self) -> Result<Event<W>, Error> {
        // Loop until we can deliver a valid decrypted message. Empty frames
        // are consumed and call for a handshake, run on the pass after them.
        loop {
            // If a reset just arrived, run the handshake
            if std::mem::take(&mut self.handshaking) {
                match self.handshake() {
                    // Transport errors propagate immediately
                    Err(Error::Terminated) => return Err(Error::Terminated),
                    Err(Error::RecvFailed(err)) => return Err(Error::RecvFailed(err)),

                    // Decode or protocol errors are logged and ignored, the
                    // client learning that no session came out of it
                    Err(err) => {
                        warn!("wire handshake failed: {}", err);
                        self.send_dropped();
                    }
                    // Handshake successful, the ack read ahead of anything
                    // sealed into the session, which is reported so a caller
                    // can send into it before the client says anything
                    Ok((sender, receiver)) => {
                        info!("new wire session established");
                        let sender = self.new_session(sender, receiver);
                        return Ok(Event::Connected(sender));
                    }
                }
                continue;
            }
            // Retrieve the next COBS encoded packet
            let packet = match self.reader.next_packet() {
                // Transport errors propagate immediately
                Err(Error::Terminated) => return Err(Error::Terminated),
                Err(Error::RecvFailed(err)) => return Err(Error::RecvFailed(err)),

                // Decode errors may be due to session resets, log and ignore.
                // Within a session the skipped frame may have carried a sealed
                // message though, leaving the HPKE sequence behind the client's,
                // so the session cannot continue either way.
                Err(err) => {
                    let ended = self.end_session();
                    if ended {
                        warn!("failed to decode cobs packet, resetting session: {}", err);
                    } else {
                        warn!("failed to decode cobs packet: {}", err);
                    }
                    self.send_dropped();
                    if ended {
                        return Ok(Event::Disconnected);
                    }
                    continue;
                }
                // Empty frame signals a session reset from the client. Report
                // any active session terminated, leaving running the handshake
                // for the next pass of the loop.
                Ok(None) => {
                    self.handshaking = true;
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
            // Sending can end the session before receiving observes it. The
            // contexts are released when receiving reports that end.
            let opened = if self.ended.load(Ordering::Acquire) {
                Err(Error::EncryptionFailed("session ended".into()))
            } else {
                let _end_on_panic = EndOnPanic(&self.ended);
                sealing::open(receiver, packet)
                    .inspect_err(|_| self.ended.store(true, Ordering::Release))
            };
            let message = match opened {
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

    /// Retains the contexts negotiated by a completed handshake and returns a
    /// sender bound to the sending context's allocation. The server uses the
    /// receive context directly and shares the sending context with active sends.
    /// Idle senders hold weak references and keep neither context nor stream alive.
    /// Each handshake gets a fresh termination flag, so ending an old session
    /// cannot invalidate its replacement.
    ///
    /// Binding takes the writer lock, ordering replacement with in-flight writes
    /// and invalidating previous senders. After binding, old senders cannot write
    /// into the new session. This method performs no handshake or stream I/O.
    fn new_session(&mut self, sender: xhpke::Sender, receiver: xhpke::Receiver) -> Sender<W> {
        let sealer = Arc::new(Mutex::new(sender));
        let ended = Arc::new(AtomicBool::new(false));
        let sender = self.outbound.bind(&sealer, &ended);
        self.receiver = Some(receiver);
        self.sealer = Some(sealer);
        self.ended = ended;
        sender
    }

    /// Marks the current termination flag ended, releases the receive context,
    /// and releases the server's reference to the sending context. Active sends
    /// may still retain that context, but observe the same termination flag.
    /// Takes no encryption or writer lock; a write already admitted may finish.
    ///
    /// Returns true when a session was removed, including one already ended by
    /// a send failure. That failure leaves the receive context present until
    /// receiving observes it. The receive loop uses this result to emit one
    /// [`Event::Disconnected`]; later calls return false until another handshake
    /// establishes a session. Local [`Server::disconnect`] ignores the result
    /// because its caller already knows the session ended.
    ///
    /// Leaves the stream open and sends no notification. The calling operation
    /// decides whether to send an empty frame to the client.
    fn end_session(&mut self) -> bool {
        self.ended.store(true, Ordering::Release);
        self.sealer = None;
        self.receiver.take().is_some()
    }

    /// Tells the client that the server has no session with it by sending an empty
    /// frame.
    fn send_dropped(&self) {
        if let Err(err) = self.outbound.send_dropped() {
            warn!("failed to signal dropped session: {}", err);
        }
    }

    /// Ends the encrypted session and tells the client with an empty frame.
    /// The stream remains available for the client to connect again. Notification
    /// failures are logged. This local action does not produce an
    /// [`Event::Disconnected`], since the caller already knows the session ended.
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
    fn handshake(&mut self) -> Result<(xhpke::Sender, xhpke::Receiver), Error> {
        self.outbound.unbind();
        loop {
            // Message 1: Read the HostHello (skip any trailing empty reset frames)
            let packet = loop {
                if let Some(packet) = self.reader.next_packet()? {
                    break packet;
                }
            };
            let host_hello: handshake::HostHello = cbor::decode(packet)
                .map_err(|err| Error::HandshakeFailed(format!("invalid client hello: {}", err)))?;

            // Generate an ephemeral server xHPKE keypair and set up the server->Client sender
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

            self.outbound.send_packet(&ark_hello)?;

            // Message 3: Read and open the HostAck. An empty frame probably
            // means the client is restarting the session, start over.
            let Some(packet) = self.reader.next_packet()? else {
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

            // Set up the Client->server receiver
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
            return Ok((sender, receiver));
        }
    }
}

impl<R: Read, W: Write, A: Attester> Drop for Server<R, W, A> {
    /// Permanently closes the stream, waits for adapter shutdown, and marks the
    /// session ended before releasing its contexts. Idle senders hold only weak
    /// references, so they cannot keep the outbound side alive.
    fn drop(&mut self) {
        let _end_on_panic = EndOnPanic(&self.ended);
        self.outbound.close();
        self.ended.store(true, Ordering::Release);
    }
}

#[cfg(all(test, unix))]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::testing;
    use crate::transport::mock::payload;
    use crate::transport::{Client, Verifier};
    use darkbio_cobs as cobs;
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    /// Self-signed attestation of a never onboarded device, the placeholder an
    /// Server presents before it is attested by a root.
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

    // Tests the two real sides against each other. The handshake hands the
    // attestation to the client's verifier unchanged and a request gets its
    // response. The server's signal for a dropped session then surfaces on the
    // client as a reset, which a fresh handshake recovers from.
    #[test]
    fn test_message_round_trip() {
        testing::init_tracing();

        let signer_key = xdsa::SecretKey::generate();
        let signer_pub = signer_key.public_key();
        let attestation = self_attestation(&signer_key);
        let presented = attestation.clone();

        let (host_sock, ark_sock) = UnixStream::pair().unwrap();
        let ark_reader = ark_sock.try_clone().unwrap();
        let ark_writer = ark_sock;

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
            host_sock.try_clone().unwrap(),
            host_sock,
            || {},
        ));
        let (sender, attest) = client.connect(&signer_pub).unwrap();
        assert_eq!(attest.as_bytes(), presented.as_bytes());
        sender.send(&payload(1)).unwrap();
        assert_eq!(client.recv().unwrap(), payload(1));

        // Inject a frame the server cannot decrypt. It drops the session and
        // signals it, the client surfacing the signal as a reset on its next
        // read and refusing to send into the dead session afterwards.
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

        let (host_sock, ark_sock) = UnixStream::pair().unwrap();
        let ark_reader = ark_sock.try_clone().unwrap();
        let ark_writer = ark_sock;

        // Server side: serve handshakes until the transport drops. The client aborts
        // mid-handshake, so the server never delivers a message.
        let ark_thread = std::thread::spawn(move || {
            let attestation = self_attestation(&signer_key);
            let mut server = Server::new(
                Stream::new(ark_reader, ark_writer, || {}),
                signer_key,
                attestation,
            );
            let mut sender = None;
            testing::served(&mut server, &mut sender)
        });

        // Client side: refuse the attestation in the verifier.
        let mut client = Client::new(Stream::new(
            host_sock.try_clone().unwrap(),
            host_sock,
            || {},
        ));
        let result = client.connect(&Untrusting);
        assert!(result.is_err());

        // Dropping the client tears down the transport, unblocking the server.
        drop(client);
        assert!(ark_thread.join().unwrap().is_err());
    }

    // Tests that the roots verifier opens sessions with root attested Arks of
    // either realm, handing back their verified identity. Arks attested under
    // unknown roots or self-signed ones are refused.
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

        /// Drives a handshake with a server presenting the attestation and the client
        /// trusting the roots, returning the client's verdict.
        fn handshake(
            signer_key: xdsa::SecretKey,
            attestation: Attestation,
            hardware: &[xdsa::PublicKey],
            emulator: &[xdsa::PublicKey],
        ) -> Result<darkbio_trust::device::Device, Error> {
            let (host_sock, ark_sock) = UnixStream::pair().unwrap();
            let ark_reader = ark_sock.try_clone().unwrap();
            let ark_writer = ark_sock;

            let ark_thread = std::thread::spawn(move || {
                let mut server = Server::new(
                    Stream::new(ark_reader, ark_writer, || {}),
                    signer_key,
                    attestation,
                );
                let mut sender = None;
                testing::served(&mut server, &mut sender)
            });
            let mut client = Client::new(Stream::new(
                host_sock.try_clone().unwrap(),
                host_sock,
                || {},
            ));
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

        // The same server is refused by a client trusting only emulator roots
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

    // Tests that only CWTs in a device attestation shape are accepted as
    // attestations, junk and other token shapes being refused up front.
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

    // Tests that the server sends through senders from other threads while
    // it blocks in a read, the client receiving every message in the order
    // sealed, or it would find its session dropped instead.
    #[test]
    fn test_senders() {
        testing::init_tracing();

        let signer_key = xdsa::SecretKey::generate();
        let signer_pub = signer_key.public_key();
        let attestation = self_attestation(&signer_key);

        let (host_sock, ark_sock) = UnixStream::pair().unwrap();
        let ark_reader = ark_sock.try_clone().unwrap();
        let ark_writer = ark_sock;

        // Server side: on the first request, push messages from a few threads
        // while waiting for the second request.
        let ark_thread = std::thread::spawn(move || {
            let mut server = Server::new(
                Stream::new(ark_reader, ark_writer, || {}),
                signer_key,
                attestation,
            );
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
        let mut client = Client::new(Stream::new(
            host_sock.try_clone().unwrap(),
            host_sock,
            || {},
        ));
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
