// wire-rs: encrypted protocol between Ark and host
// Copyright 2025 Dark Bio AG. All rights reserved.

use crate::framing::Framing;
use crate::handshake;
use crate::protocol::{ArkToHost, HostToArk};
use crate::session::Session;
use crate::{
    CRYPTO_DOMAIN_WIRE, CRYPTO_DOMAIN_WIRE_ARK_TO_HOST, CRYPTO_DOMAIN_WIRE_HOST_TO_ARK, Error,
};
use darkbio_crypto::{cbor, cose, cwt, xdsa, xhpke};
use darkbio_trust as trust;
use std::io::{Read, Write};
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

/// Server side of the wire, an encrypted transport for serving protobuf requests
/// from a connected client. It waits for session resets (empty frames), responds
/// to handshake and afterward decrypts inbound and encrypts outbound messages.
///
/// Whenever the server drops a session, fails a handshake or receives data while
/// it has no session, it answers with an empty frame of its own. A client still
/// holding a session thus learns it is gone instead of having to time out.
///
/// The device attestation is not interpreted by the wire, it is provided by an
/// `Attester` and forwarded to the client verbatim.
pub struct Server<R: Read, W: Write, A: Attester> {
    framing: Framing<R, W>, // COBS framed transport for ingress and egress data

    signer: xdsa::SecretKey,  // Server's identity key, signing the ArkHello
    attester: A,              // Source of the device attestation for handshakes
    session: Option<Session>, // Active encrypted session (if handshake completed)

    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    timestamp: Option<i64>, // Signing time of the ArkHello pinned by a test, the clock otherwise
}

impl<R: Read, W: Write, A: Attester> Server<R, W, A> {
    /// Creates a new server side around a low level reader and writer. The signer is
    /// the server's identity key, which signs the handshake. The client verifies that
    /// signature against the key it extracts from the attestation, so the two
    /// must match. Reads block per the transport's semantics, so any timeout
    /// must be configured on the reader passed in.
    pub fn new(reader: R, writer: W, signer: xdsa::SecretKey, attester: A) -> Self {
        Self {
            framing: Framing::new(reader, writer),
            signer,
            attester,
            session: None,
            #[cfg(any(test, feature = "bench", feature = "fuzz"))]
            timestamp: None,
        }
    }

    /// Test helper creating a server side signing its ArkHellos at the given
    /// time instead of the clock, so a run of it is the same every time. Not
    /// part of the API.
    #[doc(hidden)]
    #[inline]
    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn new_at(
        reader: R,
        writer: W,
        signer: xdsa::SecretKey,
        attester: A,
        timestamp: i64,
    ) -> Self {
        let mut server = Self::new(reader, writer, signer, attester);
        server.timestamp = Some(timestamp);
        server
    }

    /// Serves the next host-to-ark message, decrypting and protobuf decoding it.
    /// Empty frames are session resets and run the handshake inline. Junk
    /// outside a session, undecryptable packets and failed handshakes are
    /// logged, answered with an empty frame and skipped. Only transport
    /// failures and malformed messages surface as errors.
    pub fn next_message(&mut self) -> Result<HostToArk, Error> {
        // Loop until we can deliver a valid decrypted message. Empty frames
        // are consumed and trigger a new session handshake.
        loop {
            // Retrieve the next COBS encoded packet
            let size = match self.framing.next_packet() {
                // Transport errors propagate immediately
                Err(Error::Terminated) => return Err(Error::Terminated),
                Err(Error::RecvFailed(err)) => return Err(Error::RecvFailed(err)),

                // Decode errors may be due to session resets, log and ignore.
                // Within a session the skipped frame may have carried a sealed
                // message though, leaving the HPKE sequence behind the client's,
                // so the session cannot continue either way.
                Err(err) => {
                    if self.session.take().is_some() {
                        warn!("failed to decode cobs packet, resetting session: {}", err);
                    } else {
                        warn!("failed to decode cobs packet: {}", err);
                    }
                    self.send_dropped();
                    continue;
                }
                // Empty frame signals a session reset from the client
                Ok(None) => {
                    self.session = None;

                    match self.handshake() {
                        // Transport errors propagate immediately
                        Err(Error::Terminated) => return Err(Error::Terminated),
                        Err(Error::RecvFailed(err)) => return Err(Error::RecvFailed(err)),

                        // Decode or protocol errors are logged and ignored, the
                        // client learning that no session came out of it
                        Err(err) => {
                            warn!("wire handshake failed: {}", err);
                            self.send_dropped();
                            continue;
                        }
                        // Handshake successful
                        Ok(session) => {
                            info!("new wire session established");
                            self.session = Some(session);
                            continue;
                        }
                    }
                }
                // Valid COBS packet
                Ok(Some(size)) => size,
            };
            // Non-empty packet without a session is considered junk, the client
            // may still think it has a session though, tell it otherwise
            let session = match self.session.as_mut() {
                None => {
                    warn!("dropping data outside session");
                    self.send_dropped();
                    continue;
                }
                Some(s) => s,
            };
            // Decrypt the message and parse it with protobuf
            let req = match session.open(&self.framing.decobs_buffer[..size]) {
                // If decryption fails, the HPKE context is most probably
                // broken, no point continuing with it.
                Err(Error::EncryptionFailed(err)) => {
                    warn!("decryption failed, resetting session: {}", err);
                    self.session = None;
                    self.send_dropped();
                    continue;
                }
                Err(err) => return Err(err),
                Ok(req) => req,
            };
            trace!("read host-to-ark message ({} bytes encrypted)", size);
            return Ok(req);
        }
    }

    /// Tells the client that the server has no session with it by sending an empty
    /// frame.
    fn send_dropped(&mut self) {
        if let Err(err) = self.framing.send_dropped() {
            warn!("failed to signal dropped session: {}", err);
        }
    }

    /// Protobuf encodes an ark-to-host message, seals it with the session and
    /// sends it. Fails without an active session. A failure after sealing
    /// drops the session and signals the client, as the client's HPKE sequence can
    /// no longer be caught up with.
    pub fn send_message(&mut self, res: ArkToHost) -> Result<(), Error> {
        // Encode and seal the message, oversized messages are rejected before
        // the HPKE sequence advances, only a failed seal breaks the session
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| Error::EncryptionFailed("no active session".into()))?;

        let blob = match session.seal(&res, &mut self.framing.encode_buffer) {
            Err(err @ Error::EncryptionFailed(_)) => {
                self.session = None;
                self.send_dropped();
                return Err(err);
            }
            Err(err) => return Err(err),
            Ok(blob) => blob,
        };
        // Send the sealed message, tearing down the session if the transport
        // fails to deliver it
        if let Err(err) = self.framing.send_packet(&blob) {
            self.session = None;
            self.send_dropped();
            return Err(err);
        }
        trace!("sent ark-to-host message ({} bytes)", blob.len());
        Ok(())
    }

    /// Responds to the handshake after a session reset, establishing the
    /// HPKE contexts of both directions:
    ///
    ///   1. Client -> Server: HostHello { host_signer, host_crypto }           (plain CBOR)
    ///   2. Server -> Client: ArkHello  { ark_attest, ark_crypto, a2h_encap }  (cose::seal)
    ///   3. Client -> Server: HostAck   { h2a_encap }                          (cose::seal)
    fn handshake(&mut self) -> Result<Session, Error> {
        loop {
            // Message 1: Read the HostHello (skip any trailing empty reset frames)
            let size = loop {
                if let Some(n) = self.framing.next_packet()? {
                    break n;
                }
            };
            let host_hello: handshake::HostHello =
                cbor::decode(&self.framing.decobs_buffer[..size]).map_err(|err| {
                    Error::HandshakeFailed(format!("invalid client hello: {}", err))
                })?;

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

            self.framing.send_packet(&ark_hello)?;

            // Message 3: Read and open the HostAck. An empty frame probably
            // means the client is restarting the session, start over.
            let Some(size) = self.framing.next_packet()? else {
                warn!("session reset during handshake");
                continue;
            };
            let host_ack: handshake::HostAck = cose::open(
                &self.framing.decobs_buffer[..size],
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
            return Ok(Session { sender, receiver });
        }
    }
}

#[cfg(all(test, unix))]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::testing;
    use crate::{Client, Verifier};
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
            let mut server = Server::new(ark_reader, ark_writer, signer_key, attestation);
            let mut ids = Vec::new();
            for _ in 0..2 {
                let req = server.next_message().unwrap();
                ids.push(req.id);
                server
                    .send_message(ArkToHost {
                        id: req.id,
                        err: None,
                        content: None,
                    })
                    .unwrap();
            }
            ids
        });

        // Raw handle to inject bytes past the client side.
        let mut raw_sock = host_sock.try_clone().unwrap();

        // Session 1: handshake, checking the attestation, exchange one message.
        let mut client = Client::new(host_sock.try_clone().unwrap(), host_sock);
        let attest = client.handshake(&signer_pub).unwrap();
        assert_eq!(attest.as_bytes(), presented.as_bytes());
        client
            .send_message(HostToArk {
                id: Some(1),
                content: None,
            })
            .unwrap();
        let res = client.next_message().unwrap();
        assert_eq!(res.id, Some(1));

        // Inject a frame the server cannot decrypt. It drops the session and
        // signals it, the client surfacing the signal as a reset on its next
        // read and refusing to send into the dead session afterwards.
        raw_sock
            .write_all(&cobs_frame(b"interrupted transfer"))
            .unwrap();
        let result = client.next_message();
        assert!(matches!(result, Err(Error::SessionReset)), "{result:?}");
        let result = client.send_message(HostToArk {
            id: Some(2),
            content: None,
        });
        assert!(
            matches!(result, Err(Error::EncryptionFailed(_))),
            "{result:?}"
        );

        // Session 2: new handshake on the same wire, exchange one message.
        client.handshake(&signer_pub).unwrap();
        client
            .send_message(HostToArk {
                id: Some(2),
                content: None,
            })
            .unwrap();
        let res = client.next_message().unwrap();
        assert_eq!(res.id, Some(2));

        let ids = ark_thread.join().unwrap();
        assert_eq!(ids, vec![Some(1), Some(2)]);
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
            let mut server = Server::new(ark_reader, ark_writer, signer_key, attestation);
            server.next_message()
        });

        // Client side: refuse the attestation in the verifier.
        let mut client = Client::new(host_sock.try_clone().unwrap(), host_sock);
        let result = client.handshake(&Untrusting);
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

        use crate::Roots;
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
                let mut server = Server::new(ark_reader, ark_writer, signer_key, attestation);
                server.next_message()
            });
            let mut client = Client::new(host_sock.try_clone().unwrap(), host_sock);
            let result = client.handshake(&Roots { hardware, emulator });

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
}
