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

/// Device attestation an Ark presents in the handshake, a CWT in one of the
/// shapes darkbio-trust defines (hardware or emulator claims). Only the shape
/// is checked, so an obviously wrong blob is refused up front; whether it is
/// accepted is the host's decision.
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

/// Source of the device attestation the Ark presents in the handshake; queried
/// on every handshake, so a freshly onboarded attestation can be picked up
/// without recreating the wire.
pub trait Attester {
    /// Returns the device attestation to present to the host (e.g. a root-signed
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

/// Ark side of the wire, an encrypted transport for serving protobuf requests
/// from a connected host. It waits for session resets (empty frames), responds
/// to handshake and afterward decrypts inbound and encrypts outbound messages.
///
/// The device attestation is not interpreted by the wire, it is provided by an
/// `Attester` and forwarded to the host verbatim.
pub struct ArkSide<R: Read, W: Write, A: Attester> {
    framing: Framing<R, W>, // COBS framed transport for ingress and egress data

    signer: xdsa::SecretKey,  // Ark's identity key, signing the ArkHello
    attester: A,              // Source of the device attestation for handshakes
    session: Option<Session>, // Active encrypted session (if handshake completed)
}

impl<R: Read, W: Write, A: Attester> ArkSide<R, W, A> {
    /// Creates a new Ark side around a low level reader and writer. The signer is
    /// the Ark's identity key, which signs the handshake; the host verifies that
    /// signature against the key it extracts from the attestation, so the two
    /// must match. Reads block per the transport's semantics, so any timeout
    /// must be configured on the reader passed in.
    pub fn new(reader: R, writer: W, signer: xdsa::SecretKey, attester: A) -> Self {
        Self {
            framing: Framing::new(reader, writer),
            signer,
            attester,
            session: None,
        }
    }

    /// Serves the next host-to-ark message, decrypting and protobuf decoding it.
    /// Empty frames are session resets and run the handshake inline;
    /// junk outside a session, undecryptable packets and failed handshakes are
    /// logged and skipped, so only transport failures and malformed messages
    /// surface as errors.
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
                // message though, leaving the HPKE sequence behind the host's,
                // so the session cannot continue either way.
                Err(err) => {
                    if self.session.take().is_some() {
                        warn!("failed to decode cobs packet, resetting session: {}", err);
                    } else {
                        warn!("failed to decode cobs packet: {}", err);
                    }
                    continue;
                }
                // Empty frame signals a session reset from the host
                Ok(None) => {
                    self.session = None;

                    match self.handshake() {
                        // Transport errors propagate immediately
                        Err(Error::Terminated) => return Err(Error::Terminated),
                        Err(Error::RecvFailed(err)) => return Err(Error::RecvFailed(err)),

                        // Decode or protocol errors are logged and ignored
                        Err(err) => {
                            warn!("wire handshake failed: {}", err);
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
            // Non-empty packet without a session is considered junk
            let session = match self.session.as_mut() {
                None => {
                    warn!("dropping data outside session");
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
                    continue;
                }
                Err(err) => return Err(err),
                Ok(req) => req,
            };
            trace!("read host-to-ark message ({} bytes encrypted)", size);
            return Ok(req);
        }
    }

    /// Protobuf encodes an ark-to-host message, seals it with the session and
    /// sends it. Fails without an active session, and a failure after sealing
    /// drops the session, as the host's HPKE sequence can no longer be caught
    /// up with.
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
                return Err(err);
            }
            Err(err) => return Err(err),
            Ok(blob) => blob,
        };
        // Send the sealed message, tearing down the session if the transport
        // fails to deliver it
        if let Err(err) = self.framing.send_packet(&blob) {
            self.session = None;
            return Err(err);
        }
        trace!("sent ark-to-host message ({} bytes)", blob.len());
        Ok(())
    }

    /// Responds to the handshake after a session reset, establishing the
    /// HPKE contexts of both directions:
    ///
    ///   1. Host -> Ark:  HostHello { host_signer, host_crypto }           (plain CBOR)
    ///   2. Ark -> Host:  ArkHello  { ark_attest, ark_crypto, a2h_encap }  (cose::seal)
    ///   3. Host -> Ark:  HostAck   { h2a_encap }                          (cose::seal)
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
                    Error::HandshakeFailed(format!("invalid host hello: {}", err))
                })?;

            // Generate an ephemeral Ark xHPKE keypair and set up the Ark->Host sender
            let ark_crypto_key = xhpke::SecretKey::generate();
            let ark_crypto_pub = ark_crypto_key.public_key();

            let (sender, a2h_encap) = host_hello
                .host_crypto
                .new_sender(CRYPTO_DOMAIN_WIRE_ARK_TO_HOST)
                .map_err(|err| {
                    Error::HandshakeFailed(format!("ark sender setup failed: {}", err))
                })?;

            // Message 2: Seal and send the ArkHello
            let ark_hello = cose::seal(
                &handshake::ArkHello {
                    ark_attest: self.attester.attest().into_bytes(),
                    ark_crypto: ark_crypto_pub.clone(),
                    a2h_encap: a2h_encap.to_vec(),
                },
                &handshake::ArkHelloAuth {
                    host_signer: host_hello.host_signer.clone(),
                    host_crypto: host_hello.host_crypto.clone(),
                },
                &self.signer,
                &host_hello.host_crypto,
                CRYPTO_DOMAIN_WIRE,
            )
            .map_err(|err| Error::HandshakeFailed(format!("failed to seal ark hello: {}", err)))?;

            self.framing.send_packet(&ark_hello)?;

            // Message 3: Read and open the HostAck. An empty frame probably
            // means the host is restarting the session, start over.
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
            .map_err(|err| Error::HandshakeFailed(format!("invalid host ack: {}", err)))?;

            // Set up the Host->Ark receiver
            let enc_h2a: [u8; xhpke::ENCAP_KEY_SIZE] = host_ack
                .h2a_encap
                .try_into()
                .map_err(|_| Error::HandshakeFailed("invalid h2a_encap size".into()))?;

            let receiver = ark_crypto_key
                .new_receiver(&enc_h2a, CRYPTO_DOMAIN_WIRE_HOST_TO_ARK)
                .map_err(|err| {
                    Error::HandshakeFailed(format!("ark receiver setup failed: {}", err))
                })?;

            // Session established
            return Ok(Session { sender, receiver });
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::testing;
    use crate::{HostSide, Verifier};
    use darkbio_cobs as cobs;
    use std::io::{self, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Self-signed attestation of a never onboarded device, the placeholder an
    /// Ark presents before it is attested by a root.
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

    // Tests a full round trip, the handshake, a host-to-ark request and the
    // ark-to-host response, and that the device attestation reaches the host's
    // verifier byte-for-byte.
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

        // Ark side: handshake, receive one message, echo it back.
        let ark_thread = std::thread::spawn(move || {
            let mut ark = ArkSide::new(ark_reader, ark_writer, signer_key, attestation);
            let req = ark.next_message().unwrap();
            ark.send_message(ArkToHost {
                id: req.id,
                err: None,
                content: None,
            })
            .unwrap();
            req
        });

        // Host side: handshake, send a message, read the response.
        let mut host = HostSide::new(host_sock.try_clone().unwrap(), host_sock);
        let attest = host.handshake(&signer_pub).unwrap();
        assert_eq!(
            attest.as_bytes(),
            presented.as_bytes(),
            "attestation mismatch"
        );

        host.send_message(HostToArk {
            id: Some(42),
            content: None,
        })
        .unwrap();

        let req = ark_thread.join().unwrap();
        assert_eq!(req.id, Some(42), "request mismatch");

        let res = host.next_message().unwrap();
        assert_eq!(res.id, Some(42), "response mismatch");
    }

    // Tests that a session reset mid-transfer (after a successful handshake and
    // message exchange) correctly tears down the old session and allows a fresh
    // handshake to establish a new one.
    #[test]
    fn test_reset_mid_transfer() {
        testing::init_tracing();

        let signer_key = xdsa::SecretKey::generate();
        let signer_pub = signer_key.public_key();

        let (host_sock, ark_sock) = UnixStream::pair().unwrap();
        let ark_reader = ark_sock.try_clone().unwrap();
        let ark_writer = ark_sock;

        // Ark side: receive two messages (across two sessions), echo each back.
        let ark_thread = std::thread::spawn(move || {
            let attestation = self_attestation(&signer_key);
            let mut ark = ArkSide::new(ark_reader, ark_writer, signer_key, attestation);
            let mut ids = Vec::new();
            for _ in 0..2 {
                let req = ark.next_message().unwrap();
                ids.push(req.id);
                ark.send_message(ArkToHost {
                    id: req.id,
                    err: None,
                    content: None,
                })
                .unwrap();
            }
            ids
        });

        // Raw handle to inject bytes past the host side.
        let mut raw_sock = host_sock.try_clone().unwrap();

        // Session 1: complete handshake, exchange one message.
        let mut host = HostSide::new(host_sock.try_clone().unwrap(), host_sock);
        host.handshake(&signer_pub).unwrap();
        host.send_message(HostToArk {
            id: Some(1),
            content: None,
        })
        .unwrap();
        let res = host.next_message().unwrap();
        assert_eq!(res.id, Some(1), "session 1 response mismatch");

        // Simulate an interrupted transfer by sending a valid COBS frame with a
        // garbage payload, which the Ark fails to decrypt and drops the session
        // over.
        raw_sock
            .write_all(&cobs_frame(b"interrupted transfer"))
            .unwrap();

        // Session 2: new handshake on the same wire, exchange one message.
        host.handshake(&signer_pub).unwrap();
        host.send_message(HostToArk {
            id: Some(2),
            content: None,
        })
        .unwrap();
        let res = host.next_message().unwrap();
        assert_eq!(res.id, Some(2), "session 2 response mismatch");

        let ids = ark_thread.join().unwrap();
        assert_eq!(
            ids,
            vec![Some(1), Some(2)],
            "ark received wrong message ids"
        );
    }

    // Tests that a response the host never read (e.g. after timing out on it)
    // does not wedge subsequent handshakes. The Ark answers the request before
    // it processes the reset, so the stale response precedes the fresh ArkHello
    // and the host must skip past it.
    #[test]
    fn test_reset_unread_response() {
        testing::init_tracing();

        let signer_key = xdsa::SecretKey::generate();
        let signer_pub = signer_key.public_key();

        let (host_sock, ark_sock) = UnixStream::pair().unwrap();
        let ark_reader = ark_sock.try_clone().unwrap();
        let ark_writer = ark_sock;

        // Ark side: receive two messages (across two sessions), echo each back.
        let ark_thread = std::thread::spawn(move || {
            let attestation = self_attestation(&signer_key);
            let mut ark = ArkSide::new(ark_reader, ark_writer, signer_key, attestation);
            let mut ids = Vec::new();
            for _ in 0..2 {
                let req = ark.next_message().unwrap();
                ids.push(req.id);
                ark.send_message(ArkToHost {
                    id: req.id,
                    err: None,
                    content: None,
                })
                .unwrap();
            }
            ids
        });

        // Session 1: complete handshake, send a message but never read the
        // response.
        let mut host = HostSide::new(host_sock.try_clone().unwrap(), host_sock);
        host.handshake(&signer_pub).unwrap();
        host.send_message(HostToArk {
            id: Some(1),
            content: None,
        })
        .unwrap();

        // Session 2: new handshake on the same wire with the unread response
        // still queued in front of the ArkHello, exchange one message.
        host.handshake(&signer_pub).unwrap();
        host.send_message(HostToArk {
            id: Some(2),
            content: None,
        })
        .unwrap();
        let res = host.next_message().unwrap();
        assert_eq!(res.id, Some(2), "session 2 response mismatch");

        let ids = ark_thread.join().unwrap();
        assert_eq!(
            ids,
            vec![Some(1), Some(2)],
            "ark received wrong message ids"
        );
    }

    // Tests that a session reset mid-handshake (after HostHello/ArkHello but
    // before HostAck) correctly aborts the in-progress handshake and allows a
    // fresh one to complete, with the abandoned ArkHello left unread for the
    // fresh handshake to skip past.
    #[test]
    fn test_reset_mid_handshake() {
        testing::init_tracing();

        let signer_key = xdsa::SecretKey::generate();
        let signer_pub = signer_key.public_key();

        let (host_sock, ark_sock) = UnixStream::pair().unwrap();
        let ark_reader = ark_sock.try_clone().unwrap();
        let ark_writer = ark_sock;

        // Ark side: receive one message, echo it back.
        let ark_thread = std::thread::spawn(move || {
            let attestation = self_attestation(&signer_key);
            let mut ark = ArkSide::new(ark_reader, ark_writer, signer_key, attestation);
            let req = ark.next_message().unwrap();
            ark.send_message(ArkToHost {
                id: req.id,
                err: None,
                content: None,
            })
            .unwrap();
            req
        });

        let host_read = host_sock.try_clone().unwrap();
        let mut host_write = host_sock;

        // Start a handshake but abandon it after sending HostHello (message 1),
        // never reading ArkHello (message 2) nor sending HostAck (message 3).
        host_write.write_all(&[0x00, 0x00]).unwrap(); // session reset

        let host_signer_key = xdsa::SecretKey::generate();
        let host_crypto_key = xhpke::SecretKey::generate();
        let hello = cbor::encode(&handshake::HostHello {
            host_signer: host_signer_key.public_key(),
            host_crypto: host_crypto_key.public_key(),
        })
        .unwrap();
        host_write.write_all(&cobs_frame(&hello)).unwrap(); // message 1: HostHello

        // Now do a complete handshake (sends its own reset + full 3 messages).
        // The Ark sees the reset where it expected HostAck, restarts its
        // handshake loop, and completes the new one. The host skips the stale
        // ArkHello of the abandoned attempt to find its own.
        let mut host = HostSide::new(host_read, host_write);
        host.handshake(&signer_pub).unwrap();
        host.send_message(HostToArk {
            id: Some(99),
            content: None,
        })
        .unwrap();

        let req = ark_thread.join().unwrap();
        assert_eq!(req.id, Some(99), "request mismatch");

        let res = host.next_message().unwrap();
        assert_eq!(res.id, Some(99), "response mismatch");
    }

    // Tests that garbage sent instead of a handshake hello (after a session
    // reset) aborts the in-progress handshake without wedging the Ark, allowing
    // a fresh handshake to complete.
    #[test]
    fn test_reset_malformed_hello() {
        testing::init_tracing();

        let signer_key = xdsa::SecretKey::generate();
        let signer_pub = signer_key.public_key();

        let (host_sock, ark_sock) = UnixStream::pair().unwrap();
        let ark_reader = ark_sock.try_clone().unwrap();
        let ark_writer = ark_sock;

        // Ark side: receive one message, echo it back.
        let ark_thread = std::thread::spawn(move || {
            let attestation = self_attestation(&signer_key);
            let mut ark = ArkSide::new(ark_reader, ark_writer, signer_key, attestation);
            let req = ark.next_message().unwrap();
            ark.send_message(ArkToHost {
                id: req.id,
                err: None,
                content: None,
            })
            .unwrap();
            req
        });

        // Raw handle to inject bytes past the host side.
        let mut raw_sock = host_sock.try_clone().unwrap();

        // Signal a session reset, but follow it up with a garbage hello. The Ark
        // fails to decode it, abandons the handshake and returns to its message
        // loop.
        raw_sock.write_all(&[0x00, 0x00]).unwrap();
        raw_sock.write_all(&cobs_frame(b"not a hello")).unwrap();

        // Now do a complete handshake and exchange one message.
        let mut host = HostSide::new(host_sock.try_clone().unwrap(), host_sock);
        host.handshake(&signer_pub).unwrap();
        host.send_message(HostToArk {
            id: Some(99),
            content: None,
        })
        .unwrap();

        let req = ark_thread.join().unwrap();
        assert_eq!(req.id, Some(99), "request mismatch");

        let res = host.next_message().unwrap();
        assert_eq!(res.id, Some(99), "response mismatch");
    }

    // Tests that an untrusting verifier rejects the session on the host side.
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

        // Ark side: serve handshakes until the transport drops. The host aborts
        // mid-handshake, so the Ark never delivers a message.
        let ark_thread = std::thread::spawn(move || {
            let attestation = self_attestation(&signer_key);
            let mut ark = ArkSide::new(ark_reader, ark_writer, signer_key, attestation);
            ark.next_message()
        });

        // Host side: refuse the attestation in the verifier.
        let mut host = HostSide::new(host_sock.try_clone().unwrap(), host_sock);
        let result = host.handshake(&Untrusting);
        assert!(result.is_err(), "expected rejected handshake");

        // Dropping the host tears down the transport, unblocking the Ark.
        drop(host);
        assert!(
            ark_thread.join().unwrap().is_err(),
            "expected torn down wire"
        );
    }

    // Tests that the roots verifier opens sessions with root attested Arks of
    // either realm, handing back their verified identity, and refuses Arks
    // attested under unknown roots or self-signed ones.
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

        /// Drives a handshake with an Ark presenting the attestation and the host
        /// trusting the roots, returning the host's verdict.
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
                let mut ark = ArkSide::new(ark_reader, ark_writer, signer_key, attestation);
                ark.next_message()
            });
            let mut host = HostSide::new(host_sock.try_clone().unwrap(), host_sock);
            let result = host.handshake(&Roots { hardware, emulator });

            // Dropping the host tears down the transport, unblocking the Ark
            drop(host);
            let _ = ark_thread.join().unwrap();
            result
        }

        let hardware_root = xdsa::SecretKey::generate();
        let emulator_root = xdsa::SecretKey::generate();
        let hardware_roots = [hardware_root.public_key()];
        let emulator_roots = [emulator_root.public_key()];

        // A hardware Ark attested by a hardware root is accepted with its identity
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
        assert_eq!(device.realm, Realm::Hardware, "realm mismatch");
        assert_eq!(device.serial, "ark-1234", "serial mismatch");

        // The same Ark is refused by a host trusting only emulator roots
        let signer_key = xdsa::SecretKey::generate();
        assert!(
            handshake(signer_key, attestation, &[], &emulator_roots).is_err(),
            "hardware attestation accepted under emulator roots"
        );

        // An emulated Ark attested by an emulator root is accepted with its expiry
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
        assert_eq!(device.realm, Realm::Emulator, "realm mismatch");
        assert_eq!(device.expiry, Some(now + 1000), "expiry mismatch");

        // A never onboarded Ark presenting a self-signed attestation is refused
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
        assert!(
            handshake(signer_key, attestation, &hardware_roots, &emulator_roots).is_err(),
            "self-signed attestation accepted"
        );
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
        assert!(
            matches!(Attestation::new(cwt), Err(Error::InvalidAttestation)),
            "cloud attestation accepted as device attestation"
        );
        assert!(
            matches!(
                Attestation::new(b"junk".to_vec()),
                Err(Error::InvalidAttestation)
            ),
            "junk accepted as device attestation"
        );
    }

    // Tests that the host refuses a malformed attestation before consulting its
    // verifier. The Ark bypasses the shape check through the private constructor,
    // as a misbehaving Ark would by not using this crate at all.
    #[test]
    fn test_malformed_attestation_rejected() {
        testing::init_tracing();

        /// Verifier that must never be consulted.
        struct Unreachable;

        impl Verifier for Unreachable {
            type Info = ();

            fn verify(&self, _: &Attestation) -> Result<(xdsa::PublicKey, Self::Info), String> {
                panic!("verifier consulted with a malformed attestation")
            }
        }

        let signer_key = xdsa::SecretKey::generate();

        let (host_sock, ark_sock) = UnixStream::pair().unwrap();
        let ark_reader = ark_sock.try_clone().unwrap();
        let ark_writer = ark_sock;

        let ark_thread = std::thread::spawn(move || {
            let attestation = Attestation(b"junk".to_vec());
            let mut ark = ArkSide::new(ark_reader, ark_writer, signer_key, attestation);
            ark.next_message()
        });
        let mut host = HostSide::new(host_sock.try_clone().unwrap(), host_sock);
        assert!(
            matches!(host.handshake(&Unreachable), Err(Error::InvalidAttestation)),
            "malformed attestation not rejected"
        );

        // Dropping the host tears down the transport, unblocking the Ark
        drop(host);
        assert!(
            ark_thread.join().unwrap().is_err(),
            "expected torn down wire"
        );
    }

    // Tests that a transport failure after sealing drops the session, since
    // the peer's HPKE sequence can no longer be caught up with, and that a
    // fresh handshake recovers the wire.
    #[test]
    fn test_send_failure_drops_session() {
        testing::init_tracing();

        /// Writer failing on demand to simulate a transport fault.
        struct Faulty {
            inner: UnixStream,
            fail: Arc<AtomicBool>,
        }

        impl Write for Faulty {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                if self.fail.load(Ordering::Relaxed) {
                    return Err(io::ErrorKind::BrokenPipe.into());
                }
                self.inner.write(buf)
            }

            fn flush(&mut self) -> io::Result<()> {
                self.inner.flush()
            }
        }

        let signer_key = xdsa::SecretKey::generate();
        let signer_pub = signer_key.public_key();

        let (host_sock, ark_sock) = UnixStream::pair().unwrap();
        let ark_reader = ark_sock.try_clone().unwrap();
        let ark_writer = ark_sock;

        // Ark side: receive one message, echo it back.
        let ark_thread = std::thread::spawn(move || {
            let attestation = self_attestation(&signer_key);
            let mut ark = ArkSide::new(ark_reader, ark_writer, signer_key, attestation);
            let req = ark.next_message().unwrap();
            ark.send_message(ArkToHost {
                id: req.id,
                err: None,
                content: None,
            })
            .unwrap();
            req
        });

        let fail = Arc::new(AtomicBool::new(false));
        let writer = Faulty {
            inner: host_sock.try_clone().unwrap(),
            fail: fail.clone(),
        };
        let mut host = HostSide::new(host_sock, writer);
        host.handshake(&signer_pub).unwrap();

        // Break the transport and send a message. It gets sealed, fails to go
        // out, and must take the session down with it.
        fail.store(true, Ordering::Relaxed);
        let result = host.send_message(HostToArk {
            id: Some(1),
            content: None,
        });
        assert!(
            matches!(result, Err(Error::SendFailed(_))),
            "expected send failure"
        );
        let result = host.send_message(HostToArk {
            id: Some(2),
            content: None,
        });
        assert!(
            matches!(result, Err(Error::EncryptionFailed(_))),
            "expected dropped session"
        );

        // Heal the transport, a fresh handshake resynchronizes both sides.
        fail.store(false, Ordering::Relaxed);
        host.handshake(&signer_pub).unwrap();
        host.send_message(HostToArk {
            id: Some(3),
            content: None,
        })
        .unwrap();

        let req = ark_thread.join().unwrap();
        assert_eq!(req.id, Some(3), "request mismatch");

        let res = host.next_message().unwrap();
        assert_eq!(res.id, Some(3), "response mismatch");
    }
}
