// wire-rs: encrypted protocol between Ark and host
// Copyright 2025 Dark Bio AG. All rights reserved.

use crate::framing::Framing;
use crate::handshake;
use crate::protocol::{ArkToHost, HostToArk};
use crate::{
    CRYPTO_DOMAIN_WIRE, CRYPTO_DOMAIN_WIRE_ARK_TO_HOST, CRYPTO_DOMAIN_WIRE_HOST_TO_ARK, Error,
    MAX_FRAME_SIZE,
};
use darkbio_crypto::{cbor, cose, xdsa, xhpke};
use prost::Message;
use std::io::{Read, Write};
use tracing::{info, trace, warn};

/// Source of the device attestation the Ark presents in the handshake; queried
/// on every handshake, so a freshly onboarded attestation can be picked up
/// without recreating the wire.
///
/// The attestation is a CWT, handed over as raw bytes for now; a typed form
/// will be exposed later.
pub trait Attester {
    /// Returns the device attestation to present to the host (e.g. a root-signed
    /// CWT read from disk, or a self-signed fallback for pre-onboarding devices).
    /// The identity key it embeds must be the one signing the wire's handshake.
    fn attest(&mut self) -> Vec<u8>;
}

/// A fixed attestation, presented as is on every handshake.
impl Attester for Vec<u8> {
    fn attest(&mut self) -> Vec<u8> {
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

    signer: xdsa::SecretKey, // Ark's identity key, signing the ArkHello
    attester: A,             // Source of the device attestation for handshakes
    session: Option<handshake::Session>, // Active encrypted session (if handshake completed)
}

impl<R: Read, W: Write, A: Attester> ArkSide<R, W, A> {
    /// Creates a new Ark side around a low level reader and writer. The signer is
    /// the Ark's identity key, which signs the handshake; the host verifies that
    /// signature against the key it extracts from the attestation, so the two
    /// must match.
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

                // Decode errors may be due to session resets, log and ignore
                Err(err) => {
                    warn!("failed to decode cobs packet: {}", err);
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
            let blob = match session
                .receiver
                .open(&self.framing.decobs_buffer[..size], &[])
            {
                Err(err) => {
                    // If decryption fails, the HPKE context is most probably
                    // broken, no point continuing with it.
                    warn!("decryption failed, resetting session: {}", err);
                    self.session = None;
                    continue;
                }
                Ok(blob) => blob,
            };
            let req = HostToArk::decode(&blob[..]).map_err(Error::PacketDecodingFailed)?;

            trace!("read host-to-ark message ({} bytes encrypted)", size);
            return Ok(req);
        }
    }

    /// Protobuf encodes an ark-to-host message, seals it with the session and
    /// sends it. Fails without an active session.
    pub fn send_message(&mut self, res: ArkToHost) -> Result<(), Error> {
        // Encode it with protobuf
        let len = res.encoded_len();
        if len > MAX_FRAME_SIZE {
            return Err(Error::PacketTooLarge(len));
        }
        self.framing.encode_buffer.clear();
        if let Err(err) = res.encode(&mut self.framing.encode_buffer) {
            return Err(Error::PacketEncodingFailed(err));
        }
        // Encrypt the encoded message
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| Error::EncryptionFailed("no active session".into()))?;

        let blob = session
            .sender
            .seal(&self.framing.encode_buffer, &[])
            .map_err(|err| Error::EncryptionFailed(err.to_string()))?;

        let len = blob.len();
        if len > MAX_FRAME_SIZE {
            return Err(Error::PacketTooLarge(len));
        }
        self.framing.send_packet(&blob)?;
        trace!("sent ark-to-host message ({} bytes)", len);
        Ok(())
    }

    /// Responds to the handshake after a session reset, establishing the
    /// HPKE contexts of both directions:
    ///
    ///   1. Host -> Ark:  HostHello { host_signer, host_crypto }           (plain CBOR)
    ///   2. Ark -> Host:  ArkHello  { ark_attest, ark_crypto, a2h_encap }  (cose::seal)
    ///   3. Host -> Ark:  HostAck   { h2a_encap }                          (cose::seal)
    fn handshake(&mut self) -> Result<handshake::Session, Error> {
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
                    ark_attest: self.attester.attest(),
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
            return Ok(handshake::Session { sender, receiver });
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::testing;
    use crate::{HostSide, Verifier};
    use darkbio_cobs as cobs;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    /// COBS-encodes data and appends the frame delimiter.
    fn cobs_frame(data: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; cobs::encode_buffer(data.len())];
        let n = cobs::encode(data, &mut buf).unwrap();
        buf.truncate(n);
        buf.push(0x00);
        buf
    }

    /// Reads one COBS frame from a stream (bytes until 0x00), then COBS-decodes.
    fn read_cobs_frame(reader: &mut impl Read) -> Vec<u8> {
        let mut raw = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            reader.read_exact(&mut byte).unwrap();
            if byte[0] == 0x00 {
                break;
            }
            raw.push(byte[0]);
        }
        if raw.is_empty() {
            return Vec::new();
        }
        let mut decoded = vec![0u8; raw.len()];
        let n = cobs::decode(&raw, &mut decoded).unwrap();
        decoded.truncate(n);
        decoded
    }

    // Tests a full round trip, the handshake, a host-to-ark request and the
    // ark-to-host response, and that the device attestation reaches the host's
    // verifier byte-for-byte.
    #[test]
    fn test_message_round_trip() {
        testing::init_tracing();

        let signer_key = xdsa::SecretKey::generate();
        let signer_pub = signer_key.public_key();

        let (host_sock, ark_sock) = UnixStream::pair().unwrap();
        let ark_reader = ark_sock.try_clone().unwrap();
        let ark_writer = ark_sock;

        // Ark side: handshake, receive one message, echo it back.
        let ark_thread = std::thread::spawn(move || {
            let mut ark = ArkSide::new(
                ark_reader,
                ark_writer,
                signer_key,
                b"unit-test-attestation".to_vec(),
            );
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
        assert_eq!(attest, b"unit-test-attestation", "attestation mismatch");

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
            let mut ark = ArkSide::new(ark_reader, ark_writer, signer_key, Vec::new());
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

    // Tests that a session reset mid-handshake (after HostHello/ArkHello but
    // before HostAck) correctly aborts the in-progress handshake and allows a
    // fresh one to complete.
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
            let mut ark = ArkSide::new(ark_reader, ark_writer, signer_key, Vec::new());
            let req = ark.next_message().unwrap();
            ark.send_message(ArkToHost {
                id: req.id,
                err: None,
                content: None,
            })
            .unwrap();
            req
        });

        let mut host_read = host_sock.try_clone().unwrap();
        let mut host_write = host_sock;

        // Start a handshake but abandon it after receiving ArkHello (message 2),
        // never sending HostAck (message 3).
        host_write.write_all(&[0x00, 0x00]).unwrap(); // session reset

        let host_signer_key = xdsa::SecretKey::generate();
        let host_crypto_key = xhpke::SecretKey::generate();
        let hello = cbor::encode(&handshake::HostHello {
            host_signer: host_signer_key.public_key(),
            host_crypto: host_crypto_key.public_key(),
        })
        .unwrap();
        host_write.write_all(&cobs_frame(&hello)).unwrap(); // message 1: HostHello
        read_cobs_frame(&mut host_read); // consume and discard message 2: ArkHello

        // Now do a complete handshake (sends its own reset + full 3 messages).
        // The Ark sees the reset where it expected HostAck, restarts its
        // handshake loop, and completes the new one.
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
            let mut ark = ArkSide::new(ark_reader, ark_writer, signer_key, Vec::new());
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

            fn verify(&self, _: &[u8]) -> Result<(xdsa::PublicKey, Self::Info), String> {
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
            let mut ark = ArkSide::new(ark_reader, ark_writer, signer_key, Vec::new());
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
}
