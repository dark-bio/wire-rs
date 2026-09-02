// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

use crate::framing::Framing;
use crate::handshake;
use crate::protocol::{ArkToHost, HostToArk};
use crate::{
    CRYPTO_DOMAIN_WIRE, CRYPTO_DOMAIN_WIRE_ARK_TO_HOST, CRYPTO_DOMAIN_WIRE_HOST_TO_ARK, Error,
    MAX_FRAME_SIZE,
};
use darkbio_cobs as cobs;
use darkbio_crypto::{cbor, cose, xdsa, xhpke};
use prost::Message;
use std::io::{Read, Write};
use tracing::trace;

/// Trust policy for the device attestation an Ark presents in the handshake.
/// It owns everything the wire deliberately does not (root keys, self-signing
/// rules, recovery overrides) and decides which Arks a session is opened with.
///
/// The attestation is a CWT, handed over as raw bytes for now; a typed form
/// will be exposed later.
pub trait Verifier {
    /// Session info extracted from an accepted attestation.
    type Info;

    /// Verifies the raw device attestation, returning the Ark's identity key
    /// along with any info extracted from the attestation. The handshake
    /// signature is checked against the returned key, so this decision is what
    /// authenticates the session. Rejecting the attestation aborts the handshake.
    fn verify(&self, attestation: &[u8]) -> Result<(xdsa::PublicKey, Self::Info), String>;
}

/// A pinned identity, accepting any attestation and handing it back as
/// presented. The handshake is authenticated against the pinned key instead.
impl Verifier for xdsa::PublicKey {
    type Info = Vec<u8>;

    fn verify(&self, attestation: &[u8]) -> Result<(xdsa::PublicKey, Self::Info), String> {
        Ok((self.clone(), attestation.to_vec()))
    }
}

/// Host side of the wire, an encrypted transport for issuing protobuf requests
/// to a connected Ark. It initiates sessions by signaling a transport reset and
/// driving the handshake, afterward encrypting outbound and decrypting inbound
/// messages.
///
/// The device attestation presented in the handshake is not interpreted by the
/// wire, it is handed to a `Verifier` deciding whether to trust the Ark.
pub struct HostSide<R: Read, W: Write> {
    framing: Framing<R, W>, // COBS framed transport for ingress and egress data

    session: Option<handshake::Session>, // Active encrypted session (if handshake completed)
}

impl<R: Read, W: Write> HostSide<R, W> {
    /// Creates a new host side around a low level reader and writer.
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            framing: Framing::new(reader, writer),
            session: None,
        }
    }

    /// Sends a session reset and drives the encrypted handshake with the Ark:
    ///
    ///   1. Host -> Ark:  HostHello { host_signer, host_crypto }           (plain CBOR)
    ///   2. Ark  -> Host: ArkHello  { ark_attest, ark_crypto, a2h_encap }  (cose::seal)
    ///   3. Host -> Ark:  HostAck   { h2a_encap }                          (cose::seal)
    ///
    /// The verifier receives the raw device attestation from the Ark's hello and
    /// its accepted info is returned once the session is established.
    pub fn handshake<V: Verifier>(&mut self, verifier: &V) -> Result<V::Info, Error> {
        self.session = None;

        // Send two zero bytes: first terminates any interrupted message, second
        // signals a fresh session.
        self.framing.send_reset()?;

        // Generate ephemeral host keys for this session
        let host_xdsa_sk = xdsa::SecretKey::generate();
        let host_xdsa_pk = host_xdsa_sk.public_key();
        let host_xhpke_sk = xhpke::SecretKey::generate();
        let host_xhpke_pk = host_xhpke_sk.public_key();

        // Message 1: Send HostHello (plain CBOR, COBS-framed)
        let hello = cbor::encode(&handshake::HostHello {
            host_signer: host_xdsa_pk.clone(),
            host_crypto: host_xhpke_pk.clone(),
        })
        .map_err(|err| Error::HandshakeFailed(format!("failed to encode host hello: {}", err)))?;

        self.framing.send_packet(&hello)?;

        // Message 2: Read ArkHello (COSE seal'd, COBS-framed)
        let Some(size) = self.framing.next_packet()? else {
            return Err(Error::HandshakeFailed(
                "empty frame instead of ark hello".into(),
            ));
        };
        let auth = handshake::ArkHelloAuth {
            host_signer: host_xdsa_pk.clone(),
            host_crypto: host_xhpke_pk.clone(),
        };

        // Step 2a: Decrypt the outer COSE_Encrypt0 layer
        let sign1 = cose::decrypt(
            &self.framing.decobs_buffer[..size],
            &auth,
            &host_xhpke_sk,
            CRYPTO_DOMAIN_WIRE,
        )
        .map_err(|err| Error::HandshakeFailed(format!("failed to decrypt ark hello: {}", err)))?;

        // Step 2b: Peek at the unverified payload to discover the Ark's identity
        let unverified: handshake::ArkHello = cose::peek(&sign1)
            .map_err(|err| Error::HandshakeFailed(format!("invalid ark hello payload: {}", err)))?;

        // Step 2c: Hand the attestation to the verifier to obtain the Ark's
        // identity key and the caller's session info
        let (ark_identity, info) = verifier
            .verify(&unverified.ark_attest)
            .map_err(Error::HandshakeFailed)?;

        // Step 2d: Verify the COSE_Sign1 signature with the discovered identity
        let ark_hello: handshake::ArkHello =
            cose::verify(&sign1, &auth, &ark_identity, CRYPTO_DOMAIN_WIRE, None).map_err(
                |err| Error::HandshakeFailed(format!("ark hello signature invalid: {}", err)),
            )?;

        // Set up the Ark->Host receiver context
        let enc_a2h: [u8; xhpke::ENCAP_KEY_SIZE] = ark_hello
            .a2h_encap
            .try_into()
            .map_err(|_| Error::HandshakeFailed("invalid a2h_encap size".into()))?;

        let receiver = host_xhpke_sk
            .new_receiver(&enc_a2h, CRYPTO_DOMAIN_WIRE_ARK_TO_HOST)
            .map_err(|err| {
                Error::HandshakeFailed(format!("host receiver setup failed: {}", err))
            })?;

        // Set up the Host->Ark sender context
        let ark_xhpke_pk = ark_hello.ark_crypto;
        let (sender, enc_h2a) = ark_xhpke_pk
            .new_sender(CRYPTO_DOMAIN_WIRE_HOST_TO_ARK)
            .map_err(|err| Error::HandshakeFailed(format!("host sender setup failed: {}", err)))?;

        // Message 3: Send HostAck (COSE seal'd, COBS-framed)
        let ack = cose::seal(
            &handshake::HostAck {
                h2a_encap: enc_h2a.to_vec(),
            },
            &handshake::HostAckAuth {
                ark_signer: ark_identity,
                ark_crypto: ark_xhpke_pk.clone(),
            },
            &host_xdsa_sk,
            &ark_xhpke_pk,
            CRYPTO_DOMAIN_WIRE,
        )
        .map_err(|err| Error::HandshakeFailed(format!("failed to seal host ack: {}", err)))?;

        self.framing.send_packet(&ack)?;

        // Session established
        self.session = Some(handshake::Session { sender, receiver });
        Ok(info)
    }

    /// Reads the next packet and decodes an ark-to-host response with protobuf.
    pub fn next_message(&mut self) -> Result<ArkToHost, Error> {
        // Retrieve the next COBS encoded packet. Empty frames are never sent by
        // the Ark, so surface them as the decode failures they would have been.
        let Some(size) = self.framing.next_packet()? else {
            return Err(Error::FrameDecodingFailed(cobs::DecodeError::EmptyInput));
        };

        // Decrypt the message
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| Error::EncryptionFailed("no active session".into()))?;

        let blob = session
            .receiver
            .open(&self.framing.decobs_buffer[..size], &[])
            .map_err(|err| Error::EncryptionFailed(format!("decryption failed: {}", err)))?;

        let res = ArkToHost::decode(&blob[..]).map_err(Error::PacketDecodingFailed)?;

        trace!("read ark-to-host message ({} bytes encrypted)", size);
        Ok(res)
    }

    /// Encodes a host-to-ark request with protobuf and injects it into the transport.
    pub fn send_message(&mut self, req: HostToArk) -> Result<(), Error> {
        // Encode it with protobuf
        let len = req.encoded_len();
        if len > MAX_FRAME_SIZE {
            return Err(Error::PacketTooLarge(len));
        }
        self.framing.encode_buffer.clear();
        if let Err(err) = req.encode(&mut self.framing.encode_buffer) {
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
        trace!("sent host-to-ark message ({} bytes)", len);
        Ok(())
    }

    /// Test and benchmark helper exposing the framer's `next_packet` with the
    /// decoded packet as a slice. Not part of the API.
    #[doc(hidden)]
    #[inline]
    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    pub fn next_packet_blob(&mut self) -> Result<Option<&[u8]>, Error> {
        self.framing.next_packet_blob()
    }

    /// Test and benchmark helper exposing the framer's `send_packet`. Not part
    /// of the API.
    #[doc(hidden)]
    #[inline]
    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    pub fn send_packet_blob(&mut self, packet: &[u8]) -> Result<(), Error> {
        self.framing.send_packet(packet)
    }

    /// Test and benchmark helper exposing the framer's `next_frame` with the raw
    /// frame as a slice. Not part of the API.
    #[doc(hidden)]
    #[inline]
    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    pub fn next_frame_blob(&mut self) -> Result<&[u8], Error> {
        self.framing.next_frame_blob()
    }

    /// Test and benchmark helper exposing the framer's `send_frame` with the raw
    /// frame taken from a slice. Not part of the API.
    #[doc(hidden)]
    #[inline]
    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    pub fn send_frame_blob(&mut self, frame: &[u8]) -> Result<(), Error> {
        self.framing.send_frame_blob(frame)
    }
}
