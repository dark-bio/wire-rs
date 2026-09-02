// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

use crate::framing::Framing;
use crate::handshake;
use crate::protocol::{ArkToHost, HostToArk};
use crate::session::Session;
use crate::side_ark::Attestation;
use crate::{
    CRYPTO_DOMAIN_WIRE, CRYPTO_DOMAIN_WIRE_ARK_TO_HOST, CRYPTO_DOMAIN_WIRE_HOST_TO_ARK, Error,
};
use darkbio_cobs as cobs;
use darkbio_crypto::{cbor, cose, xdsa, xhpke};
use darkbio_trust as trust;
use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{trace, warn};

/// Maximum number of queued frames skipped while waiting for the ArkHello of a
/// handshake, before giving up on the Ark. A well-behaved Ark only ever leaves
/// a handful behind, as its writer blocks once the transport buffers fill up.
const MAX_STALE_FRAMES: usize = 32;

/// Trust policy for the device attestation an Ark presents in the handshake.
/// It owns everything the wire deliberately does not (which roots to trust,
/// self-signing rules, recovery overrides) and decides which Arks a session is
/// opened with.
pub trait Verifier {
    /// Session info extracted from an accepted attestation.
    type Info;

    /// Verifies the device attestation, returning the Ark's identity key along
    /// with any info extracted from the attestation. The handshake signature is
    /// checked against the returned key, so this decision is what authenticates
    /// the session. Rejecting the attestation aborts the handshake.
    fn verify(&self, attestation: &Attestation) -> Result<(xdsa::PublicKey, Self::Info), String>;
}

/// A pinned identity, accepting any attestation and handing it back as
/// presented. The handshake is authenticated against the pinned key instead.
impl Verifier for xdsa::PublicKey {
    type Info = Attestation;

    fn verify(&self, attestation: &Attestation) -> Result<(xdsa::PublicKey, Self::Info), String> {
        Ok((self.clone(), attestation.clone()))
    }
}

/// Roots of trust, accepting the Arks attested under them: hardware Arks by
/// the hardware roots and emulated Arks by the emulator roots, the attestation
/// having to be valid at the current time. An Ark that was never onboarded is
/// rejected, its self-signed attestation being an onboarding decision rather
/// than one of trust.
pub struct Roots<'a> {
    pub hardware: &'a [xdsa::PublicKey], // Roots attesting hardware Arks
    pub emulator: &'a [xdsa::PublicKey], // Roots attesting emulated Arks
}

impl Verifier for Roots<'_> {
    type Info = trust::device::Device;

    fn verify(&self, attestation: &Attestation) -> Result<(xdsa::PublicKey, Self::Info), String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| err.to_string())?
            .as_secs();

        let device = trust::device::verify(
            attestation.as_bytes(),
            self.hardware,
            self.emulator,
            Some(now),
        )
        .map_err(|err| err.to_string())?;
        Ok((device.signer.clone(), device))
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
    framing: Framing<R, W>,   // COBS framed transport for ingress and egress data
    session: Option<Session>, // Active encrypted session (if handshake completed)
}

impl<R: Read, W: Write> HostSide<R, W> {
    /// Creates a new host side around a low level reader and writer. Reads block
    /// per the transport's semantics, so a timeout for an unresponsive Ark must
    /// be configured on the reader passed in.
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

        // Message 2: Read ArkHello (COSE seal'd, COBS-framed). Frames the Ark
        // emitted before processing the reset may still be queued, so skip
        // everything not sealed to the fresh host key.
        let host_xhpke_fp = host_xhpke_pk.fingerprint();

        let mut stale = 0;
        let size = loop {
            // Empty frames are never sent by the Ark, they are stale junk too
            let size = self.framing.next_packet()?.unwrap_or_default();
            let recipient = cose::recipient(&self.framing.decobs_buffer[..size]);
            if recipient.is_ok_and(|fp| fp == host_xhpke_fp) {
                break size;
            }
            stale += 1;
            if stale > MAX_STALE_FRAMES {
                return Err(Error::HandshakeFailed(
                    "too many stale frames before ark hello".into(),
                ));
            }
            warn!("skipping stale frame during handshake");
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
        let attestation = Attestation::new(unverified.ark_attest)?;
        let (ark_identity, info) = verifier
            .verify(&attestation)
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
        self.session = Some(Session { sender, receiver });
        Ok(info)
    }

    /// Reads the next ark-to-host message, decrypting and protobuf decoding it.
    /// A frame that cannot be decoded or a packet that cannot be decrypted
    /// drops the session, as the Ark's HPKE sequence can no longer be followed;
    /// only a fresh handshake recovers from that.
    pub fn next_message(&mut self) -> Result<ArkToHost, Error> {
        // Retrieve the next COBS encoded packet. A skipped frame may have
        // carried a sealed message, so the session cannot continue past it.
        // Empty frames are never sent by the Ark, so surface them as the
        // decode failures they would have been.
        let size = match self.framing.next_packet() {
            Err(err) => {
                self.session = None;
                return Err(err);
            }
            Ok(None) => return Err(Error::FrameDecodingFailed(cobs::DecodeError::EmptyInput)),
            Ok(Some(size)) => size,
        };
        // Decrypt the message and parse it with protobuf, dropping the session
        // if the HPKE sequence cannot be followed anymore
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| Error::EncryptionFailed("no active session".into()))?;

        let res = match session.open(&self.framing.decobs_buffer[..size]) {
            Err(err @ Error::EncryptionFailed(_)) => {
                self.session = None;
                return Err(err);
            }
            Err(err) => return Err(err),
            Ok(res) => res,
        };
        trace!("read ark-to-host message ({} bytes encrypted)", size);
        Ok(res)
    }

    /// Protobuf encodes a host-to-ark message, seals it with the session and
    /// sends it. Fails without an active session, and a failure after sealing
    /// drops the session, as the Ark's HPKE sequence can no longer be caught up
    /// with.
    pub fn send_message(&mut self, req: HostToArk) -> Result<(), Error> {
        // Encode and seal the message, oversized messages are rejected before
        // the HPKE sequence advances, only a failed seal breaks the session
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| Error::EncryptionFailed("no active session".into()))?;

        let blob = match session.seal(&req, &mut self.framing.encode_buffer) {
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
        trace!("sent host-to-ark message ({} bytes)", blob.len());
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
