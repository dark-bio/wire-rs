// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

use crate::framing::{FrameReader, FrameWriter};
use crate::handshake;
use crate::protocol::{ArkToHost, HostToArk};
use crate::sealing;
use crate::server::Attestation;
use crate::{
    CRYPTO_DOMAIN_WIRE, CRYPTO_DOMAIN_WIRE_ARK_TO_HOST, CRYPTO_DOMAIN_WIRE_HOST_TO_ARK, Error,
    MAX_MESSAGE_SIZE,
};
use darkbio_crypto::{cbor, cose, xdsa, xhpke};
use darkbio_trust as trust;
use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{trace, warn};

/// Maximum number of queued frames skipped while waiting for the ArkHello of a
/// handshake, before giving up on the server. A well-behaved server only ever leaves
/// a handful behind, as its writer blocks once the transport buffers fill up.
pub(crate) const MAX_STALE_FRAMES: usize = 32;

/// Trust policy for the device attestation a server presents in the handshake.
/// It owns everything the wire deliberately does not (which roots to trust,
/// self-signing rules, recovery overrides) and decides which Arks a session is
/// opened with.
pub trait Verifier {
    /// Session info extracted from an accepted attestation.
    type Info;

    /// Verifies the device attestation, returning the server's identity key along
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

/// Roots of trust, accepting the Arks attested under them. Hardware Arks are
/// accepted by the hardware roots and emulated Arks by the emulator roots, the
/// attestation having to be valid at the current time. An Ark that was never
/// onboarded is rejected, its self-signed attestation being an onboarding
/// decision rather than one of trust.
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

/// Client side of the wire, an encrypted transport for issuing protobuf requests
/// to a connected server. It initiates sessions by signaling a transport reset and
/// driving the handshake, afterward encrypting outbound and decrypting inbound
/// messages.
///
/// An empty frame from the server means it has no session with the client anymore.
/// It surfaces as `Error::SessionReset` with the client's session dropped too,
/// so the caller can handshake again instead of waiting on a dead session.
///
/// The device attestation presented in the handshake is not interpreted by the
/// wire, it is handed to a `Verifier` deciding whether to trust the server.
///
/// The client is a reading and a writing half joined, `split` taking them
/// apart once a session is established, so one thread can block in a read
/// while others send. Joined, a failure of either half drops the session as a
/// whole. Apart, each half drops only its own context, whoever split them
/// ending the other.
pub struct Client<R: Read, W: Write> {
    reader: MessageReader<R>, // Reading half, the frames coming in and the context opening them
    writer: MessageWriter<W>, // Writing half, the context sealing messages and the frames going out
}

/// Reading half of a split client, receiving and opening the messages of the
/// server. A failure drops its inbound context, `next_message` refusing to go
/// on until a fresh handshake, which only the joined client can run.
pub struct MessageReader<R: Read> {
    framing: FrameReader<R>,           // COBS framed transport for ingress data
    receiver: Option<xhpke::Receiver>, // Inbound context of the session (if handshake completed)
}

/// Writing half of a split client, sealing and sending messages to the server.
/// A failure drops its outbound context, `send_message` refusing to go on
/// until a fresh handshake, which only the joined client can run.
pub struct MessageWriter<W: Write> {
    framing: FrameWriter<W>,       // COBS framed transport for egress data
    sender: Option<xhpke::Sender>, // Outbound context of the session (if handshake completed)
    scratch: Vec<u8>,              // Scratch for protobuf encoding a message before sealing
}

impl<R: Read, W: Write> Client<R, W> {
    /// Creates a new client side around a low level reader and writer. Reads block
    /// per the transport's semantics, so a timeout for an unresponsive server must
    /// be configured on the reader passed in.
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader: MessageReader::new(reader),
            writer: MessageWriter::new(writer),
        }
    }

    /// Takes the client apart into its reading and writing halves, each usable
    /// from its own thread. The halves keep the session established so far,
    /// but fail independently from then on, so the caller ends the other half
    /// when one fails.
    pub fn split(self) -> (MessageReader<R>, MessageWriter<W>) {
        (self.reader, self.writer)
    }

    /// Sends a session reset and drives the encrypted handshake with the server:
    ///
    ///   1. Client -> Server: HostHello { host_signer, host_crypto }           (plain CBOR)
    ///   2. Server -> Client: ArkHello  { ark_attest, ark_crypto, a2h_encap }  (cose::seal)
    ///   3. Client -> Server: HostAck   { h2a_encap }                          (cose::seal)
    ///
    /// The verifier receives the raw device attestation from the server's hello and
    /// its accepted info is returned once the session is established.
    pub fn handshake<V: Verifier>(&mut self, verifier: &V) -> Result<V::Info, Error> {
        // Generate ephemeral client keys for this session
        let host_xdsa_sk = xdsa::SecretKey::generate();
        let host_xhpke_sk = xhpke::SecretKey::generate();
        self.handshake_with(verifier, host_xdsa_sk, host_xhpke_sk, None)
    }

    /// Drives the handshake with the given ephemeral keys, the ack signed at
    /// the given time instead of now if one is given. This method is internally
    /// used to generate deterministic test vectors for 3rd party implementations.
    fn handshake_with<V: Verifier>(
        &mut self,
        verifier: &V,
        host_xdsa_sk: xdsa::SecretKey,
        host_xhpke_sk: xhpke::SecretKey,
        timestamp: Option<i64>,
    ) -> Result<V::Info, Error> {
        self.reader.receiver = None;
        self.writer.sender = None;

        // Send two zero bytes: first terminates any interrupted message, second
        // signals a fresh session.
        self.writer.framing.send_reset()?;

        let host_xdsa_pk = host_xdsa_sk.public_key();
        let host_xhpke_pk = host_xhpke_sk.public_key();

        // Message 1: Send HostHello (plain CBOR, COBS-framed)
        let hello = cbor::encode(&handshake::HostHello {
            host_signer: host_xdsa_pk.clone(),
            host_crypto: host_xhpke_pk.clone(),
        })
        .map_err(|err| Error::HandshakeFailed(format!("failed to encode client hello: {}", err)))?;

        self.writer.framing.send_packet(&hello)?;

        // Message 2: Read ArkHello (COSE seal'd, COBS-framed). Frames the server
        // emitted before processing the reset may still be queued, so skip
        // everything not sealed to the fresh client key.
        let host_xhpke_fp = host_xhpke_pk.fingerprint();

        let mut stale = 0;
        let packet = loop {
            // Empty frames are the server signaling an earlier session dropped,
            // stale junk too by now. So are frames failing to decode, the
            // leftovers of a transfer that was cut short.
            let packet: &[u8] = match self.reader.framing.next_packet() {
                Ok(Some(packet)) => packet,
                Ok(None) | Err(Error::FrameDecodingFailed(_)) => &[],
                Err(err) => return Err(err),
            };
            if cose::recipient(packet).is_ok_and(|fp| fp == host_xhpke_fp) {
                break packet;
            }
            stale += 1;
            if stale > MAX_STALE_FRAMES {
                return Err(Error::HandshakeFailed(
                    "too many stale frames before server hello".into(),
                ));
            }
            warn!("skipping stale frame during handshake");
        };
        let auth = handshake::ArkHelloAuth {
            host_signer: host_xdsa_pk.clone(),
            host_crypto: host_xhpke_pk.clone(),
        };

        // Step 2a: Decrypt the outer COSE_Encrypt0 layer
        let sign1 =
            cose::decrypt(packet, &auth, &host_xhpke_sk, CRYPTO_DOMAIN_WIRE).map_err(|err| {
                Error::HandshakeFailed(format!("failed to decrypt server hello: {}", err))
            })?;

        // Step 2b: Peek at the unverified payload to discover the server's identity
        let unverified: handshake::ArkHello = cose::peek(&sign1).map_err(|err| {
            Error::HandshakeFailed(format!("invalid server hello payload: {}", err))
        })?;

        // Step 2c: Hand the attestation to the verifier to obtain the server's
        // identity key and the caller's session info
        let attestation = Attestation::new(unverified.ark_attest)?;
        let (ark_identity, info) = verifier
            .verify(&attestation)
            .map_err(Error::HandshakeFailed)?;

        // Step 2d: Verify the COSE_Sign1 signature with the discovered identity
        let ark_hello: handshake::ArkHello =
            cose::verify(&sign1, &auth, &ark_identity, CRYPTO_DOMAIN_WIRE, None).map_err(
                |err| Error::HandshakeFailed(format!("server hello signature invalid: {}", err)),
            )?;

        // Set up the server->Client receiver context
        let enc_a2h: [u8; xhpke::ENCAP_KEY_SIZE] = ark_hello
            .a2h_encap
            .try_into()
            .map_err(|_| Error::HandshakeFailed("invalid a2h_encap size".into()))?;

        let receiver = host_xhpke_sk
            .new_receiver(&enc_a2h, CRYPTO_DOMAIN_WIRE_ARK_TO_HOST)
            .map_err(|err| {
                Error::HandshakeFailed(format!("client receiver setup failed: {}", err))
            })?;

        // Set up the Client->server sender context
        let ark_xhpke_pk = ark_hello.ark_crypto;
        let (sender, enc_h2a) = ark_xhpke_pk
            .new_sender(CRYPTO_DOMAIN_WIRE_HOST_TO_ARK)
            .map_err(|err| {
                Error::HandshakeFailed(format!("client sender setup failed: {}", err))
            })?;

        // Message 3: Send HostAck (COSE seal'd, COBS-framed)
        let ack = handshake::HostAck {
            h2a_encap: enc_h2a.to_vec(),
        };
        let auth = handshake::HostAckAuth {
            ark_signer: ark_identity,
            ark_crypto: ark_xhpke_pk.clone(),
        };
        let ack = match timestamp {
            Some(timestamp) => cose::seal_at(
                &ack,
                &auth,
                &host_xdsa_sk,
                &ark_xhpke_pk,
                CRYPTO_DOMAIN_WIRE,
                timestamp,
            ),
            None => cose::seal(
                &ack,
                &auth,
                &host_xdsa_sk,
                &ark_xhpke_pk,
                CRYPTO_DOMAIN_WIRE,
            ),
        }
        .map_err(|err| Error::HandshakeFailed(format!("failed to seal client ack: {}", err)))?;

        self.writer.framing.send_packet(&ack)?;

        // Session established
        self.reader.receiver = Some(receiver);
        self.writer.sender = Some(sender);
        Ok(info)
    }

    /// Reads the next ark-to-host message, decrypting and protobuf decoding it.
    /// A frame that cannot be decoded or a packet that cannot be decrypted
    /// drops the session, as the server's HPKE sequence can no longer be followed.
    /// So does an empty frame, the server signaling it dropped the session on its
    /// end. Only a fresh handshake recovers from either.
    pub fn next_message(&mut self) -> Result<ArkToHost, Error> {
        // The reading half dropping its context drops the session as a whole
        let res = self.reader.next_message();
        if self.reader.receiver.is_none() {
            self.writer.sender = None;
        }
        res
    }

    /// Protobuf encodes a host-to-ark message, seals it with the session and
    /// sends it. Fails without an active session, and a failure after sealing
    /// drops the session, as the server's HPKE sequence can no longer be caught up
    /// with.
    pub fn send_message(&mut self, req: HostToArk) -> Result<(), Error> {
        // The writing half dropping its context drops the session as a whole
        let res = self.writer.send_message(req);
        if self.writer.sender.is_none() {
            self.reader.receiver = None;
        }
        res
    }

    /// Test helper running the handshake with the given ephemeral keys instead
    /// of fresh ones and the ack signed at the given time, so a transcript of
    /// it can be replayed. Not part of the API.
    #[doc(hidden)]
    #[inline]
    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn handshake_with_keys<V: Verifier>(
        &mut self,
        verifier: &V,
        host_xdsa_sk: xdsa::SecretKey,
        host_xhpke_sk: xhpke::SecretKey,
        timestamp: i64,
    ) -> Result<V::Info, Error> {
        self.handshake_with(verifier, host_xdsa_sk, host_xhpke_sk, Some(timestamp))
    }

    /// Test and benchmark helper exposing the framer's `next_packet` with the
    /// decoded packet as a slice. Not part of the API.
    #[doc(hidden)]
    #[inline]
    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn next_packet_blob(&mut self) -> Result<Option<&[u8]>, Error> {
        self.reader.framing.next_packet()
    }

    /// Test and benchmark helper exposing the framer's `send_packet`. Not part
    /// of the API.
    #[doc(hidden)]
    #[inline]
    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn send_packet_blob(&mut self, packet: &[u8]) -> Result<(), Error> {
        self.writer.framing.send_packet(packet)
    }

    /// Test and benchmark helper exposing the framer's `next_frame` with the raw
    /// frame as a slice. Not part of the API.
    #[doc(hidden)]
    #[inline]
    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn next_frame_blob(&mut self) -> Result<&[u8], Error> {
        self.reader.framing.next_frame_blob()
    }

    /// Test and benchmark helper exposing the framer's `send_frame` with the raw
    /// frame taken from a slice. Not part of the API.
    #[doc(hidden)]
    #[inline]
    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn send_frame_blob(&mut self, frame: &[u8]) -> Result<(), Error> {
        self.writer.framing.send_frame_blob(frame)
    }
}

impl<R: Read> MessageReader<R> {
    /// Creates the reading half around a low level reader, without a context
    /// until the joined client's handshake fills one in.
    fn new(reader: R) -> Self {
        Self {
            framing: FrameReader::new(reader),
            receiver: None,
        }
    }

    /// Reads the next ark-to-host message, decrypting and protobuf decoding it.
    /// A frame that cannot be decoded or a packet that cannot be decrypted
    /// drops the inbound context, as the server's HPKE sequence can no longer be
    /// followed. So does an empty frame, the server signaling it dropped the
    /// session on its end. Only a fresh handshake recovers from either.
    pub fn next_message(&mut self) -> Result<ArkToHost, Error> {
        // Retrieve the next COBS encoded packet. A skipped frame may have
        // carried a sealed message, so the session cannot continue past it.
        // An empty frame is the server telling us it has no session with us.
        let packet = match self.framing.next_packet() {
            Err(err) => {
                self.receiver = None;
                return Err(err);
            }
            Ok(None) => {
                self.receiver = None;
                return Err(Error::SessionReset);
            }
            Ok(Some(packet)) => packet,
        };
        // Decrypt the message and parse it with protobuf, dropping the context
        // if the HPKE sequence cannot be followed anymore
        let receiver = self
            .receiver
            .as_mut()
            .ok_or_else(|| Error::EncryptionFailed("no active session".into()))?;

        let res = match sealing::open(receiver, packet) {
            Err(err @ Error::EncryptionFailed(_)) => {
                self.receiver = None;
                return Err(err);
            }
            Err(err) => return Err(err),
            Ok(res) => res,
        };
        trace!(
            "read ark-to-host message ({} bytes encrypted)",
            packet.len()
        );
        Ok(res)
    }
}

impl<W: Write> MessageWriter<W> {
    /// Creates the writing half around a low level writer, without a context
    /// until the joined client's handshake fills one in.
    fn new(writer: W) -> Self {
        Self {
            framing: FrameWriter::new(writer),
            sender: None,
            scratch: Vec::with_capacity(MAX_MESSAGE_SIZE),
        }
    }

    /// Protobuf encodes a host-to-ark message, seals it with the session and
    /// sends it. Fails without an active session, and a failure after sealing
    /// drops the outbound context, as the server's HPKE sequence can no longer
    /// be caught up with.
    pub fn send_message(&mut self, req: HostToArk) -> Result<(), Error> {
        // Encode and seal the message, oversized messages are rejected before
        // the HPKE sequence advances, only a failed seal breaks the context
        let sender = self
            .sender
            .as_mut()
            .ok_or_else(|| Error::EncryptionFailed("no active session".into()))?;

        let blob = match sealing::seal(sender, &req, &mut self.scratch) {
            Err(err @ Error::EncryptionFailed(_)) => {
                self.sender = None;
                return Err(err);
            }
            Err(err) => return Err(err),
            Ok(blob) => blob,
        };
        // Send the sealed message, tearing down the context if the transport
        // fails to deliver it
        if let Err(err) = self.framing.send_packet(&blob) {
            self.sender = None;
            return Err(err);
        }
        trace!("sent host-to-ark message ({} bytes)", blob.len());
        Ok(())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::mock::self_attestation;
    use crate::server::Server;
    use crate::testing;
    use std::io;
    use std::thread;

    // Tests that a split client reads on one thread while writing on another,
    // the halves carrying the session the joined client established.
    #[test]
    fn test_split() {
        testing::init_tracing();

        // Serve the first request over pipes, then hang up
        let (ark_reader, host_writer) = io::pipe().unwrap();
        let (host_reader, ark_writer) = io::pipe().unwrap();

        let signer = xdsa::SecretKey::generate();
        let identity = signer.public_key();
        let attestation = self_attestation(&signer);
        let ark = thread::spawn(move || {
            let mut server = Server::new(ark_reader, ark_writer, signer, attestation);
            let req = server.next_message().unwrap();
            server
                .send_message(ArkToHost {
                    id: req.id,
                    ..Default::default()
                })
                .unwrap();
        });
        let mut client = Client::new(host_reader, host_writer);
        client.handshake(&identity).unwrap();
        let (mut reader, mut writer) = client.split();

        // Wait for the response on one thread while sending on this one
        let reading = thread::spawn(move || reader.next_message().map(|res| res.id));
        writer
            .send_message(HostToArk {
                id: Some(7),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(reading.join().unwrap().unwrap(), Some(7));
        ark.join().unwrap();
    }

    // Tests that the halves fail independently, a failed read dropping only
    // the inbound context, whereas the joined client drops both contexts on a
    // failure of either.
    #[test]
    fn test_split_contexts() {
        testing::init_tracing();

        // A pair of contexts standing in for an established session
        let contexts = || {
            let secret = xhpke::SecretKey::generate();
            let (sender, encap) = secret.public_key().new_sender(b"test").unwrap();
            let receiver = secret.new_receiver(&encap, b"test").unwrap();
            (sender, receiver)
        };
        let message = || HostToArk {
            id: Some(1),
            ..Default::default()
        };

        // Apart, the reader ending the wire leaves the writer sealing
        let (sender, receiver) = contexts();
        let mut reader = MessageReader::new(io::empty());
        reader.receiver = Some(receiver);
        let mut writer = MessageWriter::new(Vec::new());
        writer.sender = Some(sender);
        assert!(matches!(reader.next_message(), Err(Error::Terminated)));
        assert!(reader.receiver.is_none());
        writer.send_message(message()).unwrap();
        assert!(writer.sender.is_some());

        // Joined, the reader ending the wire refuses the writer too
        let (sender, receiver) = contexts();
        let mut client = Client::new(io::empty(), Vec::new());
        client.reader.receiver = Some(receiver);
        client.writer.sender = Some(sender);
        assert!(matches!(client.next_message(), Err(Error::Terminated)));
        assert!(client.writer.sender.is_none());
        assert!(matches!(
            client.send_message(message()),
            Err(Error::EncryptionFailed(_))
        ));

        // Joined, the writer failing to deliver refuses the reader too
        struct Broken;

        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("broken"))
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let (sender, receiver) = contexts();
        let mut client = Client::new(io::empty(), Broken);
        client.reader.receiver = Some(receiver);
        client.writer.sender = Some(sender);
        assert!(matches!(
            client.send_message(message()),
            Err(Error::SendFailed(_))
        ));
        assert!(client.reader.receiver.is_none());
        assert!(matches!(client.next_message(), Err(Error::Terminated)));
    }
}
