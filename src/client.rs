// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

use crate::emitter::{Emitter, Funnel, Side};
use crate::framing::FrameReader;
use crate::handshake;
use crate::protocol::{ArkToHost, HostToArk};
use crate::sealing;
use crate::server::Attestation;
use crate::{
    CRYPTO_DOMAIN_WIRE, CRYPTO_DOMAIN_WIRE_ARK_TO_HOST, CRYPTO_DOMAIN_WIRE_HOST_TO_ARK, Error,
};
use darkbio_crypto::{cbor, cose, xdsa, xhpke};
use darkbio_trust as trust;
use std::io::{Read, Write};
use std::sync::Arc;
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
pub struct Client<R: Read, W: Write> {
    reader: FrameReader<R>,            // COBS framed transport for ingress data
    receiver: Option<xhpke::Receiver>, // Inbound context of the session (if handshake completed)
    funnel: Arc<Funnel<W>>,            // Funnel of the session's sends, shared with the emitters
    emitter: Emitter<W, HostToArk>,    // Handle of the live session, cloned for the emitters
}

impl<R: Read, W: Write> Client<R, W> {
    /// Creates a new client side around a low level reader and writer. Reads block
    /// per the transport's semantics, so a timeout for an unresponsive server must
    /// be configured on the reader passed in.
    pub fn new(reader: R, writer: W) -> Self {
        let funnel = Arc::new(Funnel::new(writer, Side::Client));
        let emitter = funnel.emitter();
        Self {
            reader: FrameReader::new(reader),
            receiver: None,
            funnel,
            emitter,
        }
    }

    /// Creates a handle for sending messages from another thread, while the
    /// client blocks in `next_message`. The handle is bound to the live
    /// session, a new handshake needing a new one. See `Emitter`.
    pub fn emitter(&self) -> Emitter<W, HostToArk> {
        self.emitter.clone()
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
        // The old session ends here, its emitters refused from now on
        self.drop_session();

        // Send two zero bytes: first terminates any interrupted message, second
        // signals a fresh session.
        self.funnel.send_reset()?;

        let host_xdsa_pk = host_xdsa_sk.public_key();
        let host_xhpke_pk = host_xhpke_sk.public_key();

        // Message 1: Send HostHello (plain CBOR, COBS-framed)
        let hello = cbor::encode(&handshake::HostHello {
            host_signer: host_xdsa_pk.clone(),
            host_crypto: host_xhpke_pk.clone(),
        })
        .map_err(|err| Error::HandshakeFailed(format!("failed to encode client hello: {}", err)))?;

        self.funnel.send_packet(&hello)?;

        // Message 2: Read ArkHello (COSE seal'd, COBS-framed). Frames the server
        // emitted before processing the reset may still be queued, so skip
        // everything not sealed to the fresh client key.
        let host_xhpke_fp = host_xhpke_pk.fingerprint();

        let mut stale = 0;
        let packet = loop {
            // Empty frames are the server signaling an earlier session dropped,
            // stale junk too by now. So are frames failing to decode, the
            // leftovers of a transfer that was cut short.
            let packet: &[u8] = match self.reader.next_packet() {
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

        self.funnel.send_packet(&ack)?;

        // Session established, the ack ahead of anything sealed into it
        self.establish_session(sender, receiver);
        Ok(info)
    }

    /// Reads the next ark-to-host message, decrypting and protobuf decoding it.
    /// A frame that cannot be decoded or a packet that cannot be decrypted
    /// drops the session, as the server's HPKE sequence can no longer be followed.
    /// So does an empty frame, the server signaling it dropped the session on its
    /// end. Only a fresh handshake recovers from either.
    pub fn next_message(&mut self) -> Result<ArkToHost, Error> {
        // Retrieve the next COBS encoded packet. A skipped frame may have
        // carried a sealed message, so the session cannot continue past it.
        // An empty frame is the server telling us it has no session with us.
        let packet = match self.reader.next_packet() {
            Err(err) => {
                self.drop_session();
                return Err(err);
            }
            Ok(None) => {
                self.drop_session();
                return Err(Error::SessionReset);
            }
            Ok(Some(packet)) => packet,
        };
        // An emitter may have ended the session on its own thread, in which
        // case the receiver side goes down with it here
        if !self.funnel.has_session() {
            self.receiver = None;
        }
        // Decrypt the message and parse it with protobuf, dropping the session
        // if the HPKE sequence cannot be followed anymore
        let receiver = self
            .receiver
            .as_mut()
            .ok_or_else(|| Error::EncryptionFailed("no active session".into()))?;

        let res = match sealing::open(receiver, packet) {
            Err(err @ Error::EncryptionFailed(_)) => {
                self.drop_session();
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

    /// Protobuf encodes a host-to-ark message, seals it with the session and
    /// sends it. Fails without an active session, and a failure after sealing
    /// drops the session, as the server's HPKE sequence can no longer be caught up
    /// with.
    pub fn send_message(&mut self, req: HostToArk) -> Result<(), Error> {
        // The funnel dropping the session, on this send or on an emitter's
        // before it, drops it for the reads too
        let result = self.emitter.send_message(req);
        if !self.funnel.has_session() {
            self.receiver = None;
        }
        result
    }

    /// Installs the contexts of a freshly established session, the client's
    /// own handle bound to it.
    fn establish_session(&mut self, sender: xhpke::Sender, receiver: xhpke::Receiver) {
        self.receiver = Some(receiver);
        self.funnel.establish_session(sender);
        self.emitter = self.funnel.emitter();
    }

    /// Drops the session, both of its contexts going together.
    fn drop_session(&mut self) {
        self.receiver = None;
        self.funnel.drop_session();
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
        self.reader.next_packet()
    }

    /// Test and benchmark helper exposing the framer's `send_packet`. Not part
    /// of the API.
    #[doc(hidden)]
    #[inline]
    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn send_packet_blob(&mut self, packet: &[u8]) -> Result<(), Error> {
        self.funnel.send_packet(packet)
    }

    /// Test and benchmark helper exposing the framer's `next_frame` with the raw
    /// frame as a slice. Not part of the API.
    #[doc(hidden)]
    #[inline]
    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn next_frame_blob(&mut self) -> Result<&[u8], Error> {
        self.reader.next_frame_blob()
    }

    /// Test and benchmark helper exposing the framer's `send_frame` with the raw
    /// frame taken from a slice. Not part of the API.
    #[doc(hidden)]
    #[inline]
    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn send_frame_blob(&mut self, frame: &[u8]) -> Result<(), Error> {
        self.funnel.send_frame_blob(frame)
    }
}

impl<R: Read, W: Write> Drop for Client<R, W> {
    /// Ends the session for the emitters and lets go of the transport writer,
    /// so nothing stays open on their account.
    fn drop(&mut self) {
        self.funnel.close();
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

    /// A pair of contexts standing in for an established session.
    fn contexts() -> (xhpke::Sender, xhpke::Receiver) {
        let secret = xhpke::SecretKey::generate();
        let (sender, encap) = secret.public_key().new_sender(b"test").unwrap();
        let receiver = secret.new_receiver(&encap, b"test").unwrap();
        (sender, receiver)
    }

    /// A message with the id.
    fn message(id: u64) -> HostToArk {
        HostToArk {
            id: Some(id),
            ..Default::default()
        }
    }

    // Tests that emitters send from other threads while the client blocks in
    // a read, the server receiving every message in the order sealed, or it
    // would drop the session instead of echoing them.
    #[test]
    fn test_emitters() {
        testing::init_tracing();

        // Echo every request over pipes, then hang up
        let (ark_reader, host_writer) = io::pipe().unwrap();
        let (host_reader, ark_writer) = io::pipe().unwrap();

        let signer = xdsa::SecretKey::generate();
        let identity = signer.public_key();
        let attestation = self_attestation(&signer);
        let ark = thread::spawn(move || {
            let mut server = Server::new(ark_reader, ark_writer, signer, attestation);
            for _ in 0..100 {
                let req = server.next_message().unwrap();
                server
                    .send_message(ArkToHost {
                        id: req.id,
                        ..Default::default()
                    })
                    .unwrap();
            }
        });
        let mut client = Client::new(host_reader, host_writer);
        client.handshake(&identity).unwrap();

        // Send from a few threads at once while reading the echoes on this one
        let senders: Vec<_> = (0..4)
            .map(|thread| {
                let emitter = client.emitter();
                thread::spawn(move || {
                    for i in 0..25 {
                        emitter.send_message(message(thread * 100 + i)).unwrap();
                    }
                })
            })
            .collect();
        let mut ids: Vec<u64> = (0..100)
            .map(|_| client.next_message().unwrap().id.unwrap())
            .collect();
        for sender in senders {
            sender.join().unwrap();
        }
        ark.join().unwrap();

        ids.sort_unstable();
        let mut expected: Vec<u64> = (0..4)
            .flat_map(|thread| (0..25).map(move |i| thread * 100 + i))
            .collect();
        expected.sort_unstable();
        assert_eq!(ids, expected);
    }

    // Tests that an emitter is bound to the session it was made in, a new
    // handshake refusing it while a fresh one sends into the new session.
    #[test]
    fn test_emitter_session_bound() {
        testing::init_tracing();

        // Echo one request over pipes, then hang up
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
        let stale = client.emitter();
        client.handshake(&identity).unwrap();

        let result = stale.send_message(message(1));
        assert!(
            matches!(&result, Err(Error::EncryptionFailed(msg)) if msg == "session ended"),
            "{result:?}"
        );
        client.emitter().send_message(message(2)).unwrap();
        assert_eq!(client.next_message().unwrap().id, Some(2));
        ark.join().unwrap();
    }

    // Tests that the session drops as a whole, a failed read refusing the
    // sends and a failed send refusing the reads, whether the client or an
    // emitter sent.
    #[test]
    fn test_session_lockstep() {
        testing::init_tracing();

        // The reader ending the wire refuses the sends
        let (sender, receiver) = contexts();
        let mut client = Client::new(io::empty(), Vec::new());
        client.establish_session(sender, receiver);
        let emitter = client.emitter();

        let result = client.next_message();
        assert!(matches!(result, Err(Error::Terminated)), "{result:?}");
        let result = client.send_message(message(1));
        assert!(
            matches!(result, Err(Error::EncryptionFailed(_))),
            "{result:?}"
        );
        let result = emitter.send_message(message(1));
        assert!(
            matches!(result, Err(Error::EncryptionFailed(_))),
            "{result:?}"
        );

        // The writer failing to deliver refuses the reads
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
        client.establish_session(sender, receiver);

        let result = client.send_message(message(1));
        assert!(matches!(result, Err(Error::SendFailed(_))), "{result:?}");
        assert!(client.receiver.is_none());

        // An emitter failing to deliver refuses the reads once the client
        // gets to them, a frame waiting notwithstanding
        let (sender, receiver) = contexts();
        let mut client = Client::new(&[0x02, 0x05, 0x00][..], Broken);
        client.establish_session(sender, receiver);
        let emitter = client.emitter();

        let result = emitter.send_message(message(1));
        assert!(matches!(result, Err(Error::SendFailed(_))), "{result:?}");
        let result = client.next_message();
        assert!(
            matches!(&result, Err(Error::EncryptionFailed(msg)) if msg == "no active session"),
            "{result:?}"
        );
        assert!(client.receiver.is_none());
    }

    // Tests that dropping the client ends the session for its emitters and
    // lets go of the transport writer, so nothing stays open on their account.
    #[test]
    fn test_emitter_outlives_client() {
        testing::init_tracing();

        let (mut reader, writer) = io::pipe().unwrap();
        let (sender, receiver) = contexts();
        let mut client = Client::new(io::empty(), writer);
        client.establish_session(sender, receiver);
        let emitter = client.emitter();
        emitter.send_message(message(1)).unwrap();
        drop(client);

        let result = emitter.send_message(message(2));
        assert!(
            matches!(result, Err(Error::EncryptionFailed(_))),
            "{result:?}"
        );
        // The read only returns once the writer is gone
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert!(!bytes.is_empty());
    }
}
