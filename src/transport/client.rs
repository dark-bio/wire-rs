// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

use crate::transport::framing::FrameReader;
use crate::transport::handshake;
use crate::transport::outbound::{Outbound, Side};
use crate::transport::sender::Sender;
use crate::transport::server::Attestation;
use crate::transport::session::Session;
use crate::transport::{
    CRYPTO_DOMAIN_WIRE, CRYPTO_DOMAIN_WIRE_ARK_TO_HOST, CRYPTO_DOMAIN_WIRE_HOST_TO_ARK, Closer,
    Error, Stream,
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
/// Client side of the wire, exchanging encrypted messages over a supplied byte
/// stream. [`Client::connect`] initiates a session by signaling a reset and driving
/// the handshake. It returns a [`Sender`] for outbound messages, while
/// [`Client::recv`] decrypts inbound messages.
///
/// An empty frame from the server means it has no session with the client anymore.
/// It surfaces as [`Error::SessionReset`] with the client's session dropped too,
/// so the caller can connect again instead of waiting on a dead session.
///
/// The device attestation presented in the handshake is not interpreted by the
/// wire, it is handed to a [`Verifier`] deciding whether to trust the server.
pub struct Client<R: Read, W: Write> {
    reader: FrameReader<R>,     // COBS framed transport for ingress data
    session: Option<Session>,   // Encryption contexts and lifetime of the current session
    outbound: Arc<Outbound<W>>, // Outgoing transport, shared with the senders
}

impl<R: Read, W: Write> Client<R, W> {
    /// Creates a client owning the byte stream and its shutdown operation, without
    /// an encrypted session. Call [`Client::connect`] to establish one.
    /// I/O deadlines and cancellation bounds are supplied by the stream adapter.
    pub fn new(stream: Stream<R, W>) -> Self {
        let (reader, writer, close) = stream.into_parts();

        let outbound = Arc::new(Outbound::new(writer, Side::Client, close.clone()));

        Self {
            reader: FrameReader::new(reader, close),
            session: None,
            outbound,
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

    /// Establishes an encrypted session over the supplied stream, ending any
    /// previous session first. Sends a reset and drives the handshake:
    ///
    ///   1. Client -> Server: HostHello { host_signer, host_crypto }           (plain CBOR)
    ///   2. Server -> Client: ArkHello  { ark_attest, ark_crypto, a2h_encap }  (cose::seal)
    ///   3. Client -> Server: HostAck   { h2a_encap }                          (cose::seal)
    ///
    /// The verifier receives the raw device attestation from the server's hello
    /// and its accepted info is returned alongside the sender of the established
    /// session. The sender stays bound to that session through later calls to
    /// `connect`; it cannot send into a replacement session. If connecting fails,
    /// the client has no session and previously issued senders remain invalid.
    pub fn connect<V: Verifier>(&mut self, verifier: &V) -> Result<(Sender<W>, V::Info), Error> {
        // Generate ephemeral client keys for this session
        let host_xdsa_sk = xdsa::SecretKey::generate();
        let host_xhpke_sk = xhpke::SecretKey::generate();
        self.handshake(verifier, host_xdsa_sk, host_xhpke_sk, None)
    }

    /// Ends any previous session, sends a reset and drives the handshake with the
    /// given ephemeral keys. Returns the new session's sender and verified info.
    /// The optional signing time makes the exchange deterministic for test vectors.
    fn handshake<V: Verifier>(
        &mut self,
        verifier: &V,
        host_xdsa_sk: xdsa::SecretKey,
        host_xhpke_sk: xhpke::SecretKey,
        timestamp: Option<i64>,
    ) -> Result<(Sender<W>, V::Info), Error> {
        // The old session ends here, its senders refused from now on
        self.end_session();

        // Send two zero bytes: first terminates any interrupted message, second
        // signals a fresh session.
        self.outbound.send_reset()?;

        let host_xdsa_pk = host_xdsa_sk.public_key();
        let host_xhpke_pk = host_xhpke_sk.public_key();

        // Message 1: Send HostHello (plain CBOR, COBS-framed)
        let hello = cbor::encode(&handshake::HostHello {
            host_signer: host_xdsa_pk.clone(),
            host_crypto: host_xhpke_pk.clone(),
        })
        .map_err(|err| Error::HandshakeFailed(format!("failed to encode client hello: {}", err)))?;

        self.outbound.send_packet(&hello)?;

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

        self.outbound.send_packet(&ack)?;

        // Session established, the ack ahead of anything sealed into it
        let sender = self.new_session(sender, receiver);
        Ok((sender, info))
    }

    /// Reads the next ark-to-host message, decrypting it. A frame that cannot
    /// be decoded or a packet that cannot be decrypted drops the session, as
    /// the server's HPKE sequence can no longer be followed. So does an empty
    /// frame, the server signaling it dropped the session on its end. Call
    /// [`Client::connect`] to establish a new session after either failure.
    pub fn recv(&mut self) -> Result<Vec<u8>, Error> {
        // Retrieve the next COBS encoded packet. A skipped frame may have
        // carried a sealed message, so the session cannot continue past it.
        // An empty frame is the server telling us it has no session with us.
        let packet = match self.reader.next_packet() {
            Err(err) => {
                self.end_session();
                return Err(err);
            }
            Ok(None) => {
                self.end_session();
                return Err(Error::SessionReset);
            }
            Ok(Some(packet)) => packet,
        };
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| Error::EncryptionFailed("no active session".into()))?;

        let message = match session.open(packet) {
            Err(err) => {
                self.end_session();
                return Err(err);
            }
            Ok(message) => message,
        };
        trace!(
            "read ark-to-host message ({} bytes encrypted)",
            packet.len()
        );
        Ok(message)
    }

    /// Creates a session from the contexts negotiated by a completed handshake,
    /// retains its receive context, and returns a sender bound to that session.
    /// The client owns the session; the returned handle holds weak references
    /// and cannot keep either the session or the stream alive on its own.
    ///
    /// Binding takes the writer lock to order the replacement with in-flight
    /// writes and invalidate previous senders. A write already holding the lock
    /// may finish first; after binding, old senders cannot write into the new
    /// session. This method performs no handshake or stream I/O itself.
    fn new_session(&mut self, sender: xhpke::Sender, receiver: xhpke::Receiver) -> Sender<W> {
        let session = Session::new(sender, receiver);
        let sender = self.outbound.bind(&session);
        self.session = Some(session);
        sender
    }

    /// Removes the current session. Dropping [`Session`] marks its shared
    /// sending state ended and releases its receive context. Existing senders
    /// are then refused; another completed handshake must create a new session
    /// and new sender. Calling this without a session has no effect.
    ///
    /// Takes no encryption or writer lock and does not wait for active sends.
    /// A write already admitted may finish, while queued sends are refused when
    /// they next check the session. The stream stays open and no reset is sent;
    /// the caller handles any notification required by the operation ending it.
    fn end_session(&mut self) {
        self.session = None;
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
    ) -> Result<(Sender<W>, V::Info), Error> {
        self.handshake(verifier, host_xdsa_sk, host_xhpke_sk, Some(timestamp))
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
        self.outbound.send_packet(packet)
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
        self.outbound.send_frame_blob(frame)
    }
}

impl<R: Read, W: Write> Drop for Client<R, W> {
    /// Permanently closes the stream and waits for adapter shutdown. Idle senders
    /// hold only weak references, so they cannot keep the outbound side alive.
    fn drop(&mut self) {
        self.outbound.close();
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::testing;
    use crate::transport::mock::{payload, self_attestation};
    use crate::transport::server::Server;
    use std::io;
    use std::thread;

    /// A pair of contexts standing in for an established session.
    fn contexts() -> (xhpke::Sender, xhpke::Receiver) {
        let secret = xhpke::SecretKey::generate();
        let (sender, encap) = secret.public_key().new_sender(b"test").unwrap();
        let receiver = secret.new_receiver(&encap, b"test").unwrap();
        (sender, receiver)
    }

    // Tests that senders send from other threads while the client blocks in
    // a read, the server receiving every message in the order sealed, or it
    // would drop the session instead of echoing them.
    #[test]
    fn test_senders() {
        testing::init_tracing();

        // Echo every request over pipes, then hang up
        let (ark_reader, host_writer) = io::pipe().unwrap();
        let (host_reader, ark_writer) = io::pipe().unwrap();

        let signer = xdsa::SecretKey::generate();
        let identity = signer.public_key();
        let attestation = self_attestation(&signer);
        let ark = thread::spawn(move || {
            let mut server = Server::new(
                Stream::new(ark_reader, ark_writer, || {}),
                signer,
                attestation,
            );
            let mut sender = None;
            for _ in 0..100 {
                let req = testing::served(&mut server, &mut sender).unwrap();
                sender.as_ref().unwrap().send(&req).unwrap();
            }
        });
        let mut client = Client::new(Stream::new(host_reader, host_writer, || {}));
        let (sender, _) = client.connect(&identity).unwrap();

        // Send from a few threads at once while reading the echoes on this one
        let senders: Vec<_> = (0..4)
            .map(|thread| {
                let sender = sender.clone();
                thread::spawn(move || {
                    for i in 0..25 {
                        sender.send(&payload(thread * 100 + i)).unwrap();
                    }
                })
            })
            .collect();
        let mut echoes: Vec<Vec<u8>> = (0..100).map(|_| client.recv().unwrap()).collect();
        for sender in senders {
            sender.join().unwrap();
        }
        ark.join().unwrap();

        echoes.sort_unstable();
        let mut expected: Vec<Vec<u8>> = (0..4)
            .flat_map(|thread| (0..25).map(move |i| payload(thread * 100 + i)))
            .collect();
        expected.sort_unstable();
        assert_eq!(echoes, expected);
    }

    // Tests that dropping the client ends the session for its senders and
    // lets go of the transport writer, so nothing stays open on their account.
    #[test]
    fn test_sender_outlives_client() {
        testing::init_tracing();

        let (mut reader, writer) = io::pipe().unwrap();
        let (sender, receiver) = contexts();
        let mut client = Client::new(Stream::new(io::empty(), writer, || {}));
        let sender = client.new_session(sender, receiver);
        sender.send(&payload(1)).unwrap();
        drop(client);

        let result = sender.send(&payload(2));
        assert!(matches!(result, Err(Error::Terminated)), "{result:?}");
        // The read only returns once the writer is gone
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert!(!bytes.is_empty());
    }
}
