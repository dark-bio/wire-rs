// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

use crate::transport::framing::FrameReader;
use crate::transport::handshake;
use crate::transport::outbound::{Outbound, Side};
use crate::transport::sealing;
use crate::transport::sender::Sender;
use crate::transport::server::Attestation;
use crate::transport::{
    CRYPTO_DOMAIN_WIRE, CRYPTO_DOMAIN_WIRE_ARK_TO_HOST, CRYPTO_DOMAIN_WIRE_HOST_TO_ARK, Closer,
    Error, Stream,
};
use darkbio_crypto::{cbor, cose, xdsa, xhpke};
use darkbio_trust as trust;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
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
    reader: FrameReader<R>,            // COBS framed transport for ingress data
    receiver: Option<xhpke::Receiver>, // Receive context used exclusively by this client
    sealer: Option<Arc<Mutex<xhpke::Sender>>>, // Send context shared with active sends
    outbound: Arc<Outbound<W>>,        // Outgoing transport, shared with the senders
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
            receiver: None,
            sealer: None,
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
            // stale junk too by now. So are oversized or undecodable frames,
            // the leftovers of a transfer that was cut short. The framer reports
            // an oversized frame once and drains its remainder on the next call.
            let packet: &[u8] = match self.reader.next_packet() {
                Ok(Some(packet)) => packet,
                Ok(None) | Err(Error::FrameDecodingFailed(_) | Error::FrameTooLarge(_)) => &[],
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

    /// Reads the next ark-to-host message, decrypting it. An oversized or
    /// undecodable frame, or a packet that cannot be decrypted, drops the session:
    /// the server's HPKE sequence can no longer be followed. So does an empty
    /// frame, the server signaling it dropped the session on its end. Call
    /// [`Client::connect`] to establish a new session after such a failure.
    ///
    /// Message acceptance is ordered with session ending after decryption and
    /// never waits for the writer. Ending through a receive error does wait for
    /// outgoing writes before returning. A concurrent send failure can discard
    /// a decrypted message that has not yet been accepted; an accepted message
    /// may reach the caller after the other thread ends the session.
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
        let receiver = self
            .receiver
            .as_mut()
            .ok_or_else(|| Error::EncryptionFailed("no active session".into()))?;

        let sealer = self
            .sealer
            .as_ref()
            .expect("receiver has a sending context");
        let opened = sealing::open(receiver, packet);
        let message = match self.outbound.finish_receive(sealer, opened) {
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

    /// Retains freshly negotiated crypto contexts and returns a sender bound
    /// to the sending context's allocation. The client uses the receive context
    /// directly and shares the sending context with active sends. Idle senders
    /// hold weak references and keep neither the contexts nor the stream alive.
    ///
    /// Binding takes the writer lock, then the binding lock. Once replaced,
    /// old sends cannot write and old received messages cannot be accepted.
    /// A write already owning the writer may finish before replacement. This
    /// method performs no handshake, crypto or stream I/O itself.
    fn new_session(&mut self, sender: xhpke::Sender, receiver: xhpke::Receiver) -> Sender<W> {
        let sealer = Arc::new(Mutex::new(sender));
        let sender = self.outbound.bind(&sealer);

        self.receiver = Some(receiver);
        self.sealer = Some(sealer);

        sender
    }

    /// Ends the current binding before releasing the client's crypto contexts.
    /// Waits for the writer, so no write or flush for the session remains in
    /// progress or can start after this returns. A send that acquires the writer
    /// first may finish; one still sealing after removal cannot write its packet.
    /// No encryption lock is taken and extra crypto work is not waited for.
    ///
    /// The stream stays open and no notification is sent. The caller decides
    /// whether to send a reset or empty frame. A stuck write can delay ending;
    /// an independently held Closer can cancel it without taking the writer lock.
    fn end_session(&mut self) {
        if let Some(sealer) = self.sealer.as_ref() {
            self.outbound.end(sealer);
        }
        self.receiver = None;
        self.sealer = None;
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
    use crate::testing;
    use crate::transport::framing::FrameWriter;
    use crate::transport::mock::{payload, self_attestation};
    use crate::transport::server::Server;
    use std::io;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    /// A pair of contexts standing in for an established session.
    fn contexts() -> (xhpke::Sender, xhpke::Receiver) {
        let secret = xhpke::SecretKey::generate();
        let (sender, encap) = secret.public_key().new_sender(b"test").unwrap();
        let receiver = secret.new_receiver(&encap, b"test").unwrap();
        (sender, receiver)
    }

    /// Writer accepting bytes immediately but holding its first flush until
    /// the test releases it. This distinguishes finished writes from a fully
    /// completed send, which must also wait for its flush.
    struct BlockedFlush {
        entered: Option<mpsc::Sender<()>>,
        release: mpsc::Receiver<()>,
    }

    impl Write for BlockedFlush {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            if let Some(entered) = self.entered.take() {
                entered.send(()).unwrap();
                self.release.recv().unwrap();
            }
            Ok(())
        }
    }

    // Tests that ending waits through an active flush. After it returns the
    // old sender is refused, and fresh contexts can use the still-open stream.
    #[test]
    fn test_end_waits_for_flush() {
        testing::init_tracing();

        let (entered_tx, entered) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let mut client = Client::new(Stream::new(
            io::empty(),
            BlockedFlush {
                entered: Some(entered_tx),
                release: release_rx,
            },
            || {},
        ));
        let (crypto, receiver) = contexts();
        let sender = client.new_session(crypto, receiver);
        let sending = {
            let sender = sender.clone();
            thread::spawn(move || sender.send(&payload(1)))
        };
        entered.recv_timeout(Duration::from_secs(5)).unwrap();

        let (started_tx, started) = mpsc::channel();
        let (ended_tx, ended) = mpsc::channel();
        let ending = thread::spawn(move || {
            started_tx.send(()).unwrap();
            client.end_session();
            ended_tx.send(()).unwrap();
            client
        });
        started.recv_timeout(Duration::from_secs(5)).unwrap();
        let early = ended.recv_timeout(Duration::from_millis(50));
        release.send(()).unwrap();
        sending.join().unwrap().unwrap();
        let mut client = ending.join().unwrap();
        assert!(matches!(early, Err(mpsc::RecvTimeoutError::Timeout)));
        ended.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(matches!(
            sender.send(&payload(2)),
            Err(Error::EncryptionFailed(_))
        ));

        let (crypto, receiver) = contexts();
        let fresh = client.new_session(crypto, receiver);
        fresh.send(&payload(3)).unwrap();
        assert!(matches!(
            sender.send(&payload(4)),
            Err(Error::EncryptionFailed(_))
        ));
    }

    // Tests that a real receive reads, decrypts and returns a message while an
    // outgoing flush is blocked. Waiting for the writer on the success path
    // would time out before the test releases that flush.
    #[test]
    fn test_recv_during_blocked_flush() {
        testing::init_tracing();

        let (mut peer, receiver) = contexts();
        let packet = sealing::seal(&mut peer, &payload(1)).unwrap();
        let mut bytes = Vec::new();
        FrameWriter::new(&mut bytes, Closer::new(|| {}))
            .send_packet(&packet)
            .unwrap();
        let (entered_tx, entered) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let mut client = Client::new(Stream::new(
            io::Cursor::new(bytes),
            BlockedFlush {
                entered: Some(entered_tx),
                release: release_rx,
            },
            || {},
        ));
        let sender = client.new_session(contexts().0, receiver);
        let sending = thread::spawn(move || sender.send(&payload(2)));
        entered.recv_timeout(Duration::from_secs(5)).unwrap();

        let (received_tx, received) = mpsc::channel();
        let receiving = thread::spawn(move || {
            received_tx.send(client.recv()).unwrap();
            client
        });
        let result = received.recv_timeout(Duration::from_secs(5));
        // Release the writer even on a timeout, so a failing test can unwind.
        release.send(()).unwrap();
        sending.join().unwrap().unwrap();
        let _client = receiving.join().unwrap();
        assert_eq!(result.unwrap().unwrap(), payload(1));
    }

    // Tests that releasing an old session's contexts cannot invalidate its
    // replacement, which can still receive and send. Dropping the client ends
    // the replacement even while active operations retain its sending context
    // and outbound transport, modeled here by retaining those references.
    #[test]
    fn test_owner_drop() {
        testing::init_tracing();

        let (mut peer, receiver) = contexts();
        let packet = sealing::seal(&mut peer, &payload(2)).unwrap();
        let mut bytes = Vec::new();
        FrameWriter::new(&mut bytes, Closer::new(|| {}))
            .send_packet(&packet)
            .unwrap();
        let mut client = Client::new(Stream::new(&bytes[..], Vec::new(), || {}));
        let (crypto, old_receiver) = contexts();
        let stale = client.new_session(crypto, old_receiver);
        let old_sealer = client.sealer.as_ref().unwrap().clone();

        let fresh = client.new_session(contexts().0, receiver);
        client.outbound.end(&old_sealer);
        drop(old_sealer);
        assert!(matches!(
            stale.send(&payload(1)),
            Err(Error::EncryptionFailed(_))
        ));
        assert_eq!(client.recv().unwrap(), payload(2));
        fresh.send(&payload(3)).unwrap();

        let outbound = client.outbound.clone();
        let sealer = client.sealer.as_ref().unwrap().clone();
        drop(client);
        assert!(outbound.finish_receive(&sealer, Ok(Vec::new())).is_err());
        assert!(matches!(
            fresh.send(&payload(4)),
            Err(Error::EncryptionFailed(_))
        ));
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
