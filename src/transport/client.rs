// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

use crate::transport::framing::FrameReader;
use crate::transport::handshake;
use crate::transport::outbound::{Outbound, Side};
use crate::transport::sealing;
use crate::transport::sender::Sender;
use crate::transport::server::Attestation;
use crate::transport::stream::Cancelled;
use crate::transport::{
    CRYPTO_DOMAIN_WIRE, CRYPTO_DOMAIN_WIRE_ARK_TO_HOST, CRYPTO_DOMAIN_WIRE_HOST_TO_ARK, Closer,
    Error, Read, Stream, Write,
};
use darkbio_crypto::{cbor, cose, xdsa, xhpke};
use darkbio_trust as trust;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{trace, warn};

/// Cancels a reconnect's reader if its output helper fails or unwinds. On
/// success the helper disarms this guard, allowing an ordinary idle read to
/// continue. A helper panic still propagates when the scoped thread is joined.
struct CancelRead<'a>(Option<&'a AtomicBool>);

impl Drop for CancelRead<'_> {
    fn drop(&mut self) {
        if let Some(canceled) = self.0 {
            canceled.store(true, Ordering::Relaxed);
        }
    }
}

/// Trust policy for the device attestation presented during a handshake.
/// The caller decides which roots to trust and whether to allow self-signed
/// attestations or recovery overrides. Transport enforces that decision.
pub trait Verifier {
    /// Session info extracted from an accepted attestation.
    type Info;

    /// Verifies the device attestation, returning the server's identity key along
    /// with any info extracted from the attestation. Transport checks the
    /// handshake signature against that key. Rejecting the attestation aborts
    /// the handshake.
    fn verify(&self, attestation: &Attestation) -> Result<(xdsa::PublicKey, Self::Info), String>;
}

/// Authenticates the handshake against this pinned identity key. The presented
/// attestation is returned unchanged, without checking who issued it.
impl Verifier for xdsa::PublicKey {
    type Info = Attestation;

    fn verify(&self, attestation: &Attestation) -> Result<(xdsa::PublicKey, Self::Info), String> {
        Ok((self.clone(), attestation.clone()))
    }
}

/// Roots trusted to attest Arks. Hardware and emulator roots are checked
/// separately, and attestations must be valid at the current time. Self-signed
/// attestations from devices that have not been onboarded are rejected.
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
/// Client side of the wire, exchanging encrypted messages over a byte stream.
/// [`Client::connect`] sends a reset and runs the handshake. It returns a
/// [`Sender`] for outbound messages. [`Client::recv`] decrypts inbound messages.
///
/// An empty frame from the server means it has no session with the client anymore.
/// The client ends its session and returns [`Error::SessionReset`]. The caller
/// can then reconnect.
///
/// Transport checks the shape of the device attestation. A [`Verifier`] decides
/// whether to trust the server presenting it.
pub struct Client<R: Read, W: Write> {
    reader: FrameReader<R>,            // COBS framed transport for ingress data
    receiver: Option<xhpke::Receiver>, // Receive context used exclusively by this client
    sealer: Option<Arc<Mutex<xhpke::Sender>>>, // Send context shared with active sends
    outbound: Arc<Outbound<W>>,        // Outgoing transport, shared with the senders
}

impl<R: Read, W: Write> Client<R, W> {
    /// Creates a client owning the byte stream and its shutdown operation, without
    /// an encrypted session. Call [`Client::connect`] to establish one.
    /// Output uses the stream's configured write timeout; its adapter must
    /// enforce deadlines and the shutdown cancellation contract.
    pub fn new(stream: Stream<R, W>) -> Self {
        let (reader, writer, close, timeout) = stream.into_parts();

        let outbound = Arc::new(Outbound::new(writer, Side::Client, close.clone(), timeout));

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
    /// The verifier receives the server's device attestation. Its accepted info
    /// is returned alongside the new sender. That sender belongs to this session
    /// and cannot send into a replacement established by a later handshake.
    ///
    /// A scoped native thread sends the reset and hello while this caller drains
    /// old input. This prevents reconnect deadlocks on bounded duplex streams.
    /// Output failure cancels the companion read. Read failure cancels further
    /// helper I/O. The helper is always joined before returning.
    ///
    /// Each outgoing frame gets the stream's configured write budget. Waiting
    /// for a peer's reply has no overall timeout. If connecting fails, the client
    /// has no session and all previously issued senders remain invalid.
    pub fn connect<V: Verifier>(&mut self, verifier: &V) -> Result<(Sender<W>, V::Info), Error>
    where
        W: Send,
    {
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
    ) -> Result<(Sender<W>, V::Info), Error>
    where
        W: Send,
    {
        let host_xdsa_pk = host_xdsa_sk.public_key();
        let host_xhpke_pk = host_xhpke_sk.public_key();

        // Message 1: Send HostHello (plain CBOR, COBS-framed)
        let hello = cbor::encode(&handshake::HostHello {
            host_signer: host_xdsa_pk.clone(),
            host_crypto: host_xhpke_pk.clone(),
        })
        .map_err(|err| {
            self.end_session();
            Error::HandshakeFailed(format!("failed to encode client hello: {}", err))
        })?;

        let packet = self.exchange_hello(&hello, host_xhpke_pk.fingerprint())?;
        let auth = handshake::ArkHelloAuth {
            host_signer: host_xdsa_pk.clone(),
            host_crypto: host_xhpke_pk.clone(),
        };

        // Step 2a: Decrypt the outer COSE_Encrypt0 layer
        let sign1 =
            cose::decrypt(&packet, &auth, &host_xhpke_sk, CRYPTO_DOMAIN_WIRE).map_err(|err| {
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

    /// Sends the reset and hello while draining output from earlier sessions.
    /// The helper retires the old binding before writing. Waiting for its writer
    /// lock must not prevent this caller from reading. Only a reply addressed to
    /// the fresh key is returned; the handshake authenticates it afterwards.
    /// Both directions finish before returning, even if either fails.
    ///
    /// TODO(karalabe): Ugh, this torn out with threading
    fn exchange_hello(
        &mut self,
        hello: &[u8],
        recipient: xhpke::Fingerprint,
    ) -> Result<Vec<u8>, Error>
    where
        W: Send,
    {
        // Release the client's old contexts. Active sends may still hold the
        // sending context. The helper waits for their writer before retiring
        // its binding. Read while it waits, or both peers can block writing
        // into each other's full pipe.
        self.receiver = None;
        self.sealer = None;

        // Each attempt owns a fresh stop flag. It publishes no other state;
        // joining the helper synchronizes its result before this attempt ends.
        let canceled = AtomicBool::new(false);
        let outbound = &self.outbound;
        let reader = &mut self.reader;

        thread::scope(|scope| {
            let cancellation = &canceled;
            let writer = scope.spawn(|| {
                let mut cancel_read = CancelRead(Some(cancellation));
                let result = outbound.begin_handshake(hello, cancellation);
                if result.is_ok() {
                    cancel_read.0 = None;
                }
                result
            });

            // Message 2: Read ArkHello while the helper sends reset/HostHello.
            // Discard buffered output from earlier sessions or attempts until
            // a reply names our fresh key. There is no frame-count limit: the
            // amount of legitimate stale traffic depends on adapter buffering.
            let received = loop {
                let packet = match reader.next_packet(Some(cancellation)) {
                    Ok(Some(packet)) => packet,
                    Ok(None) | Err(Error::FrameDecodingFailed(_) | Error::FrameTooLarge(_)) => &[],
                    Err(err) => break Err(err),
                };
                if cose::recipient(packet).is_ok_and(|fp| fp == recipient) {
                    break Ok(packet.to_vec());
                }
                warn!("skipping stale frame during handshake");
            };
            if received.is_err() {
                cancellation.store(true, Ordering::Relaxed);
            }
            // Join even on read failure. No helper or delayed cancellation can
            // escape this attempt and interfere with the next use of the stream.
            let sent = writer
                .join()
                .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
            match (received, sent) {
                (Err(Error::RecvFailed(err)), Err(output))
                    if err.get_ref().is_some_and(|cause| cause.is::<Cancelled>()) =>
                {
                    Err(output)
                }
                (Err(err), _) => Err(err),
                (Ok(_), Err(err)) => Err(err),
                (Ok(packet), Ok(())) => Ok(packet),
            }
        })
    }

    /// Reads and decrypts the next ark-to-host message. Invalid or oversized
    /// frames end the session because its encryption sequence may be lost.
    /// Decryption failures also end the session.
    /// An empty frame means the server dropped the session and ends it here too.
    /// Adapter read failures and EOF also end the session. Idle read timeouts are
    /// retried internally. Call [`Self::connect`] to establish a new session after failure.
    ///
    /// After decryption, message acceptance is ordered with session ending
    /// without waiting for the writer. A concurrent send failure can cause a
    /// decrypted message to be discarded before acceptance. An accepted message
    /// may reach this caller after another thread ends the session. Returning
    /// a receive error does wait for outgoing writes to finish.
    pub fn recv(&mut self) -> Result<Vec<u8>, Error> {
        // Retrieve the next COBS encoded packet. A skipped frame may have
        // carried a sealed message, so the session cannot continue past it.
        // An empty frame is the server telling us it has no session with us.
        let packet = match self.reader.next_packet(None) {
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

    /// Stores the negotiated contexts and returns a sender for the new session.
    /// The sending context's allocation identifies the session. The client owns
    /// both contexts and shares the sending context with active sends. Idle
    /// senders hold weak references and keep neither context nor stream alive.
    ///
    /// Takes the writer lock, then the binding lock. An old write that already
    /// holds the writer lock may finish first. Once the binding is replaced,
    /// old sends cannot write and old received messages cannot be accepted.
    /// This method performs no handshake, crypto or stream I/O.
    fn new_session(&mut self, sender: xhpke::Sender, receiver: xhpke::Receiver) -> Sender<W> {
        let sealer = Arc::new(Mutex::new(sender));
        let sender = self.outbound.bind(&sealer);

        self.receiver = Some(receiver);
        self.sealer = Some(sealer);

        sender
    }

    /// Ends the current binding before releasing the client's crypto contexts.
    /// Waits for the writer. After this returns, no write or flush for that
    /// session is running or can start. A send that gets the writer first may
    /// finish. A send still sealing after removal cannot write its packet.
    /// This takes no encryption lock and does not wait for crypto work.
    ///
    /// This does not close the stream or send a notification. An active write
    /// may delay ending until its frame deadline. Another thread can use the
    /// Closer to cancel I/O without taking the writer lock.
    fn end_session(&mut self) {
        if let Some(sealer) = self.sealer.as_ref() {
            self.outbound.end(sealer);
        }
        self.receiver = None;
        self.sealer = None;
    }

    /// Runs a test handshake with fixed keys and signing time for vector replay.
    /// Not part of the normal transport API.
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
    ) -> Result<(Sender<W>, V::Info), Error>
    where
        W: Send,
    {
        self.handshake(verifier, host_xdsa_sk, host_xhpke_sk, Some(timestamp))
    }

    /// Reads a framed packet without decryption for tests and benchmarks.
    #[doc(hidden)]
    #[inline]
    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn next_packet_blob(&mut self) -> Result<Option<&[u8]>, Error> {
        self.reader.next_packet(None)
    }

    /// Writes a packet without encryption for tests and benchmarks.
    #[doc(hidden)]
    #[inline]
    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn send_packet_blob(&mut self, packet: &[u8]) -> Result<(), Error> {
        self.outbound.send_packet(packet)
    }

    /// Reads an encoded frame without its delimiter for tests and benchmarks.
    #[doc(hidden)]
    #[inline]
    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn next_frame_blob(&mut self) -> Result<&[u8], Error> {
        self.reader.next_frame_blob()
    }

    /// Writes an already encoded frame with a delimiter for tests and benchmarks.
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
    use crate::transport::DEFAULT_WRITE_TIMEOUT;
    use crate::transport::framing::FrameWriter;
    use crate::transport::mock::{payload, self_attestation};
    use crate::transport::server::Server;
    use crate::transport::testing::Memory;
    use std::io::{self, Read as _};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

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
        deadline: Option<Instant>,
    }

    impl Write for BlockedFlush {
        fn set_write_deadline(&mut self, deadline: Instant) -> io::Result<()> {
            self.deadline = Some(deadline);
            Ok(())
        }
    }

    impl io::Write for BlockedFlush {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            testing::remaining(self.deadline.expect("write deadline installed"))?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            let deadline = self.deadline.expect("write deadline installed");
            testing::remaining(deadline)?;
            if let Some(entered) = self.entered.take() {
                entered.send(()).unwrap();
                self.release
                    .recv_timeout(testing::remaining(deadline)?)
                    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
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
            Memory::new(io::empty()),
            BlockedFlush {
                entered: Some(entered_tx),
                release: release_rx,
                deadline: None,
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
        FrameWriter::new(Memory::new(&mut bytes), Closer::new(|| {}))
            .send_packet(&packet, Instant::now() + DEFAULT_WRITE_TIMEOUT, None)
            .unwrap();
        let (entered_tx, entered) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let mut client = Client::new(Stream::new(
            Memory::new(io::Cursor::new(bytes)),
            BlockedFlush {
                entered: Some(entered_tx),
                release: release_rx,
                deadline: None,
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
        FrameWriter::new(Memory::new(&mut bytes), Closer::new(|| {}))
            .send_packet(&packet, Instant::now() + DEFAULT_WRITE_TIMEOUT, None)
            .unwrap();
        let mut client = Client::new(Stream::new(
            Memory::new(&bytes[..]),
            Memory::new(Vec::new()),
            || {},
        ));
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

    // Tests sending from other threads while the client blocks in a read.
    // The server must receive every message in encryption order to decrypt
    // and echo it successfully.
    #[test]
    fn test_senders() {
        testing::init_tracing();

        // Echo every request over pipes, then hang up
        let (ark_reader, host_writer) = testing::pipe();
        let (host_reader, ark_writer) = testing::pipe();

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
    // releases the transport writer even while sender handles remain.
    #[test]
    fn test_sender_outlives_client() {
        testing::init_tracing();

        let (mut reader, writer) = testing::pipe();
        let (sender, receiver) = contexts();
        let mut client = Client::new(Stream::new(Memory::new(io::empty()), writer, || {}));
        let sender = client.new_session(sender, receiver);
        sender.send(&payload(1)).unwrap();
        drop(client);

        let result = sender.send(&payload(2));
        assert!(matches!(result, Err(Error::Terminated)), "{result:?}");
        // The read only returns once the writer is gone
        let mut bytes = Vec::new();
        reader
            .set_read_deadline(Instant::now() + DEFAULT_WRITE_TIMEOUT)
            .unwrap();
        reader.read_to_end(&mut bytes).unwrap();
        assert!(!bytes.is_empty());
    }
}
