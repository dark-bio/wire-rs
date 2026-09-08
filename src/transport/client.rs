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
    /// The verifier receives the raw device attestation from the server's hello
    /// and its accepted info is returned alongside the sender of the established
    /// session. The sender stays bound to that session through later calls to
    /// `connect`; it cannot send into a replacement session. Reset and hello
    /// output run on a scoped native thread while this caller drains old input,
    /// preventing reconnect deadlocks on bounded duplex streams. Output failures
    /// cancel the companion read; read failures cancel further helper I/O. The
    /// helper is always joined before returning, leaving the stream reusable.
    /// Each outgoing frame has the stream's configured deadline; waiting for a
    /// peer's reply has no overall timeout. If connecting fails,
    /// the client has no session and previously issued senders remain invalid.
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

    /// Exchanges the reset and hello while draining output from earlier
    /// sessions. Retirement and writes run on a helper so waiting for the old
    /// writer cannot prevent reads. Only a reply addressed to the fresh key is
    /// retained; authentication remains the handshake caller's responsibility.
    /// Both directions finish before returning, including when either fails.
    fn exchange_hello(
        &mut self,
        hello: &[u8],
        recipient: xhpke::Fingerprint,
    ) -> Result<Vec<u8>, Error>
    where
        W: Send,
    {
        // Release the client's old contexts. Active sends may still retain
        // the sending allocation; the helper retires its binding in order with
        // their writes. Draining must already run during that writer wait:
        // otherwise both peers can block writing into each other's full pipe.
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
    /// whether to send a reset or empty frame. An active write may delay ending
    /// until its frame deadline. An independently held Closer can cancel it
    /// earlier without taking the writer lock.
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
    ) -> Result<(Sender<W>, V::Info), Error>
    where
        W: Send,
    {
        self.handshake(verifier, host_xdsa_sk, host_xhpke_sk, Some(timestamp))
    }

    /// Test and benchmark helper exposing the framer's `next_packet` with the
    /// decoded packet as a slice. Not part of the API.
    #[doc(hidden)]
    #[inline]
    #[cfg(any(test, feature = "bench", feature = "fuzz"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn next_packet_blob(&mut self) -> Result<Option<&[u8]>, Error> {
        self.reader.next_packet(None)
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

    // Tests that senders send from other threads while the client blocks in
    // a read, the server receiving every message in the order sealed, or it
    // would drop the session instead of echoing them.
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
    // lets go of the transport writer, so nothing stays open on their account.
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
