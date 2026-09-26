// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Client side of the transport, with the trust policies that check the
//! server's device attestation.

use crate::LogId;
use crate::transport::DEFAULT_HANDSHAKE_TIMEOUT;
use crate::transport::framing::FrameReader;
use crate::transport::handshake;
use crate::transport::io::check_deadline;
use crate::transport::outbound::{Outbound, Side};
use crate::transport::sealing;
use crate::transport::sender::Sender;
use crate::transport::server::Attestation;
use crate::transport::{
    CRYPTO_DOMAIN_WIRE, CRYPTO_DOMAIN_WIRE_ARK_TO_HOST, CRYPTO_DOMAIN_WIRE_HOST_TO_ARK, Closer,
    Error, Read, Stream, Write,
};
use darkbio_crypto::{cbor, cose, xdsa, xhpke};
use darkbio_trust as trust;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, trace, warn};

/// Trust policy for the device attestation that a server presents during a
/// handshake.
///
/// The caller decides which roots to trust and whether to allow self-signed
/// attestations or recovery overrides. Transport enforces that decision.
pub trait Verifier {
    /// Session info extracted from an accepted attestation.
    type Info;

    /// Verifies the device attestation at `now`, the wall time of the stream's
    /// clock.
    ///
    /// Returns the server's identity key along with any info extracted from
    /// the attestation. Transport checks the handshake signature against that
    /// key. Rejecting the attestation aborts the handshake.
    fn verify(
        &self,
        attestation: &Attestation,
        now: SystemTime,
    ) -> Result<(xdsa::PublicKey, Self::Info), String>;
}

/// Authenticates the handshake against this pinned identity key.
///
/// The presented attestation is returned unchanged, without checking who
/// issued it.
impl Verifier for xdsa::PublicKey {
    type Info = Attestation;

    fn verify(
        &self,
        attestation: &Attestation,
        _: SystemTime,
    ) -> Result<(xdsa::PublicKey, Self::Info), String> {
        Ok((self.clone(), attestation.clone()))
    }
}

/// Roots trusted to attest Arks.
///
/// Hardware and emulator roots are checked separately, and attestations must
/// be valid at the stream clock's wall time. Self-signed attestations from
/// devices that have not been onboarded are rejected.
#[derive(Debug)]
pub struct Roots<'a> {
    /// Roots attesting hardware Arks.
    pub hardware: &'a [xdsa::PublicKey],
    /// Roots attesting emulated Arks.
    pub emulator: &'a [xdsa::PublicKey],
}

impl Verifier for Roots<'_> {
    type Info = trust::device::Device;

    fn verify(
        &self,
        attestation: &Attestation,
        now: SystemTime,
    ) -> Result<(xdsa::PublicKey, Self::Info), String> {
        // Convert the supplied wall time to the trust API's Unix seconds
        let now = now
            .duration_since(UNIX_EPOCH)
            .map_err(|err| err.to_string())?
            .as_secs();

        // Verify the attestation and return its identity with the claims
        let device = trust::device::verify(
            attestation.as_bytes(),
            self.hardware,
            self.emulator,
            Some(now),
        )
        .map_err(|err| err.to_string())?;
        Ok((device.identity.clone(), device))
    }
}

/// Client side of the wire, exchanging encrypted messages over a byte stream.
///
/// [`Client::connect`] sends a reset and runs the handshake, returning a
/// [`Sender`] for outbound messages. [`Client::recv`] decrypts inbound
/// messages.
///
/// An empty frame from the server means it holds no session with this client.
/// [`Client::recv`] then ends the client's session and returns
/// [`Error::SessionReset`], after which the caller can reconnect.
///
/// Transport checks the shape of the device attestation. A [`Verifier`] decides
/// whether to trust the server presenting it.
pub struct Client<R: Read, W: Write> {
    /// Budget for each new handshake attempt.
    handshake_timeout: Duration,

    /// COBS frame reader for the data the server sends.
    reader: FrameReader<R>,
    /// Receive context of the current session, used only by this client.
    receiver: Option<xhpke::Receiver>,
    /// Send context of the current session, shared with active sends.
    sealer: Option<Arc<Mutex<xhpke::Sender>>>,
    /// Outgoing transport, which the senders reach through weak references.
    outbound: Arc<Outbound<W>>,
    /// Label of the latest session in log lines, zero before the first one.
    log_id: LogId,
}

impl<R: Read, W: Write> Client<R, W> {
    /// Creates a client that owns the byte stream and its shutdown operation,
    /// without an encrypted session.
    ///
    /// Call [`Client::connect`] to establish one. Output uses the stream's
    /// configured write timeout. The stream's [`Read`] and [`Write`] adapters
    /// must enforce deadlines and let shutdown cancel blocked I/O.
    pub fn new(stream: Stream<R, W>) -> Self {
        let (reader, writer, close, timeout) = stream.into_parts();

        let outbound = Arc::new(Outbound::new(writer, Side::Client, close.clone(), timeout));

        Self {
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            reader: FrameReader::new(reader, close),
            receiver: None,
            sealer: None,
            outbound,
            log_id: LogId::default(),
        }
    }

    /// Sets the budget for each later handshake, counted from the call to
    /// [`Client::connect`].
    ///
    /// Defaults to [`DEFAULT_HANDSHAKE_TIMEOUT`]. Output and peer replies share
    /// one deadline; progress and stale frames do not refresh it. Each outgoing
    /// frame is also limited by the stream's write timeout. Waiting for locks
    /// and verifier callbacks can extend the call beyond the deadline.
    ///
    /// Zero expires attempts immediately. A duration too large to add to an
    /// [`Instant`] panics when the next handshake's deadline is constructed.
    pub fn set_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Returns a handle that permanently closes the stream from another thread.
    pub fn closer(&self) -> Closer {
        self.outbound.closer()
    }

    /// Permanently closes the stream and waits for adapter shutdown.
    ///
    /// Senders observe closure through write failure, and buffered messages
    /// remain readable. See [`Closer::close`].
    pub fn close(&self) {
        self.outbound.close();
    }

    /// Establishes an encrypted session over the stream, ending any previous
    /// session first.
    ///
    /// Sends a reset and drives the handshake:
    ///
    /// ```text
    /// 1. Client -> Server: HostHello { host_signer, host_crypto }           (plain CBOR)
    /// 2. Server -> Client: ArkHello  { ark_attest, ark_crypto, a2h_encap }  (cose::seal)
    /// 3. Client -> Server: HostAck   { h2a_encap }                          (cose::seal)
    /// ```
    ///
    /// The verifier receives the server's device attestation. Its accepted info
    /// is returned alongside the new sender. That sender belongs to this session
    /// and cannot send into a replacement established by a later handshake.
    ///
    /// Sends reset and hello before draining old input. The adapter must allow
    /// that output to finish without concurrent client reads for this attempt
    /// to progress. Backpressure can instead fail an outgoing frame on timeout.
    ///
    /// The handshake uses one configured deadline, shared by output and peer
    /// waits. Waiting for writes already in flight may extend the call. If
    /// connecting fails, the client has no session and every sender it issued
    /// before is invalid.
    ///
    /// # Panics
    ///
    /// Panics if the handshake or write timeout is too large to add to an
    /// [`Instant`], or if signing reads a wall time before the Unix epoch from
    /// the stream's clock.
    pub fn connect<V: Verifier>(&mut self, verifier: &V) -> Result<(Sender<W>, V::Info), Error> {
        // Compute the deadline by which the handshake must finish
        let deadline = self.outbound.clock.now() + self.handshake_timeout;

        // Generate ephemeral client keys for this session
        let host_xdsa_sk = xdsa::SecretKey::generate();
        let host_xhpke_sk = xhpke::SecretKey::generate();

        self.handshake(verifier, host_xdsa_sk, host_xhpke_sk, None, deadline)
    }

    /// Ends any previous session, sends a reset and drives the handshake with the
    /// given ephemeral keys.
    ///
    /// Returns the new session's sender and verified info. The optional signing
    /// time makes the exchange deterministic for test vectors.
    fn handshake<V: Verifier>(
        &mut self,
        verifier: &V,
        host_xdsa_sk: xdsa::SecretKey,
        host_xhpke_sk: xhpke::SecretKey,
        timestamp: Option<i64>,
        deadline: Instant,
    ) -> Result<(Sender<W>, V::Info), Error> {
        // Derive the public halves of this attempt's keys
        let host_xdsa_pk = host_xdsa_sk.public_key();
        let host_xhpke_pk = host_xhpke_sk.public_key();
        debug!("starting wire handshake");

        // Message 1: Encode the HostHello as plain CBOR
        let hello = cbor::encode(&handshake::HostHello {
            host_signer: host_xdsa_pk.clone(),
            host_crypto: host_xhpke_pk.clone(),
        })
        .map_err(|err| {
            self.end_session();
            Error::HandshakeFailed(format!("failed to encode client hello: {}", err))
        })?;

        // Retire the old binding and send the reset and hello after admitted
        // sends. The client starts reading only once this output has finished.
        self.receiver = None;
        self.sealer = None;
        self.outbound.send_reset(deadline)?;
        self.outbound.send_packet(&hello, Some(deadline))?;

        // Message 2: Skip old replies, notifications and partial-frame leftovers
        // until ArkHello names this attempt's fresh key. All draining shares the
        // same deadline; authentication follows below.
        let recipient = host_xhpke_pk.fingerprint();
        let packet = loop {
            let packet = match self.reader.next_packet(Some(deadline)) {
                Ok(Some(packet)) => packet,
                Ok(None) | Err(Error::FrameDecodingFailed(_) | Error::FrameTooLarge(_)) => &[],
                Err(err) => return Err(err),
            };
            if cose::recipient(packet).is_ok_and(|fp| fp == recipient) {
                break packet;
            }
            debug!("skipping stale frame during handshake");
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
            .verify(&attestation, self.outbound.clock.system_time())
            .map_err(Error::HandshakeFailed)?;

        // Step 2d: Verify the COSE_Sign1 signature with the discovered identity
        let ark_hello: handshake::ArkHello = cose::verify_at(
            &sign1,
            &auth,
            &ark_identity,
            CRYPTO_DOMAIN_WIRE,
            None,
            0, // unused without a drift check, so the clock is not read
        )
        .map_err(|err| {
            Error::HandshakeFailed(format!("server hello signature invalid: {}", err))
        })?;

        // Set up the server-to-client receive context
        let enc_a2h: [u8; xhpke::ENCAP_KEY_SIZE] = ark_hello
            .a2h_encap
            .try_into()
            .map_err(|_| Error::HandshakeFailed("invalid a2h_encap size".into()))?;
        let receiver = host_xhpke_sk
            .new_receiver(&enc_a2h, CRYPTO_DOMAIN_WIRE_ARK_TO_HOST)
            .map_err(|err| {
                Error::HandshakeFailed(format!("client receiver setup failed: {}", err))
            })?;

        // Set up the client-to-server send context
        let ark_xhpke_pk = ark_hello.ark_crypto;
        let (sender, enc_h2a) = ark_xhpke_pk
            .new_sender(CRYPTO_DOMAIN_WIRE_HOST_TO_ARK)
            .map_err(|err| {
                Error::HandshakeFailed(format!("client sender setup failed: {}", err))
            })?;

        // Message 3: Seal the HostAck
        let ack = handshake::HostAck {
            h2a_encap: enc_h2a.to_vec(),
        };
        let auth = handshake::HostAckAuth {
            ark_signer: ark_identity,
            ark_crypto: ark_xhpke_pk.clone(),
        };
        let ack = cose::seal_at(
            &ack,
            &auth,
            &host_xdsa_sk,
            &ark_xhpke_pk,
            CRYPTO_DOMAIN_WIRE,
            timestamp.unwrap_or_else(|| handshake::timestamp(&self.outbound.clock)),
        )
        .map_err(|err| Error::HandshakeFailed(format!("failed to seal client ack: {}", err)))?;

        // Send the ack, failing an attempt that finished past its deadline
        self.outbound.send_packet(&ack, Some(deadline))?;
        check_deadline(&self.outbound.clock, deadline).map_err(Error::RecvFailed)?;

        // Session established, the ack ahead of anything sealed into it
        let sender = self.new_session(sender, receiver);
        info!(
            "wire session {} established with ark {}",
            self.log_id,
            hex(&auth.ark_signer.fingerprint())
        );
        Ok((sender, info))
    }

    /// Reads and decrypts the next ark-to-host message.
    ///
    /// Invalid or oversized frames end the session, since its encryption
    /// sequence may be lost. Decryption failures also end the session. An empty
    /// frame means the server dropped the session, which ends here too with
    /// [`Error::SessionReset`]. Adapter read failures and EOF also end the
    /// session, while idle read timeouts are retried internally. Call
    /// [`Self::connect`] to establish a new session after a failure. Without a
    /// session, returns an error without reading the stream.
    ///
    /// After decryption, message acceptance is ordered with session ending
    /// without waiting for the writer. A concurrent send failure can cause a
    /// decrypted message to be discarded before acceptance. An accepted message
    /// may reach this caller after another thread ends the session. Returning
    /// a receive error does wait for outgoing writes to finish.
    pub fn recv(&mut self) -> Result<Vec<u8>, Error> {
        // Refuse to read without a session
        let receiver = self
            .receiver
            .as_mut()
            .ok_or_else(|| Error::EncryptionFailed("no active session".into()))?;

        // Retrieve the next COBS encoded packet. A skipped frame may have
        // carried a sealed message, so the session cannot continue past it.
        // An empty frame signals that the server has no session with us.
        let packet = match self.reader.next_packet(None) {
            Err(err) => {
                if matches!(err, Error::FrameDecodingFailed(_) | Error::FrameTooLarge(_)) {
                    warn!("ending session {}: {}", self.log_id, err);
                }
                self.end_session();
                return Err(err);
            }
            Ok(None) => {
                info!("wire session {} reset by ark", self.log_id);
                self.end_session();
                return Err(Error::SessionReset);
            }
            Ok(Some(packet)) => packet,
        };

        // Finish after decrypting, ordering message acceptance with a send
        // failure without ever waiting for the writer on a successful receive
        let sealer = self
            .sealer
            .as_ref()
            .expect("receiver has a sending context");
        let opened = sealing::open(receiver, packet);
        let undecryptable = opened.is_err();
        let message = match self.outbound.finish_receive(sealer, opened) {
            Err(err) => {
                if undecryptable {
                    warn!("ending session {}: {}", self.log_id, err);
                } else {
                    debug!(
                        "discarding message read after session {} ended",
                        self.log_id
                    );
                }
                self.end_session();
                return Err(err);
            }
            Ok(message) => message,
        };
        trace!("received ark-to-host message ({} bytes)", packet.len());
        Ok(message)
    }

    /// Stores the negotiated contexts and returns a sender for the new session.
    ///
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
        self.log_id = sender.log_id();

        self.receiver = Some(receiver);
        self.sealer = Some(sealer);

        sender
    }

    /// Ends the current binding before releasing the client's crypto contexts.
    ///
    /// Waits for the writer while a session exists. After this returns, no
    /// write or flush for that session is running or can start. A send that
    /// gets the writer first may finish. A send still sealing after removal
    /// cannot write its packet. This takes no encryption lock and does not wait
    /// for crypto work.
    ///
    /// This does not close the stream or send a notification. An active write
    /// may delay ending until its frame deadline. Another thread can use a
    /// [`Closer`] to cancel I/O without taking the writer lock.
    fn end_session(&mut self) {
        if let Some(sealer) = self.sealer.as_ref() {
            self.outbound.end(sealer);
        }
        self.receiver = None;
        self.sealer = None;
    }

    /// Returns a waiter that blocks until a call waits for the writer, such as a
    /// handshake queued behind an admitted send.
    #[cfg(any(test, feature = "fuzz"))]
    pub(crate) fn watch_writer(&self) -> impl FnOnce() + use<R, W> {
        let outbound = self.outbound.clone();
        move || outbound.wait_writers(1)
    }

    /// Runs a handshake with fixed keys and signing time, for vector replay.
    ///
    /// It exists for test vectors and is not part of the normal transport API.
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
        self.handshake(
            verifier,
            host_xdsa_sk,
            host_xhpke_sk,
            Some(timestamp),
            self.outbound.clock.now() + self.handshake_timeout,
        )
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
        self.outbound.send_packet(packet, None)
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
    /// releasing the contexts.
    ///
    /// Shutdown must come before waiting for the writer, which a blocked write
    /// could otherwise hold until its deadline. Idle senders hold weak
    /// references and cannot extend the stream's lifetime.
    fn drop(&mut self) {
        self.outbound.close();
        self.end_session();
    }
}

impl<R: Read, W: Write> fmt::Debug for Client<R, W> {
    /// Shows the session label, whether a session is established and the
    /// handshake budget, never the adapters or the encryption contexts.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("session", &self.log_id)
            .field("connected", &self.sealer.is_some())
            .field("handshake_timeout", &self.handshake_timeout)
            .finish_non_exhaustive()
    }
}

/// Encodes a fingerprint as lowercase hexadecimal for the session log line.
fn hex(fingerprint: &xdsa::Fingerprint) -> String {
    fingerprint
        .to_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Tests of the client's session ending, receiving and sending.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::transport::DEFAULT_WRITE_TIMEOUT;
    use crate::transport::framing::FrameWriter;
    use crate::transport::mock::{payload, self_attestation};
    use crate::transport::server::Server;
    use crate::transport::testing::{Memory, test_clock};
    use crate::{memory, testing};
    use darkbio_clock::Clock;
    use std::io::{self, Read as _};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Instant;

    /// Creates a matching pair of contexts standing in for an established
    /// session.
    fn contexts() -> (xhpke::Sender, xhpke::Receiver) {
        let secret = xhpke::SecretKey::generate();
        let (sender, encap) = secret.public_key().new_sender(b"test").unwrap();
        let receiver = secret.new_receiver(&encap, b"test").unwrap();
        (sender, receiver)
    }

    /// Writer that accepts bytes at once but holds its first flush until the
    /// test releases it.
    ///
    /// This distinguishes finished writes from a fully completed send, which
    /// must also wait for its flush.
    struct BlockedFlush {
        /// Clock shared with the client and its release gate.
        clock: Clock,
        /// Signal sent when the first flush starts, taken by that flush.
        entered: Option<mpsc::Sender<()>>,
        /// Gate that holds the first flush until the test opens it.
        release: testing::Gate,
        /// Latest installed write deadline.
        deadline: Option<Instant>,
    }

    impl Write for BlockedFlush {
        fn clock(&self) -> Clock {
            self.clock.clone()
        }

        fn set_write_deadline(&mut self, deadline: Instant) -> io::Result<()> {
            self.deadline = Some(deadline);
            Ok(())
        }
    }

    impl io::Write for BlockedFlush {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            testing::remaining(
                &self.clock,
                self.deadline.expect("write deadline installed"),
            )?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            let deadline = self.deadline.expect("write deadline installed");
            testing::remaining(&self.clock, deadline)?;
            if let Some(entered) = self.entered.take() {
                entered.send(()).unwrap();
                self.release.wait(Some(deadline))?;
            }
            Ok(())
        }
    }

    /// Tests that ending a session waits for an active flush.
    #[test]
    fn test_end_waits_for_flush() {
        // Hold the first send in a flush on the client's clock
        testing::init_tracing();
        let tester = test_clock();
        let clock = tester.clock();
        let (entered_tx, entered) = mpsc::channel();
        let release = testing::Gate::new(&clock);
        let mut client = Client::new(Stream::new(
            Memory::new(io::empty(), &clock),
            BlockedFlush {
                clock: clock.clone(),
                entered: Some(entered_tx),
                release: release.clone(),
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
        entered.recv().unwrap();

        // Attempt session ending while the flush remains parked
        let (started_tx, started) = mpsc::channel();
        let (ended_tx, ended) = mpsc::channel();
        let outbound = client.outbound.clone();
        let ending = thread::spawn(move || {
            started_tx.send(()).unwrap();
            client.end_session();
            ended_tx.send(()).unwrap();
            client
        });
        started.recv().unwrap();
        tester.wait_blocked(1);
        outbound.wait_writers(1);
        assert!(ended.try_recv().is_err());

        // Release output and require the old session to refuse further sends
        release.open();
        sending.join().unwrap().unwrap();
        let mut client = ending.join().unwrap();
        ended.recv().unwrap();
        assert!(matches!(
            sender.send(&payload(2)),
            Err(Error::EncryptionFailed(_))
        ));

        // Establish fresh contexts on the still-open stream
        let (crypto, receiver) = contexts();
        let fresh = client.new_session(crypto, receiver);
        fresh.send(&payload(3)).unwrap();
        assert!(matches!(
            sender.send(&payload(4)),
            Err(Error::EncryptionFailed(_))
        ));
    }

    /// Tests that a receive returns a decrypted message while an outgoing flush
    /// is blocked.
    ///
    /// Waiting for the writer on the success path would deadlock, since the
    /// test releases that flush only after the receive returns.
    #[test]
    fn test_recv_during_blocked_flush() {
        // Prepare an encrypted incoming frame on a paused clock
        testing::init_tracing();
        let tester = test_clock();
        let clock = tester.clock();
        let (mut peer, receiver) = contexts();
        let packet = sealing::seal(&mut peer, &payload(1)).unwrap();
        let mut bytes = Vec::new();
        FrameWriter::new(Memory::new(&mut bytes, &clock), Closer::new(&clock, || {}))
            .send_packet(&packet, clock.now() + DEFAULT_WRITE_TIMEOUT)
            .unwrap();
        let (entered_tx, entered) = mpsc::channel();
        let release = testing::Gate::new(&clock);
        let mut client = Client::new(Stream::new(
            Memory::new(io::Cursor::new(bytes), &clock),
            BlockedFlush {
                clock: clock.clone(),
                entered: Some(entered_tx),
                release: release.clone(),
                deadline: None,
            },
            || {},
        ));
        let sender = client.new_session(contexts().0, receiver);
        let sending = thread::spawn(move || sender.send(&payload(2)));
        entered.recv().unwrap();

        // Receive the message while the outgoing flush is parked
        tester.wait_blocked(1);
        let (received_tx, received) = mpsc::channel();
        let receiving = thread::spawn(move || {
            received_tx.send(client.recv()).unwrap();
            client
        });
        let result = received.recv();

        // Release output only after receiving has completed
        release.open();
        sending.join().unwrap().unwrap();
        let _client = receiving.join().unwrap();
        assert_eq!(result.unwrap().unwrap(), payload(1));
    }

    /// Tests that releasing an old session's contexts leaves its replacement
    /// working, and that dropping the client ends that replacement.
    #[test]
    fn test_owner_drop() {
        // Prepare a replacement session's incoming packet on a paused clock
        testing::init_tracing();
        let tester = test_clock();
        let clock = tester.clock();
        let (mut peer, receiver) = contexts();
        let packet = sealing::seal(&mut peer, &payload(2)).unwrap();
        let mut bytes = Vec::new();
        FrameWriter::new(Memory::new(&mut bytes, &clock), Closer::new(&clock, || {}))
            .send_packet(&packet, clock.now() + DEFAULT_WRITE_TIMEOUT)
            .unwrap();
        let mut client = Client::new(Stream::new(
            Memory::new(&bytes[..], &clock),
            Memory::new(Vec::new(), &clock),
            || {},
        ));
        let (crypto, old_receiver) = contexts();
        let stale = client.new_session(crypto, old_receiver);
        let old_sealer = client.sealer.as_ref().unwrap().clone();

        // End the old contexts without disturbing their replacement
        let fresh = client.new_session(contexts().0, receiver);
        client.outbound.end(&old_sealer);
        drop(old_sealer);
        assert!(matches!(
            stale.send(&payload(1)),
            Err(Error::EncryptionFailed(_))
        ));
        assert_eq!(client.recv().unwrap(), payload(2));
        fresh.send(&payload(3)).unwrap();

        // Drop the owner while retaining its sending context and outgoing
        // transport, as active operations would
        let outbound = client.outbound.clone();
        let sealer = client.sealer.as_ref().unwrap().clone();
        drop(client);
        assert!(outbound.finish_receive(&sealer, Ok(Vec::new())).is_err());
        assert!(matches!(
            fresh.send(&payload(4)),
            Err(Error::EncryptionFailed(_))
        ));
    }

    /// Tests that other threads can send while the client blocks in a read.
    ///
    /// The server must receive every message in encryption order to decrypt
    /// and echo it.
    #[test]
    fn test_senders() {
        testing::init_tracing();

        // Connect to a server that echoes 100 requests over a bounded in-memory
        // stream, then hangs up
        let tester = test_clock();
        let (host, ark_stream) = memory::duplex(64 * 1024, &tester.clock());
        let signer = xdsa::SecretKey::generate();
        let identity = signer.public_key();
        let attestation = self_attestation(&signer);
        let ark = thread::spawn(move || {
            let mut server = Server::new(ark_stream, signer, attestation);
            let mut sender = None;
            for _ in 0..100 {
                let req = testing::served(&mut server, &mut sender).unwrap();
                sender.as_ref().unwrap().send(&req).unwrap();
            }
        });
        let mut client = Client::new(host);
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

        // Require every message back, whichever thread sent it
        echoes.sort_unstable();
        let mut expected: Vec<Vec<u8>> = (0..4)
            .flat_map(|thread| (0..25).map(move |i| payload(thread * 100 + i)))
            .collect();
        expected.sort_unstable();
        assert_eq!(echoes, expected);
    }

    /// Tests that dropping the client ends the session for its senders and
    /// releases the transport writer even while sender handles remain.
    #[test]
    fn test_sender_outlives_client() {
        // Send one packet before dropping the client owner
        testing::init_tracing();
        let tester = test_clock();
        let clock = tester.clock();
        let (mut reader, writer) = testing::pipe(&clock);
        let (sender, receiver) = contexts();
        let mut client = Client::new(Stream::new(Memory::new(io::empty(), &clock), writer, || {}));
        let sender = client.new_session(sender, receiver);
        sender.send(&payload(1)).unwrap();
        drop(client);

        // Refuse later sends and drain the closed writer to EOF
        let result = sender.send(&payload(2));
        assert!(matches!(result, Err(Error::Terminated)), "{result:?}");
        // The read only returns once the writer is gone
        let mut bytes = Vec::new();
        reader
            .set_read_deadline(Some(clock.now() + DEFAULT_WRITE_TIMEOUT))
            .unwrap();
        reader.read_to_end(&mut bytes).unwrap();
        assert!(!bytes.is_empty());
    }
}
