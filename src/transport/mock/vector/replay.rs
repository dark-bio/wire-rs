// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Replays recorded scenarios against a fresh client.
//! Reads follow the transcript. Deterministic writes must match the recorded
//! bytes. Complete encrypted frames can differ, so the replay opens them with
//! the server's keys to check their contents.

use super::{Event, ReadError, Vector};
use crate::transport::mock::server::check_session;
use crate::transport::mock::{SCRIPT_HANDSHAKE_TIMEOUT, TIMESTAMP, unframe};
use crate::transport::{
    CRYPTO_DOMAIN_WIRE, CRYPTO_DOMAIN_WIRE_HOST_TO_ARK, Client, Error, handshake,
};
use crate::transport::{Read, Write};
use base64::prelude::*;
use darkbio_cobs as cobs;
use darkbio_crypto::{cbor, cose, xdsa, xhpke};
use serde_json::Value;
use std::io::{self, ErrorKind};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Decodes a transcript from its JSON.
pub fn parse(json: &str) -> Vector {
    let root: Value = serde_json::from_str(json).expect("vector is not JSON");
    let server = &root["server"];
    Vector {
        scenario: text(&root["scenario"]),
        script: list(&root["script"]).iter().map(text).collect(),
        write_failures: root["write_failures"].as_bool().expect("expected a flag"),
        identity: bytes(&server["identity"]),
        attestation: bytes(&server["attestation"]),
        server_keys: list(&server["xhpke"]).iter().map(bytes).collect(),
        trace: list(&root["trace"]).iter().map(event).collect(),
    }
}

/// Reads a JSON string, panicking if the value has another type.
fn text(value: &Value) -> String {
    value.as_str().expect("expected a string").to_string()
}

/// Decodes a base64 JSON string, panicking if its type or encoding is invalid.
fn bytes(value: &Value) -> Vec<u8> {
    BASE64_STANDARD
        .decode(value.as_str().expect("expected base64"))
        .expect("invalid base64")
}

/// Reads a JSON array, panicking if the value has another type.
fn list(value: &Value) -> &[Value] {
    value.as_array().expect("expected a list")
}

/// Reads a nonnegative JSON integer as a count.
fn count(value: &Value) -> usize {
    value.as_u64().expect("expected a count") as usize
}

/// Decodes event bytes from base64 or runs of repeated values.
fn payload(event: &Value) -> Vec<u8> {
    match (&event["bytes"], &event["runs"]) {
        (Value::String(text), _) => BASE64_STANDARD.decode(text).expect("invalid base64"),
        (_, Value::Array(runs)) => runs
            .iter()
            .flat_map(|run| std::iter::repeat_n(count(&run[0]) as u8, count(&run[1])))
            .collect(),
        _ => panic!("event without bytes or runs"),
    }
}

/// Parses one event, panicking if its kind or required fields are invalid.
fn event(value: &Value) -> Event {
    match value["event"].as_str().expect("event without a kind") {
        "handshake" => Event::Handshake {
            xdsa: bytes(&value["xdsa"]),
            xhpke: bytes(&value["xhpke"]),
        },
        "send" => Event::Send {
            message: value
                .get("message")
                .map(bytes)
                .unwrap_or_else(|| payload(value)),
        },
        "retain" => Event::Retain,
        "send_retained" => Event::SendRetained {
            message: bytes(&value["message"]),
        },
        "recv" => Event::Recv,
        "ok" => Event::Ok {
            message: value.get("message").map(bytes),
        },
        "error" => Event::Err {
            kind: text(&value["kind"]),
        },
        "session" => Event::Session {
            established: value["established"].as_bool().expect("expected a flag"),
        },
        "read" => match value.get("error") {
            Some(error) => Event::ReadFailed {
                error: ReadError::parse(&text(error)),
            },
            None => Event::Read {
                bytes: payload(value),
                chunk: value.get("chunk").map_or(0, count),
            },
        },
        "write" => Event::Write {
            bytes: payload(value),
            failed: value.get("failed") == Some(&Value::Bool(true)),
        },
        "flush_failed" => Event::FlushFailed,
        "write_timed_out" => Event::WriteTimedOut {
            bytes: payload(value),
        },
        "flush_timed_out" => Event::FlushTimedOut,
        other => panic!("unknown event {other}"),
    }
}

/// Runs a transcript against a fresh client and checks its calls and output.
pub fn run(vector: &Vector) {
    let tape = Arc::new(Playback::new(vector.trace.clone()));
    let mut client = Client::new(crate::transport::Stream::new(
        Reader {
            playback: tape.clone(),
        },
        Writer {
            playback: tape.clone(),
            pending_error: None,
        },
        || {},
    ))
    .set_handshake_timeout(SCRIPT_HANDSHAKE_TIMEOUT);
    let mut peer = Peer::new(vector);
    let mut sender = None;
    let mut retained = None;

    while !tape.tape.lock().unwrap().done() {
        let event = {
            let mut tape = tape.tape.lock().unwrap();
            tape.next()
        };
        match event {
            Event::Handshake { xdsa, xhpke } => {
                sender = None;
                let signer = xdsa::SecretKey::from_bytes(xdsa[..].try_into().unwrap());
                let crypto = xhpke::SecretKey::from_bytes(xhpke[..].try_into().unwrap());
                peer.signer = Some(signer.public_key());
                let result = client
                    .handshake_with_keys(&peer.identity, signer, crypto, TIMESTAMP)
                    .map(|(opened, attestation)| {
                        sender = Some(opened);
                        assert_eq!(attestation.as_bytes(), &vector.attestation[..]);
                        None
                    });
                settle(&tape, &mut peer, None, result);
            }
            Event::Send { message } => {
                let result = super::super::send(sender.as_ref(), &message).map(|_| None);
                settle(&tape, &mut peer, Some(&message), result);
            }
            Event::Retain => retained = sender.clone(),
            Event::SendRetained { message } => {
                let result = super::super::send(retained.as_ref(), &message).map(|_| None);
                settle(&tape, &mut peer, Some(&message), result);
            }
            Event::Recv => {
                let result = client.recv().map(Some);
                settle(&tape, &mut peer, None, result);
            }
            Event::Session { established } => check_session(sender.as_ref(), established),
            event => panic!("transcript has {event:?} outside a call"),
        }
    }
}

/// Checks one call's result and output against the transcript.
/// `request` is the plaintext message supplied to a send call, if any.
fn settle(
    tape: &Arc<Playback>,
    peer: &mut Peer,
    request: Option<&[u8]>,
    result: Result<Option<Vec<u8>>, Error>,
) {
    let (expected, writes) = {
        let mut tape = tape.tape.lock().unwrap();
        let expected = tape.next();
        (expected, std::mem::take(&mut tape.writes))
    };
    match (result, expected) {
        (Ok(message), Event::Ok { message: recorded }) => assert_eq!(message, recorded),
        (Err(err), Event::Err { kind }) => assert_eq!(<&str>::from(&err), kind),
        (result, expected) => {
            panic!("client returned {result:?} where the transcript has {expected:?}")
        }
    }
    for (recorded, actual, failed) in writes {
        peer.check(&recorded, &actual, failed, request);
    }
}

/// Shared replay state for delivering recorded input and checking client output.
struct Playback {
    tape: Mutex<Tape>,
}

impl Playback {
    /// Shares the ordered tape between the reader and handshake writer.
    fn new(trace: Vec<Event>) -> Self {
        Self {
            tape: Mutex::new(Tape::new(trace)),
        }
    }
}

/// Recorded events and partially delivered reads under the playback lock.
struct Tape {
    trace: Vec<Event>,
    next: usize,                           // Next event to play
    pending: Vec<u8>,                      // Read event bytes, retained until fully delivered
    offset: usize, // Read cursor; keeps small reads from shifting the buffer
    chunk: usize,  // Maximum read size; zero means no limit
    writes: Vec<(Vec<u8>, Vec<u8>, bool)>, // Recorded bytes, actual bytes and recorded failure
}

impl Tape {
    /// Starts playback at the first event with no buffered I/O.
    fn new(trace: Vec<Event>) -> Self {
        Self {
            trace,
            next: 0,
            pending: Vec::new(),
            offset: 0,
            chunk: 0,
            writes: Vec::new(),
        }
    }

    /// Reports whether every transcript event has been consumed.
    fn done(&self) -> bool {
        self.next == self.trace.len()
    }

    /// Consumes the next event. Panics if the transcript has ended.
    fn next(&mut self) -> Event {
        let event = self.trace.get(self.next).cloned();
        self.next += 1;
        event.expect("transcript ended before the client did")
    }
}

/// Delivers transcript input to the real client.
struct Reader {
    playback: Arc<Playback>,
}

impl Read for Reader {
    fn set_read_deadline(&mut self, _deadline: Option<Instant>) -> io::Result<()> {
        // Recorded outcomes determine expiry without wall-clock delays.
        Ok(())
    }
}

impl io::Read for Reader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut tape = self.playback.tape.lock().unwrap();
        while tape.pending.is_empty() {
            match tape.next() {
                Event::Read { bytes, chunk } => {
                    tape.pending = bytes;
                    tape.chunk = chunk;
                }
                Event::ReadFailed {
                    error: ReadError::Eof,
                } => return Ok(0),
                Event::ReadFailed {
                    error: ReadError::Failed,
                } => return Err(ErrorKind::WouldBlock.into()),
                Event::ReadFailed {
                    error: ReadError::Interrupted,
                } => return Err(ErrorKind::Interrupted.into()),
                Event::ReadFailed {
                    error: ReadError::TimedOut,
                } => return Err(ErrorKind::TimedOut.into()),
                event => panic!("client read where the transcript has {event:?}"),
            }
        }
        let mut n = buf.len().min(tape.pending.len() - tape.offset);
        if tape.chunk > 0 {
            n = n.min(tape.chunk);
        }
        buf[..n].copy_from_slice(&tape.pending[tape.offset..tape.offset + n]);
        tape.offset += n;
        if tape.offset == tape.pending.len() {
            tape.pending.clear();
            tape.offset = 0;
        }
        Ok(n)
    }
}

/// Captures client output and injects the transcript's write and flush failures.
struct Writer {
    playback: Arc<Playback>,
    pending_error: Option<ErrorKind>, // Failure after a recorded prefix returned Ok(n)
}

impl Write for Writer {
    fn set_write_deadline(&mut self, _deadline: Instant) -> io::Result<()> {
        // Recorded outcomes determine expiry without wall-clock delays.
        // Starting new output discards any error left by an abandoned write.
        self.pending_error = None;
        Ok(())
    }
}

impl io::Write for Writer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(error) = self.pending_error.take() {
            return Err(error.into());
        }
        let mut tape = self.playback.tape.lock().unwrap();
        let (recorded, error) = match tape.next() {
            Event::Write { bytes, failed } => (bytes, failed.then_some(ErrorKind::BrokenPipe)),
            Event::WriteTimedOut { bytes } => (bytes, Some(ErrorKind::TimedOut)),
            event => panic!("client wrote where the transcript has {event:?}"),
        };
        // Fresh encryption can change COBS overhead and therefore frame length.
        // On failure, accept up to the recorded byte count from the actual frame.
        let n = match error.is_some() {
            true => recorded.len().min(buf.len()),
            // Older vectors recorded recovery separately. Accepting only its
            // delimiter remains a valid partial write of the combined output.
            false if recorded == [0] && buf.first() == Some(&0) => 1,
            false => buf.len(),
        };
        tape.writes
            .push((recorded, buf[..n].to_vec(), error.is_some()));
        match error {
            Some(error) if n > 0 => {
                self.pending_error = Some(error);
                Ok(n)
            }
            Some(error) => Err(error.into()),
            None => Ok(n),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        // A recorded partial write can cover the whole frame if its encoding
        // is shorter on replay. Return the deferred error from flush in that case.
        if let Some(error) = self.pending_error.take() {
            return Err(error.into());
        }
        let mut tape = self.playback.tape.lock().unwrap();
        if tape.trace.get(tape.next) == Some(&Event::FlushFailed) {
            tape.next += 1;
            return Err(ErrorKind::BrokenPipe.into());
        }
        if tape.trace.get(tape.next) == Some(&Event::FlushTimedOut) {
            tape.next += 1;
            return Err(ErrorKind::TimedOut.into());
        }
        Ok(())
    }
}

/// Opens client output using the server keys saved in the transcript.
struct Peer {
    identity: xdsa::PublicKey,       // Server identity key, the pinned verifier
    xhpke: Vec<xhpke::SecretKey>,    // Server crypto keys, one per ArkHello
    signer: Option<xdsa::PublicKey>, // Client's signer key of the latest handshake
    receiver: Option<xhpke::Receiver>, // Context opening the client's requests
}

impl Peer {
    /// Loads the recorded server keys with no client session established yet.
    fn new(vector: &Vector) -> Self {
        Self {
            identity: xdsa::PublicKey::from_bytes(vector.identity[..].try_into().unwrap()).unwrap(),
            xhpke: vector
                .server_keys
                .iter()
                .map(|seed| xhpke::SecretKey::from_bytes(seed[..].try_into().unwrap()))
                .collect(),
            signer: None,
            receiver: None,
        }
    }

    /// Checks client output against the recording.
    /// Unfinished output requires a recorded failure or an exact recorded prefix.
    /// Signals and HostHello must match exactly. Every complete encrypted frame
    /// is opened, even when its bytes match: HostAck installs the receiving
    /// context, and requests advance it while checking the plaintext.
    fn check(&mut self, recorded: &[u8], actual: &[u8], failed: bool, request: Option<&[u8]>) {
        if actual.last() != Some(&0) {
            assert!(
                failed || recorded == actual,
                "client left successful output unfinished: {actual:?} for {recorded:?}"
            );
            return;
        }
        // Check signals before stripping recovery prefixes. Otherwise a reset
        // missing its second delimiter could look like an unfinished frame.
        if actual.iter().all(|byte| *byte == 0) {
            assert_eq!(
                actual, recorded,
                "client signal differs from the recorded one"
            );
            return;
        }
        // A combined write includes the recovery delimiter before its encoded
        // frame. Both representations identify the same packet for verification.
        assert_eq!(
            actual.first() == Some(&0),
            recorded.first() == Some(&0),
            "client recovery delimiter differs from the recorded one"
        );
        let (recorded, actual) = match (recorded.strip_prefix(&[0]), actual.strip_prefix(&[0])) {
            (Some(recorded), Some(actual)) => (recorded, actual),
            _ => (recorded, actual),
        };
        let packet = unframe(&actual[..actual.len() - 1]);
        if cbor::decode::<handshake::HostHello>(&packet).is_ok() {
            assert_eq!(
                actual, recorded,
                "client hello differs from the recorded one"
            );
            return;
        }
        match cose::recipient(&packet) {
            Ok(fingerprint) => {
                // Encryption may change the bytes and frame length, but not
                // the recipient. A failed recording can end mid-frame even
                // when the fresh, shorter replay frame was fully accepted.
                assert_eq!(
                    fingerprint,
                    recorded_ack_recipient(recorded),
                    "client ack recipient differs from the recorded one"
                );
                let crypto = self
                    .xhpke
                    .iter()
                    .find(|key| key.public_key().fingerprint() == fingerprint)
                    .expect("ack sealed to a key the server never had");
                let auth = handshake::HostAckAuth {
                    ark_signer: self.identity.clone(),
                    ark_crypto: crypto.public_key(),
                };
                let signer = self.signer.as_ref().expect("ack before any handshake");
                let ack: handshake::HostAck =
                    cose::open(&packet, &auth, crypto, signer, CRYPTO_DOMAIN_WIRE, None)
                        .expect("client ack does not open");
                let encap: [u8; xhpke::ENCAP_KEY_SIZE] = ack
                    .h2a_encap
                    .try_into()
                    .expect("client ack encap size invalid");
                self.receiver = Some(
                    crypto
                        .new_receiver(&encap, CRYPTO_DOMAIN_WIRE_HOST_TO_ARK)
                        .unwrap(),
                );
            }
            Err(_) => {
                let receiver = self.receiver.as_mut().expect("request before any ack");
                let plain = receiver
                    .open(&packet, &[])
                    .expect("client request does not open");
                assert_eq!(
                    Some(&plain[..]),
                    request,
                    "client request differs from the one sent"
                );
            }
        }
    }
}

/// Extracts the expected recipient from a complete or partially recorded ACK.
/// A failed prefix covering a complete replay frame contains the protected
/// header even if the final ciphertext chunk is incomplete. Decode its complete
/// COBS chunks and require that header; never infer it from the replay's output.
fn recorded_ack_recipient(frame: &[u8]) -> xhpke::Fingerprint {
    if let Some(frame) = frame.strip_suffix(&[0]) {
        return cose::recipient(&unframe(frame)).expect("recorded ack has no recipient");
    }
    let mut packet = vec![0; cobs::decode_buffer(frame.len())];
    let size = match cobs::decode(frame, &mut packet) {
        Err(cobs::DecodeError::ChunkOverflow { at, .. }) => cobs::decode(&frame[..at], &mut packet),
        result => result,
    }
    .expect("recorded ack prefix has invalid COBS");
    let mut decoder = cbor::Decoder::new(&packet[..size]);
    assert_eq!(
        decoder.decode_array_header().unwrap(),
        3,
        "expected Encrypt0"
    );
    let protected = decoder
        .decode_bytes()
        .expect("recorded ack prefix lacks its protected header");
    let header: cose::EncProtectedHeader =
        cbor::decode(&protected).expect("recorded ack has invalid protected header");
    header.kid
}

// Tests a failed prefix whose recorded length covers a shorter replay frame.
// The standard write reports that whole frame as accepted; flush must surface
// the deferred error without consuming the following transcript event.
#[test]
fn test_full_prefix_failure_surfaces_on_flush() {
    use std::io::Write as _;
    use std::time::Duration;

    for error in [ErrorKind::BrokenPipe, ErrorKind::TimedOut] {
        let prefix = vec![1, 2, 3, 4];
        let failure = match error {
            ErrorKind::TimedOut => Event::WriteTimedOut { bytes: prefix },
            _ => Event::Write {
                bytes: prefix,
                failed: true,
            },
        };
        let playback = Arc::new(Playback::new(vec![
            failure,
            Event::Write {
                bytes: vec![0],
                failed: false,
            },
        ]));
        let mut writer = Writer {
            playback: playback.clone(),
            pending_error: None,
        };
        writer
            .set_write_deadline(Instant::now() + Duration::from_secs(1))
            .unwrap();
        assert_eq!(writer.write(&[1, 2, 0]).unwrap(), 3);
        assert_eq!(writer.flush().unwrap_err().kind(), error);

        writer
            .set_write_deadline(Instant::now() + Duration::from_secs(1))
            .unwrap();
        writer.write_all(&[0]).unwrap();
        writer.flush().unwrap();
        assert!(playback.tape.lock().unwrap().done());
    }
}

// Tests that every saved vector decodes, re-encodes unchanged and replays
// against the client. This checks the format consumed by other implementations.
#[test]
fn test_vectors_replay() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/client");
    if !dir.try_exists().expect("check vectors directory") {
        // Published crates omit replay fixtures.
        return;
    }
    let mut paths: Vec<_> = std::fs::read_dir(&dir)
        .expect("no vectors directory")
        .map(|entry| entry.unwrap().path())
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "no vectors to replay");

    for path in paths {
        // A checkout may have converted the line endings.
        let json = std::fs::read_to_string(&path)
            .unwrap()
            .replace("\r\n", "\n");
        let vector = parse(&json);
        assert!(
            vector.json() == json,
            "{} does not re-encode to itself",
            path.display()
        );
        run(&vector);
    }
}

/// Builds a replay peer, a sealed HostAck and its client sending context.
/// The peer has not processed the acknowledgement yet.
fn checker_session(seed: u8) -> (Peer, Vec<u8>, xhpke::Sender) {
    use crate::transport::mock::frame;

    let identity = xdsa::SecretKey::from_bytes(&[1; xdsa::SECRET_KEY_SIZE]).public_key();
    let crypto = xhpke::SecretKey::from_bytes(&[seed; xhpke::SECRET_KEY_SIZE]);
    let signer = xdsa::SecretKey::from_bytes(&[3; xdsa::SECRET_KEY_SIZE]);
    let (sender, encap) = crypto
        .public_key()
        .new_sender(CRYPTO_DOMAIN_WIRE_HOST_TO_ARK)
        .unwrap();
    let ack = cose::seal_at(
        &handshake::HostAck {
            h2a_encap: encap.to_vec(),
        },
        &handshake::HostAckAuth {
            ark_signer: identity.clone(),
            ark_crypto: crypto.public_key(),
        },
        &signer,
        &crypto.public_key(),
        CRYPTO_DOMAIN_WIRE,
        TIMESTAMP,
    )
    .unwrap();
    let peer = Peer {
        identity,
        xhpke: vec![crypto],
        signer: Some(signer.public_key()),
        receiver: None,
    };
    (peer, frame(&ack), sender)
}

// Tests that a recorded successful frame cannot replay as unfinished output.
// Includes a combined recovery prefix and a reset missing its second delimiter.
#[test]
fn test_checker_rejects_incomplete_successful_output() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    for (recorded, actual) in [
        (&[2, 42, 0][..], &[2, 42][..]),
        (&[0, 2, 42, 0][..], &[0, 2, 42][..]),
        (&[0, 0][..], &[0][..]),
    ] {
        let (mut peer, _, _) = checker_session(2);
        assert!(
            catch_unwind(AssertUnwindSafe(
                || peer.check(recorded, actual, false, None)
            ))
            .is_err(),
            "accepted incomplete successful output: {actual:?} for {recorded:?}"
        );
    }
}

// Tests that a complete encrypted frame cannot omit a recorded recovery zero,
// even if the write ultimately failed. Without that zero the peer would merge
// the packet with the preceding unfinished frame instead of decrypting it.
#[test]
fn test_checker_requires_recovery_delimiter() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    for failed in [false, true] {
        let (mut peer, ack, _) = checker_session(2);
        let mut recorded = vec![0];
        recorded.extend_from_slice(&ack);
        assert!(
            catch_unwind(AssertUnwindSafe(
                || peer.check(&recorded, &ack, failed, None)
            ))
            .is_err(),
            "accepted output without its recovery delimiter"
        );
    }
}

// Tests that exact HostAck bytes still install the replay's receiving context.
// The next request uses different valid ciphertext in the recording, forcing
// the checker to open the actual request with that installed context.
#[test]
fn test_checker_exact_ack_installs_receiver() {
    use crate::transport::mock::frame;

    let (mut peer, ack, mut sender) = checker_session(2);
    let (_, _, mut recorded_sender) = checker_session(2);
    peer.check(&ack, &ack, false, None);

    let message = b"first request";
    let actual = frame(&sender.seal(message, &[]).unwrap());
    let recorded = frame(&recorded_sender.seal(message, &[]).unwrap());
    assert_ne!(actual, recorded);
    peer.check(&recorded, &actual, false, Some(message));
}

// Tests that exact request bytes still advance the replay's receiving context.
// The following request differs from its recording and must decrypt at the next
// sequence number. The different ACK ensures this test isolates request handling.
#[test]
fn test_checker_exact_request_advances_receiver() {
    use crate::transport::mock::frame;

    let (mut peer, ack, mut sender) = checker_session(2);
    let (_, recorded_ack, mut recorded_sender) = checker_session(2);
    assert_ne!(ack, recorded_ack);
    peer.check(&recorded_ack, &ack, false, None);

    let first = b"first request";
    let actual = frame(&sender.seal(first, &[]).unwrap());
    peer.check(&actual, &actual, false, Some(first));
    recorded_sender.seal(first, &[]).unwrap();

    let second = b"second request";
    let actual = frame(&sender.seal(second, &[]).unwrap());
    let recorded = frame(&recorded_sender.seal(second, &[]).unwrap());
    assert_ne!(actual, recorded);
    peer.check(&recorded, &actual, false, Some(second));
}

// Tests the partial writes that remain valid: a failed write may stop mid-frame,
// while a successful write may match an explicitly recorded unfinished prefix.
#[test]
fn test_checker_accepts_recorded_partial_output() {
    let (mut peer, _, _) = checker_session(2);
    peer.check(&[2, 42, 0], &[2, 42], true, None);
    peer.check(&[2, 42], &[2, 42], false, None);
    peer.check(&[0], &[0], false, None);
}

// Tests that an ACK cannot use another saved server key, even with a valid
// signature from the current client. Randomized encryption preserves its recipient.
#[test]
fn test_checker_requires_recorded_ack_recipient() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let (mut peer, recorded_ack, _) = checker_session(2);
    let (stale, wrong_ack, _) = checker_session(9);
    peer.xhpke.extend(stale.xhpke);

    for failed in [false, true] {
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                peer.check(&recorded_ack, &wrong_ack, failed, None);
            }))
            .is_err(),
            "accepted an ack for a different recorded server key"
        );
    }
}

// Tests complete replay ACKs against real prefixes of longer recorded ACKs.
// Matching recipients must work; another saved key must be refused even when
// the recording ends before its delimiter or inside its final COBS chunk.
#[test]
fn test_checker_checks_complete_ack_after_recorded_prefix_failure() {
    use crate::transport::mock::frame;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    for (seed, accepted) in [(2, true), (9, false)] {
        // Randomized COBS lengths must leave room for a genuine partial write:
        // Writer can only accept a complete replay frame if it fits the prefix.
        let (mut peer, recorded, other, ack, mut sender) = (0..128)
            .find_map(|_| {
                let (peer, recorded, _) = checker_session(2);
                let (other, ack, sender) = checker_session(seed);
                let mut decoded = vec![0; cobs::decode_buffer(recorded.len())];
                (recorded.len() >= ack.len() + 2
                    && matches!(
                        cobs::decode(&recorded[..recorded.len() - 2], &mut decoded),
                        Err(cobs::DecodeError::ChunkOverflow { .. })
                    ))
                .then_some((peer, recorded, other, ack, sender))
            })
            .expect("randomized ACKs provide a shorter replay frame");
        peer.xhpke.extend(other.xhpke);
        for len in [recorded.len() - 1, recorded.len() - 2] {
            let result = catch_unwind(AssertUnwindSafe(|| {
                peer.check(&recorded[..len], &ack, true, None);
            }));
            assert_eq!(result.is_ok(), accepted, "incorrect ACK recipient decision");
            assert_eq!(peer.receiver.is_some(), accepted);
        }
        if accepted {
            let message = frame(&sender.seal(b"fresh context", &[]).unwrap());
            peer.check(&message, &message, false, Some(b"fresh context"));
        }
    }
}
