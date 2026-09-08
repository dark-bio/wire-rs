// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Replay of a transcript against a fresh client, the way another
//! implementation of it would consume the vectors. The reads are handed over
//! as recorded and the client's writes are checked against the transcript,
//! the deterministic ones for equality and the sealed ones by opening them
//! with the server's keys.

use super::{Event, ReadError, Vector};
use crate::transport::mock::server::check_session;
use crate::transport::mock::{TIMESTAMP, unframe};
use crate::transport::{
    CRYPTO_DOMAIN_WIRE, CRYPTO_DOMAIN_WIRE_HOST_TO_ARK, Client, Error, handshake,
};
use crate::transport::{Read, Write};
use base64::prelude::*;
use darkbio_crypto::{cbor, cose, xdsa, xhpke};
use serde_json::Value;
use std::io::{self, ErrorKind};
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

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

fn text(value: &Value) -> String {
    value.as_str().expect("expected a string").to_string()
}

fn bytes(value: &Value) -> Vec<u8> {
    BASE64_STANDARD
        .decode(value.as_str().expect("expected base64"))
        .expect("invalid base64")
}

fn list(value: &Value) -> &[Value] {
    value.as_array().expect("expected a list")
}

fn count(value: &Value) -> usize {
    value.as_u64().expect("expected a count") as usize
}

/// Read, write or oversized message bytes, spelled out or as runs.
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

/// Replays the transcript, panicking at the first divergence of the client
/// from it.
pub fn run(vector: &Vector) {
    let tape = Arc::new(Playback::new(vector.trace.clone()));
    let mut client = Client::new(crate::transport::Stream::new(
        Reader {
            playback: tape.clone(),
            deadline: Instant::now(),
        },
        Writer {
            playback: tape.clone(),
            pending_error: None,
        },
        || {},
    ));
    let mut peer = Peer::new(vector);
    let mut sender = None;
    let mut retained = None;

    while !tape.tape.lock().unwrap().done() {
        let event = {
            let mut tape = tape.tape.lock().unwrap();
            tape.output_failed = false;
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

/// Checks the result of a call and the writes made during it against the
/// transcript, a request being the message the call was asked to send.
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
    for (recorded, actual) in writes {
        peer.check(&recorded, &actual, request);
    }
}

/// Transport of a replay, playing the transcript's reads to the client and
/// taking its writes, failing them where the transcript says so.
struct Playback {
    tape: Mutex<Tape>,
    advanced: Condvar,
}

impl Playback {
    /// Shares the ordered tape between the reader and handshake writer.
    fn new(trace: Vec<Event>) -> Self {
        Self {
            tape: Mutex::new(Tape::new(trace)),
            advanced: Condvar::new(),
        }
    }
}

/// Recorded events and partially delivered reads under the playback lock.
struct Tape {
    trace: Vec<Event>,
    next: usize,                     // Next event to play
    pending: Vec<u8>,                // Read event bytes, retained until fully delivered
    offset: usize,                   // Bytes already delivered, avoiding a copy per small read
    chunk: usize,                    // Most bytes a read hands over, zero for all
    writes: Vec<(Vec<u8>, Vec<u8>)>, // Writes since the last check, recorded and actual
    output_failed: bool, // A concurrent helper failed, so reads wait for its cancellation
}

impl Tape {
    fn new(trace: Vec<Event>) -> Self {
        Self {
            trace,
            next: 0,
            pending: Vec::new(),
            offset: 0,
            chunk: 0,
            writes: Vec::new(),
            output_failed: false,
        }
    }

    /// Whether the transcript has been played to its end.
    fn done(&self) -> bool {
        self.next == self.trace.len()
    }

    /// The next event of the transcript, which must have one.
    fn next(&mut self) -> Event {
        let event = self.trace.get(self.next).cloned();
        self.next += 1;
        event.expect("transcript ended before the client did")
    }
}

/// Read half of the transport.
struct Reader {
    playback: Arc<Playback>,
    deadline: Instant, // Configured deadline for waiting on concurrent output
}

impl Read for Reader {
    fn set_read_deadline(&mut self, deadline: Instant) -> io::Result<()> {
        self.deadline = deadline;
        Ok(())
    }
}

impl io::Read for Reader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Quiet synthetic polls need not spend the adapter's full allowance.
        // Their count is deliberately absent from the deterministic transcript.
        let deadline = self.deadline.min(Instant::now() + Duration::from_millis(1));
        let mut tape = self.playback.tape.lock().unwrap();
        while tape.pending.is_empty() {
            // The handshake writer may not have consumed its prefix events
            // yet. A failed prefix leaves the call's error next; let the read
            // poll expire so the transport observes companion cancellation.
            if matches!(
                tape.trace.get(tape.next),
                Some(
                    Event::Write { .. }
                        | Event::WriteTimedOut { .. }
                        | Event::FlushFailed
                        | Event::FlushTimedOut
                )
            ) || (tape.output_failed
                && matches!(tape.trace.get(tape.next), Some(Event::Err { .. })))
            {
                let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                    return Err(ErrorKind::TimedOut.into());
                };
                tape = self
                    .playback
                    .advanced
                    .wait_timeout(tape, remaining)
                    .unwrap()
                    .0;
                continue;
            }
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

/// Write half of the transport.
struct Writer {
    playback: Arc<Playback>,
    pending_error: Option<ErrorKind>, // Failure after a recorded prefix returned Ok(n)
}

impl Write for Writer {
    fn set_write_deadline(&mut self, _deadline: Instant) -> io::Result<()> {
        // Recorded outcomes determine expiry without wall-clock delays.
        // An unobserved error belongs to output abandoned before another call.
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
        // A sealed frame varies in length with its COBS overhead, so a
        // failing transport takes as much of it as it did of the recorded one
        let n = match error.is_some() {
            true => recorded.len().min(buf.len()),
            // Older vectors recorded recovery separately. Accepting only its
            // delimiter remains a valid partial write of the combined output.
            false if recorded == [0] && buf.first() == Some(&0) => 1,
            false => buf.len(),
        };
        tape.writes.push((recorded, buf[..n].to_vec()));
        tape.output_failed |= error.is_some();
        self.playback.advanced.notify_all();
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
        // A recorded failed prefix can fill the replay's complete, differently
        // encoded frame. Flush must then surface the failure without a retry.
        if let Some(error) = self.pending_error.take() {
            return Err(error.into());
        }
        let mut tape = self.playback.tape.lock().unwrap();
        if tape.trace.get(tape.next) == Some(&Event::FlushFailed) {
            tape.next += 1;
            tape.output_failed = true;
            self.playback.advanced.notify_all();
            return Err(ErrorKind::BrokenPipe.into());
        }
        if tape.trace.get(tape.next) == Some(&Event::FlushTimedOut) {
            tape.next += 1;
            tape.output_failed = true;
            self.playback.advanced.notify_all();
            return Err(ErrorKind::TimedOut.into());
        }
        Ok(())
    }
}

/// The server's side of a replay, holding the keys of the transcript to open
/// what the client seals.
struct Peer {
    identity: xdsa::PublicKey,       // Server identity key, the pinned verifier
    xhpke: Vec<xhpke::SecretKey>,    // Server crypto keys, one per ArkHello
    signer: Option<xdsa::PublicKey>, // Client's signer key of the latest handshake
    receiver: Option<xhpke::Receiver>, // Context opening the client's requests
}

impl Peer {
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

    /// Checks a write of the client against the recorded one. A reset or a
    /// hello must match it. A sealed frame differs in content and, with the
    /// COBS overhead, in length. An ack must open with the server key it is
    /// sealed to, setting up the context the requests after it must open in.
    /// A write cut short leaves no frame to open.
    fn check(&mut self, recorded: &[u8], actual: &[u8], request: Option<&[u8]>) {
        // A combined write includes the recovery delimiter before its encoded
        // frame. Both representations identify the same packet for verification.
        let (recorded, actual) = match (recorded.strip_prefix(&[0]), actual.strip_prefix(&[0])) {
            (Some(recorded), Some(actual)) => (recorded, actual),
            _ => (recorded, actual),
        };
        if recorded == actual || actual.last() != Some(&0) {
            return;
        }
        let packet = unframe(&actual[..actual.len() - 1]);
        assert!(
            cbor::decode::<handshake::HostHello>(&packet).is_err(),
            "client hello differs from the recorded one"
        );
        match cose::recipient(&packet) {
            Ok(fingerprint) => {
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

// Tests a failed prefix whose recorded length covers a shorter replay frame.
// The standard write reports that whole frame as accepted; flush must surface
// the deferred error without consuming the following transcript event.
#[test]
fn test_full_prefix_failure_surfaces_on_flush() {
    use std::io::Write as _;

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

// Tests that every vector on disk decodes, re-encodes to the same file and
// replays against the client, the way another implementation consumes it.
#[test]
fn test_vectors_replay() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/client");
    let mut paths: Vec<_> = std::fs::read_dir(&dir)
        .expect("no vectors directory")
        .map(|entry| entry.unwrap().path())
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "no vectors to replay");

    for path in paths {
        // A checkout may have converted the line endings
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
