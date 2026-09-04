// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Replay of a transcript against a fresh client, the way another
//! implementation of it would consume the vectors. The reads are handed over
//! as recorded and the client's writes are checked against the transcript,
//! the deterministic ones for equality and the sealed ones by opening them
//! with the server's keys.

use super::{Event, ReadError, Vector};
use crate::mock::server::check_session;
use crate::mock::{TIMESTAMP, unframe};
use crate::{
    CRYPTO_DOMAIN_WIRE, CRYPTO_DOMAIN_WIRE_HOST_TO_ARK, Client, Error, HostToArk, handshake,
};
use base64::prelude::*;
use darkbio_crypto::{cbor, cose, xdsa, xhpke};
use prost::Message;
use serde_json::Value;
use std::cell::RefCell;
use std::io::{self, ErrorKind, Read, Write};
use std::path::Path;
use std::rc::Rc;

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

/// The bytes of a read or a write, spelled out or as runs.
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
        other => panic!("unknown event {other}"),
    }
}

/// Replays the transcript, panicking at the first divergence of the client
/// from it.
pub fn run(vector: &Vector) {
    let tape = Rc::new(RefCell::new(Tape::new(vector.trace.clone())));
    let mut client = Client::new(Reader(tape.clone()), Writer(tape.clone()));
    let mut peer = Peer::new(vector);

    while !tape.borrow().done() {
        let event = tape.borrow_mut().next();
        match event {
            Event::Handshake { xdsa, xhpke } => {
                let signer = xdsa::SecretKey::from_bytes(xdsa[..].try_into().unwrap());
                let crypto = xhpke::SecretKey::from_bytes(xhpke[..].try_into().unwrap());
                peer.signer = Some(signer.public_key());
                let result = client
                    .handshake_with_keys(&peer.identity, signer, crypto, TIMESTAMP)
                    .map(|attestation| {
                        assert_eq!(attestation.as_bytes(), &vector.attestation[..]);
                        None
                    });
                settle(&tape, &mut peer, None, result);
            }
            Event::Send { message } => {
                let request = HostToArk::decode(&message[..]).unwrap();
                let result = client.send_message(request).map(|_| None);
                settle(&tape, &mut peer, Some(&message), result);
            }
            Event::Recv => {
                let result = client.next_message().map(|msg| Some(msg.encode_to_vec()));
                settle(&tape, &mut peer, None, result);
            }
            Event::Session { established } => check_session(&mut client, established),
            event => panic!("transcript has {event:?} outside a call"),
        }
    }
}

/// Checks the result of a call and the writes made during it against the
/// transcript, a request being the message the call was asked to send.
fn settle(
    tape: &Rc<RefCell<Tape>>,
    peer: &mut Peer,
    request: Option<&[u8]>,
    result: Result<Option<Vec<u8>>, Error>,
) {
    let (expected, writes) = {
        let mut tape = tape.borrow_mut();
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
struct Tape {
    trace: Vec<Event>,
    next: usize,                     // Next event to play
    pending: Vec<u8>,                // Rest of the read in progress
    chunk: usize,                    // Most bytes a read hands over, zero for all
    writes: Vec<(Vec<u8>, Vec<u8>)>, // Writes since the last check, recorded and actual
}

impl Tape {
    fn new(trace: Vec<Event>) -> Self {
        Self {
            trace,
            next: 0,
            pending: Vec::new(),
            chunk: 0,
            writes: Vec::new(),
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
struct Reader(Rc<RefCell<Tape>>);

impl Read for Reader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut tape = self.0.borrow_mut();
        if tape.pending.is_empty() {
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
                event => panic!("client read where the transcript has {event:?}"),
            }
        }
        let mut n = buf.len().min(tape.pending.len());
        if tape.chunk > 0 {
            n = n.min(tape.chunk);
        }
        buf[..n].copy_from_slice(&tape.pending[..n]);
        tape.pending.drain(..n);
        Ok(n)
    }
}

/// Write half of the transport.
struct Writer(Rc<RefCell<Tape>>);

impl Write for Writer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut tape = self.0.borrow_mut();
        let (recorded, failed) = match tape.next() {
            Event::Write { bytes, failed } => (bytes, failed),
            event => panic!("client wrote where the transcript has {event:?}"),
        };
        // A sealed frame varies in length with its COBS overhead, so a
        // failing transport takes as much of it as it did of the recorded one
        let n = match failed {
            true => recorded.len().min(buf.len()),
            false => buf.len(),
        };
        tape.writes.push((recorded, buf[..n].to_vec()));
        match failed {
            true => Err(ErrorKind::BrokenPipe.into()),
            false => Ok(n),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut tape = self.0.borrow_mut();
        if tape.trace.get(tape.next) == Some(&Event::FlushFailed) {
            tape.next += 1;
            return Err(ErrorKind::BrokenPipe.into());
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
