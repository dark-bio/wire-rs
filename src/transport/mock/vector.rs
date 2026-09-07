// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Transcripts of the client scenarios, test vectors for other implementations
//! of the client to replay. A transcript holds the keys of both sides and every
//! byte crossing the transport in order, with the calls made into the client
//! and their results between them. The format is documented in
//! `vectors/README.md`, the replay submodule being its reference consumer.

#[cfg(test)]
pub mod replay;

use base64::prelude::*;
use std::cell::Cell;
use std::fmt::Debug;
use std::path::PathBuf;

/// Environment variable naming the directory the transcripts are written into.
pub const ENV: &str = "WIRE_VECTORS";

/// Transcript of one scenario run.
#[derive(PartialEq, Eq)]
pub struct Vector {
    scenario: String,          // Name of the test, numbered from its second script
    script: Vec<String>,       // The steps run, for reading along
    write_failures: bool,      // Whether the client's writes are made to fail
    identity: Vec<u8>,         // Public identity key of the server, the pinned verifier
    attestation: Vec<u8>,      // Attestation the server presents
    server_keys: Vec<Vec<u8>>, // Seeds of the server's xHPKE key per ArkHello
    trace: Vec<Event>,         // The calls and everything crossing the transport, in order
}

/// One thing happening during the run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The driver calls `handshake` with the client keys, as seeds.
    Handshake { xdsa: Vec<u8>, xhpke: Vec<u8> },
    /// The driver calls `send_message` with the protobuf encoded message.
    Send { message: Vec<u8> },
    /// The driver calls `next_message`.
    Recv,
    /// The call in progress returns, a read with the protobuf encoded message.
    Ok { message: Option<Vec<u8>> },
    /// The call in progress fails with the error, named after its variant.
    Err { kind: String },
    /// Whether the client holds a session, checked between calls.
    Session { established: bool },
    /// The transport hands the client the bytes, in reads of at most the
    /// chunk size when nonzero.
    Read { bytes: Vec<u8>, chunk: usize },
    /// A read comes up empty.
    ReadFailed { error: ReadError },
    /// The client writes the bytes, the transport reporting failure after
    /// taking them when failed. A write cut short carries what got out.
    Write { bytes: Vec<u8>, failed: bool },
    /// The flush after a write fails.
    FlushFailed,
}

/// How a read comes up empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadError {
    /// The transport ended.
    Eof,
    /// The read failed.
    Failed,
    /// The read was interrupted, to be retried.
    Interrupted,
}

impl ReadError {
    /// The name the transcript spells the error by.
    pub fn name(self) -> &'static str {
        match self {
            ReadError::Eof => "eof",
            ReadError::Failed => "failed",
            ReadError::Interrupted => "interrupted",
        }
    }

    /// The error the transcript names.
    pub fn parse(name: &str) -> Self {
        match name {
            "eof" => ReadError::Eof,
            "failed" => ReadError::Failed,
            "interrupted" => ReadError::Interrupted,
            other => panic!("unknown read error {other}"),
        }
    }
}

thread_local! {
    /// Runs recorded on the thread, numbering the transcripts of a test that
    /// runs more than one script.
    static RUNS: Cell<usize> = const { Cell::new(0) };
}

/// Names the scenario a run belongs to after the test running on the thread,
/// numbered from the second script the test runs. Nothing when the run is
/// not transcribed, neither testing nor WIRE_VECTORS naming a directory.
pub fn scenario() -> Option<String> {
    if !cfg!(test) && std::env::var_os(ENV).is_none() {
        return None;
    }
    let thread = std::thread::current();
    let base = thread
        .name()
        .unwrap_or("scenario")
        .rsplit("::")
        .next()
        .unwrap();
    let base = base
        .strip_prefix("test_scripted_")
        .or_else(|| base.strip_prefix("test_"))
        .unwrap_or(base);
    let runs = RUNS.with(|runs| {
        runs.set(runs.get() + 1);
        runs.get()
    });
    Some(match runs {
        1 => base.to_string(),
        n => format!("{base}-{n}"),
    })
}

impl Vector {
    /// Starts the transcript of a named run, the name being absent when the
    /// run is not transcribed.
    pub fn open<S: Debug>(
        scenario: Option<String>,
        steps: &[S],
        write_failures: bool,
        identity: Vec<u8>,
        attestation: Vec<u8>,
    ) -> Option<Self> {
        Some(Self {
            scenario: scenario?,
            script: steps.iter().map(|step| format!("{step:?}")).collect(),
            write_failures,
            identity,
            attestation,
            server_keys: Vec::new(),
            trace: Vec::new(),
        })
    }

    /// Adds the ephemeral key of an ArkHello.
    pub fn server_key(&mut self, xhpke: Vec<u8>) {
        self.server_keys.push(xhpke);
    }

    /// Appends what happened next.
    pub fn log(&mut self, event: Event) {
        self.trace.push(event);
    }

    /// Writes the transcript into the directory WIRE_VECTORS names, if set.
    pub fn write(&self) {
        let Some(root) = std::env::var_os(ENV) else {
            return;
        };
        let dir = PathBuf::from(root).join("client");
        std::fs::create_dir_all(&dir).expect("failed to create the vector directory");
        std::fs::write(dir.join(format!("{}.json", self.scenario)), self.json())
            .expect("failed to write the vector");
    }

    /// Encodes the transcript as JSON, bytes in base64, one event per line.
    pub fn json(&self) -> String {
        let script: Vec<String> = self
            .script
            .iter()
            .map(|step| serde_json::to_string(step).unwrap())
            .collect();
        let mut lines = vec![
            "{".to_string(),
            format!(
                "  \"scenario\": {},",
                serde_json::to_string(&self.scenario).unwrap()
            ),
            format!("  \"script\": [{}],", script.join(", ")),
            format!("  \"write_failures\": {},", self.write_failures),
            "  \"server\": {".to_string(),
            format!(
                "    \"identity\": \"{}\",",
                BASE64_STANDARD.encode(&self.identity)
            ),
            format!(
                "    \"attestation\": \"{}\",",
                BASE64_STANDARD.encode(&self.attestation)
            ),
            "    \"xhpke\": [".to_string(),
        ];
        let keys = self
            .server_keys
            .iter()
            .map(|key| format!("      \"{}\"", BASE64_STANDARD.encode(key)));
        lines.extend(listed(keys));
        lines.extend(["    ]", "  },", "  \"trace\": ["].map(String::from));
        lines.extend(listed(
            self.trace
                .iter()
                .map(|event| format!("    {}", event.json())),
        ));
        lines.extend(["  ]", "}", ""].map(String::from));
        lines.join("\n")
    }
}

impl Event {
    /// Encodes the event as one JSON object.
    fn json(&self) -> String {
        let fields = match self {
            Event::Handshake { xdsa, xhpke } => format!(
                "\"event\": \"handshake\", \"xdsa\": \"{}\", \"xhpke\": \"{}\"",
                BASE64_STANDARD.encode(xdsa),
                BASE64_STANDARD.encode(xhpke)
            ),
            Event::Send { message } => format!(
                "\"event\": \"send\", \"message\": \"{}\"",
                BASE64_STANDARD.encode(message)
            ),
            Event::Recv => "\"event\": \"recv\"".to_string(),
            Event::Ok { message: None } => "\"event\": \"ok\"".to_string(),
            Event::Ok {
                message: Some(message),
            } => format!(
                "\"event\": \"ok\", \"message\": \"{}\"",
                BASE64_STANDARD.encode(message)
            ),
            Event::Err { kind } => format!("\"event\": \"error\", \"kind\": \"{kind}\""),
            Event::Session { established } => {
                format!("\"event\": \"session\", \"established\": {established}")
            }
            Event::Read { bytes, chunk: 0 } => format!("\"event\": \"read\", {}", payload(bytes)),
            Event::Read { bytes, chunk } => {
                format!(
                    "\"event\": \"read\", {}, \"chunk\": {chunk}",
                    payload(bytes)
                )
            }
            Event::ReadFailed { error } => {
                format!("\"event\": \"read\", \"error\": \"{}\"", error.name())
            }
            Event::Write {
                bytes,
                failed: false,
            } => format!("\"event\": \"write\", {}", payload(bytes)),
            Event::Write {
                bytes,
                failed: true,
            } => format!("\"event\": \"write\", {}, \"failed\": true", payload(bytes)),
            Event::FlushFailed => "\"event\": \"flush_failed\"".to_string(),
        };
        format!("{{{fields}}}")
    }
}

/// The bytes of an event as a base64 string, or as runs of one byte value
/// with their count where that is much shorter, which the oversized frames
/// are.
fn payload(bytes: &[u8]) -> String {
    let mut runs: Vec<(u8, usize)> = Vec::new();
    for &byte in bytes {
        match runs.last_mut() {
            Some((last, count)) if *last == byte => *count += 1,
            _ => runs.push((byte, 1)),
        }
    }
    if runs.len() * 8 < bytes.len() {
        let runs: Vec<String> = runs
            .iter()
            .map(|(byte, count)| format!("[{byte}, {count}]"))
            .collect();
        return format!("\"runs\": [{}]", runs.join(", "));
    }
    format!("\"bytes\": \"{}\"", BASE64_STANDARD.encode(bytes))
}

/// Terminates every item of a JSON list but the last with a comma.
fn listed(items: impl Iterator<Item = String>) -> impl Iterator<Item = String> {
    let mut items = items.peekable();
    std::iter::from_fn(move || {
        let mut item = items.next()?;
        if items.peek().is_some() {
            item.push(',');
        }
        Some(item)
    })
}
