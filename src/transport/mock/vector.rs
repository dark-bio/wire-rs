// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Records client scenarios as test vectors for other client implementations.
//!
//! Each transcript contains keys for both peers, client calls and their
//! results, and the bytes read or written during each call. [`Event`] defines
//! the recorded operations, and the `replay` submodule consumes the JSON
//! format.

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
    /// Scenario name from the test, numbered from its second run on.
    scenario: String,
    /// Human-readable scenario steps, in their `Debug` form.
    script: Vec<String>,
    /// Whether the script makes the client's writes fail.
    write_failures: bool,
    /// Encoded server identity key, which the client pins.
    identity: Vec<u8>,
    /// Device attestation the server presents, as CWT bytes.
    attestation: Vec<u8>,
    /// Server xHPKE secret-key seeds, one per ArkHello.
    server_keys: Vec<Vec<u8>>,
    /// Client calls, their results and the I/O events, in order.
    trace: Vec<Event>,
}

/// One client call, result, session check or I/O operation in a transcript.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A handshake the driver starts with these client secret-key seeds.
    Handshake {
        /// Seed of the client's ephemeral xDSA signing key.
        xdsa: Vec<u8>,
        /// Seed of the client's ephemeral xHPKE encryption key.
        xhpke: Vec<u8>,
    },
    /// A [`send`](crate::transport::Sender::send) call through the current
    /// sender.
    ///
    /// In JSON, an oversized message takes the `bytes` or `runs` field of I/O
    /// events, while an ordinary one keeps the base64 `message` field.
    Send {
        /// Message passed to the call.
        message: Vec<u8>,
    },
    /// A copy of the current sender that the driver keeps for later sends.
    Retain,
    /// A send through the retained sender, leaving the current one unchanged.
    SendRetained {
        /// Message passed to the call.
        message: Vec<u8>,
    },
    /// A [`recv`](crate::transport::Client::recv) call.
    Recv,
    /// Success of the call, with the plaintext message of a receive.
    Ok {
        /// Plaintext message a receive returned, or `None` for other calls.
        message: Option<Vec<u8>>,
    },
    /// Failure of the call with this transport error variant.
    Err {
        /// Name of the [`Error`](crate::transport::Error) variant.
        kind: String,
    },
    /// A check of whether the current sender still has an active session.
    Session {
        /// Whether the model expects the sender to have a session.
        established: bool,
    },
    /// Input handed to the client, possibly over several reads.
    Read {
        /// Bytes handed to the client.
        bytes: Vec<u8>,
        /// Maximum bytes per read, or zero for no limit.
        chunk: usize,
    },
    /// A read returning EOF or an error instead of bytes.
    ReadFailed {
        /// EOF or the error the read returns.
        error: ReadError,
    },
    /// One client write, with the bytes the adapter accepted.
    ///
    /// A partial failure combines two standard I/O calls in one event, the
    /// write that accepts the bytes and the next write or flush that fails.
    Write {
        /// Bytes the adapter accepted.
        bytes: Vec<u8>,
        /// Whether an error followed the accepted bytes.
        failed: bool,
    },
    /// A failed flush after a write.
    FlushFailed,
    /// A write that reports `TimedOut` after accepting these bytes.
    ///
    /// Acceptance and its following error are recorded as one logical event.
    WriteTimedOut {
        /// Bytes the adapter accepted before the timeout.
        bytes: Vec<u8>,
    },
    /// A flush that reports `TimedOut`.
    FlushTimedOut,
}

/// EOF or an error returned by a recorded read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadError {
    /// End of the input, returned as a zero-length read.
    Eof,
    /// A `WouldBlock` error, yielding control to the driver.
    Failed,
    /// An `Interrupted` error, which the transport retries.
    Interrupted,
    /// An early `TimedOut` error, after which the transport keeps waiting for
    /// input.
    TimedOut,
}

impl ReadError {
    /// Returns the error's JSON name.
    pub fn name(self) -> &'static str {
        match self {
            ReadError::Eof => "eof",
            ReadError::Failed => "failed",
            ReadError::Interrupted => "interrupted",
            ReadError::TimedOut => "timed_out",
        }
    }

    /// Parses an error's JSON name.
    ///
    /// # Panics
    ///
    /// Panics on an unknown name.
    pub fn parse(name: &str) -> Self {
        match name {
            "eof" => ReadError::Eof,
            "failed" => ReadError::Failed,
            "interrupted" => ReadError::Interrupted,
            "timed_out" => ReadError::TimedOut,
            other => panic!("unknown read error {other}"),
        }
    }
}

thread_local! {
    /// Number of scenario names handed out on this thread, distinguishing the
    /// scripts of one test.
    static RUNS: Cell<usize> = const { Cell::new(0) };
}

/// Derives a scenario name from the current test thread's name.
///
/// The name drops the module path and any `test_scripted_` or `test_` prefix.
/// The second and later runs on the thread add a numeric suffix. Returns
/// `None` outside tests unless `WIRE_VECTORS` is set.
pub fn scenario() -> Option<String> {
    if !cfg!(test) && std::env::var_os(ENV).is_none() {
        return None;
    }

    // Name the scenario after the test function
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

    // Number the second and later runs of the test
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
    /// Starts a transcript for a named run.
    ///
    /// Returns `None` without a name, which leaves the run unrecorded.
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

    /// Records the server's ephemeral secret-key seed for one ArkHello.
    pub fn server_key(&mut self, xhpke: Vec<u8>) {
        self.server_keys.push(xhpke);
    }

    /// Appends the next event to the transcript.
    pub fn log(&mut self, event: Event) {
        self.trace.push(event);
    }

    /// Writes the transcript to `WIRE_VECTORS/client/<scenario>.json`, if
    /// `WIRE_VECTORS` is set.
    pub fn write(&self) {
        let Some(root) = std::env::var_os(ENV) else {
            return;
        };
        let dir = PathBuf::from(root).join("client");
        std::fs::create_dir_all(&dir).expect("failed to create the vector directory");
        std::fs::write(dir.join(format!("{}.json", self.scenario)), self.json())
            .expect("failed to write the vector");
    }

    /// Encodes the transcript as JSON with one event per line.
    ///
    /// Bytes use base64 or compact runs of repeated values.
    pub fn json(&self) -> String {
        // Open with the scenario, its script and the server's keys
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

        // Close the server's keys, then list the trace one event per line
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
            Event::Send { message } if message.len() > crate::transport::MAX_MESSAGE_SIZE => {
                format!("\"event\": \"send\", {}", payload(message))
            }
            Event::Send { message } => format!(
                "\"event\": \"send\", \"message\": \"{}\"",
                BASE64_STANDARD.encode(message)
            ),
            Event::Retain => "\"event\": \"retain\"".to_string(),
            Event::SendRetained { message } => format!(
                "\"event\": \"send_retained\", \"message\": \"{}\"",
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
            Event::WriteTimedOut { bytes } => {
                format!("\"event\": \"write_timed_out\", {}", payload(bytes))
            }
            Event::FlushTimedOut => "\"event\": \"flush_timed_out\"".to_string(),
        };
        format!("{{{fields}}}")
    }
}

/// Encodes event bytes as base64 or, when much shorter, runs of repeated values.
fn payload(bytes: &[u8]) -> String {
    // Count the runs of repeated byte values
    let mut runs: Vec<(u8, usize)> = Vec::new();
    for &byte in bytes {
        match runs.last_mut() {
            Some((last, count)) if *last == byte => *count += 1,
            _ => runs.push((byte, 1)),
        }
    }

    // Use the runs when there are fewer than one per 8 bytes
    if runs.len() * 8 < bytes.len() {
        let runs: Vec<String> = runs
            .iter()
            .map(|(byte, count)| format!("[{byte}, {count}]"))
            .collect();
        return format!("\"runs\": [{}]", runs.join(", "));
    }
    format!("\"bytes\": \"{}\"", BASE64_STANDARD.encode(bytes))
}

/// Adds commas after every JSON list item except the last.
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
