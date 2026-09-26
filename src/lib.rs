// wire-rs: encrypted protocol between Ark and host
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Allow excluding test code from coverage measurements on nightly
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
// Pull in the README as the package doc
#![doc = include_str!("../README.md")]

pub mod memory;
pub mod protocol;
pub mod transport;

// Re-export the crates whose types appear in the API, so consumers can name
// them at the exact versions this crate was compiled against
pub use darkbio_clock as clock;
pub use darkbio_cobs as cobs;
pub use darkbio_crypto as crypto;
pub use darkbio_trust as trust;
pub use prost;

/// Version of the wire crate compiled into this process.
///
/// It is mostly a debugging aid, so a protocol version mismatch can be found
/// without guessing who compiled what into where.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

/// Label of a session or a message in log lines.
///
/// Sessions get a process-local number the peer never sees, and the default
/// label is zero. The type derives no equality or hashing and exposes no
/// number, so no code can route or match on it.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct LogId(
    /// Number shown in log lines.
    u64,
);

impl From<u64> for LogId {
    /// Wraps a number as a log label.
    fn from(id: u64) -> Self {
        Self(id)
    }
}

impl fmt::Display for LogId {
    /// Formats the label as its bare number.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Counter numbering the sessions of every client and server in the process,
/// so log lines can follow a session from its establishment to its end.
static SESSIONS: AtomicU64 = AtomicU64::new(0);

/// Allocates the next session label, starting from one.
pub(crate) fn next_log_id() -> LogId {
    LogId(SESSIONS.fetch_add(1, Ordering::Relaxed) + 1)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod testing;
