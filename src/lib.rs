// wire-rs: encrypted protocol between Ark and host
// Copyright 2025 Dark Bio AG. All rights reserved.

// Allow excluding test code from coverage measurements on nightly
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
// Pull in the README as the package doc
#![doc = include_str!("../README.md")]

pub mod memory;
pub mod protocol;
pub mod transport;

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

/// Labels a session or a message in log lines and nothing else. Sessions get
/// a process-local number the peer never sees. The type derives no equality
/// or hashing and exposes no number, so nothing can route or match on it.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct LogId(u64);

impl From<u64> for LogId {
    fn from(id: u64) -> Self {
        Self(id)
    }
}

impl fmt::Display for LogId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Numbers the sessions of every client and server in the process, so log
/// lines can be followed from a session's establishment to its end.
static SESSIONS: AtomicU64 = AtomicU64::new(0);

/// Allocates the next session label, starting from one.
pub(crate) fn next_log_id() -> LogId {
    LogId(SESSIONS.fetch_add(1, Ordering::Relaxed) + 1)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod testing;
