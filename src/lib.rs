// wire-rs: encrypted protocol between Ark and host
// Copyright 2025 Dark Bio AG. All rights reserved.

// Allow excluding test code from coverage measurements on nightly
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
// Pull in the README as the package doc
#![doc = include_str!("../README.md")]

pub mod memory;
pub mod protocol;
pub mod transport;

#[cfg(any(test, feature = "fuzz"))]
#[doc(hidden)]
pub use transport::mock;

pub use protocol::{ArkToHost, HostToArk};
pub use transport::{
    Attestation, Attester, Client, Closer, DEFAULT_HANDSHAKE_TIMEOUT, DEFAULT_WRITE_TIMEOUT, Error,
    MAX_FRAME_SIZE, MAX_MESSAGE_SIZE, Read, Roots, Sender, Server, Stream, Verifier, Write,
};

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod testing;
