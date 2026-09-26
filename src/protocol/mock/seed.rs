// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Encodes protocol scenarios and raw envelopes for their fuzz targets.
//!
//! Action encodings are checked against their `Arbitrary` decoders; envelope
//! inputs are already wire bytes prefixed by a direction byte. The shared writer
//! saves them under `WIRE_SEEDS/<target>`. Action inputs come from
//! `session/fuzz_tests.rs` and `connection/fuzz_tests.rs`, envelope inputs from
//! `envelope/tests.rs` and `session/tests.rs`. `make fuzz-seeds` regenerates
//! them alongside the transport seeds.

use super::{connection, session};
use crate::transport::mock::seed::{Seed, Seedable};

pub(super) use crate::transport::mock::seed::seed;

/// Session lifecycle target, driven by the model's integer clock.
///
/// Must match its binary name in `fuzz/Cargo.toml`.
pub const SESSION_TARGET: &str = "protocol-session";

/// Connection target, driven through live encrypted streams.
///
/// Must match its binary name in `fuzz/Cargo.toml`.
pub const CONNECTION_TARGET: &str = "protocol-connection";

/// Envelope decoder target, driven directly with peer bytes.
///
/// Must match its binary name in `fuzz/Cargo.toml`.
pub const ENVELOPE_TARGET: &str = "protocol-envelope";

impl Seedable for session::Action {
    fn seed(&self, seed: &mut Seed) {
        /// Number of session action kinds, which scales the encoded kind index.
        const COUNT: u32 = 20;
        seed.variant(self.kind as u32, COUNT);
        seed.byte(self.slot);
        seed.byte(self.value);
        seed.byte(self.budget);
    }
}

impl Seedable for connection::Action {
    fn seed(&self, seed: &mut Seed) {
        /// Number of connection action kinds, which scales the encoded kind index.
        const COUNT: u32 = 19;
        seed.variant(self.kind as u32, COUNT);
        seed.byte(self.slot);
        seed.byte(self.value);
        seed.byte(self.budget);
    }
}

/// Saves an envelope input unchanged as a seed of [`ENVELOPE_TARGET`], when
/// `WIRE_SEEDS` is set.
pub(super) fn envelope(input: &[u8]) {
    crate::transport::mock::seed::write(ENVELOPE_TARGET, || input.to_vec());
}
