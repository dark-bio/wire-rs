// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Encodes protocol scenarios and raw envelopes for their fuzz targets.
//!
//! Action encodings are checked against their `Arbitrary` decoders; envelope
//! inputs are already wire bytes prefixed by a direction byte. The shared writer
//! saves them under `WIRE_SEEDS/<target>`. The inputs come from
//! `session/fuzz_tests.rs`, `connection/fuzz_tests.rs` and `envelope/tests.rs`.
//! `make fuzz-seeds` regenerates them alongside the transport seeds.

use super::{connection, session};
use crate::transport::mock::seed::{Seed, Seedable};

pub(super) use crate::transport::mock::seed::seed;

/// Session lifecycle target, driven by the model's integer clock.
/// Must match its binary name in fuzz/Cargo.toml.
pub const SESSION_TARGET: &str = "protocol-session";

/// Connection target, driven through live encrypted streams.
/// Must match its binary name in fuzz/Cargo.toml.
pub const CONNECTION_TARGET: &str = "protocol-connection";

/// Envelope decoder target, driven directly with peer bytes.
/// Must match its binary name in fuzz/Cargo.toml.
pub const ENVELOPE_TARGET: &str = "protocol-envelope";

impl Seedable for session::Action {
    fn seed(&self, seed: &mut Seed) {
        const COUNT: u32 = 17;
        seed.variant(self.kind as u32, COUNT);
        seed.byte(self.slot);
        seed.byte(self.value);
        seed.byte(self.budget);
    }
}

impl Seedable for connection::Action {
    fn seed(&self, seed: &mut Seed) {
        const COUNT: u32 = 18;
        seed.variant(self.kind as u32, COUNT);
        seed.byte(self.slot);
        seed.byte(self.value);
        seed.byte(self.budget);
    }
}

/// Saves an envelope input in the exact byte format consumed by its fuzz target.
pub(super) fn envelope(input: &[u8]) {
    crate::transport::mock::seed::write(ENVELOPE_TARGET, || input.to_vec());
}
