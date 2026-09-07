// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Seeds for the multiplexer fuzzers, the scripts of the scenario tests
//! written out as the fuzzers' `Arbitrary` decoding reads them. The encoder
//! is the transport's, the two layers spelling their scripts the same way.

use super::peer::Step;
use crate::transport::mock::seed::{Seed, Seedable};

/// Fuzz target driving the protocol's real client multiplexer through the
/// mock peer's scripts, which seed its corpus. Keep it in step with the binary
/// in fuzz/Cargo.toml, the fuzz-seeds make target checks that every target
/// listed there gets seeds.
pub const PROTOCOL_CLIENT: &str = "protocol-client";

/// Fuzz target driving the protocol's real server multiplexer through the
/// mock peer's scripts, which seed its corpus. Keep it in step with the binary
/// in fuzz/Cargo.toml, the fuzz-seeds make target checks that every target
/// listed there gets seeds.
pub const PROTOCOL_SERVER: &str = "protocol-server";

/// Writes the script into the seed corpus of the target, see the transport's
/// seeder.
pub fn seed(target: &str, steps: &[Step]) {
    crate::transport::mock::seed::seed(target, steps);
}

impl Seedable for Step {
    fn seed(&self, seed: &mut Seed) {
        const COUNT: u32 = 22;
        match self {
            Step::Request(tag) => {
                seed.variant(0, COUNT);
                seed.byte(*tag);
            }
            Step::Bulk(tag) => {
                seed.variant(1, COUNT);
                seed.byte(*tag);
            }
            Step::Oversized => seed.variant(2, COUNT),
            Step::Wait(tag) => {
                seed.variant(3, COUNT);
                seed.byte(*tag);
            }
            Step::Forget(tag) => {
                seed.variant(4, COUNT);
                seed.byte(*tag);
            }
            Step::Close => seed.variant(5, COUNT),
            Step::Answer(tag) => {
                seed.variant(6, COUNT);
                seed.byte(*tag);
            }
            Step::Fail(tag) => {
                seed.variant(7, COUNT);
                seed.byte(*tag);
            }
            Step::Stray => seed.variant(8, COUNT),
            Step::Void => seed.variant(9, COUNT),
            Step::Junk => seed.variant(10, COUNT),
            Step::Ask(tag) => {
                seed.variant(11, COUNT);
                seed.byte(*tag);
            }
            Step::AskVoid => seed.variant(12, COUNT),
            Step::Flood => seed.variant(13, COUNT),
            Step::Reply => seed.variant(14, COUNT),
            Step::Refuse => seed.variant(15, COUNT),
            Step::Ignore => seed.variant(16, COUNT),
            Step::Bloat => seed.variant(17, COUNT),
            Step::Reset => seed.variant(18, COUNT),
            Step::Unplug => seed.variant(19, COUNT),
            Step::Break => seed.variant(20, COUNT),
            Step::Heal => seed.variant(21, COUNT),
        }
    }
}
