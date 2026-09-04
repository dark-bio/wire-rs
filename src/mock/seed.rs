// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Seeds for the fuzzers, the scripts of the scenario tests written out as
//! the fuzzers' `Arbitrary` decoding reads them. Every scenario run writes
//! its script into the corpus of the target reading such scripts, when the
//! WIRE_SEEDS environment variable names the directory to write into.

use super::{CutPoint, client, server};
use arbitrary::{Arbitrary, Unstructured};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Environment variable naming the directory the seeds are written into.
pub const ENV: &str = "WIRE_SEEDS";

/// Fuzz target driving the real server through the mock client's scripts,
/// which seed its corpus. Keep it in step with the binary in fuzz/Cargo.toml,
/// the fuzz-seeds make target checks that every target listed there gets
/// seeds.
pub const SERVER_PROTOCOL: &str = "server-protocol";

/// Fuzz target driving the real client through the mock server's scripts,
/// which seed its corpus. Keep it in step with the binary in fuzz/Cargo.toml,
/// the fuzz-seeds make target checks that every target listed there gets
/// seeds.
pub const CLIENT_PROTOCOL: &str = "client-protocol";

/// Encoder for the byte stream the fuzzers' `Arbitrary` decoding reads a
/// script from. It mirrors arbitrary 1.4, integers little endian, a keep-going
/// byte ahead of every vector element and an enum variant picked as the high
/// half of a u32 scaled by the variant count.
pub struct Seed(Vec<u8>);

impl Seed {
    /// Picks the variant with the index out of the count.
    pub fn variant(&mut self, index: u32, count: u32) {
        let pick = (u64::from(index) << 32).div_ceil(u64::from(count)) as u32;
        self.0.extend_from_slice(&pick.to_le_bytes());
    }

    pub fn byte(&mut self, byte: u8) {
        self.0.push(byte);
    }

    pub fn word(&mut self, word: u16) {
        self.0.extend_from_slice(&word.to_le_bytes());
    }

    pub fn flag(&mut self, flag: bool) {
        self.0.push(flag as u8);
    }

    pub fn bytes(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.flag(true);
            self.byte(byte);
        }
        self.flag(false);
    }
}

/// A step able to write itself as the fuzzers read it.
pub trait Seedable: for<'a> Arbitrary<'a> + PartialEq + std::fmt::Debug {
    fn seed(&self, seed: &mut Seed);
}

/// Writes the script into the seed corpus of the target, under the directory
/// the WIRE_SEEDS environment variable names, checking that the bytes decode
/// back into the same script. The file is named by the hash of its content,
/// so regenerating leaves an unchanged script untouched. Without the variable
/// set nothing happens.
pub fn seed<S: Seedable>(target: &str, steps: &[S]) {
    let Some(root) = std::env::var_os(ENV) else {
        return;
    };
    let mut seed = Seed(Vec::new());
    for step in steps {
        seed.flag(true);
        step.seed(&mut seed);
    }
    seed.flag(false);

    let decoded =
        Vec::<S>::arbitrary_take_rest(Unstructured::new(&seed.0)).expect("seed failed to decode");
    assert_eq!(decoded, steps, "seed decoded into another script");

    let dir = Path::new(&root).join(target);
    std::fs::create_dir_all(&dir).expect("failed to create the seed directory");
    let name: String = Sha256::digest(&seed.0)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    std::fs::write(dir.join(name), &seed.0).expect("failed to write the seed");
}

impl Seedable for CutPoint {
    fn seed(&self, seed: &mut Seed) {
        match self {
            CutPoint::Start => seed.variant(0, 4),
            CutPoint::Middle(n) => {
                seed.variant(1, 4);
                seed.word(*n);
            }
            CutPoint::Delimiter => seed.variant(2, 4),
            CutPoint::Flush => seed.variant(3, 4),
        }
    }
}

impl Seedable for client::Step {
    fn seed(&self, seed: &mut Seed) {
        use client::Step;

        const COUNT: u32 = 27;
        match self {
            Step::Reset => seed.variant(0, COUNT),
            Step::ResetPair => seed.variant(1, COUNT),
            Step::Hello => seed.variant(2, COUNT),
            Step::HelloReplay => seed.variant(3, COUNT),
            Step::HelloBadKey => seed.variant(4, COUNT),
            Step::Ack => seed.variant(5, COUNT),
            Step::AckReplay => seed.variant(6, COUNT),
            Step::AckTampered => seed.variant(7, COUNT),
            Step::AckBadAuth => seed.variant(8, COUNT),
            Step::AckBadSigner => seed.variant(9, COUNT),
            Step::AckBadPayload => seed.variant(10, COUNT),
            Step::AckBadEncap => seed.variant(11, COUNT),
            Step::Request(tag) => {
                seed.variant(12, COUNT);
                seed.byte(*tag);
            }
            Step::RequestReplay => seed.variant(13, COUNT),
            Step::RequestTampered => seed.variant(14, COUNT),
            Step::Garbage => seed.variant(15, COUNT),
            Step::Junk(bytes) => {
                seed.variant(16, COUNT);
                seed.bytes(bytes);
            }
            Step::Truncated(n) => {
                seed.variant(17, COUNT);
                seed.byte(*n);
            }
            Step::Partial => seed.variant(18, COUNT),
            Step::Oversized => seed.variant(19, COUNT),
            Step::Yield => seed.variant(20, COUNT),
            Step::Interrupt => seed.variant(21, COUNT),
            Step::Break => seed.variant(22, COUNT),
            Step::Heal => seed.variant(23, COUNT),
            Step::Cut { point, then_broken } => {
                seed.variant(24, COUNT);
                point.seed(seed);
                seed.flag(*then_broken);
            }
            Step::Chunk(n) => {
                seed.variant(25, COUNT);
                seed.byte(*n);
            }
            Step::Batch(n) => {
                seed.variant(26, COUNT);
                seed.byte(*n);
            }
        }
    }
}

impl Seedable for server::Step {
    fn seed(&self, seed: &mut Seed) {
        use server::Step;

        const COUNT: u32 = 29;
        match self {
            Step::Handshake => seed.variant(0, COUNT),
            Step::Send(tag) => {
                seed.variant(1, COUNT);
                seed.byte(*tag);
            }
            Step::Recv => seed.variant(2, COUNT),
            Step::Hello => seed.variant(3, COUNT),
            Step::HelloStale => seed.variant(4, COUNT),
            Step::HelloTampered => seed.variant(5, COUNT),
            Step::HelloBadAuth => seed.variant(6, COUNT),
            Step::HelloBadSigner => seed.variant(7, COUNT),
            Step::HelloBadPayload => seed.variant(8, COUNT),
            Step::HelloBadKey => seed.variant(9, COUNT),
            Step::HelloBadEncap => seed.variant(10, COUNT),
            Step::HelloBadAttest => seed.variant(11, COUNT),
            Step::Reply(tag) => {
                seed.variant(12, COUNT);
                seed.byte(*tag);
            }
            Step::ReplyReplay => seed.variant(13, COUNT),
            Step::ReplyTampered => seed.variant(14, COUNT),
            Step::Garbage => seed.variant(15, COUNT),
            Step::Dropped => seed.variant(16, COUNT),
            Step::Junk(bytes) => {
                seed.variant(17, COUNT);
                seed.bytes(bytes);
            }
            Step::Undecodable => seed.variant(18, COUNT),
            Step::Truncated(n) => {
                seed.variant(19, COUNT);
                seed.byte(*n);
            }
            Step::Partial => seed.variant(20, COUNT),
            Step::Oversized => seed.variant(21, COUNT),
            Step::Yield => seed.variant(22, COUNT),
            Step::Interrupt => seed.variant(23, COUNT),
            Step::Break => seed.variant(24, COUNT),
            Step::Heal => seed.variant(25, COUNT),
            Step::Cut { point, then_broken } => {
                seed.variant(26, COUNT);
                point.seed(seed);
                seed.flag(*then_broken);
            }
            Step::Chunk(n) => {
                seed.variant(27, COUNT);
                seed.byte(*n);
            }
            Step::Batch(n) => {
                seed.variant(28, COUNT);
                seed.byte(*n);
            }
        }
    }
}
