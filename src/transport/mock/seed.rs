// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Encodes scenario scripts as seeds for the fuzzers' `Arbitrary` decoders.
//! When `WIRE_SEEDS` names a directory, each scenario run writes its script
//! into the corresponding target's seed corpus.

use super::{CutPoint, client, duplex, server};
use arbitrary::{Arbitrary, Unstructured};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Environment variable naming the directory the seeds are written into.
pub const ENV: &str = "WIRE_SEEDS";

/// Target that drives the real server with mock client scripts.
/// Must match its binary name in fuzz/Cargo.toml; `make fuzz-seeds` checks that
/// every binary has seeds.
pub const TRANSPORT_SERVER: &str = "transport-server";

/// Target that drives the real client with mock server scripts.
/// Must match its binary name in fuzz/Cargo.toml; `make fuzz-seeds` checks that
/// every binary has seeds.
pub const TRANSPORT_CLIENT: &str = "transport-client";

/// Fuzz target running real peers over bounded duplex pipes, with concurrent
/// reconnects and operation deadlines. Each scenario seeds one complete run.
pub const TRANSPORT_DUPLEX: &str = "transport-duplex";

/// Encodes scripts in the format decoded by arbitrary 1.4.
/// Integers use little-endian order. Each vector element starts with a
/// continuation byte. Enum selection scales a u32 by the variant count and
/// uses the upper 32 bits of the product as the variant index.
pub struct Seed(Vec<u8>);

impl Seed {
    /// Encodes a zero-based variant index from an enum with `count` variants.
    pub fn variant(&mut self, index: u32, count: u32) {
        let pick = (u64::from(index) << 32).div_ceil(u64::from(count)) as u32;
        self.0.extend_from_slice(&pick.to_le_bytes());
    }

    /// Appends an eight-bit integer in the form `Arbitrary` reads it.
    pub fn byte(&mut self, byte: u8) {
        self.0.push(byte);
    }

    /// Appends a sixteen-bit integer in little-endian order.
    pub fn word(&mut self, word: u16) {
        self.0.extend_from_slice(&word.to_le_bytes());
    }

    /// Appends a boolean as zero or one, also used for vector continuation.
    pub fn flag(&mut self, flag: bool) {
        self.0.push(flag as u8);
    }

    /// Encodes a byte vector with a continuation flag before each element and
    /// a final false flag terminating the vector.
    pub fn bytes(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.flag(true);
            self.byte(byte);
        }
        self.flag(false);
    }
}

/// A scenario or step that can encode itself for the fuzzers.
pub trait Seedable: for<'a> Arbitrary<'a> + PartialEq + std::fmt::Debug {
    /// Appends this value's encoding so `Arbitrary` reconstructs the same step.
    fn seed(&self, seed: &mut Seed);
}

/// Writes a script under `WIRE_SEEDS/<target>`, if `WIRE_SEEDS` is set.
/// First checks that the encoded bytes decode back into the same script.
/// A content hash names the file, so an unchanged script keeps the same path.
pub fn seed<S: Seedable>(target: &str, steps: &[S]) {
    write(target, || {
        let mut seed = Seed(Vec::new());
        for step in steps {
            seed.flag(true);
            step.seed(&mut seed);
        }
        seed.flag(false);

        let decoded = Vec::<S>::arbitrary_take_rest(Unstructured::new(&seed.0))
            .expect("seed failed to decode");
        assert_eq!(decoded, steps, "seed decoded into another script");
        seed.0
    });
}

/// Encodes and writes one corpus input only when `WIRE_SEEDS` is set.
pub fn write(target: &str, encode: impl FnOnce() -> Vec<u8>) {
    let Some(root) = std::env::var_os(ENV) else {
        return;
    };
    let bytes = encode();
    let dir = Path::new(&root).join(target);
    std::fs::create_dir_all(&dir).expect("failed to create the seed directory");
    let name: String = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    std::fs::write(dir.join(name), bytes).expect("failed to write the seed");
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

impl Seedable for duplex::Scenario {
    fn seed(&self, seed: &mut Seed) {
        use duplex::Scenario;

        const COUNT: u32 = 10;
        match self {
            Scenario::FailedPrelude { read } => {
                seed.variant(0, COUNT);
                seed.flag(*read);
            }
            Scenario::HandshakeFailure {
                ack,
                flush,
                timeout,
            } => {
                seed.variant(1, COUNT);
                seed.flag(*ack);
                seed.flag(*flush);
                seed.flag(*timeout);
            }
            Scenario::RepeatedAttempts(count) => {
                seed.variant(2, COUNT);
                seed.byte(*count);
            }
            Scenario::AbandonedHello => seed.variant(3, COUNT),
            Scenario::SilentHandshake { ack } => {
                seed.variant(4, COUNT);
                seed.flag(*ack);
            }
            Scenario::HandshakeNoise { server } => {
                seed.variant(5, COUNT);
                seed.flag(*server);
            }
            Scenario::Reconnect { both_directions } => {
                seed.variant(6, COUNT);
                seed.flag(*both_directions);
            }
            Scenario::Backlog(count) => {
                seed.variant(7, COUNT);
                seed.byte(*count);
            }
            Scenario::ServerTimeout { flush } => {
                seed.variant(8, COUNT);
                seed.flag(*flush);
            }
            Scenario::Shutdown { handshake, server } => {
                seed.variant(9, COUNT);
                seed.flag(*handshake);
                seed.flag(*server);
            }
        }
    }
}

impl Seedable for client::Step {
    fn seed(&self, seed: &mut Seed) {
        use client::Step;

        const COUNT: u32 = 34;
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
            Step::Retain => seed.variant(20, COUNT),
            Step::Send(tag) => {
                seed.variant(21, COUNT);
                seed.byte(*tag);
            }
            Step::SendRetained(tag) => {
                seed.variant(22, COUNT);
                seed.byte(*tag);
            }
            Step::SendOversized => seed.variant(23, COUNT),
            Step::Disconnect => seed.variant(24, COUNT),
            Step::Chunk(n) => {
                seed.variant(25, COUNT);
                seed.byte(*n);
            }
            Step::Batch(n) => {
                seed.variant(26, COUNT);
                seed.byte(*n);
            }
            Step::Yield => seed.variant(27, COUNT),
            Step::Interrupt => seed.variant(28, COUNT),
            Step::ReadTimeout => seed.variant(29, COUNT),
            Step::Break => seed.variant(30, COUNT),
            Step::Heal => seed.variant(31, COUNT),
            Step::Cut { point, then_broken } => {
                seed.variant(32, COUNT);
                point.seed(seed);
                seed.flag(*then_broken);
            }
            Step::Timeout(point) => {
                seed.variant(33, COUNT);
                point.seed(seed);
            }
        }
    }
}

impl Seedable for server::Step {
    fn seed(&self, seed: &mut Seed) {
        use server::Step;

        const COUNT: u32 = 34;
        match self {
            Step::Handshake => seed.variant(0, COUNT),
            Step::Send(tag) => {
                seed.variant(1, COUNT);
                seed.byte(*tag);
            }
            Step::SendOversized => seed.variant(2, COUNT),
            Step::Recv => seed.variant(3, COUNT),
            Step::Retain => seed.variant(4, COUNT),
            Step::SendRetained(tag) => {
                seed.variant(5, COUNT);
                seed.byte(*tag);
            }
            Step::Hello => seed.variant(6, COUNT),
            Step::HelloStale => seed.variant(7, COUNT),
            Step::HelloTampered => seed.variant(8, COUNT),
            Step::HelloBadAuth => seed.variant(9, COUNT),
            Step::HelloBadSigner => seed.variant(10, COUNT),
            Step::HelloBadPayload => seed.variant(11, COUNT),
            Step::HelloBadKey => seed.variant(12, COUNT),
            Step::HelloBadEncap => seed.variant(13, COUNT),
            Step::HelloBadAttest => seed.variant(14, COUNT),
            Step::Reply(tag) => {
                seed.variant(15, COUNT);
                seed.byte(*tag);
            }
            Step::ReplyReplay => seed.variant(16, COUNT),
            Step::ReplyTampered => seed.variant(17, COUNT),
            Step::Garbage => seed.variant(18, COUNT),
            Step::Dropped => seed.variant(19, COUNT),
            Step::Junk(bytes) => {
                seed.variant(20, COUNT);
                seed.bytes(bytes);
            }
            Step::Undecodable => seed.variant(21, COUNT),
            Step::Truncated(n) => {
                seed.variant(22, COUNT);
                seed.byte(*n);
            }
            Step::Partial => seed.variant(23, COUNT),
            Step::Oversized => seed.variant(24, COUNT),
            Step::Chunk(n) => {
                seed.variant(25, COUNT);
                seed.byte(*n);
            }
            Step::Batch(n) => {
                seed.variant(26, COUNT);
                seed.byte(*n);
            }
            Step::Yield => seed.variant(27, COUNT),
            Step::Interrupt => seed.variant(28, COUNT),
            Step::ReadTimeout => seed.variant(29, COUNT),
            Step::Break => seed.variant(30, COUNT),
            Step::Heal => seed.variant(31, COUNT),
            Step::Cut { point, then_broken } => {
                seed.variant(32, COUNT);
                point.seed(seed);
                seed.flag(*then_broken);
            }
            Step::Timeout(point) => {
                seed.variant(33, COUNT);
                point.seed(seed);
            }
        }
    }
}
