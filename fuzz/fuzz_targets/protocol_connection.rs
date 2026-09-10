// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

#![no_main]

use darkbio_wire::protocol::mock::connection::{Action, Kind, fuzz};
use libfuzzer_sys::fuzz_target;

// Shared connection scenarios drive real protocol workers and encrypted streams.
// Randomness is repeatable; native worker scheduling still varies interleavings.
fuzz_target!(
    // Initialize crypto and worker state before libFuzzer measures input coverage.
    init: {
        fuzz(&[
            Action { kind: Kind::Pipeline, slot: 0, value: 1, budget: 1 },
            Action { kind: Kind::Incoming, slot: 0, value: 2, budget: 0 },
            Action { kind: Kind::Replace, slot: 0, value: 3, budget: 0 },
        ]);
    },
    |actions: Vec<Action>| {
        #[cfg(getrandom_backend = "custom")]
        darkbio_wire::transport::mock::random::reseed("protocol-fuzz");

        fuzz(&actions);
    }
);
