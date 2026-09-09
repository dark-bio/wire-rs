// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

#![no_main]

use darkbio_wire::protocol::mock::connection::{Action, fuzz};
use libfuzzer_sys::fuzz_target;

// Shared connection scenarios drive real protocol workers and encrypted streams.
// Randomness is repeatable; native worker scheduling still varies interleavings.
fuzz_target!(|actions: Vec<Action>| {
    #[cfg(getrandom_backend = "custom")]
    darkbio_wire::mock::random::reseed("protocol-fuzz");

    fuzz(&actions);
});
