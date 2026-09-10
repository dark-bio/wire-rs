// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

#![no_main]

use darkbio_wire::transport::mock::duplex::{Scenario, run};
use libfuzzer_sys::fuzz_target;

// Exercises two real transport peers with bounded buffers and actual deadline
// expiration. Each scenario checks progress, error attribution and stream reuse;
// the native scheduler varies the interleaving on repeated executions.
fuzz_target!(|scenarios: Vec<Scenario>| {
    #[cfg(getrandom_backend = "custom")]
    darkbio_wire::transport::mock::random::reseed("duplex-fuzz");

    // Deadline cases intentionally wait, so bound the work in each fuzz input.
    for scenario in scenarios.into_iter().take(2) {
        run(scenario);
    }
});
