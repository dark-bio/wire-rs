// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Fuzz target running two real transport peers over bounded buffers, with
//! clock-driven deadline expiration.
//!
//! Each scenario checks progress, error attribution and stream reuse, while
//! the native scheduler varies the interleaving on repeated executions.

#![no_main]

use darkbio_wire::transport::mock::duplex::{Scenario, run};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|scenarios: Vec<Scenario>| {
    // Restart the randomness from the same seed for every input
    #[cfg(getrandom_backend = "custom")]
    darkbio_wire::transport::mock::random::reseed("duplex-fuzz");

    // Bound the number of crypto handshakes performed by each input
    for scenario in scenarios.into_iter().take(2) {
        run(scenario);
    }
});
