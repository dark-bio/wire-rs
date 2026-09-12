// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#![no_main]

use darkbio_wire::transport::mock::client::{Step, run};
use libfuzzer_sys::fuzz_target;

// Drives a real server side through an arbitrary sequence of client frames, the
// mock client checking every reaction against the protocol's state machine.
fuzz_target!(
    // Warm up the process on a script touching every layer, so one-time
    // initialization is not attributed to whichever input runs first
    init: {
        run(&[
            Step::Reset,
            Step::Hello,
            Step::Ack,
            Step::Request(1),
            Step::Junk(vec![1]),
            Step::Reset,
            Step::Hello,
            Step::Ack,
        ]);
    },
    |steps: Vec<Step>| {
        // Restart the randomness from the same seed for every input, so an
        // input covers the same features on every execution
        #[cfg(getrandom_backend = "custom")]
        darkbio_wire::transport::mock::random::reseed("fuzz");

        run(&steps);
    }
);
