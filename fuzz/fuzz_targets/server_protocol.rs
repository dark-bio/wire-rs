// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

#![no_main]

use darkbio_wire::mock::server::{Step, run};
use libfuzzer_sys::fuzz_target;

// Drives a real server side through an arbitrary sequence of client frames, the
// mock client checking every reaction against the protocol's state machine.
fuzz_target!(
    // Warm up the process on a script touching every layer, so one-time
    // initialization is not attributed to whichever input runs first
    init: {
        run(&[
            Step::Handshake,
            Step::Hello,
            Step::Send(1),
            Step::Reply(1),
            Step::Recv,
            Step::Junk(vec![1]),
            Step::Recv,
            Step::Handshake,
            Step::Hello,
        ]);
    },
    |steps: Vec<Step>| {
        // Restart the randomness from the same seed for every input, so an
        // input covers the same features on every execution
        #[cfg(getrandom_backend = "custom")]
        darkbio_wire::mock::random::reseed("fuzz");

        run(&steps);
    }
);
