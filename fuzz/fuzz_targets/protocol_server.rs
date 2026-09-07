// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

#![no_main]

use darkbio_wire::protocol::mock::peer::{Step, run_server};
use libfuzzer_sys::fuzz_target;

// Drives a real server multiplexer through an arbitrary interleaving of its
// own calls and peer messages, the mock peer checking every result against
// the protocol's state machine.
fuzz_target!(
    // Warm up the process on a script touching every layer, so one-time
    // initialization is not attributed to whichever input runs first
    init: {
        run_server(&[
            Step::Reset,
            Step::Stray,
            Step::Request(1),
            Step::Answer(1),
            Step::Wait(1),
            Step::Ask(2),
            Step::Reply,
            Step::Junk,
        ]);
    },
    |steps: Vec<Step>| {
        // Restart the randomness from the same seed for every input, so an
        // input covers the same features on every execution
        #[cfg(getrandom_backend = "custom")]
        darkbio_wire::mock::random::reseed("fuzz");

        run_server(&steps);
    }
);
