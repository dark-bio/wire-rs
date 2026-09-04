// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

#![no_main]

use darkbio_wire::mock::client::{Step, run};
use libfuzzer_sys::fuzz_target;

// Drives a real client side through an arbitrary interleaving of its own calls
// and server frames, the mock server checking every result against the
// protocol's state machine.
fuzz_target!(|steps: Vec<Step>| {
    run(&steps);
});
