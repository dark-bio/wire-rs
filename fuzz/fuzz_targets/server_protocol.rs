// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

#![no_main]

use darkbio_wire::mock::server::{Step, run};
use libfuzzer_sys::fuzz_target;

// Drives a real server side through an arbitrary sequence of client frames, the
// mock client checking every reaction against the protocol's state machine.
fuzz_target!(|steps: Vec<Step>| {
    run(&steps);
});
