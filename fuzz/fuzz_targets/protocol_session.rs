// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

#![no_main]

use darkbio_wire::protocol::mock::session::{Action, fuzz};
use libfuzzer_sys::fuzz_target;

// The model predicts results using integer time, then the shared scenario tester
// checks real session APIs. The runner bounds each input and settles all promises,
// including the ones parked in a blocking wait. The fixture has neither crypto nor
// a transport, so no randomness is drawn and none needs reseeding.
fuzz_target!(|actions: Vec<Action>| fuzz(&actions));
