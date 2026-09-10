// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

#![no_main]

use darkbio_wire::protocol::mock::envelope::run;
use libfuzzer_sys::fuzz_target;

// Envelopes are the only protocol surface parsing peer bytes, so this target
// checks one direction byte followed by raw protobuf, without sessions or streams.
// Every accepted body must re-encode in the direction it arrived from.
fuzz_target!(|input: &[u8]| {
    run(input);
});
