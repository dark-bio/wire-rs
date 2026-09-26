// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Fuzz target decoding raw envelopes, one direction byte followed by protobuf.
//!
//! Envelopes are the only protocol surface parsing peer bytes, so the target
//! checks them without sessions or streams. Every accepted body must re-encode
//! in the direction it arrived from, unless it exceeds the sending limit.

#![no_main]

use darkbio_wire::protocol::mock::envelope::run;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    run(input);
});
