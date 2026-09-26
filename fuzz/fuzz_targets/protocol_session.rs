// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Fuzz target checking real session APIs against a model of their results.
//!
//! The model predicts results using integer time, and the shared scenario
//! tester checks them against session fixtures. The runner bounds each input
//! and settles all promises, including the ones parked in a blocking wait. The
//! fixture has neither crypto nor a transport, so no randomness is drawn and
//! none needs reseeding.

#![no_main]

use darkbio_wire::protocol::mock::session::{Action, fuzz};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|actions: Vec<Action>| fuzz(&actions));
