// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Scripted scenarios for requests, replies, closing and replacing sessions.
//!
//! Session and connection fixtures execute explicit steps. Their `fuzz` modules
//! turn arbitrary actions into those steps, with regression scripts in neighboring
//! `tests` modules. The envelope runner checks peer bytes directly.
//!
//! With `WIRE_SEEDS` set, the runners record each scenario through the encoders
//! in `seed.rs`. `make fuzz-seeds` runs the tests to regenerate `fuzz/seeds`.

pub mod connection;
pub mod envelope;
#[cfg(feature = "fuzz")]
pub mod seed;
pub mod session;
