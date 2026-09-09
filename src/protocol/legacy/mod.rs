// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Previous callback-based protocol implementation, retained during the rewrite.
//! Its behavior and tests remain independent of the new session API.

pub mod mux;
mod switchboard;

#[cfg(any(test, feature = "fuzz"))]
#[doc(hidden)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod mock;

pub use mux::{Client, Error, Mux, Pending, Reader, Responder, Server, Writer};
