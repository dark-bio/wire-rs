// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Protocol spoken over the transport, the protobuf messages generated from
//! `proto/wire.proto` at build time and the conventions of their envelopes.

mod envelope;

pub use envelope::{Envelope, Ids, Kind, Parity};
pub use generated::*;

/// The generated bindings, kept out of the lints the crate holds itself to.
#[allow(clippy::all)]
#[allow(rustdoc::broken_intra_doc_links)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/darkbio.wire.rs"));
}
