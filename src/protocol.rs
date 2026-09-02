// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Protobuf messages, generated from `proto/wire.proto` at build time.

#![allow(clippy::all)]

include!(concat!(env!("OUT_DIR"), "/darkbio.wire.rs"));
