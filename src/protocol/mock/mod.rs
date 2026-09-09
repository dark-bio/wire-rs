// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Scripted scenarios for requests, replies, closing and replacing sessions.
//! Each runner keeps its regression scripts in a neighboring tests module.

pub mod connection;
pub mod envelope;
pub mod session;

/// Target driving session lifecycles against a model on an integer clock.
/// Must match its binary name in fuzz/Cargo.toml; `make fuzz-seeds` checks that
/// every binary has seeds.
pub const SESSION_TARGET: &str = "protocol-session";

/// Target composing protocol exchanges over live encrypted connections.
/// Must match its binary name in fuzz/Cargo.toml; `make fuzz-seeds` checks that
/// every binary has seeds.
pub const CONNECTION_TARGET: &str = "protocol-connection";

/// Target decoding arbitrary peer envelopes and re-encoding what it accepted.
/// Must match its binary name in fuzz/Cargo.toml; `make fuzz-seeds` checks that
/// every binary has seeds.
pub const ENVELOPE_TARGET: &str = "protocol-envelope";
