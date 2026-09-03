// wire-rs: encrypted protocol between Ark and host
// Copyright 2025 Dark Bio AG. All rights reserved.

// Allow excluding test code from coverage measurements on nightly
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
// Pull in the README as the package doc
#![doc = include_str!("../README.md")]

pub mod protocol;

mod framing;
mod handshake;
mod session;
mod side_ark;
mod side_host;

#[cfg(any(test, feature = "fuzz"))]
#[doc(hidden)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod scripted;

pub use protocol::{ArkToHost, HostToArk};
pub use side_ark::{ArkSide, Attestation, Attester};
pub use side_host::{HostSide, Roots, Verifier};

use std::io;

/// Maximum limit for a frame size, above which it will be discarded from the
/// wire protocol.
pub const MAX_FRAME_SIZE: usize = 2 * 1024 * 1024;

/// Largest protobuf message the wire carries, being what still fits a frame
/// after the session's sealing and the COBS framing overheads are added.
pub const MAX_MESSAGE_SIZE: usize = {
    let mut size = MAX_FRAME_SIZE;
    while darkbio_cobs::encode_buffer(size + session::Session::SEAL_OVERHEAD) > MAX_FRAME_SIZE {
        size -= 1;
    }
    size
};

/// Domain separator for the COSE envelopes of the handshake, sealing the Ark's
/// hello and the host's ack (the host's hello is plain CBOR). It binds their
/// signatures and encryption to the wire, so a handshake signed by the Ark's
/// identity key cannot be replayed into other protocols using the same key.
pub(crate) const CRYPTO_DOMAIN_WIRE: &[u8] = b"wire-v1";

/// HPKE info string for the ark-to-host encryption context of an established
/// session (message traffic after the handshake, not the handshake itself).
pub(crate) const CRYPTO_DOMAIN_WIRE_ARK_TO_HOST: &[u8] = b"wire-v1:ark-to-host";

/// HPKE info string for the host-to-ark encryption context of an established
/// session (message traffic after the handshake, not the handshake itself).
pub(crate) const CRYPTO_DOMAIN_WIRE_HOST_TO_ARK: &[u8] = b"wire-v1:host-to-ark";

/// Things that can go wrong in the wire transport.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("wire packet too large: {0} bytes, max {MAX_MESSAGE_SIZE} bytes")]
    PacketTooLarge(usize),

    #[error("wire packet encode failed: {0}")]
    PacketEncodingFailed(prost::EncodeError),

    #[error("wire packet decode failed: {0}")]
    PacketDecodingFailed(prost::DecodeError),

    #[error("wire frame too large: {0} bytes, max {MAX_FRAME_SIZE} bytes")]
    FrameTooLarge(usize),

    #[error("wire frame decode failed: {0}")]
    FrameDecodingFailed(darkbio_cobs::DecodeError),

    #[error("wire send failed: {0}")]
    SendFailed(io::Error),

    #[error("wire receive failed: {0}")]
    RecvFailed(io::Error),

    #[error("wire terminated")]
    Terminated,

    #[error("wire session reset by the ark")]
    SessionReset,

    #[error("attestation is not for a hardware or emulator")]
    InvalidAttestation,

    #[error("wire handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("wire encryption failed: {0}")]
    EncryptionFailed(String),
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod testing {
    use std::sync::Once;

    static INIT: Once = Once::new();

    // init_tracing sets up a test logger to push log messages to stderr.
    pub fn init_tracing() {
        INIT.call_once(|| {
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::from_default_env()
                        .add_directive(tracing::Level::TRACE.into()),
                )
                .with_ansi(true)
                .with_test_writer()
                .init();
        });
    }
}
