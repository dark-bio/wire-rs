// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Transport of the wire, sessions over a byte stream. The framing delimits
//! packets with COBS, the handshake establishes a session's contexts, the
//! sealing encrypts the messages within it, and the client and the server
//! drive it from either end. The client/server owns the receive context directly
//! and shares the sending context with active sends. Senders bind that context
//! to the stream writer for sending messages from any thread.

mod client;
mod framing;
mod handshake;
mod outbound;
mod sealing;
mod sender;
mod server;
mod stream;

#[cfg(any(test, feature = "fuzz"))]
#[doc(hidden)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod mock;

pub use client::{Client, Roots, Verifier};
pub use sender::Sender;
pub use server::{Attestation, Attester, Event, Server};
pub use stream::{Closer, Stream};

/// Stream writer for the protocol mock's real framing and reset notifications.
#[cfg(any(test, feature = "fuzz"))]
pub(crate) use outbound::{Outbound, Side};

use std::io;

/// Maximum encoded frame size, excluding its trailing delimiter. An oversized
/// incoming frame is a framing error that ends any active session. Its remainder
/// is discarded through its delimiter so the stream can carry a fresh handshake.
pub const MAX_FRAME_SIZE: usize = 2 * 1024 * 1024;

/// Conservative soft limit for message sizes, guaranteed to fit a frame after
/// sealing and worst-case COBS overhead.
///
/// The wire's hard limit is [`MAX_FRAME_SIZE`]; received messages may exceed
/// this value if their encoded frames fit. [`Sender::send`] currently uses
/// this conservative bound to reject oversized messages before sealing, without
/// advancing the encryption sequence.
pub const MAX_MESSAGE_SIZE: usize = {
    let mut size = MAX_FRAME_SIZE;
    while darkbio_cobs::encode_buffer(size + sealing::OVERHEAD) > MAX_FRAME_SIZE {
        size -= 1;
    }
    size
};

/// Domain separator for the COSE envelopes of the handshake, sealing the server's
/// hello and the client's ack (the client's hello is plain CBOR). It binds their
/// signatures and encryption to the wire, so a handshake signed by the server's
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
// The mocks name the variants in their transcripts
#[cfg_attr(
    all(any(test, feature = "fuzz"), not(docsrs)),
    derive(strum::IntoStaticStr)
)]
pub enum Error {
    #[error("wire packet too large: {0} bytes, max {MAX_MESSAGE_SIZE} bytes")]
    PacketTooLarge(usize),

    /// The frame size check exceeded [`MAX_FRAME_SIZE`]. On receive, the size
    /// is the bytes observed when the limit was crossed, a lower bound on the
    /// full frame length. On send, it is the required COBS encoding buffer size.
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

    #[error("wire session reset by the peer")]
    SessionReset,

    #[error("attestation is not for a hardware or emulator")]
    InvalidAttestation,

    #[error("wire handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("wire encryption failed: {0}")]
    EncryptionFailed(String),
}
