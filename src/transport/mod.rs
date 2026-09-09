// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Encrypted sessions over a duplex byte stream. COBS framing separates packets,
//! the handshake establishes encryption contexts, and sealing protects messages.
//! Each client or server owns its receive context and shares its send context
//! with active sends. Sender handles allow other threads to send into that session.
//!
//! Adapters implement standard byte I/O plus the deadline setters in [`Read`]
//! and [`Write`]. Each outgoing frame has one configurable budget covering
//! partial writes and flush. A timeout ends that send or handshake without closing
//! the byte stream. Established-session reads wait for data or adapter shutdown,
//! with no session timeout. Handshakes use one configurable deadline on each side,
//! defaulting to five seconds. The client writes reset and hello before draining
//! stale replies, so adapters need enough available buffering to accept that output
//! without concurrent client reads. Backpressure may fail an attempt; the caller
//! can retry with a fresh reset.

use std::time::Duration;

mod client;
mod framing;
mod handshake;
mod io;
mod outbound;
mod sealing;
mod sender;
mod server;
mod stream;

#[cfg(any(test, feature = "fuzz"))]
#[doc(hidden)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod mock;

#[cfg(any(test, feature = "bench", feature = "fuzz"))]
#[doc(hidden)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod testing;

pub use client::{Client, Roots, Verifier};
pub use io::{Read, Write};
pub use sender::Sender;
pub use server::{Attestation, Attester, Event, Server};
pub use stream::{Closer, Stream};

/// Stream writer for the protocol mock's real framing and reset notifications.
#[cfg(any(test, feature = "fuzz"))]
pub(crate) use outbound::{Outbound, Side};

/// Default budget for a handshake's output and peer replies. Configure it with
/// [`Client::set_handshake_timeout`] or [`Server::set_handshake_timeout`].
/// Progress, stale frames and resets within the attempt do not refresh it.
/// Writer-lock cleanup and caller callbacks may extend the call, but cannot
/// extend its I/O deadline.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Default budget for encoding, writing and flushing one complete transport frame.
/// Configure it with [`Stream::set_write_timeout`]. Progress does not refresh it.
/// The budget starts after acquiring the writer, excluding lock waits and
/// encryption. Handshake frames are also limited by the handshake deadline.
pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum encoded frame size, excluding its trailing delimiter. An oversized
/// incoming frame is a framing error that ends any active session. Its remainder
/// is discarded through its delimiter so the stream can carry a fresh handshake.
pub const MAX_FRAME_SIZE: usize = 2 * 1024 * 1024;

/// Conservative soft limit for outgoing message sizes, guaranteed to fit a frame after
/// sealing and worst-case COBS overhead.
///
/// The wire's hard limit is [`MAX_FRAME_SIZE`]; received messages may exceed
/// this value if their encoded frames fit. Sending uses this conservative bound
/// to reject oversized messages before sealing, without advancing the encryption
/// sequence.
pub const MAX_MESSAGE_SIZE: usize = {
    let mut size = MAX_FRAME_SIZE;
    while darkbio_cobs::encode_buffer(size + sealing::OVERHEAD) > MAX_FRAME_SIZE {
        size -= 1;
    }
    size
};

/// Domain separator for the handshake's COSE envelopes: ArkHello and HostAck.
/// HostHello is plain CBOR. The separator binds signatures and encryption to
/// this protocol, preventing their reuse in another protocol with the same key.
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
    /// A message exceeds the sending bound [`MAX_MESSAGE_SIZE`]. The size is
    /// the unencrypted message length. Refusal happens before sealing, leaving
    /// the session and its encryption sequence unchanged.
    #[error("wire packet too large: {0} bytes, max {MAX_MESSAGE_SIZE} bytes")]
    PacketTooLarge(usize),

    /// An encoded frame exceeds [`MAX_FRAME_SIZE`]. On receive, the size counts
    /// bytes observed so far; the full frame may be larger. On send, the size
    /// is the required worst-case COBS encoding buffer.
    /// Receiving an oversized frame ends any active session; its remainder is
    /// discarded through the delimiter before another frame can be read.
    #[error("wire frame too large: {0} bytes, max {MAX_FRAME_SIZE} bytes")]
    FrameTooLarge(usize),

    /// A delimited frame is not valid COBS. It may have carried an encrypted
    /// message, so skipping it ends any active session. A reconnecting client
    /// discards malformed stale frames while waiting for its fresh reply.
    #[error("wire frame decode failed: {0}")]
    FrameDecodingFailed(darkbio_cobs::DecodeError),

    /// Writing a frame failed, possibly while setting its deadline or flushing.
    /// [`std::io::ErrorKind::TimedOut`] means its output budget expired. The adapter
    /// may already have accepted part or all of the frame. The affected session
    /// or handshake cannot continue. This error does not close the byte stream.
    #[error("wire send failed: {0}")]
    SendFailed(std::io::Error),

    /// An adapter read or read deadline configuration failed. Idle read timeouts
    /// and interrupted reads are retried internally. Configuration failures are
    /// returned immediately, as is expiry of an overall handshake deadline.
    /// The client ends its session; the server leaves its binding in place so
    /// the caller can decide whether to retry or disconnect. Neither side closes
    /// the stream because of this error.
    #[error("wire receive failed: {0}")]
    RecvFailed(std::io::Error),

    /// Reading reached EOF or a sender's transport owner was already released.
    /// Local closure also produces EOF once buffered frames have been consumed.
    /// This does not guarantee that a concurrent shutdown has finished.
    #[error("wire terminated")]
    Terminated,

    /// The client received the server's empty frame notification and ended its
    /// session. This does not close the stream. The client can reconnect to
    /// establish another session. Servers report resets through events instead.
    #[error("wire session reset by the peer")]
    SessionReset,

    /// The presented CWT could not be decoded as hardware or emulator claims.
    /// This checks the token's shape. The client's verifier decides whether to
    /// trust a well-formed attestation.
    #[error("attestation is not for a hardware or emulator")]
    InvalidAttestation,

    /// A handshake message could not be constructed, decoded or authenticated,
    /// or the client's verifier rejected the attestation. No new session is
    /// established by this attempt. The error does not close the byte stream.
    #[error("wire handshake failed: {0}")]
    HandshakeFailed(String),

    /// A received packet could not be decrypted, or a send or receive no longer
    /// has a usable session. Invalid incoming packets end the session. Refusing
    /// an obsolete sender leaves any replacement session unaffected.
    #[error("wire encryption failed: {0}")]
    EncryptionFailed(String),
}
