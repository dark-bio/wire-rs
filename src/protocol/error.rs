// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Errors returned by protocol methods and promises.

use super::{RemoteError, ReservedErrors};
use crate::transport;
use std::convert::Infallible;
use std::sync::Arc;

/// Failure of a protocol operation. A remote application's error is carried by
/// [`Error::Remote`]; it does not by itself end the session.
#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    /// The session or server was closed locally, including by dropping its owner.
    #[error("wire protocol closed")]
    Closed,

    /// The operation's absolute deadline expired. Remote work may still run.
    #[error("wire operation timed out")]
    Timeout,

    /// The underlying transport failed or the peer reset the session.
    #[error("wire transport failed: {0}")]
    Transport(#[from] Arc<transport::Error>),

    /// The peer returned an application error for this request.
    #[error("wire peer failed the request, code {}: {}", .0.code, .0.msg)]
    Remote(RemoteError),

    /// The response's `Message` variant does not match the type requested by
    /// `Promise::wait()`. This does not end the session.
    #[error("wire response type mismatch: expected {expected}, received {received}")]
    UnexpectedResponse {
        /// Expected protobuf message type.
        expected: &'static str,
        /// Received protobuf message type.
        received: &'static str,
    },

    /// The submitted message cannot be sent from this session's side. Reported
    /// through the request or reply promise; this error does not end the session.
    #[error("wire message cannot be sent in this direction: {0}")]
    WrongDirection(&'static str),

    /// The encoded message exceeds the transport's sending limit.
    #[error("wire message too large: {0} bytes")]
    TooLarge(usize),

    /// The peer sent an invalid envelope or payload. The session closes when this
    /// is detected. Nested payloads are checked only when `recv()` or `wait()`
    /// reads them.
    #[error("wire peer sent a malformed message")]
    Malformed,

    /// A peer request would exceed the session's request limit. Also returned if
    /// the limit is lowered below usage. Carries the configured request limit.
    /// This closes the session.
    #[error("wire inbound request limit exceeded: {0}")]
    InboundRequestLimitExceeded(usize),

    /// Buffering an incoming envelope would exceed the session's byte limit.
    /// Also returned if the limit is lowered below usage. Carries the configured
    /// byte limit. This closes the session.
    #[error("wire inbound byte limit exceeded: {0}")]
    InboundByteLimitExceeded(usize),
}

impl From<transport::Error> for Error {
    /// Wraps a transport error in an `Arc` so pending promises can share it.
    fn from(error: transport::Error) -> Self {
        Self::Transport(Arc::new(error))
    }
}

impl From<RemoteError> for Error {
    /// Wraps the peer's error code and message in `Error::Remote`.
    fn from(error: RemoteError) -> Self {
        Self::Remote(error)
    }
}

impl From<Infallible> for Error {
    /// Allows `Promise::wait()` to return `Message` without extracting a variant.
    fn from(error: Infallible) -> Self {
        match error {}
    }
}

impl Error {
    /// Whether a session or server ending with this error did so in an orderly
    /// way, through a local close, a peer reset or the stream ending.
    pub(super) fn orderly(&self) -> bool {
        match self {
            Self::Closed => true,
            Self::Transport(error) => matches!(
                **error,
                transport::Error::SessionReset | transport::Error::Terminated
            ),
            _ => false,
        }
    }

    /// The error as a log reason, a transport failure named by the transport's
    /// own error rather than by the wrapping one.
    pub(super) fn reason(&self) -> &dyn std::fmt::Display {
        match self {
            Self::Transport(error) => error.as_ref(),
            other => other,
        }
    }
}

impl RemoteError {
    /// Builds an error with a numeric code and a human-readable message.
    /// Codes from 0x100 are request-specific. Use [`Self::reserved`] for named
    /// protocol errors.
    pub fn new(code: u64, msg: impl Into<String>) -> Self {
        Self {
            code,
            msg: msg.into(),
        }
    }

    /// Builds an error from a reserved protocol code and a human-readable message.
    pub fn reserved(code: ReservedErrors, msg: impl Into<String>) -> Self {
        Self::new(code as u64, msg)
    }
}
