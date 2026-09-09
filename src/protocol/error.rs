// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

use super::RemoteError;
use crate::transport;
use std::convert::Infallible;
use std::sync::Arc;

/// Failure of a protocol operation. A remote application's error is carried by
/// [`Error::Remote`]; it does not by itself end the session.
#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    /// The operation's absolute deadline expired. Remote work may still run.
    #[error("wire operation timed out")]
    Timeout,

    /// The session or endpoint was closed locally, including by dropping its owner.
    #[error("wire protocol closed")]
    Closed,

    /// The underlying transport failed or the peer reset the session.
    #[error("wire transport failed: {0}")]
    Transport(#[from] Arc<transport::Error>),

    /// The peer returned an application error for this request.
    #[error("wire peer failed the request, code {}: {}", .0.code, .0.msg)]
    Remote(RemoteError),

    /// The answer's content variant differed from the caller's selected type.
    /// Only this operation fails; decoding the same bytes as another protobuf
    /// message is not used as a substitute for checking the variant.
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

    /// The peer sent an invalid protocol envelope.
    #[error("wire peer sent a malformed message")]
    Malformed,

    /// The encoded message exceeds the transport's sending limit.
    #[error("wire message too large: {0} bytes")]
    TooLarge(usize),
}

impl From<transport::Error> for Error {
    fn from(error: transport::Error) -> Self {
        Self::Transport(Arc::new(error))
    }
}

impl From<RemoteError> for Error {
    fn from(error: RemoteError) -> Self {
        Self::Remote(error)
    }
}

// Message can be taken directly via its infallible identity conversion.
impl From<Infallible> for Error {
    fn from(error: Infallible) -> Self {
        match error {}
    }
}
