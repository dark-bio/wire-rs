// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Errors returned by protocol methods and promises.

use super::schema;
use crate::transport;
use std::convert::Infallible;
use std::sync::Arc;

/// Failure of a protocol operation.
///
/// A remote application's error is carried by [`Error::Remote`], and it does
/// not by itself end the session.
#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    /// The session or server was closed locally, including by dropping its owner.
    #[error("wire protocol closed")]
    Closed,

    /// The operation's absolute deadline expired.
    ///
    /// Remote work may still run.
    #[error("wire operation timed out")]
    Timeout,

    /// The underlying transport failed or the peer reset the session.
    #[error("wire transport failed: {0}")]
    Transport(#[from] Arc<transport::Error>),

    /// The peer returned an application error for this request.
    #[error("wire peer failed the request, code {}: {}", .0.code, .0.msg)]
    Remote(schema::Error),

    /// A [`Message`](super::Message) variant differs from the payload type it
    /// is converted to.
    ///
    /// [`Promise::wait`](super::Promise::wait) returns it for a response of the
    /// wrong type. This does not end the session.
    #[error("wire response type mismatch: expected {expected}, received {received}")]
    UnexpectedResponse {
        /// Type name of the payload the caller expected.
        expected: &'static str,
        /// Type name of the payload that arrived.
        received: &'static str,
    },

    /// The submitted message cannot be sent from this session's side.
    ///
    /// It is reported through the request or reply promise and does not end
    /// the session. Converting a [`Message`](super::Message) into the content
    /// oneof of a direction it cannot travel in fails with this error too.
    #[error("wire message cannot be sent in this direction: {0}")]
    WrongDirection(&'static str),

    /// The encoded message exceeds the transport's sending limit,
    /// [`transport::MAX_MESSAGE_SIZE`].
    ///
    /// It carries the encoded size in bytes.
    #[error("wire message too large: {0} bytes")]
    TooLarge(usize),

    /// The peer sent an invalid envelope or payload.
    ///
    /// The session closes when this is detected. Nested payloads are checked
    /// only when [`Session::recv`](super::Session::recv) or
    /// [`Promise::wait`](super::Promise::wait) reads them.
    #[error("wire peer sent a malformed message")]
    Malformed,

    /// A peer request would exceed the session's request limit.
    ///
    /// It also occurs when the limit is lowered below usage. It carries the
    /// configured request limit and closes the session.
    #[error("wire inbound request limit exceeded: {0}")]
    InboundRequestLimitExceeded(usize),

    /// Buffering an incoming envelope would exceed the session's byte limit.
    ///
    /// It also occurs when the limit is lowered below usage. It carries the
    /// configured byte limit and closes the session.
    #[error("wire inbound byte limit exceeded: {0}")]
    InboundByteLimitExceeded(usize),
}

impl From<transport::Error> for Error {
    /// Wraps a transport error in an `Arc` so pending promises can share it.
    fn from(error: transport::Error) -> Self {
        Self::Transport(Arc::new(error))
    }
}

impl From<schema::Error> for Error {
    /// Wraps the peer's error code and message in [`Error::Remote`].
    fn from(error: schema::Error) -> Self {
        Self::Remote(error)
    }
}

impl From<Infallible> for Error {
    /// Allows [`Promise::wait`](super::Promise::wait) to return a
    /// [`Message`](super::Message) without extracting a variant.
    fn from(error: Infallible) -> Self {
        match error {}
    }
}

impl Error {
    /// Checks whether a session or server ending with this error did so in an
    /// orderly way, through a local close, a peer reset or the stream ending.
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

    /// Returns the error as a log reason, naming a transport failure by the
    /// transport's own error rather than by the wrapping one.
    pub(super) fn reason(&self) -> &dyn std::fmt::Display {
        match self {
            Self::Transport(error) => error.as_ref(),
            other => other,
        }
    }
}

impl schema::Error {
    /// Builds an error with a numeric code and a human-readable message.
    ///
    /// Codes from `0x100` are request-specific. Use [`Self::reserved`] for
    /// named protocol errors.
    pub fn new(code: u64, msg: impl Into<String>) -> Self {
        Self {
            code,
            msg: msg.into(),
        }
    }

    /// Builds an error from a reserved protocol code and a human-readable message.
    pub fn reserved(code: schema::ReservedErrors, msg: impl Into<String>) -> Self {
        Self::new(code as u64, msg)
    }
}

/// Application failure that a request is answered with.
///
/// The peer can dispatch on the code and show the message. Codes below `0x100`
/// are the protocol's [`schema::ReservedErrors`], and an application assigns
/// its own from `0x100` up.
///
/// Implementing it converts the error into [`schema::Error`], so a handler can
/// fail a request with `?` and [`super::Responder::fail`] takes it directly.
pub trait CodedError: std::error::Error {
    /// Returns the code identifying the failure to the peer, `0x100` or above.
    fn code(&self) -> u64;
}

impl<E: CodedError> From<E> for schema::Error {
    /// Converts an application error into its wire form, the code as assigned
    /// and the message as displayed.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if the code is in the reserved range below `0x100`.
    fn from(error: E) -> Self {
        debug_assert!(
            error.code() >= 0x100,
            "application error code in the reserved range"
        );
        Self::new(error.code(), error.to_string())
    }
}
