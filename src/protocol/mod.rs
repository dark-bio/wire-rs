// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Bidirectional requests over the transport, with pipelining and explicit sessions.
//!
//! A reader receives messages from each connection. Each session also has a writer
//! that sends queued messages and a deadline worker that times out operations.
//! Incoming requests and unread responses stay encoded until `recv()` or `wait()`.
//! Invalid payloads close their original session when decoded.
//!
//! Each session limits accepted peer requests and buffered incoming bytes. Set
//! both with [`Session::set_inbound_limits`] or [`Server::set_inbound_limits`].
//! Exceeding a limit closes the session. The reader never waits for the application
//! to make room. These limits are local; no flow control is negotiated with the
//! peer. The outgoing queue has no capacity limit.
//!
//! The application opens a [`crate::transport::Stream`]; this layer constructs and
//! owns its transport. [`connect`] establishes one client session. [`Server`] owns
//! a persistent stream and accepts successive server sessions. Each [`Session`]
//! owns its receive queue and closes when dropped. Its [`Requester`] and
//! [`Responder`] handles always target that session, even after it closes and
//! another session connects.
//! Both sides use the same handle types. Sessions exchange [`Message`], the union
//! of every body in the [`schema`]. The [`schema::host_to_ark::Content`] and
//! [`schema::ark_to_host::Content`] oneofs hold what each side may send. Convert
//! a received [`Message`] into the peer's oneof to dispatch on it exhaustively.
//! Callers select response types when waiting on [`Promise<Message>`]. A request
//! is refused with a [`schema::Error`], an application's own error type converting
//! into one through [`CodedError`]. A request whose content this build does not
//! know is refused as `UNKNOWN` by the session itself, so a newer peer learns what
//! an older one serves. A response of unknown content is malformed, no request
//! having asked for it.
//!
//! Requests and replies return promises without waiting for I/O. Their deadlines
//! include time in the outgoing queue; `wait()` does not restart the timeout.
//! Transport write timeouts are independent: a request can still reach the peer
//! after its promise expires. The reader and writer run independently of the
//! application, but the application must keep receiving and answering requests
//! while its own requests wait for replies. All waiting is blocking; no async
//! runtime is required. Every request expects a reply, including notifications.
//!
//! Closing a session fails its pending promises and discards queued messages.
//! Completed promises keep their results. A write already in progress may still
//! reach the peer.

mod closer;
mod envelope;
mod error;
mod message;
mod operation;
mod promise;
mod requester;
mod responder;
mod server;
mod session;
mod worker;

#[cfg(any(test, feature = "fuzz"))]
#[cfg_attr(coverage_nightly, coverage(off))]
#[doc(hidden)]
pub mod mock;

pub use closer::Closer;
pub use error::{CodedError, Error};
pub use message::Message;
pub use promise::Promise;
pub use requester::Requester;
pub use responder::Responder;
pub use server::Server;
pub use session::{Session, connect};

use std::time::Duration;

/// Default timeout for sending an automatic reply, `UNANSWERED` when a responder
/// is dropped or `UNKNOWN` to a request this build does not know. Starts when
/// the responder is dropped or the request arrives and includes time in the
/// outgoing queue. Configure it with [`Session::set_autoreply_timeout`] or
/// [`Server::set_autoreply_timeout`]. Transport write timeouts are independent.
pub const DEFAULT_AUTOREPLY_TIMEOUT: Duration = Duration::from_secs(5);

/// Default limit of 1,024 accepted peer requests per session. A request counts
/// while queued, held by a responder, or waiting to send its reply. The slot is
/// freed when the writer takes the reply or the reply is discarded.
/// Configure it with [`Session::set_inbound_limits`] or
/// [`Server::set_inbound_limits`]. Zero admits no peer requests.
pub const DEFAULT_MAX_INBOUND_REQUESTS: usize = 1024;

/// Default limit of 16 MiB for queued requests and unread response promises.
/// Counts their full encoded envelopes. Taking or dropping an envelope reduces
/// the byte count.
/// Decoded application data, outgoing messages and transport buffers are excluded.
/// Configure it with [`Session::set_inbound_limits`] or
/// [`Server::set_inbound_limits`]. Zero permits no retained envelope bytes.
pub const DEFAULT_MAX_INBOUND_BYTES: usize = 16 * 1024 * 1024;

/// Protobuf bindings of the protocol, generated from `proto/wire.proto` and
/// excluded from the lints of handwritten code. Every message implements
/// `prost::Message` for raw encoding. Applications exchange the bodies through
/// [`Message`], converting to the `host_to_ark` and `ark_to_host` oneofs to
/// dispatch on one direction. The `HostToArk` and `ArkToHost` envelopes are the
/// wire form, handled by the session internally.
#[allow(clippy::all)]
#[allow(rustdoc::broken_intra_doc_links)]
pub mod schema {
    include!("generated/darkbio.wire.rs");
}
