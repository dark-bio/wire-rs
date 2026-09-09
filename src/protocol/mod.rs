// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Bidirectional requests over the transport, with pipelining and explicit sessions.
//!
//! A reader receives messages from each connection. Each session also has a writer
//! that sends queued messages and a deadline worker that times out operations.
//! Flow control and memory limits are not implemented yet; the outgoing queue is
//! currently unbounded.
//!
//! The application opens a [`crate::transport::Stream`]; this layer constructs and
//! owns its transport. [`connect`] establishes one client session. [`Server`] owns
//! a persistent stream and accepts successive server sessions. Each [`Session`]
//! owns its receive queue and closes when dropped. Its [`Requester`] and
//! [`Responder`] handles always target that session, even after it closes and
//! another session connects.
//! Both sides use the same concrete handle types and [`Message`] enum; the role and
//! wire envelope direction are internal details. Callers select response types when
//! waiting on [`Promise<Message>`].
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
//! A write already in progress may still reach the peer.

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
pub use envelope::Envelope;
pub use error::Error;
pub use generated::Error as RemoteError;
pub use generated::*;
pub use message::Message;
pub use promise::Promise;
pub use requester::Requester;
pub use responder::Responder;
pub use server::Server;
pub use session::{Session, connect};

use std::time::Duration;

/// Default timeout for sending an automatic `UNANSWERED` reply. Starts when the
/// responder is dropped and includes time in the outgoing queue. Configure it
/// with [`Session::set_abandonment_timeout`].
/// Transport write timeouts are independent.
pub const DEFAULT_ABANDONMENT_TIMEOUT: Duration = Duration::from_secs(5);

/// Generated protobuf bindings, excluded from checks for handwritten code.
#[allow(clippy::all)]
#[allow(rustdoc::broken_intra_doc_links)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/darkbio.wire.rs"));
}
