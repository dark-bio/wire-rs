// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Bidirectional requests over the transport, with pipelining and explicit sessions.
//!
//! **Work in progress:** session ownership, local retirement, receive wakeups,
//! operation registration, promises and deadline settlement are implemented.
//! Connection construction still contains `todo!` skeletons. Internal fixtures
//! currently supply sessions, input, output completion and deadline servicing;
//! real transport integration and its independent workers come later.
//! The working previous implementation and its scenario runners live in [`legacy`].
//! Protobuf bindings and message/content conversions are implemented.
//!
//! The application opens a [`crate::transport::Stream`]; this layer constructs and
//! owns its transport. [`connect`] establishes one client session. [`Server`] owns
//! a persistent endpoint and accepts successive server sessions. Each [`Session`]
//! owns its lifetime and receive queue. Its [`Requester`] and [`Responder`] handles
//! always target that session, including after a replacement connects.
//! Both sides use the same concrete handle types and [`Message`] enum; the role and
//! wire envelope direction are internal details. Callers select response types when
//! waiting on [`Promise<Message>`].
//!
//! Requests and replies return eager promises without waiting for capacity or I/O.
//! Their supplied deadlines cover capacity waits and I/O; `wait()` never restarts
//! them. I/O progresses independently of application dispatch. Applications must keep
//! receiving requests while jobs wait for reverse requests. All waiting is blocking;
//! no async runtime is required. Notification-like requests receive a reply too.
//!
//! Closing retires unresolved operations instead of draining RPCs. Already-admitted
//! transport I/O may still return. Configuration and resource limits remain to be
//! specified before their implementation.

mod closer;
mod envelope;
mod error;
pub mod legacy;
mod message;
mod operation;
mod promise;
mod requester;
mod responder;
mod server;
mod session;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod mock;

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

/// The generated bindings, kept out of the lints the crate holds itself to.
#[allow(clippy::all)]
#[allow(rustdoc::broken_intra_doc_links)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/darkbio.wire.rs"));
}
