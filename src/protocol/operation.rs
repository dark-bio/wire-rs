// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Local output obligations and their session-bound completion capabilities.

use super::session::Shared;
use super::{Error, Message, RemoteError};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Weak, mpsc};
use std::time::Instant;

/// Allocation identity for a local operation, independent of its eventual wire ID.
/// Queue entries and completion handles retain the allocation, so a late completion
/// cannot alias a newer operation even when the session reuses a wire request ID.
#[derive(Clone)]
pub(super) struct Token(Arc<()>);

impl Token {
    /// Allocates a distinct identity without a wrapping numeric counter.
    pub(super) fn new() -> Self {
        Self(Arc::new(()))
    }
}

impl PartialEq for Token {
    /// Compares allocation identities, not the equal unit values stored within them.
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for Token {}

impl Hash for Token {
    /// Hashes the same stable allocation identity used by equality.
    fn hash<H: Hasher>(&self, state: &mut H) {
        Arc::as_ptr(&self.0).hash(state);
    }
}

/// An unresolved operation, owned exclusively by the session's locked registry.
pub(super) struct Operation {
    /// Original deadline, including time spent waiting for output admission.
    pub(super) deadline: Instant,
    /// Sole producer of the operation's final result.
    pub(super) waiting: Waiting,
}

/// Distinguishes request answers from reply write acknowledgments internally.
/// Each channel has one slot and its sole sender is consumed by settlement, so
/// publishing the result never waits for the observer to receive it.
pub(super) enum Waiting {
    /// Local channel to Promise<Message>::wait, settled when the peer's answer is accepted.
    Answer(mpsc::SyncSender<Result<Message, Error>>),
    /// Local channel to Promise<()>::wait, settled when writing and flushing finish.
    Write(mpsc::SyncSender<Result<(), Error>>),
}

impl Operation {
    /// Settles a removed operation with failure, giving an elapsed deadline priority.
    /// Sending does not block; a dropped observer simply discards the result.
    pub(super) fn fail(self, error: Error, now: Instant) {
        let error = if now >= self.deadline {
            Error::Timeout
        } else {
            error
        };
        match self.waiting {
            Waiting::Answer(result) => {
                let _ = result.send(Err(error));
            }
            Waiting::Write(result) => {
                let _ = result.send(Err(error));
            }
        }
    }
}

/// A message awaiting the independent output service. Admission transfers this
/// value out of the queue; completion remains attached to the originating session.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "consumed by the upcoming transport bridge")
)]
pub(super) struct Output {
    /// Request body or reply obligation to encode in the session's wire direction.
    pub(super) body: Body,
    /// Absolute output deadline; taking the queue entry never refreshes it.
    pub(super) deadline: Instant,
    /// Capability to report output and, for requests, the eventual peer answer.
    pub(super) completion: Completion,
}

/// Output content before the transport bridge allocates or encodes wire IDs.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "consumed by the upcoming transport bridge")
)]
pub(super) enum Body {
    /// A locally initiated request, whose wire ID is assigned by the bridge.
    Request(Message),
    /// A response to the given peer request ID within this exact session.
    Reply {
        /// Original peer request ID.
        id: u64,
        /// Application response or the standard unanswered error.
        result: Result<Message, RemoteError>,
    },
}

/// A completion target bound to one operation in one session. It owns neither the
/// session nor its result sender. Retirement removes the sender before late I/O
/// can report a result, so that result cannot revive work or reach a successor.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "consumed by the upcoming transport bridge")
)]
pub(super) struct Completion {
    /// Exact originating session; never an endpoint's current-session lookup.
    pub(super) session: Weak<Shared>,
    /// Stable local operation identity, retained across output and peer processing.
    pub(super) token: Token,
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "consumed by the upcoming transport bridge")
)]
impl Completion {
    /// Reports local output completion. A successful request write still awaits its
    /// answer; a reply write or any output failure settles its operation.
    pub(super) fn written(&self, result: Result<(), Error>) {
        if let Some(session) = self.session.upgrade() {
            session.written(&self.token, result);
        }
    }

    /// Consumes the request's completion capability with the decoded peer answer.
    pub(super) fn answer(self, result: Result<Message, RemoteError>) {
        if let Some(session) = self.session.upgrade() {
            session.answered(&self.token, result.map_err(Error::Remote));
        }
    }
}
