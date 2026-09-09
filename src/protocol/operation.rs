// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Pending operations, queued messages, and reporting their results to promises.

use super::session::Shared;
use super::{Error, Message, RemoteError};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Weak, mpsc};
use std::time::Instant;

/// Key for one entry in `Shared::operations`. Equality compares the `Arc` pointers.
/// A new operation gets a new token even if the peer reuses a wire ID, so a late
/// write result cannot complete another operation.
#[derive(Clone)]
pub(super) struct Token(Arc<()>);

impl Token {
    /// Creates a token distinct from every other token still in use.
    pub(super) fn new() -> Self {
        Self(Arc::new(()))
    }
}

impl PartialEq for Token {
    /// Checks whether both tokens point to the same `Arc` allocation.
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for Token {}

impl Hash for Token {
    /// Hashes the `Arc` pointer used by `eq()`.
    fn hash<H: Hasher>(&self, state: &mut H) {
        Arc::as_ptr(&self.0).hash(state);
    }
}

/// A request waiting for an answer, or a reply waiting for its write to finish.
/// Stored in the session's `operations` map until its promise gets a result.
pub(super) struct Operation {
    /// Deadline for the result, including time in the output queue.
    pub(super) deadline: Instant,
    /// Channel that sends the result to this operation's promise.
    pub(super) waiting: Waiting,
}

/// Result channel for a request or reply promise. Each has one slot and receives
/// one result, so sending never needs to wait for `Promise::wait()`.
pub(super) enum Waiting {
    /// Sends a peer answer or error to `Promise<Message>`.
    Answer(mpsc::SyncSender<Result<Message, Error>>),
    /// Sends a write result or error to `Promise<()>`.
    Write(mpsc::SyncSender<Result<(), Error>>),
}

impl Operation {
    /// Sends the answer to the promise, or `Timeout` if `now` is at or past the
    /// deadline. Both the reader and the scenario runner use this check.
    pub(super) fn answer(self, result: Result<Message, Error>, now: Instant) {
        if now >= self.deadline {
            self.fail(Error::Timeout, now);
        } else {
            let Waiting::Answer(sender) = self.waiting else {
                unreachable!("only requests accept peer answers")
            };
            let _ = sender.send(result);
        }
    }

    /// Sends an error to the promise, using `Timeout` if its deadline has passed.
    /// If the promise was dropped, the send fails and its result is discarded.
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

/// A request or reply in `Shared::output`. The writer takes it from the queue,
/// sends it, then uses `completion` to report the write result.
pub(super) struct Output {
    /// Request or reply to encode and send.
    pub(super) body: Body,
    /// Deadline checked by scenarios. The live deadline worker reads the
    /// corresponding entry in `Shared::operations` instead.
    #[cfg(test)]
    pub(super) deadline: Instant,
    /// Reports the write result to this message's operation.
    pub(super) completion: Completion,
}

/// Outgoing message before `Side::encode()` puts it in a wire envelope.
pub(super) enum Body {
    /// Our request. `Shared::next_output()` assigns its wire ID.
    Request(Message),
    /// A response to the given peer request ID within this exact session.
    Reply {
        /// Original peer request ID.
        id: u64,
        /// Application response or the standard unanswered error.
        result: Result<Message, RemoteError>,
    },
}

/// Identifies the session and operation that should receive a write result.
/// The session removes completed operations, so reporting a result again does
/// nothing. The weak reference never changes to point to a replacement session.
pub(super) struct Completion {
    /// Session whose `operations` map is checked for this token.
    pub(super) session: Weak<Shared>,
    /// Key used to find the operation in that session.
    pub(super) token: Token,
}

impl Completion {
    /// Reports a write result. Successful requests keep waiting for a peer answer;
    /// successful replies and failed writes send their result to the promise.
    pub(super) fn written(&self, result: Result<(), Error>) {
        if let Some(session) = self.session.upgrade() {
            session.written(&self.token, result);
        }
    }

    /// Supplies a request answer in tests that replace the transport reader.
    #[cfg(test)]
    pub(super) fn answer(self, result: Result<Message, RemoteError>) {
        if let Some(session) = self.session.upgrade() {
            session.answered(&self.token, result.map_err(Error::Remote));
        }
    }
}
