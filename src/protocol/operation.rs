// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Pending operations, queued messages, and reporting their results to promises.

use super::envelope::IncomingEnvelope;
use super::promise::{PromiseResult, ResultSender};
use super::session::SessionInner;
use super::{Error, Message, schema};
use crate::LogId;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Weak};
use std::time::Instant;

/// Key for one entry in the session's `operations` map. Equality compares the
/// `Arc` pointers.
/// A new operation gets a new key even if the peer reuses a wire ID, so a late
/// write result cannot complete another operation.
#[derive(Clone)]
pub(super) struct OperationKey(Arc<()>);

impl OperationKey {
    /// Creates a key distinct from every other key still in use.
    pub(super) fn new() -> Self {
        Self(Arc::new(()))
    }
}

impl PartialEq for OperationKey {
    /// Checks whether both keys point to the same `Arc` allocation.
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for OperationKey {}

impl Hash for OperationKey {
    /// Hashes the `Arc` pointer used by `eq()`.
    fn hash<H: Hasher>(&self, state: &mut H) {
        Arc::as_ptr(&self.0).hash(state);
    }
}

/// A request waiting for an answer, or a reply waiting for its write to finish.
/// Stored in the session's `operations` map until its promise gets a result.
pub(super) struct PendingOperation {
    /// Deadline for the result, including time in the outgoing queue.
    pub(super) deadline: Instant,
    /// Channel that sends the result to this operation's promise.
    pub(super) sender: ResultSender,
    /// Wire ID as a log label, distinct from the operation key. A reply has it
    /// from queueing, a request from the moment the writer takes it.
    pub(super) log_id: Option<LogId>,
}

impl PendingOperation {
    /// Sends the answer to the promise, or `Timeout` if the deadline was reached.
    /// Only an on-time answer reserves bytes. If it exceeds the byte limit and
    /// its promise still exists, returns that error to the reader to close the session.
    pub(super) fn complete_response(
        self,
        now: Instant,
        retain: impl FnOnce() -> Result<IncomingEnvelope, Error>,
    ) -> Result<(), Error> {
        if now >= self.deadline {
            self.fail(Error::Timeout, now);
        } else {
            assert!(self.sender.response, "only requests accept peer answers");
            match retain() {
                Ok(message) => {
                    // If the promise was dropped, the failed send releases the bytes.
                    let _ = self.sender.send(Ok(PromiseResult::Response(message)));
                }
                Err(error) => {
                    // The send checks whether the promise still exists. If it was
                    // dropped, this response needs no space and must not close
                    // the session, even if other promises fill the byte limit.
                    if self.sender.send(Err(error.clone())).is_ok() {
                        return Err(error);
                    }
                }
            }
        }
        Ok(())
    }

    /// Fails either a request or a reply promise, using `Timeout` if its deadline
    /// has passed. If the promise was dropped, the result is discarded. Timeouts
    /// are logged here, whichever path detected them.
    pub(super) fn fail(self, error: Error, now: Instant) {
        let error = if now >= self.deadline {
            Error::Timeout
        } else {
            error
        };
        if matches!(error, Error::Timeout) {
            let kind = if self.sender.response {
                "request"
            } else {
                "reply"
            };
            match self.log_id {
                Some(id) => tracing::debug!("{} {} timed out", kind, id),
                None => tracing::debug!("{} timed out before sending", kind),
            }
        }
        let _ = self.sender.send(Err(error));
    }
}

/// A request or reply in the session's `outgoing` queue. The writer takes it,
/// sends it, then uses `operation` to report the write result.
pub(super) struct OutgoingMessage {
    /// Request or reply to encode and send.
    pub(super) body: OutgoingBody,
    /// Reports the write result to this message's operation.
    pub(super) operation: OperationHandle,
    /// Deadline checked by scenarios. The live deadline worker reads the
    /// corresponding entry in the session's `operations` map instead.
    #[cfg(any(test, feature = "fuzz"))]
    pub(super) deadline: Instant,
}

/// Outgoing message before `Side::encode()` puts it in a wire envelope.
pub(super) enum OutgoingBody {
    /// Our request. `SessionInner::next_outgoing()` assigns its wire ID.
    Request(Message),
    /// A response to the given peer request ID within this exact session.
    Reply {
        /// Original peer request ID.
        id: u64,
        /// Application response or the standard unanswered error.
        result: Result<Message, schema::Error>,
    },
}

/// Identifies the session and operation that should receive a write result.
/// The session removes completed operations, so reporting a result again does
/// nothing. The weak reference never changes to point to a replacement session.
pub(super) struct OperationHandle {
    /// Session whose `operations` map is checked for this key.
    pub(super) session: Weak<SessionInner>,
    /// Key used to find the operation in that session.
    pub(super) key: OperationKey,
}

impl OperationHandle {
    /// Reports a write result. Successful requests keep waiting for a peer answer;
    /// successful replies and failed writes send their result to the promise.
    pub(super) fn record_write(&self, result: Result<(), Error>) {
        if let Some(session) = self.session.upgrade() {
            session.record_write(&self.key, result);
        }
    }

    /// Supplies a request answer in tests that replace the transport reader.
    #[cfg(any(test, feature = "fuzz"))]
    pub(super) fn record_response(self, result: Result<Message, schema::Error>) {
        if let Some(session) = self.session.upgrade() {
            session.record_response(&self.key, result.map_err(Error::Remote));
        }
    }
}
