// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Pending operations, queued messages, and reporting their results to promises.

use super::envelope::IncomingEnvelope;
use super::promise::{Notification, Notifications, PromiseResult, ResultSender};
use super::session::SessionInner;
use super::{Error, Message, schema};
use crate::LogId;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Weak;
use std::time::Instant;

/// Key of one operation in its session's [`Operations`], numbered in
/// submission order.
///
/// A session never reuses a key, even when the peer reuses a wire ID, so a
/// late write result cannot complete another operation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(super) struct OperationKey(
    /// Count of operations the session submitted before this one.
    u64,
);

/// Pending operations of one session, with the messages queued for its writer
/// and the order of their deadlines.
///
/// Submitting, taking, completing and expiring an operation each take time
/// logarithmic in the number pending. Draining a long queue or expiring its
/// operations one by one therefore never rescans it.
#[derive(Default)]
pub(super) struct Operations {
    /// Operations waiting to send a result to their promise.
    ///
    /// Each is removed before sending that result, so a promise is completed
    /// only once.
    pending: HashMap<OperationKey, PendingOperation>,
    /// Messages of pending operations not yet taken by the writer, in
    /// submission order.
    queue: BTreeMap<OperationKey, OutgoingMessage>,
    /// Deadline and key of every pending operation, earliest first, with ties
    /// in submission order.
    deadlines: BTreeSet<(Instant, OperationKey)>,
    /// Key of the next submitted operation.
    next_key: u64,
}

impl Operations {
    /// Tracks a new operation and queues its message for the writer.
    ///
    /// # Panics
    ///
    /// Panics once the session has used up its operation keys, before changing
    /// anything, rather than reuse a key.
    pub(super) fn submit(
        &mut self,
        operation: PendingOperation,
        body: OutgoingBody,
        session: Weak<SessionInner>,
    ) {
        // Key the operation in submission order, which is also the queue order
        let key = OperationKey(self.next_key);
        self.next_key = key.0.checked_add(1).expect("operation keys exhausted");

        // Index its deadline and queue its message beside it
        self.deadlines.insert((operation.deadline, key));
        self.queue.insert(
            key,
            OutgoingMessage {
                body,
                operation: OperationHandle { session, key },
                #[cfg(any(test, feature = "fuzz"))]
                deadline: operation.deadline,
            },
        );
        self.pending.insert(key, operation);
    }

    /// Returns the pending operation under `key`.
    pub(super) fn get(&self, key: &OperationKey) -> Option<&PendingOperation> {
        self.pending.get(key)
    }

    /// Returns the pending operation under `key` for updating its log label.
    pub(super) fn get_mut(&mut self, key: &OperationKey) -> Option<&mut PendingOperation> {
        self.pending.get_mut(key)
    }

    /// Removes the operation under `key`, with its deadline and any message it
    /// still has queued.
    pub(super) fn remove(&mut self, key: &OperationKey) -> Option<PendingOperation> {
        let operation = self.pending.remove(key)?;
        self.deadlines.remove(&(operation.deadline, *key));
        self.queue.remove(key);
        Some(operation)
    }

    /// Takes the oldest queued message for the writer.
    ///
    /// Its operation stays pending until a write result or answer completes it.
    pub(super) fn take_queued(&mut self) -> Option<OutgoingMessage> {
        self.queue.pop_first().map(|(_, message)| message)
    }

    /// Removes the operation with the earliest deadline once `now` reaches it,
    /// with its message if the writer has not taken it.
    pub(super) fn pop_expired(
        &mut self,
        now: Instant,
    ) -> Option<(PendingOperation, Option<OutgoingMessage>)> {
        let &(deadline, key) = self.deadlines.first()?;
        if now < deadline {
            return None;
        }
        self.deadlines.pop_first();
        let operation = self
            .pending
            .remove(&key)
            .expect("indexed operation pending");
        Some((operation, self.queue.remove(&key)))
    }

    /// Returns the earliest deadline of the pending operations.
    pub(super) fn next_deadline(&self) -> Option<Instant> {
        self.deadlines.first().map(|&(deadline, _)| deadline)
    }

    /// Counts the pending operations.
    pub(super) fn len(&self) -> usize {
        self.pending.len()
    }

    /// Counts the messages not yet taken by the writer.
    pub(super) fn queued(&self) -> usize {
        self.queue.len()
    }

    /// Removes every pending operation, for closing the session.
    ///
    /// The queued messages stay, so the caller can drop them after releasing
    /// the session lock.
    pub(super) fn drain(&mut self) -> impl Iterator<Item = PendingOperation> {
        self.deadlines.clear();
        self.pending.drain().map(|(_, operation)| operation)
    }
}

/// Request waiting for an answer, or reply waiting for its write to finish.
///
/// It stays in the session's [`Operations`] until its promise gets a result.
pub(super) struct PendingOperation {
    /// Deadline for the result, including time in the outgoing queue.
    ///
    /// It is fixed at creation, since [`Operations`] orders pending operations
    /// by it.
    deadline: Instant,
    /// Channel that sends the result to this operation's promise.
    pub(super) sender: ResultSender,
    /// Wire ID as a log label, distinct from the operation key.
    ///
    /// A reply has it from queueing, a request from the moment the writer
    /// takes it.
    pub(super) log_id: Option<LogId>,
}

impl PendingOperation {
    /// Creates an operation whose result must reach `sender` by `deadline`.
    pub(super) fn new(deadline: Instant, sender: ResultSender, log_id: Option<LogId>) -> Self {
        Self {
            deadline,
            sender,
            log_id,
        }
    }

    /// Returns the deadline for this operation's result.
    pub(super) fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Sends the answer to the promise, or [`Error::Timeout`] if the deadline
    /// was reached.
    ///
    /// Only an on-time answer reserves bytes. If it exceeds the byte limit and
    /// its promise still exists, returns that error so the caller closes the
    /// session.
    pub(super) fn complete_response(
        self,
        now: Instant,
        notifications: &mut Notifications,
        retain: impl FnOnce() -> Result<IncomingEnvelope, Error>,
    ) -> Result<(), Error> {
        // Publish expiry or the admitted answer while the session orders results
        if now >= self.deadline {
            notifications.push(self.fail(Error::Timeout, now));
        } else {
            assert!(self.sender.response, "only requests accept peer answers");
            match retain() {
                Ok(message) => {
                    // If the promise was dropped, the failed send releases the bytes
                    notifications.push(self.sender.send(Ok(PromiseResult::Response(message))));
                }
                Err(error) => {
                    // The send checks whether the promise still exists. If it was
                    // dropped, this response needs no space and must not close
                    // the session, even if other promises fill the byte limit.
                    let notification = self.sender.send(Err(error.clone()));
                    let delivered = notification.delivered;
                    notifications.push(notification);
                    if delivered {
                        return Err(error);
                    }
                }
            }
        }
        Ok(())
    }

    /// Fails either a request or a reply promise, using [`Error::Timeout`] if its
    /// deadline has passed.
    ///
    /// If the promise was dropped, the result is discarded. Timeouts are logged
    /// here, whichever path detected them.
    pub(super) fn fail(self, error: Error, now: Instant) -> Notification {
        // Give expiry precedence over another failure
        let error = if now >= self.deadline {
            Error::Timeout
        } else {
            error
        };

        // Record timeouts wherever they were detected
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

        // Publish now and let the caller defer the callback until unlocking
        self.sender.send(Err(error))
    }
}

/// Request or reply queued in the session's [`Operations`].
///
/// The writer takes it, sends it, then uses `operation` to report the write
/// result.
pub(super) struct OutgoingMessage {
    /// Request or reply to encode and send.
    pub(super) body: OutgoingBody,
    /// Handle reporting the write result to this message's operation.
    pub(super) operation: OperationHandle,
    /// Deadline checked by scenarios.
    ///
    /// The live deadline worker reads the deadline order in the session's
    /// [`Operations`] instead.
    #[cfg(any(test, feature = "fuzz"))]
    pub(super) deadline: Instant,
}

/// Outgoing message before [`Side::encode`](super::envelope::Side::encode)
/// puts it in a wire envelope.
pub(super) enum OutgoingBody {
    /// Request of our own, whose wire ID [`SessionInner::next_outgoing`] assigns.
    Request(Message),
    /// Response to the given peer request ID within this exact session.
    Reply {
        /// Original peer request ID.
        id: u64,
        /// Application response or error, or an automatic `UNANSWERED` or
        /// `UNKNOWN` error.
        result: Result<Message, schema::Error>,
    },
}

/// Handle naming the session and operation that should receive a write result.
///
/// The session removes completed operations, so reporting a result again does
/// nothing. The weak reference never changes to point to a replacement session.
pub(super) struct OperationHandle {
    /// Session whose [`Operations`] are checked for this key.
    pub(super) session: Weak<SessionInner>,
    /// Key used to find the operation in that session.
    pub(super) key: OperationKey,
}

impl OperationHandle {
    /// Reports a write result to the operation, if it is still pending.
    ///
    /// Successful requests keep waiting for a peer answer, while successful
    /// replies and failed writes send their result to the promise.
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
