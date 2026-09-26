// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Session state, request queues, and the reader, writer, and deadline workers.

use super::envelope::{Header, IncomingEnvelope, MessageKind, Parity, Side};
use super::operation::{
    OperationHandle, OperationKey, OutgoingBody, OutgoingMessage, PendingOperation,
};
use super::promise::{Notifications, PromiseResult};
use super::worker;
use super::{
    Closer, DEFAULT_AUTOREPLY_TIMEOUT, DEFAULT_MAX_INBOUND_BYTES, DEFAULT_MAX_INBOUND_REQUESTS,
    Error, Message, Promise, Requester, Responder, schema,
};
use crate::LogId;
use crate::transport::{self, Read, Stream, Verifier, Write};
use darkbio_clock::Clock;
use darkbio_clock::sync::{Condvar, Mutex};
use prost::bytes::Bytes;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Establishes a client session, verifies the peer and returns the verifier's info.
///
/// Takes ownership of the stream and constructs the transport internally.
/// Failure closes the client stream, and the application can open another
/// stream and reconnect. The verifier is only borrowed during this blocking
/// call. Failure to start a required worker or an escaping worker panic aborts
/// the process.
pub fn connect<R, W, V>(stream: Stream<R, W>, verifier: &V) -> Result<(Session, V::Info), Error>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
    V: Verifier,
{
    // Take the stream's clock before the client consumes the stream
    let clock = stream.clock();
    let mut client = transport::Client::new(stream);

    // Establish the session before starting its protocol workers
    let (sender, info) = client.connect(verifier)?;
    #[cfg(any(test, feature = "fuzz"))]
    let workers = Arc::new(worker::Tracker::default());
    let session = Session::start(
        Side::Client,
        clock,
        sender,
        Some(client.closer()),
        #[cfg(any(test, feature = "fuzz"))]
        workers.clone(),
    );
    let inner = session.inner.clone();

    // Let the reader route transport messages into the shared session
    worker::spawn(
        "wire-client-reader",
        #[cfg(any(test, feature = "fuzz"))]
        &workers,
        move || run_reader(client, inner),
    );
    Ok((session, info))
}

/// Receives and handles messages for one client session.
///
/// The reader retains its session state until it exits. Closing the session
/// shuts down the stream and wakes a blocked transport read.
fn run_reader<R: Read, W: Write>(mut client: transport::Client<R, W>, session: Arc<SessionInner>) {
    loop {
        let result = client
            .recv()
            .map_err(Error::from)
            .and_then(|bytes| session.handle_message(bytes));
        if let Err(error) = result {
            // Receive and decode failures close this client session and its
            // stream, waking any other blocked transport I/O
            session.close(error);
            break;
        }
    }
}

/// Owner of one session and its incoming request queue.
///
/// Incoming requests use [`Message`], paired with a common responder. The
/// application selects the reply type; there is no static request/response pairing
/// table. The host/server role and envelope direction are handled internally.
///
/// Closing or dropping the session fails pending promises, discards queued requests,
/// and wakes blocked [`Self::recv`] calls. Completed promises keep their results.
/// Application jobs keep running, but their handles still refer to the closed
/// session and cannot send messages through a replacement session.
///
/// A client session also closes its stream. A server session leaves the server's
/// stream available for another handshake. Handles do not keep the session open.
/// The owner cannot be cloned; obtain requesters or closers for other threads:
///
/// ```compile_fail,E0599
/// use darkbio_wire::protocol::Session;
/// fn duplicate(session: Session) { let _ = session.clone(); }
/// ```
pub struct Session {
    /// Queues and pending operations shared with this session's workers.
    pub(super) inner: Arc<SessionInner>,
}

impl Session {
    /// Returns the clock of the stream this session runs on, which request and
    /// reply deadlines are measured on.
    pub fn clock(&self) -> Clock {
        self.inner.clock.clone()
    }

    /// Sets the timeout for automatic `UNANSWERED` and `UNKNOWN` replies.
    ///
    /// Defaults to [`DEFAULT_AUTOREPLY_TIMEOUT`]. Replies already queued keep
    /// their deadlines.
    ///
    /// The budget starts when a responder is dropped or an unknown request is
    /// received, and includes queueing. Expiry discards a queued reply, while a
    /// write already started still runs under the transport's independent
    /// timeout. Explicit request and reply deadlines are unaffected. Zero or an
    /// unrepresentable deadline expires immediately.
    /// Use [`super::Server::set_autoreply_timeout`] to also set the timeout for
    /// future server sessions.
    pub fn set_autoreply_timeout(self, timeout: Duration) -> Self {
        self.inner.set_autoreply_timeout(timeout);
        self
    }

    /// Sets the maximum accepted peer requests and buffered incoming bytes together.
    ///
    /// Defaults to [`DEFAULT_MAX_INBOUND_REQUESTS`] and [`DEFAULT_MAX_INBOUND_BYTES`].
    ///
    /// `requests` counts queued requests, held responders and queued replies,
    /// including automatic replies to requests with unknown content.
    /// A slot is freed when the writer takes the reply or the reply is discarded.
    /// Zero refuses all peer requests but still allows responses to our requests.
    ///
    /// `bytes` counts the full encoded envelopes of queued requests and unread
    /// responses. [`Self::recv`], [`Promise::wait`] or dropping a response promise
    /// releases that space in the budget. Zero allows no buffered envelopes.
    /// Decoded application data, outgoing messages and transport buffers are
    /// excluded.
    ///
    /// Exceeding either limit closes this session with
    /// [`Error::InboundRequestLimitExceeded`] or [`Error::InboundByteLimitExceeded`].
    /// The reader never waits for space. Lowering a limit below usage also closes
    /// the session. Completed promises keep their results and bytes until read or
    /// dropped. Raising limits does not reopen a closed session.
    pub fn set_inbound_limits(self, requests: usize, bytes: usize) -> Self {
        let mut notifications = Notifications::default();
        self.inner
            .set_inbound_limits(requests, bytes, &mut notifications);
        self
    }

    /// Returns a clonable requester bound to this session.
    pub fn requester(&self) -> Requester {
        Requester::new(Arc::downgrade(&self.inner), &self.inner.clock)
    }

    /// Blocks for the next peer request and its [`Responder`].
    ///
    /// Closing the session wakes this call with the error that closed it. The
    /// caller decides how to handle each request.
    ///
    /// Taking a request removes its bytes from the inbound byte count before
    /// decoding it. The request still counts toward the inbound request limit
    /// while its responder is held. Invalid protobuf returns [`Error::Malformed`]
    /// and closes this session, which runs the notify callbacks of its pending
    /// promises on the calling thread.
    ///
    /// If another thread closes the session after this call takes a request from
    /// the queue, it can still return that request. Replying after closure
    /// returns an error.
    pub fn recv(&mut self) -> Result<(Message, Responder), Error> {
        self.inner.recv()
    }

    /// Returns a clonable handle for closing this session from another thread,
    /// including while its owner is blocked in [`Self::recv`].
    pub fn closer(&self) -> Closer {
        Closer::session(Arc::downgrade(&self.inner))
    }

    /// Closes this session, discarding queued messages and failing pending
    /// promises.
    ///
    /// Repeated calls have no further effect. A client session also closes its
    /// stream, waiting for adapter calls in progress to return. This does not
    /// wait for application jobs or guarantee the peer has observed closure. A
    /// transport write already started may still finish, but cannot change a
    /// completed promise's result or affect a replacement session.
    pub fn close(&self) {
        self.inner.close(Error::Closed);
    }
}

impl Drop for Session {
    /// Closes the session even when requesters, responders or closers remain.
    fn drop(&mut self) {
        self.close();
    }
}

impl fmt::Debug for Session {
    /// Shows the session label and whether the session is still open.
    ///
    /// A state lock held elsewhere leaves the state out.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut session = f.debug_struct("Session");
        session.field("id", &self.inner.log_id);
        if let Ok(state) = self.inner.state.try_lock() {
            session.field("open", &matches!(*state, State::Open { .. }));
        }
        session.finish_non_exhaustive()
    }
}

/// Queues and pending operations for one session.
///
/// Requesters, responders and closers hold weak references to this object,
/// even after a new session connects.
pub(super) struct SessionInner {
    /// Clock inherited from the stream that established this session.
    pub(super) clock: Clock,
    /// Queues, pending operations and the transition to [`State::Closed`],
    /// under one lock.
    state: Mutex<State>,
    /// Signal waking [`Self::recv`], the writer and the deadline worker when
    /// `state` changes.
    changed: Condvar,
    /// Incoming bytes held by queued requests and unread responses.
    ///
    /// Accepting messages and changing limits hold `state`. Consumers can
    /// release bytes without that lock. Unread promises keep this counter alive
    /// after closure.
    retained_bytes: Arc<AtomicUsize>,
    /// Envelope direction and request parity, fixed for the whole session.
    side: Side,
    /// Label of the transport session in log lines, unset without a transport.
    pub(super) log_id: LogId,
    /// Closer of the client's stream.
    ///
    /// Server sessions and tests without a stream leave it empty, since
    /// [`Server`](super::Server) closes a server's stream.
    stream_closer: Option<transport::Closer>,
    /// Tracker letting tests wait for worker threads to exit.
    #[cfg(any(test, feature = "fuzz"))]
    pub(super) workers: Arc<worker::Tracker>,
    /// Channel notifying tests when the last `Arc<SessionInner>` is dropped.
    #[cfg(any(test, feature = "fuzz"))]
    drop_hook: std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>>,
    /// Hook pausing the writer before `sender.disconnect()` in replacement tests.
    #[cfg(any(test, feature = "fuzz"))]
    disconnect_hook:
        std::sync::Mutex<Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>>,
}

/// An open session's queues, or the error that closed the session.
///
/// Test and fuzz builds keep the same inline layout, although their wait hook
/// crosses Clippy's size threshold for the difference between variants.
#[cfg_attr(any(test, feature = "fuzz"), allow(clippy::large_enum_variant))]
enum State {
    /// Open session with its queued messages and pending operations.
    ///
    /// [`State::close`] replaces it with [`State::Closed`], and the caller drops
    /// the queues after releasing the state lock.
    Open {
        /// Ceiling for accepted requests, including application-held responders.
        max_inbound_requests: usize,
        /// Ceiling for encoded requests and unread response promises.
        max_inbound_bytes: usize,
        /// Timeout selected when an automatic reply is queued.
        autoreply_timeout: Duration,

        /// Peer requests awaiting application receipt, paired with their request IDs.
        incoming: VecDeque<(u64, IncomingEnvelope)>,
        /// IDs of accepted peer requests, whose count the request limit applies to.
        ///
        /// A duplicate ID is rejected while the receive queue, a responder or a
        /// queued reply holds it. Taking a reply into the writer or discarding
        /// an expired reply releases its ID. Release happens before writing,
        /// since the peer can receive the reply and reuse its ID before our
        /// local flush returns.
        reserved_ids: HashSet<u64>,

        /// Requests and replies waiting for the writer to take them.
        outgoing: VecDeque<OutgoingMessage>,
        /// Next locally allocated ID, or `None` once exhausted, never wrapping
        /// or reusing an ID.
        next_id: Option<u64>,
        /// Operation keys of sent requests, by wire ID.
        ///
        /// An entry stays after its promise times out, until the peer responds
        /// or the session closes. A request that fails to encode is removed at
        /// once.
        outstanding: HashMap<u64, OperationKey>,
        /// Operations waiting to send a result to their promise.
        ///
        /// Each is removed before sending that result, so a promise is completed
        /// only once.
        operations: HashMap<OperationKey, PendingOperation>,

        /// One-shot test notification sent under the state lock before waiting.
        #[cfg(any(test, feature = "fuzz"))]
        wait_hook: Option<std::sync::mpsc::Sender<()>>,
    },
    /// Closed session, with the first closing reason returned to every later
    /// operation.
    Closed(Error),
}

impl SessionInner {
    /// Creates empty queues and pending-operation maps before starting workers.
    fn new(
        side: Side,
        clock: Clock,
        log_id: LogId,
        stream_closer: Option<transport::Closer>,
        #[cfg(any(test, feature = "fuzz"))] workers: Arc<worker::Tracker>,
    ) -> Self {
        Self {
            changed: Condvar::new(&clock),
            clock,
            state: Mutex::new(State::Open {
                max_inbound_requests: DEFAULT_MAX_INBOUND_REQUESTS,
                max_inbound_bytes: DEFAULT_MAX_INBOUND_BYTES,
                autoreply_timeout: DEFAULT_AUTOREPLY_TIMEOUT,

                incoming: VecDeque::new(),
                reserved_ids: HashSet::new(),

                outgoing: VecDeque::new(),
                next_id: Some(Parity::from(side).first()),
                outstanding: HashMap::new(),
                operations: HashMap::new(),

                #[cfg(any(test, feature = "fuzz"))]
                wait_hook: None,
            }),
            retained_bytes: Arc::new(AtomicUsize::new(0)),
            side,
            log_id,
            stream_closer,
            #[cfg(any(test, feature = "fuzz"))]
            workers,
            #[cfg(any(test, feature = "fuzz"))]
            drop_hook: std::sync::Mutex::new(None),
            #[cfg(any(test, feature = "fuzz"))]
            disconnect_hook: std::sync::Mutex::new(None),
        }
    }

    /// Changes the timeout for subsequent automatic replies.
    ///
    /// Queued replies keep their original deadlines.
    pub(super) fn set_autoreply_timeout(&self, timeout: Duration) {
        let mut state = self.state.lock().expect("session state not poisoned");
        if let State::Open {
            autoreply_timeout, ..
        } = &mut *state
        {
            *autoreply_timeout = timeout;
        }
    }

    /// Updates both limits and closes the session if usage is too high.
    ///
    /// It holds the same lock used to accept incoming messages.
    pub(super) fn set_inbound_limits(
        &self,
        requests: usize,
        bytes: usize,
        notifications: &mut Notifications,
    ) {
        // Apply policy under the lock shared with incoming admission
        let removed = {
            let mut state = self.state.lock().expect("session state not poisoned");
            let State::Open {
                max_inbound_requests,
                max_inbound_bytes,
                reserved_ids,
                ..
            } = &mut *state
            else {
                return;
            };
            *max_inbound_requests = requests;
            *max_inbound_bytes = bytes;
            let error = if reserved_ids.len() > *max_inbound_requests {
                Some(Error::InboundRequestLimitExceeded(*max_inbound_requests))
            } else if self.retained_bytes.load(Ordering::Relaxed) > *max_inbound_bytes {
                Some(Error::InboundByteLimitExceeded(*max_inbound_bytes))
            } else {
                None
            };
            error.and_then(|error| {
                let (pending, queued) = state.workload();
                let removed = state.close(error.clone(), self.now(), notifications);
                if removed.is_some() {
                    self.log_closed(&error, pending, queued);
                }
                removed
            })
        };

        // Release queued work and wake waiters after unlocking
        if removed.is_some() {
            self.finish_close(removed);
        }
    }

    /// Counts the envelope's original bytes under the session lock.
    ///
    /// Decoding or dropping it later releases those bytes to this session's
    /// counter.
    fn retain_incoming(
        self: &Arc<Self>,
        bytes: Bytes,
        header: Header,
        limit: usize,
    ) -> Result<IncomingEnvelope, Error> {
        IncomingEnvelope::new(
            bytes,
            header,
            &self.retained_bytes,
            limit,
            self.side,
            Arc::downgrade(self),
        )
    }

    /// Takes the next request from `incoming` and creates its responder.
    ///
    /// If the queue is empty, it waits on `changed`. Closing the session wakes
    /// the wait and returns the error stored in [`State::Closed`]. It decodes
    /// after releasing the lock, so the reader can keep receiving messages.
    fn recv(self: &Arc<Self>) -> Result<(Message, Responder), Error> {
        let mut state = self.state.lock().expect("session state not poisoned");
        let (message, responder) = loop {
            match &mut *state {
                State::Closed(error) => return Err(error.clone()),
                State::Open {
                    incoming,
                    #[cfg(any(test, feature = "fuzz"))]
                    wait_hook,
                    ..
                } => {
                    if let Some((id, message)) = incoming.pop_front() {
                        break (
                            message,
                            Responder::new(Arc::downgrade(self), &self.clock, id),
                        );
                    }
                    #[cfg(any(test, feature = "fuzz"))]
                    if let Some(wait_hook) = wait_hook.take() {
                        let _ = wait_hook.send(());
                    }
                    state = self
                        .changed
                        .wait(state)
                        .expect("session state not poisoned");
                }
            }
        };
        drop(state);
        Ok((message.decode()?, responder))
    }

    /// Replaces `Open` with `Closed` and fails pending promises under the state lock.
    ///
    /// Expired operations receive [`Error::Timeout`], and the rest receive the
    /// closing error. Every call wakes `changed` and finishes any required
    /// stream shutdown.
    pub(super) fn close(&self, error: Error) {
        // Publish closing results while preserving callbacks past the lock scope
        let mut notifications = Notifications::default();
        let (removed, pending, queued) = {
            let mut state = self.state.lock().expect("session state not poisoned");
            let (pending, queued) = state.workload();
            (
                state.close(error.clone(), self.now(), &mut notifications),
                pending,
                queued,
            )
        };

        // Wake waiters and finish shutdown before running the callbacks
        if removed.is_some() {
            self.log_closed(&error, pending, queued);
        }
        self.finish_close(removed);
    }

    /// Logs the end of the session with its reason, the operations it failed
    /// and the messages it dropped.
    ///
    /// Orderly endings are informational, and failures are warnings.
    fn log_closed(&self, error: &Error, pending: usize, queued: usize) {
        match error {
            Error::Closed => tracing::info!(
                "wire session {} closed locally (pending {}, queued {})",
                self.log_id,
                pending,
                queued
            ),
            _ if error.orderly() => tracing::info!(
                "wire session {} closed: {} (pending {}, queued {})",
                self.log_id,
                error.reason(),
                pending,
                queued
            ),
            _ => tracing::warn!(
                "wire session {} failed: {} (pending {}, queued {})",
                self.log_id,
                error.reason(),
                pending,
                queued
            ),
        }
    }

    /// Drops queued work and wakes waiters outside the session lock.
    fn finish_close(&self, removed: Option<State>) {
        // Wake local waiters and drop queued work before adapter shutdown, which
        // may wait for transport I/O already running to return
        self.changed.notify_all();
        drop(removed);
        if let Some(stream_closer) = &self.stream_closer {
            stream_closer.close();
        }
    }

    /// Queues an `UNANSWERED` reply when a responder is dropped.
    ///
    /// The writer sends the reply later.
    pub(super) fn reply_unanswered(self: &Arc<Self>, id: u64) {
        self.autoreply(
            id,
            "unanswered",
            schema::Error::reserved(
                schema::ReservedErrors::Unanswered,
                "request left unanswered",
            ),
        );
    }

    /// Queues an `UNKNOWN` reply to a request whose content this build does not
    /// know, the application never seeing it.
    ///
    /// The writer sends the reply later.
    fn reply_unknown(self: &Arc<Self>, id: u64) {
        self.autoreply(
            id,
            "unknown",
            schema::Error::reserved(schema::ReservedErrors::Unknown, "request not known"),
        );
    }

    /// Queues an automatic reply under the configured autoreply timeout.
    ///
    /// The budget starts on entry, before acquiring the session lock, and
    /// includes queueing. An unrepresentable deadline expires immediately
    /// instead of panicking from `Drop`. A closed session queues nothing.
    fn autoreply(self: &Arc<Self>, id: u64, reason: &str, error: schema::Error) {
        // Start the budget on entry, then read the timeout of an open session
        let now = self.now();
        let timeout = {
            let state = self.state.lock().expect("session state not poisoned");
            match &*state {
                State::Open {
                    autoreply_timeout, ..
                } => *autoreply_timeout,
                State::Closed(_) => return,
            }
        };
        tracing::debug!("answering request {} as {}", id, reason);

        // Fix this reply's deadline on entry. Later changes to the session's
        // configuration do not retime already submitted work.
        let deadline = now.checked_add(timeout).unwrap_or(now);
        let _ = self.reply(id, Err(error), deadline);
    }

    /// Creates a promise and queues a request through [`Self::enqueue`].
    ///
    /// If the deadline has already passed, the promise gets [`Error::Timeout`]
    /// and nothing is queued.
    pub(super) fn request(
        self: &Arc<Self>,
        request: Message,
        deadline: Instant,
    ) -> Result<Promise<Message>, Error> {
        let (sender, promise) = Promise::pair(Arc::downgrade(self), deadline, true);
        self.enqueue(
            OutgoingBody::Request(request),
            PendingOperation {
                deadline,
                sender,
                log_id: None,
            },
        )?;
        Ok(promise)
    }

    /// Queues a reply to `id` through [`Self::enqueue`].
    ///
    /// Its promise waits for the write and flush to finish, or fails if its
    /// deadline expires first.
    pub(super) fn reply(
        self: &Arc<Self>,
        id: u64,
        result: Result<Message, schema::Error>,
        deadline: Instant,
    ) -> Result<Promise<()>, Error> {
        let (sender, promise) = Promise::pair(Arc::downgrade(self), deadline, false);
        self.enqueue(
            OutgoingBody::Reply { id, result },
            PendingOperation {
                deadline,
                sender,
                log_id: Some(LogId::from(id)),
            },
        )?;
        Ok(promise)
    }

    /// Adds a [`PendingOperation`] and its [`OutgoingMessage`] under the state lock.
    ///
    /// A closed session returns its error directly. An expired deadline fails
    /// the promise instead, releasing the ID of an expired reply.
    fn enqueue(
        self: &Arc<Self>,
        body: OutgoingBody,
        operation: PendingOperation,
    ) -> Result<(), Error> {
        // Keep callbacks outside the lock even when admission expires immediately
        let mut notifications = Notifications::default();
        {
            let mut state = self.state.lock().expect("session state not poisoned");
            let (operations, outgoing, reserved_ids) = match &mut *state {
                State::Open {
                    operations,
                    outgoing,
                    reserved_ids,
                    ..
                } => (operations, outgoing, reserved_ids),
                State::Closed(error) => return Err(error.clone()),
            };

            // Fail an expired operation at once, releasing a reply's reserved ID
            let now = self.now();
            if now >= operation.deadline {
                if let OutgoingBody::Reply { id, .. } = body {
                    reserved_ids.remove(&id);
                }
                notifications.push(operation.fail(Error::Timeout, now));
                return Ok(());
            }

            // Queue the message and track its operation under a fresh key
            let key = OperationKey::new();
            outgoing.push_back(OutgoingMessage {
                body,
                operation: OperationHandle {
                    session: Arc::downgrade(self),
                    key: key.clone(),
                },
                #[cfg(any(test, feature = "fuzz"))]
                deadline: operation.deadline,
            });
            operations.insert(key, operation);
        }

        // Wake the writer and deadline worker after publishing the queued work
        self.changed.notify_all();
        Ok(())
    }

    /// Fails expired operations and removes their queued messages.
    ///
    /// A promise waiter can call this if the deadline worker has not yet
    /// processed its timeout. Requests already sent remain in `outstanding`
    /// until answered or closed.
    pub(super) fn expire(&self) {
        // Drop the state guard before notifying completed promises
        let mut notifications = Notifications::default();
        let mut state = self.state.lock().expect("session state not poisoned");
        state.expire(self.now(), &mut notifications);
    }

    /// Returns the earliest pending operation deadline for scenario assertions.
    #[cfg(any(test, feature = "fuzz"))]
    pub(super) fn next_deadline(&self) -> Option<Instant> {
        let state = self.state.lock().expect("session state not poisoned");
        match &*state {
            State::Open { operations, .. } => operations
                .values()
                .map(|operation| operation.deadline)
                .min(),
            State::Closed(_) => None,
        }
    }

    /// Takes the next unexpired [`OutgoingMessage`] for tests that drive writing
    /// themselves.
    #[cfg(any(test, feature = "fuzz"))]
    pub(super) fn take_outgoing(&self) -> Option<OutgoingMessage> {
        // Settle expired operations before selecting queued work
        let mut notifications = Notifications::default();
        let mut state = self.state.lock().expect("session state not poisoned");
        state.expire(self.now(), &mut notifications);

        // Release a reply's reservation when the writer takes it
        match &mut *state {
            State::Open {
                outgoing,
                reserved_ids,
                ..
            } => {
                let message = outgoing.pop_front()?;
                if let OutgoingBody::Reply { id, .. } = &message.body {
                    reserved_ids.remove(id);
                }
                Some(message)
            }
            State::Closed(_) => None,
        }
    }

    /// Records a write result under the state lock.
    ///
    /// A successful request write leaves its operation waiting for an answer,
    /// while a reply write completes it. A failed or late write fails the
    /// promise.
    pub(super) fn record_write(&self, key: &OperationKey, result: Result<(), Error>) {
        // Find the operation while deferring callbacks past the state guard
        let mut notifications = Notifications::default();
        let mut state = self.state.lock().expect("session state not poisoned");
        let State::Open { operations, .. } = &mut *state else {
            return;
        };
        let Some(operation) = operations.get(key) else {
            return;
        };

        // Publish failures and reply completion while requests keep awaiting answers
        let now = self.now();
        if now >= operation.deadline || result.is_err() {
            let operation = operations.remove(key).expect("operation held under lock");
            notifications.push(operation.fail(result.err().unwrap_or(Error::Timeout), now));
        } else if !operation.sender.response {
            let operation = operations.remove(key).expect("operation held under lock");
            notifications.push(operation.sender.send(Ok(PromiseResult::Written)));
        }
    }

    /// Supplies a response to a fixture operation without depending on wire IDs.
    ///
    /// The fixture still encodes and retains bytes, matching real promise behavior.
    #[cfg(any(test, feature = "fuzz"))]
    pub(super) fn record_response(
        self: &Arc<Self>,
        key: &OperationKey,
        result: Result<Message, Error>,
    ) {
        // Remove the fixture operation and defer its callback past the lock
        let mut notifications = Notifications::default();
        let mut state = self.state.lock().expect("session state not poisoned");
        let State::Open {
            operations,
            max_inbound_bytes,
            ..
        } = &mut *state
        else {
            return;
        };
        let Some(operation) = operations.remove(key) else {
            return;
        };
        let result = match result {
            Ok(message) => Ok(message),
            Err(Error::Remote(error)) => Err(error),
            Err(error) => {
                notifications.push(operation.fail(error, self.now()));
                return;
            }
        };

        // Encode the fixture response through the same envelope admission as the reader
        let peer = match self.side {
            Side::Client => Side::Server,
            Side::Server => Side::Client,
        };
        let bytes = peer
            .encode(0, result)
            .expect("fixture response belongs to the peer");
        let bytes = Bytes::from(bytes.into_boxed_slice());
        let header = self
            .side
            .decode_header(bytes.clone())
            .expect("fixture response has a valid envelope");
        let result = operation.complete_response(self.now(), &mut notifications, || {
            self.retain_incoming(bytes, header, *max_inbound_bytes)
        });

        // Close on admission failure after releasing the session lock
        drop(state);
        if let Err(error) = result {
            self.close(error);
        }
    }

    /// Returns the stream clock's time.
    ///
    /// Deadline checks hold `state`, and [`Self::autoreply`] also calls this
    /// before waiting for that lock.
    fn now(&self) -> Instant {
        self.clock.now()
    }

    /// Checks the outer envelope and routes its original bytes.
    ///
    /// [`Self::recv`] and [`Promise::wait`] decode nested payloads. Unmatched and
    /// late responses are discarded without decoding their bodies. The reader
    /// closes the session on error.
    pub(super) fn handle_message(self: &Arc<Self>, bytes: Vec<u8>) -> Result<(), Error> {
        // Decode routing metadata before taking the session lock
        let bytes = Bytes::from(bytes.into_boxed_slice());
        let header = self.side.decode_header(bytes.clone())?;
        let mut unknown = None;

        // Publish accepted responses while retaining callbacks beyond the lock scope
        let mut notifications = Notifications::default();
        {
            let mut state = self.state.lock().expect("session state not poisoned");
            match MessageKind::from_id(header.id, self.side.into()) {
                MessageKind::Request => {
                    if header.failed {
                        return Err(self.side.malformed(
                            Some(header),
                            bytes.len(),
                            "envelope",
                            "request contains an error",
                        ));
                    }
                    // Unknown content reserves a slot for its automatic reply,
                    // which is queued once this lock is released
                    self.admit_request(&mut state, header, bytes)?;
                    if header.unknown {
                        unknown = Some(header.id);
                    }
                }
                MessageKind::Response => {
                    let State::Open {
                        operations,
                        outstanding,
                        max_inbound_bytes,
                        ..
                    } = &mut *state
                    else {
                        let State::Closed(error) = &*state else {
                            unreachable!()
                        };
                        return Err(error.clone());
                    };

                    // A sent request keeps its ID here until answered, so an ID
                    // without an operation belongs to a request that timed out
                    if let Some(key) = outstanding.remove(&header.id) {
                        if let Some(operation) = operations.remove(&key) {
                            tracing::trace!(
                                "received response {} ({})",
                                header.id,
                                header.payload.unwrap_or("none")
                            );
                            operation.complete_response(self.now(), &mut notifications, || {
                                self.retain_incoming(bytes, header, *max_inbound_bytes)
                            })?;
                        } else {
                            tracing::debug!("discarding late response {}", header.id);
                        }
                    } else {
                        tracing::warn!("discarding unmatched response {}", header.id);
                    }
                }
            }
        }

        // Queue automatic replies and wake workers after releasing the state lock
        if let Some(id) = unknown {
            self.reply_unknown(id);
        }
        self.changed.notify_all();
        Ok(())
    }

    /// Reserves a request slot and buffers known content under the session lock.
    ///
    /// Unknown content keeps only its ID for the automatic reply. If a limit is
    /// exceeded, admission leaves the queues untouched. It never waits for the
    /// application.
    fn admit_request(
        self: &Arc<Self>,
        state: &mut State,
        header: Header,
        bytes: Bytes,
    ) -> Result<(), Error> {
        let State::Open {
            incoming,
            reserved_ids,
            max_inbound_requests,
            max_inbound_bytes,
            ..
        } = state
        else {
            let State::Closed(error) = state else {
                unreachable!()
            };
            return Err(error.clone());
        };

        // Refuse an ID still in use, then a request beyond the limit
        if reserved_ids.contains(&header.id) {
            return Err(self.side.malformed(
                Some(header),
                bytes.len(),
                "envelope",
                "duplicate request ID",
            ));
        }
        let id = header.id;
        if reserved_ids.len() >= *max_inbound_requests {
            tracing::warn!(
                "inbound request limit exceeded (id: {}, used: {}, limit: {})",
                id,
                reserved_ids.len(),
                max_inbound_requests
            );
            return Err(Error::InboundRequestLimitExceeded(*max_inbound_requests));
        }

        // Buffer known content, while unknown content keeps only its ID
        let payload = header.payload.unwrap_or("none");
        let message = if header.unknown {
            None
        } else {
            Some(self.retain_incoming(bytes, header, *max_inbound_bytes)?)
        };
        reserved_ids.insert(id);
        if let Some(message) = message {
            incoming.push_back((id, message));
        }
        tracing::trace!("received request {} ({})", id, payload);
        Ok(())
    }

    /// Waits for and takes the next queued message, or returns `None` on closure.
    ///
    /// Under the state lock, it assigns each request an ID and records its
    /// operation key in `outstanding`. [`Self::handle_message`] can then match
    /// the peer's response, even one arriving before the write finishes.
    ///
    /// # Panics
    ///
    /// Panics once the session has used up its request IDs, which aborts the
    /// process when the writer calls it.
    pub(super) fn next_outgoing(&self) -> Option<(u64, OutgoingMessage)> {
        // Keep callback ownership outside the lock across every queue check
        let mut notifications = Notifications::default();
        let mut state = self.state.lock().expect("session state not poisoned");
        loop {
            // Run expiry callbacks before selecting work or parking the writer
            state.expire(self.now(), &mut notifications);
            if !notifications.is_empty() {
                drop(state);
                drop(notifications);
                notifications = Notifications::default();
                state = self.state.lock().expect("session state not poisoned");
                continue;
            }

            // Assign an ID and reserve the response route before releasing the lock
            let State::Open {
                outgoing,
                next_id,
                outstanding,
                operations,
                reserved_ids,
                ..
            } = &mut *state
            else {
                return None;
            };
            if let Some(outgoing) = outgoing.pop_front() {
                let id = match &outgoing.body {
                    OutgoingBody::Request(_) => {
                        let id = next_id.expect("wire request IDs exhausted");
                        *next_id = id.checked_add(2);
                        // Store the ID before releasing the lock, since a response
                        // can arrive before the outgoing send finishes locally
                        outstanding.insert(id, outgoing.operation.key.clone());
                        if let Some(operation) = operations.get_mut(&outgoing.operation.key) {
                            operation.log_id = Some(LogId::from(id));
                        }
                        id
                    }
                    OutgoingBody::Reply { id, .. } => {
                        // The peer may receive this reply and reuse the ID before
                        // our flush returns. Finishing this write must not remove
                        // a newer request that reuses the same ID.
                        reserved_ids.remove(id);
                        *id
                    }
                };
                return Some((id, outgoing));
            }

            // Sleep until work arrives or the session closes
            state = self
                .changed
                .wait(state)
                .expect("session state not poisoned");
        }
    }

    /// Sends queued messages through `sender` until the session closes.
    ///
    /// Transport errors close the session, while messages that cannot be encoded
    /// fail only their own promise. On exit, it disconnects the transport
    /// session this sender belongs to.
    fn run_writer(&self, sender: transport::Sender<impl Write>) {
        while let Some((id, outgoing)) = self.next_outgoing() {
            // `next_outgoing` released the state lock. The reader and deadline
            // worker can continue while encoding or sending this message blocks.
            let request = matches!(outgoing.body, OutgoingBody::Request(_));
            let kind = if request { "request" } else { "reply" };
            let body = match outgoing.body {
                OutgoingBody::Request(body) => Ok(body),
                OutgoingBody::Reply { result, .. } => result,
            };
            let payload = match &body {
                Ok(message) => message.field_name(),
                Err(_) => "err",
            };
            let result = self.side.encode(id, body).and_then(|bytes| {
                // Announced before the transport confirms the write, so a
                // message reads top down in the log
                tracing::trace!("sending {} {} ({})", kind, id, payload);
                sender.send(&bytes).map_err(Error::from)
            });

            // Close the session on a wire failure, and log a local refusal
            match &result {
                Ok(()) => {}
                Err(Error::Transport(error)) => {
                    // Wire failure ends the session even if this operation's promise
                    // has already timed out while the transport write was blocked
                    self.close(Error::Transport(error.clone()));
                    break;
                }
                Err(error) => tracing::debug!("not sending {} {}: {}", kind, id, error),
            }

            {
                // Remaining failures are local encoding refusals. No request was
                // sent, so there is no future answer to retain an ID for.
                let mut state = self.state.lock().expect("session state not poisoned");
                if let State::Open { outstanding, .. } = &mut *state
                    && request
                    && result.is_err()
                {
                    outstanding.remove(&id);
                }
            }

            // Report this operation's write result, if it is still pending.
            // A response or timeout may have completed it during the write.
            outgoing.operation.record_write(result);
        }

        // Let replacement tests pause the writer before it disconnects
        #[cfg(any(test, feature = "fuzz"))]
        if let Some((entered, released)) = self.disconnect_hook.lock().unwrap().take() {
            let _ = entered.send(());
            let _ = released.recv();
        }

        // Disconnect the session this sender belongs to. The transport ignores
        // this call if a new handshake has already replaced that session.
        if let Err(error) = sender.disconnect() {
            tracing::debug!(
                "failed to signal dropped session {}: {}",
                sender.log_id(),
                error
            );
        }
    }

    /// Expires pending operations even when no caller is waiting on a promise.
    ///
    /// It waits on `changed` until the next deadline or until new work arrives,
    /// and returns once the session closes.
    pub(super) fn run_deadlines(&self) {
        // Keep callbacks outside the guard even when the session closes
        let mut notifications = Notifications::default();
        let mut state = self.state.lock().expect("session state not poisoned");
        loop {
            // Run settled callbacks before recomputing deadlines or waiting again
            state.expire(self.now(), &mut notifications);
            if !notifications.is_empty() {
                drop(state);
                drop(notifications);
                notifications = Notifications::default();
                state = self.state.lock().expect("session state not poisoned");
                continue;
            }
            let State::Open { operations, .. } = &*state else {
                return;
            };

            // Submitting an earlier deadline wakes this wait. Every wakeup
            // recomputes the minimum under the same lock used by submission.
            state = match operations
                .values()
                .map(|operation| operation.deadline)
                .min()
            {
                Some(deadline) => {
                    self.changed
                        .wait_deadline(state, deadline)
                        .expect("session state not poisoned")
                        .0
                }
                None => self
                    .changed
                    .wait(state)
                    .expect("session state not poisoned"),
            };
        }
    }
}

impl Session {
    /// Creates the session and starts its writer and deadline threads.
    ///
    /// Only client sessions receive a stream closer, since
    /// [`Server`](super::Server) closes server streams.
    pub(super) fn start<W: Write + Send + 'static>(
        side: Side,
        clock: Clock,
        sender: transport::Sender<W>,
        stream_closer: Option<transport::Closer>,
        #[cfg(any(test, feature = "fuzz"))] workers: Arc<worker::Tracker>,
    ) -> Self {
        // Keep the stream clock with the session's queues and operations
        let session = Self {
            inner: Arc::new(SessionInner::new(
                side,
                clock,
                sender.log_id(),
                stream_closer,
                #[cfg(any(test, feature = "fuzz"))]
                workers.clone(),
            )),
        };

        // Start the writer independently of the thread reading the stream
        let inner = session.inner.clone();
        worker::spawn(
            "wire-writer",
            #[cfg(any(test, feature = "fuzz"))]
            &workers,
            move || inner.run_writer(sender),
        );

        // Expire operations even when their promises have no waiter
        let inner = session.inner.clone();
        worker::spawn(
            "wire-deadlines",
            #[cfg(any(test, feature = "fuzz"))]
            &workers,
            move || inner.run_deadlines(),
        );
        session
    }
}

impl State {
    /// Counts the pending operations and the queued messages of an open session.
    fn workload(&self) -> (usize, usize) {
        match self {
            Self::Open {
                operations,
                outgoing,
                incoming,
                ..
            } => (operations.len(), outgoing.len() + incoming.len()),
            Self::Closed(_) => (0, 0),
        }
    }

    /// Stops accepting messages and fails pending operations under the session lock.
    ///
    /// Returns the old queues to be dropped after releasing the lock. An already
    /// closed session keeps its first reason and returns `None`.
    fn close(
        &mut self,
        error: Error,
        now: Instant,
        notifications: &mut Notifications,
    ) -> Option<Self> {
        // Preserve the first closing reason
        if let Self::Closed(_) = self {
            return None;
        }

        // Publish failures now and let the caller run callbacks after unlocking
        let mut removed = std::mem::replace(self, Self::Closed(error.clone()));
        if let Self::Open { operations, .. } = &mut removed {
            for (_, operation) in operations.drain() {
                notifications.push(operation.fail(error.clone(), now));
            }
        }
        Some(removed)
    }

    /// Removes expired entries from `operations`, sends [`Error::Timeout`] to
    /// their promises, and discards any messages they still have in `outgoing`.
    fn expire(&mut self, now: Instant, notifications: &mut Notifications) {
        if let Self::Open {
            operations,
            outgoing,
            reserved_ids,
            ..
        } = self
        {
            // Remove each expired operation before publishing its terminal result
            let expired: Vec<_> = operations
                .iter()
                .filter(|(_, operation)| now >= operation.deadline)
                .map(|(key, _)| key.clone())
                .collect();
            for key in expired {
                notifications.push(
                    operations
                        .remove(&key)
                        .expect("expired operation held under lock")
                        .fail(Error::Timeout, now),
                );
            }

            // Only messages still in this queue can be discarded. Writes already
            // started keep running with their independent transport timeout.
            outgoing.retain(|outgoing| {
                let retained = operations.contains_key(&outgoing.operation.key);
                if !retained && let OutgoingBody::Reply { id, .. } = outgoing.body {
                    reserved_ids.remove(&id);
                }
                retained
            });
        }
    }
}

// Workerless sessions let tests drive time, requests and writes themselves
#[cfg(any(test, feature = "fuzz"))]
impl Session {
    /// Creates a server session without a stream or workers.
    #[cfg(test)]
    pub(super) fn fixture() -> Self {
        Self::fixture_for(Side::Server)
    }

    /// Creates a session for either side, without a stream or workers.
    #[cfg(test)]
    pub(super) fn fixture_for(side: Side) -> Self {
        Self::fixture_with_clock(side, crate::transport::testing::test_clock().clock())
    }

    /// Creates a workerless session whose operations use the supplied clock.
    pub(super) fn fixture_with_clock(side: Side, clock: Clock) -> Self {
        Self {
            inner: Arc::new(SessionInner::new(
                side,
                clock,
                LogId::default(),
                None,
                Arc::new(worker::Tracker::default()),
            )),
        }
    }
}

#[cfg(any(test, feature = "fuzz"))]
impl SessionInner {
    /// Arms a pause of the writer before it disconnects, so a test can connect a
    /// replacement session before letting the old writer finish.
    ///
    /// The returned receiver signals that the writer paused, and the sender
    /// releases it.
    pub(super) fn pause_disconnect(
        &self,
    ) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let (entered, observed) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        *self.disconnect_hook.lock().unwrap() = Some((entered, released));
        (observed, release)
    }

    /// Returns a receiver notified when the last `Arc<SessionInner>` is dropped.
    pub(super) fn watch_drop(&self) -> std::sync::mpsc::Receiver<()> {
        let (sender, receiver) = std::sync::mpsc::channel();
        *self.drop_hook.lock().unwrap() = Some(sender);
        receiver
    }

    /// Moves a fresh scenario session to its last allocatable request ID.
    ///
    /// # Panics
    ///
    /// Panics if the session is closed or has requests waiting for responses.
    pub(super) fn use_last_request_id(&self) {
        let mut state = self.state.lock().unwrap();
        let State::Open {
            next_id,
            outstanding,
            ..
        } = &mut *state
        else {
            panic!("open session required")
        };
        assert!(outstanding.is_empty());
        *next_id = Some(if self.side == Side::Client {
            u64::MAX
        } else {
            u64::MAX - 1
        });
    }

    /// Waits for the reader to remove the ID of a request sent earlier.
    ///
    /// Tests use this to leave a completed promise unread before changing limits
    /// or sessions.
    ///
    /// # Panics
    ///
    /// Panics if the session closes before the reader removes the ID.
    pub(super) fn wait_response(&self, id: u64) {
        // Wait until the reader removes the request or the session closes
        let mut state = self.state.lock().unwrap();
        while matches!(&*state, State::Open { outstanding, .. } if outstanding.contains_key(&id)) {
            state = self.changed.wait(state).unwrap();
        }

        // Require response processing before closure
        let State::Open { outstanding, .. } = &*state else {
            panic!("session closed before response fence");
        };
        assert!(
            !outstanding.contains_key(&id),
            "reader did not process response"
        );
    }

    /// Returns the sorted request IDs still waiting for peer responses.
    ///
    /// # Panics
    ///
    /// Panics if the session is closed.
    pub(super) fn outstanding_ids(&self) -> Vec<u64> {
        let state = self.state.lock().unwrap();
        let State::Open { outstanding, .. } = &*state else {
            panic!("open session required")
        };
        let mut ids: Vec<_> = outstanding.keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    /// Supplies a request directly to the fixture's admission path, independently
    /// of parity.
    ///
    /// The connection scenarios cover wire routing. A failed admission closes
    /// the session and returns its error.
    pub(super) fn inject_request(self: &Arc<Self>, id: u64, message: Message) -> Result<(), Error> {
        // Encode the request as the peer would send it
        let peer = match self.side {
            Side::Client => Side::Server,
            Side::Server => Side::Client,
        };
        let bytes = peer
            .encode(id, Ok(message))
            .expect("fixture request belongs to peer");
        let bytes = Bytes::from(bytes.into_boxed_slice());
        let header = self.side.decode_header(bytes.clone())?;

        // Admit it as the reader would, closing the session on failure
        let result = {
            let mut state = self.state.lock().expect("session state not poisoned");
            self.admit_request(&mut state, header, bytes)
        };
        self.changed.notify_all();
        if let Err(error) = &result {
            self.close(error.clone());
        }
        result
    }

    /// Returns the accepted request count and retained byte count for test checks.
    pub(super) fn inbound_usage(&self) -> (usize, usize) {
        let state = self.state.lock().expect("session state not poisoned");
        let requests = match &*state {
            State::Open { reserved_ids, .. } => reserved_ids.len(),
            State::Closed(_) => 0,
        };
        (requests, self.retained_bytes.load(Ordering::Relaxed))
    }

    /// Arms a one-shot notification for the next receive waiting on an empty queue.
    ///
    /// The notification is sent while holding the lock, immediately before the
    /// condition-variable wait releases it, so a later close cannot run too early.
    ///
    /// # Panics
    ///
    /// Panics if the fixture is closed or already has a queued request.
    pub(super) fn watch_recv_wait(&self) -> std::sync::mpsc::Receiver<()> {
        let (sender, receiver) = std::sync::mpsc::channel();
        let mut state = self.state.lock().expect("session state not poisoned");
        let State::Open {
            incoming,
            wait_hook,
            ..
        } = &mut *state
        else {
            panic!("only watch an open session receive");
        };
        assert!(incoming.is_empty());
        *wait_hook = Some(sender);
        receiver
    }
}

#[cfg(any(test, feature = "fuzz"))]
impl Drop for SessionInner {
    /// Notifies the test when the last `Arc<SessionInner>` is dropped.
    fn drop(&mut self) {
        if let Some(sender) = self.drop_hook.get_mut().unwrap().take() {
            let _ = sender.send(());
        }
    }
}

/// Checks callback lock release and session ownership bounds, and compiles the
/// client construction API.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{Notifications, SessionInner, Side};
    use crate::protocol::{self, Error, Session};
    use crate::transport::{Read, Stream, Verifier, Write};
    use std::fmt::Debug;

    /// Checks that the deadline worker releases both locks before notifying and
    /// parking again.
    #[test]
    fn test_deadline_callback_releases_locks_before_worker_parks() {
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        // Register a callback before starting the fixture's only worker
        let mut tester = crate::transport::testing::test_clock();
        let session = Session::fixture_with_clock(Side::Client, tester.clock());
        let deadline = tester.clock().now() + Duration::from_secs(5);
        let mut promise = session.requester().request(vec![1], deadline).unwrap();
        let notification = promise.notification_unlocked();
        let state = session.inner.clone();
        let (observed, receiver) = mpsc::channel();
        promise.notify(move || {
            let _ = observed.send((state.state.try_lock().is_ok(), notification()));
        });
        let state = session.inner.clone();
        let worker = thread::spawn(move || state.run_deadlines());

        // Reach the parked deadline without asking the promise to expire itself
        tester.wait_blocked(1);
        tester.advance_to(deadline);
        let unlocked = receiver.recv().unwrap();

        // Stop the worker and require unlocked notification with a timeout result
        session.close();
        worker.join().unwrap();
        assert_eq!(unlocked, (true, true));
        assert!(matches!(promise.wait::<Vec<u8>>(), Err(Error::Timeout)));
    }

    /// Checks that callbacks and their captures run with both locks free, on the
    /// thread responsible for notification.
    #[test]
    fn test_notification_releases_locks_on_every_settlement_path() {
        use crate::protocol::Promise;
        use std::sync::{Arc, mpsc};
        use std::thread::{self, ThreadId};
        use std::time::Duration;

        /// Capture checking callback execution and its own destruction against
        /// both locks.
        struct Capture {
            /// Session whose state must be unlocked during notification.
            session: Arc<SessionInner>,
            /// Probe attempting to acquire the promise's notification lock.
            notification: Box<dyn Fn() -> bool + Send>,
            /// Channel reporting lock availability and the executing thread.
            observed: mpsc::Sender<(bool, bool, ThreadId)>,
        }

        impl Capture {
            /// Reports lock availability from application code without blocking.
            fn check(&self) {
                let _ = self.observed.send((
                    self.session.state.try_lock().is_ok(),
                    (self.notification)(),
                    thread::current().id(),
                ));
            }
        }

        impl Drop for Capture {
            /// Checks locks again when the callback's captures are destroyed.
            fn drop(&mut self) {
                self.check();
            }
        }

        /// Registers on either side of settlement and checks both callback contexts.
        fn check<T>(
            mut promise: Promise<T>,
            session: Arc<SessionInner>,
            completed: bool,
            path: &str,
            settle: impl FnOnce() + Send,
        ) {
            // Prepare a capture that checks both application execution points
            let (observed, receiver) = mpsc::channel();
            let capture = Capture {
                session,
                notification: Box::new(promise.notification_unlocked()),
                observed,
            };

            // Settle on another thread to distinguish it from registration
            let expected = thread::scope(|scope| {
                if completed {
                    scope.spawn(settle).join().unwrap();
                    promise.notify(move || capture.check());
                    thread::current().id()
                } else {
                    promise.notify(move || capture.check());
                    let settling = scope.spawn(move || {
                        settle();
                        thread::current().id()
                    });
                    settling.join().unwrap()
                }
            });

            // Require one unlocked callback and one unlocked capture destructor
            let observations: Vec<_> = receiver.try_iter().collect();
            assert_eq!(
                observations,
                vec![(true, true, expected); 2],
                "{path}, completed={completed}"
            );
        }

        // Exercise result publication through each session path without workers
        for path in [
            "response",
            "response limit",
            "late response",
            "fixture response",
            "fixture error",
            "write failure",
            "late write",
            "reply",
            "close",
            "expire",
            "take outgoing",
            "next outgoing",
            "limits",
        ] {
            for completed in [false, true] {
                // Create a session whose deadlines follow a paused clock
                let mut tester = crate::transport::testing::test_clock();
                let clock = tester.clock();
                let deadline = clock.now() + Duration::from_secs(5);
                let mut session = Session::fixture_with_clock(Side::Client, clock);
                let inner = session.inner.clone();

                // Complete a real responder through the writer's success path
                if path == "reply" {
                    inner.inject_request(2, vec![1].into()).unwrap();
                    let (_, responder) = session.recv().unwrap();
                    let promise = responder.reply(vec![2], deadline).unwrap();
                    let outgoing = inner.take_outgoing().unwrap();
                    check(promise, inner, completed, path, move || {
                        outgoing.operation.record_write(Ok(()))
                    });
                    continue;
                }

                // Prepare requests and any admission limits before notification
                if path == "response limit" {
                    session = session.set_inbound_limits(1, 0);
                }
                if path == "limits" {
                    inner.inject_request(2, vec![1].into()).unwrap();
                }
                let promise = session.requester().request(vec![1], deadline).unwrap();
                let (id, outgoing) = inner.next_outgoing().unwrap();
                let next = if path == "next outgoing" {
                    Some(
                        session
                            .requester()
                            .request(vec![2], deadline + Duration::from_secs(5))
                            .unwrap(),
                    )
                } else {
                    None
                };

                // Publish through the chosen path and verify registration before
                // or after it
                check(promise, inner.clone(), completed, path, || match path {
                    "response" | "response limit" | "late response" => {
                        // Let response completion detect expiry without the
                        // deadline worker
                        if path == "late response" {
                            tester.advance_to(deadline);
                        }

                        // Route the response through the reader's publication path
                        let bytes = Side::Server.encode(id, Ok(vec![2].into())).unwrap();
                        let result = inner.handle_message(bytes);
                        assert_eq!(result.is_ok(), path != "response limit");
                    }
                    "fixture response" => outgoing.operation.record_response(Ok(vec![2].into())),
                    "fixture error" => {
                        inner.record_response(&outgoing.operation.key, Err(Error::Closed))
                    }
                    "write failure" => outgoing.operation.record_write(Err(Error::Closed)),
                    "late write" => {
                        tester.advance_to(deadline);
                        outgoing.operation.record_write(Ok(()));
                    }
                    "close" => inner.close(Error::Closed),
                    "limits" => {
                        let mut notifications = Notifications::default();
                        inner.set_inbound_limits(0, 1024, &mut notifications);
                    }
                    "expire" | "take outgoing" | "next outgoing" => {
                        tester.advance_to(deadline);
                        match path {
                            "expire" => inner.expire(),
                            "take outgoing" => assert!(inner.take_outgoing().is_none()),
                            "next outgoing" => assert!(inner.next_outgoing().is_some()),
                            _ => unreachable!(),
                        }
                    }
                    _ => unreachable!(),
                });
                drop(next);
            }
        }
    }

    /// Compiles client construction with verifier-specific information in the result.
    #[allow(dead_code)]
    fn connect<R, W, V>(stream: Stream<R, W>, verifier: &V) -> Result<(Session, V::Info), Error>
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
        V: Verifier,
    {
        protocol::connect(stream, verifier)
    }

    /// Checks the bounds required to move the session to an application thread
    /// and to print it.
    #[test]
    fn test_thread_capabilities() {
        /// Requires an owned value to be printable and transferable to a
        /// background thread.
        fn movable<T: Debug + Send + 'static>() {}
        movable::<Session>();
    }
}
