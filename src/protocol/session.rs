// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Session state, request queues, and the reader, writer, and deadline workers.

use super::envelope::{Header, IncomingEnvelope, MessageKind, Parity, Side};
use super::operation::{
    OperationHandle, OperationKey, OutgoingBody, OutgoingMessage, PendingOperation, ResultSender,
};
use super::promise::PromiseResult;
use super::worker;
use super::{
    Closer, DEFAULT_ABANDONMENT_TIMEOUT, DEFAULT_MAX_INBOUND_BYTES, DEFAULT_MAX_INBOUND_REQUESTS,
    Error, Message, Promise, RemoteError, Requester, ReservedErrors, Responder,
};
use crate::transport::{self, Read, Stream, Verifier, Write};
use prost::bytes::Bytes;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Establishes a client session, verifies the peer and returns the verifier's info.
/// Takes ownership of the stream and constructs the transport internally. Failure
/// closes the client stream; the application can open another stream and reconnect.
/// The verifier is only borrowed during this blocking call.
/// Failure to start a required worker or an escaping worker panic aborts the process.
pub fn connect<R, W, V>(stream: Stream<R, W>, verifier: &V) -> Result<(Session, V::Info), Error>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
    V: Verifier,
{
    let mut client = transport::Client::new(stream);

    let (sender, info) = client.connect(verifier)?;
    #[cfg(any(test, feature = "fuzz"))]
    let workers = Arc::new(worker::Tracker::default());
    let session = Session::start(
        Side::Client,
        sender,
        Some(client.closer()),
        #[cfg(any(test, feature = "fuzz"))]
        workers.clone(),
    );
    let inner = session.inner.clone();

    worker::spawn(
        "wire-client-reader",
        #[cfg(any(test, feature = "fuzz"))]
        &workers,
        move || run_reader(client, inner),
    );
    Ok((session, info))
}

/// Receives and handles messages for one client session. The reader retains its
/// session state until it exits; closing the session shuts down the stream and
/// wakes a blocked transport read.
fn run_reader<R: Read, W: Write>(mut client: transport::Client<R, W>, session: Arc<SessionInner>) {
    loop {
        let result = client
            .recv()
            .map_err(Error::from)
            .and_then(|bytes| session.handle_message(bytes));
        if let Err(error) = result {
            // Receive and decode failures close this client session and its
            // stream, waking any other blocked transport I/O.
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
/// and wakes blocked `recv()` calls. Completed promises keep their results.
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
    /// Sets the lifetime of automatic `UNANSWERED` replies when responders are
    /// subsequently dropped. Defaults to [`DEFAULT_ABANDONMENT_TIMEOUT`]. Replies
    /// already queued keep their deadlines.
    ///
    /// The budget starts when the responder is dropped and includes queueing.
    /// Expiry discards a queued reply; a write already started still runs under the
    /// transport's independent timeout. Explicit request/reply deadlines are
    /// unaffected. Zero or an unrepresentable deadline expires immediately.
    /// Use [`super::Server::set_abandonment_timeout`] to also set the timeout for
    /// future server sessions.
    pub fn set_abandonment_timeout(self, timeout: Duration) -> Self {
        self.inner.set_abandonment_timeout(timeout);
        self
    }

    /// Sets the maximum accepted peer requests and buffered incoming bytes together.
    /// Defaults to [`DEFAULT_MAX_INBOUND_REQUESTS`] and [`DEFAULT_MAX_INBOUND_BYTES`].
    ///
    /// `requests` counts queued requests, held responders and queued replies.
    /// A slot is freed when the writer takes the reply or the reply is discarded.
    /// Zero refuses all peer requests but still allows responses to our requests.
    ///
    /// `bytes` counts the full encoded envelopes of queued requests and unread
    /// responses. `recv()`, `wait()` or dropping a response promise releases that
    /// space in the budget. Zero allows no buffered envelopes. Decoded application
    /// data, outgoing messages and transport buffers are excluded.
    ///
    /// Exceeding either limit closes this session with
    /// [`Error::InboundRequestLimitExceeded`] or [`Error::InboundByteLimitExceeded`].
    /// The reader never waits for space. Lowering a limit below usage also closes
    /// the session. Completed promises keep their results and bytes until read or
    /// dropped. Raising limits does not reopen a closed session.
    pub fn set_inbound_limits(self, requests: usize, bytes: usize) -> Self {
        self.inner.set_inbound_limits(requests, bytes);
        self
    }

    /// Returns a clonable requester bound to this session.
    pub fn requester(&self) -> Requester {
        Requester::new(Arc::downgrade(&self.inner))
    }

    /// Blocks for the next peer request and its [`Responder`]. Closing the session
    /// wakes this call with the error that closed it. The caller decides how to
    /// handle each request; this method does not run application callbacks.
    ///
    /// Taking a request removes its bytes from the inbound byte count before
    /// decoding it. The request still counts toward the inbound request limit
    /// while its responder is held.
    /// Invalid protobuf returns [`Error::Malformed`] and closes this session.
    ///
    /// If another thread closes the session after `recv()` takes a request from
    /// the queue, `recv()` can still return it. Replying after closure returns an error.
    pub fn recv(&mut self) -> Result<(Message, Responder), Error> {
        self.inner.recv()
    }

    /// Returns a clonable handle for closing this session from another thread,
    /// including while its owner is blocked in [`Self::recv`].
    pub fn closer(&self) -> Closer {
        Closer::session(Arc::downgrade(&self.inner))
    }

    /// Closes this session. Repeated calls have no further effect. This does not
    /// wait for application jobs or guarantee the peer has observed closure.
    /// Discards queued messages and fails pending promises. A transport write
    /// already started may still finish, but cannot change a completed promise's
    /// result or affect a replacement session.
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

/// Queues and pending operations for one session. Requesters, responders, and
/// closers hold weak references to this object, even after a new session connects.
pub(super) struct SessionInner {
    /// Protects the queues, pending operations, and transition to `State::Closed`.
    state: Mutex<State>,
    /// Wakes `recv()`, the writer, and the deadline worker when `state` changes.
    changed: Condvar,
    /// Incoming bytes held by queued requests and unread responses. Accepting
    /// messages and changing limits hold `state`. Consumers can release bytes
    /// without that lock. Unread promises keep this counter alive after closure.
    retained_bytes: Arc<AtomicUsize>,
    /// Envelope direction and request parity, fixed for the whole session.
    side: Side,
    /// Closes the client's stream. Server sessions and tests without a stream
    /// leave this empty; a server's stream is closed by `Server`.
    stream_closer: Option<transport::Closer>,
    /// Lets tests wait for worker threads to exit.
    #[cfg(any(test, feature = "fuzz"))]
    pub(super) workers: Arc<worker::Tracker>,
    /// Controlled protocol time for scenarios; production always uses Instant::now.
    #[cfg(any(test, feature = "fuzz"))]
    time: Mutex<Option<Instant>>,
    /// Notifies tests when the last `Arc<SessionInner>` is dropped.
    #[cfg(any(test, feature = "fuzz"))]
    drop_hook: Mutex<Option<std::sync::mpsc::Sender<()>>>,
    /// Pauses the writer before `sender.disconnect()` in replacement tests.
    #[cfg(any(test, feature = "fuzz"))]
    disconnect_hook: Mutex<Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>>,
}

/// An open session's queues, or the error that closed the session.
// Keep the same inline state layout in tests; the wait hook crosses Clippy's
// size threshold for the difference between variants.
#[cfg_attr(any(test, feature = "fuzz"), allow(clippy::large_enum_variant))]
enum State {
    /// Holds queued messages and pending operations. `close()` replaces this
    /// with `Closed`, then drops the queues after releasing the state lock.
    Open {
        /// Ceiling for accepted requests, including application-held responders.
        max_inbound_requests: usize,
        /// Ceiling for encoded requests and unread response promises.
        max_inbound_bytes: usize,
        /// Automatic reply lifetime selected when a responder is dropped.
        abandonment: Duration,

        /// Peer requests awaiting application receipt, paired with their request IDs.
        incoming: VecDeque<(u64, IncomingEnvelope)>,
        /// Rejects duplicate incoming IDs while the receive queue, responder,
        /// or queued reply holds them. Taking a reply into the writer or
        /// discarding an expired reply releases its ID. Release happens before
        /// writing: the peer can receive the reply and reuse its ID before our
        /// local flush returns.
        reserved_ids: HashSet<u64>,

        /// Requests and replies waiting for the writer to take them.
        outgoing: VecDeque<OutgoingMessage>,
        /// Next locally allocated ID, or exhaustion. Never wraps or reuses an ID.
        next_id: Option<u64>,
        /// Maps outgoing request IDs to operation keys. Entries remain after
        /// a promise times out, until the peer responds or the session closes.
        outstanding: HashMap<u64, OperationKey>,
        /// Operations waiting to send a result to their promise. Each is removed
        /// before sending that result, so a promise is completed only once.
        operations: HashMap<OperationKey, PendingOperation>,

        /// One-shot test notification sent under the state lock before waiting.
        #[cfg(any(test, feature = "fuzz"))]
        wait_hook: Option<std::sync::mpsc::Sender<()>>,
    },
    /// Keeps the first closing reason for every subsequent operation.
    Closed(Error),
}

impl SessionInner {
    /// Creates empty queues and pending-operation maps before starting workers.
    fn new(
        side: Side,
        stream_closer: Option<transport::Closer>,
        #[cfg(any(test, feature = "fuzz"))] workers: Arc<worker::Tracker>,
    ) -> Self {
        Self {
            state: Mutex::new(State::Open {
                max_inbound_requests: DEFAULT_MAX_INBOUND_REQUESTS,
                max_inbound_bytes: DEFAULT_MAX_INBOUND_BYTES,
                abandonment: DEFAULT_ABANDONMENT_TIMEOUT,

                incoming: VecDeque::new(),
                reserved_ids: HashSet::new(),

                outgoing: VecDeque::new(),
                next_id: Some(Parity::from(side).first()),
                outstanding: HashMap::new(),
                operations: HashMap::new(),

                #[cfg(any(test, feature = "fuzz"))]
                wait_hook: None,
            }),
            changed: Condvar::new(),
            retained_bytes: Arc::new(AtomicUsize::new(0)),
            side,
            stream_closer,
            #[cfg(any(test, feature = "fuzz"))]
            workers,
            #[cfg(any(test, feature = "fuzz"))]
            time: Mutex::new(None),
            #[cfg(any(test, feature = "fuzz"))]
            drop_hook: Mutex::new(None),
            #[cfg(any(test, feature = "fuzz"))]
            disconnect_hook: Mutex::new(None),
        }
    }

    /// Changes the timeout used when responders are dropped. Queued replies keep
    /// their original deadlines.
    pub(super) fn set_abandonment_timeout(&self, timeout: Duration) {
        let mut state = self.state.lock().expect("session state not poisoned");
        if let State::Open { abandonment, .. } = &mut *state {
            *abandonment = timeout;
        }
    }

    /// Updates both limits and closes the session if usage is too high. Holds the
    /// same lock used to accept incoming messages.
    pub(super) fn set_inbound_limits(&self, requests: usize, bytes: usize) {
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
            error.and_then(|error| state.close(error, self.now()))
        };
        if removed.is_some() {
            self.finish_close(removed);
        }
    }

    /// Counts the envelope's original bytes under the session lock. Decoding or
    /// dropping it later releases those bytes to this session's counter.
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

    /// Takes the next request from `incoming` and creates its responder. If the
    /// queue is empty, waits on `changed`. Closing the session wakes the wait and
    /// returns the error stored in `State::Closed`.
    /// Decodes after releasing the lock so the reader can keep receiving messages.
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
                        break (message, Responder::new(Arc::downgrade(self), id));
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
    /// Expired operations receive `Timeout`; the rest receive the closing error.
    /// Every call wakes `changed` and finishes any required stream shutdown.
    pub(super) fn close(&self, error: Error) {
        let removed = {
            let mut state = self.state.lock().expect("session state not poisoned");
            state.close(error, self.now())
        };
        self.finish_close(removed);
    }

    /// Drops queued work and wakes waiters outside the session lock.
    fn finish_close(&self, removed: Option<State>) {
        // Wake local waiters and drop queued work before adapter shutdown, which
        // may wait for transport I/O already running to return.
        self.changed.notify_all();
        drop(removed);
        if let Some(stream_closer) = &self.stream_closer {
            stream_closer.close();
        }
    }

    /// Queues an `UNANSWERED` reply when a responder is dropped. The
    /// budget starts on entry, before acquiring the session lock, and includes
    /// queueing. An unrepresentable deadline expires immediately instead of
    /// panicking from `Drop`. The writer sends the reply later.
    pub(super) fn reply_unanswered(self: &Arc<Self>, id: u64) {
        let now = self.now();
        let timeout = {
            let state = self.state.lock().expect("session state not poisoned");
            match &*state {
                State::Open {
                    abandonment: abandonment_timeout,
                    ..
                } => *abandonment_timeout,
                State::Closed(_) => return,
            }
        };
        // Fix this reply's deadline at drop. Later changes to the session's
        // configuration do not retime already submitted work.
        let deadline = now.checked_add(timeout).unwrap_or(now);
        let _ = self.reply(
            id,
            Err(RemoteError::reserved(
                ReservedErrors::Unanswered,
                "request left unanswered",
            )),
            deadline,
        );
    }

    /// Creates a promise and queues a request through `enqueue()`. If the deadline
    /// has already passed, the promise gets `Timeout` and nothing is queued.
    pub(super) fn request(
        self: &Arc<Self>,
        request: Message,
        deadline: Instant,
    ) -> Result<Promise<Message>, Error> {
        let (sender, promise) = Promise::pair(Arc::downgrade(self), deadline);
        self.enqueue(
            OutgoingBody::Request(request),
            PendingOperation {
                deadline,
                sender: ResultSender::Response(sender),
            },
        )?;
        Ok(promise)
    }

    /// Queues a reply to `id` through `enqueue()`. Its promise waits for the write
    /// and flush to finish, or fails if its deadline expires first.
    pub(super) fn reply(
        self: &Arc<Self>,
        id: u64,
        result: Result<Message, RemoteError>,
        deadline: Instant,
    ) -> Result<Promise<()>, Error> {
        let (sender, promise) = Promise::pair(Arc::downgrade(self), deadline);
        self.enqueue(
            OutgoingBody::Reply { id, result },
            PendingOperation {
                deadline,
                sender: ResultSender::Write(sender),
            },
        )?;
        Ok(promise)
    }

    /// Adds a `PendingOperation` and its `OutgoingMessage` under the state lock.
    /// A closed session returns its error directly; an expired deadline fails
    /// the promise.
    fn enqueue(
        self: &Arc<Self>,
        body: OutgoingBody,
        operation: PendingOperation,
    ) -> Result<(), Error> {
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
            let now = self.now();
            if now >= operation.deadline {
                if let OutgoingBody::Reply { id, .. } = body {
                    reserved_ids.remove(&id);
                }
                operation.fail(Error::Timeout, now);
                return Ok(());
            }
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
        self.changed.notify_all();
        Ok(())
    }

    /// Fails expired operations and removes their queued messages. A promise waiter
    /// can call this if the deadline worker has not yet processed its timeout.
    /// Requests already sent remain in `outstanding` until answered or closed.
    pub(super) fn expire(&self) {
        let mut state = self.state.lock().expect("session state not poisoned");
        state.expire(self.now());
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

    /// Takes the next unexpired `OutgoingMessage` for tests that drive writing themselves.
    #[cfg(any(test, feature = "fuzz"))]
    pub(super) fn take_outgoing(&self) -> Option<OutgoingMessage> {
        let mut state = self.state.lock().expect("session state not poisoned");
        state.expire(self.now());
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

    /// Records a write result under the state lock. A successful request write
    /// leaves its operation waiting for an answer; a reply write completes it.
    pub(super) fn record_write(&self, key: &OperationKey, result: Result<(), Error>) {
        let mut state = self.state.lock().expect("session state not poisoned");
        let State::Open { operations, .. } = &mut *state else {
            return;
        };
        let Some(operation) = operations.get(key) else {
            return;
        };
        let now = self.now();
        if now >= operation.deadline || result.is_err() {
            let operation = operations.remove(key).expect("operation held under lock");
            operation.fail(result.err().unwrap_or(Error::Timeout), now);
        } else if matches!(operation.sender, ResultSender::Write(_)) {
            let operation = operations.remove(key).expect("operation held under lock");
            let ResultSender::Write(sender) = operation.sender else {
                unreachable!()
            };
            let _ = sender.send(Ok(PromiseResult::Written));
        }
    }

    /// Supplies a response to a fixture operation without depending on wire IDs.
    /// The fixture still encodes and retains bytes, matching real promise behavior.
    #[cfg(any(test, feature = "fuzz"))]
    pub(super) fn record_response(
        self: &Arc<Self>,
        key: &OperationKey,
        result: Result<Message, Error>,
    ) {
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
                operation.fail(error, self.now());
                return;
            }
        };
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
        let result = operation.complete_response(self.now(), || {
            self.retain_incoming(bytes, header, *max_inbound_bytes)
        });
        drop(state);
        if let Err(error) = result {
            self.close(error);
        }
    }

    /// Returns `Instant::now()` or the test clock. Deadline checks use this while
    /// holding `state`; `reply_unanswered()` also calls it before waiting for that lock.
    fn now(&self) -> Instant {
        #[cfg(any(test, feature = "fuzz"))]
        if let Some(now) = *self.time.lock().expect("scenario clock not poisoned") {
            return now;
        }
        Instant::now()
    }

    /// Checks the outer envelope and routes its original bytes. `recv()` and
    /// `wait()` decode nested payloads. Unknown and late responses are discarded
    /// without decoding their bodies. The reader closes the session on error.
    pub(super) fn handle_message(self: &Arc<Self>, bytes: Vec<u8>) -> Result<(), Error> {
        let bytes = Bytes::from(bytes.into_boxed_slice());
        let header = self.side.decode_header(bytes.clone())?;
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
                    self.queue_request(&mut state, header, bytes)?;
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
                    if let Some(key) = outstanding.remove(&header.id)
                        && let Some(operation) = operations.remove(&key)
                    {
                        operation.complete_response(self.now(), || {
                            self.retain_incoming(bytes, header, *max_inbound_bytes)
                        })?;
                    }
                }
            }
        }
        self.changed.notify_all();
        Ok(())
    }

    /// Reserves a request slot and bytes under the session lock. If either limit
    /// is exceeded, the queue stays untouched. Never waits for the application.
    fn queue_request(
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
        let id = header.id;
        if reserved_ids.contains(&id) {
            return Err(self.side.malformed(
                Some(header),
                bytes.len(),
                "envelope",
                "duplicate request ID",
            ));
        }
        if reserved_ids.len() >= *max_inbound_requests {
            tracing::warn!(
                "inbound request limit exceeded (id: {id}, used: {}, limit: {max_inbound_requests})",
                reserved_ids.len(),
            );
            return Err(Error::InboundRequestLimitExceeded(*max_inbound_requests));
        }
        let message = self.retain_incoming(bytes, header, *max_inbound_bytes)?;
        reserved_ids.insert(id);
        incoming.push_back((id, message));
        Ok(())
    }

    /// Waits for and takes the next queued message, or returns `None` on closure.
    /// Under the state lock, assigns each request an ID and records its operation
    /// key in `outstanding`, so `handle_message()` can match the peer's response
    /// even if it arrives before the write finishes.
    pub(super) fn next_outgoing(&self) -> Option<(u64, OutgoingMessage)> {
        let mut state = self.state.lock().expect("session state not poisoned");
        loop {
            // Remove expired messages before choosing the next one to send.
            state.expire(self.now());
            let State::Open {
                outgoing,
                next_id,
                outstanding,
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
                        // Store the ID before releasing the lock: a response can
                        // arrive before the outgoing send finishes locally.
                        outstanding.insert(id, outgoing.operation.key.clone());
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
            state = self
                .changed
                .wait(state)
                .expect("session state not poisoned");
        }
    }

    /// Sends queued messages through `sender`. Transport errors close the session;
    /// messages that cannot be encoded fail only their own promise.
    fn run_writer(&self, sender: transport::Sender<impl Write>) {
        while let Some((id, outgoing)) = self.next_outgoing() {
            // next_outgoing() released the state lock. The reader and deadline
            // worker can continue while encoding or sending this message blocks.
            let request = matches!(outgoing.body, OutgoingBody::Request(_));
            let body = match outgoing.body {
                OutgoingBody::Request(body) => Ok(body),
                OutgoingBody::Reply { result, .. } => result,
            };
            let result = self
                .side
                .encode(id, body)
                .and_then(|bytes| sender.send(&bytes).map_err(Error::from));
            if let Err(Error::Transport(error)) = &result {
                // Wire failure ends the session even if this operation's promise
                // has already timed out while the transport write was blocked.
                self.close(Error::Transport(error.clone()));
                break;
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
        #[cfg(any(test, feature = "fuzz"))]
        if let Some((entered, released)) = self.disconnect_hook.lock().unwrap().take() {
            let _ = entered.send(());
            let _ = released.recv();
        }
        // Disconnect the session this sender belongs to. The transport ignores
        // this call if a new handshake has already replaced that session.
        if let Err(error) = sender.disconnect() {
            tracing::debug!("could not send protocol session disconnect: {error}");
        }
    }

    /// Expires pending operations even when no caller is waiting on a promise.
    /// Waits on `changed` until the next deadline or until new work arrives.
    fn run_deadlines(&self) {
        let mut state = self.state.lock().expect("session state not poisoned");
        loop {
            state.expire(self.now());
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
                        .wait_timeout(state, deadline.saturating_duration_since(self.now()))
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
    /// Creates the session and starts its writer and deadline threads. Only
    /// client sessions receive a stream closer; `Server` closes server streams.
    pub(super) fn start<W: Write + Send + 'static>(
        side: Side,
        sender: transport::Sender<W>,
        stream_closer: Option<transport::Closer>,
        #[cfg(any(test, feature = "fuzz"))] workers: Arc<worker::Tracker>,
    ) -> Self {
        let session = Self {
            inner: Arc::new(SessionInner::new(
                side,
                stream_closer,
                #[cfg(any(test, feature = "fuzz"))]
                workers.clone(),
            )),
        };
        let inner = session.inner.clone();
        worker::spawn(
            "wire-writer",
            #[cfg(any(test, feature = "fuzz"))]
            &workers,
            move || inner.run_writer(sender),
        );
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
    /// Stops accepting messages and fails pending operations under the session lock.
    /// Returns the old queues to be dropped after releasing the lock.
    fn close(&mut self, error: Error, now: Instant) -> Option<Self> {
        if let Self::Closed(_) = self {
            return None;
        }
        let mut removed = std::mem::replace(self, Self::Closed(error.clone()));
        if let Self::Open { operations, .. } = &mut removed {
            for (_, operation) in operations.drain() {
                operation.fail(error.clone(), now);
            }
        }
        Some(removed)
    }

    /// Removes expired entries from `operations`, sends `Timeout` to their
    /// promises, and discards any messages they still have in `outgoing`.
    fn expire(&mut self, now: Instant) {
        if let Self::Open {
            operations,
            outgoing,
            reserved_ids,
            ..
        } = self
        {
            let expired: Vec<_> = operations
                .iter()
                .filter(|(_, operation)| now >= operation.deadline)
                .map(|(key, _)| key.clone())
                .collect();
            for key in expired {
                operations
                    .remove(&key)
                    .expect("expired operation held under lock")
                    .fail(Error::Timeout, now);
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

// These fixtures let tests drive time, incoming requests, and write results.
#[cfg(any(test, feature = "fuzz"))]
impl Session {
    /// Creates a session without a stream or workers for lifecycle scenarios.
    pub(super) fn fixture() -> Self {
        Self::fixture_for(Side::Server)
    }

    /// Creates either envelope direction without a stream or workers.
    pub(super) fn fixture_for(side: Side) -> Self {
        Self {
            inner: Arc::new(SessionInner::new(
                side,
                None,
                Arc::new(worker::Tracker::default()),
            )),
        }
    }
}

#[cfg(any(test, feature = "fuzz"))]
impl SessionInner {
    /// Pauses the writer before `sender.disconnect()`, so a test can connect a
    /// replacement session before letting the old writer finish.
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

    /// Waits for the reader to remove a previously sent request's ID. Tests use
    /// this to leave a completed promise unread before changing limits or sessions.
    pub(super) fn wait_response(&self, id: u64) {
        let state = self.state.lock().unwrap();
        let (state, _) = self.changed.wait_timeout_while(state, Duration::from_secs(3), |state| {
            matches!(state, State::Open { outstanding, .. } if outstanding.contains_key(&id))
        }).unwrap();
        let State::Open { outstanding, .. } = &*state else {
            panic!("session closed before response fence");
        };
        assert!(
            !outstanding.contains_key(&id),
            "reader did not process response"
        );
    }

    /// Returns the sorted request IDs still waiting for peer responses.
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
    /// of parity (wire routing is covered by the connection scenarios).
    pub(super) fn inject_request(self: &Arc<Self>, id: u64, message: Message) -> Result<(), Error> {
        let peer = match self.side {
            Side::Client => Side::Server,
            Side::Server => Side::Client,
        };
        let bytes = peer
            .encode(id, Ok(message))
            .expect("fixture request belongs to peer");
        let bytes = Bytes::from(bytes.into_boxed_slice());
        let header = self.side.decode_header(bytes.clone())?;
        let result = {
            let mut state = self.state.lock().expect("session state not poisoned");
            self.queue_request(&mut state, header, bytes)
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

    /// Advances the test clock without calling `expire()`, so tests can deliver
    /// results after a deadline but before the timeout has been processed.
    pub(super) fn set_time(&self, now: Instant) {
        let _state = self.state.lock().expect("session state not poisoned");
        let mut time = self.time.lock().expect("scenario clock not poisoned");
        assert!(
            time.is_none_or(|previous| now >= previous),
            "clock cannot go backwards"
        );
        *time = Some(now);
    }

    /// Restores wall-clock time for scenarios that exercise the waiter's real timer.
    pub(super) fn use_realtime(&self) {
        let _state = self.state.lock().expect("session state not poisoned");
        *self.time.lock().expect("scenario clock not poisoned") = None;
    }

    /// Arms a one-shot notification for the next receive waiting on an empty queue.
    /// The notification is sent while holding the lock, immediately before the
    /// condition-variable wait releases it, so a later close cannot run too early.
    ///
    /// # Panics
    /// The fixture must still be open and have no queued request.
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

/// Checks session ownership bounds and compiles the client construction API.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::protocol::{self, Error, Session};
    use crate::transport::{Read, Stream, Verifier, Write};

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

    /// Checks the send bound required to transfer ownership to an application thread.
    #[test]
    fn test_thread_capabilities() {
        /// Requires an owned value to be transferable to a background thread.
        fn movable<T: Send + 'static>() {}
        movable::<Session>();
    }
}
