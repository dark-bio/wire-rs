// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Session state, request queues, and the reader, writer, and deadline workers.

use super::envelope::{Kind, Parity, Side};
use super::operation::{Body, Completion, Operation, Output, Token, Waiting};
use super::worker;
use super::{
    Closer, DEFAULT_ABANDONMENT_TIMEOUT, Error, Message, Promise, RemoteError, Requester,
    ReservedErrors, Responder,
};
use crate::transport::{self, Read, Stream, Verifier, Write};
use std::collections::{HashMap, HashSet, VecDeque};
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
    #[cfg(test)]
    let workers = Arc::new(worker::Tracker::default());
    let session = Session::start(
        Side::Client,
        sender,
        Some(client.closer()),
        #[cfg(test)]
        workers.clone(),
    );
    let shared = session.shared.clone();

    // Spawn the message reader that just funnels into the session
    worker::spawn(
        "wire-reader",
        #[cfg(test)]
        &workers,
        move || {
            loop {
                let result = client
                    .recv()
                    .map_err(Error::from)
                    .and_then(|bytes| shared.received(&bytes));
                if let Err(error) = result {
                    // Client receive/decode failure ends the session and closes
                    // its stream, releasing any other blocked transport I/O.
                    shared.close(error);
                    break;
                }
            }
        },
    );
    Ok((session, info))
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
/// A client session also closes its stream. A server session leaves its persistent
/// endpoint available for another handshake. Handles do not keep the session open.
/// The owner cannot be cloned; obtain requesters or closers for other threads:
///
/// ```compile_fail,E0599
/// use darkbio_wire::protocol::Session;
/// fn duplicate(session: Session) { let _ = session.clone(); }
/// ```
pub struct Session {
    /// Queues and pending operations shared with this session's workers.
    pub(super) shared: Arc<Shared>,
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
    pub fn set_abandonment_timeout(self, timeout: Duration) -> Self {
        {
            let mut state = self
                .shared
                .state
                .lock()
                .expect("session state not poisoned");
            if let State::Open {
                abandonment: abandonment_timeout,
                ..
            } = &mut *state
            {
                *abandonment_timeout = timeout;
            }
        }
        self
    }

    /// Returns a clonable requester bound to this session.
    pub fn requester(&self) -> Requester {
        Requester::new(Arc::downgrade(&self.shared))
    }

    /// Blocks for the next peer request and its [`Responder`]. Closing the session
    /// wakes this call with the error that closed it. The caller decides how to
    /// handle each request; this method does not run application callbacks.
    ///
    /// If another thread closes the session after `recv()` takes a request from
    /// the queue, `recv()` can still return it. Replying after closure returns an error.
    pub fn recv(&mut self) -> Result<(Message, Responder), Error> {
        self.shared.recv()
    }

    /// Returns a clonable handle for closing this session from another thread,
    /// including while its owner is blocked in [`Self::recv`].
    pub fn closer(&self) -> Closer {
        Closer::session(Arc::downgrade(&self.shared))
    }

    /// Closes this session. Repeated calls have no further effect. This does not
    /// wait for application jobs or guarantee the peer has observed closure.
    /// Discards queued messages and fails pending promises. A transport write
    /// already started may still finish, but cannot change a completed promise's
    /// result or affect a replacement session.
    pub fn close(&self) {
        self.shared.close(Error::Closed);
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
pub(super) struct Shared {
    /// Protects the queues, pending operations, and transition to `State::Ended`.
    state: Mutex<State>,
    /// Wakes `recv()`, the writer, and the deadline worker when `state` changes.
    changed: Condvar,
    /// Envelope direction and request parity, fixed for the whole session.
    side: Side,
    /// Closes the client's stream. Server sessions and tests without a stream
    /// leave this empty; a server's stream is closed by `Server`.
    shutdown: Option<transport::Closer>,
    /// Lets tests wait for worker threads to exit.
    #[cfg(test)]
    pub(super) workers: Arc<worker::Tracker>,
    /// Controlled protocol time for scenarios; production always uses Instant::now.
    #[cfg(test)]
    time: Mutex<Option<Instant>>,
    /// Notifies tests when the last `Arc<Shared>` is dropped.
    #[cfg(test)]
    released: Mutex<Option<std::sync::mpsc::Sender<()>>>,
    /// Pauses the writer before `sender.disconnect()` in replacement tests.
    #[cfg(test)]
    ending: Mutex<Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>>,
}

/// An open session's queues, or the error that closed the session.
enum State {
    /// Holds queued messages and pending operations. `close()` replaces this
    /// with `Ended`, then drops the queues after releasing the state lock.
    Open {
        /// Automatic reply lifetime selected when a responder is dropped.
        abandonment: Duration,
        /// Peer requests awaiting application receipt, paired with their request IDs.
        incoming: VecDeque<(u64, Message)>,
        /// Operations waiting to send a result to their promise. Each is removed
        /// before sending that result, so a promise is completed only once.
        operations: HashMap<Token, Operation>,
        /// Requests and replies waiting for the writer to take them.
        output: VecDeque<Output>,
        /// Next locally allocated ID, or exhaustion. Never wraps or reuses an ID.
        next_id: Option<u64>,
        /// Maps outgoing request IDs to operation tokens. Entries remain after
        /// a promise times out, until the peer responds or the session closes.
        outstanding: HashMap<u64, Token>,
        /// Incoming IDs held by the receive queue, responder, or queued reply.
        /// Taking a reply into the writer releases its ID: the peer can receive
        /// that reply and reuse the ID before our local flush returns.
        replying: HashSet<u64>,
        /// One-shot test notification sent under the state lock before waiting.
        #[cfg(test)]
        waiting: Option<std::sync::mpsc::Sender<()>>,
    },
    /// Keeps the first ending reason for every subsequent operation.
    Ended(Error),
}

impl Shared {
    /// Creates empty queues and pending-operation maps before starting workers.
    fn new(
        side: Side,
        shutdown: Option<transport::Closer>,
        #[cfg(test)] workers: Arc<worker::Tracker>,
    ) -> Self {
        Self {
            state: Mutex::new(State::Open {
                abandonment: DEFAULT_ABANDONMENT_TIMEOUT,
                incoming: VecDeque::new(),
                operations: HashMap::new(),
                output: VecDeque::new(),
                next_id: Some(Parity::from(side).first()),
                outstanding: HashMap::new(),
                replying: HashSet::new(),
                #[cfg(test)]
                waiting: None,
            }),
            changed: Condvar::new(),
            side,
            shutdown,
            #[cfg(test)]
            workers,
            #[cfg(test)]
            time: Mutex::new(None),
            #[cfg(test)]
            released: Mutex::new(None),
            #[cfg(test)]
            ending: Mutex::new(None),
        }
    }

    /// Takes the next request from `incoming` and creates its responder. If the
    /// queue is empty, waits on `changed`. Closing the session wakes the wait and
    /// returns the error stored in `State::Ended`.
    fn recv(self: &Arc<Self>) -> Result<(Message, Responder), Error> {
        let mut state = self.state.lock().expect("session state not poisoned");
        loop {
            match &mut *state {
                State::Ended(error) => return Err(error.clone()),
                State::Open {
                    incoming,
                    #[cfg(test)]
                    waiting,
                    ..
                } => {
                    if let Some((id, message)) = incoming.pop_front() {
                        return Ok((message, Responder::new(Arc::downgrade(self), id)));
                    }
                    #[cfg(test)]
                    if let Some(waiting) = waiting.take() {
                        let _ = waiting.send(());
                    }
                    state = self
                        .changed
                        .wait(state)
                        .expect("session state not poisoned");
                }
            }
        }
    }

    /// Replaces `Open` with `Ended` and fails pending promises under the state lock.
    /// Expired operations receive `Timeout`; the rest receive the closing error.
    /// Every call wakes `changed` and finishes any required stream shutdown.
    pub(super) fn close(&self, error: Error) {
        // Replace the state while holding the lock so no caller can add more work.
        // Keep the first closing error when several threads call close().
        let removed = {
            let mut state = self.state.lock().expect("session state not poisoned");
            match &*state {
                State::Ended(_) => None,
                State::Open { .. } => {
                    let now = self.now();
                    let mut removed = std::mem::replace(&mut *state, State::Ended(error.clone()));
                    if let State::Open { operations, .. } = &mut removed {
                        for (_, operation) in operations.drain() {
                            operation.fail(error.clone(), now);
                        }
                    }
                    Some(removed)
                }
            }
        };
        // Wake local waiters and drop queued work before adapter shutdown, which
        // may wait for transport I/O already running to return.
        self.changed.notify_all();
        drop(removed);
        if let Some(shutdown) = &self.shutdown {
            shutdown.close();
        }
    }

    /// Queues an `UNANSWERED` reply when a responder is dropped. The
    /// budget starts on entry, before acquiring the session lock, and includes
    /// queueing. An unrepresentable deadline expires immediately instead of
    /// panicking from `Drop`. The writer sends the reply later.
    pub(super) fn abandon(self: &Arc<Self>, id: u64) {
        let now = self.now();
        let timeout = {
            let state = self.state.lock().expect("session state not poisoned");
            match &*state {
                State::Open {
                    abandonment: abandonment_timeout,
                    ..
                } => *abandonment_timeout,
                State::Ended(_) => return,
            }
        };
        // Fix this reply's deadline at drop. Later changes to the session's
        // configuration do not retime already submitted work.
        let deadline = now.checked_add(timeout).unwrap_or(now);
        let _ = self.reply(
            id,
            Err(RemoteError {
                code: ReservedErrors::Unanswered as u64,
                msg: "request left unanswered".into(),
            }),
            deadline,
        );
    }

    /// Creates a promise and queues a request through `submit()`. If the deadline
    /// has already passed, the promise gets `Timeout` and nothing is queued.
    pub(super) fn request(
        self: &Arc<Self>,
        request: Message,
        deadline: Instant,
    ) -> Result<Promise<Message>, Error> {
        let (result, promise) = Promise::pair(Arc::downgrade(self), deadline);
        self.submit(
            Body::Request(request),
            Operation {
                deadline,
                waiting: Waiting::Answer(result),
            },
        )?;
        Ok(promise)
    }

    /// Queues a reply to `id` through `submit()`. Its promise waits for the write
    /// and flush to finish, or fails if its deadline expires first.
    pub(super) fn reply(
        self: &Arc<Self>,
        id: u64,
        result: Result<Message, RemoteError>,
        deadline: Instant,
    ) -> Result<Promise<()>, Error> {
        let (sender, promise) = Promise::pair(Arc::downgrade(self), deadline);
        self.submit(
            Body::Reply { id, result },
            Operation {
                deadline,
                waiting: Waiting::Write(sender),
            },
        )?;
        Ok(promise)
    }

    /// Adds an `Operation` and its `Output` while holding the state lock. A closed
    /// session returns its error directly; an expired deadline fails the promise.
    fn submit(self: &Arc<Self>, body: Body, operation: Operation) -> Result<(), Error> {
        {
            let mut state = self.state.lock().expect("session state not poisoned");
            let (operations, output, replying) = match &mut *state {
                State::Open {
                    operations,
                    output,
                    replying,
                    ..
                } => (operations, output, replying),
                State::Ended(error) => return Err(error.clone()),
            };
            let now = self.now();
            if now >= operation.deadline {
                if let Body::Reply { id, .. } = body {
                    replying.remove(&id);
                }
                operation.fail(Error::Timeout, now);
                return Ok(());
            }
            let token = Token::new();
            output.push_back(Output {
                body,
                #[cfg(test)]
                deadline: operation.deadline,
                completion: Completion {
                    session: Arc::downgrade(self),
                    token: token.clone(),
                },
            });
            operations.insert(token, operation);
        }
        self.changed.notify_all();
        Ok(())
    }

    /// Fails expired operations and removes their queued output. A promise waiter
    /// can call this if the deadline worker has not yet processed its timeout.
    /// Requests already sent remain in `outstanding` until answered or closed.
    pub(super) fn expire(&self) {
        let mut state = self.state.lock().expect("session state not poisoned");
        state.expire(self.now());
    }

    /// Returns the earliest pending operation deadline for scenario assertions.
    #[cfg(test)]
    pub(super) fn next_deadline(&self) -> Option<Instant> {
        let state = self.state.lock().expect("session state not poisoned");
        match &*state {
            State::Open { operations, .. } => operations
                .values()
                .map(|operation| operation.deadline)
                .min(),
            State::Ended(_) => None,
        }
    }

    /// Takes the next unexpired `Output` for tests that drive writing themselves.
    #[cfg(test)]
    pub(super) fn take_output(&self) -> Option<Output> {
        let mut state = self.state.lock().expect("session state not poisoned");
        state.expire(self.now());
        match &mut *state {
            State::Open { output, .. } => output.pop_front(),
            State::Ended(_) => None,
        }
    }

    /// Records a write result under the state lock. A successful request write
    /// leaves its operation waiting for an answer; a reply write completes it.
    pub(super) fn written(&self, token: &Token, result: Result<(), Error>) {
        let mut state = self.state.lock().expect("session state not poisoned");
        let State::Open { operations, .. } = &mut *state else {
            return;
        };
        let Some(operation) = operations.get(token) else {
            return;
        };
        let now = self.now();
        if now >= operation.deadline || result.is_err() {
            let operation = operations.remove(token).expect("operation held under lock");
            operation.fail(result.err().unwrap_or(Error::Timeout), now);
        } else if matches!(operation.waiting, Waiting::Write(_)) {
            let operation = operations.remove(token).expect("operation held under lock");
            let Waiting::Write(sender) = operation.waiting else {
                unreachable!()
            };
            let _ = sender.send(Ok(()));
        }
    }

    /// Supplies a peer answer in tests. If the operation is still pending,
    /// `Operation::answer()` checks its deadline and sends the result.
    #[cfg(test)]
    pub(super) fn answered(&self, token: &Token, result: Result<Message, Error>) {
        let mut state = self.state.lock().expect("session state not poisoned");
        let State::Open { operations, .. } = &mut *state else {
            return;
        };
        let Some(operation) = operations.remove(token) else {
            return;
        };
        operation.answer(result, self.now());
    }

    /// Returns `Instant::now()` or the test clock. Deadline checks use this while
    /// holding `state`; `abandon()` also calls it before waiting for that lock.
    fn now(&self) -> Instant {
        #[cfg(test)]
        if let Some(now) = *self.time.lock().expect("scenario clock not poisoned") {
            return now;
        }
        Instant::now()
    }

    /// Decodes outside the state lock, then matches an envelope only against this
    /// session. Unknown responses have no effect; duplicate active requests fail.
    pub(super) fn received(&self, bytes: &[u8]) -> Result<(), Error> {
        let (id, body) = self.side.decode(bytes)?;
        {
            let mut state = self.state.lock().expect("session state not poisoned");
            let State::Open {
                incoming,
                operations,
                outstanding,
                replying,
                ..
            } = &mut *state
            else {
                let State::Ended(error) = &*state else {
                    unreachable!()
                };
                return Err(error.clone());
            };
            match Kind::of(id, self.side.into()) {
                Kind::Request(_) => {
                    // Forbid requests having errors embedded into them
                    let message = body.map_err(|_| Error::Malformed)?;

                    // Reserve the request ID and reject duplicates
                    if !replying.insert(id) {
                        return Err(Error::Malformed);
                    }
                    incoming.push_back((id, message));
                }
                Kind::Response(_) => {
                    // Throw away an answered request, unknown ids are noops
                    if let Some(token) = outstanding.remove(&id)
                        && let Some(operation) = operations.remove(&token)
                    {
                        operation.answer(body.map_err(Error::Remote), self.now());
                    }
                }
            }
        }
        self.changed.notify_all();
        Ok(())
    }

    /// Waits for queued output or session closure. Assigns each request a wire ID
    /// and stores it in `outstanding` so `received()` can match the peer's reply.
    fn next_output(&self) -> Option<(u64, Output)> {
        let mut state = self.state.lock().expect("session state not poisoned");
        loop {
            // Remove expired messages before choosing the next one to send.
            state.expire(self.now());
            let State::Open {
                output,
                next_id,
                outstanding,
                replying,
                ..
            } = &mut *state
            else {
                return None;
            };
            if let Some(output) = output.pop_front() {
                let id = match &output.body {
                    Body::Request(_) => {
                        let id = next_id.expect("wire request IDs exhausted");
                        *next_id = id.checked_add(2);
                        // Store the ID before releasing the lock: a response can
                        // arrive before the outgoing send finishes locally.
                        outstanding.insert(id, output.completion.token.clone());
                        id
                    }
                    Body::Reply { id, .. } => {
                        // The peer may receive this reply and reuse the ID before
                        // our flush returns. Finishing this write must not remove
                        // a newer request that reuses the same ID.
                        replying.remove(id);
                        *id
                    }
                };
                return Some((id, output));
            }
            state = self
                .changed
                .wait(state)
                .expect("session state not poisoned");
        }
    }

    /// Sends queued messages through `sender`. Transport errors close the session;
    /// messages that cannot be encoded fail only their own promise.
    fn write(&self, sender: transport::Sender<impl Write>) {
        while let Some((id, output)) = self.next_output() {
            // next_output() released the state lock. The reader and deadline
            // worker can continue while encoding or sending this message blocks.
            let request = matches!(output.body, Body::Request(_));
            let body = match output.body {
                Body::Request(body) => Ok(body),
                Body::Reply { result, .. } => result,
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
            // Complete the operation identified by this token, if still pending.
            // A response or timeout may have completed it during the write.
            output.completion.written(result);
        }
        #[cfg(test)]
        if let Some((entered, released)) = self.ending.lock().unwrap().take() {
            let _ = entered.send(());
            let _ = released.recv();
        }
        // Disconnect the session this sender belongs to. The transport ignores
        // this call if a new handshake has already replaced that session.
        if let Err(error) = sender.disconnect() {
            tracing::debug!(%error, "could not notify retired protocol session");
        }
    }

    /// Expires pending operations even when no caller is waiting on a promise.
    /// Waits on `changed` until the next deadline or until new work arrives.
    fn deadlines(&self) {
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
        shutdown: Option<transport::Closer>,
        #[cfg(test)] workers: Arc<worker::Tracker>,
    ) -> Self {
        let session = Self {
            shared: Arc::new(Shared::new(
                side,
                shutdown,
                #[cfg(test)]
                workers.clone(),
            )),
        };
        let shared = session.shared.clone();
        worker::spawn(
            "wire-writer",
            #[cfg(test)]
            &workers,
            move || shared.write(sender),
        );
        let shared = session.shared.clone();
        worker::spawn(
            "wire-deadlines",
            #[cfg(test)]
            &workers,
            move || shared.deadlines(),
        );
        session
    }
}

impl State {
    /// Removes expired entries from `operations`, sends `Timeout` to their
    /// promises, and discards any messages they still have in `output`.
    fn expire(&mut self, now: Instant) {
        if let Self::Open {
            operations,
            output,
            replying,
            ..
        } = self
        {
            let expired: Vec<_> = operations
                .iter()
                .filter(|(_, operation)| now >= operation.deadline)
                .map(|(token, _)| token.clone())
                .collect();
            for token in expired {
                operations
                    .remove(&token)
                    .expect("expired operation held under lock")
                    .fail(Error::Timeout, now);
            }
            // Only messages still in this queue can be discarded. Writes already
            // started keep running with their independent transport timeout.
            output.retain(|output| {
                let retained = operations.contains_key(&output.completion.token);
                if !retained && let Body::Reply { id, .. } = output.body {
                    replying.remove(&id);
                }
                retained
            });
        }
    }
}

// These fixtures let tests drive time, incoming requests, and write results.
#[cfg(test)]
impl Session {
    /// Creates a session without a stream or workers for lifecycle scenarios.
    pub(super) fn new() -> Self {
        Self {
            shared: Arc::new(Shared::new(
                Side::Server,
                None,
                Arc::new(worker::Tracker::default()),
            )),
        }
    }
}

#[cfg(test)]
impl Shared {
    /// Pauses the writer before `sender.disconnect()`, so a test can connect a
    /// replacement session before letting the old writer finish.
    pub(super) fn hold_retirement(
        &self,
    ) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let (entered, observed) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        *self.ending.lock().unwrap() = Some((entered, released));
        (observed, release)
    }

    /// Returns a receiver notified when the last `Arc<Shared>` is dropped.
    pub(super) fn watch_release(&self) -> std::sync::mpsc::Receiver<()> {
        let (sender, receiver) = std::sync::mpsc::channel();
        *self.released.lock().unwrap() = Some(sender);
        receiver
    }

    /// Moves a fresh scenario session to its last allocatable request ID.
    pub(super) fn last_id(&self) {
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

    /// Returns the sorted request IDs still waiting for peer responses.
    pub(super) fn outstanding(&self) -> Vec<u64> {
        let state = self.state.lock().unwrap();
        let State::Open { outstanding, .. } = &*state else {
            panic!("open session required")
        };
        let mut ids: Vec<_> = outstanding.keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    /// Supplies a peer request in place of the transport reader and wakes receive.
    /// Holds `state` while checking for closure and inserting into `incoming`.
    pub(super) fn deliver(&self, id: u64, message: Message) -> Result<(), Error> {
        {
            let mut state = self.state.lock().expect("session state not poisoned");
            match &mut *state {
                State::Open { incoming, .. } => incoming.push_back((id, message)),
                State::Ended(error) => return Err(error.clone()),
            }
        }
        self.changed.notify_one();
        Ok(())
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
    pub(super) fn watch_recv(&self) -> std::sync::mpsc::Receiver<()> {
        let (sender, receiver) = std::sync::mpsc::channel();
        let mut state = self.state.lock().expect("session state not poisoned");
        let State::Open {
            incoming, waiting, ..
        } = &mut *state
        else {
            panic!("only watch an open session receive");
        };
        assert!(incoming.is_empty());
        *waiting = Some(sender);
        receiver
    }
}

#[cfg(test)]
impl Drop for Shared {
    /// Notifies the test when the last `Arc<Shared>` is dropped.
    fn drop(&mut self) {
        if let Some(sender) = self.released.get_mut().unwrap().take() {
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
