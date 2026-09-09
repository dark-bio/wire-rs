// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Session ownership, incoming requests and the shared retirement boundary.

use super::operation::{Body, Completion, Operation, Output, Token, Waiting};
use super::{Closer, Error, Message, Promise, RemoteError, Requester, ReservedErrors, Responder};
use crate::transport::{Read, Stream, Verifier, Write};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Establishes a client session, verifies the peer and returns the verifier's info.
/// Takes ownership of the stream and constructs the transport internally. Failure
/// closes the client stream; the application can open another stream and reconnect.
/// The verifier is only borrowed during this blocking call.
///
/// # Panics
/// API skeleton; not implemented yet.
pub fn connect<R, W, V>(_stream: Stream<R, W>, _verifier: &V) -> Result<(Session, V::Info), Error>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
    V: Verifier,
{
    todo!("protocol client connection")
}

/// Owner of one session and its incoming request queue.
///
/// Incoming requests use [`Message`], paired with a common responder. The
/// application selects the reply type; there is no static request/response pairing
/// table. The host/server role and envelope direction are handled internally.
///
/// Closing or dropping the owner retires this session, fails unresolved promises,
/// discards queued requests and wakes blocked receivers. Completed promises retain
/// their results. Running application jobs are not cancelled. Their handles cannot
/// reach or retire a successor session.
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
    /// State owned by this session; capabilities refer to it weakly.
    pub(super) shared: Arc<Shared>,
}

impl Session {
    /// Returns a clonable requester bound to this session.
    pub fn requester(&self) -> Requester {
        Requester::new(Arc::downgrade(&self.shared))
    }

    /// Blocks for the next peer request and its one-use reply capability.
    /// Session retirement wakes this call with the ending reason. Receiving does
    /// not run application callbacks; the caller decides how to dispatch work.
    ///
    /// A receive admitted before concurrent retirement may still return its
    /// request, whose responder remains bound to the retired session.
    pub fn recv(&mut self) -> Result<(Message, Responder), Error> {
        self.shared.recv()
    }

    /// Returns a clonable handle for closing this session from another thread,
    /// including while its owner is blocked in [`Self::recv`].
    pub fn closer(&self) -> Closer {
        Closer::session(Arc::downgrade(&self.shared))
    }

    /// Retires this session. Repeated calls have no further effect. This does not
    /// wait for application jobs or guarantee the peer has observed closure.
    /// Queued work is discarded and unresolved operations fail; this does not
    /// drain outstanding RPCs. Already-admitted transport I/O may still return,
    /// but cannot revive an operation or affect a replacement session.
    pub fn close(&self) {
        self.shared.retire(Error::Closed);
    }
}

impl Drop for Session {
    /// Retires the session even when requesters, responders or closers remain.
    fn drop(&mut self) {
        self.close();
    }
}

/// One session's synchronization boundary. Handles contain weak references to
/// this allocation, never a route through the endpoint's latest session.
pub(super) struct Shared {
    /// Serializes queue access and the one-way transition to the ending reason.
    state: Mutex<State>,
    /// Wakes receivers and future output/deadline services when state changes.
    changed: Condvar,
    /// Existing stream write budget, also used for automatic abandonment replies.
    timeout: Duration,
    /// Controlled protocol time for scenarios; production always uses Instant::now.
    #[cfg(test)]
    time: Mutex<Option<Instant>>,
}

/// A session is either open with owned work or permanently ended with one reason.
enum State {
    /// Accepts incoming requests and reply obligations until retirement.
    /// Queued work lives only in this variant; retirement removes it under the
    /// lock and disposes of it after unlocking.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "constructed by fixtures until transport integration"
        )
    )]
    Open {
        /// Peer requests awaiting application receipt, paired with their request IDs.
        incoming: VecDeque<(u64, Message)>,
        /// Unresolved local operations; only removal from this registry settles them.
        operations: HashMap<Token, Operation>,
        /// Output admitted locally but not yet taken by the independent writer.
        output: VecDeque<Output>,
        /// One-shot test notification sent under the state lock before waiting.
        #[cfg(test)]
        waiting: Option<std::sync::mpsc::Sender<()>>,
    },
    /// Keeps the first ending reason for every subsequent operation.
    Ended(Error),
}

impl Shared {
    /// Removes the next request and binds its responder under the retirement lock.
    /// An empty queue waits atomically with unlocking, so delivery and retirement
    /// cannot lose a wakeup. A retired session returns its original ending reason.
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

    /// Terminal transition ordered with registration, completion and output admission.
    /// All unresolved operations settle under this lock. Each uses the retirement
    /// time, giving already-expired operations Timeout and the rest the ending reason.
    /// Every closer notifies, including concurrent/repeated retirement calls.
    pub(super) fn retire(&self, error: Error) {
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
        self.changed.notify_all();
        drop(removed);
    }

    /// Transfers an unanswered responder into one automatic error output. The
    /// budget starts on entry, before acquiring the session lock, and includes
    /// queueing. An unrepresentable deadline expires immediately instead of
    /// panicking from Drop. No I/O, capacity wait or retry occurs here.
    pub(super) fn abandon(self: &Arc<Self>, id: u64) {
        let now = self.now();
        let deadline = now.checked_add(self.timeout).unwrap_or(now);
        let _ = self.reply(
            id,
            Err(RemoteError {
                code: ReservedErrors::Unanswered as u64,
                msg: "request left unanswered".into(),
            }),
            deadline,
        );
    }

    /// Registers an eager request and its sole result producer under the retirement
    /// lock, before any output service can take it. Expired submissions return an
    /// already-failed promise without entering the output queue.
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

    /// Transfers a responder's obligation into output under the retirement lock.
    /// The returned promise observes local write/flush, including a queued timeout.
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

    /// Atomically installs both the completion producer and its output obligation.
    /// Only an already-ended session refuses registration synchronously.
    fn submit(self: &Arc<Self>, body: Body, operation: Operation) -> Result<(), Error> {
        {
            let mut state = self.state.lock().expect("session state not poisoned");
            let State::Open {
                operations, output, ..
            } = &mut *state
            else {
                let State::Ended(error) = &*state else {
                    unreachable!()
                };
                return Err(error.clone());
            };
            let now = self.now();
            if now >= operation.deadline {
                operation.fail(Error::Timeout, now);
                return Ok(());
            }
            let token = Token::new();
            output.push_back(Output {
                body,
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

    /// Settles every elapsed operation and removes output that never started.
    /// The independent deadline service will call this even without any waiter.
    /// Expiring a transmitted request does not establish that remote work ended;
    /// remote credit obligations belong to the later flow-control implementation.
    pub(super) fn expire(&self) {
        let mut state = self.state.lock().expect("session state not poisoned");
        state.expire(self.now());
    }

    /// Inspects the nearest unresolved deadline for scenario assertions. The
    /// production timer's wait will need to hold the state lock until sleeping.
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

    /// Admits the next unexpired output under the retirement lock. The owned
    /// completion capability remains bound to this session after admission.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "serviced by the upcoming transport bridge")
    )]
    pub(super) fn take_output(&self) -> Option<Output> {
        let mut state = self.state.lock().expect("session state not poisoned");
        state.expire(self.now());
        match &mut *state {
            State::Open { output, .. } => output.pop_front(),
            State::Ended(_) => None,
        }
    }

    /// Accepts output completion under the same lock as expiry and retirement.
    /// Successful request output retains its operation for the eventual answer.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "reported by the upcoming transport bridge")
    )]
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

    /// Accepts a request answer strictly before its deadline. Removed operations
    /// make late completions inert without any separate current-session check.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "reported by the upcoming transport bridge")
    )]
    pub(super) fn answered(&self, token: &Token, result: Result<Message, Error>) {
        let mut state = self.state.lock().expect("session state not poisoned");
        let State::Open { operations, .. } = &mut *state else {
            return;
        };
        let Some(operation) = operations.remove(token) else {
            return;
        };
        let now = self.now();
        if now >= operation.deadline {
            operation.fail(Error::Timeout, now);
        } else {
            let Waiting::Answer(sender) = operation.waiting else {
                unreachable!("only a request completion accepts a peer answer");
            };
            let _ = sender.send(result);
        }
    }

    /// Reads protocol time. Outcome decisions call this while holding the session
    /// lock; abandonment also samples on entry to include time waiting for that lock.
    fn now(&self) -> Instant {
        #[cfg(test)]
        if let Some(now) = *self.time.lock().expect("scenario clock not poisoned") {
            return now;
        }
        Instant::now()
    }
}

impl State {
    /// Removes expired registrations and their unstarted output at one locked
    /// decision point. Each removed sender settles once, including dropped observers.
    fn expire(&mut self, now: Instant) {
        if let Self::Open {
            operations, output, ..
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
            output.retain(|output| operations.contains_key(&output.completion.token));
        }
    }
}

// Construction and message delivery remain internal test fixtures until the
// transport bridge supplies them. The lifecycle operations above are production
// code and are exercised through the public Session/Requester/Responder/Closer.
#[cfg(test)]
impl Session {
    /// Constructs an open session without physical I/O for lifecycle scenarios.
    pub(super) fn new(timeout: Duration) -> Self {
        Self {
            shared: Arc::new(Shared {
                state: Mutex::new(State::Open {
                    incoming: VecDeque::new(),
                    operations: HashMap::new(),
                    output: VecDeque::new(),
                    waiting: None,
                }),
                changed: Condvar::new(),
                timeout,
                time: Mutex::new(None),
            }),
        }
    }
}

#[cfg(test)]
impl Shared {
    /// Supplies a peer request in place of the transport reader and wakes receive.
    /// Queue insertion and retirement are ordered by the same state lock.
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

    /// Advances the scenario clock without servicing deadlines, allowing tests to
    /// model a delayed timer. Clock changes are ordered with all outcome decisions.
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
