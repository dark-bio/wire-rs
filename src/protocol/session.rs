// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Session ownership, incoming requests and the shared retirement boundary.

use super::{Closer, Error, Message, Requester, Responder};
use crate::transport::{Read, Stream, Verifier, Write};
use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

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
    /// Wakes receivers when a request arrives or the session ends.
    changed: Condvar,
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
        /// Request IDs requiring abandonment replies from the future output worker.
        abandoned: VecDeque<u64>,
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

    /// Terminal transition ordered with receive and abandonment admission.
    /// Every caller notifies, including a concurrent/repeated retire: it must not
    /// depend on the first caller reaching its notification before being delayed.
    pub(super) fn retire(&self, error: Error) {
        let removed = {
            let mut state = self.state.lock().expect("session state not poisoned");
            match &*state {
                State::Ended(_) => None,
                State::Open { .. } => Some(std::mem::replace(&mut *state, State::Ended(error))),
            }
        };
        self.changed.notify_all();
        drop(removed);
    }

    /// Schedules an abandonment in its original session. No user code or I/O
    /// runs here. The reply execution chunk will service these obligations.
    pub(super) fn abandon(&self, id: u64) {
        let mut state = self.state.lock().expect("session state not poisoned");
        if let State::Open { abandoned, .. } = &mut *state {
            abandoned.push_back(id);
        }
    }

    /// Request registration will live under this same lock as retirement. Until
    /// that chunk is implemented, only refusal by an ended session is supported.
    ///
    /// # Panics
    /// Open-session registration and promise completion are not implemented yet.
    pub(super) fn request(
        &self,
        _request: Message,
        _deadline: Instant,
    ) -> Result<super::Pending, Error> {
        let state = self.state.lock().expect("session state not poisoned");
        if let State::Ended(error) = &*state {
            return Err(error.clone());
        }
        // The remaining branch is a skeleton, not admission. Unlock before its
        // intentional panic so destroying the owner does not encounter poison.
        drop(state);
        todo!("protocol request registration and completion")
    }

    /// Registers a reply for a request ID belonging to this session. Only refusal
    /// after retirement is implemented; successful registration will transfer the
    /// responder's obligation to output under the same lock as retirement.
    ///
    /// # Panics
    /// Open-session registration and promise completion are not implemented yet.
    pub(super) fn reply(
        &self,
        _id: u64,
        _result: Result<Message, super::RemoteError>,
        _deadline: Instant,
    ) -> Result<super::WritePending, Error> {
        let state = self.state.lock().expect("session state not poisoned");
        if let State::Ended(error) = &*state {
            return Err(error.clone());
        }
        drop(state);
        todo!("protocol reply registration and completion")
    }
}

// Construction and message delivery remain internal test fixtures until the
// transport bridge supplies them. The lifecycle operations above are production
// code and are exercised through the public Session/Requester/Responder/Closer.
#[cfg(test)]
impl Session {
    /// Constructs an open session without physical I/O for lifecycle scenarios.
    pub(super) fn new() -> Self {
        Self {
            shared: Arc::new(Shared {
                state: Mutex::new(State::Open {
                    incoming: VecDeque::new(),
                    abandoned: VecDeque::new(),
                    waiting: None,
                }),
                changed: Condvar::new(),
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

    /// Removes recorded abandonment obligations for scenario assertions. Ended
    /// sessions have already discarded them and therefore return an empty list.
    pub(super) fn take_abandoned(&self) -> Vec<u64> {
        let mut state = self.state.lock().expect("session state not poisoned");
        match &mut *state {
            State::Open { abandoned, .. } => abandoned.drain(..).collect(),
            State::Ended(_) => Vec::new(),
        }
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
