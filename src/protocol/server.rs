// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Persistent endpoint ownership and ordered publication of successive sessions.

use super::session;
use super::{Closer, Error, Session};
use crate::transport::{Attester, Read, Stream, Write};
use darkbio_crypto::xdsa;
use std::sync::{Arc, Condvar, Mutex, Weak};
#[cfg(test)]
use std::time::Duration;

/// Owner of a persistent server stream, accepting successive sessions.
/// Closing or dropping the endpoint ends its active session and shuts down the
/// physical stream. Closing an individual [`Session`] keeps this owner and
/// its stream available for another handshake.
pub struct Server {
    /// Endpoint state retained independently of any accepted session owner.
    pub(super) shared: Arc<Shared>,
}

impl Server {
    /// Takes ownership of a stream and constructs its transport internally.
    /// The attester supplies the current device attestation for each handshake.
    ///
    /// # Panics
    /// API skeleton; not implemented yet.
    pub fn new<R, W, A>(_stream: Stream<R, W>, _signer: xdsa::SecretKey, _attester: A) -> Self
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
        A: Attester + Send + 'static,
    {
        todo!("protocol server construction")
    }

    /// Blocks until a session is established or the endpoint ends. Recoverable
    /// handshake failures leave the stream available for another attempt. A
    /// replacement session retires its predecessor; old handles remain bound to it.
    pub fn accept(&mut self) -> Result<Session, Error> {
        let mut state = self
            .shared
            .state
            .lock()
            .expect("endpoint state not poisoned");
        loop {
            match &mut *state {
                State::Ended { reason, .. } => return Err(reason.clone()),
                State::Open {
                    pending,
                    #[cfg(test)]
                    waiting,
                    ..
                } => {
                    if let Some(session) = pending.take() {
                        return Ok(session);
                    }
                    #[cfg(test)]
                    if let Some(waiting) = waiting.take() {
                        let _ = waiting.send(());
                    }
                    state = self
                        .shared
                        .changed
                        .wait(state)
                        .expect("endpoint state not poisoned");
                }
            }
        }
    }

    /// Returns a clonable handle for closing this endpoint from another thread,
    /// including while its owner is blocked in [`Self::accept`].
    pub fn closer(&self) -> Closer {
        Closer::server(Arc::downgrade(&self.shared))
    }

    /// Permanently closes this endpoint and its active session, wakes blocked
    /// acceptance and receive calls, and fails unresolved operations. Idempotent.
    /// Does not join application jobs or guarantee the peer has observed closure.
    pub fn close(&self) {
        self.shared.retire(Error::Closed);
    }
}

impl Drop for Server {
    /// Ends the endpoint and its attached session even when handles remain.
    fn drop(&mut self) {
        self.close();
    }
}

/// Endpoint lifetime and the at-most-one session waiting for accept. The reader
/// will publish replacements in transport order. Accepted sessions own themselves;
/// the endpoint retains only a weak reference for endpoint shutdown.
pub(super) struct Shared {
    /// Orders acceptance, publication and permanent endpoint retirement.
    state: Mutex<State>,
    /// Wakes acceptance when a session is published or the endpoint ends.
    changed: Condvar,
}

/// An endpoint accepts sessions until it permanently retains an ending reason.
enum State {
    /// Holds the attached session and any owner not yet taken by acceptance.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "constructed by fixtures until transport integration"
        )
    )]
    Open {
        /// Weak shutdown target, retained even after acceptance takes the owner.
        session: Weak<session::Shared>,
        /// At most one unaccepted owner; replacement retires and releases its predecessor.
        pending: Option<Session>,
        /// One-shot test notification sent under the endpoint lock before waiting.
        #[cfg(test)]
        waiting: Option<std::sync::mpsc::Sender<()>>,
    },
    /// Retains the original target weakly so every concurrent or repeated close
    /// can finish its logical retirement without depending on the first closer.
    Ended {
        /// First reason the endpoint ended; later closes cannot replace it.
        reason: Error,
        /// Exact session attached at endpoint retirement, never a successor.
        session: Weak<session::Shared>,
    },
}

impl Shared {
    /// Refuses publication/acceptance before retiring the attached session.
    /// Session retirement and dropping pending owners happen outside this lock;
    /// no endpoint/session locks are ever nested.
    pub(super) fn retire(&self, error: Error) {
        let (session, reason, pending) = {
            let mut state = self.state.lock().expect("endpoint state not poisoned");
            match &mut *state {
                State::Ended { reason, session } => (session.upgrade(), reason.clone(), None),
                State::Open {
                    session, pending, ..
                } => {
                    let session = session.clone();
                    let pending = pending.take();
                    *state = State::Ended {
                        reason: error.clone(),
                        session: session.clone(),
                    };
                    (session.upgrade(), error, pending)
                }
            }
        };
        if let Some(session) = session {
            session.retire(reason);
        }
        self.changed.notify_all();
        drop(pending);
    }
}

/// Single publisher used by the lifecycle scenarios until the transport reader
/// is connected. Mutable access orders replacement: retire A before publishing B.
#[cfg(test)]
pub(super) struct Sessions {
    /// Publication destination, without extending the endpoint owner's lifetime.
    endpoint: Weak<Shared>,
    /// Stream write budget copied into each newly published session.
    write_timeout: Duration,
}

#[cfg(test)]
impl Server {
    /// Constructs an endpoint and its sole session publisher without physical I/O.
    pub(super) fn pair(write_timeout: Duration) -> (Self, Sessions) {
        let shared = Arc::new(Shared {
            state: Mutex::new(State::Open {
                session: Weak::new(),
                pending: None,
                waiting: None,
            }),
            changed: Condvar::new(),
        });
        let sessions = Sessions {
            endpoint: Arc::downgrade(&shared),
            write_timeout,
        };
        (Self { shared }, sessions)
    }
}

#[cfg(test)]
impl Sessions {
    /// Retires the previous session before publishing a replacement for acceptance.
    /// Mutable access serializes publications. Endpoint closure may interleave,
    /// but each retirement holds its exact target and publication checks closure
    /// under the same lock that installs the new owner. The returned weak handle
    /// lets scenarios deliver only to this particular session.
    pub(super) fn open(&mut self) -> Result<Weak<session::Shared>, Error> {
        let endpoint = self.endpoint.upgrade().ok_or(Error::Closed)?;
        let previous = {
            let state = endpoint.state.lock().expect("endpoint state not poisoned");
            match &*state {
                State::Ended { reason, .. } => return Err(reason.clone()),
                State::Open { session, .. } => session.upgrade(),
            }
        };
        // This is an owned target, not a current-session predicate. Concurrent
        // endpoint closure may retire it too, but it can never become session B.
        if let Some(previous) = previous {
            previous.retire(crate::transport::Error::SessionReset.into());
        }
        let session = Session::new(self.write_timeout);
        let incoming = Arc::downgrade(&session.shared);
        let previous = {
            let mut state = endpoint.state.lock().expect("endpoint state not poisoned");
            match &mut *state {
                State::Ended { reason, .. } => return Err(reason.clone()),
                State::Open {
                    session: attached,
                    pending,
                    ..
                } => {
                    *attached = incoming.clone();
                    pending.replace(session)
                }
            }
        };
        endpoint.changed.notify_one();
        drop(previous);
        Ok(incoming)
    }
}

#[cfg(test)]
impl Drop for Sessions {
    /// Models loss of the transport reader by permanently ending its endpoint.
    fn drop(&mut self) {
        if let Some(endpoint) = self.endpoint.upgrade() {
            endpoint.retire(crate::transport::Error::Terminated.into());
        }
    }
}

#[cfg(test)]
impl Shared {
    /// Arms a one-shot notification for acceptance waiting without a pending owner.
    /// The notification precedes the atomic unlock-and-wait, letting a scenario
    /// overlap acceptance with publication or closure without relying on sleeps.
    ///
    /// # Panics
    /// The fixture must still be open and have no session waiting for acceptance.
    pub(super) fn watch_accept(&self) -> std::sync::mpsc::Receiver<()> {
        let (sender, receiver) = std::sync::mpsc::channel();
        let mut state = self.state.lock().expect("endpoint state not poisoned");
        let State::Open {
            pending, waiting, ..
        } = &mut *state
        else {
            panic!("only watch an open endpoint accept");
        };
        assert!(pending.is_none());
        *waiting = Some(sender);
        receiver
    }
}

/// Checks endpoint ownership bounds and compiles server construction and acceptance.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::protocol::{Error, Server, Session};
    use crate::transport::{Attester, Read, Stream, Write};
    use darkbio_crypto::xdsa;

    /// Compiles server construction from a caller-owned stream, signer and attester.
    #[allow(dead_code)]
    fn server<R, W, A>(stream: Stream<R, W>, signer: xdsa::SecretKey, attester: A) -> Server
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
        A: Attester + Send + 'static,
    {
        Server::new(stream, signer, attester)
    }

    /// Checks that server acceptance returns the common concrete session type.
    #[allow(dead_code)]
    fn accept(server: &mut Server) -> Result<Session, Error> {
        server.accept()
    }

    /// Checks the send bound required to transfer ownership to an application thread.
    #[test]
    fn test_thread_capabilities() {
        /// Requires an owned value to be transferable to a background thread.
        fn movable<T: Send + 'static>() {}
        movable::<Server>();
    }
}
