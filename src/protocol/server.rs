// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Persistent endpoint ownership and ordered attachment of successive sessions.

use super::envelope::Side;
use super::{Closer, Error, Session};
use super::{session, worker};
use crate::transport::{self, Attester, Read, Stream, Write};
use darkbio_crypto::xdsa;
use std::sync::{Arc, Condvar, Mutex, Weak};

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
    /// Starts its persistent reader immediately. Failure to start a required
    /// worker or an escaping worker panic aborts the process.
    pub fn new<R, W, A>(stream: Stream<R, W>, signer: xdsa::SecretKey, attester: A) -> Self
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
        A: Attester + Send + 'static,
    {
        let shutdown = stream.closer();
        let server = Self {
            shared: Arc::new(Shared {
                state: Mutex::new(State::Open {
                    session: Weak::new(),
                    pending: None,
                    #[cfg(test)]
                    waiting: None,
                }),
                changed: Condvar::new(),
                shutdown: Some(shutdown),
                #[cfg(test)]
                workers: Arc::new(worker::Tracker::default()),
            }),
        };
        let endpoint = Arc::downgrade(&server.shared);
        worker::spawn(
            "wire-reader",
            #[cfg(test)]
            &server.shared.workers,
            move || {
                // Wrap the transport and create the session tracker
                let mut transport = transport::Server::new(stream, signer, attester);
                let mut current: Weak<session::Shared> = Weak::new();

                loop {
                    // Block without retaining endpoint state. Dropping the server
                    // shuts down this read through the endpoint's stream closer.
                    let result = transport.recv();
                    let Some(endpoint) = endpoint.upgrade() else {
                        break;
                    };
                    match result {
                        // If a new client connects, create a new session for it
                        Ok(transport::Event::Connected(sender)) => {
                            let session = Session::start(
                                Side::Server,
                                sender,
                                None,
                                #[cfg(test)]
                                endpoint.workers.clone(),
                            );
                            current = Arc::downgrade(&session.shared);
                            if endpoint.attach(session).is_err() {
                                break;
                            }
                        }
                        // If a client disconnects, drop the current session
                        Ok(transport::Event::Disconnected) => {
                            if let Some(session) = current.upgrade() {
                                session.close(transport::Error::SessionReset.into());
                            }
                            current = Weak::new();
                        }
                        // If a message arrives, deliver it into the current session
                        Ok(transport::Event::Message(bytes)) => {
                            if let Some(session) = current.upgrade()
                                && let Err(error) = session.received(&bytes)
                            {
                                session.close(error);
                            }
                        }
                        // Handshake timeouts and send failures are ignored
                        Err(transport::Error::RecvFailed(error))
                            if error.kind() == std::io::ErrorKind::TimedOut => {}
                        Err(transport::Error::SendFailed(error)) => {
                            tracing::debug!(%error, "server handshake output failed");
                        }
                        // Any other error tears down the endpoint
                        Err(error) => {
                            endpoint.close(error.into());
                            break;
                        }
                    }
                }
            },
        );
        server
    }

    /// Blocks until a session is established or the endpoint ends. Recoverable
    /// handshake failures leave the stream available for another attempt. A
    /// replacement session closes the previous one; old handles still refer to it.
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
        self.shared.close(Error::Closed);
    }
}

impl Drop for Server {
    /// Ends the endpoint and its attached session even when handles remain.
    fn drop(&mut self) {
        self.close();
    }
}

/// Endpoint lifetime and the at-most-one session waiting for accept. The reader
/// attaches replacements in transport order. Accepted sessions own themselves;
/// the endpoint retains only a weak reference for endpoint shutdown.
pub(super) struct Shared {
    /// Protects the attached session, pending acceptance, and endpoint closure.
    state: Mutex<State>,
    /// Wakes `accept()` when a session is attached or the endpoint closes.
    changed: Condvar,
    /// Closes the endpoint's stream. Empty in tests that supply sessions directly.
    shutdown: Option<transport::Closer>,
    /// Lets tests wait for the reader and all session workers to exit.
    #[cfg(test)]
    pub(super) workers: Arc<worker::Tracker>,
}

/// Sessions waiting for acceptance, or the error that closed the endpoint.
enum State {
    /// Tracks the current session and keeps its owner until `accept()` takes it.
    Open {
        /// Lets endpoint closure close the session after `accept()` returns it.
        session: Weak<session::Shared>,
        /// Session waiting for `accept()`. A new handshake replaces it.
        pending: Option<Session>,
        /// One-shot test notification sent under the endpoint lock before waiting.
        #[cfg(test)]
        waiting: Option<std::sync::mpsc::Sender<()>>,
    },
    /// Saves the closing error and attached session. Repeated `close()` calls
    /// can finish closing that session if the first closer is still doing so.
    Ended {
        /// First reason the endpoint ended; later closes cannot replace it.
        reason: Error,
        /// Session that was attached when the endpoint closed.
        session: Weak<session::Shared>,
    },
}

impl Shared {
    /// Refuses attachment/acceptance before closing the attached session.
    /// Releases the endpoint lock before closing or dropping a `Session`, since
    /// those operations take the session's own lock.
    pub(super) fn close(&self, error: Error) {
        // Stop attach() and accept() by switching to Ended. Save the attached
        // session so repeated close() calls can finish closing it too.
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
        // Release the endpoint lock before taking the session's lock. Wake local
        // callers before closing the stream, which waits for active I/O to return.
        if let Some(session) = session {
            session.close(reason);
        }
        self.changed.notify_all();
        drop(pending);
        if let Some(shutdown) = &self.shutdown {
            shutdown.close();
        }
    }

    /// Closes the previous session and makes this one available to `accept()`.
    /// Only the reader, or the test fixture replacing it, calls this method.
    fn attach(&self, session: Session) -> Result<(), Error> {
        // Take an Arc to the previous session, then release the endpoint lock
        // before closing that session.
        let previous = {
            let state = self.state.lock().expect("endpoint state not poisoned");
            match &*state {
                State::Ended { reason, .. } => return Err(reason.clone()),
                State::Open { session, .. } => session.upgrade(),
            }
        };
        if let Some(previous) = previous {
            previous.close(transport::Error::SessionReset.into());
        }
        // Another thread may have closed the endpoint while we closed the old
        // session. Check again under the lock before installing the new one.
        let previous = {
            let mut state = self.state.lock().expect("endpoint state not poisoned");
            match &mut *state {
                State::Ended { reason, .. } => return Err(reason.clone()),
                State::Open {
                    session: attached,
                    pending,
                    ..
                } => {
                    *attached = Arc::downgrade(&session.shared);
                    pending.replace(session)
                }
            }
        };
        self.changed.notify_all();
        // A previous session that accept never took still needs its owner dropped.
        drop(previous);
        Ok(())
    }
}

/// Supplies sessions in tests in place of the server's transport reader.
#[cfg(test)]
pub(super) struct Sessions {
    /// Endpoint that receives sessions created by `open()`.
    endpoint: Weak<Shared>,
}

#[cfg(test)]
impl Server {
    /// Creates an endpoint and a fixture that attaches sessions without a stream.
    pub(super) fn pair() -> (Self, Sessions) {
        let shared = Arc::new(Shared {
            state: Mutex::new(State::Open {
                session: Weak::new(),
                pending: None,
                waiting: None,
            }),
            changed: Condvar::new(),
            shutdown: None,
            workers: Arc::new(worker::Tracker::default()),
        });
        let sessions = Sessions {
            endpoint: Arc::downgrade(&shared),
        };
        (Self { shared }, sessions)
    }
}

#[cfg(test)]
impl Sessions {
    /// Creates a session and passes it to `attach()`, just as the reader does
    /// after a handshake. Returns its weak reference so tests can deliver messages
    /// to it even after another session connects.
    pub(super) fn open(&mut self) -> Result<Weak<session::Shared>, Error> {
        let endpoint = self.endpoint.upgrade().ok_or(Error::Closed)?;
        let session = Session::new();
        let incoming = Arc::downgrade(&session.shared);
        endpoint.attach(session)?;
        Ok(incoming)
    }
}

#[cfg(test)]
impl Drop for Sessions {
    /// Models loss of the transport reader by permanently ending its endpoint.
    fn drop(&mut self) {
        if let Some(endpoint) = self.endpoint.upgrade() {
            endpoint.close(crate::transport::Error::Terminated.into());
        }
    }
}

#[cfg(test)]
impl Shared {
    /// Arms a one-shot notification for acceptance waiting without a pending owner.
    /// Sent while holding `state`, just before `accept()` waits on `changed`.
    /// Tests can then attach a session or close the server without using sleeps.
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
