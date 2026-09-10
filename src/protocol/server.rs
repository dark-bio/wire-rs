// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Persistent server ownership and ordered attachment of successive sessions.

use super::envelope::Side;
use super::session::SessionInner;
use super::worker;
use super::{
    Closer, DEFAULT_ABANDONMENT_TIMEOUT, DEFAULT_MAX_INBOUND_BYTES, DEFAULT_MAX_INBOUND_REQUESTS,
    Error, Session,
};
use crate::transport::{self, Attester, Read, Stream, Write};
use darkbio_crypto::xdsa;
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::Duration;

/// Owner of a persistent server stream, accepting successive sessions.
/// Closing or dropping the server ends its active session and shuts down the
/// physical stream. Closing an individual [`Session`] keeps this owner and
/// its stream available for another handshake.
pub struct Server {
    /// Server state retained independently of any accepted session owner.
    pub(super) inner: Arc<ServerInner>,
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
        let stream_closer = stream.closer();
        let server = Self {
            inner: Arc::new(ServerInner {
                state: Mutex::new(State::Open {
                    max_inbound_requests: DEFAULT_MAX_INBOUND_REQUESTS,
                    max_inbound_bytes: DEFAULT_MAX_INBOUND_BYTES,
                    abandonment: DEFAULT_ABANDONMENT_TIMEOUT,
                    session: Weak::new(),
                    ready: None,
                    #[cfg(any(test, feature = "fuzz"))]
                    wait_hook: None,
                }),
                changed: Condvar::new(),
                stream_closer: Some(stream_closer),
                #[cfg(any(test, feature = "fuzz"))]
                workers: Arc::new(worker::Tracker::default()),
            }),
        };
        let server_ref = Arc::downgrade(&server.inner);
        worker::spawn(
            "wire-server-reader",
            #[cfg(any(test, feature = "fuzz"))]
            &server.inner.workers,
            move || {
                let transport = transport::Server::new(stream, signer, attester);
                run_reader(transport, server_ref);
            },
        );
        server
    }

    /// Sets the lifetime of automatic `UNANSWERED` replies for the current and
    /// future sessions. Defaults to [`DEFAULT_ABANDONMENT_TIMEOUT`]. Applies even
    /// before `accept()`. Replies already queued keep their deadlines.
    ///
    /// See [`Session::set_abandonment_timeout`] for when the timeout starts and
    /// expires. Changing a session's timeout leaves the server's default unchanged.
    /// This method also replaces a timeout set directly on the current session.
    pub fn set_abandonment_timeout(self, timeout: Duration) -> Self {
        self.inner.set_abandonment_timeout(timeout);
        self
    }

    /// Sets both per-session inbound limits, initially
    /// [`DEFAULT_MAX_INBOUND_REQUESTS`] and [`DEFAULT_MAX_INBOUND_BYTES`].
    /// Applies to the current session, even before `accept()`, and future sessions.
    /// Lowering either limit below usage closes that session. The server stays open.
    ///
    /// See [`Session::set_inbound_limits`] for what each limit counts. Changing a
    /// session's limits leaves the server's defaults unchanged. This method also
    /// replaces limits set directly on the current session.
    pub fn set_inbound_limits(self, requests: usize, bytes: usize) -> Self {
        self.inner.set_inbound_limits(requests, bytes);
        self
    }

    /// Blocks until a session is established or the server ends. Recoverable
    /// handshake failures leave the stream available for another attempt. A
    /// replacement session closes the previous one; old handles still refer to it.
    ///
    /// The reader runs before acceptance. A returned session may already have
    /// queued requests or be closed, including from exceeding an inbound limit.
    /// If several sessions arrive before acceptance, only the newest is returned.
    pub fn accept(&mut self) -> Result<Session, Error> {
        let mut state = self.inner.state.lock().expect("server state not poisoned");
        loop {
            match &mut *state {
                State::Closed { reason, .. } => return Err(reason.clone()),
                State::Open {
                    ready,
                    #[cfg(any(test, feature = "fuzz"))]
                    wait_hook,
                    ..
                } => {
                    if let Some(session) = ready.take() {
                        return Ok(session);
                    }
                    #[cfg(any(test, feature = "fuzz"))]
                    if let Some(wait_hook) = wait_hook.take() {
                        let _ = wait_hook.send(());
                    }
                    state = self
                        .inner
                        .changed
                        .wait(state)
                        .expect("server state not poisoned");
                }
            }
        }
    }

    /// Returns a clonable handle for closing this server from another thread,
    /// including while its owner is blocked in [`Self::accept`].
    pub fn closer(&self) -> Closer {
        Closer::server(Arc::downgrade(&self.inner))
    }

    /// Permanently closes this server and its active session, wakes blocked
    /// acceptance and receive calls, and fails unresolved operations. Idempotent.
    /// Does not join application jobs or guarantee the peer has observed closure.
    pub fn close(&self) {
        self.inner.close(Error::Closed);
    }
}

/// Receives transport events across successive server sessions. Weak references
/// let closed sessions be freed while this reader waits for another handshake.
fn run_reader<R: Read, W: Write + Send + 'static, A: Attester>(
    mut transport: transport::Server<R, W, A>,
    server_ref: Weak<ServerInner>,
) {
    let mut current: Weak<SessionInner> = Weak::new();
    loop {
        // Hold no server state across the blocking read. Dropping Server closes
        // its stream and wakes this call.
        let result = transport.recv();
        let Some(server) = server_ref.upgrade() else {
            break;
        };
        match result {
            // A successful handshake gets its own session and workers.
            Ok(transport::Event::Connected(sender)) => {
                let session = Session::start(
                    Side::Server,
                    sender,
                    None,
                    #[cfg(any(test, feature = "fuzz"))]
                    server.workers.clone(),
                );
                current = Arc::downgrade(&session.inner);
                if server.attach(session).is_err() {
                    break;
                }
            }
            // Disconnecting closes the session while keeping the server stream.
            Ok(transport::Event::Disconnected) => {
                if let Some(session) = current.upgrade() {
                    session.close(transport::Error::SessionReset.into());
                }
                current = Weak::new();
            }
            Ok(transport::Event::Message(bytes)) => {
                if let Some(session) = current.upgrade()
                    && let Err(error) = session.handle_message(bytes)
                {
                    session.close(error);
                }
            }
            // A failed handshake leaves the reader available for the next reset.
            Err(transport::Error::RecvFailed(error))
                if error.kind() == std::io::ErrorKind::TimedOut =>
            {
                tracing::debug!("wire handshake timed out");
            }
            Err(transport::Error::SendFailed(error)) => {
                tracing::debug!("wire handshake output failed: {}", error);
            }
            Err(error) => {
                server.close(error.into());
                break;
            }
        }
    }
}

impl Drop for Server {
    /// Ends the server and its attached session even when handles remain.
    fn drop(&mut self) {
        self.close();
    }
}

/// Server lifetime and the at-most-one session waiting for accept. The reader
/// attaches replacements in transport order. Accepted sessions own themselves;
/// the server retains only a weak reference for server shutdown.
pub(super) struct ServerInner {
    /// Protects the attached session, pending acceptance, and server closure.
    state: Mutex<State>,
    /// Wakes `accept()` when a session is attached or the server closes.
    changed: Condvar,
    /// Closes the server's stream. Empty in tests that supply sessions directly.
    stream_closer: Option<transport::Closer>,
    /// Lets tests wait for the reader and all session workers to exit.
    #[cfg(any(test, feature = "fuzz"))]
    pub(super) workers: Arc<worker::Tracker>,
}

/// Sessions waiting for acceptance, or the error that closed the server.
enum State {
    /// Tracks the current session and keeps its owner until `accept()` takes it.
    Open {
        /// Request ceiling applied to the attached session and future sessions.
        max_inbound_requests: usize,
        /// Encoded-byte ceiling applied independently to each session.
        max_inbound_bytes: usize,
        /// Automatic reply timeout applied to the current and future sessions.
        abandonment: Duration,
        /// Lets server closure close the session after `accept()` returns it.
        session: Weak<SessionInner>,
        /// Session waiting for `accept()`. A new handshake replaces it.
        ready: Option<Session>,
        /// One-shot test notification sent under the server lock before waiting.
        #[cfg(any(test, feature = "fuzz"))]
        wait_hook: Option<std::sync::mpsc::Sender<()>>,
    },
    /// Saves the closing error and attached session. Repeated `close()` calls
    /// can finish closing that session if the first closer is still doing so.
    Closed {
        /// First reason the server ended; later closes cannot replace it.
        reason: Error,
        /// Session that was attached when the server closed.
        session: Weak<SessionInner>,
    },
}

impl ServerInner {
    /// Updates the current session and default under the attachment lock.
    /// Lock order is server then session, as with inbound limit updates.
    fn set_abandonment_timeout(&self, timeout: Duration) {
        let mut state = self.state.lock().expect("server state not poisoned");
        if let State::Open {
            abandonment,
            session,
            ..
        } = &mut *state
        {
            *abandonment = timeout;
            if let Some(session) = session.upgrade() {
                session.set_abandonment_timeout(timeout);
            }
        }
    }

    /// Serializes policy changes with attachment. Lock order is server then
    /// session; session methods never acquire the server lock. Server sessions
    /// have no stream closer, so applying their limits cannot wait for stream I/O.
    fn set_inbound_limits(&self, requests: usize, bytes: usize) {
        let mut state = self.state.lock().expect("server state not poisoned");
        if let State::Open {
            max_inbound_requests,
            max_inbound_bytes,
            session,
            ..
        } = &mut *state
        {
            *max_inbound_requests = requests;
            *max_inbound_bytes = bytes;
            if let Some(session) = session.upgrade() {
                session.set_inbound_limits(requests, bytes);
            }
        }
    }

    /// Refuses attachment/acceptance before closing the attached session.
    /// Releases the server lock before closing or dropping a `Session`, since
    /// those operations take the session's own lock.
    pub(super) fn close(&self, error: Error) {
        // Stop attach() and accept() by switching to Closed. Save the attached
        // session so repeated close() calls can finish closing it too.
        let (session, reason, ready) = {
            let mut state = self.state.lock().expect("server state not poisoned");
            match &mut *state {
                State::Closed { reason, session } => (session.upgrade(), reason.clone(), None),
                State::Open { session, ready, .. } => {
                    let session = session.clone();
                    let ready = ready.take();
                    *state = State::Closed {
                        reason: error.clone(),
                        session: session.clone(),
                    };
                    match &error {
                        Error::Closed => tracing::info!("wire server closed locally"),
                        _ if error.orderly() => {
                            tracing::info!("wire server closed: {}", error.reason());
                        }
                        _ => tracing::warn!("wire server failed: {}", error.reason()),
                    }
                    (session.upgrade(), error, ready)
                }
            }
        };
        // Release the server lock before taking the session's lock. Wake local
        // callers before closing the stream, which waits for active I/O to return.
        if let Some(session) = session {
            session.close(reason);
        }
        self.changed.notify_all();
        drop(ready);
        if let Some(stream_closer) = &self.stream_closer {
            stream_closer.close();
        }
    }

    /// Closes the previous session and makes this one available to `accept()`.
    /// Only the reader, or the test fixture replacing it, calls this method.
    fn attach(&self, session: Session) -> Result<(), Error> {
        // Take an Arc to the previous session, then release the server lock
        // before closing that session.
        let previous = {
            let state = self.state.lock().expect("server state not poisoned");
            match &*state {
                State::Closed { reason, .. } => return Err(reason.clone()),
                State::Open { session, .. } => session.upgrade(),
            }
        };
        if let Some(previous) = previous {
            tracing::info!(
                "replacing wire session {} with session {}",
                previous.log_id,
                session.inner.log_id
            );
            previous.close(transport::Error::SessionReset.into());
        }
        // Another thread may have closed the server while we closed the old
        // session. Check again under the lock before installing the new one.
        let previous = {
            let mut state = self.state.lock().expect("server state not poisoned");
            match &mut *state {
                State::Closed { reason, .. } => return Err(reason.clone()),
                State::Open {
                    session: attached,
                    max_inbound_requests,
                    max_inbound_bytes,
                    abandonment,
                    ready,
                    ..
                } => {
                    // Apply the current policy before exposing this session or
                    // letting the reader deliver its first message.
                    session
                        .inner
                        .set_inbound_limits(*max_inbound_requests, *max_inbound_bytes);
                    session.inner.set_abandonment_timeout(*abandonment);
                    *attached = Arc::downgrade(&session.inner);
                    ready.replace(session)
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
#[cfg(any(test, feature = "fuzz"))]
pub(super) struct SessionSource {
    /// Server that receives sessions created by `open()`.
    server_ref: Weak<ServerInner>,
}

#[cfg(any(test, feature = "fuzz"))]
impl Server {
    /// Creates a server and a fixture that attaches sessions without a stream.
    pub(super) fn fixture() -> (Self, SessionSource) {
        let inner = Arc::new(ServerInner {
            state: Mutex::new(State::Open {
                max_inbound_requests: DEFAULT_MAX_INBOUND_REQUESTS,
                max_inbound_bytes: DEFAULT_MAX_INBOUND_BYTES,
                abandonment: DEFAULT_ABANDONMENT_TIMEOUT,
                session: Weak::new(),
                ready: None,
                wait_hook: None,
            }),
            changed: Condvar::new(),
            stream_closer: None,
            workers: Arc::new(worker::Tracker::default()),
        });
        let source = SessionSource {
            server_ref: Arc::downgrade(&inner),
        };
        (Self { inner }, source)
    }
}

#[cfg(any(test, feature = "fuzz"))]
impl SessionSource {
    /// Creates a session and passes it to `attach()`, just as the reader does
    /// after a handshake. Returns its weak reference so tests can deliver messages
    /// to it even after another session connects.
    pub(super) fn open(&mut self) -> Result<Weak<SessionInner>, Error> {
        let server = self.server_ref.upgrade().ok_or(Error::Closed)?;
        let session = Session::fixture();
        let session_ref = Arc::downgrade(&session.inner);
        server.attach(session)?;
        Ok(session_ref)
    }
}

#[cfg(any(test, feature = "fuzz"))]
impl Drop for SessionSource {
    /// Models loss of the transport reader by permanently ending its server.
    fn drop(&mut self) {
        if let Some(server) = self.server_ref.upgrade() {
            server.close(crate::transport::Error::Terminated.into());
        }
    }
}

#[cfg(any(test, feature = "fuzz"))]
impl ServerInner {
    /// Arms a one-shot notification for `accept()` waiting without a ready session.
    /// Sent while holding `state`, just before `accept()` waits on `changed`.
    /// Tests can then attach a session or close the server without using sleeps.
    ///
    /// # Panics
    /// The fixture must still be open and have no session waiting for acceptance.
    pub(super) fn watch_accept_wait(&self) -> std::sync::mpsc::Receiver<()> {
        let (sender, receiver) = std::sync::mpsc::channel();
        let mut state = self.state.lock().expect("server state not poisoned");
        let State::Open {
            ready, wait_hook, ..
        } = &mut *state
        else {
            panic!("only watch an open server accept");
        };
        assert!(ready.is_none());
        *wait_hook = Some(sender);
        receiver
    }
}

/// Checks server ownership bounds and compiles server construction and acceptance.
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
