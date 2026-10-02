// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Persistent server ownership and ordered attachment of successive sessions.

use super::envelope::Side;
use super::promise::Notifications;
use super::session::SessionInner;
use super::worker;
use super::{
    Closer, DEFAULT_AUTOREPLY_TIMEOUT, DEFAULT_MAX_INBOUND_BYTES, DEFAULT_MAX_INBOUND_REQUESTS,
    Error, Session,
};
use crate::transport::{self, Attester, Read, Stream, Write};
use darkbio_clock::Clock;
use darkbio_clock::sync::{Condvar, Mutex};
use darkbio_crypto::xdsa;
use std::fmt;
use std::sync::{Arc, Weak};
use std::time::Duration;

/// Pause before the reader retries a failed read, so an adapter that keeps
/// failing cannot spin it.
const READ_RETRY_DELAY: Duration = Duration::from_millis(100);

/// Owner of a persistent server stream, accepting successive sessions.
///
/// Closing or dropping the server ends its active session and shuts down the
/// physical stream. Closing an individual [`Session`] keeps this owner and
/// its stream available for another handshake.
///
/// A failed read keeps the server and its current session, and reading resumes
/// after a 100 ms pause on the stream's clock. The end of the stream ends the
/// server.
pub struct Server {
    /// Server state retained independently of any accepted session owner.
    pub(super) inner: Arc<ServerInner>,
}

impl Server {
    /// Takes ownership of a stream and constructs its transport internally.
    ///
    /// The signer is the server's identity key, which must match the key embedded
    /// in the attestation. The attester supplies the current device attestation
    /// for each handshake. The persistent reader starts immediately. Failure to
    /// start a required worker or an escaping worker panic aborts the process.
    pub fn new<R, W, A>(stream: Stream<R, W>, signer: xdsa::SecretKey, attester: A) -> Self
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
        A: Attester + Send + 'static,
    {
        // Retain the stream clock and shutdown handle for every accepted session
        let stream_closer = stream.closer();
        let server = Self {
            inner: Arc::new(ServerInner {
                clock: stream.clock(),
                state: Mutex::new(State::Open {
                    max_inbound_requests: DEFAULT_MAX_INBOUND_REQUESTS,
                    max_inbound_bytes: DEFAULT_MAX_INBOUND_BYTES,
                    autoreply_timeout: DEFAULT_AUTOREPLY_TIMEOUT,
                    session: Weak::new(),
                    ready: None,
                    #[cfg(any(test, feature = "fuzz"))]
                    wait_hook: None,
                    #[cfg(any(test, feature = "fuzz"))]
                    retry_hook: None,
                }),
                changed: Condvar::new(&stream.clock()),
                stream_closer: Some(stream_closer),
                #[cfg(any(test, feature = "fuzz"))]
                workers: Arc::new(worker::Tracker::default()),
            }),
        };

        // Keep accepting transport handshakes until this owner closes
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

    /// Sets the timeout for automatic `UNANSWERED` and `UNKNOWN` replies in the
    /// current and future sessions.
    ///
    /// Defaults to [`DEFAULT_AUTOREPLY_TIMEOUT`]. Applies even before
    /// [`Self::accept`]. Replies already queued keep their deadlines.
    ///
    /// See [`Session::set_autoreply_timeout`] for when the timeout starts and
    /// expires. Changing a session's timeout leaves the server's default unchanged.
    /// This method also replaces a timeout set directly on the current session.
    pub fn set_autoreply_timeout(self, timeout: Duration) -> Self {
        self.inner.set_autoreply_timeout(timeout);
        self
    }

    /// Sets both per-session inbound limits, initially
    /// [`DEFAULT_MAX_INBOUND_REQUESTS`] and [`DEFAULT_MAX_INBOUND_BYTES`].
    ///
    /// Applies to the current session, even before [`Self::accept`], and future
    /// sessions. Lowering either limit below usage closes that session. The
    /// server stays open.
    ///
    /// See [`Session::set_inbound_limits`] for what each limit counts. Changing a
    /// session's limits leaves the server's defaults unchanged. This method also
    /// replaces limits set directly on the current session.
    pub fn set_inbound_limits(self, requests: usize, bytes: usize) -> Self {
        self.inner.set_inbound_limits(requests, bytes);
        self
    }

    /// Blocks until a session is established or the server ends.
    ///
    /// Recoverable handshake failures leave the stream available for another
    /// attempt. A replacement session closes the previous one, and old handles
    /// still refer to it.
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

    /// Permanently closes this server and its active session.
    ///
    /// It wakes blocked acceptance and receive calls and fails unresolved
    /// operations. It also closes the stream, waiting for adapter calls in
    /// progress to return. Repeated calls have no further effect. It does not
    /// join application jobs or guarantee the peer has observed closure.
    pub fn close(&self) {
        self.inner.close(Error::Closed);
    }
}

/// Receives transport events across successive server sessions.
///
/// Weak references let closed sessions be freed while this reader waits for
/// another handshake.
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
            // A successful handshake gets its own session and workers
            Ok(transport::Event::Connected(sender)) => {
                let session = Session::start(
                    Side::Server,
                    server.clock.clone(),
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
            // Disconnecting closes the session while keeping the server stream
            Ok(transport::Event::Disconnected) => {
                if let Some(session) = current.upgrade() {
                    session.close(transport::Error::SessionReset.into());
                }
                current = Weak::new();
            }
            // A message goes to the current session, which closes if handling fails
            Ok(transport::Event::Message(bytes)) => {
                if let Some(session) = current.upgrade()
                    && let Err(error) = session.handle_message(bytes)
                {
                    session.close(error);
                }
            }
            // Keep the session, whose binding and partial frame survive the
            // failed read, and pause so a failing adapter cannot spin the reader
            Err(transport::Error::RecvFailed(error)) => {
                tracing::warn!("wire receive failed, retrying: {}", error);
                if !server.pause_reader() {
                    break;
                }
            }
            // A handshake that failed to write leaves the reader available for
            // the next reset
            Err(transport::Error::SendFailed(error)) => {
                tracing::debug!("wire handshake output failed: {}", error);
            }
            // The end of the stream, or any other failure, ends the server
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

impl fmt::Debug for Server {
    /// Shows whether the server still accepts sessions.
    ///
    /// A state lock held elsewhere leaves the state out.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut server = f.debug_struct("Server");
        if let Ok(state) = self.inner.state.try_lock() {
            server.field("open", &matches!(*state, State::Open { .. }));
        }
        server.finish_non_exhaustive()
    }
}

/// Shared server state, holding at most one session waiting for acceptance.
///
/// The reader attaches replacements in transport order. Accepted sessions own
/// themselves, and the server retains only a weak reference for server shutdown.
pub(super) struct ServerInner {
    /// Clock inherited by every session accepted on this stream.
    clock: Clock,
    /// Attached session, pending acceptance and server closure, under one lock.
    state: Mutex<State>,
    /// Signal waking [`Server::accept`] when a session is attached or the
    /// server closes.
    changed: Condvar,
    /// Closer of the server's stream, empty in tests that supply sessions directly.
    stream_closer: Option<transport::Closer>,
    /// Tracker letting tests wait for the reader and all session workers to exit.
    #[cfg(any(test, feature = "fuzz"))]
    pub(super) workers: Arc<worker::Tracker>,
}

/// Server policy and the session waiting for acceptance, or the error that
/// closed the server.
enum State {
    /// Open server, tracking the current session and keeping its owner until
    /// [`Server::accept`] takes it.
    Open {
        /// Request ceiling applied to the attached session and future sessions.
        max_inbound_requests: usize,
        /// Encoded-byte ceiling applied independently to each session.
        max_inbound_bytes: usize,
        /// Automatic reply timeout applied to the current and future sessions.
        autoreply_timeout: Duration,
        /// Current session, which server closure closes even after
        /// [`Server::accept`] returns it.
        session: Weak<SessionInner>,
        /// Session waiting for [`Server::accept`], replaced by a newer handshake.
        ready: Option<Session>,
        /// One-shot test notification sent under the server lock before waiting.
        #[cfg(any(test, feature = "fuzz"))]
        wait_hook: Option<std::sync::mpsc::Sender<()>>,
        /// Test notification of each pause the reader takes after a failed
        /// read, carrying the deadline it waits for, sent under the server lock.
        #[cfg(any(test, feature = "fuzz"))]
        retry_hook: Option<std::sync::mpsc::Sender<std::time::Instant>>,
    },
    /// Closed server, with its closing error and the session attached at the time.
    ///
    /// Repeated [`ServerInner::close`] calls can finish closing that session if
    /// the first closer is still doing so.
    Closed {
        /// First reason the server ended; later closes cannot replace it.
        reason: Error,
        /// Session that was attached when the server closed.
        session: Weak<SessionInner>,
    },
}

impl ServerInner {
    /// Updates the current session's timeout and the default under the
    /// attachment lock.
    ///
    /// Lock order is server then session, as with inbound limit updates.
    fn set_autoreply_timeout(&self, timeout: Duration) {
        let mut state = self.state.lock().expect("server state not poisoned");
        if let State::Open {
            autoreply_timeout,
            session,
            ..
        } = &mut *state
        {
            *autoreply_timeout = timeout;
            if let Some(session) = session.upgrade() {
                session.set_autoreply_timeout(timeout);
            }
        }
    }

    /// Updates the current session's limits and the defaults under the
    /// attachment lock.
    ///
    /// Lock order is server then session, and session methods never acquire
    /// the server lock. Server sessions have no stream closer, so applying
    /// their limits cannot wait for stream I/O.
    fn set_inbound_limits(&self, requests: usize, bytes: usize) {
        // Defer session callbacks until the server's policy lock is released too
        let mut notifications = Notifications::default();
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
                session.set_inbound_limits(requests, bytes, &mut notifications);
            }
        }
    }

    /// Closes the server, refusing attachment and acceptance before closing the
    /// attached session.
    ///
    /// The server lock is released before closing or dropping a [`Session`],
    /// since those operations take the session's own lock.
    pub(super) fn close(&self, error: Error) {
        // Stop `attach` and `accept` by switching to `Closed`. Save the attached
        // session so repeated `close` calls can finish closing it too.
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

    /// Waits [`READ_RETRY_DELAY`] on the stream clock before the reader retries
    /// a failed read, returning false if the server closes first.
    fn pause_reader(&self) -> bool {
        // Fix the deadline first, so a wait that starts late still ends on time
        let deadline = self.clock.now() + READ_RETRY_DELAY;
        let mut state = self.state.lock().expect("server state not poisoned");

        // Let a test move time on once the pause has its deadline
        #[cfg(any(test, feature = "fuzz"))]
        if let State::Open {
            retry_hook: Some(hook),
            ..
        } = &*state
        {
            let _ = hook.send(deadline);
        }

        // Wait out the delay, ending early once a close switches the state
        loop {
            if matches!(*state, State::Closed { .. }) {
                return false;
            }
            let (guard, result) = self
                .changed
                .wait_deadline(state, deadline)
                .expect("server state not poisoned");
            state = guard;
            if result.timed_out() {
                return matches!(*state, State::Open { .. });
            }
        }
    }

    /// Closes the previous session and makes this one available to
    /// [`Server::accept`].
    ///
    /// Only the reader, or the test fixture replacing it, calls this method.
    fn attach(&self, session: Session) -> Result<(), Error> {
        // Take an Arc to the previous session, then release the server lock
        // before closing that session
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
        let mut notifications = Notifications::default();
        let previous = {
            let mut state = self.state.lock().expect("server state not poisoned");
            match &mut *state {
                State::Closed { reason, .. } => return Err(reason.clone()),
                State::Open {
                    session: attached,
                    max_inbound_requests,
                    max_inbound_bytes,
                    autoreply_timeout,
                    ready,
                    ..
                } => {
                    // Apply the current policy before exposing this session or
                    // letting the reader deliver its first message
                    session.inner.set_inbound_limits(
                        *max_inbound_requests,
                        *max_inbound_bytes,
                        &mut notifications,
                    );
                    session.inner.set_autoreply_timeout(*autoreply_timeout);
                    *attached = Arc::downgrade(&session.inner);
                    ready.replace(session)
                }
            }
        };

        // Wake a blocked accept, then drop the owner of a previous session that
        // accept never took
        self.changed.notify_all();
        drop(previous);
        Ok(())
    }
}

/// Fixture supplying sessions in tests in place of the server's transport reader.
#[cfg(any(test, feature = "fuzz"))]
pub(super) struct SessionSource {
    /// Server that receives sessions created by [`SessionSource::open`].
    server_ref: Weak<ServerInner>,
}

#[cfg(any(test, feature = "fuzz"))]
impl Server {
    /// Creates a server and a fixture that attaches sessions without a stream.
    pub(super) fn fixture(clock: Clock) -> (Self, SessionSource) {
        let inner = Arc::new(ServerInner {
            clock: clock.clone(),
            state: Mutex::new(State::Open {
                max_inbound_requests: DEFAULT_MAX_INBOUND_REQUESTS,
                max_inbound_bytes: DEFAULT_MAX_INBOUND_BYTES,
                autoreply_timeout: DEFAULT_AUTOREPLY_TIMEOUT,
                session: Weak::new(),
                ready: None,
                wait_hook: None,
                retry_hook: None,
            }),
            changed: Condvar::new(&clock),
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
    /// Creates a session and passes it to [`ServerInner::attach`], just as the
    /// reader does after a handshake.
    ///
    /// Returns its weak reference so tests can deliver messages to it even
    /// after another session connects.
    pub(super) fn open(&mut self) -> Result<Weak<SessionInner>, Error> {
        let server = self.server_ref.upgrade().ok_or(Error::Closed)?;
        let session = Session::fixture_with_clock(Side::Server, server.clock.clone());
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
    /// Arms a one-shot notification for [`Server::accept`] waiting without a
    /// ready session.
    ///
    /// It is sent while holding `state`, just before acceptance waits on
    /// `changed`. Tests can then attach a session or close the server without
    /// using sleeps.
    ///
    /// # Panics
    ///
    /// Panics if the fixture is closed or already has a session waiting for
    /// acceptance.
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

    /// Arms a notification for every pause the reader takes after a failed
    /// read, carrying the deadline the pause waits for.
    ///
    /// It is sent while holding `state`, once the pause has fixed its
    /// deadline, so advancing the clock to it cannot race the wait.
    ///
    /// # Panics
    ///
    /// Panics if the server is closed.
    pub(super) fn watch_read_retries(&self) -> std::sync::mpsc::Receiver<std::time::Instant> {
        let (sender, receiver) = std::sync::mpsc::channel();
        let mut state = self.state.lock().expect("server state not poisoned");
        let State::Open { retry_hook, .. } = &mut *state else {
            panic!("only watch an open server read");
        };
        *retry_hook = Some(sender);
        receiver
    }
}

/// Checks server policy callbacks and ownership bounds, and compiles server
/// construction and acceptance.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::Side;
    use crate::memory;
    use crate::protocol::{self, Error, Message, Server, Session};
    use crate::transport::mock::self_attestation;
    use crate::transport::testing::test_clock;
    use crate::transport::{Attester, Read, Stream, Write};
    use darkbio_clock::Clock;
    use darkbio_crypto::xdsa;
    use std::collections::VecDeque;
    use std::fmt::Debug;
    use std::io::{self, Write as _};
    use std::sync::{Arc, Mutex, mpsc};
    use std::thread;
    use std::time::{Duration, Instant};

    /// Pause the server's docs promise between a failed read and its retry.
    const PAUSE: Duration = Duration::from_millis(100);

    /// Failure a [`Faults`] reader injects.
    enum Fault {
        /// The read itself fails.
        Read,
        /// Installing the read's deadline fails with a timeout, as a broken
        /// adapter's setter can.
        Setter,
        /// The read fails and loses the rest of the frame it was inside.
        Loss,
    }

    /// Ark-side reader that hands out one byte per read and injects the
    /// failures its test queues, recording when each happened.
    struct Faults {
        /// Duplex half carrying the host's bytes.
        inner: memory::Reader,
        /// Failures the test queued, shared with it.
        plan: Arc<Mutex<Plan>>,
    }

    /// Failures a [`Faults`] reader still owes, and those it injected.
    #[derive(Default)]
    struct Plan {
        /// Bytes to hand out before the first queued failure.
        after: usize,
        /// Failures to inject in order, one per read attempt.
        queued: VecDeque<Fault>,
        /// Clock times of the injected failures.
        failed: Vec<Instant>,
        /// Whether bytes are being dropped up to the next frame delimiter.
        losing: bool,
    }

    impl io::Read for Faults {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            // Fail this read if a read or loss failure is due, recording when
            {
                let mut plan = self.plan.lock().unwrap();
                if plan.after == 0 && matches!(plan.queued.front(), Some(Fault::Read | Fault::Loss))
                {
                    let fault = plan.queued.pop_front().unwrap();
                    plan.losing = matches!(fault, Fault::Loss);
                    plan.failed.push(self.inner.clock().now());
                    return Err(io::Error::other("injected read failure"));
                }
            }

            // Hand out one byte, so a failure can land inside a frame, dropping
            // the bytes a loss took up to the frame's delimiter
            loop {
                let len = buf.len().min(1);
                let read = self.inner.read(&mut buf[..len])?;
                let mut plan = self.plan.lock().unwrap();
                if plan.losing && read == 1 && buf[0] != 0 {
                    continue;
                }
                plan.losing = false;
                plan.after = plan.after.saturating_sub(read);
                return Ok(read);
            }
        }
    }

    impl Read for Faults {
        fn clock(&self) -> Clock {
            self.inner.clock()
        }

        fn set_read_deadline(&mut self, deadline: Option<Instant>) -> io::Result<()> {
            // Fail installing the deadline if a setter failure is due,
            // recording when
            {
                let mut plan = self.plan.lock().unwrap();
                if plan.after == 0 && matches!(plan.queued.front(), Some(Fault::Setter)) {
                    plan.queued.pop_front();
                    plan.failed.push(self.inner.clock().now());
                    return Err(io::ErrorKind::TimedOut.into());
                }
            }
            self.inner.set_read_deadline(deadline)
        }
    }

    /// Starts a server whose reader fails on request.
    ///
    /// Returns the server, the host's end of the link, the failure plan, the
    /// deadlines of the reader's pauses and the server's identity.
    fn faulty_server(
        clock: &Clock,
    ) -> (
        Server,
        memory::Duplex,
        Arc<Mutex<Plan>>,
        mpsc::Receiver<Instant>,
        xdsa::PublicKey,
    ) {
        // Wrap the Ark's reader, so the test decides which reads fail
        let signer = xdsa::SecretKey::generate();
        let identity = signer.public_key();
        let attestation = self_attestation(&signer);
        let (host, ark) = memory::duplex(64 * 1024, clock);
        let (reader, writer, closer, _) = ark.into_parts();
        let plan = Arc::new(Mutex::new(Plan::default()));
        let faults = Faults {
            inner: reader,
            plan: plan.clone(),
        };
        let stream = Stream::new(faults, writer, move || closer.close());

        // Start the server and watch its reader pause after each failure
        let server = Server::new(stream, signer, attestation);
        let retries = server.inner.watch_read_retries();
        (server, host, plan, retries, identity)
    }

    /// Checks that a failed read and a failing deadline setter keep the server,
    /// each retry waiting out the documented pause, and that the handshake
    /// then completes.
    #[test]
    fn test_server_retries_failed_reads() {
        // Fail a read and then a deadline setter behind a client's first byte
        let mut tester = test_clock();
        let (mut server, host, plan, retries, identity) = faulty_server(&tester.clock());
        {
            let mut plan = plan.lock().unwrap();
            plan.after = 1;
            plan.queued.extend([Fault::Read, Fault::Setter]);
        }
        let connecting =
            thread::spawn(move || protocol::connect(host, &identity).map(|(client, _)| client));

        // Require each pause to last the documented time and the retry to wait
        // it out
        for failure in 0..2 {
            let deadline = retries.recv().unwrap();
            let failed = plan.lock().unwrap().failed[failure];
            assert_eq!(deadline - failed, PAUSE, "{failure}");
            tester.advance_to(deadline);
        }
        let failed = plan.lock().unwrap().failed.clone();
        assert_eq!(failed[1] - failed[0], PAUSE);

        // Require the handshake to complete once reads succeed again, keeping
        // the client open until the server accepts
        let _client = connecting.join().unwrap().unwrap();
        server.accept().unwrap();
    }

    /// Checks that a read failing inside a frame keeps the session, whose
    /// deadlines run during the pause, and which gets the frame once the
    /// retry reads the rest.
    #[test]
    fn test_server_keeps_session_across_failed_read() {
        // Connect, and leave an Ark request that expires during the pause
        let mut tester = test_clock();
        let (mut server, host, plan, retries, identity) = faulty_server(&tester.clock());
        let (client, _) = protocol::connect(host, &identity).unwrap();
        let mut session = server.accept().unwrap();
        let expiry = tester.clock().now() + PAUSE / 2;
        let expiring = session
            .requester()
            .request(b"pong".to_vec(), expiry)
            .unwrap();

        // Send a request whose frame a failed read splits after its first byte
        {
            let mut plan = plan.lock().unwrap();
            plan.after = 1;
            plan.queued.push_back(Fault::Read);
        }
        let deadline = tester.clock().now() + Duration::from_secs(5);
        let answer = client
            .requester()
            .request(b"ping".to_vec(), deadline)
            .unwrap();

        // Require the deadline worker to expire the Ark request while the
        // reader pauses, then let the reader retry
        let resume = retries.recv().unwrap();
        tester.advance_to(expiry);
        assert!(matches!(expiring.wait_worker_result(), Err(Error::Timeout)));
        tester.advance_to(resume);

        // Require the same session to receive the split request and answer it
        let (message, responder) = session.recv().unwrap();
        assert_eq!(message, Message::Develop(b"ping".to_vec()));
        let written = responder.reply(message, deadline).unwrap();
        assert_eq!(answer.wait::<Vec<u8>>().unwrap(), b"ping");
        written.wait().unwrap();
    }

    /// Checks that a read failure losing the rest of a frame ends the session
    /// instead of letting it read past the gap.
    #[test]
    fn test_server_ends_session_after_lost_frame() {
        // Connect, then lose all but the first byte of the next frame
        let mut tester = test_clock();
        let (mut server, host, plan, retries, identity) = faulty_server(&tester.clock());
        let (client, _) = protocol::connect(host, &identity).unwrap();
        let mut session = server.accept().unwrap();
        {
            let mut plan = plan.lock().unwrap();
            plan.after = 1;
            plan.queued.push_back(Fault::Loss);
        }

        // Send a request into the loss and another behind it
        let deadline = tester.clock().now() + Duration::from_secs(5);
        let _lost = client
            .requester()
            .request(b"lost".to_vec(), deadline)
            .unwrap();
        let _after = client
            .requester()
            .request(b"after".to_vec(), deadline)
            .unwrap();
        tester.advance_to(retries.recv().unwrap());

        // Require the session to end on the broken frame without either request
        assert!(session.recv().is_err());
    }

    /// Checks that closing the server ends the reader's pause with the clock
    /// stopped.
    #[test]
    fn test_server_close_interrupts_read_retry() {
        // Fail the read after a junk byte, parking the reader in its pause
        let tester = test_clock();
        let (server, host, plan, retries, _) = faulty_server(&tester.clock());
        {
            let mut plan = plan.lock().unwrap();
            plan.after = 1;
            plan.queued.push_back(Fault::Read);
        }
        let (_reader, mut writer, _closer, _) = host.into_parts();
        writer.write_all(&[1]).unwrap();
        retries.recv().unwrap();

        // Close the server and require its reader to exit without the clock
        let workers = server.inner.workers.clone();
        server.close();
        workers.wait_stopped();
    }

    /// Checks that a server policy change closing its session runs promise
    /// callbacks outside the server lock.
    #[test]
    fn test_limit_callback_releases_server_lock() {
        use darkbio_clock::TestClock;
        use std::sync::mpsc;
        use std::time::Duration;

        // Attach a clock-controlled session and retain a peer request against its limit
        let tester = TestClock::new();
        let (server, _source) = Server::fixture(tester.clock());
        let session = Session::fixture_with_clock(Side::Server, tester.clock());
        let inner = session.inner.clone();
        server.inner.attach(session).unwrap();
        inner.inject_request(1, vec![1].into()).unwrap();

        // Register a callback on another pending operation in that session
        let mut promise = inner
            .request(
                vec![2].into(),
                tester.clock().now() + Duration::from_secs(5),
            )
            .unwrap();
        let state = server.inner.clone();
        let notification = promise.notification_unlocked();
        let (observed, receiver) = mpsc::channel();
        promise.notify(move || {
            let _ = observed.send((state.state.try_lock().is_ok(), notification()));
        });

        // Lower the server policy and require notification outside both owning locks
        let server = server.set_inbound_limits(0, 1024);
        assert_eq!(receiver.try_recv(), Ok((true, true)));
        assert!(matches!(
            promise.wait::<Vec<u8>>(),
            Err(Error::InboundRequestLimitExceeded(0))
        ));
        drop(server);
    }

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

    /// Checks the bounds required to move the server to an application thread
    /// and to print it.
    #[test]
    fn test_thread_capabilities() {
        /// Requires an owned value to be printable and transferable to a
        /// background thread.
        fn movable<T: Debug + Send + 'static>() {}
        movable::<Server>();
    }
}
