// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! The machine behind a multiplexer, what its callers, its reader thread and
//! its worker thread all plug into. It keeps the requests waiting for their
//! answer, the window, the inbox and the handler, and routes what the reader
//! brings in, an answer to the caller waiting for it, a request to the
//! worker. The threads start with it and wind down when it ends.

use crate::protocol;
use crate::protocol::envelope::{Envelope, Ids, Kind, Parity, Side};
use crate::protocol::mux::{ANSWERS, CHARGE, Error, INBOX, Reader, Responder, WINDOW, Writer};
use crate::transport::{self, Attester, Closer, Event, MAX_MESSAGE_SIZE, Sender};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::panic::{self, AssertUnwindSafe};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use tracing::{error, warn};

/// Handler of the peer's requests, answering through the responder.
pub(super) type Handler<Out, In> = Box<dyn FnMut(<In as Envelope>::Content, Responder<Out>) + Send>;

/// Handler of a session ending without a close, with the reason.
pub(super) type Disconnect = Box<dyn FnMut(Error) + Send>;

/// Delivery of an answer to the caller waiting for it, the charge of its
/// bytes of the answers budget going with it, freed when the caller takes or
/// drops the answer.
pub(super) type Answer<In> =
    SyncSender<(Result<<In as Envelope>::Content, Error>, Option<Release>)>;

/// Charge of an answer of the answers budget, freed on drop, which is when
/// the caller takes the answer out or lets it go.
pub(crate) struct Release(Option<Box<dyn FnOnce() + Send>>);

impl Release {
    /// Creates the charge of the bytes on the switchboard, its drop paying
    /// them back however far the multiplexer moved on meanwhile.
    fn new<Out: Envelope, In: Envelope>(
        switchboard: &Arc<Switchboard<Out, In>>,
        bytes: usize,
    ) -> Self {
        let switchboard = Arc::downgrade(switchboard);
        Self(Some(Box::new(move || {
            if let Some(switchboard) = switchboard.upgrade() {
                let mut registry = lock(&switchboard.registry);
                registry.buffered = registry.buffered.saturating_sub(bytes);
            }
        })))
    }
}

impl Drop for Release {
    fn drop(&mut self) {
        if let Some(release) = self.0.take() {
            release();
        }
    }
}

/// Whether the multiplexer still takes calls, and if not, why.
enum State {
    Open,          // Running, work accepted whenever a session is bound
    Failed(Error), // Session ended for the reason, calls refused with it
    Closed,        // Closed by the owner, calls refused
}

/// One session observed by the multiplexer. Requests and responders retain
/// this object so a late failure can only end the session that created them.
/// Its identity belongs to the mux and does not expose transport state.
pub(super) struct Session {
    sender: Sender<Writer>, // Transport handle delivered when the session opened
}

/// The requests waiting for their answer, along with the counters deciding if
/// new ones can be admitted.
struct Registry<In: Envelope> {
    state: State,                               // Whether calls are admitted in
    pending: HashMap<u64, (Answer<In>, usize)>, // Waiting callers by id, with their bytes

    inflight: usize, // Bytes of the pending requests, bounded by the window
    waiting: usize,  // Callers parked on the window
    session: Option<Arc<Session>>, // Session accepting work, none between sessions

    buffered: usize, // Bytes of answers delivered but not taken, bounded by the budget

    ended: Option<Error>, // Reason the session before it ended for, none before the first
}

impl<In: Envelope> Registry<In> {
    /// Checks that requests are admitted.
    fn accepting(&self) -> Result<(), Error> {
        match &self.state {
            State::Open => Ok(()),
            _ => Err(self.refusal()),
        }
    }

    /// Whether work belongs to the session held under this registry lock.
    fn bound_to(&self, session: &Arc<Session>) -> bool {
        self.session
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, session))
    }

    /// Why work cannot enter a session, preserving the last session's failure.
    fn session_refusal(&self) -> Error {
        self.ended
            .clone()
            .unwrap_or_else(|| Error::Disconnected(Arc::new(transport::Error::SessionReset)))
    }

    /// Fails every pending request with a reason.
    fn drain(&mut self, reason: &Error) {
        self.inflight = 0;
        for (_, (tx, _)) in std::mem::take(&mut self.pending) {
            let _ = tx.send((Err(reason.clone()), None));
        }
    }

    /// The error every call gets once calls are no longer taken, the fault that
    /// ended the session or plain closed.
    fn refusal(&self) -> Error {
        match &self.state {
            State::Failed(reason) => reason.clone(),
            State::Open | State::Closed => Error::Closed,
        }
    }
}

/// A request of the peer's ahead of the worker, bound to the session it
/// arrived in, so its answer goes nowhere else whatever session is live by
/// the time the worker gets to it.
struct Request<In: Envelope> {
    id: u64,                      // Id of the request, echoed by the response
    content: Option<In::Content>, // Content for the handler, none for one it cannot read
    bytes: usize,                 // Bytes the request holds of the inbox
    session: Arc<Session>,        // Mux session the request arrived in
}

/// The requests ahead of the worker, capped in bytes.
struct Inbox<In: Envelope> {
    requests: VecDeque<Request<In>>, // Requests in arrival order
    bytes: usize,                    // Bytes of the requests, bounded by the limit
    stopped: bool,                   // Whether the worker is to wind down
}

impl<In: Envelope> Inbox<In> {
    /// Drops the requests queued, none of them served.
    fn clear(&mut self) {
        self.requests.clear();
        self.bytes = 0;
    }
}

/// The switchboard as a responder sees it, a send through the session a
/// request arrived in with a failed write torn down the side's way, so a
/// responder need not name the `In` type to reach it.
pub(super) trait ReplySender: Send + Sync {
    /// Sends an encoded message through the handle of a mux session, see the
    /// switchboard's own send.
    fn send(&self, session: &Arc<Session>, message: &[u8]) -> Result<(), Error>;
}

/// Source of the messages a reader thread routes, a transport client or
/// server with its sender.
pub(super) trait Source: Send + 'static {
    /// Public transport handle ending the underlying byte stream.
    fn closer(&self) -> Closer;

    /// Reads the next message of the session, or the session ending and the
    /// next one opening, see the transport server's. A client's session is
    /// its connection, so it only ever reads messages. A server retries timed-out
    /// handshakes and failed handshake output on its reusable stream; errors
    /// returned here end the mux.
    fn recv(&mut self) -> Result<Event<Writer>, transport::Error>;

    /// Ends the live session and tells the peer through
    /// [`transport::Server::disconnect`], leaving the server ready for another
    /// session. A client multiplexer ends with its session, so its source has
    /// nothing to do here.
    fn disconnect(&mut self) {}
}

impl Source for transport::Client<Reader, Writer> {
    fn closer(&self) -> Closer {
        transport::Client::closer(self)
    }
    fn recv(&mut self) -> Result<Event<Writer>, transport::Error> {
        transport::Client::recv(self).map(Event::Message)
    }
}

impl<A: Attester + Send + 'static> Source for transport::Server<Reader, Writer, A> {
    fn closer(&self) -> Closer {
        transport::Server::closer(self)
    }
    fn recv(&mut self) -> Result<Event<Writer>, transport::Error> {
        loop {
            match transport::Server::recv(self) {
                // The transport retired the preceding session before the
                // handshake, and failed output installed no replacement.
                // Keep consuming the persistent server stream for a new reset.
                Err(transport::Error::SendFailed(err)) => {
                    warn!("wire handshake output failed: {}", err);
                }
                // The handshake deadline expired without installing a session.
                // The next receive waits for another reset on the same stream.
                Err(transport::Error::RecvFailed(err)) if err.kind() == io::ErrorKind::TimedOut => {
                    warn!("wire handshake timed out: {}", err);
                }
                result => return result,
            }
        }
    }

    fn disconnect(&mut self) {
        transport::Server::disconnect(self);
    }
}

/// Switchboard of one multiplexer, see the module docs.
pub(super) struct Switchboard<Out: Envelope, In: Envelope> {
    side: Side, // Side of the wire, a client ending with its session, a server outliving it
    parity: Parity, // Parity of the ids this side allocates
    ids: Ids,   // Allocator of the request ids
    registry: Mutex<Registry<In>>, // Pending requests and the state
    room: Condvar, // Wakes callers waiting on the window, or for the end
    inbox: Mutex<Inbox<In>>, // Work ahead of the worker
    arrived: Condvar, // Wakes the worker
    handler: Mutex<Option<Handler<Out, In>>>, // Server of the peer's requests
    disconnect: Mutex<Option<Disconnect>>, // Handler of the session ending without a close
    closer: Closer, // Public handle ending the transport
}

impl<Out: Envelope, In: Envelope> Switchboard<Out, In> {
    /// Starts the switchboard of a side over a source, its ids of the side's
    /// parity, the reader and the worker threads with it, the close handle ending
    /// the transport when the multiplexer closes or the session fails.
    pub(super) fn start(
        side: Side,
        source: impl Source,
        sender: Option<Sender<Writer>>,
    ) -> Arc<Self> {
        let session = sender.map(|sender| Arc::new(Session { sender }));
        let parity = Parity::from(side);
        let switchboard = Arc::new(Self {
            side,
            parity,
            ids: Ids::new(parity),
            registry: Mutex::new(Registry {
                state: State::Open,
                pending: HashMap::new(),
                inflight: 0,
                waiting: 0,
                session: session.clone(),
                buffered: 0,
                ended: None,
            }),
            room: Condvar::new(),
            inbox: Mutex::new(Inbox {
                requests: VecDeque::new(),
                bytes: 0,
                stopped: false,
            }),
            arrived: Condvar::new(),
            handler: Mutex::new(None),
            disconnect: Mutex::new(None),
            closer: source.closer(),
        });
        let reading = switchboard.clone();
        thread::Builder::new()
            .name("wire-reader".into())
            .spawn(move || read(reading, source, session))
            .expect("failed to spawn the reader thread");
        let working = switchboard.clone();
        thread::Builder::new()
            .name("wire-worker".into())
            .spawn(move || work(working))
            .expect("failed to spawn the worker thread");
        switchboard
    }

    /// Hands out the next request id of the side.
    pub(super) fn next_id(&self) -> u64 {
        self.ids.next()
    }

    /// Sends a request registered under its id, the answer to reach the
    /// caller, waiting for room in the window first. It is registered before
    /// it is sent, so an answer racing the send finds its caller, and it goes
    /// into the session it was registered in and no other, a reset in between
    /// failing it rather than handing it to the next peer.
    pub(super) fn request(&self, id: u64, message: &[u8], tx: Answer<In>) -> Result<(), Error> {
        let session = self.admit(id, message.len(), tx)?;
        if let Err(err) = self.send(&session, message) {
            self.withdraw(id);
            return Err(err);
        }
        Ok(())
    }

    /// Registers a request, waiting for enough room in the window to avoid
    /// overloading the remote peer. It costs the window its bytes or the
    /// least a request is charged, whichever is more, so a peer cannot hold
    /// more of them than the window suggests by keeping them small. Hands
    /// back the session the request is registered in.
    fn admit(&self, id: u64, bytes: usize, tx: Answer<In>) -> Result<Arc<Session>, Error> {
        // If no messages are being accepted, don't even look at it
        let mut registry = lock(&self.registry);
        registry.accepting()?;

        // Registry is accepting messages, ensure it's decently sized
        if bytes > MAX_MESSAGE_SIZE {
            return Err(Error::TooLarge(bytes));
        }
        // Charge it at least what holding it costs us
        let bytes = bytes.max(CHARGE);

        // Fetch the session we've accepted the message into
        let session = registry
            .session
            .clone()
            .ok_or_else(|| registry.session_refusal())?;

        // If sending is throttled, stash it away and account for it
        while registry.inflight + bytes > WINDOW {
            // Stash it away and wait until something wakes us
            registry.waiting += 1;
            registry = self
                .room
                .wait(registry)
                .unwrap_or_else(PoisonError::into_inner);
            registry.waiting -= 1;

            // Sanity check whether the registry is accepting messages
            registry.accepting()?;

            // Sanity check that no new session was established since, the
            // reason it ended for standing in for one bound before any did
            if !registry.bound_to(&session) {
                return Err(registry.session_refusal());
            }
        }
        // Message admitted into the registry, insert it
        registry.inflight += bytes;
        registry.pending.insert(id, (tx, bytes));
        Ok(session)
    }

    /// Forgets a request on the caller's behalf, its answer discarded on
    /// arrival, and tells whether it is still unanswered. The bytes stay
    /// charged to the window until the answer comes or the session ends, the
    /// peer holding the work until then whether anyone waits for it or not.
    pub(super) fn forget(&self, id: u64) -> bool {
        lock(&self.registry).pending.contains_key(&id)
    }

    /// Withdraws a request that never went out, freeing its bytes of the
    /// window.
    fn withdraw(&self, id: u64) {
        let mut registry = lock(&self.registry);
        if let Some((_, bytes)) = registry.pending.remove(&id) {
            registry.inflight -= bytes;
            self.room.notify_all();
        }
    }

    /// Callers parked on the window, for the mock to tell one parked from one
    /// still on its way to the call. Not part of the API.
    #[cfg(any(test, feature = "fuzz"))]
    pub(super) fn waiting(&self) -> usize {
        lock(&self.registry).waiting
    }

    /// Binds the switchboard to a newly opened session, the previous one
    /// already ended by its closing event or a failed send.
    fn bind(&self, session: Arc<Session>) {
        let mut registry = lock(&self.registry);
        if matches!(registry.state, State::Open) {
            registry.session = Some(session);
        }
    }

    /// Plugs in the handler of the peer's requests, replacing the previous
    /// one.
    pub(super) fn on_request(&self, handler: Handler<Out, In>) {
        *lock(&self.handler) = Some(handler);
    }

    /// Plugs in the handler told once if the session ends without a close.
    pub(super) fn on_disconnect(&self, handler: Disconnect) {
        *lock(&self.disconnect) = Some(handler);
    }

    /// Ends the switchboard on the owner's behalf, every pending request
    /// failed as closed and new calls refused.
    pub(super) fn close(&self) {
        self.end(State::Closed);
    }

    /// Routes a message of the peer's, an answer to its caller, a request to
    /// the worker. One that does not decode, or an answer with neither content
    /// nor error, is the peer breaking the protocol, the fault handed back for
    /// the reader to end the session on.
    fn route(self: &Arc<Self>, session: &Arc<Session>, message: Vec<u8>) -> Result<(), Error> {
        let bytes = message.len().max(CHARGE);
        let envelope = match In::decode(&message[..]) {
            Ok(envelope) => envelope,
            Err(err) => {
                error!("ending session, peer sent an undecodable message: {}", err);
                return Err(Error::Malformed);
            }
        };
        let (id, err, content) = envelope.into_parts();
        match Kind::of(id, self.parity) {
            Kind::Response(id) => {
                let answer = match (err, content) {
                    (Some(err), _) => Err(Error::Remote(err)),
                    (None, Some(content)) => Ok(content),
                    (None, None) => {
                        error!("ending session, peer answered with nothing: {}", id);
                        return Err(Error::Malformed);
                    }
                };
                // Deliver to the caller, unless it gave up on the request. The
                // entry leaves the registry and frees its bytes of the window
                // under one hold, or a drain in between zeroes the bytes
                // first. The answer is charged of the answers budget until
                // the caller takes or drops it, a peer piling more of them on
                // its callers than the budget having its session ended like
                // one overrunning its window.
                let delivery = {
                    let mut registry = lock(&self.registry);
                    if !registry.bound_to(session) {
                        return Ok(());
                    }
                    match registry.pending.remove(&id) {
                        Some((tx, request)) => {
                            registry.inflight -= request;
                            if registry.buffered + bytes > ANSWERS {
                                error!("ending session, peer stockpiled answers: {}", id);
                                return Err(Error::Flooded);
                            }
                            registry.buffered += bytes;
                            Some((tx, Release::new(self, bytes)))
                        }
                        None => None,
                    }
                };
                match delivery {
                    Some((tx, release)) => {
                        self.room.notify_all();
                        let _ = tx.send((answer, Some(release)));
                    }
                    None => warn!("dropping answer to no request: {}", id),
                }
                Ok(())
            }
            // One the multiplexer cannot read is queued all the same, the
            // worker refusing it, so the reader never waits on a write
            Kind::Request(id) => self.push(Request {
                id,
                content,
                bytes,
                session: session.clone(),
            }),
        }
    }

    /// Queues a request for the worker, the reader never waiting on it. A
    /// peer filling the inbox past its limit overran its window, the fault
    /// handed back for the reader to end the session on rather than served.
    fn push(&self, request: Request<In>) -> Result<(), Error> {
        // Under the registry lock, the one a reset takes, or a request read
        // out of a session could land in the inbox after that session ended
        // and be served to whoever comes next
        let registry = lock(&self.registry);
        if !registry.bound_to(&request.session) {
            warn!("dropping request of a session that ended: {}", request.id);
            return Ok(());
        }
        let mut inbox = lock(&self.inbox);
        if inbox.bytes + request.bytes > INBOX {
            warn!("ending session, peer overran its window");
            return Err(Error::Flooded);
        }
        inbox.bytes += request.bytes;
        inbox.requests.push_back(request);
        self.arrived.notify_one();
        Ok(())
    }

    /// Fails a request of the peer's on the multiplexer's own account, from
    /// whichever thread found the fault. The frame is a few bytes the peer's
    /// reader always drains, so the reader may send it too.
    fn refuse(&self, mut responder: Responder<Out>, msg: &str) {
        let id = responder.id;
        let failure = protocol::Error {
            code: 0,
            msg: msg.into(),
        };
        if let Err(err) = responder.fail(failure) {
            warn!("failed to refuse request {}: {}", id, err);
        }
    }

    /// Ends the multiplexer for the reason, the session having ended, failing
    /// every pending request with it, ending the transport so a reader still
    /// blocked in it wakes up, and telling the disconnect handler. A closed
    /// multiplexer needs none of it.
    fn fail(&self, reason: Error) {
        if self.end(State::Failed(reason.clone())) {
            self.tell(reason);
        }
    }

    /// Tells the disconnect handler that a session ended, a panic in it being
    /// its own bug, the multiplexer carrying on. It runs on whichever thread
    /// saw the session die, the reader among them, which would stop reading
    /// for good if a panic took it.
    fn tell(&self, reason: Error) {
        if let Some(handler) = lock(&self.disconnect).as_mut()
            && panic::catch_unwind(AssertUnwindSafe(|| handler(reason))).is_err()
        {
            error!("disconnect handler panicked");
        }
    }

    /// Ends the session the switchboard is bound to, which ended for the
    /// reason, leaving it bound to none until the next one opens. Every
    /// pending request fails with it, the callers waiting for window room
    /// wake up to be refused with it, the requests queued for the worker are
    /// dropped, the responders made from here on answer nowhere, and the
    /// disconnect handler is told. The multiplexer carries on. The session
    /// and its sender move under the registry's lock, the one a request
    /// registers under, so no request straddles the two sessions. A session
    /// the switchboard already moved off ends nothing, whichever thread saw
    /// it die having done this first.
    fn reset(&self, session: &Arc<Session>, reason: Error) {
        {
            // Everything the session leaves behind goes under the one lock a
            // request registers under, or the reader could bind the next
            // session and queue its requests into what this is clearing
            let mut registry = lock(&self.registry);
            if !registry.bound_to(session) {
                return;
            }
            registry.drain(&reason);
            registry.session = None;
            registry.ended = Some(reason.clone());
            lock(&self.inbox).clear();
        }
        self.room.notify_all();
        self.tell(reason);
    }

    /// Ends the multiplexer in the state, failing every pending request
    /// accordingly, waking the callers waiting for window room to be refused,
    /// stopping the worker and ending the transport. Tells whether it was open
    /// until now.
    fn end(&self, state: State) -> bool {
        {
            // Under the one lock a request registers under, as a reset is,
            // so nothing the reader brings in outlives the end
            let mut registry = lock(&self.registry);
            if !matches!(registry.state, State::Open) {
                return false;
            }
            registry.state = state;
            let refusal = registry.refusal();
            registry.drain(&refusal);

            // Bound to no session any more, so one ending afterwards has
            // nothing left to end and tells nobody, a close being silent
            registry.session = None;

            let mut inbox = lock(&self.inbox);
            inbox.clear();
            inbox.stopped = true;
        }
        self.room.notify_all();
        self.arrived.notify_one();
        self.closer.close();
        true
    }
}

impl<Out: Envelope, In: Envelope> ReplySender for Switchboard<Out, In> {
    /// Sends an encoded message through the handle of a mux session. A message
    /// refused before sealing leaves the session alone. Any other failure
    /// took the session with it, which ends a client's multiplexer, while a
    /// server's ends that session alone and serves the next client. The
    /// thread that wrote ends it rather than the reader, which may be waiting
    /// on a client that never sends again.
    fn send(&self, session: &Arc<Session>, message: &[u8]) -> Result<(), Error> {
        {
            let registry = lock(&self.registry);
            registry.accepting()?;
            if !registry.bound_to(session) {
                return Err(registry.session_refusal());
            }
        }
        match session.sender.send(message) {
            Ok(()) => Ok(()),
            Err(transport::Error::PacketTooLarge(size)) => Err(Error::TooLarge(size)),
            Err(err) => {
                let reason = Error::Disconnected(Arc::new(err));
                match self.side {
                    // The first failure names the reason, a send refused
                    // because the session ended meanwhile surfaces that one
                    Side::Client => {
                        self.fail(reason);
                        Err(lock(&self.registry).refusal())
                    }
                    Side::Server => {
                        self.reset(session, reason.clone());
                        Err(reason)
                    }
                }
            }
        }
    }
}

/// Reads messages until the transport ends, routing each, the end failing
/// the multiplexer with the reason, a close needing no notification. A server
/// reports observed session endings with `Event::Disconnected` and completed
/// handshakes with `Event::Connected`, so the multiplexer can bind a sender
/// before the first message arrives. The source goes with the thread,
/// permanently closing the byte stream.
fn read<Out: Envelope, In: Envelope>(
    switchboard: Arc<Switchboard<Out, In>>,
    mut source: impl Source,
    mut bound: Option<Arc<Session>>,
) {
    loop {
        let message = match source.recv() {
            Err(err) => {
                switchboard.fail(Error::Disconnected(Arc::new(err)));
                return;
            }
            // A handshake opened the next session, the responders made from
            // here on answering into it
            Ok(Event::Connected(sender)) => {
                let session = Arc::new(Session { sender });
                switchboard.bind(session.clone());
                bound = Some(session);
                continue;
            }
            // The session the multiplexer was bound to ended, what it left
            // pending failing with it and nothing live until the next opens.
            // A failed write may have ended it here already.
            Ok(Event::Disconnected) => {
                let reason = Error::Disconnected(Arc::new(transport::Error::SessionReset));
                if let Some(session) = bound.take() {
                    switchboard.reset(&session, reason);
                }
                continue;
            }
            Ok(Event::Message(message)) => message,
        };
        // A peer breaking the protocol has its session ended, which on a
        // client is the multiplexer's end and on a server the session's
        // alone, the next client served after it
        let Some(session) = &bound else { continue };
        if let Err(fault) = switchboard.route(session, message) {
            match switchboard.side {
                Side::Client => switchboard.fail(fault),
                Side::Server => {
                    source.disconnect();
                    switchboard.reset(session, fault);
                    bound = None;
                }
            }
        }
    }
}

/// Runs the handler over the inbox in arrival order until the end, a panic
/// in it being its own bug, the session carrying on. A request is answered
/// into the session it arrived in, one that ended meanwhile refusing the
/// answer rather than the next session taking it.
fn work<Out: Envelope, In: Envelope>(switchboard: Arc<Switchboard<Out, In>>) {
    loop {
        let request = {
            let mut inbox = lock(&switchboard.inbox);
            loop {
                if inbox.stopped {
                    return;
                }
                match inbox.requests.pop_front() {
                    Some(request) => {
                        inbox.bytes -= request.bytes;
                        break request;
                    }
                    None => {
                        inbox = switchboard
                            .arrived
                            .wait(inbox)
                            .unwrap_or_else(PoisonError::into_inner)
                    }
                }
            }
        };
        let sender = Arc::downgrade(&switchboard);
        let responder = Responder::new(sender, request.session, request.id);
        let Some(content) = request.content else {
            warn!("refusing request not understood: {}", request.id);
            switchboard.refuse(responder, "request not understood");
            continue;
        };
        match lock(&switchboard.handler).as_mut() {
            Some(handler) => {
                if panic::catch_unwind(AssertUnwindSafe(|| handler(content, responder))).is_err() {
                    error!("request handler panicked");
                }
            }
            None => switchboard.refuse(responder, "request not served"),
        }
    }
}

/// Locks a mutex, a poisoned one recovered, the state kept consistent by
/// the holders never panicking with it held except inside a handler, whose
/// panic is caught.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::testing::{self, PipeReader, PipeWriter};
    use crate::transport::mock::{payload, self_attestation};
    use crate::transport::{Read, Stream, Write};
    use darkbio_crypto::xdsa;
    use std::io;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    /// Fails the client's first read once the server's output fault has fired,
    /// allowing the client to abandon that attempt and reconnect on the same pipe.
    struct FaultReader {
        reader: PipeReader,
        failure: Option<mpsc::Receiver<()>>,
        deadline: Option<Instant>,
    }

    impl io::Read for FaultReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if let Some(failure) = &self.failure {
                let failed = match self.deadline {
                    Some(deadline) => failure.recv_timeout(testing::remaining(deadline)?),
                    None => failure
                        .recv()
                        .map_err(|_| mpsc::RecvTimeoutError::Disconnected),
                };
                failed.map_err(|error| match error {
                    mpsc::RecvTimeoutError::Timeout => io::ErrorKind::TimedOut,
                    mpsc::RecvTimeoutError::Disconnected => io::ErrorKind::BrokenPipe,
                })?;
                self.failure = None;
                return Err(io::Error::other("abandoned failed handshake"));
            }
            self.reader.read(buf)
        }
    }

    impl Read for FaultReader {
        fn set_read_deadline(&mut self, deadline: Option<Instant>) -> io::Result<()> {
            self.reader.set_read_deadline(deadline)?;
            self.deadline = deadline;
            Ok(())
        }
    }

    /// Reports an actual handshake read timeout so the peer can retry only
    /// after the incomplete attempt has exhausted its deadline.
    struct TimeoutReader {
        reader: PipeReader,
        expired: mpsc::Sender<()>,
    }

    impl io::Read for TimeoutReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let result = self.reader.read(buf);
            if matches!(&result, Err(err) if err.kind() == io::ErrorKind::TimedOut) {
                let _ = self.expired.send(());
            }
            result
        }
    }

    impl Read for TimeoutReader {
        fn set_read_deadline(&mut self, deadline: Option<Instant>) -> io::Result<()> {
            self.reader.set_read_deadline(deadline)
        }
    }

    /// Rejects the first server hello, reports that rejection to the client
    /// reader, and accepts all later output, including a failure notification.
    struct FaultWriter {
        writer: PipeWriter,
        failure: Option<mpsc::Sender<()>>,
        kind: io::ErrorKind,
        deadline: Option<Instant>,
    }

    impl io::Write for FaultWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if let Some(deadline) = self.deadline {
                testing::remaining(deadline)?;
            }
            if let Some(failure) = self.failure.take() {
                failure.send(()).unwrap();
                return Err(self.kind.into());
            }
            self.writer.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.writer.flush()
        }
    }

    impl Write for FaultWriter {
        fn set_write_deadline(&mut self, deadline: Instant) -> io::Result<()> {
            self.writer.set_write_deadline(deadline)?;
            self.deadline = Some(deadline);
            Ok(())
        }
    }

    // Tests the real server Source after failed handshake output or an expired
    // handshake read. It must accept a new session on the same stream, while EOF
    // still escapes. Protocol scenarios bypass the transport handshake.
    #[test]
    fn test_server_source_retries_handshake_failure() {
        testing::init_tracing();

        enum Fault {
            Write(io::ErrorKind),
            ReadTimeout,
        }

        for fault in [
            Fault::Write(io::ErrorKind::BrokenPipe),
            Fault::Write(io::ErrorKind::TimedOut),
            Fault::ReadTimeout,
        ] {
            let (ark_reader, host_writer) = testing::pipe();
            let (host_reader, ark_writer) = testing::pipe();
            let (failure, failed) = mpsc::channel();
            let (ark_reader, ark_writer, host_reader, expired) = match fault {
                Fault::Write(kind) => (
                    Box::new(ark_reader) as Reader,
                    Box::new(FaultWriter {
                        writer: ark_writer,
                        failure: Some(failure),
                        kind,
                        deadline: None,
                    }) as Writer,
                    Box::new(FaultReader {
                        reader: host_reader,
                        failure: Some(failed),
                        deadline: None,
                    }) as Reader,
                    None,
                ),
                Fault::ReadTimeout => (
                    Box::new(TimeoutReader {
                        reader: ark_reader,
                        expired: failure,
                    }) as Reader,
                    Box::new(ark_writer) as Writer,
                    Box::new(host_reader) as Reader,
                    Some(failed),
                ),
            };
            let signer = xdsa::SecretKey::generate();
            let identity = signer.public_key();
            let attestation = self_attestation(&signer);
            let closed = Arc::new(AtomicBool::new(false));
            let server = transport::Server::new(
                Stream::new(ark_reader, ark_writer, {
                    let closed = closed.clone();
                    move || closed.store(true, Ordering::Release)
                }),
                signer,
                attestation,
            )
            .set_handshake_timeout(Duration::from_secs(1));
            let peer = thread::spawn(move || {
                let mut server = server;
                let sender = match Source::recv(&mut server).unwrap() {
                    Event::Connected(sender) => sender,
                    _ => panic!("failed handshake escaped instead of being retried"),
                };
                let message = match Source::recv(&mut server).unwrap() {
                    Event::Message(message) => message,
                    _ => panic!("fresh session did not deliver its message"),
                };
                sender.send(&message).unwrap();
                assert!(matches!(
                    Source::recv(&mut server),
                    Err(transport::Error::Terminated)
                ));
                server
            });

            let mut client = transport::Client::new(Stream::new(host_reader, host_writer, || {}));
            if let Some(expired) = expired {
                // Start a handshake without providing a hello. Waiting on the
                // adapter's timeout keeps the retry from rescuing that attempt.
                client.send_frame_blob(&[]).unwrap();
                expired.recv_timeout(Duration::from_secs(5)).unwrap();
            } else {
                assert!(matches!(
                    client.connect(&identity),
                    Err(transport::Error::RecvFailed(_))
                ));
            }
            let (sender, _) = client.connect(&identity).unwrap();
            sender.send(&payload(1)).unwrap();
            assert_eq!(client.recv().unwrap(), payload(1));
            drop(sender);
            drop(client);
            let _server = peer.join().unwrap();
            assert!(!closed.load(Ordering::Acquire));
        }
    }
}
