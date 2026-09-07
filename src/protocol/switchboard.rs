// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! The machine behind a multiplexer, what its callers, its reader thread and
//! its worker thread all plug into. It keeps the requests waiting for their
//! answer, the window, the inbox and the handler, and routes what the reader
//! brings in, an answer to the caller waiting for it, a request to the
//! worker. The threads start with it and wind down when it ends.

use crate::protocol;
use crate::protocol::envelope::{Envelope, Ids, Kind, Parity};
use crate::protocol::mux::{Closer, Error, INBOX, Reader, Responder, WINDOW, Writer};
use crate::transport::{self, Attester, Emitter, Side};
use std::collections::{HashMap, VecDeque};
use std::panic::{self, AssertUnwindSafe};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use tracing::{error, warn};

/// Handler of the peer's requests, answering through the responder.
pub(super) type Handler<Out, In> = Box<dyn FnMut(<In as Envelope>::Content, Responder<Out>) + Send>;

/// Handler of a session ending without a close, with the reason.
pub(super) type Disconnect = Box<dyn FnMut(Error) + Send>;

/// Delivery of an answer to the caller waiting for it.
pub(super) type Answer<In> = SyncSender<Result<<In as Envelope>::Content, Error>>;

/// Whether the multiplexer still takes calls, and if not, why.
enum State {
    Open,          // Session live, calls taken
    Failed(Error), // Session ended for the reason, calls refused with it
    Closed,        // Closed by the owner, calls refused
}

/// The requests waiting for their answer along with the state deciding
/// whether new ones are taken and the bytes they hold of the window. One
/// lock, so a failure draining the requests cannot miss one being registered.
struct Registry<In: Envelope> {
    state: State,                               // Whether calls are taken
    pending: HashMap<u64, (Answer<In>, usize)>, // Waiting callers by id, with their bytes
    inflight: usize, // Bytes of the pending requests, bounded by the window
}

impl<In: Envelope> Registry<In> {
    /// Fails every pending request with the reason, freeing the window.
    fn drain(&mut self, reason: &Error) {
        self.inflight = 0;
        for (_, (tx, _)) in std::mem::take(&mut self.pending) {
            let _ = tx.send(Err(reason.clone()));
        }
    }

    /// Checks that calls are still taken, failing with the refusal otherwise.
    fn accepting(&self) -> Result<(), Error> {
        match &self.state {
            State::Open => Ok(()),
            _ => Err(self.refusal()),
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

/// A request of the peer's ahead of the worker.
struct Request<In: Envelope> {
    id: u64,              // Id of the request, echoed by the answer
    content: In::Content, // Content for the handler
    bytes: usize,         // Bytes the request holds of the inbox
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

/// Source of the messages a reader thread routes, a transport client or
/// server with its emitter.
pub(super) trait Source: Send + 'static {
    /// Reads the next message of the session, see the transport's.
    fn next_message(&mut self) -> Result<Vec<u8>, transport::Error>;

    /// Number of the live session, see the transport's.
    fn session(&self) -> u64;

    /// Handle of the live session, see the transport's.
    fn emitter(&self) -> Emitter<Writer>;

    /// Resets the live session, dropping it and telling the peer, if the
    /// source can go on without one, see the transport server's. A client
    /// cannot, its connection being its session.
    fn reset_session(&mut self) {}
}

impl Source for transport::Client<Reader, Writer> {
    fn next_message(&mut self) -> Result<Vec<u8>, transport::Error> {
        transport::Client::next_message(self)
    }
    fn session(&self) -> u64 {
        transport::Client::session(self)
    }
    fn emitter(&self) -> Emitter<Writer> {
        transport::Client::emitter(self)
    }
}

impl<A: Attester + Send + 'static> Source for transport::Server<Reader, Writer, A> {
    fn next_message(&mut self) -> Result<Vec<u8>, transport::Error> {
        transport::Server::next_message(self)
    }
    fn session(&self) -> u64 {
        transport::Server::session(self)
    }
    fn emitter(&self) -> Emitter<Writer> {
        transport::Server::emitter(self)
    }

    fn reset_session(&mut self) {
        transport::Server::reset_session(self);
    }
}

/// Switchboard of one multiplexer, see the module docs.
pub(super) struct Switchboard<Out: Envelope, In: Envelope> {
    side: Side, // Side of the wire, a client ending with its session, a server outliving it
    parity: Parity, // Parity of the ids this side allocates
    ids: Ids,   // Allocator of the request ids
    registry: Mutex<Registry<In>>, // Pending requests and the state
    room: Condvar, // Wakes callers waiting on the window, or for the end
    emitter: Mutex<Emitter<Writer>>, // Handle of the live session, cloned per send
    inbox: Mutex<Inbox<In>>, // Work ahead of the worker
    arrived: Condvar, // Wakes the worker
    handler: Mutex<Option<Handler<Out, In>>>, // Server of the peer's requests
    disconnect: Mutex<Option<Disconnect>>, // Handler of the session ending without a close
    closer: Mutex<Option<Closer>>, // Hook ending the transport, run once
}

impl<Out: Envelope, In: Envelope> Switchboard<Out, In> {
    /// Starts the switchboard of a side over a source, its ids of the side's
    /// parity, the reader and the worker threads with it, the closer ending
    /// the transport when the multiplexer closes or the session fails.
    pub(super) fn start(side: Side, source: impl Source, closer: Closer) -> Arc<Self> {
        let parity = Parity::from(side);
        let switchboard = Arc::new(Self {
            side,
            parity,
            ids: Ids::new(parity),
            registry: Mutex::new(Registry {
                state: State::Open,
                pending: HashMap::new(),
                inflight: 0,
            }),
            room: Condvar::new(),
            emitter: Mutex::new(source.emitter()),
            inbox: Mutex::new(Inbox {
                requests: VecDeque::new(),
                bytes: 0,
                stopped: false,
            }),
            arrived: Condvar::new(),
            handler: Mutex::new(None),
            disconnect: Mutex::new(None),
            closer: Mutex::new(Some(closer)),
        });
        let reading = switchboard.clone();
        thread::Builder::new()
            .name("wire-reader".into())
            .spawn(move || read(reading, source))
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

    /// Registers a request with its bytes, waiting for room in the window,
    /// unless the multiplexer no longer takes calls.
    pub(super) fn admit(&self, id: u64, bytes: usize, tx: Answer<In>) -> Result<(), Error> {
        let mut registry = lock(&self.registry);
        loop {
            registry.accepting()?;
            if registry.inflight + bytes <= WINDOW {
                registry.inflight += bytes;
                registry.pending.insert(id, (tx, bytes));
                return Ok(());
            }
            registry = self
                .room
                .wait(registry)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Forgets a request, freeing its bytes of the window, and tells whether
    /// it was still pending.
    pub(super) fn forget(&self, id: u64) -> bool {
        let mut registry = lock(&self.registry);
        let Some((_, bytes)) = registry.pending.remove(&id) else {
            return false;
        };
        registry.inflight -= bytes;
        self.room.notify_all();
        true
    }

    /// Sends an encoded message through the session's emitter. A message
    /// refused before sealing leaves the session alone. Any other failure
    /// means the session ended, which ends a client's multiplexer with it,
    /// while a server's carries on, the failure the caller's alone and the
    /// reader minding the sessions.
    pub(super) fn send(&self, message: &[u8]) -> Result<(), Error> {
        lock(&self.registry).accepting()?;
        match self.emitter().send_message(message) {
            Ok(()) => Ok(()),
            Err(transport::Error::PacketTooLarge(size)) => Err(Error::TooLarge(size)),
            Err(err) => match self.side {
                // The first failure names the reason, a send refused because
                // the session ended meanwhile surfaces that one instead
                Side::Client => {
                    self.fail(Error::Disconnected(Arc::new(err)));
                    Err(lock(&self.registry).refusal())
                }
                Side::Server => Err(Error::Disconnected(Arc::new(err))),
            },
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

    /// Handle of the live session.
    fn emitter(&self) -> Emitter<Writer> {
        lock(&self.emitter).clone()
    }

    /// Routes a message of the peer's, an answer to its caller, a request to
    /// the worker. One that does not decode, or an answer with neither content
    /// nor error, is the peer breaking the protocol, the fault handed back for
    /// the reader to end the session on.
    fn route(&self, message: Vec<u8>) -> Result<(), Error> {
        let bytes = message.len();
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
                // Deliver to the caller, unless it gave up on the request
                let pending = lock(&self.registry).pending.remove(&id);
                match pending {
                    Some((tx, bytes)) => {
                        let mut registry = lock(&self.registry);
                        registry.inflight -= bytes;
                        self.room.notify_all();
                        drop(registry);
                        let _ = tx.send(answer);
                    }
                    None => warn!("dropping answer to no request: {}", id),
                }
                Ok(())
            }
            Kind::Request(id) => {
                let Some(content) = content else {
                    warn!("refusing request not understood: {}", id);
                    let responder = Responder::new(self.emitter(), id);
                    self.refuse(responder, "request not understood");
                    return Ok(());
                };
                self.push(Request { id, content, bytes })
            }
        }
    }

    /// Queues a request for the worker, the reader never waiting on it. A
    /// peer filling the inbox past its limit overran its window, the fault
    /// handed back for the reader to end the session on rather than served.
    fn push(&self, request: Request<In>) -> Result<(), Error> {
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
    fn refuse(&self, responder: Responder<Out>, msg: &str) {
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
        if self.end(State::Failed(reason.clone()))
            && let Some(handler) = lock(&self.disconnect).as_mut()
        {
            handler(reason);
        }
    }

    /// Moves the switchboard to the next session of the source, the one
    /// before it having ended for the reason. Every pending request fails
    /// with it, the callers waiting for window room wake up, the requests
    /// queued for the worker are dropped, the responders made from here on
    /// answer into the new session, and the disconnect handler is told. The
    /// multiplexer carries on.
    fn reset(&self, reason: Error, emitter: Emitter<Writer>) {
        lock(&self.registry).drain(&reason);
        self.room.notify_all();
        lock(&self.inbox).clear();
        *lock(&self.emitter) = emitter;
        if let Some(handler) = lock(&self.disconnect).as_mut() {
            handler(reason);
        }
    }

    /// Ends the multiplexer in the state, failing every pending request
    /// accordingly, waking the callers waiting for window room to be refused,
    /// stopping the worker and ending the transport. Tells whether it was open
    /// until now.
    fn end(&self, state: State) -> bool {
        {
            let mut registry = lock(&self.registry);
            if !matches!(registry.state, State::Open) {
                return false;
            }
            registry.state = state;
            let refusal = registry.refusal();
            registry.drain(&refusal);
        }
        self.room.notify_all();
        {
            let mut inbox = lock(&self.inbox);
            inbox.clear();
            inbox.stopped = true;
        }
        self.arrived.notify_one();
        if let Some(closer) = lock(&self.closer).take() {
            closer();
        }
        true
    }
}

/// Reads messages until the transport ends, routing each, the end failing
/// the multiplexer with the reason, a close needing no notification. A server
/// handshakes the next client inside its read, so a message arriving in a new
/// session first resets the one before it, the peer having moved on. The
/// source goes with the thread, ending the session for the emitters.
fn read<Out: Envelope, In: Envelope>(
    switchboard: Arc<Switchboard<Out, In>>,
    mut source: impl Source,
) {
    let mut session = source.session();
    loop {
        match source.next_message() {
            Ok(message) => {
                // A new session, the one before it reset by the peer, if
                // there was one, and the responders made from here on
                // answering into the new one
                if source.session() != session {
                    let emitter = source.emitter();
                    if session == 0 {
                        *lock(&switchboard.emitter) = emitter;
                    } else {
                        let reason = Error::Disconnected(Arc::new(transport::Error::SessionReset));
                        switchboard.reset(reason, emitter);
                    }
                    session = source.session();
                }
                // A peer breaking the protocol has its session ended, which
                // on a client is the multiplexer's end and on a server the
                // session's alone, the next client served after it
                if let Err(fault) = switchboard.route(message) {
                    match switchboard.side {
                        Side::Client => switchboard.fail(fault),
                        Side::Server => {
                            source.reset_session();
                            switchboard.reset(fault, source.emitter());
                            session = source.session();
                        }
                    }
                }
            }
            Err(err) => {
                switchboard.fail(Error::Disconnected(Arc::new(err)));
                return;
            }
        }
    }
}

/// Runs the handler over the inbox in arrival order until the end, a panic
/// in it being its own bug, the session carrying on.
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
        let responder = Responder::new(switchboard.emitter(), request.id);
        match lock(&switchboard.handler).as_mut() {
            Some(handler) => {
                if panic::catch_unwind(AssertUnwindSafe(|| handler(request.content, responder)))
                    .is_err()
                {
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
