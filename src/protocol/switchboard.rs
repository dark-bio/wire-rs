// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! The machine behind a multiplexer, what its callers, its reader thread and
//! its worker thread all plug into. It keeps the requests waiting for their
//! answer, the window, the inbox and the handler, and routes what the reader
//! brings in, an answer to the caller waiting for it, a request to the
//! worker. The threads start with it and wind down when it ends.

use crate::protocol;
use crate::protocol::envelope::{Envelope, Ids, Kind, Parity};
use crate::protocol::mux::{CHARGE, Closer, Error, INBOX, Reader, Responder, WINDOW, Writer};
use crate::transport::{self, Attester, Emitter, Event, MAX_MESSAGE_SIZE, Side};
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

/// The requests waiting for their answer, along with the counters deciding if
/// new ones can be admitted.
struct Registry<In: Envelope> {
    state: State,                               // Whether calls are admitted in
    pending: HashMap<u64, (Answer<In>, usize)>, // Waiting callers by id, with their bytes

    inflight: usize, // Bytes of the pending requests, bounded by the window
    waiting: usize,  // Callers parked on the window
    session: u64,    // Session the switchboard is bound to, zero for none

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

    /// Fails every pending request with a reason.
    fn drain(&mut self, reason: &Error) {
        self.inflight = 0;
        for (_, (tx, _)) in std::mem::take(&mut self.pending) {
            let _ = tx.send(Err(reason.clone()));
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
    emitter: Emitter<Writer>,     // Handle of the session it arrived in
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
pub(super) trait Sender: Send + Sync {
    /// Sends an encoded message through the emitter of a session, see the
    /// switchboard's own send.
    fn send(&self, emitter: &Emitter<Writer>, message: &[u8]) -> Result<(), Error>;
}

/// Source of the messages a reader thread routes, a transport client or
/// server with its emitter.
pub(super) trait Source: Send + 'static {
    /// Reads the next message of the session, or the session ending and the
    /// next one opening, see the transport server's. A client's session is
    /// its connection, so it only ever reads messages.
    fn next_event(&mut self) -> Result<Event, transport::Error>;

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
    fn next_event(&mut self) -> Result<Event, transport::Error> {
        transport::Client::next_message(self).map(Event::Message)
    }
    fn session(&self) -> u64 {
        transport::Client::session(self)
    }
    fn emitter(&self) -> Emitter<Writer> {
        transport::Client::emitter(self)
    }
}

impl<A: Attester + Send + 'static> Source for transport::Server<Reader, Writer, A> {
    fn next_event(&mut self) -> Result<Event, transport::Error> {
        transport::Server::next_event(self)
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
                waiting: 0,
                session: source.session(),
                ended: None,
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

    /// Sends a request registered under its id, the answer to reach the
    /// caller, waiting for room in the window first. It is registered before
    /// it is sent, so an answer racing the send finds its caller, and it goes
    /// into the session it was registered in and no other, a reset in between
    /// failing it rather than handing it to the next peer.
    pub(super) fn request(&self, id: u64, message: &[u8], tx: Answer<In>) -> Result<(), Error> {
        let emitter = self.admit(id, message.len(), tx)?;
        if let Err(err) = self.send(&emitter, message) {
            self.withdraw(id);
            return Err(err);
        }
        Ok(())
    }

    /// Registers a request, waiting for enough room in the window to avoid
    /// overloading the remote peer. It costs the window its bytes or the
    /// least a request is charged, whichever is more, so a peer cannot hold
    /// more of them than the window suggests by keeping them small. Hands
    /// back the emitter of the session the request is registered in.
    fn admit(&self, id: u64, bytes: usize, tx: Answer<In>) -> Result<Emitter<Writer>, Error> {
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
        let session = registry.session;

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

            // Sanity chek that no new session was established since
            if registry.session != session {
                let ended = registry.ended.clone();
                return Err(ended.expect("a session that ended left its reason"));
            }
        }
        // Message admitted into the registry, insert it
        registry.inflight += bytes;
        registry.pending.insert(id, (tx, bytes));
        Ok(lock(&self.emitter).clone())
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

    /// Binds the switchboard to the first session of the source, nothing
    /// before it to end, the responders made from here on answering into it.
    pub(super) fn bind(&self, emitter: Emitter<Writer>, session: u64) {
        let mut registry = lock(&self.registry);
        registry.session = session;
        *lock(&self.emitter) = emitter;
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
    fn route(self: &Arc<Self>, message: Vec<u8>) -> Result<(), Error> {
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
                // entry leaves the registry and frees its bytes under one
                // hold, or a drain in between zeroes the bytes first
                let delivery = {
                    let mut registry = lock(&self.registry);
                    registry.pending.remove(&id).map(|(tx, bytes)| {
                        registry.inflight -= bytes;
                        tx
                    })
                };
                match delivery {
                    Some(tx) => {
                        self.room.notify_all();
                        let _ = tx.send(answer);
                    }
                    None => warn!("dropping answer to no request: {}", id),
                }
                Ok(())
            }
            // One the multiplexer cannot read is queued all the same, the
            // worker refusing it, so the reader never waits on a write
            Kind::Request(id) => {
                let emitter = self.emitter();
                self.push(Request {
                    id,
                    content,
                    bytes,
                    emitter,
                })
            }
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
        if registry.session != request.emitter.session() {
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
        if self.end(State::Failed(reason.clone()))
            && let Some(handler) = lock(&self.disconnect).as_mut()
        {
            handler(reason);
        }
    }

    /// Ends the session the switchboard is bound to, which ended for the
    /// reason, leaving it bound to none until the next one opens. Every
    /// pending request fails with it, the callers waiting for window room
    /// wake up to be refused with it, the requests queued for the worker are
    /// dropped, the responders made from here on answer nowhere, and the
    /// disconnect handler is told. The multiplexer carries on. The session
    /// and the emitter move under the registry's lock, the one a request
    /// registers under, so no request straddles the two sessions. A session
    /// the switchboard already moved off ends nothing, whichever thread saw
    /// it die having done this first.
    pub(super) fn reset(&self, session: u64, reason: Error, emitter: Emitter<Writer>) {
        {
            // Everything the session leaves behind goes under the one lock a
            // request registers under, or the reader could bind the next
            // session and queue its requests into what this is clearing
            let mut registry = lock(&self.registry);
            if session == 0 || registry.session != session {
                return;
            }
            registry.drain(&reason);
            registry.session = 0;
            registry.ended = Some(reason.clone());
            *lock(&self.emitter) = emitter;
            lock(&self.inbox).clear();
        }
        self.room.notify_all();
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
            // Under the one lock a request registers under, as a reset is,
            // so nothing the reader brings in outlives the end
            let mut registry = lock(&self.registry);
            if !matches!(registry.state, State::Open) {
                return false;
            }
            registry.state = state;
            let refusal = registry.refusal();
            registry.drain(&refusal);

            let mut inbox = lock(&self.inbox);
            inbox.clear();
            inbox.stopped = true;
        }
        self.room.notify_all();
        self.arrived.notify_one();
        if let Some(closer) = lock(&self.closer).take() {
            closer();
        }
        true
    }
}

impl<Out: Envelope, In: Envelope> Sender for Switchboard<Out, In> {
    /// Sends an encoded message through the emitter of a session. A message
    /// refused before sealing leaves the session alone. Any other failure
    /// took the session with it, which ends a client's multiplexer, while a
    /// server's ends that session alone and serves the next client. The
    /// thread that wrote ends it rather than the reader, which may be waiting
    /// on a client that never sends again.
    fn send(&self, emitter: &Emitter<Writer>, message: &[u8]) -> Result<(), Error> {
        lock(&self.registry).accepting()?;
        match emitter.send_message(message) {
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
                        self.reset(emitter.session(), reason.clone(), emitter.clone());
                        Err(reason)
                    }
                }
            }
        }
    }
}

/// Reads messages until the transport ends, routing each, the end failing
/// the multiplexer with the reason, a close needing no notification. A server
/// reports a session ending as soon as it does and the handshake opening the
/// next one as soon as that concludes, so the multiplexer follows the client
/// without waiting for it to say anything. The source goes with the thread,
/// ending the session for the emitters.
fn read<Out: Envelope, In: Envelope>(
    switchboard: Arc<Switchboard<Out, In>>,
    mut source: impl Source,
) {
    let mut bound = source.session();
    loop {
        let message = match source.next_event() {
            Err(err) => {
                switchboard.fail(Error::Disconnected(Arc::new(err)));
                return;
            }
            // A handshake opened the next session, the responders made from
            // here on answering into it
            Ok(Event::SessionOpened) => {
                bound = source.session();
                switchboard.bind(source.emitter(), bound);
                continue;
            }
            // The session the multiplexer was bound to ended, what it left
            // pending failing with it and nothing live until the next opens.
            // A failed write may have ended it here already.
            Ok(Event::SessionClosed) => {
                let reason = Error::Disconnected(Arc::new(transport::Error::SessionReset));
                switchboard.reset(bound, reason, source.emitter());
                bound = 0;
                continue;
            }
            Ok(Event::Message(message)) => message,
        };
        // A peer breaking the protocol has its session ended, which on a
        // client is the multiplexer's end and on a server the session's
        // alone, the next client served after it
        if let Err(fault) = switchboard.route(message) {
            match switchboard.side {
                Side::Client => switchboard.fail(fault),
                Side::Server => {
                    source.reset_session();
                    switchboard.reset(bound, fault, source.emitter());
                    bound = 0;
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
        let responder = Responder::new(sender, request.emitter, request.id);
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
