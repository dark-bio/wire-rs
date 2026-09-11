// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Session scenarios with controlled input, write results and time.
//! Scripts call the public request, reply, wait and close methods. Test hooks
//! report when a call starts waiting so later steps can run while it is blocked.

use crate::protocol::operation::{OutgoingBody, OutgoingMessage};
use crate::protocol::server::{ServerInner, SessionSource};
use crate::protocol::session::SessionInner;
use crate::protocol::{
    Closer, Error, Message, Promise, Requester, Responder, Server, Session, schema,
};
use std::collections::HashMap;
use std::sync::{Arc, Barrier, Weak, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Watchdog for scenario jobs and wait hooks, independent of operation deadlines.
const PATIENCE: Duration = Duration::from_secs(5);

/// Errors that a script can expect from a protocol call or promise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    /// The owner closed locally or no longer exists.
    Closed,
    /// A new session replaced the original one.
    Reset,
    /// The fixture dropped `SessionSource`, as if the server reader had stopped.
    Terminated,
    /// The deadline passed before the operation got a result.
    Timeout,
    /// The peer returned this application-defined error code.
    Remote(u64),
    /// The answer variant did not match the requested Rust response type.
    WrongType,
    /// The peer sent an invalid outer envelope or nested payload.
    Malformed,
    /// The inbound request limit closed the session.
    Requests,
    /// The inbound byte limit closed the session.
    Bytes,
}

/// Converts an error to the script's `Failure`, panicking on unsupported errors.
fn failure(error: Error) -> Failure {
    match error {
        Error::Closed => Failure::Closed,
        Error::Timeout => Failure::Timeout,
        Error::Transport(error) => match &*error {
            crate::transport::Error::SessionReset => Failure::Reset,
            crate::transport::Error::Terminated => Failure::Terminated,
            other => panic!("unexpected transport error: {other}"),
        },
        Error::Remote(error) => Failure::Remote(error.code),
        Error::UnexpectedResponse { .. } => Failure::WrongType,
        Error::Malformed => Failure::Malformed,
        Error::InboundRequestLimitExceeded(_) => Failure::Requests,
        Error::InboundByteLimitExceeded(_) => Failure::Bytes,
        other => panic!("unexpected protocol error: {other}"),
    }
}

/// Creates the write failures supported by scripted writer results.
fn write_error(error: Failure) -> Error {
    match error {
        Failure::Closed => Error::Closed,
        Failure::Timeout => Error::Timeout,
        Failure::Reset => crate::transport::Error::SessionReset.into(),
        Failure::Terminated => crate::transport::Error::Terminated.into(),
        other => panic!("not a write failure: {other:?}"),
    }
}

/// Builds an application response from a body tag or an application error code.
fn response(result: Result<u8, u64>) -> Result<Message, schema::Error> {
    result
        .map(|tag| vec![tag].into())
        .map_err(|code| schema::Error::new(code, "refused"))
}

/// Expected outgoing content, specified independently of the runtime queue types.
#[derive(Clone, Debug)]
enum ExpectedMessage {
    /// Locally initiated request carrying the given body tag.
    Request(u8),
    /// Reply to this peer request ID, with its body tag or error code.
    Reply(u64, Result<u8, u64>),
}

/// Requires failure with the script's exact ending reason, regardless of result type.
fn refused<T>(result: Result<T, Error>, expected: Failure) {
    match result {
        Err(error) => assert_eq!(failure(error), expected),
        Ok(_) => panic!("expected {expected:?}, operation succeeded"),
    }
}

/// Runs a blocking call on another thread and lets the script check its result.
pub(super) struct Job<T> {
    /// Completed value; disconnection also exposes a worker panic to the driver.
    result: mpsc::Receiver<T>,
    /// Worker joined after its result arrives so successful jobs leave no thread.
    thread: JoinHandle<()>,
}

impl<T: Send + 'static> Job<T> {
    /// Starts an operation without blocking the scenario's remaining steps.
    pub(super) fn start(run: impl FnOnce() -> T + Send + 'static) -> Self {
        let (result, receiver) = mpsc::channel();
        Self {
            result: receiver,
            thread: thread::spawn(move || {
                let _ = result.send(run());
            }),
        }
    }

    /// Requires the result before the watchdog expires, then joins the worker.
    ///
    /// # Panics
    /// The operation must complete within `PATIENCE` without panicking.
    pub(super) fn finish(self) -> T {
        let result = self
            .result
            .recv_timeout(PATIENCE)
            .expect("scenario operation must finish");
        self.thread
            .join()
            .expect("scenario operation must not panic");
        result
    }
}

/// Scripted actions with explicit session labels, responder slots and expectations.
/// Start/finish pairs let other steps run while a call is blocked.
#[derive(Clone, Debug)]
#[cfg_attr(not(test), allow(dead_code))]
enum Step {
    // Session setup and acceptance.
    /// Attaches a session under the given label, closing the previous session.
    Open(u8),
    /// Requires attaching a new session to fail with the given reason.
    RefuseOpen(Failure),
    /// Calls `accept()` and checks that it returns the labeled session.
    Accept(u8),
    /// Starts `accept()` and waits for the hook reporting that no session is ready.
    StartAccept,
    /// Finishes an overlapping acceptance with the given session label.
    FinishAccept(u8),
    /// Requires an overlapping acceptance to fail with this ending reason.
    FinishAcceptError(Failure),
    /// Allows either closed acceptance or an accepted session that is now closed.
    FinishAcceptClosed,

    // Session policy and usage.
    /// Changes both inbound limits through the public session setter.
    InboundLimits(u8, usize, usize),
    /// Changes both server limits for the current and future sessions.
    ServerInboundLimits(usize, usize),
    /// Sets the timeout for subsequent automatic replies.
    AutoreplyTimeout(u8, Duration),
    /// Sets the automatic reply timeout for the current and future server sessions.
    ServerAutoreplyTimeout(Duration),
    /// Checks accepted requests and retained bytes from the original envelopes.
    Usage(u8, usize, usize),

    // Incoming messages.
    /// Delivers a request: session label, request ID and one-byte body tag.
    Deliver(u8, u64, u8),
    /// Attempts fixture admission with an exact ID and expects a capacity failure.
    RejectDelivery(u8, u64, u8, Failure),
    /// Requires delivery to the labeled session to fail with the given reason.
    RefuseDelivery(u8, Failure),
    /// Passes original envelope bytes through the reader path and checks admission.
    Raw(u8, Vec<u8>, Result<(), Failure>),
    /// Receives a request: session label, expected body tag and saved responder slot.
    Receive(u8, u8, u8),
    /// Receives a full typed message and retains its responder for later steps.
    ReceiveMessage(u8, Message, u8),
    /// Starts and finishes a receive that must fail with the given ending reason.
    ReceiveError(u8, Failure),
    /// Starts receiving on the labeled session and waits until its queue wait.
    StartReceive(u8),
    /// Finishes a receive: session label, expected body tag and saved responder slot.
    FinishReceive(u8, u8, u8),
    /// Requires an overlapping receive on this session to fail with the given reason.
    FinishReceiveError(u8, Failure),

    // Request and reply submission.
    /// Submits a request: session, promise slot, body tag, absolute time in milliseconds.
    Request(u8, u8, u8, u64),
    /// Requires request submission through this session's handle to fail.
    RefuseRequest(u8, Failure),
    /// Submits a reply: responder slot, promise slot, body/error, absolute deadline.
    Reply(u8, u8, Result<u8, u64>, u64),
    /// Consumes the saved responder slot and requires reply submission to fail.
    RefuseReply(u8, Failure),
    /// Drops the saved responder slot without supplying a reply.
    DropReply(u8),
    /// Takes queued automatic replies and checks their request IDs.
    Abandoned(u8, Vec<u64>),

    // Outgoing messages and peer answers.
    /// Takes a queued message: session, outgoing slot, content and original deadline.
    Outgoing(u8, u8, ExpectedMessage, u64),
    /// Takes output using real wire-ID assignment and saves its completion handle.
    SendNext(u8, u8, u64),
    /// Checks that no unexpired messages remain in this session's outgoing queue.
    NoOutgoing(u8),
    /// Reports local write/flush completion for a retained outgoing slot.
    Written(u8, Result<(), Failure>),
    /// Supplies the peer answer for a retained outgoing request slot.
    Answer(u8, Result<u8, u64>),
    /// Supplies an answer whose content is not the byte-vector type used by the waiter.
    AnswerOther(u8),

    // Promise completion.
    /// Registers a request promise to send the supplied token on completion.
    Notify(u8, u8),
    /// Registers a reply promise to send the supplied token on completion.
    NotifyWrite(u8, u8),
    /// Drains notifications and checks the exact tokens without consuming promises.
    Notifications(Vec<u8>),
    /// Waits for a request's byte-vector answer or its exact failure.
    Wait(u8, Result<u8, Failure>),
    /// Waits for a `Message` and checks its variant and body tag.
    WaitMessage(u8, u8),
    /// Starts a request wait and waits for its blocking-call notification.
    StartWait(u8),
    /// Finishes an overlapping request wait with the expected outcome.
    FinishWait(u8, Result<u8, Failure>),
    /// Drops a request promise, leaving the request in progress.
    DropPromise(u8),
    /// Waits for a reply's local write completion.
    WaitWrite(u8, Result<(), Failure>),
    /// Starts waiting on a reply promise before reporting its write result.
    StartWaitWrite(u8),
    /// Finishes an overlapping reply wait with the expected outcome.
    FinishWaitWrite(u8, Result<(), Failure>),
    /// Drops a reply promise, leaving the reply queued or being written.
    DropWritePromise(u8),

    // Deadlines.
    /// Changes the test clock without calling `expire()`.
    Time(u64),
    /// Calls `expire()` to fail timed-out operations and discard expired messages.
    Expire(u8),
    /// Checks the earliest pending deadline, or that no operations remain.
    Deadline(u8, Option<u64>),
    /// Switches a session to wall-clock time and submits a request with this budget.
    RealRequest(u8, u8, u64),
    /// Submits a reply with a wall-clock deadline to a session already using real time.
    RealReply(u8, u8, u64),

    // Closure and release.
    /// Closes the labeled session through its saved `Closer`.
    CloseSession(u8),
    /// Drops the labeled session owner while retaining its other handles.
    DropSession(u8),
    /// Checks that the saved weak reference to this session cannot be upgraded.
    Released(u8),
    /// Closes the server through its saved `Closer`.
    CloseServer,
    /// Drops the server owner and checks weak handles do not retain its state.
    DropServer,
    /// Drops the source of sessions, modeling a terminated reader.
    DropSource,

    // Concurrent closure.
    /// Releases two threads together to close the same labeled session.
    RaceCloses(u8),
    /// Releases two threads together to close the persistent server.
    RaceServerCloses,
    /// Races server closure with attaching a session; that session must end too.
    RaceServerCloseOpen,
    /// Starts `request()` and `close()` together. The request must fail either
    /// immediately or through its promise once both calls return.
    RaceRequestClose(u8),
    /// Releases answer delivery and closure together, accepting either first result.
    RaceAnswerClose(u8, u8, u8),
    /// Starts `reply()` and `close()` together for this responder's session.
    RaceReplyClose(u8, u8),
    /// Races a reply's write result with `close()`; either result may reach the promise.
    RaceWriteClose(u8, u8, u8),
}

/// A receive result returned with its owner so the driver can use the session again.
type ReceiveResult = (Session, Result<(Message, Responder), Error>);
/// An acceptance result returned with its persistent server owner.
type AcceptResult = (Server, Result<Session, Error>);

/// Sessions, saved handles and background calls used by one script. Labels keep
/// referring to the same session after replacement so steps can exercise old handles.
struct Driver {
    /// Server owner, temporarily moved out while acceptance runs.
    server: Option<Server>,
    /// Weak reference used to check that dropping the server frees its state.
    server_ref: Weak<ServerInner>,
    /// Server closer usable while acceptance owns the server or after owner drop.
    closer: Closer,
    /// Sole source of replacement sessions in place of a real transport reader.
    source: Option<SessionSource>,
    /// In-progress acceptance job, holding the unique server owner.
    accepting: Option<Job<AcceptResult>>,

    /// Accepted owners currently available to the script, indexed by session label.
    sessions: HashMap<u8, Session>,
    /// Session references saved by `Open`, including sessions later replaced.
    session_refs: HashMap<u8, Weak<SessionInner>>,
    /// Requester handles kept after dropping their sessions.
    requesters: HashMap<u8, Requester>,
    /// Session closers retained to exercise closure after replacement or owner drop.
    closers: HashMap<u8, Closer>,
    /// In-progress receive jobs, each holding its labeled session owner.
    receiving: HashMap<u8, Job<ReceiveResult>>,

    /// Responders indexed by script slot, not by wire request ID.
    responders: HashMap<u8, Responder>,
    /// Request promises saved for later wait or drop steps.
    promises: HashMap<u8, Promise<Message>>,
    /// Reply promises saved for later wait or drop steps.
    writes: HashMap<u8, Promise<()>>,
    /// Shared event channel; tokens do not own promises or release response bytes.
    notifications: (mpsc::Sender<u8>, mpsc::Receiver<u8>),
    /// Messages taken from the queue whose write results and answers are supplied later.
    outgoing: HashMap<u8, OutgoingMessage>,
    /// Background calls waiting for request answers.
    waiting: HashMap<u8, Job<Result<Vec<u8>, Error>>>,
    /// Background calls waiting for reply write results.
    writing: HashMap<u8, Job<Result<(), Error>>>,

    /// Base for deterministic absolute deadlines, kept ahead of the wall clock.
    epoch: Instant,
    /// Current scripted time in milliseconds, independent of expiry servicing.
    time: u64,
}

impl Driver {
    /// Creates a server fixture with no attached sessions or running jobs.
    fn new() -> Self {
        let (server, source) = Server::fixture();
        let server_ref = Arc::downgrade(&server.inner);
        let closer = server.closer();
        Self {
            server: Some(server),
            server_ref,
            closer,
            source: Some(source),
            accepting: None,

            sessions: HashMap::new(),
            session_refs: HashMap::new(),
            requesters: HashMap::new(),
            closers: HashMap::new(),
            receiving: HashMap::new(),

            responders: HashMap::new(),
            promises: HashMap::new(),
            writes: HashMap::new(),
            notifications: mpsc::channel(),
            outgoing: HashMap::new(),
            waiting: HashMap::new(),
            writing: HashMap::new(),

            epoch: Instant::now() + Duration::from_secs(3600),
            time: 0,
        }
    }

    /// Checks an accepted session's identity and saves its owner and cloned handles.
    fn accepted(&mut self, id: u8, (server, result): AcceptResult) {
        self.server = Some(server);
        let session = result.unwrap();
        assert!(Weak::ptr_eq(
            &Arc::downgrade(&session.inner),
            &self.session_refs[&id]
        ));
        self.requesters.insert(id, session.requester().clone());
        self.closers.insert(id, session.closer().clone());
        assert!(self.sessions.insert(id, session).is_none());
    }

    /// Checks the received body tag, saves its responder and restores the owner.
    fn received(&mut self, id: u8, tag: u8, slot: u8, (session, result): ReceiveResult) {
        let (message, responder) = result.unwrap();
        assert_eq!(message, Message::Develop(vec![tag]));
        assert!(self.responders.insert(slot, responder).is_none());
        self.sessions.insert(id, session);
    }

    /// Converts script milliseconds into an absolute deadline.
    fn at(&self, millis: u64) -> Instant {
        self.epoch + Duration::from_millis(millis)
    }

    /// Checks a typed answer while preserving the exact error category.
    fn answer_result(result: Result<Vec<u8>, Error>, expected: Result<u8, Failure>) {
        match expected {
            Ok(tag) => assert_eq!(result.unwrap(), vec![tag]),
            Err(error) => refused(result, error),
        }
    }

    /// Checks the result of waiting for a reply to be written.
    fn write_result(result: Result<(), Error>, expected: Result<(), Failure>) {
        match expected {
            Ok(()) => result.unwrap(),
            Err(error) => refused(result, error),
        }
    }

    /// Executes one script action, using watchdogs for operations allowed to block.
    /// Assertions also reject invalid scripts, such as overwriting an owned slot.
    fn step(&mut self, step: Step) {
        match step {
            Step::Open(id) => {
                let session = self.source.as_mut().unwrap().open().unwrap();
                session.upgrade().unwrap().set_time(self.at(self.time));
                assert!(self.session_refs.insert(id, session).is_none());
            }
            Step::RefuseOpen(expected) => refused(self.source.as_mut().unwrap().open(), expected),
            Step::Accept(id) => {
                let mut server = self.server.take().unwrap();
                let accepted = Job::start(move || {
                    let result = server.accept();
                    (server, result)
                })
                .finish();
                self.accepted(id, accepted);
            }
            Step::StartAccept => {
                let mut server = self.server.take().unwrap();
                let waiting = server.inner.watch_accept_wait();
                assert!(self.accepting.is_none());
                self.accepting = Some(Job::start(move || {
                    let result = server.accept();
                    (server, result)
                }));
                waiting
                    .recv_timeout(PATIENCE)
                    .expect("accept reached its wait");
            }
            Step::FinishAccept(id) => {
                let accepted = self.accepting.take().unwrap().finish();
                self.accepted(id, accepted);
            }
            Step::FinishAcceptError(expected) => {
                let (server, result) = self.accepting.take().unwrap().finish();
                refused(result, expected);
                self.server = Some(server);
            }
            Step::FinishAcceptClosed => {
                let (server, result) = self.accepting.take().unwrap().finish();
                match result {
                    Ok(mut session) => {
                        refused(Job::start(move || session.recv()).finish(), Failure::Closed)
                    }
                    Err(error) => assert_eq!(failure(error), Failure::Closed),
                }
                self.server = Some(server);
            }
            Step::InboundLimits(id, requests, bytes) => {
                let session = self
                    .sessions
                    .remove(&id)
                    .unwrap()
                    .set_inbound_limits(requests, bytes);
                self.sessions.insert(id, session);
            }
            Step::ServerInboundLimits(requests, bytes) => {
                self.server = Some(
                    self.server
                        .take()
                        .unwrap()
                        .set_inbound_limits(requests, bytes),
                );
            }
            Step::AutoreplyTimeout(id, timeout) => {
                let session = self.sessions.remove(&id).unwrap();
                self.sessions
                    .insert(id, session.set_autoreply_timeout(timeout));
            }
            Step::ServerAutoreplyTimeout(timeout) => {
                self.server = Some(self.server.take().unwrap().set_autoreply_timeout(timeout));
            }
            Step::Usage(id, requests, bytes) => {
                assert_eq!(
                    self.session_refs[&id].upgrade().unwrap().inbound_usage(),
                    (requests, bytes)
                );
            }
            Step::Deliver(id, request, tag) => {
                self.session_refs[&id]
                    .upgrade()
                    .unwrap()
                    .inject_request(request, Message::Develop(vec![tag]))
                    .unwrap();
            }
            Step::RejectDelivery(id, request, tag, expected) => {
                refused(
                    self.session_refs[&id]
                        .upgrade()
                        .unwrap()
                        .inject_request(request, vec![tag].into()),
                    expected,
                );
            }
            Step::RefuseDelivery(id, expected) => {
                refused(
                    self.session_refs[&id]
                        .upgrade()
                        .unwrap()
                        .inject_request(1, Message::Develop(vec![0xff])),
                    expected,
                );
            }
            Step::Raw(id, bytes, expected) => {
                let session = self.session_refs[&id].upgrade().unwrap();
                let result = session.handle_message(bytes);
                if let Err(error) = &result {
                    session.close(error.clone());
                }
                assert_eq!(result.map_err(failure), expected);
            }
            Step::Receive(id, tag, slot) => {
                let mut session = self.sessions.remove(&id).unwrap();
                let received = Job::start(move || {
                    let result = session.recv();
                    (session, result)
                })
                .finish();
                self.received(id, tag, slot, received);
            }
            Step::ReceiveMessage(id, expected, slot) => {
                let mut session = self.sessions.remove(&id).unwrap();
                let (session, result) = Job::start(move || {
                    let result = session.recv();
                    (session, result)
                })
                .finish();
                let (message, responder) = result.unwrap();
                assert_eq!(message, expected);
                assert!(self.responders.insert(slot, responder).is_none());
                self.sessions.insert(id, session);
            }
            Step::ReceiveError(id, expected) => {
                let mut session = self.sessions.remove(&id).unwrap();
                let (session, result) = Job::start(move || {
                    let result = session.recv();
                    (session, result)
                })
                .finish();
                refused(result, expected);
                self.sessions.insert(id, session);
            }
            Step::StartReceive(id) => {
                let mut session = self.sessions.remove(&id).unwrap();
                let waiting = session.inner.watch_recv_wait();
                let job = Job::start(move || {
                    let result = session.recv();
                    (session, result)
                });
                assert!(self.receiving.insert(id, job).is_none());
                waiting
                    .recv_timeout(PATIENCE)
                    .expect("receive reached its wait");
            }
            Step::FinishReceive(id, tag, slot) => {
                let received = self.receiving.remove(&id).unwrap().finish();
                self.received(id, tag, slot, received);
            }
            Step::FinishReceiveError(id, expected) => {
                let (session, result) = self.receiving.remove(&id).unwrap().finish();
                refused(result, expected);
                self.sessions.insert(id, session);
            }
            Step::Request(id, slot, tag, deadline) => {
                let requester = self.requesters[&id].clone();
                let deadline = self.at(deadline);
                let promise = Job::start(move || requester.request(vec![tag], deadline))
                    .finish()
                    .unwrap();
                assert!(self.promises.insert(slot, promise).is_none());
            }
            Step::RefuseRequest(id, expected) => {
                refused(
                    self.requesters[&id].request(vec![1], Instant::now()),
                    expected,
                );
            }
            Step::Reply(responder, slot, result, deadline) => {
                let responder = self.responders.remove(&responder).unwrap();
                let deadline = self.at(deadline);
                let promise = Job::start(move || match response(result) {
                    Ok(message) => responder.reply(message, deadline),
                    Err(error) => responder.fail(error, deadline),
                })
                .finish()
                .unwrap();
                assert!(self.writes.insert(slot, promise).is_none());
            }
            Step::RefuseReply(slot, expected) => {
                refused(
                    self.responders
                        .remove(&slot)
                        .unwrap()
                        .reply(vec![1], Instant::now()),
                    expected,
                );
            }
            Step::DropReply(slot) => {
                let responder = self.responders.remove(&slot).unwrap();
                Job::start(move || drop(responder)).finish();
            }
            Step::Abandoned(id, expected) => {
                let session = self.session_refs[&id].upgrade().unwrap();
                for id in expected {
                    let outgoing = session.take_outgoing().expect("abandonment queued");
                    let OutgoingBody::Reply {
                        id: actual,
                        result: Err(error),
                    } = outgoing.body
                    else {
                        panic!("expected an abandonment reply");
                    };
                    assert_eq!(actual, id);
                    assert_eq!(error.code, schema::ReservedErrors::Unanswered as u64);
                    assert_eq!(error.msg, "request left unanswered");
                    outgoing.operation.record_write(Ok(()));
                }
                assert!(
                    session.take_outgoing().is_none(),
                    "unexpected additional outgoing message"
                );
            }
            Step::Outgoing(id, slot, expected, deadline) => {
                let outgoing = self.session_refs[&id]
                    .upgrade()
                    .unwrap()
                    .take_outgoing()
                    .expect("outgoing queued");
                assert_eq!(outgoing.deadline, self.at(deadline));
                match (&outgoing.body, expected) {
                    (OutgoingBody::Request(message), ExpectedMessage::Request(tag)) => {
                        assert_eq!(message, &Message::Develop(vec![tag]))
                    }
                    (
                        OutgoingBody::Reply { id, result },
                        ExpectedMessage::Reply(expected_id, expected),
                    ) => {
                        assert_eq!(*id, expected_id);
                        match (result, expected) {
                            (Ok(message), Ok(tag)) => {
                                assert_eq!(message, &Message::Develop(vec![tag]))
                            }
                            (Err(error), Err(code)) => {
                                assert_eq!(error.code, code);
                                assert_eq!(
                                    error.msg,
                                    if code == schema::ReservedErrors::Unanswered as u64 {
                                        "request left unanswered"
                                    } else if code == schema::ReservedErrors::Unknown as u64 {
                                        "request not known"
                                    } else {
                                        "refused"
                                    }
                                );
                            }
                            _ => panic!("unexpected reply result"),
                        }
                    }
                    _ => panic!("unexpected outgoing kind"),
                }
                assert!(self.outgoing.insert(slot, outgoing).is_none());
            }
            Step::SendNext(id, slot, wire_id) => {
                let session = self.session_refs[&id].upgrade().unwrap();
                let (actual, outgoing) = Job::start(move || session.next_outgoing())
                    .finish()
                    .unwrap();
                assert_eq!(actual, wire_id);
                assert!(self.outgoing.insert(slot, outgoing).is_none());
            }
            Step::NoOutgoing(id) => assert!(
                self.session_refs[&id]
                    .upgrade()
                    .unwrap()
                    .take_outgoing()
                    .is_none()
            ),
            Step::Written(slot, result) => self.outgoing[&slot]
                .operation
                .record_write(result.map_err(write_error)),
            Step::Answer(slot, result) => {
                let outgoing = self.outgoing.remove(&slot).unwrap();
                assert!(matches!(outgoing.body, OutgoingBody::Request(_)));
                outgoing.operation.record_response(response(result));
            }
            Step::AnswerOther(slot) => {
                let outgoing = self.outgoing.remove(&slot).unwrap();
                assert!(matches!(outgoing.body, OutgoingBody::Request(_)));
                outgoing.operation.record_response(Ok(
                    crate::protocol::schema::DeviceInfoRequest::default().into(),
                ));
            }
            Step::Notify(slot, token) => self
                .promises
                .get_mut(&slot)
                .unwrap()
                .notify(self.notifications.0.clone(), token),
            Step::NotifyWrite(slot, token) => self
                .writes
                .get_mut(&slot)
                .unwrap()
                .notify(self.notifications.0.clone(), token),
            Step::Notifications(mut expected) => {
                let mut received: Vec<_> = self.notifications.1.try_iter().collect();
                received.sort_unstable();
                expected.sort_unstable();
                assert_eq!(received, expected);
            }
            Step::Wait(slot, expected) => {
                let promise = self.promises.remove(&slot).unwrap();
                Self::answer_result(Job::start(move || promise.wait()).finish(), expected);
            }
            Step::WaitMessage(slot, tag) => {
                let promise = self.promises.remove(&slot).unwrap();
                assert_eq!(
                    Job::start(move || promise.wait::<Message>())
                        .finish()
                        .unwrap(),
                    Message::Develop(vec![tag])
                );
            }
            Step::StartWait(slot) => {
                let mut promise = self.promises.remove(&slot).unwrap();
                let waiting = promise.watch_wait();
                assert!(
                    self.waiting
                        .insert(slot, Job::start(move || promise.wait()))
                        .is_none()
                );
                waiting
                    .recv_timeout(PATIENCE)
                    .expect("request reached its wait");
            }
            Step::FinishWait(slot, expected) => {
                Self::answer_result(self.waiting.remove(&slot).unwrap().finish(), expected)
            }
            Step::DropPromise(slot) => drop(self.promises.remove(&slot).unwrap()),
            Step::WaitWrite(slot, expected) => {
                let promise = self.writes.remove(&slot).unwrap();
                Self::write_result(Job::start(move || promise.wait()).finish(), expected);
            }
            Step::StartWaitWrite(slot) => {
                let mut promise = self.writes.remove(&slot).unwrap();
                let waiting = promise.watch_wait();
                assert!(
                    self.writing
                        .insert(slot, Job::start(move || promise.wait()))
                        .is_none()
                );
                waiting
                    .recv_timeout(PATIENCE)
                    .expect("reply reached its wait");
            }
            Step::FinishWaitWrite(slot, expected) => {
                Self::write_result(self.writing.remove(&slot).unwrap().finish(), expected)
            }
            Step::DropWritePromise(slot) => drop(self.writes.remove(&slot).unwrap()),
            Step::Time(time) => {
                assert!(time >= self.time);
                self.time = time;
                for session in self.session_refs.values().filter_map(Weak::upgrade) {
                    session.set_time(self.at(time));
                }
            }
            Step::Expire(id) => self.session_refs[&id].upgrade().unwrap().expire(),
            Step::Deadline(id, expected) => assert_eq!(
                self.session_refs[&id].upgrade().unwrap().next_deadline(),
                expected.map(|time| self.at(time))
            ),
            Step::RealRequest(id, slot, budget) => {
                self.session_refs[&id].upgrade().unwrap().use_realtime();
                let promise = self.requesters[&id]
                    .request(vec![1], Instant::now() + Duration::from_millis(budget))
                    .unwrap();
                assert!(self.promises.insert(slot, promise).is_none());
            }
            Step::RealReply(responder, slot, budget) => {
                let responder = self.responders.remove(&responder).unwrap();
                let promise = responder
                    .reply(vec![2], Instant::now() + Duration::from_millis(budget))
                    .unwrap();
                assert!(self.writes.insert(slot, promise).is_none());
            }
            Step::CloseSession(id) => {
                let closer = self.closers[&id].clone();
                Job::start(move || closer.close()).finish();
            }
            Step::DropSession(id) => {
                let session = self.sessions.remove(&id).unwrap();
                Job::start(move || drop(session)).finish();
            }
            Step::Released(id) => assert!(self.session_refs[&id].upgrade().is_none()),
            Step::CloseServer => {
                let closer = self.closer.clone();
                Job::start(move || closer.close()).finish();
            }
            Step::DropServer => {
                let server = self.server.take().unwrap();
                Job::start(move || drop(server)).finish();
                assert!(
                    self.server_ref.upgrade().is_none(),
                    "closer/source must not retain server state"
                );
            }
            Step::DropSource => drop(self.source.take().unwrap()),
            step @ (Step::RaceCloses(_) | Step::RaceServerCloses) => {
                let closer = match step {
                    Step::RaceCloses(id) => self.closers[&id].clone(),
                    Step::RaceServerCloses => self.closer.clone(),
                    _ => unreachable!(),
                };
                let gate = Arc::new(Barrier::new(3));
                let jobs: Vec<_> = (0..2)
                    .map(|_| {
                        let closer = closer.clone();
                        let gate = gate.clone();
                        Job::start(move || {
                            gate.wait();
                            closer.close();
                        })
                    })
                    .collect();
                gate.wait();
                for job in jobs {
                    job.finish();
                }
            }
            Step::RaceServerCloseOpen => {
                let gate = Arc::new(Barrier::new(3));
                let mut source = self.source.take().unwrap();
                let opened = {
                    let gate = gate.clone();
                    Job::start(move || {
                        gate.wait();
                        let result = source.open();
                        (source, result)
                    })
                };
                let closer = self.closer.clone();
                let closed = {
                    let gate = gate.clone();
                    Job::start(move || {
                        gate.wait();
                        closer.close();
                    })
                };
                gate.wait();
                closed.finish();
                let (source, result) = opened.finish();
                // If accept() took the session, it may still exist but must be
                // closed now. Otherwise server closure also drops that session.
                match result {
                    Ok(session) => {
                        if let Some(session) = session.upgrade() {
                            refused(session.inject_request(1, vec![1].into()), Failure::Closed);
                        }
                    }
                    Err(error) => assert_eq!(failure(error), Failure::Closed),
                }
                self.source = Some(source);
            }
            Step::RaceRequestClose(id) => {
                let requester = self.requesters[&id].clone();
                let closer = self.closers[&id].clone();
                let deadline = self.at(self.time + 100);
                let gate = Arc::new(Barrier::new(3));
                let requested = {
                    let gate = gate.clone();
                    Job::start(move || {
                        gate.wait();
                        requester.request(vec![1], deadline)
                    })
                };
                let closed = {
                    let gate = gate.clone();
                    Job::start(move || {
                        gate.wait();
                        closer.close();
                    })
                };
                gate.wait();
                closed.finish();
                match requested.finish() {
                    Ok(promise) => refused(
                        Job::start(move || promise.wait::<Message>()).finish(),
                        Failure::Closed,
                    ),
                    Err(error) => assert_eq!(failure(error), Failure::Closed),
                }
            }
            Step::RaceAnswerClose(id, outgoing, promise) => {
                let outgoing = self.outgoing.remove(&outgoing).unwrap();
                let promise = self.promises.remove(&promise).unwrap();
                let closer = self.closers[&id].clone();
                let gate = Arc::new(Barrier::new(3));
                let answered = {
                    let gate = gate.clone();
                    Job::start(move || {
                        gate.wait();
                        outgoing.operation.record_response(response(Ok(42)));
                    })
                };
                let closed = {
                    let gate = gate.clone();
                    Job::start(move || {
                        gate.wait();
                        closer.close();
                    })
                };
                gate.wait();
                closed.finish();
                answered.finish();
                match Job::start(move || promise.wait::<Vec<u8>>()).finish() {
                    Ok(body) => assert_eq!(body, vec![42]),
                    Err(error) => assert_eq!(failure(error), Failure::Closed),
                }
            }
            Step::RaceReplyClose(id, responder) => {
                let responder = self.responders.remove(&responder).unwrap();
                let closer = self.closers[&id].clone();
                let deadline = self.at(self.time + 100);
                let gate = Arc::new(Barrier::new(3));
                let replied = {
                    let gate = gate.clone();
                    Job::start(move || {
                        gate.wait();
                        responder.reply(vec![42], deadline)
                    })
                };
                let closed = {
                    let gate = gate.clone();
                    Job::start(move || {
                        gate.wait();
                        closer.close();
                    })
                };
                gate.wait();
                closed.finish();
                match replied.finish() {
                    Ok(promise) => {
                        refused(Job::start(move || promise.wait()).finish(), Failure::Closed)
                    }
                    Err(error) => assert_eq!(failure(error), Failure::Closed),
                }
            }
            Step::RaceWriteClose(id, outgoing, promise) => {
                let outgoing = self.outgoing.remove(&outgoing).unwrap();
                let promise = self.writes.remove(&promise).unwrap();
                let closer = self.closers[&id].clone();
                let gate = Arc::new(Barrier::new(3));
                let record_write = {
                    let gate = gate.clone();
                    Job::start(move || {
                        gate.wait();
                        outgoing.operation.record_write(Ok(()));
                    })
                };
                let closed = {
                    let gate = gate.clone();
                    Job::start(move || {
                        gate.wait();
                        closer.close();
                    })
                };
                gate.wait();
                closed.finish();
                record_write.finish();
                if let Err(error) = Job::start(move || promise.wait()).finish() {
                    assert_eq!(failure(error), Failure::Closed);
                }
            }
        }
    }
}

impl Drop for Driver {
    /// Closes the server so blocked calls wake up even if an assertion panics.
    fn drop(&mut self) {
        self.closer.close();
        for closer in self.closers.values() {
            closer.close();
        }
    }
}

/// Runs a scenario, reporting the exact failed step and rejecting unfinished jobs.
fn run(steps: Vec<Step>) {
    let mut driver = Driver::new();
    for (index, step) in steps.into_iter().enumerate() {
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| driver.step(step.clone())));
        if let Err(error) = result {
            eprintln!("lifecycle scenario failed at step {index}: {step:?}");
            std::panic::resume_unwind(error);
        }
    }
    assert!(
        driver.receiving.is_empty(),
        "unfinished receive in scenario"
    );
    assert!(driver.accepting.is_none(), "unfinished accept in scenario");
    assert!(
        driver.waiting.is_empty(),
        "unfinished request wait in scenario"
    );
    assert!(
        driver.writing.is_empty(),
        "unfinished reply wait in scenario"
    );
}

#[cfg(test)]
mod tests;

mod fuzz;
pub use fuzz::{Action, Kind, run as fuzz};
