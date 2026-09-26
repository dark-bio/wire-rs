// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Session scenarios with controlled input, write results and time.
//!
//! Scripts call the public request, reply, wait and close methods, while the
//! driver stands in for the transport reader and writer. Test hooks report when
//! a call starts waiting, so later steps can run while it is blocked.

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

/// Errors that a script can expect from a protocol call or promise.
///
/// Write results scripted through [`write_error`] can also end an operation
/// with `Closed`, `Reset`, `Terminated` or `Timeout`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    /// The session or server was closed locally, or its owner was dropped.
    Closed,
    /// A replacement session reset the original one.
    Reset,
    /// The driver dropped the [`SessionSource`], as if the server reader had
    /// stopped.
    Terminated,
    /// The deadline passed before the operation got a result.
    Timeout,
    /// The peer answered with an error carrying this code.
    Remote(u64),
    /// The answer's variant did not match the response type the wait asked for.
    WrongType,
    /// The peer sent an invalid envelope or payload, or reused a request ID
    /// that is still reserved.
    Malformed,
    /// The inbound request limit closed the session.
    Requests,
    /// The inbound byte limit closed the session.
    Bytes,
}

/// Maps a protocol error to the script's [`Failure`].
///
/// # Panics
///
/// Panics on an error no scenario expects, such as [`Error::TooLarge`].
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

/// Maps a scripted write failure to the error the writer would report.
///
/// # Panics
///
/// Panics on a failure no write can report, such as `Remote`.
fn write_error(error: Failure) -> Error {
    match error {
        Failure::Closed => Error::Closed,
        Failure::Timeout => Error::Timeout,
        Failure::Reset => crate::transport::Error::SessionReset.into(),
        Failure::Terminated => crate::transport::Error::Terminated.into(),
        other => panic!("not a write failure: {other:?}"),
    }
}

/// Builds a one-byte development body from a tag, or an error with the code and
/// the message `refused`.
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

/// Asserts that a result failed with the expected reason, whatever its success
/// type.
fn refused<T>(result: Result<T, Error>, expected: Failure) {
    match result {
        Err(error) => assert_eq!(failure(error), expected),
        Ok(_) => panic!("expected {expected:?}, operation succeeded"),
    }
}

/// Blocking call running on its own thread, whose result the script collects
/// later.
pub(super) struct Job<T> {
    /// Receiver of the call's value, disconnected without one if the call panics.
    result: mpsc::Receiver<T>,
    /// Thread running the call, joined once its result arrives so a finished
    /// job leaves no thread behind.
    thread: JoinHandle<()>,
}

impl<T: Send + 'static> Job<T> {
    /// Starts the call on a new thread without blocking the script's remaining
    /// steps.
    pub(super) fn start(run: impl FnOnce() -> T + Send + 'static) -> Self {
        let (result, receiver) = mpsc::channel();
        Self {
            result: receiver,
            thread: thread::spawn(move || {
                let _ = result.send(run());
            }),
        }
    }

    /// Waits for the call's result and joins its thread.
    ///
    /// # Panics
    ///
    /// Panics if the call panicked.
    pub(super) fn finish(self) -> T {
        let result = self.result.recv().expect("scenario operation must finish");
        self.thread
            .join()
            .expect("scenario operation must not panic");
        result
    }
}

/// One script action, naming sessions by label and saved handles by slot.
///
/// A step also carries the outcome it expects. A body tag stands for a one-byte
/// development body. Start and finish pairs let other steps run while a call is
/// blocked.
#[derive(Clone, Debug)]
#[cfg_attr(not(test), allow(dead_code))]
enum Step {
    /// Session attached through the source under this label, resetting the
    /// previous one.
    Open(u8),
    /// Attachment of a new session that must fail with this reason.
    RefuseOpen(Failure),
    /// Acceptance that must return the labeled session, whose owner and
    /// handles the driver saves.
    Accept(u8),
    /// Acceptance started on its own thread, returning once `accept()` waits
    /// for a session.
    StartAccept,
    /// End of a started acceptance, which must return the labeled session.
    FinishAccept(u8),
    /// End of a started acceptance, which must fail with this reason.
    FinishAcceptError(Failure),
    /// End of a started acceptance, which either fails with `Closed` or returns
    /// a session already closed.
    FinishAcceptClosed,

    /// Request and byte limits set through the labeled session's public setter.
    InboundLimits(u8, usize, usize),
    /// Request and byte limits set on the server for the current and future
    /// sessions.
    ServerInboundLimits(usize, usize),
    /// Timeout set on the labeled session for its later automatic replies.
    AutoreplyTimeout(u8, Duration),
    /// Automatic reply timeout set on the server for the current and future
    /// sessions.
    ServerAutoreplyTimeout(Duration),
    /// Expected count of accepted requests and retained envelope bytes in the
    /// labeled session.
    Usage(u8, usize, usize),

    /// Request with this ID and body tag, which the labeled session must admit.
    Deliver(u8, u64, u8),
    /// Request with this ID and body tag, which the labeled session must refuse
    /// with the given reason.
    RejectDelivery(u8, u64, u8, Failure),
    /// Request that the labeled session must refuse with this reason.
    RefuseDelivery(u8, Failure),
    /// Envelope bytes passed through the labeled session's reader handling, with
    /// the expected result.
    ///
    /// A failure closes the session, as the reader does.
    Raw(u8, Vec<u8>, Result<(), Failure>),
    /// Receive on the labeled session, expecting this body tag and saving the
    /// responder in a slot.
    Receive(u8, u8, u8),
    /// Receive on the labeled session, expecting this whole message and saving
    /// the responder in a slot.
    ReceiveMessage(u8, Message, u8),
    /// Receive on the labeled session that must fail with this reason.
    ReceiveError(u8, Failure),
    /// Receive started on its own thread, returning once it waits on the labeled
    /// session's empty queue.
    StartReceive(u8),
    /// End of a started receive, expecting this body tag and saving the
    /// responder in a slot.
    FinishReceive(u8, u8, u8),
    /// End of a started receive, which must fail with this reason.
    FinishReceiveError(u8, Failure),

    /// Request from the labeled session with this body tag and a deadline in
    /// script milliseconds, saving its promise in a slot.
    Request(u8, u8, u8, u64),
    /// Request through the labeled session's requester that must fail with this
    /// reason.
    RefuseRequest(u8, Failure),
    /// Reply through a saved responder, with a body tag or error code and a
    /// deadline in script milliseconds, saving its promise in a slot.
    Reply(u8, u8, Result<u8, u64>, u64),
    /// Reply through a saved responder that must fail with this reason.
    RefuseReply(u8, Failure),
    /// Saved responder dropped without a reply.
    DropReply(u8),
    /// `UNANSWERED` replies taken from the labeled session's queue and written,
    /// answering these request IDs in order.
    ///
    /// Nothing else may be queued behind them.
    Abandoned(u8, Vec<u64>),

    /// Message taken from the labeled session's queue into an outgoing slot,
    /// carrying this content and deadline in script milliseconds.
    Outgoing(u8, u8, ExpectedMessage, u64),
    /// Message taken the way the writer takes it into an outgoing slot,
    /// expecting this wire ID.
    SendNext(u8, u8, u64),
    /// Check that the labeled session has no unexpired message queued.
    NoOutgoing(u8),
    /// Local write result reported for the message in a saved outgoing slot,
    /// which stays saved for further results.
    Written(u8, Result<(), Failure>),
    /// Peer answer to the request in a saved outgoing slot, with a body tag or
    /// error code.
    Answer(u8, Result<u8, u64>),
    /// Peer answer to the request in a saved outgoing slot, carrying a body
    /// other than development bytes.
    AnswerOther(u8),

    /// Notification registered on a saved request promise, sending this token
    /// once the promise settles.
    Notify(u8, u8),
    /// Notification registered on a saved reply promise, sending this token
    /// once the promise settles.
    NotifyWrite(u8, u8),
    /// Tokens expected from the notifications sent since the last check, in any
    /// order.
    Notifications(Vec<u8>),
    /// Wait on a saved request promise, expecting a development answer with this
    /// tag or this failure.
    Wait(u8, Result<u8, Failure>),
    /// Wait on a saved request promise for the whole message, which must be a
    /// development body with this tag.
    WaitMessage(u8, u8),
    /// Wait started on a saved request promise in its own thread, returning once
    /// the wait is about to block.
    StartWait(u8),
    /// End of a started request wait, expecting this answer tag or failure.
    FinishWait(u8, Result<u8, Failure>),
    /// Saved request promise dropped, leaving the request running.
    DropPromise(u8),
    /// Wait on a saved reply promise, expecting this write result.
    WaitWrite(u8, Result<(), Failure>),
    /// Wait started on a saved reply promise in its own thread, returning once
    /// the wait is about to block.
    StartWaitWrite(u8),
    /// End of a started reply wait, expecting this write result.
    FinishWaitWrite(u8, Result<(), Failure>),
    /// Saved reply promise dropped, leaving the reply queued or being written.
    DropWritePromise(u8),

    /// Test clock moved to this script time in milliseconds, without calling
    /// `expire()`.
    ///
    /// Script time never moves backward.
    Time(u64),
    /// Call to `expire()` on the labeled session, failing overdue operations and
    /// discarding their queued messages.
    Expire(u8),
    /// Expected earliest pending deadline of the labeled session in script
    /// milliseconds, or none.
    Deadline(u8, Option<u64>),
    /// Deadline worker started for the labeled session, so its timeouts settle
    /// without a waiting caller.
    ///
    /// The step returns once a thread waits on the test clock.
    Deadlines(u8),

    /// Closure of the labeled session through its saved [`Closer`].
    CloseSession(u8),
    /// Drop of the labeled session's owner, keeping its other saved handles.
    DropSession(u8),
    /// Check that the labeled session's state is freed, so its saved reference
    /// cannot upgrade.
    Released(u8),
    /// Closure of the server through its saved [`Closer`].
    CloseServer,
    /// Drop of the server owner, which must free its state despite the saved
    /// closer and session source.
    DropServer,
    /// Drop of the session source, which ends the server as a stopped reader
    /// would.
    DropSource,

    /// Two closures of the labeled session, released together from separate
    /// threads.
    RaceCloses(u8),
    /// Two closures of the server, released together from separate threads.
    RaceServerCloses,
    /// Server closure raced against attaching a session, which must end closed
    /// either way.
    RaceServerCloseOpen,
    /// Request from the labeled session raced against its closure.
    ///
    /// The request must fail with `Closed`, at once or through its promise.
    RaceRequestClose(u8),
    /// Peer answer to the request in a saved outgoing slot, raced against
    /// closing the labeled session.
    ///
    /// The saved request promise must end with the answer or with `Closed`.
    RaceAnswerClose(u8, u8, u8),
    /// Reply through a saved responder, raced against closing the labeled
    /// session.
    ///
    /// The reply must fail with `Closed`, at once or through its promise.
    RaceReplyClose(u8, u8),
    /// Write result for the reply in a saved outgoing slot, raced against
    /// closing the labeled session.
    ///
    /// The saved reply promise must end with success or with `Closed`.
    RaceWriteClose(u8, u8, u8),
}

/// Receive result handed back with the session owner, so the driver can use the
/// session again.
type ReceiveResult = (Session, Result<(Message, Responder), Error>);
/// Acceptance result handed back with the server owner, which the driver keeps.
type AcceptResult = (Server, Result<Session, Error>);

/// Fixture state for one script, holding its sessions, saved handles and
/// background calls.
///
/// Labels keep referring to the same session after replacement, so steps can
/// exercise old handles.
struct Driver {
    /// Test clock driving time for the server and every fixture session.
    tester: darkbio_clock::TestClock,
    /// Deadline workers started by [`Step::Deadlines`], joined once their
    /// sessions close.
    workers: Vec<JoinHandle<()>>,
    /// Server owner, moved out while an acceptance runs and gone after
    /// [`Step::DropServer`].
    server: Option<Server>,
    /// Weak reference used to check that dropping the server frees its state.
    server_ref: Weak<ServerInner>,
    /// Server closer, usable while an acceptance owns the server or after the
    /// owner drops.
    closer: Closer,
    /// Session source standing in for the server's transport reader, gone after
    /// [`Step::DropSource`].
    source: Option<SessionSource>,
    /// Acceptance in progress, holding the only server owner.
    accepting: Option<Job<AcceptResult>>,

    /// Accepted owners currently available to the script, by session label.
    sessions: HashMap<u8, Session>,
    /// Session references saved by [`Step::Open`], including sessions later
    /// replaced.
    session_refs: HashMap<u8, Weak<SessionInner>>,
    /// Requesters saved at acceptance, kept after their sessions drop.
    requesters: HashMap<u8, Requester>,
    /// Session closers kept to exercise closure after replacement or owner drop.
    closers: HashMap<u8, Closer>,
    /// Receive calls in progress, each holding its labeled session owner.
    receiving: HashMap<u8, Job<ReceiveResult>>,

    /// Responders by script slot, not by wire request ID.
    responders: HashMap<u8, Responder>,
    /// Request promises saved for later wait or drop steps.
    promises: HashMap<u8, Promise<Message>>,
    /// Reply promises saved for later wait or drop steps.
    writes: HashMap<u8, Promise<()>>,
    /// Channel carrying notification tokens, which neither own promises nor
    /// release response bytes.
    notifications: (mpsc::Sender<u8>, mpsc::Receiver<u8>),
    /// Messages taken from session queues, by outgoing slot, awaiting their
    /// scripted write results and answers.
    outgoing: HashMap<u8, OutgoingMessage>,
    /// Background waits on request promises, by promise slot.
    waiting: HashMap<u8, Job<Result<Vec<u8>, Error>>>,
    /// Background waits on reply promises, by promise slot.
    writing: HashMap<u8, Job<Result<(), Error>>>,

    /// Test clock instant of script time zero, which scripted times and
    /// deadlines count from.
    epoch: Instant,
    /// Current script time in milliseconds, independent of expiry.
    time: u64,
}

impl Driver {
    /// Creates a server fixture with no attached sessions or running jobs.
    fn new() -> Self {
        // Give the server and every replacement session one paused clock
        let tester = crate::transport::testing::test_clock();
        let (server, source) = Server::fixture(tester.clock());
        let server_ref = Arc::downgrade(&server.inner);
        let closer = server.closer();

        // Begin with no accepted sessions or in-progress application calls
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

            epoch: tester.clock().now(),
            tester,
            workers: Vec::new(),
            time: 0,
        }
    }

    /// Restores the server owner, checks that acceptance returned the labeled
    /// session and saves its owner and handles.
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

    /// Checks the received body tag, saves its responder in the slot and restores
    /// the session owner.
    fn received(&mut self, id: u8, tag: u8, slot: u8, (session, result): ReceiveResult) {
        let (message, responder) = result.unwrap();
        assert_eq!(message, Message::Develop(vec![tag]));
        assert!(self.responders.insert(slot, responder).is_none());
        self.sessions.insert(id, session);
    }

    /// Converts script milliseconds into an instant on the test clock.
    fn at(&self, millis: u64) -> Instant {
        self.epoch + Duration::from_millis(millis)
    }

    /// Asserts that a development answer carries the expected tag, or that the
    /// wait failed with the expected reason.
    fn answer_result(result: Result<Vec<u8>, Error>, expected: Result<u8, Failure>) {
        match expected {
            Ok(tag) => assert_eq!(result.unwrap(), vec![tag]),
            Err(error) => refused(result, error),
        }
    }

    /// Asserts that a reply wait ended with the expected write result.
    fn write_result(result: Result<(), Error>, expected: Result<(), Failure>) {
        match expected {
            Ok(()) => result.unwrap(),
            Err(error) => refused(result, error),
        }
    }

    /// Executes one script step and checks its expected outcome.
    ///
    /// A step starting a blocking call returns once the call's hook reports its
    /// wait, so later steps run while it is blocked.
    ///
    /// # Panics
    ///
    /// Panics if the outcome differs from the step's expectation, or if the
    /// script is invalid, such as saving into an occupied slot.
    fn step(&mut self, step: Step) {
        match step {
            Step::Open(id) => {
                let session = self.source.as_mut().unwrap().open().unwrap();
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
                waiting.recv().expect("accept reached its wait");
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
                waiting.recv().expect("receive reached its wait");
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
                    self.requesters[&id].request(vec![1], self.tester.clock().now()),
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
                        .reply(vec![1], self.tester.clock().now()),
                    expected,
                );
            }
            Step::DropReply(slot) => {
                let responder = self.responders.remove(&slot).unwrap();
                Job::start(move || drop(responder)).finish();
            }
            Step::Abandoned(id, expected) => {
                // Take one `UNANSWERED` reply per expected ID and report its write
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

                // Require nothing else in the queue
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
            Step::Notify(slot, token) => {
                let events = self.notifications.0.clone();
                self.promises.get_mut(&slot).unwrap().notify(move || {
                    let _ = events.send(token);
                });
            }
            Step::NotifyWrite(slot, token) => {
                let events = self.notifications.0.clone();
                self.writes.get_mut(&slot).unwrap().notify(move || {
                    let _ = events.send(token);
                });
            }
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
                waiting.recv().expect("request reached its wait");
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
                waiting.recv().expect("reply reached its wait");
            }
            Step::FinishWaitWrite(slot, expected) => {
                Self::write_result(self.writing.remove(&slot).unwrap().finish(), expected)
            }
            Step::DropWritePromise(slot) => drop(self.writes.remove(&slot).unwrap()),
            Step::Time(time) => {
                assert!(time >= self.time);
                self.time = time;
                self.tester.advance_to(self.at(time));
            }
            Step::Expire(id) => self.session_refs[&id].upgrade().unwrap().expire(),
            Step::Deadline(id, expected) => assert_eq!(
                self.session_refs[&id].upgrade().unwrap().next_deadline(),
                expected.map(|time| self.at(time))
            ),
            Step::Deadlines(id) => {
                let session = self.session_refs[&id].upgrade().unwrap();
                self.workers
                    .push(thread::spawn(move || session.run_deadlines()));
                self.tester.wait_blocked(1);
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
                // Hold two closures of the same target at one barrier
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

                // Release both and wait for them to return
                gate.wait();
                for job in jobs {
                    job.finish();
                }
            }
            Step::RaceServerCloseOpen => {
                // Hold an attach and a server closure at one barrier
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

                // Release both and wait for them to return
                gate.wait();
                closed.finish();
                let (source, result) = opened.finish();

                // If `accept()` took the session, it may still exist but must be
                // closed already. Otherwise server closure drops that session too.
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
                // Hold a request and a closure of its session at one barrier
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

                // Release both, then require the request to fail with `Closed`
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
                // Hold an answer and a closure of its session at one barrier
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

                // Release both, then require the answer or `Closed` in the promise
                gate.wait();
                closed.finish();
                answered.finish();
                match Job::start(move || promise.wait::<Vec<u8>>()).finish() {
                    Ok(body) => assert_eq!(body, vec![42]),
                    Err(error) => assert_eq!(failure(error), Failure::Closed),
                }
            }
            Step::RaceReplyClose(id, responder) => {
                // Hold a reply and a closure of its session at one barrier
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

                // Release both, then require the reply to fail with `Closed`
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
                // Hold a write result and a closure of its session at one barrier
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

                // Release both, then require success or `Closed` in the promise
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
    /// Closes the server and every saved session so blocked calls wake, even
    /// after a failed step, then joins the deadline workers.
    fn drop(&mut self) {
        // Wake every application call and deadline worker before joining
        self.closer.close();
        for closer in self.closers.values() {
            closer.close();
        }

        // Leave no fixture worker behind after the script finishes
        for worker in self.workers.drain(..) {
            worker.join().unwrap();
        }
    }
}

/// Runs a scenario script against a fresh fixture.
///
/// # Panics
///
/// Panics at the first failed step, after printing its index and value, or if
/// the script leaves a started acceptance, receive or wait unfinished.
fn run(steps: Vec<Step>) {
    // Run each step, naming the one that fails before passing its panic on
    let mut driver = Driver::new();
    for (index, step) in steps.into_iter().enumerate() {
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| driver.step(step.clone())));
        if let Err(error) = result {
            eprintln!("lifecycle scenario failed at step {index}: {step:?}");
            std::panic::resume_unwind(error);
        }
    }

    // Require every started call to have been finished by the script
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
