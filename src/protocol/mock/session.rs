// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Lifecycle and operation scenarios for the replacement API. Fixtures supply
//! sessions, peer input, output completion and protocol time; submissions, waits,
//! retirement and handle drops use the real public API. Explicit wait notifications
//! permit overlap without sleep-based ordering.

use crate::protocol::operation::{Body, Output};
use crate::protocol::{
    Closer, Error, Message, Promise, RemoteError, Requester, ReservedErrors, Responder, Server,
    Session, server, session,
};
use crate::transport::{Stream, testing::Memory};
use std::collections::HashMap;
use std::sync::{Arc, Barrier, Weak, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Watchdog for scenario jobs and wait hooks, independent of operation deadlines.
const PATIENCE: Duration = Duration::from_secs(5);

/// Terminal outcomes that lifecycle scripts can require from an operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    /// The owner closed locally or no longer exists.
    Closed,
    /// A replacement retired the original session.
    Reset,
    /// The fixture's publication source ended the endpoint.
    Terminated,
    /// The operation reached its absolute deadline before settlement.
    Timeout,
    /// The peer returned this application-defined error code.
    Remote(u64),
    /// The answer variant did not match the requested Rust response type.
    WrongType,
}

/// Classifies a runtime error, rejecting outcomes outside the lifecycle contract.
fn failure(error: Error) -> Failure {
    match error {
        Error::Closed => Failure::Closed,
        Error::Timeout => Failure::Timeout,
        Error::Remote(error) => Failure::Remote(error.code),
        Error::UnexpectedResponse { .. } => Failure::WrongType,
        Error::Transport(error) => match &*error {
            crate::transport::Error::SessionReset => Failure::Reset,
            crate::transport::Error::Terminated => Failure::Terminated,
            other => panic!("unexpected transport error: {other}"),
        },
        other => panic!("unexpected protocol error: {other}"),
    }
}

/// Creates the output failures supported by scripted writer completions.
fn output_error(error: Failure) -> Error {
    match error {
        Failure::Closed => Error::Closed,
        Failure::Timeout => Error::Timeout,
        Failure::Reset => crate::transport::Error::SessionReset.into(),
        Failure::Terminated => crate::transport::Error::Terminated.into(),
        other => panic!("not an output failure: {other:?}"),
    }
}

/// Builds an application response from a body tag or an application error code.
fn response(result: Result<u8, u64>) -> Result<Message, RemoteError> {
    result
        .map(|tag| vec![tag].into())
        .map_err(|code| RemoteError {
            code,
            msg: "refused".into(),
        })
}

/// Expected output content, specified independently of the runtime queue types.
#[derive(Clone, Debug)]
enum Sent {
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

/// Background operation whose completion is observed with a bounded watchdog.
struct Job<T> {
    /// Completed value; disconnection also exposes a worker panic to the driver.
    result: mpsc::Receiver<T>,
    /// Worker joined after its result arrives so successful jobs leave no thread.
    thread: JoinHandle<()>,
}

impl<T: Send + 'static> Job<T> {
    /// Starts an operation without blocking the scenario's remaining steps.
    fn start(run: impl FnOnce() -> T + Send + 'static) -> Self {
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
    fn finish(self) -> T {
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
/// Start/finish pairs leave calls running while intervening steps change lifetimes.
#[derive(Clone, Debug)]
enum Step {
    /// Publishes a session under the given label, retiring any predecessor.
    Open(u8),
    /// Accepts the pending owner and checks it belongs to the given session label.
    Accept(u8),
    /// Starts acceptance and waits until it reaches its empty-queue wait.
    StartAccept,
    /// Finishes an overlapping acceptance with the given session label.
    FinishAccept(u8),
    /// Requires an overlapping acceptance to fail with this ending reason.
    FinishAcceptError(Failure),
    /// Allows either closed acceptance or an accepted session that is now closed.
    FinishAcceptClosed,
    /// Delivers a request: session label, request ID and one-byte body tag.
    Deliver(u8, u64, u8),
    /// Requires delivery to the labeled session to fail with the given reason.
    RefuseDelivery(u8, Failure),
    /// Receives a request: session label, expected body tag and saved responder slot.
    Receive(u8, u8, u8),
    /// Starts receiving on the labeled session and waits until its queue wait.
    StartReceive(u8),
    /// Finishes a receive: session label, expected body tag and saved responder slot.
    FinishReceive(u8, u8, u8),
    /// Requires an overlapping receive on this session to fail with the given reason.
    FinishReceiveError(u8, Failure),
    /// Starts and finishes a receive that must fail with the given ending reason.
    ReceiveError(u8, Failure),
    /// Closes the labeled session through a retained capability.
    CloseSession(u8),
    /// Drops the labeled session owner while retaining its other handles.
    DropSession(u8),
    /// Requires request submission through this session's handle to fail.
    RefuseRequest(u8, Failure),
    /// Consumes the saved responder slot and requires reply submission to fail.
    RefuseReply(u8, Failure),
    /// Drops the saved responder slot without supplying a reply.
    DropReply(u8),
    /// Takes this session's abandonment obligations and checks their request IDs.
    Abandoned(u8, Vec<u64>),
    /// Requires retained weak handles to no longer reach this session allocation.
    Released(u8),
    /// Closes the endpoint through its retained capability.
    CloseServer,
    /// Drops the endpoint owner and checks weak handles do not retain its state.
    DropServer,
    /// Drops the source of sessions, modeling a terminated reader.
    DropPublisher,
    /// Requires a new session publication to fail with the given reason.
    RefuseOpen(Failure),
    /// Releases two threads together to close the same labeled session.
    RaceCloses(u8),
    /// Releases two threads together to close the persistent endpoint.
    RaceServerCloses,
    /// Overlaps endpoint closure and publication; any published owner must end.
    RaceServerCloseOpen,
    /// Submits a request: session, promise slot, body tag, absolute time in milliseconds.
    Request(u8, u8, u8, u64),
    /// Submits a reply: responder slot, promise slot, body/error, absolute deadline.
    Reply(u8, u8, Result<u8, u64>, u64),
    /// Takes output: session, output slot, expected content and original deadline.
    Output(u8, u8, Sent, u64),
    /// Requires this session to have no eligible queued output.
    NoOutput(u8),
    /// Reports local write/flush completion for a retained output slot.
    Written(u8, Result<(), Failure>),
    /// Supplies the peer answer for a retained request output slot.
    Answer(u8, Result<u8, u64>),
    /// Supplies an answer whose content is not the byte-vector type used by the waiter.
    AnswerOther(u8),
    /// Waits for a request's byte-vector answer or its exact failure.
    Wait(u8, Result<u8, Failure>),
    /// Takes the untyped Message result to permit application pattern matching.
    WaitMessage(u8, u8),
    /// Starts a request wait and waits for its blocking-call notification.
    StartWait(u8),
    /// Finishes an overlapping request wait with the expected outcome.
    FinishWait(u8, Result<u8, Failure>),
    /// Waits for a reply's local write completion.
    WaitWrite(u8, Result<(), Failure>),
    /// Starts observing a reply before the output service completes it.
    StartWaitWrite(u8),
    /// Finishes an overlapping reply wait with the expected outcome.
    FinishWaitWrite(u8, Result<(), Failure>),
    /// Drops request observation while retaining the registered operation.
    DropPromise(u8),
    /// Drops reply observation while retaining the output obligation.
    DropWritePromise(u8),
    /// Advances protocol time without running deadline servicing.
    Time(u64),
    /// Runs deadline servicing for this session while output may be held elsewhere.
    Expire(u8),
    /// Checks the deadline service's next wakeup, or the absence of unresolved work.
    Deadline(u8, Option<u64>),
    /// Releases request registration and session closure together; either admission
    /// outcome must be closed by the time both calls have returned.
    RaceRequestClose(u8),
    /// Releases answer delivery and closure together, accepting either first result.
    RaceAnswerClose(u8, u8, u8),
    /// Releases reply registration and session closure together for this responder.
    RaceReplyClose(u8, u8),
    /// Releases reply write completion and closure together; either may settle first.
    RaceWriteClose(u8, u8, u8),
    /// Switches a session to wall-clock time and submits a request with this budget.
    RealRequest(u8, u8, u64),
    /// Submits a reply with a wall-clock deadline to a session already using real time.
    RealReply(u8, u8, u64),
}

/// A receive result returned with its owner so the driver can use the session again.
type Receive = (Session, Result<(Message, Responder), Error>);
/// An acceptance result returned with its persistent endpoint owner.
type Accept = (Server, Result<Session, Error>);

/// Scenario-owned endpoints, sessions, saved capabilities and overlapping jobs.
/// Labels refer to exact allocations, allowing a script to act on stale handles
/// after replacement without consulting the implementation's current session.
struct Driver {
    /// Endpoint owner, temporarily moved out while acceptance runs.
    server: Option<Server>,
    /// Weak identity used to assert endpoint release after its owner is dropped.
    endpoint: Weak<server::Shared>,
    /// Sole source of replacement sessions in place of a real transport reader.
    publisher: Option<server::Sessions>,
    /// Accepted owners currently available to the script, indexed by session label.
    sessions: HashMap<u8, Session>,
    /// Delivery targets recorded at publication, including retired predecessors.
    incoming: HashMap<u8, Weak<session::Shared>>,
    /// Request capabilities retained even when the corresponding owner is dropped.
    requesters: HashMap<u8, Requester>,
    /// Session closers retained to exercise closure after replacement or owner drop.
    closers: HashMap<u8, Closer>,
    /// One-use reply capabilities indexed by script slot, not by wire request ID.
    replies: HashMap<u8, Responder>,
    /// In-progress receive jobs, each holding its labeled session owner.
    receiving: HashMap<u8, Job<Receive>>,
    /// In-progress acceptance job, holding the unique endpoint owner.
    accepting: Option<Job<Accept>>,
    /// Endpoint closer usable while acceptance owns the server or after owner drop.
    closer: Closer,
    /// Base for deterministic absolute deadlines, kept ahead of the wall clock.
    epoch: Instant,
    /// Current scripted time in milliseconds, independent of expiry servicing.
    time: u64,
    /// Unobserved request promises indexed by script slot.
    pending: HashMap<u8, Promise<Message>>,
    /// Unobserved reply write promises indexed by script slot.
    writes: HashMap<u8, Promise<()>>,
    /// Admitted output held independently to model blocked I/O and delayed answers.
    output: HashMap<u8, Output>,
    /// Request observers already inside their waiting calls.
    waiting: HashMap<u8, Job<Result<Vec<u8>, Error>>>,
    /// Reply observers already inside their waiting calls.
    writing: HashMap<u8, Job<Result<(), Error>>>,
}

impl Driver {
    /// Creates an open endpoint fixture with no published sessions or running jobs.
    fn new() -> Self {
        Self::with_timeout(crate::transport::DEFAULT_WRITE_TIMEOUT)
    }

    /// Uses the real Stream configuration accessor to supply the abandonment budget.
    fn with_timeout(timeout: Duration) -> Self {
        let stream = Stream::new(Memory::new(&b""[..]), Memory::new(Vec::new()), || {})
            .set_write_timeout(timeout);
        let (server, publisher) = Server::pair(stream.write_timeout());
        Self {
            endpoint: Arc::downgrade(&server.shared),
            closer: server.closer(),
            server: Some(server),
            publisher: Some(publisher),
            sessions: HashMap::new(),
            incoming: HashMap::new(),
            requesters: HashMap::new(),
            closers: HashMap::new(),
            replies: HashMap::new(),
            receiving: HashMap::new(),
            accepting: None,
            epoch: Instant::now() + Duration::from_secs(3600),
            time: 0,
            pending: HashMap::new(),
            writes: HashMap::new(),
            output: HashMap::new(),
            waiting: HashMap::new(),
            writing: HashMap::new(),
        }
    }

    /// Checks an accepted session's identity and saves its owner and cloned handles.
    fn accepted(&mut self, id: u8, (server, result): Accept) {
        self.server = Some(server);
        let session = result.unwrap();
        assert!(Weak::ptr_eq(
            &Arc::downgrade(&session.shared),
            &self.incoming[&id]
        ));
        self.requesters.insert(id, session.requester().clone());
        self.closers.insert(id, session.closer().clone());
        assert!(self.sessions.insert(id, session).is_none());
    }

    /// Checks the received body tag, saves its responder and restores the owner.
    fn received(&mut self, id: u8, tag: u8, slot: u8, (session, result): Receive) {
        let (message, responder) = result.unwrap();
        assert_eq!(message, Message::Develop(vec![tag]));
        assert!(self.replies.insert(slot, responder).is_none());
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

    /// Checks local output completion without treating it as remote acknowledgment.
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
                let session = self.publisher.as_mut().unwrap().open().unwrap();
                session.upgrade().unwrap().set_time(self.at(self.time));
                assert!(self.incoming.insert(id, session).is_none());
            }
            Step::Request(id, slot, tag, deadline) => {
                let requester = self.requesters[&id].clone();
                let deadline = self.at(deadline);
                let pending = Job::start(move || requester.request(vec![tag], deadline))
                    .finish()
                    .unwrap();
                assert!(self.pending.insert(slot, pending).is_none());
            }
            Step::Reply(responder, slot, result, deadline) => {
                let responder = self.replies.remove(&responder).unwrap();
                let deadline = self.at(deadline);
                let pending = Job::start(move || responder.reply(response(result), deadline))
                    .finish()
                    .unwrap();
                assert!(self.writes.insert(slot, pending).is_none());
            }
            Step::Output(id, slot, expected, deadline) => {
                let output = self.incoming[&id]
                    .upgrade()
                    .unwrap()
                    .take_output()
                    .expect("output queued");
                assert_eq!(output.deadline, self.at(deadline));
                match (&output.body, expected) {
                    (Body::Request(message), Sent::Request(tag)) => {
                        assert_eq!(message, &Message::Develop(vec![tag]))
                    }
                    (Body::Reply { id, result }, Sent::Reply(expected_id, expected)) => {
                        assert_eq!(*id, expected_id);
                        match (result, expected) {
                            (Ok(message), Ok(tag)) => {
                                assert_eq!(message, &Message::Develop(vec![tag]))
                            }
                            (Err(error), Err(code)) => {
                                assert_eq!(error.code, code);
                                assert_eq!(
                                    error.msg,
                                    if code == ReservedErrors::Unanswered as u64 {
                                        "request left unanswered"
                                    } else {
                                        "refused"
                                    }
                                );
                            }
                            _ => panic!("unexpected reply result"),
                        }
                    }
                    _ => panic!("unexpected output kind"),
                }
                assert!(self.output.insert(slot, output).is_none());
            }
            Step::NoOutput(id) => assert!(
                self.incoming[&id]
                    .upgrade()
                    .unwrap()
                    .take_output()
                    .is_none()
            ),
            Step::Written(slot, result) => self.output[&slot]
                .completion
                .written(result.map_err(output_error)),
            Step::Answer(slot, result) => {
                let output = self.output.remove(&slot).unwrap();
                assert!(matches!(output.body, Body::Request(_)));
                output.completion.answer(response(result));
            }
            Step::AnswerOther(slot) => {
                let output = self.output.remove(&slot).unwrap();
                assert!(matches!(output.body, Body::Request(_)));
                output
                    .completion
                    .answer(Ok(crate::protocol::DeviceInfoResponse::default().into()));
            }
            Step::Wait(slot, expected) => {
                let pending = self.pending.remove(&slot).unwrap();
                Self::answer_result(Job::start(move || pending.wait()).finish(), expected);
            }
            Step::WaitMessage(slot, tag) => {
                let pending = self.pending.remove(&slot).unwrap();
                assert_eq!(
                    Job::start(move || pending.wait::<Message>())
                        .finish()
                        .unwrap(),
                    Message::Develop(vec![tag])
                );
            }
            Step::StartWait(slot) => {
                let mut pending = self.pending.remove(&slot).unwrap();
                let waiting = pending.watch();
                assert!(
                    self.waiting
                        .insert(slot, Job::start(move || pending.wait()))
                        .is_none()
                );
                waiting
                    .recv_timeout(PATIENCE)
                    .expect("request reached its wait");
            }
            Step::FinishWait(slot, expected) => {
                Self::answer_result(self.waiting.remove(&slot).unwrap().finish(), expected)
            }
            Step::WaitWrite(slot, expected) => {
                let pending = self.writes.remove(&slot).unwrap();
                Self::write_result(Job::start(move || pending.wait()).finish(), expected);
            }
            Step::StartWaitWrite(slot) => {
                let mut pending = self.writes.remove(&slot).unwrap();
                let waiting = pending.watch();
                assert!(
                    self.writing
                        .insert(slot, Job::start(move || pending.wait()))
                        .is_none()
                );
                waiting
                    .recv_timeout(PATIENCE)
                    .expect("reply reached its wait");
            }
            Step::FinishWaitWrite(slot, expected) => {
                Self::write_result(self.writing.remove(&slot).unwrap().finish(), expected)
            }
            Step::DropPromise(slot) => drop(self.pending.remove(&slot).unwrap()),
            Step::DropWritePromise(slot) => drop(self.writes.remove(&slot).unwrap()),
            Step::Time(time) => {
                assert!(time >= self.time);
                self.time = time;
                for session in self.incoming.values().filter_map(Weak::upgrade) {
                    session.set_time(self.at(time));
                }
            }
            Step::Expire(id) => self.incoming[&id].upgrade().unwrap().expire(),
            Step::Deadline(id, expected) => assert_eq!(
                self.incoming[&id].upgrade().unwrap().next_deadline(),
                expected.map(|time| self.at(time))
            ),
            Step::RealRequest(id, slot, budget) => {
                self.incoming[&id].upgrade().unwrap().use_realtime();
                let pending = self.requesters[&id]
                    .request(vec![1], Instant::now() + Duration::from_millis(budget))
                    .unwrap();
                assert!(self.pending.insert(slot, pending).is_none());
            }
            Step::RealReply(responder, slot, budget) => {
                let responder = self.replies.remove(&responder).unwrap();
                let pending = responder
                    .reply(
                        response(Ok(2)),
                        Instant::now() + Duration::from_millis(budget),
                    )
                    .unwrap();
                assert!(self.writes.insert(slot, pending).is_none());
            }
            Step::RaceReplyClose(id, responder) => {
                let responder = self.replies.remove(&responder).unwrap();
                let closer = self.closers[&id].clone();
                let deadline = self.at(self.time + 100);
                let gate = Arc::new(Barrier::new(3));
                let replied = {
                    let gate = gate.clone();
                    Job::start(move || {
                        gate.wait();
                        responder.reply(response(Ok(42)), deadline)
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
                    Ok(pending) => {
                        refused(Job::start(move || pending.wait()).finish(), Failure::Closed)
                    }
                    Err(error) => assert_eq!(failure(error), Failure::Closed),
                }
            }
            Step::RaceWriteClose(id, output, pending) => {
                let output = self.output.remove(&output).unwrap();
                let pending = self.writes.remove(&pending).unwrap();
                let closer = self.closers[&id].clone();
                let gate = Arc::new(Barrier::new(3));
                let written = {
                    let gate = gate.clone();
                    Job::start(move || {
                        gate.wait();
                        output.completion.written(Ok(()));
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
                written.finish();
                if let Err(error) = Job::start(move || pending.wait()).finish() {
                    assert_eq!(failure(error), Failure::Closed);
                }
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
                    Ok(pending) => refused(
                        Job::start(move || pending.wait::<Message>()).finish(),
                        Failure::Closed,
                    ),
                    Err(error) => assert_eq!(failure(error), Failure::Closed),
                }
            }
            Step::RaceAnswerClose(id, output, pending) => {
                let output = self.output.remove(&output).unwrap();
                let pending = self.pending.remove(&pending).unwrap();
                let closer = self.closers[&id].clone();
                let gate = Arc::new(Barrier::new(3));
                let answered = {
                    let gate = gate.clone();
                    Job::start(move || {
                        gate.wait();
                        output.completion.answer(response(Ok(42)));
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
                match Job::start(move || pending.wait::<Vec<u8>>()).finish() {
                    Ok(body) => assert_eq!(body, vec![42]),
                    Err(error) => assert_eq!(failure(error), Failure::Closed),
                }
            }
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
                let waiting = server.shared.watch_accept();
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
            Step::Deliver(id, request, tag) => {
                self.incoming[&id]
                    .upgrade()
                    .unwrap()
                    .deliver(request, Message::Develop(vec![tag]))
                    .unwrap();
            }
            Step::RefuseDelivery(id, expected) => {
                refused(
                    self.incoming[&id]
                        .upgrade()
                        .unwrap()
                        .deliver(1, Message::Develop(vec![0xff])),
                    expected,
                );
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
            Step::StartReceive(id) => {
                let mut session = self.sessions.remove(&id).unwrap();
                let waiting = session.shared.watch_recv();
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
            Step::CloseSession(id) => {
                let closer = self.closers[&id].clone();
                Job::start(move || closer.close()).finish();
            }
            Step::DropSession(id) => {
                let session = self.sessions.remove(&id).unwrap();
                Job::start(move || drop(session)).finish();
            }
            Step::RefuseRequest(id, expected) => {
                refused(
                    self.requesters[&id].request(vec![1], Instant::now()),
                    expected,
                );
            }
            Step::RefuseReply(slot, expected) => {
                refused(
                    self.replies
                        .remove(&slot)
                        .unwrap()
                        .reply(Ok(vec![1].into()), Instant::now()),
                    expected,
                );
            }
            Step::DropReply(slot) => {
                let responder = self.replies.remove(&slot).unwrap();
                Job::start(move || drop(responder)).finish();
            }
            Step::Abandoned(id, expected) => {
                let session = self.incoming[&id].upgrade().unwrap();
                for id in expected {
                    let output = session.take_output().expect("abandonment queued");
                    let Body::Reply {
                        id: actual,
                        result: Err(error),
                    } = output.body
                    else {
                        panic!("expected an abandonment reply");
                    };
                    assert_eq!(actual, id);
                    assert_eq!(error.code, ReservedErrors::Unanswered as u64);
                    assert_eq!(error.msg, "request left unanswered");
                    output.completion.written(Ok(()));
                }
                assert!(
                    session.take_output().is_none(),
                    "unexpected additional output"
                );
            }
            Step::Released(id) => assert!(self.incoming[&id].upgrade().is_none()),
            Step::CloseServer => {
                let closer = self.closer.clone();
                Job::start(move || closer.close()).finish();
            }
            Step::DropServer => {
                let server = self.server.take().unwrap();
                Job::start(move || drop(server)).finish();
                assert!(
                    self.endpoint.upgrade().is_none(),
                    "closer/publisher must not retain endpoint"
                );
            }
            Step::DropPublisher => drop(self.publisher.take().unwrap()),
            Step::RefuseOpen(expected) => {
                refused(self.publisher.as_mut().unwrap().open(), expected)
            }
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
                let mut publisher = self.publisher.take().unwrap();
                let opened = {
                    let gate = gate.clone();
                    Job::start(move || {
                        gate.wait();
                        let result = publisher.open();
                        (publisher, result)
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
                let (publisher, result) = opened.finish();
                // If accept already took the owner it may still be retained, but
                // it must be retired when endpoint close returns. If no accept
                // took it, endpoint close also releases the unaccepted owner.
                match result {
                    Ok(session) => {
                        if let Some(session) = session.upgrade() {
                            refused(session.deliver(1, vec![1].into()), Failure::Closed);
                        }
                    }
                    Err(error) => assert_eq!(failure(error), Failure::Closed),
                }
                self.publisher = Some(publisher);
            }
        }
    }
}

impl Drop for Driver {
    /// Retires all remaining owners so blocked jobs can leave even after an assertion.
    fn drop(&mut self) {
        self.closer.close();
        for closer in self.closers.values() {
            closer.close();
        }
    }
}

/// Runs a scenario, reporting the exact failed step and rejecting unfinished jobs.
fn run(steps: Vec<Step>) {
    run_with(Driver::new(), steps);
}

/// Runs with an explicitly configured stream write budget for abandonment scenarios.
fn run_with_timeout(timeout: Duration, steps: Vec<Step>) {
    run_with(Driver::with_timeout(timeout), steps);
}

/// Executes a prepared driver and requires every explicitly started waiter to finish.
fn run_with(mut driver: Driver, steps: Vec<Step>) {
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
