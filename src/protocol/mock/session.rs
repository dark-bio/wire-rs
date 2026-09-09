// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Lifecycle scenarios for the replacement API. The fixtures supply sessions and
//! messages where the transport reader will eventually do so. All receive, close,
//! handle-drop and ended-session refusal operations use the real public API.
//! Explicit wait notifications permit overlap without sleep-based ordering.

use crate::protocol::{
    Closer, Error, Message, Requester, Responder, Server, Session, server, session,
};
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
}

/// Classifies a runtime error, rejecting outcomes outside the lifecycle contract.
fn failure(error: Error) -> Failure {
    match error {
        Error::Closed => Failure::Closed,
        Error::Transport(error) => match &*error {
            crate::transport::Error::SessionReset => Failure::Reset,
            crate::transport::Error::Terminated => Failure::Terminated,
            other => panic!("unexpected transport error: {other}"),
        },
        other => panic!("unexpected protocol error: {other}"),
    }
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
}

impl Driver {
    /// Creates an open endpoint fixture with no published sessions or running jobs.
    fn new() -> Self {
        let (server, publisher) = Server::pair();
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

    /// Executes one script action, using watchdogs for operations allowed to block.
    /// Assertions also reject invalid scripts, such as overwriting an owned slot.
    fn step(&mut self, step: Step) {
        match step {
            Step::Open(id) => {
                let session = self.publisher.as_mut().unwrap().open().unwrap();
                assert!(self.incoming.insert(id, session).is_none());
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
            Step::DropReply(slot) => drop(self.replies.remove(&slot).unwrap()),
            Step::Abandoned(id, expected) => {
                assert_eq!(
                    self.incoming[&id].upgrade().unwrap().take_abandoned(),
                    expected
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
}

#[cfg(test)]
mod tests;
