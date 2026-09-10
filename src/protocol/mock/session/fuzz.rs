// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Turns arbitrary actions into valid scripts with independently predicted results.
//! The model uses integer time and a ledger of operations; it never reads session
//! internals to decide which result, queued message or deadline to expect.
//!
//! The fixture supplies requests and write results directly, so duplicate wire
//! IDs and transport failures that end a whole session belong to the connection
//! runner instead. Everything here stays on the simulated clock.

use super::{ExpectedMessage, Failure, Step};
use crate::protocol::{
    DEFAULT_MAX_INBOUND_BYTES, DEFAULT_MAX_INBOUND_REQUESTS, HostToArk, RemoteError,
    ReservedErrors, host_to_ark,
};
use crate::transport::mock::MAX_STEPS;
use prost::Message as _;
use std::time::Duration;

/// One mutation-friendly action. Selectors wrap over previously created objects,
/// including closed sessions and completed operations. Missing objects are a no-op.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct Action {
    /// Operation or completion to schedule.
    pub kind: Kind,
    /// Session, responder or operation selector, depending on the action.
    pub slot: u8,
    /// Body tag, result selector, request limit or choice of concurrent execution.
    pub value: u8,
    /// Relative deadline, clock advance or abandonment timeout in milliseconds,
    /// or the retained-byte limit.
    pub budget: u8,
}

/// Public operations and independently scheduled transport/deadline completions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum Kind {
    // Session setup and policy.
    Open,
    /// Changes both inbound limits, including below live usage.
    InboundLimits,
    AbandonmentTimeout,

    // Requests and replies.
    Request,
    Receive,
    /// Queues several requests before retrieving any of their bodies.
    IncomingBatch,
    Reply,
    Abandon,
    Outgoing,
    Written,
    Answer,

    // Promise completion and deadlines.
    Wait,
    DropPromise,
    Advance,
    Expire,

    // Closure.
    Close,
    Drop,
    CloseServer,
    DropSource,

    /// Observes completion through a token while retaining the promise and bytes.
    Notify,
}

/// Default abandonment budget of a fresh session, in script milliseconds.
const ABANDONMENT: u64 = 5000;

struct Session {
    reason: Option<Failure>,
    owner: bool,
    abandonment: u64,
    /// Current limit on accepted peer requests.
    max_requests: usize,
    /// Current limit on buffered incoming bytes.
    max_bytes: usize,
}

struct Operation {
    session: usize,
    body: ExpectedMessage,
    deadline: u64,

    queued: bool,
    writing: bool,

    result: Option<Result<u8, Failure>>,
    /// Encoded bytes held by this response until its promise is read or dropped.
    response_bytes: usize,
    /// The driver still owns the promise, either directly or in a waiting job.
    retained: bool,
    /// A waiting job owns the promise until a later action collects its result.
    parked: bool,
    /// Registration is single-use; the generator must never trigger its panic.
    notified: bool,
    /// A completion token is queued but has not yet been checked by the driver.
    notification: bool,
}

impl Operation {
    fn request(&self) -> bool {
        matches!(self.body, ExpectedMessage::Request(_))
    }

    fn abandonment(&self) -> bool {
        matches!(
            self.body,
            ExpectedMessage::Reply(_, Err(code)) if code == ReservedErrors::Unanswered as u64
        )
    }

    fn complete(&mut self, now: u64, result: Result<u8, Failure>) {
        if self.result.is_none() {
            self.result = Some(if now >= self.deadline {
                Err(Failure::Timeout)
            } else {
                result
            });
            self.notification |= self.retained && self.notified;
        }
    }
}

#[derive(Default)]
struct Model {
    server: Option<Failure>,
    source: bool,
    /// Acceptance owns the server until an attach or closure wakes it.
    accepting: bool,
    /// The server owner was dropped; its weak closer and source may remain.
    server_dropped: bool,

    sessions: Vec<Session>,
    responders: Vec<Option<usize>>,
    operations: Vec<Operation>,

    time: u64,
    steps: Vec<Step>,
}

impl Model {
    /// Counts requests held by responders and queued replies.
    fn request_usage(&self, session: usize) -> usize {
        if self.sessions[session].reason.is_some() {
            return 0;
        }
        self.responders
            .iter()
            .filter(|owner| **owner == Some(session))
            .count()
            + self
                .operations
                .iter()
                .filter(|operation| {
                    operation.session == session && operation.queued && !operation.request()
                })
                .count()
    }

    /// Counts buffered response bytes until their promises are read or dropped.
    fn byte_usage(&self, session: usize) -> usize {
        self.operations
            .iter()
            .filter(|operation| operation.session == session && operation.retained)
            .map(|operation| operation.response_bytes)
            .sum()
    }

    /// Joins completed waits before checking byte counts. Pending waits stay
    /// blocked and can overlap later completions or session closure.
    fn collect_waiters(&mut self) {
        for (id, operation) in self.operations.iter_mut().enumerate() {
            if operation.parked
                && let Some(result) = operation.result
            {
                self.steps.push(if operation.request() {
                    Step::FinishWait(id as u8, result)
                } else {
                    Step::FinishWaitWrite(id as u8, result.map(|_| ()))
                });
                operation.parked = false;
                operation.retained = false;
            }
        }
    }

    /// Checks completion events separately from waits so observation keeps bytes.
    fn collect_notifications(&mut self) {
        let tokens = self
            .operations
            .iter_mut()
            .enumerate()
            .filter_map(|(id, operation)| {
                std::mem::take(&mut operation.notification).then_some(id as u8)
            })
            .collect();
        self.steps.push(Step::Notifications(tokens));
    }

    /// Queues a batch before receiving it, predicting overflow from original
    /// envelope lengths. Failed admission closes and discards the entire inbox.
    fn incoming(&mut self, session: usize, count: u8, value: u8, parked: bool) {
        let base = self.responders.len();
        let mut bytes = self.byte_usage(session);
        for offset in 0..usize::from(count) {
            let id = (base + offset) as u64;
            let tag = value.wrapping_add(offset as u8);
            bytes += HostToArk {
                id,
                err: None,
                content: Some(host_to_ark::Content::Develop(vec![tag])),
            }
            .encoded_len();
            let reason =
                if self.request_usage(session) + offset >= self.sessions[session].max_requests {
                    Some(Failure::Requests)
                } else if bytes > self.sessions[session].max_bytes {
                    Some(Failure::Bytes)
                } else {
                    None
                };
            if parked {
                self.steps.push(Step::StartReceive(session as u8));
            }
            if let Some(reason) = reason {
                self.steps
                    .push(Step::RejectDelivery(session as u8, id, tag, reason));
                self.close(session, reason);
                if parked {
                    self.steps
                        .push(Step::FinishReceiveError(session as u8, reason));
                }
                return;
            }
            self.steps.push(Step::Deliver(session as u8, id, tag));
        }
        for offset in 0..usize::from(count) {
            let slot = (base + offset) as u8;
            let tag = value.wrapping_add(offset as u8);
            self.steps.push(if parked {
                Step::FinishReceive(session as u8, tag, slot)
            } else {
                Step::Receive(session as u8, tag, slot)
            });
            self.responders.push(Some(session));
        }
    }

    fn close(&mut self, session: usize, reason: Failure) {
        if self.sessions[session].reason.is_none() {
            self.sessions[session].reason = Some(reason);
            for operation in &mut self.operations {
                if operation.session == session {
                    operation.complete(self.time, Err(reason));
                    operation.queued = false;
                }
            }
        }
    }

    fn expire(&mut self, session: usize) {
        for operation in &mut self.operations {
            if operation.session == session && self.time >= operation.deadline {
                operation.complete(self.time, Err(Failure::Timeout));
                operation.queued = false;
            }
        }
    }

    fn enqueue(&mut self, session: usize, body: ExpectedMessage, deadline: u64, retained: bool) {
        self.operations.push(Operation {
            session,
            body,
            deadline,

            queued: deadline > self.time,
            writing: false,

            result: (deadline <= self.time).then_some(Err(Failure::Timeout)),
            response_bytes: 0,
            retained,
            parked: false,
            notified: false,
            notification: false,
        });
    }

    /// Whether a completion can race with closure. The promise must still be
    /// pending, its deadline in the future, and both owners available to the driver.
    fn raceable(&self, operation: usize) -> bool {
        let operation = &self.operations[operation];
        let session = &self.sessions[operation.session];
        operation.result.is_none()
            && operation.retained
            && !operation.parked
            && self.time < operation.deadline
            && session.reason.is_none()
            && session.owner
            && (!operation.request()
                || self.byte_usage(operation.session) + answer_size(Ok(42)) <= session.max_bytes)
    }

    /// Releases an operation whose promise and queued message a race consumed.
    fn consume(&mut self, operation: usize) {
        let operation = &mut self.operations[operation];
        // Race steps settle and wait on the promise before returning, so its
        // registered event is sent even though the model releases ownership now.
        operation.notification = operation.notified;
        operation.retained = false;
        operation.queued = false;
        operation.writing = false;
    }

    fn step(&mut self, action: Action) {
        let Action {
            kind,
            slot,
            value,
            budget,
        } = action;
        let session = slot as usize % self.sessions.len().max(1);
        let operation = slot as usize % self.operations.len().max(1);
        let responder = slot as usize % self.responders.len().max(1);
        let deadline = self.time + u64::from(budget);
        match kind {
            Kind::Open if self.source => {
                if let Some(reason) = self.server {
                    self.steps.push(Step::RefuseOpen(reason));
                } else if !self.accepting && budget % 3 == 2 {
                    // Leave acceptance blocked, for a later attach or closure to end.
                    self.steps.push(Step::StartAccept);
                    self.accepting = true;
                } else {
                    if !self.sessions.is_empty() {
                        self.close(self.sessions.len() - 1, Failure::Reset);
                    }
                    let id = self.sessions.len() as u8;
                    if std::mem::take(&mut self.accepting) {
                        self.steps.extend([Step::Open(id), Step::FinishAccept(id)]);
                    } else if budget & 1 == 0 {
                        self.steps.extend([Step::Open(id), Step::Accept(id)]);
                    } else {
                        self.steps.extend([
                            Step::StartAccept,
                            Step::Open(id),
                            Step::FinishAccept(id),
                        ]);
                    }
                    self.sessions.push(Session {
                        reason: None,
                        owner: true,
                        abandonment: ABANDONMENT,
                        max_requests: DEFAULT_MAX_INBOUND_REQUESTS,
                        max_bytes: DEFAULT_MAX_INBOUND_BYTES,
                    });
                }
            }
            Kind::InboundLimits if !self.sessions.is_empty() && self.sessions[session].owner => {
                let requests = usize::from(value);
                let bytes = usize::from(budget);
                self.sessions[session].max_requests = requests;
                self.sessions[session].max_bytes = bytes;
                self.steps
                    .push(Step::InboundLimits(session as u8, requests, bytes));
                if self.request_usage(session) > requests {
                    self.close(session, Failure::Requests);
                } else if self.byte_usage(session) > bytes {
                    self.close(session, Failure::Bytes);
                }
            }
            Kind::AbandonmentTimeout
                if !self.sessions.is_empty() && self.sessions[session].owner =>
            {
                self.steps.push(Step::AbandonmentTimeout(
                    session as u8,
                    Duration::from_millis(u64::from(budget)),
                ));
                self.sessions[session].abandonment = u64::from(budget);
            }
            Kind::Request if !self.sessions.is_empty() => {
                if let Some(reason) = self.sessions[session].reason {
                    self.steps.push(Step::RefuseRequest(session as u8, reason));
                } else {
                    self.steps.push(Step::Request(
                        session as u8,
                        self.operations.len() as u8,
                        value,
                        deadline,
                    ));
                    self.enqueue(session, ExpectedMessage::Request(value), deadline, true);
                }
            }
            Kind::Receive if !self.sessions.is_empty() && self.sessions[session].owner => {
                if let Some(reason) = self.sessions[session].reason {
                    // A closed session refuses delivery and wakes its receivers.
                    self.steps.push(if budget & 1 == 0 {
                        Step::RefuseDelivery(session as u8, reason)
                    } else {
                        Step::ReceiveError(session as u8, reason)
                    });
                } else {
                    self.incoming(session, 1, value, budget & 1 != 0);
                }
            }
            Kind::IncomingBatch
                if !self.sessions.is_empty()
                    && self.sessions[session].owner
                    && self.sessions[session].reason.is_none() =>
            {
                self.incoming(session, budget % 4 + 1, value, false);
            }
            Kind::Reply | Kind::Abandon if !self.responders.is_empty() => {
                if let Some(session) = self.responders[responder].take() {
                    if kind == Kind::Abandon {
                        self.steps.push(Step::DropReply(responder as u8));
                        if self.sessions[session].reason.is_none() {
                            self.enqueue(
                                session,
                                ExpectedMessage::Reply(
                                    responder as u64,
                                    Err(ReservedErrors::Unanswered as u64),
                                ),
                                self.time + self.sessions[session].abandonment,
                                false,
                            );
                        }
                    } else if let Some(reason) = self.sessions[session].reason {
                        self.steps.push(Step::RefuseReply(responder as u8, reason));
                    } else if value % 4 == 3 {
                        // Closure fails the reply whether submission wins or loses.
                        self.steps
                            .push(Step::RaceReplyClose(session as u8, responder as u8));
                        self.close(session, Failure::Closed);
                    } else {
                        let result = if value & 1 == 0 {
                            Ok(value)
                        } else {
                            Err(u64::from(value) + 256)
                        };
                        self.steps.push(Step::Reply(
                            responder as u8,
                            self.operations.len() as u8,
                            result,
                            deadline,
                        ));
                        self.enqueue(
                            session,
                            ExpectedMessage::Reply(responder as u64, result),
                            deadline,
                            true,
                        );
                    }
                }
            }
            Kind::Outgoing if !self.sessions.is_empty() && self.sessions[session].owner => {
                self.expire(session);
                let queued: Vec<usize> = self
                    .operations
                    .iter()
                    .enumerate()
                    .filter(|(_, operation)| operation.session == session && operation.queued)
                    .map(|(id, _)| id)
                    .collect();
                let abandoned = !queued.is_empty()
                    && queued.iter().all(|&id| self.operations[id].abandonment());
                if value & 1 == 1 && abandoned {
                    // Drain automatic replies when no application messages remain.
                    let ids = queued
                        .iter()
                        .map(|&id| match self.operations[id].body {
                            ExpectedMessage::Reply(request, _) => request,
                            ExpectedMessage::Request(_) => unreachable!("abandonment is a reply"),
                        })
                        .collect();
                    self.steps.push(Step::Abandoned(session as u8, ids));
                    for id in queued {
                        let now = self.time;
                        let operation = &mut self.operations[id];
                        operation.queued = false;
                        operation.complete(now, Ok(0));
                    }
                } else if let Some(&id) = queued.first() {
                    let body = self.operations[id].body.clone();
                    let at = self.operations[id].deadline;
                    self.steps
                        .push(Step::Outgoing(session as u8, id as u8, body, at));
                    self.operations[id].queued = false;
                    self.operations[id].writing = true;
                } else {
                    self.steps.push(Step::NoOutgoing(session as u8));
                }
            }
            Kind::Written if !self.operations.is_empty() && self.operations[operation].writing => {
                let owner = self.operations[operation].session;
                if value % 8 == 7
                    && !self.operations[operation].request()
                    && self.raceable(operation)
                {
                    // Either the write result or closure may settle the promise.
                    self.steps.push(Step::RaceWriteClose(
                        owner as u8,
                        operation as u8,
                        operation as u8,
                    ));
                    self.consume(operation);
                    self.close(owner, Failure::Closed);
                } else {
                    let result = match value % 4 {
                        0 => Err(Failure::Reset),
                        1 => Err(Failure::Terminated),
                        _ => Ok(()),
                    };
                    self.steps.push(Step::Written(operation as u8, result));
                    let now = self.time;
                    let pending = &mut self.operations[operation];
                    if result.is_err() || !pending.request() || now >= pending.deadline {
                        pending.complete(now, result.map(|()| 0));
                    }
                }
            }
            Kind::Answer
                if !self.operations.is_empty()
                    && self.operations[operation].writing
                    && self.operations[operation].request() =>
            {
                let owner = self.operations[operation].session;
                if value % 8 == 7 && self.raceable(operation) {
                    // Either the peer answer or closure may settle the promise.
                    self.steps.push(Step::RaceAnswerClose(
                        owner as u8,
                        operation as u8,
                        operation as u8,
                    ));
                    self.consume(operation);
                    self.close(owner, Failure::Closed);
                } else {
                    let result = match value % 3 {
                        0 => Ok(value),
                        1 => Err(Failure::Remote(u64::from(value) + 256)),
                        _ => Err(Failure::WrongType),
                    };
                    self.steps.push(match result {
                        Ok(tag) => Step::Answer(operation as u8, Ok(tag)),
                        Err(Failure::Remote(code)) => Step::Answer(operation as u8, Err(code)),
                        _ => Step::AnswerOther(operation as u8),
                    });
                    let bytes = answer_size(result);
                    let pending = &self.operations[operation];
                    let retain = pending.result.is_none()
                        && self.time < pending.deadline
                        && pending.retained;
                    let overflow =
                        retain && self.byte_usage(owner) + bytes > self.sessions[owner].max_bytes;
                    let pending = &mut self.operations[operation];
                    pending.writing = false;
                    pending.complete(
                        self.time,
                        if overflow {
                            Err(Failure::Bytes)
                        } else {
                            result
                        },
                    );
                    if retain && !overflow {
                        pending.response_bytes = bytes;
                    }
                    if overflow {
                        self.close(owner, Failure::Bytes);
                    }
                }
            }
            Kind::Notify
                if !self.operations.is_empty()
                    && self.operations[operation].retained
                    && !self.operations[operation].parked
                    && !self.operations[operation].notified =>
            {
                let pending = &mut self.operations[operation];
                pending.notified = true;
                pending.notification = pending.result.is_some();
                self.steps.push(if pending.request() {
                    Step::Notify(operation as u8, operation as u8)
                } else {
                    Step::NotifyWrite(operation as u8, operation as u8)
                });
            }
            Kind::Wait
                if !self.operations.is_empty()
                    && self.operations[operation].retained
                    && !self.operations[operation].parked =>
            {
                let request = self.operations[operation].request();
                // Waiting expires overdue operations in the same session before
                // blocking. collect_waiters() joins it once a result is available.
                self.expire(self.operations[operation].session);
                self.operations[operation].parked = true;
                self.steps.push(if request {
                    Step::StartWait(operation as u8)
                } else {
                    Step::StartWaitWrite(operation as u8)
                });
            }
            Kind::DropPromise
                if !self.operations.is_empty()
                    && self.operations[operation].retained
                    && !self.operations[operation].parked =>
            {
                self.operations[operation].retained = false;
                self.steps.push(if self.operations[operation].request() {
                    Step::DropPromise(operation as u8)
                } else {
                    Step::DropWritePromise(operation as u8)
                });
            }
            Kind::Advance => {
                self.time += u64::from(budget);
                self.steps.push(Step::Time(self.time));
            }
            Kind::Expire if !self.sessions.is_empty() && self.sessions[session].owner => {
                self.expire(session);
                self.steps.push(Step::Expire(session as u8));
            }
            Kind::Close | Kind::Drop if !self.sessions.is_empty() => {
                if kind == Kind::Drop && self.sessions[session].owner {
                    self.steps.extend([
                        Step::DropSession(session as u8),
                        Step::Released(session as u8),
                    ]);
                    self.close(session, Failure::Closed);
                    self.sessions[session].owner = false;
                    // Weak handles to a freed session report Closed, while settled
                    // promises retain the reason that ended the original session.
                    self.sessions[session].reason = Some(Failure::Closed);
                } else {
                    let open = self.sessions[session].reason.is_none();
                    match value % 4 {
                        0 if open => self.steps.push(Step::RaceRequestClose(session as u8)),
                        1 => self.steps.push(Step::RaceCloses(session as u8)),
                        // Close under a receive already blocked on an empty queue,
                        // which has to wake with the reason that ended the session.
                        2 if open && self.sessions[session].owner => self.steps.extend([
                            Step::StartReceive(session as u8),
                            Step::CloseSession(session as u8),
                            Step::FinishReceiveError(session as u8, Failure::Closed),
                        ]),
                        _ => self.steps.push(Step::CloseSession(session as u8)),
                    }
                    self.close(session, Failure::Closed);
                }
            }
            Kind::CloseServer | Kind::DropSource => {
                // Racing an attach needs an already closed session, so the reason
                // ending it cannot depend on which thread wins.
                let raced = kind == Kind::CloseServer
                    && value % 4 == 2
                    && self.source
                    && self
                        .sessions
                        .last()
                        .is_none_or(|session| session.reason.is_some());
                let reason = if kind == Kind::CloseServer {
                    self.steps.push(match value % 4 {
                        1 => Step::RaceServerCloses,
                        2 if raced => Step::RaceServerCloseOpen,
                        _ => Step::CloseServer,
                    });
                    Some(Failure::Closed)
                } else if self.source {
                    self.steps.push(Step::DropSource);
                    self.source = false;
                    Some(Failure::Terminated)
                } else {
                    None
                };
                if let Some(reason) = reason {
                    let reason = *self.server.get_or_insert(reason);
                    if !self.sessions.is_empty() {
                        self.close(self.sessions.len() - 1, reason);
                    }
                    if std::mem::take(&mut self.accepting) {
                        // An attach may have won the race and handed over a session,
                        // which acceptance then finds already closed.
                        self.steps.push(if raced {
                            Step::FinishAcceptClosed
                        } else {
                            Step::FinishAcceptError(reason)
                        });
                    }
                    if kind == Kind::CloseServer && value % 4 == 3 && !self.server_dropped {
                        self.steps.push(Step::DropServer);
                        self.server_dropped = true;
                    }
                }
            }
            _ => {}
        }
        self.collect_waiters();
        self.collect_notifications();
        for (session, state) in self.sessions.iter().enumerate() {
            if state.owner {
                let next = self
                    .operations
                    .iter()
                    .filter(|operation| operation.session == session && operation.result.is_none())
                    .map(|operation| operation.deadline)
                    .min();
                self.steps.push(Step::Deadline(session as u8, next));
                self.steps.push(Step::Usage(
                    session as u8,
                    self.request_usage(session),
                    self.byte_usage(session),
                ));
            }
        }
    }
}

/// Measures the fixture's original answer encoding with the schema codec. The
/// ledger stores this length; it never consults production budget counters.
fn answer_size(result: Result<u8, Failure>) -> usize {
    let (err, content) = match result {
        Ok(tag) => (None, Some(host_to_ark::Content::Develop(vec![tag]))),
        Err(Failure::Remote(code)) => (
            Some(RemoteError {
                code,
                msg: "refused".into(),
            }),
            None,
        ),
        Err(Failure::WrongType) => (
            None,
            Some(host_to_ark::Content::DeviceInfo(Default::default())),
        ),
        _ => unreachable!("only peer result encodings have a byte charge"),
    };
    HostToArk {
        id: 0,
        err,
        content,
    }
    .encoded_len()
}

/// Executes up to [`MAX_STEPS`] arbitrary actions, then closes all owners and
/// checks every retained promise, including the ones parked in a blocking wait.
/// Simulated time never requires sleeps or deadline races.
pub fn run(actions: &[Action]) {
    #[cfg(feature = "fuzz")]
    super::super::seed::seed(super::super::seed::SESSION_TARGET, actions);
    let mut model = Model {
        source: true,
        ..Model::default()
    };
    model.step(Action {
        kind: Kind::Open,
        slot: 0,
        value: 0,
        budget: 0,
    });
    for &action in actions.iter().take(MAX_STEPS) {
        model.step(action);
    }
    model.step(Action {
        kind: Kind::CloseServer,
        slot: 0,
        value: 0,
        budget: 0,
    });
    for (id, operation) in model.operations.iter().enumerate() {
        if !operation.retained {
            continue;
        }
        let result = operation
            .result
            .expect("closed session settles every operation");
        assert!(
            !operation.parked,
            "completed waiters were already collected"
        );
        model.steps.push(if operation.request() {
            // An answered request can also hand back the message enum itself,
            // leaving the variant check to the application.
            match result {
                Ok(tag) if id % 2 == 1 => Step::WaitMessage(id as u8, tag),
                result => Step::Wait(id as u8, result),
            }
        } else {
            Step::WaitWrite(id as u8, result.map(|_| ()))
        });
    }
    super::run(model.steps);
}

#[cfg(test)]
#[path = "fuzz_tests.rs"]
mod tests;
