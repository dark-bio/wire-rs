// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Turns arbitrary actions into valid scripts with independently predicted results.
//! The model uses integer time and a ledger of operations; it never reads session
//! internals to decide which result, queued message or deadline to expect.

use super::{ExpectedMessage, Failure, Step};
use crate::protocol::ReservedErrors;
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
    /// Body tag, result selector or choice of concurrent execution.
    pub value: u8,
    /// Relative deadline, clock advance or abandonment timeout in milliseconds.
    pub budget: u8,
}

/// Public operations and independently scheduled transport/deadline completions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum Kind {
    Open,
    Request,
    Receive,
    Reply,
    Abandon,
    AbandonmentTimeout,
    Outgoing,
    Written,
    Answer,
    Advance,
    Expire,
    DropPromise,
    Close,
    Drop,
    CloseServer,
    DropSource,
}

struct Session {
    reason: Option<Failure>,
    owner: bool,
    abandonment: u64,
}

struct Operation {
    session: usize,
    body: ExpectedMessage,
    deadline: u64,
    result: Option<Result<u8, Failure>>,
    observed: bool,
    queued: bool,
    writing: bool,
}

impl Operation {
    fn request(&self) -> bool {
        matches!(self.body, ExpectedMessage::Request(_))
    }

    fn complete(&mut self, now: u64, result: Result<u8, Failure>) {
        if self.result.is_none() {
            self.result = Some(if now >= self.deadline {
                Err(Failure::Timeout)
            } else {
                result
            });
        }
    }
}

#[derive(Default)]
struct Model {
    time: u64,
    sessions: Vec<Session>,
    operations: Vec<Operation>,
    responders: Vec<Option<usize>>,
    server: Option<Failure>,
    source: bool,
    steps: Vec<Step>,
}

impl Model {
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

    fn enqueue(&mut self, session: usize, body: ExpectedMessage, deadline: u64, observed: bool) {
        self.operations.push(Operation {
            session,
            body,
            deadline,
            result: (deadline <= self.time).then_some(Err(Failure::Timeout)),
            observed,
            queued: deadline > self.time,
            writing: false,
        });
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
                } else {
                    if !self.sessions.is_empty() {
                        self.close(self.sessions.len() - 1, Failure::Reset);
                    }
                    let id = self.sessions.len() as u8;
                    if budget & 1 == 0 {
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
                        abandonment: 5000,
                    });
                }
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
            Kind::Receive
                if !self.sessions.is_empty() && self.sessions[session].reason.is_none() =>
            {
                let slot = self.responders.len() as u8;
                if budget & 1 == 0 {
                    self.steps.extend([
                        Step::Deliver(session as u8, u64::from(slot), value),
                        Step::Receive(session as u8, value, slot),
                    ]);
                } else {
                    self.steps.extend([
                        Step::StartReceive(session as u8),
                        Step::Deliver(session as u8, u64::from(slot), value),
                        Step::FinishReceive(session as u8, value, slot),
                    ]);
                }
                self.responders.push(Some(session));
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
            Kind::AbandonmentTimeout
                if !self.sessions.is_empty() && self.sessions[session].owner =>
            {
                self.steps.push(Step::AbandonmentTimeout(
                    session as u8,
                    Duration::from_millis(u64::from(budget)),
                ));
                self.sessions[session].abandonment = u64::from(budget);
            }
            Kind::Outgoing if !self.sessions.is_empty() && self.sessions[session].owner => {
                self.expire(session);
                if let Some((id, outgoing)) = self
                    .operations
                    .iter_mut()
                    .enumerate()
                    .find(|(_, op)| op.session == session && op.queued)
                {
                    self.steps.push(Step::Outgoing(
                        session as u8,
                        id as u8,
                        outgoing.body.clone(),
                        outgoing.deadline,
                    ));
                    outgoing.queued = false;
                    outgoing.writing = true;
                } else {
                    self.steps.push(Step::NoOutgoing(session as u8));
                }
            }
            Kind::Written if !self.operations.is_empty() && self.operations[operation].writing => {
                let op = &mut self.operations[operation];
                let result = match value % 4 {
                    0 => Err(Failure::Closed),
                    1 => Err(Failure::Reset),
                    _ => Ok(()),
                };
                self.steps.push(Step::Written(operation as u8, result));
                if result.is_err() || !op.request() || self.time >= op.deadline {
                    op.complete(self.time, result.map(|()| 0));
                }
            }
            Kind::Answer
                if !self.operations.is_empty()
                    && self.operations[operation].writing
                    && self.operations[operation].request() =>
            {
                let op = &mut self.operations[operation];
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
                op.writing = false;
                op.complete(self.time, result);
            }
            Kind::Advance => {
                self.time += u64::from(budget);
                self.steps.push(Step::Time(self.time));
            }
            Kind::Expire if !self.sessions.is_empty() && self.sessions[session].owner => {
                self.expire(session);
                self.steps.push(Step::Expire(session as u8));
            }
            Kind::DropPromise
                if !self.operations.is_empty() && self.operations[operation].observed =>
            {
                let op = &mut self.operations[operation];
                op.observed = false;
                self.steps.push(if op.request() {
                    Step::DropPromise(operation as u8)
                } else {
                    Step::DropWritePromise(operation as u8)
                });
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
                    self.steps.push(match value % 3 {
                        0 if self.sessions[session].reason.is_none() => {
                            Step::RaceRequestClose(session as u8)
                        }
                        1 => Step::RaceCloses(session as u8),
                        _ => Step::CloseSession(session as u8),
                    });
                    self.close(session, Failure::Closed);
                }
            }
            Kind::CloseServer | Kind::DropSource => {
                let reason = if kind == Kind::CloseServer {
                    self.steps.push(Step::CloseServer);
                    Failure::Closed
                } else if self.source {
                    self.steps.push(Step::DropSource);
                    self.source = false;
                    Failure::Terminated
                } else {
                    return;
                };
                let reason = *self.server.get_or_insert(reason);
                if !self.sessions.is_empty() {
                    self.close(self.sessions.len() - 1, reason);
                }
            }
            _ => {}
        }
        for (session, state) in self.sessions.iter().enumerate() {
            if state.owner {
                let next = self
                    .operations
                    .iter()
                    .filter(|op| op.session == session && op.result.is_none())
                    .map(|op| op.deadline)
                    .min();
                self.steps.push(Step::Deadline(session as u8, next));
            }
        }
    }
}

/// Executes up to 64 arbitrary actions, then closes all owners and checks every
/// retained promise. Simulated time never requires sleeps or deadline races.
pub fn run(actions: &[Action]) {
    #[cfg(feature = "fuzz")]
    crate::transport::mock::seed::seed("protocol-session", actions);
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
    for &action in actions.iter().take(64) {
        model.step(action);
    }
    model.step(Action {
        kind: Kind::CloseServer,
        slot: 0,
        value: 0,
        budget: 0,
    });
    for (id, op) in model.operations.iter().enumerate() {
        if op.observed {
            let result = op.result.expect("closed session settles every operation");
            model.steps.push(if op.request() {
                Step::Wait(id as u8, result)
            } else {
                Step::WaitWrite(id as u8, result.map(|_| ()))
            });
        }
    }
    super::run(model.steps);
}

#[cfg(feature = "fuzz")]
impl crate::transport::mock::seed::Seedable for Action {
    fn seed(&self, seed: &mut crate::transport::mock::seed::Seed) {
        seed.variant(self.kind as u32, 16);
        seed.byte(self.slot);
        seed.byte(self.value);
        seed.byte(self.budget);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_completion_orderings() {
        use Kind::*;
        for time in [9, 10, 11] {
            for result in 0..3 {
                let steps = [
                    (Request, 0, 10, 10),
                    (Request, 0, 20, 20),
                    (Outgoing, 0, 0, 0),
                    (Outgoing, 0, 0, 0),
                    (Receive, 0, 30, 1),
                    (Reply, 0, 40, 10),
                    (Outgoing, 0, 0, 0),
                    (Written, 1, 2, 0),
                    (Written, 1, 2, 0),
                    (Advance, 0, 0, time),
                    (Written, 2, 2, 0),
                    (Answer, 1, result, 0),
                    (Answer, 0, result, 0),
                    (Open, 0, 0, 1),
                    (Written, 2, 0, 0),
                    (Request, 1, 50, 20),
                    (Outgoing, 1, 0, 0),
                    (Close, 0, 1, 0),
                    (Answer, 3, result, 0),
                    (Drop, 0, 0, 0),
                ];
                run(&steps.map(|(kind, slot, value, budget)| Action {
                    kind,
                    slot,
                    value,
                    budget,
                }));
            }
        }
    }

    #[test]
    fn test_model_scripts() {
        use Kind::*;
        for ending in [Open, Close, Drop, CloseServer, DropSource] {
            for budget in [0, 1, 10, 255] {
                let actions = [
                    Request,
                    Request,
                    Outgoing,
                    Written,
                    Receive,
                    Reply,
                    Outgoing,
                    Advance,
                    Answer,
                    Expire,
                    ending,
                    Request,
                    Receive,
                    Abandon,
                    Outgoing,
                    DropPromise,
                    Drop,
                ];
                run(&actions.map(|kind| Action {
                    kind,
                    slot: 0,
                    value: 3,
                    budget,
                }));
            }
        }
        run(&[
            Receive,
            AbandonmentTimeout,
            Abandon,
            Outgoing,
            Written,
            Open,
            Close,
            Request,
            Drop,
        ]
        .map(|kind| Action {
            kind,
            slot: 0,
            value: 0,
            budget: 10,
        }));
    }
}
