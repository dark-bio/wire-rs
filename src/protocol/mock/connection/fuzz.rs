// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Composable exchanges and lifecycle transitions over live encrypted streams.
//! Each action leaves a usable connection or proves closure before reconnecting.
//! I/O gates establish ordering; the native scheduler supplies worker interleavings.

use super::{EnvelopeShape, Failure, Mode, Step};
use crate::transport::mock::duplex::Operation;
use std::io;

/// Selects a scenario and varies its pipeline size, ordering, IDs and payloads.
/// The first action's slot parity chooses whether to exercise a protocol server
/// or client. An input runs at most eight actions, including actual timeouts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct Action {
    /// Exchange or lifecycle transition to execute.
    pub kind: Kind,
    /// Peer role on the first action; ordering and I/O phase thereafter.
    pub slot: u8,
    /// Payload tag, error code or malformed envelope shape.
    pub value: u8,
    /// Pipeline size, deadline adjustment or duplicate-request phase.
    pub budget: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum Kind {
    Pipeline,
    Incoming,
    Refusal,
    ResponseDuringFlush,
    RequestTimeout,
    ReplyTimeout,
    ReuseDuringFlush,
    Duplicate,
    Malformed,
    Replace,
    Close,
    Fault,
}

/// Runs arbitrary live connection actions and joins all workers before returning.
pub fn run(actions: &[Action]) {
    #[cfg(feature = "fuzz")]
    crate::transport::mock::seed::seed("protocol-connection", actions);
    let server = actions.first().is_none_or(|action| action.slot & 1 == 0);
    let mode = if server { Mode::Server } else { Mode::Client };
    let mut script = Vec::new();
    let mut local = u8::from(server);
    let mut next = if server { 2 } else { 1 };
    let outgoing = u8::from(server);
    for (index, action) in actions.iter().take(8).enumerate() {
        let Action {
            kind,
            slot,
            value,
            budget,
        } = *action;
        tracing::debug!(index, ?action, "protocol connection fuzz action");
        let mut steps = Vec::new();
        let mut ended = false;
        // Include zero and the largest IDs, alongside small reusable IDs. Only
        // the peer parity is constrained; peer IDs need not be monotonic.
        let peer = match slot % 3 {
            0 => 0,
            1 => u64::MAX - 1,
            _ => u64::from(budget) * 2,
        } | u64::from(server);
        let content = EnvelopeShape::Content(value);
        let answer = EnvelopeShape::Content(value.wrapping_add(1));
        match kind {
            Kind::Pipeline => {
                let count = budget % 8 + 1;
                for id in 0..count {
                    steps.push(Step::Request(local, id, value.wrapping_add(id), 3000));
                }
                for id in 0..count {
                    steps.push(Step::Read(
                        next + u64::from(id) * 2,
                        EnvelopeShape::Content(value.wrapping_add(id)),
                    ));
                }
                // Unknown responses and duplicate answers must not resolve a
                // different promise. Rotate a reverse permutation of the batch.
                steps.push(Step::Send(next + 1000, content.clone()));
                for offset in 0..count {
                    let id = (count - 1 - offset + slot % count) % count;
                    let wire = next + u64::from(id) * 2;
                    let tag = value.wrapping_add(id).wrapping_add(1);
                    let (body, result) = if tag & 1 == 0 {
                        (EnvelopeShape::Content(tag), Ok(tag))
                    } else {
                        (
                            EnvelopeShape::Error(u64::from(tag)),
                            Err(Failure::Remote(u64::from(tag))),
                        )
                    };
                    steps.extend([
                        Step::Send(wire, body),
                        Step::Answer(id, result),
                        Step::Send(wire, content.clone()),
                    ]);
                }
                next += u64::from(count) * 2;
            }
            Kind::Incoming => {
                let count = budget % 8 + 1;
                for id in 0..count {
                    steps.push(Step::Send(
                        peer.wrapping_add(u64::from(id) * 2),
                        EnvelopeShape::Content(value.wrapping_add(id)),
                    ));
                }
                for id in 0..count {
                    steps.push(Step::Receive(local, value.wrapping_add(id), id));
                }
                for id in (0..count).rev() {
                    let wire = peer.wrapping_add(u64::from(id) * 2);
                    if id.wrapping_add(slot) & 1 == 0 {
                        steps
                            .extend([Step::Abandon(id), Step::Read(wire, EnvelopeShape::Error(1))]);
                    } else {
                        steps.extend([
                            Step::Reply(id, id, Ok(value), 3000),
                            Step::Read(wire, content.clone()),
                            Step::Written(id, Ok(())),
                        ]);
                    }
                }
            }
            Kind::Refusal => {
                steps.extend([
                    if value & 1 == 0 {
                        Step::WrongDirection(local, 0)
                    } else {
                        Step::Oversized(local, 0)
                    },
                    Step::Answer(
                        0,
                        Err(if value & 1 == 0 {
                            Failure::Direction
                        } else {
                            Failure::Large
                        }),
                    ),
                ]);
                next += 2;
            }
            Kind::ResponseDuringFlush | Kind::RequestTimeout => {
                let timeout = kind == Kind::RequestTimeout;
                let op = if timeout && slot & 2 == 0 {
                    Operation::Write
                } else {
                    Operation::Flush
                };
                steps.extend([
                    Step::Pause(outgoing, op, true),
                    Step::Request(
                        local,
                        0,
                        value,
                        if timeout {
                            50 + u64::from(budget % 10)
                        } else {
                            3000
                        },
                    ),
                    Step::Blocked(outgoing, op),
                ]);
                if timeout {
                    steps.extend([
                        Step::Answer(0, Err(Failure::Timeout)),
                        Step::Pause(outgoing, op, false),
                    ]);
                }
                steps.extend([
                    Step::Read(next, content.clone()),
                    Step::Send(next, answer.clone()),
                ]);
                if !timeout {
                    steps.extend([
                        Step::Answer(0, Ok(value.wrapping_add(1))),
                        Step::Pause(outgoing, op, false),
                    ]);
                }
                next += 2;
            }
            Kind::ReplyTimeout => {
                steps.extend([
                    Step::Send(peer, content.clone()),
                    Step::Receive(local, value, 0),
                    Step::Pause(outgoing, Operation::Flush, true),
                    Step::Reply(0, 0, Ok(value.wrapping_add(1)), 50 + u64::from(budget % 10)),
                    Step::Blocked(outgoing, Operation::Flush),
                    Step::Written(0, Err(Failure::Timeout)),
                    Step::Read(peer, answer.clone()),
                    Step::Pause(outgoing, Operation::Flush, false),
                ]);
            }
            Kind::ReuseDuringFlush => {
                steps.extend([
                    Step::Send(peer, content.clone()),
                    Step::Receive(local, value, 0),
                    Step::Pause(outgoing, Operation::Flush, true),
                    Step::Reply(0, 0, Ok(value.wrapping_add(1)), 3000),
                    Step::Blocked(outgoing, Operation::Flush),
                    Step::Read(peer, answer.clone()),
                    Step::Send(peer, content.clone()),
                    Step::Receive(local, value, 1),
                    Step::Pause(outgoing, Operation::Flush, false),
                    Step::Written(0, Ok(())),
                ]);
                if budget & 1 == 0 {
                    steps.extend([Step::Abandon(1), Step::Read(peer, EnvelopeShape::Error(1))]);
                } else {
                    steps.extend([
                        Step::StartReceive(local),
                        Step::Reject(peer, content.clone()),
                        Step::ReceiveFailed(local, Failure::Malformed),
                        Step::Abandon(1),
                    ]);
                    ended = true;
                }
            }
            Kind::Duplicate => {
                steps.push(Step::Send(peer, content.clone()));
                if budget % 3 != 0 {
                    steps.push(Step::Receive(local, value, 0));
                }
                if budget % 3 == 2 {
                    steps.extend([
                        Step::Pause(outgoing, Operation::Write, true),
                        Step::Request(local, 1, value, 3000),
                        Step::Blocked(outgoing, Operation::Write),
                        Step::Reply(0, 0, Ok(value), 3000),
                    ]);
                }
                steps.extend([
                    Step::Request(local, 0, value, 3000),
                    Step::Reject(peer, content.clone()),
                    Step::Answer(0, Err(Failure::Malformed)),
                ]);
                if budget % 3 == 2 {
                    steps.extend([
                        Step::Answer(1, Err(Failure::Malformed)),
                        Step::Written(0, Err(Failure::Malformed)),
                        Step::Pause(outgoing, Operation::Write, false),
                    ]);
                } else if budget % 3 == 1 {
                    steps.push(Step::Abandon(0));
                }
                ended = true;
            }
            Kind::Malformed => {
                let (id, body) = match value % 5 {
                    0 => (peer, EnvelopeShape::Error(u64::from(value))),
                    1 => (peer, EnvelopeShape::Both),
                    2 => (next, EnvelopeShape::Neither),
                    3 => (next, EnvelopeShape::Both),
                    _ => (peer, EnvelopeShape::Invalid),
                };
                steps.extend([
                    Step::StartReceive(local),
                    Step::Reject(id, body),
                    Step::ReceiveFailed(local, Failure::Malformed),
                ]);
                ended = true;
            }
            Kind::Replace if server => {
                // Retain an unanswered request and a responder across replacement.
                steps.extend([
                    Step::Send(peer, content.clone()),
                    Step::Receive(local, value, 0),
                    Step::Request(local, 0, value, 3000),
                    Step::Read(next, content.clone()),
                    Step::Reconnect(local + 1),
                    Step::Answer(0, Err(Failure::Transport)),
                    Step::Abandon(0),
                    Step::Close(local),
                    Step::Refused(local),
                    Step::Drop(local),
                    Step::Released(local),
                ]);
                local += 1;
                next = 2;
            }
            Kind::Close | Kind::Replace => {
                steps.extend([
                    Step::StartReceive(local),
                    Step::Close(local),
                    Step::ReceiveFailed(local, Failure::Closed),
                ]);
                ended = true;
            }
            Kind::Fault => {
                let op = if slot & 2 == 0 {
                    Operation::Write
                } else {
                    Operation::Flush
                };
                let fault = if value & 1 == 0 {
                    io::ErrorKind::BrokenPipe
                } else {
                    io::ErrorKind::TimedOut
                };
                steps.extend([
                    Step::StartReceive(local),
                    Step::Fault(outgoing, op, fault),
                    Step::Request(local, 0, value, 3000),
                    Step::Answer(0, Err(Failure::Transport)),
                    Step::ReceiveFailed(local, Failure::Transport),
                ]);
                ended = true;
            }
        }
        if ended {
            steps.extend([
                Step::Refused(local),
                Step::Drop(local),
                Step::Released(local),
            ]);
            if server {
                steps.extend([
                    Step::Reconnect(local + 1),
                    Step::Close(local),
                    Step::Refused(local),
                ]);
                local += 1;
                next = 2;
            }
        }
        script.extend(steps);
        if ended && !server {
            break;
        }
        // A round trip fences previous inbound answers and proves that recoverable
        // errors, late completions and stale handles left the current session usable.
        for step in [
            Step::Request(local, 0, value, 3000),
            Step::Read(next, content),
            Step::Send(next, answer),
            Step::Answer(0, Ok(value.wrapping_add(1))),
            Step::Outstanding(local, vec![]),
        ] {
            script.push(step);
        }
        next += 2;
    }
    super::run(mode, &script);
}

#[cfg(feature = "fuzz")]
impl crate::transport::mock::seed::Seedable for Action {
    fn seed(&self, seed: &mut crate::transport::mock::seed::Seed) {
        seed.variant(self.kind as u32, 12);
        seed.byte(self.slot);
        seed.byte(self.value);
        seed.byte(self.budget);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_fuzz_sequences() {
        use Kind::*;
        for slot in 0..2 {
            for kinds in [
                [
                    Pipeline,
                    Incoming,
                    ResponseDuringFlush,
                    Refusal,
                    ReuseDuringFlush,
                    ReplyTimeout,
                    RequestTimeout,
                    Pipeline,
                ],
                [
                    Replace, Pipeline, Malformed, Incoming, Fault, Pipeline, Close, Incoming,
                ],
            ] {
                run(&kinds.map(|kind| Action {
                    kind,
                    slot,
                    value: 255,
                    budget: 6,
                }));
            }
        }
    }

    #[test]
    fn test_connection_fuzz_actions() {
        use Kind::*;
        for slot in 0..6 {
            for kind in [
                Pipeline,
                Incoming,
                Refusal,
                ResponseDuringFlush,
                RequestTimeout,
                ReplyTimeout,
                ReuseDuringFlush,
                Duplicate,
                Malformed,
                Replace,
                Close,
                Fault,
            ] {
                for budget in 0..3 {
                    run(&[
                        Action {
                            kind,
                            slot,
                            value: slot * 11,
                            budget,
                        },
                        Action {
                            kind: Pipeline,
                            slot,
                            value: 255,
                            budget: 7,
                        },
                    ]);
                }
            }
        }
    }
}
