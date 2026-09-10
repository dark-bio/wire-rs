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
    /// Pipeline size, deadline adjustment or ordering of a failure scenario.
    pub budget: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum Kind {
    // Requests, replies and local refusal.
    Pipeline,
    Incoming,
    Refusal,
    ReplyRefusal,

    // Deadlines and write completion.
    ResponseDuringFlush,
    RequestTimeout,
    ReplyTimeout,
    QueuedTimeout,
    ResponseBeforeFailure,
    ReuseDuringFlush,

    // Invalid input and limits.
    Duplicate,
    Malformed,
    /// Inbound limit or deferred decode failure, optionally with blocked output.
    InboundFailure,
    Exhaust,

    // Connection lifecycle and I/O failure.
    Replace,
    Disconnect,
    HandshakeFailure,
    Close,
    Fault,
}

/// Maximum actions run from one input, each driving several live exchanges.
const ACTIONS: usize = 8;

/// Whether an action ends the client session. Its stream cannot reconnect, so
/// the runner defers the first such action until the other exchanges finish.
fn ends_client(action: &Action) -> bool {
    match action.kind {
        Kind::Duplicate
        | Kind::Malformed
        | Kind::Exhaust
        | Kind::Close
        | Kind::Fault
        | Kind::ResponseBeforeFailure
        | Kind::InboundFailure => true,
        Kind::ReuseDuringFlush => action.budget & 1 == 1,
        Kind::Replace | Kind::Disconnect | Kind::HandshakeFailure => true,
        _ => false,
    }
}

/// Runs arbitrary live connection actions and joins all workers before returning.
pub fn run(actions: &[Action]) {
    #[cfg(feature = "fuzz")]
    super::super::seed::seed(super::super::seed::CONNECTION_TARGET, actions);
    let server = actions.first().is_none_or(|action| action.slot & 1 == 0);
    let mode = if server { Mode::Server } else { Mode::Client };

    // Run a client's ending action last, so the actions behind it still execute
    // instead of being discarded along with its connection.
    let mut ordered: Vec<Action> = Vec::new();
    let mut ending = None;
    for &action in actions.iter().take(ACTIONS) {
        if server || !ends_client(&action) {
            ordered.push(action);
        } else {
            ending.get_or_insert(action);
        }
    }
    ordered.extend(ending);

    let mut script = Vec::new();
    let mut local = u8::from(server);
    let mut next = if server { 2 } else { 1 };
    let outgoing = u8::from(server);
    for (index, action) in ordered.iter().enumerate() {
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
            Kind::ReplyRefusal => {
                // Refusing a reply must not queue UNANSWERED or retain the peer ID.
                steps.extend([
                    Step::Send(peer, content.clone()),
                    Step::Receive(local, value, 0),
                    if value & 1 == 0 {
                        Step::WrongDirectionReply(local, 0, 0)
                    } else {
                        Step::OversizedReply(0, 0)
                    },
                    Step::Written(
                        0,
                        Err(if value & 1 == 0 {
                            Failure::Direction
                        } else {
                            Failure::Large
                        }),
                    ),
                    Step::Send(peer, answer.clone()),
                    Step::Receive(local, value.wrapping_add(1), 1),
                    Step::Reply(1, 1, Ok(value), 3000),
                    Step::Read(peer, content.clone()),
                    Step::Written(1, Ok(())),
                ]);
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
            Kind::QueuedTimeout => {
                // The blocked writer leaves both messages queued until expiry.
                // Reusing the peer ID and the next local ID checks their cleanup.
                let timeout = 50 + u64::from(budget % 10);
                steps.extend([
                    Step::Pause(outgoing, Operation::Write, true),
                    Step::Request(local, 0, value, 3000),
                    Step::Blocked(outgoing, Operation::Write),
                    Step::Request(local, 1, value.wrapping_add(1), timeout),
                    Step::Send(peer, content.clone()),
                    Step::Receive(local, value, 0),
                    Step::Reply(0, 0, Ok(value), timeout),
                    Step::Answer(1, Err(Failure::Timeout)),
                    Step::Written(0, Err(Failure::Timeout)),
                    Step::Send(peer, answer.clone()),
                    Step::Receive(local, value.wrapping_add(1), 1),
                    Step::Reply(1, 1, Ok(value), 3000),
                    Step::Pause(outgoing, Operation::Write, false),
                    Step::Read(next, content.clone()),
                    Step::Send(next, answer.clone()),
                    Step::Answer(0, Ok(value.wrapping_add(1))),
                    Step::Read(peer, content.clone()),
                    Step::Written(1, Ok(())),
                ]);
                next += 2;
            }
            Kind::ResponseBeforeFailure => {
                let (body, result) = if value & 1 == 0 {
                    (answer.clone(), Ok(value.wrapping_add(1)))
                } else {
                    (
                        EnvelopeShape::Error(u64::from(value)),
                        Err(Failure::Remote(u64::from(value))),
                    )
                };
                steps.extend([
                    Step::Pause(outgoing, Operation::Flush, true),
                    Step::Request(local, 0, value, 3000),
                    Step::Blocked(outgoing, Operation::Flush),
                    Step::Read(next, content.clone()),
                    Step::Send(next, body),
                    // This receive fences the answer while leaving its result
                    // buffered until after the write closes the session.
                    Step::Send(peer, content.clone()),
                    Step::Receive(local, value, 0),
                    Step::Outstanding(local, vec![]),
                    Step::Request(local, 1, value, 3000),
                    Step::Reply(0, 0, Ok(value), 3000),
                    Step::StartReceive(local),
                    Step::Fault(outgoing, Operation::Flush, io::ErrorKind::BrokenPipe),
                    Step::Pause(outgoing, Operation::Flush, false),
                    Step::ReceiveFailed(local, Failure::Transport),
                    Step::Answer(0, result),
                    Step::Answer(1, Err(Failure::Transport)),
                    Step::Written(0, Err(Failure::Transport)),
                ]);
                ended = true;
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
                match value % 8 {
                    5 => steps.extend([
                        Step::Send(peer, EnvelopeShape::MalformedBody),
                        Step::ReceiveError(local, Failure::Malformed),
                    ]),
                    6 | 7 => steps.extend([
                        Step::Request(local, 0, value, 3000),
                        Step::Read(next, content.clone()),
                        Step::Send(
                            next,
                            if value % 8 == 6 {
                                EnvelopeShape::MalformedBody
                            } else {
                                EnvelopeShape::MalformedError
                            },
                        ),
                        Step::ResponseReceived(local, next),
                        Step::StartReceive(local),
                        Step::Answer(0, Err(Failure::Malformed)),
                        Step::ReceiveFailed(local, Failure::Malformed),
                    ]),
                    shape => {
                        let (id, body) = match shape {
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
                    }
                }
                ended = true;
            }
            Kind::InboundFailure if budget & 128 != 0 => {
                let reason = match value % 3 {
                    0 => Failure::Requests,
                    1 => Failure::Bytes,
                    _ => Failure::Malformed,
                };
                let phase = if slot & 2 == 0 {
                    Operation::Write
                } else {
                    Operation::Flush
                };
                steps.extend(super::blocked_inbound_steps(
                    local, next, peer, outgoing, phase, reason,
                ));
                ended = true;
            }
            Kind::InboundFailure => {
                use crate::protocol::envelope::Side;
                use crate::protocol::{DEFAULT_MAX_INBOUND_BYTES, DEFAULT_MAX_INBOUND_REQUESTS};
                match value % 3 {
                    0 => {
                        let count = budget % 4;
                        steps.push(Step::InboundLimits(
                            local,
                            usize::from(count),
                            DEFAULT_MAX_INBOUND_BYTES,
                        ));
                        for id in 0..count {
                            steps.extend([
                                Step::Send(peer.wrapping_add(u64::from(id) * 2), content.clone()),
                                Step::Receive(local, value, id),
                            ]);
                        }
                        steps.extend([
                            Step::StartReceive(local),
                            Step::Reject(peer.wrapping_add(u64::from(count) * 2), content.clone()),
                            Step::ReceiveFailed(local, Failure::Requests),
                        ]);
                        for id in 0..count {
                            steps.push(Step::Abandon(id));
                        }
                    }
                    1 => steps.extend([
                        Step::InboundLimits(local, DEFAULT_MAX_INBOUND_REQUESTS, 0),
                        Step::Request(local, 0, value, 3000),
                        Step::Read(next, content.clone()),
                        Step::StartReceive(local),
                        Step::Reject(peer, content.clone()),
                        Step::ReceiveFailed(local, Failure::Bytes),
                        Step::Answer(0, Err(Failure::Bytes)),
                    ]),
                    _ => {
                        let peer_side = if server { Side::Client } else { Side::Server };
                        let bytes = peer_side
                            .encode(next, Ok(vec![value].into()))
                            .unwrap()
                            .len();
                        steps.extend([
                            Step::InboundLimits(local, 0, bytes),
                            Step::Request(local, 0, value, 3000),
                            Step::Read(next, content.clone()),
                            Step::Send(next, content.clone()),
                            Step::ResponseReceived(local, next),
                            Step::Usage(local, 0, bytes),
                            Step::Request(local, 1, value, 3000),
                            Step::Read(next + 2, content.clone()),
                            Step::StartReceive(local),
                            Step::Reject(next + 2, content.clone()),
                            Step::ReceiveFailed(local, Failure::Bytes),
                            Step::Answer(1, Err(Failure::Bytes)),
                            Step::Answer(0, Ok(value)),
                            Step::Usage(local, 0, 0),
                        ]);
                    }
                }
                ended = true;
            }
            Kind::Exhaust => {
                // One allocatable ID is left; taking another would abort the writer.
                let last = if server { u64::MAX - 1 } else { u64::MAX };
                steps.extend([
                    Step::LastId(local),
                    Step::Request(local, 0, value, 3000),
                    Step::Read(last, content.clone()),
                    Step::Send(last, answer.clone()),
                    Step::Answer(0, Ok(value.wrapping_add(1))),
                    Step::Outstanding(local, vec![]),
                    Step::Close(local),
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
            Kind::Disconnect if server => {
                // A writer paused before its disconnect must leave the session
                // that replaced it connected.
                steps.extend([
                    Step::PauseDisconnect(local),
                    Step::Pause(outgoing, Operation::Flush, true),
                    Step::Request(local, 0, value, 3000),
                    Step::Blocked(outgoing, Operation::Flush),
                    Step::Read(next, content.clone()),
                    Step::Close(local),
                    Step::Answer(0, Err(Failure::Closed)),
                    Step::Pause(outgoing, Operation::Flush, false),
                    Step::DisconnectPaused(local),
                    Step::Reconnect(local + 1),
                    Step::ResumeDisconnect(local),
                    Step::Refused(local),
                    Step::Drop(local),
                    Step::Released(local),
                ]);
                local += 1;
                next = 2;
            }
            Kind::HandshakeFailure if server => {
                // Failed handshake output or input must leave the server reader
                // available for the next reset.
                if value & 1 == 0 {
                    steps.extend([
                        Step::Fault(outgoing, Operation::Write, io::ErrorKind::BrokenPipe),
                        Step::FailedReconnect,
                    ]);
                } else {
                    steps.push(Step::HandshakeReadTimeout);
                }
                steps.extend([
                    Step::Reconnect(local + 1),
                    Step::Close(local),
                    Step::Refused(local),
                    Step::Drop(local),
                    Step::Released(local),
                ]);
                local += 1;
                next = 2;
            }
            Kind::Close | Kind::Replace | Kind::Disconnect | Kind::HandshakeFailure => {
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
        // Round trips in both directions fence prior input and output. A request
        // answer can arrive before its local flush returns; the reply's Written
        // step also drains that flush before the next action arms an I/O gate.
        for step in [
            Step::Request(local, 0, value, 3000),
            Step::Read(next, content.clone()),
            Step::Send(next, answer.clone()),
            Step::Answer(0, Ok(value.wrapping_add(1))),
            Step::Outstanding(local, vec![]),
            Step::Send(peer, content),
            Step::Receive(local, value, 0),
            Step::Reply(0, 0, Ok(value.wrapping_add(1)), 3000),
            Step::Read(peer, answer),
            Step::Written(0, Ok(())),
        ] {
            script.push(step);
        }
        next += 2;
    }
    super::run(mode, &script);
}

#[cfg(test)]
#[path = "fuzz_tests.rs"]
mod tests;
