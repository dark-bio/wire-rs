// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Composable exchanges and lifecycle transitions over live encrypted streams.
//!
//! Each action leaves a usable connection or proves its closure. A server then
//! reconnects, while a client run ends there. I/O gates establish the ordering,
//! and the native scheduler supplies the worker interleavings.

use super::{EnvelopeShape, Failure, Mode, Step};
use crate::transport::mock::duplex::Operation;
use std::io;

/// One fuzz action, selecting a scenario and varying its batch size, ordering,
/// IDs and payloads.
///
/// An even slot on the first action exercises a protocol server, an odd one a
/// protocol client. An input runs at most eight actions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct Action {
    /// Exchange or lifecycle transition to execute.
    pub kind: Kind,
    /// Selector of the peer request IDs, ordering and I/O phase, and of the
    /// protocol role on the first action.
    pub slot: u8,
    /// Payload tag, error code, or selector of the failure an action injects.
    pub value: u8,
    /// Batch size, deadline extension in milliseconds, peer request ID or
    /// variant of a failure scenario.
    pub budget: u8,
}

/// Scenario that one fuzz action runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum Kind {
    /// Batch of up to eight local requests, answered out of order among unknown
    /// and repeated responses.
    Pipeline,
    /// Batch of up to eight peer requests, answered in reverse order by replies
    /// or abandoned responders.
    Incoming,
    /// Local request refused for its wrong direction or its size.
    Refusal,
    /// Local reply refused for its wrong direction or its size, which frees the
    /// peer's request ID.
    ReplyRefusal,

    /// Response that completes a request while its flush is still blocked.
    ResponseDuringFlush,
    /// Request that times out in a blocked write or flush, yet still reaches the
    /// peer.
    RequestTimeout,
    /// Reply that times out in a blocked flush, yet still reaches the peer.
    ReplyTimeout,
    /// Request and reply that expire while queued behind a blocked write, the
    /// request before taking a wire ID and the reply freeing its peer's.
    QueuedTimeout,
    /// Answer received during its request's flush, kept when that flush fails.
    ResponseBeforeFailure,
    /// Peer request ID reused before the reply's flush returns, optionally
    /// followed by a duplicate that closes the session.
    ReuseDuringFlush,

    /// Duplicate of an active peer request ID, which closes the session.
    Duplicate,
    /// Invalid envelope or payload from the peer, which closes the session.
    Malformed,
    /// Inbound limit or deferred decode failure, optionally with blocked output.
    InboundFailure,
    /// Request that takes the last allocatable ID, followed by a local close.
    Exhaust,

    /// Server session replaced while it holds an unanswered request and a
    /// responder.
    ///
    /// A client closes its session instead.
    Replace,
    /// Delayed disconnect of a closed server session, released only after a
    /// replacement connects.
    ///
    /// A client closes its session instead.
    Disconnect,
    /// Failed server handshake, from an output fault or a read timeout, before a
    /// successful one.
    ///
    /// A client closes its session instead.
    HandshakeFailure,
    /// Local close while a receive waits.
    Close,
    /// Failed output write or flush while a receive waits, closing the session.
    Fault,
}

/// Maximum actions run from one input, each driving several live exchanges.
const ACTIONS: usize = 8;

/// Checks whether an action ends the client session.
///
/// A client stream cannot reconnect, so the runner moves the first such action
/// last and skips the others.
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

/// Runs arbitrary live connection actions and waits for every protocol worker
/// to exit.
///
/// With the `fuzz` feature and `WIRE_SEEDS` set, the actions are also saved as
/// a seed.
///
/// # Panics
///
/// Panics if the protocol peer does not produce a result the runner predicts.
pub fn run(actions: &[Action]) {
    // Record the input and let the first action's slot pick the protocol role
    #[cfg(feature = "fuzz")]
    super::super::seed::seed(super::super::seed::CONNECTION_TARGET, actions);
    let server = actions.first().is_none_or(|action| action.slot & 1 == 0);
    let mode = if server { Mode::Server } else { Mode::Client };

    // Run a client's ending action last, so the actions behind it still execute
    // instead of being discarded along with its connection
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

    // Track the local session label, its next request ID and its output pipe
    let mut script = Vec::new();
    let mut local = u8::from(server);
    let mut next = if server { 2 } else { 1 };
    let outgoing = u8::from(server);
    for (index, action) in ordered.iter().enumerate() {
        // Unpack the action and start collecting its steps
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

        // Turn the action into steps with predicted results
        match kind {
            Kind::Pipeline => {
                // Queue the batch with notifications and read every request
                let count = budget % 8 + 1;
                for id in 0..count {
                    steps.push(Step::Request(local, id, value.wrapping_add(id), 3000));
                    steps.push(Step::Notify(id, id));
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
                        Step::Notified(id),
                        Step::Answer(id, result),
                        Step::Send(wire, content.clone()),
                    ]);
                }
                next += u64::from(count) * 2;
            }
            Kind::Incoming => {
                // Send the batch of peer requests and receive them all
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

                // Answer in reverse, abandoning some responders and replying
                // through the others
                for id in (0..count).rev() {
                    let wire = peer.wrapping_add(u64::from(id) * 2);
                    if id.wrapping_add(slot) & 1 == 0 {
                        steps
                            .extend([Step::Abandon(id), Step::Read(wire, EnvelopeShape::Error(1))]);
                    } else {
                        steps.extend([
                            Step::Reply(id, id, Ok(value), 3000),
                            Step::NotifyWrite(id, id),
                            Step::Read(wire, content.clone()),
                            Step::Notified(id),
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
                    Step::Notify(0, 0),
                    Step::Notified(0),
                    Step::Answer(
                        0,
                        Err(if value & 1 == 0 {
                            Failure::Direction
                        } else {
                            Failure::Large
                        }),
                    ),
                ]);
                // The refused request still takes up a local ID
                next += 2;
            }
            Kind::ReplyRefusal => {
                // Refusing a reply must not queue UNANSWERED or retain the peer ID
                steps.extend([
                    Step::Send(peer, content.clone()),
                    Step::Receive(local, value, 0),
                    if value & 1 == 0 {
                        Step::WrongDirectionReply(local, 0, 0)
                    } else {
                        Step::OversizedReply(0, 0)
                    },
                    Step::NotifyWrite(0, 0),
                    Step::Notified(0),
                    Step::Written(
                        0,
                        Err(if value & 1 == 0 {
                            Failure::Direction
                        } else {
                            Failure::Large
                        }),
                    ),
                    // Reuse the peer ID, whose reply must be the next message read
                    Step::Send(peer, answer.clone()),
                    Step::Receive(local, value.wrapping_add(1), 1),
                    Step::Reply(1, 1, Ok(value), 3000),
                    Step::Read(peer, content.clone()),
                    Step::Written(1, Ok(())),
                ]);
            }
            Kind::ResponseDuringFlush | Kind::RequestTimeout => {
                // Block the request's flush, or for some timeouts its write
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
                    Step::Notify(0, 0),
                ]);

                // For a timeout, expire the request before letting it through
                if timeout {
                    steps.extend([
                        Step::Advance(50 + u64::from(budget % 10)),
                        Step::Notified(0),
                        Step::Answer(0, Err(Failure::Timeout)),
                        Step::Pause(outgoing, op, false),
                    ]);
                }

                // Deliver the request and answer it, late if it expired
                steps.extend([
                    Step::Read(next, content.clone()),
                    Step::Send(next, answer.clone()),
                ]);

                // Complete any other request while its flush still blocks
                if !timeout {
                    steps.extend([
                        Step::Notified(0),
                        Step::Answer(0, Ok(value.wrapping_add(1))),
                        Step::Pause(outgoing, op, false),
                    ]);
                }
                next += 2;
            }
            Kind::ReplyTimeout => {
                steps.extend([
                    // Receive a peer request and block its reply's flush
                    Step::Send(peer, content.clone()),
                    Step::Receive(local, value, 0),
                    Step::Pause(outgoing, Operation::Flush, true),
                    Step::Reply(0, 0, Ok(value.wrapping_add(1)), 50 + u64::from(budget % 10)),
                    Step::Blocked(outgoing, Operation::Flush),
                    // Expire the reply, which still reaches the peer
                    Step::NotifyWrite(0, 0),
                    Step::Advance(50 + u64::from(budget % 10)),
                    Step::Notified(0),
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
                    // Queue a request and a reply behind a blocked write
                    Step::Pause(outgoing, Operation::Write, true),
                    Step::Request(local, 0, value, 3000),
                    Step::Blocked(outgoing, Operation::Write),
                    Step::Request(local, 1, value.wrapping_add(1), timeout),
                    Step::Send(peer, content.clone()),
                    Step::Receive(local, value, 0),
                    Step::Reply(0, 0, Ok(value), timeout),
                    // Expire both while they wait
                    Step::Advance(timeout),
                    Step::Answer(1, Err(Failure::Timeout)),
                    Step::Written(0, Err(Failure::Timeout)),
                    // Reuse the peer ID, then release the write
                    Step::Send(peer, answer.clone()),
                    Step::Receive(local, value.wrapping_add(1), 1),
                    Step::Reply(1, 1, Ok(value), 3000),
                    Step::Pause(outgoing, Operation::Write, false),
                    // Require only the live request and reply to reach the peer
                    Step::Read(next, content.clone()),
                    Step::Send(next, answer.clone()),
                    Step::Answer(0, Ok(value.wrapping_add(1))),
                    Step::Read(peer, content.clone()),
                    Step::Written(1, Ok(())),
                ]);
                next += 2;
            }
            Kind::ResponseBeforeFailure => {
                // Answer with a body or an error, by the value's parity
                let (body, result) = if value & 1 == 0 {
                    (answer.clone(), Ok(value.wrapping_add(1)))
                } else {
                    (
                        EnvelopeShape::Error(u64::from(value)),
                        Err(Failure::Remote(u64::from(value))),
                    )
                };
                steps.extend([
                    // Answer the request while its flush is blocked
                    Step::Pause(outgoing, Operation::Flush, true),
                    Step::Request(local, 0, value, 3000),
                    Step::Blocked(outgoing, Operation::Flush),
                    Step::Read(next, content.clone()),
                    Step::Send(next, body),
                    // This receive fences the answer while leaving its result
                    // buffered until after the write closes the session
                    Step::Send(peer, content.clone()),
                    Step::Receive(local, value, 0),
                    Step::Outstanding(local, vec![]),
                    // Queue more work, then fail the flush while a receive waits
                    Step::Request(local, 1, value, 3000),
                    Step::Reply(0, 0, Ok(value), 3000),
                    Step::StartReceive(local),
                    Step::Fault(outgoing, Operation::Flush, io::ErrorKind::BrokenPipe),
                    Step::Pause(outgoing, Operation::Flush, false),
                    // The buffered answer survives while the queued work fails
                    Step::ReceiveFailed(local, Failure::Transport),
                    Step::Answer(0, result),
                    Step::Answer(1, Err(Failure::Transport)),
                    Step::Written(0, Err(Failure::Transport)),
                ]);
                ended = true;
            }
            Kind::ReuseDuringFlush => {
                // Let the peer reuse its request ID while the reply's flush blocks
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

                // Abandon the new request, or send a duplicate ending the session
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
                // Leave the first request queued, held by a responder, or
                // answered behind a blocked write
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

                // Send its duplicate, which fails a waiting local request
                steps.extend([
                    Step::Request(local, 0, value, 3000),
                    Step::Reject(peer, content.clone()),
                    Step::Answer(0, Err(Failure::Malformed)),
                ]);

                // Require the blocked work to fail too, or drop the held responder
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
                    // Fail the receive that decodes a malformed request body
                    5 => steps.extend([
                        Step::Send(peer, EnvelopeShape::MalformedBody),
                        Step::ReceiveError(local, Failure::Malformed),
                    ]),
                    // Fail the wait that decodes a malformed response body or error
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
                    // Refuse an invalid request or response envelope on arrival
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
                    // Hold as many peer requests as the request limit admits, then
                    // exceed it
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
                    // Admit no retained bytes, so the next peer request exceeds
                    // the byte limit
                    1 => steps.extend([
                        Step::InboundLimits(local, DEFAULT_MAX_INBOUND_REQUESTS, 0),
                        Step::Request(local, 0, value, 3000),
                        Step::Read(next, content.clone()),
                        Step::StartReceive(local),
                        Step::Reject(peer, content.clone()),
                        Step::ReceiveFailed(local, Failure::Bytes),
                        Step::Answer(0, Err(Failure::Bytes)),
                    ]),
                    // Fill the byte limit with one unread response, then exceed it
                    // with the next
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
                // One allocatable ID is left; taking another would abort the writer
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
                // Retain an unanswered request and a responder across replacement
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
                // that replaced it connected
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
                // available for the next reset
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

        // Prove that an ended session refuses work and frees its state, then
        // reconnect a server under the next label
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

        // A client's stream cannot reconnect, so its run stops at an ending action
        script.extend(steps);
        if ended && !server {
            break;
        }

        // Round trips in both directions fence prior input and output. A request
        // answer can arrive before its local flush returns; the reply's `Written`
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

    // Run the whole script on one driver, which waits for every worker to exit
    super::run(mode, &script);
}

#[cfg(test)]
#[path = "fuzz_tests.rs"]
mod tests;
