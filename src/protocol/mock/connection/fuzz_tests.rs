// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Regression scenarios and seed inputs for the connection action runner.

use super::*;

#[test]
fn test_connection_fuzz_repeated_handshake_timeouts() {
    // CI crash-448f502ce99548911982fe206e1b63f888716b00: a new flush gate must
    // not catch the preceding action's output while injecting an ACK timeout.
    let mut actions = vec![Action {
        kind: Kind::ResponseBeforeFailure,
        slot: 0,
        value: 0,
        budget: 173,
    }];
    actions.extend(
        [
            (255, 255, 173),
            (255, 255, 255),
            (173, 173, 173),
            (0, 33, 173),
            (173, 173, 173),
            (173, 173, 173),
        ]
        .map(|(slot, value, budget)| Action {
            kind: Kind::HandshakeFailure,
            slot,
            value,
            budget,
        }),
    );
    run(&actions);
}

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
            [
                HandshakeFailure,
                Incoming,
                Disconnect,
                Pipeline,
                Duplicate,
                Incoming,
                Exhaust,
                Pipeline,
            ],
            [
                QueuedTimeout,
                ReplyRefusal,
                Incoming,
                ResponseBeforeFailure,
                Pipeline,
                ReplyRefusal,
                QueuedTimeout,
                Pipeline,
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
            Exhaust,
            Replace,
            Disconnect,
            HandshakeFailure,
            Close,
            Fault,
            ReplyRefusal,
            QueuedTimeout,
            ResponseBeforeFailure,
            InboundFailure,
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

/// Seed every deferred decoding path and both limits in each live role.
#[test]
fn test_connection_fuzz_inbound_limits() {
    for slot in 0..2 {
        for kind in [Kind::InboundFailure, Kind::Malformed] {
            for value in 0..8 {
                run(&[
                    Action {
                        kind,
                        slot,
                        value,
                        budget: value,
                    },
                    Action {
                        kind: Kind::Pipeline,
                        slot,
                        value: 42,
                        budget: 1,
                    },
                ]);
            }
        }
    }
}

/// Limit and decode failures must settle queued work even with no writer progress.
#[test]
fn test_inbound_failure_during_blocked_output() {
    for slot in 0..4 {
        for value in 0..3 {
            run(&[
                Action {
                    kind: Kind::InboundFailure,
                    slot,
                    value,
                    budget: 128,
                },
                Action {
                    kind: Kind::Pipeline,
                    slot,
                    value: 42,
                    budget: 0,
                },
            ]);
        }
    }
}
