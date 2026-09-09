// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Regression scenarios and seed inputs for the connection action runner.

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
