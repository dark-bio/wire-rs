// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Regression scenarios and seed inputs for the session action runner.

use super::*;

/// Runs (kind, slot, value, budget) tuples through the fuzz entry point.
fn run_actions(actions: &[(Kind, u8, u8, u8)]) {
    let actions: Vec<_> = actions
        .iter()
        .map(|&(kind, slot, value, budget)| Action {
            kind,
            slot,
            value,
            budget,
        })
        .collect();
    run(&actions);
}

/// Notifications observe both kinds without consuming them. Repeated actions
/// are filtered before reaching the public method's double-registration panic.
#[test]
fn test_notifications() {
    use Kind::*;
    for budget in [0, 10, 255] {
        for value in [0, 1, 2, 7] {
            run_actions(&[
                (Request, 0, 10, budget),
                (Notify, 0, 0, 0),
                (Notify, 0, 0, 0),
                (Receive, 0, 20, 0),
                (Reply, 0, 30, budget),
                (Notify, 1, 0, 0),
                (Outgoing, 0, 0, 0),
                (Outgoing, 0, 0, 0),
                (Written, 0, 2, 0),
                (Answer, 0, value, 0),
                (Written, 1, value, 0),
                (Notify, 0, 0, 0),
                (Notify, 1, 0, 0),
                (Wait, 0, 0, 0),
                (Wait, 1, 0, 0),
                (Notify, 0, 0, 0),
            ]);
        }
    }
}

/// Completion before registration survives session destruction. Pending hooks
/// notify parked waiters and are suppressed when the promise is dropped instead.
#[test]
fn test_notification_lifetimes() {
    use Kind::*;
    for ending in [Expire, Close, Drop, Open, CloseServer, DropSource] {
        for observer in [Notify, Wait, DropPromise] {
            run_actions(&[
                (Request, 0, 10, 10),
                (Request, 0, 11, 10),
                (Receive, 0, 20, 0),
                (Reply, 0, 30, 10),
                (Notify, 0, 0, 0),
                (Notify, 2, 0, 0),
                (observer, 0, 0, 0),
                (observer, 2, 0, 0),
                (Advance, 0, 0, 10),
                (ending, 0, 0, 0),
                (Drop, 0, 0, 0),
                (Notify, 1, 0, 0),
                (Notify, 1, 0, 0),
            ]);
        }
    }
    run_actions(&[
        (Request, 0, 10, 100),
        (Notify, 0, 0, 0),
        (Outgoing, 0, 0, 0),
        (Answer, 0, 0, 0),
        // Receiving a token did not release the buffered response budget.
        (InboundLimits, 0, 0, 0),
        (Wait, 0, 0, 0),
    ]);
}

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
            run_actions(&steps);
        }
    }
}

#[test]
fn test_model_scripts() {
    use Kind::*;
    for ending in [Open, Close, Drop, CloseServer, DropSource] {
        for budget in [0, 1, 10, 255] {
            run_actions(&[
                (Request, 0, 10, budget),
                (Request, 0, 20, budget),
                (Outgoing, 0, 0, 0),
                (Written, 0, 2, 0),
                (Receive, 0, 30, 0),
                (Reply, 0, 40, budget),
                (Outgoing, 0, 0, 0),
                (Advance, 0, 0, budget),
                (Answer, 0, 0, 0),
                (Expire, 0, 0, 0),
                (ending, 0, 2, 0),
                (Request, 0, 50, budget),
                (Receive, 0, 60, 0),
                (Abandon, 1, 0, 0),
                (Outgoing, 0, 0, 0),
                (DropPromise, 1, 0, 0),
                (Drop, 0, 0, 0),
            ]);
        }
    }
    run_actions(&[
        (Receive, 0, 10, 0),
        (AutoreplyTimeout, 0, 0, 10),
        (Abandon, 0, 0, 0),
        (Outgoing, 0, 0, 0),
        (Written, 0, 0, 0),
        (Open, 0, 0, 0),
        (Close, 0, 0, 0),
        (Request, 0, 20, 10),
        (Drop, 0, 0, 0),
    ]);
}

/// Both promise kinds can wait before completion, including failed writes,
/// wrong response types and deadlines that have already passed.
#[test]
fn test_parked_waits() {
    use Kind::*;
    for budget in [0, 4, 200] {
        for value in [0, 1, 2, 7] {
            run_actions(&[
                (Request, 0, 10, budget),
                (Receive, 0, 20, 0),
                (Reply, 0, 30, budget),
                (Wait, 0, 0, 0),
                (Wait, 1, 0, 0),
                (Outgoing, 0, 0, 0),
                (Outgoing, 0, 0, 0),
                (Written, 0, value, 0),
                (Written, 1, value, 0),
                (Answer, 0, value, 0),
                (Wait, 0, 0, 0),
                (Wait, 1, 0, 0),
            ]);
        }
    }
}

/// Expiry and owner transitions respect the deadline of each parked wait.
/// A replacement session can complete new work before collecting old waits.
#[test]
fn test_parked_wait_endings() {
    use Kind::*;
    for ending in [Expire, Close, Drop, Open, CloseServer, DropSource] {
        for elapsed in [9, 10, 11] {
            run_actions(&[
                (Request, 0, 10, 10),
                (Receive, 0, 20, 0),
                (Reply, 0, 30, 10),
                (Wait, 0, 0, 0),
                (Wait, 1, 0, 0),
                (Advance, 0, 0, elapsed),
                (ending, 0, 2, 0),
                (Wait, 0, 0, 0),
                (Wait, 1, 0, 0),
            ]);
        }
    }
    run_actions(&[
        (Request, 0, 10, 20),
        (Outgoing, 0, 0, 0),
        (Wait, 0, 0, 0),
        (Open, 0, 0, 0),
        (Request, 1, 20, 20),
        (Wait, 1, 0, 0),
        (Outgoing, 1, 0, 0),
        (Answer, 1, 0, 0),
        (Wait, 1, 0, 0),
        (Wait, 0, 0, 0),
    ]);
}

/// Submission and completion races each start with an open session and a
/// pending operation. Closing an already settled operation cannot change it.
#[test]
fn test_raced_endings() {
    use Kind::*;
    for value in [0, 1, 2] {
        run_actions(&[(Request, 0, 10, 30), (Close, 0, value, 0)]);
    }
    run_actions(&[(Receive, 0, 10, 0), (Reply, 0, 3, 30)]);
    run_actions(&[(Request, 0, 10, 30), (Outgoing, 0, 0, 0), (Answer, 0, 7, 0)]);
    run_actions(&[
        (Receive, 0, 10, 0),
        (Reply, 0, 20, 30),
        (Outgoing, 0, 0, 0),
        (Written, 0, 7, 0),
    ]);
    for value in [0, 1, 2] {
        run_actions(&[
            (Receive, 0, 10, 0),
            (Reply, 0, 20, 30),
            (Outgoing, 0, 0, 0),
            (Written, 0, value, 0),
            (Written, 0, 7, 0),
        ]);
    }
}

/// Repeated server closure, racing attachment and owner drop all refuse new work.
#[test]
fn test_server_endings() {
    use Kind::*;
    for value in [1, 2, 3] {
        run_actions(&[
            (Request, 0, 10, 30),
            (Outgoing, 0, 0, 0),
            (Close, 0, 2, 0),
            (CloseServer, 0, value, 0),
            (Open, 0, 0, 0),
            (Request, 0, 20, 30),
        ]);
    }
}

/// Parks acceptance so a later attach, closure or dropped source ends it,
/// and refuses work on sessions that have already closed.
#[test]
fn test_parked_acceptance() {
    use Kind::*;
    for ending in [Open, CloseServer, DropSource] {
        for value in [0, 2, 3] {
            run_actions(&[
                (Open, 0, 0, 2),
                (Receive, 0, 10, 0),
                (Request, 0, 20, 30),
                (ending, 0, value, 0),
                (Receive, 0, 30, 1),
                (Request, 0, 40, 30),
                (Reply, 0, 50, 30),
            ]);
        }
    }
    // Close the old session first so attachment can race server closure without
    // changing the reason observed by any of its promises.
    run_actions(&[(Close, 0, 2, 0), (Open, 0, 0, 2), (CloseServer, 0, 2, 0)]);
}

/// Drops several responders at once so their automatic replies leave the
/// queue together, with and without a configured budget.
#[test]
fn test_batched_abandonment() {
    use Kind::*;
    for timeout in [None, Some(0), Some(1), Some(60)] {
        let mut actions = vec![
            (Receive, 0, 10, 0),
            (Receive, 0, 20, 0),
            (Receive, 0, 30, 0),
        ];
        if let Some(timeout) = timeout {
            actions.push((AutoreplyTimeout, 0, 0, timeout));
        }
        actions.extend([
            (Abandon, 2, 0, 0),
            (Abandon, 0, 0, 0),
            (Abandon, 1, 0, 0),
            (Outgoing, 0, 1, 0),
            (Outgoing, 0, 1, 0),
        ]);
        run_actions(&actions);
    }
}

/// Exercise both ceilings around exact usage, including queued request batches.
#[test]
fn test_inbound_request_limits() {
    use Kind::*;
    for requests in [0, 1, 2, 4] {
        for bytes in [0, 4, 5, 7, 14, 255] {
            run_actions(&[
                (InboundLimits, 0, requests, bytes),
                (IncomingBatch, 0, 10, 1),
                (Reply, 0, 20, 10),
                (Abandon, 1, 0, 0),
                (Outgoing, 0, 0, 0),
                (Receive, 0, 30, 1),
                (Advance, 0, 0, 10),
                (Expire, 0, 0, 0),
                (InboundLimits, 0, 0, 0),
                (Open, 0, 0, 0),
                (Receive, 1, 40, 0),
            ]);
        }
    }
}

/// Completed responses keep bytes until observation or drop, even after closure.
#[test]
fn test_inbound_response_limits() {
    use Kind::*;
    for result in 0..3 {
        let bytes = answer_size(match result {
            0 => Ok(0),
            1 => Err(Failure::Remote(257)),
            _ => Err(Failure::WrongType),
        }) as u8;
        for observer in [Wait, DropPromise, Advance] {
            run_actions(&[
                (InboundLimits, 0, 4, bytes),
                (Request, 0, 10, 20),
                (Outgoing, 0, 0, 0),
                (Answer, 0, result, 0),
                (InboundLimits, 0, 0, bytes),
                (observer, 0, 0, 0),
                (Request, 0, 20, 20),
                (Outgoing, 0, 0, 0),
                (Answer, 1, result, 0),
                (InboundLimits, 0, 4, bytes - 1),
                (Open, 0, 0, 0),
                (Drop, 0, 0, 0),
                (Wait, 0, 0, 0),
                (Wait, 1, 0, 0),
                (Receive, 1, 30, 0),
            ]);
        }
        for observer in [Wait, DropPromise] {
            run_actions(&[
                (InboundLimits, 0, 0, bytes),
                (Request, 0, 10, 20),
                (Outgoing, 0, 0, 0),
                (observer, 0, 0, 0),
                (Answer, 0, result, 0),
                (InboundLimits, 0, 1, 0),
                (Request, 0, 20, 1),
                (Outgoing, 0, 0, 0),
                (Advance, 0, 0, 1),
                (Answer, 1, result, 0),
                (Wait, 1, 0, 0),
            ]);
        }
    }
}
