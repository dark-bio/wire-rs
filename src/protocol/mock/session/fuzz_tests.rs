// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Regression scenarios and seed inputs for the session action runner.

use super::*;

/// Runs `(kind, slot, value, budget)` tuples through [`run`] as one action list.
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

/// Notifications observe both promise kinds without consuming them, and the
/// model never registers twice on one promise.
#[test]
fn test_notifications() {
    use Kind::*;
    for budget in [0, 10, 255] {
        for value in [0, 1, 2, 7] {
            run_actions(&[
                // Register on a request, twice, and on a reply
                (Request, 0, 10, budget),
                (Notify, 0, 0, 0),
                (Notify, 0, 0, 0),
                (Receive, 0, 20, 0),
                (Reply, 0, 30, budget),
                (Notify, 1, 0, 0),
                // Take both for writing, then report writes and an answer
                (Outgoing, 0, 0, 0),
                (Outgoing, 0, 0, 0),
                (Written, 0, 2, 0),
                (Answer, 0, value, 0),
                (Written, 1, value, 0),
                // Register again around waiting on both
                (Notify, 0, 0, 0),
                (Notify, 1, 0, 0),
                (Wait, 0, 0, 0),
                (Wait, 1, 0, 0),
                (Notify, 0, 0, 0),
            ]);
        }
    }
}

/// Registrations notify settled and parked promises, even after the session is
/// gone, but never dropped ones.
#[test]
fn test_notification_lifetimes() {
    use Kind::*;

    // Register on a request and a reply and observe them, then end everything
    // and register on the request left alone
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

    // A notified answer keeps its bytes until read
    run_actions(&[
        (Request, 0, 10, 100),
        (Notify, 0, 0, 0),
        (Outgoing, 0, 0, 0),
        (Answer, 0, 0, 0),
        // The answer stays charged despite its token, so a zero byte limit
        // closes the session
        (InboundLimits, 0, 0, 0),
        (Wait, 0, 0, 0),
    ]);
}

/// Write results and answers settle each operation once, whether they arrive
/// before, at or after its deadline.
#[test]
fn test_completion_orderings() {
    use Kind::*;
    // Vary completion results around the original deadline
    for time in [9, 10, 11] {
        for result in 0..3 {
            let steps = [
                // Take two requests and a reply for writing
                (Request, 0, 10, 10),
                (Request, 0, 20, 20),
                (Outgoing, 0, 0, 0),
                (Outgoing, 0, 0, 0),
                (Receive, 0, 30, 1),
                (Reply, 0, 40, 10),
                (Outgoing, 0, 0, 0),
                // Report results around the first deadline, some of them twice
                (Written, 1, 2, 0),
                (Written, 1, 2, 0),
                (Advance, 0, 0, time),
                (Written, 2, 2, 0),
                (Answer, 1, result, 0),
                (Answer, 0, result, 0),
                // Replace the session and settle new work beside the old results
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

/// Model scripts settle pending work across expiry and every owner transition.
#[test]
fn test_model_scripts() {
    use Kind::*;
    // Exercise each ending with expired and future deadlines
    for ending in [Open, Close, Drop, CloseServer, DropSource] {
        for budget in [0, 1, 10, 255] {
            run_actions(&[
                // Put two requests and a reply in flight
                (Request, 0, 10, budget),
                (Request, 0, 20, budget),
                (Outgoing, 0, 0, 0),
                (Written, 0, 2, 0),
                (Receive, 0, 30, 0),
                (Reply, 0, 40, budget),
                (Outgoing, 0, 0, 0),
                // Reach the deadline, answer and expire
                (Advance, 0, 0, budget),
                (Answer, 0, 0, 0),
                (Expire, 0, 0, 0),
                // End the session, then act on whatever remains
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

    // Fail an automatic reply's write, then act on the session after replacing it
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
                // Park waits on a request and a reply before either is written
                (Request, 0, 10, budget),
                (Receive, 0, 20, 0),
                (Reply, 0, 30, budget),
                (Wait, 0, 0, 0),
                (Wait, 1, 0, 0),
                // Take both for writing and report their results, then wait again
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

/// Parked waits settle with `Timeout` from their deadline on, whichever expiry or
/// ending reaches them.
#[test]
fn test_parked_wait_endings() {
    use Kind::*;

    // Park waits on a request and a reply, then end them around the deadline
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

    // A replacement ends the old parked wait with a reset, and new work then
    // settles on the successor
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

/// Closure raced against a request, reply, answer or write result settles each
/// operation once.
#[test]
fn test_raced_endings() {
    use Kind::*;

    // Close in each racing way right after a request
    for value in [0, 1, 2] {
        run_actions(&[(Request, 0, 10, 30), (Close, 0, value, 0)]);
    }

    // Race a reply, an answer and a write result against closure
    run_actions(&[(Receive, 0, 10, 0), (Reply, 0, 3, 30)]);
    run_actions(&[(Request, 0, 10, 30), (Outgoing, 0, 0, 0), (Answer, 0, 7, 0)]);
    run_actions(&[
        (Receive, 0, 10, 0),
        (Reply, 0, 20, 30),
        (Outgoing, 0, 0, 0),
        (Written, 0, 7, 0),
    ]);

    // A settled reply is not raced, so a later write result changes nothing
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

/// A parked acceptance ends with a later attach, server closure or dropped
/// source, after which closed sessions refuse work.
#[test]
fn test_parked_acceptance() {
    use Kind::*;

    // Park an acceptance beside open work, end it in each way, then act on the
    // closed session
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
    // changing the reason observed by any of its promises
    run_actions(&[(Close, 0, 2, 0), (Open, 0, 0, 2), (CloseServer, 0, 2, 0)]);
}

/// Automatic replies from several dropped responders leave the queue together,
/// with and without a configured budget.
#[test]
fn test_batched_abandonment() {
    use Kind::*;
    for timeout in [None, Some(0), Some(1), Some(60)] {
        // Hold three responders, optionally changing the automatic reply
        // timeout
        let mut actions = vec![
            (Receive, 0, 10, 0),
            (Receive, 0, 20, 0),
            (Receive, 0, 30, 0),
        ];
        if let Some(timeout) = timeout {
            actions.push((AutoreplyTimeout, 0, 0, timeout));
        }

        // Drop them out of order and drain their replies in one step
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

/// Both inbound limits hold around exact usage, queued request batches included.
#[test]
fn test_inbound_request_limits() {
    use Kind::*;

    // Sweep both limits around a batch of two requests, then lower them to zero
    // and replace the session
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
        // Size the byte limit to one answer of this kind
        let bytes = answer_size(match result {
            0 => Ok(0),
            1 => Err(Failure::Remote(257)),
            _ => Err(Failure::WrongType),
        }) as u8;

        // Read, drop or keep the first answer before a second one arrives
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

        // Wait on or drop a promise before its answer arrives, then answer
        // another request late
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
