// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Session lifecycle regressions expressed through the shared scenario runner.

use super::{Failure, Step, run};

/// Closure discards queued work, refuses later operations and remains repeatable.
#[test]
fn test_session_retirement() {
    use Failure::*;
    use Step::*;
    run(vec![
        Open(1),
        Accept(1),
        Deliver(1, 7, 11),
        CloseSession(1),
        ReceiveError(1, Closed),
        RefuseDelivery(1, Closed),
        RefuseRequest(1, Closed),
        CloseSession(1),
        ReceiveError(1, Closed),
        DropSession(1),
        Released(1),
        RefuseRequest(1, Closed),
        CloseSession(1),
        Open(2),
        Accept(2),
        StartReceive(2),
        RaceCloses(2),
        FinishReceiveError(2, Closed),
    ]);
}

/// Every ending path wakes an already-waiting receiver; delivery also wakes it.
#[test]
fn test_receiver_wakeups() {
    use Failure::*;
    use Step::*;
    for ending in [
        CloseSession(1),
        CloseServer,
        RaceServerCloses,
        DropServer,
        DropPublisher,
    ] {
        let expected = if matches!(ending, DropPublisher) {
            Terminated
        } else {
            Closed
        };
        run(vec![
            Open(1),
            Accept(1),
            StartReceive(1),
            ending,
            FinishReceiveError(1, expected),
        ]);
    }
    run(vec![
        Open(1),
        Accept(1),
        StartReceive(1),
        Deliver(1, 9, 17),
        FinishReceive(1, 17, 0),
        DropReply(0),
        Abandoned(1, vec![9]),
        Abandoned(1, vec![]),
    ]);
}

/// Old handles cannot reach a successor, including when both sessions reuse an ID.
#[test]
fn test_replacement_keeps_old_handles_bound() {
    use Failure::*;
    use Step::*;
    run(vec![
        Open(1),
        Accept(1),
        Deliver(1, 7, 11),
        Receive(1, 11, 0),
        Deliver(1, 8, 12),
        Receive(1, 12, 1),
        StartReceive(1),
        Open(2),
        FinishReceiveError(1, Reset),
        Accept(2),
        RefuseRequest(1, Reset),
        RefuseReply(0, Reset),
        DropReply(1),
        CloseSession(1),
        ReceiveError(1, Reset),
        RefuseDelivery(1, Reset),
        Abandoned(2, vec![]),
        Deliver(2, 7, 22),
        Receive(2, 22, 2),
        DropSession(1),
        Released(1),
        CloseSession(1),
        RefuseRequest(1, Closed),
        DropReply(2),
        Abandoned(2, vec![7]),
        Deliver(2, 8, 23),
        Receive(2, 23, 3),
        DropReply(3),
        Abandoned(2, vec![8]),
    ]);
}

/// Capabilities retain neither owner and cannot keep a dropped session operational.
#[test]
fn test_owner_drop_with_retained_handles() {
    use Failure::*;
    use Step::*;
    run(vec![
        Open(1),
        Accept(1),
        Deliver(1, 1, 11),
        Receive(1, 11, 0),
        DropSession(1),
        Released(1),
        RefuseRequest(1, Closed),
        RefuseReply(0, Closed),
        CloseSession(1),
        Open(2),
        Accept(2),
        StartReceive(2),
        DropServer,
        FinishReceiveError(2, Closed),
        RefuseOpen(Closed),
        CloseServer,
        DropSession(2),
        Released(2),
    ]);
}

/// Acceptance wakes for publication and retirement; only the newest pending owner stays.
#[test]
fn test_acceptance_and_endpoint_retirement() {
    use Failure::*;
    use Step::*;
    run(vec![
        StartAccept,
        Open(1),
        FinishAccept(1),
        CloseSession(1),
        StartAccept,
        Open(2),
        FinishAccept(2),
        CloseServer,
        RefuseRequest(2, Closed),
        RefuseOpen(Closed),
    ]);
    run(vec![
        StartAccept,
        RaceServerCloses,
        FinishAcceptError(Closed),
        CloseServer,
        RefuseOpen(Closed),
    ]);
    run(vec![
        StartAccept,
        DropPublisher,
        FinishAcceptError(Terminated),
        CloseServer,
    ]);
    run(vec![
        Open(1),
        Open(2),
        Released(1),
        Open(3),
        Released(2),
        Accept(3),
        DropSession(3),
        Released(3),
        Open(4),
        CloseServer,
        Released(4),
        RefuseOpen(Closed),
    ]);
}

/// Concurrent publication cannot leave a usable session behind endpoint closure.
#[test]
fn test_publication_races_endpoint_close() {
    use Failure::*;
    use Step::*;
    run(vec![
        StartAccept,
        RaceServerCloseOpen,
        FinishAcceptClosed,
        RefuseOpen(Closed),
    ]);
    run(vec![
        Open(1),
        RaceServerCloseOpen,
        Released(1),
        RefuseOpen(Closed),
    ]);
}
