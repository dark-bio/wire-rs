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

/// Requesters, responders and closers do not keep a dropped session or server alive.
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

/// `accept()` wakes when a session is attached or the server closes. If several
/// sessions connect before acceptance, only the newest one remains available.
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

/// Attaching a session concurrently with server closure leaves that session closed.
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

/// Request promises complete on peer answers and reply promises on local flush.
/// `wait()` checks the requested response type. Completed promises keep their
/// results after closing or dropping the session.
#[test]
fn test_operation_results() {
    use super::Sent;
    use Failure::*;
    use Step::*;
    run(vec![
        Open(1),
        Accept(1),
        Request(1, 0, 10, 100),
        Request(1, 1, 11, 100),
        Request(1, 2, 12, 100),
        Output(1, 0, Sent::Request(10), 100),
        Output(1, 1, Sent::Request(11), 100),
        Output(1, 2, Sent::Request(12), 100),
        StartWait(0),
        Written(0, Ok(())),
        Deadline(1, Some(100)),
        Answer(1, Err(0x123)),
        Answer(0, Ok(20)),
        FinishWait(0, Ok(20)),
        AnswerOther(2),
        Request(1, 3, 13, 100),
        Output(1, 3, Sent::Request(13), 100),
        Answer(3, Ok(23)),
        Deliver(1, 7, 30),
        Receive(1, 30, 0),
        Reply(0, 0, Ok(40), 100),
        Output(1, 4, Sent::Reply(7, Ok(40)), 100),
        StartWaitWrite(0),
        Written(4, Ok(())),
        Written(4, Err(Terminated)),
        Deadline(1, None),
        CloseSession(1),
        DropSession(1),
        Released(1),
        Wait(1, Err(Remote(0x123))),
        Wait(2, Err(WrongType)),
        WaitMessage(3, 23),
        FinishWaitWrite(0, Ok(())),
    ]);
}

/// A result accepted before the deadline survives a later `wait()`. Results at or
/// after the deadline produce `Timeout`, even before the timer processes expiry.
#[test]
fn test_completion_deadline_boundary() {
    use super::Sent;
    use Failure::*;
    use Step::*;
    for time in [99, 100, 101] {
        let answer = if time < 100 { Ok(20) } else { Err(Timeout) };
        let written = if time < 100 { Ok(()) } else { Err(Timeout) };
        run(vec![
            Open(1),
            Accept(1),
            Request(1, 0, 10, 100),
            Output(1, 0, Sent::Request(10), 100),
            Deliver(1, 7, 30),
            Receive(1, 30, 0),
            Reply(0, 0, Ok(40), 100),
            Output(1, 1, Sent::Reply(7, Ok(40)), 100),
            Time(time),
            Answer(0, Ok(20)),
            Written(1, Ok(())),
            Time(200),
            Expire(1),
            CloseSession(1),
            Wait(0, answer),
            WaitWrite(0, written),
        ]);
    }
    // A late failure cannot replace timeout either, regardless of its cause.
    run(vec![
        Open(1),
        Accept(1),
        Request(1, 0, 10, 100),
        Output(1, 0, Sent::Request(10), 100),
        Time(100),
        Written(0, Err(Terminated)),
        Answer(0, Ok(20)),
        Wait(0, Err(Timeout)),
    ]);
}

/// Expiry works without a waiting caller and while a write result is withheld.
/// Expired queued messages are discarded; new requests can still use the session.
#[test]
fn test_deadlines_without_output_progress() {
    use super::Sent;
    use Failure::*;
    use Step::*;
    run(vec![
        Open(1),
        Accept(1),
        Request(1, 0, 10, 100),
        Request(1, 1, 11, 100),
        Request(1, 2, 12, 200),
        Output(1, 0, Sent::Request(10), 100),
        Deliver(1, 7, 30),
        Receive(1, 30, 0),
        Reply(0, 0, Ok(40), 100),
        StartWait(0),
        StartWaitWrite(0),
        Deadline(1, Some(100)),
        Time(100),
        Expire(1),
        Deadline(1, Some(200)),
        FinishWait(0, Err(Timeout)),
        FinishWaitWrite(0, Err(Timeout)),
        Output(1, 1, Sent::Request(12), 200),
        NoOutput(1),
        Answer(0, Ok(20)),
        Answer(1, Ok(22)),
        Wait(1, Err(Timeout)),
        Wait(2, Ok(22)),
        Deadline(1, None),
        // Already-expired submission still returns a promise, without queueing.
        Request(1, 3, 13, 100),
        Wait(3, Err(Timeout)),
        NoOutput(1),
        Deliver(1, 8, 31),
        Receive(1, 31, 1),
        Reply(1, 1, Ok(41), 99),
        WaitWrite(1, Err(Timeout)),
        NoOutput(1),
    ]);
    // Taking a queued message checks its deadline even before expire() runs.
    run(vec![
        Open(1),
        Accept(1),
        Request(1, 0, 10, 100),
        Time(100),
        NoOutput(1),
        Wait(0, Err(Timeout)),
        Deadline(1, None),
    ]);
    // Calling wait() after expiry still uses the original deadline.
    run(vec![
        Open(1),
        Accept(1),
        Request(1, 0, 10, 100),
        Time(100),
        Wait(0, Err(Timeout)),
        NoOutput(1),
        Deadline(1, None),
    ]);
}

/// Closing fails every pending promise. Closure before its deadline produces
/// `Closed`; closure at or after its deadline produces `Timeout`.
#[test]
fn test_retirement_settles_operations() {
    use super::Sent;
    use Failure::*;
    use Step::*;
    for time in [99, 100, 101] {
        for ending in [
            CloseSession(1),
            DropSession(1),
            CloseServer,
            DropServer,
            DropPublisher,
            RaceCloses(1),
        ] {
            let reason = if time >= 100 {
                Timeout
            } else if matches!(ending, DropPublisher) {
                Terminated
            } else {
                Closed
            };
            run(vec![
                Open(1),
                Accept(1),
                Request(1, 0, 10, 100),
                Request(1, 1, 11, 100),
                Output(1, 0, Sent::Request(10), 100),
                Deliver(1, 7, 30),
                Receive(1, 30, 0),
                Reply(0, 0, Ok(40), 100),
                StartWait(0),
                StartWaitWrite(0),
                Time(time),
                ending,
                Time(200),
                Written(0, Err(Terminated)),
                Answer(0, Ok(20)),
                FinishWait(0, Err(reason)),
                Wait(1, Err(reason)),
                FinishWaitWrite(0, Err(reason)),
            ]);
        }
    }
}

/// Dropping a promise leaves its request or reply queued. Write results and answers
/// can still arrive; consuming a responder cannot enqueue a second response.
#[test]
fn test_observer_drop_keeps_operations() {
    use super::Sent;
    use Step::*;
    run(vec![
        Open(1),
        Accept(1),
        Request(1, 0, 10, 100),
        DropPromise(0),
        Output(1, 0, Sent::Request(10), 100),
        Written(0, Ok(())),
        Deadline(1, Some(100)),
        Answer(0, Ok(20)),
        Deadline(1, None),
        Request(1, 1, 11, 100),
        Output(1, 1, Sent::Request(11), 100),
        DropPromise(1),
        Answer(1, Err(0x123)),
        Deadline(1, None),
        Deliver(1, 7, 30),
        Receive(1, 30, 0),
        Reply(0, 0, Err(0x123), 100),
        DropWritePromise(0),
        Output(1, 2, Sent::Reply(7, Err(0x123)), 100),
        NoOutput(1),
        Written(2, Ok(())),
        Deadline(1, None),
        Request(1, 2, 12, 100),
        DropPromise(2),
        Time(100),
        Expire(1),
        NoOutput(1),
        Deadline(1, None),
    ]);
}

/// Abandonment uses its own configured budget starting at drop, including
/// queueing. Failed or expired automatic replies do not retry with a fresh budget.
#[test]
fn test_abandonment_timeout() {
    use super::Sent;
    use Failure::*;
    use Step::*;
    use std::time::Duration;
    run(vec![
        Open(1),
        Accept(1),
        AbandonmentTimeout(1, Duration::from_millis(30)),
        Request(1, 0, 10, 200),
        Output(1, 0, Sent::Request(10), 200), // Hold unrelated output throughout.
        Deliver(1, 7, 30),
        Receive(1, 30, 0),
        Time(20),
        DropReply(0),
        Deadline(1, Some(50)),
        Time(49),
        Output(1, 1, Sent::Reply(7, Err(1)), 50),
        Time(50),
        Written(1, Ok(())),
        Deadline(1, Some(200)),
        NoOutput(1),
        Deliver(1, 8, 31),
        Receive(1, 31, 1),
        DropReply(1),
        Output(1, 2, Sent::Reply(8, Err(1)), 80),
        Written(2, Err(Terminated)),
        NoOutput(1),
        Deadline(1, Some(200)),
        Deliver(1, 9, 32),
        Receive(1, 32, 2),
        DropReply(2),
        Time(80),
        Expire(1),
        NoOutput(1),
        Deadline(1, Some(200)),
        Answer(0, Ok(20)),
        Wait(0, Ok(20)),
        Deadline(1, None),
    ]);
    // An unrepresentable automatic deadline must not panic from Responder::drop.
    for budget in [Duration::ZERO, Duration::MAX] {
        run(vec![
            Open(1),
            Accept(1),
            AbandonmentTimeout(1, budget),
            Deliver(1, 7, 30),
            Receive(1, 30, 0),
            DropReply(0),
            NoOutput(1),
            Deadline(1, None),
        ]);
    }
}

/// Drops use current configuration, queued replies keep their deadlines, and
/// replacement sessions start with the default.
#[test]
fn test_abandonment_timeout_updates() {
    use super::Sent;
    use Step::*;
    use std::time::Duration;
    run(vec![
        Open(1),
        Accept(1),
        Deliver(1, 7, 30),
        Receive(1, 30, 0),
        Deliver(1, 8, 31),
        Receive(1, 31, 1),
        Deliver(1, 9, 32),
        Receive(1, 32, 2),
        Time(20),
        DropReply(0), // Uses the five-second default.
        AbandonmentTimeout(1, Duration::from_millis(30)),
        Output(1, 0, Sent::Reply(7, Err(1)), 5020),
        Written(0, Ok(())),
        DropReply(1), // Held since before reconfiguration, now uses 30ms.
        AbandonmentTimeout(1, Duration::from_millis(90)),
        Output(1, 1, Sent::Reply(8, Err(1)), 50),
        Written(1, Ok(())),
        DropReply(2),
        Output(1, 2, Sent::Reply(9, Err(1)), 110),
        Written(2, Ok(())),
        Open(2),
        Accept(2),
        Deliver(2, 10, 33),
        Receive(2, 33, 3),
        DropReply(3),
        Output(2, 3, Sent::Reply(10, Err(1)), 5020),
        Written(3, Ok(())),
    ]);
}

/// Late write results and answers target the original session after replacement.
/// Keeping promises and completion handles does not keep that session alive.
#[test]
fn test_replacement_keeps_completions_bound() {
    use super::Sent;
    use Failure::*;
    use Step::*;
    run(vec![
        Open(1),
        Accept(1),
        Request(1, 0, 10, 100),
        Output(1, 0, Sent::Request(10), 100),
        Deliver(1, 7, 30),
        Receive(1, 30, 0),
        Reply(0, 0, Ok(40), 100),
        Output(1, 1, Sent::Reply(7, Ok(40)), 100),
        Open(2),
        Accept(2),
        DropSession(1),
        Released(1),
        Request(2, 1, 11, 100),
        Output(2, 2, Sent::Request(11), 100),
        Deliver(2, 7, 31),
        Receive(2, 31, 1),
        Reply(1, 1, Ok(41), 100),
        Output(2, 3, Sent::Reply(7, Ok(41)), 100),
        Written(0, Err(Terminated)),
        Answer(0, Ok(99)),
        Written(1, Ok(())),
        Wait(0, Err(Reset)),
        WaitWrite(0, Err(Reset)),
        Deadline(2, Some(100)),
        Answer(2, Ok(21)),
        Written(3, Ok(())),
        Wait(1, Ok(21)),
        WaitWrite(1, Ok(())),
        Deadline(2, None),
    ]);
}

/// Racing `request()` with `close()` leaves the request failed. Racing an answer
/// with `close()` gives the promise either result once, without overwriting it.
#[test]
fn test_operation_retirement_races() {
    use super::Sent;
    use Step::*;
    for _ in 0..32 {
        run(vec![
            Open(1),
            Accept(1),
            RaceRequestClose(1),
            NoOutput(1),
            Deadline(1, None),
        ]);
        run(vec![
            Open(1),
            Accept(1),
            Request(1, 0, 10, 100),
            Output(1, 0, Sent::Request(10), 100),
            RaceAnswerClose(1, 0, 0),
            Deadline(1, None),
        ]);
    }
}

/// `Promise::wait()` enforces its deadline even without a deadline worker.
/// The watchdog fails the test if the call remains blocked.
#[test]
fn test_real_wait_deadlines() {
    use Failure::*;
    use Step::*;
    run(vec![
        Open(1),
        Accept(1),
        RealRequest(1, 0, 20),
        Deliver(1, 7, 30),
        Receive(1, 30, 0),
        RealReply(0, 0, 20),
        StartWait(0),
        StartWaitWrite(0),
        FinishWait(0, Err(Timeout)),
        FinishWaitWrite(0, Err(Timeout)),
        NoOutput(1),
        Deadline(1, None),
    ]);
}

/// A failed reply write fails its promise and does not queue an extra `UNANSWERED`
/// response: `reply()` already consumed the responder.
#[test]
fn test_output_failure_settlement() {
    use super::Sent;
    use Failure::*;
    use Step::*;
    run(vec![
        Open(1),
        Accept(1),
        Request(1, 0, 10, 100),
        Output(1, 0, Sent::Request(10), 100),
        Deliver(1, 7, 30),
        Receive(1, 30, 0),
        Reply(0, 0, Ok(40), 100),
        Output(1, 1, Sent::Reply(7, Ok(40)), 100),
        StartWait(0),
        StartWaitWrite(0),
        Written(0, Err(Terminated)),
        Written(1, Err(Terminated)),
        Answer(0, Ok(99)),
        Written(1, Ok(())),
        Time(200),
        CloseSession(1),
        FinishWait(0, Err(Terminated)),
        FinishWaitWrite(0, Err(Terminated)),
        NoOutput(1),
        Deadline(1, None),
    ]);
}

/// Racing `reply()` with `close()` leaves the reply failed. Racing its write result
/// with `close()` completes the promise once with either result.
#[test]
fn test_reply_retirement_races() {
    use super::Sent;
    use Step::*;
    for _ in 0..32 {
        run(vec![
            Open(1),
            Accept(1),
            Deliver(1, 7, 30),
            Receive(1, 30, 0),
            RaceReplyClose(1, 0),
            NoOutput(1),
            Deadline(1, None),
        ]);
        run(vec![
            Open(1),
            Accept(1),
            Deliver(1, 7, 30),
            Receive(1, 30, 0),
            Reply(0, 0, Ok(40), 100),
            Output(1, 0, Sent::Reply(7, Ok(40)), 100),
            RaceWriteClose(1, 0, 0),
            NoOutput(1),
            Deadline(1, None),
        ]);
    }
}
