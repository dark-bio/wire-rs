// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Session lifecycle, inbound accounting, and concurrency regressions.

use super::{Failure, Job, PATIENCE, Step, run};
use crate::protocol::envelope::{IncomingEnvelope, Side, opaque};
use crate::protocol::operation::PendingOperation;
use crate::protocol::schema::{self, HostToArk, host_to_ark};
use crate::protocol::session::SessionInner;
use crate::protocol::{
    DEFAULT_MAX_INBOUND_BYTES, DEFAULT_MAX_INBOUND_REQUESTS, Error, Message, Promise, Session,
};
use prost::Message as _;
use prost::bytes::Bytes;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Weak, mpsc};
use std::time::{Duration, Instant};

/// Shared tokens identify out-of-order completions. Successful request writing
/// is not terminal; notification receipt and late registration retain responses.
#[test]
fn test_notifications() {
    use super::ExpectedMessage;
    use Step::*;
    let size = incoming(0, 20).len();
    run(vec![
        Open(1),
        Accept(1),
        Request(1, 0, 10, 100),
        Notify(0, 10),
        Request(1, 1, 11, 100),
        Notify(1, 11),
        Request(1, 2, 12, 100),
        Outgoing(1, 0, ExpectedMessage::Request(10), 100),
        Outgoing(1, 1, ExpectedMessage::Request(11), 100),
        Outgoing(1, 2, ExpectedMessage::Request(12), 100),
        Written(0, Ok(())),
        Notifications(vec![]),
        Answer(1, Ok(21)),
        Notifications(vec![11]),
        Usage(1, 0, size),
        Answer(0, Ok(20)),
        Notifications(vec![10]),
        Usage(1, 0, 2 * size),
        Answer(2, Ok(22)),
        Notifications(vec![]),
        Deliver(1, 7, 30),
        Receive(1, 30, 0),
        Reply(0, 0, Ok(40), 100),
        NotifyWrite(0, 12),
        Outgoing(1, 3, ExpectedMessage::Reply(7, Ok(40)), 100),
        Notifications(vec![]),
        Written(3, Ok(())),
        Notifications(vec![12]),
        Written(3, Err(Failure::Terminated)),
        Notifications(vec![]),
        Deliver(1, 8, 31),
        Receive(1, 31, 1),
        Reply(1, 1, Ok(41), 100),
        Outgoing(1, 4, ExpectedMessage::Reply(8, Ok(41)), 100),
        Written(4, Ok(())),
        Time(200),
        Expire(1),
        Usage(1, 0, 3 * size),
        DropSession(1),
        Released(1),
        Notify(2, 13),
        NotifyWrite(1, 14),
        Notifications(vec![13, 14]),
        Wait(0, Ok(20)),
        Wait(1, Ok(21)),
        Wait(2, Ok(22)),
        WaitWrite(0, Ok(())),
        WaitWrite(1, Ok(())),
        Notifications(vec![]),
    ]);
}

/// Every terminal failure notifies both kinds. Clearing hooks on drop suppresses
/// later events without cancelling the queued operation or changing its deadline.
#[test]
fn test_notification_endings() {
    use super::ExpectedMessage;
    use Step::*;
    for dropped in [false, true] {
        for (ending, expected) in [
            (Expire(1), Failure::Timeout),
            (CloseSession(1), Failure::Closed),
            (Open(2), Failure::Reset),
            (DropSource, Failure::Terminated),
        ] {
            let mut steps = vec![
                Open(1),
                Accept(1),
                Request(1, 0, 10, 100),
                Notify(0, 1),
                Outgoing(1, 0, ExpectedMessage::Request(10), 100),
                Deliver(1, 7, 30),
                Receive(1, 30, 0),
                Reply(0, 0, Ok(40), 100),
                NotifyWrite(0, 2),
                Outgoing(1, 1, ExpectedMessage::Reply(7, Ok(40)), 100),
            ];
            if dropped {
                steps.extend([DropPromise(0), DropWritePromise(0)]);
            }
            if expected == Failure::Timeout {
                steps.push(Time(100));
            }
            steps.push(ending);
            steps.push(Notifications(if dropped { vec![] } else { vec![1, 2] }));
            steps.extend([Answer(0, Ok(20)), Written(1, Ok(())), Notifications(vec![])]);
            if !dropped {
                steps.extend([Wait(0, Err(expected)), WaitWrite(0, Err(expected))]);
            }
            run(steps);
        }
    }
}

/// Registration and completion share one linearization point. Drop before
/// completion suppresses a token; concurrent drop permits at most one stale token.
#[test]
fn test_notification_races() {
    for order in orders() {
        let (session, deadline) = fixture(0, 1024);
        let (id, mut promise) = request(&session, deadline);
        let (events, receiver) = mpsc::channel();
        let state = session.inner.clone();
        let (promise, ()) = schedule(
            order,
            move || {
                promise.notify(events, 1);
                promise
            },
            move || deliver(&state, incoming(id, 11)).unwrap(),
        );
        assert_eq!(receiver.try_recv(), Ok(1));
        assert!(receiver.try_recv().is_err());
        assert_eq!(promise.wait::<Vec<u8>>().unwrap(), vec![11]);
    }
    for order in orders() {
        let (session, deadline) = fixture(0, 1024);
        let (id, mut promise) = request(&session, deadline);
        let (events, receiver) = mpsc::channel();
        promise.notify(events, 1);
        let state = session.inner.clone();
        schedule(
            order,
            move || drop(promise),
            move || deliver(&state, incoming(id, 11)).unwrap(),
        );
        let tokens: Vec<_> = receiver.try_iter().collect();
        match order {
            Order::LeftFirst => assert!(tokens.is_empty()),
            Order::RightFirst => assert_eq!(tokens, vec![1]),
            Order::Concurrent => assert!(tokens.is_empty() || tokens == [1]),
        }
        assert_eq!(session.inner.inbound_usage(), (0, 0));
    }
}

/// Closure discards queued work, refuses later operations and remains repeatable.
#[test]
fn test_session_close() {
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
        DropSource,
    ] {
        let expected = if matches!(ending, DropSource) {
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
fn test_acceptance_and_server_close() {
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
        DropSource,
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
fn test_attach_races_server_close() {
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
    use super::ExpectedMessage;
    use Failure::*;
    use Step::*;
    run(vec![
        Open(1),
        Accept(1),
        Request(1, 0, 10, 100),
        Request(1, 1, 11, 100),
        Request(1, 2, 12, 100),
        Outgoing(1, 0, ExpectedMessage::Request(10), 100),
        Outgoing(1, 1, ExpectedMessage::Request(11), 100),
        Outgoing(1, 2, ExpectedMessage::Request(12), 100),
        StartWait(0),
        Written(0, Ok(())),
        Deadline(1, Some(100)),
        Answer(1, Err(0x123)),
        Answer(0, Ok(20)),
        FinishWait(0, Ok(20)),
        AnswerOther(2),
        Request(1, 3, 13, 100),
        Outgoing(1, 3, ExpectedMessage::Request(13), 100),
        Answer(3, Ok(23)),
        Deliver(1, 7, 30),
        Receive(1, 30, 0),
        Reply(0, 0, Ok(40), 100),
        Outgoing(1, 4, ExpectedMessage::Reply(7, Ok(40)), 100),
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
    use super::ExpectedMessage;
    use Failure::*;
    use Step::*;
    for time in [99, 100, 101] {
        let answer = if time < 100 { Ok(20) } else { Err(Timeout) };
        let written = if time < 100 { Ok(()) } else { Err(Timeout) };
        run(vec![
            Open(1),
            Accept(1),
            Request(1, 0, 10, 100),
            Outgoing(1, 0, ExpectedMessage::Request(10), 100),
            Deliver(1, 7, 30),
            Receive(1, 30, 0),
            Reply(0, 0, Ok(40), 100),
            Outgoing(1, 1, ExpectedMessage::Reply(7, Ok(40)), 100),
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
        Outgoing(1, 0, ExpectedMessage::Request(10), 100),
        Time(100),
        Written(0, Err(Terminated)),
        Answer(0, Ok(20)),
        Wait(0, Err(Timeout)),
    ]);
}

/// Expiry works without a waiting caller and while a write result is withheld.
/// Expired queued messages are discarded; new requests can still use the session.
#[test]
fn test_deadlines_without_writer_progress() {
    use super::ExpectedMessage;
    use Failure::*;
    use Step::*;
    run(vec![
        Open(1),
        Accept(1),
        Request(1, 0, 10, 100),
        Request(1, 1, 11, 100),
        Request(1, 2, 12, 200),
        Outgoing(1, 0, ExpectedMessage::Request(10), 100),
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
        Outgoing(1, 1, ExpectedMessage::Request(12), 200),
        NoOutgoing(1),
        Answer(0, Ok(20)),
        Answer(1, Ok(22)),
        Wait(1, Err(Timeout)),
        Wait(2, Ok(22)),
        Deadline(1, None),
        // Already-expired submission still returns a promise, without queueing.
        Request(1, 3, 13, 100),
        Wait(3, Err(Timeout)),
        NoOutgoing(1),
        Deliver(1, 8, 31),
        Receive(1, 31, 1),
        Reply(1, 1, Ok(41), 99),
        WaitWrite(1, Err(Timeout)),
        NoOutgoing(1),
    ]);
    // Taking a queued message checks its deadline even before expire() runs.
    run(vec![
        Open(1),
        Accept(1),
        Request(1, 0, 10, 100),
        Time(100),
        NoOutgoing(1),
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
        NoOutgoing(1),
        Deadline(1, None),
    ]);
}

/// Closing fails every pending promise. Closure before its deadline produces
/// `Closed`; closure at or after its deadline produces `Timeout`.
#[test]
fn test_close_fails_pending_operations() {
    use super::ExpectedMessage;
    use Failure::*;
    use Step::*;
    for time in [99, 100, 101] {
        for ending in [
            CloseSession(1),
            DropSession(1),
            CloseServer,
            DropServer,
            DropSource,
            RaceCloses(1),
        ] {
            let reason = if time >= 100 {
                Timeout
            } else if matches!(ending, DropSource) {
                Terminated
            } else {
                Closed
            };
            run(vec![
                Open(1),
                Accept(1),
                Request(1, 0, 10, 100),
                Request(1, 1, 11, 100),
                Outgoing(1, 0, ExpectedMessage::Request(10), 100),
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
    use super::ExpectedMessage;
    use Step::*;
    run(vec![
        Open(1),
        Accept(1),
        Request(1, 0, 10, 100),
        DropPromise(0),
        Outgoing(1, 0, ExpectedMessage::Request(10), 100),
        Written(0, Ok(())),
        Deadline(1, Some(100)),
        Answer(0, Ok(20)),
        Deadline(1, None),
        Request(1, 1, 11, 100),
        Outgoing(1, 1, ExpectedMessage::Request(11), 100),
        DropPromise(1),
        Answer(1, Err(0x123)),
        Deadline(1, None),
        Deliver(1, 7, 30),
        Receive(1, 30, 0),
        Reply(0, 0, Err(0x123), 100),
        DropWritePromise(0),
        Outgoing(1, 2, ExpectedMessage::Reply(7, Err(0x123)), 100),
        NoOutgoing(1),
        Written(2, Ok(())),
        Deadline(1, None),
        Request(1, 2, 12, 100),
        DropPromise(2),
        Time(100),
        Expire(1),
        NoOutgoing(1),
        Deadline(1, None),
    ]);
}

/// Abandonment uses its own configured budget starting at drop, including
/// queueing. Failed or expired automatic replies do not retry with a fresh budget.
#[test]
fn test_abandonment_timeout() {
    use super::ExpectedMessage;
    use Failure::*;
    use Step::*;
    use std::time::Duration;
    run(vec![
        Open(1),
        Accept(1),
        AbandonmentTimeout(1, Duration::from_millis(30)),
        Request(1, 0, 10, 200),
        Outgoing(1, 0, ExpectedMessage::Request(10), 200), // Hold unrelated output throughout.
        Deliver(1, 7, 30),
        Receive(1, 30, 0),
        Time(20),
        DropReply(0),
        Deadline(1, Some(50)),
        Time(49),
        Outgoing(1, 1, ExpectedMessage::Reply(7, Err(1)), 50),
        Time(50),
        Written(1, Ok(())),
        Deadline(1, Some(200)),
        NoOutgoing(1),
        Deliver(1, 8, 31),
        Receive(1, 31, 1),
        DropReply(1),
        Outgoing(1, 2, ExpectedMessage::Reply(8, Err(1)), 80),
        Written(2, Err(Terminated)),
        NoOutgoing(1),
        Deadline(1, Some(200)),
        Deliver(1, 9, 32),
        Receive(1, 32, 2),
        DropReply(2),
        Time(80),
        Expire(1),
        NoOutgoing(1),
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
            NoOutgoing(1),
            Deadline(1, None),
        ]);
    }
}

/// Drops use current configuration, queued replies keep their deadlines, and
/// replacement sessions start with the server's default.
#[test]
fn test_abandonment_timeout_updates() {
    use super::ExpectedMessage;
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
        Outgoing(1, 0, ExpectedMessage::Reply(7, Err(1)), 5020),
        Written(0, Ok(())),
        DropReply(1), // Held since before reconfiguration, now uses 30ms.
        AbandonmentTimeout(1, Duration::from_millis(90)),
        Outgoing(1, 1, ExpectedMessage::Reply(8, Err(1)), 50),
        Written(1, Ok(())),
        DropReply(2),
        Outgoing(1, 2, ExpectedMessage::Reply(9, Err(1)), 110),
        Written(2, Ok(())),
        Open(2),
        Accept(2),
        Deliver(2, 10, 33),
        Receive(2, 33, 3),
        DropReply(3),
        Outgoing(2, 3, ExpectedMessage::Reply(10, Err(1)), 5020),
        Written(3, Ok(())),
    ]);
}

/// Server timeouts reach pending, accepted and future sessions. Queued replies
/// keep their deadlines, and a session override does not change the server default.
#[test]
fn test_server_abandonment_timeout() {
    use super::ExpectedMessage;
    use Step::*;
    run(vec![
        ServerInboundLimits(2, 100),
        ServerAbandonmentTimeout(Duration::from_millis(30)),
        Open(1),
        Accept(1),
        Deliver(1, 7, 11),
        Receive(1, 11, 0),
        Time(20),
        DropReply(0),
        ServerAbandonmentTimeout(Duration::from_millis(40)),
        Deliver(1, 8, 12),
        Receive(1, 12, 1),
        DropReply(1),
        Usage(1, 2, 0),
        Outgoing(1, 0, ExpectedMessage::Reply(7, Err(1)), 50),
        Written(0, Ok(())),
        Outgoing(1, 1, ExpectedMessage::Reply(8, Err(1)), 60),
        Written(1, Ok(())),
        Usage(1, 0, 0),
        AbandonmentTimeout(1, Duration::from_millis(90)),
        Deliver(1, 9, 13),
        Receive(1, 13, 2),
        DropReply(2),
        Outgoing(1, 2, ExpectedMessage::Reply(9, Err(1)), 110),
        Written(2, Ok(())),
        Open(2),
        Accept(2),
        Deliver(2, 7, 14),
        Receive(2, 14, 3),
        DropReply(3),
        Outgoing(2, 3, ExpectedMessage::Reply(7, Err(1)), 60),
        Written(3, Ok(())),
        Deliver(2, 8, 15),
        Receive(2, 15, 4),
        AbandonmentTimeout(2, Duration::from_millis(90)),
        ServerAbandonmentTimeout(Duration::from_millis(50)),
        DropReply(4),
        Outgoing(2, 4, ExpectedMessage::Reply(8, Err(1)), 70),
        Written(4, Ok(())),
        Open(3),
        Deliver(3, 7, 16),
        ServerAbandonmentTimeout(Duration::from_millis(60)),
        Accept(3),
        Receive(3, 16, 5),
        DropReply(5),
        Outgoing(3, 5, ExpectedMessage::Reply(7, Err(1)), 80),
        Written(5, Ok(())),
        CloseServer,
        ServerAbandonmentTimeout(Duration::from_millis(70)),
        RefuseOpen(Failure::Closed),
        ReceiveError(3, Failure::Closed),
    ]);
    for timeout in [Duration::ZERO, Duration::MAX] {
        run(vec![
            ServerInboundLimits(1, 100),
            ServerAbandonmentTimeout(timeout),
            Open(1),
            Accept(1),
            Deliver(1, 7, 11),
            Receive(1, 11, 0),
            DropReply(0),
            NoOutgoing(1),
            Deadline(1, None),
            Usage(1, 0, 0),
            Open(2),
            Accept(2),
            Deliver(2, 7, 12),
            Receive(2, 12, 1),
            DropReply(1),
            NoOutgoing(2),
            Deadline(2, None),
            Usage(2, 0, 0),
        ]);
    }
}

/// Attachment cannot miss a timeout update. A concurrent responder drop uses
/// either the old or new timeout, and its queued reply is never retimed.
#[test]
fn test_server_abandonment_races() {
    use crate::protocol::Server;
    let timeout = Duration::from_millis(30);
    for order in orders() {
        let (server, mut source) = Server::fixture();
        let (mut server, (_source, state)) = schedule(
            order,
            move || server.set_abandonment_timeout(timeout),
            move || {
                let state = source.open().unwrap().upgrade().unwrap();
                (source, state)
            },
        );
        let mut session = server.accept().unwrap();
        let now = Instant::now() + Duration::from_secs(60);
        state.set_time(now);
        state.inject_request(1, vec![11].into()).unwrap();
        let (session, responder) = Job::start(move || {
            let (_, responder) = session.recv().unwrap();
            (session, responder)
        })
        .finish();
        Job::start(move || drop(responder)).finish();
        let outgoing = state.take_outgoing().unwrap();
        assert_eq!(outgoing.deadline, now + timeout);
        outgoing.operation.record_write(Ok(()));

        state.inject_request(3, vec![12].into()).unwrap();
        let mut session = session;
        let (session, responder) = Job::start(move || {
            let (_, responder) = session.recv().unwrap();
            (session, responder)
        })
        .finish();
        let (_server, ()) = schedule(
            order,
            move || server.set_abandonment_timeout(2 * timeout),
            move || drop(responder),
        );
        let outgoing = state.take_outgoing().unwrap();
        match order {
            Order::LeftFirst => assert_eq!(outgoing.deadline, now + 2 * timeout),
            Order::RightFirst => assert_eq!(outgoing.deadline, now + timeout),
            Order::Concurrent => assert!(
                outgoing.deadline == now + timeout || outgoing.deadline == now + 2 * timeout
            ),
        }
        outgoing.operation.record_write(Ok(()));
        assert_eq!(state.inbound_usage(), (0, 0));
        drop(session);
    }
}

/// Late write results and answers target the original session after replacement.
/// Keeping promises and operation handles does not keep that session alive.
#[test]
fn test_replacement_keeps_operation_handles_bound() {
    use super::ExpectedMessage;
    use Failure::*;
    use Step::*;
    run(vec![
        Open(1),
        Accept(1),
        Request(1, 0, 10, 100),
        Outgoing(1, 0, ExpectedMessage::Request(10), 100),
        Deliver(1, 7, 30),
        Receive(1, 30, 0),
        Reply(0, 0, Ok(40), 100),
        Outgoing(1, 1, ExpectedMessage::Reply(7, Ok(40)), 100),
        Open(2),
        Accept(2),
        DropSession(1),
        Released(1),
        Request(2, 1, 11, 100),
        Outgoing(2, 2, ExpectedMessage::Request(11), 100),
        Deliver(2, 7, 31),
        Receive(2, 31, 1),
        Reply(1, 1, Ok(41), 100),
        Outgoing(2, 3, ExpectedMessage::Reply(7, Ok(41)), 100),
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
fn test_operation_close_races() {
    use super::ExpectedMessage;
    use Step::*;
    for _ in 0..32 {
        run(vec![
            Open(1),
            Accept(1),
            RaceRequestClose(1),
            NoOutgoing(1),
            Deadline(1, None),
        ]);
        run(vec![
            Open(1),
            Accept(1),
            Request(1, 0, 10, 100),
            Outgoing(1, 0, ExpectedMessage::Request(10), 100),
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
        NoOutgoing(1),
        Deadline(1, None),
    ]);
}

/// A failed reply write fails its promise and does not queue an extra `UNANSWERED`
/// response: `reply()` already consumed the responder.
#[test]
fn test_write_failure_results() {
    use super::ExpectedMessage;
    use Failure::*;
    use Step::*;
    run(vec![
        Open(1),
        Accept(1),
        Request(1, 0, 10, 100),
        Outgoing(1, 0, ExpectedMessage::Request(10), 100),
        Deliver(1, 7, 30),
        Receive(1, 30, 0),
        Reply(0, 0, Ok(40), 100),
        Outgoing(1, 1, ExpectedMessage::Reply(7, Ok(40)), 100),
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
        NoOutgoing(1),
        Deadline(1, None),
    ]);
}

/// Racing `reply()` with `close()` leaves the reply failed. Racing its write result
/// with `close()` completes the promise once with either result.
#[test]
fn test_reply_close_races() {
    use super::ExpectedMessage;
    use Step::*;
    for _ in 0..32 {
        run(vec![
            Open(1),
            Accept(1),
            Deliver(1, 7, 30),
            Receive(1, 30, 0),
            RaceReplyClose(1, 0),
            NoOutgoing(1),
            Deadline(1, None),
        ]);
        run(vec![
            Open(1),
            Accept(1),
            Deliver(1, 7, 30),
            Receive(1, 30, 0),
            Reply(0, 0, Ok(40), 100),
            Outgoing(1, 0, ExpectedMessage::Reply(7, Ok(40)), 100),
            RaceWriteClose(1, 0, 0),
            NoOutgoing(1),
            Deadline(1, None),
        ]);
    }
}

/// Builds incoming fixture envelopes without depending on their encoded size.
fn incoming(id: u64, tag: u8) -> Vec<u8> {
    Side::Client.encode(id, Ok(vec![tag].into())).unwrap()
}

/// A request slot follows the responder and queued reply, not just the inbox.
#[test]
fn test_inbound_request_accounting() {
    use super::ExpectedMessage;
    use Step::*;
    let size = incoming(1, 11).len();
    run(vec![
        Open(0),
        Accept(0),
        InboundLimits(0, 1, size),
        Raw(0, incoming(1, 11), Ok(())),
        Usage(0, 1, size),
        Receive(0, 11, 0),
        Usage(0, 1, 0),
        Reply(0, 0, Ok(12), 10),
        Usage(0, 1, 0),
        Outgoing(0, 0, ExpectedMessage::Reply(1, Ok(12)), 10),
        Usage(0, 0, 0),
        Raw(0, incoming(1, 13), Ok(())),
        Usage(0, 1, size),
        Written(0, Ok(())),
        WaitWrite(0, Ok(())),
        Receive(0, 13, 1),
        Reply(1, 1, Ok(14), 10),
        Time(10),
        Expire(0),
        WaitWrite(1, Err(Failure::Timeout)),
        Usage(0, 0, 0),
        Raw(0, incoming(1, 15), Ok(())),
        Receive(0, 15, 2),
        AbandonmentTimeout(0, std::time::Duration::ZERO),
        DropReply(2),
        Usage(0, 0, 0),
    ]);
    // Holding a responder and waiting for the next request must wake on overflow.
    run(vec![
        Open(0),
        Accept(0),
        InboundLimits(0, 1, DEFAULT_MAX_INBOUND_BYTES),
        Raw(0, incoming(1, 11), Ok(())),
        Receive(0, 11, 0),
        StartReceive(0),
        Raw(0, incoming(3, 12), Err(Failure::Requests)),
        FinishReceiveError(0, Failure::Requests),
        RefuseReply(0, Failure::Requests),
        Usage(0, 0, 0),
        Open(1),
        Accept(1),
        Raw(1, incoming(1, 13), Ok(())),
        Receive(1, 13, 1),
    ]);
}

/// Charge the original bytes, including unknown fields and repeated scalar IDs.
#[test]
fn test_inbound_original_byte_accounting() {
    use Step::*;
    let mut bytes = incoming(1, 11);
    bytes.extend_from_slice(&[0x18, 0, 0x08, 0x81, 0]);
    let size = bytes.len();
    run(vec![
        Open(0),
        Accept(0),
        InboundLimits(0, DEFAULT_MAX_INBOUND_REQUESTS, size),
        Raw(0, bytes.clone(), Ok(())),
        Usage(0, 1, size),
        Receive(0, 11, 0),
        Usage(0, 1, 0),
        Raw(0, incoming(3, 12), Ok(())),
        Usage(0, 2, incoming(3, 12).len()),
        InboundLimits(0, DEFAULT_MAX_INBOUND_REQUESTS, incoming(3, 12).len() - 1),
        ReceiveError(0, Failure::Bytes),
        Usage(0, 0, 0),
    ]);
    run(vec![
        Open(0),
        Accept(0),
        InboundLimits(0, DEFAULT_MAX_INBOUND_REQUESTS, size - 1),
        StartReceive(0),
        Raw(0, bytes, Err(Failure::Bytes)),
        FinishReceiveError(0, Failure::Bytes),
    ]);
    for (limit, reason) in [
        (
            InboundLimits(0, 0, DEFAULT_MAX_INBOUND_BYTES),
            Failure::Requests,
        ),
        (
            InboundLimits(0, DEFAULT_MAX_INBOUND_REQUESTS, 0),
            Failure::Bytes,
        ),
    ] {
        run(vec![
            Open(0),
            Accept(0),
            limit,
            Raw(0, incoming(1, 1), Err(reason)),
            ReceiveError(0, reason),
        ]);
    }
}

/// Unread responses keep their bytes counted until read or dropped, even after closure.
#[test]
fn test_inbound_response_accounting() {
    use Step::*;
    let bytes = incoming(2, 11).len();
    run(vec![
        Open(0),
        Accept(0),
        InboundLimits(0, 0, bytes),
        Request(0, 0, 1, 10),
        SendNext(0, 0, 2),
        Raw(0, incoming(2, 11), Ok(())),
        Usage(0, 0, bytes),
        Time(10),
        Expire(0),
        Wait(0, Ok(11)),
        Usage(0, 0, 0),
        Request(0, 1, 2, 20),
        SendNext(0, 1, 4),
        Raw(0, incoming(4, 12), Ok(())),
        Usage(0, 0, bytes),
        DropPromise(1),
        Usage(0, 0, 0),
        Request(0, 2, 3, 20),
        SendNext(0, 2, 6),
        Raw(0, incoming(6, 13), Ok(())),
        CloseSession(0),
        Usage(0, 0, bytes),
        Open(1),
        Accept(1),
        Usage(1, 0, 0),
        Wait(2, Ok(13)),
        Usage(0, 0, 0),
        Usage(1, 0, 0),
    ]);
    run(vec![
        Open(0),
        Accept(0),
        InboundLimits(0, DEFAULT_MAX_INBOUND_REQUESTS, bytes),
        Request(0, 0, 1, 10),
        SendNext(0, 0, 2),
        Raw(0, incoming(2, 11), Ok(())),
        Request(0, 1, 2, 10),
        SendNext(0, 1, 4),
        StartReceive(0),
        Raw(0, incoming(4, 12), Err(Failure::Bytes)),
        FinishReceiveError(0, Failure::Bytes),
        Wait(1, Err(Failure::Bytes)),
        Usage(0, 0, bytes),
        Wait(0, Ok(11)),
        Usage(0, 0, 0),
    ]);
}

/// Unknown, late and unobserved answers need no capacity and never decode a body.
#[test]
fn test_unobserved_inbound_responses() {
    use Step::*;
    let malformed = crate::protocol::mock::envelope::malformed_body(false, 4, false);
    run(vec![
        Open(0),
        Accept(0),
        InboundLimits(0, DEFAULT_MAX_INBOUND_REQUESTS, incoming(2, 11).len()),
        Request(0, 0, 1, 10),
        SendNext(0, 0, 2),
        Raw(0, incoming(2, 11), Ok(())),
        Request(0, 1, 2, 10),
        SendNext(0, 1, 4),
        DropPromise(1),
        Raw(0, malformed.clone(), Ok(())),
        Raw(0, malformed, Ok(())),
        Request(0, 2, 3, 1),
        SendNext(0, 2, 6),
        Time(1),
        Raw(0, incoming(6, 13), Ok(())),
        Wait(2, Err(Failure::Timeout)),
        Usage(0, 0, incoming(2, 11).len()),
        Wait(0, Ok(11)),
        Usage(0, 0, 0),
        Raw(0, incoming(1, 14), Ok(())),
        Receive(0, 14, 0),
    ]);
}

/// Updates apply to already queued work and server sessions not yet accepted.
#[test]
fn test_inbound_limit_updates() {
    use Step::*;
    run(vec![
        ServerInboundLimits(1, 100),
        Open(0),
        Raw(0, incoming(1, 11), Ok(())),
        ServerInboundLimits(0, 100),
        Accept(0),
        ReceiveError(0, Failure::Requests),
        InboundLimits(0, 100, DEFAULT_MAX_INBOUND_BYTES),
        ReceiveError(0, Failure::Requests),
        ServerInboundLimits(2, 100),
        Open(1),
        Accept(1),
        Raw(1, incoming(1, 11), Ok(())),
        Raw(1, incoming(3, 12), Ok(())),
        Usage(1, 2, 2 * incoming(1, 11).len()),
        ServerInboundLimits(2, 1),
        ReceiveError(1, Failure::Bytes),
        Open(2),
        Accept(2),
        Raw(2, incoming(1, 13), Err(Failure::Bytes)),
        ServerInboundLimits(2, 100),
        Open(3),
        Accept(3),
        InboundLimits(3, 1, 100),
        Raw(3, incoming(1, 14), Ok(())),
        InboundLimits(3, 2, 100),
        Raw(3, incoming(3, 15), Ok(())),
        Receive(3, 14, 0),
        Receive(3, 15, 1),
    ]);
    let size = incoming(2, 11).len();
    run(vec![
        Open(0),
        Accept(0),
        Request(0, 0, 1, 10),
        SendNext(0, 0, 2),
        Raw(0, incoming(2, 11), Ok(())),
        InboundLimits(0, DEFAULT_MAX_INBOUND_REQUESTS, size),
        Usage(0, 0, size),
        InboundLimits(0, DEFAULT_MAX_INBOUND_REQUESTS, size - 1),
        ReceiveError(0, Failure::Bytes),
        Wait(0, Ok(11)),
        Usage(0, 0, 0),
    ]);
}

/// Malformed nested data is discovered at retrieval, closing its original session.
#[test]
fn test_inbound_deferred_validation() {
    use crate::protocol::mock::envelope::malformed_body;
    use Step::*;
    let request = malformed_body(false, 1, false);
    run(vec![
        Open(0),
        Accept(0),
        Raw(0, request.clone(), Ok(())),
        Usage(0, 1, request.len()),
        ReceiveError(0, Failure::Malformed),
        Usage(0, 0, 0),
        RefuseRequest(0, Failure::Malformed),
    ]);
    for error in [false, true] {
        let response = malformed_body(false, 2, error);
        run(vec![
            Open(0),
            Accept(0),
            Request(0, 0, 1, 10),
            SendNext(0, 0, 2),
            Notify(0, 7),
            Raw(0, response.clone(), Ok(())),
            Notifications(vec![7]),
            Usage(0, 0, response.len()),
            Wait(0, Err(Failure::Malformed)),
            ReceiveError(0, Failure::Malformed),
            Usage(0, 0, 0),
        ]);
        run(vec![
            Open(0),
            Accept(0),
            Request(0, 0, 1, 10),
            SendNext(0, 0, 2),
            Raw(0, response, Ok(())),
            Open(1),
            Accept(1),
            Wait(0, Err(Failure::Malformed)),
            Usage(0, 0, 0),
            Usage(1, 0, 0),
            Raw(1, incoming(1, 12), Ok(())),
            Receive(1, 12, 0),
        ]);
    }
}

/// Retaining the original envelope preserves protobuf's nested message merging.
#[test]
fn test_inbound_preserves_nested_merges() {
    use crate::protocol::schema::{HostToArk, PairingSetAppIdentityRequest, host_to_ark};
    use Step::*;
    use prost::Message as _;
    let first = PairingSetAppIdentityRequest { identity: vec![42] };
    let mut bytes = HostToArk {
        id: 1,
        err: None,
        content: Some(host_to_ark::Content::PairingSetAppId(first.clone())),
    }
    .encode_to_vec();
    // An empty second occurrence must preserve the first nested field. Decoding
    // only the opaque view's last payload would lose the identity.
    bytes.extend(
        HostToArk {
            id: 1,
            err: None,
            content: Some(host_to_ark::Content::PairingSetAppId(Default::default())),
        }
        .encode_to_vec(),
    );
    run(vec![
        Open(0),
        Accept(0),
        Raw(0, bytes, Ok(())),
        ReceiveMessage(0, first.into(), 0),
    ]);
}

/// Inbox entries and unread responses compete for the same original-byte budget.
#[test]
fn test_inbound_shared_byte_budget() {
    use Step::*;
    let size = incoming(1, 11).len();
    run(vec![
        Open(0),
        Accept(0),
        InboundLimits(0, 2, 2 * size),
        Request(0, 0, 10, 10),
        SendNext(0, 0, 2),
        Raw(0, incoming(2, 11), Ok(())),
        Raw(0, incoming(1, 12), Ok(())),
        Usage(0, 1, 2 * size),
        // A full budget does not stop replies to an existing local request from
        // being matched: the observer gets the capacity error and wakes up.
        Request(0, 1, 20, 10),
        SendNext(0, 1, 4),
        Raw(0, incoming(4, 21), Err(Failure::Bytes)),
        Wait(1, Err(Failure::Bytes)),
        Usage(0, 0, size),
        DropSession(0),
        Released(0),
        Wait(0, Ok(11)),
    ]);
    run(vec![
        Open(0),
        Accept(0),
        InboundLimits(0, 2, 2 * size),
        Request(0, 0, 10, 10),
        SendNext(0, 0, 2),
        Raw(0, incoming(1, 11), Ok(())),
        Raw(0, incoming(2, 12), Ok(())),
        Usage(0, 1, 2 * size),
        Raw(0, incoming(3, 13), Err(Failure::Bytes)),
        ReceiveError(0, Failure::Bytes),
        Usage(0, 0, size),
        DropPromise(0),
        Usage(0, 0, 0),
    ]);
}

/// Limit updates apply whether they happen before or after session attachment.
#[test]
fn test_inbound_limits_during_attachment() {
    use crate::protocol::Server;
    use std::sync::{Arc, Barrier};
    for (requests, bytes, reason) in [(0, 100, Failure::Requests), (1, 0, Failure::Bytes)] {
        for _ in 0..16 {
            let (server, mut source) = Server::fixture();
            let barrier = Arc::new(Barrier::new(2));
            let ready = barrier.clone();
            let update = super::Job::start(move || {
                ready.wait();
                server.set_inbound_limits(requests, bytes)
            });
            barrier.wait();
            let state = source.open().unwrap();
            let mut server = update.finish();
            let mut session = server.accept().unwrap();
            let result = state.upgrade().unwrap().inject_request(1, vec![11].into());
            assert_eq!(result.map_err(super::failure), Err(reason));
            assert_eq!(super::failure(session.recv().err().unwrap()), reason);
        }
    }
}

/// Which of two calls runs first, or whether they compete.
#[derive(Clone, Copy)]
enum Order {
    LeftFirst,
    Concurrent,
    RightFirst,
}

/// Runs both calls in the chosen order. Concurrent calls start at the same barrier.
fn schedule<A: Send + 'static, B: Send + 'static>(
    order: Order,
    left: impl FnOnce() -> A + Send + 'static,
    right: impl FnOnce() -> B + Send + 'static,
) -> (A, B) {
    match order {
        Order::LeftFirst => (Job::start(left).finish(), Job::start(right).finish()),
        Order::RightFirst => {
            let right = Job::start(right).finish();
            (Job::start(left).finish(), right)
        }
        Order::Concurrent => {
            let gate = Arc::new(Barrier::new(3));
            let a = gate.clone();
            let b = gate.clone();
            let left = Job::start(move || {
                a.wait();
                left()
            });
            let right = Job::start(move || {
                b.wait();
                right()
            });
            gate.wait();
            (left.finish(), right.finish())
        }
    }
}

/// Checks both fixed orders, then repeats with the threads competing.
fn orders() -> impl Iterator<Item = Order> {
    [Order::LeftFirst, Order::RightFirst]
        .into_iter()
        .chain(std::iter::repeat_n(Order::Concurrent, 16))
}

/// Creates a session with the given limits and a controlled deadline.
fn fixture(requests: usize, bytes: usize) -> (Session, Instant) {
    let session = Session::fixture().set_inbound_limits(requests, bytes);
    let now = Instant::now() + Duration::from_secs(60);
    session.inner.set_time(now);
    (session, now + Duration::from_secs(1))
}

/// Submits a request and assigns its wire ID without a transport writer.
fn request(session: &Session, deadline: Instant) -> (u64, Promise<Message>) {
    let promise = session.requester().request(vec![1], deadline).unwrap();
    let (id, _) = session.inner.next_outgoing().unwrap();
    (id, promise)
}

/// Mirrors reader failure handling, including the closing reason kept by waiters.
fn deliver(session: &Arc<SessionInner>, bytes: Vec<u8>) -> Result<(), Error> {
    let result = session.handle_message(bytes);
    if let Err(error) = &result {
        session.close(error.clone());
    }
    result
}

fn byte_error<T>(result: Result<T, Error>, limit: usize) {
    assert!(matches!(result, Err(Error::InboundByteLimitExceeded(actual)) if actual == limit));
}

fn request_error<T>(result: Result<T, Error>, limit: usize) {
    assert!(matches!(result, Err(Error::InboundRequestLimitExceeded(actual)) if actual == limit));
}

/// Releasing A before admitting B must permit B; the reverse order must close.
/// Overlap permits either ordering, but never leaves a leaked charge or promise.
#[test]
fn test_release_races_response_admission() {
    for consume in [false, true] {
        for order in orders() {
            let size = incoming(2, 11).len();
            let (session, deadline) = fixture(0, size);
            let (a, first) = request(&session, deadline);
            let (b, second) = request(&session, deadline);
            deliver(&session.inner, incoming(a, 11)).unwrap();
            let state = session.inner.clone();
            let (_, delivered) = schedule(
                order,
                move || {
                    if consume {
                        assert_eq!(first.wait::<Vec<u8>>().unwrap(), vec![11]);
                    } else {
                        drop(first);
                    }
                },
                move || deliver(&state, incoming(b, 12)),
            );
            match order {
                Order::LeftFirst => assert!(delivered.is_ok()),
                Order::RightFirst => byte_error(delivered.as_ref().map_err(Clone::clone), size),
                Order::Concurrent => {}
            }
            if delivered.is_ok() {
                assert_eq!(session.inner.inbound_usage(), (0, size));
                assert_eq!(second.wait::<Vec<u8>>().unwrap(), vec![12]);
            } else {
                byte_error(delivered, size);
                byte_error(second.wait::<Message>(), size);
                byte_error(session.requester().request(vec![1], deadline), size);
            }
            assert_eq!(session.inner.inbound_usage(), (0, 0));
        }
    }
}

/// Drop the promise between reserving bytes and delivering the result. A byte
/// limit failure closes the session only if the promise still exists at delivery.
#[test]
fn test_observer_drop_during_response_completion() {
    for admit in [false, true] {
        for drop_observer in [false, true] {
            let bytes = incoming(2, 11);
            let header = Side::Server.decode_header(bytes.clone().into()).unwrap();
            let limit = if admit { bytes.len() } else { 0 };
            let used = Arc::new(AtomicUsize::new(0));
            let counter = used.clone();
            let now = Instant::now();
            let (sender, promise) =
                Promise::<Message>::pair(Weak::new(), now + Duration::from_secs(60), true);
            let pending = PendingOperation {
                deadline: now + Duration::from_secs(60),
                sender,
                log_id: None,
            };
            let (entered, reserved) = mpsc::channel();
            let (release, released) = mpsc::channel();
            let completed = Job::start(move || {
                pending.complete_response(now, || {
                    let result = IncomingEnvelope::new(
                        bytes.into(),
                        header,
                        &counter,
                        limit,
                        Side::Server,
                        Weak::new(),
                    );
                    entered.send(()).unwrap();
                    released.recv_timeout(PATIENCE).unwrap();
                    result
                })
            });
            reserved.recv_timeout(PATIENCE).unwrap();
            assert_eq!(used.load(Ordering::Relaxed), limit);
            let promise = if drop_observer {
                drop(promise);
                None
            } else {
                Some(promise)
            };
            release.send(()).unwrap();
            let result = completed.finish();
            if !admit && !drop_observer {
                byte_error(result, limit);
            } else {
                result.unwrap();
            }
            if let Some(promise) = promise {
                if admit {
                    assert_eq!(promise.wait::<Vec<u8>>().unwrap(), vec![11]);
                } else {
                    byte_error(promise.wait::<Message>(), limit);
                }
            }
            assert_eq!(used.load(Ordering::Relaxed), 0);
        }
    }
}

/// Changing limits and accepting messages use the same lock, in either order.
#[test]
fn test_limits_race_request_and_response_admission() {
    for order in orders() {
        let size = incoming(1, 11).len();
        let (session, deadline) = fixture(2, 2 * size);
        deliver(&session.inner, incoming(1, 11)).unwrap();
        let (_, pending) = request(&session, deadline);
        let state = session.inner.clone();
        let (delivered, session) = schedule(
            order,
            move || deliver(&state, incoming(3, 12)),
            move || session.set_inbound_limits(1, 2 * size),
        );
        match order {
            Order::LeftFirst => assert!(delivered.is_ok()),
            Order::RightFirst => request_error(delivered.as_ref().map_err(Clone::clone), 1),
            Order::Concurrent => {}
        }
        if delivered.is_err() {
            request_error(delivered, 1);
        }
        request_error(pending.wait::<Message>(), 1);
        assert_eq!(session.inner.inbound_usage(), (0, 0));

        let (session, deadline) = fixture(0, 2 * size);
        let (a, first) = request(&session, deadline);
        let (b, second) = request(&session, deadline);
        deliver(&session.inner, incoming(a, 11)).unwrap();
        let state = session.inner.clone();
        let (delivered, session) = schedule(
            order,
            move || deliver(&state, incoming(b, 12)),
            move || session.set_inbound_limits(0, size),
        );
        match order {
            Order::LeftFirst => assert!(delivered.is_ok()),
            Order::RightFirst => byte_error(delivered.as_ref().map_err(Clone::clone), size),
            Order::Concurrent => {}
        }
        byte_error(session.requester().request(vec![1], deadline), size);
        assert_eq!(first.wait::<Vec<u8>>().unwrap(), vec![11]);
        if delivered.is_ok() {
            assert_eq!(second.wait::<Vec<u8>>().unwrap(), vec![12]);
        } else {
            byte_error(second.wait::<Message>(), size);
        }
        assert_eq!(session.inner.inbound_usage(), (0, 0));
    }
}

/// Lowering a limit after its last obligation is released keeps the session open.
/// Lowering first closes it but cannot replace an already buffered response.
#[test]
fn test_limits_race_consumers_and_reply_writes() {
    for order in orders() {
        let (session, deadline) = fixture(1, 100);
        let (id, promise) = request(&session, deadline);
        deliver(&session.inner, incoming(id, 11)).unwrap();
        let (answer, session) = schedule(
            order,
            move || promise.wait::<Vec<u8>>(),
            move || session.set_inbound_limits(1, 0),
        );
        assert_eq!(answer.unwrap(), vec![11]);
        let probe = session.requester().request(vec![1], deadline);
        match order {
            Order::LeftFirst => assert!(probe.is_ok()),
            Order::RightFirst => byte_error(probe.as_ref().map_err(Clone::clone), 0),
            Order::Concurrent => {}
        }
        if probe.is_err() {
            byte_error(probe, 0);
        }
        assert_eq!(session.inner.inbound_usage(), (0, 0));

        let (mut session, deadline) = fixture(1, 100);
        deliver(&session.inner, incoming(1, 11)).unwrap();
        let (_, responder) = session.recv().unwrap();
        let promise = responder.reply(vec![12], deadline).unwrap();
        let state = session.inner.clone();
        let (written, session) = schedule(
            order,
            move || {
                if let Some((_, outgoing)) = state.next_outgoing() {
                    outgoing.operation.record_write(Ok(()));
                    true
                } else {
                    false
                }
            },
            move || session.set_inbound_limits(0, 100),
        );
        let probe = session.requester().request(vec![1], deadline);
        match order {
            Order::LeftFirst => assert!(probe.is_ok()),
            Order::RightFirst => request_error(probe.as_ref().map_err(Clone::clone), 0),
            Order::Concurrent => {}
        }
        if probe.is_err() {
            request_error(promise.wait(), 0);
        } else {
            assert!(written);
            promise.wait().unwrap();
        }
        assert_eq!(session.inner.inbound_usage(), (0, 0));
    }
}

/// Valid outer envelopes carrying truncated payloads or invalid error text.
fn malformed(id: u64) -> Vec<Vec<u8>> {
    vec![
        super::super::envelope::malformed_body(false, id, false),
        super::super::envelope::malformed_body(false, id, true),
        opaque::HostToArk {
            id,
            err: Some(Bytes::from_static(&[0x12, 1, 0xff])),
            content: None,
        }
        .encode_to_vec(),
    ]
}

#[test]
fn test_malformed_response_observation_and_deadlines() {
    use Step::*;
    for (shape, bytes) in malformed(2).into_iter().enumerate() {
        // Exercise and seed the independent envelope decoder with the same input.
        let mut input = vec![0];
        input.extend_from_slice(&bytes);
        assert!(!super::super::envelope::run(&input));
        run(vec![
            Open(0),
            Accept(0),
            Request(0, 0, 1, 10),
            SendNext(0, 0, 2),
            Raw(0, bytes.clone(), Ok(())),
            Time(10),
            Expire(0),
            Wait(0, Err(Failure::Malformed)),
            ReceiveError(0, Failure::Malformed),
            Usage(0, 0, 0),
        ]);
        // Both exact-deadline and later arrivals bypass nested decoding, with
        // and without the deadline worker having already removed the operation.
        for time in [10, 11] {
            for expired in [false, true] {
                let mut steps = vec![
                    Open(0),
                    Accept(0),
                    InboundLimits(0, 1, 0),
                    Request(0, 0, 1, 10),
                    SendNext(0, 0, 2),
                    Time(time),
                ];
                if expired {
                    steps.push(Expire(0));
                }
                steps.extend([
                    Raw(0, bytes.clone(), Ok(())),
                    Wait(0, Err(Failure::Timeout)),
                    Usage(0, 0, 0),
                    InboundLimits(0, 1, 100),
                    Raw(0, incoming(1, 11), Ok(())),
                    Receive(0, 11, 0),
                ]);
                run(steps);
            }
        }
        run(vec![
            Open(0),
            Accept(0),
            Request(0, 0, 1, 10),
            SendNext(0, 0, 2),
            Raw(0, bytes.clone(), Ok(())),
            Usage(0, 0, bytes.len()),
            DropPromise(0),
            Usage(0, 0, 0),
            InboundLimits(0, 1, 0),
            // A duplicate, an unknown answer, and an unobserved answer all skip decoding.
            Raw(0, bytes.clone(), Ok(())),
            Request(0, 1, 2, 10),
            SendNext(0, 1, 4),
            DropPromise(1),
            Raw(0, malformed(4)[shape].clone(), Ok(())),
            Raw(0, malformed(6)[shape].clone(), Ok(())),
            InboundLimits(0, 1, 100),
            Raw(0, incoming(1, 11), Ok(())),
            Receive(0, 11, 0),
        ]);
    }
}

/// Repeated errors merge their fields. Different content alternatives replace
/// each other. Full decoding must still reject malformed earlier payloads.
#[test]
fn test_repeated_payload_fields() {
    let mut error = HostToArk {
        id: 2,
        err: Some(schema::Error {
            code: 123,
            msg: String::new(),
        }),
        content: None,
    }
    .encode_to_vec();
    error.extend(
        HostToArk {
            id: 0,
            err: Some(schema::Error {
                code: 0,
                msg: "reason".into(),
            }),
            content: None,
        }
        .encode_to_vec(),
    );
    let (session, deadline) = fixture(1, 100);
    let (_, promise) = request(&session, deadline);
    let mut input = vec![0];
    input.extend_from_slice(&error);
    assert!(super::super::envelope::run(&input));
    let size = error.len();
    deliver(&session.inner, error).unwrap();
    assert_eq!(session.inner.inbound_usage(), (0, size));
    match promise.wait::<Message>() {
        Err(Error::Remote(error)) => {
            assert_eq!(error.code, 123);
            assert_eq!(error.msg, "reason");
        }
        _ => panic!("merged remote error required"),
    }
    assert_eq!(session.inner.inbound_usage(), (0, 0));

    let first = HostToArk {
        id: 1,
        err: None,
        content: Some(host_to_ark::Content::PairingSetAppId(
            crate::protocol::schema::PairingSetAppIdentityRequest { identity: vec![42] },
        )),
    }
    .encode_to_vec();
    for (prefix, valid) in [(first, true), (malformed(1)[0].clone(), false)] {
        let mut bytes = prefix;
        bytes.extend(incoming(1, 11));
        let mut input = vec![0];
        input.extend_from_slice(&bytes);
        assert_eq!(super::super::envelope::run(&input), valid);
        let (mut session, _) = fixture(1, bytes.len());
        deliver(&session.inner, bytes).unwrap();
        let (session, result) = Job::start(move || {
            let result = session.recv();
            (session, result)
        })
        .finish();
        if valid {
            assert_eq!(result.unwrap().0, Message::Develop(vec![11]));
        } else {
            assert!(matches!(result, Err(Error::Malformed)));
        }
        assert_eq!(session.inner.inbound_usage().1, 0);
    }
}

/// Only the final ID decides routing, even if an earlier ID has the other parity.
#[test]
fn test_repeated_id_changes_routing() {
    for (side, peer, peer_id) in [
        (Side::Server, Side::Client, 1),
        (Side::Client, Side::Server, 2),
    ] {
        for is_response in [false, true] {
            let session = Session::fixture_for(side).set_inbound_limits(1, 100);
            let deadline = Instant::now() + Duration::from_secs(60);
            let (own, promise) = request(&session, deadline);
            let (first, last) = if is_response {
                (peer_id, own)
            } else {
                (own, peer_id)
            };
            let mut bytes = peer.encode(first, Ok(vec![11].into())).unwrap();
            // An ID-only envelope appends a scalar occurrence without replacing content.
            bytes.extend(match peer {
                Side::Client => HostToArk {
                    id: last,
                    err: None,
                    content: None,
                }
                .encode_to_vec(),
                Side::Server => crate::protocol::schema::ArkToHost {
                    id: last,
                    err: None,
                    content: None,
                }
                .encode_to_vec(),
            });
            let mut input = vec![u8::from(side == Side::Client)];
            input.extend_from_slice(&bytes);
            assert!(super::super::envelope::run(&input));
            let size = bytes.len();
            deliver(&session.inner, bytes).unwrap();
            assert_eq!(
                session.inner.inbound_usage(),
                (usize::from(!is_response), size)
            );
            if is_response {
                assert_eq!(promise.wait::<Vec<u8>>().unwrap(), vec![11]);
            } else {
                assert_eq!(session.inner.outstanding_ids(), vec![own]);
                let state = session.inner.clone();
                let mut session = session;
                let (session, received) = Job::start(move || {
                    let received = session.recv();
                    (session, received)
                })
                .finish();
                let (body, responder) = received.unwrap();
                assert_eq!(body, Message::Develop(vec![11]));
                deliver(&state, peer.encode(own, Ok(vec![12].into())).unwrap()).unwrap();
                assert_eq!(promise.wait::<Vec<u8>>().unwrap(), vec![12]);
                assert_eq!(state.inbound_usage(), (1, 0));
                drop(responder);
                drop(session);
            }
        }
    }
}

/// Constructs an envelope exactly at the transport's maximum sending size.
fn large_envelope(peer: Side, id: u64, error: bool) -> (Vec<u8>, usize) {
    let body = |len| {
        if error {
            Err(schema::Error {
                code: 123,
                msg: "x".repeat(len),
            })
        } else {
            Ok(Message::Develop(vec![42; len]))
        }
    };
    let size = crate::transport::MAX_MESSAGE_SIZE;
    let sample = size - 64;
    let overhead = peer.encode(id, body(sample)).unwrap().len() - sample;
    let bytes = peer.encode(id, body(size - overhead)).unwrap();
    assert_eq!(bytes.len(), size);
    (bytes, size - overhead)
}

/// Checks exact byte limits for queued requests and unread responses in both roles.
/// Includes large error strings and development payloads.
#[test]
fn test_large_inbound_boundaries_and_error_values() {
    let size = crate::transport::MAX_MESSAGE_SIZE;
    for (side, peer, peer_id) in [
        (Side::Server, Side::Client, 1),
        (Side::Client, Side::Server, 2),
    ] {
        for response in [false, true] {
            for error in [false, true] {
                if error && !response {
                    continue;
                }
                for limit in [size - 1, size, size + 1] {
                    let mut session = Session::fixture_for(side).set_inbound_limits(1, limit);
                    let (id, promise) = if response {
                        let (id, promise) =
                            request(&session, Instant::now() + Duration::from_secs(60));
                        (id, Some(promise))
                    } else {
                        (peer_id, None)
                    };
                    let (bytes, payload) = large_envelope(peer, id, error);
                    let result = deliver(&session.inner, bytes);
                    if limit < size {
                        byte_error(result, limit);
                        byte_error(session.recv(), limit);
                        if let Some(promise) = promise {
                            byte_error(promise.wait::<Message>(), limit);
                        }
                        assert_eq!(session.inner.inbound_usage(), (0, 0));
                    } else {
                        result.unwrap();
                        assert_eq!(
                            session.inner.inbound_usage(),
                            (usize::from(!response), size)
                        );
                        let result = match promise {
                            Some(promise) => promise.wait::<Message>(),
                            None => session.recv().map(|(message, _)| message),
                        };
                        match result {
                            Ok(Message::Develop(bytes)) if !error => {
                                assert_eq!(bytes.len(), payload);
                                assert!(bytes.iter().all(|byte| *byte == 42));
                            }
                            Err(Error::Remote(remote)) if error => {
                                assert_eq!(remote.code, 123);
                                assert_eq!(remote.msg.len(), payload);
                            }
                            _ => panic!("expected large payload or remote error"),
                        }
                        assert_eq!(session.inner.inbound_usage().1, 0);
                    }
                }
            }
        }
    }
    // Lowering also reports the configured ceiling, with request limits taking
    // precedence if both budgets become too small in the same update.
    let (session, deadline) = fixture(3, 100);
    deliver(&session.inner, incoming(1, 11)).unwrap();
    deliver(&session.inner, incoming(3, 12)).unwrap();
    let session = session.set_inbound_limits(1, 0);
    request_error(session.requester().request(vec![1], deadline), 1);
    let (session, deadline) = fixture(1, 100);
    deliver(&session.inner, incoming(1, 11)).unwrap();
    let session = session.set_inbound_limits(1, 3);
    byte_error(session.requester().request(vec![1], deadline), 3);
}
