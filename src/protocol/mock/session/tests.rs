// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Session lifecycle, inbound accounting, and concurrency regressions.

use super::{Failure, Job, Step, run};
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

/// Notifications report each completion once, in any order, leaving results and
/// response bytes in place.
#[test]
fn test_notifications() {
    use super::ExpectedMessage;
    use Step::*;
    let size = incoming(0, 20).len();
    run(vec![
        // Take three requests for writing, registering on the first two
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
        // A successful request write does not settle the request
        Written(0, Ok(())),
        Notifications(vec![]),
        // Answers out of order notify only registered promises and stay charged
        Answer(1, Ok(21)),
        Notifications(vec![11]),
        Usage(1, 0, size),
        Answer(0, Ok(20)),
        Notifications(vec![10]),
        Usage(1, 0, 2 * size),
        Answer(2, Ok(22)),
        Notifications(vec![]),
        // A reply's token follows its first write result only
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
        // Settle another reply, then free the session past every deadline
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
        // Registering on settled promises notifies at once, and waits return
        // every result without further tokens
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

/// Every way an operation fails notifies both promise kinds, unless dropping the
/// promises cleared their registrations first.
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
            // Register on a request and a reply, both taken for writing
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

            // Dropping both promises clears their registrations, while the
            // operations keep running
            if dropped {
                steps.extend([DropPromise(0), DropWritePromise(0)]);
            }

            // Fail both operations, reaching their deadline first for expiry
            if expected == Failure::Timeout {
                steps.push(Time(100));
            }
            steps.push(ending);
            steps.push(Notifications(if dropped { vec![] } else { vec![1, 2] }));

            // Late results send nothing, and held promises keep the failure
            steps.extend([Answer(0, Ok(20)), Written(1, Ok(())), Notifications(vec![])]);
            if !dropped {
                steps.extend([Wait(0, Err(expected)), WaitWrite(0, Err(expected))]);
            }
            run(steps);
        }
    }
}

/// Registration racing completion sends exactly one token, and a drop racing
/// completion sends at most one.
#[test]
fn test_notification_races() {
    // Race registration against the answer, which notifies either way
    for order in orders() {
        let (session, deadline) = fixture(0, 1024);
        let (id, mut promise) = request(&session, deadline);
        let (events, receiver) = mpsc::channel();
        let state = session.inner.clone();
        let (promise, ()) = schedule(
            order,
            move || {
                promise.notify(move || {
                    let _ = events.send(1);
                });
                promise
            },
            move || deliver(&state, incoming(id, 11)).unwrap(),
        );
        assert_eq!(receiver.try_recv(), Ok(1));
        assert!(receiver.try_recv().is_err());
        assert_eq!(promise.wait::<Vec<u8>>().unwrap(), vec![11]);
    }

    // Race dropping a registered promise against the answer, which notifies
    // only if the answer wins and releases the bytes either way
    for order in orders() {
        let (session, deadline) = fixture(0, 1024);
        let (id, mut promise) = request(&session, deadline);
        let (events, receiver) = mpsc::channel();
        promise.notify(move || {
            let _ = events.send(1);
        });
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
        // Closing discards a queued request and refuses later work
        Open(1),
        Accept(1),
        Deliver(1, 7, 11),
        CloseSession(1),
        ReceiveError(1, Closed),
        RefuseDelivery(1, Closed),
        RefuseRequest(1, Closed),
        // Closing again changes nothing, even after the session is freed
        CloseSession(1),
        ReceiveError(1, Closed),
        DropSession(1),
        Released(1),
        RefuseRequest(1, Closed),
        CloseSession(1),
        // Racing closures wake a blocked receive with the same reason
        Open(2),
        Accept(2),
        StartReceive(2),
        RaceCloses(2),
        FinishReceiveError(2, Closed),
    ]);
}

/// Delivery and every way of ending the session wake a receive already waiting.
#[test]
fn test_receiver_wakeups() {
    use Failure::*;
    use Step::*;

    // Each ending wakes the receive with its own reason
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

    // A delivery wakes the receive, and dropping its responder queues one
    // `UNANSWERED` reply
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
        // Hold two responders and a blocked receive on the first session
        Open(1),
        Accept(1),
        Deliver(1, 7, 11),
        Receive(1, 11, 0),
        Deliver(1, 8, 12),
        Receive(1, 12, 1),
        StartReceive(1),
        // A replacement wakes the receive with a reset
        Open(2),
        FinishReceiveError(1, Reset),
        Accept(2),
        // Old handles keep the reset and reach nothing in the successor
        RefuseRequest(1, Reset),
        RefuseReply(0, Reset),
        DropReply(1),
        CloseSession(1),
        ReceiveError(1, Reset),
        RefuseDelivery(1, Reset),
        Abandoned(2, vec![]),
        // The successor reuses an old request ID, and freeing the old session
        // turns its requester's error into `Closed`
        Deliver(2, 7, 22),
        Receive(2, 22, 2),
        DropSession(1),
        Released(1),
        CloseSession(1),
        RefuseRequest(1, Closed),
        // The successor's own responders answer the reused IDs
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
        // Dropping the session owner frees it despite a held responder
        Open(1),
        Accept(1),
        Deliver(1, 1, 11),
        Receive(1, 11, 0),
        DropSession(1),
        Released(1),
        // The remaining handles report `Closed`
        RefuseRequest(1, Closed),
        RefuseReply(0, Closed),
        CloseSession(1),
        // Dropping the server owner wakes a blocked receive and refuses sessions
        Open(2),
        Accept(2),
        StartReceive(2),
        DropServer,
        FinishReceiveError(2, Closed),
        RefuseOpen(Closed),
        // The closer of a freed server does nothing, and the ended session
        // frees once its owner drops
        CloseServer,
        DropSession(2),
        Released(2),
    ]);
}

/// `accept()` wakes on an attach or on server closure, and returns only the
/// newest of several waiting sessions.
#[test]
fn test_acceptance_and_server_close() {
    use Failure::*;
    use Step::*;

    // A blocked acceptance wakes for each attach, and server closure then ends
    // the accepted session and refuses new ones
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

    // Racing server closures wake a blocked acceptance
    run(vec![
        StartAccept,
        RaceServerCloses,
        FinishAcceptError(Closed),
        CloseServer,
        RefuseOpen(Closed),
    ]);

    // Losing the session source ends a blocked acceptance with `Terminated`
    run(vec![
        StartAccept,
        DropSource,
        FinishAcceptError(Terminated),
        CloseServer,
    ]);

    // Each attach frees the session still waiting, and server closure frees
    // one that nobody accepted
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

    // A blocked acceptance gets either the closure or a closed session
    run(vec![
        StartAccept,
        RaceServerCloseOpen,
        FinishAcceptClosed,
        RefuseOpen(Closed),
    ]);

    // Without an acceptance, the race ends every session left waiting and
    // frees the one attached before it
    run(vec![
        Open(1),
        RaceServerCloseOpen,
        Released(1),
        RefuseOpen(Closed),
    ]);
}

/// Request promises settle on peer answers and reply promises on local writes,
/// keeping their results after the session ends.
#[test]
fn test_operation_results() {
    use super::ExpectedMessage;
    use Failure::*;
    use Step::*;
    run(vec![
        // Take three requests for writing, with a wait blocked on the first
        Open(1),
        Accept(1),
        Request(1, 0, 10, 100),
        Request(1, 1, 11, 100),
        Request(1, 2, 12, 100),
        Outgoing(1, 0, ExpectedMessage::Request(10), 100),
        Outgoing(1, 1, ExpectedMessage::Request(11), 100),
        Outgoing(1, 2, ExpectedMessage::Request(12), 100),
        StartWait(0),
        // A successful write keeps the request pending until its answer
        Written(0, Ok(())),
        Deadline(1, Some(100)),
        // Answers settle requests with an error, a body or another body type
        Answer(1, Err(0x123)),
        Answer(0, Ok(20)),
        FinishWait(0, Ok(20)),
        AnswerOther(2),
        Request(1, 3, 13, 100),
        Outgoing(1, 3, ExpectedMessage::Request(13), 100),
        Answer(3, Ok(23)),
        // A reply settles on its first write result
        Deliver(1, 7, 30),
        Receive(1, 30, 0),
        Reply(0, 0, Ok(40), 100),
        Outgoing(1, 4, ExpectedMessage::Reply(7, Ok(40)), 100),
        StartWaitWrite(0),
        Written(4, Ok(())),
        Written(4, Err(Terminated)),
        Deadline(1, None),
        // Results outlive the session, and each wait checks the response type
        // it asks for
        CloseSession(1),
        DropSession(1),
        Released(1),
        Wait(1, Err(Remote(0x123))),
        Wait(2, Err(WrongType)),
        WaitMessage(3, 23),
        FinishWaitWrite(0, Ok(())),
    ]);
}

/// Results before the deadline survive a later wait, while results at or after
/// it become `Timeout` before any expiry runs.
#[test]
fn test_completion_deadline_boundary() {
    use super::ExpectedMessage;
    use Failure::*;
    use Step::*;

    // Settle a request and a reply just before, at and after their deadline
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
            // Later expiry and closure leave the settled results alone
            Time(200),
            Expire(1),
            CloseSession(1),
            Wait(0, answer),
            WaitWrite(0, written),
        ]);
    }

    // A late write failure becomes a timeout too, whatever its cause
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

/// Expiry settles overdue operations without a write result or a waiting caller,
/// discarding their queued messages and leaving the session usable.
#[test]
fn test_deadlines_without_writer_progress() {
    use super::ExpectedMessage;
    use Failure::*;
    use Step::*;
    run(vec![
        // Queue three requests and a reply, taking only the first request for
        // writing, with both promise kinds waiting
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
        // Expiry at 100 ms times out the due work and wakes both waits
        Deadline(1, Some(100)),
        Time(100),
        Expire(1),
        Deadline(1, Some(200)),
        FinishWait(0, Err(Timeout)),
        FinishWaitWrite(0, Err(Timeout)),
        // Only the request due later stays queued and gets answered, while a
        // late answer to the first changes nothing
        Outgoing(1, 1, ExpectedMessage::Request(12), 200),
        NoOutgoing(1),
        Answer(0, Ok(20)),
        Answer(1, Ok(22)),
        Wait(1, Err(Timeout)),
        Wait(2, Ok(22)),
        Deadline(1, None),
        // Submissions already past their deadline settle at once and queue
        // nothing
        Request(1, 3, 13, 100),
        Wait(3, Err(Timeout)),
        NoOutgoing(1),
        Deliver(1, 8, 31),
        Receive(1, 31, 1),
        Reply(1, 1, Ok(41), 99),
        WaitWrite(1, Err(Timeout)),
        NoOutgoing(1),
    ]);

    // Taking a queued message checks its deadline without a separate `expire()`
    run(vec![
        Open(1),
        Accept(1),
        Request(1, 0, 10, 100),
        Time(100),
        NoOutgoing(1),
        Wait(0, Err(Timeout)),
        Deadline(1, None),
    ]);

    // A wait after the deadline times out at once, since waiting never restarts
    // the deadline
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

/// Every way of ending a session fails its pending promises, with `Timeout` once
/// their deadline has passed.
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
            // Expect the ending's own reason before the deadline
            let reason = if time >= 100 {
                Timeout
            } else if matches!(ending, DropSource) {
                Terminated
            } else {
                Closed
            };
            run(vec![
                // Leave a request taken for writing, a queued request and a
                // queued reply pending, with both promise kinds waiting
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
                // End the session at the chosen time
                Time(time),
                ending,
                // Results arriving after the ending cannot replace its reason
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

/// Dropping a promise leaves its request or reply running to completion.
#[test]
fn test_observer_drop_keeps_operations() {
    use super::ExpectedMessage;
    use Step::*;
    run(vec![
        // Requests keep running after their promises drop, before or after the
        // write
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
        // A reply keeps running too, and its consumed responder queues no
        // second response
        Deliver(1, 7, 30),
        Receive(1, 30, 0),
        Reply(0, 0, Err(0x123), 100),
        DropWritePromise(0),
        Outgoing(1, 2, ExpectedMessage::Reply(7, Err(0x123)), 100),
        NoOutgoing(1),
        Written(2, Ok(())),
        Deadline(1, None),
        // An unobserved request still expires on its deadline
        Request(1, 2, 12, 100),
        DropPromise(2),
        Time(100),
        Expire(1),
        NoOutgoing(1),
        Deadline(1, None),
    ]);
}

/// An automatic reply gets the configured budget from its responder's drop, and
/// a failed or expired one is never retried.
#[test]
fn test_autoreply_timeout() {
    use super::ExpectedMessage;
    use Failure::*;
    use Step::*;
    use std::time::Duration;
    run(vec![
        // Set a 30 ms budget, keeping an unrelated request due at 200 ms in
        // flight throughout
        Open(1),
        Accept(1),
        AutoreplyTimeout(1, Duration::from_millis(30)),
        Request(1, 0, 10, 200),
        Outgoing(1, 0, ExpectedMessage::Request(10), 200),
        // A drop at 20 ms makes the reply due at 50 ms, queueing included
        Deliver(1, 7, 30),
        Receive(1, 30, 0),
        Time(20),
        DropReply(0),
        Deadline(1, Some(50)),
        Time(49),
        Outgoing(1, 1, ExpectedMessage::Reply(7, Err(1)), 50),
        // A write finishing at the deadline times out without a retry
        Time(50),
        Written(1, Ok(())),
        Deadline(1, Some(200)),
        NoOutgoing(1),
        // A failed write is not retried either
        Deliver(1, 8, 31),
        Receive(1, 31, 1),
        DropReply(1),
        Outgoing(1, 2, ExpectedMessage::Reply(8, Err(1)), 80),
        Written(2, Err(Terminated)),
        NoOutgoing(1),
        Deadline(1, Some(200)),
        // Nor is a reply that expires while queued
        Deliver(1, 9, 32),
        Receive(1, 32, 2),
        DropReply(2),
        Time(80),
        Expire(1),
        NoOutgoing(1),
        Deadline(1, Some(200)),
        // The unrelated request still completes, leaving nothing pending
        Answer(0, Ok(20)),
        Wait(0, Ok(20)),
        Deadline(1, None),
    ]);

    // Zero and unrepresentable budgets expire the reply at once, without a
    // panic from `Responder::drop`
    for budget in [Duration::ZERO, Duration::MAX] {
        run(vec![
            Open(1),
            Accept(1),
            AutoreplyTimeout(1, budget),
            Deliver(1, 7, 30),
            Receive(1, 30, 0),
            DropReply(0),
            NoOutgoing(1),
            Deadline(1, None),
        ]);
    }
}

/// Drops use the current timeout, queued replies keep their deadlines, and a
/// replacement session starts from the server's default.
#[test]
fn test_autoreply_timeout_updates() {
    use super::ExpectedMessage;
    use Step::*;
    use std::time::Duration;
    run(vec![
        // Hold three responders from before any timeout change
        Open(1),
        Accept(1),
        Deliver(1, 7, 30),
        Receive(1, 30, 0),
        Deliver(1, 8, 31),
        Receive(1, 31, 1),
        Deliver(1, 9, 32),
        Receive(1, 32, 2),
        // Each drop uses the timeout set at that moment, which later changes
        // never retime
        Time(20),
        DropReply(0), // uses the 5 s default
        AutoreplyTimeout(1, Duration::from_millis(30)),
        Outgoing(1, 0, ExpectedMessage::Reply(7, Err(1)), 5020),
        Written(0, Ok(())),
        DropReply(1), // held from before the change, yet uses 30 ms
        AutoreplyTimeout(1, Duration::from_millis(90)),
        Outgoing(1, 1, ExpectedMessage::Reply(8, Err(1)), 50),
        Written(1, Ok(())),
        DropReply(2),
        Outgoing(1, 2, ExpectedMessage::Reply(9, Err(1)), 110),
        Written(2, Ok(())),
        // A replacement session starts again from the server's default
        Open(2),
        Accept(2),
        Deliver(2, 10, 33),
        Receive(2, 33, 3),
        DropReply(3),
        Outgoing(2, 3, ExpectedMessage::Reply(10, Err(1)), 5020),
        Written(3, Ok(())),
    ]);
}

/// Server timeouts reach pending, accepted and future sessions without retiming
/// queued replies.
#[test]
fn test_server_autoreply_timeout() {
    use super::ExpectedMessage;
    use Step::*;
    run(vec![
        // A server timeout set before any session reaches the first one
        ServerInboundLimits(2, 100),
        ServerAutoreplyTimeout(Duration::from_millis(30)),
        Open(1),
        Accept(1),
        Deliver(1, 7, 11),
        Receive(1, 11, 0),
        Time(20),
        DropReply(0),
        // A change reaches the accepted session, while queued replies keep their
        // deadlines and request slots
        ServerAutoreplyTimeout(Duration::from_millis(40)),
        Deliver(1, 8, 12),
        Receive(1, 12, 1),
        DropReply(1),
        Usage(1, 2, 0),
        Outgoing(1, 0, ExpectedMessage::Reply(7, Err(1)), 50),
        Written(0, Ok(())),
        Outgoing(1, 1, ExpectedMessage::Reply(8, Err(1)), 60),
        Written(1, Ok(())),
        Usage(1, 0, 0),
        // A session override leaves the server default for the next session
        AutoreplyTimeout(1, Duration::from_millis(90)),
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
        // A later server change replaces a session override
        Deliver(2, 8, 15),
        Receive(2, 15, 4),
        AutoreplyTimeout(2, Duration::from_millis(90)),
        ServerAutoreplyTimeout(Duration::from_millis(50)),
        DropReply(4),
        Outgoing(2, 4, ExpectedMessage::Reply(8, Err(1)), 70),
        Written(4, Ok(())),
        // A change reaches a session attached but not yet accepted
        Open(3),
        Deliver(3, 7, 16),
        ServerAutoreplyTimeout(Duration::from_millis(60)),
        Accept(3),
        Receive(3, 16, 5),
        DropReply(5),
        Outgoing(3, 5, ExpectedMessage::Reply(7, Err(1)), 80),
        Written(5, Ok(())),
        // A change after server closure has no effect
        CloseServer,
        ServerAutoreplyTimeout(Duration::from_millis(70)),
        RefuseOpen(Failure::Closed),
        ReceiveError(3, Failure::Closed),
    ]);

    // Zero and unrepresentable server timeouts expire automatic replies at once,
    // freeing their request slots in every session
    for timeout in [Duration::ZERO, Duration::MAX] {
        run(vec![
            ServerInboundLimits(1, 100),
            ServerAutoreplyTimeout(timeout),
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

/// A server timeout update never misses a racing attachment, and a racing
/// responder drop uses the old or the new timeout.
#[test]
fn test_server_autoreply_timeout_races() {
    use crate::protocol::Server;

    // Race attachment against the server's timeout update
    let timeout = Duration::from_millis(30);
    for order in orders() {
        let tester = crate::transport::testing::test_clock();
        let (server, mut source) = Server::fixture(tester.clock());
        let (mut server, (_source, state)) = schedule(
            order,
            move || server.set_autoreply_timeout(timeout),
            move || {
                let state = source.open().unwrap().upgrade().unwrap();
                (source, state)
            },
        );
        let mut session = server.accept().unwrap();

        // Apply the winning timeout to the first abandoned request
        let now = tester.clock().now();
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

        // Race a later responder drop against another timeout update
        state.inject_request(3, vec![12].into()).unwrap();
        let mut session = session;
        let (session, responder) = Job::start(move || {
            let (_, responder) = session.recv().unwrap();
            (session, responder)
        })
        .finish();
        let (_server, ()) = schedule(
            order,
            move || server.set_autoreply_timeout(2 * timeout),
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

/// Late write results and answers reach only the replaced session, which its held
/// promises and handles do not keep alive.
#[test]
fn test_replacement_keeps_operation_handles_bound() {
    use super::ExpectedMessage;
    use Failure::*;
    use Step::*;
    run(vec![
        // Take a request and a reply for writing on the first session
        Open(1),
        Accept(1),
        Request(1, 0, 10, 100),
        Outgoing(1, 0, ExpectedMessage::Request(10), 100),
        Deliver(1, 7, 30),
        Receive(1, 30, 0),
        Reply(0, 0, Ok(40), 100),
        Outgoing(1, 1, ExpectedMessage::Reply(7, Ok(40)), 100),
        // Replace and free that session while its handles stay saved
        Open(2),
        Accept(2),
        DropSession(1),
        Released(1),
        // Take matching work for writing on the successor, reusing the reply ID
        Request(2, 1, 11, 100),
        Outgoing(2, 2, ExpectedMessage::Request(11), 100),
        Deliver(2, 7, 31),
        Receive(2, 31, 1),
        Reply(1, 1, Ok(41), 100),
        Outgoing(2, 3, ExpectedMessage::Reply(7, Ok(41)), 100),
        // Late results for the old work reach nothing, and its promises keep
        // the reset
        Written(0, Err(Terminated)),
        Answer(0, Ok(99)),
        Written(1, Ok(())),
        Wait(0, Err(Reset)),
        WaitWrite(0, Err(Reset)),
        // The successor's work is untouched and completes normally
        Deadline(2, Some(100)),
        Answer(2, Ok(21)),
        Written(3, Ok(())),
        Wait(1, Ok(21)),
        WaitWrite(1, Ok(())),
        Deadline(2, None),
    ]);
}

/// Closure racing a request fails it, and closure racing an answer leaves the
/// promise with exactly one of the two results.
#[test]
fn test_operation_close_races() {
    use super::ExpectedMessage;
    use Step::*;

    // Repeat both races to vary their interleaving
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

/// The deadline worker settles requests and replies while their promises wait.
#[test]
fn test_clock_settles_waiting_request_and_reply() {
    use Failure::*;
    use Step::*;

    // Park both promises before advancing the shared deadline worker's clock
    run(vec![
        Open(1),
        Accept(1),
        Request(1, 0, 1, 20),
        Deliver(1, 7, 30),
        Receive(1, 30, 0),
        Reply(0, 0, Ok(2), 20),
        StartWait(0),
        StartWaitWrite(0),
        Deadlines(1),
        Time(20),
        FinishWait(0, Err(Timeout)),
        FinishWaitWrite(0, Err(Timeout)),
        NoOutgoing(1),
        Deadline(1, None),
    ]);
}

/// A failed write settles its request or reply promise with that failure, which
/// later results cannot replace.
#[test]
fn test_write_failure_results() {
    use super::ExpectedMessage;
    use Failure::*;
    use Step::*;
    run(vec![
        // Take a request and a reply for writing, with both promise kinds waiting
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
        // Failed writes settle both, and later results change nothing
        Written(0, Err(Terminated)),
        Written(1, Err(Terminated)),
        Answer(0, Ok(99)),
        Written(1, Ok(())),
        // The failures survive the deadline and closure, leaving nothing queued
        // or pending
        Time(200),
        CloseSession(1),
        FinishWait(0, Err(Terminated)),
        FinishWaitWrite(0, Err(Terminated)),
        NoOutgoing(1),
        Deadline(1, None),
    ]);
}

/// Closure racing a reply fails it, and closure racing its write result leaves
/// the promise with exactly one of the two results.
#[test]
fn test_reply_close_races() {
    use super::ExpectedMessage;
    use Step::*;

    // Repeat both races to vary their interleaving
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

/// Encodes a host-to-Ark envelope with this ID and a one-byte development body.
fn incoming(id: u64, tag: u8) -> Vec<u8> {
    Side::Client.encode(id, Ok(vec![tag].into())).unwrap()
}

/// Encodes a host request with this ID whose only content is one byte in field
/// `0x7ff`, which this build does not know.
fn unknown(id: u64) -> Vec<u8> {
    let mut bytes = HostToArk {
        id,
        err: None,
        content: None,
    }
    .encode_to_vec();
    bytes.extend_from_slice(&[0xfa, 0x7f, 0x01, 0x2a]);
    bytes
}

/// An unknown request holds a request slot until the writer takes its `UNKNOWN`
/// reply, without buffering or delivering its body.
#[test]
fn test_unknown_request_content() {
    use super::ExpectedMessage;
    use Step::*;

    run(vec![
        // An unknown request holds a slot but no bytes
        Open(0),
        Accept(0),
        AutoreplyTimeout(0, Duration::from_millis(30)),
        Raw(0, unknown(1), Ok(())),
        Usage(0, 1, 0),
        // Taking its `UNKNOWN` reply frees the slot and the ID
        Outgoing(
            0,
            0,
            ExpectedMessage::Reply(1, Err(schema::ReservedErrors::Unknown as u64)),
            30,
        ),
        Usage(0, 0, 0),
        // A request reusing the ID reaches the application, and finishing the
        // old write does not release it
        Raw(0, incoming(1, 11), Ok(())),
        Receive(0, 11, 0),
        Written(0, Ok(())),
        Usage(0, 1, 0),
        Raw(0, unknown(1), Err(Failure::Malformed)),
    ]);
}

/// A queued `UNKNOWN` reply reserves its ID against known and unknown requests.
#[test]
fn test_unknown_request_duplicate_ids() {
    use Step::*;

    for duplicate in [unknown(1), incoming(1, 11)] {
        run(vec![
            Open(0),
            Accept(0),
            Raw(0, unknown(1), Ok(())),
            Raw(0, duplicate, Err(Failure::Malformed)),
        ]);
    }
}

/// Automatic replies share the request limit with application requests,
/// including when the limit is zero or lowered while a reply is queued.
#[test]
fn test_unknown_request_limits() {
    use Step::*;

    // Any mix of known and unknown requests past a limit of one closes the
    // session
    for (first, next) in [
        (unknown(1), unknown(3)),
        (unknown(1), incoming(3, 11)),
        (incoming(1, 11), unknown(3)),
    ] {
        run(vec![
            Open(0),
            Accept(0),
            InboundLimits(0, 1, DEFAULT_MAX_INBOUND_BYTES),
            Raw(0, first, Ok(())),
            Raw(0, next, Err(Failure::Requests)),
            Usage(0, 0, 0),
            NoOutgoing(0),
        ]);
    }

    // A zero limit refuses an unknown request, and lowering the limit below a
    // queued automatic reply closes the session
    run(vec![
        Open(0),
        Accept(0),
        InboundLimits(0, 0, DEFAULT_MAX_INBOUND_BYTES),
        Raw(0, unknown(1), Err(Failure::Requests)),
        Open(1),
        Accept(1),
        Raw(1, unknown(1), Ok(())),
        InboundLimits(1, 0, DEFAULT_MAX_INBOUND_BYTES),
        ReceiveError(1, Failure::Requests),
        NoOutgoing(1),
    ]);
}

/// Expiring an `UNKNOWN` reply frees its request slot and ID, even when it
/// expires on arrival.
#[test]
fn test_unknown_request_expiry() {
    use Step::*;

    run(vec![
        // Under a zero byte limit, an unknown request holds a slot and no bytes
        Open(0),
        Accept(0),
        InboundLimits(0, 1, 0),
        AutoreplyTimeout(0, Duration::from_millis(30)),
        Raw(0, unknown(1), Ok(())),
        Usage(0, 1, 0),
        // Expiring its reply frees the slot and the ID
        Deadline(0, Some(30)),
        Time(30),
        Expire(0),
        Usage(0, 0, 0),
        NoOutgoing(0),
        Deadline(0, None),
        // A zero timeout expires the reply on arrival, freeing both at once
        AutoreplyTimeout(0, Duration::ZERO),
        Raw(0, unknown(1), Ok(())),
        Usage(0, 0, 0),
        NoOutgoing(0),
        // The writer taking the reply frees the ID, and finishing that write
        // keeps the slot of a new request reusing it
        AutoreplyTimeout(0, Duration::from_millis(30)),
        Raw(0, unknown(1), Ok(())),
        Usage(0, 1, 0),
        SendNext(0, 0, 1),
        Usage(0, 0, 0),
        Raw(0, unknown(1), Ok(())),
        Written(0, Ok(())),
        Usage(0, 1, 0),
    ]);
}

/// A request slot follows the responder and queued reply, not just the inbox.
#[test]
fn test_inbound_request_accounting() {
    use super::ExpectedMessage;
    use Step::*;
    let size = incoming(1, 11).len();
    run(vec![
        // A request keeps its slot from the inbox until the writer takes its
        // reply
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
        // The next request can reuse the ID while that reply is being written
        Raw(0, incoming(1, 13), Ok(())),
        Usage(0, 1, size),
        Written(0, Ok(())),
        WaitWrite(0, Ok(())),
        // Expiring a queued reply frees its slot
        Receive(0, 13, 1),
        Reply(1, 1, Ok(14), 10),
        Time(10),
        Expire(0),
        WaitWrite(1, Err(Failure::Timeout)),
        Usage(0, 0, 0),
        // So does an automatic reply that expires at once
        Raw(0, incoming(1, 15), Ok(())),
        Receive(0, 15, 2),
        AutoreplyTimeout(0, std::time::Duration::ZERO),
        DropReply(2),
        Usage(0, 0, 0),
    ]);

    // A receive waiting beside a held responder wakes when the next request
    // overflows, and a replacement session starts with free slots
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

/// Admission charges the original envelope bytes, unknown fields and repeated IDs
/// included.
#[test]
fn test_inbound_original_byte_accounting() {
    use Step::*;

    // Pad a request with an unknown field and a repeated, non-canonical ID
    let mut bytes = incoming(1, 11);
    bytes.extend_from_slice(&[0x18, 0, 0x08, 0x81, 0]);
    let size = bytes.len();

    // The padded request fits a byte limit of exactly its length, and lowering
    // the limit below a queued request closes the session
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

    // A limit one byte short refuses the padded request and wakes a blocked
    // receive
    run(vec![
        Open(0),
        Accept(0),
        InboundLimits(0, DEFAULT_MAX_INBOUND_REQUESTS, size - 1),
        StartReceive(0),
        Raw(0, bytes, Err(Failure::Bytes)),
        FinishReceiveError(0, Failure::Bytes),
    ]);

    // A zero limit of either kind refuses the first request
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
        // Reading a response releases its bytes, even after its deadline
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
        // Dropping the promise releases them too
        Request(0, 1, 2, 20),
        SendNext(0, 1, 4),
        Raw(0, incoming(4, 12), Ok(())),
        Usage(0, 0, bytes),
        DropPromise(1),
        Usage(0, 0, 0),
        // Closure keeps the charge on the old session, and a replacement starts
        // empty
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

    // A response past the byte limit closes the session, while the unread one
    // before it stays readable
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
        // Fill the byte limit with one unread response
        Open(0),
        Accept(0),
        InboundLimits(0, DEFAULT_MAX_INBOUND_REQUESTS, incoming(2, 11).len()),
        Request(0, 0, 1, 10),
        SendNext(0, 0, 2),
        Raw(0, incoming(2, 11), Ok(())),
        // A malformed answer to a dropped promise, then its repeat to a spent
        // ID, are discarded without a charge
        Request(0, 1, 2, 10),
        SendNext(0, 1, 4),
        DropPromise(1),
        Raw(0, malformed.clone(), Ok(())),
        Raw(0, malformed, Ok(())),
        // So is an answer arriving after its deadline
        Request(0, 2, 3, 1),
        SendNext(0, 2, 6),
        Time(1),
        Raw(0, incoming(6, 13), Ok(())),
        Wait(2, Err(Failure::Timeout)),
        // Only the unread response stays charged, and the session stays open
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
        // Lowering the server limit closes a session not yet accepted, and
        // raising it never reopens the session
        ServerInboundLimits(1, 100),
        Open(0),
        Raw(0, incoming(1, 11), Ok(())),
        ServerInboundLimits(0, 100),
        Accept(0),
        ReceiveError(0, Failure::Requests),
        InboundLimits(0, 100, DEFAULT_MAX_INBOUND_BYTES),
        ReceiveError(0, Failure::Requests),
        // Lowering the byte limit closes the accepted session and binds the
        // next one
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
        // Raising a session's own limit admits more requests
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

    // A byte limit lowered below an unread response closes the session, and the
    // response stays readable
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

    // A malformed request is admitted, then closes the session when received
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

    // A malformed body or error settles its promise, then fails when read
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

        // Reading it after a replacement closes only the original session
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

    // Encode a request carrying an identity
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

    // The received message keeps the identity from the first occurrence
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
        // Fill the budget with an unread response and a queued request
        Open(0),
        Accept(0),
        InboundLimits(0, 2, 2 * size),
        Request(0, 0, 10, 10),
        SendNext(0, 0, 2),
        Raw(0, incoming(2, 11), Ok(())),
        Raw(0, incoming(1, 12), Ok(())),
        Usage(0, 1, 2 * size),
        // An answer past the full budget still reaches its request, whose
        // promise gets the capacity error
        Request(0, 1, 20, 10),
        SendNext(0, 1, 4),
        Raw(0, incoming(4, 21), Err(Failure::Bytes)),
        Wait(1, Err(Failure::Bytes)),
        // Closure discards the queued request, and the unread response
        // outlives the session
        Usage(0, 0, size),
        DropSession(0),
        Released(0),
        Wait(0, Ok(11)),
    ]);

    // A request past the full budget closes the session, and dropping the
    // unread response releases the rest
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

    // Race session attachment against both kinds of server limit update
    for (requests, bytes, reason) in [(0, 100, Failure::Requests), (1, 0, Failure::Bytes)] {
        for _ in 0..16 {
            let tester = crate::transport::testing::test_clock();
            let (server, mut source) = Server::fixture(tester.clock());
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

            // Require the attached session to enforce the new limits
            let result = state.upgrade().unwrap().inject_request(1, vec![11].into());
            assert_eq!(result.map_err(super::failure), Err(reason));
            assert_eq!(super::failure(session.recv().err().unwrap()), reason);
        }
    }
}

/// Order of two calls, one after the other or competing.
#[derive(Clone, Copy)]
enum Order {
    /// The left call finishes before the right one starts.
    LeftFirst,
    /// Both calls start together from one barrier.
    Concurrent,
    /// The right call finishes before the left one starts.
    RightFirst,
}

/// Runs two calls on their own threads in the chosen order and returns both
/// results.
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

/// Returns both fixed orders, then the competing order 16 times.
fn orders() -> impl Iterator<Item = Order> {
    [Order::LeftFirst, Order::RightFirst]
        .into_iter()
        .chain(std::iter::repeat_n(Order::Concurrent, 16))
}

/// Creates a fixture session with these inbound limits, and a deadline 1 s ahead
/// on its test clock.
fn fixture(requests: usize, bytes: usize) -> (Session, Instant) {
    let session = Session::fixture().set_inbound_limits(requests, bytes);
    let now = session.clock().now();
    (session, now + Duration::from_secs(1))
}

/// Submits a request and takes it the way the writer would, returning its wire
/// ID and promise.
fn request(session: &Session, deadline: Instant) -> (u64, Promise<Message>) {
    let promise = session.requester().request(vec![1], deadline).unwrap();
    let (id, _) = session.inner.next_outgoing().unwrap();
    (id, promise)
}

/// Passes envelope bytes to the session as its reader does, closing the session
/// with the failure it returns.
fn deliver(session: &Arc<SessionInner>, bytes: Vec<u8>) -> Result<(), Error> {
    let result = session.handle_message(bytes);
    if let Err(error) = &result {
        session.close(error.clone());
    }
    result
}

/// Asserts that a result failed on the inbound byte limit, reporting this limit.
fn byte_error<T>(result: Result<T, Error>, limit: usize) {
    assert!(matches!(result, Err(Error::InboundByteLimitExceeded(actual)) if actual == limit));
}

/// Asserts that a result failed on the inbound request limit, reporting this
/// limit.
fn request_error<T>(result: Result<T, Error>, limit: usize) {
    assert!(matches!(result, Err(Error::InboundRequestLimitExceeded(actual)) if actual == limit));
}

/// A response admitted while another is released fits only after the release,
/// and leaks no bytes either way.
#[test]
fn test_release_races_response_admission() {
    for consume in [false, true] {
        for order in orders() {
            // Fill a budget of one response with the first answer
            let size = incoming(2, 11).len();
            let (session, deadline) = fixture(0, size);
            let (a, first) = request(&session, deadline);
            let (b, second) = request(&session, deadline);
            deliver(&session.inner, incoming(a, 11)).unwrap();

            // Race releasing it, by reading or dropping, against the second
            // answer
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

            // Fixed orders decide admission, while competing calls may go
            // either way
            match order {
                Order::LeftFirst => assert!(delivered.is_ok()),
                Order::RightFirst => byte_error(delivered.as_ref().map_err(Clone::clone), size),
                Order::Concurrent => {}
            }

            // An admitted answer is readable, a refused one closes the session for
            // every caller, and nothing stays charged
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

/// A byte limit failure is returned for closing the session only if the promise
/// survives until delivery, and the bytes are released either way.
#[test]
fn test_observer_drop_during_response_completion() {
    // Vary admission and observer lifetime independently
    for admit in [false, true] {
        for drop_observer in [false, true] {
            // Prepare a pending request and a byte limit admitting its answer
            // or not
            let bytes = incoming(2, 11);
            let header = Side::Server.decode_header(bytes.clone().into()).unwrap();
            let limit = if admit { bytes.len() } else { 0 };
            let used = Arc::new(AtomicUsize::new(0));
            let counter = used.clone();
            let tester = crate::transport::testing::test_clock();
            let now = tester.clock().now();
            let (sender, promise) =
                Promise::<Message>::pair(Weak::new(), now + Duration::from_secs(60), true);
            let pending = PendingOperation {
                deadline: now + Duration::from_secs(60),
                sender,
                log_id: None,
            };

            // Hold response completion after its byte reservation
            let (entered, reserved) = mpsc::channel();
            let (release, released) = mpsc::channel();
            let completed = Job::start(move || {
                let mut notifications = crate::protocol::promise::Notifications::default();
                pending.complete_response(now, &mut notifications, || {
                    let result = IncomingEnvelope::new(
                        bytes.into(),
                        header,
                        &counter,
                        limit,
                        Side::Server,
                        Weak::new(),
                    );
                    entered.send(()).unwrap();
                    released.recv().unwrap();
                    result
                })
            });
            reserved.recv().unwrap();
            assert_eq!(used.load(Ordering::Relaxed), limit);

            // Drop or retain the observer before releasing response completion
            let promise = if drop_observer {
                drop(promise);
                None
            } else {
                Some(promise)
            };
            release.send(()).unwrap();
            let result = completed.finish();

            // Only a refused reservation with a live promise fails, and no
            // bytes stay charged
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

/// Lowering a limit while a request or response arrives closes the session in
/// either order.
#[test]
fn test_limits_race_request_and_response_admission() {
    for order in orders() {
        // Race a lower request limit against a second request
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

        // Either way the request limit closes the session, failing the pending
        // request and releasing everything
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

        // Race a lower byte limit against a second response
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

        // Either way the byte limit closes the session, while the responses
        // already admitted stay readable
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

/// Lowering a limit after its last charge is released keeps the session open,
/// and lowering it first closes the session.
#[test]
fn test_limits_race_consumers_and_reply_writes() {
    for order in orders() {
        // Race a zero byte limit against reading the only response
        let (session, deadline) = fixture(1, 100);
        let (id, promise) = request(&session, deadline);
        deliver(&session.inner, incoming(id, 11)).unwrap();
        let (answer, session) = schedule(
            order,
            move || promise.wait::<Vec<u8>>(),
            move || session.set_inbound_limits(1, 0),
        );

        // The answer survives either way, and the session stays open only if
        // the read came first
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

        // Race a zero request limit against the writer taking the only reply
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

        // The session stays open only if the writer took the reply first, which
        // then completes
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

/// Encodes three host envelopes with this ID that pass the outer checks but fail
/// nested decoding.
///
/// They carry a truncated body, a truncated error and error text that is not
/// UTF-8.
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

/// Malformed buffered responses fail decoding while late arrivals settle as timeouts.
#[test]
fn test_malformed_response_observation_and_deadlines() {
    use Step::*;
    for (shape, bytes) in malformed(2).into_iter().enumerate() {
        // The envelope runner rejects the same bytes, which also seeds its fuzz
        // target when seeds are collected
        let mut input = vec![0];
        input.extend_from_slice(&bytes);
        assert!(!super::super::envelope::run(&input));

        // A malformed response accepted in time fails when read, even after its
        // deadline, and closes the session
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

        // Answers at or after the deadline skip nested decoding and need no
        // bytes, whether or not expiry already removed the operation
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

        // Dropping the promise releases an unread malformed response, and later
        // answers skip decoding
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
            // A repeated, an unobserved and an unknown answer need no bytes and
            // leave the session open
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

/// Repeated envelope fields decode by protobuf's merge rules, while a malformed
/// earlier payload still fails.
#[test]
fn test_repeated_payload_fields() {
    // Repeat an error, keeping the first code and the second message
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

    // The envelope runner and the session both accept the merged error, and
    // reading it releases its bytes
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

    // A later content alternative replaces an earlier one, which still has to
    // decode
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
    // Exercise request and response routing in each envelope direction
    for (side, peer, peer_id) in [
        (Side::Server, Side::Client, 1),
        (Side::Client, Side::Server, 2),
    ] {
        for is_response in [false, true] {
            // Encode the body under an ID of the other route, which a later ID
            // overrides
            let session = Session::fixture_for(side).set_inbound_limits(1, 100);
            let deadline = session.clock().now() + Duration::from_secs(60);
            let (own, promise) = request(&session, deadline);
            let (first, last) = if is_response {
                (peer_id, own)
            } else {
                (own, peer_id)
            };
            let mut bytes = peer.encode(first, Ok(vec![11].into())).unwrap();

            // Append an ID-only envelope, adding a scalar occurrence but no content
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

            // The envelope runner and the session both accept it, routed by the
            // final ID
            let mut input = vec![u8::from(side == Side::Client)];
            input.extend_from_slice(&bytes);
            assert!(super::super::envelope::run(&input));
            let size = bytes.len();
            deliver(&session.inner, bytes).unwrap();
            assert_eq!(
                session.inner.inbound_usage(),
                (usize::from(!is_response), size)
            );

            // A response answers our request, while a request leaves ours for
            // its own answer
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

/// Encodes a peer envelope of exactly
/// [`MAX_MESSAGE_SIZE`](crate::transport::MAX_MESSAGE_SIZE), returning it with
/// its payload length.
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

/// Byte limits around the maximum message size apply exactly to requests,
/// responses and errors in both roles.
#[test]
fn test_large_inbound_boundaries_and_error_values() {
    // Exercise exact byte limits for requests, successful responses and errors
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
                    // Deliver a request, response or error of the maximum size
                    let mut session = Session::fixture_for(side).set_inbound_limits(1, limit);
                    let (id, promise) = if response {
                        let (id, promise) =
                            request(&session, session.clock().now() + Duration::from_secs(60));
                        (id, Some(promise))
                    } else {
                        (peer_id, None)
                    };
                    let (bytes, payload) = large_envelope(peer, id, error);
                    let result = deliver(&session.inner, bytes);

                    // A limit one byte short closes the session for every
                    // caller, while a fit delivers the payload intact
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

    // Lowering a limit reports the configured value, and the request limit
    // wins when one update exceeds both
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
