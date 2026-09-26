// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Scenarios through public constructors, real crypto/framing, and gated adapters.

use crate::protocol::{DEFAULT_MAX_INBOUND_BYTES, DEFAULT_MAX_INBOUND_REQUESTS};

use super::{BUDGET, Driver, EnvelopeShape, Failure, Job, Mode, Step, WRITE_BUDGET, run};
use crate::protocol::{Error, Message};
use crate::transport;
use crate::transport::mock::duplex::Operation;
use std::io;
use std::sync::{Arc, Barrier};

/// Both peers queue multiple requests before waiting for answers or calling `recv()`.
#[test]
fn test_bidirectional_exchange() {
    use Step::*;
    run(
        Mode::Both,
        &[
            // Queue two host requests and one Ark request after a typed exchange
            TypedExchange,
            Request(0, 0, 10, 3000),
            Request(0, 1, 11, 3000),
            Request(1, 2, 12, 3000),
            // Receive them all, then reply out of order
            Receive(1, 10, 0),
            Receive(1, 11, 1),
            Receive(0, 12, 2),
            Reply(1, 1, Ok(21), 3000),
            Reply(2, 2, Ok(22), 3000),
            Reply(0, 0, Ok(20), 3000),
            // Collect every answer and write result
            Answer(1, Ok(21)),
            Answer(0, Ok(20)),
            Answer(2, Ok(22)),
            Written(0, Ok(())),
            Written(1, Ok(())),
            Written(2, Ok(())),
            // Shut down and require every worker to exit
            Shutdown,
            Stopped,
        ],
    );
}

/// Both roles fail requests with reserved and custom errors, from zero to the
/// largest code, without closing the session.
#[test]
fn test_error_replies() {
    use crate::protocol::schema;

    // Connect both roles, then fail one request per error on each side
    let mut driver = Driver::new(Mode::Both);
    for local in [0, 1] {
        for (error, code, text) in [
            (
                schema::Error::reserved(schema::ReservedErrors::Unspecified, "not ready"),
                0,
                "not ready",
            ),
            (
                schema::Error::reserved(schema::ReservedErrors::Unanswered, "handler stopped"),
                1,
                "handler stopped",
            ),
            (
                schema::Error::new(u64::MAX, String::from("request refused")),
                u64::MAX,
                "request refused",
            ),
        ] {
            // Request from the peer and fail it on the local session
            let deadline = driver.tester.clock().now() + BUDGET;
            let answer = driver.requesters[&(1 - local)]
                .request(vec![11], deadline)
                .unwrap();
            let mut session = driver.sessions.remove(&local).unwrap();
            let (session, written) = Job::start(move || {
                let (message, responder) = session.recv().unwrap();
                assert_eq!(message, Message::Develop(vec![11]));
                let written = responder.fail(error, deadline).unwrap();
                (session, written)
            })
            .finish();

            // Require the peer to get the exact code and message
            let error = Job::start(move || answer.wait::<Vec<u8>>())
                .finish()
                .unwrap_err();
            let Error::Remote(error) = error else {
                panic!("expected remote error, got {error:?}");
            };
            assert_eq!(error.code, code);
            assert_eq!(error.msg, text);

            // Require the failure to be written and the request to be released
            Job::start(move || written.wait()).finish().unwrap();
            assert_eq!(session.inner.inbound_usage(), (0, 0));
            driver.sessions.insert(local, session);
        }
    }

    // Require both sessions to stay usable, then shut down
    driver.step(Step::TypedExchange);
    driver.step(Step::Shutdown);
    driver.step(Step::Stopped);
}

/// Cloned requesters submit concurrently without losing requests or sharing IDs,
/// and reversed answers reach the original promises.
#[test]
fn test_concurrent_requesters() {
    /// Number of threads submitting requests at once.
    const PRODUCERS: u8 = 8;
    /// Number of requests each producer submits.
    const REQUESTS: u8 = 8;

    // Start the producers together on one connection per role
    crate::testing::init_tracing();
    for (mode, local, first) in [(Mode::Client, 0, 1), (Mode::Server, 1, 2)] {
        let mut driver = Driver::new(mode);
        let start = Arc::new(Barrier::new(PRODUCERS as usize));
        let jobs: Vec<_> = (0..PRODUCERS)
            .map(|producer| {
                let requester = driver.requesters[&local].clone();
                let start = start.clone();
                Job::start(move || {
                    start.wait();
                    (0..REQUESTS)
                        .map(|index| {
                            let tag = producer * REQUESTS + index;
                            let promise = requester
                                .request(vec![tag], requester.clock().now() + BUDGET)
                                .unwrap();
                            (tag, promise)
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let promises: Vec<_> = jobs.into_iter().flat_map(Job::finish).collect();

        // Read every request, requiring consecutive IDs in arrival order
        let raw = driver.raw.as_mut().unwrap();
        let mut received = Vec::new();
        for index in 0..PRODUCERS * REQUESTS {
            let (id, body) = raw.read();
            assert_eq!(id, first + 2 * u64::from(index));
            let EnvelopeShape::Content(tag) = body else {
                panic!("expected request content");
            };
            received.push((id, tag));
        }

        // Require every submitted tag exactly once
        let mut tags: Vec<_> = received.iter().map(|&(_, tag)| tag).collect();
        tags.sort_unstable();
        assert_eq!(tags, (0..PRODUCERS * REQUESTS).collect::<Vec<_>>());

        // Answer in reverse order and require each promise to get its own answer
        for (id, tag) in received.into_iter().rev() {
            raw.send(id, EnvelopeShape::Content(tag + 100)).unwrap();
        }
        for (tag, promise) in promises {
            assert_eq!(promise.wait::<Vec<u8>>().unwrap(), vec![tag + 100]);
        }
        driver.step(Step::Outstanding(local, vec![]));
    }
}

/// Out-of-order answers, unknown IDs and duplicates cannot complete the wrong promise.
#[test]
fn test_response_correlation() {
    use Step::*;
    for (mode, local, first) in [(Mode::Client, 0, 1), (Mode::Server, 1, 2)] {
        run(
            mode,
            &[
                // Send two requests
                Request(local, 0, 10, 3000),
                Request(local, 1, 11, 3000),
                Read(first, EnvelopeShape::Content(10)),
                Read(first + 2, EnvelopeShape::Content(11)),
                // Answer the second first, after an unknown ID
                Send(first + 100, EnvelopeShape::Content(99)),
                Send(first + 2, EnvelopeShape::Content(21)),
                Answer(1, Ok(21)),
                Outstanding(local, vec![first]),
                // Repeat the second answer, then fail the first request
                Send(first + 2, EnvelopeShape::Content(99)),
                Send(first, EnvelopeShape::Error(0x123)),
                Answer(0, Err(Failure::Remote(0x123))),
                Outstanding(local, vec![]),
                // Require a later request to complete normally
                Request(local, 2, 12, 3000),
                Read(first + 4, EnvelopeShape::Content(12)),
                Send(first + 4, EnvelopeShape::Content(22)),
                Answer(2, Ok(22)),
            ],
        );
    }
}

/// Incoming IDs are opaque within their parity, including zero and descending IDs.
#[test]
fn test_unordered_peer_requests() {
    use Step::*;
    for (mode, local, ids) in [
        (Mode::Client, 0, [100, 0, 2]),
        (Mode::Server, 1, [u64::MAX, 7, 1]),
    ] {
        run(
            mode,
            &[
                // Receive three peer requests with unordered IDs
                Send(ids[0], EnvelopeShape::Content(10)),
                Send(ids[1], EnvelopeShape::Content(11)),
                Send(ids[2], EnvelopeShape::Content(12)),
                Receive(local, 10, 0),
                Receive(local, 11, 1),
                Receive(local, 12, 2),
                // Reply to the last, abandon the first and fail the second
                Reply(2, 2, Ok(22), 3000),
                Read(ids[2], EnvelopeShape::Content(22)),
                Written(2, Ok(())),
                Abandon(0),
                Read(ids[0], EnvelopeShape::Error(1)),
                Reply(1, 1, Err(0x100), 3000),
                Read(ids[1], EnvelopeShape::Error(0x100)),
                Written(1, Ok(())),
                // Reuse the answered last ID and abandon that request too
                Send(ids[2], EnvelopeShape::Content(13)),
                Receive(local, 13, 3),
                Abandon(3),
                Read(ids[2], EnvelopeShape::Error(1)),
            ],
        );
    }
}

/// An invalid envelope closes the session, after which a server accepts a new
/// one.
#[test]
fn test_strict_envelope_validation() {
    use Step::*;
    for (mode, local, request, response) in [(Mode::Client, 0, 2, 1), (Mode::Server, 1, 1, 2)] {
        for (id, body) in [
            (request, EnvelopeShape::Both),
            (response, EnvelopeShape::Both),
            (request, EnvelopeShape::Neither),
            (response, EnvelopeShape::Neither),
            (request, EnvelopeShape::Error(1)),
            (request, EnvelopeShape::Invalid),
        ] {
            // Close the session with the envelope while a receive waits
            let mut steps = vec![
                StartReceive(local),
                Reject(id, body),
                ReceiveFailed(local, Failure::Malformed),
                Refused(local),
            ];

            // Require a server to accept a working replacement
            if matches!(mode, Mode::Server) {
                steps.extend([
                    Reconnect(2),
                    Request(2, 0, 7, 3000),
                    Read(2, EnvelopeShape::Content(7)),
                    Send(2, EnvelopeShape::Content(8)),
                    Answer(0, Ok(8)),
                ]);
            }
            run(mode, &steps);
        }
    }
}

/// A duplicate remains invalid while the first request or its reply is queued,
/// or while the application still holds its responder.
#[test]
fn test_duplicate_active_request_ids() {
    use Step::*;
    for (mode, local, id, outgoing) in [(Mode::Client, 0, 2, 0), (Mode::Server, 1, 1, 1)] {
        for phase in 0..3 {
            // Leave the first request queued, held by a responder, or answered
            // behind a blocked write
            let mut steps = vec![Send(id, EnvelopeShape::Content(1))];
            if phase != 0 {
                steps.push(Receive(local, 1, 0));
            }
            if phase == 2 {
                steps.extend([
                    Pause(outgoing, Operation::Write, true),
                    Request(local, 9, 9, 3000),
                    Blocked(outgoing, Operation::Write),
                    Reply(0, 0, Ok(2), 3000),
                ]);
            }

            // Check closure through a pending promise. `recv()` could instead
            // return the first queued request before the duplicate is processed.
            steps.extend([
                Request(local, 1, 3, 3000),
                Reject(id, EnvelopeShape::Content(9)),
                Answer(1, Err(Failure::Malformed)),
                Refused(local),
            ]);

            // Require the queued reply and the blocked request to fail too
            if phase == 2 {
                steps.extend([
                    Written(0, Err(Failure::Malformed)),
                    Answer(9, Err(Failure::Malformed)),
                    Pause(outgoing, Operation::Write, false),
                ]);
            }
            run(mode, &steps);
        }
    }
}

/// A request that expires during its write still reaches the peer as a whole
/// frame.
#[test]
fn test_deadline_during_write() {
    use Step::*;
    for (mode, local, id, outgoing) in [(Mode::Client, 0, 1, 0), (Mode::Server, 1, 2, 1)] {
        run(
            mode,
            &[
                // Expire the request while its write is parked
                Pause(outgoing, Operation::Write, true),
                Request(local, 0, 10, 50),
                Notify(0, 7),
                Blocked(outgoing, Operation::Write),
                Advance(50),
                Notified(7),
                Answer(0, Err(Failure::Timeout)),
                Outstanding(local, vec![id]),
                // Let its frame reach the peer, whose late answer frees the ID
                Pause(outgoing, Operation::Write, false),
                Read(id, EnvelopeShape::Content(10)),
                Send(id, EnvelopeShape::Content(20)),
                // Require the next request to ignore a repeat of the old answer
                Request(local, 1, 11, 3000),
                Read(id + 2, EnvelopeShape::Content(11)),
                Send(id, EnvelopeShape::Content(99)),
                Send(id + 2, EnvelopeShape::Content(21)),
                Answer(1, Ok(21)),
                Outstanding(local, vec![]),
            ],
        );
    }
}

/// A reply can reach the peer after its write promise times out.
#[test]
fn test_reply_deadline_during_flush() {
    use Step::*;
    for (mode, local, request, outgoing) in [(Mode::Client, 0, 2, 0), (Mode::Server, 1, 1, 1)] {
        run(
            mode,
            &[
                // Receive a peer request and block its reply's flush
                Send(request, EnvelopeShape::Content(10)),
                Receive(local, 10, 0),
                Pause(outgoing, Operation::Flush, true),
                Reply(0, 0, Ok(20), 50),
                NotifyWrite(0, 7),
                Blocked(outgoing, Operation::Flush),
                // Expire the reply promise while its complete frame waits in flush
                Advance(50),
                Notified(7),
                Written(0, Err(Failure::Timeout)),
                // Deliver the reply anyway and keep serving the peer
                Read(request, EnvelopeShape::Content(20)),
                Pause(outgoing, Operation::Flush, false),
                Send(request + 2, EnvelopeShape::Content(11)),
                Receive(local, 11, 1),
                Abandon(1),
                Read(request + 2, EnvelopeShape::Error(1)),
            ],
        );
    }
}

/// A response can complete its promise before the outgoing request's flush returns.
#[test]
fn test_response_before_send_completion() {
    use Step::*;
    for (mode, local, id, outgoing) in [(Mode::Client, 0, 1, 0), (Mode::Server, 1, 2, 1)] {
        run(
            mode,
            &[
                // Block a request's flush after its frame is written
                Pause(outgoing, Operation::Flush, true),
                Request(local, 0, 10, 3000),
                Notify(0, 7),
                Blocked(outgoing, Operation::Flush),
                // Answer it, completing the promise while the flush still blocks
                Read(id, EnvelopeShape::Content(10)),
                NoNotifications,
                Send(id, EnvelopeShape::Content(20)),
                Notified(7),
                Answer(0, Ok(20)),
                NoNotifications,
                Pause(outgoing, Operation::Flush, false),
            ],
        );
    }
}

/// A reply notifies only once the writer flushes, without any promise waiter.
#[test]
fn test_writer_notifications() {
    use Step::*;
    for (mode, local, request, outgoing) in [(Mode::Client, 0, 2, 0), (Mode::Server, 1, 1, 1)] {
        run(
            mode,
            &[
                // Block a reply's flush after the peer reads its frame
                Send(request, EnvelopeShape::Content(10)),
                Receive(local, 10, 0),
                Pause(outgoing, Operation::Flush, true),
                Reply(0, 0, Ok(20), 3000),
                NotifyWrite(0, 7),
                Blocked(outgoing, Operation::Flush),
                Read(request, EnvelopeShape::Content(20)),
                NoNotifications,
                // Notify only once the flush returns
                Pause(outgoing, Operation::Flush, false),
                Notified(7),
                Written(0, Ok(())),
                NoNotifications,
            ],
        );
    }
}

/// An answer buffered before a failed flush survives the closure, while work
/// queued behind that flush fails with the transport.
#[test]
fn test_response_before_send_failure() {
    use Step::*;
    for (mode, local, id, peer, outgoing) in
        [(Mode::Client, 0, 1, 2, 0), (Mode::Server, 1, 2, 1, 1)]
    {
        for (body, result) in [
            (EnvelopeShape::Content(20), Ok(20)),
            (EnvelopeShape::Error(0x123), Err(Failure::Remote(0x123))),
        ] {
            run(
                mode,
                &[
                    // Answer a request while its flush is blocked
                    Pause(outgoing, Operation::Flush, true),
                    Request(local, 0, 10, 3000),
                    Blocked(outgoing, Operation::Flush),
                    Read(id, EnvelopeShape::Content(10)),
                    Send(id, body),
                    // Receiving the next peer message proves the reader processed
                    // the answer, without consuming its promise before closure
                    Send(peer, EnvelopeShape::Content(30)),
                    Receive(local, 30, 0),
                    Outstanding(local, vec![]),
                    // Queue more work, then fail the flush while a receive waits
                    Request(local, 1, 11, 3000),
                    Reply(0, 0, Ok(40), 3000),
                    StartReceive(local),
                    Fault(outgoing, Operation::Flush, io::ErrorKind::BrokenPipe),
                    Pause(outgoing, Operation::Flush, false),
                    // The buffered answer survives while the queued work fails
                    ReceiveFailed(local, Failure::Transport),
                    Answer(0, result),
                    Answer(1, Err(Failure::Transport)),
                    Written(0, Err(Failure::Transport)),
                    Refused(local),
                ],
            );
        }
    }
}

/// Write failures wake `Session::recv()` even while the transport reader is blocked.
#[test]
fn test_send_failure_wakes_receivers() {
    use Step::*;
    for (mode, local, outgoing) in [(Mode::Client, 0, 0), (Mode::Server, 1, 1)] {
        for op in [Operation::Write, Operation::Flush] {
            run(
                mode,
                &[
                    // Arm a write or flush failure while a receive waits
                    StartReceive(local),
                    Fault(outgoing, op, io::ErrorKind::BrokenPipe),
                    // Trip it with a request, which fails along with the receive
                    Request(local, 0, 10, 3000),
                    Answer(0, Err(Failure::Transport)),
                    ReceiveFailed(local, Failure::Transport),
                    Refused(local),
                ],
            );
        }
    }
}

/// A fatal read wakes blocked receives and accepts, and fails every pending or
/// later call with the read's cause.
#[test]
fn test_read_failure_wakes_callers() {
    use Step::*;
    crate::testing::init_tracing();
    for (mode, local, first, peer, incoming) in
        [(Mode::Client, 0, 1, 2, 1), (Mode::Server, 1, 2, 1, 0)]
    {
        for eof in [false, true] {
            // Leave two requests, a responder and a receive pending while the
            // reader blocks
            let mut driver = Driver::new(mode);
            for step in [
                Send(peer, EnvelopeShape::Content(30)),
                Receive(local, 30, 0),
                Request(local, 0, 10, 3000),
                Request(local, 1, 11, 3000),
                Read(first, EnvelopeShape::Content(10)),
                Read(first + 2, EnvelopeShape::Content(11)),
                StartReceive(local),
                Blocked(incoming, Operation::Read),
            ] {
                driver.step(step);
            }

            // Park an accept on the server too, where the mode has one
            let accepting = driver.server.take().map(|mut server| {
                let waiting = server.inner.watch_accept_wait();
                let job = Job::start(move || {
                    let error = server.accept().expect_err("accept must fail");
                    (server, error)
                });
                waiting.recv().unwrap();
                job
            });

            // Fail the blocked read with EOF or an adapter error
            if eof {
                driver.pipes[incoming as usize].close();
            } else {
                driver.step(Fault(incoming, Operation::Read, io::ErrorKind::BrokenPipe));
            }

            // Collect the errors of every woken call and of later submissions
            let mut errors = Vec::new();
            for slot in [0, 1] {
                errors.push(
                    driver
                        .promises
                        .remove(&slot)
                        .unwrap()
                        .wait_worker_result()
                        .unwrap_err(),
                );
            }
            let (session, result) = driver.receiving.remove(&local).unwrap().finish();
            errors.push(result.expect_err("receive must fail"));
            driver.sessions.insert(local, session);
            if let Some(accepting) = accepting {
                let (server, error) = accepting.finish();
                errors.push(error);
                driver.server = Some(server);
            }
            errors.push(
                driver.requesters[&local]
                    .request(vec![12], driver.tester.clock().now() + BUDGET)
                    .expect_err("request must fail"),
            );
            errors.push(
                driver
                    .responders
                    .remove(&0)
                    .unwrap()
                    .reply(vec![31], driver.tester.clock().now() + BUDGET)
                    .expect_err("reply must fail"),
            );

            // Require each error to carry the read's cause
            for error in errors {
                let Error::Transport(error) = error else {
                    panic!("expected transport error: {error:?}");
                };
                match error.as_ref() {
                    transport::Error::Terminated if eof => {}
                    transport::Error::RecvFailed(error) if !eof => {
                        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
                    }
                    other => panic!("unexpected read failure: {other:?}"),
                }
            }

            // Worker termination must follow the read failure itself, before
            // the driver's cleanup closes any remaining owners or pipes
            driver.step(Stopped);
            driver.step(Drop(local));
            driver.step(Released(local));
        }
    }
}

/// A transport write timeout closes the session even if its promise already timed out.
#[test]
fn test_transport_failure_after_protocol_timeout() {
    use Step::*;
    for (mode, local, outgoing) in [(Mode::Client, 0, 0), (Mode::Server, 1, 1)] {
        run(
            mode,
            &[
                // Block a request's write while a receive waits
                StartReceive(local),
                Pause(outgoing, Operation::Write, true),
                Request(local, 0, 10, 50),
                Blocked(outgoing, Operation::Write),
                // Reach the protocol deadline before the independent transport one
                Advance(50),
                Answer(0, Err(Failure::Timeout)),
                // Reach the 500 ms write budget, which closes the session
                Advance(450),
                ReceiveFailed(local, Failure::Transport),
                Refused(local),
            ],
        );
    }
}

/// Closing an idle server session releases its workers, while the server keeps
/// its reader for replacements.
#[test]
fn test_server_session_close_and_replacement() {
    use Step::*;
    run(
        Mode::Server,
        &[
            // Close the first session while a receive waits, then free it
            StartReceive(1),
            Close(1),
            ReceiveFailed(1, Failure::Closed),
            Drop(1),
            Released(1),
            // Accept a replacement that the old closer and requester cannot reach
            Reconnect(2),
            Close(1),
            Refused(1),
            Request(2, 0, 10, 3000),
            Read(2, EnvelopeShape::Content(10)),
            Send(2, EnvelopeShape::Content(20)),
            Answer(0, Ok(20)),
            // Free the replacement too, then accept a third session and shut down
            Drop(2),
            Released(2),
            Reconnect(3),
            Shutdown,
            Stopped,
        ],
    );
}

/// A replacement session starts over at the first ID, while old requests and
/// responders stay with their original session.
#[test]
fn test_replacement_with_old_work() {
    use Step::*;
    run(
        Mode::Server,
        &[
            // Leave a peer request held and a local request unanswered
            Send(1, EnvelopeShape::Content(10)),
            Receive(1, 10, 0),
            Request(1, 0, 11, 3000),
            Read(2, EnvelopeShape::Content(11)),
            // Replace the session, which fails the old request
            Reconnect(2),
            Answer(0, Err(Failure::Transport)),
            // Old handles must not reach the replacement
            Abandon(0),
            Close(1),
            Refused(1),
            // The replacement starts at the first ID, with no automatic reply
            // ahead of its request
            Request(2, 1, 12, 3000),
            Read(2, EnvelopeShape::Content(12)),
            Send(2, EnvelopeShape::Content(22)),
            Answer(1, Ok(22)),
            // Free the old session
            Drop(1),
            Released(1),
        ],
    );
}

/// Dropping a session or closing the server wakes blocked readers, writers and timers.
#[test]
fn test_shutdown_and_worker_exit() {
    use Step::*;
    for (mode, local) in [(Mode::Client, 0), (Mode::Server, 1)] {
        // Shut down after dropping the session, or while a receive waits
        run(mode, &[Drop(local), Shutdown, Stopped, Released(local)]);
        run(
            mode,
            &[
                StartReceive(local),
                Shutdown,
                ReceiveFailed(local, Failure::Closed),
                Stopped,
            ],
        );
    }

    // Shut down both peers while each has a request blocked in its write
    run(
        Mode::Both,
        &[
            Pause(0, Operation::Write, true),
            Pause(1, Operation::Write, true),
            Request(0, 0, 10, 3000),
            Request(1, 1, 11, 3000),
            Blocked(0, Operation::Write),
            Blocked(1, Operation::Write),
            Shutdown,
            AnswerClosed(0),
            Answer(1, Err(Failure::Closed)),
            Stopped,
        ],
    );
}

/// Oversized messages, wrong-direction messages and dropped promises do not close
/// an otherwise healthy session.
#[test]
fn test_local_refusals_and_abandoned_observers() {
    use Step::*;
    for (mode, local, first) in [(Mode::Client, 0, 1), (Mode::Server, 1, 2)] {
        run(
            mode,
            &[
                // Refuse a wrong-direction request and an oversized one
                WrongDirection(local, 0),
                Answer(0, Err(Failure::Direction)),
                Oversized(local, 1),
                Answer(1, Err(Failure::Large)),
                // Drop a promise before its answer, past the IDs the refusals used
                Request(local, 2, 12, 3000),
                DropPromise(2),
                Read(first + 4, EnvelopeShape::Content(12)),
                Send(first + 4, EnvelopeShape::Content(22)),
                // Require the next request to complete
                Request(local, 3, 13, 3000),
                Read(first + 6, EnvelopeShape::Content(13)),
                Send(first + 6, EnvelopeShape::Content(23)),
                Answer(3, Ok(23)),
            ],
        );
    }
}

/// A refused local reply consumes its responder without sending `UNANSWERED`
/// and frees the peer's request ID.
#[test]
fn test_reply_refusals_release_incoming_id() {
    use Step::*;
    for (mode, local, id) in [(Mode::Client, 0, 2), (Mode::Server, 1, 1)] {
        for (reply, failure) in [
            (WrongDirectionReply(local, 0, 0), Failure::Direction),
            (OversizedReply(0, 0), Failure::Large),
        ] {
            run(
                mode,
                &[
                    // Receive a peer request and refuse the local reply
                    Send(id, EnvelopeShape::Content(10)),
                    Receive(local, 10, 0),
                    reply,
                    Written(0, Err(failure)),
                    // Reuse the peer ID, whose reply must be the next message read
                    Send(id, EnvelopeShape::Content(11)),
                    Receive(local, 11, 1),
                    Reply(1, 1, Ok(21), 3000),
                    Read(id, EnvelopeShape::Content(21)),
                    Written(1, Ok(())),
                ],
            );
        }
    }
}

/// The last request ID works once, and taking another aborts the process
/// instead of wrapping.
#[test]
fn test_id_exhaustion() {
    use Step::*;
    worker_aborts(
        |mode, local| {
            let last = if local == 0 { u64::MAX } else { u64::MAX - 1 };
            run(
                mode,
                &[
                    // Complete one exchange on the last ID
                    LastId(local),
                    Request(local, 0, 10, 3000),
                    Read(last, EnvelopeShape::Content(10)),
                    Send(last, EnvelopeShape::Content(20)),
                    Answer(0, Ok(20)),
                    // Request once more, which must abort in the writer
                    Request(local, 1, 11, 3000),
                    Stopped,
                ],
            );
        },
        "wire request IDs exhausted",
    );
}

/// A worker panic must abort the process, including under Rust's unwind profile.
#[test]
fn test_worker_panic_aborts() {
    worker_aborts(
        |mode, local| run(mode, &[Step::WorkerPanic(local)]),
        "scripted worker failure",
    );
}

/// Runs a fatal scenario on each side in a child process, checking its panic and
/// exit status without terminating the parent test runner.
fn worker_aborts(scenario: impl Fn(Mode, u8), message: &str) {
    use std::process::Command;

    /// Environment variable naming the side a child runs, set only in the child.
    const CHILD: &str = "WIRE_TEST_WORKER_ABORT";

    // Run the scenario itself when this process is the child
    if let Ok(side) = std::env::var(CHILD) {
        let (mode, local) = match side.as_str() {
            "client" => (Mode::Client, 0),
            "server" => (Mode::Server, 1),
            _ => panic!("unknown worker panic scenario: {side}"),
        };
        scenario(mode, local);
        return;
    }

    // Libtest names its test thread after the exact test to run in the child
    let current = std::thread::current();
    let name = current.name().unwrap();
    for side in ["client", "server"] {
        // Rerun this test in a child for the side, requiring its panic message
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env(CHILD, side)
            .current_dir(std::env::temp_dir())
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(message),
            "{}: {}\n{stderr}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
        );
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            // SIGABRT is distinct from a failed test or an ordinary thread panic
            assert_eq!(output.status.signal(), Some(6), "{side}: {stderr}");
        }
        #[cfg(not(unix))]
        {
            // Without signals, require a failure other than a failed test's exit
            // code 101
            assert!(!output.status.success(), "{side}: {stderr}");
            assert_ne!(output.status.code(), Some(101), "{side}: {stderr}");
        }
    }
}

/// A delayed `Sender::disconnect()` from an old session cannot disconnect the new one.
#[test]
fn test_delayed_disconnect_after_replacement() {
    use Step::*;
    run(
        Mode::Server,
        &[
            // Close the first session during a flush, holding its writer before
            // the disconnect
            PauseDisconnect(1),
            Pause(1, Operation::Flush, true),
            Request(1, 0, 10, 3000),
            Blocked(1, Operation::Flush),
            Read(2, EnvelopeShape::Content(10)),
            Close(1),
            Answer(0, Err(Failure::Closed)),
            Pause(1, Operation::Flush, false),
            DisconnectPaused(1),
            // Accept a replacement, then let the old writer disconnect
            Reconnect(2),
            ResumeDisconnect(1),
            Drop(1),
            Released(1),
            // Require the replacement to keep working
            Request(2, 1, 11, 3000),
            Read(2, EnvelopeShape::Content(11)),
            Send(2, EnvelopeShape::Content(21)),
            Answer(1, Ok(21)),
        ],
    );
}

/// Failed handshake I/O must leave the server reader accepting future resets.
#[test]
fn test_handshake_failure_recovery() {
    use Step::*;

    // Fail the server's hello write, then reconnect and exchange
    run(
        Mode::Server,
        &[
            Fault(1, Operation::Write, io::ErrorKind::BrokenPipe),
            FailedReconnect,
            Reconnect(2),
            Request(2, 0, 10, 3000),
            Read(2, EnvelopeShape::Content(10)),
            Send(2, EnvelopeShape::Content(20)),
            Answer(0, Ok(20)),
        ],
    );

    // Time out the server's read of the HostAck, then reconnect and exchange
    run(
        Mode::Server,
        &[
            HandshakeReadTimeout,
            Reconnect(2),
            Request(2, 0, 10, 3000),
            Read(2, EnvelopeShape::Content(10)),
            Send(2, EnvelopeShape::Content(20)),
            Answer(0, Ok(20)),
        ],
    );
}

/// A failed reconnect moves time only after the server's hello takes the write
/// fault.
///
/// A hello expiring first would skip the fault and fail the next handshake,
/// whose client then waits forever on the stopped clock.
#[test]
fn test_failed_reconnect_awaits_server_output() {
    // Arm the server's next hello write to fail
    let mut driver = Driver::new(Mode::Server);
    let deadline = driver.tester.clock().now() + WRITE_BUDGET;
    driver.step(Step::Fault(1, Operation::Write, io::ErrorKind::BrokenPipe));

    // Keep the server from the reset until the step waits for its output, or
    // until the step expires the client without waiting
    driver.pipes[0].pause(Operation::Read, true);
    let pipes = driver.pipes.clone();
    let release = Job::start(move || {
        let awaited = pipes[1].wait_fault_waiter(deadline);
        pipes[0].pause(Operation::Read, false);
        awaited
    });

    // Require the step to wait for the fault, leaving the next handshake clean
    driver.step(Step::FailedReconnect);
    assert!(release.finish());
    driver.step(Step::Reconnect(2));
}

/// An immediately expired reply fails its promise and releases the peer's request ID.
#[test]
fn test_expired_reply_releases_incoming_id() {
    use Step::*;
    for (mode, local, id) in [(Mode::Client, 0, 2), (Mode::Server, 1, 1)] {
        run(
            mode,
            &[
                // Reply to a peer request with a deadline of 0 ms
                Send(id, EnvelopeShape::Content(10)),
                Receive(local, 10, 0),
                Reply(0, 0, Ok(20), 0),
                Written(0, Err(Failure::Timeout)),
                // Reuse the peer ID for a request that completes
                Send(id, EnvelopeShape::Content(11)),
                Receive(local, 11, 1),
                Reply(1, 1, Ok(21), 3000),
                Read(id, EnvelopeShape::Content(21)),
                Written(1, Ok(())),
            ],
        );
    }
}

/// An expiring queued request drops before taking a wire ID, and an expiring
/// queued reply frees its peer request ID, neither reaching the peer.
#[test]
fn test_queued_expiry_releases_ids() {
    use Step::*;
    for (mode, local, first, peer, outgoing) in
        [(Mode::Client, 0, 1, 2, 0), (Mode::Server, 1, 2, 1, 1)]
    {
        run(
            mode,
            &[
                // Queue a request and a reply behind one blocked write
                Pause(outgoing, Operation::Write, true),
                Request(local, 0, 10, 3000),
                Blocked(outgoing, Operation::Write),
                Request(local, 1, 11, 50),
                Send(peer, EnvelopeShape::Content(20)),
                Receive(local, 20, 0),
                Reply(0, 0, Ok(30), 50),
                // Expire both while they wait
                Advance(50),
                Answer(1, Err(Failure::Timeout)),
                Written(0, Err(Failure::Timeout)),
                // Reuse the peer ID, then release the write
                Send(peer, EnvelopeShape::Content(21)),
                Receive(local, 21, 1),
                Reply(1, 1, Ok(31), 3000),
                Pause(outgoing, Operation::Write, false),
                // Require only the live request and reply to reach the peer
                Read(first, EnvelopeShape::Content(10)),
                Send(first, EnvelopeShape::Content(40)),
                Answer(0, Ok(40)),
                Read(peer, EnvelopeShape::Content(31)),
                Written(1, Ok(())),
                // Require the next request to take the ID after the first one
                Request(local, 2, 12, 3000),
                Read(first + 2, EnvelopeShape::Content(12)),
                Send(first + 2, EnvelopeShape::Content(42)),
                Answer(2, Ok(42)),
                Outstanding(local, vec![]),
            ],
        );
    }
}

/// A new earlier deadline wakes an already sleeping timer while the peer is silent.
#[test]
fn test_new_earlier_deadline() {
    use Step::*;
    for (mode, local, first) in [(Mode::Client, 0, 1), (Mode::Server, 1, 2)] {
        run(
            mode,
            &[
                // Wake a parked worker with an earlier request's deadline
                Request(local, 0, 10, 3000),
                Read(first, EnvelopeShape::Content(10)),
                Request(local, 1, 11, 50),
                Read(first + 2, EnvelopeShape::Content(11)),
                // Expire only that request, whose ID stays outstanding
                Advance(50),
                Answer(1, Err(Failure::Timeout)),
                Outstanding(local, vec![first, first + 2]),
                // Answer both, the expired one late
                Send(first + 2, EnvelopeShape::Content(21)),
                Send(first, EnvelopeShape::Content(20)),
                Answer(0, Ok(20)),
                Outstanding(local, vec![]),
            ],
        );
    }
}

/// A peer can reuse a request ID as soon as it reads the reply, and the new
/// request keeps the ID after the old flush returns.
#[test]
fn test_peer_id_reuse_before_local_flush() {
    use Step::*;
    for (mode, local, id, outgoing) in [(Mode::Server, 1, 1, 1), (Mode::Client, 0, 2, 0)] {
        for duplicate in [false, true] {
            // Let the peer reuse its request ID while the reply's flush blocks
            let mut steps = vec![
                Send(id, EnvelopeShape::Content(10)),
                Receive(local, 10, 0),
                Pause(outgoing, Operation::Flush, true),
                Reply(0, 0, Ok(20), 3000),
                Blocked(outgoing, Operation::Flush),
                Read(id, EnvelopeShape::Content(20)),
                Send(id, EnvelopeShape::Content(11)),
                Receive(local, 11, 1),
                Pause(outgoing, Operation::Flush, false),
                Written(0, Ok(())),
            ];

            // Finishing the old reply must not remove the new request's ID
            if duplicate {
                steps.extend([
                    StartReceive(local),
                    Reject(id, EnvelopeShape::Content(12)),
                    ReceiveFailed(local, Failure::Malformed),
                ]);
            } else {
                steps.extend([
                    Reply(1, 1, Ok(21), 3000),
                    Read(id, EnvelopeShape::Content(21)),
                    Written(1, Ok(())),
                ]);
            }
            run(mode, &steps);
        }
    }
}

/// Both roles close promptly on admission overflow, waking requests and receivers.
#[test]
fn test_inbound_overflow_wakes_workers() {
    use EnvelopeShape::*;
    use Step::*;
    for (mode, local, peer, own) in [(Mode::Server, 1, 1, 2), (Mode::Client, 0, 2, 1)] {
        for (limit, error) in [
            (
                InboundLimits(local, 0, DEFAULT_MAX_INBOUND_BYTES),
                Failure::Requests,
            ),
            (
                InboundLimits(local, DEFAULT_MAX_INBOUND_REQUESTS, 0),
                Failure::Bytes,
            ),
        ] {
            run(
                mode,
                &[
                    // Leave a request and a receive waiting under a zero limit
                    limit,
                    Request(local, 0, 11, 3000),
                    Read(own, Content(11)),
                    StartReceive(local),
                    // Overflow it with a peer request, failing both
                    Reject(peer, Content(12)),
                    ReceiveFailed(local, error),
                    Answer(0, Err(error)),
                    Shutdown,
                    Stopped,
                ],
            );
        }

        // Overflow a limit of one request with a second peer request
        run(
            mode,
            &[
                InboundLimits(local, 1, DEFAULT_MAX_INBOUND_BYTES),
                Send(peer, Content(11)),
                Receive(local, 11, 0),
                StartReceive(local),
                Reject(peer + 2, Content(12)),
                ReceiveFailed(local, Failure::Requests),
                Shutdown,
                Stopped,
            ],
        );
    }

    // Apply server limits to the current session and to each replacement
    run(
        Mode::Server,
        &[
            // Refuse every request on the current session and its replacement
            ServerInboundLimits(0, DEFAULT_MAX_INBOUND_BYTES),
            Reject(1, Content(1)),
            ReceiveError(1, Failure::Requests),
            Reconnect(2),
            Reject(1, Content(1)),
            ReceiveError(2, Failure::Requests),
            // Refuse every retained byte on the next replacement
            ServerInboundLimits(1, 0),
            Reconnect(3),
            Reject(1, Content(1)),
            ReceiveError(3, Failure::Bytes),
            // Admit a small request on the last replacement
            ServerInboundLimits(1, 100),
            Reconnect(4),
            Send(1, Content(2)),
            Receive(4, 2, 0),
            Abandon(0),
            Read(1, Error(1)),
            Shutdown,
            Stopped,
        ],
    );
}

/// A response to a dropped promise does not close a session whose byte budget
/// is full.
#[test]
fn test_inbound_unread_response_budget() {
    use EnvelopeShape::*;
    use Step::*;
    for (mode, local, own) in [(Mode::Server, 1, 2), (Mode::Client, 0, 1)] {
        run(
            mode,
            &[
                // Fill the whole 7-byte budget with an unread response
                InboundLimits(local, DEFAULT_MAX_INBOUND_REQUESTS, 7),
                Request(local, 0, 1, 3000),
                Read(own, Content(1)),
                Send(own, Content(2)),
                ResponseReceived(local, own),
                Usage(local, 0, 7),
                // Answer a dropped promise with a malformed body, discarded unread
                Request(local, 1, 3, 3000),
                Read(own + 2, Content(3)),
                DropPromise(1),
                Send(own + 2, MalformedBody),
                ResponseReceived(local, own + 2),
                Usage(local, 0, 7),
                // Overflow the budget with a live response, closing the session
                Request(local, 2, 4, 3000),
                Read(own + 4, Content(4)),
                StartReceive(local),
                Reject(own + 4, Content(5)),
                ReceiveFailed(local, Failure::Bytes),
                Answer(2, Err(Failure::Bytes)),
                // The buffered response survives and the usage drops to zero
                Answer(0, Ok(2)),
                Usage(local, 0, 0),
                Shutdown,
                Stopped,
            ],
        );
    }
}

/// A payload decodes only when read, and a decode failure closes only its
/// original session.
#[test]
fn test_inbound_deferred_payload_errors() {
    use EnvelopeShape::*;
    use Step::*;
    for (mode, local, peer, own) in [(Mode::Server, 1, 1, 2), (Mode::Client, 0, 2, 1)] {
        // Fail the receive that decodes a malformed peer request
        run(
            mode,
            &[
                Send(peer, MalformedBody),
                ReceiveError(local, Failure::Malformed),
                Shutdown,
                Stopped,
            ],
        );

        // Fail the wait that decodes a malformed response, closing the session
        for shape in [MalformedBody, MalformedError] {
            run(
                mode,
                &[
                    Request(local, 0, 1, 3000),
                    Read(own, Content(1)),
                    Send(own, shape),
                    ResponseReceived(local, own),
                    StartReceive(local),
                    Answer(0, Err(Failure::Malformed)),
                    ReceiveFailed(local, Failure::Malformed),
                    Shutdown,
                    Stopped,
                ],
            );
        }
    }

    // Decode a malformed response only after its session is replaced
    run(
        Mode::Server,
        &[
            Request(1, 0, 1, 3000),
            Read(2, Content(1)),
            Send(2, MalformedBody),
            ResponseReceived(1, 2),
            Reconnect(2),
            Answer(0, Err(Failure::Malformed)),
            // Require the replacement to stay open
            Send(1, Content(7)),
            Receive(2, 7, 0),
            Abandon(0),
            Read(1, Error(1)),
            Shutdown,
            Stopped,
        ],
    );
}
