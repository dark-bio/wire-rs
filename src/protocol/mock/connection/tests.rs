// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Scenarios through public constructors, real crypto/framing, and gated adapters.

use crate::protocol::{DEFAULT_MAX_INBOUND_BYTES, DEFAULT_MAX_INBOUND_REQUESTS};

use super::{BUDGET, Driver, EnvelopeShape, Failure, Job, Mode, Step, run};
use crate::protocol::{Error, Message};
use crate::transport;
use crate::transport::mock::duplex::Operation;
use std::io;
use std::sync::{Arc, Barrier};
use std::time::Instant;

/// Both peers queue multiple requests before waiting for answers or calling `recv()`.
#[test]
fn test_bidirectional_exchange() {
    use Step::*;
    run(
        Mode::Both,
        &[
            TypedExchange,
            Request(0, 0, 10, 3000),
            Request(0, 1, 11, 3000),
            Request(1, 2, 12, 3000),
            Receive(1, 10, 0),
            Receive(1, 11, 1),
            Receive(0, 12, 2),
            Reply(1, 1, Ok(21), 3000),
            Reply(2, 2, Ok(22), 3000),
            Reply(0, 0, Ok(20), 3000),
            Answer(1, Ok(21)),
            Answer(0, Ok(20)),
            Answer(2, Ok(22)),
            Written(0, Ok(())),
            Written(1, Ok(())),
            Written(2, Ok(())),
            Shutdown,
            Stopped,
        ],
    );
}

/// Cloned requesters can submit concurrently without losing work or sharing IDs.
/// Reversed answers must still reach each producer's original promise.
#[test]
fn test_concurrent_requesters() {
    const PRODUCERS: u8 = 8;
    const REQUESTS: u8 = 8;

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
                                .request(vec![tag], Instant::now() + BUDGET)
                                .unwrap();
                            (tag, promise)
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let promises: Vec<_> = jobs.into_iter().flat_map(Job::finish).collect();
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
        let mut tags: Vec<_> = received.iter().map(|&(_, tag)| tag).collect();
        tags.sort_unstable();
        assert_eq!(tags, (0..PRODUCERS * REQUESTS).collect::<Vec<_>>());
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
                Request(local, 0, 10, 3000),
                Request(local, 1, 11, 3000),
                Read(first, EnvelopeShape::Content(10)),
                Read(first + 2, EnvelopeShape::Content(11)),
                Send(first + 100, EnvelopeShape::Content(99)),
                Send(first + 2, EnvelopeShape::Content(21)),
                Answer(1, Ok(21)),
                Outstanding(local, vec![first]),
                Send(first + 2, EnvelopeShape::Content(99)),
                Send(first, EnvelopeShape::Error(0x123)),
                Answer(0, Err(Failure::Remote(0x123))),
                Outstanding(local, vec![]),
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
                Send(ids[0], EnvelopeShape::Content(10)),
                Send(ids[1], EnvelopeShape::Content(11)),
                Send(ids[2], EnvelopeShape::Content(12)),
                Receive(local, 10, 0),
                Receive(local, 11, 1),
                Receive(local, 12, 2),
                Reply(2, 2, Ok(22), 3000),
                Read(ids[2], EnvelopeShape::Content(22)),
                Written(2, Ok(())),
                Abandon(0),
                Read(ids[0], EnvelopeShape::Error(1)),
                Reply(1, 1, Err(0x100), 3000),
                Read(ids[1], EnvelopeShape::Error(0x100)),
                Written(1, Ok(())),
                Send(ids[2], EnvelopeShape::Content(13)),
                Receive(local, 13, 3),
                Abandon(3),
                Read(ids[2], EnvelopeShape::Error(1)),
            ],
        );
    }
}

/// Invalid envelopes close the session; the server can accept another session.
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
            let mut steps = vec![
                StartReceive(local),
                Reject(id, body),
                ReceiveFailed(local, Failure::Malformed),
                Refused(local),
            ];
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
            // Check closure through a pending promise. recv() could instead
            // return the first queued request before the duplicate is processed.
            steps.extend([
                Request(local, 1, 3, 3000),
                Reject(id, EnvelopeShape::Content(9)),
                Answer(1, Err(Failure::Malformed)),
                Refused(local),
            ]);
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

/// Promise expiry cannot interrupt a frame; the peer may receive it afterward.
#[test]
fn test_deadline_during_write() {
    use Step::*;
    for (mode, local, id, outgoing) in [(Mode::Client, 0, 1, 0), (Mode::Server, 1, 2, 1)] {
        run(
            mode,
            &[
                Pause(outgoing, Operation::Write, true),
                Request(local, 0, 10, 50),
                Blocked(outgoing, Operation::Write),
                Answer(0, Err(Failure::Timeout)),
                Outstanding(local, vec![id]),
                Pause(outgoing, Operation::Write, false),
                Read(id, EnvelopeShape::Content(10)),
                Send(id, EnvelopeShape::Content(20)),
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
                Send(request, EnvelopeShape::Content(10)),
                Receive(local, 10, 0),
                Pause(outgoing, Operation::Flush, true),
                Reply(0, 0, Ok(20), 50),
                Blocked(outgoing, Operation::Flush),
                Written(0, Err(Failure::Timeout)),
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
                Pause(outgoing, Operation::Flush, true),
                Request(local, 0, 10, 3000),
                Blocked(outgoing, Operation::Flush),
                Read(id, EnvelopeShape::Content(10)),
                Send(id, EnvelopeShape::Content(20)),
                Answer(0, Ok(20)),
                Pause(outgoing, Operation::Flush, false),
            ],
        );
    }
}

/// An answer buffered before a failed flush survives session closure. Requests
/// and replies still queued behind that flush must fail with the transport.
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
                    Pause(outgoing, Operation::Flush, true),
                    Request(local, 0, 10, 3000),
                    Blocked(outgoing, Operation::Flush),
                    Read(id, EnvelopeShape::Content(10)),
                    Send(id, body),
                    // Receiving the next peer message proves the reader processed
                    // the answer, without consuming its promise before closure.
                    Send(peer, EnvelopeShape::Content(30)),
                    Receive(local, 30, 0),
                    Outstanding(local, vec![]),
                    Request(local, 1, 11, 3000),
                    Reply(0, 0, Ok(40), 3000),
                    StartReceive(local),
                    Fault(outgoing, Operation::Flush, io::ErrorKind::BrokenPipe),
                    Pause(outgoing, Operation::Flush, false),
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
                    StartReceive(local),
                    Fault(outgoing, op, io::ErrorKind::BrokenPipe),
                    Request(local, 0, 10, 3000),
                    Answer(0, Err(Failure::Transport)),
                    ReceiveFailed(local, Failure::Transport),
                    Refused(local),
                ],
            );
        }
    }
}

/// Fatal reads fail every pending request and wake both receive and acceptance.
/// EOF and adapter errors retain their cause, including on later submissions.
#[test]
fn test_read_failure_wakes_callers() {
    use Step::*;
    crate::testing::init_tracing();
    for (mode, local, first, peer, incoming) in
        [(Mode::Client, 0, 1, 2, 1), (Mode::Server, 1, 2, 1, 0)]
    {
        for eof in [false, true] {
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
            let accepting = driver.server.take().map(|mut server| {
                let waiting = server.inner.watch_accept_wait();
                let job = Job::start(move || {
                    let error = server.accept().err().expect("accept must fail");
                    (server, error)
                });
                waiting.recv_timeout(BUDGET).unwrap();
                job
            });
            if eof {
                driver.pipes[incoming as usize].close();
            } else {
                driver.step(Fault(incoming, Operation::Read, io::ErrorKind::BrokenPipe));
            }
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
            errors.push(result.err().expect("receive must fail"));
            driver.sessions.insert(local, session);
            if let Some(accepting) = accepting {
                let (server, error) = accepting.finish();
                errors.push(error);
                driver.server = Some(server);
            }
            errors.push(
                driver.requesters[&local]
                    .request(vec![12], Instant::now() + BUDGET)
                    .err()
                    .expect("request must fail"),
            );
            errors.push(
                driver
                    .responders
                    .remove(&0)
                    .unwrap()
                    .reply(Ok(Message::Develop(vec![31])), Instant::now() + BUDGET)
                    .err()
                    .expect("reply must fail"),
            );
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
            // the driver's cleanup closes any remaining owners or pipes.
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
                StartReceive(local),
                Pause(outgoing, Operation::Write, true),
                Request(local, 0, 10, 50),
                Blocked(outgoing, Operation::Write),
                Answer(0, Err(Failure::Timeout)),
                ReceiveFailed(local, Failure::Transport),
                Refused(local),
            ],
        );
    }
}

/// Closing an idle server session releases its workers while retaining its reader.
#[test]
fn test_server_session_close_and_replacement() {
    use Step::*;
    run(
        Mode::Server,
        &[
            StartReceive(1),
            Close(1),
            ReceiveFailed(1, Failure::Closed),
            Drop(1),
            Released(1),
            Reconnect(2),
            Close(1),
            Refused(1),
            Request(2, 0, 10, 3000),
            Read(2, EnvelopeShape::Content(10)),
            Send(2, EnvelopeShape::Content(20)),
            Answer(0, Ok(20)),
            Drop(2),
            Released(2),
            Reconnect(3),
            Shutdown,
            Stopped,
        ],
    );
}

/// Replacement gives fresh IDs. Old responders and write results still target
/// their original session.
#[test]
fn test_replacement_with_old_work() {
    use Step::*;
    run(
        Mode::Server,
        &[
            Send(1, EnvelopeShape::Content(10)),
            Receive(1, 10, 0),
            Request(1, 0, 11, 3000),
            Read(2, EnvelopeShape::Content(11)),
            Reconnect(2),
            Answer(0, Err(Failure::Transport)),
            Abandon(0),
            Close(1),
            Refused(1),
            Request(2, 1, 12, 3000),
            Read(2, EnvelopeShape::Content(12)),
            Send(2, EnvelopeShape::Content(22)),
            Answer(1, Ok(22)),
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
                WrongDirection(local, 0),
                Answer(0, Err(Failure::Direction)),
                Oversized(local, 1),
                Answer(1, Err(Failure::Large)),
                Request(local, 2, 12, 3000),
                DropPromise(2),
                Read(first + 4, EnvelopeShape::Content(12)),
                Send(first + 4, EnvelopeShape::Content(22)),
                Request(local, 3, 13, 3000),
                Read(first + 6, EnvelopeShape::Content(13)),
                Send(first + 6, EnvelopeShape::Content(23)),
                Answer(3, Ok(23)),
            ],
        );
    }
}

/// A local reply refusal consumes the responder without sending UNANSWERED.
/// The peer can reuse its ID, and the next reply is the first message sent.
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
                    Send(id, EnvelopeShape::Content(10)),
                    Receive(local, 10, 0),
                    reply,
                    Written(0, Err(failure)),
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

/// Final IDs are usable once; exhausting the counter panics instead of wrapping.
#[test]
fn test_id_exhaustion() {
    use Step::*;
    worker_aborts(
        |mode, local| {
            let last = if local == 0 { u64::MAX } else { u64::MAX - 1 };
            run(
                mode,
                &[
                    LastId(local),
                    Request(local, 0, 10, 3000),
                    Read(last, EnvelopeShape::Content(10)),
                    Send(last, EnvelopeShape::Content(20)),
                    Answer(0, Ok(20)),
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

    /// Selects the child scenario without changing the parent process environment.
    const CHILD: &str = "WIRE_TEST_WORKER_ABORT";
    if let Ok(side) = std::env::var(CHILD) {
        let (mode, local) = match side.as_str() {
            "client" => (Mode::Client, 0),
            "server" => (Mode::Server, 1),
            _ => panic!("unknown worker panic scenario: {side}"),
        };
        scenario(mode, local);
        return;
    }
    // Libtest names its test thread after the exact test to run in the child.
    let current = std::thread::current();
    let name = current.name().unwrap();
    for side in ["client", "server"] {
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
            // SIGABRT is distinct from a failed test or an ordinary thread panic.
            assert_eq!(output.status.signal(), Some(6), "{side}: {stderr}");
        }
        #[cfg(not(unix))]
        {
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
            PauseDisconnect(1),
            Pause(1, Operation::Flush, true),
            Request(1, 0, 10, 3000),
            Blocked(1, Operation::Flush),
            Read(2, EnvelopeShape::Content(10)),
            Close(1),
            Answer(0, Err(Failure::Closed)),
            Pause(1, Operation::Flush, false),
            DisconnectPaused(1),
            Reconnect(2),
            ResumeDisconnect(1),
            Drop(1),
            Released(1),
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

/// An immediately expired reply fails its promise and releases the peer's request ID.
#[test]
fn test_expired_reply_releases_incoming_id() {
    use Step::*;
    for (mode, local, id) in [(Mode::Client, 0, 2), (Mode::Server, 1, 1)] {
        run(
            mode,
            &[
                Send(id, EnvelopeShape::Content(10)),
                Receive(local, 10, 0),
                Reply(0, 0, Ok(20), 0),
                Written(0, Err(Failure::Timeout)),
                Send(id, EnvelopeShape::Content(11)),
                Receive(local, 11, 1),
                Reply(1, 1, Ok(21), 3000),
                Read(id, EnvelopeShape::Content(21)),
                Written(1, Ok(())),
            ],
        );
    }
}

/// Expiring a queued reply releases its peer ID without sending the reply.
/// Expiring a queued request must not consume a local wire ID either.
#[test]
fn test_queued_expiry_releases_ids() {
    use Step::*;
    for (mode, local, first, peer, outgoing) in
        [(Mode::Client, 0, 1, 2, 0), (Mode::Server, 1, 2, 1, 1)]
    {
        run(
            mode,
            &[
                Pause(outgoing, Operation::Write, true),
                Request(local, 0, 10, 3000),
                Blocked(outgoing, Operation::Write),
                Request(local, 1, 11, 50),
                Send(peer, EnvelopeShape::Content(20)),
                Receive(local, 20, 0),
                Reply(0, 0, Ok(30), 50),
                Answer(1, Err(Failure::Timeout)),
                Written(0, Err(Failure::Timeout)),
                Send(peer, EnvelopeShape::Content(21)),
                Receive(local, 21, 1),
                Reply(1, 1, Ok(31), 3000),
                Pause(outgoing, Operation::Write, false),
                Read(first, EnvelopeShape::Content(10)),
                Send(first, EnvelopeShape::Content(40)),
                Answer(0, Ok(40)),
                Read(peer, EnvelopeShape::Content(31)),
                Written(1, Ok(())),
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
                Request(local, 0, 10, 3000),
                Read(first, EnvelopeShape::Content(10)),
                Request(local, 1, 11, 50),
                Read(first + 2, EnvelopeShape::Content(11)),
                Answer(1, Err(Failure::Timeout)),
                Outstanding(local, vec![first, first + 2]),
                Send(first + 2, EnvelopeShape::Content(21)),
                Send(first, EnvelopeShape::Content(20)),
                Answer(0, Ok(20)),
                Outstanding(local, vec![]),
            ],
        );
    }
}

/// The peer can receive a reply and reuse its request ID before our flush returns.
/// Accept that new request, and keep it when the old write later finishes.
#[test]
fn test_peer_id_reuse_before_local_flush() {
    use Step::*;
    for (mode, local, id, outgoing) in [(Mode::Server, 1, 1, 1), (Mode::Client, 0, 2, 0)] {
        for duplicate in [false, true] {
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
            if duplicate {
                // Finishing the old reply must not remove the new request's ID.
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
                    limit,
                    Request(local, 0, 11, 3000),
                    Read(own, Content(11)),
                    StartReceive(local),
                    Reject(peer, Content(12)),
                    ReceiveFailed(local, error),
                    Answer(0, Err(error)),
                    Shutdown,
                    Stopped,
                ],
            );
        }
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
    run(
        Mode::Server,
        &[
            ServerInboundLimits(0, DEFAULT_MAX_INBOUND_BYTES),
            Reject(1, Content(1)),
            ReceiveError(1, Failure::Requests),
            Reconnect(2),
            Reject(1, Content(1)),
            ReceiveError(2, Failure::Requests),
            ServerInboundLimits(1, 0),
            Reconnect(3),
            Reject(1, Content(1)),
            ReceiveError(3, Failure::Bytes),
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

/// A full byte budget still permits replies to requests whose observers were dropped.
#[test]
fn test_inbound_unread_response_budget() {
    use EnvelopeShape::*;
    use Step::*;
    for (mode, local, own) in [(Mode::Server, 1, 2), (Mode::Client, 0, 1)] {
        run(
            mode,
            &[
                InboundLimits(local, DEFAULT_MAX_INBOUND_REQUESTS, 7),
                Request(local, 0, 1, 3000),
                Read(own, Content(1)),
                Send(own, Content(2)),
                ResponseReceived(local, own),
                Usage(local, 0, 7),
                Request(local, 1, 3, 3000),
                Read(own + 2, Content(3)),
                DropPromise(1),
                Send(own + 2, MalformedBody),
                ResponseReceived(local, own + 2),
                Usage(local, 0, 7),
                Request(local, 2, 4, 3000),
                Read(own + 4, Content(4)),
                StartReceive(local),
                Reject(own + 4, Content(5)),
                ReceiveFailed(local, Failure::Bytes),
                Answer(2, Err(Failure::Bytes)),
                Answer(0, Ok(2)),
                Usage(local, 0, 0),
                Shutdown,
                Stopped,
            ],
        );
    }
}

/// Payloads are decoded when read. A decode failure closes only the original session.
#[test]
fn test_inbound_deferred_payload_errors() {
    use EnvelopeShape::*;
    use Step::*;
    for (mode, local, peer, own) in [(Mode::Server, 1, 1, 2), (Mode::Client, 0, 2, 1)] {
        run(
            mode,
            &[
                Send(peer, MalformedBody),
                ReceiveError(local, Failure::Malformed),
                Shutdown,
                Stopped,
            ],
        );
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
    run(
        Mode::Server,
        &[
            Request(1, 0, 1, 3000),
            Read(2, Content(1)),
            Send(2, MalformedBody),
            ResponseReceived(1, 2),
            Reconnect(2),
            Answer(0, Err(Failure::Malformed)),
            Send(1, Content(7)),
            Receive(2, 7, 0),
            Abandon(0),
            Read(1, Error(1)),
            Shutdown,
            Stopped,
        ],
    );
}
