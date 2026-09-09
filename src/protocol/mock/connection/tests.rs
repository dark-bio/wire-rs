// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Scenarios through public constructors, real crypto/framing, and gated adapters.

use super::{Body, Failure, Mode, Step, run};
use crate::transport::mock::duplex::Operation;
use std::io;

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
                Read(first, Body::Content(10)),
                Read(first + 2, Body::Content(11)),
                Send(first + 100, Body::Content(99)),
                Send(first + 2, Body::Content(21)),
                Answer(1, Ok(21)),
                Outstanding(local, vec![first]),
                Send(first + 2, Body::Content(99)),
                Send(first, Body::Error(0x123)),
                Answer(0, Err(Failure::Remote(0x123))),
                Outstanding(local, vec![]),
                Request(local, 2, 12, 3000),
                Read(first + 4, Body::Content(12)),
                Send(first + 4, Body::Content(22)),
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
                Send(ids[0], Body::Content(10)),
                Send(ids[1], Body::Content(11)),
                Send(ids[2], Body::Content(12)),
                Receive(local, 10, 0),
                Receive(local, 11, 1),
                Receive(local, 12, 2),
                Reply(2, 2, Ok(22), 3000),
                Read(ids[2], Body::Content(22)),
                Written(2, Ok(())),
                Abandon(0),
                Read(ids[0], Body::Error(1)),
                Reply(1, 1, Err(0x100), 3000),
                Read(ids[1], Body::Error(0x100)),
                Written(1, Ok(())),
                Send(ids[2], Body::Content(13)),
                Receive(local, 13, 3),
                Abandon(3),
                Read(ids[2], Body::Error(1)),
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
            (request, Body::Both),
            (response, Body::Both),
            (request, Body::Neither),
            (response, Body::Neither),
            (request, Body::Error(1)),
            (request, Body::Invalid),
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
                    Read(2, Body::Content(7)),
                    Send(2, Body::Content(8)),
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
            let mut steps = vec![Send(id, Body::Content(1))];
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
                Reject(id, Body::Content(9)),
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
                Read(id, Body::Content(10)),
                Send(id, Body::Content(20)),
                Request(local, 1, 11, 3000),
                Read(id + 2, Body::Content(11)),
                Send(id, Body::Content(99)),
                Send(id + 2, Body::Content(21)),
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
                Send(request, Body::Content(10)),
                Receive(local, 10, 0),
                Pause(outgoing, Operation::Flush, true),
                Reply(0, 0, Ok(20), 50),
                Blocked(outgoing, Operation::Flush),
                Written(0, Err(Failure::Timeout)),
                Read(request, Body::Content(20)),
                Pause(outgoing, Operation::Flush, false),
                Send(request + 2, Body::Content(11)),
                Receive(local, 11, 1),
                Abandon(1),
                Read(request + 2, Body::Error(1)),
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
                Read(id, Body::Content(10)),
                Send(id, Body::Content(20)),
                Answer(0, Ok(20)),
                Pause(outgoing, Operation::Flush, false),
            ],
        );
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
            Read(2, Body::Content(10)),
            Send(2, Body::Content(20)),
            Answer(0, Ok(20)),
            Drop(2),
            Released(2),
            Reconnect(3),
            Shutdown,
            Stopped,
        ],
    );
}

/// Replacement gives fresh IDs and makes old responders and completions harmless.
#[test]
fn test_replacement_with_old_work() {
    use Step::*;
    run(
        Mode::Server,
        &[
            Send(1, Body::Content(10)),
            Receive(1, 10, 0),
            Request(1, 0, 11, 3000),
            Read(2, Body::Content(11)),
            Reconnect(2),
            Answer(0, Err(Failure::Transport)),
            Abandon(0),
            Close(1),
            Refused(1),
            Request(2, 1, 12, 3000),
            Read(2, Body::Content(12)),
            Send(2, Body::Content(22)),
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
                Read(first + 4, Body::Content(12)),
                Send(first + 4, Body::Content(22)),
                Request(local, 3, 13, 3000),
                Read(first + 6, Body::Content(13)),
                Send(first + 6, Body::Content(23)),
                Answer(3, Ok(23)),
            ],
        );
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
                    Read(last, Body::Content(10)),
                    Send(last, Body::Content(20)),
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
fn test_delayed_retirement_after_replacement() {
    use Step::*;
    run(
        Mode::Server,
        &[
            HoldRetirement(1),
            Pause(1, Operation::Flush, true),
            Request(1, 0, 10, 3000),
            Blocked(1, Operation::Flush),
            Read(2, Body::Content(10)),
            Close(1),
            Answer(0, Err(Failure::Closed)),
            Pause(1, Operation::Flush, false),
            Retiring(1),
            Reconnect(2),
            ReleaseRetirement(1),
            Drop(1),
            Released(1),
            Request(2, 1, 11, 3000),
            Read(2, Body::Content(11)),
            Send(2, Body::Content(21)),
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
            Read(2, Body::Content(10)),
            Send(2, Body::Content(20)),
            Answer(0, Ok(20)),
        ],
    );
    run(
        Mode::Server,
        &[
            HandshakeReadTimeout,
            Reconnect(2),
            Request(2, 0, 10, 3000),
            Read(2, Body::Content(10)),
            Send(2, Body::Content(20)),
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
                Send(id, Body::Content(10)),
                Receive(local, 10, 0),
                Reply(0, 0, Ok(20), 0),
                Written(0, Err(Failure::Timeout)),
                Send(id, Body::Content(11)),
                Receive(local, 11, 1),
                Reply(1, 1, Ok(21), 3000),
                Read(id, Body::Content(21)),
                Written(1, Ok(())),
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
                Read(first, Body::Content(10)),
                Request(local, 1, 11, 50),
                Read(first + 2, Body::Content(11)),
                Answer(1, Err(Failure::Timeout)),
                Outstanding(local, vec![first, first + 2]),
                Send(first + 2, Body::Content(21)),
                Send(first, Body::Content(20)),
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
                Send(id, Body::Content(10)),
                Receive(local, 10, 0),
                Pause(outgoing, Operation::Flush, true),
                Reply(0, 0, Ok(20), 3000),
                Blocked(outgoing, Operation::Flush),
                Read(id, Body::Content(20)),
                Send(id, Body::Content(11)),
                Receive(local, 11, 1),
                Pause(outgoing, Operation::Flush, false),
                Written(0, Ok(())),
            ];
            if duplicate {
                // Finishing the old reply must not remove the new request's ID.
                steps.extend([
                    StartReceive(local),
                    Reject(id, Body::Content(12)),
                    ReceiveFailed(local, Failure::Malformed),
                ]);
            } else {
                steps.extend([
                    Reply(1, 1, Ok(21), 3000),
                    Read(id, Body::Content(21)),
                    Written(1, Ok(())),
                ]);
            }
            run(mode, &steps);
        }
    }
}
