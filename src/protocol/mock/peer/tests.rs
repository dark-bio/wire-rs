// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Scenario tests of the multiplexer, scripts run against both of its sides
//! by the mock peer.

use super::*;
use crate::testing;

/// Runs a script against a client multiplexer with logging enabled.
fn client(steps: &[Step]) -> Summary {
    testing::init_tracing();
    run_client(steps)
}

/// Runs a script against a server multiplexer with logging enabled. A server
/// serves whoever opened the live session and only notices it once a message
/// of that peer's arrives, so every script starts with both.
fn server(steps: &[Step]) -> Summary {
    testing::init_tracing();
    let mut script = vec![Step::Reset, Step::Stray];
    script.extend_from_slice(steps);
    run_server(&script)
}

// Tests the happy path of both sides, requests going out and their answers
// coming back, with the peer's own requests served in between.
#[test]
fn test_scripted_round_trip() {
    let summary = client(&[
        Step::Request(1),
        Step::Answer(1),
        Step::Wait(1),
        Step::Request(2),
        Step::Answer(2),
        Step::Wait(2),
    ]);
    assert_eq!(
        summary,
        Summary {
            sent: 2,
            answered: 2,
            ..Summary::default()
        }
    );

    let summary = server(&[
        Step::Request(1),
        Step::Answer(1),
        Step::Wait(1),
        Step::Ask(2),
        Step::Reply,
    ]);
    assert_eq!(
        summary,
        Summary {
            sent: 1,
            answered: 1,
            served: 1,
            sessions: 1,
            ..Summary::default()
        }
    );
}

// Tests several requests outstanding at once, every answer reaching the
// request it belongs to whatever order they arrive in.
#[test]
fn test_scripted_pipelined_requests() {
    let summary = client(&[
        Step::Request(1),
        Step::Request(2),
        Step::Request(3),
        Step::Answer(3),
        Step::Answer(1),
        Step::Answer(2),
        Step::Wait(1),
        Step::Wait(2),
        Step::Wait(3),
    ]);
    assert_eq!(
        summary,
        Summary {
            sent: 3,
            answered: 3,
            ..Summary::default()
        }
    );
}

// Tests a request the peer fails, which fails the caller alone and leaves
// the session usable.
#[test]
fn test_scripted_remote_failure() {
    let summary = client(&[
        Step::Request(1),
        Step::Fail(1),
        Step::Wait(1),
        Step::Request(2),
        Step::Answer(2),
        Step::Wait(2),
    ]);
    assert_eq!(
        summary,
        Summary {
            sent: 2,
            answered: 1,
            failed: 1,
            ..Summary::default()
        }
    );
}

// Tests an answer to a request nobody made, which is dropped without the
// session suffering for it.
#[test]
fn test_scripted_stray_answer() {
    let summary = client(&[
        Step::Stray,
        Step::Request(1),
        Step::Stray,
        Step::Answer(1),
        Step::Wait(1),
    ]);
    assert_eq!(
        summary,
        Summary {
            sent: 1,
            answered: 1,
            ..Summary::default()
        }
    );
}

// Tests a request waited for before its answer arrives, which times out and
// is forgotten, its bytes held until the peer answers and its late answer
// dropped rather than handed to the next request.
#[test]
fn test_scripted_wait_times_out() {
    let summary = client(&[
        Step::Request(1),
        Step::Wait(1),
        Step::Answer(1),
        Step::Wait(1),
        Step::Request(2),
        Step::Answer(2),
        Step::Wait(2),
    ]);
    assert_eq!(
        summary,
        Summary {
            sent: 2,
            answered: 1,
            failed: 1,
            ..Summary::default()
        }
    );
}

// Tests a request whose answer is dropped without ever being waited for, the
// answer arriving to nobody.
#[test]
fn test_scripted_forgotten_request() {
    let summary = client(&[
        Step::Request(1),
        Step::Forget(1),
        Step::Answer(1),
        Step::Wait(1),
        Step::Request(1),
        Step::Answer(1),
        Step::Wait(1),
    ]);
    assert_eq!(
        summary,
        Summary {
            sent: 2,
            answered: 1,
            ..Summary::default()
        }
    );
}

// Tests the peer's requests, answered, failed and let go by the handler, the
// multiplexer failing the one it lets go for the peer.
#[test]
fn test_scripted_requests_served() {
    let summary = client(&[
        Step::Ask(1),
        Step::Reply,
        Step::Ask(2),
        Step::Refuse,
        Step::Ask(3),
        Step::Ignore,
    ]);
    assert_eq!(
        summary,
        Summary {
            served: 3,
            ..Summary::default()
        }
    );
}

// Tests the peer's requests piling up behind a handler that holds the worker,
// each served in arrival order once it moves on.
#[test]
fn test_scripted_requests_queue_up() {
    let summary = client(&[
        Step::Ask(1),
        Step::Ask(2),
        Step::Ask(3),
        Step::Reply,
        Step::Reply,
        Step::Reply,
    ]);
    assert_eq!(
        summary,
        Summary {
            served: 3,
            ..Summary::default()
        }
    );
}

// Tests a request of the peer's the multiplexer cannot read, which it fails
// from its reader without the session suffering for it.
#[test]
fn test_scripted_request_not_understood() {
    let summary = client(&[
        Step::AskVoid,
        Step::Request(1),
        Step::Answer(1),
        Step::Wait(1),
    ]);
    assert_eq!(
        summary,
        Summary {
            sent: 1,
            answered: 1,
            declined: 1,
            ..Summary::default()
        }
    );
}

// Tests a peer breaking the protocol, an answer carrying nothing or a message
// that is no envelope, which ends a client's multiplexer with its session.
#[test]
fn test_scripted_client_malformed() {
    for step in [Step::Void, Step::Junk] {
        let summary = client(&[
            Step::Request(1),
            step.clone(),
            Step::Wait(1),
            Step::Request(2),
        ]);
        assert_eq!(
            summary,
            Summary {
                sent: 1,
                refused: 1,
                failed: 1,
                disconnects: 1,
                closed: true,
                ..Summary::default()
            },
            "{step:?}"
        );
    }
}

// Tests a peer breaking the protocol on a server, which drops the session on
// it and serves the peer again once it opens a new one.
#[test]
fn test_scripted_server_malformed() {
    for step in [Step::Void, Step::Junk] {
        let summary = server(&[
            Step::Request(1),
            step.clone(),
            Step::Wait(1),
            Step::Request(2),
            Step::Reset,
            Step::Stray,
            Step::Request(3),
            Step::Answer(3),
            Step::Wait(3),
        ]);
        assert_eq!(
            summary,
            Summary {
                sent: 2,
                refused: 1,
                answered: 1,
                failed: 1,
                disconnects: 1,
                sessions: 2,
                ..Summary::default()
            },
            "{step:?}"
        );
    }
}

// Tests a peer reconnecting on a server, the requests of the session before
// it failing as reset and the new one served through fresh handles.
#[test]
fn test_scripted_server_reconnect() {
    let summary = server(&[
        Step::Request(1),
        Step::Ask(2),
        Step::Reset,
        Step::Stray,
        Step::Wait(1),
        Step::Request(3),
        Step::Answer(3),
        Step::Wait(3),
    ]);
    assert_eq!(
        summary,
        Summary {
            sent: 2,
            answered: 1,
            failed: 1,
            served: 1,
            disconnects: 1,
            sessions: 2,
            ..Summary::default()
        }
    );
}

// Tests a server before its first peer, which has nobody to send to, and
// after it, which has.
#[test]
fn test_scripted_server_without_a_peer() {
    let summary = run_server(&[
        Step::Request(1),
        Step::Reset,
        Step::Request(2),
        Step::Stray,
        Step::Request(3),
        Step::Answer(3),
        Step::Wait(3),
    ]);
    assert_eq!(
        summary,
        Summary {
            sent: 1,
            refused: 2,
            answered: 1,
            sessions: 1,
            ..Summary::default()
        }
    );
}

// Tests the transport ending under the reader, which ends the multiplexer
// with it, the request in flight and every later call failing.
#[test]
fn test_scripted_unplugged() {
    for side in [true, false] {
        let script = [
            Step::Request(1),
            Step::Unplug,
            Step::Wait(1),
            Step::Request(2),
        ];
        let summary = match side {
            true => client(&script),
            false => server(&script),
        };
        assert_eq!(
            summary,
            Summary {
                sent: 1,
                refused: 1,
                failed: 1,
                disconnects: 1,
                sessions: usize::from(!side),
                closed: true,
                ..Summary::default()
            },
            "client {side}"
        );
    }
}

// Tests closing with a request in flight, which fails it as closed, refuses
// every later call and leaves the disconnect handler alone.
#[test]
fn test_scripted_closed() {
    let summary = client(&[
        Step::Request(1),
        Step::Close,
        Step::Wait(1),
        Step::Request(2),
        Step::Close,
    ]);
    assert_eq!(
        summary,
        Summary {
            sent: 1,
            refused: 1,
            failed: 1,
            closed: true,
            ..Summary::default()
        }
    );
}

// Tests closing with a request in the handler, whose answer finds a transport
// the closer already ended.
#[test]
fn test_scripted_closed_with_held_request() {
    let summary = client(&[Step::Ask(1), Step::Close, Step::Reply, Step::Ask(2)]);
    assert_eq!(
        summary,
        Summary {
            served: 1,
            closed: true,
            ..Summary::default()
        }
    );
}

// Tests a transport failing under a client's writes, which ends its
// multiplexer with the session, the failure never healing.
#[test]
fn test_scripted_client_broken_transport() {
    let summary = client(&[
        Step::Request(1),
        Step::Break,
        Step::Request(2),
        Step::Heal,
        Step::Request(3),
    ]);
    assert_eq!(
        summary,
        Summary {
            sent: 1,
            refused: 2,
            disconnects: 1,
            closed: true,
            ..Summary::default()
        }
    );
}

// Tests a transport failing under a server's writes, which is the caller's
// failure alone. The session is gone with it, so the multiplexer serves the
// peer again only once it opens a new one.
#[test]
fn test_scripted_server_broken_transport() {
    let summary = server(&[
        Step::Break,
        Step::Request(1),
        Step::Request(2),
        Step::Heal,
        Step::Request(3),
        Step::Reset,
        Step::Stray,
        Step::Request(4),
        Step::Answer(4),
        Step::Wait(4),
    ]);
    assert_eq!(
        summary,
        Summary {
            sent: 1,
            refused: 3,
            answered: 1,
            disconnects: 1,
            sessions: 2,
            ..Summary::default()
        }
    );
}

// Tests an answer of the handler's failing on a broken transport, which
// leaves the multiplexer open while the session is gone under it.
#[test]
fn test_scripted_answer_fails() {
    let summary = server(&[
        Step::Ask(1),
        Step::Break,
        Step::Reply,
        Step::Heal,
        Step::Reset,
        Step::Ask(2),
        Step::Reply,
    ]);
    assert_eq!(
        summary,
        Summary {
            served: 2,
            disconnects: 1,
            sessions: 2,
            ..Summary::default()
        }
    );
}

// Tests a client whose write half died under an answer of its handler, which
// takes the session with it while the multiplexer stays open. The reader
// notices on the next message of the peer's and ends the multiplexer, a
// client's session being its connection, so the request after it is refused.
#[test]
fn test_scripted_client_answer_fails() {
    let summary = client(&[
        Step::Ask(1),
        Step::Break,
        Step::Reply,
        Step::Heal,
        Step::Stray,
        Step::Request(2),
    ]);
    assert_eq!(
        summary,
        Summary {
            refused: 1,
            served: 1,
            disconnects: 1,
            closed: true,
            ..Summary::default()
        }
    );
}

// Tests a message too large for the wire, refused before it is sealed with
// the session none the worse for it.
#[test]
fn test_scripted_message_too_large() {
    let summary = client(&[
        Step::Oversized,
        Step::Request(1),
        Step::Answer(1),
        Step::Wait(1),
    ]);
    assert_eq!(
        summary,
        Summary {
            sent: 1,
            refused: 1,
            answered: 1,
            ..Summary::default()
        }
    );
}

// Tests the window, eight bulk requests filling it and the ninth waiting for
// room until an answer frees some.
#[test]
fn test_scripted_window_fills() {
    let summary = client(&[
        Step::Bulk(1),
        Step::Bulk(2),
        Step::Bulk(3),
        Step::Bulk(4),
        Step::Bulk(5),
        Step::Bulk(6),
        Step::Bulk(7),
        Step::Bulk(8),
        Step::Bulk(9),
        Step::Answer(1),
        Step::Wait(1),
        Step::Answer(9),
        Step::Wait(9),
    ]);
    assert_eq!(
        summary,
        Summary {
            sent: 9,
            answered: 2,
            ..Summary::default()
        }
    );
}

// Tests a request waiting for room in the window when the multiplexer ends,
// which refuses it as closed rather than leaving its caller waiting.
#[test]
fn test_scripted_window_closed() {
    let summary = client(&[
        Step::Bulk(1),
        Step::Bulk(2),
        Step::Bulk(3),
        Step::Bulk(4),
        Step::Bulk(5),
        Step::Bulk(6),
        Step::Bulk(7),
        Step::Bulk(8),
        Step::Bulk(9),
        Step::Close,
    ]);
    assert_eq!(
        summary,
        Summary {
            sent: 8,
            refused: 1,
            closed: true,
            ..Summary::default()
        }
    );
}

// Tests a peer overrunning its window, its requests piling up in the inbox
// past the limit while the handler holds the worker, which ends the session
// on it. A client's multiplexer ends with it, a server's serves the peer
// again once it opens a new session.
#[test]
fn test_scripted_flooded() {
    let summary = client(&[Step::Flood, Step::Request(1)]);
    assert_eq!(
        summary,
        Summary {
            refused: 1,
            served: 1,
            disconnects: 1,
            closed: true,
            ..Summary::default()
        }
    );

    let summary = server(&[
        Step::Flood,
        Step::Request(1),
        Step::Reset,
        Step::Stray,
        Step::Request(2),
        Step::Answer(2),
        Step::Wait(2),
    ]);
    assert_eq!(
        summary,
        Summary {
            sent: 1,
            refused: 1,
            answered: 1,
            served: 1,
            disconnects: 1,
            sessions: 2,
            ..Summary::default()
        }
    );
}

// Tests that a request the handler holds across a reset is answered into the
// session it arrived in, which is gone, so the answer never reaches anyone.
#[test]
fn test_scripted_answer_into_dead_session() {
    let summary = server(&[
        Step::Ask(1),
        Step::Reset,
        Step::Stray,
        Step::Reply,
        Step::Ask(2),
        Step::Reply,
    ]);
    assert_eq!(
        summary,
        Summary {
            served: 2,
            disconnects: 1,
            sessions: 2,
            ..Summary::default()
        }
    );
}

// Tests that steps with no request, no session and no held handler to act on
// are no-ops.
#[test]
fn test_scripted_noops() {
    let summary = client(&[
        Step::Wait(1),
        Step::Forget(1),
        Step::Answer(1),
        Step::Fail(1),
        Step::Reply,
        Step::Refuse,
        Step::Ignore,
        Step::Reset,
        Step::Heal,
        Step::Request(1),
        Step::Request(1),
        Step::Answer(1),
        Step::Wait(1),
    ]);
    assert_eq!(
        summary,
        Summary {
            sent: 1,
            answered: 1,
            ..Summary::default()
        }
    );
}
