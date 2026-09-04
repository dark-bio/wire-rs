// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Scenario tests of the server, scripts run against it by the mock client.

use super::*;
use crate::client::MAX_STALE_FRAMES;
use crate::testing;

/// Runs a script with logging enabled.
fn run_logged(steps: &[Step]) -> Summary {
    testing::init_tracing();
    run(steps)
}

// Tests the happy path of the state machine, a handshake followed by
// requests round tripping through the session.
#[test]
fn test_scripted_round_trip() {
    let summary = run_logged(&[
        Step::ResetPair,
        Step::Hello,
        Step::Ack,
        Step::Request(1),
        Step::Request(2),
    ]);
    assert_eq!(
        summary,
        Summary {
            state: State::Established,
            dropped: 0,
            fragments: 0,
            handshakes: 1,
            delivered: 2,
            replies: 2,
            reads: 5,
        }
    );
}

// Tests that a reset in every state restarts the handshake without the
// Server signaling anything, the client having asked for it. A session does
// not survive one, a request into it earning a signal.
#[test]
fn test_scripted_reset_restarts() {
    let summary = run_logged(&[
        Step::Reset,
        Step::Reset,
        Step::Reset,
        Step::Hello,
        Step::Ack,
    ]);
    assert_eq!(summary.state, State::Established);
    assert_eq!(summary.handshakes, 1);
    assert_eq!(summary.dropped, 0);

    let summary = run_logged(&[
        Step::Reset,
        Step::Hello,
        Step::Reset,
        Step::Hello,
        Step::Ack,
    ]);
    assert_eq!(summary.state, State::Established);
    assert_eq!(summary.handshakes, 2);
    assert_eq!(summary.dropped, 0);

    let summary = run_logged(&[
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::ResetPair,
        Step::Hello,
        Step::Ack,
        Step::Request(1),
    ]);
    assert_eq!(summary.state, State::Established);
    assert_eq!(summary.handshakes, 2);
    assert_eq!(summary.delivered, 1);
    assert_eq!(summary.dropped, 0);

    let summary = run_logged(&[
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::Reset,
        Step::Request(1),
    ]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.delivered, 0);
    assert_eq!(summary.dropped, 1);
}

// Tests that frames arriving outside the state expecting them are junk,
// a handshake only ever starting with a reset.
#[test]
fn test_scripted_frames_outside_state() {
    let summary = run_logged(&[Step::Hello]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.handshakes, 0);
    assert_eq!(summary.dropped, 1);

    let summary = run_logged(&[Step::Reset, Step::Hello, Step::Hello]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.dropped, 1);

    let summary = run_logged(&[Step::Reset, Step::Ack]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.dropped, 1);

    let summary = run_logged(&[Step::Reset, Step::Hello, Step::Request(1)]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.handshakes, 1);
    assert_eq!(summary.dropped, 1);

    let summary = run_logged(&[Step::Reset, Step::Hello, Step::Ack, Step::Hello]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.dropped, 1);
}

// Tests that frames failing the handshake's crypto for one specific
// reason each are refused with the dropped session signal. That is a
// hello with an invalid key, acks tampered with, bound or signed wrongly,
// malformed or carrying a bad encapsulation, and a tampered request in a
// session.
#[test]
fn test_scripted_bad_crypto_frames() {
    let summary = run_logged(&[Step::Reset, Step::HelloBadKey]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.handshakes, 0);
    assert_eq!(summary.dropped, 1);

    for step in [
        Step::AckTampered,
        Step::AckBadAuth,
        Step::AckBadSigner,
        Step::AckBadPayload,
        Step::AckBadEncap,
    ] {
        let summary = run_logged(&[Step::Reset, Step::Hello, step.clone()]);
        assert_eq!(summary.state, State::Idle, "{step:?}");
        assert_eq!(summary.handshakes, 1, "{step:?}");
        assert_eq!(summary.dropped, 1, "{step:?}");

        // Without an ArkHello to answer the frame is plain junk
        let summary = run_logged(&[Step::Reset, step.clone()]);
        assert_eq!(summary.state, State::Idle, "{step:?}");
        assert_eq!(summary.dropped, 1, "{step:?}");
    }

    let summary = run_logged(&[
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::RequestTampered,
        Step::Request(1),
    ]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.delivered, 0);
    assert_eq!(summary.dropped, 2);
}

// Tests that replayed frames are refused, except a replayed hello which is
// a valid hello in its own right and can be acked with its old keys.
#[test]
fn test_scripted_replays() {
    let summary = run_logged(&[Step::Reset, Step::Hello, Step::Ack, Step::AckReplay]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.dropped, 1);

    let summary = run_logged(&[
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::Request(1),
        Step::RequestReplay,
    ]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.delivered, 1);
    assert_eq!(summary.dropped, 1);

    let summary = run_logged(&[
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::Reset,
        Step::Hello,
        Step::AckReplay,
    ]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.handshakes, 2);
    assert_eq!(summary.dropped, 1);

    let summary = run_logged(&[
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::Reset,
        Step::HelloReplay,
        Step::Ack,
        Step::Request(3),
    ]);
    assert_eq!(summary.state, State::Established);
    assert_eq!(summary.handshakes, 2);
    assert_eq!(summary.delivered, 1);
    assert_eq!(summary.dropped, 0);
}

// Tests that a packet decrypting into something that is not a message
// surfaces as an error but leaves the session usable.
#[test]
fn test_scripted_garbage_keeps_session() {
    let summary = run_logged(&[
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::Garbage,
        Step::Request(1),
    ]);
    assert_eq!(summary.state, State::Established);
    assert_eq!(summary.delivered, 1);
    assert_eq!(summary.dropped, 0);
}

// Tests that junk in every state drops the server back to idle with the client
// told about it through an empty frame, and that a fresh handshake
// recovers from it.
#[test]
fn test_scripted_junk_signals_dropped() {
    let junk = || Step::Junk(vec![0xde, 0xad, 0xbe, 0xef]);

    let summary = run_logged(&[junk()]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.dropped, 1);

    let summary = run_logged(&[Step::Reset, junk()]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.dropped, 1);

    let summary = run_logged(&[Step::Reset, Step::Hello, junk()]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.handshakes, 1);
    assert_eq!(summary.dropped, 1);

    let summary = run_logged(&[Step::Reset, Step::Hello, Step::Ack, junk()]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.dropped, 1);

    // Undecodable COBS is junk like any other, as is an empty packet in
    // a frame that is not empty
    let summary = run_logged(&[
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::Junk(vec![0xff, 0x01]),
    ]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.dropped, 1);

    let summary = run_logged(&[Step::Reset, Step::Hello, Step::Ack, Step::Junk(vec![])]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.dropped, 1);

    // A fresh handshake recovers, whether the junk hit a session or a
    // handshake in progress
    let summary = run_logged(&[
        Step::Reset,
        Step::Hello,
        Step::Ack,
        junk(),
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::Request(1),
    ]);
    assert_eq!(summary.state, State::Established);
    assert_eq!(summary.delivered, 1);
    assert_eq!(summary.dropped, 1);

    let summary = run_logged(&[
        Step::Reset,
        junk(),
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::Request(1),
    ]);
    assert_eq!(summary.state, State::Established);
    assert_eq!(summary.delivered, 1);
    assert_eq!(summary.dropped, 1);
}

// Tests that every request into a session the server no longer has earns a
// signal of its own. A client pipelining a stale bound's worth of them
// queues up as many in front of its next handshake.
#[test]
fn test_scripted_requests_into_dead_session() {
    let mut steps = vec![
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::Junk(vec![0xde, 0xad]),
    ];
    steps.extend((0..MAX_STALE_FRAMES as u8).map(Step::Request));
    let summary = run_logged(&steps);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.delivered, 0);
    assert_eq!(summary.dropped, MAX_STALE_FRAMES + 1);
}

// Tests that truncated copies of valid frames are junk in every state.
#[test]
fn test_scripted_truncated_frames() {
    for cut in [0u8, 1, 7, 255] {
        let summary = run_logged(&[Step::Reset, Step::Hello, Step::Truncated(cut)]);
        assert_eq!(summary.state, State::Idle, "cut {cut}");
        assert_eq!(summary.dropped, 1, "cut {cut}");

        let summary = run_logged(&[
            Step::Reset,
            Step::Hello,
            Step::Ack,
            Step::Request(1),
            Step::Truncated(cut),
        ]);
        assert_eq!(summary.state, State::Idle, "cut {cut}");
        assert_eq!(summary.dropped, 1, "cut {cut}");
    }
}

// Tests how an unterminated frame merges with what follows it. Bytes
// swallow the next frame into junk, while a lone delimiter completes a
// partial hello into a valid one. Only the second zero of a reset pair
// gets through as a reset.
#[test]
fn test_scripted_partial_frames() {
    let summary = run_logged(&[Step::Partial, Step::Reset, Step::Hello]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.handshakes, 0);
    assert_eq!(summary.dropped, 2);

    let summary = run_logged(&[Step::Reset, Step::Partial, Step::Reset, Step::Ack]);
    assert_eq!(summary.state, State::Established);
    assert_eq!(summary.handshakes, 1);
    assert_eq!(summary.dropped, 0);

    let summary = run_logged(&[
        Step::Reset,
        Step::Partial,
        Step::ResetPair,
        Step::Hello,
        Step::Ack,
    ]);
    assert_eq!(summary.state, State::Established);
    assert_eq!(summary.handshakes, 2);
    assert_eq!(summary.dropped, 0);

    let summary = run_logged(&[Step::Reset, Step::Partial, Step::Partial, Step::Reset]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.dropped, 1);

    let summary = run_logged(&[Step::Partial, Step::ResetPair, Step::Hello, Step::Ack]);
    assert_eq!(summary.state, State::Established);
    assert_eq!(summary.dropped, 1);

    let summary = run_logged(&[
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::Partial,
        Step::Request(1),
    ]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.delivered, 0);
    assert_eq!(summary.dropped, 1);
}

// Tests that a read failing aborts a handshake in progress without a
// signal to the client, but leaves an established session intact.
#[test]
fn test_scripted_yield() {
    let summary = run_logged(&[Step::Yield]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.replies, 0);

    let summary = run_logged(&[Step::Reset, Step::Yield, Step::Hello]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.handshakes, 0);
    assert_eq!(summary.dropped, 1);

    let summary = run_logged(&[Step::Reset, Step::Hello, Step::Yield, Step::Ack]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.handshakes, 1);
    assert_eq!(summary.dropped, 1);

    let summary = run_logged(&[
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::Yield,
        Step::Request(1),
    ]);
    assert_eq!(summary.state, State::Established);
    assert_eq!(summary.delivered, 1);
    assert_eq!(summary.replies, 2);
}

// Tests a transport failing under the server's writes. A failed reply drops
// the session, the signals it would send are lost and a handshake whose
// ArkHello cannot go out is given up. A healed transport recovers, the
// first send on it starting with a resync delimiter, an empty frame.
#[test]
fn test_scripted_broken_transport() {
    let summary = run_logged(&[
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::Request(1),
        Step::Break,
        Step::Request(2),
        Step::Request(3),
        Step::Heal,
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::Request(4),
    ]);
    assert_eq!(summary.state, State::Established);
    assert_eq!(summary.delivered, 3);
    assert_eq!(summary.replies, 2);
    assert_eq!(summary.dropped, 1);

    let summary = run_logged(&[
        Step::Reset,
        Step::Break,
        Step::Hello,
        Step::Heal,
        Step::Ack,
        Step::Reset,
        Step::Hello,
        Step::Ack,
    ]);
    assert_eq!(summary.state, State::Established);
    assert_eq!(summary.handshakes, 1);
    assert_eq!(summary.dropped, 2);

    let summary = run_logged(&[
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::Break,
        Step::Yield,
        Step::Heal,
        Step::Request(1),
    ]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.delivered, 0);
    assert_eq!(summary.replies, 0);
    assert_eq!(summary.dropped, 2);
}

// Tests the server's reply cut short. The bytes that got out are terminated
// by the resync delimiter ahead of the signal, into junk or into the
// valid reply that lacked only its delimiter. A reply lost whole, or one
// whose flush failed after it went out whole, arms the resync too, its
// delimiter forming a needless empty frame ahead of the signal.
#[test]
fn test_scripted_cut_replies() {
    struct TestCase {
        point: CutPoint,
        fragments: usize,
        replies: usize,
        dropped: usize,
    }
    let tests = [
        TestCase {
            point: CutPoint::Middle(7),
            fragments: 1,
            replies: 0,
            dropped: 1,
        },
        TestCase {
            point: CutPoint::Delimiter,
            fragments: 0,
            replies: 1,
            dropped: 1,
        },
        TestCase {
            point: CutPoint::Start,
            fragments: 0,
            replies: 0,
            dropped: 2,
        },
        TestCase {
            point: CutPoint::Flush,
            fragments: 0,
            replies: 1,
            dropped: 2,
        },
    ];
    for (i, tt) in tests.into_iter().enumerate() {
        let summary = run_logged(&[
            Step::Reset,
            Step::Hello,
            Step::Ack,
            Step::Cut {
                point: tt.point,
                then_broken: false,
            },
            Step::Request(1),
        ]);
        assert_eq!(summary.state, State::Idle, "test {i}");
        assert_eq!(summary.delivered, 1, "test {i}");
        assert_eq!(summary.fragments, tt.fragments, "test {i}");
        assert_eq!(summary.replies, tt.replies, "test {i}");
        assert_eq!(summary.dropped, tt.dropped, "test {i}");
    }
}

// Tests a cut whose signal is lost too, the transport staying broken. The
// cut frame waits on the stream until the healed transport carries the
// Server's next send, the ArkHello of a fresh handshake, whose resync
// delimiter terminates it ahead of the hello.
#[test]
fn test_scripted_cut_then_broken() {
    struct TestCase {
        point: CutPoint,
        fragments: usize,
        replies: usize,
        dropped: usize,
    }
    let tests = [
        TestCase {
            point: CutPoint::Middle(7),
            fragments: 1,
            replies: 1,
            dropped: 0,
        },
        TestCase {
            point: CutPoint::Delimiter,
            fragments: 0,
            replies: 2,
            dropped: 0,
        },
        TestCase {
            point: CutPoint::Start,
            fragments: 0,
            replies: 1,
            dropped: 1,
        },
        TestCase {
            point: CutPoint::Flush,
            fragments: 0,
            replies: 2,
            dropped: 1,
        },
    ];
    for (i, tt) in tests.into_iter().enumerate() {
        let summary = run_logged(&[
            Step::Reset,
            Step::Hello,
            Step::Ack,
            Step::Cut {
                point: tt.point,
                then_broken: true,
            },
            Step::Request(1),
            Step::Heal,
            Step::Reset,
            Step::Hello,
            Step::Ack,
            Step::Request(2),
        ]);
        assert_eq!(summary.state, State::Established, "test {i}");
        assert_eq!(summary.handshakes, 2, "test {i}");
        assert_eq!(summary.delivered, 2, "test {i}");
        assert_eq!(summary.fragments, tt.fragments, "test {i}");
        assert_eq!(summary.replies, tt.replies, "test {i}");
        assert_eq!(summary.dropped, tt.dropped, "test {i}");
    }
}

// Tests the ArkHello cut short. The server gives up on the handshake and
// signals so, the resync delimiter ahead of the signal terminating what
// got out. An ArkHello lacking only its delimiter is completed into a
// valid one, which the client acks in vain. A fresh handshake recovers.
#[test]
fn test_scripted_cut_handshakes() {
    struct TestCase {
        point: CutPoint,
        handshakes: usize,
        fragments: usize,
        dropped: usize,
    }
    let tests = [
        TestCase {
            point: CutPoint::Middle(3),
            handshakes: 0,
            fragments: 1,
            dropped: 2,
        },
        TestCase {
            point: CutPoint::Delimiter,
            handshakes: 1,
            fragments: 0,
            dropped: 2,
        },
        TestCase {
            point: CutPoint::Start,
            handshakes: 0,
            fragments: 0,
            dropped: 3,
        },
        TestCase {
            point: CutPoint::Flush,
            handshakes: 1,
            fragments: 0,
            dropped: 3,
        },
    ];
    for (i, tt) in tests.into_iter().enumerate() {
        let cut = Step::Cut {
            point: tt.point,
            then_broken: false,
        };
        let summary = run_logged(&[Step::Reset, cut.clone(), Step::Hello, Step::Ack]);
        assert_eq!(summary.state, State::Idle, "test {i}");
        assert_eq!(summary.handshakes, tt.handshakes, "test {i}");
        assert_eq!(summary.fragments, tt.fragments, "test {i}");
        assert_eq!(summary.dropped, tt.dropped, "test {i}");

        let summary = run_logged(&[
            Step::Reset,
            cut,
            Step::Hello,
            Step::Reset,
            Step::Hello,
            Step::Ack,
            Step::Request(1),
        ]);
        assert_eq!(summary.state, State::Established, "test {i}");
        assert_eq!(summary.handshakes, tt.handshakes + 1, "test {i}");
        assert_eq!(summary.delivered, 1, "test {i}");
    }
}

// Tests that a cut needing a body passes over the lone delimiters of the
// Server's signals and fires on its next frame, whereas one at the start
// loses the signal it lands on, the resync it arms forming an empty frame
// ahead of the next frame.
#[test]
fn test_scripted_cut_signals() {
    struct TestCase {
        point: CutPoint,
        handshakes: usize,
        fragments: usize,
        dropped: usize,
    }
    let tests = [
        TestCase {
            point: CutPoint::Middle(1),
            handshakes: 1,
            fragments: 1,
            dropped: 2,
        },
        TestCase {
            point: CutPoint::Delimiter,
            handshakes: 2,
            fragments: 0,
            dropped: 2,
        },
        TestCase {
            point: CutPoint::Flush,
            handshakes: 2,
            fragments: 0,
            dropped: 3,
        },
    ];
    for (i, tt) in tests.into_iter().enumerate() {
        let summary = run_logged(&[
            Step::Reset,
            Step::Hello,
            Step::Ack,
            Step::Cut {
                point: tt.point,
                then_broken: false,
            },
            Step::Junk(vec![1]),
            Step::Reset,
            Step::Hello,
        ]);
        assert_eq!(summary.state, State::Idle, "test {i}");
        assert_eq!(summary.handshakes, tt.handshakes, "test {i}");
        assert_eq!(summary.fragments, tt.fragments, "test {i}");
        assert_eq!(summary.dropped, tt.dropped, "test {i}");
    }

    let summary = run_logged(&[
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::Cut {
            point: CutPoint::Start,
            then_broken: false,
        },
        Step::Junk(vec![1]),
        Step::Reset,
        Step::Hello,
        Step::Ack,
    ]);
    assert_eq!(summary.state, State::Established);
    assert_eq!(summary.handshakes, 2);
    assert_eq!(summary.dropped, 1);
}

// Tests that frames arriving in pieces, down to a byte per read, are
// reassembled and served like whole ones. A partial hello completes
// across reads the same way.
#[test]
fn test_scripted_chunked_reads() {
    for chunk in [1u8, 7, 254, 255] {
        let summary = run_logged(&[
            Step::Chunk(chunk),
            Step::Reset,
            Step::Hello,
            Step::Ack,
            Step::Request(1),
            Step::Junk(vec![1; 300]),
            Step::Reset,
            Step::Hello,
            Step::Ack,
            Step::Request(2),
        ]);
        assert_eq!(summary.state, State::Established, "chunk {chunk}");
        assert_eq!(summary.delivered, 2, "chunk {chunk}");
        assert_eq!(summary.dropped, 1, "chunk {chunk}");

        let summary = run_logged(&[
            Step::Chunk(chunk),
            Step::Reset,
            Step::Partial,
            Step::Reset,
            Step::Ack,
        ]);
        assert_eq!(summary.state, State::Established, "chunk {chunk}");
        assert_eq!(summary.handshakes, 1, "chunk {chunk}");
    }
}

// Tests that the frames of several steps batched into one read are served
// like frames arriving one per read, a partial hello completing within a
// batch too. A step the server surfaces something for ends the batch, so
// requests still arrive one per read.
#[test]
fn test_scripted_batched_reads() {
    let summary = run_logged(&[
        Step::Batch(3),
        Step::Reset,
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::Request(1),
    ]);
    assert_eq!(summary.state, State::Established);
    assert_eq!(summary.handshakes, 1);
    assert_eq!(summary.delivered, 1);
    assert_eq!(summary.reads, 3);

    let summary = run_logged(&[
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::Batch(3),
        Step::Junk(vec![1]),
        Step::Junk(vec![2]),
        Step::Junk(vec![3]),
    ]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.dropped, 3);
    assert_eq!(summary.reads, 4);

    let summary = run_logged(&[
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::Batch(3),
        Step::Request(1),
        Step::Request(2),
        Step::Request(3),
    ]);
    assert_eq!(summary.state, State::Established);
    assert_eq!(summary.delivered, 3);
    assert_eq!(summary.reads, 6);

    let summary = run_logged(&[
        Step::Reset,
        Step::Batch(2),
        Step::Partial,
        Step::Reset,
        Step::Ack,
    ]);
    assert_eq!(summary.state, State::Established);
    assert_eq!(summary.handshakes, 1);
    assert_eq!(summary.reads, 3);

    for chunk in [1u8, 7] {
        let summary = run_logged(&[
            Step::Chunk(chunk),
            Step::Batch(3),
            Step::Reset,
            Step::Reset,
            Step::Hello,
            Step::Ack,
            Step::Request(1),
        ]);
        assert_eq!(summary.state, State::Established, "chunk {chunk}");
        assert_eq!(summary.delivered, 1, "chunk {chunk}");
    }
}

// Tests that a read interrupted by a signal is retried by the framing in
// every state, the server none the wiser.
#[test]
fn test_scripted_interrupted_reads() {
    let summary = run_logged(&[
        Step::Interrupt,
        Step::Reset,
        Step::Interrupt,
        Step::Hello,
        Step::Interrupt,
        Step::Ack,
        Step::Interrupt,
        Step::Request(1),
        Step::Interrupt,
    ]);
    assert_eq!(summary.state, State::Established);
    assert_eq!(summary.handshakes, 1);
    assert_eq!(summary.delivered, 1);
    assert_eq!(summary.dropped, 0);
}

// Tests that frames past the size limit vanish in the framing in every
// state, a partial hello in front of one vanishing with it, whole or in
// pieces.
#[test]
fn test_scripted_oversized_frames() {
    let summary = run_logged(&[
        Step::Oversized,
        Step::Reset,
        Step::Oversized,
        Step::Hello,
        Step::Oversized,
        Step::Ack,
        Step::Oversized,
        Step::Request(1),
    ]);
    assert_eq!(summary.state, State::Established);
    assert_eq!(summary.handshakes, 1);
    assert_eq!(summary.delivered, 1);
    assert_eq!(summary.dropped, 0);

    let summary = run_logged(&[
        Step::Reset,
        Step::Partial,
        Step::Oversized,
        Step::Hello,
        Step::Ack,
    ]);
    assert_eq!(summary.state, State::Established);
    assert_eq!(summary.handshakes, 1);

    let summary = run_logged(&[
        Step::Chunk(255),
        Step::Reset,
        Step::Oversized,
        Step::Hello,
        Step::Ack,
        Step::Request(1),
    ]);
    assert_eq!(summary.state, State::Established);
    assert_eq!(summary.delivered, 1);
}

// Tests that steps with nothing to replay or truncate yet are no-ops.
#[test]
fn test_scripted_noops() {
    let summary = run_logged(&[
        Step::HelloReplay,
        Step::AckReplay,
        Step::RequestReplay,
        Step::Truncated(3),
        Step::Reset,
        Step::Hello,
        Step::Ack,
    ]);
    assert_eq!(summary.state, State::Established);
    assert_eq!(summary.dropped, 0);
}
