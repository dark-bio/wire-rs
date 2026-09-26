// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Server scenario tests driven by mock client scripts.

use super::*;
use crate::testing;

/// Runs a script with logging enabled.
fn run_logged(steps: &[Step]) -> Summary {
    testing::init_tracing();
    run(steps)
}

/// Tests a successful handshake followed by two request and reply exchanges.
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

/// Tests that every connection supplies a working sender and that a reset
/// refuses the retained one.
#[test]
fn test_scripted_retained_sender() {
    let summary = run_logged(&[
        // Retaining before any session leaves no sender to use
        Step::Retain,
        Step::SendRetained(0),
        Step::SendOversized,
        // The first session's sender works before any request
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::Send(1),
        // A retained copy of that sender works as well
        Step::Retain,
        Step::SendRetained(2),
        Step::Request(3),
        // A reset ends the session, refusing the retained sender
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::SendRetained(4),
        Step::Send(5),
        // Retaining the new sender restores retained sends
        Step::Retain,
        Step::SendRetained(6),
        Step::Request(7),
    ]);
    assert_eq!(summary.state, State::Established);
    assert_eq!(summary.handshakes, 2);
    assert_eq!(summary.delivered, 2);
    assert_eq!(summary.replies, 6);
    assert_eq!(summary.dropped, 0);
}

/// Tests that a local disconnect emits an empty frame and ends the session's
/// senders without a disconnect event.
#[test]
fn test_scripted_local_disconnect() {
    let summary = run_logged(&[
        // Open a session and keep a copy of its sender
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::Request(1),
        Step::Retain,
        // Disconnecting ends both senders before the call returns
        Step::Disconnect,
        Step::SendRetained(2),
        Step::Send(3),
        // A new handshake on the same stream supplies a working sender
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::SendRetained(4),
        Step::Send(5),
        Step::Request(6),
    ]);
    assert_eq!(summary.state, State::Established);
    assert_eq!(summary.handshakes, 2);
    assert_eq!(summary.delivered, 2);
    assert_eq!(summary.replies, 3);
    assert_eq!(summary.dropped, 1);
}

/// Tests that an oversized send keeps the session, while a failed send through
/// a retained sender ends it.
#[test]
fn test_scripted_retained_sender_failures() {
    let summary = run_logged(&[
        // An oversized send leaves both directions of the session usable
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::SendOversized,
        Step::Send(1),
        Step::Request(2),
        // A failed send through the retained sender ends the session for good
        Step::Retain,
        Step::Break,
        Step::SendRetained(3),
        Step::Heal,
        Step::SendRetained(4),
        // A new handshake supplies a fresh sender, and the old one stays refused
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::SendRetained(5),
        Step::Send(6),
        Step::Request(7),
    ]);
    assert_eq!(summary.state, State::Established);
    assert_eq!(summary.handshakes, 2);
    assert_eq!(summary.delivered, 2);
    assert_eq!(summary.replies, 4);
    assert_eq!(summary.dropped, 1);
}

/// Tests that owner actions met during a handshake read abort that handshake,
/// like other read interruptions.
#[test]
fn test_scripted_actions_during_handshake() {
    let summary = run_logged(&[
        // An action while waiting for HostAck aborts that handshake
        Step::Reset,
        Step::Hello,
        Step::Retain,
        Step::Send(1),
        // Disconnects work without a session, even on a broken writer
        Step::Disconnect,
        Step::Break,
        Step::Disconnect,
        Step::Heal,
        Step::Disconnect,
        // A fresh handshake still succeeds afterwards
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::Send(2),
    ]);
    assert_eq!(summary.state, State::Established);
    assert_eq!(summary.handshakes, 2);
    assert_eq!(summary.replies, 1);
    assert_eq!(summary.dropped, 3);

    // Actions between the reset's disconnect event and the next receive do
    // not cancel the handshake already scheduled by that reset
    let summary = run_logged(&[
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::Retain,
        Step::Reset,
        Step::Disconnect,
        Step::SendRetained(1),
        Step::Hello,
        Step::Ack,
        Step::Send(2),
    ]);
    assert_eq!(summary.state, State::Established);
    assert_eq!(summary.handshakes, 2);
    assert_eq!(summary.replies, 1);
    assert_eq!(summary.dropped, 1);
}

/// Tests that a reset starts a handshake in every state without a wire reply.
#[test]
fn test_scripted_reset_restarts() {
    // Repeated resets before a handshake draw no reply
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

    // A reset while waiting for HostAck restarts the handshake
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

    // A reset pair inside a session starts the next handshake
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

    // A reset ends the session, so a request after it is refused
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

/// Tests that handshake frames are refused in the wrong state.
#[test]
fn test_scripted_frames_outside_state() {
    // A HostHello needs a preceding reset
    let summary = run_logged(&[Step::Hello]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.handshakes, 0);
    assert_eq!(summary.dropped, 1);

    // A second HostHello while waiting for HostAck aborts the handshake
    let summary = run_logged(&[Step::Reset, Step::Hello, Step::Hello]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.dropped, 1);

    // A HostAck needs a pending ArkHello
    let summary = run_logged(&[Step::Reset, Step::Ack]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.dropped, 1);

    // A request during the handshake aborts it
    let summary = run_logged(&[Step::Reset, Step::Hello, Step::Request(1)]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.handshakes, 1);
    assert_eq!(summary.dropped, 1);

    // A HostHello inside a session ends it
    let summary = run_logged(&[Step::Reset, Step::Hello, Step::Ack, Step::Hello]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.dropped, 1);
}

/// Tests that invalid handshake crypto and tampered requests are refused with a
/// session-end signal.
#[test]
fn test_scripted_bad_crypto_frames() {
    // A HostHello with an invalid key fails the handshake
    let summary = run_logged(&[Step::Reset, Step::HelloBadKey]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.handshakes, 0);
    assert_eq!(summary.dropped, 1);

    // Each flawed HostAck fails the handshake too
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

        // Without a pending ArkHello, the mock sends junk instead of an ack
        let summary = run_logged(&[Step::Reset, step.clone()]);
        assert_eq!(summary.state, State::Idle, "{step:?}");
        assert_eq!(summary.dropped, 1, "{step:?}");
    }

    // A tampered request ends the session, so the next request is refused too
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

/// Tests that replayed HostAcks and requests are refused, while a replayed
/// HostHello works with a fresh ack.
#[test]
fn test_scripted_replays() {
    // A replayed HostAck inside a session ends it
    let summary = run_logged(&[Step::Reset, Step::Hello, Step::Ack, Step::AckReplay]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.dropped, 1);

    // A replayed request ends the session too
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

    // An old HostAck cannot complete a new handshake
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

    // A replayed HostHello after a reset needs a fresh ack for the new ArkHello
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

/// Tests that the transport delivers decrypted bytes without a protobuf check
/// and keeps the session usable.
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

/// Tests that invalid input in any state returns the server to idle with an
/// empty frame.
#[test]
fn test_scripted_junk_signals_dropped() {
    let junk = || Step::Junk(vec![0xde, 0xad, 0xbe, 0xef]);

    // Refuse junk while idle
    let summary = run_logged(&[junk()]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.dropped, 1);

    // Refuse junk while waiting for HostHello
    let summary = run_logged(&[Step::Reset, junk()]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.dropped, 1);

    // Refuse junk while waiting for HostAck
    let summary = run_logged(&[Step::Reset, Step::Hello, junk()]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.handshakes, 1);
    assert_eq!(summary.dropped, 1);

    // Refuse junk inside a session
    let summary = run_logged(&[Step::Reset, Step::Hello, Step::Ack, junk()]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.dropped, 1);

    // Undecodable COBS is junk
    let summary = run_logged(&[
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::Junk(vec![0xff, 0x01]),
    ]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.dropped, 1);

    // So is a nonempty frame encoding the empty packet
    let summary = run_logged(&[Step::Reset, Step::Hello, Step::Ack, Step::Junk(vec![])]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.dropped, 1);

    // A fresh handshake recovers from junk inside a session
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

    // It also recovers from junk during a handshake
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

/// Tests that each request after the session ends draws its own empty frame.
///
/// A client with many requests already in flight must drain that backlog of
/// signals.
#[test]
fn test_scripted_requests_into_dead_session() {
    // End the session with junk, then keep sending requests into it
    let stale = 40;
    let mut steps = vec![
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::Junk(vec![0xde, 0xad]),
    ];
    steps.extend((0..stale).map(Step::Request));
    let summary = run_logged(&steps);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.delivered, 0);
    assert_eq!(summary.dropped, usize::from(stale) + 1);
}

/// Tests that truncated copies of valid frames are refused as junk.
#[test]
fn test_scripted_truncated_frames() {
    for cut in [0u8, 1, 7, 255] {
        // Truncate the HostHello while the server waits for HostAck
        let summary = run_logged(&[Step::Reset, Step::Hello, Step::Truncated(cut)]);
        assert_eq!(summary.state, State::Idle, "cut {cut}");
        assert_eq!(summary.dropped, 1, "cut {cut}");

        // Truncate a request inside a session
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

/// Tests that input after an unterminated frame either completes it or merges
/// with it into junk.
#[test]
fn test_scripted_partial_frames() {
    // The delimiter completes an idle partial hello instead of resetting, so
    // both hellos arrive without a reset and are refused
    let summary = run_logged(&[Step::Partial, Step::Reset, Step::Hello]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.handshakes, 0);
    assert_eq!(summary.dropped, 2);

    // A lone delimiter completes a partial hello after a reset
    let summary = run_logged(&[Step::Reset, Step::Partial, Step::Reset, Step::Ack]);
    assert_eq!(summary.state, State::Established);
    assert_eq!(summary.handshakes, 1);
    assert_eq!(summary.dropped, 0);

    // The first zero of a reset pair completes the hello, and the second
    // starts a new handshake
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

    // Two partial hellos merge into junk
    let summary = run_logged(&[Step::Reset, Step::Partial, Step::Partial, Step::Reset]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.dropped, 1);

    // Without a prior reset, only the pair's second zero starts a handshake
    let summary = run_logged(&[Step::Partial, Step::ResetPair, Step::Hello, Step::Ack]);
    assert_eq!(summary.state, State::Established);
    assert_eq!(summary.dropped, 1);

    // A request merged into a partial hello is junk that ends the session
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

/// Tests that a frame encoding the empty packet completes a partial hello
/// whose encoding ends in a full run.
///
/// That lone `0x01` then decodes to nothing, and for any other hello the
/// merge is junk.
#[test]
fn test_scripted_partial_hello_empty_packet() {
    // Pair a reset, a partial hello and an empty packet as often as a script allows
    let rounds = MAX_STEPS / 3;
    let steps: Vec<Step> = (0..rounds)
        .flat_map(|_| [Step::Reset, Step::Partial, Step::Junk(vec![])])
        .collect();

    // Rerun with fresh keys until one hello ends in a full run and completes
    for run in 0..1000 {
        let summary = run_logged(&steps);
        assert_eq!(summary.handshakes + summary.dropped, rounds, "run {run}");
        if summary.handshakes > 0 {
            return;
        }
    }
    panic!("no partial hello ended in a full run");
}

/// Tests that a `WouldBlock` read aborts an unfinished handshake without a
/// signal and keeps an established session.
#[test]
fn test_scripted_yield() {
    // A yield while idle leaves no session for the driver's probe
    let summary = run_logged(&[Step::Yield]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.replies, 0);

    // A yield while waiting for HostHello aborts the handshake
    let summary = run_logged(&[Step::Reset, Step::Yield, Step::Hello]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.handshakes, 0);
    assert_eq!(summary.dropped, 1);

    // A yield while waiting for HostAck aborts it too
    let summary = run_logged(&[Step::Reset, Step::Hello, Step::Yield, Step::Ack]);
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.handshakes, 1);
    assert_eq!(summary.dropped, 1);

    // A yield inside a session keeps it, and the driver's probe gets through
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

/// Tests that persistent output failure ends the session or handshake it hits,
/// losing the failure signals as well.
#[test]
fn test_scripted_broken_transport() {
    let summary = run_logged(&[
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::Request(1),
        // A failed reply ends the session, and every signal after it is lost
        Step::Break,
        Step::Request(2),
        Step::Request(3),
        // Once writes recover, the next output leads with a recovery delimiter
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

    // A failed ArkHello aborts the handshake, and its signal is lost too
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

    // A failed probe ends the session as well, and the next signal leads with
    // a recovery delimiter
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

/// Tests that early adapter read timeouts leave every phase intact, from idle
/// to an established session.
///
/// They produce no notification or extra session transition.
#[test]
fn test_scripted_read_timeouts() {
    let summary = run_logged(&[
        Step::ReadTimeout,
        Step::Reset,
        Step::ReadTimeout,
        Step::Hello,
        Step::ReadTimeout,
        Step::Ack,
        Step::ReadTimeout,
        Step::Request(1),
    ]);
    assert_eq!(summary.state, State::Established);
    assert_eq!(summary.handshakes, 1);
    assert_eq!(summary.delivered, 1);
    assert_eq!(summary.replies, 1);
    assert_eq!(summary.dropped, 0);
}

/// Tests an oversized frame arriving one byte per read, which ends the session
/// until a fresh handshake.
///
/// Advancing the mock input must not copy the unread frame of over 2 MiB for
/// every byte.
#[test]
fn test_scripted_bytewise_oversized_frame() {
    let summary = run_logged(&[
        // Open a session over single-byte reads and keep its sender
        Step::Chunk(1),
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::Retain,
        // The oversized frame ends the session and refuses the retained sender
        Step::Oversized,
        Step::SendRetained(1),
        // A fresh handshake recovers the stream
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::Request(2),
    ]);
    assert_eq!(summary.state, State::Established);
    assert_eq!(summary.handshakes, 2);
    assert_eq!(summary.delivered, 1);
    assert_eq!(summary.dropped, 1);
    assert!(summary.reads > MAX_FRAME_SIZE);
}

/// Tests that ArkHello write and flush timeouts fail the receive without a
/// failure notification.
#[test]
fn test_scripted_handshake_timeouts() {
    for point in [
        CutPoint::Start,
        CutPoint::Middle(7),
        CutPoint::Delimiter,
        CutPoint::Flush,
    ] {
        let summary = run_logged(&[
            // Time out the ArkHello, leaving no budget for a notification
            Step::Reset,
            Step::Timeout(point),
            Step::Hello,
            // The next handshake terminates whatever prefix reached the client
            Step::Reset,
            Step::Hello,
            Step::Ack,
            Step::Request(1),
        ]);
        assert_eq!(summary.state, State::Established, "{point:?}");
        assert_eq!(summary.delivered, 1, "{point:?}");
        assert_eq!(summary.replies, 1, "{point:?}");
        assert_eq!(
            summary.dropped,
            usize::from(matches!(point, CutPoint::Start | CutPoint::Flush)),
            "{point:?}"
        );
    }
}

/// Tests that an expired send ends its session without a notification write.
#[test]
fn test_scripted_send_timeouts() {
    for point in [
        CutPoint::Start,
        CutPoint::Middle(7),
        CutPoint::Delimiter,
        CutPoint::Flush,
    ] {
        let summary = run_logged(&[
            // Open a session and keep a copy of its sender
            Step::Reset,
            Step::Hello,
            Step::Ack,
            Step::Retain,
            // The expired send starts no notification, and later retained
            // sends emit nothing
            Step::Timeout(point),
            Step::Send(1),
            Step::SendRetained(2),
            Step::SendRetained(3),
            // Only the next handshake's recovery delimiter ends any old prefix
            Step::Reset,
            Step::Hello,
            Step::Ack,
            Step::Request(4),
        ]);
        assert_eq!(summary.state, State::Established, "{point:?}");
        assert_eq!(summary.delivered, 1, "{point:?}");
        assert_eq!(
            summary.dropped,
            usize::from(matches!(point, CutPoint::Start | CutPoint::Flush)),
            "{point:?}"
        );
        assert_eq!(
            summary.replies,
            1 + usize::from(matches!(point, CutPoint::Delimiter | CutPoint::Flush)),
            "{point:?}"
        );
    }
}

/// Tests cuts in an ArkHello that carries a pending recovery delimiter.
///
/// Offset zero accepts only the recovery delimiter, while positive offsets
/// leave a fragment. The cut must fire even when ordinary writes are also
/// configured to fail.
#[test]
fn test_scripted_recovery_prefix_cuts() {
    for offset in [0, 1, u16::MAX] {
        for broken in [false, true] {
            let summary = run_logged(&[
                // Leave a recovery delimiter pending behind an expired send
                Step::Reset,
                Step::Hello,
                Step::Ack,
                Step::Timeout(CutPoint::Start),
                Step::Send(1),
                // Cut the ArkHello that carries that delimiter
                Step::Cut {
                    point: CutPoint::Middle(offset),
                    then_broken: broken,
                },
                Step::Reset,
                Step::Hello,
                // Recover with a fresh handshake once writes work
                Step::Heal,
                Step::Reset,
                Step::Hello,
                Step::Ack,
                Step::Request(2),
            ]);
            assert_eq!(
                summary.state,
                State::Established,
                "offset {offset}, broken {broken}"
            );
            assert_eq!(summary.handshakes, 2, "offset {offset}, broken {broken}");
            assert_eq!(summary.delivered, 1, "offset {offset}, broken {broken}");
            assert_eq!(
                summary.fragments,
                usize::from(offset != 0),
                "offset {offset}, broken {broken}"
            );
            assert_eq!(
                summary.dropped,
                1 + usize::from(offset == 0) + usize::from(!broken),
                "offset {offset}, broken {broken}"
            );
        }
    }
}

/// Tests cuts that hit a recovery delimiter and session-end signal written
/// together.
///
/// `Delimiter` accepts only the recovery delimiter, while `Flush` accepts both
/// zeros before failing.
#[test]
fn test_scripted_recovery_signal_cuts() {
    for point in [CutPoint::Delimiter, CutPoint::Flush] {
        let summary = run_logged(&[
            // Leave a recovery delimiter pending behind an expired send
            Step::Reset,
            Step::Hello,
            Step::Ack,
            Step::Timeout(CutPoint::Start),
            Step::Send(1),
            // Cut the delimiter and signal that answer the junk
            Step::Cut {
                point,
                then_broken: false,
            },
            Step::Junk(vec![0xde, 0xad]),
            // The next handshake recovers the same stream
            Step::Reset,
            Step::Hello,
            Step::Ack,
            Step::Request(2),
        ]);
        assert_eq!(summary.state, State::Established, "{point:?}");
        assert_eq!(summary.handshakes, 2, "{point:?}");
        assert_eq!(summary.delivered, 1, "{point:?}");
        assert_eq!(
            summary.dropped,
            2 + usize::from(point == CutPoint::Flush),
            "{point:?}"
        );
    }
}

/// Tests reply failures at each output boundary.
///
/// The recovery delimiter before the failure signal terminates any partial
/// body. A complete body becomes a valid reply, and without a pending body the
/// delimiter creates an extra empty frame.
#[test]
fn test_scripted_cut_replies() {
    /// Expected wire output after a reply fails at this boundary.
    struct TestCase {
        /// Point where the reply's write fails.
        point: CutPoint,
        /// Cut frames the server leaves behind.
        fragments: usize,
        /// Replies that reach the client.
        replies: usize,
        /// Empty frames the server emits.
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

    // Cut the reply to a single request at each boundary
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

/// Tests a partial reply whose failure signal is lost as well.
///
/// Its bytes stay pending until writes recover. The next ArkHello's recovery
/// delimiter must terminate them before the new response begins.
#[test]
fn test_scripted_cut_then_broken() {
    /// Expected output after a cut reply and a later successful reconnect.
    struct TestCase {
        /// Point where the reply's write fails.
        point: CutPoint,
        /// Cut frames the server leaves behind.
        fragments: usize,
        /// Replies that reach the client.
        replies: usize,
        /// Empty frames the server emits.
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

    // Cut the reply at each boundary, then heal and reconnect
    for (i, tt) in tests.into_iter().enumerate() {
        let summary = run_logged(&[
            Step::Reset,
            Step::Hello,
            Step::Ack,
            // Cut the reply to a request and break every write after it
            Step::Cut {
                point: tt.point,
                then_broken: true,
            },
            Step::Request(1),
            // Heal and reconnect, which terminates the pending bytes
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

/// Tests failed ArkHello output and the refused ack that follows it.
///
/// The recovery delimiter before the failure signal completes any pending
/// body. Even when that produces a valid ArkHello, the server has already
/// abandoned its handshake.
#[test]
fn test_scripted_cut_handshakes() {
    /// Expected output after ArkHello fails and the client attempts an ack.
    struct TestCase {
        /// Point where the ArkHello's write fails.
        point: CutPoint,
        /// ArkHellos that reach the client.
        handshakes: usize,
        /// Cut frames the server leaves behind.
        fragments: usize,
        /// Empty frames the server emits.
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
        // The ack after a failed ArkHello is refused, whatever reached the client
        let cut = Step::Cut {
            point: tt.point,
            then_broken: false,
        };
        let summary = run_logged(&[Step::Reset, cut.clone(), Step::Hello, Step::Ack]);
        assert_eq!(summary.state, State::Idle, "test {i}");
        assert_eq!(summary.handshakes, tt.handshakes, "test {i}");
        assert_eq!(summary.fragments, tt.fragments, "test {i}");
        assert_eq!(summary.dropped, tt.dropped, "test {i}");

        // A fresh reset recovers the stream
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

/// Tests that body cuts skip a lone signal delimiter and stay armed for the
/// next frame.
#[test]
fn test_scripted_cut_signals() {
    /// Expected output when a body cut skips a signal and reaches ArkHello.
    struct TestCase {
        /// Point where the armed cut fires.
        point: CutPoint,
        /// ArkHellos that reach the client.
        handshakes: usize,
        /// Cut frames the server leaves behind.
        fragments: usize,
        /// Empty frames the server emits.
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

    // A body cut skips the signal answering the junk and hits the next ArkHello
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

    // A cut at `Start` refuses the signal itself, so the next output leads
    // with a recovery delimiter
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

/// Tests frame assembly across reads as small as one byte.
#[test]
fn test_scripted_chunked_reads() {
    for chunk in [1u8, 7, 254, 255] {
        // Assemble handshakes, requests and a long junk frame from small reads
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

        // Complete a partial hello with a delimiter from a later step
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

/// Tests several frames arriving in one read, with the batch ending at each
/// receive event.
///
/// The driver then handles each request or session transition before the
/// model advances again.
#[test]
fn test_scripted_batched_reads() {
    // A reset pair and a HostHello share one read
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

    // The first invalid frame ends the session and this batch. The next two
    // arrive in separate reads after the driver handles `Disconnected`.
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
    assert_eq!(summary.reads, 6);

    // Each delivered request ends the batch as well
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

    // A partial hello completes within one batched read
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

    // Batches also work with small reads
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

/// Tests that framing retries `Interrupted` reads in every state without a
/// server event or a session change.
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

/// Tests that oversized input is refused outside a session and ends an active
/// one.
#[test]
fn test_scripted_oversized_frames() {
    let summary = run_logged(&[
        // Oversized input outside a session is refused
        Step::Oversized,
        // Open a session and keep a copy of its sender
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::Retain,
        Step::Request(1),
        // Oversized input ends the session, and its delimiter is no reset
        Step::Oversized,
        Step::SendRetained(2),
        Step::Request(3),
        // A fresh handshake restores requests but not the retained sender
        Step::ResetPair,
        Step::Hello,
        Step::Ack,
        Step::SendRetained(4),
        Step::Request(5),
    ]);
    assert_eq!(summary.state, State::Established);
    assert_eq!(summary.handshakes, 2);
    assert_eq!(summary.delivered, 2);
    assert_eq!(summary.replies, 2);
    assert_eq!(summary.dropped, 3);
}

/// Tests that oversized input aborts a handshake waiting for HostHello or
/// HostAck.
#[test]
fn test_scripted_oversized_handshakes() {
    for awaiting_ack in [false, true] {
        // Wait for HostHello, or for HostAck after one
        let mut steps = vec![Step::Reset];
        if awaiting_ack {
            steps.push(Step::Hello);
        }

        // After oversized input, handshake frames need a fresh reset
        steps.extend([
            Step::Oversized,
            Step::Hello,
            Step::Ack,
            Step::ResetPair,
            Step::Hello,
            Step::Ack,
            Step::Request(1),
        ]);
        let summary = run_logged(&steps);
        assert_eq!(summary.state, State::Established);
        assert_eq!(summary.handshakes, 1 + usize::from(awaiting_ack));
        assert_eq!(summary.delivered, 1);
        assert_eq!(summary.replies, 1);
        assert_eq!(summary.dropped, 3);
    }
}

/// Tests early rejection of an oversized frame that a partial hello precedes.
///
/// The cases cover chunked input and batches holding its tail and a later
/// reset. The discarded frame's delimiter is consumed once, and the real reset
/// survives.
#[test]
fn test_scripted_oversized_partial_and_batches() {
    for chunk in [0, 255] {
        for established in [false, true] {
            // Start while waiting for HostHello, or inside a session
            let mut steps = vec![Step::Chunk(chunk), Step::Reset];
            if established {
                steps.extend([Step::Hello, Step::Ack, Step::Retain]);
            }

            // Batch a partial hello, an oversized frame and a real reset, which
            // lands in a later read if the oversized frame ends a session
            steps.extend([
                Step::Batch(3),
                Step::Partial,
                Step::Oversized,
                Step::ResetPair,
                // The real reset survives, so a fresh handshake succeeds
                Step::Hello,
                Step::Ack,
                Step::SendRetained(1),
                Step::Request(2),
            ]);
            let summary = run_logged(&steps);
            assert_eq!(summary.state, State::Established);
            assert_eq!(summary.handshakes, 1 + usize::from(established));
            assert_eq!(summary.delivered, 1);
            assert_eq!(summary.replies, 1);
            assert_eq!(summary.dropped, 1);
        }
    }
}

/// Tests that steps with nothing to replay or truncate yet send nothing.
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
