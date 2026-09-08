// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Server scenario tests driven by mock client scripts.

use super::*;
use crate::testing;

/// Runs a script with logging enabled.
fn run_logged(steps: &[Step]) -> Summary {
    testing::init_tracing();
    run(steps)
}

// Tests a successful handshake followed by two request/reply exchanges.
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

// Tests that each connection event supplies a working sender before any request,
// and that disconnect precedes the next connection. A retained sender is refused
// after the peer resets; replacing it with the new sender restores sending.
#[test]
fn test_scripted_retained_sender() {
    let summary = run_logged(&[
        Step::Retain,
        Step::SendRetained(0),
        Step::SendOversized,
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::Send(1),
        Step::Retain,
        Step::SendRetained(2),
        Step::Request(3),
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::SendRetained(4),
        Step::Send(5),
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

// Tests that local disconnection emits an empty frame and invalidates senders
// before returning, without a local disconnect event. Reconnecting the same stream
// supplies a working sender while the retained old sender remains unusable.
#[test]
fn test_scripted_local_disconnect() {
    let summary = run_logged(&[
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::Request(1),
        Step::Retain,
        Step::Disconnect,
        Step::SendRetained(2),
        Step::Send(3),
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

// Tests that oversize refusal leaves sending and receiving usable, but a failed
// send through a retained handle ends both. A later handshake creates a fresh
// sender; neither healing nor reconnecting revives the retained one.
#[test]
fn test_scripted_retained_sender_failures() {
    let summary = run_logged(&[
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::SendOversized,
        Step::Send(1),
        Step::Request(2),
        Step::Retain,
        Step::Break,
        Step::SendRetained(3),
        Step::Heal,
        Step::SendRetained(4),
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

// Tests owner actions encountered while a handshake is reading. They yield to
// the driver, aborting that handshake like other read interruptions. Disconnect
// and send actions remain valid without a session, including on a broken writer.
#[test]
fn test_scripted_actions_during_handshake() {
    let summary = run_logged(&[
        Step::Reset,
        Step::Hello,
        Step::Retain,
        Step::Send(1),
        Step::Disconnect,
        Step::Break,
        Step::Disconnect,
        Step::Heal,
        Step::Disconnect,
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
    // not cancel the handshake already scheduled by that reset.
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

// Tests that a reset starts a handshake in every state without a wire reply.
// It ends any existing session, so later requests using that session are refused.
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

// Tests that handshake frames are rejected in the wrong state. HostHello needs
// a preceding reset, and HostAck needs a pending ArkHello.
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

// Tests handshake rejection for each invalid key, authentication field, signature,
// payload, and encapsulation. Each failure emits a session-end signal. Tampered
// requests also end an established session.
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

        // Without a pending ArkHello, the mock sends junk instead of an ack.
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

// Tests rejection of replayed HostAcks and requests. Reusing HostHello keys after
// a reset is allowed, but requires a fresh ack for the new server response.
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

// Tests that transport delivers decrypted bytes without checking protobuf validity
// and leaves the session usable for the next request.
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

// Tests that invalid input returns the server to idle and emits an empty frame.
// A fresh handshake restores the session after failure in any state.
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

    // Both undecodable COBS and a nonempty frame encoding an empty packet are junk.
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

    // A fresh handshake recovers from invalid session or handshake input.
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

// Tests that each request after session loss produces its own empty-frame signal.
// A client with many requests already in flight must drain that signal backlog.
#[test]
fn test_scripted_requests_into_dead_session() {
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

// Tests input after an unterminated frame. A lone delimiter completes a partial
// hello; other bytes merge into invalid input. The first zero of a reset pair
// completes the old frame, and the second starts the new handshake.
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

// Tests that a WouldBlock read aborts an unfinished handshake without a wire
// signal, while an established session remains usable.
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

// Tests persistent server output failure. A failed reply ends the session and
// a failed ArkHello aborts the handshake. Failure signals are lost too. Once
// writes recover, the next output starts with a recovery delimiter.
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

// Tests expired read polls while idle, during both handshake phases, and in an
// established session. Polling timeouts leave every phase intact and produce no
// notification or extra session transition.
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

// Tests an oversized frame arriving one byte at a time, ending the session and
// refusing its retained sender before a fresh handshake recovers. Advancing the
// mock input must not copy the unread multi-megabyte frame for every byte.
#[test]
fn test_scripted_bytewise_oversized_frame() {
    let summary = run_logged(&[
        Step::Chunk(1),
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::Retain,
        Step::Oversized,
        Step::SendRetained(1),
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

// Tests ArkHello write and flush timeouts surfacing from receive without a new
// notification budget. The failed attempt leaves the stream reusable, and the
// next handshake resynchronizes whatever prefix reached the client.
#[test]
fn test_scripted_handshake_timeouts() {
    for point in [
        CutPoint::Start,
        CutPoint::Middle(7),
        CutPoint::Delimiter,
        CutPoint::Flush,
    ] {
        let summary = run_logged(&[
            Step::Reset,
            Step::Timeout(point),
            Step::Hello,
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

// Tests that an expired send does not start a fresh notification write, and
// repeated use of its retained sender emits nothing. A later reset allows a new
// handshake; only that handshake's resync delimiter terminates any old prefix.
#[test]
fn test_scripted_send_timeouts() {
    for point in [
        CutPoint::Start,
        CutPoint::Middle(7),
        CutPoint::Delimiter,
        CutPoint::Flush,
    ] {
        let summary = run_logged(&[
            Step::Reset,
            Step::Hello,
            Step::Ack,
            Step::Retain,
            Step::Timeout(point),
            Step::Send(1),
            Step::SendRetained(2),
            Step::SendRetained(3),
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

// Tests cutting a combined recovery delimiter and ArkHello after an earlier
// timeout. Offset zero accepts only recovery; positive offsets leave a fragment.
// The cut must fire even when ordinary writes are also configured to fail.
#[test]
fn test_scripted_recovery_prefix_cuts() {
    for offset in [0, 1, u16::MAX] {
        for broken in [false, true] {
            let summary = run_logged(&[
                Step::Reset,
                Step::Hello,
                Step::Ack,
                Step::Timeout(CutPoint::Start),
                Step::Send(1),
                Step::Cut {
                    point: CutPoint::Middle(offset),
                    then_broken: broken,
                },
                Step::Reset,
                Step::Hello,
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

// Tests cuts that apply to a recovery delimiter and session-end signal
// offered together. Delimiter accepts only recovery; Flush accepts both zeros
// before failing. The next handshake recovers the same stream in either case.
#[test]
fn test_scripted_recovery_signal_cuts() {
    for point in [CutPoint::Delimiter, CutPoint::Flush] {
        let summary = run_logged(&[
            Step::Reset,
            Step::Hello,
            Step::Ack,
            Step::Timeout(CutPoint::Start),
            Step::Send(1),
            Step::Cut {
                point,
                then_broken: false,
            },
            Step::Junk(vec![0xde, 0xad]),
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

// Tests reply failures at each output boundary. The recovery delimiter before
// the failure signal terminates any partial body. A complete body becomes a
// valid reply; no pending body means the delimiter creates an extra empty frame.
#[test]
fn test_scripted_cut_replies() {
    /// Expected wire output after a reply fails at this boundary.
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

// Tests a partial reply whose failure signal is also lost. Its bytes remain
// pending until writes recover. The next ArkHello's recovery delimiter must
// terminate those bytes before the new response begins.
#[test]
fn test_scripted_cut_then_broken() {
    /// Expected output after a cut reply and a later successful reconnect.
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

// Tests failed ArkHello output. The recovery delimiter before the failure signal
// completes any pending body. Even if that produces a valid ArkHello, the server
// has already abandoned its handshake and rejects the ack. A fresh reset recovers.
#[test]
fn test_scripted_cut_handshakes() {
    /// Expected output after ArkHello fails and the client attempts an ack.
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

// Tests that body cuts skip a lone signal delimiter and stay armed for the next
// frame. A cut at Start rejects the signal itself, requiring a recovery delimiter
// before the next output.
#[test]
fn test_scripted_cut_signals() {
    /// Expected output when a body cut skips a signal and reaches ArkHello.
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

// Tests frame assembly across reads as small as one byte, including a partial
// hello whose delimiter arrives in a later step.
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

// Tests several frames arriving in one read, including a partial hello completed
// within the batch. The mock ends a batch at a receive event so the driver can
// handle each request or session transition before the model advances again.
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
    // The first invalid frame ends the session and this batch. The next two
    // arrive in separate reads after the driver handles Disconnected.
    assert_eq!(summary.state, State::Idle);
    assert_eq!(summary.dropped, 3);
    assert_eq!(summary.reads, 6);

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

// Tests that framing retries Interrupted reads in every state without emitting
// a server event or changing the session.
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

// Tests that oversized input is refused outside a session and ends an active
// session, invalidating retained senders. Its delimiter does not act as a reset;
// a fresh reset and handshake are needed before another request can succeed.
#[test]
fn test_scripted_oversized_frames() {
    let summary = run_logged(&[
        Step::Oversized,
        Step::Reset,
        Step::Hello,
        Step::Ack,
        Step::Retain,
        Step::Request(1),
        Step::Oversized,
        Step::SendRetained(2),
        Step::Request(3),
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

// Tests that oversized input aborts both waiting for HostHello and waiting for
// HostAck. Further handshake packets are refused until a fresh reset arrives.
#[test]
fn test_scripted_oversized_handshakes() {
    for awaiting_ack in [false, true] {
        let mut steps = vec![Step::Reset];
        if awaiting_ack {
            steps.push(Step::Hello);
        }
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

// Tests early rejection when a partial hello precedes an oversized frame,
// including chunked input and batches containing its tail and a later reset.
// The discarded frame's delimiter is consumed once, and the real reset survives.
#[test]
fn test_scripted_oversized_partial_and_batches() {
    for chunk in [0, 255] {
        for established in [false, true] {
            let mut steps = vec![Step::Chunk(chunk), Step::Reset];
            if established {
                steps.extend([Step::Hello, Step::Ack, Step::Retain]);
            }
            steps.extend([
                Step::Batch(3),
                Step::Partial,
                Step::Oversized,
                Step::ResetPair,
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
