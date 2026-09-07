// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Scenario tests of the client, scripts run against it by the mock server.

use super::*;
use crate::testing;

/// Runs a script with logging enabled.
fn run_logged(steps: &[Step]) -> Summary {
    testing::init_tracing();
    run(steps)
}

// Tests the happy path of the state machine, a handshake followed by
// requests and replies through the session, one at a time and pipelined.
#[test]
fn test_scripted_round_trip() {
    let summary = run_logged(&[
        Step::Handshake,
        Step::Hello,
        Step::Send(1),
        Step::Reply(1),
        Step::Recv,
        Step::Send(2),
        Step::Send(3),
        Step::Reply(2),
        Step::Reply(3),
        Step::Recv,
        Step::Recv,
    ]);
    assert_eq!(
        summary,
        Summary {
            established: true,
            handshakes: 1,
            messages: 3,
            resets: 0,
            failures: 0,
            reads: 4,
        }
    );
}

// Tests that flawed hellos fail the handshake once found, each with its
// own error, leaving the client without a session. That is a hello tampered
// with, bound or signed wrongly, malformed, carrying a bad key or
// encapsulation, or an attestation of the wrong shape.
#[test]
fn test_scripted_flawed_hellos() {
    for flaw in [
        Step::HelloTampered,
        Step::HelloBadAuth,
        Step::HelloBadSigner,
        Step::HelloBadPayload,
        Step::HelloBadKey,
        Step::HelloBadEncap,
        Step::HelloBadAttest,
    ] {
        let summary = run_logged(&[Step::Handshake, flaw.clone(), Step::Send(1)]);
        assert!(!summary.established, "{flaw:?}");
        assert_eq!(summary.failures, 1, "{flaw:?}");

        // Without a hello to answer the frame is plain junk
        let summary = run_logged(&[flaw.clone(), Step::Recv]);
        assert!(!summary.established, "{flaw:?}");
        assert_eq!(summary.failures, 1, "{flaw:?}");
    }
}

// Tests that frames not meant for the handshake in progress are skipped
// as stale, up to the bound.
#[test]
fn test_scripted_stale_skipping() {
    let summary = run_logged(&[
        Step::Dropped,
        Step::Junk(vec![1, 2, 3]),
        Step::Handshake,
        Step::HelloStale,
        Step::Dropped,
        Step::Junk(vec![]),
        Step::Hello,
    ]);
    assert!(summary.established);
    assert_eq!(summary.failures, 0);

    // A reply left unread from the previous session is stale too
    let summary = run_logged(&[
        Step::Handshake,
        Step::Hello,
        Step::Send(1),
        Step::Reply(1),
        Step::Handshake,
        Step::Hello,
        Step::Send(2),
        Step::Reply(2),
        Step::Recv,
    ]);
    assert_eq!(summary.handshakes, 2);
    assert_eq!(summary.messages, 1);
    assert_eq!(summary.failures, 0);

    // An old ArkHello left over from a completed handshake is stale too
    let summary = run_logged(&[
        Step::Handshake,
        Step::Hello,
        Step::Hello,
        Step::Handshake,
        Step::Hello,
    ]);
    assert_eq!(summary.handshakes, 2);
    assert!(summary.established);

    let mut steps = vec![Step::Handshake];
    steps.extend(std::iter::repeat_n(Step::Dropped, MAX_STALE_FRAMES));
    steps.push(Step::Hello);
    let summary = run_logged(&steps);
    assert!(summary.established);

    let mut steps = vec![Step::Handshake];
    steps.extend(std::iter::repeat_n(Step::Dropped, MAX_STALE_FRAMES + 1));
    steps.push(Step::Hello);
    let summary = run_logged(&steps);
    assert!(!summary.established);
    assert_eq!(summary.failures, 1);

    // A frame failing to decode, the leftover of a transfer cut short, is
    // stale like any other
    let summary = run_logged(&[Step::Handshake, Step::Undecodable, Step::Hello]);
    assert!(summary.established);
    assert_eq!(summary.failures, 0);
}

// Tests that a read failing and the transport ending both abort a
// handshake with their own errors.
#[test]
fn test_scripted_handshake_interrupted() {
    let summary = run_logged(&[Step::Handshake, Step::Yield, Step::Send(1)]);
    assert!(!summary.established);
    assert_eq!(summary.failures, 1);

    let summary = run_logged(&[Step::Handshake]);
    assert!(!summary.established);
    assert_eq!(summary.failures, 1);
}

// Tests that a packet decrypting into something that is not a message
// surfaces as an error but leaves the session usable.
#[test]
fn test_scripted_garbage_keeps_session() {
    let summary = run_logged(&[
        Step::Handshake,
        Step::Hello,
        Step::Garbage,
        Step::Recv,
        Step::Reply(2),
        Step::Recv,
    ]);
    assert!(summary.established);
    assert_eq!(summary.messages, 1);
    assert_eq!(summary.failures, 1);
}

// Tests that packets the session cannot open drop it. That is a replayed
// reply, one from an earlier session, a tampered one, junk, a leftover
// ArkHello and an undecodable frame.
#[test]
fn test_scripted_undecryptable_drops_session() {
    let summary = run_logged(&[
        Step::Handshake,
        Step::Hello,
        Step::Reply(1),
        Step::ReplyReplay,
        Step::Recv,
        Step::Recv,
        Step::Send(1),
    ]);
    assert!(!summary.established);
    assert_eq!(summary.messages, 1);
    assert_eq!(summary.failures, 1);

    let summary = run_logged(&[
        Step::Handshake,
        Step::Hello,
        Step::Reply(1),
        Step::Recv,
        Step::Handshake,
        Step::Hello,
        Step::ReplyReplay,
        Step::Recv,
    ]);
    assert!(!summary.established);
    assert_eq!(summary.handshakes, 2);
    assert_eq!(summary.messages, 1);
    assert_eq!(summary.failures, 1);

    let summary = run_logged(&[
        Step::Handshake,
        Step::Hello,
        Step::ReplyTampered,
        Step::Recv,
    ]);
    assert!(!summary.established);

    let summary = run_logged(&[
        Step::Handshake,
        Step::Hello,
        Step::Junk(vec![7]),
        Step::Recv,
    ]);
    assert!(!summary.established);

    let summary = run_logged(&[Step::Handshake, Step::Hello, Step::Hello, Step::Recv]);
    assert!(!summary.established);

    let summary = run_logged(&[Step::Handshake, Step::Hello, Step::Undecodable, Step::Recv]);
    assert!(!summary.established);
}

// Tests that the server signaling a dropped session surfaces as a reset and
// drops the client's session, sends failing until a new handshake. A
// request sent before the signal is read still goes out.
#[test]
fn test_scripted_dropped_signal() {
    let summary = run_logged(&[
        Step::Handshake,
        Step::Hello,
        Step::Dropped,
        Step::Recv,
        Step::Send(1),
        Step::Handshake,
        Step::Hello,
        Step::Send(2),
    ]);
    assert!(summary.established);
    assert_eq!(summary.handshakes, 2);
    assert_eq!(summary.resets, 1);
    assert_eq!(summary.failures, 0);

    let summary = run_logged(&[
        Step::Handshake,
        Step::Hello,
        Step::Dropped,
        Step::Send(1),
        Step::Recv,
        Step::Send(2),
    ]);
    assert!(!summary.established);
    assert_eq!(summary.resets, 1);
    assert_eq!(summary.failures, 0);

    // Without a session the signal still surfaces as a reset, so a request
    // the server answered with a signal of its own shows up as a second reset
    let summary = run_logged(&[Step::Dropped, Step::Recv]);
    assert_eq!(summary.resets, 1);

    let summary = run_logged(&[
        Step::Handshake,
        Step::Hello,
        Step::Dropped,
        Step::Dropped,
        Step::Recv,
        Step::Recv,
    ]);
    assert!(!summary.established);
    assert_eq!(summary.resets, 2);
}

// Tests that reads without a session consume a frame and fail with the
// error matching the frame, the session check coming after the read.
#[test]
fn test_scripted_recv_without_session() {
    let summary = run_logged(&[Step::Junk(vec![1]), Step::Recv]);
    assert_eq!(summary.failures, 1);

    let summary = run_logged(&[Step::Undecodable, Step::Recv]);
    assert_eq!(summary.failures, 1);

    let summary = run_logged(&[Step::Recv]);
    assert_eq!(summary.failures, 1);

    let summary = run_logged(&[Step::Send(1)]);
    assert_eq!(summary.failures, 0);
}

// Tests that a read failing in a session drops the session, the client not
// knowing what it missed. So does the transport ending.
#[test]
fn test_scripted_read_failure_drops_session() {
    let summary = run_logged(&[Step::Handshake, Step::Hello, Step::Recv, Step::Send(1)]);
    assert!(!summary.established);
    assert_eq!(summary.failures, 1);

    let summary = run_logged(&[Step::Handshake, Step::Hello, Step::Recv]);
    assert!(!summary.established);
    assert_eq!(summary.failures, 1);
}

// Tests a transport failing under the client's writes. A send fails and
// drops the session, a handshake fails at its reset or at its ack, and a
// healed transport recovers.
#[test]
fn test_scripted_broken_transport() {
    let summary = run_logged(&[
        Step::Handshake,
        Step::Hello,
        Step::Break,
        Step::Send(1),
        Step::Send(2),
        Step::Handshake,
        Step::Heal,
        Step::Handshake,
        Step::Hello,
        Step::Send(3),
    ]);
    assert!(summary.established);
    assert_eq!(summary.handshakes, 2);
    assert_eq!(summary.failures, 1);

    let summary = run_logged(&[
        Step::Handshake,
        Step::Break,
        Step::Hello,
        Step::Heal,
        Step::Handshake,
        Step::Hello,
    ]);
    assert!(summary.established);
    assert_eq!(summary.handshakes, 1);
    assert_eq!(summary.failures, 1);
}

// Tests the client's sends cut short. A cut request fails the send and
// drops the session, the reset of the next handshake terminating what got
// out, junk or the request itself, ahead of its hello. A cut reset, hello
// or ack fails the handshake before anything is read, a fresh handshake
// recovering either way.
#[test]
fn test_scripted_cut_sends() {
    for point in [
        CutPoint::Start,
        CutPoint::Middle(5),
        CutPoint::Delimiter,
        CutPoint::Flush,
    ] {
        let cut = Step::Cut {
            point,
            then_broken: false,
        };

        let summary = run_logged(&[
            Step::Handshake,
            Step::Hello,
            cut.clone(),
            Step::Send(1),
            Step::Handshake,
            Step::Hello,
            Step::Send(2),
        ]);
        assert!(summary.established, "{point:?}");
        assert_eq!(summary.handshakes, 2, "{point:?}");
        assert_eq!(summary.failures, 0, "{point:?}");

        let summary = run_logged(&[cut.clone(), Step::Handshake, Step::Handshake, Step::Hello]);
        assert!(summary.established, "{point:?}");
        assert_eq!(summary.handshakes, 1, "{point:?}");
        assert_eq!(summary.failures, 1, "{point:?}");

        let summary = run_logged(&[
            Step::Handshake,
            cut,
            Step::Hello,
            Step::Handshake,
            Step::Hello,
        ]);
        assert!(summary.established, "{point:?}");
        assert_eq!(summary.handshakes, 1, "{point:?}");
        assert_eq!(summary.failures, 1, "{point:?}");
    }

    // A transport staying broken after the cut heals into a working
    // handshake, the fragment waiting on the stream until then
    let summary = run_logged(&[
        Step::Handshake,
        Step::Hello,
        Step::Cut {
            point: CutPoint::Middle(5),
            then_broken: true,
        },
        Step::Send(1),
        Step::Handshake,
        Step::Heal,
        Step::Handshake,
        Step::Hello,
    ]);
    assert!(summary.established);
    assert_eq!(summary.handshakes, 2);
    assert_eq!(summary.failures, 1);
}

// Tests that frames arriving in pieces, down to a byte per read, are
// reassembled and read like whole ones.
#[test]
fn test_scripted_chunked_reads() {
    for chunk in [1u8, 7, 254, 255] {
        let summary = run_logged(&[
            Step::Chunk(chunk),
            Step::Handshake,
            Step::Hello,
            Step::Send(1),
            Step::Reply(1),
            Step::Recv,
            Step::Junk(vec![1; 300]),
            Step::Recv,
            Step::Handshake,
            Step::Hello,
        ]);
        assert!(summary.established, "chunk {chunk}");
        assert_eq!(summary.messages, 1, "chunk {chunk}");
        assert_eq!(summary.handshakes, 2, "chunk {chunk}");
    }
}

// Tests that frames batched into one read are read like frames arriving
// one per read, the batch ending at the frame settling the call, so a
// read never takes in more than its call consumes.
#[test]
fn test_scripted_batched_reads() {
    let summary = run_logged(&[
        Step::Handshake,
        Step::Batch(3),
        Step::Dropped,
        Step::Junk(vec![1]),
        Step::Hello,
    ]);
    assert!(summary.established);
    assert_eq!(summary.reads, 1);

    let summary = run_logged(&[
        Step::Handshake,
        Step::Batch(2),
        Step::Undecodable,
        Step::Hello,
    ]);
    assert!(summary.established);
    assert_eq!(summary.reads, 1);

    let summary = run_logged(&[
        Step::Handshake,
        Step::Hello,
        Step::Send(1),
        Step::Send(2),
        Step::Batch(2),
        Step::Reply(1),
        Step::Reply(2),
        Step::Recv,
        Step::Recv,
    ]);
    assert!(summary.established);
    assert_eq!(summary.messages, 2);
    assert_eq!(summary.reads, 3);

    for chunk in [1u8, 7] {
        let summary = run_logged(&[
            Step::Chunk(chunk),
            Step::Handshake,
            Step::Batch(3),
            Step::Dropped,
            Step::Junk(vec![1]),
            Step::Hello,
            Step::Send(1),
        ]);
        assert!(summary.established, "chunk {chunk}");
    }
}

// Tests frames cut short and unterminated ones in front of the client. A
// truncated ArkHello or reply is stale to a handshake and drops a
// session, whether its prefix still decodes or not. A partial ArkHello
// swallows the frame after it into junk, a lone delimiter completing it
// into the valid ArkHello it is instead.
#[test]
fn test_scripted_interrupted_frames() {
    for cut in [0u8, 1, 7, 255] {
        let summary = run_logged(&[
            Step::Handshake,
            Step::Hello,
            Step::Handshake,
            Step::Truncated(cut),
            Step::Hello,
        ]);
        assert!(summary.established, "cut {cut}");
        assert_eq!(summary.handshakes, 2, "cut {cut}");
        assert_eq!(summary.failures, 0, "cut {cut}");

        let summary = run_logged(&[
            Step::Handshake,
            Step::Hello,
            Step::Send(1),
            Step::Reply(1),
            Step::Recv,
            Step::Truncated(cut),
            Step::Recv,
            Step::Send(2),
        ]);
        assert!(!summary.established, "cut {cut}");
        assert_eq!(summary.messages, 1, "cut {cut}");
        assert_eq!(summary.failures, 1, "cut {cut}");
    }

    let summary = run_logged(&[Step::Handshake, Step::Partial, Step::Dropped]);
    assert!(summary.established);
    assert_eq!(summary.reads, 2);

    let summary = run_logged(&[
        Step::Handshake,
        Step::Partial,
        Step::Junk(vec![1]),
        Step::Hello,
    ]);
    assert!(summary.established);
    assert_eq!(summary.failures, 0);

    let summary = run_logged(&[
        Step::Handshake,
        Step::Partial,
        Step::Partial,
        Step::Dropped,
        Step::Hello,
    ]);
    assert!(summary.established);
    assert_eq!(summary.failures, 0);

    let summary = run_logged(&[
        Step::Handshake,
        Step::Hello,
        Step::Send(1),
        Step::Partial,
        Step::Reply(1),
        Step::Recv,
        Step::Send(2),
    ]);
    assert!(!summary.established);
    assert_eq!(summary.failures, 1);

    let summary = run_logged(&[
        Step::Handshake,
        Step::Hello,
        Step::Partial,
        Step::Dropped,
        Step::Recv,
    ]);
    assert!(!summary.established);
    assert_eq!(summary.failures, 1);

    for chunk in [1u8, 7] {
        let summary = run_logged(&[
            Step::Chunk(chunk),
            Step::Handshake,
            Step::Partial,
            Step::Dropped,
        ]);
        assert!(summary.established, "chunk {chunk}");
    }
}

// Tests that a read interrupted by a signal is retried by the framing, in
// a handshake and in a session alike, the client none the wiser.
#[test]
fn test_scripted_interrupted_reads() {
    let summary = run_logged(&[
        Step::Handshake,
        Step::Interrupt,
        Step::Hello,
        Step::Send(1),
        Step::Recv,
        Step::Interrupt,
        Step::Reply(1),
    ]);
    assert!(summary.established);
    assert_eq!(summary.messages, 1);
    assert_eq!(summary.failures, 0);
}

// Tests that frames past the size limit vanish in the framing, in a
// handshake and in a session alike, a partial ArkHello in front of one
// vanishing with it.
#[test]
fn test_scripted_oversized_frames() {
    let summary = run_logged(&[
        Step::Handshake,
        Step::Oversized,
        Step::Hello,
        Step::Send(1),
        Step::Oversized,
        Step::Reply(1),
        Step::Recv,
    ]);
    assert!(summary.established);
    assert_eq!(summary.messages, 1);
    assert_eq!(summary.failures, 0);

    let summary = run_logged(&[Step::Handshake, Step::Partial, Step::Oversized, Step::Hello]);
    assert!(summary.established);
}

// Tests that server frames, yields and interrupts outside a read queue up or
// vanish, and that replies before a session are junk, as is truncating
// with no valid frame yet.
#[test]
fn test_scripted_noops() {
    let summary = run_logged(&[
        Step::Yield,
        Step::Interrupt,
        Step::ReplyReplay,
        Step::Truncated(3),
        Step::Reply(1),
        Step::Hello,
        Step::Handshake,
        Step::Hello,
    ]);
    assert!(summary.established);
    assert_eq!(summary.handshakes, 1);
}
