// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Client scenario tests driven by mock server scripts.

use super::*;
use crate::testing;

/// Runs a script with logging enabled.
fn run_logged(steps: &[Step]) -> Summary {
    testing::init_tracing();
    run(steps)
}

/// Tests a handshake followed by request and reply exchanges, including
/// requests sent before their replies are read.
#[test]
fn test_scripted_round_trip() {
    let summary = run_logged(&[
        // Establish a session and exchange one request and reply
        Step::Handshake,
        Step::Hello,
        Step::Send(1),
        Step::Reply(1),
        Step::Recv,
        // Send two requests before reading either reply
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

/// Tests that a failed send ends receiving, even with a valid reply already
/// queued.
#[test]
fn test_scripted_send_failure_ends_receiving() {
    let summary = run_logged(&[
        // Queue a valid reply in a fresh session
        Step::Handshake,
        Step::Hello,
        Step::Reply(1),
        // Fail a send, which ends receiving that reply
        Step::Break,
        Step::Send(2),
        Step::Recv,
        // Healing the writer does not revive the session
        Step::Heal,
        Step::Send(3),
        // Reconnecting creates a session that sends and receives again
        Step::Handshake,
        Step::Hello,
        Step::Send(4),
        Step::Reply(4),
        Step::Recv,
    ]);
    assert!(summary.established);
    assert_eq!(summary.handshakes, 2);
    assert_eq!(summary.messages, 1);
    assert_eq!(summary.failures, 1);

    // With no reply waiting, EOF ends the receive side after a failed send
    let summary = run_logged(&[
        Step::Handshake,
        Step::Hello,
        Step::Break,
        Step::Send(1),
        Step::Recv,
    ]);
    assert!(!summary.established);
    assert_eq!(summary.failures, 1);
}

/// Tests that an oversized send keeps both encryption sequences, while a
/// corrupt reply ends both directions until a new handshake.
#[test]
fn test_scripted_send_refusal_and_receive_failure() {
    let summary = run_logged(&[
        // Refuse an oversized send without a session, then within one
        Step::SendOversized,
        Step::Handshake,
        Step::Hello,
        Step::SendOversized,
        // Both directions still work after the refusal
        Step::Send(1),
        Step::Reply(1),
        Step::Recv,
        // A corrupt reply ends receiving and sending
        Step::ReplyTampered,
        Step::Recv,
        Step::Send(2),
        // A new handshake restores both directions
        Step::Handshake,
        Step::Hello,
        Step::Send(3),
        Step::Reply(3),
        Step::Recv,
    ]);
    assert!(summary.established);
    assert_eq!(summary.handshakes, 2);
    assert_eq!(summary.messages, 2);
    assert_eq!(summary.failures, 1);
}

/// Tests that a retained sender works only in its own session and cannot
/// damage a later one.
#[test]
fn test_scripted_retained_sender() {
    let summary = run_logged(&[
        // Retaining the absent sender before any session is safe
        Step::Retain,
        Step::SendRetained(0),
        // A sender retained in a session sends in it
        Step::Handshake,
        Step::Hello,
        Step::Retain,
        Step::SendRetained(1),
        // After a reconnect it is refused, and the new session still works
        Step::Handshake,
        Step::Hello,
        Step::SendRetained(2),
        Step::Send(3),
        Step::Reply(3),
        Step::Recv,
        // Retaining the new sender makes the slot usable again
        Step::Retain,
        Step::SendRetained(4),
        Step::Reply(4),
        Step::Recv,
    ]);
    assert!(summary.established);
    assert_eq!(summary.handshakes, 2);
    assert_eq!(summary.messages, 2);
    assert_eq!(summary.failures, 0);
}

/// Tests that a failed reconnect and a failed retained send each retire the
/// old handle for good.
#[test]
fn test_scripted_retained_sender_failures() {
    let summary = run_logged(&[
        // Retain a sender, then fail a reconnect, which retires it
        Step::Handshake,
        Step::Hello,
        Step::Retain,
        Step::Handshake,
        Step::HelloTampered,
        Step::SendRetained(1),
        // It stays refused in the next session, which still sends
        Step::Handshake,
        Step::Hello,
        Step::SendRetained(2),
        Step::Send(3),
        // Retain the new sender and fail a send through it, retiring it too
        Step::Retain,
        Step::Break,
        Step::SendRetained(4),
        Step::Heal,
        Step::SendRetained(5),
        // Another session cannot revive it, and its refusal leaves the new
        // sender working
        Step::Handshake,
        Step::Hello,
        Step::SendRetained(6),
        Step::Send(7),
        Step::Reply(7),
        Step::Recv,
    ]);
    assert!(summary.established);
    assert_eq!(summary.handshakes, 3);
    assert_eq!(summary.messages, 1);
    assert_eq!(summary.failures, 1);
}

/// Tests that each flawed ArkHello fails the handshake with its own error and
/// leaves the client without a session.
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
        // A flawed reply to the client's own hello fails its handshake
        let summary = run_logged(&[Step::Handshake, flaw.clone(), Step::Send(1)]);
        assert!(!summary.established, "{flaw:?}");
        assert_eq!(summary.failures, 1, "{flaw:?}");

        // Without a HostHello to answer, the mock sends junk instead
        let summary = run_logged(&[flaw.clone(), Step::Recv]);
        assert!(!summary.established, "{flaw:?}");
        assert_eq!(summary.failures, 1, "{flaw:?}");
    }
}

/// Tests that a handshake drains every frame not meant for it until its own
/// ArkHello arrives.
#[test]
fn test_scripted_stale_skipping() {
    let summary = run_logged(&[
        // Leave a signal and junk from before the handshake
        Step::Dropped,
        Step::Junk(vec![1, 2, 3]),
        // Mix a stale hello, a signal and an empty packet into the handshake
        Step::Handshake,
        Step::HelloStale,
        Step::Dropped,
        Step::Junk(vec![]),
        Step::Hello,
    ]);
    assert!(summary.established);
    assert_eq!(summary.failures, 0);

    // Reconnect drains replies left unread from the previous session
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

    // Reconnect also drains ArkHellos left from an earlier handshake
    let summary = run_logged(&[
        Step::Handshake,
        Step::Hello,
        Step::Hello,
        Step::Handshake,
        Step::Hello,
    ]);
    assert_eq!(summary.handshakes, 2);
    assert!(summary.established);

    // Backlogs drain fully, up to the longest a script can queue
    for stale in [40, MAX_STEPS - 2] {
        let mut steps = vec![Step::Handshake];
        steps.extend(std::iter::repeat_n(Step::Dropped, stale));
        steps.push(Step::Hello);
        let summary = run_logged(&steps);
        assert!(summary.established);
        assert_eq!(summary.failures, 0);
    }

    // An undecodable frame left by an interrupted transfer is also drained
    let summary = run_logged(&[Step::Handshake, Step::Undecodable, Step::Hello]);
    assert!(summary.established);
    assert_eq!(summary.failures, 0);
}

/// Tests that a read error and EOF each abort the handshake with their own error.
#[test]
fn test_scripted_handshake_interrupted() {
    // A failed read aborts the handshake
    let summary = run_logged(&[Step::Handshake, Step::Yield, Step::Send(1)]);
    assert!(!summary.established);
    assert_eq!(summary.failures, 1);

    // So does the end of the script's input
    let summary = run_logged(&[Step::Handshake]);
    assert!(!summary.established);
    assert_eq!(summary.failures, 1);
}

/// Tests that the client delivers decrypted bytes without checking them as
/// protobuf, keeping the session for the next reply.
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
    assert_eq!(summary.messages, 2);
    assert_eq!(summary.failures, 0);
}

/// Tests that input a session cannot decode or decrypt ends the session.
#[test]
fn test_scripted_undecryptable_drops_session() {
    // A replayed reply ends the session
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

    // So does a reply from the previous session
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

    // So does a tampered reply
    let summary = run_logged(&[
        Step::Handshake,
        Step::Hello,
        Step::ReplyTampered,
        Step::Recv,
    ]);
    assert!(!summary.established);

    // So does junk
    let summary = run_logged(&[
        Step::Handshake,
        Step::Hello,
        Step::Junk(vec![7]),
        Step::Recv,
    ]);
    assert!(!summary.established);

    // So does an unexpected ArkHello
    let summary = run_logged(&[Step::Handshake, Step::Hello, Step::Hello, Step::Recv]);
    assert!(!summary.established);

    // So does a frame failing COBS decoding
    let summary = run_logged(&[Step::Handshake, Step::Hello, Step::Undecodable, Step::Recv]);
    assert!(!summary.established);
}

/// Tests that reading the server's empty frame reports a session reset and ends
/// the session.
#[test]
fn test_scripted_dropped_signal() {
    // A read signal ends the session until a new handshake
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

    // Sending still works until the signal is read
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

    // Without a receive context, signals stay queued for the next handshake
    let summary = run_logged(&[Step::Dropped, Step::Recv]);
    assert_eq!(summary.resets, 0);
    assert_eq!(summary.failures, 1);
    assert_eq!(summary.reads, 0);

    // Once one signal ends the session, receiving fails before reading the next
    let summary = run_logged(&[
        Step::Handshake,
        Step::Hello,
        Step::Dropped,
        Step::Dropped,
        Step::Recv,
        Step::Recv,
    ]);
    assert!(!summary.established);
    assert_eq!(summary.resets, 1);
    assert_eq!(summary.failures, 1);
}

/// Tests that receiving without a receive context fails before reading,
/// whatever input is queued.
#[test]
fn test_scripted_recv_without_session() {
    // Receiving fails before reading junk
    let summary = run_logged(&[Step::Junk(vec![1]), Step::Recv]);
    assert_eq!(summary.failures, 1);
    assert_eq!(summary.reads, 0);

    // It fails before reading an undecodable frame too
    let summary = run_logged(&[Step::Undecodable, Step::Recv]);
    assert_eq!(summary.failures, 1);
    assert_eq!(summary.reads, 0);

    // It fails without any input too
    let summary = run_logged(&[Step::Recv]);
    assert_eq!(summary.failures, 1);
    assert_eq!(summary.reads, 0);

    // A send refused without a session does not count as a failure
    let summary = run_logged(&[Step::Send(1)]);
    assert_eq!(summary.failures, 0);

    // A failed receive releases its context. Further receives leave queued
    // input for reconnect to drain before accepting fresh session traffic.
    let summary = run_logged(&[
        Step::Handshake,
        Step::Hello,
        Step::Undecodable,
        Step::Recv,
        Step::Junk(vec![1]),
        Step::Recv,
        Step::Handshake,
        Step::Hello,
        Step::Reply(1),
        Step::Recv,
    ]);
    assert!(summary.established);
    assert_eq!(summary.failures, 2);
    assert_eq!(summary.handshakes, 2);
    assert_eq!(summary.messages, 1);
}

/// Tests that a read error or EOF ends an established session and refuses later
/// sends through its sender.
#[test]
fn test_scripted_read_failure_drops_session() {
    // A read failing before the next call ends the session
    let summary = run_logged(&[Step::Handshake, Step::Hello, Step::Recv, Step::Send(1)]);
    assert!(!summary.established);
    assert_eq!(summary.failures, 1);

    // So does the end of the script's input
    let summary = run_logged(&[Step::Handshake, Step::Hello, Step::Recv]);
    assert!(!summary.established);
    assert_eq!(summary.failures, 1);
}

/// Tests that persistent write failures fail a send, a reset and a HostAck,
/// until healed writes and a new handshake restore the session.
#[test]
fn test_scripted_broken_transport() {
    let summary = run_logged(&[
        // Break writes in a session, failing a send and a reconnect's reset
        Step::Handshake,
        Step::Hello,
        Step::Break,
        Step::Send(1),
        Step::Send(2),
        Step::Handshake,
        // Heal them and reconnect
        Step::Heal,
        Step::Handshake,
        Step::Hello,
        Step::Send(3),
    ]);
    assert!(summary.established);
    assert_eq!(summary.handshakes, 2);
    assert_eq!(summary.failures, 1);

    // Writes breaking during a handshake fail its HostAck
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

/// Tests that a cut in a request, reset, HostHello or HostAck fails the call,
/// and the next handshake's reset lets the stream recover.
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

        // A cut request fails its send, and a reconnect recovers
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

        // A cut reset or HostHello fails the handshake, and a retry recovers
        let summary = run_logged(&[cut.clone(), Step::Handshake, Step::Handshake, Step::Hello]);
        assert!(summary.established, "{point:?}");
        assert_eq!(summary.handshakes, 1, "{point:?}");
        assert_eq!(summary.failures, 1, "{point:?}");

        // A cut HostAck fails the handshake, and a retry recovers
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

    // A partial frame survives further write failures until a successful reset
    // can terminate it
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

/// Tests that consecutive failed handshakes, by cut or timeout, still allow a
/// successful exchange afterwards.
///
/// Each reset must retire the previous truncated hello before another output
/// failure leaves its own tail. The points include a failed reset that leaves
/// the earlier fragment untouched, and one that only terminates it.
#[test]
fn test_scripted_consecutive_handshake_failures() {
    for timeout in [false, true] {
        for point in [
            CutPoint::Middle(5),
            CutPoint::Start,
            CutPoint::Middle(0),
            CutPoint::Middle(u16::MAX),
            CutPoint::Delimiter,
            CutPoint::Flush,
        ] {
            // Fault the output with a cut or a timeout, as the outer loop picks
            let fault = |point| {
                if timeout {
                    Step::Timeout(point)
                } else {
                    Step::Cut {
                        point,
                        then_broken: false,
                    }
                }
            };

            let summary = run_logged(&[
                // Leave a truncated hello from a first failed handshake
                fault(CutPoint::Middle(5)),
                Step::Handshake,
                // Fail a second handshake at the point under test
                fault(point),
                Step::Handshake,
                // A third handshake recovers and exchanges a message
                Step::Handshake,
                Step::Hello,
                Step::Send(1),
                Step::Reply(1),
                Step::Recv,
            ]);
            assert!(summary.established, "{point:?}, timeout: {timeout}");
            assert_eq!(summary.handshakes, 1, "{point:?}, timeout: {timeout}");
            assert_eq!(summary.messages, 1, "{point:?}, timeout: {timeout}");
            assert_eq!(summary.failures, 2, "{point:?}, timeout: {timeout}");
        }
    }
}

/// Tests frame assembly across reads as small as one byte.
#[test]
fn test_scripted_chunked_reads() {
    for chunk in [1u8, 7, 254, 255] {
        let summary = run_logged(&[
            // Limit reads to the chunk, then exchange a message
            Step::Chunk(chunk),
            Step::Handshake,
            Step::Hello,
            Step::Send(1),
            Step::Reply(1),
            Step::Recv,
            // A long junk frame ends the session, and a reconnect recovers
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

/// Tests that several frames can arrive in one read, each batch ending at the
/// frame that settles its call.
#[test]
fn test_scripted_batched_reads() {
    // A signal, junk and the hello arrive in one read
    let summary = run_logged(&[
        Step::Handshake,
        Step::Batch(3),
        Step::Dropped,
        Step::Junk(vec![1]),
        Step::Hello,
    ]);
    assert!(summary.established);
    assert_eq!(summary.reads, 1);

    // So do an undecodable frame and the hello
    let summary = run_logged(&[
        Step::Handshake,
        Step::Batch(2),
        Step::Undecodable,
        Step::Hello,
    ]);
    assert!(summary.established);
    assert_eq!(summary.reads, 1);

    // A batch of two replies stops after the first, which settles its receive
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

    // Batches still form under small chunks
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

/// Tests truncated and unterminated input, in a handshake and in a session.
#[test]
fn test_scripted_interrupted_frames() {
    for cut in [0u8, 1, 7, 255] {
        // A handshake drains a truncated frame
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

        // A truncated frame ends a session
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

    // A lone delimiter completes a partial ArkHello
    let summary = run_logged(&[Step::Handshake, Step::Partial, Step::Dropped]);
    assert!(summary.established);
    assert_eq!(summary.reads, 2);

    // Other bytes merge into it, and the handshake drains the result
    let summary = run_logged(&[
        Step::Handshake,
        Step::Partial,
        Step::Junk(vec![1]),
        Step::Hello,
    ]);
    assert!(summary.established);
    assert_eq!(summary.failures, 0);

    // So does a second partial hello
    let summary = run_logged(&[
        Step::Handshake,
        Step::Partial,
        Step::Partial,
        Step::Dropped,
        Step::Hello,
    ]);
    assert!(summary.established);
    assert_eq!(summary.failures, 0);

    // In a session, a partial frame merged into a reply ends it
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

    // So does a partial ArkHello the delimiter completes
    let summary = run_logged(&[
        Step::Handshake,
        Step::Hello,
        Step::Partial,
        Step::Dropped,
        Step::Recv,
    ]);
    assert!(!summary.established);
    assert_eq!(summary.failures, 1);

    // Small chunks do not change how a delimiter completes the hello
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

/// Tests that the model completes a pending ArkHello with the empty packet only
/// when the hello's encoding ends in a full run.
#[test]
fn test_partial_hello_empty_packet_model() {
    // Encoding 254 nonzero bytes ends in a full run, encoding 253 does not
    for (len, completes) in [(254, true), (253, false)] {
        // Leave a pending hello of that length in an idle model
        let clock = crate::transport::testing::test_clock().clock();
        let mut server = Server::new(&[], Outbox::new(&clock), Recorder::default());
        let pending = frame(&vec![0x11; len]);
        server.partial = Partial::Hello(7, pending[..pending.len() - 1].to_vec());

        // Deliver the empty packet and check the predicted frame
        server.execute(Step::Junk(vec![]));
        let (bytes, frame) = server.queue.pop_back().unwrap();
        assert_eq!(bytes, [0x01, 0x00], "len {len}");
        assert_eq!(
            matches!(
                frame,
                Some(Frame::ArkHello {
                    generation: 7,
                    flaw: Flaw::None
                })
            ),
            completes,
            "len {len}"
        );
    }
}

/// Tests that interrupted reads are retried during a handshake or a receive
/// without ending the call or changing its result.
#[test]
fn test_scripted_interrupted_reads() {
    let summary = run_logged(&[
        // Interrupt a read during the handshake
        Step::Handshake,
        Step::Interrupt,
        Step::Hello,
        // Interrupt a read during a receive
        Step::Send(1),
        Step::Recv,
        Step::Interrupt,
        Step::Reply(1),
    ]);
    assert!(summary.established);
    assert_eq!(summary.messages, 1);
    assert_eq!(summary.failures, 0);
}

/// Tests that early read timeouts are retried in a handshake and a receive
/// without disturbing the session or a retained sender.
#[test]
fn test_scripted_read_timeouts() {
    let summary = run_logged(&[
        // A timeout during the handshake is retried
        Step::Handshake,
        Step::ReadTimeout,
        Step::Hello,
        // Retain the new sender and send through it
        Step::Retain,
        Step::SendRetained(1),
        // Timeouts during a receive are retried until the reply arrives
        Step::Recv,
        Step::ReadTimeout,
        Step::ReadTimeout,
        Step::Reply(1),
        // The retained sender still works
        Step::SendRetained(2),
    ]);
    assert!(summary.established);
    assert_eq!(summary.handshakes, 1);
    assert_eq!(summary.messages, 1);
    assert_eq!(summary.failures, 0);
}

/// Tests that a timed-out reset or HostHello fails the handshake, and a retry
/// succeeds on the same stream.
#[test]
fn test_scripted_handshake_timeouts() {
    for point in [
        CutPoint::Start,
        CutPoint::Middle(7),
        CutPoint::Delimiter,
        CutPoint::Flush,
    ] {
        let summary = run_logged(&[
            // Time out the reset or HostHello of a first handshake
            Step::Timeout(point),
            Step::Handshake,
            // A retry on the same stream exchanges a message
            Step::Handshake,
            Step::Hello,
            Step::Send(1),
            Step::Recv,
            Step::Reply(1),
        ]);
        assert!(summary.established, "{point:?}");
        assert_eq!(summary.handshakes, 1, "{point:?}");
        assert_eq!(summary.messages, 1, "{point:?}");
        assert_eq!(summary.failures, 1, "{point:?}");
    }
}

/// Tests that a send timeout ends its session and retires retained senders,
/// while a reconnect supplies a working one.
#[test]
fn test_scripted_send_timeouts() {
    for point in [
        CutPoint::Start,
        CutPoint::Middle(7),
        CutPoint::Delimiter,
        CutPoint::Flush,
    ] {
        let summary = run_logged(&[
            // Retain the sender, then time out a send, which ends the session
            Step::Handshake,
            Step::Hello,
            Step::Retain,
            Step::Timeout(point),
            Step::Send(1),
            // The retained sender stays refused, even after a reconnect
            // terminates any interrupted frame
            Step::SendRetained(2),
            Step::Handshake,
            Step::Hello,
            Step::SendRetained(3),
            // The new session sends and receives
            Step::Send(4),
            Step::Recv,
            Step::Reply(4),
        ]);
        assert!(summary.established, "{point:?}");
        assert_eq!(summary.handshakes, 2, "{point:?}");
        assert_eq!(summary.messages, 1, "{point:?}");
        assert_eq!(summary.failures, 0, "{point:?}");
    }
}

/// Tests that a handshake drains an oversized frame, while a session ends on
/// one along with its senders.
#[test]
fn test_scripted_oversized_frames() {
    let summary = run_logged(&[
        // A handshake drains an oversized frame
        Step::Handshake,
        Step::Oversized,
        Step::Hello,
        // In a session, one ends it before a queued reply is read
        Step::Retain,
        Step::Send(1),
        Step::Oversized,
        Step::Reply(1),
        Step::Recv,
        // The retained sender is refused, and receiving fails before reading
        Step::SendRetained(2),
        Step::Recv,
        // Only a new handshake supplies a working sender
        Step::Handshake,
        Step::Hello,
        Step::SendRetained(3),
        Step::Send(4),
        Step::Reply(4),
        Step::Recv,
    ]);
    assert!(summary.established);
    assert_eq!(summary.handshakes, 2);
    assert_eq!(summary.messages, 1);
    assert_eq!(summary.failures, 2);
}

/// Tests that oversized input after a partial hello is discarded through its
/// delimiter, with batched and chunked reads.
#[test]
fn test_scripted_oversized_fragments() {
    for chunk in [0, 255] {
        let summary = run_logged(&[
            // A handshake discards a partial hello grown oversized
            Step::Chunk(chunk),
            Step::Handshake,
            Step::Batch(3),
            Step::Partial,
            Step::Oversized,
            Step::Hello,
            // In a session, the same input ends it
            Step::Retain,
            Step::Partial,
            Step::Oversized,
            Step::Recv,
            // Later sends and receives fail at once
            Step::SendRetained(1),
            Step::Recv,
            // A reconnect drains the rest and a queued signal, and only its
            // sender works
            Step::Dropped,
            Step::Handshake,
            Step::Hello,
            Step::SendRetained(2),
            Step::Send(3),
            Step::Reply(3),
            Step::Recv,
        ]);
        assert!(summary.established, "chunk {chunk}");
        assert_eq!(summary.handshakes, 2, "chunk {chunk}");
        assert_eq!(summary.failures, 2, "chunk {chunk}");
        assert_eq!(summary.resets, 0, "chunk {chunk}");
        assert_eq!(summary.messages, 1, "chunk {chunk}");
    }
}

/// Tests that a handshake drains an oversized frame arriving one byte per read
/// after a partial hello.
///
/// The driver and vector replay must step through these reads without copying
/// the unread frame on every byte.
#[test]
fn test_scripted_bytewise_oversized_frame() {
    let summary = run_logged(&[
        Step::Chunk(1),
        Step::Handshake,
        Step::Batch(3),
        Step::Partial,
        Step::Oversized,
        Step::Hello,
    ]);
    assert!(summary.established);
    assert_eq!(summary.handshakes, 1);
    assert_eq!(summary.failures, 0);
    assert!(summary.reads > MAX_FRAME_SIZE);
}

/// Tests that a handshake drains an oversized stale frame and a long backlog
/// after it before its own ArkHello.
#[test]
fn test_scripted_oversized_stale_frames() {
    for stale in [40, MAX_STEPS - 4] {
        // Batch the oversized frame and the backlog ahead of the hello
        let mut steps = vec![Step::Handshake, Step::Batch(255), Step::Oversized];
        steps.extend(std::iter::repeat_n(Step::Dropped, stale));
        steps.push(Step::Hello);
        let summary = run_logged(&steps);
        assert!(summary.established, "stale {stale}");
        assert_eq!(summary.handshakes, 1, "stale {stale}");
        assert_eq!(summary.failures, 0, "stale {stale}");
    }
}

/// Tests that steps before the first client call either do nothing or queue
/// junk a later handshake drains.
#[test]
fn test_scripted_noops() {
    let summary = run_logged(&[
        // Read faults and unavailable replays or truncations do nothing
        Step::Yield,
        Step::Interrupt,
        Step::ReplyReplay,
        Step::Truncated(3),
        // Responses without a session or HostHello become junk
        Step::Reply(1),
        Step::Hello,
        // A handshake drains that junk
        Step::Handshake,
        Step::Hello,
    ]);
    assert!(summary.established);
    assert_eq!(summary.handshakes, 1);
}

/// Tests that a reset failing on broken writes leaves a middle cut armed for
/// the next HostHello.
///
/// A middle cut needs at least three bytes, so the model must not spend it on
/// the two-byte reset.
#[test]
fn test_scripted_cut_survives_broken_handshake() {
    let summary = run_logged(&[
        // Break writes with a middle cut armed, failing the reset
        Step::Cut {
            point: CutPoint::Middle(100),
            then_broken: true,
        },
        Step::Handshake,
        // Once healed, the cut fails the next HostHello
        Step::Heal,
        Step::Handshake,
    ]);
    assert_eq!(summary.handshakes, 0);
    assert_eq!(summary.failures, 2);
}
