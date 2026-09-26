// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Tests that the transport and the protocol take their time from the clock of
//! the stream they run on.

use super::framing::{FrameReader, FrameWriter};
use super::{
    Attestation, CRYPTO_DOMAIN_WIRE, CRYPTO_DOMAIN_WIRE_ARK_TO_HOST,
    CRYPTO_DOMAIN_WIRE_HOST_TO_ARK, Client, Error, Event, Read, Roots, Server, Stream, Verifier,
    Write, handshake,
};
use crate::{memory, protocol};
use darkbio_clock::TestClock;
use darkbio_crypto::cwt::claims::{self, eat};
use darkbio_crypto::{cbor, cose, cwt, xdsa, xhpke};
use std::io::{self, Read as _, Write as _};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Issues an emulator attestation for `signer` that is valid only within a
/// second of `wall`, so a check at any other time rejects it.
fn attestation(signer: &xdsa::SecretKey, wall: SystemTime) -> Attestation {
    // Claim the signer's key for one second either side of the given time
    let now = wall.duration_since(UNIX_EPOCH).unwrap().as_secs();
    let claims = darkbio_trust::device::EmulatorClaims {
        sub: claims::Subject {
            sub: "clock-test".into(),
        },
        cnf: claims::Confirm::new(signer.public_key()),
        nbf: claims::NotBefore { nbf: now - 1 },
        exp: claims::Expiration { exp: now + 1 },
        iat: claims::IssuedAt { iat: now },
        oem: eat::Oemid::new_pen(0),
        hwm: eat::HwModel { hw_model: vec![] },
        hwv: eat::HwVersion::new("".into()),
    };

    // Sign the claims at that same time
    Attestation::new(
        cwt::issue_at(
            &claims,
            signer,
            darkbio_trust::CRYPTO_DOMAIN_DEVICE_ATTESTATION,
            now as i64,
        )
        .unwrap(),
    )
    .unwrap()
}

/// Checks that a stream refuses a reader and a writer on different clocks.
#[test]
#[should_panic(expected = "stream halves must use the same clock")]
fn test_stream_rejects_different_clocks() {
    // Take the reader and the writer from connections on separate clocks
    let first = TestClock::new();
    let second = TestClock::new();
    let (first, _first_peer) = memory::duplex(4, &first.clock());
    let (second, _second_peer) = memory::duplex(4, &second.clock());
    let (reader, _) = first.into_halves();
    let (_, writer) = second.into_halves();

    // Pair them into one stream
    let _ = Stream::new(reader, writer, || {});
}

/// Checks that memory halves report their clock through boxed and borrowed
/// adapters, and that the stream and the halves measure deadlines on it.
#[test]
fn test_memory_and_adapter_wrappers_keep_the_clock() {
    // Run a day ahead of real time, so a deadline checked in real time never
    // expires, and require both memory ends and their halves to report the clock
    let mut tester = TestClock::new();
    tester.advance(Duration::from_secs(86400));
    let clock = tester.clock();
    let (host, ark) = memory::duplex(64, &clock);
    assert_eq!(host.clock(), clock);
    assert_eq!(ark.clock(), clock);
    let (host_read, host_write) = host.into_halves();
    let (mut ark_read, mut ark_write) = ark.into_halves();
    assert_eq!(host_read.clock(), clock);
    assert_eq!(host_write.clock(), clock);
    assert_eq!(ark_read.clock(), clock);
    assert_eq!(ark_write.clock(), clock);

    // Borrow boxed halves into a stream, which must still report the clock
    let mut reader: Box<dyn Read> = Box::new(host_read);
    let mut writer: Box<dyn Write> = Box::new(host_write);
    let stream = Stream::new(&mut reader, &mut writer, || {});
    assert_eq!(stream.clock(), clock);

    // Send a frame within a deadline two seconds ahead
    let (reader, writer, closer, _) = stream.into_parts();
    let mut reader = FrameReader::new(reader, closer.clone());
    let mut writer = FrameWriter::new(writer, closer);
    let deadline = clock.now() + Duration::from_secs(2);
    writer.send_packet(b"out", deadline).unwrap();
    let mut frame = [0; 5];
    ark_read.read_exact(&mut frame).unwrap();
    assert_eq!(&frame, b"\x04out\0");

    // Receive two frames in one read, leaving the second in the frame buffer
    ark_write.write_all(b"\x03in\0\x03on\0").unwrap();
    assert_eq!(
        reader.next_packet(Some(deadline)).unwrap(),
        Some(&b"in"[..])
    );

    // Refuse framed I/O once the clock reaches that deadline, even with a frame
    // buffered
    tester.advance(Duration::from_secs(2));
    assert!(matches!(
        reader.next_packet(Some(deadline)),
        Err(Error::RecvFailed(err)) if err.kind() == io::ErrorKind::TimedOut
    ));
    assert_eq!(reader.next_packet(None).unwrap(), Some(&b"on"[..]));
    assert!(matches!(
        writer.send_packet(b"late", deadline),
        Err(Error::SendFailed(err)) if err.kind() == io::ErrorKind::TimedOut
    ));

    // Refuse raw writes and flushes past it without waiting for buffer space
    ark_write.set_write_deadline(deadline).unwrap();
    assert_eq!(
        ark_write.write(b"late").unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(
        ark_write.flush().unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );

    // Refuse a raw read past it on an empty pipe instead of waiting for input
    ark_read.forbid_waits();
    ark_read.set_read_deadline(Some(deadline)).unwrap();
    assert_eq!(
        ark_read.read(&mut frame).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
}

/// Checks that a framed read blocked in its adapter expires through the stream
/// reader's clock check.
#[test]
fn test_blocked_framed_read_expires_on_stream_clock() {
    // Park an empty framed read a day ahead of real time
    let mut tester = crate::transport::testing::test_clock();
    let clock = tester.clock();
    let (host, _peer) = memory::duplex(64, &clock);
    let (reader, _writer, closer, _) = host.into_parts();
    let mut reader = FrameReader::new(reader, closer);
    let deadline = clock.now() + Duration::from_secs(5);
    let reading = thread::spawn(move || reader.next_packet(Some(deadline)).map(|_| ()));
    tester.wait_blocked(1);
    assert_eq!(tester.next_deadline(), Some(deadline));

    // Pass expiry and require the reader to return instead of retrying adapter
    // timeouts
    tester.advance_to(deadline + Duration::from_nanos(1));
    assert!(matches!(
        reading.join().unwrap(),
        Err(Error::RecvFailed(error)) if error.kind() == io::ErrorKind::TimedOut
    ));
}

/// Checks that a client verifies the attestation and signs its ack at the wall
/// time of the stream's clock.
#[test]
fn test_client_handshake_uses_clock_wall_time() {
    /// Verifier requiring the exact wall time, then applying the roots policy.
    struct VerifierAt {
        /// Wall time the client must pass, with its fraction of a second.
        wall: SystemTime,
        /// Root that issued the attestation.
        root: xdsa::PublicKey,
    }

    impl Verifier for VerifierAt {
        type Info = darkbio_trust::device::Device;

        fn verify(
            &self,
            attestation: &Attestation,
            now: SystemTime,
        ) -> Result<(xdsa::PublicKey, Self::Info), String> {
            // Require the exact wall time, before the roots round it to seconds
            assert_eq!(now, self.wall);

            // Verify through the roots, which reject the attestation at any
            // other second
            Roots {
                hardware: &[],
                emulator: std::slice::from_ref(&self.root),
            }
            .verify(attestation, now)
        }
    }

    // Run a day ahead of real time, with the wall time in 2009 and a fraction of
    // a second
    let mut tester = TestClock::new();
    tester.advance(Duration::from_secs(86400));
    let wall = UNIX_EPOCH + Duration::new(1_234_567_890, 123_456_789);
    tester.set_system_time(wall);
    let clock = tester.clock();
    let signer = xdsa::SecretKey::generate();
    let verifier = VerifierAt {
        wall,
        root: signer.public_key(),
    };
    let attest = attestation(&signer, wall);
    let (host, ark) = memory::duplex(64 * 1024, &clock);

    // Answer the client's hello as the Ark, keeping the keys that open its ack
    let peer = thread::spawn(move || {
        // Read the client's reset and ephemeral keys
        let (reader, writer, closer, _) = ark.into_parts();
        let mut reader = FrameReader::new(reader, closer.clone());
        let mut writer = FrameWriter::new(writer, closer);
        assert!(reader.next_packet(None).unwrap().is_none());
        assert!(reader.next_packet(None).unwrap().is_none());
        let hello: handshake::HostHello =
            cbor::decode(reader.next_packet(None).unwrap().unwrap()).unwrap();
        let crypto = xhpke::SecretKey::generate();
        let (_, encap) = hello
            .host_crypto
            .new_sender(CRYPTO_DOMAIN_WIRE_ARK_TO_HOST)
            .unwrap();

        // Present the attestation, long expired in real time
        let sealed = cose::seal_at(
            handshake::ArkHello {
                ark_attest: attest.into_bytes(),
                ark_crypto: crypto.public_key(),
                a2h_encap: encap.to_vec(),
            },
            handshake::ArkHelloAuth {
                host_signer: hello.host_signer.clone(),
                host_crypto: hello.host_crypto.clone(),
            },
            &signer,
            &hello.host_crypto,
            CRYPTO_DOMAIN_WIRE,
            1_234_567_890,
        )
        .unwrap();
        writer
            .send_packet(&sealed, clock.now() + Duration::from_secs(5))
            .unwrap();

        // Open the client's ack, which must be signed at exactly the wall second
        let ack = reader.next_packet(None).unwrap().unwrap();
        let _: handshake::HostAck = cose::open_at(
            ack,
            &handshake::HostAckAuth {
                ark_signer: signer.public_key(),
                ark_crypto: crypto.public_key(),
            },
            &crypto,
            &hello.host_signer,
            CRYPTO_DOMAIN_WIRE,
            Some(0),
            1_234_567_890,
        )
        .unwrap();
    });

    // Connect the client, then let the Ark side finish its check
    let mut client = Client::new(host);
    client.connect(&verifier).unwrap();
    peer.join().unwrap();
}

/// Checks that a server signs its hello at the wall time of the stream's clock,
/// and opens the client's ack without reading that time.
#[test]
fn test_server_handshake_uses_clock_wall_time() {
    // Run a day ahead of real time, with the wall time in 2012
    let mut tester = TestClock::new();
    tester.advance(Duration::from_secs(86400));
    let wall = UNIX_EPOCH + Duration::from_secs(1_345_678_901);
    tester.set_system_time(wall);
    let clock = tester.clock();
    let signer = xdsa::SecretKey::generate();
    let identity = signer.public_key();
    let attest = attestation(&signer, wall);
    let (host, ark) = memory::duplex(64 * 1024, &clock);

    // Serve one handshake on the Ark side
    let peer = thread::spawn(move || {
        let mut server = Server::new(ark, signer, attest);
        assert!(matches!(server.recv().unwrap(), Event::Connected(_)));
    });

    // Start a handshake with host keys the test holds
    let (reader, writer, closer, _) = host.into_parts();
    let mut reader = FrameReader::new(reader, closer.clone());
    let mut writer = FrameWriter::new(writer, closer);
    let host_signer = xdsa::SecretKey::generate();
    let host_crypto = xhpke::SecretKey::generate();
    let deadline = clock.now() + Duration::from_secs(5);
    writer.send_reset(deadline).unwrap();
    writer
        .send_packet(
            &cbor::encode(handshake::HostHello {
                host_signer: host_signer.public_key(),
                host_crypto: host_crypto.public_key(),
            })
            .unwrap(),
            deadline,
        )
        .unwrap();

    // Open the server's hello, which must be signed at exactly the wall second
    let hello: handshake::ArkHello = cose::open_at(
        reader.next_packet(None).unwrap().unwrap(),
        &handshake::ArkHelloAuth {
            host_signer: host_signer.public_key(),
            host_crypto: host_crypto.public_key(),
        },
        &host_crypto,
        &identity,
        CRYPTO_DOMAIN_WIRE,
        Some(0),
        1_345_678_901,
    )
    .unwrap();

    // Seal the ack that completes the handshake
    let (_, encap) = hello
        .ark_crypto
        .new_sender(CRYPTO_DOMAIN_WIRE_HOST_TO_ARK)
        .unwrap();
    let ack = cose::seal_at(
        handshake::HostAck {
            h2a_encap: encap.to_vec(),
        },
        handshake::HostAckAuth {
            ark_signer: identity,
            ark_crypto: hello.ark_crypto.clone(),
        },
        &host_signer,
        &hello.ark_crypto,
        CRYPTO_DOMAIN_WIRE,
        1_345_678_901,
    )
    .unwrap();

    // Deliver it at a wall time before 1970, which the server's unchecked open
    // must not read
    tester.set_system_time(UNIX_EPOCH - Duration::from_secs(1));
    writer.send_packet(&ack, deadline).unwrap();
    peer.join().unwrap();
}

/// Checks that sessions and their handles report the stream's clock, also after
/// the session is gone, and time out requests on it.
#[test]
fn test_protocol_handles_keep_the_stream_clock() {
    // Connect both protocol peers over a memory connection a day ahead of real time
    let mut tester = TestClock::new();
    tester.advance(Duration::from_secs(86400));
    let clock = tester.clock();
    let signer = xdsa::SecretKey::generate();
    let identity = signer.public_key();
    let attest = attestation(&signer, clock.system_time());
    let (host, ark) = memory::duplex(64 * 1024, &clock);
    let mut server = protocol::Server::new(ark, signer, attest);
    let (client, _) = protocol::connect(host, &identity).unwrap();
    let mut session = server.accept().unwrap();
    assert_eq!(client.clock(), clock);
    assert_eq!(session.clock(), clock);
    let requester = client.requester();
    assert_eq!(requester.clock(), clock);
    assert_eq!(session.requester().clock(), clock);

    // Fail at once a request whose deadline passed on the clock but not in real time
    for requester in [&requester, &session.requester()] {
        let mut expired = requester.request(vec![0], clock.now()).unwrap();
        let (notified, notification) = mpsc::channel();
        expired.notify(move || {
            let _ = notified.send(());
        });
        assert_eq!(notification.try_recv(), Ok(()));
        assert!(matches!(
            expired.wait::<Vec<u8>>(),
            Err(protocol::Error::Timeout)
        ));
    }

    // Exchange a request and a reply with deadlines taken from the handles' clock
    let deadline = requester.clock().now() + Duration::from_secs(30);
    let answer = requester.request(vec![1, 2, 3], deadline).unwrap();
    let (message, responder) = session.recv().unwrap();
    assert_eq!(responder.clock(), clock);
    let written = responder.reply(message, deadline).unwrap();
    assert_eq!(answer.wait::<Vec<u8>>().unwrap(), [1, 2, 3]);
    written.wait().unwrap();

    // Report the clock from handles that outlive their session
    let _pending = requester.request(vec![4], deadline).unwrap();
    let (_, responder) = session.recv().unwrap();
    drop(client);
    drop(session);
    drop(server);
    assert_eq!(requester.clock(), clock);
    assert_eq!(responder.clock(), clock);
}

/// Checks that server acceptance parks on the stream clock until a client
/// establishes a session.
#[test]
fn test_server_accept_waits_on_stream_clock() {
    // Start acceptance before the client has sent a handshake
    let tester = TestClock::new();
    let clock = tester.clock();
    let signer = xdsa::SecretKey::generate();
    let identity = signer.public_key();
    let attest = attestation(&signer, clock.system_time());
    let (host, ark) = memory::duplex(64 * 1024, &clock);
    let mut server = protocol::Server::new(ark, signer, attest);
    let accepting = thread::spawn(move || {
        let session = server.accept().unwrap();
        (server, session)
    });

    // Observe both the server reader and acceptance parked on this clock
    tester.wait_blocked(2);
    let (client, _) = protocol::connect(host, &identity).unwrap();
    let (server, session) = accepting.join().unwrap();

    // Close both owners after acceptance has returned
    drop(client);
    drop(session);
    drop(server);
}

/// Checks that the deadline worker settles a request on clock advance while
/// nobody waits on its promise.
#[test]
fn test_protocol_deadline_worker_notifies_without_promise_waiter() {
    // Establish both protocol peers a day ahead of real time
    let mut tester = TestClock::new();
    tester.advance(Duration::from_secs(86400));
    let clock = tester.clock();
    let signer = xdsa::SecretKey::generate();
    let identity = signer.public_key();
    let attest = attestation(&signer, clock.system_time());
    let (host, ark) = memory::duplex(64 * 1024, &clock);
    let mut server = protocol::Server::new(ark, signer, attest);
    let (client, _) = protocol::connect(host, &identity).unwrap();
    let mut session = server.accept().unwrap();

    // Leave one request pending, with all six protocol threads parked: a reader, a
    // writer and a deadline worker per side
    let later = clock.now() + Duration::from_secs(30);
    let first = client.requester().request(vec![1], later).unwrap();
    let (_, first_responder) = session.recv().unwrap();
    tester.wait_blocked(6);

    // Submit an earlier deadline, which the parked worker must recompute its
    // wait for
    let deadline = clock.now() + Duration::from_secs(5);
    let mut promise = client.requester().request(vec![2], deadline).unwrap();
    let (events, observed) = mpsc::channel();
    promise.notify(move || {
        let _ = events.send(());
    });
    let (_, responder) = session.recv().unwrap();
    tester.wait_blocked(6);
    assert!(observed.try_recv().is_err());

    // Observe worker notification before any call that could synchronously
    // expire work
    tester.advance_to(deadline);
    observed.recv().unwrap();
    assert!(matches!(
        promise.wait::<Vec<u8>>(),
        Err(protocol::Error::Timeout)
    ));

    // Keep the later request alive until its own deadline and observe worker
    // settlement
    let mut first = first;
    let (events, observed) = mpsc::channel();
    first.notify(move || {
        let _ = events.send(());
    });
    assert!(observed.try_recv().is_err());
    tester.advance_to(later);
    observed.recv().unwrap();
    assert!(matches!(
        first.wait::<Vec<u8>>(),
        Err(protocol::Error::Timeout)
    ));

    // Close the peers before abandoning unanswered responders
    client.close();
    server.close();
    drop((first_responder, responder));
}
