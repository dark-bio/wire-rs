// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Real transport scenarios using the transport runner's gated byte pipes.
//!
//! Scripts can run both protocol peers or inspect one peer through a raw transport.

use super::session::Job;
use crate::protocol::schema::{self, ArkToHost, HostToArk, ark_to_host, host_to_ark};
use crate::protocol::session::SessionInner;
use crate::protocol::worker::{self, Tracker};
use crate::protocol::{
    self, Closer, Error, Message, Promise, Requester, Responder, Server, Session,
};
use crate::transport::mock::{
    duplex::{Adapter, FaultKind, Operation, Pipe},
    self_attestation,
};
use crate::transport::{self, Attestation, Stream};
use darkbio_crypto::xdsa;
use prost::Message as _;
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Weak, mpsc};
use std::time::Duration;

/// Default protocol timeout for scenarios that do not specify one.
const BUDGET: Duration = Duration::from_secs(3);
/// Transport write timeout of both streams and handshake timeout of the raw
/// client, independent of protocol request deadlines.
const WRITE_BUDGET: Duration = Duration::from_millis(500);

/// Choice of the peers that run the protocol API.
///
/// The other peer, if any, sends raw envelopes through its transport.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(not(test), allow(dead_code))]
enum Mode {
    /// Both peers use the public protocol constructors.
    Both,
    /// A raw client drives the protocol server, including successive sessions.
    Server,
    /// A raw server drives the protocol client.
    Client,
}

/// Errors a script can expect from a protocol call or promise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    /// The session or server was closed locally.
    Closed,
    /// The operation's protocol deadline expired.
    Timeout,
    /// An adapter or encrypted session failed.
    Transport,
    /// The peer answered with an application error of this code.
    Remote(u64),
    /// A submitted body has no field in this wire direction.
    Direction,
    /// A submitted envelope exceeds the transport's plaintext limit.
    Large,
    /// Invalid envelope or payload from the peer, or a reused active request ID.
    Malformed,
    /// The inbound request limit closed the session.
    Requests,
    /// The inbound byte limit closed the session.
    Bytes,
}

/// Maps a public error to the script's expected outcome, panicking on errors
/// no script expects.
fn failure(error: Error) -> Failure {
    match error {
        Error::Closed => Failure::Closed,
        Error::Timeout => Failure::Timeout,
        Error::Transport(_) => Failure::Transport,
        Error::Remote(error) => Failure::Remote(error.code),
        Error::WrongDirection(_) => Failure::Direction,
        Error::TooLarge(_) => Failure::Large,
        Error::Malformed => Failure::Malformed,
        Error::InboundRequestLimitExceeded(_) => Failure::Requests,
        Error::InboundByteLimitExceeded(_) => Failure::Bytes,
        other => panic!("unexpected protocol failure: {other}"),
    }
}

/// Raw wire shape, including field combinations that protobuf itself permits.
#[derive(Clone, Debug, PartialEq, Eq)]
enum EnvelopeShape {
    /// Opaque develop body carrying one distinguishing byte.
    Content(u8),
    /// Error-only envelope carrying this code.
    Error(u64),
    /// A valid envelope containing a truncated nested protobuf body.
    MalformedBody,
    /// A valid envelope containing a truncated nested protobuf error.
    MalformedError,
    /// Both content and error, invalid in the protocol.
    Both,
    /// Neither content nor error, invalid in the protocol.
    Neither,
    /// A truncated protobuf field.
    Invalid,
}

/// Script step, with explicit starts and completions for concurrent API calls.
#[derive(Clone, Debug)]
#[cfg_attr(not(test), allow(dead_code))]
enum Step {
    /// Clock advance in milliseconds, taken once the protocol workers park.
    Advance(u64),

    /// Reconnect of the raw client, accepting the replacement under this label.
    Reconnect(u8),
    /// Raw client handshake that times out after the server's output takes its
    /// armed fault.
    FailedReconnect,
    /// Read timeout injected into the server after its ArkHello, while it awaits
    /// the HostAck.
    HandshakeReadTimeout,
    /// Inbound request and byte limits for the labeled session, through its
    /// public setter.
    InboundLimits(u8, usize, usize),
    /// Inbound request and byte limits for the server's current and future
    /// sessions.
    ServerInboundLimits(usize, usize),
    /// Expected accepted requests and retained bytes of the labeled session.
    Usage(u8, usize, usize),

    /// Typed round trip of a schema body from session 0 to session 1, which needs
    /// both protocol peers.
    TypedExchange,
    /// Request from the labeled session, with its promise slot, body tag and
    /// deadline in milliseconds.
    Request(u8, u8, u8, u64),
    /// Request from the labeled session with a body only its peer may send, its
    /// promise saved in a slot.
    WrongDirection(u8, u8),
    /// Request from the labeled session with a body beyond the plaintext limit,
    /// its promise saved in a slot.
    Oversized(u8, u8),
    /// Receipt of a request with this tag on the labeled session, its responder
    /// saved in a slot.
    Receive(u8, u8, u8),
    /// Receive on the labeled session that must fail with this error.
    ///
    /// Unlike [`Self::StartReceive`], it arms no wait hook, so it works on a
    /// nonempty queue or a closed session.
    ReceiveError(u8, Failure),
    /// Receive started in the background on the labeled session, returning once
    /// the call waits on an empty queue.
    StartReceive(u8),
    /// Expected failure of the labeled session's background receive.
    ReceiveFailed(u8, Failure),
    /// Reply through a saved responder with a body tag or an error code, its
    /// write promise saved in a slot and its deadline in milliseconds.
    Reply(u8, u8, Result<u8, u64>, u64),
    /// Reply through a saved responder with a body only the labeled session's
    /// peer may send, its write promise saved in a slot.
    WrongDirectionReply(u8, u8, u8),
    /// Reply through a saved responder with a body beyond the plaintext limit,
    /// its write promise saved in a slot.
    OversizedReply(u8, u8),
    /// Dropped responder, which queues the automatic error reply.
    Abandon(u8),

    /// Notification that sends a token once a saved request promise settles,
    /// leaving its result unread.
    Notify(u8, u8),
    /// Notification that sends a token once a saved reply promise settles,
    /// leaving its result unread.
    NotifyWrite(u8, u8),
    /// Expected next completion token, awaited without servicing deadlines or
    /// taking bytes.
    Notified(u8),
    /// Absence of any queued completion token.
    NoNotifications,
    /// Processing of the response to this ID by the labeled session's reader,
    /// awaited while its bytes stay buffered.
    ResponseReceived(u8, u64),
    /// Expected result of a saved request promise, read without servicing its
    /// deadline.
    ///
    /// The deadline worker must deliver any timeout without help from
    /// `Promise::wait()`.
    Answer(u8, Result<u8, Failure>),
    /// Expected failure of a saved request promise, from local closure or from
    /// the peer closing its stream.
    AnswerClosed(u8),
    /// Dropped request promise, leaving its request in progress.
    DropPromise(u8),
    /// Expected result of a saved reply promise, read without calling
    /// `Promise::wait()`.
    Written(u8, Result<(), Failure>),

    /// Envelope of a chosen ID and shape, sent by the raw peer.
    Send(u64, EnvelopeShape),
    /// Envelope from the raw peer that the protocol peer must refuse.
    ///
    /// The send may fail, since its final flush can race the protocol peer's
    /// shutdown. Later receive or promise steps must prove the rejection.
    Reject(u64, EnvelopeShape),
    /// Expected ID and shape of the next envelope the raw peer receives.
    Read(u64, EnvelopeShape),
    /// Jump of the labeled session's request IDs to the last one it can allocate.
    LastId(u8),
    /// Expected sorted IDs of the labeled session's unanswered requests.
    Outstanding(u8, Vec<u64>),

    /// Pause or resumption of one operation on a pipe, 0 carrying host output
    /// and 1 carrying Ark output.
    Pause(u8, Operation, bool),
    /// Blocked operation on a pipe, awaited before the script goes on.
    Blocked(u8, Operation),
    /// Error injected into the next matching operation on a pipe.
    Fault(u8, Operation, io::ErrorKind),
    /// Gate that pauses the labeled session's writer just before it calls
    /// [`Sender::disconnect`](transport::Sender::disconnect).
    PauseDisconnect(u8),
    /// Arrival of the labeled session's writer at its disconnect gate.
    DisconnectPaused(u8),
    /// Release of the paused writer, letting it call
    /// [`Sender::disconnect`](transport::Sender::disconnect).
    ResumeDisconnect(u8),

    /// Close of the labeled session through its saved [`Closer`].
    Close(u8),
    /// Dropped session owner, which closes the session while saved handles remain.
    Drop(u8),
    /// Refused request through the labeled session's saved [`Requester`].
    Refused(u8),
    /// Awaited drop of the labeled session's last state reference.
    Released(u8),
    /// Closure of the server, every saved session and both streams.
    Shutdown,
    /// Awaited exit of every tracked protocol worker.
    Stopped,
    /// Panicking worker on the labeled session, which must abort the process.
    WorkerPanic(u8),
}

/// Transport owner and bound sender retained by the scripted remote peer.
enum RawPeer {
    /// Raw host, which can handshake again on the same open pipes.
    Client(
        Box<transport::Client<Adapter, Adapter>>,
        transport::Sender<Adapter>,
    ),
    /// Raw Ark, which sends arbitrary server envelopes.
    Server(
        Box<transport::Server<Adapter, Adapter, Attestation>>,
        transport::Sender<Adapter>,
    ),
}

impl RawPeer {
    /// Sends an envelope without applying the protocol's validation rules.
    fn send(&self, id: u64, body: EnvelopeShape) -> Result<(), transport::Error> {
        // Send a truncated nested body or error, built through the opaque view
        if matches!(
            body,
            EnvelopeShape::MalformedBody | EnvelopeShape::MalformedError
        ) {
            let bytes = super::envelope::malformed_body(
                matches!(self, Self::Server(..)),
                id,
                body == EnvelopeShape::MalformedError,
            );
            return match self {
                Self::Client(_, sender) | Self::Server(_, sender) => sender.send(&bytes),
            };
        }

        // Pick the content tag and the error that the other shapes carry
        let (tag, error) = match body {
            EnvelopeShape::Content(tag) => (Some(tag), None),
            EnvelopeShape::Error(code) => (
                None,
                Some(schema::Error {
                    code,
                    msg: "remote failure".into(),
                }),
            ),
            EnvelopeShape::Both => (
                Some(1),
                Some(schema::Error {
                    code: 1,
                    msg: "invalid".into(),
                }),
            ),
            EnvelopeShape::Neither | EnvelopeShape::Invalid => (None, None),
            EnvelopeShape::MalformedBody | EnvelopeShape::MalformedError => unreachable!(),
        };

        // Send them in an envelope of this peer's direction, or send a lone
        // truncated field instead
        let bytes = if body == EnvelopeShape::Invalid {
            vec![0x80]
        } else {
            match self {
                Self::Client(..) => HostToArk {
                    id,
                    err: error,
                    content: tag.map(|tag| host_to_ark::Content::Develop(vec![tag])),
                }
                .encode_to_vec(),
                Self::Server(..) => ArkToHost {
                    id,
                    err: error,
                    content: tag.map(|tag| ark_to_host::Content::Develop(vec![tag])),
                }
                .encode_to_vec(),
            }
        };
        match self {
            Self::Client(_, sender) | Self::Server(_, sender) => sender.send(&bytes),
        }
    }

    /// Receives the next envelope and returns its ID and shape, panicking on
    /// anything but a develop body or an error.
    fn read(&mut self) -> (u64, EnvelopeShape) {
        // Decode the next envelope the protocol peer sent
        let (id, error, content) = match self {
            Self::Client(client, _) => {
                let envelope = ArkToHost::decode(client.recv().unwrap().as_slice()).unwrap();
                (
                    envelope.id,
                    envelope.err,
                    envelope.content.map(Message::from),
                )
            }
            Self::Server(server, _) => {
                let transport::Event::Message(bytes) = server.recv().unwrap() else {
                    panic!("expected message")
                };
                let envelope = HostToArk::decode(bytes.as_slice()).unwrap();
                (
                    envelope.id,
                    envelope.err,
                    envelope.content.map(Message::from),
                )
            }
        };

        // Reduce it to the shapes that scripts compare
        let body = match (content, error) {
            (Some(Message::Develop(bytes)), None) => EnvelopeShape::Content(bytes[0]),
            (None, Some(error)) => EnvelopeShape::Error(error.code),
            other => panic!("unexpected wire body: {other:?}"),
        };
        (id, body)
    }
}

/// Connection fixtures and application handles sharing one scenario clock.
struct Driver {
    /// Sole driver of time for the encrypted peers and protocol workers.
    tester: darkbio_clock::TestClock,
    /// Number of protocol workers that park before scripted clock advances.
    parked: usize,
    /// Persistent protocol server, if this scenario exercises one.
    server: Option<Server>,
    /// Optional scripted transport peer.
    raw: Option<RawPeer>,
    /// Server handshake identity for raw reconnects.
    identity: xdsa::PublicKey,
    /// Host-to-Ark and Ark-to-host pipes.
    pipes: [Arc<Pipe>; 2],

    /// Owners keyed by script labels, including retained predecessors.
    sessions: HashMap<u8, Session>,
    /// Weak session states, for test hooks and for checking that closed sessions
    /// are freed.
    states: HashMap<u8, Weak<SessionInner>>,
    /// Requester handles kept after dropping their sessions.
    requesters: HashMap<u8, Requester>,
    /// Closer handles saved for each session.
    closers: HashMap<u8, Closer>,
    /// Receive calls left blocked while later script steps change state.
    receiving: HashMap<u8, ReceiveJob>,

    /// Responders saved for reply or drop steps.
    responders: HashMap<u8, Responder>,
    /// Request promises saved for later steps.
    promises: HashMap<u8, Promise<Message>>,
    /// Reply promises saved for later steps.
    writes: HashMap<u8, Promise<()>>,
    /// Shared completion events, observed independently of the saved promises.
    notifications: (mpsc::Sender<u8>, mpsc::Receiver<u8>),

    /// Gates that pause old writers before
    /// [`Sender::disconnect`](transport::Sender::disconnect) while a new session
    /// connects.
    disconnects: HashMap<u8, (mpsc::Receiver<()>, mpsc::Sender<()>)>,
    /// Trackers used to wait for each connection's workers to finish.
    workers: Vec<Arc<Tracker>>,
    /// Closers of both streams, used by shutdown steps and on scenario cleanup.
    shutdown: [transport::Closer; 2],
}

/// A receive call returning its non-cloneable owner alongside its result.
type ReceiveJob = Job<(Session, Result<(Message, Responder), Error>)>;

impl Driver {
    /// Constructs peers on shared transport gates, with space for a full handshake.
    fn new(mode: Mode) -> Self {
        // Build both streams on gated pipes sharing the scenario's paused clock
        let tester = crate::transport::testing::test_clock();
        let pipes = [
            Pipe::new(64 * 1024, &tester.clock()),
            Pipe::new(64 * 1024, &tester.clock()),
        ];
        let stream = |side: usize| {
            Stream::new(
                Adapter::new(pipes[1 - side].clone()),
                Adapter::new(pipes[side].clone()),
                {
                    let pipes = pipes.clone();
                    move || {
                        for pipe in pipes {
                            pipe.close();
                        }
                    }
                },
            )
            .set_write_timeout(WRITE_BUDGET)
        };
        let host = stream(0);
        let ark = stream(1);
        let shutdown = [host.closer(), ark.closer()];

        // Retain the identity and application handles for later script steps
        let signer = xdsa::SecretKey::generate();
        let identity = signer.public_key();
        let attestation = self_attestation(&signer);
        let mut driver = Self {
            tester,
            parked: if matches!(mode, Mode::Both) { 6 } else { 3 },
            server: None,
            raw: None,
            identity: identity.clone(),
            pipes,

            sessions: HashMap::new(),
            states: HashMap::new(),
            requesters: HashMap::new(),
            closers: HashMap::new(),
            receiving: HashMap::new(),

            responders: HashMap::new(),
            promises: HashMap::new(),
            writes: HashMap::new(),
            notifications: mpsc::channel(),

            disconnects: HashMap::new(),
            workers: Vec::new(),
            shutdown,
        };

        // Establish the protocol roles selected by the scenario
        match mode {
            Mode::Both | Mode::Server => {
                let mut server = Server::new(ark, signer, attestation);
                driver.workers.push(server.inner.workers.clone());
                match mode {
                    Mode::Both => {
                        let (client, info) = protocol::connect(host, &identity).unwrap();
                        assert!(!info.as_bytes().is_empty());
                        driver.workers.push(client.inner.workers.clone());
                        driver.save(0, client);
                    }
                    Mode::Server => {
                        let mut client =
                            transport::Client::new(host).set_handshake_timeout(WRITE_BUDGET);
                        let (sender, _) = client.connect(&identity).unwrap();
                        driver.raw = Some(RawPeer::Client(Box::new(client), sender));
                    }
                    Mode::Client => unreachable!(),
                }
                driver.save(1, server.accept().unwrap());
                driver.server = Some(server);
            }
            Mode::Client => {
                let server = Job::start(move || {
                    let mut server = transport::Server::new(ark, signer, attestation);
                    let transport::Event::Connected(sender) = server.recv().unwrap() else {
                        panic!("expected handshake")
                    };
                    RawPeer::Server(Box::new(server), sender)
                });
                let (client, _) = protocol::connect(host, &identity).unwrap();
                driver.workers.push(client.inner.workers.clone());
                driver.save(0, client);
                driver.raw = Some(server.finish());
            }
        }
        driver
    }

    /// Saves a session and its requester, closer and weak state under an unused
    /// label.
    fn save(&mut self, label: u8, session: Session) {
        self.requesters.insert(label, session.requester());
        self.closers.insert(label, session.closer());
        self.states.insert(label, Arc::downgrade(&session.inner));
        assert!(self.sessions.insert(label, session).is_none());
    }

    /// Permanently ends protocol owners before canceling remaining physical I/O.
    fn shutdown(&self) {
        if let Some(server) = &self.server {
            server.close();
        }
        for closer in self.closers.values() {
            closer.close();
        }
        for closer in &self.shutdown {
            closer.close();
        }
    }

    /// Runs one scripted action using public calls and controlled adapter events.
    fn step(&mut self, step: Step) {
        match step {
            Step::Advance(millis) => {
                self.tester.wait_blocked(self.parked);
                self.tester.advance(Duration::from_millis(millis));
            }
            Step::Reconnect(label) => {
                let Some(RawPeer::Client(client, sender)) = &mut self.raw else {
                    panic!("raw client required")
                };
                *sender = client.connect(&self.identity).unwrap().0;
                let session = self.server.as_mut().unwrap().accept().unwrap();
                self.save(label, session);
            }
            Step::FailedReconnect => {
                let Some(RawPeer::Client(client, _)) = &mut self.raw else {
                    panic!("raw client required")
                };
                // Expire the raw client's read after failed server output leaves
                // it parked. Time moves only once the server's hello has taken
                // the write fault. A hello that expires first skips the fault,
                // leaving it to fail the next handshake, whose client then waits
                // on this stopped clock.
                let deadline = self.tester.clock().now() + WRITE_BUDGET;
                std::thread::scope(|scope| {
                    let connecting = scope.spawn(|| client.connect(&self.identity));
                    self.pipes[1].wait_blocked(Operation::Read);
                    self.pipes[1].wait_faults_taken();
                    self.tester.advance_to(deadline);
                    assert!(connecting.join().unwrap().is_err());
                });
            }
            Step::HandshakeReadTimeout => {
                // Fail the server's next read deadline once its hello flush blocks
                let incoming = self.pipes[0].clone();
                let outgoing = self.pipes[1].clone();
                outgoing.pause(Operation::Flush, true);
                let gate = Job::start(move || {
                    outgoing.wait_blocked(Operation::Flush);
                    incoming.fail_read_deadline(io::ErrorKind::TimedOut);
                    outgoing.pause(Operation::Flush, false);
                });

                // Run the raw handshake, which the client may finish on its side
                // even though the server fails
                let Some(RawPeer::Client(client, _)) = &mut self.raw else {
                    panic!("raw client required")
                };
                let _ = client.connect(&self.identity);
                gate.finish();
            }
            Step::InboundLimits(id, requests, bytes) => {
                let session = self
                    .sessions
                    .remove(&id)
                    .unwrap()
                    .set_inbound_limits(requests, bytes);
                self.sessions.insert(id, session);
            }
            Step::ServerInboundLimits(requests, bytes) => {
                self.server = Some(
                    self.server
                        .take()
                        .unwrap()
                        .set_inbound_limits(requests, bytes),
                );
            }
            Step::Usage(label, requests, bytes) => {
                assert_eq!(
                    self.states[&label].upgrade().unwrap().inbound_usage(),
                    (requests, bytes)
                );
            }
            Step::TypedExchange => {
                let promise = self.requesters[&0]
                    .request(
                        schema::DeviceInfoRequest {},
                        self.tester.clock().now() + BUDGET,
                    )
                    .unwrap();
                let (message, responder) = self.sessions.get_mut(&1).unwrap().recv().unwrap();
                assert!(matches!(message, Message::DeviceInfoRequest(_)));
                let write = responder
                    .reply(
                        schema::DeviceInfoResponse {
                            version_id: 42,
                            ..Default::default()
                        },
                        self.tester.clock().now() + BUDGET,
                    )
                    .unwrap();
                let reply: schema::DeviceInfoResponse = promise.wait().unwrap();
                assert_eq!(reply.version_id, 42);
                write.wait().unwrap();
            }
            Step::Request(session, slot, tag, ms) => {
                self.promises.insert(
                    slot,
                    self.requesters[&session]
                        .request(
                            vec![tag],
                            self.tester.clock().now() + Duration::from_millis(ms),
                        )
                        .unwrap(),
                );
            }
            Step::WrongDirection(session, slot) => {
                let body: Message = if session == 0 {
                    schema::DeviceInfoResponse::default().into()
                } else {
                    schema::DeviceInfoRequest {}.into()
                };
                self.promises.insert(
                    slot,
                    self.requesters[&session]
                        .request(body, self.tester.clock().now() + BUDGET)
                        .unwrap(),
                );
            }
            Step::Oversized(session, slot) => {
                self.promises.insert(
                    slot,
                    self.requesters[&session]
                        .request(
                            vec![0; transport::MAX_MESSAGE_SIZE + 1],
                            self.tester.clock().now() + BUDGET,
                        )
                        .unwrap(),
                );
            }
            Step::Receive(session, tag, slot) => {
                let (message, responder) = self.sessions.get_mut(&session).unwrap().recv().unwrap();
                assert_eq!(message, Message::Develop(vec![tag]));
                self.responders.insert(slot, responder);
            }
            Step::ReceiveError(label, expected) => {
                let mut session = self.sessions.remove(&label).unwrap();
                let (session, result) = Job::start(move || {
                    let result = session.recv();
                    (session, result)
                })
                .finish();
                assert_eq!(failure(result.expect_err("receive must fail")), expected);
                self.sessions.insert(label, session);
            }
            Step::StartReceive(label) => {
                // Arm the wait hook first, so the step returns once the call waits
                let mut session = self.sessions.remove(&label).unwrap();
                let waiting = session.inner.watch_recv_wait();
                self.receiving.insert(
                    label,
                    Job::start(move || {
                        let result = session.recv();
                        (session, result)
                    }),
                );
                waiting.recv().unwrap();
            }
            Step::ReceiveFailed(label, expected) => {
                let (session, result) = self.receiving.remove(&label).unwrap().finish();
                assert_eq!(failure(result.expect_err("receive must fail")), expected);
                self.sessions.insert(label, session);
            }
            Step::Reply(slot, promise, body, ms) => {
                let responder = self.responders.remove(&slot).unwrap();
                let deadline = self.tester.clock().now() + Duration::from_millis(ms);
                let result = match body {
                    Ok(tag) => responder.reply(vec![tag], deadline),
                    Err(code) => responder.fail(schema::Error::new(code, "refused"), deadline),
                };
                self.writes.insert(promise, result.unwrap());
            }
            Step::WrongDirectionReply(session, slot, promise) => {
                let body: Message = if session == 0 {
                    schema::DeviceInfoResponse::default().into()
                } else {
                    schema::DeviceInfoRequest {}.into()
                };
                self.writes.insert(
                    promise,
                    self.responders
                        .remove(&slot)
                        .unwrap()
                        .reply(body, self.tester.clock().now() + BUDGET)
                        .unwrap(),
                );
            }
            Step::OversizedReply(slot, promise) => {
                self.writes.insert(
                    promise,
                    self.responders
                        .remove(&slot)
                        .unwrap()
                        .reply(
                            vec![0; transport::MAX_MESSAGE_SIZE + 1],
                            self.tester.clock().now() + BUDGET,
                        )
                        .unwrap(),
                );
            }
            Step::Abandon(slot) => {
                drop(self.responders.remove(&slot).unwrap());
            }
            Step::Notify(slot, token) => {
                let events = self.notifications.0.clone();
                self.promises.get_mut(&slot).unwrap().notify(move || {
                    let _ = events.send(token);
                });
            }
            Step::NotifyWrite(slot, token) => {
                let events = self.notifications.0.clone();
                self.writes.get_mut(&slot).unwrap().notify(move || {
                    let _ = events.send(token);
                });
            }
            Step::Notified(token) => {
                assert_eq!(self.notifications.1.recv().unwrap(), token)
            }
            Step::NoNotifications => assert!(self.notifications.1.try_recv().is_err()),
            Step::ResponseReceived(label, id) => {
                self.states[&label].upgrade().unwrap().wait_response(id)
            }
            Step::Answer(slot, expected) => {
                let result = self
                    .promises
                    .remove(&slot)
                    .unwrap()
                    .wait_worker_result()
                    .map(|body| Vec::<u8>::try_from(body).unwrap()[0])
                    .map_err(failure);
                assert_eq!(result, expected);
            }
            Step::AnswerClosed(slot) => {
                assert!(matches!(
                    self.promises.remove(&slot).unwrap().wait_worker_result(),
                    Err(Error::Closed | Error::Transport(_))
                ));
            }
            Step::DropPromise(slot) => {
                drop(self.promises.remove(&slot).unwrap());
            }
            Step::Written(slot, expected) => {
                assert_eq!(
                    self.writes
                        .remove(&slot)
                        .unwrap()
                        .wait_worker_result()
                        .map_err(failure),
                    expected
                );
            }
            Step::Send(id, body) => self.raw.as_ref().unwrap().send(id, body).unwrap(),
            Step::Reject(id, body) => {
                let _ = self.raw.as_ref().unwrap().send(id, body);
            }
            Step::Read(id, body) => assert_eq!(self.raw.as_mut().unwrap().read(), (id, body)),
            Step::LastId(label) => self.states[&label].upgrade().unwrap().use_last_request_id(),
            Step::Outstanding(label, ids) => {
                assert_eq!(
                    self.states[&label].upgrade().unwrap().outstanding_ids(),
                    ids
                )
            }
            Step::Pause(side, op, paused) => self.pipes[side as usize].pause(op, paused),
            Step::Blocked(side, op) => self.pipes[side as usize].wait_blocked(op),
            Step::Fault(side, op, error) => {
                self.pipes[side as usize].fault(op, 0, FaultKind::Error(error))
            }
            Step::PauseDisconnect(label) => {
                self.disconnects.insert(
                    label,
                    self.states[&label].upgrade().unwrap().pause_disconnect(),
                );
            }
            Step::DisconnectPaused(label) => self.disconnects[&label].0.recv().unwrap(),
            Step::ResumeDisconnect(label) => {
                self.disconnects.remove(&label).unwrap().1.send(()).unwrap();
            }
            Step::Close(label) => self.closers[&label].close(),
            Step::Drop(label) => {
                drop(self.sessions.remove(&label).unwrap());
            }
            Step::Refused(label) => {
                assert!(
                    self.requesters[&label]
                        .request(vec![1], self.tester.clock().now() + BUDGET)
                        .is_err()
                );
            }
            Step::Released(label) => {
                // Wait for workers to release the last strong session reference
                if let Some(state) = self.states[&label].upgrade() {
                    let released = state.watch_drop();
                    drop(state);
                    released.recv().unwrap();
                }
                assert!(self.states[&label].upgrade().is_none());
            }
            Step::Shutdown => self.shutdown(),
            Step::Stopped => {
                for workers in &self.workers {
                    workers.wait_stopped();
                }
            }
            Step::WorkerPanic(label) => {
                worker::spawn(
                    "wire-test-failure",
                    &self.states[&label].upgrade().unwrap().workers,
                    || panic!("scripted worker failure"),
                );
            }
        }
    }
}

impl Drop for Driver {
    /// Closes the pipes, even after a failed assertion, and waits for every
    /// protocol worker to exit.
    fn drop(&mut self) {
        // Release the writers held before their disconnect, then close everything
        self.disconnects.clear();
        self.shutdown();

        // The server tracker also counts workers from replaced sessions and
        // sessions the application never accepted
        for workers in &self.workers {
            workers.wait_stopped();
        }
    }
}

/// Builds a script that closes the labeled session through an inbound limit or
/// a deferred decoding failure while its output is blocked.
///
/// One request stays blocked in the given write or flush phase, with an explicit
/// reply, an automatic reply and a second request queued behind it. The closing
/// `reason` must fail both requests and the explicit reply, and free the inbound
/// usage.
///
/// # Panics
///
/// Panics unless `reason` is [`Failure::Requests`], [`Failure::Bytes`] or
/// [`Failure::Malformed`].
fn blocked_inbound_steps(
    local: u8,
    own: u64,
    peer: u64,
    outgoing: u8,
    phase: Operation,
    reason: Failure,
) -> Vec<Step> {
    use EnvelopeShape::*;
    use Step::*;

    // Tighten the limits and block a first request, whose frame the peer reads
    // when only its flush is blocked
    let mut steps = vec![
        InboundLimits(local, 3, 100),
        Pause(outgoing, phase, true),
        Request(local, 0, 10, 3000),
        Blocked(outgoing, phase),
    ];
    if phase == Operation::Flush {
        steps.push(Read(own, Content(10)));
    }

    // Buffer a malformed response for the decoding failure to come
    if reason == Failure::Malformed {
        steps.extend([Send(own, MalformedBody), ResponseReceived(local, own)]);
    }

    // Queue an explicit reply, an automatic reply and a second request
    steps.extend([
        Send(peer, Content(11)),
        Receive(local, 11, 0),
        Send(peer.wrapping_add(2), Content(12)),
        Receive(local, 12, 1),
        Reply(0, 0, Ok(13), 3000),
        Abandon(1),
        Request(local, 1, 14, 3000),
    ]);

    // Set a limit that the next peer request exceeds, unless decoding is to fail
    match reason {
        Failure::Requests => steps.push(InboundLimits(local, 2, 100)),
        Failure::Bytes => steps.push(InboundLimits(local, 3, 0)),
        Failure::Malformed => {}
        _ => unreachable!("inbound closing reason required"),
    }

    // Close the session while a receive waits, by decoding the malformed
    // response or by sending one more peer request
    steps.push(StartReceive(local));
    if reason == Failure::Malformed {
        steps.push(Answer(0, Err(reason)));
    } else {
        steps.push(Reject(peer.wrapping_add(4), Content(15)));
    }
    steps.push(ReceiveFailed(local, reason));
    if reason != Failure::Malformed {
        steps.push(Answer(0, Err(reason)));
    }

    // Require the queued work to fail and the inbound usage to drop to zero
    steps.extend([
        Answer(1, Err(reason)),
        Written(0, Err(reason)),
        Usage(local, 0, 0),
        Pause(outgoing, phase, false),
    ]);
    steps
}

/// Runs a script on a fresh driver, logging each step so a failure shows where
/// it stopped.
fn run(mode: Mode, steps: &[Step]) {
    #[cfg(test)]
    crate::testing::init_tracing();
    let mut driver = Driver::new(mode);
    for (index, step) in steps.iter().enumerate() {
        tracing::debug!(index, ?step, "protocol connection scenario");
        driver.step(step.clone());
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;

mod fuzz;
pub use fuzz::{Action, Kind, run as fuzz};
