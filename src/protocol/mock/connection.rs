// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Real transport scenarios using the transport runner's gated byte pipes.
//! Scripts can run both protocol peers or inspect one peer through a raw transport.

use super::session::Job;
use crate::protocol::session::SessionInner;
use crate::protocol::worker::{self, Tracker};
use crate::protocol::{
    self, ArkToHost, Closer, Error, HostToArk, Message, Promise, RemoteError, Requester, Responder,
    Server, Session, ark_to_host, host_to_ark,
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
use std::time::{Duration, Instant};

/// Default protocol timeout for scenarios that do not specify one.
const BUDGET: Duration = Duration::from_secs(3);
/// Transport write timeout, shorter than the scenario watchdog.
const WRITE_BUDGET: Duration = Duration::from_millis(500);

/// Which peers run the protocol API; the other peer, if any, uses raw envelopes.
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
    /// Invalid peer envelope or duplicate outstanding request ID.
    Malformed,
    /// An adapter or encrypted session failed.
    Transport,
    /// A submitted body has no field in this wire direction.
    Direction,
    /// A submitted envelope exceeds the transport's plaintext limit.
    Large,
    /// A peer application error.
    Remote(u64),
    /// The inbound request limit closed the session.
    Requests,
    /// The inbound byte limit closed the session.
    Bytes,
}

/// Maps public errors into the script's expected outcomes.
fn failure(error: Error) -> Failure {
    match error {
        Error::Closed => Failure::Closed,
        Error::InboundRequestLimitExceeded(_) => Failure::Requests,
        Error::InboundByteLimitExceeded(_) => Failure::Bytes,
        Error::Timeout => Failure::Timeout,
        Error::Malformed => Failure::Malformed,
        Error::Transport(_) => Failure::Transport,
        Error::WrongDirection(_) => Failure::Direction,
        Error::TooLarge(_) => Failure::Large,
        Error::Remote(error) => Failure::Remote(error.code),
        other => panic!("unexpected protocol failure: {other}"),
    }
}

/// Raw wire shape, including field combinations that protobuf itself permits.
#[derive(Clone, Debug, PartialEq, Eq)]
enum EnvelopeShape {
    /// Opaque develop body carrying one distinguishing byte.
    Content(u8),
    /// Error-only response.
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

/// Serial script with explicit starts and completions for concurrent API calls.
#[derive(Clone, Debug)]
#[cfg_attr(not(test), allow(dead_code))]
enum Step {
    /// Receives a queued request and requires a specific failure without a wait hook.
    ReceiveError(u8, Failure),
    /// Checks accepted requests and retained bytes after earlier work has completed.
    Usage(u8, usize, usize),
    /// Waits for response delivery without consuming its buffered bytes.
    ResponseReceived(u8, u64),
    /// Changes both inbound limits through the public session setter.
    InboundLimits(u8, usize, usize),
    /// Changes both server limits for the current and future sessions.
    ServerInboundLimits(usize, usize),

    /// Round-trip a concrete schema body through the public typed waiting API.
    TypedExchange,
    /// Request from session label, save promise in slot, payload tag, deadline ms.
    Request(u8, u8, u8, u64),
    /// Submit a body belonging to the opposite wire direction.
    WrongDirection(u8, u8),
    /// Submit a body beyond the plaintext limit.
    Oversized(u8, u8),
    /// Receive a request and retain its responder in the given slot.
    Receive(u8, u8, u8),
    /// Begin a blocked receive on the labeled session.
    StartReceive(u8),
    /// Require the blocked receive to finish with this failure.
    ReceiveFailed(u8, Failure),
    /// Reply through a responder, retaining its write promise.
    Reply(u8, u8, Result<u8, u64>, u64),
    /// Reply with a body invalid for the labeled session's wire direction.
    WrongDirectionReply(u8, u8, u8),
    /// Reply with a body beyond the plaintext limit, retaining its write promise.
    OversizedReply(u8, u8),
    /// Drop a responder to queue the automatic error.
    Abandon(u8),
    /// Reads the request's result channel directly, so its deadline worker must
    /// deliver any timeout without help from `Promise::wait()`.
    Answer(u8, Result<u8, Failure>),
    /// The promise may fail from local closure or from the peer closing its stream.
    AnswerClosed(u8),
    /// Reads the reply's result channel directly, without calling `Promise::wait()`.
    Written(u8, Result<(), Failure>),
    /// Drops the promise, leaving the request in progress.
    DropPromise(u8),
    /// Send a chosen ID and shape from the raw peer.
    Send(u64, EnvelopeShape),
    /// Send invalid traffic; peer shutdown may race the sender's final flush.
    /// Following receive/promise assertions must prove the actual rejection.
    Reject(u64, EnvelopeShape),
    /// Inspect a raw received ID and shape.
    Read(u64, EnvelopeShape),
    /// Pause or resume one physical direction (0 host output, 1 Ark output).
    Pause(u8, Operation, bool),
    /// Wait until the selected adapter operation is actually blocked.
    Blocked(u8, Operation),
    /// Fail the next matching adapter operation.
    Fault(u8, Operation, io::ErrorKind),
    /// Close this session through its saved `Closer`.
    Close(u8),
    /// Drop a session owner with its worker and handle references still alive.
    Drop(u8),
    /// Reconnect the raw client and accept a replacement under this label.
    Reconnect(u8),
    /// Require a failed raw handshake before testing another attempt.
    FailedReconnect,
    /// Inject a read timeout after ArkHello, while the server awaits HostAck.
    HandshakeReadTimeout,
    /// Pause the session writer just before it calls `Sender::disconnect()`.
    PauseDisconnect(u8),
    /// Wait until the writer is paused before `Sender::disconnect()`.
    DisconnectPaused(u8),
    /// Let the paused writer call `Sender::disconnect()`.
    ResumeDisconnect(u8),
    /// Require a request through an old `Requester` to fail.
    Refused(u8),
    /// Check that the session's weak reference stops upgrading after its workers exit.
    Released(u8),
    /// Close the server and all protocol connections.
    Shutdown,
    /// Start a protocol worker that panics to test that the process aborts.
    WorkerPanic(u8),
    /// Start the local allocator at its final valid ID.
    LastId(u8),
    /// Check the request IDs still awaiting peer responses.
    Outstanding(u8, Vec<u64>),
    /// Require all threads to exit after physical shutdown.
    Stopped,
}

/// Transport owner and bound sender retained by the scripted remote peer.
enum RawPeer {
    /// Raw host can re-handshake on the same open pipe.
    Client(
        Box<transport::Client<Adapter, Adapter>>,
        transport::Sender<Adapter>,
    ),
    /// Raw Ark supplies arbitrary server envelopes.
    Server(
        Box<transport::Server<Adapter, Adapter, Attestation>>,
        transport::Sender<Adapter>,
    ),
}

impl RawPeer {
    /// Sends an envelope without applying the protocol's validation rules.
    fn send(&self, id: u64, body: EnvelopeShape) -> Result<(), transport::Error> {
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
        let (tag, error) = match body {
            EnvelopeShape::Content(tag) => (Some(tag), None),
            EnvelopeShape::Error(code) => (
                None,
                Some(RemoteError {
                    code,
                    msg: "remote failure".into(),
                }),
            ),
            EnvelopeShape::Both => (
                Some(1),
                Some(RemoteError {
                    code: 1,
                    msg: "invalid".into(),
                }),
            ),
            EnvelopeShape::Neither | EnvelopeShape::Invalid => (None, None),
            EnvelopeShape::MalformedBody | EnvelopeShape::MalformedError => unreachable!(),
        };
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

    /// Receives and extracts one raw peer result for script assertions.
    fn read(&mut self) -> (u64, EnvelopeShape) {
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
        let body = match (content, error) {
            (Some(Message::Develop(bytes)), None) => EnvelopeShape::Content(bytes[0]),
            (None, Some(error)) => EnvelopeShape::Error(error.code),
            other => panic!("unexpected wire body: {other:?}"),
        };
        (id, body)
    }
}

/// Connection fixtures, application handles, and an independent hang watchdog.
struct Driver {
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
    /// Requester handles kept after dropping their sessions.
    requesters: HashMap<u8, Requester>,
    /// Closer handles saved for each session.
    closers: HashMap<u8, Closer>,
    /// Weak references used to check that closed sessions are freed.
    states: HashMap<u8, Weak<SessionInner>>,
    /// Trackers used to wait for each connection's workers to finish.
    workers: Vec<Arc<Tracker>>,
    /// Request promises saved for later steps.
    promises: HashMap<u8, Promise<Message>>,
    /// Reply promises saved for later steps.
    writes: HashMap<u8, Promise<()>>,
    /// Responders saved for reply or drop steps.
    responders: HashMap<u8, Responder>,
    /// Calls left blocked while later script steps change state.
    receiving: HashMap<u8, ReceiveJob>,
    /// Gates that pause old writers before `Sender::disconnect()` while a new
    /// session connects.
    disconnects: HashMap<u8, (mpsc::Receiver<()>, mpsc::Sender<()>)>,
    /// Physical closers used on normal cleanup and watchdog expiry.
    shutdown: [transport::Closer; 2],
    /// Stops the watchdog once all workers and calls have been released.
    stop: Option<mpsc::Sender<()>>,
    /// Watchdog outcome; true means the scenario exceeded its time budget.
    watchdog: Option<Job<bool>>,
}

/// A receive call returning its non-cloneable owner alongside its result.
type ReceiveJob = Job<(Session, Result<(Message, Responder), Error>)>;

impl Driver {
    /// Constructs peers on shared transport gates, with space for a full handshake.
    fn new(mode: Mode) -> Self {
        let pipes = [Pipe::new(64 * 1024), Pipe::new(64 * 1024)];
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
        let (stop, stopped) = mpsc::channel();
        let closers = shutdown.clone();
        // Arm the watchdog before handshaking so setup stalls release the same
        // pipes as stalls during a scripted step.
        let watchdog = Job::start(move || {
            if stopped.recv_timeout(Duration::from_secs(8)).is_ok() {
                return false;
            }
            for closer in closers {
                closer.close();
            }
            true
        });
        let signer = xdsa::SecretKey::generate();
        let identity = signer.public_key();
        let attestation = self_attestation(&signer);
        let mut driver = Self {
            server: None,
            raw: None,
            identity: identity.clone(),
            pipes,
            sessions: HashMap::new(),
            requesters: HashMap::new(),
            closers: HashMap::new(),
            states: HashMap::new(),
            workers: Vec::new(),
            promises: HashMap::new(),
            writes: HashMap::new(),
            responders: HashMap::new(),
            receiving: HashMap::new(),
            disconnects: HashMap::new(),
            shutdown,
            stop: Some(stop),
            watchdog: Some(watchdog),
        };
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

    /// Saves a session and its requester, closer, and weak state reference.
    fn save(&mut self, label: u8, session: Session) {
        self.requesters.insert(label, session.requester());
        self.closers.insert(label, session.closer());
        self.states.insert(label, Arc::downgrade(&session.inner));
        assert!(self.sessions.insert(label, session).is_none());
    }

    /// Permanently ends protocol owners before cancelling remaining physical I/O.
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
            Step::ReceiveError(label, expected) => {
                let mut session = self.sessions.remove(&label).unwrap();
                let (session, result) = Job::start(move || {
                    let result = session.recv();
                    (session, result)
                })
                .finish();
                assert_eq!(failure(result.err().expect("receive must fail")), expected);
                self.sessions.insert(label, session);
            }
            Step::Usage(label, requests, bytes) => {
                assert_eq!(
                    self.states[&label].upgrade().unwrap().inbound_usage(),
                    (requests, bytes)
                );
            }
            Step::ResponseReceived(label, id) => {
                self.states[&label].upgrade().unwrap().wait_response(id)
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

            Step::TypedExchange => {
                let promise = self.requesters[&0]
                    .request(protocol::DeviceInfoRequest {}, Instant::now() + BUDGET)
                    .unwrap();
                let (message, responder) = self.sessions.get_mut(&1).unwrap().recv().unwrap();
                assert!(matches!(message, Message::DeviceInfoRequest(_)));
                let write = responder
                    .reply(
                        protocol::DeviceInfoResponse {
                            version_id: 42,
                            ..Default::default()
                        },
                        Instant::now() + BUDGET,
                    )
                    .unwrap();
                let reply: protocol::DeviceInfoResponse = promise.wait().unwrap();
                assert_eq!(reply.version_id, 42);
                write.wait().unwrap();
            }
            Step::Request(session, slot, tag, ms) => {
                self.promises.insert(
                    slot,
                    self.requesters[&session]
                        .request(vec![tag], Instant::now() + Duration::from_millis(ms))
                        .unwrap(),
                );
            }
            Step::WrongDirection(session, slot) => {
                let body: Message = if session == 0 {
                    protocol::DeviceInfoResponse::default().into()
                } else {
                    protocol::DeviceInfoRequest {}.into()
                };
                self.promises.insert(
                    slot,
                    self.requesters[&session]
                        .request(body, Instant::now() + BUDGET)
                        .unwrap(),
                );
            }
            Step::Oversized(session, slot) => {
                self.promises.insert(
                    slot,
                    self.requesters[&session]
                        .request(
                            vec![0; transport::MAX_MESSAGE_SIZE + 1],
                            Instant::now() + BUDGET,
                        )
                        .unwrap(),
                );
            }
            Step::Receive(session, tag, slot) => {
                let (message, responder) = self.sessions.get_mut(&session).unwrap().recv().unwrap();
                assert_eq!(message, Message::Develop(vec![tag]));
                self.responders.insert(slot, responder);
            }
            Step::StartReceive(label) => {
                let mut session = self.sessions.remove(&label).unwrap();
                let waiting = session.inner.watch_recv_wait();
                self.receiving.insert(
                    label,
                    Job::start(move || {
                        let result = session.recv();
                        (session, result)
                    }),
                );
                waiting.recv_timeout(BUDGET).unwrap();
            }
            Step::ReceiveFailed(label, expected) => {
                let (session, result) = self.receiving.remove(&label).unwrap().finish();
                assert_eq!(failure(result.err().expect("receive must fail")), expected);
                self.sessions.insert(label, session);
            }
            Step::Reply(slot, promise, body, ms) => {
                let responder = self.responders.remove(&slot).unwrap();
                let deadline = Instant::now() + Duration::from_millis(ms);
                let result = match body {
                    Ok(tag) => responder.reply(vec![tag], deadline),
                    Err(code) => responder.fail(RemoteError::new(code, "refused"), deadline),
                };
                self.writes.insert(promise, result.unwrap());
            }
            Step::WrongDirectionReply(session, slot, promise) => {
                let body: Message = if session == 0 {
                    protocol::DeviceInfoResponse::default().into()
                } else {
                    protocol::DeviceInfoRequest {}.into()
                };
                self.writes.insert(
                    promise,
                    self.responders
                        .remove(&slot)
                        .unwrap()
                        .reply(body, Instant::now() + BUDGET)
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
                            Instant::now() + BUDGET,
                        )
                        .unwrap(),
                );
            }
            Step::Abandon(slot) => {
                drop(self.responders.remove(&slot).unwrap());
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
            Step::DropPromise(slot) => {
                drop(self.promises.remove(&slot).unwrap());
            }
            Step::Send(id, body) => self.raw.as_ref().unwrap().send(id, body).unwrap(),
            Step::Reject(id, body) => {
                let _ = self.raw.as_ref().unwrap().send(id, body);
            }
            Step::Read(id, body) => assert_eq!(self.raw.as_mut().unwrap().read(), (id, body)),
            Step::Pause(side, op, paused) => self.pipes[side as usize].pause(op, paused),
            Step::Blocked(side, op) => self.pipes[side as usize].wait_blocked(op),
            Step::Fault(side, op, error) => {
                self.pipes[side as usize].fault(op, 0, FaultKind::Error(error))
            }
            Step::Close(label) => self.closers[&label].close(),
            Step::Drop(label) => {
                drop(self.sessions.remove(&label).unwrap());
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
                assert!(client.connect(&self.identity).is_err());
            }
            Step::HandshakeReadTimeout => {
                let incoming = self.pipes[0].clone();
                let outgoing = self.pipes[1].clone();
                outgoing.pause(Operation::Flush, true);
                let gate = Job::start(move || {
                    outgoing.wait_blocked(Operation::Flush);
                    incoming.fail_read_deadline(io::ErrorKind::TimedOut);
                    outgoing.pause(Operation::Flush, false);
                });
                let Some(RawPeer::Client(client, _)) = &mut self.raw else {
                    panic!("raw client required")
                };
                let _ = client.connect(&self.identity);
                gate.finish();
            }
            Step::PauseDisconnect(label) => {
                self.disconnects.insert(
                    label,
                    self.states[&label].upgrade().unwrap().pause_disconnect(),
                );
            }
            Step::DisconnectPaused(label) => {
                self.disconnects[&label].0.recv_timeout(BUDGET).unwrap()
            }
            Step::ResumeDisconnect(label) => {
                self.disconnects.remove(&label).unwrap().1.send(()).unwrap();
            }
            Step::Refused(label) => {
                assert!(
                    self.requesters[&label]
                        .request(vec![1], Instant::now() + BUDGET)
                        .is_err()
                );
            }
            Step::Released(label) => {
                // Workers release their SessionInner references on exit. Wait up to
                // BUDGET for the last strong reference to disappear.
                if let Some(state) = self.states[&label].upgrade() {
                    let released = state.watch_drop();
                    drop(state);
                    released.recv_timeout(BUDGET).unwrap();
                }
                assert!(self.states[&label].upgrade().is_none());
            }
            Step::Shutdown => self.shutdown(),
            Step::WorkerPanic(label) => {
                worker::spawn(
                    "wire-test-failure",
                    &self.states[&label].upgrade().unwrap().workers,
                    || panic!("scripted worker failure"),
                );
            }
            Step::LastId(label) => self.states[&label].upgrade().unwrap().use_last_request_id(),
            Step::Outstanding(label, ids) => {
                assert_eq!(
                    self.states[&label].upgrade().unwrap().outstanding_ids(),
                    ids
                )
            }
            Step::Stopped => {
                for workers in &self.workers {
                    workers.wait_stopped();
                }
            }
        }
    }
}

impl Drop for Driver {
    /// Closes the pipes even if an assertion panics. On success, also checks that
    /// every protocol worker exits.
    fn drop(&mut self) {
        self.disconnects.clear();
        self.shutdown();
        // The server tracker also counts workers from replaced sessions and
        // sessions the application never accepted.
        for workers in &self.workers {
            workers.wait_stopped();
        }
        let _ = self.stop.take().unwrap().send(());
        let expired = self.watchdog.take().unwrap().finish();
        if !std::thread::panicking() {
            assert!(!expired, "connection scenario exceeded watchdog");
        }
    }
}

/// Keeps one write in flight and both explicit and automatic replies queued
/// while inbound admission or deferred decoding closes the session.
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
    let mut steps = vec![
        InboundLimits(local, 3, 100),
        Pause(outgoing, phase, true),
        Request(local, 0, 10, 3000),
        Blocked(outgoing, phase),
    ];
    if phase == Operation::Flush {
        steps.push(Read(own, Content(10)));
    }
    if reason == Failure::Malformed {
        steps.extend([Send(own, MalformedBody), ResponseReceived(local, own)]);
    }
    steps.extend([
        Send(peer, Content(11)),
        Receive(local, 11, 0),
        Send(peer.wrapping_add(2), Content(12)),
        Receive(local, 12, 1),
        Reply(0, 0, Ok(13), 3000),
        Abandon(1),
        Request(local, 1, 14, 3000),
    ]);
    match reason {
        Failure::Requests => steps.push(InboundLimits(local, 2, 100)),
        Failure::Bytes => steps.push(InboundLimits(local, 3, 0)),
        Failure::Malformed => {}
        _ => unreachable!("inbound closing reason required"),
    }
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
    steps.extend([
        Answer(1, Err(reason)),
        Written(0, Err(reason)),
        Usage(local, 0, 0),
        Pause(outgoing, phase, false),
    ]);
    steps
}

/// Runs a script with automatic cleanup and step diagnostics on failure.
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
