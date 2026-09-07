// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Multiplexer of requests and responses over one session, for either side
//! of the wire. A reader thread owns the transport and routes what arrives,
//! answers to the callers waiting for them, requests to a worker thread
//! running the handler, so the reader blocks on nothing but its read. Callers
//! send through the session's emitter from any thread, a request coming back
//! as a pending answer to wait on, several outstanding at once pipelining
//! them within a window of bytes in flight, so a peer following the same
//! rules never overflows, and a peer that does not follow them has its
//! session ended.

use crate::protocol::envelope::Envelope;
#[cfg(any(test, feature = "fuzz"))]
use crate::protocol::switchboard::Source;
use crate::protocol::switchboard::{Sender, Switchboard};
use crate::protocol::{self, ArkToHost, HostToArk};
use crate::transport::{self, Attester, Emitter, MAX_MESSAGE_SIZE, Side};
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Weak};
use std::time::Duration;
use tracing::warn;

/// Reading half of the transport, the type erased.
pub type Reader = Box<dyn Read + Send>;

/// Writing half of the transport, the type erased.
pub type Writer = Box<dyn Write + Send>;

/// Hook ending the transport underneath, so a reader blocked in it wakes up.
pub type Closer = Box<dyn FnOnce() + Send>;

/// Bytes of unanswered requests a mux keeps in flight before its callers
/// wait. Eight maximal messages, enough for three uploads pipelining a few
/// chunks each to keep a link busy while the peer works, and a second of link
/// time to resend if the session drops.
pub const WINDOW: usize = 16 * 1024 * 1024;

/// Bytes of requests the inbox holds ahead of the worker before the session
/// is ended on the peer. Four windows, which a peer respecting its window
/// never reaches, so only one ignoring the rules does.
pub const INBOX: usize = 64 * 1024 * 1024;

/// Things that can go wrong for a caller of the multiplexer.
#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    #[error("wire request timed out")]
    Timeout,

    #[error("wire peer overran its window")]
    Flooded,

    #[error("wire peer sent a malformed message")]
    Malformed,

    #[error("wire multiplexer closed")]
    Closed,

    #[error("wire session ended: {0}")]
    Disconnected(Arc<transport::Error>),

    #[error("wire message too large: {0} bytes, max {MAX_MESSAGE_SIZE} bytes")]
    TooLarge(usize),

    #[error("wire peer failed the request, code {}: {}", .0.code, .0.msg)]
    Remote(protocol::Error),
}

/// The client side of the protocol, what a host holds.
pub type Client = Mux<HostToArk, ArkToHost>;

impl Client {
    /// Starts multiplexing over a transport client with its handshake done,
    /// the closer ending the transport when the multiplexer closes or the
    /// session fails.
    pub fn new(client: transport::Client<Reader, Writer>, closer: Closer) -> Self {
        Self {
            switchboard: Switchboard::start(Side::Client, client, closer),
        }
    }
}

/// The server side of the protocol, what an Ark holds.
pub type Server = Mux<ArkToHost, HostToArk>;

impl Server {
    /// Starts multiplexing over a transport server, serving the clients it
    /// handshakes one session at a time, a session ending failing whatever it
    /// left pending. The closer ends the transport when the multiplexer
    /// closes or the transport fails.
    pub fn new<A: Attester + Send + 'static>(
        server: transport::Server<Reader, Writer, A>,
        closer: Closer,
    ) -> Self {
        Self {
            switchboard: Switchboard::start(Side::Server, server, closer),
        }
    }
}

/// Answer to a request still on its way, waited for once. Dropped, the
/// request is forgotten and its answer discarded on arrival, the request
/// keeping its place in the window until then, the peer still holding the
/// work.
pub struct Pending<T> {
    answer: mpsc::Receiver<Result<T, Error>>, // Answer, or the reason there is none
    forget: Option<Box<dyn FnOnce() -> bool + Send>>, // Forgets the request, telling if it was still pending
}

impl<T> Pending<T> {
    /// Waits for the answer within the timeout. Past it the request is
    /// forgotten and its answer discarded on arrival, unless the answer was
    /// being delivered at that very moment, in which case it is returned.
    pub fn wait(mut self, timeout: Duration) -> Result<T, Error> {
        let forget = self.forget.take().expect("answer waited for once");
        match self.answer.recv_timeout(timeout) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => {
                if forget() {
                    return Err(Error::Timeout);
                }
                self.answer.recv().unwrap_or(Err(Error::Closed))
            }
            Err(RecvTimeoutError::Disconnected) => Err(Error::Closed),
        }
    }
}

impl<T> Drop for Pending<T> {
    fn drop(&mut self) {
        if let Some(forget) = self.forget.take() {
            forget();
        }
    }
}

/// Handle answering one request of the peer's, made by the multiplexer for
/// its handler and answering once, with a reply or a failure. An answer the
/// wire cannot carry leaves it unanswered, so a handler may try a smaller
/// one. Dropped unanswered, it fails the request for the peer, so a handler
/// that panics, forgets or gives up does not leave the peer waiting. It is
/// bound to the session the request arrived in and refused once that ended.
pub struct Responder<Out: Envelope> {
    switchboard: Weak<dyn Sender>, // Answers through it, a failed write tearing the session down
    emitter: Emitter<Writer>,      // Handle of the session the request arrived in
    pub(super) id: u64,            // Id of the request, echoed by the answer
    answered: bool,                // Whether an answer went out
    envelope: PhantomData<fn() -> Out>, // Envelope the answer travels in
}

impl<Out: Envelope> Responder<Out> {
    /// Creates the responder of a request, answering through the switchboard
    /// into the session the request arrived in.
    pub(super) fn new(switchboard: Weak<dyn Sender>, emitter: Emitter<Writer>, id: u64) -> Self {
        Self {
            switchboard,
            emitter,
            id,
            answered: false,
            envelope: PhantomData,
        }
    }

    /// Answers the request with the content.
    pub fn reply(&mut self, content: Out::Content) -> Result<(), Error> {
        self.send(Out::response(self.id, Some(content), None))
    }

    /// Fails the request with the error.
    pub fn fail(&mut self, err: protocol::Error) -> Result<(), Error> {
        self.send(Out::response(self.id, None, Some(err)))
    }

    /// Sends an answer through the switchboard, into the session the request
    /// arrived in, so a failed write ends that session the side's way rather
    /// than going unnoticed. An answer the wire refuses before sealing never
    /// reached the peer, which leaves the request unanswered for a smaller
    /// answer to take, and the drop fails it for the peer if none comes. A
    /// refusal once the multiplexer no longer takes calls needs no session
    /// touched, and answering twice is the handler's bug, the second one
    /// dropped rather than sent.
    fn send(&mut self, answer: Out) -> Result<(), Error> {
        if self.answered {
            warn!("dropping a second answer to request {}", self.id);
            return Ok(());
        }
        let message = answer.encode_to_vec();
        let result = match self.switchboard.upgrade() {
            Some(switchboard) => switchboard.send(&self.emitter, &message),
            None => Err(Error::Closed),
        };
        self.answered = !matches!(result, Err(Error::TooLarge(_)));
        result
    }
}

impl<Out: Envelope> Drop for Responder<Out> {
    fn drop(&mut self) {
        if !self.answered {
            let failure = protocol::Error {
                code: 0,
                msg: "request left unanswered".into(),
            };
            if let Err(err) = self.fail(failure) {
                warn!("failed to fail an unanswered request: {}", err);
            }
        }
    }
}

/// Multiplexer over one session, see the module docs. `Client` and `Server`
/// are its two instantiations, one per side of the wire.
pub struct Mux<Out: Envelope, In: Envelope> {
    switchboard: Arc<Switchboard<Out, In>>, // Shared with the reader and the worker
}

impl<Out: Envelope, In: Envelope> Mux<Out, In> {
    /// Starts multiplexing over a mock transport, for the scenario tests and
    /// the fuzzers to drive either side without a wire under it. Not part of
    /// the API.
    #[cfg(any(test, feature = "fuzz"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(super) fn mocked(side: Side, source: impl Source, closer: Closer) -> Self {
        Self {
            switchboard: Switchboard::start(side, source, closer),
        }
    }

    /// Callers parked on the window, see the switchboard's. Not part of the
    /// API.
    #[cfg(any(test, feature = "fuzz"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(super) fn waiting(&self) -> usize {
        self.switchboard.waiting()
    }

    /// Sends a request, returning its answer to wait on once the frame is
    /// written. Waits first if the window of requests in flight is full, and
    /// refuses if the multiplexer is closed, the session ended or the message
    /// is too large for the wire.
    pub fn request(&self, content: Out::Content) -> Result<Pending<In::Content>, Error> {
        let id = self.switchboard.next_id();
        let message = Out::request(id, content).encode_to_vec();
        let (tx, rx) = mpsc::sync_channel(1);
        self.switchboard.request(id, &message, tx)?;
        let switchboard = self.switchboard.clone();
        Ok(Pending {
            answer: rx,
            forget: Some(Box::new(move || switchboard.forget(id))),
        })
    }

    /// Registers the handler of the peer's requests, replacing the previous
    /// one. It runs on the worker thread in arrival order and answers through
    /// the responder, from the worker or from a thread it hands it to. Without
    /// a handler every request is refused. It must not wait for the worker and
    /// must not replace the handler itself.
    pub fn on_request(&self, handler: impl FnMut(In::Content, Responder<Out>) + Send + 'static) {
        self.switchboard.on_request(Box::new(handler));
    }

    /// Registers the handler told each time a session ends short of a close,
    /// with the reason, an unplug, the peer dropping the session, a failed
    /// write, the peer overrunning its window or sending a malformed message.
    /// On a client that is at most once, the multiplexer ending with its
    /// session. On a server every client's session ends this way, the next one
    /// served after. The handler must not register a handler itself.
    pub fn on_disconnect(&self, handler: impl FnMut(Error) + Send + 'static) {
        self.switchboard.on_disconnect(Box::new(handler));
    }

    /// Ends the multiplexer, failing every pending request as closed, refusing
    /// new calls and ending the transport, so the reader thread winds down and
    /// drops the client with it. Dropping the multiplexer does the same.
    pub fn close(&self) {
        self.switchboard.close();
    }
}

impl<Out: Envelope, In: Envelope> Drop for Mux<Out, In> {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(all(test, unix))]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::protocol::{ark_to_host, host_to_ark};
    use crate::testing;
    use crate::transport::Attestation;
    use crate::transport::mock::self_attestation;
    use darkbio_crypto::xdsa;
    use prost::Message;
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread::{self, JoinHandle};
    use std::time::Instant;

    /// Transport server of a peer, over a socket.
    type PeerServer = transport::Server<Reader, Writer, Attestation>;

    /// Script of a peer, told every message of the client and answering as it
    /// pleases through the server, saying whether to keep serving.
    type Script = Box<dyn FnMut(&mut PeerServer, HostToArk) -> bool + Send>;

    /// Starts a peer, a real transport server run by the script on its own
    /// thread over a socket pair, and a client multiplexer talking to it with
    /// the handshake done, its closer shutting the socket down.
    fn connect(mut script: Script) -> (Client, JoinHandle<()>) {
        let (host_sock, ark_sock) = UnixStream::pair().unwrap();
        let signer = xdsa::SecretKey::generate();
        let identity = signer.public_key();
        let attestation = self_attestation(&signer);

        let ark_reader: Reader = Box::new(ark_sock.try_clone().unwrap());
        let ark_writer: Writer = Box::new(ark_sock);
        let peer = thread::spawn(move || {
            let mut server = PeerServer::new(ark_reader, ark_writer, signer, attestation);
            while let Ok(message) = server.next_message() {
                let message = HostToArk::decode(&message[..]).unwrap();
                if !script(&mut server, message) {
                    break;
                }
            }
        });

        let closing = host_sock.try_clone().unwrap();
        let host_reader: Reader = Box::new(host_sock.try_clone().unwrap());
        let host_writer: Writer = Box::new(host_sock);
        let mut client = transport::Client::new(host_reader, host_writer);
        client.handshake(&identity).unwrap();
        let closer = Box::new(move || {
            let _ = closing.shutdown(Shutdown::Both);
        });
        (Client::new(client, closer), peer)
    }

    /// A request payload.
    fn ping(bytes: &[u8]) -> host_to_ark::Content {
        host_to_ark::Content::Develop(bytes.to_vec())
    }

    /// A response payload.
    fn pong(bytes: &[u8]) -> ark_to_host::Content {
        ark_to_host::Content::Develop(bytes.to_vec())
    }

    /// The bytes of a request payload, none for anything else.
    fn pinged(message: HostToArk) -> (u64, Option<protocol::Error>, Option<Vec<u8>>) {
        let (id, err, content) = message.into_parts();
        let bytes = match content {
            Some(host_to_ark::Content::Develop(bytes)) => Some(bytes),
            _ => None,
        };
        (id, err, bytes)
    }

    /// Sends an answer of the peer's.
    fn answer(server: &mut PeerServer, envelope: ArkToHost) {
        server.send_message(&envelope.encode_to_vec()).unwrap();
    }

    /// A peer echoing every request's payload back as its response.
    fn echo() -> Script {
        Box::new(|server, message| {
            if let (id, _, Some(bytes)) = pinged(message) {
                answer(server, ArkToHost::response(id, Some(pong(&bytes)), None));
            }
            true
        })
    }

    /// Waits for the answer within a second.
    fn wait<T>(pending: Pending<T>) -> Result<T, Error> {
        pending.wait(Duration::from_secs(1))
    }

    /// Transport client of a peer, over a socket.
    type PeerClient = transport::Client<Reader, Writer>;

    /// Script of a peer, driving its transport client as it pleases with the
    /// handshake done, the server's identity at hand for handshakes of its
    /// own.
    type ClientScript = Box<dyn FnOnce(&mut PeerClient, &xdsa::PublicKey) + Send>;

    /// Starts a peer, a real transport client run by the script on its own
    /// thread over a socket pair, and a server multiplexer serving it, its
    /// closer shutting the socket down.
    fn serve(script: ClientScript) -> (Server, JoinHandle<()>) {
        let (host_sock, ark_sock) = UnixStream::pair().unwrap();
        let signer = xdsa::SecretKey::generate();
        let identity = signer.public_key();
        let attestation = self_attestation(&signer);

        let host_reader: Reader = Box::new(host_sock.try_clone().unwrap());
        let host_writer: Writer = Box::new(host_sock);
        let peer = thread::spawn(move || {
            let mut client = PeerClient::new(host_reader, host_writer);
            client.handshake(&identity).unwrap();
            script(&mut client, &identity);
        });

        let closing = ark_sock.try_clone().unwrap();
        let ark_reader: Reader = Box::new(ark_sock.try_clone().unwrap());
        let ark_writer: Writer = Box::new(ark_sock);
        let server = transport::Server::new(ark_reader, ark_writer, signer, attestation);
        let closer = Box::new(move || {
            let _ = closing.shutdown(Shutdown::Both);
        });
        (Server::new(server, closer), peer)
    }

    /// Sends a message of the client's.
    fn say(client: &mut PeerClient, envelope: HostToArk) {
        client.send_message(&envelope.encode_to_vec()).unwrap();
    }

    /// Reads the next message of the server's, taken apart.
    fn hear(
        client: &mut PeerClient,
    ) -> (u64, Option<protocol::Error>, Option<ark_to_host::Content>) {
        let message = client.next_message().unwrap();
        ArkToHost::decode(&message[..]).unwrap().into_parts()
    }

    /// A handler echoing every request's payload back as its reply and
    /// reporting the payload served.
    fn echoing(
        served: mpsc::Sender<Vec<u8>>,
    ) -> impl FnMut(host_to_ark::Content, Responder<ArkToHost>) + Send + 'static {
        move |content, mut responder| match content {
            host_to_ark::Content::Develop(bytes) => {
                responder.reply(pong(&bytes)).unwrap();
                served.send(bytes).unwrap();
            }
            other => panic!("{other:?}"),
        }
    }

    // Tests requests from many threads at once, and several outstanding from
    // one thread, every answer reaching the request it belongs to.
    #[test]
    fn test_requests_at_once() {
        testing::init_tracing();

        let (mux, peer) = connect(echo());
        let mux = Arc::new(mux);

        let threads: Vec<_> = (0..8)
            .map(|thread| {
                let mux = mux.clone();
                thread::spawn(move || {
                    for i in 0..25u64 {
                        let payload = (thread * 100 + i).to_be_bytes();
                        let answer = wait(mux.request(ping(&payload)).unwrap()).unwrap();
                        assert_eq!(answer, pong(&payload));
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }

        // Pipelined, five in flight before the first is waited for
        let pendings: Vec<_> = (0..5u64)
            .map(|i| mux.request(ping(&i.to_be_bytes())).unwrap())
            .collect();
        for (i, pending) in pendings.into_iter().enumerate() {
            assert_eq!(wait(pending).unwrap(), pong(&(i as u64).to_be_bytes()));
        }

        drop(mux);
        peer.join().unwrap();
    }

    // Tests the peer's requests, answered through the responder, refused
    // without a handler, and failed for the peer when a handler lets the
    // responder go.
    #[test]
    fn test_on_request() {
        testing::init_tracing();

        // A peer asking a question of its own when told, reporting what it
        // gets back, and echoing everything else
        let (asked_tx, asked) = mpsc::channel();
        let (mux, peer) = connect(Box::new(move |server, message| {
            let (id, err, bytes) = pinged(message);
            match bytes {
                Some(bytes) if bytes == b"ask" => {
                    answer(server, ArkToHost::request(2, pong(b"question")));
                    answer(server, ArkToHost::response(id, Some(pong(b"asked")), None));
                }
                Some(bytes) if id % 2 == 1 => {
                    answer(server, ArkToHost::response(id, Some(pong(&bytes)), None));
                }
                bytes => asked_tx.send((id, err, bytes)).unwrap(),
            }
            true
        }));

        // Without a handler the request is refused
        wait(mux.request(ping(b"ask")).unwrap()).unwrap();
        let (id, err, bytes) = asked.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(
            (id, err.map(|err| err.msg), bytes),
            (2, Some("request not served".into()), None)
        );

        // A handler answers it, on the worker thread
        let (served_tx, served) = mpsc::channel();
        mux.on_request(move |content, mut responder: Responder<HostToArk>| {
            served_tx.send(thread::current().id()).unwrap();
            assert_eq!(content, pong(b"question"));
            responder.reply(ping(b"answer")).unwrap();
        });
        wait(mux.request(ping(b"ask")).unwrap()).unwrap();
        assert_ne!(
            served.recv_timeout(Duration::from_secs(1)).unwrap(),
            thread::current().id()
        );
        let (id, err, bytes) = asked.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!((id, err, bytes), (2, None, Some(b"answer".to_vec())));

        // A handler letting the responder go fails the request for the peer
        mux.on_request(|_, responder: Responder<HostToArk>| drop(responder));
        wait(mux.request(ping(b"ask")).unwrap()).unwrap();
        let (id, err, bytes) = asked.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(
            (id, err.map(|err| err.msg), bytes),
            (2, Some("request left unanswered".into()), None)
        );

        // So does one panicking with it
        mux.on_request(|_, _: Responder<HostToArk>| panic!("injected panic"));
        wait(mux.request(ping(b"ask")).unwrap()).unwrap();
        let (id, err, bytes) = asked.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(
            (id, err.map(|err| err.msg), bytes),
            (2, Some("request left unanswered".into()), None)
        );

        drop(mux);
        peer.join().unwrap();
    }

    // Tests the window, requests blocking once the bytes in flight fill it
    // and going on as answers arrive.
    #[test]
    fn test_window() {
        testing::init_tracing();

        // A peer holding every request, handing its emitter out so the test
        // answers them when it pleases
        let (held_tx, held) = mpsc::channel();
        let (emitter_tx, emitter_rx) = mpsc::channel();
        let mut emitter_tx = Some(emitter_tx);
        let (mux, peer) = connect(Box::new(move |server, message| {
            if let Some(tx) = emitter_tx.take() {
                tx.send(server.emitter()).unwrap();
            }
            held_tx.send(pinged(message).0).unwrap();
            true
        }));
        let mux = Arc::new(mux);

        // Requests of a megabyte each, fifteen fitting the window and the
        // sixteenth waiting for room
        let payload = vec![0x42; 1024 * 1024];
        let issued = Arc::new(AtomicUsize::new(0));
        let requester = {
            let mux = mux.clone();
            let issued = issued.clone();
            let payload = payload.clone();
            thread::spawn(move || {
                let pendings: Vec<_> = (0..16)
                    .map(|_| {
                        let pending = mux.request(ping(&payload)).unwrap();
                        issued.fetch_add(1, Ordering::SeqCst);
                        pending
                    })
                    .collect();
                for pending in pendings {
                    wait(pending).unwrap();
                }
            })
        };
        let emitter = emitter_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let mut ids: Vec<u64> = (0..15)
            .map(|_| held.recv_timeout(Duration::from_secs(5)).unwrap())
            .collect();
        thread::sleep(Duration::from_millis(100));
        assert_eq!(issued.load(Ordering::SeqCst), 15);

        // Answering one makes room for the sixteenth
        let reply = |id: u64| ArkToHost::response(id, Some(pong(b"ok")), None).encode_to_vec();
        emitter.send_message(&reply(ids.remove(0))).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while issued.load(Ordering::SeqCst) < 16 {
            assert!(Instant::now() < deadline, "sixteenth request never issued");
            thread::sleep(Duration::from_millis(10));
        }
        ids.push(held.recv_timeout(Duration::from_secs(5)).unwrap());
        for id in ids {
            emitter.send_message(&reply(id)).unwrap();
        }
        requester.join().unwrap();

        drop(mux);
        peer.join().unwrap();
    }

    // Tests that a forgotten request keeps its place in the window until its
    // answer arrives, dropping the pendings making no room for more.
    #[test]
    fn test_forgotten() {
        testing::init_tracing();

        // A peer holding every request, handing its emitter out so the test
        // answers them when it pleases
        let (held_tx, held) = mpsc::channel();
        let (emitter_tx, emitter_rx) = mpsc::channel();
        let mut emitter_tx = Some(emitter_tx);
        let (mux, peer) = connect(Box::new(move |server, message| {
            if let Some(tx) = emitter_tx.take() {
                tx.send(server.emitter()).unwrap();
            }
            held_tx.send(pinged(message).0).unwrap();
            true
        }));
        let mux = Arc::new(mux);

        // Requests of a megabyte each with their pendings dropped on the
        // spot, fifteen filling the window and the sixteenth waiting for
        // room all the same
        let payload = vec![0x42; 1024 * 1024];
        let issued = Arc::new(AtomicUsize::new(0));
        let requester = {
            let mux = mux.clone();
            let issued = issued.clone();
            let payload = payload.clone();
            thread::spawn(move || {
                for _ in 0..15 {
                    drop(mux.request(ping(&payload)).unwrap());
                    issued.fetch_add(1, Ordering::SeqCst);
                }
                let pending = mux.request(ping(&payload)).unwrap();
                issued.fetch_add(1, Ordering::SeqCst);
                wait(pending).unwrap();
            })
        };
        let emitter = emitter_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let mut ids: Vec<u64> = (0..15)
            .map(|_| held.recv_timeout(Duration::from_secs(5)).unwrap())
            .collect();
        thread::sleep(Duration::from_millis(100));
        assert_eq!(issued.load(Ordering::SeqCst), 15);

        // Answering a forgotten one makes room for the sixteenth
        let reply = |id: u64| ArkToHost::response(id, Some(pong(b"ok")), None).encode_to_vec();
        emitter.send_message(&reply(ids.remove(0))).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while issued.load(Ordering::SeqCst) < 16 {
            assert!(Instant::now() < deadline, "sixteenth request never issued");
            thread::sleep(Duration::from_millis(10));
        }
        ids.push(held.recv_timeout(Duration::from_secs(5)).unwrap());
        for id in ids {
            emitter.send_message(&reply(id)).unwrap();
        }
        requester.join().unwrap();

        drop(mux);
        peer.join().unwrap();
    }

    // Tests a client sending a malformed message over a request of the
    // server's, the session dropped on it with the request failing as
    // malformed and the disconnect handler told, and the client served again
    // once it reconnects.
    #[test]
    fn test_server_malformed() {
        testing::init_tracing();

        // A client asking once told to, reading the server's question and
        // answering with a byte that is no envelope, reading the reset that
        // gets it, then reconnecting and asking again
        let (go_tx, go) = mpsc::channel();
        let (answered_tx, answered) = mpsc::channel();
        let (mux, peer) = serve(Box::new(move |client, identity| {
            go.recv().unwrap();
            say(client, HostToArk::request(1, ping(b"first")));
            hear(client);
            assert_eq!(hear(client), (2, None, Some(pong(b"question"))));
            client.send_message(&[0x07]).unwrap();
            let result = client.next_message();
            assert!(
                matches!(result, Err(transport::Error::SessionReset)),
                "{result:?}"
            );

            client.handshake(identity).unwrap();
            say(client, HostToArk::request(1, ping(b"second")));
            answered_tx.send(hear(client)).unwrap();
        }));
        let (ended_tx, ended) = mpsc::channel();
        mux.on_disconnect(move |reason| ended_tx.send(reason).unwrap());
        let (served_tx, served) = mpsc::channel();
        mux.on_request(echoing(served_tx));
        go_tx.send(()).unwrap();

        assert_eq!(
            served.recv_timeout(Duration::from_secs(5)).unwrap(),
            b"first"
        );
        let pending = mux.request(pong(b"question")).unwrap();
        let result = pending.wait(Duration::from_secs(5));
        assert!(matches!(result, Err(Error::Malformed)), "{result:?}");
        let reason = ended.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(matches!(reason, Error::Malformed), "{reason:?}");
        assert_eq!(
            served.recv_timeout(Duration::from_secs(5)).unwrap(),
            b"second"
        );
        let (id, err, content) = answered.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!((id, err, content), (1, None, Some(pong(b"second"))));

        drop(mux);
        peer.join().unwrap();
    }

    // Tests a client reconnecting over a request of the server's and saying
    // nothing after, the request failing as reset and the disconnect handler
    // told on the handshake rather than on the client's next message.
    #[test]
    fn test_server_silent_reconnect() {
        testing::init_tracing();

        // A client asking once told to, reading the server's question,
        // reconnecting instead of answering and then waiting to be told
        // before asking again
        let (go_tx, go) = mpsc::channel();
        let (answered_tx, answered) = mpsc::channel();
        let (mux, peer) = serve(Box::new(move |client, identity| {
            go.recv().unwrap();
            say(client, HostToArk::request(1, ping(b"first")));
            hear(client);
            assert_eq!(hear(client), (2, None, Some(pong(b"question"))));
            client.handshake(identity).unwrap();
            go.recv().unwrap();
            say(client, HostToArk::request(1, ping(b"second")));
            answered_tx.send(hear(client)).unwrap();
        }));
        let (ended_tx, ended) = mpsc::channel();
        mux.on_disconnect(move |reason| ended_tx.send(reason).unwrap());
        let (served_tx, served) = mpsc::channel();
        mux.on_request(echoing(served_tx));
        go_tx.send(()).unwrap();

        // The question fails and the handler is told while the client is
        // still silent in its new session
        assert_eq!(
            served.recv_timeout(Duration::from_secs(5)).unwrap(),
            b"first"
        );
        let pending = mux.request(pong(b"question")).unwrap();
        let result = pending.wait(Duration::from_secs(5));
        assert!(
            matches!(&result, Err(Error::Disconnected(reason)) if matches!(**reason, transport::Error::SessionReset)),
            "{result:?}"
        );
        let reason = ended.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(
            matches!(&reason, Error::Disconnected(reason) if matches!(**reason, transport::Error::SessionReset)),
            "{reason:?}"
        );
        go_tx.send(()).unwrap();
        assert_eq!(
            served.recv_timeout(Duration::from_secs(5)).unwrap(),
            b"second"
        );
        let (id, err, content) = answered.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!((id, err, content), (1, None, Some(pong(b"second"))));

        drop(mux);
        peer.join().unwrap();
    }
}
