// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Handles bound to individual transport sessions. Neither an idle sender nor
//! any of its clones keeps the session or the byte stream alive.

use super::outbound::Outbound;
use super::session::SessionState;
use super::{Error, sealing};
use std::io::Write;
use std::sync::Weak;

/// Cloneable handle for sending messages into a session from any thread.
/// Delivered by [`Client::connect`](super::Client::connect) or a server's
/// [`Event::Connected`](super::Event::Connected) event.
///
/// Sends share one encryption sequence and are written in that order, each
/// waiting for its own frame and getting its own result. Each handle belongs
/// permanently to the session that issued it. Ending that session through a
/// failure, disconnect, reconnect, or dropping the client/server invalidates
/// every handle for it. Another session supplies a new sender; old handles
/// cannot send messages to its peer.
///
/// The client/server retains the session and stream. Senders hold only weak
/// references, so keeping a handle or cloning it does not extend either lifetime.
/// A send temporarily retains both while it runs, but still observes session
/// termination. Dropping a sender does not end the session.
#[derive(Debug)]
pub struct Sender<W: Write> {
    outbound: Weak<Outbound<W>>, // Writer retained by the client/server and active sends
    session: Weak<SessionState>, // The particular session that issued this handle
}

impl<W: Write> Sender<W> {
    /// Stores weak references to the writer and the session bound to it. Each
    /// send upgrades them for its duration; this handle alone retains neither.
    pub(super) fn new(outbound: Weak<Outbound<W>>, session: Weak<SessionState>) -> Self {
        Self { outbound, session }
    }

    /// Seals the message and writes and flushes its complete frame. Concurrent
    /// sends take turns in encryption order, each waiting for its own write.
    /// An oversized message is refused without advancing encryption or ending
    /// the session. Encryption or write failure marks both directions ended:
    /// later sends and decryption attempts are refused. This does not wake a
    /// blocked receive; it observes the failure when reading progresses.
    ///
    /// Returns [`Error::Terminated`] if the outgoing transport has been released,
    /// or [`Error::EncryptionFailed`] if this handle's session has ended or been
    /// released. Queued sends check termination again after acquiring the writer
    /// lock. A write already admitted may complete during session termination.
    /// Stream closure is observed through I/O failure; an overlapping write may
    /// still succeed.
    pub fn send(&self, message: &[u8]) -> Result<(), Error> {
        // Retain the writer and session state for this operation. Ending the
        // session still marks this state ended even while we hold a reference.
        let outbound = self.outbound.upgrade().ok_or(Error::Terminated)?;
        let session = self
            .session
            .upgrade()
            .ok_or_else(|| Error::EncryptionFailed("session ended".into()))?;

        // A panic can leave encryption or wire order uncertain, so unwinding
        // must invalidate both directions before another operation uses them.
        let _end_on_panic = session.end_on_panic();

        // Attempt to seal the message
        let mut sealer = session.lock()?;

        let packet = match sealing::seal(&mut sealer, message) {
            Err(err @ Error::EncryptionFailed(_)) => {
                // Encryption failed, no recovery here, nuke the session
                session.end();
                drop(sealer);

                // If we're a server, notify the client that they're gone
                outbound.notify_session_ended(&session);
                return Err(err);
            }
            Err(err) => return Err(err),
            Ok(packet) => packet,
        };
        // Acquire the writer before releasing the encryption context, keeping
        // wire order equal to sealing order while the next send seals during I/O.
        let mut writer = outbound.lock();
        drop(sealer);
        writer.send(&session, &packet)
    }
}

impl<W: Write> Clone for Sender<W> {
    fn clone(&self) -> Self {
        Self::new(self.outbound.clone(), self.session.clone())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::testing;
    use crate::transport::framing::FrameReader;
    use crate::transport::mock::payload;
    use crate::transport::outbound::Side;
    use crate::transport::{Closer, session::Session};
    use darkbio_crypto::xhpke;
    use std::io;
    use std::panic::{self, AssertUnwindSafe};
    use std::sync::{Arc, Mutex, mpsc};
    use std::thread;
    use std::time::Duration;

    /// Creates a session and binds its sender to the test writer.
    fn connect<W: Write>(
        outbound: &Arc<Outbound<W>>,
        sender: xhpke::Sender,
        receiver: xhpke::Receiver,
    ) -> (Session, Sender<W>) {
        let session = Session::new(sender, receiver);
        let sender = outbound.bind(&session);
        (session, sender)
    }

    /// A pair of contexts standing in for an established session.
    fn contexts() -> (xhpke::Sender, xhpke::Receiver) {
        let secret = xhpke::SecretKey::generate();
        let (sender, encap) = secret.public_key().new_sender(b"test").unwrap();
        let receiver = secret.new_receiver(&encap, b"test").unwrap();
        (sender, receiver)
    }

    /// Writer collecting everything written into a shared buffer.
    #[derive(Clone, Default)]
    struct Collector(Arc<Mutex<Vec<u8>>>);

    impl Write for Collector {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Writer holding its first write until released, then failing it or
    /// panicking inside it, the ones after passing, and reporting its drop.
    struct Gate {
        entered: mpsc::Sender<()>,
        release: Option<mpsc::Receiver<()>>,
        dropped: mpsc::Sender<()>,
        panics: bool,
    }

    impl Gate {
        /// Creates the gate along with the channel telling that a write is
        /// held, the one releasing it and the one telling that the gate was
        /// dropped.
        fn new() -> (
            Self,
            mpsc::Receiver<()>,
            mpsc::Sender<()>,
            mpsc::Receiver<()>,
        ) {
            let (entered_tx, entered) = mpsc::channel();
            let (release, release_rx) = mpsc::channel();
            let (dropped_tx, dropped) = mpsc::channel();
            let gate = Self {
                entered: entered_tx,
                release: Some(release_rx),
                dropped: dropped_tx,
                panics: false,
            };
            (gate, entered, release, dropped)
        }
    }

    impl Write for Gate {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            match self.release.take() {
                Some(release) => {
                    let _ = self.entered.send(());
                    let _ = release.recv();
                    if self.panics {
                        panic!("injected panic");
                    }
                    Err(io::Error::other("gate closed"))
                }
                None => Ok(buf.len()),
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Drop for Gate {
        fn drop(&mut self) {
            let _ = self.dropped.send(());
        }
    }

    /// Writer panicking on its first write and collecting the ones after.
    struct Panicky {
        armed: bool,
        written: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for Panicky {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if std::mem::take(&mut self.armed) {
                panic!("injected panic");
            }
            self.written.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    // Tests that messages sent from many threads at once go out in the order
    // they were sealed, every one opening in sequence on the receiving side.
    #[test]
    fn test_send_order() {
        testing::init_tracing();

        let (sender, mut receiver) = contexts();
        let collector = Collector::default();
        let outbound = Arc::new(Outbound::new(
            collector.clone(),
            Side::Client,
            Closer::new(|| {}),
        ));
        let (_session, sender) = connect(&outbound, sender, contexts().1);

        let threads: Vec<_> = (0..8)
            .map(|thread| {
                let sender = sender.clone();
                thread::spawn(move || {
                    for i in 0..20 {
                        sender.send(&payload(thread * 100 + i)).unwrap();
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }

        // Every frame must open in the order written, or the sequence is off
        let written = collector.0.lock().unwrap().clone();
        let mut reader = FrameReader::new(&written[..], Closer::new(|| {}));
        let mut messages = Vec::new();
        loop {
            let packet = match reader.next_packet() {
                Err(Error::Terminated) => break,
                result => result.unwrap().unwrap(),
            };
            messages.push(sealing::open(&mut receiver, packet).unwrap());
        }
        messages.sort_unstable();
        let mut expected: Vec<Vec<u8>> = (0..8)
            .flat_map(|thread| (0..20).map(move |i| payload(thread * 100 + i)))
            .collect();
        expected.sort_unstable();
        assert_eq!(messages, expected);
    }

    // Tests that ending a session takes no writer or encryption lock. A send is
    // held after sealing while the owner ends, then races a replacement session
    // for the writer. Only the replacement's frame may reach the byte stream.
    #[test]
    fn test_end_with_queued_send() {
        testing::init_tracing();

        let collector = Collector::default();
        let outbound = Arc::new(Outbound::new(
            collector.clone(),
            Side::Client,
            Closer::new(|| {}),
        ));
        let (crypto, _) = contexts();
        let (session, sender) = connect(&outbound, crypto, contexts().1);
        let writer = outbound.lock();
        let sending = thread::spawn(move || sender.send(&payload(1)));

        session.state.wait_sealing();
        let (ended_tx, ended) = mpsc::channel();
        let ending = thread::spawn(move || {
            session.end();
            ended_tx.send(()).unwrap();
        });
        ended.recv_timeout(Duration::from_secs(5)).unwrap();
        ending.join().unwrap();
        drop(writer);

        let (crypto, mut peer) = contexts();
        let (_replacement, fresh) = connect(&outbound, crypto, contexts().1);
        fresh.send(&payload(2)).unwrap();
        assert!(matches!(
            sending.join().unwrap(),
            Err(Error::EncryptionFailed(_))
        ));

        let bytes = collector.0.lock().unwrap().clone();
        let mut reader = FrameReader::new(&bytes[..], Closer::new(|| {}));
        let packet = reader.next_packet().unwrap().unwrap();
        assert_eq!(sealing::open(&mut peer, packet).unwrap(), payload(2));
        assert!(matches!(reader.next_packet(), Err(Error::Terminated)));
    }

    // Tests that a failed write is reported to the sender it failed, that a
    // message sealed behind it is refused rather than written, and that every
    // later one is refused before sealing.
    #[test]
    fn test_send_failure_attribution() {
        testing::init_tracing();

        let (gate, entered, release, _) = Gate::new();
        let (sender, _) = contexts();
        let outbound = Arc::new(Outbound::new(gate, Side::Client, Closer::new(|| {})));
        let (session, sender) = connect(&outbound, sender, contexts().1);

        // The first sender blocks inside its write, the second seals behind it
        // and waits for the write lock while retaining the encryption lock.
        let first = {
            let sender = sender.clone();
            thread::spawn(move || sender.send(&payload(1)))
        };
        entered.recv_timeout(Duration::from_secs(5)).unwrap();
        let second = {
            let sender = sender.clone();
            thread::spawn(move || sender.send(&payload(2)))
        };
        session.state.wait_sealing();

        // The write fails, taking the session with it
        release.send(()).unwrap();
        let result = first.join().unwrap();
        assert!(matches!(result, Err(Error::SendFailed(_))), "{result:?}");
        let result = second.join().unwrap();
        assert!(
            matches!(result, Err(Error::EncryptionFailed(_))),
            "{result:?}"
        );
        let result = sender.send(&payload(3));
        assert!(
            matches!(result, Err(Error::EncryptionFailed(_))),
            "{result:?}"
        );
        assert!(session.ended());
    }

    // Tests that senders stay bound to the session that issued them, that ending
    // or dropping it refuses further sends, and that stream closure is observed
    // through I/O while dropping the stream owner yields Terminated.
    #[test]
    fn test_send_refusals() {
        testing::init_tracing();

        let outbound = Arc::new(Outbound::new(Vec::new(), Side::Client, Closer::new(|| {})));
        let (crypto, _) = contexts();
        let (first_session, first) = connect(&outbound, crypto, contexts().1);
        first.send(&payload(1)).unwrap();

        first_session.end();
        assert!(matches!(
            first.send(&payload(2)),
            Err(Error::EncryptionFailed(_))
        ));

        let (crypto, _) = contexts();
        let (second_session, second) = connect(&outbound, crypto, contexts().1);
        assert!(matches!(
            first.send(&payload(3)),
            Err(Error::EncryptionFailed(_))
        ));
        drop(first_session);
        assert!(matches!(
            first.send(&payload(4)),
            Err(Error::EncryptionFailed(_))
        ));
        second.send(&payload(5)).unwrap();

        // Closure leaves logical termination to the operation's I/O result.
        outbound.close();
        assert!(!second_session.ended());
        let result = second.send(&payload(6));
        assert!(
            matches!(&result, Err(Error::SendFailed(err)) if err.kind() == io::ErrorKind::NotConnected),
            "{result:?}"
        );
        assert!(second_session.ended());
        drop(outbound);
        assert!(matches!(second.send(&payload(7)), Err(Error::Terminated)));
    }

    // Tests that closing cancels a blocked write without taking the send locks,
    // including when a second sender holds the sealer while waiting for the
    // writer. Both senders finish and a surviving sender refuses new sends.
    #[test]
    fn test_close_with_stuck_sends() {
        testing::init_tracing();

        let (gate, entered, release, dropped) = Gate::new();
        let (sender, _) = contexts();
        let closer = Closer::new(move || {
            let _ = release.send(());
        });
        let outbound = Arc::new(Outbound::new(gate, Side::Client, closer));
        let (session, sender) = connect(&outbound, sender, contexts().1);

        let first = {
            let sender = sender.clone();
            thread::spawn(move || sender.send(&payload(1)))
        };
        entered.recv_timeout(Duration::from_secs(5)).unwrap();
        let second = {
            let sender = sender.clone();
            thread::spawn(move || sender.send(&payload(2)))
        };
        session.state.wait_sealing();

        let (closed_tx, closed) = mpsc::channel();
        let owner = {
            let outbound = outbound.clone();
            thread::spawn(move || {
                outbound.close();
                closed_tx.send(()).unwrap();
            })
        };
        closed.recv_timeout(Duration::from_secs(5)).unwrap();
        owner.join().unwrap();
        assert!(matches!(first.join().unwrap(), Err(Error::SendFailed(_))));
        assert!(matches!(
            second.join().unwrap(),
            Err(Error::EncryptionFailed(_))
        ));
        assert!(session.ended());
        assert!(matches!(
            sender.send(&payload(3)),
            Err(Error::EncryptionFailed(_))
        ));
        drop(outbound);
        dropped.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(matches!(sender.send(&payload(4)), Err(Error::Terminated)));
    }

    // Tests that an I/O panic releases its admission charge, allowing shutdown
    // to complete and the last active send to release the transport writer.
    #[test]
    fn test_close_with_panicking_send() {
        testing::init_tracing();

        let (mut gate, entered, release, dropped) = Gate::new();
        gate.panics = true;
        let (sender, _) = contexts();
        let closer = Closer::new(move || {
            let _ = release.send(());
        });
        let outbound = Arc::new(Outbound::new(gate, Side::Client, closer));
        let (_session, sender) = connect(&outbound, sender, contexts().1);

        let sending = thread::spawn(move || {
            panic::catch_unwind(AssertUnwindSafe(|| sender.send(&payload(1))))
        });
        entered.recv_timeout(Duration::from_secs(5)).unwrap();
        outbound.close();
        assert!(sending.join().unwrap().is_err());
        drop(outbound);
        dropped.recv_timeout(Duration::from_secs(5)).unwrap();
    }

    // Tests that a transport panicking inside a write ends the session, the
    // sealed message never having gone out, while the framer stays usable for
    // the next session.
    #[test]
    fn test_writer_panic() {
        testing::init_tracing();

        let written = Arc::new(Mutex::new(Vec::new()));
        let (sender, _) = contexts();
        let outbound = Arc::new(Outbound::new(
            Panicky {
                armed: true,
                written: written.clone(),
            },
            Side::Client,
            Closer::new(|| {}),
        ));
        let (session, sender) = connect(&outbound, sender, contexts().1);

        let result = panic::catch_unwind(AssertUnwindSafe(|| sender.send(&payload(1))));
        assert!(result.is_err());

        // Unwinding ends the session immediately, before any operation retries.
        assert!(session.ended());
        let result = sender.send(&payload(2));
        assert!(
            matches!(result, Err(Error::EncryptionFailed(_))),
            "{result:?}"
        );
        assert!(session.ended());
        assert!(written.lock().unwrap().is_empty());

        // The next session sends, the framer having kept its buffer and first
        // terminating whatever the panic left behind
        let (sender, mut receiver) = contexts();
        let (_session, sender) = connect(&outbound, sender, contexts().1);
        sender.send(&payload(3)).unwrap();

        let written = written.lock().unwrap().clone();
        let mut reader = FrameReader::new(&written[..], Closer::new(|| {}));
        assert!(reader.next_packet().unwrap().is_none());
        let packet = reader.next_packet().unwrap().unwrap();
        let opened = sealing::open(&mut receiver, packet).unwrap();
        assert_eq!(opened, payload(3));
    }
}
