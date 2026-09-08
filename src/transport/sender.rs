// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Handles bound to individual transport sessions. Neither an idle sender nor
//! any of its clones keeps the session or the byte stream alive.

use super::Write;
use super::outbound::Outbound;
use super::{Error, sealing};
use darkbio_crypto::xhpke;
use std::sync::{Mutex, Weak};

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
    sealer: Weak<Mutex<xhpke::Sender>>, // Encryption context whose allocation identifies the session
}

impl<W: Write> Sender<W> {
    /// Stores weak references to the writer and encryption allocation. Each
    /// send retains them for its duration; an idle handle owns neither.
    pub(super) fn new(outbound: Weak<Outbound<W>>, sealer: Weak<Mutex<xhpke::Sender>>) -> Self {
        Self { outbound, sealer }
    }

    /// Seals a message and writes and flushes its complete frame. Concurrent
    /// sends retain encryption order on the wire while the next message can
    /// seal during the preceding write. An oversized message is refused without
    /// advancing encryption or ending the session. Once the writer is acquired,
    /// all partial writes, resynchronization and flush share the stream's write
    /// timeout. Encryption and waiting for the writer are outside that budget.
    ///
    /// A write failure ends the binding before returning: subsequent sends and
    /// receive completions are refused. A timeout returns [`Error::SendFailed`]
    /// containing [`std::io::ErrorKind::TimedOut`] and leaves the byte stream
    /// reusable. Server failure notification uses only the failed frame's
    /// remaining budget and is skipped after timeout. This does not wake a
    /// blocked receive.
    /// Ending elsewhere waits for a write already holding the writer lock;
    /// queued sends can still seal but must match the binding before writing.
    ///
    /// Returns [`Error::Terminated`] if the outgoing transport was released, or
    /// [`Error::EncryptionFailed`] if the context was released or its binding
    /// ended. Stream closure is observed through I/O; an overlapping write may
    /// succeed. Unexpected encryption failures and poisoned locks panic, and
    /// transport reuse after a panic is unsupported.
    pub fn send(&self, message: &[u8]) -> Result<(), Error> {
        let outbound = self.outbound.upgrade().ok_or(Error::Terminated)?;
        let context = self
            .sealer
            .upgrade()
            .ok_or_else(|| Error::EncryptionFailed("session ended".into()))?;

        let mut sealer = context.lock().expect("encryption lock not poisoned");
        let packet = match sealing::seal(&mut sealer, message) {
            Ok(packet) => packet,
            Err(Error::PacketTooLarge(size)) => return outbound.refuse_oversized(&context, size),
            Err(err) => panic!("message encryption failed: {err}"),
        };
        // Acquire the writer before releasing encryption, keeping wire order
        // equal to sealing order while the next message seals during this I/O.
        let mut writer = outbound.lock();
        drop(sealer);
        writer.send(&context, &packet)
    }
}

impl<W: Write> Clone for Sender<W> {
    fn clone(&self) -> Self {
        Self::new(self.outbound.clone(), self.sealer.clone())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::testing;
    use crate::transport::Closer;
    use crate::transport::DEFAULT_WRITE_TIMEOUT;
    use crate::transport::framing::FrameReader;
    use crate::transport::mock::payload;
    use crate::transport::outbound::Side;
    use crate::transport::testing::Memory;
    use std::io;
    use std::panic::{self, AssertUnwindSafe};
    use std::sync::{Arc, TryLockError, mpsc};
    use std::thread;
    use std::time::{Duration, Instant};

    /// Retains a sending context as a client/server would and binds a sender to it.
    fn connect<W: Write>(
        outbound: &Arc<Outbound<W>>,
        sender: xhpke::Sender,
    ) -> (Arc<Mutex<xhpke::Sender>>, Sender<W>) {
        let sealer = Arc::new(Mutex::new(sender));
        let sender = outbound.bind(&sealer);
        (sealer, sender)
    }

    /// Waits until a sender acquires encryption while the writer is held by
    /// the test or an earlier send. No sleep determines the ordering.
    fn wait_sealing(sealer: &Mutex<xhpke::Sender>) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !matches!(sealer.try_lock(), Err(TryLockError::WouldBlock)) {
            assert!(
                Instant::now() < deadline,
                "sender did not acquire encryption context"
            );
            thread::yield_now();
        }
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
        fn set_write_deadline(&mut self, deadline: Instant) -> io::Result<()> {
            testing::remaining(deadline)?;
            Ok(())
        }
    }

    impl io::Write for Collector {
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
        deadline: Option<Instant>,
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
                deadline: None,
            };
            (gate, entered, release, dropped)
        }
    }

    impl Write for Gate {
        fn set_write_deadline(&mut self, deadline: Instant) -> io::Result<()> {
            self.deadline = Some(deadline);
            Ok(())
        }
    }

    impl io::Write for Gate {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let deadline = self.deadline.expect("write deadline installed");
            testing::remaining(deadline)?;
            match self.release.take() {
                Some(release) => {
                    let _ = self.entered.send(());
                    release
                        .recv_timeout(testing::remaining(deadline)?)
                        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
                    if self.panics {
                        panic!("injected panic");
                    }
                    Err(io::Error::other("gate closed"))
                }
                None => Ok(buf.len()),
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            testing::remaining(self.deadline.expect("write deadline installed"))?;
            Ok(())
        }
    }

    impl Drop for Gate {
        fn drop(&mut self) {
            let _ = self.dropped.send(());
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
            DEFAULT_WRITE_TIMEOUT,
        ));
        let (_sealer, sender) = connect(&outbound, sender);

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
        let mut reader = FrameReader::new(Memory::new(&written[..]), Closer::new(|| {}));
        let mut messages = Vec::new();
        loop {
            let packet = match reader.next_packet(None) {
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

    // Tests that a send holding encryption observes termination when it acquires
    // the writer lock. The old send races a replacement for that lock; only the
    // replacement's frame may reach the byte stream.
    #[test]
    fn test_end_with_queued_send() {
        testing::init_tracing();

        let collector = Collector::default();
        let outbound = Arc::new(Outbound::new(
            collector.clone(),
            Side::Client,
            Closer::new(|| {}),
            DEFAULT_WRITE_TIMEOUT,
        ));
        let (crypto, _) = contexts();
        let (sealer, sender) = connect(&outbound, crypto);
        let mut writer = outbound.lock();
        let sending = thread::spawn(move || sender.send(&payload(1)));

        wait_sealing(&sealer);
        assert!(writer.end(&sealer));
        drop(sealer);
        drop(writer);

        let (crypto, mut peer) = contexts();
        let (_replacement, fresh) = connect(&outbound, crypto);
        fresh.send(&payload(2)).unwrap();
        assert!(matches!(
            sending.join().unwrap(),
            Err(Error::EncryptionFailed(_))
        ));

        let bytes = collector.0.lock().unwrap().clone();
        let mut reader = FrameReader::new(Memory::new(&bytes[..]), Closer::new(|| {}));
        let packet = reader.next_packet(None).unwrap().unwrap();
        assert_eq!(sealing::open(&mut peer, packet).unwrap(), payload(2));
        assert!(matches!(reader.next_packet(None), Err(Error::Terminated)));
    }

    // Tests that a failed write is reported to the sender it failed, that a
    // message sealed behind it is refused rather than written, and that every
    // later one is refused too, even if it performs extra sealing.
    #[test]
    fn test_send_failure_attribution() {
        testing::init_tracing();

        let (gate, entered, release, _) = Gate::new();
        let (sender, _) = contexts();
        let outbound = Arc::new(Outbound::new(
            gate,
            Side::Client,
            Closer::new(|| {}),
            DEFAULT_WRITE_TIMEOUT,
        ));
        let (sealer, sender) = connect(&outbound, sender);

        // The first sender blocks inside its write, the second seals behind it
        // and waits for the write lock while retaining the encryption lock.
        let first = {
            let sender = sender.clone();
            thread::spawn(move || sender.send(&payload(1)))
        };
        entered.recv_timeout(Duration::from_secs(5)).unwrap();
        // The first write must leave encryption available for the next message.
        drop(sealer.try_lock().expect("encryption held during writing"));
        let second = {
            let sender = sender.clone();
            thread::spawn(move || sender.send(&payload(2)))
        };
        wait_sealing(&sealer);

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
        assert!(outbound.finish_receive(&sealer, Ok(Vec::new())).is_err());
    }

    // Tests that senders stay bound to the session that issued them, that ending
    // or dropping it refuses further sends, and that stream closure is observed
    // through I/O while dropping the stream owner yields Terminated.
    #[test]
    fn test_send_refusals() {
        testing::init_tracing();

        let outbound = Arc::new(Outbound::new(
            Memory::new(Vec::new()),
            Side::Client,
            Closer::new(|| {}),
            DEFAULT_WRITE_TIMEOUT,
        ));
        let (crypto, _) = contexts();
        let (first_sealer, first) = connect(&outbound, crypto);
        first.send(&payload(1)).unwrap();

        outbound.end(&first_sealer);
        assert!(matches!(
            first.send(&payload(2)),
            Err(Error::EncryptionFailed(_))
        ));

        let (crypto, _) = contexts();
        let (second_sealer, second) = connect(&outbound, crypto);
        assert!(matches!(
            first.send(&payload(3)),
            Err(Error::EncryptionFailed(_))
        ));
        drop(first_sealer);
        assert!(matches!(
            first.send(&payload(4)),
            Err(Error::EncryptionFailed(_))
        ));
        second.send(&payload(5)).unwrap();

        // Closure leaves logical termination to the operation's I/O result.
        outbound.close();
        outbound
            .finish_receive(&second_sealer, Ok(Vec::new()))
            .unwrap();
        let result = second.send(&payload(6));
        assert!(
            matches!(&result, Err(Error::SendFailed(err)) if err.kind() == io::ErrorKind::NotConnected),
            "{result:?}"
        );
        assert!(
            outbound
                .finish_receive(&second_sealer, Ok(Vec::new()))
                .is_err()
        );
        drop(outbound);
        assert!(matches!(second.send(&payload(7)), Err(Error::Terminated)));
    }

    // Tests that closing cancels a blocked write without taking the send locks,
    // including when a second sender holds the sealer while waiting for the
    // writer and session ending waits for it too. Closing lets both senders and
    // ending finish, and a surviving sender refuses new sends.
    #[test]
    fn test_close_with_stuck_sends() {
        testing::init_tracing();

        let (gate, entered, release, dropped) = Gate::new();
        let (sender, _) = contexts();
        let closer = Closer::new(move || {
            let _ = release.send(());
        });
        let outbound = Arc::new(Outbound::new(
            gate,
            Side::Client,
            closer,
            DEFAULT_WRITE_TIMEOUT,
        ));
        let (sealer, sender) = connect(&outbound, sender);

        let first = {
            let sender = sender.clone();
            thread::spawn(move || sender.send(&payload(1)))
        };
        entered.recv_timeout(Duration::from_secs(5)).unwrap();
        let second = {
            let sender = sender.clone();
            thread::spawn(move || sender.send(&payload(2)))
        };
        wait_sealing(&sealer);

        let (ending_tx, started) = mpsc::channel();
        let ending = {
            let outbound = outbound.clone();
            let sealer = sealer.clone();
            thread::spawn(move || {
                ending_tx.send(()).unwrap();
                outbound.end(&sealer);
            })
        };
        started.recv_timeout(Duration::from_secs(5)).unwrap();

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
        ending.join().unwrap();
        assert!(matches!(first.join().unwrap(), Err(Error::SendFailed(_))));
        assert!(matches!(
            second.join().unwrap(),
            Err(Error::EncryptionFailed(_))
        ));
        assert!(outbound.finish_receive(&sealer, Ok(Vec::new())).is_err());
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
        let outbound = Arc::new(Outbound::new(
            gate,
            Side::Client,
            closer,
            DEFAULT_WRITE_TIMEOUT,
        ));
        let (_sealer, sender) = connect(&outbound, sender);

        let sending = thread::spawn(move || {
            panic::catch_unwind(AssertUnwindSafe(|| sender.send(&payload(1))))
        });
        entered.recv_timeout(Duration::from_secs(5)).unwrap();
        outbound.close();
        assert!(sending.join().unwrap().is_err());
        drop(outbound);
        dropped.recv_timeout(Duration::from_secs(5)).unwrap();
    }
}
