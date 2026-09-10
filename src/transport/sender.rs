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
/// Returned by [`Client::connect`](super::Client::connect) or delivered in a
/// server's [`Connected`](super::Event::Connected) event.
///
/// Sends share one encryption sequence and are written in that order. Each send
/// waits for its own frame and receives its own result. A handle belongs
/// permanently to the session that issued it. Session failure, disconnect,
/// reconnect or dropping the client/server invalidates all that session's handles.
/// A new session supplies a new sender. Old handles cannot send into it.
///
/// The client/server retains the session and stream. Idle senders hold only weak
/// references and do not extend either lifetime. An active send temporarily
/// retains both, but can write only while its session remains current.
/// Dropping a sender does not end the session.
#[derive(Debug)]
pub struct Sender<W: Write> {
    outbound: Weak<Outbound<W>>, // Writer retained by the client/server and active sends
    sealer: Weak<Mutex<xhpke::Sender>>, // Encryption context whose allocation identifies the session
}

impl<W: Write> Sender<W> {
    /// Stores weak references to the writer and encryption allocation. Each
    /// active send temporarily retains both. An idle handle owns neither.
    pub(super) fn new(outbound: Weak<Outbound<W>>, sealer: Weak<Mutex<xhpke::Sender>>) -> Self {
        Self { outbound, sealer }
    }

    /// Encrypts a message, writes its complete frame and flushes the output.
    /// Concurrent sends preserve encryption order on the wire. The next message
    /// can be encrypted while the previous one is being written. An oversized
    /// message is refused without advancing encryption or ending the session.
    ///
    /// The write timeout starts after acquiring the writer. Frame encoding,
    /// recovery delimiters, partial writes and flush all share that budget.
    /// Encryption and waiting for the writer are outside the budget.
    ///
    /// An output failure ends the session before returning. Subsequent sends and
    /// receive completions are refused. A timeout returns [`Error::SendFailed`]
    /// containing an I/O `TimedOut` error and leaves the byte stream reusable.
    /// Server failure notification uses the frame's remaining budget and is
    /// skipped after timeout. Ending this way does not wake a blocked receive.
    ///
    /// Ending from another thread waits for a send holding the writer lock.
    /// Queued sends can still encrypt, but must belong to the current session
    /// when they acquire the writer.
    ///
    /// Returns [`Error::Terminated`] if the outgoing transport was released.
    /// Returns [`Error::EncryptionFailed`] if the context was released or its
    /// session ended. Permanent stream closure is observed through I/O, so an
    /// overlapping send may succeed. Unexpected encryption failures and poisoned
    /// locks panic. Transport reuse after a panic is unsupported.
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

    /// Ends this sender's session. On the server, also sends Dropped under the
    /// writer lock. Does nothing if the session has ended or been replaced.
    /// May wait for an active write, so the protocol closes its local queues and
    /// promises first, then calls this from its writer thread.
    pub(crate) fn disconnect(&self) -> Result<(), Error> {
        if let (Some(outbound), Some(context)) = (self.outbound.upgrade(), self.sealer.upgrade()) {
            outbound.disconnect(&context)?;
        }
        Ok(())
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

    /// Holds its first write until released, then fails or panics as configured.
    /// Later writes succeed. Dropping the writer notifies the test driver.
    struct Gate {
        entered: mpsc::Sender<()>,
        release: Option<mpsc::Receiver<()>>,
        dropped: mpsc::Sender<()>,
        panics: bool,
        deadline: Option<Instant>,
    }

    impl Gate {
        /// Creates the gate and channels to observe a blocked write, release it
        /// and observe the writer's drop.
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

    // Tests that concurrent messages go out in encryption order. The receiver
    // must decrypt every frame in sequence and recover every submitted message.
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

    // Tests that a send receives its own write failure. The message encrypted
    // behind it must be refused before writing. Later sends must also fail,
    // even if they perform extra encryption before finding the ended session.
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

    // Tests that senders stay bound to their original session after replacement
    // or ending. Closing the stream is observed through I/O. Dropping its owner
    // makes later sends return Terminated.
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

    // Tests close while a send blocks in I/O, another waits with encryption
    // locked, and session ending also waits for the writer. Close must release
    // the blocked I/O without taking those locks. Both sends and ending then
    // finish, and a surviving sender refuses new messages.
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

    // Tests that an I/O panic releases its active-operation count. Shutdown can
    // then complete, and the last active send releases the transport writer.
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
