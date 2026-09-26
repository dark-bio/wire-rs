// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Handles that send into individual transport sessions.
//!
//! Neither an idle sender nor any of its clones keeps the session or the byte
//! stream alive.

use super::Write;
use super::outbound::Outbound;
use super::{Error, sealing};
use crate::LogId;
use darkbio_crypto::xhpke;
use std::fmt;
use std::sync::{Mutex, Weak};
use tracing::{debug, warn};

/// Cloneable handle for sending messages into a session from any thread.
///
/// [`Client::connect`](super::Client::connect) returns one, and a server
/// delivers one in its [`Connected`](super::Event::Connected) event.
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
pub struct Sender<W: Write> {
    /// Outgoing transport, retained by the client or server and by active sends.
    outbound: Weak<Outbound<W>>,
    /// Encryption context, whose allocation identifies the session.
    sealer: Weak<Mutex<xhpke::Sender>>,
    /// Label of the session in log lines.
    log_id: LogId,
}

impl<W: Write> Sender<W> {
    /// Creates a sender from weak references to the writer and the encryption
    /// allocation.
    ///
    /// Each active send temporarily retains both, and an idle handle owns
    /// neither.
    pub(super) fn new(
        outbound: Weak<Outbound<W>>,
        sealer: Weak<Mutex<xhpke::Sender>>,
        log_id: LogId,
    ) -> Self {
        Self {
            outbound,
            sealer,
            log_id,
        }
    }

    /// Returns the label of this sender's session, for log lines.
    pub(crate) fn log_id(&self) -> LogId {
        self.log_id
    }

    /// Encrypts a message, writes its complete frame and flushes the output.
    ///
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
    /// overlapping send may succeed.
    ///
    /// # Panics
    ///
    /// Panics on an unexpected encryption failure, a poisoned lock, or a write
    /// timeout too large to add to an [`Instant`](std::time::Instant). Transport
    /// reuse after a panic is unsupported.
    pub fn send(&self, message: &[u8]) -> Result<(), Error> {
        // Retain the transport and the session's context, refusing once either
        // is gone
        let Some(outbound) = self.outbound.upgrade() else {
            debug!("wire send refused, transport released");
            return Err(Error::Terminated);
        };
        let Some(context) = self.sealer.upgrade() else {
            debug!("wire send refused, session {} ended", self.log_id);
            return Err(Error::EncryptionFailed("session ended".into()));
        };

        // Seal under the encryption lock, refusing an oversized message before
        // it advances the sequence
        let mut sealer = context.lock().expect("encryption lock not poisoned");
        let packet = match sealing::seal(&mut sealer, message) {
            Ok(packet) => packet,
            Err(Error::PacketTooLarge(size)) => {
                warn!("wire message of {} bytes exceeds the sending limit", size);
                return outbound.refuse_oversized(&context, size);
            }
            Err(err) => panic!("message encryption failed: {err}"),
        };

        // Acquire the writer before releasing encryption, keeping wire order
        // equal to sealing order while the next message seals during this I/O
        let mut writer = outbound.lock();
        drop(sealer);
        let result = writer.send(&context, &packet, self.log_id);
        if let Err(Error::EncryptionFailed(_)) = &result {
            debug!("wire send refused, session {} ended", self.log_id);
        }
        result
    }

    /// Ends this sender's session and, on the server, sends an empty frame
    /// under the writer lock to notify the client.
    ///
    /// Does nothing if the session has ended or been replaced. It may wait for
    /// an active write, so the protocol closes its local queues and promises
    /// first, then calls this from its writer thread.
    pub(crate) fn disconnect(&self) -> Result<(), Error> {
        if let (Some(outbound), Some(context)) = (self.outbound.upgrade(), self.sealer.upgrade()) {
            outbound.disconnect(&context)?;
        }
        Ok(())
    }
}

impl<W: Write> Clone for Sender<W> {
    fn clone(&self) -> Self {
        Self::new(self.outbound.clone(), self.sealer.clone(), self.log_id)
    }
}

impl<W: Write> fmt::Debug for Sender<W> {
    /// Shows the session label and whether the session's sending context is
    /// still alive.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sender")
            .field("session", &self.log_id)
            .field("valid", &(self.sealer.strong_count() > 0))
            .finish()
    }
}

/// Tests of send ordering, refusal and shutdown through sender handles.
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
    use crate::transport::testing::{Memory, test_clock};
    use darkbio_clock::Clock;
    use std::io;
    use std::panic::{self, AssertUnwindSafe};
    use std::sync::{Arc, TryLockError, mpsc};
    use std::thread;
    use std::time::Instant;

    /// Retains a sending context as a client/server would and binds a sender to it.
    fn connect<W: Write>(
        outbound: &Arc<Outbound<W>>,
        sender: xhpke::Sender,
    ) -> (Arc<Mutex<xhpke::Sender>>, Sender<W>) {
        let sealer = Arc::new(Mutex::new(sender));
        let sender = outbound.bind(&sealer);
        (sealer, sender)
    }

    /// Waits until a sender holds the encryption lock while the test or an
    /// earlier send holds the writer.
    ///
    /// It yields between checks, so no sleep decides the ordering.
    fn wait_sealing(sealer: &Mutex<xhpke::Sender>) {
        while !matches!(sealer.try_lock(), Err(TryLockError::WouldBlock)) {
            thread::yield_now();
        }
    }

    /// Creates a matching pair of contexts standing in for an established
    /// session.
    fn contexts() -> (xhpke::Sender, xhpke::Receiver) {
        let secret = xhpke::SecretKey::generate();
        let (sender, encap) = secret.public_key().new_sender(b"test").unwrap();
        let receiver = secret.new_receiver(&encap, b"test").unwrap();
        (sender, receiver)
    }

    /// Writer collecting everything written into a shared buffer.
    #[derive(Clone)]
    struct Collector(
        /// Bytes accepted in wire order.
        Arc<Mutex<Vec<u8>>>,
        /// Clock governing output deadlines.
        Clock,
    );

    impl Write for Collector {
        fn clock(&self) -> Clock {
            self.1.clone()
        }

        fn set_write_deadline(&mut self, deadline: Instant) -> io::Result<()> {
            testing::remaining(&self.1, deadline)?;
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

    /// Writer that holds its first write until released, then fails or panics
    /// as configured.
    ///
    /// Later writes succeed. Dropping the writer notifies the test driver.
    struct Gate {
        /// Clock shared with the outgoing transport and release gate.
        clock: Clock,
        /// Signal sent when the first write starts waiting.
        entered: mpsc::Sender<()>,
        /// Release for the first write, taken when that write starts.
        release: Option<testing::Gate>,
        /// Signal sent when the writer is dropped.
        dropped: mpsc::Sender<()>,
        /// Whether the released first write panics instead of failing.
        panics: bool,
        /// Latest installed write deadline.
        deadline: Option<Instant>,
    }

    impl Gate {
        /// Creates the gate and channels to observe a blocked write, release it
        /// and observe the writer's drop.
        fn new(clock: &Clock) -> (Self, mpsc::Receiver<()>, testing::Gate, mpsc::Receiver<()>) {
            let (entered_tx, entered) = mpsc::channel();
            let release = testing::Gate::new(clock);
            let (dropped_tx, dropped) = mpsc::channel();
            let gate = Self {
                clock: clock.clone(),
                entered: entered_tx,
                release: Some(release.clone()),
                dropped: dropped_tx,
                panics: false,
                deadline: None,
            };
            (gate, entered, release, dropped)
        }
    }

    impl Write for Gate {
        fn clock(&self) -> Clock {
            self.clock.clone()
        }

        fn set_write_deadline(&mut self, deadline: Instant) -> io::Result<()> {
            self.deadline = Some(deadline);
            Ok(())
        }
    }

    impl io::Write for Gate {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let deadline = self.deadline.expect("write deadline installed");
            testing::remaining(&self.clock, deadline)?;
            match self.release.take() {
                Some(release) => {
                    let _ = self.entered.send(());
                    release.wait(Some(deadline))?;
                    if self.panics {
                        panic!("injected panic");
                    }
                    Err(io::Error::other("gate closed"))
                }
                None => Ok(buf.len()),
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            testing::remaining(
                &self.clock,
                self.deadline.expect("write deadline installed"),
            )?;
            Ok(())
        }
    }

    impl Drop for Gate {
        fn drop(&mut self) {
            let _ = self.dropped.send(());
        }
    }

    /// Tests that concurrent messages go out in encryption order.
    #[test]
    fn test_send_order() {
        // Bind a sender to a collector on a paused clock
        testing::init_tracing();
        let tester = test_clock();
        let clock = tester.clock();
        let (sender, mut receiver) = contexts();
        let collector = Collector(Arc::default(), clock.clone());
        let outbound = Arc::new(Outbound::new(
            collector.clone(),
            Side::Client,
            Closer::new(&clock, || {}),
            DEFAULT_WRITE_TIMEOUT,
        ));
        let (_sealer, sender) = connect(&outbound, sender);

        // Submit concurrent messages through the shared sender
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
        let mut reader = FrameReader::new(
            Memory::new(&written[..], &clock),
            Closer::new(&clock, || {}),
        );
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

    /// Tests that a send holding the encryption lock finds its session ended
    /// once it acquires the writer.
    #[test]
    fn test_end_with_queued_send() {
        // Hold the writer while a send acquires encryption
        testing::init_tracing();
        let tester = test_clock();
        let clock = tester.clock();
        let collector = Collector(Arc::default(), clock.clone());
        let outbound = Arc::new(Outbound::new(
            collector.clone(),
            Side::Client,
            Closer::new(&clock, || {}),
            DEFAULT_WRITE_TIMEOUT,
        ));
        let (crypto, _) = contexts();
        let (sealer, sender) = connect(&outbound, crypto);
        let mut writer = outbound.lock();
        let sending = thread::spawn(move || sender.send(&payload(1)));

        // End the original binding before the queued send can acquire output
        wait_sealing(&sealer);
        assert!(writer.end(&sealer));
        drop(sealer);
        drop(writer);

        // Send through the replacement while the old send is refused
        let (crypto, mut peer) = contexts();
        let (_replacement, fresh) = connect(&outbound, crypto);
        fresh.send(&payload(2)).unwrap();
        assert!(matches!(
            sending.join().unwrap(),
            Err(Error::EncryptionFailed(_))
        ));

        // Require only the replacement's frame in the captured output
        let bytes = collector.0.lock().unwrap().clone();
        let mut reader =
            FrameReader::new(Memory::new(&bytes[..], &clock), Closer::new(&clock, || {}));
        let packet = reader.next_packet(None).unwrap().unwrap();
        assert_eq!(sealing::open(&mut peer, packet).unwrap(), payload(2));
        assert!(matches!(reader.next_packet(None), Err(Error::Terminated)));
    }

    /// Tests that a send receives its own write failure, while the sends behind
    /// it are refused.
    ///
    /// Later sends must fail even if they encrypt before finding the ended
    /// session.
    #[test]
    fn test_send_failure_attribution() {
        // Gate the first send on a paused clock
        testing::init_tracing();
        let tester = test_clock();
        let clock = tester.clock();
        let (gate, entered, release, _) = Gate::new(&clock);
        let (sender, _) = contexts();
        let outbound = Arc::new(Outbound::new(
            gate,
            Side::Client,
            Closer::new(&clock, || {}),
            DEFAULT_WRITE_TIMEOUT,
        ));
        let (sealer, sender) = connect(&outbound, sender);

        // The first sender blocks inside its write, the second seals behind it
        // and waits for the write lock while retaining the encryption lock
        let first = {
            let sender = sender.clone();
            thread::spawn(move || sender.send(&payload(1)))
        };
        entered.recv().unwrap();
        // The first write must leave encryption available for the next message
        drop(sealer.try_lock().expect("encryption held during writing"));
        let second = {
            let sender = sender.clone();
            thread::spawn(move || sender.send(&payload(2)))
        };
        wait_sealing(&sealer);

        // The write fails, taking the session with it
        release.open();
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

    /// Tests that senders stay bound to their original session after it ends or
    /// is replaced.
    ///
    /// Closing the stream is observed through I/O, and releasing the transport
    /// makes later sends return `Terminated`.
    #[test]
    fn test_send_refusals() {
        // Send through a fresh session on a paused clock
        testing::init_tracing();
        let tester = test_clock();
        let clock = tester.clock();
        let outbound = Arc::new(Outbound::new(
            Memory::new(Vec::new(), &clock),
            Side::Client,
            Closer::new(&clock, || {}),
            DEFAULT_WRITE_TIMEOUT,
        ));
        let (crypto, _) = contexts();
        let (first_sealer, first) = connect(&outbound, crypto);
        first.send(&payload(1)).unwrap();

        // Refuse sends after ending the first session
        outbound.end(&first_sealer);
        assert!(matches!(
            first.send(&payload(2)),
            Err(Error::EncryptionFailed(_))
        ));

        // Keep the replacement independent of old sender handles
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

        // Closing ends the session only through a failed send, and releasing the
        // transport terminates later sends
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

    /// Tests that closing releases a send blocked in I/O, a send queued behind
    /// it and a session end waiting for the writer.
    ///
    /// Close must release the blocked I/O without taking those locks, and a
    /// surviving sender then refuses new messages.
    #[test]
    fn test_close_with_stuck_sends() {
        // Configure shutdown to release blocked output on the same clock
        testing::init_tracing();
        let tester = test_clock();
        let clock = tester.clock();
        let (gate, entered, release, dropped) = Gate::new(&clock);
        let (sender, _) = contexts();
        let closer = Closer::new(&clock, move || {
            release.open();
        });
        let outbound = Arc::new(Outbound::new(
            gate,
            Side::Client,
            closer,
            DEFAULT_WRITE_TIMEOUT,
        ));
        let (sealer, sender) = connect(&outbound, sender);

        // Start one send in I/O and another behind the writer
        let first = {
            let sender = sender.clone();
            thread::spawn(move || sender.send(&payload(1)))
        };
        entered.recv().unwrap();
        let second = {
            let sender = sender.clone();
            thread::spawn(move || sender.send(&payload(2)))
        };
        wait_sealing(&sealer);

        // Start session ending before closing the physical stream
        let (ending_tx, started) = mpsc::channel();
        let ending = {
            let outbound = outbound.clone();
            let sealer = sealer.clone();
            thread::spawn(move || {
                ending_tx.send(()).unwrap();
                outbound.end(&sealer);
            })
        };
        started.recv().unwrap();

        // Let physical shutdown release I/O and all queued operations
        let (closed_tx, closed) = mpsc::channel();
        let owner = {
            let outbound = outbound.clone();
            thread::spawn(move || {
                outbound.close();
                closed_tx.send(()).unwrap();
            })
        };
        closed.recv().unwrap();
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
        dropped.recv().unwrap();
        assert!(matches!(sender.send(&payload(4)), Err(Error::Terminated)));
    }

    /// Tests that an I/O panic releases its active-operation count, so shutdown
    /// completes and the last active send releases the transport writer.
    #[test]
    fn test_close_with_panicking_send() {
        // Arrange a panic after shutdown releases the gated write
        testing::init_tracing();
        let tester = test_clock();
        let clock = tester.clock();
        let (mut gate, entered, release, dropped) = Gate::new(&clock);
        gate.panics = true;
        let (sender, _) = contexts();
        let closer = Closer::new(&clock, move || {
            release.open();
        });
        let outbound = Arc::new(Outbound::new(
            gate,
            Side::Client,
            closer,
            DEFAULT_WRITE_TIMEOUT,
        ));
        let (_sealer, sender) = connect(&outbound, sender);

        // Catch the send panic and require shutdown and writer drop to complete
        let sending = thread::spawn(move || {
            panic::catch_unwind(AssertUnwindSafe(|| sender.send(&payload(1))))
        });
        entered.recv().unwrap();
        outbound.close();
        assert!(sending.join().unwrap().is_err());
        drop(outbound);
        dropped.recv().unwrap();
    }
}
