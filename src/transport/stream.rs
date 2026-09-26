// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! The byte stream and its shutdown operation, owned together by the transport.

use super::io::check_deadline;
use super::{DEFAULT_WRITE_TIMEOUT, Read, Write};
use darkbio_clock::Clock;
use darkbio_clock::sync::{Condvar, Mutex};
use std::fmt;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::debug;

/// A duplex byte stream with a shutdown operation for both directions.
///
/// Shutdown must release blocked reads, writes and flushes, including reads
/// with no deadline. Socket adapters can shut down the underlying socket.
/// The shutdown operation must return promptly, must not panic, and must not
/// acquire a lock held by a blocked I/O operation. It runs at most once.
/// Neither shutdown nor an I/O operation may call this stream's closer. Closing
/// would wait for the calling operation itself to return.
///
/// Closing refuses further adapter I/O. Admitted operations return their normal
/// results and may succeed while shutdown is in progress. A failed frame send
/// may have moved any prefix of its bytes. A successful write and flush means
/// the adapter took the bytes, not that the peer received or processed them.
/// Data already buffered by the transport may still be received after closing.
///
/// Dropping the stream closes it. Passing it to a client or server transfers
/// that responsibility to the transport owner. [`Closer`] handles do not keep
/// the reader or writer alive, and dropping a handle does not close the stream.
pub struct Stream<R: Read, W: Write> {
    /// Clock shared by both adapters and the transport on them.
    clock: Clock,
    /// Reader and writer, taken when ownership passes to the transport.
    io: Option<(R, W)>,
    /// Handle closing this stream, cloned for every caller that asks.
    closer: Closer,
    /// One budget for each frame's writes and flush.
    timeout: Duration,
}

impl<R: Read, W: Write> Stream<R, W> {
    /// Bundles the two I/O directions with their shutdown operation.
    ///
    /// Each frame gets [`DEFAULT_WRITE_TIMEOUT`] to write and flush until
    /// [`Self::set_write_timeout`] changes it.
    ///
    /// # Panics
    ///
    /// Panics if the reader and writer report different clocks.
    pub fn new(reader: R, writer: W, shutdown: impl FnOnce() + Send + 'static) -> Self {
        // Reject mixed clocks before creating the stream's shutdown state
        let clock = reader.clock();
        assert_eq!(
            clock,
            writer.clock(),
            "stream halves must use the same clock"
        );

        // Retain the shared clock alongside the adapters
        Self {
            closer: Closer::new(&clock, shutdown),
            clock,
            io: Some((reader, writer)),
            timeout: DEFAULT_WRITE_TIMEOUT,
        }
    }

    /// Returns the clock shared by this stream's adapters.
    pub fn clock(&self) -> Clock {
        self.clock.clone()
    }

    /// Sets the budget for writing and flushing one complete frame, including
    /// any delimiter needed after failed output.
    ///
    /// Progress does not restart it. The budget begins after acquiring the
    /// writer and includes frame encoding. Waiting for locks, encryption and
    /// peer replies is outside this budget. Handshake frames also share the
    /// overall handshake deadline, which can shorten this write budget.
    ///
    /// Zero refuses output immediately. A duration too large to add to an
    /// [`Instant`] panics when an outgoing frame's deadline is constructed.
    pub fn set_write_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Returns a handle that can close the stream from another thread.
    pub fn closer(&self) -> Closer {
        self.closer.clone()
    }

    /// Permanently closes the stream and waits for shutdown and admitted adapter
    /// operations to finish.
    ///
    /// Concurrent close calls wait for the same completion. See
    /// [`Closer::close`].
    pub fn close(&self) {
        self.closer.close();
    }

    /// Hands the adapters, a closer and the write budget to a transport
    /// without closing the stream.
    pub(crate) fn into_parts(mut self) -> (R, W, Closer, Duration) {
        let (reader, writer) = self.io.take().expect("stream consumed once");
        (reader, writer, self.closer.clone(), self.timeout)
    }
}

impl<R: Read, W: Write> Drop for Stream<R, W> {
    fn drop(&mut self) {
        if self.io.is_some() {
            self.close();
        }
    }
}

impl<R: Read, W: Write> fmt::Debug for Stream<R, W> {
    /// Shows the write budget and the shutdown state, never the adapters.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Stream")
            .field("timeout", &self.timeout)
            .field("closer", &self.closer)
            .finish_non_exhaustive()
    }
}

/// A cloneable handle that permanently closes a byte stream.
#[derive(Clone)]
pub struct Closer(
    /// Shutdown coordination shared by every clone.
    Arc<Shutdown>,
);

/// Shutdown coordination shared by every handle of one stream.
///
/// The state lock orders I/O admission and closure. Adapter operations and the
/// shutdown callback run without this lock.
struct Shutdown {
    /// Lifecycle, active operations and the pending shutdown callback.
    state: Mutex<State>,
    /// Signal waking closers as admitted operations and shutdown finish.
    changed: Condvar,
}

/// Lifecycle phase of a byte stream.
///
/// Closing refuses new adapter operations. Closed also guarantees that
/// shutdown and all admitted operations have finished.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Stream admitting adapter I/O, with no shutdown requested.
    Open,
    /// Shutdown run by one closer while other closers wait and new I/O is
    /// refused.
    Closing,
    /// End state, reached once the callback and every admitted adapter call
    /// have returned.
    Closed,
}

/// Stream lifecycle and active adapter operations, guarded by one lock.
///
/// Each admitted operation increments the active count and decrements it on
/// completion. Closed requires a zero count.
struct State {
    /// Current lifecycle phase.
    phase: Phase,
    /// Admitted adapter operations that shutdown must wait for.
    active: usize,
    /// Shutdown callback, taken by the first closer.
    action: Option<Box<dyn FnOnce() + Send>>,
}

impl Closer {
    /// Creates the coordinator of an open stream, whose closers wait on `clock`
    /// and whose first closer runs `shutdown`.
    pub(super) fn new(clock: &Clock, shutdown: impl FnOnce() + Send + 'static) -> Self {
        Self(Arc::new(Shutdown {
            state: Mutex::new(State {
                phase: Phase::Open,
                active: 0,
                action: Some(Box::new(shutdown)),
            }),
            changed: Condvar::new(clock),
        }))
    }

    /// Permanently closes the stream.
    ///
    /// Every caller waits until the shutdown callback and all admitted adapter
    /// calls have returned. This includes deadline setters, reads, writes and
    /// flushes. New I/O is refused as soon as closing begins. This does not join
    /// the threads using the transport or wait for application handlers.
    ///
    /// The callback runs once, without holding a state or I/O lock. It must
    /// return promptly and release blocked I/O, including reads with no
    /// deadline. Calling close from adapter I/O or the callback would wait on
    /// itself.
    pub fn close(&self) {
        // Wait for another closer to finish or take responsibility for shutdown
        let action = {
            let mut state = self.0.state.lock().expect("stream state not poisoned");
            loop {
                match state.phase {
                    // Stream already closed, return early
                    Phase::Closed => return,

                    // Another closer is running shutdown. Wait for it to finish.
                    Phase::Closing => {
                        state = self
                            .0
                            .changed
                            .wait(state)
                            .expect("stream state not poisoned");
                    }

                    // Stream open, mark it closing and begin teardown
                    Phase::Open => {
                        debug!("closing wire stream");
                        state.phase = Phase::Closing;
                        break state.action.take().expect("shutdown called once");
                    }
                }
            }
        };

        // The first closer runs shutdown without holding the state lock
        action();

        // Wait until all admitted adapter operations return
        let mut state = self.0.state.lock().expect("stream state not poisoned");
        while state.active != 0 {
            state = self
                .0
                .changed
                .wait(state)
                .expect("stream state not poisoned");
        }

        // Mark the stream closed and wake any threads blocked on close
        state.phase = Phase::Closed;
        self.0.changed.notify_all();
    }

    /// Admits one adapter call while the stream is open, or returns `None` once
    /// closing has begun.
    ///
    /// Admission and the decision to start closing are ordered under the state
    /// lock.
    fn enter(&self) -> Option<Activity<'_>> {
        let mut state = self.0.state.lock().expect("stream state not poisoned");
        if state.phase != Phase::Open {
            return None;
        }
        state.active += 1;
        Some(Activity(self))
    }
}

impl fmt::Debug for Closer {
    /// Shows the lifecycle phase and the admitted adapter operations.
    ///
    /// A state lock held elsewhere is reported instead of waited for.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut closer = f.debug_struct("Closer");
        match self.0.state.try_lock() {
            Ok(state) => closer
                .field("phase", &state.phase)
                .field("active", &state.active),
            Err(_) => closer.field("state", &format_args!("<locked>")),
        };
        closer.finish()
    }
}

/// Guard for one admitted adapter operation, held until it returns or unwinds.
///
/// Dropping it decrements the active count without acquiring an I/O lock.
struct Activity<'a>(
    /// Coordinator that admitted the operation.
    &'a Closer,
);

impl Drop for Activity<'_> {
    fn drop(&mut self) {
        let mut state = self.0.0.state.lock().expect("stream state not poisoned");
        state.active -= 1;
        if state.active == 0 {
            self.0.0.changed.notify_all();
        }
    }
}

/// Reader admitting each adapter call through the shutdown coordinator.
pub(super) struct ReadHalf<R> {
    /// Reading adapter of the stream.
    pub(super) inner: R,
    /// Coordinator admitting each deadline setter and read call.
    pub(super) closer: Closer,
}

impl<R: Read> ReadHalf<R> {
    /// Reads with the optional handshake deadline.
    ///
    /// Ordinary reads wait for data or adapter shutdown. Timeouts and
    /// interruptions retry within the deadline. A successful read reports its
    /// bytes even if it finishes late, so the framer can retain them before
    /// surfacing expiry. Closure refuses new I/O with EOF.
    pub(super) fn read(&mut self, buf: &mut [u8], deadline: Option<Instant>) -> io::Result<usize> {
        loop {
            // Refuse an operation whose deadline has expired
            if let Some(deadline) = deadline {
                check_deadline(&self.inner.clock(), deadline)?;
            }

            // Keep the setter and read accounted for until both have returned
            let result = {
                let Some(_active) = self.closer.enter() else {
                    return Ok(0);
                };
                self.inner.set_read_deadline(deadline)?;
                self.inner.read(buf)
            };

            // Retry an idle timeout or interrupted read. Other errors return.
            match result {
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                result => return result,
            }
        }
    }
}

/// Writer admitting each deadline setter, partial write and flush through the
/// shutdown coordinator.
pub(super) struct WriteHalf<W> {
    /// Writing adapter of the stream.
    pub(super) inner: W,
    /// Coordinator admitting each deadline setter, write and flush call.
    pub(super) closer: Closer,
}

impl<W: Write> WriteHalf<W> {
    /// Writes all bytes and flushes them under one absolute deadline.
    ///
    /// Installs the deadline once before I/O. Each partial write and flush
    /// checks expiration and closure before calling the adapter. Interrupted
    /// writes are retried. Zero progress fails with
    /// [`WriteZero`](io::ErrorKind::WriteZero). Setter and flush errors are not
    /// retried.
    ///
    /// An admitted call may finish after closure begins. Failure can leave a
    /// written prefix. The framer checks the deadline again after this
    /// operation returns, so a late flush fails the complete frame.
    pub(super) fn write(&mut self, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
        // Refuse an operation whose deadline has expired
        check_deadline(&self.inner.clock(), deadline)?;

        // Account for the deadline setter so shutdown waits for it too
        {
            let _active = self
                .closer
                .enter()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "stream closed"))?;
            self.inner.set_write_deadline(deadline)?;
        }

        // Keep writing while bytes remain; flush only after the complete write
        while !bytes.is_empty() {
            // Recheck the deadline before each partial write
            check_deadline(&self.inner.clock(), deadline)?;

            // Attempt to write as much data as possible
            let result = {
                let _active = self
                    .closer
                    .enter()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "stream closed"))?;
                self.inner.write(bytes)
            };
            match result {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => bytes = &bytes[n..],
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(err),
            }
        }

        // Flush is part of the same operation and gets its own admission
        check_deadline(&self.inner.clock(), deadline)?;
        let _active = self
            .closer
            .enter()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "stream closed"))?;
        self.inner.flush()
    }
}

/// Checks stream ownership, shutdown, I/O admission and output deadlines.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::testing;
    use crate::transport::Client;
    use crate::transport::testing::{Memory, test_clock};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    /// Checks that concurrent closers park on the stream clock until admitted
    /// I/O is released.
    #[test]
    fn test_concurrent_closers_wait_on_stream_clock() {
        // Keep an admitted operation alive while two threads close the stream
        let tester = darkbio_clock::TestClock::new();
        let (stream, _peer) = crate::memory::duplex(1, &tester.clock());
        let closer = stream.closer();
        let activity = closer.enter().unwrap();
        thread::scope(|scope| {
            let first = scope.spawn(|| closer.close());
            let second = scope.spawn(|| closer.close());

            // Require both shutdown waits to be registered on this clock
            tester.wait_blocked(2);
            assert!(closer.enter().is_none());

            // Complete the admitted operation and let both closers finish
            drop(activity);
            first.join().unwrap();
            second.join().unwrap();
            assert!(closer.enter().is_none());
        });
    }

    /// Checks that the transport's owners and handles print without printable
    /// adapters, which hosts may box as trait objects.
    #[test]
    fn test_debug_capabilities() {
        use crate::transport::{Attestation, Event, Roots, Sender, Server};

        /// Requires a type to be printable.
        fn printable<T: fmt::Debug>() {}
        printable::<Stream<Box<dyn Read>, Box<dyn Write>>>();
        printable::<Closer>();
        printable::<Client<Box<dyn Read>, Box<dyn Write>>>();
        printable::<Server<Box<dyn Read>, Box<dyn Write>, Attestation>>();
        printable::<Sender<Box<dyn Write>>>();
        printable::<Event<Box<dyn Write>>>();
        printable::<Attestation>();
        printable::<Roots<'static>>();
    }

    /// Checks that the transport refuses an expired read before consuming bytes
    /// a memory reader would still deliver after its own deadline.
    #[test]
    fn test_memory_reader_keeps_transport_deadline() {
        // Queue bytes on a clock a day ahead of real time
        let tester = test_clock();
        let clock = tester.clock();
        let (host, ark) = crate::memory::duplex(4, &clock);
        let (_ark_read, mut ark_write) = ark.into_halves();
        std::io::Write::write_all(&mut ark_write, b"abc").unwrap();
        let (reader, _writer, closer, _) = host.into_parts();
        let mut reader = ReadHalf {
            inner: reader,
            closer,
        };

        // Refuse an expired read without consuming the available bytes
        let mut bytes = [0; 3];
        assert_eq!(
            reader
                .read(&mut bytes, Some(clock.now()))
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(bytes, [0; 3]);
        assert_eq!(reader.read(&mut bytes, None).unwrap(), 3);
        assert_eq!(&bytes, b"abc");
    }

    /// Adapter holding an admitted call until shutdown has been requested,
    /// then returning the result selected by the test.
    struct Adapter {
        /// Clock shared by the adapter and shutdown gate.
        clock: Clock,
        /// Channel notifying the test that an adapter call has started.
        entered: mpsc::Sender<()>,
        /// Gate the shutdown callback opens to release the held call.
        released: testing::Gate,
        /// Whether the held call returns an adapter failure.
        fails: bool,
        /// Latest deadline installed by either direction's setter.
        deadline: Option<Instant>,
    }

    impl Adapter {
        /// Reports entry and waits for shutdown to release the call within its
        /// deadline, then returns the selected result.
        fn wait(&self, deadline: Option<Instant>) -> io::Result<()> {
            self.entered.send(()).unwrap();
            self.released.wait(deadline)?;
            if self.fails {
                Err(io::Error::other("adapter failure"))
            } else {
                Ok(())
            }
        }
    }

    impl Read for Adapter {
        fn clock(&self) -> Clock {
            self.clock.clone()
        }

        fn set_read_deadline(&mut self, deadline: Option<Instant>) -> io::Result<()> {
            self.deadline = deadline;
            Ok(())
        }
    }

    impl io::Read for Adapter {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.wait(self.deadline)?;
            buf[0] = 0x5a;
            Ok(1)
        }
    }

    impl Write for Adapter {
        fn clock(&self) -> Clock {
            self.clock.clone()
        }

        fn set_write_deadline(&mut self, deadline: Instant) -> io::Result<()> {
            self.deadline = Some(deadline);
            Ok(())
        }
    }

    impl io::Write for Adapter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.wait(Some(self.deadline.expect("write deadline installed")))?;
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.wait(Some(self.deadline.expect("write deadline installed")))
        }
    }

    /// Runs an adapter call across shutdown and checks that its result survives.
    fn during_shutdown(
        fails: bool,
        operation: impl FnOnce(Adapter, Closer) -> io::Result<()> + Send + 'static,
    ) {
        // Start an admitted adapter call on a paused clock
        let tester = test_clock();
        let clock = tester.clock();
        let (entered, entries) = mpsc::channel();
        let released = testing::Gate::new(&clock);
        let release = released.clone();
        let closer = Closer::new(&clock, move || release.open());
        let io = thread::spawn({
            let closer = closer.clone();
            move || {
                operation(
                    Adapter {
                        clock,
                        entered,
                        released,
                        fails,
                        deadline: None,
                    },
                    closer,
                )
            }
        });

        // Close only after the adapter has parked and preserve its result
        entries.recv().unwrap();
        tester.wait_blocked(1);
        closer.close();
        let result = io.join().unwrap();
        if fails {
            let err = result.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::Other);
            assert_eq!(err.to_string(), "adapter failure");
        } else {
            result.unwrap();
        }
    }

    /// Checks that shutdown preserves the results of an admitted read and final
    /// flush, including their errors.
    #[test]
    fn test_admitted_io_preserves_results_during_shutdown() {
        for fails in [false, true] {
            // Preserve the admitted read's result across shutdown
            during_shutdown(fails, |inner, closer| {
                let mut buf = [0];
                assert_eq!(ReadHalf { inner, closer }.read(&mut buf, None)?, 1);
                assert_eq!(buf, [0x5a]);
                Ok(())
            });

            // Let an admitted write finish, then refuse the flush after it
            during_shutdown(fails, move |inner, closer| {
                let deadline = inner.clock.now() + Duration::from_secs(5);
                let result = WriteHalf { inner, closer }.write(&[1, 2, 3], deadline);
                if fails {
                    result
                } else {
                    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotConnected);
                    Ok(())
                }
            });

            // Preserve the admitted final flush's result across shutdown
            during_shutdown(fails, |inner, closer| {
                let deadline = inner.clock.now() + Duration::from_secs(5);
                WriteHalf { inner, closer }.write(&[], deadline)
            });
        }
    }

    /// Checks that handing a stream to a client keeps it open, and dropping
    /// either owner runs shutdown exactly once despite repeated closes.
    #[test]
    fn test_ownership_and_repeated_close() {
        // Transfer a paused stream to its client without closing it
        let tester = test_clock();
        let clock = tester.clock();
        let calls = Arc::new(AtomicUsize::new(0));
        let stream = Stream::new(
            Memory::new(io::empty(), &clock),
            Memory::new(io::sink(), &clock),
            {
                let calls = calls.clone();
                move || {
                    calls.fetch_add(1, Ordering::SeqCst);
                }
            },
        );
        let closer = stream.closer();
        let client = Client::new(stream);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "handoff must keep the stream open"
        );

        // Close once when its owner drops and ignore repeated closes
        drop(client);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        closer.close();
        drop(closer.clone());
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Close an unclaimed stream when it drops too
        let stream = Stream::new(
            Memory::new(io::empty(), &clock),
            Memory::new(io::sink(), &clock),
            {
                let calls = calls.clone();
                move || {
                    calls.fetch_add(1, Ordering::SeqCst);
                }
            },
        );
        drop(stream);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "unclaimed streams also close on drop"
        );
    }

    /// Checks that concurrent close calls and the owner's drop all wait for the
    /// shutdown callback to return.
    #[test]
    fn test_every_closer_waits_for_the_shutdown_callback() {
        // Park the shutdown callback on the stream's paused clock
        let tester = test_clock();
        let clock = tester.clock();
        let (entered, callback) = mpsc::channel();
        let release = testing::Gate::new(&clock);
        let released = release.clone();
        let stream = Stream::new(
            Memory::new(io::empty(), &clock),
            Memory::new(io::sink(), &clock),
            move || {
                entered.send(()).unwrap();
                released.wait(None).unwrap();
            },
        );
        let closer = stream.closer();
        let (finished, finishes) = mpsc::channel();
        let first = thread::spawn({
            let closer = closer.clone();
            let finished = finished.clone();
            move || {
                closer.close();
                finished.send(()).unwrap();
            }
        });
        callback.recv().unwrap();

        // Start another close and owner drop while the first callback is parked
        let (started, starts) = mpsc::channel();
        let second = thread::spawn({
            let closer = closer.clone();
            let started = started.clone();
            let finished = finished.clone();
            move || {
                started.send(()).unwrap();
                closer.close();
                finished.send(()).unwrap();
            }
        });
        let owner = thread::spawn(move || {
            started.send(()).unwrap();
            drop(stream);
            finished.send(()).unwrap();
        });
        starts.recv().unwrap();
        starts.recv().unwrap();
        tester.wait_blocked(3);
        assert!(finishes.try_recv().is_err());

        // Release the callback and await all three closers
        release.open();
        finishes.recv().unwrap();
        finishes.recv().unwrap();
        finishes.recv().unwrap();
        first.join().unwrap();
        second.join().unwrap();
        owner.join().unwrap();
    }

    /// Adapter operation held in flight while the test requests shutdown.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum BlockAt {
        /// Raw read held until the test releases it.
        Read,
        /// Raw write held until the test releases it.
        Write,
        /// Flush held until the test releases it.
        Flush,
    }

    /// Barrier holding one adapter operation until the test releases it.
    ///
    /// This keeps I/O in progress long enough to observe shutdown.
    struct Gate {
        /// Clock shared with both gated adapters.
        clock: Clock,
        /// Operation this barrier holds.
        at: BlockAt,
        /// Channel notifying the test that the held operation started.
        entered: mpsc::Sender<()>,
        /// Gate the test opens to let the held operation finish.
        released: testing::Gate,
        /// Read, write and flush calls made through either half.
        calls: AtomicUsize,
    }

    impl Gate {
        /// Counts an adapter call and holds the selected operation until
        /// released or its supplied deadline expires.
        fn call(&self, at: BlockAt, deadline: Option<Instant>) -> io::Result<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if at == self.at {
                self.entered.send(()).unwrap();
                self.released.wait(deadline)?;
            }
            Ok(())
        }

        /// Allows the admitted operation to finish.
        fn release(&self) {
            self.released.open();
        }
    }

    /// Adapter half sharing a gate with the test driver.
    struct GatedAdapter {
        /// Barrier shared with the other half and the test.
        gate: Arc<Gate>,
        /// Latest deadline installed through either setter.
        deadline: Option<Instant>,
    }

    impl Read for GatedAdapter {
        fn clock(&self) -> Clock {
            self.gate.clock.clone()
        }

        fn set_read_deadline(&mut self, deadline: Option<Instant>) -> io::Result<()> {
            self.deadline = deadline;
            Ok(())
        }
    }

    impl io::Read for GatedAdapter {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            self.gate.call(BlockAt::Read, self.deadline)?;
            Ok(0)
        }
    }

    impl Write for GatedAdapter {
        fn clock(&self) -> Clock {
            self.gate.clock.clone()
        }

        fn set_write_deadline(&mut self, deadline: Instant) -> io::Result<()> {
            self.deadline = Some(deadline);
            Ok(())
        }
    }

    impl io::Write for GatedAdapter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.gate.call(
                BlockAt::Write,
                Some(self.deadline.expect("write deadline installed")),
            )?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.gate.call(
                BlockAt::Flush,
                Some(self.deadline.expect("write deadline installed")),
            )
        }
    }

    /// Checks that close waits for an admitted read, write or flush after the
    /// shutdown callback returns, and later I/O never reaches the adapter.
    #[test]
    fn test_every_closer_waits_for_active_io_and_refuses_new_io() {
        for at in [BlockAt::Read, BlockAt::Write, BlockAt::Flush] {
            // Hold one admitted adapter operation on the stream's clock
            let tester = test_clock();
            let clock = tester.clock();
            let (entered, entries) = mpsc::channel();
            let gate = Arc::new(Gate {
                clock: clock.clone(),
                at,
                entered,
                released: testing::Gate::new(&clock),
                calls: AtomicUsize::new(0),
            });
            let (requested, requests) = mpsc::channel();
            let stream = Stream::new(
                GatedAdapter {
                    gate: gate.clone(),
                    deadline: None,
                },
                GatedAdapter {
                    gate: gate.clone(),
                    deadline: None,
                },
                move || {
                    requested.send(()).unwrap();
                },
            );
            let (reader, writer, closer, _) = stream.into_parts();
            let io_closer = closer.clone();
            let deadline = clock.now() + Duration::from_secs(5);
            let io = thread::spawn(move || {
                let mut reader = ReadHalf {
                    inner: reader,
                    closer: io_closer.clone(),
                };
                let mut writer = WriteHalf {
                    inner: writer,
                    closer: io_closer,
                };
                match at {
                    BlockAt::Read => assert_eq!(reader.read(&mut [0], None).unwrap(), 0),
                    BlockAt::Write => assert_eq!(
                        writer.write(&[1], deadline).unwrap_err().kind(),
                        io::ErrorKind::NotConnected
                    ),
                    BlockAt::Flush => writer.write(&[], deadline).unwrap(),
                }
                (reader, writer)
            });
            entries.recv().unwrap();

            // Require both I/O and shutdown to park before checking completion
            let (finished, finishes) = mpsc::channel();
            let closing = thread::spawn({
                let closer = closer.clone();
                move || {
                    closer.close();
                    finished.send(()).unwrap();
                }
            });
            requests.recv().unwrap();
            tester.wait_blocked(2);
            assert!(finishes.try_recv().is_err());

            // Release the admitted operation and refuse every new adapter call
            gate.release();
            finishes.recv().unwrap();
            closing.join().unwrap();
            let (mut reader, mut writer) = io.join().unwrap();
            let calls = gate.calls.load(Ordering::SeqCst);
            assert_eq!(reader.read(&mut [0], None).unwrap(), 0);
            assert!(matches!(
                writer.write(&[1], deadline),
                Err(err) if err.kind() == io::ErrorKind::NotConnected
            ));
            assert_eq!(gate.calls.load(Ordering::SeqCst), calls);
            closer.close();
            assert!(requests.try_recv().is_err(), "shutdown called twice");
        }
    }

    /// Writer accepting one byte per write, able to hold its flush until the
    /// supplied deadline.
    ///
    /// Recorded deadlines reveal whether partial progress restarts the budget.
    struct BudgetWriter {
        /// Clock governing writes and the deliberately stalled flush.
        clock: Clock,
        /// Bytes accepted so far.
        bytes: Vec<u8>,
        /// Deadline each accepted write and each flush saw.
        deadlines: Vec<Instant>,
        /// Whether flush sleeps until its deadline and then times out.
        stall_flush: bool,
        /// Latest installed write deadline.
        deadline: Option<Instant>,
        /// Number of deadline setter calls.
        settings: usize,
    }

    impl Write for BudgetWriter {
        fn clock(&self) -> Clock {
            self.clock.clone()
        }

        fn set_write_deadline(&mut self, deadline: Instant) -> io::Result<()> {
            self.deadline = Some(deadline);
            self.settings += 1;
            Ok(())
        }
    }

    impl io::Write for BudgetWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let deadline = self.deadline.expect("write deadline installed");
            check_deadline(&self.clock(), deadline)?;
            self.deadlines.push(deadline);
            self.bytes.push(bytes[0]);
            Ok(1)
        }

        fn flush(&mut self) -> io::Result<()> {
            let deadline = self.deadline.expect("write deadline installed");
            self.deadlines.push(deadline);
            if self.stall_flush {
                self.clock.sleep_until(deadline);
                return Err(io::ErrorKind::TimedOut.into());
            }
            check_deadline(&self.clock(), deadline)
        }
    }

    /// Checks that partial writes and a stalled flush share one absolute
    /// deadline, a timeout leaves the stream reusable and a zero budget skips I/O.
    #[test]
    fn test_output_deadline_and_reuse() {
        // Start a partial write whose flush parks until its clock deadline
        let mut tester = test_clock();
        let clock = tester.clock();
        let timeout = Duration::from_millis(40);
        let stream = Stream::new(
            Memory::new(io::empty(), &clock),
            BudgetWriter {
                clock: clock.clone(),
                bytes: Vec::new(),
                deadlines: Vec::new(),
                stall_flush: true,
                deadline: None,
                settings: 0,
            },
            || {},
        )
        .set_write_timeout(timeout);
        let (_, inner, closer, configured) = stream.into_parts();
        assert_eq!(configured, timeout);
        let mut writer = WriteHalf { inner, closer };
        let deadline = clock.now() + configured;
        let result = thread::scope(|scope| {
            let writing = scope.spawn(|| writer.write(b"abc", deadline));
            tester.wait_blocked(1);
            assert_eq!(tester.next_deadline(), Some(deadline));
            tester.advance_to(deadline);
            writing.join().unwrap()
        });
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(writer.inner.deadlines, vec![deadline; 4]);
        assert_eq!(writer.inner.settings, 1);

        // Resume writes with a new deadline on the same stream
        writer.inner.stall_flush = false;
        let deadline = clock.now() + Duration::from_secs(5);
        writer.write(b"d", deadline).unwrap();
        assert_eq!(writer.inner.bytes, b"abcd");
        assert_eq!(writer.inner.settings, 2);

        // Reject an already expired budget before configuring adapter I/O
        let calls = writer.inner.deadlines.len();
        let deadline = clock.now();
        assert!(matches!(
            writer.write(b"e", deadline),
            Err(err) if err.kind() == io::ErrorKind::TimedOut
        ));
        assert_eq!(writer.inner.deadlines.len(), calls);
        assert_eq!(writer.inner.settings, 2);
        writer.closer.close();
    }

    /// Checks that write retries keep the unsent suffix, zero progress fails
    /// without flushing and an interrupted flush is returned without a retry.
    #[test]
    fn test_partial_write_retries_and_failures() {
        /// Writer replaying scripted results while recording offered and
        /// accepted bytes.
        struct Script {
            /// Clock governing every scripted partial write.
            clock: Clock,
            /// Results the next writes return, in order.
            results: std::collections::VecDeque<io::Result<usize>>,
            /// Bytes offered to each write call.
            offered: Vec<Vec<u8>>,
            /// Bytes the writes accepted, in order.
            accepted: Vec<u8>,
            /// Whether the flush fails as interrupted.
            interrupted_flush: bool,
            /// Number of flush calls.
            flushes: usize,
            /// Number of deadline setter calls.
            settings: usize,
            /// Latest installed write deadline.
            deadline: Option<Instant>,
        }

        impl Write for Script {
            fn clock(&self) -> Clock {
                self.clock.clone()
            }

            fn set_write_deadline(&mut self, deadline: Instant) -> io::Result<()> {
                self.settings += 1;
                self.deadline = Some(deadline);
                Ok(())
            }
        }

        impl io::Write for Script {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                check_deadline(
                    &self.clock(),
                    self.deadline.expect("write deadline installed"),
                )?;
                self.offered.push(bytes.to_vec());
                let result = self.results.pop_front().expect("unexpected write");
                if let Ok(size) = &result {
                    self.accepted.extend_from_slice(&bytes[..*size]);
                }
                result
            }

            fn flush(&mut self) -> io::Result<()> {
                check_deadline(
                    &self.clock(),
                    self.deadline.expect("write deadline installed"),
                )?;
                self.flushes += 1;
                assert_eq!(self.flushes, 1, "flush retried");
                if self.interrupted_flush {
                    Err(io::ErrorKind::Interrupted.into())
                } else {
                    Ok(())
                }
            }
        }

        for (stalls, interrupted_flush) in [(false, false), (true, false), (false, true)] {
            // Run an interrupted write followed by partial progress on a paused clock
            let tester = test_clock();
            let clock = tester.clock();
            let mut writer = WriteHalf {
                inner: Script {
                    clock: clock.clone(),
                    results: [
                        Err(io::ErrorKind::Interrupted.into()),
                        Ok(1),
                        Ok(usize::from(!stalls)),
                    ]
                    .into(),
                    offered: Vec::new(),
                    accepted: Vec::new(),
                    interrupted_flush,
                    flushes: 0,
                    settings: 0,
                    deadline: None,
                },
                closer: Closer::new(&clock, || {}),
            };
            let result = writer.write(b"ab", clock.now() + Duration::from_secs(5));
            if stalls {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WriteZero);
            } else if interrupted_flush {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
            } else {
                result.unwrap();
            }

            // Retain the unsent suffix across retries and configure the deadline once
            assert_eq!(
                writer.inner.offered,
                [b"ab".to_vec(), b"ab".to_vec(), b"b".to_vec()]
            );
            assert_eq!(
                writer.inner.accepted,
                if stalls { &b"a"[..] } else { &b"ab"[..] }
            );
            assert_eq!(writer.inner.flushes, usize::from(!stalls));
            assert_eq!(writer.inner.settings, 1);
            writer.closer.close();
        }
    }

    /// Checks that a failed deadline setter prevents byte I/O and keeps its
    /// error, even an `Interrupted` or `TimedOut` one.
    ///
    /// Only retryable errors from an actual read may start another attempt.
    #[test]
    fn test_deadline_setter_failure_prevents_io() {
        /// Adapter refusing deadline installation, panicking if byte I/O is
        /// attempted.
        struct Refused {
            /// Clock shared by the test's adapters and closer.
            clock: Clock,
            /// Number of deadline setter calls.
            settings: usize,
            /// Error kind the setter fails with.
            kind: io::ErrorKind,
        }

        impl Refused {
            /// Fails the setter call, panicking on a second one so an incorrect
            /// retry fails the test promptly.
            fn reject(&mut self) -> io::Result<()> {
                self.settings += 1;
                assert_eq!(self.settings, 1, "deadline setter failure retried");
                Err(io::Error::new(self.kind, "deadline refused"))
            }
        }

        impl Read for Refused {
            fn clock(&self) -> Clock {
                self.clock.clone()
            }

            fn set_read_deadline(&mut self, _: Option<Instant>) -> io::Result<()> {
                self.reject()
            }
        }

        impl io::Read for Refused {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                panic!("read after deadline setter failed")
            }
        }

        impl Write for Refused {
            fn clock(&self) -> Clock {
                self.clock.clone()
            }

            fn set_write_deadline(&mut self, _: Instant) -> io::Result<()> {
                self.reject()
            }
        }

        impl io::Write for Refused {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                panic!("write after deadline setter failed")
            }

            fn flush(&mut self) -> io::Result<()> {
                panic!("flush after deadline setter failed")
            }
        }

        for kind in [io::ErrorKind::Interrupted, io::ErrorKind::TimedOut] {
            // Fail each direction's deadline installation before byte I/O
            let tester = test_clock();
            let clock = tester.clock();
            let closer = Closer::new(&clock, || {});
            let mut reader = ReadHalf {
                inner: Refused {
                    clock: clock.clone(),
                    settings: 0,
                    kind,
                },
                closer: closer.clone(),
            };
            let err = reader.read(&mut [0], None).unwrap_err();
            assert_eq!(err.kind(), kind);
            assert_eq!(err.to_string(), "deadline refused");
            let mut writer = WriteHalf {
                inner: Refused {
                    clock: clock.clone(),
                    settings: 0,
                    kind,
                },
                closer: closer.clone(),
            };
            assert!(matches!(
                writer.write(&[1], clock.now() + Duration::from_secs(5)),
                Err(err) if err.kind() == kind && err.to_string() == "deadline refused"
            ));

            // Refuse all new I/O after shutdown without another deadline setter call
            closer.close();
            assert_eq!(reader.read(&mut [0], None).unwrap(), 0);
            assert!(matches!(
                writer.write(&[1], clock.now() + Duration::from_secs(5)),
                Err(err) if err.kind() == io::ErrorKind::NotConnected
            ));
            assert_eq!(reader.inner.settings, 1);
            assert_eq!(writer.inner.settings, 1);
        }
    }

    /// Checks that a partial write returning after its deadline keeps its
    /// accepted byte but fails the complete operation.
    ///
    /// Depending on the input length, either the remaining write or the flush
    /// is refused before I/O.
    #[test]
    fn test_late_write_preserves_progress() {
        /// Writer accepting one byte per write, returning only at its installed
        /// deadline.
        struct LateWriter {
            /// Clock governing the late partial write.
            clock: Clock,
            /// Latest installed write deadline.
            deadline: Option<Instant>,
            /// Bytes accepted so far.
            bytes: Vec<u8>,
        }

        impl Write for LateWriter {
            fn clock(&self) -> Clock {
                self.clock.clone()
            }

            fn set_write_deadline(&mut self, deadline: Instant) -> io::Result<()> {
                self.deadline = Some(deadline);
                Ok(())
            }
        }

        impl io::Write for LateWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.bytes.push(bytes[0]);
                self.clock
                    .sleep_until(self.deadline.expect("write deadline installed"));
                Ok(1)
            }

            fn flush(&mut self) -> io::Result<()> {
                panic!("flush admitted after deadline expired")
            }
        }

        for bytes in [&b"a"[..], &b"ab"[..]] {
            // Park a successful partial write until its deadline
            let mut tester = test_clock();
            let clock = tester.clock();
            let mut writer = WriteHalf {
                inner: LateWriter {
                    clock: clock.clone(),
                    deadline: None,
                    bytes: Vec::new(),
                },
                closer: Closer::new(&clock, || {}),
            };
            let deadline = clock.now() + Duration::from_millis(40);
            let result = thread::scope(|scope| {
                let writing = scope.spawn(|| writer.write(bytes, deadline));
                tester.wait_blocked(1);
                tester.advance_to(deadline);
                writing.join().unwrap()
            });

            // Retain only the accepted byte and reject all subsequent adapter I/O
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
            assert_eq!(writer.inner.bytes, b"a");
            writer.closer.close();
        }
    }
}
