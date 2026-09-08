// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! The byte stream and its shutdown operation, owned together by the transport.

use std::io::{self, Read, Write};
use std::sync::{Arc, Condvar, Mutex};

/// A duplex byte stream with a shutdown operation for both directions.
///
/// The adapter must make blocked reads, writes and flushes return within its
/// documented cancellation bound after shutdown. Socket adapters can shut down
/// the socket; adapters that poll or use I/O timeouts must document those bounds.
/// The shutdown operation must return promptly, must not panic, and must not
/// acquire a lock held by a blocked I/O operation. It runs at most once.
/// Neither shutdown nor an I/O operation may call this stream's closer: closing
/// waits for those operations to return.
///
/// Closing refuses further adapter I/O. Admitted operations return their normal
/// results and may succeed while shutdown is in progress. A failed operation
/// may have moved any prefix of its bytes. A successful write and flush means
/// the adapter took the bytes, not that the peer received or processed them.
/// Data already buffered by the transport may still be received after closing.
///
/// Dropping the stream closes it. Passing it to a client or server transfers
/// that responsibility to the transport owner. Close handles do not keep the
/// reader or writer alive, and dropping a handle does not close the stream.
pub struct Stream<R: Read, W: Write> {
    io: Option<(R, W)>, // Taken when ownership passes to the transport
    closer: Closer,
}

impl<R: Read, W: Write> Stream<R, W> {
    /// Bundles the two I/O directions with their shutdown operation.
    pub fn new(reader: R, writer: W, shutdown: impl FnOnce() + Send + 'static) -> Self {
        Self {
            io: Some((reader, writer)),
            closer: Closer::new(shutdown),
        }
    }

    /// A handle that can close the stream from another thread.
    pub fn closer(&self) -> Closer {
        self.closer.clone()
    }

    /// Permanently closes the stream, see [`Closer::close`].
    pub fn close(&self) {
        self.closer.close();
    }

    /// Transfers ownership to a transport without closing the stream.
    pub(crate) fn into_parts(mut self) -> (R, W, Closer) {
        let (reader, writer) = self.io.take().expect("stream consumed once");
        (reader, writer, self.closer.clone())
    }
}

impl<R: Read, W: Write> Drop for Stream<R, W> {
    fn drop(&mut self) {
        if self.io.is_some() {
            self.close();
        }
    }
}

/// A cloneable handle that permanently closes a byte stream.
#[derive(Clone)]
pub struct Closer(Arc<Shutdown>);

/// Shared shutdown coordination. The state lock serializes admission and
/// closure; the condition variable wakes closers when I/O drains or another
/// closer completes shutdown. Neither adapter I/O nor its callback holds it.
struct Shutdown {
    state: Mutex<State>,
    changed: Condvar,
}

/// Lifecycle of a byte stream, advancing once from open through closing to
/// closed. Closing refuses admission; closed additionally guarantees completion.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Adapter I/O may be admitted and shutdown has not been requested.
    Open,
    /// One closer owns shutdown; all others wait and new I/O is refused.
    Closing,
    /// The callback and every admitted adapter call have returned.
    Closed,
}

/// Stream lifecycle and I/O admission under one lock. Only the closer that
/// changes open to closing takes the action. Closed implies no action remains
/// and the active I/O count is zero; every admitted call releases one count on drop.
struct State {
    phase: Phase,
    active: usize, // Active IO operations to wait on after close
    action: Option<Box<dyn FnOnce() + Send>>,
}

impl Closer {
    /// Creates the shutdown coordinator before either I/O half can be used.
    pub(super) fn new(shutdown: impl FnOnce() + Send + 'static) -> Self {
        Self(Arc::new(Shutdown {
            state: Mutex::new(State {
                phase: Phase::Open,
                active: 0,
                action: Some(Box::new(shutdown)),
            }),
            changed: Condvar::new(),
        }))
    }

    /// Permanently closes the stream. Every caller waits until the shutdown
    /// callback and all admitted reads, writes and flushes have returned.
    /// New I/O is refused as soon as closing begins. This does not join the
    /// threads using the transport or wait for application handlers.
    ///
    /// The callback runs once, without holding a state or I/O lock. The adapter
    /// must satisfy the cancellation contract of [`Stream`]. Calling this from
    /// inside the adapter's I/O or shutdown callback would wait on itself.
    pub fn close(&self) {
        // Loop until someone closes in front of us, of we get the shutdown
        let action = {
            let mut state = self.0.state.lock().expect("stream state not poisoned");
            loop {
                match state.phase {
                    // Stream already closed, return early
                    Phase::Closed => return,

                    // Stream currently closing by someone else, idle around
                    Phase::Closing => {
                        state = self
                            .0
                            .changed
                            .wait(state)
                            .expect("stream state not poisoned");
                    }

                    // Stream open, mark it closing and begin teardown
                    Phase::Open => {
                        state.phase = Phase::Closing;
                        break state.action.take().expect("shutdown called once");
                    }
                }
            }
        };

        // We're the first to call close, were granted the shutdown invocation
        action();

        // Keep idling until all active IO operations settle
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

    /// Admits one adapter call atomically with the decision to start closing.
    fn enter(&self) -> Option<Activity<'_>> {
        let mut state = self.0.state.lock().expect("stream state not poisoned");
        if state.phase != Phase::Open {
            return None;
        }
        state.active += 1;
        Some(Activity(self))
    }
}

/// An admitted call, released on return or unwind without holding an I/O lock.
struct Activity<'a>(&'a Closer);

impl Drop for Activity<'_> {
    fn drop(&mut self) {
        let mut state = self.0.0.state.lock().expect("stream state not poisoned");
        state.active -= 1;
        if state.active == 0 {
            self.0.0.changed.notify_all();
        }
    }
}

/// Reader admitting each adapter call under the shutdown coordinator's lock.
pub(super) struct ReadHalf<R> {
    pub(super) inner: R,
    pub(super) closer: Closer,
}

impl<R: Read> Read for ReadHalf<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(_active) = self.closer.enter() else {
            return Ok(0);
        };
        self.inner.read(buf)
    }
}

/// Writer admitting each partial write and flush under the shutdown lock.
pub(super) struct WriteHalf<W> {
    pub(super) inner: W,
    pub(super) closer: Closer,
}

impl<W: Write> Write for WriteHalf<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let _active = self
            .closer
            .enter()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "stream closed"))?;
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let _active = self
            .closer
            .enter()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "stream closed"))?;
        self.inner.flush()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::transport::{Client, Error};
    use darkbio_crypto::xdsa;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    const PATIENCE: Duration = Duration::from_secs(5);

    /// Adapter holding an admitted call until shutdown has been requested,
    /// then returning the result selected by the test.
    struct Adapter {
        entered: mpsc::Sender<()>,
        released: mpsc::Receiver<()>,
        fails: bool,
    }

    impl Adapter {
        fn wait(&self) -> io::Result<()> {
            self.entered.send(()).unwrap();
            self.released.recv_timeout(PATIENCE).unwrap();
            if self.fails {
                Err(io::Error::new(io::ErrorKind::TimedOut, "adapter timeout"))
            } else {
                Ok(())
            }
        }
    }

    impl Read for Adapter {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.wait()?;
            buf[0] = 0x5a;
            Ok(1)
        }
    }

    impl Write for Adapter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.wait()?;
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.wait()
        }
    }

    /// Runs an adapter call across shutdown and checks that its result survives.
    fn during_shutdown(
        fails: bool,
        operation: impl FnOnce(Adapter, Closer) -> io::Result<()> + Send + 'static,
    ) {
        let (entered, entries) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let closer = Closer::new(move || release.send(()).unwrap());
        let io = thread::spawn({
            let closer = closer.clone();
            move || {
                operation(
                    Adapter {
                        entered,
                        released,
                        fails,
                    },
                    closer,
                )
            }
        });
        entries.recv_timeout(PATIENCE).unwrap();
        closer.close();
        let result = io.join().unwrap();
        if fails {
            let err = result.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::TimedOut);
            assert_eq!(err.to_string(), "adapter timeout");
        } else {
            result.unwrap();
        }
    }

    // Tests that shutdown preserves successful adapter results and original
    // errors, releasing admitted reads, writes and flushes from the shutdown
    // callback so each operation completes after closing has begun.
    #[test]
    fn test_admitted_io_preserves_results_during_shutdown() {
        for fails in [false, true] {
            during_shutdown(fails, |inner, closer| {
                let mut buf = [0];
                assert_eq!(ReadHalf { inner, closer }.read(&mut buf)?, 1);
                assert_eq!(buf, [0x5a]);
                Ok(())
            });
            during_shutdown(fails, |inner, closer| {
                assert_eq!(WriteHalf { inner, closer }.write(&[1, 2, 3])?, 3);
                Ok(())
            });
            during_shutdown(fails, |inner, closer| WriteHalf { inner, closer }.flush());
        }
    }

    // Tests that handing a stream to a client transfers shutdown responsibility
    // without closing it. Dropping either owner invokes shutdown exactly once,
    // repeated closes do nothing, and emitters outliving the client fail.
    #[test]
    fn test_ownership_and_repeated_close() {
        let calls = Arc::new(AtomicUsize::new(0));
        let stream = Stream::new(io::empty(), io::sink(), {
            let calls = calls.clone();
            move || {
                calls.fetch_add(1, Ordering::SeqCst);
            }
        });
        let closer = stream.closer();
        let client = Client::new(stream);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "handoff must keep the stream open"
        );
        let emitter = client.emitter();
        assert_eq!(emitter.session_id(), 0);
        drop(client);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(matches!(
            emitter.send_message(b"late"),
            Err(Error::Terminated)
        ));
        closer.close();
        drop(closer.clone());
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let stream = Stream::new(io::empty(), io::sink(), {
            let calls = calls.clone();
            move || {
                calls.fetch_add(1, Ordering::SeqCst);
            }
        });
        drop(stream);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "unclaimed streams also close on drop"
        );
    }

    // Tests that concurrent close calls and owner drop all wait for shutdown
    // completion, holding the callback until every caller has started and
    // checking that none returns before the callback is released.
    #[test]
    fn test_every_closer_waits_for_the_shutdown_callback() {
        let (entered, callback) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let stream = Stream::new(io::empty(), io::sink(), move || {
            entered.send(()).unwrap();
            released.recv_timeout(PATIENCE).unwrap();
        });
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
        callback.recv_timeout(PATIENCE).unwrap();

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
        starts.recv_timeout(PATIENCE).unwrap();
        starts.recv_timeout(PATIENCE).unwrap();
        assert!(finishes.recv_timeout(Duration::from_millis(50)).is_err());
        release.send(()).unwrap();
        finishes.recv_timeout(PATIENCE).unwrap();
        finishes.recv_timeout(PATIENCE).unwrap();
        finishes.recv_timeout(PATIENCE).unwrap();
        first.join().unwrap();
        second.join().unwrap();
        owner.join().unwrap();
    }

    /// Adapter operation held in flight while the test requests shutdown.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum BlockAt {
        /// Hold a raw read until the driver completes cancellation.
        Read,
        /// Hold a raw write until the driver completes cancellation.
        Write,
        /// Hold a flush until the driver completes cancellation.
        Flush,
    }

    /// An adapter whose cancellation takes time after the shutdown request. The
    /// driver controls completion to test the interval with I/O still in flight.
    struct Gate {
        at: BlockAt,
        entered: mpsc::Sender<()>,
        released: Mutex<bool>,
        changed: Condvar,
        calls: AtomicUsize,
    }

    impl Gate {
        fn call(&self, at: BlockAt) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if at == self.at {
                self.entered.send(()).unwrap();
                let (released, _) = self
                    .changed
                    .wait_timeout_while(self.released.lock().unwrap(), PATIENCE, |released| {
                        !*released
                    })
                    .unwrap();
                assert!(*released, "driver never completed cancellation");
            }
        }

        fn release(&self) {
            *self.released.lock().unwrap() = true;
            self.changed.notify_all();
        }
    }

    /// Two byte-stream halves sharing the driver's cancellation gate.
    struct GatedAdapter(Arc<Gate>);

    impl Read for GatedAdapter {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            self.0.call(BlockAt::Read);
            Ok(0)
        }
    }

    impl Write for GatedAdapter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.call(BlockAt::Write);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0.call(BlockAt::Flush);
            Ok(())
        }
    }

    // Tests that close waits for an admitted read, write or flush even after
    // the shutdown callback returns. A gate holds the operation during a client
    // handshake; subsequent client I/O must never reach the closed adapter.
    #[test]
    fn test_every_closer_waits_for_active_io_and_refuses_new_io() {
        for at in [BlockAt::Read, BlockAt::Write, BlockAt::Flush] {
            let (entered, entries) = mpsc::channel();
            let gate = Arc::new(Gate {
                at,
                entered,
                released: Mutex::new(false),
                changed: Condvar::new(),
                calls: AtomicUsize::new(0),
            });
            let (requested, requests) = mpsc::channel();
            let stream = Stream::new(
                GatedAdapter(gate.clone()),
                GatedAdapter(gate.clone()),
                move || {
                    requested.send(()).unwrap();
                },
            );
            let mut client = Client::new(stream);
            let closer = client.closer();
            let io = thread::spawn(move || {
                let identity = xdsa::SecretKey::generate().public_key();
                assert!(client.handshake(&identity).is_err());
                client
            });
            entries.recv_timeout(PATIENCE).unwrap();
            let (finished, finishes) = mpsc::channel();
            let closing = thread::spawn({
                let closer = closer.clone();
                move || {
                    closer.close();
                    finished.send(()).unwrap();
                }
            });
            requests.recv_timeout(PATIENCE).unwrap();
            assert!(finishes.recv_timeout(Duration::from_millis(20)).is_err());

            gate.release();
            finishes.recv_timeout(PATIENCE).unwrap();
            closing.join().unwrap();
            let mut client = io.join().unwrap();
            let calls = gate.calls.load(Ordering::SeqCst);
            assert!(matches!(client.next_message(), Err(Error::Terminated)));
            let identity = xdsa::SecretKey::generate().public_key();
            assert!(matches!(
                client.handshake(&identity),
                Err(Error::SendFailed(err)) if err.kind() == io::ErrorKind::NotConnected
            ));
            assert_eq!(gate.calls.load(Ordering::SeqCst), calls);
            drop(client);
            assert!(requests.try_recv().is_err(), "shutdown called twice");
        }
    }
}
