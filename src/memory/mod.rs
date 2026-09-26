// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Portable in-memory streams for local connections, emulators and tests.
//!
//! These streams synchronize through the clock's locks, with no sockets or
//! worker threads. Split an endpoint with [`Duplex::into_halves`] for plain I/O.

use crate::transport::{Read, Stream, Write};
use darkbio_clock::Clock;
use darkbio_clock::sync::{Condvar, Mutex, MutexGuard};
use std::collections::VecDeque;
use std::io;
use std::sync::Arc;
use std::time::Instant;

/// One endpoint of an in-memory duplex connection, ready for a
/// [`Client`](crate::transport::Client) or [`Server`](crate::transport::Server).
pub type Duplex = Stream<Reader, Writer>;

impl Duplex {
    /// Takes the reader and writer out of the stream without closing either half.
    ///
    /// Each half closes its own direction on drop. Dropping the writer lets the
    /// peer drain accepted output before EOF; dropping the reader refuses
    /// further peer writes. Obtain a [`crate::transport::Closer`] with
    /// [`Self::closer`] before splitting if you need to shut down both halves
    /// from another thread.
    ///
    /// The stream's write timeout is discarded, and the halves have no deadline
    /// until one is configured.
    ///
    /// ```
    /// use darkbio_wire::{clock::Clock, memory};
    /// use darkbio_wire::transport::Client;
    ///
    /// let (host, bus) = memory::duplex(64 * 1024, &Clock::real());
    /// let (reader, writer) = bus.into_halves();
    /// let client = Client::new(host);
    /// // Move `reader` and `writer` to the bus's input and output pumps.
    /// ```
    pub fn into_halves(self) -> (Reader, Writer) {
        let (reader, writer, _, _) = self.into_parts();
        (reader, writer)
    }
}

/// Creates two connected streams with `capacity` bytes of buffering per
/// direction.
///
/// Both measure their deadlines on `clock`, and so does any transport on them.
/// Reads wait for data and writes wait for buffer space, bounded by the
/// deadlines the transport installs. Partial progress never refreshes a
/// deadline. A timeout leaves the connection reusable and preserves any bytes
/// already accepted. Flush checks its deadline but does not wait for the peer
/// to consume output. Reads deliver available bytes, EOF and empty reads even
/// after their deadline; the deadline only limits waiting for input. Writes and
/// flushes refuse expired deadlines even if buffer space is available. The
/// transport enforces its own deadlines before calling either half.
///
/// Closing or dropping an endpoint wakes blocked I/O on both sides. Its unread
/// input is discarded, while the peer can still drain the endpoint's accepted
/// output before receiving EOF. Further nonempty writes on either side fail
/// with [`io::ErrorKind::BrokenPipe`]. So do flushes on the closed endpoint.
/// The peer's flush fails the same way only if the endpoint closed with some of
/// the peer's output unread. Output the endpoint had consumed before closing
/// flushes fine afterwards.
///
/// Both peers must run concurrently when exchanging data. Allow enough capacity
/// for the handshake's initial output; 64 KiB (`64 * 1024`) is a useful
/// starting point. Small buffers can cause handshake backpressure, just as a
/// real stream can.
///
/// # Panics
///
/// Panics if `capacity` is zero.
pub fn duplex(capacity: usize, clock: &Clock) -> (Duplex, Duplex) {
    // Validate capacity before allocating either direction
    assert!(capacity > 0, "duplex capacity must be nonzero");

    // Give both endpoints the same clock and independent buffers
    let incoming = Arc::new(Pipe::new(capacity, clock));
    let outgoing = Arc::new(Pipe::new(capacity, clock));
    (
        endpoint(incoming.clone(), outgoing.clone()),
        endpoint(outgoing, incoming),
    )
}

/// Bundles independent I/O halves with shutdown that wakes both directions.
fn endpoint(incoming: Arc<Pipe>, outgoing: Arc<Pipe>) -> Duplex {
    Stream::new(
        Reader {
            pipe: incoming.clone(),
            deadline: None,
        },
        Writer {
            pipe: outgoing.clone(),
            deadline: None,
        },
        move || {
            incoming.close_reader();
            outgoing.close_writer();
        },
    )
}

/// Receiving half of a [`Duplex`], with an independently configured read deadline.
#[derive(Debug)]
pub struct Reader {
    /// Buffer this half reads from, shared with the peer's writer.
    pipe: Arc<Pipe>,
    /// Latest read deadline, or `None` to wait without one.
    deadline: Option<Instant>,
}

impl io::Read for Reader {
    /// Reads the buffered bytes, waiting for more until the read deadline.
    ///
    /// Buffered bytes are delivered even past the deadline. An empty `buf`, a
    /// closed reader or a closed peer with nothing buffered returns zero.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Recheck the buffer and closure state after every wake
        let mut state = self.pipe.lock();
        loop {
            // Empty reads and local closure need no buffered input
            if buf.is_empty() || !state.reader_open {
                return Ok(0);
            }

            // Deliver ready bytes even after the installed read deadline
            if !state.bytes.is_empty() {
                let count = buf.len().min(state.bytes.len());
                for (out, byte) in buf.iter_mut().zip(state.bytes.drain(..count)) {
                    *out = byte;
                }
                drop(state);
                self.pipe.changed.notify_all();
                return Ok(count);
            }

            // End at peer closure or wait within the remaining clock budget
            if !state.writer_open {
                return Ok(0);
            }
            self.pipe.check_deadline(self.deadline)?;
            state = self.pipe.wait(state, self.deadline);
        }
    }
}

impl Read for Reader {
    fn clock(&self) -> Clock {
        self.pipe.clock.clone()
    }

    fn set_read_deadline(&mut self, deadline: Option<Instant>) -> io::Result<()> {
        self.deadline = deadline;
        Ok(())
    }
}

impl Drop for Reader {
    /// Closes this reading direction and discards its unread bytes.
    fn drop(&mut self) {
        self.pipe.close_reader();
    }
}

#[cfg(test)]
impl Reader {
    /// Makes any later wait for input panic instead of blocking, so a test
    /// expecting an immediate return fails rather than hangs.
    pub(crate) fn forbid_waits(&self) {
        self.pipe.lock().waits_forbidden = true;
    }
}

/// Sending half of a [`Duplex`], sharing one deadline across writes and flushes.
#[derive(Debug)]
pub struct Writer {
    /// Buffer this half writes into, shared with the peer's reader.
    pipe: Arc<Pipe>,
    /// Latest write deadline, or `None` before the first is set.
    deadline: Option<Instant>,
}

impl io::Write for Writer {
    /// Appends as many bytes as fit, waiting for space until the write
    /// deadline.
    ///
    /// An expired deadline fails before accepting any bytes, even with space
    /// free. An empty `buf` then returns zero, and a closed end fails with
    /// [`io::ErrorKind::BrokenPipe`].
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Recheck capacity and the same deadline after every wake
        let mut state = self.pipe.lock();
        loop {
            // Refuse expiry and closure before accepting any bytes
            self.pipe.check_deadline(self.deadline)?;
            if buf.is_empty() {
                return Ok(0);
            }
            if !state.reader_open || !state.writer_open {
                return Err(io::ErrorKind::BrokenPipe.into());
            }

            // Fill available space and wake the reader after releasing the lock
            let count = buf.len().min(self.pipe.capacity - state.bytes.len());
            if count > 0 {
                state.bytes.extend(&buf[..count]);
                drop(state);
                self.pipe.changed.notify_all();
                return Ok(count);
            }

            // Wait for space without extending the deadline
            state = self.pipe.wait(state, self.deadline);
        }
    }

    /// Checks the write deadline and that no output was lost, without waiting
    /// for the peer to read.
    ///
    /// It fails with [`io::ErrorKind::BrokenPipe`] after local closure, or when
    /// the reader closed with output unread.
    fn flush(&mut self) -> io::Result<()> {
        // Check the installed deadline while observing a consistent pipe state
        let state = self.pipe.lock();
        self.pipe.check_deadline(self.deadline)?;

        // Reject local closure or output lost when the peer closed
        if !state.writer_open || state.lost {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        Ok(())
    }
}

impl Write for Writer {
    fn clock(&self) -> Clock {
        self.pipe.clock.clone()
    }

    fn set_write_deadline(&mut self, deadline: Instant) -> io::Result<()> {
        self.deadline = Some(deadline);
        Ok(())
    }
}

impl Drop for Writer {
    /// Closes this writing direction, so the reader gets EOF once the buffer
    /// drains.
    fn drop(&mut self) {
        self.pipe.close_writer();
    }
}

/// Shared bounded buffer for one direction.
///
/// Waiting always releases the mutex.
#[derive(Debug)]
struct Pipe {
    /// Clock used to check the installed I/O deadlines.
    clock: Clock,
    /// Most bytes the buffer holds before writers wait.
    capacity: usize,
    /// Buffered bytes and the open state of both ends.
    state: Mutex<State>,
    /// Signal waking readers and writers when the buffer or either end changes.
    changed: Condvar,
}

/// Contents of a pipe and the open state of its two ends.
#[derive(Debug)]
struct State {
    /// Bytes written and not yet read.
    bytes: VecDeque<u8>,
    /// Whether the reading end is open.
    reader_open: bool,
    /// Whether the writing end is open.
    writer_open: bool,
    /// Whether the reader closed with accepted output still unconsumed.
    lost: bool,
    /// Operations parked in a wait, counted for tests to observe.
    #[cfg(test)]
    waiting: usize,
    /// Whether a wait fails instead of blocking, so a test cannot hang.
    #[cfg(test)]
    waits_forbidden: bool,
}

impl Pipe {
    /// Creates an open, empty pipe holding up to `capacity` bytes, waiting on
    /// `clock`.
    fn new(capacity: usize, clock: &Clock) -> Self {
        Self {
            clock: clock.clone(),
            capacity,
            state: Mutex::new(State {
                bytes: VecDeque::with_capacity(capacity),
                reader_open: true,
                writer_open: true,
                lost: false,
                #[cfg(test)]
                waiting: 0,
                #[cfg(test)]
                waits_forbidden: false,
            }),
            changed: Condvar::new(clock),
        }
    }

    /// Locks the pipe state, recovering it from a poisoned mutex.
    fn lock(&self) -> MutexGuard<'_, State> {
        // Shutdown must remain usable even after a panic in an I/O operation
        self.state.lock().unwrap_or_else(|err| err.into_inner())
    }

    /// Releases the buffer until notified or the installed deadline is reached.
    fn wait<'a>(
        &self,
        state: MutexGuard<'a, State>,
        deadline: Option<Instant>,
    ) -> MutexGuard<'a, State> {
        // Let tests observe the wait before it releases the mutex, or refuse it
        #[cfg(test)]
        let state = {
            let mut state = state;
            assert!(!state.waits_forbidden, "memory pipe waited");
            state.waiting += 1;
            self.changed.notify_all();
            state
        };

        // Release the buffer lock until notified or the current budget runs out
        let state = match deadline {
            Some(deadline) => {
                self.changed
                    .wait_deadline(state, deadline)
                    .unwrap_or_else(|err| err.into_inner())
                    .0
            }
            None => self
                .changed
                .wait(state)
                .unwrap_or_else(|err| err.into_inner()),
        };

        // Remove the test's waiter count after the buffer lock is retaken
        #[cfg(test)]
        let state = {
            let mut state = state;
            state.waiting -= 1;
            state
        };
        state
    }

    /// Refuses an expired deadline using the pipe's clock on every attempt.
    fn check_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        if deadline.is_some_and(|deadline| self.clock.now() >= deadline) {
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok(())
    }

    /// Closes the reading end and discards unread bytes, marking them lost for
    /// the writer's flush, then wakes both ends.
    fn close_reader(&self) {
        let mut state = self.lock();
        state.reader_open = false;
        state.lost |= !state.bytes.is_empty();
        state.bytes.clear();
        drop(state);
        self.changed.notify_all();
    }

    /// Closes the writing end, so the reader gets EOF once the buffer drains,
    /// then wakes both ends.
    fn close_writer(&self) {
        self.lock().writer_open = false;
        self.changed.notify_all();
    }
}

/// Checks the in-memory streams' byte order, deadlines, backpressure and
/// shutdown.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::transport::Closer;
    use crate::transport::testing::test_clock;
    use darkbio_clock::TestClock;
    use std::io::{Read as _, Write as _};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    /// Budget of 50 ms for the timeout and reuse checks.
    const TIMEOUT: Duration = Duration::from_millis(50);

    /// Splits a stream into its halves and a closer, without closing it.
    fn halves(stream: Duplex) -> (Reader, Writer, Closer) {
        let closer = stream.closer();
        let (reader, writer) = stream.into_halves();
        (reader, writer, closer)
    }

    /// Waits until an operation has released its mutex in a condition-variable wait.
    fn blocked(pipe: &Pipe) {
        let mut state = pipe.lock();
        while state.waiting == 0 {
            state = pipe.changed.wait(state).unwrap();
        }
    }

    /// Checks that a read blocked on an empty pipe expires when its clock
    /// reaches the installed deadline.
    #[test]
    fn test_blocked_read_expires_on_clock_deadline() {
        // Park an empty read with a deadline a day ahead of real time
        let mut tester = TestClock::new();
        tester.advance(Duration::from_secs(86400));
        let clock = tester.clock();
        let (host, _peer) = duplex(1, &clock);
        let (mut reader, _writer) = host.into_halves();
        let deadline = clock.now() + Duration::from_secs(5);
        reader.set_read_deadline(Some(deadline)).unwrap();
        let reading = thread::spawn(move || reader.read(&mut [0]));
        tester.wait_blocked(1);
        assert_eq!(tester.next_deadline(), Some(deadline));

        // Advance exactly to expiry and observe the blocked operation returning
        tester.advance_to(deadline);
        assert_eq!(
            reading.join().unwrap().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    /// Checks that a write blocked on a full pipe expires when its clock
    /// reaches the installed deadline.
    #[test]
    fn test_blocked_write_expires_on_clock_deadline() {
        // Fill the pipe and park another write on the same fixed deadline
        let mut tester = TestClock::new();
        tester.advance(Duration::from_secs(86400));
        let clock = tester.clock();
        let (host, _peer) = duplex(1, &clock);
        let (_reader, mut writer) = host.into_halves();
        writer.write_all(b"a").unwrap();
        let deadline = clock.now() + Duration::from_secs(5);
        writer.set_write_deadline(deadline).unwrap();
        let writing = thread::spawn(move || writer.write(b"b"));
        tester.wait_blocked(1);
        assert_eq!(tester.next_deadline(), Some(deadline));

        // Advance exactly to expiry and observe the blocked operation returning
        tester.advance_to(deadline);
        assert_eq!(
            writing.join().unwrap().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    /// Checks that an expired read delivers available input before reporting
    /// expiry on the empty pipe.
    #[test]
    fn test_read_delivers_buffered_bytes_after_deadline() {
        // Buffer input before the installed read deadline
        let mut tester = test_clock();
        let clock = tester.clock();
        let (host, peer) = duplex(1, &clock);
        let (mut reader, _writer) = host.into_halves();
        let (_peer_reader, mut writer) = peer.into_halves();
        let deadline = clock.now() + Duration::from_secs(5);
        reader.set_read_deadline(Some(deadline)).unwrap();
        writer.write_all(b"a").unwrap();

        // Read buffered bytes at expiry without entering a condvar wait
        tester.advance_to(deadline);
        reader.forbid_waits();
        let mut byte = [0];
        assert_eq!(reader.read(&mut byte).unwrap(), 1);
        assert_eq!(&byte, b"a");

        // Derive expiry from the clock once input is exhausted
        assert_eq!(
            reader.read(&mut byte).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    /// Checks that a zero-capacity pipe is rejected at construction, before
    /// any I/O can wait.
    #[test]
    #[should_panic(expected = "duplex capacity must be nonzero")]
    fn test_zero_capacity() {
        duplex(0, &test_clock().clock());
    }

    /// Checks that partial reads and writes keep byte order across queue
    /// wraparound, with independent read and write deadlines.
    ///
    /// The deadlines stay independent for empty I/O and flush too.
    #[test]
    fn test_byte_stream_and_independent_deadlines() {
        // Create both directions on one paused clock
        let tester = test_clock();
        let clock = tester.clock();
        let (host, ark) = duplex(4, &clock);
        let (mut host_read, mut host_write, _host_close) = halves(host);
        let (mut ark_read, mut ark_write, _ark_close) = halves(ark);

        // Preserve byte order across partial writes and queue wraparound
        assert_eq!(host_read.read(&mut []).unwrap(), 0);
        assert_eq!(host_write.write(b"abcdef").unwrap(), 4);
        assert_eq!(host_write.write(&[]).unwrap(), 0);
        // Flush succeeds even while the queue is full
        host_write.flush().unwrap();
        let mut first = [0; 2];
        ark_read.read_exact(&mut first).unwrap();
        assert_eq!(&first, b"ab");
        host_write.write_all(b"ef").unwrap();
        let mut rest = [0; 4];
        ark_read.read_exact(&mut rest).unwrap();
        assert_eq!(&rest, b"cdef");

        // Deliver buffered input before reporting its expired deadline
        ark_write.write_all(b"xy").unwrap();
        host_read.set_read_deadline(Some(clock.now())).unwrap();
        host_read.read_exact(&mut first).unwrap();
        assert_eq!(&first, b"xy");
        assert_eq!(
            host_read.read(&mut first).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(host_read.read(&mut []).unwrap(), 0);
        host_write.write_all(b"q").unwrap();

        // Expire output while input remains usable
        host_write.set_write_deadline(clock.now()).unwrap();
        host_read.set_read_deadline(None).unwrap();
        ark_write.write_all(b"uv").unwrap();
        host_read.read_exact(&mut first).unwrap();
        assert_eq!(&first, b"uv");
        for bytes in [b"t".as_slice(), b""] {
            assert_eq!(
                host_write.write(bytes).unwrap_err().kind(),
                io::ErrorKind::TimedOut
            );
        }
        assert_eq!(
            host_write.flush().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );

        // Resume output with a fresh deadline
        host_write
            .set_write_deadline(clock.now() + Duration::from_secs(5))
            .unwrap();
        host_write.write_all(b"rs").unwrap();
        host_write.flush().unwrap();
        let mut accepted = [0; 3];
        ark_read.read_exact(&mut accepted).unwrap();
        assert_eq!(&accepted, b"qrs");
    }

    /// Checks that an idle timed read expires without EOF or buffer changes,
    /// and clearing its deadline restores an indefinite read.
    #[test]
    fn test_read_timeout_and_reuse() {
        // Park an empty read on a deadline ahead of the paused clock
        let mut tester = test_clock();
        let clock = tester.clock();
        let deadline = clock.now() + TIMEOUT;
        let (host, ark) = duplex(1, &clock);
        let (mut reader, _host_write, _host_close) = halves(host);
        let (_ark_read, mut writer, _ark_close) = halves(ark);
        let pipe = reader.pipe.clone();
        let (done, result) = mpsc::channel();
        let timed = thread::spawn(move || {
            reader.set_read_deadline(Some(deadline)).unwrap();
            let mut buf = [99];
            let error = reader.read(&mut buf).unwrap_err();
            assert!(clock.now() >= deadline);
            assert_eq!(buf, [99]);
            done.send((reader, error.kind())).unwrap();
        });
        tester.wait_blocked(1);
        tester.advance_to(deadline);
        let (mut reader, kind) = result.recv().unwrap();
        timed.join().unwrap();
        assert_eq!(kind, io::ErrorKind::TimedOut);

        // Clear expiry and wake a new indefinite read with input
        reader.set_read_deadline(None).unwrap();
        let (done, result) = mpsc::channel();
        let reading = thread::spawn(move || {
            let mut buf = [0];
            reader.read_exact(&mut buf).unwrap();
            done.send(buf).unwrap();
        });
        blocked(&pipe);
        writer.write_all(b"x").unwrap();
        assert_eq!(&result.recv().unwrap(), b"x");
        reading.join().unwrap();
    }

    /// Checks that a later write follows the prefix a `write_all` accepted
    /// before timing out, without the abandoned suffix appearing afterwards.
    #[test]
    fn test_write_timeout_and_reuse() {
        // Fill the pipe and park the remaining byte until its deadline
        let mut tester = test_clock();
        let clock = tester.clock();
        let deadline = clock.now() + TIMEOUT;
        let (host, ark) = duplex(3, &clock);
        let (_host_read, mut writer, _host_close) = halves(host);
        let (mut reader, _ark_write, _ark_close) = halves(ark);
        let (done, result) = mpsc::channel();
        let writing = thread::spawn(move || {
            writer.set_write_deadline(deadline).unwrap();
            let error = writer.write_all(b"abcd").unwrap_err();
            assert!(clock.now() >= deadline);
            done.send((writer, error.kind())).unwrap();
        });
        tester.wait_blocked(1);
        tester.advance_to(deadline);
        let (mut writer, kind) = result.recv().unwrap();
        writing.join().unwrap();
        assert_eq!(kind, io::ErrorKind::TimedOut);
        let mut prefix = [0; 3];
        reader.read_exact(&mut prefix).unwrap();
        assert_eq!(&prefix, b"abc");

        // Resume output after the accepted prefix with a fresh deadline
        writer
            .set_write_deadline(tester.clock().now() + Duration::from_secs(5))
            .unwrap();
        writer.write_all(b"ef").unwrap();
        drop(writer);
        let mut suffix = Vec::new();
        reader.read_to_end(&mut suffix).unwrap();
        assert_eq!(&suffix, b"ef");
    }

    /// Checks that draining a full queue wakes its writer through several
    /// partial writes, while bounded reads rebuild the original byte stream.
    #[test]
    fn test_backpressure_wakes_writer() {
        // Fill a paused pipe and start a writer behind its queued bytes
        let tester = test_clock();
        let deadline = tester.clock().now() + Duration::from_secs(5);
        let (host, ark) = duplex(3, &tester.clock());
        let (_host_read, mut writer, _host_close) = halves(host);
        let (mut reader, _ark_write, _ark_close) = halves(ark);
        writer.write_all(b"abc").unwrap();
        let pipe = writer.pipe.clone();
        let (done, result) = mpsc::channel();
        let writing = thread::spawn(move || {
            writer.set_write_deadline(deadline).unwrap();
            done.send(writer.write_all(b"defgh")).unwrap();
        });

        // Drain the pipe after the writer has parked
        blocked(&pipe);
        reader.set_read_deadline(Some(deadline)).unwrap();
        let mut bytes = [0; 8];
        reader.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"abcdefgh");
        result.recv().unwrap().unwrap();
        writing.join().unwrap();
    }

    /// Checks that a local shutdown and dropping the peer both release blocked
    /// reads and writes, including ones without a deadline.
    #[test]
    fn test_shutdown_wakes_both_directions() {
        for local in [false, true] {
            // Start a blocked read and a blocked write on the same clock
            let tester = test_clock();
            let (host, ark) = duplex(1, &tester.clock());
            let (mut reader, mut writer, closer) = halves(host);
            writer.write_all(b"a").unwrap();
            let incoming = reader.pipe.clone();
            let outgoing = writer.pipe.clone();
            let (read_done, read_result) = mpsc::channel();
            let reading = thread::spawn(move || {
                read_done.send(reader.read(&mut [0])).unwrap();
            });
            let (write_done, write_result) = mpsc::channel();
            let writing = thread::spawn(move || {
                write_done.send(writer.write(b"b")).unwrap();
            });

            // Close only after both adapter calls have parked
            blocked(&incoming);
            blocked(&outgoing);
            if local {
                closer.close();
            } else {
                drop(ark);
            }
            assert_eq!(read_result.recv().unwrap().unwrap(), 0);
            assert_eq!(
                write_result.recv().unwrap().unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
            reading.join().unwrap();
            writing.join().unwrap();
        }
    }

    /// Checks that closing discards local input but lets the peer drain accepted
    /// output before EOF, even while the halves are still held.
    #[test]
    fn test_shutdown_drains_output_and_discards_input() {
        // Queue bytes in both directions on a paused clock
        let tester = test_clock();
        let clock = tester.clock();
        let (host, ark) = duplex(3, &clock);
        let (mut host_read, mut host_write, closer) = halves(host);
        let (mut ark_read, mut ark_write, _ark_close) = halves(ark);
        host_write.write_all(b"abc").unwrap();
        ark_write.write_all(b"xy").unwrap();
        host_read.set_read_deadline(Some(clock.now())).unwrap();
        ark_read.set_read_deadline(Some(clock.now())).unwrap();

        // Close twice and retain only the peer's accepted input
        closer.close();
        closer.close();
        assert_eq!(host_read.read(&mut [0]).unwrap(), 0);
        let mut bytes = Vec::new();
        ark_read.read_to_end(&mut bytes).unwrap();
        assert_eq!(&bytes, b"abc");
        for writer in [&mut host_write, &mut ark_write] {
            assert_eq!(
                writer.write(b"z").unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
            assert_eq!(
                writer.flush().unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
        }
    }

    /// Checks that a flush succeeds after the peer consumed every accepted byte
    /// and closed, while new output fails.
    #[test]
    fn test_flush_after_peer_drained_and_closed() {
        // Drain the accepted output before closing the peer
        let tester = test_clock();
        let (host, ark) = duplex(4, &tester.clock());
        let (_host_read, mut host_write) = host.into_halves();
        let (mut ark_read, _ark_write) = ark.into_halves();
        host_write.write_all(b"ab").unwrap();
        let mut bytes = [0; 2];
        ark_read.read_exact(&mut bytes).unwrap();
        drop(ark_read);

        // Allow a flush but reject any new output
        host_write.flush().unwrap();
        assert_eq!(
            host_write.write(b"c").unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    /// Checks that splitting discards the write budget without closing the
    /// halves, and dropping one half leaves the other direction usable.
    #[test]
    fn test_into_halves_and_independent_drop() {
        // Split both streams on a paused clock
        let tester = test_clock();
        let (host, ark) = duplex(4, &tester.clock());
        let (mut host_read, mut host_write) = host.set_write_timeout(Duration::ZERO).into_halves();
        let (mut ark_read, mut ark_write) = ark.into_halves();

        // Drop one writer and let its peer drain to EOF
        host_write.write_all(b"abc").unwrap();
        drop(host_write);
        let mut bytes = Vec::new();
        ark_read.read_to_end(&mut bytes).unwrap();
        assert_eq!(&bytes, b"abc");

        // Keep the opposite direction usable until its own reader drops
        ark_write.write_all(b"xy").unwrap();
        let mut reply = [0; 2];
        host_read.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"xy");
        drop(host_read);
        assert_eq!(
            ark_write.write(b"z").unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    /// Checks that protocol peers exchange a message larger than the pipe both
    /// ways, then close while their transport readers wait for input.
    #[test]
    fn test_protocol_round_trip() {
        use crate::protocol::{self, Message};
        use crate::transport::mock::self_attestation;
        use darkbio_crypto::xdsa;

        // Connect protocol peers on a paused clock
        let tester = test_clock();
        let signer = xdsa::SecretKey::generate();
        let identity = signer.public_key();
        let attestation = self_attestation(&signer);
        let (host, ark) = duplex(64 * 1024, &tester.clock());
        let mut server = protocol::Server::new(ark, signer, attestation);
        let (client, _) = protocol::connect(host, &identity).unwrap();
        let mut session = server.accept().unwrap();

        // Exchange a payload larger than the bounded transport pipe
        let payload: Vec<u8> = (0..256 * 1024).map(|n| n as u8).collect();
        let deadline = tester.clock().now() + Duration::from_secs(5);
        let answer = client
            .requester()
            .request(payload.clone(), deadline)
            .unwrap();
        let (message, responder) = session.recv().unwrap();
        assert_eq!(message, Message::Develop(payload.clone()));
        let written = responder.reply(message, deadline).unwrap();
        assert_eq!(answer.wait::<Vec<u8>>().unwrap(), payload);
        written.wait().unwrap();

        // Release both protocol owners after delivery
        client.close();
        server.close();
    }
}
