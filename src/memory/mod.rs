// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Portable in-memory streams for local connections, emulators and tests.
//!
//! These streams use only standard Rust synchronization, with no sockets or
//! worker threads. Split an endpoint with [`Duplex::into_halves`] for plain I/O.

use crate::transport::{Read, Stream, Write};
use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// One endpoint of an in-memory duplex connection, ready for a client or server.
pub type Duplex = Stream<Reader, Writer>;

impl Duplex {
    /// Takes the reader and writer out of the stream without closing either half.
    ///
    /// Each half closes its own direction on drop. Dropping the writer lets the
    /// peer drain accepted output before EOF; dropping the reader refuses further
    /// peer writes. Obtain a [`crate::transport::Closer`] with [`Self::closer`] before splitting
    /// if you need to shut down both halves from another thread.
    ///
    /// The stream's write timeout is discarded. Any deadlines already installed
    /// on the halves are retained; new halves have no deadline until configured.
    ///
    /// ```
    /// use darkbio_wire::memory;
    /// use darkbio_wire::transport::Client;
    ///
    /// let (host, bus) = memory::duplex(64 * 1024);
    /// let (reader, writer) = bus.into_halves();
    /// let client = Client::new(host);
    /// // Move `reader` and `writer` to the bus's input and output pumps.
    /// ```
    pub fn into_halves(self) -> (Reader, Writer) {
        let (reader, writer, _, _) = self.into_parts();
        (reader, writer)
    }
}

/// Creates two connected streams with `capacity` bytes of buffering per direction.
///
/// Reads wait for data and writes wait for buffer space, bounded by the deadlines
/// installed by Wire. Partial progress never refreshes a deadline. A timeout
/// leaves the connection reusable and preserves any bytes already accepted.
/// Flush checks its deadline but does not wait for the peer to consume output.
/// Reads deliver available bytes, EOF and empty reads even after their deadline;
/// the deadline only limits waiting for input. Writes and flushes refuse expired
/// deadlines even if buffer space is available. Wire enforces its own deadlines
/// before calling either half.
///
/// Closing or dropping an endpoint wakes blocked I/O on both sides. Its unread
/// input is discarded; the peer can drain its accepted output before receiving
/// EOF. Further nonempty writes fail with [`io::ErrorKind::BrokenPipe`]. A flush
/// fails the same way only if the peer closed with accepted output still unread.
/// Output the peer had consumed before closing flushes fine afterwards.
///
/// Both peers must run concurrently when exchanging data. Allow enough capacity
/// for the handshake's initial output; `64 * 1024` is a useful starting point.
/// Small buffers can cause handshake backpressure, just as a real stream can.
///
/// # Panics
///
/// Panics if `capacity` is zero.
pub fn duplex(capacity: usize) -> (Duplex, Duplex) {
    assert!(capacity > 0, "duplex capacity must be nonzero");
    let incoming = Arc::new(Pipe::new(capacity));
    let outgoing = Arc::new(Pipe::new(capacity));
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
    pipe: Arc<Pipe>,
    deadline: Option<Instant>,
}

impl io::Read for Reader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut state = self.pipe.lock();
        loop {
            if buf.is_empty() || !state.reader_open {
                return Ok(0);
            }
            if !state.bytes.is_empty() {
                let count = buf.len().min(state.bytes.len());
                for (out, byte) in buf.iter_mut().zip(state.bytes.drain(..count)) {
                    *out = byte;
                }
                drop(state);
                self.pipe.changed.notify_all();
                return Ok(count);
            }
            if !state.writer_open {
                return Ok(0);
            }
            state = self.pipe.wait(state, time_left(self.deadline)?);
        }
    }
}

impl Read for Reader {
    fn set_read_deadline(&mut self, deadline: Option<Instant>) -> io::Result<()> {
        self.deadline = deadline;
        Ok(())
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        self.pipe.close_reader();
    }
}

/// Sending half of a [`Duplex`], sharing one deadline across writes and flushes.
#[derive(Debug)]
pub struct Writer {
    pipe: Arc<Pipe>,
    deadline: Option<Instant>,
}

impl io::Write for Writer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut state = self.pipe.lock();
        loop {
            let timeout = time_left(self.deadline)?;
            if buf.is_empty() {
                return Ok(0);
            }
            if !state.reader_open || !state.writer_open {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            let count = buf.len().min(self.pipe.capacity - state.bytes.len());
            if count > 0 {
                state.bytes.extend(&buf[..count]);
                drop(state);
                self.pipe.changed.notify_all();
                return Ok(count);
            }
            state = self.pipe.wait(state, timeout);
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let state = self.pipe.lock();
        time_left(self.deadline)?;
        if !state.writer_open || state.lost {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        Ok(())
    }
}

impl Write for Writer {
    fn set_write_deadline(&mut self, deadline: Instant) -> io::Result<()> {
        self.deadline = Some(deadline);
        Ok(())
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        self.pipe.close_writer();
    }
}

/// Shared bounded buffer for one direction. Waiting always releases the mutex.
#[derive(Debug)]
struct Pipe {
    capacity: usize,
    state: Mutex<State>,
    changed: Condvar,
}

#[derive(Debug)]
struct State {
    bytes: VecDeque<u8>,
    reader_open: bool,
    writer_open: bool,
    lost: bool, // Accepted output the reader closed without consuming
    #[cfg(test)]
    waiting: usize,
}

impl Pipe {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            state: Mutex::new(State {
                bytes: VecDeque::with_capacity(capacity),
                reader_open: true,
                writer_open: true,
                lost: false,
                #[cfg(test)]
                waiting: 0,
            }),
            changed: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // Shutdown must remain usable even after a panic in an I/O operation.
        self.state.lock().unwrap_or_else(|err| err.into_inner())
    }

    fn wait<'a>(
        &self,
        state: MutexGuard<'a, State>,
        timeout: Option<Duration>,
    ) -> MutexGuard<'a, State> {
        #[cfg(test)]
        let state = {
            let mut state = state;
            state.waiting += 1;
            self.changed.notify_all();
            state
        };
        let state = match timeout {
            Some(timeout) => {
                self.changed
                    .wait_timeout(state, timeout)
                    .unwrap_or_else(|err| err.into_inner())
                    .0
            }
            None => self
                .changed
                .wait(state)
                .unwrap_or_else(|err| err.into_inner()),
        };
        #[cfg(test)]
        let state = {
            let mut state = state;
            state.waiting -= 1;
            state
        };
        state
    }

    fn close_reader(&self) {
        let mut state = self.lock();
        state.reader_open = false;
        state.lost |= !state.bytes.is_empty();
        state.bytes.clear();
        drop(state);
        self.changed.notify_all();
    }

    fn close_writer(&self) {
        self.lock().writer_open = false;
        self.changed.notify_all();
    }
}

/// Computes a fresh wait budget without extending the installed deadline.
fn time_left(deadline: Option<Instant>) -> io::Result<Option<Duration>> {
    deadline
        .map(|deadline| {
            deadline
                .checked_duration_since(Instant::now())
                .filter(|left| !left.is_zero())
                .ok_or_else(|| io::ErrorKind::TimedOut.into())
        })
        .transpose()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::transport::Closer;
    use std::io::{Read as _, Write as _};
    use std::sync::mpsc;
    use std::thread;

    const PATIENCE: Duration = Duration::from_secs(5);
    const TIMEOUT: Duration = Duration::from_millis(50);

    /// Exposes standard I/O for adapter tests without closing the stream.
    fn halves(stream: Duplex) -> (Reader, Writer, Closer) {
        let closer = stream.closer();
        let (reader, writer) = stream.into_halves();
        (reader, writer, closer)
    }

    /// Waits until an operation has released its mutex in a condition-variable wait.
    fn blocked(pipe: &Pipe) {
        let deadline = Instant::now() + PATIENCE;
        let mut state = pipe.lock();
        while state.waiting == 0 {
            let timeout = deadline.checked_duration_since(Instant::now()).unwrap();
            state = pipe.changed.wait_timeout(state, timeout).unwrap().0;
        }
    }

    #[test]
    #[should_panic(expected = "duplex capacity must be nonzero")]
    fn test_zero_capacity() {
        duplex(0);
    }

    // Partial reads and writes preserve byte order across queue wraparound. Read
    // and write deadlines remain independent, including empty I/O and flush.
    #[test]
    fn test_byte_stream_and_independent_deadlines() {
        let (host, ark) = duplex(4);
        let (mut host_read, mut host_write, _host_close) = halves(host);
        let (mut ark_read, mut ark_write, _ark_close) = halves(ark);

        assert_eq!(host_read.read(&mut []).unwrap(), 0);
        assert_eq!(host_write.write(b"abcdef").unwrap(), 4);
        assert_eq!(host_write.write(&[]).unwrap(), 0);
        // Flush succeeds even while the queue is full.
        host_write.flush().unwrap();
        let mut first = [0; 2];
        ark_read.read_exact(&mut first).unwrap();
        assert_eq!(&first, b"ab");
        host_write.write_all(b"ef").unwrap();
        let mut rest = [0; 4];
        ark_read.read_exact(&mut rest).unwrap();
        assert_eq!(&rest, b"cdef");

        ark_write.write_all(b"xy").unwrap();
        host_read.set_read_deadline(Some(Instant::now())).unwrap();
        host_read.read_exact(&mut first).unwrap();
        assert_eq!(&first, b"xy");
        assert_eq!(
            host_read.read(&mut first).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(host_read.read(&mut []).unwrap(), 0);
        host_write.write_all(b"q").unwrap();

        host_write.set_write_deadline(Instant::now()).unwrap();
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

        host_write
            .set_write_deadline(Instant::now() + PATIENCE)
            .unwrap();
        host_write.write_all(b"rs").unwrap();
        host_write.flush().unwrap();
        let mut accepted = [0; 3];
        ark_read.read_exact(&mut accepted).unwrap();
        assert_eq!(&accepted, b"qrs");
    }

    // An idle timed read neither reports EOF nor changes the caller's buffer.
    // Clearing that deadline restores an indefinite read, woken by fresh output.
    #[test]
    fn test_read_timeout_and_reuse() {
        let (host, ark) = duplex(1);
        let (mut reader, _host_write, _host_close) = halves(host);
        let (_ark_read, mut writer, _ark_close) = halves(ark);
        let pipe = reader.pipe.clone();
        let (done, result) = mpsc::channel();
        let timed = thread::spawn(move || {
            let deadline = Instant::now() + TIMEOUT;
            reader.set_read_deadline(Some(deadline)).unwrap();
            let mut buf = [99];
            let error = reader.read(&mut buf).unwrap_err();
            assert!(Instant::now() >= deadline);
            assert_eq!(buf, [99]);
            done.send((reader, error.kind())).unwrap();
        });
        let (mut reader, kind) = result.recv_timeout(PATIENCE).unwrap();
        timed.join().unwrap();
        assert_eq!(kind, io::ErrorKind::TimedOut);

        reader.set_read_deadline(None).unwrap();
        let (done, result) = mpsc::channel();
        let reading = thread::spawn(move || {
            let mut buf = [0];
            reader.read_exact(&mut buf).unwrap();
            done.send(buf).unwrap();
        });
        blocked(&pipe);
        writer.write_all(b"x").unwrap();
        assert_eq!(&result.recv_timeout(PATIENCE).unwrap(), b"x");
        reading.join().unwrap();
    }

    // write_all can accept a prefix before timing out on backpressure. A later
    // write must follow that prefix, without an abandoned suffix appearing later.
    #[test]
    fn test_write_timeout_and_reuse() {
        let (host, ark) = duplex(3);
        let (_host_read, mut writer, _host_close) = halves(host);
        let (mut reader, _ark_write, _ark_close) = halves(ark);
        let (done, result) = mpsc::channel();
        let writing = thread::spawn(move || {
            let deadline = Instant::now() + TIMEOUT;
            writer.set_write_deadline(deadline).unwrap();
            let error = writer.write_all(b"abcd").unwrap_err();
            assert!(Instant::now() >= deadline);
            done.send((writer, error.kind())).unwrap();
        });
        let (mut writer, kind) = result.recv_timeout(PATIENCE).unwrap();
        writing.join().unwrap();
        assert_eq!(kind, io::ErrorKind::TimedOut);
        let mut prefix = [0; 3];
        reader.read_exact(&mut prefix).unwrap();
        assert_eq!(&prefix, b"abc");

        writer
            .set_write_deadline(Instant::now() + PATIENCE)
            .unwrap();
        writer.write_all(b"ef").unwrap();
        drop(writer);
        let mut suffix = Vec::new();
        reader.read_to_end(&mut suffix).unwrap();
        assert_eq!(&suffix, b"ef");
    }

    // Draining a full queue wakes its writer and permits progress through multiple
    // partial writes, while bounded reads reconstruct the original byte stream.
    #[test]
    fn test_backpressure_wakes_writer() {
        let (host, ark) = duplex(3);
        let (_host_read, mut writer, _host_close) = halves(host);
        let (mut reader, _ark_write, _ark_close) = halves(ark);
        writer.write_all(b"abc").unwrap();
        let pipe = writer.pipe.clone();
        let (done, result) = mpsc::channel();
        let writing = thread::spawn(move || {
            writer
                .set_write_deadline(Instant::now() + PATIENCE)
                .unwrap();
            done.send(writer.write_all(b"defgh")).unwrap();
        });
        blocked(&pipe);
        reader
            .set_read_deadline(Some(Instant::now() + PATIENCE))
            .unwrap();
        let mut bytes = [0; 8];
        reader.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"abcdefgh");
        result.recv_timeout(PATIENCE).unwrap().unwrap();
        writing.join().unwrap();
    }

    // Explicit local shutdown and dropping the peer both release already blocked
    // reads and writes, including operations that have no deadline at all.
    #[test]
    fn test_shutdown_wakes_both_directions() {
        for local in [false, true] {
            let (host, ark) = duplex(1);
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
            blocked(&incoming);
            blocked(&outgoing);
            if local {
                closer.close();
            } else {
                drop(ark);
            }
            assert_eq!(read_result.recv_timeout(PATIENCE).unwrap().unwrap(), 0);
            assert_eq!(
                write_result
                    .recv_timeout(PATIENCE)
                    .unwrap()
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::BrokenPipe
            );
            reading.join().unwrap();
            writing.join().unwrap();
        }
    }

    // Closing discards local input but preserves accepted output for the peer to
    // drain before EOF. Keeping the handles alive must not keep the connection open.
    #[test]
    fn test_shutdown_drains_output_and_discards_input() {
        let (host, ark) = duplex(3);
        let (mut host_read, mut host_write, closer) = halves(host);
        let (mut ark_read, mut ark_write, _ark_close) = halves(ark);
        host_write.write_all(b"abc").unwrap();
        ark_write.write_all(b"xy").unwrap();
        host_read.set_read_deadline(Some(Instant::now())).unwrap();
        ark_read.set_read_deadline(Some(Instant::now())).unwrap();
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

    // A peer that consumed every accepted byte before closing does not fail a
    // later flush. Only output it closed without reading is reported as lost.
    #[test]
    fn test_flush_after_peer_drained_and_closed() {
        let (host, ark) = duplex(4);
        let (_host_read, mut host_write) = host.into_halves();
        let (mut ark_read, _ark_write) = ark.into_halves();
        host_write.write_all(b"ab").unwrap();
        let mut bytes = [0; 2];
        ark_read.read_exact(&mut bytes).unwrap();
        drop(ark_read);
        host_write.flush().unwrap();
        assert_eq!(
            host_write.write(b"c").unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    // Splitting drops the stream's closer and output budget without closing
    // its halves. Dropping one half still permits I/O in the other direction.
    #[test]
    fn test_into_halves_and_independent_drop() {
        let (host, ark) = duplex(4);
        let (mut host_read, mut host_write) = host.set_write_timeout(Duration::ZERO).into_halves();
        let (mut ark_read, mut ark_write) = ark.into_halves();

        host_write.write_all(b"abc").unwrap();
        drop(host_write);
        let mut bytes = Vec::new();
        ark_read.read_to_end(&mut bytes).unwrap();
        assert_eq!(&bytes, b"abc");

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

    // Real protocol workers exchange a message larger than the pipe in both
    // directions, then close while their transport readers are waiting for input.
    #[test]
    fn test_protocol_round_trip() {
        use crate::protocol::{self, Message};
        use crate::transport::mock::self_attestation;
        use darkbio_crypto::xdsa;

        let signer = xdsa::SecretKey::generate();
        let identity = signer.public_key();
        let attestation = self_attestation(&signer);
        let (host, ark) = duplex(64 * 1024);
        let mut server = protocol::Server::new(ark, signer, attestation);
        let (client, _) = protocol::connect(host, &identity).unwrap();
        let mut session = server.accept().unwrap();
        let payload: Vec<u8> = (0..256 * 1024).map(|n| n as u8).collect();
        let deadline = Instant::now() + PATIENCE;
        let answer = client
            .requester()
            .request(payload.clone(), deadline)
            .unwrap();
        let (message, responder) = session.recv().unwrap();
        assert_eq!(message, Message::Develop(payload.clone()));
        let written = responder.reply(message, deadline).unwrap();
        assert_eq!(answer.wait::<Vec<u8>>().unwrap(), payload);
        written.wait().unwrap();
        client.close();
        server.close();
    }
}
