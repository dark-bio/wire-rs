// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Private fixtures shared by the crate's tests.

use crate::transport::{Attester, Error, Event, Read, Sender, Server, Write};
use darkbio_clock::{Clock, crossbeam_channel as mpsc};
use std::io;
use std::sync::{Arc, Once};
use std::time::{Duration, Instant};

/// Guard installing the test logger once per process.
static INIT: Once = Once::new();

/// A one-shot gate whose wait is visible to the scenario's paused clock.
#[derive(Clone)]
pub struct Gate {
    /// Shared release state and its clock-aware notification.
    inner: Arc<(
        darkbio_clock::sync::Mutex<bool>,
        darkbio_clock::sync::Condvar,
    )>,
}

impl Gate {
    /// Creates a closed gate on the supplied clock.
    pub fn new(clock: &Clock) -> Self {
        Self {
            inner: Arc::new((
                darkbio_clock::sync::Mutex::new(false),
                darkbio_clock::sync::Condvar::new(clock),
            )),
        }
    }

    /// Parks until released or until the optional deadline expires on the
    /// gate's clock.
    ///
    /// An expired deadline returns a `TimedOut` error.
    pub fn wait(&self, deadline: Option<Instant>) -> io::Result<()> {
        let mut open = self.inner.0.lock().unwrap();
        while !*open {
            open = match deadline {
                Some(deadline) => {
                    let (open, timeout) = self.inner.1.wait_deadline(open, deadline).unwrap();
                    if timeout.timed_out() && !*open {
                        return Err(io::ErrorKind::TimedOut.into());
                    }
                    open
                }
                None => self.inner.1.wait(open).unwrap(),
            };
        }
        Ok(())
    }

    /// Releases the current wait and every later wait.
    pub fn open(&self) {
        *self.inner.0.lock().unwrap() = true;
        self.inner.1.notify_all();
    }
}

/// Receiving end of a test pipe, retaining unread bytes across bounded reads.
pub struct PipeReader {
    /// Clock governing read deadlines.
    clock: Clock,
    /// Chunks queued by the writer.
    incoming: mpsc::Receiver<Vec<u8>>,
    /// Unconsumed bytes of the current chunk.
    buffered: io::Cursor<Vec<u8>>,
    /// Latest read deadline.
    deadline: Option<Instant>,
}

/// Sending end of an unbounded test pipe, closed when its owner is dropped.
pub struct PipeWriter {
    /// Clock governing write deadlines.
    clock: Clock,
    /// Queue consumed by the reader.
    outgoing: mpsc::Sender<Vec<u8>>,
    /// Latest write deadline.
    deadline: Option<Instant>,
}

/// Creates an in-memory pipe whose output never waits for the reader.
///
/// Reads and writes observe the configured deadlines, and have none until one
/// is set. Dropping the writer delivers EOF after its bytes.
pub fn pipe(clock: &Clock) -> (PipeReader, PipeWriter) {
    let (outgoing, incoming) = mpsc::unbounded();
    (
        PipeReader {
            clock: clock.clone(),
            incoming,
            buffered: io::Cursor::new(Vec::new()),
            deadline: None,
        },
        PipeWriter {
            clock: clock.clone(),
            outgoing,
            deadline: None,
        },
    )
}

impl io::Read for PipeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Fail at once if the read deadline has already passed
        if let Some(deadline) = self.deadline {
            remaining(&self.clock, deadline)?;
        }
        if buf.is_empty() {
            return Ok(0);
        }

        // Take the next chunk once the current one is consumed, then read from it
        if self.buffered.position() == self.buffered.get_ref().len() as u64 {
            let incoming = match self.deadline {
                Some(deadline) => self.clock.recv_deadline(&self.incoming, deadline),
                None => self
                    .incoming
                    .recv()
                    .map_err(|_| mpsc::RecvTimeoutError::Disconnected),
            };
            self.buffered = match incoming {
                Ok(bytes) => io::Cursor::new(bytes),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(0),
            };
        }
        io::Read::read(&mut self.buffered, buf)
    }
}

impl Read for PipeReader {
    fn clock(&self) -> Clock {
        self.clock.clone()
    }

    fn set_read_deadline(&mut self, deadline: Option<Instant>) -> io::Result<()> {
        self.deadline = deadline;
        Ok(())
    }
}

impl io::Write for PipeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(deadline) = self.deadline {
            remaining(&self.clock, deadline)?;
        }
        if !buf.is_empty() {
            self.outgoing
                .send(buf.to_vec())
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(deadline) = self.deadline {
            remaining(&self.clock, deadline)?;
        }
        Ok(())
    }
}

impl Write for PipeWriter {
    fn clock(&self) -> Clock {
        self.clock.clone()
    }

    fn set_write_deadline(&mut self, deadline: Instant) -> io::Result<()> {
        self.deadline = Some(deadline);
        Ok(())
    }
}

/// Returns the time an adapter call has left before a deadline.
///
/// A deadline already reached returns a `TimedOut` error.
pub fn remaining(clock: &Clock, deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(clock.now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| io::ErrorKind::TimedOut.into())
}

/// Installs a trace-level logger writing to the test harness's captured output,
/// once per process.
///
/// `RUST_LOG` can still set the levels of specific targets.
pub fn init_tracing() {
    INIT.call_once(|| {
        tracing_subscriber::fmt()
            .without_time()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(tracing::Level::TRACE.into()),
            )
            .with_ansi(true)
            .with_test_writer()
            .init();
    });
}

/// Reads the next message from a transport server, keeping `sender` on the
/// server's current session.
///
/// An [`Event::Connected`] stores its sender and an [`Event::Disconnected`]
/// clears it, for tests exchanging messages across sessions.
pub fn served<R: Read, W: Write, A: Attester>(
    server: &mut Server<R, W, A>,
    sender: &mut Option<Sender<W>>,
) -> Result<Vec<u8>, Error> {
    loop {
        match server.recv()? {
            Event::Connected(opened) => *sender = Some(opened),
            Event::Disconnected => *sender = None,
            Event::Message(message) => return Ok(message),
        }
    }
}
