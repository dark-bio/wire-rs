// wire-rs: encrypted protocol between Ark and host
// Copyright 2025 Dark Bio AG. All rights reserved.

// Allow excluding test code from coverage measurements on nightly
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
// Pull in the README as the package doc
#![doc = include_str!("../README.md")]

pub mod protocol;
pub mod transport;

#[cfg(any(test, feature = "fuzz"))]
#[doc(hidden)]
pub use transport::mock;

pub use protocol::{ArkToHost, HostToArk};
pub use transport::{
    Attestation, Attester, Client, Closer, DEFAULT_HANDSHAKE_TIMEOUT, DEFAULT_WRITE_TIMEOUT, Error,
    MAX_FRAME_SIZE, MAX_MESSAGE_SIZE, Read, Roots, Sender, Server, Stream, Verifier, Write,
};

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod testing {
    use crate::transport::{Attester, Error, Event, Read, Sender, Server, Write};
    use std::io;
    #[cfg(unix)]
    use std::os::unix::net::UnixStream;
    use std::sync::{Once, mpsc};
    use std::time::{Duration, Instant};

    static INIT: Once = Once::new();

    /// Receiving end of a test pipe, retaining unread bytes across bounded reads.
    pub struct PipeReader {
        incoming: mpsc::Receiver<Vec<u8>>,
        buffered: io::Cursor<Vec<u8>>,
        deadline: Option<Instant>,
    }

    /// Sending end of an unbounded test pipe, closed when its owner is dropped.
    pub struct PipeWriter {
        outgoing: mpsc::Sender<Vec<u8>>,
        deadline: Option<Instant>,
    }

    /// Creates an in-memory pipe whose configured deadlines bound reads and whose
    /// output never waits for the reader. Dropping the writer delivers EOF after
    /// its bytes. Direct standard I/O is unlimited until a deadline is configured.
    pub fn pipe() -> (PipeReader, PipeWriter) {
        let (outgoing, incoming) = mpsc::channel();
        (
            PipeReader {
                incoming,
                buffered: io::Cursor::new(Vec::new()),
                deadline: None,
            },
            PipeWriter {
                outgoing,
                deadline: None,
            },
        )
    }

    impl io::Read for PipeReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if let Some(deadline) = self.deadline {
                remaining(deadline)?;
            }
            if buf.is_empty() {
                return Ok(0);
            }
            if self.buffered.position() == self.buffered.get_ref().len() as u64 {
                let incoming = match self.deadline {
                    Some(deadline) => self.incoming.recv_timeout(remaining(deadline)?),
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
        fn set_read_deadline(&mut self, deadline: Option<Instant>) -> io::Result<()> {
            self.deadline = deadline;
            Ok(())
        }
    }

    impl io::Write for PipeWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if let Some(deadline) = self.deadline {
                remaining(deadline)?;
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
                remaining(deadline)?;
            }
            Ok(())
        }
    }

    impl Write for PipeWriter {
        fn set_write_deadline(&mut self, deadline: Instant) -> io::Result<()> {
            self.deadline = Some(deadline);
            Ok(())
        }
    }

    /// Test socket adapter with independent absolute deadlines. Every standard
    /// I/O call recomputes its relative socket timeout so partial progress never
    /// restarts the budget and an expired deadline leaves the socket reusable.
    #[cfg(unix)]
    #[derive(Debug)]
    pub struct Socket {
        inner: UnixStream,
        read_deadline: Option<Instant>,
        write_deadline: Option<Instant>,
    }

    #[cfg(unix)]
    impl Socket {
        /// Wraps a test socket without configuring either direction's deadline.
        pub fn new(inner: UnixStream) -> Self {
            Self {
                inner,
                read_deadline: None,
                write_deadline: None,
            }
        }
    }

    #[cfg(unix)]
    impl io::Read for Socket {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.inner
                .set_read_timeout(self.read_deadline.map(remaining).transpose()?)?;
            io::Read::read(&mut self.inner, buf).map_err(socket_error)
        }
    }

    #[cfg(unix)]
    impl Read for Socket {
        fn set_read_deadline(&mut self, deadline: Option<Instant>) -> io::Result<()> {
            self.read_deadline = deadline;
            Ok(())
        }
    }

    #[cfg(unix)]
    impl io::Write for Socket {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.inner
                .set_write_timeout(self.write_deadline.map(remaining).transpose()?)?;
            io::Write::write(&mut self.inner, buf).map_err(socket_error)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.inner
                .set_write_timeout(self.write_deadline.map(remaining).transpose()?)?;
            io::Write::flush(&mut self.inner).map_err(socket_error)
        }
    }

    #[cfg(unix)]
    impl Write for Socket {
        fn set_write_deadline(&mut self, deadline: Instant) -> io::Result<()> {
            self.write_deadline = Some(deadline);
            Ok(())
        }
    }

    /// Returns the nonzero part of a deadline still available for an adapter call.
    pub fn remaining(deadline: Instant) -> io::Result<Duration> {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::ErrorKind::TimedOut.into())
    }

    /// Normalizes the platform-specific socket timeout result for transport.
    #[cfg(unix)]
    fn socket_error(error: io::Error) -> io::Error {
        if error.kind() == io::ErrorKind::WouldBlock {
            io::ErrorKind::TimedOut.into()
        } else {
            error
        }
    }

    // init_tracing sets up a test logger to push log messages to stderr.
    pub fn init_tracing() {
        INIT.call_once(|| {
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::from_default_env()
                        .add_directive(tracing::Level::TRACE.into()),
                )
                .with_ansi(true)
                .with_test_writer()
                .init();
        });
    }

    // served reads the next message and retains the sender delivered by the
    // latest Connected event, for tests exchanging messages across sessions.
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
}
