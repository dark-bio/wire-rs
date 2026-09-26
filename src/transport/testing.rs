// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Memory adapters for transport tests, benchmarks and fuzz harnesses.
//!
//! These wrappers check deadlines before nonblocking memory I/O. They cannot
//! interrupt a blocking call. Use them for memory buffers, not production
//! sockets, files or device endpoints.

use super::{Read, Write};
use darkbio_clock::Clock;
use std::io;
use std::time::Instant;

/// Adapter adding independent read and write deadlines to nonblocking memory
/// I/O.
///
/// Neither direction has a deadline until its setter is called. Replacing an
/// expired deadline allows further operations on the same buffer.
#[derive(Debug)]
pub struct Memory<T> {
    /// In-memory reader or writer retained by this test adapter.
    pub inner: T,
    /// Clock used to check this adapter's deadlines.
    clock: Clock,
    /// Latest configured read deadline.
    read_deadline: Option<Instant>,
    /// Latest configured write deadline.
    write_deadline: Option<Instant>,
}

impl<T> Memory<T> {
    /// Wraps a nonblocking memory reader or writer with no initial deadlines,
    /// measuring later ones on `clock`.
    pub fn new(inner: T, clock: &Clock) -> Self {
        Self {
            inner,
            clock: clock.clone(),
            read_deadline: None,
            write_deadline: None,
        }
    }
}

impl<T: io::Read> io::Read for Memory<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        check_deadline(&self.clock, self.read_deadline)?;
        self.inner.read(buf)
    }
}

impl<T: io::Read> Read for Memory<T> {
    fn clock(&self) -> Clock {
        self.clock.clone()
    }

    fn set_read_deadline(&mut self, deadline: Option<Instant>) -> io::Result<()> {
        self.read_deadline = deadline;
        Ok(())
    }
}

impl<T: io::Write> io::Write for Memory<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        check_deadline(&self.clock, self.write_deadline)?;
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        check_deadline(&self.clock, self.write_deadline)?;
        self.inner.flush()
    }
}

impl<T: io::Write> Write for Memory<T> {
    fn clock(&self) -> Clock {
        self.clock.clone()
    }

    fn set_write_deadline(&mut self, deadline: Instant) -> io::Result<()> {
        self.write_deadline = Some(deadline);
        Ok(())
    }
}

/// Rejects an expired deadline before accessing the memory buffer.
fn check_deadline(clock: &Clock, deadline: Option<Instant>) -> io::Result<()> {
    if deadline.is_some_and(|deadline| clock.now() >= deadline) {
        Err(io::ErrorKind::TimedOut.into())
    } else {
        Ok(())
    }
}

/// Creates a paused clock a day ahead of real time to expose accidental real reads.
#[cfg(any(test, feature = "fuzz"))]
pub fn test_clock() -> darkbio_clock::TestClock {
    let mut tester = darkbio_clock::TestClock::new();
    tester.advance(std::time::Duration::from_secs(86400));
    tester
}

/// Checks the memory adapter's deadlines.
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::time::Duration;

    /// Checks that read and write deadlines expire independently without
    /// touching the buffer, and that replacing one allows reuse.
    #[test]
    fn test_independent_deadlines_and_reuse() {
        // Expire only reads while writes still update the buffer
        let tester = test_clock();
        let clock = tester.clock();
        let mut memory = Memory::new(io::Cursor::new(vec![1, 2, 3]), &clock);
        memory.set_read_deadline(Some(clock.now())).unwrap();
        assert_eq!(
            memory.read_exact(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        memory.write_all(&[4]).unwrap();
        assert_eq!(memory.inner.get_ref(), &[4, 2, 3]);

        // Expire writes and restore reads without changing the buffer
        memory.set_write_deadline(clock.now()).unwrap();
        memory.set_read_deadline(None).unwrap();
        let mut rest = Vec::new();
        memory.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, [2, 3]);
        assert_eq!(
            memory.write_all(&[5]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(memory.flush().unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(memory.inner.get_ref(), &[4, 2, 3]);

        // Replace the expired write deadline and resume output
        memory
            .set_write_deadline(clock.now() + Duration::from_secs(1))
            .unwrap();
        memory.write_all(&[5]).unwrap();
        memory.flush().unwrap();
        assert_eq!(memory.inner.get_ref(), &[4, 2, 3, 5]);
    }
}
