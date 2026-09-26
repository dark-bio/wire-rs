// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Standard byte I/O with separate read and write deadlines.
//!
//! Transport chooses an absolute deadline. The adapter limits how long its I/O
//! can block and keeps the stream reusable after a timeout.

use darkbio_clock::Clock;
use std::io;
use std::time::Instant;

/// A standard byte reader whose blocking operations honor an absolute deadline.
///
/// An idle read returns [`TimedOut`](io::ErrorKind::TimedOut) when its deadline
/// expires, without consuming bytes. Transport retries early timeouts and
/// interruptions within the same deadline. Reads that consume bytes must report
/// them through the standard [`io::Read`] contract. Timeouts leave the adapter
/// open and reusable.
///
/// The actual I/O must honor the deadline. Checking the clock before a call that
/// can block indefinitely is insufficient. With no deadline, reads wait for data
/// or shutdown. The stream's shutdown operation must release blocked reads.
pub trait Read: io::Read {
    /// Returns the clock this adapter measures its deadlines on, the
    /// [real one](Clock::real) by default.
    ///
    /// The transport reads all its time from this clock, so a stream's reader
    /// and writer must return the same one. [`Stream::new`](super::Stream::new)
    /// panics otherwise.
    fn clock(&self) -> Clock {
        Clock::real()
    }

    /// Installs the deadline for subsequent reads until replaced, with `None`
    /// clearing it.
    ///
    /// Returns promptly, transfers no bytes and leaves the write deadline
    /// unchanged. Reads attempted after expiration must not wait. Adapters may
    /// return immediately available bytes, EOF or an empty read, or report
    /// [`TimedOut`](io::ErrorKind::TimedOut). Transport enforces its own
    /// deadline before calling the adapter. If this setter fails, transport
    /// returns the error without attempting a read.
    fn set_read_deadline(&mut self, deadline: Option<Instant>) -> io::Result<()>;
}

impl<T: Read + ?Sized> Read for &mut T {
    fn clock(&self) -> Clock {
        (**self).clock()
    }

    fn set_read_deadline(&mut self, deadline: Option<Instant>) -> io::Result<()> {
        (**self).set_read_deadline(deadline)
    }
}

impl<T: Read + ?Sized> Read for Box<T> {
    fn clock(&self) -> Clock {
        (**self).clock()
    }

    fn set_read_deadline(&mut self, deadline: Option<Instant>) -> io::Result<()> {
        (**self).set_read_deadline(deadline)
    }
}

/// A standard byte writer whose writes and flushes honor an absolute deadline.
///
/// The installed deadline covers partial writes and flush. Progress does not
/// restart it. Expiration returns [`TimedOut`](io::ErrorKind::TimedOut) and
/// leaves the adapter open and reusable. Each write reports accepted bytes
/// through the standard [`io::Write`] contract. A frame can therefore fail
/// after earlier writes accepted a prefix. Successful output does not guarantee
/// that the peer received or processed it.
///
/// Pending transfers must remain ordered before subsequent output or be
/// canceled before that output begins. An abandoned operation must never append
/// bytes out of order after a later call starts writing. The adapter must bound
/// actual I/O.
pub trait Write: io::Write {
    /// Returns the clock this adapter measures its deadlines on, the
    /// [real one](Clock::real) by default.
    ///
    /// The transport reads all its time from this clock, so a stream's reader
    /// and writer must return the same one. [`Stream::new`](super::Stream::new)
    /// panics otherwise.
    fn clock(&self) -> Clock {
        Clock::real()
    }

    /// Installs the deadline for subsequent writes and flushes until replaced.
    ///
    /// Returns promptly, transfers no bytes and leaves the read deadline
    /// unchanged. Operations attempted after expiration return
    /// [`TimedOut`](io::ErrorKind::TimedOut). If this setter fails, transport
    /// returns the error without attempting a write or flush.
    fn set_write_deadline(&mut self, deadline: Instant) -> io::Result<()>;
}

impl<T: Write + ?Sized> Write for &mut T {
    fn clock(&self) -> Clock {
        (**self).clock()
    }

    fn set_write_deadline(&mut self, deadline: Instant) -> io::Result<()> {
        (**self).set_write_deadline(deadline)
    }
}

impl<T: Write + ?Sized> Write for Box<T> {
    fn clock(&self) -> Clock {
        (**self).clock()
    }

    fn set_write_deadline(&mut self, deadline: Instant) -> io::Result<()> {
        (**self).set_write_deadline(deadline)
    }
}

/// Refuses work whose absolute I/O deadline has already elapsed.
pub(super) fn check_deadline(clock: &Clock, deadline: Instant) -> io::Result<()> {
    if clock.now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "I/O deadline expired",
        ))
    } else {
        Ok(())
    }
}
