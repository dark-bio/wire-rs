// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Standard byte I/O extended with independent absolute deadlines. Transport
//! chooses the deadline; the adapter bounds its actual I/O without closing the
//! stream. These setters configure operations and expose no lifecycle snapshots.

use std::io;
use std::time::Instant;

/// Refuses work whose absolute output deadline has already elapsed.
pub(super) fn check_deadline(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "I/O deadline expired",
        ))
    } else {
        Ok(())
    }
}

/// A standard byte reader whose blocking operations honor an absolute deadline.
///
/// Idle expiration returns [`io::ErrorKind::TimedOut`] without consuming bytes;
/// transport retries these polls until data, cancellation or another error arrives.
/// Received bytes must be reported through the standard [`io::Read`] contract.
/// Timeouts leave the adapter open and reusable. Implementations must bound the
/// actual I/O; checking the clock before an indefinitely blocking call is insufficient.
pub trait Read: io::Read {
    /// Installs the deadline for subsequent reads until replaced. This returns
    /// promptly without transferring bytes and leaves the write deadline alone.
    /// Reads attempted after expiration return TimedOut. A setter failure aborts
    /// that read attempt without reading bytes.
    fn set_read_deadline(&mut self, deadline: Instant) -> io::Result<()>;
}

/// A standard byte writer whose writes and flushes honor an absolute deadline.
///
/// The installed deadline covers partial writes and flush without restarting
/// on progress. Expiration returns [`io::ErrorKind::TimedOut`] and leaves the
/// adapter open and reusable. Each write reports accepted bytes according to
/// [`io::Write`]; a complete frame can fail after earlier writes accepted a prefix.
/// Success means adapter acceptance, not that the peer received or processed data.
///
/// Pending transfers must remain ordered before subsequent output or be cancelled
/// before that output begins. An abandoned operation must never append bytes out
/// of order after a later call starts writing. The adapter must bound actual I/O.
pub trait Write: io::Write {
    /// Installs the deadline for subsequent writes and flushes until replaced.
    /// This returns promptly without transferring bytes and leaves the read
    /// deadline alone. Operations attempted after expiration return TimedOut.
    /// A setter failure aborts that frame before its first write or flush.
    fn set_write_deadline(&mut self, deadline: Instant) -> io::Result<()>;
}

impl<T: Read + ?Sized> Read for &mut T {
    fn set_read_deadline(&mut self, deadline: Instant) -> io::Result<()> {
        (**self).set_read_deadline(deadline)
    }
}

impl<T: Read + ?Sized> Read for Box<T> {
    fn set_read_deadline(&mut self, deadline: Instant) -> io::Result<()> {
        (**self).set_read_deadline(deadline)
    }
}

impl<T: Write + ?Sized> Write for &mut T {
    fn set_write_deadline(&mut self, deadline: Instant) -> io::Result<()> {
        (**self).set_write_deadline(deadline)
    }
}

impl<T: Write + ?Sized> Write for Box<T> {
    fn set_write_deadline(&mut self, deadline: Instant) -> io::Result<()> {
        (**self).set_write_deadline(deadline)
    }
}
