// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Encryption contexts and lifetime of one handshake. Receiving owns its context
//! exclusively; senders share the sending context and the same terminal state.
//! A new handshake creates a new object, never reviving an ended session.

use super::{Error, sealing};
use darkbio_crypto::xhpke;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

/// One encrypted session, owned by the client or server that completed its
/// handshake. Its receive context is accessed exclusively through `&mut self`;
/// the send context and termination flag are shared with active send operations.
///
/// Dropping this value marks the shared state ended before releasing the receive
/// context. Active sends may keep that state allocated, but cannot keep it usable
/// after termination. Writes already admitted may complete; subsequent operations
/// fail. Destruction takes no encryption or writer lock and performs no stream I/O.
pub(crate) struct Session {
    receiver: xhpke::Receiver, // Context used exclusively by the receiving owner
    pub(super) state: Arc<SessionState>, // Sending context and the lifetime of both directions
}

impl Session {
    /// Owns freshly negotiated contexts with a shared lifetime. The session has
    /// no stream dependency; the owner binds it to a writer when issuing a sender.
    pub(crate) fn new(sender: xhpke::Sender, receiver: xhpke::Receiver) -> Self {
        let state = Arc::new(SessionState {
            sealer: Mutex::new(sender),
            ended: AtomicBool::new(false),
        });
        Self { receiver, state }
    }

    /// Opens a packet in this session, refusing it if either direction already
    /// ended. Decryption failure or panic ends the session for senders too.
    /// An operation overlapping termination may still return a message.
    pub(super) fn open(&mut self, packet: &[u8]) -> Result<Vec<u8>, Error> {
        self.state.check()?;
        let _end_on_panic = self.state.end_on_panic();
        sealing::open(&mut self.receiver, packet).inspect_err(|_| self.state.end())
    }

    /// Ends both encryption directions. Takes no I/O or encryption lock, and
    /// does not close the stream or wait for operations already in progress.
    pub(super) fn end(&self) {
        self.state.end();
    }

    /// Mock helper observing termination without performing I/O or modifying
    /// the encryption sequence. Production callers use operation results.
    #[cfg(any(test, feature = "fuzz"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(crate) fn ended(&self) -> bool {
        self.state.ended.load(Ordering::Acquire)
    }
}

impl Drop for Session {
    /// Invalidates the shared state even when active sends still retain it.
    /// The receive context and this value's strong reference are then released.
    fn drop(&mut self) {
        self.end();
    }
}

/// Sending context and terminal state shared by both directions of one session.
/// Its allocation identifies the session; it is never reused by another handshake.
/// Only the owner and active operations hold strong references.
pub(super) struct SessionState {
    sealer: Mutex<xhpke::Sender>, // Fixes encryption order among concurrent sends
    ended: AtomicBool,            // Monotonic termination of both encryption directions
}

impl SessionState {
    /// Acquires the sending context for an operation, refusing ended sessions.
    /// The caller retains the guard until it acquires its place in wire order.
    pub(super) fn lock(&self) -> Result<MutexGuard<'_, xhpke::Sender>, Error> {
        self.check()?;
        let sealer = self.sealer.lock().unwrap_or_else(|poisoned| {
            self.end();
            self.sealer.clear_poison();
            poisoned.into_inner()
        });
        self.check()?;
        Ok(sealer)
    }

    /// Guards an operation whose panic would leave this session's sequence
    /// uncertain. The guard ends the session if the operation unwinds.
    pub(super) fn end_on_panic(&self) -> EndOnPanic<'_> {
        EndOnPanic(self)
    }

    /// Refuses an operation after termination. A successful check admits only
    /// the operation containing it, which may overlap a later termination.
    pub(super) fn check(&self) -> Result<(), Error> {
        if self.ended.load(Ordering::Acquire) {
            Err(Error::EncryptionFailed("session ended".into()))
        } else {
            Ok(())
        }
    }

    /// Irreversibly ends both directions without waiting on either send lock.
    pub(super) fn end(&self) {
        self.ended.store(true, Ordering::Release);
    }

    /// Test barrier waiting until a sender holds the encryption context while
    /// queued behind a writer held by the test. No sleep determines the ordering.
    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(super) fn wait_sealing(&self) {
        use std::sync::TryLockError;
        use std::time::{Duration, Instant};

        let deadline = Instant::now() + Duration::from_secs(5);
        while !matches!(self.sealer.try_lock(), Err(TryLockError::WouldBlock)) {
            assert!(
                Instant::now() < deadline,
                "sender did not acquire encryption context"
            );
            std::thread::yield_now();
        }
    }
}

/// Ends the session if an encryption or write operation unwinds. Ordinary errors
/// are handled by the operation, including size refusals that preserve the session.
pub(super) struct EndOnPanic<'a>(&'a SessionState);

impl Drop for EndOnPanic<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.0.end();
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::testing;
    use crate::transport::Closer;
    use crate::transport::mock::payload;
    use crate::transport::outbound::{Outbound, Side};

    /// Matching encryption contexts for one direction of a test session.
    fn contexts() -> (xhpke::Sender, xhpke::Receiver) {
        let key = xhpke::SecretKey::generate();
        let (sender, encap) = key.public_key().new_sender(b"test").unwrap();
        (sender, key.new_receiver(&encap, b"test").unwrap())
    }

    // Tests that ending and dropping an old session owner cannot invalidate its
    // replacement. Dropping the current owner immediately refuses its sender,
    // even though the stream remains alive.
    #[test]
    fn test_owner_drop() {
        testing::init_tracing();

        let outbound = Arc::new(Outbound::new(Vec::new(), Side::Client, Closer::new(|| {})));
        let (crypto, receiver) = contexts();
        let session = Session::new(crypto, receiver);
        let stale = outbound.bind(&session);

        let (mut peer, receiver) = contexts();
        let (crypto, _) = contexts();
        let mut replacement = Session::new(crypto, receiver);
        let fresh = outbound.bind(&replacement);
        session.end();
        drop(session);
        assert!(matches!(
            stale.send(&payload(1)),
            Err(Error::EncryptionFailed(_))
        ));
        let packet = sealing::seal(&mut peer, &payload(2)).unwrap();
        assert_eq!(replacement.open(&packet).unwrap(), payload(2));
        fresh.send(&payload(3)).unwrap();
        drop(replacement);
        assert!(matches!(
            fresh.send(&payload(4)),
            Err(Error::EncryptionFailed(_))
        ));
    }
}
