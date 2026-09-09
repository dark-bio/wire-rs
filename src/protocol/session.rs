// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

use super::{Closer, Error, Message, Requester, Responder};
use crate::transport::{Read, Stream, Verifier, Write};

/// Establishes a client session, verifies the peer and returns the verifier's info.
/// Takes ownership of the stream and constructs the transport internally. Failure
/// closes the client stream; the application can open another stream and reconnect.
/// The verifier is only borrowed during this blocking call.
///
/// # Panics
/// API skeleton; not implemented yet.
pub fn connect<R, W, V>(_stream: Stream<R, W>, _verifier: &V) -> Result<(Session, V::Info), Error>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
    V: Verifier,
{
    todo!("protocol client connection")
}

/// Owner of one session and its incoming request queue.
///
/// Incoming requests use [`Message`], paired with a common responder. The
/// application selects the reply type; there is no static request/response pairing
/// table. The host/server role and envelope direction are handled internally.
///
/// Closing or dropping the owner retires this session, fails unresolved promises,
/// discards queued requests and wakes blocked receivers. Completed promises retain
/// their results. Running application jobs are not cancelled. Their handles cannot
/// reach or retire a successor session.
///
/// A client session also closes its stream. A server session leaves its persistent
/// endpoint available for another handshake. Handles do not keep the session open.
/// The owner cannot be cloned; obtain requesters or closers for other threads:
///
/// ```compile_fail,E0599
/// use darkbio_wire::protocol::Session;
/// fn duplicate(session: Session) { let _ = session.clone(); }
/// ```
pub struct Session {
    _private: (),
}

impl Session {
    /// Returns a clonable requester bound to this session.
    ///
    /// # Panics
    /// API skeleton; not implemented yet.
    pub fn requester(&self) -> Requester {
        todo!("protocol session requester")
    }

    /// Blocks for the next peer request and its one-use reply capability.
    /// Session retirement wakes this call with the ending reason. Receiving does
    /// not run application callbacks; the caller decides how to dispatch work.
    ///
    /// # Panics
    /// API skeleton; not implemented yet.
    pub fn recv(&mut self) -> Result<(Message, Responder), Error> {
        todo!("protocol session receive")
    }

    /// Returns a clonable handle for closing this session from another thread,
    /// including while its owner is blocked in [`Self::recv`].
    ///
    /// # Panics
    /// API skeleton; not implemented yet.
    pub fn closer(&self) -> Closer {
        todo!("protocol session closer")
    }

    /// Retires this session. Repeated calls have no further effect. This does not
    /// wait for application jobs or guarantee the peer has observed closure.
    ///
    /// # Panics
    /// API skeleton; not implemented yet.
    pub fn close(&self) {
        todo!("protocol session close")
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        todo!("protocol session retirement")
    }
}
