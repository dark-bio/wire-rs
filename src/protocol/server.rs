// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

use super::{Closer, Error, Session};
use crate::transport::{Attester, Read, Stream, Write};
use darkbio_crypto::xdsa;

/// Owner of a persistent server stream, accepting successive sessions.
/// Closing or dropping the endpoint ends its active session and shuts down the
/// physical stream. Closing an individual [`Session`] keeps this owner and
/// its stream available for another handshake.
pub struct Server {
    _private: (),
}

impl Server {
    /// Takes ownership of a stream and constructs its transport internally.
    /// The attester supplies the current device attestation for each handshake.
    ///
    /// # Panics
    /// API skeleton; not implemented yet.
    pub fn new<R, W, A>(_stream: Stream<R, W>, _signer: xdsa::SecretKey, _attester: A) -> Self
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
        A: Attester + Send + 'static,
    {
        todo!("protocol server construction")
    }

    /// Blocks until a session is established or the endpoint ends. Recoverable
    /// handshake failures leave the stream available for another attempt. A
    /// replacement session retires its predecessor; old handles remain bound to it.
    ///
    /// # Panics
    /// API skeleton; not implemented yet.
    pub fn accept(&mut self) -> Result<Session, Error> {
        todo!("protocol server accept")
    }

    /// Returns a clonable handle for closing this endpoint from another thread,
    /// including while its owner is blocked in [`Self::accept`].
    ///
    /// # Panics
    /// API skeleton; not implemented yet.
    pub fn closer(&self) -> Closer {
        todo!("protocol server closer")
    }

    /// Permanently closes this endpoint and its active session, wakes blocked
    /// acceptance and receive calls, and fails unresolved operations. Idempotent.
    /// Does not join application jobs or guarantee the peer has observed closure.
    ///
    /// # Panics
    /// API skeleton; not implemented yet.
    pub fn close(&self) {
        todo!("protocol server close")
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        todo!("protocol server shutdown")
    }
}
