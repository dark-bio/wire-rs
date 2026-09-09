// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

/// Clonable capability to close its original owner from any thread.
///
/// From [`super::Session::closer`], it retires that session, with the semantics of
/// [`super::Session::close`]. From [`super::Server::closer`], it closes the server
/// endpoint and its active session, with the semantics of [`super::Server::close`].
/// Its target never changes: a session's closer cannot affect a successor session.
///
/// This handle does not keep its owner open. Dropping it does not close anything.
pub struct Closer {
    _private: (),
}

impl Closer {
    /// Closes the original owner. Repeated calls have no further effect.
    ///
    /// # Panics
    /// API skeleton; not implemented yet.
    pub fn close(&self) {
        todo!("protocol owner close")
    }
}

impl Clone for Closer {
    fn clone(&self) -> Self {
        todo!("protocol closer clone")
    }
}
