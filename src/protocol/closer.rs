// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Handles for closing a session or server from another thread.

use super::{Error, server, session};
use std::sync::Weak;

/// Clonable handle for closing the session or server that created it.
///
/// From [`super::Session::closer`], it closes that session, with the semantics of
/// [`super::Session::close`]. From [`super::Server::closer`], it closes the server
/// endpoint and its active session, with the semantics of [`super::Server::close`].
/// Its target never changes: a session's closer cannot affect a successor session.
///
/// This handle does not keep its owner open. Dropping it does not close anything.
#[derive(Clone)]
pub struct Closer {
    /// Session or server to close.
    target: Target,
}

/// The session or server targeted by a `Closer`.
#[derive(Clone)]
enum Target {
    /// One session, even after another session connects to the same server.
    Session(Weak<session::Shared>),
    /// One persistent endpoint and whichever session it has attached at closure.
    Server(Weak<server::Shared>),
}

impl Closer {
    /// Closes the original owner. Repeated calls have no further effect.
    pub fn close(&self) {
        match &self.target {
            Target::Session(target) => {
                if let Some(session) = target.upgrade() {
                    session.close(Error::Closed);
                }
            }
            Target::Server(target) => {
                if let Some(server) = target.upgrade() {
                    server.close(Error::Closed);
                }
            }
        }
    }

    /// Creates a closer for one session using a weak reference.
    pub(super) fn session(target: Weak<session::Shared>) -> Self {
        Self {
            target: Target::Session(target),
        }
    }

    /// Creates a closer for one server using a weak reference.
    pub(super) fn server(target: Weak<server::Shared>) -> Self {
        Self {
            target: Target::Server(target),
        }
    }
}

/// Checks that the same closer type works for sessions and servers.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::protocol::{Closer, Server, Session};

    /// Compiles closing sessions and servers through cloned handles on other threads.
    #[allow(dead_code)]
    fn cross_thread_close(session: &Session, server: &Server) {
        let session_closer: Closer = session.closer();
        let endpoint_closer: Closer = server.closer();
        let session_copy = session_closer.clone();
        let endpoint_copy = endpoint_closer.clone();
        std::thread::spawn(move || session_copy.close());
        std::thread::spawn(move || endpoint_copy.close());
        session.close();
        server.close();
    }

    /// Checks that `Closer` implements `Clone`, `Send`, and `Sync`.
    #[test]
    fn test_thread_capabilities() {
        /// Requires a handle to be clonable and usable by multiple threads.
        fn shared<T: Clone + Send + Sync + 'static>() {}
        shared::<Closer>();
    }
}
