// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Weak capabilities for retiring a particular session or persistent endpoint.

use super::{Error, server, session};
use std::sync::Weak;

/// Clonable capability to close its original owner from any thread.
///
/// From [`super::Session::closer`], it retires that session, with the semantics of
/// [`super::Session::close`]. From [`super::Server::closer`], it closes the server
/// endpoint and its active session, with the semantics of [`super::Server::close`].
/// Its target never changes: a session's closer cannot affect a successor session.
///
/// This handle does not keep its owner open. Dropping it does not close anything.
#[derive(Clone)]
pub struct Closer {
    /// Fixed destination chosen when the owner creates this capability.
    target: Target,
}

/// The two ownership boundaries exposed through the same public close capability.
#[derive(Clone)]
enum Target {
    /// One session allocation, unaffected by endpoint session replacement.
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
                    session.retire(Error::Closed);
                }
            }
            Target::Server(target) => {
                if let Some(server) = target.upgrade() {
                    server.retire(Error::Closed);
                }
            }
        }
    }

    /// Binds closure to one session without retaining its owner.
    pub(super) fn session(target: Weak<session::Shared>) -> Self {
        Self {
            target: Target::Session(target),
        }
    }

    /// Binds closure to one endpoint without retaining its owner.
    pub(super) fn server(target: Weak<server::Shared>) -> Self {
        Self {
            target: Target::Server(target),
        }
    }
}

/// Checks closer sharing and compiles closure of both ownership boundaries.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::protocol::{Closer, Server, Session};

    /// Checks that both owners expose the same clonable cross-thread close capability.
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

    /// Checks the clone, send and sync bounds required for a shared capability.
    #[test]
    fn test_thread_capabilities() {
        /// Requires a capability to be clonable and usable by multiple threads.
        fn shared<T: Clone + Send + Sync + 'static>() {}
        shared::<Closer>();
    }
}
