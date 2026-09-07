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
    Attestation, Attester, Client, Emitter, Error, MAX_FRAME_SIZE, MAX_MESSAGE_SIZE, Roots, Server,
    Verifier,
};

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod testing {
    use crate::transport::{Attester, Error, Event, Server};
    use std::io::{Read, Write};
    use std::sync::Once;

    static INIT: Once = Once::new();

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

    // served reads the next message of a server, the sessions it takes to get
    // there passing unseen, for tests holding nothing of a session.
    pub fn served<R: Read, W: Write, A: Attester>(
        server: &mut Server<R, W, A>,
    ) -> Result<Vec<u8>, Error> {
        loop {
            if let Event::Message(message) = server.next_event()? {
                return Ok(message);
            }
        }
    }
}
