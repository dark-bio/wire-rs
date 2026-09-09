// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Clonable request submission bound to the originating session.

use super::session::Shared;
use super::{Error, Message, Promise};
use std::sync::Weak;
use std::time::Instant;

/// Clonable capability to initiate requests in its original session.
/// Does not keep the session open or follow a replacement session. Dropping a
/// requester does not close the session or cancel operations it already submitted.
#[derive(Clone)]
pub struct Requester {
    /// Original session, never a lookup of the endpoint's newest session.
    session: Weak<Shared>,
}

impl Requester {
    /// Submits a request and promptly returns its eager promise. Does not wait for
    /// request credit, the writer or a reply. An ended session may return an error
    /// immediately; accepted operations report subsequent failures via the promise.
    /// A full request window delays the operation instead of rejecting it.
    /// A message invalid for this session's direction fails the promise with
    /// [`Error::WrongDirection`].
    ///
    /// The deadline covers waiting for capacity, sending and receiving the reply.
    /// Waiting on the promise does not start or refresh it. Dropping the promise
    /// only abandons observation. Neither dropping nor expiry cancels remote work.
    /// The expected response type is selected when waiting on [`Promise<Message>`].
    pub fn request(
        &self,
        request: impl Into<Message>,
        deadline: Instant,
    ) -> Result<Promise<Message>, Error> {
        self.session
            .upgrade()
            .ok_or(Error::Closed)?
            .request(request.into(), deadline)
    }

    /// Creates a submission capability that does not retain its session owner.
    pub(super) fn new(session: Weak<Shared>) -> Self {
        Self { session }
    }
}

/// Checks requester sharing and compiles pipelined request submission.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::protocol::{
        DeviceInfoRequest, DeviceInfoResponse, Error, Message, Promise, Requester, Session,
    };
    use std::time::Instant;

    /// Compiles pipelined requests, discarded observations and caller-selected replies.
    #[allow(dead_code)]
    fn pipeline(session: &Session, deadline: Instant) -> Result<(), Error> {
        let requester: Requester = session.requester();
        let first: Promise<Message> = requester.request(DeviceInfoRequest {}, deadline)?;
        let second = requester.request(DeviceInfoRequest {}, deadline)?;

        // Observation can be abandoned without selecting a response type.
        drop(requester.request(DeviceInfoRequest {}, deadline)?);

        // Caller-selected typing, by annotation or by explicit generic argument.
        let _: DeviceInfoResponse = second.wait()?;
        let _ = first.wait::<DeviceInfoResponse>()?;

        // Callers may also request the message enum to match it themselves.
        let _: Message = requester.request(DeviceInfoRequest {}, deadline)?.wait()?;
        Ok(())
    }

    /// Checks the clone, send and sync bounds required for a shared capability.
    #[test]
    fn test_thread_capabilities() {
        /// Requires a capability to be clonable and usable by multiple threads.
        fn shared<T: Clone + Send + Sync + 'static>() {}
        shared::<Requester>();
    }
}
