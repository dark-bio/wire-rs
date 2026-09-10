// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Sending requests through a shared handle to a session.

use super::session::SessionInner;
use super::{Error, Message, Promise};
use std::sync::Weak;
use std::time::Instant;

/// Clonable handle for sending requests through the session that created it.
/// Does not keep the session open or follow a replacement session. Dropping a
/// requester does not close the session or cancel operations it already submitted.
#[derive(Clone)]
pub struct Requester {
    /// Session that created this requester, even after a replacement connects.
    session: Weak<SessionInner>,
}

impl Requester {
    /// Queues a request and returns its promise without waiting for the writer or
    /// a reply. A closed session returns an error immediately; errors after queueing
    /// are returned through the promise. The outgoing queue has no capacity limit.
    /// A message invalid for this session's direction fails the promise with
    /// [`Error::WrongDirection`].
    ///
    /// The deadline covers time in the queue, sending and accepting the response.
    /// Waiting on the promise does not start or refresh it. Dropping the promise
    /// does not cancel the request. The peer may keep working after a timeout.
    /// Decoding the response in `wait()` is outside this deadline.
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

    /// Creates a requester from a weak reference to its session.
    pub(super) fn new(session: Weak<SessionInner>) -> Self {
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

    /// Compiles sending several requests before waiting, dropping promises, and
    /// choosing the expected response type at `wait()`.
    #[allow(dead_code)]
    fn pipeline(session: &Session, deadline: Instant) -> Result<(), Error> {
        let requester: Requester = session.requester();
        let first: Promise<Message> = requester.request(DeviceInfoRequest {}, deadline)?;
        let second = requester.request(DeviceInfoRequest {}, deadline)?;

        // A promise can be dropped without selecting a response type.
        drop(requester.request(DeviceInfoRequest {}, deadline)?);

        // Caller-selected typing, by annotation or by explicit generic argument.
        let _: DeviceInfoResponse = second.wait()?;
        let _ = first.wait::<DeviceInfoResponse>()?;

        // Callers may also request the message enum to match it themselves.
        let _: Message = requester.request(DeviceInfoRequest {}, deadline)?.wait()?;
        Ok(())
    }

    /// Checks that `Requester` implements `Clone`, `Send`, and `Sync`.
    #[test]
    fn test_thread_capabilities() {
        /// Requires a handle to be clonable and usable by multiple threads.
        fn shared<T: Clone + Send + Sync + 'static>() {}
        shared::<Requester>();
    }
}
