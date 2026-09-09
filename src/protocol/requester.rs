// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

use super::{Error, Message, Pending};
use std::time::Instant;

/// Clonable capability to initiate requests in its original session.
/// Does not keep the session open or follow a replacement session. Dropping a
/// requester does not close the session or cancel operations it already submitted.
pub struct Requester {
    _private: (),
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
    /// The expected response type is selected at [`Pending::wait`].
    ///
    /// # Panics
    /// API skeleton; not implemented yet.
    pub fn request(
        &self,
        _request: impl Into<Message>,
        _deadline: Instant,
    ) -> Result<Pending, Error> {
        todo!("protocol request submission")
    }
}

impl Clone for Requester {
    fn clone(&self) -> Self {
        todo!("protocol requester clone")
    }
}
