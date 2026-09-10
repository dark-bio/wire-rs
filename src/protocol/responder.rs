// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Sending one reply to a received request, or `UNANSWERED` when dropped.

use super::session::SessionInner;
use super::{Error, Message, Promise, schema};
use std::sync::Weak;
use std::time::Instant;

/// Handle for answering one incoming request through the session that received it.
/// The handler selects the success content, without a static request/response map.
/// This handle cannot keep its session open or address a replacement session.
///
/// Dropping an unanswered responder queues an `UNANSWERED` error without blocking
/// on I/O, using the session's current abandonment timeout.
/// Configure it with [`super::Session::set_abandonment_timeout`] or
/// [`super::Server::set_abandonment_timeout`]. If the session has closed, no reply
/// is queued.
///
/// A held responder counts toward the session's inbound request limit. Queuing a
/// reply keeps that slot until the writer takes it or the reply is discarded.
/// See [`super::Session::set_inbound_limits`].
///
/// Both [`Self::reply`] and [`Self::fail`] consume the responder, so it cannot be reused:
///
/// ```compile_fail,E0382
/// use darkbio_wire::protocol::{Responder, schema};
/// use std::time::Instant;
///
/// fn answer_twice(responder: Responder, deadline: Instant) {
///     let _ = responder.reply(schema::DeviceInfoResponse::default(), deadline);
///     let _ = responder.fail(schema::Error::new(0x100, "refused"), deadline);
/// }
/// ```
///
/// Responders cannot be cloned either:
///
/// ```compile_fail,E0599
/// use darkbio_wire::protocol::Responder;
/// fn duplicate(responder: Responder) { let _ = responder.clone(); }
/// ```
#[derive(Debug)]
pub struct Responder {
    /// Session that received the request; holding a responder cannot keep it open.
    session: Weak<SessionInner>,
    /// Request ID to answer. Cleared after queueing a reply so `Drop` does nothing.
    id: Option<u64>,
}

impl Responder {
    /// Queues a successful response and consumes the responder. Returns a promise
    /// for writing and flushing it. A closed session returns an error immediately.
    /// The deadline includes time in the queue and I/O. Waiting on the promise
    /// does not restart it.
    ///
    /// A message invalid for this session's direction fails the promise with
    /// [`Error::WrongDirection`].
    ///
    /// A reply needs no further acknowledgment. Dropping its promise leaves it queued.
    /// Accepts a protobuf response or [`Message`] directly. Use [`Self::fail`] to
    /// return an error instead.
    pub fn reply(
        self,
        response: impl Into<Message>,
        deadline: Instant,
    ) -> Result<Promise<()>, Error> {
        self.enqueue(Ok(response.into()), deadline)
    }

    /// Queues an error response and consumes the responder. The deadline and write
    /// promise work as in [`Self::reply`]. The error itself does not close the session.
    /// Use [`schema::Error::reserved`] for a named protocol error or
    /// [`schema::Error::new`] for a numeric error code.
    pub fn fail(self, error: schema::Error, deadline: Instant) -> Result<Promise<()>, Error> {
        self.enqueue(Err(error), deadline)
    }

    /// Queues either kind of response and marks this responder as answered.
    fn enqueue(
        mut self,
        result: Result<Message, schema::Error>,
        deadline: Instant,
    ) -> Result<Promise<()>, Error> {
        let promise = self.session.upgrade().ok_or(Error::Closed)?.reply(
            self.id.expect("reply obligation present"),
            result,
            deadline,
        )?;
        self.id = None; // Prevent Drop from also queueing UNANSWERED.
        Ok(promise)
    }

    /// Creates a responder for the request taken by `Session::recv()`.
    pub(super) fn new(session: Weak<SessionInner>, id: u64) -> Self {
        Self {
            session,
            id: Some(id),
        }
    }
}

impl Drop for Responder {
    /// Queues `UNANSWERED` if this responder still has an ID and its session is
    /// open. The writer sends the error later.
    fn drop(&mut self) {
        if let Some(id) = self.id.take()
            && let Some(session) = self.session.upgrade()
        {
            session.reply_unanswered(id);
        }
    }
}

/// Checks responder ownership and compiles success, error and deferred reply paths.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::protocol::schema::DeviceInfoResponse;
    use crate::protocol::{Error, Message, Promise, Responder, Session, schema};
    use std::fmt::Debug;
    use std::time::Instant;

    /// Compiles receiving a host-side request and returning an application error.
    #[allow(dead_code)]
    fn receive_on_host(session: &mut Session, deadline: Instant) -> Result<(), Error> {
        let (request, responder): (Message, Responder) = session.recv()?;
        let _ = request;
        responder
            .fail(
                schema::Error::reserved(schema::ReservedErrors::Unspecified, "refused"),
                deadline,
            )?
            .wait()
    }

    /// Compiles immediate replies, a background reverse request and responder abandonment.
    #[allow(dead_code)]
    fn receive_on_server(session: &mut Session, deadline: Instant) -> Result<(), Error> {
        let (request, responder): (Message, Responder) = session.recv()?;
        match request {
            Message::DeviceInfoRequest(_) => {
                let written: Promise<()> =
                    responder.reply(DeviceInfoResponse::default(), deadline)?;
                written.wait()?;
            }
            Message::Develop(bytes) => {
                // Opaque development traffic is supported in both directions.
                let requester = session.requester();
                std::thread::spawn(move || -> Result<(), Error> {
                    let answer: Vec<u8> = requester.request(bytes, deadline)?.wait()?;
                    drop(responder.reply(answer, deadline)?);
                    Ok(())
                });
            }
            _ => drop(responder), // Schedules the standard unanswered error.
        }
        Ok(())
    }

    /// Checks the bounds required to move the responder to an application thread
    /// and to print it.
    #[test]
    fn test_thread_capabilities() {
        /// Requires an owned value to be printable and transferable to a background thread.
        fn movable<T: Debug + Send + 'static>() {}
        movable::<Responder>();
    }
}
