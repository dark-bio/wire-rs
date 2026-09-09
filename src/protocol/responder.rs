// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! One-use reply obligations bound to the session that received the request.

use super::session::Shared;
use super::{Error, Message, RemoteError, WritePending};
use std::sync::Weak;
use std::time::Instant;

/// One-use capability to answer an incoming request in its original session.
/// The handler selects the success content, without a static request/response map.
/// This handle cannot keep its session open or address a replacement session.
///
/// Dropping an unanswered responder schedules a standard abandonment error without
/// blocking on I/O, using the configured write timeout. If the session has ended,
/// the obligation ends with it. No reply can escape into another session.
///
/// Replying consumes the capability, so it cannot be reused:
///
/// ```compile_fail,E0382
/// use darkbio_wire::protocol::{DeviceInfoResponse, Responder};
/// use std::time::Instant;
///
/// fn answer_twice(responder: Responder, deadline: Instant) {
///     let _ = responder.reply(Ok(DeviceInfoResponse::default().into()), deadline);
///     let _ = responder.reply(Ok(DeviceInfoResponse::default().into()), deadline);
/// }
/// ```
///
/// Reply capabilities cannot be cloned either:
///
/// ```compile_fail,E0599
/// use darkbio_wire::protocol::Responder;
/// fn duplicate(responder: Responder) { let _ = responder.clone(); }
/// ```
pub struct Responder {
    /// Session that received the request; holding a responder cannot keep it open.
    session: Weak<Shared>,
    /// Outstanding request ID, cleared only when output takes its reply obligation.
    id: Option<u64>,
}

impl Responder {
    /// Consumes this capability and promptly returns a promise for writing/flushing
    /// the reply. An ended session may fail immediately. The deadline covers output
    /// scheduling and I/O; waiting on the promise does not restart it.
    /// A message invalid for this session's direction fails the promise with
    /// [`Error::WrongDirection`].
    ///
    /// Replies bypass outgoing request credit so reverse requests cannot prevent
    /// responses. Their resource needs are accounted for when requests are accepted.
    /// A reply needs no further acknowledgment. Dropping its promise leaves it queued.
    /// Success content can be converted from a protobuf message using `.into()`;
    /// the concrete content type also lets `reply(Err(error), deadline)` infer fully.
    ///
    /// # Panics
    /// Open-session submission is not implemented yet. Ended sessions are refused.
    pub fn reply(
        mut self,
        result: Result<Message, RemoteError>,
        deadline: Instant,
    ) -> Result<WritePending, Error> {
        let pending = self.session.upgrade().ok_or(Error::Closed)?.reply(
            self.id.expect("reply obligation present"),
            result,
            deadline,
        )?;
        self.id = None; // Ownership passed to the output path.
        Ok(pending)
    }

    /// Creates the sole reply capability for a request removed from this session.
    pub(super) fn new(session: Weak<Shared>, id: u64) -> Self {
        Self {
            session,
            id: Some(id),
        }
    }
}

impl Drop for Responder {
    /// Records an unanswered request for abandonment without performing I/O.
    /// Consumed replies and retired sessions have no remaining obligation here.
    fn drop(&mut self) {
        if let Some(id) = self.id.take()
            && let Some(session) = self.session.upgrade()
        {
            session.abandon(id);
        }
    }
}

/// Checks responder ownership and compiles success, error and deferred reply paths.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::protocol::{
        DeviceInfoResponse, Error, Message, RemoteError, Responder, Session, WritePending,
    };
    use std::time::Instant;

    /// Compiles receiving a host-side request and returning an application error.
    #[allow(dead_code)]
    fn receive_on_host(session: &mut Session, deadline: Instant) -> Result<(), Error> {
        let (request, responder): (Message, Responder) = session.recv()?;
        let _ = request;
        responder
            .reply(
                Err(RemoteError {
                    code: 1,
                    msg: "refused".into(),
                }),
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
                let written: WritePending =
                    responder.reply(Ok(DeviceInfoResponse::default().into()), deadline)?;
                written.wait()?;
            }
            Message::Develop(bytes) => {
                // Opaque development traffic is supported in both directions.
                let requester = session.requester();
                std::thread::spawn(move || -> Result<(), Error> {
                    let answer: Vec<u8> = requester.request(bytes, deadline)?.wait()?;
                    drop(responder.reply(Ok(answer.into()), deadline)?);
                    Ok(())
                });
            }
            _ => drop(responder), // Schedules an abandonment error in the real implementation.
        }
        Ok(())
    }

    /// Checks the send bound required to transfer ownership to an application thread.
    #[test]
    fn test_thread_capabilities() {
        /// Requires an owned value to be transferable to a background thread.
        fn movable<T: Send + 'static>() {}
        movable::<Responder>();
    }
}
