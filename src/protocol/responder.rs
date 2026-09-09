// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

use super::{Error, Message, RemoteError, WritePending};
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
    _private: (),
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
    /// API skeleton; not implemented yet.
    pub fn reply(
        self,
        _result: Result<Message, RemoteError>,
        _deadline: Instant,
    ) -> Result<WritePending, Error> {
        todo!("protocol reply submission")
    }
}

impl Drop for Responder {
    fn drop(&mut self) {
        todo!("protocol abandoned request reply")
    }
}
