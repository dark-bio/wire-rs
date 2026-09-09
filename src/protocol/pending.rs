// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

use super::{Error, Message};

/// Promise for an eagerly submitted request's answer.
/// Dropping it abandons observation, not the operation. Eventual answers still
/// settle accounting and are discarded if unobserved. A timeout does not prove
/// that the peer stopped working. Completed answers remain available after closure.
/// A promise yields its answer once:
///
/// ```compile_fail,E0382
/// use darkbio_wire::protocol::{DeviceInfoResponse, Pending};
/// fn take_twice(pending: Pending) {
///     let _ = pending.wait::<DeviceInfoResponse>();
///     let _ = pending.wait::<DeviceInfoResponse>();
/// }
/// ```
pub struct Pending {
    _private: (),
}

impl Pending {
    /// Blocks for completion under the request's original absolute deadline.
    /// Selects the expected response type at this call, either through inference
    /// or `wait::<Response>()`. Message extraction checks the content variant and
    /// returns [`Error::UnexpectedResponse`] on mismatch. The [`Message`] enum can
    /// also be taken directly for application pattern matching.
    ///
    /// # Panics
    /// API skeleton; not implemented yet.
    pub fn wait<T>(self) -> Result<T, Error>
    where
        T: TryFrom<Message>,
        Error: From<T::Error>,
    {
        todo!("protocol request completion")
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        todo!("protocol request observation release")
    }
}

/// Promise for an eagerly submitted reply's local write and flush.
/// Dropping it abandons observation; the reply continues under its original
/// deadline. Completion does not mean the peer received or processed the reply.
pub struct WritePending {
    _private: (),
}

impl WritePending {
    /// Blocks for local write/flush completion under the reply's original deadline.
    /// The peer does not send another acknowledgment for this reply.
    ///
    /// # Panics
    /// API skeleton; not implemented yet.
    pub fn wait(self) -> Result<(), Error> {
        todo!("protocol reply write completion")
    }
}

impl Drop for WritePending {
    fn drop(&mut self) {
        todo!("protocol reply observation release")
    }
}
