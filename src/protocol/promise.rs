// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Promises for requests and replies, independent of operation execution.

use super::session::Shared;
use super::{Error, Message};
use std::sync::{Weak, mpsc};
use std::time::Instant;

/// Promise for an eagerly submitted operation's result.
///
/// Requests return `Promise<Message>`; their wait selects the expected response
/// type or takes the message directly. Replies return `Promise<()>`; their wait
/// observes local writing and flushing, not peer receipt or processing.
///
/// Dropping it abandons observation, not the operation, which continues under its
/// original deadline. Eventual answers still settle accounting and are discarded
/// if unobserved. A timeout does not prove that the peer stopped working. Completed
/// results remain available after closure. A promise yields its result once:
///
/// ```compile_fail,E0382
/// use darkbio_wire::protocol::{DeviceInfoResponse, Message, Promise};
/// fn take_twice(pending: Promise<Message>) {
///     let _ = pending.wait::<DeviceInfoResponse>();
///     let _ = pending.wait::<DeviceInfoResponse>();
/// }
/// ```
pub struct Promise<T> {
    /// Sole observer; only the session registry owns the result sender. Buffered
    /// results survive session destruction without retaining its other operations.
    result: mpsc::Receiver<Result<T, Error>>,
    /// Original session, used to service expiry when the waiter reaches its deadline.
    session: Weak<Shared>,
    /// Submission deadline, never recomputed when observation starts.
    deadline: Instant,
    /// One-shot notification just before entering the blocking receive.
    #[cfg(test)]
    waiting: Option<mpsc::Sender<()>>,
}

impl Promise<Message> {
    /// Blocks for completion under the request's original absolute deadline.
    /// Selects the expected response type at this call, either through inference
    /// or `wait::<Response>()`. Message extraction checks the content variant and
    /// returns [`Error::UnexpectedResponse`] on mismatch. The [`Message`] enum can
    /// also be taken directly for application pattern matching.
    pub fn wait<T>(self) -> Result<T, Error>
    where
        T: TryFrom<Message>,
        Error: From<T::Error>,
    {
        T::try_from(self.receive()?).map_err(Error::from)
    }
}

impl Promise<()> {
    /// Blocks for local write/flush completion under the reply's original deadline.
    /// The peer does not send another acknowledgment for this reply.
    pub fn wait(self) -> Result<(), Error> {
        self.receive()
    }
}

impl<T> Promise<T> {
    /// Creates a promise and its sole result sender before registration makes
    /// output visible. One slot buffers completion without waiting for observation.
    pub(super) fn pair(
        session: Weak<Shared>,
        deadline: Instant,
    ) -> (mpsc::SyncSender<Result<T, Error>>, Self) {
        let (sender, result) = mpsc::sync_channel(1);
        (
            sender,
            Self {
                result,
                session,
                deadline,
                #[cfg(test)]
                waiting: None,
            },
        )
    }

    /// Waits for the one accepted result. A delayed waiter first services expiry;
    /// an already-buffered result is unaffected. Timeout wakes also go through the
    /// session lock, so racing completion and retirement use the same decision point.
    fn receive(self) -> Result<T, Error> {
        if let Some(session) = self.session.upgrade() {
            session.expire();
        }
        #[cfg(test)]
        if let Some(waiting) = self.waiting {
            let _ = waiting.send(());
        }
        loop {
            match self
                .result
                .recv_timeout(self.deadline.saturating_duration_since(Instant::now()))
            {
                Ok(result) => return result,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if let Some(session) = self.session.upgrade() {
                        session.expire();
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    unreachable!("registered operation settles before its sender is released");
                }
            }
        }
    }

    /// Arms notification before a scenario starts observing an unresolved promise.
    /// Channels retain sent results, so completion cannot lose a wakeup even if it
    /// races the receiver's entry into its blocking call.
    #[cfg(test)]
    pub(super) fn watch(&mut self) -> mpsc::Receiver<()> {
        let (sender, receiver) = mpsc::channel();
        self.waiting = Some(sender);
        receiver
    }
}

/// Checks that both promise owners can be transferred to application threads.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{Message, Promise};

    /// Checks the send bound required to transfer ownership to an application thread.
    #[test]
    fn test_thread_capabilities() {
        /// Requires an owned value to be transferable to a background thread.
        fn movable<T: Send + 'static>() {}
        movable::<Promise<Message>>();
        movable::<Promise<()>>();
    }
}
