// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Waiting for request answers and reply write results.

use super::session::Shared;
use super::{Error, Message};
use std::sync::{Weak, mpsc};
#[cfg(test)]
use std::time::Duration;
use std::time::Instant;

/// Result of a queued request or reply.
///
/// Requests return `Promise<Message>`; their wait selects the expected response
/// type or takes the message directly. Replies return `Promise<()>`; their wait
/// observes local writing and flushing, not peer receipt or processing.
///
/// Dropping a promise leaves the request or reply running with its original
/// deadline. The session still processes a later answer, but discards its result.
/// A timeout does not mean the peer stopped working. A completed result remains
/// available after the session closes. Each promise returns its result once:
///
/// ```compile_fail,E0382
/// use darkbio_wire::protocol::{DeviceInfoResponse, Message, Promise};
/// fn take_twice(pending: Promise<Message>) {
///     let _ = pending.wait::<DeviceInfoResponse>();
///     let _ = pending.wait::<DeviceInfoResponse>();
/// }
/// ```
pub struct Promise<T> {
    /// Receives one result from the corresponding `Operation`. A buffered result
    /// remains available even after the session is dropped.
    result: mpsc::Receiver<Result<T, Error>>,
    /// Lets the waiter call `Shared::expire()` when its deadline is reached.
    session: Weak<Shared>,
    /// Deadline supplied with the request or reply. `wait()` does not restart it.
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
    /// Creates a promise and the channel sender that its `Operation` will own.
    /// The channel holds one result without waiting for the caller to receive it.
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

    /// Waits for the result channel. On timeout, asks the session to expire pending
    /// operations, then reads the result it sent. The session decides whether an
    /// answer or timeout came first; results already in the channel are kept.
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

    /// Notifies a test just before `receive()` starts waiting on the result channel.
    /// A result sent before the wait stays buffered in that channel.
    #[cfg(test)]
    pub(super) fn watch(&mut self) -> mpsc::Receiver<()> {
        let (sender, receiver) = mpsc::channel();
        self.waiting = Some(sender);
        receiver
    }

    /// Reads the result without calling `Shared::expire()`, so tests can prove
    /// the workers process deadlines without help from `Promise::wait()`.
    #[cfg(test)]
    pub(super) fn settled(self) -> Result<T, Error> {
        self.result
            .recv_timeout(Duration::from_secs(5))
            .expect("protocol worker must settle the promise")
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
