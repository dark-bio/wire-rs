// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Waiting for request answers and reply write results.

use super::session::SessionInner;
use super::{Error, Message};
use std::sync::{Weak, mpsc};
#[cfg(any(test, feature = "fuzz"))]
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
/// fn take_twice(promise: Promise<Message>) {
///     let _ = promise.wait::<DeviceInfoResponse>();
///     let _ = promise.wait::<DeviceInfoResponse>();
/// }
/// ```
pub struct Promise<T> {
    /// Receives one result from the corresponding `PendingOperation`. A buffered
    /// result remains available even after the session is dropped.
    result: mpsc::Receiver<Result<T, Error>>,
    /// Lets the waiter call `SessionInner::expire()` when its deadline is reached.
    session: Weak<SessionInner>,
    /// Deadline supplied with the request or reply. `wait()` does not restart it.
    deadline: Instant,
    /// One-shot notification just before entering the blocking receive.
    #[cfg(any(test, feature = "fuzz"))]
    wait_hook: Option<mpsc::Sender<()>>,
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
        T::try_from(self.wait_result()?).map_err(Error::from)
    }
}

impl Promise<()> {
    /// Blocks for local write/flush completion under the reply's original deadline.
    /// The peer does not send another acknowledgment for this reply.
    pub fn wait(self) -> Result<(), Error> {
        self.wait_result()
    }
}

impl<T> Promise<T> {
    /// Creates a promise and the sender that its `PendingOperation` will own.
    /// The channel holds one result without waiting for the caller to receive it.
    pub(super) fn pair(
        session: Weak<SessionInner>,
        deadline: Instant,
    ) -> (mpsc::SyncSender<Result<T, Error>>, Self) {
        let (sender, result) = mpsc::sync_channel(1);
        (
            sender,
            Self {
                result,
                session,
                deadline,
                #[cfg(any(test, feature = "fuzz"))]
                wait_hook: None,
            },
        )
    }

    /// Waits for the result channel. On timeout, asks the session to expire pending
    /// operations, then reads the result it sent. The session decides whether an
    /// answer or timeout came first; results already in the channel are kept.
    fn wait_result(self) -> Result<T, Error> {
        if let Some(session) = self.session.upgrade() {
            session.expire();
        }
        #[cfg(any(test, feature = "fuzz"))]
        if let Some(wait_hook) = self.wait_hook {
            let _ = wait_hook.send(());
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

    /// Notifies a test just before `wait_result()` starts waiting on the result channel.
    /// A result sent before the wait stays buffered in that channel.
    #[cfg(any(test, feature = "fuzz"))]
    pub(super) fn watch_wait(&mut self) -> mpsc::Receiver<()> {
        let (sender, receiver) = mpsc::channel();
        self.wait_hook = Some(sender);
        receiver
    }

    /// Waits for a worker result without calling `SessionInner::expire()`, so tests
    /// can prove workers process deadlines without help from `Promise::wait()`.
    /// Fails the test if the result does not arrive within five seconds.
    #[cfg(any(test, feature = "fuzz"))]
    pub(super) fn wait_worker_result(self) -> Result<T, Error> {
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
