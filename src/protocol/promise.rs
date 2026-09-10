// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Waiting for request answers and reply write results.

use super::envelope::IncomingEnvelope;
use super::session::SessionInner;
use super::{Error, Message};
use std::marker::PhantomData;
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
/// deadline. A timeout does not mean the peer stopped working.
/// Completed results remain available after the session closes.
///
/// A buffered response counts toward the session's inbound byte limit until
/// `wait()` or drop. It stays encoded until `wait()` decodes it. Late answers and
/// answers with no matching request are discarded. Answers whose promises were
/// dropped are also discarded. Their payloads are never decoded.
///
/// Each promise returns its result once:
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
    result: mpsc::Receiver<Result<PromiseResult, Error>>,
    /// Public result type; responses stay encoded until `wait()`.
    value: PhantomData<fn() -> T>,
    /// Lets the waiter call `SessionInner::expire()` when its deadline is reached.
    session: Weak<SessionInner>,
    /// Deadline supplied with the request or reply. `wait()` does not restart it.
    deadline: Instant,
    /// One-shot notification just before entering the blocking receive.
    #[cfg(any(test, feature = "fuzz"))]
    wait_hook: Option<mpsc::Sender<()>>,
}

impl Promise<Message> {
    /// Blocks for completion, then decodes the response. The response must be
    /// accepted before the request's original deadline. Decoding is outside that
    /// deadline. An accepted response remains available after the deadline or closure.
    ///
    /// Taking the response removes its bytes from the inbound byte count before
    /// decoding it. Invalid protobuf returns [`Error::Malformed`] and closes its
    /// original session.
    ///
    /// Selects the expected response type at this call, either through inference
    /// or `wait::<Response>()`. Message extraction checks the content variant and
    /// returns [`Error::UnexpectedResponse`] on mismatch. The [`Message`] enum can
    /// also be taken directly for application pattern matching.
    pub fn wait<T>(self) -> Result<T, Error>
    where
        T: TryFrom<Message>,
        Error: From<T::Error>,
    {
        T::try_from(self.wait_result()?.response()?).map_err(Error::from)
    }

    /// Observes reader/deadline worker completion without servicing deadlines itself.
    #[cfg(any(test, feature = "fuzz"))]
    pub(super) fn wait_worker_result(self) -> Result<Message, Error> {
        self.worker_result()?.response()
    }
}

impl Promise<()> {
    /// Blocks for local write/flush completion under the reply's original deadline.
    /// The peer does not send another acknowledgment for this reply.
    pub fn wait(self) -> Result<(), Error> {
        self.wait_result()?.written()
    }

    /// Observes writer/deadline worker completion without servicing deadlines itself.
    #[cfg(any(test, feature = "fuzz"))]
    pub(super) fn wait_worker_result(self) -> Result<(), Error> {
        self.worker_result()?.written()
    }
}

impl<T> Promise<T> {
    /// Creates a promise and the sender that its `PendingOperation` will own.
    /// The channel holds one result without waiting for the caller to receive it.
    pub(super) fn pair(
        session: Weak<SessionInner>,
        deadline: Instant,
    ) -> (mpsc::SyncSender<Result<PromiseResult, Error>>, Self) {
        let (sender, result) = mpsc::sync_channel(1);
        (
            sender,
            Self {
                result,
                value: PhantomData,
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
    fn wait_result(self) -> Result<PromiseResult, Error> {
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
    fn worker_result(self) -> Result<PromiseResult, Error> {
        self.result
            .recv_timeout(Duration::from_secs(5))
            .expect("protocol worker must settle the promise")
    }
}

/// An operation result before the application waits on its promise.
pub(super) enum PromiseResult {
    /// Original response bytes, decoded only when a request promise is observed.
    Response(IncomingEnvelope),
    /// Local reply writing and flushing completed; no incoming message exists.
    Written,
}

impl PromiseResult {
    /// Decodes the response carried by a request operation's result channel.
    fn response(self) -> Result<Message, Error> {
        match self {
            Self::Response(message) => message.decode(),
            Self::Written => unreachable!("requests complete with responses"),
        }
    }

    /// Checks that a reply operation reported its local write completion.
    fn written(self) -> Result<(), Error> {
        match self {
            Self::Written => Ok(()),
            Self::Response(_) => unreachable!("replies complete with write results"),
        }
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
