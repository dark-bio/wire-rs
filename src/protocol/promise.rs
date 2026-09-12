// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Waiting for request answers and reply write results.

use super::envelope::IncomingEnvelope;
use super::session::SessionInner;
use super::{Error, Message};
use std::fmt;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex, Weak, mpsc};
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
/// use darkbio_wire::protocol::schema::DeviceInfoResponse;
/// use darkbio_wire::protocol::{Message, Promise};
/// fn take_twice(promise: Promise<Message>) {
///     let _ = promise.wait::<DeviceInfoResponse>();
///     let _ = promise.wait::<DeviceInfoResponse>();
/// }
/// ```
pub struct Promise<T> {
    /// Receives one result from the corresponding `PendingOperation`. A buffered
    /// result remains available even after the session is dropped.
    result: mpsc::Receiver<Result<PromiseResult, Error>>,
    /// Completion and its optional notification, independent of session lifetime.
    notification: Arc<Mutex<NotificationState>>,
    /// Registration is single-use even after the notification has been sent.
    registered: bool,
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
        response: bool,
    ) -> (ResultSender, Self) {
        let (sender, result) = mpsc::sync_channel(1);
        let notification = Arc::new(Mutex::new(NotificationState::default()));
        (
            ResultSender {
                response,
                result: sender,
                notification: notification.clone(),
            },
            Self {
                result,
                notification,
                registered: false,
                value: PhantomData,
                session,
                deadline,
                #[cfg(any(test, feature = "fuzz"))]
                wait_hook: None,
            },
        )
    }

    /// Sends `event` through the unbounded channel once a terminal result is ready.
    /// Requests notify on a response or error; replies notify on local write/flush
    /// completion or error. Notification does not imply success or peer receipt.
    /// The result is published before the event, so `wait()` can then extract it
    /// without waiting for completion. Response decoding still happens in `wait()`.
    ///
    /// Registering or receiving a notification neither decodes the response nor
    /// releases its retained bytes. They remain charged until `wait()` or drop.
    /// Deadlines are unchanged, and registration does not service expiry.
    ///
    /// An already-completed promise sends immediately on the registering thread,
    /// even after its session is gone. Otherwise the thread settling the operation
    /// sends the event. A disconnected notification receiver discards the event
    /// without affecting the result. Copy tokens cannot run application destructors
    /// on a protocol worker; keep any associated payload on the consumer's side.
    ///
    /// Dropping the promise clears an unsent notification without cancelling the
    /// operation. An event already sent can outlive its promise.
    ///
    /// # Panics
    /// Panics if notification was already registered on this promise.
    pub fn notify<E: Copy + Send + 'static>(&mut self, sender: mpsc::Sender<E>, event: E) {
        // Check before locking so caller misuse cannot poison shared state and
        // cause another panic when the promise is dropped during unwinding.
        assert!(!self.registered, "promise notification already registered");

        self.registered = true;
        let mut notification = self.notification.lock().expect("notification not poisoned");
        if notification.done {
            let _ = sender.send(event);
        } else {
            notification.hook = Some(Box::new(move || {
                let _ = sender.send(event);
            }));
        }
    }

    /// Waits for the result channel. On timeout, asks the session to expire pending
    /// operations, then reads the result it sent. The session decides whether an
    /// answer or timeout came first; results already in the channel are kept.
    #[allow(unused_mut)] // The test-only wait hook must be taken now that we implement Drop.
    fn wait_result(mut self) -> Result<PromiseResult, Error> {
        if let Some(session) = self.session.upgrade() {
            session.expire();
        }
        #[cfg(any(test, feature = "fuzz"))]
        if let Some(wait_hook) = self.wait_hook.take() {
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

impl<T> Drop for Promise<T> {
    /// Clears an unsent event. The protocol never drops a handed-out promise
    /// under its session lock; this path only takes the notification lock.
    fn drop(&mut self) {
        let hook = self
            .notification
            .lock()
            .expect("notification not poisoned")
            .hook
            .take();
        drop(hook);
    }
}

impl<T> fmt::Debug for Promise<T> {
    /// Shows the deadline, whether a notification is registered and whether
    /// the result has been published. A notification lock held elsewhere
    /// leaves the completion out.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut promise = f.debug_struct("Promise");
        promise
            .field("deadline", &self.deadline)
            .field("registered", &self.registered);
        if let Ok(notification) = self.notification.try_lock() {
            promise.field("done", &notification.done);
        }
        promise.finish_non_exhaustive()
    }
}

/// Shared notification state survives the session without retaining it.
#[derive(Default)]
struct NotificationState {
    /// The result has been published, including when no hook was registered yet.
    done: bool,
    /// Internally constructed channel send; never an application callback.
    hook: Option<Box<dyn FnOnce() + Send>>,
}

/// Single-use result sender for a request or reply. Its one-slot channel never
/// needs to wait for the application to receive the result.
pub(super) struct ResultSender {
    /// Requests expect peer answers; replies expect local write completion.
    pub(super) response: bool,
    /// Receives exactly one result before this sender is released.
    result: mpsc::SyncSender<Result<PromiseResult, Error>>,
    /// Serializes publication and notification with registration and promise drop.
    notification: Arc<Mutex<NotificationState>>,
}

impl ResultSender {
    /// Publishes before notifying, preserving disconnection for byte admission.
    pub(super) fn send(
        self,
        result: Result<PromiseResult, Error>,
    ) -> Result<(), mpsc::SendError<Result<PromiseResult, Error>>> {
        // Lock before publishing: a concurrent waiter must not drop the promise
        // and clear its hook between receiving the result and our notification.
        let mut notification = self.notification.lock().expect("notification not poisoned");
        self.result.send(result)?;
        notification.done = true;
        if let Some(hook) = notification.hook.take() {
            hook();
        }
        Ok(())
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
    use super::{Error, Message, Promise, PromiseResult};
    use std::fmt::Debug;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::{Weak, mpsc};
    use std::time::{Duration, Instant};

    /// Misuse panics before poisoning the lock, keeping the original registration
    /// and result usable whether the promise was pending or already completed.
    #[test]
    fn test_duplicate_notification() {
        for completed in [false, true] {
            let (sender, mut promise) = Promise::<()>::pair(Weak::new(), Instant::now(), false);
            let (events, receiver) = mpsc::channel();
            promise.notify(events.clone(), 1);
            let sender = if completed {
                assert!(sender.send(Ok(PromiseResult::Written)).is_ok());
                None
            } else {
                Some(sender)
            };
            assert!(catch_unwind(AssertUnwindSafe(|| promise.notify(events, 2))).is_err());
            if let Some(sender) = sender {
                assert!(sender.send(Ok(PromiseResult::Written)).is_ok());
            }
            assert_eq!(receiver.try_recv(), Ok(1));
            assert!(receiver.try_recv().is_err());
            promise.wait().unwrap();
        }
    }

    /// Losing the event consumer does not change success or failure, including
    /// when registration happens after publication and sender destruction.
    #[test]
    fn test_disconnected_notification() {
        for completed in [false, true] {
            for success in [false, true] {
                let (sender, mut promise) = Promise::<()>::pair(Weak::new(), Instant::now(), false);
                let (events, receiver) = mpsc::channel();
                drop(receiver);
                let result = if success {
                    Ok(PromiseResult::Written)
                } else {
                    Err(Error::Timeout)
                };
                if completed {
                    assert!(sender.send(result).is_ok());
                    promise.notify(events, 1);
                } else {
                    promise.notify(events, 1);
                    assert!(sender.send(result).is_ok());
                }
                match promise.wait() {
                    Ok(()) => assert!(success),
                    Err(Error::Timeout) => assert!(!success),
                    result => panic!("unexpected result: {result:?}"),
                }
            }
        }
    }

    /// A waiter can receive immediately after publication, but its Drop must not
    /// clear the hook before the sender has emitted the completion event.
    #[test]
    fn test_notification_with_waiter() {
        for _ in 0..32 {
            let (sender, mut promise) =
                Promise::<()>::pair(Weak::new(), Instant::now() + Duration::from_secs(5), false);
            let (events, receiver) = mpsc::channel();
            promise.notify(events, 1);
            let waiting = promise.watch_wait();
            let waiter = std::thread::spawn(move || promise.wait());
            waiting.recv_timeout(Duration::from_secs(5)).unwrap();
            assert!(sender.send(Ok(PromiseResult::Written)).is_ok());
            waiter.join().unwrap().unwrap();
            assert_eq!(receiver.try_recv(), Ok(1));
            assert!(receiver.try_recv().is_err());
        }
    }

    /// Checks the bounds required to move a promise to an application thread
    /// and to print it.
    #[test]
    fn test_thread_capabilities() {
        /// Requires an owned value to be printable and transferable to a background thread.
        fn movable<T: Debug + Send + 'static>() {}
        movable::<Promise<Message>>();
        movable::<Promise<()>>();
    }
}
