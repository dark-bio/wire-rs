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
/// [`Promise::wait`] or drop. It stays encoded until waiting decodes it. Late
/// answers and answers with no matching request are discarded. Answers whose
/// promises were dropped are also discarded. Their payloads are never decoded.
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
    /// Channel receiving one result from the corresponding
    /// [`PendingOperation`](super::operation::PendingOperation).
    ///
    /// A buffered result remains available even after the session is dropped.
    result: mpsc::Receiver<Result<PromiseResult, Error>>,
    /// Completion and its optional notification, independent of session lifetime.
    notification: Arc<Mutex<NotificationState>>,
    /// Whether a callback was registered, since registration is single-use even
    /// after the notification has been sent.
    registered: bool,
    /// Marker for the public result type, since the channel carries responses
    /// still encoded.
    value: PhantomData<fn() -> T>,
    /// Session whose expired operations the waiter settles before receiving
    /// its result.
    session: Weak<SessionInner>,
    /// Deadline supplied with the request or reply, which waiting does not restart.
    deadline: Instant,
    /// One-shot notification just before entering the blocking receive.
    #[cfg(any(test, feature = "fuzz"))]
    wait_hook: Option<mpsc::Sender<()>>,
}

impl Promise<Message> {
    /// Blocks for completion, then decodes the response.
    ///
    /// The response must be accepted before the request's original deadline.
    /// Decoding is outside that deadline. An accepted response remains available
    /// after the deadline or closure.
    ///
    /// Taking the response removes its bytes from the inbound byte count before
    /// decoding it. A peer's error answer returns [`Error::Remote`]. Invalid
    /// protobuf returns [`Error::Malformed`] and closes its original session.
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

    /// Waits for the reader or the deadline worker to settle the promise,
    /// without servicing deadlines itself.
    #[cfg(any(test, feature = "fuzz"))]
    pub(super) fn wait_worker_result(self) -> Result<Message, Error> {
        self.worker_result()?.response()
    }
}

impl Promise<()> {
    /// Blocks until the reply is written and flushed locally, under its original
    /// deadline.
    ///
    /// The peer does not send another acknowledgment for this reply.
    pub fn wait(self) -> Result<(), Error> {
        self.wait_result()?.written()
    }

    /// Waits for the writer or the deadline worker to settle the promise,
    /// without servicing deadlines itself.
    #[cfg(any(test, feature = "fuzz"))]
    pub(super) fn wait_worker_result(self) -> Result<(), Error> {
        self.worker_result()?.written()
    }
}

impl<T> Promise<T> {
    /// Creates a promise and the sender that its
    /// [`PendingOperation`](super::operation::PendingOperation) will own.
    ///
    /// The channel holds one result without waiting for the caller to receive
    /// it. The `response` flag marks a request, which expects a peer answer
    /// rather than a local write result.
    pub(super) fn pair(
        session: Weak<SessionInner>,
        deadline: Instant,
        response: bool,
    ) -> (ResultSender, Self) {
        // Give completion one buffered result and a shared notification state
        let (sender, result) = mpsc::sync_channel(1);
        let notification = Arc::new(Mutex::new(NotificationState::default()));

        // Keep publication and observation independent of the session's lifetime
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

    /// Runs `callback` once the result is ready.
    ///
    /// Requests notify on a response or an error, replies on local write and
    /// flush completion or an error, so a notification implies neither success
    /// nor peer receipt. The result is published first, so [`Promise::wait`]
    /// then takes it without waiting for publication, though it still decodes
    /// a response.
    ///
    /// Registering or receiving a notification neither decodes the response nor
    /// releases its retained bytes. They remain charged until waiting or drop.
    /// Deadlines are unchanged, and registration does not service expiry.
    ///
    /// On a settled promise, the callback runs at once on the registering thread,
    /// even after its session is gone. Otherwise the thread settling the operation
    /// runs it, which can be a protocol worker. Either way it runs, and its captures
    /// drop, outside every wire lock, so it may call back into the session. It must
    /// return promptly and must not panic.
    ///
    /// Dropping the promise drops a callback still waiting for settlement, without
    /// canceling the operation. A callback already taken by settlement still runs.
    ///
    /// # Panics
    /// Panics if notification was already registered on this promise.
    pub fn notify(&mut self, callback: impl FnOnce() + Send + 'static) {
        // Check before locking so caller misuse cannot poison shared state and
        // cause another panic when the promise is dropped during unwinding
        assert!(!self.registered, "promise notification already registered");

        // Serialize registration with publication and promise drop
        self.registered = true;
        let mut notification = self.notification.lock().expect("notification not poisoned");
        if notification.done {
            drop(notification);
            callback();
        } else {
            notification.hook = Some(Box::new(callback));
        }
    }

    /// Expires pending operations, then waits for the session to publish its result.
    ///
    /// The session decides whether an answer or timeout came first.
    #[allow(unused_mut)] // only test and fuzz builds mutate self, taking the wait hook
    fn wait_result(mut self) -> Result<PromiseResult, Error> {
        // Settle any operations already expired before waiting
        if let Some(session) = self.session.upgrade() {
            session.expire();
        }

        // Let scenarios observe entry into the receive
        #[cfg(any(test, feature = "fuzz"))]
        if let Some(wait_hook) = self.wait_hook.take() {
            let _ = wait_hook.send(());
        }

        // Let the deadline worker settle timeouts while this receive stays untimed
        match self.result.recv() {
            Ok(result) => result,
            Err(mpsc::RecvError) => {
                unreachable!("registered operation settles before its sender is released");
            }
        }
    }

    /// Arms a one-shot notification sent just before [`Self::wait_result`]
    /// starts waiting on the result channel.
    ///
    /// A result sent before the wait stays buffered in that channel.
    #[cfg(any(test, feature = "fuzz"))]
    pub(super) fn watch_wait(&mut self) -> mpsc::Receiver<()> {
        let (sender, receiver) = mpsc::channel();
        self.wait_hook = Some(sender);
        receiver
    }

    /// Returns a probe reporting whether the notification lock is free, usable
    /// after the promise is gone.
    #[cfg(test)]
    pub(super) fn notification_unlocked(&self) -> impl Fn() -> bool + Send + 'static {
        let notification = self.notification.clone();
        move || notification.try_lock().is_ok()
    }

    /// Waits for a worker result without calling [`SessionInner::expire`], so
    /// tests can prove workers process deadlines without help from
    /// [`Promise::wait`].
    #[cfg(any(test, feature = "fuzz"))]
    fn worker_result(self) -> Result<PromiseResult, Error> {
        self.result
            .recv()
            .expect("protocol worker must settle the promise")
    }
}

impl<T> Drop for Promise<T> {
    /// Takes an unrun callback under the notification lock, then drops it outside.
    ///
    /// The protocol never drops a handed-out promise under its session lock.
    fn drop(&mut self) {
        // Clear registration before releasing the lock
        let hook = self
            .notification
            .lock()
            .expect("notification not poisoned")
            .hook
            .take();

        // Release application captures without the notification lock
        drop(hook);
    }
}

impl<T> fmt::Debug for Promise<T> {
    /// Shows the deadline, whether a notification is registered and whether
    /// the result has been published.
    ///
    /// A notification lock held elsewhere leaves the completion out.
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

/// Notification state shared by a promise and its sender, surviving the
/// session without retaining it.
#[derive(Default)]
struct NotificationState {
    /// Whether the result has been published, including when no hook was
    /// registered yet.
    done: bool,
    /// Application callback taken by settlement or promise drop.
    hook: Option<Box<dyn FnOnce() + Send>>,
}

/// Single-use result sender for a request or reply.
///
/// Its one-slot channel never needs to wait for the application to receive
/// the result.
pub(super) struct ResultSender {
    /// Whether the operation is a request expecting a peer answer, rather than
    /// a reply expecting local write completion.
    pub(super) response: bool,
    /// Channel carrying exactly one result before this sender is released.
    result: mpsc::SyncSender<Result<PromiseResult, Error>>,
    /// State serializing publication and notification with registration and
    /// promise drop.
    notification: Arc<Mutex<NotificationState>>,
}

impl ResultSender {
    /// Publishes the result and hands back its callback, to run once the caller
    /// holds no wire lock.
    ///
    /// Byte admission reads the delivery flag to learn whether the promise
    /// still exists.
    pub(super) fn send(self, result: Result<PromiseResult, Error>) -> Notification {
        // Lock before publishing, so a concurrent waiter cannot drop the promise
        // and clear its hook between receiving the result and our notification
        let mut notification = self.notification.lock().expect("notification not poisoned");
        let delivered = self.result.send(result).is_ok();
        if delivered {
            notification.done = true;
        }

        // Hand ownership to the caller before releasing the publication lock
        Notification {
            delivered,
            callback: notification.hook.take(),
        }
    }
}

/// Publication status and the callback to run once every wire lock is released.
#[must_use = "collect the notification and run it outside all wire locks"]
pub(super) struct Notification {
    /// Whether the promise still existed when its result was published.
    pub(super) delivered: bool,
    /// Callback removed atomically with result publication.
    callback: Option<Box<dyn FnOnce() + Send>>,
}

impl Notification {
    /// Runs the callback and drops its captures on the settling thread.
    pub(super) fn run(self) {
        if let Some(callback) = self.callback {
            callback();
        }
    }
}

/// Collector of callbacks that run on scope exit, including early returns.
///
/// Declare it before acquiring any wire locks, so their guards drop first.
#[derive(Default)]
pub(super) struct Notifications {
    /// Callbacks taken from promises settled in this scope.
    pending: Vec<Notification>,
}

impl Notifications {
    /// Retains callbacks until the caller has released its locks.
    pub(super) fn push(&mut self, notification: Notification) {
        if notification.callback.is_some() {
            self.pending.push(notification);
        }
    }

    /// Reports whether no callback is waiting to run.
    pub(super) fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

impl Drop for Notifications {
    /// Runs callbacks after guards declared later in the scope have released locks.
    fn drop(&mut self) {
        for notification in self.pending.drain(..) {
            notification.run();
        }
    }
}

/// An operation result before the application waits on its promise.
pub(super) enum PromiseResult {
    /// Original response bytes, decoded only when a request promise is observed.
    Response(IncomingEnvelope),
    /// Completion of the local reply write and flush, with no incoming message.
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

/// Checks promise notifications and that promises move to application threads.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{Error, Message, NotificationState, Promise, PromiseResult};
    use darkbio_clock::TestClock;
    use std::fmt::Debug;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::{Arc, Mutex, Weak, mpsc};
    use std::time::Duration;

    /// Checks that a duplicate registration panics and leaves the original
    /// callback and result usable.
    #[test]
    fn test_duplicate_notification() {
        for completed in [false, true] {
            // Register a callback on a pending promise
            let tester = TestClock::new();
            let (sender, mut promise) =
                Promise::<()>::pair(Weak::new(), tester.clock().now(), false);
            let (events, receiver) = mpsc::channel();
            promise.notify(move || {
                let _ = events.send(1);
            });

            // Reject another registration before or after settlement
            let sender = if completed {
                sender.send(Ok(PromiseResult::Written)).run();
                None
            } else {
                Some(sender)
            };
            assert!(
                catch_unwind(AssertUnwindSafe(
                    || promise.notify(|| panic!("duplicate callback ran"))
                ))
                .is_err()
            );

            // Keep the first callback and result intact without poisoning the lock
            if let Some(sender) = sender {
                sender.send(Ok(PromiseResult::Written)).run();
            }
            assert_eq!(receiver.try_recv(), Ok(1));
            assert!(receiver.try_recv().is_err());
            promise.wait().unwrap();
        }
    }

    /// Checks that a callback whose consumer is gone leaves success and failure
    /// results unchanged.
    #[test]
    fn test_disconnected_notification() {
        for completed in [false, true] {
            for success in [false, true] {
                // Disconnect the callback's consumer before registering it
                let tester = TestClock::new();
                let (sender, mut promise) =
                    Promise::<()>::pair(Weak::new(), tester.clock().now(), false);
                let (events, receiver) = mpsc::channel();
                drop(receiver);

                // Register on either side of publishing success or failure
                let result = if success {
                    Ok(PromiseResult::Written)
                } else {
                    Err(Error::Timeout)
                };
                if completed {
                    sender.send(result).run();
                    promise.notify(move || {
                        let _ = events.send(1);
                    });
                } else {
                    promise.notify(move || {
                        let _ = events.send(1);
                    });
                    sender.send(result).run();
                }

                // Observe the original result despite the lost notification consumer
                match promise.wait() {
                    Ok(()) => assert!(success),
                    Err(Error::Timeout) => assert!(!success),
                    result => panic!("unexpected result: {result:?}"),
                }
            }
        }
    }

    /// Checks that a returning waiter cannot clear a callback already taken by
    /// publication.
    #[test]
    fn test_notification_with_waiter() {
        for _ in 0..32 {
            // Register a callback and start a waiter before publishing
            let tester = TestClock::new();
            let (sender, mut promise) = Promise::<()>::pair(
                Weak::new(),
                tester.clock().now() + Duration::from_secs(5),
                false,
            );
            let (events, receiver) = mpsc::channel();
            promise.notify(move || {
                let _ = events.send(1);
            });
            let waiting = promise.watch_wait();
            let waiter = std::thread::spawn(move || promise.wait());
            waiting.recv().unwrap();

            // Let the waiter drop its promise before running the taken callback
            let notification = sender.send(Ok(PromiseResult::Written));
            waiter.join().unwrap().unwrap();
            notification.run();

            // Require exactly one notification after the promise is gone
            assert_eq!(receiver.try_recv(), Ok(1));
            assert!(receiver.try_recv().is_err());
        }
    }

    /// Checks that dropping a pending promise releases its callback captures
    /// outside the notification lock.
    #[test]
    fn test_dropped_promise_releases_callback_without_lock() {
        /// Capture reporting whether its destruction can acquire the
        /// notification lock.
        struct Capture {
            /// Shared registration state surviving the dropped promise.
            notification: Arc<Mutex<NotificationState>>,
            /// Channel reporting destruction to the test without blocking.
            dropped: mpsc::Sender<bool>,
        }

        impl Drop for Capture {
            /// Checks the lock from application destruction code.
            fn drop(&mut self) {
                let _ = self.dropped.send(self.notification.try_lock().is_ok());
            }
        }

        // Register a callback whose capture checks its destruction context
        let tester = TestClock::new();
        let (sender, mut promise) = Promise::<()>::pair(Weak::new(), tester.clock().now(), false);
        let (dropped, observed) = mpsc::channel();
        let capture = Capture {
            notification: promise.notification.clone(),
            dropped,
        };
        let (ran, running) = mpsc::channel();
        promise.notify(move || {
            let _ = ran.send(());
            drop(capture);
        });

        // Drop before settlement and require unlocked capture destruction
        drop(promise);
        assert_eq!(observed.try_recv(), Ok(true));
        assert!(running.try_recv().is_err());

        // Settle the abandoned operation without running its cleared callback
        let notification = sender.send(Ok(PromiseResult::Written));
        assert!(!notification.delivered);
        notification.run();
        assert!(running.try_recv().is_err());
        assert!(observed.try_recv().is_err());
    }

    /// Checks the bounds required to move a promise to an application thread
    /// and to print it.
    #[test]
    fn test_thread_capabilities() {
        /// Requires an owned value to be printable and transferable to a
        /// background thread.
        fn movable<T: Debug + Send + 'static>() {}
        movable::<Promise<Message>>();
        movable::<Promise<()>>();
    }
}
