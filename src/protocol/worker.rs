// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Starts protocol threads and lets scenarios wait for them to finish.

#[cfg(any(test, feature = "fuzz"))]
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

/// Starts a named thread. Failure to start or a panic in `run` aborts the process.
/// In tests, `tracker` counts the thread until `run` and its captured values drop.
pub(super) fn spawn(
    name: &str,
    #[cfg(any(test, feature = "fuzz"))] tracker: &Arc<Tracker>,
    run: impl FnOnce() + Send + 'static,
) {
    // Increment before spawning so wait_stopped() cannot see zero while this
    // thread is still starting.
    #[cfg(any(test, feature = "fuzz"))]
    {
        *tracker.active.lock().expect("worker count not poisoned") += 1;
    }
    let guard = WorkerGuard {
        #[cfg(any(test, feature = "fuzz"))]
        tracker: tracker.clone(),
    };
    let result = thread::Builder::new().name(name.into()).spawn(move || {
        // Drop the guard after run() releases its captured state. On panic,
        // unwinding drops the guard and its destructor aborts the process.
        run();
        drop(guard);
    });
    if let Err(error) = result {
        tracing::error!("could not start protocol worker: {}", error);
        std::process::abort();
    }
}

/// Aborts the process if the worker panics; otherwise updates the test tracker.
struct WorkerGuard {
    /// Counter shared with the scenario waiting for this worker to finish.
    #[cfg(any(test, feature = "fuzz"))]
    tracker: Arc<Tracker>,
}

impl Drop for WorkerGuard {
    /// Aborts on panic; otherwise records exit after the task released its state.
    fn drop(&mut self) {
        if thread::panicking() {
            tracing::error!("protocol worker panicked, aborting");
            std::process::abort();
        }
        #[cfg(any(test, feature = "fuzz"))]
        {
            *self.tracker.active.lock().unwrap() -= 1;
            self.tracker.stopped.notify_all();
        }
    }
}

/// Counts a client's reader, writer and deadline threads, or a server's reader
/// and the writer and deadline threads of all its sessions. Used only in tests.
#[cfg(any(test, feature = "fuzz"))]
#[derive(Default)]
pub(super) struct Tracker {
    /// Number of workers whose tasks have not completely exited.
    active: Mutex<usize>,
    /// Wakes `wait_stopped()` when a worker finishes.
    stopped: Condvar,
}

#[cfg(any(test, feature = "fuzz"))]
impl Tracker {
    /// Waits for the count to reach zero, failing the test after five seconds.
    pub(super) fn wait_stopped(&self) {
        use std::time::{Duration, Instant};
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut active = self.active.lock().unwrap();
        while *active != 0 {
            let (count, timeout) = self
                .stopped
                .wait_timeout(active, deadline.saturating_duration_since(Instant::now()))
                .unwrap();
            active = count;
            if timeout.timed_out() && *active != 0 {
                drop(active);
                panic!("protocol workers did not exit");
            }
        }
    }
}
