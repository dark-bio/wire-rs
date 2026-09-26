// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Protocol worker threads and the tracker letting scenarios wait for them.

#[cfg(any(test, feature = "fuzz"))]
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

/// Starts a named worker thread running `run`.
///
/// Failure to start or a panic in `run` aborts the process. In test and fuzz
/// builds, `tracker` counts the thread until `run` and its captured values drop.
pub(super) fn spawn(
    name: &str,
    #[cfg(any(test, feature = "fuzz"))] tracker: &Arc<Tracker>,
    run: impl FnOnce() + Send + 'static,
) {
    // Increment before spawning so `wait_stopped` cannot see zero while this
    // thread is still starting
    #[cfg(any(test, feature = "fuzz"))]
    {
        *tracker.active.lock().expect("worker count not poisoned") += 1;
    }

    // Run the task on its own thread, guarded until its state is released
    let guard = WorkerGuard {
        #[cfg(any(test, feature = "fuzz"))]
        tracker: tracker.clone(),
    };
    let result = thread::Builder::new().name(name.into()).spawn(move || {
        // Drop the guard after `run` releases its captured state. On panic,
        // unwinding drops the guard and its destructor aborts the process.
        run();
        drop(guard);
    });

    // A session cannot work without its workers, so a failed start is fatal
    if let Err(error) = result {
        tracing::error!("could not start protocol worker: {}", error);
        std::process::abort();
    }
}

/// Guard that aborts the process if its worker panics, and otherwise updates
/// the test tracker.
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

/// Counter of the worker threads that scenarios wait on to finish.
///
/// A client's tracker counts its reader, writer and deadline threads. A
/// server's counts its reader and the writer and deadline threads of all its
/// sessions. It exists only in test and fuzz builds.
#[cfg(any(test, feature = "fuzz"))]
#[derive(Default)]
pub(super) struct Tracker {
    /// Number of workers whose tasks have not completely exited.
    active: Mutex<usize>,
    /// Signal waking [`Self::wait_stopped`] when a worker finishes.
    stopped: Condvar,
}

#[cfg(any(test, feature = "fuzz"))]
impl Tracker {
    /// Waits for every worker to release its captured state.
    pub(super) fn wait_stopped(&self) {
        let mut active = self.active.lock().unwrap();
        while *active != 0 {
            active = self.stopped.wait(active).unwrap();
        }
    }
}
