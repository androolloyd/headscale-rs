//! Native client response-body handshake, derived from Go 1.26.9
//! net/http/transport.go bodyEOFSignal and persistConn.readLoop.
//! See LICENSE-GO and LICENSE-GO-NOTICE for upstream attribution.

use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Pending,
    Eof,
    Early,
}

struct State {
    verdict: Verdict,
    done: bool,
    pool_required: bool,
    pool_done: bool,
    driver: Option<Waker>,
    consumer: Option<Waker>,
}

pub(crate) struct Consumer(Arc<Mutex<State>>);
pub(crate) struct Driver(Arc<Mutex<State>>);

/// Completes the native HTTP/1 pool-return decision when dropped.
#[doc(hidden)]
pub struct GoH1PoolWait(Arc<Mutex<State>>);

impl std::fmt::Debug for GoH1PoolWait {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("GoH1PoolWait(..)")
    }
}

pub(crate) fn channel() -> (Driver, Consumer) {
    let state = Arc::new(Mutex::new(State {
        verdict: Verdict::Pending,
        done: false,
        pool_required: false,
        pool_done: false,
        driver: None,
        consumer: None,
    }));
    (Driver(state.clone()), Consumer(state))
}

impl Consumer {
    pub(crate) fn pending(&self) -> bool {
        self.0.lock().unwrap().verdict == Verdict::Pending
    }

    pub(crate) fn verdict(&self, verdict: Verdict) {
        let task = {
            let mut state = self.0.lock().unwrap();
            if state.verdict != Verdict::Pending {
                return;
            }
            state.verdict = verdict;
            state.driver.take()
        };
        if let Some(task) = task {
            task.wake();
        }
    }

    pub(crate) fn poll_done(&self, cx: &Context<'_>) -> Poll<()> {
        let mut state = self.0.lock().unwrap();
        if state.done && (!state.pool_required || state.pool_done) {
            Poll::Ready(())
        } else {
            state.consumer = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub(crate) fn pool_wait(&self) -> GoH1PoolWait {
        self.0.lock().unwrap().pool_required = true;
        GoH1PoolWait(self.0.clone())
    }
}

impl Drop for GoH1PoolWait {
    fn drop(&mut self) {
        let task = {
            let mut state = self.0.lock().unwrap();
            state.pool_done = true;
            state.consumer.take()
        };
        if let Some(task) = task {
            task.wake();
        }
    }
}

impl Drop for Consumer {
    fn drop(&mut self) {
        // Cancellation of Close/Read must not leave the connection waiting for
        // a consumer that can no longer deliver its EOF decision.
        self.verdict(Verdict::Early);
    }
}

impl Driver {
    pub(crate) fn verdict(&self, cx: &Context<'_>) -> Verdict {
        let mut state = self.0.lock().unwrap();
        state.driver = Some(cx.waker().clone());
        state.verdict
    }

    pub(crate) fn complete(&self) {
        let task = {
            let mut state = self.0.lock().unwrap();
            state.done = true;
            state.consumer.take()
        };
        if let Some(task) = task {
            task.wake();
        }
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        // Covers connection errors and cancellation of the connection future.
        self.complete();
    }
}
