use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::Notify;

#[derive(Default)]
pub(super) struct NativeShutdown {
    state: Mutex<State>,
    changed: Notify,
}

#[derive(Default)]
struct State {
    closing: bool,
    work: usize,
}

pub(super) struct NativeWork {
    shutdown: Arc<NativeShutdown>,
}

impl NativeShutdown {
    pub(super) fn begin(self: &Arc<Self>) -> Option<NativeWork> {
        let mut state = self.state.lock();
        if state.closing {
            return None;
        }
        state.work += 1;
        Some(NativeWork {
            shutdown: self.clone(),
        })
    }

    pub(super) fn is_closing(&self) -> bool {
        self.state.lock().closing
    }

    pub(super) fn mark_closing(&self) {
        self.state.lock().closing = true;
    }

    pub(super) fn wake(&self) {
        self.changed.notify_waiters();
    }

    pub(super) async fn closing(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.is_closing() {
                return;
            }
            changed.await;
        }
    }

    pub(super) async fn drained(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.state.lock().work == 0 {
                return;
            }
            changed.await;
        }
    }
}

impl Drop for NativeWork {
    fn drop(&mut self) {
        self.shutdown.state.lock().work -= 1;
        self.shutdown.changed.notify_waiters();
    }
}
