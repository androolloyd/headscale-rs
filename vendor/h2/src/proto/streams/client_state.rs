// Copyright 2013 The Go Authors. All rights reserved.
// Selected Go lifecycle rules are adapted under the BSD license in LICENSE-GO.
// Native client connection ownership, following Go net/http/h2_bundle.go.
// Kept separate from Streams so an observer can outlive the transport itself.
use atomic_waker::AtomicWaker;
use std::sync::Mutex;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub(crate) struct GoLifecycle {
    state: Mutex<State>,
    changed: AtomicWaker,
}

#[derive(Debug)]
struct State {
    last_active: Instant,
    selected: bool,
    never_used: bool,
    closed: Option<crate::client::GoClosedState>,
}

impl GoLifecycle {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(State {
                last_active: tokio::time::Instant::now().into_std(),
                selected: false,
                never_used: true,
                closed: None,
            }),
            changed: AtomicWaker::new(),
        }
    }

    pub(crate) fn active(&self) {
        self.state.lock().unwrap().last_active = tokio::time::Instant::now().into_std();
    }

    pub(crate) fn opened(&self) {
        self.state.lock().unwrap().never_used = false;
    }

    pub(crate) fn mark_selected(&self) {
        self.state.lock().unwrap().selected = true;
    }

    pub(crate) fn close(&self, closed_on_idle: bool, go_away: bool, timeout: Duration) {
        let mut state = self.state.lock().unwrap();
        if state.closed.is_some() {
            return;
        }
        let wait = if timeout.is_zero() {
            Duration::from_secs(5)
        } else {
            timeout.min(Duration::from_secs(5))
        };
        let retain_until = if !state.selected && !closed_on_idle && !go_away {
            state
                .last_active
                .checked_add(wait)
                .filter(|until| *until > tokio::time::Instant::now().into_std())
        } else {
            None
        };
        state.closed = Some(crate::client::GoClosedState {
            never_used: state.never_used,
            closed_on_idle,
            go_away,
            retain_until,
        });
        drop(state);
        self.changed.wake();
    }

    pub(crate) fn snapshot_closed(&self) -> Option<crate::client::GoClosedState> {
        self.state.lock().unwrap().closed
    }

    pub(crate) fn poll_closed(&self, cx: &mut Context<'_>) -> Poll<crate::client::GoClosedState> {
        self.changed.register(cx.waker());
        match self.snapshot_closed() {
            Some(closed) => Poll::Ready(closed),
            None => Poll::Pending,
        }
    }
}
