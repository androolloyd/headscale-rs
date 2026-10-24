// Copyright 2013 The Go Authors. All rights reserved.
// Native connection-cache ordering and retirement follow Go 1.26.9
// net/http/h2_bundle.go clientConnPool. See LICENSE-GO.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

use futures_channel::oneshot;
use hyper::rt::Timer as _;

use super::{Error, PoolClient};
use crate::common::{Exec, timer::Timer};

pub(super) enum Lookup<B> {
    Unknown,
    Available(PoolClient<B>),
    Saturated,
}

pub(super) struct Cache<B> {
    inner: Mutex<Inner<B>>,
    exec: Exec,
    timer: Option<Timer>,
}

struct Inner<B> {
    connections: HashMap<Arc<[u8]>, Vec<PoolClient<B>>>,
    dialing: HashMap<Arc<[u8]>, Dialing>,
}

struct Dialing {
    generation: Arc<()>,
    waiters: Vec<oneshot::Sender<Outcome>>,
}

#[derive(Clone)]
pub(super) enum Outcome {
    Retry,
    Failed(Arc<Error>),
}

pub(super) enum Dial<B> {
    Owner(DialGuard<B>),
    Wait(oneshot::Receiver<Outcome>),
}

pub(super) struct DialGuard<B> {
    cache: Weak<Cache<B>>,
    key: Arc<[u8]>,
    generation: Arc<()>,
    finished: bool,
}

impl<B> DialGuard<B> {
    pub(super) fn finish(&mut self, outcome: Outcome) {
        self.finished = true;
        let Some(cache) = self.cache.upgrade() else {
            return;
        };
        let waiters = {
            let mut inner = cache.inner.lock().unwrap();
            if inner
                .dialing
                .get(&self.key)
                .is_some_and(|dial| Arc::ptr_eq(&dial.generation, &self.generation))
            {
                inner.dialing.remove(&self.key).unwrap().waiters
            } else {
                Vec::new()
            }
        };
        for waiter in waiters {
            let _ = waiter.send(outcome.clone());
        }
    }
}

impl<B> Drop for DialGuard<B> {
    fn drop(&mut self) {
        if !self.finished {
            // A canceled owner does not leave an immortal in-flight dial.
            // Followers select a fresh owner using their own live request.
            self.finish(Outcome::Retry);
        }
    }
}

impl<B> Cache<B> {
    pub(super) fn new(exec: Exec, timer: Option<Timer>) -> Self {
        Self {
            inner: Mutex::new(Inner {
                connections: HashMap::new(),
                dialing: HashMap::new(),
            }),
            exec,
            timer,
        }
    }

    pub(super) fn begin_dial(self: &Arc<Self>, key: Arc<[u8]>) -> Dial<B> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(dial) = inner.dialing.get_mut(&key) {
            // Drop canceled receivers instead of retaining one entry for every
            // abandoned waiter until a slow network dial eventually completes.
            dial.waiters.retain(|waiter| !waiter.is_canceled());
            let (sender, receiver) = oneshot::channel();
            dial.waiters.push(sender);
            return Dial::Wait(receiver);
        }
        let generation = Arc::new(());
        inner.dialing.insert(
            key.clone(),
            Dialing {
                generation: generation.clone(),
                waiters: Vec::new(),
            },
        );
        Dial::Owner(DialGuard {
            cache: Arc::downgrade(self),
            key,
            generation,
            finished: false,
        })
    }

    pub(super) fn remove(&self, key: &[u8], identity: usize) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(connections) = inner.connections.get_mut(key) {
            connections.retain(|connection| {
                connection
                    .go_h2_state()
                    .is_some_and(|state| state.identity() != identity)
            });
            if connections.is_empty() {
                inner.connections.remove(key);
            }
        }
    }
}

impl<B: Send + 'static> Cache<B> {
    pub(super) fn checkout(&self, key: &[u8]) -> Lookup<B> {
        use hyper::client::conn::http2::GoAvailability;
        let mut inner = self.inner.lock().unwrap();
        let Some(connections) = inner.connections.get_mut(key) else {
            return Lookup::Unknown;
        };
        let mut index = 0;
        while index < connections.len() {
            let (availability, reserved) = connections[index].go_h2_reserve();
            match availability {
                Some(GoAvailability::Available) => {
                    return Lookup::Available(
                        reserved.expect("available checkout owns a reservation"),
                    );
                }
                Some(GoAvailability::Saturated) => index += 1,
                Some(GoAvailability::Unusable) | None => {
                    connections.remove(index);
                }
            }
        }
        if connections.is_empty() {
            inner.connections.remove(key);
            Lookup::Unknown
        } else {
            Lookup::Saturated
        }
    }

    pub(super) fn insert(self: &Arc<Self>, key: Arc<[u8]>, connection: PoolClient<B>) {
        let Some(state) = connection.go_h2_state() else {
            return;
        };
        let identity = state.identity();
        {
            let mut inner = self.inner.lock().unwrap();
            let list = inner.connections.entry(key.clone()).or_default();
            if list.iter().any(|existing| {
                existing
                    .go_h2_state()
                    .is_some_and(|state| state.identity() == identity)
            }) {
                return;
            }
            list.push(connection);
        }
        let cache = Arc::downgrade(self);
        let timer = self.timer.clone();
        self.exec.execute(async move {
            let closed = std::future::poll_fn(|cx| state.poll_closed(cx)).await;
            // Go briefly retains a never-selected early failure so the first
            // caller sees the connection error instead of silently redialing.
            if let (Some(deadline), Some(timer)) = (closed.retain_until, timer) {
                timer.sleep_until(deadline).await;
            }
            if let Some(cache) = cache.upgrade() {
                cache.remove(&key, identity);
            }
        });
    }
}

#[derive(Debug)]
pub(super) struct SharedDialError(pub(super) Arc<Error>);

impl std::fmt::Display for SharedDialError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self.0.as_ref(), formatter)
    }
}

impl std::error::Error for SharedDialError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}
