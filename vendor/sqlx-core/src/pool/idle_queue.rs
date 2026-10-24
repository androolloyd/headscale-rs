//! Optional bounded idle storage for the headscale database/sql pool bridge.
//! Upstream pools keep their original lock-free queue when no limit is set.

use crossbeam_queue::ArrayQueue;
use std::collections::VecDeque;
use std::sync::Mutex;

pub(super) enum IdleQueue<T> {
    Upstream(ArrayQueue<T>),
    Limited {
        capacity: usize,
        values: Mutex<VecDeque<T>>,
    },
}

impl<T> IdleQueue<T> {
    pub(super) fn new(max_connections: u32, max_idle: Option<u32>) -> Self {
        match max_idle {
            None => Self::Upstream(ArrayQueue::new(max_connections as usize)),
            Some(limit) => Self::Limited {
                capacity: limit.min(max_connections) as usize,
                values: Mutex::new(VecDeque::new()),
            },
        }
    }

    pub(super) fn push(&self, value: T) -> Result<(), T> {
        match self {
            Self::Upstream(queue) => queue.push(value),
            Self::Limited { capacity, values } => {
                let mut values = values.lock().expect("idle queue lock poisoned");
                if values.len() >= *capacity {
                    return Err(value);
                }
                values.push_back(value);
                Ok(())
            }
        }
    }

    pub(super) fn pop(&self) -> Option<T> {
        match self {
            Self::Upstream(queue) => queue.pop(),
            Self::Limited { values, .. } => {
                values.lock().expect("idle queue lock poisoned").pop_front()
            }
        }
    }

    /// Explicitly capped pools mirror database/sql's most-recently-returned
    /// reuse. Maintenance removes expired entries without rotating survivors.
    pub(super) fn pop_for_acquire(&self) -> Option<T> {
        match self {
            Self::Upstream(queue) => queue.pop(),
            Self::Limited { values, .. } => {
                values.lock().expect("idle queue lock poisoned").pop_back()
            }
        }
    }

    /// Remove an expired entry without rotating or refreshing other idle
    /// entries. Only explicitly capped pools use this maintenance path.
    pub(super) fn pop_matching(&self, mut predicate: impl FnMut(&T) -> bool) -> Option<T> {
        match self {
            Self::Upstream(_) => None,
            Self::Limited { values, .. } => {
                let mut values = values.lock().expect("idle queue lock poisoned");
                let index = values.iter().position(&mut predicate)?;
                values.remove(index)
            }
        }
    }
}
