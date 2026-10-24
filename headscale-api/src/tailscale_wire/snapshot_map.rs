//! Copy-on-write side tables retained by a control response snapshot.

use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::{
    collections::HashMap,
    hash::Hash,
    ops::{Deref, DerefMut},
    sync::Arc,
};

pub(super) struct SnapshotMap<K, V>(RwLock<Arc<HashMap<K, V>>>);

impl<K, V> Default for SnapshotMap<K, V> {
    fn default() -> Self {
        Self(RwLock::new(Arc::new(HashMap::new())))
    }
}

impl<K: Clone + Eq + Hash, V: Clone> SnapshotMap<K, V> {
    pub(super) fn read(&self) -> RwLockReadGuard<'_, Arc<HashMap<K, V>>> {
        self.0.read()
    }

    pub(super) fn write(&self) -> SnapshotMapWriteGuard<'_, K, V> {
        SnapshotMapWriteGuard(self.0.write())
    }
}

pub(super) struct SnapshotMapWriteGuard<'a, K, V>(RwLockWriteGuard<'a, Arc<HashMap<K, V>>>);

impl<K, V> Deref for SnapshotMapWriteGuard<'_, K, V> {
    type Target = HashMap<K, V>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<K: Clone + Eq + Hash, V: Clone> DerefMut for SnapshotMapWriteGuard<'_, K, V> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        Arc::make_mut(&mut self.0)
    }
}
