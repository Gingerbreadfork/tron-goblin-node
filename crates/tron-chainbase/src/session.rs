//! Transactional [`KvBackend`] wrapper — the foundation for per-tx
//! rollback in the block executor.
//!
//! A [`SessionBackend`] wraps a parent [`KvBackend`] and buffers all
//! writes into a private pending overlay. Reads transparently fall
//! through to the parent unless the key has been written in the session.
//!
//! ```text
//!                ┌─────────────────────────────────────┐
//!                │  SessionBackend                     │
//!     reads ──▶  │   pending: { k → Put(v) | Delete }  │ ──▶  parent
//!     writes ─▶  │                                     │
//!                └─────────────────────────────────────┘
//!                       │              │
//!                  commit()       revert()
//!                       │              │
//!                       ▼              └▶ pending cleared
//!                  flushes pending writes to parent,
//!                  then clears the overlay.
//! ```
//!
//! **Mirrors java-tron**: `org.tron.core.db2.core.SnapshotImpl` is the
//! same idea — a copy-on-write overlay tied to a tx (or block) lifetime
//! that commits to a `SnapshotRoot` (the persistent base) on success.
//!
//! **Isolation guarantee**: writes performed via a `SessionBackend` are
//! invisible to anyone reading the parent directly, until `commit()`
//! is called. Sibling sessions over the same parent are isolated from
//! each other.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};

use crate::backend::{KvBackend, WriteOp};

/// A single pending mutation in a session's overlay.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Op {
    Put(Vec<u8>),
    Delete,
}

/// Transactional wrapper around a [`KvBackend`].
///
/// Construct via [`SessionBackend::new`]; mutate freely via [`KvBackend`]
/// methods; commit or revert via the namesake methods.
///
/// All operations are thread-safe — internal state is guarded by an
/// `RwLock`. Multiple readers in parallel are fine; writers take an
/// exclusive lock.
pub struct SessionBackend {
    parent: Arc<dyn KvBackend>,
    pending: RwLock<HashMap<Vec<u8>, Op>>,
}

impl SessionBackend {
    /// Wrap `parent` in a fresh, empty session.
    pub fn new(parent: Arc<dyn KvBackend>) -> Self {
        Self {
            parent,
            pending: RwLock::new(HashMap::new()),
        }
    }

    /// Flush all pending writes to the parent and clear the overlay.
    ///
    /// After this returns, reads through this session continue to work
    /// (they see whatever the parent now contains); future writes start
    /// a fresh overlay.
    ///
    /// **Atomicity**: the writes are pushed to the parent through a
    /// single [`KvBackend::write_batch`] call. The atomicity guarantee
    /// the caller gets is the parent's — `MemBackend` applies the whole
    /// batch under one write-lock; `RocksDbBackend` submits a single
    /// `rocksdb::WriteBatch` (WAL-backed, all-or-nothing across a
    /// crash). A custom parent that doesn't override `write_batch`
    /// falls back to per-key `put`/`delete`, which is non-atomic — fine
    /// for test stubs, not for production stores.
    pub fn commit(&self) {
        let drained = {
            let mut g = self.pending.write().expect("SessionBackend lock poisoned");
            std::mem::take(&mut *g)
        };
        if drained.is_empty() {
            return;
        }
        let ops: Vec<WriteOp> = drained
            .into_iter()
            .map(|(key, op)| match op {
                Op::Put(value) => WriteOp::Put(key, value),
                Op::Delete => WriteOp::Delete(key),
            })
            .collect();
        self.parent.write_batch(&ops);
    }

    /// Same as [`commit`], but for every pending key, read the parent's
    /// current value BEFORE applying the new one and return the
    /// captured `(key, before)` pairs as an undo log. Used by
    /// block-level rollback (KhaosDb Phase B): the executor wraps a
    /// whole block's commits in undo capture, persists the result to a
    /// `BlockUndoStore`, and on reorg replays the captured pairs in
    /// reverse to restore the pre-block state.
    ///
    /// `before == None` means the key didn't exist before (so rollback
    /// must `delete` it). `before == Some(v)` means rollback must `put`
    /// the old value back.
    ///
    /// Reads the parent's current value for every drained key BEFORE
    /// submitting the batch — captures the true pre-images. The batch
    /// itself is atomic per the same guarantees as [`commit`].
    ///
    /// [`commit`]: SessionBackend::commit
    pub fn commit_with_undo(&self) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
        let drained = {
            let mut g = self.pending.write().expect("SessionBackend lock poisoned");
            std::mem::take(&mut *g)
        };
        if drained.is_empty() {
            return Vec::new();
        }
        let mut undo = Vec::with_capacity(drained.len());
        let mut ops = Vec::with_capacity(drained.len());
        for (key, op) in drained {
            let before = self.parent.get(&key);
            undo.push((key.clone(), before));
            ops.push(match op {
                Op::Put(value) => WriteOp::Put(key, value),
                Op::Delete => WriteOp::Delete(key),
            });
        }
        self.parent.write_batch(&ops);
        undo
    }

    /// Discard all pending writes. The parent is unaffected.
    pub fn revert(&self) {
        self.pending
            .write()
            .expect("SessionBackend lock poisoned")
            .clear();
    }

    /// Number of distinct keys currently in the overlay.
    pub fn pending_len(&self) -> usize {
        self.pending
            .read()
            .expect("SessionBackend lock poisoned")
            .len()
    }

    /// `true` if there are no pending writes.
    pub fn is_clean(&self) -> bool {
        self.pending_len() == 0
    }
}

impl KvBackend for SessionBackend {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let g = self.pending.read().expect("SessionBackend lock poisoned");
        match g.get(key) {
            Some(Op::Put(v)) => Some(v.clone()),
            Some(Op::Delete) => None,
            None => {
                // Drop the read guard before delegating to the parent —
                // some parent implementations may take their own locks
                // and we don't want to risk reentrant deadlocks.
                drop(g);
                self.parent.get(key)
            }
        }
    }

    fn put(&self, key: &[u8], value: &[u8]) {
        self.pending
            .write()
            .expect("SessionBackend lock poisoned")
            .insert(key.to_vec(), Op::Put(value.to_vec()));
    }

    fn delete(&self, key: &[u8]) {
        self.pending
            .write()
            .expect("SessionBackend lock poisoned")
            .insert(key.to_vec(), Op::Delete);
    }

    /// Snapshot: parent state with the pending overlay applied. Uses
    /// a `BTreeMap` to deduplicate and sort — pending writes shadow
    /// parent entries; pending deletes remove them.
    fn scan_all(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut merged: BTreeMap<Vec<u8>, Vec<u8>> = self.parent.scan_all().into_iter().collect();
        let g = self.pending.read().expect("SessionBackend lock poisoned");
        for (k, op) in g.iter() {
            match op {
                Op::Put(v) => {
                    merged.insert(k.clone(), v.clone());
                }
                Op::Delete => {
                    merged.remove(k);
                }
            }
        }
        merged.into_iter().collect()
    }
}
