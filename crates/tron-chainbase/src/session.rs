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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use crate::backend::{KvBackend, KvError, WriteOp};

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
    /// `false` while the overlay has never been written (set `true` by the
    /// first `put`/`delete`, reset by `commit`/`revert`/`drain_*`). When clean,
    /// `get` skips the `pending` `RwLock` entirely and reads the parent directly
    /// — every read during the input-reading phase of a tx (before it writes),
    /// and *every* read against a read-only base session (e.g. the block-level
    /// overlay during Block-STM parallel speculation, which 32 threads hammer
    /// concurrently), avoids an otherwise-pointless lock acquire. Writes/reads to
    /// one session are single-threaded per tx; the shared base session is only
    /// written between blocks (serially), never concurrently with the parallel
    /// read phase — so the flag never transitions while readers race it, and a
    /// `Relaxed` load is sufficient (the `RwLock` still guards real overlay
    /// access once dirty).
    dirty: AtomicBool,
}

impl SessionBackend {
    /// Wrap `parent` in a fresh, empty session.
    pub fn new(parent: Arc<dyn KvBackend>) -> Self {
        Self {
            parent,
            pending: RwLock::new(HashMap::new()),
            dirty: AtomicBool::new(false),
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
    pub fn commit(&self) -> Result<(), KvError> {
        let drained = {
            let mut g = self.pending.write().expect("SessionBackend lock poisoned");
            self.dirty.store(false, Ordering::Relaxed);
            std::mem::take(&mut *g)
        };
        if drained.is_empty() {
            return Ok(());
        }
        let ops: Vec<WriteOp> = drained
            .into_iter()
            .map(|(key, op)| match op {
                Op::Put(value) => WriteOp::Put(key, value),
                Op::Delete => WriteOp::Delete(key),
            })
            .collect();
        self.parent.write_batch(&ops)
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
    /// # Serialization requirement (C-7)
    ///
    /// The pending overlay is drained atomically (under the `pending`
    /// lock), but the before-image read at [`KvBackend::get`] and the
    /// final [`KvBackend::write_batch`] are **two separate steps against
    /// the parent**. The captured undo log is only correct if no other
    /// writer mutates the parent between them — otherwise a concurrent
    /// commit could change a value after we snapshot its "before image",
    /// and a later rollback would restore the wrong value.
    ///
    /// The block-apply pipeline provides this invariant: blocks are
    /// applied one at a time, so a block's undo-commit is the sole writer
    /// to the parent for its duration. Callers that share a parent across
    /// genuinely concurrent committers must serialize them externally
    /// (e.g. a parent-level exclusive lock) before calling this.
    ///
    /// [`commit`]: SessionBackend::commit
    pub fn commit_with_undo(&self) -> Result<Vec<(Vec<u8>, Option<Vec<u8>>)>, KvError> {
        // One implementation: this is `commit_with_undo_and_ops` with
        // the (internally-built-anyway) ops vec dropped. Keeping a
        // verbatim second copy of the drain/before-image/write-batch
        // sequence would let a future correctness change (locking,
        // error path) land on only one of the two commit flavors —
        // and these produce the undo logs rollback depends on.
        Ok(self.commit_with_undo_and_ops()?.1)
    }

    /// [`commit_with_undo`](Self::commit_with_undo) that also returns
    /// the applied write ops (post-images), parallel to the undo
    /// pairs (same key order). The ops vec is built internally either
    /// way; returning it costs nothing. Used by the executor's
    /// state-delta capture (`ExecConfig::capture_state_deltas`), which
    /// needs both the pre- and post-image of every key a block
    /// committed.
    pub fn commit_with_undo_and_ops(
        &self,
    ) -> Result<(Vec<WriteOp>, Vec<(Vec<u8>, Option<Vec<u8>>)>), KvError> {
        let drained = {
            let mut g = self.pending.write().expect("SessionBackend lock poisoned");
            self.dirty.store(false, Ordering::Relaxed);
            std::mem::take(&mut *g)
        };
        if drained.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        let mut undo = Vec::with_capacity(drained.len());
        let mut ops = Vec::with_capacity(drained.len());
        for (key, op) in drained {
            let before = self.parent.get(&key)?;
            undo.push((key.clone(), before));
            ops.push(match op {
                Op::Put(value) => WriteOp::Put(key, value),
                Op::Delete => WriteOp::Delete(key),
            });
        }
        self.parent.write_batch(&ops)?;
        Ok((ops, undo))
    }

    /// Drain pending writes WITHOUT applying them to the parent.
    /// Used when multiple sessions share one atomicity boundary —
    /// e.g., a block-level checkpoint that batches writes across many
    /// stores under one manifest. The caller is now responsible for
    /// persisting these via `parent.write_batch(..)` (or whatever
    /// equivalent the cross-store flush path arranges).
    ///
    /// After this returns, the session's overlay is empty, future
    /// writes start a fresh overlay, and reads through the session
    /// fall through to the parent (which the caller may or may not
    /// have updated yet).
    pub fn drain_pending(&self) -> Vec<WriteOp> {
        let drained = {
            let mut g = self.pending.write().expect("SessionBackend lock poisoned");
            self.dirty.store(false, Ordering::Relaxed);
            std::mem::take(&mut *g)
        };
        drained
            .into_iter()
            .map(|(key, op)| match op {
                Op::Put(value) => WriteOp::Put(key, value),
                Op::Delete => WriteOp::Delete(key),
            })
            .collect()
    }

    /// Same as [`drain_pending`] but also reads the parent's current
    /// value for every drained key — for block-level undo logs.
    /// Returns `(ops_to_apply, undo_pairs)` where each undo pair is
    /// `(key, before)` — `before == None` means the key didn't exist
    /// before (so rollback must `delete` it).
    ///
    /// The pre-image reads run BEFORE the caller's eventual
    /// `parent.write_batch(..)`, so they capture the true pre-block
    /// state.
    ///
    /// [`drain_pending`]: SessionBackend::drain_pending
    pub fn drain_pending_with_undo(
        &self,
    ) -> Result<(Vec<WriteOp>, Vec<(Vec<u8>, Option<Vec<u8>>)>), KvError> {
        let drained = {
            let mut g = self.pending.write().expect("SessionBackend lock poisoned");
            self.dirty.store(false, Ordering::Relaxed);
            std::mem::take(&mut *g)
        };
        let mut ops = Vec::with_capacity(drained.len());
        let mut undo = Vec::with_capacity(drained.len());
        for (key, op) in drained {
            let before = self.parent.get(&key)?;
            undo.push((key.clone(), before));
            ops.push(match op {
                Op::Put(value) => WriteOp::Put(key, value),
                Op::Delete => WriteOp::Delete(key),
            });
        }
        Ok((ops, undo))
    }

    /// Discard all pending writes. The parent is unaffected.
    pub fn revert(&self) {
        let mut g = self.pending.write().expect("SessionBackend lock poisoned");
        self.dirty.store(false, Ordering::Relaxed);
        g.clear();
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
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, KvError> {
        // Fast path: a never-written overlay has nothing to shadow the parent,
        // so skip the `pending` lock entirely (see the `dirty` field doc).
        if !self.dirty.load(Ordering::Relaxed) {
            return self.parent.get(key);
        }
        let g = self.pending.read().expect("SessionBackend lock poisoned");
        match g.get(key) {
            Some(Op::Put(v)) => Ok(Some(v.clone())),
            Some(Op::Delete) => Ok(None),
            None => {
                // Drop the read guard before delegating to the parent —
                // some parent implementations may take their own locks
                // and we don't want to risk reentrant deadlocks.
                drop(g);
                self.parent.get(key)
            }
        }
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), KvError> {
        self.dirty.store(true, Ordering::Relaxed);
        self.pending
            .write()
            .expect("SessionBackend lock poisoned")
            .insert(key.to_vec(), Op::Put(value.to_vec()));
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> Result<(), KvError> {
        self.dirty.store(true, Ordering::Relaxed);
        self.pending
            .write()
            .expect("SessionBackend lock poisoned")
            .insert(key.to_vec(), Op::Delete);
        Ok(())
    }

    /// Snapshot: parent state with the pending overlay applied. Uses
    /// a `BTreeMap` to deduplicate and sort — pending writes shadow
    /// parent entries; pending deletes remove them.
    fn scan_all(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, KvError> {
        let mut merged: BTreeMap<Vec<u8>, Vec<u8>> =
            self.parent.scan_all()?.into_iter().collect();
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
        Ok(merged.into_iter().collect())
    }

    /// Bounded forward scan, merging the overlay with the parent's NATIVE
    /// `scan_from`.
    ///
    /// The `KvBackend` default routes `scan_from` through `scan_all`, and
    /// this session's `scan_all` calls `parent.scan_all()` — which some
    /// parents deliberately do NOT support (an at-height archive view serves
    /// point + bounded scans but errors on unbounded `scan_all`). Routing a
    /// bounded scan through `scan_all` there fails outright, and even on a
    /// normal parent it forces an O(N) full-store read for an O(log N + limit)
    /// request. Delegating to `parent.scan_from` fixes both.
    fn scan_from(&self, start: &[u8], limit: usize) -> Result<Vec<(Vec<u8>, Vec<u8>)>, KvError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        // Clean overlay: the parent's bounded scan is authoritative.
        if !self.dirty.load(Ordering::Relaxed) {
            return self.parent.scan_from(start, limit);
        }
        // Snapshot the overlay ops at keys >= start, releasing the lock before
        // touching the parent (parents may take their own locks — see `get`).
        let ov: Vec<(Vec<u8>, Option<Vec<u8>>)> = {
            let g = self.pending.read().expect("SessionBackend lock poisoned");
            g.iter()
                .filter(|(k, _)| k.as_slice() >= start)
                .map(|(k, op)| {
                    let v = match op {
                        Op::Put(v) => Some(v.clone()),
                        Op::Delete => None,
                    };
                    (k.clone(), v)
                })
                .collect()
        };
        // Fetch `limit + deletes` parent rows: even if every overlay delete
        // removes a parent key ahead of a survivor, that many guarantees every
        // parent key that could land in the first `limit` merged rows is seen,
        // so `take(limit)` after the merge is exact.
        let deletes = ov.iter().filter(|(_, v)| v.is_none()).count();
        let mut merged: BTreeMap<Vec<u8>, Vec<u8>> = self
            .parent
            .scan_from(start, limit.saturating_add(deletes))?
            .into_iter()
            .collect();
        for (k, v) in ov {
            match v {
                Some(val) => {
                    merged.insert(k, val);
                }
                None => {
                    merged.remove(&k);
                }
            }
        }
        Ok(merged.into_iter().take(limit).collect())
    }

    /// Prefix scan, merging the overlay with the parent's NATIVE
    /// `scan_prefix` (same rationale as [`Self::scan_from`]: the default
    /// `scan_all`-based path errors over an at-height archive parent and is
    /// O(N) elsewhere).
    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, KvError> {
        if !self.dirty.load(Ordering::Relaxed) {
            return self.parent.scan_prefix(prefix);
        }
        let ov: Vec<(Vec<u8>, Option<Vec<u8>>)> = {
            let g = self.pending.read().expect("SessionBackend lock poisoned");
            g.iter()
                .filter(|(k, _)| k.starts_with(prefix))
                .map(|(k, op)| {
                    let v = match op {
                        Op::Put(v) => Some(v.clone()),
                        Op::Delete => None,
                    };
                    (k.clone(), v)
                })
                .collect()
        };
        let mut merged: BTreeMap<Vec<u8>, Vec<u8>> =
            self.parent.scan_prefix(prefix)?.into_iter().collect();
        for (k, v) in ov {
            match v {
                Some(val) => {
                    merged.insert(k, val);
                }
                None => {
                    merged.remove(&k);
                }
            }
        }
        Ok(merged.into_iter().collect())
    }
}
