//! Read-mostly pending-write overlay — the visibility layer for the
//! pipelined block-apply path.
//!
//! When block N's commit (checkpoint manifest fsync + per-store write
//! batches + undo-log fsync) is handed to a background committer so
//! block N+1 can start executing immediately, N+1's reads must still
//! see N's writes — they aren't in the base stores yet. A
//! [`PendingOverlay`] wraps each base backend and holds exactly one
//! block's drained write-set; reads check the overlay first and fall
//! through to the base. Once the background commit lands, the applier
//! replaces the overlay contents with the next block's writes (or
//! clears it), so the overlay never holds more than one block.
//!
//! ```text
//!                  ┌────────────────────────────────────────┐
//!     reads ──▶    │ PendingOverlay                         │ ──▶ base
//!                  │   shards[k] : { key → Some(v) | None } │
//!     writes ──▶   │   (rejected — read-only by design)     │
//!                  └────────────────────────────────────────┘
//!                      ▲ replace_with(ops) / clear()
//!                      │ applier thread only, between blocks
//! ```
//!
//! Differences from [`SessionBackend`](crate::SessionBackend):
//!
//! * **Read-only through the trait.** `put`/`delete` return an error:
//!   nothing may write through the overlay. Executor writes go to the
//!   block session stacked on top; sync-driver bookkeeping writes
//!   (solidified pointer, block index) go to the base directly — those
//!   keys are never part of a block's drained write-set, so the overlay
//!   can't shadow them.
//! * **Sharded.** During Block-STM parallel execution ~32 threads read
//!   through this layer concurrently while it holds the previous
//!   block's writes (so the single-`RwLock` fast path SessionBackend
//!   uses for *clean* overlays doesn't apply). Sharding spreads the
//!   read-lock traffic across [`SHARD_COUNT`] lock words.
//!
//! Concurrency contract: `replace_with` / `clear` are called only by
//! the applier thread between blocks, when no executor threads are
//! reading. Concurrent `get`/`scan_all` during execution are safe
//! (read locks); the `populated` fast-path flag only transitions while
//! readers are quiescent, mirroring the `dirty` flag rationale on
//! `SessionBackend`.

use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use crate::backend::{KvBackend, KvError, WriteOp};

/// Number of independent shard locks. 16 keeps the lock-word
/// cacheline ping-pong negligible for 32 reader threads while the
/// per-overlay footprint (16 empty HashMaps × ~24 stores) stays trivial.
const SHARD_COUNT: usize = 16;

type Shard = RwLock<HashMap<Vec<u8>, Option<Vec<u8>>>>;

/// One store's pending-write overlay. `Some(v)` = pending put,
/// `None` = pending delete (mirrors `SessionBackend`'s `Op`).
pub struct PendingOverlay {
    parent: Arc<dyn KvBackend>,
    shards: Vec<Shard>,
    /// `false` while the overlay holds nothing — `get` then skips the
    /// shard lock entirely and reads the parent directly. Transitions
    /// only happen between blocks (no concurrent readers), so a
    /// `Relaxed` load suffices; the shard `RwLock`s still guard real
    /// overlay access once populated.
    populated: AtomicBool,
}

impl PendingOverlay {
    pub fn new(parent: Arc<dyn KvBackend>) -> Self {
        Self {
            parent,
            shards: (0..SHARD_COUNT).map(|_| RwLock::new(HashMap::new())).collect(),
            populated: AtomicBool::new(false),
        }
    }

    fn shard_for(key: &[u8]) -> usize {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut h);
        (h.finish() as usize) % SHARD_COUNT
    }

    /// Replace the overlay contents with `ops` (one block's drained
    /// write-set). Applier thread only, with no concurrent readers.
    pub fn replace_with(&self, ops: &[WriteOp]) {
        let mut staged: Vec<HashMap<Vec<u8>, Option<Vec<u8>>>> =
            (0..SHARD_COUNT).map(|_| HashMap::new()).collect();
        for op in ops {
            let (key, value) = match op {
                WriteOp::Put(k, v) => (k.clone(), Some(v.clone())),
                WriteOp::Delete(k) => (k.clone(), None),
            };
            staged[Self::shard_for(&key)].insert(key, value);
        }
        for (shard, staged) in self.shards.iter().zip(staged) {
            *shard.write().expect("PendingOverlay lock poisoned") = staged;
        }
        self.populated.store(!ops.is_empty(), Ordering::Relaxed);
    }

    /// Drop all pending entries — reads fall through to the parent
    /// again. Applier thread only, with no concurrent readers.
    pub fn clear(&self) {
        for shard in &self.shards {
            shard.write().expect("PendingOverlay lock poisoned").clear();
        }
        self.populated.store(false, Ordering::Relaxed);
    }

    /// Number of distinct keys currently shadowed.
    pub fn pending_len(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.read().expect("PendingOverlay lock poisoned").len())
            .sum()
    }
}

impl KvBackend for PendingOverlay {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, KvError> {
        if !self.populated.load(Ordering::Relaxed) {
            return self.parent.get(key);
        }
        let shard = self.shards[Self::shard_for(key)]
            .read()
            .expect("PendingOverlay lock poisoned");
        match shard.get(key) {
            Some(Some(v)) => Ok(Some(v.clone())),
            Some(None) => Ok(None),
            None => {
                // Release before delegating — parents may take their
                // own locks (same reentrancy caution as SessionBackend).
                drop(shard);
                self.parent.get(key)
            }
        }
    }

    fn put(&self, _key: &[u8], _value: &[u8]) -> Result<(), KvError> {
        Err(KvError::Backend(
            "PendingOverlay is read-only; write to the block session or the base store".into(),
        ))
    }

    fn delete(&self, _key: &[u8]) -> Result<(), KvError> {
        Err(KvError::Backend(
            "PendingOverlay is read-only; write to the block session or the base store".into(),
        ))
    }

    /// Parent snapshot with the pending overlay applied — same merge
    /// semantics as `SessionBackend::scan_all`, so the `scan_from` /
    /// `scan_prefix` / `scan_before` trait defaults stay correct.
    fn scan_all(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, KvError> {
        let mut merged: BTreeMap<Vec<u8>, Vec<u8>> =
            self.parent.scan_all()?.into_iter().collect();
        for shard in &self.shards {
            let g = shard.read().expect("PendingOverlay lock poisoned");
            for (k, v) in g.iter() {
                match v {
                    Some(v) => {
                        merged.insert(k.clone(), v.clone());
                    }
                    None => {
                        merged.remove(k);
                    }
                }
            }
        }
        Ok(merged.into_iter().collect())
    }

    /// Forward the durability barrier to the real store. (The pipelined
    /// committer calls `sync_wal` on the base backends directly, but a
    /// caller holding only the overlay view must still reach the WAL.)
    fn sync_wal(&self) -> Result<(), KvError> {
        self.parent.sync_wal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MemBackend;

    fn base_with(pairs: &[(&[u8], &[u8])]) -> Arc<dyn KvBackend> {
        let b = MemBackend::new();
        for (k, v) in pairs {
            b.put(k, v).unwrap();
        }
        Arc::new(b)
    }

    #[test]
    fn empty_overlay_passes_through() {
        let ov = PendingOverlay::new(base_with(&[(b"a", b"1")]));
        assert_eq!(ov.get(b"a").unwrap(), Some(b"1".to_vec()));
        assert_eq!(ov.get(b"missing").unwrap(), None);
        assert_eq!(ov.pending_len(), 0);
    }

    #[test]
    fn installed_ops_shadow_parent_reads() {
        let ov = PendingOverlay::new(base_with(&[(b"a", b"1"), (b"b", b"2")]));
        ov.replace_with(&[
            WriteOp::Put(b"a".to_vec(), b"9".to_vec()),
            WriteOp::Delete(b"b".to_vec()),
            WriteOp::Put(b"c".to_vec(), b"3".to_vec()),
        ]);
        assert_eq!(ov.get(b"a").unwrap(), Some(b"9".to_vec()), "put shadows parent");
        assert_eq!(ov.get(b"b").unwrap(), None, "delete shadows parent");
        assert_eq!(ov.get(b"c").unwrap(), Some(b"3".to_vec()), "new key visible");
        assert_eq!(ov.pending_len(), 3);
    }

    #[test]
    fn scan_all_merges_puts_and_deletes() {
        let ov = PendingOverlay::new(base_with(&[(b"a", b"1"), (b"b", b"2")]));
        ov.replace_with(&[
            WriteOp::Delete(b"a".to_vec()),
            WriteOp::Put(b"c".to_vec(), b"3".to_vec()),
        ]);
        assert_eq!(
            ov.scan_all().unwrap(),
            vec![(b"b".to_vec(), b"2".to_vec()), (b"c".to_vec(), b"3".to_vec())]
        );
    }

    #[test]
    fn replace_with_swaps_the_whole_set() {
        let ov = PendingOverlay::new(base_with(&[(b"a", b"1")]));
        ov.replace_with(&[WriteOp::Put(b"x".to_vec(), b"old".to_vec())]);
        ov.replace_with(&[WriteOp::Put(b"y".to_vec(), b"new".to_vec())]);
        assert_eq!(ov.get(b"x").unwrap(), None, "previous block's entry retired");
        assert_eq!(ov.get(b"y").unwrap(), Some(b"new".to_vec()));
        assert_eq!(ov.pending_len(), 1);
    }

    #[test]
    fn clear_restores_pass_through() {
        let ov = PendingOverlay::new(base_with(&[(b"a", b"1")]));
        ov.replace_with(&[WriteOp::Put(b"a".to_vec(), b"9".to_vec())]);
        ov.clear();
        assert_eq!(ov.get(b"a").unwrap(), Some(b"1".to_vec()));
        assert_eq!(ov.pending_len(), 0);
    }

    #[test]
    fn writes_through_the_overlay_are_rejected() {
        let ov = PendingOverlay::new(base_with(&[]));
        assert!(ov.put(b"k", b"v").is_err());
        assert!(ov.delete(b"k").is_err());
        // write_batch's default impl routes through put → must error too.
        assert!(ov
            .write_batch(&[WriteOp::Put(b"k".to_vec(), b"v".to_vec())])
            .is_err());
    }
}
