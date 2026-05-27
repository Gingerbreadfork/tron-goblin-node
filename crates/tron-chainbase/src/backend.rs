//! KV-backend abstraction shared by every store.
//!
//! java-tron uses a separate DB instance per store (no column families), so
//! conceptually each store owns its own [`KvBackend`]. In production each
//! one will wrap a RocksDB/LevelDB handle; in tests we use [`MemBackend`].

use std::collections::BTreeMap;
use std::sync::RwLock;

/// One write operation in a [`KvBackend::write_batch`] call. Owned
/// bytes so callers can drain a session's pending map (or any other
/// in-memory log) directly into the batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteOp {
    /// Put `value` at `key`, replacing any existing entry.
    Put(Vec<u8>, Vec<u8>),
    /// Delete `key`. No-op if the key doesn't exist.
    Delete(Vec<u8>),
}

/// Minimum-viable KV interface every backend must support.
///
/// Returning `Vec<u8>` here (instead of borrows) keeps the trait
/// object-safe and matches what RocksDB/LevelDB FFIs naturally produce.
pub trait KvBackend: Send + Sync {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
    fn put(&self, key: &[u8], value: &[u8]);
    fn delete(&self, key: &[u8]);
    fn contains(&self, key: &[u8]) -> bool {
        self.get(key).is_some()
    }

    /// Apply `ops` as a single atomic batch. Either every operation is
    /// visible to subsequent reads, or none is — even across a process
    /// crash. Backends that can't provide that guarantee (test stubs,
    /// third-party impls that pre-date this method) fall through to
    /// the default implementation, which simply replays the ops via
    /// `put` / `delete` in order — correct, but non-atomic.
    ///
    /// `MemBackend` and `RocksDbBackend` (the only production
    /// implementors in this crate) both override with native atomic
    /// writes: `MemBackend` acquires its inner `RwLock` write guard
    /// once for the whole batch; `RocksDbBackend` builds a
    /// `rocksdb::WriteBatch` and submits it with one `db.write` call,
    /// which RocksDB writes to its WAL and applies as a single
    /// transaction.
    ///
    /// Used by [`crate::SessionBackend::commit`] to drain a tx's
    /// pending writes in one shot (so a crash mid-commit can't leave
    /// half a tx's mutations on disk), and by the snapshot stack's
    /// `merge` to flush a layer's tentative writes to root atomically.
    fn write_batch(&self, ops: &[WriteOp]) {
        for op in ops {
            match op {
                WriteOp::Put(k, v) => self.put(k, v),
                WriteOp::Delete(k) => self.delete(k),
            }
        }
    }

    /// Apply `ops` as a single atomic batch AND fsync the WAL before
    /// returning. The "atomic" guarantee matches [`write_batch`]; the
    /// "sync" guarantee adds **durability against power loss** — when
    /// this returns Ok, the writes survive a kernel panic / pulled
    /// plug, not just a process crash.
    ///
    /// Use this for consensus-critical writes where losing the write
    /// would put the chain into an inconsistent state on restart —
    /// notably the per-store flush inside the CheckPointV2 commit
    /// path (so deleting the manifest is safe), and the block-undo
    /// log (so rollback isn't lost on power loss).
    ///
    /// Non-critical writes (mempool entries, peer-state cache) should
    /// stay on [`write_batch`] — the extra fsync per write is ~10×
    /// slower and they're recoverable from peers anyway.
    ///
    /// Default impl delegates to [`write_batch`] — non-RocksDB
    /// backends (MemBackend, test stubs) treat both the same since
    /// they have no persistent storage to fsync. RocksDB overrides
    /// with `WriteOptions { sync: true }`.
    ///
    /// [`write_batch`]: KvBackend::write_batch
    fn write_batch_sync(&self, ops: &[WriteOp]) {
        self.write_batch(ops);
    }

    /// Snapshot every `(key, value)` pair currently stored. Callers get
    /// owned bytes to avoid lifetime entanglement with internal locks.
    /// Iteration order is ascending byte-lexicographic (matches RocksDB
    /// and `BTreeMap`).
    ///
    /// This is the minimum primitive needed by consensus-critical paths
    /// that must walk the full table — e.g. `WitnessStore::all` for the
    /// maintenance round, or the `TotalVoteCount` precompile.
    ///
    /// The default implementation panics; backends MUST override. It's a
    /// default only so trait objects taken before `scan_all` existed
    /// remain object-safe — every real backend in this crate overrides
    /// it. A `#[must_implement]` lint would be nicer but stable Rust
    /// doesn't have one.
    fn scan_all(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        panic!("scan_all not implemented for this KvBackend");
    }

    /// Read up to `limit` `(key, value)` pairs starting at the first
    /// key `>= start` in ascending byte-lexicographic order. Used by
    /// store-level range helpers (`BlockStore::get_limit_number`,
    /// `DelegatedResourceStore::get_by_from`, etc.) without forcing
    /// every caller through an O(N) `scan_all`.
    ///
    /// Default implementation builds on `scan_all` (O(N) but correct).
    /// RocksDB-backed implementations override with native iterator
    /// seek for O(log N + limit).
    fn scan_from(&self, start: &[u8], limit: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
        if limit == 0 {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(limit.min(64));
        for (k, v) in self.scan_all() {
            if k.as_slice() < start {
                continue;
            }
            out.push((k, v));
            if out.len() == limit {
                break;
            }
        }
        out
    }

    /// Read every `(key, value)` whose key starts with `prefix`,
    /// ascending. Used by composite-key stores (e.g.
    /// `DelegatedResourceStore::get_by_from`, `AccountAssetStore::
    /// prefix_query`).
    ///
    /// Default implementation builds on `scan_all`. RocksDB backends
    /// can override for native prefix iteration.
    fn scan_prefix(&self, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.scan_all()
            .into_iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .collect()
    }
}

/// In-memory `BTreeMap`-backed implementation. `BTreeMap` (not `HashMap`)
/// because some stores rely on ordered iteration (e.g.
/// `BlockIndexStore::getLimitNumber`) and we want the same iteration
/// semantics across backends.
#[derive(Default)]
pub struct MemBackend {
    inner: RwLock<BTreeMap<Vec<u8>, Vec<u8>>>,
}

impl MemBackend {
    pub fn new() -> Self {
        Self::default()
    }

    /// Visit every `(key, value)` in ascending key order. Used by store-
    /// level iteration helpers like `get_limit_number`.
    pub fn for_each<F: FnMut(&[u8], &[u8])>(&self, mut f: F) {
        let guard = self.inner.read().expect("MemBackend lock poisoned");
        for (k, v) in guard.iter() {
            f(k, v);
        }
    }

    pub fn len(&self) -> usize {
        self.inner.read().expect("MemBackend lock poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl KvBackend for MemBackend {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.inner
            .read()
            .expect("MemBackend lock poisoned")
            .get(key)
            .cloned()
    }

    fn put(&self, key: &[u8], value: &[u8]) {
        self.inner
            .write()
            .expect("MemBackend lock poisoned")
            .insert(key.to_vec(), value.to_vec());
    }

    fn delete(&self, key: &[u8]) {
        self.inner
            .write()
            .expect("MemBackend lock poisoned")
            .remove(key);
    }

    fn scan_all(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.inner
            .read()
            .expect("MemBackend lock poisoned")
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    fn scan_from(&self, start: &[u8], limit: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
        if limit == 0 {
            return Vec::new();
        }
        // BTreeMap::range(start..) is the in-memory equivalent of
        // RocksDB's iter+seek. No O(N) scan.
        self.inner
            .read()
            .expect("MemBackend lock poisoned")
            .range(start.to_vec()..)
            .take(limit)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        if prefix.is_empty() {
            return self.scan_all();
        }
        self.inner
            .read()
            .expect("MemBackend lock poisoned")
            .range(prefix.to_vec()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    fn write_batch(&self, ops: &[WriteOp]) {
        // Single write-lock acquisition — apply the whole batch
        // atomically with respect to any other reader/writer of this
        // backend.
        let mut g = self.inner.write().expect("MemBackend lock poisoned");
        for op in ops {
            match op {
                WriteOp::Put(k, v) => {
                    g.insert(k.clone(), v.clone());
                }
                WriteOp::Delete(k) => {
                    g.remove(k);
                }
            }
        }
    }
}
