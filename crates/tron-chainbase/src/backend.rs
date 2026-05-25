//! KV-backend abstraction shared by every store.
//!
//! java-tron uses a separate DB instance per store (no column families), so
//! conceptually each store owns its own [`KvBackend`]. In production each
//! one will wrap a RocksDB/LevelDB handle; in tests we use [`MemBackend`].

use std::collections::BTreeMap;
use std::sync::RwLock;

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
}
