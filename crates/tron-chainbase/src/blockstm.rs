//! Block-STM multi-version memory — phase 1: the pure MVCC core.
//!
//! Optimistic parallel block execution (see `working/BLOCKSTM-DESIGN.md`) needs a
//! place to hold the *speculative* writes of in-flight transactions, versioned by
//! transaction index, so that a higher-indexed tx reading a key sees the write of
//! the highest **lower-indexed** tx (or the committed base) — exactly what serial
//! execution would have seen. This module is that store plus the read-set
//! validation used to detect when a speculative read was wrong and the tx must be
//! re-executed.
//!
//! It is deliberately self-contained and integration-free: it knows nothing about
//! the EVM, actuators, or RocksDB. Higher phases wrap a `KvBackend` around it to
//! capture per-tx read/write-sets (phase 2) and drive the parallel scheduler
//! (phase 3). Keeping the conflict-resolution logic pure makes it exhaustively
//! unit-testable, which matters because a bug here is a silent consensus
//! divergence.
//!
//! Concurrency note: a single `RwLock<HashMap>` guards the map for now —
//! correctness first. Phase 3 swaps it for a sharded / lock-free map; the `&self`
//! API is unchanged by that.

use std::collections::{BTreeMap, HashMap};
use std::sync::RwLock;

/// Identifies one of the node's KV stores (accounts, storage_row, dyn_props, …).
/// The conflict-key space is `(StoreId, key-bytes)`; each store gets a stable
/// small index so two different stores never alias on the same key bytes.
pub type StoreId = u16;

/// A transaction's position in the block (0-based serial execution order). The
/// whole point of the version index is "what would tx `i` have read if every tx
/// `< i` had already run".
pub type TxIdx = u32;

/// A value a transaction wrote: `Some` = put, `None` = delete (tombstone). Stored
/// so a reader sees a delete as "absent" rather than falling through to the base.
pub type VersionValue = Option<Vec<u8>>;

/// A (transaction, incarnation) pair. A tx is re-executed (a new *incarnation*)
/// when an earlier read is invalidated; the incarnation lets validation tell a
/// re-run's writes apart from the originals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Version {
    pub idx: TxIdx,
    pub incarnation: u32,
}

/// One slot for a (store,key) at a particular tx index.
#[derive(Clone, Debug)]
enum Entry {
    /// A concrete value from a finished incarnation.
    Written {
        value: VersionValue,
        incarnation: u32,
    },
    /// The writing tx is mid-re-execution; its prior value can't be trusted.
    /// Block-STM's ESTIMATE — a reader must treat the writer as a dependency.
    Estimate,
}

/// Where a read resolved. Recorded in the read-set so validation can re-check that
/// the same source would still serve the read after other txs commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadOrigin {
    /// No lower-indexed tx had written the key — the value came from the committed
    /// base state.
    Base,
    /// The value came from a lower tx's speculative write.
    Version(Version),
}

/// Outcome of resolving a read against the multi-version memory.
#[derive(Clone, Debug)]
pub enum ReadOutcome {
    /// Resolved to a lower tx's write (`origin = Version`). `value` is its put/
    /// tombstone.
    Versioned {
        value: VersionValue,
        version: Version,
    },
    /// No lower tx wrote the key — caller should read the base backend and record
    /// [`ReadOrigin::Base`].
    Base,
    /// A lower tx that wrote this key is currently an ESTIMATE (being re-run). The
    /// reader can't proceed deterministically; the scheduler should make it wait
    /// on `blocking` and retry.
    Blocked { blocking: TxIdx },
}

/// One entry of a transaction's read-set: the key it read and where the value came
/// from. Validation re-resolves the key and confirms the origin is unchanged.
#[derive(Clone, Debug)]
pub struct ReadDescriptor {
    pub store: StoreId,
    pub key: Vec<u8>,
    pub origin: ReadOrigin,
}

/// The multi-version store: for each `(store,key)`, the writes keyed by tx index.
#[derive(Default)]
pub struct MvMemory {
    data: RwLock<HashMap<(StoreId, Vec<u8>), BTreeMap<TxIdx, Entry>>>,
}

impl MvMemory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolve what tx `reader` should see for `(store,key)`: the write of the
    /// highest tx strictly below `reader`, or `Base` if none. An ESTIMATE from a
    /// lower tx yields `Blocked`.
    pub fn read(&self, store: StoreId, key: &[u8], reader: TxIdx) -> ReadOutcome {
        let map = self.data.read().expect("MvMemory poisoned");
        let Some(versions) = map.get(&(store, key.to_vec())) else {
            return ReadOutcome::Base;
        };
        // Highest tx index strictly below the reader.
        match versions.range(..reader).next_back() {
            None => ReadOutcome::Base,
            Some((&idx, Entry::Estimate)) => ReadOutcome::Blocked { blocking: idx },
            Some((&idx, Entry::Written { value, incarnation })) => ReadOutcome::Versioned {
                value: value.clone(),
                version: Version {
                    idx,
                    incarnation: *incarnation,
                },
            },
        }
    }

    /// Record a finished incarnation's writes (put/tombstone) at tx `version.idx`.
    pub fn record_writes(&self, version: Version, writes: &[(StoreId, Vec<u8>, VersionValue)]) {
        let mut map = self.data.write().expect("MvMemory poisoned");
        for (store, key, value) in writes {
            map.entry((*store, key.clone())).or_default().insert(
                version.idx,
                Entry::Written {
                    value: value.clone(),
                    incarnation: version.incarnation,
                },
            );
        }
    }

    /// Mark a tx's previously-written keys as ESTIMATE before re-executing it, so
    /// concurrent readers below the next incarnation treat them as a dependency
    /// instead of reading a soon-to-be-stale value.
    pub fn mark_estimates(&self, idx: TxIdx, written_keys: &[(StoreId, Vec<u8>)]) {
        let mut map = self.data.write().expect("MvMemory poisoned");
        for (store, key) in written_keys {
            if let Some(versions) = map.get_mut(&(*store, key.clone())) {
                versions.insert(idx, Entry::Estimate);
            }
        }
    }

    /// Remove a tx's entries for keys it no longer writes in its newest
    /// incarnation (a re-run may touch fewer keys). Leaves keys still written by
    /// `record_writes`.
    pub fn remove_writes(&self, idx: TxIdx, stale_keys: &[(StoreId, Vec<u8>)]) {
        let mut map = self.data.write().expect("MvMemory poisoned");
        for (store, key) in stale_keys {
            if let Some(versions) = map.get_mut(&(*store, key.clone())) {
                versions.remove(&idx);
            }
        }
    }

    /// Re-validate a tx's read-set: every read must still resolve to the same
    /// origin it saw during execution. A changed origin (a newly-visible lower
    /// write, a changed incarnation, or a write that disappeared) means the tx
    /// read a stale value and must be re-executed. An ESTIMATE encountered during
    /// validation is treated as a failure (the dependency is in flux).
    pub fn validate(&self, reader: TxIdx, read_set: &[ReadDescriptor]) -> bool {
        for rd in read_set {
            match self.read(rd.store, &rd.key, reader) {
                ReadOutcome::Base => {
                    if rd.origin != ReadOrigin::Base {
                        return false;
                    }
                }
                ReadOutcome::Versioned { version, .. } => {
                    if rd.origin != ReadOrigin::Version(version) {
                        return false;
                    }
                }
                ReadOutcome::Blocked { .. } => return false,
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACC: StoreId = 0;
    fn v(idx: TxIdx, inc: u32) -> Version {
        Version {
            idx,
            incarnation: inc,
        }
    }
    fn val(b: &[u8]) -> VersionValue {
        Some(b.to_vec())
    }

    #[test]
    fn read_sees_highest_lower_write_else_base() {
        let mv = MvMemory::new();
        // No writers yet → base.
        assert!(matches!(mv.read(ACC, b"a", 5), ReadOutcome::Base));
        // tx2 writes "a"; tx5 sees it, tx1 (below the writer) sees base.
        mv.record_writes(v(2, 0), &[(ACC, b"a".to_vec(), val(b"x"))]);
        match mv.read(ACC, b"a", 5) {
            ReadOutcome::Versioned { value, version } => {
                assert_eq!(value, val(b"x"));
                assert_eq!(version, v(2, 0));
            }
            o => panic!("expected versioned, got {o:?}"),
        }
        assert!(matches!(mv.read(ACC, b"a", 1), ReadOutcome::Base));
        assert!(matches!(mv.read(ACC, b"a", 2), ReadOutcome::Base), "own index excluded");
    }

    #[test]
    fn read_picks_nearest_lower_writer() {
        let mv = MvMemory::new();
        mv.record_writes(v(2, 0), &[(ACC, b"a".to_vec(), val(b"from2"))]);
        mv.record_writes(v(4, 0), &[(ACC, b"a".to_vec(), val(b"from4"))]);
        // tx5 sees tx4 (nearest below); tx3 sees tx2.
        match mv.read(ACC, b"a", 5) {
            ReadOutcome::Versioned { version, .. } => assert_eq!(version, v(4, 0)),
            o => panic!("got {o:?}"),
        }
        match mv.read(ACC, b"a", 3) {
            ReadOutcome::Versioned { version, .. } => assert_eq!(version, v(2, 0)),
            o => panic!("got {o:?}"),
        }
    }

    #[test]
    fn tombstone_is_a_versioned_absent_not_base() {
        let mv = MvMemory::new();
        mv.record_writes(v(2, 0), &[(ACC, b"a".to_vec(), None)]); // delete
        match mv.read(ACC, b"a", 5) {
            ReadOutcome::Versioned { value, version } => {
                assert_eq!(value, None);
                assert_eq!(version, v(2, 0));
            }
            o => panic!("got {o:?}"),
        }
    }

    #[test]
    fn estimate_blocks_lower_readers() {
        let mv = MvMemory::new();
        mv.record_writes(v(2, 0), &[(ACC, b"a".to_vec(), val(b"x"))]);
        mv.mark_estimates(2, &[(ACC, b"a".to_vec())]);
        assert!(matches!(
            mv.read(ACC, b"a", 5),
            ReadOutcome::Blocked { blocking: 2 }
        ));
    }

    #[test]
    fn validate_detects_a_newly_visible_lower_write() {
        let mv = MvMemory::new();
        // tx5 executed reading "a" from base (no lower writer existed).
        let rs = vec![ReadDescriptor {
            store: ACC,
            key: b"a".to_vec(),
            origin: ReadOrigin::Base,
        }];
        assert!(mv.validate(5, &rs), "still base → valid");
        // Now tx3 writes "a" → tx5's base read is stale.
        mv.record_writes(v(3, 0), &[(ACC, b"a".to_vec(), val(b"x"))]);
        assert!(!mv.validate(5, &rs), "tx3 now visible → tx5 must re-run");
    }

    #[test]
    fn validate_detects_changed_incarnation_and_disappeared_write() {
        let mv = MvMemory::new();
        mv.record_writes(v(3, 0), &[(ACC, b"a".to_vec(), val(b"x"))]);
        let rs = vec![ReadDescriptor {
            store: ACC,
            key: b"a".to_vec(),
            origin: ReadOrigin::Version(v(3, 0)),
        }];
        assert!(mv.validate(5, &rs));
        // tx3 re-executed (incarnation bumped) → same idx, different incarnation.
        mv.record_writes(v(3, 1), &[(ACC, b"a".to_vec(), val(b"y"))]);
        assert!(!mv.validate(5, &rs), "incarnation changed → re-run");
        // tx3's write disappears entirely (its re-run no longer touches "a").
        mv.remove_writes(3, &[(ACC, b"a".to_vec())]);
        assert!(!mv.validate(5, &rs), "now resolves to base → re-run");
    }
}
