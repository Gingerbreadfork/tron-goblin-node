//! In-memory revoking-snapshot layer.
//!
//! Mirrors java-tron's `SnapshotManager` + `SnapshotImpl`: a stack of
//! tentative-write layers on top of a root [`KvBackend`]. Each
//! [`SnapshotKvBackend::advance`] pushes a new layer; [`revoke`] drops
//! the topmost (rolls back its tentative writes); [`merge`] squashes
//! the top into the layer below (or into the root once at the
//! bottom). Reads walk top-to-bottom and return the first hit;
//! writes always land in the topmost layer.
//!
//! ## Why
//!
//! The existing `BlockUndoStore` records the inverse of each block's
//! writes so reorg-rollback can replay them. SnapshotManager achieves
//! the same end through a different design — speculative writes live
//! in memory until they're known-good, at which point the layer is
//! merged into the root. Both designs preserve the byte-exact
//! mainnet-DB compatibility; the snapshot variant matches java-tron's
//! internal architecture more closely, which simplifies sharing
//! reorg-handling code paths in mixed-implementation networks.
//!
//! ## Status
//!
//! This module ships the primitive. The runtime still drives reorg
//! via `BlockUndoStore`; switching is a follow-up that touches every
//! store-construction site.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::backend::{KvBackend, WriteOp};

/// Per-layer tentative state. `None` value means "tombstone" — the
/// key was deleted in this layer.
type Layer = HashMap<Vec<u8>, Option<Vec<u8>>>;

/// Read-write KV that layers tentative writes on top of a root
/// backend.
///
/// Cloning is cheap; the inner state is `Arc<RwLock<…>>` so multiple
/// callers can share a single snapshot tree.
#[derive(Clone)]
pub struct SnapshotKvBackend {
    root: Arc<dyn KvBackend>,
    state: Arc<RwLock<SnapshotState>>,
}

struct SnapshotState {
    /// Stack of tentative-write layers. `layers.last()` is the
    /// topmost (most-recent-block). Writes always land here.
    layers: Vec<Layer>,
}

impl SnapshotKvBackend {
    pub fn new(root: Arc<dyn KvBackend>) -> Self {
        Self {
            root,
            state: Arc::new(RwLock::new(SnapshotState { layers: Vec::new() })),
        }
    }

    /// Number of active layers. `0` means writes go straight to root.
    pub fn depth(&self) -> usize {
        self.state.read().expect("snapshot lock poisoned").layers.len()
    }

    /// Push a new empty tentative layer. Subsequent writes land here.
    pub fn advance(&self) {
        let mut g = self.state.write().expect("snapshot lock poisoned");
        g.layers.push(Layer::new());
    }

    /// Drop the topmost layer (rolls back its tentative writes).
    /// No-op when the stack is empty.
    pub fn revoke(&self) {
        let mut g = self.state.write().expect("snapshot lock poisoned");
        g.layers.pop();
    }

    /// Squash the topmost layer into the layer below it. When only
    /// one layer remains, squash into the root backend instead (the
    /// tentative writes become permanent).
    ///
    /// No-op when the stack is empty.
    ///
    /// **Root-flush atomicity**: when the squashed layer goes to root
    /// (not an in-memory layer below), the writes are submitted as a
    /// single [`KvBackend::write_batch`]. Without that, a crash mid-flush
    /// could leave the root partially mutated AND the snapshot layer
    /// already popped — no way to recover the unwritten entries.
    /// RocksDB's WriteBatch + WAL is what makes the all-or-nothing
    /// recovery guarantee hold across crashes.
    pub fn merge(&self) -> Result<(), crate::KvError> {
        let mut g = self.state.write().expect("snapshot lock poisoned");
        let Some(top) = g.layers.pop() else {
            return Ok(());
        };
        if let Some(below) = g.layers.last_mut() {
            for (k, v) in top {
                below.insert(k, v);
            }
            return Ok(());
        }
        // No remaining layer → flush to root as a single atomic batch.
        if top.is_empty() {
            return Ok(());
        }
        let ops: Vec<WriteOp> = top
            .into_iter()
            .map(|(k, v)| match v {
                Some(value) => WriteOp::Put(k, value),
                None => WriteOp::Delete(k),
            })
            .collect();
        // Drop the layers lock before doing IO so a slow root flush
        // doesn't block readers of higher layers.
        drop(g);
        self.root.write_batch(&ops)
    }

    /// Squash every layer into the root. Equivalent to repeated
    /// [`merge`] until depth is zero.
    pub fn merge_all(&self) -> Result<(), crate::KvError> {
        while self.depth() > 0 {
            self.merge()?;
        }
        Ok(())
    }

    /// Peek the bottom-most layer's pending writes without removing
    /// the layer. Returns `(key, Some(value))` for puts and
    /// `(key, None)` for tombstones (deletes). Used by the
    /// checkpoint-V2 flush cycle to materialise the layer's contents
    /// into a cross-store atomic manifest BEFORE committing them to
    /// disk via `merge`.
    ///
    /// Returns an empty vec when the stack is empty.
    pub fn peek_bottom_layer(&self) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
        let g = self.state.read().expect("snapshot lock poisoned");
        let Some(bottom) = g.layers.first() else {
            return Vec::new();
        };
        bottom
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Read a key. Walks layers top→bottom; first hit wins. A
    /// tombstone in any layer is treated as "deleted" (read returns
    /// `None`) even when a lower layer or the root has a value.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, crate::KvError> {
        let g = self.state.read().expect("snapshot lock poisoned");
        for layer in g.layers.iter().rev() {
            if let Some(slot) = layer.get(key) {
                return Ok(slot.clone());
            }
        }
        drop(g);
        self.root.get(key)
    }

    /// Write into the topmost layer. When no layer exists, writes
    /// land straight in the root.
    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<(), crate::KvError> {
        let mut g = self.state.write().expect("snapshot lock poisoned");
        if let Some(top) = g.layers.last_mut() {
            top.insert(key.to_vec(), Some(value.to_vec()));
            return Ok(());
        }
        drop(g);
        self.root.put(key, value)
    }

    /// Tombstone the key in the topmost layer (or delete in the root
    /// when no layer exists).
    pub fn delete(&self, key: &[u8]) -> Result<(), crate::KvError> {
        let mut g = self.state.write().expect("snapshot lock poisoned");
        if let Some(top) = g.layers.last_mut() {
            top.insert(key.to_vec(), None);
            return Ok(());
        }
        drop(g);
        self.root.delete(key)
    }

    /// `true` when [`get`] would return `Some`. Slightly cheaper
    /// than `get(...).is_some()` because it doesn't clone values
    /// out of the layer maps.
    pub fn contains(&self, key: &[u8]) -> Result<bool, crate::KvError> {
        let g = self.state.read().expect("snapshot lock poisoned");
        for layer in g.layers.iter().rev() {
            if let Some(slot) = layer.get(key) {
                return Ok(slot.is_some());
            }
        }
        drop(g);
        self.root.contains(key)
    }
}

/// `KvBackend` bridge so `Arc<SnapshotKvBackend>` is a drop-in
/// replacement for any `Arc<dyn KvBackend>` consumer. Snapshot
/// semantics layer ABOVE the trait surface — outside this impl
/// nothing changes; consumers see a normal kv store whose writes
/// are transparently routed to the topmost layer (or the root when
/// the stack is empty).
///
/// `scan_all`, `scan_from`, and `scan_prefix` are implemented by
/// walking each layer's pending writes overlaid on the root's
/// pre-existing keys. This makes a snapshot-wrapped store correct
/// for stores that consult `scan_*` (e.g. `WitnessStore::all`,
/// `VotesStore::all`) under tentative-write conditions.
impl KvBackend for SnapshotKvBackend {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, crate::KvError> {
        SnapshotKvBackend::get(self, key)
    }
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), crate::KvError> {
        SnapshotKvBackend::put(self, key, value)
    }
    fn delete(&self, key: &[u8]) -> Result<(), crate::KvError> {
        SnapshotKvBackend::delete(self, key)
    }
    fn contains(&self, key: &[u8]) -> Result<bool, crate::KvError> {
        SnapshotKvBackend::contains(self, key)
    }

    /// Atomic batch write. When the snapshot stack is empty (depth =
    /// 0) the batch flows straight to the root — for RocksDB roots
    /// this means a single native `WriteBatch`, preserving per-store
    /// atomicity across the keys in `ops`. When layers exist, the
    /// batch is applied to the topmost layer under a single lock
    /// acquisition (atomic from the perspective of any concurrent
    /// reader of this snapshot wrapper).
    fn write_batch(&self, ops: &[crate::backend::WriteOp]) -> Result<(), crate::KvError> {
        if ops.is_empty() {
            return Ok(());
        }
        let mut g = self.state.write().expect("snapshot lock poisoned");
        if let Some(top) = g.layers.last_mut() {
            for op in ops {
                match op {
                    crate::backend::WriteOp::Put(k, v) => {
                        top.insert(k.clone(), Some(v.clone()));
                    }
                    crate::backend::WriteOp::Delete(k) => {
                        top.insert(k.clone(), None);
                    }
                }
            }
            return Ok(());
        }
        drop(g);
        self.root.write_batch(ops)
    }

    /// Sync variant — only meaningful at depth = 0 (writes are going
    /// to the persistent root). When a layer is on top, the batch is
    /// in-memory by definition and the fsync is a no-op; we degrade
    /// gracefully to the non-sync overlay path. The whole point of
    /// the stack layers is that they aren't durable yet.
    fn write_batch_sync(&self, ops: &[crate::backend::WriteOp]) -> Result<(), crate::KvError> {
        if ops.is_empty() {
            return Ok(());
        }
        let g = self.state.read().expect("snapshot lock poisoned");
        let has_layers = !g.layers.is_empty();
        drop(g);
        if has_layers {
            return self.write_batch(ops);
        }
        self.root.write_batch_sync(ops)
    }

    fn scan_all(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, crate::KvError> {
        // Start from the root's full key set, then overlay tentative
        // writes (puts/deletes) from each layer in order. We use a
        // BTreeMap to keep ascending byte-lexicographic iteration
        // order matching every other `KvBackend::scan_all` impl.
        use std::collections::BTreeMap;
        let mut overlay: BTreeMap<Vec<u8>, Vec<u8>> =
            self.root.scan_all()?.into_iter().collect();
        let g = self.state.read().expect("snapshot lock poisoned");
        for layer in g.layers.iter() {
            for (k, slot) in layer.iter() {
                match slot {
                    Some(v) => {
                        overlay.insert(k.clone(), v.clone());
                    }
                    None => {
                        overlay.remove(k);
                    }
                }
            }
        }
        Ok(overlay.into_iter().collect())
    }

    fn scan_from(&self, start: &[u8], limit: usize) -> Result<Vec<(Vec<u8>, Vec<u8>)>, crate::KvError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        Ok(self
            .scan_all()?
            .into_iter()
            .filter(|(k, _)| k.as_slice() >= start)
            .take(limit)
            .collect())
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, crate::KvError> {
        Ok(self
            .scan_all()?
            .into_iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MemBackend;

    fn fresh() -> SnapshotKvBackend {
        SnapshotKvBackend::new(Arc::new(MemBackend::new()))
    }

    #[test]
    fn root_writes_pass_through_when_no_layer() {
        let snap = fresh();
        snap.put(b"k", b"v").unwrap();
        assert_eq!(snap.get(b"k").unwrap().as_deref(), Some(b"v".as_ref()));
        assert!(snap.contains(b"k").unwrap());
    }

    #[test]
    fn advance_pushes_writes_into_top_layer() {
        let snap = fresh();
        snap.put(b"k", b"root").unwrap();
        snap.advance();
        assert_eq!(snap.depth(), 1);
        snap.put(b"k", b"layer1").unwrap();
        assert_eq!(snap.get(b"k").unwrap().as_deref(), Some(b"layer1".as_ref()));
    }

    #[test]
    fn revoke_drops_topmost_layer_writes() {
        let snap = fresh();
        snap.put(b"k", b"root").unwrap();
        snap.advance();
        snap.put(b"k", b"layer1").unwrap();
        snap.revoke();
        assert_eq!(snap.depth(), 0);
        assert_eq!(snap.get(b"k").unwrap().as_deref(), Some(b"root".as_ref()));
    }

    #[test]
    fn delete_in_layer_shadows_root_value() {
        let snap = fresh();
        snap.put(b"k", b"root").unwrap();
        snap.advance();
        snap.delete(b"k").unwrap();
        assert_eq!(snap.get(b"k").unwrap(), None);
        assert!(!snap.contains(b"k").unwrap());
        // Revoke restores the root view.
        snap.revoke();
        assert_eq!(snap.get(b"k").unwrap().as_deref(), Some(b"root".as_ref()));
    }

    #[test]
    fn merge_squashes_top_into_below() {
        let snap = fresh();
        snap.put(b"k1", b"root").unwrap();
        snap.advance(); // layer A
        snap.put(b"k1", b"layerA").unwrap();
        snap.put(b"k2", b"layerA").unwrap();
        snap.advance(); // layer B
        snap.put(b"k2", b"layerB").unwrap();
        snap.merge().unwrap(); // collapse B into A
        assert_eq!(snap.depth(), 1);
        assert_eq!(snap.get(b"k1").unwrap().as_deref(), Some(b"layerA".as_ref()));
        assert_eq!(snap.get(b"k2").unwrap().as_deref(), Some(b"layerB".as_ref()));
    }

    #[test]
    fn merge_at_bottom_flushes_to_root() {
        let snap = fresh();
        snap.put(b"k", b"root").unwrap();
        snap.advance();
        snap.put(b"k", b"layer1").unwrap();
        snap.merge().unwrap(); // bottom layer → flushed to root
        assert_eq!(snap.depth(), 0);
        assert_eq!(snap.get(b"k").unwrap().as_deref(), Some(b"layer1".as_ref()));
    }

    #[test]
    fn merge_all_flushes_every_layer_to_root() {
        let snap = fresh();
        snap.advance();
        snap.put(b"a", b"1").unwrap();
        snap.advance();
        snap.put(b"b", b"2").unwrap();
        snap.advance();
        snap.put(b"c", b"3").unwrap();
        snap.merge_all().unwrap();
        assert_eq!(snap.depth(), 0);
        for (k, want) in [(b"a", "1"), (b"b", "2"), (b"c", "3")] {
            assert_eq!(snap.get(k).unwrap().unwrap(), want.as_bytes());
        }
    }

    #[test]
    fn deeper_layer_shadows_earlier_one() {
        let snap = fresh();
        snap.put(b"k", b"root").unwrap();
        snap.advance();
        snap.put(b"k", b"a").unwrap();
        snap.advance();
        snap.put(b"k", b"b").unwrap();
        assert_eq!(snap.get(b"k").unwrap().as_deref(), Some(b"b".as_ref()));
        snap.revoke(); // drop b
        assert_eq!(snap.get(b"k").unwrap().as_deref(), Some(b"a".as_ref()));
        snap.revoke(); // drop a
        assert_eq!(snap.get(b"k").unwrap().as_deref(), Some(b"root".as_ref()));
    }

    #[test]
    fn revoke_on_empty_stack_is_safe() {
        let snap = fresh();
        snap.revoke(); // no-op
        snap.merge().unwrap(); // no-op
        snap.put(b"k", b"v").unwrap(); // still goes to root
        assert_eq!(snap.get(b"k").unwrap().as_deref(), Some(b"v".as_ref()));
    }

    #[test]
    fn tombstone_followed_by_put_resurrects_value() {
        let snap = fresh();
        snap.put(b"k", b"root").unwrap();
        snap.advance();
        snap.delete(b"k").unwrap();
        assert!(snap.get(b"k").unwrap().is_none());
        snap.put(b"k", b"alive").unwrap();
        assert_eq!(snap.get(b"k").unwrap().as_deref(), Some(b"alive".as_ref()));
    }

    // ────────────────────────────────────────────────────────────
    // `KvBackend` trait bridge — confirms a `SnapshotKvBackend`
    // works wherever an `Arc<dyn KvBackend>` is expected.
    // ────────────────────────────────────────────────────────────

    #[test]
    fn scan_all_overlays_layers_on_root() {
        let snap = fresh();
        snap.put(b"a", b"root-a").unwrap();
        snap.put(b"b", b"root-b").unwrap();
        snap.advance();
        snap.put(b"a", b"layer-a").unwrap(); // overwrite
        snap.put(b"c", b"layer-c").unwrap(); // insert
        snap.delete(b"b").unwrap(); // tombstone
        // scan_all reads through the bridge
        let pairs: Vec<(Vec<u8>, Vec<u8>)> =
            <SnapshotKvBackend as KvBackend>::scan_all(&snap).unwrap();
        let map: HashMap<Vec<u8>, Vec<u8>> = pairs.into_iter().collect();
        assert_eq!(map.get(b"a".as_ref()).map(|v| v.as_slice()), Some(b"layer-a".as_ref()));
        assert_eq!(map.get(b"c".as_ref()).map(|v| v.as_slice()), Some(b"layer-c".as_ref()));
        assert!(map.get(b"b".as_ref()).is_none(), "tombstone must hide root value");
    }

    #[test]
    fn scan_all_returns_sorted_ascending() {
        let snap = fresh();
        snap.put(b"zzz", b"3").unwrap();
        snap.put(b"aaa", b"1").unwrap();
        snap.advance();
        snap.put(b"mmm", b"2").unwrap();
        let pairs = <SnapshotKvBackend as KvBackend>::scan_all(&snap).unwrap();
        let keys: Vec<&[u8]> = pairs.iter().map(|(k, _)| k.as_slice()).collect();
        assert_eq!(keys, vec![b"aaa".as_ref(), b"mmm".as_ref(), b"zzz".as_ref()]);
    }

    #[test]
    fn scan_from_respects_start_and_limit() {
        let snap = fresh();
        for byte in [0xa0u8, 0xb0, 0xc0, 0xd0] {
            snap.put(&[byte], &[byte ^ 0xff]).unwrap();
        }
        let pairs =
            <SnapshotKvBackend as KvBackend>::scan_from(&snap, &[0xb5], 5).unwrap();
        let keys: Vec<u8> = pairs.iter().map(|(k, _)| k[0]).collect();
        assert_eq!(keys, vec![0xc0, 0xd0]);
    }

    #[test]
    fn scan_prefix_filters_to_matching_keys() {
        let snap = fresh();
        snap.put(b"foo:1", b"1").unwrap();
        snap.put(b"foo:2", b"2").unwrap();
        snap.put(b"bar:1", b"3").unwrap();
        snap.advance();
        snap.put(b"foo:3", b"4").unwrap(); // layer-only
        snap.delete(b"foo:1").unwrap(); // tombstone
        let pairs =
            <SnapshotKvBackend as KvBackend>::scan_prefix(&snap, b"foo:").unwrap();
        let keys: HashSet<String> = pairs
            .iter()
            .map(|(k, _)| String::from_utf8_lossy(k).to_string())
            .collect();
        assert!(keys.contains("foo:2"));
        assert!(keys.contains("foo:3"));
        assert!(!keys.contains("foo:1"), "tombstoned key must be excluded");
        assert!(!keys.iter().any(|k| k.starts_with("bar")));
    }

    #[test]
    fn arc_dyn_kvbackend_can_wrap_snapshot() {
        // Compile-time + smoke check that an `Arc<SnapshotKvBackend>`
        // coerces to `Arc<dyn KvBackend>` and the trait methods route
        // through the snapshot layering.
        let snap: Arc<SnapshotKvBackend> = Arc::new(fresh());
        snap.advance();
        snap.put(b"k", b"layered").unwrap();
        let dyn_ref: Arc<dyn KvBackend> = snap.clone();
        assert_eq!(dyn_ref.get(b"k").unwrap().as_deref(), Some(b"layered".as_ref()));
        // Revoke through the typed handle; the dyn-ref sees the same
        // underlying state.
        snap.revoke();
        assert!(dyn_ref.get(b"k").unwrap().is_none());
    }

    /// **C-6 pin.** Squashing the bottom layer to root MUST route
    /// through `root.write_batch` (one call, all ops at once), NOT
    /// through per-key `put`/`delete` loops. Without the batch, a
    /// crash mid-flush leaves the root partially mutated AND the
    /// snapshot layer already popped — no way to recover. The batch
    /// path inherits RocksDB's WriteBatch + WAL atomicity.
    #[test]
    fn bottom_layer_flush_routes_through_root_write_batch() {
        use std::sync::Mutex;
        use crate::backend::WriteOp;

        struct RecordingRoot {
            inner: MemBackend,
            batches: Mutex<Vec<Vec<WriteOp>>>,
            per_call_puts: Mutex<usize>,
            per_call_deletes: Mutex<usize>,
        }

        impl KvBackend for RecordingRoot {
            fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, crate::KvError> {
                self.inner.get(key)
            }
            fn put(&self, key: &[u8], value: &[u8]) -> Result<(), crate::KvError> {
                *self.per_call_puts.lock().unwrap() += 1;
                self.inner.put(key, value)
            }
            fn delete(&self, key: &[u8]) -> Result<(), crate::KvError> {
                *self.per_call_deletes.lock().unwrap() += 1;
                self.inner.delete(key)
            }
            fn scan_all(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, crate::KvError> {
                self.inner.scan_all()
            }
            fn write_batch(&self, ops: &[WriteOp]) -> Result<(), crate::KvError> {
                self.batches.lock().unwrap().push(ops.to_vec());
                self.inner.write_batch(ops)
            }
        }

        let root = Arc::new(RecordingRoot {
            inner: MemBackend::new(),
            batches: Mutex::new(Vec::new()),
            per_call_puts: Mutex::new(0),
            per_call_deletes: Mutex::new(0),
        });
        let snap = SnapshotKvBackend::new(root.clone() as Arc<dyn KvBackend>);
        snap.advance();
        snap.put(b"a", b"1").unwrap();
        snap.put(b"b", b"2").unwrap();
        snap.delete(b"c").unwrap();
        snap.merge().unwrap(); // bottom → flushed to root

        let batches = root.batches.lock().unwrap();
        assert_eq!(batches.len(), 1, "expected one batch flush, got {}", batches.len());
        assert_eq!(
            batches[0].len(),
            3,
            "all three pending ops should be in the single batch"
        );
        drop(batches);
        assert_eq!(
            *root.per_call_puts.lock().unwrap(),
            0,
            "merge must NOT fall back to per-key put"
        );
        assert_eq!(
            *root.per_call_deletes.lock().unwrap(),
            0,
            "merge must NOT fall back to per-key delete"
        );
    }

    /// Empty bottom layer doesn't even invoke `write_batch` — short-
    /// circuit to avoid spurious empty-batch lock acquisitions on
    /// the hot path.
    #[test]
    fn bottom_layer_flush_with_no_writes_is_noop() {
        use std::sync::Mutex;
        use crate::backend::WriteOp;

        struct CountingRoot {
            inner: MemBackend,
            calls: Mutex<usize>,
        }
        impl KvBackend for CountingRoot {
            fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, crate::KvError> {
                self.inner.get(key)
            }
            fn put(&self, key: &[u8], value: &[u8]) -> Result<(), crate::KvError> {
                self.inner.put(key, value)
            }
            fn delete(&self, key: &[u8]) -> Result<(), crate::KvError> {
                self.inner.delete(key)
            }
            fn scan_all(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, crate::KvError> {
                self.inner.scan_all()
            }
            fn write_batch(&self, ops: &[WriteOp]) -> Result<(), crate::KvError> {
                *self.calls.lock().unwrap() += 1;
                self.inner.write_batch(ops)
            }
        }

        let root = Arc::new(CountingRoot {
            inner: MemBackend::new(),
            calls: Mutex::new(0),
        });
        let snap = SnapshotKvBackend::new(root.clone() as Arc<dyn KvBackend>);
        snap.advance();
        snap.merge().unwrap(); // empty bottom layer → flushed to root with nothing to do
        assert_eq!(*root.calls.lock().unwrap(), 0);
    }

    use std::collections::HashSet;

    /// At depth = 0, `write_batch` forwards to the root's
    /// `write_batch` in one call — that's what gives the executor's
    /// per-store flush per-store atomicity even when the SnapshotKv
    /// wrapper is in front of RocksDB.
    #[test]
    fn write_batch_at_depth_zero_forwards_to_root_in_one_call() {
        use std::sync::Mutex;

        struct CountingRoot {
            inner: MemBackend,
            batch_calls: Mutex<usize>,
            put_calls: Mutex<usize>,
        }
        impl KvBackend for CountingRoot {
            fn get(&self, k: &[u8]) -> Result<Option<Vec<u8>>, crate::KvError> {
                self.inner.get(k)
            }
            fn put(&self, k: &[u8], v: &[u8]) -> Result<(), crate::KvError> {
                *self.put_calls.lock().unwrap() += 1;
                self.inner.put(k, v)
            }
            fn delete(&self, k: &[u8]) -> Result<(), crate::KvError> {
                self.inner.delete(k)
            }
            fn scan_all(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, crate::KvError> {
                self.inner.scan_all()
            }
            fn write_batch(&self, ops: &[crate::backend::WriteOp]) -> Result<(), crate::KvError> {
                *self.batch_calls.lock().unwrap() += 1;
                self.inner.write_batch(ops)
            }
        }
        let root = Arc::new(CountingRoot {
            inner: MemBackend::new(),
            batch_calls: Mutex::new(0),
            put_calls: Mutex::new(0),
        });
        let snap = SnapshotKvBackend::new(root.clone() as Arc<dyn KvBackend>);
        snap.write_batch(&[
            crate::backend::WriteOp::Put(b"a".to_vec(), b"1".to_vec()),
            crate::backend::WriteOp::Put(b"b".to_vec(), b"2".to_vec()),
        ])
        .unwrap();
        assert_eq!(*root.batch_calls.lock().unwrap(), 1);
        assert_eq!(*root.put_calls.lock().unwrap(), 0);
        assert_eq!(snap.get(b"a").unwrap(), Some(b"1".to_vec()));
        assert_eq!(snap.get(b"b").unwrap(), Some(b"2".to_vec()));
    }

    /// When layers are pushed, `write_batch` applies in-memory under
    /// one lock — does NOT touch root (which would be a correctness
    /// bug: layers are tentative).
    #[test]
    fn write_batch_with_layer_writes_only_to_top_layer() {
        use std::sync::Mutex;

        struct CountingRoot {
            inner: MemBackend,
            batch_calls: Mutex<usize>,
            put_calls: Mutex<usize>,
        }
        impl KvBackend for CountingRoot {
            fn get(&self, k: &[u8]) -> Result<Option<Vec<u8>>, crate::KvError> {
                self.inner.get(k)
            }
            fn put(&self, k: &[u8], v: &[u8]) -> Result<(), crate::KvError> {
                *self.put_calls.lock().unwrap() += 1;
                self.inner.put(k, v)
            }
            fn delete(&self, k: &[u8]) -> Result<(), crate::KvError> {
                self.inner.delete(k)
            }
            fn scan_all(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, crate::KvError> {
                self.inner.scan_all()
            }
            fn write_batch(&self, ops: &[crate::backend::WriteOp]) -> Result<(), crate::KvError> {
                *self.batch_calls.lock().unwrap() += 1;
                self.inner.write_batch(ops)
            }
        }
        let root = Arc::new(CountingRoot {
            inner: MemBackend::new(),
            batch_calls: Mutex::new(0),
            put_calls: Mutex::new(0),
        });
        let snap = SnapshotKvBackend::new(root.clone() as Arc<dyn KvBackend>);
        snap.advance();
        snap.write_batch(&[
            crate::backend::WriteOp::Put(b"a".to_vec(), b"1".to_vec()),
            crate::backend::WriteOp::Delete(b"b".to_vec()),
        ])
        .unwrap();
        // Root untouched.
        assert_eq!(*root.batch_calls.lock().unwrap(), 0);
        assert_eq!(*root.put_calls.lock().unwrap(), 0);
        // Snapshot sees the writes (tentative).
        assert_eq!(snap.get(b"a").unwrap(), Some(b"1".to_vec()));
        assert_eq!(snap.get(b"b").unwrap(), None);
    }

    /// `write_batch_sync` at depth 0 forwards to the root's sync
    /// variant. The default impl on MemBackend delegates to
    /// write_batch — so we use a custom root that counts which
    /// method was called.
    #[test]
    fn write_batch_sync_at_depth_zero_forwards_to_root_sync() {
        use std::sync::Mutex;

        struct CountingRoot {
            inner: MemBackend,
            sync_calls: Mutex<usize>,
            async_calls: Mutex<usize>,
        }
        impl KvBackend for CountingRoot {
            fn get(&self, k: &[u8]) -> Result<Option<Vec<u8>>, crate::KvError> {
                self.inner.get(k)
            }
            fn put(&self, k: &[u8], v: &[u8]) -> Result<(), crate::KvError> {
                self.inner.put(k, v)
            }
            fn delete(&self, k: &[u8]) -> Result<(), crate::KvError> {
                self.inner.delete(k)
            }
            fn scan_all(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, crate::KvError> {
                self.inner.scan_all()
            }
            fn write_batch(&self, ops: &[crate::backend::WriteOp]) -> Result<(), crate::KvError> {
                *self.async_calls.lock().unwrap() += 1;
                self.inner.write_batch(ops)
            }
            fn write_batch_sync(
                &self,
                ops: &[crate::backend::WriteOp],
            ) -> Result<(), crate::KvError> {
                *self.sync_calls.lock().unwrap() += 1;
                self.inner.write_batch(ops)
            }
        }
        let root = Arc::new(CountingRoot {
            inner: MemBackend::new(),
            sync_calls: Mutex::new(0),
            async_calls: Mutex::new(0),
        });
        let snap = SnapshotKvBackend::new(root.clone() as Arc<dyn KvBackend>);
        snap.write_batch_sync(&[crate::backend::WriteOp::Put(b"a".to_vec(), b"1".to_vec())])
            .unwrap();
        assert_eq!(*root.sync_calls.lock().unwrap(), 1);
        assert_eq!(*root.async_calls.lock().unwrap(), 0);
    }
}
