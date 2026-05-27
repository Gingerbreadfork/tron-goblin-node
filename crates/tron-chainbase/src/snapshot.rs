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
    pub fn merge(&self) {
        let mut g = self.state.write().expect("snapshot lock poisoned");
        let Some(top) = g.layers.pop() else {
            return;
        };
        if let Some(below) = g.layers.last_mut() {
            for (k, v) in top {
                below.insert(k, v);
            }
            return;
        }
        // No remaining layer → flush to root as a single atomic batch.
        if top.is_empty() {
            return;
        }
        let ops: Vec<WriteOp> = top
            .into_iter()
            .map(|(k, v)| match v {
                Some(value) => WriteOp::Put(k, value),
                None => WriteOp::Delete(k),
            })
            .collect();
        self.root.write_batch(&ops);
    }

    /// Squash every layer into the root. Equivalent to repeated
    /// [`merge`] until depth is zero.
    pub fn merge_all(&self) {
        while self.depth() > 0 {
            self.merge();
        }
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
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let g = self.state.read().expect("snapshot lock poisoned");
        for layer in g.layers.iter().rev() {
            if let Some(slot) = layer.get(key) {
                return slot.clone();
            }
        }
        self.root.get(key)
    }

    /// Write into the topmost layer. When no layer exists, writes
    /// land straight in the root.
    pub fn put(&self, key: &[u8], value: &[u8]) {
        let mut g = self.state.write().expect("snapshot lock poisoned");
        if let Some(top) = g.layers.last_mut() {
            top.insert(key.to_vec(), Some(value.to_vec()));
            return;
        }
        drop(g);
        self.root.put(key, value);
    }

    /// Tombstone the key in the topmost layer (or delete in the root
    /// when no layer exists).
    pub fn delete(&self, key: &[u8]) {
        let mut g = self.state.write().expect("snapshot lock poisoned");
        if let Some(top) = g.layers.last_mut() {
            top.insert(key.to_vec(), None);
            return;
        }
        drop(g);
        self.root.delete(key);
    }

    /// `true` when [`get`] would return `Some`. Slightly cheaper
    /// than `get(...).is_some()` because it doesn't clone values
    /// out of the layer maps.
    pub fn contains(&self, key: &[u8]) -> bool {
        let g = self.state.read().expect("snapshot lock poisoned");
        for layer in g.layers.iter().rev() {
            if let Some(slot) = layer.get(key) {
                return slot.is_some();
            }
        }
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
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        SnapshotKvBackend::get(self, key)
    }
    fn put(&self, key: &[u8], value: &[u8]) {
        SnapshotKvBackend::put(self, key, value)
    }
    fn delete(&self, key: &[u8]) {
        SnapshotKvBackend::delete(self, key)
    }
    fn contains(&self, key: &[u8]) -> bool {
        SnapshotKvBackend::contains(self, key)
    }

    fn scan_all(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        // Start from the root's full key set, then overlay tentative
        // writes (puts/deletes) from each layer in order. We use a
        // BTreeMap to keep ascending byte-lexicographic iteration
        // order matching every other `KvBackend::scan_all` impl.
        use std::collections::BTreeMap;
        let mut overlay: BTreeMap<Vec<u8>, Vec<u8>> =
            self.root.scan_all().into_iter().collect();
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
        overlay.into_iter().collect()
    }

    fn scan_from(&self, start: &[u8], limit: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
        if limit == 0 {
            return Vec::new();
        }
        self.scan_all()
            .into_iter()
            .filter(|(k, _)| k.as_slice() >= start)
            .take(limit)
            .collect()
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.scan_all()
            .into_iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .collect()
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
        snap.put(b"k", b"v");
        assert_eq!(snap.get(b"k").as_deref(), Some(b"v".as_ref()));
        assert!(snap.contains(b"k"));
    }

    #[test]
    fn advance_pushes_writes_into_top_layer() {
        let snap = fresh();
        snap.put(b"k", b"root");
        snap.advance();
        assert_eq!(snap.depth(), 1);
        snap.put(b"k", b"layer1");
        assert_eq!(snap.get(b"k").as_deref(), Some(b"layer1".as_ref()));
    }

    #[test]
    fn revoke_drops_topmost_layer_writes() {
        let snap = fresh();
        snap.put(b"k", b"root");
        snap.advance();
        snap.put(b"k", b"layer1");
        snap.revoke();
        assert_eq!(snap.depth(), 0);
        assert_eq!(snap.get(b"k").as_deref(), Some(b"root".as_ref()));
    }

    #[test]
    fn delete_in_layer_shadows_root_value() {
        let snap = fresh();
        snap.put(b"k", b"root");
        snap.advance();
        snap.delete(b"k");
        assert_eq!(snap.get(b"k"), None);
        assert!(!snap.contains(b"k"));
        // Revoke restores the root view.
        snap.revoke();
        assert_eq!(snap.get(b"k").as_deref(), Some(b"root".as_ref()));
    }

    #[test]
    fn merge_squashes_top_into_below() {
        let snap = fresh();
        snap.put(b"k1", b"root");
        snap.advance(); // layer A
        snap.put(b"k1", b"layerA");
        snap.put(b"k2", b"layerA");
        snap.advance(); // layer B
        snap.put(b"k2", b"layerB");
        snap.merge(); // collapse B into A
        assert_eq!(snap.depth(), 1);
        assert_eq!(snap.get(b"k1").as_deref(), Some(b"layerA".as_ref()));
        assert_eq!(snap.get(b"k2").as_deref(), Some(b"layerB".as_ref()));
    }

    #[test]
    fn merge_at_bottom_flushes_to_root() {
        let snap = fresh();
        snap.put(b"k", b"root");
        snap.advance();
        snap.put(b"k", b"layer1");
        snap.merge(); // bottom layer → flushed to root
        assert_eq!(snap.depth(), 0);
        assert_eq!(snap.get(b"k").as_deref(), Some(b"layer1".as_ref()));
    }

    #[test]
    fn merge_all_flushes_every_layer_to_root() {
        let snap = fresh();
        snap.advance();
        snap.put(b"a", b"1");
        snap.advance();
        snap.put(b"b", b"2");
        snap.advance();
        snap.put(b"c", b"3");
        snap.merge_all();
        assert_eq!(snap.depth(), 0);
        for (k, want) in [(b"a", "1"), (b"b", "2"), (b"c", "3")] {
            assert_eq!(snap.get(k).unwrap(), want.as_bytes());
        }
    }

    #[test]
    fn deeper_layer_shadows_earlier_one() {
        let snap = fresh();
        snap.put(b"k", b"root");
        snap.advance();
        snap.put(b"k", b"a");
        snap.advance();
        snap.put(b"k", b"b");
        assert_eq!(snap.get(b"k").as_deref(), Some(b"b".as_ref()));
        snap.revoke(); // drop b
        assert_eq!(snap.get(b"k").as_deref(), Some(b"a".as_ref()));
        snap.revoke(); // drop a
        assert_eq!(snap.get(b"k").as_deref(), Some(b"root".as_ref()));
    }

    #[test]
    fn revoke_on_empty_stack_is_safe() {
        let snap = fresh();
        snap.revoke(); // no-op
        snap.merge(); // no-op
        snap.put(b"k", b"v"); // still goes to root
        assert_eq!(snap.get(b"k").as_deref(), Some(b"v".as_ref()));
    }

    #[test]
    fn tombstone_followed_by_put_resurrects_value() {
        let snap = fresh();
        snap.put(b"k", b"root");
        snap.advance();
        snap.delete(b"k");
        assert!(snap.get(b"k").is_none());
        snap.put(b"k", b"alive");
        assert_eq!(snap.get(b"k").as_deref(), Some(b"alive".as_ref()));
    }

    // ────────────────────────────────────────────────────────────
    // `KvBackend` trait bridge — confirms a `SnapshotKvBackend`
    // works wherever an `Arc<dyn KvBackend>` is expected.
    // ────────────────────────────────────────────────────────────

    #[test]
    fn scan_all_overlays_layers_on_root() {
        let snap = fresh();
        snap.put(b"a", b"root-a");
        snap.put(b"b", b"root-b");
        snap.advance();
        snap.put(b"a", b"layer-a"); // overwrite
        snap.put(b"c", b"layer-c"); // insert
        snap.delete(b"b"); // tombstone
        // scan_all reads through the bridge
        let pairs: Vec<(Vec<u8>, Vec<u8>)> =
            <SnapshotKvBackend as KvBackend>::scan_all(&snap);
        let map: HashMap<Vec<u8>, Vec<u8>> = pairs.into_iter().collect();
        assert_eq!(map.get(b"a".as_ref()).map(|v| v.as_slice()), Some(b"layer-a".as_ref()));
        assert_eq!(map.get(b"c".as_ref()).map(|v| v.as_slice()), Some(b"layer-c".as_ref()));
        assert!(map.get(b"b".as_ref()).is_none(), "tombstone must hide root value");
    }

    #[test]
    fn scan_all_returns_sorted_ascending() {
        let snap = fresh();
        snap.put(b"zzz", b"3");
        snap.put(b"aaa", b"1");
        snap.advance();
        snap.put(b"mmm", b"2");
        let pairs = <SnapshotKvBackend as KvBackend>::scan_all(&snap);
        let keys: Vec<&[u8]> = pairs.iter().map(|(k, _)| k.as_slice()).collect();
        assert_eq!(keys, vec![b"aaa".as_ref(), b"mmm".as_ref(), b"zzz".as_ref()]);
    }

    #[test]
    fn scan_from_respects_start_and_limit() {
        let snap = fresh();
        for byte in [0xa0u8, 0xb0, 0xc0, 0xd0] {
            snap.put(&[byte], &[byte ^ 0xff]);
        }
        let pairs =
            <SnapshotKvBackend as KvBackend>::scan_from(&snap, &[0xb5], 5);
        let keys: Vec<u8> = pairs.iter().map(|(k, _)| k[0]).collect();
        assert_eq!(keys, vec![0xc0, 0xd0]);
    }

    #[test]
    fn scan_prefix_filters_to_matching_keys() {
        let snap = fresh();
        snap.put(b"foo:1", b"1");
        snap.put(b"foo:2", b"2");
        snap.put(b"bar:1", b"3");
        snap.advance();
        snap.put(b"foo:3", b"4"); // layer-only
        snap.delete(b"foo:1"); // tombstone
        let pairs =
            <SnapshotKvBackend as KvBackend>::scan_prefix(&snap, b"foo:");
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
        snap.put(b"k", b"layered");
        let dyn_ref: Arc<dyn KvBackend> = snap.clone();
        assert_eq!(dyn_ref.get(b"k").as_deref(), Some(b"layered".as_ref()));
        // Revoke through the typed handle; the dyn-ref sees the same
        // underlying state.
        snap.revoke();
        assert!(dyn_ref.get(b"k").is_none());
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
            fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
                self.inner.get(key)
            }
            fn put(&self, key: &[u8], value: &[u8]) {
                *self.per_call_puts.lock().unwrap() += 1;
                self.inner.put(key, value);
            }
            fn delete(&self, key: &[u8]) {
                *self.per_call_deletes.lock().unwrap() += 1;
                self.inner.delete(key);
            }
            fn scan_all(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
                self.inner.scan_all()
            }
            fn write_batch(&self, ops: &[WriteOp]) {
                self.batches.lock().unwrap().push(ops.to_vec());
                self.inner.write_batch(ops);
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
        snap.put(b"a", b"1");
        snap.put(b"b", b"2");
        snap.delete(b"c");
        snap.merge(); // bottom → flushed to root

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
            fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
                self.inner.get(key)
            }
            fn put(&self, key: &[u8], value: &[u8]) {
                self.inner.put(key, value);
            }
            fn delete(&self, key: &[u8]) {
                self.inner.delete(key);
            }
            fn scan_all(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
                self.inner.scan_all()
            }
            fn write_batch(&self, ops: &[WriteOp]) {
                *self.calls.lock().unwrap() += 1;
                self.inner.write_batch(ops);
            }
        }

        let root = Arc::new(CountingRoot {
            inner: MemBackend::new(),
            calls: Mutex::new(0),
        });
        let snap = SnapshotKvBackend::new(root.clone() as Arc<dyn KvBackend>);
        snap.advance();
        snap.merge(); // empty bottom layer → flushed to root with nothing to do
        assert_eq!(*root.calls.lock().unwrap(), 0);
    }

    use std::collections::HashSet;
}
