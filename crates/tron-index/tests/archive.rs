//! Historical-state archive tests: codec edge cases, point reads at
//! height, base coverage, reorg unwind, exact gap repair from the undo
//! log, coverage resets, and the merged at-height KvBackend view.

use std::sync::Arc;

use tron_chainbase::{BlockUndoStore, KvBackend, MemBackend, UndoEntry, UndoStoreId, WriteOp};
use tron_index::{ArchiveAtBackend, ArchiveWriter, AtHeight, DeltaRef};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

const S: UndoStoreId = UndoStoreId::Accounts;

/// Test rig: an archive writer + one live store it mirrors. `apply`
/// mutates the live store AND feeds the archive, like the real hook;
/// `mutate_silently` mutates only live (simulating blocks the archive
/// missed).
struct Rig {
    live: Arc<dyn KvBackend>,
    undo_be: Arc<dyn KvBackend>,
    writer: ArchiveWriter,
}

impl Rig {
    fn new() -> Self {
        let live = mem();
        let undo_be = mem();
        let writer = ArchiveWriter::new(
            mem(),
            Some(BlockUndoStore::new(undo_be.clone())),
            vec![(S, live.clone())],
        );
        writer.check_or_init().unwrap();
        Self { live, undo_be, writer }
    }

    /// One block writing `(key, value)` pairs (`None` = delete), with
    /// the archive fed like the production hook (including the
    /// matching undo record, as the executor would persist).
    fn apply(&self, height: i64, writes: &[(&[u8], Option<&[u8]>)]) {
        let befores: Vec<Option<Vec<u8>>> =
            writes.iter().map(|(k, _)| self.live.get(k).unwrap()).collect();
        let mut record = tron_chainbase::BlockUndoRecord::new();
        for ((key, _), before) in writes.iter().zip(befores.iter()) {
            record.push(UndoEntry { store: S, key: key.to_vec(), before: before.clone() });
        }
        BlockUndoStore::new(self.undo_be.clone()).put(height, &record).unwrap();
        for (key, value) in writes {
            match value {
                Some(v) => self.live.put(key, v).unwrap(),
                None => self.live.delete(key).unwrap(),
            }
        }
        let deltas: Vec<DeltaRef<'_>> = writes
            .iter()
            .zip(befores.iter())
            .map(|((key, after), before)| DeltaRef {
                store: S,
                key,
                before: before.as_deref(),
                after: *after,
            })
            .collect();
        self.writer.on_block_applied(height, Some(&deltas)).unwrap();
    }

    /// A block the archive never saw: live + undo record only.
    fn mutate_silently(&self, height: i64, writes: &[(&[u8], Option<&[u8]>)]) {
        let mut record = tron_chainbase::BlockUndoRecord::new();
        for (key, _) in writes {
            record.push(UndoEntry {
                store: S,
                key: key.to_vec(),
                before: self.live.get(key).unwrap(),
            });
        }
        BlockUndoStore::new(self.undo_be.clone()).put(height, &record).unwrap();
        for (key, value) in writes {
            match value {
                Some(v) => self.live.put(key, v).unwrap(),
                None => self.live.delete(key).unwrap(),
            }
        }
    }

    fn value_at(&self, key: &[u8], h: i64) -> AtHeight {
        self.writer.reader().value_at(S, key, h).unwrap()
    }
}

#[test]
fn point_reads_return_the_value_as_of_each_height() {
    let rig = Rig::new();
    rig.apply(10, &[(b"acct", Some(b"v10"))]);
    rig.apply(11, &[(b"other", Some(b"x"))]);
    rig.apply(12, &[(b"acct", Some(b"v12"))]);
    rig.apply(13, &[(b"acct", None)]); // deleted
    rig.apply(14, &[(b"acct", Some(b"v14"))]);

    assert_eq!(rig.writer.reader().coverage().unwrap(), Some((9, 14)));
    // Before its first write (height 9 = base): the pre-image (absent).
    assert_eq!(rig.value_at(b"acct", 9), AtHeight::Deleted);
    assert_eq!(rig.value_at(b"acct", 10), AtHeight::Value(b"v10".to_vec()));
    assert_eq!(rig.value_at(b"acct", 11), AtHeight::Value(b"v10".to_vec()), "carried forward");
    assert_eq!(rig.value_at(b"acct", 12), AtHeight::Value(b"v12".to_vec()));
    assert_eq!(rig.value_at(b"acct", 13), AtHeight::Deleted);
    assert_eq!(rig.value_at(b"acct", 14), AtHeight::Value(b"v14".to_vec()));
    // Never-written key: not covered → live applies.
    assert_eq!(rig.value_at(b"untouched", 12), AtHeight::NotCovered);
}

#[test]
fn base_pre_image_gives_coverage_before_first_write() {
    let rig = Rig::new();
    // Key exists in live state BEFORE capture starts.
    rig.live.put(b"old", b"pre-capture").unwrap();
    // Capture starts at 100 (base = 99); blocks are contiguous, as the
    // apply hook delivers them.
    for h in 100..=104 {
        rig.apply(h, &[(b"noise", Some(b"n"))]);
    }
    rig.apply(105, &[(b"old", Some(b"changed"))]);

    // Reads in [99, 104] must see the pre-capture value even though
    // live now holds "changed" — the base pre-image pins it.
    for h in 99..=104 {
        assert_eq!(rig.value_at(b"old", h), AtHeight::Value(b"pre-capture".to_vec()), "h={h}");
    }
    assert_eq!(rig.value_at(b"old", 105), AtHeight::Value(b"changed".to_vec()));
}

#[test]
fn prefix_related_and_nul_containing_keys_do_not_interleave() {
    let rig = Rig::new();
    // "ab" is a strict prefix of the others; 0x00/0xFF bytes exercise
    // the escaping.
    let k1: &[u8] = b"ab";
    let k2: &[u8] = &[0x61, 0x62, 0x00, 0x07]; // "ab\x00\x07"
    let k3: &[u8] = &[0x61, 0x62, 0xFF, 0xFF]; // "ab\xFF\xFF"
    rig.apply(10, &[(k1, Some(b"one@10"))]);
    rig.apply(11, &[(k2, Some(b"two@11"))]);
    rig.apply(12, &[(k3, Some(b"three@12")), (k1, Some(b"one@12"))]);

    assert_eq!(rig.value_at(k1, 10), AtHeight::Value(b"one@10".to_vec()));
    assert_eq!(rig.value_at(k1, 11), AtHeight::Value(b"one@10".to_vec()));
    assert_eq!(rig.value_at(k1, 12), AtHeight::Value(b"one@12".to_vec()));
    assert_eq!(rig.value_at(k2, 10), AtHeight::Deleted, "k2's base pre-image (absent)");
    assert_eq!(rig.value_at(k2, 11), AtHeight::Value(b"two@11".to_vec()));
    assert_eq!(rig.value_at(k3, 11), AtHeight::Deleted);
    assert_eq!(rig.value_at(k3, 12), AtHeight::Value(b"three@12".to_vec()));
}

#[test]
fn reorg_reapply_unwinds_orphaned_heights_exactly() {
    let rig = Rig::new();
    rig.apply(10, &[(b"a", Some(b"a10"))]);
    rig.apply(11, &[(b"a", Some(b"a11-old")), (b"orphan", Some(b"only-on-old-chain"))]);
    rig.apply(12, &[(b"a", Some(b"a12-old"))]);

    // Reorg: heights 11-12 replaced (the hook reapplies 11 first).
    rig.apply(11, &[(b"a", Some(b"a11-new"))]);
    rig.apply(12, &[(b"b", Some(b"b12-new"))]);
    rig.apply(13, &[(b"a", Some(b"a13"))]);

    assert_eq!(rig.value_at(b"a", 10), AtHeight::Value(b"a10".to_vec()));
    assert_eq!(rig.value_at(b"a", 11), AtHeight::Value(b"a11-new".to_vec()));
    assert_eq!(rig.value_at(b"a", 12), AtHeight::Value(b"a11-new".to_vec()), "new chain didn't rewrite a at 12");
    assert_eq!(rig.value_at(b"a", 13), AtHeight::Value(b"a13".to_vec()));
    // The old chain's key never written on the new chain: fully gone.
    assert_eq!(rig.value_at(b"orphan", 12), AtHeight::NotCovered);
    let unwinds = rig
        .writer
        .counters()
        .reorg_unwinds
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(unwinds, 1);
}

#[test]
fn crash_gap_is_repaired_exactly_from_the_undo_log() {
    let rig = Rig::new();
    rig.apply(10, &[(b"k", Some(b"k10")), (b"stable", Some(b"s10"))]);

    // Blocks 11-12 happen while the archive is "off" (crash tail):
    // live + undo records advance, the archive does not.
    rig.mutate_silently(11, &[(b"k", Some(b"k11")), (b"gaponly", Some(b"g11"))]);
    rig.mutate_silently(12, &[(b"k", Some(b"k12"))]);

    // Block 13 applies normally → triggers repair of 11..12. It also
    // rewrites `k`, so k@12 must come from 13's pre-image.
    rig.apply(13, &[(b"k", Some(b"k13"))]);

    assert_eq!(rig.value_at(b"k", 10), AtHeight::Value(b"k10".to_vec()));
    assert_eq!(rig.value_at(b"k", 11), AtHeight::Value(b"k11".to_vec()), "intermediate from next pre-image");
    assert_eq!(rig.value_at(b"k", 12), AtHeight::Value(b"k12".to_vec()), "last gap write from block 13's pre-image");
    assert_eq!(rig.value_at(b"k", 13), AtHeight::Value(b"k13".to_vec()));
    // A key written only inside the gap and never after: final value
    // comes from the live store.
    assert_eq!(rig.value_at(b"gaponly", 10), AtHeight::Deleted, "base pre-image: absent before 11");
    assert_eq!(rig.value_at(b"gaponly", 11), AtHeight::Value(b"g11".to_vec()));
    assert_eq!(rig.value_at(b"gaponly", 12), AtHeight::Value(b"g11".to_vec()));
    // Untouched-by-gap key still reads through.
    assert_eq!(rig.value_at(b"stable", 12), AtHeight::Value(b"s10".to_vec()));
    let repaired = rig
        .writer
        .counters()
        .gap_repaired_blocks
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(repaired, 2);
    assert_eq!(rig.writer.reader().coverage().unwrap(), Some((9, 13)));
}

#[test]
fn unrepairable_gap_resets_coverage_loudly() {
    let rig = Rig::new();
    rig.apply(10, &[(b"k", Some(b"k10"))]);
    // Gap blocks WITHOUT undo records (pruned / lost).
    rig.live.put(b"k", b"k11").unwrap();
    // Block 30 applies — gap 11..29 has no undo records → reset.
    rig.apply(30, &[(b"k", Some(b"k30"))]);

    assert_eq!(
        rig.writer
            .counters()
            .coverage_resets
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    // Coverage restarted at 29; old history is gone (wiped).
    assert_eq!(rig.writer.reader().coverage().unwrap(), Some((29, 30)));
    assert_eq!(rig.value_at(b"k", 29), AtHeight::Value(b"k11".to_vec()), "base pre-image of block 30");
    assert_eq!(rig.value_at(b"k", 30), AtHeight::Value(b"k30".to_vec()));
}

#[test]
fn missing_deltas_resets_coverage() {
    let rig = Rig::new();
    rig.apply(10, &[(b"k", Some(b"k10"))]);
    rig.writer.on_block_applied(11, None).unwrap();
    assert_eq!(
        rig.writer
            .counters()
            .coverage_resets
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    assert_eq!(rig.writer.reader().coverage().unwrap(), Some((11, 11)));
}

// ---------------------------------------------------------------------------
// The at-height KvBackend view
// ---------------------------------------------------------------------------

#[test]
fn at_height_backend_resolves_gets_with_fall_through() {
    let rig = Rig::new();
    rig.live.put(b"untouched", b"live-val").unwrap();
    rig.apply(10, &[(b"k", Some(b"k10"))]);
    rig.apply(11, &[(b"k", Some(b"k11")), (b"born11", Some(b"baby"))]);
    rig.apply(12, &[(b"k", None)]); // k deleted at 12

    let at = |h: i64| ArchiveAtBackend::new(rig.live.clone(), rig.writer.reader(), S, h);
    assert_eq!(at(10).get(b"k").unwrap().as_deref(), Some(&b"k10"[..]));
    assert_eq!(at(11).get(b"k").unwrap().as_deref(), Some(&b"k11"[..]));
    assert_eq!(at(12).get(b"k").unwrap(), None, "deleted as of 12");
    assert_eq!(at(10).get(b"born11").unwrap(), None, "not yet created at 10");
    assert_eq!(at(11).get(b"born11").unwrap().as_deref(), Some(&b"baby"[..]));
    assert_eq!(
        at(10).get(b"untouched").unwrap().as_deref(),
        Some(&b"live-val"[..]),
        "never written since capture → live fall-through"
    );
    // Writes refused.
    assert!(at(10).put(b"x", b"y").is_err());
    assert!(at(10).delete(b"x").is_err());
    assert!(at(10).write_batch(&[WriteOp::Put(b"x".to_vec(), b"y".to_vec())]).is_err());
    assert!(at(10).scan_all().is_err());
}

#[test]
fn at_height_scans_merge_live_and_archive_correctly() {
    let rig = Rig::new();
    // Live-only keys (never written since capture).
    rig.live.put(b"p/live1", b"L1").unwrap();
    rig.live.put(b"p/live2", b"L2").unwrap();
    rig.live.put(b"q/other", b"Q").unwrap();
    rig.apply(10, &[(b"p/archived", Some(b"A10"))]);
    rig.apply(11, &[(b"p/born11", Some(b"B11")), (b"p/archived", Some(b"A11"))]);
    rig.apply(12, &[(b"p/live1", None)]); // deletes a live key at 12

    let scan = |h: i64| {
        ArchiveAtBackend::new(rig.live.clone(), rig.writer.reader(), S, h)
            .scan_prefix(b"p/")
            .unwrap()
            .into_iter()
            .map(|(k, v)| (String::from_utf8(k).unwrap(), String::from_utf8(v).unwrap()))
            .collect::<Vec<_>>()
    };

    // At height 10: born11 doesn't exist yet, live1/live2 unchanged,
    // archived at its h10 value.
    assert_eq!(
        scan(10),
        vec![
            ("p/archived".into(), "A10".into()),
            ("p/live1".into(), "L1".into()),
            ("p/live2".into(), "L2".into()),
        ]
    );
    // At height 11: born11 appears; archived at its h11 value.
    assert_eq!(
        scan(11),
        vec![
            ("p/archived".into(), "A11".into()),
            ("p/born11".into(), "B11".into()),
            ("p/live1".into(), "L1".into()),
            ("p/live2".into(), "L2".into()),
        ]
    );
    // At height 12: live1 was deleted at 12 → hidden, even though the
    // live store still holds it... (it was deleted from live too; its
    // archived tombstone hides it regardless).
    assert_eq!(
        scan(12),
        vec![
            ("p/archived".into(), "A11".into()),
            ("p/born11".into(), "B11".into()),
            ("p/live2".into(), "L2".into()),
        ]
    );

    // scan_from with a limit walks the merged order.
    let first_two = ArchiveAtBackend::new(rig.live.clone(), rig.writer.reader(), S, 11)
        .scan_from(b"p/", 2)
        .unwrap();
    assert_eq!(first_two.len(), 2);
    assert_eq!(first_two[0].0, b"p/archived".to_vec());
    assert_eq!(first_two[1].0, b"p/born11".to_vec());
}
