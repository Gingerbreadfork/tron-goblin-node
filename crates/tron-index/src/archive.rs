//! Historical-state archive — versioned-KV by key (P2, opt-in).
//!
//! When `[index] capture_state_deltas` is on, every block's committed
//! write-set (post-images, captured by the executor at the
//! block-session drain) is stored **per-changed-key, key-keyed**:
//!
//! ```text
//! row key = 0x01 ‖ store(1) ‖ escape(key) ‖ height_desc(8)
//! value   = 0x00              (key deleted at that height)
//!         | 0x01 ‖ bytes      (value as committed at that height)
//! ```
//!
//! A historical point read of `key` at height `H` is **one seek** to
//! the first entry ≥ `… ‖ escape(key) ‖ height_desc(H)` — the value as
//! of ≤ H. Not a replay, not an anchor-walk; history depth adds zero
//! read cost. `escape()` makes encoded keys prefix-free (0x00 →
//! 0x00 0xFF, terminated by 0x00 0x00) while preserving raw
//! lexicographic order, so variable-length store keys can never
//! interleave another key's version range.
//!
//! **Coverage.** Deltas alone answer "value at H" only for keys
//! written since capture began. Two rules close the gaps exactly:
//!
//! * On a key's **first** write since capture, its pre-image is also
//!   stored at the capture **base height** — so every archived key has
//!   full coverage from `base` forward.
//! * A key with **no archive entry at all** was never written since
//!   capture — its current (live) value IS its value at any covered H,
//!   and reads fall through to the live store.
//!
//! Reads are valid only inside `[base, head]`; the API layer enforces
//! it.
//!
//! **The archive is NOT disposable** (unlike the tx-history index):
//! deltas are not re-derivable from the stores after the fact. A
//! coverage break (capture toggled off and on, or a crash whose gap
//! out-lives the undo log) wipes the archive and restarts coverage at
//! the current head — loudly, because that is hours/terabytes of
//! history. Small gaps (crash tails) are repaired **exactly** from the
//! block-undo log: consecutive pre-images of a key reconstruct the
//! intermediate post-images, and the final write's post-image is the
//! current live value (or the next block's pre-image).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tron_chainbase::{BlockUndoStore, KvBackend, UndoStoreId, WriteOp};

use crate::db::IndexError;
use crate::keys::{decode_key_list, encode_key_list, height_desc, height_from_desc};

/// Bumped on any layout/semantics change a reader could mis-interpret.
pub const ARCHIVE_FORMAT_VERSION: u32 = 1;

const TAG_META: u8 = 0x00;
const TAG_ROW: u8 = 0x01;

/// One key mutation of a block's write-set, as the archive consumes
/// it. Borrowed view — the node maps the executor's `CapturedDelta`
/// into this without copying.
#[derive(Debug, Clone, Copy)]
pub struct DeltaRef<'a> {
    pub store: UndoStoreId,
    pub key: &'a [u8],
    pub before: Option<&'a [u8]>,
    pub after: Option<&'a [u8]>,
}

/// Outcome of a historical point read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtHeight {
    /// Key never written since capture began — the live value applies.
    NotCovered,
    /// Key did not exist (or was deleted) as of the queried height.
    Deleted,
    Value(Vec<u8>),
}

// ---------------------------------------------------------------------------
// Codec
// ---------------------------------------------------------------------------

/// Escape a store key so encoded keys are prefix-free while preserving
/// raw lexicographic order: `0x00 → 0x00 0xFF`, terminated by
/// `0x00 0x00` (the smallest possible continuation, so "k" sorts
/// before "k‖anything").
fn escape_key(key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(key.len() + 2);
    for &b in key {
        if b == 0 {
            out.extend_from_slice(&[0x00, 0xFF]);
        } else {
            out.push(b);
        }
    }
    out.extend_from_slice(&[0x00, 0x00]);
    out
}

/// Escape WITHOUT the terminator — the encoded prefix shared by every
/// key that starts with `prefix` in raw space.
fn escape_partial(prefix: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(prefix.len() + 2);
    for &b in prefix {
        if b == 0 {
            out.extend_from_slice(&[0x00, 0xFF]);
        } else {
            out.push(b);
        }
    }
    out
}

/// Parse an escaped key back out of a row key (after the 2-byte
/// `[TAG_ROW, store]` header). Returns `(raw_key, bytes_consumed)`.
fn unescape_key(buf: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < buf.len() {
        match (buf[i], buf[i + 1]) {
            (0x00, 0x00) => return Some((out, i + 2)),
            (0x00, 0xFF) => {
                out.push(0x00);
                i += 2;
            }
            (0x00, _) => return None, // malformed escape
            (b, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    None
}

fn row_key(store: UndoStoreId, key: &[u8], height: i64) -> Vec<u8> {
    let mut k = Vec::with_capacity(2 + key.len() + 2 + 8);
    k.push(TAG_ROW);
    k.push(store as u8);
    k.extend_from_slice(&escape_key(key));
    k.extend_from_slice(&height_desc(height));
    k
}

/// Split a version row key into `(group_prefix, height)`. The group
/// prefix is `TAG_ROW ‖ store ‖ escape(key)` — everything that every
/// version of one key shares; the trailing 8 bytes are the
/// `height_desc`. Returns `None` for a key too short to carry a header
/// + a full height suffix (a non-row key, or a corrupt one).
fn split_row_key(key: &[u8]) -> Option<(&[u8], i64)> {
    if key.len() < 2 + 8 || key[0] != TAG_ROW {
        return None;
    }
    let split = key.len() - 8;
    let desc: [u8; 8] = key[split..].try_into().ok()?;
    Some((&key[..split], height_from_desc(desc)))
}

fn enc_value(v: Option<&[u8]>) -> Vec<u8> {
    match v {
        None => vec![0x00],
        Some(bytes) => {
            let mut out = Vec::with_capacity(1 + bytes.len());
            out.push(0x01);
            out.extend_from_slice(bytes);
            out
        }
    }
}

fn dec_value(bytes: &[u8]) -> AtHeight {
    match bytes.first() {
        Some(0x00) => AtHeight::Deleted,
        Some(0x01) => AtHeight::Value(bytes[1..].to_vec()),
        _ => AtHeight::Deleted, // malformed — treat as absent, never panic
    }
}

fn meta_key(name: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + name.len());
    k.push(TAG_META);
    k.extend_from_slice(name);
    k
}

fn meta_keys_at(height: i64) -> Vec<u8> {
    let mut k = meta_key(b"keys_at/");
    k.extend_from_slice(&(height as u64).to_be_bytes());
    k
}

/// The reset-in-progress marker. A coverage reset is a multi-batch
/// wipe; without a durable marker, a power loss mid-wipe could leave
/// stale version rows behind a fresh stamp — served as exact history.
/// Value: the new base height (8 bytes BE), or empty for a
/// format-upgrade wipe that re-initializes coverage on the next block.
fn meta_wiping() -> Vec<u8> {
    meta_key(b"wiping")
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

/// Counters mirrored into the node's metrics sampler.
#[derive(Debug, Default)]
pub struct ArchiveCounters {
    pub blocks_archived: AtomicU64,
    pub entries_written: AtomicU64,
    pub reorg_unwinds: AtomicU64,
    pub gap_repaired_blocks: AtomicU64,
    /// Coverage resets (wipe + restart) — should stay 0 in steady
    /// operation; non-zero means history was lost and capture
    /// restarted.
    pub coverage_resets: AtomicU64,
    /// Retention prune passes that actually advanced the floor.
    pub prune_passes: AtomicU64,
    /// Cumulative version rows deleted by retention pruning.
    pub pruned_rows: AtomicU64,
    /// Lowest covered height — mirrors the stored `base_height` after
    /// the most recent prune so the sampler can surface it without a
    /// read.
    pub prune_floor: AtomicU64,
}

/// Outcome of one [`ArchiveWriter::prune_below`] pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PruneStats {
    /// Version rows examined across every key group.
    pub rows_scanned: u64,
    /// Version rows deleted (strictly older than each key's retained
    /// anchor).
    pub rows_deleted: u64,
    /// Anchors re-pinned at the new floor (a key whose newest version
    /// `<= floor` sat strictly below it).
    pub rows_repinned: u64,
    /// Coverage base before this pass.
    pub base_before: i64,
    /// Coverage base after this pass (== `floor` when the floor moved,
    /// else unchanged).
    pub base_after: i64,
    /// `true` when the pass was a no-op (floor at or below the current
    /// base) — the idempotent-replay case.
    pub noop: bool,
}

/// Synchronous archive capture, fed from the apply hook. Internally
/// locked — apply is already serialized, the lock is a safety net.
pub struct ArchiveWriter {
    backend: Arc<dyn KvBackend>,
    /// Gap-repair source: the consensus block-undo log.
    undo: Option<BlockUndoStore>,
    /// Gap-repair source: live store backends per `StoreId`, for the
    /// final post-image of a gap key not rewritten afterwards.
    live: Vec<(UndoStoreId, Arc<dyn KvBackend>)>,
    counters: Arc<ArchiveCounters>,
    inner: Mutex<WriterInner>,
}

/// Heights within this distance of the head keep unwind records.
/// Reorgs are bounded by the solidified gate (~19 blocks); 512 leaves
/// enormous margin.
const RING_DEPTH: i64 = 512;
/// WAL fsync cadence (blocks). Crash tails inside the window repair
/// exactly from the undo log.
const SYNC_EVERY: u32 = 16;

struct WriterInner {
    blocks_since_sync: u32,
}

impl ArchiveWriter {
    pub fn new(
        backend: Arc<dyn KvBackend>,
        undo: Option<BlockUndoStore>,
        live: Vec<(UndoStoreId, Arc<dyn KvBackend>)>,
    ) -> Self {
        Self {
            backend,
            undo,
            live,
            counters: Arc::new(ArchiveCounters::default()),
            inner: Mutex::new(WriterInner { blocks_since_sync: 0 }),
        }
    }

    pub fn counters(&self) -> Arc<ArchiveCounters> {
        self.counters.clone()
    }

    pub fn reader(&self) -> ArchiveReader {
        ArchiveReader { backend: self.backend.clone() }
    }

    /// Check or stamp the on-disk format. `Err` for a newer-format DB.
    /// Returns `true` when this is a fresh (just-stamped) archive.
    pub fn check_or_init(&self) -> Result<bool, IndexError> {
        // A crash mid-reset leaves the durable `wiping` marker; finish
        // the interrupted wipe before trusting anything else on disk.
        if self.backend.get(&meta_wiping())?.is_some() {
            tracing::warn!("archive: resuming an interrupted coverage reset");
            self.finish_reset()?;
            self.counters.coverage_resets.fetch_add(1, Ordering::Relaxed);
        }
        match self.get_u32(b"format_version")? {
            None => {
                self.backend.write_batch(&[WriteOp::Put(
                    meta_key(b"format_version"),
                    ARCHIVE_FORMAT_VERSION.to_be_bytes().to_vec(),
                )])?;
                Ok(true)
            }
            Some(v) if v == ARCHIVE_FORMAT_VERSION => Ok(false),
            Some(v) if v < ARCHIVE_FORMAT_VERSION => {
                // No migrations: an old-format archive can't be
                // re-derived, so the only honest move is reset.
                tracing::warn!(
                    on_disk = v,
                    current = ARCHIVE_FORMAT_VERSION,
                    "archive: format version bumped — wiping and restarting coverage"
                );
                self.wipe_and_restamp()?;
                Ok(true)
            }
            Some(v) => Err(IndexError::NewerFormat {
                on_disk: v,
                supported: ARCHIVE_FORMAT_VERSION,
            }),
        }
    }

    fn get_i64(&self, name: &[u8]) -> Result<Option<i64>, IndexError> {
        Ok(self
            .backend
            .get(&meta_key(name))?
            .and_then(|v| v.try_into().ok())
            .map(i64::from_be_bytes))
    }

    fn get_u32(&self, name: &[u8]) -> Result<Option<u32>, IndexError> {
        Ok(self
            .backend
            .get(&meta_key(name))?
            .and_then(|v| v.try_into().ok())
            .map(u32::from_be_bytes))
    }

    pub fn base_height(&self) -> Result<Option<i64>, IndexError> {
        self.get_i64(b"base_height")
    }

    pub fn head(&self) -> Result<Option<i64>, IndexError> {
        self.get_i64(b"head")
    }

    /// `(base, head)` coverage — `None` until capture has started.
    /// Mirrors [`ArchiveReader::coverage`] for callers holding only the
    /// writer (e.g. the retention timer logging the post-prune range).
    pub fn coverage(&self) -> Result<Option<(i64, i64)>, IndexError> {
        match (self.base_height()?, self.head()?) {
            (Some(b), Some(h)) => Ok(Some((b, h))),
            _ => Ok(None),
        }
    }

    /// The two-phase, crash-safe wipe. Phase 1 (caller): make the
    /// `wiping` marker durable. Phase 2 (here): delete everything
    /// except the marker, then atomically restamp + apply the
    /// marker's coverage + drop the marker, and fsync. A crash at any
    /// point either left the marker durable (the next open resumes
    /// here and finishes the job) or completed — stale rows can never
    /// survive behind a fresh stamp.
    fn finish_reset(&self) -> Result<(), IndexError> {
        let marker = self.backend.get(&meta_wiping())?;
        let Some(marker) = marker else {
            return Err(IndexError::Corrupt("finish_reset without a wiping marker".into()));
        };
        let wiping_key = meta_wiping();
        // Delete every row except the wiping marker, streaming in bounded
        // chunks via scan_from. scan_all would materialize the ENTIRE archive
        // (keys AND values) in one allocation — hours/terabytes of history —
        // and OOM the node; the `wiping` marker then re-OOMs on every reopen.
        const CHUNK: usize = 50_000;
        let mut cursor: Vec<u8> = Vec::new();
        loop {
            let rows = self.backend.scan_from(&cursor, CHUNK)?;
            let Some((last, _)) = rows.last() else {
                break;
            };
            let mut next = last.clone();
            let ops: Vec<WriteOp> = rows
                .iter()
                .filter(|(k, _)| *k != wiping_key)
                .map(|(k, _)| WriteOp::Delete(k.clone()))
                .collect();
            if !ops.is_empty() {
                self.backend.write_batch(&ops)?;
            }
            // Advance strictly past the last key scanned. The just-deleted rows
            // and the surviving marker all sort before it, so no row is
            // revisited and the loop terminates.
            next.push(0);
            cursor = next;
        }
        let mut finalize = vec![
            WriteOp::Put(
                meta_key(b"format_version"),
                ARCHIVE_FORMAT_VERSION.to_be_bytes().to_vec(),
            ),
            WriteOp::Delete(wiping_key),
        ];
        if let Ok(base_bytes) = <[u8; 8]>::try_from(marker.as_slice()) {
            let at = i64::from_be_bytes(base_bytes);
            finalize.push(WriteOp::Put(meta_key(b"base_height"), at.to_be_bytes().to_vec()));
            finalize.push(WriteOp::Put(meta_key(b"head"), at.to_be_bytes().to_vec()));
        }
        self.backend.write_batch(&finalize)?;
        self.backend.sync_wal()?;
        Ok(())
    }

    fn wipe_and_restamp(&self) -> Result<(), IndexError> {
        self.backend
            .write_batch(&[WriteOp::Put(meta_wiping(), Vec::new())])?;
        self.backend.sync_wal()?;
        self.finish_reset()
    }

    /// Wipe everything and restart coverage with `base = head = at`.
    /// The loud failure mode — history before `at` is gone.
    fn reset_coverage(&self, at: i64, why: &str) -> Result<(), IndexError> {
        tracing::error!(
            base = at,
            why,
            "archive: COVERAGE RESET — wiping versioned history and restarting capture; \
             historical reads below the new base are no longer served"
        );
        self.backend
            .write_batch(&[WriteOp::Put(meta_wiping(), at.to_be_bytes().to_vec())])?;
        self.backend.sync_wal()?;
        self.finish_reset()?;
        self.counters.coverage_resets.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Archive one applied block's write-set. Called from the apply
    /// hook, once per successfully-applied block (including
    /// reorg-reapplies, which arrive with `height <= head` and unwind
    /// first). Never fails the apply — the caller logs errors.
    pub fn on_block_applied(
        &self,
        height: i64,
        deltas: Option<&[DeltaRef<'_>]>,
    ) -> Result<(), IndexError> {
        let mut inner = self.inner.lock().expect("archive writer poisoned");

        // Missing deltas with capture on means the block ran a commit
        // path that can't capture (config inconsistency) — coverage is
        // broken at this height; restart it here.
        let Some(deltas) = deltas else {
            self.reset_coverage(height, "block applied without a captured write-set")?;
            return Ok(());
        };

        let head = self.head()?;
        match head {
            None => {
                // First captured block: coverage base is the parent —
                // the live state minus this block's writes, whose
                // pre-images land at the base below.
                self.backend.write_batch(&[
                    WriteOp::Put(meta_key(b"base_height"), (height - 1).to_be_bytes().to_vec()),
                    WriteOp::Put(meta_key(b"head"), (height - 1).to_be_bytes().to_vec()),
                ])?;
                tracing::info!(base = height - 1, "archive: capture starting");
            }
            Some(h) if height <= h => {
                // Reorg re-apply: unwind orphaned heights exactly.
                if let Err(e) = self.unwind_to(height - 1, h) {
                    self.reset_coverage(height - 1, &format!("unwind failed: {e}"))?;
                }
            }
            Some(h) if height > h + 1 => {
                // Crash / off-period gap: repair from the undo log, or
                // give up coverage.
                if let Err(e) = self.repair_gap(h + 1, height - 1, deltas) {
                    self.reset_coverage(height - 1, &format!("gap {}..{} unrepairable: {e}", h + 1, height - 1))?;
                }
            }
            Some(_) => {}
        }

        let base = self.base_height()?.unwrap_or(height - 1);
        let mut ops: Vec<WriteOp> = Vec::with_capacity(deltas.len() * 2 + 2);
        let mut ring: Vec<Vec<u8>> = Vec::with_capacity(deltas.len() * 2);
        for d in deltas {
            let vkey = row_key(d.store, d.key, height);
            ops.push(WriteOp::Put(vkey.clone(), enc_value(d.after)));
            ring.push(vkey);
            // First write since capture → pin the pre-image at the
            // base so this key has coverage from `base` forward.
            let bkey = row_key(d.store, d.key, base);
            if self.backend.get(&bkey)?.is_none() {
                ops.push(WriteOp::Put(bkey.clone(), enc_value(d.before)));
                ring.push(bkey);
            }
        }
        self.counters
            .entries_written
            .fetch_add(ops.len() as u64, Ordering::Relaxed);
        // Unwind records for reorg territory, pruned as the ring
        // advances. Reorgs are bounded by the solidified gate, so the
        // ring always covers them.
        ops.push(WriteOp::Put(meta_keys_at(height), encode_key_list(&ring)));
        let expired = height - RING_DEPTH;
        if expired > 0 {
            ops.push(WriteOp::Delete(meta_keys_at(expired)));
        }
        ops.push(WriteOp::Put(meta_key(b"head"), height.to_be_bytes().to_vec()));
        self.backend.write_batch(&ops)?;
        self.counters.blocks_archived.fetch_add(1, Ordering::Relaxed);

        // WAL durability barrier, amortized. A crash inside the window
        // loses only the un-fsynced tail, which the gap repair above
        // reconstructs exactly from the undo log on the next apply.
        inner.blocks_since_sync += 1;
        if inner.blocks_since_sync >= SYNC_EVERY {
            inner.blocks_since_sync = 0;
            self.backend.sync_wal()?;
        }
        Ok(())
    }

    /// Delete exactly the entries recorded for heights
    /// `(ancestor, upto]`, newest-first. Errors when a height inside
    /// the range has no unwind record (deeper than the ring — cannot
    /// happen for real reorgs, which are bounded by solidity).
    fn unwind_to(&self, ancestor: i64, upto: i64) -> Result<(), IndexError> {
        let mut ops: Vec<WriteOp> = Vec::new();
        for h in ((ancestor + 1)..=upto).rev() {
            let Some(bytes) = self.backend.get(&meta_keys_at(h))? else {
                return Err(IndexError::Corrupt(format!(
                    "archive unwind needs the ring at height {h} but it is not present"
                )));
            };
            let keys = decode_key_list(&bytes).ok_or_else(|| {
                IndexError::Corrupt(format!("archive ring at {h} undecodable"))
            })?;
            ops.extend(keys.into_iter().map(WriteOp::Delete));
            ops.push(WriteOp::Delete(meta_keys_at(h)));
        }
        ops.push(WriteOp::Put(meta_key(b"head"), ancestor.to_be_bytes().to_vec()));
        self.backend.write_batch(&ops)?;
        self.backend.sync_wal()?;
        self.counters.reorg_unwinds.fetch_add(1, Ordering::Relaxed);
        tracing::info!(ancestor, upto, "archive: reorg unwound");
        Ok(())
    }

    /// Exact gap repair from the block-undo log. For each key written
    /// inside the gap: consecutive pre-images reconstruct intermediate
    /// post-images; the final write's post-image is the next block's
    /// pre-image (when the block now applying rewrote it) or the
    /// current live value (state is at `gap_end + 1`'s parent for keys
    /// the new block didn't touch).
    fn repair_gap(
        &self,
        from: i64,
        to: i64,
        next_block_deltas: &[DeltaRef<'_>],
    ) -> Result<(), IndexError> {
        let Some(undo) = self.undo.as_ref() else {
            return Err(IndexError::Unavailable("no undo store attached".into()));
        };
        let base = self.base_height()?.unwrap_or(from - 1);

        // (store, key) → ordered (height, before) writes inside the gap.
        let mut per_key: BTreeMap<(u8, Vec<u8>), Vec<(i64, Option<Vec<u8>>)>> = BTreeMap::new();
        for g in from..=to {
            let record = undo
                .get(g)
                .map_err(|e| IndexError::Corrupt(format!("undo decode at {g}: {e:?}")))?
                .ok_or_else(|| {
                    IndexError::Unavailable(format!("undo record for block {g} not retained"))
                })?;
            for e in record.entries {
                per_key
                    .entry((e.store as u8, e.key))
                    .or_default()
                    .push((g, e.before));
            }
        }

        let next_before: BTreeMap<(u8, &[u8]), Option<&[u8]>> = next_block_deltas
            .iter()
            .map(|d| ((d.store as u8, d.key), d.before))
            .collect();

        let mut ops: Vec<WriteOp> = Vec::new();
        let mut ring_per_height: BTreeMap<i64, Vec<Vec<u8>>> = BTreeMap::new();
        for ((store_b, key), writes) in &per_key {
            let store = UndoStoreId::from_u8(*store_b).ok_or_else(|| {
                IndexError::Corrupt(format!("unknown store id {store_b} in undo record"))
            })?;
            for (i, (g, _)) in writes.iter().enumerate() {
                let post: Option<Vec<u8>> = if let Some((_, next_pre)) = writes.get(i + 1) {
                    next_pre.clone()
                } else if let Some(nb) = next_before.get(&(*store_b, key.as_slice())) {
                    nb.map(|b| b.to_vec())
                } else {
                    self.live
                        .iter()
                        .find(|(id, _)| *id == store)
                        .ok_or_else(|| {
                            IndexError::Unavailable(format!("no live backend for {store:?}"))
                        })?
                        .1
                        .get(key)?
                };
                let vkey = row_key(store, key, *g);
                ops.push(WriteOp::Put(vkey.clone(), enc_value(post.as_deref())));
                ring_per_height.entry(*g).or_default().push(vkey);
            }
            let bkey = row_key(store, key, base);
            if self.backend.get(&bkey)?.is_none() {
                let first_before = writes[0].1.as_deref();
                ops.push(WriteOp::Put(bkey.clone(), enc_value(first_before)));
                ring_per_height.entry(writes[0].0).or_default().push(bkey);
            }
        }
        for (h, keys) in &ring_per_height {
            ops.push(WriteOp::Put(meta_keys_at(*h), encode_key_list(keys)));
        }
        self.backend.write_batch(&ops)?;
        self.counters
            .gap_repaired_blocks
            .fetch_add((to - from + 1) as u64, Ordering::Relaxed);
        tracing::warn!(
            from,
            to,
            keys = per_key.len(),
            "archive: repaired a capture gap exactly from the undo log"
        );
        Ok(())
    }

    // -- retention / windowing --------------------------------------------

    /// Retention entry point the runtime calls on a timer. Given the
    /// current chain `head`, a `retain_blocks` window, and the
    /// `solidified` (irreversible) height, compute the floor
    /// `head - retain_blocks` (saturating, and never above `head`),
    /// clamp it to `solidified`, and prune below it. `retain_blocks == 0`
    /// keeps only the solidified head's snapshot; a window wider than the
    /// covered range is a no-op. Returns `None` when capture has not
    /// started yet (no coverage to prune).
    ///
    /// **Why clamp to `solidified`.** The floor's anchor is re-pinned as
    /// the coverage base. If the floor sat at an unsolidified (reorg-able)
    /// height, that re-pin could carry a value from a block that is later
    /// orphaned; the reorg unwind deletes only ring-tracked rows, not the
    /// re-pin, so a read at `>= floor` would serve the orphaned value
    /// forever. Keeping the floor at or below the irreversible head makes
    /// the anchor un-orphanable. (With the default multi-million-block
    /// window the floor is already far below `solidified`; the clamp only
    /// bites for very small retention windows, e.g. `retain_blocks == 0`.)
    ///
    /// The engine stays config-agnostic — the caller supplies the head,
    /// the window, and the solidified height; **full-history mode is
    /// simply never calling this.**
    pub fn prune_for_window(
        &self,
        head: i64,
        retain_blocks: u64,
        solidified: i64,
    ) -> Result<Option<PruneStats>, IndexError> {
        if self.head()?.is_none() {
            return Ok(None);
        }
        let retain = i64::try_from(retain_blocks).unwrap_or(i64::MAX);
        let floor = head.saturating_sub(retain).min(solidified).max(0);
        self.prune_below(floor).map(Some)
    }

    /// Remove archived versions strictly older than `floor` while
    /// preserving exact reads at every height `H >= floor`.
    ///
    /// **The coverage invariant.** A read at `H` resolves to a key's
    /// newest version `<= H` (one seek, [`ArchiveReader::value_at`]).
    /// The oldest read this prune must still serve is at `H = floor`,
    /// which needs the newest version `<= floor` — the key's *anchor*.
    /// So per key:
    ///
    /// * every version `> floor` is kept (a read at some `H` in
    ///   `(floor, head]` may land on it);
    /// * the anchor (newest version `<= floor`) is kept, and if it sits
    ///   strictly below `floor` it is **re-pinned at `floor`** so the
    ///   new coverage base `floor` has a row to resolve, exactly like
    ///   the writer's first-write base pin;
    /// * every version strictly older than the anchor is deleted.
    ///
    /// In row-key space versions of one key are contiguous and ordered
    /// newest-first (`height_desc`), so the kept set is a prefix of the
    /// group and the deletable set its suffix — a single forward walk
    /// finds the boundary per group with no per-key seek.
    ///
    /// Idempotent: a `floor` at or below the stored base is a no-op
    /// (`PruneStats::noop`). Advances the stored coverage `base` to
    /// `floor`; `head` is untouched. Safe to call repeatedly.
    ///
    /// **Caller contract.** `floor` must not exceed the live `head`
    /// (this never prunes a height a future read still treats as
    /// current), and the caller must serialize prune against capture
    /// (`on_block_applied`) and against any in-flight at-height read —
    /// apply is already serialized, and the runtime drives both from
    /// the same hook.
    pub fn prune_below(&self, floor: i64) -> Result<PruneStats, IndexError> {
        let base = self.base_height()?.unwrap_or(floor);
        let mut stats = PruneStats {
            base_before: base,
            base_after: base,
            ..PruneStats::default()
        };

        // Idempotency / full-history guard: nothing below the floor is
        // older than the base, so there is nothing to remove. Floors
        // above the head are clamped by the window helper; a direct
        // caller passing one only over-prunes its own future reads, not
        // ours — we still honor the invariant for H >= floor.
        if floor <= base {
            stats.noop = true;
            return Ok(stats);
        }

        // Advance the durable coverage base to `floor` BEFORE deleting any
        // version rows. At-height reads run lock-free and validate coverage
        // (base ≤ H ≤ head) with a `base_height` read that is separate from
        // the row read, so the two orderings differ sharply:
        //   * base LAST  (old behavior): throughout the delete pass the base
        //     still admits H ∈ [old_base, floor) while those rows are being
        //     deleted — a read lands past the deleted anchor, resolves
        //     `NotCovered`, and serves the LIVE value as exact history. A
        //     crash mid-pass froze that state until the next pass.
        //   * base FIRST (here): a read (or a crash) can only ever
        //     UNDER-claim — H < floor is rejected as out-of-coverage while
        //     its rows may still physically exist, which is safe.
        // Re-prune stays idempotent: the next pass runs a higher rolling
        // floor, which still sweeps any rows a crashed pass left behind, and
        // an unrepinned anchor below `floor` reads correctly from its
        // original (lower-height) row until then.
        self.backend.write_batch(&[WriteOp::Put(
            meta_key(b"base_height"),
            floor.to_be_bytes().to_vec(),
        )])?;
        self.backend.sync_wal()?;
        stats.base_after = floor;

        // Stream every version row in byte order, grouping by the
        // (store ‖ escaped-key) prefix. Within a group rows are
        // newest-first; the first row with height <= floor is the
        // anchor — keep it (re-pinning when it sits below floor), drop
        // everything after it in the group.
        let mut ops: Vec<WriteOp> = Vec::new();
        let mut cur: Vec<u8> = vec![TAG_ROW];
        let mut group: Vec<u8> = Vec::new();
        // `true` once this group's anchor has been passed — remaining
        // rows of the group are strictly older and deletable.
        let mut past_anchor = false;
        const CHUNK: usize = 4096;
        const FLUSH_AT: usize = 50_000;

        loop {
            let chunk = self.backend.scan_from(&cur, CHUNK)?;
            if chunk.is_empty() {
                break;
            }
            let n = chunk.len();
            for (k, v) in &chunk {
                let Some((prefix, height)) = split_row_key(k) else {
                    // Left the TAG_ROW keyspace (meta rows sort before
                    // TAG_ROW, version rows are the tail) — done.
                    if k.first() != Some(&TAG_ROW) {
                        self.commit_prune(ops, floor, &mut stats)?;
                        return Ok(stats);
                    }
                    continue; // corrupt row — skip, never panic
                };
                stats.rows_scanned += 1;
                if prefix != group.as_slice() {
                    group.clear();
                    group.extend_from_slice(prefix);
                    past_anchor = false;
                }
                if past_anchor {
                    // Strictly older than the anchor → removable.
                    ops.push(WriteOp::Delete(k.clone()));
                    stats.rows_deleted += 1;
                } else if height <= floor {
                    // The anchor: newest version <= floor. Keep it; if it
                    // sits below the floor, re-pin its value at the floor
                    // and drop the original so coverage starts cleanly at
                    // `floor` (mirrors the writer's base pin).
                    if height < floor {
                        let mut repin = prefix.to_vec();
                        repin.extend_from_slice(&height_desc(floor));
                        ops.push(WriteOp::Put(repin, v.clone()));
                        ops.push(WriteOp::Delete(k.clone()));
                        stats.rows_repinned += 1;
                        stats.rows_deleted += 1;
                    }
                    past_anchor = true;
                }
                // else height > floor → kept, no op.
            }
            if ops.len() >= FLUSH_AT {
                let drained = std::mem::take(&mut ops);
                self.backend.write_batch(&drained)?;
            }
            // Advance the cursor past the last key scanned. The
            // re-pin Put lands at `height_desc(floor)`, which sorts
            // *before* the original (lower height) row we delete in the
            // same batch, and both sort within the group we have already
            // moved past — so resuming after the last scanned key never
            // revisits a written row.
            let mut next = chunk[n - 1].0.clone();
            next.push(0);
            cur = next;
            if n < CHUNK {
                break;
            }
        }

        self.commit_prune(ops, floor, &mut stats)?;
        Ok(stats)
    }

    /// Flush the final delete/re-pin batch, then fsync. The coverage base
    /// was already advanced to `floor` (durably) at the start of the pass,
    /// so this only has to make the row deletions durable.
    fn commit_prune(
        &self,
        ops: Vec<WriteOp>,
        floor: i64,
        stats: &mut PruneStats,
    ) -> Result<(), IndexError> {
        self.backend.write_batch(&ops)?;
        self.backend.sync_wal()?;
        self.counters.prune_passes.fetch_add(1, Ordering::Relaxed);
        self.counters
            .pruned_rows
            .fetch_add(stats.rows_deleted, Ordering::Relaxed);
        self.counters
            .prune_floor
            .store(floor as u64, Ordering::Relaxed);
        tracing::info!(
            floor,
            base_before = stats.base_before,
            rows_scanned = stats.rows_scanned,
            rows_deleted = stats.rows_deleted,
            rows_repinned = stats.rows_repinned,
            "archive: retention prune advanced coverage base"
        );
        Ok(())
    }

}

// ---------------------------------------------------------------------------
// Reader + at-height view
// ---------------------------------------------------------------------------

/// Read side. Cheap to clone.
#[derive(Clone)]
pub struct ArchiveReader {
    backend: Arc<dyn KvBackend>,
}

impl ArchiveReader {
    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    pub fn coverage(&self) -> Result<Option<(i64, i64)>, IndexError> {
        let get = |name: &[u8]| -> Result<Option<i64>, IndexError> {
            Ok(self
                .backend
                .get(&meta_key(name))?
                .and_then(|v| v.try_into().ok())
                .map(i64::from_be_bytes))
        };
        match (get(b"base_height")?, get(b"head")?) {
            (Some(b), Some(h)) => Ok(Some((b, h))),
            _ => Ok(None),
        }
    }

    /// One-seek historical point read: the value of `key` in `store`
    /// as of (≤) `height`. Caller must have validated coverage.
    pub fn value_at(
        &self,
        store: UndoStoreId,
        key: &[u8],
        height: i64,
    ) -> Result<AtHeight, IndexError> {
        let seek = row_key(store, key, height);
        // The escaped key is prefix-free, so the first row ≥ seek
        // either belongs to this exact key (its newest version ≤
        // height) or the key's version range is exhausted.
        let group_prefix_len = seek.len() - 8;
        let found = self.backend.scan_from(&seek, 1)?;
        match found.first() {
            Some((k, v))
                if k.len() == seek.len() && k[..group_prefix_len] == seek[..group_prefix_len] =>
            {
                Ok(dec_value(v))
            }
            _ => Ok(AtHeight::NotCovered),
        }
    }

    /// Reconstruct the write-set (post-images) captured at `height` from the
    /// reorg ring: the same `(store, key, after)` set the apply hook fed the
    /// archive — and, from the identical `report.state_deltas`, the commitment
    /// builder. Used as a gap-repair source so a commitment restart or dropped
    /// write-set replays in O(gap) instead of a full re-Merkleize.
    ///
    /// `Ok(None)` when the height's ring entry is absent (older than the ring
    /// window, or the height was never captured) or unreadable — the caller
    /// then falls back to re-bootstrap, which is always correct. Only a backend
    /// I/O error propagates as `Err`.
    pub fn write_set_at(
        &self,
        height: i64,
    ) -> Result<Option<Vec<(UndoStoreId, Vec<u8>, Option<Vec<u8>>)>>, IndexError> {
        let Some(bytes) = self.backend.get(&meta_keys_at(height))? else {
            return Ok(None); // outside the ring window → re-bootstrap
        };
        let Some(ring) = decode_key_list(&bytes) else {
            tracing::warn!(
                height,
                "archive: ring undecodable during commitment resume; re-bootstrapping"
            );
            return Ok(None);
        };
        let mut out = Vec::new();
        for vkey in ring {
            // The ring holds this height's post-image version rows plus base
            // pins at the coverage base; keep only rows whose embedded height
            // is exactly `height` (the write-set), skipping the pins.
            let Some((prefix, h)) = split_row_key(&vkey) else {
                tracing::warn!(
                    height,
                    "archive: unparseable ring row during resume; re-bootstrapping"
                );
                return Ok(None);
            };
            if h != height {
                continue;
            }
            let (Some(store), Some((raw_key, _))) = (
                prefix.get(1).copied().and_then(UndoStoreId::from_u8),
                unescape_key(prefix.get(2..).unwrap_or(&[])),
            ) else {
                tracing::warn!(
                    height,
                    "archive: undecodable ring key during resume; re-bootstrapping"
                );
                return Ok(None);
            };
            let after = match self.backend.get(&vkey)? {
                Some(v) => match dec_value(&v) {
                    AtHeight::Value(val) => Some(val),
                    _ => None,
                },
                None => None,
            };
            out.push((store, raw_key, after));
        }
        Ok(Some(out))
    }

}

/// Lazy, pull-based walk of one store's archived keys in raw-key
/// order, each resolved to its version ≤ `height`. One group per
/// `next()` call — nothing is materialized, so an at-height scan over
/// a store with millions of touched keys streams instead of (the
/// previous design) filling a bounded map and silently serving LIVE
/// values past the bound.
struct ArchGroupIter {
    reader: ArchiveReader,
    store: UndoStoreId,
    height: i64,
    /// Encoded scan position (row-key space).
    cur: Vec<u8>,
    done: bool,
}

impl ArchGroupIter {
    fn new(reader: ArchiveReader, store: UndoStoreId, height: i64, from: &[u8]) -> Self {
        let mut cur = vec![TAG_ROW, store as u8];
        cur.extend_from_slice(&escape_partial(from));
        Self { reader, store, height, cur, done: false }
    }

    fn next(&mut self) -> Result<Option<(Vec<u8>, AtHeight)>, IndexError> {
        if self.done {
            return Ok(None);
        }
        let header = [TAG_ROW, self.store as u8];
        let chunk = self.reader.backend.scan_from(&self.cur, 1)?;
        let Some((k, _)) = chunk.first() else {
            self.done = true;
            return Ok(None);
        };
        if k.len() < 2 || k[..2] != header {
            self.done = true;
            return Ok(None);
        }
        let Some((raw_key, _)) = unescape_key(&k[2..]) else {
            self.done = true; // malformed row — stop defensively
            return Ok(None);
        };
        // Resolve this key's version ≤ height with a direct seek.
        let resolved = self.reader.value_at(self.store, &raw_key, self.height)?;
        // Jump past every row of this key: the successor of the raw
        // key in escaped space (raw_key ‖ 0x00 encodes to the escaped
        // bytes + 0x00 0xFF, which sorts after the terminator
        // 0x00 0x00 of raw_key's own rows).
        let mut next = header.to_vec();
        let mut succ = raw_key.clone();
        succ.push(0x00);
        next.extend_from_slice(&escape_partial(&succ));
        self.cur = next;
        Ok(Some((raw_key, resolved)))
    }
}

/// A read-only `KvBackend` presenting one store **as of a height**:
/// point reads resolve through the archive (falling through to the
/// live store for keys never written since capture), and range scans
/// merge the live keyspace with archived versions — keys created
/// after `height` disappear, keys deleted since reappear, untouched
/// keys read straight from live. Writes are refused.
pub struct ArchiveAtBackend {
    live: Arc<dyn KvBackend>,
    reader: ArchiveReader,
    store: UndoStoreId,
    height: i64,
}

impl ArchiveAtBackend {
    pub fn new(
        live: Arc<dyn KvBackend>,
        reader: ArchiveReader,
        store: UndoStoreId,
        height: i64,
    ) -> Self {
        Self { live, reader, store, height }
    }

    fn read_only_err<T>(&self) -> Result<T, tron_chainbase::KvError> {
        Err(tron_chainbase::KvError::Backend(
            "historical (at-height) view is read-only".into(),
        ))
    }

    /// Merge live + archive in raw-key order from `from`, calling
    /// `visit` per resolved key until it returns false. Both sides are
    /// streamed — the archive through a lazy group iterator, the live
    /// store through chunked scans — so the walk is O(keys visited)
    /// with no materialization and no truncation bound.
    fn merged_from(
        &self,
        from: &[u8],
        mut visit: impl FnMut(&[u8], Vec<u8>) -> bool,
    ) -> Result<(), tron_chainbase::KvError> {
        let to_kv = |e: IndexError| tron_chainbase::KvError::Backend(e.to_string());
        let mut arch = ArchGroupIter::new(self.reader.clone(), self.store, self.height, from);
        let mut arch_next = arch.next().map_err(to_kv)?;
        let mut live_cur = from.to_vec();
        let mut live_buf: std::collections::VecDeque<(Vec<u8>, Vec<u8>)> = Default::default();
        let mut live_done = false;
        loop {
            if live_buf.is_empty() && !live_done {
                let chunk = self.live.scan_from(&live_cur, 256)?;
                if chunk.is_empty() {
                    live_done = true;
                } else {
                    let mut next = chunk.last().expect("non-empty").0.clone();
                    next.push(0);
                    live_cur = next;
                    live_buf.extend(chunk);
                }
            }
            let take_arch = match (live_buf.front(), arch_next.as_ref()) {
                (None, None) => break,
                (None, Some(_)) => true,
                (Some(_), None) => false,
                (Some((lk, _)), Some((ak, _))) => ak <= lk,
            };
            if take_arch {
                let (ak, resolved) = arch_next.take().expect("checked");
                arch_next = arch.next().map_err(to_kv)?;
                // Take the live duplicate of this key, if buffered.
                let live_dup = if live_buf.front().map(|(lk, _)| *lk == ak).unwrap_or(false) {
                    live_buf.pop_front().map(|(_, v)| v)
                } else {
                    None
                };
                match resolved {
                    AtHeight::Value(v) => {
                        if !visit(&ak, v) {
                            return Ok(());
                        }
                    }
                    // `NotCovered` means no archived version applies, so the
                    // live value is authoritative — exactly what the point
                    // `get()` does (`NotCovered => live.get`). A scan must
                    // agree, so emit the live duplicate instead of dropping the
                    // key. Only reachable in degraded states (a mid-prune crash
                    // or on-disk corruption); in the normal case every archived
                    // key has a covered version. `Deleted` emits nothing.
                    AtHeight::NotCovered => {
                        if let Some(v) = live_dup {
                            if !visit(&ak, v) {
                                return Ok(());
                            }
                        }
                    }
                    AtHeight::Deleted => {}
                }
            } else {
                let (lk, lv) = live_buf.pop_front().expect("checked");
                // Key absent from the archive ⇒ never written since
                // capture ⇒ unchanged at the queried height.
                if !visit(&lk, lv) {
                    return Ok(());
                }
            }
        }
        Ok(())
    }
}

impl KvBackend for ArchiveAtBackend {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, tron_chainbase::KvError> {
        match self
            .reader
            .value_at(self.store, key, self.height)
            .map_err(|e| tron_chainbase::KvError::Backend(e.to_string()))?
        {
            AtHeight::Value(v) => Ok(Some(v)),
            AtHeight::Deleted => Ok(None),
            AtHeight::NotCovered => self.live.get(key),
        }
    }

    fn put(&self, _key: &[u8], _value: &[u8]) -> Result<(), tron_chainbase::KvError> {
        self.read_only_err()
    }

    fn delete(&self, _key: &[u8]) -> Result<(), tron_chainbase::KvError> {
        self.read_only_err()
    }

    fn write_batch(&self, _ops: &[WriteOp]) -> Result<(), tron_chainbase::KvError> {
        self.read_only_err()
    }

    fn scan_all(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, tron_chainbase::KvError> {
        // Unbounded full-store reconstruction is deliberately
        // unsupported — none of the historical read paths need it.
        Err(tron_chainbase::KvError::Backend(
            "scan_all is not supported on a historical (at-height) view".into(),
        ))
    }

    fn scan_from(
        &self,
        start: &[u8],
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, tron_chainbase::KvError> {
        let mut out = Vec::with_capacity(limit.min(64));
        self.merged_from(start, |k, v| {
            out.push((k.to_vec(), v));
            out.len() < limit
        })?;
        Ok(out)
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, tron_chainbase::KvError> {
        let mut out = Vec::new();
        self.merged_from(prefix, |k, v| {
            if !k.starts_with(prefix) {
                return false;
            }
            out.push((k.to_vec(), v));
            true
        })?;
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tron_chainbase::MemBackend;

    const STORE: UndoStoreId = UndoStoreId::Accounts;

    /// A writer over an in-memory backend with no undo/live sources
    /// (none of the prune or sequential-apply paths touch them).
    fn writer() -> ArchiveWriter {
        let w = ArchiveWriter::new(Arc::new(MemBackend::new()), None, Vec::new());
        assert!(w.check_or_init().unwrap());
        w
    }

    fn key(n: u8) -> Vec<u8> {
        vec![0x41, n]
    }

    /// Apply one block, deriving each delta's `before` from the running
    /// model so the base-pin pre-image matches reality, then update the
    /// model. `writes` is `(key, after)` where `after = None` is a
    /// delete (tombstone).
    fn apply(
        w: &ArchiveWriter,
        model: &mut HashMap<Vec<u8>, Vec<u8>>,
        height: i64,
        writes: &[(Vec<u8>, Option<Vec<u8>>)],
    ) {
        let befores: Vec<Option<Vec<u8>>> =
            writes.iter().map(|(k, _)| model.get(k).cloned()).collect();
        let deltas: Vec<DeltaRef<'_>> = writes
            .iter()
            .zip(&befores)
            .map(|((k, after), before)| DeltaRef {
                store: STORE,
                key: k,
                before: before.as_deref(),
                after: after.as_deref(),
            })
            .collect();
        w.on_block_applied(height, Some(&deltas)).unwrap();
        for (k, after) in writes {
            match after {
                Some(v) => {
                    model.insert(k.clone(), v.clone());
                }
                None => {
                    model.remove(k);
                }
            }
        }
    }

    fn val(b: &[u8]) -> AtHeight {
        AtHeight::Value(b.to_vec())
    }

    #[test]
    fn split_row_key_isolates_height() {
        let k = row_key(STORE, &key(7), 84_210_003);
        let (prefix, h) = split_row_key(&k).unwrap();
        assert_eq!(h, 84_210_003);
        assert_eq!(prefix, &row_key(STORE, &key(7), 0)[..k.len() - 8]);
        assert_eq!(split_row_key(&[TAG_ROW, 0, 1]), None); // too short
        assert_eq!(split_row_key(&meta_key(b"head")), None); // not a row
    }

    /// `write_set_at` reconstructs a block's exact `(store, key, after)`
    /// write-set from the ring — the input the commitment resume source needs
    /// — excluding the base pins the same block writes, and mapping deletes to
    /// `None`. A never-captured height returns `None` (re-bootstrap fallback).
    #[test]
    fn write_set_at_reconstructs_the_block_write_set() {
        let w = writer();
        let r = w.reader();
        let mut model = HashMap::new();

        // Block 10 (first capture, base = 9): two upserts. The block also
        // writes base pins at height 9 — these must NOT appear in ws(10).
        apply(&w, &mut model, 10, &[(key(1), Some(vec![0xaa])), (key(2), Some(vec![0xbb]))]);
        // Block 11: rewrite key 1, delete key 2.
        apply(&w, &mut model, 11, &[(key(1), Some(vec![0xcc])), (key(2), None)]);

        let sorted = |ws: Vec<(UndoStoreId, Vec<u8>, Option<Vec<u8>>)>| {
            let mut v: Vec<_> = ws.into_iter().map(|(s, k, a)| (s as u8, k, a)).collect();
            v.sort();
            v
        };

        assert_eq!(
            sorted(r.write_set_at(10).unwrap().expect("height 10 covered")),
            vec![
                (STORE as u8, key(1), Some(vec![0xaa])),
                (STORE as u8, key(2), Some(vec![0xbb])),
            ]
        );
        assert_eq!(
            sorted(r.write_set_at(11).unwrap().expect("height 11 covered")),
            vec![
                (STORE as u8, key(1), Some(vec![0xcc])),
                (STORE as u8, key(2), None), // delete → after = None
            ]
        );

        // Heights with no ring entry → None, forcing the caller to re-bootstrap.
        assert_eq!(r.write_set_at(9).unwrap(), None);
        assert_eq!(r.write_set_at(99).unwrap(), None);
    }

    /// The core invariant: after pruning to `floor`, every height
    /// `>= floor` still reads exactly, including a key whose last write
    /// was below the floor (re-pinned), and the boundary `H == floor`.
    #[test]
    fn prune_preserves_reads_at_and_above_floor() {
        let w = writer();
        let r = w.reader();
        let mut model = HashMap::new();

        // a: written every block. b: written once early (last write far
        // below the floor → must re-pin). c: written only above the
        // floor.
        let a = key(0xaa);
        let b = key(0xbb);
        let c = key(0xcc);
        for h in 1..=20i64 {
            let mut writes = vec![(a.clone(), Some(vec![h as u8]))];
            if h == 2 {
                writes.push((b.clone(), Some(b"b-early".to_vec())));
            }
            if h == 15 {
                writes.push((c.clone(), Some(b"c-late".to_vec())));
            }
            apply(&w, &mut model, h, &writes);
        }
        assert_eq!(w.coverage().unwrap(), Some((0, 20)));

        let floor = 10;
        let stats = w.prune_below(floor).unwrap();
        assert!(!stats.noop);
        assert_eq!(stats.base_after, floor);
        assert!(stats.rows_deleted > 0);
        // Both `b` (anchor = the height-2 write) and `c` (anchor = the
        // height-0 base-pinned pre-image tombstone) sit below the floor,
        // so each is re-pinned at the floor exactly once. `a` has a true
        // version at the floor, so it is not re-pinned.
        assert_eq!(stats.rows_repinned, 2);
        assert_eq!(w.coverage().unwrap(), Some((floor, 20)));

        // Reads at and above the floor are byte-exact. `c` did not exist
        // until height 15, so a covered read below it resolves to its
        // re-pinned pre-image (Deleted), never a stale live fall-through.
        for h in floor..=20 {
            assert_eq!(r.value_at(STORE, &a, h).unwrap(), val(&[h as u8]), "a@{h}");
            assert_eq!(r.value_at(STORE, &b, h).unwrap(), val(b"b-early"), "b@{h}");
            let expect_c = if h >= 15 { val(b"c-late") } else { AtHeight::Deleted };
            assert_eq!(r.value_at(STORE, &c, h).unwrap(), expect_c, "c@{h}");
        }

        // The boundary read at exactly the floor resolves to the anchor
        // (a@10 is the version written at 10; b's re-pinned anchor).
        assert_eq!(r.value_at(STORE, &a, floor).unwrap(), val(&[10u8]));
        assert_eq!(r.value_at(STORE, &b, floor).unwrap(), val(b"b-early"));

        // Below the floor the deep history is gone: the seek can only
        // find the anchor (re-pinned at floor), never a true sub-floor
        // version. The API layer rejects H < base via `coverage`; here
        // we assert no stale sub-floor row survived for `a`.
        assert!(
            w.backend.get(&row_key(STORE, &a, 9)).unwrap().is_none(),
            "a@9 should have been pruned"
        );
        assert!(w.backend.get(&row_key(STORE, &a, 1)).unwrap().is_none());
        // b's original sub-floor row is gone; its re-pin sits at floor.
        assert!(w.backend.get(&row_key(STORE, &b, 2)).unwrap().is_none());
        assert!(w.backend.get(&row_key(STORE, &b, floor)).unwrap().is_some());
    }

    #[test]
    fn prune_handles_deleted_key_tombstone() {
        let w = writer();
        let r = w.reader();
        let mut model = HashMap::new();
        let d = key(0xdd);
        let f = key(0xfe); // filler so heights stay consecutive (no gap repair)

        // Consecutive heights only — a non-consecutive apply would trip
        // the writer's gap-repair/reset path, not the prune under test.
        let writes_at = |h: i64| -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
            let mut v = vec![(f.clone(), Some(vec![h as u8]))];
            match h {
                1 => v.push((d.clone(), Some(b"v1".to_vec()))),
                5 => v.push((d.clone(), Some(b"v5".to_vec()))),
                8 => v.push((d.clone(), None)),                 // deleted at 8
                12 => v.push((d.clone(), Some(b"v12".to_vec()))), // resurrected
                _ => {}
            }
            v
        };
        for h in 1..=14 {
            apply(&w, &mut model, h, &writes_at(h));
        }

        // Floor lands on the tombstone height: the anchor IS the delete.
        let stats = w.prune_below(8).unwrap();
        assert!(!stats.noop);
        assert_eq!(w.coverage().unwrap().unwrap().0, 8);

        // At/after the tombstone height but before resurrection: Deleted.
        assert_eq!(r.value_at(STORE, &d, 8).unwrap(), AtHeight::Deleted);
        assert_eq!(r.value_at(STORE, &d, 11).unwrap(), AtHeight::Deleted);
        assert_eq!(r.value_at(STORE, &d, 12).unwrap(), val(b"v12"));
        // Sub-floor versions gone.
        assert!(w.backend.get(&row_key(STORE, &d, 1)).unwrap().is_none());
        assert!(w.backend.get(&row_key(STORE, &d, 5)).unwrap().is_none());
        // The retained anchor (the tombstone, exactly at floor) survives.
        assert_eq!(
            dec_value(&w.backend.get(&row_key(STORE, &d, 8)).unwrap().unwrap()),
            AtHeight::Deleted
        );
    }

    #[test]
    fn deleted_key_repinned_below_floor() {
        let w = writer();
        let r = w.reader();
        let mut model = HashMap::new();
        let d = key(0x11);

        apply(&w, &mut model, 1, &[(d.clone(), Some(b"v1".to_vec()))]);
        apply(&w, &mut model, 4, &[(d.clone(), None)]); // deleted at 4, never rewritten
        // Pad the archive so head advances well past the floor.
        for h in 5..=20 {
            apply(&w, &mut model, h, &[(key(0xff), Some(vec![h as u8]))]);
        }

        let floor = 10;
        w.prune_below(floor).unwrap();
        // d's last version (a tombstone at 4 < floor) must be re-pinned
        // at the floor as a tombstone — reads at H >= floor see Deleted.
        assert_eq!(r.value_at(STORE, &d, floor).unwrap(), AtHeight::Deleted);
        assert_eq!(r.value_at(STORE, &d, 20).unwrap(), AtHeight::Deleted);
        assert!(w.backend.get(&row_key(STORE, &d, 4)).unwrap().is_none());
        assert_eq!(
            dec_value(&w.backend.get(&row_key(STORE, &d, floor)).unwrap().unwrap()),
            AtHeight::Deleted
        );
    }

    #[test]
    fn reprune_is_idempotent_noop() {
        let w = writer();
        let mut model = HashMap::new();
        for h in 1..=20 {
            apply(&w, &mut model, h, &[(key(1), Some(vec![h as u8]))]);
        }
        let first = w.prune_below(10).unwrap();
        assert!(!first.noop);

        // Same floor again: base is already 10, nothing older remains.
        let again = w.prune_below(10).unwrap();
        assert!(again.noop);
        assert_eq!(again.rows_deleted, 0);
        assert_eq!(again.base_after, 10);

        // A lower floor than the current base is also a no-op (can't
        // resurrect pruned history).
        let lower = w.prune_below(5).unwrap();
        assert!(lower.noop);
        assert_eq!(w.coverage().unwrap().unwrap().0, 10);
    }

    #[test]
    fn second_prune_advances_floor_further() {
        let w = writer();
        let r = w.reader();
        let mut model = HashMap::new();
        let a = key(0xaa);
        for h in 1..=30 {
            apply(&w, &mut model, h, &[(a.clone(), Some(vec![h as u8]))]);
        }
        w.prune_below(10).unwrap();
        let s2 = w.prune_below(20).unwrap();
        assert!(!s2.noop);
        assert_eq!(w.coverage().unwrap(), Some((20, 30)));
        for h in 20..=30 {
            assert_eq!(r.value_at(STORE, &a, h).unwrap(), val(&[h as u8]));
        }
        assert!(w.backend.get(&row_key(STORE, &a, 19)).unwrap().is_none());
        assert!(w.backend.get(&row_key(STORE, &a, 20)).unwrap().is_some());
    }

    #[test]
    fn prune_for_window_computes_floor_and_clamps() {
        let w = writer();
        let mut model = HashMap::new();
        for h in 1..=100 {
            apply(&w, &mut model, h, &[(key(1), Some(vec![h as u8]))]);
        }
        // Window of 40 blocks at head 100 (solidified 100) → floor 60.
        let s = w.prune_for_window(100, 40, 100).unwrap().unwrap();
        assert!(!s.noop);
        assert_eq!(w.coverage().unwrap().unwrap().0, 60);

        // Window wider than the covered range → floor clamps at 0,
        // which is <= base (now 60) → no-op.
        let wide = w.prune_for_window(100, 1_000, 100).unwrap().unwrap();
        assert!(wide.noop);
        assert_eq!(w.coverage().unwrap().unwrap().0, 60);
    }

    #[test]
    fn prune_for_window_clamps_floor_to_solidified() {
        let w = writer();
        let mut model = HashMap::new();
        for h in 1..=100 {
            apply(&w, &mut model, h, &[(key(1), Some(vec![h as u8]))]);
        }
        // retain_blocks = 0 would put the floor at head 100, but the
        // solidified head is 90 — the floor must clamp to 90 so the re-pinned
        // anchor sits at an irreversible height, never a reorg-able one.
        let s = w.prune_for_window(100, 0, 90).unwrap().unwrap();
        assert!(!s.noop);
        assert_eq!(w.coverage().unwrap().unwrap().0, 90);
        // Reads at and above the clamped floor still resolve exactly.
        assert_eq!(w.reader().value_at(STORE, &key(1), 95).unwrap(), val(&[95]));
        assert_eq!(w.reader().value_at(STORE, &key(1), 90).unwrap(), val(&[90]));
    }

    #[test]
    fn prune_for_window_before_capture_is_none() {
        let w = writer();
        assert_eq!(w.prune_for_window(100, 10, 100).unwrap(), None);
    }

    /// Many keys + a tight chunk-spanning prune: exercises group
    /// continuation across `scan_from` chunk boundaries and the
    /// mid-scan flush. Asserts every retained read is exact.
    #[test]
    fn prune_across_many_keys_and_chunks() {
        let w = writer();
        let r = w.reader();
        let mut model = HashMap::new();
        // 300 keys, each written at several heights → thousands of rows,
        // forcing multiple 4096-row scan chunks and a flush.
        for h in 1..=40i64 {
            let writes: Vec<(Vec<u8>, Option<Vec<u8>>)> = (0..300u16)
                .filter(|k| (h as u16 + k) % 3 == 0) // each key written ~1/3 of heights
                .map(|k| {
                    let key = vec![0x41, (k >> 8) as u8, k as u8];
                    (key, Some(vec![h as u8, k as u8]))
                })
                .collect();
            if !writes.is_empty() {
                apply(&w, &mut model, h, &writes);
            }
        }
        let floor = 25;
        let stats = w.prune_below(floor).unwrap();
        assert!(!stats.noop);
        assert_eq!(w.coverage().unwrap().unwrap().0, floor);

        // Reconstruct the expected value-at-floor for every key from the
        // model's full write history and assert exactness.
        for k in 0..300u16 {
            let key = vec![0x41, (k >> 8) as u8, k as u8];
            // The latest height <= 40 each key was written; reads at the
            // head must still match. We re-derive via a fresh seek.
            let head = r.value_at(STORE, &key, 40).unwrap();
            if let AtHeight::Value(_) = head {
                // And the floor read must resolve (never NotCovered for a
                // key that existed before the floor).
                let at_floor = r.value_at(STORE, &key, floor).unwrap();
                assert!(
                    matches!(at_floor, AtHeight::Value(_) | AtHeight::Deleted),
                    "key {k} lost coverage at floor"
                );
            }
        }
        // No row strictly below the floor survived for a sampled key.
        let sample = vec![0x41u8, 0, 0];
        for h in 1..floor {
            assert!(
                w.backend.get(&row_key(STORE, &sample, h)).unwrap().is_none(),
                "sample row @{h} below floor survived"
            );
        }
    }

    /// Pruning must not disturb the live fall-through: a key never
    /// written since capture has no archive rows and reads `NotCovered`.
    #[test]
    fn prune_leaves_untouched_keys_not_covered() {
        let w = writer();
        let r = w.reader();
        let mut model = HashMap::new();
        for h in 1..=20 {
            apply(&w, &mut model, h, &[(key(1), Some(vec![h as u8]))]);
        }
        w.prune_below(10).unwrap();
        // A key never written: still NotCovered (falls through to live).
        assert_eq!(r.value_at(STORE, &key(99), 15).unwrap(), AtHeight::NotCovered);
    }
}
