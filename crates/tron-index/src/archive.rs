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
use crate::keys::{decode_key_list, encode_key_list, height_desc};

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
        let all = self.backend.scan_all()?;
        let ops: Vec<WriteOp> = all
            .into_iter()
            .filter(|(k, _)| *k != wiping_key)
            .map(|(k, _)| WriteOp::Delete(k))
            .collect();
        for chunk in ops.chunks(100_000) {
            self.backend.write_batch(chunk)?;
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
                // Drop the live duplicate of this key, if buffered.
                if live_buf.front().map(|(lk, _)| *lk == ak).unwrap_or(false) {
                    live_buf.pop_front();
                }
                match resolved {
                    AtHeight::Value(v) => {
                        if !visit(&ak, v) {
                            return Ok(());
                        }
                    }
                    AtHeight::Deleted | AtHeight::NotCovered => {}
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
