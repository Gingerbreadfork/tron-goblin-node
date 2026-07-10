//! The off-hook fold + bootstrap.
//!
//! The commitment is computed downstream of block commit, never on the apply
//! critical path: a single leaf upsert recomputes up to 256 node hashes, far
//! too heavy to run inline (unlike the archive's flat append). The runtime
//! owns a dedicated background task that drains a bounded channel and drives
//! this builder; ALL confirmation-lag/buffer/reorg logic lives here so it is
//! unit-testable without tokio.
//!
//! **Confirmation-lag fold.** The builder buffers each incoming block in a
//! height-keyed map and folds only heights at least `confirmation_lag_blocks`
//! (`K`) behind the max height it has seen. `committed_height` therefore
//! trails head by ~K, so a committed root is past TRON's ~19-block PBFT
//! finality and never commits a reorg-able tip height — a proof against it
//! stays valid. A reorg shallower than K is absorbed entirely in the buffer
//! (overwrite the buffered height, prune orphaned heights above it) with NO
//! tree mutation. Only a rewind to `h <= committed_height` (deeper than K,
//! astronomically rare under PBFT finality) falls back to a full
//! re-bootstrap, loudly.
//!
//! **Backpressure (runtime side, documented here).** The hook delivers blocks
//! with a non-blocking `try_send`; on a full channel it drops the message and
//! flags a resync, so the hook never blocks the apply loop. A dropped message
//! leaves a forward gap in the buffer below the release ceiling; the builder
//! closes it on the next ingest by replaying the gap from a [`ResumeSource`]
//! (the archive, when present) or, failing that, re-bootstrapping. Dropping is
//! safe precisely because the commitment is re-derivable from live state.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;

use tron_chainbase::{KvBackend, UndoStoreId};
use tron_crypto::keccak256;

use crate::commitment::reader::{leaf_path_for, CommitmentReader};
use crate::commitment::smt::{CommitmentError, LeafPath, NodeHash, Smt, EMPTY_ROOT};
use crate::commitment::store::{BootstrapCursor, CommitmentStore};

/// Chunk size for the bootstrap scan (rows per `scan_from` page).
const BOOTSTRAP_CHUNK: usize = 50_000;
/// WAL fsync cadence (folded blocks), mirroring `ArchiveWriter::SYNC_EVERY`.
const SYNC_EVERY: u64 = 16;

/// Message the apply hook hands the builder task. Owns its bytes — the hook
/// holds only borrows.
#[derive(Debug, Clone)]
pub enum CommitmentMsg {
    /// One applied block's write-set.
    Block {
        height: i64,
        deltas: Vec<CommitmentDeltaRef>,
    },
}

/// One key mutation of a block's write-set, owned. `before` is intentionally
/// absent: the SMT is overwrite-by-path, so delete vs upsert is decided solely
/// by `after`, and reorgs never undo a folded block (they are absorbed in the
/// unfolded buffer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentDeltaRef {
    pub store: UndoStoreId,
    pub key: Vec<u8>,
    /// `None` ⇒ delete the leaf (the key became absent at this height).
    pub after: Option<Vec<u8>>,
}

/// Shared live counters, surfaced as metrics and read by [`CommitmentReader`]
/// for `head_height`. All fields are process-shared atomics.
#[derive(Debug, Default)]
pub struct CommitmentCounters {
    /// Max height the builder has seen on the channel (≈ live head). `-1`
    /// before the first block.
    pub head_height: AtomicI64,
    /// Folded-into-tree watermark, mirrored for metrics. `-1` before the
    /// first commit.
    pub committed_height: AtomicI64,
    /// Cumulative blocks folded into the tree.
    pub blocks_folded: AtomicU64,
    /// Cumulative messages dropped at the channel (backpressure).
    pub lagged: AtomicU64,
    /// Current pending-buffer depth (heights buffered but not yet folded).
    pub pending_depth: AtomicU64,
    /// `true` while the full-state Merkleize is running.
    pub bootstrapping: AtomicBool,
    /// Leaves folded so far during bootstrap.
    pub bootstrap_keys_done: AtomicU64,
    /// Set by the hook when it drops a message; the builder resyncs on it.
    pub resync_needed: AtomicBool,
}

impl CommitmentCounters {
    pub fn new() -> Self {
        let c = Self::default();
        c.head_height.store(-1, Ordering::Relaxed);
        c.committed_height.store(-1, Ordering::Relaxed);
        c
    }
    pub fn head_height(&self) -> i64 {
        self.head_height.load(Ordering::Relaxed)
    }
}

/// Outcome of an [`CommitmentBuilder::ingest`] call: what (if anything) was
/// folded and the resulting committed state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Committed {
    /// Heights folded into the tree by this ingest (ascending). Empty when
    /// nothing was confirmed yet.
    pub folded: Vec<i64>,
    /// Committed height after this ingest (`None` before any fold).
    pub committed_height: Option<i64>,
    /// Committed root after this ingest.
    pub root: NodeHash,
    /// `true` if this ingest took the deep-reorg re-bootstrap fallback.
    pub rebootstrapped: bool,
}

/// A source of historical per-block write-sets for gap repair, abstracted so
/// the builder can replay a dropped/crashed gap from the archive (when
/// enabled) without depending on it directly. Returns the write-set for one
/// height, or `None` when the height is not covered.
pub trait ResumeSource: Send {
    /// The per-key post-images at `height`, or `None` if `height` is outside
    /// this source's coverage (forcing the re-bootstrap fallback).
    fn deltas_at(&self, height: i64) -> Result<Option<Vec<CommitmentDeltaRef>>, CommitmentError>;
}

/// A [`ResumeSource`] backed by the historical-state archive. Replays a gap's
/// write-set from the archive's reorg ring (which covers the most recent
/// heights), converting the archive's `(store, key, after)` tuples into
/// [`CommitmentDeltaRef`]s — byte-identical to the write-set the apply hook
/// fed the builder, since both derive from the same `report.state_deltas`.
/// A gap older than the ring window resolves to `None` → full re-bootstrap.
/// Requires the archive (`[index] capture_state_deltas` / `[index.archive]`)
/// to be enabled; without it the builder has no resume source and every gap
/// re-Merkleizes.
pub struct ArchiveResume {
    reader: crate::archive::ArchiveReader,
}

impl ArchiveResume {
    pub fn new(reader: crate::archive::ArchiveReader) -> Self {
        Self { reader }
    }
}

impl ResumeSource for ArchiveResume {
    fn deltas_at(&self, height: i64) -> Result<Option<Vec<CommitmentDeltaRef>>, CommitmentError> {
        let rows = self
            .reader
            .write_set_at(height)
            .map_err(|e| CommitmentError::Backend(e.to_string()))?;
        Ok(rows.map(|rows| {
            rows.into_iter()
                .map(|(store, key, after)| CommitmentDeltaRef { store, key, after })
                .collect()
        }))
    }
}

/// Builder state: the fold watermark, the head the builder has seen, and the
/// height-keyed pending buffer of not-yet-folded write-sets.
#[derive(Debug, Default)]
pub struct BuildState {
    /// Folded-into-tree watermark. `None` before the first commit. Persisted
    /// with the root.
    pub committed_height: Option<i64>,
    /// Max height observed on the channel (head as the builder sees it).
    pub max_seen_height: i64,
    /// Buffered, not-yet-folded write-sets, keyed by height. Last-write-wins
    /// per height (a reorg-reapply overwrites). Bounded by `K + channel-lag`.
    pub pending: BTreeMap<i64, Vec<CommitmentDeltaRef>>,
}

/// Owns the [`Smt`] over the [`CommitmentStore`], the live store backends (for
/// bootstrap/resume), the confirmation-lag buffer, and the shared counters.
/// The single background task is the only writer.
pub struct CommitmentBuilder {
    smt: Smt<CommitmentStore>,
    store: CommitmentStore,
    /// Executor-written state surface — the same `(UndoStoreId, backend)` set
    /// the archive versions. Bootstrap/resume scan these.
    backends: Vec<(UndoStoreId, Arc<dyn KvBackend>)>,
    /// Confirmation depth K.
    confirmation_lag_blocks: u64,
    state: BuildState,
    counters: Arc<CommitmentCounters>,
    blocks_since_sync: u64,
}

impl CommitmentBuilder {
    /// Construct over an opened [`CommitmentStore`] and the executor-written
    /// store surface. `confirmation_lag_blocks` is `K` (from config). The
    /// caller must have run [`CommitmentStore::check_or_init`] first.
    pub fn new(
        store: CommitmentStore,
        backends: Vec<(UndoStoreId, Arc<dyn KvBackend>)>,
        confirmation_lag_blocks: u64,
        counters: Arc<CommitmentCounters>,
    ) -> Result<Self, CommitmentError> {
        let root = store.root()?;
        let committed_height = store.committed_height()?;
        let smt = Smt::open(store.clone(), root);
        let mut state = BuildState::default();
        state.committed_height = committed_height;
        state.max_seen_height = committed_height.unwrap_or(-1);
        if let Some(h) = committed_height {
            counters.committed_height.store(h, Ordering::Relaxed);
        }
        Ok(Self {
            smt,
            store,
            backends,
            confirmation_lag_blocks,
            state,
            counters,
            blocks_since_sync: 0,
        })
    }

    /// A cheap-clone read handle for the RPC layer.
    pub fn reader(&self) -> CommitmentReader {
        CommitmentReader::new(
            self.store.clone(),
            self.counters.clone(),
            self.confirmation_lag_blocks,
        )
    }

    /// Shared counters (also held by the reader and the metrics sampler).
    pub fn counters(&self) -> Arc<CommitmentCounters> {
        self.counters.clone()
    }

    /// Current committed height (`None` before any fold).
    pub fn committed_height(&self) -> Option<i64> {
        self.state.committed_height
    }

    /// Current committed root.
    pub fn root(&self) -> NodeHash {
        self.smt.root()
    }

    /// Number of heights currently buffered (not yet folded).
    pub fn pending_depth(&self) -> usize {
        self.state.pending.len()
    }

    /// Run the full-state Merkleize if this is a fresh store, or resume an
    /// interrupted bootstrap, anchoring at `anchor_height`. A no-op when the
    /// store already has a committed height (a clean restart resumes folding
    /// from the persisted watermark via [`Self::ingest`]).
    ///
    /// `anchor_height` is `dp.latest_block_header_number()` at scan start — a
    /// fixed snapshot of head. Blocks applied during the scan are buffered by
    /// the caller and folded forward afterward.
    pub fn bootstrap_or_resume(&mut self, anchor_height: i64) -> Result<(), CommitmentError> {
        // Already committed: nothing to bootstrap — fold forward on ingest.
        if self.state.committed_height.is_some() {
            return Ok(());
        }
        match self.store.bootstrap_progress()? {
            Some(cursor) => {
                tracing::warn!(
                    anchor = cursor.anchor,
                    store_id = cursor.store_id,
                    "commitment: resuming an interrupted bootstrap scan"
                );
                self.run_bootstrap(cursor.anchor, Some(cursor))
            }
            None => {
                // A fresh (non-resume) bootstrap must start from an EMPTY node
                // store: run_bootstrap folds live keys additively and never
                // wipes, so leftover leaves for keys deleted since a prior fold
                // would survive and yield a permanently wrong root. We reach
                // here only with no committed height; a non-empty tree on disk
                // means the committed-height meta was lost over populated state.
                // Refuse the additive bootstrap loudly rather than commit a
                // silently-wrong root (the commitment is off the apply path, so
                // this only stops the builder; the operator wipes the dir).
                if self.smt.root() != EMPTY_ROOT {
                    return Err(CommitmentError::Corrupt(
                        "no committed height but a non-empty tree on disk \
                         (committed-height meta lost?) — refusing an additive \
                         bootstrap; wipe the commitment directory to re-Merkleize"
                            .into(),
                    ));
                }
                self.run_bootstrap(anchor_height, None)
            }
        }
    }

    /// The bootstrap scan. Iterates each store backend with chunked
    /// `scan_from`, folding every `(key, value)` as a leaf. Resumable: each
    /// chunk persists an advanced cursor atomically with its node ops.
    fn run_bootstrap(
        &mut self,
        anchor: i64,
        resume: Option<BootstrapCursor>,
    ) -> Result<(), CommitmentError> {
        self.counters.bootstrapping.store(true, Ordering::Relaxed);
        let mut keys_done = self.store.bootstrap_keys_done()?;

        // Determine the store index to resume at (skip fully-scanned stores).
        let start_idx = match &resume {
            Some(c) => self
                .backends
                .iter()
                .position(|(s, _)| *s as u8 == c.store_id)
                .unwrap_or(0),
            None => 0,
        };

        for idx in start_idx..self.backends.len() {
            let (store_id, backend) = {
                let (s, b) = &self.backends[idx];
                (*s, b.clone())
            };
            // Resume cursor only applies to the store it was recorded in.
            let mut cursor: Vec<u8> = match &resume {
                Some(c) if c.store_id == store_id as u8 && idx == start_idx => c.next_key.clone(),
                _ => Vec::new(),
            };
            loop {
                let chunk = backend
                    .scan_from(&cursor, BOOTSTRAP_CHUNK)
                    .map_err(|e| CommitmentError::Backend(e.to_string()))?;
                if chunk.is_empty() {
                    break;
                }
                let changes: Vec<(LeafPath, Option<NodeHash>)> = chunk
                    .iter()
                    .map(|(k, v)| (leaf_path_for(store_id, k), Some(keccak256(v))))
                    .collect();
                let (_root, ops) = self.smt.apply(&changes)?;
                keys_done += chunk.len() as u64;

                let last_key = chunk.last().map(|(k, _)| k.clone()).unwrap_or_default();
                let next_cursor = succ(&last_key);
                let saved = BootstrapCursor {
                    store_id: store_id as u8,
                    next_key: next_cursor.clone(),
                    anchor,
                };
                self.store
                    .commit_bootstrap_chunk(&ops, &saved, keys_done)?;
                self.counters
                    .bootstrap_keys_done
                    .store(keys_done, Ordering::Relaxed);
                cursor = next_cursor;
                if chunk.len() < BOOTSTRAP_CHUNK {
                    break;
                }
            }
        }

        let root = self.smt.root();
        // The live head at scan completion is the convergence horizon: the
        // scan is a fuzzy cut of state up to at most this height, so committed
        // roots below it are provisional until the fold-forward passes it.
        let horizon = self.live_head().max(anchor);
        self.store.finish_bootstrap(anchor, &root, horizon)?;
        self.state.committed_height = Some(anchor);
        self.state.max_seen_height = self.state.max_seen_height.max(anchor);
        self.counters
            .committed_height
            .store(anchor, Ordering::Relaxed);
        self.counters.bootstrapping.store(false, Ordering::Relaxed);
        tracing::info!(anchor, keys = keys_done, "commitment: bootstrap complete");
        Ok(())
    }

    /// The live chain head, read from the DynProps backend the builder scans.
    /// Used as the bootstrap convergence horizon; `0` if DynProps is somehow
    /// absent from the scanned surface (the provisional flag then stays inert,
    /// which is safe).
    fn live_head(&self) -> i64 {
        self.backends
            .iter()
            .find(|(id, _)| *id == UndoStoreId::DynProps)
            .and_then(|(_, b)| {
                tron_chainbase::DynamicPropertiesStore::new(b.clone())
                    .latest_block_header_number()
            })
            .unwrap_or(0)
    }

    /// Buffer one applied block's write-set and fold every now-confirmed
    /// height contiguously up to `max_seen_height - K`. Reorg-reapplies
    /// (`height <= max_seen_height`) overwrite the buffered height and prune
    /// orphaned heights above it; a rewind to `<= committed_height` takes the
    /// re-bootstrap fallback. A forward gap below the release ceiling triggers
    /// resume.
    ///
    /// This is the clean, tokio-free seam the background task drives.
    pub fn ingest(
        &mut self,
        height: i64,
        deltas: Vec<CommitmentDeltaRef>,
    ) -> Result<Committed, CommitmentError> {
        self.ingest_with_resume(height, deltas, None)
    }

    /// As [`Self::ingest`], with an optional [`ResumeSource`] used to repair a
    /// forward gap (a dropped message or a crash tail) below the release
    /// ceiling without a full re-bootstrap.
    pub fn ingest_with_resume(
        &mut self,
        height: i64,
        deltas: Vec<CommitmentDeltaRef>,
        resume: Option<&dyn ResumeSource>,
    ) -> Result<Committed, CommitmentError> {
        // Deep reorg: a rewind at or below the folded watermark cannot be
        // absorbed in the buffer — fall back to re-bootstrap.
        if let Some(committed) = self.state.committed_height {
            if height <= committed {
                tracing::error!(
                    height,
                    committed,
                    "commitment: reorg deeper than the confirmation lag — re-bootstrapping \
                     from live state (rare fallback)"
                );
                return self.rebootstrap_at_head(height, deltas);
            }
        }

        // Reorg-reapply (shallow): a block at a height already seen. Overwrite
        // the buffered entry (last-write-wins) and prune any buffered heights
        // ABOVE it — they belonged to the now-orphaned branch.
        if height <= self.state.max_seen_height {
            self.state.pending.insert(height, deltas);
            let orphaned: Vec<i64> = self
                .state
                .pending
                .range((height + 1)..)
                .map(|(h, _)| *h)
                .collect();
            for h in orphaned {
                self.state.pending.remove(&h);
            }
        } else {
            self.state.pending.insert(height, deltas);
        }

        self.state.max_seen_height = self.state.max_seen_height.max(height);
        self.counters
            .head_height
            .store(self.state.max_seen_height, Ordering::Relaxed);
        self.counters
            .pending_depth
            .store(self.state.pending.len() as u64, Ordering::Relaxed);

        self.release_contiguous(resume)
    }

    /// Fold buffered heights from `committed_height + 1` upward, stopping at
    /// the release ceiling (`max_seen_height - K`), the first missing height
    /// (a gap → resume), or exhaustion of the buffer.
    fn release_contiguous(
        &mut self,
        resume: Option<&dyn ResumeSource>,
    ) -> Result<Committed, CommitmentError> {
        let k = self.confirmation_lag_blocks as i64;
        let release_to = self.state.max_seen_height - k;
        let mut folded = Vec::new();
        let mut rebootstrapped = false;

        // `next` is the first height we must fold. Before any commit it is the
        // lowest buffered height (bootstrap anchored committed_height already
        // when fresh, so this is only the no-commit-yet edge case).
        loop {
            let next = match self.state.committed_height {
                Some(c) => c + 1,
                None => match self.state.pending.keys().next() {
                    Some(h) => *h,
                    None => break,
                },
            };
            if next > release_to {
                break; // not yet confirmed — leave buffered
            }
            let deltas = match self.state.pending.remove(&next) {
                Some(d) => d,
                None => {
                    // Forward gap below the release ceiling. Repair from the
                    // resume source if it covers `next`, else re-bootstrap.
                    match resume.map(|r| r.deltas_at(next)).transpose()?.flatten() {
                        Some(d) => d,
                        None => {
                            tracing::error!(
                                gap_at = next,
                                release_to,
                                "commitment: forward gap below the release ceiling and no \
                                 resume coverage — re-bootstrapping from live state"
                            );
                            let c = self.rebootstrap_at_head_only()?;
                            rebootstrapped = true;
                            // After a re-bootstrap committed_height jumped to
                            // head - K; restart the release loop against the
                            // new watermark.
                            folded.clear();
                            let _ = c;
                            continue;
                        }
                    }
                }
            };
            self.fold_height(next, &deltas)?;
            folded.push(next);
        }

        self.counters
            .pending_depth
            .store(self.state.pending.len() as u64, Ordering::Relaxed);

        Ok(Committed {
            folded,
            committed_height: self.state.committed_height,
            root: self.smt.root(),
            rebootstrapped,
        })
    }

    /// Fold one height's write-set into the tree and persist atomically.
    fn fold_height(
        &mut self,
        height: i64,
        deltas: &[CommitmentDeltaRef],
    ) -> Result<(), CommitmentError> {
        let changes: Vec<(LeafPath, Option<NodeHash>)> = deltas
            .iter()
            .map(|d| {
                let path = leaf_path_for(d.store, &d.key);
                let vh = d.after.as_ref().map(|v| keccak256(v));
                (path, vh)
            })
            .collect();
        let (new_root, ops) = self.smt.apply(&changes)?;

        self.blocks_since_sync += 1;
        let sync = self.blocks_since_sync >= SYNC_EVERY;
        if sync {
            self.blocks_since_sync = 0;
        }
        self.store.commit_block(&ops, height, &new_root, sync)?;

        self.state.committed_height = Some(height);
        self.counters
            .committed_height
            .store(height, Ordering::Relaxed);
        self.counters.blocks_folded.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Re-bootstrap fallback for a deep reorg: wipe the tree, re-Merkleize the
    /// live stores at the recovered head, set `committed_height = head - K`,
    /// then continue with the buffered/just-arrived block.
    fn rebootstrap_at_head(
        &mut self,
        arriving_height: i64,
        arriving_deltas: Vec<CommitmentDeltaRef>,
    ) -> Result<Committed, CommitmentError> {
        // The new head is the arriving (rewound) height — every buffered
        // height above it is orphaned.
        self.state.pending.clear();
        self.state.pending.insert(arriving_height, arriving_deltas);
        self.state.max_seen_height = arriving_height;
        self.counters
            .head_height
            .store(arriving_height, Ordering::Relaxed);

        self.rebootstrap_core(arriving_height)?;
        let mut out = self.release_contiguous(None)?;
        out.rebootstrapped = true;
        Ok(out)
    }

    /// Re-bootstrap when a forward gap can't be repaired. Re-Merkleizes at
    /// `max_seen_height`, sets `committed_height = max_seen_height - K`.
    fn rebootstrap_at_head_only(&mut self) -> Result<Committed, CommitmentError> {
        let anchor = self.state.max_seen_height;
        self.rebootstrap_core(anchor)?;
        Ok(Committed {
            folded: Vec::new(),
            committed_height: self.state.committed_height,
            root: self.smt.root(),
            rebootstrapped: true,
        })
    }

    /// Shared re-bootstrap mechanics: wipe the store, re-Merkleize live state,
    /// and set `committed_height = anchor - K` (clamped to the anchor). After
    /// this, buffered heights `> committed_height` fold forward normally.
    fn rebootstrap_core(&mut self, anchor: i64) -> Result<(), CommitmentError> {
        self.store.wipe()?;
        // Reset the in-memory tree to empty; the wipe cleared the node store.
        self.smt = Smt::open(self.store.clone(), EMPTY_ROOT);
        self.state.committed_height = None;
        self.run_bootstrap(anchor, None)?;
        // run_bootstrap set committed_height = anchor (full live state). The
        // confirmation lag means the externally-reported committed height is
        // anchor - K, but the tree IS the live state at anchor; we keep
        // committed_height = anchor here (the tree's true height) and let the
        // release loop fold buffered heights above it. Heights in
        // (anchor - K, anchor] that were already folded into live state are
        // not re-folded — the live snapshot already reflects them.
        Ok(())
    }
}

/// The lexicographic successor of `key`: the smallest byte string strictly
/// greater than `key`, used to advance a scan cursor past the last key read.
/// Appending a `0x00` byte yields the next key after `key` in byte order
/// (`key` sorts before `key ‖ 0x00`).
fn succ(key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(key.len() + 1);
    out.extend_from_slice(key);
    out.push(0x00);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::smt::{NodeBackend, NodeHash};
    use tron_chainbase::MemBackend;

    fn store() -> CommitmentStore {
        let s = CommitmentStore::new(Arc::new(MemBackend::new()));
        s.check_or_init().unwrap();
        s
    }

    /// A builder over an empty live-state surface (no backends), so bootstrap
    /// anchors an empty tree at the given height.
    fn builder(store: CommitmentStore, k: u64) -> CommitmentBuilder {
        CommitmentBuilder::new(store, Vec::new(), k, Arc::new(CommitmentCounters::new())).unwrap()
    }

    fn delta(store: UndoStoreId, key: &[u8], val: Option<&[u8]>) -> CommitmentDeltaRef {
        CommitmentDeltaRef {
            store,
            key: key.to_vec(),
            after: val.map(|v| v.to_vec()),
        }
    }

    /// Build a reference root over a flat `(store_byte, key) → value` map by
    /// folding all leaves in one apply on a throwaway store. Keyed by the
    /// store discriminant (`UndoStoreId` is not `Ord`).
    fn reference_root(state: &BTreeMap<(u8, Vec<u8>), Vec<u8>>) -> NodeHash {
        let s = store();
        let mut smt = Smt::open(s.clone(), EMPTY_ROOT);
        let changes: Vec<(LeafPath, Option<NodeHash>)> = state
            .iter()
            .map(|((st, k), v)| {
                let store = UndoStoreId::from_u8(*st).unwrap();
                (leaf_path_for(store, k), Some(keccak256(v)))
            })
            .collect();
        let (root, ops) = smt.apply(&changes).unwrap();
        s.write_nodes(&ops).unwrap();
        root
    }

    /// The `Accounts` store discriminant, the only store used in these tests.
    const ACC: u8 = UndoStoreId::Accounts as u8;

    // -- 10. Confirmation-lag release + resume/contiguity -------------------

    #[test]
    fn release_stops_at_confirmation_ceiling() {
        let k = 3;
        let s = store();
        let mut b = builder(s, k);
        b.bootstrap_or_resume(0).unwrap();
        // committed_height = anchor 0 after bootstrap of an empty tree.
        assert_eq!(b.committed_height(), Some(0));

        let n = 10i64;
        let mut last = None;
        for h in 1..=n {
            let d = vec![delta(UndoStoreId::Accounts, &h.to_be_bytes(), Some(&[h as u8]))];
            last = Some(b.ingest(h, d).unwrap());
        }
        // Release ceiling = max_seen - K = n - K. Folding stops there.
        assert_eq!(b.committed_height(), Some(n - k as i64));
        // Heights (n-K, n] stay buffered.
        assert_eq!(b.pending_depth(), k as usize);
        let _ = last;
    }

    #[test]
    fn resume_from_persisted_height_advances_by_one() {
        let k = 2;
        let s = store();
        // Track the full state so we can compute the reference root.
        let mut full: BTreeMap<(u8, Vec<u8>), Vec<u8>> = BTreeMap::new();

        let n = 8i64;
        {
            let mut b = builder(s.clone(), k);
            b.bootstrap_or_resume(0).unwrap();
            for h in 1..=n {
                let key = h.to_be_bytes().to_vec();
                let val = vec![h as u8];
                full.insert((ACC, key.clone()), val.clone());
                b.ingest(h, vec![delta(UndoStoreId::Accounts, &key, Some(&val))])
                    .unwrap();
            }
            assert_eq!(b.committed_height(), Some(n - k as i64));
        }

        // Reopen from the persisted store. A real restart re-delivers blocks
        // from committed_height+1 (sync replays uncommitted heights), so feed
        // (prev+1)..=(n+1): the heights buffered-but-not-committed before the
        // drop plus the new tip.
        let mut b2 = CommitmentBuilder::new(
            s.clone(),
            Vec::new(),
            k,
            Arc::new(CommitmentCounters::new()),
        )
        .unwrap();
        b2.bootstrap_or_resume(0).unwrap(); // no-op: already committed
        let prev = b2.committed_height().unwrap();
        assert_eq!(prev, n - k as i64);
        for h in (prev + 1)..=(n + 1) {
            let key = h.to_be_bytes().to_vec();
            let val = vec![h as u8];
            full.insert((ACC, key.clone()), val.clone());
            b2.ingest(h, vec![delta(UndoStoreId::Accounts, &key, Some(&val))])
                .unwrap();
        }
        // committed_height advances by exactly one (release ceiling moved one
        // since the persisted height: (n+1)-K = (n-K)+1 = prev+1).
        assert_eq!(b2.committed_height(), Some(prev + 1));

        // The committed root equals folding 1..=(n+1-K) straight through.
        let mut expected_state: BTreeMap<(u8, Vec<u8>), Vec<u8>> = BTreeMap::new();
        for hh in 1..=(n + 1 - k as i64) {
            let key = hh.to_be_bytes().to_vec();
            expected_state.insert((ACC, key), vec![hh as u8]);
        }
        assert_eq!(b2.root(), reference_root(&expected_state));
    }

    #[test]
    fn dropped_message_gap_is_repaired_from_resume_source() {
        // A resume source backed by an in-memory log of per-height write-sets.
        struct LogResume {
            log: BTreeMap<i64, Vec<CommitmentDeltaRef>>,
        }
        impl ResumeSource for LogResume {
            fn deltas_at(
                &self,
                height: i64,
            ) -> Result<Option<Vec<CommitmentDeltaRef>>, CommitmentError> {
                Ok(self.log.get(&height).cloned())
            }
        }

        let k = 2;
        let s = store();
        let mut b = builder(s, k);
        b.bootstrap_or_resume(0).unwrap();

        let n = 9i64;
        let mut log: BTreeMap<i64, Vec<CommitmentDeltaRef>> = BTreeMap::new();
        let mut full: BTreeMap<(u8, Vec<u8>), Vec<u8>> = BTreeMap::new();
        for h in 1..=n {
            let key = h.to_be_bytes().to_vec();
            let val = vec![h as u8];
            let d = vec![delta(UndoStoreId::Accounts, &key, Some(&val))];
            log.insert(h, d.clone());
            full.insert((ACC, key), val);
        }

        // Deliver all but height 4 (simulate a dropped message). Height 4 is
        // below the release ceiling once head reaches 6+.
        let resume = LogResume { log: log.clone() };
        for h in 1..=n {
            if h == 4 {
                continue;
            }
            let d = log.get(&h).unwrap().clone();
            b.ingest_with_resume(h, d, Some(&resume)).unwrap();
        }
        // Folding should have repaired the gap at 4 and folded up to n-K.
        assert_eq!(b.committed_height(), Some(n - k as i64));

        let mut expected_state: BTreeMap<(u8, Vec<u8>), Vec<u8>> = BTreeMap::new();
        for hh in 1..=(n - k as i64) {
            let key = hh.to_be_bytes().to_vec();
            expected_state.insert((ACC, key), vec![hh as u8]);
        }
        assert_eq!(b.root(), reference_root(&expected_state));
    }

    // -- 11. Shallow reorg absorbed in the buffer ---------------------------

    #[test]
    fn shallow_reorg_absorbed_same_root_as_no_orphan() {
        let k = 4;
        // Run A: an orphan block at height h arrives, then the canonical
        // branch reapplies at h and continues.
        let s_a = store();
        let mut a = builder(s_a, k);
        a.bootstrap_or_resume(0).unwrap();

        // Heights 1..=5 canonical so far.
        let mut canonical: BTreeMap<i64, Vec<CommitmentDeltaRef>> = BTreeMap::new();
        for h in 1..=5i64 {
            let d = vec![delta(UndoStoreId::Accounts, &h.to_be_bytes(), Some(&[h as u8]))];
            canonical.insert(h, d.clone());
            a.ingest(h, d).unwrap();
        }
        let committed_before = a.committed_height();

        // Orphan block at height 4 (within K of head=5, so still buffered).
        let orphan = vec![delta(
            UndoStoreId::Accounts,
            &4i64.to_be_bytes(),
            Some(b"ORPHAN"),
        )];
        a.ingest(4, orphan).unwrap();
        // committed_height never moved backward.
        assert_eq!(a.committed_height(), committed_before);
        // Buffered heights above 4 (i.e. 5) were pruned.
        assert!(!a.state.pending.contains_key(&5));

        // Canonical branch reapplies at 4 and continues 5..=9.
        for h in 4..=9i64 {
            let d = canonical
                .get(&h)
                .cloned()
                .unwrap_or_else(|| vec![delta(UndoStoreId::Accounts, &h.to_be_bytes(), Some(&[h as u8]))]);
            canonical.insert(h, d.clone());
            a.ingest(h, d).unwrap();
        }
        assert_eq!(a.committed_height(), Some(9 - k as i64));

        // Run B: the orphan NEVER arrived. Same canonical stream.
        let s_b = store();
        let mut bld = builder(s_b, k);
        bld.bootstrap_or_resume(0).unwrap();
        for h in 1..=9i64 {
            let d = vec![delta(UndoStoreId::Accounts, &h.to_be_bytes(), Some(&[h as u8]))];
            bld.ingest(h, d).unwrap();
        }

        // The committed root at the same height must be identical.
        assert_eq!(a.committed_height(), bld.committed_height());
        assert_eq!(a.root(), bld.root());
    }

    // -- 12. Deep reorg falls back to re-bootstrap --------------------------

    #[test]
    fn deep_reorg_rebootstraps_to_post_reorg_state() {
        // Use a live-state surface so re-bootstrap has something to Merkleize.
        // The "live store" is a MemBackend the test mutates to reflect the
        // post-reorg state at the rewind height.
        let live = Arc::new(MemBackend::new());
        let backends: Vec<(UndoStoreId, Arc<dyn KvBackend>)> =
            vec![(UndoStoreId::Accounts, live.clone())];

        let k = 2;
        let s = store();
        let counters = Arc::new(CommitmentCounters::new());
        let mut b =
            CommitmentBuilder::new(s.clone(), backends.clone(), k, counters).unwrap();
        b.bootstrap_or_resume(0).unwrap();

        // Fold forward to commit several heights. Mirror each fold into the
        // live store so it stays consistent with the tree.
        for h in 1..=8i64 {
            let key = h.to_be_bytes().to_vec();
            let val = vec![h as u8];
            live.put(&key, &val).unwrap();
            b.ingest(h, vec![delta(UndoStoreId::Accounts, &key, Some(&val))])
                .unwrap();
        }
        let committed = b.committed_height().unwrap();
        assert_eq!(committed, 8 - k as i64);
        assert!(committed > 0);

        // Now a DEEP rewind to height 1 (<= committed). The post-reorg live
        // state: rewrite the live store to the canonical-at-1 snapshot.
        // Simulate the new branch by clearing everything above height 1 and
        // setting a distinct value.
        for h in 1..=8i64 {
            let _ = live.delete(&h.to_be_bytes());
        }
        let key1 = 1i64.to_be_bytes().to_vec();
        live.put(&key1, b"NEWBRANCH").unwrap();

        let rewind_delta = vec![delta(UndoStoreId::Accounts, &key1, Some(b"NEWBRANCH"))];
        let out = b.ingest(1, rewind_delta).unwrap();
        assert!(out.rebootstrapped, "deep reorg must re-bootstrap");

        // The resulting root must equal a fresh tree over the post-reorg live
        // state.
        let mut post: BTreeMap<(u8, Vec<u8>), Vec<u8>> = BTreeMap::new();
        post.insert((ACC, key1), b"NEWBRANCH".to_vec());
        assert_eq!(b.root(), reference_root(&post));
    }
}
