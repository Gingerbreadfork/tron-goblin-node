//! The unified gap-closing follower.
//!
//! One self-healing loop, driven by the node's **own committed
//! stores**, that closes the gap between the index cursor and the
//! committed head. Backfill is just "the gap is large"; live-follow is
//! "the gap is ≈ 0 and grows by one block every ~3s". There is no
//! backfill mode vs follow mode — startup behavior is a pure function
//! of `(cursor, head, floor)`.
//!
//! Two edges, one invariant: the indexed range is
//! `[back_edge, cursor_height]` (empty when `back_edge >
//! cursor_height`).
//!
//! * **floor-first** init: `cursor = floor − 1`, `back_edge = floor` —
//!   the live edge grinds forward from the snapshot base.
//! * **head-first** init: `cursor = head`, `back_edge = head + 1` —
//!   the live edge follows new blocks immediately (recent history
//!   queryable within seconds) while the backward edge walks down
//!   toward the floor behind it.
//!
//! Both edges advance **atomically with their window's rows** in one
//! write-batch, so every crash resolves to "re-derive at most one
//! window from immutable committed blocks" — idempotent because keys
//! are content-addressed by `(address, height, txidx)`.
//!
//! Reorgs are reconciled **by hash, not by event** (§4 of the plan):
//! the canonical id recorded at the cursor height is compared against
//! `BlockIndexStore`'s current canonical id; a mismatch unwinds using
//! the recorded per-height key ring. The ring — not re-derivation from
//! the orphaned block — is what makes un-indexing exact: the old
//! chain's TRC20/internal rows came from block-num-keyed
//! transaction-info that the new chain *overwrites* at apply time, so
//! they cannot be re-derived after the fact. (This corrects the plan's
//! §4.1 re-derive sketch.)

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use tron_chainbase::{
    BlockIndexStore, DynamicPropertiesStore, KvBackend, StoreError,
    TransactionRetStore, WriteOp,
};
use tron_types::BlockId;

use crate::db::{IndexDb, IndexError};
use crate::extract::{extract_block, BlockEntries, CaptureSet};
use crate::keys;

/// Missing-txinfo wait rule. Blocks apply serially and the hook
/// persists a block's transaction-info before `accept_block` returns,
/// so once the head has advanced PAST a height, that height's txinfo
/// is either on disk or permanently absent (hook ran and failed /
/// capture was off). Only the top of the chain can still be racing
/// its hook write — `head_raw` itself, plus one block of margin for a
/// leadership handoff where the new leader starts the next apply
/// while the old leader's hook is finishing. Crucially this rule does
/// NOT depend on block timestamps: a wall-clock-recency guard fails
/// exactly during catch-up, where the racing block is months old.
const TXINFO_WAIT_MARGIN: i64 = 1;

/// Safety valve: if the same boundary height stays txinfo-less for
/// this many consecutive waits (the head not advancing all the
/// while), give up and index it as genuinely missing — a wedged hook
/// or a dead store must not park the follower forever. At the 3s
/// poll cadence this is ~5 minutes.
const TXINFO_WAIT_MAX_ATTEMPTS: u32 = 100;

/// Engine tuning. The node's `[index.backfill]` config maps onto this.
#[derive(Debug, Clone)]
pub struct EngineOptions {
    /// Max heights per gap-closing window (one atomic batch each).
    pub window_blocks: usize,
    /// Soft cap on transactions per window — bounds batch RAM on
    /// tx-heavy ranges regardless of `window_blocks`.
    pub window_tx_budget: usize,
    /// Head-first (newest history queryable within seconds, long tail
    /// fills in behind) vs floor-first (monotonic single edge).
    pub head_first: bool,
    /// Capacity clamp: never index below this height even when the
    /// block store goes deeper.
    pub start_height: i64,
    /// Trail the PBFT-solidified mark instead of the head (never
    /// unwinds; lags ~19 blocks).
    pub follow_solidified: bool,
    /// Heights within this distance of the head keep unwind records
    /// (the recent ring). Reorgs are bounded by the solidified mark
    /// (~19 blocks); 512 leaves enormous margin.
    pub ring_depth: i64,
    /// WAL fsync barrier: sync once every N committed windows (and on
    /// park). Crash recovery re-derives at most N windows.
    pub sync_every_windows: u32,
}

impl Default for EngineOptions {
    fn default() -> Self {
        Self {
            window_blocks: 1024,
            window_tx_budget: 20_000,
            head_first: true,
            start_height: 0,
            follow_solidified: false,
            ring_depth: 512,
            sync_every_windows: 16,
        }
    }
}

/// Monotonic counters, shared with the node's metrics sampler.
#[derive(Debug, Default)]
pub struct IndexCounters {
    pub blocks_indexed: AtomicU64,
    pub rows_native: AtomicU64,
    pub rows_trc20: AtomicU64,
    pub rows_trc721: AtomicU64,
    pub rows_internal: AtomicU64,
    pub rows_logs: AtomicU64,
    pub reorg_unwinds: AtomicU64,
    pub reorg_rows_deleted: AtomicU64,
    /// Blocks indexed without transaction-info while VM-derived kinds
    /// were requested — the §1.3 precondition being paid for.
    pub missing_txinfo_blocks: AtomicU64,
}

/// Point-in-time view for logging / metrics / the API `meta.backfill`
/// marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexStatus {
    /// Highest contiguously-indexed height (live edge). `None` before
    /// the first window.
    pub cursor: Option<i64>,
    /// Lowest indexed height (`indexed_from`).
    pub back_edge: Option<i64>,
    /// Effective floor (`max(lowest stored block, start_height)`).
    pub floor: Option<i64>,
    /// The head the follower is chasing (solidified-clamped when
    /// configured).
    pub target_head: i64,
    /// Backward edge reached the floor — full history present.
    pub backfill_complete: bool,
    /// Live edge caught up to the target head.
    pub at_tip: bool,
}

/// What a single `tick` did — the node's follower loop uses this to
/// decide whether to immediately tick again or park on the wake-up
/// signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tick {
    /// Indexed a forward window ending at this height.
    Forward { upto: i64, blocks: u64 },
    /// Backfilled a backward window down to this height.
    Backward { downto: i64, blocks: u64 },
    /// Unwound a reorg back to the common ancestor.
    Unwound { ancestor: i64, rows_deleted: u64 },
    /// Nothing to do — park until the head advances.
    Parked,
    /// The node's stores aren't ready yet (no head / empty block
    /// index) — park and retry.
    NotReady,
}

struct EngineInner {
    windows_since_sync: u32,
    /// Un-synced batches outstanding — triggers one WAL fsync when
    /// parking.
    dirty: bool,
    /// `(height, consecutive waits)` for the missing-txinfo boundary —
    /// the safety valve's memory.
    txinfo_wait: Option<(i64, u32)>,
}

/// The follower engine. `tick()` is the entire control surface — the
/// node calls it in a loop from a blocking task and parks on
/// [`Tick::Parked`]. Internally synchronized; safe to share with
/// status readers.
pub struct IndexEngine {
    db: IndexDb,
    blocks: Arc<dyn KvBackend>,
    block_index: Arc<dyn KvBackend>,
    txret: Arc<dyn KvBackend>,
    dyn_props: Arc<dyn KvBackend>,
    caps: CaptureSet,
    opts: EngineOptions,
    counters: Arc<IndexCounters>,
    inner: Mutex<EngineInner>,
}

/// Dedicated small rayon pool for window decode. Deliberately NOT the
/// global pool: Block-STM parallel execution lives there, and backfill
/// decode must never steal apply-path threads (sync throughput is the
/// node's king metric). Bounded at 2–8 threads.
fn decode_pool() -> &'static rayon::ThreadPool {
    static POOL: OnceLock<rayon::ThreadPool> = OnceLock::new();
    POOL.get_or_init(|| {
        let n = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        rayon::ThreadPoolBuilder::new()
            .num_threads((n / 4).clamp(2, 8))
            .thread_name(|i| format!("idx-decode-{i}"))
            .build()
            .expect("index decode pool")
    })
}

impl IndexEngine {
    pub fn new(
        db: IndexDb,
        blocks: Arc<dyn KvBackend>,
        block_index: Arc<dyn KvBackend>,
        txret: Arc<dyn KvBackend>,
        dyn_props: Arc<dyn KvBackend>,
        caps: CaptureSet,
        opts: EngineOptions,
    ) -> Self {
        Self {
            db,
            blocks,
            block_index,
            txret,
            dyn_props,
            caps,
            opts,
            counters: Arc::new(IndexCounters::default()),
            inner: Mutex::new(EngineInner {
                windows_since_sync: 0,
                dirty: false,
                txinfo_wait: None,
            }),
        }
    }

    pub fn counters(&self) -> Arc<IndexCounters> {
        self.counters.clone()
    }

    pub fn capture_set(&self) -> CaptureSet {
        self.caps
    }

    fn dp(&self) -> DynamicPropertiesStore {
        DynamicPropertiesStore::new(self.dyn_props.clone())
    }

    fn bi(&self) -> BlockIndexStore {
        BlockIndexStore::new(self.block_index.clone())
    }

    /// The head the follower chases: the committed head, or the
    /// solidified mark under `stream = "solidified"`.
    fn target_head(&self) -> Option<i64> {
        let dp = self.dp();
        let head = dp.latest_block_header_number()?;
        if self.opts.follow_solidified {
            Some(head.min(dp.latest_solidified_block_num().unwrap_or(0)))
        } else {
            Some(head)
        }
    }

    pub fn status(&self) -> IndexStatus {
        let cursor = self.db.cursor_height().ok().flatten();
        let back_edge = self.db.back_edge().ok().flatten();
        let floor = self.db.floor().ok().flatten();
        let target_head = self.target_head().unwrap_or(0);
        let backfill_complete = match (back_edge, floor) {
            (Some(b), Some(f)) => b <= f,
            _ => false,
        };
        IndexStatus {
            cursor,
            back_edge,
            floor,
            target_head,
            backfill_complete,
            at_tip: cursor.map(|c| c >= target_head).unwrap_or(false),
        }
    }

    /// Run one step of the gap-closing loop. Never blocks on the
    /// network; reads committed local stores only.
    pub fn tick(&self) -> Result<Tick, IndexError> {
        let Some(head) = self.target_head() else {
            return Ok(Tick::NotReady);
        };
        // head_raw (unclamped) drives ring decisions — reorg territory
        // is relative to the real chain tip, not the solidified mark.
        let head_raw = self.dp().latest_block_header_number().unwrap_or(head);

        // ---- self-orchestrating init: a pure fn of (cursor, head, floor)
        if self.db.cursor_height()?.is_none() {
            let Some(lowest) = self.bi().lowest()? else {
                return Ok(Tick::NotReady);
            };
            let floor = lowest.max(self.opts.start_height);
            if head < floor {
                return Ok(Tick::NotReady);
            }
            let (cursor0, back0) = if self.opts.head_first {
                (head, head + 1)
            } else {
                (floor - 1, floor)
            };
            // Record the canonical id at the initial cursor when one
            // exists, so by-hash reorg detection is armed from the
            // first tick — a head-first start indexes heights *below*
            // the cursor (backward windows) before any forward window
            // would otherwise stamp the cursor id.
            let cursor0_id = match self.bi().get(cursor0) {
                Ok(id) => Some(*id.as_bytes()),
                Err(_) => None,
            };
            let mut ops = vec![
                IndexDb::floor_put_op(floor),
                IndexDb::back_edge_put_op(back0),
            ];
            ops.extend(IndexDb::cursor_put_ops(cursor0, cursor0_id));
            self.db.commit(&ops)?;
            tracing::info!(
                cursor = cursor0,
                back_edge = back0,
                floor,
                head,
                head_first = self.opts.head_first,
                "index: initialized edges"
            );
        }

        // ---- reorg reconcile (by hash, needs no witness) -------------
        if let Some(unwound) = self.reconcile_reorg()? {
            return Ok(unwound);
        }

        let cursor = self.db.cursor_height()?.expect("initialized above");
        if cursor < head {
            return self.forward_window(cursor, head, head_raw);
        }

        let back_edge = self.db.back_edge()?.unwrap_or(cursor + 1);
        let floor = self.db.floor()?.unwrap_or(0);
        if back_edge > floor {
            return self.backward_window(back_edge, floor, head_raw);
        }

        // At tip, fully backfilled: make outstanding batches durable
        // once, then park.
        let mut inner = self.inner.lock().expect("index engine poisoned");
        if inner.dirty {
            self.db.sync()?;
            inner.dirty = false;
            inner.windows_since_sync = 0;
        }
        Ok(Tick::Parked)
    }

    /// Compare the recorded canonical id at the cursor height against
    /// the store's current canonical id; on mismatch, unwind exactly
    /// the recorded keys back to the common ancestor. Detection works
    /// across restarts and off-periods — the index does not need to
    /// have witnessed the reorg.
    fn reconcile_reorg(&self) -> Result<Option<Tick>, IndexError> {
        let (Some(cursor), Some(recorded)) = (self.db.cursor_height()?, self.db.cursor_id()?)
        else {
            return Ok(None);
        };
        match self.bi().get(cursor) {
            Ok(canonical) if *canonical.as_bytes() == recorded => return Ok(None),
            Ok(_) | Err(StoreError::NotFound) => {}
            Err(e) => return Err(e.into()),
        }

        // Mismatch: walk down while the recorded ring id differs from
        // the canonical id, deleting exactly the recorded row keys.
        // The walk only covers the indexed range `[back_edge, cursor]`
        // — heights below the back edge hold no rows, so a mismatch
        // there (e.g. a head-first start whose cursor id moved before
        // any forward window) just repoints the cursor. Reorgs are
        // bounded by the solidified gate, so the ring (depth 512)
        // always covers indexed heights in the walk; a missing ring
        // entry inside the range means store-level inconsistency → the
        // blessed remedy is delete-and-rebuild, surfaced as a hard
        // error.
        let back_edge = self.db.back_edge()?.unwrap_or(i64::MIN);
        let mut h = cursor;
        let mut ops: Vec<WriteOp> = Vec::new();
        let mut rows_deleted: u64 = 0;
        let ancestor = loop {
            if h < back_edge {
                break h; // nothing indexed at or below h
            }
            let Some(ring_id) = self.db.id_at(h)? else {
                return Err(IndexError::Corrupt(format!(
                    "reorg unwind needs the recorded ring at height {h} but it is not present \
                     (reorg deeper than ring_depth?)"
                )));
            };
            let canonical_matches = match self.bi().get(h) {
                Ok(c) => *c.as_bytes() == ring_id,
                Err(StoreError::NotFound) => false,
                Err(e) => return Err(e.into()),
            };
            if canonical_matches {
                break h;
            }
            if let Some(keys) = self.db.keys_at(h)? {
                rows_deleted += keys.len() as u64;
                ops.extend(keys.into_iter().map(WriteOp::Delete));
            }
            ops.push(WriteOp::Delete(keys::meta_id_at(h)));
            ops.push(WriteOp::Delete(keys::meta_keys_at(h)));
            h -= 1;
        };

        // Re-arm detection at the ancestor: its recorded id, or the
        // store's canonical id where nothing was indexed.
        let ancestor_id = match self.db.id_at(ancestor)? {
            Some(id) => Some(id),
            None => self.bi().get(ancestor).ok().map(|c| *c.as_bytes()),
        };
        ops.extend(IndexDb::cursor_put_ops(ancestor, ancestor_id));
        self.db.commit(&ops)?;
        // A reorg is consensus-critical bookkeeping — make the unwind
        // durable immediately rather than waiting for the barrier.
        self.db.sync()?;
        self.counters.reorg_unwinds.fetch_add(1, Ordering::Relaxed);
        self.counters
            .reorg_rows_deleted
            .fetch_add(rows_deleted, Ordering::Relaxed);
        tracing::info!(
            from = cursor,
            ancestor,
            rows_deleted,
            "index: reorg reconciled — unwound to common ancestor, re-indexing forward"
        );
        Ok(Some(Tick::Unwound { ancestor, rows_deleted }))
    }

    /// Decode + extract one height from already-fetched block bytes.
    /// `Ok(None)` ⇒ skip (unreadable / undecodable).
    fn load_and_extract(
        &self,
        h: i64,
        bytes: Option<&[u8]>,
        txinfo_expected: bool,
    ) -> Result<Option<BlockEntries>, IndexError> {
        let Some(bytes) = bytes else {
            tracing::warn!(height = h, "index: canonical block body missing; skipping height");
            return Ok(None);
        };
        let block = match <tron_proto::Block as prost::Message>::decode(bytes) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(height = h, error = %e, "index: block body undecodable; skipping height");
                return Ok(None);
            }
        };
        let txinfo = TransactionRetStore::new(self.txret.clone()).get(h)?;
        let entries = extract_block(h, &block, txinfo.as_ref(), &self.caps);
        if entries.txinfo_missing && txinfo_expected {
            self.counters
                .missing_txinfo_blocks
                .fetch_add(1, Ordering::Relaxed);
        }
        Ok(Some(entries))
    }

    fn note_entries(&self, e: &BlockEntries) {
        self.counters.rows_native.fetch_add(e.native_rows, Ordering::Relaxed);
        self.counters.rows_trc20.fetch_add(e.trc20_rows, Ordering::Relaxed);
        self.counters.rows_trc721.fetch_add(e.trc721_rows, Ordering::Relaxed);
        self.counters.rows_internal.fetch_add(e.internal_rows, Ordering::Relaxed);
        self.counters.rows_logs.fetch_add(e.log_rows, Ordering::Relaxed);
    }

    /// Commit a window's ops + edge update, handling the fsync
    /// barrier.
    fn commit_window(&self, ops: Vec<WriteOp>) -> Result<(), IndexError> {
        self.db.commit(&ops)?;
        let mut inner = self.inner.lock().expect("index engine poisoned");
        inner.dirty = true;
        inner.windows_since_sync += 1;
        if inner.windows_since_sync >= self.opts.sync_every_windows {
            self.db.sync()?;
            inner.dirty = false;
            inner.windows_since_sync = 0;
        }
        Ok(())
    }

    /// Collect `(height, canonical id)` pairs for a window walking
    /// `step` (+1 forward / −1 backward) from `from`, bounded by
    /// `bound` (inclusive) and the window/tx budgets. Returns the pairs
    /// plus whether the walk stopped at a not-yet-available height.
    fn plan_window(&self, from: i64, bound: i64, step: i64) -> Result<Vec<(i64, BlockId)>, IndexError> {
        let mut out = Vec::with_capacity(self.opts.window_blocks.min(4096));
        let bi = self.bi();
        let mut h = from;
        while out.len() < self.opts.window_blocks
            && ((step > 0 && h <= bound) || (step < 0 && h >= bound))
        {
            match bi.get(h) {
                Ok(id) => out.push((h, id)),
                Err(StoreError::NotFound) => {
                    // A hole in the canonical index below the head is a
                    // store inconsistency; stop the window here and let
                    // the next tick retry (forward) — backward walks
                    // treat it as the effective floor.
                    tracing::warn!(height = h, "index: block-index hole; window truncated");
                    break;
                }
                Err(e) => return Err(e.into()),
            }
            h += step;
        }
        Ok(out)
    }

    fn forward_window(&self, cursor: i64, head: i64, head_raw: i64) -> Result<Tick, IndexError> {
        let planned = self.plan_window(cursor + 1, head, 1)?;
        if planned.is_empty() {
            return Ok(Tick::Parked);
        }

        // In-flight txinfo wait: a height the head has already moved
        // past has final txinfo (apply is serialized; the hook runs
        // before accept_block returns), so absence there is genuine —
        // index native kinds and count it. Only the head block itself
        // (± one block of leadership-handoff margin) can still be
        // racing its hook write: truncate the window there and let the
        // wake-up retry, with an attempts cap so a wedged hook can't
        // park the follower forever.
        let wants_vm = self.caps.trc20 || self.caps.internal || self.caps.logs;
        let mut cut = planned.len();
        if wants_vm {
            let txret = TransactionRetStore::new(self.txret.clone());
            for (i, (h, _)) in planned.iter().enumerate() {
                if *h < head_raw - TXINFO_WAIT_MARGIN || txret.get(*h)?.is_some() {
                    continue;
                }
                let mut inner = self.inner.lock().expect("index engine poisoned");
                let attempts = match inner.txinfo_wait {
                    Some((waited_h, n)) if waited_h == *h => n + 1,
                    _ => 1,
                };
                if attempts > TXINFO_WAIT_MAX_ATTEMPTS {
                    tracing::warn!(
                        height = h,
                        attempts,
                        "index: txinfo never arrived for the head block; indexing it without VM rows"
                    );
                    inner.txinfo_wait = None;
                    continue;
                }
                inner.txinfo_wait = Some((*h, attempts));
                cut = i;
                break;
            }
        }
        let planned = &planned[..cut];
        if planned.is_empty() {
            return Ok(Tick::Parked);
        }
        let planned = self.budget_clamp(planned)?;

        let extracted = self.extract_many(&planned)?;
        let mut ops: Vec<WriteOp> = Vec::new();
        let mut indexed: u64 = 0;
        let mut last = (cursor, None::<[u8; 32]>);
        for ((h, id, _), entries) in planned.iter().zip(extracted) {
            let Some(entries) = entries else {
                // Unreadable body — cursor still advances over it so a
                // single bad height can't wedge the follower forever.
                // The ring entry is still written (with an empty key
                // list): a later reorg unwind walking this height must
                // find a record, or it would hard-error on a hole the
                // skip created.
                self.ring_ops(*h, id, &BlockEntries::default(), head_raw, &mut ops);
                last = (*h, Some(*id.as_bytes()));
                continue;
            };
            self.ring_ops(*h, id, &entries, head_raw, &mut ops);
            self.note_entries(&entries);
            ops.extend(
                entries
                    .puts
                    .into_iter()
                    .map(|(k, v)| WriteOp::Put(k, v)),
            );
            indexed += 1;
            last = (*h, Some(*id.as_bytes()));
        }
        ops.extend(IndexDb::cursor_put_ops(last.0, last.1));
        self.commit_window(ops)?;
        self.counters.blocks_indexed.fetch_add(indexed, Ordering::Relaxed);
        Ok(Tick::Forward { upto: last.0, blocks: indexed })
    }

    fn backward_window(&self, back_edge: i64, floor: i64, head_raw: i64) -> Result<Tick, IndexError> {
        let planned = self.plan_window(back_edge - 1, floor, -1)?;
        if planned.is_empty() {
            // Hole right below the back edge: nothing further down is
            // reachable through the canonical index — treat as done by
            // clamping the floor up to the edge so the follower parks
            // instead of spinning. (`lowest()` said deeper blocks
            // exist, but the contiguous range ends here.)
            tracing::warn!(
                back_edge,
                floor,
                "index: no contiguous canonical blocks below the back edge; raising floor"
            );
            self.db
                .commit(&[IndexDb::floor_put_op(back_edge)])?;
            return Ok(Tick::Parked);
        }
        let planned = self.budget_clamp(&planned)?;

        let extracted = self.extract_many(&planned)?;
        let mut ops: Vec<WriteOp> = Vec::new();
        let mut indexed: u64 = 0;
        let mut lowest = back_edge;
        for ((h, id, _), entries) in planned.iter().zip(extracted) {
            lowest = *h;
            let Some(entries) = entries else {
                // Same hole-prevention as the forward path: skipped
                // heights still get a (empty) ring record.
                self.ring_ops(*h, id, &BlockEntries::default(), head_raw, &mut ops);
                continue;
            };
            self.ring_ops(*h, id, &entries, head_raw, &mut ops);
            self.note_entries(&entries);
            ops.extend(entries.puts.into_iter().map(|(k, v)| WriteOp::Put(k, v)));
            indexed += 1;
        }
        ops.push(IndexDb::back_edge_put_op(lowest));
        self.commit_window(ops)?;
        self.counters.blocks_indexed.fetch_add(indexed, Ordering::Relaxed);
        Ok(Tick::Backward { downto: lowest, blocks: indexed })
    }

    /// Shrink a planned window to the tx budget (always keeps at least
    /// one height so progress is guaranteed) and fetch each kept
    /// block's raw bytes exactly once — the budget pre-pass counts txs
    /// with a raw field-walk over those bytes (no decode), and
    /// `extract_many` then decodes the SAME bytes, so a backfill never
    /// reads a block body from the store twice. `None` bytes = the
    /// canonical body is unexpectedly missing (skipped at extraction,
    /// ring-recorded by the caller).
    fn budget_clamp(
        &self,
        planned: &[(i64, BlockId)],
    ) -> Result<Vec<(i64, BlockId, Option<Vec<u8>>)>, IndexError> {
        let mut out = Vec::with_capacity(planned.len());
        let mut txs = 0usize;
        for (h, id) in planned {
            let bytes = self.blocks.get(id.as_bytes())?;
            if let Some(bytes) = &bytes {
                txs += crate::extract::count_block_txs_raw(bytes);
            }
            out.push((*h, *id, bytes));
            if txs >= self.opts.window_tx_budget {
                break;
            }
        }
        Ok(out)
    }

    /// Extract a window's heights on the dedicated decode pool —
    /// parallel across blocks, deterministic output order.
    fn extract_many(
        &self,
        planned: &[(i64, BlockId, Option<Vec<u8>>)],
    ) -> Result<Vec<Option<BlockEntries>>, IndexError> {
        use rayon::prelude::*;
        let wants_vm = self.caps.trc20 || self.caps.internal || self.caps.logs;
        if planned.len() < 8 {
            return planned
                .iter()
                .map(|(h, _, bytes)| self.load_and_extract(*h, bytes.as_deref(), wants_vm))
                .collect();
        }
        decode_pool().install(|| {
            planned
                .par_iter()
                .map(|(h, _, bytes)| self.load_and_extract(*h, bytes.as_deref(), wants_vm))
                .collect()
        })
    }

    /// Ring bookkeeping for heights in reorg territory: record the
    /// canonical id + the exact row keys written, and prune the entry
    /// that falls out of the ring.
    fn ring_ops(
        &self,
        h: i64,
        id: &BlockId,
        entries: &BlockEntries,
        head_raw: i64,
        ops: &mut Vec<WriteOp>,
    ) {
        if h <= head_raw - self.opts.ring_depth {
            return;
        }
        ops.push(WriteOp::Put(keys::meta_id_at(h), id.as_bytes().to_vec()));
        let row_keys: Vec<Vec<u8>> = entries.puts.iter().map(|(k, _)| k.clone()).collect();
        ops.push(WriteOp::Put(
            keys::meta_keys_at(h),
            keys::encode_key_list(&row_keys),
        ));
        let expired = h - self.opts.ring_depth;
        if expired > 0 {
            ops.push(WriteOp::Delete(keys::meta_id_at(expired)));
            ops.push(WriteOp::Delete(keys::meta_keys_at(expired)));
        }
    }
}
