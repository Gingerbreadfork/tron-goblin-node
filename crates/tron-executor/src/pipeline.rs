//! Pipelined block apply — overlap block N's commit I/O with block
//! N+1's execution.
//!
//! `APPLY_TIMING` profiling on a mainnet catch-up showed the per-block
//! apply cost splits into *execution* (the dominant share) and *commit*
//! (checkpoint-manifest write + fsync, per-store write batches) plus the
//! *undo-log put* (its own fsync) — all strictly serialized today.
//! Execution of block N+1 doesn't need block N's writes to be DURABLE,
//! it only needs to READ them. So:
//!
//! ```text
//!  classic:    [ exec N ][ commit N ][ undo N ][ exec N+1 ][ commit N+1 ] …
//!  pipelined:  [ exec N ][ exec N+1          ][ exec N+2          ] …   (applier thread)
//!                        [ commit N ][undo N ][ commit N+1 ][undo …]    (committer thread)
//! ```
//!
//! Visibility: after block N executes, its drained write-set is parked
//! in a [`PendingOverlay`] per store. Block N+1 executes over a
//! `BlockSession` wrapped around those overlays, so its reads see N's
//! writes while the committer flushes them to the base stores in the
//! background. The pipeline is depth-1: before installing N+1's writes
//! the applier joins N's commit, so the overlay never holds more than
//! one block and the committer never runs two blocks concurrently.
//!
//! What does NOT change:
//!
//! * **Write order and content.** The committer runs the exact same
//!   [`commit_drained`] + `BlockUndoStore::put` sequence the classic
//!   path runs, one block at a time, in block order. Manifest-before-
//!   stores (the crash-recovery invariant) is preserved per block.
//! * **Crash recovery.** A crash while a commit is in flight is
//!   indistinguishable from today's crash-mid-commit: the fsync'd
//!   manifest (or its absence) decides whether the block replays on
//!   restart via `replay_pending_checkpoints`.
//! * **C-7 serialization.** Pre-images for block N+1's undo log are
//!   read through the overlay (base + N's writes) on the applier
//!   thread *before* N+1's job is handed to the committer — and the
//!   committer only ever writes blocks the applier already drained, so
//!   no concurrent writer can slip between pre-image capture and flush.
//!
//! What DOES change: `apply` returning `Ok` means the block executed
//! and its writes are visible through [`ApplyPipeline::view`]; they
//! become durable when the *next* `apply` (or [`ApplyPipeline::flush`])
//! joins the background commit. A commit failure therefore surfaces one
//! block late — same blast radius as today's commit failure (state
//! repairs from the retained manifest on restart), just reported on the
//! following apply. Callers that need everything durable (end of a
//! drain batch, before a reorg, before reading base stores directly)
//! call `flush`.

use std::sync::mpsc;
use std::sync::Arc;
use std::time::Instant;

use tron_chainbase::{
    BlockUndoRecord, BlockUndoStore, CheckPointV2, CheckpointError, KvBackend, PendingOverlay,
    UndoStoreId, WriteOp,
};
use tron_proto::Block;
use tron_types::BlockId;

use crate::{
    apply_timing, commit_drained, drain_block_session, execute_block_logic, BlockExecError,
    BlockExecutionReport, BlockSession, ExecConfig, StateBackends,
};

/// One block's durable work, handed from the applier to the committer.
struct CommitJob {
    block_num: i64,
    stores: Vec<(UndoStoreId, Arc<dyn KvBackend>, Vec<WriteOp>)>,
    record: BlockUndoRecord,
    defer_store_fsync: bool,
    /// Execution time measured on the applier thread, so the
    /// committer can emit the same `[apply]` profiler line as the
    /// classic path (`APPLY_TIMING`).
    exec_us: u64,
    timing: bool,
}

/// Handle to the lazily-spawned committer thread.
struct Committer {
    /// `Option` so `Drop` can hang up the channel before joining.
    jobs: Option<mpsc::SyncSender<CommitJob>>,
    results: mpsc::Receiver<Result<(), String>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Committer {
    fn spawn(base: StateBackends, undo_store: BlockUndoStore, checkpoint: CheckPointV2) -> Self {
        // Depth-1 pipeline: the applier joins the previous result
        // before sending the next job, so capacity 1 never blocks.
        let (jobs_tx, jobs_rx) = mpsc::sync_channel::<CommitJob>(1);
        let (results_tx, results_rx) = mpsc::sync_channel::<Result<(), String>>(1);
        let handle = std::thread::Builder::new()
            .name("block-committer".into())
            .spawn(move || {
                while let Ok(job) = jobs_rx.recv() {
                    let t_commit = job.timing.then(Instant::now);
                    let mut res = commit_drained(
                        &job.stores,
                        &checkpoint,
                        &base,
                        job.defer_store_fsync,
                    )
                    .map_err(|e| format!("commit block {}: {e}", job.block_num));
                    let commit_us =
                        t_commit.map(|t| t.elapsed().as_micros() as u64).unwrap_or(0);
                    if res.is_ok() {
                        let t_undo = job.timing.then(Instant::now);
                        res = undo_store
                            .put(job.block_num, &job.record)
                            .map_err(|e| format!("undo put block {}: {e}", job.block_num));
                        if job.timing {
                            let undo_us =
                                t_undo.map(|t| t.elapsed().as_micros() as u64).unwrap_or(0);
                            apply_timing::record(job.exec_us, commit_us, undo_us);
                        }
                    }
                    if results_tx.send(res).is_err() {
                        // Applier hung up — nothing left to report to.
                        return;
                    }
                }
            })
            .expect("spawn block-committer thread");
        Self {
            jobs: Some(jobs_tx),
            results: results_rx,
            handle: Some(handle),
        }
    }
}

impl Drop for Committer {
    fn drop(&mut self) {
        // Hang up the job channel, then wait for any in-flight commit
        // to finish — dropping mid-write would be no worse than a
        // crash (the manifest replays), but there's no reason to leave
        // the write racing process exit when a join is this cheap.
        self.jobs = None;
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Depth-1 pipelined block applier over the undo + checkpoint commit
/// path. See the module docs for the execution model.
///
/// Single-consumer by construction: exactly one thread calls `apply` /
/// `flush` (the sync driver's apply loop), and only that thread may
/// read through [`view`](Self::view) while a block is in flight.
/// Readers of the BASE stores (RPC, other tasks) see block N's writes
/// appear as the background commit lands — at most one block behind
/// `view`, exactly like a reader racing the classic path's commit.
pub struct ApplyPipeline {
    base: StateBackends,
    /// `base` with every store wrapped in a [`PendingOverlay`] — what
    /// block execution (and the driver's between-block reads) sees.
    view: StateBackends,
    overlays: Vec<(UndoStoreId, Arc<PendingOverlay>)>,
    undo_store: BlockUndoStore,
    checkpoint: CheckPointV2,
    /// Spawned on the first `apply` — drivers that never lead never
    /// pay for a thread.
    committer: Option<Committer>,
    in_flight: bool,
}

impl ApplyPipeline {
    pub fn new(
        base: &StateBackends,
        undo_store: BlockUndoStore,
        checkpoint: CheckPointV2,
    ) -> Self {
        let mut overlays: Vec<(UndoStoreId, Arc<PendingOverlay>)> = Vec::new();
        let mut wrap = |id: UndoStoreId, b: &Arc<dyn KvBackend>| -> Arc<dyn KvBackend> {
            let ov = Arc::new(PendingOverlay::new(b.clone()));
            overlays.push((id, ov.clone()));
            ov
        };
        let opt = |overlays: &mut Vec<(UndoStoreId, Arc<PendingOverlay>)>,
                   id: UndoStoreId,
                   b: &Option<Arc<dyn KvBackend>>|
         -> Option<Arc<dyn KvBackend>> {
            b.as_ref().map(|b| {
                let ov = Arc::new(PendingOverlay::new(b.clone()));
                overlays.push((id, ov.clone()));
                ov as Arc<dyn KvBackend>
            })
        };
        use UndoStoreId as Id;
        let view = StateBackends {
            accounts: wrap(Id::Accounts, &base.accounts),
            witnesses: wrap(Id::Witnesses, &base.witnesses),
            votes: wrap(Id::Votes, &base.votes),
            delegation: wrap(Id::Delegation, &base.delegation),
            delegated_resources: wrap(Id::DelegatedResources, &base.delegated_resources),
            dyn_props: wrap(Id::DynProps, &base.dyn_props),
            proposals: wrap(Id::Proposals, &base.proposals),
            name_index: wrap(Id::NameIndex, &base.name_index),
            id_index: wrap(Id::IdIndex, &base.id_index),
            asset_v1: wrap(Id::AssetV1, &base.asset_v1),
            asset_v2: wrap(Id::AssetV2, &base.asset_v2),
            contracts: wrap(Id::Contracts, &base.contracts),
            abi: wrap(Id::Abi, &base.abi),
            exchange_v1: wrap(Id::ExchangeV1, &base.exchange_v1),
            exchange_v2: wrap(Id::ExchangeV2, &base.exchange_v2),
            market_orders: wrap(Id::MarketOrders, &base.market_orders),
            market_account: wrap(Id::MarketAccount, &base.market_account),
            nullifiers: wrap(Id::Nullifiers, &base.nullifiers),
            delegated_resource_account_index: opt(
                &mut overlays,
                Id::DelegatedResourceAccountIndex,
                &base.delegated_resource_account_index,
            ),
            merkle_trees: opt(&mut overlays, Id::MerkleTrees, &base.merkle_trees),
            code: opt(&mut overlays, Id::Code, &base.code),
            storage_row: opt(&mut overlays, Id::StorageRow, &base.storage_row),
            contract_state: opt(&mut overlays, Id::ContractState, &base.contract_state),
            block_index: opt(&mut overlays, Id::BlockIndex, &base.block_index),
            witness_schedule: opt(&mut overlays, Id::WitnessSchedule, &base.witness_schedule),
            // Read-only pass-through — never in a block's write-set, so it
            // needs no pending overlay.
            reward_vi: base.reward_vi.clone(),
        };
        Self {
            base: base.clone(),
            view,
            overlays,
            undo_store,
            checkpoint,
            committer: None,
            in_flight: false,
        }
    }

    /// The pipeline-consistent state view: base stores plus any
    /// not-yet-committed block. The driver must route every read that
    /// feeds block validation (executed head, block-signer account,
    /// solidified-containment gate) through this — reading base
    /// directly while a block is in flight sees the pre-block state.
    ///
    /// Read-only: writes through this view are rejected by the
    /// overlay. Driver bookkeeping writes (solidified pointer, block
    /// index) keep going to the base stores; those keys are never in
    /// a block's write-set, so the overlay can't mask them.
    pub fn view(&self) -> &StateBackends {
        &self.view
    }

    /// `true` while a block's commit is running (or queued) on the
    /// committer thread.
    pub fn is_pending(&self) -> bool {
        self.in_flight
    }

    /// Execute `block` against the pipeline view and hand its commit
    /// to the background committer. Equivalent to
    /// `execute_block_with_undo_checkpoint_and_config` except that
    /// durability for this block is deferred to the next
    /// `apply`/`flush` (see module docs).
    ///
    /// On an execution error the previous block's pending commit is
    /// left in flight and the overlay untouched — the failed block
    /// wrote nothing.
    pub fn apply(
        &mut self,
        block: &Block,
        expected_parent: Option<BlockId>,
        config: &ExecConfig,
        original_tx_sizes: Option<&[i64]>,
    ) -> Result<BlockExecutionReport, BlockExecError> {
        let timing = apply_timing::enabled();

        // 1) Execute over the overlay view (sees the previous block's
        //    pending writes).
        let session = BlockSession::wrap(&self.view);
        let wrapped = session.as_state_backends();
        let t_exec = timing.then(Instant::now);
        let mut report =
            execute_block_logic(&wrapped, block, expected_parent, config, original_tx_sizes)?;
        let exec_us = t_exec.map(|t| t.elapsed().as_micros() as u64).unwrap_or(0);

        // 2) Drain on the applier thread: pre-images read through the
        //    overlay (the true pre-state for this block), batch targets
        //    are the real base stores.
        let drained = drain_block_session(session, &self.base, config.capture_state_deltas)?;
        report.state_deltas = drained.deltas;

        // 3) Join the previous block's commit before retiring its
        //    overlay. (Almost always already done — commit is the
        //    short phase.)
        self.join_in_flight()?;

        // 4) Park this block's writes in the overlay so the NEXT
        //    block's execution (and the driver's reads) see them while
        //    the committer works.
        for (id, ov) in &self.overlays {
            match drained.stores.iter().find(|(sid, _, _)| sid == id) {
                Some((_, _, ops)) => ov.replace_with(ops),
                None => ov.clear(),
            }
        }

        // 5) Queue the durable work.
        let block_num = block
            .block_header
            .as_ref()
            .and_then(|h| h.raw_data.as_ref())
            .map(|r| r.number)
            .unwrap_or(0);
        let committer = self.committer.get_or_insert_with(|| {
            Committer::spawn(
                self.base.clone(),
                self.undo_store.clone(),
                self.checkpoint.clone(),
            )
        });
        let job = CommitJob {
            block_num,
            stores: drained.stores,
            record: drained.record,
            defer_store_fsync: config.defer_store_fsync,
            exec_us,
            timing,
        };
        committer
            .jobs
            .as_ref()
            .expect("committer job channel open")
            .send(job)
            .map_err(|_| commit_err("committer thread exited"))?;
        self.in_flight = true;

        Ok(report)
    }

    /// Wait for any in-flight commit and retire the overlay (view ==
    /// base again). Call at the end of an apply batch, and before any
    /// path that mutates or reads base stores directly (reorg,
    /// rollback, shutdown).
    ///
    /// An `Err` means the previous block's commit failed: its writes
    /// may be partially applied to the base stores, exactly like a
    /// classic-path commit error — the fsync'd manifest replays them
    /// to a consistent state on restart. The overlay is cleared either
    /// way so the view never wedges on a dead block.
    pub fn flush(&mut self) -> Result<(), BlockExecError> {
        let res = self.join_in_flight();
        for (_, ov) in &self.overlays {
            ov.clear();
        }
        res
    }

    fn join_in_flight(&mut self) -> Result<(), BlockExecError> {
        if !self.in_flight {
            return Ok(());
        }
        self.in_flight = false;
        let committer = self
            .committer
            .as_ref()
            .expect("in_flight implies a committer");
        match committer.results.recv() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(msg)) => {
                // The pending block is broken on disk (manifest replay
                // repairs on restart); don't keep serving its writes.
                for (_, ov) in &self.overlays {
                    ov.clear();
                }
                Err(commit_err(&msg))
            }
            Err(_) => {
                for (_, ov) in &self.overlays {
                    ov.clear();
                }
                Err(commit_err("committer thread died"))
            }
        }
    }
}

fn commit_err(msg: &str) -> BlockExecError {
    BlockExecError::Checkpoint(CheckpointError::Io(format!("pipelined apply: {msg}")))
}
