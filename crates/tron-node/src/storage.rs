//! Per-store RocksDB instance opener.
//!
//! Each chainbase store lives in its own subdirectory under
//! `data_dir/db/<store_name>/`. This module opens every one we
//! need and returns the bundle so the rest of the node can wire
//! it into executor + RPC handles.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tron_chainbase::{KvBackend, RocksDbBackend, RocksDbError, SnapshotKvBackend};

/// Every on-disk backend the node needs. `Arc<dyn KvBackend>` so
/// each store can be shared between the executor and the RPC server
/// without re-opening.
#[derive(Clone)]
pub struct OpenedStores {
    pub accounts: Arc<dyn KvBackend>,
    pub witnesses: Arc<dyn KvBackend>,
    pub votes: Arc<dyn KvBackend>,
    pub delegation: Arc<dyn KvBackend>,
    pub delegated_resources: Arc<dyn KvBackend>,
    pub dyn_props: Arc<dyn KvBackend>,
    pub proposals: Arc<dyn KvBackend>,
    pub name_index: Arc<dyn KvBackend>,
    pub id_index: Arc<dyn KvBackend>,
    pub asset_v1: Arc<dyn KvBackend>,
    pub asset_v2: Arc<dyn KvBackend>,
    pub account_asset: Arc<dyn KvBackend>,
    pub contracts: Arc<dyn KvBackend>,
    pub abi: Arc<dyn KvBackend>,
    pub exchange_v1: Arc<dyn KvBackend>,
    pub exchange_v2: Arc<dyn KvBackend>,
    pub market_orders: Arc<dyn KvBackend>,
    pub nullifiers: Arc<dyn KvBackend>,
    pub merkle_trees: Arc<dyn KvBackend>,
    pub code: Arc<dyn KvBackend>,
    pub storage_row: Arc<dyn KvBackend>,
    pub contract_state: Arc<dyn KvBackend>,
    pub block_index: Arc<dyn KvBackend>,
    pub blocks: Arc<dyn KvBackend>,
    pub transactions: Arc<dyn KvBackend>,
    pub tx_history: Arc<dyn KvBackend>,
    /// `transactionRetStore` — per-block `TransactionRet` (the list of
    /// `TransactionInfo` receipts, block-num keyed, java-tron layout).
    /// Read by the address-history indexer's backfill (a snapshot that
    /// includes it makes TRC20/internal history derivable without
    /// re-execution); written at block commit when `[index]` is
    /// enabled. Append-only, KhaosDb owns reorg semantics (the reorg
    /// reapply path overwrites the block-num key with the new chain's
    /// receipts).
    pub transaction_ret: Arc<dyn KvBackend>,
    pub delegated_resource_account_index: Arc<dyn KvBackend>,
    pub market_account: Arc<dyn KvBackend>,
    pub market_pair_to_price: Arc<dyn KvBackend>,
    pub market_pair_price_to_order: Arc<dyn KvBackend>,
    pub balance_trace: Arc<dyn KvBackend>,
    pub witness_schedule: Arc<dyn KvBackend>,
    /// Per-block undo log powering KhaosDb Phase B reorg-with-rollback.
    /// On a fresh node this starts empty; every block applied via the
    /// SyncDriver writes a record here. Pruned beyond the reorg horizon.
    pub block_undo: Arc<dyn KvBackend>,
    /// PBFT signature aggregates per block (and per SR list rotation).
    /// Populated by the PbftRuntime when a block crosses commit
    /// threshold. Consumed by `latest_solid_block` + light clients
    /// that need cryptographic proof of finality.
    pub pbft_sign_data: Arc<dyn KvBackend>,
    /// `common-database` — java-tron's misc store, holds
    /// `LATEST_PBFT_BLOCK_NUM` written by `PbftMessageAction.action()`
    /// on every commit-threshold crossing. Read by block explorers
    /// and oracles for finality proof.
    pub common_database: Arc<dyn KvBackend>,
    /// `common` — distinct from `common-database`. Generic byte-keyed
    /// kv store used for one-off node-local state. The discovery
    /// `NodePersistService` writes the persisted peer set here under
    /// the `peers` key (wire-compatible with java-tron's `DBNodes`).
    pub common: Arc<dyn KvBackend>,
    /// Mempool restart persistence — `tx_id → raw_bytes` of every
    /// accepted pending tx. tron-goblin-node-specific (java-tron's pending
    /// queue is volatile). The mempool reloads from this store at
    /// startup so reboots don't drop work waiting to be included.
    pub mempool: Arc<dyn KvBackend>,
    /// Snapshot-stack handles for every state-mutating store. Every
    /// `Arc<dyn KvBackend>` above is actually an `Arc<SnapshotKvBackend>`
    /// whose root is the RocksDB instance; this field exposes the
    /// snapshot handles so the runtime can drive `advance`/`merge`/
    /// `revoke` across all of them in lockstep. Append-only stores
    /// (blocks, block_index, transactions, tx_history, mempool, and
    /// the undo/checkpoint metadata stores) are not wrapped — writes
    /// to them aren't reorged at the storage layer; KhaosDb owns
    /// their reorg semantics.
    pub snapshots: SnapshotStack,
}

/// Coordinator over every state-mutating `SnapshotKvBackend` in
/// [`OpenedStores`]. Owns the per-block layer-tracking state and an
/// internal `Mutex` so multiple block-applying tasks (SR runtime,
/// per-peer SyncDriver) can safely call through the same stack
/// without racing on advance/merge/revoke. Cloning is cheap — the
/// inner state is `Arc<Mutex<…>>`.
///
/// All mutation goes through the high-level [`Self::apply_block`] /
/// [`Self::reorg`] APIs. Lower-level fan-out helpers
/// (`advance`/`merge`/`revoke`) are still exposed for tests and the
/// startup recovery path, but production code paths should not call
/// them directly — the high-level APIs handle block_num tracking and
/// horizon-driven bottom-layer merge in lockstep.
#[derive(Clone)]
pub struct SnapshotStack {
    inner: Arc<std::sync::Mutex<SnapshotStackInner>>,
}

struct SnapshotStackInner {
    /// `(store_name, snapshot_backend)` pairs. Order is stable across
    /// the process lifetime — assigned at construction time by
    /// [`OpenedStores::open_inner`].
    backends: Vec<(String, Arc<SnapshotKvBackend>)>,
    /// Block numbers, parallel to the layer order (oldest first).
    /// `block_nums.len() == depth()`. Reorg consults this to figure
    /// out how many layers to revoke; horizon-merge pops from the
    /// front when depth exceeds the cap.
    block_nums: Vec<i64>,
    /// Bound on layer depth. Layers older than `horizon` blocks past
    /// the head get merged into the root (un-reorgable). Default
    /// `usize::MAX` for tests / `empty()` so they never auto-merge.
    horizon: usize,
    /// Optional checkpoint-V2 dir. When set, horizon-driven
    /// bottom-layer commits route through
    /// `flush_bottom_via_checkpoint` (atomic manifest → per-store
    /// merge → manifest delete). When `None`, the bottom layer is
    /// merged in-place (still correct, no cross-store atomicity on
    /// crash).
    checkpoint: Option<tron_chainbase::CheckPointV2>,
}

/// Errors returned by [`SnapshotStack::reorg`] when the stack's
/// view of the linear apply order disagrees with the reorg path.
/// Production code surfaces these to the operator; they indicate
/// either a programming error in the caller or genuine state
/// corruption.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotReorgError {
    #[error(
        "snapshot drift: reorg expected to revoke block {expected} but top layer is for block {actual}"
    )]
    Drift { expected: i64, actual: i64 },
    #[error(
        "reorg target block {0} is past the snapshot horizon (already merged into root)"
    )]
    PastHorizon(i64),
}

impl SnapshotStack {
    /// Construct an empty stack — useful for tests that build
    /// `OpenedStores` with `MemBackend`s and don't need real snapshot
    /// management. All mutating ops become no-ops because there's
    /// nothing to fan out to.
    pub fn empty() -> Self {
        Self {
            inner: Arc::new(std::sync::Mutex::new(SnapshotStackInner {
                backends: Vec::new(),
                block_nums: Vec::new(),
                horizon: usize::MAX,
                checkpoint: None,
            })),
        }
    }

    /// Construct a stack from a pre-built list of `(store_name,
    /// snapshot_backend)` pairs. Used by integration tests that wrap
    /// `MemBackend`s in `SnapshotKvBackend` to exercise the
    /// snapshot-driven block-apply paths without standing up a full
    /// `OpenedStores`.
    pub fn from_named(backends: Vec<(String, Arc<SnapshotKvBackend>)>) -> Self {
        Self {
            inner: Arc::new(std::sync::Mutex::new(SnapshotStackInner {
                backends,
                block_nums: Vec::new(),
                horizon: usize::MAX,
                checkpoint: None,
            })),
        }
    }

    /// Configure the horizon (max layer depth) and optional checkpoint
    /// directory used by horizon-driven bottom-layer commits. Builder
    /// pattern — returns `self` for chaining at construction time.
    pub fn with_horizon(self, horizon: usize) -> Self {
        {
            let mut g = self.inner.lock().expect("snapshot stack lock poisoned");
            g.horizon = horizon.max(1);
        }
        self
    }

    pub fn with_checkpoint(self, cp: tron_chainbase::CheckPointV2) -> Self {
        {
            let mut g = self.inner.lock().expect("snapshot stack lock poisoned");
            g.checkpoint = Some(cp);
        }
        self
    }

    /// Number of layers currently pushed (`0` = writes flow straight
    /// to the root RocksDB).
    pub fn depth(&self) -> usize {
        self.inner
            .lock()
            .expect("snapshot stack lock poisoned")
            .block_nums
            .len()
    }

    /// Snapshot of the block numbers tracked per layer, oldest first.
    /// Useful for observability and tests.
    pub fn block_nums(&self) -> Vec<i64> {
        self.inner
            .lock()
            .expect("snapshot stack lock poisoned")
            .block_nums
            .clone()
    }

    /// Apply a block under a fresh tentative-write layer. The caller
    /// supplies the actual `execute_block` closure; this method
    /// wraps it with:
    /// 1. Acquire the coordinator lock (serialises all block-apply
    ///    across SR + per-peer SyncDrivers).
    /// 2. `advance` every backend.
    /// 3. Run `exec_fn`.
    /// 4. On `Ok`: record `block_num`, then `merge` the bottom layer
    ///    if the stack exceeds the horizon (using checkpoint-V2 when
    ///    configured). Layers remain stacked otherwise so future
    ///    reorg can revoke them.
    /// 5. On `Err`: `revoke` the just-pushed layer so partial writes
    ///    don't leak.
    ///
    /// Returns whatever the closure returned. The lock is held for
    /// the duration of `exec_fn`, so concurrent block-apply by
    /// another producer waits.
    pub fn apply_block<F, T, E>(&self, block_num: i64, exec_fn: F) -> Result<T, E>
    where
        F: FnOnce() -> Result<T, E>,
    {
        let mut g = self.inner.lock().expect("snapshot stack lock poisoned");
        for (_, b) in &g.backends {
            b.advance();
        }
        let outcome = exec_fn();
        match outcome {
            Ok(value) => {
                g.block_nums.push(block_num);
                // Drain anything past the horizon via checkpoint-V2
                // when configured; falls back to direct merge on
                // checkpoint failure (logged inline by caller).
                while g.block_nums.len() > g.horizon {
                    if let Some(cp) = &g.checkpoint {
                        match flush_bottom_locked(&g.backends, cp) {
                            Ok(_) => {}
                            Err(_) => {
                                // Checkpoint failed — fall back to
                                // direct merge so we don't get stuck.
                                for (_, b) in &g.backends {
                                    b.merge().expect(
                                        "db error in SnapshotStack::apply_block: \
                                         merge fallback after checkpoint failure",
                                    );
                                }
                            }
                        }
                    } else {
                        for (_, b) in &g.backends {
                            b.merge().expect(
                                "db error in SnapshotStack::apply_block: merge bottom layer",
                            );
                        }
                    }
                    g.block_nums.remove(0);
                }
                Ok(value)
            }
            Err(err) => {
                for (_, b) in &g.backends {
                    b.revoke();
                }
                Err(err)
            }
        }
    }

    /// Coordinated reorg. Revokes the topmost layers matching
    /// `old_block_nums` (newest-first), then applies the new fork
    /// blocks under fresh layers via `apply_new`. Returns:
    /// * `Ok(Vec<R>)` with each new-fork apply's result on the happy
    ///   path.
    /// * `Err(SnapshotReorgError)` when the stack's view diverges
    ///   from `old_block_nums`.
    /// * `Err(...)` when `apply_new` returns an error AND the
    ///   recovery couldn't restore the original chain. Recovery is
    ///   driven by re-running `apply_new` against the old-chain
    ///   blocks (which the caller passes via the `old_blocks_replay`
    ///   closure, since the snapshot stack doesn't own Block bytes).
    ///
    /// Holds the lock across the entire reorg — concurrent block
    /// apply by another producer waits.
    pub fn reorg<E, FB, F, R>(
        &self,
        old_block_nums: &[i64],
        new_block_nums: &[i64],
        between_revoke_and_apply: FB,
        mut apply_one: F,
    ) -> Result<Vec<R>, ReorgFailure<E, R>>
    where
        FB: FnOnce(),
        F: FnMut(i64, usize) -> Result<R, E>,
    {
        let mut g = self.inner.lock().expect("snapshot stack lock poisoned");

        // Validate + revoke the old-fork layers, newest first.
        for &block_num in old_block_nums {
            match g.block_nums.last().copied() {
                Some(top) if top == block_num => {
                    for (_, b) in &g.backends {
                        b.revoke();
                    }
                    g.block_nums.pop();
                }
                Some(top) => {
                    return Err(ReorgFailure::Drift {
                        expected: block_num,
                        actual: top,
                    });
                }
                None => {
                    return Err(ReorgFailure::PastHorizon(block_num));
                }
            }
        }

        // State is now at the common ancestor — run the operator's
        // between-revoke-and-apply hook (mempool repush, metrics,
        // etc.) inside the lock so concurrent producers can't
        // observe a half-reorg state.
        between_revoke_and_apply();

        // Apply the new fork under fresh layers, oldest first.
        let mut results: Vec<R> = Vec::with_capacity(new_block_nums.len());
        for (idx, &block_num) in new_block_nums.iter().enumerate() {
            for (_, b) in &g.backends {
                b.advance();
            }
            match apply_one(block_num, idx) {
                Ok(value) => {
                    g.block_nums.push(block_num);
                    results.push(value);
                }
                Err(e) => {
                    // Revoke the just-pushed (failing) layer.
                    for (_, b) in &g.backends {
                        b.revoke();
                    }
                    // Caller is responsible for recovering the old
                    // chain via its own apply path. Surface the
                    // partial-apply state.
                    return Err(ReorgFailure::ApplyFailed {
                        failed_block: block_num,
                        applied: results,
                        source: e,
                    });
                }
            }
        }

        // Drain past horizon, same as apply_block does.
        while g.block_nums.len() > g.horizon {
            if let Some(cp) = &g.checkpoint {
                let _ = flush_bottom_locked(&g.backends, cp);
            } else {
                for (_, b) in &g.backends {
                    b.merge().expect(
                        "db error in SnapshotStack::reorg_apply: merge bottom layer",
                    );
                }
            }
            g.block_nums.remove(0);
        }
        Ok(results)
    }

    /// Squash every remaining layer into the root on every wrapped
    /// backend. Used at shutdown to flush in-flight tentative writes
    /// before closing the RocksDB handles.
    pub fn merge_all(&self) {
        let mut g = self.inner.lock().expect("snapshot stack lock poisoned");
        while !g.block_nums.is_empty() {
            for (_, b) in &g.backends {
                b.merge().expect(
                    "db error in SnapshotStack::merge_all: shutdown flush layer",
                );
            }
            g.block_nums.remove(0);
        }
    }

    /// Atomic cross-store flush of the bottom-most snapshot layer.
    /// Mirrors java-tron's `SnapshotManager.flush` cycle. See
    /// [`flush_bottom_locked`] for the under-the-lock implementation.
    pub fn flush_bottom_via_checkpoint(
        &self,
        checkpoint: &tron_chainbase::CheckPointV2,
    ) -> Result<Option<tron_chainbase::CheckpointId>, tron_chainbase::CheckpointError> {
        let mut g = self.inner.lock().expect("snapshot stack lock poisoned");
        let result = flush_bottom_locked(&g.backends, checkpoint)?;
        if result.is_some() || !g.block_nums.is_empty() {
            // Even on empty layers we merged, so pop the block_num.
            if !g.block_nums.is_empty() {
                g.block_nums.remove(0);
            }
        }
        Ok(result)
    }

    /// Replay any orphan checkpoint manifests (from a prior crashed
    /// flush) into the matching backends. Called once at startup,
    /// before any new tentative-write layer is pushed.
    pub fn recover_from_checkpoints(
        &self,
        checkpoint: &tron_chainbase::CheckPointV2,
    ) -> Result<usize, tron_chainbase::CheckpointError> {
        let g = self.inner.lock().expect("snapshot stack lock poisoned");
        let mut total = 0;
        let ids = checkpoint.list()?;
        for id in ids {
            let n = checkpoint.replay(id, |entry| {
                if let Some((_, b)) = g.backends.iter().find(|(n, _)| n == &entry.db_name) {
                    match &entry.value {
                        Some(v) => b
                            .put(&entry.key, v)
                            .map_err(|e| tron_chainbase::CheckpointError::Decode(e.to_string()))?,
                        None => b
                            .delete(&entry.key)
                            .map_err(|e| tron_chainbase::CheckpointError::Decode(e.to_string()))?,
                    }
                }
                Ok(())
            })?;
            total += n;
            // Best-effort cleanup: the checkpoint's data is already replayed,
            // so a failed delete only leaves a stale (idempotently re-applied)
            // checkpoint behind — log it rather than discard the error silently.
            if let Err(e) = checkpoint.delete(id) {
                tracing::warn!(checkpoint_id = id, error = %e, "failed to delete replayed checkpoint");
            }
        }
        Ok(total)
    }

    /// Borrow the wrapped backends. Test-only.
    #[cfg(test)]
    pub fn backends(&self) -> Vec<Arc<SnapshotKvBackend>> {
        let g = self.inner.lock().expect("snapshot stack lock poisoned");
        g.backends.iter().map(|(_, b)| b.clone()).collect()
    }
}

/// Outcome from [`SnapshotStack::reorg`]. Distinguishes
/// stack-internal validation failures (drift, past horizon) from
/// downstream `apply_one` callback failures so callers can pick the
/// right recovery path.
#[derive(Debug, thiserror::Error)]
pub enum ReorgFailure<E, R = ()> {
    #[error(
        "snapshot drift: reorg expected to revoke block {expected} but top layer is for block {actual}"
    )]
    Drift { expected: i64, actual: i64 },
    #[error(
        "reorg target block {0} is past the snapshot horizon (already merged into root)"
    )]
    PastHorizon(i64),
    #[error("new-fork apply failed at block {failed_block}: {source}")]
    ApplyFailed {
        failed_block: i64,
        /// Results of the new-fork blocks that DID apply (and remain
        /// committed — the coordinator does not roll them back).
        /// Carried so the caller can run its per-block side effects
        /// for them: the index/firehose/archive hook must fire for
        /// every block that lands in state, or external sinks hold
        /// blocks with no transaction-info and no unwind.
        applied: Vec<R>,
        #[source]
        source: E,
    },
}

/// Internal: flush the bottom layer's pending writes through a
/// checkpoint-V2 manifest, then merge per-store. Called from inside
/// the stack's mutex.
fn flush_bottom_locked(
    backends: &[(String, Arc<SnapshotKvBackend>)],
    checkpoint: &tron_chainbase::CheckPointV2,
) -> Result<Option<tron_chainbase::CheckpointId>, tron_chainbase::CheckpointError> {
    let depth = backends.first().map(|(_, b)| b.depth()).unwrap_or(0);
    if depth == 0 {
        return Ok(None);
    }
    let mut entries: Vec<tron_chainbase::CheckpointEntry> = Vec::new();
    for (name, b) in backends {
        for (key, value) in b.peek_bottom_layer() {
            entries.push(tron_chainbase::CheckpointEntry {
                db_name: name.clone(),
                key,
                value,
            });
        }
    }
    let id = if entries.is_empty() {
        None
    } else {
        Some(checkpoint.write(&entries)?)
    };
    for (_, b) in backends {
        b.merge()
            .map_err(|e| tron_chainbase::CheckpointError::Decode(e.to_string()))?;
    }
    if let Some(id) = id {
        // Best-effort: data already merged to root; a failed delete only
        // leaves a stale checkpoint behind. Log instead of swallowing.
        if let Err(e) = checkpoint.delete(id) {
            tracing::warn!(checkpoint_id = id, error = %e, "failed to delete merged checkpoint");
        }
    }
    Ok(id)
}

/// java-tron's RocksDB stores directory name (`storage.db.directory`, default
/// `database`). We match it exactly, so a java-tron mainnet snapshot extracted
/// straight into the node's data dir is used in place with no rename/import
/// step, and fresh nodes lay out identically.
pub(crate) const DB_DIR: &str = "database";

/// The directory holding the RocksDB stores under `data_dir` — always
/// `<data_dir>/database`, matching java-tron. (Kept as one named source of
/// truth / future config hook rather than scattering the literal.)
pub(crate) fn resolve_db_root(data_dir: &Path) -> PathBuf {
    data_dir.join(DB_DIR)
}

impl OpenedStores {
    /// Open every store under `data_dir/database/` (java-tron's layout).
    /// Creates the subtree if
    /// missing. Each store is independent — they don't share a single
    /// RocksDB column family because java-tron uses separate
    /// directories and we mirror that layout 1:1.
    ///
    /// Uses RocksDB defaults. For tuned settings (write buffer,
    /// max-open-files), use [`open_tuned`].
    pub fn open(data_dir: &Path) -> Result<Self, StorageError> {
        Self::open_inner(data_dir, None)
    }

    /// Open every store with operator-tuned RocksDB knobs. Plumbed
    /// from `StorageConfig` in the daemon config.
    pub fn open_tuned(
        data_dir: &Path,
        write_buffer_mb: usize,
        max_open_files: i32,
    ) -> Result<Self, StorageError> {
        Self::open_inner(data_dir, Some((write_buffer_mb, max_open_files)))
    }

    fn open_inner(
        data_dir: &Path,
        tuning: Option<(usize, i32)>,
    ) -> Result<Self, StorageError> {
        let db_root = resolve_db_root(data_dir);
        std::fs::create_dir_all(&db_root).map_err(|e| StorageError::Io {
            path: db_root.clone(),
            source: e,
        })?;

        let open = |name: &str| open_store(&db_root, name, tuning);

        // State-mutating stores get wrapped in `SnapshotKvBackend` so
        // every block-apply runs under a tentative-write layer that
        // can be revoked on reorg. Append-only stores stay raw — their
        // contents are owned by KhaosDb's in-memory tree until they
        // become irreversible, at which point they're written once
        // and never changed. Wrapping them would just add overhead.
        let mut snapshots: Vec<(String, Arc<SnapshotKvBackend>)> = Vec::new();
        let mut wrap = |name: &str| -> Result<Arc<dyn KvBackend>, StorageError> {
            let root = open(name)?;
            let snap = Arc::new(SnapshotKvBackend::new(root));
            snapshots.push((name.to_string(), snap.clone()));
            Ok(snap as Arc<dyn KvBackend>)
        };

        let accounts = wrap("account")?;
        let witnesses = wrap("witness")?;
        let votes = wrap("votes")?;
        let delegation = wrap("delegation")?;
        let delegated_resources = wrap("DelegatedResource")?;
        let dyn_props = wrap("properties")?;
        // Schema-version gate (M-14): stamp a fresh / pre-versioning DB,
        // or refuse to open one written by an incompatible future schema
        // rather than silently mis-decoding it. At open time no tentative
        // layer is active, so this write-throughs to the properties store.
        {
            let dp = tron_chainbase::DynamicPropertiesStore::new(dyn_props.clone());
            if let Err(found) = dp.check_or_stamp_schema_version() {
                return Err(StorageError::SchemaVersion {
                    found,
                    expected: tron_chainbase::DynamicPropertiesStore::CURRENT_SCHEMA_VERSION,
                });
            }
        }
        let proposals = wrap("proposal")?;
        let name_index = wrap("accountid-index")?;
        let id_index = wrap("account-index")?;
        let asset_v1 = wrap("asset-issue")?;
        let asset_v2 = wrap("asset-issue-v2")?;
        let contracts = wrap("contract")?;
        let abi = wrap("abi")?;
        let exchange_v1 = wrap("exchange")?;
        let exchange_v2 = wrap("exchange-v2")?;
        let market_orders = wrap("market_order")?;
        let nullifiers = wrap("nullifier")?;
        let merkle_trees = wrap("IncrementalMerkleTree")?;
        let code = wrap("code")?;
        let storage_row = wrap("storage-row")?;
        let contract_state = wrap("contract-state")?;
        let delegated_resource_account_index = wrap("DelegatedResourceAccountIndex")?;
        let market_account = wrap("market_account")?;
        let market_pair_to_price = wrap("market_pair_to_price")?;
        let market_pair_price_to_order = wrap("market_pair_price_to_order")?;
        let balance_trace = wrap("balance-trace")?;
        let witness_schedule = wrap("witness_schedule")?;

        Ok(Self {
            accounts,
            witnesses,
            votes,
            delegation,
            delegated_resources,
            dyn_props,
            proposals,
            name_index,
            id_index,
            asset_v1,
            asset_v2,
            // Read-only for us: the executor writes TRC10 balances inline to
            // `Account.asset_v2`, never to this store. java-tron's snapshot
            // splits optimized accounts' balances out to here, so the RPC
            // merges it back on getAccount. Opened raw (no snapshot layer) —
            // block-apply never mutates it.
            account_asset: open("account-asset")?,
            contracts,
            abi,
            exchange_v1,
            exchange_v2,
            market_orders,
            nullifiers,
            merkle_trees,
            code,
            storage_row,
            contract_state,
            block_index: open("block-index")?,
            blocks: open("block")?,
            transactions: open("trans")?,
            tx_history: open("transactionHistoryStore")?,
            // camelCase trap: java-tron names this one (and the history
            // store above) in camelCase, unlike every kebab-case store.
            transaction_ret: open(tron_chainbase::TransactionRetStore::DB_NAME)?,
            delegated_resource_account_index,
            market_account,
            market_pair_to_price,
            market_pair_price_to_order,
            balance_trace,
            witness_schedule,
            block_undo: open("block-undo")?,
            pbft_sign_data: open("pbft-sign-data")?,
            common_database: open("common-database")?,
            common: open("common")?,
            mempool: open("mempool")?,
            snapshots: SnapshotStack::from_named(snapshots),
        })
    }

    /// Build the `StateBackends` handle for the executor.
    pub fn to_state_backends(&self) -> tron_executor::StateBackends {
        // Install the process-wide account-asset backend (java-tron's static
        // `AssetUtil.accountAssetStore`, set at ChainBaseManager init) so the
        // asset actuators can merge an optimized account's TRC10 balances on
        // read. Set-once / idempotent; harmless in tests (they hold no
        // asset-optimized accounts, so the merge is a no-op).
        tron_chainbase::set_account_asset_backend(self.account_asset.clone());
        tron_executor::StateBackends {
            accounts: self.accounts.clone(),
            witnesses: self.witnesses.clone(),
            votes: self.votes.clone(),
            delegation: self.delegation.clone(),
            delegated_resources: self.delegated_resources.clone(),
            delegated_resource_account_index: Some(self.delegated_resource_account_index.clone()),
            dyn_props: self.dyn_props.clone(),
            proposals: self.proposals.clone(),
            name_index: self.name_index.clone(),
            id_index: self.id_index.clone(),
            asset_v1: self.asset_v1.clone(),
            asset_v2: self.asset_v2.clone(),
            contracts: self.contracts.clone(),
            abi: self.abi.clone(),
            exchange_v1: self.exchange_v1.clone(),
            exchange_v2: self.exchange_v2.clone(),
            market_orders: self.market_orders.clone(),
            nullifiers: self.nullifiers.clone(),
            merkle_trees: Some(self.merkle_trees.clone()),
            code: Some(self.code.clone()),
            storage_row: Some(self.storage_row.clone()),
            contract_state: Some(self.contract_state.clone()),
            block_index: Some(self.block_index.clone()),
            witness_schedule: Some(self.witness_schedule.clone()),
        }
    }

    /// Build a fully-stocked `RpcState`. Plumbs every store the RPC
    /// methods know how to consult, so `eth_*`, `getAccount`, and
    /// friends all work without further wiring.
    pub fn to_rpc_state(&self, chain_id: u64) -> tron_rpc::RpcState {
        tron_rpc::RpcState::new(
            self.accounts.clone(),
            self.blocks.clone(),
            self.block_index.clone(),
            self.transactions.clone(),
            self.dyn_props.clone(),
            chain_id,
        )
        .with_evm_stores(self.code.clone(), self.storage_row.clone())
        .with_governance_stores(
            self.witnesses.clone(),
            self.delegation.clone(),
            self.delegated_resources.clone(),
            self.proposals.clone(),
            self.asset_v2.clone(),
            self.exchange_v2.clone(),
        )
        .with_tx_history(self.tx_history.clone())
        .with_transaction_ret(self.transaction_ret.clone())
        .with_account_id_index(self.id_index.clone())
        .with_contract_stores(self.contracts.clone(), self.abi.clone())
        .with_delegated_resource_account_index(self.delegated_resource_account_index.clone())
        .with_market_stores(
            self.market_orders.clone(),
            self.market_account.clone(),
            self.market_pair_to_price.clone(),
            self.market_pair_price_to_order.clone(),
        )
        .with_balance_trace(self.balance_trace.clone())
        .with_assets_v1(self.asset_v1.clone())
        .with_account_assets(self.account_asset.clone())
        .with_nullifiers(self.nullifiers.clone())
        .with_eth_call_backends(tron_rpc::EthCallBackends {
            accounts: self.accounts.clone(),
            code: self.code.clone(),
            storage: self.storage_row.clone(),
            witnesses: self.witnesses.clone(),
            contract_state: self.contract_state.clone(),
            dyn_props: self.dyn_props.clone(),
            delegated_resources: self.delegated_resources.clone(),
            delegation: self.delegation.clone(),
            contracts: self.contracts.clone(),
            block_index: Some(self.block_index.clone()),
        })
        // The mempool is attached externally — see
        // `runtime::run` which constructs a `TxMempool` and shares it
        // with the sync driver. Tests that don't need broadcast can
        // call `.with_mempool(tron_rpc::InMemoryMempool::new())` to
        // re-add the stub.
    }
}

fn open_store(
    root: &Path,
    name: &str,
    tuning: Option<(usize, i32)>,
) -> Result<Arc<dyn KvBackend>, StorageError> {
    let path = root.join(name);
    // java-tron writes a few stores (today just `market_pair_price_to_order`)
    // with a custom RocksDB comparator whose name is recorded in the MANIFEST;
    // a default-comparator open is refused. `comparator_for_store` is the
    // single registry every open path consults so they can't drift.
    let result = match tron_chainbase::comparator_for_store(name) {
        Some((cmp_name, cmp_fn)) => {
            RocksDbBackend::open_with_comparator(&path, tuning, cmp_name, cmp_fn)
        }
        None => match tuning {
            Some((write_buffer_mb, max_open_files)) => {
                RocksDbBackend::open_tuned(&path, write_buffer_mb, max_open_files)
            }
            None => RocksDbBackend::open(&path),
        },
    };
    result
        .map(|b| Arc::new(b) as Arc<dyn KvBackend>)
        .map_err(|e| StorageError::Open {
            path,
            source: e,
        })
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("create dir {path:?}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("open RocksDB {path:?}: {source:?}")]
    Open {
        path: PathBuf,
        source: RocksDbError,
    },
    #[error("store error: {0}")]
    Store(#[from] tron_chainbase::StoreError),
    #[error("kv backend error: {0}")]
    Kv(#[from] tron_chainbase::KvError),
    #[error("incompatible chainbase schema version: on-disk {found}, this binary expects {expected}")]
    SchemaVersion { found: i64, expected: i64 },
}

#[cfg(test)]
mod db_root_tests {
    use super::*;

    #[test]
    fn resolve_db_root_is_java_tron_database_dir() {
        let base = Path::new("/some/data/dir");
        assert_eq!(resolve_db_root(base), base.join("database"));
    }
}

#[cfg(test)]
mod snapshot_stack_tests {
    // Coordinator-level invariants (advance/merge/revoke fan-out,
    // multi-producer mutex semantics, horizon-merge, reorg semantics)
    // are covered by `tests/snapshot_coordinator.rs`. The tests below
    // focus on the startup-recovery path which directly pokes the
    // underlying backends without going through `apply_block`.
    use super::*;
    use tron_chainbase::MemBackend;

    fn build_stack(n: usize) -> (SnapshotStack, Vec<Arc<dyn KvBackend>>) {
        let mut snaps: Vec<(String, Arc<SnapshotKvBackend>)> = Vec::with_capacity(n);
        let mut handles: Vec<Arc<dyn KvBackend>> = Vec::with_capacity(n);
        for i in 0..n {
            let root: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
            let snap = Arc::new(SnapshotKvBackend::new(root));
            handles.push(snap.clone() as Arc<dyn KvBackend>);
            snaps.push((format!("store_{i}"), snap));
        }
        (SnapshotStack::from_named(snaps), handles)
    }

    #[test]
    fn recover_from_checkpoints_replays_orphan_manifests_into_roots() {
        // Simulate a crash: write a checkpoint with two entries
        // directly (bypassing flush_bottom_via_checkpoint), then call
        // recover and verify the roots contain the writes.
        let tmp = tempfile::tempdir().unwrap();
        let cp = tron_chainbase::CheckPointV2::new(tmp.path());
        let (stack, handles) = build_stack(2);
        cp.write(&[
            tron_chainbase::CheckpointEntry {
                db_name: "store_0".into(),
                key: b"recovered_key0".to_vec(),
                value: Some(b"recovered_value0".to_vec()),
            },
            tron_chainbase::CheckpointEntry {
                db_name: "store_1".into(),
                key: b"recovered_key1".to_vec(),
                value: Some(b"recovered_value1".to_vec()),
            },
        ])
        .unwrap();
        let n = stack.recover_from_checkpoints(&cp).unwrap();
        assert_eq!(n, 2);
        // Manifest deleted post-replay.
        assert!(cp.list().unwrap().is_empty());
        // Writes landed in the roots.
        assert_eq!(
            handles[0].get(b"recovered_key0").unwrap().as_deref(),
            Some(b"recovered_value0".as_ref())
        );
        assert_eq!(
            handles[1].get(b"recovered_key1").unwrap().as_deref(),
            Some(b"recovered_value1".as_ref())
        );
    }

    #[test]
    fn recover_handles_tombstone_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let cp = tron_chainbase::CheckPointV2::new(tmp.path());
        let (stack, handles) = build_stack(1);
        // Pre-seed a value the recovery should tombstone.
        handles[0].put(b"to_delete", b"present").unwrap();
        cp.write(&[tron_chainbase::CheckpointEntry {
            db_name: "store_0".into(),
            key: b"to_delete".to_vec(),
            value: None,
        }])
        .unwrap();
        stack.recover_from_checkpoints(&cp).unwrap();
        assert!(handles[0].get(b"to_delete").unwrap().is_none());
    }

    #[test]
    fn recover_ignores_entries_for_unknown_stores() {
        // Manifests may reference store names that don't exist on
        // this node (e.g. config drift between releases). Recovery
        // must not panic; it simply skips them.
        let tmp = tempfile::tempdir().unwrap();
        let cp = tron_chainbase::CheckPointV2::new(tmp.path());
        let (stack, _) = build_stack(1);
        cp.write(&[tron_chainbase::CheckpointEntry {
            db_name: "phantom_store".into(),
            key: b"k".to_vec(),
            value: Some(b"v".to_vec()),
        }])
        .unwrap();
        let n = stack.recover_from_checkpoints(&cp).unwrap();
        assert_eq!(n, 1, "entry was counted even though it had no target");
    }
}
