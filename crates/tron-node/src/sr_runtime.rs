//! Super-Representative (SR) block-production runtime.
//!
//! Mirrors java-tron's `DposTask` — every block-interval tick, check
//! if the node owns the current slot per DPoS, and if so produce +
//! sign + apply + broadcast a block.
//!
//! ## Loop
//!
//! Every 500ms (roughly twice per block interval to keep latency
//! low at the cost of a few wasted polls):
//!
//! 1. Read head info (number, hash, timestamp, genesis timestamp).
//! 2. Compute `slot_from_head(now, head_time, genesis_time, …)` — how
//!    many full slots have elapsed since the head (java `getSlot`,
//!    including the maintenance skip when the head crossed a
//!    maintenance boundary). If zero, sleep until the next slot.
//! 3. Compute `abs_slot = ab_slot(head_time) + slots_since` —
//!    the absolute slot number for the block we'd produce.
//! 4. Load the active witness list. Compute
//!    `scheduled_witness(abs_slot, active_witnesses)`. If it's not
//!    our witness address, this slot belongs to someone else; sleep.
//! 5. Otherwise drain up to `max_txs_per_block` from the mempool,
//!    call [`tron_consensus::produce_block`], apply locally via
//!    [`tron_executor::execute_block_with_undo`], persist to
//!    BlockStore + BlockIndexStore + KhaosDb, and broadcast the
//!    encoded bytes through the `produced_blocks` channel so the
//!    per-peer sync drivers can forward to their peers.
//!
//! ## Concurrency model
//!
//! The runtime shares the durable chain stores (StateBackends,
//! BlockUndoStore, BlockStore, BlockIndexStore) with the per-peer
//! SyncDriver tasks, but keeps its OWN in-memory `KhaosDb` fork tree
//! — the sync-driver fleet shares one tree and a single-applier apply
//! lock among themselves; the SR runtime participates in neither.
//! Each side's own KhaosDb dedup means it's safe for either to apply a
//! block first: if a peer happens to gossip our own produced block
//! back via a different path, that driver's `accept_block` returns
//! `AlreadyKnown` (or `SideFork`) and skips re-execution. There's a
//! thin window where the SR runtime and a peer-driver race on
//! `apply_block` for the same number, but the state writes are
//! idempotent (same block, same outcome) and each side's KhaosDb head
//! re-election leaves only one head-pointer writer, the other a
//! no-op. Serialising this SR-vs-sync apply is a separate, pre-existing
//! concern the fleet apply lock does not cover (witness mode only).

use std::sync::Arc;
use std::time::Duration;

use prost::Message as _;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};
use tron_chainbase::{
    BlockIndexStore, BlockStore, BlockUndoStore, DynamicPropertiesStore, KvBackend,
    WitnessScheduleStore,
};
use tron_consensus::{
    ab_slot, scheduled_witness, slot_from_head, slot_time_ms, KhaosDb, MAINTENANCE_SKIP_SLOTS,
};
use tron_crypto::address::Address;
use tron_executor::{execute_block_with_undo_and_config, StateBackends};

use crate::config::WitnessConfig;

/// Reasonable upper bound on the `produced_blocks` channel buffer.
/// A producer mints at most one block per BLOCK_PRODUCED_INTERVAL_MS
/// (3s on mainnet); buffering 32 lets per-peer drivers tolerate a
/// few minutes of head-of-line stall without dropping outbound
/// frames.
const BROADCAST_CHANNEL_CAPACITY: usize = 32;

/// Default block version field. java-tron currently emits 28; we
/// match so produced blocks look indistinguishable on the wire.
const BLOCK_VERSION: i32 = 28;

/// Loaded + decrypted SR witness identity, ready to sign blocks.
pub struct SrIdentity {
    pub witness_address: Address,
    pub witness_priv_key: [u8; 32],
}

impl std::fmt::Debug for SrIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never expose the private key in debug output — log only
        // the witness address.
        f.debug_struct("SrIdentity")
            .field("witness_address", &self.witness_address)
            .field("witness_priv_key", &"<redacted>")
            .finish()
    }
}

impl SrIdentity {
    /// Resolve a witness identity from both config trees, mirroring
    /// java-tron's `WitnessInitializer.init` precedence:
    ///
    /// 1. `localwitness` private-key list (`LocalWitnessConfig.private_keys`)
    ///    — first entry wins.
    /// 2. `localwitnesskeystore` paths (`LocalWitnessConfig.keystores`)
    ///    — first entry wins, decrypted via the existing
    ///    `tron_wallet::Keystore` path. The password env var is read
    ///    from `WitnessConfig.keystore_password_env` when set.
    /// 3. The typed `WitnessConfig` (our existing tree).
    ///
    /// Returns an error when none of the three are populated, or when
    /// the chosen source fails to resolve.
    pub fn from_node_config(
        local: &crate::config::LocalWitnessConfig,
        witness: &WitnessConfig,
    ) -> Result<Self, SrRuntimeError> {
        use crate::config::LocalWitnessSource;
        match local.source() {
            LocalWitnessSource::PrivateKeys(keys) => {
                let hex = keys.first().ok_or_else(|| {
                    SrRuntimeError::Config("localwitness list is empty".into())
                })?;
                let priv_key = parse_priv_hex(hex)?;
                let witness_address = tron_wallet::address_from_private(&priv_key)
                    .map_err(|e| SrRuntimeError::Config(format!("derive address: {e}")))?;
                Ok(Self {
                    witness_address,
                    witness_priv_key: priv_key,
                })
            }
            LocalWitnessSource::Keystores(paths) => {
                let path = paths.first().ok_or_else(|| {
                    SrRuntimeError::Config("localwitnesskeystore list is empty".into())
                })?;
                let pw_env = witness.keystore_password_env.as_ref().ok_or_else(|| {
                    SrRuntimeError::Config(
                        "witness.keystore_password_env required when \
                         localwitnesskeystore is set"
                            .into(),
                    )
                })?;
                let password = std::env::var(pw_env).map_err(|_| {
                    SrRuntimeError::Config(format!("env var '{pw_env}' not set"))
                })?;
                let ks = tron_wallet::Keystore::load_from_file(std::path::Path::new(path))
                    .map_err(|e| SrRuntimeError::Config(format!("load keystore: {e}")))?;
                let priv_key = ks
                    .decrypt(&password)
                    .map_err(|e| SrRuntimeError::Config(format!("decrypt keystore: {e}")))?;
                let witness_address = tron_wallet::address_from_private(&priv_key)
                    .map_err(|e| SrRuntimeError::Config(format!("derive address: {e}")))?;
                Ok(Self {
                    witness_address,
                    witness_priv_key: priv_key,
                })
            }
            LocalWitnessSource::None => Self::from_config(witness),
        }
    }

    /// Resolve a [`WitnessConfig`] into a usable identity. The
    /// resolution order matches the config doc-string: `keystore`
    /// first (most secure), then `key_env`, then `key_hex` (NOT
    /// recommended). Returns an error if none of the three are set,
    /// or if the chosen source is malformed.
    pub fn from_config(cfg: &WitnessConfig) -> Result<Self, SrRuntimeError> {
        let priv_key = if let Some(keystore_path) = &cfg.keystore {
            let pw_env = cfg.keystore_password_env.as_ref().ok_or_else(|| {
                SrRuntimeError::Config(
                    "witness.keystore_password_env required when witness.keystore is set".into(),
                )
            })?;
            let password = std::env::var(pw_env).map_err(|_| {
                SrRuntimeError::Config(format!("env var '{pw_env}' not set"))
            })?;
            let ks = tron_wallet::Keystore::load_from_file(keystore_path)
                .map_err(|e| SrRuntimeError::Config(format!("load keystore: {e}")))?;
            ks.decrypt(&password)
                .map_err(|e| SrRuntimeError::Config(format!("decrypt keystore: {e}")))?
        } else if let Some(env_name) = &cfg.key_env {
            let hex = std::env::var(env_name).map_err(|_| {
                SrRuntimeError::Config(format!("env var '{env_name}' not set"))
            })?;
            parse_priv_hex(&hex)?
        } else if let Some(hex) = &cfg.key_hex {
            parse_priv_hex(hex)?
        } else {
            return Err(SrRuntimeError::Config(
                "witness config must specify one of: keystore, key_env, key_hex".into(),
            ));
        };
        let witness_address = tron_wallet::address_from_private(&priv_key)
            .map_err(|e| SrRuntimeError::Config(format!("derive address: {e}")))?;
        Ok(Self {
            witness_address,
            witness_priv_key: priv_key,
        })
    }
}

fn parse_priv_hex(s: &str) -> Result<[u8; 32], SrRuntimeError> {
    let s = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    let v = hex::decode(s)
        .map_err(|e| SrRuntimeError::Config(format!("witness key hex decode: {e}")))?;
    if v.len() != 32 {
        return Err(SrRuntimeError::Config(format!(
            "witness key must be 32 bytes, got {}",
            v.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

/// Information about a newly-produced block. Emitted on the
/// `produced_blocks` broadcast channel; per-peer drivers subscribe
/// and forward as a `MessageType::Block` frame.
#[derive(Clone)]
pub struct ProducedBlockNotice {
    pub block_id: tron_types::BlockId,
    pub block_num: i64,
    /// Pre-encoded protobuf bytes — peer drivers just stuff this
    /// directly into a `Frame { ty: Block, payload }`.
    pub encoded: Vec<u8>,
}

/// The SR block-production loop. Constructed once at startup and
/// spawned as a tokio task.
pub struct SrRuntime {
    /// Witness-HA election gate (java `BlockHandleImpl.getState()` →
    /// `BACKUP_IS_NOT_MASTER`). `None` = no backup group configured →
    /// always produce.
    backup: Option<crate::backup::BackupHandle>,
    state: StateBackends,
    blocks_backend: Arc<dyn KvBackend>,
    witness_schedule_backend: Arc<dyn KvBackend>,
    khaos: Arc<KhaosDb>,
    undo_store: BlockUndoStore,
    mempool: Arc<tron_mempool::TxMempool>,
    identity: SrIdentity,
    /// Outbound channel — per-peer drivers subscribe and forward.
    produced_tx: broadcast::Sender<ProducedBlockNotice>,
    max_txs_per_block: usize,
    metrics: Option<Arc<tron_rpc::Metrics>>,
    /// `vm.*` executor knobs (saveInternalTx / vmTrace etc.). Threaded
    /// through to `execute_block_with_undo_and_config` so SR-produced
    /// blocks record traces the same way peer-applied blocks do.
    exec_config: tron_executor::ExecConfig,
    /// Optional shared snapshot coordinator. When attached, SR's
    /// `try_produce` applies its own produced block through
    /// `SnapshotStack::apply_block`, sharing the layer stack and
    /// horizon with any SyncDrivers using the same coordinator. The
    /// coordinator's internal mutex serialises SR's apply against
    /// every peer-driver apply, eliminating the multi-producer race
    /// window. When `None`, SR falls back to the legacy
    /// `BlockUndoStore`-driven apply path.
    snapshot_stack: Option<crate::storage::SnapshotStack>,
    /// Optional cross-store checkpoint manifest. Only used on the
    /// fallback BlockUndoStore path (when no snapshot stack is
    /// attached); the snapshot-stack path provides cross-store
    /// atomicity via its own checkpoint flow.
    checkpoint: Option<tron_chainbase::CheckPointV2>,
    /// Optional WebSocket pubsub broker. When set, every produced
    /// block fires a `newHeads` notification to subscribers.
    pubsub: Option<Arc<tron_rpc::PubSubBroker>>,
    /// Optional address-history index hook — SR-produced blocks
    /// persist their transaction-info + wake the follower, same as
    /// sync-applied blocks (see `crate::index_hook`).
    index_hook: Option<Arc<crate::index_hook::IndexHook>>,
}

impl SrRuntime {
    /// Attach the witness-HA election handle — production is skipped
    /// while this node isn't the backup-group MASTER.
    pub fn with_backup(mut self, backup: crate::backup::BackupHandle) -> Self {
        self.backup = Some(backup);
        self
    }

    /// Construct a fresh runtime. The returned `produced_tx` is the
    /// channel that per-peer drivers must subscribe to; clones are
    /// cheap (tokio broadcast handles are `Arc`-backed internally).
    pub fn new(
        state: StateBackends,
        blocks_backend: Arc<dyn KvBackend>,
        witness_schedule_backend: Arc<dyn KvBackend>,
        khaos: Arc<KhaosDb>,
        undo_store: BlockUndoStore,
        mempool: Arc<tron_mempool::TxMempool>,
        identity: SrIdentity,
        max_txs_per_block: usize,
    ) -> Self {
        let (produced_tx, _) = broadcast::channel(BROADCAST_CHANNEL_CAPACITY);
        Self {
            state,
            blocks_backend,
            witness_schedule_backend,
            khaos,
            undo_store,
            mempool,
            identity,
            produced_tx,
            max_txs_per_block,
            metrics: None,
            exec_config: tron_executor::ExecConfig::default(),
            snapshot_stack: None,
            checkpoint: None,
            pubsub: None,
            index_hook: None,
            backup: None,
        }
    }

    /// Attach a cross-store [`tron_chainbase::CheckPointV2`]. Only
    /// takes effect on the BlockUndoStore path (no snapshot stack).
    pub fn with_checkpoint(mut self, cp: tron_chainbase::CheckPointV2) -> Self {
        self.checkpoint = Some(cp);
        self
    }

    /// Attach a WebSocket pubsub broker so produced blocks publish
    /// `newHeads` notifications.
    pub fn with_pubsub(mut self, broker: Arc<tron_rpc::PubSubBroker>) -> Self {
        self.pubsub = Some(broker);
        self
    }

    /// Attach the address-history index hook (see `crate::index_hook`).
    pub fn with_index_hook(mut self, hook: Arc<crate::index_hook::IndexHook>) -> Self {
        self.index_hook = Some(hook);
        self
    }

    /// Attach a Prometheus metrics sink. When set, produced-block
    /// events bump a counter (operators expect this for SR
    /// monitoring).
    pub fn with_metrics(mut self, metrics: Arc<tron_rpc::Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Override the executor [`tron_executor::ExecConfig`]. The runtime
    /// threads parsed `vm.*` knobs in here so SR-produced blocks record
    /// per-frame traces according to operator config (default off).
    pub fn with_exec_config(mut self, config: tron_executor::ExecConfig) -> Self {
        self.exec_config = config;
        self
    }

    /// Attach the shared [`crate::storage::SnapshotStack`] so SR's
    /// own block apply participates in the coordinator's layer
    /// stack (instead of writing directly to root). Required for
    /// SR + multi-peer reorg parity.
    pub fn with_snapshot_stack(mut self, stack: crate::storage::SnapshotStack) -> Self {
        self.snapshot_stack = Some(stack);
        self
    }

    /// Get a fresh subscriber for the produced-blocks channel. Each
    /// per-peer driver task calls this once at startup and `recv`s
    /// in its select loop.
    pub fn subscribe(&self) -> broadcast::Receiver<ProducedBlockNotice> {
        self.produced_tx.subscribe()
    }

    /// Get the broadcast sender so the runtime can be moved into a
    /// task while the per-peer drivers still subscribe. Returns a
    /// clone — `Sender::subscribe()` works on the clone.
    pub fn subscribe_handle(&self) -> broadcast::Sender<ProducedBlockNotice> {
        self.produced_tx.clone()
    }

    /// Run one production attempt synchronously without spinning up
    /// the ticker loop. Intended for integration tests. Production
    /// code should `spawn` [`run`] instead, which drives this from a
    /// 500ms tokio interval.
    ///
    /// [`run`]: SrRuntime::run
    pub fn try_produce_for_test(
        &self,
        last_produced_slot: i64,
    ) -> Result<Option<ProducedBlockNotice>, SrRuntimeError> {
        let result = self.try_produce(last_produced_slot)?;
        if let Some(notice) = &result {
            // Also push through the broadcast channel so test
            // subscribers see the same flow production would.
            let _ = self.produced_tx.send(notice.clone());
        }
        Ok(result)
    }

    /// Test-only handle to the mempool.
    pub fn mempool_handle_for_test(&self) -> Arc<tron_mempool::TxMempool> {
        self.mempool.clone()
    }

    /// Run the production loop until `shutdown` fires. Polls every
    /// 500ms. Designed to be spawned as `tokio::spawn(runtime.run(rx))`.
    pub async fn run(self, mut shutdown: broadcast::Receiver<()>) {
        info!(
            witness = %tron_crypto::base58check::encode_address(&self.identity.witness_address),
            "SR runtime started"
        );
        // Track the last absolute slot we produced for; prevents
        // emitting two blocks for the same slot if the poll catches
        // the boundary twice in one slot.
        let mut last_produced_slot: i64 = i64::MIN;
        let mut ticker = tokio::time::interval(Duration::from_millis(500));
        loop {
            tokio::select! {
                _ = shutdown.recv() => {
                    info!("SR runtime shutting down");
                    break;
                }
                _ = ticker.tick() => {
                    match self.try_produce(last_produced_slot) {
                        Ok(Some(notice)) => {
                            last_produced_slot = notice.block_num;
                            // Best-effort broadcast — `send` errors only if
                            // there are no live receivers, which happens
                            // before any peer driver attaches. We log at
                            // debug to avoid noise during boot.
                            if let Err(e) = self.produced_tx.send(notice.clone()) {
                                debug!(error = %e, "no subscribers for produced-blocks channel");
                            }
                            info!(
                                block_num = notice.block_num,
                                hash = %hex::encode(&notice.block_id.as_bytes()[..8]),
                                "produced block"
                            );
                            if let Some(m) = &self.metrics {
                                m.inc_blocks_applied();
                                m.inc_sr_blocks_produced();
                                m.set_head_block_number(notice.block_num);
                            }
                        }
                        Ok(None) => {
                            // Not our slot, or no head yet. Continue.
                        }
                        Err(e) => {
                            warn!(error = %e, "SR runtime produce attempt failed");
                            if let Some(m) = &self.metrics {
                                m.inc_sr_produce_failures();
                            }
                        }
                    }
                }
            }
        }
    }

    /// One production attempt. Returns `Ok(Some(notice))` when a
    /// block was produced; `Ok(None)` when this isn't our slot (or
    /// we can't determine ownership yet); `Err(_)` on a true
    /// failure (apply failed, mempool drain failed, etc.).
    fn try_produce(
        &self,
        last_produced_slot: i64,
    ) -> Result<Option<ProducedBlockNotice>, SrRuntimeError> {
        // Witness HA: only the backup-group MASTER may produce (java
        // checks BackupManager status before every attempt).
        if let Some(backup) = &self.backup {
            if !backup.is_master() {
                return Ok(None);
            }
        }

        let dp = DynamicPropertiesStore::new(self.state.dyn_props.clone());

        // Need a head and a genesis time to compute slots.
        let Some(head_num) = dp.latest_block_header_number() else {
            return Ok(None);
        };
        let Some(head_hash_bytes) = dp
            .latest_block_header_hash()
            .map_err(|e| SrRuntimeError::Storage(format!("read head hash: {e}")))?
        else {
            return Ok(None);
        };
        let head_id = tron_types::BlockId::from_raw(head_hash_bytes);
        let Some(head_time) = dp.latest_block_header_timestamp() else {
            return Ok(None);
        };
        let genesis_time = dp.genesis_block_timestamp().unwrap_or(0);
        // java `consensusDelegate.lastHeadBlockIsMaintenance()` =
        // `getStateFlag() == 1`. When the head block crossed a maintenance
        // boundary `DposSlot.getTime` adds `MAINTENANCE_SKIP_SLOTS`, so both
        // the relative slot (`getSlot`) and the produced block time
        // (`getTime(slot)`) must account for it — without the skip a
        // producer fires for the wrong slot/witness right after maintenance.
        let head_was_maintenance = dp.state_flag() == 1;

        // Compute the relative slot since the head (java `getSlot`).
        let now_ms = current_time_ms();
        let slots_since = slot_from_head(
            now_ms,
            head_time,
            genesis_time,
            head_was_maintenance,
            MAINTENANCE_SKIP_SLOTS,
        );
        if slots_since < 1 {
            // Haven't crossed into the next slot yet.
            return Ok(None);
        }
        // java `getScheduledWitness(slot)` indexes
        // `active[(getAbSlot(headTime) + slot) % size]`; `target_slot` is
        // that `currentSlot`. The maintenance skip is already folded into
        // `slots_since`, so it must NOT be added again here.
        let head_abs_slot = ab_slot(head_time, genesis_time);
        let target_slot = head_abs_slot + slots_since;
        if target_slot <= last_produced_slot {
            // Already produced for this slot this poll-cycle.
            return Ok(None);
        }

        // Load the active witness list.
        let schedule = WitnessScheduleStore::new(self.witness_schedule_backend.clone());
        let active = schedule
            .load_active()
            .map_err(|e| SrRuntimeError::Storage(format!("load active witnesses: {e}")))?
            .unwrap_or_default();
        if active.is_empty() {
            // No active witnesses loaded yet — chain is pre-genesis
            // maintenance or schedule isn't populated. Skip.
            return Ok(None);
        }

        // Whose slot is it?
        let scheduled = scheduled_witness(target_slot, &active);
        if scheduled != self.identity.witness_address {
            return Ok(None);
        }

        // The block's timestamp is java's `dposSlot.getTime(slot)`: the
        // head timestamp aligned DOWN to the 3s grid, plus
        // `(slots_since + maintenance_skip) * interval`. We use the slot
        // time (not `now_ms`) so produced timestamps land exactly on the
        // schedule grid, and route through `slot_time_ms` so the
        // maintenance skip + head alignment match java byte-for-byte —
        // the prior `head_time + slots_since * interval` dropped both.
        let block_time = slot_time_ms(
            slots_since,
            head_time,
            genesis_time,
            head_was_maintenance,
            MAINTENANCE_SKIP_SLOTS,
        );

        // Drain mempool: pull up to max_txs_per_block tx ids; only
        // keep ones still in the mempool's pending map (race-safe).
        //
        // The count cap is ours; the BYTE cap is java's and is what the rest of
        // the network enforces. java `Manager.generateBlock` tracks a running
        // serialized size against `ChainConstant.BLOCK_SIZE` and skips any
        // transaction that would overflow it, continuing down the queue so
        // smaller transactions still get packed. Every java peer drops a block
        // message larger than `BLOCK_SIZE + 1000` in `BlockMsgHandler` before
        // validating it, so a block produced past the budget would be orphaned
        // network-wide however valid it is.
        let pending_ids = self.mempool.pending_ids();
        let mut txs = Vec::with_capacity(pending_ids.len().min(self.max_txs_per_block));
        // java seeds `currentSize` with the header-only block's serialized size.
        let mut current_size = tron_consensus::producer::assemble_block(
            &head_id,
            head_num + 1,
            block_time,
            &self.identity.witness_address,
            Vec::new(),
            BLOCK_VERSION,
        )
        .map(|b| b.encoded_len())
        .unwrap_or(0);
        for id in pending_ids.iter().take(self.max_txs_per_block) {
            if let Some(p) = self.mempool.get(id) {
                let pack_size = tron_consensus::tx_pack_size(p.tx.encoded_len());
                if !tron_consensus::tx_fits_in_block(current_size, pack_size) {
                    continue;
                }
                current_size += pack_size;
                txs.push(p.tx);
            }
        }
        let _tx_count = txs.len();

        // Decide whether we need to embed `account_state_root` in the
        // header. Mainnet has `ALLOW_ACCOUNT_STATE_ROOT == 0`, so the
        // fast path is `None`. When the flag is on (testnets, future
        // mainnet upgrade), dry-run-apply the assembled block, compute
        // the state root, and embed it before signing.
        let state_root_enabled = dp
            .get_long(b"ALLOW_ACCOUNT_STATE_ROOT")
            .unwrap_or(0)
            == 1;
        let account_state_root: Option<[u8; 32]> = if state_root_enabled {
            // Build an UNSIGNED block first so the dry-run apply can run
            // (verify_witness_signature is skipped on empty sigs). We
            // use `assemble_block` directly + then re-produce with the
            // root embedded + sign.
            let unsigned = tron_consensus::producer::assemble_block(
                &head_id,
                head_num + 1,
                block_time,
                &self.identity.witness_address,
                txs.clone(),
                BLOCK_VERSION,
            )
            .map_err(|e| SrRuntimeError::Produce(format!("{e:?}")))?;
            let root = tron_executor::dry_run_for_state_root(
                &self.state,
                &unsigned,
                Some(head_id),
            )
            .map_err(|e| {
                SrRuntimeError::Produce(format!("dry-run for state root: {e:?}"))
            })?;
            Some(root)
        } else {
            None
        };

        // Produce + sign (with state root if computed).
        let (block, block_id) = tron_consensus::producer::produce_block_with_state_root(
            &head_id,
            head_num + 1,
            block_time,
            &self.identity.witness_address,
            &self.identity.witness_priv_key,
            txs,
            BLOCK_VERSION,
            account_state_root,
        )
        .map_err(|e| SrRuntimeError::Produce(format!("{e:?}")))?;

        // Push into KhaosDb first so dedup works against any peer
        // gossip that comes back.
        if let Err(e) = self.khaos.push(block.clone()) {
            // BadNumber / Malformed are not recoverable; Unlinked means
            // the KhaosDb hasn't been seeded yet (first block of the
            // session). The KhaosDb seeder lives in SyncDriver; if
            // we're producing without any peers, start it manually.
            match e {
                tron_consensus::KhaosPushError::Unlinked => {
                    // Try to seed.
                    if self.khaos.head().is_none() {
                        let _ = self.khaos.start(block.clone());
                    }
                }
                other => return Err(SrRuntimeError::Produce(format!("khaos.push: {other:?}"))),
            }
        }

        // Persist to BlockStore + BlockIndex.
        BlockStore::new(self.blocks_backend.clone()).put(&block_id, &block)?;
        if let Some(bi_be) = &self.state.block_index {
            BlockIndexStore::new(bi_be.clone()).put(&block_id)?;
        }

        // Apply state. When the snapshot coordinator is attached,
        // SR's produced block goes through the same layer stack as
        // peer-applied blocks — the coordinator's internal mutex
        // serialises SR's apply against every per-peer SyncDriver
        // apply, eliminating the multi-producer race window. The
        // legacy path (no coordinator) keeps the `BlockUndoStore`
        // undo-log for reorg support.
        let block_num = head_num + 1;
        let exec_report = match &self.snapshot_stack {
            Some(stack) => {
                let state = &self.state;
                let exec_config = &self.exec_config;
                let block_ref = &block;
                stack
                    .apply_block(block_num, || {
                        tron_executor::execute_block_with_config(
                            state, block_ref, Some(head_id), exec_config,
                        )
                        .map_err(|e| format!("{e:?}"))
                    })
                    .map_err(SrRuntimeError::Execute)?
            }
            None => match &self.checkpoint {
                Some(cp) => tron_executor::execute_block_with_undo_checkpoint_and_config(
                    &self.state,
                    &block,
                    Some(head_id),
                    &self.undo_store,
                    cp,
                    &self.exec_config,
                    None,
                )
                .map_err(|e| SrRuntimeError::Execute(format!("{e:?}")))?,
                None => execute_block_with_undo_and_config(
                    &self.state,
                    &block,
                    Some(head_id),
                    &self.undo_store,
                    &self.exec_config,
                    None,
                )
                .map_err(|e| SrRuntimeError::Execute(format!("{e:?}")))?,
            },
        };

        // Remove the txs we just included from the mempool so they
        // don't get re-broadcast.
        for tx in &block.transactions {
            if let Some(raw) = &tx.raw_data {
                use prost::Message as _;
                let id = tron_crypto::hash::sha256(&raw.encode_to_vec());
                self.mempool.remove(&id);
            }
        }

        // Publish the newly-produced block to WebSocket
        // subscribers — both `newHeads` and per-log `logs`.
        if let Some(broker) = &self.pubsub {
            broker.publish_head(tron_rpc::pubsub::head_event_from_block(
                &block,
                block_id.as_bytes(),
            ));
            let block_hash = *block_id.as_bytes();
            for tx_result in &exec_report.tx_results {
                for (log_index, vm_log) in tx_result.vm_logs.iter().enumerate() {
                    broker.publish_log(tron_rpc::pubsub::log_event_from_vm_log(
                        vm_log,
                        block_num,
                        &block_hash,
                        &tx_result.tx_id,
                        log_index,
                    ));
                }
            }
        }

        // Persist the produced block's transaction-info + wake the
        // index follower (no-op when the index is disabled).
        if let Some(hook) = &self.index_hook {
            hook.on_block_applied(&block, &block_id, &exec_report);
        }

        // Encode for broadcast.
        let encoded = tron_consensus::encode_for_broadcast(&block);
        Ok(Some(ProducedBlockNotice {
            block_id,
            block_num: head_num + 1,
            encoded,
        }))
    }
}

fn current_time_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[derive(Debug, thiserror::Error)]
pub enum SrRuntimeError {
    #[error("config: {0}")]
    Config(String),
    #[error("storage: {0}")]
    Storage(String),
    #[error("produce: {0}")]
    Produce(String),
    #[error("execute: {0}")]
    Execute(String),
}

impl From<tron_chainbase::StoreError> for SrRuntimeError {
    fn from(e: tron_chainbase::StoreError) -> Self {
        Self::Storage(e.to_string())
    }
}

impl From<tron_chainbase::KvError> for SrRuntimeError {
    fn from(e: tron_chainbase::KvError) -> Self {
        Self::Storage(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_priv_hex_accepts_0x_prefix_and_bare() {
        assert!(parse_priv_hex(
            "0x1234567890123456789012345678901234567890123456789012345678901234"
        )
        .is_ok());
        assert!(parse_priv_hex(
            "1234567890123456789012345678901234567890123456789012345678901234"
        )
        .is_ok());
    }

    #[test]
    fn parse_priv_hex_rejects_wrong_length() {
        assert!(parse_priv_hex("0xdeadbeef").is_err());
    }

    #[test]
    fn parse_priv_hex_trims_whitespace() {
        // Useful when reading from a file with a trailing newline.
        let s = "  0x1234567890123456789012345678901234567890123456789012345678901234\n";
        assert!(parse_priv_hex(s).is_ok());
    }

    #[test]
    fn from_config_errors_when_no_source_given() {
        let cfg = WitnessConfig::default();
        let err = SrIdentity::from_config(&cfg).unwrap_err();
        match err {
            SrRuntimeError::Config(msg) => {
                assert!(msg.contains("witness config must specify"));
            }
            other => panic!("expected Config error, got {other:?}"),
        }
    }

    #[test]
    fn from_config_with_inline_hex_derives_correct_address() {
        let cfg = WitnessConfig {
            key_hex: Some(
                "1234567890123456789012345678901234567890123456789012345678901234".into(),
            ),
            ..Default::default()
        };
        let identity = SrIdentity::from_config(&cfg).expect("identity");
        // This is the canonical ALICE keypair used elsewhere in the
        // test suite — the derived address is 412e988a... (TRON form).
        assert_eq!(
            tron_crypto::base58check::encode_address(&identity.witness_address),
            "TEDapYSVvAZ3aYH7w8N9tMEEFKaNKUD5Bp"
        );
    }

    // ────────────────────────────────────────────────────────────
    // LocalWitnessConfig integration (java-tron parity for
    // `localwitness` / `localwitnesskeystore` top-level keys).
    // ────────────────────────────────────────────────────────────

    #[test]
    fn from_node_config_falls_back_to_witness_when_local_is_empty() {
        let local = crate::config::LocalWitnessConfig::default();
        let cfg = WitnessConfig {
            key_hex: Some(
                "1234567890123456789012345678901234567890123456789012345678901234".into(),
            ),
            ..Default::default()
        };
        let identity = SrIdentity::from_node_config(&local, &cfg).expect("identity");
        assert_eq!(
            tron_crypto::base58check::encode_address(&identity.witness_address),
            "TEDapYSVvAZ3aYH7w8N9tMEEFKaNKUD5Bp"
        );
    }

    #[test]
    fn from_node_config_prefers_localwitness_private_keys_over_witness_config() {
        // `localwitness` takes precedence over the WitnessConfig tree.
        // The derived address from the local key (0x1234…234) must
        // appear, NOT the address derived from a different key in
        // WitnessConfig.
        let local = crate::config::LocalWitnessConfig {
            private_keys: vec![
                "1234567890123456789012345678901234567890123456789012345678901234".into(),
            ],
            ..Default::default()
        };
        // Different key in WitnessConfig — must be ignored.
        let cfg = WitnessConfig {
            key_hex: Some(
                "abababababababababababababababababababababababababababababababab".into(),
            ),
            ..Default::default()
        };
        let identity = SrIdentity::from_node_config(&local, &cfg).expect("identity");
        assert_eq!(
            tron_crypto::base58check::encode_address(&identity.witness_address),
            "TEDapYSVvAZ3aYH7w8N9tMEEFKaNKUD5Bp",
            "must derive from localwitness, not WitnessConfig"
        );
    }

    #[test]
    fn from_node_config_rejects_malformed_local_private_key() {
        let local = crate::config::LocalWitnessConfig {
            private_keys: vec!["not-a-hex".into()],
            ..Default::default()
        };
        let cfg = WitnessConfig::default();
        let err = SrIdentity::from_node_config(&local, &cfg).unwrap_err();
        assert!(matches!(err, SrRuntimeError::Config(_)));
    }

    #[test]
    fn from_node_config_with_neither_source_errors_with_witness_required_msg() {
        let local = crate::config::LocalWitnessConfig::default();
        let cfg = WitnessConfig::default();
        let err = SrIdentity::from_node_config(&local, &cfg).unwrap_err();
        match err {
            SrRuntimeError::Config(msg) => {
                assert!(msg.contains("witness config must specify"));
            }
            other => panic!("expected Config error, got {other:?}"),
        }
    }

    #[test]
    fn from_node_config_keystore_path_requires_password_env() {
        // localwitnesskeystore set but `keystore_password_env` is not
        // → clear configuration error before we try to load the file.
        let local = crate::config::LocalWitnessConfig {
            keystores: vec!["/tmp/no-such-keystore.json".into()],
            ..Default::default()
        };
        let cfg = WitnessConfig::default();
        let err = SrIdentity::from_node_config(&local, &cfg).unwrap_err();
        match err {
            SrRuntimeError::Config(msg) => {
                assert!(
                    msg.contains("keystore_password_env"),
                    "should surface missing-password-env error; got: {msg}"
                );
            }
            other => panic!("expected Config error, got {other:?}"),
        }
    }
}
