//! PBFT vote-driving runtime for the local Super Representative.
//!
//! Spawned alongside the SR runtime when `config.witness` is set.
//! Owns the per-block vote tally; consumes inbound `PbftMessage`s
//! observed on the wire (fed by SyncDriver tasks); emits outbound
//! `PbftMessage`s (Prepare/Commit) on a broadcast channel that each
//! SyncDriver subscribes to and forwards as `MessageType::PbftMsg`
//! frames.
//!
//! ## State machine per block at height N
//!
//! ```text
//! Initial:                       no votes seen
//! On first sight of block N:     broadcast our Prepare
//! On 2/3+ Prepare for N:         broadcast our Commit
//! On 2/3+ Commit for N:          persist signatures to
//!                                PbftSignDataStore[BLOCK<N>]; bump
//!                                LATEST_SOLIDIFIED_BLOCK_NUM
//! ```
//!
//! Active SR set membership: each inbound message is checked against
//! the current `WitnessScheduleStore::load_active` list. java-tron
//! does NOT persist per-cycle SR snapshots in this store either — it
//! keeps the previous SR set only in-memory (`MaintenanceManager`'s
//! `getBeforeWitness` / `getCurrentWitness`). A vote signed by the
//! pre-rotation SR set and delivered after maintenance will be
//! rejected here; closing that narrow window means sharing an
//! in-memory before/current snapshot with the executor — separate
//! work item.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;
use tracing::{debug, info, warn};
use tron_chainbase::{DynamicPropertiesStore, KvBackend, PbftSignDataStore, WitnessScheduleStore};
use tron_consensus::pbft::{
    block_data_payload, cast_commit, cast_prepare, parse_block_data_payload, recover_signer,
    srl_data_payload, EquivocationDetector, EquivocationEvidence, PbftVoteTally, VoteRecord,
};
use tron_consensus::SharedSrEpochSnapshot;
use std::time::Duration;
use tron_crypto::address::Address;
use tron_proto::protocol::pbft_message::{DataType, MsgType, Raw as PbftRaw};
use tron_proto::protocol::PbftMessage;

use crate::sr_runtime::SrIdentity;

fn current_time_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

const BROADCAST_CHANNEL_CAPACITY: usize = 256;

/// Inbound + outbound PBFT message broadcasters owned by the runtime.
#[derive(Clone)]
pub struct PbftChannels {
    /// SyncDriver pushes every observed PbftMessage here.
    pub inbound: broadcast::Sender<PbftMessage>,
    /// SyncDriver subscribes; forwards each msg as `MessageType::PbftMsg`.
    pub outbound: broadcast::Sender<PbftMessage>,
}

impl PbftChannels {
    pub fn new() -> Self {
        let (inbound, _) = broadcast::channel(BROADCAST_CHANNEL_CAPACITY);
        let (outbound, _) = broadcast::channel(BROADCAST_CHANNEL_CAPACITY);
        Self { inbound, outbound }
    }
}

impl Default for PbftChannels {
    fn default() -> Self {
        Self::new()
    }
}

/// The PBFT vote-driving runtime.
pub struct PbftRuntime {
    state_dyn_props: Arc<dyn KvBackend>,
    witness_schedule: Arc<dyn KvBackend>,
    pbft_sign_data: Arc<dyn KvBackend>,
    /// Optional `common-database` backend. When attached, every PBFT
    /// commit-threshold crossing writes the block number into
    /// `LATEST_PBFT_BLOCK_NUM` — matching java-tron's behaviour at
    /// `PbftMessageAction.action()`. Without this, the entire chain
    /// stays consistent but external tooling that reads PBFT-block-num
    /// (block explorers, light clients) won't see the field populated.
    common_database: Option<Arc<dyn KvBackend>>,
    identity: SrIdentity,
    channels: PbftChannels,
    tally: Arc<Mutex<PbftVoteTally>>,
    /// Separate tally for SRL (witness-list rotation) PBFT. Keyed by
    /// epoch instead of block hash — there's at most one SRL vote
    /// per cycle.
    srl_tally: Arc<Mutex<PbftVoteTally>>,
    /// Last cycle for which we've broadcast an SRL Prepare. Tracked
    /// so the periodic check doesn't keep re-casting.
    last_srl_cycle: Arc<Mutex<i64>>,
    /// How many blocks of vote history to keep. Older entries are
    /// pruned on every commit-threshold check. Default 1024 — same
    /// horizon as KhaosDb.
    history_cap: i64,
    /// Optional cross-rotation SR snapshot. When attached, the active-
    /// set lookup consults this in preference to
    /// `WitnessScheduleStore::load_active()` so votes signed by the
    /// pre-rotation SR set during the brief post-maintenance window
    /// are accepted (matches java-tron's
    /// `PbftManager.verifyMsg` with `getBeforeWitness`). When `None`,
    /// behaviour falls back to the on-disk active list — same
    /// (slightly narrower) acceptance window the runtime had before.
    sr_snapshot: Option<SharedSrEpochSnapshot>,
    /// Cross-payload equivocation detector. Every SR-signed inbound
    /// message routes through this BEFORE the per-block tally update,
    /// so cross-block double-signing is caught regardless of which
    /// payload the votes target. Evidence is retained in a bounded
    /// FIFO pool; consumers retrieve it via
    /// [`drain_equivocation_evidence`].
    equivocation: Arc<Mutex<EquivocationDetector>>,
    /// Counter of received `VIEW_CHANGE` messages. java-tron's
    /// `onChangeView` is a no-op; we mirror but increment this counter
    /// so the data is exposed for metrics/observability. Operators
    /// who see this climb know peers are attempting view-changes.
    view_change_count: Arc<Mutex<u64>>,
    /// Optional metrics sink. Production wires this; tests usually skip.
    metrics: Option<Arc<tron_rpc::Metrics>>,
}

impl PbftRuntime {
    pub fn new(
        state_dyn_props: Arc<dyn KvBackend>,
        witness_schedule: Arc<dyn KvBackend>,
        pbft_sign_data: Arc<dyn KvBackend>,
        identity: SrIdentity,
        channels: PbftChannels,
    ) -> Self {
        Self {
            state_dyn_props,
            witness_schedule,
            pbft_sign_data,
            common_database: None,
            identity,
            channels,
            tally: Arc::new(Mutex::new(PbftVoteTally::new())),
            srl_tally: Arc::new(Mutex::new(PbftVoteTally::new())),
            last_srl_cycle: Arc::new(Mutex::new(0)),
            history_cap: 1024,
            sr_snapshot: None,
            equivocation: Arc::new(Mutex::new(EquivocationDetector::default())),
            view_change_count: Arc::new(Mutex::new(0)),
            metrics: None,
        }
    }

    /// Attach a metrics sink. Bumps inbound message + Prepare/Commit
    /// emit counters that surface on the Prometheus `/metrics` endpoint.
    pub fn with_metrics(mut self, metrics: Arc<tron_rpc::Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Drain the equivocation evidence pool. Returns full
    /// `EquivocationEvidence` records (each containing the two signed
    /// `PbftMessage`s) and clears the internal buffer. Intended for an
    /// RPC accessor or a governance-proposal pipeline.
    pub fn drain_equivocation_evidence(&self) -> Vec<EquivocationEvidence> {
        let mut det = self.equivocation.lock().unwrap();
        det.drain_evidence()
    }

    /// Snapshot the count of evidence currently buffered (without
    /// draining). Useful for metrics.
    pub fn equivocation_evidence_count(&self) -> usize {
        self.equivocation.lock().unwrap().evidence_count()
    }

    /// Total number of `VIEW_CHANGE` messages observed since startup.
    /// java-tron's handler is empty; we expose this counter for
    /// observability so operators can detect view-change storms.
    pub fn view_change_count(&self) -> u64 {
        *self.view_change_count.lock().unwrap()
    }

    /// Attach the cross-rotation SR snapshot. The snapshot is shared
    /// with the sync driver, which writes the post-maintenance `before`
    /// + `current` lists into it as each block applies. The PBFT
    /// runtime reads it to validate inbound votes — see
    /// [`load_active_set_for_epoch`].
    pub fn with_sr_snapshot(mut self, snap: SharedSrEpochSnapshot) -> Self {
        self.sr_snapshot = Some(snap);
        self
    }

    /// Attach the `common-database` backend so PBFT-committed block
    /// numbers get written to `LATEST_PBFT_BLOCK_NUM` (java-tron's
    /// `CommonDataBase`). Production callers should always attach this.
    pub fn with_common_database(mut self, backend: Arc<dyn KvBackend>) -> Self {
        self.common_database = Some(backend);
        self
    }

    /// Get a handle to the inbound channel for SyncDriver wiring.
    pub fn inbound_sender(&self) -> broadcast::Sender<PbftMessage> {
        self.channels.inbound.clone()
    }

    /// Get a handle to the outbound channel for SyncDriver wiring.
    pub fn outbound_sender(&self) -> broadcast::Sender<PbftMessage> {
        self.channels.outbound.clone()
    }

    /// Spawn the runtime loop. Drives inbound messages until
    /// `shutdown` fires. Also runs a 1Hz timer mirroring java-tron's
    /// `PbftMessageHandle.start()`: stuck votes (60s without commit
    /// threshold) get pruned via [`PbftVoteTally::expire_stale`].
    pub async fn run(self, mut shutdown: broadcast::Receiver<()>) {
        info!(
            witness = %tron_crypto::base58check::encode_address(&self.identity.witness_address),
            "PBFT runtime started"
        );
        let mut inbound_rx = self.channels.inbound.subscribe();
        let mut timeout_ticker = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = shutdown.recv() => {
                    info!("PBFT runtime shutting down");
                    break;
                }
                _ = timeout_ticker.tick() => {
                    let now = current_time_ms();
                    let dropped = {
                        let mut t = self.tally.lock().unwrap();
                        t.expire_stale(now)
                    };
                    if dropped > 0 {
                        debug!(dropped, "PBFT vote-timeout sweep");
                    }
                    let srl_dropped = {
                        let mut t = self.srl_tally.lock().unwrap();
                        t.expire_stale(now)
                    };
                    if srl_dropped > 0 {
                        debug!(srl_dropped, "SRL PBFT timeout sweep");
                    }
                    // Check whether the chain advanced to a new cycle
                    // since we last broadcast our SRL — if so, fire a
                    // fresh SRL Prepare.
                    self.maybe_cast_srl_on_cycle_advance();
                }
                msg = inbound_rx.recv() => match msg {
                    Ok(m) => {
                        if let Some(metrics) = &self.metrics {
                            metrics.inc_pbft_messages_received();
                        }
                        if let Err(e) = self.handle_inbound(&m) {
                            warn!(error = %e, "PBFT inbound handling failed");
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!(dropped = n, "PBFT inbound channel lagged");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }

    /// Locally observe a freshly-produced/applied block: cast our
    /// Prepare vote and broadcast it. Idempotent — calling twice for
    /// the same block does nothing the second time.
    pub fn on_local_block(
        &self,
        block_num: i64,
        block_hash: [u8; 32],
        epoch: i64,
    ) -> Result<(), PbftRuntimeError> {
        let data = block_data_payload(block_num, &block_hash);
        let already = {
            let mut t = self.tally.lock().unwrap();
            let entry = t.entry_with_time(data.clone(), current_time_ms());
            std::mem::replace(&mut entry.broadcast_prepare, true)
        };
        if already {
            return Ok(());
        }
        let msg = cast_prepare(
            &self.identity.witness_priv_key,
            epoch,
            0,
            DataType::Block,
            data,
        )
        .map_err(|e| PbftRuntimeError::Sign(format!("{e:?}")))?;
        // Record our own vote in the tally so threshold counts include
        // it.
        if let Some(raw) = msg.raw_data.as_ref() {
            let mut t = self.tally.lock().unwrap();
            let entry = t.entry_with_time(raw.data.clone(), current_time_ms());
            entry.record_prepare(
                self.identity.witness_address,
                msg.signature.clone(),
            );
        }
        let _ = self.channels.outbound.send(msg);
        if let Some(metrics) = &self.metrics {
            metrics.inc_pbft_prepares_sent();
        }
        Ok(())
    }

    /// Handle one inbound `PbftMessage`. Recovers the signer,
    /// membership-checks against the current active SR set, updates
    /// the tally, advances to the next phase if a threshold crossed.
    fn handle_inbound(&self, msg: &PbftMessage) -> Result<(), PbftRuntimeError> {
        let Some(raw) = msg.raw_data.as_ref() else {
            return Err(PbftRuntimeError::Malformed("missing raw_data".into()));
        };
        // Route by DataType. SRL has its own state machine (one vote
        // per cycle, key the tally by epoch). Block uses the per-
        // block tally.
        if raw.data_type == DataType::Srl as i32 {
            return self.handle_srl_inbound(msg, raw);
        }
        if raw.data_type != DataType::Block as i32 {
            // Unknown data type — drop silently.
            return Ok(());
        }
        let (_block_num, _block_hash) = parse_block_data_payload(&raw.data)
            .ok_or_else(|| PbftRuntimeError::Malformed("bad data payload".into()))?;
        let Some(signer) = recover_signer(msg) else {
            return Err(PbftRuntimeError::Malformed("signature recovery failed".into()));
        };

        // Look up the active SR set AT THIS MESSAGE'S EPOCH (not the
        // current one — the SR rotation may have advanced since the
        // block was produced). Falls back to current active list when
        // no per-cycle snapshot exists (e.g. epoch < first
        // maintenance, or epoch was pruned).
        let active = self.load_active_set_for_epoch(raw.epoch)?;
        if !active.contains(&signer) {
            // Non-SR sender — drop silently. This is expected during
            // gossip when a full node forwards messages from SRs.
            return Ok(());
        }

        // Cross-payload equivocation check. Runs BEFORE the per-block
        // tally update so two votes for different blocks at the same
        // (epoch, view_n, msg_type) — which land in different
        // BlockVoteTallys — are correlated. Evidence is retained in
        // the bounded pool until drained.
        self.record_equivocation_if_any(signer, msg);

        let msg_type = match MsgType::try_from(raw.msg_type) {
            Ok(t) => t,
            Err(_) => return Ok(()),
        };

        match msg_type {
            MsgType::Prepare => self.handle_prepare(raw, signer, &msg.signature, &active),
            MsgType::Commit => self.handle_commit(raw, signer, &msg.signature, &active),
            // Preprepare from the slot's producer ⇒ trigger our own
            // Prepare.
            MsgType::Preprepare => {
                let (block_num, block_hash) =
                    parse_block_data_payload(&raw.data).unwrap_or((0, [0u8; 32]));
                self.on_local_block(block_num, block_hash, raw.epoch)
            }
            // VIEW_CHANGE: java-tron's onChangeView is an empty method
            // (PbftMessageHandle.java:224-226). We mirror by logging
            // and bumping a counter so the receipt is visible to
            // operators (e.g., a view-change storm signals byzantine
            // peers). The protocol does not need view-change to
            // advance — DPoS rotates leaders every slot.
            MsgType::ViewChange => self.handle_view_change(signer, raw.epoch),
            MsgType::Request => Ok(()),
        }
    }

    /// Push `msg` through the cross-payload equivocation detector.
    /// Logs loudly and retains evidence in the pool when a fresh
    /// detection fires. Safe to call for every inbound msg — the
    /// detector dedups identical re-sends internally.
    fn record_equivocation_if_any(&self, signer: Address, msg: &PbftMessage) {
        let outcome = {
            let mut det = self.equivocation.lock().unwrap();
            det.record(signer, msg)
        };
        if let Some(ev) = outcome {
            warn!(
                signer = %tron_crypto::base58check::encode_address(&ev.signer),
                epoch = ev.epoch,
                view_n = ev.view_n,
                msg_type = ev.msg_type,
                data_type = ev.data_type,
                first_data = %hex::encode(
                    &ev.first.raw_data.as_ref().map(|r| r.data.clone()).unwrap_or_default()
                ),
                conflicting_data = %hex::encode(
                    &ev.conflicting
                        .raw_data
                        .as_ref()
                        .map(|r| r.data.clone())
                        .unwrap_or_default()
                ),
                "PBFT EQUIVOCATION (cross-payload double-sign): SR signed two conflicting payloads"
            );
        }
    }

    fn handle_view_change(&self, signer: Address, epoch: i64) -> Result<(), PbftRuntimeError> {
        {
            let mut c = self.view_change_count.lock().unwrap();
            *c = c.saturating_add(1);
        }
        info!(
            signer = %tron_crypto::base58check::encode_address(&signer),
            epoch,
            "PBFT VIEW_CHANGE received (no-op per java-tron parity — DPoS handles leader rotation)"
        );
        Ok(())
    }

    fn handle_prepare(
        &self,
        raw: &PbftRaw,
        signer: Address,
        signature: &[u8],
        active: &HashSet<Address>,
    ) -> Result<(), PbftRuntimeError> {
        // Record the vote + check whether crossing the threshold
        // should trigger our own Commit. Drop the lock before
        // broadcasting (which is async-safe but takes time).
        let (record, cross_to_commit) = {
            let mut t = self.tally.lock().unwrap();
            let entry = t.entry_with_time(raw.data.clone(), current_time_ms());
            let record = entry.record_prepare(signer, signature.to_vec());
            let crossed = entry.prepare_threshold_met(active.len());
            let need_broadcast = crossed && !entry.broadcast_commit;
            if need_broadcast {
                entry.broadcast_commit = true;
            }
            (record, need_broadcast)
        };
        // Log equivocations loudly — a Byzantine SR is double-signing.
        // The on-chain slash is a separate flow (proposal-driven); we
        // surface the evidence so an operator can act on it.
        if let VoteRecord::Equivocation {
            signer,
            first_signature,
            conflicting_signature,
        } = &record
        {
            warn!(
                signer = %tron_crypto::base58check::encode_address(signer),
                epoch = raw.epoch,
                first_sig = %hex::encode(&first_signature[..8]),
                conflicting_sig = %hex::encode(&conflicting_signature[..8]),
                "PBFT EQUIVOCATION: SR double-signed a Prepare vote"
            );
        }
        if !cross_to_commit {
            return Ok(());
        }
        // Build + broadcast our own Commit.
        let commit = cast_commit(
            &self.identity.witness_priv_key,
            raw.epoch,
            raw.view_n,
            DataType::Block,
            raw.data.clone(),
        )
        .map_err(|e| PbftRuntimeError::Sign(format!("{e:?}")))?;
        // Record our own commit so threshold count includes it.
        if let Some(commit_raw) = commit.raw_data.as_ref() {
            let mut t = self.tally.lock().unwrap();
            let entry = t.entry_with_time(commit_raw.data.clone(), current_time_ms());
            entry.record_commit(self.identity.witness_address, commit.signature.clone());
        }
        let _ = self.channels.outbound.send(commit);
        if let Some(metrics) = &self.metrics {
            metrics.inc_pbft_commits_sent();
        }
        debug!(epoch = raw.epoch, "cast Commit after Prepare threshold");
        Ok(())
    }

    fn handle_commit(
        &self,
        raw: &PbftRaw,
        signer: Address,
        signature: &[u8],
        active: &HashSet<Address>,
    ) -> Result<(), PbftRuntimeError> {
        let (record, cross_to_finality) = {
            let mut t = self.tally.lock().unwrap();
            let entry = t.entry_with_time(raw.data.clone(), current_time_ms());
            let record = entry.record_commit(signer, signature.to_vec());
            let crossed = entry.commit_threshold_met(active.len());
            (record, crossed)
        };
        if let VoteRecord::Equivocation {
            signer,
            first_signature,
            conflicting_signature,
        } = &record
        {
            warn!(
                signer = %tron_crypto::base58check::encode_address(signer),
                epoch = raw.epoch,
                first_sig = %hex::encode(&first_signature[..8]),
                conflicting_sig = %hex::encode(&conflicting_signature[..8]),
                "PBFT EQUIVOCATION: SR double-signed a Commit vote"
            );
        }
        if !cross_to_finality {
            return Ok(());
        }
        // Persist + bump LATEST_SOLIDIFIED_BLOCK_NUM.
        let (block_num, _block_hash) =
            parse_block_data_payload(&raw.data).ok_or_else(|| {
                PbftRuntimeError::Malformed("bad data payload in commit handler".into())
            })?;

        let signatures = {
            let t = self.tally.lock().unwrap();
            t.get(&raw.data).map(|e| e.commit_signatures()).unwrap_or_default()
        };

        let store = PbftSignDataStore::new(self.pbft_sign_data.clone());
        store.put_commit_result(&PbftSignDataStore::block_key(block_num), raw, &signatures);

        let dp = DynamicPropertiesStore::new(self.state_dyn_props.clone());
        let prev_solid = dp.latest_solidified_block_num().unwrap_or(0);
        if block_num > prev_solid {
            dp.save_latest_solidified_block_num(block_num);
            info!(block_num, "PBFT solidified block");
        }

        // java-tron mirror: PbftMessageAction.action() also writes
        // CommonDataBase[LATEST_PBFT_BLOCK_NUM] on every commit. The
        // store rejects non-monotonic writes internally so re-firing
        // for the same block is harmless.
        if let Some(cdb_be) = &self.common_database {
            tron_chainbase::CommonDataBaseStore::new(cdb_be.clone())
                .save_latest_pbft_block_num(block_num);
        }

        // Drop our tally + prune older.
        let mut t = self.tally.lock().unwrap();
        t.forget(&raw.data);
        t.prune_below(block_num - self.history_cap);
        Ok(())
    }

    /// Handle one inbound SRL PBFT message. Same Prepare → Commit →
    /// Finality flow as block PBFT, but keyed by epoch (not block
    /// hash) and persisted to `PbftSignDataStore::sr_list_key(epoch)`
    /// on commit threshold.
    fn handle_srl_inbound(
        &self,
        msg: &PbftMessage,
        raw: &PbftRaw,
    ) -> Result<(), PbftRuntimeError> {
        let Some(signer) = recover_signer(msg) else {
            return Err(PbftRuntimeError::Malformed("SRL signature recovery failed".into()));
        };
        let active = self.load_active_set_for_epoch(raw.epoch)?;
        if !active.contains(&signer) {
            return Ok(());
        }
        // Cross-payload equivocation check — fires when an SR signs
        // two DIFFERENT SR lists for the same epoch.
        self.record_equivocation_if_any(signer, msg);
        let msg_type = match MsgType::try_from(raw.msg_type) {
            Ok(t) => t,
            Err(_) => return Ok(()),
        };
        // Keyed by epoch — same SRL never overlaps with another SRL.
        // Use the raw `data` field (the encoded SRL proto) as the
        // tally key for byte-equality dedup on the SR list itself.
        let tally_key = raw.data.clone();
        match msg_type {
            MsgType::Preprepare => {
                // Producer signals "we're rotating; here's the list" —
                // cast our own Prepare.
                self.cast_our_srl_prepare(raw.epoch, &raw.data);
                Ok(())
            }
            MsgType::Prepare => {
                let (record, cross_to_commit) = {
                    let mut t = self.srl_tally.lock().unwrap();
                    let entry = t.entry_with_time(tally_key.clone(), current_time_ms());
                    let record = entry.record_prepare(signer, msg.signature.clone());
                    let crossed = entry.prepare_threshold_met(active.len());
                    let need = crossed && !entry.broadcast_commit;
                    if need {
                        entry.broadcast_commit = true;
                    }
                    (record, need)
                };
                if let VoteRecord::Equivocation { signer, .. } = &record {
                    warn!(
                        signer = %tron_crypto::base58check::encode_address(signer),
                        epoch = raw.epoch,
                        "PBFT EQUIVOCATION: SR double-signed an SRL Prepare"
                    );
                }
                if !cross_to_commit {
                    return Ok(());
                }
                // Cast our own SRL Commit.
                let commit = tron_consensus::pbft::cast_commit(
                    &self.identity.witness_priv_key,
                    raw.epoch,
                    raw.view_n,
                    DataType::Srl,
                    raw.data.clone(),
                )
                .map_err(|e| PbftRuntimeError::Sign(format!("{e:?}")))?;
                {
                    let mut t = self.srl_tally.lock().unwrap();
                    let entry = t.entry_with_time(tally_key, current_time_ms());
                    entry.record_commit(
                        self.identity.witness_address,
                        commit.signature.clone(),
                    );
                }
                let _ = self.channels.outbound.send(commit);
                if let Some(metrics) = &self.metrics {
                    metrics.inc_pbft_commits_sent();
                }
                Ok(())
            }
            MsgType::Commit => {
                let (record, cross_to_finality) = {
                    let mut t = self.srl_tally.lock().unwrap();
                    let entry = t.entry_with_time(tally_key.clone(), current_time_ms());
                    let record = entry.record_commit(signer, msg.signature.clone());
                    (record, entry.commit_threshold_met(active.len()))
                };
                if let VoteRecord::Equivocation { signer, .. } = &record {
                    warn!(
                        signer = %tron_crypto::base58check::encode_address(signer),
                        epoch = raw.epoch,
                        "PBFT EQUIVOCATION: SR double-signed an SRL Commit"
                    );
                }
                if !cross_to_finality {
                    return Ok(());
                }
                let signatures = {
                    let t = self.srl_tally.lock().unwrap();
                    t.get(&tally_key).map(|e| e.commit_signatures()).unwrap_or_default()
                };
                let store = PbftSignDataStore::new(self.pbft_sign_data.clone());
                store.put_commit_result(
                    &PbftSignDataStore::sr_list_key(raw.epoch),
                    raw,
                    &signatures,
                );
                info!(epoch = raw.epoch, "PBFT solidified SRL rotation");
                // Drop the SRL tally for this epoch.
                let mut t = self.srl_tally.lock().unwrap();
                t.forget(&tally_key);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Cast our own SRL Prepare with `payload` (the encoded SRL).
    /// Idempotent — second call for the same epoch is a no-op.
    fn cast_our_srl_prepare(&self, epoch: i64, payload: &[u8]) {
        let already = {
            let mut t = self.srl_tally.lock().unwrap();
            let entry = t.entry_with_time(payload.to_vec(), current_time_ms());
            std::mem::replace(&mut entry.broadcast_prepare, true)
        };
        if already {
            return;
        }
        if let Ok(msg) = tron_consensus::pbft::cast_prepare(
            &self.identity.witness_priv_key,
            epoch,
            epoch, // view_n = epoch for SRL per java-tron
            DataType::Srl,
            payload.to_vec(),
        ) {
            {
                let mut t = self.srl_tally.lock().unwrap();
                let entry = t.entry_with_time(payload.to_vec(), current_time_ms());
                entry.record_prepare(self.identity.witness_address, msg.signature.clone());
            }
            let _ = self.channels.outbound.send(msg);
            if let Some(metrics) = &self.metrics {
                metrics.inc_pbft_prepares_sent();
            }
            debug!(epoch, "cast SRL Prepare");
        }
    }

    /// Periodic check: when the cycle number advances past what we
    /// last broadcast for, cast a fresh SRL Prepare for the new SR
    /// list. Mirrors java-tron's `srPrePrepare` call from
    /// `MaintenanceManager.applyBlock`.
    fn maybe_cast_srl_on_cycle_advance(&self) {
        let dp = DynamicPropertiesStore::new(self.state_dyn_props.clone());
        let cur = dp.current_cycle_number();
        let mut last = self.last_srl_cycle.lock().unwrap();
        if cur <= *last || cur == 0 {
            return;
        }
        // Use the current active list. java-tron also keeps only the
        // live `WitnessScheduleStore.active_witnesses` entry (no
        // per-cycle snapshot in this store) — the previous SR set
        // lives in `MaintenanceManager`'s in-memory `getBeforeWitness`.
        let sched = WitnessScheduleStore::new(self.witness_schedule.clone());
        let active_list = match sched.load_active() {
            Ok(Some(list)) => list,
            _ => return,
        };
        let payload = srl_data_payload(&active_list);
        self.cast_our_srl_prepare(cur, &payload);
        *last = cur;
    }

    fn load_active_set(&self) -> Result<HashSet<Address>, PbftRuntimeError> {
        let sched = WitnessScheduleStore::new(self.witness_schedule.clone());
        let list = sched
            .load_active()
            .map_err(|e| PbftRuntimeError::Storage(format!("load_active: {e}")))?
            .unwrap_or_default();
        Ok(list.into_iter().collect())
    }

    /// SR membership check for a vote at `epoch`.
    ///
    /// When a cross-rotation snapshot is attached, this routes between
    /// `before` and `current` exactly the way java-tron's
    /// `PbftManager.verifyMsg` does: `epoch > before_maintenance_time`
    /// → `current`, else → `before`. Falls back to the on-disk active
    /// list when no snapshot is attached (production wires a snapshot;
    /// some tests don't).
    pub(crate) fn load_active_set_for_epoch(
        &self,
        epoch: i64,
    ) -> Result<HashSet<Address>, PbftRuntimeError> {
        if let Some(snap) = &self.sr_snapshot {
            let snap = snap
                .read()
                .map_err(|e| PbftRuntimeError::Storage(format!("sr snapshot poisoned: {e}")))?;
            return Ok(snap.active_set_for_epoch(epoch).iter().copied().collect());
        }
        self.load_active_set()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PbftRuntimeError {
    #[error("malformed PBFT message: {0}")]
    Malformed(String),
    #[error("signing failed: {0}")]
    Sign(String),
    #[error("storage: {0}")]
    Storage(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tron_chainbase::MemBackend;
    use tron_consensus::pbft::cast_prepare as _cast_prepare;
    use tron_crypto::signature::public_key_from_private;

    fn mem() -> Arc<dyn KvBackend> {
        Arc::new(MemBackend::new())
    }

    fn id_from_priv(priv_key: [u8; 32]) -> SrIdentity {
        let pk = public_key_from_private(&priv_key).unwrap();
        SrIdentity {
            witness_address: Address::from_uncompressed_pubkey(&pk).unwrap(),
            witness_priv_key: priv_key,
        }
    }

    fn seed_active(schedule_be: &Arc<dyn KvBackend>, addrs: &[Address]) {
        WitnessScheduleStore::new(schedule_be.clone()).save_active(addrs);
    }

    #[tokio::test]
    async fn on_local_block_emits_prepare_msg() {
        let priv_key = [0x11u8; 32];
        let id = id_from_priv(priv_key);
        let schedule = mem();
        seed_active(&schedule, &[id.witness_address]);

        let channels = PbftChannels::new();
        let mut outbound_rx = channels.outbound.subscribe();
        let runtime = PbftRuntime::new(mem(), schedule, mem(), id, channels);

        runtime.on_local_block(42, [0x99u8; 32], 0).unwrap();
        let msg = outbound_rx.try_recv().expect("Prepare emitted");
        let raw = msg.raw_data.as_ref().unwrap();
        assert_eq!(raw.msg_type, MsgType::Prepare as i32);
        let signer = recover_signer(&msg).unwrap();
        assert_eq!(
            signer.as_bytes(),
            public_key_from_private(&priv_key)
                .map(|pk| Address::from_uncompressed_pubkey(&pk).unwrap())
                .unwrap()
                .as_bytes()
        );
    }

    #[tokio::test]
    async fn on_local_block_is_idempotent() {
        let priv_key = [0x11u8; 32];
        let id = id_from_priv(priv_key);
        let schedule = mem();
        seed_active(&schedule, &[id.witness_address]);

        let channels = PbftChannels::new();
        let mut outbound_rx = channels.outbound.subscribe();
        let runtime = PbftRuntime::new(mem(), schedule, mem(), id, channels);

        runtime.on_local_block(42, [0x99u8; 32], 0).unwrap();
        runtime.on_local_block(42, [0x99u8; 32], 0).unwrap();
        // Only one msg should have been broadcast.
        outbound_rx.try_recv().expect("first Prepare");
        assert!(outbound_rx.try_recv().is_err(), "no second Prepare");
    }

    #[tokio::test]
    async fn quorum_of_prepares_triggers_our_commit() {
        // 4 SRs total → 2/3+1 = 3. Our SR (Alice) + 2 peers ⇒ on
        // the second peer's Prepare we should emit our Commit.
        let alice_priv = [0x11u8; 32];
        let alice = id_from_priv(alice_priv);
        let bob_priv = [0x22u8; 32];
        let charlie_priv = [0x33u8; 32];
        let dan_priv = [0x44u8; 32];

        fn pk_addr(p: [u8; 32]) -> Address {
            let pk = public_key_from_private(&p).unwrap();
            Address::from_uncompressed_pubkey(&pk).unwrap()
        }
        let bob_addr = pk_addr(bob_priv);
        let charlie_addr = pk_addr(charlie_priv);
        let dan_addr = pk_addr(dan_priv);

        let schedule = mem();
        seed_active(
            &schedule,
            &[alice.witness_address, bob_addr, charlie_addr, dan_addr],
        );

        let channels = PbftChannels::new();
        let mut outbound_rx = channels.outbound.subscribe();
        let runtime = PbftRuntime::new(mem(), schedule, mem(), alice, channels);

        // Alice's own Prepare (count = 1).
        runtime.on_local_block(7, [0xaa; 32], 0).unwrap();
        outbound_rx.try_recv().expect("Alice's Prepare");

        // Bob's Prepare (count = 2). Threshold not yet met.
        let data = block_data_payload(7, &[0xaa; 32]);
        let bob_msg = _cast_prepare(&bob_priv, 0, 0, DataType::Block, data.clone()).unwrap();
        runtime.handle_inbound(&bob_msg).unwrap();
        assert!(
            outbound_rx.try_recv().is_err(),
            "no Commit yet, only 2/3 = 2 of 4 prepared"
        );

        // Charlie's Prepare (count = 3). Threshold met → emit Commit.
        let charlie_msg =
            _cast_prepare(&charlie_priv, 0, 0, DataType::Block, data).unwrap();
        runtime.handle_inbound(&charlie_msg).unwrap();
        let commit = outbound_rx.try_recv().expect("Commit after prepare threshold");
        let commit_raw = commit.raw_data.as_ref().unwrap();
        assert_eq!(commit_raw.msg_type, MsgType::Commit as i32);
    }

    #[tokio::test]
    async fn quorum_of_commits_persists_signatures_and_bumps_solid() {
        // 4 SRs. We need 3 commit votes to finalize.
        let alice_priv = [0x11u8; 32];
        let alice = id_from_priv(alice_priv);
        let bob_priv = [0x22u8; 32];
        let charlie_priv = [0x33u8; 32];
        let dan_priv = [0x44u8; 32];

        fn pk_addr(p: [u8; 32]) -> Address {
            let pk = public_key_from_private(&p).unwrap();
            Address::from_uncompressed_pubkey(&pk).unwrap()
        }
        let bob_addr = pk_addr(bob_priv);
        let charlie_addr = pk_addr(charlie_priv);
        let dan_addr = pk_addr(dan_priv);

        let schedule = mem();
        seed_active(
            &schedule,
            &[alice.witness_address, bob_addr, charlie_addr, dan_addr],
        );

        let dp_be = mem();
        let pbft_be = mem();
        let cdb_be = mem();
        let channels = PbftChannels::new();
        let _outbound_rx = channels.outbound.subscribe();
        let runtime = PbftRuntime::new(dp_be.clone(), schedule, pbft_be.clone(), alice, channels)
            .with_common_database(cdb_be.clone());

        let data = block_data_payload(123, &[0xab; 32]);

        // Inject 3 commit votes from Bob, Charlie, Dan (Alice's own
        // Commit goes in via the Prepare-threshold path; bypass it
        // here by feeding Commits directly).
        for priv_key in [bob_priv, charlie_priv, dan_priv] {
            let msg = tron_consensus::pbft::cast_commit(
                &priv_key,
                0,
                0,
                DataType::Block,
                data.clone(),
            )
            .unwrap();
            runtime.handle_inbound(&msg).unwrap();
        }

        // Solidified block num must be 123.
        let dp = DynamicPropertiesStore::new(dp_be);
        assert_eq!(dp.latest_solidified_block_num(), Some(123));

        // Commit-result is persisted with 3 signatures.
        let store = PbftSignDataStore::new(pbft_be);
        let (_raw, sigs) = store
            .get_commit_result(&PbftSignDataStore::block_key(123))
            .unwrap()
            .expect("commit result stored");
        assert_eq!(sigs.len(), 3);

        // CommonDataBase[LATEST_PBFT_BLOCK_NUM] must mirror the
        // solidified block num — same pattern as java-tron's
        // `PbftMessageAction.action()`.
        let cdb = tron_chainbase::CommonDataBaseStore::new(cdb_be);
        assert_eq!(cdb.latest_pbft_block_num(), 123);
    }

    #[tokio::test]
    async fn cross_block_equivocation_is_collected_as_evidence() {
        // 2 SRs total — threshold is 2. Both run on the wire.
        let alice_priv = [0x11u8; 32];
        let alice = id_from_priv(alice_priv);
        let bob_priv = [0x22u8; 32];
        let bob_addr = {
            let pk = public_key_from_private(&bob_priv).unwrap();
            Address::from_uncompressed_pubkey(&pk).unwrap()
        };
        let schedule = mem();
        seed_active(&schedule, &[alice.witness_address, bob_addr]);

        let channels = PbftChannels::new();
        let runtime = PbftRuntime::new(mem(), schedule, mem(), alice, channels);

        // Bob votes Prepare at (epoch=5, view=0) for TWO DIFFERENT blocks.
        let data_a = block_data_payload(7, &[0xaa; 32]);
        let data_b = block_data_payload(7, &[0xbb; 32]);
        let bob_msg_a = tron_consensus::pbft::cast_prepare(
            &bob_priv,
            5,
            0,
            DataType::Block,
            data_a,
        )
        .unwrap();
        let bob_msg_b = tron_consensus::pbft::cast_prepare(
            &bob_priv,
            5,
            0,
            DataType::Block,
            data_b,
        )
        .unwrap();

        runtime.handle_inbound(&bob_msg_a).unwrap();
        // No evidence yet.
        assert_eq!(runtime.equivocation_evidence_count(), 0);

        runtime.handle_inbound(&bob_msg_b).unwrap();
        // Now we should have one evidence entry.
        assert_eq!(runtime.equivocation_evidence_count(), 1);

        let drained = runtime.drain_equivocation_evidence();
        assert_eq!(drained.len(), 1);
        let ev = &drained[0];
        assert_eq!(ev.signer, bob_addr);
        assert_eq!(ev.epoch, 5);
        assert_eq!(ev.msg_type, MsgType::Prepare as i32);
        assert_eq!(ev.first, bob_msg_a);
        assert_eq!(ev.conflicting, bob_msg_b);

        // Drain cleared the pool.
        assert_eq!(runtime.equivocation_evidence_count(), 0);
    }

    #[tokio::test]
    async fn view_change_msg_is_counted_and_does_not_disrupt_tally() {
        let alice_priv = [0x11u8; 32];
        let alice = id_from_priv(alice_priv);
        let bob_priv = [0x22u8; 32];
        let bob_addr = {
            let pk = public_key_from_private(&bob_priv).unwrap();
            Address::from_uncompressed_pubkey(&pk).unwrap()
        };
        let schedule = mem();
        seed_active(&schedule, &[alice.witness_address, bob_addr]);

        let channels = PbftChannels::new();
        let mut outbound_rx = channels.outbound.subscribe();
        let runtime = PbftRuntime::new(mem(), schedule, mem(), alice, channels);

        // Build a VIEW_CHANGE message from Bob (counter-bump only).
        let raw = PbftRaw {
            msg_type: MsgType::ViewChange as i32,
            data_type: DataType::Block as i32,
            view_n: 1,
            epoch: 3,
            data: block_data_payload(10, &[0u8; 32]),
        };
        let bob_msg =
            tron_consensus::pbft::sign_pbft_raw(raw, &bob_priv).unwrap();

        assert_eq!(runtime.view_change_count(), 0);
        runtime.handle_inbound(&bob_msg).unwrap();
        assert_eq!(runtime.view_change_count(), 1);

        // Bob's VIEW_CHANGE must not have produced our Commit or any
        // other outbound message.
        assert!(
            outbound_rx.try_recv().is_err(),
            "VIEW_CHANGE must not trigger any outbound msg"
        );
        // Equivocation pool stays empty for a single VIEW_CHANGE.
        assert_eq!(runtime.equivocation_evidence_count(), 0);

        // Two more VIEW_CHANGEs from the same SR.
        runtime.handle_inbound(&bob_msg).unwrap();
        runtime.handle_inbound(&bob_msg).unwrap();
        assert_eq!(runtime.view_change_count(), 3);
    }

    #[tokio::test]
    async fn equivocation_does_not_block_legitimate_threshold_progress() {
        // 4 SRs. Alice (us), Bob, Charlie, Dan. Threshold = 3.
        // Bob double-signs (evidence collected). The OTHER honest SRs
        // (Charlie + Dan) plus Alice still make 3 → block must
        // solidify.
        let alice_priv = [0x11u8; 32];
        let alice = id_from_priv(alice_priv);
        let bob_priv = [0x22u8; 32];
        let charlie_priv = [0x33u8; 32];
        let dan_priv = [0x44u8; 32];

        fn pk_addr(p: [u8; 32]) -> Address {
            let pk = public_key_from_private(&p).unwrap();
            Address::from_uncompressed_pubkey(&pk).unwrap()
        }
        let bob_addr = pk_addr(bob_priv);
        let charlie_addr = pk_addr(charlie_priv);
        let dan_addr = pk_addr(dan_priv);

        let schedule = mem();
        seed_active(
            &schedule,
            &[alice.witness_address, bob_addr, charlie_addr, dan_addr],
        );

        let dp_be = mem();
        let pbft_be = mem();
        let channels = PbftChannels::new();
        let _outbound_rx = channels.outbound.subscribe();
        let runtime =
            PbftRuntime::new(dp_be.clone(), schedule, pbft_be.clone(), alice, channels);

        let data = block_data_payload(42, &[0xaa; 32]);

        // 3 honest commits → threshold met, block 42 finalizes.
        for priv_key in [bob_priv, charlie_priv, dan_priv] {
            let msg = tron_consensus::pbft::cast_commit(
                &priv_key,
                0,
                0,
                DataType::Block,
                data.clone(),
            )
            .unwrap();
            runtime.handle_inbound(&msg).unwrap();
        }
        let dp = DynamicPropertiesStore::new(dp_be);
        assert_eq!(dp.latest_solidified_block_num(), Some(42));

        // Bob then double-signs for a CONFLICTING block at the same
        // (epoch, view, msg_type) — evidence is collected, but
        // finalisation is unaffected.
        let conflicting = block_data_payload(42, &[0xbb; 32]);
        let bob_conflict =
            tron_consensus::pbft::cast_commit(&bob_priv, 0, 0, DataType::Block, conflicting)
                .unwrap();
        runtime.handle_inbound(&bob_conflict).unwrap();

        let evidence = runtime.drain_equivocation_evidence();
        assert_eq!(evidence.len(), 1, "Bob's double-sign must yield evidence");
        assert_eq!(evidence[0].signer, bob_addr);
    }

    #[tokio::test]
    async fn srl_equivocation_is_also_detected() {
        // Bob signs two DIFFERENT SRLs for the same cycle.
        let alice_priv = [0x11u8; 32];
        let alice = id_from_priv(alice_priv);
        let bob_priv = [0x22u8; 32];
        let bob_addr = {
            let pk = public_key_from_private(&bob_priv).unwrap();
            Address::from_uncompressed_pubkey(&pk).unwrap()
        };
        let schedule = mem();
        seed_active(&schedule, &[alice.witness_address, bob_addr]);

        let channels = PbftChannels::new();
        let runtime = PbftRuntime::new(mem(), schedule, mem(), alice, channels);

        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[20] = 0xaa;
        let mut b = [0u8; 21];
        b[0] = 0x41;
        b[20] = 0xbb;
        let srl_a = srl_data_payload(&[Address::from_raw(a)]);
        let srl_b = srl_data_payload(&[Address::from_raw(b)]);

        let msg_a = tron_consensus::pbft::cast_prepare(
            &bob_priv,
            7,
            7,
            DataType::Srl,
            srl_a,
        )
        .unwrap();
        let msg_b = tron_consensus::pbft::cast_prepare(
            &bob_priv,
            7,
            7,
            DataType::Srl,
            srl_b,
        )
        .unwrap();

        runtime.handle_inbound(&msg_a).unwrap();
        runtime.handle_inbound(&msg_b).unwrap();

        let ev = runtime.drain_equivocation_evidence();
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].data_type, DataType::Srl as i32);
        assert_eq!(ev[0].signer, bob_addr);
    }

    #[tokio::test]
    async fn non_sr_signed_msg_is_dropped() {
        // A msg signed by a non-SR is silently dropped — no
        // contribution to the tally.
        let alice_priv = [0x11u8; 32];
        let alice = id_from_priv(alice_priv);
        let schedule = mem();
        seed_active(&schedule, &[alice.witness_address]);

        let channels = PbftChannels::new();
        let mut outbound_rx = channels.outbound.subscribe();
        let runtime = PbftRuntime::new(mem(), schedule, mem(), alice, channels);

        let intruder_priv = [0x99u8; 32];
        let data = block_data_payload(1, &[0u8; 32]);
        let msg = _cast_prepare(&intruder_priv, 0, 0, DataType::Block, data).unwrap();
        runtime.handle_inbound(&msg).unwrap();
        assert!(outbound_rx.try_recv().is_err(), "no broadcast from non-SR vote");
    }
}

#[cfg(test)]
mod per_cycle_snapshot_tests {
    use super::*;
    use tron_chainbase::MemBackend;

    fn mem() -> Arc<dyn KvBackend> {
        Arc::new(MemBackend::new())
    }

    fn id_from_priv(priv_key: [u8; 32]) -> SrIdentity {
        let pk = tron_crypto::signature::public_key_from_private(&priv_key).unwrap();
        SrIdentity {
            witness_address: Address::from_uncompressed_pubkey(&pk).unwrap(),
            witness_priv_key: priv_key,
        }
    }

    /// Regression guard for the deliberate cross-rotation gap.
    /// Bob's vote at epoch 5 (when Bob was an SR) is REJECTED by the
    /// runtime today because we only consult the current active list
    /// (`WitnessScheduleStore::load_active`), matching java-tron's
    /// persistent-state shape. Closing this gap requires an in-memory
    /// before/current SR snapshot shared with the executor — when
    /// that lands, replace this test with the accept-case.
    #[test]
    fn vote_from_rotated_out_sr_is_rejected_until_in_memory_snapshot_lands() {
        let alice_priv = [0x11u8; 32];
        let alice = id_from_priv(alice_priv);
        let bob_priv = [0x22u8; 32];
        let bob_addr = {
            let pk = tron_crypto::signature::public_key_from_private(&bob_priv).unwrap();
            Address::from_uncompressed_pubkey(&pk).unwrap()
        };

        let schedule_be = mem();
        let sched = WitnessScheduleStore::new(schedule_be.clone());
        // Current active = [Alice]; Bob has rotated out.
        sched.save_active(&[alice.witness_address]);

        let channels = PbftChannels::new();
        let runtime = PbftRuntime::new(mem(), schedule_be, mem(), alice, channels);

        let data = tron_consensus::pbft::block_data_payload(10, &[0u8; 32]);
        let bob_msg = tron_consensus::pbft::cast_prepare(
            &bob_priv,
            5,
            0,
            DataType::Block,
            data,
        )
        .unwrap();
        runtime.handle_inbound(&bob_msg).unwrap();

        let payload = tron_consensus::pbft::block_data_payload(10, &[0u8; 32]);
        let tally_guard = runtime.tally.lock().unwrap();
        if let Some(entry) = tally_guard.get(&payload) {
            assert!(
                !entry.prepare_votes.contains_key(&bob_addr),
                "Bob is no longer in the current active list — vote must be rejected"
            );
        }
    }

    #[test]
    fn vote_from_current_active_sr_is_accepted() {
        let alice_priv = [0x11u8; 32];
        let alice = id_from_priv(alice_priv);
        let schedule_be = mem();
        let sched = WitnessScheduleStore::new(schedule_be.clone());
        sched.save_active(&[alice.witness_address]);

        let alice_addr = alice.witness_address;
        let channels = PbftChannels::new();
        let runtime = PbftRuntime::new(mem(), schedule_be, mem(), alice, channels);

        let data = tron_consensus::pbft::block_data_payload(10, &[0u8; 32]);
        let msg = tron_consensus::pbft::cast_prepare(
            &alice_priv,
            0,
            0,
            DataType::Block,
            data,
        )
        .unwrap();
        runtime.handle_inbound(&msg).unwrap();
        let payload = tron_consensus::pbft::block_data_payload(10, &[0u8; 32]);
        let tally_guard = runtime.tally.lock().unwrap();
        assert!(
            tally_guard.get(&payload).unwrap().prepare_votes.contains_key(&alice_addr),
            "Alice is in the current active list and must be accepted"
        );
    }
}

#[cfg(test)]
mod srl_tests {
    use super::*;
    use tron_chainbase::MemBackend;
    use tron_consensus::pbft::{srl_data_payload, parse_srl_data_payload};

    fn mem() -> Arc<dyn KvBackend> {
        Arc::new(MemBackend::new())
    }

    fn id_from_priv(priv_key: [u8; 32]) -> SrIdentity {
        let pk = tron_crypto::signature::public_key_from_private(&priv_key).unwrap();
        SrIdentity {
            witness_address: Address::from_uncompressed_pubkey(&pk).unwrap(),
            witness_priv_key: priv_key,
        }
    }

    fn priv_to_addr(p: [u8; 32]) -> Address {
        let pk = tron_crypto::signature::public_key_from_private(&p).unwrap();
        Address::from_uncompressed_pubkey(&pk).unwrap()
    }

    #[test]
    fn srl_payload_round_trips() {
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[20] = 0xaa;
        let mut b = [0u8; 21];
        b[0] = 0x41;
        b[20] = 0xbb;
        let list = vec![Address::from_raw(a), Address::from_raw(b)];
        let payload = srl_data_payload(&list);
        let decoded = parse_srl_data_payload(&payload).unwrap();
        assert_eq!(decoded, list);
    }

    #[tokio::test]
    async fn srl_quorum_persists_to_sr_list_key_and_bumps_solidified_implicitly() {
        // 4 SRs. We need 3 commit votes to finalize the SRL.
        // (LATEST_SOLIDIFIED_BLOCK_NUM is NOT bumped on SRL finality —
        //  that's tied to block-PBFT only.)
        let alice_priv = [0x11u8; 32];
        let alice = id_from_priv(alice_priv);
        let bob_priv = [0x22u8; 32];
        let charlie_priv = [0x33u8; 32];
        let dan_priv = [0x44u8; 32];

        let bob_addr = priv_to_addr(bob_priv);
        let charlie_addr = priv_to_addr(charlie_priv);
        let dan_addr = priv_to_addr(dan_priv);

        let schedule_be = mem();
        let sched = WitnessScheduleStore::new(schedule_be.clone());
        sched.save_active(&[alice.witness_address, bob_addr, charlie_addr, dan_addr]);

        let dp_be = mem();
        let pbft_be = mem();
        let channels = PbftChannels::new();
        let runtime = PbftRuntime::new(dp_be, schedule_be, pbft_be.clone(), alice, channels);

        // The SRL being voted on = same active list, encoded.
        let sr_list = vec![
            priv_to_addr(alice_priv),
            bob_addr,
            charlie_addr,
            dan_addr,
        ];
        let payload = srl_data_payload(&sr_list);

        // Inject 3 Commit votes (Bob, Charlie, Dan).
        for priv_key in [bob_priv, charlie_priv, dan_priv] {
            let msg = tron_consensus::pbft::cast_commit(
                &priv_key,
                7, // epoch
                7,
                DataType::Srl,
                payload.clone(),
            )
            .unwrap();
            runtime.handle_inbound(&msg).unwrap();
        }

        let store = PbftSignDataStore::new(pbft_be);
        let (raw, sigs) = store
            .get_commit_result(&PbftSignDataStore::sr_list_key(7))
            .unwrap()
            .expect("SRL commit result stored");
        assert_eq!(sigs.len(), 3);
        assert_eq!(raw.epoch, 7);
        assert_eq!(raw.data_type, DataType::Srl as i32);
    }

    #[tokio::test]
    async fn srl_prepare_threshold_triggers_our_commit() {
        let alice_priv = [0x11u8; 32];
        let alice = id_from_priv(alice_priv);
        let bob_priv = [0x22u8; 32];
        let charlie_priv = [0x33u8; 32];
        let dan_priv = [0x44u8; 32];

        let bob_addr = priv_to_addr(bob_priv);
        let charlie_addr = priv_to_addr(charlie_priv);
        let dan_addr = priv_to_addr(dan_priv);

        let schedule_be = mem();
        let sched = WitnessScheduleStore::new(schedule_be.clone());
        sched.save_active(&[alice.witness_address, bob_addr, charlie_addr, dan_addr]);

        let channels = PbftChannels::new();
        let mut outbound_rx = channels.outbound.subscribe();
        let runtime = PbftRuntime::new(mem(), schedule_be, mem(), alice, channels);

        let payload = srl_data_payload(&[
            priv_to_addr(alice_priv),
            bob_addr,
            charlie_addr,
            dan_addr,
        ]);

        // Cast our own SRL Prepare first so it's in the tally.
        runtime.cast_our_srl_prepare(5, &payload);
        outbound_rx.try_recv().expect("our SRL Prepare");

        // Inject 2 more Prepares (Bob, Charlie) → threshold (3 of 4) met.
        for priv_key in [bob_priv, charlie_priv] {
            let msg = tron_consensus::pbft::cast_prepare(
                &priv_key,
                5,
                5,
                DataType::Srl,
                payload.clone(),
            )
            .unwrap();
            runtime.handle_inbound(&msg).unwrap();
        }
        // After Charlie's vote → we cast SRL Commit.
        let commit = outbound_rx.try_recv().expect("our SRL Commit");
        let raw = commit.raw_data.as_ref().unwrap();
        assert_eq!(raw.msg_type, MsgType::Commit as i32);
        assert_eq!(raw.data_type, DataType::Srl as i32);
    }
}

#[cfg(test)]
mod cross_rotation_tests {
    //! Pins java-tron's `PbftManager.verifyMsg` routing rule:
    //!   - epoch > before_maintenance_time_ms → `current` SR set
    //!   - epoch <= before_maintenance_time_ms → `before` SR set

    use super::*;
    use tron_chainbase::MemBackend;
    use tron_crypto::signature::public_key_from_private;

    fn mem() -> Arc<dyn KvBackend> {
        Arc::new(MemBackend::new())
    }

    fn id_from_priv(priv_key: [u8; 32]) -> SrIdentity {
        let pk = public_key_from_private(&priv_key).unwrap();
        SrIdentity {
            witness_address: Address::from_uncompressed_pubkey(&pk).unwrap(),
            witness_priv_key: priv_key,
        }
    }

    fn pk_addr(p: [u8; 32]) -> Address {
        let pk = public_key_from_private(&p).unwrap();
        Address::from_uncompressed_pubkey(&pk).unwrap()
    }

    fn seed_active(schedule_be: &Arc<dyn KvBackend>, addrs: &[Address]) {
        WitnessScheduleStore::new(schedule_be.clone()).save_active(addrs);
    }

    /// With a cross-rotation snapshot wired up, the SR membership lookup
    /// routes by epoch: votes with `epoch <= before_maintenance_time`
    /// validate against `before`, votes with strictly greater epoch
    /// validate against `current`. This pins the routing decision
    /// (separate from the inbound-message accept/drop policy).
    #[test]
    fn snapshot_routes_active_set_by_epoch_relative_to_before_time() {
        let alice = id_from_priv([0x11u8; 32]);
        let alice_addr = alice.witness_address;
        let bob_addr = pk_addr([0x22u8; 32]);
        let charlie_addr = pk_addr([0x33u8; 32]);

        let schedule = mem();
        // On-disk = post-rotation list.
        seed_active(&schedule, &[alice_addr, charlie_addr]);

        let channels = PbftChannels::new();
        let runtime = PbftRuntime::new(mem(), schedule, mem(), alice, channels);

        // before = [alice, bob]; current = [alice, charlie];
        // before_maintenance_time_ms = 1000.
        let snap = tron_consensus::shared_from_current(vec![alice_addr, charlie_addr]);
        snap.write().unwrap().rotate(
            vec![alice_addr, bob_addr],
            vec![alice_addr, charlie_addr],
            1000,
        );
        let runtime = runtime.with_sr_snapshot(snap);

        // epoch=1000 (== before_maintenance_time) routes to `before` —
        // Bob must be in the set.
        let pre_active = runtime.load_active_set_for_epoch(1000).unwrap();
        assert!(
            pre_active.contains(&bob_addr),
            "pre-rotation Bob must be accepted at epoch == before_maintenance_time"
        );
        assert!(!pre_active.contains(&charlie_addr));

        // epoch=1001 (> before_maintenance_time) routes to `current` —
        // Charlie in, Bob out.
        let post_active = runtime.load_active_set_for_epoch(1001).unwrap();
        assert!(post_active.contains(&charlie_addr));
        assert!(
            !post_active.contains(&bob_addr),
            "post-rotation Bob must NOT be accepted once epoch crosses the boundary"
        );

        // Alice is in both lists (cross-rotation incumbent).
        assert!(pre_active.contains(&alice_addr));
        assert!(post_active.contains(&alice_addr));
    }

    /// Without a snapshot attached, `load_active_set_for_epoch` falls
    /// back to the on-disk active list — same behavior as before this
    /// work item, regardless of the epoch passed in.
    #[test]
    fn no_snapshot_falls_back_to_on_disk_active_list() {
        let alice = id_from_priv([0x11u8; 32]);
        let alice_addr = alice.witness_address;
        let bob_addr = pk_addr([0x22u8; 32]);

        let schedule = mem();
        seed_active(&schedule, &[alice_addr]); // Bob NOT in active set.

        let channels = PbftChannels::new();
        let runtime = PbftRuntime::new(mem(), schedule, mem(), alice, channels);

        // No snapshot wired — fall back to on-disk list. Bob is not
        // there at any epoch.
        let any_epoch_set = runtime.load_active_set_for_epoch(0).unwrap();
        assert!(any_epoch_set.contains(&alice_addr));
        assert!(!any_epoch_set.contains(&bob_addr));
        let later_set = runtime.load_active_set_for_epoch(10_000_000).unwrap();
        assert!(later_set.contains(&alice_addr));
        assert!(!later_set.contains(&bob_addr));
    }

    /// Live update: SyncDriver fires rotation into the snapshot — a
    /// PbftRuntime holding the same Arc must see the change.
    #[test]
    fn live_snapshot_update_propagates_to_pbft_lookup() {
        let alice = id_from_priv([0x11u8; 32]);
        let alice_addr = alice.witness_address;
        let bob_addr = pk_addr([0x22u8; 32]);
        let charlie_addr = pk_addr([0x33u8; 32]);

        let schedule = mem();
        seed_active(&schedule, &[alice_addr, bob_addr]);

        let snap = tron_consensus::shared_from_current(vec![alice_addr, bob_addr]);

        let channels = PbftChannels::new();
        let runtime = PbftRuntime::new(mem(), schedule, mem(), alice, channels)
            .with_sr_snapshot(snap.clone());

        // Pre-rotation: only alice+bob in the active set, any epoch.
        let set = runtime.load_active_set_for_epoch(5_000).unwrap();
        assert!(set.contains(&bob_addr));
        assert!(!set.contains(&charlie_addr));

        // SyncDriver path applies a rotation: before = [alice, bob],
        // current = [alice, charlie], before_maintenance_time = 5_000.
        snap.write().unwrap().rotate(
            vec![alice_addr, bob_addr],
            vec![alice_addr, charlie_addr],
            5_000,
        );

        // Now epoch=5000 → before (bob), epoch=5001 → current (charlie).
        let pre = runtime.load_active_set_for_epoch(5_000).unwrap();
        assert!(pre.contains(&bob_addr));
        assert!(!pre.contains(&charlie_addr));
        let post = runtime.load_active_set_for_epoch(5_001).unwrap();
        assert!(post.contains(&charlie_addr));
        assert!(!post.contains(&bob_addr));
    }
}
