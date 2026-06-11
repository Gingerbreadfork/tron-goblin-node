//! Prometheus-style metrics for the node.
//!
//! All counters/gauges are kept in [`Metrics`], a `Send + Sync`
//! struct shared via `Arc` across the RPC server, the sync driver,
//! and the periodic chain-state sampler. Atomic ops are
//! `Ordering::Relaxed` — these are accounting metrics, not
//! cross-thread synchronization primitives, and Prometheus scrapes
//! tolerate eventually-consistent reads.
//!
//! Output format: standard text exposition (the format Prometheus
//! scrapes by default). Hand-rolled rather than pulling in the
//! `prometheus` crate, because (a) we have ≤ 20 distinct metrics,
//! (b) we don't need histograms, and (c) the hand-roll keeps the
//! crate footprint small.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Cloneable handle to the node's metrics. `Arc<Metrics>` is what
/// every subsystem holds.
pub struct Metrics {
    started_at: Instant,
    // --- Chain head (gauges) ----------------------------------------------
    head_block_number: AtomicI64,
    solidified_block_number: AtomicI64,
    total_net_weight: AtomicI64,
    total_energy_weight: AtomicI64,
    total_witnesses: AtomicI64,
    // --- Sync driver (counters) -------------------------------------------
    sync_blocks_applied: AtomicU64,
    sync_blocks_rejected_validation: AtomicU64,
    sync_blocks_rejected_execution: AtomicU64,
    sync_peer_failures: AtomicU64,
    sync_reconnects: AtomicU64,
    /// Inbound P2P frames dropped by the per-peer rate limiter (one
    /// per registered frame type that overran its bucket).
    p2p_rate_limited: AtomicU64,
    // --- Reorg / fork-tree outcomes (counters) ----------------------------
    blocks_already_known: AtomicU64,
    blocks_side_fork: AtomicU64,
    reorgs_required: AtomicU64,
    blocks_rejected_solidified_diverged: AtomicU64,
    // --- Block production (SR runtime) (counters) -------------------------
    sr_blocks_produced: AtomicU64,
    sr_produce_failures: AtomicU64,
    // --- PBFT runtime (counters) ------------------------------------------
    pbft_messages_received: AtomicU64,
    pbft_prepares_sent: AtomicU64,
    pbft_commits_sent: AtomicU64,
    // --- Mempool ----------------------------------------------------------
    mempool_size: AtomicI64,
    mempool_accepted: AtomicU64,
    mempool_evicted_expired: AtomicU64,
    /// Per-reason rejection counter — `{reason: count}`. Mutex-protected
    /// because the label set is small and write-rare (one bump per submit).
    mempool_rejected_by_reason: Mutex<HashMap<String, u64>>,
    // --- Peers (gauge) ----------------------------------------------------
    active_peers: AtomicI64,
    /// Inbound P2P connections we are currently serving (peers that dialed
    /// US and are syncing FROM us). Zero on a sync-only node.
    p2p_inbound_peers: AtomicI64,
    /// Total inbound sync requests served (`SyncBlockChain` inventories +
    /// `FetchInvData` block/tx batches answered for inbound peers).
    p2p_inbound_served: AtomicU64,
    // --- RPC (counters) ---------------------------------------------------
    rpc_requests_total: AtomicU64,
    /// Per-method counter — `{method_name: count}`. Mutex-protected
    /// because the method-label set grows over time.
    rpc_requests_by_method: Mutex<HashMap<String, u64>>,
    /// Per-method error counter — `{method_name: count}`.
    rpc_errors_by_method: Mutex<HashMap<String, u64>>,
    // --- Address-history index (gauges + counters) --------------------------
    index_cursor_block_number: AtomicI64,
    index_indexed_from_block_number: AtomicI64,
    index_floor_block_number: AtomicI64,
    index_lag_blocks: AtomicI64,
    index_backfill_complete: AtomicI64,
    index_blocks_indexed: AtomicU64,
    index_rows_native: AtomicU64,
    index_rows_trc20: AtomicU64,
    index_rows_trc721: AtomicU64,
    index_rows_internal: AtomicU64,
    index_rows_logs: AtomicU64,
    index_reorg_unwinds: AtomicU64,
    index_reorg_rows_deleted: AtomicU64,
    index_missing_txinfo_blocks: AtomicU64,
    // --- Historical-state archive (gauges + counters) -----------------------
    archive_base_height: AtomicI64,
    archive_head: AtomicI64,
    archive_blocks_total: AtomicU64,
    archive_entries_total: AtomicU64,
    archive_reorg_unwinds: AtomicU64,
    archive_gap_repaired_blocks: AtomicU64,
    archive_coverage_resets: AtomicU64,
    // --- Firehose external-sink log ------------------------------------------
    firehose_head_seq: AtomicU64,
    firehose_entries_total: AtomicU64,
    firehose_unwinds_total: AtomicU64,
    firehose_gap_repaired_total: AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            head_block_number: AtomicI64::new(0),
            solidified_block_number: AtomicI64::new(0),
            total_net_weight: AtomicI64::new(0),
            total_energy_weight: AtomicI64::new(0),
            total_witnesses: AtomicI64::new(0),
            sync_blocks_applied: AtomicU64::new(0),
            sync_blocks_rejected_validation: AtomicU64::new(0),
            sync_blocks_rejected_execution: AtomicU64::new(0),
            sync_peer_failures: AtomicU64::new(0),
            sync_reconnects: AtomicU64::new(0),
            p2p_rate_limited: AtomicU64::new(0),
            blocks_already_known: AtomicU64::new(0),
            blocks_side_fork: AtomicU64::new(0),
            reorgs_required: AtomicU64::new(0),
            blocks_rejected_solidified_diverged: AtomicU64::new(0),
            sr_blocks_produced: AtomicU64::new(0),
            sr_produce_failures: AtomicU64::new(0),
            pbft_messages_received: AtomicU64::new(0),
            pbft_prepares_sent: AtomicU64::new(0),
            pbft_commits_sent: AtomicU64::new(0),
            mempool_size: AtomicI64::new(0),
            mempool_accepted: AtomicU64::new(0),
            mempool_evicted_expired: AtomicU64::new(0),
            mempool_rejected_by_reason: Mutex::new(HashMap::new()),
            active_peers: AtomicI64::new(0),
            p2p_inbound_peers: AtomicI64::new(0),
            p2p_inbound_served: AtomicU64::new(0),
            rpc_requests_total: AtomicU64::new(0),
            rpc_requests_by_method: Mutex::new(HashMap::new()),
            rpc_errors_by_method: Mutex::new(HashMap::new()),
            index_cursor_block_number: AtomicI64::new(0),
            index_indexed_from_block_number: AtomicI64::new(0),
            index_floor_block_number: AtomicI64::new(0),
            index_lag_blocks: AtomicI64::new(0),
            index_backfill_complete: AtomicI64::new(0),
            index_blocks_indexed: AtomicU64::new(0),
            index_rows_native: AtomicU64::new(0),
            index_rows_trc20: AtomicU64::new(0),
            index_rows_trc721: AtomicU64::new(0),
            index_rows_internal: AtomicU64::new(0),
            index_rows_logs: AtomicU64::new(0),
            index_reorg_unwinds: AtomicU64::new(0),
            index_reorg_rows_deleted: AtomicU64::new(0),
            index_missing_txinfo_blocks: AtomicU64::new(0),
            archive_base_height: AtomicI64::new(0),
            archive_head: AtomicI64::new(0),
            archive_blocks_total: AtomicU64::new(0),
            archive_entries_total: AtomicU64::new(0),
            archive_reorg_unwinds: AtomicU64::new(0),
            archive_gap_repaired_blocks: AtomicU64::new(0),
            archive_coverage_resets: AtomicU64::new(0),
            firehose_head_seq: AtomicU64::new(0),
            firehose_entries_total: AtomicU64::new(0),
            firehose_unwinds_total: AtomicU64::new(0),
            firehose_gap_repaired_total: AtomicU64::new(0),
        }
    }

    pub fn new_arc() -> Arc<Self> {
        Arc::new(Self::new())
    }

    // -------------------- Setters (gauges) ----------------------------

    pub fn set_head_block_number(&self, n: i64) {
        self.head_block_number.store(n, Ordering::Relaxed);
    }
    pub fn set_solidified_block_number(&self, n: i64) {
        self.solidified_block_number.store(n, Ordering::Relaxed);
    }
    pub fn set_total_net_weight(&self, w: i64) {
        self.total_net_weight.store(w, Ordering::Relaxed);
    }
    pub fn set_total_energy_weight(&self, w: i64) {
        self.total_energy_weight.store(w, Ordering::Relaxed);
    }
    pub fn set_total_witnesses(&self, n: i64) {
        self.total_witnesses.store(n, Ordering::Relaxed);
    }

    // -------------------- Incrementers (counters) ---------------------

    pub fn inc_blocks_applied(&self) {
        self.sync_blocks_applied.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_blocks_rejected_validation(&self) {
        self.sync_blocks_rejected_validation
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_blocks_rejected_execution(&self) {
        self.sync_blocks_rejected_execution
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_peer_failures(&self) {
        self.sync_peer_failures.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_reconnects(&self) {
        self.sync_reconnects.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_p2p_rate_limited(&self) {
        self.p2p_rate_limited.fetch_add(1, Ordering::Relaxed);
    }
    pub fn p2p_rate_limited(&self) -> u64 {
        self.p2p_rate_limited.load(Ordering::Relaxed)
    }
    pub fn inc_blocks_already_known(&self) {
        self.blocks_already_known.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_blocks_side_fork(&self) {
        self.blocks_side_fork.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_reorgs_required(&self) {
        self.reorgs_required.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_blocks_rejected_solidified_diverged(&self) {
        self.blocks_rejected_solidified_diverged
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_sr_blocks_produced(&self) {
        self.sr_blocks_produced.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_sr_produce_failures(&self) {
        self.sr_produce_failures.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_pbft_messages_received(&self) {
        self.pbft_messages_received.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_pbft_prepares_sent(&self) {
        self.pbft_prepares_sent.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_pbft_commits_sent(&self) {
        self.pbft_commits_sent.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_mempool_accepted(&self) {
        self.mempool_accepted.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_mempool_evicted_expired(&self, n: u64) {
        self.mempool_evicted_expired
            .fetch_add(n, Ordering::Relaxed);
    }
    pub fn record_mempool_rejected(&self, reason: &str) {
        let mut by = self.mempool_rejected_by_reason.lock().unwrap();
        *by.entry(reason.to_string()).or_insert(0) += 1;
    }
    pub fn set_mempool_size(&self, n: i64) {
        self.mempool_size.store(n, Ordering::Relaxed);
    }
    pub fn set_active_peers(&self, n: i64) {
        self.active_peers.store(n, Ordering::Relaxed);
    }

    /// Set the current count of inbound peers syncing FROM us.
    pub fn set_p2p_inbound_peers(&self, n: i64) {
        self.p2p_inbound_peers.store(n, Ordering::Relaxed);
    }

    /// Bump the inbound-served counter (one per sync request answered).
    pub fn inc_p2p_inbound_served(&self) {
        self.p2p_inbound_served.fetch_add(1, Ordering::Relaxed);
    }

    /// Uptime in seconds. Used by `/monitor/getstatsinfo`.
    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }
    /// Read the current head block number gauge.
    pub fn head_block_number(&self) -> i64 {
        self.head_block_number.load(Ordering::Relaxed)
    }
    /// Read the current solidified block number gauge.
    pub fn solidified_block_number(&self) -> i64 {
        self.solidified_block_number.load(Ordering::Relaxed)
    }
    pub fn sync_blocks_applied(&self) -> u64 {
        self.sync_blocks_applied.load(Ordering::Relaxed)
    }
    pub fn sync_blocks_rejected_validation(&self) -> u64 {
        self.sync_blocks_rejected_validation.load(Ordering::Relaxed)
    }
    pub fn sync_blocks_rejected_execution(&self) -> u64 {
        self.sync_blocks_rejected_execution.load(Ordering::Relaxed)
    }
    pub fn sync_peer_failures(&self) -> u64 {
        self.sync_peer_failures.load(Ordering::Relaxed)
    }
    pub fn sync_reconnects(&self) -> u64 {
        self.sync_reconnects.load(Ordering::Relaxed)
    }
    pub fn rpc_requests_total(&self) -> u64 {
        self.rpc_requests_total.load(Ordering::Relaxed)
    }

    pub fn record_rpc_request(&self, method: &str, success: bool) {
        self.rpc_requests_total.fetch_add(1, Ordering::Relaxed);
        let mut by = self.rpc_requests_by_method.lock().unwrap();
        *by.entry(method.to_string()).or_insert(0) += 1;
        if !success {
            let mut err = self.rpc_errors_by_method.lock().unwrap();
            *err.entry(method.to_string()).or_insert(0) += 1;
        }
    }

    /// Bulk update of the address-history-index gauges + counters.
    /// Called by the node's index sampler (the index engine keeps its
    /// own atomic counters; this mirrors a snapshot of them into the
    /// Prometheus surface). Counters are *stored*, not added — the
    /// source values are already monotonic totals.
    #[allow(clippy::too_many_arguments)]
    pub fn set_index_stats(
        &self,
        cursor: i64,
        indexed_from: i64,
        floor: i64,
        lag: i64,
        backfill_complete: bool,
        blocks_indexed: u64,
        rows_native: u64,
        rows_trc20: u64,
        rows_trc721: u64,
        rows_internal: u64,
        rows_logs: u64,
        reorg_unwinds: u64,
        reorg_rows_deleted: u64,
        missing_txinfo_blocks: u64,
    ) {
        self.index_cursor_block_number.store(cursor, Ordering::Relaxed);
        self.index_indexed_from_block_number.store(indexed_from, Ordering::Relaxed);
        self.index_floor_block_number.store(floor, Ordering::Relaxed);
        self.index_lag_blocks.store(lag, Ordering::Relaxed);
        self.index_backfill_complete
            .store(backfill_complete as i64, Ordering::Relaxed);
        self.index_blocks_indexed.store(blocks_indexed, Ordering::Relaxed);
        self.index_rows_native.store(rows_native, Ordering::Relaxed);
        self.index_rows_trc20.store(rows_trc20, Ordering::Relaxed);
        self.index_rows_trc721.store(rows_trc721, Ordering::Relaxed);
        self.index_rows_internal.store(rows_internal, Ordering::Relaxed);
        self.index_rows_logs.store(rows_logs, Ordering::Relaxed);
        self.index_reorg_unwinds.store(reorg_unwinds, Ordering::Relaxed);
        self.index_reorg_rows_deleted
            .store(reorg_rows_deleted, Ordering::Relaxed);
        self.index_missing_txinfo_blocks
            .store(missing_txinfo_blocks, Ordering::Relaxed);
    }

    /// Bulk update of the historical-state-archive gauges/counters
    /// (mirrored from the archive writer's atomics by the node's
    /// sampler — stored, not added).
    #[allow(clippy::too_many_arguments)]
    pub fn set_archive_stats(
        &self,
        base: i64,
        head: i64,
        blocks: u64,
        entries: u64,
        reorg_unwinds: u64,
        gap_repaired_blocks: u64,
        coverage_resets: u64,
    ) {
        self.archive_base_height.store(base, Ordering::Relaxed);
        self.archive_head.store(head, Ordering::Relaxed);
        self.archive_blocks_total.store(blocks, Ordering::Relaxed);
        self.archive_entries_total.store(entries, Ordering::Relaxed);
        self.archive_reorg_unwinds.store(reorg_unwinds, Ordering::Relaxed);
        self.archive_gap_repaired_blocks
            .store(gap_repaired_blocks, Ordering::Relaxed);
        self.archive_coverage_resets
            .store(coverage_resets, Ordering::Relaxed);
    }

    /// Mirror of the firehose writer's counters (stored, not added).
    pub fn set_firehose_stats(
        &self,
        head_seq: u64,
        entries: u64,
        unwinds: u64,
        gap_repaired: u64,
    ) {
        self.firehose_head_seq.store(head_seq, Ordering::Relaxed);
        self.firehose_entries_total.store(entries, Ordering::Relaxed);
        self.firehose_unwinds_total.store(unwinds, Ordering::Relaxed);
        self.firehose_gap_repaired_total
            .store(gap_repaired, Ordering::Relaxed);
    }

    // -------------------- Exposition (Prometheus text format) ----------

    /// Render every metric in Prometheus text-exposition format.
    /// Each metric gets a `# HELP` + `# TYPE` line followed by one or
    /// more sample lines. Returned as a single `String` — Prometheus
    /// scrapes are small (< 100 KB even with many label combinations)
    /// so we materialise the whole thing.
    pub fn to_prometheus_text(&self) -> String {
        let uptime = self.started_at.elapsed().as_secs();
        let mut out = String::with_capacity(2048);

        // --- Uptime ---
        let _ = std::fmt::Write::write_str(&mut out, "\
# HELP tron_node_uptime_seconds Seconds since the node process started.
# TYPE tron_node_uptime_seconds counter
");
        let _ = std::fmt::Write::write_fmt(&mut out, format_args!("tron_node_uptime_seconds {uptime}\n"));

        // --- Chain head gauges ---
        emit_gauge(
            &mut out,
            "tron_node_head_block_number",
            "Current chain head block number.",
            self.head_block_number.load(Ordering::Relaxed),
        );
        emit_gauge(
            &mut out,
            "tron_node_solidified_block_number",
            "Latest solidified (PBFT-finalized) block number.",
            self.solidified_block_number.load(Ordering::Relaxed),
        );
        emit_gauge(
            &mut out,
            "tron_node_total_net_weight",
            "Chain-wide TOTAL_NET_WEIGHT in TRX units (bandwidth global scaling denominator).",
            self.total_net_weight.load(Ordering::Relaxed),
        );
        emit_gauge(
            &mut out,
            "tron_node_total_energy_weight",
            "Chain-wide TOTAL_ENERGY_WEIGHT in TRX units (energy global scaling denominator).",
            self.total_energy_weight.load(Ordering::Relaxed),
        );
        emit_gauge(
            &mut out,
            "tron_node_total_witnesses",
            "Number of witnesses in the WitnessStore.",
            self.total_witnesses.load(Ordering::Relaxed),
        );

        // --- Sync counters ---
        emit_counter(
            &mut out,
            "tron_node_sync_blocks_applied_total",
            "Blocks successfully applied to state by the sync driver.",
            self.sync_blocks_applied.load(Ordering::Relaxed),
        );
        emit_counter(
            &mut out,
            "tron_node_sync_blocks_rejected_validation_total",
            "Blocks rejected at the validation pipeline (parent link / tx trie / witness sig).",
            self.sync_blocks_rejected_validation.load(Ordering::Relaxed),
        );
        emit_counter(
            &mut out,
            "tron_node_sync_blocks_rejected_execution_total",
            "Blocks that passed validation but failed during executor commit.",
            self.sync_blocks_rejected_execution.load(Ordering::Relaxed),
        );
        emit_counter(
            &mut out,
            "tron_node_sync_peer_failures_total",
            "Per-peer dial/handshake/read failures during sync.",
            self.sync_peer_failures.load(Ordering::Relaxed),
        );
        emit_counter(
            &mut out,
            "tron_node_sync_reconnects_total",
            "Reconnect attempts the sync driver has made.",
            self.sync_reconnects.load(Ordering::Relaxed),
        );
        emit_counter(
            &mut out,
            "tron_node_p2p_rate_limited_total",
            "Inbound P2P frames dropped by the per-peer rate limiter.",
            self.p2p_rate_limited.load(Ordering::Relaxed),
        );

        // --- Reorg / fork-tree outcomes ---
        emit_counter(
            &mut out,
            "tron_node_blocks_already_known_total",
            "Blocks peers re-served that we already had in the fork tree.",
            self.blocks_already_known.load(Ordering::Relaxed),
        );
        emit_counter(
            &mut out,
            "tron_node_blocks_side_fork_total",
            "Blocks linked into the fork tree on a side branch (not applied to state).",
            self.blocks_side_fork.load(Ordering::Relaxed),
        );
        emit_counter(
            &mut out,
            "tron_node_reorgs_required_total",
            "Sibling-fork overtakes detected (true reorg with state rollback not yet wired).",
            self.reorgs_required.load(Ordering::Relaxed),
        );
        emit_counter(
            &mut out,
            "tron_node_blocks_rejected_solidified_diverged_total",
            "Head-promotion attempts rejected because the fork diverges from latest solidified.",
            self.blocks_rejected_solidified_diverged.load(Ordering::Relaxed),
        );

        // --- SR (block production) ---
        emit_counter(
            &mut out,
            "tron_node_sr_blocks_produced_total",
            "Blocks the local SR runtime produced + applied + broadcast.",
            self.sr_blocks_produced.load(Ordering::Relaxed),
        );
        emit_counter(
            &mut out,
            "tron_node_sr_produce_failures_total",
            "SR runtime produce-attempt errors (apply / mempool drain / signing).",
            self.sr_produce_failures.load(Ordering::Relaxed),
        );

        // --- PBFT ---
        emit_counter(
            &mut out,
            "tron_node_pbft_messages_received_total",
            "Inbound PbftMessage frames the PBFT runtime processed (Prepare + Commit).",
            self.pbft_messages_received.load(Ordering::Relaxed),
        );
        emit_counter(
            &mut out,
            "tron_node_pbft_prepares_sent_total",
            "Prepare votes the local PBFT runtime broadcast.",
            self.pbft_prepares_sent.load(Ordering::Relaxed),
        );
        emit_counter(
            &mut out,
            "tron_node_pbft_commits_sent_total",
            "Commit votes the local PBFT runtime broadcast.",
            self.pbft_commits_sent.load(Ordering::Relaxed),
        );

        // --- Mempool ---
        emit_gauge(
            &mut out,
            "tron_node_mempool_size",
            "Current count of pending transactions in the mempool.",
            self.mempool_size.load(Ordering::Relaxed),
        );
        emit_counter(
            &mut out,
            "tron_node_mempool_accepted_total",
            "Transactions accepted into the mempool.",
            self.mempool_accepted.load(Ordering::Relaxed),
        );
        emit_counter(
            &mut out,
            "tron_node_mempool_evicted_expired_total",
            "Pending transactions removed because their expiration passed.",
            self.mempool_evicted_expired.load(Ordering::Relaxed),
        );
        let _ = std::fmt::Write::write_str(&mut out, "\
# HELP tron_node_mempool_rejected_by_reason_total Mempool submissions rejected, labelled by reason.
# TYPE tron_node_mempool_rejected_by_reason_total counter
");
        let mp_rej = self.mempool_rejected_by_reason.lock().unwrap();
        for (reason, count) in mp_rej.iter() {
            let _ = std::fmt::Write::write_fmt(
                &mut out,
                format_args!(
                    "tron_node_mempool_rejected_by_reason_total{{reason=\"{}\"}} {}\n",
                    escape_label(reason),
                    count
                ),
            );
        }
        drop(mp_rej);

        // --- Peers ---
        emit_gauge(
            &mut out,
            "tron_node_active_peers",
            "Peers currently registered with the live peer registry (handshake completed).",
            self.active_peers.load(Ordering::Relaxed),
        );
        emit_gauge(
            &mut out,
            "tron_node_p2p_inbound_peers",
            "Inbound P2P peers currently syncing FROM us (peers that dialed us).",
            self.p2p_inbound_peers.load(Ordering::Relaxed),
        );
        emit_counter(
            &mut out,
            "tron_node_p2p_inbound_served_total",
            "Inbound sync requests served (SyncBlockChain + FetchInvData answered for inbound peers).",
            self.p2p_inbound_served.load(Ordering::Relaxed),
        );

        // --- RPC counters ---
        emit_counter(
            &mut out,
            "tron_node_rpc_requests_total",
            "Total JSON-RPC requests served.",
            self.rpc_requests_total.load(Ordering::Relaxed),
        );

        // Per-method requests + errors (labelled).
        let _ = std::fmt::Write::write_str(&mut out, "\
# HELP tron_node_rpc_requests_by_method_total JSON-RPC requests served, labelled by method.
# TYPE tron_node_rpc_requests_by_method_total counter
");
        let by = self.rpc_requests_by_method.lock().unwrap();
        for (method, count) in by.iter() {
            let _ = std::fmt::Write::write_fmt(
                &mut out,
                format_args!(
                    "tron_node_rpc_requests_by_method_total{{method=\"{}\"}} {}\n",
                    escape_label(method),
                    count
                ),
            );
        }
        drop(by);

        let _ = std::fmt::Write::write_str(&mut out, "\
# HELP tron_node_rpc_errors_by_method_total JSON-RPC errors served, labelled by method.
# TYPE tron_node_rpc_errors_by_method_total counter
");
        let err = self.rpc_errors_by_method.lock().unwrap();
        for (method, count) in err.iter() {
            let _ = std::fmt::Write::write_fmt(
                &mut out,
                format_args!(
                    "tron_node_rpc_errors_by_method_total{{method=\"{}\"}} {}\n",
                    escape_label(method),
                    count
                ),
            );
        }
        drop(err);

        // --- Address-history index ---
        emit_gauge(
            &mut out,
            "tron_node_index_cursor_block_number",
            "Address-history index live-edge cursor (highest contiguously-indexed block).",
            self.index_cursor_block_number.load(Ordering::Relaxed),
        );
        emit_gauge(
            &mut out,
            "tron_node_index_indexed_from_block_number",
            "Address-history index lowest indexed block (the backward backfill edge).",
            self.index_indexed_from_block_number.load(Ordering::Relaxed),
        );
        emit_gauge(
            &mut out,
            "tron_node_index_floor_block_number",
            "Address-history index effective floor (snapshot base / start_height clamp).",
            self.index_floor_block_number.load(Ordering::Relaxed),
        );
        emit_gauge(
            &mut out,
            "tron_node_index_lag_blocks",
            "Blocks between the committed head and the index cursor (0 = parked at tip).",
            self.index_lag_blocks.load(Ordering::Relaxed),
        );
        emit_gauge(
            &mut out,
            "tron_node_index_backfill_complete",
            "1 once the index back edge reached the floor (full history present).",
            self.index_backfill_complete.load(Ordering::Relaxed),
        );
        emit_counter(
            &mut out,
            "tron_node_index_blocks_indexed_total",
            "Blocks the address-history index has processed.",
            self.index_blocks_indexed.load(Ordering::Relaxed),
        );
        emit_counter(
            &mut out,
            "tron_node_index_rows_written_total_native",
            "idx_native rows written.",
            self.index_rows_native.load(Ordering::Relaxed),
        );
        emit_counter(
            &mut out,
            "tron_node_index_rows_written_total_trc20",
            "idx_trc20 rows written.",
            self.index_rows_trc20.load(Ordering::Relaxed),
        );
        emit_counter(
            &mut out,
            "tron_node_index_rows_written_total_trc721",
            "idx_trc721 rows written.",
            self.index_rows_trc721.load(Ordering::Relaxed),
        );
        emit_counter(
            &mut out,
            "tron_node_index_rows_written_total_internal",
            "idx_internal rows written.",
            self.index_rows_internal.load(Ordering::Relaxed),
        );
        emit_counter(
            &mut out,
            "tron_node_index_rows_written_total_logs",
            "idx_logs rows written (scope = all only).",
            self.index_rows_logs.load(Ordering::Relaxed),
        );
        emit_counter(
            &mut out,
            "tron_node_index_reorg_unwinds_total",
            "Reorgs the index reconciled by unwinding to the common ancestor.",
            self.index_reorg_unwinds.load(Ordering::Relaxed),
        );
        emit_counter(
            &mut out,
            "tron_node_index_reorg_rows_deleted_total",
            "Rows deleted by reorg unwinds.",
            self.index_reorg_rows_deleted.load(Ordering::Relaxed),
        );
        emit_counter(
            &mut out,
            "tron_node_index_missing_txinfo_blocks_total",
            "Blocks indexed without transaction-info while VM-derived kinds were enabled (those ranges lack TRC20/internal rows).",
            self.index_missing_txinfo_blocks.load(Ordering::Relaxed),
        );

        // --- Historical-state archive ---
        emit_gauge(
            &mut out,
            "tron_node_archive_base_height",
            "Historical-state archive coverage base (reads valid from here up).",
            self.archive_base_height.load(Ordering::Relaxed),
        );
        emit_gauge(
            &mut out,
            "tron_node_archive_head",
            "Historical-state archive coverage head (last archived block).",
            self.archive_head.load(Ordering::Relaxed),
        );
        emit_counter(
            &mut out,
            "tron_node_archive_blocks_total",
            "Blocks whose write-sets were archived.",
            self.archive_blocks_total.load(Ordering::Relaxed),
        );
        emit_counter(
            &mut out,
            "tron_node_archive_entries_total",
            "Versioned key entries written to the archive.",
            self.archive_entries_total.load(Ordering::Relaxed),
        );
        emit_counter(
            &mut out,
            "tron_node_archive_reorg_unwinds_total",
            "Reorgs the archive reconciled by unwinding orphaned heights.",
            self.archive_reorg_unwinds.load(Ordering::Relaxed),
        );
        emit_counter(
            &mut out,
            "tron_node_archive_gap_repaired_blocks_total",
            "Capture-gap blocks repaired exactly from the undo log.",
            self.archive_gap_repaired_blocks.load(Ordering::Relaxed),
        );
        emit_counter(
            &mut out,
            "tron_node_archive_coverage_resets_total",
            "Archive coverage resets (history lost, capture restarted) — should stay 0.",
            self.archive_coverage_resets.load(Ordering::Relaxed),
        );

        // --- Firehose ---
        emit_gauge(
            &mut out,
            "tron_node_firehose_head_seq",
            "Newest durable firehose log sequence number (the consumers' cursor space).",
            self.firehose_head_seq.load(Ordering::Relaxed) as i64,
        );
        emit_counter(
            &mut out,
            "tron_node_firehose_entries_total",
            "Firehose APPLY entries appended this run.",
            self.firehose_entries_total.load(Ordering::Relaxed),
        );
        emit_counter(
            &mut out,
            "tron_node_firehose_unwinds_total",
            "Firehose UNWIND entries appended (reorgs + crash recoveries).",
            self.firehose_unwinds_total.load(Ordering::Relaxed),
        );
        emit_counter(
            &mut out,
            "tron_node_firehose_gap_repaired_total",
            "Firehose entries re-derived from the stores to close log gaps.",
            self.firehose_gap_repaired_total.load(Ordering::Relaxed),
        );

        out
    }
}

/// Emit a Prometheus gauge in one shot.
fn emit_gauge(out: &mut String, name: &str, help: &str, value: i64) {
    let _ = std::fmt::Write::write_fmt(
        out,
        format_args!("# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}\n"),
    );
}

/// Emit a Prometheus counter in one shot.
fn emit_counter(out: &mut String, name: &str, help: &str, value: u64) {
    let _ = std::fmt::Write::write_fmt(
        out,
        format_args!("# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}\n"),
    );
}

/// Escape Prometheus label values per the exposition format spec:
/// `\\`, `\"`, `\n` must be escaped. Method names use only ASCII
/// alphanumeric + `_` in practice, so this is mostly defensive.
fn escape_label(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_metrics_emit_zero_counters_and_help_lines() {
        let m = Metrics::new();
        let text = m.to_prometheus_text();
        assert!(text.contains("tron_node_uptime_seconds"));
        assert!(text.contains("# TYPE tron_node_head_block_number gauge"));
        assert!(text.contains("tron_node_head_block_number 0"));
        assert!(text.contains("tron_node_sync_blocks_applied_total 0"));
    }

    #[test]
    fn setters_and_incrementers_propagate_to_output() {
        let m = Metrics::new();
        m.set_head_block_number(12_345);
        m.set_solidified_block_number(12_300);
        m.set_total_net_weight(777);
        for _ in 0..3 {
            m.inc_blocks_applied();
        }
        m.inc_peer_failures();
        m.record_rpc_request("eth_blockNumber", true);
        m.record_rpc_request("eth_blockNumber", true);
        m.record_rpc_request("eth_call", false);

        let text = m.to_prometheus_text();
        assert!(text.contains("tron_node_head_block_number 12345"));
        assert!(text.contains("tron_node_solidified_block_number 12300"));
        assert!(text.contains("tron_node_total_net_weight 777"));
        assert!(text.contains("tron_node_sync_blocks_applied_total 3"));
        assert!(text.contains("tron_node_sync_peer_failures_total 1"));
        assert!(text.contains("tron_node_rpc_requests_total 3"));
        assert!(text.contains(
            "tron_node_rpc_requests_by_method_total{method=\"eth_blockNumber\"} 2"
        ));
        assert!(text.contains(
            "tron_node_rpc_errors_by_method_total{method=\"eth_call\"} 1"
        ));
    }

    #[test]
    fn label_escaping_handles_quotes_and_backslashes() {
        let m = Metrics::new();
        m.record_rpc_request("weird\"name\\here", true);
        let text = m.to_prometheus_text();
        assert!(text.contains("weird\\\"name\\\\here"), "{}", text);
    }

    #[test]
    fn reorg_and_production_counters_emit() {
        let m = Metrics::new();
        m.inc_blocks_already_known();
        m.inc_blocks_already_known();
        m.inc_blocks_side_fork();
        m.inc_reorgs_required();
        m.inc_blocks_rejected_solidified_diverged();
        m.inc_sr_blocks_produced();
        m.inc_sr_produce_failures();
        m.inc_pbft_messages_received();
        m.inc_pbft_prepares_sent();
        m.inc_pbft_commits_sent();

        let text = m.to_prometheus_text();
        assert!(text.contains("tron_node_blocks_already_known_total 2"));
        assert!(text.contains("tron_node_blocks_side_fork_total 1"));
        assert!(text.contains("tron_node_reorgs_required_total 1"));
        assert!(text.contains("tron_node_blocks_rejected_solidified_diverged_total 1"));
        assert!(text.contains("tron_node_sr_blocks_produced_total 1"));
        assert!(text.contains("tron_node_sr_produce_failures_total 1"));
        assert!(text.contains("tron_node_pbft_messages_received_total 1"));
        assert!(text.contains("tron_node_pbft_prepares_sent_total 1"));
        assert!(text.contains("tron_node_pbft_commits_sent_total 1"));
    }

    #[test]
    fn mempool_and_peer_gauges_emit() {
        let m = Metrics::new();
        m.set_mempool_size(42);
        m.set_active_peers(7);
        m.inc_mempool_accepted();
        m.inc_mempool_accepted();
        m.inc_mempool_evicted_expired(3);
        m.record_mempool_rejected("duplicate");
        m.record_mempool_rejected("duplicate");
        m.record_mempool_rejected("expired");

        let text = m.to_prometheus_text();
        assert!(text.contains("tron_node_mempool_size 42"));
        assert!(text.contains("tron_node_active_peers 7"));
        assert!(text.contains("tron_node_mempool_accepted_total 2"));
        assert!(text.contains("tron_node_mempool_evicted_expired_total 3"));
        assert!(text.contains(
            "tron_node_mempool_rejected_by_reason_total{reason=\"duplicate\"} 2"
        ));
        assert!(text.contains(
            "tron_node_mempool_rejected_by_reason_total{reason=\"expired\"} 1"
        ));
    }
}
