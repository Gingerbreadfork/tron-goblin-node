//! Block-sync driver.
//!
//! What `tron_replay::run_sync_loop` does:
//!
//! * One peer, one pass — when the peer reports `remain_num == 0` the
//!   loop exits and the caller restarts it.
//! * Doesn't persist accepted blocks anywhere — `execute_block` only
//!   updates the dyn-props head pointer. Blocks themselves aren't
//!   written to `BlockStore`, so the RPC `eth_getBlockByNumber` can't
//!   retrieve them after the fact.
//! * Always starts from a fixed `starting_head`; no resume-from-disk.
//! * No fork resolution, no peer scoring, no validation ahead of
//!   execution.
//!
//! What this driver does on top:
//!
//! 1. **Resume from disk**: reads `latest_block_header_hash` +
//!    `latest_block_header_number` out of `DynamicPropertiesStore` on
//!    every fresh pass.
//! 2. **Persistent block storage**: every accepted block is written to
//!    `BlockStore` and `BlockIndexStore` before the executor runs, so
//!    RPC reads land on the same data.
//! 3. **Continuous tail-follow**: when the peer reports it has no more
//!    blocks, we idle for `tail_interval` and ask again, rather than
//!    exiting.
//! 4. **Peer rotation**: a pool of peers is provided; on dial /
//!    handshake / read failure, the driver moves to the next peer with
//!    exponential backoff per-peer.
//! 5. **Validation pipeline**: every block is checked for
//!    `verify_witness_signature` + `verify_tx_trie_root` + parent
//!    link before execution. A failing block is rejected and the
//!    peer's failure counter is bumped.
//!
//! What's still **deferred** (separate work):
//!
//! * Fork resolution against competing chains. v1 trusts the peer's
//!   inventory ordering.
//! * Parallel header-then-body fetch across multiple peers.
//! * Pruning / snapshot import.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use prost::Message as _;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};
use tron_chainbase::{
    BlockIndexStore, BlockStore, DynamicPropertiesStore, KvBackend, WitnessScheduleStore,
};
use tron_executor::{expected_block_signer, StateBackends};
use tron_eventer::EventBus;
use tron_mempool::{MempoolError, TxMempool};
use tron_net::{
    Frame, HelloInputs, Libp2pHelloInputs, MessageType, PeerConnection, MAINNET_P2P_VERSION,
};
use tron_proto::{Block, Endpoint};
use tron_types::{
    block_id_from_block, genesis_block_id, mainnet_inputs, verify_parent_link, verify_tx_trie_root,
    verify_tx_trie_root_raw, verify_witness_signature, BlockId,
};

use crate::logfmt;

/// Per-driver configuration.
#[derive(Clone)]
pub struct SyncConfig {
    /// Peer addresses to try in rotation. `HOST:PORT` strings.
    pub peers: Vec<String>,
    /// Optional hard cap on the total number of blocks to apply
    /// before the driver returns. `None` = unlimited.
    pub max_blocks: Option<usize>,
    /// How long to idle when the current peer reports no new blocks
    /// before going around the loop again.
    pub tail_interval: Duration,
    /// Initial backoff after a peer failure, doubled on each
    /// successive failure for the same peer (capped at 5 minutes).
    pub initial_backoff: Duration,
    /// Raw `blocks` backend — needed because `StateBackends` doesn't
    /// expose it (the executor doesn't write blocks).
    pub blocks_backend: Arc<dyn KvBackend>,
    /// Emit a "applied block #N" heartbeat every N blocks. `0` =
    /// silent (only failures are logged). Set to `1` to log every
    /// block — useful during the first-mainnet-sync triage to see
    /// exactly which block diverges.
    pub progress_log_interval: usize,
    /// Port we advertise in our Hello endpoints. Mainnet peers run
    /// `NetUtil.validNode` against the `(address, port)` pair before
    /// accepting; `port: 0` is rejected as `BAD_PROTOCOL`. Default
    /// 18888 (java-tron's standard P2P port) is safe even when we
    /// don't actually listen.
    pub advertise_port: i32,
    /// Tip-test mode. When `true`, incoming Block frames are counted
    /// + logged but NOT validated, NOT executed, NOT stored. The
    /// driver also skips KhaosDb seeding. Used to exercise multi-peer
    /// wire-level sync against modern validators that pruned the
    /// genesis-era state. The runtime is responsible for spoofing the
    /// `DynamicPropertiesStore` head before construction.
    pub tip_test: bool,
    /// Per-frame-type inbound P2P rate-limit caps. The peer loop
    /// installs one `P2pRateLimiter` per connection, registers these
    /// rates against the relevant frame-type bytes, and silently drops
    /// frames whose bucket is empty. Mirrors java-tron's
    /// `PeerConnection.setChannel` registration of `SYNC_BLOCK_CHAIN`,
    /// `FETCH_INV_DATA`, and `P2P_DISCONNECT` rates.
    pub p2p_rate_limits: crate::config::RateLimiterP2pConfig,
    /// Timeout for the single-slot live-tip block fetch
    /// (`FetchBlockScheduler`). Java-tron's `fetchBlockTimeout` is
    /// clamped to `[100, 1000]ms` with `200` the typical default. The
    /// scheduler treats the slot as releasable after `timeout *
    /// BLOCK_FETCH_LEFT_TIME_PERCENT` (50%).
    pub fetch_block_timeout: Duration,
    /// `true` when THIS peer is one of the operator's
    /// `fastForwardNodes`. Drives the produced-block relay decision:
    /// fast-forward peers receive the full `Block` frame as a direct
    /// push (lowest-latency hand-off); non-fast-forward peers receive
    /// only an `Inventory(BLOCK)` advertisement and pull the body via
    /// `FetchInvData`. Mirrors java-tron's `RelayService` +
    /// `peer.isFastForwardPeer()` gate.
    pub peer_is_fast_forward: bool,
}

/// Aggregate statistics across the driver's lifetime.
#[derive(Default, Debug, Clone)]
pub struct DriverStats {
    pub blocks_applied: usize,
    pub blocks_rejected_validation: usize,
    pub blocks_rejected_execution: usize,
    pub peer_failures: usize,
    pub reconnects: usize,
}

/// How long the active syncer may make no block-apply progress before a
/// standby driver is allowed to take leadership. Comfortably above
/// mainnet's ~3s block cadence (a healthy leader applies a block well
/// within this), but well under the 120s keepalive deadline so failover
/// from a dead/stuck leader is prompt.
const LEADERSHIP_STALE: Duration = Duration::from_secs(30);

/// Coordinates the single active block-applying `SyncDriver` across the
/// per-peer driver fleet. The runtime spawns one driver per peer, all
/// sharing the same RocksDB state; without coordination every driver
/// applies the same blocks concurrently — racing the head and flooding
/// spurious `unlinked` / `ParentLinkMismatch` rejections (each driver has
/// its own in-memory fork tree). Exactly one driver leads (requests +
/// applies blocks); the rest stay connected as standby — serving inbound
/// sync, answering keepalives — and take over only if the leader stops
/// making progress for [`LEADERSHIP_STALE`] or disconnects.
#[derive(Debug)]
pub struct SyncLeadership {
    inner: std::sync::Mutex<LeaderState>,
}

#[derive(Debug)]
struct LeaderState {
    /// Peer key of the current active syncer, or `None` when the slot is
    /// free (startup, or just after the leader released it).
    leader: Option<String>,
    /// When the leader last applied a block (or, for a fresh claimant,
    /// when it took the slot). Drives the staleness check.
    last_progress: Instant,
}

impl SyncLeadership {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(LeaderState {
                leader: None,
                last_progress: Instant::now(),
            }),
        }
    }

    /// Claim or retain leadership for `peer`. Returns `true` if `peer` is
    /// the active syncer after the call. A challenger wins only when it's
    /// `eligible` (a useful sync source — not dramatically behind us) AND
    /// the slot is free or the incumbent has made no progress within
    /// `stale`. The incumbent always retains regardless of `eligible` (it
    /// may have caught up past its own handshake head while leading) and
    /// without resetting its progress timer (so a busy-looping-but-not-
    /// applying leader can still be displaced).
    pub fn claim_or_check(&self, peer: &str, stale: Duration, eligible: bool) -> bool {
        let mut g = self.inner.lock().expect("SyncLeadership poisoned");
        // Already the leader → retain unconditionally.
        if g.leader.as_deref() == Some(peer) {
            return true;
        }
        // A challenger must be a useful sync source to take the slot.
        if !eligible {
            return false;
        }
        let free_or_stale = g.leader.is_none() || g.last_progress.elapsed() >= stale;
        if free_or_stale {
            g.leader = Some(peer.to_string());
            g.last_progress = Instant::now();
            true
        } else {
            false
        }
    }

    /// Reset the staleness timer — the leader just applied a block.
    /// No-op if `peer` isn't the current leader.
    pub fn note_progress(&self, peer: &str) {
        let mut g = self.inner.lock().expect("SyncLeadership poisoned");
        if g.leader.as_deref() == Some(peer) {
            g.last_progress = Instant::now();
        }
    }

    /// Relinquish leadership if `peer` holds it (on disconnect), freeing
    /// the slot so a standby can take over immediately rather than waiting
    /// out [`LEADERSHIP_STALE`].
    pub fn release(&self, peer: &str) {
        let mut g = self.inner.lock().expect("SyncLeadership poisoned");
        if g.leader.as_deref() == Some(peer) {
            g.leader = None;
        }
    }
}

impl Default for SyncLeadership {
    fn default() -> Self {
        Self::new()
    }
}

/// Block-sync driver. Hold one per node; spawn it on a task.
pub struct SyncDriver {
    state: StateBackends,
    blocks_backend: Arc<dyn KvBackend>,
    config: SyncConfig,
    stats: DriverStats,
    /// Per-session 64-byte node id. Generated once at driver
    /// construction so every dial looks like the same node to the peer
    /// (which is what java-tron does) but different from any prior
    /// session — fixes `DUPLICATE_PEER` on restart.
    node_id: Vec<u8>,
    /// Optional metrics sink. When attached, per-event counters
    /// (blocks applied, rejected, peer failures, reconnects) are bumped
    /// in parallel with the `DriverStats` struct.
    metrics: Option<Arc<tron_rpc::Metrics>>,
    /// Optional tx mempool. When attached, we subscribe to its
    /// broadcast channel and forward each accepted tx as a `Trx`
    /// frame on the current peer connection.
    mempool: Option<Arc<TxMempool>>,
    /// In-memory fork tree (java-tron's `KhaosDatabase`). Tracks every
    /// block we receive, links siblings into fork branches, dedups
    /// repeats, and buffers orphans whose parent hasn't arrived yet.
    /// Always present once construction completes — used on every
    /// `accept_block` to decide between extension / dedup / orphan-
    /// stash / fork-switch.
    khaos: Arc<tron_consensus::KhaosDb>,
    /// True once `khaos` has been seeded with our current head — set
    /// in `accept_block` on the first push (when the chain is empty
    /// at startup) or by `seed_khaos_from_head` after a restart.
    khaos_started: bool,
    /// Per-block undo log for KhaosDb Phase B reorg-with-rollback.
    /// Optional because lightweight tests / read-only nodes don't need
    /// the rollback infrastructure. When `None`, `accept_block` uses
    /// the no-undo execute path; `ReorgRequired` becomes informational
    /// only. When `Some`, every applied block writes an undo record
    /// here and `accept_block` will perform a real reorg.
    undo_store: Option<tron_chainbase::BlockUndoStore>,
    /// Cross-store atomic-flush manifest. When attached, every
    /// block-apply through the BlockSession path goes through
    /// `execute_block_with_undo_and_checkpoint` — writes for the
    /// block are captured in one durable manifest BEFORE the per-
    /// store batches run, so a crash mid-flush is replayed on the
    /// next startup. Without this, per-store atomicity is RocksDB's
    /// WriteBatch only; a crash between two stores' batches leaves
    /// them out of sync. Skipped when the snapshot stack is attached
    /// (which already provides cross-store atomicity at horizon-flush
    /// time through its own checkpoint pathway).
    checkpoint: Option<tron_chainbase::CheckPointV2>,
    /// Outbound channel for blocks produced by the local SR runtime.
    /// When set, the dispatch loop subscribes and forwards every
    /// produced block to its peer as a `MessageType::Block` frame —
    /// the same path peer-relayed blocks take inbound. Without this,
    /// the SR runtime applies blocks locally but they never leave the
    /// node; useful only for tests / standalone testnets.
    produced_blocks_tx: Option<tokio::sync::broadcast::Sender<crate::sr_runtime::ProducedBlockNotice>>,
    /// PBFT channels — when set, inbound `PbftMsg` frames get
    /// decoded and forwarded into the runtime's inbound channel;
    /// outbound vote casts from the runtime get forwarded as
    /// `PbftMsg` frames to this peer.
    pbft_channels: Option<crate::pbft_runtime::PbftChannels>,
    /// Optional cross-restart peer-dial-recency tracker. When set,
    /// every dial attempt touches this; the runtime flushes it to
    /// disk so restarts don't re-dial peers still inside their 60s
    /// `bannedNodes` window.
    peer_state: Option<crate::peer_state::PeerState>,
    /// Optional logsfilter / eventer fan-out. When attached, every
    /// successful `accept_block` emits a `BlockEvent` + one
    /// `TransactionEvent` per tx for downstream consumers (Kafka
    /// indexer, Prometheus counter, etc.). `None` makes block emit a
    /// noop — keeps the path zero-cost for nodes that don't subscribe.
    event_bus: Option<EventBus>,
    /// Optional cross-rotation SR snapshot. Shared with the PBFT
    /// runtime so cross-maintenance vote acceptance follows
    /// java-tron's `before`/`current` rule. The sync driver writes
    /// `MaintenanceRotation` from each accepted block's
    /// `BlockExecutionReport` into the snapshot; the PBFT runtime
    /// reads it. `None` skips the rotation update — PBFT then falls
    /// back to the on-disk active list (the pre-fix behavior).
    sr_snapshot: Option<tron_consensus::SharedSrEpochSnapshot>,
    /// Optional per-peer disconnect/interactive-time table. When
    /// attached, the peer loop calls `touch` on every inbound frame
    /// and `record_local_disconnect`/`record_remote_disconnect` on the
    /// matching exit path. The shared `ResilienceService` reads these
    /// to decide eviction candidates.
    node_statistics: Option<crate::node_statistics::NodeStatisticsTable>,
    /// Optional shared peer-registry. SyncDriver registers its peer
    /// snapshot on handshake-success and unregisters on task exit.
    /// The `ResilienceService` reads from this registry to enumerate
    /// live peers.
    peer_registry: Option<crate::PeerRegistry>,
    /// Optional eviction-signal source. When the resilience service
    /// asks us to drop a peer, the peer key is sent on this broadcast
    /// channel; matching SyncDrivers exit cleanly via `PeerFailure`.
    /// Stored as the sender so the per-peer loop can call
    /// `subscribe()` each iteration.
    eviction_tx: Option<tokio::sync::broadcast::Sender<String>>,
    /// Executor-side trace recording config, driven by `vm.*` in the
    /// node config. Applied to every `execute_block_with_undo` call so
    /// the block-apply path honors `vm.saveInternalTx` / `vm.vmTrace`.
    /// Default = java-tron parity (all off).
    exec_config: tron_executor::ExecConfig,
    /// Optional snapshot stack — when attached, every block-apply
    /// wraps its state mutations in a tentative-write layer that can
    /// be revoked on reorg. Replaces the `BlockUndoStore`-based reorg
    /// path with java-tron's `SnapshotManager`-style overlay model.
    /// When `None`, falls back to the legacy undo-log path. Operators
    /// can enable the new path via `daemon.snapshot_reorg` in the
    /// config; the default stays on the legacy path until the
    /// snapshot stack has been exercised across the SR + multi-peer
    /// concurrency surface.
    /// Optional snapshot stack — the coordinator owns horizon
    /// management and block_num tracking. When set, every block
    /// apply goes through `SnapshotStack::apply_block` /
    /// `SnapshotStack::reorg`, which serialise operations across
    /// any other tasks (SR runtime, other per-peer drivers) using
    /// the same coordinator.
    snapshot_stack: Option<crate::storage::SnapshotStack>,
    /// Optional WebSocket pubsub broker. When attached, every
    /// applied block fires a `newHeads` notification and every VM
    /// log on the block fires a `logs` notification. Without this,
    /// pubsub stays silent on the inbound (sync) side; the SR
    /// runtime's local apply still publishes if it has its own
    /// broker handle.
    pubsub: Option<Arc<tron_rpc::PubSubBroker>>,
    /// When `true`, every tx inside an incoming block has its
    /// `ref_block_bytes` / `ref_block_hash` validated against the
    /// chain's `BlockIndexStore` before the block is accepted. A bad
    /// ref_block rejects the entire block with
    /// `AcceptOutcome::RejectedValidation` (mirrors java-tron's
    /// `Manager.pushBlock → TransactionUtil.validateRefBlock` —
    /// structurally-invalid tx in a block means the whole block is
    /// malformed). Defaults to `false` so test setups whose
    /// `block_index` isn't populated still work; production wires
    /// `with_strict_ref_block_check()` to turn it on. See
    /// `crate::ref_block` for the validator implementation.
    strict_ref_block: bool,
    /// Newest-first rolling window of recently-applied `(block_num,
    /// witness)` pairs, used to advance the DPoS solidified-block
    /// pointer as blocks sync (`update_solidified`). java-tron advances
    /// solidity every block via `updateLatestSolidifiedBlock`; without
    /// this the pointer only moves on PBFT commit traffic, and the head
    /// jams ~1024 blocks past the last solidified block once the
    /// reversible window fills (`gate_new_head_against_solidified`).
    /// Capped at [`Self::SOLID_WINDOW`] entries — enough to always
    /// contain ⌈2/3⌉ distinct active witnesses.
    recent_witnesses: VecDeque<tron_consensus::RecentBlock>,
    /// Raw wire bytes of the block currently being handed to
    /// [`Self::accept_block`], set by the peer loop right before the call
    /// and consumed inside it. Lets `accept_block` validate `txTrieRoot`
    /// against the *original* transaction bytes (M-20) — prost's
    /// `BTreeMap` map round-trip reorders `ret` map entries and would
    /// otherwise spuriously fail the merkle. `None` for in-memory callers
    /// (tests / SR runtime), which fall back to the decoded check (their
    /// blocks re-encode canonically anyway).
    pending_raw_block: Option<Bytes>,
    /// Optional shared single-active-syncer coordinator. The runtime
    /// spawns one driver per peer; without coordination they all apply
    /// the same blocks against shared state concurrently, racing the head
    /// and flooding spurious `unlinked` / `ParentLinkMismatch` rejections.
    /// When attached, exactly one driver leads (requests + applies); the
    /// rest stay connected as standby and take over only if the leader
    /// stalls or drops. `None` ⇒ no coordination (tests / SR / single
    /// peer), preserving the original always-active behavior.
    leadership: Option<Arc<SyncLeadership>>,
    /// Progress-log throttle + rate state: `(when, blocks_applied_then)` at
    /// the last emitted sync line. Time-gated so the cadence is readable at
    /// any sync speed (a count gate is a flood during catch-up and silent at
    /// the tip).
    last_progress_log: Option<(Instant, usize)>,
    /// Whether the last progress line reported us caught up to the tip. Used
    /// to log the catch-up→tip and tip→falling-behind transitions once each.
    at_tip: bool,
    /// Optional shared, continuously-growing peer pool for ROTATION drivers
    /// (java-tron-like always-active discovery). A background feeder keeps
    /// appending freshly-discovered peers (deduped) to it; the driver merges
    /// any new entries into its working set each loop so a months-long run
    /// keeps finding peers as the startup set ages — without this, the dial
    /// list is frozen at the startup snapshot. `None` for pinned drivers
    /// (configured `--peer`s), which keep their fixed `config.peers`.
    dynamic_pool: Option<Arc<std::sync::Mutex<Vec<String>>>>,
}

impl SyncDriver {
    pub fn new(state: StateBackends, config: SyncConfig) -> Self {
        let blocks_backend = config.blocks_backend.clone();
        // Derive a fresh 64-byte node_id at startup from a random
        // secp256k1 private key. java-tron treats the node_id as
        // the uncompressed pubkey (X || Y, 64 bytes, no 0x04 marker).
        // Mainnet peers tolerate any well-shaped 64-byte blob from a
        // full node, but reusing the same bytes across sessions makes
        // the peer flag us as DUPLICATE_PEER until its internal
        // dedup-window expires (minutes).
        let node_id = random_node_id();
        Self {
            state,
            blocks_backend,
            config,
            stats: DriverStats::default(),
            node_id,
            metrics: None,
            mempool: None,
            khaos: Arc::new(tron_consensus::KhaosDb::new()),
            khaos_started: false,
            last_progress_log: None,
            at_tip: false,
            undo_store: None,
            checkpoint: None,
            produced_blocks_tx: None,
            pbft_channels: None,
            peer_state: None,
            event_bus: None,
            sr_snapshot: None,
            node_statistics: None,
            peer_registry: None,
            eviction_tx: None,
            // The sync driver validates `txTrieRoot` against each block's
            // original wire bytes in `accept_block` (M-20); the executor
            // only sees the decoded block, so disable its (re-encode-based)
            // tx-trie check to avoid a spurious mismatch on `ret` maps.
            exec_config: tron_executor::ExecConfig {
                verify_tx_trie: false,
                ..tron_executor::ExecConfig::default()
            },
            snapshot_stack: None,
            pubsub: None,
            strict_ref_block: false,
            recent_witnesses: VecDeque::new(),
            dynamic_pool: None,
            pending_raw_block: None,
            leadership: None,
        }
    }

    /// Attach the shared single-active-syncer coordinator. All per-peer
    /// drivers in a node share one [`SyncLeadership`]; exactly one leads
    /// (requests + applies blocks) while the rest stand by. Without it,
    /// every driver applies the same blocks concurrently and races the
    /// shared head. Omitted by tests / the SR runtime / single-peer setups,
    /// which keep the always-active behavior.
    pub fn with_leadership(mut self, leadership: Arc<SyncLeadership>) -> Self {
        self.leadership = Some(leadership);
        self
    }

    /// Attach a shared, continuously-grown discovery pool. ROTATION
    /// drivers merge newly-discovered peers from it each loop iteration so
    /// the dial set stays fresh over long runs. Pinned (configured) drivers
    /// leave this unset and keep their fixed `config.peers`.
    pub fn with_dynamic_pool(mut self, pool: Arc<std::sync::Mutex<Vec<String>>>) -> Self {
        self.dynamic_pool = Some(pool);
        self
    }

    /// Whether this driver may act as the active syncer right now —
    /// claiming or retaining leadership if it can. With no coordinator
    /// attached, always `true` (original behavior).
    fn is_active_syncer(&self, peer: &str, eligible: bool) -> bool {
        match &self.leadership {
            Some(l) => l.claim_or_check(peer, LEADERSHIP_STALE, eligible),
            None => true,
        }
    }

    /// Record that the active syncer applied a block, resetting the
    /// leadership staleness timer. No-op without a coordinator.
    fn note_sync_progress(&self, peer: &str) {
        if let Some(l) = &self.leadership {
            l.note_progress(peer);
        }
    }

    /// Emit a human-readable sync-progress line for a freshly-applied block.
    ///
    /// Answers the three questions an operator actually has while watching a
    /// sync: *what is the node doing* (syncing vs. following the tip), *how
    /// fast are blocks coming in* (blk/s), and *what time are these blocks
    /// from* (the block's UTC wall-clock + how far behind real time). It's
    /// time-throttled — a count gate floods during catch-up and goes silent
    /// at the tip — and logs the catch-up→tip transition once.
    ///
    /// `progress_log_interval == 0` disables it entirely.
    fn log_sync_progress(&mut self, block: &Block, block_num: i64, peer: &str) {
        use std::time::{SystemTime, UNIX_EPOCH};
        if self.config.progress_log_interval == 0 {
            return;
        }

        let block_ts = block
            .block_header
            .as_ref()
            .and_then(|h| h.raw_data.as_ref())
            .map(|r| r.timestamp)
            .unwrap_or(0);
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let behind_ms = (now_ms - block_ts).max(0);
        // Within ~90s of real time (a few block intervals) counts as "at the
        // tip" — past that we're catching up.
        const TIP_MS: i64 = 90_000;
        let is_tip = behind_ms <= TIP_MS;

        // Transition lines fire once, regardless of the throttle.
        if is_tip && !self.at_tip {
            info!(
                "caught up to chain tip at #{} ({}) — now following live blocks",
                logfmt::commas(block_num),
                logfmt::utc_millis(block_ts),
            );
            self.at_tip = true;
        } else if !is_tip && self.at_tip {
            info!(
                "fell behind the tip at #{} — re-syncing ({} behind)",
                logfmt::commas(block_num),
                logfmt::duration_ms(behind_ms),
            );
            self.at_tip = false;
        }

        // Recurring progress line: frequent while catching up, sparse once
        // we're just following the tip.
        let now = Instant::now();
        let min_interval = if is_tip {
            Duration::from_secs(30)
        } else {
            Duration::from_secs(5)
        };
        if let Some((last, _)) = self.last_progress_log {
            if now.duration_since(last) < min_interval {
                return;
            }
        }
        let rate = match self.last_progress_log {
            Some((last, prev_blocks)) => {
                let secs = now.duration_since(last).as_secs_f64();
                if secs > 0.0 {
                    self.stats.blocks_applied.saturating_sub(prev_blocks) as f64 / secs
                } else {
                    0.0
                }
            }
            None => 0.0,
        };

        let height = logfmt::commas(block_num);
        let when = logfmt::utc_millis(block_ts);
        let behind = logfmt::duration_ms(behind_ms);
        let mut line = if is_tip {
            format!("at tip  #{height}  {when}  ({behind} behind)  ·  via {peer}")
        } else {
            format!("syncing #{height}  {when}  ({behind} behind)  ·  {rate:.0} blk/s  ·  via {peer}")
        };
        let vr = self.stats.blocks_rejected_validation;
        let er = self.stats.blocks_rejected_execution;
        if vr > 0 || er > 0 {
            line.push_str(&format!("  ·  {vr} val-rej  {er} exec-rej"));
        }
        info!("{line}");
        self.last_progress_log = Some((now, self.stats.blocks_applied));
    }

    /// Free the leadership slot if this driver's `peer` holds it (called
    /// when the connection drops). No-op without a coordinator.
    fn release_leadership(&self, peer: &str) {
        if let Some(l) = &self.leadership {
            l.release(peer);
        }
    }

    /// Attach a WebSocket pubsub broker. With this set, every
    /// successful block-apply pushes a `newHeads` + per-log
    /// notification to subscribers.
    pub fn with_pubsub(mut self, broker: Arc<tron_rpc::PubSubBroker>) -> Self {
        self.pubsub = Some(broker);
        self
    }

    /// Enable per-tx `ref_block_bytes` / `ref_block_hash` validation
    /// during `accept_block`. Production callers should always set
    /// this; the daemon's runtime wires it in. The opt-in is
    /// deliberate so that the many tron-node integration tests that
    /// construct synthetic blocks against a fresh, empty
    /// `BlockIndexStore` don't have their txs mass-rejected — those
    /// tests exercise the sync driver's orchestration, not the
    /// per-tx replay gate.
    pub fn with_strict_ref_block_check(mut self) -> Self {
        self.strict_ref_block = true;
        self
    }

    /// Attach a [`crate::storage::SnapshotStack`]. With this attached,
    /// `accept_block` drives per-block `apply_block` (advance + exec
    /// + horizon-merge) and `perform_reorg_via_snapshot` calls the
    /// coordinator's `reorg` API. The coordinator owns horizon /
    /// block_nums / checkpoint; configure them via
    /// `SnapshotStack::with_horizon` / `with_checkpoint` at
    /// construction time. Without this, the driver falls back to
    /// the legacy `BlockUndoStore` reorg path.
    pub fn with_snapshot_stack(mut self, stack: crate::storage::SnapshotStack) -> Self {
        self.snapshot_stack = Some(stack);
        self
    }

    /// Override the executor [`tron_executor::ExecConfig`] used at
    /// block-apply time. The runtime threads the parsed `vm.*` knobs
    /// through here so peer-relayed blocks honor `vm.saveInternalTx`
    /// etc. Defaults to java-tron parity (all off).
    pub fn with_exec_config(mut self, config: tron_executor::ExecConfig) -> Self {
        self.exec_config = config;
        // The sync driver always owns `txTrieRoot` validation (raw-bytes
        // check in `accept_block`), so keep the executor's decoded check off
        // regardless of what the runtime threads in — otherwise it would
        // spuriously reject blocks whose `ret` carries a non-sorted map.
        self.exec_config.verify_tx_trie = false;
        self
    }

    /// Attach a shared [`NodeStatisticsTable`]. Per-frame inbound
    /// activity bumps `touch`; peer exit records the disconnect reason
    /// via `record_local_disconnect`. The resilience scheduler reads
    /// from the same handle to decide eviction.
    pub fn with_node_statistics(
        mut self,
        table: crate::node_statistics::NodeStatisticsTable,
    ) -> Self {
        self.node_statistics = Some(table);
        self
    }

    /// Attach the shared peer registry. The driver registers its peer
    /// snapshot on handshake-success and unregisters on task exit so
    /// the [`ResilienceService`] can enumerate live peers.
    pub fn with_peer_registry(mut self, registry: crate::PeerRegistry) -> Self {
        self.peer_registry = Some(registry);
        self
    }

    /// Attach an eviction-signal sender. The driver subscribes per
    /// peer-pass; when the resilience scheduler sends a peer key,
    /// matching SyncDrivers exit cleanly via `PeerFailure`.
    pub fn with_eviction_signal(
        mut self,
        tx: tokio::sync::broadcast::Sender<String>,
    ) -> Self {
        self.eviction_tx = Some(tx);
        self
    }

    /// Attach the cross-rotation SR snapshot. After each block applies,
    /// any [`tron_executor::MaintenanceRotation`] surfaced on the
    /// report is folded into this snapshot so the shared PBFT runtime
    /// validates cross-rotation votes against the right SR list.
    pub fn with_sr_snapshot(
        mut self,
        snap: tron_consensus::SharedSrEpochSnapshot,
    ) -> Self {
        self.sr_snapshot = Some(snap);
        self
    }

    /// Attach an eventer bus. Every successful `accept_block` emits a
    /// block trigger + one transaction trigger per tx in the block.
    /// Without this builder call the emit path is a noop.
    pub fn with_event_bus(mut self, bus: EventBus) -> Self {
        self.event_bus = Some(bus);
        self
    }

    /// Attach the SR runtime's produced-blocks broadcast channel.
    /// While connected to a peer, every notice received here gets
    /// forwarded as a `MessageType::Block` frame, mirroring the
    /// outbound tx-broadcast path. Without this builder call, the SR
    /// runtime produces blocks but they're never propagated to
    /// peers — useful only for tests / standalone testnets.
    pub fn with_produced_blocks(
        mut self,
        tx: tokio::sync::broadcast::Sender<crate::sr_runtime::ProducedBlockNotice>,
    ) -> Self {
        self.produced_blocks_tx = Some(tx);
        self
    }

    /// Attach the PBFT runtime's channels. Inbound `PbftMsg` frames
    /// get pushed onto `channels.inbound`; outbound vote casts (sent
    /// by the runtime to `channels.outbound`) get forwarded to this
    /// peer as `PbftMsg` frames.
    pub fn with_pbft(mut self, channels: crate::pbft_runtime::PbftChannels) -> Self {
        self.pbft_channels = Some(channels);
        self
    }

    /// Attach a block-undo store. Without this, KhaosDb's
    /// `ReorgRequired` outcome is informational only — there's no undo
    /// log to roll back with. Production setups should always attach
    /// one; tests can omit it for the cheaper no-undo execute path.
    pub fn with_undo_store(mut self, undo: tron_chainbase::BlockUndoStore) -> Self {
        self.undo_store = Some(undo);
        self
    }

    /// Attach a cross-store checkpoint. Only takes effect on the
    /// BlockSession path (i.e., when an undo store is attached and
    /// no snapshot stack is attached) — the snapshot-stack path
    /// already provides cross-store atomicity via its own checkpoint
    /// flow, so this is ignored there.
    pub fn with_checkpoint(mut self, cp: tron_chainbase::CheckPointV2) -> Self {
        self.checkpoint = Some(cp);
        self
    }

    /// Attach a metrics sink. Each sync-side event (block accepted,
    /// rejected, peer failure, reconnect) bumps the corresponding
    /// Prometheus counter.
    pub fn with_metrics(mut self, metrics: Arc<tron_rpc::Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Attach the transaction mempool. The sync loop subscribes to its
    /// broadcast channel and, while connected to a peer, forwards
    /// every newly-accepted tx as a `MessageType::Trx` frame.
    ///
    /// A peer may immediately reject our broadcast (with `Disconnect`
    /// or just by closing); we don't track per-peer acceptance — the
    /// goal is best-effort propagation. If the peer drops we'll
    /// reconnect via the usual rotation and the next-current-peer will
    /// receive the same tx if it's still pending at that time.
    pub fn with_mempool(mut self, mempool: Arc<TxMempool>) -> Self {
        self.mempool = Some(mempool);
        self
    }

    /// Attach a [`crate::peer_state::PeerState`] for cross-restart
    /// dial-recency tracking. Each dial attempt updates the
    /// peer-state; the runtime is expected to flush on shutdown.
    pub fn with_peer_state(mut self, state: crate::peer_state::PeerState) -> Self {
        self.peer_state = Some(state);
        self
    }

    /// Run the driver until shutdown or until `max_blocks` is reached.
    pub async fn run(&mut self, mut shutdown: broadcast::Receiver<()>) -> DriverStats {
        // Restore the block-store/head invariant first: drop any blocks
        // persisted-but-never-executed by a prior stall (M-19), so the
        // gap is re-fetched rather than skipped as already-held.
        self.reconcile_stores_to_head();
        // Then advance the solidified pointer from already-applied on-disk
        // blocks before processing anything new. A node resumed at/near
        // `solid + WALK_HORIZON` (e.g. one synced by a pre-M-18 binary)
        // would otherwise deadlock — the head-promotion gate rejects the
        // next block before any apply could advance solidity.
        self.seed_solidified_from_disk();

        if self.config.peers.is_empty() && self.dynamic_pool.is_none() {
            warn!("no peers configured; sync driver idle");
            return self.stats.clone();
        }

        // Working dial list. For pinned drivers this is just `config.peers`
        // (fixed). For rotation drivers it starts from `config.peers` (the
        // startup discovery snapshot) and GROWS as the shared `dynamic_pool`
        // feeder appends freshly-discovered peers — merged in at the top of
        // each loop iteration so a long-running node keeps a fresh dial set.
        let mut peers: Vec<String> = self.config.peers.clone();
        if let Some(dp) = &self.dynamic_pool {
            if let Ok(g) = dp.lock() {
                for p in g.iter() {
                    if !peers.contains(p) {
                        peers.push(p.clone());
                    }
                }
            }
        }
        let mut known: std::collections::HashSet<String> = peers.iter().cloned().collect();

        // Randomize peer dial order per-session. Two reasons:
        //  1. Without it, every restart hammers the same seed first —
        //     load-skewed and triggers `DUPLICATE_PEER` / `RECENT_DISCONNECT`
        //     on the same peer after a quick restart.
        //  2. On `PeerFailure` we hop to a *random* different peer
        //     instead of `+1 % len`, so a misbehaving peer in the
        //     middle of the list doesn't gate the whole pool.
        let mut rng = XorShift64::seed_from_clock();
        let mut shuffled: Vec<usize> = (0..peers.len()).collect();
        rng.shuffle(&mut shuffled);
        // Per-peer failure counter for exponential backoff (indexed by
        // original `peers` position, not by shuffle order).
        let mut peer_failures: Vec<u32> = vec![0; peers.len()];
        // Per-peer FETCH_FAIL count. When a peer responds to our
        // `SyncBlockChain` with a `ChainInventory` and then immediately
        // disconnects with `FETCH_FAIL (19)` on the subsequent
        // `FetchInvData`, they have inventory but pruned the bodies —
        // a modern validator that can't serve archive sync. After 2
        // such failures we mark them `archive_incapable` and exclude
        // them from rotation until *all* peers are excluded (at which
        // point we reset, since something fundamental is wrong).
        let mut fetch_fail_count: Vec<u32> = vec![0; peers.len()];
        let mut archive_incapable: Vec<bool> = vec![false; peers.len()];
        // Per-peer TIME_BANNED retry count. After 3 consecutive
        // TIME_BANNED rejections (with 90s waits between, so 4.5 min
        // of trying), the peer has us in something stronger than the
        // 60s `bannedNodes` cache — likely an operator anti-abuse
        // shelf. Stop hammering: shelve for 30 min so the deeper ban
        // can decay.
        let mut time_banned_strikes: Vec<u32> = vec![0; peers.len()];
        let mut cursor = 0usize; // index into `shuffled`

        loop {
            // Check shutdown first so we exit promptly even mid-loop.
            if shutdown.try_recv().is_ok() {
                info!("shutdown observed; sync driver exiting");
                return self.stats.clone();
            }
            // Always-active discovery: pull any peers the shared feeder has
            // found since we last looked into our working set, extending the
            // per-peer state vectors + shuffle order in lockstep. Bounded in
            // practice (the Kad table is capped), so `peers` doesn't grow
            // without limit over a months-long run.
            if let Some(dp) = &self.dynamic_pool {
                if let Ok(g) = dp.lock() {
                    for p in g.iter() {
                        if known.insert(p.clone()) {
                            peers.push(p.clone());
                            peer_failures.push(0);
                            fetch_fail_count.push(0);
                            archive_incapable.push(false);
                            time_banned_strikes.push(0);
                            shuffled.push(peers.len() - 1);
                        }
                    }
                }
            }
            // If we have no peers yet (rotation driver waiting for the
            // feeder), idle briefly rather than busy-spin or index-panic.
            if peers.is_empty() {
                tokio::select! {
                    _ = shutdown.recv() => return self.stats.clone(),
                    _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {}
                }
                continue;
            }
            if cursor >= shuffled.len() {
                cursor = 0;
            }
            let peer_idx = shuffled[cursor];
            let peer = peers[peer_idx].clone();
            // Stamp the dial-recency tracker before we dial, so even
            // if we crash mid-attempt the next restart knows we tried
            // this peer recently.
            if let Some(ps) = &self.peer_state {
                ps.touch(&peer);
            }
            let outcome = tokio::select! {
                _ = shutdown.recv() => {
                    info!("shutdown observed (mid-peer); sync driver exiting");
                    // Clean up peer registry / stats on shutdown too —
                    // dropping a SyncDriver mid-handshake would leave
                    // stale entries otherwise.
                    if let Some(reg) = &self.peer_registry {
                        reg.unregister(&peer);
                    }
                    return self.stats.clone();
                }
                o = self.run_against_peer(&peer) => o,
            };
            // Drop the live registry entry now — the peer-pass is
            // over either way. Stats table retains the disconnect
            // record (set just above PeerFailure / inside the
            // P2pDisconnect branch).
            if let Some(reg) = &self.peer_registry {
                reg.unregister(&peer);
            }
            match outcome {
                PeerOutcome::CaughtUp => {
                    peer_failures[peer_idx] = 0;
                    tokio::select! {
                        _ = shutdown.recv() => return self.stats.clone(),
                        _ = tokio::time::sleep(self.config.tail_interval) => {}
                    }
                }
                PeerOutcome::CapReached => {
                    info!(applied = self.stats.blocks_applied, "max_blocks cap reached; exiting");
                    return self.stats.clone();
                }
                PeerOutcome::PeerFailure(reason) => {
                    self.stats.peer_failures += 1;
                    if let Some(m) = &self.metrics {
                        m.inc_peer_failures();
                    }
                    // The connection dropped — if we were the active
                    // syncer, free the leadership slot now so a standby
                    // takes over immediately instead of waiting out
                    // LEADERSHIP_STALE. (CaughtUp/CapReached retain it.)
                    self.release_leadership(&peer);
                    // Classify the failure into a NodeStatistics
                    // DisconnectReason for the resilience scheduler.
                    // The lossy "best effort" mapping below mirrors
                    // java-tron's NodeStatistics setter, where text
                    // disconnect reasons are coalesced into the wire
                    // enum on observation.
                    if let Some(stats) = &self.node_statistics {
                        let reason_code = if reason.contains("peer app-disconnected") {
                            crate::node_statistics::DisconnectReason::Unknown
                        } else if reason.contains("FETCH_FAIL") {
                            crate::node_statistics::DisconnectReason::FetchFail
                        } else if reason.contains("TIME_BANNED") {
                            crate::node_statistics::DisconnectReason::TimeBanned
                        } else if reason.contains("resilience") {
                            crate::node_statistics::DisconnectReason::RandomElimination
                        } else {
                            crate::node_statistics::DisconnectReason::BadProtocol
                        };
                        // Remote-initiated (peer told us to disconnect)
                        // vs local-initiated (we failed our side).
                        if reason.contains("peer app-disconnected") {
                            stats
                                .record_remote_disconnect(&peer, reason_code)
                                .await;
                        } else {
                            stats
                                .record_local_disconnect(&peer, reason_code)
                                .await;
                        }
                    }
                    // Distinguish "peer rejected us with a rate-limit
                    // code" (try another peer right away) from "real
                    // network failure" (back off this peer).
                    //
                    // tronprotocol/libp2p uses these codes when a peer
                    // is full / has us in a cooldown window / has too
                    // many connections from our IP, not when our message
                    // is structurally broken. Treat them the same as
                    // TOO_MANY_PEERS: skip to another peer with no
                    // per-peer backoff penalty.
                    //
                    // * BAD_PROTOCOL (1)              — also used as a
                    //   catch-all rate-limit on saturated public seeds.
                    // * DUPLICATE_PEER (3)            — recent reconnect.
                    // * RANDOM_ELIMINATION (5)        — peer hit
                    //   max-connections-per-IP and randomly dropped us.
                    // Match on the parenthesised enum name in the
                    // formatted HandshakeError::Libp2pDisconnected
                    // display: "peer refused libp2p handshake with
                    // code N (NAME)" — see crates/tron-net/src/peer.rs.
                    //
                    // These are the codes tronprotocol/libp2p uses for
                    // saturation / per-IP rate-limit rejections (not
                    // structurally bad messages). Per current mainnet
                    // `DisconnectCode.java`:
                    //   1 = TOO_MANY_PEERS
                    //   3 = TIME_BANNED   (recent-disconnect cooldown,
                    //                      ChannelManager bans IP for 60s)
                    //   4 = DUPLICATE_PEER (per-node-id dedup)
                    //   5 = MAX_CONNECTION_WITH_SAME_IP
                    //
                    // TIME_BANNED is special: the peer has put our IP
                    // in a `bannedNodes` cache with a 60s expiry (see
                    // `ChannelManager.notifyDisconnect`). Retrying
                    // within that window is just wasted dials.
                    //
                    // The other rate-limits (slot full, dup id) are NOT
                    // bans on arrival — but re-dialing inside that same
                    // ~60s reconnect window is exactly what *creates* a
                    // TIME_BANNED. With one single-peer driver per peer
                    // (~60 of them) and a 500ms backoff here, every
                    // driver assigned to a full peer re-dialed it twice a
                    // second and got the whole fleet banned — the
                    // "excessive issues connecting to peers" churn. So we
                    // back these off past the reconnect window too (a
                    // full public peer almost never frees a slot in under
                    // a minute anyway), which prevents the ban instead of
                    // serving it out afterwards.
                    let is_time_banned = reason.contains("(TIME_BANNED)");
                    let is_other_rate_limit = reason.contains("(TOO_MANY_PEERS)")
                        || reason.contains("(DUPLICATE_PEER)")
                        || reason.contains("(MAX_CONNECTION_WITH_SAME_IP)");
                    // FETCH_FAIL (app-disconnect reason 19): peer
                    // served us a ChainInventory but disconnected on
                    // the subsequent FetchInvData. They have inventory
                    // metadata but pruned the block bodies — a modern
                    // validator that can't serve archive sync. Count
                    // these; demote on the 2nd occurrence.
                    let is_fetch_fail = reason.contains("app-disconnected with reason code 19");
                    if is_fetch_fail {
                        fetch_fail_count[peer_idx] =
                            fetch_fail_count[peer_idx].saturating_add(1);
                        if fetch_fail_count[peer_idx] >= 2 && !archive_incapable[peer_idx] {
                            archive_incapable[peer_idx] = true;
                            info!(
                                peer = peer.as_str(),
                                fetch_fails = fetch_fail_count[peer_idx],
                                "peer marked archive-incapable; excluding from rotation"
                            );
                        }
                    }
                    if is_time_banned {
                        time_banned_strikes[peer_idx] =
                            time_banned_strikes[peer_idx].saturating_add(1);
                    } else {
                        time_banned_strikes[peer_idx] = 0;
                    }
                    let backoff = if is_time_banned {
                        if time_banned_strikes[peer_idx] >= 3 {
                            // Three consecutive TIME_BANNED with 90s
                            // waits in between (=4.5 min) — operator
                            // shelf in play, back off hard.
                            warn!(
                                peer = peer.as_str(),
                                strikes = time_banned_strikes[peer_idx],
                                "peer in deep ban; shelving for 30 min"
                            );
                            std::time::Duration::from_secs(30 * 60)
                        } else {
                            // 90s = 60s ban window + comfortable margin
                            // past the edge of `bannedNodes` TTL.
                            std::time::Duration::from_secs(90)
                        }
                    } else if is_other_rate_limit {
                        // Past the upstream's ~60s reconnect window (with
                        // margin) so re-dialing a full peer can't escalate
                        // into a TIME_BANNED. Matches the TIME_BANNED wait.
                        std::time::Duration::from_secs(90)
                    } else {
                        peer_failures[peer_idx] = peer_failures[peer_idx].saturating_add(1);
                        backoff_for(self.config.initial_backoff, peer_failures[peer_idx])
                    };
                    if is_time_banned {
                        debug!(peer = peer.as_str(), reason = reason.as_str(), ?backoff,
                            strikes = time_banned_strikes[peer_idx],
                            "peer banned us; waiting out ban window");
                    } else if is_other_rate_limit {
                        debug!(peer = peer.as_str(), reason = reason.as_str(), ?backoff,
                            "peer rate-limited; rotating");
                    } else if is_expected_peer_failure(&reason) {
                        // Unreachable / full / deduped peers from the
                        // discovery pool — normal churn, not a fault on our
                        // side. Keep at debug so a genuine protocol rejection
                        // (BAD_PROTOCOL / INCOMPATIBLE_VERSION / BAD_MESSAGE)
                        // stands out at warn instead of drowning in noise.
                        debug!(peer = peer.as_str(), reason = reason.as_str(), ?backoff,
                            "peer unavailable; rotating");
                    } else {
                        warn!(peer = peer.as_str(), reason = reason.as_str(), ?backoff,
                            "peer rejected us; backing off");
                    }
                    tokio::select! {
                        _ = shutdown.recv() => return self.stats.clone(),
                        _ = tokio::time::sleep(backoff) => {}
                    }
                    // Hop to a random different peer that hasn't been
                    // archive-demoted. If every peer is demoted (the
                    // whole pool can't serve archive sync) reset the
                    // demotion list so we don't starve out — better to
                    // re-try a known-broken peer than spin forever.
                    let pool_len = shuffled.len();
                    if pool_len > 1 {
                        let all_demoted =
                            shuffled.iter().all(|&i| archive_incapable[i]);
                        if all_demoted {
                            warn!(
                                "all peers archive-demoted; resetting demotion list"
                            );
                            for slot in archive_incapable.iter_mut() {
                                *slot = false;
                            }
                            for slot in fetch_fail_count.iter_mut() {
                                *slot = 0;
                            }
                        }
                        // Try up to `pool_len` candidates to find an
                        // undemoted one different from the current cursor.
                        let mut next = cursor;
                        for _ in 0..pool_len {
                            let candidate = rng.next_usize_below(pool_len);
                            if candidate != cursor
                                && !archive_incapable[shuffled[candidate]]
                            {
                                next = candidate;
                                break;
                            }
                        }
                        // Fallback: linear scan if random sampling
                        // didn't find an undemoted slot.
                        if next == cursor || archive_incapable[shuffled[next]] {
                            for offset in 1..pool_len {
                                let candidate = (cursor + offset) % pool_len;
                                if !archive_incapable[shuffled[candidate]] {
                                    next = candidate;
                                    break;
                                }
                            }
                        }
                        cursor = next;
                    } else {
                        cursor = 0;
                    }
                }
            }
        }
    }

    /// One pass against one peer. Dials, handshakes, runs the
    /// fetch-execute loop until the peer says it has no more or
    /// `max_blocks` is hit.
    async fn run_against_peer(&mut self, peer: &str) -> PeerOutcome {
        self.stats.reconnects += 1;
        if let Some(m) = &self.metrics {
            m.inc_reconnects();
        }
        // Re-randomize node_id for EACH connection attempt. Mainnet
        // peers dedup connections by node_id (`ChannelManager.processPeer`
        // → DUPLICATE_PEER), and an in-flight channel from a previous
        // failed attempt may still be lingering in the peer's `channels`
        // map until netty's idle-timeout reaps it (tens of seconds).
        // Using a fresh node_id per attempt sidesteps the dedup window
        // entirely.
        let attempt_node_id = random_node_id();
        debug!(peer, "dialing");
        let mut conn = match PeerConnection::dial(peer).await {
            Ok(c) => c,
            Err(e) => return PeerOutcome::PeerFailure(format!("dial: {e}")),
        };
        let genesis = genesis_block_id(&mainnet_inputs());
        let head = self.resume_head().unwrap_or(genesis);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);

        // STEP 1: libp2p connection-layer handshake (frame 0xfd).
        // Mainnet peers require this *before* the app-level Hello —
        // sending P2pHello first triggers an immediate Libp2pDisconnect.
        // Values mirror `crates/tron-net/tests/live_mainnet.rs`:
        // network_id=11111 for mainnet, version=2 for libp2p v0.2.
        // The `from.node_id` is a placeholder 64-byte uncompressed
        // pubkey; mainnet peers don't authenticate full nodes here.
        let libp2p_inputs = Libp2pHelloInputs {
            from: Endpoint {
                address: b"127.0.0.1".to_vec(),
                address_ipv6: Vec::new(),
                // Advertise the standard mainnet P2P port (18888) even
                // though we don't listen — java-tron's `NetUtil.validNode`
                // rejects port 0 with `BAD_PROTOCOL` regardless of
                // whether the peer can actually dial us back.
                port: self.config.advertise_port,
                node_id: attempt_node_id.clone(),
            },
            network_id: 11_111,
            version: 2,
            timestamp_ms: now,
        };
        if let Err(e) = conn.libp2p_handshake(libp2p_inputs).await {
            return PeerOutcome::PeerFailure(format!("libp2p_handshake: {e}"));
        }

        // STEP 2: application-layer Hello (frame P2pHello). Carries
        // genesis / solid / head block ids for chain compatibility.
        //
        // Advertise our TRUE solid block (lags head by the finalization
        // gap) and TRUE lowest-held block (our snapshot base, not
        // genesis). The old `solid = head` / `lowest_block_num = 0`
        // defaults are protocol lies that a strict peer can reject — and
        // lite peers (node_type=1) were the ones disconnecting us right
        // after serving an inventory.
        let solid = self.solid_block_id().unwrap_or(head);
        let lowest = self.lowest_block_num();
        let hello = HelloInputs {
            from: Endpoint {
                address: b"127.0.0.1".to_vec(),
                address_ipv6: Vec::new(),
                port: self.config.advertise_port,
                node_id: attempt_node_id.clone(),
            },
            version: MAINNET_P2P_VERSION,
            timestamp_ms: now,
            genesis,
            solid,
            head,
            node_type: 0,
            lowest_block_num: lowest,
            code_version: b"tron-goblin/0.0.1",
        };
        match conn.handshake(hello).await {
            Ok(outcome) => {
                if outcome.is_implicit_accept() {
                    // Peer skipped its reciprocal Hello and went straight
                    // to streaming, so the handshake did NOT verify its
                    // genesis / chain id. We still proceed — mainnet peers
                    // routinely accept implicitly — but per-block
                    // validation on the delivered stream is what actually
                    // anchors us to the right chain. Flag it so an eclipse
                    // attempt via a sinkhole peer is at least visible.
                    warn!(peer, "peer accepted implicitly; chain identity not verified at handshake");
                }
            }
            Err(e) => return PeerOutcome::PeerFailure(format!("handshake: {e}")),
        }
        // Surface the peer's advertised chain state so we can tell whether a
        // peer that then refuses to serve us is genuinely ahead (a real
        // sync-protocol bug on our side) or just behind / a non-serving lite
        // node (peer-quality, expected). `node_type != 0` ⇒ a lite/fullnode
        // variant that may not serve archive sync. (M-22b diagnostics.)
        let (peer_head, peer_solid, peer_node_type, peer_lowest) = match conn.peer_hello() {
            Some(h) => (
                h.head_block_id.as_ref().map(|b| b.number).unwrap_or(-1),
                h.solid_block_id.as_ref().map(|b| b.number).unwrap_or(-1),
                h.node_type,
                h.lowest_block_num,
            ),
            None => (-1, -1, -1, -1),
        };
        let our_head_at_handshake = self.head_number();
        info!(
            peer,
            our_head = our_head_at_handshake,
            peer_head,
            peer_solid,
            peer_node_type,
            peer_lowest,
            "handshake ok"
        );

        // Leadership eligibility, decided once here from the peer's
        // advertised head. We only ever lead-sync from a peer that can
        // actually serve us — i.e. one that ISN'T dramatically behind us.
        // A fresh node (head 0) or one millions of blocks back is a
        // dead-end: it returns empty inventories forever, and without
        // this gate it could win the active-syncer slot and stall us for
        // a full LEADERSHIP_STALE window. The margin is generous (one
        // sync window) so caught-up / live-tip / slightly-behind peers
        // stay eligible; an unknown head (`-1`, peer skipped its Hello)
        // defaults to eligible. Computed once so head drift over a long
        // connection can't later flip a good leader off.
        const LEAD_LAG_MARGIN: i64 = 65_536;
        let leader_eligible =
            !(peer_head >= 0 && peer_head + LEAD_LAG_MARGIN < our_head_at_handshake);

        // Register this peer with the live registry (if attached) so
        // the resilience scheduler can see it as a candidate. Fields
        // refreshed in-place as the loop runs.
        if let Some(reg) = &self.peer_registry {
            reg.register(
                peer,
                crate::resilience::PeerSnapshot {
                    key: peer.to_string(),
                    is_active_dialer: true, // we dialed (not yet accepting inbound)
                    is_trust_peer: false,
                    need_sync_from_peer: true,
                    need_sync_from_us: false,
                    last_interactive_ms: crate::node_statistics::unix_now_ms(),
                    block_recv_ms: 0,
                },
            );
        }
        // Subscribe to the eviction channel for this peer-pass. Each
        // PeerOutcome::PeerFailure exit path unregisters below.
        let mut eviction_rx = self.eviction_tx.as_ref().map(|tx| tx.subscribe());

        // Subscribe to the tx mempool's broadcast channel (if any).
        // Drained between dispatch ticks; see `drain_pending_txs` below.
        let mut tx_rx = self.mempool.as_ref().map(|m| m.subscribe());
        // Subscribe to the SR runtime's produced-blocks channel (if any).
        let mut produced_rx = self.produced_blocks_tx.as_ref().map(|tx| tx.subscribe());
        // Subscribe to the PBFT runtime's outbound vote channel (if any).
        let mut pbft_out_rx = self
            .pbft_channels
            .as_ref()
            .map(|c| c.outbound.subscribe());

        let mut prev_id = self.resume_head();
        // Track how many `Block` frames we still expect for the current
        // FetchInvData batch. When this hits zero, drain the next chunk
        // from `pending_fetch_queue` (if any), or — if the queue is
        // empty — issue a fresh `SyncBlockChain` against our new head
        // to get the next inventory window. The peer's response
        // naturally terminates the loop at head (ChainInventory of
        // size 1 → empty queue → no more SyncBlockChain). After that,
        // the peer's `AdvService.broadcast` filter starts including us
        // (since `needSyncFromUs` flipped to false in its
        // SyncBlockChainMsgHandler), so live blocks arrive as
        // `BlockInventory` advs and get fetched by the existing arm.
        let mut blocks_in_flight: usize = 0;
        // All block-id hashes from the most recent `ChainInventory`
        // that we haven't asked for yet. Peer's `SyncBlockChainMsgHandler`
        // sends up to `SYNC_FETCH_BATCH_NUM` (2000) ids per response;
        // we can only `FetchInvData` `MAX_BLOCK_FETCH_PER_PEER` (100)
        // at a time, so we queue the rest here and drain locally.
        // Draining locally instead of re-asking via `SyncBlockChain`
        // is critical: peer rate-limits `SYNC_BLOCK_CHAIN` to 3/s
        // (default `rate.limiter.p2p.syncBlockChain`), and sending
        // one per 100-block batch trips that gate within ~225 ms.
        let mut pending_fetch_queue: std::collections::VecDeque<Vec<u8>> =
            std::collections::VecDeque::new();
        // Per-peer single-slot block-fetch scheduler. Gates the
        // live-tip advertise path (Inventory(BLOCK) / BlockInventory):
        // we accept only ONE in-flight adv fetch at a time, only for
        // `head + 1`, with a budget-based slot release. Bulk-sync
        // (BlockChainInventory → batched FetchInvData) bypasses this
        // gate — that path already has its own pacing via
        // REQ_MIN_INTERVAL + FETCH_CHUNK_SIZE.
        let mut fetch_block_scheduler = crate::fetch_block::FetchBlockScheduler::new(
            self.config.fetch_block_timeout,
        );

        // Per-peer inbound P2P rate limiter — mirrors java-tron's
        // `PeerConnection.setChannel` registration of SYNC_BLOCK_CHAIN,
        // FETCH_INV_DATA, P2P_DISCONNECT rates. We check
        // `try_acquire` before processing each frame; unregistered
        // types pass through unlimited (the default).
        let p2p_rate_limiter = crate::p2p_rate_limiter::P2pRateLimiter::new();
        p2p_rate_limiter.register(
            MessageType::SyncBlockChain.as_byte(),
            self.config.p2p_rate_limits.sync_block_chain,
        );
        p2p_rate_limiter.register(
            MessageType::FetchInvData.as_byte(),
            self.config.p2p_rate_limits.fetch_inv_data,
        );
        p2p_rate_limiter.register(
            MessageType::P2pDisconnect.as_byte(),
            self.config.p2p_rate_limits.disconnect,
        );

        // Per-peer adv-receive cache: hashes this peer has advertised
        // to us (and that we may also have already fetched). Used to
        // avoid (a) re-fetching a hash they re-advertise, and (b)
        // advertising the same hash BACK to them when our mempool
        // fans it out. Mirrors java-tron's
        // `PeerConnection.advInvReceive`. Bounded to
        // `MAX_PEER_ADV_RECEIVE` with FIFO eviction so memory stays
        // capped even on long-lived peers.
        const MAX_PEER_ADV_RECEIVE: usize = 50_000;
        let mut peer_adv_receive: std::collections::HashSet<[u8; 32]> =
            std::collections::HashSet::new();
        let mut peer_adv_receive_order: std::collections::VecDeque<[u8; 32]> =
            std::collections::VecDeque::new();
        // Pending tx hashes to fetch from this peer (hashes they
        // advertised that we don't yet have in mempool). Drained into
        // `FetchInvData{type=TRX}` frames by the outbound section
        // below.
        let mut pending_tx_fetch_queue: std::collections::VecDeque<[u8; 32]> =
            std::collections::VecDeque::new();
        // Rate gating. The peer's `P2pRateLimiter` permits ~3 qps for
        // both `SYNC_BLOCK_CHAIN` and `FETCH_INV_DATA` (Guava
        // RateLimiter at rate=3.0). Sleep just over 1/3 s between
        // outbound requests of either type to stay under the cap.
        // Initial token is granted on the first call, so the very
        // first send doesn't wait.
        const REQ_MIN_INTERVAL: Duration = Duration::from_millis(400);
        let mut last_request_at: Option<Instant> = None;
        // Chain sync is kicked off from inside the loop, gated on
        // leadership: only the single active syncer sends the locator (a
        // java-tron-style geometric back-off of our recent block ids,
        // oldest first). That locator flips the peer's `needSyncFromUs =
        // true`, gating `AdvService.broadcast` — without it the peer never
        // pushes us BlockInventory adv frames. Its first id is a deep block
        // the peer is sure to have, so `containBlockInMainChain` passes and
        // the peer serves blocks after the highest id we share; the peer
        // replies with a `ChainInventory` of up to ~2000 hashes that the
        // queue + select! send branch drains. Standby drivers never send
        // it, so they never pull a redundant block stream.
        // `sync_started` flips once we've sent it as leader; if we later
        // lose leadership we reset it (and drop queued work) and go quiet.
        let mut sync_started = false;
        // Pipelining threshold: when in-flight blocks drop below this,
        // try to queue the next FetchInvData chunk so the peer is
        // continuously processing while we're draining the current
        // batch's blocks. Half a batch (50) is a sweet spot: leaves
        // enough processing headroom that we don't race the rate
        // limiter, but starts the next request well before the
        // current batch finishes.
        const PIPELINE_LOW_WATER: usize = 50;
        const FETCH_CHUNK_SIZE: usize = 100;

        // KeepAlive heartbeat. Mirrors java-tron's
        // `KeepAliveService` — every `KEEPALIVE_INTERVAL` we send the
        // peer a `Libp2pKeepAlivePing` carrying a fresh timestamp.
        // Peers reply with `Libp2pKeepAlivePong`; we record receipt to
        // `last_inbound_at` (any frame counts, not just Pong, since
        // active sync traffic is itself a sign of life). If
        // `last_inbound_at` is older than `KEEPALIVE_INBOUND_DEADLINE`
        // we drop the peer with PeerFailure — they're either stuck or
        // dead.
        const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);
        const KEEPALIVE_INBOUND_DEADLINE: Duration = Duration::from_secs(120);
        let mut last_ping_sent_at: Instant = Instant::now();
        let mut last_inbound_at: Instant = Instant::now();

        #[derive(Clone, Copy)]
        enum PendingAction {
            FetchChunk,
            AskInventory,
        }

        loop {
            if let Some(cap) = self.config.max_blocks {
                if self.stats.blocks_applied >= cap {
                    return PeerOutcome::CapReached;
                }
            }

            // Resilience-scheduler eviction: if our peer was named by
            // the resilience service, drop the connection. The
            // matching `record_local_disconnect` happens inside the
            // service before the broadcast.
            if let Some(rx) = eviction_rx.as_mut() {
                match rx.try_recv() {
                    Ok(target) if target == peer => {
                        return PeerOutcome::PeerFailure(format!(
                            "resilience: evicted by scheduler"
                        ));
                    }
                    Ok(_) | Err(tokio::sync::broadcast::error::TryRecvError::Empty) => {}
                    Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => {
                        // Don't care — peer eviction is idempotent.
                    }
                    Err(tokio::sync::broadcast::error::TryRecvError::Closed) => {
                        eviction_rx = None;
                    }
                }
            }

            // KeepAlive: enforce inbound-deadline + send periodic Pings.
            if last_inbound_at.elapsed() > KEEPALIVE_INBOUND_DEADLINE {
                return PeerOutcome::PeerFailure(format!(
                    "peer silent for {}s — keepalive timeout",
                    last_inbound_at.elapsed().as_secs()
                ));
            }
            if last_ping_sent_at.elapsed() >= KEEPALIVE_INTERVAL {
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as i64)
                    .unwrap_or(0);
                let ping = tron_proto::libp2p::KeepAliveMessage { timestamp: now_ms };
                if let Err(e) = conn
                    .send_frame(Frame {
                        ty: MessageType::Libp2pKeepAlivePing,
                        payload: Bytes::from(ping.encode_to_vec()),
                    })
                    .await
                {
                    return PeerOutcome::PeerFailure(format!("send keepalive ping: {e}"));
                }
                last_ping_sent_at = Instant::now();
            }

            // Best-effort broadcast: drain mempool before reading the
            // next frame so newly-submitted txs leave the local node
            // promptly. Now uses java-tron's pull-based advertise path:
            // we send `Inventory{type=TRX, ids=[...]}` and the peer
            // requests bodies via `FetchInvData` if it wants them.
            // Hashes the peer already advertised to us are skipped to
            // avoid an echo loop.
            if let (Some(rx), Some(mempool)) = (tx_rx.as_mut(), self.mempool.as_ref()) {
                if let Err(reason) = drain_pending_tx_inventory(
                    &mut conn,
                    rx,
                    mempool.as_ref(),
                    &peer_adv_receive,
                )
                .await
                {
                    return PeerOutcome::PeerFailure(format!("broadcast tx adv: {reason}"));
                }
            }

            // Drain queued tx hashes the peer told us about into one
            // `FetchInvData{type=TRX}` frame. Bounded per drain by
            // `MAX_TX_FETCH_PER_BATCH` so a chatty peer can't pin a
            // huge single frame; remainder stays in the queue for the
            // next pass. Matches java-tron's
            // `MAX_TRX_FETCH_PER_PEER` cap (1000).
            if !pending_tx_fetch_queue.is_empty() {
                if let Err(reason) =
                    drain_tx_fetch_requests(&mut conn, &mut pending_tx_fetch_queue).await
                {
                    return PeerOutcome::PeerFailure(format!(
                        "send FetchInvData(TRX): {reason}"
                    ));
                }
            }

            // Same pattern for produced blocks from the local SR
            // runtime. Each notice carries pre-encoded bytes ready to
            // stuff into a `MessageType::Block` frame.
            if let Some(rx) = produced_rx.as_mut() {
                if let Err(reason) =
                    drain_produced_blocks(&mut conn, rx, self.config.peer_is_fast_forward).await
                {
                    return PeerOutcome::PeerFailure(format!(
                        "broadcast produced block: {reason}"
                    ));
                }
            }

            // Same again for PBFT vote casts. Each msg is encoded as
            // a `MessageType::PbftMsg` frame.
            if let Some(rx) = pbft_out_rx.as_mut() {
                if let Err(reason) = drain_pbft_outbound(&mut conn, rx).await {
                    return PeerOutcome::PeerFailure(format!(
                        "broadcast pbft msg: {reason}"
                    ));
                }
            }

            // Single active syncer. Only the leader requests + applies
            // blocks; standbys stay connected (keepalive above, inbound
            // sync served in the dispatch loop) and take over only if the
            // leader stalls. `is_active_syncer` claims/retains the shared
            // leadership slot — but only an eligible (not dramatically
            // behind) peer may take it, so a fresh node can't win the slot
            // and stall us.
            let am_leader = self.is_active_syncer(peer, leader_eligible);
            if am_leader && !sync_started {
                // We're the active syncer and haven't kicked off yet —
                // send the locator to start the block stream.
                let mut summary = self.build_chain_summary();
                if summary.is_empty() {
                    // Fresh node / no index — genesis is in every peer's
                    // main chain.
                    summary.push(prev_id.unwrap_or(genesis));
                }
                debug!(
                    peer,
                    len = summary.len(),
                    first_num = summary.first().map(|id| id.num()).unwrap_or(0),
                    last_num = summary.last().map(|id| id.num()).unwrap_or(0),
                    "sent SyncBlockChain locator (active syncer)"
                );
                last_request_at = Some(Instant::now());
                if let Err(e) =
                    tron_net::sync::send_sync_request(&mut conn, &summary).await
                {
                    return PeerOutcome::PeerFailure(format!("send_sync_request: {e}"));
                }
                sync_started = true;
            } else if !am_leader && sync_started {
                // We led, then a peer took the slot (we stalled ≥
                // LEADERSHIP_STALE). Stop driving sync and drop queued work
                // so we don't apply against a head the new leader is now
                // advancing; we'll re-kick if we reclaim leadership.
                debug!(peer, "yielded active-syncer role; going standby");
                sync_started = false;
                pending_fetch_queue.clear();
                blocks_in_flight = 0;
            }

            // Determine if there's outbound work waiting (queued
            // fetches to issue, or queue-empty-need-inventory). Compute
            // the earliest time we're rate-allowed to issue it. Used
            // by the `select!` below to race the request timer against
            // the next inbound frame — this is what enables pipelining.
            // Standby drivers issue nothing.
            let pending: Option<PendingAction> = if !am_leader {
                None
            } else if !pending_fetch_queue.is_empty()
                && blocks_in_flight < PIPELINE_LOW_WATER
            {
                Some(PendingAction::FetchChunk)
            } else if pending_fetch_queue.is_empty()
                && blocks_in_flight == 0
                && prev_id.is_some()
            {
                Some(PendingAction::AskInventory)
            } else {
                None
            };
            let action_deadline: Option<tokio::time::Instant> = pending.map(|_| {
                match last_request_at {
                    Some(t) => tokio::time::Instant::from_std(t + REQ_MIN_INTERVAL),
                    None => tokio::time::Instant::now(),
                }
            });

            let read = tokio::select! {
                biased;
                // Send branch: fires when (a) there's work to send and
                // (b) the per-message rate-limit window has elapsed.
                // Gate the branch's inclusion on `pending.is_some()` so
                // the `unwrap`s below are sound — tokio::select! only
                // polls a branch when its `if` guard is true.
                _ = tokio::time::sleep_until(action_deadline.unwrap_or_else(tokio::time::Instant::now)),
                    if pending.is_some() =>
                {
                    last_request_at = Some(Instant::now());
                    match pending.unwrap() {
                        PendingAction::FetchChunk => {
                            let take = pending_fetch_queue.len().min(FETCH_CHUNK_SIZE);
                            let to_fetch: Vec<Vec<u8>> =
                                pending_fetch_queue.drain(..take).collect();
                            blocks_in_flight += to_fetch.len();
                            if let Err(e) = tron_net::sync::send_fetch_inv_data(
                                &mut conn,
                                &to_fetch,
                            )
                            .await
                            {
                                return PeerOutcome::PeerFailure(format!(
                                    "send_fetch_inv_data (pipeline): {e}"
                                ));
                            }
                        }
                        PendingAction::AskInventory => {
                            // safe: pending is `AskInventory` only when prev_id is Some.
                            let id = prev_id.expect("AskInventory requires prev_id");
                            if let Err(e) =
                                tron_net::sync::send_sync_request(&mut conn, &[id]).await
                            {
                                return PeerOutcome::PeerFailure(format!(
                                    "send_sync_request (continue): {e}"
                                ));
                            }
                        }
                    }
                    // Loop around to re-evaluate `pending` (we may need
                    // to queue another request immediately, e.g. when
                    // a fresh ChainInventory just landed).
                    continue;
                }
                // Standby wakeup: a non-leader otherwise blocks on the
                // 60s frame read, which is too slow to notice the leader
                // stalling. Tick every 5s so it re-checks leadership and
                // can take over promptly. Leaders skip this (their loop is
                // already driven by the constant block stream).
                _ = tokio::time::sleep(Duration::from_secs(5)), if !am_leader => {
                    continue;
                }
                // Read branch: wait up to 60s for the next frame. The
                // timeout lets us periodically wake up to re-check the
                // cap and drain the mempool even on a silent peer.
                r = tokio::time::timeout(Duration::from_secs(60), conn.next_frame()) => r,
            };
            let frame = match read {
                Ok(Ok(Some(f))) => f,
                Ok(Ok(None)) => {
                    return PeerOutcome::PeerFailure(
                        "peer closed connection".to_string(),
                    )
                }
                Ok(Err(e)) => {
                    return PeerOutcome::PeerFailure(format!("frame: {e}"))
                }
                Err(_) => {
                    debug!("60s idle waiting for peer frame; loop continues");
                    continue;
                }
            };
            // Any frame counts as "peer alive" — refresh the keepalive
            // deadline. The dedicated Pong handler still needs to
            // exist so we don't disconnect noisy peers as "unhandled
            // frame type", but for liveness the frame-arrival itself
            // is the signal.
            last_inbound_at = Instant::now();

            // Mirror the bump on the shared NodeStatisticsTable + the
            // live peer registry so the resilience scheduler sees this
            // peer as recently-interactive.
            let now_ms = crate::node_statistics::unix_now_ms();
            if let Some(stats) = &self.node_statistics {
                stats.touch(peer).await;
            }
            if let Some(reg) = &self.peer_registry {
                reg.touch(peer, |s| s.last_interactive_ms = now_ms);
            }

            // Per-frame-type rate limit. Registered types
            // (SYNC_BLOCK_CHAIN, FETCH_INV_DATA, P2P_DISCONNECT) gate
            // through a token bucket; on bucket-empty the frame is
            // dropped silently (matches java-tron's
            // `P2pEventHandlerImpl` policy). Unregistered types
            // pass through unlimited.
            if !p2p_rate_limiter.try_acquire(frame.ty.as_byte()) {
                debug!(ty = ?frame.ty, "P2P rate limit: dropping frame");
                if let Some(m) = &self.metrics {
                    m.inc_p2p_rate_limited();
                }
                continue;
            }

            // M-22b: trace every inbound frame so the exact post-handshake
            // exchange with a peer that then rejects us is visible (run with
            // `RUST_LOG=tron_node::sync=debug`). Pairs with the outbound
            // "sent SyncBlockChain locator" / fetch logs.
            debug!(peer, frame = ?frame.ty, len = frame.payload.len(), "rx frame");

            match frame.ty {
                MessageType::Inventory => {
                    // Adv broadcast from peer: java-tron's `AdvService`
                    // wraps new blocks (and pending txs) in
                    // `InventoryMessage` (proto `Inventory`,
                    // wire type 0x06). This is the actual live-tip
                    // notification path — when peer learns of a new
                    // block and we're in its adv-eligible bucket
                    // (`!needSyncFromPeer && !needSyncFromUs`), it
                    // sends us an `Inventory{type=BLOCK, ids=[hash]}`.
                    // The `Inventory` proto is shaped differently from
                    // `BlockInventory`: `ids` is a flat
                    // `Vec<Vec<u8>>` (raw 32-byte hashes), not the
                    // `{hash, number}` pair list used by sync.
                    let inv =
                        match tron_proto::Inventory::decode(frame.payload) {
                            Ok(i) => i,
                            Err(e) => {
                                warn!(error = %e, "decode Inventory");
                                continue;
                            }
                        };
                    let is_block = inv.r#type
                        == tron_proto::inventory::InventoryType::Block as i32;
                    debug!(
                        ids = inv.ids.len(),
                        ty = inv.r#type,
                        is_block,
                        "Inventory (adv) received"
                    );
                    if is_block {
                        // Live-tip adv path: gate every hash through
                        // FetchBlockScheduler (single-slot, head+1
                        // only). Bulk-sync goes through the
                        // BlockChainInventory branch below — that path
                        // bypasses the scheduler intentionally.
                        let head = self.head_number();
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis() as u64)
                            .unwrap_or(0);
                        for hash in inv.ids {
                            if hash.len() != 32 {
                                continue;
                            }
                            let mut raw = [0u8; 32];
                            raw.copy_from_slice(&hash);
                            let id = BlockId::from_raw(raw);
                            let block_num = id.num() as i64;
                            match fetch_block_scheduler.try_fetch(
                                block_num,
                                raw,
                                peer,
                                head,
                                now_ms,
                            ) {
                                crate::fetch_block::FetchDecision::Dispatch => {
                                    pending_fetch_queue.push_back(hash);
                                }
                                crate::fetch_block::FetchDecision::Defer
                                | crate::fetch_block::FetchDecision::NotNextBlock => {
                                    debug!(
                                        block_num,
                                        head,
                                        "fetch_block_scheduler dropped adv hash"
                                    );
                                }
                            }
                        }
                    } else {
                        // Tx inventory (type=TRX). See
                        // `process_tx_inventory_advertise`.
                        process_tx_inventory_advertise(
                            &inv.ids,
                            self.mempool.as_deref(),
                            &mut peer_adv_receive,
                            &mut peer_adv_receive_order,
                            &mut pending_tx_fetch_queue,
                            MAX_PEER_ADV_RECEIVE,
                        );
                    }
                }
                MessageType::BlockInventory => {
                    // Legacy / defensive path. Current mainnet
                    // java-tron does not emit type 0x12 directly —
                    // `SyncBlockChainMessage` (0x08) inherits from
                    // `BlockInventoryMessage` but always overrides the
                    // wire type. Kept as a no-op-style queue push in
                    // case a forked peer emits the bare form.
                    let raw = frame.payload.clone();
                    let inv =
                        match tron_proto::BlockInventory::decode(frame.payload) {
                            Ok(i) => i,
                            Err(e) => {
                                let hex_preview = hex::encode(
                                    &raw[..raw.len().min(64)],
                                );
                                warn!(
                                    error = %e,
                                    len = raw.len(),
                                    hex_head = %hex_preview,
                                    "decode BlockInventory"
                                );
                                continue;
                            }
                        };
                    debug!(
                        ids = inv.ids.len(),
                        ty = inv.r#type,
                        "BlockInventory; queueing (legacy path)"
                    );
                    // Same single-slot gate as Inventory(BLOCK) above.
                    // BlockInventory carries `BlockId{hash, num}` pairs
                    // directly so we don't need to decode the num from
                    // the hash prefix; use the explicit field.
                    let head = self.head_number();
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0);
                    for b in inv.ids.iter() {
                        if b.hash.len() != 32 {
                            continue;
                        }
                        let mut raw = [0u8; 32];
                        raw.copy_from_slice(&b.hash);
                        match fetch_block_scheduler.try_fetch(
                            b.number,
                            raw,
                            peer,
                            head,
                            now_ms,
                        ) {
                            crate::fetch_block::FetchDecision::Dispatch => {
                                pending_fetch_queue.push_back(b.hash.clone());
                            }
                            crate::fetch_block::FetchDecision::Defer
                            | crate::fetch_block::FetchDecision::NotNextBlock => {
                                debug!(
                                    block_num = b.number,
                                    head,
                                    "fetch_block_scheduler dropped legacy adv hash"
                                );
                            }
                        }
                    }
                }
                MessageType::BlockChainInventory => {
                    // Peer's response to our `SyncBlockChain`. Carries
                    // up to `SYNC_FETCH_BATCH_NUM` (2000) block ids
                    // starting at the unfork point (first id is our
                    // last-shared block; skip it). Queue the rest; the
                    // select! send branch drains them in 100-id chunks
                    // per the peer's MAX_BLOCK_FETCH_PER_PEER cap.
                    let chain_inv =
                        match tron_proto::ChainInventory::decode(frame.payload) {
                            Ok(c) => c,
                            Err(e) => {
                                warn!(error = %e, "decode ChainInventory");
                                continue;
                            }
                        };
                    for b in chain_inv.ids.iter().skip(1) {
                        pending_fetch_queue.push_back(b.hash.clone());
                    }
                    let appended = pending_fetch_queue.len();
                    debug!(
                        queued = appended,
                        remain = chain_inv.remain_num,
                        "ChainInventory queued"
                    );
                    // An empty inventory + `remain_num=0` means the peer
                    // says "you're caught up" — there are no blocks after
                    // our common ancestor. New tip blocks arrive via
                    // Inventory adverts, NOT this loop, so throttle before
                    // the outer loop's AskInventory branch re-fires;
                    // otherwise it spins at `REQ_MIN_INTERVAL` (~0.4s) and
                    // hammers the peer with empty round-trips. (Previously
                    // gated on `tip_test`, but the spin happens in normal
                    // sync too — every caught-up peer and every dead-end
                    // peer we briefly lead from.)
                    if appended == 0 && chain_inv.remain_num == 0 {
                        tokio::time::sleep(self.config.tail_interval).await;
                    }
                }
                MessageType::Block => {
                    // Retain the raw wire bytes before prost consumes them on
                    // decode — `accept_block` validates `txTrieRoot` against
                    // these original bytes (M-20). `Bytes::clone` is a cheap
                    // refcount bump.
                    let raw_block_bytes = frame.payload.clone();
                    let block = match Block::decode(frame.payload) {
                        Ok(b) => b,
                        Err(e) => {
                            warn!(error = %e, "decode Block");
                            continue;
                        }
                    };
                    let block_num = block
                        .block_header
                        .as_ref()
                        .and_then(|h| h.raw_data.as_ref())
                        .map(|r| r.number)
                        .unwrap_or(-1);
                    let tx_count = block.transactions.len();
                    // Release the live-tip single-slot scheduler if the
                    // arriving block matches the in-flight adv fetch.
                    // Bulk-sync arrivals (which don't go through the
                    // scheduler) leave the slot alone via the matching
                    // hash check inside `complete_if_matches`.
                    if let Ok(id) = block_id_from_block(&block) {
                        fetch_block_scheduler.complete_if_matches(id.as_bytes());
                    }
                    // Tip-test mode short-circuit: just count + log.
                    // No validation, no execution, no fork tree, no
                    // store write. The point is to measure whether
                    // peers actually serve us recent-tip blocks at
                    // all, not whether we can apply them.
                    //
                    // We DO advance `prev_id` to the highest received
                    // block so the outer loop's `AskInventory` branch
                    // fires when the fetch queue drains — that's what
                    // keeps the peer streaming us more inventory
                    // instead of dropping us as "client done" after
                    // the first 100-block batch.
                    if self.config.tip_test {
                        self.stats.blocks_applied += 1;
                        if let Some(m) = &self.metrics {
                            m.inc_blocks_applied();
                        }
                        blocks_in_flight = blocks_in_flight.saturating_sub(1);
                        if let Ok(id) = block_id_from_block(&block) {
                            prev_id = Some(id);
                        }
                        if self.config.progress_log_interval > 0
                            && self.stats.blocks_applied
                                % self.config.progress_log_interval
                                == 0
                        {
                            info!(
                                tip_test = true,
                                peer = peer,
                                block = block_num,
                                txs = tx_count,
                                received = self.stats.blocks_applied,
                                "tip-test block received"
                            );
                        }
                        continue;
                    }
                    // Standby drivers don't apply blocks — the active
                    // syncer owns the head. We shouldn't receive any
                    // (we never requested), but drop defensively so a
                    // late-arriving or broadcast block can't race the
                    // shared head and spawn spurious unlinked/parent
                    // rejections.
                    if !am_leader {
                        blocks_in_flight = blocks_in_flight.saturating_sub(1);
                        debug!(
                            peer,
                            block = block_num,
                            "standby; dropping block (active syncer owns the head)"
                        );
                        continue;
                    }
                    self.pending_raw_block = Some(raw_block_bytes);
                    match self.accept_block(&block, prev_id) {
                        AcceptOutcome::Accepted(id) => {
                            prev_id = Some(id);
                            // Reset the leadership staleness timer — we're
                            // making progress, so no standby should preempt.
                            self.note_sync_progress(peer);
                            // Human-readable, time-throttled progress line
                            // (height + block wall-clock + lag + rate + peer).
                            self.log_sync_progress(&block, block_num, peer);
                        }
                        AcceptOutcome::RejectedValidation(reason) => {
                            self.stats.blocks_rejected_validation += 1;
                            if let Some(m) = &self.metrics {
                                m.inc_blocks_rejected_validation();
                            }
                            warn!(
                                block = block_num,
                                reason = reason.as_str(),
                                "block rejected: validation"
                            );
                        }
                        AcceptOutcome::RejectedExecution(reason) => {
                            self.stats.blocks_rejected_execution += 1;
                            if let Some(m) = &self.metrics {
                                m.inc_blocks_rejected_execution();
                            }
                            warn!(
                                block = block_num,
                                reason = reason.as_str(),
                                "block rejected: execution"
                            );
                        }
                        AcceptOutcome::AlreadyKnown(_id) => {
                            // Peer re-sent inventory we already
                            // applied. Common and not interesting —
                            // log at debug.
                            debug!(block = block_num, "block already in fork tree, skipped");
                            if let Some(m) = &self.metrics {
                                m.inc_blocks_already_known();
                            }
                        }
                        AcceptOutcome::SideFork(id) => {
                            // Recorded in the fork tree but not
                            // applied — log at info so the operator
                            // sees fork activity without it being a
                            // warning.
                            info!(
                                block = block_num,
                                hash = %hex::encode(&id.as_bytes()[..8]),
                                "block on side fork; fork tree updated, state unchanged"
                            );
                            if let Some(m) = &self.metrics {
                                m.inc_blocks_side_fork();
                            }
                        }
                        AcceptOutcome::ReorgRequired(id, new_head_num) => {
                            // Sibling fork overtook us — true reorg
                            // needed but Phase B (state rollback) is
                            // not yet wired. Warn loudly so the
                            // operator knows the head is now divergent
                            // from the canonical chain.
                            warn!(
                                block = block_num,
                                hash = %hex::encode(&id.as_bytes()[..8]),
                                new_head_num,
                                "REORG REQUIRED: sibling fork overtook canonical head; \
                                 state rollback not yet implemented, head is stale"
                            );
                            if let Some(m) = &self.metrics {
                                m.inc_reorgs_required();
                            }
                        }
                        AcceptOutcome::RejectedSolidifiedDiverged(id) => {
                            // KhaosDb wanted to promote this fork's
                            // head but it doesn't contain the latest
                            // solidified block — finality gate caught
                            // it. Warn so the operator notices a peer
                            // serving a divergent history.
                            warn!(
                                block = block_num,
                                hash = %hex::encode(&id.as_bytes()[..8]),
                                "rejected head promotion: fork diverges from solidified"
                            );
                            if let Some(m) = &self.metrics {
                                m.inc_blocks_rejected_solidified_diverged();
                            }
                        }
                    }
                    // Count *every* Block frame received (including
                    // rejected ones), not just accepted ones — a peer
                    // that sent us a bad block still consumed one of
                    // our in-flight slots, and if we only counted
                    // accepted ones we'd stall whenever validation
                    // rejected anything. The select! send branch
                    // re-evaluates `pending` on the next loop turn and
                    // issues the next request when the rate window
                    // re-opens (or immediately if we've crossed the
                    // pipeline low-water mark).
                    blocks_in_flight = blocks_in_flight.saturating_sub(1);
                }
                MessageType::P2pPing => {
                    // java-tron's app-level Ping/Pong payload is the
                    // single byte 0xC0 (RLP empty list). An empty
                    // payload triggers BAD_MESSAGE from the parser.
                    let _ = conn
                        .send_frame(Frame {
                            ty: MessageType::P2pPong,
                            payload: Bytes::from_static(&[0xC0]),
                        })
                        .await;
                }
                MessageType::Libp2pKeepAlivePing => {
                    // libp2p KeepAlivePong carries a `KeepAliveMessage`
                    // proto with a fresh timestamp. The peer's
                    // `PongMessage.valid()` requires `ts > 0` AND
                    // `ts <= now + NETWORK_TIME_DIFF` — an empty
                    // payload parses as ts=0 and fails with BAD_MESSAGE
                    // (libp2p disconnect reason 11).
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis() as i64)
                        .unwrap_or(0);
                    let pong = tron_proto::libp2p::KeepAliveMessage { timestamp: now_ms };
                    let _ = conn
                        .send_frame(Frame {
                            ty: MessageType::Libp2pKeepAlivePong,
                            payload: Bytes::from(pong.encode_to_vec()),
                        })
                        .await;
                }
                MessageType::Libp2pKeepAlivePong => {
                    // Reply to our outbound Ping. The deadline refresh
                    // already happened on frame arrival; no further
                    // work needed. Logged at trace to keep noise low.
                    tracing::trace!("keepalive pong from peer");
                }
                MessageType::Libp2pDisconnect => {
                    // Decode the reason byte AND its enum name so the log is
                    // human-readable, not a bare number. This is the libp2p
                    // connection-layer enum (`DisconnectReasonCode`), distinct
                    // from the app-layer `ReasonCode` used by P2pDisconnect.
                    let reason = tron_proto::libp2p::P2pDisconnectMessage::decode(
                        frame.payload,
                    )
                    .map(|d| d.reason)
                    .unwrap_or(-1);
                    let name = tron_proto::libp2p::DisconnectReasonCode::try_from(reason)
                        .map(|r| r.as_str_name())
                        .unwrap_or("UNKNOWN");
                    return PeerOutcome::PeerFailure(format!(
                        "peer libp2p-disconnected with reason code {reason} ({name})"
                    ));
                }
                MessageType::P2pDisconnect => {
                    // App-layer `ReasonCode` (e.g. 4 = TOO_MANY_PEERS — the
                    // peer is at capacity, not a fault on our side).
                    let reason = tron_proto::DisconnectMessage::decode(frame.payload)
                        .map(|d| d.reason)
                        .unwrap_or(-1);
                    let name = tron_proto::ReasonCode::try_from(reason)
                        .map(|r| r.as_str_name())
                        .unwrap_or("UNKNOWN");
                    return PeerOutcome::PeerFailure(format!(
                        "peer app-disconnected with reason code {reason} ({name})"
                    ));
                }
                MessageType::Trx => {
                    // Single-tx broadcast: payload IS the wire-encoded
                    // `Transaction`. Submit raw bytes to the mempool —
                    // it handles decode, signer recovery, expiration,
                    // dedup, and capacity. On accept, the mempool's
                    // broadcast channel will fan the tx back out to
                    // other peers via `drain_pending_txs`.
                    if let Some(mp) = &self.mempool {
                        let outcome = mp.submit(&frame.payload);
                        log_inbound_tx_outcome(&outcome);
                    }
                }
                MessageType::Trxs => {
                    // Batch broadcast: payload is `Transactions {
                    // transactions: repeated Transaction }`. Decode,
                    // re-encode each, submit each.
                    use prost::Message as _;
                    if let Some(mp) = &self.mempool {
                        match tron_proto::Transactions::decode(frame.payload.as_ref()) {
                            Ok(batch) => {
                                for tx in batch.transactions {
                                    let raw = tx.encode_to_vec();
                                    let outcome = mp.submit(&raw);
                                    log_inbound_tx_outcome(&outcome);
                                }
                            }
                            Err(e) => {
                                debug!(?e, "malformed Trxs frame; ignoring");
                            }
                        }
                    }
                }
                MessageType::TrxInventory => {
                    // 0x13 — defined in java-tron's `MessageTypes` but
                    // not used on the wire for normal tx propagation.
                    // Tx advertisements ride 0x06 `Inventory` with
                    // type=TRX (handled above). Silently ignore so a
                    // peer running an alternative path doesn't trip
                    // the unhandled-frame disconnect.
                    debug!("ignoring TrxInventory (0x13) frame; tx adv rides 0x06");
                }
                MessageType::FetchInvData => {
                    // Peer is asking us to send back the bodies for
                    // these hashes (either blocks or txs). TRX requests
                    // route through the mempool; BLOCK requests route
                    // through the BlockStore. Misses on either get
                    // gathered into one `ItemNotFound`.
                    if let Err(reason) = serve_tx_fetch_inv_data(
                        &mut conn,
                        frame.payload,
                        self.mempool.as_deref(),
                        Some(&self.blocks_backend),
                    )
                    .await
                    {
                        return PeerOutcome::PeerFailure(reason);
                    }
                }
                MessageType::ItemNotFound => {
                    warn!(
                        "peer reported ItemNotFound for our FetchInvData request"
                    );
                }
                MessageType::PbftMsg => {
                    // Decode + forward into the PbftRuntime if we
                    // have one. Errors are non-fatal — drop the msg
                    // and continue.
                    use prost::Message as _;
                    if let Some(channels) = &self.pbft_channels {
                        match tron_proto::PbftMessage::decode(frame.payload.as_ref()) {
                            Ok(msg) => {
                                // best-effort — channel may have no
                                // subscribers if the runtime exited.
                                let _ = channels.inbound.send(msg);
                            }
                            Err(e) => {
                                debug!(error = %e, "PBFT msg decode failed");
                            }
                        }
                    }
                }
                MessageType::SyncBlockChain => {
                    // A peer wants to sync FROM us: it sent its chain locator
                    // and expects a `BlockChainInventory` of the ids we hold
                    // past the highest block we share. Without this reply the
                    // peer waits a few hundred ms, gets nothing, and drops us
                    // with BAD_PROTOCOL (reason 2) — java-tron's
                    // SyncBlockChainMsgHandler is mandatory, not optional, and
                    // its absence was why public peers rejected us while our
                    // own node (whose head matched ours) tolerated it. (M-22b)
                    let inv = match tron_proto::BlockInventory::decode(frame.payload)
                    {
                        Ok(i) => i,
                        Err(e) => {
                            debug!(peer, error = %e, "decode inbound SyncBlockChain");
                            continue;
                        }
                    };
                    let (ids, remain) = self.serve_sync_block_chain(&inv.ids);
                    let reply =
                        tron_net::sync::chain_inventory_from_ids(&ids, remain);
                    if let Err(e) =
                        tron_net::sync::send_chain_inventory(&mut conn, &reply).await
                    {
                        return PeerOutcome::PeerFailure(format!(
                            "send_chain_inventory: {e}"
                        ));
                    }
                    debug!(
                        peer,
                        served = ids.len(),
                        remain,
                        locator = inv.ids.len(),
                        "served SyncBlockChain"
                    );
                }
                other => {
                    debug!(ty = ?other, "unhandled frame in dispatch loop");
                }
            }
        }
    }

    /// Expose the node_id this driver advertises. Stable for the
    /// driver's lifetime; differs across processes.
    pub fn node_id(&self) -> &[u8] {
        &self.node_id
    }

    /// Read the current head from `DynamicPropertiesStore`. Returns
    /// `None` on a fresh node (no head pointer yet).
    pub fn resume_head(&self) -> Option<BlockId> {
        let dp = DynamicPropertiesStore::new(self.state.dyn_props.clone());
        let hash = dp.latest_block_header_hash().ok().flatten()?;
        Some(BlockId::from_raw(hash))
    }

    pub fn head_number(&self) -> i64 {
        let dp = DynamicPropertiesStore::new(self.state.dyn_props.clone());
        dp.latest_block_header_number().unwrap_or(0)
    }

    /// The id of our latest solidified block, for the P2P Hello `solid`
    /// field. `None` on a fresh node (no solid pointer yet, or its index
    /// entry is missing) so the caller can fall back to head.
    ///
    /// Advertising `solid = head` (the old default) is a protocol lie:
    /// under DPoS the solidified block always lags head by the
    /// finalization gap, so a peer that validates `solid <= head -` gap
    /// could treat an equal-to-head solid as malformed.
    fn solid_block_id(&self) -> Option<BlockId> {
        let dp = DynamicPropertiesStore::new(self.state.dyn_props.clone());
        let num = dp.latest_solidified_block_num()?;
        let bi = self.state.block_index.as_ref()?;
        BlockIndexStore::new(bi.clone()).get(num).ok()
    }

    /// Our lowest-held block number, for the P2P Hello `lowest_block_num`
    /// field. Falls back to 0 when we can't size the index. A
    /// snapshot-synced node holds blocks only from its base forward, so
    /// advertising 0 (archive-from-genesis) misleads peers about what we
    /// can actually serve.
    fn lowest_block_num(&self) -> i64 {
        self.state
            .block_index
            .as_ref()
            .and_then(|bi| BlockIndexStore::new(bi.clone()).lowest().ok().flatten())
            .unwrap_or(0)
    }

    /// Build the `SyncBlockChain` locator — a direct port of java-tron's
    /// `SyncService.getBlockChainSummary`.
    ///
    /// Anchor at our **lowest** stored block (java-tron's `syncBeginNumber`)
    /// and walk **up** to head, halving the remaining gap each step
    /// (`low += (high - low + 2) / 2`). The result is ascending, dense near
    /// head, and — critically — `ids[0]` is the *deepest* block we hold.
    ///
    /// Why the deepest-anchor matters: java-tron's `SyncBlockChainMsgHandler`
    /// `check()` validates `containBlockInMainChain(blockIds.get(0))` and
    /// disconnects with `BAD_PROTOCOL` if that first/deepest id isn't on the
    /// peer's main chain; it then serves blocks after the *highest* summary id
    /// it shares. The old version anchored at an arbitrary `head − 2^k` point
    /// (wherever the doubling back-off bottomed out), which stricter peers
    /// refused. Matching java-tron — anchor at our true lowest block — makes
    /// `ids[0]` the block most certain to be in any peer's main chain.
    ///
    /// The halving cadence keeps the id count ~log2(head − lowest) regardless
    /// of range, so no explicit frame cap is needed.
    ///
    /// Returns empty when there's no usable index (fresh node) — the caller
    /// falls back to the genesis/head id.
    fn build_chain_summary(&self) -> Vec<BlockId> {
        let head_num = self.head_number();
        let Some(bi) = &self.state.block_index else {
            return Vec::new();
        };
        let block_index = BlockIndexStore::new(bi.clone());

        // `low` = our sync-begin point (lowest stored block). Bail if we can't
        // size it or it's somehow past head.
        let low = match block_index.lowest() {
            Ok(Some(n)) if n <= head_num => n,
            _ => return Vec::new(),
        };

        let mut ids: Vec<BlockId> = Vec::new();
        let mut n = low;
        while n <= head_num {
            if let Ok(id) = block_index.get(n) {
                ids.push(id);
            }
            // Halve the remaining gap to head; the `+2` keeps the step ≥ 1
            // (no infinite loop) and lands exactly on head as the final id.
            n += (head_num - n + 2) / 2;
        }
        ids
    }

    /// Build the `BlockChainInventory` reply for a peer that sent us a
    /// `SyncBlockChain` locator (it wants to catch up FROM us).
    ///
    /// Finds the highest block in the peer's locator that sits on our main
    /// chain — the common ancestor — and returns our block ids from there
    /// onward (the shared block first, so the peer can verify the link),
    /// capped at `SYNC_FETCH_BATCH_NUM`, plus how many more blocks we hold
    /// beyond the batch (`remain_num`).
    ///
    /// Returns `(empty, 0)` when we have no index or share no block with the
    /// peer — still a valid "nothing for you" reply, which is what keeps the
    /// peer from timing out and dropping us with BAD_PROTOCOL. (M-22b)
    fn serve_sync_block_chain(
        &self,
        locator: &[tron_proto::block_inventory::BlockId],
    ) -> (Vec<BlockId>, i64) {
        let our_head = self.head_number();
        let Some(bi) = &self.state.block_index else {
            return (Vec::new(), 0);
        };
        let block_index = BlockIndexStore::new(bi.clone());

        // The locator is dense near the peer's head and sparse below; keep the
        // highest entry whose id matches our main-chain block at that number.
        let mut common: Option<i64> = None;
        for entry in locator {
            if entry.hash.len() != 32 {
                continue;
            }
            let mut raw = [0u8; 32];
            raw.copy_from_slice(&entry.hash);
            let their_id = BlockId::from_raw(raw);
            if block_index
                .get(entry.number)
                .map(|ours| ours == their_id)
                .unwrap_or(false)
            {
                common = Some(common.map_or(entry.number, |c| c.max(entry.number)));
            }
        }
        let Some(start) = common else {
            return (Vec::new(), 0);
        };

        const SYNC_FETCH_BATCH_NUM: i64 = 2000;
        let end = (start + SYNC_FETCH_BATCH_NUM).min(our_head);
        let mut ids = Vec::new();
        for num in start..=end {
            match block_index.get(num) {
                Ok(id) => ids.push(id),
                Err(_) => break,
            }
        }
        (ids, (our_head - end).max(0))
    }

    /// Validate + persist + execute a single block. Returns the
    /// granular outcome so the driver can keep separate counters for
    /// validation rejection vs execution rejection.
    ///
    /// **KhaosDb integration**: every block also goes through the
    /// in-memory fork tree before executing. This gives us:
    ///   * **Dedup**: blocks already in the linked store are
    ///     short-circuited as `AlreadyKnown` — no re-execution, no
    ///     storage churn.
    ///   * **Orphan buffering**: blocks whose parent isn't yet in the
    ///     fork tree get stashed in the unlinked store and reported as
    ///     `RejectedValidation("unlinked")`. The caller can re-push
    ///     them once the gap fills (sync driver does this implicitly
    ///     when the parent later arrives).
    ///   * **Fork detection**: a block that lands on a sibling chain
    ///     (same parent as our head, different witness) is recorded
    ///     in the fork tree without disturbing the executed head. If
    ///     the sibling chain later grows past our head's number, the
    ///     `kReorgRequired` outcome flags it for the (Phase B) reorg
    ///     handler. **Today** Phase B is not wired — we log it and
    ///     keep applying on the original head, matching the v1
    ///     behavior. The KhaosDb correctly tracks the divergence so
    ///     the SR runtime and a future reorg implementation can use
    ///     it.
    pub fn accept_block(&mut self, block: &Block, prev_id: Option<BlockId>) -> AcceptOutcome {
        // `txTrieRoot`: for blocks received from the network the peer loop
        // stashes the raw wire bytes, so we hash each transaction's original
        // bytes (M-20 — prost's `BTreeMap` map round-trip reorders `ret` map
        // entries and would otherwise spuriously fail the merkle). In-memory
        // callers (tests / SR runtime) leave it `None` and fall back to the
        // decoded check, which is exact for their canonically-encoded blocks.
        let trie_check = match self.pending_raw_block.take() {
            Some(raw) => verify_tx_trie_root_raw(block, &raw),
            None => verify_tx_trie_root(block),
        };
        if let Err(e) = trie_check {
            return AcceptOutcome::RejectedValidation(format!("tx_trie: {e:?}"));
        }
        // Block-signature authorization, per java-tron's
        // `BlockCapsule.validateSignature`: the signature must recover to
        // the producer's witness-permission key when `ALLOW_MULTI_SIGN` is
        // on (mainnet — SRs may sign with a delegated cold/hot key), else
        // to the witness account address. `expected_block_signer` reads the
        // producer account from current (parent) state to pick the right
        // one; passing `None` here would unconditionally demand the account
        // key and reject every delegated-signer block (~1/4 of mainnet).
        // This does NOT check slot scheduling — who's *due* this slot is a
        // separate consensus concern (`tron-consensus`); here we only prove
        // the block was signed by a key authorized for its claimed witness.
        let expected = match expected_block_signer(block, &self.state) {
            Ok(addr) => addr,
            Err(e) => return AcceptOutcome::RejectedValidation(format!("witness sig: {e}")),
        };
        if let Err(e) = verify_witness_signature(block, Some(&expected)) {
            return AcceptOutcome::RejectedValidation(format!("witness sig: {e:?}"));
        }
        let id = match block_id_from_block(block) {
            Ok(id) => id,
            Err(e) => return AcceptOutcome::RejectedValidation(format!("block id: {e:?}")),
        };

        // Per-tx ref_block / chain-id replay check. The check is
        // anchored at the PARENT (`block_num - 1`) — the current
        // block isn't in `block_index` yet at this point (sync.rs
        // populates `block_index` further down, just before handing
        // off to the executor). java-tron's
        // `Manager.pushBlock → validateTransaction` rejects the whole
        // block if any tx fails, since a structurally-invalid tx in
        // a valid-looking block means the producer or a relay
        // tampered with the contents.
        if self.strict_ref_block {
            if let Some(bi) = &self.state.block_index {
                let block_num = block
                    .block_header
                    .as_ref()
                    .and_then(|h| h.raw_data.as_ref())
                    .map(|r| r.number)
                    .unwrap_or(0);
                let head_num = block_num.saturating_sub(1);
                for (i, tx) in block.transactions.iter().enumerate() {
                    let Some(raw) = tx.raw_data.as_ref() else {
                        continue; // a tx with no raw_data is rejected by execute_one_tx separately
                    };
                    if let Err(e) = crate::ref_block::validate_ref_block(raw, head_num, bi) {
                        return AcceptOutcome::RejectedValidation(format!(
                            "ref_block (tx {i}): {e}"
                        ));
                    }
                }
            }
        }

        // Seed KhaosDb on the first block of the session. We can't do
        // this in `new()` because `state` may not have a head yet.
        if !self.khaos_started {
            if let Some(head_id) = self.resume_head() {
                // Resume from disk: load the head block and seed
                // KhaosDb so the fork tree begins from the known head.
                let block_store = BlockStore::new(self.blocks_backend.clone());
                if let Ok(head_block) = block_store.get(&head_id) {
                    let _ = self.khaos.start(head_block);
                    self.khaos_started = true;
                }
            }
            // Fall through even if seeding failed (no head yet on a
            // fresh node) — `khaos.push` handles the empty-DB case.
        }

        // Dedup via KhaosDb: if we've already seen this block, skip
        // execution. Catches the common case of a peer re-sending
        // inventory we already processed.
        if self.khaos.contains_in_linked(&id) {
            return AcceptOutcome::AlreadyKnown(id);
        }

        if let Some(prev) = prev_id {
            if let Err(e) = verify_parent_link(block, prev) {
                return AcceptOutcome::RejectedValidation(format!("parent link: {e:?}"));
            }
        }

        // Push into KhaosDb to record the fork-tree position. Three
        // outcomes:
        //   * Ok(head) — linked; head may or may not have changed.
        //   * Err(Unlinked) — orphan, stashed; tell caller to gap-fill.
        //   * Err(BadNumber/Malformed) — reject outright.
        let prev_head_arc = self.khaos.head();
        let prev_head_num = prev_head_arc.as_ref().map(|h| h.num).unwrap_or(0);
        let khaos_head = match self.khaos.push(block.clone()) {
            // `PushOutcome` also classifies extension vs reorg vs sibling;
            // we only need the resulting head here. Acting on the reorg
            // signal is the sync-reorg follow-up (review §9).
            Ok(outcome) => outcome.into_head(),
            Err(tron_consensus::KhaosPushError::Unlinked) => {
                if !self.khaos_started {
                    // No head yet — first-block push is allowed even
                    // with a stranger parent (genesis-like). Re-push
                    // is unsafe here (would loop); start the head
                    // manually and proceed.
                    if self.khaos.start(block.clone()).is_ok() {
                        self.khaos_started = true;
                    }
                    self.khaos.head().unwrap_or_else(|| {
                        // Defensive: should be unreachable.
                        panic!("khaos.start succeeded but head still None")
                    })
                } else {
                    self.stats.blocks_rejected_validation += 1;
                    return AcceptOutcome::RejectedValidation(
                        "unlinked block (parent not in fork tree)".into(),
                    );
                }
            }
            Err(tron_consensus::KhaosPushError::BadNumber { parent_num, block_num }) => {
                return AcceptOutcome::RejectedValidation(format!(
                    "bad block number: parent {parent_num}, block {block_num}"
                ));
            }
            Err(tron_consensus::KhaosPushError::Malformed) => {
                return AcceptOutcome::RejectedValidation("malformed block header".into());
            }
        };
        if !self.khaos_started {
            self.khaos_started = true;
        }

        // Persist the block bytes BEFORE executing so even a partial
        // executor failure leaves them recoverable for the RPC layer and
        // for reorg re-application. `block_store` is keyed by id (hash),
        // so storing a sibling fork can't clobber the canonical block.
        //
        // `block_index` (num → id), by contrast, IS a canonical map that
        // RPC `getblockbynum` and ref_block validation read — so it must
        // NOT be written here, before we know whether this block is on
        // the canonical chain. A side fork at height N would otherwise
        // repoint `block_index[N]` away from the canonical block. The
        // index is written only once the block is confirmed canonical:
        // below for a clean head extension, and in `perform_reorg*` for a
        // block promoted by a fork switch.
        let block_store = BlockStore::new(self.blocks_backend.clone());
        if let Err(e) = block_store.put(&id, block) {
            return AcceptOutcome::RejectedExecution(format!("block_store.put: {e}"));
        }

        // Solidified-containment gate: KhaosDb already picked
        // `khaos_head` by longest-chain rule, but TRON's full
        // fork-choice rule requires the new head's chain to contain
        // the latest solidified block. If it doesn't, revert the
        // head pointer and treat the block as a rejected fork.
        // (No-ops pre-PBFT when no solidified block is set yet.)
        if let Some(rejected) = self.gate_new_head_against_solidified(
            khaos_head.id,
            khaos_head.num,
            &prev_head_arc,
        ) {
            return AcceptOutcome::RejectedSolidifiedDiverged(rejected);
        }

        // Fork-switch detection. If the new head in KhaosDb has a
        // *different* id than our just-pushed block, we landed on a
        // non-canonical fork — the executor stays on the canonical
        // chain. Phase B reorg-with-state-rollback would walk
        // get_branch here; for now, log and skip execution.
        if khaos_head.id != id {
            // This block is on a sibling fork that's still shorter
            // than or equal to the canonical head. Recorded for fork
            // analytics; not executed against state.
            return AcceptOutcome::SideFork(id);
        }
        let _ = prev_head_num;

        // The block became KhaosDb's head. Is it a clean extension of
        // the canonical chain (parent == executor's current head) or a
        // fork switch (parent points at a sibling we previously walked
        // past)?
        //
        // We compare against the actual on-disk head from dyn_props,
        // NOT the caller-supplied `prev_id` — the dispatcher loop may
        // pass a per-stream parent that doesn't reflect the canonical
        // tip. The DPS hash is authoritative for "what we've actually
        // executed against."
        let dp = DynamicPropertiesStore::new(self.state.dyn_props.clone());
        let executed_head = dp
            .latest_block_header_hash()
            .ok()
            .flatten()
            .map(BlockId::from_raw);
        let needs_reorg = match (khaos_head.parent(), executed_head) {
            (Some(p), Some(prev)) => p.id != prev,
            // No parent in the fork tree (pruned or genesis) — can't
            // tell; trust the executor's parent-link check above.
            (None, _) => false,
            // First block of the session (no executed head yet) — let
            // the executor handle parent-link validation.
            (Some(_), None) => false,
        };
        if needs_reorg {
            // Snapshot-stack path takes priority: when wired, the
            // tentative-write layers from the divergent old chain
            // get revoked one-by-one and the new fork applies under
            // fresh layers. Falls back to BlockUndoStore-driven
            // rollback when no snapshot stack is attached.
            if self.snapshot_stack.is_some() {
                return self.perform_reorg_via_snapshot(block, id);
            }
            if let Some(undo_store) = self.undo_store.clone() {
                return self.perform_reorg(block, id, undo_store);
            }
            return AcceptOutcome::ReorgRequired(id, khaos_head.num);
        }
        let _ = prev_head_num;

        // Clean canonical extension: this block's parent is the executed
        // head, so it's on the main chain. Record it in the num → id
        // index now (before execute, mirroring the old persist-before-gate
        // ordering — a `reconcile_stores_to_head` pass prunes the entry on
        // startup if execution then fails). Side forks returned above and
        // never reach here, so they don't pollute the index.
        if let Some(bi) = &self.state.block_index {
            let block_index = BlockIndexStore::new(bi.clone());
            if let Err(e) = block_index.put(&id) {
                return AcceptOutcome::RejectedExecution(format!("block_index.put: {e}"));
            }
        }

        // When the snapshot stack is attached, every block runs under
        // its own tentative-write layer so a future reorg can revoke
        // it. Without the stack, fall through to the legacy
        // BlockUndoStore path.
        if self.snapshot_stack.is_some() {
            return self.execute_under_snapshot(block, id, prev_id);
        }

        // Catch-up fast path: while the block we're applying is well
        // behind wall-clock we're doing bulk sync, so defer the expensive
        // per-store WAL fsync (batched into a barrier inside the commit —
        // see `ExecConfig::defer_store_fsync`). At/near the tip every block
        // fsyncs for full per-block durability. Either way no data is lost:
        // a crash replays the retained cross-store manifests on restart.
        // Only applies on this canonical-extension path; the rarer reorg /
        // reapply paths keep full per-block fsync.
        self.exec_config.defer_store_fsync = is_catching_up(block);

        // Execute. The executor commits dyn_props head + applies every
        // tx atomically inside a session. With an undo store, also
        // persist a per-block undo log for any future reorg. If a
        // cross-store checkpoint is attached, route through it so the
        // block's writes land behind one durable manifest (recovered
        // on next startup if we crash mid-flush).
        let exec_result = match (&self.undo_store, &self.checkpoint) {
            (Some(undo), Some(cp)) => tron_executor::execute_block_with_undo_checkpoint_and_config(
                &self.state,
                block,
                prev_id,
                undo,
                cp,
                &self.exec_config,
            ),
            (Some(undo), None) => tron_executor::execute_block_with_undo_and_config(
                &self.state,
                block,
                prev_id,
                undo,
                &self.exec_config,
            ),
            (None, _) => tron_executor::execute_block_with_config(
                &self.state,
                block,
                prev_id,
                &self.exec_config,
            ),
        };
        match exec_result {
            Ok(report) => {
                self.stats.blocks_applied += 1;
                if let Some(m) = &self.metrics {
                    m.inc_blocks_applied();
                    // Reflect the new head pointer in the gauge too —
                    // operators care about how far the node has progressed.
                    m.set_head_block_number(id.num() as i64);
                }
                self.apply_sr_rotation(&report);
                self.update_solidified(block, id.num() as i64);
                self.emit_block_events(block, &id, &report);
                self.publish_block_to_pubsub(block, &id, &report);
                self.drop_included_txs_from_mempool(block);
                AcceptOutcome::Accepted(id)
            }
            Err(e) => AcceptOutcome::RejectedExecution(format!("{e:?}")),
        }
    }

    /// Apply `block` under a fresh snapshot layer. On success, the
    /// layer is kept on the stack so a future reorg can revoke it;
    /// on failure, the layer is revoked immediately so no partial
    /// state mutations leak. After success, the bottom-most layer is
    /// merged into the root whenever the stack depth would exceed
    /// `snapshot_horizon` — this caps RAM at `horizon` layers and
    /// fixes the reorg ceiling at that many blocks.
    ///
    /// This is the snapshot-stack-driven replacement for the
    /// `BlockUndoStore`-based path. The legacy path is still
    /// available when `snapshot_stack` is `None`.
    fn execute_under_snapshot(
        &mut self,
        block: &Block,
        id: BlockId,
        prev_id: Option<BlockId>,
    ) -> AcceptOutcome {
        let stack = self
            .snapshot_stack
            .clone()
            .expect("execute_under_snapshot called without a snapshot stack");
        let block_num = id.num() as i64;
        // The coordinator owns advance/revoke/horizon-merge under
        // its internal mutex. We pass the execute closure in; the
        // coordinator handles the rest.
        let state = &self.state;
        let exec_config = &self.exec_config;
        let result = stack.apply_block(block_num, || {
            tron_executor::execute_block_with_config(state, block, prev_id, exec_config)
                .map_err(|e| format!("{e:?}"))
        });
        match result {
            Ok(report) => {
                self.stats.blocks_applied += 1;
                if let Some(m) = &self.metrics {
                    m.inc_blocks_applied();
                    m.set_head_block_number(id.num() as i64);
                }
                self.apply_sr_rotation(&report);
                self.update_solidified(block, id.num() as i64);
                self.emit_block_events(block, &id, &report);
                self.publish_block_to_pubsub(block, &id, &report);
                self.drop_included_txs_from_mempool(block);
                AcceptOutcome::Accepted(id)
            }
            Err(e) => AcceptOutcome::RejectedExecution(e),
        }
    }

    /// Snapshot-stack-driven reorg. Walks back to the most-recent
    /// common ancestor by `revoke`-ing one layer per old-chain block,
    /// then applies the new-fork blocks under fresh layers. Mirrors
    /// the semantics of `perform_reorg` but uses tentative-write
    /// layers instead of the `BlockUndoStore` undo log. On a partial
    /// failure mid-replay, attempts to recover by revoking the
    /// partial new-fork progress — but since the old chain's layers
    /// were already discarded by the initial `revoke`, full recovery
    /// requires re-applying the old chain from KhaosDb's cache. If
    /// re-apply also fails, the chain enters a known-inconsistent
    /// state that requires operator intervention.
    fn perform_reorg_via_snapshot(
        &mut self,
        new_block: &Block,
        new_block_id: BlockId,
    ) -> AcceptOutcome {
        let stack = self
            .snapshot_stack
            .clone()
            .expect("perform_reorg_via_snapshot called without a snapshot stack");
        let dp = DynamicPropertiesStore::new(self.state.dyn_props.clone());
        let executed_head = match dp
            .latest_block_header_hash()
            .ok()
            .flatten()
            .map(BlockId::from_raw)
        {
            Some(h) => h,
            None => {
                return AcceptOutcome::ReorgRequired(
                    new_block_id,
                    new_block_id.num() as i64,
                );
            }
        };

        let (path_old, path_new) = match self.khaos.get_branch(&executed_head, &new_block_id) {
            Ok(pair) => pair,
            Err(e) => {
                warn!(?e, "khaos.get_branch failed during snapshot reorg");
                return AcceptOutcome::RejectedValidation(format!(
                    "reorg failed: no common ancestor: {e:?}"
                ));
            }
        };

        let new_oldest_first: Vec<_> = path_new.iter().rev().collect();
        let old_block_nums: Vec<i64> = path_old.iter().map(|kb| kb.num).collect();
        let new_block_nums: Vec<i64> = new_oldest_first.iter().map(|kb| kb.num).collect();

        // Each new-fork block needs to be looked up: the just-pushed
        // tip uses the caller-supplied `new_block` (it isn't in
        // KhaosBlock cache yet); older fork blocks come from KhaosDb.
        let new_blocks: Vec<&Block> = new_oldest_first
            .iter()
            .map(|kb| if kb.id == new_block_id { new_block } else { &kb.block })
            .collect();
        let state = &self.state;
        let exec_config = &self.exec_config;
        let path_old_for_repush = &path_old;
        let outcome = stack.reorg::<String, _, _, _>(
            &old_block_nums,
            &new_block_nums,
            // BETWEEN: state is now at common ancestor — repush
            // old-fork txs against this state.
            || {
                self.repush_reorged_txs(path_old_for_repush.iter());
            },
            // APPLY: per new-fork block, execute against the state
            // that the coordinator has just `advance`d.
            |block_num, idx| {
                let block_to_apply = new_blocks[idx];
                tron_executor::execute_block_with_config(
                    state,
                    block_to_apply,
                    None,
                    exec_config,
                )
                .map_err(|e| format!("block {block_num}: {e:?}"))
            },
        );

        match outcome {
            Ok(reports) => {
                // The coordinator has applied every new-fork block
                // and updated the layer stack; here we emit
                // per-block side effects in the same order, threading
                // each block's report through `apply_sr_rotation`,
                // event bus emission, and pubsub publishing.
                for (idx, kb) in new_oldest_first.iter().enumerate() {
                    let block_to_apply = new_blocks[idx];
                    let report = &reports[idx];
                    self.stats.blocks_applied += 1;
                    if let Some(m) = &self.metrics {
                        m.inc_blocks_applied();
                        m.set_head_block_number(kb.num);
                    }
                    self.apply_sr_rotation(report);
                    let block_id =
                        tron_types::block_id_from_block(block_to_apply).unwrap_or(kb.id);
                    self.emit_block_events(block_to_apply, &block_id, report);
                    self.publish_block_to_pubsub(block_to_apply, &block_id, report);
                    self.drop_included_txs_from_mempool(block_to_apply);
                }
                // Repoint num → id at the new canonical branch (side-fork
                // blocks never indexed themselves).
                self.reindex_canonical_branch(new_oldest_first.iter().copied());
                info!(
                    old_chain_revoked = path_old.len(),
                    new_chain_applied = new_oldest_first.len(),
                    new_head = %hex::encode(&new_block_id.as_bytes()[..8]),
                    "REORG (snapshot): switched canonical chain"
                );
                AcceptOutcome::Accepted(new_block_id)
            }
            Err(crate::storage::ReorgFailure::Drift { expected, actual }) => {
                error!(
                    expected,
                    actual, "snapshot stack out of sync with reorg path"
                );
                AcceptOutcome::RejectedExecution(format!(
                    "snapshot drift at block {expected}: top layer is for block {actual}"
                ))
            }
            Err(crate::storage::ReorgFailure::PastHorizon(num)) => {
                AcceptOutcome::RejectedValidation(format!(
                    "reorg target {num} is past the snapshot horizon (already merged)"
                ))
            }
            Err(crate::storage::ReorgFailure::ApplyFailed {
                failed_block,
                applied_before,
                source,
            }) => {
                error!(
                    ?source,
                    failed_block,
                    applied_before,
                    "new-fork block failed; original chain NOT restored"
                );
                // Recovery (re-apply old chain) requires a second
                // coordinator pass. Future work — operator
                // intervention required for now.
                AcceptOutcome::RejectedExecution(format!(
                    "new-fork block {failed_block} apply failed: {source}; \
                     {applied_before} blocks committed before failure — \
                     chain state may be inconsistent"
                ))
            }
        }
    }

    /// Push `newHeads` + per-log notifications to the WebSocket
    /// pubsub broker. No-op when no broker is attached. Called
    /// after each successful block-apply; the report carries the
    /// VM logs already grouped by tx.
    fn publish_block_to_pubsub(
        &self,
        block: &Block,
        block_id: &BlockId,
        report: &tron_executor::BlockExecutionReport,
    ) {
        let Some(broker) = self.pubsub.as_ref() else {
            return;
        };
        broker.publish_head(tron_rpc::pubsub::head_event_from_block(block, block_id.as_bytes()));
        let block_number = block_id.num() as i64;
        let block_hash = *block_id.as_bytes();
        for tx_result in &report.tx_results {
            for (log_index, vm_log) in tx_result.vm_logs.iter().enumerate() {
                broker.publish_log(tron_rpc::pubsub::log_event_from_vm_log(
                    vm_log,
                    block_number,
                    &block_hash,
                    &tx_result.tx_id,
                    log_index,
                ));
            }
        }
    }

    /// Drop every transaction in `block` from the mempool's pending
    /// pool. Called after a successful block-apply so peer-relayed
    /// txs (which entered our mempool via the pull-based inventory
    /// cycle) don't sit around once they're on chain. Mirrors the
    /// `mempool.remove` loop in `SrRuntime::try_produce` — same
    /// rationale, applied to the inbound (sync) side.
    ///
    /// No-op when no mempool is attached.
    fn drop_included_txs_from_mempool(&self, block: &Block) {
        let Some(mempool) = self.mempool.as_ref() else {
            return;
        };
        use prost::Message as _;
        for tx in &block.transactions {
            if let Some(raw) = &tx.raw_data {
                let id = tron_crypto::hash::sha256(&raw.encode_to_vec());
                mempool.remove(&id);
            }
        }
    }

    /// Push every transaction from the reorged-out blocks back into
    /// the mempool. Mirrors java-tron's `Manager.popTransactions` +
    /// `rePushLoop`: txs that were on the abandoned fork are
    /// re-validated against the post-reorg state via the standard
    /// `submit_tron` path. Failures (expired, conflicting with a tx on
    /// the new fork, signer balance dropped below fee, etc.) are
    /// silently dropped — matching java-tron's behaviour where
    /// `pushTransaction` exceptions inside `rePushLoop` are logged
    /// but not surfaced.
    ///
    /// Called from both reorg paths only after the new fork has been
    /// fully applied; the txs validate against the new head's state.
    fn repush_reorged_txs<'a, I>(&self, reverted_blocks: I)
    where
        I: IntoIterator<Item = &'a std::sync::Arc<tron_consensus::KhaosBlock>>,
    {
        let Some(mempool) = self.mempool.as_ref() else {
            return;
        };
        use prost::Message as _;
        let mut total = 0usize;
        let mut accepted = 0usize;
        let mut dropped = 0usize;
        let mut block_count = 0usize;
        for kb in reverted_blocks {
            block_count += 1;
            for tx in &kb.block.transactions {
                total += 1;
                let raw = tx.encode_to_vec();
                match mempool.submit(&raw) {
                    Ok(_) => accepted += 1,
                    Err(MempoolError::Duplicate) => {
                        // Already in pending — fine; the next block
                        // production will pick it up.
                        accepted += 1;
                    }
                    Err(_) => dropped += 1,
                }
            }
        }
        if total > 0 {
            info!(
                reverted_blocks = block_count,
                txs_total = total,
                txs_repushed = accepted,
                txs_dropped = dropped,
                "mempool repushed txs from reorged blocks"
            );
        }
    }

    /// Fold this block's [`MaintenanceRotation`] (if any) into the
    /// shared [`tron_consensus::SrEpochSnapshot`]. Mirrors java-tron's
    /// `MaintenanceManager.applyBlock` populating `beforeWitness` /
    /// `currentWitness` / `beforeMaintenanceTime` so the PBFT runtime
    /// can validate cross-rotation votes correctly.
    fn apply_sr_rotation(&self, report: &tron_executor::BlockExecutionReport) {
        let Some(rot) = &report.maintenance else {
            return;
        };
        let Some(snap) = &self.sr_snapshot else {
            return;
        };
        let Ok(mut guard) = snap.write() else {
            warn!("sr snapshot poisoned; skipping rotation update");
            return;
        };
        guard.rotate(
            rot.prev_active.clone(),
            rot.new_active.clone(),
            rot.before_maintenance_time_ms,
        );
    }

    /// Maximum entries held in [`Self::recent_witnesses`]. ⌈2/3⌉ of 27
    /// mainnet SRs is 19 distinct witnesses; 64 leaves ample slack for
    /// skipped slots / occasional repeats within one rotation.
    const SOLID_WINDOW: usize = 64;

    /// Advance the DPoS solidified-block pointer after applying `block`.
    ///
    /// Ports java-tron's `Manager.updateLatestSolidifiedBlock`: a block is
    /// solid once ⌈2/3⌉ of the active witnesses have produced it or a
    /// descendant. We feed the rolling newest-first `(num, witness)` window
    /// to [`tron_consensus::latest_solid_block`] and bump
    /// `LATEST_SOLIDIFIED_BLOCK_NUM` whenever it moves forward (never
    /// backward). Without this the pointer only advances on PBFT commit
    /// traffic, so a plain block sync jams ~1024 blocks past the snapshot's
    /// solidified head once the reversible window fills
    /// (`gate_new_head_against_solidified`).
    fn update_solidified(&mut self, block: &Block, block_num: i64) {
        // Producing witness for this block.
        let witness = match block
            .block_header
            .as_ref()
            .and_then(|h| h.raw_data.as_ref())
            .map(|raw| raw.witness_address.as_slice())
        {
            Some(w) if w.len() == 21 => {
                let mut buf = [0u8; 21];
                buf.copy_from_slice(w);
                tron_crypto::address::Address::from_raw(buf)
            }
            // The block already passed signature validation, so a
            // malformed witness address shouldn't reach here; skip safely.
            _ => return,
        };

        // Push newest-first and cap the window.
        self.recent_witnesses
            .push_front(tron_consensus::RecentBlock { num: block_num, witness });
        while self.recent_witnesses.len() > Self::SOLID_WINDOW {
            self.recent_witnesses.pop_back();
        }

        self.advance_solid_from_window();
    }

    /// Compute the DPoS solidified block from the current rolling window
    /// and advance `LATEST_SOLIDIFIED_BLOCK_NUM` if it moved forward (never
    /// backward — a higher PBFT-set value wins). Shared by
    /// [`Self::update_solidified`] (per applied block) and
    /// [`Self::seed_solidified_from_disk`] (startup).
    fn advance_solid_from_window(&self) {
        // Active-witness count drives the ⌈2/3⌉ threshold; read it from the
        // witness schedule (27 on mainnet). No schedule store / empty list
        // → can't size the threshold, so leave solidity untouched.
        let Some(ws) = &self.state.witness_schedule else {
            return;
        };
        let active_count = match WitnessScheduleStore::new(ws.clone()).load_active() {
            Ok(Some(list)) if !list.is_empty() => list.len(),
            _ => return,
        };

        // The window is newest-first, exactly what `latest_solid_block`
        // walks. It returns `None` until the window holds `threshold`
        // distinct witnesses (the first ~19 blocks after a snapshot boot)
        // — leave the pointer alone in that case.
        let window: Vec<tron_consensus::RecentBlock> =
            self.recent_witnesses.iter().cloned().collect();
        let Some(solid) = tron_consensus::latest_solid_block(&window, active_count) else {
            return;
        };

        let dp = DynamicPropertiesStore::new(self.state.dyn_props.clone());
        let current = dp.latest_solidified_block_num().unwrap_or(0);
        if solid > current {
            dp.save_latest_solidified_block_num(solid);
            if let Some(m) = &self.metrics {
                m.set_solidified_block_number(solid);
            }
        }
    }

    /// Seed the rolling window and the solidified pointer from the most
    /// recent on-disk blocks at startup.
    ///
    /// Without this a node resumed at or near `solid + WALK_HORIZON`
    /// deadlocks: `gate_new_head_against_solidified` rejects the next block
    /// before any apply can run [`Self::update_solidified`], and the
    /// in-memory window starts empty across restarts — so the pointer can
    /// never catch up. Reads at most [`Self::SOLID_WINDOW`] blocks back
    /// from the persisted head; cheap, and reorg-safe (always reflects the
    /// current canonical chain).
    fn seed_solidified_from_disk(&mut self) {
        let head = self.head_number();
        if head < 1 {
            return;
        }
        let Some(bi_backend) = self.state.block_index.clone() else {
            return;
        };
        let block_index = BlockIndexStore::new(bi_backend);
        let block_store = BlockStore::new(self.blocks_backend.clone());

        let lowest = (head - Self::SOLID_WINDOW as i64 + 1).max(1);
        let mut window: VecDeque<tron_consensus::RecentBlock> = VecDeque::new();
        // Newest-first: walk head down to `lowest`. Stop at the first gap
        // (a pruned / missing index entry) — the newest contiguous run is
        // what solidification needs.
        for num in (lowest..=head).rev() {
            let Ok(id) = block_index.get(num) else { break };
            let Ok(block) = block_store.get(&id) else { break };
            let Some(w) = block
                .block_header
                .as_ref()
                .and_then(|h| h.raw_data.as_ref())
                .map(|raw| raw.witness_address.clone())
                .filter(|w| w.len() == 21)
            else {
                continue;
            };
            let mut buf = [0u8; 21];
            buf.copy_from_slice(&w);
            window.push_back(tron_consensus::RecentBlock {
                num,
                witness: tron_crypto::address::Address::from_raw(buf),
            });
        }
        let dp = DynamicPropertiesStore::new(self.state.dyn_props.clone());
        let before = dp.latest_solidified_block_num().unwrap_or(0);
        self.recent_witnesses = window;
        self.advance_solid_from_window();
        let after = dp.latest_solidified_block_num().unwrap_or(0);
        // Only the first driver to seed actually moves the pointer; the
        // rest find it already advanced. Log just the real advance.
        if after > before {
            info!(head, solidified = after, "seeded DPoS solidified block from disk at startup");
        }
    }

    /// Prune any `block_store` / `block_index` entries ahead of the executed
    /// head at startup (M-19).
    ///
    /// `accept_block` persists a block (`block_store` + `block_index`)
    /// *before* the solidified-containment gate and before execution, so a
    /// block that is persisted then gate-rejected — e.g. by a pre-M-18
    /// binary stalled at the `solid + WALK_HORIZON` jam — is left on disk
    /// yet never executed. `block_index` then leads the executed head; the
    /// inventory-dedup treats the orphan as already-held and never
    /// re-fetches it, so the head can't advance past it and every later
    /// block fails parent-link.
    ///
    /// Removing the orphans restores the invariant that the block stores
    /// never lead the executed head, so the gap is cleanly re-fetched and
    /// re-executed. Runs once at startup before any peer work, so nothing
    /// races the deletes; bounded by the reversible window as a backstop.
    fn reconcile_stores_to_head(&mut self) {
        let head = self.head_number();
        let Some(bi_backend) = self.state.block_index.clone() else {
            return;
        };
        let block_index = BlockIndexStore::new(bi_backend);
        let block_store = BlockStore::new(self.blocks_backend.clone());

        let mut pruned = 0i64;
        let mut num = head + 1;
        while pruned <= 1024 {
            let id = match block_index.get(num) {
                Ok(id) => id,
                Err(_) => break, // first gap → no more orphans
            };
            // Remove the bytes first, then the index entry. Best-effort on
            // the bytes; stop if the index delete fails so we don't spin.
            let _ = block_store.delete(&id);
            if block_index.delete(num).is_err() {
                break;
            }
            pruned += 1;
            num += 1;
        }
        if pruned > 0 {
            warn!(
                head,
                pruned,
                "pruned persist-before-gate block(s) ahead of the executed head; they will be re-fetched and re-executed"
            );
        }
    }

    /// Enforce TRON's solidified-containment rule on a head switch:
    /// the new head's chain must walk back to the latest solidified
    /// block. Returns `Some(rejected_id)` if the gate fails, and
    /// reverts KhaosDb's head pointer to `prev_head_arc` so subsequent
    /// pushes don't keep building on the rejected fork.
    ///
    /// `None` returned in any of these cases (gate is vacuously OK):
    /// * Head didn't change (no promotion to gate).
    /// * No latest-solidified is set yet (boot-time / pre-PBFT).
    /// * No executed head exists in DPS (first block of a fresh node).
    /// * The walk back from executed head can't reach the solidified
    ///   height (pruned, corrupted) — trust existing parent-link checks.
    ///
    /// The actual containment walk is delegated to
    /// [`tron_consensus::best_head_with_solidified`], which already
    /// handles the WALK_HORIZON cap + same-height-different-id
    /// divergence detection.
    ///
    /// ## Why we derive `solid_id` by walking from DPS, not BlockIndex
    ///
    /// `BlockIndexStore::put` is called for every accepted block
    /// regardless of fork (line ~1338), so a side-fork push at the
    /// solidified height temporarily overwrites the canonical id in
    /// the index. Walking back from `dp.latest_block_header_hash()`
    /// — which only advances on actual block APPLICATION (not push)
    /// — is the canonical source of truth.
    fn gate_new_head_against_solidified(
        &mut self,
        new_head_id: BlockId,
        new_head_num: i64,
        prev_head_arc: &Option<Arc<tron_consensus::KhaosBlock>>,
    ) -> Option<BlockId> {
        // No-op when the head didn't actually change.
        let prev_id = prev_head_arc.as_ref().map(|h| h.id);
        if prev_id == Some(new_head_id) {
            return None;
        }

        let dp = DynamicPropertiesStore::new(self.state.dyn_props.clone());
        let solid_num = dp.latest_solidified_block_num().unwrap_or(0);
        if solid_num < 1 {
            return None;
        }
        let executed_head_bytes = match dp.latest_block_header_hash() {
            Ok(Some(b)) => b,
            Ok(None) => return None,
            Err(e) => {
                // A read fault here mustn't masquerade as "no head" silently.
                error!(error = %e, "reorg ancestor scan: failed to read latest block header hash");
                return None;
            }
        };
        let executed_head_id = BlockId::from_raw(executed_head_bytes);

        let block_store = BlockStore::new(self.blocks_backend.clone());
        let parent_of = |id: &BlockId| -> Option<BlockId> {
            let block = match block_store.get(id) {
                Ok(b) => b,
                // Walking off the end of what we have is expected — stop quietly.
                Err(tron_chainbase::StoreError::NotFound) => return None,
                // A real IO fault is not "missing parent"; surface it.
                Err(e) => {
                    error!(block = ?id, error = %e, "reorg ancestor scan: failed to read block");
                    return None;
                }
            };
            let raw = block.block_header.as_ref()?.raw_data.as_ref()?;
            if raw.parent_hash.len() != 32 {
                return None;
            }
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&raw.parent_hash);
            Some(BlockId::from_raw(buf))
        };

        // Walk back from the executed head (canonical chain) until we
        // reach a block at solid_num. That BlockId is the canonical
        // solidified id. Stop early if we walk off the chain or hit a
        // ~1024-block bound (KhaosDb's same horizon — anything deeper
        // is almost certainly pruned). Walking from the executed head,
        // which side-fork pushes can't update, sidesteps the temporary
        // BlockIndex corruption that sibling-pushes cause.
        const WALK_HORIZON: usize = 1024;
        let mut cur = executed_head_id;
        let mut cur_num = (cur.num() as i64).max(0);
        let mut steps = 0usize;
        while cur_num > solid_num && steps < WALK_HORIZON {
            let Some(p) = parent_of(&cur) else {
                return None; // chain gap — skip the gate defensively
            };
            cur = p;
            cur_num = (cur.num() as i64).max(0);
            steps += 1;
        }
        if cur_num != solid_num {
            return None; // overshot or undershot — skip
        }
        let solid_id = cur;

        let candidate = tron_consensus::ForkChoice {
            head: new_head_id,
            number: new_head_num,
        };
        match tron_consensus::best_head_with_solidified(&[candidate], solid_id, parent_of) {
            Ok(_) => None,
            Err(_) => {
                // Revert head pointer so the rejected fork can't
                // silently absorb the next block as well.
                if let Some(prev) = prev_head_arc.clone() {
                    self.khaos.set_head(prev);
                }
                warn!(
                    head = ?new_head_id,
                    head_num = new_head_num,
                    solid_num,
                    "rejecting head promotion: candidate diverges from latest solidified"
                );
                Some(new_head_id)
            }
        }
    }

    /// Hand the executor's per-tx outcomes to the eventer bus (when
    /// attached) so downstream subscribers see one block trigger +
    /// one transaction trigger per tx, plus a contract-event /
    /// contract-log trigger per successful VM log. The bus's own
    /// `is_empty` check makes this a one-instruction noop on nodes
    /// that don't subscribe.
    fn emit_block_events(
        &self,
        block: &Block,
        id: &BlockId,
        report: &tron_executor::BlockExecutionReport,
    ) {
        let Some(bus) = &self.event_bus else {
            return;
        };
        if bus.is_empty() {
            return;
        }
        let dyn_props = tron_chainbase::DynamicPropertiesStore::new(self.state.dyn_props.clone());
        let latest_solid = dyn_props.latest_solidified_block_num().unwrap_or(0);
        let outcomes: Vec<tron_eventer::TxOutcomeSlice> = report
            .tx_results
            .iter()
            .map(|r| tron_eventer::TxOutcomeSlice {
                tx_id: r.tx_id,
                contract_result: format!("{:?}", r.outcome),
            })
            .collect();
        tron_eventer::emit_block_and_transactions(
            bus,
            block,
            id.as_bytes(),
            &outcomes,
            latest_solid,
        );
        self.emit_vm_logs(bus, block, id, report, latest_solid);
    }

    /// For each successful VM-bound tx, walk the captured `vm_logs`,
    /// ABI-decode each one via `decode_one_log`, and emit a
    /// `ContractEvent` (decoded) or `ContractLogEvent` (raw fallback)
    /// on the bus. Mirrors java-tron's `LogsFilter` post-execution
    /// emit: only successful txs surface logs, and the per-event
    /// ABI decode is best-effort (missing ABI → raw log).
    fn emit_vm_logs(
        &self,
        bus: &EventBus,
        block: &Block,
        block_id: &BlockId,
        report: &tron_executor::BlockExecutionReport,
        latest_solid: i64,
    ) {
        // Pull the per-block timestamp once.
        let timestamp_ms = block
            .block_header
            .as_ref()
            .and_then(|h| h.raw_data.as_ref())
            .map(|r| r.timestamp)
            .unwrap_or(0);
        let block_number = block
            .block_header
            .as_ref()
            .and_then(|h| h.raw_data.as_ref())
            .map(|r| r.number)
            .unwrap_or(0);
        let block_hash_hex = hex::encode(block_id.as_bytes());

        let abi_store = tron_chainbase::AbiStore::new(self.state.abi.clone());
        let contract_store =
            tron_chainbase::ContractStore::new(self.state.contracts.clone());

        for (tx, result) in block.transactions.iter().zip(report.tx_results.iter()) {
            if !matches!(result.outcome, tron_executor::TxOutcome::Success) {
                continue;
            }
            if result.vm_logs.is_empty() {
                continue;
            }

            // origin_address = tx's owner (signer). caller_address for
            // the top-level frame equals origin; nested CALL frames'
            // callers aren't preserved through the executor's flat log
            // list (revm collapses logs across frames). java-tron's
            // logsfilter accepts this approximation — consumers that
            // want per-frame caller info read the trace anyway.
            let origin_hex = tx
                .raw_data
                .as_ref()
                .and_then(|r| r.contract.first())
                .and_then(|c| c.parameter.as_ref())
                .map(|any| extract_owner_address_hex(&any.value))
                .unwrap_or_default();
            let tx_id_hex = hex::encode(result.tx_id);

            for (log_index, vm_log) in result.vm_logs.iter().enumerate() {
                // EVM 20-byte → TRON 21-byte (prepend 0x41), then hex.
                let mut tron_addr = [0u8; 21];
                tron_addr[0] = 0x41;
                tron_addr[1..].copy_from_slice(&vm_log.address);
                let contract_addr_hex = hex::encode(tron_addr);
                let creator_hex = contract_store
                    .get(&tron_crypto::address::Address::from_raw(tron_addr))
                    .ok()
                    .flatten()
                    .map(|c| hex::encode(&c.origin_address))
                    .unwrap_or_default();

                let ctx = crate::abi_event_decoder::EventLogContext {
                    time_stamp: timestamp_ms,
                    block_number,
                    block_hash_hex: block_hash_hex.clone(),
                    transaction_id_hex: tx_id_hex.clone(),
                    contract_address_hex: contract_addr_hex,
                    origin_address_hex: origin_hex.clone(),
                    caller_address_hex: origin_hex.clone(),
                    creator_address_hex: creator_hex,
                    unique_id: format!("{}_{}", tx_id_hex, log_index),
                    removed: false,
                    latest_solidified_block_number: latest_solid,
                };

                let decoded = crate::abi_event_decoder::decode_one_log(
                    &ctx,
                    &tron_addr,
                    &vm_log.topics,
                    &vm_log.data,
                    |addr| {
                        // ContractStore key is the 21-byte form.
                        let mut buf = [0u8; 21];
                        if addr.len() == 21 {
                            buf.copy_from_slice(addr);
                        } else {
                            return None;
                        }
                        abi_store
                            .get(&tron_crypto::address::Address::from_raw(buf))
                            .ok()
                            .flatten()
                    },
                );
                match decoded {
                    crate::abi_event_decoder::DecodedLog::Event(ev) => {
                        bus.emit_contract_event(&ev);
                    }
                    crate::abi_event_decoder::DecodedLog::Log(log) => {
                        bus.emit_contract_log(&log);
                    }
                }
            }
        }
    }

    /// Roll back the divergent canonical chain to the most-recent
    /// common ancestor with the new head's chain, then apply the new
    /// fork's blocks in order. Called by `accept_block` when KhaosDb
    /// signals a fork switch and an undo store is attached.
    ///
    /// **Atomicity**: if any block on the new fork fails to apply, we
    /// roll back our partial new-fork progress AND re-apply the
    /// original chain blocks so the executed head returns to its
    /// pre-reorg state. Matches java-tron's `Manager.switchFork`
    /// try/catch-and-rebuild logic.
    /// Point `block_index` (num → id) at every block on a freshly-promoted
    /// canonical branch after a reorg. Side-fork blocks deliberately never
    /// wrote their index entry (only canonical blocks do), so the winning
    /// branch's heights — which until now still pointed at the losing
    /// branch — must be (re)written here. A reorg only fires when the new
    /// tip is strictly higher than the old head, so these writes overwrite
    /// every stale old-branch height and no deletes are needed. Best-effort:
    /// a put failure is logged, not fatal — the blocks are already applied.
    fn reindex_canonical_branch<'a>(
        &self,
        blocks: impl IntoIterator<Item = &'a std::sync::Arc<tron_consensus::KhaosBlock>>,
    ) {
        let Some(bi) = &self.state.block_index else {
            return;
        };
        let block_index = BlockIndexStore::new(bi.clone());
        for kb in blocks {
            if let Err(e) = block_index.put(&kb.id) {
                warn!(num = kb.num, ?e, "block_index.put failed during reorg reindex");
            }
        }
    }

    fn perform_reorg(
        &mut self,
        new_block: &Block,
        new_block_id: BlockId,
        undo_store: tron_chainbase::BlockUndoStore,
    ) -> AcceptOutcome {
        let dp = DynamicPropertiesStore::new(self.state.dyn_props.clone());
        let executed_head = match dp
            .latest_block_header_hash()
            .ok()
            .flatten()
            .map(BlockId::from_raw)
        {
            Some(h) => h,
            None => {
                // No head to walk back from — treat as informational.
                return AcceptOutcome::ReorgRequired(new_block_id, new_block_id.num() as i64);
            }
        };

        // Walk back from each tip to the most-recent common ancestor.
        // path_old = blocks on the canonical chain that must be rolled
        // back (newest→oldest). path_new = blocks on the new fork that
        // must be re-applied (we'll reverse it for oldest-first apply).
        let (path_old, path_new) = match self.khaos.get_branch(&executed_head, &new_block_id) {
            Ok(pair) => pair,
            Err(e) => {
                warn!(?e, "khaos.get_branch failed during reorg");
                return AcceptOutcome::RejectedValidation(format!(
                    "reorg failed: no common ancestor: {e:?}"
                ));
            }
        };

        // Roll back the old chain, newest first. Each block consumes
        // its undo record (which `rollback_block` deletes after replay).
        let mut rolled_back: Vec<(BlockId, i64)> = Vec::new();
        for kb in &path_old {
            match tron_executor::rollback_block(&self.state, kb.num, &undo_store) {
                Ok(_) => rolled_back.push((kb.id, kb.num)),
                Err(e) => {
                    // Partial rollback — the chain is now in a hybrid
                    // state. We can't safely continue. Surface the
                    // error; an operator restart from a snapshot is the
                    // recovery path.
                    error!(?e, block = kb.num, "rollback failed mid-reorg");
                    return AcceptOutcome::RejectedExecution(format!(
                        "rollback failed at block {}: {e:?}",
                        kb.num
                    ));
                }
            }
        }
        let _ = rolled_back;

        // Re-push old-fork txs BEFORE applying the new fork — see
        // the matching call in `perform_reorg_via_snapshot` for the
        // ordering rationale.
        self.repush_reorged_txs(&path_old);

        // Apply the new fork, oldest first. path_new is in newest-
        // first order from get_branch; iter().rev() reverses it. Each
        // block needs to be looked up either in the KhaosBlock (which
        // owns the full Block) or, for the just-pushed new head, used
        // directly.
        let new_path_oldest_first: Vec<_> = path_new.iter().rev().collect();
        // Track every block we successfully apply on the new fork.
        // If a later block fails, we walk this list backwards to undo
        // each one before re-applying the old chain.
        let mut applied_new: Vec<i64> = Vec::with_capacity(new_path_oldest_first.len());
        for kb in &new_path_oldest_first {
            let block_to_apply = if kb.id == new_block_id {
                new_block
            } else {
                &kb.block
            };
            let apply_res = match &self.checkpoint {
                Some(cp) => tron_executor::execute_block_with_undo_checkpoint_and_config(
                    &self.state,
                    block_to_apply,
                    None,
                    &undo_store,
                    cp,
                    &self.exec_config,
                ),
                None => tron_executor::execute_block_with_undo_and_config(
                    &self.state,
                    block_to_apply,
                    None,
                    &undo_store,
                    &self.exec_config,
                ),
            };
            match apply_res {
                Ok(report) => {
                    applied_new.push(kb.num);
                    self.stats.blocks_applied += 1;
                    if let Some(m) = &self.metrics {
                        m.inc_blocks_applied();
                        m.set_head_block_number(kb.num);
                    }
                    // Reorgs are short on real chains (< maintenance
                    // interval), but if a maintenance block lands on
                    // the winning fork, the snapshot must still
                    // capture its rotation.
                    self.apply_sr_rotation(&report);
                    let block_id =
                        tron_types::block_id_from_block(block_to_apply).unwrap_or(kb.id);
                    self.publish_block_to_pubsub(block_to_apply, &block_id, &report);
                    self.drop_included_txs_from_mempool(block_to_apply);
                }
                Err(e) => {
                    // Mid-reorg failure recovery (mirrors java-tron's
                    // `Manager.switchFork` try/catch-and-rebuild):
                    //   (a) Roll back every block we just applied on
                    //       the NEW fork.
                    //   (b) Re-apply the OLD chain in chronological
                    //       order from the KhaosBlock cache (which
                    //       still owns the bytes — `path_old` holds
                    //       Arc<KhaosBlock> references).
                    // If recovery itself fails, we surface the
                    // original error: the chain is in a known-bad
                    // state and operator intervention is required.
                    error!(
                        ?e,
                        block = kb.num,
                        applied_so_far = applied_new.len(),
                        "new-fork block failed to apply; reverting to original chain"
                    );

                    // (a) Unwind the partial new-fork progress.
                    let mut rollback_errors = Vec::new();
                    for num in applied_new.iter().rev() {
                        if let Err(re) =
                            tron_executor::rollback_block(&self.state, *num, &undo_store)
                        {
                            rollback_errors.push((*num, re.to_string()));
                        }
                    }

                    // (b) Re-apply the old chain from oldest-first.
                    // path_old is newest→oldest; .iter().rev() puts
                    // genesis-most first.
                    let mut reapplied = 0usize;
                    let mut reapply_failed = None;
                    for old_kb in path_old.iter().rev() {
                        let reapply_res = match &self.checkpoint {
                            Some(cp) => {
                                tron_executor::execute_block_with_undo_checkpoint_and_config(
                                    &self.state,
                                    &old_kb.block,
                                    None,
                                    &undo_store,
                                    cp,
                                    &self.exec_config,
                                )
                            }
                            None => tron_executor::execute_block_with_undo_and_config(
                                &self.state,
                                &old_kb.block,
                                None,
                                &undo_store,
                                &self.exec_config,
                            ),
                        };
                        match reapply_res {
                            Ok(_) => reapplied += 1,
                            Err(re) => {
                                reapply_failed =
                                    Some(format!("block {}: {re:?}", old_kb.num));
                                break;
                            }
                        }
                    }

                    if reapply_failed.is_none() && rollback_errors.is_empty() {
                        warn!(
                            failed_block = kb.num,
                            reapplied,
                            "reorg aborted; original chain restored"
                        );
                        return AcceptOutcome::RejectedExecution(format!(
                            "new-fork block {} apply failed: {e:?} \
                             (original chain restored; head unchanged)",
                            kb.num
                        ));
                    } else {
                        // Recovery failed — log loudly. The chain
                        // state is now in a partial state; operator
                        // intervention (restart from snapshot, or
                        // re-sync) is required.
                        error!(
                            ?rollback_errors,
                            ?reapply_failed,
                            "REORG RECOVERY FAILED — chain state is inconsistent; \
                             operator action required"
                        );
                        return AcceptOutcome::RejectedExecution(format!(
                            "new-fork block {} apply failed: {e:?}; \
                             recovery also failed (rollback_errors={:?}, reapply_failed={:?})",
                            kb.num, rollback_errors, reapply_failed
                        ));
                    }
                }
            }
        }

        // Repoint num → id at the new canonical branch (side-fork blocks
        // never indexed themselves).
        self.reindex_canonical_branch(new_path_oldest_first.iter().copied());

        info!(
            old_chain_rolled_back = path_old.len(),
            new_chain_applied = new_path_oldest_first.len(),
            new_head = %hex::encode(&new_block_id.as_bytes()[..8]),
            "REORG: switched canonical chain"
        );
        AcceptOutcome::Accepted(new_block_id)
    }

    /// Read-only view of the in-memory fork tree. Useful for tests +
    /// the `dump-state` snapshot.
    pub fn khaos(&self) -> &Arc<tron_consensus::KhaosDb> {
        &self.khaos
    }

    pub fn stats(&self) -> DriverStats {
        self.stats.clone()
    }
}

/// One pass's outcome — drives the supervisor's next move.
#[derive(Debug)]
enum PeerOutcome {
    /// Peer reported no more blocks — idle and retry. Currently
    /// unused in the inv-driven flow (peers don't signal "caught up"
    /// — the dispatch loop just stays open waiting for new
    /// `BlockInventory`); kept for the SyncBlockChain code path.
    #[allow(dead_code)]
    CaughtUp,
    /// `max_blocks` cap hit.
    CapReached,
    /// Peer dial/handshake/read error — rotate.
    PeerFailure(String),
}

/// Per-block outcome from `accept_block`.
#[derive(Debug)]
pub enum AcceptOutcome {
    /// Applied to state and committed.
    Accepted(BlockId),
    /// KhaosDb dedup hit — we already saw this block. Not an error.
    AlreadyKnown(BlockId),
    /// Block linked into the fork tree on a side branch that's not
    /// the canonical head. Recorded for reorg analysis but NOT
    /// applied to state. Not an error.
    SideFork(BlockId),
    /// Block became the new canonical head via a multi-block jump
    /// (a sibling fork overtook our head). True reorg-with-rollback
    /// is Phase B; we record this as a distinct outcome so the
    /// operator / consumer can spot the divergence. Carries the new
    /// head's number for logging.
    ReorgRequired(BlockId, i64),
    /// Block was on a fork that KhaosDb wanted to promote (longer
    /// than the current head), but the chain back from it does NOT
    /// contain the latest solidified block — promoting it would
    /// silently rewrite finalized history. KhaosDb's head pointer
    /// has been reverted; the block is recorded in the fork tree but
    /// not applied to state. Mirrors java-tron's solidified-containment
    /// guard ("longest chain containing the last solidified block").
    RejectedSolidifiedDiverged(BlockId),
    RejectedValidation(String),
    RejectedExecution(String),
}

/// Log a per-tx mempool submission outcome at the right level. Spam-
/// shaped failures (Duplicate, Expired) go to `debug` so a noisy peer
/// doesn't fill the log; real-shape failures (BadSignature, Decode)
/// go to `debug` too because peer-controlled inputs are not our bug.
/// Successful submits are silent — `TxMempool` already broadcasts and
/// `drain_pending_txs` traces the outbound side.
fn log_inbound_tx_outcome(outcome: &Result<[u8; 32], MempoolError>) {
    match outcome {
        Ok(_) => {}
        Err(e) => debug!(?e, "peer tx rejected by mempool"),
    }
}

/// Drain the mempool broadcast channel and advertise newly-accepted
/// tx hashes to `conn` as one `Inventory{type=TRX, ids=[...]}` frame.
/// Mirrors java-tron's `AdvService.broadcast` → `consumerInvToSpread`
/// → `InventoryMessage` flow: the peer receives just the hashes and
/// pulls the bodies via `FetchInvData` if it doesn't have them.
///
/// Filters against `adv_receive` so we don't echo a hash back to the
/// peer that just told us about it (matches java-tron's
/// `peer.getAdvInvReceive() == null` check). Non-blocking via
/// `try_recv`. Lagged broadcasts are reported and skipped — the
/// next-peer rotation will pick up the dropped notifications via the
/// mempool's pending map.
async fn drain_pending_tx_inventory<S>(
    conn: &mut PeerConnection<S>,
    rx: &mut broadcast::Receiver<[u8; 32]>,
    mempool: &TxMempool,
    adv_receive: &std::collections::HashSet<[u8; 32]>,
) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use prost::Message as _;
    let mut to_advertise: Vec<Vec<u8>> = Vec::new();
    loop {
        match rx.try_recv() {
            Ok(tx_id) => {
                // Skip hashes the peer already told us about — they
                // have it (or they advertised it from someone who did),
                // so re-announcing is wasted bytes.
                if adv_receive.contains(&tx_id) {
                    continue;
                }
                // Only advertise hashes still resident in the mempool;
                // if it was evicted between broadcast and drain (e.g.
                // expiration), the peer would get an ItemNotFound on
                // pull, which is noisy.
                if mempool.get(&tx_id).is_none() {
                    continue;
                }
                to_advertise.push(tx_id.to_vec());
            }
            Err(broadcast::error::TryRecvError::Empty) => break,
            Err(broadcast::error::TryRecvError::Lagged(n)) => {
                warn!(
                    dropped = n,
                    "mempool broadcast channel lagged; some tx adv notifications lost"
                );
                continue;
            }
            Err(broadcast::error::TryRecvError::Closed) => break,
        }
    }
    if to_advertise.is_empty() {
        return Ok(());
    }
    let count = to_advertise.len();
    let payload = tron_proto::Inventory {
        r#type: tron_proto::inventory::InventoryType::Trx as i32,
        ids: to_advertise,
    }
    .encode_to_vec();
    if let Err(e) = conn
        .send_frame(Frame {
            ty: MessageType::Inventory,
            payload: Bytes::from(payload),
        })
        .await
    {
        return Err(format!("send tx Inventory: {e}"));
    }
    debug!(count, "advertised tx hashes");
    Ok(())
}

/// Apply an inbound `Inventory{type=TRX, ids=[...]}` to per-peer state:
///   * Record every well-formed 32-byte hash in `adv_receive` (so we
///     don't echo it back in our outbound advertise drain).
///   * Queue every hash we don't already have in the mempool onto
///     `fetch_queue` for the next `FetchInvData` drain.
///
/// Mirrors java-tron's `AdvService.add(item)` for `InventoryType.TRX`.
/// Malformed (non-32-byte) ids are silently skipped — the connection
/// layer doesn't reject them so neither does this stage.
fn process_tx_inventory_advertise(
    ids: &[Vec<u8>],
    mempool: Option<&TxMempool>,
    adv_receive: &mut std::collections::HashSet<[u8; 32]>,
    adv_receive_order: &mut std::collections::VecDeque<[u8; 32]>,
    fetch_queue: &mut std::collections::VecDeque<[u8; 32]>,
    max_adv_receive: usize,
) {
    for raw in ids {
        if raw.len() != 32 {
            continue;
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(raw);
        fifo_set_insert(adv_receive, adv_receive_order, h, max_adv_receive);
        let already_have = mempool.map(|mp| mp.get(&h).is_some()).unwrap_or(false);
        if !already_have {
            fetch_queue.push_back(h);
        }
    }
}

/// Serve an inbound `FetchInvData` request by looking up each
/// requested id and sending the corresponding body frame.
///   * `type=TRX` → look up in `mempool`; reply with one `Trx` frame
///     per hit. Misses gather into one `ItemNotFound`.
///   * `type=BLOCK` → look up in `blocks` store via `BlockStore`;
///     reply with one `Block` frame per hit. Misses gather into one
///     `ItemNotFound`. Mirrors java-tron's
///     `FetchInvDataMsgHandler.processMessage` block path which reads
///     `blockStore.get(blockId)` and serves the matching capsule.
///
/// Returns the wire-error string on send failure so the caller can
/// drop the peer.
async fn serve_tx_fetch_inv_data<S>(
    conn: &mut PeerConnection<S>,
    payload: Bytes,
    mempool: Option<&TxMempool>,
    blocks: Option<&Arc<dyn KvBackend>>,
) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use prost::Message as _;
    let inv = match tron_proto::Inventory::decode(payload) {
        Ok(i) => i,
        Err(e) => {
            warn!(error = %e, "decode FetchInvData");
            return Ok(());
        }
    };
    let is_trx = inv.r#type == tron_proto::inventory::InventoryType::Trx as i32;
    let is_block = inv.r#type == tron_proto::inventory::InventoryType::Block as i32;
    if !is_trx && !is_block {
        debug!(
            ids = inv.ids.len(),
            ty = inv.r#type,
            "ignoring FetchInvData of unknown inventory type"
        );
        return Ok(());
    }
    let inv_type = inv.r#type;
    let mut not_found: Vec<Vec<u8>> = Vec::new();
    if is_trx {
        let Some(mempool) = mempool else {
            let payload = tron_proto::Inventory {
                r#type: inv_type,
                ids: inv.ids,
            }
            .encode_to_vec();
            if let Err(e) = conn
                .send_frame(Frame {
                    ty: MessageType::ItemNotFound,
                    payload: Bytes::from(payload),
                })
                .await
            {
                return Err(format!("send ItemNotFound: {e}"));
            }
            return Ok(());
        };
        for raw in &inv.ids {
            if raw.len() != 32 {
                not_found.push(raw.clone());
                continue;
            }
            let mut h = [0u8; 32];
            h.copy_from_slice(raw);
            match mempool.get(&h) {
                Some(pending) => {
                    let body = pending.tx.encode_to_vec();
                    if let Err(e) = conn
                        .send_frame(Frame {
                            ty: MessageType::Trx,
                            payload: Bytes::from(body),
                        })
                        .await
                    {
                        return Err(format!("send Trx response: {e}"));
                    }
                }
                None => not_found.push(raw.clone()),
            }
        }
    } else {
        // BLOCK: serve from BlockStore using the BlockId as key.
        let Some(blocks_be) = blocks else {
            let payload = tron_proto::Inventory {
                r#type: inv_type,
                ids: inv.ids,
            }
            .encode_to_vec();
            if let Err(e) = conn
                .send_frame(Frame {
                    ty: MessageType::ItemNotFound,
                    payload: Bytes::from(payload),
                })
                .await
            {
                return Err(format!("send ItemNotFound: {e}"));
            }
            return Ok(());
        };
        let store = BlockStore::new(blocks_be.clone());
        for raw in &inv.ids {
            if raw.len() != 32 {
                not_found.push(raw.clone());
                continue;
            }
            let mut h = [0u8; 32];
            h.copy_from_slice(raw);
            let id = BlockId::from_raw(h);
            match store.get(&id) {
                Ok(block) => {
                    if let Err(e) = conn
                        .send_frame(Frame {
                            ty: MessageType::Block,
                            payload: Bytes::from(block.encode_to_vec()),
                        })
                        .await
                    {
                        return Err(format!("send Block response: {e}"));
                    }
                }
                Err(_) => not_found.push(raw.clone()),
            }
        }
    }
    if !not_found.is_empty() {
        let payload = tron_proto::Inventory {
            r#type: inv_type,
            ids: not_found,
        }
        .encode_to_vec();
        if let Err(e) = conn
            .send_frame(Frame {
                ty: MessageType::ItemNotFound,
                payload: Bytes::from(payload),
            })
            .await
        {
            return Err(format!("send ItemNotFound: {e}"));
        }
    }
    Ok(())
}

/// Drain `queue` of tx hashes to fetch (collected from inbound
/// `Inventory{type=TRX}` frames) into one outbound
/// `FetchInvData{type=TRX, ids=[...]}` frame. Caps per drain at
/// `MAX_TX_FETCH_PER_BATCH` to mirror java-tron's
/// `MAX_TRX_FETCH_PER_PEER`; leftover hashes stay queued for the next
/// outer pass. Returns `Ok(())` when the queue is empty.
async fn drain_tx_fetch_requests<S>(
    conn: &mut PeerConnection<S>,
    queue: &mut std::collections::VecDeque<[u8; 32]>,
) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use prost::Message as _;
    const MAX_TX_FETCH_PER_BATCH: usize = 1000;
    if queue.is_empty() {
        return Ok(());
    }
    let take = queue.len().min(MAX_TX_FETCH_PER_BATCH);
    let mut ids: Vec<Vec<u8>> = Vec::with_capacity(take);
    for _ in 0..take {
        if let Some(h) = queue.pop_front() {
            ids.push(h.to_vec());
        }
    }
    let count = ids.len();
    let payload = tron_proto::Inventory {
        r#type: tron_proto::inventory::InventoryType::Trx as i32,
        ids,
    }
    .encode_to_vec();
    if let Err(e) = conn
        .send_frame(Frame {
            ty: MessageType::FetchInvData,
            payload: Bytes::from(payload),
        })
        .await
    {
        return Err(format!("send FetchInvData frame: {e}"));
    }
    debug!(count, "requested tx bodies via FetchInvData");
    Ok(())
}

/// Forward SR-produced blocks to `conn`. The send shape depends on
/// `is_fast_forward`:
///   * `true`  → full `Block` frame (low-latency direct push, matches
///     java-tron's `RelayService.broadcast` to `fastForwardNodes`).
///   * `false` → `Inventory{type=BLOCK, ids=[block_id]}` advertisement
///     (peer pulls the body via `FetchInvData` if it wants it). This
///     mirrors java-tron's `AdvService.broadcast` fan-out for
///     non-fast-forward peers.
///
/// Treats `Lagged` as a warning; `Closed` as a no-op.
async fn drain_produced_blocks<S>(
    conn: &mut PeerConnection<S>,
    rx: &mut broadcast::Receiver<crate::sr_runtime::ProducedBlockNotice>,
    is_fast_forward: bool,
) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use prost::Message as _;
    loop {
        match rx.try_recv() {
            Ok(notice) => {
                if is_fast_forward {
                    if let Err(e) = conn
                        .send_frame(Frame {
                            ty: MessageType::Block,
                            payload: Bytes::from(notice.encoded),
                        })
                        .await
                    {
                        return Err(format!("send Block frame: {e}"));
                    }
                    debug!(
                        block_num = notice.block_num,
                        hash = %hex::encode(&notice.block_id.as_bytes()[..8]),
                        "force-pushed produced block to fast-forward peer"
                    );
                } else {
                    let inv = tron_proto::Inventory {
                        r#type: tron_proto::inventory::InventoryType::Block as i32,
                        ids: vec![notice.block_id.as_bytes().to_vec()],
                    };
                    if let Err(e) = conn
                        .send_frame(Frame {
                            ty: MessageType::Inventory,
                            payload: Bytes::from(inv.encode_to_vec()),
                        })
                        .await
                    {
                        return Err(format!("send block Inventory: {e}"));
                    }
                    debug!(
                        block_num = notice.block_num,
                        hash = %hex::encode(&notice.block_id.as_bytes()[..8]),
                        "advertised produced block to peer"
                    );
                }
            }
            Err(broadcast::error::TryRecvError::Empty) => return Ok(()),
            Err(broadcast::error::TryRecvError::Lagged(n)) => {
                warn!(
                    dropped = n,
                    "produced-block broadcast channel lagged; some notices skipped"
                );
                continue;
            }
            Err(broadcast::error::TryRecvError::Closed) => return Ok(()),
        }
    }
}

/// Mirror of [`drain_produced_blocks`] for outbound PBFT vote
/// messages. Each msg is encoded as a `MessageType::PbftMsg` frame.
async fn drain_pbft_outbound<S>(
    conn: &mut PeerConnection<S>,
    rx: &mut broadcast::Receiver<tron_proto::PbftMessage>,
) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use prost::Message as _;
    loop {
        match rx.try_recv() {
            Ok(msg) => {
                let payload = msg.encode_to_vec();
                if let Err(e) = conn
                    .send_frame(Frame {
                        ty: MessageType::PbftMsg,
                        payload: Bytes::from(payload),
                    })
                    .await
                {
                    return Err(format!("send PbftMsg frame: {e}"));
                }
                debug!("broadcasted PBFT msg to peer");
            }
            Err(broadcast::error::TryRecvError::Empty) => return Ok(()),
            Err(broadcast::error::TryRecvError::Lagged(n)) => {
                warn!(dropped = n, "PBFT outbound channel lagged");
                continue;
            }
            Err(broadcast::error::TryRecvError::Closed) => return Ok(()),
        }
    }
}

/// Insert `hash` into a bounded FIFO set/queue pair, evicting the
/// oldest entry when the size cap is reached. Used by the peer-loop
/// adv-receive cache so memory stays bounded on long-lived peer
/// connections. Returns `true` when the hash was newly inserted.
fn fifo_set_insert(
    set: &mut std::collections::HashSet<[u8; 32]>,
    order: &mut std::collections::VecDeque<[u8; 32]>,
    hash: [u8; 32],
    cap: usize,
) -> bool {
    if !set.insert(hash) {
        return false;
    }
    order.push_back(hash);
    while order.len() > cap {
        if let Some(stale) = order.pop_front() {
            set.remove(&stale);
        }
    }
    true
}

/// Extract the `owner_address` (first protobuf field, tag=1, wire-type
/// 2 = length-delimited bytes) from an encoded TRON contract parameter
/// blob, returning the hex form of the 21-byte address. Every TRON
/// contract type starts with this field, so a single protobuf-prefix
/// peek covers all of them — cheaper than full-decode dispatch on
/// `ContractType`. Returns the empty string on malformed input.
fn extract_owner_address_hex(any_value: &[u8]) -> String {
    // Tag byte for field=1 wire-type=2 is `(1 << 3) | 2 = 0x0a`.
    if any_value.len() < 2 || any_value[0] != 0x0a {
        return String::new();
    }
    let len = any_value[1] as usize;
    // TRON addresses are always 21 bytes (0x41 prefix + 20-byte hash).
    if len != 21 || any_value.len() < 2 + 21 {
        return String::new();
    }
    hex::encode(&any_value[2..2 + 21])
}

/// Classify a `PeerFailure` reason as *expected* discovery-pool churn —
/// peers that are unreachable, at capacity, or deduping us — rather than a
/// rejection that suggests a problem on OUR side. Expected churn is logged
/// at debug so the steady-state log stays readable; everything else (a
/// protocol/version/message rejection) stays at warn, where a real
/// incompatibility is actually visible.
///
/// Reason strings carry the decoded enum name (e.g. `TOO_MANY_PEERS`), so we
/// match on those rather than raw numbers. The default is "treat as a real
/// rejection" — better to over-warn on an unrecognised reason than hide a
/// genuine "they don't like us" signal.
fn is_expected_peer_failure(reason: &str) -> bool {
    // Never even established a TCP connection — dead / firewalled host.
    reason.starts_with("dial:")
        // Peer accepted TCP but dropped us before/at handshake for its own
        // capacity / policy reasons (their choice, not our bug).
        || reason.contains("connection closed before peer Hello")
        || reason.contains("TOO_MANY_PEERS")          // peer is full
        || reason.contains("DUPLICATE_PEER")          // already connected to our id
        || reason.contains("RANDOM_ELIMINATION")      // peer trimmed its peer set
        || reason.contains("RECENT_DISCONNECT")       // peer's reconnect cooldown
        || reason.contains("DISCOVER_MODE")           // peer is discovery-only
        || reason.contains("TIME_OUT")                // peer-side idle/ping timeout
}

/// Per-peer backoff: `initial × 2^failures`, capped at 5 minutes.
pub fn backoff_for(initial: Duration, failures: u32) -> Duration {
    let f = failures.min(8); // 2^8 = 256× initial
    let scaled = initial.checked_mul(1u32 << f).unwrap_or(initial);
    scaled.min(Duration::from_secs(300))
}

/// Generate a 64-byte pseudo-random node_id.
///
/// java-tron expects this to be the uncompressed-pubkey form (X || Y,
/// no 0x04 prefix). Mainnet peers don't actually verify it for full
/// nodes, so we don't need a real secp256k1 keypair — but they DO
/// dedup by node_id, so reusing the same value across reconnects
/// trips DUPLICATE_PEER until the peer's window expires.
///
/// We seed from `(monotonic_now_ns ^ pid)` and hash through sha256
/// twice to produce 64 bytes. Non-cryptographic but trivially unique
/// across process restarts and reconnect attempts within a process.
/// Whether the block we're about to apply is far enough behind wall-clock
/// that we're in bulk catch-up rather than following the tip. Drives the
/// deferred-fsync fast path in `accept_block`. Uses the same 90s threshold
/// as the progress logger's tip detection.
fn is_catching_up(block: &Block) -> bool {
    const TIP_MS: i64 = 90_000;
    let block_ts = block
        .block_header
        .as_ref()
        .and_then(|h| h.raw_data.as_ref())
        .map(|r| r.timestamp)
        .unwrap_or(0);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    now_ms.saturating_sub(block_ts) > TIP_MS
}

fn random_node_id() -> Vec<u8> {
    use tron_crypto::hash::sha256;
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let pid = std::process::id() as u64;
    let mut seed = [0u8; 16];
    seed[..8].copy_from_slice(&now_ns.to_le_bytes());
    seed[8..].copy_from_slice(&pid.to_le_bytes());
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&sha256(&seed));
    let mut next = [0u8; 32];
    next.copy_from_slice(&out);
    out.extend_from_slice(&sha256(&next));
    out
}

#[cfg(test)]
mod node_id_tests {
    use super::random_node_id;

    #[test]
    fn random_node_id_is_64_bytes() {
        assert_eq!(random_node_id().len(), 64);
    }

    #[test]
    fn random_node_id_differs_between_calls() {
        // Across two calls in the same process the nanosecond clock
        // advances — should produce distinct ids.
        let a = random_node_id();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = random_node_id();
        assert_ne!(a, b);
    }
}

/// Tiny xorshift64 PRNG — used to randomize peer dial order per
/// session. Non-cryptographic; just needs to be deterministic-given-seed
/// and produce a usable spread for shuffle + bounded `next_usize_below`.
///
/// Pulled in instead of the `rand` crate to keep tron-node's
/// dependency surface minimal — peer selection isn't a security
/// boundary.
pub(crate) struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    /// Seed from the system clock + process id. Distinct across
    /// process restarts and across concurrent invocations.
    pub(crate) fn seed_from_clock() -> Self {
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(1);
        let pid = std::process::id() as u64;
        // xorshift requires a non-zero state.
        let seed = (now_ns ^ pid.wrapping_mul(0x9E37_79B9_7F4A_7C15)).max(1);
        Self { state: seed }
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        // Marsaglia's xorshift64 — period 2^64 - 1, good enough for
        // shuffling small peer lists.
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    /// Uniform-ish integer in `[0, bound)`. Uses simple modulo, which
    /// has a tiny bias for non-power-of-2 bounds; acceptable here.
    pub(crate) fn next_usize_below(&mut self, bound: usize) -> usize {
        if bound <= 1 {
            return 0;
        }
        (self.next_u64() as usize) % bound
    }

    /// In-place Fisher–Yates shuffle.
    pub(crate) fn shuffle<T>(&mut self, slice: &mut [T]) {
        for i in (1..slice.len()).rev() {
            let j = self.next_usize_below(i + 1);
            slice.swap(i, j);
        }
    }
}

#[cfg(test)]
mod xorshift_tests {
    use super::XorShift64;

    #[test]
    fn shuffle_preserves_set() {
        let mut rng = XorShift64::seed_from_clock();
        let mut v: Vec<usize> = (0..16).collect();
        rng.shuffle(&mut v);
        let mut sorted = v.clone();
        sorted.sort();
        assert_eq!(sorted, (0..16).collect::<Vec<_>>());
    }

    #[test]
    fn shuffle_actually_reorders_eventually() {
        // It's possible (1/16!) that a shuffle produces the identity,
        // but exceedingly unlikely. Run a few seeds; at least one
        // must reorder.
        let mut any_changed = false;
        for s in 1u64..16 {
            let mut rng = XorShift64 { state: s };
            let mut v: Vec<usize> = (0..16).collect();
            rng.shuffle(&mut v);
            if v != (0..16).collect::<Vec<_>>() {
                any_changed = true;
                break;
            }
        }
        assert!(any_changed, "16 shuffles all returned identity ordering");
    }

    #[test]
    fn next_usize_below_is_bounded() {
        let mut rng = XorShift64 { state: 0x1234_5678 };
        for _ in 0..1000 {
            assert!(rng.next_usize_below(7) < 7);
            assert_eq!(rng.next_usize_below(1), 0);
            assert_eq!(rng.next_usize_below(0), 0);
        }
    }
}

#[cfg(test)]
mod trx_inventory_tests {
    //! Coverage for the java-tron pull-based tx propagation cycle:
    //!   1. Outbound advertise: `drain_pending_tx_inventory` turns
    //!      mempool broadcasts into `Inventory{type=TRX}` frames.
    //!   2. Adv-receive filter: hashes the peer already told us about
    //!      are not re-advertised back.
    //!   3. Outbound fetch: `drain_tx_fetch_requests` packs queued
    //!      hashes into `FetchInvData{type=TRX}` frames with bounded
    //!      batch size.
    //!   4. fifo_set_insert keeps the per-peer adv-receive cache
    //!      bounded.
    //!
    //! Plus an end-to-end duplex test where a synthetic peer drives
    //! the full pull-based handshake: peer advertises a tx hash, our
    //! node requests it via `FetchInvData`, peer sends the body, our
    //! mempool ingests it.
    //!
    //! Inbound `FetchInvData` serving (a peer asks us for tx bodies)
    //! is covered by the duplex test in
    //! `tests/trx_inventory_serve.rs` since it requires running the
    //! full peer loop.
    use super::*;
    use std::collections::{HashSet, VecDeque};
    use tokio::io::duplex;
    use tron_mempool::{MempoolConfig, TxMempool};
    use tron_net::PeerConnection;

    /// `keccak256("Transfer")` first 32 bytes — just a recognisable
    /// pattern for test hashes.
    fn h(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn build_signed_transfer_bytes(seed: u8) -> Vec<u8> {
        use tron_proto::transaction::{contract::ContractType, Contract, Raw};
        use tron_proto::{Transaction, TransferContract};
        let mut owner = [0u8; 21];
        owner[0] = 0x41;
        owner[1..].fill(seed);
        let mut to = [0u8; 21];
        to[0] = 0x41;
        to[1..].fill(seed.wrapping_add(1));
        let tc = TransferContract {
            owner_address: owner.to_vec(),
            to_address: to.to_vec(),
            amount: 100,
        };
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let mut tx = Transaction {
            raw_data: Some(Raw {
                contract: vec![Contract {
                    r#type: ContractType::TransferContract as i32,
                    parameter: Some(prost_types::Any {
                        type_url: "type.googleapis.com/protocol.TransferContract".into(),
                        value: tc.encode_to_vec(),
                    }),
                    ..Default::default()
                }],
                expiration: now_ms + 60_000,
                timestamp: now_ms,
                ..Default::default()
            }),
            signature: vec![],
            ret: vec![],
        };
        let priv_key = {
            let mut k = [0u8; 32];
            k[0] = 0x10;
            k[31] = seed;
            k
        };
        tron_types::sign_transaction(&mut tx, &priv_key).unwrap();
        tx.encode_to_vec()
    }

    #[test]
    fn fifo_set_insert_returns_true_on_first_insert_and_evicts_oldest() {
        let mut set: HashSet<[u8; 32]> = HashSet::new();
        let mut order: VecDeque<[u8; 32]> = VecDeque::new();
        assert!(fifo_set_insert(&mut set, &mut order, h(1), 3));
        assert!(fifo_set_insert(&mut set, &mut order, h(2), 3));
        assert!(fifo_set_insert(&mut set, &mut order, h(3), 3));
        // Re-insert is a no-op (already present, return false).
        assert!(!fifo_set_insert(&mut set, &mut order, h(2), 3));
        assert_eq!(set.len(), 3);
        // Inserting a 4th evicts the oldest entry (h(1)).
        assert!(fifo_set_insert(&mut set, &mut order, h(4), 3));
        assert!(!set.contains(&h(1)));
        assert!(set.contains(&h(2)));
        assert!(set.contains(&h(3)));
        assert!(set.contains(&h(4)));
        assert_eq!(set.len(), 3);
    }

    #[tokio::test]
    async fn drain_pending_tx_inventory_advertises_recent_mempool_submissions() {
        let mempool = TxMempool::new(MempoolConfig::default());
        let mut rx = mempool.subscribe();
        let id1 = mempool.submit(&build_signed_transfer_bytes(1)).unwrap();
        let id2 = mempool.submit(&build_signed_transfer_bytes(2)).unwrap();
        // Empty adv-receive: both hashes go on the wire.
        let adv_receive: HashSet<[u8; 32]> = HashSet::new();

        let (a_s, b_s) = duplex(64 * 1024);
        let mut us = PeerConnection::new(a_s);
        let mut peer = PeerConnection::new(b_s);

        drain_pending_tx_inventory(&mut us, &mut rx, &mempool, &adv_receive)
            .await
            .expect("drain ok");

        let frame = peer.next_frame().await.unwrap().expect("frame");
        assert_eq!(frame.ty, MessageType::Inventory);
        let inv = tron_proto::Inventory::decode(frame.payload).unwrap();
        assert_eq!(inv.r#type, tron_proto::inventory::InventoryType::Trx as i32);
        assert_eq!(inv.ids.len(), 2);
        let ids: HashSet<_> = inv.ids.iter().map(|v| v.as_slice().to_vec()).collect();
        assert!(ids.contains(&id1.to_vec()));
        assert!(ids.contains(&id2.to_vec()));
    }

    #[tokio::test]
    async fn drain_skips_hashes_already_advertised_by_the_peer() {
        let mempool = TxMempool::new(MempoolConfig::default());
        let mut rx = mempool.subscribe();
        let id1 = mempool.submit(&build_signed_transfer_bytes(11)).unwrap();
        let id2 = mempool.submit(&build_signed_transfer_bytes(12)).unwrap();

        // Pretend the peer advertised id1 to us → exclude from adv.
        let mut adv_receive: HashSet<[u8; 32]> = HashSet::new();
        adv_receive.insert(id1);

        let (a_s, b_s) = duplex(64 * 1024);
        let mut us = PeerConnection::new(a_s);
        let mut peer = PeerConnection::new(b_s);

        drain_pending_tx_inventory(&mut us, &mut rx, &mempool, &adv_receive)
            .await
            .expect("drain ok");

        let frame = peer.next_frame().await.unwrap().expect("frame");
        assert_eq!(frame.ty, MessageType::Inventory);
        let inv = tron_proto::Inventory::decode(frame.payload).unwrap();
        assert_eq!(inv.ids.len(), 1, "id1 must be filtered out");
        assert_eq!(inv.ids[0], id2.to_vec());
    }

    #[tokio::test]
    async fn drain_with_empty_channel_sends_no_frame() {
        let mempool = TxMempool::new(MempoolConfig::default());
        let mut rx = mempool.subscribe();
        let adv_receive: HashSet<[u8; 32]> = HashSet::new();

        let (a_s, b_s) = duplex(64 * 1024);
        let mut us = PeerConnection::new(a_s);
        let mut peer = PeerConnection::new(b_s);

        drain_pending_tx_inventory(&mut us, &mut rx, &mempool, &adv_receive)
            .await
            .expect("drain ok");

        // Nothing was sent — close our side; peer's next_frame returns None.
        drop(us);
        let f = peer.next_frame().await;
        assert!(
            matches!(f, Ok(None) | Err(_)),
            "no frame should have been written"
        );
    }

    #[tokio::test]
    async fn drain_skips_hash_when_tx_evicted_between_broadcast_and_drain() {
        let mempool = TxMempool::new(MempoolConfig::default());
        let mut rx = mempool.subscribe();
        let id = mempool.submit(&build_signed_transfer_bytes(20)).unwrap();
        // Drop the tx before draining — simulates expiration / removal.
        mempool.remove(&id);
        let adv_receive: HashSet<[u8; 32]> = HashSet::new();

        let (a_s, b_s) = duplex(64 * 1024);
        let mut us = PeerConnection::new(a_s);
        let mut peer = PeerConnection::new(b_s);

        drain_pending_tx_inventory(&mut us, &mut rx, &mempool, &adv_receive)
            .await
            .expect("drain ok");
        drop(us);
        let f = peer.next_frame().await;
        assert!(
            matches!(f, Ok(None) | Err(_)),
            "evicted tx must not be advertised"
        );
    }

    #[tokio::test]
    async fn drain_tx_fetch_requests_packs_queue_into_one_fetchinvdata() {
        let mut queue: VecDeque<[u8; 32]> = VecDeque::new();
        queue.push_back(h(1));
        queue.push_back(h(2));
        queue.push_back(h(3));

        let (a_s, b_s) = duplex(64 * 1024);
        let mut us = PeerConnection::new(a_s);
        let mut peer = PeerConnection::new(b_s);

        drain_tx_fetch_requests(&mut us, &mut queue)
            .await
            .expect("ok");

        let frame = peer.next_frame().await.unwrap().expect("frame");
        assert_eq!(frame.ty, MessageType::FetchInvData);
        let inv = tron_proto::Inventory::decode(frame.payload).unwrap();
        assert_eq!(inv.r#type, tron_proto::inventory::InventoryType::Trx as i32);
        assert_eq!(inv.ids.len(), 3);
        assert!(queue.is_empty());
    }

    #[tokio::test]
    async fn drain_tx_fetch_requests_caps_at_max_per_batch() {
        let mut queue: VecDeque<[u8; 32]> = VecDeque::new();
        // 1500 distinct hashes; cap is 1000.
        for i in 0..1500u32 {
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(&i.to_be_bytes());
            queue.push_back(b);
        }
        let (a_s, b_s) = duplex(128 * 1024);
        let mut us = PeerConnection::new(a_s);
        let mut peer = PeerConnection::new(b_s);

        drain_tx_fetch_requests(&mut us, &mut queue)
            .await
            .expect("ok");

        let frame = peer.next_frame().await.unwrap().expect("frame");
        assert_eq!(frame.ty, MessageType::FetchInvData);
        let inv = tron_proto::Inventory::decode(frame.payload).unwrap();
        assert_eq!(inv.ids.len(), 1000, "must cap one batch at 1000 hashes");
        assert_eq!(queue.len(), 500, "remainder stays queued");
    }

    #[tokio::test]
    async fn drain_tx_fetch_requests_empty_queue_is_noop() {
        let mut queue: VecDeque<[u8; 32]> = VecDeque::new();
        let (a_s, b_s) = duplex(64 * 1024);
        let mut us = PeerConnection::new(a_s);
        let mut peer = PeerConnection::new(b_s);

        drain_tx_fetch_requests(&mut us, &mut queue)
            .await
            .expect("ok");
        drop(us);
        let f = peer.next_frame().await;
        assert!(matches!(f, Ok(None) | Err(_)), "no frame sent on empty queue");
    }

    // ────────────────────────────────────────────────────────────
    // serve_tx_fetch_inv_data — inbound fetch handler
    // ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn serve_responds_with_trx_for_each_known_hash() {
        use prost::Message as _;
        let mempool = TxMempool::new(MempoolConfig::default());
        let id1 = mempool.submit(&build_signed_transfer_bytes(31)).unwrap();
        let id2 = mempool.submit(&build_signed_transfer_bytes(32)).unwrap();

        let req = tron_proto::Inventory {
            r#type: tron_proto::inventory::InventoryType::Trx as i32,
            ids: vec![id1.to_vec(), id2.to_vec()],
        };

        let (a_s, b_s) = duplex(64 * 1024);
        let mut us = PeerConnection::new(a_s);
        let mut peer = PeerConnection::new(b_s);

        serve_tx_fetch_inv_data(
            &mut us,
            Bytes::from(req.encode_to_vec()),
            Some(&mempool),
            None,
        )
        .await
        .expect("serve ok");

        // Expect two Trx frames back, in request order.
        for &expected_id in &[id1, id2] {
            let frame = peer.next_frame().await.unwrap().expect("frame");
            assert_eq!(frame.ty, MessageType::Trx);
            let tx = tron_proto::Transaction::decode(frame.payload).unwrap();
            let raw = tx.raw_data.unwrap().encode_to_vec();
            let id = tron_crypto::hash::sha256(&raw);
            assert_eq!(id, expected_id, "Trx body must match requested hash");
        }
    }

    #[tokio::test]
    async fn serve_responds_with_item_not_found_for_unknown_hash() {
        use prost::Message as _;
        let mempool = TxMempool::new(MempoolConfig::default());
        let known = mempool.submit(&build_signed_transfer_bytes(41)).unwrap();
        let unknown = h(0xff);

        let req = tron_proto::Inventory {
            r#type: tron_proto::inventory::InventoryType::Trx as i32,
            ids: vec![known.to_vec(), unknown.to_vec()],
        };

        let (a_s, b_s) = duplex(64 * 1024);
        let mut us = PeerConnection::new(a_s);
        let mut peer = PeerConnection::new(b_s);

        serve_tx_fetch_inv_data(
            &mut us,
            Bytes::from(req.encode_to_vec()),
            Some(&mempool),
            None,
        )
        .await
        .expect("serve ok");

        // First: Trx for known.
        let f1 = peer.next_frame().await.unwrap().expect("frame");
        assert_eq!(f1.ty, MessageType::Trx);
        // Then: ItemNotFound for unknown.
        let f2 = peer.next_frame().await.unwrap().expect("frame");
        assert_eq!(f2.ty, MessageType::ItemNotFound);
        let inv = tron_proto::Inventory::decode(f2.payload).unwrap();
        assert_eq!(inv.r#type, tron_proto::inventory::InventoryType::Trx as i32);
        assert_eq!(inv.ids.len(), 1);
        assert_eq!(inv.ids[0], unknown.to_vec());
    }

    #[tokio::test]
    async fn serve_block_request_returns_block_frame_when_in_blocks_store() {
        use prost::Message as _;
        use tron_chainbase::{BlockStore as BS, KvBackend as KB, MemBackend};
        use tron_proto::{block_header::Raw as Hdr, Block, BlockHeader};
        use tron_types::block_id_from_block;
        let backend: Arc<dyn KB> = Arc::new(MemBackend::new());
        let store = BS::new(backend.clone());
        let block = Block {
            block_header: Some(BlockHeader {
                raw_data: Some(Hdr {
                    number: 42,
                    parent_hash: vec![0u8; 32],
                    timestamp: 1_700_000_000_000,
                    tx_trie_root: vec![],
                    ..Default::default()
                }),
                witness_signature: vec![],
            }),
            transactions: vec![],
        };
        let id = block_id_from_block(&block).expect("id");
        store.put(&id, &block).unwrap();

        let req = tron_proto::Inventory {
            r#type: tron_proto::inventory::InventoryType::Block as i32,
            ids: vec![id.as_bytes().to_vec()],
        };
        let (a_s, b_s) = duplex(64 * 1024);
        let mut us = PeerConnection::new(a_s);
        let mut peer = PeerConnection::new(b_s);

        serve_tx_fetch_inv_data(
            &mut us,
            Bytes::from(req.encode_to_vec()),
            None,
            Some(&backend),
        )
        .await
        .expect("serve ok");

        let frame = peer.next_frame().await.unwrap().expect("frame");
        assert_eq!(frame.ty, MessageType::Block);
        let decoded = Block::decode(frame.payload).unwrap();
        let decoded_id = block_id_from_block(&decoded).unwrap();
        assert_eq!(decoded_id, id);
    }

    #[tokio::test]
    async fn serve_block_request_misses_emit_item_not_found_with_block_type() {
        use prost::Message as _;
        use tron_chainbase::{KvBackend as KB, MemBackend};
        let backend: Arc<dyn KB> = Arc::new(MemBackend::new());
        let unknown = h(0xaa);
        let req = tron_proto::Inventory {
            r#type: tron_proto::inventory::InventoryType::Block as i32,
            ids: vec![unknown.to_vec()],
        };
        let (a_s, b_s) = duplex(64 * 1024);
        let mut us = PeerConnection::new(a_s);
        let mut peer = PeerConnection::new(b_s);

        serve_tx_fetch_inv_data(
            &mut us,
            Bytes::from(req.encode_to_vec()),
            None,
            Some(&backend),
        )
        .await
        .expect("serve ok");

        let frame = peer.next_frame().await.unwrap().expect("frame");
        assert_eq!(frame.ty, MessageType::ItemNotFound);
        let inv = tron_proto::Inventory::decode(frame.payload).unwrap();
        assert_eq!(
            inv.r#type,
            tron_proto::inventory::InventoryType::Block as i32
        );
        assert_eq!(inv.ids[0], unknown.to_vec());
    }

    #[tokio::test]
    async fn drain_produced_blocks_advertises_to_non_fast_forward_peer() {
        use prost::Message as _;
        use tokio::sync::broadcast as bc;
        use tron_types::BlockId;
        let (tx, mut rx) = bc::channel::<crate::sr_runtime::ProducedBlockNotice>(8);
        // Hand-roll a notice (we don't need a real produced block).
        let mut id_raw = [0u8; 32];
        id_raw[0..8].copy_from_slice(&42u64.to_be_bytes());
        id_raw[8..].fill(0xab);
        let notice = crate::sr_runtime::ProducedBlockNotice {
            block_id: BlockId::from_raw(id_raw),
            block_num: 42,
            encoded: vec![0u8; 16], // arbitrary bytes; non-FF path doesn't send this
        };
        let _ = tx.send(notice);

        let (a_s, b_s) = duplex(64 * 1024);
        let mut us = PeerConnection::new(a_s);
        let mut peer = PeerConnection::new(b_s);

        drain_produced_blocks(&mut us, &mut rx, false)
            .await
            .expect("drain ok");

        // Non-FF peer must get an Inventory(BLOCK) advertisement, NOT a
        // Block frame.
        let frame = peer.next_frame().await.unwrap().expect("frame");
        assert_eq!(frame.ty, MessageType::Inventory);
        let inv = tron_proto::Inventory::decode(frame.payload).unwrap();
        assert_eq!(
            inv.r#type,
            tron_proto::inventory::InventoryType::Block as i32
        );
        assert_eq!(inv.ids.len(), 1);
        assert_eq!(inv.ids[0], id_raw.to_vec());
    }

    #[tokio::test]
    async fn drain_produced_blocks_pushes_full_block_to_fast_forward_peer() {
        use tokio::sync::broadcast as bc;
        use tron_types::BlockId;
        let (tx, mut rx) = bc::channel::<crate::sr_runtime::ProducedBlockNotice>(8);
        let mut id_raw = [0u8; 32];
        id_raw[0..8].copy_from_slice(&42u64.to_be_bytes());
        id_raw[8..].fill(0xcd);
        let payload_bytes = vec![1u8, 2, 3, 4, 5];
        let notice = crate::sr_runtime::ProducedBlockNotice {
            block_id: BlockId::from_raw(id_raw),
            block_num: 42,
            encoded: payload_bytes.clone(),
        };
        let _ = tx.send(notice);

        let (a_s, b_s) = duplex(64 * 1024);
        let mut us = PeerConnection::new(a_s);
        let mut peer = PeerConnection::new(b_s);

        drain_produced_blocks(&mut us, &mut rx, true)
            .await
            .expect("drain ok");

        // FF peer gets the full Block frame with the pre-encoded
        // bytes verbatim.
        let frame = peer.next_frame().await.unwrap().expect("frame");
        assert_eq!(frame.ty, MessageType::Block);
        assert_eq!(frame.payload.as_ref(), payload_bytes.as_slice());
    }

    #[tokio::test]
    async fn serve_block_request_without_blocks_store_returns_item_not_found() {
        use prost::Message as _;
        let mempool = TxMempool::new(MempoolConfig::default());
        let req = tron_proto::Inventory {
            r#type: tron_proto::inventory::InventoryType::Block as i32,
            ids: vec![h(1).to_vec(), h(2).to_vec()],
        };

        let (a_s, b_s) = duplex(64 * 1024);
        let mut us = PeerConnection::new(a_s);
        let mut peer = PeerConnection::new(b_s);

        // BLOCK request, no blocks backend attached → ItemNotFound
        // echoing all requested ids.
        serve_tx_fetch_inv_data(
            &mut us,
            Bytes::from(req.encode_to_vec()),
            Some(&mempool),
            None,
        )
        .await
        .expect("serve ok");

        let frame = peer.next_frame().await.unwrap().expect("frame");
        assert_eq!(frame.ty, MessageType::ItemNotFound);
        let inv = tron_proto::Inventory::decode(frame.payload).unwrap();
        assert_eq!(
            inv.r#type,
            tron_proto::inventory::InventoryType::Block as i32
        );
        assert_eq!(inv.ids.len(), 2);
    }

    #[tokio::test]
    async fn serve_responds_with_item_not_found_when_no_mempool_attached() {
        use prost::Message as _;
        let req = tron_proto::Inventory {
            r#type: tron_proto::inventory::InventoryType::Trx as i32,
            ids: vec![h(1).to_vec(), h(2).to_vec()],
        };

        let (a_s, b_s) = duplex(64 * 1024);
        let mut us = PeerConnection::new(a_s);
        let mut peer = PeerConnection::new(b_s);

        serve_tx_fetch_inv_data(&mut us, Bytes::from(req.encode_to_vec()), None, None)
            .await
            .expect("serve ok");

        let frame = peer.next_frame().await.unwrap().expect("frame");
        assert_eq!(frame.ty, MessageType::ItemNotFound);
        let inv = tron_proto::Inventory::decode(frame.payload).unwrap();
        assert_eq!(inv.ids.len(), 2, "all requested ids must be echoed back");
    }

    #[tokio::test]
    async fn serve_treats_malformed_short_hash_as_not_found() {
        use prost::Message as _;
        let mempool = TxMempool::new(MempoolConfig::default());
        let req = tron_proto::Inventory {
            r#type: tron_proto::inventory::InventoryType::Trx as i32,
            ids: vec![vec![0xaa; 8]], // 8 bytes, not 32
        };

        let (a_s, b_s) = duplex(64 * 1024);
        let mut us = PeerConnection::new(a_s);
        let mut peer = PeerConnection::new(b_s);

        serve_tx_fetch_inv_data(
            &mut us,
            Bytes::from(req.encode_to_vec()),
            Some(&mempool),
            None,
        )
        .await
        .expect("serve ok");

        let frame = peer.next_frame().await.unwrap().expect("frame");
        assert_eq!(frame.ty, MessageType::ItemNotFound);
    }

    // ────────────────────────────────────────────────────────────
    // process_tx_inventory_advertise — inbound advertise handler
    // ────────────────────────────────────────────────────────────

    #[test]
    fn advertise_queues_unknown_hashes_and_records_adv_receive() {
        let mempool = TxMempool::new(MempoolConfig::default());
        let known_id = mempool.submit(&build_signed_transfer_bytes(51)).unwrap();
        let unknown_a = h(0x77);
        let unknown_b = h(0x88);

        let ids = vec![known_id.to_vec(), unknown_a.to_vec(), unknown_b.to_vec()];
        let mut adv_receive: HashSet<[u8; 32]> = HashSet::new();
        let mut adv_receive_order: VecDeque<[u8; 32]> = VecDeque::new();
        let mut fetch_queue: VecDeque<[u8; 32]> = VecDeque::new();

        process_tx_inventory_advertise(
            &ids,
            Some(&mempool),
            &mut adv_receive,
            &mut adv_receive_order,
            &mut fetch_queue,
            1_000,
        );

        // All 3 hashes recorded in adv-receive (so we don't echo any back).
        assert_eq!(adv_receive.len(), 3);
        assert!(adv_receive.contains(&known_id));
        assert!(adv_receive.contains(&unknown_a));
        assert!(adv_receive.contains(&unknown_b));
        // Only the two unknown hashes queued for fetch.
        assert_eq!(fetch_queue.len(), 2);
        let queued: HashSet<_> = fetch_queue.iter().copied().collect();
        assert!(queued.contains(&unknown_a));
        assert!(queued.contains(&unknown_b));
        assert!(!queued.contains(&known_id));
    }

    #[test]
    fn advertise_drops_malformed_short_hash() {
        let mempool = TxMempool::new(MempoolConfig::default());
        let ids = vec![vec![0xaa; 4], h(0x42).to_vec()]; // first is 4-byte garbage

        let mut adv_receive: HashSet<[u8; 32]> = HashSet::new();
        let mut adv_receive_order: VecDeque<[u8; 32]> = VecDeque::new();
        let mut fetch_queue: VecDeque<[u8; 32]> = VecDeque::new();

        process_tx_inventory_advertise(
            &ids,
            Some(&mempool),
            &mut adv_receive,
            &mut adv_receive_order,
            &mut fetch_queue,
            1_000,
        );
        assert_eq!(adv_receive.len(), 1);
        assert!(adv_receive.contains(&h(0x42)));
        assert_eq!(fetch_queue.len(), 1);
        assert_eq!(fetch_queue.front(), Some(&h(0x42)));
    }

    #[test]
    fn advertise_without_mempool_queues_every_well_formed_hash() {
        let ids = vec![h(0xaa).to_vec(), h(0xbb).to_vec()];
        let mut adv_receive: HashSet<[u8; 32]> = HashSet::new();
        let mut adv_receive_order: VecDeque<[u8; 32]> = VecDeque::new();
        let mut fetch_queue: VecDeque<[u8; 32]> = VecDeque::new();

        process_tx_inventory_advertise(
            &ids,
            None,
            &mut adv_receive,
            &mut adv_receive_order,
            &mut fetch_queue,
            1_000,
        );
        assert_eq!(adv_receive.len(), 2);
        assert_eq!(fetch_queue.len(), 2);
    }

    #[test]
    fn advertise_respects_adv_receive_cap_with_fifo_eviction() {
        // Cap 3; advertise 5 hashes → only last 3 retained in adv-receive.
        let ids: Vec<Vec<u8>> = (0..5u8).map(|i| h(i).to_vec()).collect();
        let mut adv_receive: HashSet<[u8; 32]> = HashSet::new();
        let mut adv_receive_order: VecDeque<[u8; 32]> = VecDeque::new();
        let mut fetch_queue: VecDeque<[u8; 32]> = VecDeque::new();

        process_tx_inventory_advertise(
            &ids,
            None,
            &mut adv_receive,
            &mut adv_receive_order,
            &mut fetch_queue,
            3,
        );
        assert_eq!(adv_receive.len(), 3);
        // The oldest two should be evicted; newest three retained.
        assert!(adv_receive.contains(&h(2)));
        assert!(adv_receive.contains(&h(3)));
        assert!(adv_receive.contains(&h(4)));
        assert!(!adv_receive.contains(&h(0)));
        assert!(!adv_receive.contains(&h(1)));
        // Fetch queue receives ALL ids regardless of adv-receive cap.
        assert_eq!(fetch_queue.len(), 5);
    }

    #[tokio::test]
    async fn serve_with_empty_payload_is_noop() {
        use prost::Message as _;
        let mempool = TxMempool::new(MempoolConfig::default());
        let req = tron_proto::Inventory {
            r#type: tron_proto::inventory::InventoryType::Trx as i32,
            ids: vec![],
        };

        let (a_s, b_s) = duplex(64 * 1024);
        let mut us = PeerConnection::new(a_s);
        let mut peer = PeerConnection::new(b_s);

        serve_tx_fetch_inv_data(
            &mut us,
            Bytes::from(req.encode_to_vec()),
            Some(&mempool),
            None,
        )
        .await
        .expect("serve ok");
        drop(us);
        let f = peer.next_frame().await;
        assert!(
            matches!(f, Ok(None) | Err(_)),
            "empty id list → no Trx or ItemNotFound frame"
        );
    }
}

#[cfg(test)]
mod solidify_tests {
    //! DPoS solidified-block advancement during sync
    //! (`SyncDriver::update_solidified`). The consensus math itself lives
    //! in `tron_consensus::latest_solid_block`; here we pin the wiring:
    //! the rolling window advances `LATEST_SOLIDIFIED_BLOCK_NUM` to
    //! head − (threshold − 1) once enough distinct witnesses are seen,
    //! never moves it backward, and stays put when it can't size the
    //! threshold.

    use super::*;
    use tron_chainbase::MemBackend;
    use tron_crypto::address::Address;
    use tron_proto::block_header::Raw as BlockHeaderRaw;
    use tron_proto::BlockHeader;

    fn mem() -> Arc<dyn KvBackend> {
        Arc::new(MemBackend::new())
    }

    fn mem_state() -> StateBackends {
        StateBackends {
            accounts: mem(),
            witnesses: mem(),
            votes: mem(),
            delegation: mem(),
            delegated_resources: mem(),
            delegated_resource_account_index: None,
            dyn_props: mem(),
            proposals: mem(),
            name_index: mem(),
            id_index: mem(),
            asset_v1: mem(),
            asset_v2: mem(),
            contracts: mem(),
            abi: mem(),
            exchange_v1: mem(),
            exchange_v2: mem(),
            market_orders: mem(),
            nullifiers: mem(),
            merkle_trees: None,
            code: Some(mem()),
            storage_row: Some(mem()),
            contract_state: Some(mem()),
            block_index: Some(mem()),
            witness_schedule: Some(mem()),
        }
    }

    fn driver_with(state: StateBackends, blocks_be: Arc<dyn KvBackend>) -> SyncDriver {
        let cfg = SyncConfig {
            peers: vec![],
            max_blocks: None,
            tail_interval: Duration::from_millis(1),
            initial_backoff: Duration::from_millis(1),
            blocks_backend: blocks_be,
            progress_log_interval: 0,
            advertise_port: 18_888,
            tip_test: false,
            p2p_rate_limits: Default::default(),
            fetch_block_timeout: Duration::from_millis(200),
            peer_is_fast_forward: false,
        };
        SyncDriver::new(state, cfg)
    }

    fn witness(i: usize) -> [u8; 21] {
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[1] = (i >> 8) as u8;
        a[2] = i as u8;
        a
    }

    fn block_by(num: i64, witness_addr: &[u8; 21]) -> Block {
        Block {
            transactions: Vec::new(),
            block_header: Some(BlockHeader {
                raw_data: Some(BlockHeaderRaw {
                    number: num,
                    witness_address: witness_addr.to_vec(),
                    ..Default::default()
                }),
                witness_signature: Vec::new(),
            }),
        }
    }

    /// Seed `n` distinct active witnesses into the schedule store.
    fn seed_witnesses(state: &StateBackends, n: usize) {
        let ws = WitnessScheduleStore::new(state.witness_schedule.clone().unwrap());
        let list: Vec<Address> = (0..n).map(|i| Address::from_raw(witness(i))).collect();
        ws.save_active(&list).unwrap();
    }

    #[test]
    fn solid_advances_to_head_minus_threshold_over_a_rotation() {
        const N: usize = 27; // mainnet active witness count
        let state = mem_state();
        seed_witnesses(&state, N);
        let mut driver = driver_with(state.clone(), mem());
        let dp = DynamicPropertiesStore::new(state.dyn_props.clone());

        let threshold = tron_consensus::solidity_threshold(N) as i64;
        assert!(threshold > 1);

        // Feed a clean rotation: block `num` is produced by witness
        // `(num-1) % N`, so the newest `threshold` blocks always hold
        // `threshold` distinct witnesses.
        for num in 1..=40i64 {
            let w = witness(((num - 1) as usize) % N);
            driver.update_solidified(&block_by(num, &w), num);

            let solid = dp.latest_solidified_block_num().unwrap_or(0);
            let expected = if num < threshold { 0 } else { num - threshold + 1 };
            assert_eq!(
                solid, expected,
                "after block {num}: solid={solid}, expected={expected} (threshold={threshold})"
            );
        }
    }

    #[test]
    fn solid_holds_until_threshold_distinct_witnesses_seen() {
        const N: usize = 27;
        let state = mem_state();
        seed_witnesses(&state, N);
        let mut driver = driver_with(state.clone(), mem());
        let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
        let threshold = tron_consensus::solidity_threshold(N) as i64;

        // Feed threshold-1 blocks from DISTINCT witnesses — not enough.
        for num in 1..threshold {
            let w = witness((num - 1) as usize);
            driver.update_solidified(&block_by(num, &w), num);
            assert_eq!(dp.latest_solidified_block_num().unwrap_or(0), 0);
        }
        // The threshold-th distinct witness tips it over → solid = 1.
        let w = witness((threshold - 1) as usize);
        driver.update_solidified(&block_by(threshold, &w), threshold);
        assert_eq!(dp.latest_solidified_block_num().unwrap_or(0), 1);
    }

    #[test]
    fn solid_never_regresses() {
        const N: usize = 27;
        let state = mem_state();
        seed_witnesses(&state, N);
        let mut driver = driver_with(state.clone(), mem());
        let dp = DynamicPropertiesStore::new(state.dyn_props.clone());

        // A higher solid is already on disk (e.g. from PBFT finality).
        dp.save_latest_solidified_block_num(1000);

        // Feed a rotation that computes a much lower DPoS solid (~head-18).
        for num in 1..=40i64 {
            let w = witness(((num - 1) as usize) % N);
            driver.update_solidified(&block_by(num, &w), num);
            assert_eq!(
                dp.latest_solidified_block_num().unwrap_or(0),
                1000,
                "solid must never move backward"
            );
        }
    }

    #[test]
    fn solid_unchanged_without_an_active_witness_list() {
        // No active list seeded → can't size the ⌈2/3⌉ threshold → leave
        // the pointer untouched rather than guess.
        let state = mem_state();
        let mut driver = driver_with(state.clone(), mem());
        let dp = DynamicPropertiesStore::new(state.dyn_props.clone());

        for num in 1..=40i64 {
            let w = witness((num as usize) % 27);
            driver.update_solidified(&block_by(num, &w), num);
            assert_eq!(dp.latest_solidified_block_num(), None);
        }
    }

    #[test]
    fn seed_from_disk_recovers_a_stuck_node() {
        // Reproduces the deadlock: a node synced by a pre-M-18 binary has a
        // full block chain on disk but a frozen solid pointer. Startup must
        // recompute solid from the on-disk blocks, or the head-promotion
        // gate rejects the next block forever (apply gated on solid, solid
        // advanced only by apply).
        const N: usize = 27;
        let state = mem_state();
        seed_witnesses(&state, N);
        let blocks_be = mem();

        let bi = BlockIndexStore::new(state.block_index.clone().unwrap());
        let bs = BlockStore::new(blocks_be.clone());
        let dp = DynamicPropertiesStore::new(state.dyn_props.clone());

        let head = 40i64;
        for num in 1..=head {
            let w = witness(((num - 1) as usize) % N);
            let block = block_by(num, &w);
            let id = block_id_from_block(&block).unwrap();
            bs.put(&id, &block).unwrap();
            bi.put(&id).unwrap();
        }
        dp.save_latest_block_header_number(head);
        // Stuck state: solid never advanced.
        assert_eq!(dp.latest_solidified_block_num(), None);

        // Startup seeding (what `run()` calls before the peer loop).
        let mut driver = driver_with(state.clone(), blocks_be);
        driver.seed_solidified_from_disk();

        let threshold = tron_consensus::solidity_threshold(N) as i64;
        assert_eq!(
            dp.latest_solidified_block_num().unwrap_or(0),
            head - threshold + 1,
            "seed must advance solid to head-(threshold-1), unjamming the gate"
        );
    }

    #[test]
    fn reconcile_prunes_blocks_ahead_of_executed_head() {
        // M-19: a persist-before-gate orphan (block on disk, never executed)
        // leads the executed head and gets skipped on re-sync. Startup
        // reconciliation must drop it so it's re-fetched.
        const N: usize = 27;
        let state = mem_state();
        let blocks_be = mem();
        let bi = BlockIndexStore::new(state.block_index.clone().unwrap());
        let bs = BlockStore::new(blocks_be.clone());
        let dp = DynamicPropertiesStore::new(state.dyn_props.clone());

        // Executed head = 100, but blocks 101..=103 are persisted orphans.
        let head = 100i64;
        let mut orphans = vec![];
        for num in 1..=103i64 {
            let w = witness(((num - 1) as usize) % N);
            let block = block_by(num, &w);
            let id = block_id_from_block(&block).unwrap();
            bs.put(&id, &block).unwrap();
            bi.put(&id).unwrap();
            if num > head {
                orphans.push((num, id));
            }
        }
        dp.save_latest_block_header_number(head);
        assert!(bi.get(101).is_ok() && bi.get(103).is_ok());

        let mut driver = driver_with(state.clone(), blocks_be);
        driver.reconcile_stores_to_head();

        // Orphans gone from both stores; head + in-window entries intact.
        for (num, id) in orphans {
            assert!(bi.get(num).is_err(), "index orphan {num} pruned");
            assert!(bs.get(&id).is_err(), "block-bytes orphan {num} pruned");
        }
        assert!(bi.get(head).is_ok(), "head index entry must remain");
        assert_eq!(
            dp.latest_block_header_number(),
            Some(head),
            "the head pointer must be left untouched"
        );
    }

    #[test]
    fn chain_summary_anchors_at_lowest_block_and_halves_to_head() {
        // Ports java-tron's SyncService.getBlockChainSummary: the locator is
        // ascending, ends at our head, and its FIRST id is our LOWEST stored
        // block (java-tron's syncBeginNumber) — the deepest, most-certainly-
        // canonical anchor, which the peer validates via
        // containBlockInMainChain(blockIds.get(0)). The gap halves toward head.
        let state = mem_state();
        let blocks_be = mem();
        let bi = BlockIndexStore::new(state.block_index.clone().unwrap());
        let dp = DynamicPropertiesStore::new(state.dyn_props.clone());

        // Snapshot-like base: a chain that starts well above genesis.
        let base = 83_278_566i64;
        let head = base + 65_535;
        for num in base..=head {
            let block = block_by(num, &witness((num as usize) % 27));
            bi.put(&block_id_from_block(&block).unwrap()).unwrap();
        }
        dp.save_latest_block_header_number(head);

        let driver = driver_with(state.clone(), blocks_be);
        let summary = driver.build_chain_summary();

        let nums: Vec<i64> = summary.iter().map(|id| id.num() as i64).collect();
        assert!(nums.len() > 2, "locator should have several anchors: {nums:?}");
        assert!(nums.windows(2).all(|w| w[0] < w[1]), "ascending: {nums:?}");
        assert_eq!(*nums.last().unwrap(), head, "last id is our head");
        // The anchor is our true lowest block, NOT an arbitrary head-2^k point.
        assert_eq!(
            *nums.first().unwrap(),
            base,
            "first id must be the lowest stored block: {nums:?}"
        );
        // Dense near head: the final gap is a single block.
        assert_eq!(nums[nums.len() - 2], head - 1, "tail must be dense: {nums:?}");
        // Every id resolves to the matching block_index entry.
        for id in &summary {
            assert_eq!(bi.get(id.num() as i64).unwrap(), *id);
        }
    }

    /// Build a peer locator (`block_inventory::BlockId` list) from the
    /// canonical ids at the given numbers, mimicking what a peer sends in a
    /// `SyncBlockChain`.
    fn locator_of(
        ids_by_num: &std::collections::HashMap<i64, BlockId>,
        nums: &[i64],
    ) -> Vec<tron_proto::block_inventory::BlockId> {
        nums.iter()
            .map(|&n| tron_proto::block_inventory::BlockId {
                hash: ids_by_num[&n].as_bytes().to_vec(),
                number: n,
            })
            .collect()
    }

    /// Index a `head`-long chain into `state`, set the head pointer, and
    /// return the driver plus the num→id map for building locators.
    fn driver_with_chain(
        head: i64,
    ) -> (SyncDriver, std::collections::HashMap<i64, BlockId>) {
        let state = mem_state();
        let blocks_be = mem();
        let bi = BlockIndexStore::new(state.block_index.clone().unwrap());
        let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
        let mut ids_by_num = std::collections::HashMap::new();
        for num in 1..=head {
            let block = block_by(num, &witness((num as usize) % 27));
            let id = block_id_from_block(&block).unwrap();
            bi.put(&id).unwrap();
            ids_by_num.insert(num, id);
        }
        dp.save_latest_block_header_number(head);
        (driver_with(state, blocks_be), ids_by_num)
    }

    #[test]
    fn serve_sync_block_chain_serves_from_shared_block_to_head() {
        // A peer 200 blocks behind sends its locator (tops out at 300). We
        // must reply with our ids from the shared block 300 onward — the
        // shared block first so it can verify the link — contiguous to head.
        let head = 500i64;
        let (driver, ids) = driver_with_chain(head);
        let locator = locator_of(&ids, &[300, 299, 297, 293, 285, 269, 237, 173, 45, 1]);

        let (served, remain) = driver.serve_sync_block_chain(&locator);

        assert_eq!(served.first().unwrap().num() as i64, 300, "shared block first");
        assert_eq!(served.last().unwrap().num() as i64, head, "served up to head");
        assert_eq!(served.len(), (head - 300 + 1) as usize);
        assert!(
            served.windows(2).all(|w| w[1].num() == w[0].num() + 1),
            "contiguous run"
        );
        assert_eq!(remain, 0, "nothing beyond our head");
    }

    #[test]
    fn serve_sync_block_chain_caps_batch_and_reports_remain() {
        // From a deep common ancestor we send at most SYNC_FETCH_BATCH_NUM
        // (2000) ids and report the rest via remain_num so the peer keeps
        // asking.
        let head = 5000i64;
        let (driver, ids) = driver_with_chain(head);
        let locator = locator_of(&ids, &[1000, 999, 997, 993, 1]);

        let (served, remain) = driver.serve_sync_block_chain(&locator);

        // 1000..=3000 inclusive = 2001 ids (shared block + 2000-block batch).
        assert_eq!(served.first().unwrap().num() as i64, 1000);
        assert_eq!(served.last().unwrap().num() as i64, 3000);
        assert_eq!(served.len(), 2001);
        assert_eq!(remain, head - 3000, "remaining blocks beyond the batch");
    }

    #[test]
    fn serve_sync_block_chain_empty_when_no_shared_block() {
        // A locator whose ids don't match our chain (wrong hashes / a fork we
        // don't have) yields an empty reply — a valid "nothing for you" that
        // still keeps the peer from timing out.
        let head = 100i64;
        let (driver, _ids) = driver_with_chain(head);
        // Numbers we have, but bogus hashes → no match.
        let bogus: Vec<tron_proto::block_inventory::BlockId> = [50i64, 25, 1]
            .iter()
            .map(|&n| tron_proto::block_inventory::BlockId {
                hash: vec![0xab; 32],
                number: n,
            })
            .collect();

        let (served, remain) = driver.serve_sync_block_chain(&bogus);

        assert!(served.is_empty(), "no shared block → empty reply");
        assert_eq!(remain, 0);
    }

    #[test]
    fn serve_sync_block_chain_handles_peer_ahead_of_us() {
        // A peer ahead of us sends a locator with blocks above our head plus
        // some we share. The common ancestor is our head (highest shared), so
        // we serve just [head] with remain 0 — telling it we have nothing new.
        let head = 300i64;
        let (driver, ids) = driver_with_chain(head);
        // Locator: phantom future blocks (we don't have them) + our head + deep.
        let mut locator = vec![
            tron_proto::block_inventory::BlockId { hash: vec![0x11; 32], number: 305 },
            tron_proto::block_inventory::BlockId { hash: vec![0x22; 32], number: 303 },
        ];
        locator.extend(locator_of(&ids, &[300, 296, 288, 1]));

        let (served, remain) = driver.serve_sync_block_chain(&locator);

        assert_eq!(served.len(), 1, "only the shared head");
        assert_eq!(served[0].num() as i64, head);
        assert_eq!(remain, 0);
    }
}

#[cfg(test)]
mod peer_failure_log_tests {
    use super::is_expected_peer_failure;

    #[test]
    fn disconnect_codes_decode_to_readable_names() {
        // The two enums the two disconnect paths use. "reason code 4" means
        // different things in each — which is exactly why the raw number was
        // confusing and we now log the name.
        assert_eq!(
            tron_proto::ReasonCode::try_from(4).unwrap().as_str_name(),
            "TOO_MANY_PEERS",
            "app-layer P2pDisconnect code 4 = peer is full"
        );
        assert_eq!(
            tron_proto::ReasonCode::try_from(2).unwrap().as_str_name(),
            "BAD_PROTOCOL"
        );
        assert_eq!(
            tron_proto::libp2p::DisconnectReasonCode::try_from(4)
                .unwrap()
                .as_str_name(),
            "DIFFERENT_VERSION",
            "libp2p-layer code 4 = version mismatch (a DIFFERENT enum)"
        );
    }

    #[test]
    fn expected_churn_is_quiet_real_rejections_are_loud() {
        // Unreachable / full / deduped peers → expected churn (debug).
        for r in [
            "dial: Connection refused (os error 111)",
            "dial: No route to host (os error 113)",
            "dial: Connection timed out (os error 110)",
            "peer app-disconnected with reason code 4 (TOO_MANY_PEERS)",
            "peer app-disconnected with reason code 5 (DUPLICATE_PEER)",
            "handshake: connection closed before peer Hello arrived",
        ] {
            assert!(is_expected_peer_failure(r), "should be quiet: {r}");
        }
        // Protocol/version/message rejections → real signal (warn): these are
        // the ones that mean "we're doing something peers don't like".
        for r in [
            "peer app-disconnected with reason code 2 (BAD_PROTOCOL)",
            "peer app-disconnected with reason code 24 (INCOMPATIBLE_VERSION)",
            "peer libp2p-disconnected with reason code 11 (BAD_MESSAGE)",
            "libp2p_handshake: frame error: unknown message type byte: 0x54",
        ] {
            assert!(!is_expected_peer_failure(r), "should be loud: {r}");
        }
    }
}

#[cfg(test)]
mod leadership_tests {
    //! Single-active-syncer coordination (`SyncLeadership`): exactly one
    //! driver leads at a time; a standby takes over only after the leader
    //! stalls past the threshold or releases.
    use super::SyncLeadership;
    use std::time::Duration;

    const STALE: Duration = Duration::from_millis(40);

    #[test]
    fn first_claimant_leads_and_blocks_others() {
        let l = SyncLeadership::new();
        assert!(l.claim_or_check("A", STALE, true), "first claimant wins the slot");
        assert!(l.claim_or_check("A", STALE, true), "incumbent retains");
        assert!(!l.claim_or_check("B", STALE, true), "challenger blocked while leader fresh");
    }

    #[test]
    fn progress_keeps_a_standby_from_preempting() {
        let l = SyncLeadership::new();
        assert!(l.claim_or_check("A", STALE, true));
        // Sleep past STALE but keep noting progress — A must keep the slot.
        for _ in 0..3 {
            std::thread::sleep(STALE / 2);
            l.note_progress("A");
            assert!(!l.claim_or_check("B", STALE, true), "fresh progress blocks preemption");
        }
        assert!(l.claim_or_check("A", STALE, true), "A still leads");
    }

    #[test]
    fn standby_takes_over_after_leader_stalls() {
        let l = SyncLeadership::new();
        assert!(l.claim_or_check("A", STALE, true));
        std::thread::sleep(STALE + Duration::from_millis(10));
        // A made no progress for > STALE → B preempts.
        assert!(l.claim_or_check("B", STALE, true), "B steals a stalled leader");
        assert!(!l.claim_or_check("A", STALE, true), "A is now the standby");
    }

    #[test]
    fn release_frees_the_slot_immediately() {
        let l = SyncLeadership::new();
        assert!(l.claim_or_check("A", STALE, true));
        l.release("A");
        // No need to wait out STALE — the slot is free.
        assert!(l.claim_or_check("B", STALE, true), "B leads right after A releases");
        // A releasing again (it no longer holds the slot) is a harmless no-op.
        l.release("A");
        assert!(l.claim_or_check("B", STALE, true), "B still leads");
    }

    #[test]
    fn note_progress_by_non_leader_is_a_noop() {
        let l = SyncLeadership::new();
        assert!(l.claim_or_check("A", STALE, true));
        // B isn't the leader; its (bogus) progress must not refresh A's timer.
        std::thread::sleep(STALE / 2);
        l.note_progress("B");
        std::thread::sleep(STALE / 2 + Duration::from_millis(10));
        assert!(l.claim_or_check("B", STALE, true), "A's timer was untouched, so B preempts");
    }

    #[test]
    fn ineligible_peer_cannot_take_the_slot() {
        let l = SyncLeadership::new();
        // A free slot is NOT handed to an ineligible (dramatically-behind)
        // peer — that's the fresh-node-at-head-0 case.
        assert!(!l.claim_or_check("fresh", STALE, false), "ineligible can't claim free slot");
        // An eligible peer takes it.
        assert!(l.claim_or_check("good", STALE, true));
        // Even after the leader goes stale, an ineligible challenger still
        // can't preempt it.
        std::thread::sleep(STALE + Duration::from_millis(10));
        assert!(!l.claim_or_check("fresh", STALE, false), "ineligible can't preempt a stalled leader");
        // The stalled leader still nominally holds it until an *eligible*
        // peer takes over.
        assert!(l.claim_or_check("good", STALE, false), "incumbent retains regardless of eligibility");
    }
}
