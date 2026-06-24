//! Runtime supervisor: wires the daemon's three concurrent tasks
//! together (storage, RPC, sync) and coordinates graceful shutdown
//! via a broadcast channel.
//!
//! `run(config, shutdown)` is the canonical entry point. Returns
//! when:
//!
//! * a `Ctrl-C` or external `shutdown.shutdown()` is observed,
//! * any required subsystem (RPC bind, peer dial) fails fatally,
//! * or, in `--no-sync --no-rpc` mode, the moment storage is open
//!   (so the binary doubles as a `tron-node init` check).

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use crate::config::NodeConfig;
use crate::storage::OpenedStores;

/// Cooperative shutdown handle. Cloneable; each clone observes the
/// same signal.
///
/// The broadcast channel only delivers a `send()` to receivers that were
/// already subscribed — a receiver created *after* shutdown fired would
/// never see it and block forever on `recv()`. Because the signal can fire
/// at any time (the Ctrl-C task is spawned before `run`, so it can trip
/// during the multi-second startup), we also keep a sticky `fired` flag:
/// any code about to block on `recv()` must first check [`is_shutdown`] so
/// an already-delivered shutdown isn't missed.
#[derive(Clone)]
pub struct ShutdownSignal {
    tx: broadcast::Sender<()>,
    fired: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl ShutdownSignal {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(8);
        Self {
            tx,
            fired: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Trigger shutdown. Idempotent — multiple calls coalesce. Sets the
    /// sticky flag *before* sending so any concurrent
    /// `subscribe()`-then-[`is_shutdown`] sees it.
    pub fn shutdown(&self) {
        self.fired.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = self.tx.send(());
    }

    /// True once [`shutdown`] has been called. Sticky — unlike a fresh
    /// broadcast receiver, it reflects a shutdown that already happened.
    pub fn is_shutdown(&self) -> bool {
        self.fired.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Get a fresh receiver. Each subsystem holds one and `.recv()`s
    /// to know when to exit. NOTE: a receiver only sees `send()`s that
    /// happen after it subscribes — pair a blocking `recv()` with an
    /// [`is_shutdown`] check if the receiver may be created late.
    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.tx.subscribe()
    }
}

impl Default for ShutdownSignal {
    fn default() -> Self {
        Self::new()
    }
}

/// Top-level error returned from [`run`].
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error(transparent)]
    Storage(#[from] crate::storage::StorageError),
    #[error("RPC server: {0}")]
    Rpc(String),
    #[error("sync: {0}")]
    Sync(String),
}

/// Run the node until the shutdown signal fires.
///
/// Three concurrent tasks:
/// 1. **RPC server** (axum on `config.rpc.host:port`) — unless disabled.
/// 2. **Sync loop** (one task per configured peer) — unless disabled.
/// 3. **Shutdown watcher** — listens for the broadcast and unblocks
///    the top-level `select!`.
///
/// On shutdown: every task gets `signal.subscribe().recv().await` and
/// exits cleanly. RocksDB instances flush on `Drop` of `Arc<RocksDbBackend>`.
/// Decide the new soft FD limit given current `(soft, hard)`: raise to the
/// hard ceiling when below it, else leave unchanged. Pure (testable) half of
/// [`raise_fd_limit`].
fn fd_limit_target(soft: u64, hard: u64) -> Option<u64> {
    (soft < hard).then_some(hard)
}

/// Raise the process open-file soft limit to the hard ceiling at startup.
///
/// A full node opens one RocksDB instance per store (~60 here), each holding
/// up to `max_open_files` SST handles, plus peer sockets — easily 15k+
/// descriptors once every store is warmed by sync. A 1024/4096 default soft
/// limit then trips `EMFILE` ("Too many open files") part-way through a sync
/// (M-21). Databases raise this themselves; soft→hard needs no privilege.
fn raise_fd_limit() {
    // SAFETY: `get/setrlimit` with `RLIMIT_NOFILE` and a stack-owned
    // `rlimit`; no aliasing, both return codes checked.
    unsafe {
        let mut rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) != 0 {
            warn!("could not read RLIMIT_NOFILE; leaving the open-file limit as inherited");
            return;
        }
        let Some(target) = fd_limit_target(rl.rlim_cur as u64, rl.rlim_max as u64) else {
            // Surface the effective limit: if a sync still hits EMFILE with
            // this already high, the cause is descriptor *leakage*, not the
            // ceiling.
            info!(limit = rl.rlim_cur as u64, "open-file limit (RLIMIT_NOFILE) already at hard ceiling");
            return;
        };
        let prev = rl.rlim_cur as u64;
        rl.rlim_cur = target as libc::rlim_t;
        if libc::setrlimit(libc::RLIMIT_NOFILE, &rl) != 0 {
            warn!(
                soft = prev,
                hard = rl.rlim_max as u64,
                "could not raise RLIMIT_NOFILE; sync may hit 'Too many open files'"
            );
            return;
        }
        info!(from = prev, to = target, "raised open-file limit (RLIMIT_NOFILE soft → hard)");
    }
}

pub async fn run(config: NodeConfig, shutdown: ShutdownSignal) -> Result<(), RunError> {
    // Give RocksDB (one instance per store) + peer sockets enough file
    // descriptors before anything opens one (M-21).
    raise_fd_limit();
    // Size the shared RocksDB block cache before any store opens (it's
    // built lazily, first-open-wins). Bigger cache → more state stays hot →
    // faster apply-bound catch-up.
    tron_chainbase::set_block_cache_bytes(
        config.storage.block_cache_mb.saturating_mul(1024 * 1024),
    );
    info!(
        data_dir = ?config.data_dir,
        block_cache_mb = config.storage.block_cache_mb,
        "opening stores"
    );
    let mut stores = OpenedStores::open_tuned(
        &config.data_dir,
        config.storage.write_buffer_size_mb,
        config.storage.max_open_files,
    )?;

    // java-tron checkpoint replay: a data dir copied straight from a
    // java-tron node (the usual mainnet-snapshot form) carries a redo
    // log of the most-recent flush batch in `database/tmp` (V1) or
    // `database/checkpoint/<ts>` (V2) that java replays over its stores
    // on every startup (`SnapshotManager.recover`). If the operator
    // dropped such a dir in by hand instead of going through
    // `snapshot_import` (which already merges it), the base would sit up
    // to one flush behind the head pointer — a silent consensus
    // divergence. Replaying is idempotent for an already-flushed base,
    // so run it unconditionally, then remove the merged checkpoint so it
    // isn't reconsidered (this node uses its own checkpoint format).
    {
        let db_root = crate::storage::resolve_db_root(&config.data_dir);
        match tron_chainbase::replay_java_checkpoint(&db_root, |name| {
            stores.backend_for_store_name(name)
        }) {
            Ok(0) => {}
            Ok(n) => {
                info!(
                    entries = n,
                    "replayed java-tron checkpoint redo log into base stores \
                     (imported data dir was not fully flushed)"
                );
                for sub in [
                    tron_chainbase::JAVA_CHECKPOINT_V1_DIR,
                    tron_chainbase::JAVA_CHECKPOINT_V2_DIR,
                ] {
                    let p = db_root.join(sub);
                    if p.exists() {
                        if let Err(e) = std::fs::remove_dir_all(&p) {
                            warn!(path = ?p, error = %e, "failed to remove merged java checkpoint");
                        }
                    }
                }
            }
            Err(e) => warn!(error = %e, "java checkpoint replay failed; continuing"),
        }
    }

    // Checkpoint-V2 recovery: if the previous run crashed between the
    // manifest write and the per-store flush, replay any orphan
    // manifests into the freshly-opened root backends so the chain
    // sees a consistent post-flush state. Cheap — `list()` is one
    // readdir; on the common no-crash path there are zero manifests.
    //
    // Two code paths converge on the same checkpoint dir:
    //   * snapshot_reorg=true → snapshot-stack flush manifests.
    //   * snapshot_reorg=false → BlockSession flush manifests
    //     (cross-store atomicity for the executor's direct-to-base
    //     path; see `replay_pending_checkpoints`).
    let checkpoint_dir = tron_chainbase::CheckPointV2::new(&config.data_dir);
    if config.storage.snapshot_reorg {
        match stores.snapshots.recover_from_checkpoints(&checkpoint_dir) {
            Ok(n) if n > 0 => {
                info!(
                    entries = n,
                    "replayed orphan checkpoint manifests into root stores"
                );
            }
            Ok(_) => {}
            Err(e) => warn!(error = ?e, "checkpoint recovery failed; continuing"),
        }
        // Configure the coordinator's horizon + checkpoint dir once;
        // every consumer (SyncDriver, SrRuntime) shares the same
        // configured stack via Arc clone.
        stores.snapshots = stores
            .snapshots
            .clone()
            .with_horizon(config.storage.snapshot_horizon)
            .with_checkpoint(checkpoint_dir.clone());
    } else {
        // BlockSession path: replay any leftover manifests into the
        // base backends before serving blocks. Hard-fails on an
        // unknown store id (manifest produced by a different build).
        let state = stores.to_state_backends();
        match tron_executor::replay_pending_checkpoints(&state, &checkpoint_dir) {
            Ok((0, _)) => {}
            Ok((cp_count, entries)) => info!(
                checkpoints = cp_count,
                entries,
                "replayed orphan BlockSession checkpoint manifests into base stores"
            ),
            Err(e) => {
                error!(error = ?e, "BlockSession checkpoint recovery failed");
                return Err(RunError::Sync(format!(
                    "BlockSession checkpoint recovery failed: {e}"
                )));
            }
        }
    }

    // Decide whether the genesis block is already applied; if the
    // dyn-props head is missing, write the mainnet genesis +
    // committee initial values.
    if !chain_initialized(&stores) {
        initialize_genesis(&stores)?;
        // Seed governance proposal flags from the resolved
        // `CommitteeConfig`. java-tron treats these as the **initial**
        // values; the on-chain proposal flow can later override them.
        // We only seed once at fresh-chain bootstrap, mirroring
        // `Manager.initGenesisData` calling each `save*` setter from
        // the committee config.
        match config.resolve_committee() {
            Ok(committee) => seed_committee_initial_values(&stores, &committee),
            Err(e) => warn!(error = %e, "committee.* validation failed; skipping bootstrap"),
        }
    }

    // Startup system summary — a compact, at-a-glance boot readout for
    // operators and the curious: build provenance, which chain/fork, where
    // we're resuming from, the detected hardware + derived RocksDB tuning, the
    // execution-engine switches, and the network/API surfaces. Everything here
    // is a free config/const read or a cheap dyn-props point lookup — no scans.
    {
        use tron_chainbase::rocksdb_tuning;
        let dp = tron_chainbase::DynamicPropertiesStore::new(stores.dyn_props.clone());
        let num = dp.latest_block_header_number().unwrap_or(0);
        let ts = dp.latest_block_header_timestamp().unwrap_or(0);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let head_hash = dp.latest_block_header_hash().ok().flatten();
        let solid = dp.latest_solidified_block_num().unwrap_or(0);
        let cycle = dp.current_cycle_number();
        let schema = dp.schema_version().unwrap_or(0);
        let t = rocksdb_tuning();
        let genesis = tron_types::genesis_block_id(&tron_types::mainnet_inputs()).0;

        // Local formatting helpers (only the summary uses them).
        let gib = |b: usize| b as f64 / (1u64 << 30) as f64;
        let mib = |b: usize| b / (1usize << 20);
        // Block ids are height-prefixed (8-byte height ++ 24-byte hash tail), so
        // the meaningful fingerprint is the TAIL — render it as `0x…<last4>`.
        let fp = |b: &[u8]| {
            let mut s = String::from("0x…");
            for x in &b[b.len().saturating_sub(4)..] {
                s.push_str(&format!("{x:02x}"));
            }
            s
        };
        let on = |b: bool| if b { "ON" } else { "OFF" };
        let api = |disabled: bool, port: u16| {
            if disabled {
                "off".to_string()
            } else {
                format!(":{port}")
            }
        };
        let head_hex = head_hash
            .as_ref()
            .map(|h| fp(&h[..]))
            .unwrap_or_else(|| "—".to_string());
        let profile = if cfg!(debug_assertions) { "debug" } else { "release" };

        info!(
            "🧌 build: tron-goblin/{} · {} · {} · {}-{} · mimalloc",
            env!("CARGO_PKG_VERSION"),
            env!("GOBLIN_GIT_SHA"),
            profile,
            std::env::consts::ARCH,
            std::env::consts::OS,
        );
        // Genesis tail (last 4 bytes) is the meaningful fingerprint — paired
        // with the p2p net id it pins exactly which chain/fork this data-dir is.
        info!(
            "🧱 chain: TRON mainnet · p2p net {} · genesis {}",
            tron_net::MAINNET_P2P_VERSION,
            fp(&genesis[..]),
        );
        info!(
            "🌱 head: #{} ({}) · {} behind · solidified #{} · cycle {}",
            crate::logfmt::commas(num),
            head_hex,
            crate::logfmt::duration_ms((now_ms - ts).max(0)),
            crate::logfmt::commas(solid),
            cycle,
        );
        info!(
            "⚙ runtime: {} cores · {:.1} GiB RAM · tokio {} workers",
            t.cores,
            gib(t.mem_total_bytes),
            t.cores,
        );
        info!(
            "💾 rocksdb: WBM {:.1} GiB · HyperClockCache {} MiB · {}c+{}f threads · bloom {}b/key · schema v{}",
            gib(t.write_buffer_manager_bytes),
            mib(t.block_cache_bytes),
            t.background_threads,
            t.flush_threads,
            t.bloom_bits_per_key,
            schema,
        );
        info!(
            "🧠 vm: Block-STM {} · pipelined-apply {} · reorg={}",
            on(config.vm.parallel_exec),
            on(config.vm.pipelined_apply),
            if config.storage.snapshot_reorg { "snapshot" } else { "undo-log" },
        );
        info!(
            "📡 p2p :{} ({}) · discovery {} · max {} peers",
            config.p2p.advertise_port,
            if config.p2p.listen { "listening" } else { "outbound-only" },
            if config.p2p.discover_enable { "DNS+Kad" } else { "off" },
            config.p2p.max_peers,
        );
        info!(
            "🔌 RPC {} · gRPC {} · 🌐 REST {} · 📊 metrics {}",
            api(config.rpc.disabled, config.rpc.port),
            api(config.grpc.disabled, config.grpc.port),
            api(config.http.disabled, config.http.port),
            api(config.metrics.disabled, config.metrics.port),
        );

        // Cross-store consistency guard: an imported snapshot whose stores
        // were captured at different heights (a live-node copy without a
        // quiescent flush) opens fine but SILENTLY diverges from consensus
        // once we apply blocks on top — the head pointer describes one
        // height while the account/block stores hold another, baking a
        // permanent offset into resource weights and fees. Surface it
        // loudly at startup rather than letting the operator chase ghost
        // state-diff mismatches.
        for w in crate::snapshot_import::startup_consistency_warnings(&stores, num) {
            warn!(
                "snapshot consistency: {w} — this node will diverge from consensus; \
                 re-import from a CONSISTENT snapshot (stop the source node before copying, \
                 or use its snapshot-export tooling)"
            );
        }
    }

    // Tip-test mode: spoof the local head pointer so SyncBlockChain
    // requests use a recent block ID, letting peers that pruned the
    // archive serve us their post-pruning tail. The chain state is
    // NOT modified — only `DynamicPropertiesStore`'s head pointers.
    if let Some(checkpoint) = config.p2p.tip_test.clone() {
        use tron_chainbase::DynamicPropertiesStore;
        // Refuse to overwrite a real synced head: this path moves the head
        // pointer forward without applying any block, so doing it on a
        // data-dir that already holds a synced chain bakes a permanent
        // offset between the head pointer and the account/block stores —
        // the exact silent-divergence the startup consistency guard above
        // warns about. A fresh / genesis-only data-dir is safe to spoof.
        guard_head_spoof(&stores, "--tip-test")?;
        let hash = hex::decode(&checkpoint.block_id_hex).map_err(|e| {
            RunError::Sync(format!(
                "--tip-test hash hex: {e}"
            ))
        })?;
        if hash.len() != 32 {
            return Err(RunError::Sync(format!(
                "--tip-test hash must be 32 bytes (got {})",
                hash.len()
            )));
        }
        let dp = DynamicPropertiesStore::new(stores.dyn_props.clone());
        dp.save_latest_block_header_number(checkpoint.block_num);
        let mut hash_arr = [0u8; 32];
        hash_arr.copy_from_slice(&hash);
        dp.save_latest_block_header_hash(&hash_arr);
        warn!(
            block = checkpoint.block_num,
            hash = checkpoint.block_id_hex.as_str(),
            "TIP-TEST MODE: spoofed head; blocks will be counted, NOT applied"
        );
    }

    // Single metrics sink shared across RPC + sync + the periodic
    // chain-state sampler. Cheap to clone (Arc).
    let metrics = tron_rpc::Metrics::new_arc();

    // Single pubsub broker shared between the RPC WebSocket
    // handlers, the SyncDriver / SrRuntime block-apply paths (which
    // publish `newHeads` + `logs`), and the mempool→broker bridge
    // task that forwards every accepted tx_id to
    // `newPendingTransactions` subscribers.
    let pubsub = tron_rpc::PubSubBroker::new_arc();

    // Single validating mempool — shared between the RPC submit path
    // (eth_sendRawTransaction / broadcastTransaction), the sync
    // driver's inbound `Trx` / `Trxs` handlers (which submit
    // peer-relayed txs), and the sync driver's outbound broadcast
    // (which subscribes to the mempool's channel and forwards every
    // accepted tx_id as a `Trx` frame on every connected peer).
    //
    // The state-aware validator runs the actuator dispatch against
    // current state before accepting — same precondition checks a
    // peer would apply on receive, so we don't broadcast txs that
    // would be rejected.
    //
    // `--mempool` dashboard mode is decode-only: the head is spoofed to
    // the live tip and the stores hold only genesis, so there is no real
    // account state to validate against and the validator would reject
    // every inbound tx. Skip it in that mode so the dashboard observes
    // the raw pending stream; never skip it for a normal node.
    let mut mempool = tron_mempool::TxMempool::new(tron_mempool::MempoolConfig::default())
        .with_persistence(stores.mempool.clone())
        .with_metrics(metrics.clone());
    if !config.p2p.mempool {
        let mempool_state = stores.to_state_backends();
        mempool = mempool.with_validator(crate::mempool_validator::build(&mempool_state));
    }
    let mempool = std::sync::Arc::new(mempool);
    // Repopulate pending pool from disk. Stale entries (expired, sig
    // re-validation failures, etc.) are dropped from the backend in
    // the same pass so they don't keep re-attempting on every restart.
    let reload = mempool.reload_from_disk();
    if reload.scanned > 0 {
        info!(
            scanned = reload.scanned,
            restored = reload.restored,
            dropped = reload.dropped,
            "mempool reloaded from disk"
        );
    }

    // Mempool → pubsub broker bridge: every accepted tx_id is
    // rebroadcast through the broker so `newPendingTransactions`
    // subscribers see it. Exits when the runtime shuts down.
    {
        let mut mp_rx = mempool.subscribe();
        let broker = pubsub.clone();
        let mut sd = shutdown.subscribe();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    res = mp_rx.recv() => match res {
                        Ok(tx_id) => broker.publish_pending_tx(tx_id),
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(_) => break,
                    },
                    _ = sd.recv() => break,
                }
            }
        });
    }

    let mut handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    // === Metrics server (Prometheus /metrics) ===
    if !config.metrics.disabled {
        let metrics_addr: std::net::SocketAddr =
            format!("{}:{}", config.metrics.host, config.metrics.port)
                .parse()
                .map_err(|e: std::net::AddrParseError| RunError::Rpc(e.to_string()))?;
        let listener = tokio::net::TcpListener::bind(metrics_addr)
            .await
            .map_err(|e| RunError::Rpc(format!("metrics bind {metrics_addr}: {e}")))?;
        let bound = listener
            .local_addr()
            .map_err(|e| RunError::Rpc(e.to_string()))?;
        info!(%bound, "📊 Prometheus metrics listening");
        let app = tron_rpc::server::metrics_router(metrics.clone());
        let mut sd = shutdown.subscribe();
        handles.push(tokio::spawn(async move {
            let server = axum::serve(listener, app.into_make_service());
            tokio::select! {
                r = server => {
                    if let Err(e) = r {
                        error!(error = %e, "metrics server exited");
                    }
                }
                _ = sd.recv() => {
                    info!("metrics server shutting down");
                }
            }
        }));
    }

    // === Periodic chain-state sampler ===
    //
    // Gauges (head block, solidified block, weights, witness count)
    // change in places we don't easily instrument — the executor
    // mutates dyn-props via the session backends, freeze actuators
    // bump weights inside an Arc<dyn KvBackend>. Simpler: poll the
    // stores every 5s and update the gauges. The cost is negligible
    // and reads stay in-process.
    {
        let m = metrics.clone();
        let dp = stores.dyn_props.clone();
        let ws = stores.witnesses.clone();
        let mp_for_sampler = mempool.clone();
        let mut sd = shutdown.subscribe();
        handles.push(tokio::spawn(async move {
            use tron_chainbase::{DynamicPropertiesStore, WitnessStore};
            let dp = DynamicPropertiesStore::new(dp);
            let ws = WitnessStore::new(ws);
            loop {
                tokio::select! {
                    _ = sd.recv() => break,
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                }
                m.set_head_block_number(dp.latest_block_header_number().unwrap_or(0));
                m.set_solidified_block_number(dp.latest_solidified_block_num().unwrap_or(0));
                m.set_total_net_weight(dp.total_net_weight());
                m.set_total_energy_weight(dp.total_energy_weight());
                if let Ok(all) = ws.all() {
                    m.set_total_witnesses(all.len() as i64);
                }
                m.set_mempool_size(mp_for_sampler.pending_count() as i64);
            }
        }));
    }

    // Resolve `vm.*` once and derive the effective constant-call cap.
    // java-tron clamps `eth_call`-style read gas to whichever is
    // smaller of `rpc.eth_call_gas_cap` and `vm.maxEnergyLimitForConstant`.
    // Constant-call settings forwarded to every RpcState below. java's
    // `maxEnergyLimitForConstant` (default 100M) is the ceiling for
    // `triggerConstantContract` / `estimateEnergy`; `estimate_energy`
    // and `estimate_energy_max_retry` gate / bound `estimateEnergy`'s
    // binary search; `energy_fee` / `max_fee_limit` map feeLimit↔energy.
    let constant_call_energy_limit = config
        .resolve_vm()
        .map(|vm| vm.max_energy_limit_for_constant.max(0) as u64)
        .unwrap_or(100_000_000);
    let estimate_energy_enabled = config
        .resolve_vm()
        .map(|vm| vm.estimate_energy)
        .unwrap_or(false);
    let estimate_energy_max_retry = config
        .resolve_vm()
        .map(|vm| vm.estimate_energy_max_retry.max(0) as u32)
        .unwrap_or(3);
    // The live `ENERGY_FEE` / `MAX_FEE_LIMIT` are read from dyn_props at
    // call time; seed the genesis/config defaults here.
    let constant_energy_fee = tron_chainbase::DynamicPropertiesStore::DEFAULT_ENERGY_FEE;
    let constant_max_fee_limit = 15_000_000_000_i64;

    let (support_constant, eth_call_gas_cap, constant_call_timeout_ms, exec_config) =
        match config.resolve_vm() {
            Ok(vm) => {
                let cap = vm.max_energy_limit_for_constant.max(0) as u64;
                let effective = config.rpc.eth_call_gas_cap.min(cap);
                let exec_cfg = tron_executor::ExecConfig {
                    save_internal_tx: vm.save_internal_tx,
                    vm_trace: vm.vm_trace,
                    save_featured_internal_tx: vm.save_featured_internal_tx,
                    // Default-strict: every peer-received and SR-produced
                    // block we ever apply via the daemon must carry a
                    // valid witness signature. The dry-run path used to
                    // compute `account_state_root` constructs its own
                    // `ExecConfig::unsigned()` inside `tron-executor`.
                    require_signature: true,
                    // Same logic: production must derive the VM's
                    // energy budget from each tx's `fee_limit`, never
                    // a hardcoded fallback. A consensus break
                    // otherwise.
                    require_fee_limit: true,
                    // Strict default; `SyncDriver::with_exec_config` forces
                    // this off for the sync path (it owns the raw-bytes
                    // `txTrieRoot` check). Self-produced/canonical blocks on
                    // any other consumer keep the check.
                    verify_tx_trie: true,
                    // Full per-block durability by default; `SyncDriver`
                    // flips this on per-block while catching up.
                    defer_store_fsync: false,
                    // Master switch carried into the SyncDriver, which only
                    // turns parallel execution on per-block while catching up
                    // (Block-STM; byte-identical to serial). `vm.parallel_exec`
                    // defaults true.
                    parallel_exec: vm.parallel_exec,
                    // Flipped on below when the historical-state archive
                    // ([index] capture_state_deltas) is enabled.
                    capture_state_deltas: false,
                    // The success/failure contractRet tripwire always logs a
                    // divergence at ERROR; hard-rejecting the block (which halts
                    // sync at that block) is opt-in via the
                    // TRON_VERIFY_CONTRACT_RET env gate, for a strict-validation
                    // re-sync. Default (unset) is log-only so a production node
                    // never halts on a divergence.
                    verify_contract_ret: std::env::var("TRON_VERIFY_CONTRACT_RET").is_ok(),
                };
                (
                    vm.support_constant,
                    effective,
                    vm.constant_call_timeout_ms,
                    exec_cfg,
                )
            }
            Err(e) => {
                warn!(error = %e, "vm.* validation failed; using rpc.eth_call_gas_cap unclamped");
                (
                    false,
                    config.rpc.eth_call_gas_cap,
                    0,
                    tron_executor::ExecConfig::default(),
                )
            }
        };
    let mut exec_config = exec_config;

    // === Address-history index (the `[index]` subsystem) ===
    //
    // Self-orchestrating: opens (or rebuilds) the dedicated index DB
    // under <data_dir>/index/db, arms the apply-path hook (persist
    // per-block transaction-info + wake the follower), and yields the
    // engine/reader pair that the follower task and the HTTP /v1
    // surface use below. A failure here logs and disables the index —
    // it never blocks consensus.
    let mut index_parts = if config.index.enable {
        match open_index_subsystem(&config, &stores) {
            Ok(parts) => {
                // Internal-tx capture requires the executor to record
                // per-frame traces (observational only — no state or
                // consensus impact). Force it on so `idx_internal`
                // actually sees data; java-tron operators do the same
                // via vm.saveInternalTx for their event plugins.
                if parts.engine.capture_set().internal && !exec_config.save_internal_tx {
                    info!("index: capture_internal is on — enabling vm.save_internal_tx for trace capture");
                    exec_config.save_internal_tx = true;
                }
                if parts.archive.is_some() || parts.commitment.is_some() {
                    // The archive and the commitment builder both consume the
                    // per-block write-set; tell the executor to capture it
                    // (pure observation — no consensus-path behavior change).
                    exec_config.capture_state_deltas = true;
                }
                Some(parts)
            }
            Err(e) => {
                error!(error = %e, "index: subsystem failed to start; continuing WITHOUT the index");
                None
            }
        }
    } else {
        None
    };
    let index_hook = index_parts.as_ref().map(|p| p.hook.clone());

    // Spawn the dedicated state-commitment builder task. It takes ownership of
    // the builder + receiver (the tree's single writer), runs the one-time
    // bootstrap anchored at the recovered head, then folds confirmed blocks
    // entirely off the apply path. The reader/counters stay in `index_parts`
    // for the HTTP and metrics surfaces.
    if let Some(commitment) = index_parts.as_mut().and_then(|p| p.commitment.as_mut()) {
        if let (Some(builder), Some(rx)) = (commitment.builder.take(), commitment.rx.take()) {
            let anchor_head = tron_chainbase::DynamicPropertiesStore::new(stores.dyn_props.clone())
                .latest_block_header_number()
                .unwrap_or(0);
            let max_lag = config.index.commitment.max_lag_blocks;
            handles.push(tokio::spawn(run_commitment_builder(
                builder,
                rx,
                anchor_head,
                max_lag,
                shutdown.clone(),
            )));
        }
    }

    // Index follower + metrics sampler tasks. The follower is the
    // unified gap-closing loop: backfill from the local stores while
    // behind, park on the apply hook's wake-up at the tip, reconcile
    // reorgs by hash. The sampler mirrors the engine's counters into
    // the Prometheus surface every 5s.
    if let Some(parts) = &index_parts {
        spawn_index_follower(
            &mut handles,
            parts.engine.clone(),
            parts.hook.notify_handle(),
            shutdown.clone(),
        );
        let engine = parts.engine.clone();

        // Rolling-window retention for the historical-state archive: prune
        // archived versions older than the configured window on a timer.
        // `prune_for_window` clamps the floor to the live head, and
        // ArchiveWriter serializes its writes (RocksDB backend + inner
        // Mutex), so this runs safely alongside per-block capture. Full mode
        // (and the raw capture_state_deltas flag) never prune.
        if config.index.archive.enabled
            && config.index.archive.mode == crate::config::ArchiveMode::Rolling
        {
            if let Some(archive) = parts.archive.as_ref() {
                let prune_writer = archive.writer.clone();
                let retain = config.index.archive.retain_blocks;
                let mut sd_prune = shutdown.subscribe();
                handles.push(tokio::spawn(async move {
                    let mut ticker = tokio::time::interval(Duration::from_secs(600));
                    ticker.tick().await; // skip the immediate tick
                    loop {
                        tokio::select! {
                            _ = sd_prune.recv() => return,
                            _ = ticker.tick() => {
                                let head = match prune_writer.coverage() {
                                    Ok(Some((_, head))) => head,
                                    _ => continue,
                                };
                                match prune_writer.prune_for_window(head, retain) {
                                    Ok(Some(stats)) if !stats.noop => info!(
                                        rows_deleted = stats.rows_deleted,
                                        rows_repinned = stats.rows_repinned,
                                        base = stats.base_after,
                                        head,
                                        retain_blocks = retain,
                                        "archive: rolling-window prune"
                                    ),
                                    Ok(_) => {}
                                    Err(e) => warn!(
                                        error = %e,
                                        "archive: rolling-window prune failed; will retry"
                                    ),
                                }
                            }
                        }
                    }
                }));
            }
        }

        let archive_sampler = parts
            .archive
            .as_ref()
            .map(|a| (a.reader.clone(), a.counters.clone()));
        let firehose_sampler = parts
            .firehose_tail
            .as_ref()
            .zip(parts.firehose_counters.as_ref())
            .map(|(t, c)| (t.clone(), c.clone()));
        let commitment_sampler = parts.commitment.as_ref().map(|c| c.counters.clone());
        let m = metrics.clone();
        let mut sd = shutdown.subscribe();
        handles.push(tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = sd.recv() => break,
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                }
                let st = engine.status();
                let c = engine.counters();
                use std::sync::atomic::Ordering::Relaxed;
                if let Some((tail, counters)) = &firehose_sampler {
                    m.set_firehose_stats(
                        tail.durable_seq(),
                        counters.entries.load(Relaxed),
                        counters.unwinds.load(Relaxed),
                        counters.gap_repaired_blocks.load(Relaxed),
                    );
                }
                if let Some((reader, counters)) = &archive_sampler {
                    let (base, head) = reader.coverage().ok().flatten().unwrap_or((0, 0));
                    m.set_archive_stats(
                        base,
                        head,
                        counters.blocks_archived.load(Relaxed),
                        counters.entries_written.load(Relaxed),
                        counters.reorg_unwinds.load(Relaxed),
                        counters.gap_repaired_blocks.load(Relaxed),
                        counters.coverage_resets.load(Relaxed),
                    );
                }
                if let Some(counters) = &commitment_sampler {
                    m.set_commitment_stats(
                        counters.committed_height.load(Relaxed),
                        counters.head_height.load(Relaxed),
                        counters.blocks_folded.load(Relaxed),
                        counters.lagged.load(Relaxed),
                        counters.pending_depth.load(Relaxed),
                        counters.bootstrapping.load(Relaxed),
                    );
                }
                m.set_index_stats(
                    st.cursor.unwrap_or(0),
                    st.back_edge.unwrap_or(0),
                    st.floor.unwrap_or(0),
                    (st.target_head - st.cursor.unwrap_or(0)).max(0),
                    st.backfill_complete && st.at_tip,
                    c.blocks_indexed.load(Relaxed),
                    c.rows_native.load(Relaxed),
                    c.rows_trc20.load(Relaxed),
                    c.rows_trc721.load(Relaxed),
                    c.rows_internal.load(Relaxed),
                    c.rows_logs.load(Relaxed),
                    c.reorg_unwinds.load(Relaxed),
                    c.reorg_rows_deleted.load(Relaxed),
                    c.missing_txinfo_blocks.load(Relaxed),
                );
            }
        }));
    }

    // ERC-4337 bundler (off unless `[bundler] enable = true`). Built once and
    // shared across the JSON-RPC / gRPC / REST RpcStates below.
    let bundler_state = build_bundler_state(config.bundler.as_ref())?;

    // ERC-4337 auto bundling loop: in `auto` mode, drains the bundler mempool
    // into `handleOps` bundles on the configured cadence (manual mode bundles
    // only via `debug_bundler_sendBundleNow`). Shares the same Arc<BundlerState>
    // as the RPC states, so ops accepted over RPC land in the mempool this loop
    // drains. Runs regardless of whether the public RPC is served.
    if let Some(bundler) = bundler_state.clone() {
        let interval = bundler.bundle_interval;
        let loop_state = stores
            .to_rpc_state(config.rpc.chain_id)
            .with_bundler_opt(Some(bundler))
            .with_mempool(mempool.clone())
            .with_eth_call_gas_cap(eth_call_gas_cap)
            .with_constant_call_budget(
                constant_call_energy_limit,
                constant_energy_fee,
                constant_max_fee_limit,
            )
            .with_constant_call_timeout_ms(constant_call_timeout_ms);
        let mut sd = shutdown.subscribe();
        handles.push(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let is_auto = loop_state.bundler.as_ref().map(|b| b.mode())
                            == Some(tron_rpc::bundler::BundlingMode::Auto);
                        if !is_auto {
                            continue;
                        }
                        let st = loop_state.clone();
                        match tokio::task::spawn_blocking(move || tron_rpc::bundler::try_bundle(&st)).await {
                            Ok(bundles) if !bundles.is_empty() => {
                                info!(bundles = bundles.len(), "ERC-4337 auto-bundled ops")
                            }
                            Ok(_) => {}
                            Err(e) => warn!(error = %e, "ERC-4337 bundling task panicked"),
                        }
                    }
                    _ = sd.recv() => {
                        info!("ERC-4337 bundling loop shutting down");
                        break;
                    }
                }
            }
        }));
    }

    // === RPC server ===
    if !config.rpc.disabled {
        let rpc_state = stores
            .to_rpc_state(config.rpc.chain_id)
            .with_bundler_opt(bundler_state.clone())
            .with_metrics(metrics.clone())
            .with_mempool(mempool.clone())
            .with_eth_call_gas_cap(eth_call_gas_cap)
            .with_support_constant(support_constant)
            .with_estimate_energy(estimate_energy_enabled)
            .with_estimate_energy_max_retry(estimate_energy_max_retry)
            .with_constant_call_budget(
                constant_call_energy_limit,
                constant_energy_fee,
                constant_max_fee_limit,
            )
            .with_constant_call_timeout_ms(constant_call_timeout_ms)
            .with_pubsub(pubsub.clone());
        let addr: std::net::SocketAddr = format!("{}:{}", config.rpc.host, config.rpc.port)
            .parse()
            .map_err(|e: std::net::AddrParseError| RunError::Rpc(e.to_string()))?;
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| RunError::Rpc(format!("bind {addr}: {e}")))?;
        let bound = listener
            .local_addr()
            .map_err(|e| RunError::Rpc(e.to_string()))?;
        info!(%bound, "🔌 JSON-RPC listening");
        let mut sd = shutdown.subscribe();
        // Rate limits: java's JsonRpcServlet sits behind the same
        // rate.limiter.http chain — the `jsonrpc` component (servlet
        // suffix normalized) + the node-wide global limiter.
        let jsonrpc_limits = build_rate_limit_registry(&config.rate_limiter.http);
        let jsonrpc_global = tron_rpc::GlobalRateLimiter::new(
            config.rate_limiter.global_qps,
            config.rate_limiter.global_ip_qps,
        );
        handles.push(tokio::spawn(async move {
            let app =
                tron_rpc::server::router_with_limits(rpc_state, jsonrpc_limits, jsonrpc_global);
            let server = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            );
            tokio::select! {
                r = server => {
                    if let Err(e) = r {
                        error!(error = %e, "RPC server exited");
                    }
                }
                _ = sd.recv() => {
                    info!("RPC server shutting down");
                }
            }
        }));
    }

    // === Lite-fullnode history gate (java LiteFnQuery* filters) ===
    let lite_gate_enabled = {
        let lite = stores.is_lite_node();
        if lite && !config.open_history_query_when_lite_fn {
            info!(
                "lite dataset detected: history-query APIs closed \
                 (set open_history_query_when_lite_fn = true to serve them anyway)"
            );
        }
        lite && !config.open_history_query_when_lite_fn
    };

    // === gRPC server ===
    //
    // Mirrors java-tron's port-50051 API surface. Same `RpcState` as
    // the JSON-RPC server, so the two surfaces always see identical
    // data — clients can mix and match.
    if !config.grpc.disabled {
        let mut grpc_state = stores
            .to_rpc_state(config.rpc.chain_id)
            .with_bundler_opt(bundler_state.clone())
            .with_metrics(metrics.clone())
            .with_mempool(mempool.clone())
            .with_eth_call_gas_cap(eth_call_gas_cap)
            .with_support_constant(support_constant)
            .with_estimate_energy(estimate_energy_enabled)
            .with_estimate_energy_max_retry(estimate_energy_max_retry)
            .with_constant_call_budget(
                constant_call_energy_limit,
                constant_energy_fee,
                constant_max_fee_limit,
            )
            .with_constant_call_timeout_ms(constant_call_timeout_ms)
            .with_pubsub(pubsub.clone());
        // The firehose tail service mounts on this same port when the
        // durable log is enabled.
        if let Some(handle) = index_parts.as_ref().and_then(|p| p.firehose_tail.clone()) {
            grpc_state = grpc_state.with_firehose(handle);
        }
        let addr: std::net::SocketAddr = format!("{}:{}", config.grpc.host, config.grpc.port)
            .parse()
            .map_err(|e: std::net::AddrParseError| RunError::Rpc(e.to_string()))?;
        let mut sd = shutdown.subscribe();
        // Per-method limits from rate.limiter.rpc
        // (`protocol.Wallet/GetAccount`-style components) + the global
        // ceiling — java's RateLimiterInterceptor + GlobalRateLimiter.
        let grpc_limits = build_rate_limit_registry(&config.rate_limiter.rpc);
        let grpc_global = tron_rpc::GlobalRateLimiter::new(
            config.rate_limiter.global_qps,
            config.rate_limiter.global_ip_qps,
        );
        let lite_gate_for_grpc = lite_gate_enabled;
        handles.push(tokio::spawn(async move {
            let shutdown_fut = async move {
                let _ = sd.recv().await;
            };
            if let Err(e) = tron_grpc::start_server_with_limits_and_gates(
                grpc_state,
                addr,
                shutdown_fut,
                grpc_limits,
                grpc_global,
                lite_gate_for_grpc,
            )
            .await
            {
                error!(error = %e, "gRPC server exited");
            }
        }));
    }

    // === HTTP REST API on port 8090 ===
    //
    // The surface TronWeb / TronGrid / wallet-cli speak. Same
    // `RpcState` as JSON-RPC / gRPC — all three surfaces are live
    // views over the same underlying chainbase.
    if !config.http.disabled {
        let mut http_state = stores
            .to_rpc_state(config.rpc.chain_id)
            .with_bundler_opt(bundler_state.clone())
            .with_metrics(metrics.clone())
            .with_mempool(mempool.clone())
            .with_eth_call_gas_cap(eth_call_gas_cap)
            .with_support_constant(support_constant)
            .with_estimate_energy(estimate_energy_enabled)
            .with_estimate_energy_max_retry(estimate_energy_max_retry)
            .with_constant_call_budget(
                constant_call_energy_limit,
                constant_energy_fee,
                constant_max_fee_limit,
            )
            // The /v1 surfaces run constant calls too (token metadata,
            // archive trigger-at-height — the latter over at-height
            // store views, the slowest read path in the node), so the
            // wall-clock budget must apply here exactly as it does on
            // the JSON-RPC and gRPC servers.
            .with_constant_call_timeout_ms(constant_call_timeout_ms);
        // The /v1 address-history surface reads the embedded index;
        // token-metadata resolution additionally needs the constant-
        // call machinery, which `to_rpc_state` already attached.
        if let Some(parts) = &index_parts {
            http_state = http_state.with_index(parts.reader.clone());
            if let Some(arch) = &parts.archive {
                http_state = http_state.with_archive(tron_rpc::ArchiveApiState::new(
                    arch.reader.clone(),
                    arch.backends.clone(),
                ));
            }
            if let Some(commitment) = &parts.commitment {
                http_state = http_state.with_commitment(commitment.reader.clone());
            }
        }
        let addr: std::net::SocketAddr = format!("{}:{}", config.http.host, config.http.port)
            .parse()
            .map_err(|e: std::net::AddrParseError| RunError::Rpc(e.to_string()))?;
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| RunError::Rpc(format!("bind {addr}: {e}")))?;
        info!(bound = %listener.local_addr().unwrap_or(addr), "🌐 HTTP REST listening");
        let mut sd = shutdown.subscribe();
        // Build the HTTP rate-limit registry from config. Each entry
        // binds a path-tail component (lowercased) to a strategy
        // (QPS / IP-QPS / Preemptible). Missing components pass
        // through unlimited, matching java-tron's interceptor
        // behavior on unconfigured servlets.
        let http_limits = build_rate_limit_registry(&config.rate_limiter.http);
        let http_global = tron_rpc::GlobalRateLimiter::new(
            config.rate_limiter.global_qps,
            config.rate_limiter.global_ip_qps,
        );
        let lite_gate_for_http = lite_gate_enabled;
        handles.push(tokio::spawn(async move {
            let shutdown_fut = async move {
                let _ = sd.recv().await;
            };
            let app =
                tron_rpc::http_rest::router_with_limits(http_state, http_limits, http_global);
            let app = tron_rpc::lite_gate::layer(app, lite_gate_for_http);
            let server = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown_fut);
            if let Err(e) = server.await {
                error!(error = %e, "HTTP REST server exited");
            }
        }));
    }

    // === SR runtime (block production) ===
    //
    // When `config.witness` is set, the node steps from "sync-only"
    // to "block-producing SR". The runtime task fires every 500ms,
    // checks slot ownership, and produces+applies+broadcasts a
    // block when it owns the current slot.
    //
    // Each per-peer SyncDriver below subscribes to the produced-
    // blocks channel and forwards every notice as a
    // `MessageType::Block` frame — same pattern as the mempool tx
    // broadcast hook.
    let (sr_produced_tx, pbft_channels, sr_snapshot) = if let Some(witness_cfg) =
        &config.witness
    {
        let sr_identity = crate::sr_runtime::SrIdentity::from_node_config(&config.local_witness, witness_cfg)
            .map_err(|e| RunError::Rpc(format!("SR identity: {e}")))?;
        // PBFT runtime needs its own identity clone (same witness key).
        let pbft_identity = crate::sr_runtime::SrIdentity::from_node_config(&config.local_witness, witness_cfg)
            .map_err(|e| RunError::Rpc(format!("PBFT identity: {e}")))?;

        // Build the cross-rotation SR snapshot seeded from the current
        // on-disk active list. Each SyncDriver below clones this Arc
        // and writes future rotations into it; the PBFT runtime clones
        // it and reads from it on every vote-membership check.
        let initial_active = tron_chainbase::WitnessScheduleStore::new(
            stores.witness_schedule.clone(),
        )
        .load_active()
        .ok()
        .flatten()
        .unwrap_or_default();
        let sr_snapshot = tron_consensus::shared_from_current(initial_active);
        let runtime = crate::sr_runtime::SrRuntime::new(
            stores.to_state_backends(),
            stores.blocks.clone(),
            stores.witness_schedule.clone(),
            // Each SyncDriver builds its own KhaosDb today; the SR
            // runtime needs its own too. KhaosDb push is idempotent
            // (dedup), so the duplicate trees re-converge whenever a
            // block is observed by both paths.
            Arc::new(tron_consensus::KhaosDb::new()),
            tron_chainbase::BlockUndoStore::new(stores.block_undo.clone()),
            mempool.clone(),
            sr_identity,
            witness_cfg.max_txs_per_block,
        )
        .with_metrics(metrics.clone())
        .with_exec_config(exec_config)
        .with_pubsub(pubsub.clone());
        // Witness HA: when a backup group is configured, run the UDP
        // keepalive election and gate production on MASTER status
        // (java BackupManager + BlockHandleImpl.BACKUP_IS_NOT_MASTER).
        let runtime = if !config.node_backup.members.is_empty() {
            let mut sd_backup = shutdown.subscribe();
            let (backup_handle, backup_fut) = crate::backup::start(
                config.node_backup.clone(),
                async move {
                    let _ = sd_backup.recv().await;
                },
            );
            handles.push(tokio::spawn(backup_fut));
            info!(
                members = config.node_backup.members.len(),
                priority = config.node_backup.priority,
                port = config.node_backup.port,
                "witness HA: backup election active — production gated on MASTER"
            );
            runtime.with_backup(backup_handle)
        } else {
            runtime
        };
        let runtime = match &index_hook {
            Some(hook) => runtime.with_index_hook(hook.clone()),
            None => runtime,
        };
        let runtime = if config.storage.snapshot_reorg {
            runtime.with_snapshot_stack(stores.snapshots.clone())
        } else {
            // BlockSession path: attach the cross-store checkpoint
            // so each produced block's writes land behind one
            // durable manifest.
            runtime.with_checkpoint(checkpoint_dir.clone())
        };
        let tx = runtime.subscribe_handle();

        // PBFT runtime: spawn alongside SR. Inbound msgs come from
        // SyncDriver per-peer tasks; outbound votes go to SyncDriver
        // per-peer tasks (forwarded as `MessageType::PbftMsg` frames).
        let pbft_channels = crate::pbft_runtime::PbftChannels::new();
        let pbft_runtime = crate::pbft_runtime::PbftRuntime::new(
            stores.dyn_props.clone(),
            stores.witness_schedule.clone(),
            stores.pbft_sign_data.clone(),
            pbft_identity,
            pbft_channels.clone(),
        )
        .with_common_database(stores.common_database.clone())
        .with_sr_snapshot(sr_snapshot.clone())
        .with_metrics(metrics.clone());

        // Bridge: when our SR produces a block, fire a self-signed
        // Prepare for it. We do this by synthesizing a PbftMessage
        // and pushing it onto the PBFT runtime's INBOUND channel —
        // the runtime's machinery then handles it like any other
        // peer-observed Prepare, including emitting onto outbound
        // for SyncDriver to forward to peers.
        let bridge_channels = pbft_channels.clone();
        let bridge_identity = crate::sr_runtime::SrIdentity::from_node_config(&config.local_witness, witness_cfg)
            .map_err(|e| RunError::Rpc(format!("PBFT bridge identity: {e}")))?;
        let mut produced_rx = tx.subscribe();
        let mut sd_bridge = shutdown.subscribe();
        handles.push(tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = sd_bridge.recv() => break,
                    notice = produced_rx.recv() => {
                        if let Ok(n) = notice {
                            let data = tron_consensus::pbft::block_data_payload(
                                n.block_num,
                                n.block_id.as_bytes(),
                            );
                            if let Ok(msg) = tron_consensus::pbft::cast_prepare(
                                &bridge_identity.witness_priv_key,
                                0,
                                0,
                                tron_proto::protocol::pbft_message::DataType::Block,
                                data,
                            ) {
                                let _ = bridge_channels.inbound.send(msg);
                            }
                        }
                    }
                }
            }
        }));

        // Spawn the PBFT runtime.
        let sd_pbft = shutdown.subscribe();
        handles.push(tokio::spawn(async move {
            pbft_runtime.run(sd_pbft.resubscribe()).await;
        }));

        // Spawn the SR runtime.
        let sd_sr = shutdown.subscribe();
        handles.push(tokio::spawn(async move {
            runtime.run(sd_sr.resubscribe()).await;
        }));

        (Some(tx), Some(pbft_channels), Some(sr_snapshot))
    } else {
        (None, None, None)
    };

    // === Sync driver: one driver, all peers in rotation ===
    //
    // Peer-set assembly:
    //   - Start from `config.p2p.peers` (CLI/TOML-supplied). May be empty —
    //     there is no hardcoded seed list; the node finds peers on its own.
    //   - The DNS tree (trondisco.net) is walked below and its endpoints merged
    //     in (deduped), which is the primary bootstrap with no `--peer`.
    //   - If `config.p2p.discover_enable`, spawn a KadService on the advertise
    //     port (UDP) bootstrapped from the assembled set, wait
    //     `discover_bootstrap_ms` for the routing table to fill, then merge the
    //     discovered peers in (deduped) — talking to the wider TRON network
    //     like a real java-tron node.
    let seed_peers = assemble_peers(&config.p2p);
    let mut combined_peers = seed_peers.clone();

    // Build NodePersistService over the `common` store. java-tron's
    // discovery layer flushes the active table to disk every 60s and
    // re-seeds from it on startup. This is what lets a restart skip
    // re-bootstrapping from discovery when a usable peer set is
    // already on disk.
    let node_persist = crate::node_persist::NodePersistService::new(
        Arc::new(tron_chainbase::CommonStore::new(stores.common.clone())),
        config.p2p.node_discovery_persist,
    );
    // On startup: load persisted peers and merge into combined_peers.
    // We dedupe against the seed set so an explicit CLI peer doesn't
    // get duplicated.
    if node_persist.enabled() {
        let mut seen: std::collections::HashSet<String> =
            combined_peers.iter().cloned().collect();
        let mut loaded = 0usize;
        for node in node_persist.read() {
            let s = format!("{}:{}", node.host, node.port);
            if seen.insert(s.clone()) {
                combined_peers.push(s);
                loaded += 1;
            }
        }
        if loaded > 0 {
            info!(
                loaded,
                total_unique = combined_peers.len(),
                "node_persist: re-seeded discovery from disk"
            );
        }
    }

    // `--explore` tip discovery + dashboard is set up below, AFTER peer
    // discovery has populated `combined_peers` (we probe discovered peers for
    // the live tip, not the overloaded hardcoded seeds).

    // Shared, continuously-grown discovery pool for rotation drivers
    // (java-tron-like always-active discovery). The Kad feeder below
    // appends freshly-discovered peers to it on a timer; each rotation
    // driver merges new entries into its working dial set so a long-running
    // node keeps finding peers as the startup snapshot ages. Bounded so a
    // months-long run can't grow it without limit.
    const DYNAMIC_POOL_CAP: usize = 4096;
    let dynamic_pool: Arc<std::sync::Mutex<Vec<String>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));

    if !config.p2p.disabled && config.p2p.discover_enable && !seed_peers.is_empty() {
        let seed_socks: Vec<std::net::SocketAddr> = seed_peers
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        let bind_addr: std::net::SocketAddr =
            format!("0.0.0.0:{}", config.p2p.advertise_port).parse().unwrap();
        let home_id = random_node_id_64();
        let public_addr: std::net::SocketAddr =
            format!("0.0.0.0:{}", config.p2p.advertise_port).parse().unwrap();
        let network_id = tron_net::MAINNET_P2P_VERSION;
        match tron_net::KadService::new(bind_addr, home_id, public_addr, network_id, seed_socks)
            .await
        {
            Ok(kad) => {
                let handle = kad.handle();
                let sd_kad = shutdown.subscribe();
                handles.push(tokio::spawn(async move {
                    kad.run(async move {
                        let mut sd = sd_kad;
                        let _ = sd.recv().await;
                    })
                    .await;
                }));
                // Block briefly so the first wave of pongs/neighbours can
                // populate the table. After this we snapshot — if more
                // peers arrive later they're picked up on the next run.
                tokio::time::sleep(Duration::from_millis(
                    config.p2p.discover_bootstrap_ms,
                ))
                .await;
                let discovered = handle.known_peers();
                let discovered_n = discovered.len();
                let mut seen: std::collections::HashSet<String> =
                    combined_peers.iter().cloned().collect();
                for addr in &discovered {
                    let s = addr.to_string();
                    if seen.insert(s.clone()) {
                        combined_peers.push(s);
                    }
                }
                info!(
                    seeds = seed_peers.len(),
                    discovered = discovered_n,
                    total_unique = combined_peers.len(),
                    "kad: bootstrap snapshot taken"
                );

                // Periodic flush: every 60s by default, snapshot the
                // KadService's known-peers table and persist up to
                // `MAX_NODES_WRITE_TO_DB` of them via
                // NodePersistService. On shutdown, do one final flush
                // so the next restart has the latest set. java-tron
                // parity: `NodePersistService.init` / `db_commit`.
                if node_persist.enabled() {
                    let persist = node_persist.clone();
                    let kad_handle = handle.clone();
                    let interval_ms = config.p2p.node_discovery_persist_interval_ms;
                    let mut sd_persist = shutdown.subscribe();
                    handles.push(tokio::spawn(async move {
                        let mut ticker = tokio::time::interval(Duration::from_millis(
                            interval_ms.max(1_000),
                        ));
                        ticker.tick().await; // skip the immediate tick
                        loop {
                            tokio::select! {
                                _ = sd_persist.recv() => {
                                    // Final flush on shutdown. `write_batch`
                                    // returns a count and logs any store error
                                    // internally, so discarding it is correct.
                                    let snap = snapshot_for_persist(&kad_handle);
                                    let _ = persist.write_batch(&snap);
                                    return;
                                }
                                _ = ticker.tick() => {
                                    let snap = snapshot_for_persist(&kad_handle);
                                    let _ = persist.write_batch(&snap);
                                }
                            }
                        }
                    }));
                }

                // Always-active discovery feeder: every 30s, fold the
                // KadService's freshly-discovered peers into the shared
                // rotation pool (deduped, capped). Rotation drivers pick
                // these up on their next loop, so the dial set keeps
                // refreshing for the life of the process — no restart
                // needed to reach peers found after startup. Mirrors
                // java-tron's continuously-refreshed node table.
                {
                    let feeder_handle = handle.clone();
                    let feeder_pool = dynamic_pool.clone();
                    let mut sd_feeder = shutdown.subscribe();
                    handles.push(tokio::spawn(async move {
                        let mut ticker = tokio::time::interval(Duration::from_secs(30));
                        ticker.tick().await; // skip immediate tick
                        loop {
                            tokio::select! {
                                _ = sd_feeder.recv() => return,
                                _ = ticker.tick() => {
                                    let discovered = feeder_handle.known_peers();
                                    if let Ok(mut g) = feeder_pool.lock() {
                                        let mut added = 0usize;
                                        for addr in discovered {
                                            let s = addr.to_string();
                                            if g.contains(&s) {
                                                continue;
                                            }
                                            // FIFO-evict the oldest at the cap so a
                                            // long run keeps cycling in freshly-
                                            // discovered peers instead of freezing
                                            // on the first cap-full snapshot.
                                            if g.len() >= DYNAMIC_POOL_CAP {
                                                g.remove(0);
                                            }
                                            g.push(s);
                                            added += 1;
                                        }
                                        if added > 0 {
                                            debug!(
                                                added,
                                                pool = g.len(),
                                                "discovery feeder: new peers folded into rotation pool"
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }));
                }
            }
            Err(e) => {
                warn!(error = %e, port = config.p2p.advertise_port,
                      "kad: UDP bind failed; continuing with seed-only dial list");
            }
        }
    }

    // DNS-tree discovery (EIP-1459-style). For each configured
    // `tree://{pubkey}@{domain}` URL, walk the TXT-record tree and
    // merge the discovered endpoints into the dial list. This is the
    // production peer-discovery path — the mainnet tree typically
    // returns 2000+ endpoints, dwarfing the 13 hardcoded seeds.
    if !config.p2p.disabled && !config.p2p.discover_tree_urls.is_empty() {
        let query_timeout = Duration::from_millis(config.p2p.discover_tree_query_timeout_ms);
        let mut tree_total = 0usize;
        let mut seen: std::collections::HashSet<String> =
            combined_peers.iter().cloned().collect();
        for url in &config.p2p.discover_tree_urls {
            match tron_net::resolve_dns_tree(url, query_timeout).await {
                Ok(eps) => {
                    let n = eps.len();
                    tree_total += n;
                    for addr in eps {
                        let s = addr.to_string();
                        if seen.insert(s.clone()) {
                            combined_peers.push(s);
                        }
                    }
                    info!(url = url.as_str(), endpoints = n,
                          total_unique = combined_peers.len(),
                          "dns: tree walk complete");
                }
                Err(e) => {
                    warn!(url = url.as_str(), error = %e,
                          "dns: tree walk failed; continuing");
                }
            }
        }
        if tree_total > 0 {
            info!(
                tree_endpoints_total = tree_total,
                combined_peers = combined_peers.len(),
                "dns: discovery complete"
            );
        }
    }

    // Periodic DNS-tree refresh. The walk above is a one-shot startup
    // snapshot; on a long run those endpoints go stale (good servers drop
    // off, dial targets die), and without `discover_enable` there is no Kad
    // feeder replenishing the rotation pool — so a sync-only node's
    // throughput decays until a manual restart re-walks the tree. Re-walk on
    // a timer and fold fresh endpoints into the shared `dynamic_pool` the
    // rotation drivers consume, independent of `discover_enable`. The drivers
    // already demote dead peers via per-peer backoff; this keeps a fresh
    // supply flowing in to replace them.
    if !config.p2p.disabled && !config.p2p.discover_tree_urls.is_empty() {
        let urls = config.p2p.discover_tree_urls.clone();
        let query_timeout = Duration::from_millis(config.p2p.discover_tree_query_timeout_ms);
        let refresh_pool = dynamic_pool.clone();
        let mut sd_dns = shutdown.subscribe();
        // Gentle on the tree's DNS, frequent enough to cycle in fresh peers
        // well within a single multi-hour sync.
        const DNS_REFRESH_INTERVAL: Duration = Duration::from_secs(600);
        handles.push(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(DNS_REFRESH_INTERVAL);
            ticker.tick().await; // skip the immediate tick — startup already walked
            loop {
                tokio::select! {
                    _ = sd_dns.recv() => return,
                    _ = ticker.tick() => {
                        let mut fresh: Vec<String> = Vec::new();
                        for url in &urls {
                            match tron_net::resolve_dns_tree(url, query_timeout).await {
                                Ok(eps) => {
                                    fresh.extend(eps.into_iter().map(|a| a.to_string()))
                                }
                                Err(e) => warn!(
                                    url = url.as_str(), error = %e,
                                    "dns: periodic tree re-walk failed; continuing"
                                ),
                            }
                        }
                        if fresh.is_empty() {
                            continue;
                        }
                        if let Ok(mut g) = refresh_pool.lock() {
                            let present: std::collections::HashSet<String> =
                                g.iter().cloned().collect();
                            let mut added = 0usize;
                            for s in fresh {
                                if present.contains(&s) {
                                    continue;
                                }
                                // FIFO-evict the oldest entry at the cap so fresh
                                // peers always get a slot — otherwise a long run
                                // freezes on the first cap-full snapshot. The
                                // rotation drivers keep already-dialed peers in
                                // their own working set, so an eviction here only
                                // stops the pool from blocking new discoveries.
                                if g.len() >= DYNAMIC_POOL_CAP {
                                    g.remove(0);
                                }
                                g.push(s);
                                added += 1;
                            }
                            if added > 0 {
                                info!(
                                    added, pool = g.len(),
                                    "dns: periodic re-walk folded fresh peers into rotation pool"
                                );
                            }
                        }
                    }
                }
            }
        }));
    }

    // `--explore` / `--mempool` live dashboards. Both bootstrap from a real
    // recent tip and follow the live tail decode-only; `--mempool` additionally
    // watches the pending tx stream peers broadcast once we're at the tip.
    //
    // Bootstrap tip: an explicit `--tip-test` checkpoint wins; otherwise
    // discover it over p2p from the freshly DISCOVERED peer pool (not the
    // hardcoded seeds — those bootstrap nodes are overloaded and ban new
    // dials). We ask peers for their head, spoof ours to it, then `follow_tip`
    // makes the drivers anchor there and stream the live tail. Renderers paint
    // to stdout (logs go to stderr). `--mempool` takes precedence when both
    // flags are set.
    let mut explore_state: Option<Arc<crate::explore::ExploreState>> = None;
    if config.p2p.explore || config.p2p.mempool {
        let mode = if config.p2p.mempool { "mempool" } else { "explore" };
        let tip_num = if let Some(cp) = &config.p2p.tip_test {
            cp.block_num
        } else {
            // Discovering + spoofing the tip moves the head pointer forward
            // without applying blocks; refuse on a data-dir that already holds
            // a synced chain so the dashboard never clobbers a real node's head
            // (see `guard_head_spoof`). The `--tip-test` branch above already
            // went through the same guard.
            guard_head_spoof(&stores, &format!("--{mode}"))?;
            info!("{mode}: discovering the live tip from the peer network…");
            match discover_tip(&combined_peers).await {
                Some((num, hash)) => {
                    use tron_chainbase::DynamicPropertiesStore;
                    let dp = DynamicPropertiesStore::new(stores.dyn_props.clone());
                    dp.save_latest_block_header_number(num);
                    dp.save_latest_block_header_hash(&hash);
                    info!(tip = num, "{mode}: locked onto the live tip");
                    num
                }
                None => {
                    error!(
                        "{mode}: couldn't reach a peer to learn the tip — check your \
                         connection, or pass --peer HOST:18888"
                    );
                    0
                }
            }
        };
        if config.p2p.mempool {
            // Pending txs flow into the shared mempool via the sync driver's
            // inbound `Trx` / `Trxs` handlers once we reach the tip; the
            // observer subscribes to that mempool and folds each into the
            // dashboard state. No explore (block) dashboard in this mode.
            let jsonl = config.p2p.mempool_json.as_deref().map(|p| {
                Arc::new(if p == "-" {
                    crate::mempool_explore::JsonlSink::Stdout
                } else {
                    crate::mempool_explore::JsonlSink::File(std::path::PathBuf::from(p))
                })
            });
            let st = Arc::new(crate::mempool_explore::MempoolState::new(tip_num));
            tokio::spawn(crate::mempool_explore::run_observer(
                st.clone(),
                mempool.clone(),
                jsonl,
                shutdown.subscribe(),
            ));
            tokio::spawn(crate::mempool_explore::run_renderer(
                st,
                shutdown.subscribe(),
            ));
        } else {
            let st = Arc::new(crate::explore::ExploreState::new(tip_num));
            st.set_discovered(combined_peers.len());
            tokio::spawn(crate::explore::run_renderer(st.clone(), shutdown.subscribe()));
            explore_state = Some(st);
        }
    }

    // Filter out peers we dialed recently — within the upstream's 60s
    // `bannedNodes` window (plus margin). Re-dialing immediately after
    // a restart would just refresh those bans, locking us out for
    // another window. The state file at `data_dir/peer_state.json`
    // tracks last-dial timestamps across binary restarts.
    let peer_state = crate::peer_state::PeerState::load(&config.data_dir);
    let pruned_old = peer_state.prune(24 * 60 * 60 * 1000);
    if pruned_old > 0 {
        debug!(
            removed = pruned_old,
            "peer-state: pruned entries older than 24h"
        );
    }
    let before_filter = combined_peers.len();
    let filtered_out: Vec<String> = combined_peers
        .iter()
        .filter(|p| peer_state.was_dialed_recently(p))
        .cloned()
        .collect();
    combined_peers.retain(|p| !peer_state.was_dialed_recently(p));
    if !filtered_out.is_empty() {
        info!(
            skipped = filtered_out.len(),
            remaining = combined_peers.len(),
            window_ms = crate::peer_state::SKIP_AFTER_DIAL_MS,
            "peer-state: skipping recently-dialed peers"
        );
        if combined_peers.is_empty() {
            warn!(
                "peer-state filtered the entire dial list; restoring to avoid stall"
            );
            combined_peers = filtered_out;
        } else {
            let _ = before_filter;
        }
    }

    // The FULL discovered set — every peer DNS + Kad + persistence found
    // (typically 2500+). Rotation drivers hunt across ALL of these for an
    // available peer; `max_peers` bounds the number of concurrent
    // CONNECTIONS (rotation driver count) below, NOT the size of the pool
    // they search. Capping the pool here (as the old code did) starved
    // rotation down to a handful of mostly-saturated peers — the reason
    // public-peer sync didn't work.
    let full_discovered_pool: Vec<String> = combined_peers.clone();
    // Keep `combined_peers` capped only as the bound on driver COUNT (the
    // emptiness check below + the rotation-driver budget). Shuffle the
    // non-seed tail so the sample is diverse.
    if combined_peers.len() > config.p2p.max_peers {
        let seed_count = seed_peers.len().min(combined_peers.len());
        let (head, tail) = combined_peers.split_at_mut(seed_count);
        use rand::seq::SliceRandom;
        tail.shuffle(&mut rand::thread_rng());
        let mut shuffled: Vec<String> = head.iter().cloned().collect();
        // saturating_sub: when `max_peers` < seed count (a small-VM
        // config), keep just the seeds rather than underflow-panicking.
        shuffled.extend(
            tail.iter()
                .take(config.p2p.max_peers.saturating_sub(seed_count))
                .cloned(),
        );
        combined_peers = shuffled;
    }

    // Shared process-wide inbound-bytes budget (N-3): a single ceiling on
    // frame bytes being buffered across ALL peer connections — the inbound
    // server AND every outbound dialer draw from this one pool. Without it
    // the per-frame `MAX_FRAME_BYTES` (10 MiB) multiplies into
    // `peers × 10 MiB` of potentially-pinned RAM under a many-peer flood
    // (~2 GiB at 200 peers). 512 MiB sits far above normal use (a handful
    // of peers mid-block is tens of MiB) while capping the pathological case;
    // a peer whose frame would breach the ceiling is shed with
    // `FrameError::BudgetExceeded` and reconnects.
    const INBOUND_BUDGET_BYTES: usize = 512 * 1024 * 1024;
    let inbound_budget = tron_net::InboundByteBudget::new(INBOUND_BUDGET_BYTES);

    // Inbound P2P listener — lets other peers (java-tron deployments and our
    // own kind) sync FROM us. Independent of the outbound dialers below: we
    // serve even with zero configured outbound peers. Bind failures are
    // non-fatal (the node keeps running as an outbound-only client).
    if config.p2p.listen && !config.p2p.disabled {
        let listen_host = config.p2p.listen_host.clone();
        let listen_port = config.p2p.advertise_port;
        match format!("{listen_host}:{listen_port}").parse::<std::net::SocketAddr>() {
            Ok(addr) => {
                let inbound_state = stores.to_state_backends();
                let server = std::sync::Arc::new(
                    crate::inbound::InboundServer::new(
                        inbound_state.block_index.clone(),
                        stores.blocks.clone(),
                        inbound_state.dyn_props.clone(),
                        Some(mempool.clone()),
                        tron_types::genesis_block_id(&tron_types::mainnet_inputs()),
                        config.p2p.advertise_port,
                        Some(metrics.clone()),
                        config.p2p.max_peers,
                    )
                    .with_inbound_budget(inbound_budget.clone()),
                );
                let sd = shutdown.subscribe();
                handles.push(tokio::spawn(crate::inbound::run_inbound_listener(
                    server, addr, sd,
                )));
            }
            Err(e) => {
                warn!(listen_host, listen_port, error = %e,
                    "invalid p2p listen address — inbound listener disabled");
            }
        }
    }

    if !config.p2p.disabled && !combined_peers.is_empty() {
        // Multi-peer sync: one independent `SyncDriver` per configured
        // peer, each running in its own tokio task. They share the
        // RocksDB backends (Arc-cloned), metrics sink, and mempool, so
        // accepted blocks all land in the same store and metric
        // counters aggregate globally. Each driver maintains its own
        // local `prev_id`/dispatch state and its own `DriverStats`;
        // a single follower task aggregates per-peer stats once all
        // drivers exit, then emits the combined `sync driver stats`
        // log line.
        //
        // Duplication trade-off: with N peers all syncing from the
        // same head, each will try to fetch overlapping block ranges
        // (each driver thinks it is the only one). RocksDB last-write
        // wins so correctness is preserved, but bandwidth and CPU are
        // wasted on duplicate `accept_block` calls. The win is
        // reliability — any single peer going down doesn't stall the
        // chain because the others keep advancing the head.
        let state = stores.to_state_backends();
        let blocks_backend = stores.blocks.clone();
        let undo_backend = stores.block_undo.clone();
        let mut driver_handles = Vec::new();
        // Pre-compute fast-forward membership once. Operator-supplied
        // `fastForwardNodes` entries are compared by full HOST:PORT
        // string (matches the peer key used by the driver) — IP-only
        // entries would need normalisation that this loader doesn't
        // do today.
        let fast_forward_set: std::collections::HashSet<String> = config
            .p2p
            .fast_forward_nodes
            .iter()
            .cloned()
            .collect();

        // Shared P2P-scoring scaffolding: each SyncDriver writes
        // touches + disconnect reasons against `node_stats`; each
        // registers itself in `peer_registry` on handshake-success.
        // `ResilienceService` periodically reads the registry and
        // broadcasts an eviction peer-key on `eviction_tx`, which the
        // matching SyncDriver observes inside its loop.
        let node_stats = crate::node_statistics::NodeStatisticsTable::new();
        // Periodic prune of the per-peer statistics table — it's keyed by
        // peer and entries were never removed in production, so over a
        // long run with rotation touching thousands of distinct peers it
        // grew without bound. Drop entries idle > 1h every 5 min.
        {
            let pruner = node_stats.clone();
            let mut sd_prune = shutdown.subscribe();
            handles.push(tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(300));
                tick.tick().await; // skip immediate tick
                loop {
                    tokio::select! {
                        _ = sd_prune.recv() => return,
                        _ = tick.tick() => {
                            pruner.prune_older_than(Duration::from_secs(3600)).await;
                        }
                    }
                }
            }));
        }
        let peer_registry = crate::PeerRegistry::new();
        let (eviction_tx, _eviction_rx_keep_alive) =
            tokio::sync::broadcast::channel::<String>(64);
        // Single-active-syncer coordinator shared by every per-peer driver:
        // exactly one leads (requests + applies blocks) while the rest
        // stand by, so concurrent drivers don't race the shared head.
        let leadership = std::sync::Arc::new(crate::sync::SyncLeadership::new());

        // Cooperative multi-peer fetch pool, shared by every driver: workers
        // fetch the backlog in parallel (each within its peer's offered
        // window) and the leader applies in order. `None` ⇒ single-peer path.
        let fetch_pool = if config.p2p.multi_peer_fetch {
            Some(std::sync::Arc::new(crate::sync::SyncFetchPool::new()))
        } else {
            None
        };
        info!(multi_peer_fetch = config.p2p.multi_peer_fetch, "cooperative fetch");

        // Active-peers gauge sampler. Reads `peer_registry.len()` every
        // 5 s and pushes it into the metrics handle so a Prometheus
        // scrape always reflects current connection count even between
        // explicit register/unregister events.
        {
            let m = metrics.clone();
            let reg = peer_registry.clone();
            let mut sd = shutdown.subscribe();
            handles.push(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = sd.recv() => break,
                        _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                    }
                    m.set_active_peers(reg.len() as i64);
                }
            }));
        }
        // Spawn the resilience service. We tick once a minute (java-
        // tron uses 10–30s; one minute is plenty for a node-driver
        // scheduler that's mostly a safety net). The decision channel
        // is `eviction_tx`; SyncDrivers `subscribe()` to receive
        // peer-keys to drop.
        //
        // The policy's per-peer inputs are live: the sync driver updates
        // `need_sync_from_peer` on every ChainInventory, `need_sync_from_us`
        // on every SyncBlockChain it serves, and `block_recv_ms` on every
        // Block frame — so the isolation-breakout rule (no block from ANY
        // peer for 60s while we hold adv-eligible peers) can actually fire.
        // `open_full_tcp_disconnect` stays false deliberately: the random-
        // elimination rule exists for nodes accepting inbound connections at
        // their cap, which we don't yet do; with all-outbound dialers it
        // would only churn useful peers.
        {
            let resilience = crate::resilience::ResilienceService {
                config: crate::resilience::ResilienceConfig {
                    max_connections: config.p2p.max_peers,
                    min_connections: 8,
                    min_active_connections: 1,
                    inactive_threshold: std::time::Duration::from_secs(600),
                    block_not_change_threshold: std::time::Duration::from_secs(60),
                    retention_percent: 0.8,
                    min_broadcast_peer_size: 3,
                },
                statistics: node_stats.clone(),
                tick_interval: std::time::Duration::from_secs(60),
                open_full_tcp_disconnect: false,
            };
            let registry_for_peers_fn = peer_registry.clone();
            let eviction_tx_resilience = eviction_tx.clone();
            let (decisions_tx, mut decisions_rx) =
                tokio::sync::mpsc::channel::<crate::resilience::ResilienceDecision>(64);
            let mut sd_resilience = shutdown.subscribe();
            // Consumer: forward each decision's peer key onto the
            // eviction broadcast channel + log it. Closes on
            // shutdown.
            handles.push(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = sd_resilience.recv() => return,
                        msg = decisions_rx.recv() => {
                            let Some(decision) = msg else { return };
                            info!(
                                peer = %decision.peer_key,
                                cause = ?decision.cause,
                                "resilience: evicting peer"
                            );
                            let _ = eviction_tx_resilience.send(decision.peer_key);
                        }
                    }
                }
            }));
            handles.push(tokio::spawn(async move {
                resilience
                    .run(move || registry_for_peers_fn.snapshot(), decisions_tx)
                    .await;
            }));
        }
        // Peer connectivity model (java-tron-like). Explicitly-configured
        // peers (`--peer` / `config.peers`) each get a DEDICATED driver
        // pinned to that one peer, so a reliable configured peer (e.g. a
        // LAN node) is always dialed. The rest of the connection budget is
        // filled with ROTATION drivers, each handed the FULL discovered
        // pool — the driver's built-in rotation then hunts across every
        // known peer for an available one instead of being pinned to a
        // single (usually-saturated) peer. This is what makes syncing from
        // public peers work even with no configured peer; without it each
        // driver re-dialed one fixed peer forever (a 1-element pool makes
        // the rotation logic a no-op).
        let configured_set: std::collections::HashSet<String> =
            config.p2p.peers.iter().cloned().collect();
        // Rotation drivers search the FULL discovered pool (not the
        // driver-count-capped `combined_peers`), so they can hunt across
        // thousands of peers for an available one.
        let rotation_pool: Vec<String> = full_discovered_pool
            .iter()
            .filter(|p| !configured_set.contains(*p))
            .cloned()
            .collect();
        // `(peers_for_driver, pinned)` — pinned drivers keep the exact
        // single-peer behaviour; rotation drivers share the full pool.
        let mut driver_specs: Vec<(Vec<String>, bool)> = config
            .p2p
            .peers
            .iter()
            .map(|p| (vec![p.clone()], true))
            .collect();
        // Cap the rotation fleet. Each rotation driver is a full sync task
        // (own fork tree, own mempool-broadcast subscription, a live
        // connection) — 60 of them is wasteful (extra GBs of fork-tree RAM,
        // 60 broadcast subscribers → "broadcast channel lagged" drops, and
        // CPU forwarding every tx 60×). A couple dozen rotating connections
        // give ample peer diversity + failover while staying light for
        // months-long uptime. Each still hunts the FULL discovered pool.
        const MAX_ROTATION_DRIVERS: usize = 24;
        let n_rotation = config
            .p2p
            .max_peers
            .saturating_sub(driver_specs.len())
            .min(MAX_ROTATION_DRIVERS);
        if !rotation_pool.is_empty() {
            for _ in 0..n_rotation.max(1) {
                driver_specs.push((rotation_pool.clone(), false));
            }
        }
        info!(
            pinned = config.p2p.peers.len(),
            rotation_drivers = driver_specs.iter().filter(|(_, p)| !p).count(),
            pool_size = rotation_pool.len(),
            "peer drivers: configured peers pinned, rest rotate the full discovered pool"
        );
        // === Event subscription ([event] → plugin registry → EventBus) ===
        //
        // java-tron's EventPluginLoader equivalent: the registry holds the
        // compiled-in sinks (kafka today); `[event] enable = true` +
        // `path` pick one and every applied block fans out the java-shaped
        // triggers (block/transaction/contractevent/contractlog/solidity),
        // post-filter. Disabled → empty bus, zero per-block cost.
        let event_bus = {
            let mut registry = tron_eventer::PluginRegistry::new();
            registry.register(tron_eventer_kafka::KafkaPluginFactory);
            match crate::event_loader::build_event_bus(config.event.as_ref(), &registry) {
                Ok(bus) => {
                    if !bus.is_empty() {
                        info!("event plugin: bus active");
                    }
                    bus
                }
                Err(e) => {
                    error!(error = %e, "event plugin: loader failed; continuing WITHOUT event subscription");
                    tron_eventer::EventBus::default()
                }
            }
        };

        // Pipelined block apply (`vm.pipelined_apply`, default on): the
        // leader's drain batches overlap each block's commit + undo-log
        // I/O with the next block's execution. Gated off when this node
        // produces blocks — the SR runtime applies its own blocks to the
        // shared state outside the sync driver, and the pipeline's
        // visibility overlay must be the only in-flight writer. The
        // snapshot-stack reorg path ignores the flag internally.
        let pipelined_apply_enabled = config.vm.pipelined_apply && config.witness.is_none();
        if config.vm.pipelined_apply && config.witness.is_some() {
            info!("vm.pipelined_apply disabled: witness mode applies blocks outside the sync drivers");
        }
        for (driver_peers, pinned) in driver_specs {
            let peer_is_fast_forward = pinned
                && driver_peers
                    .first()
                    .map(|p| fast_forward_set.contains(p))
                    .unwrap_or(false);
            // Label for stats aggregation: the peer for a pinned driver,
            // or a generic tag for a rotation driver (which cycles many).
            let driver_label = if pinned {
                driver_peers
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "pinned".to_string())
            } else {
                "rotation".to_string()
            };
            let cfg = crate::sync::SyncConfig {
                peers: driver_peers,
                max_blocks: config.p2p.max_blocks,
                tail_interval: std::time::Duration::from_secs(3),
                initial_backoff: std::time::Duration::from_secs(5),
                blocks_backend: blocks_backend.clone(),
                progress_log_interval: config.p2p.progress_log_interval,
                advertise_port: config.p2p.advertise_port,
                tip_test: config.p2p.tip_test.is_some(),
                p2p_rate_limits: config.rate_limiter.p2p.clone(),
                fetch_block_timeout: std::time::Duration::from_millis(
                    config.p2p.fetch_block_timeout_ms.clamp(100, 1000),
                ),
                fetch_inflight_per_peer: config
                    .p2p
                    .sync_fetch_inflight_per_peer
                    .clamp(16, 100),
                peer_is_fast_forward,
                follow_tip: config.p2p.follow_tip,
            };
            let sd = shutdown.subscribe();
            let state_for_peer = state.clone();
            let metrics_for_peer = metrics.clone();
            let mempool_for_peer = mempool.clone();
            let undo_for_peer = tron_chainbase::BlockUndoStore::new(undo_backend.clone());
            let produced_for_peer = sr_produced_tx.clone();
            let pbft_for_peer = pbft_channels.clone();
            let peer_state_for_peer = peer_state.clone();
            let sr_snapshot_for_peer = sr_snapshot.clone();
            let node_stats_for_peer = node_stats.clone();
            let peer_registry_for_peer = peer_registry.clone();
            let eviction_tx_for_peer = eviction_tx.clone();
            let leadership_for_peer = leadership.clone();
            let exec_config_for_peer = exec_config;
            let snapshot_stack_for_peer = if config.storage.snapshot_reorg {
                Some(stores.snapshots.clone())
            } else {
                None
            };
            // BlockSession-path checkpoint: only attach when the
            // snapshot stack isn't (the stack already wraps cross-
            // store atomicity in its own manifest flow).
            let checkpoint_for_peer = if config.storage.snapshot_reorg {
                None
            } else {
                Some(checkpoint_dir.clone())
            };
            let pubsub_for_peer = pubsub.clone();
            // Rotation drivers (not pinned to a configured peer) share the
            // continuously-grown discovery pool; pinned drivers keep their
            // fixed single peer.
            let dynamic_pool_for_peer = if pinned {
                None
            } else {
                Some(dynamic_pool.clone())
            };
            let fetch_pool_for_peer = fetch_pool.clone();
            let explore_for_peer = explore_state.clone();
            let index_hook_for_peer = index_hook.clone();
            let event_bus_for_peer = event_bus.clone();
            let inbound_budget_for_peer = inbound_budget.clone();
            driver_handles.push(tokio::spawn(async move {
                let mut driver = crate::sync::SyncDriver::new(state_for_peer, cfg)
                    .with_metrics(metrics_for_peer)
                    .with_mempool(mempool_for_peer)
                    .with_undo_store(undo_for_peer)
                    .with_inbound_budget(inbound_budget_for_peer)
                    .with_peer_state(peer_state_for_peer)
                    .with_node_statistics(node_stats_for_peer)
                    .with_peer_registry(peer_registry_for_peer)
                    .with_eviction_signal(eviction_tx_for_peer)
                    .with_exec_config(exec_config_for_peer)
                    .with_pubsub(pubsub_for_peer)
                    .with_leadership(leadership_for_peer)
                    // Production runs the per-tx replay gate. The
                    // `BlockIndexStore` is populated from
                    // `initialize_genesis` onward, so the validator
                    // has chain history to compare against.
                    .with_strict_ref_block_check();
                if let Some(dp) = dynamic_pool_for_peer {
                    driver = driver.with_dynamic_pool(dp);
                }
                if let Some(fp) = fetch_pool_for_peer {
                    driver = driver.with_fetch_pool(fp);
                }
                if let Some(hook) = index_hook_for_peer {
                    driver = driver.with_index_hook(hook);
                }
                if let Some(stack) = snapshot_stack_for_peer {
                    driver = driver.with_snapshot_stack(stack);
                }
                if let Some(cp) = checkpoint_for_peer {
                    driver = driver.with_checkpoint(cp);
                }
                if let Some(tx) = produced_for_peer {
                    driver = driver.with_produced_blocks(tx);
                }
                if let Some(ch) = pbft_for_peer {
                    driver = driver.with_pbft(ch);
                }
                if let Some(snap) = sr_snapshot_for_peer {
                    driver = driver.with_sr_snapshot(snap);
                }
                if pipelined_apply_enabled {
                    driver = driver.with_pipelined_apply();
                }
                driver = driver.with_event_bus(event_bus_for_peer);
                if let Some(explore) = explore_for_peer {
                    driver = driver.with_explore(explore);
                }
                (driver_label, driver.run(sd).await)
            }));
        }
        // Periodic peer-state flush — every 30s the dial-recency
        // tracker writes to disk so a crashing binary doesn't lose
        // more than 30s of dial history.
        let peer_state_flusher = peer_state.clone();
        let mut sd_flush = shutdown.subscribe();
        handles.push(tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(30));
            tick.tick().await; // skip immediate first tick
            loop {
                tokio::select! {
                    _ = sd_flush.recv() => {
                        peer_state_flusher.flush();
                        return;
                    }
                    _ = tick.tick() => {
                        // Prune dial-recency entries older than 24h before
                        // flushing — otherwise the map (and its JSON file)
                        // grows unbounded over a long run as rotation dials
                        // thousands of distinct peers. (`prune` ran only at
                        // startup before; now it runs every flush.)
                        peer_state_flusher.prune(24 * 60 * 60 * 1000);
                        peer_state_flusher.flush();
                    }
                }
            }
        }));
        // Aggregator task: collect per-peer stats once all drivers
        // exit (cap hit, shutdown, or unrecoverable failure).
        handles.push(tokio::spawn(async move {
            let mut combined = crate::sync::DriverStats::default();
            for h in driver_handles {
                match h.await {
                    Ok((peer, stats)) => {
                        info!(
                            peer = %peer,
                            applied = stats.blocks_applied,
                            val_rej = stats.blocks_rejected_validation,
                            exec_rej = stats.blocks_rejected_execution,
                            peer_failures = stats.peer_failures,
                            reconnects = stats.reconnects,
                            "per-peer sync stats"
                        );
                        combined.blocks_applied += stats.blocks_applied;
                        combined.blocks_rejected_validation +=
                            stats.blocks_rejected_validation;
                        combined.blocks_rejected_execution +=
                            stats.blocks_rejected_execution;
                        combined.peer_failures += stats.peer_failures;
                        combined.reconnects += stats.reconnects;
                    }
                    Err(e) => warn!(error = %e, "sync driver task panicked"),
                }
            }
            info!(
                applied = combined.blocks_applied,
                validation_rejects = combined.blocks_rejected_validation,
                execution_rejects = combined.blocks_rejected_execution,
                peer_failures = combined.peer_failures,
                reconnects = combined.reconnects,
                "sync driver stats"
            );
        }));
    }

    if handles.is_empty() {
        // Neither RPC nor sync — nothing to do except wait for Ctrl-C.
        warn!(
            rpc_disabled = config.rpc.disabled,
            p2p_disabled = config.p2p.disabled,
            "no subsystems enabled; holding open until shutdown"
        );
    }

    // === Block until shutdown ===
    // Subscribe *before* checking the sticky flag: if shutdown already
    // fired during startup (Ctrl-C before we got here), the broadcast
    // message is gone, but `is_shutdown()` still reports it — so we skip
    // the `recv()` that would otherwise block forever. If it hasn't fired,
    // the subscription guarantees we catch the next `send()`.
    let mut sd = shutdown.subscribe();
    if !shutdown.is_shutdown() {
        let _ = sd.recv().await;
    }
    info!("👋 shutdown observed; waiting up to 3s for subsystems to drain");

    // Give subsystems a grace window to drain gracefully, then force-abort
    // any stragglers. Most tasks observe the shutdown broadcast and return
    // within ~1s, but a server doing a graceful HTTP/gRPC shutdown can sit
    // waiting on an idle keep-alive connection from a monitoring client
    // (Prometheus scraping :9090, a wallet polling :8090) until that client
    // disconnects. Aborting the stragglers — rather than waiting out the
    // runtime's own shutdown timeout — keeps Ctrl-C/SIGTERM snappy.
    //
    // Aborting is safe for everything in the straggler set. The tasks that
    // write durable state — the sync drivers (block apply) and the SR
    // producer — observe the shutdown broadcast at every loop iteration and
    // exit at a clean boundary, never mid-commit, so they self-terminate
    // well inside the grace window. The drivers are not even in this handle
    // set (they're awaited via the aggregator), so an abort here cannot land
    // mid-apply. A block's commit I/O runs in a synchronous `run_blocking`
    // closure that cannot be cancelled by `abort()`; any pipelined commit is
    // flushed before that closure returns, and a crash mid-flush replays from
    // the retained checkpoint manifest on the next startup. The remaining
    // straggler candidates are network servers and periodic samplers with no
    // durable mid-operation state. The peer_state flusher is shutdown-driven
    // and also exits inside the grace window.
    let abort_handles: Vec<_> = handles.iter().map(|h| h.abort_handle()).collect();
    let drain = tokio::time::timeout(Duration::from_secs(3), async {
        for h in handles {
            let _ = h.await;
        }
    });
    if drain.await.is_err() {
        warn!("subsystems did not drain in 3s; aborting stragglers");
        for ah in &abort_handles {
            ah.abort();
        }
    }
    info!("💀 bye");
    Ok(())
}

// `sync_supervisor` was replaced by `crate::sync::SyncDriver`, which
// persists accepted blocks, resumes from disk, rotates across multiple
// peers, and validates each block ahead of execution.

/// Build a [`tron_rpc::RateLimitRegistry`] from a parsed
/// `rate.limiter.*` config list. Each entry's `component` becomes the
/// lookup key (lowercased to match the request-path tail extraction).
/// Strategy names that don't match a known adapter are logged and
/// skipped — the request passes through unlimited rather than failing
/// to start.
/// Resolve `[bundler]` config into the optional shared [`BundlerState`]. Returns
/// `Ok(None)` when the section is absent or `enable = false`; otherwise resolves
/// the signing key, derives the bundler's address, and parses the EntryPoint /
/// beneficiary addresses.
fn build_bundler_state(
    cfg: Option<&crate::config::BundlerConfig>,
) -> Result<Option<Arc<tron_rpc::bundler::BundlerState>>, RunError> {
    let Some(cfg) = cfg.filter(|c| c.enable) else {
        return Ok(None);
    };
    let priv_key = resolve_bundler_key(cfg)?;
    let address = tron_wallet::address_from_private(&priv_key)
        .map_err(|e| RunError::Rpc(format!("[bundler] derive address: {e}")))?;
    let mut addr21 = [0u8; 21];
    addr21.copy_from_slice(address.as_bytes());
    let mode = tron_rpc::bundler::BundlingMode::parse(&cfg.bundling_mode).ok_or_else(|| {
        RunError::Rpc(format!(
            "[bundler] bundling_mode must be \"auto\" or \"manual\", got `{}`",
            cfg.bundling_mode
        ))
    })?;
    let state = tron_rpc::bundler::BundlerState::from_config(
        &cfg.entry_points,
        priv_key,
        addr21,
        cfg.beneficiary.as_deref(),
        cfg.fee_limit_sun,
    )
    .map_err(RunError::Rpc)?
    .with_bundling(
        mode,
        cfg.max_bundle_size,
        std::time::Duration::from_millis(cfg.bundle_interval_ms),
    )
    .with_validation_rules(cfg.enforce_validation_rules);
    tracing::info!(
        entry_points = cfg.entry_points.len(),
        bundler = %hex::encode(addr21),
        mode = cfg.bundling_mode,
        interval_ms = cfg.bundle_interval_ms,
        max_bundle = cfg.max_bundle_size,
        "ERC-4337 bundler enabled"
    );
    Ok(Some(Arc::new(state)))
}

/// Resolve the bundler's signing key from `keystore` / `key_env` / `key_hex`
/// (same precedence and sources as `[witness]`).
fn resolve_bundler_key(cfg: &crate::config::BundlerConfig) -> Result<[u8; 32], RunError> {
    if let Some(ks_path) = &cfg.keystore {
        let pw_env = cfg.keystore_password_env.as_ref().ok_or_else(|| {
            RunError::Rpc("[bundler] keystore_password_env required when keystore is set".into())
        })?;
        let pw = std::env::var(pw_env)
            .map_err(|_| RunError::Rpc(format!("[bundler] env var '{pw_env}' not set")))?;
        let ks = tron_wallet::Keystore::load_from_file(ks_path)
            .map_err(|e| RunError::Rpc(format!("[bundler] load keystore: {e}")))?;
        ks.decrypt(&pw)
            .map_err(|e| RunError::Rpc(format!("[bundler] decrypt keystore: {e}")))
    } else if let Some(env_name) = &cfg.key_env {
        let hex = std::env::var(env_name)
            .map_err(|_| RunError::Rpc(format!("[bundler] env var '{env_name}' not set")))?;
        parse_bundler_key_hex(&hex)
    } else if let Some(hex) = &cfg.key_hex {
        parse_bundler_key_hex(hex)
    } else {
        Err(RunError::Rpc("[bundler] requires one of: keystore, key_env, key_hex".into()))
    }
}

fn parse_bundler_key_hex(s: &str) -> Result<[u8; 32], RunError> {
    let s = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    let v = hex::decode(s).map_err(|e| RunError::Rpc(format!("[bundler] key hex: {e}")))?;
    v.try_into().map_err(|_| RunError::Rpc("[bundler] key must be 32 bytes".into()))
}

fn build_rate_limit_registry(
    items: &[crate::config::RateLimiterItem],
) -> tron_rpc::RateLimitRegistry {
    let mut map = std::collections::HashMap::new();
    for item in items {
        // Lowercase + strip java's `Servlet` class-name suffix so a
        // config.conf copied verbatim from java-tron matches our
        // path-tail components.
        let key = tron_rpc::normalize_component(&item.component);
        match tron_rpc::build_rate_limit(&item.strategy, &item.params) {
            Some(limit) => {
                map.insert(key, limit);
            }
            None => {
                warn!(
                    component = %item.component,
                    strategy = %item.strategy,
                    "rate.limiter: unknown strategy, skipping"
                );
            }
        }
    }
    tron_rpc::RateLimitRegistry::new(map)
}

/// Snapshot the discovery layer's known-peers table into a
/// [`Vec<DbNode>`] suitable for [`NodePersistService::write_batch`].
/// Pulls the host:port pair off each `SocketAddr` returned by the
/// `KadService::known_peers` accessor — no recency sort because the
/// service already returns its table in MRU order.
fn snapshot_for_persist(
    kad: &tron_net::KadHandle,
) -> Vec<crate::node_persist::DbNode> {
    kad.known_peers()
        .into_iter()
        .map(|addr| crate::node_persist::DbNode::new(addr.ip().to_string(), addr.port()))
        .collect()
}

/// Generate a fresh 64-byte node-id for the DHT layer. Stable for the
/// lifetime of one `tron-node start` invocation; not persisted. The TCP
/// sync layer keeps its own per-attempt randomized id (see `sync.rs`).
fn random_node_id_64() -> Vec<u8> {
    use std::time::SystemTime;
    // Cheap entropy without pulling in a new crate dependency at this
    // layer: nanos since epoch xor-spread across 64 bytes. Good enough
    // for DHT routing; not cryptographic.
    let mut id = [0u8; 64];
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u128)
        .unwrap_or(0);
    let bytes = nanos.to_le_bytes();
    for i in 0..64 {
        id[i] = bytes[i % bytes.len()] ^ (i as u8).wrapping_mul(0x9E);
    }
    id.to_vec()
}

/// The synthetic head we advertise while probing for the tip — far above any
/// real chain height (~30 years of blocks). It just signals "I'm caught up" so
/// the peer volunteers its own head. Peers that echo our Hello back report this
/// value as their "head"; we filter those out (see [`pick_anchor_tip`]).
const PROBE_AHEAD_HEAD: i64 = 900_000_000;

/// Ask one peer for its current head over the real TRON handshake.
///
/// We advertise a deliberately far-ahead head, so the peer treats us as
/// caught-up and replies with a normal reciprocal `HelloMessage` (carrying its
/// own head) instead of starting to serve us a backfill. A peer that advertises
/// `head = genesis` only ever gets an `ImplicitAccept` with no head — claiming
/// to be ahead is what makes the peer volunteer its tip. The peer never
/// validates our head hash (only the genesis id), so the synthetic head is
/// fine. Returns the peer's `(head_number, head_hash_32)`.
async fn probe_peer_head(peer: String) -> Option<(i64, [u8; 32])> {
    use tron_net::{
        HandshakeOutcome, HelloInputs, Libp2pHelloInputs, PeerConnection, MAINNET_P2P_VERSION,
    };
    use tron_proto::Endpoint;
    use tron_types::{genesis_block_id, mainnet_inputs, BlockId};

    let genesis = genesis_block_id(&mainnet_inputs());
    let mut ahead = [0u8; 32];
    ahead[..8].copy_from_slice(&PROBE_AHEAD_HEAD.to_be_bytes());
    let ahead_id = BlockId::from_raw(ahead);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let node_id = random_node_id_64();

    let probe = async {
        let mut conn = match PeerConnection::dial(&peer).await {
            Ok(c) => c,
            Err(e) => {
                debug!(peer = %peer, "tip probe: dial failed: {e}");
                return None;
            }
        };
        let from = Endpoint {
            address: b"127.0.0.1".to_vec(),
            address_ipv6: Vec::new(),
            port: 18_888,
            node_id: node_id.clone(),
        };
        if let Err(e) = conn
            .libp2p_handshake(Libp2pHelloInputs {
                from: from.clone(),
                network_id: 11_111,
                version: 2,
                timestamp_ms: now,
            })
            .await
        {
            debug!(peer = %peer, "tip probe: libp2p handshake failed: {e}");
            return None;
        }
        let outcome = match conn
            .handshake(HelloInputs {
                from,
                version: MAINNET_P2P_VERSION,
                timestamp_ms: now,
                genesis,
                solid: ahead_id,
                head: ahead_id,
                node_type: 0,
                lowest_block_num: 0,
                code_version: b"tron-goblin/0.0.1",
            })
            .await
        {
            Ok(o) => o,
            Err(e) => {
                debug!(peer = %peer, "tip probe: app handshake failed: {e}");
                return None;
            }
        };
        let hello = match outcome {
            HandshakeOutcome::Verified(h) => h,
            HandshakeOutcome::ImplicitAccept => {
                debug!(peer = %peer, "tip probe: implicit accept (no head)");
                return None;
            }
        };
        let head = hello.head_block_id?;
        if head.hash.len() != 32 || head.number <= 0 {
            return None;
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&head.hash);
        Some((head.number, hash))
    };

    match tokio::time::timeout(Duration::from_secs(10), probe).await {
        Ok(res) => res,
        Err(_) => None,
    }
}

/// Discover the current mainnet tip over p2p for `--explore`: probe batches of
/// the DISCOVERED peer pool concurrently, ask each for its head, and take the
/// highest. No external HTTP and no hardcoded seed list — the node bootstraps
/// itself with its own protocol over peers it found via discovery. Each round
/// samples a fresh window of the pool (most peers answer; some are full/busy),
/// so a handful of healthy nodes is enough. `None` only if nothing answers
/// across all rounds.
async fn discover_tip(peers: &[String]) -> Option<(i64, [u8; 32])> {
    if peers.is_empty() {
        return None;
    }
    const BATCH: usize = 64;
    // Start at a time-varied offset so restarts don't always hit the same peers.
    let mut offset = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as usize)
        .unwrap_or(0)
        % peers.len();

    // Keep probing fresh batches of the discovered pool until we learn a tip;
    // a single unlucky batch (all-busy peers) shouldn't strand startup. Give up
    // only after a deadline so a genuine no-connectivity case still surfaces.
    let start = std::time::Instant::now();
    loop {
        let mut set = tokio::task::JoinSet::new();
        for i in 0..BATCH.min(peers.len()) {
            let peer = peers[(offset + i) % peers.len()].clone();
            set.spawn(async move { probe_peer_head(peer).await });
        }
        offset = (offset + BATCH) % peers.len();

        let mut heads: Vec<(i64, [u8; 32])> = Vec::new();
        while let Some(joined) = set.join_next().await {
            if let Ok(Some(h)) = joined {
                heads.push(h);
            }
        }
        if let Some(tip) = pick_anchor_tip(heads) {
            return Some(tip);
        }
        if start.elapsed() >= Duration::from_secs(30) {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

/// Choose the bootstrap block from a round of probed peer heads.
///
/// The discovered pool is a wide mix: nodes at the tip, half-synced nodes far
/// behind, and a few that echo our far-ahead probe head straight back. So:
///   1. Drop the echoes (heads at/above the synthetic probe head).
///   2. The tip is the MAX of what remains (real nodes top out at the live tip;
///      the many laggards sit below it, so the median/mean would anchor us
///      hundreds of thousands of blocks back).
///   3. Anchor at the LOWEST head within a small window below that tip — a
///      recent block essentially every up-to-date peer holds, so the follow
///      locator is never rejected with `BAD_PROTOCOL` (vs the bare max, which a
///      peer one block behind the leader would refuse).
fn pick_anchor_tip(heads: Vec<(i64, [u8; 32])>) -> Option<(i64, [u8; 32])> {
    let real: Vec<(i64, [u8; 32])> = heads
        .into_iter()
        .filter(|(n, _)| *n > 0 && *n < PROBE_AHEAD_HEAD)
        .collect();
    let tip = real.iter().map(|(n, _)| *n).max()?;
    real.into_iter()
        .filter(|(n, _)| *n >= tip - 16)
        .min_by_key(|(n, _)| *n)
}


// ---------------------------------------------------------------------------
// Address-history index wiring
// ---------------------------------------------------------------------------

/// Live handles for the `[index]` subsystem.
struct IndexParts {
    hook: Arc<crate::index_hook::IndexHook>,
    engine: Arc<tron_index::IndexEngine>,
    reader: tron_index::IndexReader,
    /// Historical-state archive (P2, `capture_state_deltas`) — reader
    /// + per-store live backends for at-height views, plus the
    /// writer's counters for the metrics sampler.
    archive: Option<ArchiveParts>,
    /// Verifiable state-commitment layer (`[index.commitment]`) — the
    /// read handle + counters for the HTTP/metrics surfaces; the builder
    /// and its receiver are taken out in `run` for the background task.
    commitment: Option<CommitmentParts>,
    /// Firehose tail handle (P3, `[index.firehose]`) — handed to the
    /// gRPC server so external consumers can tail the durable log.
    firehose_tail: Option<tron_index::FirehoseTailHandle>,
    firehose_counters: Option<Arc<crate::firehose::FirehoseCounters>>,
}

struct ArchiveParts {
    reader: tron_index::ArchiveReader,
    counters: Arc<tron_index::ArchiveCounters>,
    backends: Vec<(tron_chainbase::UndoStoreId, Arc<dyn tron_chainbase::KvBackend>)>,
    /// Write-side handle, cloned out so `run` can spawn the rolling-window
    /// retention timer (the writer is otherwise consumed by the index hook).
    writer: Arc<tron_index::ArchiveWriter>,
}

struct CommitmentParts {
    /// Cheap-clone read handle for the HTTP `/v1/commitment` surface.
    reader: tron_index::CommitmentReader,
    /// Shared with the builder; mirrored into the metrics sampler.
    counters: Arc<tron_index::CommitmentCounters>,
    /// The builder and its receiver are taken (`Option::take`) in `run` and
    /// moved into the dedicated background task — the only writer of the tree.
    builder: Option<tron_index::CommitmentBuilder>,
    rx: Option<tokio::sync::mpsc::Receiver<tron_index::CommitmentMsg>>,
}

/// Bounded depth of the commitment write-set channel (blocks). A full channel
/// drops the message rather than blocking apply; the dropped height is
/// re-derivable, so this only bounds how far a lagging builder may fall behind
/// before it must repair a gap.
const COMMITMENT_CHANNEL_CAP: usize = 4096;

/// Every state store the executor's write-set can touch, paired with
/// its `StoreId` — the archive's gap-repair source and the raw
/// backends behind the `/v1/archive` at-height views.
fn store_id_backends(
    stores: &OpenedStores,
) -> Vec<(tron_chainbase::UndoStoreId, Arc<dyn tron_chainbase::KvBackend>)> {
    use tron_chainbase::UndoStoreId as Id;
    vec![
        (Id::Accounts, stores.accounts.clone()),
        (Id::Witnesses, stores.witnesses.clone()),
        (Id::Votes, stores.votes.clone()),
        (Id::Delegation, stores.delegation.clone()),
        (Id::DelegatedResources, stores.delegated_resources.clone()),
        (Id::DynProps, stores.dyn_props.clone()),
        (Id::Proposals, stores.proposals.clone()),
        (Id::NameIndex, stores.name_index.clone()),
        (Id::IdIndex, stores.id_index.clone()),
        (Id::AssetV1, stores.asset_v1.clone()),
        (Id::AssetV2, stores.asset_v2.clone()),
        (Id::Contracts, stores.contracts.clone()),
        (Id::Abi, stores.abi.clone()),
        (Id::ExchangeV1, stores.exchange_v1.clone()),
        (Id::ExchangeV2, stores.exchange_v2.clone()),
        (Id::MarketOrders, stores.market_orders.clone()),
        (Id::MarketAccount, stores.market_account.clone()),
        (Id::Nullifiers, stores.nullifiers.clone()),
        (Id::MerkleTrees, stores.merkle_trees.clone()),
        (Id::Code, stores.code.clone()),
        (Id::StorageRow, stores.storage_row.clone()),
        (Id::ContractState, stores.contract_state.clone()),
        (Id::BlockIndex, stores.block_index.clone()),
        (Id::WitnessSchedule, stores.witness_schedule.clone()),
        (
            Id::DelegatedResourceAccountIndex,
            stores.delegated_resource_account_index.clone(),
        ),
    ]
}

/// Open (or rebuild) the dedicated index DB and assemble the
/// hook/engine/reader trio. The DB lives at `<data_dir>/index/db`,
/// is a separate RocksDB instance (its compactions never touch the
/// consensus stores; memory is bounded by the process-wide shared
/// cache + write-buffer manager), and is **disposable by contract**:
/// a format-version bump or scope change deletes and re-derives it
/// from the node's own committed stores — the rebuild path IS the
/// follower's ordinary cold start.
fn open_index_subsystem(
    config: &NodeConfig,
    stores: &OpenedStores,
) -> Result<IndexParts, String> {
    use tron_chainbase::RocksDbBackend;
    use tron_index::{IndexDb, IndexEngine, IndexReader, InitOutcome};

    let caps = config.index.capture_set();
    let opts = config.index.engine_options();
    let fingerprint = caps.fingerprint(opts.start_height);
    let dir = config.data_dir.join("index").join("db");
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {parent:?}: {e}"))?;
    }
    let open = || -> Result<Arc<dyn tron_chainbase::KvBackend>, String> {
        RocksDbBackend::open_tuned(
            &dir,
            config.storage.write_buffer_size_mb,
            config.storage.max_open_files,
        )
        .map(|b| Arc::new(b) as Arc<dyn tron_chainbase::KvBackend>)
        .map_err(|e| format!("open index db {dir:?}: {e:?}"))
    };

    let mut backend = open()?;
    match IndexDb::new(backend.clone())
        .check_or_init(fingerprint)
        .map_err(|e| e.to_string())?
    {
        InitOutcome::Fresh => {
            info!(scope = ?config.index.scope, "index: fresh database stamped");
        }
        InitOutcome::Compatible => {}
        InitOutcome::NeedsRebuild { reason } => {
            // Loud by design: a multi-TB index rebuild is hours of
            // work and the operator should know why it happened.
            warn!(
                reason,
                "index: REBUILDING from scratch — dropping {dir:?} and re-deriving from local stores"
            );
            drop(backend);
            std::fs::remove_dir_all(&dir).map_err(|e| format!("remove {dir:?}: {e}"))?;
            backend = open()?;
            IndexDb::new(backend.clone())
                .stamp(fingerprint)
                .map_err(|e| e.to_string())?;
        }
    }

    let db = IndexDb::new(backend);

    // Historical-state archive (P2) — its own DB instance: unlike the
    // tx-history index it is NOT a disposable projection (deltas are
    // not re-derivable), so it must never share the index DB's
    // wipe-and-rebuild lifecycle.
    let mut archive_parts: Option<ArchiveParts> = None;
    let mut hook = crate::index_hook::IndexHook::new(stores.transaction_ret.clone())
        .with_tx_refs(stores.transactions.clone());
    if config.index.archive.enabled || config.index.capture_state_deltas {
        if config.storage.snapshot_reorg {
            error!(
                "index: the historical-state archive (index.archive.enabled / \
                 index.capture_state_deltas) requires the BlockSession commit path \
                 (storage.snapshot_reorg = false) — the snapshot-stack path does not \
                 materialize per-block write-sets. Archive DISABLED."
            );
        } else {
            let arch_dir = config.data_dir.join("archive").join("db");
            if let Some(parent) = arch_dir.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("create {parent:?}: {e}"))?;
            }
            let arch_backend: Arc<dyn tron_chainbase::KvBackend> = Arc::new(
                RocksDbBackend::open_tuned(
                    &arch_dir,
                    config.storage.write_buffer_size_mb,
                    config.storage.max_open_files,
                )
                .map_err(|e| format!("open archive db {arch_dir:?}: {e:?}"))?,
            );
            let backends = store_id_backends(stores);
            let writer = Arc::new(tron_index::ArchiveWriter::new(
                arch_backend,
                Some(tron_chainbase::BlockUndoStore::new(stores.block_undo.clone())),
                backends.clone(),
            ));
            let fresh = writer.check_or_init().map_err(|e| e.to_string())?;
            let coverage = writer.reader().coverage().map_err(|e| e.to_string())?;
            info!(fresh, ?coverage, dir = ?arch_dir, "index: historical-state archive enabled");
            archive_parts = Some(ArchiveParts {
                reader: writer.reader(),
                counters: writer.counters(),
                backends,
                writer: writer.clone(),
            });
            hook = hook.with_archive(writer);
        }
    }
    // Verifiable state-commitment layer (`[index.commitment]`) — its own
    // RocksDB instance under <data_dir>/commitment/db. Independent of the
    // archive; like it, it needs the per-block write-set, so it shares the
    // same BlockSession-commit requirement. The builder is handed a bounded
    // channel sender via the hook (non-blocking try_send) and runs entirely
    // off the apply path in `run`.
    let mut commitment_parts: Option<CommitmentParts> = None;
    if config.index.commitment.enabled {
        if config.storage.snapshot_reorg {
            error!(
                "index: the state-commitment layer (index.commitment.enabled) requires the \
                 BlockSession commit path (storage.snapshot_reorg = false) — the snapshot-stack \
                 path does not materialize per-block write-sets. Commitment DISABLED."
            );
        } else {
            let commit_dir = config.data_dir.join("commitment").join("db");
            if let Some(parent) = commit_dir.parent() {
                std::fs::create_dir_all(parent).map_err(|e| format!("create {parent:?}: {e}"))?;
            }
            let commit_backend: Arc<dyn tron_chainbase::KvBackend> = Arc::new(
                RocksDbBackend::open_tuned(
                    &commit_dir,
                    config.storage.write_buffer_size_mb,
                    config.storage.max_open_files,
                )
                .map_err(|e| format!("open commitment db {commit_dir:?}: {e:?}"))?,
            );
            let store = tron_index::CommitmentStore::new(commit_backend);
            let fresh = store.check_or_init().map_err(|e| e.to_string())?;
            let counters = Arc::new(tron_index::CommitmentCounters::new());
            let k = config.index.commitment.confirmation_lag_blocks;
            let builder = tron_index::CommitmentBuilder::new(
                store,
                store_id_backends(stores),
                k,
                counters.clone(),
            )
            .map_err(|e| e.to_string())?;
            let reader = builder.reader();
            let committed = builder.committed_height();
            // Bounded so a lagging builder never blocks the apply path: a full
            // channel drops the write-set (the hook flags a resync; the gap is
            // re-derivable). Sized to absorb ordinary catch-up bursts.
            let (tx, rx) = tokio::sync::mpsc::channel(COMMITMENT_CHANNEL_CAP);
            info!(
                fresh,
                ?committed,
                confirmation_lag_blocks = k,
                dir = ?commit_dir,
                "index: state-commitment layer enabled"
            );
            hook = hook.with_commitment(tx, counters.clone());
            commitment_parts = Some(CommitmentParts {
                reader,
                counters,
                builder: Some(builder),
                rx: Some(rx),
            });
        }
    }
    // Firehose external-sink log (P3) — its own durable artifact under
    // <data_dir>/firehose/, reconciled against consensus at open (a
    // log ahead of the recovered chain emits an UNWIND; a log behind
    // repairs from the stores on the next apply).
    let mut firehose_tail: Option<tron_index::FirehoseTailHandle> = None;
    let mut firehose_counters: Option<Arc<crate::firehose::FirehoseCounters>> = None;
    if config.index.firehose.enable {
        let fh_dir = config.data_dir.join("firehose");
        let writer = Arc::new(
            crate::firehose::FirehoseWriter::open(
                &fh_dir,
                config.index.firehose.retain_mb.saturating_mul(1024 * 1024),
                stores.blocks.clone(),
                stores.block_index.clone(),
                stores.transaction_ret.clone(),
                stores.dyn_props.clone(),
            )
            .map_err(|e| format!("firehose open {fh_dir:?}: {e}"))?,
        );
        firehose_tail = Some(writer.tail_handle());
        firehose_counters = Some(writer.counters());
        info!(dir = ?fh_dir, retain_mb = config.index.firehose.retain_mb, "index: firehose log enabled");
        hook = hook.with_firehose(writer);
    }
    let hook = Arc::new(hook);
    let engine = Arc::new(IndexEngine::new(
        db.clone(),
        stores.blocks.clone(),
        stores.block_index.clone(),
        stores.transaction_ret.clone(),
        stores.dyn_props.clone(),
        caps,
        opts,
    ));
    let reader = IndexReader::new(
        db,
        stores.blocks.clone(),
        stores.block_index.clone(),
        stores.dyn_props.clone(),
    )
    .with_solidified_stream(config.index.engine_options().follow_solidified);
    info!(
        ?caps,
        head_first = config.index.engine_options().head_first,
        dir = ?dir,
        "index: subsystem ready"
    );
    Ok(IndexParts {
        hook,
        engine,
        reader,
        archive: archive_parts,
        commitment: commitment_parts,
        firehose_tail,
        firehose_counters,
    })
}

/// The state-commitment builder's background task: a one-time bootstrap (or
/// crash-resume) anchored at the recovered head, then an off-apply-path fold
/// loop. All CPU/IO — the full-state Merkleize (minutes on a fresh enable) and
/// every per-block fold (up to hundreds of node hashes) — runs on a blocking
/// thread so it never occupies a tokio worker. `committed_height` deliberately
/// trails the head by the configured confirmation lag, so committed roots are
/// final. A fold/store error stops the builder (the node is unaffected; the
/// commitment simply stops advancing and `/v1/commitment/status` shows it).
async fn run_commitment_builder(
    builder: tron_index::CommitmentBuilder,
    mut rx: tokio::sync::mpsc::Receiver<tron_index::CommitmentMsg>,
    anchor_head: i64,
    max_lag_blocks: u64,
    shutdown: ShutdownSignal,
) {
    let mut sd = shutdown.subscribe();
    // Bootstrap / resume off-thread, moving the builder through and back.
    let mut builder = match tokio::task::spawn_blocking(move || {
        let mut builder = builder;
        let r = builder.bootstrap_or_resume(anchor_head);
        (builder, r)
    })
    .await
    {
        Ok((b, Ok(()))) => {
            info!(committed = ?b.committed_height(), "commitment: bootstrap/resume complete");
            b
        }
        Ok((_, Err(e))) => {
            error!(error = %e, "commitment: bootstrap/resume failed; builder stopping");
            return;
        }
        Err(_) => {
            error!("commitment: bootstrap task panicked; builder stopping");
            return;
        }
    };

    let mut warned = false;
    loop {
        let (height, deltas) = tokio::select! {
            _ = sd.recv() => break,
            msg = rx.recv() => match msg {
                Some(tron_index::CommitmentMsg::Block { height, deltas }) => (height, deltas),
                None => break, // all senders dropped (shutdown)
            },
        };
        // Fold off-thread (a block recomputes hundreds of node hashes; a rare
        // deep-reorg fallback re-Merkleizes from live state).
        let (b, result) = match tokio::task::spawn_blocking(move || {
            let mut builder = builder;
            let r = builder.ingest(height, deltas);
            (builder, r)
        })
        .await
        {
            Ok(pair) => pair,
            Err(_) => {
                error!(block = height, "commitment: fold task panicked; builder stopping");
                return;
            }
        };
        builder = b;
        match result {
            Ok(c) => {
                if c.rebootstrapped {
                    warn!(
                        committed = ?c.committed_height,
                        "commitment: re-bootstrapped after a deep reorg or unrepairable gap"
                    );
                }
                // The builder trails head by ~K by design; warn (once per
                // lag episode) only when it exceeds the operator threshold.
                let lag = height - c.committed_height.unwrap_or(height);
                if lag as u64 > max_lag_blocks {
                    if !warned {
                        warn!(
                            lag,
                            max_lag_blocks,
                            head = height,
                            "commitment: builder lagging head beyond threshold"
                        );
                        warned = true;
                    }
                } else {
                    warned = false;
                }
            }
            Err(e) => {
                error!(block = height, error = %e, "commitment: fold failed; builder stopping");
                return;
            }
        }
    }
    info!("commitment: builder task stopped");
}

/// Spawn the follower loop: tick the engine on a blocking thread,
/// park on the apply hook's wake-up (with a 3s poll fallback — a
/// missed signal costs nothing, the stores are the queue), and emit
/// the count-gated progress line while a gap is being closed.
fn spawn_index_follower(
    handles: &mut Vec<tokio::task::JoinHandle<()>>,
    engine: Arc<tron_index::IndexEngine>,
    notify: Arc<tokio::sync::Notify>,
    shutdown: ShutdownSignal,
) {
    let mut sd = shutdown.subscribe();
    handles.push(tokio::spawn(async move {
        // Startup decision line — the (cursor, head, floor) triple
        // makes the chosen behavior legible at a glance.
        {
            let st = engine.status();
            info!(
                cursor = st.cursor,
                indexed_from = st.back_edge,
                floor = st.floor,
                head = st.target_head,
                "🧌 index follower starting"
            );
        }
        let mut progress = IndexProgress::new(&engine);
        loop {
            if shutdown.is_shutdown() {
                break;
            }
            let eng = engine.clone();
            let tick = match tokio::task::spawn_blocking(move || eng.tick()).await {
                Ok(t) => t,
                Err(join_err) => {
                    error!(error = %join_err, "index: follower tick panicked; stopping");
                    break;
                }
            };
            match tick {
                Ok(tron_index::Tick::Parked) | Ok(tron_index::Tick::NotReady) => {
                    progress.log_caught_up(&engine);
                    tokio::select! {
                        _ = notify.notified() => {}
                        _ = tokio::time::sleep(Duration::from_secs(3)) => {}
                        _ = sd.recv() => break,
                    }
                }
                Ok(_) => progress.maybe_log(&engine),
                Err(
                    e @ (tron_index::IndexError::Corrupt(_)
                    | tron_index::IndexError::NewerFormat { .. }),
                ) => {
                    // The tx-history index is a disposable projection —
                    // unlike the archive/firehose, delete-and-rebuild is
                    // always the correct remedy here.
                    error!(
                        error = %e,
                        "index: follower stopped — delete <data_dir>/index and restart to rebuild"
                    );
                    break;
                }
                Err(e) => {
                    warn!(error = %e, "index: tick failed; retrying in 5s");
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                        _ = sd.recv() => break,
                    }
                }
            }
        }
        debug!("index follower exiting");
    }));
}

/// Count-gated progress reporting for the index follower, in the same
/// voice as the sync driver's catch-up line.
struct IndexProgress {
    last_log: std::time::Instant,
    last_blocks: u64,
    caught_up_logged: bool,
    counters: Arc<tron_index::IndexCounters>,
}

impl IndexProgress {
    fn new(engine: &tron_index::IndexEngine) -> Self {
        Self {
            last_log: std::time::Instant::now(),
            last_blocks: 0,
            caught_up_logged: false,
            counters: engine.counters(),
        }
    }

    fn remaining(st: &tron_index::IndexStatus) -> i64 {
        let forward = (st.target_head - st.cursor.unwrap_or(st.target_head)).max(0);
        let backward = match (st.back_edge, st.floor) {
            (Some(b), Some(f)) => (b - f).max(0),
            _ => 0,
        };
        forward + backward
    }

    fn maybe_log(&mut self, engine: &tron_index::IndexEngine) {
        let elapsed = self.last_log.elapsed();
        if elapsed < Duration::from_secs(5) {
            return;
        }
        let st = engine.status();
        let blocks = self
            .counters
            .blocks_indexed
            .load(std::sync::atomic::Ordering::Relaxed);
        let rate = (blocks.saturating_sub(self.last_blocks)) as f64 / elapsed.as_secs_f64();
        let remaining = Self::remaining(&st);
        let eta_ms = if rate > 0.0 {
            ((remaining as f64 / rate) * 1000.0) as i64
        } else {
            0
        };
        info!(
            "🧌 index backfill cursor #{} head #{} backfill-edge #{} floor #{}  ({} to go)  {:.0} blk/s{}",
            crate::logfmt::commas(st.cursor.unwrap_or(0)),
            crate::logfmt::commas(st.target_head),
            crate::logfmt::commas(st.back_edge.unwrap_or(0)),
            crate::logfmt::commas(st.floor.unwrap_or(0)),
            crate::logfmt::commas(remaining),
            rate,
            if eta_ms > 0 {
                format!("  eta {}", crate::logfmt::duration_ms(eta_ms))
            } else {
                String::new()
            },
        );
        self.last_log = std::time::Instant::now();
        self.last_blocks = blocks;
        // Re-arm the caught-up transition if we fell well behind.
        if remaining > 1_000 {
            self.caught_up_logged = false;
        }
    }

    fn log_caught_up(&mut self, engine: &tron_index::IndexEngine) {
        if self.caught_up_logged {
            return;
        }
        let st = engine.status();
        if st.at_tip && st.backfill_complete {
            info!(
                "🧌 index caught up to head at #{} — now following live",
                crate::logfmt::commas(st.cursor.unwrap_or(0)),
            );
            self.caught_up_logged = true;
        }
    }
}

/// True if `dyn_props` already has a head-pointer entry. Used to
/// skip re-applying genesis on a node that's already been bootstrapped.
fn chain_initialized(stores: &OpenedStores) -> bool {
    use tron_chainbase::DynamicPropertiesStore;
    let dp = DynamicPropertiesStore::new(stores.dyn_props.clone());
    dp.latest_block_header_number().is_some()
}

/// Refuse to spoof the head pointer when the data-dir already holds a
/// synced chain.
///
/// The `--tip-test` / `--explore` / `--mempool` paths move the
/// `DynamicPropertiesStore` head pointer forward to a recent tip
/// *without* applying any block — the chain state (accounts, blocks) is
/// left untouched. On a fresh or genesis-only data-dir that's harmless:
/// the spoofed head just steers `SyncBlockChain` locators at the live
/// tail for a decode-only follow. But on a data-dir that already holds a
/// real synced chain (head past genesis), overwriting the head pointer
/// bakes a permanent offset between it and the account/block stores —
/// the exact silent-divergence the startup consistency guard warns
/// about, except here we would be the cause. Surface it as a hard
/// startup error directing the operator at a throwaway `--data-dir`
/// rather than corrupting their node's state.
///
/// `mode` names the triggering flag for the error message.
fn guard_head_spoof(stores: &OpenedStores, mode: &str) -> Result<(), RunError> {
    use tron_chainbase::DynamicPropertiesStore;
    let dp = DynamicPropertiesStore::new(stores.dyn_props.clone());
    let head = dp.latest_block_header_number().unwrap_or(0);
    if head > 0 {
        return Err(RunError::Sync(format!(
            "{mode} would overwrite the head pointer of an already-synced chain \
             (current head #{head}); refusing to corrupt this data-dir. \
             Run the dashboard against a throwaway directory, e.g. \
             `--data-dir $(mktemp -d)` (or use `try.sh`)."
        )));
    }
    Ok(())
}

/// Apply the mainnet genesis block. Writes the genesis Block to
/// `BlockStore` + the head pointer into `DynamicPropertiesStore`.
/// Genesis allocations are NOT yet replayed into AccountStore — the
/// existing `tron-types::mainnet_inputs` describes them but the
/// executor's `apply_genesis_allocations` is a follow-up.
fn initialize_genesis(stores: &OpenedStores) -> Result<(), crate::storage::StorageError> {
    use tron_chainbase::{BlockIndexStore, BlockStore, DynamicPropertiesStore};
    use tron_types::{build_genesis_block, genesis_block_id, mainnet_inputs};

    let inputs = mainnet_inputs();
    let block = build_genesis_block(&inputs);
    let id = genesis_block_id(&inputs);

    let block_store = BlockStore::new(stores.blocks.clone());
    block_store.put(&id, &block)?;
    let block_index = BlockIndexStore::new(stores.block_index.clone());
    block_index.put(&id)?;
    let dp = DynamicPropertiesStore::new(stores.dyn_props.clone());
    dp.save_latest_block_header_number(0);
    if let Some(raw) = block.block_header.as_ref().and_then(|h| h.raw_data.as_ref()) {
        dp.save_latest_block_header_timestamp(raw.timestamp);
        // Pin the genesis timestamp so per-block slot attribution
        // (`total_missed`) can compute absolute slot indices without
        // re-reading block 0 every time.
        dp.save_genesis_block_timestamp(raw.timestamp);
    }
    // Critical for the sync driver: it reads `latest_block_header_hash`
    // to know what to send to peers as our current head.
    dp.save_latest_block_header_hash(id.as_bytes());

    // Apply the genesis allocations + initial 27 SRs.
    let state = stores.to_state_backends();
    tron_executor::apply_genesis_allocations(
        &state,
        inputs.assets,
        tron_types::mainnet_witnesses(),
    )?;

    info!(
        assets = inputs.assets.len(),
        witnesses = tron_types::mainnet_witnesses().len(),
        id = %hex_encode(id.as_bytes()),
        "wrote genesis block"
    );
    Ok(())
}

/// Write the committee initial values into `DynamicPropertiesStore`.
/// One `put_long(key, value)` per governance flag — keys match
/// java-tron's `DynamicPropertiesStore` byte-array literals exactly so
/// that a chain bootstrapped here is wire-compatible with java-tron's
/// proposal-store reads.
///
/// Called once at fresh-chain genesis bootstrap. java-tron mirrors this
/// in `Manager.initGenesisData`, where the committee config feeds each
/// `save*` setter unconditionally; on-chain proposal records can then
/// override values later via the normal maintenance flow.
fn seed_committee_initial_values(
    stores: &crate::storage::OpenedStores,
    cfg: &crate::config::CommitteeConfig,
) {
    let dp = tron_chainbase::DynamicPropertiesStore::new(stores.dyn_props.clone());
    let write = |key: &[u8], v: i64| dp.put_long(key, v);

    write(b"ALLOW_CREATION_OF_CONTRACTS", cfg.allow_creation_of_contracts);
    write(b"ALLOW_MULTI_SIGN", cfg.allow_multi_sign);
    write(b"ALLOW_ADAPTIVE_ENERGY", cfg.allow_adaptive_energy);
    write(b"ALLOW_DELEGATE_RESOURCE", cfg.allow_delegate_resource);
    write(b" ALLOW_SAME_TOKEN_NAME", cfg.allow_same_token_name); // intentional leading space (java-tron quirk)
    write(b"ALLOW_TVM_TRANSFER_TRC10", cfg.allow_tvm_transfer_trc10);
    write(b"ALLOW_TVM_CONSTANTINOPLE", cfg.allow_tvm_constantinople);
    write(b"ALLOW_TVM_SOLIDITY_059", cfg.allow_tvm_solidity_059);
    write(b"FORBID_TRANSFER_TO_CONTRACT", cfg.forbid_transfer_to_contract);
    write(
        b"ALLOW_SHIELDED_TRC20_TRANSACTION",
        cfg.allow_shielded_trc20_transaction,
    );
    write(b"ALLOW_MARKET_TRANSACTION", cfg.allow_market_transaction);
    write(b"ALLOW_TRANSACTION_FEE_POOL", cfg.allow_transaction_fee_pool);
    write(
        b"ALLOW_BLACKHOLE_OPTIMIZATION",
        cfg.allow_black_hole_optimization,
    );
    write(b"ALLOW_NEW_RESOURCE_MODEL", cfg.allow_new_resource_model);
    write(b"ALLOW_TVM_ISTANBUL", cfg.allow_tvm_istanbul);
    write(b"ALLOW_PROTO_FILTER_NUM", cfg.allow_proto_filter_num);
    write(b"ALLOW_ACCOUNT_STATE_ROOT", cfg.allow_account_state_root);
    write(b"CHANGED_DELEGATION", cfg.changed_delegation);
    write(b"ALLOW_PBFT", cfg.allow_pbft);
    write(b"PBFT_EXPIRE_NUM", cfg.pbft_expire_num);
    write(b"ALLOW_TVM_FREEZE", cfg.allow_tvm_freeze);
    write(b"ALLOW_TVM_VOTE", cfg.allow_tvm_vote);
    write(b"ALLOW_TVM_LONDON", cfg.allow_tvm_london);
    write(b"ALLOW_TVM_COMPATIBLE_EVM", cfg.allow_tvm_compatible_evm);
    write(
        b"ALLOW_HIGHER_LIMIT_FOR_MAX_CPU_TIME_OF_ONE_TX",
        cfg.allow_higher_limit_for_max_cpu_time_of_one_tx,
    );
    write(
        b"ALLOW_NEW_REWARD_ALGORITHM",
        cfg.allow_new_reward_algorithm,
    );
    write(
        b"ALLOW_OPTIMIZED_RETURN_VALUE_OF_CHAIN_ID",
        cfg.allow_optimized_return_value_of_chain_id,
    );
    write(b"ALLOW_TVM_SHANGHAI", cfg.allow_tvm_shanghai);
    write(b"ALLOW_OLD_REWARD_OPT", cfg.allow_old_reward_opt);
    write(b"ALLOW_ENERGY_ADJUSTMENT", cfg.allow_energy_adjustment);
    write(b"ALLOW_STRICT_MATH", cfg.allow_strict_math);
    write(
        b"CONSENSUS_LOGIC_OPTIMIZATION",
        cfg.consensus_logic_optimization,
    );
    write(b"ALLOW_TVM_CANCUN", cfg.allow_tvm_cancun);
    write(b"ALLOW_TVM_BLOB", cfg.allow_tvm_blob);
    write(b"UNFREEZE_DELAY_DAYS", cfg.unfreeze_delay_days);
    write(b"ALLOW_RECEIPTS_MERKLE_ROOT", cfg.allow_receipts_merkle_root);
    write(
        b"ALLOW_ACCOUNT_ASSET_OPTIMIZATION",
        cfg.allow_account_asset_optimization,
    );
    write(b"ALLOW_ASSET_OPTIMIZATION", cfg.allow_asset_optimization);
    write(b"ALLOW_NEW_REWARD", cfg.allow_new_reward);
    write(b"MEMO_FEE", cfg.memo_fee);
    write(
        b"ALLOW_DELEGATE_OPTIMIZATION",
        cfg.allow_delegate_optimization,
    );
    write(b"ALLOW_DYNAMIC_ENERGY", cfg.allow_dynamic_energy);
    write(b"DYNAMIC_ENERGY_THRESHOLD", cfg.dynamic_energy_threshold);
    write(
        b"DYNAMIC_ENERGY_INCREASE_FACTOR",
        cfg.dynamic_energy_increase_factor,
    );
    write(
        b"DYNAMIC_ENERGY_MAX_FACTOR",
        cfg.dynamic_energy_max_factor,
    );

    // java `DynamicPropertiesStore.init()` seeds the global energy resource pool
    // at genesis (chainbase DynamicPropertiesStore.java:455/736/742). A fresh
    // chain MUST start with a non-zero limit: otherwise `total_energy_limit()`
    // reads 0, every account's frozen-energy quota computes to 0, and every
    // contract tx wrongly pays the full energy fee instead of drawing its quota
    // — a silent state divergence vs java from the block the VM goes live. The
    // 83M snapshot import already carries the live values, so this fresh-genesis
    // path is the only place we seed them. TARGET = limit/14400 (init():742).
    dp.save_total_energy_limit(50_000_000_000);
    dp.save_total_energy_current_limit(50_000_000_000);
    dp.save_total_energy_target_limit(50_000_000_000 / 14_400);

    // java `init()` also seeds the contract-type / default-active-operations
    // bitmaps (DynamicPropertiesStore.java:661-675). These EVOLVE as proposals
    // activate — `addSystemContractAndSetPermission(id)` OR-sets bit `id` in BOTH
    // bitmaps for each newly-enabled contract type (see proposals.rs). Without
    // the genesis seed + the evolution, every account auto-created in the
    // from-genesis window is serialized with the wrong ACTIVE_DEFAULT_OPERATIONS
    // (the modern value instead of the era-appropriate one), forking the state
    // root once ALLOW_MULTI_SIGN activates. 32-byte values, java-exact:
    // AVAILABLE = 7fff1fc0037e0000…, ACTIVE = 7fff1fc0033e0000… (rest zero).
    let mut available_contract_type = [0u8; 32];
    available_contract_type[..6].copy_from_slice(&[0x7f, 0xff, 0x1f, 0xc0, 0x03, 0x7e]);
    dp.put_bytes(b"AVAILABLE_CONTRACT_TYPE", &available_contract_type);
    let mut active_default_operations = [0u8; 32];
    active_default_operations[..6].copy_from_slice(&[0x7f, 0xff, 0x1f, 0xc0, 0x03, 0x3e]);
    dp.put_bytes(b"ACTIVE_DEFAULT_OPERATIONS", &active_default_operations);

    info!("🏛 seeded committee.* governance flags into DynamicPropertiesStore");
}

fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

/// The startup dial list: the explicit `p2p.peers`, deduped (first-occurrence
/// order preserved). There is no hardcoded seed list — with no `--peer` the
/// node bootstraps entirely from peer discovery (the DNS tree + Kad DHT).
pub(crate) fn assemble_peers(p2p: &crate::config::P2pConfig) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for p in &p2p.peers {
        if seen.insert(p.clone()) {
            out.push(p.clone());
        }
    }
    out
}

#[cfg(test)]
mod assemble_peers_tests {
    use super::assemble_peers;
    use crate::config::P2pConfig;

    #[test]
    fn no_peers_means_empty_dial_list_discovery_only() {
        // No explicit peers: the startup dial list is empty and the node
        // bootstraps purely via discovery (DNS tree + Kad DHT).
        assert!(assemble_peers(&P2pConfig::default()).is_empty());
    }

    #[test]
    fn explicit_peers_used_in_order_and_deduped() {
        let p2p = P2pConfig {
            peers: vec![
                "1.2.3.4:18888".into(),
                "5.6.7.8:18888".into(),
                "1.2.3.4:18888".into(),
            ],
            ..P2pConfig::default()
        };
        assert_eq!(
            assemble_peers(&p2p),
            vec!["1.2.3.4:18888".to_string(), "5.6.7.8:18888".to_string()]
        );
    }

    #[test]
    fn pick_anchor_tip_ignores_echoes_and_laggards() {
        let id = |n: i64| {
            let mut h = [0u8; 32];
            h[..8].copy_from_slice(&n.to_be_bytes());
            (n, h)
        };
        // 5 real near-tip heads + 1 echo (our 900M probe head reflected) + 1
        // half-synced laggard. Anchor at the lowest of the real cluster.
        let heads = vec![
            id(83_615_700),
            id(83_615_701),
            id(83_615_699),
            id(83_615_702),
            id(83_615_700),
            id(900_000_000),
            id(50_000_000),
        ];
        assert_eq!(super::pick_anchor_tip(heads).unwrap().0, 83_615_699);
        assert!(super::pick_anchor_tip(vec![]).is_none());
    }

    #[test]
    fn fd_limit_raises_only_when_below_hard() {
        // Typical: low default soft, high hard → raise to hard.
        assert_eq!(super::fd_limit_target(1024, 1_048_576), Some(1_048_576));
        // Already at the ceiling → no-op.
        assert_eq!(super::fd_limit_target(1_048_576, 1_048_576), None);
        // Defensive: never lower an already-generous soft limit.
        assert_eq!(super::fd_limit_target(4096, 1024), None);
    }

    #[test]
    fn head_spoof_guard_allows_fresh_and_genesis_only_dirs() {
        use tron_chainbase::DynamicPropertiesStore;
        let tmp = tempfile::tempdir().unwrap();

        // Fresh data-dir (no head pointer written yet): the dashboard is
        // free to spoof the head.
        let stores = crate::storage::OpenedStores::open(tmp.path()).expect("open");
        assert!(
            super::guard_head_spoof(&stores, "--explore").is_ok(),
            "fresh dir must be spoofable"
        );

        // Genesis-only (head == 0, as `initialize_genesis` leaves it):
        // still safe — there is no synced chain to clobber.
        let dp = DynamicPropertiesStore::new(stores.dyn_props.clone());
        dp.save_latest_block_header_number(0);
        assert!(
            super::guard_head_spoof(&stores, "--explore").is_ok(),
            "genesis-only dir must be spoofable"
        );
    }

    #[test]
    fn head_spoof_guard_refuses_synced_chain() {
        use tron_chainbase::DynamicPropertiesStore;
        let tmp = tempfile::tempdir().unwrap();
        let stores = crate::storage::OpenedStores::open(tmp.path()).expect("open");

        // A data-dir holding a synced chain (head past genesis): spoofing
        // the head pointer here would bake a permanent offset against the
        // account/block stores, so it must be refused.
        let dp = DynamicPropertiesStore::new(stores.dyn_props.clone());
        dp.save_latest_block_header_number(83_316_752);
        let err = super::guard_head_spoof(&stores, "--explore")
            .expect_err("synced chain must be refused");
        let msg = err.to_string();
        assert!(msg.contains("already-synced"), "message explains the refusal: {msg}");
        assert!(msg.contains("83316752"), "message reports the current head: {msg}");
    }
}

#[cfg(test)]
mod shutdown_signal_tests {
    use super::ShutdownSignal;

    #[test]
    fn is_shutdown_is_sticky_and_survives_late_subscribe() {
        let sig = ShutdownSignal::new();
        assert!(!sig.is_shutdown());
        sig.shutdown();
        assert!(sig.is_shutdown(), "flag is set even with no live receivers");
        // A receiver created AFTER shutdown fired never sees the broadcast
        // message (this is the bug that wedged `run`) — but the sticky flag
        // still reports it, which is what the guarded `recv()` relies on.
        let mut late = sig.subscribe();
        assert!(sig.is_shutdown());
        assert!(late.try_recv().is_err(), "late subscriber missed the send");
    }

    #[test]
    fn clones_share_the_flag() {
        let sig = ShutdownSignal::new();
        let clone = sig.clone();
        clone.shutdown();
        assert!(sig.is_shutdown(), "shutdown via a clone is visible everywhere");
    }

    #[tokio::test]
    async fn guarded_wait_returns_when_shutdown_fired_before_subscribe() {
        // Reproduces the run()-level fix: shutdown fires, THEN we subscribe
        // and would-block on recv() — the is_shutdown() guard must let us
        // through instead of hanging. A timeout proves we don't block.
        let sig = ShutdownSignal::new();
        sig.shutdown(); // fired before the "final wait" subscribes
        let waited = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            let mut sd = sig.subscribe();
            if !sig.is_shutdown() {
                let _ = sd.recv().await;
            }
        })
        .await;
        assert!(waited.is_ok(), "guarded wait must not block when shutdown already fired");
    }
}
