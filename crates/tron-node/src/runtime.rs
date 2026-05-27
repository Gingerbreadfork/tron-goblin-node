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
#[derive(Clone)]
pub struct ShutdownSignal {
    tx: broadcast::Sender<()>,
}

impl ShutdownSignal {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(8);
        Self { tx }
    }

    /// Trigger shutdown. Idempotent — multiple calls coalesce.
    pub fn shutdown(&self) {
        let _ = self.tx.send(());
    }

    /// Get a fresh receiver. Each subsystem holds one and `.recv()`s
    /// to know when to exit.
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
pub async fn run(config: NodeConfig, shutdown: ShutdownSignal) -> Result<(), RunError> {
    info!(data_dir = ?config.data_dir, "opening stores");
    let mut stores = OpenedStores::open_tuned(
        &config.data_dir,
        config.storage.write_buffer_size_mb,
        config.storage.max_open_files,
    )?;

    // Checkpoint-V2 recovery: if the previous run crashed between the
    // manifest write and the per-store merge, replay any orphan
    // manifests into the freshly-opened root backends so the chain
    // sees a consistent post-flush state. Cheap — `list()` is one
    // readdir; on the common no-crash path there are zero manifests.
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

    // Tip-test mode: spoof the local head pointer so SyncBlockChain
    // requests use a recent block ID, letting peers that pruned the
    // archive serve us their post-pruning tail. The chain state is
    // NOT modified — only `DynamicPropertiesStore`'s head pointers.
    if let Some(checkpoint) = config.p2p.tip_test.clone() {
        use tron_chainbase::DynamicPropertiesStore;
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
    let mempool_state = stores.to_state_backends();
    let validator = crate::mempool_validator::build(&mempool_state);
    let mempool = std::sync::Arc::new(
        tron_mempool::TxMempool::new(tron_mempool::MempoolConfig::default())
            .with_validator(validator)
            .with_persistence(stores.mempool.clone())
            .with_metrics(metrics.clone()),
    );
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
        info!(%bound, "Prometheus metrics listening");
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

    // === RPC server ===
    if !config.rpc.disabled {
        let rpc_state = stores
            .to_rpc_state(config.rpc.chain_id)
            .with_metrics(metrics.clone())
            .with_mempool(mempool.clone())
            .with_eth_call_gas_cap(eth_call_gas_cap)
            .with_support_constant(support_constant)
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
        info!(%bound, "JSON-RPC listening");
        let mut sd = shutdown.subscribe();
        handles.push(tokio::spawn(async move {
            let app = tron_rpc::server::router(rpc_state);
            let server = axum::serve(listener, app.into_make_service());
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

    // === gRPC server ===
    //
    // Mirrors java-tron's port-50051 API surface. Same `RpcState` as
    // the JSON-RPC server, so the two surfaces always see identical
    // data — clients can mix and match.
    if !config.grpc.disabled {
        let grpc_state = stores
            .to_rpc_state(config.rpc.chain_id)
            .with_metrics(metrics.clone())
            .with_mempool(mempool.clone())
            .with_eth_call_gas_cap(eth_call_gas_cap)
            .with_support_constant(support_constant)
            .with_constant_call_timeout_ms(constant_call_timeout_ms)
            .with_pubsub(pubsub.clone());
        let addr: std::net::SocketAddr = format!("{}:{}", config.grpc.host, config.grpc.port)
            .parse()
            .map_err(|e: std::net::AddrParseError| RunError::Rpc(e.to_string()))?;
        let mut sd = shutdown.subscribe();
        handles.push(tokio::spawn(async move {
            let shutdown_fut = async move {
                let _ = sd.recv().await;
            };
            if let Err(e) = tron_grpc::start_server(grpc_state, addr, shutdown_fut).await {
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
        let http_state = stores
            .to_rpc_state(config.rpc.chain_id)
            .with_metrics(metrics.clone())
            .with_mempool(mempool.clone())
            .with_eth_call_gas_cap(eth_call_gas_cap)
            .with_support_constant(support_constant);
        let addr: std::net::SocketAddr = format!("{}:{}", config.http.host, config.http.port)
            .parse()
            .map_err(|e: std::net::AddrParseError| RunError::Rpc(e.to_string()))?;
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| RunError::Rpc(format!("bind {addr}: {e}")))?;
        info!(bound = %listener.local_addr().unwrap_or(addr), "HTTP REST listening");
        let mut sd = shutdown.subscribe();
        // Build the HTTP rate-limit registry from config. Each entry
        // binds a path-tail component (lowercased) to a strategy
        // (QPS / IP-QPS / Preemptible). Missing components pass
        // through unlimited, matching java-tron's interceptor
        // behavior on unconfigured servlets.
        let http_limits = build_rate_limit_registry(&config.rate_limiter.http);
        handles.push(tokio::spawn(async move {
            let shutdown_fut = async move {
                let _ = sd.recv().await;
            };
            let app = tron_rpc::http_rest::router_with_rate_limits(http_state, http_limits);
            let server = axum::serve(listener, app.into_make_service())
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
        let runtime = if config.storage.snapshot_reorg {
            runtime.with_snapshot_stack(stores.snapshots.clone())
        } else {
            runtime
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
    //   - Start from `config.p2p.peers` (CLI/TOML-supplied).
    //   - If `config.p2p.use_mainnet_seeds` is on, append the
    //     `tron_net::MAINNET_SEEDS` list (deduped against `peers`).
    //   - If the result is empty AND no explicit peers were given,
    //     fall back to MAINNET_SEEDS so `tron-node start` with no
    //     flags does something useful.
    //   - If `config.p2p.discover_enable`, spawn a KadService on the
    //     advertise port (UDP) bootstrapped from the assembled set,
    //     wait `discover_bootstrap_ms` for the routing table to fill,
    //     then merge the discovered peers in (deduped). This is what
    //     lifts us from "only ever talk to the 13 seeds" to "talk to
    //     the wider TRON network like a real java-tron node."
    let seed_peers = assemble_peers(&config.p2p);
    let mut combined_peers = seed_peers.clone();

    // Build NodePersistService over the `common` store. java-tron's
    // discovery layer flushes the active table to disk every 60s and
    // re-seeds from it on startup. This is what lets a restart skip
    // re-bootstrapping from MAINNET_SEEDS when a usable peer set is
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
                                    // Final flush on shutdown.
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

    // Cap to `max_peers` — each driver task owns one socket and one
    // KhaosDb; runaway peer lists from misconfiguration shouldn't
    // blow out the FD table. Shuffle the *non-seed tail* first so that
    // (a) explicit seeds always get a slot, (b) the discovered pool
    // (DNS + kad) is sampled diversely across ASNs/regions on each
    // restart rather than always taking the first 30 alphabetically.
    if combined_peers.len() > config.p2p.max_peers {
        let seed_count = seed_peers.len().min(combined_peers.len());
        let (head, tail) = combined_peers.split_at_mut(seed_count);
        use rand::seq::SliceRandom;
        tail.shuffle(&mut rand::thread_rng());
        let mut shuffled: Vec<String> = head.iter().cloned().collect();
        shuffled.extend(tail.iter().take(config.p2p.max_peers - seed_count).cloned());
        combined_peers = shuffled;
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
        let peer_registry = crate::PeerRegistry::new();
        let (eviction_tx, _eviction_rx_keep_alive) =
            tokio::sync::broadcast::channel::<String>(64);

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
        for peer in combined_peers {
            let cfg = crate::sync::SyncConfig {
                peers: vec![peer.clone()],
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
                peer_is_fast_forward: fast_forward_set.contains(&peer),
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
            let exec_config_for_peer = exec_config;
            let snapshot_stack_for_peer = if config.storage.snapshot_reorg {
                Some(stores.snapshots.clone())
            } else {
                None
            };
            let pubsub_for_peer = pubsub.clone();
            driver_handles.push(tokio::spawn(async move {
                let mut driver = crate::sync::SyncDriver::new(state_for_peer, cfg)
                    .with_metrics(metrics_for_peer)
                    .with_mempool(mempool_for_peer)
                    .with_undo_store(undo_for_peer)
                    .with_peer_state(peer_state_for_peer)
                    .with_node_statistics(node_stats_for_peer)
                    .with_peer_registry(peer_registry_for_peer)
                    .with_eviction_signal(eviction_tx_for_peer)
                    .with_exec_config(exec_config_for_peer)
                    .with_pubsub(pubsub_for_peer)
                    // Production runs the per-tx replay gate. The
                    // `BlockIndexStore` is populated from
                    // `initialize_genesis` onward, so the validator
                    // has chain history to compare against.
                    .with_strict_ref_block_check();
                if let Some(stack) = snapshot_stack_for_peer {
                    driver = driver.with_snapshot_stack(stack);
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
                (peer, driver.run(sd).await)
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
    let mut sd = shutdown.subscribe();
    let _ = sd.recv().await;
    info!("shutdown observed; waiting up to 5s for subsystems");

    // Give subsystems a moment to drain.
    let drain = tokio::time::timeout(Duration::from_secs(5), async {
        for h in handles {
            let _ = h.await;
        }
    });
    let _ = drain.await;
    info!("bye");
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
fn build_rate_limit_registry(
    items: &[crate::config::RateLimiterItem],
) -> tron_rpc::RateLimitRegistry {
    let mut map = std::collections::HashMap::new();
    for item in items {
        let key = item.component.to_lowercase();
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

/// True if `dyn_props` already has a head-pointer entry. Used to
/// skip re-applying genesis on a node that's already been bootstrapped.
fn chain_initialized(stores: &OpenedStores) -> bool {
    use tron_chainbase::DynamicPropertiesStore;
    let dp = DynamicPropertiesStore::new(stores.dyn_props.clone());
    dp.latest_block_header_number().is_some()
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
    block_store.put(&id, &block);
    let block_index = BlockIndexStore::new(stores.block_index.clone());
    block_index.put(&id);
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
    );

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
    info!("seeded committee.* governance flags into DynamicPropertiesStore");
}

fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

/// Combine `p2p.peers` with `MAINNET_SEEDS` when seeds are enabled or
/// when no explicit peers were given. Dedup preserves first-occurrence
/// order so a user-provided peer always sorts before a seed.
pub(crate) fn assemble_peers(p2p: &crate::config::P2pConfig) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for p in &p2p.peers {
        if seen.insert(p.clone()) {
            out.push(p.clone());
        }
    }
    let want_seeds = p2p.use_mainnet_seeds || p2p.peers.is_empty();
    if want_seeds {
        for s in tron_net::MAINNET_SEEDS {
            let s = (*s).to_string();
            if seen.insert(s.clone()) {
                out.push(s);
            }
        }
    }
    out
}

#[cfg(test)]
mod assemble_peers_tests {
    use super::assemble_peers;
    use crate::config::P2pConfig;

    #[test]
    fn empty_peers_falls_back_to_mainnet_seeds() {
        let p2p = P2pConfig::default();
        let peers = assemble_peers(&p2p);
        assert_eq!(peers.len(), tron_net::MAINNET_SEEDS.len());
    }

    #[test]
    fn explicit_peers_used_alone_when_seeds_disabled() {
        let p2p = P2pConfig {
            peers: vec!["1.2.3.4:18888".into()],
            use_mainnet_seeds: false,
            ..P2pConfig::default()
        };
        let peers = assemble_peers(&p2p);
        assert_eq!(peers, vec!["1.2.3.4:18888".to_string()]);
    }

    #[test]
    fn explicit_peers_plus_seeds_dedups_and_orders_explicit_first() {
        let seed0 = tron_net::MAINNET_SEEDS[0].to_string();
        let p2p = P2pConfig {
            peers: vec!["1.2.3.4:18888".into(), seed0.clone()],
            use_mainnet_seeds: true,
            ..P2pConfig::default()
        };
        let peers = assemble_peers(&p2p);
        // First two entries are the explicit peers, in order.
        assert_eq!(peers[0], "1.2.3.4:18888");
        assert_eq!(peers[1], seed0);
        // No duplicates of seed0 later.
        assert_eq!(peers.iter().filter(|p| **p == seed0).count(), 1);
        // Length = explicit (2) + remaining seeds.
        assert_eq!(peers.len(), 1 + tron_net::MAINNET_SEEDS.len());
    }
}
