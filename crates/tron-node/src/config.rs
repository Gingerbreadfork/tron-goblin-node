//! TOML-backed node configuration.
//!
//! The schema mirrors `tron-node start`'s CLI flags so a file and a
//! command-line invocation are interchangeable. CLI flags override
//! anything set in the file.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Directory holding `db/`, the writable on-disk state.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,

    /// JSON-RPC server settings.
    #[serde(default)]
    pub rpc: RpcConfig,

    /// P2P sync settings.
    #[serde(default)]
    pub p2p: P2pConfig,

    /// Prometheus metrics endpoint settings.
    #[serde(default)]
    pub metrics: MetricsConfig,

    /// gRPC server settings. Mirrors java-tron's port-50051 API so
    /// TronWeb / Java SDK / TronGrid clients can connect.
    #[serde(default)]
    pub grpc: GrpcConfig,

    /// HTTP REST API (port 8091 by default) — the surface that TronWeb,
    /// TronGrid, and the reference wallet-cli speak.
    #[serde(default)]
    pub http: HttpRestConfig,

    /// Super Representative block-production runtime. When `None`,
    /// the node runs sync-only. When set, a tokio task fires every
    /// 500ms checking whether we own the current slot per DPoS, and
    /// produces+broadcasts a block when we do.
    #[serde(default)]
    pub witness: Option<WitnessConfig>,
    /// `[bundler]` — optional ERC-4337 bundler. Off unless `enable = true`.
    #[serde(default)]
    pub bundler: Option<BundlerConfig>,
    /// java-tron `node.openHistoryQueryWhenLiteFN`: when the node runs
    /// on a LITE dataset (history pruned), the history-query APIs are
    /// closed with java's "this API is closed because this node is a
    /// lite fullnode" unless this is set. Default `false`.
    #[serde(default, alias = "openHistoryQueryWhenLiteFN")]
    pub open_history_query_when_lite_fn: bool,

    /// RocksDB tuning + DB-lifecycle settings.
    #[serde(default)]
    pub storage: StorageConfig,

    /// Event-plugin subscription settings. `None` (the default) leaves
    /// the eventer crate's local listeners as the only sinks. Set to
    /// enable the external-plugin schema mirroring java-tron's
    /// `event.subscribe.*` section.
    ///
    /// **Status**: schema only — the parser accepts these keys so that
    /// java-tron config files round-trip, but the plugin loader is not
    /// yet wired. Setting fields here is a no-op until the loader lands.
    #[serde(default)]
    pub event: Option<EventSubscribeConfig>,

    /// Witness-node high-availability backup-server settings. Mirrors
    /// java-tron's `node.backup.*`. Used by SR operators running an
    /// active/standby pair: the higher-priority instance announces
    /// itself on the backup port and the standby keeps quiet (won't
    /// produce blocks) as long as it sees the master.
    ///
    /// **Status**: schema only — the parser accepts these keys but the
    /// `BackupManager` runtime (backup election + standby coordination)
    /// is not yet wired.
    #[serde(default)]
    pub node_backup: NodeBackupConfig,

    /// EVM / TVM runtime knobs. Mirrors java-tron's `vm.*` section
    /// (constant-call energy ceilings, internal-tx save toggles, time
    /// ratios for the long-running gate, etc.).
    ///
    /// **Status**: schema parses with java-tron's clamps applied; only
    /// a subset of fields are consulted by the executor today.
    #[serde(default)]
    pub vm: VmConfig,

    /// Per-component rate-limiter bindings (`rate.limiter.http[]` and
    /// `rate.limiter.rpc[]`). Schema only — no enforcement wired yet.
    #[serde(default, alias = "rate", alias = "rateLimiter")]
    pub rate_limiter: RateLimiterConfig,

    /// Local-witness key sources (top-level `localwitness*` keys).
    /// Schema only — the SR runtime currently reads [`WitnessConfig`]
    /// instead. Folding these together is a follow-up.
    #[serde(default, alias = "localwitness_config")]
    pub local_witness: LocalWitnessConfig,

    /// Governance proposal bootstrap values (`committee.*`). Schema +
    /// clamps + cross-field validator parse with java-tron's rules;
    /// folding them into the genesis path is a separate follow-up.
    #[serde(default)]
    pub committee: CommitteeConfig,

    /// Built-in address-history indexer (`[index]`). Off by default;
    /// `enable = true` turns the node into its own TronGrid-compatible
    /// history API: a follower task backfills automatically from the
    /// local block store (no command), follows the live head, and the
    /// HTTP surface serves `/v1/accounts/{address}/transactions[/...]`.
    /// Everything lives under `<data_dir>/index/` and is disposable —
    /// delete it any time, the node rebuilds it.
    #[serde(default)]
    pub index: IndexConfig,
}

/// Per-store RocksDB tuning. The defaults mirror java-tron's
/// recommended mainnet profile: 64 MiB write buffer, 65 535
/// max-open files (Linux soft-limit minus headroom). Operators
/// running on smaller VMs should lower `write_buffer_size_mb` to
/// 16 or 32.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Per-CF write-buffer size in MiB. RocksDB flushes when this
    /// fills. Bigger = fewer flushes (faster write throughput) at
    /// the cost of memory.
    #[serde(default = "default_write_buffer_mb")]
    pub write_buffer_size_mb: usize,
    /// Max open SST file descriptors **per store**. Each chainbase store
    /// is its own RocksDB instance (~60 of them), so the process-wide
    /// ceiling is this value × the store count — set it with that
    /// multiplication in mind. The default (1024 → ~60k aggregate) stays
    /// well under typical `RLIMIT_NOFILE` while keeping a syncing node's
    /// working set resident; the daemon also raises its soft FD limit to
    /// the hard ceiling at startup (`raise_fd_limit`).
    #[serde(default = "default_max_open_files")]
    pub max_open_files: i32,
    /// Run a manual compaction (across every store) on startup. Off
    /// by default — only useful after a `prune-before` operation
    /// when the operator wants to reclaim disk space immediately.
    #[serde(default)]
    pub compact_on_start: bool,

    /// Per-CF RocksDB tuning mirroring java-tron's
    /// `storage.dbSettings.*`. Defaults match java-tron's
    /// `DbSettingsConfig`; `compact_threads = 0` resolves to
    /// `max(num_cpus, 1)` via [`DbSettingsConfig::resolve`].
    #[serde(default, alias = "dbSettings")]
    pub db_settings: DbSettingsConfig,

    /// Tx-cache tuning mirroring java-tron's `storage.txCache.*`.
    #[serde(default, alias = "txCache")]
    pub tx_cache: TxCacheConfig,

    /// Drive reorg via java-tron's `SnapshotManager`-style overlay
    /// stack (per-block tentative-write layers, revoked on reorg)
    /// instead of the `BlockUndoStore`-based undo-log path. Default
    /// `false` — the legacy path is battle-tested; the snapshot
    /// path is exercised by integration tests but hasn't been
    /// validated across multi-peer concurrency at mainnet scale.
    /// Operators enabling this should also configure
    /// `snapshot_horizon` to bound RAM.
    #[serde(default, alias = "snapshotReorg")]
    pub snapshot_reorg: bool,
    /// Bound on the snapshot-stack depth when `snapshot_reorg = true`.
    /// Defines the maximum number of blocks reorgable via revoke —
    /// blocks older than this have their layer merged into the root
    /// and become un-reorgable. Default `64`; mainnet rarely reorgs
    /// past ~10 blocks so this leaves comfortable headroom while
    /// capping the per-layer HashMap footprint.
    #[serde(default = "default_snapshot_horizon", alias = "snapshotHorizon")]
    pub snapshot_horizon: usize,
    /// Shared RocksDB block-cache ceiling, in MiB, across every store this
    /// process opens (state is ~30 separate DBs sharing one cache). A
    /// bigger cache keeps more of the multi-GB state hot, which is the
    /// dominant lever on catch-up throughput — sync is apply-bound and
    /// per-tx state reads that miss the cache hit disk. Default 1024 MiB;
    /// operators doing a full re-sync on a roomy box can raise it (e.g.
    /// 4096–8192) to cut read I/O. It's a ceiling that fills lazily, not a
    /// pre-allocation.
    #[serde(default = "default_block_cache_mb", alias = "blockCacheMb")]
    pub block_cache_mb: usize,
}

fn default_snapshot_horizon() -> usize {
    64
}

fn default_block_cache_mb() -> usize {
    1024
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            write_buffer_size_mb: default_write_buffer_mb(),
            max_open_files: default_max_open_files(),
            compact_on_start: false,
            db_settings: DbSettingsConfig::default(),
            tx_cache: TxCacheConfig::default(),
            snapshot_reorg: false,
            snapshot_horizon: default_snapshot_horizon(),
            block_cache_mb: default_block_cache_mb(),
        }
    }
}

/// Per-CF RocksDB tuning. Field defaults mirror java-tron's
/// `StorageConfig.DbSettingsConfig` exactly.
///
/// Accepted for `storage.dbSettings.*` config-file compatibility — a
/// config.conf copied from java-tron parses without error. These fields
/// are **not** wired into the store-open path: RocksDB column-family
/// options are derived from the detected hardware at startup
/// (`tron_chainbase::apply_runtime_tuning` / `rocksdb_tuning`), which
/// supersedes the static java knobs. Only `storage.write_buffer_size_mb`,
/// `storage.max_open_files`, and `storage.block_cache_mb` reach the open
/// path. Setting any field here has no effect today.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbSettingsConfig {
    #[serde(default = "default_db_level_number", alias = "levelNumber")]
    pub level_number: i32,
    /// `0` means "auto" — [`resolve`] expands to `max(num_cpus, 1)`.
    #[serde(default, alias = "compactThreads")]
    pub compact_threads: i32,
    #[serde(default = "default_db_blocksize")]
    pub blocksize: i32,
    #[serde(default = "default_db_max_bytes_for_level_base", alias = "maxBytesForLevelBase")]
    pub max_bytes_for_level_base: i64,
    #[serde(default = "default_db_max_bytes_for_level_multiplier", alias = "maxBytesForLevelMultiplier")]
    pub max_bytes_for_level_multiplier: f64,
    #[serde(default = "default_db_level0_compaction_trigger", alias = "level0FileNumCompactionTrigger")]
    pub level0_file_num_compaction_trigger: i32,
    #[serde(default = "default_db_target_file_size_base", alias = "targetFileSizeBase")]
    pub target_file_size_base: i64,
    #[serde(default = "default_db_target_file_size_multiplier", alias = "targetFileSizeMultiplier")]
    pub target_file_size_multiplier: i32,
    #[serde(default = "default_db_max_open_files_inner", alias = "maxOpenFiles")]
    pub max_open_files: i32,
}

impl Default for DbSettingsConfig {
    fn default() -> Self {
        Self {
            level_number: default_db_level_number(),
            compact_threads: 0,
            blocksize: default_db_blocksize(),
            max_bytes_for_level_base: default_db_max_bytes_for_level_base(),
            max_bytes_for_level_multiplier: default_db_max_bytes_for_level_multiplier(),
            level0_file_num_compaction_trigger: default_db_level0_compaction_trigger(),
            target_file_size_base: default_db_target_file_size_base(),
            target_file_size_multiplier: default_db_target_file_size_multiplier(),
            max_open_files: default_db_max_open_files_inner(),
        }
    }
}

impl DbSettingsConfig {
    /// Return a copy with `compact_threads = 0` expanded to
    /// `max(num_cpus, 1)`. Mirrors java-tron's
    /// `DbSettingsConfig.postProcess`.
    pub fn resolve(&self) -> Self {
        let mut out = self.clone();
        if out.compact_threads == 0 {
            // std::thread::available_parallelism returns Err on platforms
            // that can't introspect the CPU set; fall back to 1.
            let n = std::thread::available_parallelism()
                .map(|nz| nz.get() as i32)
                .unwrap_or(1);
            out.compact_threads = n.max(1);
        }
        out
    }
}

fn default_db_level_number() -> i32 {
    7
}
fn default_db_blocksize() -> i32 {
    16
}
fn default_db_max_bytes_for_level_base() -> i64 {
    256
}
fn default_db_max_bytes_for_level_multiplier() -> f64 {
    10.0
}
fn default_db_level0_compaction_trigger() -> i32 {
    2
}
fn default_db_target_file_size_base() -> i64 {
    64
}
fn default_db_target_file_size_multiplier() -> i32 {
    1
}
fn default_db_max_open_files_inner() -> i32 {
    5000
}

/// Tx-cache config. Mirrors java-tron's
/// `StorageConfig.TxCacheConfig`. `estimated_transactions` is clamped
/// to `[100, 10_000]` via [`TxCacheConfig::clamp`].
///
/// Accepted for `storage.txCache.*` config-file compatibility; not yet
/// wired into a runtime tx-cache (transaction dedup is handled elsewhere
/// in the apply path). Setting these has no effect today.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxCacheConfig {
    #[serde(default = "default_tx_cache_estimated", alias = "estimatedTransactions")]
    pub estimated_transactions: i32,
    /// java-tron's `tx-cache.initOptimization` toggle (eager BloomFilter
    /// build on startup vs. lazy). Default `false`.
    #[serde(default, alias = "initOptimization")]
    pub init_optimization: bool,
}

impl Default for TxCacheConfig {
    fn default() -> Self {
        Self {
            estimated_transactions: default_tx_cache_estimated(),
            init_optimization: false,
        }
    }
}

impl TxCacheConfig {
    pub const MIN_ESTIMATED_TXS: i32 = 100;
    pub const MAX_ESTIMATED_TXS: i32 = 10_000;

    /// In-place clamp mirroring java-tron's `postProcess`.
    pub fn clamp(&mut self) {
        if self.estimated_transactions > Self::MAX_ESTIMATED_TXS {
            self.estimated_transactions = Self::MAX_ESTIMATED_TXS;
        } else if self.estimated_transactions < Self::MIN_ESTIMATED_TXS {
            self.estimated_transactions = Self::MIN_ESTIMATED_TXS;
        }
    }
}

fn default_tx_cache_estimated() -> i32 {
    1000
}

fn default_write_buffer_mb() -> usize {
    64
}
fn default_max_open_files() -> i32 {
    // Per-store (each store is its own RocksDB instance). ~60 stores ×
    // 1024 ≈ 60k aggregate FDs — safe under typical limits, unlike the
    // old 65_535 which multiplied out to millions and exhausted the
    // process mid-sync (M-21).
    1024
}

/// Configuration for the SR block-production runtime.
///
/// Exactly one of `key_hex`, `key_env`, or `keystore` must be set.
/// `key_hex` writes the raw private key into the config file (NOT
/// recommended for production); `key_env` reads from an environment
/// variable at startup; `keystore` reads a v3 JSON keystore + a
/// password from `keystore_password_env`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WitnessConfig {
    /// Optional raw private key hex (`0x`-prefix optional). DISCOURAGED.
    pub key_hex: Option<String>,
    /// Environment variable name holding the raw private key hex.
    pub key_env: Option<String>,
    /// Path to a v3 keystore JSON file (java-tron compatible).
    pub keystore: Option<std::path::PathBuf>,
    /// Environment variable holding the keystore password. Required
    /// when `keystore` is set.
    pub keystore_password_env: Option<String>,
    /// Maximum number of transactions to pull from the mempool per
    /// produced block. Default 1000 (well below mainnet's typical
    /// per-block budget; tunable upward for high-load networks).
    #[serde(default = "default_max_txs_per_block")]
    pub max_txs_per_block: usize,
}

fn default_max_txs_per_block() -> usize {
    1000
}

/// `[bundler]` — ERC-4337 account-abstraction bundler. When `enable = true` with
/// a signing key, the node exposes the bundler RPC namespace
/// (`eth_sendUserOperation` etc.) and submits `handleOps` transactions signed
/// with this key. Exactly one of `key_hex`/`key_env`/`keystore` must be set
/// (same key sources as `[witness]`). Off-protocol — no consensus effect.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BundlerConfig {
    /// Master switch. The bundler stays off unless this is `true`.
    #[serde(default)]
    pub enable: bool,
    /// EntryPoint contract addresses this bundler accepts (operator-deployed;
    /// `0x…` 20-byte EVM, TRON `41…`, or base58 `T…`).
    #[serde(default)]
    pub entry_points: Vec<String>,
    /// Optional raw private key hex for signing handleOps txs. DISCOURAGED.
    pub key_hex: Option<String>,
    /// Environment variable name holding the raw private key hex.
    pub key_env: Option<String>,
    /// Path to a v3 keystore JSON file (java-tron compatible).
    pub keystore: Option<std::path::PathBuf>,
    /// Environment variable holding the keystore password (required with `keystore`).
    pub keystore_password_env: Option<String>,
    /// Gas-fee beneficiary passed to `handleOps`. Defaults to the bundler's address.
    pub beneficiary: Option<String>,
    /// Per-bundle TRX fee cap, in sun. Default 1e9 (1000 TRX).
    #[serde(default = "default_bundler_fee_limit")]
    pub fee_limit_sun: i64,
    /// Bundling mode: `auto` submits pending ops on the interval; `manual` holds
    /// them until `debug_bundler_sendBundleNow`. Default `auto`.
    #[serde(default = "default_bundling_mode")]
    pub bundling_mode: String,
    /// Auto-mode bundling cadence, in milliseconds. Default 2000.
    #[serde(default = "default_bundle_interval_ms")]
    pub bundle_interval_ms: u64,
    /// Max UserOps packed into one `handleOps` bundle. Default 50.
    #[serde(default = "default_max_bundle_size")]
    pub max_bundle_size: usize,
    /// Enforce ERC-7562 opcode/storage validation rules on accept. Default true.
    #[serde(default = "default_enforce_validation_rules")]
    pub enforce_validation_rules: bool,
}

fn default_enforce_validation_rules() -> bool {
    true
}

fn default_bundler_fee_limit() -> i64 {
    1_000_000_000
}

fn default_bundling_mode() -> String {
    "auto".to_string()
}

fn default_bundle_interval_ms() -> u64 {
    2_000
}

fn default_max_bundle_size() -> usize {
    50
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRestConfig {
    /// Bind host. `127.0.0.1` by default; set to `0.0.0.0` for public
    /// exposure (the HTTP REST surface includes `broadcasttransaction`
    /// — be deliberate before opening it up).
    #[serde(default = "default_http_host")]
    pub host: String,
    /// Listen port. `8091` = java-tron's `8090` + 1, so a java-tron node and
    /// this one can share a host without clashing. (TronWeb/TronGrid targets
    /// are configurable — point them at 8091, or override this back to 8090.)
    #[serde(default = "default_http_port")]
    pub port: u16,
    /// Set to `true` to disable the HTTP REST server entirely.
    #[serde(default)]
    pub disabled: bool,
}

impl Default for HttpRestConfig {
    fn default() -> Self {
        Self {
            host: default_http_host(),
            port: default_http_port(),
            disabled: false,
        }
    }
}

fn default_http_host() -> String {
    "127.0.0.1".into()
}
fn default_http_port() -> u16 {
    8091
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrpcConfig {
    /// Bind host. `127.0.0.1` by default — set to `0.0.0.0` for
    /// public exposure (the gRPC surface includes writer methods).
    #[serde(default = "default_grpc_host")]
    pub host: String,
    /// Listen port. `50052` = java-tron's `50051` + 1, so both can run on one
    /// host without clashing. (Client libs are configurable — point them here,
    /// or override this back to 50051.)
    #[serde(default = "default_grpc_port")]
    pub port: u16,
    /// Set to `true` to disable the gRPC server entirely.
    #[serde(default)]
    pub disabled: bool,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            host: default_grpc_host(),
            port: default_grpc_port(),
            disabled: false,
        }
    }
}

fn default_grpc_host() -> String {
    "127.0.0.1".into()
}
fn default_grpc_port() -> u16 {
    50052
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Bind host. `127.0.0.1` by default — metrics endpoints
    /// typically shouldn't be exposed publicly.
    #[serde(default = "default_metrics_host")]
    pub host: String,
    /// Listen port. `9091` = the Prometheus default `9090` + 1, keeping the
    /// node's whole port block one above java-tron's so they coexist.
    #[serde(default = "default_metrics_port")]
    pub port: u16,
    /// Set to `true` to disable the metrics endpoint entirely.
    #[serde(default)]
    pub disabled: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            host: default_metrics_host(),
            port: default_metrics_port(),
            disabled: false,
        }
    }
}

fn default_metrics_host() -> String {
    "127.0.0.1".into()
}
fn default_metrics_port() -> u16 {
    9091
}

// -- event.subscribe.* (java-tron parity schema) --

/// Top-level container mirroring java-tron's `event.subscribe` section
/// (`EventPluginConfig` + `FilterQuery`). Schema is wire-compatible
/// with `config.conf`; semantics deferred (no plugin loader yet).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventSubscribeConfig {
    /// Master enable. When `false`, every other field is ignored.
    #[serde(default)]
    pub enable: bool,
    /// Filesystem path to the plugin (.zip on JVM, .so/.dylib on
    /// native, etc.).
    #[serde(default)]
    pub path: String,
    /// Remote server endpoint (Kafka brokers, NATS, etc.) the plugin
    /// uses to publish.
    #[serde(default)]
    pub server: String,
    /// Plugin-specific DB connection string (MongoDB-style URI in the
    /// java-tron reference plugins).
    #[serde(default, alias = "dbconfig", rename = "db_config")]
    pub db_config: String,
    /// Block number to start replaying triggers from. `0` means
    /// "from the current tip".
    #[serde(default, alias = "startSyncBlockNum")]
    pub start_sync_block_num: i64,
    /// When `true`, use the in-process queue ZeroMQ binding instead of
    /// the plugin .zip pipeline.
    #[serde(default, alias = "useNativeQueue")]
    pub use_native_queue: bool,
    /// TCP port the native-queue ZeroMQ socket binds to. Ignored when
    /// `use_native_queue == false`.
    #[serde(default, alias = "bindPort")]
    pub bind_port: u16,
    /// Bounded send-queue length for the native-queue publisher.
    /// `0` means unbounded (matches java-tron's default).
    #[serde(default, alias = "sendQueueLength")]
    pub send_queue_length: usize,
    /// Per-trigger enable + topic-name overrides. See
    /// [`EventTopicConfig`].
    #[serde(default)]
    pub topics: Vec<EventTopicConfig>,
    /// Block-range + contract address/topic filter for the contract
    /// triggers (`contractevent`, `contractlog`, `solidityevent`,
    /// `soliditylog`). See [`EventFilterConfig`].
    #[serde(default)]
    pub filter: EventFilterConfig,
    /// Run the ABI decoder on contract logs before posting. Mirrors
    /// java-tron's `event.subscribe.contractParse`.
    #[serde(default, alias = "contractParse")]
    pub contract_parse: bool,
}

/// One row of `event.subscribe.topics[]`. Mirrors java-tron's
/// `TriggerConfig`.
///
/// Valid `trigger_name` values match java-tron's
/// `EventPluginConfig.*_TRIGGER_NAME` constants:
/// `"block"`, `"transaction"`, `"contractevent"`, `"contractlog"`,
/// `"solidity"`, `"solidityevent"`, `"soliditylog"`. Anything else is
/// accepted at parse time but ignored at runtime by the loader.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventTopicConfig {
    #[serde(default, alias = "triggerName")]
    pub trigger_name: String,
    #[serde(default, alias = "enabled")]
    pub enable: bool,
    #[serde(default)]
    pub topic: String,
    /// When `true`, the event is **also** written to the standard log
    /// sink (so a misbehaving plugin doesn't lose history).
    #[serde(default)]
    pub redundancy: bool,
    /// Eth-compatible field set (extra hashes, gas, etc.) — currently
    /// only meaningful for `"transaction"`.
    #[serde(default, alias = "ethCompatible")]
    pub eth_compatible: bool,
    /// Only post once the block has solidified. Only meaningful for
    /// `"block"` and `"transaction"`.
    #[serde(default)]
    pub solidified: bool,
}

/// Block-range + contract filter applied to contract triggers.
///
/// `from_block` / `to_block` accept the same literals as java-tron:
/// the empty string `""` or `"earliest"` map to block 0; `""` or
/// `"latest"` for `to_block` means "no upper bound". Numeric strings
/// are parsed via [`FilterQuery::parse_from_block`] /
/// [`FilterQuery::parse_to_block`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventFilterConfig {
    #[serde(default, alias = "fromblock")]
    pub from_block: String,
    #[serde(default, alias = "toblock")]
    pub to_block: String,
    /// Hex-prefixed (`41…`) base58 (`T…`) or 0x-eth addresses — same
    /// strings java-tron accepts.
    #[serde(default, alias = "contractAddress")]
    pub contract_addresses: Vec<String>,
    /// Topic hex strings (32-byte log topics). Matches java-tron's
    /// `contractTopic` list.
    #[serde(default, alias = "contractTopic")]
    pub contract_topics: Vec<String>,
}

/// Resolved block-range filter, after string→i64 parsing.
///
/// Same sentinel values as java-tron's `FilterQuery`:
/// * `from_block` of `0` = `EARLIEST_BLOCK_NUM`
/// * `to_block` of `-1` = `LATEST_BLOCK_NUM` ("no upper bound")
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilterQuery {
    pub from_block: i64,
    pub to_block: i64,
}

impl FilterQuery {
    pub const EARLIEST_BLOCK_NUM: i64 = 0;
    pub const LATEST_BLOCK_NUM: i64 = -1;

    /// `""` / `"earliest"` → 0; everything else parsed as decimal i64.
    /// Returns an error on unparseable input (java-tron would throw
    /// `NumberFormatException`; we surface it as a `ConfigError`).
    pub fn parse_from_block(s: &str) -> Result<i64, ConfigError> {
        let t = s.trim();
        if t.is_empty() || t.eq_ignore_ascii_case("earliest") {
            return Ok(Self::EARLIEST_BLOCK_NUM);
        }
        t.parse::<i64>().map_err(|e| ConfigError::FilterQuery {
            field: "from_block",
            value: s.to_string(),
            source: e,
        })
    }

    /// `""` / `"latest"` → -1; everything else parsed as decimal i64.
    pub fn parse_to_block(s: &str) -> Result<i64, ConfigError> {
        let t = s.trim();
        if t.is_empty() || t.eq_ignore_ascii_case("latest") {
            return Ok(Self::LATEST_BLOCK_NUM);
        }
        t.parse::<i64>().map_err(|e| ConfigError::FilterQuery {
            field: "to_block",
            value: s.to_string(),
            source: e,
        })
    }

    /// Resolve both ends of an [`EventFilterConfig`]'s string range.
    pub fn from_event_filter(cfg: &EventFilterConfig) -> Result<Self, ConfigError> {
        Ok(Self {
            from_block: Self::parse_from_block(&cfg.from_block)?,
            to_block: Self::parse_to_block(&cfg.to_block)?,
        })
    }
}

// -- node.backup.* (java-tron parity schema) --

/// Mirrors java-tron's `NodeConfig.NodeBackupConfig` (`node.backup.*`).
/// Used by the SR backup-server election: the higher-priority instance
/// claims the master role and the lower-priority standby suppresses
/// block production while the master is reachable.
///
/// **Status**: schema only. The `BackupManager` runtime that consumes
/// these fields is not yet ported.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeBackupConfig {
    /// Election priority. Higher value wins; ties are broken by the
    /// `members` list order. Default `0`.
    #[serde(default)]
    pub priority: i32,
    /// UDP port the backup-server keep-alive packets bind to. java-tron
    /// default `10001`.
    #[serde(default = "default_node_backup_port")]
    pub port: u16,
    /// Keep-alive packet interval in milliseconds. java-tron default
    /// `3000`.
    #[serde(default = "default_node_backup_keep_alive_interval", alias = "keepAliveInterval")]
    pub keep_alive_interval: u64,
    /// Peer-list: IP addresses (or DNS names) of every node in the
    /// backup cluster. Empty list disables the backup-server entirely
    /// (matches java-tron behaviour).
    #[serde(default)]
    pub members: Vec<String>,
}

impl Default for NodeBackupConfig {
    fn default() -> Self {
        Self {
            priority: 0,
            port: default_node_backup_port(),
            keep_alive_interval: default_node_backup_keep_alive_interval(),
            members: Vec::new(),
        }
    }
}

fn default_node_backup_port() -> u16 {
    10001
}

fn default_node_backup_keep_alive_interval() -> u64 {
    3_000
}

// -- vm.* (java-tron parity schema) --

/// Mirrors java-tron's `VmConfig` (`vm.*` section). Field defaults and
/// clamps match `VmConfig.postProcess` exactly so a `config.conf` and
/// our TOML round-trip to the same effective values.
///
/// **Status**: parses with java-tron's clamps applied (via
/// [`VmConfig::clamp`]); only a subset of fields are consulted by the
/// executor today.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmConfig {
    /// Allow `constant`/`view` calls without a signature. Default
    /// `false`; mainnet operators that expose `triggerConstantContract`
    /// publicly leave this off.
    #[serde(default, alias = "supportConstant")]
    pub support_constant: bool,
    /// Hard ceiling on energy a constant call may consume. java-tron
    /// silently clamps inputs below `3_000_000` up to that floor —
    /// [`VmConfig::clamp`] replicates that. Default `100_000_000`.
    #[serde(default = "default_vm_max_energy_for_constant", alias = "maxEnergyLimitForConstant")]
    pub max_energy_limit_for_constant: i64,
    /// LRU cache size for compiled contract bytecode. Default `500`.
    #[serde(default = "default_vm_lru_cache_size", alias = "lruCacheSize")]
    pub lru_cache_size: i32,
    /// Lower bound on the (CPU-time / mainnet-time) ratio under which a
    /// contract is considered "fast enough" not to trip the long-running
    /// gate. Default `0.0`.
    #[serde(default, alias = "minTimeRatio")]
    pub min_time_ratio: f64,
    /// Upper bound on the (CPU-time / mainnet-time) ratio. Default
    /// `5.0`; raise on slow hosts so the long-running gate doesn't fire
    /// on legitimate contracts.
    #[serde(default = "default_vm_max_time_ratio", alias = "maxTimeRatio")]
    pub max_time_ratio: f64,
    /// Slot-budget cutoff (ms) above which a contract counts as
    /// "long-running" for the rate-limit gate. Default `10`.
    #[serde(default = "default_vm_long_running_time", alias = "longRunningTime")]
    pub long_running_time: i32,
    /// Enable the eth-style `estimateGas` RPC. Default `false`.
    #[serde(default, alias = "estimateEnergy")]
    pub estimate_energy: bool,
    /// Max retry attempts inside `estimateGas` binary search. java-tron
    /// clamps to `[0, 10]`. Default `3`.
    #[serde(default = "default_vm_estimate_energy_max_retry", alias = "estimateEnergyMaxRetry")]
    pub estimate_energy_max_retry: i32,
    /// Emit the per-opcode VM trace alongside the contract receipt.
    /// Mainnet operators leave this off — the traces are huge.
    /// Default `false`.
    #[serde(default, alias = "vmTrace")]
    pub vm_trace: bool,
    /// Persist plain internal-transactions (every CALL/CREATE/SELFDESTRUCT).
    /// Default `false`.
    #[serde(default, alias = "saveInternalTx")]
    pub save_internal_tx: bool,
    /// Persist "featured" internal-transactions: the system-contract
    /// calls (delegate/freeze/etc.). Default `false`.
    #[serde(default, alias = "saveFeaturedInternalTx")]
    pub save_featured_internal_tx: bool,
    /// Persist the per-unfreeze details produced by
    /// `cancelAllUnfreezeV2`. Inert unless both `save_internal_tx` and
    /// `save_featured_internal_tx` are `true` (java-tron logs a warning
    /// in that case; we surface the same warning via
    /// [`VmConfig::cross_field_warnings`]). Default `false`.
    #[serde(default, alias = "saveCancelAllUnfreezeV2Details")]
    pub save_cancel_all_unfreeze_v2_details: bool,
    /// Wall-clock timeout (ms) applied to constant-call evaluation.
    /// `0` means "no timeout" (java-tron treats this field as opt-in;
    /// the value must be `> 0` and `<= i64::MAX / 1_000` when set —
    /// [`VmConfig::validate_constant_call_timeout`] enforces both).
    /// Default `0`.
    #[serde(default, alias = "constantCallTimeoutMs")]
    pub constant_call_timeout_ms: i64,
    /// Master switch for Block-STM optimistic parallel block execution
    /// during catch-up (byte-identical to serial; the `SyncDriver` only
    /// turns it on per-block while bulk-syncing, never at the tip).
    ///
    /// **Default `true`.** Byte-identical to serial. After the
    /// dependency-ordered scheduler rewrite it runs faster than serial on a
    /// real RocksDB-backed mainnet catch-up; an earlier naive scheduler was
    /// slower (per-read MVCC bookkeeping plus thread allocator / block-cache
    /// contention outweighed the parallelism), which is why it first shipped
    /// off. Set `false` to force the serial loop (run with `BLOCKSTM_DEBUG=1`
    /// to log per-block convergence: `rounds`/`reexecs`/`converged`).
    #[serde(default = "default_vm_parallel_exec", alias = "parallelExec")]
    pub parallel_exec: bool,
    /// Overlap each applied block's commit I/O (cross-store checkpoint
    /// manifest fsync + per-store write batches + undo-log fsync) with the
    /// next block's execution while bulk-draining the sync fetch pool.
    /// Byte-identical writes in the same order — only the overlap changes;
    /// the pipeline is flushed at the end of every drain batch and before
    /// any reorg, so everything outside the drain loop observes fully
    /// committed state. Auto-disabled when the node produces blocks
    /// (`[witness]`) or runs the snapshot-stack reorg path
    /// (`storage.snapshot_reorg`).
    ///
    /// **Default `true`.** Set `false` to A/B against the strictly serial
    /// apply path.
    #[serde(default = "default_vm_pipelined_apply", alias = "pipelinedApply")]
    pub pipelined_apply: bool,
}

fn default_vm_pipelined_apply() -> bool {
    true
}

fn default_vm_parallel_exec() -> bool {
    true
}

impl Default for VmConfig {
    fn default() -> Self {
        Self {
            support_constant: false,
            max_energy_limit_for_constant: default_vm_max_energy_for_constant(),
            lru_cache_size: default_vm_lru_cache_size(),
            min_time_ratio: 0.0,
            max_time_ratio: default_vm_max_time_ratio(),
            long_running_time: default_vm_long_running_time(),
            estimate_energy: false,
            estimate_energy_max_retry: default_vm_estimate_energy_max_retry(),
            vm_trace: false,
            save_internal_tx: false,
            save_featured_internal_tx: false,
            save_cancel_all_unfreeze_v2_details: false,
            constant_call_timeout_ms: 0,
            parallel_exec: default_vm_parallel_exec(),
            pipelined_apply: default_vm_pipelined_apply(),
        }
    }
}

impl VmConfig {
    /// Lower bound that java-tron applies to `maxEnergyLimitForConstant`.
    pub const MIN_MAX_ENERGY_LIMIT_FOR_CONSTANT: i64 = 3_000_000;
    /// `estimateEnergyMaxRetry` is clamped to `[0, MAX_ESTIMATE_RETRY]`.
    pub const MAX_ESTIMATE_RETRY: i32 = 10;
    /// Java-tron's `MAX_CONSTANT_CALL_TIMEOUT_MS` =
    /// `Long.MAX_VALUE / 1_000`. Larger values can't be safely
    /// converted to microseconds inside the VM deadline checker.
    pub const MAX_CONSTANT_CALL_TIMEOUT_MS: i64 = i64::MAX / 1_000;

    /// Apply java-tron's `postProcess` clamps in-place. Called by
    /// [`NodeConfig::resolve_vm`]; tests may call it directly.
    pub fn clamp(&mut self) {
        if self.max_energy_limit_for_constant < Self::MIN_MAX_ENERGY_LIMIT_FOR_CONSTANT {
            self.max_energy_limit_for_constant = Self::MIN_MAX_ENERGY_LIMIT_FOR_CONSTANT;
        }
        if self.estimate_energy_max_retry < 0 {
            self.estimate_energy_max_retry = 0;
        }
        if self.estimate_energy_max_retry > Self::MAX_ESTIMATE_RETRY {
            self.estimate_energy_max_retry = Self::MAX_ESTIMATE_RETRY;
        }
    }

    /// Validate `constant_call_timeout_ms` per java-tron's rule:
    /// when non-zero it must be in `(0, MAX_CONSTANT_CALL_TIMEOUT_MS]`.
    /// `0` is "unset" and accepted.
    pub fn validate_constant_call_timeout(&self) -> Result<(), ConfigError> {
        if self.constant_call_timeout_ms == 0 {
            return Ok(());
        }
        if self.constant_call_timeout_ms < 0 {
            return Err(ConfigError::VmConfig(format!(
                "vm.constantCallTimeoutMs must be > 0 when configured, got {}",
                self.constant_call_timeout_ms
            )));
        }
        if self.constant_call_timeout_ms > Self::MAX_CONSTANT_CALL_TIMEOUT_MS {
            return Err(ConfigError::VmConfig(format!(
                "vm.constantCallTimeoutMs must be <= {} to fit VM deadline conversion, got {}",
                Self::MAX_CONSTANT_CALL_TIMEOUT_MS,
                self.constant_call_timeout_ms
            )));
        }
        Ok(())
    }

    /// Return the (non-fatal) warning java-tron emits when
    /// `save_cancel_all_unfreeze_v2_details` is on but its prerequisites
    /// (`save_internal_tx` + `save_featured_internal_tx`) are off.
    pub fn cross_field_warnings(&self) -> Option<&'static str> {
        if self.save_cancel_all_unfreeze_v2_details
            && (!self.save_internal_tx || !self.save_featured_internal_tx)
        {
            Some(
                "Configuring [vm.saveCancelAllUnfreezeV2Details] won't work as \
                 vm.saveInternalTx or vm.saveFeaturedInternalTx is off.",
            )
        } else {
            None
        }
    }
}

fn default_vm_max_energy_for_constant() -> i64 {
    100_000_000
}
fn default_vm_lru_cache_size() -> i32 {
    500
}
fn default_vm_max_time_ratio() -> f64 {
    5.0
}
fn default_vm_long_running_time() -> i32 {
    10
}
fn default_vm_estimate_energy_max_retry() -> i32 {
    3
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcConfig {
    /// Bind host. `127.0.0.1` by default to avoid exposing the server
    /// unexpectedly; set to `0.0.0.0` to listen on every interface.
    #[serde(default = "default_rpc_host")]
    pub host: String,
    /// Listen port. `8546` = the Ethereum-standard `8545` + 1, keeping the
    /// node's port block one above java-tron's (whose optional JSON-RPC also
    /// defaults to 8545) so they coexist. Point Ethereum wallets at 8546, or
    /// override this back to 8545.
    #[serde(default = "default_rpc_port")]
    pub port: u16,
    /// Set to `true` to disable the RPC server entirely.
    #[serde(default)]
    pub disabled: bool,
    /// EIP-155 chain id surfaced via `eth_chainId` and `net_version`.
    #[serde(default = "default_chain_id")]
    pub chain_id: u64,

    /// `eth_call` / `eth_estimateGas` per-call gas cap. revm's
    /// default is `eip7825::TX_GAS_LIMIT_CAP` (16,777,216). java-tron's
    /// HTTP `triggerConstantContract` accepts arbitrary `fee_limit`
    /// (mainnet hard-caps it at 5000 TRX ≈ ~17.85M energy), so this
    /// is bumped to 50M by default to cover heavy read-only calls
    /// (DEX simulations, big multi-hop swaps). Override via TOML for
    /// public-facing nodes that want a tighter ceiling.
    #[serde(default = "default_eth_call_gas_cap")]
    pub eth_call_gas_cap: u64,
}

fn default_eth_call_gas_cap() -> u64 {
    50_000_000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pConfig {
    /// Peer addresses to sync from. Each entry is `HOST:PORT`. If
    /// empty, the node stays at its current head and serves RPC only.
    #[serde(default)]
    pub peers: Vec<String>,
    /// Optional cap on the number of blocks to apply per sync pass —
    /// useful for testing and bounded smoke runs. `None` = unlimited.
    #[serde(default)]
    pub max_blocks: Option<usize>,
    /// Set to `true` to skip the sync loop entirely (RPC-only mode).
    #[serde(default)]
    pub disabled: bool,
    /// Enable the human-readable sync-progress log line (height + block
    /// wall-clock + lag behind real time + apply rate + peer). `0` =
    /// silent (only failures logged); any non-zero value enables it. The
    /// cadence is **time-throttled** — roughly every 5s while catching up,
    /// every 30s once following the tip — so it stays readable at any sync
    /// speed rather than flooding during catch-up and going silent at the
    /// tip. (In `--tip-test` mode the value is still used as a per-N-block
    /// count gate.) Default `100` ⇒ enabled.
    #[serde(default = "default_progress_log_interval")]
    pub progress_log_interval: usize,
    /// Port we advertise to peers in our Hello messages. Default `18889`
    /// (one above java-tron's mainnet P2P port `18888`, so both nodes can
    /// share a host). java-tron's `NetUtil.validNode` rejects port `0` with
    /// `BAD_PROTOCOL`, so
    /// even sync-only nodes that don't listen still need to advertise
    /// a valid port.
    #[serde(default = "default_advertise_port")]
    pub advertise_port: i32,
    /// Maximum number of concurrent peer connections. java-tron's
    /// default is 30 on mainnet (`maxConnections`). Each peer holds
    /// one tokio task + one open TCP socket; capping prevents
    /// runaway resource use on long peer-list misconfigurations.
    #[serde(default = "default_max_peers")]
    pub max_peers: usize,
    /// Accept INBOUND P2P connections so other peers (java-tron deployments and
    /// our own kind) can sync FROM us. When on, we bind `listen_host:advertise_port`
    /// and serve the sync protocol (SyncBlockChain → inventory, FetchInvData →
    /// blocks) over accepted connections. Default `true` — a full node should be
    /// reachable; set `false` for a pure outbound-only / firewalled sync client.
    #[serde(default = "default_listen")]
    pub listen: bool,
    /// Interface to bind the inbound P2P listener on. Default `0.0.0.0` (all
    /// interfaces). The port is `advertise_port` (the same one we tell peers to
    /// dial). Only consulted when `listen = true`.
    #[serde(default = "default_listen_host")]
    pub listen_host: String,
    /// Enable Kademlia DHT peer discovery. When on, bootstraps from any
    /// explicit `peers` over UDP, then augments the TCP dial list with the
    /// discovered peers. java-tron parity flag: `node.p2p.discover.enable`.
    #[serde(default = "default_discover_enable")]
    pub discover_enable: bool,
    /// How long to wait at startup for the DHT bootstrap to populate
    /// the routing table before snapshotting it into the sync dial
    /// list. Too short and we miss the first wave of Neighbours
    /// responses; too long delays the first sync attempt. Default 5s.
    #[serde(default = "default_discover_bootstrap_ms")]
    pub discover_bootstrap_ms: u64,
    /// EIP-1459-style DNS-discovery tree URLs to walk at startup.
    /// Format: `tree://{base32_pubkey}@{domain}`. java-tron parity flag:
    /// `node.p2p.dns.treeUrls`. Mainnet's official tree
    /// (`main.trondisco.net`) is included by default. The walk happens
    /// once during the bootstrap window; discovered endpoints are
    /// merged into the sync dial list with the seeds + kad-discovered
    /// peers. Set to `[]` to disable.
    #[serde(default = "default_discover_tree_urls")]
    pub discover_tree_urls: Vec<String>,
    /// Per-query timeout for DNS lookups during tree-walk. Default 5s.
    #[serde(default = "default_discover_tree_query_timeout_ms")]
    pub discover_tree_query_timeout_ms: u64,
    /// Persist the discovered peer set to `CommonStore["peers"]` so a
    /// restart can re-dial known-good peers without waiting on
    /// bootstrap. Java-tron parity flag: `node.discovery.persist`
    /// (default true). The on-disk JSON shape matches `DBNodes`/`DBNode`.
    #[serde(default = "default_node_discovery_persist")]
    pub node_discovery_persist: bool,
    /// How often to flush the discovery table to disk while running.
    /// Matches java-tron's `NodePersistService.DB_COMMIT_RATE` (60s).
    #[serde(default = "default_node_discovery_persist_interval_ms")]
    pub node_discovery_persist_interval_ms: u64,
    /// Timeout for the live-tip single-slot block fetch in ms. Used
    /// by `FetchBlockScheduler` to release the in-flight slot after
    /// `timeout * BLOCK_FETCH_LEFT_TIME_PERCENT` (50%). Java-tron
    /// clamps to `[100, 1000]`; we mirror that at the use site.
    /// Default 200.
    #[serde(default = "default_fetch_block_timeout_ms")]
    pub fetch_block_timeout_ms: u64,
    /// Cooperative-fetch per-peer in-flight block cap (only consulted when
    /// [`Self::multi_peer_fetch`] is on). The most blocks this node will have
    /// outstanding to ANY single peer at once — the per-peer back-pressure that
    /// keeps the fetch fan-out spread across many peers instead of letting one
    /// fast peer vacuum the whole window. Lower = more peers share the load
    /// (better citizenship, no single host overloaded); higher = deeper
    /// per-peer pipeline. java-tron's own pull cap is `MAX_BLOCK_FETCH_PER_PEER`
    /// (100); we stay at or below that so we never out-pressure what a peer
    /// expects from one connection. Default 64 keeps a healthy per-peer pipe
    /// while leaving headroom under the 100 cap and spreading the rest across
    /// the fleet. Clamped to `[16, 100]` at the use site.
    #[serde(
        default = "default_sync_fetch_inflight_per_peer",
        alias = "syncFetchInflightPerPeer"
    )]
    pub sync_fetch_inflight_per_peer: usize,
    /// Operator-supplied `fastForwardNodes` set. Each entry is a peer
    /// `HOST:PORT` string. When a SR produces a block, peers in this
    /// list receive the full `Block` frame directly (lowest-latency
    /// push); peers NOT in the list receive only an `Inventory(BLOCK)`
    /// advertisement and must pull the body via `FetchInvData`.
    /// Mirrors java-tron's `RelayService.fastForwardNodes`.
    #[serde(default)]
    pub fast_forward_nodes: Vec<String>,
    /// Tip-test mode: spoof our local head to `Some((block_num, hash))`
    /// before sync starts, then accept incoming Block frames *without*
    /// validating or executing them — just count + log. Lets us
    /// exercise multi-peer sync against modern validators that pruned
    /// the genesis-era state and would otherwise FETCH_FAIL on an
    /// archive sync request. NOT a real sync — the chain state is left
    /// untouched. Skips KhaosDb seeding too.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tip_test: Option<TipTestCheckpoint>,
    /// Cooperative multi-peer block fetch: when on, every connected
    /// ahead-of-us peer helps fetch the sync backlog (each on its own valid
    /// sync context, only within its offered window) into a shared pool that
    /// the single leader applies in chain order. Faster catch-up + resilience
    /// (no dependence on one peer), network-polite (each block fetched once,
    /// per-peer pacing unchanged). Off ⇒ the proven single-peer path.
    #[serde(default = "default_multi_peer_fetch", alias = "multiPeerFetch")]
    pub multi_peer_fetch: bool,
    /// Fast-join "follow-tip" mechanic. Off by default.
    ///
    /// When set together with a [`Self::tip_test`] checkpoint, the node treats
    /// that recent block id as its head, anchors its `SyncBlockChain` locator
    /// there (so peers serve the *live tail* forward rather than the historical
    /// backfill), and advances its head as each block streams in — so it keeps
    /// pulling new blocks as they are produced. Blocks are decoded + DISPLAYED,
    /// never executed or applied (there is no chain state). This is the engine
    /// behind [`Self::explore`]; on its own it just emits a per-block line.
    #[serde(default, alias = "followTip")]
    pub follow_tip: bool,
    /// `--explore` live-dashboard mode. Bootstraps from a real recent tip
    /// (supplied as the flag's `BLOCK_NUM:HEX_HASH` argument, which also
    /// populates [`Self::tip_test`] and enables [`Self::follow_tip`]), follows
    /// the live block tail decode-only, and paints a self-updating terminal
    /// dashboard of real mainnet activity. Off by default; never affects a
    /// normal syncing node.
    #[serde(default, alias = "explore")]
    pub explore: bool,
    /// `--mempool` live-dashboard mode. Reuses the same tip bootstrap as
    /// [`Self::explore`] (so the node reaches the live tip and peers start
    /// broadcasting pending txs to it), but instead of confirmed blocks it
    /// watches the *pending* tx stream: every accepted mempool tx is decoded
    /// (TRX / USDT / contract call), classified, and painted in a live
    /// dashboard with arrival rate, pending volume, hot contracts/methods, and
    /// whale alerts. Decode-only — never executes or applies. When both this
    /// and [`Self::explore`] are set, the mempool dashboard wins. Off by
    /// default; never affects a normal syncing node.
    #[serde(default, alias = "mempool")]
    pub mempool: bool,
    /// Optional JSONL sink for [`Self::mempool`] mode: one JSON object per
    /// pending tx (txid, ts, signer, type, to, amount_sun, usdt_units,
    /// contract, method, expiration). `"-"` writes to stdout; any other value
    /// is a file path opened in append mode. `None` disables the feed.
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "mempoolJson")]
    pub mempool_json: Option<String>,
}

fn default_multi_peer_fetch() -> bool {
    true
}

/// `(block_num, block_id_hex)` pair used by [`P2pConfig::tip_test`].
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct TipTestCheckpoint {
    pub block_num: i64,
    /// 32-byte block ID, hex-encoded (the wire form is `[num as u64
    /// big-endian][block hash big-endian 24 bytes]` per java-tron's
    /// `BlockCapsule.calcBlockID`, but the TXT/UI form just shows the
    /// full 32-byte hex).
    pub block_id_hex: String,
}

fn default_max_peers() -> usize {
    // java-tron's mainnet default is 30 (`maxConnections`), but with
    // 2000+ peers from DNS discovery we can spread thinner across more
    // ASNs at low cost (each idle driver is just a tokio task + one
    // socket). 60 keeps the per-IP ratio low so we don't trip any
    // single peer's `maxConnectionsWithSameIp` cap, while widening the
    // pool enough that a few archive-capable peers are more likely to
    // be in the sample.
    60
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
            rpc: RpcConfig::default(),
            p2p: P2pConfig::default(),
            metrics: MetricsConfig::default(),
            grpc: GrpcConfig::default(),
            http: HttpRestConfig::default(),
            witness: None,
            bundler: None,
            storage: StorageConfig::default(),
            event: None,
            node_backup: NodeBackupConfig::default(),
            vm: VmConfig::default(),
            rate_limiter: RateLimiterConfig::default(),
            open_history_query_when_lite_fn: false,
            local_witness: LocalWitnessConfig::default(),
            committee: CommitteeConfig::default(),
            index: IndexConfig::default(),
        }
    }
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            host: default_rpc_host(),
            port: default_rpc_port(),
            disabled: false,
            chain_id: default_chain_id(),
            eth_call_gas_cap: default_eth_call_gas_cap(),
        }
    }
}

impl Default for P2pConfig {
    fn default() -> Self {
        Self {
            peers: Vec::new(),
            max_blocks: None,
            disabled: false,
            progress_log_interval: default_progress_log_interval(),
            advertise_port: default_advertise_port(),
            max_peers: default_max_peers(),
            listen: default_listen(),
            listen_host: default_listen_host(),
            discover_enable: default_discover_enable(),
            discover_bootstrap_ms: default_discover_bootstrap_ms(),
            discover_tree_urls: default_discover_tree_urls(),
            discover_tree_query_timeout_ms: default_discover_tree_query_timeout_ms(),
            node_discovery_persist: default_node_discovery_persist(),
            node_discovery_persist_interval_ms: default_node_discovery_persist_interval_ms(),
            fetch_block_timeout_ms: default_fetch_block_timeout_ms(),
            sync_fetch_inflight_per_peer: default_sync_fetch_inflight_per_peer(),
            fast_forward_nodes: Vec::new(),
            tip_test: None,
            multi_peer_fetch: default_multi_peer_fetch(),
            follow_tip: false,
            explore: false,
            mempool: false,
            mempool_json: None,
        }
    }
}

fn default_advertise_port() -> i32 {
    18_889
}

fn default_listen() -> bool {
    true
}

fn default_listen_host() -> String {
    "0.0.0.0".to_string()
}

fn default_discover_enable() -> bool {
    true
}

fn default_discover_bootstrap_ms() -> u64 {
    5_000
}

fn default_discover_tree_urls() -> Vec<String> {
    vec![
        // Official mainnet tree, signed by the TRON Foundation
        // (commented out by default in java-tron's config.conf but
        // we enable it by default — without it we're stuck on the 13
        // hard-coded seeds, which the network largely rejects).
        "tree://AKMQMNAJJBL73LXWPXDI4I5ZWWIZ4AWO34DWQ636QOBBXNFXH3LQS@main.trondisco.net".into(),
    ]
}

fn default_discover_tree_query_timeout_ms() -> u64 {
    5_000
}

fn default_node_discovery_persist() -> bool {
    true
}

fn default_node_discovery_persist_interval_ms() -> u64 {
    // java-tron's `NodePersistService.DB_COMMIT_RATE` — 60s.
    60_000
}

fn default_fetch_block_timeout_ms() -> u64 {
    // java-tron clamps to [100, 1000]; the config.conf default is
    // typically 200.
    200
}

fn default_sync_fetch_inflight_per_peer() -> usize {
    // At or below java-tron's `MAX_BLOCK_FETCH_PER_PEER` (100) so a single
    // connection never carries more in-flight than the peer expects; 64 keeps
    // a deep-enough per-peer pipe while leaving the rest of the backlog for
    // OTHER peers to fetch in parallel (spreads load, no single host hammered).
    64
}

fn default_progress_log_interval() -> usize {
    100
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("./tron-data")
}
fn default_rpc_host() -> String {
    "127.0.0.1".into()
}
fn default_rpc_port() -> u16 {
    8546
}
fn default_chain_id() -> u64 {
    tron_rpc::MAINNET_CHAIN_ID
}

// -- rate.limiter.* (java-tron parity schema) --

/// Mirrors java-tron's `RateLimiterInitialization`. Each entry binds a
/// component (HTTP servlet name or gRPC method) to a strategy +
/// params string. Also covers the per-frame-type P2P rate caps that
/// each `PeerConnection` registers on its `P2pRateLimiter`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimiterConfig {
    #[serde(default)]
    pub http: Vec<RateLimiterItem>,
    #[serde(default)]
    pub rpc: Vec<RateLimiterItem>,
    /// Per-frame-type rate caps for inbound P2P messages. Mirrors
    /// java-tron's `rate.limiter.p2p.{syncBlockChain, fetchInvData,
    /// disconnect}` with the same defaults (3.0/3.0/1.0 qps).
    #[serde(default)]
    pub p2p: RateLimiterP2pConfig,
    /// Node-wide request ceiling applied to every HTTP servlet, the
    /// JSON-RPC endpoint, and every gRPC call AFTER any per-component
    /// limit — java-tron's `rate.limiter.global.qps`. `0` disables.
    #[serde(default = "default_global_qps", alias = "globalQps")]
    pub global_qps: f64,
    /// Per-source-IP companion ceiling — java-tron's
    /// `rate.limiter.global.ip.qps`. `0` disables.
    #[serde(default = "default_global_ip_qps", alias = "globalIpQps")]
    pub global_ip_qps: f64,
}

fn default_global_qps() -> f64 {
    50_000.0
}

fn default_global_ip_qps() -> f64 {
    10_000.0
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            http: Vec::new(),
            rpc: Vec::new(),
            p2p: RateLimiterP2pConfig::default(),
            // java defaults: the global ceilings are armed even with no
            // [rate_limiter] section configured.
            global_qps: default_global_qps(),
            global_ip_qps: default_global_ip_qps(),
        }
    }
}

impl RateLimiterConfig {
    /// `true` when the HTTP map is non-empty (matches java-tron's
    /// `httpFlag` derivation after `setHttpMap`).
    pub fn http_flag(&self) -> bool {
        !self.http.is_empty()
    }
    /// `true` when the RPC map is non-empty.
    pub fn rpc_flag(&self) -> bool {
        !self.rpc.is_empty()
    }
}

/// Per-frame-type rate-limit caps for inbound P2P messages. Each
/// `PeerConnection` calls `try_acquire(type)` before processing the
/// frame; when the bucket is empty the frame is dropped (silently,
/// matching java-tron's `P2pEventHandlerImpl`). Defaults match
/// java-tron's `Args.getInstance().getRateLimiter*` (3.0/3.0/1.0).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimiterP2pConfig {
    /// `SYNC_BLOCK_CHAIN` (0x08) — peer asking us for chain
    /// inventory. Default 3.0 qps.
    #[serde(default = "default_p2p_rate_sync_block_chain",
            alias = "syncBlockChain")]
    pub sync_block_chain: f64,
    /// `FETCH_INV_DATA` (0x07) — peer asking us for body data for
    /// previously-advertised block / tx hashes. Default 3.0 qps.
    #[serde(default = "default_p2p_rate_fetch_inv_data", alias = "fetchInvData")]
    pub fetch_inv_data: f64,
    /// `P2P_DISCONNECT` (0x21) — peer announcing they're closing. We
    /// rate-limit acknowledgement so a chatty peer can't flood our
    /// disconnect-handling path. Default 1.0 qps.
    #[serde(default = "default_p2p_rate_disconnect")]
    pub disconnect: f64,
}

impl Default for RateLimiterP2pConfig {
    fn default() -> Self {
        Self {
            sync_block_chain: default_p2p_rate_sync_block_chain(),
            fetch_inv_data: default_p2p_rate_fetch_inv_data(),
            disconnect: default_p2p_rate_disconnect(),
        }
    }
}

fn default_p2p_rate_sync_block_chain() -> f64 {
    3.0
}
fn default_p2p_rate_fetch_inv_data() -> f64 {
    3.0
}
fn default_p2p_rate_disconnect() -> f64 {
    1.0
}

/// One rate-limiter binding. java-tron uses two near-identical inner
/// classes (`HttpRateLimiterItem` + `RpcRateLimiterItem`); the field
/// shape is the same so we collapse them.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RateLimiterItem {
    /// Component identifier. For HTTP this is the servlet name
    /// (e.g. `"getaccount"`); for gRPC it's the dotted method name
    /// (e.g. `"protocol.Wallet/GetAccount"`).
    #[serde(default)]
    pub component: String,
    /// Strategy class name. java-tron supports `GlobalPreemptibleAdapter`
    /// (rate-per-window) and `IPQPSRateLimiter` (per-source-IP QPS).
    #[serde(default)]
    pub strategy: String,
    /// Strategy-specific param string. Format depends on `strategy`
    /// (e.g. `"qps=100"`). Stored opaquely; the rate-limiter loader
    /// parses it at construction time.
    #[serde(default, alias = "paramString")]
    pub params: String,
}

// -- localwitness* (top-level keys) --

/// Mirrors java-tron's `LocalWitnessConfig`. Reads top-level keys
/// `localwitness`, `localWitnessAccountAddress`, `localwitnesskeystore`.
/// Each source is mutually exclusive; the runtime picks the first
/// non-empty in the order documented by [`LocalWitnessConfig::source`].
///
/// **Status**: schema only — the [`WitnessConfig`] tree above is what
/// the SR runtime currently consults. A follow-up will fold this into
/// `WitnessConfig` so config.conf files round-trip.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LocalWitnessConfig {
    /// Raw private keys (hex strings). Each entry produces one signing
    /// witness identity at startup.
    #[serde(default, alias = "localwitness")]
    pub private_keys: Vec<String>,
    /// Optional account-address override (Base58 `T…`). When set,
    /// the witness signs as this address rather than the address
    /// derived from the private key.
    #[serde(default, alias = "localWitnessAccountAddress")]
    pub account_address: Option<String>,
    /// V3 keystore file paths (decrypted with the CLI `--password`
    /// flag at startup).
    #[serde(default, alias = "localwitnesskeystore")]
    pub keystores: Vec<String>,
}

/// Resolved key source for [`LocalWitnessConfig`]. Returned by
/// [`LocalWitnessConfig::source`] in the same precedence order as
/// java-tron's `WitnessInitializer.init`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalWitnessSource<'a> {
    PrivateKeys(&'a [String]),
    Keystores(&'a [String]),
    None,
}

impl LocalWitnessConfig {
    /// Returns the first non-empty source, in java-tron's precedence
    /// order: CLI `--private-key` (handled elsewhere) > `localwitness`
    /// > `localwitnesskeystore`.
    pub fn source(&self) -> LocalWitnessSource<'_> {
        if !self.private_keys.is_empty() {
            LocalWitnessSource::PrivateKeys(&self.private_keys)
        } else if !self.keystores.is_empty() {
            LocalWitnessSource::Keystores(&self.keystores)
        } else {
            LocalWitnessSource::None
        }
    }
}

// -- committee.* (java-tron parity schema) --

/// Mirrors java-tron's `CommitteeConfig`. Holds the bootstrap values
/// for every governance proposal flag. Field defaults match java-tron
/// (almost all `0`, with `pbft_expire_num = 20`).
///
/// **Status**: schema only — these values are governance flags that
/// java-tron uses as the **initial** values when bootstrapping a
/// fresh chain (mainnet uses on-chain proposal records to override
/// them). Wiring them into the genesis path is a separate follow-up.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitteeConfig {
    #[serde(default, alias = "allowCreationOfContracts")]
    pub allow_creation_of_contracts: i64,
    #[serde(default, alias = "allowMultiSign")]
    pub allow_multi_sign: i64,
    #[serde(default, alias = "allowAdaptiveEnergy")]
    pub allow_adaptive_energy: i64,
    #[serde(default, alias = "allowDelegateResource")]
    pub allow_delegate_resource: i64,
    #[serde(default, alias = "allowSameTokenName")]
    pub allow_same_token_name: i64,
    #[serde(default, alias = "allowTvmTransferTrc10")]
    pub allow_tvm_transfer_trc10: i64,
    #[serde(default, alias = "allowTvmConstantinople")]
    pub allow_tvm_constantinople: i64,
    #[serde(default, alias = "allowTvmSolidity059")]
    pub allow_tvm_solidity_059: i64,
    #[serde(default, alias = "forbidTransferToContract")]
    pub forbid_transfer_to_contract: i64,
    #[serde(default, alias = "allowShieldedTRC20Transaction")]
    pub allow_shielded_trc20_transaction: i64,
    #[serde(default, alias = "allowMarketTransaction")]
    pub allow_market_transaction: i64,
    #[serde(default, alias = "allowTransactionFeePool")]
    pub allow_transaction_fee_pool: i64,
    #[serde(default, alias = "allowBlackHoleOptimization")]
    pub allow_black_hole_optimization: i64,
    #[serde(default, alias = "allowNewResourceModel")]
    pub allow_new_resource_model: i64,
    #[serde(default, alias = "allowTvmIstanbul")]
    pub allow_tvm_istanbul: i64,
    #[serde(default, alias = "allowProtoFilterNum")]
    pub allow_proto_filter_num: i64,
    #[serde(default, alias = "allowAccountStateRoot")]
    pub allow_account_state_root: i64,
    #[serde(default, alias = "changedDelegation")]
    pub changed_delegation: i64,
    /// `committee.allowPBFT` (java-tron uses non-standard PBFT casing).
    #[serde(default, alias = "allowPBFT")]
    pub allow_pbft: i64,
    /// `committee.pBFTExpireNum` (java-tron uses lowercase-p start).
    /// Default `20`.
    #[serde(default = "default_committee_pbft_expire", alias = "pBFTExpireNum")]
    pub pbft_expire_num: i64,
    #[serde(default, alias = "allowTvmFreeze")]
    pub allow_tvm_freeze: i64,
    #[serde(default, alias = "allowTvmVote")]
    pub allow_tvm_vote: i64,
    #[serde(default, alias = "allowTvmLondon")]
    pub allow_tvm_london: i64,
    #[serde(default, alias = "allowTvmCompatibleEvm")]
    pub allow_tvm_compatible_evm: i64,
    #[serde(default, alias = "allowHigherLimitForMaxCpuTimeOfOneTx")]
    pub allow_higher_limit_for_max_cpu_time_of_one_tx: i64,
    #[serde(default, alias = "allowNewRewardAlgorithm")]
    pub allow_new_reward_algorithm: i64,
    #[serde(default, alias = "allowOptimizedReturnValueOfChainId")]
    pub allow_optimized_return_value_of_chain_id: i64,
    #[serde(default, alias = "allowTvmShangHai")]
    pub allow_tvm_shanghai: i64,
    #[serde(default, alias = "allowOldRewardOpt")]
    pub allow_old_reward_opt: i64,
    #[serde(default, alias = "allowEnergyAdjustment")]
    pub allow_energy_adjustment: i64,
    #[serde(default, alias = "allowStrictMath")]
    pub allow_strict_math: i64,
    #[serde(default, alias = "consensusLogicOptimization")]
    pub consensus_logic_optimization: i64,
    #[serde(default, alias = "allowTvmCancun")]
    pub allow_tvm_cancun: i64,
    #[serde(default, alias = "allowTvmBlob")]
    pub allow_tvm_blob: i64,
    /// Clamped to `[0, 365]` via [`CommitteeConfig::clamp`].
    #[serde(default, alias = "unfreezeDelayDays")]
    pub unfreeze_delay_days: i64,
    #[serde(default, alias = "allowReceiptsMerkleRoot")]
    pub allow_receipts_merkle_root: i64,
    #[serde(default, alias = "allowAccountAssetOptimization")]
    pub allow_account_asset_optimization: i64,
    #[serde(default, alias = "allowAssetOptimization")]
    pub allow_asset_optimization: i64,
    /// Clamped to `[0, 1]`.
    #[serde(default, alias = "allowNewReward")]
    pub allow_new_reward: i64,
    /// Clamped to `[0, 1_000_000_000]`.
    #[serde(default, alias = "memoFee")]
    pub memo_fee: i64,
    /// Clamped to `[0, 1]`.
    #[serde(default, alias = "allowDelegateOptimization")]
    pub allow_delegate_optimization: i64,
    /// Clamped to `[0, 1]`.
    #[serde(default, alias = "allowDynamicEnergy")]
    pub allow_dynamic_energy: i64,
    /// Clamped to `[0, 100_000_000_000_000_000]`.
    #[serde(default, alias = "dynamicEnergyThreshold")]
    pub dynamic_energy_threshold: i64,
    /// Clamped to `[0, 10_000]`.
    #[serde(default, alias = "dynamicEnergyIncreaseFactor")]
    pub dynamic_energy_increase_factor: i64,
    /// Clamped to `[0, 100_000]`.
    #[serde(default, alias = "dynamicEnergyMaxFactor")]
    pub dynamic_energy_max_factor: i64,
}

impl Default for CommitteeConfig {
    fn default() -> Self {
        Self {
            allow_creation_of_contracts: 0,
            allow_multi_sign: 0,
            allow_adaptive_energy: 0,
            allow_delegate_resource: 0,
            allow_same_token_name: 0,
            allow_tvm_transfer_trc10: 0,
            allow_tvm_constantinople: 0,
            allow_tvm_solidity_059: 0,
            forbid_transfer_to_contract: 0,
            allow_shielded_trc20_transaction: 0,
            allow_market_transaction: 0,
            allow_transaction_fee_pool: 0,
            allow_black_hole_optimization: 0,
            allow_new_resource_model: 0,
            allow_tvm_istanbul: 0,
            allow_proto_filter_num: 0,
            allow_account_state_root: 0,
            changed_delegation: 0,
            allow_pbft: 0,
            pbft_expire_num: default_committee_pbft_expire(),
            allow_tvm_freeze: 0,
            allow_tvm_vote: 0,
            allow_tvm_london: 0,
            allow_tvm_compatible_evm: 0,
            allow_higher_limit_for_max_cpu_time_of_one_tx: 0,
            allow_new_reward_algorithm: 0,
            allow_optimized_return_value_of_chain_id: 0,
            allow_tvm_shanghai: 0,
            allow_old_reward_opt: 0,
            allow_energy_adjustment: 0,
            allow_strict_math: 0,
            consensus_logic_optimization: 0,
            allow_tvm_cancun: 0,
            allow_tvm_blob: 0,
            unfreeze_delay_days: 0,
            allow_receipts_merkle_root: 0,
            allow_account_asset_optimization: 0,
            allow_asset_optimization: 0,
            allow_new_reward: 0,
            memo_fee: 0,
            allow_delegate_optimization: 0,
            allow_dynamic_energy: 0,
            dynamic_energy_threshold: 0,
            dynamic_energy_increase_factor: 0,
            dynamic_energy_max_factor: 0,
        }
    }
}

impl CommitteeConfig {
    /// In-place clamping mirroring java-tron's `postProcess`. Run after
    /// deserialize and before consumers read the values.
    pub fn clamp(&mut self) {
        Self::clamp_range(&mut self.unfreeze_delay_days, 0, 365);
        Self::clamp_range(&mut self.allow_delegate_optimization, 0, 1);
        Self::clamp_range(&mut self.allow_dynamic_energy, 0, 1);
        Self::clamp_range(
            &mut self.dynamic_energy_threshold,
            0,
            100_000_000_000_000_000,
        );
        Self::clamp_range(&mut self.dynamic_energy_increase_factor, 0, 10_000);
        Self::clamp_range(&mut self.dynamic_energy_max_factor, 0, 100_000);
        Self::clamp_range(&mut self.allow_new_reward, 0, 1);
        Self::clamp_range(&mut self.memo_fee, 0, 1_000_000_000);
    }

    /// Cross-field check: `allow_old_reward_opt = 1` requires at least
    /// one of `allow_new_reward_algorithm`, `allow_new_reward`, or
    /// `allow_tvm_vote` to be enabled (matches java-tron exactly).
    pub fn validate_old_reward_prereq(&self) -> Result<(), ConfigError> {
        if self.allow_old_reward_opt == 1
            && self.allow_new_reward_algorithm != 1
            && self.allow_new_reward != 1
            && self.allow_tvm_vote != 1
        {
            return Err(ConfigError::Committee(
                "At least one of the following proposals is required to be opened first: \
                 committee.allowNewRewardAlgorithm = 1 \
                 or committee.allowNewReward = 1 \
                 or committee.allowTvmVote = 1."
                    .into(),
            ));
        }
        Ok(())
    }

    fn clamp_range(value: &mut i64, min: i64, max: i64) {
        if *value < min {
            *value = min;
        }
        if *value > max {
            *value = max;
        }
    }
}

fn default_committee_pbft_expire() -> i64 {
    20
}

impl NodeConfig {
    /// Load from a TOML file. Missing fields fall back to defaults.
    pub fn from_file(path: &std::path::Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        toml::from_str(&text).map_err(|e| ConfigError::Decode {
            path: path.to_path_buf(),
            source: e,
        })
    }

    /// Return a `vm` view with java-tron's `postProcess` rules applied
    /// (clamps + `constantCallTimeoutMs` validation). Does NOT mutate
    /// `self`. Used by anything consuming the VM knobs at runtime so
    /// the raw deserialized values still round-trip back to the same
    /// TOML form.
    pub fn resolve_vm(&self) -> Result<VmConfig, ConfigError> {
        let mut out = self.vm.clone();
        out.clamp();
        out.validate_constant_call_timeout()?;
        Ok(out)
    }

    /// Return a `tx_cache` view with `estimated_transactions` clamped
    /// to `[100, 10_000]`. Does NOT mutate `self`.
    pub fn resolve_tx_cache(&self) -> TxCacheConfig {
        let mut out = self.storage.tx_cache.clone();
        out.clamp();
        out
    }

    /// Return a `db_settings` view with `compact_threads` resolved
    /// against the host CPU count (matches java-tron's
    /// `DbSettingsConfig.postProcess`).
    pub fn resolve_db_settings(&self) -> DbSettingsConfig {
        self.storage.db_settings.resolve()
    }

    /// Return a `committee` view with all clamps applied and the
    /// cross-field `allow_old_reward_opt` prerequisite verified. Does
    /// NOT mutate `self`.
    pub fn resolve_committee(&self) -> Result<CommitteeConfig, ConfigError> {
        let mut out = self.committee.clone();
        out.clamp();
        out.validate_old_reward_prereq()?;
        Ok(out)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading {path:?}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("decoding {path:?}: {source}")]
    Decode {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("event.subscribe.filter.{field}: cannot parse {value:?}: {source}")]
    FilterQuery {
        field: &'static str,
        value: String,
        source: std::num::ParseIntError,
    },
    #[error("vm.{0}")]
    VmConfig(String),
    #[error("committee.{0}")]
    Committee(String),
}

// -- [index] — built-in address-history indexer --

/// `[index]` — the built-in address-history indexer + TronGrid-style
/// `/v1` history API. See `working/INDEXER_PLAN.md` for the design and
/// `working/INDEXER_IMPL_NOTES.md` for implementation notes.
///
/// Cost when disabled: zero — the subsystem never starts, no files,
/// no threads, and the apply path carries one `Option::is_none()`
/// branch per committed block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexConfig {
    /// Master switch. `true` additionally persists per-block
    /// transaction-info (`transactionRetStore`) at commit so every
    /// kind of history stays re-derivable from local stores.
    #[serde(default)]
    pub enable: bool,

    /// Index size/coverage preset; sets the `capture_*` flags below.
    /// An explicit `capture_*` key overrides the preset.
    #[serde(default)]
    pub scope: IndexScope,

    /// Per-dimension overrides (`capture_* > scope` precedence).
    #[serde(default, alias = "captureNative")]
    pub capture_native: Option<bool>,
    #[serde(default, alias = "captureTrc20")]
    pub capture_trc20: Option<bool>,
    #[serde(default, alias = "captureTrc721")]
    pub capture_trc721: Option<bool>,
    #[serde(default, alias = "captureInternal")]
    pub capture_internal: Option<bool>,
    #[serde(default, alias = "captureLogs")]
    pub capture_logs: Option<bool>,

    /// Index the CALLED contract of every `TriggerSmartContract` (not
    /// just the caller), powering `/v1/accounts/{contract}/transactions`.
    /// Outside the scope preset and default-off: it is the single
    /// largest row source (hot contracts accrue billions of rows).
    /// Changing it later triggers an automatic full index rebuild.
    #[serde(default, alias = "captureCalleeContract")]
    pub capture_callee_contract: bool,

    /// Opt-in historical-state archive (P2): record every block's
    /// committed write-set as per-key versions under
    /// `<data_dir>/archive/db`, enabling `getaccount` /
    /// `getaccountresource` / `triggerconstantcontract` **at any
    /// covered height** via `/v1/archive/...`. NEVER set by a scope
    /// preset — it has its own cost profile (terabyte-scale on
    /// mainnet, write amplification comparable to chain state).
    /// Unlike the tx-history index, the archive is NOT re-derivable:
    /// deleting it (or toggling this off and back on) restarts
    /// coverage at the then-current head. Requires the BlockSession
    /// commit path (`storage.snapshot_reorg = false`). Excluded from
    /// the index scope fingerprint — toggling it never rebuilds the
    /// tx-history index.
    #[serde(default, alias = "captureStateDeltas")]
    pub capture_state_deltas: bool,

    /// `[index.archive]` — the user-facing historical-state archive switch
    /// (enable + rolling/full retention + retain window). `archive.enabled`
    /// implies `capture_state_deltas`. See [`ArchiveConfig`].
    #[serde(default)]
    pub archive: ArchiveConfig,

    /// `[index.commitment]` — opt-in verifiable state-commitment layer.
    /// `commitment.enabled` implies `capture_state_deltas`. Independent of
    /// `[index.archive]` — neither requires the other. See
    /// [`CommitmentConfig`].
    #[serde(default)]
    pub commitment: CommitmentConfig,

    /// Which stream the index follows: the canonical head
    /// (reorg-reconciled, freshest) or the PBFT-solidified mark
    /// (never unwinds, lags ~19 blocks).
    #[serde(default)]
    pub stream: IndexStream,

    /// Backfill tuning (automatic either way; these only tune it).
    #[serde(default)]
    pub backfill: IndexBackfillConfig,

    /// The firehose external-sink log (`[index.firehose]`, P3): a
    /// durable append-only log of applied blocks (decoded tx facts +
    /// logs + internal txs) with explicit unwind entries, tailed by
    /// external consumers over the gRPC `tronfirehose.Firehose`
    /// service on the existing gRPC port. Format + cursor protocol:
    /// `working/FIREHOSE.md`.
    #[serde(default)]
    pub firehose: IndexFirehoseConfig,
}

impl Default for IndexConfig {
    fn default() -> Self {
        Self {
            enable: false,
            scope: IndexScope::default(),
            capture_native: None,
            capture_trc20: None,
            capture_trc721: None,
            capture_internal: None,
            capture_logs: None,
            capture_callee_contract: false,
            capture_state_deltas: false,
            archive: ArchiveConfig::default(),
            commitment: CommitmentConfig::default(),
            stream: IndexStream::default(),
            backfill: IndexBackfillConfig::default(),
            firehose: IndexFirehoseConfig::default(),
        }
    }
}

/// `[index.archive]` — the historical-state archive's user-facing config.
/// Off by default. When `enabled`, the node records every block's committed
/// write-set so `/v1/archive/...` can serve account / storage / resource
/// reads — and `triggerconstantcontract` — at any covered height.
/// `mode = "rolling"` keeps a bounded `retain_blocks` window (older versions
/// are pruned on a timer); `mode = "full"` keeps all captured history
/// (terabyte-scale on mainnet). Enabling implies `capture_state_deltas` and
/// requires the BlockSession commit path (`storage.snapshot_reorg = false`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveConfig {
    /// Master switch (default false). Implies `capture_state_deltas`.
    #[serde(default)]
    pub enabled: bool,
    /// Retention strategy: `"rolling"` (bounded window) or `"full"`.
    #[serde(default)]
    pub mode: ArchiveMode,
    /// Rolling-mode window: keep `[head - retain_blocks, head]`. Default
    /// 2_592_000 ≈ 90 days at 3s blocks. Ignored in full mode.
    #[serde(default = "default_archive_retain_blocks", alias = "retainBlocks")]
    pub retain_blocks: u64,
}

/// Retention strategy for [`ArchiveConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArchiveMode {
    /// Keep only the bounded `retain_blocks` window; prune older versions.
    Rolling,
    /// Keep the entire captured history (never prune).
    Full,
}

impl Default for ArchiveMode {
    fn default() -> Self {
        ArchiveMode::Rolling
    }
}

impl Default for ArchiveConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: ArchiveMode::Rolling,
            retain_blocks: default_archive_retain_blocks(),
        }
    }
}

fn default_archive_retain_blocks() -> u64 {
    2_592_000
}

/// `[index.commitment]` — the verifiable state-commitment layer.
/// Off by default. When `enabled`, the node maintains a Sparse Merkle Tree
/// (keccak256) over committed state, exposes the current root plus
/// inclusion/exclusion proofs via `/v1/commitment/...`, and lets an operator
/// cross-check the node is byte-exact with the canonical chain by comparing
/// roots with another independently-bootstrapped node at the same committed
/// height. The root commits to the executor-written state surface — the same
/// surface the archive versions. It is computed off the block-apply path and
/// trails the head by `confirmation_lag_blocks`, so committed roots are final
/// rather than reorg-able. Enabling implies `capture_state_deltas` and
/// requires the BlockSession commit path (`storage.snapshot_reorg = false`).
/// Storage (the latest tree) lives under `<data_dir>/commitment/db`; it is not
/// cheaply re-derivable — disabling and re-enabling triggers a full
/// re-Merkleization at the then-current head. Independent of `[index.archive]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentConfig {
    /// Master switch (default false). Implies `capture_state_deltas`.
    #[serde(default)]
    pub enabled: bool,
    /// Blocks behind head at which a root is committed. The builder defers
    /// folding a block until the head is this many blocks beyond it, so a
    /// committed root is past PBFT finality and a tip reorg cannot orphan it.
    /// Default 20 (just past the ~19-block solidification gap); lowering it
    /// below finality risks committing a root a later reorg orphans.
    #[serde(default = "default_commitment_confirmation_lag", alias = "confirmationLagBlocks")]
    pub confirmation_lag_blocks: u64,
    /// Warn threshold: how far the async builder may trail the head before a
    /// lag warning is logged. The channel is bounded independently; this only
    /// tunes when the operator is told the builder is falling behind.
    #[serde(default = "default_commitment_max_lag", alias = "maxLagBlocks")]
    pub max_lag_blocks: u64,
}

impl Default for CommitmentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            confirmation_lag_blocks: default_commitment_confirmation_lag(),
            max_lag_blocks: default_commitment_max_lag(),
        }
    }
}

fn default_commitment_confirmation_lag() -> u64 {
    20
}

fn default_commitment_max_lag() -> u64 {
    256
}

impl IndexConfig {
    /// Resolve the preset + overrides into the effective capture set
    /// (`capture_* > scope` precedence — the §6.5 rule).
    pub fn capture_set(&self) -> tron_index::CaptureSet {
        // TRC721 rides with TRC20 in the presets (NFT transfers are a
        // tiny row source next to fungible transfers).
        let (native, trc20, internal, logs) = match self.scope {
            IndexScope::Native => (true, false, false, false),
            IndexScope::Trc20 => (true, true, true, false),
            IndexScope::All => (true, true, true, true),
        };
        tron_index::CaptureSet {
            native: self.capture_native.unwrap_or(native),
            trc20: self.capture_trc20.unwrap_or(trc20),
            trc721: self.capture_trc721.unwrap_or(trc20),
            internal: self.capture_internal.unwrap_or(internal),
            logs: self.capture_logs.unwrap_or(logs),
            callee_contract: self.capture_callee_contract,
        }
    }

    /// Map the backfill knobs onto the engine options.
    pub fn engine_options(&self) -> tron_index::EngineOptions {
        tron_index::EngineOptions {
            window_blocks: self.backfill.window_blocks.clamp(1, 65_536),
            window_tx_budget: self.backfill.window_tx_budget.clamp(64, 2_000_000),
            head_first: matches!(self.backfill.order, IndexBackfillOrder::HeadFirst),
            start_height: self.backfill.start_height.max(0),
            follow_solidified: matches!(self.stream, IndexStream::Solidified),
            sync_every_windows: self.backfill.fsync_barrier_windows.clamp(1, 4096),
            ..tron_index::EngineOptions::default()
        }
    }
}

/// `index.scope` preset values.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IndexScope {
    /// TRX / TRC10 / account-level only (smallest).
    Native,
    /// + TRC20 transfers + internal txs (default; wallets/explorers).
    #[default]
    Trc20,
    /// + all VM logs/events (largest; event-search rows).
    All,
}

/// `index.stream` values.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IndexStream {
    #[default]
    Head,
    Solidified,
}

/// `index.backfill.order` values.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexBackfillOrder {
    /// Newest history queryable within seconds; the long tail fills in
    /// behind it (the default).
    #[default]
    HeadFirst,
    /// Monotonic single edge from the snapshot base upward.
    FloorFirst,
}

/// `[index.backfill]` — tuning only; backfill itself is automatic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexBackfillConfig {
    #[serde(default)]
    pub order: IndexBackfillOrder,
    /// Blocks per gap-closing window (one atomic write-batch each).
    #[serde(default = "default_index_window_blocks", alias = "windowBlocks")]
    pub window_blocks: usize,
    /// Soft cap on transactions per window — bounds batch RAM on
    /// tx-heavy ranges regardless of `window_blocks`.
    #[serde(default = "default_index_window_tx_budget", alias = "windowTxBudget")]
    pub window_tx_budget: usize,
    /// Deferred-fsync barrier: WAL-sync once every N windows. Crash
    /// recovery re-derives at most N windows.
    #[serde(default = "default_index_fsync_barrier", alias = "fsyncBarrierWindows")]
    pub fsync_barrier_windows: u32,
    /// Optional capacity clamp: index only from this height up (the
    /// snapshot base still floors it). Changing it later triggers an
    /// automatic full index rebuild.
    #[serde(default, alias = "startHeight")]
    pub start_height: i64,
}

impl Default for IndexBackfillConfig {
    fn default() -> Self {
        Self {
            order: IndexBackfillOrder::default(),
            window_blocks: default_index_window_blocks(),
            window_tx_budget: default_index_window_tx_budget(),
            fsync_barrier_windows: default_index_fsync_barrier(),
            start_height: 0,
        }
    }
}

/// `[index.firehose]` — the durable external-sink log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexFirehoseConfig {
    /// Master switch. The log lives under `<data_dir>/firehose/`;
    /// enabling also mounts the gRPC tail service.
    #[serde(default)]
    pub enable: bool,
    /// Retention budget in MiB — oldest segments are pruned past it.
    /// Consumers further behind than retention resume at the oldest
    /// retained entry (visible as a seq jump). Default 32 GiB.
    #[serde(default = "default_firehose_retain_mb", alias = "retainMb")]
    pub retain_mb: u64,
}

impl Default for IndexFirehoseConfig {
    fn default() -> Self {
        Self { enable: false, retain_mb: default_firehose_retain_mb() }
    }
}

fn default_firehose_retain_mb() -> u64 {
    32 * 1024
}

fn default_index_window_blocks() -> usize {
    1024
}
fn default_index_window_tx_budget() -> usize {
    20_000
}
fn default_index_fsync_barrier() -> u32 {
    16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_example_config_parses_and_matches_defaults() {
        // `config.example.toml` (repo root) is documented as "every value is
        // the built-in default". Parse it through the real loader and pin a
        // few load-bearing values so the shipped file can't silently drift
        // from the schema.
        let path = std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../config.example.toml"
        ));
        let cfg = NodeConfig::from_file(path).expect("config.example.toml must parse");
        assert_eq!(cfg.storage.max_open_files, 1024);
        assert_eq!(cfg.storage.write_buffer_size_mb, 64);
        assert_eq!(cfg.storage.snapshot_horizon, 64);
        assert_eq!(cfg.rpc.port, 8546);
        assert_eq!(cfg.rpc.eth_call_gas_cap, 50_000_000);
        assert_eq!(cfg.http.port, 8091);
        assert_eq!(cfg.grpc.port, 50052);
        assert_eq!(cfg.metrics.port, 9091);
        assert_eq!(cfg.p2p.advertise_port, 18889);
        assert_eq!(cfg.p2p.max_peers, 60);
        assert!(cfg.p2p.listen);
        assert_eq!(cfg.p2p.listen_host, "0.0.0.0");
        assert!(cfg.p2p.discover_enable);
        assert_eq!(cfg.p2p.sync_fetch_inflight_per_peer, 64);
        // The opt-in state surfaces ship off with their documented defaults.
        assert!(!cfg.index.commitment.enabled);
        assert_eq!(cfg.index.commitment.confirmation_lag_blocks, 20);
        assert_eq!(cfg.index.commitment.max_lag_blocks, 256);
        // No [witness] table → sync-only.
        assert!(cfg.witness.is_none());
    }

    // ---- [index] schema ----

    #[test]
    fn index_defaults_are_off_and_trc20_scope() {
        let cfg: NodeConfig = toml::from_str("").expect("empty TOML");
        assert!(!cfg.index.enable);
        let caps = cfg.index.capture_set();
        assert!(caps.native && caps.trc20 && caps.internal);
        assert!(!caps.logs && !caps.callee_contract);
        let opts = cfg.index.engine_options();
        assert!(opts.head_first);
        assert!(!opts.follow_solidified);
        assert_eq!(opts.window_blocks, 1024);
        assert_eq!(opts.start_height, 0);
    }

    #[test]
    fn index_bare_enable_is_fully_valid() {
        // The blessed operator flow: a bare `[index]\nenable = true`.
        let cfg: NodeConfig =
            toml::from_str("[index]\nenable = true").expect("bare enable parses");
        assert!(cfg.index.enable);
    }

    #[test]
    fn index_capture_overrides_beat_the_scope_preset() {
        let cfg: NodeConfig = toml::from_str(
            r#"
                [index]
                enable = true
                scope = "native"
                capture_trc20 = true

                [index.backfill]
                order = "floor_first"
                start_height = 50000000
            "#,
        )
        .expect("parse");
        let caps = cfg.index.capture_set();
        assert!(caps.native, "preset");
        assert!(caps.trc20, "override beats preset");
        assert!(!caps.internal, "preset (native) leaves internal off");
        let opts = cfg.index.engine_options();
        assert!(!opts.head_first);
        assert_eq!(opts.start_height, 50_000_000);
    }

    #[test]
    fn index_scope_typo_is_a_hard_parse_error() {
        // A typo'd scope silently defaulting could mean terabytes of
        // unexpected disk use — fail loudly instead.
        assert!(toml::from_str::<NodeConfig>("[index]\nscope = \"trc-20\"").is_err());
        assert!(toml::from_str::<NodeConfig>("[index]\nstream = \"both\"").is_err());
    }

    #[test]
    fn index_capture_state_deltas_is_off_by_default_and_outside_the_fingerprint() {
        let cfg: NodeConfig = toml::from_str("").unwrap();
        assert!(!cfg.index.capture_state_deltas);
        let on: NodeConfig =
            toml::from_str("[index]\ncapture_state_deltas = true").unwrap();
        assert!(on.index.capture_state_deltas);
        // Toggling the archive must NOT change the tx-history index's
        // scope fingerprint (it would force a pointless index rebuild).
        assert_eq!(
            cfg.index.capture_set().fingerprint(0),
            on.index.capture_set().fingerprint(0)
        );
    }

    #[test]
    fn index_commitment_is_off_by_default_and_outside_the_fingerprint() {
        let cfg: NodeConfig = toml::from_str("").unwrap();
        assert!(!cfg.index.commitment.enabled);
        assert_eq!(cfg.index.commitment.confirmation_lag_blocks, 20);
        assert_eq!(cfg.index.commitment.max_lag_blocks, 256);
        // camelCase aliases parse (java-tron-style config.conf portability).
        let on: NodeConfig = toml::from_str(
            "[index.commitment]\nenabled = true\nconfirmationLagBlocks = 32\nmaxLagBlocks = 512",
        )
        .unwrap();
        assert!(on.index.commitment.enabled);
        assert_eq!(on.index.commitment.confirmation_lag_blocks, 32);
        assert_eq!(on.index.commitment.max_lag_blocks, 512);
        // Like the archive, enabling the commitment must NOT change the
        // tx-history index's scope fingerprint (it would force a needless
        // index rebuild).
        assert_eq!(
            cfg.index.capture_set().fingerprint(0),
            on.index.capture_set().fingerprint(0)
        );
    }

    #[test]
    fn index_firehose_defaults_off_with_32g_retention() {
        let cfg: NodeConfig = toml::from_str("").unwrap();
        assert!(!cfg.index.firehose.enable);
        assert_eq!(cfg.index.firehose.retain_mb, 32 * 1024);
        let on: NodeConfig = toml::from_str(
            "[index]\nenable = true\n[index.firehose]\nenable = true\nretain_mb = 1024",
        )
        .unwrap();
        assert!(on.index.firehose.enable);
        assert_eq!(on.index.firehose.retain_mb, 1024);
    }

    #[test]
    fn index_solidified_stream_and_fingerprint_stability() {
        let cfg: NodeConfig = toml::from_str("[index]\nstream = \"solidified\"").unwrap();
        assert!(cfg.index.engine_options().follow_solidified);
        // The scope fingerprint must be stable for identical configs
        // and differ when the effective capture set changes.
        let a = cfg.index.capture_set().fingerprint(0);
        let b = cfg.index.capture_set().fingerprint(0);
        assert_eq!(a, b);
        let cfg2: NodeConfig =
            toml::from_str("[index]\ncapture_callee_contract = true").unwrap();
        assert_ne!(a, cfg2.index.capture_set().fingerprint(0));
    }

    // ---- event.subscribe.* schema ----

    #[test]
    fn event_section_is_optional() {
        // No [event] section → field stays None, doesn't error.
        let cfg: NodeConfig = toml::from_str("").expect("empty TOML");
        assert!(cfg.event.is_none());
    }

    #[test]
    fn event_section_parses_minimal() {
        let cfg: NodeConfig = toml::from_str(
            r#"
                [event]
                enable = true
                path = "/opt/tron/plugins/kafka.zip"
                server = "127.0.0.1:9092"
            "#,
        )
        .expect("parse");
        let ev = cfg.event.expect("event present");
        assert!(ev.enable);
        assert_eq!(ev.path, "/opt/tron/plugins/kafka.zip");
        assert_eq!(ev.server, "127.0.0.1:9092");
        // Defaults fill the rest.
        assert!(ev.topics.is_empty());
        assert!(!ev.use_native_queue);
        assert!(!ev.contract_parse);
    }

    #[test]
    fn event_section_accepts_java_tron_camelcase_aliases() {
        // java-tron config.conf uses camelCase + the historical
        // single-token spellings (`dbconfig`, `fromblock`). Our aliases
        // must let those files round-trip without a sed-rewrite.
        let cfg: NodeConfig = toml::from_str(
            r#"
                [event]
                enable = true
                dbconfig = "mongodb://localhost:27017"
                startSyncBlockNum = 1234
                useNativeQueue = true
                bindPort = 5555
                sendQueueLength = 1000
                contractParse = true

                [[event.topics]]
                triggerName = "block"
                enabled = true
                topic = "blocks"
                ethCompatible = true

                [event.filter]
                fromblock = "earliest"
                toblock = "latest"
                contractAddress = ["TXXXXXXXXXX"]
                contractTopic = ["0xddf2"]
            "#,
        )
        .expect("parse with camelCase");
        let ev = cfg.event.expect("event present");
        assert_eq!(ev.db_config, "mongodb://localhost:27017");
        assert_eq!(ev.start_sync_block_num, 1234);
        assert!(ev.use_native_queue);
        assert_eq!(ev.bind_port, 5555);
        assert_eq!(ev.send_queue_length, 1000);
        assert!(ev.contract_parse);
        assert_eq!(ev.topics.len(), 1);
        let t = &ev.topics[0];
        assert_eq!(t.trigger_name, "block");
        assert!(t.enable);
        assert_eq!(t.topic, "blocks");
        assert!(t.eth_compatible);
        assert_eq!(ev.filter.from_block, "earliest");
        assert_eq!(ev.filter.to_block, "latest");
        assert_eq!(ev.filter.contract_addresses, vec!["TXXXXXXXXXX"]);
        assert_eq!(ev.filter.contract_topics, vec!["0xddf2"]);
    }

    // ---- FilterQuery sentinels match java-tron ----

    #[test]
    fn filter_query_earliest_and_empty_map_to_zero() {
        assert_eq!(FilterQuery::parse_from_block("").unwrap(), 0);
        assert_eq!(FilterQuery::parse_from_block("earliest").unwrap(), 0);
        assert_eq!(FilterQuery::parse_from_block("EARLIEST").unwrap(), 0);
        assert_eq!(FilterQuery::parse_from_block("  earliest  ").unwrap(), 0);
    }

    #[test]
    fn filter_query_latest_and_empty_map_to_negative_one() {
        assert_eq!(FilterQuery::parse_to_block("").unwrap(), -1);
        assert_eq!(FilterQuery::parse_to_block("latest").unwrap(), -1);
        assert_eq!(FilterQuery::parse_to_block("LATEST").unwrap(), -1);
    }

    #[test]
    fn filter_query_decimal_numbers_round_trip() {
        assert_eq!(FilterQuery::parse_from_block("100").unwrap(), 100);
        assert_eq!(FilterQuery::parse_to_block("9999999").unwrap(), 9999999);
    }

    #[test]
    fn filter_query_rejects_unparseable() {
        let err = FilterQuery::parse_from_block("not-a-number").unwrap_err();
        assert!(matches!(err, ConfigError::FilterQuery { field: "from_block", .. }));
    }

    #[test]
    fn filter_query_from_event_filter_resolves_both_ends() {
        let cfg = EventFilterConfig {
            from_block: "1000".into(),
            to_block: "latest".into(),
            ..Default::default()
        };
        let fq = FilterQuery::from_event_filter(&cfg).unwrap();
        assert_eq!(fq.from_block, 1000);
        assert_eq!(fq.to_block, FilterQuery::LATEST_BLOCK_NUM);
    }

    // ---- node.backup.* ----

    #[test]
    fn node_backup_defaults_match_java_tron() {
        let nb = NodeBackupConfig::default();
        assert_eq!(nb.priority, 0);
        assert_eq!(nb.port, 10001);
        assert_eq!(nb.keep_alive_interval, 3000);
        assert!(nb.members.is_empty());
    }

    #[test]
    fn node_backup_parses_with_camelcase_alias() {
        let cfg: NodeConfig = toml::from_str(
            r#"
                [node_backup]
                priority = 7
                port = 10001
                keepAliveInterval = 1500
                members = ["10.0.0.1", "10.0.0.2"]
            "#,
        )
        .expect("parse");
        assert_eq!(cfg.node_backup.priority, 7);
        assert_eq!(cfg.node_backup.keep_alive_interval, 1500);
        assert_eq!(cfg.node_backup.members.len(), 2);
    }

    #[test]
    fn node_backup_omitted_section_is_default() {
        let cfg: NodeConfig = toml::from_str("").unwrap();
        assert_eq!(cfg.node_backup.port, 10001);
        assert!(cfg.node_backup.members.is_empty());
    }

    // ---- vm.* ----

    #[test]
    fn vm_defaults_match_java_tron() {
        let vm = VmConfig::default();
        assert!(!vm.support_constant);
        assert_eq!(vm.max_energy_limit_for_constant, 100_000_000);
        assert_eq!(vm.lru_cache_size, 500);
        assert_eq!(vm.min_time_ratio, 0.0);
        assert_eq!(vm.max_time_ratio, 5.0);
        assert_eq!(vm.long_running_time, 10);
        assert_eq!(vm.estimate_energy_max_retry, 3);
        assert_eq!(vm.constant_call_timeout_ms, 0);
    }

    #[test]
    fn vm_clamp_pins_max_energy_floor() {
        let mut vm = VmConfig {
            max_energy_limit_for_constant: 1_000_000, // below floor
            ..Default::default()
        };
        vm.clamp();
        assert_eq!(
            vm.max_energy_limit_for_constant,
            VmConfig::MIN_MAX_ENERGY_LIMIT_FOR_CONSTANT
        );
    }

    #[test]
    fn vm_clamp_clamps_estimate_retry_to_zero_ten_range() {
        let mut vm = VmConfig {
            estimate_energy_max_retry: -5,
            ..Default::default()
        };
        vm.clamp();
        assert_eq!(vm.estimate_energy_max_retry, 0);

        let mut vm = VmConfig {
            estimate_energy_max_retry: 99,
            ..Default::default()
        };
        vm.clamp();
        assert_eq!(vm.estimate_energy_max_retry, VmConfig::MAX_ESTIMATE_RETRY);
    }

    #[test]
    fn vm_constant_call_timeout_zero_is_unset() {
        let vm = VmConfig::default();
        assert!(vm.validate_constant_call_timeout().is_ok());
    }

    #[test]
    fn vm_constant_call_timeout_negative_rejected() {
        let vm = VmConfig {
            constant_call_timeout_ms: -1,
            ..Default::default()
        };
        assert!(matches!(
            vm.validate_constant_call_timeout(),
            Err(ConfigError::VmConfig(_))
        ));
    }

    #[test]
    fn vm_constant_call_timeout_over_max_rejected() {
        let vm = VmConfig {
            constant_call_timeout_ms: VmConfig::MAX_CONSTANT_CALL_TIMEOUT_MS + 1,
            ..Default::default()
        };
        assert!(matches!(
            vm.validate_constant_call_timeout(),
            Err(ConfigError::VmConfig(_))
        ));
    }

    #[test]
    fn vm_cross_field_warning_fires_only_when_prereqs_off() {
        // Off prereqs + on toggle → warning.
        let vm = VmConfig {
            save_cancel_all_unfreeze_v2_details: true,
            save_internal_tx: false,
            save_featured_internal_tx: false,
            ..Default::default()
        };
        assert!(vm.cross_field_warnings().is_some());

        // Both prereqs on → no warning.
        let vm = VmConfig {
            save_cancel_all_unfreeze_v2_details: true,
            save_internal_tx: true,
            save_featured_internal_tx: true,
            ..Default::default()
        };
        assert!(vm.cross_field_warnings().is_none());

        // Toggle off → no warning regardless of prereqs.
        let vm = VmConfig {
            save_cancel_all_unfreeze_v2_details: false,
            ..Default::default()
        };
        assert!(vm.cross_field_warnings().is_none());
    }

    #[test]
    fn vm_section_parses_with_camelcase_aliases() {
        let cfg: NodeConfig = toml::from_str(
            r#"
                [vm]
                supportConstant = true
                maxEnergyLimitForConstant = 200000000
                lruCacheSize = 1000
                minTimeRatio = 0.2
                maxTimeRatio = 10.0
                longRunningTime = 25
                estimateEnergy = true
                estimateEnergyMaxRetry = 5
                vmTrace = true
                saveInternalTx = true
                saveFeaturedInternalTx = true
                saveCancelAllUnfreezeV2Details = true
                constantCallTimeoutMs = 2500
            "#,
        )
        .expect("parse");
        assert!(cfg.vm.support_constant);
        assert_eq!(cfg.vm.max_energy_limit_for_constant, 200_000_000);
        assert_eq!(cfg.vm.lru_cache_size, 1000);
        assert_eq!(cfg.vm.long_running_time, 25);
        assert_eq!(cfg.vm.estimate_energy_max_retry, 5);
        assert!(cfg.vm.save_cancel_all_unfreeze_v2_details);
        assert_eq!(cfg.vm.constant_call_timeout_ms, 2500);
    }

    #[test]
    fn node_config_resolve_vm_applies_clamps_and_validates_timeout() {
        let mut cfg = NodeConfig::default();
        cfg.vm.max_energy_limit_for_constant = 100; // below floor
        cfg.vm.estimate_energy_max_retry = 99; // above ceil
        let resolved = cfg.resolve_vm().expect("ok");
        assert_eq!(
            resolved.max_energy_limit_for_constant,
            VmConfig::MIN_MAX_ENERGY_LIMIT_FOR_CONSTANT
        );
        assert_eq!(resolved.estimate_energy_max_retry, VmConfig::MAX_ESTIMATE_RETRY);

        // Original is unmutated.
        assert_eq!(cfg.vm.max_energy_limit_for_constant, 100);

        // Invalid timeout propagates.
        cfg.vm.constant_call_timeout_ms = -1;
        assert!(matches!(cfg.resolve_vm(), Err(ConfigError::VmConfig(_))));
    }

    // ---- storage.dbSettings + storage.txCache ----

    #[test]
    fn db_settings_defaults_match_java_tron() {
        let d = DbSettingsConfig::default();
        assert_eq!(d.level_number, 7);
        assert_eq!(d.compact_threads, 0); // 0 = auto sentinel
        assert_eq!(d.blocksize, 16);
        assert_eq!(d.max_bytes_for_level_base, 256);
        assert_eq!(d.level0_file_num_compaction_trigger, 2);
        assert_eq!(d.target_file_size_base, 64);
        assert_eq!(d.target_file_size_multiplier, 1);
        assert_eq!(d.max_open_files, 5000);
    }

    #[test]
    fn db_settings_resolve_expands_auto_compact_threads() {
        let d = DbSettingsConfig::default();
        let r = d.resolve();
        assert!(r.compact_threads >= 1, "auto must resolve to ≥1 thread");
        // Original untouched.
        assert_eq!(d.compact_threads, 0);
    }

    #[test]
    fn db_settings_resolve_preserves_explicit_thread_count() {
        let mut d = DbSettingsConfig::default();
        d.compact_threads = 7;
        let r = d.resolve();
        assert_eq!(r.compact_threads, 7);
    }

    #[test]
    fn tx_cache_clamps_to_documented_range() {
        let mut t = TxCacheConfig {
            estimated_transactions: 5,
            ..Default::default()
        };
        t.clamp();
        assert_eq!(t.estimated_transactions, TxCacheConfig::MIN_ESTIMATED_TXS);

        let mut t = TxCacheConfig {
            estimated_transactions: 999_999,
            ..Default::default()
        };
        t.clamp();
        assert_eq!(t.estimated_transactions, TxCacheConfig::MAX_ESTIMATED_TXS);

        let mut t = TxCacheConfig {
            estimated_transactions: 500,
            ..Default::default()
        };
        t.clamp();
        assert_eq!(t.estimated_transactions, 500); // in-range unchanged
    }

    #[test]
    fn storage_section_parses_nested_dbsettings_txcache_aliases() {
        let cfg: NodeConfig = toml::from_str(
            r#"
                [storage]
                write_buffer_size_mb = 64

                [storage.dbSettings]
                levelNumber = 9
                maxBytesForLevelBase = 512
                level0FileNumCompactionTrigger = 4

                [storage.txCache]
                estimatedTransactions = 5000
                initOptimization = true
            "#,
        )
        .expect("parse");
        assert_eq!(cfg.storage.db_settings.level_number, 9);
        assert_eq!(cfg.storage.db_settings.max_bytes_for_level_base, 512);
        assert_eq!(cfg.storage.db_settings.level0_file_num_compaction_trigger, 4);
        assert_eq!(cfg.storage.tx_cache.estimated_transactions, 5000);
        assert!(cfg.storage.tx_cache.init_optimization);

        let resolved_tx_cache = cfg.resolve_tx_cache();
        assert_eq!(resolved_tx_cache.estimated_transactions, 5000);
    }

    // ---- rate.limiter.* ----

    #[test]
    fn rate_limiter_defaults_are_empty_and_flags_off() {
        let r = RateLimiterConfig::default();
        assert!(!r.http_flag());
        assert!(!r.rpc_flag());
    }

    #[test]
    fn rate_limiter_parses_http_and_rpc_lists_with_alias() {
        let cfg: NodeConfig = toml::from_str(
            r#"
                [rate_limiter]
                [[rate_limiter.http]]
                component = "getaccount"
                strategy = "GlobalPreemptibleAdapter"
                paramString = "qps=100"

                [[rate_limiter.rpc]]
                component = "protocol.Wallet/GetAccount"
                strategy = "IPQPSRateLimiter"
                params = "qps=50"
            "#,
        )
        .expect("parse");
        assert_eq!(cfg.rate_limiter.http.len(), 1);
        assert_eq!(cfg.rate_limiter.rpc.len(), 1);
        assert!(cfg.rate_limiter.http_flag());
        assert!(cfg.rate_limiter.rpc_flag());
        // Aliases: paramString → params, direct params field both work.
        assert_eq!(cfg.rate_limiter.http[0].params, "qps=100");
        assert_eq!(cfg.rate_limiter.rpc[0].params, "qps=50");
    }

    // ---- localwitness* ----

    #[test]
    fn local_witness_defaults_to_none_source() {
        let lw = LocalWitnessConfig::default();
        assert_eq!(lw.source(), LocalWitnessSource::None);
    }

    #[test]
    fn local_witness_private_keys_win_over_keystores() {
        let lw = LocalWitnessConfig {
            private_keys: vec!["deadbeef".into()],
            keystores: vec!["/tmp/k.json".into()],
            ..Default::default()
        };
        match lw.source() {
            LocalWitnessSource::PrivateKeys(keys) => assert_eq!(keys.len(), 1),
            other => panic!("expected PrivateKeys, got {other:?}"),
        }
    }

    #[test]
    fn local_witness_parses_toplevel_keys() {
        // The aliases must let the operator write the same key names
        // they'd use in a java-tron config.conf.
        let cfg: NodeConfig = toml::from_str(
            r#"
                [local_witness]
                localwitness = ["00aa", "00bb"]
                localWitnessAccountAddress = "TXYZ..."
                localwitnesskeystore = ["/etc/tron/keystore.json"]
            "#,
        )
        .expect("parse");
        assert_eq!(cfg.local_witness.private_keys, vec!["00aa", "00bb"]);
        assert_eq!(cfg.local_witness.account_address.as_deref(), Some("TXYZ..."));
        assert_eq!(cfg.local_witness.keystores, vec!["/etc/tron/keystore.json"]);
    }

    // ---- committee.* ----

    #[test]
    fn committee_defaults_match_java_tron() {
        let c = CommitteeConfig::default();
        // Most flags default to 0.
        assert_eq!(c.allow_creation_of_contracts, 0);
        assert_eq!(c.allow_tvm_cancun, 0);
        // Only pbft_expire_num has a non-zero default.
        assert_eq!(c.pbft_expire_num, 20);
    }

    #[test]
    fn committee_clamps_all_ranges() {
        let mut c = CommitteeConfig {
            unfreeze_delay_days: 1000,
            allow_delegate_optimization: 7,
            allow_dynamic_energy: -3,
            dynamic_energy_threshold: i64::MAX,
            dynamic_energy_increase_factor: 50_000,
            dynamic_energy_max_factor: i64::MAX,
            allow_new_reward: 5,
            memo_fee: i64::MAX,
            ..Default::default()
        };
        c.clamp();
        assert_eq!(c.unfreeze_delay_days, 365);
        assert_eq!(c.allow_delegate_optimization, 1);
        assert_eq!(c.allow_dynamic_energy, 0);
        assert_eq!(c.dynamic_energy_threshold, 100_000_000_000_000_000);
        assert_eq!(c.dynamic_energy_increase_factor, 10_000);
        assert_eq!(c.dynamic_energy_max_factor, 100_000);
        assert_eq!(c.allow_new_reward, 1);
        assert_eq!(c.memo_fee, 1_000_000_000);
    }

    #[test]
    fn committee_old_reward_opt_requires_prereq() {
        let mut c = CommitteeConfig {
            allow_old_reward_opt: 1,
            ..Default::default()
        };
        assert!(matches!(
            c.validate_old_reward_prereq(),
            Err(ConfigError::Committee(_))
        ));

        // Any one of the three unlocks it.
        c.allow_new_reward = 1;
        assert!(c.validate_old_reward_prereq().is_ok());
        c.allow_new_reward = 0;
        c.allow_tvm_vote = 1;
        assert!(c.validate_old_reward_prereq().is_ok());
    }

    #[test]
    fn committee_parses_pbft_nonstandard_camelcase_keys() {
        // java-tron's `allowPBFT` / `pBFTExpireNum` keys are the
        // non-standard-camelCase ones we have to round-trip.
        let cfg: NodeConfig = toml::from_str(
            r#"
                [committee]
                allowPBFT = 1
                pBFTExpireNum = 50
                allowTvmCancun = 1
                allowDynamicEnergy = 1
                dynamicEnergyMaxFactor = 75000
            "#,
        )
        .expect("parse");
        assert_eq!(cfg.committee.allow_pbft, 1);
        assert_eq!(cfg.committee.pbft_expire_num, 50);
        assert_eq!(cfg.committee.allow_tvm_cancun, 1);

        let resolved = cfg.resolve_committee().expect("ok");
        assert_eq!(resolved.allow_dynamic_energy, 1);
        assert_eq!(resolved.dynamic_energy_max_factor, 75_000); // within clamp
    }

    #[test]
    fn node_config_resolve_committee_propagates_prereq_failure() {
        let mut cfg = NodeConfig::default();
        cfg.committee.allow_old_reward_opt = 1; // prereq missing
        assert!(matches!(
            cfg.resolve_committee(),
            Err(ConfigError::Committee(_))
        ));
    }
}
