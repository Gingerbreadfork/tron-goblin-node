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

    /// HTTP REST API on port 8090 — the surface that TronWeb,
    /// TronGrid, and the reference wallet-cli speak.
    #[serde(default)]
    pub http: HttpRestConfig,

    /// Super Representative block-production runtime. When `None`,
    /// the node runs sync-only. When set, a tokio task fires every
    /// 500ms checking whether we own the current slot per DPoS, and
    /// produces+broadcasts a block when we do.
    #[serde(default)]
    pub witness: Option<WitnessConfig>,

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
    /// yet wired (see PARITY.md "Eventer / logsfilter"). Setting fields
    /// here is a no-op until the loader lands.
    #[serde(default)]
    pub event: Option<EventSubscribeConfig>,

    /// Witness-node high-availability backup-server settings. Mirrors
    /// java-tron's `node.backup.*`. Used by SR operators running an
    /// active/standby pair: the higher-priority instance announces
    /// itself on the backup port and the standby keeps quiet (won't
    /// produce blocks) as long as it sees the master.
    ///
    /// **Status**: schema only — the parser accepts these keys but the
    /// `BackupManager` runtime is not yet wired (see PARITY.md HIGH
    /// "P2P: NodePersistService / RelayService / fastForward witness
    /// role" — backup election lives in the same service tier).
    #[serde(default)]
    pub node_backup: NodeBackupConfig,

    /// EVM / TVM runtime knobs. Mirrors java-tron's `vm.*` section
    /// (constant-call energy ceilings, internal-tx save toggles, time
    /// ratios for the long-running gate, etc.).
    ///
    /// **Status**: schema parses with java-tron's clamps applied; only
    /// a subset of fields are consulted by the executor today. See
    /// PARITY.md HIGH "TVM opcodes" + "EVM `gas_refunded` hardcoded"
    /// for the related execution gaps.
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
    /// Per-process max open file descriptors. RocksDB opens one fd
    /// per SST + a few per CF; for ~30 stores this is comfortably
    /// under typical 65 535 / 1 048 576 user limits.
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
}

fn default_snapshot_horizon() -> usize {
    64
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
        }
    }
}

/// Per-CF RocksDB tuning. Field defaults mirror java-tron's
/// `StorageConfig.DbSettingsConfig` exactly; consumers (the RocksDB
/// open path) should read via [`DbSettingsConfig::resolve`] so the
/// `compact_threads = 0` "auto" sentinel expands to the host CPU count
/// (matching `postProcess` in java-tron).
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
    65_535
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRestConfig {
    /// Bind host. `127.0.0.1` by default; set to `0.0.0.0` for public
    /// exposure (the HTTP REST surface includes `broadcasttransaction`
    /// — be deliberate before opening it up).
    #[serde(default = "default_http_host")]
    pub host: String,
    /// Listen port. `8090` matches java-tron's default and what
    /// TronWeb/TronGrid expect.
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
    8090
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrpcConfig {
    /// Bind host. `127.0.0.1` by default — set to `0.0.0.0` for
    /// public exposure (the gRPC surface includes writer methods).
    #[serde(default = "default_grpc_host")]
    pub host: String,
    /// Listen port. `50051` matches java-tron's default and what
    /// every TRON client library expects.
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
    50051
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Bind host. `127.0.0.1` by default — metrics endpoints
    /// typically shouldn't be exposed publicly.
    #[serde(default = "default_metrics_host")]
    pub host: String,
    /// Listen port. `9090` is the Prometheus default scrape port.
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
    9090
}

// -- event.subscribe.* (java-tron parity schema) --

/// Top-level container mirroring java-tron's `event.subscribe` section
/// (`EventPluginConfig` + `FilterQuery`). Schema is wire-compatible
/// with `config.conf`; semantics deferred (no plugin loader yet — see
/// PARITY.md MEDIUM "Eventer / logsfilter").
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
    /// Listen port. `8545` is the Ethereum-standard default; java-tron
    /// uses `8090` for its HTTP API but Ethereum wallets expect 8545.
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
    /// Emit a heartbeat log line every N applied blocks during sync.
    /// `0` = silent (only failures logged). `1` = log every block. The
    /// default of `100` keeps idle steady-state quiet but produces a
    /// usable progress trail when syncing from genesis or triaging
    /// divergences against live mainnet.
    #[serde(default = "default_progress_log_interval")]
    pub progress_log_interval: usize,
    /// Mix `tron_net::MAINNET_SEEDS` into the peer pool, in addition
    /// to any explicit `peers`. When `peers` is empty, the seeds are
    /// always used regardless of this flag — so a flagless `tron-node
    /// start` does something useful.
    #[serde(default)]
    pub use_mainnet_seeds: bool,
    /// Port we advertise to peers in our Hello messages. Default
    /// `18888` (java-tron's mainnet P2P port). java-tron's
    /// `NetUtil.validNode` rejects port `0` with `BAD_PROTOCOL`, so
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
    /// Enable Kademlia DHT peer discovery. When on, bootstraps from
    /// `peers` + `MAINNET_SEEDS` over UDP, then augments the TCP dial
    /// list with the discovered peers. Off keeps the legacy
    /// seeds-only behavior. java-tron parity flag:
    /// `node.p2p.discover.enable`.
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
            storage: StorageConfig::default(),
            event: None,
            node_backup: NodeBackupConfig::default(),
            vm: VmConfig::default(),
            rate_limiter: RateLimiterConfig::default(),
            local_witness: LocalWitnessConfig::default(),
            committee: CommitteeConfig::default(),
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
            use_mainnet_seeds: false,
            advertise_port: default_advertise_port(),
            max_peers: default_max_peers(),
            discover_enable: default_discover_enable(),
            discover_bootstrap_ms: default_discover_bootstrap_ms(),
            discover_tree_urls: default_discover_tree_urls(),
            discover_tree_query_timeout_ms: default_discover_tree_query_timeout_ms(),
            node_discovery_persist: default_node_discovery_persist(),
            node_discovery_persist_interval_ms: default_node_discovery_persist_interval_ms(),
            fetch_block_timeout_ms: default_fetch_block_timeout_ms(),
            fast_forward_nodes: Vec::new(),
            tip_test: None,
        }
    }
}

fn default_advertise_port() -> i32 {
    18_888
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
    8545
}
fn default_chain_id() -> u64 {
    tron_rpc::MAINNET_CHAIN_ID
}

// -- rate.limiter.* (java-tron parity schema) --

/// Mirrors java-tron's `RateLimiterInitialization`. Each entry binds a
/// component (HTTP servlet name or gRPC method) to a strategy +
/// params string. Also covers the per-frame-type P2P rate caps that
/// each `PeerConnection` registers on its `P2pRateLimiter`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

#[cfg(test)]
mod tests {
    use super::*;

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
