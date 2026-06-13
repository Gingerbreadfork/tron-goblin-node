//! `tron-node` — full-node daemon library surface.
//!
//! The binary in `src/main.rs` is a thin shell around [`run`] that
//! parses CLI args and a TOML config. Everything else lives in this
//! crate so integration tests can spawn a node in-process.

pub mod abi_event_decoder;
pub mod admin;
pub mod config;
pub mod diag;
pub mod dump_state;
pub mod backup;
pub mod event_loader;
pub mod fetch_block;
pub mod firehose;
pub mod inbound;
pub mod index_hook;
pub mod logfmt;
pub mod mempool_validator;
pub mod node_persist;
pub mod node_statistics;
pub mod p2p_rate_limiter;
pub mod peer_registry;
pub mod relay;
pub mod resilience;
pub mod runtime;
pub mod pbft_runtime;
pub mod peer_state;
pub mod ref_block;
pub mod snapshot_export;
pub mod snapshot_import;
pub mod sr_runtime;
pub mod storage;
pub mod sync;

pub use admin::{
    compact_all, db_copy, db_lite, db_move, db_root, prune_before, AdminError, DbLiteReport,
    DEFAULT_LITE_RECENT_BLOCKS,
};
pub use config::{
    CommitteeConfig, ConfigError, DbSettingsConfig, EventFilterConfig, EventSubscribeConfig,
    EventTopicConfig, FilterQuery, LocalWitnessConfig, LocalWitnessSource, MetricsConfig,
    NodeBackupConfig, NodeConfig, P2pConfig, RateLimiterConfig, RateLimiterItem, RpcConfig,
    StorageConfig, TxCacheConfig, VmConfig, WitnessConfig,
};
pub use pbft_runtime::{PbftChannels, PbftRuntime, PbftRuntimeError};
pub use peer_state::PeerState;
pub use abi_event_decoder::{decode_one_log, DecodedLog, EventLogContext};
pub use event_loader::{build_event_bus, EventLoaderError};
pub use fetch_block::{FetchBlockInfo, FetchBlockScheduler, FetchDecision};
pub use node_persist::{DbNode, DbNodes, NodePersistService};
pub use node_statistics::{DisconnectReason, NodeStatistics, NodeStatisticsTable};
pub use p2p_rate_limiter::P2pRateLimiter;
pub use peer_registry::PeerRegistry;
pub use relay::{RelayConfig, RelayPeer, RelayPlan, RelayPolicy};
pub use resilience::{
    DisconnectCause, PeerSnapshot, ResilienceConfig, ResilienceDecision, ResiliencePolicy,
    ResilienceService,
};
pub use sr_runtime::{ProducedBlockNotice, SrIdentity, SrRuntime, SrRuntimeError};
pub use dump_state::{snapshot, snapshot_to_json, StateSnapshot};
pub use runtime::{run, RunError, ShutdownSignal};
pub use snapshot_export::{
    export_to_tarball, export_via_checkpoint, Compression, ExportError, ExportReport,
};
pub use snapshot_import::{
    import_from_directory, import_live, import_snapshot, verify_snapshot, ImportError,
    ImportMode, ImportReport,
};
pub use storage::{OpenedStores, StorageError};
pub use sync::{AcceptOutcome, DriverStats, SyncConfig, SyncDriver};
