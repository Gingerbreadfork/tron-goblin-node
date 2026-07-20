//! Storage layer for the TRON node.
//!
//! Each "store" in java-tron's `chainbase` module is a separate
//! RocksDB/LevelDB instance keyed by some convention (address, hash,
//! block-number-as-big-endian-long, etc.) with values that are usually
//! protobuf-serialised "capsule" messages. This crate ports the per-store
//! key/value codecs over a pluggable [`KvBackend`] trait so the same
//! store implementations work against an in-memory backend (for tests),
//! a RocksDB backend, or a LevelDB backend (both deferred until a real
//! data directory is available to validate byte-for-byte parity).

pub mod backend;
pub mod blockstm;
pub mod checkpoint_v2;
pub mod convert;
pub mod fee;
pub mod java_checkpoint;
pub mod pending_overlay;
pub mod permissions;
pub mod rocksdb_backend;
pub mod session;
pub mod snapshot;
pub mod stores;
pub use stores::incremental_merkle_tree_store;

pub use backend::{KvBackend, KvError, MemBackend, ShardedMemBackend, WriteOp};
pub use checkpoint_v2::{
    decode_manifest, encode_manifest, CheckPointV2, CheckpointEntry, CheckpointError,
    CheckpointId, CHECKPOINT_DIR_NAME,
};
pub use java_checkpoint::{
    has_pending_java_checkpoint, replay_java_checkpoint, JavaCheckpointError,
    JAVA_CHECKPOINT_V1_DIR, JAVA_CHECKPOINT_V2_DIR,
};
pub use convert::{
    open_dest_store, stream_source_into_dest, verify_dest_store, ConvertError, KvSource,
    RocksDbSource, StreamStats, VisitError, CONVERT_BATCH, NODE_STORE_NAMES,
};
pub use fee::dispose_fee_to_blackhole;
pub use pending_overlay::PendingOverlay;
pub use permissions::{
    apply_default_account_permissions, default_account_permissions, set_default_witness_permission,
};
pub use rocksdb_backend::{
    rocksdb_tuning, set_block_cache_bytes, RocksDbBackend, RocksDbError, RocksdbTuning,
};
pub use session::SessionBackend;
pub use snapshot::SnapshotKvBackend;
pub use stores::{
    account_asset_rows_for_trace, dynamic_properties_keys, import_all_asset,
    set_account_asset_backend, witness_schedule_keys,
    AbiStore, AccountAssetStore,
    AccountIdIndexStore, AccountIndexStore, AccountStore, AccountTraceStore, AssetIssueStore,
    AssetIssueV2Store, BalanceTraceStore, BlockIndexStore, BlockStore, BlockUndoDecodeError,
    BlockUndoRecord, BlockUndoStore, CheckPointV2Store,
    CheckTmpStore, CodeStore, CommonDataBaseStore, CommonStore, ContractStateStore, ContractStore,
    DelegatedResourceAccountIndexStore, DelegatedResourceStore, DelegationStore,
    comparator_for_store, market_order_price_comparator, DynamicPropertiesStore, ExchangeStore, ExchangeV2Store,
    IncrementalMerkleTreeStore, MarketAccountStore, MarketOrderStore, MarketPairPriceToOrderStore,
    MarketPairToPriceStore, MARKET_ORDER_PRICE_COMPARATOR_NAME, MARKET_PAIR_PRICE_TO_ORDER_DB_NAME,
    NullifierStore, PbftSignDataStore, ProposalStore, RecentBlockStore, RecentTransactionStore,
    RewardViStore, SectionBloomStore, StorageRowStore, StoreError, StoredTransaction,
    TransactionCacheStore, TransactionHistoryStore, TransactionRetStore, TransactionStore, TreeBlockIndexStore,
    UndoEntry, UndoStoreId, VotesStore, WitnessScheduleStore, WitnessStore, ZkProofStore, DEFAULT_BROKERAGE, REMARK,
    V1_FROM_PREFIX, V1_TO_PREFIX, V2_FROM_PREFIX, V2_PREFIX_LOCKED, V2_PREFIX_UNLOCKED,
    V2_TO_PREFIX,
};

/// Block height at which java-tron's `ENERGY_LIMIT_HARD_FORK` activates on
/// mainnet (java `CommonParameter.blockNumForEnergyLimit`, default `4727890`).
pub const ENERGY_LIMIT_HARD_FORK_BLOCK: i64 = 4_727_890;

/// Whether `ENERGY_LIMIT_HARD_FORK` is active for the transaction currently
/// being executed.
///
/// java resolves this through `ReceiptCapsule.checkForEnergyLimit`, which
/// compares the *persisted* head (`getLatestBlockHeaderNumber`) against
/// [`ENERGY_LIMIT_HARD_FORK_BLOCK`]. The head pointer is advanced only after
/// every transaction in a block has been applied, so while block `N` executes
/// the store still reads `N - 1`. Callers must therefore use this helper rather
/// than the number of the block being applied, which would activate the fork
/// one block early.
pub fn energy_limit_hard_fork_active(dyn_props: &DynamicPropertiesStore) -> bool {
    dyn_props.latest_block_header_number().unwrap_or(0) >= ENERGY_LIMIT_HARD_FORK_BLOCK
}
