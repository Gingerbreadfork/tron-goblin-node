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
pub use pending_overlay::PendingOverlay;
pub use permissions::{apply_default_account_permissions, default_account_permissions};
pub use rocksdb_backend::{
    rocksdb_tuning, set_block_cache_bytes, RocksDbBackend, RocksDbError, RocksdbTuning,
};
pub use session::SessionBackend;
pub use snapshot::SnapshotKvBackend;
pub use stores::{
    dynamic_properties_keys, import_all_asset, set_account_asset_backend, witness_schedule_keys,
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
