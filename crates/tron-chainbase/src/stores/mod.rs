//! Per-store wrappers. Each file in this module corresponds to one store
//! directory under java-tron's `output-directory/database/<name>/`.

mod abi_store;
mod account_asset_store;
mod account_id_index_store;
mod account_index_store;
mod account_store;
mod account_trace_store;
mod asset_issue_store;
mod balance_trace_store;
mod block_index_store;
mod block_store;
mod block_undo_store;
mod check_tmp_store;
mod checkpoint_v2_store;
mod code_store;
mod common_database_store;
mod common_store;
mod contract_state_store;
mod contract_store;
mod delegated_resource_account_index_store;
mod delegated_resource_store;
mod delegation_store;
mod dynamic_properties_store;
mod exchange_store;
pub mod incremental_merkle_tree_store;
mod market_stores;
mod nullifier_store;
mod pbft_sign_data_store;
mod proposal_store;
mod recent_block_store;
mod recent_transaction_store;
mod reward_vi_store;
mod section_bloom_store;
mod storage_row_store;
mod transaction_cache_store;
mod transaction_history_store;
mod transaction_ret_store;
mod transaction_store;
mod tree_block_index_store;
mod votes_store;
mod witness_schedule_store;
mod witness_store;
mod zk_proof_store;

pub use abi_store::AbiStore;
pub use account_asset_store::{
    account_asset_rows_for_trace, import_all_asset, set_account_asset_backend, AccountAssetStore,
};
pub use account_id_index_store::AccountIdIndexStore;
pub use account_index_store::AccountIndexStore;
pub use account_store::AccountStore;
pub use account_trace_store::AccountTraceStore;
pub use asset_issue_store::{AssetIssueStore, AssetIssueV2Store};
pub use balance_trace_store::BalanceTraceStore;
pub use block_index_store::BlockIndexStore;
pub use block_store::BlockStore;
pub use block_undo_store::{
    BlockUndoRecord, BlockUndoStore, DecodeError as BlockUndoDecodeError, StoreId as UndoStoreId,
    UndoEntry,
};
pub use check_tmp_store::CheckTmpStore;
pub use checkpoint_v2_store::CheckPointV2Store;
pub use code_store::CodeStore;
pub use common_database_store::CommonDataBaseStore;
pub use common_store::CommonStore;
pub use contract_state_store::ContractStateStore;
pub use contract_store::ContractStore;
pub use delegated_resource_account_index_store::{
    DelegatedResourceAccountIndexStore, V1_FROM_PREFIX, V1_TO_PREFIX, V2_FROM_PREFIX, V2_TO_PREFIX,
};
pub use delegated_resource_store::{
    DelegatedResourceStore, V2_PREFIX_LOCKED, V2_PREFIX_UNLOCKED,
};
pub use delegation_store::{DelegationStore, DEFAULT_BROKERAGE, REMARK};
pub use dynamic_properties_store::{keys as dynamic_properties_keys, DynamicPropertiesStore};
pub use exchange_store::{ExchangeStore, ExchangeV2Store};
pub use incremental_merkle_tree_store::IncrementalMerkleTreeStore;
pub use market_stores::{
    comparator_for_store, market_order_price_comparator, MarketAccountStore, MarketOrderStore,
    MarketPairPriceToOrderStore, MarketPairToPriceStore, MARKET_ORDER_PRICE_COMPARATOR_NAME,
    MARKET_PAIR_PRICE_TO_ORDER_DB_NAME,
};
pub use nullifier_store::NullifierStore;
pub use pbft_sign_data_store::PbftSignDataStore;
pub use proposal_store::ProposalStore;
pub use recent_block_store::RecentBlockStore;
pub use recent_transaction_store::RecentTransactionStore;
pub use reward_vi_store::RewardViStore;
pub use section_bloom_store::SectionBloomStore;
pub use storage_row_store::StorageRowStore;
pub use transaction_cache_store::TransactionCacheStore;
pub use transaction_history_store::TransactionHistoryStore;
pub use transaction_ret_store::TransactionRetStore;
pub use transaction_store::{StoredTransaction, TransactionStore};
pub use tree_block_index_store::TreeBlockIndexStore;
pub use votes_store::VotesStore;
pub use witness_schedule_store::{keys as witness_schedule_keys, WitnessScheduleStore};
pub use witness_store::WitnessStore;
pub use zk_proof_store::ZkProofStore;

/// Errors raised by store reads/writes.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StoreError {
    #[error("item not found")]
    NotFound,
    #[error("invalid key length: got {got}, expected {expected}")]
    InvalidKeyLength { got: usize, expected: usize },
    #[error("invalid value length: got {got}, expected {expected}")]
    InvalidValueLength { got: usize, expected: usize },
    #[error("protobuf decode error: {0}")]
    Decode(String),
    /// Surfaced when the underlying [`crate::KvBackend`] returned an
    /// error (RocksDB IO, corruption detected at open, etc.). Lets
    /// store-level callers distinguish "key isn't there" from
    /// "couldn't even ask the disk" — the prior infallible `get`
    /// silently merged both, which was the C-9 footgun.
    #[error("kv backend: {0}")]
    Backend(String),
}

impl From<prost::DecodeError> for StoreError {
    fn from(e: prost::DecodeError) -> Self {
        Self::Decode(e.to_string())
    }
}

impl From<crate::KvError> for StoreError {
    fn from(e: crate::KvError) -> Self {
        Self::Backend(e.to_string())
    }
}
