//! `WalletSolidity` gRPC service — solidified-state mirror of Wallet.
//!
//! java-tron exposes this on a separate port (50061 by default) so
//! clients can opt into "only blocks already past the solidified
//! checkpoint." Our state layer is single-version (we don't keep a
//! distinct solidified snapshot store), so every method here forwards
//! to the corresponding `Wallet` impl on `WalletService`. The behaviour
//! difference is informational only — clients connecting to this
//! service get the same shape they'd get from `Wallet` today; once a
//! true solidified state layer lands, swap the inner calls for the
//! solid-state lookups without changing the wire surface.

use tonic::{Request, Response, Status};
use tron_proto::protocol::{
    Account, AssetIssueContract, AssetIssueList, Block, BlockExtention, BlockReq,
    BytesMessage, CanDelegatedMaxSizeRequestMessage, CanDelegatedMaxSizeResponseMessage,
    CanWithdrawUnfreezeAmountRequestMessage, CanWithdrawUnfreezeAmountResponseMessage,
    DecryptNotes, DecryptNotesMarked, DecryptNotesTrc20, DelegatedResourceAccountIndex,
    DelegatedResourceList, DelegatedResourceMessage, EmptyMessage, EstimateEnergyMessage,
    Exchange, ExchangeList, GetAvailableUnfreezeCountRequestMessage,
    GetAvailableUnfreezeCountResponseMessage, IncrementalMerkleVoucherInfo,
    IvkDecryptAndMarkParameters, IvkDecryptParameters, IvkDecryptTrc20Parameters, MarketOrder,
    MarketOrderList, MarketOrderPair, MarketOrderPairList, MarketPriceList, NfTrc20Parameters,
    NoteParameters, NullifierResult, NumberMessage, OutputPointInfo, OvkDecryptParameters,
    OvkDecryptTrc20Parameters, PaginatedMessage, PricesResponseMessage, SpendResult,
    Transaction, TransactionExtention, TransactionInfo, TransactionInfoList,
    TriggerSmartContract, WitnessList,
};

use crate::proto::wallet_server::Wallet;
use crate::proto::wallet_solidity_server::WalletSolidity;
use crate::service::WalletService;

#[tonic::async_trait]
impl WalletSolidity for WalletService {
    async fn get_account(
        &self,
        request: Request<Account>,
    ) -> Result<Response<Account>, Status> {
        Wallet::get_account(self, request).await
    }

    async fn get_account_by_id(
        &self,
        request: Request<Account>,
    ) -> Result<Response<Account>, Status> {
        Wallet::get_account_by_id(self, request).await
    }

    async fn list_witnesses(
        &self,
        request: Request<EmptyMessage>,
    ) -> Result<Response<WitnessList>, Status> {
        Wallet::list_witnesses(self, request).await
    }

    async fn get_paginated_now_witness_list(
        &self,
        request: Request<PaginatedMessage>,
    ) -> Result<Response<WitnessList>, Status> {
        Wallet::get_paginated_now_witness_list(self, request).await
    }

    async fn get_asset_issue_list(
        &self,
        request: Request<EmptyMessage>,
    ) -> Result<Response<AssetIssueList>, Status> {
        Wallet::get_asset_issue_list(self, request).await
    }

    async fn get_paginated_asset_issue_list(
        &self,
        request: Request<PaginatedMessage>,
    ) -> Result<Response<AssetIssueList>, Status> {
        Wallet::get_paginated_asset_issue_list(self, request).await
    }

    async fn get_asset_issue_by_name(
        &self,
        request: Request<BytesMessage>,
    ) -> Result<Response<AssetIssueContract>, Status> {
        Wallet::get_asset_issue_by_name(self, request).await
    }

    async fn get_asset_issue_list_by_name(
        &self,
        request: Request<BytesMessage>,
    ) -> Result<Response<AssetIssueList>, Status> {
        Wallet::get_asset_issue_list_by_name(self, request).await
    }

    async fn get_asset_issue_by_id(
        &self,
        request: Request<BytesMessage>,
    ) -> Result<Response<AssetIssueContract>, Status> {
        Wallet::get_asset_issue_by_id(self, request).await
    }

    async fn get_now_block(
        &self,
        request: Request<EmptyMessage>,
    ) -> Result<Response<Block>, Status> {
        Wallet::get_now_block(self, request).await
    }

    async fn get_now_block2(
        &self,
        request: Request<EmptyMessage>,
    ) -> Result<Response<BlockExtention>, Status> {
        Wallet::get_now_block2(self, request).await
    }

    async fn get_block_by_num(
        &self,
        request: Request<NumberMessage>,
    ) -> Result<Response<Block>, Status> {
        Wallet::get_block_by_num(self, request).await
    }

    async fn get_block_by_num2(
        &self,
        request: Request<NumberMessage>,
    ) -> Result<Response<BlockExtention>, Status> {
        Wallet::get_block_by_num2(self, request).await
    }

    async fn get_transaction_count_by_block_num(
        &self,
        request: Request<NumberMessage>,
    ) -> Result<Response<NumberMessage>, Status> {
        Wallet::get_transaction_count_by_block_num(self, request).await
    }

    async fn get_delegated_resource(
        &self,
        request: Request<DelegatedResourceMessage>,
    ) -> Result<Response<DelegatedResourceList>, Status> {
        Wallet::get_delegated_resource(self, request).await
    }

    async fn get_delegated_resource_v2(
        &self,
        request: Request<DelegatedResourceMessage>,
    ) -> Result<Response<DelegatedResourceList>, Status> {
        Wallet::get_delegated_resource_v2(self, request).await
    }

    async fn get_delegated_resource_account_index(
        &self,
        request: Request<BytesMessage>,
    ) -> Result<Response<DelegatedResourceAccountIndex>, Status> {
        Wallet::get_delegated_resource_account_index(self, request).await
    }

    async fn get_delegated_resource_account_index_v2(
        &self,
        request: Request<BytesMessage>,
    ) -> Result<Response<DelegatedResourceAccountIndex>, Status> {
        Wallet::get_delegated_resource_account_index_v2(self, request).await
    }

    async fn get_can_delegated_max_size(
        &self,
        request: Request<CanDelegatedMaxSizeRequestMessage>,
    ) -> Result<Response<CanDelegatedMaxSizeResponseMessage>, Status> {
        Wallet::get_can_delegated_max_size(self, request).await
    }

    async fn get_available_unfreeze_count(
        &self,
        request: Request<GetAvailableUnfreezeCountRequestMessage>,
    ) -> Result<Response<GetAvailableUnfreezeCountResponseMessage>, Status> {
        Wallet::get_available_unfreeze_count(self, request).await
    }

    async fn get_can_withdraw_unfreeze_amount(
        &self,
        request: Request<CanWithdrawUnfreezeAmountRequestMessage>,
    ) -> Result<Response<CanWithdrawUnfreezeAmountResponseMessage>, Status> {
        Wallet::get_can_withdraw_unfreeze_amount(self, request).await
    }

    async fn get_exchange_by_id(
        &self,
        request: Request<BytesMessage>,
    ) -> Result<Response<Exchange>, Status> {
        Wallet::get_exchange_by_id(self, request).await
    }

    async fn list_exchanges(
        &self,
        request: Request<EmptyMessage>,
    ) -> Result<Response<ExchangeList>, Status> {
        Wallet::list_exchanges(self, request).await
    }

    async fn get_transaction_by_id(
        &self,
        request: Request<BytesMessage>,
    ) -> Result<Response<Transaction>, Status> {
        Wallet::get_transaction_by_id(self, request).await
    }

    async fn get_transaction_info_by_id(
        &self,
        request: Request<BytesMessage>,
    ) -> Result<Response<TransactionInfo>, Status> {
        Wallet::get_transaction_info_by_id(self, request).await
    }

    async fn get_merkle_tree_voucher_info(
        &self,
        request: Request<OutputPointInfo>,
    ) -> Result<Response<IncrementalMerkleVoucherInfo>, Status> {
        Wallet::get_merkle_tree_voucher_info(self, request).await
    }

    async fn scan_note_by_ivk(
        &self,
        request: Request<IvkDecryptParameters>,
    ) -> Result<Response<DecryptNotes>, Status> {
        Wallet::scan_note_by_ivk(self, request).await
    }

    async fn scan_and_mark_note_by_ivk(
        &self,
        request: Request<IvkDecryptAndMarkParameters>,
    ) -> Result<Response<DecryptNotesMarked>, Status> {
        Wallet::scan_and_mark_note_by_ivk(self, request).await
    }

    async fn scan_note_by_ovk(
        &self,
        request: Request<OvkDecryptParameters>,
    ) -> Result<Response<DecryptNotes>, Status> {
        Wallet::scan_note_by_ovk(self, request).await
    }

    async fn is_spend(
        &self,
        request: Request<NoteParameters>,
    ) -> Result<Response<SpendResult>, Status> {
        Wallet::is_spend(self, request).await
    }

    async fn scan_shielded_trc20_notes_by_ivk(
        &self,
        request: Request<IvkDecryptTrc20Parameters>,
    ) -> Result<Response<DecryptNotesTrc20>, Status> {
        Wallet::scan_shielded_trc20_notes_by_ivk(self, request).await
    }

    async fn scan_shielded_trc20_notes_by_ovk(
        &self,
        request: Request<OvkDecryptTrc20Parameters>,
    ) -> Result<Response<DecryptNotesTrc20>, Status> {
        Wallet::scan_shielded_trc20_notes_by_ovk(self, request).await
    }

    async fn is_shielded_trc20_contract_note_spent(
        &self,
        request: Request<NfTrc20Parameters>,
    ) -> Result<Response<NullifierResult>, Status> {
        Wallet::is_shielded_trc20_contract_note_spent(self, request).await
    }

    async fn get_reward_info(
        &self,
        request: Request<BytesMessage>,
    ) -> Result<Response<NumberMessage>, Status> {
        Wallet::get_reward_info(self, request).await
    }

    async fn get_brokerage_info(
        &self,
        request: Request<BytesMessage>,
    ) -> Result<Response<NumberMessage>, Status> {
        Wallet::get_brokerage_info(self, request).await
    }

    async fn trigger_constant_contract(
        &self,
        request: Request<TriggerSmartContract>,
    ) -> Result<Response<TransactionExtention>, Status> {
        Wallet::trigger_constant_contract(self, request).await
    }

    async fn estimate_energy(
        &self,
        request: Request<TriggerSmartContract>,
    ) -> Result<Response<EstimateEnergyMessage>, Status> {
        Wallet::estimate_energy(self, request).await
    }

    async fn get_transaction_info_by_block_num(
        &self,
        request: Request<NumberMessage>,
    ) -> Result<Response<TransactionInfoList>, Status> {
        Wallet::get_transaction_info_by_block_num(self, request).await
    }

    async fn get_market_order_by_id(
        &self,
        request: Request<BytesMessage>,
    ) -> Result<Response<MarketOrder>, Status> {
        Wallet::get_market_order_by_id(self, request).await
    }

    async fn get_market_order_by_account(
        &self,
        request: Request<BytesMessage>,
    ) -> Result<Response<MarketOrderList>, Status> {
        Wallet::get_market_order_by_account(self, request).await
    }

    async fn get_market_price_by_pair(
        &self,
        request: Request<MarketOrderPair>,
    ) -> Result<Response<MarketPriceList>, Status> {
        Wallet::get_market_price_by_pair(self, request).await
    }

    async fn get_market_order_list_by_pair(
        &self,
        request: Request<MarketOrderPair>,
    ) -> Result<Response<MarketOrderList>, Status> {
        Wallet::get_market_order_list_by_pair(self, request).await
    }

    async fn get_market_pair_list(
        &self,
        request: Request<EmptyMessage>,
    ) -> Result<Response<MarketOrderPairList>, Status> {
        Wallet::get_market_pair_list(self, request).await
    }

    async fn get_burn_trx(
        &self,
        request: Request<EmptyMessage>,
    ) -> Result<Response<NumberMessage>, Status> {
        Wallet::get_burn_trx(self, request).await
    }

    async fn get_block(
        &self,
        request: Request<BlockReq>,
    ) -> Result<Response<BlockExtention>, Status> {
        Wallet::get_block(self, request).await
    }

    async fn get_bandwidth_prices(
        &self,
        request: Request<EmptyMessage>,
    ) -> Result<Response<PricesResponseMessage>, Status> {
        Wallet::get_bandwidth_prices(self, request).await
    }

    async fn get_energy_prices(
        &self,
        request: Request<EmptyMessage>,
    ) -> Result<Response<PricesResponseMessage>, Status> {
        Wallet::get_energy_prices(self, request).await
    }
}
