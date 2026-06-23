//! Top-level dispatch from `ContractType` → actuator.
//!
//! Every transaction's first contract carries a [`ContractType`]; the
//! dispatcher decodes the embedded `Any` parameter, unpacks to the
//! correct contract proto, and routes to the matching `validate_*` /
//! `execute_*` function from the per-domain modules.
//!
//! This is the layer the **block executor** (not yet ported) will call
//! once per transaction. It owns no state; the [`ActuatorStores`] handle
//! provides borrowed access to every store an actuator might touch.

use prost_types::Any;
use tron_chainbase::{
    AbiStore, AccountIdIndexStore, AccountIndexStore, AccountStore, AssetIssueStore,
    AssetIssueV2Store, ContractStore, DelegatedResourceAccountIndexStore, DelegatedResourceStore,
    DelegationStore, DynamicPropertiesStore, ExchangeStore, ExchangeV2Store,
    IncrementalMerkleTreeStore, MarketAccountStore, MarketOrderStore, NullifierStore,
    ProposalStore, VotesStore, WitnessStore,
};
use tron_proto::transaction::contract::ContractType;

use crate::transfer::ExecutionResult;
use crate::ActuatorError;

/// Borrowed handles to every store an actuator might need. The block
/// executor constructs this once per block and reuses it for all
/// transactions; per-tx work just calls `dispatch_validate` then
/// `dispatch_execute` against the same handle.
pub struct ActuatorStores<'a> {
    pub accounts: &'a AccountStore,
    pub witnesses: &'a WitnessStore,
    pub votes: &'a VotesStore,
    pub delegation: &'a DelegationStore,
    pub delegated_resources: &'a DelegatedResourceStore,
    /// Bidirectional `(from, to)` delegation index. Updated on
    /// delegate/undelegate so the RPC `getdelegatedresourceaccountindex`
    /// queries match java-tron. `None` only in unit-test / validate-only
    /// setups that don't exercise the index (production always provides it).
    pub delegated_resource_account_index: Option<&'a DelegatedResourceAccountIndexStore>,
    pub dyn_props: &'a DynamicPropertiesStore,
    pub proposals: &'a ProposalStore,
    pub name_index: &'a AccountIndexStore,
    pub id_index: &'a AccountIdIndexStore,
    pub asset_v1: &'a AssetIssueStore,
    pub asset_v2: &'a AssetIssueV2Store,
    pub contracts: &'a ContractStore,
    pub abi: &'a AbiStore,
    pub exchange_v1: &'a ExchangeStore,
    pub exchange_v2: &'a ExchangeV2Store,
    pub market_orders: &'a MarketOrderStore,
    /// Per-owner aggregate market order accounting (order-id list +
    /// active `count` + monotonic `total_count`). Mirrors
    /// [`market_orders`](Self::market_orders); written by the market
    /// sell/cancel actuators.
    pub market_account: &'a MarketAccountStore,
    pub nullifiers: &'a NullifierStore,
    /// Optional: the shielded-transfer incremental Merkle tree store.
    /// When `None`, the actuator skips the anchor-existence check and
    /// the commitment-append on execute (legacy behaviour for non-
    /// shielded configurations).
    pub merkle_trees: Option<&'a IncrementalMerkleTreeStore>,
    /// Optional: the `reward-vi` store backing the `ALLOW_OLD_REWARD_OPT`
    /// legacy-reward fast path inside reward settlement (vote / unfreeze /
    /// withdraw actuators). Read-only; only consulted for voters whose
    /// reward window predates the new reward algorithm. Production wires
    /// it; `None` in setups that never replay pre-switch accounts.
    pub reward_vi: Option<&'a tron_chainbase::RewardViStore>,
}

/// Per-transaction context needed by actuators that can't be derived
/// from the contract `Any` alone — currently just the shielded-transfer
/// `sighash`, computed by the executor from the canonical transaction
/// body.
#[derive(Default, Clone, Copy)]
pub struct ActuatorTxCtx {
    /// `getShieldTransactionHashIgnoreTypeException(tx)` — 32-byte
    /// sighash over the transaction body. Zero when the transaction
    /// isn't a shielded one (the actuator only consults it then).
    pub sighash: [u8; 32],
}

/// Dispatch validate by contract type.
///
/// **VM-bound contracts** (`CreateSmartContract`, `TriggerSmartContract`)
/// run only their *precondition* gate here (via [`crate::vm::validate_vm`])
/// — owner/contract existence and value-range checks, no EVM. Full
/// execution still goes through `tron_executor::execute_vm_tx`, which
/// provides the EVM stores (`code`, `storage_row`, `contract_state`,
/// `block_index`) that `ActuatorStores` doesn't carry. This split lets
/// non-executor callers (the mempool admission validator) accept valid
/// contract txs instead of rejecting every one.
pub fn dispatch_validate(
    stores: &ActuatorStores<'_>,
    tx_ctx: &ActuatorTxCtx,
    ty: ContractType,
    parameter: &Any,
) -> Result<(), ActuatorError> {
    match ty {
        ContractType::TransferContract => {
            let c = unpack::<tron_proto::TransferContract>(parameter)?;
            crate::transfer::validate_transfer(stores.accounts, stores.dyn_props, &c)
        }
        ContractType::TransferAssetContract => {
            let c = unpack::<tron_proto::TransferAssetContract>(parameter)?;
            crate::asset::validate_transfer_asset(stores.accounts, stores.dyn_props, &c)
        }
        ContractType::VoteWitnessContract => {
            let c = unpack::<tron_proto::VoteWitnessContract>(parameter)?;
            crate::vote_witness::validate_vote_witness(stores.accounts, stores.witnesses, &c)
        }
        ContractType::WitnessCreateContract => {
            let c = unpack::<tron_proto::WitnessCreateContract>(parameter)?;
            crate::witness::validate_witness_create(
                stores.accounts,
                stores.witnesses,
                stores.dyn_props,
                &c,
            )
        }
        ContractType::WitnessUpdateContract => {
            let c = unpack::<tron_proto::WitnessUpdateContract>(parameter)?;
            crate::witness::validate_witness_update(stores.accounts, stores.witnesses, &c)
        }
        ContractType::UpdateBrokerageContract => {
            let c = unpack::<tron_proto::UpdateBrokerageContract>(parameter)?;
            crate::witness::validate_update_brokerage(stores.accounts, stores.witnesses, stores.dyn_props, &c)
        }
        ContractType::WithdrawBalanceContract => {
            let c = unpack::<tron_proto::WithdrawBalanceContract>(parameter)?;
            crate::witness::validate_withdraw_balance(
                stores.accounts,
                stores.dyn_props,
                stores.delegation,
                stores.reward_vi,
                &c,
            )
        }
        ContractType::AccountCreateContract => {
            let c = unpack::<tron_proto::AccountCreateContract>(parameter)?;
            crate::account::validate_create_account(stores.accounts, stores.dyn_props, &c)
        }
        ContractType::AccountUpdateContract => {
            let c = unpack::<tron_proto::AccountUpdateContract>(parameter)?;
            crate::account::validate_update_account(
                stores.accounts,
                stores.name_index,
                stores.dyn_props,
                &c,
            )
        }
        ContractType::SetAccountIdContract => {
            let c = unpack::<tron_proto::SetAccountIdContract>(parameter)?;
            crate::account::validate_set_account_id(stores.accounts, stores.id_index, &c)
        }
        ContractType::AccountPermissionUpdateContract => {
            let c = unpack::<tron_proto::AccountPermissionUpdateContract>(parameter)?;
            crate::account::validate_account_permission_update(
                stores.accounts,
                stores.dyn_props,
                &c,
            )
        }
        ContractType::ProposalCreateContract => {
            let c = unpack::<tron_proto::ProposalCreateContract>(parameter)?;
            crate::proposal::validate_proposal_create(
                stores.accounts,
                stores.witnesses,
                stores.dyn_props,
                &c,
            )
        }
        ContractType::ProposalApproveContract => {
            let c = unpack::<tron_proto::ProposalApproveContract>(parameter)?;
            crate::proposal::validate_proposal_approve(
                stores.accounts,
                stores.witnesses,
                stores.proposals,
                stores.dyn_props,
                &c,
            )
        }
        ContractType::ProposalDeleteContract => {
            let c = unpack::<tron_proto::ProposalDeleteContract>(parameter)?;
            crate::proposal::validate_proposal_delete(
                stores.accounts,
                stores.proposals,
                stores.dyn_props,
                &c,
            )
        }
        ContractType::AssetIssueContract => {
            let c = unpack::<tron_proto::AssetIssueContract>(parameter)?;
            crate::asset::validate_asset_issue(
                stores.accounts,
                stores.asset_v1,
                stores.dyn_props,
                &c,
            )
        }
        ContractType::UpdateAssetContract => {
            let c = unpack::<tron_proto::UpdateAssetContract>(parameter)?;
            crate::asset::validate_update_asset(
                stores.accounts,
                stores.asset_v1,
                stores.asset_v2,
                stores.dyn_props,
                &c,
            )
        }
        ContractType::ParticipateAssetIssueContract => {
            let c = unpack::<tron_proto::ParticipateAssetIssueContract>(parameter)?;
            crate::asset::validate_participate_asset_issue(
                stores.accounts,
                stores.asset_v1,
                stores.asset_v2,
                stores.dyn_props,
                &c,
            )
        }
        ContractType::UnfreezeAssetContract => {
            let c = unpack::<tron_proto::UnfreezeAssetContract>(parameter)?;
            crate::asset::validate_unfreeze_asset(stores.accounts, stores.dyn_props, &c)
        }
        ContractType::FreezeBalanceContract => {
            let c = unpack::<tron_proto::FreezeBalanceContract>(parameter)?;
            crate::freeze::validate_freeze_balance(stores.accounts, stores.dyn_props, &c)
        }
        ContractType::UnfreezeBalanceContract => {
            let c = unpack::<tron_proto::UnfreezeBalanceContract>(parameter)?;
            crate::freeze::validate_unfreeze_balance(
                stores.accounts,
                stores.dyn_props,
                stores.delegated_resources,
                &c,
            )
        }
        ContractType::FreezeBalanceV2Contract => {
            let c = unpack::<tron_proto::FreezeBalanceV2Contract>(parameter)?;
            crate::freeze_v2::validate_freeze_balance_v2(stores.accounts, stores.dyn_props, &c)
        }
        ContractType::UnfreezeBalanceV2Contract => {
            let c = unpack::<tron_proto::UnfreezeBalanceV2Contract>(parameter)?;
            crate::freeze_v2::validate_unfreeze_balance_v2(stores.accounts, stores.dyn_props, &c)
        }
        ContractType::WithdrawExpireUnfreezeContract => {
            let c = unpack::<tron_proto::WithdrawExpireUnfreezeContract>(parameter)?;
            crate::freeze_v2::validate_withdraw_expire_unfreeze(
                stores.accounts,
                stores.dyn_props,
                &c,
            )
        }
        ContractType::CancelAllUnfreezeV2Contract => {
            let c = unpack::<tron_proto::CancelAllUnfreezeV2Contract>(parameter)?;
            crate::freeze_v2::validate_cancel_all_unfreeze_v2(
                stores.accounts,
                stores.dyn_props,
                &c,
            )
        }
        ContractType::DelegateResourceContract => {
            let c = unpack::<tron_proto::DelegateResourceContract>(parameter)?;
            crate::delegate::validate_delegate_resource(stores.accounts, stores.dyn_props, &c)
        }
        ContractType::UnDelegateResourceContract => {
            let c = unpack::<tron_proto::UnDelegateResourceContract>(parameter)?;
            crate::delegate::validate_undelegate_resource(
                stores.accounts,
                stores.delegated_resources,
                stores.dyn_props,
                &c,
            )
        }
        ContractType::ExchangeCreateContract => {
            let c = unpack::<tron_proto::ExchangeCreateContract>(parameter)?;
            crate::exchange::validate_exchange_create(stores.accounts, stores.dyn_props, &c)
        }
        ContractType::ExchangeInjectContract => {
            let c = unpack::<tron_proto::ExchangeInjectContract>(parameter)?;
            crate::exchange::validate_exchange_inject(
                stores.accounts,
                stores.dyn_props,
                stores.exchange_v2,
                &c,
            )
        }
        ContractType::ExchangeWithdrawContract => {
            let c = unpack::<tron_proto::ExchangeWithdrawContract>(parameter)?;
            crate::exchange::validate_exchange_withdraw(
                stores.accounts,
                stores.dyn_props,
                stores.exchange_v2,
                &c,
            )
        }
        ContractType::ExchangeTransactionContract => {
            let c = unpack::<tron_proto::ExchangeTransactionContract>(parameter)?;
            crate::exchange::validate_exchange_transaction(
                stores.accounts,
                stores.exchange_v2,
                stores.dyn_props,
                &c,
            )
        }
        ContractType::MarketSellAssetContract => {
            let c = unpack::<tron_proto::MarketSellAssetContract>(parameter)?;
            crate::market::validate_market_sell_asset(
                stores.accounts,
                stores.market_account,
                stores.asset_v1,
                stores.asset_v2,
                stores.dyn_props,
                &c,
            )
        }
        ContractType::MarketCancelOrderContract => {
            let c = unpack::<tron_proto::MarketCancelOrderContract>(parameter)?;
            crate::market::validate_market_cancel_order(
                stores.accounts,
                stores.market_orders,
                stores.dyn_props,
                &c,
            )
        }
        ContractType::ClearAbiContract => {
            let c = unpack::<tron_proto::ClearAbiContract>(parameter)?;
            crate::contract_admin::validate_clear_abi(
                stores.accounts,
                stores.contracts,
                stores.dyn_props,
                &c,
            )
        }
        ContractType::UpdateEnergyLimitContract => {
            let c = unpack::<tron_proto::UpdateEnergyLimitContract>(parameter)?;
            crate::contract_admin::validate_update_energy_limit(
                stores.accounts,
                stores.contracts,
                stores.dyn_props,
                &c,
            )
        }
        ContractType::UpdateSettingContract => {
            let c = unpack::<tron_proto::UpdateSettingContract>(parameter)?;
            crate::contract_admin::validate_update_setting(stores.accounts, stores.contracts, &c)
        }
        ContractType::CreateSmartContract | ContractType::TriggerSmartContract => {
            // Precondition gate only (owner/contract existence, value
            // ranges). Execution still runs through the executor's
            // `execute_vm_tx`; this lets non-executor callers (the mempool
            // admission validator) accept valid contract txs instead of
            // rejecting every one. See `crate::vm`.
            crate::vm::validate_vm(stores.accounts, stores.contracts, ty, parameter)
        }
        ContractType::ShieldedTransferContract => {
            let c = unpack::<tron_proto::ShieldedTransferContract>(parameter)?;
            // Fee is read by the actuator from DynamicPropertiesStore;
            // pass 0 as the upper-layer placeholder. Validate uses fee
            // only for the transparent-half balance check, which the
            // executor enforces separately when accounting transparent
            // amounts.
            let fee = stores
                .dyn_props
                .get_long(b"SHIELDED_TRANSACTION_FEE")
                .unwrap_or(0);
            crate::shielded_transfer::validate_shielded_transfer(
                stores.accounts,
                stores.dyn_props,
                stores.nullifiers,
                stores.merkle_trees,
                &c,
                &tx_ctx.sighash,
                fee,
            )
        }
        _ => Err(ActuatorError::NotImplemented(
            "contract type has no actuator (deprecated or unused)",
        )),
    }
}

/// Dispatch execute by contract type.
///
/// **VM-bound contracts** (`CreateSmartContract`, `TriggerSmartContract`)
/// return `ActuatorError::NotImplemented` here — see
/// [`dispatch_validate`] for the routing rule.
pub fn dispatch_execute(
    stores: &ActuatorStores<'_>,
    _tx_ctx: &ActuatorTxCtx,
    ty: ContractType,
    parameter: &Any,
) -> Result<ExecutionResult, ActuatorError> {
    match ty {
        ContractType::TransferContract => {
            let c = unpack::<tron_proto::TransferContract>(parameter)?;
            crate::transfer::execute_transfer(stores.accounts, stores.dyn_props, &c)
        }
        ContractType::TransferAssetContract => {
            let c = unpack::<tron_proto::TransferAssetContract>(parameter)?;
            crate::asset::execute_transfer_asset(stores.accounts, stores.dyn_props, stores.asset_v1, &c)
        }
        ContractType::VoteWitnessContract => {
            let c = unpack::<tron_proto::VoteWitnessContract>(parameter)?;
            crate::vote_witness::execute_vote_witness(
                stores.accounts,
                stores.votes,
                stores.delegation,
                stores.dyn_props,
                stores.reward_vi,
                &c,
            )?;
            Ok(ExecutionResult::default())
        }
        ContractType::WitnessCreateContract => {
            let c = unpack::<tron_proto::WitnessCreateContract>(parameter)?;
            crate::witness::execute_witness_create(
                stores.accounts,
                stores.witnesses,
                stores.dyn_props,
                &c,
            )
        }
        ContractType::WitnessUpdateContract => {
            let c = unpack::<tron_proto::WitnessUpdateContract>(parameter)?;
            crate::witness::execute_witness_update(stores.witnesses, &c)
        }
        ContractType::UpdateBrokerageContract => {
            let c = unpack::<tron_proto::UpdateBrokerageContract>(parameter)?;
            crate::witness::execute_update_brokerage(stores.delegation, &c)
        }
        ContractType::WithdrawBalanceContract => {
            let c = unpack::<tron_proto::WithdrawBalanceContract>(parameter)?;
            crate::witness::execute_withdraw_balance(
                stores.accounts,
                stores.dyn_props,
                stores.delegation,
                stores.reward_vi,
                &c,
            )
        }
        ContractType::AccountCreateContract => {
            let c = unpack::<tron_proto::AccountCreateContract>(parameter)?;
            crate::account::execute_create_account(stores.accounts, stores.dyn_props, &c)
        }
        ContractType::AccountUpdateContract => {
            let c = unpack::<tron_proto::AccountUpdateContract>(parameter)?;
            crate::account::execute_update_account(stores.accounts, stores.name_index, &c)
        }
        ContractType::SetAccountIdContract => {
            let c = unpack::<tron_proto::SetAccountIdContract>(parameter)?;
            crate::account::execute_set_account_id(stores.accounts, stores.id_index, &c)
        }
        ContractType::AccountPermissionUpdateContract => {
            let c = unpack::<tron_proto::AccountPermissionUpdateContract>(parameter)?;
            crate::account::execute_account_permission_update(
                stores.accounts,
                stores.dyn_props,
                &c,
            )
        }
        ContractType::ProposalCreateContract => {
            let c = unpack::<tron_proto::ProposalCreateContract>(parameter)?;
            crate::proposal::execute_proposal_create(stores.proposals, stores.dyn_props, &c)
        }
        ContractType::ProposalApproveContract => {
            let c = unpack::<tron_proto::ProposalApproveContract>(parameter)?;
            crate::proposal::execute_proposal_approve(stores.proposals, &c)
        }
        ContractType::ProposalDeleteContract => {
            let c = unpack::<tron_proto::ProposalDeleteContract>(parameter)?;
            crate::proposal::execute_proposal_delete(stores.proposals, &c)
        }
        ContractType::AssetIssueContract => {
            let c = unpack::<tron_proto::AssetIssueContract>(parameter)?;
            crate::asset::execute_asset_issue(
                stores.accounts,
                stores.asset_v1,
                stores.asset_v2,
                stores.dyn_props,
                &c,
            )
        }
        ContractType::UpdateAssetContract => {
            let c = unpack::<tron_proto::UpdateAssetContract>(parameter)?;
            crate::asset::execute_update_asset(stores.accounts, stores.asset_v1, stores.asset_v2, &c)
        }
        ContractType::ParticipateAssetIssueContract => {
            let c = unpack::<tron_proto::ParticipateAssetIssueContract>(parameter)?;
            crate::asset::execute_participate_asset_issue(
                stores.accounts,
                stores.asset_v1,
                stores.asset_v2,
                stores.dyn_props,
                &c,
            )
        }
        ContractType::UnfreezeAssetContract => {
            let c = unpack::<tron_proto::UnfreezeAssetContract>(parameter)?;
            crate::asset::execute_unfreeze_asset(
                stores.accounts,
                stores.asset_v1,
                stores.dyn_props,
                &c,
            )
        }
        ContractType::FreezeBalanceContract => {
            let c = unpack::<tron_proto::FreezeBalanceContract>(parameter)?;
            crate::freeze::execute_freeze_balance(
                stores.accounts,
                stores.dyn_props,
                stores.delegated_resources,
                stores.delegated_resource_account_index,
                &c,
            )
        }
        ContractType::UnfreezeBalanceContract => {
            let c = unpack::<tron_proto::UnfreezeBalanceContract>(parameter)?;
            crate::freeze::execute_unfreeze_balance(
                stores.accounts,
                stores.dyn_props,
                stores.votes,
                stores.delegation,
                stores.delegated_resources,
                stores.delegated_resource_account_index,
                stores.reward_vi,
                &c,
            )
        }
        ContractType::FreezeBalanceV2Contract => {
            let c = unpack::<tron_proto::FreezeBalanceV2Contract>(parameter)?;
            crate::freeze_v2::execute_freeze_balance_v2(stores.accounts, stores.dyn_props, &c)
        }
        ContractType::UnfreezeBalanceV2Contract => {
            let c = unpack::<tron_proto::UnfreezeBalanceV2Contract>(parameter)?;
            crate::freeze_v2::execute_unfreeze_balance_v2(
                stores.accounts,
                stores.dyn_props,
                stores.votes,
                stores.delegation,
                stores.reward_vi,
                &c,
            )
        }
        ContractType::WithdrawExpireUnfreezeContract => {
            let c = unpack::<tron_proto::WithdrawExpireUnfreezeContract>(parameter)?;
            crate::freeze_v2::execute_withdraw_expire_unfreeze(
                stores.accounts,
                stores.dyn_props,
                &c,
            )
        }
        ContractType::CancelAllUnfreezeV2Contract => {
            let c = unpack::<tron_proto::CancelAllUnfreezeV2Contract>(parameter)?;
            crate::freeze_v2::execute_cancel_all_unfreeze_v2(
                stores.accounts,
                stores.dyn_props,
                &c,
            )
        }
        ContractType::DelegateResourceContract => {
            let c = unpack::<tron_proto::DelegateResourceContract>(parameter)?;
            crate::delegate::execute_delegate_resource(
                stores.accounts,
                stores.delegated_resources,
                stores.delegated_resource_account_index,
                stores.dyn_props,
                &c,
            )
        }
        ContractType::UnDelegateResourceContract => {
            let c = unpack::<tron_proto::UnDelegateResourceContract>(parameter)?;
            crate::delegate::execute_undelegate_resource(
                stores.accounts,
                stores.delegated_resources,
                stores.delegated_resource_account_index,
                stores.dyn_props,
                &c,
            )
        }
        ContractType::ExchangeCreateContract => {
            let c = unpack::<tron_proto::ExchangeCreateContract>(parameter)?;
            crate::exchange::execute_exchange_create(
                stores.accounts,
                stores.exchange_v1,
                stores.exchange_v2,
                stores.dyn_props,
                &c,
            )
        }
        ContractType::ExchangeInjectContract => {
            let c = unpack::<tron_proto::ExchangeInjectContract>(parameter)?;
            crate::exchange::execute_exchange_inject(
                stores.accounts,
                stores.exchange_v1,
                stores.exchange_v2,
                &c,
            )
        }
        ContractType::ExchangeWithdrawContract => {
            let c = unpack::<tron_proto::ExchangeWithdrawContract>(parameter)?;
            crate::exchange::execute_exchange_withdraw(
                stores.accounts,
                stores.exchange_v1,
                stores.exchange_v2,
                &c,
            )
        }
        ContractType::ExchangeTransactionContract => {
            let c = unpack::<tron_proto::ExchangeTransactionContract>(parameter)?;
            crate::exchange::execute_exchange_transaction(
                stores.accounts,
                stores.exchange_v1,
                stores.exchange_v2,
                stores.dyn_props,
                &c,
            )
        }
        ContractType::MarketSellAssetContract => {
            let c = unpack::<tron_proto::MarketSellAssetContract>(parameter)?;
            crate::market::execute_market_sell_asset(
                stores.accounts,
                stores.market_orders,
                stores.market_account,
                stores.dyn_props,
                &c,
            )
        }
        ContractType::MarketCancelOrderContract => {
            let c = unpack::<tron_proto::MarketCancelOrderContract>(parameter)?;
            crate::market::execute_market_cancel_order(
                stores.accounts,
                stores.market_orders,
                stores.market_account,
                stores.dyn_props,
                &c,
            )
        }
        ContractType::ClearAbiContract => {
            let c = unpack::<tron_proto::ClearAbiContract>(parameter)?;
            crate::contract_admin::execute_clear_abi(stores.abi, &c)
        }
        ContractType::UpdateEnergyLimitContract => {
            let c = unpack::<tron_proto::UpdateEnergyLimitContract>(parameter)?;
            crate::contract_admin::execute_update_energy_limit(stores.contracts, &c)
        }
        ContractType::UpdateSettingContract => {
            let c = unpack::<tron_proto::UpdateSettingContract>(parameter)?;
            crate::contract_admin::execute_update_setting(stores.contracts, &c)
        }
        ContractType::CreateSmartContract | ContractType::TriggerSmartContract => crate::deferred::execute_vm(),
        ContractType::ShieldedTransferContract => {
            let c = unpack::<tron_proto::ShieldedTransferContract>(parameter)?;
            crate::shielded_transfer::execute_shielded_transfer(
                stores.accounts,
                stores.dyn_props,
                stores.nullifiers,
                stores.merkle_trees,
                &c,
            )
        }
        _ => Err(ActuatorError::NotImplemented(
            "contract type has no actuator (deprecated or unused)",
        )),
    }
}

fn unpack<T: prost::Message + Default>(any: &Any) -> Result<T, ActuatorError> {
    T::decode(any.value.as_slice()).map_err(|e| {
        ActuatorError::Store(format!("failed to decode contract parameter: {e}"))
    })
}
