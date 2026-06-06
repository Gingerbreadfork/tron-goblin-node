//! Mempool state-aware validator hook.
//!
//! Builds a [`tron_mempool::TxValidatorFn`] from a [`StateBackends`]
//! handle. The returned closure runs `tron_actuator::dispatch_validate`
//! against the current state for each contract in the transaction,
//! catching the same precondition failures a peer would catch on
//! receive — fee insufficiency, missing permission, contract-specific
//! state mismatches.
//!
//! Without this, the mempool only does stateless checks (decode / sig
//! recovery / expiration / dedup) and a peer can silently reject our
//! broadcast.

use std::sync::Arc;

use tron_actuator::{dispatch_validate, ActuatorStores, ActuatorTxCtx};
use tron_chainbase::{
    AbiStore, AccountIdIndexStore, AccountIndexStore, AccountStore, AssetIssueStore,
    AssetIssueV2Store, ContractStore, DelegatedResourceStore, DelegationStore,
    DynamicPropertiesStore, ExchangeStore, ExchangeV2Store, IncrementalMerkleTreeStore,
    KvBackend, MarketOrderStore, NullifierStore, ProposalStore, VotesStore, WitnessStore,
};
use tron_executor::StateBackends;
use tron_mempool::TxValidatorFn;
use tron_proto::{transaction::contract::ContractType, Transaction};

use crate::ref_block::validate_ref_block;

/// Construct a state-aware mempool validator from the live backends.
/// The closure clones the necessary `Arc<dyn KvBackend>` handles once;
/// every call reconstructs the per-store wrappers (cheap — they're
/// just typed views over the backends).
pub fn build(state: &StateBackends) -> TxValidatorFn {
    // Required (non-optional) backends.
    let accounts_be = state.accounts.clone();
    let witnesses_be = state.witnesses.clone();
    let votes_be = state.votes.clone();
    let delegation_be = state.delegation.clone();
    let delegated_resources_be = state.delegated_resources.clone();
    let dyn_props_be = state.dyn_props.clone();
    let proposals_be = state.proposals.clone();
    let name_index_be = state.name_index.clone();
    let id_index_be = state.id_index.clone();
    let asset_v1_be = state.asset_v1.clone();
    let asset_v2_be = state.asset_v2.clone();
    let contracts_be = state.contracts.clone();
    let abi_be = state.abi.clone();
    let exchange_v1_be = state.exchange_v1.clone();
    let exchange_v2_be = state.exchange_v2.clone();
    let market_orders_be = state.market_orders.clone();
    let nullifiers_be = state.nullifiers.clone();
    let merkle_trees_be: Option<Arc<dyn KvBackend>> = state.merkle_trees.clone();
    // The ref_block / chain-id replay gate also runs at mempool
    // admission so wallets get a fast, clear rejection instead of
    // their tx silently lingering until expiration. Optional so
    // tests with no block_index (the gate has no chain history to
    // compare against) skip the check.
    let block_index_be: Option<Arc<dyn KvBackend>> = state.block_index.clone();
    let dyn_props_for_ref_block = state.dyn_props.clone();

    Box::new(move |tx: &Transaction| -> Result<(), String> {
        let raw = tx.raw_data.as_ref().ok_or("transaction has no raw_data")?;
        if raw.contract.is_empty() {
            return Err("transaction has no contracts".into());
        }

        // Per-tx replay gate. Anchored at the current chain head
        // (`latest_block_header_number`) — at mempool admission
        // there's no "block being applied" so head is the right
        // reference frame. Skipped if no `block_index` is attached.
        if let Some(bi) = &block_index_be {
            let dp = DynamicPropertiesStore::new(dyn_props_for_ref_block.clone());
            let head_num = dp.latest_block_header_number().unwrap_or(0);
            if let Err(e) = validate_ref_block(raw, head_num, bi) {
                return Err(format!("ref_block: {e}"));
            }
        }

        // Build the actuator store handles once per call. Cheap —
        // every `*Store::new` is a single `Arc::clone`.
        let accounts = AccountStore::new(accounts_be.clone());
        let witnesses = WitnessStore::new(witnesses_be.clone());
        let votes = VotesStore::new(votes_be.clone());
        let delegation = DelegationStore::new(delegation_be.clone());
        let delegated_resources = DelegatedResourceStore::new(delegated_resources_be.clone());
        let dyn_props = DynamicPropertiesStore::new(dyn_props_be.clone());
        let proposals = ProposalStore::new(proposals_be.clone());
        let name_index = AccountIndexStore::new(name_index_be.clone());
        let id_index = AccountIdIndexStore::new(id_index_be.clone());
        let asset_v1 = AssetIssueStore::new(asset_v1_be.clone());
        let asset_v2 = AssetIssueV2Store::new(asset_v2_be.clone());
        let contracts = ContractStore::new(contracts_be.clone());
        let abi = AbiStore::new(abi_be.clone());
        let exchange_v1 = ExchangeStore::new(exchange_v1_be.clone());
        let exchange_v2 = ExchangeV2Store::new(exchange_v2_be.clone());
        let market_orders = MarketOrderStore::new(market_orders_be.clone());
        let nullifiers = NullifierStore::new(nullifiers_be.clone());
        let merkle_trees =
            merkle_trees_be.as_ref().map(|be| IncrementalMerkleTreeStore::new(be.clone()));

        let stores = ActuatorStores {
            accounts: &accounts,
            witnesses: &witnesses,
            votes: &votes,
            delegation: &delegation,
            delegated_resources: &delegated_resources,
            // Mempool admission only runs `validate_*`, which doesn't touch
            // the delegation index — the executor wires the real index on
            // the block-execution path.
            delegated_resource_account_index: None,
            dyn_props: &dyn_props,
            proposals: &proposals,
            name_index: &name_index,
            id_index: &id_index,
            asset_v1: &asset_v1,
            asset_v2: &asset_v2,
            contracts: &contracts,
            abi: &abi,
            exchange_v1: &exchange_v1,
            exchange_v2: &exchange_v2,
            market_orders: &market_orders,
            nullifiers: &nullifiers,
            merkle_trees: merkle_trees.as_ref(),
        };
        // `ActuatorTxCtx::default()` zeros the sighash; only the
        // shielded-transfer actuator consults it, and the executor
        // recomputes it before *execute* anyway. For mempool admission
        // a zero sighash means shielded txs will fail the precondition
        // check here — they'll be rejected with a clear error rather
        // than silently rotting in pending.
        let ctx = ActuatorTxCtx::default();

        // Multi-contract txs are rare on mainnet but possible —
        // validate every contract.
        for contract in &raw.contract {
            let ty = ContractType::try_from(contract.r#type)
                .map_err(|_| format!("unknown contract type {}", contract.r#type))?;
            let parameter = contract
                .parameter
                .as_ref()
                .ok_or("contract has no parameter")?;
            // Re-encode `Any` from prost-types to prost. The actuator
            // takes a `&Any` (prost type); the proto already produces
            // the matching shape.
            dispatch_validate(&stores, &ctx, ty, parameter).map_err(|e| e.to_string())?;
        }
        Ok(())
    })
}
