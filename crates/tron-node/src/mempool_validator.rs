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
    KvBackend, MarketAccountStore, MarketOrderStore, NullifierStore, ProposalStore, SessionBackend,
    VotesStore, WitnessStore,
};
use tron_executor::{charge_flat_fee, StateBackends};
use tron_mempool::{TxValidatorFn, MAXIMUM_TIME_UNTIL_EXPIRATION_MS};
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
    let market_account_be = state.market_account.clone();
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
        // java-tron `Manager.processTransaction` (Manager.java:1522) rejects any
        // tx whose contract list size is not exactly 1
        // (`ContractSizeNotEqualToOneException`). Enforcing it here keeps us from
        // admitting and relaying a multi- or zero-contract tx that every peer
        // rejects on receive.
        if raw.contract.len() != 1 {
            return Err(format!(
                "contract size should be exactly 1, actual: {}",
                raw.contract.len()
            ));
        }

        // Head-block-time-relative expiration window, matching java-tron
        // `Manager.validateCommon` (Manager.java:835-841): reject when
        // `expiration <= headBlockTime` (expired) or
        // `expiration > headBlockTime + MAXIMUM_TIME_UNTIL_EXPIRATION` (too far
        // future). The stateless mempool already enforces this window against
        // wall-clock `now`; here it is re-checked against the committed head
        // timestamp — the exact frame a peer uses on receive — so a node whose
        // head lags wall-clock (catching up after downtime) admits the same
        // set of txs a synced peer would. `expiration == 0` is "unset" and
        // skips the check, mirroring java treating only positive expirations.
        {
            let dp = DynamicPropertiesStore::new(dyn_props_for_ref_block.clone());
            if let Some(head_time) = dp.latest_block_header_timestamp() {
                let expiration = raw.expiration;
                if expiration > 0 {
                    if expiration <= head_time {
                        return Err(format!(
                            "expiration {expiration} <= head block time {head_time}"
                        ));
                    }
                    if expiration > head_time + MAXIMUM_TIME_UNTIL_EXPIRATION_MS {
                        return Err(format!(
                            "expiration {expiration} > head block time {head_time} + {MAXIMUM_TIME_UNTIL_EXPIRATION_MS}"
                        ));
                    }
                }
            }
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

        // Replay java's pre-actuator flat-fee debits on an isolated overlay.
        // `Manager.processTransaction` charges `consumeMultiSignFee` then
        // `consumeMemoFee` to the contract owner BEFORE the actuator validates,
        // so the actuator's balance check sees the reduced balance. Admission
        // must do the same, or it admits + relays a tx every peer rejects with
        // `AccountResourceInsufficientException` — e.g. a memo'd transfer whose
        // owner covers `amount` but not `amount + memo_fee`. The charge runs on
        // throwaway `SessionBackend` overlays of the accounts + dyn_props
        // backends, so the debit (and the blackhole/burn write) never touch
        // committed state. Admission-only: the executor already charges these on
        // the block-execution path, so there is no consensus impact.
        let accounts_overlay: Arc<dyn KvBackend> =
            Arc::new(SessionBackend::new(accounts_be.clone()));
        let dyn_props_overlay: Arc<dyn KvBackend> =
            Arc::new(SessionBackend::new(dyn_props_be.clone()));
        let accounts = AccountStore::new(accounts_overlay);
        let dyn_props = DynamicPropertiesStore::new(dyn_props_overlay);
        {
            // Exactly one contract (enforced above), matching java charging the
            // flat fees per-contract before `trace.exec()`.
            let contract0 = &raw.contract[0];
            let ty0 = ContractType::try_from(contract0.r#type)
                .map_err(|_| format!("unknown contract type {}", contract0.r#type))?;
            // `consumeMultiSignFee` — a tx with more than one signature pays it.
            if tx.signature.len() > 1 {
                let fee = dyn_props.multi_sign_fee();
                if fee > 0 {
                    charge_flat_fee(&accounts, &dyn_props, contract0, ty0, fee)
                        .map_err(|e| format!("multi-sign fee: {e}"))?;
                }
            }
            // `consumeMemoFee` — a tx carrying a memo (`raw.data`) pays it when
            // the committee memo fee is set.
            if !raw.data.is_empty() {
                let fee = dyn_props.memo_fee();
                if fee > 0 {
                    charge_flat_fee(&accounts, &dyn_props, contract0, ty0, fee)
                        .map_err(|e| format!("memo fee: {e}"))?;
                }
            }
        }

        // Build the remaining actuator store handles once per call. Cheap —
        // every `*Store::new` is a single `Arc::clone`.
        let witnesses = WitnessStore::new(witnesses_be.clone());
        let votes = VotesStore::new(votes_be.clone());
        let delegation = DelegationStore::new(delegation_be.clone());
        let delegated_resources = DelegatedResourceStore::new(delegated_resources_be.clone());
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
        let market_account = MarketAccountStore::new(market_account_be.clone());
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
            market_account: &market_account,
            nullifiers: &nullifiers,
            merkle_trees: merkle_trees.as_ref(),
            // Admission checks never reach legacy-reward settlement depth.
            reward_vi: None,
        };
        // `ActuatorTxCtx::default()` zeros the sighash; only the
        // shielded-transfer actuator consults it, and the executor
        // recomputes it before *execute* anyway. For mempool admission
        // a zero sighash means shielded txs will fail the precondition
        // check here — they'll be rejected with a clear error rather
        // than silently rotting in pending.
        let ctx = ActuatorTxCtx::default();

        // Exactly one contract per tx (enforced above, matching java).
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

#[cfg(test)]
mod tests {
    use super::build;
    use prost::Message as _;
    use std::sync::Arc;
    use tron_chainbase::{AccountStore, DynamicPropertiesStore, KvBackend, MemBackend};
    use tron_crypto::address::Address;
    use tron_executor::StateBackends;
    use tron_proto::transaction::{contract::ContractType, Contract, Raw};
    use tron_proto::{Account, Transaction, TransferContract};

    fn mem() -> Arc<dyn KvBackend> {
        Arc::new(MemBackend::new())
    }

    /// All-in-memory backends. `block_index` is `None` so the admission
    /// ref_block (tapos) gate is skipped — this test exercises the flat-fee +
    /// actuator path, not tapos.
    fn fresh_state() -> StateBackends {
        StateBackends {
            accounts: mem(),
            witnesses: mem(),
            votes: mem(),
            delegation: mem(),
            delegated_resources: mem(),
            delegated_resource_account_index: None,
            dyn_props: mem(),
            proposals: mem(),
            name_index: mem(),
            id_index: mem(),
            asset_v1: mem(),
            asset_v2: mem(),
            contracts: mem(),
            abi: mem(),
            exchange_v1: mem(),
            exchange_v2: mem(),
            market_orders: mem(),
            market_account: mem(),
            nullifiers: mem(),
            merkle_trees: None,
            code: None,
            storage_row: None,
            contract_state: None,
            block_index: None,
            witness_schedule: None,
            reward_vi: None,
        }
    }

    fn addr(b: u8) -> [u8; 21] {
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[1..].fill(b);
        a
    }

    /// A single-signature `TransferContract` tx; attaches `memo` to `raw.data`
    /// when non-empty.
    fn transfer_tx(owner: [u8; 21], to: [u8; 21], amount: i64, memo: &[u8]) -> Transaction {
        let tc = TransferContract {
            owner_address: owner.to_vec(),
            to_address: to.to_vec(),
            amount,
        };
        let contract = Contract {
            r#type: ContractType::TransferContract as i32,
            parameter: Some(prost_types::Any {
                type_url: "type.googleapis.com/protocol.TransferContract".into(),
                value: tc.encode_to_vec(),
            }),
            ..Default::default()
        };
        Transaction {
            raw_data: Some(Raw {
                contract: vec![contract],
                data: memo.to_vec(),
                ..Default::default()
            }),
            signature: vec![vec![0u8; 65]], // single (dummy) signature
            ret: vec![],
            unparsed_field10: None,
        }
    }

    /// java charges `consumeMemoFee` (1 TRX on mainnet) to the owner BEFORE the
    /// actuator validates, so an owner that covers `amount` but not
    /// `amount + memo_fee` is rejected. Admission must match — otherwise we
    /// relay a tx every peer rejects with `AccountResourceInsufficientException`.
    #[test]
    fn memo_fee_pushing_owner_below_amount_is_rejected_at_admission() {
        let state = fresh_state();
        let owner = addr(0x11);
        let to = addr(0x22);
        let amount = 4_567_888i64;
        let memo_fee = 1_000_000i64;
        // Covers `amount` (the transfer fee is 0), but `balance - memo_fee`
        // (= 4_000_000) is below `amount`.
        let balance = 5_000_000i64;

        let accounts = AccountStore::new(state.accounts.clone());
        accounts
            .put(
                &Address::from_raw(owner),
                &Account { address: owner.to_vec(), balance, ..Default::default() },
            )
            .unwrap();
        // `to` exists, so the actuator adds no create-account fee.
        accounts
            .put(
                &Address::from_raw(to),
                &Account { address: to.to_vec(), ..Default::default() },
            )
            .unwrap();
        DynamicPropertiesStore::new(state.dyn_props.clone()).put_long(b"MEMO_FEE", memo_fee);

        let validate = build(&state);

        // With a memo: the 1 TRX fee is debited first, so the actuator's
        // balance check fails → reject.
        let err = validate(&transfer_tx(owner, to, amount, b"memo note")).unwrap_err();
        assert!(
            err.contains("insufficient balance"),
            "memo'd transfer over the post-fee balance must be rejected, got: {err}"
        );

        // Without a memo: no flat fee, balance covers `amount` → admitted.
        validate(&transfer_tx(owner, to, amount, b""))
            .expect("the same transfer without a memo is admitted");

        // With a memo AND enough to cover `amount + memo_fee` → admitted.
        accounts
            .put(
                &Address::from_raw(owner),
                &Account {
                    address: owner.to_vec(),
                    balance: amount + memo_fee + 1,
                    ..Default::default()
                },
            )
            .unwrap();
        validate(&transfer_tx(owner, to, amount, b"memo note"))
            .expect("a memo'd transfer with balance >= amount + memo_fee is admitted");
    }
}
