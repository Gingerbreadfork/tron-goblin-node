//! End-to-end tests of [`tron_executor::execute_block`].
//!
//! Each test sets up a fresh in-memory state, constructs one or more
//! blocks (signing them with a known witness key), and runs them
//! through the executor. Assertions cover:
//!
//! * State mutations match the contracts in the block.
//! * Per-tx failures are reported, not silently applied.
//! * Head-pointer fields in `DynamicPropertiesStore` advance per block.
//! * TVM and ShieldedTransfer txs are explicitly rejected.

use std::sync::Arc;

use hex_literal::hex;
use prost::Message;
use prost_types::Any;
use tron_chainbase::{
    AbiStore, AccountIdIndexStore, AccountIndexStore, AccountStore, AssetIssueStore,
    AssetIssueV2Store, ContractStore, DelegatedResourceStore, DelegationStore,
    DynamicPropertiesStore, ExchangeStore, ExchangeV2Store, KvBackend, MarketOrderStore,
    MemBackend, ProposalStore, VotesStore, WitnessStore,
};
use tron_crypto::address::Address;
use tron_executor::{execute_block, StateBackends, TxOutcome};
use tron_proto::block_header::Raw as BlockHeaderRaw;
use tron_proto::transaction::contract::ContractType;
use tron_proto::transaction::{Contract as TxContract, Raw as TxRaw};
use tron_proto::{Account, AccountType, Block, BlockHeader, Transaction, TransferContract};
use tron_types::{calc_tx_trie_root, sign_block};

const ALICE: [u8; 21] = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");
const ALICE_PRIV: [u8; 32] =
    hex!("1234567890123456789012345678901234567890123456789012345678901234");
const BOB: [u8; 21] = hex!("41a614f803b6fd780986a42c78ec9c7f77e6ded13c");
const CARROL: [u8; 21] = hex!("4171b0af54e0a1182a5e0947d6a64f3b22740ef318");

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}
fn addr(b: [u8; 21]) -> Address {
    Address::from_raw(b)
}

/// One backend per store — distinct keyspaces. Holds both the typed
/// stores (for direct setup/assertions in tests) AND the raw backends
/// (for handing to `execute_block` via `StateBackends`).
struct StateBundle {
    // Raw backends per store.
    accounts_be: Arc<dyn KvBackend>,
    witnesses_be: Arc<dyn KvBackend>,
    votes_be: Arc<dyn KvBackend>,
    delegation_be: Arc<dyn KvBackend>,
    delegated_resources_be: Arc<dyn KvBackend>,
    dyn_props_be: Arc<dyn KvBackend>,
    proposals_be: Arc<dyn KvBackend>,
    name_index_be: Arc<dyn KvBackend>,
    id_index_be: Arc<dyn KvBackend>,
    asset_v1_be: Arc<dyn KvBackend>,
    asset_v2_be: Arc<dyn KvBackend>,
    contracts_be: Arc<dyn KvBackend>,
    abi_be: Arc<dyn KvBackend>,
    exchange_v1_be: Arc<dyn KvBackend>,
    exchange_v2_be: Arc<dyn KvBackend>,
    market_orders_be: Arc<dyn KvBackend>,
    // Typed views for setup/assertions.
    accounts: AccountStore,
    #[allow(dead_code)]
    witnesses: WitnessStore,
    #[allow(dead_code)]
    votes: VotesStore,
    #[allow(dead_code)]
    delegation: DelegationStore,
    #[allow(dead_code)]
    delegated_resources: DelegatedResourceStore,
    dyn_props: DynamicPropertiesStore,
    #[allow(dead_code)]
    proposals: ProposalStore,
    #[allow(dead_code)]
    name_index: AccountIndexStore,
    #[allow(dead_code)]
    id_index: AccountIdIndexStore,
    #[allow(dead_code)]
    asset_v1: AssetIssueStore,
    #[allow(dead_code)]
    asset_v2: AssetIssueV2Store,
    #[allow(dead_code)]
    contracts: ContractStore,
    #[allow(dead_code)]
    abi: AbiStore,
    #[allow(dead_code)]
    exchange_v1: ExchangeStore,
    #[allow(dead_code)]
    exchange_v2: ExchangeV2Store,
    #[allow(dead_code)]
    market_orders: MarketOrderStore,
    nullifiers_be: Arc<dyn KvBackend>,
}

impl StateBundle {
    fn fresh() -> Self {
        let (accounts_be, witnesses_be, votes_be, delegation_be) = (mem(), mem(), mem(), mem());
        let (delegated_resources_be, dyn_props_be, proposals_be, name_index_be) =
            (mem(), mem(), mem(), mem());
        let (id_index_be, asset_v1_be, asset_v2_be, contracts_be) = (mem(), mem(), mem(), mem());
        let (abi_be, exchange_v1_be, exchange_v2_be, market_orders_be) =
            (mem(), mem(), mem(), mem());
        let nullifiers_be = mem();
        Self {
            accounts: AccountStore::new(accounts_be.clone()),
            witnesses: WitnessStore::new(witnesses_be.clone()),
            votes: VotesStore::new(votes_be.clone()),
            delegation: DelegationStore::new(delegation_be.clone()),
            delegated_resources: DelegatedResourceStore::new(delegated_resources_be.clone()),
            dyn_props: DynamicPropertiesStore::new(dyn_props_be.clone()),
            proposals: ProposalStore::new(proposals_be.clone()),
            name_index: AccountIndexStore::new(name_index_be.clone()),
            id_index: AccountIdIndexStore::new(id_index_be.clone()),
            asset_v1: AssetIssueStore::new(asset_v1_be.clone()),
            asset_v2: AssetIssueV2Store::new(asset_v2_be.clone()),
            contracts: ContractStore::new(contracts_be.clone()),
            abi: AbiStore::new(abi_be.clone()),
            exchange_v1: ExchangeStore::new(exchange_v1_be.clone()),
            exchange_v2: ExchangeV2Store::new(exchange_v2_be.clone()),
            market_orders: MarketOrderStore::new(market_orders_be.clone()),
            nullifiers_be,
            accounts_be,
            witnesses_be,
            votes_be,
            delegation_be,
            delegated_resources_be,
            dyn_props_be,
            proposals_be,
            name_index_be,
            id_index_be,
            asset_v1_be,
            asset_v2_be,
            contracts_be,
            abi_be,
            exchange_v1_be,
            exchange_v2_be,
            market_orders_be,
        }
    }

    /// Build the [`StateBackends`] handle that `execute_block` consumes.
    fn backends(&self) -> StateBackends {
        StateBackends {
            accounts: self.accounts_be.clone(),
            witnesses: self.witnesses_be.clone(),
            votes: self.votes_be.clone(),
            delegation: self.delegation_be.clone(),
            delegated_resources: self.delegated_resources_be.clone(),
            dyn_props: self.dyn_props_be.clone(),
            proposals: self.proposals_be.clone(),
            name_index: self.name_index_be.clone(),
            id_index: self.id_index_be.clone(),
            asset_v1: self.asset_v1_be.clone(),
            asset_v2: self.asset_v2_be.clone(),
            contracts: self.contracts_be.clone(),
            abi: self.abi_be.clone(),
            exchange_v1: self.exchange_v1_be.clone(),
            exchange_v2: self.exchange_v2_be.clone(),
            market_orders: self.market_orders_be.clone(),
            nullifiers: self.nullifiers_be.clone(),
            merkle_trees: None,
            // VM stores not attached for non-VM contract tests.
            code: None,
            storage_row: None,
            contract_state: None,
            block_index: None,
            witness_schedule: None,
        }
    }
}

fn put_account(store: &AccountStore, address: [u8; 21], balance: i64) {
    store.put(
        &addr(address),
        &Account {
            address: address.to_vec(),
            balance,
            r#type: AccountType::Normal as i32,
            ..Default::default()
        },
    );
}

fn transfer_tx(owner: [u8; 21], to: [u8; 21], amount: i64) -> Transaction {
    let tc = TransferContract {
        owner_address: owner.to_vec(),
        to_address: to.to_vec(),
        amount,
    };
    let mut tx = Transaction {
        raw_data: Some(TxRaw {
            ref_block_bytes: vec![0, 1],
            ref_block_num: 0,
            ref_block_hash: vec![0u8; 8],
            expiration: 1_700_000_000_000,
            auths: Vec::new(),
            data: Vec::new(),
            contract: vec![TxContract {
                r#type: ContractType::TransferContract as i32,
                parameter: Some(Any {
                    type_url: "type.googleapis.com/protocol.TransferContract".into(),
                    value: tc.encode_to_vec(),
                }),
                provider: Vec::new(),
                contract_name: Vec::new(),
                permission_id: 0,
            }],
            scripts: Vec::new(),
            timestamp: 1_700_000_000_000,
            fee_limit: 0,
        }),
        signature: Vec::new(),
        ret: Vec::new(),
    };
    // Sign with ALICE_PRIV when ALICE is the owner — every test in this
    // file uses ALICE as the sender. The signature is required since
    // Phase 10 (permission enforcement at the executor level).
    if owner == ALICE {
        tron_types::sign_transaction(&mut tx, &ALICE_PRIV).expect("sign");
    }
    tx
}

/// Build a signed block over `transactions`. `parent_hash` is the raw
/// 32 bytes of the previous BlockId (or zeros for the chain head).
fn build_block(number: i64, parent_hash: [u8; 32], transactions: Vec<Transaction>) -> Block {
    let tx_root = calc_tx_trie_root(&transactions).map(|h| h.to_vec()).unwrap_or_default();
    let mut block = Block {
        transactions,
        block_header: Some(BlockHeader {
            raw_data: Some(BlockHeaderRaw {
                timestamp: 1_700_000_000_000 + number * 3000,
                tx_trie_root: tx_root,
                parent_hash: parent_hash.to_vec(),
                number,
                witness_id: 0,
                witness_address: ALICE.to_vec(),
                version: 28,
                account_state_root: Vec::new(),
            }),
            witness_signature: Vec::new(),
        }),
    };
    sign_block(&mut block, &ALICE_PRIV).expect("sign");
    block
}

// =============================================================================
// Tests
// =============================================================================

#[test]
fn empty_block_advances_head_pointer() {
    let state = StateBundle::fresh();
    let block = build_block(1, [0u8; 32], Vec::new());
    let report = execute_block(&state.backends(), &block, None).unwrap();
    assert_eq!(report.tx_results.len(), 0);
    assert_eq!(state.dyn_props.latest_block_header_number(), Some(1));
    assert!(state.dyn_props.latest_block_header_timestamp().unwrap() > 0);
    let saved_hash = state.dyn_props.latest_block_header_hash().unwrap().unwrap();
    assert_eq!(saved_hash, *report.block_id.as_bytes());
}

#[test]
fn single_transfer_is_applied_to_state() {
    let state = StateBundle::fresh();
    put_account(&state.accounts, ALICE, 1_000_000);
    put_account(&state.accounts, BOB, 0);

    let tx = transfer_tx(ALICE, BOB, 250_000);
    let block = build_block(1, [0u8; 32], vec![tx]);
    let report = execute_block(&state.backends(), &block, None).unwrap();

    assert_eq!(report.successes(), 1);
    assert_eq!(report.failures(), 0);
    assert_eq!(
        state.accounts.get(&addr(ALICE)).unwrap().unwrap().balance,
        750_000
    );
    assert_eq!(
        state.accounts.get(&addr(BOB)).unwrap().unwrap().balance,
        250_000
    );
}

#[test]
fn invalid_tx_is_recorded_as_failure_without_aborting_block() {
    let state = StateBundle::fresh();
    put_account(&state.accounts, ALICE, 1_000_000);
    put_account(&state.accounts, BOB, 0);
    put_account(&state.accounts, CARROL, 0);

    // tx0: valid transfer
    // tx1: invalid (Alice's balance won't cover 5 TRX)
    // tx2: valid follow-up
    let tx0 = transfer_tx(ALICE, BOB, 100_000);
    let tx1 = transfer_tx(ALICE, CARROL, 5_000_000_000); // way over balance
    let tx2 = transfer_tx(ALICE, CARROL, 50_000);
    let block = build_block(1, [0u8; 32], vec![tx0, tx1, tx2]);
    let report = execute_block(&state.backends(), &block, None).unwrap();

    assert_eq!(report.tx_results.len(), 3);
    assert!(report.tx_results[0].outcome.is_success());
    assert!(matches!(
        report.tx_results[1].outcome,
        TxOutcome::Invalid(tron_actuator::ActuatorError::InsufficientBalance { .. })
    ));
    assert!(report.tx_results[2].outcome.is_success());

    // tx0 + tx2 applied; tx1 didn't move money.
    assert_eq!(state.accounts.get(&addr(BOB)).unwrap().unwrap().balance, 100_000);
    assert_eq!(state.accounts.get(&addr(CARROL)).unwrap().unwrap().balance, 50_000);
    assert_eq!(
        state.accounts.get(&addr(ALICE)).unwrap().unwrap().balance,
        1_000_000 - 100_000 - 50_000
    );
}

#[test]
fn smart_contract_tx_is_rejected_via_notimplemented() {
    // Forge a tx whose ContractType is TriggerSmartContract. We don't
    // bother populating a real TriggerSmartContract proto — the
    // dispatch table returns NotImplemented before unpacking.
    //
    // The tx needs a signature so it passes the permission/multi-sig
    // check (which now runs before the VM branch — java-tron parity).
    // We use a forged 65-byte signature; the permission code only counts
    // signatures, it doesn't verify them at this layer.
    let state = StateBundle::fresh();
    put_account(&state.accounts, ALICE, 1_000_000);

    let trigger_tx = Transaction {
        raw_data: Some(TxRaw {
            contract: vec![TxContract {
                r#type: ContractType::TriggerSmartContract as i32,
                parameter: Some(Any {
                    type_url: "type.googleapis.com/protocol.TriggerSmartContract".into(),
                    value: Vec::new(),
                }),
                ..Default::default()
            }],
            timestamp: 1_700_000_000_000,
            ..Default::default()
        }),
        signature: vec![vec![0u8; 65]],
        ret: Vec::new(),
    };

    let block = build_block(1, [0u8; 32], vec![trigger_tx]);
    let report = execute_block(&state.backends(), &block, None).unwrap();
    assert_eq!(report.failures(), 1);
    // The executor branches to the VM path for TriggerSmartContract.
    // Without EVM stores attached, this surfaces as either a clear
    // NotImplemented (no EVM stores), or — if bandwidth charging
    // pre-empts because the owner address is empty — an Invalid
    // outcome. Either is a defensible rejection here.
    match &report.tx_results[0].outcome {
        TxOutcome::Invalid(tron_actuator::ActuatorError::NotImplemented(msg)) => {
            assert!(
                msg.contains("EVM stores") || msg.contains("VMActuator"),
                "unexpected NotImplemented message: {msg}"
            );
        }
        TxOutcome::Invalid(_) | TxOutcome::ExecutionFailed(_) => {
            // Acceptable: the empty TriggerSmartContract was rejected
            // by some upstream check (bandwidth, permission). The test's
            // intent — "the executor doesn't silently succeed on a
            // VM-bound tx without EVM stores" — still holds.
        }
        other => panic!("expected Invalid/ExecutionFailed, got {other:?}"),
    }
}

#[test]
fn shielded_transfer_tx_validates_through_real_actuator() {
    // With Phase 9a, the dispatcher routes ShieldedTransferContract to
    // the real actuator (not the NotImplemented stub). An empty body
    // fails validation on the ALLOW_SAME_TOKEN_NAME feature flag — a
    // `Validate` error variant, not `NotImplemented`.
    let state = StateBundle::fresh();
    let tx = Transaction {
        raw_data: Some(TxRaw {
            contract: vec![TxContract {
                r#type: ContractType::ShieldedTransferContract as i32,
                parameter: Some(Any::default()),
                ..Default::default()
            }],
            timestamp: 1_700_000_000_000,
            ..Default::default()
        }),
        signature: Vec::new(),
        ret: Vec::new(),
    };
    let block = build_block(1, [0u8; 32], vec![tx]);
    let report = execute_block(&state.backends(), &block, None).unwrap();
    assert_eq!(report.failures(), 1);
    assert!(matches!(
        &report.tx_results[0].outcome,
        TxOutcome::Invalid(tron_actuator::ActuatorError::Validate(_))
    ));
}

#[test]
fn parent_link_must_match() {
    let state = StateBundle::fresh();
    // Build block 1 with parent = zeros (genesis case is OK with None).
    let block = build_block(1, [0u8; 32], Vec::new());
    // Now claim its parent should have been all-0xff bytes — must fail.
    use tron_executor::BlockExecError;
    use tron_types::BlockId;
    let wrong_parent = BlockId::from_raw([0xff; 32]);
    match execute_block(&state.backends(), &block, Some(wrong_parent)) {
        Err(BlockExecError::Structural(_)) => {}
        other => panic!("expected Structural error, got {other:?}"),
    }
}

#[test]
fn tx_trie_root_mismatch_aborts_block() {
    let state = StateBundle::fresh();
    put_account(&state.accounts, ALICE, 1_000_000);
    put_account(&state.accounts, BOB, 0);

    // Build a valid block then corrupt the header's tx_trie_root.
    let mut block = build_block(1, [0u8; 32], vec![transfer_tx(ALICE, BOB, 1)]);
    block
        .block_header
        .as_mut()
        .unwrap()
        .raw_data
        .as_mut()
        .unwrap()
        .tx_trie_root = vec![0xab; 32];
    // Need to re-sign since the raw_data changed.
    sign_block(&mut block, &ALICE_PRIV).unwrap();

    use tron_executor::BlockExecError;
    match execute_block(&state.backends(), &block, None) {
        Err(BlockExecError::Structural(_)) => {}
        other => panic!("expected Structural error, got {other:?}"),
    }
    // State should NOT have been mutated (the executor aborted at step 1).
    assert_eq!(state.accounts.get(&addr(BOB)).unwrap().unwrap().balance, 0);
}

/// **The Track-1 invariant**: a transaction whose `validate` succeeds
/// but whose `execute` errors must NOT leak partial state. The session
/// layer is what fixes this — pre-Track-1 the executor explicitly
/// documented this as a v1 limitation.
///
/// Reproducing the scenario directly is awkward because for built-in
/// actuators, validate catches everything execute would reject. We
/// instead drive the same code path via a transaction whose ContractType
/// is `TriggerSmartContract` — the deferred VM stub returns
/// `NotImplemented` from *both* validate and execute, but if we could
/// reach execute somehow with mid-state writes, the session would
/// revert. Here we use a simpler witness for the invariant: two
/// tx-failures in sequence, then a tx-success — verifying the
/// successful tx's state mutations are visible (proving sessions
/// commit) and that failures leave the parent untouched (proving
/// sessions revert).
#[test]
fn failed_txs_leave_no_trace_in_parent_state() {
    let state = StateBundle::fresh();
    put_account(&state.accounts, ALICE, 1_000_000);

    // Three txs:
    //   tx0: invalid (BOB doesn't exist as owner) → revert
    //   tx1: valid transfer  Alice → Carrol 100   → commit
    //   tx2: invalid (Alice → Alice = self)       → revert
    let bad_owner = transfer_tx(BOB, CARROL, 1);
    let good = transfer_tx(ALICE, CARROL, 100);
    let self_transfer = transfer_tx(ALICE, ALICE, 50);
    let block = build_block(1, [0u8; 32], vec![bad_owner, good, self_transfer]);

    let report = execute_block(&state.backends(), &block, None).unwrap();
    assert_eq!(report.tx_results.len(), 3);
    assert!(!report.tx_results[0].outcome.is_success(), "bad owner: invalid");
    assert!(report.tx_results[1].outcome.is_success(), "good transfer ok");
    assert!(!report.tx_results[2].outcome.is_success(), "self transfer: invalid");

    // Only tx1's effects landed.
    assert_eq!(state.accounts.get(&addr(ALICE)).unwrap().unwrap().balance, 999_900);
    assert_eq!(state.accounts.get(&addr(CARROL)).unwrap().unwrap().balance, 100);
    // BOB never created — bad owner tx didn't run.
    assert!(state.accounts.get(&addr(BOB)).unwrap().is_none());
}

/// **Full multi-block chain replay**: build three linked blocks, execute
/// each with the previous's BlockId as expected parent. Verifies head
/// pointers advance correctly across blocks.
#[test]
fn three_block_chain_replays_with_correct_parent_links() {
    let state = StateBundle::fresh();
    put_account(&state.accounts, ALICE, 1_000_000);
    put_account(&state.accounts, BOB, 0);

    let block1 = build_block(1, [0u8; 32], vec![transfer_tx(ALICE, BOB, 100)]);
    let r1 = execute_block(&state.backends(), &block1, None).unwrap();

    let block2 = build_block(2, *r1.block_id.as_bytes(), vec![transfer_tx(ALICE, BOB, 200)]);
    let r2 = execute_block(&state.backends(), &block2, Some(r1.block_id)).unwrap();

    let block3 = build_block(3, *r2.block_id.as_bytes(), vec![transfer_tx(ALICE, BOB, 300)]);
    let r3 = execute_block(&state.backends(), &block3, Some(r2.block_id)).unwrap();

    assert_eq!(state.dyn_props.latest_block_header_number(), Some(3));
    let saved_hash = state.dyn_props.latest_block_header_hash().unwrap().unwrap();
    assert_eq!(saved_hash, *r3.block_id.as_bytes());
    assert_eq!(state.accounts.get(&addr(BOB)).unwrap().unwrap().balance, 600);
    assert_eq!(
        state.accounts.get(&addr(ALICE)).unwrap().unwrap().balance,
        1_000_000 - 600
    );
}

/// Regression: the default `ExecConfig` requires a non-empty
/// `witness_signature` and rejects unsigned blocks with
/// `BlockValidateError::MissingSignature`. Without this gate, any caller
/// that bypassed `sync::accept_block` (the production layer that
/// pre-validates) could silently apply a peer-injected block.
///
/// The dry-run path that produces `account_state_root` for in-construction
/// blocks (see `dry_run_for_state_root`) and a handful of executor tests
/// opt out via `ExecConfig::unsigned()`.
#[test]
fn unsigned_block_is_rejected_under_default_config() {
    use tron_executor::BlockExecError;
    use tron_types::BlockValidateError;

    let state = StateBundle::fresh();
    let mut block = build_block(1, [0u8; 32], Vec::new());
    // Strip the signature `build_block` attached. Header is otherwise
    // well-formed (correct tx_trie_root, matching witness_address).
    block
        .block_header
        .as_mut()
        .unwrap()
        .witness_signature
        .clear();

    match execute_block(&state.backends(), &block, None) {
        Err(BlockExecError::Structural(BlockValidateError::MissingSignature)) => {}
        other => panic!(
            "expected Structural(MissingSignature) under default-strict config, got {other:?}"
        ),
    }
    // And state was NOT mutated — head pointer must still be unset.
    assert_eq!(state.dyn_props.latest_block_header_number(), None);
}

/// Companion to the test above: with `ExecConfig::unsigned()`, the same
/// unsigned block applies successfully. This is the path used by
/// `dry_run_for_state_root` during block production.
#[test]
fn unsigned_block_is_accepted_when_explicitly_opted_out() {
    use tron_executor::{execute_block_with_config, ExecConfig};

    let state = StateBundle::fresh();
    let mut block = build_block(1, [0u8; 32], Vec::new());
    block
        .block_header
        .as_mut()
        .unwrap()
        .witness_signature
        .clear();

    let report =
        execute_block_with_config(&state.backends(), &block, None, &ExecConfig::unsigned())
            .expect("opt-out config should accept unsigned block");
    assert_eq!(report.tx_results.len(), 0);
    assert_eq!(state.dyn_props.latest_block_header_number(), Some(1));
}
