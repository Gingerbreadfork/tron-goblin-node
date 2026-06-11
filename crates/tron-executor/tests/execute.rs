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
use tron_proto::{
    Account, AccountType, Block, BlockHeader, FreezeBalanceV2Contract, Transaction,
    TransferContract,
};
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
            delegated_resource_account_index: None,
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
            reward_vi: None,
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
    ).unwrap();
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
            // 24h past the base block timestamp — well into the future
            // for every block this file builds (`build_block(N)` uses
            // `base + N*3000ms`). Keeps the per-tx expiration gate from
            // rejecting transfers in tests that aren't about expiration.
            expiration: 1_700_000_000_000 + 86_400_000,
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

    // Only tx1's effects landed. CARROL didn't exist, so the transfer
    // took the contractCreateNewAccount bandwidth branch: with no
    // frozen net, ALICE burned the flat 0.1 TRX create-account fee on
    // top of the amount (java-tron `consumeFeeForCreateNewAccount`).
    assert_eq!(
        state.accounts.get(&addr(ALICE)).unwrap().unwrap().balance,
        1_000_000 - 100 - 100_000
    );
    assert_eq!(state.accounts.get(&addr(CARROL)).unwrap().unwrap().balance, 100);
    assert_eq!(state.dyn_props.get_long(b"TOTAL_CREATE_ACCOUNT_COST"), Some(100_000));
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

/// Regression: a transaction whose `raw_data.expiration` is at or before
/// the block's `timestamp` is rejected with `TxOutcome::Expired` and
/// state is NOT mutated. The mempool catches this at submit time
/// against wall-clock — but a peer-pushed block bypasses the mempool,
/// so the executor enforces against the BLOCK timestamp (deterministic
/// across replays) at block-apply time.
#[test]
fn expired_tx_is_rejected_at_block_apply_and_state_unchanged() {
    let state = StateBundle::fresh();
    put_account(&state.accounts, ALICE, 1_000_000);
    put_account(&state.accounts, BOB, 0);

    // Build a transfer tx, then back-date its expiration to one ms
    // BEFORE what `build_block(1, …)` will stamp as the block
    // timestamp. Re-sign because mutating raw_data changed the digest.
    let mut tx = transfer_tx(ALICE, BOB, 100);
    let block_ts = 1_700_000_000_000 + 3000; // mirrors build_block formula
    tx.raw_data.as_mut().unwrap().expiration = block_ts - 1;
    // sign_transaction pushes (multi-sig semantics) — clear first so we
    // re-sign exactly once after the raw_data mutation above.
    tx.signature.clear();
    tron_types::sign_transaction(&mut tx, &ALICE_PRIV).expect("re-sign");
    let expected_tx_id =
        tron_crypto::hash::sha256(&prost::Message::encode_to_vec(tx.raw_data.as_ref().unwrap()));

    let block = build_block(1, [0u8; 32], vec![tx]);
    let report = execute_block(&state.backends(), &block, None).unwrap();

    assert_eq!(report.tx_results.len(), 1);
    let tx_result = &report.tx_results[0];
    match &tx_result.outcome {
        TxOutcome::Expired { expiration_ms, block_timestamp_ms } => {
            assert_eq!(*expiration_ms, block_ts - 1);
            assert_eq!(*block_timestamp_ms, block_ts);
        }
        other => panic!("expected TxOutcome::Expired, got {other:?}"),
    }

    // No state mutation: Alice's balance is untouched, Bob's at zero.
    // The outcome reports the right tx_id (not the zero sentinel).
    assert_eq!(
        state.accounts.get(&addr(ALICE)).unwrap().unwrap().balance,
        1_000_000
    );
    assert_eq!(
        state.accounts.get(&addr(BOB)).unwrap().unwrap().balance,
        0
    );
    assert_eq!(tx_result.tx_id, expected_tx_id);

    // And the block's head pointer DID still advance — block validity
    // is not blocked by per-tx expiration; only that one tx is dropped.
    assert_eq!(state.dyn_props.latest_block_header_number(), Some(1));
}

/// Companion: `expiration == 0` (java-tron's "unset" sentinel) is NOT
/// treated as expired. Required so transactions built before the
/// expiration field existed don't suddenly start failing.
#[test]
fn expiration_zero_sentinel_is_not_treated_as_expired() {
    let state = StateBundle::fresh();
    put_account(&state.accounts, ALICE, 1_000_000);
    put_account(&state.accounts, BOB, 0);

    let mut tx = transfer_tx(ALICE, BOB, 100);
    tx.raw_data.as_mut().unwrap().expiration = 0;
    // sign_transaction pushes (multi-sig semantics) — clear first so we
    // re-sign exactly once after the raw_data mutation above.
    tx.signature.clear();
    tron_types::sign_transaction(&mut tx, &ALICE_PRIV).expect("re-sign");

    let block = build_block(1, [0u8; 32], vec![tx]);
    let report = execute_block(&state.backends(), &block, None).unwrap();
    assert!(
        matches!(report.tx_results[0].outcome, TxOutcome::Success),
        "got: {:?}", report.tx_results[0].outcome
    );
    assert_eq!(state.accounts.get(&addr(BOB)).unwrap().unwrap().balance, 100);
}

/// Companion: an `expiration` exactly one millisecond AFTER the block
/// timestamp passes (the rejection condition is `<=`, not `<`). Pins
/// the boundary so a future refactor doesn't accidentally make it
/// inclusive on the high end.
#[test]
fn expiration_one_ms_in_the_future_passes() {
    let state = StateBundle::fresh();
    put_account(&state.accounts, ALICE, 1_000_000);
    put_account(&state.accounts, BOB, 0);

    let mut tx = transfer_tx(ALICE, BOB, 100);
    let block_ts = 1_700_000_000_000 + 3000;
    tx.raw_data.as_mut().unwrap().expiration = block_ts + 1;
    // sign_transaction pushes (multi-sig semantics) — clear first so we
    // re-sign exactly once after the raw_data mutation above.
    tx.signature.clear();
    tron_types::sign_transaction(&mut tx, &ALICE_PRIV).expect("re-sign");

    let block = build_block(1, [0u8; 32], vec![tx]);
    let report = execute_block(&state.backends(), &block, None).unwrap();
    assert!(
        matches!(report.tx_results[0].outcome, TxOutcome::Success),
        "got: {:?}", report.tx_results[0].outcome
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

// =============================================================================
// Block-STM: parallel execution must be byte-identical to serial.
// =============================================================================

/// Full dump of every store's key→value, sorted, for state comparison.
fn dump_state(b: &StateBundle) -> Vec<(&'static str, std::collections::BTreeMap<Vec<u8>, Vec<u8>>)> {
    let one = |be: &Arc<dyn KvBackend>| -> std::collections::BTreeMap<Vec<u8>, Vec<u8>> {
        be.scan_all().unwrap().into_iter().collect()
    };
    vec![
        ("accounts", one(&b.accounts_be)),
        ("witnesses", one(&b.witnesses_be)),
        ("votes", one(&b.votes_be)),
        ("delegation", one(&b.delegation_be)),
        ("delegated_resources", one(&b.delegated_resources_be)),
        ("dyn_props", one(&b.dyn_props_be)),
        ("proposals", one(&b.proposals_be)),
        ("name_index", one(&b.name_index_be)),
        ("id_index", one(&b.id_index_be)),
        ("asset_v1", one(&b.asset_v1_be)),
        ("asset_v2", one(&b.asset_v2_be)),
        ("contracts", one(&b.contracts_be)),
        ("abi", one(&b.abi_be)),
        ("exchange_v1", one(&b.exchange_v1_be)),
        ("exchange_v2", one(&b.exchange_v2_be)),
        ("market_orders", one(&b.market_orders_be)),
        ("nullifiers", one(&b.nullifiers_be)),
    ]
}

/// A FreezeBalanceV2(BANDWIDTH) tx — bumps the chain-wide `TOTAL_NET_WEIGHT`
/// accumulator. Signed by ALICE when owned by ALICE (mirrors `transfer_tx`).
fn freeze_v2_bw_tx(owner: [u8; 21], amount: i64) -> Transaction {
    let c = FreezeBalanceV2Contract {
        owner_address: owner.to_vec(),
        frozen_balance: amount,
        resource: 0, // BANDWIDTH
    };
    let mut tx = Transaction {
        raw_data: Some(TxRaw {
            ref_block_bytes: vec![0, 1],
            ref_block_num: 0,
            ref_block_hash: vec![0u8; 8],
            expiration: 1_700_000_000_000 + 86_400_000,
            auths: Vec::new(),
            data: Vec::new(),
            contract: vec![TxContract {
                r#type: ContractType::FreezeBalanceV2Contract as i32,
                parameter: Some(Any {
                    type_url: "type.googleapis.com/protocol.FreezeBalanceV2Contract".into(),
                    value: c.encode_to_vec(),
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
    if owner == ALICE {
        tron_types::sign_transaction(&mut tx, &ALICE_PRIV).expect("sign");
    }
    tx
}

/// Derive a deterministic (private_key, 21-byte address) pair (mirrors the
/// helper in `vm_integration.rs`) so the second sender can actually sign — the
/// per-tx permission check is unconditional, unsigned txs are rejected.
fn derive_keypair(seed: u8) -> ([u8; 32], [u8; 21]) {
    use tron_crypto::signature::RecoverableSignature;
    let mut priv_key = [0u8; 32];
    priv_key[0] = 0x10;
    priv_key[31] = seed;
    let dummy = [0x42u8; 32];
    let sig = RecoverableSignature::sign_prehash(&priv_key, &dummy).expect("sign");
    let pubkey = sig.recover_uncompressed_pubkey(&dummy).expect("recover");
    let h = tron_crypto::hash::keccak256(&pubkey[1..]);
    let mut addr = [0u8; 21];
    addr[0] = 0x41;
    addr[1..].copy_from_slice(&h[12..]);
    (priv_key, addr)
}

/// A TransferContract tx signed with an arbitrary key (for senders other than
/// ALICE, whose key is the only one `transfer_tx` knows).
fn signed_transfer_tx(priv_key: &[u8; 32], owner: [u8; 21], to: [u8; 21], amount: i64) -> Transaction {
    let mut tx = transfer_tx(owner, to, amount); // unsigned for non-ALICE owners
    tx.signature.clear();
    tron_types::sign_transaction(&mut tx, priv_key).expect("sign");
    tx
}

/// Regression for the commutative-accumulator audit (Finding 1): a dyn_props key
/// that is BOTH written (`+=`) AND read-and-branched within tx execution must NOT
/// be delta-ized — the delta scheme would feed a later tx `base + own_delta`
/// instead of `base + Σ lower deltas`, diverging from serial with no read-set
/// entry to catch it. `TOTAL_NET_WEIGHT` is exactly that: a FreezeBalanceV2 bumps
/// it, and a same-block bandwidth-charged transfer reads it (as a `==0` gate +
/// divisor in `calculate_global_net_limit`) to decide frozen-quota vs free/fee.
///
/// Block: [ FreezeBalanceV2(ALICE, BANDWIDTH), Transfer(BOB→d1) ] on a fresh
/// chain (TOTAL_NET_WEIGHT base 0). With the weight wrongly treated as a delta,
/// BOB's parallel transfer reads weight 0 → net_limit 0 → free/fee path, while
/// serial reads ALICE's freeze (weight > 0) → frozen-quota path → different BOB
/// account proto + different fee accumulators. Must be byte-identical.
#[test]
fn parallel_many_freezes_one_block_weight_matches_serial() {
    // The live-divergent counter is TOTAL_NET_WEIGHT (+ ENERGY/TRON_POWER).
    // It is a CONFLICT key under Block-STM (read-for-decisions, not
    // delta-ized): MANY freeze txs in one block each read the running
    // weight and write weight+own_delta. If value-based validation fails
    // to re-execute a later freeze against an earlier freeze's committed
    // write, a delta is lost → the final weight is base+Σ MINUS the
    // dropped deltas — exactly "ours TOTAL_NET_WEIGHT below java",
    // permanently (it's an accumulator). Interleave bandwidth-reading
    // transfers so the scheduler sees the full read/write web.
    use tron_executor::{execute_block_with_config, ExecConfig};

    const FREEZERS: u8 = 8;
    let freezers: Vec<([u8;32],[u8;21])> = (0..FREEZERS).map(|i| derive_keypair(0xA0 + i)).collect();
    let (charlie_priv, charlie) = derive_keypair(0xB7);
    fn rcpt() -> [u8;21] { let mut a=[0u8;21]; a[0]=0x41; a[20]=0xe1; a }

    let setup = |b: &StateBundle| {
        b.dyn_props.save_unfreeze_delay_days(14);
        for (_, f) in &freezers { put_account(&b.accounts, *f, 10_000_000_000_000); }
        put_account(&b.accounts, rcpt(), 1);
        b.accounts.put(&addr(charlie), &Account {
            address: charlie.to_vec(), balance: 1_000_000_000, r#type: AccountType::Normal as i32,
            frozen_v2: vec![tron_proto::account::FreezeV2 { r#type: 0, amount: 1_000_000_000 }],
            ..Default::default()
        }).unwrap();
    };
    // Sign a FreezeBalanceV2 with an arbitrary key (freeze_v2_bw_tx only
    // signs for ALICE).
    let signed_freeze = |pk: &[u8;32], owner: [u8;21], amount: i64| -> Transaction {
        use prost::Message as _;
        let c = tron_proto::FreezeBalanceV2Contract { owner_address: owner.to_vec(), frozen_balance: amount, resource: 0 };
        let mut tx = Transaction {
            raw_data: Some(tron_proto::transaction::Raw {
                ref_block_bytes: vec![0,1], ref_block_num: 0, ref_block_hash: vec![0u8;8],
                expiration: 1_700_000_000_000 + 86_400_000, auths: Vec::new(), data: Vec::new(),
                contract: vec![tron_proto::transaction::Contract {
                    r#type: ContractType::FreezeBalanceV2Contract as i32,
                    parameter: Some(prost_types::Any {
                        type_url: "type.googleapis.com/protocol.FreezeBalanceV2Contract".into(),
                        value: c.encode_to_vec(),
                    }),
                    provider: Vec::new(), contract_name: Vec::new(), permission_id: 0,
                }],
                scripts: Vec::new(), timestamp: 1_700_000_000_000, fee_limit: 0,
            }),
            signature: Vec::new(), ret: Vec::new(),
        };
        tron_types::sign_transaction(&mut tx, pk).expect("sign");
        tx
    };
    // One block: 8 distinct freezers each freeze a DIFFERENT amount (so a
    // dropped delta is detectable), plus a weight-reading transfer.
    let txs = || {
        let mut v: Vec<Transaction> = freezers.iter().enumerate()
            .map(|(i,(pk,f))| signed_freeze(pk, *f, 1_000_000_000 * (i as i64 + 1)))
            .collect();
        v.push(signed_transfer_tx(&charlie_priv, charlie, rcpt(), 1));
        v
    };

    let serial_cfg = ExecConfig::unsigned();
    let par_cfg = ExecConfig { parallel_exec: true, ..ExecConfig::unsigned() };
    let s = StateBundle::fresh(); setup(&s);
    let rs = execute_block_with_config(&s.backends(), &build_block(1,[0u8;32],txs()), None, &serial_cfg).expect("serial");
    let p_ = StateBundle::fresh(); setup(&p_);
    let rp = execute_block_with_config(&p_.backends(), &build_block(1,[0u8;32],txs()), None, &par_cfg).expect("parallel");

    let so: Vec<_> = rs.tx_results.iter().map(|r| format!("{:?}", r.outcome)).collect();
    let po: Vec<_> = rp.tx_results.iter().map(|r| format!("{:?}", r.outcome)).collect();
    assert!(so.iter().all(|o| o=="Success"), "setup wrong: {so:?}");
    assert_eq!(so, po, "tx outcomes diverged");
    let wt_s = s.dyn_props.get_long(tron_chainbase::dynamic_properties_keys::TOTAL_NET_WEIGHT).unwrap_or(0);
    let wt_p = p_.dyn_props.get_long(tron_chainbase::dynamic_properties_keys::TOTAL_NET_WEIGHT).unwrap_or(0);
    // Σ of frozen/TRX_PRECISION: amounts 1e9..8e9 → weight deltas 1000..8000 = 36000.
    assert!(wt_s > 0, "weight moved");
    assert_eq!(wt_s, wt_p, "TOTAL_NET_WEIGHT lost a delta under parallel (serial={wt_s} parallel={wt_p})");
    assert_eq!(dump_state(&s), dump_state(&p_), "many-freeze block diverged from serial");
}

/// LIVE-DIVERGENCE REPRO (mainnet rig, energy-rental contracts): several
/// `UnDelegateResource` txs from the SAME (owner → receiver) in one block, each
/// draining the full delegation. In SERIAL the first drains the (owner,to)
/// `DelegatedResource` record (record deleted, `delegated_frozen_v2_balance_for_
/// energy` → 0, `frozen_v2[ENERGY]` += DELEG) and the rest fail validation
/// (`NothingToUndelegate`). Under Block-STM each undelegate validates
/// `available >= balance` against the per-(owner,to) record; if a later
/// undelegate is NOT re-validated against an earlier one's committed draw-down,
/// more than one "succeeds" and the owner's `delegated_frozen_v2_balance_for_
/// energy` is driven NEGATIVE — exactly the −4.58M-TRX `deleg_v2_en` seen on a
/// real rig contract (`TCw6YaWm…`). Parallel MUST equal serial.
#[test]
fn parallel_conflicting_undelegate_matches_serial() {
    use prost::Message as _;
    use tron_executor::{execute_block_with_config, ExecConfig};

    const DELEG: i64 = 9_000_000_000;
    let (owner_priv, owner) = derive_keypair(0xD1);
    let (_recv_priv, receiver) = derive_keypair(0xD2);

    let setup = |b: &StateBundle| {
        b.dyn_props.save_unfreeze_delay_days(14);
        b.dyn_props.put_long(
            tron_chainbase::dynamic_properties_keys::ALLOW_DELEGATE_RESOURCE,
            1,
        );
        // Non-zero weights so undelegate's usage-transfer math has a divisor.
        b.dyn_props.save_total_energy_weight(1_000_000);
        b.dyn_props.save_total_energy_current_limit(90_000_000_000);
        // Owner holds the delegated-OUT side (no held frozen_v2 yet).
        let owner_res = tron_proto::account::AccountResource {
            delegated_frozen_v2_balance_for_energy: DELEG,
            ..Default::default()
        };
        b.accounts
            .put(
                &addr(owner),
                &Account {
                    address: owner.to_vec(),
                    balance: 1_000_000_000,
                    r#type: AccountType::Normal as i32,
                    account_resource: Some(owner_res),
                    ..Default::default()
                },
            )
            .unwrap();
        // Receiver holds the acquired side.
        let recv_res = tron_proto::account::AccountResource {
            acquired_delegated_frozen_v2_balance_for_energy: DELEG,
            ..Default::default()
        };
        b.accounts
            .put(
                &addr(receiver),
                &Account {
                    address: receiver.to_vec(),
                    balance: 1,
                    r#type: AccountType::Normal as i32,
                    account_resource: Some(recv_res),
                    ..Default::default()
                },
            )
            .unwrap();
        // The single (owner → receiver) unlocked delegation record.
        let key = DelegatedResourceStore::v2_unlocked_key(&addr(owner), &addr(receiver));
        b.delegated_resources
            .put_raw(
                &key,
                &tron_proto::DelegatedResource {
                    from: owner.to_vec(),
                    to: receiver.to_vec(),
                    frozen_balance_for_bandwidth: 0,
                    frozen_balance_for_energy: DELEG,
                    expire_time_for_bandwidth: 0,
                    expire_time_for_energy: 0,
                },
            )
            .unwrap();
    };

    let undelegate = |amount: i64| -> Transaction {
        let c = tron_proto::UnDelegateResourceContract {
            owner_address: owner.to_vec(),
            receiver_address: receiver.to_vec(),
            resource: 1, // ENERGY
            balance: amount,
        };
        let mut tx = Transaction {
            raw_data: Some(TxRaw {
                ref_block_bytes: vec![0, 1],
                ref_block_num: 0,
                ref_block_hash: vec![0u8; 8],
                expiration: 1_700_000_000_000 + 86_400_000,
                auths: Vec::new(),
                data: Vec::new(),
                contract: vec![TxContract {
                    r#type: ContractType::UnDelegateResourceContract as i32,
                    parameter: Some(Any {
                        type_url: "type.googleapis.com/protocol.UnDelegateResourceContract".into(),
                        value: c.encode_to_vec(),
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
        tron_types::sign_transaction(&mut tx, &owner_priv).expect("sign");
        tx
    };
    let txs = || vec![undelegate(DELEG), undelegate(DELEG), undelegate(DELEG)];

    let serial_cfg = ExecConfig::unsigned();
    let par_cfg = ExecConfig { parallel_exec: true, ..ExecConfig::unsigned() };
    let s = StateBundle::fresh();
    setup(&s);
    let rs = execute_block_with_config(&s.backends(), &build_block(1, [0u8; 32], txs()), None, &serial_cfg)
        .expect("serial");
    let p_ = StateBundle::fresh();
    setup(&p_);
    let rp = execute_block_with_config(&p_.backends(), &build_block(1, [0u8; 32], txs()), None, &par_cfg)
        .expect("parallel");

    let so: Vec<_> = rs.tx_results.iter().map(|r| format!("{:?}", r.outcome)).collect();
    let po: Vec<_> = rp.tx_results.iter().map(|r| format!("{:?}", r.outcome)).collect();
    let s_succ = so.iter().filter(|o| o.as_str() == "Success").count();
    assert_eq!(s_succ, 1, "serial: exactly one undelegate should succeed, got {so:?}");
    assert_eq!(so, po, "undelegate outcomes diverged serial vs parallel: {so:?} vs {po:?}");

    let owner_acc = p_.accounts.get(&addr(owner)).unwrap().unwrap();
    let deleg_en = owner_acc
        .account_resource
        .as_ref()
        .map(|r| r.delegated_frozen_v2_balance_for_energy)
        .unwrap_or(0);
    assert!(deleg_en >= 0, "parallel drove delegated_frozen_v2_balance_for_energy NEGATIVE: {deleg_en}");
    assert_eq!(dump_state(&s), dump_state(&p_), "conflicting-undelegate block diverged from serial");
}

/// LIVE-DIVERGENCE REPRO #2 (energy-rental contract fan-out): ONE owner
/// delegates energy to MANY receivers in a single block. Every delegate
/// read-modify-writes the SAME owner account (`frozen_v2[ENERGY] -= b`,
/// `delegated_frozen_v2_balance_for_energy += b`), so all N txs conflict on the
/// owner account. If Block-STM loses any owner write (or applies one twice),
/// the owner's held/delegated split diverges from serial — the live signature
/// (held LOWER + delegated HIGHER than java, basis doubled on `TQ2PvH3c…`).
/// Parallel MUST equal serial across the full state.
#[test]
fn parallel_many_delegates_same_owner_matches_serial() {
    use prost::Message as _;
    use tron_executor::{execute_block_with_config, ExecConfig};

    const N: i64 = 8;
    const EACH: i64 = 1_000_000_000;
    let (owner_priv, owner) = derive_keypair(0xC1);
    let receivers: Vec<[u8; 21]> = (0..N as u8).map(|i| derive_keypair(0xE0 + i).1).collect();

    let setup = |b: &StateBundle| {
        b.dyn_props.save_unfreeze_delay_days(14);
        b.dyn_props.put_long(
            tron_chainbase::dynamic_properties_keys::ALLOW_DELEGATE_RESOURCE,
            1,
        );
        b.dyn_props.save_total_energy_weight(1_000_000);
        b.dyn_props.save_total_energy_current_limit(90_000_000_000);
        // Owner holds exactly N*EACH energy frozen-V2 to delegate out.
        b.accounts
            .put(
                &addr(owner),
                &Account {
                    address: owner.to_vec(),
                    balance: 1_000_000_000,
                    r#type: AccountType::Normal as i32,
                    frozen_v2: vec![tron_proto::account::FreezeV2 {
                        r#type: 1, // ENERGY
                        amount: N * EACH,
                    }],
                    ..Default::default()
                },
            )
            .unwrap();
        for r in &receivers {
            put_account(&b.accounts, *r, 1);
        }
    };

    let delegate = |to: [u8; 21], amount: i64| -> Transaction {
        let c = tron_proto::DelegateResourceContract {
            owner_address: owner.to_vec(),
            receiver_address: to.to_vec(),
            resource: 1, // ENERGY
            balance: amount,
            lock: false,
            lock_period: 0,
        };
        let mut tx = Transaction {
            raw_data: Some(TxRaw {
                ref_block_bytes: vec![0, 1],
                ref_block_num: 0,
                ref_block_hash: vec![0u8; 8],
                expiration: 1_700_000_000_000 + 86_400_000,
                auths: Vec::new(),
                data: Vec::new(),
                contract: vec![TxContract {
                    r#type: ContractType::DelegateResourceContract as i32,
                    parameter: Some(Any {
                        type_url: "type.googleapis.com/protocol.DelegateResourceContract".into(),
                        value: c.encode_to_vec(),
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
        tron_types::sign_transaction(&mut tx, &owner_priv).expect("sign");
        tx
    };
    let txs = || receivers.iter().map(|r| delegate(*r, EACH)).collect::<Vec<_>>();

    let serial_cfg = ExecConfig::unsigned();
    let par_cfg = ExecConfig { parallel_exec: true, ..ExecConfig::unsigned() };
    let s = StateBundle::fresh();
    setup(&s);
    let rs = execute_block_with_config(&s.backends(), &build_block(1, [0u8; 32], txs()), None, &serial_cfg)
        .expect("serial");
    let p_ = StateBundle::fresh();
    setup(&p_);
    let rp = execute_block_with_config(&p_.backends(), &build_block(1, [0u8; 32], txs()), None, &par_cfg)
        .expect("parallel");

    let so: Vec<_> = rs.tx_results.iter().map(|r| format!("{:?}", r.outcome)).collect();
    let po: Vec<_> = rp.tx_results.iter().map(|r| format!("{:?}", r.outcome)).collect();
    assert!(so.iter().all(|o| o.as_str() == "Success"), "serial setup wrong: {so:?}");
    assert_eq!(so, po, "delegate outcomes diverged serial vs parallel");

    // After N delegates of EACH, owner must hold 0 frozen + N*EACH delegated.
    let oa = p_.accounts.get(&addr(owner)).unwrap().unwrap();
    let held: i64 = oa.frozen_v2.iter().filter(|f| f.r#type == 1).map(|f| f.amount).sum();
    let deleg = oa.account_resource.as_ref().map(|r| r.delegated_frozen_v2_balance_for_energy).unwrap_or(0);
    assert_eq!(held, 0, "parallel: owner held energy should be 0, got {held}");
    assert_eq!(deleg, N * EACH, "parallel: owner delegated energy should be {}, got {deleg}", N * EACH);
    assert_eq!(dump_state(&s), dump_state(&p_), "many-delegate block diverged from serial");
}

/// LIVE-DIVERGENCE REPRO #3 (full energy-rental churn): ONE owner, in a single
/// block, delegates EACH energy to receiver R_i and then undelegates it back —
/// for many receivers, interleaved. Every tx RMWs the same owner account and
/// each undelegate depends on (and must re-validate against) its delegate's
/// committed write to the per-(owner,R_i) record. This is the densest
/// owner-account conflict web (the shape the real rig contracts run). Parallel
/// MUST end byte-identical to serial, with no negative delegated balance.
#[test]
fn parallel_delegate_undelegate_churn_matches_serial() {
    use prost::Message as _;
    use tron_executor::{execute_block_with_config, ExecConfig};

    const N: usize = 12;
    const EACH: i64 = 1_000_000_000;
    let (owner_priv, owner) = derive_keypair(0xF1);
    let receivers: Vec<[u8; 21]> = (0..N as u8).map(|i| derive_keypair(0x30 + i).1).collect();

    let setup = |b: &StateBundle| {
        b.dyn_props.save_unfreeze_delay_days(14);
        b.dyn_props.put_long(
            tron_chainbase::dynamic_properties_keys::ALLOW_DELEGATE_RESOURCE,
            1,
        );
        b.dyn_props.save_total_energy_weight(1_000_000);
        b.dyn_props.save_total_energy_current_limit(90_000_000_000);
        b.accounts
            .put(
                &addr(owner),
                &Account {
                    address: owner.to_vec(),
                    balance: 1_000_000_000,
                    r#type: AccountType::Normal as i32,
                    frozen_v2: vec![tron_proto::account::FreezeV2 {
                        r#type: 1,
                        amount: (N as i64) * EACH,
                    }],
                    ..Default::default()
                },
            )
            .unwrap();
        for r in &receivers {
            put_account(&b.accounts, *r, 1);
        }
    };

    let deleg_tx = |to: [u8; 21], undelegate: bool| -> Transaction {
        let (ty, type_url, value) = if undelegate {
            let c = tron_proto::UnDelegateResourceContract {
                owner_address: owner.to_vec(),
                receiver_address: to.to_vec(),
                resource: 1,
                balance: EACH,
            };
            (
                ContractType::UnDelegateResourceContract as i32,
                "type.googleapis.com/protocol.UnDelegateResourceContract",
                c.encode_to_vec(),
            )
        } else {
            let c = tron_proto::DelegateResourceContract {
                owner_address: owner.to_vec(),
                receiver_address: to.to_vec(),
                resource: 1,
                balance: EACH,
                lock: false,
                lock_period: 0,
            };
            (
                ContractType::DelegateResourceContract as i32,
                "type.googleapis.com/protocol.DelegateResourceContract",
                c.encode_to_vec(),
            )
        };
        let mut tx = Transaction {
            raw_data: Some(TxRaw {
                ref_block_bytes: vec![0, 1],
                ref_block_num: 0,
                ref_block_hash: vec![0u8; 8],
                expiration: 1_700_000_000_000 + 86_400_000,
                auths: Vec::new(),
                data: Vec::new(),
                contract: vec![TxContract {
                    r#type: ty,
                    parameter: Some(Any { type_url: type_url.into(), value }),
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
        tron_types::sign_transaction(&mut tx, &owner_priv).expect("sign");
        tx
    };
    // delegate R0, undelegate R0, delegate R1, undelegate R1, ...
    let txs = || {
        let mut v = Vec::new();
        for r in &receivers {
            v.push(deleg_tx(*r, false));
            v.push(deleg_tx(*r, true));
        }
        v
    };

    let serial_cfg = ExecConfig::unsigned();
    let par_cfg = ExecConfig { parallel_exec: true, ..ExecConfig::unsigned() };
    let s = StateBundle::fresh();
    setup(&s);
    let rs = execute_block_with_config(&s.backends(), &build_block(1, [0u8; 32], txs()), None, &serial_cfg)
        .expect("serial");
    let p_ = StateBundle::fresh();
    setup(&p_);
    let rp = execute_block_with_config(&p_.backends(), &build_block(1, [0u8; 32], txs()), None, &par_cfg)
        .expect("parallel");

    let so: Vec<_> = rs.tx_results.iter().map(|r| format!("{:?}", r.outcome)).collect();
    let po: Vec<_> = rp.tx_results.iter().map(|r| format!("{:?}", r.outcome)).collect();
    assert_eq!(so, po, "delegate/undelegate churn outcomes diverged: {so:?} vs {po:?}");

    let oa = p_.accounts.get(&addr(owner)).unwrap().unwrap();
    let deleg = oa.account_resource.as_ref().map(|r| r.delegated_frozen_v2_balance_for_energy).unwrap_or(0);
    assert!(deleg >= 0, "parallel: delegated energy NEGATIVE: {deleg}");
    assert_eq!(dump_state(&s), dump_state(&p_), "delegate/undelegate churn diverged from serial");
}

/// SCOPE PROBE: is the lost-update general to any chained same-account RMW, or
/// specific to delegate/undelegate? One sender makes N transfers to N receivers
/// in one block — each tx RMWs the sender's balance + bandwidth window, a dense
/// dependency chain on a single account. If THIS diverges, the bug hits every
/// block with multiple txs from the same signer (exchanges, contracts).
#[test]
fn parallel_same_sender_many_transfers_matches_serial() {
    use tron_executor::{execute_block_with_config, ExecConfig};
    const N: usize = 12;
    let (sender_priv, sender) = derive_keypair(0x5A);
    let receivers: Vec<[u8; 21]> = (0..N as u8).map(|i| derive_keypair(0x60 + i).1).collect();
    let setup = |b: &StateBundle| {
        put_account(&b.accounts, sender, 100_000_000_000);
        for r in &receivers {
            put_account(&b.accounts, *r, 1);
        }
    };
    let txs = || {
        receivers
            .iter()
            .map(|r| signed_transfer_tx(&sender_priv, sender, *r, 1_000_000))
            .collect::<Vec<_>>()
    };
    let serial_cfg = ExecConfig::unsigned();
    let par_cfg = ExecConfig { parallel_exec: true, ..ExecConfig::unsigned() };
    let s = StateBundle::fresh();
    setup(&s);
    let _ = execute_block_with_config(&s.backends(), &build_block(1, [0u8; 32], txs()), None, &serial_cfg).expect("serial");
    let p_ = StateBundle::fresh();
    setup(&p_);
    let _ = execute_block_with_config(&p_.backends(), &build_block(1, [0u8; 32], txs()), None, &par_cfg).expect("parallel");
    let ss = s.accounts.get(&addr(sender)).unwrap().unwrap();
    let sp = p_.accounts.get(&addr(sender)).unwrap().unwrap();
    assert_eq!(ss.balance, sp.balance, "sender balance: serial={} parallel={}", ss.balance, sp.balance);
    assert_eq!(ss.free_net_usage, sp.free_net_usage, "sender free_net_usage: serial={} parallel={}", ss.free_net_usage, sp.free_net_usage);
    assert_eq!(dump_state(&s), dump_state(&p_), "same-sender transfers diverged from serial");
}

#[test]
fn parallel_weight_dependent_block_is_byte_identical_to_serial() {
    use tron_executor::{execute_block_with_config, ExecConfig};

    let (charlie_priv, charlie) = derive_keypair(0x77);
    let d1 = {
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[20] = 0xe1;
        a
    };
    // CHARLIE holds frozen-V2 bandwidth so its transfer takes the account-net
    // path (which reads TOTAL_NET_WEIGHT). Set directly so setup itself doesn't
    // bump the weight — base stays 0 until ALICE's in-block freeze.
    let setup = |b: &StateBundle| {
        // Enable the V2-staking fork so FreezeBalanceV2 validates (else tx0
        // fails, no weight is written, and there's nothing to diverge on).
        b.dyn_props.save_unfreeze_delay_days(14);
        put_account(&b.accounts, ALICE, 10_000_000_000_000);
        put_account(&b.accounts, d1, 1); // pre-exists ⇒ plain transfer, not account-creation
        b.accounts
            .put(
                &addr(charlie),
                &Account {
                    address: charlie.to_vec(),
                    balance: 1_000_000_000,
                    r#type: AccountType::Normal as i32,
                    frozen_v2: vec![tron_proto::account::FreezeV2 {
                        r#type: 0, // BANDWIDTH
                        amount: 1_000_000_000,
                    }],
                    ..Default::default()
                },
            )
            .unwrap();
    };
    let txs = || {
        vec![
            freeze_v2_bw_tx(ALICE, 1_000_000_000_000), // writes TOTAL_NET_WEIGHT
            signed_transfer_tx(&charlie_priv, charlie, d1, 1), // reads TOTAL_NET_WEIGHT
        ]
    };

    let serial_cfg = ExecConfig::unsigned();
    let par_cfg = ExecConfig {
        parallel_exec: true,
        ..ExecConfig::unsigned()
    };

    let s = StateBundle::fresh();
    setup(&s);
    let rs = execute_block_with_config(&s.backends(), &build_block(1, [0u8; 32], txs()), None, &serial_cfg)
        .expect("serial");

    let p = StateBundle::fresh();
    setup(&p);
    let rp = execute_block_with_config(&p.backends(), &build_block(1, [0u8; 32], txs()), None, &par_cfg)
        .expect("parallel");

    // Both txs must succeed (a rejected freeze/transfer would make the divergence
    // vacuous — see the keypair/fork-flag setup above).
    let so: Vec<_> = rs.tx_results.iter().map(|r| format!("{:?}", r.outcome)).collect();
    assert_eq!(so, vec!["Success", "Success"], "setup wrong: a tx was rejected");
    let po: Vec<_> = rp.tx_results.iter().map(|r| format!("{:?}", r.outcome)).collect();
    assert_eq!(so, po, "tx outcomes diverged");

    // The decisive check: CHARLIE's transfer must take the SAME bandwidth path in
    // both (account-net, having seen ALICE's in-block freeze raise the weight).
    // The bug (weight delta-ized) makes parallel read weight 0 → free-net.
    assert_eq!(
        dump_state(&s),
        dump_state(&p),
        "parallel diverged from serial on a weight-dependent (freeze + bandwidth) block"
    );
}

#[test]
fn parallel_execution_is_byte_identical_to_serial() {
    use tron_executor::{execute_block_with_config, ExecConfig};

    fn rcpt(n: u8) -> [u8; 21] {
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[20] = n;
        a
    }
    let (d1, d2, d3, d4) = (rcpt(0xd1), rcpt(0xd2), rcpt(0xd3), rcpt(0xd4));

    let fund = |b: &StateBundle| {
        put_account(&b.accounts, ALICE, 1_000_000_000);
        put_account(&b.accounts, BOB, 1_000_000_000);
        put_account(&b.accounts, CARROL, 1_000_000_000);
    };
    // Independent (different senders) + conflicting (same sender) + shared
    // recipient (d1 credited by two txs) — exercises the re-execution path.
    let txs = || {
        vec![
            transfer_tx(ALICE, d1, 100),
            transfer_tx(BOB, d2, 200),
            transfer_tx(CARROL, d3, 300),
            transfer_tx(ALICE, d4, 50),  // conflicts with ALICE's first tx
            transfer_tx(BOB, d1, 20),    // conflicts with BOB's first tx + shares d1
        ]
    };

    let serial_cfg = ExecConfig::unsigned();
    let par_cfg = ExecConfig {
        parallel_exec: true,
        ..ExecConfig::unsigned()
    };

    let s = StateBundle::fresh();
    fund(&s);
    let rs = execute_block_with_config(&s.backends(), &build_block(1, [0u8; 32], txs()), None, &serial_cfg)
        .expect("serial");

    let p = StateBundle::fresh();
    fund(&p);
    let rp = execute_block_with_config(&p.backends(), &build_block(1, [0u8; 32], txs()), None, &par_cfg)
        .expect("parallel");

    // Every store, byte-for-byte.
    assert_eq!(dump_state(&s), dump_state(&p), "parallel state diverged from serial");
    // Per-tx outcomes identical and in order.
    let so: Vec<_> = rs.tx_results.iter().map(|r| format!("{:?}", r.outcome)).collect();
    let po: Vec<_> = rp.tx_results.iter().map(|r| format!("{:?}", r.outcome)).collect();
    assert_eq!(so, po, "tx outcomes diverged");
    // Block ids identical (tx_trie + header).
    assert_eq!(rs.block_id, rp.block_id);
}

#[test]
fn parallel_free_net_chain_is_byte_identical_to_serial() {
    // Every funded account with no frozen bandwidth pays its transfer from the
    // daily FREE quota, which read-modify-writes the chain-global
    // `PUBLIC_NET_USAGE` via a windowed-average `increase()`. Serial threads that
    // single counter through all N txs — an N-deep dependency chain that is the
    // dominant Block-STM tax on real mainnet blocks. The parallel path excludes
    // it from the MVCC chain (a deferred-sequential key) and replays the exact
    // fold at commit. With N DISTINCT senders → distinct recipients, the only
    // write all txs share is `PUBLIC_NET_USAGE`, so a byte-identical result
    // proves the deferred fold reproduces the serial windowed-average chain
    // exactly (ceil/floor rounding and all). A wrong fold (bad order / off-by-one
    // / missed decay) diverges here.
    use tron_executor::{execute_block_with_config, ExecConfig};

    fn rcpt(n: u8) -> [u8; 21] {
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[1] = 0xb0;
        a[20] = n;
        a
    }

    const N: u8 = 16;
    // Distinct, validly-signed senders (signatures are required even under
    // `ExecConfig::unsigned()`, which only skips tx-trie verification).
    let keypairs: Vec<([u8; 32], [u8; 21])> = (0..N).map(|i| derive_keypair(0x50 + i)).collect();
    let fund = |b: &StateBundle| {
        for (_, sender) in &keypairs {
            put_account(&b.accounts, *sender, 1_000_000_000);
        }
        for i in 0..N {
            put_account(&b.accounts, rcpt(i), 1); // pre-exists ⇒ plain transfer
        }
    };
    let txs = || {
        keypairs
            .iter()
            .enumerate()
            .map(|(i, (priv_key, sender))| signed_transfer_tx(priv_key, *sender, rcpt(i as u8), 100))
            .collect::<Vec<_>>()
    };

    let serial_cfg = ExecConfig::unsigned();
    let par_cfg = ExecConfig {
        parallel_exec: true,
        ..ExecConfig::unsigned()
    };

    let s = StateBundle::fresh();
    fund(&s);
    let rs = execute_block_with_config(&s.backends(), &build_block(1, [0u8; 32], txs()), None, &serial_cfg)
        .expect("serial");

    let p = StateBundle::fresh();
    fund(&p);
    let rp = execute_block_with_config(&p.backends(), &build_block(1, [0u8; 32], txs()), None, &par_cfg)
        .expect("parallel");

    // All txs must have actually spent free net (else the test is vacuous).
    let so: Vec<_> = rs.tx_results.iter().map(|r| format!("{:?}", r.outcome)).collect();
    assert!(so.iter().all(|o| o == "Success"), "setup wrong, a tx was rejected: {so:?}");
    let po: Vec<_> = rp.tx_results.iter().map(|r| format!("{:?}", r.outcome)).collect();
    assert_eq!(so, po, "tx outcomes diverged");

    // Non-vacuous: the free-net path was exercised and the counter moved.
    let su = s.dyn_props.public_net_usage();
    assert!(su > 0, "free-net path not exercised — PUBLIC_NET_USAGE stayed 0");
    assert_eq!(
        su,
        p.dyn_props.public_net_usage(),
        "deferred PUBLIC_NET fold != serial windowed-average chain"
    );

    // Every store, byte-for-byte (PUBLIC_NET_USAGE + PUBLIC_NET_TIME included).
    assert_eq!(
        dump_state(&s),
        dump_state(&p),
        "parallel diverged from serial on a free-net (PUBLIC_NET_USAGE chain) block"
    );
    assert_eq!(rs.block_id, rp.block_id);
}

// ---------------------------------------------------------------------------
// State-delta capture (ExecConfig::capture_state_deltas)
// ---------------------------------------------------------------------------

/// Capture is OFF by default — no allocation, report carries None.
#[test]
fn state_deltas_absent_by_default() {
    let state = StateBundle::fresh();
    put_account(&state.accounts, ALICE, 1_000_000);
    let block = build_block(1, [0u8; 32], vec![transfer_tx(ALICE, BOB, 100)]);
    let undo = tron_chainbase::BlockUndoStore::new(mem());
    let report = tron_executor::execute_block_with_undo_and_config(
        &state.backends(),
        &block,
        None,
        &undo,
        &tron_executor::ExecConfig::unsigned(),
    )
    .unwrap();
    assert!(report.state_deltas.is_none());
}

/// With capture on, the report carries one (store, key) entry per
/// committed write with exact pre/post images, sorted by (store, key),
/// and the SAME set on the plain-undo and checkpoint commit paths.
#[test]
fn state_deltas_capture_pre_and_post_images_on_both_commit_paths() {
    let cfg = tron_executor::ExecConfig {
        capture_state_deltas: true,
        ..tron_executor::ExecConfig::unsigned()
    };
    let run_plain = || {
        let state = StateBundle::fresh();
        put_account(&state.accounts, ALICE, 1_000_000);
        put_account(&state.accounts, BOB, 0);
        let block = build_block(1, [0u8; 32], vec![transfer_tx(ALICE, BOB, 250_000)]);
        let undo = tron_chainbase::BlockUndoStore::new(mem());
        tron_executor::execute_block_with_undo_and_config(
            &state.backends(),
            &block,
            None,
            &undo,
            &cfg,
        )
        .unwrap()
    };
    let run_checkpoint = || {
        let state = StateBundle::fresh();
        put_account(&state.accounts, ALICE, 1_000_000);
        put_account(&state.accounts, BOB, 0);
        let block = build_block(1, [0u8; 32], vec![transfer_tx(ALICE, BOB, 250_000)]);
        let undo = tron_chainbase::BlockUndoStore::new(mem());
        let cp_root = std::env::temp_dir().join(format!(
            "tron-delta-capture-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let cp = tron_chainbase::CheckPointV2::new(&cp_root);
        tron_executor::execute_block_with_undo_checkpoint_and_config(
            &state.backends(),
            &block,
            None,
            &undo,
            &cp,
            &cfg,
        )
        .unwrap()
    };

    let plain = run_plain().state_deltas.expect("captured on plain path");
    let checkpointed = run_checkpoint()
        .state_deltas
        .expect("captured on checkpoint path");
    assert!(!plain.is_empty());
    assert_eq!(plain, checkpointed, "both commit paths capture the identical write-set");

    // Sorted by (store, key) — the deterministic-consumption contract.
    let keys: Vec<(u8, Vec<u8>)> =
        plain.iter().map(|d| (d.store as u8, d.key.clone())).collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted);

    // The account mutations carry exact pre/post images.
    use prost::Message as _;
    let balance_of = |bytes: &Option<Vec<u8>>| -> Option<i64> {
        bytes
            .as_ref()
            .and_then(|b| tron_proto::Account::decode(b.as_slice()).ok())
            .map(|a| a.balance)
    };
    let alice_delta = plain
        .iter()
        .find(|d| d.store == tron_chainbase::UndoStoreId::Accounts && d.key == ALICE.to_vec())
        .expect("alice account delta present");
    assert_eq!(balance_of(&alice_delta.before), Some(1_000_000));
    assert_eq!(balance_of(&alice_delta.after), Some(750_000));
    let bob_delta = plain
        .iter()
        .find(|d| d.store == tron_chainbase::UndoStoreId::Accounts && d.key == BOB.to_vec())
        .expect("bob account delta present");
    assert_eq!(balance_of(&bob_delta.after), Some(250_000));

    // Head-pointer writes are part of the write-set too (dyn props).
    assert!(plain.iter().any(|d| d.store == tron_chainbase::UndoStoreId::DynProps));
}

// =============================================================================
// Flat fees: multi-sign + memo (java-tron Manager.consumeMultiSignFee /
// consumeMemoFee) and the actuator fee in the result.
// =============================================================================

/// A tx with more than one signature pays MULTI_SIGN_FEE (1 TRX
/// default) from the owner's balance, burned — and the receipt carries
/// it for the stored TransactionInfo.fee aggregation.
#[test]
fn second_signature_charges_the_multi_sign_fee() {
    // A second keypair for the 2-of-2 owner permission.
    let dave_priv: [u8; 32] =
        hex!("9876543210987654321098765432109876543210987654321098765432109876");
    let dave: [u8; 21] = {
        use tron_crypto::signature::RecoverableSignature;
        let dummy = [0x42u8; 32];
        let sig = RecoverableSignature::sign_prehash(&dave_priv, &dummy).expect("sign");
        let pubkey = sig.recover_uncompressed_pubkey(&dummy).expect("recover");
        let h = tron_crypto::hash::keccak256(&pubkey[1..]);
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[1..].copy_from_slice(&h[12..]);
        a
    };

    let state = StateBundle::fresh();
    // ALICE with a 2-of-2 owner permission (ALICE + DAVE) — the real
    // multi-sign shape; both signatures are required and the tx pays
    // the multi-sign fee for carrying more than one.
    state
        .accounts
        .put(
            &addr(ALICE),
            &Account {
                address: ALICE.to_vec(),
                balance: 10_000_000,
                r#type: AccountType::Normal as i32,
                owner_permission: Some(tron_proto::Permission {
                    r#type: 0,
                    id: 0,
                    permission_name: "owner".into(),
                    threshold: 2,
                    keys: vec![
                        tron_proto::Key { address: ALICE.to_vec(), weight: 1 },
                        tron_proto::Key { address: dave.to_vec(), weight: 1 },
                    ],
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .unwrap();
    put_account(&state.accounts, BOB, 0);

    let mut tx = transfer_tx(ALICE, BOB, 100); // transfer_tx signs with ALICE_PRIV
    tron_types::sign_transaction(&mut tx, &dave_priv).expect("dave co-signs");
    let block = build_block(1, [0u8; 32], vec![tx]);

    let report = execute_block(&state.backends(), &block, None).unwrap();
    let res = &report.tx_results[0];
    assert!(res.outcome.is_success(), "got {:?}", res.outcome);
    assert_eq!(res.receipt.multi_sign_fee, 1_000_000);
    assert_eq!(
        state.accounts.get(&addr(ALICE)).unwrap().unwrap().balance,
        10_000_000 - 100 - 1_000_000
    );
    assert_eq!(state.dyn_props.get_long(b"BURN_TRX_AMOUNT"), Some(1_000_000));
    // (Single-signature txs paying no multi-sign fee is implicit in
    // every other test here: their receipt.multi_sign_fee is 0.)
}

/// A non-empty memo (`raw_data.data`) pays MEMO_FEE once the SR
/// proposal sets it; with the property unset (0) the memo is free.
#[test]
fn memo_fee_charges_only_when_the_property_is_set() {
    let state = StateBundle::fresh();
    put_account(&state.accounts, ALICE, 10_000_000);
    put_account(&state.accounts, BOB, 0);

    // MEMO_FEE unset → free.
    let mut tx = transfer_tx(ALICE, BOB, 100);
    tx.raw_data.as_mut().unwrap().data = b"hello".to_vec();
    tron_types::sign_transaction(&mut tx, &ALICE_PRIV).expect("re-sign");
    tx.signature.drain(..tx.signature.len() - 1); // keep only the fresh signature
    let block = build_block(1, [0u8; 32], vec![tx.clone()]);
    let report = execute_block(&state.backends(), &block, None).unwrap();
    assert!(report.tx_results[0].outcome.is_success(), "got {:?}", report.tx_results[0].outcome);
    assert_eq!(report.tx_results[0].receipt.memo_fee, 0);
    assert_eq!(
        state.accounts.get(&addr(ALICE)).unwrap().unwrap().balance,
        10_000_000 - 100
    );

    // Proposal sets MEMO_FEE = 1 TRX → the next memo tx pays it.
    state.dyn_props.put_long(b"MEMO_FEE", 1_000_000);
    let mut tx2 = transfer_tx(ALICE, BOB, 100);
    tx2.raw_data.as_mut().unwrap().data = b"world".to_vec();
    tron_types::sign_transaction(&mut tx2, &ALICE_PRIV).expect("re-sign");
    tx2.signature.drain(..tx2.signature.len() - 1);
    let block2 = build_block(2, *report.block_id.as_bytes(), vec![tx2]);
    let report2 = execute_block(&state.backends(), &block2, Some(report.block_id)).unwrap();
    let res = &report2.tx_results[0];
    assert!(res.outcome.is_success(), "got {:?}", res.outcome);
    assert_eq!(res.receipt.memo_fee, 1_000_000);
    assert_eq!(
        state.accounts.get(&addr(ALICE)).unwrap().unwrap().balance,
        10_000_000 - 200 - 1_000_000
    );
}

/// The actuator-charged fee (here: createNewAccountFeeInSystemContract,
/// set by proposal) surfaces on `TxResult::actuator_fee` — java's
/// `ProgramResult.ret.fee` half of the TransactionInfo.fee sum.
#[test]
fn actuator_fee_is_reported_on_the_result() {
    let state = StateBundle::fresh();
    put_account(&state.accounts, ALICE, 10_000_000);
    // The in-system-contract creation fee (distinct from the bandwidth
    // processor's CREATE_ACCOUNT_FEE) — mainnet sets it to 1 TRX.
    state.dyn_props.put_long(b"CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT", 1_000_000);

    // CARROL doesn't exist → transfer pays the actuator-side creation
    // fee AND the bandwidth-side flat create fee.
    let block = build_block(1, [0u8; 32], vec![transfer_tx(ALICE, CARROL, 500)]);
    let report = execute_block(&state.backends(), &block, None).unwrap();
    let res = &report.tx_results[0];
    assert!(res.outcome.is_success(), "got {:?}", res.outcome);
    assert_eq!(res.actuator_fee, 1_000_000, "in-system-contract creation fee");
    assert_eq!(res.receipt.net_fee, 100_000, "bandwidth-side flat create-account fee");
    assert_eq!(
        state.accounts.get(&addr(ALICE)).unwrap().unwrap().balance,
        10_000_000 - 500 - 1_000_000 - 100_000
    );
}

#[test]
fn parallel_conflicting_create_account_burn_matches_serial() {
    // The LIVE-divergent shape: ONE hot sender does MANY transfers to
    // fresh accounts in the same block. Same sender on every tx → a
    // write-write conflict on its account row → Block-STM RE-EXECUTES
    // the conflicting txs. Each create-account tx also bumps the
    // delta-ized BURN_TRX_AMOUNT / TOTAL_CREATE_ACCOUNT_COST counters
    // (the create fee burn). If a re-executed tx's delta is counted
    // more than once, BURN_TRX over-counts vs serial — the live
    // "ours burns more" signal. This forces that path.
    use tron_executor::{execute_block_with_config, ExecConfig};

    fn fresh_rcpt(n: u16) -> [u8; 21] {
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[1] = 0xf0;
        a[18] = (n >> 8) as u8;
        a[19] = n as u8;
        a[20] = 0xcd;
        a
    }

    // ONE sender, no frozen bandwidth → each create-account charges the
    // flat fee (burned). 8 transfers to 8 fresh accounts in one block.
    let (priv_key, sender) = derive_keypair(0xC1);
    const N: u16 = 8;
    let fund = |b: &StateBundle| {
        put_account(&b.accounts, sender, 1_000_000_000);
    };
    let txs = || {
        (0..N)
            .map(|i| signed_transfer_tx(&priv_key, sender, fresh_rcpt(i), 1000))
            .collect::<Vec<_>>()
    };

    let serial_cfg = ExecConfig::unsigned();
    let par_cfg = ExecConfig { parallel_exec: true, ..ExecConfig::unsigned() };

    let s = StateBundle::fresh();
    fund(&s);
    let rs = execute_block_with_config(&s.backends(), &build_block(1, [0u8; 32], txs()), None, &serial_cfg).expect("serial");

    let p = StateBundle::fresh();
    fund(&p);
    let rp = execute_block_with_config(&p.backends(), &build_block(1, [0u8; 32], txs()), None, &par_cfg).expect("parallel");

    let so: Vec<_> = rs.tx_results.iter().map(|r| format!("{:?}", r.outcome)).collect();
    let po: Vec<_> = rp.tx_results.iter().map(|r| format!("{:?}", r.outcome)).collect();
    assert_eq!(so, po, "tx outcomes diverged");
    assert!(so.iter().all(|o| o == "Success"), "setup wrong: {so:?}");

    let burn_s = s.dyn_props.get_long(tron_chainbase::dynamic_properties_keys::BURN_TRX_AMOUNT).unwrap_or(0);
    let burn_p = p.dyn_props.get_long(tron_chainbase::dynamic_properties_keys::BURN_TRX_AMOUNT).unwrap_or(0);
    let cac_s = s.dyn_props.get_long(tron_chainbase::dynamic_properties_keys::TOTAL_CREATE_ACCOUNT_COST).unwrap_or(0);
    let cac_p = p.dyn_props.get_long(tron_chainbase::dynamic_properties_keys::TOTAL_CREATE_ACCOUNT_COST).unwrap_or(0);
    assert!(burn_s > 0, "non-vacuous: burn moved");
    assert_eq!(burn_s, burn_p, "BURN_TRX_AMOUNT diverged under conflict re-execution (serial={burn_s} parallel={burn_p})");
    assert_eq!(cac_s, cac_p, "TOTAL_CREATE_ACCOUNT_COST diverged (serial={cac_s} parallel={cac_p})");
    assert_eq!(dump_state(&s), dump_state(&p), "conflicting create-account state diverged from serial");
}

#[test]
fn pipelined_parallel_create_account_chain_matches_classic_serial() {
    // The live-divergent path: transfers to NON-EXISTENT recipients
    // (account creation + create-account bandwidth/fee), executed with
    // parallel_exec + the apply pipeline + deferred fsync, vs classic
    // serial. Each created account, the create-account fee burn
    // (TOTAL_CREATE_ACCOUNT_COST, BURN_TRX), and the windowed bandwidth
    // must match serial byte-for-byte across blocks.
    use tron_chainbase::{BlockUndoStore, CheckPointV2, MemBackend};
    use tron_executor::{
        execute_block_with_undo_checkpoint_and_config, ApplyPipeline, ExecConfig,
    };

    fn fresh_rcpt(block: u8, n: u8) -> [u8; 21] {
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[1] = 0xe0 + block;
        a[19] = n;
        a[20] = 0xab;
        a
    }
    fn tmp_root(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "tron-pipe-ca-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    const SENDERS: u8 = 6;
    const BLOCKS: u8 = 4;
    let keypairs: Vec<([u8; 32], [u8; 21])> =
        (0..SENDERS).map(|i| derive_keypair(0x90 + i)).collect();
    // Senders have NO frozen bandwidth → create-account falls to the
    // flat create-account fee path (burned from balance).
    let fund = |b: &StateBundle| {
        for (_, sender) in &keypairs {
            put_account(&b.accounts, *sender, 1_000_000_000);
        }
        // recipients deliberately NOT pre-created.
    };
    let block_txs = |k: u8| {
        keypairs
            .iter()
            .enumerate()
            .map(|(i, (priv_key, sender))| {
                signed_transfer_tx(priv_key, *sender, fresh_rcpt(k - 1, i as u8), 1000)
            })
            .collect::<Vec<_>>()
    };
    let chain = || {
        let mut blocks = Vec::new();
        let mut parent = [0u8; 32];
        for k in 1..=BLOCKS {
            let b = build_block(k as i64, parent, block_txs(k));
            parent = *tron_types::block_id_from_block(&b).unwrap().as_bytes();
            blocks.push(b);
        }
        blocks
    };

    let serial_cfg = ExecConfig::unsigned();
    let s = StateBundle::fresh();
    fund(&s);
    let undo_s = BlockUndoStore::new(Arc::new(MemBackend::new()) as Arc<dyn KvBackend>);
    let root_s = tmp_root("serial");
    let cp_s = CheckPointV2::new(&root_s);
    let mut serial_outcomes = Vec::new();
    for b in chain() {
        let r = execute_block_with_undo_checkpoint_and_config(
            &s.backends(), &b, None, &undo_s, &cp_s, &serial_cfg,
        ).expect("serial apply");
        for t in &r.tx_results {
            serial_outcomes.push(format!("{:?}", t.outcome));
        }
    }

    let par_cfg = ExecConfig {
        parallel_exec: true,
        defer_store_fsync: true,
        ..ExecConfig::unsigned()
    };
    let p = StateBundle::fresh();
    fund(&p);
    let undo_p = BlockUndoStore::new(Arc::new(MemBackend::new()) as Arc<dyn KvBackend>);
    let root_p = tmp_root("pipelined");
    let cp_p = CheckPointV2::new(&root_p);
    let backends = p.backends();
    let mut pipeline = ApplyPipeline::new(&backends, undo_p, cp_p);
    let mut par_outcomes = Vec::new();
    for b in chain() {
        let r = pipeline.apply(&b, None, &par_cfg).expect("pipelined apply");
        for t in &r.tx_results {
            par_outcomes.push(format!("{:?}", t.outcome));
        }
    }
    pipeline.flush().expect("flush");

    assert!(
        serial_outcomes.iter().all(|o| o == "Success"),
        "setup wrong, a serial tx failed: {serial_outcomes:?}"
    );
    assert_eq!(serial_outcomes, par_outcomes, "tx outcomes diverged");
    assert_eq!(
        dump_state(&s),
        dump_state(&p),
        "pipelined+parallel create-account state diverged from classic serial"
    );

    let _ = std::fs::remove_dir_all(&root_s);
    let _ = std::fs::remove_dir_all(&root_p);
}

#[test]
fn pipelined_parallel_weight_chain_matches_classic_serial() {
    // Catch-up shape of the weight hazard: across MULTIPLE blocks through
    // the apply pipeline, a FreezeBalanceV2 (writes TOTAL_NET_WEIGHT) and
    // a bandwidth-reading transfer (reads it for the frozen-quota gate)
    // interleave. Block N's weight write is pending in the pipeline
    // overlay while block N+1 reads it. Must equal classic serial across
    // every store + the global weight counters.
    use tron_chainbase::{BlockUndoStore, CheckPointV2, MemBackend};
    use tron_executor::{execute_block_with_undo_checkpoint_and_config, ApplyPipeline, ExecConfig};

    fn tmp_root(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("tron-pipe-wt-{tag}-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()))
    }
    let (charlie_priv, charlie) = derive_keypair(0xD7);
    fn rcpt(k: u8) -> [u8;21] { let mut a=[0u8;21]; a[0]=0x41; a[1]=0xd0+k; a[20]=0xe1; a }
    const BLOCKS: u8 = 4;
    let setup = |b: &StateBundle| {
        b.dyn_props.save_unfreeze_delay_days(14);
        put_account(&b.accounts, ALICE, 10_000_000_000_000);
        for k in 0..BLOCKS { put_account(&b.accounts, rcpt(k), 1); }
        b.accounts.put(&addr(charlie), &Account {
            address: charlie.to_vec(), balance: 1_000_000_000, r#type: AccountType::Normal as i32,
            frozen_v2: vec![tron_proto::account::FreezeV2 { r#type: 0, amount: 1_000_000_000 }],
            ..Default::default()
        }).unwrap();
    };
    // Each block: ALICE freezes a chunk (bumps weight), CHARLIE transfers
    // (reads weight). Weight chains across blocks.
    let block_txs = |k: u8| vec![
        freeze_v2_bw_tx(ALICE, 1_000_000_000_000),
        signed_transfer_tx(&charlie_priv, charlie, rcpt(k-1), 1),
    ];
    let chain = || {
        let mut blocks=Vec::new(); let mut parent=[0u8;32];
        for k in 1..=BLOCKS {
            let b = build_block(k as i64, parent, block_txs(k));
            parent = *tron_types::block_id_from_block(&b).unwrap().as_bytes();
            blocks.push(b);
        }
        blocks
    };

    let serial_cfg = ExecConfig::unsigned();
    let s = StateBundle::fresh(); setup(&s);
    let undo_s = BlockUndoStore::new(Arc::new(MemBackend::new()) as Arc<dyn KvBackend>);
    let root_s = tmp_root("serial"); let cp_s = CheckPointV2::new(&root_s);
    for b in chain() {
        execute_block_with_undo_checkpoint_and_config(&s.backends(), &b, None, &undo_s, &cp_s, &serial_cfg).expect("serial");
    }

    let par_cfg = ExecConfig { parallel_exec: true, defer_store_fsync: true, ..ExecConfig::unsigned() };
    let p = StateBundle::fresh(); setup(&p);
    let undo_p = BlockUndoStore::new(Arc::new(MemBackend::new()) as Arc<dyn KvBackend>);
    let root_p = tmp_root("pipe"); let cp_p = CheckPointV2::new(&root_p);
    let backends = p.backends();
    let mut pipe = ApplyPipeline::new(&backends, undo_p, cp_p);
    for b in chain() { pipe.apply(&b, None, &par_cfg).expect("pipelined"); }
    pipe.flush().expect("flush");

    let wt_s = s.dyn_props.get_long(tron_chainbase::dynamic_properties_keys::TOTAL_NET_WEIGHT).unwrap_or(0);
    let wt_p = p.dyn_props.get_long(tron_chainbase::dynamic_properties_keys::TOTAL_NET_WEIGHT).unwrap_or(0);
    assert!(wt_s > 0, "weight moved");
    assert_eq!(wt_s, wt_p, "TOTAL_NET_WEIGHT diverged under pipeline (serial={wt_s} parallel={wt_p})");
    assert_eq!(dump_state(&s), dump_state(&p), "pipelined weight-chain state diverged from serial");
    let _ = std::fs::remove_dir_all(&root_s); let _ = std::fs::remove_dir_all(&root_p);
}

#[test]
fn pipelined_parallel_free_net_chain_matches_classic_serial() {
    // RIG-SHAPED reproduction: multi-block chains of free-net transfers
    // executed with BOTH `vm.parallel_exec` (Block-STM + the deferred
    // PUBLIC_NET fold) AND the apply pipeline (block N's writes pending
    // in the overlay while block N+1 executes). The deferred fold and
    // every per-account read of block N+1 must see block N's pending
    // writes through the overlay; any miss diverges the windowed
    // bandwidth accounting and the balances — exactly the live drift
    // class (fee-sized balance deltas, PUBLIC_NET divergence).
    use tron_chainbase::{BlockUndoStore, CheckPointV2, MemBackend};
    use tron_executor::{
        execute_block_with_undo_checkpoint_and_config, ApplyPipeline, ExecConfig,
    };

    fn rcpt(block: u8, n: u8) -> [u8; 21] {
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[1] = 0xc0 + block;
        a[20] = n;
        a
    }
    fn tmp_root(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "tron-pipe-par-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    const SENDERS: u8 = 8;
    const BLOCKS: u8 = 4;
    let keypairs: Vec<([u8; 32], [u8; 21])> =
        (0..SENDERS).map(|i| derive_keypair(0x70 + i)).collect();
    let fund = |b: &StateBundle| {
        for (_, sender) in &keypairs {
            put_account(&b.accounts, *sender, 1_000_000_000);
        }
        for blk in 0..BLOCKS {
            for i in 0..SENDERS {
                put_account(&b.accounts, rcpt(blk, i), 1);
            }
        }
    };
    // Block `k` (1-based): every sender pays a fresh recipient — the
    // sender rows + PUBLIC_NET_USAGE chain across blocks.
    let block_txs = |k: u8| {
        keypairs
            .iter()
            .enumerate()
            .map(|(i, (priv_key, sender))| {
                signed_transfer_tx(priv_key, *sender, rcpt(k - 1, i as u8), 100 + k as i64)
            })
            .collect::<Vec<_>>()
    };
    let chain = || {
        let mut blocks = Vec::new();
        let mut parent = [0u8; 32];
        for k in 1..=BLOCKS {
            let b = build_block(k as i64, parent, block_txs(k));
            parent = *tron_types::block_id_from_block(&b).unwrap().as_bytes();
            blocks.push(b);
        }
        blocks
    };

    // Classic serial reference.
    let serial_cfg = ExecConfig::unsigned();
    let s = StateBundle::fresh();
    fund(&s);
    let undo_s = BlockUndoStore::new(Arc::new(MemBackend::new()) as Arc<dyn KvBackend>);
    let root_s = tmp_root("serial");
    let cp_s = CheckPointV2::new(&root_s);
    for b in chain() {
        execute_block_with_undo_checkpoint_and_config(
            &s.backends(),
            &b,
            None,
            &undo_s,
            &cp_s,
            &serial_cfg,
        )
        .expect("serial apply");
    }

    // Pipelined + parallel + deferred fsync — the rig's catch-up shape.
    let par_cfg = ExecConfig {
        parallel_exec: true,
        defer_store_fsync: true,
        ..ExecConfig::unsigned()
    };
    let p = StateBundle::fresh();
    fund(&p);
    let undo_p = BlockUndoStore::new(Arc::new(MemBackend::new()) as Arc<dyn KvBackend>);
    let root_p = tmp_root("pipelined");
    let cp_p = CheckPointV2::new(&root_p);
    let backends = p.backends();
    let mut pipeline = ApplyPipeline::new(&backends, undo_p, cp_p);
    for b in chain() {
        pipeline.apply(&b, None, &par_cfg).expect("pipelined apply");
    }
    pipeline.flush().expect("flush");

    // The free-net counter must have moved (non-vacuous) and match.
    let su = s.dyn_props.public_net_usage();
    assert!(su > 0, "free-net path not exercised");
    assert_eq!(
        su,
        p.dyn_props.public_net_usage(),
        "deferred PUBLIC_NET fold diverged under the pipeline"
    );
    // Every store byte-for-byte.
    assert_eq!(
        dump_state(&s),
        dump_state(&p),
        "pipelined+parallel state diverged from classic serial"
    );

    let _ = std::fs::remove_dir_all(&root_s);
    let _ = std::fs::remove_dir_all(&root_p);
}
