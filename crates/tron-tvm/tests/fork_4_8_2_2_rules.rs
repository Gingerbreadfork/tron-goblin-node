//! java-tron 4.8.2.2 (`VERSION_4_8_2_2`, block version 37) deterministic
//! `OutOfTimeException` rules: FreezeBalanceV2 by a self-destructed owner,
//! SELFDESTRUCT to a self-destructed beneficiary, Stake-2.0 withdrawals on an
//! account with a negative delegated-out balance, and a CreateSmartContract
//! carrying `code_hash` / `trx_hash`. Each rule is gated on the fork having
//! passed; without it the pre-fork behaviour is unchanged.

use std::sync::Arc;

use tron_chainbase::fork::VERSION_4_8_2_2;
use tron_chainbase::{
    AccountStore, CodeStore, ContractStateStore, DelegatedResourceStore, DelegationStore,
    DynamicPropertiesStore, KvBackend, MemBackend, StorageRowStore, VotesStore, WitnessStore,
};
use tron_crypto::address::Address;
use tron_proto::account::{AccountResource, FreezeV2};
use tron_proto::transaction::result::ContractResult;
use tron_proto::{Account, CreateSmartContract, SmartContract, TriggerSmartContract};
use tron_tvm::database::code_hash;
use tron_tvm::execute::{execute_create, execute_trigger, VmBlockEnv, VmOutcome, VmStores};

const NOW_MS: i64 = 1_700_000_000_000;
const LIMIT: u64 = 1_000_000;
const TRX: i64 = 1_000_000;

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn stores() -> VmStores {
    let dp = Arc::new(DynamicPropertiesStore::new(mem()));
    for k in [
        "ALLOW_TVM_TRANSFER_TRC10",
        "ALLOW_TVM_CONSTANTINOPLE",
        "ALLOW_TVM_SOLIDITY_059",
        "ALLOW_TVM_ISTANBUL",
        "ALLOW_TVM_FREEZE",
        "ALLOW_TVM_VOTE",
        "ALLOW_TVM_LONDON",
        "ALLOW_TVM_SHANGHAI",
        "ALLOW_TVM_CANCUN",
        "ALLOW_ENERGY_ADJUSTMENT",
        "ALLOW_HIGHER_LIMIT_FOR_MAX_CPU_TIME_OF_ONE_TX",
        "ALLOW_TVM_SELFDESTRUCT_RESTRICTION",
        "ALLOW_NEW_RESOURCE_MODEL",
        "ALLOW_DELEGATE_RESOURCE",
    ] {
        dp.put_long(k.as_bytes(), 1);
    }
    dp.put_long(b"UNFREEZE_DELAY_DAYS", 14);
    dp.save_latest_block_header_timestamp(NOW_MS);
    VmStores {
        accounts: Arc::new(AccountStore::new(mem())),
        code: Arc::new(CodeStore::new(mem())),
        storage: Arc::new(StorageRowStore::new(mem())),
        witnesses: Arc::new(WitnessStore::new(mem())),
        contract_state: Arc::new(ContractStateStore::new(mem())),
        dynamic_properties: dp,
        delegated_resources: Arc::new(DelegatedResourceStore::new(mem())),
        delegated_resource_account_index: None,
        delegation: Arc::new(DelegationStore::new(mem())),
        block_index: None,
        contracts: None,
        votes: Some(Arc::new(VotesStore::new(mem()))),
        reward_vi: None,
        abi: None,
    }
}

/// Twenty-seven adopters of version 37: `ForkController.pass(VERSION_4_8_2_2)`.
fn pass_fork(stores: &VmStores) {
    stores
        .dynamic_properties
        .save_fork_stats(VERSION_4_8_2_2, &[1u8; 27]);
    assert!(stores.dynamic_properties.fork_passed(VERSION_4_8_2_2));
}

fn tron_addr(byte: u8) -> [u8; 21] {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(byte);
    a
}

fn push1(v: u8) -> Vec<u8> {
    vec![0x60, v]
}

fn push20(addr: [u8; 21]) -> Vec<u8> {
    let mut out = vec![0x73];
    out.extend_from_slice(&addr[1..]);
    out
}

fn push_u256(word: [u8; 32]) -> Vec<u8> {
    let mut out = vec![0x7f];
    out.extend_from_slice(&word);
    out
}

fn word_u64(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

/// `CALL(gas, target, 0, 0, args_len, 0, 0); POP`.
fn call_code(target: [u8; 21], args_len: u8) -> Vec<u8> {
    let mut bc = Vec::new();
    bc.extend(push1(0));
    bc.extend(push1(0));
    bc.extend(push1(args_len));
    bc.extend(push1(0));
    bc.extend(push1(0));
    bc.extend(push20(target));
    bc.push(0x5a); // GAS
    bc.push(0xf1); // CALL
    bc.push(0x50); // POP
    bc
}

/// `PUSH20 <beneficiary> SELFDESTRUCT`.
fn suicide_code(beneficiary: [u8; 21]) -> Vec<u8> {
    let mut bc = push20(beneficiary);
    bc.push(0xff);
    bc
}

/// `<opcode>(amount, resource)` with the result flag stored in slot 0.
fn stake_v2_code(opcode: u8, amount: [u8; 32], resource: [u8; 32]) -> Vec<u8> {
    let mut bc = Vec::new();
    bc.extend(push_u256(amount));
    bc.extend(push_u256(resource));
    bc.push(opcode);
    bc.extend(push1(0));
    bc.push(0x55); // SSTORE
    bc.push(0x00); // STOP
    bc
}

/// `<opcode>()` (no stack inputs) with the result stored in slot 0.
fn stake_v2_nullary_code(opcode: u8) -> Vec<u8> {
    let mut bc = vec![opcode];
    bc.extend(push1(0));
    bc.push(0x55);
    bc.push(0x00);
    bc
}

/// Empty calldata: SELFDESTRUCT to self. Any calldata: FREEZEBALANCEV2 1 TRX
/// of energy, flag into slot 0.
fn selfdestruct_or_freeze_code(me: [u8; 21]) -> Vec<u8> {
    let mut bc = vec![0x36]; // CALLDATASIZE
    let dest = 1 + 2 + 1 + 21 + 1;
    bc.extend(push1(dest as u8));
    bc.push(0x57); // JUMPI
    bc.extend(suicide_code(me));
    assert_eq!(bc.len(), dest);
    bc.push(0x5b); // JUMPDEST
    bc.extend(stake_v2_code(0xda, word_u64(TRX as u64), word_u64(1)));
    bc
}

fn install(stores: &VmStores, addr: [u8; 21], bytecode: Vec<u8>, mut account: Account) {
    let hash = code_hash(&bytecode);
    stores.code.put(hash.as_slice(), &bytecode).unwrap();
    account.address = addr.to_vec();
    account.code = bytecode;
    account.code_hash = hash.as_slice().to_vec();
    stores.accounts.put(&Address::from_raw(addr), &account).unwrap();
}

fn funded(balance: i64) -> Account {
    Account {
        balance,
        ..Default::default()
    }
}

fn caller(stores: &VmStores) -> [u8; 21] {
    let who = tron_addr(0x01);
    stores
        .accounts
        .put(
            &Address::from_raw(who),
            &Account {
                address: who.to_vec(),
                balance: 1_000 * TRX,
                ..Default::default()
            },
        )
        .unwrap();
    who
}

fn run(stores: &VmStores, contract: [u8; 21]) -> VmOutcome {
    let from = caller(stores);
    execute_trigger(
        stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: NOW_MS,
            ..Default::default()
        },
        &TriggerSmartContract {
            owner_address: from.to_vec(),
            contract_address: contract.to_vec(),
            call_value: 0,
            data: vec![],
            call_token_value: 0,
            token_id: 0,
        },
        LIMIT,
    )
}

fn assert_out_of_time(out: VmOutcome) {
    match out {
        VmOutcome::Halt {
            result, energy_used, ..
        } => {
            assert_eq!(result, ContractResult::OutOfTime, "java OutOfTimeException");
            assert_eq!(energy_used, LIMIT, "spendAllEnergy");
        }
        other => panic!("expected OUT_OF_TIME, got {other:?}"),
    }
}

fn assert_success(out: VmOutcome) {
    assert!(matches!(out, VmOutcome::Success { .. }), "expected Success, got {out:?}");
}

fn flag_slot(stores: &VmStores, addr: [u8; 21]) -> u8 {
    let key = StorageRowStore::compose_key(&Address::from_raw(addr), &[0u8; 32]);
    stores.storage.get(&key).unwrap().map(|b| b[31]).unwrap_or(0)
}

fn account_of(stores: &VmStores, addr: [u8; 21]) -> Account {
    stores.accounts.get(&Address::from_raw(addr)).unwrap().unwrap()
}

// ---------------------------------------------------------------------------
// SELFDESTRUCT to a self-destructed beneficiary
// ---------------------------------------------------------------------------

/// The contract destroys itself to itself twice in one transaction; the
/// second beneficiary check finds the mark left by the first.
fn double_selfdestruct(stores: &VmStores) -> VmOutcome {
    let a = tron_addr(0xa0);
    let b = tron_addr(0xb0);
    install(stores, b, suicide_code(b), funded(5 * TRX));
    let mut code = call_code(b, 0);
    code.extend(call_code(b, 0));
    code.push(0x00);
    install(stores, a, code, funded(0));
    run(stores, a)
}

#[test]
fn selfdestruct_to_a_selfdestructed_beneficiary_is_out_of_time_after_the_fork() {
    let stores = stores();
    pass_fork(&stores);
    assert_out_of_time(double_selfdestruct(&stores));
}

#[test]
fn selfdestruct_to_a_selfdestructed_beneficiary_runs_before_the_fork() {
    let stores = stores();
    assert_success(double_selfdestruct(&stores));
}

// ---------------------------------------------------------------------------
// FreezeBalanceV2 by a self-destructed owner
// ---------------------------------------------------------------------------

fn freeze_after_selfdestruct(stores: &VmStores) -> ([u8; 21], VmOutcome) {
    let a = tron_addr(0xa1);
    let b = tron_addr(0xb1);
    install(stores, b, selfdestruct_or_freeze_code(b), funded(5 * TRX));
    let mut code = call_code(b, 0);
    code.extend(call_code(b, 1));
    code.push(0x00);
    install(stores, a, code, funded(0));
    (b, run(stores, a))
}

#[test]
fn freeze_v2_by_a_selfdestructed_owner_is_out_of_time_after_the_fork() {
    let stores = stores();
    pass_fork(&stores);
    let (_, out) = freeze_after_selfdestruct(&stores);
    assert_out_of_time(out);
}

#[test]
fn freeze_v2_by_a_selfdestructed_owner_runs_before_the_fork() {
    let stores = stores();
    let (b, out) = freeze_after_selfdestruct(&stores);
    assert_success(out);
    assert_eq!(flag_slot(&stores, b), 1);
    let frozen: i64 = account_of(&stores, b)
        .frozen_v2
        .iter()
        .filter(|f| f.r#type == 1)
        .map(|f| f.amount)
        .sum();
    assert_eq!(frozen, TRX);
}

// ---------------------------------------------------------------------------
// Stake-2.0 withdrawals on an account with a negative delegated-out balance
// ---------------------------------------------------------------------------

fn invalid_bandwidth_account() -> Account {
    Account {
        balance: 10 * TRX,
        frozen_v2: vec![FreezeV2 {
            r#type: 1,
            amount: 5 * TRX,
        }],
        delegated_frozen_v2_balance_for_bandwidth: -1,
        ..Default::default()
    }
}

fn invalid_energy_account() -> Account {
    Account {
        balance: 10 * TRX,
        frozen_v2: vec![FreezeV2 {
            r#type: 1,
            amount: 5 * TRX,
        }],
        account_resource: Some(AccountResource {
            delegated_frozen_v2_balance_for_energy: -1,
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn unfreeze_code() -> Vec<u8> {
    stake_v2_code(0xdb, word_u64(TRX as u64), word_u64(1))
}

#[test]
fn unfreeze_v2_with_negative_delegated_bandwidth_is_out_of_time_after_the_fork() {
    let stores = stores();
    pass_fork(&stores);
    let c = tron_addr(0xc1);
    install(&stores, c, unfreeze_code(), invalid_bandwidth_account());
    assert_out_of_time(run(&stores, c));
}

#[test]
fn unfreeze_v2_with_negative_delegated_bandwidth_runs_before_the_fork() {
    let stores = stores();
    let c = tron_addr(0xc1);
    install(&stores, c, unfreeze_code(), invalid_bandwidth_account());
    assert_success(run(&stores, c));
    assert_eq!(flag_slot(&stores, c), 1);
    assert_eq!(account_of(&stores, c).unfrozen_v2.len(), 1);
}

#[test]
fn unfreeze_v2_rejected_for_other_reasons_is_not_out_of_time() {
    // The invalid-delegation check is the LAST validation: an unfreeze of
    // more than is staked fails the earlier balance check and pushes 0.
    let stores = stores();
    pass_fork(&stores);
    let c = tron_addr(0xc2);
    install(
        &stores,
        c,
        stake_v2_code(0xdb, word_u64(50 * TRX as u64), word_u64(1)),
        invalid_bandwidth_account(),
    );
    assert_success(run(&stores, c));
    assert_eq!(flag_slot(&stores, c), 0);
}

#[test]
fn cancel_all_unfreeze_v2_with_negative_delegated_energy_is_out_of_time_after_the_fork() {
    let stores = stores();
    pass_fork(&stores);
    let c = tron_addr(0xc3);
    install(&stores, c, stake_v2_nullary_code(0xdc), invalid_energy_account());
    assert_out_of_time(run(&stores, c));
}

#[test]
fn cancel_all_unfreeze_v2_with_negative_delegated_energy_runs_before_the_fork() {
    let stores = stores();
    let c = tron_addr(0xc3);
    install(&stores, c, stake_v2_nullary_code(0xdc), invalid_energy_account());
    assert_success(run(&stores, c));
}

#[test]
fn withdraw_expire_unfreeze_with_negative_delegation_is_out_of_time_even_with_nothing_matured() {
    let stores = stores();
    pass_fork(&stores);
    let c = tron_addr(0xc4);
    install(&stores, c, stake_v2_nullary_code(0xdd), invalid_bandwidth_account());
    assert_out_of_time(run(&stores, c));
}

#[test]
fn withdraw_expire_unfreeze_with_negative_delegation_runs_before_the_fork() {
    let stores = stores();
    let c = tron_addr(0xc4);
    install(&stores, c, stake_v2_nullary_code(0xdd), invalid_bandwidth_account());
    assert_success(run(&stores, c));
    assert_eq!(flag_slot(&stores, c), 0);
}

// ---------------------------------------------------------------------------
// CreateSmartContract carrying code_hash / trx_hash
// ---------------------------------------------------------------------------

fn create_with(stores: &VmStores, code_hash_field: Vec<u8>, trx_hash_field: Vec<u8>) -> VmOutcome {
    let from = caller(stores);
    let create = CreateSmartContract {
        owner_address: from.to_vec(),
        new_contract: Some(SmartContract {
            origin_address: from.to_vec(),
            // PUSH1 1 PUSH1 0 RETURN: a one-byte STOP runtime.
            bytecode: vec![0x60, 0x01, 0x60, 0x00, 0xf3],
            consume_user_resource_percent: 100,
            origin_energy_limit: 1_000_000,
            code_hash: code_hash_field,
            trx_hash: trx_hash_field,
            ..Default::default()
        }),
        call_token_value: 0,
        token_id: 0,
    };
    execute_create(
        stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: NOW_MS,
            ..Default::default()
        },
        &create,
        &[0xab; 32],
        LIMIT,
    )
}

#[test]
fn create_with_code_hash_set_is_out_of_time_after_the_fork() {
    let stores = stores();
    pass_fork(&stores);
    assert_out_of_time(create_with(&stores, vec![1u8; 32], vec![]));
}

#[test]
fn create_with_trx_hash_set_is_out_of_time_after_the_fork() {
    let stores = stores();
    pass_fork(&stores);
    assert_out_of_time(create_with(&stores, vec![], vec![2u8; 32]));
}

#[test]
fn create_with_empty_hash_fields_deploys_after_the_fork() {
    let stores = stores();
    pass_fork(&stores);
    assert_success(create_with(&stores, vec![], vec![]));
}

#[test]
fn create_with_hash_fields_set_deploys_before_the_fork() {
    let stores = stores();
    assert_success(create_with(&stores, vec![1u8; 32], vec![2u8; 32]));
}
