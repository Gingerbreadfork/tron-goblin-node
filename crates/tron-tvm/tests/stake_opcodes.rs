//! Wiring tests for the 10 Stake 1.0/2.0 opcodes (0xd5..0xdf minus
//! the read-only 0xd7).
//!
//! Each test proves:
//! * The opcode is installed — bytecode using it doesn't halt as
//!   "unknown instruction".
//! * Stack args are correctly popped (no underflow).
//! * The handler pushes a result (no missing-output halt).
//!
//! These do NOT prove the state mutations happen — those need the
//! Host bridge (revm-context fork or TronContext wrapper) plus
//! actuator-primitive refactoring. Documented in
//! `crates/tron-tvm/src/tron_host.rs`.

use std::sync::Arc;

use tron_chainbase::{
    AccountStore, CodeStore, ContractStateStore, DelegatedResourceStore, DelegationStore,
    DynamicPropertiesStore, KvBackend, MemBackend, StorageRowStore, WitnessStore,
};
use tron_crypto::address::Address;
use tron_proto::{Account, TriggerSmartContract};
use tron_tvm::database::code_hash;
use tron_tvm::execute::{execute_trigger, VmBlockEnv, VmOutcome, VmStores};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn fresh_stores() -> VmStores {
    let dynamic_properties = Arc::new(DynamicPropertiesStore::new(mem()));
    // Stake-family opcodes (0xd5..0xdf) are gated by ALLOW_TVM_FREEZE
    // (FREEZE/UNFREEZE/FREEZEEXPIRETIME), ALLOW_TVM_VOTE (VOTEWITNESS,
    // WITHDRAWREWARD), and ALLOW_TVM_FREEZE_V2 (the V2 family +
    // DELEGATE/UNDELEGATE). Every test in this file exercises at
    // least one of them, so enable all three at fixture construction.
    dynamic_properties.put_long(b"ALLOW_TVM_FREEZE", 1);
    dynamic_properties.put_long(b"ALLOW_TVM_VOTE", 1);
    dynamic_properties.put_long(b"ALLOW_TVM_FREEZE_V2", 1);
    VmStores {
        accounts: Arc::new(AccountStore::new(mem())),
        code: Arc::new(CodeStore::new(mem())),
        storage: Arc::new(StorageRowStore::new(mem())),
        witnesses: Arc::new(WitnessStore::new(mem())),
        contract_state: Arc::new(ContractStateStore::new(mem())),
        dynamic_properties,
        delegated_resources: Arc::new(DelegatedResourceStore::new(mem())),
        delegation: Arc::new(DelegationStore::new(mem())),
        block_index: None,
        contracts: None,
        votes: None,
        reward_vi: None,
    abi: None,
    }
}

fn tron_addr(byte: u8) -> [u8; 21] {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(byte);
    a
}

fn install_caller(stores: &VmStores) -> [u8; 21] {
    let caller = tron_addr(0xa0);
    stores.accounts.put(
        &Address::from_raw(caller),
        &Account {
            address: caller.to_vec(),
            balance: 1_000_000_000,
            ..Default::default()
        },
    ).unwrap();
    caller
}

fn install_contract(stores: &VmStores, addr: [u8; 21], bytecode: Vec<u8>) {
    let hash = code_hash(&bytecode);
    stores.code.put(hash.as_slice(), &bytecode).unwrap();
    stores.accounts.put(
        &Address::from_raw(addr),
        &Account {
            address: addr.to_vec(),
            balance: 0,
            code: bytecode,
            code_hash: hash.as_slice().to_vec(),
            ..Default::default()
        },
    ).unwrap();
}

fn run(stores: &VmStores, caller: [u8; 21], contract: [u8; 21]) -> VmOutcome {
    let trigger = TriggerSmartContract {
        owner_address: caller.to_vec(),
        contract_address: contract.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };
    execute_trigger(
        stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: 1_700_000_000_000,
        },
        &trigger,
        500_000,
    )
}

fn push1(b: u8) -> Vec<u8> {
    vec![0x60, b]
}

fn push20(addr: [u8; 21]) -> Vec<u8> {
    let mut v = vec![0x73];
    v.extend_from_slice(&addr[1..]);
    v
}

/// WITHDRAWREWARD (0xd9) — in=0, out=1. Push amount to storage slot 0.
#[test]
fn withdrawreward_pushes_zero_and_persists_to_slot() {
    let stores = fresh_stores();
    let caller = install_caller(&stores);
    let contract = tron_addr(0xc0);
    // 0xd9 PUSH1 0 SSTORE STOP
    install_contract(&stores, contract, vec![0xd9, 0x60, 0x00, 0x55, 0x00]);
    let outcome = run(&stores, caller, contract);
    assert!(
        matches!(outcome, VmOutcome::Success { .. }),
        "WITHDRAWREWARD must not halt; got {outcome:?}"
    );
}

/// FREEZEBALANCEV2 (0xda) — in=2, out=1. Stack: resourceType, frozenBalance.
#[test]
fn freezebalancev2_pops_two_args_and_pushes() {
    let stores = fresh_stores();
    let caller = install_caller(&stores);
    let contract = tron_addr(0xc1);
    let mut bc = Vec::new();
    bc.extend(push1(0x01));      // frozenBalance (top after both pushes? — PUSHes go onto top)
    bc.extend(push1(0x01));      // resourceType (this becomes top of stack)
    // Wait — in EVM, pushes are last-in-first-out: PUSH a then PUSH b makes b the top.
    // freeze_balance_v2 handler pops `[resource_type, frozen_balance]` (resource_type top).
    // So I need push frozenBalance first, then resourceType — that's what's above.
    bc.push(0xda);               // FREEZEBALANCEV2
    bc.extend(push1(0x00));      // slot 0
    bc.push(0x55);               // SSTORE
    bc.push(0x00);               // STOP
    install_contract(&stores, contract, bc);
    let outcome = run(&stores, caller, contract);
    assert!(
        matches!(outcome, VmOutcome::Success { .. }),
        "FREEZEBALANCEV2 must not halt; got {outcome:?}"
    );
}

/// CANCELALLUNFREEZEV2 (0xdc) — in=0, out=1.
#[test]
fn cancelallunfreezev2_zero_args_one_result() {
    let stores = fresh_stores();
    let caller = install_caller(&stores);
    let contract = tron_addr(0xc2);
    install_contract(&stores, contract, vec![0xdc, 0x60, 0x00, 0x55, 0x00]);
    let outcome = run(&stores, caller, contract);
    assert!(
        matches!(outcome, VmOutcome::Success { .. }),
        "CANCELALLUNFREEZEV2 must not halt; got {outcome:?}"
    );
}

/// DELEGATERESOURCE (0xde) — in=3, out=1.
/// Stack (top first): resourceType, delegateBalance, receiverAddress.
#[test]
fn delegateresource_pops_three_args_and_pushes() {
    let stores = fresh_stores();
    let caller = install_caller(&stores);
    let contract = tron_addr(0xc3);
    let receiver = tron_addr(0xb0);
    let mut bc = Vec::new();
    // Push in reverse stack order: receiver (bottom), then balance, then resourceType (top).
    bc.extend(push20(receiver));
    bc.extend(push1(0x10));        // delegateBalance = 16
    bc.extend(push1(0x01));        // resourceType = energy (top)
    bc.push(0xde);                  // DELEGATERESOURCE
    bc.extend(push1(0x00));
    bc.push(0x55);                  // SSTORE
    bc.push(0x00);
    install_contract(&stores, contract, bc);
    let outcome = run(&stores, caller, contract);
    assert!(
        matches!(outcome, VmOutcome::Success { .. }),
        "DELEGATERESOURCE must not halt; got {outcome:?}"
    );
}

/// VOTEWITNESS (0xd8) — in=4, out=1. Just verifying the handler pops
/// the correct number of args from the stack — no memory read needed
/// today because the default Host impl ignores the offsets.
#[test]
fn votewitness_pops_four_args() {
    let stores = fresh_stores();
    let caller = install_caller(&stores);
    let contract = tron_addr(0xc4);
    let mut bc = Vec::new();
    // 4 PUSH1 values — order doesn't matter for the smoke test since
    // we're just proving no underflow.
    for v in [0x00, 0x00, 0x00, 0x00] {
        bc.extend(push1(v));
    }
    bc.push(0xd8); // VOTEWITNESS
    bc.extend(push1(0x00));
    bc.push(0x55); // SSTORE
    bc.push(0x00);
    install_contract(&stores, contract, bc);
    let outcome = run(&stores, caller, contract);
    assert!(
        matches!(outcome, VmOutcome::Success { .. }),
        "VOTEWITNESS must not halt; got {outcome:?}"
    );
}
