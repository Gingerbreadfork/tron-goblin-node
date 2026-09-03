//! Parity fixes for TVM opcode / precompile / context semantics that a deep
//! audit found diverging from java-tron 4.8.1.1. Each test runs a tiny contract
//! through the real EVM (`execute_trigger`) and asserts the java-exact behavior:
//!
//! * GASLIMIT (0x45) pushes 0 (java `gasLimitAction`, OperationActions.java:517).
//! * BASEFEE (0x48) pushes `getEnergyFee()` (java `baseFeeAction`, :538).
//! * GASPRICE (0x3a) pushes 0 unless `allowTvmCompatibleEvm() && version==1`,
//!   then `getEnergyFee()` (java `gasPriceAction`, :431).
//! * The EIP-150 1/64 retention on CALL is per-frame version-gated: a version-0
//!   caller forwards ALL energy even with `ALLOW_TVM_COMPATIBLE_EVM` on; a
//!   version-1 caller retains 1/64 (java `Program.getCallEnergy`, :1856).
//! * A staking opcode in a STATIC context reverts before bumping the internal-tx
//!   nonce (java `delegateResourceAction` throws StaticCallModificationException
//!   before increaseNonce, OperationActions.java:869 / Program.java:2177).

use std::sync::Arc;

use tron_chainbase::{
    AccountStore, CodeStore, ContractStateStore, ContractStore, DelegatedResourceStore,
    DelegationStore, DynamicPropertiesStore, KvBackend, MemBackend, StorageRowStore, VotesStore,
    WitnessStore,
};
use tron_crypto::address::Address;
use tron_proto::{Account, SmartContract};
use tron_tvm::database::code_hash;
use tron_tvm::execute::{execute_trigger, VmBlockEnv, VmOutcome, VmStores};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

/// Fresh stores with a `ContractStore` attached (needed for the per-frame
/// contract-version lookup) and the energy fee + compatible-EVM proposal set.
fn fresh_stores() -> (VmStores, Arc<ContractStore>) {
    let dynamic_properties = Arc::new(DynamicPropertiesStore::new(mem()));
    dynamic_properties.put_long(b"ENERGY_FEE", 210);
    dynamic_properties.save_latest_block_header_timestamp(1_700_000_000_000);
    let contracts = Arc::new(ContractStore::new(mem()));
    let stores = VmStores {
        accounts: Arc::new(AccountStore::new(mem())),
        code: Arc::new(CodeStore::new(mem())),
        storage: Arc::new(StorageRowStore::new(mem())),
        witnesses: Arc::new(WitnessStore::new(mem())),
        contract_state: Arc::new(ContractStateStore::new(mem())),
        dynamic_properties,
        delegated_resources: Arc::new(DelegatedResourceStore::new(mem())),
        delegated_resource_account_index: None,
        delegation: Arc::new(DelegationStore::new(mem())),
        block_index: None,
        contracts: Some(Arc::clone(&contracts)),
        votes: Some(Arc::new(VotesStore::new(mem()))),
        reward_vi: None,
        abi: None,
    };
    (stores, contracts)
}

fn tron_addr(byte: u8) -> [u8; 21] {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(byte);
    a
}

fn install_contract(stores: &VmStores, addr: [u8; 21], bytecode: Vec<u8>, balance: i64) {
    let hash = code_hash(&bytecode);
    stores.code.put(hash.as_slice(), &bytecode).unwrap();
    stores
        .accounts
        .put(
            &Address::from_raw(addr),
            &Account {
                address: addr.to_vec(),
                balance,
                code: bytecode,
                code_hash: hash.as_slice().to_vec(),
                r#type: tron_proto::AccountType::Contract as i32,
                ..Default::default()
            },
        )
        .unwrap();
}

/// Write the `SmartContract` row that the per-frame version lookup reads.
fn set_contract_version(contracts: &ContractStore, addr: [u8; 21], version: i32) {
    contracts
        .put(
            &Address::from_raw(addr),
            &SmartContract {
                contract_address: addr.to_vec(),
                version,
                ..Default::default()
            },
        )
        .unwrap();
}

fn install_eoa(stores: &VmStores, addr: [u8; 21], balance: i64) {
    stores
        .accounts
        .put(
            &Address::from_raw(addr),
            &Account { address: addr.to_vec(), balance, ..Default::default() },
        )
        .unwrap();
}

fn trigger(from: [u8; 21], to: [u8; 21]) -> tron_proto::TriggerSmartContract {
    tron_proto::TriggerSmartContract {
        owner_address: from.to_vec(),
        contract_address: to.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    }
}

fn run(stores: &VmStores, from: [u8; 21], to: [u8; 21]) -> VmOutcome {
    execute_trigger(
        stores,
        VmBlockEnv { block_number: 100, block_timestamp_ms: 1_700_000_000_000, ..Default::default()},
        &trigger(from, to),
        5_000_000,
    )
}

/// `OPCODE; PUSH1 0; MSTORE; PUSH1 32; PUSH1 0; RETURN` — return the 32-byte
/// word the opcode pushed, so the test can read it from `return_data`.
fn return_opcode(opcode: u8) -> Vec<u8> {
    vec![
        opcode, // pushes a 32-byte word
        0x60, 0x00, // PUSH1 0
        0x52, // MSTORE (mem[0..32] = word)
        0x60, 0x20, // PUSH1 32
        0x60, 0x00, // PUSH1 0
        0xf3, // RETURN(0, 32)
    ]
}

fn return_word(outcome: &VmOutcome) -> [u8; 32] {
    match outcome {
        VmOutcome::Success { return_data, .. } => {
            let mut w = [0u8; 32];
            assert_eq!(return_data.len(), 32, "expected a 32-byte return");
            w.copy_from_slice(return_data);
            w
        }
        other => panic!("expected Success, got {other:?}"),
    }
}

fn word_to_u64(w: &[u8; 32]) -> u64 {
    u64::from_be_bytes(w[24..32].try_into().unwrap())
}

// =============================================================================
// #6 GASLIMIT (0x45) → 0
// =============================================================================

#[test]
fn gaslimit_pushes_zero() {
    let (stores, _contracts) = fresh_stores();
    let caller = tron_addr(0xa1);
    let c = tron_addr(0xc1);
    install_eoa(&stores, caller, 0);
    install_contract(&stores, c, return_opcode(0x45), 0); // GASLIMIT
    let out = run(&stores, caller, c);
    assert_eq!(
        word_to_u64(&return_word(&out)),
        0,
        "GASLIMIT must push 0 (java gasLimitAction)"
    );
}

// =============================================================================
// #7 BASEFEE (0x48) → getEnergyFee()
// =============================================================================

#[test]
fn basefee_pushes_energy_fee() {
    let (stores, _contracts) = fresh_stores();
    // BASEFEE requires the London opcode spec; ALLOW_TVM_LONDON resolves it.
    stores.dynamic_properties.put_long(b"ALLOW_TVM_LONDON", 1);
    let caller = tron_addr(0xa1);
    let c = tron_addr(0xc1);
    install_eoa(&stores, caller, 0);
    install_contract(&stores, c, return_opcode(0x48), 0); // BASEFEE
    let out = run(&stores, caller, c);
    assert_eq!(
        word_to_u64(&return_word(&out)),
        210,
        "BASEFEE must push getEnergyFee() = 210 (java baseFeeAction)"
    );
}

// =============================================================================
// #8 GASPRICE (0x3a) — version-gated
// =============================================================================

#[test]
fn gasprice_zero_for_version_0_contract() {
    let (stores, contracts) = fresh_stores();
    stores.dynamic_properties.put_long(b"ALLOW_TVM_COMPATIBLE_EVM", 1);
    let caller = tron_addr(0xa1);
    let c = tron_addr(0xc1);
    install_eoa(&stores, caller, 0);
    install_contract(&stores, c, return_opcode(0x3a), 0); // GASPRICE
    set_contract_version(&contracts, c, 0); // legacy
    let out = run(&stores, caller, c);
    assert_eq!(
        word_to_u64(&return_word(&out)),
        0,
        "GASPRICE must push 0 for a version-0 contract even with the flag on"
    );
}

#[test]
fn gasprice_energy_fee_for_version_1_contract() {
    let (stores, contracts) = fresh_stores();
    stores.dynamic_properties.put_long(b"ALLOW_TVM_COMPATIBLE_EVM", 1);
    let caller = tron_addr(0xa1);
    let c = tron_addr(0xc1);
    install_eoa(&stores, caller, 0);
    install_contract(&stores, c, return_opcode(0x3a), 0); // GASPRICE
    set_contract_version(&contracts, c, 1); // post-fork
    let out = run(&stores, caller, c);
    assert_eq!(
        word_to_u64(&return_word(&out)),
        210,
        "GASPRICE must push getEnergyFee()=210 for a version-1 contract with the flag on"
    );
}

#[test]
fn gasprice_zero_for_version_1_when_flag_off() {
    let (stores, contracts) = fresh_stores();
    // ALLOW_TVM_COMPATIBLE_EVM deliberately omitted (off).
    let caller = tron_addr(0xa1);
    let c = tron_addr(0xc1);
    install_eoa(&stores, caller, 0);
    install_contract(&stores, c, return_opcode(0x3a), 0); // GASPRICE
    set_contract_version(&contracts, c, 1);
    let out = run(&stores, caller, c);
    assert_eq!(
        word_to_u64(&return_word(&out)),
        0,
        "GASPRICE must push 0 when allowTvmCompatibleEvm is off, regardless of version"
    );
}

// =============================================================================
// #1 Per-frame contract-version gates the EIP-150 1/64 retention on CALL.
// =============================================================================
//
// The caller CALLs a child requesting "all" gas (a u64::MAX request, so the
// forwarded amount is the caller's `available` energy). The child does GAS
// (0x5a) and RETURNs its own remaining energy at entry; the caller copies that
// 32-byte value out and RETURNs it, so the test reads exactly how much energy
// the child was forwarded. java's `getCallEnergy` reduces `available` by 1/64
// ONLY for a version-1 frame (with `allowTvmCompatibleEvm` on); a version-0
// frame forwards the full `available`. So the version-1 child must see ~1/64
// LESS than the version-0 child for the identical setup.

/// CALLER: CALL(gas=u64::MAX, to=child, value=0, in 0/0, out 0/32); then
/// RETURN(0,32) — bubbling the child's returned 32-byte word (its entry GAS).
fn caller_forwards_all(child_evm: &[u8; 20]) -> Vec<u8> {
    let mut bc = Vec::new();
    bc.extend_from_slice(&[0x60, 0x20]); // PUSH1 32  (outLen)
    bc.extend_from_slice(&[0x60, 0x00]); // PUSH1 0   (outOff)
    bc.extend_from_slice(&[0x60, 0x00]); // PUSH1 0   (inLen)
    bc.extend_from_slice(&[0x60, 0x00]); // PUSH1 0   (inOff)
    bc.extend_from_slice(&[0x60, 0x00]); // PUSH1 0   (value)
    bc.push(0x73); // PUSH20 to
    bc.extend_from_slice(child_evm);
    bc.push(0x7f); // PUSH32 u64::MAX (request "all" gas)
    let mut g = [0u8; 32];
    g[24..].copy_from_slice(&u64::MAX.to_be_bytes());
    bc.extend_from_slice(&g);
    bc.push(0xf1); // CALL
    bc.push(0x50); // POP the success flag (child's RETURN data is already in mem 0..32)
    bc.extend_from_slice(&[0x60, 0x20, 0x60, 0x00]); // PUSH1 32 PUSH1 0
    bc.push(0xf3); // RETURN(0,32) — the child's entry-GAS word
    bc
}

/// CHILD: GAS; PUSH1 0; MSTORE; PUSH1 32; PUSH1 0; RETURN — return entry GAS.
const CHILD_RETURNS_GAS: &[u8] = &[0x5a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];

/// Forward energy to the child and read back the child's entry-GAS, for a caller
/// of the given contract version with `ALLOW_TVM_COMPATIBLE_EVM` set as given.
fn child_entry_gas(caller_version: i32, flag_on: bool) -> u64 {
    let (stores, contracts) = fresh_stores();
    if flag_on {
        stores.dynamic_properties.put_long(b"ALLOW_TVM_COMPATIBLE_EVM", 1);
    }
    let caller_user = tron_addr(0xa1);
    let caller_c = tron_addr(0xc1);
    let child = tron_addr(0xb1);
    let child_evm: [u8; 20] = child[1..].try_into().unwrap();
    install_eoa(&stores, caller_user, 0);
    install_contract(&stores, caller_c, caller_forwards_all(&child_evm), 0);
    install_contract(&stores, child, CHILD_RETURNS_GAS.to_vec(), 0);
    set_contract_version(&contracts, caller_c, caller_version);
    let out = run(&stores, caller_user, caller_c);
    word_to_u64(&return_word(&out))
}

#[test]
fn version_0_caller_forwards_all_energy_on_call() {
    // flag on, version-0 caller → no 1/64 retention; the child sees (essentially)
    // all the caller's remaining energy.
    let v0_flag_on = child_entry_gas(0, true);
    // The same with the flag OFF must be identical (flag-off never retains either).
    let v0_flag_off = child_entry_gas(0, false);
    assert_eq!(
        v0_flag_on, v0_flag_off,
        "a version-0 caller forwards all energy whether or not the flag is on"
    );
    assert!(v0_flag_on > 4_000_000, "child should be forwarded most of the 5M budget");
}

#[test]
fn version_1_caller_retains_64th_on_call() {
    let v1 = child_entry_gas(1, true); // retains 1/64
    let v0 = child_entry_gas(0, true); // forwards all
    assert!(
        v1 < v0,
        "version-1 caller must retain 1/64 → child sees less energy (v1={v1}, v0={v0})"
    );
    // The retention is ~1/64 of the caller's available energy: v1 ≈ v0 * 63/64.
    // Allow a small slack for the GAS-opcode cost and rounding.
    let expected_v1 = v0 - v0 / 64;
    let slack = 100u64;
    assert!(
        v1 >= expected_v1.saturating_sub(slack) && v1 <= expected_v1 + slack,
        "v1 ({v1}) should be ~63/64 of v0 ({v0}); expected ≈ {expected_v1}"
    );
}

// =============================================================================
// #3 Static-context staking opcode reverts before any state mutation / nonce.
// =============================================================================
//
// A STATICCALL into a contract that runs DELEGATERESOURCE must revert
// (StaticCallModificationException → spendAllEnergy), and the delegate must NOT
// mutate state. We observe this by checking the inner DELEGATERESOURCE never
// committed a DelegatedResource row.

/// INNER: PUSH the DELEGATERESOURCE args [resourceType, balance, receiver] then
/// DELEGATERESOURCE (0xde); STOP.
fn inner_delegates(receiver_evm: &[u8; 20], balance: u64, resource_type: u8) -> Vec<u8> {
    let mut bc = Vec::new();
    // Stack (top first): resourceType, delegateBalance, receiverAddress.
    bc.push(0x73); // PUSH20 receiver
    bc.extend_from_slice(receiver_evm);
    bc.push(0x7f); // PUSH32 balance
    let mut b = [0u8; 32];
    b[24..].copy_from_slice(&balance.to_be_bytes());
    bc.extend_from_slice(&b);
    bc.extend_from_slice(&[0x60, resource_type]); // PUSH1 resourceType (top)
    bc.push(0xde); // DELEGATERESOURCE
    bc.push(0x00); // STOP
    bc
}

/// OUTER: STATICCALL(gas, inner, in 0/0, out 0/0); POP; STOP. The static context
/// propagates into the inner frame, so its DELEGATERESOURCE must revert.
fn outer_staticcalls(inner_evm: &[u8; 20]) -> Vec<u8> {
    let mut bc = Vec::new();
    // STATICCALL stack (top first): gas, to, inOff, inLen, outOff, outLen.
    bc.extend_from_slice(&[0x60, 0x00]); // outLen
    bc.extend_from_slice(&[0x60, 0x00]); // outOff
    bc.extend_from_slice(&[0x60, 0x00]); // inLen
    bc.extend_from_slice(&[0x60, 0x00]); // inOff
    bc.push(0x73); // PUSH20 to
    bc.extend_from_slice(inner_evm);
    bc.extend_from_slice(&[0x62, 0x0f, 0x42, 0x40]); // PUSH3 1_000_000 (gas)
    bc.push(0xfa); // STATICCALL
    bc.push(0x50); // POP
    bc.push(0x00); // STOP
    bc
}

// =============================================================================
// SSTORE-to-zero DELETES the storage row (java Storage.commit isZero -> delete).
// =============================================================================

#[test]
fn sstore_to_zero_deletes_the_storage_row() {
    // java `Storage.commit()` (org.tron.core.vm.program.Storage): a dirty row
    // whose committed value is zero is `store.delete`d, not persisted as a
    // 32-byte-zero row. Pre-seed slot 7 with a non-zero value (so a row
    // exists), run a contract that SSTOREs 0 there, and assert the row is gone.
    let (stores, _contracts) = fresh_stores();
    let caller = tron_addr(0xa1);
    let c = tron_addr(0xc1);

    // SSTORE(key=7, value=0): PUSH1 0 (value); PUSH1 7 (key); SSTORE; STOP.
    let bytecode = vec![0x60, 0x00, 0x60, 0x07, 0x55, 0x00];
    install_eoa(&stores, caller, 0);
    install_contract(&stores, c, bytecode, 0);

    // Pre-seed slot 7 with a non-zero value so there is a row to delete and the
    // VM sees original_value != 0 (forcing a committed write of the new zero).
    let mut slot7 = [0u8; 32];
    slot7[31] = 7;
    let key = StorageRowStore::compose_key(&Address::from_raw(c), &slot7);
    let mut nonzero = [0u8; 32];
    nonzero[31] = 0x2a;
    stores.storage.put(&key, &nonzero).unwrap();
    assert!(stores.storage.get(&key).unwrap().is_some(), "pre-seed failed");

    let out = run(&stores, caller, c);
    assert!(matches!(out, VmOutcome::Success { .. }), "got {out:?}");

    assert!(
        stores.storage.get(&key).unwrap().is_none(),
        "SSTORE-to-zero must DELETE the row, not persist a 32-byte-zero row"
    );
}

#[test]
fn static_context_delegate_reverts_without_mutation() {
    let (stores, _contracts) = fresh_stores();
    stores.dynamic_properties.put_long(b"UNFREEZE_DELAY_DAYS", 14); // FreezeV2 active
    let caller_user = tron_addr(0xa1);
    let outer = tron_addr(0xc1);
    let inner = tron_addr(0xb1);
    let receiver = tron_addr(0xd1);
    let inner_evm: [u8; 20] = inner[1..].try_into().unwrap();
    let receiver_evm: [u8; 20] = receiver[1..].try_into().unwrap();

    install_eoa(&stores, caller_user, 0);
    install_contract(&stores, outer, outer_staticcalls(&inner_evm), 0);
    // Inner has 100 TRX frozen-V2 for bandwidth so the delegate WOULD be valid
    // were it not in a static context.
    let hash = code_hash(&inner_delegates(&receiver_evm, 1_000_000, 0));
    let inner_code = inner_delegates(&receiver_evm, 1_000_000, 0);
    stores.code.put(hash.as_slice(), &inner_code).unwrap();
    stores
        .accounts
        .put(
            &Address::from_raw(inner),
            &Account {
                address: inner.to_vec(),
                code: inner_code,
                code_hash: hash.as_slice().to_vec(),
                r#type: tron_proto::AccountType::Contract as i32,
                frozen_v2: vec![tron_proto::account::FreezeV2 { r#type: 0, amount: 100_000_000 }],
                ..Default::default()
            },
        )
        .unwrap();
    install_eoa(&stores, receiver, 0);

    let out = run(&stores, caller_user, outer);
    // The outer frame discards the STATICCALL result (POP) and STOPs → the TX
    // succeeds, but the inner DELEGATERESOURCE must have reverted (static guard),
    // leaving NO DelegatedResource row.
    assert!(matches!(out, VmOutcome::Success { .. }), "got {out:?}");
    let key = DelegatedResourceStore::v2_unlocked_key(
        &Address::from_raw(inner),
        &Address::from_raw(receiver),
    );
    assert!(
        stores.delegated_resources.get_raw(&key).unwrap().is_none(),
        "a static-context DELEGATERESOURCE must not write a DelegatedResource row"
    );
}

// =============================================================================
// A failed CREATE2 in a version-0 frame leaves the parent with no energy.
// =============================================================================
//
// java `Program.createContractImpl` spends `getCreateEnergy(remaining)` on the
// parent up front — ALL of it for a version-0 frame — and on any child
// exception (here `notEnoughSpendEnergy` at the code deposit) returns before
// `refundEnergyAfterVM`, so the parent forfeits the whole forwarded budget and
// dies on its very next opcode with OUT_OF_ENERGY. A version-1 frame retained
// 1/64 and carries on.

/// Init code `PUSH2 40000; PUSH1 0; RETURN` left-aligned in one 32-byte word:
/// the constructor returns 40,000 zero bytes, a 8,000,000-energy deposit that
/// no 5,000,000 budget can pay.
fn big_deposit_init_word() -> [u8; 32] {
    let mut w = [0u8; 32];
    w[..6].copy_from_slice(&[0x61, 0x9c, 0x40, 0x60, 0x00, 0xf3]);
    w
}

/// `MSTORE(0, init); CREATE2(0, 0, 6, salt 0); POP; PUSH1 0; PUSH1 0; REVERT`.
fn create2_big_deposit_then_revert() -> Vec<u8> {
    let mut bc = vec![0x7f];
    bc.extend_from_slice(&big_deposit_init_word());
    bc.extend_from_slice(&[0x60, 0x00, 0x52]); // MSTORE(0, word)
    bc.extend_from_slice(&[0x60, 0x00]); // salt
    bc.extend_from_slice(&[0x60, 0x06]); // size
    bc.extend_from_slice(&[0x60, 0x00]); // offset
    bc.extend_from_slice(&[0x60, 0x00]); // value
    bc.push(0xf5); // CREATE2
    bc.push(0x50); // POP — the first opcode after the failed create
    bc.extend_from_slice(&[0x60, 0x00, 0x60, 0x00, 0xfd]); // REVERT(0, 0)
    bc
}

/// `CALL(gas=all, target, 0, 0, 0, 0, 0); POP; STOP` — a root that forwards
/// everything to `target` and then runs one more opcode.
fn call_then_stop(target: [u8; 21]) -> Vec<u8> {
    let mut bc = Vec::new();
    bc.extend_from_slice(&[0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00]);
    bc.push(0x73); // PUSH20 target
    bc.extend_from_slice(&target[1..]);
    bc.push(0x5a); // GAS
    bc.push(0xf1); // CALL
    bc.push(0x50); // POP
    bc.push(0x00); // STOP
    bc
}

fn create2_stores() -> (VmStores, Arc<ContractStore>) {
    let (stores, contracts) = fresh_stores();
    stores.dynamic_properties.put_long(b"ALLOW_TVM_COMPATIBLE_EVM", 1);
    stores.dynamic_properties.put_long(b"ALLOW_TVM_CONSTANTINOPLE", 1);
    (stores, contracts)
}

#[test]
fn version_0_frame_dies_out_of_energy_after_a_failed_create2() {
    let (stores, contracts) = create2_stores();
    let user = tron_addr(0xa2);
    let c = tron_addr(0xc2);
    install_eoa(&stores, user, 0);
    install_contract(&stores, c, create2_big_deposit_then_revert(), 0);
    set_contract_version(&contracts, c, 0);

    match run(&stores, user, c) {
        VmOutcome::Halt { result, energy_used, .. } => {
            assert_eq!(
                result,
                tron_proto::transaction::result::ContractResult::OutOfEnergy,
                "the forfeited create budget leaves nothing for POP"
            );
            assert_eq!(energy_used, 5_000_000, "java spendAllEnergy: the whole limit");
        }
        other => panic!("expected an OUT_OF_ENERGY halt, got {other:?}"),
    }
}

#[test]
fn version_1_frame_keeps_a_64th_and_reverts_after_a_failed_create2() {
    let (stores, contracts) = create2_stores();
    let user = tron_addr(0xa3);
    let c = tron_addr(0xc3);
    install_eoa(&stores, user, 0);
    install_contract(&stores, c, create2_big_deposit_then_revert(), 0);
    set_contract_version(&contracts, c, 1);

    match run(&stores, user, c) {
        VmOutcome::Revert { energy_used, .. } => {
            assert!(energy_used < 5_000_000, "the retained 1/64 is refunded on REVERT");
            assert!(energy_used > 4_800_000, "the forwarded 63/64 is forfeited (used={energy_used})");
        }
        other => panic!("expected REVERT, got {other:?}"),
    }
}

#[test]
fn version_0_root_dies_out_of_energy_when_its_callee_forfeits_a_create2() {
    // Root R (v0) CALLs F (v0) with everything; F forfeits it all on the failed
    // CREATE2 and dies; R has nothing left for its own POP. java: OUT_OF_ENERGY.
    let (stores, contracts) = create2_stores();
    let user = tron_addr(0xa4);
    let r = tron_addr(0xc4);
    let f = tron_addr(0xc5);
    install_eoa(&stores, user, 0);
    install_contract(&stores, f, create2_big_deposit_then_revert(), 0);
    install_contract(&stores, r, call_then_stop(f), 0);
    set_contract_version(&contracts, r, 0);
    set_contract_version(&contracts, f, 0);

    match run(&stores, user, r) {
        VmOutcome::Halt { result, energy_used, .. } => {
            assert_eq!(result, tron_proto::transaction::result::ContractResult::OutOfEnergy);
            assert_eq!(energy_used, 5_000_000);
        }
        other => panic!("expected an OUT_OF_ENERGY halt, got {other:?}"),
    }
}
