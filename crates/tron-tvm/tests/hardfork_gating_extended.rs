//! Extended hardfork-gating tests for opcodes the original
//! `hardfork_gating.rs` didn't cover individually.
//!
//! Each TRON-specific opcode lives at a fixed bytecode position and
//! is gated on a distinct `ALLOW_TVM_*` proposal. Wrong gating
//! (opcode runs when proposal off, or halts when proposal on) is a
//! silent consensus split. Java-tron has per-opcode tests for each;
//! this file fills in the ones we skipped.

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
    VmStores {
        accounts: Arc::new(AccountStore::new(mem())),
        code: Arc::new(CodeStore::new(mem())),
        storage: Arc::new(StorageRowStore::new(mem())),
        witnesses: Arc::new(WitnessStore::new(mem())),
        contract_state: Arc::new(ContractStateStore::new(mem())),
        dynamic_properties: Arc::new(DynamicPropertiesStore::new(mem())),
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

fn is_halt(o: &VmOutcome) -> bool {
    matches!(o, VmOutcome::Halt { .. })
}
fn is_success(o: &VmOutcome) -> bool {
    matches!(o, VmOutcome::Success { .. })
}

/// Run a contract with the given proposal off vs on; assert halt vs
/// success. `enable_proposal` is the key set when "on"; "off" means
/// the dynamic properties store is empty.
fn gate(proposal_key: &[u8], bytecode: Vec<u8>, label: &str) {
    {
        let stores = fresh_stores();
        let caller = install_caller(&stores);
        let c = tron_addr(0xbb);
        install_contract(&stores, c, bytecode.clone());
        assert!(
            is_halt(&run(&stores, caller, c)),
            "{label} must halt without {}",
            std::str::from_utf8(proposal_key).unwrap_or("<binary>")
        );
    }
    {
        let stores = fresh_stores();
        stores.dynamic_properties.put_long(proposal_key, 1);
        let caller = install_caller(&stores);
        let c = tron_addr(0xbb);
        install_contract(&stores, c, bytecode);
        assert!(
            is_success(&run(&stores, caller, c)),
            "{label} must run with {}",
            std::str::from_utf8(proposal_key).unwrap_or("<binary>")
        );
    }
}

// ============================================================
// Constantinople opcodes (besides CREATE2 — already covered)
// ============================================================

#[test]
fn shl_gated_on_constantinople() {
    // PUSH1 1 PUSH1 2 SHL PUSH1 0 SSTORE STOP
    let bc = vec![0x60, 0x01, 0x60, 0x02, 0x1b, 0x60, 0x00, 0x55, 0x00];
    gate(b"ALLOW_TVM_CONSTANTINOPLE", bc, "SHL");
}

#[test]
fn shr_gated_on_constantinople() {
    // PUSH1 4 PUSH1 1 SHR PUSH1 0 SSTORE STOP
    let bc = vec![0x60, 0x04, 0x60, 0x01, 0x1c, 0x60, 0x00, 0x55, 0x00];
    gate(b"ALLOW_TVM_CONSTANTINOPLE", bc, "SHR");
}

#[test]
fn sar_gated_on_constantinople() {
    // PUSH1 4 PUSH1 1 SAR PUSH1 0 SSTORE STOP
    let bc = vec![0x60, 0x04, 0x60, 0x01, 0x1d, 0x60, 0x00, 0x55, 0x00];
    gate(b"ALLOW_TVM_CONSTANTINOPLE", bc, "SAR");
}

#[test]
fn extcodehash_gated_on_constantinople() {
    // PUSH20 <self> EXTCODEHASH PUSH1 0 SSTORE STOP
    let mut bc = vec![0x73];
    bc.extend_from_slice(&[0u8; 20]);
    bc.extend_from_slice(&[0x3f, 0x60, 0x00, 0x55, 0x00]);
    gate(b"ALLOW_TVM_CONSTANTINOPLE", bc, "EXTCODEHASH");
}

// ============================================================
// Istanbul opcodes (besides CHAINID)
// ============================================================

#[test]
fn selfbalance_gated_on_istanbul() {
    // SELFBALANCE PUSH1 0 SSTORE STOP
    let bc = vec![0x47, 0x60, 0x00, 0x55, 0x00];
    gate(b"ALLOW_TVM_ISTANBUL", bc, "SELFBALANCE");
}

// ============================================================
// Cancun opcodes (besides MCOPY)
// ============================================================

#[test]
fn tload_gated_on_cancun() {
    // PUSH1 0 TLOAD PUSH1 0 SSTORE STOP
    let bc = vec![0x60, 0x00, 0x5c, 0x60, 0x00, 0x55, 0x00];
    gate(b"ALLOW_TVM_CANCUN", bc, "TLOAD");
}

#[test]
fn tstore_gated_on_cancun() {
    // PUSH1 42 PUSH1 0 TSTORE STOP
    let bc = vec![0x60, 0x2a, 0x60, 0x00, 0x5d, 0x00];
    gate(b"ALLOW_TVM_CANCUN", bc, "TSTORE");
}

// ============================================================
// BLOB opcodes — distinct gate from CANCUN
// ============================================================

#[test]
fn blobhash_gated_on_blob_proposal_not_cancun() {
    // PUSH1 0 BLOBHASH PUSH1 0 SSTORE STOP
    let bc = vec![0x60, 0x00, 0x49, 0x60, 0x00, 0x55, 0x00];
    // With Cancun ON but BLOB OFF, BLOBHASH must still halt.
    {
        let stores = fresh_stores();
        stores.dynamic_properties.put_long(b"ALLOW_TVM_CANCUN", 1);
        let caller = install_caller(&stores);
        let c = tron_addr(0xbb);
        install_contract(&stores, c, bc.clone());
        assert!(
            is_halt(&run(&stores, caller, c)),
            "BLOBHASH must halt when CANCUN alone is on (BLOB proposal off)"
        );
    }
    // With both CANCUN + BLOB on, it runs.
    {
        let stores = fresh_stores();
        stores.dynamic_properties.put_long(b"ALLOW_TVM_CANCUN", 1);
        stores.dynamic_properties.put_long(b"ALLOW_TVM_BLOB", 1);
        let caller = install_caller(&stores);
        let c = tron_addr(0xbb);
        install_contract(&stores, c, bc);
        assert!(
            is_success(&run(&stores, caller, c)),
            "BLOBHASH must run with CANCUN + BLOB both on"
        );
    }
}

#[test]
fn blobbasefee_gated_on_blob_proposal_not_cancun() {
    // BLOBBASEFEE PUSH1 0 SSTORE STOP
    let bc = vec![0x4a, 0x60, 0x00, 0x55, 0x00];
    {
        let stores = fresh_stores();
        stores.dynamic_properties.put_long(b"ALLOW_TVM_CANCUN", 1);
        let caller = install_caller(&stores);
        let c = tron_addr(0xbb);
        install_contract(&stores, c, bc.clone());
        assert!(
            is_halt(&run(&stores, caller, c)),
            "BLOBBASEFEE must halt when CANCUN alone is on (BLOB proposal off)"
        );
    }
    {
        let stores = fresh_stores();
        stores.dynamic_properties.put_long(b"ALLOW_TVM_CANCUN", 1);
        stores.dynamic_properties.put_long(b"ALLOW_TVM_BLOB", 1);
        let caller = install_caller(&stores);
        let c = tron_addr(0xbb);
        install_contract(&stores, c, bc);
        assert!(
            is_success(&run(&stores, caller, c)),
            "BLOBBASEFEE must run with CANCUN + BLOB both on"
        );
    }
}

// ============================================================
// TRON TRC-10 opcodes — gated on ALLOW_TVM_TRANSFER_TRC10
// ============================================================

#[test]
fn calltokenvalue_gated_on_transfer_trc10() {
    // CALLTOKENVALUE PUSH1 0 SSTORE STOP
    let bc = vec![0xd2, 0x60, 0x00, 0x55, 0x00];
    gate(b"ALLOW_TVM_TRANSFER_TRC10", bc, "CALLTOKENVALUE");
}

#[test]
fn calltokenid_gated_on_transfer_trc10() {
    // CALLTOKENID PUSH1 0 SSTORE STOP
    let bc = vec![0xd3, 0x60, 0x00, 0x55, 0x00];
    gate(b"ALLOW_TVM_TRANSFER_TRC10", bc, "CALLTOKENID");
}

#[test]
fn tokenbalance_gated_on_transfer_trc10() {
    // PUSH1 0 PUSH20 <zeros> TOKENBALANCE PUSH1 0 SSTORE STOP
    let mut bc = vec![0x60, 0x00, 0x73];
    bc.extend_from_slice(&[0u8; 20]);
    bc.extend_from_slice(&[0xd1, 0x60, 0x00, 0x55, 0x00]);
    gate(b"ALLOW_TVM_TRANSFER_TRC10", bc, "TOKENBALANCE");
}

// ============================================================
// TRON Stake-1 opcodes
// ============================================================

#[test]
fn freeze_gated_on_freeze_v1() {
    // PUSH1 0 PUSH1 0 PUSH1 0 FREEZE PUSH1 0 SSTORE STOP
    let bc = vec![
        0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0xd5, 0x60, 0x00, 0x55, 0x00,
    ];
    gate(b"ALLOW_TVM_FREEZE", bc, "FREEZE");
}

#[test]
fn unfreeze_gated_on_freeze_v1() {
    // PUSH1 0 PUSH1 0 UNFREEZE PUSH1 0 SSTORE STOP
    let bc = vec![0x60, 0x00, 0x60, 0x00, 0xd6, 0x60, 0x00, 0x55, 0x00];
    gate(b"ALLOW_TVM_FREEZE", bc, "UNFREEZE");
}

#[test]
fn freezeexpiretime_gated_on_freeze_v1() {
    // PUSH1 0 PUSH1 0 FREEZEEXPIRETIME PUSH1 0 SSTORE STOP
    let bc = vec![0x60, 0x00, 0x60, 0x00, 0xd7, 0x60, 0x00, 0x55, 0x00];
    gate(b"ALLOW_TVM_FREEZE", bc, "FREEZEEXPIRETIME");
}

// ============================================================
// TRON Vote opcodes
// ============================================================

#[test]
fn withdrawreward_gated_on_vote() {
    // WITHDRAWREWARD PUSH1 0 SSTORE STOP
    let bc = vec![0xd9, 0x60, 0x00, 0x55, 0x00];
    gate(b"ALLOW_TVM_VOTE", bc, "WITHDRAWREWARD");
}

// ============================================================
// TRON Stake-2 opcodes (besides FREEZEBALANCEV2)
// ============================================================

#[test]
fn unfreezebalancev2_gated_on_freeze_v2() {
    // PUSH1 0 PUSH1 0 PUSH1 0 UNFREEZEBALANCEV2 PUSH1 0 SSTORE STOP
    let bc = vec![
        0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0xdb, 0x60, 0x00, 0x55, 0x00,
    ];
    gate(b"ALLOW_TVM_FREEZE_V2", bc, "UNFREEZEBALANCEV2");
}

#[test]
fn cancelallunfreezev2_gated_on_freeze_v2() {
    // CANCELALLUNFREEZEV2 PUSH1 0 SSTORE STOP
    let bc = vec![0xdc, 0x60, 0x00, 0x55, 0x00];
    gate(b"ALLOW_TVM_FREEZE_V2", bc, "CANCELALLUNFREEZEV2");
}

#[test]
fn withdrawexpireunfreeze_gated_on_freeze_v2() {
    // WITHDRAWEXPIREUNFREEZE PUSH1 0 SSTORE STOP
    let bc = vec![0xdd, 0x60, 0x00, 0x55, 0x00];
    gate(b"ALLOW_TVM_FREEZE_V2", bc, "WITHDRAWEXPIREUNFREEZE");
}

#[test]
fn delegateresource_gated_on_freeze_v2() {
    // PUSH1 0 PUSH1 0 PUSH1 0 PUSH1 0 DELEGATERESOURCE PUSH1 0 SSTORE STOP
    let bc = vec![
        0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0xde, 0x60, 0x00, 0x55, 0x00,
    ];
    gate(b"ALLOW_TVM_FREEZE_V2", bc, "DELEGATERESOURCE");
}

#[test]
fn undelegateresource_gated_on_freeze_v2() {
    // PUSH1 0 PUSH1 0 PUSH1 0 PUSH1 0 UNDELEGATERESOURCE PUSH1 0 SSTORE STOP
    let bc = vec![
        0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0xdf, 0x60, 0x00, 0x55, 0x00,
    ];
    gate(b"ALLOW_TVM_FREEZE_V2", bc, "UNDELEGATERESOURCE");
}

// ============================================================
// Resource isolation — different proposals don't cross-enable
// ============================================================

#[test]
fn vote_proposal_does_not_enable_stake_v2_opcodes() {
    // FREEZEBALANCEV2 is gated on ALLOW_TVM_FREEZE_V2, not VOTE. Even
    // with VOTE on, the opcode must still halt.
    let bc = vec![0x60, 0x01, 0x60, 0x64, 0xda, 0x60, 0x00, 0x55, 0x00];
    let stores = fresh_stores();
    stores.dynamic_properties.put_long(b"ALLOW_TVM_VOTE", 1);
    let caller = install_caller(&stores);
    let c = tron_addr(0xc5);
    install_contract(&stores, c, bc);
    assert!(
        is_halt(&run(&stores, caller, c)),
        "FREEZEBALANCEV2 must remain halted when only VOTE is on"
    );
}

#[test]
fn freeze_v1_proposal_does_not_enable_freeze_v2_opcodes() {
    // FREEZEBALANCEV2 gated on FREEZE_V2, not FREEZE (v1).
    let bc = vec![0x60, 0x01, 0x60, 0x64, 0xda, 0x60, 0x00, 0x55, 0x00];
    let stores = fresh_stores();
    stores.dynamic_properties.put_long(b"ALLOW_TVM_FREEZE", 1);
    let caller = install_caller(&stores);
    let c = tron_addr(0xc5);
    install_contract(&stores, c, bc);
    assert!(
        is_halt(&run(&stores, caller, c)),
        "FREEZEBALANCEV2 must remain halted when only FREEZE (v1) is on"
    );
}

#[test]
fn istanbul_proposal_alone_does_not_enable_cancun_features() {
    // TLOAD gated on Cancun. ISTANBUL alone must not enable it.
    let bc = vec![0x60, 0x00, 0x5c, 0x60, 0x00, 0x55, 0x00];
    let stores = fresh_stores();
    stores.dynamic_properties.put_long(b"ALLOW_TVM_ISTANBUL", 1);
    let caller = install_caller(&stores);
    let c = tron_addr(0xc5);
    install_contract(&stores, c, bc);
    assert!(
        is_halt(&run(&stores, caller, c)),
        "TLOAD must remain halted when only ISTANBUL is on"
    );
}
