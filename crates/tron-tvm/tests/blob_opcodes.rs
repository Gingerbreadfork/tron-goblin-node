//! Regression tests for BLOBHASH (0x49) + BLOBBASEFEE (0x4a) gating.
//!
//! revm installs both opcodes when the spec is CANCUN or later. In
//! java-tron, however, these are gated by a separate `ALLOW_TVM_BLOB`
//! proposal (not `ALLOW_TVM_CANCUN`). The fork-gating layer in
//! `tron-tvm/src/proposals.rs` + `evm.rs::install_tron_opcode_stubs`
//! reconciles the split: when CANCUN is on but BLOB is off, we
//! override both opcodes to `OpcodeNotFound`.
//!
//! Cases covered:
//! 1. No proposals at all → BYZANTIUM spec → halt.
//! 2. `ALLOW_TVM_CANCUN` on, `ALLOW_TVM_BLOB` off → CANCUN spec but
//!    BLOBHASH/BLOBBASEFEE halt via the override.
//! 3. Both flags on → opcodes execute cleanly.
//! 4. With both flags on, BLOBBASEFEE pushes zero, matching java's
//!    `blobBaseFeeAction` (`DataWord.ZERO()`) rather than an
//!    Ethereum blob gas price.

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
        delegated_resource_account_index: None,
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
            block_timestamp_ms: 1_700_000_000_000, ..Default::default()
        },
        &trigger,
        500_000,
    )
}

// BLOBHASH bytecode: PUSH1 0 ; BLOBHASH ; PUSH1 0 ; SSTORE ; STOP
const BLOBHASH_BC: &[u8] = &[0x60, 0x00, 0x49, 0x60, 0x00, 0x55, 0x00];
// BLOBBASEFEE bytecode: BLOBBASEFEE ; PUSH1 0 ; SSTORE ; STOP
const BLOBBASEFEE_BC: &[u8] = &[0x4a, 0x60, 0x00, 0x55, 0x00];
// Self-checking BLOBBASEFEE value probe, by offset:
//   0x00 BLOBBASEFEE ; 0x01 ISZERO ; 0x02 PUSH1 0x06 ; 0x04 JUMPI
//   0x05 INVALID     ; 0x06 JUMPDEST ; 0x07 STOP
// The jump is taken only when BLOBBASEFEE pushed zero; any other value
// falls through to INVALID and halts.
const BLOBBASEFEE_IS_ZERO_BC: &[u8] = &[0x4a, 0x15, 0x60, 0x06, 0x57, 0xfe, 0x5b, 0x00];

fn was_halted(outcome: VmOutcome) -> bool {
    matches!(outcome, VmOutcome::Halt { .. })
}

fn was_success(outcome: VmOutcome) -> bool {
    matches!(outcome, VmOutcome::Success { .. })
}

#[test]
fn blob_opcodes_halt_when_no_proposals_active() {
    // Default spec is BYZANTIUM — BLOBHASH (Cancun feature) halts.
    let stores = fresh_stores();
    let caller = install_caller(&stores);
    let c1 = tron_addr(0xc1);
    install_contract(&stores, c1, BLOBHASH_BC.to_vec());
    assert!(
        was_halted(run(&stores, caller, c1)),
        "BLOBHASH must halt under Byzantium"
    );
    let c2 = tron_addr(0xc2);
    install_contract(&stores, c2, BLOBBASEFEE_BC.to_vec());
    assert!(
        was_halted(run(&stores, caller, c2)),
        "BLOBBASEFEE must halt under Byzantium"
    );
}

#[test]
fn blob_opcodes_halt_when_cancun_on_but_blob_off() {
    // CANCUN spec is active (TLOAD/TSTORE/MCOPY would work) but the
    // BLOB gate is off — BLOBHASH / BLOBBASEFEE must halt via the
    // 0x49 / 0x4a override installed by `install_tron_opcode_stubs`.
    let stores = fresh_stores();
    stores.dynamic_properties.put_long(b"ALLOW_TVM_CANCUN", 1);
    // ALLOW_TVM_BLOB deliberately omitted.
    let caller = install_caller(&stores);
    let c1 = tron_addr(0xc1);
    install_contract(&stores, c1, BLOBHASH_BC.to_vec());
    assert!(
        was_halted(run(&stores, caller, c1)),
        "BLOBHASH must halt when ALLOW_TVM_BLOB is off"
    );
    let c2 = tron_addr(0xc2);
    install_contract(&stores, c2, BLOBBASEFEE_BC.to_vec());
    assert!(
        was_halted(run(&stores, caller, c2)),
        "BLOBBASEFEE must halt when ALLOW_TVM_BLOB is off"
    );
}

#[test]
fn blob_opcodes_execute_when_cancun_and_blob_on() {
    let stores = fresh_stores();
    stores.dynamic_properties.put_long(b"ALLOW_TVM_CANCUN", 1);
    stores.dynamic_properties.put_long(b"ALLOW_TVM_BLOB", 1);
    let caller = install_caller(&stores);
    let c1 = tron_addr(0xc1);
    install_contract(&stores, c1, BLOBHASH_BC.to_vec());
    assert!(
        was_success(run(&stores, caller, c1)),
        "BLOBHASH must succeed with CANCUN + BLOB on"
    );
    let c2 = tron_addr(0xc2);
    install_contract(&stores, c2, BLOBBASEFEE_BC.to_vec());
    assert!(
        was_success(run(&stores, caller, c2)),
        "BLOBBASEFEE must succeed with CANCUN + BLOB on"
    );
}

#[test]
fn blobbasefee_pushes_zero() {
    // java's `blobBaseFeeAction` (OperationActions.java:686) pushes
    // `DataWord.ZERO()` with no host or environment lookup, so TRON reports a
    // zero blob base fee in every era. Ethereum's blob gas price floors at
    // `MIN_BLOB_GASPRICE` (1) and can never satisfy this.
    let stores = fresh_stores();
    stores.dynamic_properties.put_long(b"ALLOW_TVM_CANCUN", 1);
    stores.dynamic_properties.put_long(b"ALLOW_TVM_BLOB", 1);
    let caller = install_caller(&stores);
    let c = tron_addr(0xc3);
    install_contract(&stores, c, BLOBBASEFEE_IS_ZERO_BC.to_vec());
    assert!(
        was_success(run(&stores, caller, c)),
        "BLOBBASEFEE must push 0 (java DataWord.ZERO()), not the blob gas price"
    );
}
