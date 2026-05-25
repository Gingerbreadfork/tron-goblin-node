//! End-to-end test for hard-fork gating in `tron-tvm`.
//!
//! Confirms that the proposal-driven `SpecId` resolution + TRON-opcode
//! gating in `execute_trigger` actually changes runtime behavior. For
//! each proposal we deploy a minimal contract that uses an opcode
//! gated by that proposal, then run it twice: once with the proposal
//! off (expect halt) and once with the proposal on (expect success).

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
    );
    caller
}

fn install_contract(stores: &VmStores, addr: [u8; 21], bytecode: Vec<u8>) {
    let hash = code_hash(&bytecode);
    stores.code.put(hash.as_slice(), &bytecode);
    stores.accounts.put(
        &Address::from_raw(addr),
        &Account {
            address: addr.to_vec(),
            balance: 0,
            code: bytecode,
            code_hash: hash.as_slice().to_vec(),
            ..Default::default()
        },
    );
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

// ---------- Standard EVM opcodes gated by SpecId ----------

/// PUSH0 (0x5f, Shanghai). Bytecode: `PUSH0 PUSH1 0 SSTORE STOP` — the
/// PUSH0 pushes a zero, SSTORE persists at slot 0.
fn push0_bytecode() -> Vec<u8> {
    vec![0x5f, 0x60, 0x00, 0x55, 0x00]
}

/// MCOPY (0x5e, Cancun). Bytecode: `PUSH1 0 PUSH1 0 PUSH1 0 MCOPY STOP`
/// — copies 0 bytes; valid in CANCUN, halts otherwise.
fn mcopy_bytecode() -> Vec<u8> {
    vec![0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x5e, 0x00]
}

/// CHAINID (0x46, Istanbul). Bytecode: `CHAINID PUSH1 0 SSTORE STOP`.
fn chainid_bytecode() -> Vec<u8> {
    vec![0x46, 0x60, 0x00, 0x55, 0x00]
}

/// BASEFEE (0x48, London). Bytecode: `BASEFEE PUSH1 0 SSTORE STOP`.
fn basefee_bytecode() -> Vec<u8> {
    vec![0x48, 0x60, 0x00, 0x55, 0x00]
}

/// CREATE2 (0xf5, Constantinople). Bytecode: pushes a tiny init code
/// and CREATE2's it. Mostly we just want to confirm the opcode isn't
/// invalid — execution beyond CREATE2 doesn't matter.
fn create2_bytecode() -> Vec<u8> {
    // PUSH1 0 PUSH1 0 PUSH1 0 PUSH1 0 CREATE2 STOP — salt=0, length=0,
    // offset=0, value=0. Init runs zero bytes, succeeds trivially.
    vec![
        0x60, 0x00, // salt
        0x60, 0x00, // length
        0x60, 0x00, // offset
        0x60, 0x00, // value
        0xf5, // CREATE2
        0x50, // POP the returned address
        0x00, // STOP
    ]
}

#[test]
fn push0_halts_without_shanghai_runs_with_it() {
    {
        let stores = fresh_stores();
        let caller = install_caller(&stores);
        let c = tron_addr(0xc0);
        install_contract(&stores, c, push0_bytecode());
        assert!(
            is_halt(&run(&stores, caller, c)),
            "PUSH0 must halt without ALLOW_TVM_SHANGHAI"
        );
    }
    {
        let stores = fresh_stores();
        stores.dynamic_properties.put_long(b"ALLOW_TVM_SHANGHAI", 1);
        let caller = install_caller(&stores);
        let c = tron_addr(0xc0);
        install_contract(&stores, c, push0_bytecode());
        assert!(
            is_success(&run(&stores, caller, c)),
            "PUSH0 must run with ALLOW_TVM_SHANGHAI"
        );
    }
}

#[test]
fn mcopy_halts_without_cancun_runs_with_it() {
    {
        let stores = fresh_stores();
        let caller = install_caller(&stores);
        let c = tron_addr(0xc1);
        install_contract(&stores, c, mcopy_bytecode());
        assert!(
            is_halt(&run(&stores, caller, c)),
            "MCOPY must halt without ALLOW_TVM_CANCUN"
        );
    }
    {
        let stores = fresh_stores();
        stores.dynamic_properties.put_long(b"ALLOW_TVM_CANCUN", 1);
        let caller = install_caller(&stores);
        let c = tron_addr(0xc1);
        install_contract(&stores, c, mcopy_bytecode());
        assert!(
            is_success(&run(&stores, caller, c)),
            "MCOPY must run with ALLOW_TVM_CANCUN"
        );
    }
}

#[test]
fn chainid_halts_without_istanbul_runs_with_it() {
    {
        let stores = fresh_stores();
        let caller = install_caller(&stores);
        let c = tron_addr(0xc2);
        install_contract(&stores, c, chainid_bytecode());
        assert!(
            is_halt(&run(&stores, caller, c)),
            "CHAINID must halt without ALLOW_TVM_ISTANBUL"
        );
    }
    {
        let stores = fresh_stores();
        stores.dynamic_properties.put_long(b"ALLOW_TVM_ISTANBUL", 1);
        let caller = install_caller(&stores);
        let c = tron_addr(0xc2);
        install_contract(&stores, c, chainid_bytecode());
        assert!(
            is_success(&run(&stores, caller, c)),
            "CHAINID must run with ALLOW_TVM_ISTANBUL"
        );
    }
}

#[test]
fn basefee_halts_without_london_runs_with_it() {
    {
        let stores = fresh_stores();
        let caller = install_caller(&stores);
        let c = tron_addr(0xc3);
        install_contract(&stores, c, basefee_bytecode());
        assert!(
            is_halt(&run(&stores, caller, c)),
            "BASEFEE must halt without ALLOW_TVM_LONDON"
        );
    }
    {
        let stores = fresh_stores();
        stores.dynamic_properties.put_long(b"ALLOW_TVM_LONDON", 1);
        let caller = install_caller(&stores);
        let c = tron_addr(0xc3);
        install_contract(&stores, c, basefee_bytecode());
        assert!(
            is_success(&run(&stores, caller, c)),
            "BASEFEE must run with ALLOW_TVM_LONDON"
        );
    }
}

#[test]
fn create2_halts_without_constantinople_runs_with_it() {
    {
        let stores = fresh_stores();
        let caller = install_caller(&stores);
        let c = tron_addr(0xc4);
        install_contract(&stores, c, create2_bytecode());
        assert!(
            is_halt(&run(&stores, caller, c)),
            "CREATE2 must halt without ALLOW_TVM_CONSTANTINOPLE"
        );
    }
    {
        let stores = fresh_stores();
        stores.dynamic_properties.put_long(b"ALLOW_TVM_CONSTANTINOPLE", 1);
        let caller = install_caller(&stores);
        let c = tron_addr(0xc4);
        install_contract(&stores, c, create2_bytecode());
        assert!(
            is_success(&run(&stores, caller, c)),
            "CREATE2 must run with ALLOW_TVM_CONSTANTINOPLE"
        );
    }
}

// ---------- TRON-specific opcodes gated by ALLOW_TVM_* ----------

/// FREEZEBALANCEV2 (0xda): pops 2, pushes 1. Stake-2.0 gate.
fn freezebalancev2_bytecode() -> Vec<u8> {
    // PUSH1 1 PUSH1 100 FREEZEBALANCEV2 PUSH1 0 SSTORE STOP
    vec![0x60, 0x01, 0x60, 0x64, 0xda, 0x60, 0x00, 0x55, 0x00]
}

/// VOTEWITNESS (0xd8): pops 4, pushes 1. Vote gate.
fn votewitness_bytecode() -> Vec<u8> {
    // PUSH1 0 PUSH1 0 PUSH1 0 PUSH1 0 VOTEWITNESS PUSH1 0 SSTORE STOP
    vec![
        0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0xd8, 0x60, 0x00, 0x55, 0x00,
    ]
}

/// ISCONTRACT (0xd4): pops 1, pushes 1. Gated by ALLOW_TVM_SOLIDITY_059.
fn iscontract_bytecode() -> Vec<u8> {
    // PUSH1 0 ISCONTRACT PUSH1 0 SSTORE STOP
    vec![0x60, 0x00, 0xd4, 0x60, 0x00, 0x55, 0x00]
}

#[test]
fn freezebalancev2_halts_without_freeze_v2_runs_with_it() {
    {
        let stores = fresh_stores();
        let caller = install_caller(&stores);
        let c = tron_addr(0xc5);
        install_contract(&stores, c, freezebalancev2_bytecode());
        assert!(
            is_halt(&run(&stores, caller, c)),
            "FREEZEBALANCEV2 must halt without ALLOW_TVM_FREEZE_V2"
        );
    }
    {
        let stores = fresh_stores();
        stores
            .dynamic_properties
            .put_long(b"ALLOW_TVM_FREEZE_V2", 1);
        let caller = install_caller(&stores);
        let c = tron_addr(0xc5);
        install_contract(&stores, c, freezebalancev2_bytecode());
        assert!(
            is_success(&run(&stores, caller, c)),
            "FREEZEBALANCEV2 must run with ALLOW_TVM_FREEZE_V2"
        );
    }
}

#[test]
fn votewitness_halts_without_vote_runs_with_it() {
    {
        let stores = fresh_stores();
        let caller = install_caller(&stores);
        let c = tron_addr(0xc6);
        install_contract(&stores, c, votewitness_bytecode());
        assert!(
            is_halt(&run(&stores, caller, c)),
            "VOTEWITNESS must halt without ALLOW_TVM_VOTE"
        );
    }
    {
        let stores = fresh_stores();
        stores.dynamic_properties.put_long(b"ALLOW_TVM_VOTE", 1);
        let caller = install_caller(&stores);
        let c = tron_addr(0xc6);
        install_contract(&stores, c, votewitness_bytecode());
        assert!(
            is_success(&run(&stores, caller, c)),
            "VOTEWITNESS must run with ALLOW_TVM_VOTE"
        );
    }
}

#[test]
fn iscontract_halts_without_solidity_059_runs_with_it() {
    {
        let stores = fresh_stores();
        let caller = install_caller(&stores);
        let c = tron_addr(0xc7);
        install_contract(&stores, c, iscontract_bytecode());
        assert!(
            is_halt(&run(&stores, caller, c)),
            "ISCONTRACT must halt without ALLOW_TVM_SOLIDITY_059"
        );
    }
    {
        let stores = fresh_stores();
        stores
            .dynamic_properties
            .put_long(b"ALLOW_TVM_SOLIDITY_059", 1);
        let caller = install_caller(&stores);
        let c = tron_addr(0xc7);
        install_contract(&stores, c, iscontract_bytecode());
        assert!(
            is_success(&run(&stores, caller, c)),
            "ISCONTRACT must run with ALLOW_TVM_SOLIDITY_059"
        );
    }
}

// ---------- Precompile gating ----------
//
// A call to a TRON-precompile address when its proposal is off must
// behave like a call to a non-precompile EOA: success with empty
// return. The cleanest way to detect that is to compare the
// `RETURNDATASIZE` after the call. Real precompiles return ≥ 1 byte
// here (e.g. `validatemultisign` returns 32 bytes), while a call to an
// EOA returns 0.
//
// We use `validatemultisign` (gated by ALLOW_TVM_SOLIDITY_059) because
// its 32-byte return value is easy to compare against zero. The
// contract calls the precompile address, then writes
// `returndatasize` into slot 0.

const VALIDATEMULTISIGN_ADDR: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x04,
];

fn call_precompile_size_bytecode(addr: [u8; 20]) -> Vec<u8> {
    let mut bc = Vec::new();
    // PUSH1 0   (retSize)
    // PUSH1 0   (retOffset)
    // PUSH1 0   (argSize)
    // PUSH1 0   (argOffset)
    // PUSH1 0   (value)
    // PUSH20 <addr>
    // PUSH2 0xFFFF (gas)
    // CALL — pops 7, pushes 1 (success flag)
    // POP — drop the success flag, we don't care
    // RETURNDATASIZE — push the size of returndata
    // PUSH1 0 SSTORE — store at slot 0
    // STOP
    bc.extend_from_slice(&[0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00]);
    bc.push(0x73); // PUSH20
    bc.extend_from_slice(&addr);
    bc.push(0x61); // PUSH2
    bc.push(0xFF);
    bc.push(0xFF);
    bc.push(0xf1); // CALL
    bc.push(0x50); // POP
    bc.push(0x3d); // RETURNDATASIZE
    bc.push(0x60); // PUSH1
    bc.push(0x00);
    bc.push(0x55); // SSTORE
    bc.push(0x00); // STOP
    bc
}

#[test]
fn validatemultisign_precompile_unreachable_without_solidity_059() {
    let stores = fresh_stores();
    let caller = install_caller(&stores);
    let c = tron_addr(0xc8);
    install_contract(
        &stores,
        c,
        call_precompile_size_bytecode(VALIDATEMULTISIGN_ADDR),
    );
    // Proposal off → CALL to the precompile address routes to an EOA
    // (no code, no precompile body) → returndatasize is 0 OR the call
    // halts before SSTORE runs. Either way, the contract halts or the
    // stored value is 0. We just want to confirm the precompile didn't
    // run (which would have produced 32-byte returndata).
    let outcome = run(&stores, caller, c);
    // The outer contract should succeed (the inner CALL returning empty
    // doesn't halt the outer frame) but the returndatasize must be 0.
    if let VmOutcome::Success { .. } = outcome {
        use tron_chainbase::StorageRowStore;
        let key = StorageRowStore::compose_key(&Address::from_raw(c), &[0u8; 32]);
        let value = stores.storage.get(&key).unwrap_or_default();
        // returndatasize fits in the low bytes — assert all 32 bytes
        // are zero (no precompile output).
        assert!(
            value.iter().all(|&b| b == 0),
            "precompile must NOT have produced output (returndatasize=0), got {value:?}"
        );
    }
    // (We tolerate a halt here too — some revm versions halt on a CALL
    // to a precompile address when the precompile returns Revert. The
    // key invariant is "precompile didn't produce its real output".)
}
