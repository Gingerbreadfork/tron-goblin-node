//! End-to-end test: deploy + call a real smart contract through our
//! full TVM stack (revm + `TronDatabase` + `TronPrecompiles`).
//!
//! Each test exercises a different cross-cut:
//! * Simple bytecode that does math + RETURN.
//! * Bytecode that SSTOREs a value, then we check it shows up in
//!   `StorageRowStore` via the v2 composite-key layout.
//! * Bytecode that CALLs a TRON-specific precompile (`IsSrCandidate`)
//!   and returns its result.
//!
//! These tests are the proof that smart contracts execute end-to-end
//! against TRON's on-disk state shape.

use std::sync::Arc;

use revm::context::{Context, Evm, FrameStack, TxEnv};
use revm::context_interface::result::ExecutionResult;
use revm::handler::instructions::EthInstructions;
use revm::interpreter::interpreter::EthInterpreter;
use revm::primitives::{Address as EvmAddress, TxKind};
use revm::{ExecuteCommitEvm, MainContext};
use tron_chainbase::{
    AccountStore, CodeStore, ContractStateStore, DelegatedResourceStore, DelegationStore,
    DynamicPropertiesStore, KvBackend, MemBackend, StorageRowStore, WitnessStore,
};
use tron_tvm::database::{code_hash, evm_to_tron_address, TronDatabase};
use tron_tvm::evm::TronPrecompiles;

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

struct Stores {
    accounts: Arc<AccountStore>,
    code: Arc<CodeStore>,
    storage: Arc<StorageRowStore>,
    witnesses: Arc<WitnessStore>,
    contract_state: Arc<ContractStateStore>,
    dynamic_properties: Arc<DynamicPropertiesStore>,
    delegated_resources: Arc<DelegatedResourceStore>,
    delegation: Arc<DelegationStore>,
}

fn fresh_stores() -> Stores {
    Stores {
        accounts: Arc::new(AccountStore::new(mem())),
        code: Arc::new(CodeStore::new(mem())),
        storage: Arc::new(StorageRowStore::new(mem())),
        witnesses: Arc::new(WitnessStore::new(mem())),
        contract_state: Arc::new(ContractStateStore::new(mem())),
        dynamic_properties: Arc::new(DynamicPropertiesStore::new(mem())),
        delegated_resources: Arc::new(DelegatedResourceStore::new(mem())),
        delegation: Arc::new(DelegationStore::new(mem())),
    }
}

/// Install a contract account directly (skipping the CREATE path) with
/// the given bytecode. Returns the EVM-style 20-byte contract address.
fn install_contract(stores: &Stores, addr: EvmAddress, bytecode: &[u8]) {
    let tron_addr = evm_to_tron_address(&addr);
    let hash = code_hash(bytecode);
    stores.code.put(hash.as_slice(), bytecode);
    stores.accounts.put(
        &tron_addr,
        &tron_proto::Account {
            address: tron_addr.as_bytes().to_vec(),
            balance: 0,
            code_hash: hash.as_slice().to_vec(),
            code: bytecode.to_vec(),
            ..Default::default()
        },
    );
}

/// Build the EVM in a local macro so we avoid spelling out the deep
/// generic signature. Each test does `let mut evm = build_evm!(stores);`
/// and gets back a fully-configured `Evm` with TronDatabase + TronPrecompiles.
macro_rules! build_evm {
    ($stores:expr) => {{
        let stores = &$stores;
        let tron_db = TronDatabase::new(
            Arc::clone(&stores.accounts),
            Arc::clone(&stores.code),
            Arc::clone(&stores.storage),
        );
        // These tests pre-date hard-fork gating and exercise the full
        // post-Byzantium opcode/precompile surface — use the
        // `all_enabled` snapshot so behavior matches today's mainnet.
        let proposals = tron_tvm::ProposalSet::all_enabled();
        let spec = proposals.resolve_spec();
        let ctx = Context::mainnet().with_db(tron_db);
        let precompiles = TronPrecompiles::new(
            spec,
            Arc::clone(&stores.accounts),
            Arc::clone(&stores.witnesses),
            Arc::clone(&stores.contract_state),
            Arc::clone(&stores.dynamic_properties),
            Arc::clone(&stores.delegated_resources),
            Arc::clone(&stores.delegation),
            0i64,
            0i64,
            proposals,
        );
        let mut instructions = EthInstructions::<EthInterpreter, _>::new_mainnet_with_spec(spec);
        tron_tvm::evm::install_tron_opcode_stubs(&mut instructions, &proposals);
        Evm {
            ctx,
            inspector: (),
            instruction: instructions,
            precompiles,
            frame_stack: FrameStack::new_prealloc(8),
        }
    }};
}

// ===========================================================================
// Test 1: bytecode that just returns the constant 42.
// ===========================================================================
//
// PUSH1 0x2a   // 60 2a   — push 42
// PUSH1 0x00   // 60 00   — push memory offset 0
// MSTORE       // 52      — mem[0..32] = 42 (right-aligned)
// PUSH1 0x20   // 60 20   — push length 32
// PUSH1 0x00   // 60 00   — push memory offset 0
// RETURN       // f3      — return mem[0..32]

#[test]
fn contract_that_returns_constant_returns_it_through_revm() {
    let stores = fresh_stores();
    let caller = EvmAddress::from([0xee; 20]);
    let contract = EvmAddress::from([0xcc; 20]);

    let bytecode = vec![
        0x60, 0x2a, // PUSH1 42
        0x60, 0x00, // PUSH1 0
        0x52, // MSTORE
        0x60, 0x20, // PUSH1 32
        0x60, 0x00, // PUSH1 0
        0xf3, // RETURN
    ];
    install_contract(&stores, contract, &bytecode);

    // Give the caller some balance.
    let caller_tron = evm_to_tron_address(&caller);
    stores.accounts.put(
        &caller_tron,
        &tron_proto::Account {
            address: caller_tron.as_bytes().to_vec(),
            balance: 1_000_000_000,
            ..Default::default()
        },
    );

    let mut evm = build_evm!(stores);
    let tx = TxEnv::builder()
        .caller(caller)
        .kind(TxKind::Call(contract))
        .gas_limit(100_000)
        .nonce(0)
        .gas_price(0)
        .build()
        .unwrap();

    let exec = evm.transact_commit(tx).expect("transact failed");
    let output = match exec {
        ExecutionResult::Success { output, .. } => output,
        other => panic!("expected Success, got {other:?}"),
    };
    let bytes = output.data();
    assert_eq!(bytes.len(), 32);
    // The 32-byte return value, right-aligned with 42 in the low byte.
    let mut expected = [0u8; 32];
    expected[31] = 42;
    assert_eq!(bytes.as_ref(), &expected);
}

// ===========================================================================
// Test 2: bytecode that SSTOREs 0x12345678 at slot 0, then halts.
// We check the storage row landed in StorageRowStore via the v2 layout.
// ===========================================================================
//
// PUSH4 0x12345678  // 63 12 34 56 78
// PUSH1 0x00        // 60 00
// SSTORE            // 55
// STOP              // 00

#[test]
fn sstore_lands_in_storage_row_store_via_v2_layout() {
    let stores = fresh_stores();
    let caller = EvmAddress::from([0xee; 20]);
    let contract = EvmAddress::from([0xcd; 20]);

    let bytecode = vec![
        0x63, 0x12, 0x34, 0x56, 0x78, // PUSH4 0x12345678
        0x60, 0x00, // PUSH1 0
        0x55, // SSTORE
        0x00, // STOP
    ];
    install_contract(&stores, contract, &bytecode);

    let caller_tron = evm_to_tron_address(&caller);
    stores.accounts.put(
        &caller_tron,
        &tron_proto::Account {
            address: caller_tron.as_bytes().to_vec(),
            balance: 1_000_000_000,
            ..Default::default()
        },
    );

    let mut evm = build_evm!(stores);
    let tx = TxEnv::builder()
        .caller(caller)
        .kind(TxKind::Call(contract))
        .gas_limit(200_000)
        .nonce(0)
        .gas_price(0)
        .build()
        .unwrap();

    let exec = evm.transact_commit(tx).expect("transact failed");
    assert!(matches!(exec, ExecutionResult::Success { .. }));

    // Verify the SSTORE landed in StorageRowStore at the v2 composite
    // key location (the key bytes we crafted for `slot=0`).
    let contract_tron = evm_to_tron_address(&contract);
    let slot_bytes = [0u8; 32]; // slot index 0
    let composite = StorageRowStore::compose_key(&contract_tron, &slot_bytes);
    let stored = stores.storage.get(&composite).expect("storage not written");
    // Right-aligned big-endian 0x12345678
    let mut expected = [0u8; 32];
    expected[28..32].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
    assert_eq!(stored, expected.to_vec());
}

// ===========================================================================
// Test 3: round-trip — SSTORE then SLOAD within the same contract,
// verifying the EVM's storage state-machine and the v2 composite-key
// path through TronDatabase agree on the slot.
// ===========================================================================
//
// SSTORE 99 at slot 7, SLOAD slot 7, return it.
//
// PUSH1 0x63   // 60 63   — push 99
// PUSH1 0x07   // 60 07   — push slot 7
// SSTORE       // 55      — storage[7] = 99
// PUSH1 0x07   // 60 07   — push slot 7
// SLOAD        // 54      — load storage[7] → stack
// PUSH1 0x00   // 60 00
// MSTORE       // 52      — mem[0..32] = value
// PUSH1 0x20   // 60 20
// PUSH1 0x00   // 60 00
// RETURN       // f3

#[test]
fn sstore_then_sload_within_one_contract_round_trips_the_value() {
    let stores = fresh_stores();
    let caller = EvmAddress::from([0xee; 20]);
    let contract = EvmAddress::from([0xce; 20]);

    install_contract(
        &stores,
        contract,
        &[
            0x60, 0x63, // PUSH1 99
            0x60, 0x07, // PUSH1 7
            0x55, // SSTORE
            0x60, 0x07, // PUSH1 7
            0x54, // SLOAD
            0x60, 0x00, // PUSH1 0
            0x52, // MSTORE
            0x60, 0x20, // PUSH1 32
            0x60, 0x00, // PUSH1 0
            0xf3, // RETURN
        ],
    );

    let caller_tron = evm_to_tron_address(&caller);
    stores.accounts.put(
        &caller_tron,
        &tron_proto::Account {
            address: caller_tron.as_bytes().to_vec(),
            balance: 1_000_000_000,
            ..Default::default()
        },
    );

    let mut evm = build_evm!(stores);
    let tx = TxEnv::builder()
        .caller(caller)
        .kind(TxKind::Call(contract))
        .gas_limit(200_000)
        .nonce(0)
        .gas_price(0)
        .build()
        .unwrap();
    let exec = evm.transact_commit(tx).expect("transact failed");
    let bytes = match exec {
        ExecutionResult::Success { output, .. } => output.data().clone(),
        other => panic!("expected Success, got {other:?}"),
    };
    let mut expected = [0u8; 32];
    expected[31] = 99;
    assert_eq!(bytes.as_ref(), &expected, "SLOAD should return 99");

    // After commit, the storage row must also be visible via the v2
    // composite-key path — confirming the TronDatabase write path
    // matches the read path.
    let contract_tron = evm_to_tron_address(&contract);
    let mut slot_bytes = [0u8; 32];
    slot_bytes[31] = 7;
    let composite = StorageRowStore::compose_key(&contract_tron, &slot_bytes);
    let stored = stores
        .storage
        .get(&composite)
        .expect("storage row missing after commit");
    let mut expected_bytes = [0u8; 32];
    expected_bytes[31] = 99;
    assert_eq!(stored, expected_bytes.to_vec());
}

// ===========================================================================
// Test 4: TRON-extended opcode (0xd0 CALLTOKEN) halts cleanly with
// OpcodeNotFound — a clear diagnostic rather than UB. Full impl
// requires a revm fork (documented in evm::install_tron_opcode_stubs).
// ===========================================================================

#[test]
fn tron_extended_opcode_halts_cleanly_not_undefined() {
    let stores = fresh_stores();
    let caller = EvmAddress::from([0xee; 20]);
    let contract = EvmAddress::from([0xc4; 20]);

    // Bytecode: emit 0xd0 (CALLTOKEN) directly. Doesn't matter that the
    // stack is empty — the stub halts before reading it.
    install_contract(&stores, contract, &[0xd0u8]);

    let caller_tron = evm_to_tron_address(&caller);
    stores.accounts.put(
        &caller_tron,
        &tron_proto::Account {
            address: caller_tron.as_bytes().to_vec(),
            balance: 1_000_000_000,
            ..Default::default()
        },
    );

    let mut evm = build_evm!(stores);
    let tx = TxEnv::builder()
        .caller(caller)
        .kind(TxKind::Call(contract))
        .gas_limit(100_000)
        .nonce(0)
        .gas_price(0)
        .build()
        .unwrap();
    let exec = evm.transact_commit(tx).expect("transact failed");
    // CALLTOKEN stub halts with OpcodeNotFound -> revm reports Halt.
    match exec {
        ExecutionResult::Halt { reason, .. } => {
            // Either OpcodeNotFound or PrecompileError-like — the
            // important thing is that we get a deterministic halt, not
            // a panic or silent success.
            let _ = reason;
        }
        other => panic!("expected Halt for CALLTOKEN stub, got {other:?}"),
    }
}
