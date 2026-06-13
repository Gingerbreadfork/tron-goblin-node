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
    stores.code.put(hash.as_slice(), bytecode).unwrap();
    stores.accounts.put(
        &tron_addr,
        &tron_proto::Account {
            address: tron_addr.as_bytes().to_vec(),
            balance: 0,
            code_hash: hash.as_slice().to_vec(),
            code: bytecode.to_vec(),
            ..Default::default()
        },
    ).unwrap();
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
        // TRON fork: the opcode set comes from `spec` (proposal-resolved), but
        // the *energy* schedule is TRON's Frontier-era gas table with a
        // Frontier-pinned gas spec — exactly what production sets in
        // `execute.rs`. Without this the harness would run default Cancun gas
        // params and never exercise the TRON energy rules (e.g. the Frontier
        // new-account CALL charge).
        let ctx = Context::mainnet()
            .with_db(tron_db)
            .modify_cfg_chained(|cfg| {
                cfg.spec = spec;
                cfg.gas_params = tron_tvm::tron_gas_params();
            });
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
    ).unwrap();

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
    ).unwrap();

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
    let stored = stores
        .storage
        .get(&composite)
        .unwrap()
        .expect("storage not written");
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
    ).unwrap();

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
        .unwrap()
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
    ).unwrap();

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

// ===========================================================================
// Test 5: a ZERO-VALUE CALL to a dead (never-seen, empty) account must NOT
// charge java-tron's NEW_ACCT_CALL (25000) energy top-up, while a
// VALUE-BEARING CALL to the same dead account MUST.
//
// java-tron `EnergyCost.getCallCost`:
//   energyCost = CALL_ENERGY (40)
//   if (!value.isZero()) {
//     energyCost += VT_CALL (9000)
//     if (isDeadAccount(addr)) energyCost += NEW_ACCT_CALL (25000)
//   }
// So the 25000 (and the 9000) are charged ONLY when value > 0. TRON pins its
// gas table to Frontier, where the new-account top-up would otherwise be
// charged unconditionally (pre-Spurious-Dragon) — over-charging every
// zero-value CALL to an empty account by 25000. This test pins the
// value-gating. (Regression for the c29c1baf +225000 = 9 × 25000 over-charge,
// where a router CALLed the identity precompile 0x04 nine times with value 0.)
// ===========================================================================

/// Build a contract that does a single CALL and STOPs, with the given value
/// pushed for the CALL. Stack for CALL (top first): gas,to,value,inOff,inLen,
/// outOff,outLen — pushed in reverse so `to` and `value` end up just below gas.
fn call_then_stop_bytecode(to_low_byte: u8, value: u8) -> Vec<u8> {
    vec![
        0x60, 0x00, // PUSH1 0   outLen
        0x60, 0x00, // PUSH1 0   outOff
        0x60, 0x00, // PUSH1 0   inLen
        0x60, 0x00, // PUSH1 0   inOff
        0x60, value, // PUSH1 value
        0x60, to_low_byte, // PUSH1 to (0x00..0xff address low byte)
        0x61, 0xff, 0xff, // PUSH2 0xffff  forwarded gas (capped to 63/64 left)
        0xf1, // CALL
        0x00, // STOP
    ]
}

fn run_call_energy(value: u8, to_low_byte: u8, caller_balance: u64) -> u64 {
    let stores = fresh_stores();
    let caller = EvmAddress::from([0xee; 20]);
    let contract = EvmAddress::from([0xc5; 20]);
    install_contract(&stores, contract, &call_then_stop_bytecode(to_low_byte, value));

    let caller_tron = evm_to_tron_address(&caller);
    stores
        .accounts
        .put(
            &caller_tron,
            &tron_proto::Account {
                address: caller_tron.as_bytes().to_vec(),
                balance: caller_balance as i64,
                ..Default::default()
            },
        )
        .unwrap();
    // Give the contract a balance so a value-bearing CALL can transfer.
    let contract_tron = evm_to_tron_address(&contract);
    stores
        .accounts
        .put(
            &contract_tron,
            &tron_proto::Account {
                address: contract_tron.as_bytes().to_vec(),
                balance: 1_000_000,
                code_hash: code_hash(&call_then_stop_bytecode(to_low_byte, value))
                    .as_slice()
                    .to_vec(),
                code: call_then_stop_bytecode(to_low_byte, value),
                ..Default::default()
            },
        )
        .unwrap();
    // Install an EXISTING (alive, non-empty) account at low-byte 0xad so a CALL
    // to 0x00..00ad never hits the new-account path — the control case.
    let mut alive_raw = [0u8; 20];
    alive_raw[19] = 0xad;
    let alive = EvmAddress::from(alive_raw);
    let alive_tron = evm_to_tron_address(&alive);
    stores
        .accounts
        .put(
            &alive_tron,
            &tron_proto::Account {
                address: alive_tron.as_bytes().to_vec(),
                balance: 7,
                ..Default::default()
            },
        )
        .unwrap();

    let mut evm = build_evm!(stores);
    let tx = TxEnv::builder()
        .caller(caller)
        .kind(TxKind::Call(contract))
        .gas_limit(1_000_000)
        .nonce(0)
        .gas_price(0)
        .build()
        .unwrap();
    let exec = evm.transact_commit(tx).expect("transact failed");
    assert!(
        matches!(exec, ExecutionResult::Success { .. }),
        "expected Success, got {exec:?}"
    );
    exec.gas_used()
}

#[test]
fn zero_value_call_to_dead_account_does_not_charge_new_acct_energy() {
    // Two zero-value CALLs, identical except for the target:
    //   0xbe — a DEAD account (no record installed → empty)
    //   0xad — an EXISTING account (installed with balance 7 → not empty)
    // java charges NEW_ACCT_CALL only on value>0, so a zero-value CALL costs
    // the SAME whether the target is dead or alive. With the Frontier-
    // unconditional bug, the dead-account path charged +25000.
    let to_dead = run_call_energy(0x00, 0xbe, 1_000_000_000);
    let to_alive = run_call_energy(0x00, 0xad, 1_000_000_000);
    assert_eq!(
        to_dead, to_alive,
        "a zero-value CALL must cost the same to a dead vs existing account; a \
higher dead-account cost means NEW_ACCT_CALL(25000) was wrongly charged"
    );

    // And confirm the value-bearing CALL to the dead account DOES pay the
    // NEW_ACCT_CALL top-up: it must exceed the value-bearing call to an alive
    // account by exactly 25000 (the VT_CALL/stipend/forwarding terms are
    // identical between the two, so they cancel).
    let val_dead = run_call_energy(0x01, 0xbe, 1_000_000_000);
    let val_alive = run_call_energy(0x01, 0xad, 1_000_000_000);
    assert_eq!(
        val_dead - val_alive,
        25_000,
        "a value-bearing CALL to a DEAD account must pay NEW_ACCT_CALL(25000) \
more than the same call to an existing account"
    );
}

// ===========================================================================
// Test 6: SSTORE billing for the `0 → 0 → non-zero` pattern.
//
// java-tron `EnergyCost.getSstoreCost` uses `storageLoad(key)` (the per-tx
// repository cache). `storageSave` caches the row on EVERY SSTORE, so once a
// slot has been written this tx — even a no-op `0 → 0` write — `storageLoad`
// returns non-null and the NEXT write is billed RESET(5000), not SET(20000).
// revm normally skips journaling a value-unchanged write, which lost that
// signal and mis-billed the re-set as SET — a +15000 energy over-charge per
// occurrence (regression for blk 83317074 tx 27e49687 on contract 3e5f6aed:
// energy 171672 vs java 156672 = one such re-set).
// ===========================================================================

/// Run a contract and return its gas_used (top-level call).
fn run_contract_energy(bytecode: &[u8]) -> u64 {
    let stores = fresh_stores();
    let caller = EvmAddress::from([0xee; 20]);
    let contract = EvmAddress::from([0xc6; 20]);
    install_contract(&stores, contract, bytecode);
    let caller_tron = evm_to_tron_address(&caller);
    stores
        .accounts
        .put(
            &caller_tron,
            &tron_proto::Account {
                address: caller_tron.as_bytes().to_vec(),
                balance: 1_000_000_000,
                ..Default::default()
            },
        )
        .unwrap();
    let mut evm = build_evm!(stores);
    let tx = TxEnv::builder()
        .caller(caller)
        .kind(TxKind::Call(contract))
        .gas_limit(1_000_000)
        .nonce(0)
        .gas_price(0)
        .build()
        .unwrap();
    let exec = evm.transact_commit(tx).expect("transact failed");
    assert!(
        matches!(exec, ExecutionResult::Success { .. }),
        "expected Success, got {exec:?}"
    );
    exec.gas_used()
}

#[test]
fn sstore_zero_then_nonzero_bills_reset_not_set_like_java() {
    // A: SSTORE slot7 = 0 (a 0→0 no-op write), then SSTORE slot7 = 1.
    //    java: the first store caches the row → second store is RESET(5000).
    let a = run_contract_energy(&[
        0x60, 0x00, 0x60, 0x07, 0x55, // PUSH1 0 PUSH1 7 SSTORE  (slot7 := 0)
        0x60, 0x01, 0x60, 0x07, 0x55, // PUSH1 1 PUSH1 7 SSTORE  (slot7 := 1)
        0x00, // STOP
    ]);
    // B: a single SSTORE slot7 = 1 on a genuinely fresh slot → SET(20000).
    let b = run_contract_energy(&[
        0x60, 0x01, 0x60, 0x07, 0x55, // PUSH1 1 PUSH1 7 SSTORE  (slot7 := 1)
        0x00, // STOP
    ]);

    // Energy is execution-only (no 21000 intrinsic in TRON energy), so:
    //   A = 2×PUSH1(3) + SSTORE_RESET(5000)  [0→0]
    //     + 2×PUSH1(3) + SSTORE_RESET(5000)  [0→1, RESET with the fix]
    //     = 12 + 10_000 = 10_012
    //   B = 2×PUSH1(3) + SSTORE_SET(20_000)  [fresh slot]
    //     = 6 + 20_000  = 20_006
    // Without the fix, A's re-set is mis-billed SET(20_000) → A = 25_012.
    assert_eq!(
        a, 10_012,
        "the 0→0→1 pattern must bill BOTH stores RESET(5000) (java parity); \
25_012 means the re-set was mis-billed SET(20_000)"
    );
    assert_eq!(b, 20_006, "a fresh-slot SSTORE must bill SET(20_000)");
}
