//! Integration test for Phase 3c: executor → TVM wiring.
//!
//! Builds a `StateBackends` with EVM stores attached, then drives a
//! `TriggerSmartContract` transaction through `execute_block` and
//! verifies the contract actually ran (storage row written).

use std::sync::Arc;

use prost::Message;
use prost_types::Any;
use tron_chainbase::{
    AccountStore, CodeStore, KvBackend, MemBackend, StorageRowStore,
};
use tron_crypto::address::Address;
use tron_actuator::ActuatorError;
use tron_executor::{
    execute_block_with_config, BlockExecError, BlockExecutionReport, ExecConfig, StateBackends,
    TxOutcome,
};
use tron_proto::{
    transaction::{contract::ContractType, Contract as TxContract, Raw as TxRaw},
    Account, Block, BlockHeader, Transaction, TriggerSmartContract,
};
use tron_types::BlockId;

/// Apply a synthetic UNSIGNED block. See note on the same helper in
/// `maintenance_rotation.rs` — these tests exercise VM execution paths,
/// not the witness-sig path.
fn apply_unsigned(
    state: &StateBackends,
    block: &Block,
    prev: Option<BlockId>,
) -> Result<BlockExecutionReport, BlockExecError> {
    execute_block_with_config(state, block, prev, &ExecConfig::unsigned())
}

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn addr_with_byte(byte: u8) -> [u8; 21] {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(byte);
    a
}

/// Derive a deterministic (private_key, 21-byte address) pair from a
/// single seed byte. The address is computed exactly as
/// `Address::from_uncompressed_pubkey` does (keccak256 of the X||Y
/// concatenation, last 20 bytes prefixed with 0x41).
///
/// Used by VM integration tests where the caller account must own the
/// private key that signs the tx — otherwise the permission check
/// rejects with "signer recovery failed" or "signer not in permission".
fn caller_keypair(seed: u8) -> ([u8; 32], [u8; 21]) {
    use tron_crypto::signature::RecoverableSignature;
    let mut priv_key = [0u8; 32];
    priv_key[0] = 0x10;
    priv_key[31] = seed;
    let dummy_hash = [0x42u8; 32];
    let sig = RecoverableSignature::sign_prehash(&priv_key, &dummy_hash).expect("sign");
    let pub_key = sig
        .recover_uncompressed_pubkey(&dummy_hash)
        .expect("recover");
    let h = tron_crypto::hash::keccak256(&pub_key[1..]);
    let mut addr = [0u8; 21];
    addr[0] = 0x41;
    addr[1..].copy_from_slice(&h[12..]);
    (priv_key, addr)
}

fn build_state() -> StateBackends {
    StateBackends {
        accounts: mem(),
        witnesses: mem(),
        votes: mem(),
        delegation: mem(),
        delegated_resources: mem(),
        dyn_props: mem(),
        proposals: mem(),
        name_index: mem(),
        id_index: mem(),
        asset_v1: mem(),
        asset_v2: mem(),
        contracts: mem(),
        abi: mem(),
        exchange_v1: mem(),
        exchange_v2: mem(),
        market_orders: mem(),
        nullifiers: mem(),
        merkle_trees: None,
        code: Some(mem()),
        storage_row: Some(mem()),
        contract_state: Some(mem()),
        block_index: Some(mem()),
        witness_schedule: Some(mem()),
    }
}

fn make_block(num: i64, parent: [u8; 32], txs: Vec<Transaction>) -> Block {
    Block {
        block_header: Some(BlockHeader {
            raw_data: Some(tron_proto::block_header::Raw {
                number: num,
                parent_hash: parent.to_vec(),
                timestamp: 1_700_000_000_000,
                tx_trie_root: tron_types::calc_tx_trie_root(&txs)
                    .map(|h| h.to_vec())
                    .unwrap_or_default(),
                ..Default::default()
            }),
            ..Default::default()
        }),
        transactions: txs,
    }
}

#[test]
fn executor_runs_trigger_smart_contract_end_to_end() {
    let state = build_state();
    let (caller_priv, caller_bytes) = caller_keypair(0xa1);
    let contract_bytes = addr_with_byte(0xc1);

    // Bytecode: SSTORE 0x42 at slot 0; STOP.
    // PUSH1 0x42 PUSH1 0x00 SSTORE STOP
    let bytecode: Vec<u8> = vec![0x60, 0x42, 0x60, 0x00, 0x55, 0x00];

    // Pre-install caller (with balance) and the contract account + code.
    let accounts = AccountStore::new(state.accounts.clone());
    accounts.put(
        &Address::from_raw(caller_bytes),
        &Account {
            address: caller_bytes.to_vec(),
            balance: 1_000_000_000,
            ..Default::default()
        },
    );
    let code = CodeStore::new(state.code.as_ref().unwrap().clone());
    let hash = tron_crypto::hash::keccak256(&bytecode);
    code.put(&hash, &bytecode);
    accounts.put(
        &Address::from_raw(contract_bytes),
        &Account {
            address: contract_bytes.to_vec(),
            balance: 0,
            code: bytecode.clone(),
            code_hash: hash.to_vec(),
            ..Default::default()
        },
    );

    // Build the TriggerSmartContract transaction.
    let trigger = TriggerSmartContract {
        owner_address: caller_bytes.to_vec(),
        contract_address: contract_bytes.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };
    let any = Any {
        type_url: "type.googleapis.com/protocol.TriggerSmartContract".into(),
        value: trigger.encode_to_vec(),
    };
    let mut tx = Transaction {
        raw_data: Some(TxRaw {
            contract: vec![TxContract {
                r#type: ContractType::TriggerSmartContract as i32,
                parameter: Some(any),
                ..Default::default()
            }],
            timestamp: 1_700_000_000_000,
            ..Default::default()
        }),
        signature: Vec::new(),
        ret: Vec::new(),
    };
    tron_types::sign_transaction(&mut tx, &caller_priv).expect("sign tx");

    let block = make_block(1, [0u8; 32], vec![tx]);
    let report = apply_unsigned(&state, &block, None).expect("execute_block");
    assert_eq!(
        report.failures(),
        0,
        "expected success, got: {:?}",
        report.tx_results[0].outcome
    );
    assert!(matches!(
        report.tx_results[0].outcome,
        TxOutcome::Success
    ));

    // The SSTORE must have landed in StorageRowStore via the v2
    // composite-key layout.
    let storage = StorageRowStore::new(state.storage_row.as_ref().unwrap().clone());
    let composite = StorageRowStore::compose_key(&Address::from_raw(contract_bytes), &[0u8; 32]);
    let stored = storage.get(&composite).expect("storage row missing");
    let mut expected = [0u8; 32];
    expected[31] = 0x42;
    assert_eq!(stored, expected.to_vec());
}

#[test]
fn executor_top_level_calltoken_trigger_runs_with_trc10_transfer() {
    let state = build_state();
    let (caller_priv, caller_bytes) = caller_keypair(0xa2);
    let contract_bytes = addr_with_byte(0xc2);

    // Install an empty-stop contract so the VM has something to call,
    // and seed the caller with TRC-10 balance so the transfer succeeds.
    let accounts = AccountStore::new(state.accounts.clone());
    let token_id: i64 = 1_000_001;
    let key = token_id.to_string();
    let mut caller_acct = Account {
        address: caller_bytes.to_vec(),
        balance: 1_000_000_000,
        ..Default::default()
    };
    caller_acct.asset_v2.insert(key.clone(), 1_000);
    accounts.put(&Address::from_raw(caller_bytes), &caller_acct);
    accounts.put(
        &Address::from_raw(contract_bytes),
        &Account {
            address: contract_bytes.to_vec(),
            ..Default::default()
        },
    );

    // TriggerSmartContract with non-zero call_token_value → asset transferred,
    // EVM runs the (empty-STOP) contract bytecode, transaction succeeds.
    let trigger = TriggerSmartContract {
        owner_address: caller_bytes.to_vec(),
        contract_address: contract_bytes.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 100,
        token_id,
    };
    let any = Any {
        type_url: "type.googleapis.com/protocol.TriggerSmartContract".into(),
        value: trigger.encode_to_vec(),
    };
    let mut tx = Transaction {
        raw_data: Some(TxRaw {
            contract: vec![TxContract {
                r#type: ContractType::TriggerSmartContract as i32,
                parameter: Some(any),
                ..Default::default()
            }],
            timestamp: 1_700_000_000_000,
            ..Default::default()
        }),
        signature: Vec::new(),
        ret: Vec::new(),
    };
    tron_types::sign_transaction(&mut tx, &caller_priv).expect("sign tx");

    let block = make_block(1, [0u8; 32], vec![tx]);
    let report = apply_unsigned(&state, &block, None).unwrap();
    assert_eq!(
        report.failures(),
        0,
        "transaction should succeed: {:?}",
        report.tx_results[0].outcome
    );
    assert!(matches!(report.tx_results[0].outcome, TxOutcome::Success));

    // Caller debited 100, contract credited 100.
    let after_caller = accounts
        .get(&Address::from_raw(caller_bytes))
        .unwrap()
        .unwrap();
    assert_eq!(after_caller.asset_v2.get(&key).copied(), Some(900));
    let after_contract = accounts
        .get(&Address::from_raw(contract_bytes))
        .unwrap()
        .unwrap();
    assert_eq!(after_contract.asset_v2.get(&key).copied(), Some(100));
    let _ = BlockId::from_raw([0u8; 32]); // suppress unused dep
}

// =============================================================================
// Phase 8c: witness produced-counter bumping
// =============================================================================

#[test]
fn executing_block_bumps_witnesss_total_produced_counter() {
    use tron_chainbase::WitnessStore;
    use tron_crypto::signature::RecoverableSignature;
    use tron_proto::Witness;

    let state = build_state();

    // Witness keypair (deterministic).
    let mut priv_key = [0u8; 32];
    priv_key[0] = 0x01;
    priv_key[31] = 0xaa;
    let dummy_hash = [0x42u8; 32];
    let sig = RecoverableSignature::sign_prehash(&priv_key, &dummy_hash).expect("sign");
    let pub_key = sig
        .recover_uncompressed_pubkey(&dummy_hash)
        .expect("recover");
    let h = tron_crypto::hash::keccak256(&pub_key[1..]);
    let mut witness_addr = [0u8; 21];
    witness_addr[0] = 0x41;
    witness_addr[1..].copy_from_slice(&h[12..]);
    let witness_addr_typed = tron_crypto::address::Address::from_raw(witness_addr);

    // Pre-register the witness with a starting count.
    let ws = WitnessStore::new(state.witnesses.clone());
    ws.put(
        &witness_addr_typed,
        &Witness {
            address: witness_addr.to_vec(),
            vote_count: 1_000,
            total_produced: 7, // starting value
            ..Default::default()
        },
    );

    // Build a block signed by this witness.
    let parent = tron_types::BlockId::from_raw([0u8; 32]);
    let (block, _) = tron_consensus::produce_block(
        &parent,
        1,
        1_700_000_003_000,
        &witness_addr_typed,
        &priv_key,
        vec![],
        29,
    )
    .unwrap();

    let _ = apply_unsigned(&state, &block, None).unwrap();

    let updated = ws.get(&witness_addr_typed).unwrap().unwrap();
    assert_eq!(updated.total_produced, 8, "counter should bump by 1");
    assert_eq!(updated.latest_block_num, 1, "latest_block_num should track");
    // latest_slot_num = (blockTime - genesis_ts) / 3_000.
    // Fixture starts fresh (genesis_ts = 0), blockTime = 1_700_000_003_000.
    assert_eq!(
        updated.latest_slot_num,
        1_700_000_003_000 / 3_000,
        "latest_slot_num = absolute slot since genesis (mirrors java-tron StatisticManager.applyBlock)"
    );
    assert_eq!(updated.vote_count, 1_000, "other fields preserved");
}

#[test]
fn executing_block_for_unknown_witness_does_not_panic() {
    use tron_crypto::signature::RecoverableSignature;

    let state = build_state();

    // Derive a real witness address from a seeded private key, but
    // DON'T pre-register the witness — verifies the executor's
    // counter-update path tolerates a missing WitnessStore entry.
    let mut priv_key = [0u8; 32];
    priv_key[0] = 0x02;
    priv_key[31] = 0xbb;
    let dummy_hash = [0x42u8; 32];
    let sig = RecoverableSignature::sign_prehash(&priv_key, &dummy_hash).expect("sign");
    let pub_key = sig.recover_uncompressed_pubkey(&dummy_hash).expect("recover");
    let h = tron_crypto::hash::keccak256(&pub_key[1..]);
    let mut witness_addr = [0u8; 21];
    witness_addr[0] = 0x41;
    witness_addr[1..].copy_from_slice(&h[12..]);
    let witness = tron_crypto::address::Address::from_raw(witness_addr);

    let parent = tron_types::BlockId::from_raw([0u8; 32]);
    let (block, _) = tron_consensus::produce_block(
        &parent,
        1,
        1_700_000_003_000,
        &witness,
        &priv_key,
        vec![],
        29,
    )
    .unwrap();

    // Should succeed with no panic — counter update silently skipped.
    let _ = apply_unsigned(&state, &block, None).unwrap();
}

/// Mirrors java-tron's `StatisticManager.applyBlock`: when a block lands
/// in a slot beyond the next expected slot, every SR scheduled for the
/// skipped slots in between has their `total_missed` bumped.
///
/// Setup: genesis at t=0, prev block at slot 1 (t=3000ms), this block
/// lands at slot 4 (t=12000ms). Slots 2 and 3 were missed; the SRs
/// scheduled for those slots (indices 1 and 2 in the active list) get
/// `total_missed += 1`.
#[test]
fn executing_block_bumps_total_missed_for_skipped_slots() {
    use tron_chainbase::{
        DynamicPropertiesStore, WitnessScheduleStore, WitnessStore,
    };
    use tron_crypto::signature::RecoverableSignature;
    use tron_proto::Witness;

    let state = build_state();

    // Build a deterministic producer keypair for the block we'll execute.
    let mut priv_key = [0u8; 32];
    priv_key[0] = 0x03;
    priv_key[31] = 0xcc;
    let dummy = [0x42u8; 32];
    let sig = RecoverableSignature::sign_prehash(&priv_key, &dummy).expect("sign");
    let pubkey = sig.recover_uncompressed_pubkey(&dummy).expect("recover");
    let h = tron_crypto::hash::keccak256(&pubkey[1..]);
    let mut producer_bytes = [0u8; 21];
    producer_bytes[0] = 0x41;
    producer_bytes[1..].copy_from_slice(&h[12..]);
    let producer = Address::from_raw(producer_bytes);

    // Build five distinct fake addresses for the active witness schedule.
    // Indices 1 and 2 are what we expect to be debited.
    let mut active: Vec<Address> = (0..5_u8)
        .map(|i| {
            let mut a = [0u8; 21];
            a[0] = 0x41;
            a[1] = 0xa0 + i;
            Address::from_raw(a)
        })
        .collect();
    // Stamp the producer at a known index (index 3) so we can verify
    // total_produced bumps independently of the miss accounting.
    active[3] = producer;
    WitnessScheduleStore::new(state.witness_schedule.clone().unwrap())
        .save_active(&active);

    // Seed witness rows for everyone in the schedule with a starting
    // total_missed of 0. (Unknown witnesses are silently skipped, so
    // we *must* seed the ones we want to observe.)
    let ws = WitnessStore::new(state.witnesses.clone());
    for (i, a) in active.iter().enumerate() {
        ws.put(
            a,
            &Witness {
                address: a.as_bytes().to_vec(),
                vote_count: 100 + i as i64,
                ..Default::default()
            },
        );
    }

    // Genesis at t=0, prev block at t=3000ms (slot 1). This block lands
    // at t=12000ms (slot 4). Slots 2 and 3 were missed → witnesses[1]
    // and witnesses[2] should each gain a miss.
    let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
    dp.save_genesis_block_timestamp(0);
    dp.save_latest_block_header_timestamp(3_000);
    dp.save_latest_block_header_number(1);

    // Block at number=2, timestamp = 12_000.
    let parent = tron_types::BlockId::from_raw([0u8; 32]);
    let (block, _) = tron_consensus::produce_block(
        &parent,
        2,
        12_000,
        &producer,
        &priv_key,
        vec![],
        29,
    )
    .unwrap();

    apply_unsigned(&state, &block, None).expect("execute");

    // The producer (active[3]) should have total_produced = 1.
    let prod_row = ws.get(&producer).unwrap().unwrap();
    assert_eq!(prod_row.total_produced, 1);
    assert_eq!(prod_row.total_missed, 0);

    // Witnesses at indices 1 and 2 should each have total_missed = 1.
    let m1 = ws.get(&active[1]).unwrap().unwrap();
    let m2 = ws.get(&active[2]).unwrap().unwrap();
    assert_eq!(m1.total_missed, 1, "slot 2 scheduled SR (index 1)");
    assert_eq!(m2.total_missed, 1, "slot 3 scheduled SR (index 2)");

    // No collateral damage on the others.
    let m0 = ws.get(&active[0]).unwrap().unwrap();
    let m4 = ws.get(&active[4]).unwrap().unwrap();
    assert_eq!(m0.total_missed, 0);
    assert_eq!(m4.total_missed, 0);
}

/// Block 1 is special-cased to skip miss attribution in
/// `StatisticManager` (no previous producer to anchor the slot gap).
/// Verify we mirror that — even with a schedule loaded and a wide
/// timestamp gap to genesis, no witnesses get debited.
#[test]
fn executing_block_one_does_not_attribute_misses() {
    use tron_chainbase::{
        DynamicPropertiesStore, WitnessScheduleStore, WitnessStore,
    };
    use tron_crypto::signature::RecoverableSignature;
    use tron_proto::Witness;

    let state = build_state();

    let mut priv_key = [0u8; 32];
    priv_key[0] = 0x04;
    priv_key[31] = 0xdd;
    let dummy = [0x42u8; 32];
    let sig = RecoverableSignature::sign_prehash(&priv_key, &dummy).expect("sign");
    let pubkey = sig.recover_uncompressed_pubkey(&dummy).expect("recover");
    let h = tron_crypto::hash::keccak256(&pubkey[1..]);
    let mut producer_bytes = [0u8; 21];
    producer_bytes[0] = 0x41;
    producer_bytes[1..].copy_from_slice(&h[12..]);
    let producer = Address::from_raw(producer_bytes);

    let other_bytes = addr_with_byte(0xe1);
    let other = Address::from_raw(other_bytes);

    WitnessScheduleStore::new(state.witness_schedule.clone().unwrap())
        .save_active(&[producer, other]);

    let ws = WitnessStore::new(state.witnesses.clone());
    ws.put(
        &other,
        &Witness {
            address: other_bytes.to_vec(),
            ..Default::default()
        },
    );

    let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
    dp.save_genesis_block_timestamp(0);
    dp.save_latest_block_header_timestamp(0);
    // (No latest_block_header_number set → block 1 is the first block.)

    let parent = tron_types::BlockId::from_raw([0u8; 32]);
    let (block, _) = tron_consensus::produce_block(
        &parent,
        1,           // block 1 → miss attribution must be skipped
        30_000,      // 10 slots after genesis; would otherwise mis-debit
        &producer,
        &priv_key,
        vec![],
        29,
    )
    .unwrap();

    apply_unsigned(&state, &block, None).expect("execute");

    let m = ws.get(&other).unwrap().unwrap();
    assert_eq!(m.total_missed, 0, "block 1 must not debit anyone");
}

#[test]
fn trigger_smart_contract_with_wrong_signer_is_rejected_by_permission_check() {
    // Regression test: VM-bound transactions (TriggerSmartContract /
    // CreateSmartContract) must run through `check_transaction_permission`
    // before dispatching to the VM. A common mistake is to wire the
    // permission check only for non-VM contracts and let VM-bound ones
    // skip it — that lets anyone trigger any contract with any
    // signature. java-tron enforces; we must too.
    let state = build_state();

    // Two distinct keypairs. The TRANSACTION names `owner_address =
    // caller_bytes` (Alice's address), but the SIGNATURE is over the
    // raw_data using Bob's private key. Permission check should
    // recover Bob as the signer, find that Bob is not in Alice's
    // permission, and reject with PermissionDenied.
    let (_alice_priv, alice_bytes) = caller_keypair(0xa3);
    let (bob_priv, _bob_bytes) = caller_keypair(0xb3);
    let contract_bytes = addr_with_byte(0xc3);
    let bytecode: Vec<u8> = vec![0x60, 0x42, 0x60, 0x00, 0x55, 0x00];

    let accounts = AccountStore::new(state.accounts.clone());
    accounts.put(
        &Address::from_raw(alice_bytes),
        &Account {
            address: alice_bytes.to_vec(),
            balance: 1_000_000_000,
            ..Default::default()
        },
    );
    let code = CodeStore::new(state.code.as_ref().unwrap().clone());
    let hash = tron_crypto::hash::keccak256(&bytecode);
    code.put(&hash, &bytecode);
    accounts.put(
        &Address::from_raw(contract_bytes),
        &Account {
            address: contract_bytes.to_vec(),
            balance: 0,
            code: bytecode.clone(),
            code_hash: hash.to_vec(),
            ..Default::default()
        },
    );

    let trigger = TriggerSmartContract {
        owner_address: alice_bytes.to_vec(),
        contract_address: contract_bytes.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };
    let any = Any {
        type_url: "type.googleapis.com/protocol.TriggerSmartContract".into(),
        value: trigger.encode_to_vec(),
    };
    let mut tx = Transaction {
        raw_data: Some(TxRaw {
            contract: vec![TxContract {
                r#type: ContractType::TriggerSmartContract as i32,
                parameter: Some(any),
                ..Default::default()
            }],
            timestamp: 1_700_000_000_000,
            ..Default::default()
        }),
        signature: Vec::new(),
        ret: Vec::new(),
    };
    // Sign with BOB's key, even though the transaction says Alice
    // is the owner.
    tron_types::sign_transaction(&mut tx, &bob_priv).expect("sign with wrong key");

    let block = make_block(1, [0u8; 32], vec![tx]);
    let report = apply_unsigned(&state, &block, None).expect("execute_block");
    let outcome = &report.tx_results[0].outcome;
    assert!(
        matches!(outcome, TxOutcome::Invalid(ActuatorError::PermissionDenied(_))),
        "expected PermissionDenied, got {:?}",
        outcome
    );

    // The VM must NOT have executed — the storage slot stays absent.
    let storage = StorageRowStore::new(state.storage_row.as_ref().unwrap().clone());
    let composite =
        StorageRowStore::compose_key(&Address::from_raw(contract_bytes), &[0u8; 32]);
    assert!(
        storage.get(&composite).is_none(),
        "VM ran despite permission rejection — storage slot should still be absent"
    );
}

/// Verifies the EVM inspector captures nested-CALL traces and surfaces
/// them on `TxResult.internal_transactions`. Contract A's bytecode
/// performs a single nested CALL into contract B (which is a no-op
/// STOP). The trace must contain exactly one entry: note == "call",
/// caller == A, target == B, rejected == false.
#[test]
fn internal_call_trace_is_captured_for_nested_call() {
    let state = build_state();
    let (caller_priv, caller_bytes) = caller_keypair(0xe1);
    let contract_a_bytes = addr_with_byte(0xea);
    let contract_b_bytes = addr_with_byte(0xeb);

    // Contract B: just STOP.
    let b_bytecode: Vec<u8> = vec![0x00];

    // Contract A: CALL B with no value, no data. Stack pushes are
    // bottom-up (last pushed is topmost):
    //   gas, addr, value, argOffset, argLen, retOffset, retLen → CALL
    // So push in REVERSE: retLen, retOffset, argLen, argOffset, value,
    // addr, gas.
    let mut a_bytecode: Vec<u8> = vec![
        0x60, 0x00, // PUSH1 0   (retLen)
        0x60, 0x00, // PUSH1 0   (retOffset)
        0x60, 0x00, // PUSH1 0   (argLen)
        0x60, 0x00, // PUSH1 0   (argOffset)
        0x60, 0x00, // PUSH1 0   (value)
        0x73,       // PUSH20
    ];
    // The address pushed onto the EVM stack is the 20-byte form (no
    // 0x41 prefix) — `evm_to_tron_address` round-trips it back to 21
    // bytes when the inspector records the trace.
    a_bytecode.extend_from_slice(&contract_b_bytes[1..]);
    a_bytecode.extend_from_slice(&[
        0x5A, // GAS
        0xF1, // CALL
        0x00, // STOP
    ]);

    // Pre-install caller + both contracts.
    let accounts = AccountStore::new(state.accounts.clone());
    accounts.put(
        &Address::from_raw(caller_bytes),
        &Account {
            address: caller_bytes.to_vec(),
            balance: 1_000_000_000,
            ..Default::default()
        },
    );
    let code = CodeStore::new(state.code.as_ref().unwrap().clone());
    let a_hash = tron_crypto::hash::keccak256(&a_bytecode);
    let b_hash = tron_crypto::hash::keccak256(&b_bytecode);
    code.put(&a_hash, &a_bytecode);
    code.put(&b_hash, &b_bytecode);
    accounts.put(
        &Address::from_raw(contract_a_bytes),
        &Account {
            address: contract_a_bytes.to_vec(),
            balance: 0,
            code: a_bytecode,
            code_hash: a_hash.to_vec(),
            ..Default::default()
        },
    );
    accounts.put(
        &Address::from_raw(contract_b_bytes),
        &Account {
            address: contract_b_bytes.to_vec(),
            balance: 0,
            code: b_bytecode,
            code_hash: b_hash.to_vec(),
            ..Default::default()
        },
    );

    // Trigger A.
    let trigger = TriggerSmartContract {
        owner_address: caller_bytes.to_vec(),
        contract_address: contract_a_bytes.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };
    let any = Any {
        type_url: "type.googleapis.com/protocol.TriggerSmartContract".into(),
        value: trigger.encode_to_vec(),
    };
    let mut tx = Transaction {
        raw_data: Some(TxRaw {
            contract: vec![TxContract {
                r#type: ContractType::TriggerSmartContract as i32,
                parameter: Some(any),
                ..Default::default()
            }],
            timestamp: 1_700_000_000_000,
            ..Default::default()
        }),
        signature: Vec::new(),
        ret: Vec::new(),
    };
    tron_types::sign_transaction(&mut tx, &caller_priv).expect("sign tx");

    let block = make_block(1, [0u8; 32], vec![tx]);
    let cfg = ExecConfig {
        save_internal_tx: true,
        // Test fixture builds an unsigned block via `make_block`; opt out
        // of the strict witness-sig gate accordingly.
        ..ExecConfig::unsigned()
    };
    let report = execute_block_with_config(&state, &block, None, &cfg).expect("execute_block");

    let tx_result = &report.tx_results[0];
    assert!(
        matches!(tx_result.outcome, TxOutcome::Success),
        "expected Success, got {:?}",
        tx_result.outcome
    );

    // Exactly one internal-tx entry for the nested CALL into B.
    assert_eq!(
        tx_result.internal_transactions.len(),
        1,
        "expected one internal call trace; got: {:?}",
        tx_result.internal_transactions
    );
    let entry = &tx_result.internal_transactions[0];
    assert_eq!(entry.note, b"call", "note should be 'call'");
    assert_eq!(
        entry.caller_address, contract_a_bytes,
        "caller should be A (the contract executing CALL)"
    );
    assert_eq!(
        entry.transfer_to_address, contract_b_bytes,
        "target should be B (the CALL target)"
    );
    assert!(
        !entry.rejected,
        "B's STOP succeeds, so the call is not rejected"
    );
    assert_eq!(
        entry.hash, tx_result.tx_id,
        "internal_transaction.hash points at the root tx id"
    );
}

/// SELFDESTRUCT must produce an internal-tx entry with note "suicide",
/// caller = the destroyed contract, target = the beneficiary, value =
/// the contract's pre-destruction balance. Mirrors java-tron's
/// `Program.suicide` which calls
/// `addInternalTx(null, owner, obtainer, balance, null, "suicide", ...)`.
#[test]
fn selfdestruct_emits_suicide_internal_tx() {
    let state = build_state();
    let (caller_priv, caller_bytes) = caller_keypair(0xe2);
    let contract_bytes = addr_with_byte(0xec);
    let beneficiary_bytes = addr_with_byte(0xed);

    // Bytecode: PUSH20 <beneficiary>, SELFDESTRUCT.
    let mut bytecode: Vec<u8> = vec![0x73]; // PUSH20
    bytecode.extend_from_slice(&beneficiary_bytes[1..]); // 20-byte form
    bytecode.push(0xFF); // SELFDESTRUCT

    let accounts = AccountStore::new(state.accounts.clone());
    accounts.put(
        &Address::from_raw(caller_bytes),
        &Account {
            address: caller_bytes.to_vec(),
            balance: 1_000_000_000,
            ..Default::default()
        },
    );
    let code = CodeStore::new(state.code.as_ref().unwrap().clone());
    let code_hash = tron_crypto::hash::keccak256(&bytecode);
    code.put(&code_hash, &bytecode);
    // Contract has a non-zero balance so we can assert it shows up as
    // the suicide entry's value.
    let contract_balance: i64 = 12_345;
    accounts.put(
        &Address::from_raw(contract_bytes),
        &Account {
            address: contract_bytes.to_vec(),
            balance: contract_balance,
            code: bytecode,
            code_hash: code_hash.to_vec(),
            ..Default::default()
        },
    );

    let trigger = TriggerSmartContract {
        owner_address: caller_bytes.to_vec(),
        contract_address: contract_bytes.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };
    let any = Any {
        type_url: "type.googleapis.com/protocol.TriggerSmartContract".into(),
        value: trigger.encode_to_vec(),
    };
    let mut tx = Transaction {
        raw_data: Some(TxRaw {
            contract: vec![TxContract {
                r#type: ContractType::TriggerSmartContract as i32,
                parameter: Some(any),
                ..Default::default()
            }],
            timestamp: 1_700_000_000_000,
            ..Default::default()
        }),
        signature: Vec::new(),
        ret: Vec::new(),
    };
    tron_types::sign_transaction(&mut tx, &caller_priv).expect("sign tx");

    let block = make_block(1, [0u8; 32], vec![tx]);
    let cfg = ExecConfig {
        save_internal_tx: true,
        // Test fixture builds an unsigned block via `make_block`; opt out
        // of the strict witness-sig gate accordingly.
        ..ExecConfig::unsigned()
    };
    let report = execute_block_with_config(&state, &block, None, &cfg).expect("execute_block");

    let tx_result = &report.tx_results[0];
    assert!(
        matches!(tx_result.outcome, TxOutcome::Success),
        "expected Success, got {:?}",
        tx_result.outcome
    );

    assert_eq!(
        tx_result.internal_transactions.len(),
        1,
        "expected exactly one 'suicide' internal-tx entry; got: {:?}",
        tx_result.internal_transactions
    );
    let entry = &tx_result.internal_transactions[0];
    assert_eq!(entry.note, b"suicide", "note should be 'suicide'");
    assert_eq!(
        entry.caller_address, contract_bytes,
        "caller should be the destroyed contract"
    );
    assert_eq!(
        entry.transfer_to_address, beneficiary_bytes,
        "target should be the SELFDESTRUCT beneficiary"
    );
    assert!(!entry.rejected, "successful SELFDESTRUCT is not rejected");
    assert_eq!(
        entry.call_value_info.len(),
        1,
        "balance > 0 → exactly one CallValueInfo entry for the TRX heritage"
    );
    assert_eq!(
        entry.call_value_info[0].call_value, contract_balance,
        "value should be the contract's pre-destruction balance"
    );
    assert_eq!(
        entry.call_value_info[0].token_id, "",
        "no token_id for the TRX heritage entry"
    );
}

/// `ExecConfig::default()` (java-tron parity: vmTrace=false,
/// saveInternalTx=false) must DROP per-frame traces. Pairs with
/// [`internal_call_trace_is_captured_for_nested_call`] which exercises
/// the ON path with the same shape.
#[test]
fn default_exec_config_drops_internal_tx_traces() {
    use tron_chainbase::{AccountStore, CodeStore};
    use tron_crypto::address::Address;
    use tron_proto::transaction::{contract::ContractType, Contract as TxContract, Raw as TxRaw};
    use tron_proto::{Account, Transaction, TriggerSmartContract};
    use prost::Message as _;
    use prost_types::Any;

    let state = build_state();
    let (caller_priv, caller_bytes) = caller_keypair(0xe3);
    let contract_a_bytes = addr_with_byte(0xfa);
    let contract_b_bytes = addr_with_byte(0xfb);

    // Same A→B nested CALL fixture as the ON-path test, abbreviated.
    let b_bytecode: Vec<u8> = vec![0x00];
    let mut a_bytecode: Vec<u8> = vec![
        0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x73,
    ];
    a_bytecode.extend_from_slice(&contract_b_bytes[1..]);
    a_bytecode.extend_from_slice(&[0x5A, 0xF1, 0x00]);

    let accounts = AccountStore::new(state.accounts.clone());
    accounts.put(
        &Address::from_raw(caller_bytes),
        &Account {
            address: caller_bytes.to_vec(),
            balance: 1_000_000_000,
            ..Default::default()
        },
    );
    let code = CodeStore::new(state.code.as_ref().unwrap().clone());
    let a_hash = tron_crypto::hash::keccak256(&a_bytecode);
    let b_hash = tron_crypto::hash::keccak256(&b_bytecode);
    code.put(&a_hash, &a_bytecode);
    code.put(&b_hash, &b_bytecode);
    accounts.put(
        &Address::from_raw(contract_a_bytes),
        &Account {
            address: contract_a_bytes.to_vec(),
            balance: 0,
            code: a_bytecode,
            code_hash: a_hash.to_vec(),
            ..Default::default()
        },
    );
    accounts.put(
        &Address::from_raw(contract_b_bytes),
        &Account {
            address: contract_b_bytes.to_vec(),
            balance: 0,
            code: b_bytecode,
            code_hash: b_hash.to_vec(),
            ..Default::default()
        },
    );

    let trigger = TriggerSmartContract {
        owner_address: caller_bytes.to_vec(),
        contract_address: contract_a_bytes.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };
    let any = Any {
        type_url: "type.googleapis.com/protocol.TriggerSmartContract".into(),
        value: trigger.encode_to_vec(),
    };
    let mut tx = Transaction {
        raw_data: Some(TxRaw {
            contract: vec![TxContract {
                r#type: ContractType::TriggerSmartContract as i32,
                parameter: Some(any),
                ..Default::default()
            }],
            timestamp: 1_700_000_000_000,
            ..Default::default()
        }),
        signature: Vec::new(),
        ret: Vec::new(),
    };
    tron_types::sign_transaction(&mut tx, &caller_priv).expect("sign tx");

    let block = make_block(1, [0u8; 32], vec![tx]);
    // Default config: traces are DROPPED — proves the gate is real and
    // the ON-path test isn't a false positive that always produces
    // traces regardless of config.
    let report = apply_unsigned(&state, &block, None).expect("execute_block");

    let tx_result = &report.tx_results[0];
    assert!(
        matches!(tx_result.outcome, TxOutcome::Success),
        "expected Success, got {:?}",
        tx_result.outcome
    );
    assert!(
        tx_result.internal_transactions.is_empty(),
        "default ExecConfig must drop internal_transactions; got {} entries",
        tx_result.internal_transactions.len()
    );
}

// =============================================================================
// ET-C2: VM-frame state isolation — a tx whose top-level VM call
// REVERTs must leave contract storage / balances / etc. untouched
// while STILL charging energy (java-tron's consensus rule).
// =============================================================================

/// Mirrors the "SSTORE then STOP" contract above but reverts after
/// the SSTORE. Storage MUST NOT show the SSTOREd value; the executor
/// MUST still charge the caller for the energy the VM consumed
/// before the revert.
///
/// Bytecode (10 bytes): PUSH1 0x42 PUSH1 0x00 SSTORE PUSH1 0x00
/// PUSH1 0x00 REVERT.
#[test]
fn revert_after_sstore_drops_storage_write_but_charges_energy() {
    let state = build_state();
    let (caller_priv, caller_bytes) = caller_keypair(0xa3);
    let contract_bytes = addr_with_byte(0xc3);

    let bytecode: Vec<u8> = vec![
        0x60, 0x42, // PUSH1 0x42
        0x60, 0x00, // PUSH1 0x00 (slot)
        0x55,       // SSTORE
        0x60, 0x00, // PUSH1 0x00 (revert offset)
        0x60, 0x00, // PUSH1 0x00 (revert size)
        0xfd,       // REVERT
    ];

    // Pre-install caller with TRX balance (no frozen energy → fee path).
    // Pre-install contract with the bytecode.
    let accounts = AccountStore::new(state.accounts.clone());
    let initial_balance: i64 = 1_000_000_000;
    accounts.put(
        &Address::from_raw(caller_bytes),
        &Account {
            address: caller_bytes.to_vec(),
            balance: initial_balance,
            ..Default::default()
        },
    );
    let code = CodeStore::new(state.code.as_ref().unwrap().clone());
    let hash = tron_crypto::hash::keccak256(&bytecode);
    code.put(&hash, &bytecode);
    accounts.put(
        &Address::from_raw(contract_bytes),
        &Account {
            address: contract_bytes.to_vec(),
            balance: 0,
            code: bytecode.clone(),
            code_hash: hash.to_vec(),
            ..Default::default()
        },
    );

    // Pre-seed storage slot 0 with a sentinel so we can distinguish
    // "no write happened" from "write happened then was reverted into
    // an empty slot". After the revert the slot MUST still read 0x07.
    let storage = StorageRowStore::new(state.storage_row.as_ref().unwrap().clone());
    let composite_key =
        StorageRowStore::compose_key(&Address::from_raw(contract_bytes), &[0u8; 32]);
    let mut sentinel = [0u8; 32];
    sentinel[31] = 0x07;
    storage.put(&composite_key, &sentinel);

    let trigger = TriggerSmartContract {
        owner_address: caller_bytes.to_vec(),
        contract_address: contract_bytes.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };
    let any = Any {
        type_url: "type.googleapis.com/protocol.TriggerSmartContract".into(),
        value: trigger.encode_to_vec(),
    };
    let mut tx = Transaction {
        raw_data: Some(TxRaw {
            contract: vec![TxContract {
                r#type: ContractType::TriggerSmartContract as i32,
                parameter: Some(any),
                ..Default::default()
            }],
            timestamp: 1_700_000_000_000,
            ..Default::default()
        }),
        signature: Vec::new(),
        ret: Vec::new(),
    };
    tron_types::sign_transaction(&mut tx, &caller_priv).expect("sign");

    let block = make_block(1, [0u8; 32], vec![tx]);
    let report = apply_unsigned(&state, &block, None).expect("execute_block");
    assert_eq!(report.tx_results.len(), 1);

    // Outcome should be ExecutionFailed("VM revert") — the tx is
    // rejected, but the energy still applies. Halt would mean the
    // revert wasn't reached (e.g. the SSTORE ran out of gas).
    let tx_result = &report.tx_results[0];
    match &tx_result.outcome {
        TxOutcome::ExecutionFailed(e) => {
            let s = format!("{e}");
            assert!(s.contains("VM revert"), "expected 'VM revert', got: {s}");
        }
        other => panic!("expected ExecutionFailed(VM revert), got {other:?}"),
    }

    // The decisive assertion: storage slot 0 still holds the sentinel.
    // Pre-fix this would fail with the SSTOREd value 0x42 (or, worst
    // case, with revm's net-zero "delete the slot" depending on
    // commit semantics).
    let after_value = storage
        .get(&composite_key)
        .expect("sentinel must still be there");
    assert_eq!(
        after_value, sentinel,
        "revert must drop the SSTORE; slot 0 should still read 0x07"
    );

    // Energy charge survived the revert. The caller's TRX balance
    // shrank by `energy_used * energy_fee` sun. Exact value is
    // VM-dependent; assert "strictly less than starting balance" so
    // the test isn't tied to a specific gas formula.
    let after_caller = accounts
        .get(&Address::from_raw(caller_bytes))
        .unwrap()
        .expect("caller account still present");
    assert!(
        after_caller.balance < initial_balance,
        "energy charge must apply on revert: balance was {}, expected < {}",
        after_caller.balance,
        initial_balance
    );
}

/// Companion: a Halt (e.g. out-of-gas) on a tx that performed
/// state-changing ops must ALSO drop those state changes while
/// keeping the energy charge. Uses a contract with an infinite loop
/// preceded by an SSTORE — the SSTORE runs, then the loop runs out
/// of gas. Storage must still read the pre-call sentinel.
#[test]
fn halt_after_sstore_drops_storage_write_but_charges_energy() {
    let state = build_state();
    let (caller_priv, caller_bytes) = caller_keypair(0xa4);
    let contract_bytes = addr_with_byte(0xc4);

    // SSTORE 0x42 to slot 0, then JUMPDEST loop forever.
    // PUSH1 0x42 PUSH1 0x00 SSTORE JUMPDEST PUSH1 0x05 JUMP
    let bytecode: Vec<u8> = vec![
        0x60, 0x42, // PUSH1 0x42
        0x60, 0x00, // PUSH1 0x00
        0x55,       // SSTORE
        0x5b,       // JUMPDEST (pc=5)
        0x60, 0x05, // PUSH1 0x05
        0x56,       // JUMP
    ];

    let accounts = AccountStore::new(state.accounts.clone());
    let initial_balance: i64 = 1_000_000_000;
    accounts.put(
        &Address::from_raw(caller_bytes),
        &Account {
            address: caller_bytes.to_vec(),
            balance: initial_balance,
            ..Default::default()
        },
    );
    let code = CodeStore::new(state.code.as_ref().unwrap().clone());
    let hash = tron_crypto::hash::keccak256(&bytecode);
    code.put(&hash, &bytecode);
    accounts.put(
        &Address::from_raw(contract_bytes),
        &Account {
            address: contract_bytes.to_vec(),
            balance: 0,
            code: bytecode.clone(),
            code_hash: hash.to_vec(),
            ..Default::default()
        },
    );

    let storage = StorageRowStore::new(state.storage_row.as_ref().unwrap().clone());
    let composite_key =
        StorageRowStore::compose_key(&Address::from_raw(contract_bytes), &[0u8; 32]);
    let mut sentinel = [0u8; 32];
    sentinel[31] = 0x09;
    storage.put(&composite_key, &sentinel);

    let trigger = TriggerSmartContract {
        owner_address: caller_bytes.to_vec(),
        contract_address: contract_bytes.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };
    let any = Any {
        type_url: "type.googleapis.com/protocol.TriggerSmartContract".into(),
        value: trigger.encode_to_vec(),
    };
    let mut tx = Transaction {
        raw_data: Some(TxRaw {
            contract: vec![TxContract {
                r#type: ContractType::TriggerSmartContract as i32,
                parameter: Some(any),
                ..Default::default()
            }],
            timestamp: 1_700_000_000_000,
            ..Default::default()
        }),
        signature: Vec::new(),
        ret: Vec::new(),
    };
    tron_types::sign_transaction(&mut tx, &caller_priv).expect("sign");

    let block = make_block(1, [0u8; 32], vec![tx]);
    let report = apply_unsigned(&state, &block, None).expect("execute_block");
    let tx_result = &report.tx_results[0];
    match &tx_result.outcome {
        TxOutcome::ExecutionFailed(e) => {
            let s = format!("{e}");
            assert!(
                s.contains("VM halt"),
                "expected 'VM halt' (out-of-gas loop), got: {s}"
            );
        }
        other => panic!("expected ExecutionFailed(VM halt), got {other:?}"),
    }
    let after = storage.get(&composite_key).expect("sentinel must remain");
    assert_eq!(
        after, sentinel,
        "halt must drop the SSTORE; slot 0 should still read 0x09"
    );
    let after_caller = accounts
        .get(&Address::from_raw(caller_bytes))
        .unwrap()
        .unwrap();
    assert!(
        after_caller.balance < initial_balance,
        "energy charge must apply on halt: balance was {}, expected < {}",
        after_caller.balance,
        initial_balance
    );
}
