//! Integration test for Phase 3c: executor → TVM wiring.
//!
//! Builds a `StateBackends` with EVM stores attached, then drives a
//! `TriggerSmartContract` transaction through `execute_block` and
//! verifies the contract actually ran (storage row written).

// Multi-threaded allocator for the throughput benchmark: the parallel block
// executor allocates heavily per tx (session fork + VM store wrappers), and the
// default glibc malloc serializes those across threads, capping scaling at ~4-8
// cores. mimalloc's per-thread heaps remove that ceiling.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::sync::Arc;

use prost::Message;
use prost_types::Any;
use tron_chainbase::{
    AccountStore, CodeStore, KvBackend, ShardedMemBackend, StorageRowStore,
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
    // Sharded so concurrent base reads scale (like RocksDB) instead of all 32
    // Block-STM threads serializing on one RwLock — otherwise the base lock, not
    // the MVCC machinery, dominates the parallel throughput benchmark.
    Arc::new(ShardedMemBackend::new())
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
        delegated_resource_account_index: None,
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
        market_account: mem(),
        nullifiers: mem(),
        merkle_trees: None,
        code: Some(mem()),
        storage_row: Some(mem()),
        contract_state: Some(mem()),
        block_index: Some(mem()),
        witness_schedule: Some(mem()),
        reward_vi: None,
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
    ).unwrap();
    let code = CodeStore::new(state.code.as_ref().unwrap().clone());
    let hash = tron_crypto::hash::keccak256(&bytecode);
    code.put(&hash, &bytecode).unwrap();
    accounts.put(
        &Address::from_raw(contract_bytes),
        &Account {
            address: contract_bytes.to_vec(),
            balance: 0,
            code: bytecode.clone(),
            code_hash: hash.to_vec(),
            ..Default::default()
        },
    ).unwrap();

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
        unparsed_field10: None,
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
    let stored = storage
        .get(&composite)
        .unwrap()
        .expect("storage row missing");
    let mut expected = [0u8; 32];
    expected[31] = 0x42;
    assert_eq!(stored, expected.to_vec());
}

/// Block-recorded `OUT_OF_TIME` deferral (java-tron parity).
///
/// java-tron terminates a VM tx that exceeds `maxCpuTimeOfOneTx` on the
/// producing SR with `OutOfTimeException`: it `spendAllEnergy()` and never
/// reaches `rootRepository.commit()`, so EVERY VM contract-state change is
/// discarded (the wallet debits never land) while the full energy budget is
/// charged. That outcome is a wall-clock artifact of the JVM — a non-JVM node
/// can't reproduce it by timing — so on replay/validation we DEFER to the
/// block's recorded `contractRet`: when it says `OUT_OF_TIME` we force the
/// outcome regardless of local execution.
///
/// This drives the EXACT same tx as
/// [`executor_runs_trigger_smart_contract_end_to_end`] (an SSTORE that our VM
/// would happily SUCCEED on), but stamps the block-recorded `contractRet =
/// OUT_OF_TIME`. The SSTORE must NOT land, the receipt must read OUT_OF_TIME,
/// and energy must still be charged.
#[test]
fn block_recorded_out_of_time_discards_vm_state_but_charges_energy() {
    let state = build_state();
    let (caller_priv, caller_bytes) = caller_keypair(0xa9);
    let contract_bytes = addr_with_byte(0xc9);

    // Same bytecode as the success test: PUSH1 0x42 PUSH1 0x00 SSTORE STOP.
    let bytecode: Vec<u8> = vec![0x60, 0x42, 0x60, 0x00, 0x55, 0x00];

    let accounts = AccountStore::new(state.accounts.clone());
    // Comfortably larger than the lenient-mode energy budget (10M energy *
    // 100 sun = 1e9 sun) so the full `spendAllEnergy` charge is always
    // coverable and the test never trips the insufficient-balance preflight.
    let caller_start_balance: i64 = 100_000_000_000;
    accounts
        .put(
            &Address::from_raw(caller_bytes),
            &Account {
                address: caller_bytes.to_vec(),
                balance: caller_start_balance,
                ..Default::default()
            },
        )
        .unwrap();
    let code = CodeStore::new(state.code.as_ref().unwrap().clone());
    let hash = tron_crypto::hash::keccak256(&bytecode);
    code.put(&hash, &bytecode).unwrap();
    accounts
        .put(
            &Address::from_raw(contract_bytes),
            &Account {
                address: contract_bytes.to_vec(),
                balance: 0,
                code: bytecode.clone(),
                code_hash: hash.to_vec(),
                ..Default::default()
            },
        )
        .unwrap();

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
            // A non-zero fee_limit so the (lenient-mode) energy budget — hence
            // the `spendAllEnergy` charge — is non-zero and observable.
            fee_limit: 1_000_000_000,
            ..Default::default()
        }),
        signature: Vec::new(),
        // The canonical block recorded this tx as OUT_OF_TIME. This is the
        // signal that forces the deferral.
        ret: vec![tron_proto::transaction::Result {
            contract_ret:
                tron_proto::transaction::result::ContractResult::OutOfTime as i32,
            ..Default::default()
        }],
        unparsed_field10: None,
    };
    tron_types::sign_transaction(&mut tx, &caller_priv).expect("sign tx");

    let block = make_block(1, [0u8; 32], vec![tx]);
    let report = apply_unsigned(&state, &block, None).expect("execute_block");
    let tx_result = &report.tx_results[0];

    // 1) The receipt result must be OUT_OF_TIME.
    assert_eq!(
        tx_result.receipt.result,
        tron_proto::transaction::result::ContractResult::OutOfTime as i32,
        "receipt result must be OUT_OF_TIME (deferred to block), got {:?}",
        tx_result.outcome
    );

    // 2) The VM state change (SSTORE) must have been DISCARDED — java's
    //    OutOfTimeException path never commits the child deposit. The storage
    //    slot the success-path test asserts present must be ABSENT here.
    let storage = StorageRowStore::new(state.storage_row.as_ref().unwrap().clone());
    let composite =
        StorageRowStore::compose_key(&Address::from_raw(contract_bytes), &[0u8; 32]);
    assert!(
        storage.get(&composite).unwrap().is_none(),
        "OUT_OF_TIME must discard VM state; the SSTORE slot should be absent"
    );

    // 3) Energy must still be charged (`spendAllEnergy` → full budget). In
    //    lenient mode the energy is billed entirely as a TRX fee (the test
    //    caller has no staked energy), so the caller's balance drops.
    assert!(
        tx_result.receipt.energy_usage_total > 0,
        "OUT_OF_TIME must charge the full energy budget; energy_usage_total was 0"
    );
    let after_caller = accounts
        .get(&Address::from_raw(caller_bytes))
        .unwrap()
        .unwrap();
    assert!(
        after_caller.balance < caller_start_balance,
        "OUT_OF_TIME must charge energy (caller balance {} should be < {})",
        after_caller.balance,
        caller_start_balance
    );
}

#[test]
fn executor_top_level_calltoken_trigger_runs_with_trc10_transfer() {
    let state = build_state();
    // Post-#15 (ALLOW_TVM_TRANSFER_TRC10): a top-level CALLTOKEN actually
    // transfers the TRC-10 amount. Pre-#15 the token fields are ignored (no
    // transfer) — that gate is verified by the tron-tvm CALLTOKEN unit tests.
    tron_chainbase::DynamicPropertiesStore::new(state.dyn_props.clone())
        .put_long(b"ALLOW_TVM_TRANSFER_TRC10", 1);
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
    accounts.put(&Address::from_raw(caller_bytes), &caller_acct).unwrap();
    accounts.put(
        &Address::from_raw(contract_bytes),
        &Account {
            address: contract_bytes.to_vec(),
            ..Default::default()
        },
    ).unwrap();

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
        unparsed_field10: None,
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
    ).unwrap();

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
    // Indices 2 and 3 are what we expect to be debited (java's
    // `DposSlot.getScheduledWitness(i)` = `active[(abSlot(head) + i) % N]`,
    // so missed abs slots 2 and 3 map to indices 2 and 3).
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
        .save_active(&active).unwrap();

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
        ).unwrap();
    }

    // Genesis at t=0, prev block at t=3000ms (abs slot 1). This block
    // lands at t=12000ms (abs slot 4). Abs slots 2 and 3 were missed →
    // the SRs scheduled at those slots, `active[2]` and `active[3]`
    // (which is the producer — java DOES debit a producer that skipped
    // its earlier slot), each gain a miss.
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

    // The producer (active[3]) should have total_produced = 1 — and one
    // miss: it was also the SR scheduled for skipped abs slot 3.
    let prod_row = ws.get(&producer).unwrap().unwrap();
    assert_eq!(prod_row.total_produced, 1);
    assert_eq!(prod_row.total_missed, 1, "abs slot 3 scheduled SR (index 3)");

    // The witness at index 2 takes the abs-slot-2 miss.
    let m2 = ws.get(&active[2]).unwrap().unwrap();
    assert_eq!(m2.total_missed, 1, "abs slot 2 scheduled SR (index 2)");

    // No collateral damage on the others.
    let m0 = ws.get(&active[0]).unwrap().unwrap();
    let m1 = ws.get(&active[1]).unwrap().unwrap();
    let m4 = ws.get(&active[4]).unwrap().unwrap();
    assert_eq!(m0.total_missed, 0);
    assert_eq!(m1.total_missed, 0);
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
        .save_active(&[producer, other]).unwrap();

    let ws = WitnessStore::new(state.witnesses.clone());
    ws.put(
        &other,
        &Witness {
            address: other_bytes.to_vec(),
            ..Default::default()
        },
    ).unwrap();

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
    ).unwrap();
    let code = CodeStore::new(state.code.as_ref().unwrap().clone());
    let hash = tron_crypto::hash::keccak256(&bytecode);
    code.put(&hash, &bytecode).unwrap();
    accounts.put(
        &Address::from_raw(contract_bytes),
        &Account {
            address: contract_bytes.to_vec(),
            balance: 0,
            code: bytecode.clone(),
            code_hash: hash.to_vec(),
            ..Default::default()
        },
    ).unwrap();

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
        unparsed_field10: None,
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
        storage.get(&composite).unwrap().is_none(),
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
    ).unwrap();
    let code = CodeStore::new(state.code.as_ref().unwrap().clone());
    let a_hash = tron_crypto::hash::keccak256(&a_bytecode);
    let b_hash = tron_crypto::hash::keccak256(&b_bytecode);
    code.put(&a_hash, &a_bytecode).unwrap();
    code.put(&b_hash, &b_bytecode).unwrap();
    accounts.put(
        &Address::from_raw(contract_a_bytes),
        &Account {
            address: contract_a_bytes.to_vec(),
            balance: 0,
            code: a_bytecode,
            code_hash: a_hash.to_vec(),
            ..Default::default()
        },
    ).unwrap();
    accounts.put(
        &Address::from_raw(contract_b_bytes),
        &Account {
            address: contract_b_bytes.to_vec(),
            balance: 0,
            code: b_bytecode,
            code_hash: b_hash.to_vec(),
            ..Default::default()
        },
    ).unwrap();

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
        unparsed_field10: None,
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
    // The beneficiary has no account row, so the suicide must create it.
    // java gates `createAccountIfNotExist` on ALLOW_TVM_SOLIDITY_059 (#32);
    // before it, `MUtil.transfer` of a non-zero balance to an absent obtainer
    // throws and the transaction dies. That pre-#32 matrix is covered by the
    // tron-tvm selfdestruct tests; here the post-#32 gate is what lets the
    // inheritance succeed and the "suicide" entry be recorded.
    tron_chainbase::DynamicPropertiesStore::new(state.dyn_props.clone())
        .put_long(b"ALLOW_TVM_SOLIDITY_059", 1);
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
    ).unwrap();
    let code = CodeStore::new(state.code.as_ref().unwrap().clone());
    let code_hash = tron_crypto::hash::keccak256(&bytecode);
    code.put(&code_hash, &bytecode).unwrap();
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
    ).unwrap();

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
        unparsed_field10: None,
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
    ).unwrap();
    let code = CodeStore::new(state.code.as_ref().unwrap().clone());
    let a_hash = tron_crypto::hash::keccak256(&a_bytecode);
    let b_hash = tron_crypto::hash::keccak256(&b_bytecode);
    code.put(&a_hash, &a_bytecode).unwrap();
    code.put(&b_hash, &b_bytecode).unwrap();
    accounts.put(
        &Address::from_raw(contract_a_bytes),
        &Account {
            address: contract_a_bytes.to_vec(),
            balance: 0,
            code: a_bytecode,
            code_hash: a_hash.to_vec(),
            ..Default::default()
        },
    ).unwrap();
    accounts.put(
        &Address::from_raw(contract_b_bytes),
        &Account {
            address: contract_b_bytes.to_vec(),
            balance: 0,
            code: b_bytecode,
            code_hash: b_hash.to_vec(),
            ..Default::default()
        },
    ).unwrap();

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
        unparsed_field10: None,
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
// Block-STM: parallel VM execution must be byte-identical to serial.
// =============================================================================

/// Full dump of every store's key→value (sorted) for state comparison.
fn dump_vm_state(
    s: &StateBackends,
) -> Vec<(&'static str, std::collections::BTreeMap<Vec<u8>, Vec<u8>>)> {
    let one = |be: &Arc<dyn KvBackend>| -> std::collections::BTreeMap<Vec<u8>, Vec<u8>> {
        be.scan_all().unwrap().into_iter().collect()
    };
    let opt = |be: &Option<Arc<dyn KvBackend>>| -> std::collections::BTreeMap<Vec<u8>, Vec<u8>> {
        be.as_ref().map(|b| one(b)).unwrap_or_default()
    };
    vec![
        ("accounts", one(&s.accounts)),
        ("witnesses", one(&s.witnesses)),
        ("votes", one(&s.votes)),
        ("delegation", one(&s.delegation)),
        ("delegated_resources", one(&s.delegated_resources)),
        ("dyn_props", one(&s.dyn_props)),
        ("proposals", one(&s.proposals)),
        ("name_index", one(&s.name_index)),
        ("id_index", one(&s.id_index)),
        ("asset_v1", one(&s.asset_v1)),
        ("asset_v2", one(&s.asset_v2)),
        ("contracts", one(&s.contracts)),
        ("abi", one(&s.abi)),
        ("exchange_v1", one(&s.exchange_v1)),
        ("exchange_v2", one(&s.exchange_v2)),
        ("market_orders", one(&s.market_orders)),
        ("nullifiers", one(&s.nullifiers)),
        ("code", opt(&s.code)),
        ("storage_row", opt(&s.storage_row)),
        ("contract_state", opt(&s.contract_state)),
        ("block_index", opt(&s.block_index)),
    ]
}

/// Install a contract account + its code into the given state.
fn install_contract(state: &StateBackends, contract: [u8; 21], bytecode: &[u8]) {
    let accounts = AccountStore::new(state.accounts.clone());
    let code = CodeStore::new(state.code.as_ref().unwrap().clone());
    let hash = tron_crypto::hash::keccak256(bytecode);
    code.put(&hash, bytecode).unwrap();
    accounts
        .put(
            &Address::from_raw(contract),
            &Account {
                address: contract.to_vec(),
                balance: 0,
                code: bytecode.to_vec(),
                code_hash: hash.to_vec(),
                ..Default::default()
            },
        )
        .unwrap();
}

/// Build a signed TriggerSmartContract tx for `caller` → `contract`.
fn trigger_tx(caller_priv: &[u8; 32], caller: [u8; 21], contract: [u8; 21]) -> Transaction {
    let trigger = TriggerSmartContract {
        owner_address: caller.to_vec(),
        contract_address: contract.to_vec(),
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
        unparsed_field10: None,
    };
    tron_types::sign_transaction(&mut tx, caller_priv).expect("sign tx");
    tx
}

/// The decisive Block-STM VM test: a block whose transactions form a
/// genuine read-modify-write dependency CHAIN on a single storage slot
/// (a counter incremented by N distinct callers) interleaved with an
/// independent contract. Serial execution gives slot0 == N; parallel
/// execution must converge to the identical full state, byte-for-byte —
/// proving the MVCC read/validate/re-execute fixpoint reproduces
/// serial semantics for VM (SLOAD/SSTORE) transactions, not just
/// transfers.
#[test]
fn parallel_vm_execution_is_byte_identical_to_serial() {
    use tron_executor::ExecConfig;

    // INC contract: slot0 = SLOAD(slot0) + 1; STOP.
    // PUSH1 0x00 SLOAD PUSH1 0x01 ADD PUSH1 0x00 SSTORE STOP
    let inc_code: Vec<u8> = vec![
        0x60, 0x00, // PUSH1 0   (slot)
        0x54, // SLOAD
        0x60, 0x01, // PUSH1 1
        0x01, // ADD
        0x60, 0x00, // PUSH1 0   (slot)
        0x55, // SSTORE
        0x00, // STOP
    ];
    // SET contract: slot0 = 0x42; STOP. Independent of INC's slot.
    let set_code: Vec<u8> = vec![0x60, 0x42, 0x60, 0x00, 0x55, 0x00];

    let inc_addr = addr_with_byte(0xc1);
    let set_addr = addr_with_byte(0xc2);

    // Six distinct callers; their per-call order against INC defines the
    // dependency chain. Interleave SET triggers so the scheduler sees a
    // mix of conflicting and independent work.
    let callers: Vec<([u8; 32], [u8; 21])> =
        (0..6u8).map(|i| caller_keypair(0x30 + i)).collect();

    // tx plan: a0→INC a1→INC a2→SET a3→INC a4→SET a5→INC
    //          (INC hit 4× → slot0 must == 4; SET hit 2× → slot0 == 0x42)
    let plan: [(usize, [u8; 21]); 6] = [
        (0, inc_addr),
        (1, inc_addr),
        (2, set_addr),
        (3, inc_addr),
        (4, set_addr),
        (5, inc_addr),
    ];

    let setup = |state: &StateBackends| {
        install_contract(state, inc_addr, &inc_code);
        install_contract(state, set_addr, &set_code);
        let accounts = AccountStore::new(state.accounts.clone());
        for (_, caller) in &callers {
            accounts
                .put(
                    &Address::from_raw(*caller),
                    &Account {
                        address: caller.to_vec(),
                        balance: 1_000_000_000,
                        ..Default::default()
                    },
                )
                .unwrap();
        }
    };
    let txs = || -> Vec<Transaction> {
        plan.iter()
            .map(|(ci, contract)| {
                let (priv_key, caller) = &callers[*ci];
                trigger_tx(priv_key, *caller, *contract)
            })
            .collect()
    };

    let serial_cfg = ExecConfig::unsigned();
    let par_cfg = ExecConfig {
        parallel_exec: true,
        ..ExecConfig::unsigned()
    };

    let s = build_state();
    setup(&s);
    let rs = execute_block_with_config(&s, &make_block(1, [0u8; 32], txs()), None, &serial_cfg)
        .expect("serial");

    let p = build_state();
    setup(&p);
    let rp = execute_block_with_config(&p, &make_block(1, [0u8; 32], txs()), None, &par_cfg)
        .expect("parallel");

    // The counter must read exactly 4 (chain of 4 INC txs) in BOTH runs —
    // proves the dependency chain serialised correctly, not just "matched
    // each other while both being wrong".
    let inc_slot = StorageRowStore::compose_key(&Address::from_raw(inc_addr), &[0u8; 32]);
    let read_inc = |state: &StateBackends| -> Vec<u8> {
        StorageRowStore::new(state.storage_row.as_ref().unwrap().clone())
            .get(&inc_slot)
            .unwrap()
            .expect("INC slot written")
    };
    let mut want = [0u8; 32];
    want[31] = 4;
    assert_eq!(read_inc(&s), want.to_vec(), "serial counter != 4");
    assert_eq!(read_inc(&p), want.to_vec(), "parallel counter != 4");

    // Full state, byte-for-byte.
    assert_eq!(
        dump_vm_state(&s),
        dump_vm_state(&p),
        "parallel VM state diverged from serial"
    );
    // Per-tx outcomes identical and in order.
    let so: Vec<_> = rs.tx_results.iter().map(|r| format!("{:?}", r.outcome)).collect();
    let po: Vec<_> = rp.tx_results.iter().map(|r| format!("{:?}", r.outcome)).collect();
    assert_eq!(so, po, "tx outcomes diverged");
    assert_eq!(rs.block_id, rp.block_id, "block id diverged");
}

/// Block-STM: the chain-global `BLOCK_ENERGY_USAGE` accumulator must fold
/// byte-identically to serial. With `ALLOW_ADAPTIVE_ENERGY = 1`, every VM tx's
/// energy charge RMWs that single dyn_props key (`block_energy_usage += used`) —
/// a would-be N-deep chain. The parallel path treats it as a commutative delta
/// (each tx records only its `+= used`; the commit sums `base + Σ delta` with
/// `wrapping_add`, matching java's plain `long +=`). Driving a multi-tx block
/// down that path with adaptive on (so the accumulator code actually executes)
/// and asserting full-state byte-identity proves the fold reproduces serial.
///
/// Note: the post-block adaptive update resets `BLOCK_ENERGY_USAGE` to 0 every
/// block (java `EnergyProcessor.updateTotalEnergyAverageUsage`), so the
/// accumulator is unobservable post-block; non-vacuity is asserted on the per-tx
/// receipt energy instead, and parity on the energy-fee-debited account balances
/// carried in the full-state dump.
#[test]
fn parallel_block_energy_usage_accumulator_matches_serial() {
    use tron_chainbase::DynamicPropertiesStore;
    use tron_executor::ExecConfig;

    // A tiny energy-using contract with NO storage write, so the only shared
    // chain-global state every call touches is `BLOCK_ENERGY_USAGE` via the
    // energy charge — isolating the commutative-accumulator fold.
    // PUSH1 1 PUSH1 2 ADD POP STOP.
    let noop_code: Vec<u8> = vec![0x60, 0x01, 0x60, 0x02, 0x01, 0x50, 0x00];
    let c_addr = addr_with_byte(0xe2);

    let callers: Vec<([u8; 32], [u8; 21])> = (0..8u8).map(|i| caller_keypair(0x60 + i)).collect();

    let setup = |state: &StateBackends| {
        install_contract(state, c_addr, &noop_code);
        let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
        // Adaptive energy ON → every energy charge bumps BLOCK_ENERGY_USAGE.
        dp.put_long(b"ALLOW_ADAPTIVE_ENERGY", 1);
        let accounts = AccountStore::new(state.accounts.clone());
        for (_, caller) in &callers {
            // Fund the caller so the energy bill is paid via the TRX-fee path
            // (no frozen energy) — the charge still bumps BLOCK_ENERGY_USAGE.
            accounts
                .put(
                    &Address::from_raw(*caller),
                    &Account {
                        address: caller.to_vec(),
                        balance: 1_000_000_000,
                        ..Default::default()
                    },
                )
                .unwrap();
        }
    };
    let txs = || {
        callers
            .iter()
            .map(|(pk, c)| trigger_tx(pk, *c, c_addr))
            .collect::<Vec<_>>()
    };

    let serial_cfg = ExecConfig::unsigned();
    let par_cfg = ExecConfig {
        parallel_exec: true,
        ..ExecConfig::unsigned()
    };

    let s = build_state();
    setup(&s);
    let rs = execute_block_with_config(&s, &make_block(1, [0u8; 32], txs()), None, &serial_cfg)
        .expect("serial");
    let p = build_state();
    setup(&p);
    let rp = execute_block_with_config(&p, &make_block(1, [0u8; 32], txs()), None, &par_cfg)
        .expect("parallel");

    // Non-vacuous: every tx actually consumed energy, so the BLOCK_ENERGY_USAGE
    // `+=` (and its commutative-delta fold under parallel) genuinely executed.
    let serial_energy: i64 = rs.tx_results.iter().map(|r| r.receipt.energy_usage_total).sum();
    assert!(serial_energy > 0, "no energy consumed — accumulator path not exercised");

    let so: Vec<_> = rs.tx_results.iter().map(|r| format!("{:?}", r.outcome)).collect();
    let po: Vec<_> = rp.tx_results.iter().map(|r| format!("{:?}", r.outcome)).collect();
    assert!(so.iter().all(|o| o == "Success"), "a call failed: {so:?}");
    assert_eq!(so, po, "tx outcomes diverged");
    assert_eq!(
        dump_vm_state(&s),
        dump_vm_state(&p),
        "parallel diverged from serial with the BLOCK_ENERGY_USAGE accumulator active"
    );
    assert_eq!(rs.block_id, rp.block_id, "block id diverged");
}

/// Block-STM: the deferred per-contract dynamic-energy fold must be byte-identical
/// to serial. Every call to a contract that's already caught-up this cycle RMWs
/// its `ContractState.energy_usage` (a windowed `+=` whose factor is fixed for the
/// cycle) — on mainnet that's USDT, written by ~every tx, the dominant remaining
/// Block-STM chain. The parallel path excludes it from the MVCC chain and sums the
/// per-tx deltas onto base at commit; this proves that sum equals serial's in-order
/// chain AND that the (non-zero) energy_factor + update_cycle survive untouched.
#[test]
fn parallel_dynamic_energy_chain_is_byte_identical_to_serial() {
    use tron_chainbase::{ContractStateStore, DynamicPropertiesStore};
    use tron_executor::ExecConfig;
    use tron_proto::ContractState;

    // A tiny energy-using contract with NO storage write, so the ONLY state every
    // call shares is its ContractState.energy_usage — isolating the deferral.
    // PUSH1 1 PUSH1 2 ADD POP STOP.
    let noop_code: Vec<u8> = vec![0x60, 0x01, 0x60, 0x02, 0x01, 0x50, 0x00];
    let c_addr = addr_with_byte(0xe1);
    const CYCLE: i64 = 100;

    let callers: Vec<([u8; 32], [u8; 21])> = (0..8u8).map(|i| caller_keypair(0x40 + i)).collect();

    let setup = |state: &StateBackends| {
        install_contract(state, c_addr, &noop_code);
        let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
        dp.put_long(b"ALLOW_DYNAMIC_ENERGY", 1);
        dp.put_long(b"DYNAMIC_ENERGY_THRESHOLD", 1_000_000_000);
        dp.put_long(b"DYNAMIC_ENERGY_INCREASE_FACTOR", 1_000);
        dp.put_long(b"DYNAMIC_ENERGY_MAX_FACTOR", 100_000);
        dp.save_current_cycle_number(CYCLE);
        // Already caught-up THIS cycle, with a NON-ZERO factor — so it takes the
        // deferred path and we verify the factor is preserved (not zeroed/reset).
        let cs = ContractStateStore::new(state.contract_state.as_ref().unwrap().clone());
        cs.put(
            &Address::from_raw(c_addr),
            &ContractState {
                update_cycle: CYCLE,
                energy_factor: 3_000,
                energy_usage: 0,
            },
        )
        .unwrap();
        let accounts = AccountStore::new(state.accounts.clone());
        for (_, caller) in &callers {
            accounts
                .put(
                    &Address::from_raw(*caller),
                    &Account {
                        address: caller.to_vec(),
                        balance: 1_000_000_000,
                        ..Default::default()
                    },
                )
                .unwrap();
        }
    };
    let txs = || {
        callers
            .iter()
            .map(|(pk, c)| trigger_tx(pk, *c, c_addr))
            .collect::<Vec<_>>()
    };

    let serial_cfg = ExecConfig::unsigned();
    let par_cfg = ExecConfig {
        parallel_exec: true,
        ..ExecConfig::unsigned()
    };

    let s = build_state();
    setup(&s);
    let rs = execute_block_with_config(&s, &make_block(1, [0u8; 32], txs()), None, &serial_cfg)
        .expect("serial");
    let p = build_state();
    setup(&p);
    let rp = execute_block_with_config(&p, &make_block(1, [0u8; 32], txs()), None, &par_cfg)
        .expect("parallel");

    let read_cs = |st: &StateBackends| {
        ContractStateStore::new(st.contract_state.as_ref().unwrap().clone())
            .get(&Address::from_raw(c_addr))
            .unwrap()
            .expect("contract state present")
    };
    let scs = read_cs(&s);
    let pcs = read_cs(&p);
    // Non-vacuous: the dynamic-energy accumulator actually moved, the fold matches
    // serial, and the factor + cycle survived the deferral untouched.
    assert!(scs.energy_usage > 0, "dynamic energy not exercised (usage stayed 0)");
    assert_eq!(scs.energy_usage, pcs.energy_usage, "deferred energy fold != serial chain");
    assert_eq!(scs.energy_factor, 3_000, "serial factor changed unexpectedly");
    assert_eq!(pcs.energy_factor, 3_000, "factor not preserved through the deferral");
    assert_eq!(scs.update_cycle, pcs.update_cycle, "update_cycle diverged");

    let so: Vec<_> = rs.tx_results.iter().map(|r| format!("{:?}", r.outcome)).collect();
    let po: Vec<_> = rp.tx_results.iter().map(|r| format!("{:?}", r.outcome)).collect();
    assert!(so.iter().all(|o| o == "Success"), "a call failed: {so:?}");
    assert_eq!(so, po, "tx outcomes diverged");
    assert_eq!(
        dump_vm_state(&s),
        dump_vm_state(&p),
        "parallel diverged from serial on a dynamic-energy (ContractState) chain"
    );
    assert_eq!(rs.block_id, rp.block_id, "block id diverged");
}

/// Throughput benchmark (ignored — run with
/// `cargo test -p tron-executor --test vm_integration --release -- --ignored --nocapture bench`).
/// Builds a heavy block of N independent contract calls (each caller →
/// its own contract instance running a multi-SSTORE workload) and times
/// serial vs Block-STM parallel apply. Independent calls are the upper
/// bound for parallel scaling — the "can we actually use the cores"
/// answer the rig has 32 of.
#[test]
#[ignore]
fn bench_parallel_vs_serial_throughput() {
    use std::time::Instant;
    use tron_executor::ExecConfig;

    const N: usize = 512; // txs per block
    const STORES_PER_TX: u8 = 24; // SSTOREs per call (≈ a busy contract tx)

    // Bytecode: SSTORE value=i to slot=i for i in 0..STORES_PER_TX; STOP.
    let mut bytecode: Vec<u8> = Vec::new();
    if std::env::var("BENCH_COMPUTE").is_ok() {
        // Compute-heavy variant: unrolled arithmetic, few state ops — measures
        // the parallel ceiling when per-tx VM work dwarfs MVCC overhead.
        for _ in 0..4000u16 {
            bytecode.extend_from_slice(&[0x60, 0x01, 0x60, 0x01, 0x01, 0x50]); // PUSH1 1 PUSH1 1 ADD POP
        }
        bytecode.extend_from_slice(&[0x60, 0x01, 0x60, 0x00, 0x55, 0x00]); // SSTORE 1->0 STOP
    } else {
        for i in 0..STORES_PER_TX {
            bytecode.extend_from_slice(&[0x60, i, 0x60, i, 0x55]); // PUSH1 i PUSH1 i SSTORE
        }
        bytecode.push(0x00); // STOP
    }

    // Distinct caller + distinct contract instance per tx → fully independent.
    let callers: Vec<([u8; 32], [u8; 21])> =
        (0..N).map(|i| caller_keypair((i & 0xff) as u8 ^ 0x5a)).collect();
    // Caller seeds can collide (only 256 distinct seed bytes); dedup by
    // giving each its own contract address derived from the index.
    let contract_addr = |i: usize| -> [u8; 21] {
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[19] = (i >> 8) as u8;
        a[20] = (i & 0xff) as u8;
        a
    };

    let setup = |state: &StateBackends| {
        let accounts = AccountStore::new(state.accounts.clone());
        for (i, (_, caller)) in callers.iter().enumerate() {
            // Fund the caller (idempotent if seeds collide — same balance).
            accounts
                .put(
                    &Address::from_raw(*caller),
                    &Account {
                        address: caller.to_vec(),
                        balance: 100_000_000_000,
                        ..Default::default()
                    },
                )
                .unwrap();
            install_contract(state, contract_addr(i), &bytecode);
        }
    };
    let txs = || -> Vec<Transaction> {
        callers
            .iter()
            .enumerate()
            .map(|(i, (priv_key, caller))| trigger_tx(priv_key, *caller, contract_addr(i)))
            .collect()
    };

    let run = |parallel: bool| -> (std::time::Duration, usize) {
        let state = build_state();
        setup(&state);
        let cfg = ExecConfig {
            parallel_exec: parallel,
            ..ExecConfig::unsigned()
        };
        let block = make_block(1, [0u8; 32], txs());
        let t = Instant::now();
        let report = execute_block_with_config(&state, &block, None, &cfg).expect("exec");
        let dt = t.elapsed();
        (dt, report.successes())
    };

    // Warm up (build caches / page in), then take the best of 3.
    let _ = run(false);
    let _ = run(true);
    let best = |parallel: bool| -> (std::time::Duration, usize) {
        let mut best: Option<(std::time::Duration, usize)> = None;
        for _ in 0..3 {
            let r = run(parallel);
            if best.map_or(true, |b| r.0 < b.0) {
                best = Some(r);
            }
        }
        best.unwrap()
    };
    let (serial_dt, serial_ok) = best(false);
    let (par_dt, par_ok) = best(true);

    assert_eq!(serial_ok, N, "all serial txs should succeed");
    assert_eq!(par_ok, N, "all parallel txs should succeed");

    let s_tps = N as f64 / serial_dt.as_secs_f64();
    let p_tps = N as f64 / par_dt.as_secs_f64();
    eprintln!("=== Block-STM throughput ({} cores) ===", num_cpus_hint());
    eprintln!(
        "  block = {N} independent contract calls × {STORES_PER_TX} SSTOREs each"
    );
    eprintln!("  serial:   {:>8.2?}  ({:>9.0} tx/s)", serial_dt, s_tps);
    eprintln!("  parallel: {:>8.2?}  ({:>9.0} tx/s)", par_dt, p_tps);
    eprintln!("  speedup:  {:.2}×", serial_dt.as_secs_f64() / par_dt.as_secs_f64());
}

/// Best-effort core count for the bench printout (avoids a num_cpus dep).
fn num_cpus_hint() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0)
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
    ).unwrap();
    let code = CodeStore::new(state.code.as_ref().unwrap().clone());
    let hash = tron_crypto::hash::keccak256(&bytecode);
    code.put(&hash, &bytecode).unwrap();
    accounts.put(
        &Address::from_raw(contract_bytes),
        &Account {
            address: contract_bytes.to_vec(),
            balance: 0,
            code: bytecode.clone(),
            code_hash: hash.to_vec(),
            ..Default::default()
        },
    ).unwrap();

    // Pre-seed storage slot 0 with a sentinel so we can distinguish
    // "no write happened" from "write happened then was reverted into
    // an empty slot". After the revert the slot MUST still read 0x07.
    let storage = StorageRowStore::new(state.storage_row.as_ref().unwrap().clone());
    let composite_key =
        StorageRowStore::compose_key(&Address::from_raw(contract_bytes), &[0u8; 32]);
    let mut sentinel = [0u8; 32];
    sentinel[31] = 0x07;
    storage.put(&composite_key, &sentinel).unwrap();

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
        unparsed_field10: None,
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
        .unwrap()
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
    ).unwrap();
    let code = CodeStore::new(state.code.as_ref().unwrap().clone());
    let hash = tron_crypto::hash::keccak256(&bytecode);
    code.put(&hash, &bytecode).unwrap();
    accounts.put(
        &Address::from_raw(contract_bytes),
        &Account {
            address: contract_bytes.to_vec(),
            balance: 0,
            code: bytecode.clone(),
            code_hash: hash.to_vec(),
            ..Default::default()
        },
    ).unwrap();

    let storage = StorageRowStore::new(state.storage_row.as_ref().unwrap().clone());
    let composite_key =
        StorageRowStore::compose_key(&Address::from_raw(contract_bytes), &[0u8; 32]);
    let mut sentinel = [0u8; 32];
    sentinel[31] = 0x09;
    storage.put(&composite_key, &sentinel).unwrap();

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
        unparsed_field10: None,
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
    let after = storage
        .get(&composite_key)
        .unwrap()
        .expect("sentinel must remain");
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

/// The closest offline analogue of the live catch-up condition for a
/// USDT-shaped contract: a hot contract that BOTH writes storage (the
/// INC slot chain — like a balance map) AND accumulates dynamic energy
/// (deferred per-contract fold), hammered by many conflicting callers,
/// across MULTIPLE blocks through the apply PIPELINE with
/// `defer_store_fsync` — exactly how the rig replays mainnet during
/// catch-up (parallel_exec + pipeline + deferred fsync together).
///
/// Storage (conflict keys, MVCC) + energy_usage (deferred fold) +
/// pipeline overlay (cross-block pending reads) + conflict-driven
/// re-execution all interact here in one fixture. Must be byte-identical
/// to classic serial, including the ContractState.energy_usage chain.
#[test]
fn pipelined_parallel_storage_plus_dynamic_energy_matches_serial() {
    use tron_chainbase::{BlockUndoStore, CheckPointV2, ContractStateStore, DynamicPropertiesStore, MemBackend};
    use tron_executor::{execute_block_with_undo_checkpoint_and_config, ApplyPipeline, ExecConfig};
    use tron_proto::ContractState;

    // INC: slot0 = SLOAD(slot0) + 1; SSTORE; STOP — storage + energy.
    let inc_code: Vec<u8> = vec![0x60,0x00,0x54,0x60,0x01,0x01,0x60,0x00,0x55,0x00];
    let c_addr = addr_with_byte(0xe7);
    const CYCLE: i64 = 100;
    const BLOCKS: usize = 5;
    // 8 callers; every block ALL of them hit the SAME contract → max
    // conflict on slot0 + the shared deferred energy_usage.
    let callers: Vec<([u8;32],[u8;21])> = (0..8u8).map(|i| caller_keypair(0x60 + i)).collect();

    let setup = |state: &StateBackends| {
        install_contract(state, c_addr, &inc_code);
        let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
        dp.put_long(b"ALLOW_DYNAMIC_ENERGY", 1);
        dp.put_long(b"DYNAMIC_ENERGY_THRESHOLD", 1_000_000_000);
        dp.put_long(b"DYNAMIC_ENERGY_INCREASE_FACTOR", 1_000);
        dp.put_long(b"DYNAMIC_ENERGY_MAX_FACTOR", 100_000);
        dp.save_current_cycle_number(CYCLE);
        let cs = ContractStateStore::new(state.contract_state.as_ref().unwrap().clone());
        cs.put(&Address::from_raw(c_addr), &ContractState {
            update_cycle: CYCLE, energy_factor: 3_000, energy_usage: 0,
        }).unwrap();
        let accounts = AccountStore::new(state.accounts.clone());
        for (_, caller) in &callers {
            accounts.put(&Address::from_raw(*caller), &Account {
                address: caller.to_vec(), balance: 1_000_000_000_000, ..Default::default()
            }).unwrap();
        }
    };
    let block_txs = || callers.iter().map(|(pk,c)| trigger_tx(pk, *c, c_addr)).collect::<Vec<_>>();
    let chain = || {
        let mut blocks=Vec::new(); let mut parent=[0u8;32];
        for k in 1..=BLOCKS as i64 {
            let b = make_block(k, parent, block_txs());
            parent = *tron_types::block_id_from_block(&b).unwrap().as_bytes();
            blocks.push(b);
        }
        blocks
    };

    // Classic serial reference.
    let serial_cfg = ExecConfig::unsigned();
    let s = build_state(); setup(&s);
    let undo_s = BlockUndoStore::new(Arc::new(MemBackend::new()) as Arc<dyn KvBackend>);
    let root_s = std::env::temp_dir().join(format!("tron-se-{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    let cp_s = CheckPointV2::new(&root_s);
    for b in chain() {
        execute_block_with_undo_checkpoint_and_config(&s, &b, None, &undo_s, &cp_s, &serial_cfg, None).expect("serial");
    }

    // Parallel + pipeline + defer fsync (the catch-up shape).
    let par_cfg = ExecConfig { parallel_exec: true, defer_store_fsync: true, ..ExecConfig::unsigned() };
    let p = build_state(); setup(&p);
    let undo_p = BlockUndoStore::new(Arc::new(MemBackend::new()) as Arc<dyn KvBackend>);
    let root_p = std::env::temp_dir().join(format!("tron-pe-{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    let cp_p = CheckPointV2::new(&root_p);
    let mut pipe = ApplyPipeline::new(&p, undo_p, cp_p);
    for b in chain() { pipe.apply(&b, None, &par_cfg, None).expect("pipelined"); }
    pipe.flush().expect("flush");

    let read_cs = |st: &StateBackends| ContractStateStore::new(st.contract_state.as_ref().unwrap().clone())
        .get(&Address::from_raw(c_addr)).unwrap().expect("cs");
    let scs = read_cs(&s); let pcs = read_cs(&p);
    assert!(scs.energy_usage > 0, "energy not exercised");
    assert_eq!(scs.energy_usage, pcs.energy_usage, "energy_usage diverged (serial={} parallel={})", scs.energy_usage, pcs.energy_usage);
    assert_eq!(scs.energy_factor, pcs.energy_factor, "factor diverged");
    assert_eq!(dump_vm_state(&s), dump_vm_state(&p), "storage+energy pipeline state diverged from serial");
    let _ = std::fs::remove_dir_all(&root_s); let _ = std::fs::remove_dir_all(&root_p);
}

// =============================================================================
// Whole-tx VM revert must NOT leak reward-settle delegation writes
// =============================================================================
//
// The TVM reward-settle path (`VoteRewardUtil.withdrawReward` — WITHDRAWREWARD /
// VOTEWITNESS / UNFREEZEBALANCEV2 / SELFDESTRUCT under ALLOW_TVM_VOTE) writes the
// voter's begin-cycle / end-cycle / account-vote rows into the `delegation`
// store. java scopes those to the frame's `RepositoryImpl.delegationCache`,
// flushed to the parent only when the frame `commit()`s and discarded on revert.
//
// At the executor level the per-tx `VmSession` is the analogue of java's child
// `rootRepository`: on a whole-tx VM revert the executor calls
// `vm_session.revert()` (discarding the VM's writes) but still `iso.commit()`s
// the OUTER `TxSession` (so the energy bill + bandwidth charge survive — the
// "energy is paid even on revert" rule). The `delegation` store is now routed
// through `vm_session`, so its reward-settle writes are dropped on revert exactly
// like the votes / delegated-resource writes. This test proves it: a top-level
// contract that WITHDRAWREWARDs (a real settle that WOULD write the three rows)
// then REVERTs must leave the delegation rows byte-identical to their pre-tx
// state, while the success control confirms a committed settle persists them.

/// Seed the stores so a WITHDRAWREWARD by `contract` settles a finalised cycle
/// (and therefore WOULD write begin/end-cycle + account-vote rows). Returns the
/// three raw delegation rows captured BEFORE any tx runs.
fn seed_reward_state_and_capture(
    state: &StateBackends,
    contract: [u8; 21],
    witness: [u8; 21],
) -> (Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>) {
    use tron_chainbase::{
        AccountStore, CodeStore, DelegationStore, DynamicPropertiesStore, WitnessStore,
    };
    use tron_proto::{Vote, Witness};

    let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
    dp.put_long(b"ALLOW_TVM_VOTE", 1);
    dp.put_long(b"CURRENT_CYCLE_NUMBER", 5);
    dp.save_latest_block_header_timestamp(1_700_000_000_000);

    WitnessStore::new(state.witnesses.clone())
        .put(
            &Address::from_raw(witness),
            &Witness { address: witness.to_vec(), ..Default::default() },
        )
        .unwrap();

    // Contract holds 100 votes for the witness so the settle pays a nonzero
    // reward and writes its delegation rows.
    let accounts = AccountStore::new(state.accounts.clone());
    // WITHDRAWREWARD with no contract code STOPs immediately; install minimal
    // bytecode so the trigger actually enters the VM.
    let bytecode: Vec<u8> = {
        // WITHDRAWREWARD (0xd9), POP, then REVERT(0,0).
        vec![0xd9, 0x50, 0x60, 0x00, 0x60, 0x00, 0xfd]
    };
    let code = CodeStore::new(state.code.as_ref().unwrap().clone());
    let hash = tron_crypto::hash::keccak256(&bytecode);
    code.put(&hash, &bytecode).unwrap();
    accounts
        .put(
            &Address::from_raw(contract),
            &Account {
                address: contract.to_vec(),
                balance: 0,
                code: bytecode.clone(),
                code_hash: hash.to_vec(),
                votes: vec![Vote { vote_address: witness.to_vec(), vote_count: 100 }],
                ..Default::default()
            },
        )
        .unwrap();

    let dlg = DelegationStore::new(state.delegation.clone());
    dlg.add_reward(0, &Address::from_raw(witness), 1_000_000_000);
    dlg.set_witness_vi_raw(
        4,
        &Address::from_raw(witness),
        &tron_tvm::reward::encode_signed_be(2_000_000_000_000_000_000),
    );
    dlg.set_begin_cycle(&Address::from_raw(contract), 0);
    dlg.set_end_cycle(&Address::from_raw(contract), 1);
    dlg.set_account_vote(
        0,
        &Address::from_raw(contract),
        &Account {
            address: contract.to_vec(),
            votes: vec![Vote { vote_address: witness.to_vec(), vote_count: 100 }],
            ..Default::default()
        },
    )
    .unwrap();

    let a = Address::from_raw(contract);
    (
        dlg.get_raw(&DelegationStore::begin_cycle_key(&a)).unwrap(),
        dlg.get_raw(&DelegationStore::end_cycle_key(&a)).unwrap(),
        dlg.get_raw(&DelegationStore::account_vote_key(5, &a)).unwrap(),
    )
}

fn make_trigger_tx(caller_priv: [u8; 32], caller: [u8; 21], contract: [u8; 21]) -> Transaction {
    let trigger = TriggerSmartContract {
        owner_address: caller.to_vec(),
        contract_address: contract.to_vec(),
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
            fee_limit: 1_000_000_000,
            ..Default::default()
        }),
        signature: Vec::new(),
        ret: Vec::new(),
        unparsed_field10: None,
    };
    tron_types::sign_transaction(&mut tx, &caller_priv).expect("sign tx");
    tx
}

#[test]
fn whole_tx_revert_does_not_leak_reward_settle_delegation() {
    use tron_chainbase::{AccountStore, DelegationStore};

    let state = build_state();
    let (caller_priv, caller) = caller_keypair(0xaa);
    let contract = addr_with_byte(0xcd);
    let witness = addr_with_byte(0x99);

    AccountStore::new(state.accounts.clone())
        .put(
            &Address::from_raw(caller),
            &Account { address: caller.to_vec(), balance: 1_000_000_000, ..Default::default() },
        )
        .unwrap();

    // Contract bytecode WITHDRAWREWARDs then REVERTs → whole tx reverts.
    let before = seed_reward_state_and_capture(&state, contract, witness);

    let tx = make_trigger_tx(caller_priv, caller, contract);
    let block = make_block(1, [0u8; 32], vec![tx]);
    let report = apply_unsigned(&state, &block, None).expect("execute_block");

    // The tx reverts (top-level REVERT). The point is the delegation rows.
    assert!(
        !matches!(report.tx_results[0].outcome, TxOutcome::Success),
        "tx must NOT succeed (it REVERTs), got: {:?}",
        report.tx_results[0].outcome
    );

    let dlg = DelegationStore::new(state.delegation.clone());
    let a = Address::from_raw(contract);
    let after = (
        dlg.get_raw(&DelegationStore::begin_cycle_key(&a)).unwrap(),
        dlg.get_raw(&DelegationStore::end_cycle_key(&a)).unwrap(),
        dlg.get_raw(&DelegationStore::account_vote_key(5, &a)).unwrap(),
    );
    assert_eq!(
        before, after,
        "whole-tx revert leaked reward-settle delegation rows (VmSession must discard them)"
    );
}

#[test]
fn whole_tx_success_commits_reward_settle_delegation() {
    use tron_chainbase::{AccountStore, CodeStore, DelegationStore};

    let state = build_state();
    let (caller_priv, caller) = caller_keypair(0xab);
    let contract = addr_with_byte(0xce);
    let witness = addr_with_byte(0x9a);

    AccountStore::new(state.accounts.clone())
        .put(
            &Address::from_raw(caller),
            &Account { address: caller.to_vec(), balance: 1_000_000_000, ..Default::default() },
        )
        .unwrap();

    seed_reward_state_and_capture(&state, contract, witness);
    // Overwrite the contract code with the SUCCESS variant: WITHDRAWREWARD,
    // POP, STOP — the settle commits.
    let bytecode: Vec<u8> = vec![0xd9, 0x50, 0x00];
    let code = CodeStore::new(state.code.as_ref().unwrap().clone());
    let hash = tron_crypto::hash::keccak256(&bytecode);
    code.put(&hash, &bytecode).unwrap();
    let accounts = AccountStore::new(state.accounts.clone());
    let mut acct = accounts.get(&Address::from_raw(contract)).unwrap().unwrap();
    acct.code = bytecode.clone();
    acct.code_hash = hash.to_vec();
    accounts.put(&Address::from_raw(contract), &acct).unwrap();

    let tx = make_trigger_tx(caller_priv, caller, contract);
    let block = make_block(1, [0u8; 32], vec![tx]);
    let report = apply_unsigned(&state, &block, None).expect("execute_block");
    assert!(
        matches!(report.tx_results[0].outcome, TxOutcome::Success),
        "tx must succeed, got: {:?}",
        report.tx_results[0].outcome
    );

    let dlg = DelegationStore::new(state.delegation.clone());
    let a = Address::from_raw(contract);
    // java's settle tail: begin_cycle = current (5), end_cycle = 6, account_vote
    // snapshot at the current cycle.
    assert_eq!(dlg.get_begin_cycle(&a), 5, "committed settle must advance begin_cycle");
    assert_eq!(dlg.get_end_cycle(&a), 6, "committed settle must set end_cycle = current+1");
    assert!(
        dlg.get_account_vote(5, &a).unwrap().is_some(),
        "committed settle must write the current-cycle account-vote snapshot"
    );
}
