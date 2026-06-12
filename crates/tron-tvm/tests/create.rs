//! End-to-end test for `execute_create` — deploying a smart contract
//! through the CreateSmartContract path.

use std::sync::Arc;

use tron_chainbase::{
    AccountStore, CodeStore, ContractStateStore, DelegatedResourceStore, DelegationStore,
    DynamicPropertiesStore, KvBackend, MemBackend, StorageRowStore, WitnessStore,
};
use tron_crypto::address::Address;
use tron_proto::{smart_contract::Abi, Account, CreateSmartContract, SmartContract};
use tron_tvm::execute::{execute_create, VmBlockEnv, VmOutcome, VmStores};

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

/// Like [`fresh_stores`] but with the `ContractStore` + `AbiStore` attached, so
/// deploy paths persist `SmartContract` rows.
fn fresh_stores_with_contracts() -> VmStores {
    let mut s = fresh_stores();
    s.contracts = Some(Arc::new(tron_chainbase::ContractStore::new(mem())));
    s.abi = Some(Arc::new(tron_chainbase::AbiStore::new(mem())));
    s
}

/// java-tron CREATE2 address: `0x41 || sha3omit12(0x41 ++ caller20 ++ salt32 ++ keccak(init))`.
fn tron_create2(caller21: &[u8; 21], salt: [u8; 32], init_code: &[u8]) -> [u8; 21] {
    let mut buf = Vec::new();
    buf.push(0x41u8);
    buf.extend_from_slice(&caller21[1..]); // 20-byte EVM half
    buf.extend_from_slice(&salt);
    buf.extend_from_slice(&tron_crypto::hash::keccak256(init_code));
    let h = tron_crypto::hash::keccak256(&buf);
    let mut out = [0u8; 21];
    out[0] = 0x41;
    out[1..].copy_from_slice(&h[12..]);
    out
}

#[test]
fn execute_create_deploys_contract_at_tron_derived_address() {
    let stores = fresh_stores();

    // Owner: a known address with TRX balance.
    let mut owner_bytes = [0u8; 21];
    owner_bytes[0] = 0x41;
    owner_bytes[1..].fill(0xa0);
    let owner = Address::from_raw(owner_bytes);
    stores.accounts.put(
        &owner,
        &Account {
            address: owner.as_bytes().to_vec(),
            balance: 1_000_000_000,
            ..Default::default()
        },
    ).unwrap();

    // Init code returns a runtime code of `[0x60, 0x00, 0x60, 0x00, 0xf3]`
    // (PUSH1 0, PUSH1 0, RETURN — a trivial valid runtime).
    //
    // Init code (puts runtime in memory then RETURNs it):
    //   PUSH5 0x6000600060f3  (placeholder for 5-byte target -- can't push 5 directly so use 32-byte right-padded)
    //
    // Simpler approach: have init code MSTORE the 5-byte runtime and RETURN
    // those 5 bytes.
    //
    // Bytecode:
    //   PUSH5 0x6000600060f3 — actually opcode 0x64 is PUSH5
    //   PUSH1 0x1b   - shift left 27 bytes (=216 bit) — actually we'll just
    //                  use MSTORE with the value right-aligned
    //
    // Cleanest path: load the 5 bytes via PUSH32, MSTORE at offset 0, then
    // RETURN (offset=27, len=5).
    //
    //   PUSH32 0x000...006000600060f3 (the 5 runtime bytes in the low 5 of a word)
    //   PUSH1 0x00         <- memory offset
    //   MSTORE             <- mem[0..32] = the padded value
    //   PUSH1 0x05         <- length 5
    //   PUSH1 0x1b         <- offset 27 (= 32 - 5; runtime is right-aligned)
    //   RETURN
    let runtime = vec![0x60u8, 0x00, 0x60, 0x00, 0xf3];

    let mut padded = [0u8; 32];
    padded[27..].copy_from_slice(&runtime);
    let mut init_code = vec![0x7fu8]; // PUSH32
    init_code.extend_from_slice(&padded);
    init_code.extend_from_slice(&[
        0x60, 0x00, // PUSH1 0
        0x52, // MSTORE
        0x60, 0x05, // PUSH1 5
        0x60, 0x1b, // PUSH1 27
        0xf3, // RETURN
    ]);

    let create = CreateSmartContract {
        owner_address: owner_bytes.to_vec(),
        new_contract: Some(SmartContract {
            origin_address: owner_bytes.to_vec(),
            contract_address: vec![],
            abi: Some(Abi::default()),
            bytecode: init_code.clone(),
            call_value: 0,
            consume_user_resource_percent: 100,
            name: "Trivial".into(),
            origin_energy_limit: 1_000_000,
            code_hash: vec![],
            trx_hash: vec![],
            version: 1,
        }),
        call_token_value: 0,
        token_id: 0,
    };

    let tx_id = [0xab; 32];
    let outcome = execute_create(
        &stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: 1_700_000_000_000,
        },
        &create,
        &tx_id,
        500_000,
    );

    let (contract_addr_bytes, _energy_used) = match outcome {
        VmOutcome::Success {
            return_data,
            energy_used,
            ..
        } => (return_data, energy_used),
        other => panic!("expected Success, got {other:?}"),
    };
    assert_eq!(contract_addr_bytes.len(), 21);
    assert_eq!(contract_addr_bytes[0], 0x41);

    // Verify the derived address matches the TRON formula:
    // 0x41 || sha3omit12(tx_id || owner)[12..] (java-tron
    // WalletUtil.generateContractAddress: tx id FIRST, then the 21-byte owner).
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&tx_id);
    hash_input.extend_from_slice(&owner_bytes);
    let h = tron_crypto::hash::keccak256(&hash_input);
    let mut expected_addr = [0u8; 21];
    expected_addr[0] = 0x41;
    expected_addr[1..].copy_from_slice(&h[12..]);
    assert_eq!(contract_addr_bytes, expected_addr.to_vec());
    // And it must match the shared derivation helper.
    assert_eq!(
        contract_addr_bytes,
        tron_tvm::execute::derive_top_level_contract_address(&tx_id, &owner_bytes).to_vec()
    );

    // Verify the deployed runtime code is stored on the Account.
    let contract_addr = Address::from_raw(expected_addr);
    let acct = stores
        .accounts
        .get(&contract_addr)
        .unwrap()
        .expect("contract account missing after deploy");
    assert_eq!(
        acct.code, runtime,
        "deployed runtime bytecode mismatch (expected the 5-byte PUSH1 0 PUSH1 0 RETURN)"
    );
    let expected_runtime_hash = tron_crypto::hash::keccak256(&runtime);
    assert_eq!(acct.code_hash, expected_runtime_hash.as_slice());

    // CodeStore must contain the runtime code keyed by ADDRESS (java-tron's
    // `saveCode(address, ...)` layout), not by code_hash.
    let stored_code = stores.code.get(contract_addr.as_bytes()).unwrap().unwrap();
    assert_eq!(stored_code, runtime);
}

#[test]
fn execute_create_cleans_up_on_init_code_revert() {
    let stores = fresh_stores();

    let mut owner_bytes = [0u8; 21];
    owner_bytes[0] = 0x41;
    owner_bytes[1..].fill(0xa1);
    stores.accounts.put(
        &Address::from_raw(owner_bytes),
        &Account {
            address: owner_bytes.to_vec(),
            balance: 1_000_000_000,
            ..Default::default()
        },
    ).unwrap();

    // Init code: PUSH1 0 PUSH1 0 REVERT — reverts immediately.
    let init_code = vec![0x60, 0x00, 0x60, 0x00, 0xfd];

    let create = CreateSmartContract {
        owner_address: owner_bytes.to_vec(),
        new_contract: Some(SmartContract {
            origin_address: owner_bytes.to_vec(),
            bytecode: init_code,
            consume_user_resource_percent: 100,
            origin_energy_limit: 1_000_000,
            version: 1,
            ..Default::default()
        }),
        call_token_value: 0,
        token_id: 0,
    };

    let tx_id = [0xcd; 32];
    let outcome = execute_create(
        &stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: 0,
        },
        &create,
        &tx_id,
        500_000,
    );
    assert!(matches!(outcome, VmOutcome::Revert { .. }), "got {outcome:?}");

    // The pre-installed Account at the derived address must have been
    // cleaned up — no half-deployed contract left behind.
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&owner_bytes);
    hash_input.extend_from_slice(&tx_id);
    let h = tron_crypto::hash::keccak256(&hash_input);
    let mut addr = [0u8; 21];
    addr[0] = 0x41;
    addr[1..].copy_from_slice(&h[12..]);
    let absent = stores.accounts.get(&Address::from_raw(addr)).unwrap();
    assert!(
        absent.is_none(),
        "contract account should not persist after init-code revert"
    );
}

#[test]
fn execute_create_halts_when_code_deposit_charge_exceeds_budget() {
    let stores = fresh_stores();

    let mut owner_bytes = [0u8; 21];
    owner_bytes[0] = 0x41;
    owner_bytes[1..].fill(0xa3);
    stores.accounts.put(
        &Address::from_raw(owner_bytes),
        &Account {
            address: owner_bytes.to_vec(),
            balance: 1_000_000_000,
            ..Default::default()
        },
    ).unwrap();

    // Init code that returns a LARGE runtime body — 1000 bytes of 0x00.
    // Code deposit = 1000 × 200 = 200_000 gas. With a tight 30_000 gas
    // budget, this must halt.
    //
    // Construct memory: write 1000 bytes (each MSTORE writes 32 bytes,
    // we need ~32 MSTOREs). For simplicity: PUSH2 0x03e8 (1000),
    // PUSH1 0 RETURN — returns memory from offset 0, length 1000.
    // Memory expands implicitly to 1000 bytes (cost ~negligible).
    let init_code = vec![
        0x61, 0x03, 0xe8, // PUSH2 1000  (size)
        0x60, 0x00, // PUSH1 0  (offset)
        0xf3, // RETURN
    ];

    let create = CreateSmartContract {
        owner_address: owner_bytes.to_vec(),
        new_contract: Some(SmartContract {
            origin_address: owner_bytes.to_vec(),
            bytecode: init_code,
            consume_user_resource_percent: 100,
            origin_energy_limit: 1_000_000,
            version: 1,
            ..Default::default()
        }),
        call_token_value: 0,
        token_id: 0,
    };

    let tx_id = [0xef; 32];
    // 30_000 < 1000 × 200, so deposit cost alone exceeds budget.
    let outcome = execute_create(
        &stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: 0,
        },
        &create,
        &tx_id,
        30_000,
    );
    match outcome {
        VmOutcome::Halt { reason, .. } => {
            assert!(
                reason.contains("code-deposit"),
                "expected code-deposit OOG, got: {reason}"
            );
        }
        other => panic!("expected Halt for code-deposit OOG, got {other:?}"),
    }

    // Account should be cleaned up.
    let mut hi = Vec::new();
    hi.extend_from_slice(&owner_bytes);
    hi.extend_from_slice(&tx_id);
    let h = tron_crypto::hash::keccak256(&hi);
    let mut addr = [0u8; 21];
    addr[0] = 0x41;
    addr[1..].copy_from_slice(&h[12..]);
    assert!(stores.accounts.get(&Address::from_raw(addr)).unwrap().is_none());
}

#[test]
fn top_level_create_writes_contract_row_and_marks_account() {
    let stores = fresh_stores_with_contracts();

    let mut owner_bytes = [0u8; 21];
    owner_bytes[0] = 0x41;
    owner_bytes[1..].fill(0xa2);
    stores
        .accounts
        .put(
            &Address::from_raw(owner_bytes),
            &Account {
                address: owner_bytes.to_vec(),
                balance: 1_000_000_000,
                ..Default::default()
            },
        )
        .unwrap();

    // Init code returns a 1-byte STOP runtime: PUSH1 1, PUSH1 0, RETURN reads
    // mem[0..1] (zero) → runtime [0x00].
    let init_code = vec![0x60, 0x01, 0x60, 0x00, 0xf3];

    let create = CreateSmartContract {
        owner_address: owner_bytes.to_vec(),
        new_contract: Some(SmartContract {
            origin_address: owner_bytes.to_vec(),
            bytecode: init_code,
            consume_user_resource_percent: 75,
            origin_energy_limit: 5_000_000,
            name: "MyToken".to_string(),
            abi: Some(Abi::default()),
            ..Default::default()
        }),
        call_token_value: 0,
        token_id: 0,
    };

    let tx_id = [0xee; 32];
    let outcome = execute_create(
        &stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: 0,
        },
        &create,
        &tx_id,
        2_000_000,
    );
    let addr_bytes = match outcome {
        VmOutcome::Success { return_data, .. } => return_data,
        other => panic!("expected Success, got {other:?}"),
    };
    let mut addr = [0u8; 21];
    addr.copy_from_slice(&addr_bytes);
    let contract_addr = Address::from_raw(addr);

    // Account is marked a contract with the DECLARED name.
    let acct = stores.accounts.get(&contract_addr).unwrap().unwrap();
    assert_eq!(acct.r#type, tron_proto::AccountType::Contract as i32);
    assert_eq!(acct.account_name, b"MyToken".to_vec());

    // Contract row persisted with the tx's economic fields and version 0.
    let row = stores
        .contracts
        .as_ref()
        .unwrap()
        .get(&contract_addr)
        .unwrap()
        .expect("contract row missing after top-level deploy");
    assert_eq!(row.consume_user_resource_percent, 75);
    assert_eq!(row.origin_energy_limit, 5_000_000);
    assert_eq!(row.origin_address, owner_bytes.to_vec());
    assert_eq!(row.contract_address, addr.to_vec());
    assert_eq!(row.version, 0);
    assert!(row.abi.is_none(), "ContractStore must strip ABI");
}

#[test]
fn nested_create2_writes_contract_row_and_marks_account() {
    use tron_proto::TriggerSmartContract;
    use tron_tvm::execute::execute_trigger_with_trace_tx_id;

    let stores = fresh_stores_with_contracts();
    // CREATE2 (0xf5) needs the Petersburg spec → ALLOW_TVM_CONSTANTINOPLE.
    stores
        .dynamic_properties
        .put_long(b"ALLOW_TVM_CONSTANTINOPLE", 1);

    // Child init code: PUSH1 1, PUSH1 0, RETURN → returns mem[0..1] = [0x00].
    let child_init: [u8; 5] = [0x60, 0x01, 0x60, 0x00, 0xf3];

    // Factory runtime: MSTORE the 5-byte child init at mem[27..32], then
    // CREATE2(value=0, offset=27, length=5, salt=0); STOP.
    let factory_runtime = vec![
        0x64, child_init[0], child_init[1], child_init[2], child_init[3], child_init[4], // PUSH5 child_init
        0x60, 0x00, // PUSH1 0
        0x52, // MSTORE
        0x60, 0x00, // PUSH1 0  (salt)
        0x60, 0x05, // PUSH1 5  (length)
        0x60, 0x1b, // PUSH1 27 (offset)
        0x60, 0x00, // PUSH1 0  (value)
        0xf5, // CREATE2
        0x00, // STOP
    ];

    // Caller (EOA) with balance.
    let mut caller = [0u8; 21];
    caller[0] = 0x41;
    caller[1..].fill(0xa3);
    stores
        .accounts
        .put(
            &Address::from_raw(caller),
            &Account {
                address: caller.to_vec(),
                balance: 1_000_000_000,
                ..Default::default()
            },
        )
        .unwrap();

    // Pre-install the factory as a contract account with its runtime code.
    let mut factory = [0u8; 21];
    factory[0] = 0x41;
    factory[1..].fill(0xbb);
    let factory_addr = Address::from_raw(factory);
    let factory_code_hash = tron_crypto::hash::keccak256(&factory_runtime);
    stores
        .accounts
        .put(
            &factory_addr,
            &Account {
                address: factory.to_vec(),
                balance: 0,
                code: factory_runtime.clone(),
                code_hash: factory_code_hash.to_vec(),
                r#type: tron_proto::AccountType::Contract as i32,
                ..Default::default()
            },
        )
        .unwrap();
    stores
        .code
        .put(factory_addr.as_bytes(), &factory_runtime)
        .unwrap();

    let trigger = TriggerSmartContract {
        owner_address: caller.to_vec(),
        contract_address: factory.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };

    let tx_id = [0x7c; 32];
    let (outcome, _traces, _pen) = execute_trigger_with_trace_tx_id(
        &stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: 0,
        },
        &trigger,
        2_000_000,
        tx_id,
    );
    assert!(matches!(outcome, VmOutcome::Success { .. }), "got {outcome:?}");

    // The CREATE2 child must exist at the java-tron-derived address.
    let child = tron_create2(&factory, [0u8; 32], &child_init);
    let child_addr = Address::from_raw(child);
    let child_acct = stores
        .accounts
        .get(&child_addr)
        .unwrap()
        .expect("CREATE2 child account missing");
    assert_eq!(child_acct.r#type, tron_proto::AccountType::Contract as i32);
    assert_eq!(child_acct.account_name, b"CreatedByContract".to_vec());

    // Contract row: percent 100, origin = factory, trx_hash = root tx id.
    let row = stores
        .contracts
        .as_ref()
        .unwrap()
        .get(&child_addr)
        .unwrap()
        .expect("CREATE2 child contract row missing");
    assert_eq!(row.consume_user_resource_percent, 100);
    assert_eq!(row.origin_address, factory.to_vec());
    assert_eq!(row.trx_hash, tx_id.to_vec());
    assert_eq!(row.contract_address, child.to_vec());
    assert_eq!(row.version, 0);
}

/// java-tron nested CREATE address: `0x41 || sha3omit12(rootTxId ++ nonce_be8)`.
fn tron_create(root_tx_id: &[u8; 32], nonce: u64) -> [u8; 21] {
    let mut buf = Vec::new();
    buf.extend_from_slice(root_tx_id);
    buf.extend_from_slice(&nonce.to_be_bytes());
    let h = tron_crypto::hash::keccak256(&buf);
    let mut out = [0u8; 21];
    out[0] = 0x41;
    out[1..].copy_from_slice(&h[12..]);
    out
}

/// End-to-end: a staking opcode (FREEZEBALANCEV2) executed before a nested
/// CREATE must advance the per-tx internal-tx nonce counter, so the CREATE's
/// child lands at the nonce=1 address — NOT the nonce=0 address it would use if
/// the staking bump were missing. This proves the bridge bump and the frame's
/// create-nonce read share one counter (full java-tron parity for
/// staking-then-deploy).
#[test]
fn staking_opcode_shifts_following_nested_create_address() {
    let stores = fresh_stores_with_contracts();
    // FreezeV2 is gated on supportUnfreezeDelay() = UNFREEZE_DELAY_DAYS > 0
    // (java has no ALLOW_TVM_FREEZE_V2 dyn-props key).
    stores.dynamic_properties.put_long(b"UNFREEZE_DELAY_DAYS", 14);

    // Runtime: FREEZEBALANCEV2(1 TRX, resource 0), POP, then CREATE a child.
    let child_init: [u8; 5] = [0x60, 0x01, 0x60, 0x00, 0xf3];
    let runtime = vec![
        0x62, 0x0f, 0x42, 0x40, // PUSH3 1_000_000  (frozenBalance, pushed first/deeper)
        0x60, 0x00, // PUSH1 0  (resourceType, on top)
        0xda, // FREEZEBALANCEV2  -> bumps the nonce counter (0 -> 1)
        0x50, // POP  (discard success flag)
        0x64, child_init[0], child_init[1], child_init[2], child_init[3], child_init[4], // PUSH5 child_init
        0x60, 0x00, // PUSH1 0
        0x52, // MSTORE
        0x60, 0x05, // PUSH1 5  (length)
        0x60, 0x1b, // PUSH1 27 (offset)
        0x60, 0x00, // PUSH1 0  (value)
        0xf0, // CREATE  (plain) -> uses nonce=1
        0x00, // STOP
    ];

    let mut caller = [0u8; 21];
    caller[0] = 0x41;
    caller[1..].fill(0xc1);
    stores
        .accounts
        .put(
            &Address::from_raw(caller),
            &Account { address: caller.to_vec(), balance: 1_000_000_000, ..Default::default() },
        )
        .unwrap();

    let mut factory = [0u8; 21];
    factory[0] = 0x41;
    factory[1..].fill(0xc2);
    let factory_addr = Address::from_raw(factory);
    stores
        .accounts
        .put(
            &factory_addr,
            &Account {
                address: factory.to_vec(),
                balance: 100_000_000, // enough to freeze 1 TRX
                code: runtime.clone(),
                code_hash: tron_crypto::hash::keccak256(&runtime).to_vec(),
                r#type: tron_proto::AccountType::Contract as i32,
                ..Default::default()
            },
        )
        .unwrap();
    stores.code.put(factory_addr.as_bytes(), &runtime).unwrap();

    let trigger = tron_proto::TriggerSmartContract {
        owner_address: caller.to_vec(),
        contract_address: factory.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };

    let tx_id = [0x9a; 32];
    let (outcome, _t, _p) = tron_tvm::execute::execute_trigger_with_trace_tx_id(
        &stores,
        VmBlockEnv { block_number: 1, block_timestamp_ms: 1_000_000 },
        &trigger,
        3_000_000,
        tx_id,
    );
    assert!(matches!(outcome, VmOutcome::Success { .. }), "got {outcome:?}");

    // Child must be at the nonce=1 address (staking op bumped the counter)…
    let child_n1 = Address::from_raw(tron_create(&tx_id, 1));
    assert!(
        stores.accounts.get(&child_n1).unwrap().is_some(),
        "child should deploy at the nonce=1 address (staking opcode bumped the nonce)"
    );
    // …and NOT at the nonce=0 address (which is where the pre-fix bug would put it).
    let child_n0 = Address::from_raw(tron_create(&tx_id, 0));
    assert!(
        stores.accounts.get(&child_n0).unwrap().is_none(),
        "child must NOT be at the nonce=0 address"
    );
}
