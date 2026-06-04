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
    }
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
    // 0x41 || keccak256(owner || tx_id)[12..]
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&owner_bytes);
    hash_input.extend_from_slice(&tx_id);
    let h = tron_crypto::hash::keccak256(&hash_input);
    let mut expected_addr = [0u8; 21];
    expected_addr[0] = 0x41;
    expected_addr[1..].copy_from_slice(&h[12..]);
    assert_eq!(contract_addr_bytes, expected_addr.to_vec());

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

    // CodeStore must contain the runtime code keyed by its hash.
    let stored_code = stores.code.get(acct.code_hash.as_slice()).unwrap().unwrap();
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
