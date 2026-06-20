//! Tests for the high-level `execute_trigger` API — the entry point
//! the block executor will call for `TriggerSmartContract` transactions.

use std::sync::Arc;

use tron_chainbase::{
    AccountStore, CodeStore, ContractStateStore, DelegatedResourceStore, DelegationStore,
    DynamicPropertiesStore, KvBackend, MemBackend, StorageRowStore, WitnessStore,
};
use tron_proto::TriggerSmartContract;
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

/// Pre-install a TRON contract by writing both the Account proto and the
/// CodeStore entry. The contract's 21-byte address is returned.
fn install_contract(stores: &VmStores, prefix: u8, bytecode: &[u8]) -> [u8; 21] {
    let mut tron_addr_bytes = [0u8; 21];
    tron_addr_bytes[0] = 0x41;
    tron_addr_bytes[1..].fill(prefix);
    let tron_addr = tron_crypto::address::Address::from_raw(tron_addr_bytes);
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
    tron_addr_bytes
}

fn fund_account(stores: &VmStores, prefix: u8, balance: i64) -> [u8; 21] {
    let mut tron_addr_bytes = [0u8; 21];
    tron_addr_bytes[0] = 0x41;
    tron_addr_bytes[1..].fill(prefix);
    let tron_addr = tron_crypto::address::Address::from_raw(tron_addr_bytes);
    stores.accounts.put(
        &tron_addr,
        &tron_proto::Account {
            address: tron_addr.as_bytes().to_vec(),
            balance,
            ..Default::default()
        },
    ).unwrap();
    tron_addr_bytes
}

#[test]
fn execute_trigger_succeeds_for_simple_return_contract() {
    let stores = fresh_stores();
    // Bytecode: return 0x42 as a 32-byte word.
    let contract_addr = install_contract(
        &stores,
        0xc0,
        &[
            0x60, 0x42, // PUSH1 0x42
            0x60, 0x00, // PUSH1 0
            0x52, // MSTORE
            0x60, 0x20, // PUSH1 32
            0x60, 0x00, // PUSH1 0
            0xf3, // RETURN
        ],
    );
    let owner_addr = fund_account(&stores, 0xa0, 1_000_000_000);

    let trigger = TriggerSmartContract {
        owner_address: owner_addr.to_vec(),
        contract_address: contract_addr.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };

    let outcome = execute_trigger(
        &stores,
        VmBlockEnv {
            block_number: 100,
            block_timestamp_ms: 1_700_000_000_000,
        },
        &trigger,
        100_000,
    );

    match outcome {
        VmOutcome::Success { return_data, .. } => {
            assert_eq!(return_data.len(), 32);
            assert_eq!(return_data[31], 0x42);
        }
        other => panic!("expected Success, got {other:?}"),
    }
}

/// Regression: the `TIMESTAMP` / `NUMBER` opcodes must reflect the executing
/// block's env. They previously returned the revm BlockEnv defaults
/// (timestamp=1, number=0) because the block env was never populated, so any
/// `block.timestamp - t` underflowed (Panic 0x11) — the root cause of the
/// energy-rental / DeFi contractRet divergence cascade. TIMESTAMP is in
/// SECONDS (java `getTimestamp() / 1000`).
#[test]
fn block_timestamp_and_number_opcodes_reflect_block_env() {
    let stores = fresh_stores();
    let owner = fund_account(&stores, 0xa7, 1_000_000_000);
    let mk_trigger = |c: [u8; 21]| TriggerSmartContract {
        owner_address: owner.to_vec(),
        contract_address: c.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };
    let env = || VmBlockEnv {
        block_number: 83_316_753,
        block_timestamp_ms: 1_700_000_001_000,
    };
    let read_word = |o: VmOutcome| -> i64 {
        match o {
            VmOutcome::Success { return_data, .. } => {
                assert_eq!(return_data.len(), 32);
                i64::from_be_bytes(return_data[24..32].try_into().unwrap())
            }
            other => panic!("expected Success, got {other:?}"),
        }
    };

    // TIMESTAMP PUSH1 0 MSTORE PUSH1 0x20 PUSH1 0 RETURN
    let ts_c = install_contract(&stores, 0x71, &[0x42, 0x60, 0, 0x52, 0x60, 0x20, 0x60, 0, 0xf3]);
    let ts = read_word(execute_trigger(&stores, env(), &mk_trigger(ts_c), 100_000));
    assert_eq!(ts, 1_700_000_001, "TIMESTAMP = block ts in seconds, not 1");

    // NUMBER PUSH1 0 MSTORE PUSH1 0x20 PUSH1 0 RETURN
    let num_c = install_contract(&stores, 0x72, &[0x43, 0x60, 0, 0x52, 0x60, 0x20, 0x60, 0, 0xf3]);
    let num = read_word(execute_trigger(&stores, env(), &mk_trigger(num_c), 100_000));
    assert_eq!(num, 83_316_753, "NUMBER = block number, not 0");
}

#[test]
fn execute_trigger_top_level_calltoken_transfers_trc10_before_evm_runs() {
    use tron_crypto::address::Address;
    let stores = fresh_stores();
    let contract_addr = install_contract(&stores, 0xc1, &[0x00]); // STOP
    let owner_addr = fund_account(&stores, 0xa1, 1_000_000_000);

    // Seed sender with 1_000 of token id 1_000_001.
    let token_id: i64 = 1_000_001;
    let key = token_id.to_string();
    let mut owner = stores
        .accounts
        .get(&Address::from_raw(owner_addr))
        .unwrap()
        .unwrap();
    owner.asset_v2.insert(key.clone(), 1_000);
    stores.accounts.put(&Address::from_raw(owner_addr), &owner).unwrap();

    let trigger = TriggerSmartContract {
        owner_address: owner_addr.to_vec(),
        contract_address: contract_addr.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 250,
        token_id,
    };
    let outcome = execute_trigger(
        &stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: 0,
        },
        &trigger,
        100_000,
    );
    assert!(matches!(outcome, VmOutcome::Success { .. }), "got {outcome:?}");

    // Sender: -250, Recipient: +250.
    let after_owner = stores
        .accounts
        .get(&Address::from_raw(owner_addr))
        .unwrap()
        .unwrap();
    assert_eq!(after_owner.asset_v2.get(&key).copied(), Some(750));
    let after_contract = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    assert_eq!(after_contract.asset_v2.get(&key).copied(), Some(250));
}

#[test]
fn execute_trigger_top_level_calltoken_unwinds_on_revert() {
    use tron_crypto::address::Address;
    let stores = fresh_stores();
    // PUSH1 0 PUSH1 0 REVERT
    let contract_addr = install_contract(&stores, 0xc2, &[0x60, 0x00, 0x60, 0x00, 0xfd]);
    let owner_addr = fund_account(&stores, 0xa2, 1_000_000_000);
    let token_id: i64 = 1_000_002;
    let key = token_id.to_string();
    let mut owner = stores
        .accounts
        .get(&Address::from_raw(owner_addr))
        .unwrap()
        .unwrap();
    owner.asset_v2.insert(key.clone(), 500);
    stores.accounts.put(&Address::from_raw(owner_addr), &owner).unwrap();

    let trigger = TriggerSmartContract {
        owner_address: owner_addr.to_vec(),
        contract_address: contract_addr.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 200,
        token_id,
    };
    let outcome = execute_trigger(
        &stores,
        VmBlockEnv { block_number: 1, block_timestamp_ms: 0 },
        &trigger,
        100_000,
    );
    assert!(matches!(outcome, VmOutcome::Revert { .. }));

    // After revert, sender's balance is fully restored.
    let after_owner = stores
        .accounts
        .get(&Address::from_raw(owner_addr))
        .unwrap()
        .unwrap();
    assert_eq!(after_owner.asset_v2.get(&key).copied(), Some(500));
    let after_contract = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap();
    // Contract may or may not exist with the asset map; either way,
    // its balance for `token_id` must be 0.
    if let Some(c) = after_contract {
        assert_eq!(c.asset_v2.get(&key).copied().unwrap_or(0), 0);
    }
}

#[test]
fn execute_trigger_top_level_calltoken_rejects_insufficient_balance() {
    let stores = fresh_stores();
    let contract_addr = install_contract(&stores, 0xc3, &[0x00]);
    let owner_addr = fund_account(&stores, 0xa3, 1_000_000_000);
    // Owner has no asset_v2 entry — balance is 0.
    let trigger = TriggerSmartContract {
        owner_address: owner_addr.to_vec(),
        contract_address: contract_addr.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 100,
        token_id: 1_000_003,
    };
    let outcome = execute_trigger(
        &stores,
        VmBlockEnv { block_number: 1, block_timestamp_ms: 0 },
        &trigger,
        100_000,
    );
    match outcome {
        VmOutcome::PreflightError(s) => assert!(s.contains("sender has 0")),
        other => panic!("expected PreflightError, got {other:?}"),
    }
}

#[test]
fn execute_trigger_reports_revert_for_revert_opcode() {
    let stores = fresh_stores();
    // Bytecode: REVERT immediately with no data.
    // PUSH1 0 PUSH1 0 REVERT
    let contract_addr = install_contract(&stores, 0xc2, &[0x60, 0x00, 0x60, 0x00, 0xfd]);
    let owner_addr = fund_account(&stores, 0xa2, 1_000_000_000);

    let trigger = TriggerSmartContract {
        owner_address: owner_addr.to_vec(),
        contract_address: contract_addr.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };
    let outcome = execute_trigger(
        &stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: 0,
        },
        &trigger,
        100_000,
    );
    assert!(matches!(outcome, VmOutcome::Revert { .. }), "got {outcome:?}");
}

#[test]
fn execute_trigger_rejects_bad_address() {
    let stores = fresh_stores();
    let trigger = TriggerSmartContract {
        owner_address: vec![0x42; 20], // wrong length / prefix
        contract_address: vec![0x41; 21],
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };
    let outcome = execute_trigger(
        &stores,
        VmBlockEnv {
            block_number: 0,
            block_timestamp_ms: 0,
        },
        &trigger,
        100_000,
    );
    assert!(matches!(outcome, VmOutcome::PreflightError(_)), "got {outcome:?}");
}

/// TRON has **no** SSTORE-clear energy refund, unlike Ethereum.
///
/// java-tron removed the EthereumJ refund machinery: `Program.java` has
/// `futureRefundEnergy`/`resetFutureRefund` commented out, `storageSave`
/// performs no refund, and `EnergyCost.getSstoreCost` returns a flat
/// `CLEAR_SSTORE = 5000` for clearing a slot to zero — the same as a
/// `RESET_SSTORE`, with no offsetting refund. So clearing a slot and
/// overwriting it with another non-zero value cost the *same* energy.
///
/// (A previous revision of this test asserted the opposite — that a clear
/// refunds — which was Ethereum behaviour leaking through revm's gas model;
/// that was the energy-parity bug. The TRON gas schedule pins gas decisions
/// to Frontier and zeroes the clear refund, matching java-tron.)
#[test]
fn sstore_clear_does_not_refund_matching_java_tron() {
    fn run_contract(prefix: u8, bytecode: &[u8]) -> u64 {
        let stores = fresh_stores();
        let contract_addr = install_contract(&stores, prefix, bytecode);
        let owner_addr = fund_account(&stores, prefix ^ 0xff, 1_000_000_000);
        let trigger = TriggerSmartContract {
            owner_address: owner_addr.to_vec(),
            contract_address: contract_addr.to_vec(),
            call_value: 0,
            data: vec![],
            call_token_value: 0,
            token_id: 0,
        };
        let outcome = execute_trigger(
            &stores,
            VmBlockEnv {
                block_number: 1,
                block_timestamp_ms: 0,
            },
            &trigger,
            1_000_000,
        );
        match outcome {
            VmOutcome::Success { energy_used, .. } => energy_used,
            other => panic!("expected Success, got {other:?}"),
        }
    }

    // Contract A — two SSTOREs that both leave the slot non-zero
    // (no clear ⇒ no refund).
    //   PUSH1 1 PUSH1 0 SSTORE  // slot0 := 1
    //   PUSH1 2 PUSH1 0 SSTORE  // slot0 := 2
    //   STOP
    let no_clear = run_contract(
        0xc8,
        &[
            0x60, 0x01, 0x60, 0x00, 0x55,
            0x60, 0x02, 0x60, 0x00, 0x55,
            0x00,
        ],
    );

    // Contract B — second SSTORE clears the slot (write 0 to a
    // previously non-zero slot ⇒ refund).
    //   PUSH1 1 PUSH1 0 SSTORE  // slot0 := 1
    //   PUSH1 0 PUSH1 0 SSTORE  // slot0 := 0  (refund)
    //   STOP
    let with_clear = run_contract(
        0xc9,
        &[
            0x60, 0x01, 0x60, 0x00, 0x55,
            0x60, 0x00, 0x60, 0x00, 0x55,
            0x00,
        ],
    );

    // TRON gives no SSTORE-clear refund: CLEAR_SSTORE (5000) == RESET_SSTORE
    // (5000), so the two contracts spend identical energy.
    assert_eq!(
        with_clear, no_clear,
        "TRON has no SSTORE-clear refund: with_clear={with_clear} no_clear={no_clear}"
    );
}
