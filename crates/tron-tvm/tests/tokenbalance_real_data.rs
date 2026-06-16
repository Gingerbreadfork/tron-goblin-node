//! End-to-end proof that the forked-revm-context Host bridge now
//! routes TRON-specific opcodes through the database's real chainbase
//! reads (not the default-zero stub that shadowed real data before
//! `TronDatabaseExt` was wired).
//!
//! Test shape: deploy a contract whose bytecode invokes TOKENBALANCE
//! (`0xd1`) on a known address + token id, persist the result to slot
//! 0, then verify the slot holds the actual asset_v2 balance preloaded
//! into AccountStore — not zero.
//!
//! Before the bridge landed, this test would have observed `0` (Host
//! trait default). After: it observes the real balance.

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
    let dynamic_properties = Arc::new(DynamicPropertiesStore::new(mem()));
    // TOKENBALANCE (0xd1) needs ALLOW_TVM_TRANSFER_TRC10; ISCONTRACT
    // (0xd4) needs ALLOW_TVM_SOLIDITY_059.
    dynamic_properties.put_long(b"ALLOW_TVM_TRANSFER_TRC10", 1);
    dynamic_properties.put_long(b"ALLOW_TVM_SOLIDITY_059", 1);
    VmStores {
        accounts: Arc::new(AccountStore::new(mem())),
        code: Arc::new(CodeStore::new(mem())),
        storage: Arc::new(StorageRowStore::new(mem())),
        witnesses: Arc::new(WitnessStore::new(mem())),
        contract_state: Arc::new(ContractStateStore::new(mem())),
        dynamic_properties,
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

fn push20(addr: [u8; 21]) -> Vec<u8> {
    let mut v = vec![0x73];
    v.extend_from_slice(&addr[1..]);
    v
}

fn push_u256(value: u64) -> Vec<u8> {
    let mut out = vec![0x7f]; // PUSH32
    let mut buf = [0u8; 32];
    buf[24..].copy_from_slice(&value.to_be_bytes());
    out.extend_from_slice(&buf);
    out
}

/// Bytecode: TOKENBALANCE(target, token_id) → store result at slot 0.
///
/// Stack contract per OperationActions.java (top first):
///     [tokenId, address]
/// So push order (LIFO): address first, then tokenId on top.
///
///   PUSH20 <holder>     ; stack: [holder]
///   PUSH32 <token_id>   ; stack: [token_id, holder]   ← tokenId on top
///   0xd1                ; TOKENBALANCE pops [tokenId, address], pushes balance
///   PUSH1 0x00          ; slot 0
///   SSTORE              ; persist balance
///   STOP
fn build_tokenbalance_caller(holder: [u8; 21], token_id: i64) -> Vec<u8> {
    let mut bc = Vec::new();
    bc.extend(push20(holder));
    bc.extend(push_u256(token_id as u64));
    bc.push(0xd1); // TOKENBALANCE
    bc.push(0x60); // PUSH1
    bc.push(0x00); // slot 0
    bc.push(0x55); // SSTORE
    bc.push(0x00); // STOP
    bc
}

#[test]
fn tokenbalance_opcode_returns_real_chainbase_asset_v2_balance() {
    let stores = fresh_stores();

    let caller_user = tron_addr(0xa0);
    let contract_addr = tron_addr(0xc0);
    let holder_addr = tron_addr(0xd0);
    let token_id = 1_000_001i64;
    let real_balance = 987_654_321i64;

    // Caller-user (transaction signer / msg.sender).
    stores.accounts.put(
        &Address::from_raw(caller_user),
        &Account {
            address: caller_user.to_vec(),
            balance: 1_000_000_000,
            ..Default::default()
        },
    ).unwrap();

    // The holder account — has a real asset_v2 entry. THIS is what
    // TOKENBALANCE must surface.
    let mut holder = Account {
        address: holder_addr.to_vec(),
        balance: 0,
        ..Default::default()
    };
    holder
        .asset_v2
        .insert(token_id.to_string(), real_balance);
    stores.accounts.put(&Address::from_raw(holder_addr), &holder).unwrap();

    // The contract that calls TOKENBALANCE.
    let bytecode = build_tokenbalance_caller(holder_addr, token_id);
    let hash = code_hash(&bytecode);
    stores.code.put(hash.as_slice(), &bytecode).unwrap();
    stores.accounts.put(
        &Address::from_raw(contract_addr),
        &Account {
            address: contract_addr.to_vec(),
            balance: 0,
            code: bytecode,
            code_hash: hash.as_slice().to_vec(),
            ..Default::default()
        },
    ).unwrap();

    let trigger = TriggerSmartContract {
        owner_address: caller_user.to_vec(),
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
            block_timestamp_ms: 1_700_000_000_000,
        },
        &trigger,
        500_000,
    );
    match outcome {
        VmOutcome::Success { .. } => {}
        other => panic!("expected Success, got {other:?}"),
    }

    // Read slot 0 — should hold `real_balance` (not zero!).
    let slot_key =
        StorageRowStore::compose_key(&Address::from_raw(contract_addr), &[0u8; 32]);
    let bytes = stores
        .storage
        .get(&slot_key)
        .unwrap()
        .expect("TOKENBALANCE result must be persisted to slot 0");

    // The pushed U256 is in big-endian. Extract the low 8 bytes.
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[24..32]);
    let observed = i64::from_be_bytes(buf);

    assert_eq!(
        observed, real_balance,
        "TOKENBALANCE must return the real asset_v2 balance from AccountStore \
         (this is the proof that the forked-revm-context TronHostExt bridge works); \
         before the bridge landed, this would observe 0."
    );
}

/// Negative case — make sure we didn't accidentally always-return
/// nonzero. An address without the token returns 0.
#[test]
fn tokenbalance_returns_zero_for_unknown_token() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0xa1);
    let contract_addr = tron_addr(0xc1);
    let holder_addr = tron_addr(0xd1);
    let real_token = 1_000_002i64;
    let queried_token = 9_999_999i64; // not held

    stores.accounts.put(
        &Address::from_raw(caller_user),
        &Account {
            address: caller_user.to_vec(),
            balance: 1_000_000_000,
            ..Default::default()
        },
    ).unwrap();

    let mut holder = Account {
        address: holder_addr.to_vec(),
        ..Default::default()
    };
    holder.asset_v2.insert(real_token.to_string(), 12345);
    stores.accounts.put(&Address::from_raw(holder_addr), &holder).unwrap();

    let bytecode = build_tokenbalance_caller(holder_addr, queried_token);
    let hash = code_hash(&bytecode);
    stores.code.put(hash.as_slice(), &bytecode).unwrap();
    stores.accounts.put(
        &Address::from_raw(contract_addr),
        &Account {
            address: contract_addr.to_vec(),
            code: bytecode,
            code_hash: hash.as_slice().to_vec(),
            ..Default::default()
        },
    ).unwrap();

    let trigger = TriggerSmartContract {
        owner_address: caller_user.to_vec(),
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
            block_timestamp_ms: 1_700_000_000_000,
        },
        &trigger,
        500_000,
    );
    assert!(matches!(outcome, VmOutcome::Success { .. }));

    let slot_key =
        StorageRowStore::compose_key(&Address::from_raw(contract_addr), &[0u8; 32]);
    // SSTORE of zero is a no-op (slot stays absent).
    assert!(
        stores.storage.get(&slot_key).unwrap().is_none(),
        "TOKENBALANCE for unknown token must push 0 (SSTORE 0 is a no-op)"
    );
}

/// ISCONTRACT (0xd4) must return 1 for a deployed contract, 0 for an
/// EOA. Same Host bridge — proves multiple TRON methods are wired.
#[test]
fn iscontract_returns_one_for_contract_and_zero_for_eoa() {
    // Build two test cases inline.
    for (label, target_byte, is_contract, expect_slot_value) in [
        ("contract", 0xeau8, true, true),
        ("eoa", 0xebu8, false, false),
    ] {
        let stores = fresh_stores();
        let caller_user = tron_addr(0xa2);
        let contract_addr = tron_addr(0xc2);
        let target_addr = tron_addr(target_byte);

        stores.accounts.put(
            &Address::from_raw(caller_user),
            &Account {
                address: caller_user.to_vec(),
                balance: 1_000_000_000,
                ..Default::default()
            },
        ).unwrap();

        if is_contract {
            stores.accounts.put(
                &Address::from_raw(target_addr),
                &Account {
                    address: target_addr.to_vec(),
                    // ISCONTRACT mirrors java's Program.isContract (contract row /
                    // AccountType::Contract), NOT code_hash — snapshot-imported
                    // contracts carry an EMPTY code_hash (code is keyed by
                    // address). Set the Contract type and leave code_hash empty
                    // to exercise exactly that case.
                    r#type: tron_proto::AccountType::Contract as i32,
                    ..Default::default()
                },
            ).unwrap();
        } else {
            stores.accounts.put(
                &Address::from_raw(target_addr),
                &Account {
                    address: target_addr.to_vec(),
                    code_hash: vec![],
                    ..Default::default()
                },
            ).unwrap();
        }

        // PUSH20 target; ISCONTRACT (0xd4); PUSH1 0; SSTORE; STOP
        let mut bc = Vec::new();
        bc.extend(push20(target_addr));
        bc.push(0xd4);
        bc.push(0x60);
        bc.push(0x00);
        bc.push(0x55);
        bc.push(0x00);

        let hash = code_hash(&bc);
        stores.code.put(hash.as_slice(), &bc).unwrap();
        stores.accounts.put(
            &Address::from_raw(contract_addr),
            &Account {
                address: contract_addr.to_vec(),
                code: bc,
                code_hash: hash.as_slice().to_vec(),
                ..Default::default()
            },
        ).unwrap();

        let trigger = TriggerSmartContract {
            owner_address: caller_user.to_vec(),
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
                block_timestamp_ms: 1_700_000_000_000,
            },
            &trigger,
            500_000,
        );
        assert!(matches!(outcome, VmOutcome::Success { .. }), "{label}");

        let slot_key =
            StorageRowStore::compose_key(&Address::from_raw(contract_addr), &[0u8; 32]);
        let observed_nonzero = stores.storage.get(&slot_key).unwrap().is_some();
        assert_eq!(
            observed_nonzero, expect_slot_value,
            "ISCONTRACT for {label} (target=0x{target_byte:02x}) should push {} → slot present={expect_slot_value}",
            if is_contract { 1 } else { 0 }
        );
    }
}
