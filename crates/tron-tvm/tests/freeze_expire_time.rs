//! End-to-end wiring test for FREEZEEXPIRETIME (0xd7).
//!
//! What this test proves:
//! * The opcode is installed — bytecode containing `0xd7` doesn't halt
//!   with "unknown instruction".
//! * The handler decodes its two stack args (resourceType, address)
//!   without underflowing.
//! * The handler queries `Host::tron_freeze_expire_time` and pushes
//!   the result.
//!
//! What it does NOT prove (yet — separate gap on PARITY.md): the
//! returned value reflects real on-chain frozen entries. The current
//! `Context` Host impl uses the trait's default `tron_freeze_expire_time`
//! → 0 because no override delegates to TronDatabase. The same gap
//! affects pre-existing TOKENBALANCE / ISCONTRACT opcodes; closing it
//! requires a `Host` impl override on the Context that reads frozen /
//! delegated entries from the AccountStore + DelegatedResourceStore.

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
    // FREEZEEXPIRETIME (0xd7) is gated by ALLOW_TVM_FREEZE.
    dynamic_properties.put_long(b"ALLOW_TVM_FREEZE", 1);
    VmStores {
        accounts: Arc::new(AccountStore::new(mem())),
        code: Arc::new(CodeStore::new(mem())),
        storage: Arc::new(StorageRowStore::new(mem())),
        witnesses: Arc::new(WitnessStore::new(mem())),
        contract_state: Arc::new(ContractStateStore::new(mem())),
        dynamic_properties,
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

/// Bytecode:
///   PUSH20 <target>      ; target address (20 bytes EVM form)
///   PUSH1  0x01          ; resourceType = ENERGY
///   0xd7                 ; FREEZEEXPIRETIME — pops [resourceType, address]
///   PUSH1  0x00          ; storage slot 0
///   SSTORE               ; persist result so the test can read it back
///   STOP
fn build_freeze_expire_time_caller(target: [u8; 21]) -> Vec<u8> {
    let mut bc = Vec::new();
    bc.push(0x73); // PUSH20
    bc.extend_from_slice(&target[1..]);
    bc.push(0x60); // PUSH1
    bc.push(0x01); // resourceType = 1 (energy)
    bc.push(0xd7); // FREEZEEXPIRETIME
    bc.push(0x60); // PUSH1
    bc.push(0x00); // slot 0
    bc.push(0x55); // SSTORE
    bc.push(0x00); // STOP
    bc
}

#[test]
fn freezeexpiretime_is_wired_and_returns_zero_with_default_host() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0xa0);
    let caller_contract = tron_addr(0xc0);
    let target = tron_addr(0xc1);

    // Caller user.
    stores.accounts.put(
        &Address::from_raw(caller_user),
        &Account {
            address: caller_user.to_vec(),
            balance: 1_000_000_000,
            ..Default::default()
        },
    ).unwrap();
    // Contract with the FREEZEEXPIRETIME-using bytecode.
    let bytecode = build_freeze_expire_time_caller(target);
    let hash = code_hash(&bytecode);
    stores.code.put(hash.as_slice(), &bytecode).unwrap();
    stores.accounts.put(
        &Address::from_raw(caller_contract),
        &Account {
            address: caller_contract.to_vec(),
            balance: 0,
            code: bytecode.clone(),
            code_hash: hash.as_slice().to_vec(),
            ..Default::default()
        },
    ).unwrap();

    let trigger = TriggerSmartContract {
        owner_address: caller_user.to_vec(),
        contract_address: caller_contract.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };

    let outcome = execute_trigger(
        &stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: 1_700_000_000_000, ..Default::default()
        },
        &trigger,
        500_000,
    );
    match outcome {
        VmOutcome::Success { .. } => {}
        other => panic!(
            "expected Success — if Halt(Unknown) the opcode isn't wired; got {other:?}"
        ),
    }

    // The opcode pushed 0 (no frozen entry / no delegation). Verify by reading
    // slot 0 — must be all-zero. If we got here without a Halt(Unknown)
    // the opcode is wired.
    let slot0_key =
        StorageRowStore::compose_key(&Address::from_raw(caller_contract), &[0u8; 32]);
    match stores.storage.get(&slot0_key).unwrap() {
        Some(bytes) => {
            assert_eq!(bytes, vec![0u8; 32], "no frozen entry → 0");
        }
        None => {
            // SSTORE of zero is a no-op in the EVM, so the slot may
            // simply be absent — that's the same observable outcome.
        }
    }
}

/// FREEZEEXPIRETIME bytecode that RETURNs the pushed value (instead of SSTORE),
/// so the test reads the result directly from the VM return data.
///   PUSH20 <target>; PUSH1 <resourceType>; 0xd7; PUSH1 0; MSTORE;
///   PUSH1 32; PUSH1 0; RETURN
fn build_freeze_expire_time_return(target: [u8; 21], resource_type: u8) -> Vec<u8> {
    let mut bc = Vec::new();
    bc.push(0x73); // PUSH20 target
    bc.extend_from_slice(&target[1..]);
    bc.push(0x60);
    bc.push(resource_type); // PUSH1 resourceType
    bc.push(0xd7); // FREEZEEXPIRETIME
    bc.push(0x60);
    bc.push(0x00); // PUSH1 0
    bc.push(0x52); // MSTORE
    bc.push(0x60);
    bc.push(0x20); // PUSH1 32
    bc.push(0x60);
    bc.push(0x00); // PUSH1 0
    bc.push(0xf3); // RETURN(0,32)
    bc
}

/// java `Program.freezeExpireTime` delegate path (Program.java:2013-2026): when
/// `caller != target`, look up the V1 DelegatedResource row `(owner, target)`
/// and return `expireTimeFor{Bandwidth,Energy}` (guarded by a non-zero frozen
/// balance), then `freezeExpireTimeAction` divides ms→seconds (`expireTime/1000`).
#[test]
fn freezeexpiretime_delegate_path_returns_expire_seconds() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0xa0);
    let caller_contract = tron_addr(0xc2);
    let target = tron_addr(0xc3);

    // resourceType = 1 (energy). The contract's own address is the delegate
    // OWNER; `target` is the delegate receiver.
    let bytecode = build_freeze_expire_time_return(target, 1);
    let hash = code_hash(&bytecode);
    stores.code.put(hash.as_slice(), &bytecode).unwrap();
    stores
        .accounts
        .put(
            &Address::from_raw(caller_contract),
            &Account {
                address: caller_contract.to_vec(),
                code: bytecode.clone(),
                code_hash: hash.as_slice().to_vec(),
                ..Default::default()
            },
        )
        .unwrap();
    stores
        .accounts
        .put(
            &Address::from_raw(caller_user),
            &Account {
                address: caller_user.to_vec(),
                balance: 1_000_000_000,
                ..Default::default()
            },
        )
        .unwrap();

    // Seed the V1 DelegatedResource row (owner = caller_contract, to = target)
    // with a non-zero energy frozen balance + a known energy expire time in ms.
    let expire_ms = 1_700_500_000_000i64;
    let key = DelegatedResourceStore::v1_key(
        &Address::from_raw(caller_contract),
        &Address::from_raw(target),
    );
    stores
        .delegated_resources
        .put_raw(
            &key,
            &tron_proto::DelegatedResource {
                from: caller_contract.to_vec(),
                to: target.to_vec(),
                frozen_balance_for_energy: 5_000_000,
                expire_time_for_energy: expire_ms,
                ..Default::default()
            },
        )
        .unwrap();

    let trigger = TriggerSmartContract {
        owner_address: caller_user.to_vec(),
        contract_address: caller_contract.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };
    let outcome = execute_trigger(
        &stores,
        VmBlockEnv { block_number: 1, block_timestamp_ms: 1_700_000_000_000, ..Default::default()},
        &trigger,
        500_000,
    );
    let ret = match outcome {
        VmOutcome::Success { return_data, .. } => return_data,
        other => panic!("expected Success, got {other:?}"),
    };
    assert_eq!(ret.len(), 32);
    let got = u64::from_be_bytes(ret[24..32].try_into().unwrap());
    assert_eq!(
        got,
        (expire_ms / 1000) as u64,
        "delegate FREEZEEXPIRETIME must return expireTimeForEnergy/1000 seconds"
    );
}

/// The delegate path returns 0 when the matching frozen balance is zero (java
/// guards each branch on a non-zero frozen balance).
#[test]
fn freezeexpiretime_delegate_path_zero_when_no_frozen_balance() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0xa0);
    let caller_contract = tron_addr(0xc4);
    let target = tron_addr(0xc5);

    let bytecode = build_freeze_expire_time_return(target, 1); // energy
    let hash = code_hash(&bytecode);
    stores.code.put(hash.as_slice(), &bytecode).unwrap();
    stores
        .accounts
        .put(
            &Address::from_raw(caller_contract),
            &Account {
                address: caller_contract.to_vec(),
                code: bytecode.clone(),
                code_hash: hash.as_slice().to_vec(),
                ..Default::default()
            },
        )
        .unwrap();
    stores
        .accounts
        .put(
            &Address::from_raw(caller_user),
            &Account { address: caller_user.to_vec(), balance: 1_000_000_000, ..Default::default() },
        )
        .unwrap();
    // Row present but only BANDWIDTH frozen (energy frozen = 0) → energy lookup 0.
    let key = DelegatedResourceStore::v1_key(
        &Address::from_raw(caller_contract),
        &Address::from_raw(target),
    );
    stores
        .delegated_resources
        .put_raw(
            &key,
            &tron_proto::DelegatedResource {
                from: caller_contract.to_vec(),
                to: target.to_vec(),
                frozen_balance_for_bandwidth: 5_000_000,
                expire_time_for_bandwidth: 1_700_500_000_000,
                frozen_balance_for_energy: 0,
                expire_time_for_energy: 1_700_900_000_000,
                ..Default::default()
            },
        )
        .unwrap();

    let trigger = TriggerSmartContract {
        owner_address: caller_user.to_vec(),
        contract_address: caller_contract.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };
    let outcome = execute_trigger(
        &stores,
        VmBlockEnv { block_number: 1, block_timestamp_ms: 1_700_000_000_000, ..Default::default()},
        &trigger,
        500_000,
    );
    let ret = match outcome {
        VmOutcome::Success { return_data, .. } => return_data,
        other => panic!("expected Success, got {other:?}"),
    };
    let got = u64::from_be_bytes(ret[24..32].try_into().unwrap());
    assert_eq!(got, 0, "energy lookup with zero frozen-energy balance must return 0");
}
