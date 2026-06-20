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
            block_timestamp_ms: 1_700_000_000_000,
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

    // The opcode pushed 0 (default Host returns 0). Verify by reading
    // slot 0 — must be all-zero. If we got here without a Halt(Unknown)
    // the opcode is wired; the zero value is the documented default-
    // Host behavior pending the Host-on-Context integration.
    let slot0_key =
        StorageRowStore::compose_key(&Address::from_raw(caller_contract), &[0u8; 32]);
    match stores.storage.get(&slot0_key).unwrap() {
        Some(bytes) => {
            assert_eq!(bytes, vec![0u8; 32], "default Host returns 0");
        }
        None => {
            // SSTORE of zero is a no-op in the EVM, so the slot may
            // simply be absent — that's the same observable outcome.
        }
    }
}
