//! End-to-end tests for the Stake 1.0 / 2.0 state-mutating opcodes.
//! Each test deploys a tiny contract that invokes one opcode, runs
//! it through the real EVM (`execute_trigger`), and verifies the
//! chainbase stores received the expected writes — proving the
//! TronDatabase Host bridge actually mutates state (not just pushes
//! a success flag).
//!
//! **Balance reconciliation**: each balance-affecting bridge
//! (`FREEZE`, `UNFREEZE`, `FREEZEBALANCEV2`, `WITHDRAWREWARD`,
//! `WITHDRAWEXPIREUNFREEZE`) stashes a `(target, signed_delta)`
//! pair on `TronDatabase.last_balance_delta`. `impl Host for
//! Context` in revm-context drains it via
//! `tron_take_last_balance_delta` immediately after the bridge call
//! and applies the delta to `journaled_state.balance_incr` /
//! `balance_decr` so subsequent BALANCE opcodes inside the same EVM
//! run see the post-stake balance AND the commit cycle writes the
//! correct balance back to chainbase. Tests below check both
//! TRON-side staking fields and the contract's final balance after
//! commit.

use std::sync::Arc;

use tron_chainbase::{
    AccountStore, CodeStore, ContractStateStore, DelegatedResourceStore, DelegationStore,
    DynamicPropertiesStore, KvBackend, MemBackend, StorageRowStore, VotesStore, WitnessStore,
};
use tron_crypto::address::Address;
use tron_proto::Account;
use tron_tvm::database::code_hash;
use tron_tvm::execute::{execute_trigger, VmBlockEnv, VmOutcome, VmStores};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn fresh_stores() -> VmStores {
    let dynamic_properties = Arc::new(DynamicPropertiesStore::new(mem()));
    // Enable every proposal the staking opcodes gate on.
    dynamic_properties.put_long(b"ALLOW_TVM_FREEZE", 1);
    dynamic_properties.put_long(b"ALLOW_TVM_VOTE", 1);
    dynamic_properties.put_long(b"ALLOW_TVM_FREEZE_V2", 1);
    // Cheap unfreeze delay so tests don't need to wait.
    dynamic_properties.put_long(b"UNFREEZE_DELAY_DAYS", 0);
    // Block-timestamp anchor so duration math works.
    dynamic_properties.save_latest_block_header_timestamp(1_700_000_000_000);
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
        votes: Some(Arc::new(VotesStore::new(mem()))),
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

fn install_contract(stores: &VmStores, addr: [u8; 21], bytecode: Vec<u8>, balance: i64) {
    let hash = code_hash(&bytecode);
    stores.code.put(hash.as_slice(), &bytecode).unwrap();
    stores.accounts.put(
        &Address::from_raw(addr),
        &Account {
            address: addr.to_vec(),
            balance,
            code: bytecode,
            code_hash: hash.as_slice().to_vec(),
            ..Default::default()
        },
    ).unwrap();
}

fn install_caller(stores: &VmStores, addr: [u8; 21], balance: i64) {
    stores.accounts.put(
        &Address::from_raw(addr),
        &Account {
            address: addr.to_vec(),
            balance,
            ..Default::default()
        },
    ).unwrap();
}

fn trigger(from: [u8; 21], to: [u8; 21]) -> tron_proto::TriggerSmartContract {
    tron_proto::TriggerSmartContract {
        owner_address: from.to_vec(),
        contract_address: to.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    }
}

fn push1(v: u8) -> Vec<u8> {
    vec![0x60, v]
}

fn push_u64(v: u64) -> Vec<u8> {
    // PUSH32 — generous for any 8-byte value.
    let mut out = vec![0x7f];
    let mut buf = [0u8; 32];
    buf[24..].copy_from_slice(&v.to_be_bytes());
    out.extend_from_slice(&buf);
    out
}

// =============================================================================
// FREEZEBALANCEV2 (0xda)
// =============================================================================

#[test]
fn freeze_balance_v2_actually_freezes_caller_balance() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0xa1);
    let contract_addr = tron_addr(0xc1);
    install_caller(&stores, caller_user, 100_000_000); // 100 TRX

    // Bytecode that invokes FREEZEBALANCEV2(amount=10_000_000, resource=0).
    // Stack order per the opcode handler:
    //   popn!([resource_type, frozen_balance], ...)
    // So the top of the stack is resource_type, below is frozen_balance.
    // Push frozen_balance first, then resource_type on top.
    //   PUSH32 frozen_balance
    //   PUSH1 resource_type
    //   0xda           ; FREEZEBALANCEV2
    //   PUSH1 0x00     ; slot 0
    //   SSTORE         ; save success flag
    //   STOP
    let frozen = 10_000_000u64;
    let mut bc = Vec::new();
    bc.extend(push_u64(frozen));
    bc.extend(push1(0)); // resource = 0 (BANDWIDTH)
    bc.push(0xda);
    bc.extend(push1(0));
    bc.push(0x55); // SSTORE
    bc.push(0x00);
    install_contract(&stores, contract_addr, bc, 100_000_000);

    let outcome = execute_trigger(
        &stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: 1_700_000_000_000,
        },
        &trigger(caller_user, contract_addr),
        500_000,
    );
    assert!(
        matches!(outcome, VmOutcome::Success { .. }),
        "expected Success, got: {outcome:?}"
    );

    // The contract is the EVM-side caller, so its account is the one
    // whose balance got frozen.
    let contract_acct = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    let freeze_slot = contract_acct
        .frozen_v2
        .iter()
        .find(|f| f.r#type == 0)
        .expect("frozen_v2 slot for resource 0");
    assert_eq!(freeze_slot.amount, frozen as i64);
    // Chain-wide weight reflects the freeze.
    assert_eq!(
        stores.dynamic_properties.total_net_weight(),
        frozen as i64 / 1_000_000,
    );
    // Balance reconciliation: the journaled-balance debit flows
    // through `tron_take_last_balance_delta` → `balance_decr`, then
    // commit writes the post-freeze balance back.
    assert_eq!(
        contract_acct.balance,
        100_000_000 - frozen as i64,
        "contract balance must reflect the freeze debit after commit"
    );

    // Slot 0 holds the success flag (1).
    let storage_key =
        tron_chainbase::StorageRowStore::compose_key(&Address::from_raw(contract_addr), &[0u8; 32]);
    let bytes = stores
        .storage
        .get(&storage_key)
        .unwrap()
        .expect("FREEZEBALANCEV2 success flag persisted");
    let last = bytes[31];
    assert_eq!(last, 1, "FREEZEBALANCEV2 should push 1 on success");
}

// =============================================================================
// UNFREEZEBALANCEV2 (0xdb)
// =============================================================================

#[test]
fn unfreeze_balance_v2_moves_funds_to_unfrozen_v2_queue() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0xa2);
    let contract_addr = tron_addr(0xc2);

    let unfreeze_amount = 5_000_000u64;
    let mut bc = Vec::new();
    bc.extend(push_u64(unfreeze_amount));
    bc.extend(push1(0)); // resource
    bc.push(0xdb);
    bc.extend(push1(0));
    bc.push(0x55);
    bc.push(0x00);
    let hash = code_hash(&bc);
    stores.code.put(hash.as_slice(), &bc).unwrap();
    // Pre-seed the contract with a FreezeV2 slot to unfreeze from.
    stores.accounts.put(
        &Address::from_raw(contract_addr),
        &Account {
            address: contract_addr.to_vec(),
            balance: 0,
            code: bc.clone(),
            code_hash: hash.as_slice().to_vec(),
            frozen_v2: vec![tron_proto::account::FreezeV2 {
                r#type: 0,
                amount: 20_000_000,
            }],
            ..Default::default()
        },
    ).unwrap();
    install_caller(&stores, caller_user, 1_000_000_000);

    let outcome = execute_trigger(
        &stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: 1_700_000_000_000,
        },
        &trigger(caller_user, contract_addr),
        500_000,
    );
    assert!(
        matches!(outcome, VmOutcome::Success { .. }),
        "expected Success, got: {outcome:?}"
    );

    let acct = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    let remaining = acct.frozen_v2.iter().find(|f| f.r#type == 0).unwrap().amount;
    assert_eq!(remaining, 20_000_000 - unfreeze_amount as i64);
    // Unfreeze entry queued with the configured 0-day delay (matures
    // at the current block timestamp).
    assert_eq!(acct.unfrozen_v2.len(), 1);
    assert_eq!(acct.unfrozen_v2[0].unfreeze_amount, unfreeze_amount as i64);
    assert_eq!(acct.unfrozen_v2[0].r#type, 0);
}

// =============================================================================
// WITHDRAWEXPIREUNFREEZE (0xdd)
// =============================================================================

#[test]
fn withdraw_expire_unfreeze_sweeps_matured_entries() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0xa3);
    let contract_addr = tron_addr(0xc3);

    let bc = vec![0xdd, 0x60, 0x00, 0x55, 0x00];
    let hash = code_hash(&bc);
    stores.code.put(hash.as_slice(), &bc).unwrap();
    // Pre-seed two unfrozen_v2 entries: one matured, one not.
    let now = 1_700_000_000_000i64;
    stores.accounts.put(
        &Address::from_raw(contract_addr),
        &Account {
            address: contract_addr.to_vec(),
            balance: 0,
            code: bc.clone(),
            code_hash: hash.as_slice().to_vec(),
            unfrozen_v2: vec![
                tron_proto::account::UnFreezeV2 {
                    r#type: 0,
                    unfreeze_amount: 1_000_000,
                    unfreeze_expire_time: now - 1, // matured
                },
                tron_proto::account::UnFreezeV2 {
                    r#type: 1,
                    unfreeze_amount: 2_000_000,
                    unfreeze_expire_time: now + 100_000, // future
                },
            ],
            ..Default::default()
        },
    ).unwrap();
    install_caller(&stores, caller_user, 1_000_000_000);

    let outcome = execute_trigger(
        &stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: now,
        },
        &trigger(caller_user, contract_addr),
        500_000,
    );
    assert!(matches!(outcome, VmOutcome::Success { .. }));

    let acct = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    // The matured 1_000_000 was consumed from `unfrozen_v2`; the
    // future 2_000_000 entry remains.
    assert_eq!(acct.unfrozen_v2.len(), 1);
    assert_eq!(acct.unfrozen_v2[0].unfreeze_amount, 2_000_000);
    // Balance reconciliation: the matured amount got credited to
    // the contract's journaled balance, then commit wrote it back.
    assert_eq!(acct.balance, 1_000_000);

    // Pushed value = withdrawn amount.
    let storage_key = tron_chainbase::StorageRowStore::compose_key(
        &Address::from_raw(contract_addr),
        &[0u8; 32],
    );
    let bytes = stores.storage.get(&storage_key).unwrap().unwrap();
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[24..32]);
    assert_eq!(i64::from_be_bytes(buf), 1_000_000);
}

// =============================================================================
// CANCELALLUNFREEZEV2 (0xdc)
// =============================================================================

#[test]
fn cancel_all_unfreeze_v2_restakes_pending_entries() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0xa4);
    let contract_addr = tron_addr(0xc4);

    let bc = vec![0xdc, 0x60, 0x00, 0x55, 0x00];
    let hash = code_hash(&bc);
    stores.code.put(hash.as_slice(), &bc).unwrap();
    stores.accounts.put(
        &Address::from_raw(contract_addr),
        &Account {
            address: contract_addr.to_vec(),
            balance: 0,
            code: bc.clone(),
            code_hash: hash.as_slice().to_vec(),
            frozen_v2: vec![tron_proto::account::FreezeV2 {
                r#type: 0,
                amount: 1_000_000,
            }],
            unfrozen_v2: vec![tron_proto::account::UnFreezeV2 {
                r#type: 0,
                unfreeze_amount: 4_000_000,
                unfreeze_expire_time: 1_800_000_000_000,
            }],
            ..Default::default()
        },
    ).unwrap();
    install_caller(&stores, caller_user, 1_000_000_000);

    let outcome = execute_trigger(
        &stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: 1_700_000_000_000,
        },
        &trigger(caller_user, contract_addr),
        500_000,
    );
    assert!(matches!(outcome, VmOutcome::Success { .. }));

    let acct = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    // Every pending unfreeze re-stakes into the matching FreezeV2 slot.
    assert_eq!(acct.unfrozen_v2.len(), 0);
    let restaked = acct.frozen_v2.iter().find(|f| f.r#type == 0).unwrap().amount;
    assert_eq!(restaked, 1_000_000 + 4_000_000);
}

// =============================================================================
// WITHDRAWREWARD (0xd9)
// =============================================================================

#[test]
fn withdraw_reward_returns_allowance_and_zeroes_it() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0xa5);
    let contract_addr = tron_addr(0xc5);

    let bc = vec![0xd9, 0x60, 0x00, 0x55, 0x00];
    let hash = code_hash(&bc);
    stores.code.put(hash.as_slice(), &bc).unwrap();
    stores.accounts.put(
        &Address::from_raw(contract_addr),
        &Account {
            address: contract_addr.to_vec(),
            balance: 0,
            code: bc.clone(),
            code_hash: hash.as_slice().to_vec(),
            allowance: 7_500_000,
            latest_withdraw_time: 0, // first call ever
            ..Default::default()
        },
    ).unwrap();
    install_caller(&stores, caller_user, 1_000_000_000);

    let outcome = execute_trigger(
        &stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: 1_700_000_000_000,
        },
        &trigger(caller_user, contract_addr),
        500_000,
    );
    assert!(matches!(outcome, VmOutcome::Success { .. }));

    let acct = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    assert_eq!(acct.allowance, 0, "allowance zeroed after withdraw");
    // Balance reconciliation: the withdrawn allowance got
    // credited to the contract's journaled balance.
    assert_eq!(acct.balance, 7_500_000);

    let storage_key = tron_chainbase::StorageRowStore::compose_key(
        &Address::from_raw(contract_addr),
        &[0u8; 32],
    );
    let bytes = stores.storage.get(&storage_key).unwrap().unwrap();
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[24..32]);
    assert_eq!(i64::from_be_bytes(buf), 7_500_000);
}

// =============================================================================
// FREEZE (0xd5) — legacy v1
// =============================================================================

#[test]
fn freeze_v1_actually_locks_balance_with_expire_time() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0xa6);
    let contract_addr = tron_addr(0xc6);

    let frozen = 3_000_000u64;
    let receiver = tron_addr(0xd6);
    // FREEZE pops [resource_type, frozen_balance, receiver_address].
    // Push order: receiver, balance, resource (resource on top).
    let mut bc = Vec::new();
    // PUSH20 receiver (the receiver_address ignored by our v1
    // bridge, but the stack needs an entry there).
    bc.push(0x73);
    bc.extend_from_slice(&receiver[1..]);
    bc.extend(push_u64(frozen));
    bc.extend(push1(0)); // resource
    bc.push(0xd5);
    bc.extend(push1(0));
    bc.push(0x55);
    bc.push(0x00);
    let hash = code_hash(&bc);
    stores.code.put(hash.as_slice(), &bc).unwrap();
    stores.accounts.put(
        &Address::from_raw(contract_addr),
        &Account {
            address: contract_addr.to_vec(),
            balance: 50_000_000,
            code: bc.clone(),
            code_hash: hash.as_slice().to_vec(),
            ..Default::default()
        },
    ).unwrap();
    install_caller(&stores, caller_user, 1_000_000_000);

    let outcome = execute_trigger(
        &stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: 1_700_000_000_000,
        },
        &trigger(caller_user, contract_addr),
        500_000,
    );
    assert!(matches!(outcome, VmOutcome::Success { .. }));

    let acct = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    let frozen_entry = acct.frozen.first().expect("frozen entry");
    assert_eq!(frozen_entry.frozen_balance, frozen as i64);
    assert!(frozen_entry.expire_time > 1_700_000_000_000);
    // Balance reconciliation through the journal.
    assert_eq!(acct.balance, 50_000_000 - frozen as i64);
}

// =============================================================================
// VOTEWITNESS (0xd8) — args are empty arrays today, but the bridge
// still runs and writes the (empty) vote-set.
// =============================================================================

// =============================================================================
// UNFREEZE (0xd6) — legacy v1
// =============================================================================

#[test]
fn unfreeze_v1_clears_matured_frozen_entries() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0xa8);
    let contract_addr = tron_addr(0xc8);
    let receiver = tron_addr(0xd8);

    // UNFREEZE pops [resource_type, receiver_address].
    // Stack push order: receiver first, then resource_type.
    let mut bc = Vec::new();
    bc.push(0x73);
    bc.extend_from_slice(&receiver[1..]);
    bc.extend(push1(0));
    bc.push(0xd6);
    bc.extend(push1(0));
    bc.push(0x55);
    bc.push(0x00);
    let hash = code_hash(&bc);
    stores.code.put(hash.as_slice(), &bc).unwrap();
    // Pre-seed an EXPIRED frozen entry on the contract.
    stores.accounts.put(
        &Address::from_raw(contract_addr),
        &Account {
            address: contract_addr.to_vec(),
            balance: 0,
            code: bc.clone(),
            code_hash: hash.as_slice().to_vec(),
            frozen: vec![tron_proto::account::Frozen {
                frozen_balance: 5_000_000,
                expire_time: 1_700_000_000_000 - 1, // already past
            }],
            ..Default::default()
        },
    ).unwrap();
    install_caller(&stores, caller_user, 1_000_000_000);

    let outcome = execute_trigger(
        &stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: 1_700_000_000_000,
        },
        &trigger(caller_user, contract_addr),
        500_000,
    );
    assert!(matches!(outcome, VmOutcome::Success { .. }));

    let acct = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    // The matured entry was removed from `frozen` — the bridge
    // cleared it. (Balance-side credit lives in revm's journal.)
    assert!(acct.frozen.is_empty());
}

// =============================================================================
// DELEGATERESOURCE (0xde) / UNDELEGATERESOURCE (0xdf)
// =============================================================================

#[test]
fn delegate_resource_creates_record_and_moves_balances() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0xa9);
    let contract_addr = tron_addr(0xc9);
    let receiver = tron_addr(0xd9);

    let amount = 3_000_000u64;
    // DELEGATERESOURCE pops [resource_type, delegate_balance, receiver_address].
    // Push: receiver, balance, resource (resource on top).
    let mut bc = Vec::new();
    bc.push(0x73);
    bc.extend_from_slice(&receiver[1..]);
    bc.extend(push_u64(amount));
    bc.extend(push1(0)); // resource = BANDWIDTH
    bc.push(0xde);
    bc.extend(push1(0));
    bc.push(0x55);
    bc.push(0x00);
    let hash = code_hash(&bc);
    stores.code.put(hash.as_slice(), &bc).unwrap();
    // Pre-seed contract with FreezeV2 to delegate FROM.
    stores.accounts.put(
        &Address::from_raw(contract_addr),
        &Account {
            address: contract_addr.to_vec(),
            balance: 0,
            code: bc.clone(),
            code_hash: hash.as_slice().to_vec(),
            frozen_v2: vec![tron_proto::account::FreezeV2 {
                r#type: 0,
                amount: 10_000_000,
            }],
            ..Default::default()
        },
    ).unwrap();
    // Receiver must also exist (the bridge checks).
    stores.accounts.put(
        &Address::from_raw(receiver),
        &Account {
            address: receiver.to_vec(),
            balance: 0,
            ..Default::default()
        },
    ).unwrap();
    install_caller(&stores, caller_user, 1_000_000_000);

    let outcome = execute_trigger(
        &stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: 1_700_000_000_000,
        },
        &trigger(caller_user, contract_addr),
        500_000,
    );
    assert!(
        matches!(outcome, VmOutcome::Success { .. }),
        "expected Success, got: {outcome:?}"
    );

    let owner_acct = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    // Owner's FreezeV2 dropped by `amount`.
    let owner_frozen = owner_acct
        .frozen_v2
        .iter()
        .find(|f| f.r#type == 0)
        .unwrap()
        .amount;
    assert_eq!(owner_frozen, 10_000_000 - amount as i64);
    // Owner records the outgoing delegation on `delegated_frozen_v2_...`.
    assert_eq!(
        owner_acct.delegated_frozen_v2_balance_for_bandwidth,
        amount as i64
    );

    let receiver_acct = stores
        .accounts
        .get(&Address::from_raw(receiver))
        .unwrap()
        .unwrap();
    assert_eq!(
        receiver_acct.acquired_delegated_frozen_v2_balance_for_bandwidth,
        amount as i64
    );

    // The DelegatedResource record exists keyed by (owner, receiver).
    let key = tron_chainbase::DelegatedResourceStore::v2_unlocked_key(
        &Address::from_raw(contract_addr),
        &Address::from_raw(receiver),
    );
    let record = stores
        .delegated_resources
        .get_raw(&key)
        .unwrap()
        .expect("DelegatedResource record written");
    assert_eq!(record.frozen_balance_for_bandwidth, amount as i64);
}

#[test]
fn undelegate_resource_reverses_a_delegation() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0xaa);
    let contract_addr = tron_addr(0xca);
    let receiver = tron_addr(0xda);

    let amount = 2_000_000u64;
    // UNDELEGATERESOURCE pops [resource_type, undelegate_balance, receiver_address].
    let mut bc = Vec::new();
    bc.push(0x73);
    bc.extend_from_slice(&receiver[1..]);
    bc.extend(push_u64(amount));
    bc.extend(push1(0));
    bc.push(0xdf);
    bc.extend(push1(0));
    bc.push(0x55);
    bc.push(0x00);
    let hash = code_hash(&bc);
    stores.code.put(hash.as_slice(), &bc).unwrap();
    // Pre-seed the delegation record AND both accounts' acquired/
    // delegated counters.
    stores.accounts.put(
        &Address::from_raw(contract_addr),
        &Account {
            address: contract_addr.to_vec(),
            balance: 0,
            code: bc.clone(),
            code_hash: hash.as_slice().to_vec(),
            delegated_frozen_v2_balance_for_bandwidth: amount as i64,
            ..Default::default()
        },
    ).unwrap();
    stores.accounts.put(
        &Address::from_raw(receiver),
        &Account {
            address: receiver.to_vec(),
            balance: 0,
            acquired_delegated_frozen_v2_balance_for_bandwidth: amount as i64,
            ..Default::default()
        },
    ).unwrap();
    let key = tron_chainbase::DelegatedResourceStore::v2_unlocked_key(
        &Address::from_raw(contract_addr),
        &Address::from_raw(receiver),
    );
    stores.delegated_resources.put_raw(
        &key,
        &tron_proto::DelegatedResource {
            from: contract_addr.to_vec(),
            to: receiver.to_vec(),
            frozen_balance_for_bandwidth: amount as i64,
            frozen_balance_for_energy: 0,
            expire_time_for_bandwidth: 0,
            expire_time_for_energy: 0,
        },
    ).unwrap();
    install_caller(&stores, caller_user, 1_000_000_000);

    let outcome = execute_trigger(
        &stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: 1_700_000_000_000,
        },
        &trigger(caller_user, contract_addr),
        500_000,
    );
    assert!(matches!(outcome, VmOutcome::Success { .. }));

    let owner_acct = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    assert_eq!(owner_acct.delegated_frozen_v2_balance_for_bandwidth, 0);
    // Owner's FreezeV2 got the amount back.
    let restaked = owner_acct
        .frozen_v2
        .iter()
        .find(|f| f.r#type == 0)
        .unwrap()
        .amount;
    assert_eq!(restaked, amount as i64);

    let receiver_acct = stores
        .accounts
        .get(&Address::from_raw(receiver))
        .unwrap()
        .unwrap();
    assert_eq!(
        receiver_acct.acquired_delegated_frozen_v2_balance_for_bandwidth,
        0
    );

    // The DelegatedResource record's bandwidth counter is now 0.
    let record = stores
        .delegated_resources
        .get_raw(&key)
        .unwrap()
        .unwrap();
    assert_eq!(record.frozen_balance_for_bandwidth, 0);
}

#[test]
fn vote_witness_writes_empty_vote_set_when_args_are_empty() {
    // The interpreter handler currently passes `&[]` to the bridge —
    // memory parsing is wired to a follow-up. So the test asserts the
    // bridge accepts the no-vote case and records an empty new_votes
    // list, leaving any prior votes ready to be cleared.
    let stores = fresh_stores();
    let caller_user = tron_addr(0xa7);
    let contract_addr = tron_addr(0xc7);

    // Stack args for VOTEWITNESS handler:
    //   popn!([amount_array_len, amount_array_off, witness_array_len,
    //          witness_array_off], ...)
    // Push 4 zeros (top→bottom: amount_array_len, ...).
    let mut bc = Vec::new();
    for _ in 0..4 {
        bc.extend(push1(0));
    }
    bc.push(0xd8);
    bc.extend(push1(0));
    bc.push(0x55);
    bc.push(0x00);
    let hash = code_hash(&bc);
    stores.code.put(hash.as_slice(), &bc).unwrap();
    let mut pre_account = Account {
        address: contract_addr.to_vec(),
        balance: 0,
        code: bc.clone(),
        code_hash: hash.as_slice().to_vec(),
        ..Default::default()
    };
    // Pre-seed a vote so the test sees a real clearing happen.
    pre_account.votes.push(tron_proto::Vote {
        vote_address: tron_addr(0xfe).to_vec(),
        vote_count: 100,
    });
    stores.accounts.put(&Address::from_raw(contract_addr), &pre_account).unwrap();
    install_caller(&stores, caller_user, 1_000_000_000);

    let outcome = execute_trigger(
        &stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: 1_700_000_000_000,
        },
        &trigger(caller_user, contract_addr),
        500_000,
    );
    assert!(matches!(outcome, VmOutcome::Success { .. }));

    // The bridge clears existing votes + writes the (empty) new vote
    // set. So the account ends up with no votes.
    let acct = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    assert!(acct.votes.is_empty(), "VOTEWITNESS must clear existing votes");
    // VotesStore got a row recording (old_votes, new_votes=[]).
    let votes_capsule = stores
        .votes
        .as_ref()
        .unwrap()
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .expect("votes capsule");
    assert_eq!(votes_capsule.new_votes.len(), 0);
}
