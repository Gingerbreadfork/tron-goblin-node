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
    // FreezeV2 is gated on supportUnfreezeDelay() = UNFREEZE_DELAY_DAYS > 0
    // (java has no ALLOW_TVM_FREEZE_V2 key); 14 = the mainnet value.
    dynamic_properties.put_long(b"UNFREEZE_DELAY_DAYS", 14);
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
fn freeze_v1_is_noop_when_freezev2_active() {
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

    // Stake-2.0 freeze-v2 is active in `fresh_stores` (UNFREEZE_DELAY_DAYS=14),
    // so the deprecated V1 FREEZE opcode is a no-op that pushes 0 — matching
    // java `OperationActions.freezeAction` under `allowTvmFreezeV2`. Nothing is
    // frozen, the balance is untouched, and no net weight is credited.
    let acct = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    assert!(
        acct.frozen.is_empty(),
        "V1 FREEZE must not lock balance when freeze-v2 is active"
    );
    assert_eq!(acct.balance, 50_000_000);
    assert_eq!(stores.dynamic_properties.total_net_weight(), 0);
}

// =============================================================================
// VOTEWITNESS (0xd8) — the handler reads the witness/amount arrays from
// memory and the bridge validates + casts them (see the focused test
// below and `vote_opcode.rs` for the full memory-layout cases).
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

/// Regression: a VM ENERGY undelegate must SHED the receiver's usage that the
/// un-delegated balance was carrying (java `UnDelegateResourceProcessor.execute`
/// → `transferUsage` / `newEnergyUsage = energyUsage - transferUsage`), not just
/// zero its `acquired`. The old host code skipped the usage transfer entirely,
/// so the receiver's limit dropped while its usage stayed put → it burned TRX
/// for energy where java covered it from stake (mainnet div: bot 41c203d579,
/// blocks 83316960/64/69, fee 6428500 vs 0).
#[test]
fn undelegate_energy_sheds_receiver_usage_not_just_acquired() {
    let stores = fresh_stores();
    // Account-aware V2 increase path + a huge per-TRX usage cap so it doesn't bind.
    stores.dynamic_properties.put_long(b"ALLOW_CANCEL_ALL_UNFREEZE_V2", 1);
    stores.dynamic_properties.put_long(b"TOTAL_ENERGY_WEIGHT", 1);
    stores
        .dynamic_properties
        .put_long(b"TOTAL_ENERGY_CURRENT_LIMIT", 1_000_000_000_000);
    let now_slot = stores.dynamic_properties.head_slot();

    let caller_user = tron_addr(0xaa);
    let contract_addr = tron_addr(0xcb);
    let receiver = tron_addr(0xdb);
    let amount = 100_000_000u64; // 100 TRX of ENERGY

    // UNDELEGATERESOURCE pops [resource_type, undelegate_balance, receiver_address].
    let mut bc = Vec::new();
    bc.push(0x73);
    bc.extend_from_slice(&receiver[1..]);
    bc.extend(push_u64(amount));
    bc.extend(push1(1)); // resource = ENERGY
    bc.push(0xdf);
    bc.extend(push1(0));
    bc.push(0x55);
    bc.push(0x00);
    let hash = code_hash(&bc);
    stores.code.put(hash.as_slice(), &bc).unwrap();

    stores
        .accounts
        .put(
            &Address::from_raw(contract_addr),
            &Account {
                address: contract_addr.to_vec(),
                code: bc.clone(),
                code_hash: hash.as_slice().to_vec(),
                account_resource: Some(tron_proto::account::AccountResource {
                    delegated_frozen_v2_balance_for_energy: amount as i64,
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .unwrap();
    // Receiver holds 100 TRX own ENERGY stake + the 100 TRX acquired, and has
    // 1000 units of energy usage on the clock at `now_slot` (so no decay).
    stores
        .accounts
        .put(
            &Address::from_raw(receiver),
            &Account {
                address: receiver.to_vec(),
                frozen_v2: vec![tron_proto::account::FreezeV2 {
                    r#type: 1,
                    amount: amount as i64,
                }],
                account_resource: Some(tron_proto::account::AccountResource {
                    acquired_delegated_frozen_v2_balance_for_energy: amount as i64,
                    energy_usage: 1000,
                    latest_consume_time_for_energy: now_slot,
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .unwrap();
    let key = tron_chainbase::DelegatedResourceStore::v2_unlocked_key(
        &Address::from_raw(contract_addr),
        &Address::from_raw(receiver),
    );
    stores
        .delegated_resources
        .put_raw(
            &key,
            &tron_proto::DelegatedResource {
                from: contract_addr.to_vec(),
                to: receiver.to_vec(),
                frozen_balance_for_energy: amount as i64,
                ..Default::default()
            },
        )
        .unwrap();
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

    let recv = stores
        .accounts
        .get(&Address::from_raw(receiver))
        .unwrap()
        .unwrap();
    let r = recv.account_resource.unwrap();
    // acquired fully removed (this always worked) ...
    assert_eq!(r.acquired_delegated_frozen_v2_balance_for_energy, 0);
    // ... AND the usage it supported is shed: transferUsage = usage *
    // (balance/allFrozen) = 1000 * (100M / 200M) = 500, so 1000 - 500 = 500.
    // The OLD (buggy) code left this at 1000 — that's the regression this guards.
    assert!(
        r.energy_usage < 1000,
        "receiver energy_usage must drop (was the bug); got {}",
        r.energy_usage
    );
    assert!(
        (450..=550).contains(&r.energy_usage),
        "expected ~500 (1000 - transferUsage 500); got {}",
        r.energy_usage
    );
}

#[test]
fn vote_witness_writes_empty_vote_set_when_args_are_empty() {
    // Both arrays have length 0, and the length word at each offset (0) is
    // zero, so the handler decodes an empty vote list and the bridge casts
    // it — clearing any prior votes and recording an empty `new_votes`
    // list. (java `VoteWitnessProcessor.execute` clears the account's votes
    // before re-adding the empty `voteMap`.)
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

/// DIAGNOSTIC (temporary): isolate the +3 energy over-charge to the CALL path.
/// A caller does CALL(gas=100000, callee, value=0, no args/ret) then STOP.
/// java charges 40 for the CALL base regardless of whether the callee has
/// code (the forwarded gas round-trips and nets to 0 since [STOP] consumes 0).
/// Expected total energy = 21 (7 PUSHes) + 40 (CALL) = 61 in BOTH cases.
/// A +3 on the with-code case => round-trip over-charge; +3 on both => the
/// gas-forward (record_unscaled) path.
#[test]
#[ignore]
fn diag_call_roundtrip_energy() {
    fn caller_bc(callee_evm: [u8; 20]) -> Vec<u8> {
        let mut bc = Vec::new();
        bc.extend([0x60, 0x00]); // PUSH1 retLen
        bc.extend([0x60, 0x00]); // PUSH1 retOffset
        bc.extend([0x60, 0x00]); // PUSH1 argsLen
        bc.extend([0x60, 0x00]); // PUSH1 argsOffset
        bc.extend([0x60, 0x00]); // PUSH1 value
        bc.push(0x73);
        bc.extend(callee_evm); // PUSH20 callee
        bc.extend([0x62, 0x01, 0x86, 0xa0]); // PUSH3 100000 (gas)
        bc.push(0xf1); // CALL
        bc.push(0x00); // STOP
        bc
    }
    let run = |with_code: bool| -> u64 {
        let stores = fresh_stores();
        let user = tron_addr(0xa1);
        let caller_c = tron_addr(0xc1);
        let callee = tron_addr(0xc2);
        let callee_evm: [u8; 20] = callee[1..].try_into().unwrap();
        install_caller(&stores, user, 100_000_000);
        install_contract(&stores, caller_c, caller_bc(callee_evm), 100_000_000);
        if with_code {
            install_contract(&stores, callee, vec![0x00], 0); // [STOP]
        }
        match execute_trigger(
            &stores,
            VmBlockEnv { block_number: 1, block_timestamp_ms: 1_700_000_000_000 },
            &trigger(user, caller_c),
            5_000_000,
        ) {
            VmOutcome::Success { energy_used, .. } => energy_used,
            other => panic!("not success: {other:?}"),
        }
    };
    let e_empty = run(false);
    let e_code = run(true);
    eprintln!("CALL->empty energy={e_empty}   CALL->[STOP] energy={e_code}   Δcode-empty={}", e_code as i64 - e_empty as i64);
    eprintln!("(java expects 61 for BOTH; deviation = the +3 over-charge location)");
}

/// DIAGNOSTIC (temporary): isolate CREATE2 base energy. CREATE2 with a
/// zero-length init code: java charges CREATE(32000) + 0 mem + 0 hash = 32000.
/// 4 PUSH1 (12) before it => total 32012. 32015 means CREATE2 is +3.
#[test]
#[ignore]
fn diag_create2_base_energy() {
    let stores = fresh_stores();
    for k in [
        "ALLOW_TVM_CONSTANTINOPLE",
        "ALLOW_TVM_SOLIDITY_059",
        "ALLOW_TVM_ISTANBUL",
        "ALLOW_TVM_LONDON",
        "ALLOW_TVM_COMPATIBLE_EVM",
    ] {
        stores.dynamic_properties.put_long(k.as_bytes(), 1);
    }
    let user = tron_addr(0xa1);
    let caller_c = tron_addr(0xc1);
    install_caller(&stores, user, 100_000_000);
    // PUSH1 salt, PUSH1 length(0), PUSH1 offset, PUSH1 value, CREATE2, STOP
    let bc = vec![
        0x60, 0x00, // salt
        0x60, 0x00, // length = 0
        0x60, 0x00, // offset
        0x60, 0x00, // value
        0xf5, // CREATE2
        0x00, // STOP
    ];
    install_contract(&stores, caller_c, bc, 100_000_000);
    match execute_trigger(
        &stores,
        VmBlockEnv { block_number: 1, block_timestamp_ms: 1_700_000_000_000 },
        &trigger(user, caller_c),
        5_000_000,
    ) {
        VmOutcome::Success { energy_used, .. } => {
            eprintln!("CREATE2(empty) total energy = {energy_used}  (java expects 32012; 32015 => +3)");
        }
        other => eprintln!("CREATE2 outcome: {other:?}"),
    }
}

/// DIAGNOSTIC (temporary): reproduce the real "Factory" withdraw(address(0),12)
/// in the full VM (state-independent) to confirm the +3 energy over-charge
/// (java = 50408). Once reproduced here it can be instrumented per-op.
#[test]
#[ignore]
fn diag_factory_withdraw_energy() {
    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap()).collect()
    }
    let runtime = unhex("608060405234801561001057600080fd5b50d3801561001d57600080fd5b50d2801561002a57600080fd5b50600436106100ad5760003560e01c80638da5cb5b116100805780638da5cb5b146101115780639f9fb96814610122578063f2fde38b14610143578063f3fef3a314610156578063fc0c546a1461016957600080fd5b806331d4fd77146100b25780634e71e0c8146100c75780635b51bec0146100cf57806366d003ac146100ec575b600080fd5b6100c56100c036600461045d565b61017c565b005b6100c5610201565b604051660c0b8d8b8c0b5d60ca1b81526020015b60405180910390f35b6002546001600160a01b03165b6040516001600160a01b0390911681526020016100e3565b6000546001600160a01b03166100f9565b6101356101303660046104c3565b6102a2565b6040516100e39291906104dc565b6100c561015136600461043b565b610328565b6100c5610164366004610499565b610370565b6003546100f9906001600160a01b031681565b3361018f6000546001600160a01b031690565b6001600160a01b0316146101a257600080fd5b6001600160a01b0383166101b557600080fd5b600280546001600160a01b0319166001600160a01b0385161790556101da82826103a4565b5050600054600280546001600160a01b0319166001600160a01b0390921691909117905550565b6001546001600160a01b0316331461021857600080fd5b6001546001600160a01b03166102366000546001600160a01b031690565b6001600160a01b03167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a360018054600080546001600160a01b0383166001600160a01b03199182168117909255918216909255600280549091169091179055565b60606000604051806020016102b690610406565b601f1982820381018352601f9091011660408181528251602080850191909120604160f81b828501526bffffffffffffffffffffffff193060601b1660218501526035840197909752605580840197909752815180840390970187526075909201905284519401939093209293915050565b3361033b6000546001600160a01b031690565b6001600160a01b03161461034e57600080fd5b600180546001600160a01b0319166001600160a01b0392909216919091179055565b336103836000546001600160a01b031690565b6001600160a01b03161461039657600080fd5b6103a082826103a4565b5050565b60006103af826102a2565b50600380546001600160a01b0319166001600160a01b038616179055805190915060009083906020840183f590506001600160a01b0381166103f057600080fd5b5050600380546001600160a01b03191690555050565b61031c8061054383390190565b600081356001600160a81b038116811461042c57600080fd5b6001600160a01b031692915050565b60006020828403121561044d57600080fd5b61045682610413565b9392505050565b60008060006060848603121561047257600080fd5b61047b84610413565b925061048960208501610413565b9150604084013590509250925092565b600080604083850312156104ac57600080fd5b6104b583610413565b946020939093013593505050565b6000602082840312156104d557600080fd5b5035919050565b604081526000835180604084015260005b8181101561050a57602081870181015160608684010152016104ed565b8181111561051c576000606083860101525b506001600160a01b0393909316602083015250601f91909101601f19160160600191905056fe608060408190526319b400eb60e21b8152339060009082906366d003ac9060849060209060048186803b15801561003557600080fd5b505afa158015610049573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061006d919061028e565b90506000826001600160a01b031663fc0c546a6040518163ffffffff1660e01b815260040160206040518083038186803b1580156100aa57600080fd5b505afa1580156100be573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906100e2919061028e565b90506001600160a01b0381161561018d576040516370a0823160e01b815230600482015261018d9083906001600160a01b038416906370a082319060240160206040518083038186803b15801561013857600080fd5b505afa15801561014c573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061017091906102c7565b836001600160a01b031661019960201b610009179092919060201c565b816001600160a01b0316ff5b604080516001600160a01b038481166024830152604480830185905283518084039091018152606490920183526020820180516001600160e01b031663a9059cbb60e01b17905291516000928616916101f1916102e0565b6000604051808303816000865af19150503d806000811461022e576040519150601f19603f3d011682016040523d82523d6000602084013e610233565b606091505b50509050806102885760405162461bcd60e51b815260206004820181905260248201527f5361666554524332303a206c6f772d6c6576656c2063616c6c206661696c6564604482015260640160405180910390fd5b50505050565b6000602082840312156102a057600080fd5b81516001600160a81b03811681146102b757600080fd5b6001600160a01b03169392505050565b6000602082840312156102d957600080fd5b5051919050565b6000825160005b8181101561030157602081860181015185830152016102e7565b81811115610310576000828501525b50919091019291505056fea26474726f6e58221220c1d41502b7821c3056096bcd94d3ae582042132f0a50319971cfbff224784d9a64736f6c63430008060033");
    let stores = fresh_stores();
    for k in ["ALLOW_TVM_CONSTANTINOPLE","ALLOW_TVM_SOLIDITY_059","ALLOW_TVM_ISTANBUL",
              "ALLOW_TVM_LONDON","ALLOW_TVM_COMPATIBLE_EVM","ALLOW_TVM_TRANSFER_TRC10"] {
        stores.dynamic_properties.put_long(k.as_bytes(), 1);
    }
    let user = tron_addr(0xa1);
    let factory = tron_addr(0xc1);
    install_caller(&stores, user, 1_000_000_000);
    install_contract(&stores, factory, runtime, 1_000_000_000);
    // withdraw(address(0), 12): selector f3fef3a3 + 32B zero addr + 32B 0x0c
    let mut data = unhex("f3fef3a3");
    data.extend(std::iter::repeat(0u8).take(63));
    data.push(0x0c);
    let mut tr = trigger(user, factory);
    tr.data = data;
    match execute_trigger(&stores,
        VmBlockEnv { block_number: 1, block_timestamp_ms: 1_700_000_000_000 },
        &tr, 50_000_000) {
        VmOutcome::Success { energy_used, .. } => eprintln!("Factory withdraw energy = {energy_used}  (java=50408; 50411 => +3 reproduced)"),
        other => eprintln!("Factory outcome: {other:?}"),
    }
}
