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
    AccountStore, CodeStore, ContractStateStore, DelegatedResourceAccountIndexStore,
    DelegatedResourceStore, DelegationStore, DynamicPropertiesStore, KvBackend, MemBackend,
    StorageRowStore, VotesStore, WitnessStore,
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
        delegated_resource_account_index: None,
        delegation: Arc::new(DelegationStore::new(mem())),
        block_index: None,
        contracts: None,
        votes: Some(Arc::new(VotesStore::new(mem()))),
        reward_vi: None,
    abi: None,
    }
}

/// `fresh_stores()` with the Stake-2.0 unfreeze delay OFF — the
/// ALLOW_TVM_FREEZE-on / UNFREEZE_DELAY_DAYS-off window in which the legacy
/// FREEZE (0xd5) opcode actually reaches `Program.freeze` instead of
/// `OperationActions.freezeAction`'s push-zero short circuit.
fn fresh_stores_pre_stake2() -> VmStores {
    let stores = fresh_stores();
    stores.dynamic_properties.put_long(b"UNFREEZE_DELAY_DAYS", 0);
    stores
}

/// `fresh_stores()` plus a real `DelegatedResourceAccountIndex` store attached,
/// for the DELEGATERESOURCE / UNDELEGATERESOURCE index-maintenance tests. The
/// returned store handle is shared with the `VmStores`, so tests can read the
/// index rows the opcode bridges write.
fn fresh_stores_with_index() -> (VmStores, Arc<DelegatedResourceAccountIndexStore>) {
    let mut stores = fresh_stores();
    let index = Arc::new(DelegatedResourceAccountIndexStore::new(mem()));
    stores.delegated_resource_account_index = Some(Arc::clone(&index));
    (stores, index)
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

/// PUSH32 of a full 256-bit word — for operands that must exercise the high
/// limbs (out-of-`i64` amounts, out-of-range resource codes).
fn push_u256(word: [u8; 32]) -> Vec<u8> {
    let mut out = vec![0x7f];
    out.extend_from_slice(&word);
    out
}

/// The 32-byte word an opcode's `SSTORE`d result left in storage slot 0, or
/// all-zero when the slot was never written (an all-zero store is elided).
fn slot0(stores: &VmStores, addr: [u8; 21]) -> [u8; 32] {
    let key = tron_chainbase::StorageRowStore::compose_key(&Address::from_raw(addr), &[0u8; 32]);
    match stores.storage.get(&key).unwrap() {
        Some(bytes) => {
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            out
        }
        None => [0u8; 32],
    }
}

/// The success flag a staking opcode pushed, read back out of slot 0.
fn pushed_flag(stores: &VmStores, addr: [u8; 21]) -> u8 {
    slot0(stores, addr)[31]
}

/// Seed an account row directly (contracts with pre-existing staking state).
fn put_account(stores: &VmStores, addr: [u8; 21], account: Account) {
    stores
        .accounts
        .put(&Address::from_raw(addr), &account)
        .unwrap();
}

/// Install `bytecode` at `addr` as a contract, carrying whatever TRON-side
/// staking fields `account` already holds.
fn install_contract_with(
    stores: &VmStores,
    addr: [u8; 21],
    bytecode: Vec<u8>,
    mut account: Account,
) {
    let hash = code_hash(&bytecode);
    stores.code.put(hash.as_slice(), &bytecode).unwrap();
    account.address = addr.to_vec();
    account.code = bytecode;
    account.code_hash = hash.as_slice().to_vec();
    put_account(stores, addr, account);
}

/// Run `bytecode` as the contract at `addr` and require the transaction to
/// succeed. Every staking test below has the same shape: a fresh caller EOA
/// triggers the contract, the contract runs one staking opcode and `SSTORE`s
/// the pushed flag into slot 0.
fn run_contract(stores: &VmStores, caller: [u8; 21], addr: [u8; 21]) {
    install_caller(stores, caller, 1_000_000_000);
    let outcome = execute_trigger(
        stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: NOW_MS,
            ..Default::default()
        },
        &trigger(caller, addr),
        500_000,
    );
    assert!(
        matches!(outcome, VmOutcome::Success { .. }),
        "expected Success, got: {outcome:?}"
    );
}

/// The block timestamp every fixture anchors on (`fresh_stores` saves the same
/// value as the latest block-header timestamp).
const NOW_MS: i64 = 1_700_000_000_000;

/// Three days in ms — java `FROZEN_PERIOD * getMinFrozenTime()`, the expiry a
/// v1 TVM freeze stamps (`Program.freeze` passes `getMinFrozenTime()` = 3).
const V1_EXPIRE: i64 = NOW_MS + 3 * 24 * 60 * 60 * 1000;

/// FREEZE (0xd5) pops `[resource_type, frozen_balance, receiver_address]`, so
/// the push order is receiver, balance, resource. The trailing
/// `PUSH1 0; SSTORE; STOP` records the pushed flag in slot 0.
fn freeze_v1_code(receiver: [u8; 21], balance: Vec<u8>, resource: Vec<u8>) -> Vec<u8> {
    let mut bc = vec![0x73];
    bc.extend_from_slice(&receiver[1..]);
    bc.extend(balance);
    bc.extend(resource);
    bc.push(0xd5);
    bc.extend(push1(0));
    bc.push(0x55);
    bc.push(0x00);
    bc
}

/// UNFREEZE (0xd6) pops `[resource_type, receiver_address]`.
fn unfreeze_v1_code(receiver: [u8; 21], resource: Vec<u8>) -> Vec<u8> {
    let mut bc = vec![0x73];
    bc.extend_from_slice(&receiver[1..]);
    bc.extend(resource);
    bc.push(0xd6);
    bc.extend(push1(0));
    bc.push(0x55);
    bc.push(0x00);
    bc
}

fn frozen(balance: i64, expire: i64) -> tron_proto::account::Frozen {
    tron_proto::account::Frozen {
        frozen_balance: balance,
        expire_time: expire,
    }
}

fn energy_frozen(account: &Account) -> Option<tron_proto::account::Frozen> {
    account
        .account_resource
        .as_ref()
        .and_then(|r| r.frozen_balance_for_energy.clone())
}

// =============================================================================
// Inner-frame-revert staking leak (mirrors e0e37f2 for the per-frame case)
// =============================================================================
//
// java-tron scopes every VM frame's staking-opcode side effects (the callee's
// frozen / frozen_v2 / votes / delegated_* fields AND the chain-global
// TOTAL_*_WEIGHT accumulators) to that frame's child Repository, committed to
// the parent ONLY on frame success and discarded on frame revert. So a staking
// op run inside an inner CALL frame that REVERTS leaves NO trace — even when
// the outer/top-level tx frame SUCCEEDS.
//
// Our staking bridges (`crates/tron-tvm/src/tron_host.rs`) write directly to
// the chainbase stores, BYPASSING revm's journal, so revm's per-frame
// `checkpoint_revert` never undoes them. e0e37f2 added a per-TRANSACTION
// VmSession (in tron-executor) that rolls these back on a WHOLE-TX revert, but
// it has NO per-frame checkpoint: an inner frame that reverts while the
// top-level frame succeeds still leaks. These tests reproduce that leak at the
// VM level (no executor session) and assert the callee fields + global weight
// accumulators are UNCHANGED after the tx.

/// Build the OUTER contract (the trigger target): it CALLs `inner_evm` with
/// gas=`gas`, value 0, no calldata, no return buffer, then POPs the (0/1)
/// success flag and STOPs. Because it discards the CALL result, the outer
/// frame SUCCEEDS even when the inner frame REVERTs.
fn outer_calls_then_succeeds(inner_evm: [u8; 20], gas: u64) -> Vec<u8> {
    let mut bc = Vec::new();
    // CALL stack (top first): gas, to, value, inOffset, inLen, outOffset, outLen.
    // Push in reverse so `gas` ends up on top.
    bc.extend(push1(0)); // outLen
    bc.extend(push1(0)); // outOffset
    bc.extend(push1(0)); // inLen
    bc.extend(push1(0)); // inOffset
    bc.extend(push1(0)); // value
    bc.push(0x73); // PUSH20 to
    bc.extend_from_slice(&inner_evm);
    bc.extend(push_u64(gas)); // gas (top of stack)
    bc.push(0xf1); // CALL
    bc.push(0x50); // POP the success flag — ignore inner revert
    bc.push(0x00); // STOP → outer SUCCEEDS
    bc
}

/// Regression: FREEZEBALANCEV2 inside an inner CALL frame that REVERTS must
/// NOT leak — neither the inner contract's `frozen_v2` / balance debit nor the
/// chain-global TOTAL_NET_WEIGHT. Before the fix the bridge's direct store
/// writes survive the inner revert (revm's journal + the per-tx VmSession both
/// miss it), so the freeze persisted and TOTAL_NET_WEIGHT drifted.
#[test]
fn inner_frame_revert_does_not_leak_freeze_v2() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0xa1);
    let outer_addr = tron_addr(0xc1);
    let inner_addr = tron_addr(0xb1);
    let inner_evm: [u8; 20] = inner_addr[1..].try_into().unwrap();

    // INNER: FREEZEBALANCEV2(amount, resource=0) then REVERT(0,0).
    let frozen = 10_000_000u64;
    let mut inner = Vec::new();
    inner.extend(push_u64(frozen));
    inner.extend(push1(0)); // resource = BANDWIDTH
    inner.push(0xda); // FREEZEBALANCEV2
    inner.push(0x50); // POP the success flag
    inner.extend(push1(0)); // REVERT len
    inner.extend(push1(0)); // REVERT offset
    inner.push(0xfd); // REVERT → inner frame fails
    install_contract(&stores, inner_addr, inner, 100_000_000);

    install_contract(&stores, outer_addr, outer_calls_then_succeeds(inner_evm, 400_000), 0);
    install_caller(&stores, caller_user, 100_000_000);

    let outcome = execute_trigger(
        &stores,
        VmBlockEnv { block_number: 1, block_timestamp_ms: 1_700_000_000_000, ..Default::default()},
        &trigger(caller_user, outer_addr),
        2_000_000,
    );
    assert!(
        matches!(outcome, VmOutcome::Success { .. }),
        "outer frame must SUCCEED (it ignores the inner revert), got: {outcome:?}"
    );

    // The inner contract (the freeze caller) must be byte-identical to its
    // pre-state: no frozen_v2 slot, balance untouched.
    let inner_acct = stores
        .accounts
        .get(&Address::from_raw(inner_addr))
        .unwrap()
        .unwrap();
    assert!(
        inner_acct.frozen_v2.iter().all(|f| f.amount == 0),
        "inner-frame FREEZEBALANCEV2 leaked frozen_v2: {:?}",
        inner_acct.frozen_v2
    );
    assert_eq!(
        inner_acct.balance, 100_000_000,
        "inner-frame FREEZEBALANCEV2 leaked the balance debit"
    );
    // The chain-global accumulator must not have drifted.
    assert_eq!(
        stores.dynamic_properties.total_net_weight(),
        0,
        "inner-frame FREEZEBALANCEV2 leaked TOTAL_NET_WEIGHT"
    );
}

/// Regression: UNFREEZEBALANCEV2 inside an inner CALL frame that REVERTS must
/// leave the callee's `frozen_v2` / `unfrozen_v2` and TOTAL_NET_WEIGHT exactly
/// as they were. Exercises the unstake path (which decrements the weight and
/// queues an unfreeze entry) under inner-frame revert.
#[test]
fn inner_frame_revert_does_not_leak_unfreeze_v2() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0xa2);
    let outer_addr = tron_addr(0xc2);
    let inner_addr = tron_addr(0xb2);
    let inner_evm: [u8; 20] = inner_addr[1..].try_into().unwrap();

    // INNER: UNFREEZEBALANCEV2(amount, resource=0) then REVERT.
    let unfreeze = 5_000_000u64;
    let mut inner = Vec::new();
    inner.extend(push_u64(unfreeze));
    inner.extend(push1(0));
    inner.push(0xdb); // UNFREEZEBALANCEV2
    inner.push(0x50);
    inner.extend(push1(0));
    inner.extend(push1(0));
    inner.push(0xfd); // REVERT
    let hash = code_hash(&inner);
    stores.code.put(hash.as_slice(), &inner).unwrap();
    // Seed the inner contract with held FreezeV2 and the matching weight, as if
    // a prior (committed) freeze had recorded it.
    stores.dynamic_properties.put_long(b"TOTAL_NET_WEIGHT", 20);
    stores
        .accounts
        .put(
            &Address::from_raw(inner_addr),
            &Account {
                address: inner_addr.to_vec(),
                balance: 0,
                code: inner.clone(),
                code_hash: hash.as_slice().to_vec(),
                frozen_v2: vec![tron_proto::account::FreezeV2 { r#type: 0, amount: 20_000_000 }],
                ..Default::default()
            },
        )
        .unwrap();

    install_contract(&stores, outer_addr, outer_calls_then_succeeds(inner_evm, 400_000), 0);
    install_caller(&stores, caller_user, 100_000_000);

    let outcome = execute_trigger(
        &stores,
        VmBlockEnv { block_number: 1, block_timestamp_ms: 1_700_000_000_000, ..Default::default()},
        &trigger(caller_user, outer_addr),
        2_000_000,
    );
    assert!(matches!(outcome, VmOutcome::Success { .. }), "outer must succeed: {outcome:?}");

    let inner_acct = stores
        .accounts
        .get(&Address::from_raw(inner_addr))
        .unwrap()
        .unwrap();
    let held: i64 = inner_acct.frozen_v2.iter().filter(|f| f.r#type == 0).map(|f| f.amount).sum();
    assert_eq!(held, 20_000_000, "inner-frame UNFREEZEBALANCEV2 leaked the FreezeV2 debit");
    assert!(
        inner_acct.unfrozen_v2.is_empty(),
        "inner-frame UNFREEZEBALANCEV2 leaked an unfrozen_v2 entry: {:?}",
        inner_acct.unfrozen_v2
    );
    assert_eq!(
        stores.dynamic_properties.total_net_weight(),
        20,
        "inner-frame UNFREEZEBALANCEV2 leaked TOTAL_NET_WEIGHT"
    );
}

/// Regression: DELEGATERESOURCE inside an inner CALL frame that REVERTS must
/// not leak the owner/receiver account moves OR the DelegatedResource row.
#[test]
fn inner_frame_revert_does_not_leak_delegate_resource() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0xa3);
    let outer_addr = tron_addr(0xc3);
    let inner_addr = tron_addr(0xb3);
    let receiver = tron_addr(0xd3);
    let inner_evm: [u8; 20] = inner_addr[1..].try_into().unwrap();

    let amount = 3_000_000u64;
    // INNER: DELEGATERESOURCE(receiver, amount, resource=0) then REVERT.
    // Stack: [resource_type, delegate_balance, receiver_address] (resource top).
    let mut inner = Vec::new();
    inner.push(0x73); // PUSH20 receiver
    inner.extend_from_slice(&receiver[1..]);
    inner.extend(push_u64(amount));
    inner.extend(push1(0)); // resource = BANDWIDTH
    inner.push(0xde); // DELEGATERESOURCE
    inner.push(0x50);
    inner.extend(push1(0));
    inner.extend(push1(0));
    inner.push(0xfd); // REVERT
    let hash = code_hash(&inner);
    stores.code.put(hash.as_slice(), &inner).unwrap();
    stores
        .accounts
        .put(
            &Address::from_raw(inner_addr),
            &Account {
                address: inner_addr.to_vec(),
                balance: 0,
                code: inner.clone(),
                code_hash: hash.as_slice().to_vec(),
                frozen_v2: vec![tron_proto::account::FreezeV2 { r#type: 0, amount: 10_000_000 }],
                ..Default::default()
            },
        )
        .unwrap();
    stores
        .accounts
        .put(
            &Address::from_raw(receiver),
            &Account { address: receiver.to_vec(), balance: 0, ..Default::default() },
        )
        .unwrap();

    install_contract(&stores, outer_addr, outer_calls_then_succeeds(inner_evm, 400_000), 0);
    install_caller(&stores, caller_user, 100_000_000);

    let outcome = execute_trigger(
        &stores,
        VmBlockEnv { block_number: 1, block_timestamp_ms: 1_700_000_000_000, ..Default::default()},
        &trigger(caller_user, outer_addr),
        2_000_000,
    );
    assert!(matches!(outcome, VmOutcome::Success { .. }), "outer must succeed: {outcome:?}");

    let owner_acct = stores
        .accounts
        .get(&Address::from_raw(inner_addr))
        .unwrap()
        .unwrap();
    let held: i64 = owner_acct.frozen_v2.iter().filter(|f| f.r#type == 0).map(|f| f.amount).sum();
    assert_eq!(held, 10_000_000, "inner-frame DELEGATERESOURCE leaked the owner FreezeV2 debit");
    assert_eq!(
        owner_acct.delegated_frozen_v2_balance_for_bandwidth, 0,
        "inner-frame DELEGATERESOURCE leaked the owner delegated counter"
    );
    let receiver_acct = stores
        .accounts
        .get(&Address::from_raw(receiver))
        .unwrap()
        .unwrap();
    assert_eq!(
        receiver_acct.acquired_delegated_frozen_v2_balance_for_bandwidth, 0,
        "inner-frame DELEGATERESOURCE leaked the receiver acquired counter"
    );
    let key = tron_chainbase::DelegatedResourceStore::v2_unlocked_key(
        &Address::from_raw(inner_addr),
        &Address::from_raw(receiver),
    );
    let record = stores.delegated_resources.get_raw(&key).unwrap();
    assert!(
        record.map_or(true, |r| r.frozen_balance_for_bandwidth == 0),
        "inner-frame DELEGATERESOURCE leaked a DelegatedResource row"
    );
}

/// Regression (ANCESTOR revert): a staking op in a frame that itself SUCCEEDS
/// must still be discarded when an ANCESTOR frame later reverts — java rolls
/// back the whole child deposit. Three-level chain: outer CALLs `middle`
/// (ignoring its result, so outer succeeds); `middle` CALLs `inner` then
/// REVERTs; `inner` does FREEZEBALANCEV2 then STOPs (succeeds). The freeze must
/// NOT persist, because `middle`'s revert discards `inner`'s committed subtree.
#[test]
fn ancestor_frame_revert_discards_succeeded_descendant_freeze() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0xa5);
    let outer_addr = tron_addr(0xc5);
    let middle_addr = tron_addr(0xb5);
    let inner_addr = tron_addr(0xe5);
    let middle_evm: [u8; 20] = middle_addr[1..].try_into().unwrap();
    let inner_evm: [u8; 20] = inner_addr[1..].try_into().unwrap();

    // INNER: FREEZEBALANCEV2(amount, 0) then STOP (this frame SUCCEEDS).
    let frozen = 10_000_000u64;
    let mut inner = Vec::new();
    inner.extend(push_u64(frozen));
    inner.extend(push1(0));
    inner.push(0xda); // FREEZEBALANCEV2
    inner.push(0x50);
    inner.push(0x00); // STOP
    install_contract(&stores, inner_addr, inner, 100_000_000);

    // MIDDLE: CALL inner (succeeds), then REVERT (discards inner's subtree).
    let mut middle = Vec::new();
    middle.extend(push1(0)); // outLen
    middle.extend(push1(0)); // outOffset
    middle.extend(push1(0)); // inLen
    middle.extend(push1(0)); // inOffset
    middle.extend(push1(0)); // value
    middle.push(0x73); // PUSH20 inner
    middle.extend_from_slice(&inner_evm);
    middle.extend(push_u64(300_000)); // gas
    middle.push(0xf1); // CALL inner
    middle.push(0x50); // POP success
    middle.extend(push1(0)); // REVERT len
    middle.extend(push1(0)); // REVERT offset
    middle.push(0xfd); // REVERT → discards the whole subtree
    install_contract(&stores, middle_addr, middle, 0);

    install_contract(&stores, outer_addr, outer_calls_then_succeeds(middle_evm, 500_000), 0);
    install_caller(&stores, caller_user, 100_000_000);

    let outcome = execute_trigger(
        &stores,
        VmBlockEnv { block_number: 1, block_timestamp_ms: 1_700_000_000_000, ..Default::default()},
        &trigger(caller_user, outer_addr),
        3_000_000,
    );
    assert!(matches!(outcome, VmOutcome::Success { .. }), "outer must succeed: {outcome:?}");

    let inner_acct = stores
        .accounts
        .get(&Address::from_raw(inner_addr))
        .unwrap()
        .unwrap();
    assert!(
        inner_acct.frozen_v2.iter().all(|f| f.amount == 0),
        "ancestor revert must discard the descendant's committed freeze: {:?}",
        inner_acct.frozen_v2
    );
    assert_eq!(inner_acct.balance, 100_000_000, "ancestor revert must restore the balance");
    assert_eq!(
        stores.dynamic_properties.total_net_weight(),
        0,
        "ancestor revert must restore TOTAL_NET_WEIGHT"
    );
}

/// Control: the SAME inner staking op, but the inner frame SUCCEEDS (STOP
/// instead of REVERT). The freeze MUST persist and the global weight MUST move
/// — proving the fix only suppresses the REVERTED-frame writes, not legitimate
/// committed ones.
#[test]
fn inner_frame_success_still_commits_freeze_v2() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0xa4);
    let outer_addr = tron_addr(0xc4);
    let inner_addr = tron_addr(0xb4);
    let inner_evm: [u8; 20] = inner_addr[1..].try_into().unwrap();

    let frozen = 10_000_000u64;
    let mut inner = Vec::new();
    inner.extend(push_u64(frozen));
    inner.extend(push1(0));
    inner.push(0xda); // FREEZEBALANCEV2
    inner.push(0x50);
    inner.push(0x00); // STOP → inner SUCCEEDS
    install_contract(&stores, inner_addr, inner, 100_000_000);

    install_contract(&stores, outer_addr, outer_calls_then_succeeds(inner_evm, 400_000), 0);
    install_caller(&stores, caller_user, 100_000_000);

    let outcome = execute_trigger(
        &stores,
        VmBlockEnv { block_number: 1, block_timestamp_ms: 1_700_000_000_000, ..Default::default()},
        &trigger(caller_user, outer_addr),
        2_000_000,
    );
    assert!(matches!(outcome, VmOutcome::Success { .. }), "outer must succeed: {outcome:?}");

    let inner_acct = stores
        .accounts
        .get(&Address::from_raw(inner_addr))
        .unwrap()
        .unwrap();
    let held: i64 = inner_acct.frozen_v2.iter().filter(|f| f.r#type == 0).map(|f| f.amount).sum();
    assert_eq!(held, frozen as i64, "committed inner-frame freeze must persist");
    assert_eq!(
        inner_acct.balance,
        100_000_000 - frozen as i64,
        "committed inner-frame freeze must debit balance"
    );
    assert_eq!(
        stores.dynamic_properties.total_net_weight(),
        frozen as i64 / 1_000_000,
        "committed inner-frame freeze must move TOTAL_NET_WEIGHT"
    );
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
            block_timestamp_ms: 1_700_000_000_000, ..Default::default()
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
            block_timestamp_ms: 1_700_000_000_000, ..Default::default()
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
            block_timestamp_ms: now, ..Default::default()
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
            block_timestamp_ms: 1_700_000_000_000, ..Default::default()
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
            block_timestamp_ms: 1_700_000_000_000, ..Default::default()
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
            block_timestamp_ms: 1_700_000_000_000, ..Default::default()
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

/// java `setFrozenForEnergy` writes `accountResource.frozenBalanceForEnergy` —
/// NOT the legacy `frozen` list, which belongs to BANDWIDTH alone. Only
/// TOTAL_ENERGY_WEIGHT moves.
#[test]
fn freeze_v1_self_energy_writes_account_resource_slot() {
    let stores = fresh_stores_pre_stake2();
    let caller_user = tron_addr(0xb1);
    let contract_addr = tron_addr(0xf1);

    let bc = freeze_v1_code(contract_addr, push_u64(10_000_000), push1(1));
    install_contract_with(
        &stores,
        contract_addr,
        bc,
        Account {
            balance: 50_000_000,
            ..Default::default()
        },
    );
    run_contract(&stores, caller_user, contract_addr);

    let acct = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    assert_eq!(pushed_flag(&stores, contract_addr), 1);
    assert_eq!(energy_frozen(&acct), Some(frozen(10_000_000, V1_EXPIRE)));
    assert!(
        acct.frozen.is_empty(),
        "an ENERGY freeze must not write the bandwidth frozen list"
    );
    assert_eq!(acct.balance, 40_000_000);
    assert_eq!(stores.dynamic_properties.total_energy_weight(), 10);
    assert_eq!(stores.dynamic_properties.total_net_weight(), 0);
}

/// `setFrozenForBandwidth(frozenBalance + getFrozenBalance(), expireTime)`
/// REPLACES entry 0 rather than appending, so a second freeze leaves exactly
/// one entry carrying the summed balance and the new expiry.
#[test]
fn freeze_v1_self_bandwidth_twice_overwrites_entry_zero() {
    let stores = fresh_stores_pre_stake2();
    let caller_user = tron_addr(0xb2);
    let contract_addr = tron_addr(0xf2);

    // Two back-to-back FREEZEs, each SSTOREing its flag over slot 0.
    let mut bc = freeze_v1_code(contract_addr, push_u64(10_000_000), push1(0));
    bc.truncate(bc.len() - 1); // drop the trailing STOP
    bc.extend(freeze_v1_code(contract_addr, push_u64(4_000_000), push1(0)));
    install_contract_with(
        &stores,
        contract_addr,
        bc,
        Account {
            balance: 50_000_000,
            ..Default::default()
        },
    );
    run_contract(&stores, caller_user, contract_addr);

    let acct = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    assert_eq!(pushed_flag(&stores, contract_addr), 1);
    assert_eq!(
        acct.frozen,
        vec![frozen(14_000_000, V1_EXPIRE)],
        "the second freeze merges into entry 0 instead of appending"
    );
    assert_eq!(acct.balance, 36_000_000);
    assert_eq!(stores.dynamic_properties.total_net_weight(), 14);
}

/// `FreezeBalanceProcessor.validate`'s ResourceCode switch accepts BANDWIDTH
/// and ENERGY only — TRON_POWER(2) is a Stake-2.0 code and throws here.
#[test]
fn freeze_v1_rejects_tron_power_resource_code() {
    let stores = fresh_stores_pre_stake2();
    let caller_user = tron_addr(0xb3);
    let contract_addr = tron_addr(0xf3);

    let bc = freeze_v1_code(contract_addr, push_u64(10_000_000), push1(2));
    install_contract_with(
        &stores,
        contract_addr,
        bc,
        Account {
            balance: 50_000_000,
            ..Default::default()
        },
    );
    run_contract(&stores, caller_user, contract_addr);

    let acct = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    assert_eq!(pushed_flag(&stores, contract_addr), 0);
    assert!(acct.frozen.is_empty());
    assert_eq!(energy_frozen(&acct), None);
    assert_eq!(acct.balance, 50_000_000);
    assert_eq!(stores.dynamic_properties.total_net_weight(), 0);
    assert_eq!(stores.dynamic_properties.total_energy_weight(), 0);
}

/// `frozenBalance.sValue().longValueExact()` (Program.java:1947) throws on a
/// word outside signed-64 range and the opcode pushes 0. A truncating read
/// would see the low 64 bits (1000 TRX here) and freeze for real.
#[test]
fn freeze_v1_rejects_balance_above_i64() {
    let stores = fresh_stores_pre_stake2();
    let caller_user = tron_addr(0xb4);
    let contract_addr = tron_addr(0xf4);

    // 2^64 + 1_000_000_000 — low limb 1e9, high limb 1.
    let mut word = [0u8; 32];
    word[15] = 1;
    word[24..].copy_from_slice(&1_000_000_000u64.to_be_bytes());
    let bc = freeze_v1_code(contract_addr, push_u256(word), push1(0));
    install_contract_with(
        &stores,
        contract_addr,
        bc,
        Account {
            balance: 50_000_000_000,
            ..Default::default()
        },
    );
    run_contract(&stores, caller_user, contract_addr);

    let acct = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    assert_eq!(pushed_flag(&stores, contract_addr), 0);
    assert!(acct.frozen.is_empty());
    assert_eq!(acct.balance, 50_000_000_000);
    assert_eq!(stores.dynamic_properties.total_net_weight(), 0);
}

/// "FrozenCount must be 0 or 1" — an owner whose legacy `frozen` list already
/// holds two entries is rejected outright.
#[test]
fn freeze_v1_rejects_owner_with_two_frozen_entries() {
    let stores = fresh_stores_pre_stake2();
    let caller_user = tron_addr(0xb5);
    let contract_addr = tron_addr(0xf5);

    let bc = freeze_v1_code(contract_addr, push_u64(10_000_000), push1(0));
    let seeded = vec![
        frozen(1_000_000, NOW_MS + 1),
        frozen(2_000_000, NOW_MS + 2),
    ];
    install_contract_with(
        &stores,
        contract_addr,
        bc,
        Account {
            balance: 50_000_000,
            frozen: seeded.clone(),
            ..Default::default()
        },
    );
    run_contract(&stores, caller_user, contract_addr);

    let acct = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    assert_eq!(pushed_flag(&stores, contract_addr), 0);
    assert_eq!(acct.frozen, seeded);
    assert_eq!(acct.balance, 50_000_000);
    assert_eq!(stores.dynamic_properties.total_net_weight(), 0);
}

/// The delegating branch: a receiver that differs from the owner gets a
/// `DelegatedResource` row keyed `from || to`, an auto-created account row
/// (`repo.createNormalAccount`) and the acquired credit, while the owner is
/// debited and books `delegatedFrozenBalanceForBandwidth`. The weight switch
/// sits outside the branch, so TOTAL_NET_WEIGHT moves here too.
#[test]
fn freeze_v1_delegated_bandwidth_creates_row_and_receiver() {
    let stores = fresh_stores_pre_stake2();
    let caller_user = tron_addr(0xb6);
    let contract_addr = tron_addr(0xf6);
    let receiver = tron_addr(0x16);

    let bc = freeze_v1_code(receiver, push_u64(10_000_000), push1(0));
    install_contract_with(
        &stores,
        contract_addr,
        bc,
        Account {
            balance: 50_000_000,
            ..Default::default()
        },
    );
    run_contract(&stores, caller_user, contract_addr);

    assert_eq!(pushed_flag(&stores, contract_addr), 1);
    let key = DelegatedResourceStore::v1_key(
        &Address::from_raw(contract_addr),
        &Address::from_raw(receiver),
    );
    let record = stores
        .delegated_resources
        .get_raw(&key)
        .unwrap()
        .expect("v1 DelegatedResource row written");
    assert_eq!(record.from, contract_addr.to_vec());
    assert_eq!(record.to, receiver.to_vec());
    assert_eq!(record.frozen_balance_for_bandwidth, 10_000_000);
    assert_eq!(record.expire_time_for_bandwidth, V1_EXPIRE);

    let owner = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    assert_eq!(owner.delegated_frozen_balance_for_bandwidth, 10_000_000);
    assert_eq!(owner.balance, 40_000_000);
    assert!(
        owner.frozen.is_empty(),
        "a delegating freeze never writes the owner's own frozen list"
    );

    let recv = stores
        .accounts
        .get(&Address::from_raw(receiver))
        .unwrap()
        .expect("receiver auto-created by createNormalAccount");
    assert_eq!(recv.acquired_delegated_frozen_balance_for_bandwidth, 10_000_000);
    assert_eq!(recv.create_time, NOW_MS);
    assert_eq!(stores.dynamic_properties.total_net_weight(), 10);
}

/// Same on the ENERGY fields, which live under `AccountResource`.
#[test]
fn freeze_v1_delegated_energy_credits_energy_fields() {
    let stores = fresh_stores_pre_stake2();
    let caller_user = tron_addr(0xb7);
    let contract_addr = tron_addr(0xf7);
    let receiver = tron_addr(0x17);

    let bc = freeze_v1_code(receiver, push_u64(10_000_000), push1(1));
    install_contract_with(
        &stores,
        contract_addr,
        bc,
        Account {
            balance: 50_000_000,
            ..Default::default()
        },
    );
    run_contract(&stores, caller_user, contract_addr);

    assert_eq!(pushed_flag(&stores, contract_addr), 1);
    let key = DelegatedResourceStore::v1_key(
        &Address::from_raw(contract_addr),
        &Address::from_raw(receiver),
    );
    let record = stores.delegated_resources.get_raw(&key).unwrap().unwrap();
    assert_eq!(record.frozen_balance_for_energy, 10_000_000);
    assert_eq!(record.expire_time_for_energy, V1_EXPIRE);
    assert_eq!(record.frozen_balance_for_bandwidth, 0);

    let owner = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    assert_eq!(
        owner
            .account_resource
            .as_ref()
            .unwrap()
            .delegated_frozen_balance_for_energy,
        10_000_000
    );
    let recv = stores
        .accounts
        .get(&Address::from_raw(receiver))
        .unwrap()
        .unwrap();
    assert_eq!(
        recv.account_resource
            .as_ref()
            .unwrap()
            .acquired_delegated_frozen_balance_for_energy,
        10_000_000
    );
    assert_eq!(stores.dynamic_properties.total_energy_weight(), 10);
    assert_eq!(stores.dynamic_properties.total_net_weight(), 0);
}

/// "Do not allow delegate resources to contract addresses" — and, because java
/// validates inside a child Repository committed only on success, the receiver
/// account its own delegation branch may have created is discarded with it.
/// Nothing at all may be written.
#[test]
fn freeze_v1_delegated_to_contract_receiver_writes_nothing() {
    let stores = fresh_stores_pre_stake2();
    let caller_user = tron_addr(0xb8);
    let contract_addr = tron_addr(0xf8);
    let receiver = tron_addr(0x18);

    let bc = freeze_v1_code(receiver, push_u64(10_000_000), push1(0));
    install_contract_with(
        &stores,
        contract_addr,
        bc,
        Account {
            balance: 50_000_000,
            ..Default::default()
        },
    );
    let receiver_row = Account {
        address: receiver.to_vec(),
        r#type: tron_proto::AccountType::Contract as i32,
        balance: 123,
        ..Default::default()
    };
    put_account(&stores, receiver, receiver_row.clone());
    run_contract(&stores, caller_user, contract_addr);

    assert_eq!(pushed_flag(&stores, contract_addr), 0);
    let key = DelegatedResourceStore::v1_key(
        &Address::from_raw(contract_addr),
        &Address::from_raw(receiver),
    );
    assert!(stores.delegated_resources.get_raw(&key).unwrap().is_none());
    let owner = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    assert_eq!(owner.balance, 50_000_000);
    assert_eq!(owner.delegated_frozen_balance_for_bandwidth, 0);
    assert_eq!(
        stores
            .accounts
            .get(&Address::from_raw(receiver))
            .unwrap()
            .unwrap(),
        receiver_row,
        "the rejected receiver row must be byte-identical"
    );
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

/// SELF unfreeze — the receiver on the stack IS the executing contract, so
/// java's `!isEqual(ownerAddress, receiverAddress)` is false and
/// `UnfreezeBalanceProcessor` takes the non-delegating branch: every matured
/// entry leaves the legacy `frozen` list, its balance is credited, and
/// TOTAL_NET_WEIGHT sheds the corresponding weight.
#[test]
fn unfreeze_v1_self_clears_matured_frozen_entries() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0xa8);
    let contract_addr = tron_addr(0xc8);

    let bc = unfreeze_v1_code(contract_addr, push1(0));
    install_contract_with(
        &stores,
        contract_addr,
        bc,
        Account {
            balance: 0,
            frozen: vec![frozen(5_000_000, NOW_MS - 1)],
            ..Default::default()
        },
    );
    stores.dynamic_properties.save_total_net_weight(5);
    run_contract(&stores, caller_user, contract_addr);

    let acct = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    assert_eq!(pushed_flag(&stores, contract_addr), 1);
    assert!(acct.frozen.is_empty());
    assert_eq!(acct.balance, 5_000_000, "unlocked stake credited to balance");
    assert_eq!(stores.dynamic_properties.total_net_weight(), 0);
}

/// DELEGATED unfreeze with no `DelegatedResource` row — the receiver on the
/// stack differs from the executing contract, so java sets `delegating` and
/// `UnfreezeBalanceProcessor.validate` throws "delegated Resource does not
/// exist" before `execute` runs. The opcode pushes 0 and the owner's own
/// matured `frozen` entry is NOT swept: it belongs to the self branch java
/// never reaches.
#[test]
fn unfreeze_v1_delegated_without_record_is_rejected() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0xa8);
    let contract_addr = tron_addr(0xc8);
    let receiver = tron_addr(0xd8);

    let bc = unfreeze_v1_code(receiver, push1(0));
    install_contract_with(
        &stores,
        contract_addr,
        bc,
        Account {
            balance: 0,
            frozen: vec![frozen(5_000_000, NOW_MS - 1)],
            ..Default::default()
        },
    );
    stores.dynamic_properties.save_total_net_weight(5);
    run_contract(&stores, caller_user, contract_addr);

    let acct = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    assert_eq!(pushed_flag(&stores, contract_addr), 0);
    assert_eq!(
        acct.frozen,
        vec![frozen(5_000_000, NOW_MS - 1)],
        "the self-branch sweep must not run on the delegating branch"
    );
    assert_eq!(acct.balance, 0);
    assert_eq!(stores.dynamic_properties.total_net_weight(), 5);
}

/// ENERGY unfreeze reads `accountResource.frozenBalanceForEnergy` and clears
/// it, crediting the balance and shedding TOTAL_ENERGY_WEIGHT.
#[test]
fn unfreeze_v1_self_energy_clears_account_resource_slot() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0xa4);
    let contract_addr = tron_addr(0xc4);

    let bc = unfreeze_v1_code(contract_addr, push1(1));
    install_contract_with(
        &stores,
        contract_addr,
        bc,
        Account {
            balance: 0,
            account_resource: Some(tron_proto::account::AccountResource {
                frozen_balance_for_energy: Some(frozen(7_000_000, NOW_MS - 1)),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    stores.dynamic_properties.save_total_energy_weight(7);
    run_contract(&stores, caller_user, contract_addr);

    let acct = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    assert_eq!(pushed_flag(&stores, contract_addr), 1);
    assert_eq!(energy_frozen(&acct), None);
    assert_eq!(acct.balance, 7_000_000);
    assert_eq!(stores.dynamic_properties.total_energy_weight(), 0);
}

/// The ENERGY branch's maturity check: an unexpired `frozenBalanceForEnergy`
/// makes `validate` throw "It's not time to unfreeze(Energy)".
#[test]
fn unfreeze_v1_self_energy_rejects_unexpired_stake() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0xa5);
    let contract_addr = tron_addr(0xc5);

    let bc = unfreeze_v1_code(contract_addr, push1(1));
    install_contract_with(
        &stores,
        contract_addr,
        bc,
        Account {
            balance: 0,
            account_resource: Some(tron_proto::account::AccountResource {
                frozen_balance_for_energy: Some(frozen(7_000_000, NOW_MS + 1)),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    stores.dynamic_properties.save_total_energy_weight(7);
    run_contract(&stores, caller_user, contract_addr);

    let acct = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    assert_eq!(pushed_flag(&stores, contract_addr), 0);
    assert_eq!(energy_frozen(&acct), Some(frozen(7_000_000, NOW_MS + 1)));
    assert_eq!(acct.balance, 0);
    assert_eq!(stores.dynamic_properties.total_energy_weight(), 7);
}

/// An ENERGY unfreeze must never touch the legacy BANDWIDTH `frozen` list.
/// java's ENERGY arm reads only `frozenBalanceForEnergy`, so an owner holding
/// nothing but a matured bandwidth entry fails validate with "no
/// frozenBalance(Energy)" and keeps that entry.
#[test]
fn unfreeze_v1_energy_leaves_matured_bandwidth_entry_alone() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0xa7);
    let contract_addr = tron_addr(0xc7);

    let bc = unfreeze_v1_code(contract_addr, push1(1));
    install_contract_with(
        &stores,
        contract_addr,
        bc,
        Account {
            balance: 0,
            frozen: vec![frozen(5_000_000, NOW_MS - 1)],
            ..Default::default()
        },
    );
    stores.dynamic_properties.save_total_net_weight(5);
    stores.dynamic_properties.save_total_energy_weight(9);
    run_contract(&stores, caller_user, contract_addr);

    let acct = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    assert_eq!(pushed_flag(&stores, contract_addr), 0);
    assert_eq!(acct.frozen, vec![frozen(5_000_000, NOW_MS - 1)]);
    assert_eq!(acct.balance, 0);
    assert_eq!(stores.dynamic_properties.total_net_weight(), 5);
    assert_eq!(
        stores.dynamic_properties.total_energy_weight(),
        9,
        "a bandwidth stake must never be charged against energy weight"
    );
}

/// java's v1 processors accept only BANDWIDTH(0) and ENERGY(1); both the
/// delegating and self branches of `UnfreezeBalanceProcessor.validate` end in
/// `default: throw new ContractValidateException("Unknown ResourceCode, ...")`.
#[test]
fn unfreeze_v1_rejects_unknown_resource_code() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0xab);
    let contract_addr = tron_addr(0xcb);

    let bc = unfreeze_v1_code(contract_addr, push1(7));
    install_contract_with(
        &stores,
        contract_addr,
        bc,
        Account {
            balance: 0,
            frozen: vec![frozen(5_000_000, NOW_MS - 1)],
            ..Default::default()
        },
    );
    stores.dynamic_properties.save_total_net_weight(5);
    run_contract(&stores, caller_user, contract_addr);

    let acct = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    assert_eq!(pushed_flag(&stores, contract_addr), 0);
    assert_eq!(acct.frozen, vec![frozen(5_000_000, NOW_MS - 1)]);
    assert_eq!(acct.balance, 0);
    assert_eq!(stores.dynamic_properties.total_net_weight(), 5);
}

/// DELEGATED unfreeze against a matured row: the row's per-type balance and
/// expiry are zeroed, the owner's `delegatedFrozenBalanceForBandwidth` is
/// debited and its TRX balance credited, and the receiver's acquired balance is
/// reduced — clamped at 0 by
/// `safeAddAcquiredDelegatedFrozenBalanceForBandwidth`, which is why a receiver
/// holding less than the row's balance floors instead of going negative.
#[test]
fn unfreeze_v1_delegated_zeroes_row_and_clamps_receiver() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0xac);
    let contract_addr = tron_addr(0xcc);
    let receiver = tron_addr(0xdc);

    let bc = unfreeze_v1_code(receiver, push1(0));
    install_contract_with(
        &stores,
        contract_addr,
        bc,
        Account {
            balance: 0,
            delegated_frozen_balance_for_bandwidth: 6_000_000,
            ..Default::default()
        },
    );
    // Receiver holds LESS acquired than the row delegates (java's clamp case).
    put_account(
        &stores,
        receiver,
        Account {
            address: receiver.to_vec(),
            acquired_delegated_frozen_balance_for_bandwidth: 2_000_000,
            ..Default::default()
        },
    );
    let key = DelegatedResourceStore::v1_key(
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
                frozen_balance_for_bandwidth: 6_000_000,
                expire_time_for_bandwidth: NOW_MS - 1,
                ..Default::default()
            },
        )
        .unwrap();
    stores.dynamic_properties.save_total_net_weight(6);
    run_contract(&stores, caller_user, contract_addr);

    assert_eq!(pushed_flag(&stores, contract_addr), 1);
    let record = stores.delegated_resources.get_raw(&key).unwrap().unwrap();
    assert_eq!(record.frozen_balance_for_bandwidth, 0);
    assert_eq!(record.expire_time_for_bandwidth, 0);

    let owner = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    assert_eq!(owner.delegated_frozen_balance_for_bandwidth, 0);
    assert_eq!(owner.balance, 6_000_000);

    let recv = stores
        .accounts
        .get(&Address::from_raw(receiver))
        .unwrap()
        .unwrap();
    assert_eq!(
        recv.acquired_delegated_frozen_balance_for_bandwidth, 0,
        "safeAdd clamps at 0 rather than going negative"
    );
    assert_eq!(stores.dynamic_properties.total_net_weight(), 0);
}

/// An unexpired delegated row fails validate with "It's not time to
/// unfreeze(BANDWIDTH)" — nothing moves.
#[test]
fn unfreeze_v1_delegated_rejects_unexpired_row() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0xad);
    let contract_addr = tron_addr(0xcd);
    let receiver = tron_addr(0xdd);

    let bc = unfreeze_v1_code(receiver, push1(0));
    install_contract_with(
        &stores,
        contract_addr,
        bc,
        Account {
            balance: 0,
            delegated_frozen_balance_for_bandwidth: 6_000_000,
            ..Default::default()
        },
    );
    put_account(
        &stores,
        receiver,
        Account {
            address: receiver.to_vec(),
            acquired_delegated_frozen_balance_for_bandwidth: 6_000_000,
            ..Default::default()
        },
    );
    let key = DelegatedResourceStore::v1_key(
        &Address::from_raw(contract_addr),
        &Address::from_raw(receiver),
    );
    let row = tron_proto::DelegatedResource {
        from: contract_addr.to_vec(),
        to: receiver.to_vec(),
        frozen_balance_for_bandwidth: 6_000_000,
        expire_time_for_bandwidth: NOW_MS + 1,
        ..Default::default()
    };
    stores.delegated_resources.put_raw(&key, &row).unwrap();
    stores.dynamic_properties.save_total_net_weight(6);
    run_contract(&stores, caller_user, contract_addr);

    assert_eq!(pushed_flag(&stores, contract_addr), 0);
    assert_eq!(stores.delegated_resources.get_raw(&key).unwrap().unwrap(), row);
    let owner = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    assert_eq!(owner.delegated_frozen_balance_for_bandwidth, 6_000_000);
    assert_eq!(owner.balance, 0);
    assert_eq!(stores.dynamic_properties.total_net_weight(), 6);
}

/// `UnfreezeBalanceProcessor.execute`'s tail: under ALLOW_TVM_VOTE, an owner
/// whose remaining TRON Power no longer covers the votes it has cast has those
/// votes dropped and a `Votes` row written.
#[test]
fn unfreeze_v1_clears_votes_when_power_falls_below_used() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0xae);
    let contract_addr = tron_addr(0xce);
    let witness = tron_addr(0xee);

    let bc = unfreeze_v1_code(contract_addr, push1(0));
    install_contract_with(
        &stores,
        contract_addr,
        bc,
        Account {
            balance: 0,
            frozen: vec![frozen(5_000_000, NOW_MS - 1)],
            // 5 votes need 5 TRX of power; unfreezing leaves 0.
            votes: vec![tron_proto::Vote {
                vote_address: witness.to_vec(),
                vote_count: 5,
            }],
            ..Default::default()
        },
    );
    stores.dynamic_properties.save_total_net_weight(5);
    run_contract(&stores, caller_user, contract_addr);

    let acct = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    assert_eq!(pushed_flag(&stores, contract_addr), 1);
    assert!(acct.frozen.is_empty());
    assert!(acct.votes.is_empty(), "votes dropped once power no longer covers them");
    let row = stores
        .votes
        .as_ref()
        .unwrap()
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .expect("a Votes row records the cleared votes");
    assert_eq!(row.old_votes.len(), 1);
    assert!(row.new_votes.is_empty());
}

/// The negative half: TRON Power that still covers the cast votes leaves them
/// in place (java's `getTronPower() < usedTronPower * TRX_PRECISION` is false).
/// The remaining delegated-out stake keeps the power up.
#[test]
fn unfreeze_v1_keeps_votes_when_power_still_covers_them() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0xaf);
    let contract_addr = tron_addr(0xcf);
    let witness = tron_addr(0xef);

    let bc = unfreeze_v1_code(contract_addr, push1(0));
    install_contract_with(
        &stores,
        contract_addr,
        bc,
        Account {
            balance: 0,
            frozen: vec![frozen(5_000_000, NOW_MS - 1)],
            // Delegated-out stake still counts toward TRON Power.
            delegated_frozen_balance_for_bandwidth: 50_000_000,
            votes: vec![tron_proto::Vote {
                vote_address: witness.to_vec(),
                vote_count: 5,
            }],
            ..Default::default()
        },
    );
    stores.dynamic_properties.save_total_net_weight(55);
    run_contract(&stores, caller_user, contract_addr);

    let acct = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    assert_eq!(acct.votes.len(), 1, "votes survive while power covers them");
    assert!(stores
        .votes
        .as_ref()
        .unwrap()
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .is_none());
}

/// With ALLOW_TVM_VOTE off, java's whole vote-reconciliation block is skipped
/// regardless of how far the power fell.
#[test]
fn unfreeze_v1_keeps_votes_when_tvm_vote_is_off() {
    let stores = fresh_stores();
    stores.dynamic_properties.put_long(b"ALLOW_TVM_VOTE", 0);
    let caller_user = tron_addr(0xa3);
    let contract_addr = tron_addr(0xc3);
    let witness = tron_addr(0xe3);

    let bc = unfreeze_v1_code(contract_addr, push1(0));
    install_contract_with(
        &stores,
        contract_addr,
        bc,
        Account {
            balance: 0,
            frozen: vec![frozen(5_000_000, NOW_MS - 1)],
            votes: vec![tron_proto::Vote {
                vote_address: witness.to_vec(),
                vote_count: 5,
            }],
            ..Default::default()
        },
    );
    stores.dynamic_properties.save_total_net_weight(5);
    run_contract(&stores, caller_user, contract_addr);

    let acct = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    assert!(acct.frozen.is_empty());
    assert_eq!(acct.votes.len(), 1, "vote reconciliation is ALLOW_TVM_VOTE-gated");
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
            block_timestamp_ms: 1_700_000_000_000, ..Default::default()
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

/// Build the standard DELEGATERESOURCE contract: push [receiver, balance,
/// resource] and run 0xde, then SSTORE the result and STOP.
fn delegate_contract_bytecode(receiver: [u8; 21], amount: u64, resource: u8) -> Vec<u8> {
    let mut bc = Vec::new();
    bc.push(0x73);
    bc.extend_from_slice(&receiver[1..]);
    bc.extend(push_u64(amount));
    bc.extend(push1(resource));
    bc.push(0xde);
    bc.extend(push1(0));
    bc.push(0x55);
    bc.push(0x00);
    bc
}

/// java `DelegateResourceProcessor.validate` (DelegateResourceProcessor.java:53):
/// `delegateBalance < TRX_PRECISION` (1 TRX = 1_000_000 sun) is rejected → the
/// opcode reverts (pushes 0) with NO state mutation.
#[test]
fn delegate_resource_rejects_balance_below_one_trx() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0xa8);
    let contract_addr = tron_addr(0xc8);
    let receiver = tron_addr(0xd8);

    let amount = 999_999u64; // one sun below 1 TRX
    let bc = delegate_contract_bytecode(receiver, amount, 0);
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
                frozen_v2: vec![tron_proto::account::FreezeV2 { r#type: 0, amount: 10_000_000 }],
                ..Default::default()
            },
        )
        .unwrap();
    stores
        .accounts
        .put(
            &Address::from_raw(receiver),
            &Account { address: receiver.to_vec(), ..Default::default() },
        )
        .unwrap();
    install_caller(&stores, caller_user, 1_000_000_000);

    let outcome = execute_trigger(
        &stores,
        VmBlockEnv { block_number: 1, block_timestamp_ms: 1_700_000_000_000, ..Default::default()},
        &trigger(caller_user, contract_addr),
        500_000,
    );
    assert!(matches!(outcome, VmOutcome::Success { .. }), "got {outcome:?}");
    // No mutation: owner FreezeV2 untouched, no DelegatedResource row.
    let owner = stores.accounts.get(&Address::from_raw(contract_addr)).unwrap().unwrap();
    assert_eq!(
        owner.frozen_v2.iter().find(|f| f.r#type == 0).unwrap().amount,
        10_000_000,
        "a sub-1-TRX delegate must not debit the owner FreezeV2"
    );
    assert_eq!(owner.delegated_frozen_v2_balance_for_bandwidth, 0);
    let key = tron_chainbase::DelegatedResourceStore::v2_unlocked_key(
        &Address::from_raw(contract_addr),
        &Address::from_raw(receiver),
    );
    assert!(
        stores.delegated_resources.get_raw(&key).unwrap().is_none(),
        "a sub-1-TRX delegate must not write a DelegatedResource row"
    );
}

/// java `DelegateResourceProcessor.validate` (DelegateResourceProcessor.java:111):
/// delegating to a contract-type receiver is rejected → revert, no mutation.
#[test]
fn delegate_resource_rejects_contract_receiver() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0xa7);
    let contract_addr = tron_addr(0xc7);
    let receiver = tron_addr(0xd7);

    let amount = 3_000_000u64; // >= 1 TRX, so only the receiver-type check can reject
    let bc = delegate_contract_bytecode(receiver, amount, 0);
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
                frozen_v2: vec![tron_proto::account::FreezeV2 { r#type: 0, amount: 10_000_000 }],
                ..Default::default()
            },
        )
        .unwrap();
    // Receiver is a CONTRACT-type account → java rejects.
    stores
        .accounts
        .put(
            &Address::from_raw(receiver),
            &Account {
                address: receiver.to_vec(),
                r#type: tron_proto::AccountType::Contract as i32,
                ..Default::default()
            },
        )
        .unwrap();
    install_caller(&stores, caller_user, 1_000_000_000);

    let outcome = execute_trigger(
        &stores,
        VmBlockEnv { block_number: 1, block_timestamp_ms: 1_700_000_000_000, ..Default::default()},
        &trigger(caller_user, contract_addr),
        500_000,
    );
    assert!(matches!(outcome, VmOutcome::Success { .. }), "got {outcome:?}");
    let owner = stores.accounts.get(&Address::from_raw(contract_addr)).unwrap().unwrap();
    assert_eq!(
        owner.frozen_v2.iter().find(|f| f.r#type == 0).unwrap().amount,
        10_000_000,
        "delegating to a contract receiver must not debit the owner FreezeV2"
    );
    let key = tron_chainbase::DelegatedResourceStore::v2_unlocked_key(
        &Address::from_raw(contract_addr),
        &Address::from_raw(receiver),
    );
    assert!(
        stores.delegated_resources.get_raw(&key).unwrap().is_none(),
        "delegating to a contract receiver must not write a DelegatedResource row"
    );
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
            block_timestamp_ms: 1_700_000_000_000, ..Default::default()
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
            block_timestamp_ms: 1_700_000_000_000, ..Default::default()
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

// =============================================================================
// DelegatedResourceAccountIndex maintenance (RPC-only, java parity)
// =============================================================================
//
// The DELEGATERESOURCE / UNDELEGATERESOURCE opcode bridges keep the
// bidirectional `DelegatedResourceAccountIndex` rows in sync with java-tron's
// `DelegateResourceProcessor` / `UnDelegateResourceProcessor`. The index is
// RPC-only — never read into any balance/usage/energy/consensus computation —
// so it is wired through the executor's session-wrapped store, NOT the staking
// journal. These tests prove the bridge writes/clears both V2 rows and that a
// setup WITHOUT the index store attached is a silent no-op (no panic).

/// An in-VM DELEGATERESOURCE writes BOTH V2 index rows, each stamped with the
/// latest block-header timestamp and pointing at the counterparty — matching
/// java `DelegateResourceProcessor.delegateResource`'s `delegateV2(...)`.
#[test]
fn delegate_resource_writes_both_index_rows() {
    let (stores, index) = fresh_stores_with_index();
    let caller_user = tron_addr(0xa9);
    let contract_addr = tron_addr(0xc9);
    let receiver = tron_addr(0xd9);

    let amount = 3_000_000u64;
    // DELEGATERESOURCE pops [resource_type, delegate_balance, receiver_address].
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
    stores
        .accounts
        .put(
            &Address::from_raw(contract_addr),
            &Account {
                address: contract_addr.to_vec(),
                code: bc.clone(),
                code_hash: hash.as_slice().to_vec(),
                frozen_v2: vec![tron_proto::account::FreezeV2 { r#type: 0, amount: 10_000_000 }],
                ..Default::default()
            },
        )
        .unwrap();
    stores
        .accounts
        .put(
            &Address::from_raw(receiver),
            &Account { address: receiver.to_vec(), ..Default::default() },
        )
        .unwrap();
    install_caller(&stores, caller_user, 1_000_000_000);

    let outcome = execute_trigger(
        &stores,
        VmBlockEnv { block_number: 1, block_timestamp_ms: 1_700_000_000_000, ..Default::default()},
        &trigger(caller_user, contract_addr),
        500_000,
    );
    assert!(matches!(outcome, VmOutcome::Success { .. }), "expected Success, got: {outcome:?}");

    let owner = Address::from_raw(contract_addr);
    let recv = Address::from_raw(receiver);
    // From-side row (0x03 ‖ owner ‖ receiver) holds the counterparty `receiver`,
    // stamped with the fixture's latest-block-header timestamp.
    let from_row = index
        .get_raw(&DelegatedResourceAccountIndexStore::v2_from_key(&owner, &recv))
        .unwrap()
        .expect("from-side index row written");
    assert_eq!(from_row.account, recv.as_bytes().to_vec());
    assert_eq!(from_row.timestamp, 1_700_000_000_000);
    // To-side row (0x04 ‖ receiver ‖ owner) holds `owner`.
    let to_row = index
        .get_raw(&DelegatedResourceAccountIndexStore::v2_to_key(&owner, &recv))
        .unwrap()
        .expect("to-side index row written");
    assert_eq!(to_row.account, owner.as_bytes().to_vec());
    assert_eq!(to_row.timestamp, 1_700_000_000_000);
}

/// An in-VM UNDELEGATERESOURCE that ZEROES the delegation record clears BOTH V2
/// index rows — matching java `UnDelegateResourceProcessor.execute`, which
/// overwrites both rows with an empty capsule (committed as a delete) once
/// `frozenBalanceForBandwidth == 0 && frozenBalanceForEnergy == 0`.
#[test]
fn undelegate_resource_clears_both_index_rows_when_record_zeroed() {
    let (stores, index) = fresh_stores_with_index();
    let caller_user = tron_addr(0xaa);
    let contract_addr = tron_addr(0xca);
    let receiver = tron_addr(0xda);

    let amount = 2_000_000u64;
    let mut bc = Vec::new();
    bc.push(0x73);
    bc.extend_from_slice(&receiver[1..]);
    bc.extend(push_u64(amount));
    bc.extend(push1(0)); // resource = BANDWIDTH
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
                delegated_frozen_v2_balance_for_bandwidth: amount as i64,
                ..Default::default()
            },
        )
        .unwrap();
    stores
        .accounts
        .put(
            &Address::from_raw(receiver),
            &Account {
                address: receiver.to_vec(),
                acquired_delegated_frozen_v2_balance_for_bandwidth: amount as i64,
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
                frozen_balance_for_bandwidth: amount as i64,
                ..Default::default()
            },
        )
        .unwrap();
    let owner = Address::from_raw(contract_addr);
    let recv = Address::from_raw(receiver);
    // Pre-seed the index rows as a prior delegate would have.
    index.delegate_v2(&owner, &recv, 1).unwrap();
    install_caller(&stores, caller_user, 1_000_000_000);

    let outcome = execute_trigger(
        &stores,
        VmBlockEnv { block_number: 1, block_timestamp_ms: 1_700_000_000_000, ..Default::default()},
        &trigger(caller_user, contract_addr),
        500_000,
    );
    assert!(matches!(outcome, VmOutcome::Success { .. }), "expected Success, got: {outcome:?}");

    // The record is now fully zero, so both index rows are gone.
    assert!(
        index
            .get_raw(&DelegatedResourceAccountIndexStore::v2_from_key(&owner, &recv))
            .unwrap()
            .is_none(),
        "from-side index row must be cleared"
    );
    assert!(
        index
            .get_raw(&DelegatedResourceAccountIndexStore::v2_to_key(&owner, &recv))
            .unwrap()
            .is_none(),
        "to-side index row must be cleared"
    );
}

/// CRUCIAL frame-revert-safety: the index writes must NOT reach the underlying
/// store when the VM frame they belong to reverts. The executor routes the
/// index store through the per-tx `VmSession` — a `SessionBackend` overlay that
/// is COMMITTED on `VmOutcome::Success` and DISCARDED (never committed) on a
/// revert/halt. This test exercises that exact mechanism directly: a delegate
/// written through a session-wrapped index store is invisible in the parent
/// store until commit, and stays invisible if the session is reverted instead
/// — proving the discard-on-revert path the executor depends on.
///
/// (The `execute_trigger` unit harness has no `VmSession`, so it cannot drive a
/// real VM-frame revert against a session-wrapped index — this asserts the
/// mechanism instead, as the test plan allows.)
#[test]
fn session_wrapped_index_discards_writes_on_revert_and_commits_on_success() {
    use tron_chainbase::SessionBackend;

    let from = Address::from_raw(tron_addr(0xaa));
    let to = Address::from_raw(tron_addr(0xbb));

    // ----- Frame REVERT: write through the session, never commit. -----
    let parent: Arc<dyn KvBackend> = mem();
    let session = Arc::new(SessionBackend::new(Arc::clone(&parent)));
    let index = DelegatedResourceAccountIndexStore::new(Arc::clone(&session) as _);
    index.delegate_v2(&from, &to, 1_234).unwrap();
    // The write is visible THROUGH the session overlay ...
    assert!(
        index
            .get_raw(&DelegatedResourceAccountIndexStore::v2_from_key(&from, &to))
            .unwrap()
            .is_some(),
        "delegate must be visible through the session overlay before revert"
    );
    // ... but NOT in the parent store, and discarding (revert = no commit)
    // leaves the parent untouched — exactly what a reverted VM frame does.
    session.revert();
    let parent_index = DelegatedResourceAccountIndexStore::new(Arc::clone(&parent));
    assert!(
        parent_index
            .get_raw(&DelegatedResourceAccountIndexStore::v2_from_key(&from, &to))
            .unwrap()
            .is_none(),
        "reverted VM frame must leave NO index row in the parent store"
    );
    assert!(
        parent_index
            .get_raw(&DelegatedResourceAccountIndexStore::v2_to_key(&from, &to))
            .unwrap()
            .is_none(),
        "reverted VM frame must leave NO index row in the parent store (to-side)"
    );

    // ----- Frame SUCCESS: write through a fresh session, then commit. -----
    let parent2: Arc<dyn KvBackend> = mem();
    let session2 = Arc::new(SessionBackend::new(Arc::clone(&parent2)));
    let index2 = DelegatedResourceAccountIndexStore::new(Arc::clone(&session2) as _);
    index2.delegate_v2(&from, &to, 1_234).unwrap();
    session2.commit().unwrap();
    let parent2_index = DelegatedResourceAccountIndexStore::new(Arc::clone(&parent2));
    let from_row = parent2_index
        .get_raw(&DelegatedResourceAccountIndexStore::v2_from_key(&from, &to))
        .unwrap()
        .expect("committed VM frame must persist the from-side index row");
    assert_eq!(from_row.account, to.as_bytes().to_vec());
    let to_row = parent2_index
        .get_raw(&DelegatedResourceAccountIndexStore::v2_to_key(&from, &to))
        .unwrap()
        .expect("committed VM frame must persist the to-side index row");
    assert_eq!(to_row.account, from.as_bytes().to_vec());
}

/// When NO index store is attached (read-only / unit-test setups, `None`), an
/// in-VM DELEGATERESOURCE is a silent no-op for the index: the opcode still
/// succeeds and mutates the staking state, it simply skips the index write.
#[test]
fn delegate_resource_without_index_store_is_a_noop() {
    // Default `fresh_stores()` leaves `delegated_resource_account_index = None`.
    let stores = fresh_stores();
    assert!(stores.delegated_resource_account_index.is_none());
    let caller_user = tron_addr(0xa9);
    let contract_addr = tron_addr(0xc9);
    let receiver = tron_addr(0xd9);

    let amount = 3_000_000u64;
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
    stores
        .accounts
        .put(
            &Address::from_raw(contract_addr),
            &Account {
                address: contract_addr.to_vec(),
                code: bc.clone(),
                code_hash: hash.as_slice().to_vec(),
                frozen_v2: vec![tron_proto::account::FreezeV2 { r#type: 0, amount: 10_000_000 }],
                ..Default::default()
            },
        )
        .unwrap();
    stores
        .accounts
        .put(
            &Address::from_raw(receiver),
            &Account { address: receiver.to_vec(), ..Default::default() },
        )
        .unwrap();
    install_caller(&stores, caller_user, 1_000_000_000);

    let outcome = execute_trigger(
        &stores,
        VmBlockEnv { block_number: 1, block_timestamp_ms: 1_700_000_000_000, ..Default::default()},
        &trigger(caller_user, contract_addr),
        500_000,
    );
    // The opcode still succeeds and the delegation record/balances still move;
    // only the index write is skipped (no panic, no store handle to write to).
    assert!(matches!(outcome, VmOutcome::Success { .. }), "expected Success, got: {outcome:?}");
    let key = tron_chainbase::DelegatedResourceStore::v2_unlocked_key(
        &Address::from_raw(contract_addr),
        &Address::from_raw(receiver),
    );
    let record = stores
        .delegated_resources
        .get_raw(&key)
        .unwrap()
        .expect("DelegatedResource record still written without an index store");
    assert_eq!(record.frozen_balance_for_bandwidth, amount as i64);
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
            block_timestamp_ms: 1_700_000_000_000, ..Default::default()
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
            VmBlockEnv { block_number: 1, block_timestamp_ms: 1_700_000_000_000, ..Default::default()},
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
        VmBlockEnv { block_number: 1, block_timestamp_ms: 1_700_000_000_000, ..Default::default()},
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
        VmBlockEnv { block_number: 1, block_timestamp_ms: 1_700_000_000_000, ..Default::default()},
        &tr, 50_000_000) {
        VmOutcome::Success { energy_used, .. } => eprintln!("Factory withdraw energy = {energy_used}  (java=50408; 50411 => +3 reproduced)"),
        other => eprintln!("Factory outcome: {other:?}"),
    }
}

// =============================================================================
// Inner-frame-revert reward-settle leak (delegation store)
// =============================================================================
//
// The TVM reward-settle path (`VoteRewardUtil.withdrawReward`, reached by
// VOTEWITNESS / WITHDRAWREWARD / UNFREEZEBALANCEV2 / SELFDESTRUCT under
// ALLOW_TVM_VOTE) writes the voter's begin-cycle / end-cycle / account-vote
// rows straight into the `delegation` store. java scopes those to the frame's
// `RepositoryImpl.delegationCache`, flushed to the parent only on frame
// `commit()` and discarded on revert. Like the other staking bridges these
// writes BYPASS revm's journal, so without the staking-journal `Delegation`
// reverser an inner CALL frame that reverts (while the outer tx succeeds) would
// leak the begin/end-cycle + account-vote markers — silently shifting the
// voter's future reward window, invisible to the contractRet tripwire.
//
// These tests run at the VM level (no executor `VmSession`), so they isolate
// the per-frame journal mechanism. The companion whole-tx-revert path (the
// `VmSession.delegation` overlay) is covered in tron-executor's tests.

/// Seed `voter`'s delegation + account state so a WITHDRAWREWARD settle has a
/// finalised cycle to close out and therefore WRITES the three delegation rows
/// (`set_begin_cycle` / `set_end_cycle` / `set_account_vote`). Mirrors the
/// reward-cycle fixture in tron-executor's `rewards.rs`.
fn seed_reward_cycle(stores: &VmStores, voter: [u8; 21], witness: [u8; 21]) {
    use tron_proto::Vote;
    let dlg = &stores.delegation;
    // current cycle = 5; the witness's cycle-0 reward pool drives a nonzero
    // settle, and the voter's vote is in that pool.
    stores.dynamic_properties.put_long(b"CURRENT_CYCLE_NUMBER", 5);
    dlg.add_reward(0, &Address::from_raw(witness), 1_000_000_000);
    // A finalised Vi so `computeReward` has a positive delta to pay.
    dlg.set_witness_vi_raw(
        4,
        &Address::from_raw(witness),
        &tron_tvm::reward::encode_signed_be(2_000_000_000_000_000_000),
    );
    dlg.set_begin_cycle(&Address::from_raw(voter), 0);
    dlg.set_end_cycle(&Address::from_raw(voter), 1);
    dlg.set_account_vote(
        0,
        &Address::from_raw(voter),
        &Account {
            address: voter.to_vec(),
            votes: vec![Vote { vote_address: witness.to_vec(), vote_count: 100 }],
            ..Default::default()
        },
    )
    .unwrap();
}

/// Capture the three delegation rows the settle can touch, for a before/after
/// comparison. Reads the raw bytes so an absent row stays distinct from a zero.
fn delegation_row_bytes(stores: &VmStores, addr: [u8; 21]) -> (Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>) {
    let dlg = &stores.delegation;
    let a = Address::from_raw(addr);
    let begin = dlg.get_raw(&DelegationStore::begin_cycle_key(&a)).unwrap();
    let end = dlg.get_raw(&DelegationStore::end_cycle_key(&a)).unwrap();
    // The settle writes account_vote at the CURRENT cycle (5 in the fixture).
    let av = dlg.get_raw(&DelegationStore::account_vote_key(5, &a)).unwrap();
    (begin, end, av)
}

/// Build an inner contract that runs WITHDRAWREWARD (0xd9) then `tail`
/// (REVERT or STOP). The withdrawn amount is left on the stack and POPped.
fn withdraw_reward_then(tail: &[u8]) -> Vec<u8> {
    let mut bc = Vec::new();
    bc.push(0xd9); // WITHDRAWREWARD — settles for the executing contract
    bc.push(0x50); // POP the withdrawn amount
    bc.extend_from_slice(tail);
    bc
}

/// Regression: WITHDRAWREWARD inside an inner CALL frame that REVERTS must NOT
/// leak the begin/end-cycle + account-vote rows the settle writes — even though
/// the outer tx SUCCEEDS. Before the fix the bridge's direct delegation-store
/// writes survived the inner revert (revm's journal misses them and there is no
/// per-frame `VmSession`), shifting the voter's future reward window.
#[test]
fn inner_frame_revert_does_not_leak_withdraw_reward_delegation() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0xa7);
    let outer_addr = tron_addr(0xc7);
    let inner_addr = tron_addr(0xb7);
    let witness = tron_addr(0x77);
    let inner_evm: [u8; 20] = inner_addr[1..].try_into().unwrap();

    // INNER: WITHDRAWREWARD then REVERT(0,0).
    let mut tail = Vec::new();
    tail.extend(push1(0)); // REVERT len
    tail.extend(push1(0)); // REVERT offset
    tail.push(0xfd); // REVERT → inner frame fails
    install_contract(&stores, inner_addr, withdraw_reward_then(&tail), 0);
    install_contract(&stores, outer_addr, outer_calls_then_succeeds(inner_evm, 400_000), 0);
    install_caller(&stores, caller_user, 100_000_000);
    register_witness(&stores, witness);
    // The settle reads the inner contract's votes; give it the same vote.
    {
        let mut acct = stores.accounts.get(&Address::from_raw(inner_addr)).unwrap().unwrap();
        acct.votes = vec![tron_proto::Vote { vote_address: witness.to_vec(), vote_count: 100 }];
        stores.accounts.put(&Address::from_raw(inner_addr), &acct).unwrap();
    }
    seed_reward_cycle(&stores, inner_addr, witness);

    let before = delegation_row_bytes(&stores, inner_addr);

    let outcome = execute_trigger(
        &stores,
        VmBlockEnv { block_number: 1, block_timestamp_ms: 1_700_000_000_000, ..Default::default()},
        &trigger(caller_user, outer_addr),
        2_000_000,
    );
    assert!(
        matches!(outcome, VmOutcome::Success { .. }),
        "outer frame must SUCCEED (it ignores the inner revert), got: {outcome:?}"
    );

    let after = delegation_row_bytes(&stores, inner_addr);
    assert_eq!(
        before, after,
        "inner-frame WITHDRAWREWARD leaked delegation rows (begin/end-cycle/account-vote) past the revert"
    );
}

/// Control: the SAME WITHDRAWREWARD, but the inner frame SUCCEEDS (STOP). The
/// settle MUST persist its delegation writes — proving the fix only suppresses
/// the REVERTED-frame writes, not legitimate committed ones. After a successful
/// settle java advances begin_cycle to `current_cycle` (5) and writes the
/// account-vote snapshot at that cycle.
#[test]
fn inner_frame_success_still_commits_withdraw_reward_delegation() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0xa8);
    let outer_addr = tron_addr(0xc8);
    let inner_addr = tron_addr(0xb8);
    let witness = tron_addr(0x88);
    let inner_evm: [u8; 20] = inner_addr[1..].try_into().unwrap();

    // INNER: WITHDRAWREWARD then STOP → inner SUCCEEDS.
    install_contract(&stores, inner_addr, withdraw_reward_then(&[0x00]), 0);
    install_contract(&stores, outer_addr, outer_calls_then_succeeds(inner_evm, 400_000), 0);
    install_caller(&stores, caller_user, 100_000_000);
    register_witness(&stores, witness);
    {
        let mut acct = stores.accounts.get(&Address::from_raw(inner_addr)).unwrap().unwrap();
        acct.votes = vec![tron_proto::Vote { vote_address: witness.to_vec(), vote_count: 100 }];
        stores.accounts.put(&Address::from_raw(inner_addr), &acct).unwrap();
    }
    seed_reward_cycle(&stores, inner_addr, witness);

    let outcome = execute_trigger(
        &stores,
        VmBlockEnv { block_number: 1, block_timestamp_ms: 1_700_000_000_000, ..Default::default()},
        &trigger(caller_user, outer_addr),
        2_000_000,
    );
    assert!(matches!(outcome, VmOutcome::Success { .. }), "outer must succeed: {outcome:?}");

    let inner = Address::from_raw(inner_addr);
    // java's withdrawReward tail: begin_cycle = current (5), end_cycle = 6,
    // account_vote snapshot written at current cycle (5).
    assert_eq!(
        stores.delegation.get_begin_cycle(&inner),
        5,
        "committed WITHDRAWREWARD must advance begin_cycle to current_cycle"
    );
    assert_eq!(
        stores.delegation.get_end_cycle(&inner),
        6,
        "committed WITHDRAWREWARD must set end_cycle = current_cycle + 1"
    );
    assert!(
        stores.delegation.get_account_vote(5, &inner).unwrap().is_some(),
        "committed WITHDRAWREWARD must write the current-cycle account-vote snapshot"
    );
}

/// `register_witness`-equivalent local (this file has no `register_witness`).
fn register_witness(stores: &VmStores, addr: [u8; 21]) {
    stores
        .witnesses
        .put(
            &Address::from_raw(addr),
            &tron_proto::Witness { address: addr.to_vec(), ..Default::default() },
        )
        .unwrap();
}

// =============================================================================
// Stake-2.0 resource-code parsing (java `Program.parseResourceCodeV2`)
// =============================================================================
//
// The V2 opcodes read the resource code with `sValue().byteValueExact()`, so
// only an exact 0, 1 or 2 across all 256 bits is a code; anything else is
// UNRECOGNIZED and the processor's ResourceCode switch throws, leaving the
// opcode a nonce-bumped no-op that pushes 0. A low-32-bit truncation (which is
// what the *v1* opcodes correctly use, via `DataWord.intValue()`) would read
// several of these words as valid codes and stake for real.

/// FREEZEBALANCEV2 (0xda) with `resource_type = 2^32`: truncation would call it
/// BANDWIDTH.
#[test]
fn freezebalancev2_rejects_resource_type_above_32_bits() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0x21);
    let contract_addr = tron_addr(0x31);

    let mut word = [0u8; 32];
    word[27] = 1; // 1 << 32
    let mut bc = push_u64(10_000_000);
    bc.extend(push_u256(word));
    bc.push(0xda);
    bc.extend(push1(0));
    bc.push(0x55);
    bc.push(0x00);
    install_contract_with(
        &stores,
        contract_addr,
        bc,
        Account { balance: 100_000_000, ..Default::default() },
    );
    run_contract(&stores, caller_user, contract_addr);

    let acct = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    assert_eq!(pushed_flag(&stores, contract_addr), 0);
    assert!(acct.frozen_v2.iter().all(|f| f.amount == 0));
    assert_eq!(acct.balance, 100_000_000);
    assert_eq!(stores.dynamic_properties.total_net_weight(), 0);
}

/// `resource_type = 2^32 + 1`: truncation would call it ENERGY.
#[test]
fn freezebalancev2_rejects_resource_type_one_above_32_bits() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0x22);
    let contract_addr = tron_addr(0x32);

    let mut word = [0u8; 32];
    word[27] = 1;
    word[31] = 1; // (1 << 32) + 1
    let mut bc = push_u64(10_000_000);
    bc.extend(push_u256(word));
    bc.push(0xda);
    bc.extend(push1(0));
    bc.push(0x55);
    bc.push(0x00);
    install_contract_with(
        &stores,
        contract_addr,
        bc,
        Account { balance: 100_000_000, ..Default::default() },
    );
    run_contract(&stores, caller_user, contract_addr);

    let acct = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    assert_eq!(pushed_flag(&stores, contract_addr), 0);
    assert!(acct.frozen_v2.iter().all(|f| f.amount == 0));
    assert_eq!(acct.balance, 100_000_000);
    assert_eq!(stores.dynamic_properties.total_energy_weight(), 0);
}

/// `resource_type = …FF00000000` — a large NEGATIVE word under `sValue()`, so
/// `byteValueExact()` throws. Its low 32 bits are zero, so truncation would
/// call it BANDWIDTH.
#[test]
fn freezebalancev2_rejects_negative_resource_type_word() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0x23);
    let contract_addr = tron_addr(0x33);

    let mut word = [0xffu8; 32];
    word[28..].copy_from_slice(&[0, 0, 0, 0]);
    let mut bc = push_u64(10_000_000);
    bc.extend(push_u256(word));
    bc.push(0xda);
    bc.extend(push1(0));
    bc.push(0x55);
    bc.push(0x00);
    install_contract_with(
        &stores,
        contract_addr,
        bc,
        Account { balance: 100_000_000, ..Default::default() },
    );
    run_contract(&stores, caller_user, contract_addr);

    let acct = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    assert_eq!(pushed_flag(&stores, contract_addr), 0);
    assert!(acct.frozen_v2.iter().all(|f| f.amount == 0));
    assert_eq!(acct.balance, 100_000_000);
    assert_eq!(stores.dynamic_properties.total_net_weight(), 0);
}

/// DELEGATERESOURCE (0xde) parses its resource code the same way.
#[test]
fn delegateresource_rejects_resource_type_above_32_bits() {
    let stores = fresh_stores();
    let caller_user = tron_addr(0x24);
    let contract_addr = tron_addr(0x34);
    let receiver = tron_addr(0x44);

    let mut word = [0u8; 32];
    word[27] = 1;
    let mut bc = vec![0x73];
    bc.extend_from_slice(&receiver[1..]);
    bc.extend(push_u64(3_000_000));
    bc.extend(push_u256(word));
    bc.push(0xde);
    bc.extend(push1(0));
    bc.push(0x55);
    bc.push(0x00);
    install_contract_with(
        &stores,
        contract_addr,
        bc,
        Account {
            balance: 0,
            frozen_v2: vec![tron_proto::account::FreezeV2 { r#type: 0, amount: 10_000_000 }],
            ..Default::default()
        },
    );
    put_account(
        &stores,
        receiver,
        Account { address: receiver.to_vec(), ..Default::default() },
    );
    run_contract(&stores, caller_user, contract_addr);

    assert_eq!(pushed_flag(&stores, contract_addr), 0);
    let key = DelegatedResourceStore::v2_unlocked_key(
        &Address::from_raw(contract_addr),
        &Address::from_raw(receiver),
    );
    assert!(
        stores.delegated_resources.get_raw(&key).unwrap().is_none(),
        "an UNRECOGNIZED resource code must not write a delegation row"
    );
    let owner = stores
        .accounts
        .get(&Address::from_raw(contract_addr))
        .unwrap()
        .unwrap();
    assert_eq!(owner.frozen_v2[0].amount, 10_000_000);
}

// =============================================================================
// Internal-tx nonce on a rejected Stake-2.0 op
// =============================================================================
//
// java runs `increaseNonce()` ABOVE the try in every V2 stake method
// (Program.java:2035 / :2066 / :2176 / :2210), so an amount outside signed-64
// range — which makes `sValue().longValueExact()` throw — still advances the
// nonce. That nonce seeds `generateContractAddress(rootTransactionId, nonce)`
// (Program.java:807), so skipping the bump would move every later CREATE
// address in the transaction.

/// Run a contract whose body is `prefix` followed by a zero-value CREATE whose
/// result address is stored in slot 0, and return that address word.
fn create_address_after(stores: &VmStores, caller: [u8; 21], addr: [u8; 21], prefix: Vec<u8>) -> [u8; 32] {
    let mut bc = prefix;
    bc.extend(push1(0)); // size
    bc.extend(push1(0)); // offset
    bc.extend(push1(0)); // value
    bc.push(0xf0); // CREATE
    bc.extend(push1(0));
    bc.push(0x55); // SSTORE slot 0
    bc.push(0x00);
    install_contract_with(
        stores,
        addr,
        bc,
        Account { balance: 100_000_000, ..Default::default() },
    );
    run_contract(stores, caller, addr);
    slot0(stores, addr)
}

/// A FREEZEBALANCEV2 whose amount is out of signed-64 range must leave the
/// create-nonce exactly where an in-range rejection (insufficient balance) does
/// — one bump — so the following CREATE lands on the same address. The
/// no-stake-op baseline pins that this is a real advance, not a shared zero.
#[test]
fn out_of_range_freezebalancev2_still_bumps_internal_tx_nonce() {
    // 2^200 — far outside signed-64 range.
    let mut huge = [0u8; 32];
    huge[6] = 1;
    let mut out_of_range = push_u256(huge);
    out_of_range.extend(push1(0));
    out_of_range.push(0xda);
    out_of_range.push(0x50); // POP the pushed 0

    // In-range but rejected: 500 TRX against a 100 TRX balance.
    let mut in_range = push_u64(500_000_000);
    in_range.extend(push1(0));
    in_range.push(0xda);
    in_range.push(0x50);

    let stores_a = fresh_stores();
    let addr_out = create_address_after(&stores_a, tron_addr(0x25), tron_addr(0x35), out_of_range);
    let stores_b = fresh_stores();
    let addr_in = create_address_after(&stores_b, tron_addr(0x26), tron_addr(0x36), in_range);
    let stores_c = fresh_stores();
    let addr_none = create_address_after(&stores_c, tron_addr(0x27), tron_addr(0x37), Vec::new());

    assert_ne!(addr_none, [0u8; 32], "the CREATE must have produced an address");
    assert_eq!(
        addr_out, addr_in,
        "an out-of-range amount must bump the nonce exactly as an in-range rejection does"
    );
    assert_ne!(
        addr_out, addr_none,
        "the rejected FREEZEBALANCEV2 must still advance the create-nonce"
    );
}

/// Same for UNFREEZEBALANCEV2 (0xdb).
#[test]
fn out_of_range_unfreezebalancev2_still_bumps_internal_tx_nonce() {
    let mut huge = [0u8; 32];
    huge[6] = 1;
    let mut out_of_range = push_u256(huge);
    out_of_range.extend(push1(0));
    out_of_range.push(0xdb);
    out_of_range.push(0x50);

    // In-range but rejected: nothing is staked to unfreeze.
    let mut in_range = push_u64(5_000_000);
    in_range.extend(push1(0));
    in_range.push(0xdb);
    in_range.push(0x50);

    let stores_a = fresh_stores();
    let addr_out = create_address_after(&stores_a, tron_addr(0x28), tron_addr(0x38), out_of_range);
    let stores_b = fresh_stores();
    let addr_in = create_address_after(&stores_b, tron_addr(0x29), tron_addr(0x39), in_range);
    let stores_c = fresh_stores();
    let addr_none = create_address_after(&stores_c, tron_addr(0x2a), tron_addr(0x3a), Vec::new());

    assert_eq!(addr_out, addr_in);
    assert_ne!(addr_out, addr_none);
}

/// Regression guard for the same edit: a SUCCESSFUL FREEZEBALANCEV2 must bump
/// the nonce exactly once, not twice.
#[test]
fn successful_freezebalancev2_bumps_internal_tx_nonce_once() {
    let mut ok = push_u64(10_000_000);
    ok.extend(push1(0));
    ok.push(0xda);
    ok.push(0x50);

    let mut rejected = push_u64(500_000_000);
    rejected.extend(push1(0));
    rejected.push(0xda);
    rejected.push(0x50);

    let stores_a = fresh_stores();
    let addr_ok = create_address_after(&stores_a, tron_addr(0x2b), tron_addr(0x3b), ok);
    let stores_b = fresh_stores();
    let addr_rejected = create_address_after(&stores_b, tron_addr(0x2c), tron_addr(0x3c), rejected);

    assert_eq!(
        addr_ok, addr_rejected,
        "success and rejection must consume the same single nonce"
    );
}
