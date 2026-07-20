//! Stake 2.0 TVM opcode behaviours pinned by java-tron's
//! `framework/src/test/java/org/tron/common/runtime/vm/FreezeV2Test.java`.
//!
//! `FreezeV2Test` drives `freezeBalanceV2` / `unfreezeBalanceV2` through a
//! deployed contract and asserts, for every call, the exact post-state:
//! the owner's balance delta, the resource-typed `frozenV2` slot, and which
//! of `TOTAL_NET_WEIGHT` / `TOTAL_ENERGY_WEIGHT` / `TOTAL_TRON_POWER_WEIGHT`
//! moved. Calls it expects to fail are asserted as `REVERT` — for a TVM
//! stake opcode that means the opcode pushes 0 and leaves every store
//! untouched.
//!
//! The argument matrix `FreezeV2Test.testFreezeV2Operations` walks is
//! reproduced here one case per test, plus the `ALLOW_NEW_RESOURCE_MODEL`
//! gate on the `TRON_POWER` resource code that the java test enables in its
//! fixture (`saveAllowNewResourceModel(1L)`) and mainnet leaves off.

use std::sync::Arc;

use tron_chainbase::{
    AccountStore, CodeStore, ContractStateStore, DelegatedResourceStore, DelegationStore,
    DynamicPropertiesStore, KvBackend, MemBackend, StorageRowStore, VotesStore, WitnessStore,
};
use tron_crypto::address::Address;
use tron_proto::account::{FreezeV2, UnFreezeV2};
use tron_proto::Account;
use tron_tvm::database::code_hash;
use tron_tvm::execute::{execute_trigger, VmBlockEnv, VmOutcome, VmStores};

/// The block timestamp every fixture anchors on.
const NOW_MS: i64 = 1_700_000_000_000;

/// `ChainConstant.TRX_PRECISION` — the sun-per-TRX divisor every
/// `TOTAL_*_WEIGHT` accumulator is floored by.
const TRX_PRECISION: i64 = 1_000_000;

/// `UnfreezeBalanceV2Actuator.getUNFREEZE_MAX_TIMES()` — the cap on
/// concurrently in-progress unfreezes per account.
const UNFREEZE_MAX_TIMES: usize = 32;

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

/// Stores with the Stake-2.0 opcodes live and `ALLOW_NEW_RESOURCE_MODEL`
/// off — the mainnet configuration.
fn fresh_stores() -> VmStores {
    let dynamic_properties = Arc::new(DynamicPropertiesStore::new(mem()));
    dynamic_properties.put_long(b"ALLOW_TVM_FREEZE", 1);
    dynamic_properties.put_long(b"ALLOW_TVM_VOTE", 1);
    // supportUnfreezeDelay() = UNFREEZE_DELAY_DAYS > 0; 14 = the mainnet value.
    dynamic_properties.put_long(b"UNFREEZE_DELAY_DAYS", 14);
    dynamic_properties.save_latest_block_header_timestamp(NOW_MS);
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

/// `fresh_stores()` with `ALLOW_NEW_RESOURCE_MODEL = 1` — the configuration
/// `FreezeV2Test.init` installs, under which `TRON_POWER` becomes a legal
/// resource code for freeze/unfreeze.
fn fresh_stores_new_resource_model() -> VmStores {
    let stores = fresh_stores();
    stores
        .dynamic_properties
        .put_long(b"ALLOW_NEW_RESOURCE_MODEL", 1);
    stores
}

fn tron_addr(byte: u8) -> [u8; 21] {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(byte);
    a
}

fn push1(v: u8) -> Vec<u8> {
    vec![0x60, v]
}

fn push_u256(word: [u8; 32]) -> Vec<u8> {
    let mut out = vec![0x7f];
    out.extend_from_slice(&word);
    out
}

fn word_u64(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

/// The 256-bit two's-complement encoding of a negative amount — what
/// solidity passes when `FreezeV2Test` calls `freezeBalanceV2(-frozenBalance, res)`.
fn word_neg(v: u64) -> [u8; 32] {
    let mut w = [0xffu8; 32];
    let neg = (v as u128).wrapping_neg();
    w[16..].copy_from_slice(&neg.to_be_bytes());
    w
}

/// `FREEZEBALANCEV2` (0xda) pops `[resource_type, frozen_balance]` with the
/// resource code on top, then the result flag is stored into slot 0.
fn freeze_v2_code(amount: [u8; 32], resource: [u8; 32]) -> Vec<u8> {
    stake_v2_code(0xda, amount, resource)
}

/// `UNFREEZEBALANCEV2` (0xdb) — same stack shape as `FREEZEBALANCEV2`.
fn unfreeze_v2_code(amount: [u8; 32], resource: [u8; 32]) -> Vec<u8> {
    stake_v2_code(0xdb, amount, resource)
}

fn stake_v2_code(opcode: u8, amount: [u8; 32], resource: [u8; 32]) -> Vec<u8> {
    let mut bc = Vec::new();
    bc.extend(push_u256(amount));
    bc.extend(push_u256(resource));
    bc.push(opcode);
    bc.extend(push1(0));
    bc.push(0x55); // SSTORE
    bc.push(0x00); // STOP
    bc
}

fn install_contract_with(stores: &VmStores, addr: [u8; 21], bytecode: Vec<u8>, mut account: Account) {
    let hash = code_hash(&bytecode);
    stores.code.put(hash.as_slice(), &bytecode).unwrap();
    account.address = addr.to_vec();
    account.code = bytecode;
    account.code_hash = hash.as_slice().to_vec();
    stores.accounts.put(&Address::from_raw(addr), &account).unwrap();
}

/// Run the contract at `addr` from a fresh EOA and require the transaction
/// itself to succeed — a rejected stake opcode pushes 0 rather than halting.
fn run_contract(stores: &VmStores, caller: [u8; 21], addr: [u8; 21]) {
    stores.accounts.put(
        &Address::from_raw(caller),
        &Account {
            address: caller.to_vec(),
            balance: 1_000_000_000,
            ..Default::default()
        },
    ).unwrap();
    let outcome = execute_trigger(
        stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: NOW_MS,
            ..Default::default()
        },
        &tron_proto::TriggerSmartContract {
            owner_address: caller.to_vec(),
            contract_address: addr.to_vec(),
            call_value: 0,
            data: vec![],
            call_token_value: 0,
            token_id: 0,
        },
        500_000,
    );
    assert!(
        matches!(outcome, VmOutcome::Success { .. }),
        "expected Success, got: {outcome:?}"
    );
}

/// The flag the stake opcode pushed, read back out of storage slot 0.
fn pushed_flag(stores: &VmStores, addr: [u8; 21]) -> u8 {
    let key = tron_chainbase::StorageRowStore::compose_key(&Address::from_raw(addr), &[0u8; 32]);
    match stores.storage.get(&key).unwrap() {
        Some(bytes) => bytes[31],
        None => 0,
    }
}

fn account_of(stores: &VmStores, addr: [u8; 21]) -> Account {
    stores
        .accounts
        .get(&Address::from_raw(addr))
        .unwrap()
        .unwrap()
}

fn frozen_v2_amount(account: &Account, resource: i32) -> i64 {
    account
        .frozen_v2
        .iter()
        .find(|f| f.r#type == resource)
        .map(|f| f.amount)
        .unwrap_or(0)
}

/// The three chain-wide stake accumulators, in the order
/// (bandwidth, energy, tron power).
fn weights(stores: &VmStores) -> (i64, i64, i64) {
    let dp = &stores.dynamic_properties;
    (
        dp.total_net_weight(),
        dp.total_energy_weight(),
        dp.total_tron_power_weight(),
    )
}

/// Assert a `freezeBalanceV2` call was rejected exactly as
/// `FreezeV2Test.freezeV2WithException` requires: REVERT, and the owner's
/// balance, `frozenV2` list and every weight accumulator untouched.
fn assert_freeze_v2_rejected(label: &str, amount: [u8; 32], resource: [u8; 32], balance: i64) {
    let stores = fresh_stores();
    let caller = tron_addr(0xa0);
    let contract = tron_addr(0xc0);
    install_contract_with(
        &stores,
        contract,
        freeze_v2_code(amount, resource),
        Account {
            balance,
            ..Default::default()
        },
    );
    run_contract(&stores, caller, contract);

    let acct = account_of(&stores, contract);
    assert_eq!(pushed_flag(&stores, contract), 0, "{label}: must push 0");
    assert!(acct.frozen_v2.is_empty(), "{label}: must not stake");
    assert_eq!(acct.balance, balance, "{label}: must not debit balance");
    assert_eq!(weights(&stores), (0, 0, 0), "{label}: must not move weights");
}

// =============================================================================
// freezeBalanceV2 argument validation — FreezeV2Test.testFreezeV2Operations
// =============================================================================

/// `freezeV2WithException(owner, contract, 0, 0)` — java
/// `FreezeBalanceV2Processor.validate`: "FrozenBalance must be positive".
#[test]
fn freeze_v2_rejects_zero_amount() {
    assert_freeze_v2_rejected("zero amount", word_u64(0), word_u64(0), 100_000_000);
}

/// `freezeV2WithException(owner, contract, -frozenBalance, 0)` — the amount
/// arrives as a 256-bit two's-complement word and is read signed, so it is
/// negative and fails the same positivity check.
#[test]
fn freeze_v2_rejects_negative_amount() {
    assert_freeze_v2_rejected(
        "negative amount",
        word_neg(1_000_000),
        word_u64(0),
        100_000_000,
    );
}

/// `freezeV2WithException(owner, contract, frozenBalance - 1, 1)` where
/// `frozenBalance` is 1 TRX — "FrozenBalance must be greater than or equal
/// to 1 TRX". One sun below the floor is rejected; the floor itself is not.
#[test]
fn freeze_v2_rejects_amount_one_sun_below_one_trx() {
    assert_freeze_v2_rejected(
        "999_999 sun",
        word_u64(999_999),
        word_u64(1),
        100_000_000,
    );
}

/// The boundary the previous test brackets: exactly 1 TRX is accepted and
/// contributes 1 to `TOTAL_ENERGY_WEIGHT`.
#[test]
fn freeze_v2_accepts_exactly_one_trx() {
    let stores = fresh_stores();
    let caller = tron_addr(0xa1);
    let contract = tron_addr(0xc1);
    install_contract_with(
        &stores,
        contract,
        freeze_v2_code(word_u64(1_000_000), word_u64(1)),
        Account {
            balance: 100_000_000,
            ..Default::default()
        },
    );
    run_contract(&stores, caller, contract);

    let acct = account_of(&stores, contract);
    assert_eq!(pushed_flag(&stores, contract), 1);
    assert_eq!(frozen_v2_amount(&acct, 1), 1_000_000);
    assert_eq!(acct.balance, 99_000_000);
    assert_eq!(weights(&stores), (0, 1, 0));
}

/// `freezeV2WithException(owner, contract, value, 0)` where `value` far
/// exceeds the contract's balance — "FrozenBalance must be less than or
/// equal to accountBalance".
#[test]
fn freeze_v2_rejects_amount_above_balance() {
    assert_freeze_v2_rejected(
        "amount above balance",
        word_u64(200_000_000),
        word_u64(0),
        100_000_000,
    );
}

/// `freezeV2WithException(owner, contract, frozenBalance, 3)` — resource
/// code 3 is outside `ResourceCode`, so the validate switch's default arm
/// throws whether or not the new resource model is on.
#[test]
fn freeze_v2_rejects_resource_type_three() {
    assert_freeze_v2_rejected(
        "resource code 3",
        word_u64(1_000_000),
        word_u64(3),
        100_000_000,
    );
}

// =============================================================================
// The TRON_POWER resource code — gated on ALLOW_NEW_RESOURCE_MODEL
// =============================================================================

/// `FreezeV2Test.init` calls `saveAllowNewResourceModel(1L)`, which is the
/// only reason `freezeV2(owner, contract, frozenBalance, 2)` succeeds there.
/// `FreezeBalanceV2Processor.validate`'s `case TRON_POWER` throws
/// "Unknown ResourceCode, valid ResourceCode[BANDWIDTH、ENERGY]" whenever
/// `supportAllowNewResourceModel()` is false — the mainnet configuration.
#[test]
fn freeze_v2_rejects_tron_power_when_new_resource_model_off() {
    assert_freeze_v2_rejected(
        "TRON_POWER with the new resource model off",
        word_u64(1_000_000),
        word_u64(2),
        100_000_000,
    );
}

/// With the model on, the same call is the `freezeV2(..., 2)` branch of
/// `FreezeV2Test`: the stake lands in the `TRON_POWER`-typed `frozenV2`
/// slot and only `TOTAL_TRON_POWER_WEIGHT` moves.
#[test]
fn freeze_v2_accepts_tron_power_when_new_resource_model_on() {
    let stores = fresh_stores_new_resource_model();
    let caller = tron_addr(0xa2);
    let contract = tron_addr(0xc2);
    install_contract_with(
        &stores,
        contract,
        freeze_v2_code(word_u64(5_000_000), word_u64(2)),
        Account {
            balance: 100_000_000,
            ..Default::default()
        },
    );
    run_contract(&stores, caller, contract);

    let acct = account_of(&stores, contract);
    assert_eq!(pushed_flag(&stores, contract), 1);
    assert_eq!(frozen_v2_amount(&acct, 2), 5_000_000);
    assert_eq!(acct.balance, 95_000_000);
    assert_eq!(
        weights(&stores),
        (0, 0, 5),
        "a TRON_POWER stake moves only TOTAL_TRON_POWER_WEIGHT"
    );
}

/// `UnfreezeBalanceV2Processor.validate` carries the same gate on the
/// unstake side: `case TRON_POWER` throws unless the new resource model is
/// on, even when the account genuinely holds a TRON_POWER stake.
#[test]
fn unfreeze_v2_rejects_tron_power_when_new_resource_model_off() {
    let stores = fresh_stores();
    let caller = tron_addr(0xa3);
    let contract = tron_addr(0xc3);
    stores
        .dynamic_properties
        .save_total_tron_power_weight(10);
    install_contract_with(
        &stores,
        contract,
        unfreeze_v2_code(word_u64(5_000_000), word_u64(2)),
        Account {
            balance: 0,
            frozen_v2: vec![FreezeV2 {
                r#type: 2,
                amount: 10_000_000,
            }],
            ..Default::default()
        },
    );
    run_contract(&stores, caller, contract);

    let acct = account_of(&stores, contract);
    assert_eq!(pushed_flag(&stores, contract), 0);
    assert_eq!(
        frozen_v2_amount(&acct, 2),
        10_000_000,
        "the TRON_POWER stake must be left intact"
    );
    assert!(acct.unfrozen_v2.is_empty(), "no unfreeze entry may be queued");
    assert_eq!(weights(&stores), (0, 0, 10));
}

// =============================================================================
// unfreezeBalanceV2 argument validation
// =============================================================================

/// Assert an `unfreezeBalanceV2` call was rejected as
/// `FreezeV2Test.unfreezeV2WithException` requires: the stake stays whole
/// and no entry joins the unfreezing list.
fn assert_unfreeze_v2_rejected(
    label: &str,
    stores: &VmStores,
    contract: [u8; 21],
    caller: [u8; 21],
    amount: [u8; 32],
    resource: [u8; 32],
    seeded: Account,
) {
    let staked = frozen_v2_amount(&seeded, 0);
    let pending = seeded.unfrozen_v2.len();
    install_contract_with(stores, contract, unfreeze_v2_code(amount, resource), seeded);
    run_contract(stores, caller, contract);

    let acct = account_of(stores, contract);
    assert_eq!(pushed_flag(stores, contract), 0, "{label}: must push 0");
    assert_eq!(
        frozen_v2_amount(&acct, 0),
        staked,
        "{label}: stake must be untouched"
    );
    assert_eq!(
        acct.unfrozen_v2.len(),
        pending,
        "{label}: no unfreeze entry may be queued"
    );
}

/// `unfreezeV2WithException(owner, contract, frozenBalance + 100, 2)` —
/// `checkUnfreezeBalance` rejects an amount larger than the resource's
/// `frozenV2` slot.
#[test]
fn unfreeze_v2_rejects_amount_above_frozen() {
    let stores = fresh_stores();
    assert_unfreeze_v2_rejected(
        "amount above stake",
        &stores,
        tron_addr(0xc4),
        tron_addr(0xa4),
        word_u64(10_000_100),
        word_u64(0),
        Account {
            frozen_v2: vec![FreezeV2 {
                r#type: 0,
                amount: 10_000_000,
            }],
            ..Default::default()
        },
    );
}

/// `unfreezeV2WithException(owner, contract, 0, 2)` — a zero unstake is
/// rejected by `checkUnfreezeBalance`.
#[test]
fn unfreeze_v2_rejects_zero_amount() {
    let stores = fresh_stores();
    assert_unfreeze_v2_rejected(
        "zero amount",
        &stores,
        tron_addr(0xc5),
        tron_addr(0xa5),
        word_u64(0),
        word_u64(0),
        Account {
            frozen_v2: vec![FreezeV2 {
                r#type: 0,
                amount: 10_000_000,
            }],
            ..Default::default()
        },
    );
}

/// `unfreezeV2WithException(owner, contract, -frozenBalance, 2)`.
#[test]
fn unfreeze_v2_rejects_negative_amount() {
    let stores = fresh_stores();
    assert_unfreeze_v2_rejected(
        "negative amount",
        &stores,
        tron_addr(0xc6),
        tron_addr(0xa6),
        word_neg(1_000_000),
        word_u64(0),
        Account {
            frozen_v2: vec![FreezeV2 {
                r#type: 0,
                amount: 10_000_000,
            }],
            ..Default::default()
        },
    );
}

/// `unfreezeV2WithException(owner, contract, frozenBalance, 3)`.
#[test]
fn unfreeze_v2_rejects_resource_type_three() {
    let stores = fresh_stores();
    assert_unfreeze_v2_rejected(
        "resource code 3",
        &stores,
        tron_addr(0xc7),
        tron_addr(0xa7),
        word_u64(1_000_000),
        word_u64(3),
        Account {
            frozen_v2: vec![FreezeV2 {
                r#type: 0,
                amount: 10_000_000,
            }],
            ..Default::default()
        },
    );
}

/// The "full unfreeze list exception" of `testFreezeV2Operations`: java pads
/// `unfrozenV2` up to `UNFREEZE_MAX_TIMES` unexpired entries and the next
/// unstake reverts. Only entries whose `unfreezeExpireTime` is still in the
/// future occupy a slot (`AccountCapsule.getUnfreezingV2Count(now)`).
#[test]
fn unfreeze_v2_rejects_when_unfreezing_list_at_cap() {
    let stores = fresh_stores();
    let pending: Vec<UnFreezeV2> = (0..UNFREEZE_MAX_TIMES)
        .map(|_| UnFreezeV2 {
            r#type: 0,
            unfreeze_amount: 1,
            unfreeze_expire_time: NOW_MS + 30_000,
        })
        .collect();
    assert_unfreeze_v2_rejected(
        "unfreezing list at cap",
        &stores,
        tron_addr(0xc8),
        tron_addr(0xa8),
        word_u64(1_000_000),
        word_u64(0),
        Account {
            frozen_v2: vec![FreezeV2 {
                r#type: 0,
                amount: 10_000_000,
            }],
            unfrozen_v2: pending,
            ..Default::default()
        },
    );
}

/// The complement: `UNFREEZE_MAX_TIMES` entries that have all matured do NOT
/// occupy slots, so the unstake is accepted. The matured entries are swept
/// into balance by the same call (`unfreezeExpire`), leaving exactly the one
/// freshly queued entry behind.
#[test]
fn unfreeze_v2_allows_unstake_when_capped_list_has_matured() {
    let stores = fresh_stores();
    let caller = tron_addr(0xa9);
    let contract = tron_addr(0xc9);
    let matured: Vec<UnFreezeV2> = (0..UNFREEZE_MAX_TIMES)
        .map(|_| UnFreezeV2 {
            r#type: 0,
            unfreeze_amount: 1,
            unfreeze_expire_time: NOW_MS - 1,
        })
        .collect();
    stores.dynamic_properties.save_total_net_weight(10);
    install_contract_with(
        &stores,
        contract,
        unfreeze_v2_code(word_u64(1_000_000), word_u64(0)),
        Account {
            balance: 0,
            frozen_v2: vec![FreezeV2 {
                r#type: 0,
                amount: 10_000_000,
            }],
            unfrozen_v2: matured,
            ..Default::default()
        },
    );
    run_contract(&stores, caller, contract);

    let acct = account_of(&stores, contract);
    assert_eq!(pushed_flag(&stores, contract), 1);
    assert_eq!(frozen_v2_amount(&acct, 0), 9_000_000);
    assert_eq!(
        acct.balance,
        UNFREEZE_MAX_TIMES as i64,
        "the matured entries are swept into balance"
    );
    assert_eq!(acct.unfrozen_v2.len(), 1, "only the new entry remains");
    assert_eq!(
        weights(&stores),
        (9, 0, 0),
        "TOTAL_NET_WEIGHT drops by the unstaked TRX"
    );
}

// =============================================================================
// Weight bookkeeping — FreezeV2Test.freezeV2 / unfreezeV2 helpers
// =============================================================================

/// `FreezeV2Test.freezeV2` asserts a bandwidth stake moves ONLY
/// `TOTAL_NET_WEIGHT`, by `frozenBalance / TRX_PRECISION`, and leaves the
/// energy and tron-power accumulators alone.
#[test]
fn freeze_v2_bandwidth_moves_only_net_weight() {
    let stores = fresh_stores();
    let caller = tron_addr(0xaa);
    let contract = tron_addr(0xca);
    install_contract_with(
        &stores,
        contract,
        freeze_v2_code(word_u64(7_000_000), word_u64(0)),
        Account {
            balance: 100_000_000,
            ..Default::default()
        },
    );
    run_contract(&stores, caller, contract);

    let acct = account_of(&stores, contract);
    assert_eq!(frozen_v2_amount(&acct, 0), 7_000_000);
    assert_eq!(acct.balance, 93_000_000);
    assert_eq!(weights(&stores), (7_000_000 / TRX_PRECISION, 0, 0));
}

/// The weight accumulators are floored per-account, not per-call: java
/// recomputes `getFrozenV2BalanceWithDelegated(res) / TRX_PRECISION` before
/// and after and applies the difference. A stake that carries a sub-TRX
/// remainder therefore credits the extra whole TRX only once the remainder
/// crosses the boundary.
#[test]
fn freeze_v2_weight_delta_is_floored_against_the_running_basis() {
    let stores = fresh_stores();
    let caller = tron_addr(0xab);
    let contract = tron_addr(0xcb);
    stores.dynamic_properties.save_total_net_weight(3);
    install_contract_with(
        &stores,
        contract,
        freeze_v2_code(word_u64(1_500_000), word_u64(0)),
        Account {
            balance: 100_000_000,
            // 3.5 TRX already staked → basis floor 3; after the call the
            // basis is 5.0 TRX → floor 5, so the delta is 2, not 1.
            frozen_v2: vec![FreezeV2 {
                r#type: 0,
                amount: 3_500_000,
            }],
            ..Default::default()
        },
    );
    run_contract(&stores, caller, contract);

    let acct = account_of(&stores, contract);
    assert_eq!(frozen_v2_amount(&acct, 0), 5_000_000);
    assert_eq!(
        weights(&stores),
        (5, 0, 0),
        "delta = 5_000_000/1e6 - 3_500_000/1e6 = 2"
    );
}

/// `FreezeV2Test.unfreezeV2` asserts the mirror image on the unstake side:
/// the resource's slot shrinks by exactly the requested amount and only that
/// resource's accumulator moves.
#[test]
fn unfreeze_v2_energy_moves_only_energy_weight() {
    let stores = fresh_stores();
    let caller = tron_addr(0xac);
    let contract = tron_addr(0xcc);
    stores.dynamic_properties.save_total_net_weight(4);
    stores.dynamic_properties.save_total_energy_weight(20);
    install_contract_with(
        &stores,
        contract,
        unfreeze_v2_code(word_u64(6_000_000), word_u64(1)),
        Account {
            balance: 0,
            frozen_v2: vec![
                FreezeV2 {
                    r#type: 0,
                    amount: 4_000_000,
                },
                FreezeV2 {
                    r#type: 1,
                    amount: 20_000_000,
                },
            ],
            ..Default::default()
        },
    );
    run_contract(&stores, caller, contract);

    let acct = account_of(&stores, contract);
    assert_eq!(pushed_flag(&stores, contract), 1);
    assert_eq!(frozen_v2_amount(&acct, 1), 14_000_000);
    assert_eq!(
        frozen_v2_amount(&acct, 0),
        4_000_000,
        "the bandwidth stake is untouched"
    );
    assert_eq!(weights(&stores), (4, 14, 0));
    // The unstaked balance is parked, not credited: it becomes a pending
    // `unfrozenV2` entry maturing UNFREEZE_DELAY_DAYS out.
    assert_eq!(acct.balance, 0);
    assert_eq!(acct.unfrozen_v2.len(), 1);
    assert_eq!(acct.unfrozen_v2[0].unfreeze_amount, 6_000_000);
    assert_eq!(acct.unfrozen_v2[0].r#type, 1);
}
