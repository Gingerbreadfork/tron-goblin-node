//! Error-path tests for the resource-delegation actuators:
//!   * `DelegateResource`   — lend frozen-V2 bandwidth/energy to another account
//!   * `UnDelegateResource` — recall a previously-issued delegation
//!
//! Java reference: `DelegateResourceActuatorTest` + `UnDelegateResourceActuatorTest`
//! (~22 cases combined). Our `full_layer.rs` had one happy-path. These
//! cover gating proposals, resource-type isolation, and the
//! `delegated_*`/`acquired_*` bookkeeping pair invariants.

use std::sync::Arc;

use hex_literal::hex;
use tron_actuator::{delegate, ActuatorError};
use tron_chainbase::{
    AccountStore, DelegatedResourceStore, DynamicPropertiesStore, KvBackend, MemBackend,
};
use tron_crypto::address::Address;
use tron_proto::account::FreezeV2 as FreezeV2Entry;
use tron_proto::account::AccountResource;
use tron_proto::{
    Account, AccountType, DelegateResourceContract, DelegatedResource, UnDelegateResourceContract,
};

const ALICE: [u8; 21] = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");
const BOB: [u8; 21] = hex!("41a614f803b6fd780986a42c78ec9c7f77e6ded13c");

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}
fn addr(b: [u8; 21]) -> Address {
    Address::from_raw(b)
}
const PRECISION: i64 = 1_000_000;

struct Ctx {
    accounts: AccountStore,
    resources: DelegatedResourceStore,
    dp: DynamicPropertiesStore,
}

fn ctx_enabled() -> Ctx {
    let c = Ctx {
        accounts: AccountStore::new(mem()),
        resources: DelegatedResourceStore::new(mem()),
        dp: DynamicPropertiesStore::new(mem()),
    };
    c.dp.put_long(b"ALLOW_DELEGATE_RESOURCE", 1);
    c.dp.put_long(b"UNFREEZE_DELAY_DAYS", 14);
    c
}

fn put_basic_account(ctx: &Ctx, who: [u8; 21]) {
    ctx.accounts.put(
        &addr(who),
        &Account {
            address: who.to_vec(),
            balance: 0,
            r#type: AccountType::Normal as i32,
            ..Default::default()
        },
    ).unwrap();
}

fn put_account_with_frozen(ctx: &Ctx, who: [u8; 21], resource: i32, amount: i64) {
    ctx.accounts.put(
        &addr(who),
        &Account {
            address: who.to_vec(),
            balance: 0,
            r#type: AccountType::Normal as i32,
            frozen_v2: vec![FreezeV2Entry {
                r#type: resource,
                amount,
            }],
            ..Default::default()
        },
    ).unwrap();
}

// ============================================================
// DelegateResource — validate
// ============================================================

#[test]
fn delegate_rejects_when_proposals_disabled() {
    let ctx = Ctx {
        accounts: AccountStore::new(mem()),
        resources: DelegatedResourceStore::new(mem()),
        dp: DynamicPropertiesStore::new(mem()),
    };
    // ALLOW_DELEGATE_RESOURCE not set.
    let c = DelegateResourceContract {
        owner_address: ALICE.to_vec(),
        receiver_address: BOB.to_vec(),
        resource: 0,
        balance: 10 * PRECISION,
        lock: false,
        lock_period: 0,
    };
    let err = delegate::validate_delegate_resource(&ctx.accounts, &ctx.dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::DelegationDisabled));
}

#[test]
fn delegate_rejects_self_delegation() {
    let ctx = ctx_enabled();
    put_account_with_frozen(&ctx, ALICE, 0, 100 * PRECISION);
    let c = DelegateResourceContract {
        owner_address: ALICE.to_vec(),
        receiver_address: ALICE.to_vec(),
        resource: 0,
        balance: 10 * PRECISION,
        lock: false,
        lock_period: 0,
    };
    let err = delegate::validate_delegate_resource(&ctx.accounts, &ctx.dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::InvalidDelegationReceiver));
}

#[test]
fn delegate_rejects_amount_below_precision() {
    let ctx = ctx_enabled();
    put_account_with_frozen(&ctx, ALICE, 0, 100 * PRECISION);
    put_basic_account(&ctx, BOB);
    for amt in [0i64, PRECISION - 1, -1] {
        let c = DelegateResourceContract {
            owner_address: ALICE.to_vec(),
            receiver_address: BOB.to_vec(),
            resource: 0,
            balance: amt,
            lock: false,
            lock_period: 0,
        };
        let err = delegate::validate_delegate_resource(&ctx.accounts, &ctx.dp, &c).unwrap_err();
        assert!(
            matches!(err, ActuatorError::FreezeTooSmall),
            "amt={amt} got: {err:?}"
        );
    }
}

#[test]
fn delegate_rejects_invalid_resource_code() {
    let ctx = ctx_enabled();
    put_account_with_frozen(&ctx, ALICE, 0, 100 * PRECISION);
    put_basic_account(&ctx, BOB);
    for r in [-1, 2, 99] {
        let c = DelegateResourceContract {
            owner_address: ALICE.to_vec(),
            receiver_address: BOB.to_vec(),
            resource: r,
            balance: 10 * PRECISION,
            lock: false,
            lock_period: 0,
        };
        let err = delegate::validate_delegate_resource(&ctx.accounts, &ctx.dp, &c).unwrap_err();
        assert!(
            matches!(err, ActuatorError::InvalidResourceCode),
            "r={r} got: {err:?}"
        );
    }
}

#[test]
fn delegate_rejects_insufficient_frozen_balance() {
    let ctx = ctx_enabled();
    put_account_with_frozen(&ctx, ALICE, 0, 5 * PRECISION); // only 5 TRX frozen
    put_basic_account(&ctx, BOB);
    let c = DelegateResourceContract {
        owner_address: ALICE.to_vec(),
        receiver_address: BOB.to_vec(),
        resource: 0,
        balance: 10 * PRECISION,
        lock: false,
        lock_period: 0,
    };
    let err = delegate::validate_delegate_resource(&ctx.accounts, &ctx.dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::InsufficientBalance { .. }));
}

#[test]
fn delegate_rejects_to_contract_account() {
    let ctx = ctx_enabled();
    put_account_with_frozen(&ctx, ALICE, 0, 100 * PRECISION);
    ctx.accounts.put(
        &addr(BOB),
        &Account {
            address: BOB.to_vec(),
            r#type: AccountType::Contract as i32, // contract
            ..Default::default()
        },
    ).unwrap();
    let c = DelegateResourceContract {
        owner_address: ALICE.to_vec(),
        receiver_address: BOB.to_vec(),
        resource: 0,
        balance: 10 * PRECISION,
        lock: false,
        lock_period: 0,
    };
    let err = delegate::validate_delegate_resource(&ctx.accounts, &ctx.dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::DelegationToContract));
}

#[test]
fn delegate_rejects_missing_recipient_account() {
    let ctx = ctx_enabled();
    put_account_with_frozen(&ctx, ALICE, 0, 100 * PRECISION);
    // Bob not in accounts.
    let c = DelegateResourceContract {
        owner_address: ALICE.to_vec(),
        receiver_address: BOB.to_vec(),
        resource: 0,
        balance: 10 * PRECISION,
        lock: false,
        lock_period: 0,
    };
    let err = delegate::validate_delegate_resource(&ctx.accounts, &ctx.dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::TargetAccountMissing));
}

// ============================================================
// DelegateResource — execute (bookkeeping invariants)
// ============================================================

#[test]
fn delegate_bandwidth_moves_frozen_to_delegated_and_credits_recipient_acquired() {
    let ctx = ctx_enabled();
    put_account_with_frozen(&ctx, ALICE, 0, 100 * PRECISION);
    put_basic_account(&ctx, BOB);
    let c = DelegateResourceContract {
        owner_address: ALICE.to_vec(),
        receiver_address: BOB.to_vec(),
        resource: 0,
        balance: 30 * PRECISION,
        lock: false,
        lock_period: 0,
    };
    delegate::validate_delegate_resource(&ctx.accounts, &ctx.dp, &c).unwrap();
    delegate::execute_delegate_resource(&ctx.accounts, &ctx.resources, &c).unwrap();
    let alice = ctx.accounts.get(&addr(ALICE)).unwrap().unwrap();
    let bob = ctx.accounts.get(&addr(BOB)).unwrap().unwrap();
    // Alice's frozen pool dropped 30 TRX; delegated counter +30.
    let bw_slot = alice.frozen_v2.iter().find(|f| f.r#type == 0).unwrap();
    assert_eq!(bw_slot.amount, 70 * PRECISION);
    assert_eq!(alice.delegated_frozen_v2_balance_for_bandwidth, 30 * PRECISION);
    // Bob's acquired counter +30. No frozen change.
    assert_eq!(bob.acquired_delegated_frozen_v2_balance_for_bandwidth, 30 * PRECISION);
}

#[test]
fn delegate_energy_uses_account_resource_fields() {
    let ctx = ctx_enabled();
    put_account_with_frozen(&ctx, ALICE, 1, 100 * PRECISION); // energy
    put_basic_account(&ctx, BOB);
    let c = DelegateResourceContract {
        owner_address: ALICE.to_vec(),
        receiver_address: BOB.to_vec(),
        resource: 1, // energy
        balance: 40 * PRECISION,
        lock: false,
        lock_period: 0,
    };
    delegate::validate_delegate_resource(&ctx.accounts, &ctx.dp, &c).unwrap();
    delegate::execute_delegate_resource(&ctx.accounts, &ctx.resources, &c).unwrap();
    let alice = ctx.accounts.get(&addr(ALICE)).unwrap().unwrap();
    let bob = ctx.accounts.get(&addr(BOB)).unwrap().unwrap();
    let alice_res = alice.account_resource.unwrap_or_default();
    let bob_res = bob.account_resource.unwrap_or_default();
    assert_eq!(alice_res.delegated_frozen_v2_balance_for_energy, 40 * PRECISION);
    assert_eq!(bob_res.acquired_delegated_frozen_v2_balance_for_energy, 40 * PRECISION);
    // Bandwidth fields untouched.
    assert_eq!(alice.delegated_frozen_v2_balance_for_bandwidth, 0);
    assert_eq!(bob.acquired_delegated_frozen_v2_balance_for_bandwidth, 0);
}

#[test]
fn multiple_delegations_accumulate_in_per_pair_record() {
    let ctx = ctx_enabled();
    put_account_with_frozen(&ctx, ALICE, 0, 100 * PRECISION);
    put_basic_account(&ctx, BOB);
    let c = DelegateResourceContract {
        owner_address: ALICE.to_vec(),
        receiver_address: BOB.to_vec(),
        resource: 0,
        balance: 10 * PRECISION,
        lock: false,
        lock_period: 0,
    };
    for _ in 0..3 {
        delegate::validate_delegate_resource(&ctx.accounts, &ctx.dp, &c).unwrap();
        delegate::execute_delegate_resource(&ctx.accounts, &ctx.resources, &c).unwrap();
    }
    let alice = ctx.accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(alice.delegated_frozen_v2_balance_for_bandwidth, 30 * PRECISION);
    let key = DelegatedResourceStore::v2_unlocked_key(&addr(ALICE), &addr(BOB));
    let rec = ctx.resources.get_raw(&key).unwrap().unwrap();
    assert_eq!(rec.frozen_balance_for_bandwidth, 30 * PRECISION);
    assert_eq!(rec.frozen_balance_for_energy, 0);
}

// ============================================================
// UnDelegateResource
// ============================================================

#[test]
fn undelegate_rejects_when_disabled() {
    let ctx = Ctx {
        accounts: AccountStore::new(mem()),
        resources: DelegatedResourceStore::new(mem()),
        dp: DynamicPropertiesStore::new(mem()),
    };
    let c = UnDelegateResourceContract {
        owner_address: ALICE.to_vec(),
        receiver_address: BOB.to_vec(),
        resource: 0,
        balance: 10 * PRECISION,
    };
    let err =
        delegate::validate_undelegate_resource(&ctx.accounts, &ctx.resources, &ctx.dp, &c)
            .unwrap_err();
    assert!(matches!(err, ActuatorError::DelegationDisabled));
}

#[test]
fn undelegate_rejects_self() {
    let ctx = ctx_enabled();
    put_basic_account(&ctx, ALICE);
    let c = UnDelegateResourceContract {
        owner_address: ALICE.to_vec(),
        receiver_address: ALICE.to_vec(),
        resource: 0,
        balance: 10 * PRECISION,
    };
    let err =
        delegate::validate_undelegate_resource(&ctx.accounts, &ctx.resources, &ctx.dp, &c)
            .unwrap_err();
    assert!(matches!(err, ActuatorError::InvalidDelegationReceiver));
}

#[test]
fn undelegate_rejects_when_no_record_exists() {
    let ctx = ctx_enabled();
    put_basic_account(&ctx, ALICE);
    let c = UnDelegateResourceContract {
        owner_address: ALICE.to_vec(),
        receiver_address: BOB.to_vec(),
        resource: 0,
        balance: 10 * PRECISION,
    };
    let err =
        delegate::validate_undelegate_resource(&ctx.accounts, &ctx.resources, &ctx.dp, &c)
            .unwrap_err();
    assert!(matches!(err, ActuatorError::NothingToUndelegate));
}

#[test]
fn undelegate_rejects_amount_exceeding_record() {
    let ctx = ctx_enabled();
    put_account_with_frozen(&ctx, ALICE, 0, 100 * PRECISION);
    put_basic_account(&ctx, BOB);
    let c_del = DelegateResourceContract {
        owner_address: ALICE.to_vec(),
        receiver_address: BOB.to_vec(),
        resource: 0,
        balance: 10 * PRECISION,
        lock: false,
        lock_period: 0,
    };
    delegate::execute_delegate_resource(&ctx.accounts, &ctx.resources, &c_del).unwrap();
    let c_undel = UnDelegateResourceContract {
        owner_address: ALICE.to_vec(),
        receiver_address: BOB.to_vec(),
        resource: 0,
        balance: 50 * PRECISION, // way more than the 10 delegated
    };
    let err =
        delegate::validate_undelegate_resource(&ctx.accounts, &ctx.resources, &ctx.dp, &c_undel)
            .unwrap_err();
    assert!(matches!(err, ActuatorError::InsufficientBalance { .. }));
}

#[test]
fn undelegate_returns_balance_to_frozen_pool_and_decrements_bookkeeping() {
    let ctx = ctx_enabled();
    put_account_with_frozen(&ctx, ALICE, 0, 100 * PRECISION);
    put_basic_account(&ctx, BOB);
    let c_del = DelegateResourceContract {
        owner_address: ALICE.to_vec(),
        receiver_address: BOB.to_vec(),
        resource: 0,
        balance: 30 * PRECISION,
        lock: false,
        lock_period: 0,
    };
    delegate::execute_delegate_resource(&ctx.accounts, &ctx.resources, &c_del).unwrap();
    let c_undel = UnDelegateResourceContract {
        owner_address: ALICE.to_vec(),
        receiver_address: BOB.to_vec(),
        resource: 0,
        balance: 20 * PRECISION, // partial recall
    };
    delegate::validate_undelegate_resource(&ctx.accounts, &ctx.resources, &ctx.dp, &c_undel)
        .unwrap();
    delegate::execute_undelegate_resource(&ctx.accounts, &ctx.resources, &ctx.dp, &c_undel).unwrap();
    let alice = ctx.accounts.get(&addr(ALICE)).unwrap().unwrap();
    let bob = ctx.accounts.get(&addr(BOB)).unwrap().unwrap();
    // Alice: frozen pool +20 (back to 90 from 70 post-delegate);
    // delegated counter dropped by 20 (back to 10 from 30).
    let bw_slot = alice.frozen_v2.iter().find(|f| f.r#type == 0).unwrap();
    assert_eq!(bw_slot.amount, 90 * PRECISION);
    assert_eq!(alice.delegated_frozen_v2_balance_for_bandwidth, 10 * PRECISION);
    // Bob's acquired dropped by 20 (back to 10).
    assert_eq!(bob.acquired_delegated_frozen_v2_balance_for_bandwidth, 10 * PRECISION);
    // Record still exists with the remaining 10.
    let key = DelegatedResourceStore::v2_unlocked_key(&addr(ALICE), &addr(BOB));
    let rec = ctx.resources.get_raw(&key).unwrap().unwrap();
    assert_eq!(rec.frozen_balance_for_bandwidth, 10 * PRECISION);
}

#[test]
fn undelegate_full_amount_deletes_pair_record() {
    let ctx = ctx_enabled();
    put_account_with_frozen(&ctx, ALICE, 0, 100 * PRECISION);
    put_basic_account(&ctx, BOB);
    let c_del = DelegateResourceContract {
        owner_address: ALICE.to_vec(),
        receiver_address: BOB.to_vec(),
        resource: 0,
        balance: 30 * PRECISION,
        lock: false,
        lock_period: 0,
    };
    delegate::execute_delegate_resource(&ctx.accounts, &ctx.resources, &c_del).unwrap();
    let c_undel = UnDelegateResourceContract {
        owner_address: ALICE.to_vec(),
        receiver_address: BOB.to_vec(),
        resource: 0,
        balance: 30 * PRECISION, // full
    };
    delegate::execute_undelegate_resource(&ctx.accounts, &ctx.resources, &ctx.dp, &c_undel).unwrap();
    let key = DelegatedResourceStore::v2_unlocked_key(&addr(ALICE), &addr(BOB));
    assert!(
        ctx.resources.get_raw(&key).unwrap().is_none(),
        "record should be deleted once both sides are zero"
    );
}

#[test]
fn undelegate_keeps_record_when_other_resource_type_still_has_balance() {
    let ctx = ctx_enabled();
    put_account_with_frozen(&ctx, ALICE, 0, 100 * PRECISION);
    let mut alice = ctx.accounts.get(&addr(ALICE)).unwrap().unwrap();
    alice.frozen_v2.push(FreezeV2Entry {
        r#type: 1,
        amount: 100 * PRECISION,
    });
    ctx.accounts.put(&addr(ALICE), &alice).unwrap();
    put_basic_account(&ctx, BOB);
    // Delegate both BW and Energy.
    let c_del_bw = DelegateResourceContract {
        owner_address: ALICE.to_vec(),
        receiver_address: BOB.to_vec(),
        resource: 0,
        balance: 10 * PRECISION,
        lock: false,
        lock_period: 0,
    };
    let c_del_energy = DelegateResourceContract {
        owner_address: ALICE.to_vec(),
        receiver_address: BOB.to_vec(),
        resource: 1,
        balance: 20 * PRECISION,
        lock: false,
        lock_period: 0,
    };
    delegate::execute_delegate_resource(&ctx.accounts, &ctx.resources, &c_del_bw).unwrap();
    delegate::execute_delegate_resource(&ctx.accounts, &ctx.resources, &c_del_energy).unwrap();
    // Fully undelegate bandwidth — record persists because energy is still delegated.
    let c_undel_bw = UnDelegateResourceContract {
        owner_address: ALICE.to_vec(),
        receiver_address: BOB.to_vec(),
        resource: 0,
        balance: 10 * PRECISION,
    };
    delegate::execute_undelegate_resource(&ctx.accounts, &ctx.resources, &ctx.dp, &c_undel_bw).unwrap();
    let key = DelegatedResourceStore::v2_unlocked_key(&addr(ALICE), &addr(BOB));
    let rec = ctx.resources.get_raw(&key).unwrap().expect("record persists");
    assert_eq!(rec.frozen_balance_for_bandwidth, 0);
    assert_eq!(rec.frozen_balance_for_energy, 20 * PRECISION);
}

// ============================================================
// UnDelegateResource — locked (expired) delegations
//
// java-tron stores a `lock = true` delegation under the locked key
// (0x02) with a per-resource expiry, and an undelegate folds the
// EXPIRED-locked balance into the unlocked record before drawing on it
// (`DelegatedResourceStore.unLockExpireResource`). The old code read only
// the unlocked key, so every undelegate of a still-recorded locked
// delegation (e.g. one imported from a mainnet snapshot) was wrongly
// rejected as "nothing to undelegate".
// ============================================================

/// Seed a locked-key delegation record + the matching owner/receiver
/// bookkeeping, as if ALICE had delegated `amount` bandwidth to BOB with
/// `lock = true`, expiring at `expire`.
fn seed_locked_bandwidth_delegation(ctx: &Ctx, amount: i64, expire: i64) {
    ctx.accounts
        .put(
            &addr(ALICE),
            &Account {
                address: ALICE.to_vec(),
                delegated_frozen_v2_balance_for_bandwidth: amount,
                ..Default::default()
            },
        )
        .unwrap();
    ctx.accounts
        .put(
            &addr(BOB),
            &Account {
                address: BOB.to_vec(),
                acquired_delegated_frozen_v2_balance_for_bandwidth: amount,
                ..Default::default()
            },
        )
        .unwrap();
    let lock_key = DelegatedResourceStore::v2_locked_key(&addr(ALICE), &addr(BOB));
    ctx.resources
        .put_raw(
            &lock_key,
            &DelegatedResource {
                from: ALICE.to_vec(),
                to: BOB.to_vec(),
                frozen_balance_for_bandwidth: amount,
                expire_time_for_bandwidth: expire,
                ..Default::default()
            },
        )
        .unwrap();
}

#[test]
fn undelegate_accepts_expired_locked_delegation() {
    let ctx = ctx_enabled();
    ctx.dp.save_latest_block_header_timestamp(1_000);
    // Locked delegation that expired at t=500 (< now=1000).
    seed_locked_bandwidth_delegation(&ctx, 30 * PRECISION, 500);

    let c_undel = UnDelegateResourceContract {
        owner_address: ALICE.to_vec(),
        receiver_address: BOB.to_vec(),
        resource: 0,
        balance: 20 * PRECISION,
    };
    // Previously this returned NothingToUndelegate — the bug.
    delegate::validate_undelegate_resource(&ctx.accounts, &ctx.resources, &ctx.dp, &c_undel)
        .expect("an expired locked delegation IS undelegate-able");
    delegate::execute_undelegate_resource(&ctx.accounts, &ctx.resources, &ctx.dp, &c_undel)
        .unwrap();

    // The locked balance was folded into the unlocked record, then 20
    // recalled, leaving 10 under the unlocked key and the locked key gone.
    let lock_key = DelegatedResourceStore::v2_locked_key(&addr(ALICE), &addr(BOB));
    let unlock_key = DelegatedResourceStore::v2_unlocked_key(&addr(ALICE), &addr(BOB));
    assert!(ctx.resources.get_raw(&lock_key).unwrap().is_none(), "locked record drained");
    let rec = ctx.resources.get_raw(&unlock_key).unwrap().expect("unlocked record exists");
    assert_eq!(rec.frozen_balance_for_bandwidth, 10 * PRECISION);
    // Bookkeeping decremented on both sides.
    let alice = ctx.accounts.get(&addr(ALICE)).unwrap().unwrap();
    let bob = ctx.accounts.get(&addr(BOB)).unwrap().unwrap();
    assert_eq!(alice.delegated_frozen_v2_balance_for_bandwidth, 10 * PRECISION);
    assert_eq!(bob.acquired_delegated_frozen_v2_balance_for_bandwidth, 10 * PRECISION);
    // The recalled 20 is returned to ALICE's frozen-V2 pool.
    let bw = alice.frozen_v2.iter().find(|f| f.r#type == 0).unwrap();
    assert_eq!(bw.amount, 20 * PRECISION);
}

#[test]
fn undelegate_rejects_locked_delegation_not_yet_expired() {
    let ctx = ctx_enabled();
    ctx.dp.save_latest_block_header_timestamp(1_000);
    // Locked until t=2000 (> now=1000) — still locked, not undelegate-able.
    seed_locked_bandwidth_delegation(&ctx, 30 * PRECISION, 2_000);

    let c_undel = UnDelegateResourceContract {
        owner_address: ALICE.to_vec(),
        receiver_address: BOB.to_vec(),
        resource: 0,
        balance: 20 * PRECISION,
    };
    let err = delegate::validate_undelegate_resource(
        &ctx.accounts,
        &ctx.resources,
        &ctx.dp,
        &c_undel,
    )
    .unwrap_err();
    // The record exists but none of it is available yet → InsufficientBalance,
    // not NothingToUndelegate.
    assert!(matches!(err, ActuatorError::InsufficientBalance { .. }), "got {err:?}");
}

// Reference unused import so module-level warnings stay quiet across refactors.
#[allow(dead_code)]
fn _ar_warm() {
    let _ = std::mem::size_of::<AccountResource>();
}
