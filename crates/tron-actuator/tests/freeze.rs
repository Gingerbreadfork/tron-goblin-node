//! Error-path tests for the freeze actuators (v1 + v2).
//!
//! Java reference: `FreezeBalanceActuatorTest` (~22 cases),
//! `UnfreezeBalanceActuatorTest` (~22 cases), `FreezeBalanceV2ActuatorTest`
//! (~16 cases), `UnfreezeBalanceV2ActuatorTest` (~22 cases). Our
//! `full_layer.rs` had 3 happy-path round-trips; these tests focus on
//! the validation predicates and the per-resource weight accounting
//! that's silent-wrong-result risk territory.

use std::sync::Arc;

use hex_literal::hex;
use tron_actuator::{freeze, freeze_v2, ActuatorError};
use tron_chainbase::{
    AccountStore, DelegatedResourceAccountIndexStore, DelegatedResourceStore, DelegationStore,
    DynamicPropertiesStore, KvBackend, MemBackend, VotesStore,
};
use tron_crypto::address::Address;
use tron_proto::account::{Frozen, FreezeV2 as FreezeV2Entry};
use tron_proto::{
    Account, AccountType, FreezeBalanceContract, FreezeBalanceV2Contract,
    UnfreezeBalanceContract, UnfreezeBalanceV2Contract,
};

const ALICE: [u8; 21] = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");
const BOB: [u8; 21] = hex!("41a614f803b6fd780986a42c78ec9c7f77e6ded13c");

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}
fn addr(b: [u8; 21]) -> Address {
    Address::from_raw(b)
}

const PRECISION: i64 = 1_000_000; // 1 TRX

fn put_account(accounts: &AccountStore, address: [u8; 21], balance: i64) {
    accounts.put(
        &addr(address),
        &Account {
            address: address.to_vec(),
            balance,
            r#type: AccountType::Normal as i32,
            ..Default::default()
        },
    ).unwrap();
}

// ============================================================
// FreezeBalance v1 — validate
// ============================================================

#[test]
fn freeze_v1_rejects_missing_owner() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let c = FreezeBalanceContract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 10 * PRECISION,
        frozen_duration: 3,
        resource: 0,
        receiver_address: Vec::new(),
    };
    let err = freeze::validate_freeze_balance(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::OwnerAccountMissing), "got: {err:?}");
}

#[test]
fn freeze_v1_rejects_below_minimum_amount() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_account(&accounts, ALICE, 100 * PRECISION);
    // Anything below 1 TRX is `FreezeTooSmall`.
    for amt in [0, 1, 999_999, PRECISION - 1] {
        let c = FreezeBalanceContract {
            owner_address: ALICE.to_vec(),
            frozen_balance: amt,
            frozen_duration: 3,
            resource: 0,
            receiver_address: Vec::new(),
        };
        let err = freeze::validate_freeze_balance(&accounts, &dp, &c).unwrap_err();
        assert!(
            matches!(err, ActuatorError::FreezeTooSmall),
            "amt={amt} got: {err:?}"
        );
    }
}

#[test]
fn freeze_v1_rejects_negative_amount() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_account(&accounts, ALICE, 100 * PRECISION);
    let c = FreezeBalanceContract {
        owner_address: ALICE.to_vec(),
        frozen_balance: -PRECISION,
        frozen_duration: 3,
        resource: 0,
        receiver_address: Vec::new(),
    };
    let err = freeze::validate_freeze_balance(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::FreezeTooSmall), "got: {err:?}");
}

#[test]
fn freeze_v1_rejects_insufficient_balance() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_account(&accounts, ALICE, 5 * PRECISION);
    let c = FreezeBalanceContract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 10 * PRECISION,
        frozen_duration: 3,
        resource: 0,
        receiver_address: Vec::new(),
    };
    let err = freeze::validate_freeze_balance(&accounts, &dp, &c).unwrap_err();
    assert!(
        matches!(
            err,
            ActuatorError::InsufficientBalance {
                balance: 5_000_000,
                needed: 10_000_000
            }
        ),
        "got: {err:?}"
    );
}

#[test]
fn freeze_v1_rejects_invalid_resource_code() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_account(&accounts, ALICE, 100 * PRECISION);
    for r in [-1, 3, 99, i32::MAX] {
        let c = FreezeBalanceContract {
            owner_address: ALICE.to_vec(),
            frozen_balance: 10 * PRECISION,
            frozen_duration: 3,
            resource: r,
            receiver_address: Vec::new(),
        };
        let err = freeze::validate_freeze_balance(&accounts, &dp, &c).unwrap_err();
        assert!(
            matches!(err, ActuatorError::InvalidResourceCode),
            "r={r} got: {err:?}"
        );
    }
}

// ============================================================
// FreezeBalance v1 — execute (weight accounting)
// ============================================================

#[test]
fn freeze_v1_bandwidth_updates_total_net_weight() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_account(&accounts, ALICE, 1000 * PRECISION);
    let c = FreezeBalanceContract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 100 * PRECISION,
        frozen_duration: 3,
        resource: 0, // BANDWIDTH
        receiver_address: Vec::new(),
    };
    freeze::execute_freeze_balance(&accounts, &dp, &DelegatedResourceStore::new(mem()), None, &c)
        .unwrap();
    // weight = 100 TRX (= 100M sun) / 1M = 100.
    assert_eq!(dp.get_long(b"TOTAL_NET_WEIGHT").unwrap_or(0), 100);
    // Energy weight untouched.
    assert_eq!(dp.get_long(b"TOTAL_ENERGY_WEIGHT").unwrap_or(0), 0);
    // Account balance decreased.
    let alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(alice.balance, 900 * PRECISION);
    assert_eq!(alice.frozen.len(), 1);
    assert_eq!(alice.frozen[0].frozen_balance, 100 * PRECISION);
}

#[test]
fn freeze_v1_energy_updates_total_energy_weight() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_account(&accounts, ALICE, 1000 * PRECISION);
    let c = FreezeBalanceContract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 50 * PRECISION,
        frozen_duration: 3,
        resource: 1, // ENERGY
        receiver_address: Vec::new(),
    };
    freeze::execute_freeze_balance(&accounts, &dp, &DelegatedResourceStore::new(mem()), None, &c)
        .unwrap();
    assert_eq!(dp.get_long(b"TOTAL_ENERGY_WEIGHT").unwrap_or(0), 50);
    assert_eq!(dp.get_long(b"TOTAL_NET_WEIGHT").unwrap_or(0), 0);
}

#[test]
fn freeze_v1_tron_power_does_not_update_global_weights() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_account(&accounts, ALICE, 1000 * PRECISION);
    let c = FreezeBalanceContract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 100 * PRECISION,
        frozen_duration: 3,
        resource: 2, // TRON_POWER
        receiver_address: Vec::new(),
    };
    freeze::execute_freeze_balance(&accounts, &dp, &DelegatedResourceStore::new(mem()), None, &c)
        .unwrap();
    assert_eq!(dp.get_long(b"TOTAL_NET_WEIGHT").unwrap_or(0), 0);
    assert_eq!(dp.get_long(b"TOTAL_ENERGY_WEIGHT").unwrap_or(0), 0);
}

/// V1 energy freeze must coalesce into `AccountResource.frozen_balance_for_energy`
/// (java `getEnergyFrozenBalance()` / `setFrozenForEnergy`), NOT the BANDWIDTH
/// `frozen` list. The V1 unfreeze reads `frozen_balance_for_energy`, so a freeze
/// written to the wrong bucket was invisible to it.
#[test]
fn freeze_v1_energy_lands_in_energy_frozen_field() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_account(&accounts, ALICE, 1000 * PRECISION);
    let c = FreezeBalanceContract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 50 * PRECISION,
        frozen_duration: 3,
        resource: 1, // ENERGY
        receiver_address: Vec::new(),
    };
    freeze::execute_freeze_balance(&accounts, &dp, &DelegatedResourceStore::new(mem()), None, &c)
        .unwrap();
    let alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert!(alice.frozen.is_empty(), "energy freeze must not touch the bandwidth `frozen` list");
    assert_eq!(
        alice
            .account_resource
            .as_ref()
            .and_then(|r| r.frozen_balance_for_energy.as_ref())
            .map(|f| f.frozen_balance)
            .unwrap_or(0),
        50 * PRECISION,
        "energy freeze coalesces into AccountResource.frozen_balance_for_energy"
    );
}

/// With ALLOW_NEW_REWARD = 1 (mainnet), java's `FreezeBalanceActuator
/// .addTotalWeight` adds `floor(newFrozen/1e6) - floor(oldFrozen/1e6)` over the
/// resource's coalesced V1 frozen balance — NOT `floor(freezeBalance/1e6)`.
/// When the account already holds a fractional-TRX V1 frozen balance the two
/// differ by 1 at a flooring boundary, and the legacy form leaked into
/// TOTAL_*_WEIGHT (same class as the V2 fix). Here a 0.5-TRX existing energy
/// freeze plus a 0.6-TRX freeze gives java floor(1.1)-floor(0.5)=1; the legacy
/// floor(0.6)=0 form was wrong.
#[test]
fn freeze_v1_weight_is_floor_difference_under_new_reward() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(b"ALLOW_NEW_REWARD", 1);
    // Seed a fractional (0.5 TRX) pre-existing V1 energy frozen balance.
    accounts
        .put(
            &addr(ALICE),
            &Account {
                address: ALICE.to_vec(),
                balance: 1000 * PRECISION,
                r#type: AccountType::Normal as i32,
                account_resource: Some(tron_proto::account::AccountResource {
                    frozen_balance_for_energy: Some(Frozen {
                        frozen_balance: 500_000, // 0.5 TRX
                        expire_time: 0,
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .unwrap();
    let c = FreezeBalanceContract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 600_000, // 0.6 TRX
        frozen_duration: 3,
        resource: 1, // ENERGY
        receiver_address: Vec::new(),
    };
    freeze::execute_freeze_balance(&accounts, &dp, &DelegatedResourceStore::new(mem()), None, &c)
        .unwrap();
    // floor((0.5+0.6) TRX / 1) - floor(0.5) = 1 - 0 = 1.
    assert_eq!(
        dp.get_long(b"TOTAL_ENERGY_WEIGHT").unwrap_or(0),
        1,
        "new-reward weight is the floored basis difference, not floor(freezeBalance)"
    );
    // The new frozen balance is the coalesced 1.1 TRX.
    let alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(
        alice
            .account_resource
            .unwrap()
            .frozen_balance_for_energy
            .unwrap()
            .frozen_balance,
        1_100_000
    );
}

/// The same flooring fix for BANDWIDTH: 0.5-TRX existing + 0.6-TRX freeze →
/// floor(1.1)-floor(0.5) = 1 (legacy floor(0.6) = 0).
#[test]
fn freeze_v1_bandwidth_weight_is_floor_difference_under_new_reward() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(b"ALLOW_NEW_REWARD", 1);
    accounts
        .put(
            &addr(ALICE),
            &Account {
                address: ALICE.to_vec(),
                balance: 1000 * PRECISION,
                r#type: AccountType::Normal as i32,
                frozen: vec![Frozen { frozen_balance: 500_000, expire_time: 0 }],
                ..Default::default()
            },
        )
        .unwrap();
    let c = FreezeBalanceContract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 600_000,
        frozen_duration: 3,
        resource: 0, // BANDWIDTH
        receiver_address: Vec::new(),
    };
    freeze::execute_freeze_balance(&accounts, &dp, &DelegatedResourceStore::new(mem()), None, &c)
        .unwrap();
    assert_eq!(dp.get_long(b"TOTAL_NET_WEIGHT").unwrap_or(0), 1);
    let alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(alice.frozen[0].frozen_balance, 1_100_000);
}

// ============================================================
// UnfreezeBalance v1
// ============================================================

#[test]
fn unfreeze_v1_rejects_missing_owner() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let c = UnfreezeBalanceContract {
        owner_address: ALICE.to_vec(),
        resource: 0,
        receiver_address: Vec::new(),
    };
    let err = freeze::validate_unfreeze_balance(&accounts, &dp, &DelegatedResourceStore::new(mem()), &c).unwrap_err();
    assert!(matches!(err, ActuatorError::OwnerAccountMissing), "got: {err:?}");
}

#[test]
fn unfreeze_v1_rejects_when_no_frozen_entries() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_account(&accounts, ALICE, 100 * PRECISION);
    let c = UnfreezeBalanceContract {
        owner_address: ALICE.to_vec(),
        resource: 0,
        receiver_address: Vec::new(),
    };
    let err = freeze::validate_unfreeze_balance(&accounts, &dp, &DelegatedResourceStore::new(mem()), &c).unwrap_err();
    assert!(matches!(err, ActuatorError::NothingToUnfreeze), "got: {err:?}");
}

#[test]
fn unfreeze_v1_rejects_when_all_entries_still_locked() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.save_latest_block_header_timestamp(1_000_000);
    let alice = Account {
        address: ALICE.to_vec(),
        balance: 0,
        frozen: vec![Frozen {
            frozen_balance: 100 * PRECISION,
            expire_time: 2_000_000, // future
        }],
        ..Default::default()
    };
    accounts.put(&addr(ALICE), &alice).unwrap();
    let c = UnfreezeBalanceContract {
        owner_address: ALICE.to_vec(),
        resource: 0,
        receiver_address: Vec::new(),
    };
    let err = freeze::validate_unfreeze_balance(&accounts, &dp, &DelegatedResourceStore::new(mem()), &c).unwrap_err();
    assert!(matches!(err, ActuatorError::NothingToUnfreeze), "got: {err:?}");
}

#[test]
fn unfreeze_v1_returns_only_expired_entries() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.save_latest_block_header_timestamp(5_000);
    let alice = Account {
        address: ALICE.to_vec(),
        balance: 0,
        frozen: vec![
            Frozen {
                frozen_balance: 10 * PRECISION,
                expire_time: 4_000, // expired
            },
            Frozen {
                frozen_balance: 20 * PRECISION,
                expire_time: 9_000, // future
            },
        ],
        ..Default::default()
    };
    accounts.put(&addr(ALICE), &alice).unwrap();
    let c = UnfreezeBalanceContract {
        owner_address: ALICE.to_vec(),
        resource: 0,
        receiver_address: Vec::new(),
    };
    freeze::validate_unfreeze_balance(&accounts, &dp, &DelegatedResourceStore::new(mem()), &c).unwrap();
    let votes = VotesStore::new(mem());
    let delegation = DelegationStore::new(mem());
    freeze::execute_unfreeze_balance(
        &accounts,
        &dp,
        &votes,
        &delegation,
        &DelegatedResourceStore::new(mem()),
        None,
        None,
        &c,
    )
    .unwrap();
    let alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    // Only the expired 10 TRX returned to balance.
    assert_eq!(alice.balance, 10 * PRECISION);
    // The future entry remains.
    assert_eq!(alice.frozen.len(), 1);
    assert_eq!(alice.frozen[0].frozen_balance, 20 * PRECISION);
}

// ============================================================
// FreezeBalance v1 — delegate (receiver) lifecycle
//
// Java reference: `FreezeBalanceActuator.delegateResource` /
// `UnfreezeBalanceActuator.execute` receiver branch. java still accepts a
// V1 freeze-with-receiver for BANDWIDTH/ENERGY (FreezeBalanceActuator
// .validate only gates out TRON_POWER / unknown resources), so the
// receiver_address must drive the delegated-resource path, not a
// self-freeze.
// ============================================================

/// Enable the delegate gates a V1 freeze-with-receiver runs under on
/// mainnet: ALLOW_DELEGATE_RESOURCE (supportDR), the new-index optimization
/// (so per-pair index rows are written directly), and ALLOW_NEW_REWARD (the
/// floored-difference weight basis).
fn enable_v1_delegate(dp: &DynamicPropertiesStore) {
    dp.put_long(b"ALLOW_DELEGATE_RESOURCE", 1);
    dp.put_long(b"ALLOW_DELEGATE_OPTIMIZATION", 1);
    dp.put_long(b"ALLOW_NEW_REWARD", 1);
    dp.put_long(b"ALLOW_MULTI_SIGN", 1);
}

#[test]
fn freeze_v1_bandwidth_delegate_moves_resource_to_receiver() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let resources = DelegatedResourceStore::new(mem());
    let index = DelegatedResourceAccountIndexStore::new(mem());
    enable_v1_delegate(&dp);
    dp.save_latest_block_header_timestamp(1_000);
    put_account(&accounts, ALICE, 1000 * PRECISION);
    put_account(&accounts, BOB, 0);

    let c = FreezeBalanceContract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 100 * PRECISION,
        frozen_duration: 3,
        resource: 0, // BANDWIDTH
        receiver_address: BOB.to_vec(),
    };
    freeze::validate_freeze_balance(&accounts, &dp, &c).unwrap();
    freeze::execute_freeze_balance(&accounts, &dp, &resources, Some(&index), &c).unwrap();

    // Owner: balance debited, delegated_V1 bandwidth up, NO self-frozen entry.
    let alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(alice.balance, 900 * PRECISION);
    assert_eq!(alice.delegated_frozen_balance_for_bandwidth, 100 * PRECISION);
    assert!(alice.frozen.is_empty(), "delegate freeze must not self-freeze");

    // Receiver: acquired_V1 bandwidth up.
    let bob = accounts.get(&addr(BOB)).unwrap().unwrap();
    assert_eq!(bob.acquired_delegated_frozen_balance_for_bandwidth, 100 * PRECISION);

    // V1 DelegatedResource row carries the bandwidth balance + expiry.
    let key = DelegatedResourceStore::v1_key(&addr(ALICE), &addr(BOB));
    let row = resources.get_raw(&key).unwrap().expect("v1 row");
    assert_eq!(row.from, ALICE.to_vec());
    assert_eq!(row.to, BOB.to_vec());
    assert_eq!(row.frozen_balance_for_bandwidth, 100 * PRECISION);
    assert_eq!(row.expire_time_for_bandwidth, 1_000 + 3 * 24 * 60 * 60 * 1000);
    assert_eq!(row.frozen_balance_for_energy, 0);

    // Bidirectional index rows present.
    assert!(index
        .get_raw(&DelegatedResourceAccountIndexStore::v1_from_key(&addr(ALICE), &addr(BOB)))
        .unwrap()
        .is_some());
    assert!(index
        .get_raw(&DelegatedResourceAccountIndexStore::v1_to_key(&addr(ALICE), &addr(BOB)))
        .unwrap()
        .is_some());

    // Weight: floor(100 TRX / 1e6 sun-per-TRX) on the receiver acquired delta.
    assert_eq!(dp.get_long(b"TOTAL_NET_WEIGHT").unwrap_or(0), 100);
    assert_eq!(dp.get_long(b"TOTAL_ENERGY_WEIGHT").unwrap_or(0), 0);
}

#[test]
fn freeze_v1_energy_delegate_moves_resource_to_receiver() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let resources = DelegatedResourceStore::new(mem());
    let index = DelegatedResourceAccountIndexStore::new(mem());
    enable_v1_delegate(&dp);
    dp.save_latest_block_header_timestamp(1_000);
    put_account(&accounts, ALICE, 1000 * PRECISION);
    put_account(&accounts, BOB, 0);

    let c = FreezeBalanceContract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 50 * PRECISION,
        frozen_duration: 3,
        resource: 1, // ENERGY
        receiver_address: BOB.to_vec(),
    };
    freeze::execute_freeze_balance(&accounts, &dp, &resources, Some(&index), &c).unwrap();

    // Owner: delegated_V1 energy lives on AccountResource (field 5).
    let alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(alice.balance, 950 * PRECISION);
    assert_eq!(
        alice
            .account_resource
            .as_ref()
            .map(|r| r.delegated_frozen_balance_for_energy)
            .unwrap_or(0),
        50 * PRECISION
    );
    assert!(alice
        .account_resource
        .as_ref()
        .and_then(|r| r.frozen_balance_for_energy.as_ref())
        .is_none());

    // Receiver: acquired_V1 energy lives on AccountResource (field 4).
    let bob = accounts.get(&addr(BOB)).unwrap().unwrap();
    assert_eq!(
        bob.account_resource
            .as_ref()
            .map(|r| r.acquired_delegated_frozen_balance_for_energy)
            .unwrap_or(0),
        50 * PRECISION
    );

    // V1 row carries the energy balance + energy expiry.
    let key = DelegatedResourceStore::v1_key(&addr(ALICE), &addr(BOB));
    let row = resources.get_raw(&key).unwrap().expect("v1 row");
    assert_eq!(row.frozen_balance_for_energy, 50 * PRECISION);
    assert_eq!(row.expire_time_for_energy, 1_000 + 3 * 24 * 60 * 60 * 1000);

    assert_eq!(dp.get_long(b"TOTAL_ENERGY_WEIGHT").unwrap_or(0), 50);
    assert_eq!(dp.get_long(b"TOTAL_NET_WEIGHT").unwrap_or(0), 0);
}

#[test]
fn freeze_v1_delegate_coalesces_into_existing_row() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let resources = DelegatedResourceStore::new(mem());
    let index = DelegatedResourceAccountIndexStore::new(mem());
    enable_v1_delegate(&dp);
    dp.save_latest_block_header_timestamp(1_000);
    put_account(&accounts, ALICE, 1000 * PRECISION);
    put_account(&accounts, BOB, 0);

    let c = FreezeBalanceContract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 40 * PRECISION,
        frozen_duration: 3,
        resource: 0,
        receiver_address: BOB.to_vec(),
    };
    freeze::execute_freeze_balance(&accounts, &dp, &resources, Some(&index), &c).unwrap();
    // Second freeze into the same (owner, receiver, bandwidth) row.
    freeze::execute_freeze_balance(&accounts, &dp, &resources, Some(&index), &c).unwrap();

    let key = DelegatedResourceStore::v1_key(&addr(ALICE), &addr(BOB));
    let row = resources.get_raw(&key).unwrap().expect("v1 row");
    assert_eq!(row.frozen_balance_for_bandwidth, 80 * PRECISION, "coalesced");
    let alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(alice.delegated_frozen_balance_for_bandwidth, 80 * PRECISION);
    let bob = accounts.get(&addr(BOB)).unwrap().unwrap();
    assert_eq!(bob.acquired_delegated_frozen_balance_for_bandwidth, 80 * PRECISION);
    // Each freeze's floored receiver-acquired increment is 40; total 80.
    assert_eq!(dp.get_long(b"TOTAL_NET_WEIGHT").unwrap_or(0), 80);
}

// === FreezeBalance v1 — receiver validation errors ===

#[test]
fn freeze_v1_delegate_rejects_self_receiver() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    enable_v1_delegate(&dp);
    put_account(&accounts, ALICE, 1000 * PRECISION);
    let c = FreezeBalanceContract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 10 * PRECISION,
        frozen_duration: 3,
        resource: 0,
        receiver_address: ALICE.to_vec(),
    };
    let err = freeze::validate_freeze_balance(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::ReceiverSameAsOwner), "got: {err:?}");
}

#[test]
fn freeze_v1_delegate_rejects_missing_receiver_account() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    enable_v1_delegate(&dp);
    put_account(&accounts, ALICE, 1000 * PRECISION);
    // BOB not created.
    let c = FreezeBalanceContract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 10 * PRECISION,
        frozen_duration: 3,
        resource: 0,
        receiver_address: BOB.to_vec(),
    };
    let err = freeze::validate_freeze_balance(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::TargetAccountMissing), "got: {err:?}");
}

#[test]
fn freeze_v1_delegate_rejects_contract_receiver_post_constantinople() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    enable_v1_delegate(&dp);
    dp.put_long(b"ALLOW_TVM_CONSTANTINOPLE", 1);
    put_account(&accounts, ALICE, 1000 * PRECISION);
    accounts
        .put(
            &addr(BOB),
            &Account {
                address: BOB.to_vec(),
                r#type: AccountType::Contract as i32,
                ..Default::default()
            },
        )
        .unwrap();
    let c = FreezeBalanceContract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 10 * PRECISION,
        frozen_duration: 3,
        resource: 0,
        receiver_address: BOB.to_vec(),
    };
    let err = freeze::validate_freeze_balance(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::DelegationToContract), "got: {err:?}");
}

#[test]
fn freeze_v1_receiver_ignored_when_support_dr_off() {
    // Without ALLOW_DELEGATE_RESOURCE the receiver is ignored and the freeze
    // is a self-freeze — java's `!isEmpty(receiver) && supportDR()` gate.
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let resources = DelegatedResourceStore::new(mem());
    put_account(&accounts, ALICE, 1000 * PRECISION);
    put_account(&accounts, BOB, 0);
    // supportDR off.
    let c = FreezeBalanceContract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 30 * PRECISION,
        frozen_duration: 3,
        resource: 0,
        receiver_address: BOB.to_vec(),
    };
    freeze::validate_freeze_balance(&accounts, &dp, &c).unwrap();
    freeze::execute_freeze_balance(&accounts, &dp, &resources, None, &c).unwrap();
    let alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(alice.frozen.len(), 1, "self-freeze when supportDR off");
    assert_eq!(alice.frozen[0].frozen_balance, 30 * PRECISION);
    assert_eq!(alice.delegated_frozen_balance_for_bandwidth, 0);
    let bob = accounts.get(&addr(BOB)).unwrap().unwrap();
    assert_eq!(bob.acquired_delegated_frozen_balance_for_bandwidth, 0);
    assert!(resources
        .get_raw(&DelegatedResourceStore::v1_key(&addr(ALICE), &addr(BOB)))
        .unwrap()
        .is_none());
}

// ============================================================
// UnfreezeBalance v1 — undelegate (receiver) lifecycle: the inverse of
// freeze-delegate. Java reference: `UnfreezeBalanceActuator.execute`
// receiver branch.
// ============================================================

#[test]
fn unfreeze_v1_bandwidth_undelegate_round_trips_freeze_delegate() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let resources = DelegatedResourceStore::new(mem());
    let index = DelegatedResourceAccountIndexStore::new(mem());
    let votes = VotesStore::new(mem());
    let delegation = DelegationStore::new(mem());
    enable_v1_delegate(&dp);
    dp.put_long(b"ALLOW_TVM_CONSTANTINOPLE", 1);
    dp.put_long(b"ALLOW_TVM_SOLIDITY_059", 1);
    dp.save_latest_block_header_timestamp(1_000);
    put_account(&accounts, ALICE, 1000 * PRECISION);
    put_account(&accounts, BOB, 0);

    // Freeze-delegate 100 TRX of bandwidth to BOB.
    let freeze_c = FreezeBalanceContract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 100 * PRECISION,
        frozen_duration: 3,
        resource: 0,
        receiver_address: BOB.to_vec(),
    };
    freeze::execute_freeze_balance(&accounts, &dp, &resources, Some(&index), &freeze_c).unwrap();
    assert_eq!(dp.get_long(b"TOTAL_NET_WEIGHT").unwrap_or(0), 100);

    // Advance past the delegation expiry, then undelegate.
    dp.save_latest_block_header_timestamp(1_000 + 3 * 24 * 60 * 60 * 1000 + 1);
    let unfreeze_c = UnfreezeBalanceContract {
        owner_address: ALICE.to_vec(),
        resource: 0,
        receiver_address: BOB.to_vec(),
    };
    freeze::validate_unfreeze_balance(&accounts, &dp, &resources, &unfreeze_c).unwrap();
    freeze::execute_unfreeze_balance(
        &accounts,
        &dp,
        &votes,
        &delegation,
        &resources,
        Some(&index),
        None,
        &unfreeze_c,
    )
    .unwrap();

    // Owner: balance restored, delegated_V1 back to 0.
    let alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(alice.balance, 1000 * PRECISION);
    assert_eq!(alice.delegated_frozen_balance_for_bandwidth, 0);
    // Receiver: acquired_V1 back to 0.
    let bob = accounts.get(&addr(BOB)).unwrap().unwrap();
    assert_eq!(bob.acquired_delegated_frozen_balance_for_bandwidth, 0);
    // V1 row + index rows deleted (both balances zero).
    assert!(resources
        .get_raw(&DelegatedResourceStore::v1_key(&addr(ALICE), &addr(BOB)))
        .unwrap()
        .is_none());
    assert!(index
        .get_raw(&DelegatedResourceAccountIndexStore::v1_from_key(&addr(ALICE), &addr(BOB)))
        .unwrap()
        .is_none());
    // Weight back to 0.
    assert_eq!(dp.get_long(b"TOTAL_NET_WEIGHT").unwrap_or(0), 0);
}

#[test]
fn unfreeze_v1_energy_undelegate_round_trips_freeze_delegate() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let resources = DelegatedResourceStore::new(mem());
    let index = DelegatedResourceAccountIndexStore::new(mem());
    let votes = VotesStore::new(mem());
    let delegation = DelegationStore::new(mem());
    enable_v1_delegate(&dp);
    dp.put_long(b"ALLOW_TVM_CONSTANTINOPLE", 1);
    dp.put_long(b"ALLOW_TVM_SOLIDITY_059", 1);
    dp.save_latest_block_header_timestamp(1_000);
    put_account(&accounts, ALICE, 1000 * PRECISION);
    put_account(&accounts, BOB, 0);

    let freeze_c = FreezeBalanceContract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 60 * PRECISION,
        frozen_duration: 3,
        resource: 1, // ENERGY
        receiver_address: BOB.to_vec(),
    };
    freeze::execute_freeze_balance(&accounts, &dp, &resources, Some(&index), &freeze_c).unwrap();
    assert_eq!(dp.get_long(b"TOTAL_ENERGY_WEIGHT").unwrap_or(0), 60);

    dp.save_latest_block_header_timestamp(1_000 + 3 * 24 * 60 * 60 * 1000 + 1);
    let unfreeze_c = UnfreezeBalanceContract {
        owner_address: ALICE.to_vec(),
        resource: 1,
        receiver_address: BOB.to_vec(),
    };
    freeze::validate_unfreeze_balance(&accounts, &dp, &resources, &unfreeze_c).unwrap();
    freeze::execute_unfreeze_balance(
        &accounts,
        &dp,
        &votes,
        &delegation,
        &resources,
        Some(&index),
        None,
        &unfreeze_c,
    )
    .unwrap();

    let alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(alice.balance, 1000 * PRECISION);
    assert_eq!(
        alice
            .account_resource
            .as_ref()
            .map(|r| r.delegated_frozen_balance_for_energy)
            .unwrap_or(0),
        0
    );
    let bob = accounts.get(&addr(BOB)).unwrap().unwrap();
    assert_eq!(
        bob.account_resource
            .as_ref()
            .map(|r| r.acquired_delegated_frozen_balance_for_energy)
            .unwrap_or(0),
        0
    );
    assert!(resources
        .get_raw(&DelegatedResourceStore::v1_key(&addr(ALICE), &addr(BOB)))
        .unwrap()
        .is_none());
    assert_eq!(dp.get_long(b"TOTAL_ENERGY_WEIGHT").unwrap_or(0), 0);
}

#[test]
fn unfreeze_v1_undelegate_rejects_before_expiry() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let resources = DelegatedResourceStore::new(mem());
    let index = DelegatedResourceAccountIndexStore::new(mem());
    enable_v1_delegate(&dp);
    dp.put_long(b"ALLOW_TVM_CONSTANTINOPLE", 1);
    dp.save_latest_block_header_timestamp(1_000);
    put_account(&accounts, ALICE, 1000 * PRECISION);
    put_account(&accounts, BOB, 0);
    let freeze_c = FreezeBalanceContract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 100 * PRECISION,
        frozen_duration: 3,
        resource: 0,
        receiver_address: BOB.to_vec(),
    };
    freeze::execute_freeze_balance(&accounts, &dp, &resources, Some(&index), &freeze_c).unwrap();
    // Still locked (now < expiry).
    let unfreeze_c = UnfreezeBalanceContract {
        owner_address: ALICE.to_vec(),
        resource: 0,
        receiver_address: BOB.to_vec(),
    };
    let err =
        freeze::validate_unfreeze_balance(&accounts, &dp, &resources, &unfreeze_c).unwrap_err();
    assert!(matches!(err, ActuatorError::NothingToUnfreeze), "got: {err:?}");
}

#[test]
fn unfreeze_v1_undelegate_rejects_missing_delegation() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let resources = DelegatedResourceStore::new(mem());
    enable_v1_delegate(&dp);
    dp.put_long(b"ALLOW_TVM_CONSTANTINOPLE", 1);
    put_account(&accounts, ALICE, 1000 * PRECISION);
    put_account(&accounts, BOB, 0);
    // No delegation recorded.
    let unfreeze_c = UnfreezeBalanceContract {
        owner_address: ALICE.to_vec(),
        resource: 0,
        receiver_address: BOB.to_vec(),
    };
    let err =
        freeze::validate_unfreeze_balance(&accounts, &dp, &resources, &unfreeze_c).unwrap_err();
    assert!(matches!(err, ActuatorError::DelegatedResourceMissing), "got: {err:?}");
}

// ============================================================
// FreezeBalanceV2 — validate
// ============================================================

fn enable_v2(dp: &DynamicPropertiesStore) {
    dp.put_long(b"UNFREEZE_DELAY_DAYS", 14);
}

#[test]
fn freeze_v2_rejects_when_unfreeze_delay_disabled() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    // ALLOW_UNFREEZE_DELAY not set / set to 0.
    put_account(&accounts, ALICE, 100 * PRECISION);
    let c = FreezeBalanceV2Contract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 10 * PRECISION,
        resource: 0,
    };
    let err = freeze_v2::validate_freeze_balance_v2(&accounts, &dp, &c).unwrap_err();
    assert!(
        matches!(err, ActuatorError::UnfreezeDelayDisabled),
        "got: {err:?}"
    );
}

#[test]
fn freeze_v2_rejects_below_minimum_amount() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    enable_v2(&dp);
    put_account(&accounts, ALICE, 100 * PRECISION);
    for amt in [0, 1, PRECISION - 1, -1] {
        let c = FreezeBalanceV2Contract {
            owner_address: ALICE.to_vec(),
            frozen_balance: amt,
            resource: 0,
        };
        let err = freeze_v2::validate_freeze_balance_v2(&accounts, &dp, &c).unwrap_err();
        assert!(
            matches!(err, ActuatorError::FreezeTooSmall),
            "amt={amt} got: {err:?}"
        );
    }
}

#[test]
fn freeze_v2_rejects_invalid_resource() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    enable_v2(&dp);
    put_account(&accounts, ALICE, 100 * PRECISION);
    let c = FreezeBalanceV2Contract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 10 * PRECISION,
        resource: 99,
    };
    let err = freeze_v2::validate_freeze_balance_v2(&accounts, &dp, &c).unwrap_err();
    assert!(
        matches!(err, ActuatorError::InvalidResourceCode),
        "got: {err:?}"
    );
}

#[test]
fn freeze_v2_rejects_insufficient_balance() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    enable_v2(&dp);
    put_account(&accounts, ALICE, 5 * PRECISION);
    let c = FreezeBalanceV2Contract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 10 * PRECISION,
        resource: 0,
    };
    let err = freeze_v2::validate_freeze_balance_v2(&accounts, &dp, &c).unwrap_err();
    assert!(
        matches!(err, ActuatorError::InsufficientBalance { .. }),
        "got: {err:?}"
    );
}

// ============================================================
// FreezeBalanceV2 — weight accounting (the silent-wrong-result tier)
// ============================================================

#[test]
fn freeze_v2_re_freezing_same_resource_only_adds_delta_to_global_weight() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    enable_v2(&dp);
    put_account(&accounts, ALICE, 1000 * PRECISION);
    let c1 = FreezeBalanceV2Contract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 100 * PRECISION,
        resource: 0,
    };
    freeze_v2::execute_freeze_balance_v2(&accounts, &dp, &c1).unwrap();
    assert_eq!(dp.get_long(b"TOTAL_NET_WEIGHT").unwrap_or(0), 100);
    // Second freeze into the same resource bucket. Java-tron's logic:
    //   oldWeight = oldFrozen / TRX_PRECISION
    //   newWeight = (oldFrozen + addAmount) / TRX_PRECISION
    //   delta = newWeight - oldWeight = 50 - 100 = wait, addAmount=50
    //          delta = 150 - 100 = 50
    let c2 = FreezeBalanceV2Contract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 50 * PRECISION,
        resource: 0,
    };
    freeze_v2::execute_freeze_balance_v2(&accounts, &dp, &c2).unwrap();
    assert_eq!(
        dp.get_long(b"TOTAL_NET_WEIGHT").unwrap_or(0),
        150,
        "delta must be 50 (not double-counted)"
    );
}

#[test]
fn freeze_v2_weight_basis_includes_delegated_out_frozen() {
    // Regression for the TOTAL_*_WEIGHT drift (caught by tron-state-diff):
    // the chain-weight basis is java-tron's `getFrozenV2BalanceWithDelegated`
    // = held frozen-V2 + delegated-OUT, not just the held portion. Because
    // weight = floor(basis / TRX_PRECISION), omitting the delegated 1.5 TRX
    // shifts the rounding boundary and the freeze delta comes out wrong.
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    enable_v2(&dp);
    // ALICE holds no frozen-V2 bandwidth, but has 1.5 TRX delegated out.
    accounts
        .put(
            &addr(ALICE),
            &Account {
                address: ALICE.to_vec(),
                balance: 1000 * PRECISION,
                r#type: AccountType::Normal as i32,
                delegated_frozen_v2_balance_for_bandwidth: 1_500_000, // 1.5 TRX
                ..Default::default()
            },
        )
        .unwrap();

    // Freeze another 1.5 TRX of bandwidth.
    let c = FreezeBalanceV2Contract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 1_500_000,
        resource: 0,
    };
    freeze_v2::execute_freeze_balance_v2(&accounts, &dp, &c).unwrap();

    // java: floor((1.5+1.5 TRX)/TRX) - floor(1.5 TRX/TRX) = 3 - 1 = 2.
    // The held-only bug would have given floor(1.5/1) - floor(0/1) = 1.
    assert_eq!(
        dp.get_long(b"TOTAL_NET_WEIGHT").unwrap_or(0),
        2,
        "weight delta must use the with-delegated basis (java parity), not held-only"
    );
}

#[test]
fn freeze_v2_different_resources_accumulate_in_separate_buckets() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    enable_v2(&dp);
    put_account(&accounts, ALICE, 1000 * PRECISION);
    let c_band = FreezeBalanceV2Contract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 100 * PRECISION,
        resource: 0,
    };
    let c_energy = FreezeBalanceV2Contract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 75 * PRECISION,
        resource: 1,
    };
    freeze_v2::execute_freeze_balance_v2(&accounts, &dp, &c_band).unwrap();
    freeze_v2::execute_freeze_balance_v2(&accounts, &dp, &c_energy).unwrap();
    assert_eq!(dp.get_long(b"TOTAL_NET_WEIGHT").unwrap_or(0), 100);
    assert_eq!(dp.get_long(b"TOTAL_ENERGY_WEIGHT").unwrap_or(0), 75);
    let alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(alice.frozen_v2.len(), 2);
    assert_eq!(alice.balance, 1000 * PRECISION - 100 * PRECISION - 75 * PRECISION);
}

#[test]
fn freeze_v2_tron_power_updates_only_total_tron_power_weight() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    enable_v2(&dp);
    put_account(&accounts, ALICE, 1000 * PRECISION);
    let c = FreezeBalanceV2Contract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 100 * PRECISION,
        resource: 2,
    };
    freeze_v2::execute_freeze_balance_v2(&accounts, &dp, &c).unwrap();
    // TRON_POWER freeze updates TOTAL_TRON_POWER_WEIGHT (java parity) — this
    // accumulator was previously never written (apply_weight_delta no-op'd
    // resource=2), so it silently drifted.
    assert_eq!(
        dp.get_long(b"TOTAL_TRON_POWER_WEIGHT").unwrap_or(0),
        100,
        "TRON_POWER freeze must bump TOTAL_TRON_POWER_WEIGHT"
    );
    // ...and leaves net/energy untouched.
    assert_eq!(dp.get_long(b"TOTAL_NET_WEIGHT").unwrap_or(0), 0);
    assert_eq!(dp.get_long(b"TOTAL_ENERGY_WEIGHT").unwrap_or(0), 0);
}

// ============================================================
// UnfreezeBalanceV2 — validate
// ============================================================

#[test]
fn unfreeze_v2_rejects_when_delay_disabled() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_account(&accounts, ALICE, 0);
    let c = UnfreezeBalanceV2Contract {
        owner_address: ALICE.to_vec(),
        unfreeze_balance: PRECISION,
        resource: 0,
    };
    let err = freeze_v2::validate_unfreeze_balance_v2(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::UnfreezeDelayDisabled));
}

#[test]
fn unfreeze_v2_rejects_invalid_resource() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    enable_v2(&dp);
    put_account(&accounts, ALICE, 0);
    let c = UnfreezeBalanceV2Contract {
        owner_address: ALICE.to_vec(),
        unfreeze_balance: PRECISION,
        resource: 99,
    };
    let err = freeze_v2::validate_unfreeze_balance_v2(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::InvalidResourceCode));
}

#[test]
fn unfreeze_v2_rejects_when_resource_bucket_empty() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    enable_v2(&dp);
    put_account(&accounts, ALICE, 0);
    let c = UnfreezeBalanceV2Contract {
        owner_address: ALICE.to_vec(),
        unfreeze_balance: PRECISION,
        resource: 0,
    };
    let err = freeze_v2::validate_unfreeze_balance_v2(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::NothingToUnfreeze));
}

#[test]
fn unfreeze_v2_rejects_when_unfreeze_exceeds_frozen() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    enable_v2(&dp);
    let alice = Account {
        address: ALICE.to_vec(),
        balance: 0,
        frozen_v2: vec![FreezeV2Entry {
            r#type: 0,
            amount: 50 * PRECISION,
        }],
        ..Default::default()
    };
    accounts.put(&addr(ALICE), &alice).unwrap();
    let c = UnfreezeBalanceV2Contract {
        owner_address: ALICE.to_vec(),
        unfreeze_balance: 100 * PRECISION, // > frozen 50
        resource: 0,
    };
    let err = freeze_v2::validate_unfreeze_balance_v2(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::UnfreezeExceedsFrozen));
}

#[test]
fn unfreeze_v2_rejects_zero_or_negative_amount() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    enable_v2(&dp);
    let alice = Account {
        address: ALICE.to_vec(),
        balance: 0,
        frozen_v2: vec![FreezeV2Entry {
            r#type: 0,
            amount: 50 * PRECISION,
        }],
        ..Default::default()
    };
    accounts.put(&addr(ALICE), &alice).unwrap();
    for amt in [0i64, -PRECISION] {
        let c = UnfreezeBalanceV2Contract {
            owner_address: ALICE.to_vec(),
            unfreeze_balance: amt,
            resource: 0,
        };
        let err = freeze_v2::validate_unfreeze_balance_v2(&accounts, &dp, &c).unwrap_err();
        assert!(
            matches!(err, ActuatorError::UnfreezeExceedsFrozen),
            "amt={amt} got: {err:?}"
        );
    }
}

#[test]
fn unfreeze_v2_rejects_too_many_concurrent_unfreezes() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    enable_v2(&dp);
    use tron_proto::account::UnFreezeV2;
    let mut alice = Account {
        address: ALICE.to_vec(),
        balance: 0,
        frozen_v2: vec![FreezeV2Entry {
            r#type: 0,
            amount: 100 * PRECISION,
        }],
        ..Default::default()
    };
    for i in 0..freeze_v2::UNFREEZE_MAX_TIMES {
        alice.unfrozen_v2.push(UnFreezeV2 {
            r#type: 0,
            unfreeze_amount: PRECISION,
            unfreeze_expire_time: 1_000_000 + i as i64,
        });
    }
    accounts.put(&addr(ALICE), &alice).unwrap();
    let c = UnfreezeBalanceV2Contract {
        owner_address: ALICE.to_vec(),
        unfreeze_balance: PRECISION,
        resource: 0,
    };
    let err = freeze_v2::validate_unfreeze_balance_v2(&accounts, &dp, &c).unwrap_err();
    assert!(
        matches!(err, ActuatorError::TooManyUnfreezes { .. }),
        "got: {err:?}"
    );
}

// ============================================================
// UnfreezeBalanceV2 — weight + state coherence
// ============================================================

#[test]
fn unfreeze_v2_partial_unfreeze_only_subtracts_delta_from_global_weight() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    enable_v2(&dp);
    dp.save_latest_block_header_timestamp(1_000_000);
    put_account(&accounts, ALICE, 1000 * PRECISION);
    // Freeze 100 TRX bandwidth.
    let c_freeze = FreezeBalanceV2Contract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 100 * PRECISION,
        resource: 0,
    };
    freeze_v2::execute_freeze_balance_v2(&accounts, &dp, &c_freeze).unwrap();
    assert_eq!(dp.get_long(b"TOTAL_NET_WEIGHT").unwrap_or(0), 100);
    // Partial unfreeze of 30 TRX.
    let c_unfreeze = UnfreezeBalanceV2Contract {
        owner_address: ALICE.to_vec(),
        unfreeze_balance: 30 * PRECISION,
        resource: 0,
    };
    let votes = VotesStore::new(mem());
    let delegation = DelegationStore::new(mem());
    freeze_v2::execute_unfreeze_balance_v2(&accounts, &dp, &votes, &delegation, None, &c_unfreeze)
        .unwrap();
    assert_eq!(dp.get_long(b"TOTAL_NET_WEIGHT").unwrap_or(0), 70);
    let alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    let bw_slot = alice.frozen_v2.iter().find(|f| f.r#type == 0).unwrap();
    assert_eq!(bw_slot.amount, 70 * PRECISION);
    // Unfreeze record created with expire time = now + 14 days.
    assert_eq!(alice.unfrozen_v2.len(), 1);
    let unfreeze = &alice.unfrozen_v2[0];
    assert_eq!(unfreeze.unfreeze_amount, 30 * PRECISION);
    let expected_expire = 1_000_000 + 14 * 24 * 60 * 60 * 1000;
    assert_eq!(unfreeze.unfreeze_expire_time, expected_expire);
}

#[test]
fn unfreeze_v2_full_unfreeze_zeroes_resource_bucket_and_global_weight() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    enable_v2(&dp);
    put_account(&accounts, ALICE, 1000 * PRECISION);
    let c_freeze = FreezeBalanceV2Contract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 100 * PRECISION,
        resource: 1, // energy
    };
    freeze_v2::execute_freeze_balance_v2(&accounts, &dp, &c_freeze).unwrap();
    let c_unfreeze = UnfreezeBalanceV2Contract {
        owner_address: ALICE.to_vec(),
        unfreeze_balance: 100 * PRECISION,
        resource: 1,
    };
    let votes = VotesStore::new(mem());
    let delegation = DelegationStore::new(mem());
    freeze_v2::execute_unfreeze_balance_v2(&accounts, &dp, &votes, &delegation, None, &c_unfreeze)
        .unwrap();
    assert_eq!(dp.get_long(b"TOTAL_ENERGY_WEIGHT").unwrap_or(0), 0);
    let alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    let energy_slot = alice.frozen_v2.iter().find(|f| f.r#type == 1).unwrap();
    assert_eq!(energy_slot.amount, 0);
}
