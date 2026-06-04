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
use tron_chainbase::{AccountStore, DynamicPropertiesStore, KvBackend, MemBackend};
use tron_crypto::address::Address;
use tron_proto::account::{Frozen, FreezeV2 as FreezeV2Entry};
use tron_proto::{
    Account, AccountType, FreezeBalanceContract, FreezeBalanceV2Contract,
    UnfreezeBalanceContract, UnfreezeBalanceV2Contract,
};

const ALICE: [u8; 21] = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");

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
    let c = FreezeBalanceContract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 10 * PRECISION,
        frozen_duration: 3,
        resource: 0,
        receiver_address: Vec::new(),
    };
    let err = freeze::validate_freeze_balance(&accounts, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::OwnerAccountMissing), "got: {err:?}");
}

#[test]
fn freeze_v1_rejects_below_minimum_amount() {
    let accounts = AccountStore::new(mem());
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
        let err = freeze::validate_freeze_balance(&accounts, &c).unwrap_err();
        assert!(
            matches!(err, ActuatorError::FreezeTooSmall),
            "amt={amt} got: {err:?}"
        );
    }
}

#[test]
fn freeze_v1_rejects_negative_amount() {
    let accounts = AccountStore::new(mem());
    put_account(&accounts, ALICE, 100 * PRECISION);
    let c = FreezeBalanceContract {
        owner_address: ALICE.to_vec(),
        frozen_balance: -PRECISION,
        frozen_duration: 3,
        resource: 0,
        receiver_address: Vec::new(),
    };
    let err = freeze::validate_freeze_balance(&accounts, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::FreezeTooSmall), "got: {err:?}");
}

#[test]
fn freeze_v1_rejects_insufficient_balance() {
    let accounts = AccountStore::new(mem());
    put_account(&accounts, ALICE, 5 * PRECISION);
    let c = FreezeBalanceContract {
        owner_address: ALICE.to_vec(),
        frozen_balance: 10 * PRECISION,
        frozen_duration: 3,
        resource: 0,
        receiver_address: Vec::new(),
    };
    let err = freeze::validate_freeze_balance(&accounts, &c).unwrap_err();
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
    put_account(&accounts, ALICE, 100 * PRECISION);
    for r in [-1, 3, 99, i32::MAX] {
        let c = FreezeBalanceContract {
            owner_address: ALICE.to_vec(),
            frozen_balance: 10 * PRECISION,
            frozen_duration: 3,
            resource: r,
            receiver_address: Vec::new(),
        };
        let err = freeze::validate_freeze_balance(&accounts, &c).unwrap_err();
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
    freeze::execute_freeze_balance(&accounts, &dp, &c).unwrap();
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
    freeze::execute_freeze_balance(&accounts, &dp, &c).unwrap();
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
    freeze::execute_freeze_balance(&accounts, &dp, &c).unwrap();
    assert_eq!(dp.get_long(b"TOTAL_NET_WEIGHT").unwrap_or(0), 0);
    assert_eq!(dp.get_long(b"TOTAL_ENERGY_WEIGHT").unwrap_or(0), 0);
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
    let err = freeze::validate_unfreeze_balance(&accounts, &dp, &c).unwrap_err();
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
    let err = freeze::validate_unfreeze_balance(&accounts, &dp, &c).unwrap_err();
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
    let err = freeze::validate_unfreeze_balance(&accounts, &dp, &c).unwrap_err();
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
    freeze::validate_unfreeze_balance(&accounts, &dp, &c).unwrap();
    freeze::execute_unfreeze_balance(&accounts, &dp, &c).unwrap();
    let alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    // Only the expired 10 TRX returned to balance.
    assert_eq!(alice.balance, 10 * PRECISION);
    // The future entry remains.
    assert_eq!(alice.frozen.len(), 1);
    assert_eq!(alice.frozen[0].frozen_balance, 20 * PRECISION);
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
fn freeze_v2_tron_power_does_not_touch_global_net_or_energy_weights() {
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
    freeze_v2::execute_unfreeze_balance_v2(&accounts, &dp, &c_unfreeze).unwrap();
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
    freeze_v2::execute_unfreeze_balance_v2(&accounts, &dp, &c_unfreeze).unwrap();
    assert_eq!(dp.get_long(b"TOTAL_ENERGY_WEIGHT").unwrap_or(0), 0);
    let alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    let energy_slot = alice.frozen_v2.iter().find(|f| f.r#type == 1).unwrap();
    assert_eq!(energy_slot.amount, 0);
}
