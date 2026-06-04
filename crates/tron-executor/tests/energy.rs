//! Tests for `energy::consume_energy` — the post-VM energy-cost
//! billing that mirrors java-tron's `EnergyProcessor.useEnergy` plus
//! the TRX-fee fallback from `TransactionTrace.pay`.

use std::sync::Arc;

use hex_literal::hex;
use tron_chainbase::{AccountStore, DynamicPropertiesStore, KvBackend, MemBackend};
use tron_crypto::address::Address;
use tron_executor::energy::{
    consume_energy, pay_energy_bill, EnergyBill, EnergyCharge, EnergyError,
};
use tron_proto::account::{AccountResource, FreezeV2, Frozen};
use tron_proto::Account;

const ALICE: [u8; 21] = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

struct Env {
    accounts: AccountStore,
    dyn_props: DynamicPropertiesStore,
}

impl Env {
    fn new() -> Self {
        Self {
            accounts: AccountStore::new(mem()),
            dyn_props: DynamicPropertiesStore::new(mem()),
        }
    }
}

fn put(accounts: &AccountStore, addr: [u8; 21], a: Account) {
    accounts.put(&Address::from_raw(addr), &a).unwrap();
}

/// Set up the global energy parameters so the V2 limit formula yields
/// a non-zero per-account cap. `total_energy_limit` is denominated in
/// energy units; `total_energy_weight` in TRX units (NOT sun).
fn seed_global_energy(env: &Env, total_limit: i64, total_weight: i64) {
    env.dyn_props.save_total_energy_limit(total_limit);
    env.dyn_props.save_total_energy_current_limit(total_limit);
    env.dyn_props.save_total_energy_weight(total_weight);
    env.dyn_props.save_unfreeze_delay_days(1); // turn on supportUnfreezeDelay → V2 formula
}

#[test]
fn frozen_energy_quota_covers_full_charge() {
    let env = Env::new();
    seed_global_energy(&env, /*total_limit=*/ 100_000_000_000, /*total_weight=*/ 100);
    let mut acct = Account {
        address: ALICE.to_vec(),
        balance: 1_000,
        ..Default::default()
    };
    // 100 TRX frozen for energy.
    acct.frozen_v2.push(FreezeV2 { r#type: 1, amount: 100_000_000 });
    put(&env.accounts, ALICE, acct);

    let charge = consume_energy(&env.accounts, &env.dyn_props, &Address::from_raw(ALICE), 1_000, 0)
        .expect("ok");
    match charge {
        EnergyCharge::Frozen { energy_used, .. } => assert_eq!(energy_used, 1_000),
        other => panic!("expected Frozen, got {other:?}"),
    }
    let after = env.accounts.get(&Address::from_raw(ALICE)).unwrap().unwrap();
    // Balance untouched.
    assert_eq!(after.balance, 1_000);
    let res = after.account_resource.unwrap();
    assert!(res.energy_usage > 0);
    assert_eq!(res.latest_consume_time_for_energy, 0);
}

#[test]
fn zero_quota_falls_back_to_trx_fee() {
    let env = Env::new();
    // No frozen energy. Caller has 1M sun balance, energy_fee defaults
    // to 100 sun/energy. Charge 1000 energy → 100_000 sun fee.
    seed_global_energy(&env, /*total_limit=*/ 0, /*total_weight=*/ 0);
    put(
        &env.accounts,
        ALICE,
        Account { address: ALICE.to_vec(), balance: 1_000_000, ..Default::default() },
    );

    let charge = consume_energy(&env.accounts, &env.dyn_props, &Address::from_raw(ALICE), 1_000, 0)
        .expect("ok");
    match charge {
        EnergyCharge::Fee { energy_used, fee_sun } => {
            assert_eq!(energy_used, 1_000);
            assert_eq!(fee_sun, 100_000);
        }
        other => panic!("expected Fee, got {other:?}"),
    }
    let after = env.accounts.get(&Address::from_raw(ALICE)).unwrap().unwrap();
    assert_eq!(after.balance, 900_000);
    // Burn counter bumped.
    assert_eq!(env.dyn_props.burn_trx_amount(), 100_000);
    assert_eq!(env.dyn_props.total_transaction_cost(), 100_000);
}

#[test]
fn partial_quota_then_fee_for_remainder() {
    let env = Env::new();
    // V2 formula: limit = froze * totalLimit / (TRX_PRECISION * totalWeight)
    // With froze=1_000_000 sun (1 TRX), totalLimit=2000, totalWeight=2 TRX,
    // limit = 1_000_000 * 2000 / (1_000_000 * 2) = 1000 energy.
    seed_global_energy(&env, /*total_limit=*/ 2000, /*total_weight=*/ 2);
    let mut acct = Account {
        address: ALICE.to_vec(),
        balance: 1_000_000,
        ..Default::default()
    };
    acct.frozen_v2.push(FreezeV2 { r#type: 1, amount: 1_000_000 });
    put(&env.accounts, ALICE, acct);

    // Charge 1500 energy — 1000 covered by frozen, 500 by fee.
    let charge = consume_energy(&env.accounts, &env.dyn_props, &Address::from_raw(ALICE), 1_500, 0)
        .expect("ok");
    let (frozen, fee) = match charge {
        EnergyCharge::Mixed {
            energy_used,
            energy_from_frozen,
            fee_sun,
            ..
        } => {
            assert_eq!(energy_used, 1_500);
            (energy_from_frozen, fee_sun)
        }
        other => panic!("expected Mixed, got {other:?}"),
    };
    assert_eq!(frozen, 1_000);
    assert_eq!(fee, 500 * 100);
    let after = env.accounts.get(&Address::from_raw(ALICE)).unwrap().unwrap();
    assert_eq!(after.balance, 1_000_000 - 50_000);
}

#[test]
fn insufficient_balance_for_fee_errors_out_atomically() {
    let env = Env::new();
    seed_global_energy(&env, 0, 0);
    // Tiny balance → can't cover any fee.
    put(
        &env.accounts,
        ALICE,
        Account { address: ALICE.to_vec(), balance: 100, ..Default::default() },
    );
    let err = consume_energy(&env.accounts, &env.dyn_props, &Address::from_raw(ALICE), 1_000, 0)
        .unwrap_err();
    assert!(matches!(err, EnergyError::Insufficient { .. }));
    // Balance UNCHANGED on failure.
    let after = env.accounts.get(&Address::from_raw(ALICE)).unwrap().unwrap();
    assert_eq!(after.balance, 100);
    assert_eq!(env.dyn_props.burn_trx_amount(), 0);
}

#[test]
fn missing_account_yields_error() {
    let env = Env::new();
    seed_global_energy(&env, 0, 0);
    let err = consume_energy(&env.accounts, &env.dyn_props, &Address::from_raw(ALICE), 100, 0)
        .unwrap_err();
    assert!(matches!(err, EnergyError::AccountMissing));
}

#[test]
fn adaptive_energy_bumps_block_energy_usage() {
    let env = Env::new();
    seed_global_energy(&env, 100_000_000_000, 100);
    env.dyn_props.put_long(b"ALLOW_ADAPTIVE_ENERGY", 1);
    let mut acct = Account {
        address: ALICE.to_vec(),
        balance: 1_000,
        ..Default::default()
    };
    acct.frozen_v2.push(FreezeV2 { r#type: 1, amount: 100_000_000 });
    put(&env.accounts, ALICE, acct);

    consume_energy(&env.accounts, &env.dyn_props, &Address::from_raw(ALICE), 12_345, 0).unwrap();
    assert_eq!(env.dyn_props.block_energy_usage(), 12_345);

    consume_energy(&env.accounts, &env.dyn_props, &Address::from_raw(ALICE), 100, 0).unwrap();
    assert_eq!(env.dyn_props.block_energy_usage(), 12_445);
}

#[test]
fn adaptive_disabled_does_not_bump_block_energy_usage() {
    let env = Env::new();
    seed_global_energy(&env, 100_000_000_000, 100);
    // ALLOW_ADAPTIVE_ENERGY unset (defaults to 0).
    let mut acct = Account {
        address: ALICE.to_vec(),
        balance: 1_000,
        ..Default::default()
    };
    acct.frozen_v2.push(FreezeV2 { r#type: 1, amount: 100_000_000 });
    put(&env.accounts, ALICE, acct);

    consume_energy(&env.accounts, &env.dyn_props, &Address::from_raw(ALICE), 999, 0).unwrap();
    assert_eq!(env.dyn_props.block_energy_usage(), 0);
}

#[test]
fn legacy_v1_frozen_for_energy_counted() {
    let env = Env::new();
    // V1 freeze: AccountResource.frozen_balance_for_energy.frozen_balance.
    // Total weight needs to include this 100-TRX entry equivalent.
    env.dyn_props.save_total_energy_limit(100_000_000_000);
    env.dyn_props.save_total_energy_current_limit(100_000_000_000);
    env.dyn_props.save_total_energy_weight(100);
    env.dyn_props.save_unfreeze_delay_days(1);
    let acct = Account {
        address: ALICE.to_vec(),
        balance: 1_000,
        account_resource: Some(AccountResource {
            frozen_balance_for_energy: Some(Frozen {
                frozen_balance: 100_000_000,
                expire_time: 0,
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    put(&env.accounts, ALICE, acct);

    let charge = consume_energy(&env.accounts, &env.dyn_props, &Address::from_raw(ALICE), 500, 0)
        .expect("ok");
    assert!(matches!(charge, EnergyCharge::Frozen { .. }));
}

#[test]
fn zero_energy_call_is_noop_no_state_change() {
    let env = Env::new();
    seed_global_energy(&env, 100_000_000_000, 100);
    put(
        &env.accounts,
        ALICE,
        Account { address: ALICE.to_vec(), balance: 10_000, ..Default::default() },
    );
    let before = env.accounts.get(&Address::from_raw(ALICE)).unwrap().unwrap();
    let charge = consume_energy(&env.accounts, &env.dyn_props, &Address::from_raw(ALICE), 0, 0)
        .expect("ok");
    assert!(matches!(charge, EnergyCharge::Frozen { energy_used: 0, .. }));
    let after = env.accounts.get(&Address::from_raw(ALICE)).unwrap().unwrap();
    assert_eq!(after.balance, before.balance);
}

// =============================================================================
// pay_energy_bill — origin / caller split (java-tron's
// `ReceiptCapsule.payEnergyBill`). For TriggerSmartContract, the
// contract's deployer subsidizes `100 - consume_user_resource_percent`
// of each call's energy, clamped by `origin_energy_limit` and the
// origin's remaining frozen quota.
// =============================================================================

const ORIGIN: [u8; 21] = hex!("411111111111111111111111111111111111111111");
const CALLER: [u8; 21] = hex!("412222222222222222222222222222222222222222");

/// Seed `addr` with a populated account row that has the given amount
/// of TRX frozen for energy (TRX units, not sun) and the given balance.
fn put_account_with_energy(env: &Env, addr: [u8; 21], frozen_trx: i64, balance_sun: i64) {
    let mut acct = Account {
        address: addr.to_vec(),
        balance: balance_sun,
        ..Default::default()
    };
    if frozen_trx > 0 {
        // FreezeV2.amount is in sun. `frozen_trx * TRX_PRECISION` (=1e6).
        acct.frozen_v2.push(FreezeV2 {
            r#type: 1, // ENERGY
            amount: frozen_trx * 1_000_000,
        });
    }
    put(&env.accounts, addr, acct);
}

#[test]
fn split_with_no_origin_charges_caller_for_everything() {
    let env = Env::new();
    seed_global_energy(&env, 100_000_000_000, 100);
    put_account_with_energy(&env, CALLER, 100, 0);

    let bill = pay_energy_bill(
        &env.accounts,
        &env.dyn_props,
        &Address::from_raw(CALLER),
        None, // no origin (e.g. CreateSmartContract, or contract row missing)
        /*origin_energy_limit=*/ 0,
        /*consume_user_resource_percent=*/ 0,
        /*energy_used=*/ 1_000,
        /*now_slot=*/ 0,
    )
    .expect("bill ok");
    assert!(bill.origin_charge.is_none(), "no origin → no origin charge");
    match bill.caller_charge {
        EnergyCharge::Frozen { energy_used, .. } => assert_eq!(energy_used, 1_000),
        other => panic!("expected caller Frozen, got {other:?}"),
    }
}

#[test]
fn split_when_caller_equals_origin_collapses_to_caller_pays_all() {
    let env = Env::new();
    seed_global_energy(&env, 100_000_000_000, 100);
    put_account_with_energy(&env, CALLER, 100, 0);

    let bill = pay_energy_bill(
        &env.accounts,
        &env.dyn_props,
        &Address::from_raw(CALLER),
        Some(&Address::from_raw(CALLER)), // caller IS origin
        /*origin_energy_limit=*/ 1_000_000,
        /*consume_user_resource_percent=*/ 30, // would normally split 70/30
        /*energy_used=*/ 1_000,
        /*now_slot=*/ 0,
    )
    .expect("bill ok");
    assert!(bill.origin_charge.is_none(), "caller==origin → no split");
    match bill.caller_charge {
        EnergyCharge::Frozen { energy_used, .. } => assert_eq!(energy_used, 1_000),
        other => panic!("expected Frozen, got {other:?}"),
    }
}

#[test]
fn split_charges_origin_their_percentage_when_quota_covers_it() {
    let env = Env::new();
    seed_global_energy(&env, 100_000_000_000, 200);
    // Origin and caller each have 100 TRX frozen — plenty of quota.
    put_account_with_energy(&env, ORIGIN, 100, 0);
    put_account_with_energy(&env, CALLER, 100, 0);

    // consume_user_resource_percent = 30 → origin pays 70%, caller 30%.
    let bill = pay_energy_bill(
        &env.accounts,
        &env.dyn_props,
        &Address::from_raw(CALLER),
        Some(&Address::from_raw(ORIGIN)),
        /*origin_energy_limit=*/ 10_000_000, // way above the actual usage
        /*consume_user_resource_percent=*/ 30,
        /*energy_used=*/ 1_000,
        /*now_slot=*/ 0,
    )
    .expect("bill ok");

    // Origin should be charged 700 energy (= 1000 * 70 / 100).
    let origin_charge = bill.origin_charge.expect("split applied");
    match origin_charge {
        EnergyCharge::Frozen { energy_used, .. } => assert_eq!(energy_used, 700),
        other => panic!("expected origin Frozen, got {other:?}"),
    }
    // Caller picks up the remaining 300 from its own frozen quota.
    match bill.caller_charge {
        EnergyCharge::Frozen { energy_used, .. } => assert_eq!(energy_used, 300),
        other => panic!("expected caller Frozen, got {other:?}"),
    }
}

#[test]
fn split_clamps_origin_share_at_origin_energy_limit() {
    let env = Env::new();
    seed_global_energy(&env, 100_000_000_000, 200);
    put_account_with_energy(&env, ORIGIN, 100, 0);
    put_account_with_energy(&env, CALLER, 100, 0);

    // Origin's per-tx subsidy cap is just 100 energy. The math says
    // origin should pay 700 (70% of 1000), but the limit drops it to
    // 100 — caller picks up the difference (900).
    let bill = pay_energy_bill(
        &env.accounts,
        &env.dyn_props,
        &Address::from_raw(CALLER),
        Some(&Address::from_raw(ORIGIN)),
        /*origin_energy_limit=*/ 100,
        /*consume_user_resource_percent=*/ 30,
        /*energy_used=*/ 1_000,
        /*now_slot=*/ 0,
    )
    .expect("bill ok");

    let origin_used = match bill.origin_charge.expect("split") {
        EnergyCharge::Frozen { energy_used, .. } => energy_used,
        other => panic!("expected Frozen, got {other:?}"),
    };
    assert_eq!(origin_used, 100, "origin clamped by origin_energy_limit");

    let caller_used = match bill.caller_charge {
        EnergyCharge::Frozen { energy_used, .. } => energy_used,
        other => panic!("expected Frozen, got {other:?}"),
    };
    assert_eq!(caller_used, 900);
}

#[test]
fn split_clamps_origin_share_at_origin_quota_left() {
    let env = Env::new();
    seed_global_energy(&env, 100_000_000_000, 200);
    // Origin has only 1 TRX frozen → ~500_000_000 / 200 = 2_500_000
    // global limit allocated to origin's 1 TRX out of 200 total
    // → origin's quota is small. Use a very tight origin balance so
    // the test is unambiguous.
    put_account_with_energy(&env, ORIGIN, 1, 0); // 1 TRX frozen for energy
    put_account_with_energy(&env, CALLER, 100, 0);

    let bill = pay_energy_bill(
        &env.accounts,
        &env.dyn_props,
        &Address::from_raw(CALLER),
        Some(&Address::from_raw(ORIGIN)),
        /*origin_energy_limit=*/ 10_000_000_000, // no contract-side cap
        /*consume_user_resource_percent=*/ 30, // origin pays 70%
        /*energy_used=*/ 10_000_000_000, // hugely over origin's tiny quota
        /*now_slot=*/ 0,
    );
    // The caller may or may not have enough quota to cover the rest —
    // for this test the important thing is origin's share is bounded
    // by what it can actually pay from frozen, not by the math.
    let bill = bill.expect("caller has plenty of quota to cover the rest");

    // Origin should pay at most its quota left, never the full 7B
    // that the percent split would have computed.
    let origin_used = match bill.origin_charge.expect("split") {
        EnergyCharge::Frozen { energy_used, .. } => energy_used,
        other => panic!("expected Frozen, got {other:?}"),
    };
    // 1 TRX out of 200 weight → origin's slice of the 100_000_000_000
    // global limit = 500_000_000.
    let expected_origin_max: i64 = 500_000_000;
    assert!(
        origin_used <= expected_origin_max,
        "origin used {origin_used} should not exceed its quota cap {expected_origin_max}"
    );
    assert!(origin_used > 0, "origin should pay something");

    // Caller covers the rest. With 100 TRX frozen they have plenty.
    let _ = bill.caller_charge;
}

#[test]
fn split_with_consume_user_resource_percent_100_charges_caller_for_everything() {
    // Most user-facing contracts set percent=100 (caller pays all).
    // The split degenerates: origin contributes 0.
    let env = Env::new();
    seed_global_energy(&env, 100_000_000_000, 200);
    put_account_with_energy(&env, ORIGIN, 100, 0);
    put_account_with_energy(&env, CALLER, 100, 0);

    let bill = pay_energy_bill(
        &env.accounts,
        &env.dyn_props,
        &Address::from_raw(CALLER),
        Some(&Address::from_raw(ORIGIN)),
        /*origin_energy_limit=*/ 10_000_000,
        /*consume_user_resource_percent=*/ 100,
        /*energy_used=*/ 1_000,
        /*now_slot=*/ 0,
    )
    .expect("bill ok");

    assert!(
        bill.origin_charge.is_none(),
        "percent=100 → origin contributes 0 → no origin charge recorded"
    );
    match bill.caller_charge {
        EnergyCharge::Frozen { energy_used, .. } => assert_eq!(energy_used, 1_000),
        other => panic!("expected Frozen, got {other:?}"),
    }
}

#[test]
fn split_clamps_out_of_range_consume_user_resource_percent() {
    // Pathological contract row with percent < 0 or > 100 → java-tron
    // clamps to [0, 100]. We mirror.
    let env = Env::new();
    seed_global_energy(&env, 100_000_000_000, 200);
    put_account_with_energy(&env, ORIGIN, 100, 0);
    put_account_with_energy(&env, CALLER, 100, 0);

    // percent = 200 → max(0, 100 - 200) = 0 → caller pays everything.
    let bill = pay_energy_bill(
        &env.accounts,
        &env.dyn_props,
        &Address::from_raw(CALLER),
        Some(&Address::from_raw(ORIGIN)),
        /*origin_energy_limit=*/ 10_000_000,
        /*consume_user_resource_percent=*/ 200,
        /*energy_used=*/ 1_000,
        /*now_slot=*/ 0,
    )
    .expect("bill ok");
    assert!(bill.origin_charge.is_none());

    // percent = -50 → max(0, 100 - (-50)) = 150, clamped to 100 →
    // origin pays everything.
    let bill = pay_energy_bill(
        &env.accounts,
        &env.dyn_props,
        &Address::from_raw(CALLER),
        Some(&Address::from_raw(ORIGIN)),
        /*origin_energy_limit=*/ 10_000_000,
        /*consume_user_resource_percent=*/ -50,
        /*energy_used=*/ 1_000,
        /*now_slot=*/ 0,
    )
    .expect("bill ok");
    let origin_used = match bill.origin_charge.expect("split") {
        EnergyCharge::Frozen { energy_used, .. } => energy_used,
        other => panic!("expected Frozen, got {other:?}"),
    };
    assert_eq!(origin_used, 1_000, "clamped percent=100 → origin pays everything");
}

#[test]
fn split_with_missing_origin_account_falls_through_to_caller() {
    let env = Env::new();
    seed_global_energy(&env, 100_000_000_000, 100);
    // ORIGIN has no stored account row — origin_quota_left returns 0,
    // so the split's clamp drops origin_usage to 0 and caller pays
    // everything. Matches java-tron's `Objects.isNull(origin)` arm in
    // payEnergyBill (with AllowTvmConstantinople set, the standard
    // mainnet config).
    put_account_with_energy(&env, CALLER, 100, 0);

    let bill = pay_energy_bill(
        &env.accounts,
        &env.dyn_props,
        &Address::from_raw(CALLER),
        Some(&Address::from_raw(ORIGIN)),
        /*origin_energy_limit=*/ 10_000_000,
        /*consume_user_resource_percent=*/ 30,
        /*energy_used=*/ 1_000,
        /*now_slot=*/ 0,
    )
    .expect("bill ok");
    assert!(bill.origin_charge.is_none(), "no origin row → no origin charge");
    match bill.caller_charge {
        EnergyCharge::Frozen { energy_used, .. } => assert_eq!(energy_used, 1_000),
        other => panic!("expected Frozen, got {other:?}"),
    }
}

#[test]
fn split_origin_zero_origin_energy_limit_charges_caller_for_everything() {
    // origin_energy_limit = 0 clamps origin_usage to 0 regardless of
    // percent. This is the "deployer turned off subsidy" knob.
    let env = Env::new();
    seed_global_energy(&env, 100_000_000_000, 200);
    put_account_with_energy(&env, ORIGIN, 100, 0);
    put_account_with_energy(&env, CALLER, 100, 0);

    let bill = pay_energy_bill(
        &env.accounts,
        &env.dyn_props,
        &Address::from_raw(CALLER),
        Some(&Address::from_raw(ORIGIN)),
        /*origin_energy_limit=*/ 0,
        /*consume_user_resource_percent=*/ 30,
        /*energy_used=*/ 1_000,
        /*now_slot=*/ 0,
    )
    .expect("bill ok");
    assert!(bill.origin_charge.is_none(), "origin_energy_limit=0 → no origin charge");
    match bill.caller_charge {
        EnergyCharge::Frozen { energy_used, .. } => assert_eq!(energy_used, 1_000),
        other => panic!("expected Frozen, got {other:?}"),
    }
}

#[test]
fn split_returns_bill_struct_shape() {
    // Belt-and-braces — pin the public struct exists and is debuggable.
    let env = Env::new();
    seed_global_energy(&env, 100_000_000_000, 100);
    put_account_with_energy(&env, CALLER, 100, 0);
    let bill: EnergyBill = pay_energy_bill(
        &env.accounts,
        &env.dyn_props,
        &Address::from_raw(CALLER),
        None,
        0,
        100,
        500,
        0,
    )
    .unwrap();
    let _ = format!("{bill:?}");
}
