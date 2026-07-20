//! Tests for `energy::consume_energy` — the post-VM energy-cost
//! billing that mirrors java-tron's `EnergyProcessor.useEnergy` plus
//! the TRX-fee fallback from `TransactionTrace.pay`.

use std::sync::Arc;

use hex_literal::hex;
use tron_chainbase::{AccountStore, DynamicPropertiesStore, KvBackend, MemBackend};
use tron_crypto::address::Address;
use tron_executor::energy::{
    account_energy_limit_with_fix_ratio, account_energy_limit_with_float_ratio, consume_energy,
    effective_origin_energy_limit, get_pre_tx_energy, pay_energy_bill, reset_energy_pre_consume,
    revert_energy_pre_consume, total_energy_limit_with_float_ratio, vm_energy_budget_create,
    vm_energy_budget_trigger, EnergyBill, EnergyCharge, EnergyError,
};
use tron_proto::account::{AccountResource, FreezeV2, Frozen};
use tron_proto::Account;

const ALICE: [u8; 21] = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");
const BOB: [u8; 21] = hex!("41a0b4750e2cd76e19dca331f3cb2b6b7f3d5f8a9c");

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
    // Model the post-#49 mainnet era (the validated snapshot range): a disposed
    // energy fee is burned (BURN_TRX_AMOUNT) rather than credited to the
    // blackhole account. Pre-#49 credit behavior is covered by tron-chainbase's
    // dispose_fee_to_blackhole unit tests.
    env.dyn_props.put_long(b"ALLOW_BLACKHOLE_OPTIMIZATION", 1);
    // Model a post-ENERGY_LIMIT_HARD_FORK (4,727,890) block so the VM energy
    // budget uses the FIX ratio; the pre-fork float-ratio path has its own test.
    env.dyn_props.save_latest_block_header_number(60_000_000);
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
    // Burn counter bumped (no fee pool, no blackhole-opt → burn).
    assert_eq!(env.dyn_props.burn_trx_amount(), 100_000);
    // TOTAL_TRANSACTION_COST is NOT bumped by energy fees: java only adds to it
    // in the bandwidth path (BandwidthProcessor.useTransactionFee), never in the
    // energy path (ReceiptCapsule.payEnergyBill).
    assert_eq!(env.dyn_props.total_transaction_cost(), 0);
}

#[test]
fn energy_fee_pool_excludes_out_of_time() {
    use tron_executor::energy::set_tx_out_of_time;
    // With ALLOW_TRANSACTION_FEE_POOL on, a normal tx's energy fee goes to the
    // transaction-fee pool, but an OUT_OF_TIME tx's energy fee is EXCLUDED and
    // burns instead — java `ReceiptCapsule.payEnergyBill`'s
    // `supportTransactionFeePool() && !contractResult.equals(OUT_OF_TIME)`.
    let env = Env::new();
    seed_global_energy(&env, /*total_limit=*/ 0, /*total_weight=*/ 0); // no frozen → full fee
    env.dyn_props.put_long(b"ALLOW_TRANSACTION_FEE_POOL", 1);
    put(
        &env.accounts,
        ALICE,
        Account { address: ALICE.to_vec(), balance: 1_000_000, ..Default::default() },
    );

    // Normal (not OUT_OF_TIME): 1000 energy × 100 sun = 100_000 fee → pool.
    set_tx_out_of_time(false);
    consume_energy(&env.accounts, &env.dyn_props, &Address::from_raw(ALICE), 1_000, 0).unwrap();
    assert_eq!(env.dyn_props.transaction_fee_pool(), 100_000);
    assert_eq!(env.dyn_props.burn_trx_amount(), 0);

    // OUT_OF_TIME: the fee is excluded from the pool and burned instead.
    set_tx_out_of_time(true);
    consume_energy(&env.accounts, &env.dyn_props, &Address::from_raw(ALICE), 1_000, 0).unwrap();
    assert_eq!(env.dyn_props.transaction_fee_pool(), 100_000, "pool unchanged for OUT_OF_TIME");
    assert_eq!(env.dyn_props.burn_trx_amount(), 100_000, "OUT_OF_TIME energy fee burned");

    // Reset the per-thread flag so sibling tests see the default.
    set_tx_out_of_time(false);
}

#[test]
fn float_ratio_budget_pre_energy_limit_hard_fork() {
    // VME-1: pre-ENERGY_LIMIT_HARD_FORK (block 4,727,890) the VM energy budget
    // uses the FLOAT ratio. With no frozen energy it reduces to feeLimit/spe and
    // matches the fix ratio; the caller/creator split has no per-origin cap.
    let env = Env::new();
    let caller = Account { address: ALICE.to_vec(), balance: 100_000_000, ..Default::default() };
    let fee_limit = 1_000_000;
    let spe = 100; // default sun_per_energy (energy_fee unset)

    let caller_budget =
        account_energy_limit_with_float_ratio(&caller, &env.dyn_props, fee_limit, 0, 0);
    assert_eq!(caller_budget, fee_limit / spe, "no frozen energy → feeLimit / spe");
    // No frozen energy → the float ratio equals the fix ratio.
    assert_eq!(
        caller_budget,
        account_energy_limit_with_fix_ratio(&caller, &env.dyn_props, fee_limit, 0, 0)
    );

    // creator == caller → just the caller budget.
    assert_eq!(
        total_energy_limit_with_float_ratio(&caller, &caller, &env.dyn_props, 50, fee_limit, 0, 0),
        caller_budget
    );

    // Distinct creator with no frozen energy → caller + 0 (the else branch).
    let creator = Account { address: BOB.to_vec(), balance: 0, ..Default::default() };
    assert_eq!(
        total_energy_limit_with_float_ratio(&creator, &caller, &env.dyn_props, 50, fee_limit, 0, 0),
        caller_budget,
        "creator with no frozen energy adds nothing"
    );
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

/// Covers the NO-CAPTURE arm only: this calls `pay_energy_bill` with no prior
/// budget call, so the origin clamp comes from the live `origin_quota_left`
/// read — java `ReceiptCapsule.getOriginUsage` arms 2/3, i.e. the pre-#52 era.
/// From ALLOW_TVM_FREEZE onward the clamp is the budget-time capture instead;
/// the `freeze_only_*` tests below cover that.
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

    // java-tron's payEnergyBill calls useEnergy(origin, 0, now) even when the
    // origin contributes 0 (percent=100): the origin's energy_usage is still
    // decayed + window rewritten. So the charge IS recorded — as Frozen with
    // energy_used == 0 — not absent.
    match bill.origin_charge.expect("origin still decayed at 0 usage") {
        EnergyCharge::Frozen { energy_used, .. } => assert_eq!(energy_used, 0),
        other => panic!("expected Frozen{{0}}, got {other:?}"),
    }
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
    // percent=200 → origin share clamps to 0, but the origin is still decayed
    // (java useEnergy(origin, 0, now)) → Frozen with energy_used == 0.
    match bill.origin_charge.expect("origin still decayed at 0 usage") {
        EnergyCharge::Frozen { energy_used, .. } => assert_eq!(energy_used, 0),
        other => panic!("expected Frozen{{0}}, got {other:?}"),
    }

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
    // origin_energy_limit=0 clamps the origin's share to 0, but the origin
    // account EXISTS, so java still decays it (useEnergy(origin, 0, now)) →
    // Frozen with energy_used == 0 (not absent).
    match bill.origin_charge.expect("existing origin still decayed at 0 usage") {
        EnergyCharge::Frozen { energy_used, .. } => assert_eq!(energy_used, 0),
        other => panic!("expected Frozen{{0}}, got {other:?}"),
    }
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

// ===========================================================================
// VM energy BUDGET (java VMActuator.getTotalEnergyLimit, fix-ratio path).
// Pre-execution read that decides the gas_limit handed to the VM — distinct
// from the post-execution charge above.
// ===========================================================================

#[test]
fn origin_energy_limit_zero_remaps_to_creator_default() {
    // java Constant: PB_DEFAULT_ENERGY_LIMIT (0) -> CREATOR_DEFAULT (1000*10000).
    assert_eq!(effective_origin_energy_limit(0), 10_000_000);
    assert_eq!(effective_origin_energy_limit(1), 1);
    assert_eq!(effective_origin_energy_limit(50_000_000), 50_000_000);
}

#[test]
fn caller_budget_capped_by_balance_minus_call_value() {
    // Replicates mainnet tx 9928cfa6 (block 83317250): the caller has no
    // frozen energy and sends call_value with the trigger, so the budget is
    // (balance - call_value)/energy_fee, NOT the larger fee_limit/energy_fee.
    // java ran OUT_OF_ENERGY at 14_240; the old budget (fee_limit/100 = 68_116)
    // wrongly let us succeed.
    let env = Env::new();
    let caller = Account {
        address: ALICE.to_vec(),
        balance: 220_424_000,
        ..Default::default()
    };
    // energy_fee defaults to 100. fee_limit/100 = 68_116 but only
    // (220_424_000 - 219_000_000)/100 = 14_240 is backable by balance.
    let budget = account_energy_limit_with_fix_ratio(
        &caller,
        &env.dyn_props,
        /*fee_limit=*/ 6_811_600,
        /*call_value=*/ 219_000_000,
        /*now_slot=*/ 0,
    );
    assert_eq!(budget, 14_240);
}

#[test]
fn caller_budget_capped_by_fee_limit_when_balance_ample() {
    let env = Env::new();
    let caller = Account {
        address: ALICE.to_vec(),
        balance: 1_000_000_000,
        ..Default::default()
    };
    // balance/100 = 10_000_000 >> fee_limit/100 = 5_000; min picks fee_limit.
    let budget = account_energy_limit_with_fix_ratio(&caller, &env.dyn_props, 500_000, 0, 0);
    assert_eq!(budget, 5_000);
}

#[test]
fn caller_frozen_energy_adds_to_budget() {
    // leftFrozen + balance/fee both count toward `available`.
    let env = Env::new();
    seed_global_energy(&env, /*total_limit=*/ 100_000_000_000, /*total_weight=*/ 1_000);
    let mut caller = Account {
        address: ALICE.to_vec(),
        balance: 0,
        ..Default::default()
    };
    caller.frozen_v2.push(FreezeV2 { r#type: 1, amount: 1_000_000_000 });
    // No balance → available = leftFrozen only. fee_limit huge so the min
    // picks `available`. Budget must equal the account's left frozen energy.
    let left = tron_executor::energy::account_left_energy_from_freeze(&caller, &env.dyn_props, 0);
    assert!(left > 0, "frozen energy should yield a non-zero quota");
    let budget =
        account_energy_limit_with_fix_ratio(&caller, &env.dyn_props, i64::MAX / 2, 0, 0);
    assert_eq!(budget, left);
}

#[test]
fn trigger_budget_adds_creator_subsidy_capped_by_origin_energy_limit() {
    let env = Env::new();
    seed_global_energy(&env, 100_000_000_000, 1_000);
    let caller = Account {
        address: ALICE.to_vec(),
        balance: 100_000,
        ..Default::default()
    };
    // caller_only = min(100_000/100, fee_limit/100) = min(1000, 100000) = 1000.
    let caller_only =
        account_energy_limit_with_fix_ratio(&caller, &env.dyn_props, 10_000_000, 0, 0);
    assert_eq!(caller_only, 1_000);
    // Creator holds lots of frozen energy; origin_energy_limit caps its
    // subsidy at 500. percent = 0 → origin covers the whole call but is
    // limited to min(originLeft, 500) = 500.
    let mut creator = Account {
        address: BOB.to_vec(),
        balance: 0,
        ..Default::default()
    };
    creator.frozen_v2.push(FreezeV2 { r#type: 1, amount: 1_000_000_000 });
    let budget = vm_energy_budget_trigger(
        &env.accounts,
        &env.dyn_props,
        &Address::from_raw(ALICE),
        &caller,
        Some((&Address::from_raw(BOB), &creator)),
        /*percent=*/ 0,
        /*raw_origin_energy_limit=*/ 500,
        /*fee_limit=*/ 10_000_000,
        /*call_value=*/ 0,
        /*now_slot=*/ 0,
    );
    assert_eq!(budget, caller_only + 500);
}

#[test]
fn trigger_budget_percent_100_means_no_creator_subsidy() {
    let env = Env::new();
    seed_global_energy(&env, 100_000_000_000, 1_000);
    let caller = Account {
        address: ALICE.to_vec(),
        balance: 100_000,
        ..Default::default()
    };
    let mut creator = Account {
        address: BOB.to_vec(),
        balance: 0,
        ..Default::default()
    };
    creator.frozen_v2.push(FreezeV2 { r#type: 1, amount: 1_000_000_000 });
    let caller_only =
        account_energy_limit_with_fix_ratio(&caller, &env.dyn_props, 5_000_000, 0, 0);
    // percent == 100 → caller pays everything, creator contributes nothing.
    let budget = vm_energy_budget_trigger(
        &env.accounts,
        &env.dyn_props,
        &Address::from_raw(ALICE),
        &caller,
        Some((&Address::from_raw(BOB), &creator)),
        100,
        500,
        5_000_000,
        0,
        0,
    );
    assert_eq!(budget, caller_only);
}

#[test]
fn trigger_budget_no_creator_is_caller_only() {
    let env = Env::new();
    let caller = Account {
        address: ALICE.to_vec(),
        balance: 1_000_000,
        ..Default::default()
    };
    let caller_only =
        account_energy_limit_with_fix_ratio(&caller, &env.dyn_props, 1_000_000, 0, 0);
    let budget = vm_energy_budget_trigger(
        &env.accounts,
        &env.dyn_props,
        &Address::from_raw(ALICE),
        &caller,
        None,
        100,
        0,
        1_000_000,
        0,
        0,
    );
    assert_eq!(budget, caller_only);
}

#[test]
fn preconsume_then_reset_restores_post_decay_state() {
    // SAFETY PROPERTY (guards the byte-exact majority): java's budget-time
    // frozen-energy PRE-CONSUME + the SUCCESS-path resetAccountUsage must, for a
    // tx that touches no energy mid-VM, restore the account EXACTLY to the
    // post-decay usage — so the net charge is byte-identical to the
    // no-pre-consume flow. This is the invariant the whole fix rests on.
    let env = Env::new();
    seed_global_energy(&env, 100_000_000_000, 1_000);
    let alice = Address::from_raw(ALICE);
    let mut caller = Account {
        address: ALICE.to_vec(),
        balance: 10_000_000_000,
        ..Default::default()
    };
    // Staked energy + a non-zero, STALE usage so the budget decay is meaningful.
    caller.frozen_v2.push(FreezeV2 {
        r#type: 1,
        amount: 1_000_000_000,
    });
    caller.account_resource = Some(AccountResource {
        energy_usage: 5_000_000,
        latest_consume_time_for_energy: 0,
        ..Default::default()
    });
    put(&env.accounts, ALICE, caller.clone());

    let now_slot = 1_000; // within the 28800-block window → a partial decay.
    // BUDGET: decay → pre-consume the frozen quota → persist → capture.
    let _ = vm_energy_budget_create(
        &env.accounts,
        &env.dyn_props,
        &alice,
        &caller,
        10_000_000,
        0,
        now_slot,
    );
    let cap = get_pre_tx_energy(&alice).expect("budget must capture the caller pre-consume");
    assert!(
        cap.usage < 5_000_000,
        "budget must decay the stale usage (got {} vs 5_000_000)",
        cap.usage
    );
    assert!(
        cap.merged_usage > cap.usage,
        "pre-consume must ADD the reserved frozen energy (merged {} vs decayed {})",
        cap.merged_usage,
        cap.usage
    );
    let persisted = env.accounts.get(&alice).unwrap().unwrap();
    assert_eq!(
        persisted.account_resource.as_ref().unwrap().energy_usage,
        cap.merged_usage,
        "budget must PERSIST the pre-consumed usage so an in-VM UNDELEGATE reads the un-decayed base"
    );

    // NO in-VM energy op: the SUCCESS-path reset must restore the EXACT post-decay
    // usage and leave latest_consume_time at `now`.
    reset_energy_pre_consume(&env.accounts, &env.dyn_props, &alice, None).unwrap();
    let after = env.accounts.get(&alice).unwrap().unwrap().account_resource.unwrap();
    assert_eq!(
        after.energy_usage, cap.usage,
        "resetAccountUsage must restore the exact post-decay usage (byte-exact safety property)"
    );
    assert_eq!(
        after.latest_consume_time_for_energy, now_slot,
        "reset must NOT touch latest_consume_time (stays `now` from the budget)"
    );
}

#[test]
fn revert_undoes_preconsume_to_original_state() {
    // On a VM REVERT java never commits the budget pre-consume (it lives in the
    // discarded rootRepository cache), so payEnergyBill decays the ORIGINAL row.
    // We persist the pre-consume to the outer session (it survives the revert),
    // so revert_energy_pre_consume must restore the ORIGINAL pre-budget energy
    // fields — else the caller's usage stays inflated by `reserve` and its next
    // tx wrongly runs OUT_OF_ENERGY (the regression this guards against).
    let env = Env::new();
    seed_global_energy(&env, 100_000_000_000, 1_000);
    let alice = Address::from_raw(ALICE);
    let mut caller = Account {
        address: ALICE.to_vec(),
        balance: 10_000_000_000,
        ..Default::default()
    };
    caller.frozen_v2.push(FreezeV2 {
        r#type: 1,
        amount: 1_000_000_000,
    });
    caller.account_resource = Some(AccountResource {
        energy_usage: 5_000_000,
        latest_consume_time_for_energy: 0,
        ..Default::default()
    });
    put(&env.accounts, ALICE, caller.clone());

    let now_slot = 1_000;
    let _ = vm_energy_budget_create(
        &env.accounts,
        &env.dyn_props,
        &alice,
        &caller,
        10_000_000,
        0,
        now_slot,
    );
    // Budget persisted a MUTATED (decayed + pre-consumed) row.
    let merged = env.accounts.get(&alice).unwrap().unwrap().account_resource.unwrap();
    assert_ne!(
        merged.energy_usage, 5_000_000,
        "budget must have mutated the persisted usage"
    );

    // REVERT: must restore the ORIGINAL pre-budget fields exactly.
    revert_energy_pre_consume(&env.accounts, &env.dyn_props, &alice, None).unwrap();
    let after = env.accounts.get(&alice).unwrap().unwrap().account_resource.unwrap();
    assert_eq!(
        after.energy_usage, 5_000_000,
        "revert must restore the ORIGINAL energy_usage (no `reserve` inflation)"
    );
    assert_eq!(
        after.latest_consume_time_for_energy, 0,
        "revert must restore the ORIGINAL latest_consume_time"
    );
    assert_eq!(
        after.energy_window_size, 0,
        "revert must restore the ORIGINAL window"
    );
}

// =============================================================================
// The ALLOW_TVM_FREEZE-on / UNFREEZE_DELAY_DAYS-off window (proposal #52 through
// Stake 2.0)
// =============================================================================
//
// java gates its origin-clamp CAPTURE on `VMConfig.allowTvmFreeze() ||
// VMConfig.allowTvmFreezeV2()` (VMActuator.java:736-738) — the same predicate
// `ReceiptCapsule.getOriginUsage` reads on the consume side
// (ReceiptCapsule.java:265-269) — while the account-mutating origin pre-consume
// is `allowTvmFreezeV2`-only. In the freeze-only window the capture therefore
// exists without the pre-consume, and the origin's share is clamped by the
// BUDGET-time quota rather than a pay-time re-read. The window matters because
// the Stake 1.0 FREEZE/UNFREEZE opcodes are live in it and mutate exactly what
// `getAccountLeftEnergyFromFreeze` reads.

/// `seed_global_energy` with the Stake-2.0 unfreeze delay OFF and
/// ALLOW_TVM_FREEZE on — the freeze-only era.
fn seed_global_energy_freeze_only(env: &Env, total_limit: i64, total_weight: i64) {
    env.dyn_props.save_total_energy_limit(total_limit);
    env.dyn_props.save_total_energy_current_limit(total_limit);
    env.dyn_props.save_total_energy_weight(total_weight);
    env.dyn_props.save_unfreeze_delay_days(0);
    env.dyn_props.put_long(b"ALLOW_TVM_FREEZE", 1);
    env.dyn_props.put_long(b"ALLOW_BLACKHOLE_OPTIMIZATION", 1);
    env.dyn_props.save_latest_block_header_number(60_000_000);
}

/// An account staked under Stake 1.0: the legacy
/// `accountResource.frozenBalanceForEnergy` slot, which is what the v1 FREEZE
/// opcode writes.
fn v1_energy_account(addr: [u8; 21], frozen_trx: i64, balance_sun: i64) -> Account {
    Account {
        address: addr.to_vec(),
        balance: balance_sun,
        account_resource: Some(AccountResource {
            frozen_balance_for_energy: Some(Frozen {
                frozen_balance: frozen_trx * 1_000_000,
                expire_time: 0,
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Raise (or lower) an already-stored account's v1 frozen-for-energy stake,
/// standing in for an in-VM FREEZE / UNFREEZE opcode.
fn restake_energy(env: &Env, addr: [u8; 21], frozen_trx: i64) {
    let mut a = env.accounts.get(&Address::from_raw(addr)).unwrap().unwrap();
    a.account_resource
        .get_or_insert_with(Default::default)
        .frozen_balance_for_energy = Some(Frozen {
        frozen_balance: frozen_trx * 1_000_000,
        expire_time: 0,
    });
    put(&env.accounts, addr, a);
}

/// The origin's share must be clamped by the quota captured at budget time, not
/// by a pay-time re-read that an in-VM FREEZE has inflated.
#[test]
fn freeze_only_origin_clamp_uses_budget_capture_when_origin_freezes_midtx() {
    tron_executor::energy::clear_pre_tx_energy_quota();
    let env = Env::new();
    seed_global_energy_freeze_only(&env, 100_000_000_000, 200);
    let origin = v1_energy_account(ORIGIN, 1, 0);
    let caller = v1_energy_account(CALLER, 100, 0);
    put(&env.accounts, ORIGIN, origin.clone());
    put(&env.accounts, CALLER, caller.clone());

    vm_energy_budget_trigger(
        &env.accounts,
        &env.dyn_props,
        &Address::from_raw(CALLER),
        &caller,
        Some((&Address::from_raw(ORIGIN), &origin)),
        /*percent=*/ 30,
        /*raw_origin_energy_limit=*/ 10_000_000_000,
        /*fee_limit=*/ 10_000_000_000,
        /*call_value=*/ 0,
        /*now_slot=*/ 0,
    );
    let captured = get_pre_tx_energy(&Address::from_raw(ORIGIN))
        .expect("the freeze-only era captures the origin clamp")
        .left;
    assert!(captured > 0);

    // In-VM FREEZE: the origin stakes 100x more, so a live re-read would let it
    // absorb the whole 70% share.
    restake_energy(&env, ORIGIN, 100);

    let bill = pay_energy_bill(
        &env.accounts,
        &env.dyn_props,
        &Address::from_raw(CALLER),
        Some(&Address::from_raw(ORIGIN)),
        /*origin_energy_limit=*/ 10_000_000_000,
        /*consume_user_resource_percent=*/ 30,
        /*energy_used=*/ 10_000_000_000,
        /*now_slot=*/ 0,
    )
    .expect("bill ok");

    let origin_used = match bill.origin_charge.expect("split") {
        EnergyCharge::Frozen { energy_used, .. } => energy_used,
        other => panic!("expected Frozen, got {other:?}"),
    };
    assert_eq!(
        origin_used, captured,
        "the origin share must be bounded by the BUDGET-time quota"
    );
    match bill.caller_charge {
        EnergyCharge::Frozen { energy_used, .. } => {
            assert_eq!(energy_used, 10_000_000_000 - captured)
        }
        other => panic!("expected Frozen, got {other:?}"),
    }
}

/// The broad blast radius: `repo.addTotalEnergyWeight` runs for ANY in-tx energy
/// freeze, and `calculateGlobalEnergyLimitV2` divides by the total weight — so a
/// freeze targeting some unrelated account still shifts the origin's live quota.
/// The captured clamp must make the split identical to a run with no mutation.
#[test]
fn freeze_only_origin_clamp_survives_total_energy_weight_dilution() {
    fn run(dilute: bool) -> (i64, i64) {
        tron_executor::energy::clear_pre_tx_energy_quota();
        let env = Env::new();
        seed_global_energy_freeze_only(&env, 100_000_000_000, 200);
        let origin = v1_energy_account(ORIGIN, 1, 0);
        let caller = v1_energy_account(CALLER, 100, 0);
        put(&env.accounts, ORIGIN, origin.clone());
        put(&env.accounts, CALLER, caller.clone());

        vm_energy_budget_trigger(
            &env.accounts,
            &env.dyn_props,
            &Address::from_raw(CALLER),
            &caller,
            Some((&Address::from_raw(ORIGIN), &origin)),
            30,
            10_000_000_000,
            10_000_000_000,
            0,
            0,
        );
        if dilute {
            // An unrelated in-VM energy freeze grows the chain-wide weight.
            env.dyn_props.save_total_energy_weight(20_000);
        }
        let bill = pay_energy_bill(
            &env.accounts,
            &env.dyn_props,
            &Address::from_raw(CALLER),
            Some(&Address::from_raw(ORIGIN)),
            10_000_000_000,
            30,
            10_000_000_000,
            0,
        )
        .expect("bill ok");
        let o = match bill.origin_charge.expect("split") {
            EnergyCharge::Frozen { energy_used, .. } => energy_used,
            other => panic!("expected Frozen, got {other:?}"),
        };
        let c = match bill.caller_charge {
            EnergyCharge::Frozen { energy_used, .. } => energy_used,
            other => panic!("expected Frozen, got {other:?}"),
        };
        (o, c)
    }

    assert_eq!(
        run(true),
        run(false),
        "TOTAL_ENERGY_WEIGHT dilution mid-tx must not move the split"
    );
}

/// java's `useEnergy` skips its over-limit rejection entirely under this gate
/// (EnergyProcessor.java:112-116) and never charges the origin a TRX fee. The
/// capture keeps our clamp and our charge base in agreement, so an origin whose
/// live quota collapses mid-VM still settles wholly from stake.
#[test]
fn freeze_only_origin_never_pays_fee_when_quota_drops_midtx() {
    tron_executor::energy::clear_pre_tx_energy_quota();
    let env = Env::new();
    seed_global_energy_freeze_only(&env, 100_000_000_000, 200);
    // Give the origin a TRX balance so a fee path would actually be reachable.
    let origin = v1_energy_account(ORIGIN, 1, 1_000_000_000);
    let caller = v1_energy_account(CALLER, 100, 0);
    put(&env.accounts, ORIGIN, origin.clone());
    put(&env.accounts, CALLER, caller.clone());

    vm_energy_budget_trigger(
        &env.accounts,
        &env.dyn_props,
        &Address::from_raw(CALLER),
        &caller,
        Some((&Address::from_raw(ORIGIN), &origin)),
        30,
        10_000_000_000,
        10_000_000_000,
        0,
        0,
    );
    let captured = get_pre_tx_energy(&Address::from_raw(ORIGIN)).unwrap().left;
    assert!(captured > 0);

    // In-VM UNFREEZE: the origin's stake is gone by pay time.
    restake_energy(&env, ORIGIN, 0);

    let bill = pay_energy_bill(
        &env.accounts,
        &env.dyn_props,
        &Address::from_raw(CALLER),
        Some(&Address::from_raw(ORIGIN)),
        10_000_000_000,
        30,
        10_000_000_000,
        0,
    )
    .expect("bill ok");

    match bill.origin_charge.expect("split") {
        EnergyCharge::Frozen { energy_used, .. } => assert_eq!(energy_used, captured),
        other => panic!("the origin must never be routed to a fee, got {other:?}"),
    }
    assert_eq!(
        env.accounts
            .get(&Address::from_raw(ORIGIN))
            .unwrap()
            .unwrap()
            .balance,
        1_000_000_000,
        "the origin's TRX balance is never touched"
    );
}

/// java leaves `originEnergyLeft` at its `0` default when
/// `consumeUserResourcePercent == 100` (VMActuator.java:734-739 only assigns it
/// inside `if (percent < ONE_HUNDRED)`). Our capture is deliberately NOT
/// guarded on the percent, because `origin_left` is already forced to 0 there —
/// which reproduces that default rather than leaving a live-read fallback.
#[test]
fn freeze_only_percent_100_captures_zero_left() {
    tron_executor::energy::clear_pre_tx_energy_quota();
    let env = Env::new();
    seed_global_energy_freeze_only(&env, 100_000_000_000, 200);
    let origin = v1_energy_account(ORIGIN, 100, 0);
    let caller = v1_energy_account(CALLER, 100, 0);
    put(&env.accounts, ORIGIN, origin.clone());
    put(&env.accounts, CALLER, caller.clone());

    vm_energy_budget_trigger(
        &env.accounts,
        &env.dyn_props,
        &Address::from_raw(CALLER),
        &caller,
        Some((&Address::from_raw(ORIGIN), &origin)),
        /*percent=*/ 100,
        10_000_000_000,
        10_000_000_000,
        0,
        0,
    );
    assert_eq!(
        get_pre_tx_energy(&Address::from_raw(ORIGIN)).unwrap().left,
        0
    );

    let bill = pay_energy_bill(
        &env.accounts,
        &env.dyn_props,
        &Address::from_raw(CALLER),
        Some(&Address::from_raw(ORIGIN)),
        10_000_000,
        100,
        1_000,
        0,
    )
    .expect("bill ok");
    match bill.origin_charge.expect("origin still decayed at 0 usage") {
        EnergyCharge::Frozen { energy_used, .. } => assert_eq!(energy_used, 0),
        other => panic!("expected Frozen{{0}}, got {other:?}"),
    }
    match bill.caller_charge {
        EnergyCharge::Frozen { energy_used, .. } => assert_eq!(energy_used, 1_000),
        other => panic!("expected Frozen, got {other:?}"),
    }
}

/// Before proposal #52 java's `getOriginUsage` falls through to arms 2/3, both
/// of which genuinely re-read `getAccountLeftEnergyFromFreeze(origin)`. No
/// capture may exist, and a mid-tx quota change MUST move the split — the proof
/// that the new gate did not widen too far.
#[test]
fn pre_tvm_freeze_era_origin_still_live_reads() {
    fn run(restake: bool) -> i64 {
        tron_executor::energy::clear_pre_tx_energy_quota();
        let env = Env::new();
        seed_global_energy_freeze_only(&env, 100_000_000_000, 200);
        env.dyn_props.put_long(b"ALLOW_TVM_FREEZE", 0);
        let origin = v1_energy_account(ORIGIN, 1, 0);
        let caller = v1_energy_account(CALLER, 100, 0);
        put(&env.accounts, ORIGIN, origin.clone());
        put(&env.accounts, CALLER, caller.clone());

        vm_energy_budget_trigger(
            &env.accounts,
            &env.dyn_props,
            &Address::from_raw(CALLER),
            &caller,
            Some((&Address::from_raw(ORIGIN), &origin)),
            30,
            10_000_000_000,
            10_000_000_000,
            0,
            0,
        );
        assert!(
            get_pre_tx_energy(&Address::from_raw(ORIGIN)).is_none(),
            "no origin capture exists before ALLOW_TVM_FREEZE"
        );
        if restake {
            restake_energy(&env, ORIGIN, 100);
        }
        let bill = pay_energy_bill(
            &env.accounts,
            &env.dyn_props,
            &Address::from_raw(CALLER),
            Some(&Address::from_raw(ORIGIN)),
            10_000_000_000,
            30,
            10_000_000_000,
            0,
        )
        .expect("bill ok");
        match bill.origin_charge.expect("split") {
            EnergyCharge::Frozen { energy_used, .. } => energy_used,
            other => panic!("expected Frozen, got {other:?}"),
        }
    }

    assert!(
        run(true) > run(false),
        "arms 2/3 re-read the origin's live quota at pay time"
    );
}

/// The freeze-only capture is value-only: every other `EnergyPreConsume` field
/// is a `Default` zero, which would corrupt an account if it ever reached
/// `reset_account_usage` or the revert restore. Both entry points early-return
/// on `!support_unfreeze_delay()`, which is false by construction here — this
/// pins that guard.
#[test]
fn freeze_only_capture_does_not_trigger_reset_or_revert() {
    tron_executor::energy::clear_pre_tx_energy_quota();
    let env = Env::new();
    seed_global_energy_freeze_only(&env, 100_000_000_000, 200);
    let origin = v1_energy_account(ORIGIN, 1, 0);
    let caller = v1_energy_account(CALLER, 100, 0);
    put(&env.accounts, ORIGIN, origin.clone());
    put(&env.accounts, CALLER, caller.clone());

    vm_energy_budget_trigger(
        &env.accounts,
        &env.dyn_props,
        &Address::from_raw(CALLER),
        &caller,
        Some((&Address::from_raw(ORIGIN), &origin)),
        30,
        10_000_000_000,
        10_000_000_000,
        0,
        0,
    );
    assert!(get_pre_tx_energy(&Address::from_raw(ORIGIN)).is_some());
    let before = env.accounts.get(&Address::from_raw(ORIGIN)).unwrap().unwrap();

    reset_energy_pre_consume(
        &env.accounts,
        &env.dyn_props,
        &Address::from_raw(CALLER),
        Some(&Address::from_raw(ORIGIN)),
    )
    .unwrap();
    revert_energy_pre_consume(
        &env.accounts,
        &env.dyn_props,
        &Address::from_raw(CALLER),
        Some(&Address::from_raw(ORIGIN)),
    )
    .unwrap();

    assert_eq!(
        env.accounts.get(&Address::from_raw(ORIGIN)).unwrap().unwrap(),
        before,
        "a value-only capture must never reach the reset / revert restore"
    );
}

// =============================================================================
// `EnergyProcessor.useEnergy`'s over-limit bail-out
// =============================================================================
//
// Before proposal #52 (ALLOW_TVM_FREEZE) and Stake 2.0, `useEnergy` returns
// early — ahead of every mutation — when the charge exceeds the account's
// headroom (EnergyProcessor.java:112-116). The subtraction `energyLimit -
// newEnergyUsage` is signed and unclamped, so an account already past its limit
// has NEGATIVE headroom; its callers pre-clamp the frozen slice to zero, the
// comparison reads `0 > negative`, and the row keeps its anchor. The anchor is
// what makes java's recovery linear: one `increase` step across the whole
// elapsed span, rather than one compounding step per slot.

/// The pre-#52 legacy era — ALLOW_TVM_FREEZE off and the Stake-2.0 unfreeze
/// delay off, the window in which `useEnergy`'s bail-out is reachable.
fn seed_global_energy_legacy(env: &Env, total_limit: i64, total_weight: i64) {
    env.dyn_props.save_total_energy_limit(total_limit);
    env.dyn_props.save_total_energy_current_limit(total_limit);
    env.dyn_props.save_total_energy_weight(total_weight);
    env.dyn_props.save_unfreeze_delay_days(0);
    env.dyn_props.put_long(b"ALLOW_TVM_FREEZE", 0);
    env.dyn_props.put_long(b"ALLOW_BLACKHOLE_OPTIMIZATION", 1);
    env.dyn_props.save_latest_block_header_number(4_800_000);
}

/// A Stake-1.0 account carrying an explicit energy-usage anchor.
fn v1_energy_account_with_usage(
    addr: [u8; 21],
    frozen_trx: i64,
    balance_sun: i64,
    energy_usage: i64,
    latest_consume: i64,
) -> Account {
    let mut a = v1_energy_account(addr, frozen_trx, balance_sun);
    let r = a.account_resource.as_mut().unwrap();
    r.energy_usage = energy_usage;
    r.latest_consume_time_for_energy = latest_consume;
    a
}

/// An over-limit row is left byte-identical by a further charge: the growth
/// `increase`, `setEnergyUsage`, `setLatestConsumeTimeForEnergy`,
/// `setLatestOperationTime` and `accountStore.put` all sit after the return.
#[test]
fn over_limit_charge_leaves_the_row_untouched() {
    tron_executor::energy::clear_pre_tx_energy_quota();
    let env = Env::new();
    // 1 TRX staked against a 10_000-energy chain limit at weight 1 → a 10_000
    // per-account limit, with the anchor sitting four times over it.
    seed_global_energy_legacy(&env, 10_000, 1);
    let anchored = v1_energy_account_with_usage(ALICE, 1, 1_000_000, 40_000, 0);
    put(&env.accounts, ALICE, anchored.clone());

    let charge = consume_energy(&env.accounts, &env.dyn_props, &Address::from_raw(ALICE), 0, 100)
        .expect("ok");
    assert_eq!(
        charge,
        EnergyCharge::Frozen { energy_used: 0, new_energy_usage: 40_000 },
        "the receipt still reports the requested split, as java sets it regardless \
         of what useEnergy returned"
    );
    assert_eq!(
        env.accounts.get(&Address::from_raw(ALICE)).unwrap().unwrap(),
        anchored,
        "an over-limit account is a frozen anchor: nothing in the row may move"
    );
}

/// The point of the frozen anchor: a charge landing after the account recovers
/// decays from the ORIGINAL anchor in one linear step, so intervening
/// over-limit charges leave no trace at all. Re-stamping the row on each of
/// them would compound the decay and settle on a different usage.
#[test]
fn later_charge_decays_from_the_original_anchor() {
    fn run(intervening_slots: &[i64]) -> Account {
        tron_executor::energy::clear_pre_tx_energy_quota();
        let env = Env::new();
        seed_global_energy_legacy(&env, 10_000, 1);
        put(
            &env.accounts,
            ALICE,
            v1_energy_account_with_usage(ALICE, 1, 100_000_000, 40_000, 0),
        );
        for slot in intervening_slots {
            consume_energy(&env.accounts, &env.dyn_props, &Address::from_raw(ALICE), 0, *slot)
                .expect("ok");
        }
        // Slot 25_000: 40_000 decayed linearly from slot 0 is back under the
        // 10_000 limit, so this charge is the first one that writes.
        consume_energy(&env.accounts, &env.dyn_props, &Address::from_raw(ALICE), 0, 25_000)
            .expect("ok");
        env.accounts.get(&Address::from_raw(ALICE)).unwrap().unwrap()
    }

    assert_eq!(
        run(&[100, 200, 300]),
        run(&[]),
        "charges made while over the limit must not shift the anchor the \
         recovering charge decays from"
    );
}

/// Regression fence: with headroom to spare the bail-out must not fire, and the
/// charge writes the row exactly as before.
#[test]
fn under_limit_charge_still_writes_the_row() {
    tron_executor::energy::clear_pre_tx_energy_quota();
    let env = Env::new();
    seed_global_energy_legacy(&env, 10_000, 1);
    put(
        &env.accounts,
        ALICE,
        v1_energy_account_with_usage(ALICE, 1, 1_000_000, 1_000, 0),
    );

    let charge = consume_energy(&env.accounts, &env.dyn_props, &Address::from_raw(ALICE), 500, 100)
        .expect("ok");
    assert!(matches!(charge, EnergyCharge::Frozen { energy_used: 500, .. }));
    let after = env.accounts.get(&Address::from_raw(ALICE)).unwrap().unwrap();
    let res = after.account_resource.unwrap();
    assert!(res.energy_usage > 1_000, "the 500-energy charge was added to the usage");
    assert_eq!(res.latest_consume_time_for_energy, 100, "the row was re-stamped");
}

/// java's guard is an `&&` chain over three terms, so ALLOW_TVM_FREEZE alone
/// disables it — the same over-limit row must be written.
#[test]
fn allow_tvm_freeze_disables_the_bailout() {
    tron_executor::energy::clear_pre_tx_energy_quota();
    let env = Env::new();
    seed_global_energy_legacy(&env, 10_000, 1);
    env.dyn_props.put_long(b"ALLOW_TVM_FREEZE", 1);
    let anchored = v1_energy_account_with_usage(ALICE, 1, 1_000_000, 40_000, 0);
    put(&env.accounts, ALICE, anchored.clone());

    consume_energy(&env.accounts, &env.dyn_props, &Address::from_raw(ALICE), 0, 100).expect("ok");
    let after = env.accounts.get(&Address::from_raw(ALICE)).unwrap().unwrap();
    assert_ne!(after, anchored, "ALLOW_TVM_FREEZE == 1 skips the bail-out");
    assert_eq!(after.account_resource.unwrap().latest_consume_time_for_energy, 100);
}

/// The Stake-2.0 unfreeze delay disables the guard independently of
/// ALLOW_TVM_FREEZE, which stays off here.
#[test]
fn unfreeze_delay_disables_the_bailout() {
    tron_executor::energy::clear_pre_tx_energy_quota();
    let env = Env::new();
    seed_global_energy_legacy(&env, 10_000, 1);
    env.dyn_props.save_unfreeze_delay_days(1);
    let anchored = v1_energy_account_with_usage(ALICE, 1, 1_000_000, 40_000, 0);
    put(&env.accounts, ALICE, anchored.clone());

    consume_energy(&env.accounts, &env.dyn_props, &Address::from_raw(ALICE), 0, 100).expect("ok");
    let after = env.accounts.get(&Address::from_raw(ALICE)).unwrap().unwrap();
    assert_ne!(after, anchored, "supportUnfreezeDelay() skips the bail-out");
    assert_eq!(after.account_resource.unwrap().latest_consume_time_for_energy, 100);
}

/// Recovery timing. An account parked over its limit is charged once per slot;
/// the slot on which its stake starts covering the charge again is fixed by the
/// linear decay of the frozen anchor. Re-stamping the row on every call applies
/// `(1 - 1/window)` per slot instead, which is strictly larger than
/// `1 - N/window`, so usage stays higher and recovery arrives blocks late.
#[test]
fn over_limit_recovery_follows_the_frozen_anchor() {
    tron_executor::energy::clear_pre_tx_energy_quota();
    let env = Env::new();
    // 1 TRX at weight 1 against a 6_865_600_000 chain limit — the per-account
    // limit the anchor below decays back through after 990 slots.
    seed_global_energy_legacy(&env, 6_865_600_000, 1);
    put(
        &env.accounts,
        ALICE,
        v1_energy_account_with_usage(ALICE, 1, 1_000_000_000, 7_110_000_000, 0),
    );

    let mut recovered_at = None;
    for slot in 1..=1_200 {
        let charge = consume_energy(&env.accounts, &env.dyn_props, &Address::from_raw(ALICE), 1, slot)
            .expect("ok");
        if matches!(charge, EnergyCharge::Frozen { .. }) {
            recovered_at = Some(slot);
            break;
        }
    }
    assert_eq!(
        recovered_at,
        Some(990),
        "the anchor decays linearly across the whole span, so the stake covers \
         the charge again on the java slot"
    );
}

/// `BLOCK_ENERGY_USAGE` is accumulated in two places in java. The frozen slice
/// is added inside `useEnergy`, past the bail-out (EnergyProcessor.java:133-136)
/// — so a bailed-out charge contributes nothing from that side — while the
/// TRX-paid remainder is added by `ReceiptCapsule.payEnergyBill` itself
/// (ReceiptCapsule.java:309-314), which the bail-out does not reach.
#[test]
fn bailed_out_charge_accumulates_only_the_fee_remainder() {
    tron_executor::energy::clear_pre_tx_energy_quota();
    let env = Env::new();
    seed_global_energy_legacy(&env, 10_000, 1);
    env.dyn_props.put_long(b"ALLOW_ADAPTIVE_ENERGY", 1);
    let anchored = v1_energy_account_with_usage(ALICE, 1, 100_000_000, 40_000, 0);
    put(&env.accounts, ALICE, anchored.clone());

    // Over the limit, so the whole 700 is a fee remainder and the frozen slice
    // is zero: the accumulator moves by the remainder alone.
    let charge = consume_energy(&env.accounts, &env.dyn_props, &Address::from_raw(ALICE), 700, 100)
        .expect("ok");
    assert_eq!(charge, EnergyCharge::Fee { energy_used: 700, fee_sun: 70_000 });
    assert_eq!(env.dyn_props.block_energy_usage(), 700);

    let after = env.accounts.get(&Address::from_raw(ALICE)).unwrap().unwrap();
    assert_eq!(
        after.balance,
        100_000_000 - 70_000,
        "the caller path writes the account back after useEnergy returns, so the \
         fee deduction still persists"
    );
    let res = after.account_resource.unwrap();
    assert_eq!(res.energy_usage, 40_000, "the anchor is untouched");
    assert_eq!(res.latest_consume_time_for_energy, 0, "the anchor is untouched");
    assert_eq!(after.latest_opration_time, 0, "set after the return, so never reached");
}

/// `payEnergyBill` picks the caller's frozen-vs-fee clamp on the same gate as
/// the origin clamp (ReceiptCapsule.java:289-294): the budget-time capture from
/// proposal #52 onward, a live re-read before it. In the legacy era the live
/// value must win, which also keeps the frozen slice — the `energy` argument
/// java passes to `useEnergy` — equal to java's on both sides of the bail-out.
#[test]
fn pre_tvm_freeze_era_caller_clamp_is_a_live_read() {
    tron_executor::energy::clear_pre_tx_energy_quota();
    let env = Env::new();
    seed_global_energy_legacy(&env, 10_000, 1);
    // 10 TRX staked at budget time → a 100_000-energy caller quota.
    let caller = v1_energy_account(ALICE, 10, 100_000_000);
    put(&env.accounts, ALICE, caller.clone());
    vm_energy_budget_create(
        &env.accounts,
        &env.dyn_props,
        &Address::from_raw(ALICE),
        &caller,
        10_000_000_000,
        0,
        0,
    );
    // Stake drops to 1 TRX mid-tx → a 10_000-energy live quota.
    restake_energy(&env, ALICE, 1);

    let charge = consume_energy(&env.accounts, &env.dyn_props, &Address::from_raw(ALICE), 50_000, 0)
        .expect("ok");
    assert_eq!(
        charge,
        EnergyCharge::Mixed {
            energy_used: 50_000,
            energy_from_frozen: 10_000,
            fee_sun: 40_000 * 100,
            new_energy_usage: 10_000,
        },
        "the live quota covers 10_000 and the rest burns as a TRX fee"
    );
    let after = env.accounts.get(&Address::from_raw(ALICE)).unwrap().unwrap();
    assert_eq!(after.balance, 100_000_000 - 4_000_000);
}

// ---------------------------------------------------------------------------
// java `RuntimeImplTest.getCreatorEnergyLimit2Test`
//
// java walks one account through six (feeLimit, callValue, stake) combinations
// and asserts the exact budget `VMActuator.getAccountEnergyLimitWithFixRatio`
// returns for each. Reproducing all six with one fixture pins both halves of
// the `min(feeLimit / energyFee, leftFrozenEnergy + (balance - callValue) /
// energyFee)` formula, including the frozen-energy quota derived from
// `totalEnergyCurrentLimit / totalEnergyWeight`.
// ---------------------------------------------------------------------------

/// java's fixture: 3,000 TRX of balance, a 5,000,000,000-TRX global energy
/// weight against the default 50,000,000,000 global energy limit, and the
/// default 100 sun/energy price.
fn runtime_impl_test_env() -> Env {
    let env = Env::new();
    env.dyn_props.save_total_energy_limit(50_000_000_000);
    env.dyn_props.save_total_energy_current_limit(50_000_000_000);
    env.dyn_props.save_total_energy_weight(5_000_000_000);
    env.dyn_props.save_unfreeze_delay_days(1);
    env.dyn_props.save_latest_block_header_number(60_000_000);
    env
}

fn runtime_impl_test_creator(balance: i64, frozen_for_energy: i64) -> Account {
    Account {
        address: ALICE.to_vec(),
        balance,
        account_resource: Some(AccountResource {
            frozen_balance_for_energy: Some(Frozen {
                frozen_balance: frozen_for_energy,
                expire_time: 0,
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// java `RuntimeImplTest.getCreatorEnergyLimit2Test`, unstaked cases: with
/// 3,000 TRX of balance and no stake the budget is whichever of the fee limit
/// and the spendable balance runs out first.
#[test]
fn java_runtime_impl_fix_ratio_budget_without_stake() {
    let env = runtime_impl_test_env();
    let creator = runtime_impl_test_creator(3_000_000_000, 0);

    // feeLimit 1e9, callValue 10 → fee limit binds. java: 10_000_000.
    assert_eq!(
        account_energy_limit_with_fix_ratio(&creator, &env.dyn_props, 1_000_000_000, 10, 0),
        10_000_000
    );
    // callValue 2.5e9 leaves only 0.5e9 spendable → balance binds.
    // java: 5_000_000.
    assert_eq!(
        account_energy_limit_with_fix_ratio(
            &creator,
            &env.dyn_props,
            1_000_000_000,
            2_500_000_000,
            0
        ),
        5_000_000
    );
    // A small fee limit binds well below the balance. java: 10_000.
    assert_eq!(
        account_energy_limit_with_fix_ratio(&creator, &env.dyn_props, 1_000_000, 10, 0),
        10_000
    );
}

/// java `RuntimeImplTest.getCreatorEnergyLimit2Test`, staked cases: moving
/// 1,000 TRX of the balance into an energy stake yields a 10,000-energy quota
/// (1,000 TRX of a 5,000,000,000-TRX weight against a 50,000,000,000 limit)
/// which is ADDED to the remaining balance's worth, so the balance-side term
/// becomes 10_000 + 19_999_999 = 20_009_999.
#[test]
fn java_runtime_impl_fix_ratio_budget_with_stake() {
    let env = runtime_impl_test_env();
    // java: `setFrozenForEnergy(1e9, 0)` and `setBalance(balance - 1e9)`.
    let creator = runtime_impl_test_creator(2_000_000_000, 1_000_000_000);

    // The fee limit still binds below the staked budget. java: 10_000_000.
    assert_eq!(
        account_energy_limit_with_fix_ratio(&creator, &env.dyn_props, 1_000_000_000, 10, 0),
        10_000_000
    );
    // Raising the fee limit past the staked budget exposes it exactly.
    // java: 20_009_999.
    assert_eq!(
        account_energy_limit_with_fix_ratio(&creator, &env.dyn_props, 3_000_000_000, 10, 0),
        20_009_999
    );
    // A tiny fee limit binds regardless of the stake. java: 30.
    assert_eq!(
        account_energy_limit_with_fix_ratio(&creator, &env.dyn_props, 3_000, 10, 0),
        30
    );
}
