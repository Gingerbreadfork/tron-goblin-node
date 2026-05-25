//! Tests for `energy::consume_energy` — the post-VM energy-cost
//! billing that mirrors java-tron's `EnergyProcessor.useEnergy` plus
//! the TRX-fee fallback from `TransactionTrace.pay`.

use std::sync::Arc;

use hex_literal::hex;
use tron_chainbase::{AccountStore, DynamicPropertiesStore, KvBackend, MemBackend};
use tron_crypto::address::Address;
use tron_executor::energy::{consume_energy, EnergyCharge, EnergyError};
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
    accounts.put(&Address::from_raw(addr), &a);
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
