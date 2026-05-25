//! Energy accounting per java-tron's `EnergyProcessor`.
//!
//! Smart-contract execution charges *energy*, not bytes. Source of truth:
//! `chainbase/src/main/java/org/tron/core/db/EnergyProcessor.java`.
//!
//! The processing order, mirroring java-tron's `TransactionTrace.pay()`:
//!
//! 1. **`useEnergy(caller, energy_used)`** — windowed-average decay of
//!    `account.account_resource.energy_usage` against the global-scaled
//!    `energy_limit` derived from `frozen_v2[ENERGY]` via
//!    `TOTAL_ENERGY_CURRENT_LIMIT / TOTAL_ENERGY_WEIGHT`.
//! 2. **TRX fee fallback** — any energy not covered by the frozen quota
//!    is paid in TRX: `(energy_used - quota_covered) * ENERGY_FEE` sun
//!    is deducted from the caller's balance.
//!
//! Bumps `BLOCK_ENERGY_USAGE` when `ALLOW_ADAPTIVE_ENERGY == 1`, so the
//! maintenance pass can drive the `TOTAL_ENERGY_CURRENT_LIMIT` adaptive
//! adjustment (see [`crate::adaptive`]).
//!
//! **Note on contract-owner energy (`origin_energy_usage`).** java-tron's
//! full `TransactionTrace.pay()` flow splits the energy cost between the
//! contract origin (limited by `originEnergyLimit / consumeUserResourcePercent`)
//! and the caller. The current implementation models only the caller's
//! share — origin-side accounting is pinned as a follow-up gap. The
//! divergence affects contracts that set `consume_user_resource_percent < 100`
//! (rare on mainnet — most user-facing contracts charge the caller 100%).

use tron_chainbase::{AccountStore, DynamicPropertiesStore, StoreError};
use tron_crypto::address::Address;
use tron_proto::account::AccountResource;
use tron_proto::Account;

use crate::resource::{
    calculate_global_limit_v1, calculate_global_limit_v2, increase_default, recovery,
    TRX_PRECISION,
};

/// What happened during a `consume_energy` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnergyCharge {
    /// All the energy was covered by the caller's frozen-energy quota.
    Frozen {
        energy_used: i64,
        new_energy_usage: i64,
    },
    /// All the energy was paid in TRX (`energy_used * energy_fee`).
    Fee { energy_used: i64, fee_sun: i64 },
    /// Mixed: some covered by the frozen quota, the remainder by TRX
    /// fee. java-tron splits the bill this way when the quota covers
    /// part of the cost — the frozen-quota slice is debited first, then
    /// the leftover energy is converted to TRX.
    Mixed {
        energy_used: i64,
        energy_from_frozen: i64,
        fee_sun: i64,
        new_energy_usage: i64,
    },
}

/// Hard errors — caller should mark the tx as failed (or revert).
#[derive(Debug, thiserror::Error)]
pub enum EnergyError {
    #[error("account not found")]
    AccountMissing,
    #[error("account has insufficient frozen energy + balance to cover {energy_used} energy ({fee_sun} sun fee)")]
    Insufficient { energy_used: i64, fee_sun: i64 },
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Consume energy for the given caller. Mirrors
/// `EnergyProcessor.useEnergy(accountCapsule, energy, now)` plus the
/// TRX-fee fallback from `TransactionTrace.pay`.
///
/// Returns the kind of charge applied. Mutates `caller`'s account row
/// in `accounts`. If the caller has neither sufficient quota nor TRX,
/// returns [`EnergyError::Insufficient`] and leaves state untouched
/// (caller will revert the tx session).
pub fn consume_energy(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    caller: &Address,
    energy_used: u64,
    now_slot: i64,
) -> Result<EnergyCharge, EnergyError> {
    if energy_used == 0 {
        // Nothing to do — but we still want a consistent return shape so
        // the caller's accounting code is uniform.
        return Ok(EnergyCharge::Frozen {
            energy_used: 0,
            new_energy_usage: account_energy_usage(
                &accounts.get(caller)?.ok_or(EnergyError::AccountMissing)?,
            ),
        });
    }

    let energy_used_i = energy_used as i64;
    let mut account = accounts.get(caller)?.ok_or(EnergyError::AccountMissing)?;

    // Read current windowed-decay of the caller's energy_usage. java-tron
    // uses `recovery()` when supportUnfreezeDelay is on (preserves the
    // per-account window), else `increase()` with the default window.
    let support_unfreeze_delay = dyn_props.support_unfreeze_delay();
    let res = account.account_resource.unwrap_or_default();
    let current_usage = res.energy_usage;
    let latest_consume = res.latest_consume_time_for_energy;
    let decayed_usage = if support_unfreeze_delay {
        recovery(current_usage, latest_consume, now_slot, res.energy_window_size)
    } else {
        increase_default(current_usage, 0, latest_consume, now_slot)
    };

    let energy_limit = calculate_global_energy_limit(&account, dyn_props);
    let quota_left = energy_limit.saturating_sub(decayed_usage).max(0);

    let energy_from_frozen = quota_left.min(energy_used_i);
    let energy_remainder = energy_used_i - energy_from_frozen;
    let fee_per_energy = dyn_props.energy_fee().max(0);
    let fee = energy_remainder.saturating_mul(fee_per_energy);

    // Pre-flight: if there's a remainder, the caller must have the TRX.
    if energy_remainder > 0 && account.balance < fee {
        return Err(EnergyError::Insufficient {
            energy_used: energy_used_i,
            fee_sun: fee,
        });
    }

    // Apply the frozen-quota slice, if any.
    let new_energy_usage = if energy_from_frozen > 0 {
        let new = if support_unfreeze_delay {
            increase_default(current_usage, energy_from_frozen, latest_consume, now_slot)
        } else {
            increase_default(decayed_usage, energy_from_frozen, now_slot, now_slot)
        };
        let new_res = AccountResource {
            energy_usage: new,
            latest_consume_time_for_energy: now_slot,
            ..res
        };
        account.account_resource = Some(new_res);
        new
    } else {
        // No quota slice — still bump latest_consume_time_for_energy
        // so the next consume call sees up-to-date state. java-tron's
        // useEnergy always updates this.
        let new_res = AccountResource {
            latest_consume_time_for_energy: now_slot,
            ..res
        };
        account.account_resource = Some(new_res);
        current_usage
    };

    // Apply the TRX fee slice, if any.
    if energy_remainder > 0 {
        account.balance -= fee;
        pay_energy_fee(dyn_props, fee);
    }
    account.latest_opration_time = head_block_timestamp(dyn_props);
    accounts.put(caller, &account);

    // BLOCK_ENERGY_USAGE accumulator: drives the adaptive-energy
    // recalculation at every block boundary (or maintenance, depending
    // on java-tron's path). Bump whether the energy came from frozen
    // or fee — adaptive scaling is about chain-wide load, not how the
    // user paid.
    if dyn_props.allow_adaptive_energy() == 1 {
        let cur = dyn_props.block_energy_usage();
        dyn_props.save_block_energy_usage(cur.saturating_add(energy_used_i));
    }

    Ok(match (energy_from_frozen, energy_remainder) {
        (frozen, 0) => EnergyCharge::Frozen {
            energy_used: frozen,
            new_energy_usage,
        },
        (0, _) => EnergyCharge::Fee {
            energy_used: energy_used_i,
            fee_sun: fee,
        },
        (frozen, _) => EnergyCharge::Mixed {
            energy_used: energy_used_i,
            energy_from_frozen: frozen,
            fee_sun: fee,
            new_energy_usage,
        },
    })
}

/// `EnergyProcessor.calculateGlobalEnergyLimit`. Sum all sources of
/// energy frozen-weight, then scale by `TOTAL_ENERGY_CURRENT_LIMIT /
/// TOTAL_ENERGY_WEIGHT`.
pub fn calculate_global_energy_limit(
    account: &Account,
    dyn_props: &DynamicPropertiesStore,
) -> i64 {
    let froze_balance = all_frozen_balance_for_energy(account);
    let total_limit = dyn_props.total_energy_current_limit();
    let total_weight = dyn_props.total_energy_weight();

    if dyn_props.support_unfreeze_delay() {
        return calculate_global_limit_v2(froze_balance, total_limit, total_weight);
    }
    if froze_balance < TRX_PRECISION {
        return 0;
    }
    if total_weight == 0 {
        return 0;
    }
    if dyn_props.allow_new_reward() && total_weight <= 0 {
        return 0;
    }
    calculate_global_limit_v1(froze_balance, total_limit, total_weight)
}

/// Sum of all energy weight: the v2 frozen-for-energy entry, the
/// legacy v1 `frozen_balance_for_energy`, and the acquired-delegated
/// v1/v2 amounts. Mirrors
/// `AccountCapsule.getAllFrozenBalanceForEnergy`.
fn all_frozen_balance_for_energy(account: &Account) -> i64 {
    let res = account.account_resource.unwrap_or_default();
    let v2: i64 = account
        .frozen_v2
        .iter()
        .filter(|fb| fb.r#type == 1) // ENERGY
        .map(|fb| fb.amount)
        .sum();
    let v1 = res
        .frozen_balance_for_energy
        .map(|f| f.frozen_balance)
        .unwrap_or(0);
    v2.saturating_add(v1)
        .saturating_add(res.acquired_delegated_frozen_balance_for_energy)
        .saturating_add(res.acquired_delegated_frozen_v2_balance_for_energy)
}

fn account_energy_usage(account: &Account) -> i64 {
    account
        .account_resource
        .as_ref()
        .map(|r| r.energy_usage)
        .unwrap_or(0)
}

fn head_block_timestamp(dyn_props: &DynamicPropertiesStore) -> i64 {
    dyn_props.latest_block_header_timestamp().unwrap_or(0)
}

/// Pay the energy-side fee (matches `BandwidthProcessor.consumeFeeForBandwidth`
/// behavior — pool, burn, or blackhole). Energy fees also bump
/// `TOTAL_TRANSACTION_COST` since java-tron sweeps both into the same
/// counter.
fn pay_energy_fee(dyn_props: &DynamicPropertiesStore, fee: i64) {
    dyn_props.add_total_transaction_cost(fee);
    if dyn_props.support_transaction_fee_pool() {
        dyn_props.add_transaction_fee_pool(fee);
    } else if dyn_props.support_blackhole_optimization() {
        dyn_props.burn_trx(fee);
    } else {
        dyn_props.burn_trx(fee);
    }
}
