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
//! ## Origin / caller split
//!
//! For `TriggerSmartContract`, java-tron's `TransactionTrace.pay()` →
//! `ReceiptCapsule.payEnergyBill` splits the total energy cost between
//! the contract's `origin_address` (the deployer who agreed to subsidize
//! `100 - consume_user_resource_percent` of each call) and the
//! `caller_address` (the user invoking the contract). [`pay_energy_bill`]
//! implements that split; [`consume_energy`] remains the per-account
//! frozen-quota-then-TRX-fee primitive used by both halves of the
//! split as well as by non-VM bandwidth charging.
//!
//! `CreateSmartContract` has no pre-existing origin (the caller IS the
//! origin), so the split degenerates and the caller pays everything.

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

/// Result of `pay_energy_bill`: the origin's contribution (if any) and
/// the caller's. The origin's share is always `EnergyCharge::Frozen`
/// (origin only contributes from its frozen quota, never a TRX fee —
/// the pre-clamp guarantees `originUsage <= origin_quota_left`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnergyBill {
    /// `None` when no split applied (caller == origin, origin missing,
    /// or the percent / origin-quota math produced zero origin usage).
    pub origin_charge: Option<EnergyCharge>,
    /// The caller's slice — always present, may be `EnergyCharge::Frozen`
    /// with `energy_used = 0` if origin covered the whole bill.
    pub caller_charge: EnergyCharge,
}

/// java-tron's `consume_user_resource_percent` is the percentage of
/// each call's energy charged to the CALLER. The origin pays the
/// complement, clamped to `[0, 100]` defensively against bad contract
/// rows. Mirrors `payEnergyBill`'s `percent` derivation.
fn origin_percent(consume_user_resource_percent: i64) -> i64 {
    (100 - consume_user_resource_percent).clamp(0, 100)
}

/// How much energy the origin account could pay from its frozen quota
/// right now. Reads the same `account_resource.energy_usage` +
/// windowed-decay primitive `consume_energy` uses, so the two stay
/// consistent. Returns 0 if the account has no row.
///
/// Pre-clamping the origin's share by this value guarantees the
/// subsequent `consume_energy` call against origin can never go through
/// the TRX-fee path (origin never pays a fee — that's the caller's
/// responsibility per `payEnergyBill`).
fn origin_quota_left(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    origin: &Address,
    now_slot: i64,
) -> Result<i64, EnergyError> {
    let Some(account) = accounts.get(origin)? else {
        return Ok(0);
    };
    let res = account.account_resource.unwrap_or_default();
    let support_unfreeze_delay = dyn_props.support_unfreeze_delay();
    let decayed_usage = if support_unfreeze_delay {
        recovery(
            res.energy_usage,
            res.latest_consume_time_for_energy,
            now_slot,
            res.energy_window_size,
        )
    } else {
        increase_default(
            res.energy_usage,
            0,
            res.latest_consume_time_for_energy,
            now_slot,
        )
    };
    let energy_limit = calculate_global_energy_limit(&account, dyn_props);
    Ok(energy_limit.saturating_sub(decayed_usage).max(0))
}

/// Top-level energy charge for a smart-contract tx — splits the bill
/// between the contract origin and the caller per java-tron's
/// `TransactionTrace.pay()` + `ReceiptCapsule.payEnergyBill`.
///
/// * `origin`: the contract's deployer (from `SmartContract.origin_address`).
///   Pass `None` for `CreateSmartContract` (no pre-existing origin), for
///   contracts whose row is missing from `ContractStore`, or any other
///   case where the split should collapse to "caller pays everything".
/// * `origin_energy_limit`: the contract's per-tx cap on its deployer's
///   subsidy (`SmartContract.origin_energy_limit`). Ignored when `origin`
///   is `None`.
/// * `consume_user_resource_percent`: the % charged to the caller
///   (`SmartContract.consume_user_resource_percent`); the origin pays
///   `100 - this`, clamped to `[0, 100]`. Ignored when `origin` is `None`.
///
/// Returns an [`EnergyBill`] describing what each party paid. Mutates
/// both account rows. Insufficient caller funds returns
/// [`EnergyError::Insufficient`] and rolls nothing — but ONLY after
/// origin's frozen quota has been debited (mirrors java-tron, which
/// runs `useEnergy(origin)` before `payEnergyBill(caller)`); the
/// session-level revert in the executor undoes both writes atomically.
pub fn pay_energy_bill(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    caller: &Address,
    origin: Option<&Address>,
    origin_energy_limit: i64,
    consume_user_resource_percent: i64,
    energy_used: u64,
    now_slot: i64,
) -> Result<EnergyBill, EnergyError> {
    // Collapse to caller-pays-all when there's no distinct origin.
    let origin_addr = match origin {
        None => {
            return Ok(EnergyBill {
                origin_charge: None,
                caller_charge: consume_energy(accounts, dyn_props, caller, energy_used, now_slot)?,
            });
        }
        Some(o) if o == caller => {
            return Ok(EnergyBill {
                origin_charge: None,
                caller_charge: consume_energy(accounts, dyn_props, caller, energy_used, now_slot)?,
            });
        }
        Some(o) => o,
    };

    let percent = origin_percent(consume_user_resource_percent);
    let total_i = energy_used as i64;
    // `originUsage = total * percent / 100`, then clamped to the
    // smaller of (a) origin's remaining frozen quota, (b) the
    // per-contract `origin_energy_limit`. Both clamps are non-negative
    // so the result fits in i64 without overflow concerns.
    let origin_share_raw = total_i.saturating_mul(percent) / 100;
    let origin_left = origin_quota_left(accounts, dyn_props, origin_addr, now_slot)?;
    let origin_usage = origin_share_raw
        .min(origin_left)
        .min(origin_energy_limit.max(0))
        .max(0);
    let caller_usage = (total_i - origin_usage).max(0) as u64;

    // Debit origin first (frozen-only — guaranteed by the pre-clamp).
    let origin_charge = if origin_usage > 0 {
        Some(consume_energy(
            accounts,
            dyn_props,
            origin_addr,
            origin_usage as u64,
            now_slot,
        )?)
    } else {
        None
    };
    // Then debit caller. If the caller can't cover, `consume_energy`
    // returns `Insufficient` and the executor reverts the whole
    // session — origin's debit comes back with it.
    let caller_charge = consume_energy(accounts, dyn_props, caller, caller_usage, now_slot)?;

    Ok(EnergyBill {
        origin_charge,
        caller_charge,
    })
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
