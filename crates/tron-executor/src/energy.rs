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
    calculate_global_limit_v1, calculate_global_limit_v2, increase_account, increase_default,
    recovery_account, update_usage, usage as resource_usage, window_size, window_size_v2,
    ResourceGates, ResourceKind, TRX_PRECISION,
};

thread_local! {
    /// Per-tx capture of each account's BUDGET-TIME energy quota — java
    /// `VMActuator.getAccountEnergyLimitWithFixRatio` stores `callerEnergyLeft`
    /// before execution and `ReceiptCapsule.payEnergyBill` splits frozen-vs-fee
    /// against that STORED value, not a post-execution re-read. Matters when the
    /// caller self-rents mid-tx (a JustLend rental delegates fresh frozen energy
    /// back to it) — the re-read quota is then inflated, so we'd bill frozen
    /// where java bills fee. Keyed by address bytes; cleared per VM tx.
    static PRE_TX_ENERGY_QUOTA: std::cell::RefCell<std::collections::HashMap<Vec<u8>, i64>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
}

/// Store an account's budget-time energy quota for the self-rent split fix.
pub fn set_pre_tx_energy_quota(addr: &[u8], quota: i64) {
    PRE_TX_ENERGY_QUOTA.with(|m| {
        m.borrow_mut().insert(addr.to_vec(), quota);
    });
}

/// Clear the budget-time quota capture (call once per tx, before its budget).
pub fn clear_pre_tx_energy_quota() {
    PRE_TX_ENERGY_QUOTA.with(|m| m.borrow_mut().clear());
}

fn pre_tx_energy_quota_for(addr: &Address) -> Option<i64> {
    let key: &[u8] = addr.as_bytes();
    PRE_TX_ENERGY_QUOTA.with(|m| m.borrow().get(key).copied())
}

/// The two-step caller energy quota (`energy_limit - recover(decayed_D)`),
/// computed IDENTICALLY to [`consume_energy`]'s `quota_left`, captured at budget
/// time so the frozen-vs-fee split bills against the PRE-rent value (java
/// `payEnergyBill` parity).
pub fn caller_energy_quota_left(
    account: &Account,
    dyn_props: &DynamicPropertiesStore,
    now_slot: i64,
) -> i64 {
    let res = account.account_resource.clone().unwrap_or_default();
    let decayed_usage = if dyn_props.support_unfreeze_delay() {
        let gates = ResourceGates {
            support_unfreeze_delay: true,
            support_allow_cancel_all_unfreeze_v2: dyn_props.support_allow_cancel_all_unfreeze_v2(),
        };
        let mut q = account.clone();
        update_usage(&mut q, ResourceKind::Energy, now_slot, gates);
        let decayed_d = resource_usage(&q, ResourceKind::Energy);
        recovery_account(
            &q,
            ResourceKind::Energy,
            decayed_d,
            now_slot,
            now_slot,
            dyn_props.allow_harden_resource_calculation(),
        )
    } else {
        increase_default(res.energy_usage, 0, res.latest_consume_time_for_energy, now_slot)
    };
    let energy_limit = calculate_global_energy_limit(account, dyn_props);
    energy_limit.saturating_sub(decayed_usage).max(0)
}

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
    // NOTE: do NOT early-return on `energy_used == 0`. java-tron's
    // `payEnergyBill` calls `useEnergy(account, usage, now)` even with
    // `usage == 0` (origin charged 0% under `consume_user_resource_percent
    // == 100`, or caller charged 0 when the origin covers all), and
    // `useEnergy` UNCONDITIONALLY decays `energy_usage`, rewrites the
    // per-account window, and stamps `latest_consume_time`. Skipping that for
    // a 0 charge left the account's usage stale-high, so its NEXT charge
    // decayed from the wrong base and over-charged `energy_fee` by a unit or
    // two — a silent per-account drift that cascades. The executor only calls
    // into the energy path when the tx's TOTAL energy is > 0 (java's
    // `energyUsageTotal <= 0` guard), so a 0 here is always a real split slice.
    let energy_used_i = energy_used as i64;
    let mut account = accounts.get(caller)?.ok_or(EnergyError::AccountMissing)?;

    // Read current windowed-decay of the caller's energy_usage. java-tron
    // uses `recovery()` when supportUnfreezeDelay is on (preserves the
    // per-account window), else `increase()` with the default window.
    let support_unfreeze_delay = dyn_props.support_unfreeze_delay();
    // Clone (not move) so `account.account_resource` stays intact: the
    // account-aware growth path mutates the window fields on it in place.
    let res = account.account_resource.clone().unwrap_or_default();
    let current_usage = res.energy_usage;
    let latest_consume = res.latest_consume_time_for_energy;
    let decayed_usage = if support_unfreeze_delay {
        // java computes the caller's remaining frozen-energy quota in
        // `ReceiptCapsule.payEnergyBill` via `getAccountLeftEnergyFromFreeze`,
        // and by then the VM's `updateUsage` has ALREADY decayed+floored
        // `energy_usage` to `decayed_D` and rewritten the per-account window.
        // `getAccountLeftEnergyFromFreeze` then `recover(decayed_D, now, now)` —
        // `lastTime == now` so no further time-decay, but the
        // `divideCeil(decayed_D*precision, window_after)*window_after/precision`
        // round-trip can nudge it up a unit. A single `recover(current_usage)`
        // (one decay, no re-quantize) undershoots that quota by the occasional
        // unit, so the staked-vs-fee split — and hence the stored
        // `energy_usage` — drifts vs java. Replicate the two-step quota on a
        // clone (no mutation of the real account before the balance pre-flight).
        let gates = ResourceGates {
            support_unfreeze_delay: true,
            support_allow_cancel_all_unfreeze_v2: dyn_props.support_allow_cancel_all_unfreeze_v2(),
        };
        let mut q = account.clone();
        update_usage(&mut q, ResourceKind::Energy, now_slot, gates);
        let decayed_d = resource_usage(&q, ResourceKind::Energy);
        recovery_account(
            &q,
            ResourceKind::Energy,
            decayed_d,
            now_slot,
            now_slot,
            dyn_props.allow_harden_resource_calculation(),
        )
    } else {
        increase_default(current_usage, 0, latest_consume, now_slot)
    };

    let energy_limit = calculate_global_energy_limit(&account, dyn_props);
    let quota_left = energy_limit.saturating_sub(decayed_usage).max(0);
    // SELF-RENT FIX (verified java-exact, e.g. 9fa74013 energy_fee 0→842900):
    // bill the frozen-vs-fee split against the budget-time `callerEnergyLeft`,
    // not this post-execution re-read (which is inflated when the caller
    // self-rented mid-tx). Identical to `quota_left` when the caller did NOT
    // self-rent, so a no-op there.
    let quota_left = pre_tx_energy_quota_for(caller).unwrap_or(quota_left);
    let energy_window_before = window_size(&account, ResourceKind::Energy);
    let energy_window_before_v2 = window_size_v2(&account, ResourceKind::Energy);
    let account_pre_decay = account.clone();

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

    // Charge the frozen-quota slice. java-tron's `ReceiptCapsule.payEnergyBill`
    // ALWAYS calls `EnergyProcessor.useEnergy(account, frozenPortion, now)` —
    // including when the frozen portion is 0 (the caller pays the whole bill by
    // fee). `useEnergy` unconditionally decays `energy_usage` (the windowed
    // `increase()`), rewrites the per-account window, and stamps
    // `latest_consume_time`. The previous code special-cased `frozen == 0` to
    // ONLY stamp the time — skipping the decay + window rewrite — which left
    // `energy_usage` stale-high and the window un-recomputed, so the account's
    // NEXT charge decayed from the wrong base and over-charged `energy_fee` by a
    // unit or two: a silent per-account drift that cascades into balance/
    // contractRet divergences. Run the identical path for `frozen == 0` (the
    // `increase` with `usage = 0` is exactly java's `useEnergy(.., 0, now)`).
    let new_energy_usage = if support_unfreeze_delay {
        // java-tron `useEnergy`: the account-aware `increase()` recomputes AND
        // writes back the per-account energy window (energy_window_size /
        // energy_window_optimized) in place.
        let gates = ResourceGates {
            support_unfreeze_delay: true,
            support_allow_cancel_all_unfreeze_v2: dyn_props.support_allow_cancel_all_unfreeze_v2(),
        };
        // java's VM energy accounting is TWO-PHASE, and the two phases do NOT
        // collapse into a single windowed `increase`:
        //   1. `VMActuator` pre-consumes the available frozen energy, but first
        //      calls `EnergyProcessor.updateUsage` — which decays `energy_usage`
        //      to `now`, FLOORs it (`getUsage = avg*window/precision`) to a
        //      `decayed_D`, and rewrites the per-account window. The pre-consume
        //      and `TransactionTrace.resetAccountUsage` then cancel out, leaving
        //      the account at exactly `(decayed_D, window_after_decay)` with
        //      `latestConsumeTime = now`.
        //   2. `ReceiptCapsule.payEnergyBill -> EnergyProcessor.useEnergy` then
        //      `increase(decayed_D, staked, now, now)` — `lastTime == now`, so
        //      NO further decay; it adds the staked slice onto the *floored*
        //      `decayed_D` using `window_after_decay`.
        // A single `increase(current_usage, staked, lct, now)` keeps the decayed
        // average UN-floored and decays with the pre-decay window, so its stored
        // usage drifts a sub-unit from java's. Across the tens of thousands of
        // delegate/undelegate ops a heavy energy-rental account sees per window,
        // that sub-unit compounds into the +1 `energy_usage` that shifts every
        // `CheckUnDelegateResource` read (the af6f4896 / JustLend +6/+7 cascade).
        // Replicate java's two phases exactly.
        update_usage(&mut account, ResourceKind::Energy, now_slot, gates);
        let decayed_d = resource_usage(&account, ResourceKind::Energy);
        let new = increase_account(
            &mut account,
            ResourceKind::Energy,
            decayed_d,
            energy_from_frozen,
            now_slot,
            now_slot,
            gates,
        );
        let r = account.account_resource.get_or_insert_with(Default::default);
        r.energy_usage = new;
        r.latest_consume_time_for_energy = now_slot;
        new
    } else {
        let new = increase_default(decayed_usage, energy_from_frozen, now_slot, now_slot);
        let new_res = AccountResource {
            energy_usage: new,
            latest_consume_time_for_energy: now_slot,
            ..res.clone()
        };
        account.account_resource = Some(new_res);
        new
    };

    // Apply the TRX fee slice, if any.
    if energy_remainder > 0 {
        account.balance -= fee;
        pay_energy_fee(dyn_props, fee);
    }
    account.latest_opration_time = head_block_timestamp(dyn_props);
    accounts.put(caller, &account)?;

    // BLOCK_ENERGY_USAGE accumulator: drives the adaptive-energy
    // recalculation at every block boundary (or maintenance, depending
    // on java-tron's path). Bump whether the energy came from frozen
    // or fee — adaptive scaling is about chain-wide load, not how the
    // user paid.
    if dyn_props.allow_adaptive_energy() == 1 {
        let cur = dyn_props.block_energy_usage();
        dyn_props.save_block_energy_usage(cur.saturating_add(energy_used_i));
    }

    if let Ok(t) = std::env::var("TRON_ETRACE") {
        let addr: String = caller.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        if t.split(',').any(|x| addr == x.trim().trim_start_matches("0x")) {
            // DECAY-PATH CONSISTENCY CHECK: caller_left uses recovery_account
            // (increase_legacy), new_usage uses increase_account (increase_v2).
            // Recompute the decayed usage via the increase_account(usage=0) path
            // on a clone and compare — a difference proves the two paths decay
            // the same usage inconsistently (the off-by-1 stake-vs-burn split).
            let mut clone = account_pre_decay.clone();
            let gates_dbg = ResourceGates {
                support_unfreeze_delay: dyn_props.support_unfreeze_delay(),
                support_allow_cancel_all_unfreeze_v2: dyn_props
                    .support_allow_cancel_all_unfreeze_v2(),
            };
            let decayed_via_increase = increase_account(
                &mut clone,
                ResourceKind::Energy,
                current_usage,
                0,
                latest_consume,
                now_slot,
                gates_dbg,
            );
            eprintln!(
                "EDECAY addr={addr} cusage={current_usage} decayed_recovery={decayed_usage} decayed_via_increase={decayed_via_increase} delta={}",
                decayed_via_increase - decayed_usage
            );
            eprintln!(
                "ETRACE addr={addr} cusage={current_usage} lct={latest_consume} now={now_slot} \
                 win_before={energy_window_before} winv2_before={energy_window_before_v2} \
                 decayed={decayed_usage} limit={energy_limit} froze={} \
                 quota_left={quota_left} eused={energy_used_i} from_frozen={energy_from_frozen} \
                 new_usage={new_energy_usage} win_after={} winv2_after={} fee={fee} tew={} tel={}",
                all_frozen_balance_for_energy(&account),
                window_size(&account, ResourceKind::Energy),
                window_size_v2(&account, ResourceKind::Energy),
                dyn_props.total_energy_weight(),
                dyn_props.total_energy_current_limit(),
            );
        }
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
    // ALLOW_HARDEN_RESOURCE_CALCULATION (proposal #97) is OFF on mainnet, so
    // java runs the legacy IEEE-754 `double` scaling; we must match it or the
    // stake-vs-TRX-burn split (energy_fee) drifts by a few units.
    let harden = dyn_props.allow_harden_resource_calculation();

    if dyn_props.support_unfreeze_delay() {
        return calculate_global_limit_v2(froze_balance, total_limit, total_weight, harden);
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
    calculate_global_limit_v1(froze_balance, total_limit, total_weight, harden)
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

/// java `EnergyProcessor.getAccountLeftEnergyFromFreeze` — the account's
/// currently-available staked energy: the global limit derived from its
/// frozen-for-energy balance minus its windowed-decayed `energy_usage`,
/// floored at 0. The pre-execution VM energy budget
/// ([`vm_energy_budget_trigger`] / [`account_energy_limit_with_fix_ratio`]) and
/// the per-account `origin_quota_left` charge clamp both read through this so
/// the budget and the charge stay consistent.
pub fn account_left_energy_from_freeze(
    account: &Account,
    dyn_props: &DynamicPropertiesStore,
    now_slot: i64,
) -> i64 {
    let (energy_usage, latest_consume) = account
        .account_resource
        .as_ref()
        .map(|r| (r.energy_usage, r.latest_consume_time_for_energy))
        .unwrap_or((0, 0));
    let decayed_usage = if dyn_props.support_unfreeze_delay() {
        // Window-interpreted decay — see `consume_energy`.
        recovery_account(
            account,
            ResourceKind::Energy,
            energy_usage,
            latest_consume,
            now_slot,
            dyn_props.allow_harden_resource_calculation(),
        )
    } else {
        increase_default(energy_usage, 0, latest_consume, now_slot)
    };
    let energy_limit = calculate_global_energy_limit(account, dyn_props);
    energy_limit.saturating_sub(decayed_usage).max(0)
}

/// How much energy the origin account could pay from its frozen quota
/// right now. Returns 0 if the account has no row.
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
    Ok(account_left_energy_from_freeze(&account, dyn_props, now_slot))
}

/// java `Constant.CREATOR_DEFAULT_ENERGY_LIMIT` (1000 × 10_000). A contract row
/// whose stored `origin_energy_limit` is the proto default `0`
/// (`PB_DEFAULT_ENERGY_LIMIT`) predates the per-contract origin cap and is
/// treated as this value. Mirrors `ContractCapsule.getOriginEnergyLimit`.
pub const CREATOR_DEFAULT_ENERGY_LIMIT: i64 = 1000 * 10_000;

/// java `ContractCapsule.getOriginEnergyLimit`: a stored `0` maps to
/// [`CREATOR_DEFAULT_ENERGY_LIMIT`]. Applied to BOTH the pre-execution energy
/// budget and the post-execution charge so an old contract (`origin_energy_limit
/// == 0`, common for pre-2020 deploys) lets its origin subsidize the caller's
/// energy exactly as java does — without this the caller is over-charged for
/// every call to such a contract.
pub fn effective_origin_energy_limit(raw_origin_energy_limit: i64) -> i64 {
    if raw_origin_energy_limit == 0 {
        CREATOR_DEFAULT_ENERGY_LIMIT
    } else {
        raw_origin_energy_limit
    }
}

/// sun-per-energy, java `VMActuator`: `energyFee` when `> 0`, else
/// `VMConstant.SUN_PER_ENERGY` (100). Differs from [`DynamicPropertiesStore::
/// energy_fee`] only when the stored fee is a non-positive misconfiguration.
fn sun_per_energy(dyn_props: &DynamicPropertiesStore) -> i64 {
    let f = dyn_props.energy_fee();
    if f > 0 {
        f
    } else {
        100
    }
}

/// java `VMActuator.getAccountEnergyLimitWithFixRatio` — the CALLER's energy
/// budget: `min(leftFrozenEnergy + max(balance - callValue, 0) / sunPerEnergy,
/// feeLimit / sunPerEnergy)`. Pure read (no `energy_usage` reservation write —
/// our charge in [`consume_energy`] already lands java's net final state, so
/// replaying java's reserve-then-refund would double-count). Used directly as
/// the budget for `CreateSmartContract` (caller == origin) and as the caller
/// term of [`vm_energy_budget_trigger`].
pub fn account_energy_limit_with_fix_ratio(
    caller: &Account,
    dyn_props: &DynamicPropertiesStore,
    fee_limit: i64,
    call_value: i64,
    now_slot: i64,
) -> i64 {
    let spe = sun_per_energy(dyn_props);
    let left_frozen = account_left_energy_from_freeze(caller, dyn_props, now_slot);
    let energy_from_balance = caller.balance.saturating_sub(call_value).max(0) / spe;
    let available = left_frozen.saturating_add(energy_from_balance);
    let energy_from_fee_limit = fee_limit / spe;
    available.min(energy_from_fee_limit)
}

/// java `VMActuator.getTotalEnergyLimitWithFixRatio` for a `TriggerSmartContract`
/// call: the caller's budget plus the contract creator's subsidy.
///
/// * `caller` / `creator` are the resolved account rows. Pass `creator = None`
///   when the contract has no distinct origin (origin == caller, or the
///   contract row is missing) — then only the caller term applies.
/// * `consume_user_resource_percent` is the % charged to the caller (clamped to
///   `[0,100]`); the origin subsidizes `100 - percent`.
/// * `raw_origin_energy_limit` is the contract's stored cap (the `0 → default`
///   remap is applied here via [`effective_origin_energy_limit`]).
///
/// Pure reads — the actual split charge happens after execution in
/// [`pay_energy_bill`].
pub fn vm_energy_budget_trigger(
    dyn_props: &DynamicPropertiesStore,
    caller: &Account,
    creator: Option<&Account>,
    consume_user_resource_percent: i64,
    raw_origin_energy_limit: i64,
    fee_limit: i64,
    call_value: i64,
    now_slot: i64,
) -> i64 {
    // SELF-RENT FIX: capture the caller's quota at budget time (before the VM
    // runs / self-rents) — java's `setCallerEnergyLeft`.
    set_pre_tx_energy_quota(
        &caller.address,
        caller_energy_quota_left(caller, dyn_props, now_slot),
    );
    let caller_energy_limit =
        account_energy_limit_with_fix_ratio(caller, dyn_props, fee_limit, call_value, now_slot);
    let Some(creator) = creator else {
        return caller_energy_limit;
    };
    let percent = consume_user_resource_percent.clamp(0, 100);
    let origin_energy_limit = effective_origin_energy_limit(raw_origin_energy_limit).max(0);
    // `originEnergyLeft` is only read when the origin actually subsidizes part
    // of the call (`percent < 100`), matching java.
    let origin_left = if percent < 100 {
        account_left_energy_from_freeze(creator, dyn_props, now_slot)
    } else {
        0
    };
    let creator_energy_limit = if percent <= 0 {
        origin_left.min(origin_energy_limit)
    } else if percent < 100 {
        // min(callerEnergyLimit * (100 - percent) / percent,
        //     min(originEnergyLeft, originEnergyLimit)) — i128 to avoid the
        // intermediate multiply overflowing i64.
        let by_ratio = ((caller_energy_limit as i128) * ((100 - percent) as i128)
            / (percent as i128)) as i64;
        by_ratio.min(origin_left.min(origin_energy_limit))
    } else {
        0
    };
    caller_energy_limit.saturating_add(creator_energy_limit)
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

    // Debit origin first (frozen-only — guaranteed by the pre-clamp). java's
    // `ReceiptCapsule.payEnergyBill` calls `useEnergy(origin, originUsage, now)`
    // UNCONDITIONALLY when the origin account EXISTS — even `originUsage == 0`,
    // the common case under `consume_user_resource_percent == 100`: it decays
    // the origin's `energy_usage` and rewrites its window on EVERY call to its
    // contract. Skipping the debit for `origin_usage == 0` left popular contract
    // owners' energy_usage stale-high, drifting their own later charges. A
    // MISSING origin row collapses to caller-pays-all (java's
    // `Objects.isNull(origin)` arm — `origin_quota_left` already returned 0, so
    // `caller_usage == total`), and must not be charged. So decay the origin iff
    // its account exists.
    let origin_charge = if accounts.get(origin_addr)?.is_some() {
        Some(consume_energy(accounts, dyn_props, origin_addr, origin_usage as u64, now_slot)?)
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
