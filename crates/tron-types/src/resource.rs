//! Shared resource-accounting math used by both the executor (bandwidth /
//! energy consumption) and the actuators (delegate / undelegate
//! usage-transfer).
//!
//! Mirrors java-tron's `ResourceProcessor` (the common base of
//! `BandwidthProcessor` / `EnergyProcessor`) and the per-account window
//! helpers on `AccountCapsule`:
//!
//! * Windowed-average `increase()` for per-account usage decay/growth.
//! * The per-account **window-size** machinery (`getWindowSize`,
//!   `getWindowSizeV2`, `setNewWindowSize(V2)`, `getNewWindowSize`) that
//!   `supportUnfreezeDelay` / `supportAllowCancelAllUnfreezeV2` widen.
//! * `unDelegateIncrease(V2)` — folds a receiver's transferred usage back
//!   into the owner on undelegate.
//! * `calculate_global_limit_v1 / v2` — global-ratio scaling.
//!
//! This lives in `tron-types` (not `tron-executor`) so the actuators can
//! reuse it: `tron-executor` depends on `tron-actuator`, so the math could
//! not live in the executor without an inverted dependency. java-tron
//! itself keeps `ResourceProcessor` in the `chainbase` module for the same
//! reason (both the actuator and consumption layers use it).
//!
//! Reference: `chainbase/src/main/java/org/tron/core/db/ResourceProcessor.java`
//! and `AccountCapsule.{getWindowSize,getWindowSizeV2,setNewWindowSize,
//! setNewWindowSizeV2,getUsage,getLastConsumeTime,setUsage,setLatestTime}`.
//!
//! **Hardened arithmetic.** java-tron has two modes, gated by
//! `allowHardenResourceCalculation()` (proposal #97): the hardened `BigInteger`
//! path (exact integer) and the legacy IEEE-754 `double` path. Proposal #97 is
//! **NOT active on mainnet**, so the legacy `double` path is the byte-exact one
//! there — the two disagree once operands exceed 2^53 (large-stake accounts),
//! and that gap is the staked-vs-burned resource split (`energy_fee`/`net_fee`).
//! Functions that take a `harden: bool` reproduce BOTH; callers pass
//! `DynamicPropertiesStore::allow_harden_resource_calculation()`.

use tron_proto::Account;

/// Window size in BLOCKS (24h / 3s). java-tron's
/// `ResourceProcessor::windowSize` = `WINDOW_SIZE_MS / BLOCK_PRODUCED_INTERVAL`.
pub const WINDOW_SIZE_BLOCKS: i64 = 28_800;
/// `ChainConstant.PRECISION` — precision for the windowed-average math.
pub const PRECISION: i64 = 1_000_000;
/// `ChainConstant.WINDOW_SIZE_PRECISION` — extra denominator applied to the
/// v2 (unfreeze-delay) per-account window size.
pub const WINDOW_SIZE_PRECISION: i64 = 1_000;
/// `TRX_PRECISION` — sun-per-TRX. Converts frozen-balance (sun) to "weight".
pub const TRX_PRECISION: i64 = 1_000_000;
/// `ChainConstant.BLOCK_PRODUCED_INTERVAL` in ms.
pub const BLOCK_PRODUCED_INTERVAL_MS: i64 = 3_000;
/// `AdaptiveResourceLimitConstants.PERIODS_MS / BLOCK_PRODUCED_INTERVAL`
/// = 60_000 / 3000 = 20 blocks — the chain-wide energy-usage average window.
pub const ADAPTIVE_AVERAGE_WINDOW_BLOCKS: i64 = 20;

/// `AdaptiveResourceLimitConstants.CONTRACT_RATE_NUMERATOR`.
pub const CONTRACT_RATE_NUMERATOR: i64 = 99;
pub const CONTRACT_RATE_DENOMINATOR: i64 = 100;
/// `AdaptiveResourceLimitConstants.EXPAND_RATE_NUMERATOR`.
pub const EXPAND_RATE_NUMERATOR: i64 = 1_000;
pub const EXPAND_RATE_DENOMINATOR: i64 = 999;

/// `Common.ResourceCode` — the two delegatable / windowed resources.
/// (TRON_POWER cannot be delegated and has no usage window.)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ResourceKind {
    Bandwidth,
    Energy,
}

/// The two `DynamicPropertiesStore` feature gates that change the
/// windowed-average math. Passed explicitly so this module stays
/// store-independent (and callable from both crates).
#[derive(Clone, Copy, Debug)]
pub struct ResourceGates {
    /// `dynamicStore.supportUnfreezeDelay()` (mainnet: true).
    pub support_unfreeze_delay: bool,
    /// `dynamicStore.supportAllowCancelAllUnfreezeV2()`.
    pub support_allow_cancel_all_unfreeze_v2: bool,
}

// =============================================================================
// Pure windowed-average primitives (java-tron ResourceProcessor)
// =============================================================================

/// Windowed-average usage update — java-tron's
/// `ResourceProcessor.increase(lastUsage, usage, lastTime, now, windowSize)`
/// with the hardened (BigInteger) arithmetic path.
///
/// `usage` is the bytes/energy being added this tick (0 when only decaying).
/// All times are in slot units (java-tron's `getHeadSlot()`).
pub fn increase(last_usage: i64, usage: i64, last_time: i64, now: i64, window: i64) -> i64 {
    if window <= 0 {
        return 0;
    }
    let precision = PRECISION as i128;
    let window_i = window as i128;
    let average_usage = div_ceil_i128((usage as i128) * precision, window_i);
    let mut average_last = div_ceil_i128((last_usage as i128) * precision, window_i);

    if last_time != now {
        if last_time + window > now {
            let delta = now - last_time;
            // java `ResourceProcessor.increase`: the decay is ALWAYS done in
            // IEEE-754 `double` — `round(averageLastUsage * ((windowSize - delta)
            // / (double) windowSize))` — regardless of `hardenCalculation()`
            // (which only switches the `divideCeil` above between BigInteger and
            // long). Doing it in exact integer (`round_div`) rounds differently
            // by a few units, which surfaces as the staked-vs-burned resource
            // split (`energy_fee`/`net_fee`) diverging vs java.
            let decay = (window - delta) as f64 / window as f64;
            average_last = strict_round(average_last as f64 * decay) as i128;
        } else {
            average_last = 0;
        }
    }
    let total_avg = average_last + average_usage;
    ((total_avg * window_i) / precision) as i64
}

/// Convenience wrapper using the default 24h window.
pub fn increase_default(last_usage: i64, usage: i64, last_time: i64, now: i64) -> i64 {
    increase(last_usage, 0i64.max(usage), last_time, now, WINDOW_SIZE_BLOCKS)
}

/// Pure decay using an explicit window size — `increase(last_usage, 0,
/// last_time, now, old_window)`. (The account-aware java `recovery` is
/// [`recovery_account`].)
pub fn recovery(last_usage: i64, last_time: i64, now: i64, old_window: i64) -> i64 {
    let effective_window = if old_window > 0 { old_window } else { WINDOW_SIZE_BLOCKS };
    increase(last_usage, 0, last_time, now, effective_window)
}

/// Global-limit scaling V1 — `weight * totalLimit / totalWeight` where
/// `weight = frozeBalance / TRX_PRECISION` (integer divide).
///
/// `harden` = `ALLOW_HARDEN_RESOURCE_CALCULATION` (proposal #97, **off on
/// mainnet**). When off, java's `calculateGlobalEnergyLimit` legacy branch runs
/// the multiply in IEEE-754 `double`:
/// `(long)(weight * ((double) totalLimit / totalWeight))` — which rounds
/// differently from the exact integer result once the operands lose precision,
/// so we must reproduce it to stay byte-exact on the stake-vs-burn split.
pub fn calculate_global_limit_v1(
    froze_balance: i64,
    total_limit: i64,
    total_weight: i64,
    harden: bool,
) -> i64 {
    if total_weight <= 0 {
        return 0;
    }
    let weight = froze_balance / TRX_PRECISION;
    if harden {
        ((weight as i128) * (total_limit as i128) / (total_weight as i128)) as i64
    } else {
        ((weight as f64) * (total_limit as f64 / total_weight as f64)) as i64
    }
}

/// Global-limit scaling for the `supportUnfreezeDelay` path (mainnet).
///
/// **Floors `froze / TRX_PRECISION` to whole TRX**, then scales by
/// `totalLimit / totalWeight`. This matches the java-tron binary **deployed on
/// mainnet**, whose `calculateGlobalEnergyLimitV2` computes a *long* energy
/// weight (`frozeBalance / TRX_PRECISION`) — it predates the upstream change
/// (in the vendored source) that preserves the fractional weight via
/// `(frozeBalance * totalLimit) / (TRX_PRECISION * totalWeight)`. Proven
/// byte-exact against mainnet receipts: every divergent account held its energy
/// purely as *acquired-delegated v2* with a fractional sun balance (e.g.
/// 14231726819 → weight 14231, not 14231.726819), and the receipts use the
/// floored weight. `harden` keeps java's int-vs-double split for the final
/// multiply (identical once the weight is an integer, but mirrored for fidelity).
pub fn calculate_global_limit_v2(
    froze_balance: i64,
    total_limit: i64,
    total_weight: i64,
    harden: bool,
) -> i64 {
    if total_weight <= 0 {
        return 0;
    }
    let weight = froze_balance / TRX_PRECISION;
    if harden {
        ((weight as i128) * (total_limit as i128) / (total_weight as i128)) as i64
    } else {
        ((weight as f64) * (total_limit as f64 / total_weight as f64)) as i64
    }
}

/// `divideCeil(a, b)` over i128 — `ceil(a / b)` for `a, b >= 0`.
fn div_ceil_i128(a: i128, b: i128) -> i128 {
    if b == 0 {
        return 0;
    }
    let q = a / b;
    let r = a % b;
    if r > 0 {
        q + 1
    } else {
        q
    }
}

/// java-tron `getUsage(usage, windowSize)` = `usage * windowSize / precision`.
fn get_usage_i128(usage: i128, window: i128) -> i128 {
    usage * window / (PRECISION as i128)
}

/// java-tron `getUsage(oldUsage, oldWindowSize, newUsage, newWindowSize)`
/// = `(oldUsage*oldWindowSize + newUsage*newWindowSize) / precision`.
fn get_usage2_i128(old_usage: i128, old_window: i128, new_usage: i128, new_window: i128) -> i128 {
    (old_usage * old_window + new_usage * new_window) / (PRECISION as i128)
}

/// java-tron `getNewWindowSize(lastUsage, lastWindowSize, usage, windowSize,
/// newUsage)` = `(lastUsage*lastWindowSize + usage*windowSize) / newUsage`
/// (plain integer divide — floor for non-negative operands).
fn get_new_window_size_i128(
    last_usage: i128,
    last_window: i128,
    usage: i128,
    window: i128,
    new_usage: i128,
) -> i128 {
    if new_usage == 0 {
        return 0;
    }
    (last_usage * last_window + usage * window) / new_usage
}

// =============================================================================
// Per-account window helpers (java-tron AccountCapsule)
// =============================================================================

/// Raw stored `(window_size, window_optimized)` for the resource.
fn raw_window(account: &Account, kind: ResourceKind) -> (i64, bool) {
    match kind {
        ResourceKind::Bandwidth => (account.net_window_size, account.net_window_optimized),
        ResourceKind::Energy => account
            .account_resource
            .as_ref()
            .map(|r| (r.energy_window_size, r.energy_window_optimized))
            .unwrap_or((0, false)),
    }
}

/// java-tron `AccountCapsule.getWindowSize(resourceCode)`.
pub fn window_size(account: &Account, kind: ResourceKind) -> i64 {
    let (ws, optimized) = raw_window(account, kind);
    if ws == 0 {
        return WINDOW_SIZE_BLOCKS;
    }
    if optimized {
        if ws < WINDOW_SIZE_PRECISION {
            WINDOW_SIZE_BLOCKS
        } else {
            ws / WINDOW_SIZE_PRECISION
        }
    } else {
        ws
    }
}

/// java-tron `AccountCapsule.getWindowSizeV2(resourceCode)`.
pub fn window_size_v2(account: &Account, kind: ResourceKind) -> i64 {
    let (ws, optimized) = raw_window(account, kind);
    if ws == 0 {
        return WINDOW_SIZE_BLOCKS * WINDOW_SIZE_PRECISION;
    }
    if optimized {
        ws
    } else {
        ws * WINDOW_SIZE_PRECISION
    }
}

/// java-tron `AccountCapsule.getWindowOptimized(resourceCode)`.
fn window_optimized(account: &Account, kind: ResourceKind) -> bool {
    raw_window(account, kind).1
}

/// java-tron `AccountCapsule.setNewWindowSize(resourceCode, v)`.
pub fn set_new_window_size(account: &mut Account, kind: ResourceKind, v: i64) {
    match kind {
        ResourceKind::Bandwidth => account.net_window_size = v,
        ResourceKind::Energy => {
            account.account_resource.get_or_insert_with(Default::default).energy_window_size = v;
        }
    }
}

/// java-tron `AccountCapsule.setWindowOptimized(resourceCode, b)`.
fn set_window_optimized(account: &mut Account, kind: ResourceKind, b: bool) {
    match kind {
        ResourceKind::Bandwidth => account.net_window_optimized = b,
        ResourceKind::Energy => {
            account
                .account_resource
                .get_or_insert_with(Default::default)
                .energy_window_optimized = b;
        }
    }
}

/// java-tron `AccountCapsule.setNewWindowSizeV2(resourceCode, v)` — writes the
/// window and marks the account window-optimized (so the precision-scaled
/// value is interpreted correctly on subsequent reads).
fn set_new_window_size_v2(account: &mut Account, kind: ResourceKind, v: i64) {
    set_new_window_size(account, kind, v);
    if !window_optimized(account, kind) {
        set_window_optimized(account, kind, true);
    }
}

/// java-tron `AccountCapsule.getUsage(resourceCode)`.
pub fn usage(account: &Account, kind: ResourceKind) -> i64 {
    match kind {
        ResourceKind::Bandwidth => account.net_usage,
        ResourceKind::Energy => account
            .account_resource
            .as_ref()
            .map(|r| r.energy_usage)
            .unwrap_or(0),
    }
}

/// java-tron `AccountCapsule.setUsage(resourceCode, v)`.
pub fn set_usage(account: &mut Account, kind: ResourceKind, v: i64) {
    match kind {
        ResourceKind::Bandwidth => account.net_usage = v,
        ResourceKind::Energy => {
            account.account_resource.get_or_insert_with(Default::default).energy_usage = v;
        }
    }
}

/// java-tron `AccountCapsule.getLastConsumeTime(resourceCode)`.
pub fn last_consume_time(account: &Account, kind: ResourceKind) -> i64 {
    match kind {
        ResourceKind::Bandwidth => account.latest_consume_time,
        ResourceKind::Energy => account
            .account_resource
            .as_ref()
            .map(|r| r.latest_consume_time_for_energy)
            .unwrap_or(0),
    }
}

/// java-tron `AccountCapsule.setLatestTime(resourceCode, v)`.
pub fn set_latest_time(account: &mut Account, kind: ResourceKind, v: i64) {
    match kind {
        ResourceKind::Bandwidth => account.latest_consume_time = v,
        ResourceKind::Energy => {
            account
                .account_resource
                .get_or_insert_with(Default::default)
                .latest_consume_time_for_energy = v;
        }
    }
}

/// Sum of all bandwidth-weight sources — java-tron
/// `AccountCapsule.getAllFrozenBalanceForBandwidth`.
pub fn all_frozen_balance_for_bandwidth(account: &Account) -> i64 {
    let v2: i64 = account
        .frozen_v2
        .iter()
        .filter(|fb| fb.r#type == 0) // BANDWIDTH
        .map(|fb| fb.amount)
        .sum();
    let v1: i64 = account.frozen.iter().map(|fb| fb.frozen_balance).sum();
    v2.saturating_add(v1)
        .saturating_add(account.acquired_delegated_frozen_v2_balance_for_bandwidth)
        .saturating_add(account.acquired_delegated_frozen_balance_for_bandwidth)
}

/// Sum of all energy-weight sources — java-tron
/// `AccountCapsule.getAllFrozenBalanceForEnergy`.
pub fn all_frozen_balance_for_energy(account: &Account) -> i64 {
    let res = account.account_resource.clone().unwrap_or_default();
    let v2: i64 = account
        .frozen_v2
        .iter()
        .filter(|fb| fb.r#type == 1) // ENERGY
        .map(|fb| fb.amount)
        .sum();
    let v1 = res.frozen_balance_for_energy.map(|f| f.frozen_balance).unwrap_or(0);
    v2.saturating_add(v1)
        .saturating_add(res.acquired_delegated_frozen_balance_for_energy)
        .saturating_add(res.acquired_delegated_frozen_v2_balance_for_energy)
}

/// java-tron `RepositoryImpl.usageToBalance(usage, totalWeight, totalLimit)` —
/// convert a recovered usage figure back into the sun-denominated balance it
/// represents.
///
/// `harden` selects java's two arithmetic modes (gated by
/// `ALLOW_HARDEN_RESOURCE_CALCULATION`, proposal #97 — **NOT active on
/// mainnet**, so the legacy `double` path is the byte-exact one there):
/// * harden:   `usage * totalWeight * TRX_PRECISION / totalLimit` (BigInteger / i128, exact).
/// * legacy:   `(long)((double)usage * totalWeight / totalLimit * TRX_PRECISION)`
///   — the division happens *before* the `TRX_PRECISION` multiply and the whole
///   chain is IEEE-754 `double`, so the result differs from the exact value
///   whenever `usage * totalWeight` exceeds 2^53. We must reproduce that loss.
pub fn usage_to_balance(usage: i64, total_weight: i64, total_limit: i64, harden: bool) -> i64 {
    if total_limit <= 0 {
        return 0;
    }
    if harden {
        ((usage as i128) * (total_weight as i128) * (TRX_PRECISION as i128)
            / (total_limit as i128)) as i64
    } else {
        ((usage as f64) * (total_weight as f64) / (total_limit as f64) * (TRX_PRECISION as f64))
            as i64
    }
}

/// java-tron `StrictMath.round(double)` = `floor(a + 0.5)` (the
/// `disableJavaLangMath = true` path active on mainnet). Usages are
/// non-negative so this is the only case that matters.
fn strict_round(a: f64) -> i64 {
    (a + 0.5).floor() as i64
}

fn div_ceil_i64(n: i64, d: i64) -> i64 {
    if d == 0 {
        return 0;
    }
    let q = n / d;
    if n % d > 0 {
        q + 1
    } else {
        q
    }
}

/// java-tron `ResourceProcessor.increase` on the **legacy** (`long` / `double`)
/// path — used when `ALLOW_HARDEN_RESOURCE_CALCULATION` is off (mainnet). Uses
/// wrapping `long` multiplies (java silently overflows here) and the `double`
/// decay + `StrictMath.round` step.
fn increase_legacy(last_usage: i64, usage: i64, last_time: i64, now: i64, window: i64) -> i64 {
    if window <= 0 {
        return 0;
    }
    let mut average_last = div_ceil_i64(last_usage.wrapping_mul(PRECISION), window);
    let average_usage = div_ceil_i64(usage.wrapping_mul(PRECISION), window);
    if last_time != now {
        if last_time + window > now {
            let delta = now - last_time;
            let decay = (window - delta) as f64 / window as f64;
            average_last = strict_round(average_last as f64 * decay);
        } else {
            average_last = 0;
        }
    }
    let total = average_last.wrapping_add(average_usage);
    total.wrapping_mul(window) / PRECISION
}

/// java-tron `RepositoryImpl.getAccount{Net,Energy}UsageBalanceAndRestoreSeconds`
/// — `(usageBalanceInSun, restoreSeconds)` for the account's *current* (decayed)
/// usage. Returns `(0, 0)` once the usage window has fully elapsed
/// (`now >= latestConsumeTime + windowSize`), matching java's `Pair.of(0L, 0L)`.
///
/// `now_slot` is `getHeadSlot()`. `total_weight` / `total_limit` are the
/// chain-global `TOTAL_{NET,ENERGY}_WEIGHT` / `TOTAL_NET_LIMIT` /
/// `TOTAL_ENERGY_CURRENT_LIMIT`. `harden` is `ALLOW_HARDEN_RESOURCE_CALCULATION`
/// (false on mainnet → legacy arithmetic).
pub fn account_usage_balance_and_restore_seconds(
    account: &Account,
    kind: ResourceKind,
    now_slot: i64,
    total_weight: i64,
    total_limit: i64,
    harden: bool,
) -> (i64, i64) {
    let usage_now = usage(account, kind);
    let latest = last_consume_time(account, kind);
    let window = window_size(account, kind);
    if now_slot >= latest + window {
        return (0, 0);
    }
    let restore_slots = latest + window - now_slot;
    // java `recover(usage, latestConsumeTime, now, windowSize)`.
    let new_usage = if harden {
        increase(usage_now, 0, latest, now_slot, window)
    } else {
        increase_legacy(usage_now, 0, latest, now_slot, window)
    };
    let balance = usage_to_balance(new_usage, total_weight, total_limit, harden);
    (balance, restore_slots * BLOCK_PRODUCED_INTERVAL_MS / 1_000)
}

// =============================================================================
// Account-aware windowed-average (writes the per-account window back)
// =============================================================================

/// java-tron `ResourceProcessor.recovery(accountCapsule, resourceCode,
/// lastUsage, lastTime, now)` — decay-only using the account's window size,
/// **without** writing the window back (used for read-only quota checks).
pub fn recovery_account(
    account: &Account,
    kind: ResourceKind,
    last_usage: i64,
    last_time: i64,
    now: i64,
    harden: bool,
) -> i64 {
    let window = window_size(account, kind);
    if harden {
        increase(last_usage, 0, last_time, now, window)
    } else {
        // ALLOW_HARDEN_RESOURCE_CALCULATION off (mainnet): java decays the
        // averaged usage in IEEE-754 `double` and rounds with `StrictMath.round`
        // (`floor(x + 0.5)`), which differs from the exact integer round-div by a
        // few units — and that difference is exactly the staked-vs-burned energy
        // split (`energy_fee`) seen diverging vs java.
        increase_legacy(last_usage, 0, last_time, now, window)
    }
}

/// java-tron `ResourceProcessor.increase(accountCapsule, resourceCode,
/// lastUsage, usage, lastTime, now)` — the account-aware growth/decay that
/// also recomputes and writes the per-account window size. Returns the new
/// usage. Mutates `account`'s window fields (and, via the V2 path, the
/// window-optimized flag).
pub fn increase_account(
    account: &mut Account,
    kind: ResourceKind,
    last_usage: i64,
    usage_amt: i64,
    last_time: i64,
    now: i64,
    gates: ResourceGates,
) -> i64 {
    if gates.support_allow_cancel_all_unfreeze_v2 {
        return increase_v2_account(account, kind, last_usage, usage_amt, last_time, now);
    }
    let old_window = window_size(account, kind);
    let precision = PRECISION as i128;
    let mut average_last = div_ceil_i128((last_usage as i128) * precision, old_window as i128);
    let average_usage = div_ceil_i128((usage_amt as i128) * precision, WINDOW_SIZE_BLOCKS as i128);

    if last_time != now {
        if last_time + old_window > now {
            let delta = now - last_time;
            // java decays in `double` always (only the divideCeil is harden-gated).
            let decay = (old_window - delta) as f64 / old_window as f64;
            average_last = strict_round(average_last as f64 * decay) as i128;
        } else {
            average_last = 0;
        }
    }

    let new_usage =
        get_usage2_i128(average_last, old_window as i128, average_usage, WINDOW_SIZE_BLOCKS as i128);
    if gates.support_unfreeze_delay {
        let remain_usage = get_usage_i128(average_last, old_window as i128);
        if remain_usage == 0 {
            set_new_window_size(account, kind, WINDOW_SIZE_BLOCKS);
            return new_usage as i64;
        }
        let remain_window = (old_window - (now - last_time)) as i128;
        let new_window = get_new_window_size_i128(
            remain_usage,
            remain_window,
            usage_amt as i128,
            WINDOW_SIZE_BLOCKS as i128,
            new_usage,
        );
        set_new_window_size(account, kind, new_window as i64);
    }
    new_usage as i64
}

/// java-tron `ResourceProcessor.increaseV2(...)` — the
/// `supportAllowCancelAllUnfreezeV2` window path (precision-scaled window).
fn increase_v2_account(
    account: &mut Account,
    kind: ResourceKind,
    last_usage: i64,
    usage_amt: i64,
    last_time: i64,
    now: i64,
) -> i64 {
    let old_window_v2 = window_size_v2(account, kind);
    let old_window = window_size(account, kind);
    let precision = PRECISION as i128;
    let mut average_last = div_ceil_i128((last_usage as i128) * precision, old_window as i128);
    let average_usage = div_ceil_i128((usage_amt as i128) * precision, WINDOW_SIZE_BLOCKS as i128);

    if last_time != now {
        if last_time + old_window > now {
            let delta = now - last_time;
            // java decays in `double` always (only the divideCeil is harden-gated).
            let decay = (old_window - delta) as f64 / old_window as f64;
            average_last = strict_round(average_last as f64 * decay) as i128;
        } else {
            average_last = 0;
        }
    }

    let new_usage =
        get_usage2_i128(average_last, old_window as i128, average_usage, WINDOW_SIZE_BLOCKS as i128);
    let remain_usage = get_usage_i128(average_last, old_window as i128);
    if remain_usage == 0 {
        set_new_window_size_v2(account, kind, WINDOW_SIZE_BLOCKS * WINDOW_SIZE_PRECISION);
        return new_usage as i64;
    }

    let remain_window =
        old_window_v2 as i128 - (now - last_time) as i128 * WINDOW_SIZE_PRECISION as i128;
    let bi = remain_usage * remain_window
        + (usage_amt as i128) * (WINDOW_SIZE_BLOCKS as i128) * (WINDOW_SIZE_PRECISION as i128);
    let mut new_window = div_ceil_i128(bi, new_usage);
    let cap = (WINDOW_SIZE_BLOCKS as i128) * (WINDOW_SIZE_PRECISION as i128);
    if new_window > cap {
        new_window = cap;
    }
    set_new_window_size_v2(account, kind, new_window as i64);
    new_usage as i64
}

/// java-tron `BandwidthProcessor.updateUsageForDelegated` /
/// `EnergyProcessor.updateUsage` — decay the account's usage to `now`
/// (writing the window back) **without** touching `latest_consume_time`.
pub fn update_usage(account: &mut Account, kind: ResourceKind, now: i64, gates: ResourceGates) {
    let old = usage(account, kind);
    let last = last_consume_time(account, kind);
    let new = increase_account(account, kind, old, 0, last, now, gates);
    set_usage(account, kind, new);
}

/// java-tron `ResourceProcessor.unDelegateIncrease(owner, receiver,
/// transferUsage, resourceCode, now)` — fold the receiver's transferred
/// usage back into the owner, recomputing the owner's window from the
/// usage-weighted blend of the two windows. Mutates `owner`.
pub fn undelegate_increase(
    owner: &mut Account,
    receiver: &Account,
    transfer_usage: i64,
    kind: ResourceKind,
    now: i64,
    gates: ResourceGates,
) {
    if gates.support_allow_cancel_all_unfreeze_v2 {
        undelegate_increase_v2(owner, receiver, transfer_usage, kind, now, gates);
        return;
    }
    let last_owner_time = last_consume_time(owner, kind);
    let owner_usage0 = usage(owner, kind);
    // Update itself first (decays owner usage + writes its window).
    let owner_usage = increase_account(owner, kind, owner_usage0, 0, last_owner_time, now, gates);

    let mut remain_owner_window = window_size(owner, kind);
    let mut remain_receiver_window = window_size(receiver, kind);
    if remain_owner_window < 0 {
        remain_owner_window = 0;
    }
    if remain_receiver_window < 0 {
        remain_receiver_window = 0;
    }

    let new_owner_usage = owner_usage + transfer_usage;
    if new_owner_usage == 0 {
        set_new_window_size(owner, kind, WINDOW_SIZE_BLOCKS);
        set_usage(owner, kind, 0);
        set_latest_time(owner, kind, now);
        return;
    }
    let new_owner_window = get_new_window_size_i128(
        owner_usage as i128,
        remain_owner_window as i128,
        transfer_usage as i128,
        remain_receiver_window as i128,
        new_owner_usage as i128,
    ) as i64;
    set_new_window_size(owner, kind, new_owner_window);
    set_usage(owner, kind, new_owner_usage);
    set_latest_time(owner, kind, now);
}

/// java-tron `ResourceProcessor.unDelegateIncreaseV2(...)`.
fn undelegate_increase_v2(
    owner: &mut Account,
    receiver: &Account,
    transfer_usage: i64,
    kind: ResourceKind,
    now: i64,
    gates: ResourceGates,
) {
    let last_owner_time = last_consume_time(owner, kind);
    let owner_usage0 = usage(owner, kind);
    let owner_usage = increase_account(owner, kind, owner_usage0, 0, last_owner_time, now, gates);
    let new_owner_usage = owner_usage + transfer_usage;
    if new_owner_usage == 0 {
        set_new_window_size_v2(owner, kind, WINDOW_SIZE_BLOCKS * WINDOW_SIZE_PRECISION);
        set_usage(owner, kind, 0);
        set_latest_time(owner, kind, now);
        return;
    }

    let mut remain_owner_window_v2 = window_size_v2(owner, kind);
    let mut remain_receiver_window_v2 = window_size_v2(receiver, kind);
    if remain_owner_window_v2 < 0 {
        remain_owner_window_v2 = 0;
    }
    if remain_receiver_window_v2 < 0 {
        remain_receiver_window_v2 = 0;
    }

    let bi = (owner_usage as i128) * (remain_owner_window_v2 as i128)
        + (transfer_usage as i128) * (remain_receiver_window_v2 as i128);
    let mut new_owner_window = div_ceil_i128(bi, new_owner_usage as i128);
    let cap = (WINDOW_SIZE_BLOCKS as i128) * (WINDOW_SIZE_PRECISION as i128);
    if new_owner_window > cap {
        new_owner_window = cap;
    }
    set_new_window_size_v2(owner, kind, new_owner_window as i64);
    set_usage(owner, kind, new_owner_usage);
    set_latest_time(owner, kind, now);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tron_proto::account::AccountResource;

    const GATES_V1: ResourceGates = ResourceGates {
        support_unfreeze_delay: true,
        support_allow_cancel_all_unfreeze_v2: false,
    };
    const GATES_V2: ResourceGates = ResourceGates {
        support_unfreeze_delay: true,
        support_allow_cancel_all_unfreeze_v2: true,
    };

    #[test]
    fn increase_decays_to_zero_after_full_window() {
        assert_eq!(increase(1_000_000, 0, 0, WINDOW_SIZE_BLOCKS, WINDOW_SIZE_BLOCKS), 0);
        assert_eq!(increase(1_000_000, 0, 0, WINDOW_SIZE_BLOCKS + 1, WINDOW_SIZE_BLOCKS), 0);
    }

    #[test]
    fn increase_half_window_keeps_roughly_half() {
        let half = WINDOW_SIZE_BLOCKS / 2;
        let v = increase(1_000_000, 0, 0, half, WINDOW_SIZE_BLOCKS);
        assert!((499_999..=500_001).contains(&v), "expected ~500000, got {v}");
    }

    /// Sub-1-TRX froze yields 0 — the deployed mainnet floors `froze /
    /// TRX_PRECISION`, so 0.5 TRX (500_000 sun) → weight 0 → 0 (it does NOT
    /// preserve the fractional weight; see `..._floors_to_whole_trx`).
    #[test]
    fn calculate_global_limit_v2_sub_trx_froze_is_zero() {
        assert_eq!(calculate_global_limit_v2(500_000, 1_000_000_000_000, 2_000_000, true), 0);
        assert_eq!(calculate_global_limit_v2(500_000, 1_000_000_000_000, 2_000_000, false), 0);
    }

    #[test]
    fn calculate_global_limit_v1_zero_weight_yields_zero() {
        assert_eq!(calculate_global_limit_v1(1_000_000, 1_000_000, 0, true), 0);
        assert_eq!(calculate_global_limit_v2(1_000_000, 1_000_000, 0, true), 0);
        assert_eq!(calculate_global_limit_v1(1_000_000, 1_000_000, 0, false), 0);
        assert_eq!(calculate_global_limit_v2(1_000_000, 1_000_000, 0, false), 0);
    }

    /// The deployed mainnet java-tron FLOORS `froze / TRX_PRECISION` for the
    /// `supportUnfreezeDelay` limit (its V2 uses a long energy weight, not the
    /// fractional one). Pinned against the real divergent mainnet tx c169493b
    /// (caller's whole froze is acquired-delegated v2 = 14231726819 sun, a
    /// fractional 14231.726819 TRX): the limit floors to weight 14231 → 129993,
    /// NOT the fractional-weight 129999. So V2 == V1 (floored) on mainnet.
    #[test]
    fn calculate_global_limit_v2_floors_to_whole_trx() {
        let (f, l, w) = (14_231_726_819i64, 180_000_000_000i64, 19_705_467_908i64);
        assert_eq!(calculate_global_limit_v2(f, l, w, true), 129_993);
        assert_eq!(calculate_global_limit_v2(f, l, w, false), 129_993);
        // floored V2 matches V1 exactly (both take whole-TRX weight).
        assert_eq!(
            calculate_global_limit_v2(f, l, w, true),
            calculate_global_limit_v1(f, l, w, true)
        );
    }

    // ---- window-size helpers (java AccountCapsule) -------------------------

    #[test]
    fn window_size_defaults_and_optimized_scaling() {
        let mut a = Account::default();
        // Unset → default 28800 (V1) / 28800*1000 (V2).
        assert_eq!(window_size(&a, ResourceKind::Bandwidth), WINDOW_SIZE_BLOCKS);
        assert_eq!(
            window_size_v2(&a, ResourceKind::Bandwidth),
            WINDOW_SIZE_BLOCKS * WINDOW_SIZE_PRECISION
        );
        // Non-optimized raw value: V1 = raw, V2 = raw*1000.
        a.net_window_size = 1_234;
        a.net_window_optimized = false;
        assert_eq!(window_size(&a, ResourceKind::Bandwidth), 1_234);
        assert_eq!(window_size_v2(&a, ResourceKind::Bandwidth), 1_234 * WINDOW_SIZE_PRECISION);
        // Optimized raw value: V1 = raw/1000, V2 = raw.
        a.net_window_optimized = true;
        a.net_window_size = 28_800_000;
        assert_eq!(window_size(&a, ResourceKind::Bandwidth), 28_800);
        assert_eq!(window_size_v2(&a, ResourceKind::Bandwidth), 28_800_000);
    }

    #[test]
    fn set_new_window_size_v2_marks_optimized() {
        let mut a = Account::default();
        set_new_window_size_v2(&mut a, ResourceKind::Energy, 12_345);
        let r = a.account_resource.as_ref().unwrap();
        assert_eq!(r.energy_window_size, 12_345);
        assert!(r.energy_window_optimized);
    }

    // ---- account-aware increase matches the pure path when window default --

    #[test]
    fn increase_account_default_window_matches_pure_increase() {
        let mut a = Account::default(); // window unset → default 28800
        let now = 1_000;
        let pure = increase(0, 500_000, 0, now, WINDOW_SIZE_BLOCKS);
        let acct = increase_account(&mut a, ResourceKind::Bandwidth, 0, 500_000, 0, now, GATES_V1);
        assert_eq!(pure, acct);
        // A window was written back (growth path, supportUnfreezeDelay on).
        assert!(a.net_window_size > 0);
    }

    #[test]
    fn increase_account_zero_remain_resets_window_to_default() {
        let mut a = Account::default();
        // last_usage 0, no new usage, far future → remain usage 0 → reset.
        a.net_window_size = 5_000;
        let _ = increase_account(
            &mut a,
            ResourceKind::Bandwidth,
            0,
            0,
            0,
            WINDOW_SIZE_BLOCKS * 10,
            GATES_V1,
        );
        assert_eq!(a.net_window_size, WINDOW_SIZE_BLOCKS);
    }

    // ---- unDelegateIncrease: zero usage resets, nonzero blends window ------

    #[test]
    fn undelegate_increase_zero_resets_owner() {
        let mut owner = Account::default();
        let receiver = Account::default();
        undelegate_increase(&mut owner, &receiver, 0, ResourceKind::Bandwidth, 777, GATES_V1);
        assert_eq!(owner.net_usage, 0);
        assert_eq!(owner.latest_consume_time, 777);
        assert_eq!(owner.net_window_size, WINDOW_SIZE_BLOCKS);
    }

    #[test]
    fn undelegate_increase_adds_transfer_usage_to_owner() {
        let mut owner = Account::default();
        owner.net_usage = 0;
        owner.latest_consume_time = 1_000;
        let mut receiver = Account::default();
        receiver.net_usage = 200_000;
        // now == last so owner usage doesn't decay; transfer adds straight.
        undelegate_increase(&mut owner, &receiver, 50_000, ResourceKind::Bandwidth, 1_000, GATES_V1);
        assert_eq!(owner.net_usage, 50_000);
        assert_eq!(owner.latest_consume_time, 1_000);
        assert!(owner.net_window_size > 0);
    }

    #[test]
    fn undelegate_increase_v2_sets_optimized_window() {
        let mut owner = Account::default();
        owner.account_resource = Some(AccountResource { energy_usage: 0, ..Default::default() });
        let mut receiver = Account::default();
        receiver.account_resource =
            Some(AccountResource { energy_usage: 100_000, ..Default::default() });
        undelegate_increase(&mut owner, &receiver, 40_000, ResourceKind::Energy, 2_000, GATES_V2);
        let r = owner.account_resource.as_ref().unwrap();
        assert_eq!(r.energy_usage, 40_000);
        assert_eq!(r.latest_consume_time_for_energy, 2_000);
        assert!(r.energy_window_optimized);
    }

    #[test]
    fn update_usage_decays_without_touching_latest_time() {
        let mut a = Account::default();
        a.net_usage = 1_000_000;
        a.latest_consume_time = 0;
        let half = WINDOW_SIZE_BLOCKS / 2;
        update_usage(&mut a, ResourceKind::Bandwidth, half, GATES_V1);
        assert!((499_000..=501_000).contains(&a.net_usage), "got {}", a.net_usage);
        // updateUsage must NOT advance latest_consume_time.
        assert_eq!(a.latest_consume_time, 0);
    }
}
