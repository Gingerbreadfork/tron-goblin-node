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
/// **Preserves the fractional weight**: `(long)((double) froze / TRX_PRECISION
/// * ((double) totalLimit / totalWeight))`. This matches the java-tron binary
/// **deployed on mainnet (GreatVoyage-v4.8.1.1)**, whose
/// `calculateGlobalEnergyLimitV2` uses a `double` energy weight and has **no**
/// `hardenCalculation()` branch (the `harden` param is therefore ignored here).
/// VERIFIED LIVE against the reference node on fractional-froze accounts (e.g.
/// 410000775507 froze=249403390 → `EnergyLimit` 2342, the fractional value, not
/// the floored 2338; same for 410000a6824c→229, 410001e051da→2978,
/// 410004293a36→60 — all fractional).
///
/// HISTORICAL NOTE: an earlier reading concluded "energy V2 floors" (matching
/// the 4.8.0-125 *master* checkout). That was WRONG for the deployed 4.8.1.1
/// *release* — flooring undershoots every fractional-froze account's limit by a
/// unit, shifting its stake-vs-burn split and cascading into balance /
/// contractRet divergences. Now identical to the net V2 path
/// ([`calculate_global_net_limit_v2`]).
pub fn calculate_global_limit_v2(
    froze_balance: i64,
    total_limit: i64,
    total_weight: i64,
    _harden: bool,
) -> i64 {
    if total_weight <= 0 {
        return 0;
    }
    // The TX-consensus energy limit FLOORS the weight to a whole-TRX long
    // FIRST (java `calculateGlobalEnergyLimit` line 150 `energyWeight =
    // frozeBalance / TRX_PRECISION` — integer division — then
    // `(long)(energyWeight * ((double) totalEnergyLimit / totalEnergyWeight))`).
    // PROVEN against java-tron 4.8.1.1 local-replay ground truth for
    // acquired-delegated-v2 renters: 41727d2f froze=14233172453 → java stake
    // 129998 == floor(14233)*L/W, NOT the fractional 129999; 41dcda6c→129993,
    // 4138ce28→130166 — all the floored value. The earlier "fractional"
    // reading came from `getaccountresource` (a DISPLAY path) and INTRODUCED
    // 348 energy_fee divergences (+1..+8 stake per renter) that cascade into
    // the fc772f18 balance failures. Floor matches the deployed TX behavior.
    let weight = froze_balance / TRX_PRECISION;
    ((weight as f64) * (total_limit as f64 / total_weight as f64)) as i64
}

/// **Net**-specific V2 global-limit scaling — java
/// `BandwidthProcessor.calculateGlobalNetLimitV2`.
///
/// Like the energy V2 path ([`calculate_global_limit_v2`]), the NET V2 path
/// **preserves the fractional weight**: the divide by `TRX_PRECISION` happens in
/// `double`, so a 214.48-TRX stake yields a strictly larger limit than a
/// 214-TRX stake. Flooring the weight costs up to 1 byte of
/// `net_limit`, which wrongly rejects a frozen-net transaction whose quota java
/// covers — live-proven on mainnet account `413cadd745…` at block 83317517
/// (floored = 344 < the 345-byte tx; fractional = 345 = java's success, with an
/// identical `TOTAL_NET_WEIGHT`). The rejected account then spills every tx onto
/// its free quota until that saturates, so the 1-byte floor cascades into a
/// chain of contractRet divergences.
///
/// java-tron 4.8.1.1's `calculateGlobalNetLimitV2` is UNCONDITIONALLY this
/// `double` scaling: `(long)((double) frozeBalance / TRX_PRECISION
/// * ((double) totalNetLimit / totalNetWeight))`. The deployed release has
/// **no** `hardenCalculation()`/integer branch for NET V2 (verified against
/// `BandwidthProcessor.calculateGlobalNetLimitV2` source), so the `harden`
/// flag is ignored here — exactly as the energy V2 path
/// ([`calculate_global_limit_v2`]) ignores it. A BigInteger/i64 integer path
/// would truncate up to 1 byte differently from java's double and wrongly
/// reject a frozen-net tx java covers.
pub fn calculate_global_net_limit_v2(
    froze_balance: i64,
    total_limit: i64,
    total_weight: i64,
    _harden: bool,
) -> i64 {
    if total_weight <= 0 {
        return 0;
    }
    ((froze_balance as f64 / TRX_PRECISION as f64)
        * (total_limit as f64 / total_weight as f64)) as i64
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

// -- Legacy (`long`) growth helpers ------------------------------------------
//
// java-tron's `ResourceProcessor` performs the growth/window math entirely in
// 64-bit `long` (there is NO BigInteger branch in the deployed 4.8.1.1 code).
// The intermediate products silently overflow and wrap on the JVM, and that
// wrapped result is what mainnet commits. These helpers reproduce that exact
// `long` wrap (`wrapping_*`) so the persisted growth path stays byte-identical
// to java when an operand product exceeds `i64::MAX` — the same way
// [`increase_legacy`] already mirrors the decay/quota-check path. For in-range
// operands they are bit-for-bit equal to the i128 helpers above.

/// `long` form of [`get_usage_i128`] — `usage * windowSize / precision`.
fn get_usage_i64(usage: i64, window: i64) -> i64 {
    usage.wrapping_mul(window) / PRECISION
}

/// `long` form of [`get_usage2_i128`] —
/// `(oldUsage*oldWindowSize + newUsage*newWindowSize) / precision`.
fn get_usage2_i64(old_usage: i64, old_window: i64, new_usage: i64, new_window: i64) -> i64 {
    old_usage
        .wrapping_mul(old_window)
        .wrapping_add(new_usage.wrapping_mul(new_window))
        / PRECISION
}

/// `long` form of [`get_new_window_size_i128`] —
/// `(lastUsage*lastWindowSize + usage*windowSize) / newUsage`.
fn get_new_window_size_i64(
    last_usage: i64,
    last_window: i64,
    usage: i64,
    window: i64,
    new_usage: i64,
) -> i64 {
    if new_usage == 0 {
        return 0;
    }
    last_usage
        .wrapping_mul(last_window)
        .wrapping_add(usage.wrapping_mul(window))
        / new_usage
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
pub fn set_new_window_size_v2(account: &mut Account, kind: ResourceKind, v: i64) {
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
    // java-tron rounds the windowed-average decay with `StrictMath.round`
    // (`Maths.round(..)` → `StrictMathWrapper.round`/`MathWrapper.round`, both
    // `StrictMath.round`). That is NOT `floor(a + 0.5)`: the `a + 0.5` form
    // over-rounds by 1 at the fp edge (e.g. `a = n.499999999999…` where
    // `a + 0.5` rounds up to `n + 1.0`). `f64::round()` (ties away from zero)
    // equals `StrictMath.round` for the non-negative inputs here (avg * decay,
    // decay ∈ [0,1]) and avoids that fp error. Using `floor(a + 0.5)` drifts the
    // staked-energy/window accounting by a unit at those edges, diverging the
    // stake-vs-burn split vs java.
    a.round() as i64
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
///
/// `harden` is `ALLOW_HARDEN_RESOURCE_CALCULATION` (proposal #97, **off on
/// mainnet**). The deployed java-tron does the entire growth/window
/// computation in 64-bit `long`, whose intermediate products silently wrap;
/// when `harden == false` we reproduce that wrap exactly (the byte-exact
/// mainnet path), mirroring how the decay/quota-check path
/// ([`recovery_account`] → [`increase_legacy`]) already wraps. When
/// `harden == true` the same math is done in exact i128 (no wrap), kept
/// symmetric with the other harden-gated helpers in this module
/// ([`usage_to_balance`], [`calculate_global_net_limit_v2`]). For in-range
/// operands the two branches return identical values.
pub fn increase_account(
    account: &mut Account,
    kind: ResourceKind,
    last_usage: i64,
    usage_amt: i64,
    last_time: i64,
    now: i64,
    gates: ResourceGates,
    harden: bool,
) -> i64 {
    if gates.support_allow_cancel_all_unfreeze_v2 {
        return increase_v2_account(account, kind, last_usage, usage_amt, last_time, now, harden);
    }
    let old_window = window_size(account, kind);
    if !harden {
        return increase_account_legacy(
            account, kind, last_usage, usage_amt, last_time, now, gates, old_window,
        );
    }
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

/// Legacy (`long`, mainnet) form of [`increase_account`]'s V1 (non-cancel-all)
/// path. Mirrors java `ResourceProcessor.increase` term-for-term in wrapping
/// i64 — same operand order, same grouping, same truncating-divide points as
/// `divideCeil` / `getUsage` / `getNewWindowSize`.
fn increase_account_legacy(
    account: &mut Account,
    kind: ResourceKind,
    last_usage: i64,
    usage_amt: i64,
    last_time: i64,
    now: i64,
    gates: ResourceGates,
    old_window: i64,
) -> i64 {
    let mut average_last = div_ceil_i64(last_usage.wrapping_mul(PRECISION), old_window);
    let average_usage = div_ceil_i64(usage_amt.wrapping_mul(PRECISION), WINDOW_SIZE_BLOCKS);

    if last_time != now {
        if last_time + old_window > now {
            let delta = now - last_time;
            let decay = (old_window - delta) as f64 / old_window as f64;
            average_last = strict_round(average_last as f64 * decay);
        } else {
            average_last = 0;
        }
    }

    let new_usage = get_usage2_i64(average_last, old_window, average_usage, WINDOW_SIZE_BLOCKS);
    if gates.support_unfreeze_delay {
        let remain_usage = get_usage_i64(average_last, old_window);
        if remain_usage == 0 {
            set_new_window_size(account, kind, WINDOW_SIZE_BLOCKS);
            return new_usage;
        }
        let remain_window = old_window.wrapping_sub(now - last_time);
        let new_window = get_new_window_size_i64(
            remain_usage,
            remain_window,
            usage_amt,
            WINDOW_SIZE_BLOCKS,
            new_usage,
        );
        set_new_window_size(account, kind, new_window);
    }
    new_usage
}

/// java-tron `ResourceProcessor.increaseV2(...)` — the
/// `supportAllowCancelAllUnfreezeV2` window path (precision-scaled window).
///
/// `harden` gates the same wrapping-`long` (mainnet) vs exact-i128 split as
/// [`increase_account`].
fn increase_v2_account(
    account: &mut Account,
    kind: ResourceKind,
    last_usage: i64,
    usage_amt: i64,
    last_time: i64,
    now: i64,
    harden: bool,
) -> i64 {
    if !harden {
        return increase_v2_account_legacy(account, kind, last_usage, usage_amt, last_time, now);
    }
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

/// Legacy (`long`, mainnet) form of [`increase_v2_account`]. Mirrors java
/// `ResourceProcessor.increaseV2` term-for-term in wrapping i64.
fn increase_v2_account_legacy(
    account: &mut Account,
    kind: ResourceKind,
    last_usage: i64,
    usage_amt: i64,
    last_time: i64,
    now: i64,
) -> i64 {
    let old_window_v2 = window_size_v2(account, kind);
    let old_window = window_size(account, kind);
    let mut average_last = div_ceil_i64(last_usage.wrapping_mul(PRECISION), old_window);
    let average_usage = div_ceil_i64(usage_amt.wrapping_mul(PRECISION), WINDOW_SIZE_BLOCKS);

    if last_time != now {
        if last_time + old_window > now {
            let delta = now - last_time;
            let decay = (old_window - delta) as f64 / old_window as f64;
            average_last = strict_round(average_last as f64 * decay);
        } else {
            average_last = 0;
        }
    }

    let new_usage = get_usage2_i64(average_last, old_window, average_usage, WINDOW_SIZE_BLOCKS);
    let remain_usage = get_usage_i64(average_last, old_window);
    if remain_usage == 0 {
        set_new_window_size_v2(account, kind, WINDOW_SIZE_BLOCKS * WINDOW_SIZE_PRECISION);
        return new_usage;
    }

    // java: `remainWindowSize = oldWindowSizeV2 - (now - lastTime) * WINDOW_SIZE_PRECISION`.
    let remain_window =
        old_window_v2.wrapping_sub((now - last_time).wrapping_mul(WINDOW_SIZE_PRECISION));
    // java: `divideCeil(remainUsage * remainWindowSize
    //                    + usage * windowSize * WINDOW_SIZE_PRECISION, newUsage)`
    // — `usage * windowSize * WINDOW_SIZE_PRECISION` evaluates left-to-right.
    let numerator = remain_usage.wrapping_mul(remain_window).wrapping_add(
        usage_amt
            .wrapping_mul(WINDOW_SIZE_BLOCKS)
            .wrapping_mul(WINDOW_SIZE_PRECISION),
    );
    let mut new_window = div_ceil_i64(numerator, new_usage);
    let cap = WINDOW_SIZE_BLOCKS.wrapping_mul(WINDOW_SIZE_PRECISION);
    if new_window > cap {
        new_window = cap;
    }
    set_new_window_size_v2(account, kind, new_window);
    new_usage
}

/// java-tron `BandwidthProcessor.updateUsageForDelegated` /
/// `EnergyProcessor.updateUsage` — decay the account's usage to `now`
/// (writing the window back) **without** touching `latest_consume_time`.
pub fn update_usage(
    account: &mut Account,
    kind: ResourceKind,
    now: i64,
    gates: ResourceGates,
    harden: bool,
) {
    let old = usage(account, kind);
    let last = last_consume_time(account, kind);
    let new = increase_account(account, kind, old, 0, last, now, gates, harden);
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
    harden: bool,
) {
    if gates.support_allow_cancel_all_unfreeze_v2 {
        undelegate_increase_v2(owner, receiver, transfer_usage, kind, now, gates, harden);
        return;
    }
    let last_owner_time = last_consume_time(owner, kind);
    let owner_usage0 = usage(owner, kind);
    // Update itself first (decays owner usage + writes its window).
    let owner_usage =
        increase_account(owner, kind, owner_usage0, 0, last_owner_time, now, gates, harden);

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
    // java `getNewWindowSize` is plain `long`; harden=false reproduces the wrap.
    let new_owner_window = if harden {
        get_new_window_size_i128(
            owner_usage as i128,
            remain_owner_window as i128,
            transfer_usage as i128,
            remain_receiver_window as i128,
            new_owner_usage as i128,
        ) as i64
    } else {
        get_new_window_size_i64(
            owner_usage,
            remain_owner_window,
            transfer_usage,
            remain_receiver_window,
            new_owner_usage,
        )
    };
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
    harden: bool,
) {
    let last_owner_time = last_consume_time(owner, kind);
    let owner_usage0 = usage(owner, kind);
    let owner_usage =
        increase_account(owner, kind, owner_usage0, 0, last_owner_time, now, gates, harden);
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

    // java: `divideCeil(ownerUsage * remainOwnerWindowSizeV2
    //                    + transferUsage * remainReceiverWindowSizeV2, newOwnerUsage)`
    // — plain `long`; harden=false reproduces the wrap.
    let cap = (WINDOW_SIZE_BLOCKS as i128) * (WINDOW_SIZE_PRECISION as i128);
    let mut new_owner_window = if harden {
        let bi = (owner_usage as i128) * (remain_owner_window_v2 as i128)
            + (transfer_usage as i128) * (remain_receiver_window_v2 as i128);
        div_ceil_i128(bi, new_owner_usage as i128)
    } else {
        let numerator = owner_usage.wrapping_mul(remain_owner_window_v2).wrapping_add(
            transfer_usage.wrapping_mul(remain_receiver_window_v2),
        );
        div_ceil_i64(numerator, new_owner_usage) as i128
    };
    if new_owner_window > cap {
        new_owner_window = cap;
    }
    set_new_window_size_v2(owner, kind, new_owner_window as i64);
    set_usage(owner, kind, new_owner_usage);
    set_latest_time(owner, kind, now);
    if let Ok(__tgt) = std::env::var("TRON_ETRAJ") {
        if kind == ResourceKind::Energy {
            let oh: String = owner.address.iter().map(|b| format!("{b:02x}")).collect();
            if oh.contains(__tgt.trim_start_matches("0x")) {
                eprintln!(
                    "ETRAJ_UNDEL_OWN owner={oh} usage0={owner_usage0} usage_decayed={owner_usage} transfer={transfer_usage} own_winv2={remain_owner_window_v2} recv_winv2={remain_receiver_window_v2} new_usage={new_owner_usage} new_winv2={}",
                    new_owner_window as i64
                );
            }
        }
    }
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

    /// Sub-1-TRX froze still yields a (fractional) limit — the deployed mainnet
    /// The TX-consensus energy limit FLOORS the weight to a whole-TRX long
    /// (java `energyWeight = frozeBalance / TRX_PRECISION`), so 0.5 TRX
    /// (500_000 sun) → weight 0 → limit 0.
    #[test]
    fn calculate_global_limit_v2_sub_trx_froze_floors_to_zero() {
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

    /// The deployed mainnet java-tron (4.8.1.1) TX-consensus energy limit FLOORS
    /// the weight to a whole-TRX long — PROVEN against java-tron 4.8.1.1
    /// local-replay ground truth for acquired-delegated-v2 renters: 41727d2f
    /// froze=14233172453 → java stake 129998 = floor(14233)·L/W (NOT 129999);
    /// 41dcda6c→129993, 4138ce28→130166. The froze-fractionality CORRELATION is
    /// the proof: renters with sub-1e6-sun energy freeze diverge by +1..+8, but
    /// whole-TRX-froze accounts (412a0bc3) match byte-for-byte — so the unit is
    /// in the limit floor, not payEnergyBill. (Unlike the NET V2 path below,
    /// which is fractional — energy and net round differently on the deployed
    /// node.) The earlier "energy V2 fractional" pin was a getaccountresource
    /// DISPLAY read and introduced 348 energy_fee divergences.
    #[test]
    fn calculate_global_limit_v2_floors_weight() {
        let (f, l, w) = (14_231_726_819i64, 180_000_000_000i64, 19_705_467_908i64);
        // energy V2 == V1 (both floor the whole-TRX weight).
        assert_eq!(calculate_global_limit_v2(f, l, w, true), 129_993);
        assert_eq!(calculate_global_limit_v2(f, l, w, false), 129_993);
        assert_eq!(calculate_global_limit_v1(f, l, w, false), 129_993);
    }

    /// The deployed mainnet java-tron PRESERVES the fractional weight for the
    /// *net* (bandwidth) V2 limit (`calculateGlobalNetLimitV2`) — the opposite
    /// of the floored *energy* V2 above. Pinned against the real divergent
    /// mainnet tx cc46b1c7 (acct 413cadd745… @83317517): a 214.48-TRX bandwidth
    /// stake (214_480_000 sun) with TOTAL_NET_LIMIT 43.2e9 and TOTAL_NET_WEIGHT
    /// 26_854_832_843 yields net_limit 345 (fractional), which java uses to
    /// cover the 345-byte tx. Flooring the weight gives 344 — a 1-byte shortfall
    /// that rejects the tx and cascades the account onto its (saturating) free
    /// quota.
    #[test]
    fn calculate_global_net_limit_v2_preserves_fractional_weight() {
        let (f, l, w) = (214_480_000i64, 43_200_000_000i64, 26_854_832_843i64);
        // NET V2 keeps the .48 → 345 (java's covered value), both modes.
        assert_eq!(calculate_global_net_limit_v2(f, l, w, true), 345);
        assert_eq!(calculate_global_net_limit_v2(f, l, w, false), 345);
        // The energy V2 FLOORS the weight on the deployed node (4.8.1.1) → 344,
        // UNLIKE net (345). Proven against acquired-delegated renters (see
        // calculate_global_limit_v2_floors_weight). Energy and net round
        // differently: net keeps the fraction, energy floors the whole-TRX weight.
        assert_eq!(calculate_global_limit_v2(f, l, w, true), 344);
        assert_eq!(calculate_global_limit_v2(f, l, w, false), 344);
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
        // `increase` is the exact (i128) path, so compare against harden=true.
        let acct =
            increase_account(&mut a, ResourceKind::Bandwidth, 0, 500_000, 0, now, GATES_V1, true);
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
            false,
        );
        assert_eq!(a.net_window_size, WINDOW_SIZE_BLOCKS);
    }

    // ---- unDelegateIncrease: zero usage resets, nonzero blends window ------

    #[test]
    fn undelegate_increase_zero_resets_owner() {
        let mut owner = Account::default();
        let receiver = Account::default();
        undelegate_increase(&mut owner, &receiver, 0, ResourceKind::Bandwidth, 777, GATES_V1, false);
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
        undelegate_increase(
            &mut owner,
            &receiver,
            50_000,
            ResourceKind::Bandwidth,
            1_000,
            GATES_V1,
            false,
        );
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
        undelegate_increase(&mut owner, &receiver, 40_000, ResourceKind::Energy, 2_000, GATES_V2, false);
        let r = owner.account_resource.as_ref().unwrap();
        assert_eq!(r.energy_usage, 40_000);
        assert_eq!(r.latest_consume_time_for_energy, 2_000);
        assert!(r.energy_window_optimized);
    }

    /// The harden gate on the persisted growth path must be a NO-OP for
    /// in-range operands and engage exactly at the i64-overflow boundary,
    /// mirroring java-tron's plain-`long` (wrapping) growth math vs the exact
    /// (i128) hardened mode.
    #[test]
    fn increase_account_harden_gate_engages_at_i64_overflow_boundary() {
        // (a) In-range operands: both branches are byte-identical. `now ==
        // last_time` so there is no `double` decay step — the result is pure
        // integer windowed-average growth, identical under both modes.
        let mut a_legacy = Account::default();
        let mut a_harden = Account::default();
        let legacy = increase_account(
            &mut a_legacy,
            ResourceKind::Bandwidth,
            1_234_567,
            89_000,
            500,
            500,
            GATES_V1,
            false,
        );
        let harden = increase_account(
            &mut a_harden,
            ResourceKind::Bandwidth,
            1_234_567,
            89_000,
            500,
            500,
            GATES_V1,
            true,
        );
        assert_eq!(legacy, harden, "in-range growth must match across modes");
        assert_eq!(
            a_legacy.net_window_size, a_harden.net_window_size,
            "in-range window must match across modes"
        );

        // (b) Boundary: `last_usage * PRECISION` exceeds i64::MAX
        // (1e13 * 1e6 = 1e19 > 9.22e18), the first product java forms in
        // `divideCeil(lastUsage * precision, oldWindowSize)`. The deployed
        // mainnet java does this in `long` and the product wraps; harden=false
        // must reproduce that wrap, and it must DIFFER from the exact i128
        // (harden=true) value — proving the fix engages precisely here.
        let overflow_usage = 10_000_000_000_000i64; // 1e13
        let mut b_legacy = Account::default();
        let mut b_harden = Account::default();
        let legacy_of = increase_account(
            &mut b_legacy,
            ResourceKind::Bandwidth,
            overflow_usage,
            0,
            500,
            500,
            GATES_V1,
            false,
        );
        let harden_of = increase_account(
            &mut b_harden,
            ResourceKind::Bandwidth,
            overflow_usage,
            0,
            500,
            500,
            GATES_V1,
            true,
        );
        assert_ne!(
            legacy_of, harden_of,
            "at the i64-overflow boundary the wrapping `long` path must diverge from exact i128"
        );
        // The exact (i128) value is the lossless windowed-average round-trip
        // (no wrap): div_ceil(1e13*1e6, 28800) * 28800 / 1e6.
        let exact_avg =
            div_ceil_i128((overflow_usage as i128) * (PRECISION as i128), WINDOW_SIZE_BLOCKS as i128);
        let exact = get_usage2_i128(exact_avg, WINDOW_SIZE_BLOCKS as i128, 0, WINDOW_SIZE_BLOCKS as i128);
        assert_eq!(harden_of as i128, exact);
        // The legacy value is the wrapped-`long` result, matching java mainnet:
        // the `1e13 * 1e6` product overflows i64 and wraps before the divide.
        let wrapped_avg = div_ceil_i64(overflow_usage.wrapping_mul(PRECISION), WINDOW_SIZE_BLOCKS);
        assert_eq!(legacy_of, get_usage2_i64(wrapped_avg, WINDOW_SIZE_BLOCKS, 0, WINDOW_SIZE_BLOCKS));
    }

    #[test]
    fn update_usage_decays_without_touching_latest_time() {
        let mut a = Account::default();
        a.net_usage = 1_000_000;
        a.latest_consume_time = 0;
        let half = WINDOW_SIZE_BLOCKS / 2;
        update_usage(&mut a, ResourceKind::Bandwidth, half, GATES_V1, false);
        assert!((499_000..=501_000).contains(&a.net_usage), "got {}", a.net_usage);
        // updateUsage must NOT advance latest_consume_time.
        assert_eq!(a.latest_consume_time, 0);
    }
}
