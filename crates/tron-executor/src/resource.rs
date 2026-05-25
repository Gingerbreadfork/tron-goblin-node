//! Shared resource-accounting math used by both bandwidth and energy.
//!
//! Mirrors java-tron's `ResourceProcessor` (the common base class of
//! `BandwidthProcessor` and `EnergyProcessor`):
//!
//! * Windowed-average `increase()` for per-account usage decay/growth.
//! * `recovery()` — same as `increase()` but using the account's stored
//!   per-resource `window_size` (rather than the global default), which
//!   v2 freeze accounting may have widened.
//! * `calculate_global_limit_v1` / `v2` — the global-ratio scaling that
//!   distributes `TOTAL_*_LIMIT` proportionally to each account's share
//!   of `TOTAL_*_WEIGHT`.
//!
//! Reference: `chainbase/src/main/java/org/tron/core/db/ResourceProcessor.java`.
//!
//! **Hardened arithmetic.** Java-tron has two modes — the legacy
//! `long`-arithmetic path and the `BigInteger` `allowHardenResourceCalculation()`
//! path. Mainnet has the hardened path on as of v4.7.7; we always use the
//! hardened path because (a) it cannot overflow for any plausible input
//! and (b) it produces the same results as the legacy path for non-edge
//! inputs. The legacy path's overflow behavior would only matter for
//! historical replay of blocks from before the proposal activated; that
//! is not in scope for first-mainnet-sync.

/// Window size in BLOCKS (24h / 3s). java-tron's
/// `ResourceProcessor::windowSize`.
pub const WINDOW_SIZE_BLOCKS: i64 = 28_800;
/// Precision for the windowed-average math. java-tron's
/// `ChainConstant.PRECISION`.
pub const PRECISION: i64 = 1_000_000;
/// `ChainConstant.WINDOW_SIZE_PRECISION` — extra denominator applied to
/// the v2 (unfreeze-delay) per-account window size.
pub const WINDOW_SIZE_PRECISION: i64 = 1_000;
/// `TRX_PRECISION` — sun-per-TRX. Used by the global-limit calculation
/// to convert frozen-balance (in sun) to "weight units".
pub const TRX_PRECISION: i64 = 1_000_000;
/// Adaptive `BLOCK_PRODUCED_INTERVAL` in ms (java-tron's
/// `ChainConstant.BLOCK_PRODUCED_INTERVAL`).
pub const BLOCK_PRODUCED_INTERVAL_MS: i64 = 3_000;
/// `AdaptiveResourceLimitConstants.PERIODS_MS / BLOCK_PRODUCED_INTERVAL`
/// = 60_000 / 3000 = 20 blocks. The window used for the
/// chain-wide energy-usage average.
pub const ADAPTIVE_AVERAGE_WINDOW_BLOCKS: i64 = 20;

/// `AdaptiveResourceLimitConstants.CONTRACT_RATE_NUMERATOR` — the
/// shrink rate applied to `TOTAL_ENERGY_CURRENT_LIMIT` when chain-wide
/// usage exceeds the target.
pub const CONTRACT_RATE_NUMERATOR: i64 = 99;
pub const CONTRACT_RATE_DENOMINATOR: i64 = 100;
/// `AdaptiveResourceLimitConstants.EXPAND_RATE_NUMERATOR` — the grow
/// rate applied when chain-wide usage is below target.
pub const EXPAND_RATE_NUMERATOR: i64 = 1_000;
pub const EXPAND_RATE_DENOMINATOR: i64 = 999;

/// Windowed-average usage update — java-tron's
/// `ResourceProcessor.increase(lastUsage, usage, lastTime, now, windowSize)`
/// with the hardened (BigInteger) arithmetic path.
///
/// `usage` is the bytes/energy being added this tick (0 when only
/// decaying — used to compute the *current* effective usage before the
/// quota check).
///
/// All times are in slot units (block-count since genesis for energy,
/// block-count since genesis as approximated by `latest_block_header_number`
/// for bandwidth).
pub fn increase(last_usage: i64, usage: i64, last_time: i64, now: i64, window: i64) -> i64 {
    if window <= 0 {
        return 0;
    }
    // Hardened path: 128-bit intermediates (i128 in Rust, since
    // i64*i64 fits in 127 bits and division stays within i128).
    let precision = PRECISION as i128;
    let window_i = window as i128;
    let average_usage = div_ceil_i128((usage as i128) * precision, window_i);
    let mut average_last = div_ceil_i128((last_usage as i128) * precision, window_i);

    if last_time != now {
        if last_time + window > now {
            let delta = (now - last_time) as i128;
            // java-tron uses double arithmetic here and `Math.round` (or
            // `StrictMath.round` under the harden flag). We compute the
            // equivalent in integer math: `round(average_last * (W - d) / W)`.
            let numerator = average_last * (window_i - delta);
            average_last = round_div_i128(numerator, window_i);
        } else {
            average_last = 0;
        }
    }
    let total_avg = average_last + average_usage;
    // Convert back from "average per block" to "bytes/energy used in
    // window" — i.e. `totalAvg * windowSize / precision`. This is what
    // java-tron stores as the new account.usage.
    ((total_avg * window_i) / precision) as i64
}

/// Convenience wrapper using the default 24h window. Used by the
/// bandwidth path on accounts that don't have a per-resource window
/// override.
pub fn increase_default(last_usage: i64, usage: i64, last_time: i64, now: i64) -> i64 {
    increase(last_usage, usage, last_time, now, WINDOW_SIZE_BLOCKS)
}

/// Java-tron's `ResourceProcessor.recovery()` — pure decay using the
/// account's per-resource old window size. Equivalent to
/// `increase(last_usage, 0, last_time, now, old_window)`.
pub fn recovery(last_usage: i64, last_time: i64, now: i64, old_window: i64) -> i64 {
    let effective_window = if old_window > 0 { old_window } else { WINDOW_SIZE_BLOCKS };
    increase(last_usage, 0, last_time, now, effective_window)
}

/// Global-limit scaling — java-tron's `ResourceProcessor.calculateGlobalLimitV1`.
///
/// Returns `weight * totalLimit / totalWeight` where
/// `weight = frozeBalance / TRX_PRECISION` (i.e. balance-in-TRX, not sun).
///
/// Used pre-`supportUnfreezeDelay`. Hardened with 128-bit math so the
/// `(weight * totalLimit)` intermediate never overflows.
pub fn calculate_global_limit_v1(froze_balance: i64, total_limit: i64, total_weight: i64) -> i64 {
    if total_weight <= 0 {
        return 0;
    }
    let weight = froze_balance / TRX_PRECISION;
    ((weight as i128) * (total_limit as i128) / (total_weight as i128)) as i64
}

/// Global-limit scaling V2 — `(frozeBalance * totalLimit) / (TRX_PRECISION * totalWeight)`
/// with a single truncation at the end. Used when `supportUnfreezeDelay`
/// is active (mainnet, post-fork).
///
/// Critically: fractional weight (`frozeBalance < TRX_PRECISION`) is
/// preserved through the multiplication and only truncated at the final
/// divide, so dust frozen amounts still get proportional limit. This is
/// the *hardened* V2 — java-tron's `calculateGlobalLimitV2` replaced an
/// earlier double-arithmetic implementation.
pub fn calculate_global_limit_v2(froze_balance: i64, total_limit: i64, total_weight: i64) -> i64 {
    if total_weight <= 0 {
        return 0;
    }
    let num = (froze_balance as i128) * (total_limit as i128);
    let den = (TRX_PRECISION as i128) * (total_weight as i128);
    (num / den) as i64
}

/// `divideCeil(a, b)` over i128 — `ceil(a / b)`. Required so the
/// windowed-average decay rounds toward larger usage (which is what
/// java-tron's `BigInteger.divideAndRemainder` + add-1-if-remainder does).
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

/// `Math.round(a / b)` over i128 — banker-style round-half-up. Used by
/// the decay step where java-tron rounds the double `averageLastUsage * decay`.
///
/// Java's `Math.round(double)` returns `floor(x + 0.5)`. For positive
/// integer inputs (which is what we always have here — usages are
/// non-negative), that's the same as `(a + b/2) / b`.
fn round_div_i128(a: i128, b: i128) -> i128 {
    if b == 0 {
        return 0;
    }
    (a + b / 2) / b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn increase_decays_to_zero_after_full_window() {
        assert_eq!(increase(1_000_000, 0, 0, WINDOW_SIZE_BLOCKS, WINDOW_SIZE_BLOCKS), 0);
        assert_eq!(increase(1_000_000, 0, 0, WINDOW_SIZE_BLOCKS + 1, WINDOW_SIZE_BLOCKS), 0);
    }

    #[test]
    fn increase_half_window_keeps_roughly_half() {
        let half = WINDOW_SIZE_BLOCKS / 2;
        let v = increase(1_000_000, 0, 0, half, WINDOW_SIZE_BLOCKS);
        // Exactly half ± rounding.
        let expected = 500_000;
        assert!(
            (expected - 1..=expected + 1).contains(&v),
            "expected ~{expected}, got {v}"
        );
    }

    #[test]
    fn increase_zero_window_is_safe() {
        assert_eq!(increase(1, 1, 0, 1, 0), 0);
    }

    #[test]
    fn calculate_global_limit_v2_preserves_fractional_weight() {
        // 0.5 TRX frozen → 0.5 * totalLimit / totalWeight.
        // With totalLimit=1_000_000_000_000 and totalWeight=2_000_000 TRX-weight,
        // result = 500_000 sun * 1e12 / (1e6 * 2e6) = 5e17 / 2e12 = 250_000.
        let r = calculate_global_limit_v2(500_000, 1_000_000_000_000, 2_000_000);
        assert_eq!(r, 250_000);
    }

    #[test]
    fn calculate_global_limit_v1_zero_weight_yields_zero() {
        assert_eq!(calculate_global_limit_v1(1_000_000, 1_000_000, 0), 0);
    }

    #[test]
    fn calculate_global_limit_v2_zero_weight_yields_zero() {
        assert_eq!(calculate_global_limit_v2(1_000_000, 1_000_000, 0), 0);
    }
}
