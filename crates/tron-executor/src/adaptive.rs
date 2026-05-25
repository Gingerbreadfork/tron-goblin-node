//! Adaptive-energy total-limit adjustment.
//!
//! Mirrors `EnergyProcessor.updateTotalEnergyAverageUsage` +
//! `EnergyProcessor.updateAdaptiveTotalEnergyLimit`, which java-tron
//! runs at the end of every block.
//!
//! The flow:
//!
//! 1. **`update_total_energy_average_usage(now_slot)`** — fold this
//!    block's `BLOCK_ENERGY_USAGE` into the chain-wide
//!    `TOTAL_ENERGY_AVERAGE_USAGE` via the windowed-average formula
//!    over a 20-block window (`AdaptiveResourceLimitConstants.PERIODS_MS /
//!    BLOCK_PRODUCED_INTERVAL = 60_000 / 3_000`).
//! 2. **`update_adaptive_total_energy_limit()`** — if chain-wide
//!    average usage exceeds `TOTAL_ENERGY_TARGET_LIMIT`, scale down
//!    `TOTAL_ENERGY_CURRENT_LIMIT` by `99/100`. Otherwise scale up by
//!    `1000/999`. Clamp to `[TOTAL_ENERGY_LIMIT, TOTAL_ENERGY_LIMIT *
//!    ADAPTIVE_RESOURCE_LIMIT_MULTIPLIER]`.
//! 3. **`reset_block_energy_usage()`** — zero the per-block accumulator
//!    so the next block starts fresh.
//!
//! Reference:
//! `chainbase/src/main/java/org/tron/core/db/EnergyProcessor.java:51-93`.
//!
//! When `ALLOW_ADAPTIVE_ENERGY != 1`, every operation here is a no-op
//! — the `TOTAL_ENERGY_CURRENT_LIMIT` stays pinned at `TOTAL_ENERGY_LIMIT`.

use tron_chainbase::DynamicPropertiesStore;

use crate::resource::{
    increase, ADAPTIVE_AVERAGE_WINDOW_BLOCKS, CONTRACT_RATE_DENOMINATOR, CONTRACT_RATE_NUMERATOR,
    EXPAND_RATE_DENOMINATOR, EXPAND_RATE_NUMERATOR,
};

/// Run the per-block adaptive-energy update. Call this from the block
/// executor *after* all transactions have been processed and *before*
/// resetting `BLOCK_ENERGY_USAGE`. Mirrors java-tron's `Manager.processBlock`
/// finalization where it calls both
/// `updateTotalEnergyAverageUsage` and `updateAdaptiveTotalEnergyLimit`.
///
/// No-ops when `ALLOW_ADAPTIVE_ENERGY != 1`.
pub fn run_per_block_adaptive_update(dyn_props: &DynamicPropertiesStore, now_slot: i64) {
    if dyn_props.allow_adaptive_energy() != 1 {
        return;
    }
    update_total_energy_average_usage(dyn_props, now_slot);
    update_adaptive_total_energy_limit(dyn_props);
    dyn_props.save_block_energy_usage(0);
}

/// Update the chain-wide energy-usage average.
/// Mirrors `EnergyProcessor.updateTotalEnergyAverageUsage`.
pub fn update_total_energy_average_usage(dyn_props: &DynamicPropertiesStore, now_slot: i64) {
    let block_usage = dyn_props.block_energy_usage();
    let average = dyn_props.total_energy_average_usage();
    let last_time = dyn_props.total_energy_average_time();
    let new_average = increase(
        average,
        block_usage,
        last_time,
        now_slot,
        ADAPTIVE_AVERAGE_WINDOW_BLOCKS,
    );
    dyn_props.save_total_energy_average_usage(new_average);
    dyn_props.save_total_energy_average_time(now_slot);
}

/// Recompute `TOTAL_ENERGY_CURRENT_LIMIT` based on whether
/// `TOTAL_ENERGY_AVERAGE_USAGE` is above or below
/// `TOTAL_ENERGY_TARGET_LIMIT`.
///
/// java-tron clamps the result to `[totalEnergyLimit,
/// totalEnergyLimit * adaptiveResourceLimitMultiplier]`. Hardened
/// (BigInteger) multiplication is used to avoid overflow on
/// `totalEnergyLimit * multiplier`.
pub fn update_adaptive_total_energy_limit(dyn_props: &DynamicPropertiesStore) {
    let average = dyn_props.total_energy_average_usage();
    let target = dyn_props.total_energy_target_limit();
    let current = dyn_props.total_energy_current_limit();
    let total = dyn_props.total_energy_limit();
    let multiplier = dyn_props.adaptive_resource_limit_multiplier();

    let scaled = if average > target {
        scale_by_rate(current, CONTRACT_RATE_NUMERATOR, CONTRACT_RATE_DENOMINATOR)
    } else {
        scale_by_rate(current, EXPAND_RATE_NUMERATOR, EXPAND_RATE_DENOMINATOR)
    };

    // upper_bound = totalEnergyLimit * multiplier, BigInteger semantics.
    let upper_bound = ((total as i128).saturating_mul(multiplier as i128)) as i64;
    let lower_bound = total;
    let clamped = scaled.max(lower_bound).min(upper_bound);
    dyn_props.save_total_energy_current_limit(clamped);
}

/// `value * numerator / denominator`, hardened with 128-bit math.
fn scale_by_rate(value: i64, num: i64, den: i64) -> i64 {
    if den == 0 {
        return value;
    }
    ((value as i128) * (num as i128) / (den as i128)) as i64
}
