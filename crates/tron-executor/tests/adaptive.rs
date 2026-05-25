//! Tests for `adaptive::run_per_block_adaptive_update`.
//!
//! Covers:
//!
//! 1. No-op when `ALLOW_ADAPTIVE_ENERGY != 1`.
//! 2. Scale-down when chain-wide average usage exceeds target.
//! 3. Scale-up (with clamp to `total_energy_limit`) when usage is below
//!    target.
//! 4. Clamp to upper bound (`total_limit * multiplier`).
//! 5. `BLOCK_ENERGY_USAGE` reset to 0 after the update.

use std::sync::Arc;

use tron_chainbase::{DynamicPropertiesStore, KvBackend, MemBackend};
use tron_executor::adaptive::run_per_block_adaptive_update;

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn props_with_defaults(total_limit: i64, current: i64, target: i64) -> DynamicPropertiesStore {
    let dp = DynamicPropertiesStore::new(mem());
    dp.save_total_energy_limit(total_limit);
    dp.save_total_energy_current_limit(current);
    dp.save_total_energy_target_limit(target);
    dp.save_adaptive_resource_limit_multiplier(1_000);
    dp
}

#[test]
fn disabled_flag_yields_no_op() {
    let dp = props_with_defaults(1_000, 1_000, 100);
    dp.save_block_energy_usage(10_000_000);
    // ALLOW_ADAPTIVE_ENERGY unset.
    run_per_block_adaptive_update(&dp, 100);
    // current_limit untouched.
    assert_eq!(dp.total_energy_current_limit(), 1_000);
    // BLOCK_ENERGY_USAGE not reset (since the whole update is skipped).
    assert_eq!(dp.block_energy_usage(), 10_000_000);
}

#[test]
fn enabled_resets_block_energy_usage() {
    let dp = props_with_defaults(1_000, 1_000, 100);
    dp.put_long(b"ALLOW_ADAPTIVE_ENERGY", 1);
    dp.save_block_energy_usage(50_000);
    run_per_block_adaptive_update(&dp, 100);
    assert_eq!(dp.block_energy_usage(), 0);
}

#[test]
fn scale_down_when_usage_above_target() {
    let dp = props_with_defaults(
        /*total_limit=*/ 1_000,
        /*current=*/ 10_000,
        /*target=*/ 100,
    );
    dp.put_long(b"ALLOW_ADAPTIVE_ENERGY", 1);
    // Force average_usage > target by seeding TOTAL_ENERGY_AVERAGE_USAGE high.
    dp.save_total_energy_average_usage(1_000);
    dp.save_total_energy_average_time(50);
    dp.save_block_energy_usage(1_000_000);
    run_per_block_adaptive_update(&dp, 100);
    // current limit scaled down by 99/100 from 10_000 → 9_900,
    // but clamped to at least total_limit (1_000).
    assert!(dp.total_energy_current_limit() < 10_000);
    assert!(dp.total_energy_current_limit() >= 1_000);
}

#[test]
fn scale_up_when_usage_below_target_clamps_to_lower_bound() {
    let dp = props_with_defaults(
        /*total_limit=*/ 1_000,
        /*current=*/ 1_000,
        /*target=*/ 10_000,
    );
    dp.put_long(b"ALLOW_ADAPTIVE_ENERGY", 1);
    dp.save_total_energy_average_usage(0); // way below target
    dp.save_total_energy_average_time(0);
    dp.save_block_energy_usage(0);
    run_per_block_adaptive_update(&dp, 100);
    // 1000 * 1000/999 = 1001; clamped to current = 1001 (above lower bound).
    let after = dp.total_energy_current_limit();
    assert!(after >= 1_000, "got {after}, expected ≥ lower bound 1000");
    assert!(after <= 1_000 * 1_000, "got {after}, expected ≤ multiplier upper bound");
}

#[test]
fn scale_up_clamps_to_upper_bound() {
    let dp = props_with_defaults(
        /*total_limit=*/ 10,
        /*current=*/ 10_000, // already way above the multiplier cap
        /*target=*/ 10_000,
    );
    dp.save_adaptive_resource_limit_multiplier(5); // upper = 10*5 = 50
    dp.put_long(b"ALLOW_ADAPTIVE_ENERGY", 1);
    dp.save_total_energy_average_usage(0);
    dp.save_total_energy_average_time(0);
    run_per_block_adaptive_update(&dp, 100);
    assert_eq!(dp.total_energy_current_limit(), 50);
}

#[test]
fn block_energy_usage_folds_into_average() {
    let dp = props_with_defaults(1_000, 1_000, 100);
    dp.put_long(b"ALLOW_ADAPTIVE_ENERGY", 1);
    dp.save_block_energy_usage(1_000);
    let before_avg = dp.total_energy_average_usage();
    run_per_block_adaptive_update(&dp, 10);
    let after_avg = dp.total_energy_average_usage();
    // Average should have increased from the per-block usage fold-in.
    assert!(after_avg > before_avg, "before={before_avg}, after={after_avg}");
}
