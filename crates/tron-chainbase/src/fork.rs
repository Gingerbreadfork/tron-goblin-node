//! java-tron `ForkController`: per-witness block-version adoption statistics
//! that gate the stat-based hard forks (`Parameter.ForkBlockVersionEnum`).
//!
//! State lives in `DynamicPropertiesStore` under java's own keys so a
//! converted java snapshot carries it unchanged:
//!
//! * `FORK_VERSION_<v>` — one byte per active witness, `1` once that
//!   witness's latest block carried version `v` (reset to zeros at every
//!   maintenance boundary until the fork passes).
//! * `VERSION_NUMBER` — the highest version whose fork has passed (java
//!   `saveLatestVersion`, 4-byte big-endian int).
//!
//! A fork `v` passes once `count(stats == 1) >= ceil(rate * witnesses / 100)`
//! and the latest block time is past the version's `hardForkTime` rounded up
//! to a maintenance boundary. Statistics are keyed by the block's exact
//! version: a block of version 38 does not count toward 37; the lower
//! versions are filled in (`upgrade`) once the higher one passes.

use std::collections::HashMap;

use tron_crypto::address::Address;

use crate::stores::{dynamic_properties_keys, DynamicPropertiesStore};
use crate::ENERGY_LIMIT_HARD_FORK_BLOCK;

/// One `ForkBlockVersionEnum` entry: block version, activation floor and the
/// percentage of active witnesses that must have adopted it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkVersion {
    pub version: i32,
    pub hard_fork_time_ms: i64,
    pub rate: i32,
}

const HARD_FORK_TIME_2020_08_07: i64 = 1_596_780_000_000;

pub const ENERGY_LIMIT: i32 = 5;
pub const VERSION_3_2_2: i32 = 6;
pub const VERSION_3_5: i32 = 7;
pub const VERSION_3_6: i32 = 8;
pub const VERSION_3_6_5: i32 = 9;
pub const VERSION_3_6_6: i32 = 10;
pub const VERSION_4_0: i32 = 16;
pub const VERSION_4_0_1: i32 = 17;
pub const VERSION_4_1: i32 = 19;
pub const VERSION_4_1_2: i32 = 20;
pub const VERSION_4_2: i32 = 21;
pub const VERSION_4_3: i32 = 22;
pub const VERSION_4_4: i32 = 23;
pub const VERSION_4_5: i32 = 24;
pub const VERSION_4_6: i32 = 25;
pub const VERSION_4_7: i32 = 26;
pub const VERSION_4_7_1: i32 = 27;
pub const VERSION_4_7_2: i32 = 28;
pub const VERSION_4_7_4: i32 = 29;
pub const VERSION_4_7_5: i32 = 30;
pub const VERSION_4_7_7: i32 = 31;
pub const VERSION_4_8_0: i32 = 32;
pub const VERSION_4_8_0_1: i32 = 33;
pub const VERSION_4_8_1: i32 = 34;
pub const VERSION_4_8_1_1: i32 = 35;
pub const VERSION_4_8_2: i32 = 36;
pub const VERSION_4_8_2_2: i32 = 37;
pub const VERSION_4_8_2_3: i32 = 38;

/// `Parameter.ChainConstant.BLOCK_VERSION` — the version a producing node
/// stamps on its blocks.
pub const BLOCK_VERSION: i32 = 38;

/// `ForkBlockVersionEnum.values()`, in declaration order.
pub const FORK_VERSIONS: [ForkVersion; 28] = [
    ForkVersion { version: ENERGY_LIMIT, hard_fork_time_ms: 0, rate: 0 },
    ForkVersion { version: VERSION_3_2_2, hard_fork_time_ms: 0, rate: 0 },
    ForkVersion { version: VERSION_3_5, hard_fork_time_ms: 0, rate: 0 },
    ForkVersion { version: VERSION_3_6, hard_fork_time_ms: 0, rate: 0 },
    ForkVersion { version: VERSION_3_6_5, hard_fork_time_ms: 0, rate: 0 },
    ForkVersion { version: VERSION_3_6_6, hard_fork_time_ms: 0, rate: 0 },
    ForkVersion { version: VERSION_4_0, hard_fork_time_ms: 0, rate: 0 },
    ForkVersion { version: VERSION_4_0_1, hard_fork_time_ms: HARD_FORK_TIME_2020_08_07, rate: 80 },
    ForkVersion { version: VERSION_4_1, hard_fork_time_ms: HARD_FORK_TIME_2020_08_07, rate: 80 },
    ForkVersion { version: VERSION_4_1_2, hard_fork_time_ms: HARD_FORK_TIME_2020_08_07, rate: 80 },
    ForkVersion { version: VERSION_4_2, hard_fork_time_ms: HARD_FORK_TIME_2020_08_07, rate: 80 },
    ForkVersion { version: VERSION_4_3, hard_fork_time_ms: HARD_FORK_TIME_2020_08_07, rate: 80 },
    ForkVersion { version: VERSION_4_4, hard_fork_time_ms: HARD_FORK_TIME_2020_08_07, rate: 80 },
    ForkVersion { version: VERSION_4_5, hard_fork_time_ms: HARD_FORK_TIME_2020_08_07, rate: 80 },
    ForkVersion { version: VERSION_4_6, hard_fork_time_ms: HARD_FORK_TIME_2020_08_07, rate: 80 },
    ForkVersion { version: VERSION_4_7, hard_fork_time_ms: HARD_FORK_TIME_2020_08_07, rate: 80 },
    ForkVersion { version: VERSION_4_7_1, hard_fork_time_ms: HARD_FORK_TIME_2020_08_07, rate: 80 },
    ForkVersion { version: VERSION_4_7_2, hard_fork_time_ms: HARD_FORK_TIME_2020_08_07, rate: 80 },
    ForkVersion { version: VERSION_4_7_4, hard_fork_time_ms: HARD_FORK_TIME_2020_08_07, rate: 80 },
    ForkVersion { version: VERSION_4_7_5, hard_fork_time_ms: HARD_FORK_TIME_2020_08_07, rate: 80 },
    ForkVersion { version: VERSION_4_7_7, hard_fork_time_ms: HARD_FORK_TIME_2020_08_07, rate: 80 },
    ForkVersion { version: VERSION_4_8_0, hard_fork_time_ms: HARD_FORK_TIME_2020_08_07, rate: 80 },
    ForkVersion { version: VERSION_4_8_0_1, hard_fork_time_ms: HARD_FORK_TIME_2020_08_07, rate: 70 },
    ForkVersion { version: VERSION_4_8_1, hard_fork_time_ms: HARD_FORK_TIME_2020_08_07, rate: 80 },
    ForkVersion { version: VERSION_4_8_1_1, hard_fork_time_ms: HARD_FORK_TIME_2020_08_07, rate: 70 },
    ForkVersion { version: VERSION_4_8_2, hard_fork_time_ms: HARD_FORK_TIME_2020_08_07, rate: 80 },
    ForkVersion { version: VERSION_4_8_2_2, hard_fork_time_ms: HARD_FORK_TIME_2020_08_07, rate: 70 },
    ForkVersion { version: VERSION_4_8_2_3, hard_fork_time_ms: HARD_FORK_TIME_2020_08_07, rate: 70 },
];

const STATS_KEY_PREFIX: &[u8] = b"FORK_VERSION_";
const VERSION_UPGRADE: u8 = 1;
const VERSION_DOWNGRADE: u8 = 0;
const DEFAULT_MAINTENANCE_INTERVAL_MS: i64 = 21_600_000;

/// Dynamic-properties key holding the per-witness stats for `version`.
pub fn stats_key(version: i32) -> Vec<u8> {
    let mut key = STATS_KEY_PREFIX.to_vec();
    key.extend_from_slice(version.to_string().as_bytes());
    key
}

pub fn fork_version(version: i32) -> Option<ForkVersion> {
    FORK_VERSIONS.iter().copied().find(|f| f.version == version)
}

/// `ceil(rate * witnesses / 100)` in exact integer arithmetic.
pub fn pass_threshold(rate: i32, witnesses: usize) -> usize {
    (rate.max(0) as usize * witnesses).div_ceil(100)
}

impl DynamicPropertiesStore {
    pub fn fork_stats(&self, version: i32) -> Option<Vec<u8>> {
        self.get_bytes(&stats_key(version))
    }

    pub fn save_fork_stats(&self, version: i32, stats: &[u8]) {
        self.put_bytes(&stats_key(version), stats);
    }

    /// java `getLatestVersion`: the highest fork version that has passed, as
    /// recorded by `update`. `0` when never written.
    pub fn latest_fork_version(&self) -> i32 {
        match self.get_bytes(dynamic_properties_keys::VERSION_NUMBER) {
            Some(b) if b.len() == 4 => i32::from_be_bytes([b[0], b[1], b[2], b[3]]),
            Some(b) if b.len() == 8 => {
                i64::from_be_bytes(b[..8].try_into().unwrap()).clamp(0, i32::MAX as i64) as i32
            }
            _ => 0,
        }
    }

    /// java `saveLatestVersion` (`ByteArray.fromInt`, 4-byte big-endian).
    pub fn save_latest_fork_version(&self, version: i32) {
        self.put_bytes(dynamic_properties_keys::VERSION_NUMBER, &version.to_be_bytes());
    }

    /// java `ForkController.pass(version)`.
    pub fn fork_passed(&self, version: i32) -> bool {
        if version > VERSION_4_0 {
            self.fork_passed_new(version)
        } else {
            self.fork_passed_old(version)
        }
    }

    fn fork_passed_old(&self, version: i32) -> bool {
        if version == ENERGY_LIMIT {
            return self.latest_block_header_number().unwrap_or(0) >= ENERGY_LIMIT_HARD_FORK_BLOCK;
        }
        all_upgraded(self.fork_stats(version).as_deref())
    }

    fn fork_passed_new(&self, version: i32) -> bool {
        let Some(fv) = fork_version(version) else {
            return false;
        };
        let latest_block_time = self.latest_block_header_timestamp().unwrap_or(0);
        let interval = self
            .maintenance_time_interval()
            .filter(|&i| i > 0)
            .unwrap_or(DEFAULT_MAINTENANCE_INTERVAL_MS);
        let hard_fork_time = ((fv.hard_fork_time_ms - 1) / interval + 1) * interval;
        if latest_block_time < hard_fork_time {
            return false;
        }
        let Some(stats) = self.fork_stats(version) else {
            return false;
        };
        if stats.is_empty() {
            return false;
        }
        let count = stats.iter().filter(|&&b| b == VERSION_UPGRADE).count();
        count >= pass_threshold(fv.rate, stats.len())
    }
}

fn all_upgraded(stats: Option<&[u8]>) -> bool {
    match stats {
        Some(s) if !s.is_empty() => s.iter().all(|&b| b == VERSION_UPGRADE),
        _ => false,
    }
}

/// java `ForkController.update(block)`: fold one applied block's
/// `(witness, version)` into the statistics. Runs after the whole block
/// (including its maintenance pass), against the active witness list the
/// block left behind.
pub fn update_fork_stats(
    dp: &DynamicPropertiesStore,
    active_witnesses: &[Address],
    block_witness: &Address,
    block_version: i32,
) {
    let Some(slot) = active_witnesses.iter().position(|w| w == block_witness) else {
        return;
    };
    if block_version < ENERGY_LIMIT {
        return;
    }
    if dp.latest_fork_version() >= block_version {
        return;
    }
    downgrade(dp, block_version, slot);

    let mut stats = dp
        .fork_stats(block_version)
        .filter(|s| s.len() == active_witnesses.len())
        .unwrap_or_else(|| vec![VERSION_DOWNGRADE; active_witnesses.len()]);

    if dp.fork_passed(block_version) {
        upgrade(dp, block_version, stats.len());
        dp.save_latest_fork_version(block_version);
        return;
    }
    stats[slot] = VERSION_UPGRADE;
    dp.save_fork_stats(block_version, &stats);
}

/// A witness producing `version` has not adopted anything newer: clear its
/// slot in every higher, not-yet-passed fork.
fn downgrade(dp: &DynamicPropertiesStore, version: i32, slot: usize) {
    for fv in FORK_VERSIONS.iter() {
        if fv.version > version && !dp.fork_passed(fv.version) {
            if let Some(mut stats) = dp.fork_stats(fv.version) {
                if slot < stats.len() {
                    stats[slot] = VERSION_DOWNGRADE;
                    dp.save_fork_stats(fv.version, &stats);
                }
            }
        }
    }
}

/// Once `version` has passed, every lower fork that has not passed yet is
/// marked fully adopted.
fn upgrade(dp: &DynamicPropertiesStore, version: i32, slot_count: usize) {
    for fv in FORK_VERSIONS.iter() {
        if fv.version < version && !dp.fork_passed(fv.version) {
            let mut stats = dp.fork_stats(fv.version).unwrap_or_default();
            if stats.is_empty() {
                stats = vec![VERSION_DOWNGRADE; slot_count];
            }
            stats.iter_mut().for_each(|b| *b = VERSION_UPGRADE);
            dp.save_fork_stats(fv.version, &stats);
        }
    }
}

/// java `ForkController.reset()`: at a maintenance boundary every fork that
/// has statistics but has not passed starts over with a zeroed array sized
/// to the new active witness set.
pub fn reset_fork_stats(dp: &DynamicPropertiesStore, active_witness_count: usize) {
    for fv in FORK_VERSIONS.iter() {
        if dp.fork_stats(fv.version).is_some() && !dp.fork_passed(fv.version) {
            dp.save_fork_stats(fv.version, &vec![VERSION_DOWNGRADE; active_witness_count]);
        }
    }
}

/// Seed the statistics for a data directory that never recorded them (one
/// synced by a build without this module). `latest_per_witness` is each
/// active witness's most recent block version; forks that enough witnesses
/// have already adopted are marked passed, the rest get the per-witness
/// slots those headers imply. Returns the latest passed version, or `None`
/// when the store already carries java state.
pub fn backfill_fork_stats(
    dp: &DynamicPropertiesStore,
    active_witnesses: &[Address],
    latest_per_witness: &HashMap<Address, i32>,
) -> Option<i32> {
    if dp.latest_fork_version() != 0 || dp.fork_stats(VERSION_4_8_2).is_some() {
        return None;
    }
    if active_witnesses.is_empty() {
        return None;
    }
    let n = active_witnesses.len();
    let mut latest = 0;
    for fv in FORK_VERSIONS.iter() {
        let adopted = active_witnesses
            .iter()
            .filter(|w| latest_per_witness.get(w).is_some_and(|&v| v >= fv.version))
            .count();
        let threshold = if fv.version > VERSION_4_0 {
            pass_threshold(fv.rate, n)
        } else {
            n
        };
        if adopted >= threshold {
            dp.save_fork_stats(fv.version, &vec![VERSION_UPGRADE; n]);
            latest = fv.version;
        } else {
            let stats: Vec<u8> = active_witnesses
                .iter()
                .map(|w| {
                    if latest_per_witness.get(w).is_some_and(|&v| v == fv.version) {
                        VERSION_UPGRADE
                    } else {
                        VERSION_DOWNGRADE
                    }
                })
                .collect();
            dp.save_fork_stats(fv.version, &stats);
        }
    }
    dp.save_latest_fork_version(latest);
    Some(latest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemBackend;
    use std::sync::Arc;

    fn witness(i: u8) -> Address {
        let mut raw = [0u8; 21];
        raw[0] = 0x41;
        raw[20] = i;
        Address::from_raw(raw)
    }

    fn store() -> DynamicPropertiesStore {
        let dp = DynamicPropertiesStore::new(Arc::new(MemBackend::new()));
        dp.save_latest_block_header_timestamp(1_790_000_000_000);
        dp.put_long(dynamic_properties_keys::MAINTENANCE_TIME_INTERVAL, 21_600_000);
        dp
    }

    #[test]
    fn stats_key_matches_java() {
        assert_eq!(stats_key(37), b"FORK_VERSION_37".to_vec());
    }

    #[test]
    fn threshold_is_ceil() {
        assert_eq!(pass_threshold(70, 27), 19);
        assert_eq!(pass_threshold(80, 27), 22);
        assert_eq!(pass_threshold(70, 10), 7);
        assert_eq!(pass_threshold(0, 27), 0);
    }

    #[test]
    fn latest_version_round_trips_as_four_byte_int() {
        let dp = store();
        assert_eq!(dp.latest_fork_version(), 0);
        dp.save_latest_fork_version(36);
        assert_eq!(dp.get_bytes(dynamic_properties_keys::VERSION_NUMBER).unwrap(), 36i32.to_be_bytes());
        assert_eq!(dp.latest_fork_version(), 36);
        dp.put_long(dynamic_properties_keys::VERSION_NUMBER, 34);
        assert_eq!(dp.latest_fork_version(), 34);
    }

    #[test]
    fn passes_at_nineteen_of_twenty_seven() {
        let dp = store();
        let active: Vec<Address> = (0..27).map(witness).collect();
        for w in active.iter().take(18) {
            update_fork_stats(&dp, &active, w, VERSION_4_8_2_2);
            assert!(!dp.fork_passed(VERSION_4_8_2_2));
        }
        update_fork_stats(&dp, &active, &active[18], VERSION_4_8_2_2);
        assert!(dp.fork_passed(VERSION_4_8_2_2));
        assert_eq!(dp.latest_fork_version(), 0);
        // The next block of that version records the pass and fills the
        // lower forks in.
        update_fork_stats(&dp, &active, &active[19], VERSION_4_8_2_2);
        assert_eq!(dp.latest_fork_version(), VERSION_4_8_2_2);
        assert!(dp.fork_passed(VERSION_4_8_2));
        assert!(dp.fork_passed(VERSION_4_7_1));
        assert_eq!(dp.fork_stats(VERSION_4_8_2).unwrap(), vec![1u8; 27]);
        // Later blocks of a passed version are ignored.
        update_fork_stats(&dp, &active, &active[0], VERSION_4_8_2_2);
        assert_eq!(dp.fork_stats(VERSION_4_8_2_2).unwrap().iter().filter(|&&b| b == 1).count(), 19);
    }

    #[test]
    fn higher_version_does_not_count_for_lower() {
        let dp = store();
        let active: Vec<Address> = (0..27).map(witness).collect();
        for w in active.iter().take(19) {
            update_fork_stats(&dp, &active, w, VERSION_4_8_2_3);
        }
        assert!(dp.fork_passed(VERSION_4_8_2_3));
        assert!(!dp.fork_passed(VERSION_4_8_2_2));
        update_fork_stats(&dp, &active, &active[19], VERSION_4_8_2_3);
        assert!(dp.fork_passed(VERSION_4_8_2_2));
    }

    #[test]
    fn downgrade_clears_the_slot_of_a_reverted_witness() {
        let dp = store();
        let active: Vec<Address> = (0..27).map(witness).collect();
        for w in active.iter().take(18) {
            update_fork_stats(&dp, &active, w, VERSION_4_8_2_2);
        }
        update_fork_stats(&dp, &active, &active[0], VERSION_4_8_2);
        assert_eq!(dp.fork_stats(VERSION_4_8_2_2).unwrap()[0], 0);
        update_fork_stats(&dp, &active, &active[18], VERSION_4_8_2_2);
        assert!(!dp.fork_passed(VERSION_4_8_2_2));
    }

    #[test]
    fn maintenance_reset_zeroes_unpassed_forks_only() {
        let dp = store();
        let active: Vec<Address> = (0..27).map(witness).collect();
        // 80% of 27 = 22: nineteen adopters leave version 36 unpassed, so a
        // maintenance boundary starts its count over.
        for w in active.iter().take(19) {
            update_fork_stats(&dp, &active, w, VERSION_4_8_2);
        }
        reset_fork_stats(&dp, 27);
        assert_eq!(dp.fork_stats(VERSION_4_8_2).unwrap(), vec![0u8; 27]);
        for w in active.iter().take(22) {
            update_fork_stats(&dp, &active, w, VERSION_4_8_2);
        }
        assert!(dp.fork_passed(VERSION_4_8_2));
        for w in active.iter().take(5) {
            update_fork_stats(&dp, &active, w, VERSION_4_8_2_2);
        }
        reset_fork_stats(&dp, 27);
        // The passed fork keeps its statistics; the pending one is zeroed.
        assert!(dp.fork_passed(VERSION_4_8_2));
        assert_eq!(dp.fork_stats(VERSION_4_8_2).unwrap().iter().filter(|&&b| b == 1).count(), 22);
        assert_eq!(dp.fork_stats(VERSION_4_8_2_2).unwrap(), vec![0u8; 27]);
        // A shrunken witness set resizes the pending array.
        reset_fork_stats(&dp, 25);
        assert_eq!(dp.fork_stats(VERSION_4_8_2_2).unwrap().len(), 25);
    }

    #[test]
    fn unknown_witness_and_pre_energy_limit_versions_are_ignored() {
        let dp = store();
        let active: Vec<Address> = (0..3).map(witness).collect();
        update_fork_stats(&dp, &active, &witness(200), VERSION_4_8_2_2);
        assert!(dp.fork_stats(VERSION_4_8_2_2).is_none());
        update_fork_stats(&dp, &active, &active[0], 4);
        assert!(dp.fork_stats(4).is_none());
    }

    #[test]
    fn time_gate_blocks_before_hard_fork_time() {
        let dp = store();
        dp.save_latest_block_header_timestamp(1_500_000_000_000);
        let active: Vec<Address> = (0..3).map(witness).collect();
        for w in &active {
            update_fork_stats(&dp, &active, w, VERSION_4_8_2_2);
        }
        assert!(!dp.fork_passed(VERSION_4_8_2_2));
        dp.save_latest_block_header_timestamp(1_600_000_000_000);
        assert!(dp.fork_passed(VERSION_4_8_2_2));
    }

    #[test]
    fn old_style_forks_need_every_witness() {
        let dp = store();
        let active: Vec<Address> = (0..3).map(witness).collect();
        update_fork_stats(&dp, &active, &active[0], VERSION_3_6_5);
        update_fork_stats(&dp, &active, &active[1], VERSION_3_6_5);
        assert!(!dp.fork_passed(VERSION_3_6_5));
        update_fork_stats(&dp, &active, &active[2], VERSION_3_6_5);
        assert!(dp.fork_passed(VERSION_3_6_5));
        dp.save_latest_block_header_number(ENERGY_LIMIT_HARD_FORK_BLOCK);
        assert!(dp.fork_passed(ENERGY_LIMIT));
    }

    #[test]
    fn backfill_marks_adopted_forks_and_partial_rollouts() {
        let dp = store();
        let active: Vec<Address> = (0..27).map(witness).collect();
        let mut latest = HashMap::new();
        for (i, w) in active.iter().enumerate() {
            latest.insert(*w, if i < 10 { 38 } else { 37 });
        }
        assert_eq!(backfill_fork_stats(&dp, &active, &latest), Some(VERSION_4_8_2_2));
        assert!(dp.fork_passed(VERSION_4_8_2_2));
        assert!(dp.fork_passed(VERSION_4_8_2));
        assert!(!dp.fork_passed(VERSION_4_8_2_3));
        assert_eq!(dp.fork_stats(VERSION_4_8_2_3).unwrap().iter().filter(|&&b| b == 1).count(), 10);
        assert_eq!(dp.latest_fork_version(), VERSION_4_8_2_2);
        assert_eq!(backfill_fork_stats(&dp, &active, &latest), None);
    }
}
