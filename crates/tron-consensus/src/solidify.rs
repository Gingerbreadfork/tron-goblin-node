//! Block solidification (DPoS finality).
//!
//! In TRON's DPoS model a block becomes **solid** — final, immune to
//! fork choice and rollback — once enough of the active witnesses have
//! advanced past it. java-tron computes this in
//! `DposService.updateSolidBlock` (consensus/.../dpos/DposService.java
//! lines 159-176): it reads each of the active witnesses' stored
//! `LatestBlockNum`, sorts them ascending, and picks the value at index
//! `(int)(size * (1 - SOLIDIFIED_THRESHOLD / 100))`. With the mainnet
//! `SOLIDIFIED_THRESHOLD = 70` and `size = 27` that index is
//! `(int)(27 * 0.3) = 8` — the 9th-smallest latest-block number, i.e.
//! the block ~18 behind the head in steady state, which is the point at
//! which 70% of the active set has produced a strictly later block.
//!
//! [`solid_block_from_witnesses`] is the exact port of that routine.
//!
//! [`latest_solid_block`] is a separate distinct-witness window walk
//! kept for the pure consensus tests / light-client use; it is *not* the
//! algorithm java uses to set `LATEST_SOLIDIFIED_BLOCK_NUM` and the
//! syncing node no longer relies on it.

use std::collections::HashSet;

use tron_crypto::address::Address;

use crate::slot::SOLIDIFIED_THRESHOLD_PCT;

/// java-tron's exact `DposService.updateSolidBlock` solid-number pick.
///
/// Takes the active witnesses' stored `LatestBlockNum` values (one per
/// active witness, any order), sorts ascending, and returns the entry at
/// index `(int)(size * (1 - SOLIDIFIED_THRESHOLD / 100))`.
///
/// `DposService.java:160-166`:
/// ```java
/// List<Long> numbers = activeWitnesses.stream()
///     .map(a -> getWitness(a).getLatestBlockNum()).sorted().collect(...);
/// long size = activeWitnesses.size();
/// int position = (int) (size * (1 - SOLIDIFIED_THRESHOLD * 1.0 / 100));
/// long newSolidNum = numbers.get(position);
/// ```
///
/// Returns `None` for an empty witness set (java would throw on the
/// `get(position)` — the caller must hold the schedule before calling).
/// The `latest_block_nums` slice MUST contain exactly one entry per
/// active witness (zeros for witnesses that have never produced),
/// matching java's per-witness `getLatestBlockNum()` (defaults to 0).
pub fn solid_block_from_witnesses(latest_block_nums: &[i64]) -> Option<i64> {
    if latest_block_nums.is_empty() {
        return None;
    }
    let size = latest_block_nums.len();
    let mut sorted: Vec<i64> = latest_block_nums.to_vec();
    sorted.sort_unstable();
    // `(int)(size * (1 - 70/100))` — the truncating double→int cast is
    // exact for these magnitudes; reproduce it with integer math:
    // `size * (100 - PCT) / 100` then floor (integer division floors for
    // the non-negative operands here).
    let position = (size as i64 * (100 - SOLIDIFIED_THRESHOLD_PCT as i64) / 100) as usize;
    sorted.get(position).copied()
}

/// Compute the threshold for a given active-witness count.
/// Uses `ceil(active * 2/3)` to match java-tron's `SOLIDITY_NUMBER`.
pub const fn solidity_threshold(active_witnesses: usize) -> usize {
    // (a * 2 + 2) / 3  — integer ceil(2a/3) for positive a.
    (active_witnesses * 2 + 2) / 3
}

/// A snapshot of the recent block history needed for solidification —
/// just `(block_num, witness_address)` pairs in **newest-first** order.
#[derive(Debug, Clone)]
pub struct RecentBlock {
    pub num: i64,
    pub witness: Address,
}

/// Walk `recent` (newest first) and return the block number that became
/// solid given `active_witnesses` total in the active schedule.
///
/// Returns `None` if not enough distinct witnesses have signed within
/// the supplied window — the caller should not advance the
/// `LATEST_SOLIDIFIED_BLOCK_NUM` pointer in that case.
pub fn latest_solid_block(recent: &[RecentBlock], active_witnesses: usize) -> Option<i64> {
    let threshold = solidity_threshold(active_witnesses);
    if threshold == 0 {
        // Degenerate (0 witnesses) — fall back to the head.
        return recent.first().map(|b| b.num);
    }
    let mut seen: HashSet<Address> = HashSet::new();
    for block in recent.iter() {
        seen.insert(block.witness);
        if seen.len() >= threshold {
            return Some(block.num);
        }
    }
    None
}
