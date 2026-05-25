//! Block solidification (PBFT finality).
//!
//! In TRON's DPoS + PBFT model, each block is signed by exactly one
//! witness — the witness scheduled for that slot. A block becomes
//! **solid** once `ceil(active_witnesses * 2/3)` distinct witnesses
//! have signed *that block or any descendant*. Once solid, a block is
//! considered final — neither fork choice nor rollback can move past it.
//!
//! Mainnet uses 27 active witnesses, so the threshold is 19 distinct
//! signatures. java-tron's exact constant is encoded as `SOLIDITY_NUMBER`
//! and matches the ⌈2/3⌉ formula.
//!
//! ## Algorithm
//!
//! Walk recent blocks newest-to-oldest, keeping a `HashSet` of witness
//! addresses. The first block whose ancestry has accumulated `threshold`
//! distinct witnesses is the latest solid block.
//!
//! ```text
//!   head:    block_N  (witness A)         ← newest
//!   parent:  block_N-1 (witness B)
//!   parent:  block_N-2 (witness A)        ← duplicate, doesn't count
//!   parent:  block_N-3 (witness C)        ← 3 distinct, ≥ threshold for 3-SR chain
//!   parent:  block_N-4 (...)              ← anything earlier is solid
//! ```
//!
//! Each tick is O(window_size) work, called once per new block.

use std::collections::HashSet;

use tron_crypto::address::Address;

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
