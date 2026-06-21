//! Slot scheduling — pure math.
//!
//! TRON produces one block every [`BLOCK_PRODUCED_INTERVAL_MS`]
//! milliseconds. Each absolute slot since genesis is owned by exactly
//! one of the [`MAX_ACTIVE_WITNESS_NUM`] active Super Representatives,
//! cycled in order from the active witness list.
//!
//! Source: `org.tron.consensus.dpos.DposSlot`. All constants pinned
//! from `org.tron.core.config.Parameter.ChainConstant`.
//!
//! These functions take *every* input they need as arguments (head
//! block time, genesis time, active witness list). They never read
//! global state — so the same code paths serve a syncing node, a
//! block producer, and fork-choice walkers without ambiguity.

use tron_crypto::address::{Address, ADDRESS_LENGTH};

/// 3-second block interval. java-tron's `ChainConstant.BLOCK_PRODUCED_INTERVAL`.
pub const BLOCK_PRODUCED_INTERVAL_MS: i64 = 3_000;

/// 27 Super Representatives. `ChainConstant.MAX_ACTIVE_WITNESS_NUM`.
pub const MAX_ACTIVE_WITNESS_NUM: usize = 27;

/// `1` — each SR produces one block per round. `ChainConstant.SINGLE_REPEAT`.
pub const SINGLE_REPEAT: i64 = 1;

/// `70%` — the supermajority threshold for block solidification.
/// `ChainConstant.SOLIDIFIED_THRESHOLD`.
pub const SOLIDIFIED_THRESHOLD_PCT: i32 = 70;

/// `128` — sliding window of recent slots used for missed-block
/// statistics. `ChainConstant.BLOCK_FILLED_SLOTS_NUMBER`.
pub const BLOCK_FILLED_SLOTS_NUMBER: usize = 128;

/// **Absolute slot number** since genesis. Slot 0 is the genesis block;
/// slot 1 starts at `genesis_time + 3000ms`.
///
/// Mirrors `DposSlot.getAbSlot`:
///   `(time - genesisBlockTime) / BLOCK_PRODUCED_INTERVAL`
#[inline]
pub fn ab_slot(time_ms: i64, genesis_time_ms: i64) -> i64 {
    (time_ms - genesis_time_ms) / BLOCK_PRODUCED_INTERVAL_MS
}

/// Number of slots between `head_block_time` and `now`. Mirrors
/// `DposSlot.getSlot`, used by block-producing SRs to figure out how
/// many empty slots they need to skip past.
///
/// `head_was_maintenance` + `maintenance_skip_slots` thread through to
/// the `getTime(1)` baseline: when the head block crossed a maintenance
/// boundary java's `getTime` adds `MAINTENANCE_SKIP_SLOTS` to the first
/// expected production slot, so the production pause around maintenance
/// is not mistaken for a missed slot. A producer that hardcodes
/// `(false, 0)` would, right after a maintenance boundary, compute a
/// relative slot two positions too high and so target the wrong witness
/// / wrong block time.
pub fn slot_from_head(
    now_ms: i64,
    head_block_time_ms: i64,
    genesis_time_ms: i64,
    head_was_maintenance: bool,
    maintenance_skip_slots: i64,
) -> i64 {
    let first_slot_time = slot_time_ms(
        1,
        head_block_time_ms,
        genesis_time_ms,
        head_was_maintenance,
        maintenance_skip_slots,
    );
    if now_ms < first_slot_time {
        return 0;
    }
    (now_ms - first_slot_time) / BLOCK_PRODUCED_INTERVAL_MS + 1
}

/// Compute the wall-clock millisecond timestamp at which `slot` starts,
/// given the head block's time and the genesis time.
///
/// `head_was_maintenance` + `maintenance_skip_slots` reproduce
/// java-tron's quirk where a block that crossed a maintenance period
/// adds extra skipped slots after it. For non-maintenance heads pass
/// `(false, 0)`.
///
/// Source: `DposSlot.getTime`.
pub fn slot_time_ms(
    slot: i64,
    head_block_time_ms: i64,
    genesis_time_ms: i64,
    head_was_maintenance: bool,
    maintenance_skip_slots: i64,
) -> i64 {
    let interval = BLOCK_PRODUCED_INTERVAL_MS;
    let effective_slot = if head_was_maintenance {
        slot + maintenance_skip_slots
    } else {
        slot
    };
    let head_aligned = head_block_time_ms - ((head_block_time_ms - genesis_time_ms) % interval);
    head_aligned + interval * effective_slot
}

/// Index into the active witness list for an absolute slot.
///
/// Formula: `(slot % (size * SINGLE_REPEAT)) / SINGLE_REPEAT`.
/// With `SINGLE_REPEAT = 1` this is just `slot % size`. Pulled out
/// as a function so a future change to `SINGLE_REPEAT` (java-tron has
/// considered batching multiple blocks per witness per round) needs
/// updating in exactly one place.
#[inline]
pub fn scheduled_witness_index(slot: i64, active_witness_count: usize) -> usize {
    assert!(active_witness_count > 0, "active witness list cannot be empty");
    let size = active_witness_count as i64;
    let raw = slot.rem_euclid(size * SINGLE_REPEAT);
    (raw / SINGLE_REPEAT) as usize
}

/// The SR address that should produce the given absolute slot.
pub fn scheduled_witness(slot: i64, active_witnesses: &[Address]) -> Address {
    let idx = scheduled_witness_index(slot, active_witnesses.len());
    active_witnesses[idx]
}

/// Decode a raw 21-byte witness address from a Block header's
/// `witness_address` field. Returns `None` if the bytes aren't a valid
/// mainnet address.
pub fn decode_witness_address(bytes: &[u8]) -> Option<Address> {
    if bytes.len() != ADDRESS_LENGTH {
        return None;
    }
    let mut buf = [0u8; ADDRESS_LENGTH];
    buf.copy_from_slice(bytes);
    Some(Address::from_raw(buf))
}
