//! Block-level consensus checks — the port of java-tron's
//! `DposService.validBlock` (consensus/.../dpos/DposService.java).
//!
//! This complements the structural validation in [`tron_types`]
//! (parent link, tx-trie root, witness signature). A block can be
//! structurally valid — correctly signed by some witness — and still
//! be **consensus-invalid**: produced for a non-advancing or misaligned
//! slot, or by a witness that wasn't scheduled to produce that slot.
//!
//! [`verify_block_witness`] is the narrow scheduled-witness check (used
//! by the producer round-trip tests). [`validate_block_consensus`] is the
//! full inbound-block gate that mirrors `validBlock` in java's exact
//! order: timestamp alignment, slot monotonicity, non-zero relative slot,
//! and the scheduled-witness identity.

use tron_proto::Block;

use crate::slot::{
    ab_slot, decode_witness_address, scheduled_witness_index, BLOCK_PRODUCED_INTERVAL_MS,
    SINGLE_REPEAT,
};
use tron_crypto::address::Address;

/// `ChainConstant.MAINTENANCE_SKIP_SLOTS` — extra slots skipped by
/// `DposSlot.getTime` when the head block crossed a maintenance boundary.
pub const MAINTENANCE_SKIP_SLOTS: i64 = 2;

/// Errors raised by [`verify_block_witness`] / [`validate_block_consensus`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConsensusError {
    #[error("block has no header / raw_data")]
    NoHeader,
    #[error("block's witness_address is not a valid 21-byte address")]
    InvalidWitnessAddress,
    #[error("empty active witness list")]
    EmptyActiveWitnesses,
    #[error(
        "wrong witness for slot {slot}: expected {expected:?}, got {got:?}"
    )]
    WrongWitness {
        slot: i64,
        expected: Address,
        got: Address,
    },
    #[error("block timestamp {timestamp} not aligned to {BLOCK_PRODUCED_INTERVAL_MS}ms slot grid")]
    Misaligned { timestamp: i64 },
    #[error("non-advancing slot: block slot {b_slot} <= head slot {h_slot}")]
    NonAdvancingSlot { b_slot: i64, h_slot: i64 },
    #[error("block slot resolves to 0 (no slot crossed since head)")]
    ZeroSlot,
}

/// Verify that `block.witness_address` matches the SR scheduled to
/// produce the block's slot.
pub fn verify_block_witness(
    block: &Block,
    active_witnesses: &[Address],
    genesis_time_ms: i64,
) -> Result<(), ConsensusError> {
    if active_witnesses.is_empty() {
        return Err(ConsensusError::EmptyActiveWitnesses);
    }
    let raw = block
        .block_header
        .as_ref()
        .and_then(|h| h.raw_data.as_ref())
        .ok_or(ConsensusError::NoHeader)?;
    let block_witness =
        decode_witness_address(&raw.witness_address).ok_or(ConsensusError::InvalidWitnessAddress)?;

    let slot = ab_slot(raw.timestamp, genesis_time_ms);
    let idx = scheduled_witness_index(slot, active_witnesses.len());
    let expected = active_witnesses[idx];
    if expected != block_witness {
        return Err(ConsensusError::WrongWitness {
            slot,
            expected,
            got: block_witness,
        });
    }
    Ok(())
}

/// `DposSlot.getSlot` — the relative slot of `time_ms` measured from the
/// head block, accounting for the maintenance skip.
///
/// `DposSlot.java:28-34` + `getTime(1)` (`:36-50`): the first expected
/// production slot after the head is the head timestamp aligned DOWN to
/// the slot grid, plus one interval — plus `MAINTENANCE_SKIP_SLOTS` more
/// when the head block crossed a maintenance boundary
/// (`lastHeadBlockIsMaintenance`). `getSlot` then returns 0 if `time_ms`
/// hasn't reached that first slot, else the slot index (1-based).
fn relative_slot(
    time_ms: i64,
    head_time_ms: i64,
    genesis_time_ms: i64,
    head_was_maintenance: bool,
) -> i64 {
    let interval = BLOCK_PRODUCED_INTERVAL_MS;
    let skip = if head_was_maintenance {
        MAINTENANCE_SKIP_SLOTS
    } else {
        0
    };
    let head_aligned =
        head_time_ms - (head_time_ms - genesis_time_ms).rem_euclid(interval);
    let first_slot_time = head_aligned + (1 + skip) * interval;
    if time_ms < first_slot_time {
        0
    } else {
        (time_ms - first_slot_time) / interval + 1
    }
}

/// Full consensus block-acceptance gate — the exact ported sequence of
/// `DposService.validBlock` (consensus/.../dpos/DposService.java:113-149),
/// for every inbound block once the chain is past genesis.
///
/// Checks, in java's order:
///   1. **Timestamp alignment** (gated on `allow_consensus_logic_optimization`):
///      `timeStamp % BLOCK_PRODUCED_INTERVAL == 0`.
///   2. **Slot monotonicity** (ungated): the block's absolute slot must
///      strictly exceed the head's — `bSlot <= hSlot` is rejected.
///   3. **Non-zero relative slot** (gated): `getSlot(timeStamp) != 0`.
///   4. **Scheduled witness** (ungated): the block's witness must equal
///      `getScheduledWitness(slot)` for that slot.
///
/// `head_was_maintenance` mirrors `consensusDelegate.lastHeadBlockIsMaintenance()`
/// (`DynamicPropertiesStore.getStateFlag() == 1`); callers pass it from the
/// head block's persisted state flag so the maintenance skip in `getTime`
/// is reproduced. `allow_consensus_logic_optimization` mirrors the proposal
/// flag of the same name (gates the alignment + zero-slot rejects, both of
/// which java only enforces once the optimization is active).
///
/// Returns `Ok(())` for the genesis-era case (`head` not yet set) is the
/// caller's responsibility — java early-returns `true` when
/// `getLatestBlockHeaderNumber() == 0`; this function assumes a real head.
#[allow(clippy::too_many_arguments)]
pub fn validate_block_consensus(
    block: &Block,
    active_witnesses: &[Address],
    head_time_ms: i64,
    genesis_time_ms: i64,
    head_was_maintenance: bool,
    allow_consensus_logic_optimization: bool,
) -> Result<(), ConsensusError> {
    if active_witnesses.is_empty() {
        return Err(ConsensusError::EmptyActiveWitnesses);
    }
    let raw = block
        .block_header
        .as_ref()
        .and_then(|h| h.raw_data.as_ref())
        .ok_or(ConsensusError::NoHeader)?;
    let block_witness =
        decode_witness_address(&raw.witness_address).ok_or(ConsensusError::InvalidWitnessAddress)?;
    let timestamp = raw.timestamp;

    // 1. Timestamp alignment (gated). java rejects a block whose timestamp
    //    isn't on the 3s grid once allowConsensusLogicOptimization is set.
    if allow_consensus_logic_optimization
        && timestamp.rem_euclid(BLOCK_PRODUCED_INTERVAL_MS) != 0
    {
        return Err(ConsensusError::Misaligned { timestamp });
    }

    // 2. Slot monotonicity (ungated). The block's absolute slot must
    //    strictly exceed the head's — same-slot or backwards-time blocks
    //    are rejected even when their parent link / number look correct.
    let b_slot = ab_slot(timestamp, genesis_time_ms);
    let h_slot = ab_slot(head_time_ms, genesis_time_ms);
    if b_slot <= h_slot {
        return Err(ConsensusError::NonAdvancingSlot { b_slot, h_slot });
    }

    // 3. Non-zero relative slot (gated). getSlot == 0 means the block's
    //    timestamp didn't reach the first expected slot after the head.
    let slot = relative_slot(timestamp, head_time_ms, genesis_time_ms, head_was_maintenance);
    if slot == 0 && allow_consensus_logic_optimization {
        return Err(ConsensusError::ZeroSlot);
    }

    // 4. Scheduled witness (ungated). java's getScheduledWitness(slot)
    //    indexes active[(getAbSlot(headTime) + slot) % size] — NOT
    //    active[getAbSlot(blockTime) % size]; the two differ by the
    //    maintenance skip baked into `slot`. Reproduce java exactly.
    let current_slot = h_slot + slot;
    let size = active_witnesses.len() as i64;
    let witness_index = (current_slot.rem_euclid(size * SINGLE_REPEAT) / SINGLE_REPEAT) as usize;
    let expected = active_witnesses[witness_index];
    if expected != block_witness {
        return Err(ConsensusError::WrongWitness {
            slot,
            expected,
            got: block_witness,
        });
    }
    Ok(())
}
