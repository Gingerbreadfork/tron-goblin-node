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

/// `ChainConstant.BLOCK_SIZE` — the byte budget a producer may fill with
/// transactions. java's `Manager.generateBlock` stops packing once the
/// running total (header included) would exceed this.
pub const BLOCK_SIZE: usize = 2_000_000;

/// Largest serialized `Block` a java-tron peer will accept off the wire:
/// `BLOCK_SIZE + Constant.ONE_THOUSAND` (`BlockMsgHandler.maxBlockSize`).
/// A block above this is dropped with `BAD_MESSAGE` ("block size over
/// limit") before any validation runs, so a block we produce or relay
/// above it is invisible to the rest of the network.
pub const MAX_BLOCK_MESSAGE_SIZE: usize = BLOCK_SIZE + 1_000;

/// Rejections raised by [`check_block_message_admission`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BlockAdmissionError {
    #[error("block size over limit: {size} > {MAX_BLOCK_MESSAGE_SIZE}")]
    SizeOverLimit { size: usize },
    #[error("block time error: timestamp {timestamp} is {gap_ms}ms ahead of now")]
    TimeTooFarAhead { timestamp: i64, gap_ms: i64 },
}

/// The two cheap checks java-tron's `BlockMsgHandler.processMessage` runs on
/// every `Block` message before it touches the block at all:
///
/// 1. `serialized_size > BLOCK_SIZE + 1000` → `BAD_MESSAGE`.
/// 2. `timestamp - now >= BLOCK_PRODUCED_INTERVAL` → `BAD_MESSAGE`.
///
/// The second admits a block up to one slot early — clock skew between an SR
/// and its peers routinely puts a fresh tip a few hundred milliseconds in the
/// future — but rejects anything a full slot or more ahead. Applying the same
/// bound keeps this node's fork tree in step with its java peers': a block they
/// dropped must not become a branch we would reorg onto.
///
/// `serialized_size` is the length of the block's original wire bytes, matching
/// java's `getSerializedSize()` on the received message.
pub fn check_block_message_admission(
    serialized_size: usize,
    block_timestamp_ms: i64,
    now_ms: i64,
) -> Result<(), BlockAdmissionError> {
    if serialized_size > MAX_BLOCK_MESSAGE_SIZE {
        return Err(BlockAdmissionError::SizeOverLimit {
            size: serialized_size,
        });
    }
    let gap = block_timestamp_ms - now_ms;
    if gap >= BLOCK_PRODUCED_INTERVAL_MS {
        return Err(BlockAdmissionError::TimeTooFarAhead {
            timestamp: block_timestamp_ms,
            gap_ms: gap,
        });
    }
    Ok(())
}

/// Whether a transaction of `tx_pack_size` bytes still fits in a block that
/// currently serializes to `current_size` bytes.
///
/// java `Manager.generateBlock` keeps a running `currentSize`, seeded with the
/// header-only block's serialized size, and skips (does not stop at) any
/// transaction that would push the total past [`BLOCK_SIZE`] — smaller
/// transactions later in the queue can still be packed. `tx_pack_size` is java's
/// `TransactionCapsule.computeTrxSizeForBlockMessage`, the size the transaction
/// contributes as field 1 of the enclosing `Block` (tag + length prefix +
/// payload), not the bare message length.
pub fn tx_fits_in_block(current_size: usize, tx_pack_size: usize) -> bool {
    current_size.saturating_add(tx_pack_size) <= BLOCK_SIZE
}

/// Size a transaction contributes to the enclosing `Block` message, matching
/// java's `CodedOutputStream.computeMessageSize(1, transaction)`: a one-byte
/// field-1 tag, a varint length prefix, then the payload.
pub fn tx_pack_size(tx_serialized_size: usize) -> usize {
    1 + varint_len(tx_serialized_size) + tx_serialized_size
}

/// Byte length of `value` encoded as a protobuf varint.
fn varint_len(value: usize) -> usize {
    let mut n = 1;
    let mut v = value >> 7;
    while v > 0 {
        n += 1;
        v >>= 7;
    }
    n
}

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
