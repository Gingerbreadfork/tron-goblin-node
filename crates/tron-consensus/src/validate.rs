//! Block-level consensus check: was this block produced by the SR
//! that the slot scheduler says owns the slot?
//!
//! This complements the structural validation in [`tron_types`]
//! (parent link, tx-trie root, witness signature). A block can be
//! structurally valid — correctly signed by some witness — and still
//! be **consensus-invalid** because that witness wasn't supposed to
//! produce a block at that slot.

use tron_proto::Block;

use crate::slot::{ab_slot, decode_witness_address, scheduled_witness_index};
use tron_crypto::address::Address;

/// Errors raised by [`verify_block_witness`].
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
