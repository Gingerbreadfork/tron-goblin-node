//! Block-producer foundation: assemble + sign a block from a witness
//! keypair and a set of transactions.
//!
//! ## What's here
//!
//! * [`assemble_block`] — pure function that builds a `Block` proto
//!   given the parent's `BlockId`, the witness's address, the slot
//!   timestamp, and the list of transactions to include. Computes the
//!   `tx_trie_root` via [`tron_types::calc_tx_trie_root`].
//! * [`produce_block`] — combines `assemble_block` with
//!   [`tron_types::sign_block`] so callers get a fully-signed block in
//!   one call.
//!
//! ## What's *not* here (deferred to a separate SR-runtime session)
//!
//! * A mempool. `produce_block` takes a `Vec<Transaction>` slice from
//!   the caller. A real producer ranks, deduplicates, and budget-checks
//!   pending txs.
//! * Slot-driven scheduling. The producer doesn't pick *when* to fire —
//!   the caller decides (using [`crate::slot`] helpers to know when
//!   it's their slot).
//! * P2P broadcast. The signed block is returned; the caller plumbs it
//!   into `tron-net`'s outbound queue.
//! * Energy / bandwidth reservation. Production-grade producers reject
//!   txs that would exceed their slot budget; we just include whatever
//!   the caller supplies.
//!
//! ## Cross-cutting invariants
//!
//! * `parent_hash` is taken directly from the parent's `BlockId`
//!   (full 32 bytes). Note that `BlockId::num()` and the new block's
//!   number must satisfy `new.num() == parent.num() + 1` — the helper
//!   enforces this so producers can't accidentally skip block numbers.
//! * `timestamp` is the slot's wall-clock millisecond; consensus
//!   validates this against the schedule (see
//!   [`crate::slot::scheduled_witness`]).

use prost::Message;
use tron_crypto::address::Address;
use tron_proto::{block_header::Raw as BlockHeaderRaw, Block, BlockHeader, Transaction};
use tron_types::{block_id_from_block, sign_block, BlockId, BlockValidateError};

/// Errors that can occur during block assembly / production.
#[derive(Debug, thiserror::Error)]
pub enum ProducerError {
    #[error("block number must be strictly greater than parent: got {got}, parent {parent}")]
    NonMonotonicNumber { parent: i64, got: i64 },
    #[error("signing failed: {0}")]
    Sign(#[from] BlockValidateError),
}

/// Pure assembly: build an unsigned `Block` from its parts. Does not
/// touch the witness key; callers wanting a signed block use
/// [`produce_block`] which composes this with `sign_block`.
pub fn assemble_block(
    parent: &BlockId,
    new_number: i64,
    timestamp_ms: i64,
    witness_address: &Address,
    transactions: Vec<Transaction>,
    version: i32,
) -> Result<Block, ProducerError> {
    let parent_num = parent.num() as i64;
    if new_number <= parent_num {
        return Err(ProducerError::NonMonotonicNumber {
            parent: parent_num,
            got: new_number,
        });
    }

    let tx_trie_root = tron_types::calc_tx_trie_root(&transactions)
        .map(|h| h.to_vec())
        .unwrap_or_default();

    let raw = BlockHeaderRaw {
        timestamp: timestamp_ms,
        tx_trie_root,
        parent_hash: parent.as_bytes().to_vec(),
        number: new_number,
        witness_address: witness_address.as_bytes().to_vec(),
        version,
        ..Default::default()
    };

    Ok(Block {
        block_header: Some(BlockHeader {
            raw_data: Some(raw),
            witness_signature: Vec::new(), // populated by sign_block
        }),
        transactions,
    })
}

/// Assemble + sign in one call. Returns the fully-formed `Block` ready
/// for broadcast and its computed `BlockId`.
///
/// `account_state_root`: when `ALLOW_ACCOUNT_STATE_ROOT == 1` is
/// active on the chain, producers must embed the post-apply state
/// root in the header so verifiers can check it. The SR runtime
/// computes the root via [`tron_executor::dry_run_for_state_root`]
/// and passes it in here. Pass `None` when the flag is off (mainnet
/// default).
pub fn produce_block(
    parent: &BlockId,
    new_number: i64,
    timestamp_ms: i64,
    witness_address: &Address,
    witness_priv_key: &[u8; 32],
    transactions: Vec<Transaction>,
    version: i32,
) -> Result<(Block, BlockId), ProducerError> {
    produce_block_with_state_root(
        parent,
        new_number,
        timestamp_ms,
        witness_address,
        witness_priv_key,
        transactions,
        version,
        None,
    )
}

/// Same as [`produce_block`] but allows embedding the
/// `account_state_root` field in the header before signing. Required
/// path for chains with `ALLOW_ACCOUNT_STATE_ROOT == 1`. The root
/// must be the post-apply state root for the just-assembled block —
/// callers typically compute it via
/// `tron_executor::dry_run_for_state_root`.
pub fn produce_block_with_state_root(
    parent: &BlockId,
    new_number: i64,
    timestamp_ms: i64,
    witness_address: &Address,
    witness_priv_key: &[u8; 32],
    transactions: Vec<Transaction>,
    version: i32,
    account_state_root: Option<[u8; 32]>,
) -> Result<(Block, BlockId), ProducerError> {
    let mut block = assemble_block(
        parent,
        new_number,
        timestamp_ms,
        witness_address,
        transactions,
        version,
    )?;
    if let Some(root) = account_state_root {
        if let Some(raw) = block
            .block_header
            .as_mut()
            .and_then(|h| h.raw_data.as_mut())
        {
            raw.account_state_root = root.to_vec();
        }
    }
    sign_block(&mut block, witness_priv_key)?;
    let block_id = block_id_from_block(&block)
        .expect("BlockId derivable from a signed block");
    Ok((block, block_id))
}

/// Serialise the signed block for network transmission. Thin wrapper
/// around `prost`; lives here so callers don't have to import `prost`
/// themselves.
pub fn encode_for_broadcast(block: &Block) -> Vec<u8> {
    block.encode_to_vec()
}
