//! Structural validation for a [`Block`].
//!
//! These are the checks a node performs *before* state transition: they
//! confirm a block is well-formed, signed by the witness it claims to be
//! from, and links to the chain we already have. They do **not** validate
//! transaction execution (that's the actuator layer) or DPoS slot
//! ownership (that's consensus).
//!
//! Three primitives:
//!
//! 1. [`verify_witness_signature`] — recover the signer from
//!    `block_header.witness_signature` against
//!    `sha256(block_header.raw_data.encode())` and compare to the
//!    `witness_address` field. Source: `BlockCapsule.validateSignature`.
//!
//! 2. [`verify_tx_trie_root`] — recompute the binary-Merkle root of the
//!    transactions and check against `header.tx_trie_root`. Empty txs
//!    must coincide with an empty `tx_trie_root` field. Source:
//!    `BlockCapsule.validateMerkleRoot` + `calcMerkleRoot`.
//!
//! 3. [`verify_parent_link`] — `header.parent_hash` must equal the bytes
//!    of the expected parent's [`BlockId`]. Source: `BlockUtil.isParentOf`.
//!
//! [`sign_block`] is the witness-side counterpart: given a block and a
//! witness private key, attach a valid `witness_signature`. Useful for
//! tests; production code does this inside the block-production path.

use prost::Message;
use tron_crypto::address::Address;
use tron_crypto::hash::sha256;
use tron_crypto::signature::{RecoverableSignature, SigError};
use tron_proto::Block;

use crate::block_id::BlockId;
use crate::tx_id::{calc_tx_trie_root, tx_trie_root_from_block_bytes};

/// `sha256(block.block_header.raw_data.encode())` — the digest the witness
/// signs. Distinct from the [`BlockId`], which overwrites the first 8
/// bytes of this hash with the block number.
pub fn block_raw_hash(block: &Block) -> Result<[u8; 32], BlockValidateError> {
    let raw = block
        .block_header
        .as_ref()
        .and_then(|h| h.raw_data.as_ref())
        .ok_or(BlockValidateError::MissingHeader)?;
    Ok(sha256(&raw.encode_to_vec()))
}

/// Sign `block` in place using the witness's private key. Sets
/// `block_header.witness_signature` to the 65-byte `[r‖s‖v]` form.
/// Matches the witness side of `BlockCapsule.validateSignature`.
pub fn sign_block(
    block: &mut Block,
    witness_priv_key: &[u8; 32],
) -> Result<RecoverableSignature, BlockValidateError> {
    let hash = block_raw_hash(block)?;
    let sig = RecoverableSignature::sign_prehash(witness_priv_key, &hash)
        .map_err(BlockValidateError::Sig)?;
    let header = block
        .block_header
        .as_mut()
        .expect("checked in block_raw_hash");
    header.witness_signature = sig.to_bytes().to_vec();
    Ok(sig)
}

/// Recover the signer's address from `witness_signature` and confirm it
/// matches `witness_address`.
///
/// java-tron also supports a permission-delegated signing mode where the
/// signer is a separate "witness permission" key rather than the witness
/// account itself. That mode is gated by `allowMultiSign == 1` in
/// `DynamicPropertiesStore`. We accept an optional override
/// (`expected_signer`) for that case; pass `None` to default to the
/// block's own `witness_address`.
pub fn verify_witness_signature(
    block: &Block,
    expected_signer: Option<&Address>,
) -> Result<Address, BlockValidateError> {
    let hash = block_raw_hash(block)?;
    let header = block
        .block_header
        .as_ref()
        .ok_or(BlockValidateError::MissingHeader)?;
    let raw = header
        .raw_data
        .as_ref()
        .ok_or(BlockValidateError::MissingHeader)?;

    let sig_bytes = &header.witness_signature;
    if sig_bytes.is_empty() {
        return Err(BlockValidateError::MissingSignature);
    }
    let sig =
        RecoverableSignature::from_bytes(sig_bytes).map_err(BlockValidateError::Sig)?;
    let pubkey = sig
        .recover_uncompressed_pubkey(&hash)
        .map_err(BlockValidateError::Sig)?;
    let recovered =
        Address::from_uncompressed_pubkey(&pubkey).map_err(|e| BlockValidateError::Address(e.to_string()))?;

    let expected = match expected_signer {
        Some(addr) => *addr,
        None => {
            if raw.witness_address.len() != 21 {
                return Err(BlockValidateError::WitnessAddressLength(raw.witness_address.len()));
            }
            let mut buf = [0u8; 21];
            buf.copy_from_slice(&raw.witness_address);
            Address::from_raw(buf)
        }
    };

    if recovered != expected {
        return Err(BlockValidateError::WitnessMismatch {
            recovered,
            expected,
        });
    }
    Ok(recovered)
}

/// Re-derive the transactions' Merkle root and compare against
/// `header.tx_trie_root`.
///
/// java-tron's convention for the empty-transactions case: the witness
/// sets `tx_trie_root` to either an empty `bytes` field (proto default)
/// or 32 zero bytes (`Sha256Hash.ZERO_HASH`). We accept both.
pub fn verify_tx_trie_root(block: &Block) -> Result<(), BlockValidateError> {
    let header = block
        .block_header
        .as_ref()
        .ok_or(BlockValidateError::MissingHeader)?;
    let raw = header
        .raw_data
        .as_ref()
        .ok_or(BlockValidateError::MissingHeader)?;

    compare_tx_trie_root(calc_tx_trie_root(&block.transactions), &raw.tx_trie_root)
}

/// Like [`verify_tx_trie_root`] but computes the root from the block's
/// **original wire bytes** ([`tx_trie_root_from_block_bytes`]) instead of a
/// prost re-encode, so it matches java-tron for transactions whose encoding
/// isn't canonical under a decode→re-encode (notably map-field ordering in
/// `ret`). Use this on blocks received from the network — the only place
/// the raw bytes still exist (block storage re-encodes, dropping the order).
///
/// `block_bytes` must be the exact serialized `Block` the header's
/// `txTrieRoot` was computed over.
pub fn verify_tx_trie_root_raw(
    block: &Block,
    block_bytes: &[u8],
) -> Result<(), BlockValidateError> {
    let header = block
        .block_header
        .as_ref()
        .ok_or(BlockValidateError::MissingHeader)?;
    let raw = header
        .raw_data
        .as_ref()
        .ok_or(BlockValidateError::MissingHeader)?;

    compare_tx_trie_root(tx_trie_root_from_block_bytes(block_bytes), &raw.tx_trie_root)
}

/// Shared comparison for [`verify_tx_trie_root`] / [`verify_tx_trie_root_raw`]:
/// reconcile a computed root (`None` = no transactions) against the header's
/// declared `tx_trie_root`. java-tron writes the empty-block root as either
/// an empty `bytes` field or 32 zero bytes; both are accepted.
fn compare_tx_trie_root(
    computed: Option<[u8; 32]>,
    header_root: &[u8],
) -> Result<(), BlockValidateError> {
    match (computed, header_root) {
        // Empty txs + empty header root: ok.
        (None, h) if h.is_empty() || h == [0u8; 32].as_slice() => Ok(()),
        // Empty txs but header says non-empty: bad.
        (None, _) => Err(BlockValidateError::TxTrieRootMismatch {
            header_has: header_root.to_vec(),
            computed: None,
        }),
        // Non-empty txs but header is empty: bad.
        (Some(c), h) if h.is_empty() => Err(BlockValidateError::TxTrieRootMismatch {
            header_has: h.to_vec(),
            computed: Some(c),
        }),
        // Both present: must be equal.
        (Some(c), h) => {
            if h == c {
                Ok(())
            } else {
                Err(BlockValidateError::TxTrieRootMismatch {
                    header_has: h.to_vec(),
                    computed: Some(c),
                })
            }
        }
    }
}

/// `header.parent_hash` must equal the 32 bytes of `expected_parent`.
///
/// Note: java-tron stores the **full BlockId** (with num-prefix
/// overwrite) in `parent_hash`, not the plain block raw hash. So an
/// `expected_parent: BlockId` is the right type.
pub fn verify_parent_link(
    block: &Block,
    expected_parent: BlockId,
) -> Result<(), BlockValidateError> {
    let header = block
        .block_header
        .as_ref()
        .ok_or(BlockValidateError::MissingHeader)?;
    let raw = header
        .raw_data
        .as_ref()
        .ok_or(BlockValidateError::MissingHeader)?;
    if raw.parent_hash != expected_parent.as_bytes() {
        return Err(BlockValidateError::ParentLinkMismatch {
            header_has: raw.parent_hash.clone(),
            expected: *expected_parent.as_bytes(),
        });
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum BlockValidateError {
    #[error("block header or raw data missing")]
    MissingHeader,
    #[error("block has no witness signature attached")]
    MissingSignature,
    #[error("witness_address field is {0} bytes, expected 21")]
    WitnessAddressLength(usize),
    #[error("signature recovered to {recovered:?} but expected {expected:?}")]
    WitnessMismatch { recovered: Address, expected: Address },
    #[error("tx_trie_root mismatch: header has {header_has:02x?}, computed {computed:02x?}")]
    TxTrieRootMismatch {
        header_has: Vec<u8>,
        computed: Option<[u8; 32]>,
    },
    #[error("parent_hash mismatch: header has {header_has:02x?}, expected {expected:02x?}")]
    ParentLinkMismatch {
        header_has: Vec<u8>,
        expected: [u8; 32],
    },
    #[error("signature error: {0}")]
    Sig(#[from] SigError),
    #[error("address: {0}")]
    Address(String),
}
