//! Transaction-level hashes.
//!
//! TRON uses **two distinct** hashes per transaction:
//!
//! * **`tx_id`** = `sha256(transaction.raw_data.encode())`
//!   The signed message digest. This is what shows up in block explorers
//!   as the "transaction hash" and what gets signed by senders.
//!   Source: `TransactionCapsule.getRawHash` / `getTransactionId`.
//!
//! * **`tx_merkle_hash`** = `sha256(transaction.encode())` *(the entire
//!   message, including signatures and `ret`)*.
//!   This is what goes into the block's `txTrieRoot` Merkle tree.
//!   Source: `TransactionCapsule.getMerkleHash`.
//!
//! These differ for any signed transaction. Conflating them produces silent
//! consensus divergence on the `txTrieRoot`.

use prost::Message;
use tron_crypto::hash::sha256;
use tron_crypto::merkle::merkle_root;
use tron_proto::Transaction;

/// The transaction's signing id — what gets signed and what wallets show.
pub fn tx_id(transaction: &Transaction) -> Result<[u8; 32], TxIdError> {
    let raw = transaction.raw_data.as_ref().ok_or(TxIdError::MissingRawData)?;
    Ok(sha256(&raw.encode_to_vec()))
}

/// The transaction's *Merkle* leaf hash — covers the entire signed message
/// including the `signature` and `ret` fields.
pub fn tx_merkle_hash(transaction: &Transaction) -> [u8; 32] {
    sha256(&transaction.encode_to_vec())
}

/// Compute a block's `txTrieRoot` from its transactions.
///
/// Returns `None` for an empty list, matching java-tron's
/// `BlockCapsule.calcMerkleRoot` which returns `Sha256Hash.ZERO_HASH` —
/// callers should substitute the all-zero 32-byte value if a sentinel is
/// required.
pub fn calc_tx_trie_root(transactions: &[Transaction]) -> Option<[u8; 32]> {
    if transactions.is_empty() {
        return None;
    }
    let leaves: Vec<[u8; 32]> = transactions.iter().map(tx_merkle_hash).collect();
    merkle_root(&leaves)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TxIdError {
    #[error("transaction raw_data missing")]
    MissingRawData,
}
