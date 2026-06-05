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

/// Compute a block's `txTrieRoot` directly from its raw wire bytes —
/// hashing each transaction's **original** bytes rather than a prost
/// re-encode.
///
/// java-tron's `TransactionCapsule.getMerkleHash` hashes
/// `transaction.toByteArray()`, which for a message *parsed from the wire*
/// reproduces the original encoding — including map-field entry order,
/// which java preserves (parsed maps keep wire order) but prost does not
/// (we decode maps into `BTreeMap`, which re-emits them sorted). For a tx
/// whose `ret` carries a non-sorted `map` (e.g. `cancel_unfreezeV2_amount`)
/// the prost round-trip reorders the entries, changing the leaf hash and so
/// the whole root — a `TxTrieRootMismatch` on exactly those blocks. The
/// dropped order is unrecoverable from the parsed struct, so the only
/// faithful root is one computed over the original bytes.
///
/// `block_bytes` is the full serialized `Block`. We walk the top-level
/// protobuf and hash the bytes of every `transactions` entry (field 1,
/// length-delimited); all other fields (`block_header` = field 2, etc.)
/// are skipped. Returns `None` for a block with no transactions (caller
/// substitutes the zero hash), or on malformed/truncated input.
pub fn tx_trie_root_from_block_bytes(block_bytes: &[u8]) -> Option<[u8; 32]> {
    const TRANSACTIONS_FIELD: u64 = 1;
    let mut leaves: Vec<[u8; 32]> = Vec::new();
    let mut i = 0usize;
    while i < block_bytes.len() {
        let (tag, n) = read_varint(&block_bytes[i..])?;
        i += n;
        let field = tag >> 3;
        match tag & 0x7 {
            0 => {
                // varint
                let (_, n) = read_varint(&block_bytes[i..])?;
                i += n;
            }
            1 => i = i.checked_add(8)?, // 64-bit
            5 => i = i.checked_add(4)?, // 32-bit
            2 => {
                // length-delimited
                let (len, n) = read_varint(&block_bytes[i..])?;
                i += n;
                let len = len as usize;
                let end = i.checked_add(len)?;
                if end > block_bytes.len() {
                    return None; // truncated
                }
                if field == TRANSACTIONS_FIELD {
                    leaves.push(sha256(&block_bytes[i..end]));
                }
                i = end;
            }
            _ => return None, // groups (3/4) — not used by these messages
        }
    }
    if leaves.is_empty() {
        return None;
    }
    merkle_root(&leaves)
}

/// Minimal protobuf varint reader: returns `(value, bytes_consumed)`, or
/// `None` on overflow / truncation. Kept local to avoid pulling prost's
/// decoder (which would re-introduce the very re-encoding we're avoiding).
fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    for (idx, &b) in buf.iter().enumerate() {
        if shift >= 64 {
            return None; // varint too long
        }
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some((result, idx + 1));
        }
        shift += 7;
    }
    None // truncated
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TxIdError {
    #[error("transaction raw_data missing")]
    MissingRawData,
}

#[cfg(test)]
mod tx_trie_raw_tests {
    use super::*;
    use tron_proto::transaction::Raw;
    use tron_proto::{Block, Transaction};

    /// Build a length-delimited protobuf field: `tag || varint(len) || payload`
    /// (`field_num` < 16 → single-byte tag).
    fn ld_field(field_num: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![(field_num << 3) | 2];
        let mut len = payload.len() as u64;
        loop {
            let mut b = (len & 0x7f) as u8;
            len >>= 7;
            if len != 0 {
                b |= 0x80;
            }
            out.push(b);
            if len == 0 {
                break;
            }
        }
        out.extend_from_slice(payload);
        out
    }

    fn sample_raw(n: i64) -> Raw {
        Raw {
            ref_block_num: n,
            ref_block_bytes: vec![0xab, 0xcd],
            expiration: 1_700_000_000_000,
            timestamp: 1_700_000_000_000,
            ..Default::default()
        }
    }

    #[test]
    fn raw_root_matches_reencode_for_canonical_blocks() {
        // A prost-encoded block is canonical, so hashing the original tx
        // spans must equal hashing the re-encoded txs. Pins the protobuf
        // field walker.
        let txs: Vec<Transaction> = (0..3)
            .map(|i| Transaction {
                raw_data: Some(sample_raw(i)),
                signature: vec![vec![i as u8; 65]],
                ..Default::default()
            })
            .collect();
        let block = Block { transactions: txs.clone(), ..Default::default() };
        assert_eq!(
            tx_trie_root_from_block_bytes(&block.encode_to_vec()),
            calc_tx_trie_root(&txs),
            "raw-bytes root must equal re-encode root for canonical input"
        );
    }

    #[test]
    fn raw_root_preserves_wire_order_that_reencode_collapses() {
        // The M-20 bug in miniature: two byte-different-but-logically-equal
        // encodings of the same transaction (top-level fields swapped — the
        // same non-canonicality class as reordered `ret` map entries).
        // prost decodes both to the SAME struct, so a re-encode gives them
        // the SAME merkle root, losing the distinction the block's declared
        // root was computed over. Hashing the original bytes keeps it.
        let raw_bytes = sample_raw(7).encode_to_vec();
        let sig = vec![0xAAu8; 65];

        // raw_data = Transaction field 1, signature = field 2.
        let canonical = [ld_field(1, &raw_bytes), ld_field(2, &sig)].concat();
        let swapped = [ld_field(2, &sig), ld_field(1, &raw_bytes)].concat();

        // Same logical transaction either way.
        let dec_c = Transaction::decode(canonical.as_slice()).unwrap();
        let dec_s = Transaction::decode(swapped.as_slice()).unwrap();
        assert_eq!(dec_c, dec_s);

        // Blocks carrying each encoding (transactions = Block field 1).
        let block_c = ld_field(1, &canonical);
        let block_s = ld_field(1, &swapped);

        // Raw-bytes roots DIFFER — the function preserves the wire bytes
        // (single tx → merkle root == that tx's leaf hash).
        assert_eq!(tx_trie_root_from_block_bytes(&block_c).unwrap(), sha256(&canonical));
        assert_eq!(tx_trie_root_from_block_bytes(&block_s).unwrap(), sha256(&swapped));
        assert_ne!(
            tx_trie_root_from_block_bytes(&block_c),
            tx_trie_root_from_block_bytes(&block_s)
        );

        // Re-encode roots are EQUAL — prost normalises both to canonical, so
        // the old decoded check couldn't tell them apart (the bug).
        assert_eq!(calc_tx_trie_root(&[dec_c]), calc_tx_trie_root(&[dec_s]));
    }

    #[test]
    fn handles_empty_and_truncated_input() {
        // No transactions → None (caller substitutes the zero hash).
        assert_eq!(tx_trie_root_from_block_bytes(&Block::default().encode_to_vec()), None);
        // Truncated length-delimited field → None, not a panic.
        assert_eq!(tx_trie_root_from_block_bytes(&[0x0A, 0xFF]), None);
        // A header-only block (field 2 present, no transactions) → None.
        let header_only = ld_field(2, &[0x01, 0x02, 0x03]);
        assert_eq!(tx_trie_root_from_block_bytes(&header_only), None);
    }
}
