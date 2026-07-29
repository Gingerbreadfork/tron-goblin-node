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
///
/// CAUTION: this hashes a prost re-encode of `raw_data`, which silently
/// DROPS any unknown protobuf field the original wire bytes carried —
/// java's `getRawData().toByteArray()` retains and re-emits them, so for
/// such a tx this id (and any signature recovery keyed on it) diverges
/// from the network. Whenever the original wire bytes are available, use
/// [`tx_id_from_tx_bytes`] / [`tx_wire_infos_from_block_bytes`] instead;
/// this remains exact only for prost-canonical transactions.
pub fn tx_id(transaction: &Transaction) -> Result<[u8; 32], TxIdError> {
    let raw = transaction.raw_data.as_ref().ok_or(TxIdError::MissingRawData)?;
    Ok(sha256(&raw.encode_to_vec()))
}

/// The transaction id from the tx's ORIGINAL wire bytes: `sha256` of the
/// `raw_data` (field 1) span exactly as encoded.
///
/// Matches java's `TransactionCapsule.getRawHash`
/// (`sha256(getRawData().toByteArray())`): java protobuf retains unknown
/// fields, so a tx off the wire hashes its original `raw_data` span. prost
/// drops unknown fields on decode, so a re-encode of the parsed struct
/// hashes a different preimage for the rare mainnet txs that append stray
/// fields to `raw_data`. Hashing the span is identical to the re-encode for
/// canonical txs and byte-exact java for the rest.
///
/// Returns `None` (caller falls back to the re-encode) for bytes that are
/// malformed, carry no `raw_data`, or carry more than one `raw_data` field
/// (protobuf merge semantics).
pub fn tx_id_from_tx_bytes(tx_bytes: &[u8]) -> Option<[u8; 32]> {
    const RAW_DATA_FIELD: u64 = 1;
    let mut span: Option<(usize, usize)> = None;
    let mut i = 0usize;
    while i < tx_bytes.len() {
        let (tag, n) = read_varint(&tx_bytes[i..])?;
        i += n;
        let field = tag >> 3;
        match tag & 0x7 {
            0 => {
                let (_, n) = read_varint(&tx_bytes[i..])?;
                i += n;
            }
            1 => i = i.checked_add(8)?,
            5 => i = i.checked_add(4)?,
            2 => {
                let (len, n) = read_varint(&tx_bytes[i..])?;
                i += n;
                let end = i.checked_add(len as usize)?;
                if end > tx_bytes.len() {
                    return None; // truncated
                }
                if field == RAW_DATA_FIELD {
                    if span.is_some() {
                        return None; // repeated raw_data → merge semantics
                    }
                    span = Some((i, end));
                }
                i = end;
            }
            _ => return None, // groups (3/4) — not used by these messages
        }
    }
    span.map(|(s, e)| sha256(&tx_bytes[s..e]))
}

/// Per-transaction ORIGINAL wire facts captured from a serialized block:
/// the tx entry's wire size (java `getSerializedSize`) and its wire tx id
/// ([`tx_id_from_tx_bytes`]). `tx_id` is `None` when the id could not be
/// derived from the span (consumers fall back to the prost re-encode,
/// which is exact for canonical txs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxWireInfo {
    pub size: i64,
    pub tx_id: Option<[u8; 32]>,
}

/// Borrowed per-transaction wire spans of a serialized `Block` — the exact
/// bytes of every `transactions` entry (field 1, length-delimited), in block
/// order. These are each tx's ORIGINAL encoding, so re-broadcasting or
/// re-hashing them is byte-exact where a prost re-encode of the decoded tx
/// would normalize (dropping unknown fields, re-sorting maps). Same protobuf
/// walk as [`tx_trie_root_from_block_bytes`]; `None` on malformed/truncated
/// input.
pub fn tx_spans_from_block_bytes(block_bytes: &[u8]) -> Option<Vec<&[u8]>> {
    const TRANSACTIONS_FIELD: u64 = 1;
    let mut spans: Vec<&[u8]> = Vec::new();
    let mut i = 0usize;
    while i < block_bytes.len() {
        let (tag, n) = read_varint(&block_bytes[i..])?;
        i += n;
        let field = tag >> 3;
        match tag & 0x7 {
            0 => {
                let (_, n) = read_varint(&block_bytes[i..])?;
                i += n;
            }
            1 => i = i.checked_add(8)?,
            5 => i = i.checked_add(4)?,
            2 => {
                let (len, n) = read_varint(&block_bytes[i..])?;
                i += n;
                let len = len as usize;
                let end = i.checked_add(len)?;
                if end > block_bytes.len() {
                    return None; // truncated
                }
                if field == TRANSACTIONS_FIELD {
                    spans.push(&block_bytes[i..end]);
                }
                i = end;
            }
            _ => return None, // groups (3/4) — not used by these messages
        }
    }
    Some(spans)
}

/// Walk a serialized `Block` and capture each `transactions` entry's
/// [`TxWireInfo`], in block order. Returns `None` on malformed/truncated
/// input (callers fall back to prost-derived values).
pub fn tx_wire_infos_from_block_bytes(block_bytes: &[u8]) -> Option<Vec<TxWireInfo>> {
    Some(
        tx_spans_from_block_bytes(block_bytes)?
            .into_iter()
            .map(|span| TxWireInfo {
                size: span.len() as i64,
                tx_id: tx_id_from_tx_bytes(span),
            })
            .collect(),
    )
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

/// Per-transaction ORIGINAL serialized sizes, in block order — the wire length
/// of every `transactions` entry (field 1, length-delimited) in `block_bytes`.
///
/// This is java-tron's `Transaction.getSerializedSize()` for each tx: the
/// original wire size, including any non-canonical / unknown Transaction-level
/// bytes that a prost round-trip (`Message::encoded_len`) silently drops. The
/// bandwidth charge needs it so `net_usage` matches java byte-for-byte even on
/// the ~0.1% of mainnet txs whose wire form is not prost-canonical (java's
/// parsed `TransactionCapsule` caches the original size; prost recomputes a
/// canonical one). Returns `None` on malformed/truncated input — the caller
/// falls back to the prost size. The protobuf walk mirrors
/// [`tx_trie_root_from_block_bytes`] exactly; the only difference is recording
/// each tx span's length instead of its hash.
pub fn tx_sizes_from_block_bytes(block_bytes: &[u8]) -> Option<Vec<i64>> {
    const TRANSACTIONS_FIELD: u64 = 1;
    let mut sizes: Vec<i64> = Vec::new();
    let mut i = 0usize;
    while i < block_bytes.len() {
        let (tag, n) = read_varint(&block_bytes[i..])?;
        i += n;
        let field = tag >> 3;
        match tag & 0x7 {
            0 => {
                let (_, n) = read_varint(&block_bytes[i..])?;
                i += n;
            }
            1 => i = i.checked_add(8)?,
            5 => i = i.checked_add(4)?,
            2 => {
                let (len, n) = read_varint(&block_bytes[i..])?;
                i += n;
                let len = len as usize;
                let end = i.checked_add(len)?;
                if end > block_bytes.len() {
                    return None; // truncated
                }
                if field == TRANSACTIONS_FIELD {
                    sizes.push(len as i64);
                }
                i = end;
            }
            _ => return None, // groups (3/4) — not used by these messages
        }
    }
    Some(sizes)
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
    fn tx_sizes_match_prost_for_canonical_blocks() {
        let txs: Vec<Transaction> = (0..3)
            .map(|i| Transaction {
                raw_data: Some(sample_raw(i)),
                signature: vec![vec![i as u8; 65]],
                ..Default::default()
            })
            .collect();
        let block = Block { transactions: txs.clone(), ..Default::default() };
        let sizes = tx_sizes_from_block_bytes(&block.encode_to_vec()).unwrap();
        assert_eq!(sizes.len(), 3);
        for (s, tx) in sizes.iter().zip(&txs) {
            assert_eq!(*s, tx.encoded_len() as i64);
        }
    }

    #[test]
    fn tx_sizes_use_original_wire_size_including_dropped_bytes() {
        // The #9 bug in miniature: a transaction carrying an UNKNOWN field
        // (field 15) that prost drops on decode. java's getSerializedSize
        // counts those bytes; prost's encoded_len does not.
        let raw_bytes = sample_raw(9).encode_to_vec();
        let sig = vec![0xCDu8; 65];
        let unknown = ld_field(15, &[0xDE, 0xAD, 0xBE, 0xEF]);
        // raw_data = field 1, signature = field 2, then the unknown field.
        let tx_wire = [ld_field(1, &raw_bytes), ld_field(2, &sig), unknown.clone()].concat();
        let block = ld_field(1, &tx_wire); // transactions = Block field 1

        let sizes = tx_sizes_from_block_bytes(&block).unwrap();
        assert_eq!(sizes.len(), 1);
        // Original wire size = the full tx span, including the unknown field.
        assert_eq!(sizes[0], tx_wire.len() as i64);

        // prost drops the unknown field, so its re-encode is shorter — and the
        // gap is exactly the dropped bytes the bandwidth charge must add back.
        let decoded = Transaction::decode(tx_wire.as_slice()).unwrap();
        assert!((decoded.encoded_len() as i64) < sizes[0]);
        assert_eq!(sizes[0] - decoded.encoded_len() as i64, unknown.len() as i64);
    }

    #[test]
    fn tx_id_from_wire_hashes_full_raw_data_including_trailing_unknown_field() {
        // raw_data with a trailing unknown varint field (field 20, `a0 01 03`)
        // that prost drops on decode. The wire id hashes the full span (java
        // getRawHash); the re-encode hashes the shorter, stripped preimage,
        // giving a different id.
        let canonical_raw = sample_raw(3).encode_to_vec();
        let mut raw_with_unknown = canonical_raw.clone();
        raw_with_unknown.extend_from_slice(&[0xa0, 0x01, 0x03]); // field 20, varint, value 3

        let sig = vec![0xEEu8; 65];
        let tx_wire = [ld_field(1, &raw_with_unknown), ld_field(2, &sig)].concat();

        // Wire id = sha256 of the FULL original raw_data span.
        let wire_id = tx_id_from_tx_bytes(&tx_wire).expect("well-formed tx bytes");
        assert_eq!(wire_id, sha256(&raw_with_unknown));

        // The prost round-trip drops the unknown bytes → different id.
        let decoded = Transaction::decode(tx_wire.as_slice()).unwrap();
        let reencode_id = tx_id(&decoded).unwrap();
        assert_eq!(reencode_id, sha256(&canonical_raw));
        assert_ne!(wire_id, reencode_id);

        // Block-level walker returns the same wire id per entry.
        let block = ld_field(1, &tx_wire);
        let infos = tx_wire_infos_from_block_bytes(&block).unwrap();
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].size, tx_wire.len() as i64);
        assert_eq!(infos[0].tx_id, Some(wire_id));
    }

    #[test]
    fn tx_id_from_wire_is_a_noop_for_canonical_txs() {
        // A tx WITHOUT unknown fields: the wire id must be byte-identical to
        // the prost re-encode id (equal for all canonical txs).
        let tx = Transaction {
            raw_data: Some(sample_raw(11)),
            signature: vec![vec![0x42u8; 65]],
            ..Default::default()
        };
        let wire = tx.encode_to_vec();
        assert_eq!(tx_id_from_tx_bytes(&wire), Some(tx_id(&tx).unwrap()));

        let block = Block { transactions: vec![tx.clone()], ..Default::default() };
        let infos = tx_wire_infos_from_block_bytes(&block.encode_to_vec()).unwrap();
        assert_eq!(infos[0].tx_id, Some(tx_id(&tx).unwrap()));
        assert_eq!(infos[0].size, tx.encoded_len() as i64);
    }

    #[test]
    fn tx_id_from_wire_rejects_missing_or_repeated_raw_data() {
        // No raw_data → None (fallback path).
        let sig_only = ld_field(2, &[0xAA; 65]);
        assert_eq!(tx_id_from_tx_bytes(&sig_only), None);
        // Repeated raw_data (protobuf merge semantics) → None.
        let raw = sample_raw(1).encode_to_vec();
        let doubled = [ld_field(1, &raw), ld_field(1, &raw)].concat();
        assert_eq!(tx_id_from_tx_bytes(&doubled), None);
        // Truncated → None.
        assert_eq!(tx_id_from_tx_bytes(&[0x0A, 0xFF]), None);
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
