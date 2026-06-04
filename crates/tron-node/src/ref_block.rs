//! Replay-protection: validate a transaction's `ref_block_bytes` /
//! `ref_block_hash` against the chain's recent-block history.
//!
//! A TRON transaction binds itself to a specific historical block on
//! the chain it was crafted against, via two fields on `Transaction.raw_data`:
//!
//!   * `ref_block_bytes` (2 bytes) — low 16 bits of the referenced
//!     block number, big-endian. Used as the lookup key.
//!   * `ref_block_hash` (8 bytes) — `BlockId.bytes[8..16]` of that
//!     block. Used for verification.
//!
//! The producer-side encoding lives at `tron_rpc::builder::build_unsigned_tx`
//! (lines 62-67). Without this gate at the sync / mempool entry points,
//! a signed transaction can be replayed on any forked chain that
//! happens to share the referenced block — or after the 65k-block
//! window has rolled over.
//!
//! ## Why this layer, not the executor?
//!
//! java-tron performs this check in `Manager.pushBlock →
//! TransactionUtil.validateRefBlock` (sync layer) and at mempool
//! admission, NOT inside the per-tx execution loop. The executor is
//! the pure-execution engine — it trusts the caller has already gated
//! on these policies. Mirroring that split keeps the executor's tests
//! storage-free and pins the validation in the layer where peer-pushed
//! blocks actually enter.
//!
//! ## Implementation choice: `BlockIndexStore` over `RecentBlockStore`
//!
//! java-tron's canonical store is `RecentBlockStore` — a 2-byte-keyed
//! wrapping window of 65,536 entries. We have the store defined in
//! `tron-chainbase` but nothing populates it (tracked in REVIEW.md).
//! Until that wires up, we query `BlockIndexStore` (already populated
//! on every applied block) and apply the 65k window check ourselves.
//! The byte-output for an in-window valid tx is identical either way;
//! the only behavioral difference is that we ALSO accept ref_blocks
//! older than 65k if they happen to be in the unbounded `BlockIndexStore`
//! — defensively, the window check rejects those anyway.

use std::sync::Arc;

use tron_chainbase::{BlockIndexStore, KvBackend};
use tron_proto::transaction::Raw as TxRaw;

/// java-tron's recent-block window. Txs whose `ref_block_bytes`
/// resolves to a block older than `head - REF_BLOCK_WINDOW` are
/// rejected. 2^16 to match the 2-byte key space.
pub const REF_BLOCK_WINDOW: i64 = 65_536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefBlockError {
    /// `raw_data.ref_block_bytes` was not exactly 2 bytes (the
    /// canonical low-16-bits big-endian encoding of the referenced
    /// block number — see `tron-rpc/src/builder.rs:64-66`).
    InvalidRefBlockBytesLength(usize),
    /// `raw_data.ref_block_hash` was not exactly 8 bytes (the
    /// canonical `BlockId.bytes[8..16]` slice — see
    /// `tron-rpc/src/builder.rs:67`).
    InvalidRefBlockHashLength(usize),
    /// No block in the recent-block window matches the low-16-bits
    /// the tx referenced. Either the tx is too old (referenced block
    /// fell out of the 65k window) or the chain never had that block.
    UnknownReferencedBlock { ref_low16: u16, head_num: i64 },
    /// The referenced block exists at the resolved `block_num`, but
    /// its `BlockId.bytes[8..16]` slice doesn't match the tx's
    /// `ref_block_hash`. The tx was built against a different fork.
    HashMismatch {
        block_num: i64,
        expected: [u8; 8],
        actual: Vec<u8>,
    },
}

impl std::fmt::Display for RefBlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRefBlockBytesLength(n) => {
                write!(f, "ref_block_bytes must be 2 bytes, got {n}")
            }
            Self::InvalidRefBlockHashLength(n) => {
                write!(f, "ref_block_hash must be 8 bytes, got {n}")
            }
            Self::UnknownReferencedBlock { ref_low16, head_num } => write!(
                f,
                "tx references block whose low-16-bits {ref_low16:#06x} resolves \
                 outside the 65,536-block window at head {head_num}"
            ),
            Self::HashMismatch { block_num, expected, actual } => write!(
                f,
                "ref_block_hash mismatch at block {block_num}: expected {expected:02x?}, \
                 got {actual:02x?}"
            ),
        }
    }
}

impl std::error::Error for RefBlockError {}

/// Resolve the canonical full block-num the tx is referencing. java-tron
/// stores only the low 16 bits in `ref_block_bytes`; the validator
/// recovers the high bits by taking the most recent matching block-num
/// at or before `head_num`.
///
/// Returns the candidate even if it falls outside the valid window —
/// the window check is performed separately. Returns a value `<= head_num`
/// or potentially negative for the degenerate `head_num < 0` case.
pub fn resolve_ref_block_candidate(head_num: i64, ref_low16: u16) -> i64 {
    let high_bits = head_num & !0xFFFF;
    let mut candidate = high_bits | (ref_low16 as i64);
    if candidate > head_num {
        candidate -= REF_BLOCK_WINDOW;
    }
    candidate
}

/// Validate `raw.ref_block_bytes` + `raw.ref_block_hash` against chain
/// history queried through `block_index`.
///
/// * `head_num` is the highest block number considered "in the index"
///   — typically the parent of the block being applied. The window is
///   `[head_num - REF_BLOCK_WINDOW + 1, head_num]`.
/// * `block_index` is the populated chain index (`BlockIndexStore`'s
///   backend). Production wires this on every `accept_block`; tests
///   that build synthetic blocks may pass an empty backend, in which
///   case the lookup returns `UnknownReferencedBlock`.
pub fn validate_ref_block(
    raw: &TxRaw,
    head_num: i64,
    block_index: &Arc<dyn KvBackend>,
) -> Result<(), RefBlockError> {
    if raw.ref_block_bytes.len() != 2 {
        return Err(RefBlockError::InvalidRefBlockBytesLength(
            raw.ref_block_bytes.len(),
        ));
    }
    if raw.ref_block_hash.len() != 8 {
        return Err(RefBlockError::InvalidRefBlockHashLength(
            raw.ref_block_hash.len(),
        ));
    }
    let ref_low16 = u16::from_be_bytes([raw.ref_block_bytes[0], raw.ref_block_bytes[1]]);

    if head_num < 0 {
        return Err(RefBlockError::UnknownReferencedBlock {
            ref_low16,
            head_num,
        });
    }
    let candidate = resolve_ref_block_candidate(head_num, ref_low16);
    if candidate < 0 || head_num - candidate >= REF_BLOCK_WINDOW {
        return Err(RefBlockError::UnknownReferencedBlock {
            ref_low16,
            head_num,
        });
    }

    let bi_store = BlockIndexStore::new(block_index.clone());
    let block_id = bi_store.get(candidate).map_err(|_| {
        RefBlockError::UnknownReferencedBlock {
            ref_low16,
            head_num,
        }
    })?;

    // `BlockId.bytes[8..16]` — same slice the producer writes (see
    // `tron-rpc/src/builder.rs:67`). Any other byte-range diverges
    // from java-tron and from every tx built against this chain.
    let mut expected = [0u8; 8];
    expected.copy_from_slice(&block_id.as_bytes()[8..16]);
    if expected != raw.ref_block_hash.as_slice() {
        return Err(RefBlockError::HashMismatch {
            block_num: candidate,
            expected,
            actual: raw.ref_block_hash.clone(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tron_chainbase::MemBackend;
    use tron_types::BlockId;

    fn mem() -> Arc<dyn KvBackend> {
        Arc::new(MemBackend::new())
    }

    /// `BlockId` is `block_num` (BE, replacing first 8 bytes of the
    /// hash) || bytes 8..32 of `sha256(raw_data.encode())`. For these
    /// tests we just construct synthetic ids — the validator only
    /// looks at bytes [8..16], so the specific raw_data hash doesn't
    /// matter as long as those 8 bytes are deterministic.
    fn synthetic_block_id(num: i64, hash_tail_seed: u8) -> BlockId {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&num.to_be_bytes());
        // Fill 8..32 with a recognizable pattern keyed by `num` so each
        // synthetic block gets a unique [8..16] slice.
        for (i, b) in bytes.iter_mut().enumerate().skip(8) {
            *b = hash_tail_seed.wrapping_add(i as u8).wrapping_add((num & 0xFF) as u8);
        }
        BlockId::from_raw(bytes)
    }

    fn raw_with(ref_bytes: Vec<u8>, ref_hash: Vec<u8>) -> TxRaw {
        TxRaw {
            ref_block_bytes: ref_bytes,
            ref_block_hash: ref_hash,
            ..Default::default()
        }
    }

    #[test]
    fn resolve_candidate_for_head_below_65k_just_picks_low_bits() {
        // head_num = 100, ref_low16 = 50 → candidate = 50 (well within
        // the window, no high-bit wrap needed).
        assert_eq!(resolve_ref_block_candidate(100, 50), 50);
        // ref_low16 == head_num → candidate == head_num.
        assert_eq!(resolve_ref_block_candidate(100, 100), 100);
    }

    #[test]
    fn resolve_candidate_when_low_bits_exceed_head_wraps_back() {
        // head_num = 10, ref_low16 = 0xFFFF: high_bits of head are 0,
        // so the naive candidate would be 0x0000FFFF = 65535, which is
        // > head. Wrap back by REF_BLOCK_WINDOW → -1. Caller's window
        // check rejects this (candidate < 0).
        assert_eq!(resolve_ref_block_candidate(10, 0xFFFF), -1);
    }

    #[test]
    fn resolve_candidate_picks_most_recent_match_at_or_before_head() {
        // head_num = 0x12000 (73728). The most recent block_num whose
        // low 16 bits == 0x0010 and is <= head is 0x10010 (65552) —
        // candidates are 16, 65552, 131088, …; 131088 > head, so 65552.
        // High bits of head (0x10000) ORed with ref_low16 lands there
        // directly, no wrap needed.
        assert_eq!(resolve_ref_block_candidate(0x12000, 0x0010), 0x10010);
        // Same head, but ref_low16 = 0x3000: the naive candidate is
        // 0x13000 (> head), so we wrap to 0x03000 (12288).
        assert_eq!(resolve_ref_block_candidate(0x12000, 0x3000), 0x03000);
        // ref_low16 == low 16 of head → candidate == head exactly.
        assert_eq!(resolve_ref_block_candidate(0x12000, 0x2000), 0x12000);
    }

    #[test]
    fn rejects_wrong_length_ref_block_bytes() {
        let bi = mem();
        let raw = raw_with(vec![0u8; 3], vec![0u8; 8]); // 3 bytes, not 2
        let err = validate_ref_block(&raw, 0, &bi).unwrap_err();
        assert!(matches!(err, RefBlockError::InvalidRefBlockBytesLength(3)));
    }

    #[test]
    fn rejects_wrong_length_ref_block_hash() {
        let bi = mem();
        let raw = raw_with(vec![0, 0], vec![0u8; 7]); // 7 bytes, not 8
        let err = validate_ref_block(&raw, 0, &bi).unwrap_err();
        assert!(matches!(err, RefBlockError::InvalidRefBlockHashLength(7)));
    }

    #[test]
    fn rejects_when_referenced_block_isnt_in_index() {
        let bi = mem(); // empty
        let raw = raw_with(vec![0x00, 0x05], vec![0u8; 8]);
        let err = validate_ref_block(&raw, 100, &bi).unwrap_err();
        assert!(matches!(
            err,
            RefBlockError::UnknownReferencedBlock { ref_low16: 5, head_num: 100 }
        ));
    }

    #[test]
    fn rejects_when_head_below_zero() {
        let bi = mem();
        let raw = raw_with(vec![0, 0], vec![0u8; 8]);
        let err = validate_ref_block(&raw, -1, &bi).unwrap_err();
        assert!(matches!(err, RefBlockError::UnknownReferencedBlock { .. }));
    }

    #[test]
    fn rejects_when_candidate_falls_outside_65k_window() {
        // Pre-populate block 5 with a known hash, but ask about
        // ref_low16 = 0xFFFF when head_num = 10. That resolves to
        // -65525, which is outside the window AND not in the index.
        let bi = mem();
        let bi_store = BlockIndexStore::new(bi.clone());
        bi_store.put(&synthetic_block_id(5, 0xaa)).unwrap();

        let raw = raw_with(vec![0xFF, 0xFF], vec![0u8; 8]);
        let err = validate_ref_block(&raw, 10, &bi).unwrap_err();
        assert!(matches!(err, RefBlockError::UnknownReferencedBlock { .. }));
    }

    #[test]
    fn rejects_on_hash_mismatch() {
        let bi = mem();
        let bi_store = BlockIndexStore::new(bi.clone());
        let real_block = synthetic_block_id(10, 0xaa);
        bi_store.put(&real_block).unwrap();

        // Same low-16 (10) but a wrong hash.
        let raw = raw_with(vec![0x00, 0x0a], vec![0xff; 8]);
        let err = validate_ref_block(&raw, 100, &bi).unwrap_err();
        match err {
            RefBlockError::HashMismatch { block_num, expected, actual } => {
                assert_eq!(block_num, 10);
                assert_eq!(expected[..], real_block.as_bytes()[8..16]);
                assert_eq!(actual, vec![0xff; 8]);
            }
            other => panic!("expected HashMismatch, got {other:?}"),
        }
    }

    #[test]
    fn passes_when_ref_block_hash_matches_indexed_block() {
        let bi = mem();
        let bi_store = BlockIndexStore::new(bi.clone());
        let real_block = synthetic_block_id(42, 0xcc);
        bi_store.put(&real_block).unwrap();

        let expected_hash = real_block.as_bytes()[8..16].to_vec();
        let raw = raw_with(vec![0x00, 0x2a], expected_hash);
        assert_eq!(validate_ref_block(&raw, 100, &bi), Ok(()));
    }

    #[test]
    fn passes_for_block_at_exact_window_edge() {
        // head_num = 65_535, ref_low16 = 0 → candidate = 0 (genesis).
        // The window is `[head - 65_535, head]` = `[0, 65_535]`, so 0
        // is the oldest acceptable.
        let bi = mem();
        let bi_store = BlockIndexStore::new(bi.clone());
        let genesis = synthetic_block_id(0, 0x00);
        bi_store.put(&genesis).unwrap();

        let expected = genesis.as_bytes()[8..16].to_vec();
        let raw = raw_with(vec![0x00, 0x00], expected);
        assert_eq!(validate_ref_block(&raw, 65_535, &bi), Ok(()));
    }

    #[test]
    fn rejects_one_block_past_window_edge() {
        // Same setup but head_num = 65_536: block 0 is now exactly
        // 65_536 blocks back, which is `>= REF_BLOCK_WINDOW` → reject.
        let bi = mem();
        let bi_store = BlockIndexStore::new(bi.clone());
        bi_store.put(&synthetic_block_id(0, 0x00)).unwrap();

        let raw = raw_with(vec![0x00, 0x00], vec![0u8; 8]);
        let err = validate_ref_block(&raw, 65_536, &bi).unwrap_err();
        assert!(matches!(err, RefBlockError::UnknownReferencedBlock { .. }));
    }
}
