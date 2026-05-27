//! `BlockUndoStore` — per-block undo logs powering KhaosDb Phase B
//! reorg-with-state-rollback.
//!
//! When the executor applies a block, every per-store `SessionBackend`
//! commit captures `(key, before_image)` pairs via
//! [`SessionBackend::commit_with_undo`]. The executor aggregates those
//! pairs across all stores and all txs in the block into one
//! [`BlockUndoRecord`] and writes it here, keyed by the block number.
//!
//! On reorg, [`tron_executor::rollback_block`] reads the record and
//! replays it: every `before == Some(v)` puts the old value back; every
//! `before == None` deletes the key (because the block was what first
//! created it). The corresponding entries on the stores' base backends
//! are restored to their pre-block values exactly.
//!
//! ## Why a single blob per block, not per (block, store)?
//!
//! Reorg cost is bounded: the whole record loads in one read, replays
//! in one pass. Writing it back at the end of execute_block is also
//! one `put`. Storage cost is modest (a typical mainnet block touches
//! ~hundreds of keys; the encoded blob is a few KB). Pruning is
//! trivial: a single `delete(block_num)` clears the record once the
//! block is solidified beyond the reorg horizon.
//!
//! ## Wire format
//!
//! ```text
//! u32 BE  entry_count
//! for each entry:
//!   u8       store_id (matches StoreId enum)
//!   u32 BE   key_len
//!   bytes    key
//!   u8       has_before (0 = tombstone / 1 = value follows)
//!   if has_before == 1:
//!     u32 BE   value_len
//!     bytes    value
//! ```
//!
//! Hand-rolled to keep zero deps; encoder + decoder are exercised by
//! the round-trip tests below.

use std::sync::Arc;

use crate::backend::KvBackend;

/// Stable per-store identifier used inside [`BlockUndoRecord`]. The
/// numeric values are part of the on-disk wire format — **never
/// renumber an existing variant**. Add new stores at the end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum StoreId {
    Accounts = 0,
    Witnesses = 1,
    Votes = 2,
    Delegation = 3,
    DelegatedResources = 4,
    DynProps = 5,
    Proposals = 6,
    NameIndex = 7,
    IdIndex = 8,
    AssetV1 = 9,
    AssetV2 = 10,
    Contracts = 11,
    Abi = 12,
    ExchangeV1 = 13,
    ExchangeV2 = 14,
    MarketOrders = 15,
    Nullifiers = 16,
    MerkleTrees = 17,
    Code = 18,
    StorageRow = 19,
    ContractState = 20,
    BlockIndex = 21,
    WitnessSchedule = 22,
}

impl StoreId {
    /// Try to convert a raw byte back to a variant. `None` on unknown
    /// — the on-disk record was produced by a future tron-goblin-node that
    /// added more stores. Caller policy: refuse rollback (return an
    /// error) rather than silently misinterpret.
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0 => Self::Accounts,
            1 => Self::Witnesses,
            2 => Self::Votes,
            3 => Self::Delegation,
            4 => Self::DelegatedResources,
            5 => Self::DynProps,
            6 => Self::Proposals,
            7 => Self::NameIndex,
            8 => Self::IdIndex,
            9 => Self::AssetV1,
            10 => Self::AssetV2,
            11 => Self::Contracts,
            12 => Self::Abi,
            13 => Self::ExchangeV1,
            14 => Self::ExchangeV2,
            15 => Self::MarketOrders,
            16 => Self::Nullifiers,
            17 => Self::MerkleTrees,
            18 => Self::Code,
            19 => Self::StorageRow,
            20 => Self::ContractState,
            21 => Self::BlockIndex,
            22 => Self::WitnessSchedule,
            _ => return None,
        })
    }

    /// Canonical on-disk DB directory name for this store. Used by
    /// the cross-store checkpoint manifest (CheckPointV2) so replay
    /// can route each entry back to its store. Matches the
    /// `DB_NAME` constant in the corresponding stores/ module.
    pub fn db_name(self) -> &'static str {
        match self {
            Self::Accounts => "account",
            Self::Witnesses => "witness",
            Self::Votes => "votes",
            Self::Delegation => "delegation",
            Self::DelegatedResources => "DelegatedResource",
            Self::DynProps => "properties",
            Self::Proposals => "proposal",
            Self::NameIndex => "account-index",
            Self::IdIndex => "accountid-index",
            Self::AssetV1 => "asset-issue",
            Self::AssetV2 => "asset-issue-v2",
            Self::Contracts => "contract",
            Self::Abi => "abi",
            Self::ExchangeV1 => "exchange",
            Self::ExchangeV2 => "exchange-v2",
            Self::MarketOrders => "market_order",
            Self::Nullifiers => "nullifier",
            Self::MerkleTrees => "IncrementalMerkleTree",
            Self::Code => "code",
            Self::StorageRow => "storage-row",
            Self::ContractState => "contract-state",
            Self::BlockIndex => "block-index",
            Self::WitnessSchedule => "witness_schedule",
        }
    }
}

/// One `(key, before_image)` pair captured from a session commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndoEntry {
    pub store: StoreId,
    pub key: Vec<u8>,
    /// `None` means "the key didn't exist before this block" — rollback
    /// must delete it. `Some(v)` means rollback must restore `v`.
    pub before: Option<Vec<u8>>,
}

/// One block's complete undo log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockUndoRecord {
    pub entries: Vec<UndoEntry>,
}

impl BlockUndoRecord {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, e: UndoEntry) {
        self.entries.push(e);
    }

    /// Serialize to the wire format described in the module doc.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.entries.len() * 40);
        out.extend_from_slice(&(self.entries.len() as u32).to_be_bytes());
        for e in &self.entries {
            out.push(e.store as u8);
            out.extend_from_slice(&(e.key.len() as u32).to_be_bytes());
            out.extend_from_slice(&e.key);
            match &e.before {
                Some(v) => {
                    out.push(1);
                    out.extend_from_slice(&(v.len() as u32).to_be_bytes());
                    out.extend_from_slice(v);
                }
                None => out.push(0),
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut p = 0;
        if bytes.len() < 4 {
            return Err(DecodeError::Truncated);
        }
        let count = u32::from_be_bytes(bytes[p..p + 4].try_into().unwrap()) as usize;
        p += 4;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            if bytes.len() < p + 1 + 4 {
                return Err(DecodeError::Truncated);
            }
            let store_byte = bytes[p];
            p += 1;
            let store = StoreId::from_u8(store_byte)
                .ok_or(DecodeError::UnknownStoreId(store_byte))?;
            let key_len = u32::from_be_bytes(bytes[p..p + 4].try_into().unwrap()) as usize;
            p += 4;
            if bytes.len() < p + key_len + 1 {
                return Err(DecodeError::Truncated);
            }
            let key = bytes[p..p + key_len].to_vec();
            p += key_len;
            let has = bytes[p];
            p += 1;
            let before = if has == 1 {
                if bytes.len() < p + 4 {
                    return Err(DecodeError::Truncated);
                }
                let vl = u32::from_be_bytes(bytes[p..p + 4].try_into().unwrap()) as usize;
                p += 4;
                if bytes.len() < p + vl {
                    return Err(DecodeError::Truncated);
                }
                let v = bytes[p..p + vl].to_vec();
                p += vl;
                Some(v)
            } else if has == 0 {
                None
            } else {
                return Err(DecodeError::BadHasFlag(has));
            };
            entries.push(UndoEntry { store, key, before });
        }
        Ok(Self { entries })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("undo record truncated")]
    Truncated,
    #[error("unknown store id {0} in undo record (newer tron-goblin-node wrote it?)")]
    UnknownStoreId(u8),
    #[error("bad 'has before' flag {0} (must be 0 or 1)")]
    BadHasFlag(u8),
}

/// Typed wrapper over the raw KvBackend holding the per-block undo
/// logs. Keys are 8-byte big-endian block numbers; values are encoded
/// [`BlockUndoRecord`]s.
#[derive(Clone)]
pub struct BlockUndoStore {
    backend: Arc<dyn KvBackend>,
}

impl BlockUndoStore {
    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    /// Persist the undo log for `block_num`. Overwrites any prior
    /// entry — which only happens during a reorg where we're
    /// re-applying a block we previously rolled back, and the new
    /// log supersedes the old one.
    pub fn put(&self, block_num: i64, record: &BlockUndoRecord) {
        self.backend.put(&num_key(block_num), &record.encode());
    }

    /// Read the undo log for `block_num`. `None` when there's no
    /// record (typically: block was never applied, or the record was
    /// pruned because the block is now beyond the reorg horizon).
    pub fn get(&self, block_num: i64) -> Result<Option<BlockUndoRecord>, DecodeError> {
        match self.backend.get(&num_key(block_num)) {
            Some(bytes) => BlockUndoRecord::decode(&bytes).map(Some),
            None => Ok(None),
        }
    }

    /// Drop the record for `block_num`. Idempotent.
    pub fn delete(&self, block_num: i64) {
        self.backend.delete(&num_key(block_num));
    }

    /// Drop every record with `block_num < threshold`. Used after a
    /// block is solidified beyond the reorg window — once a block is
    /// PBFT-confirmed by 2/3 of SRs, no reorg can pull it back, so the
    /// undo log is dead weight.
    pub fn prune_below(&self, threshold: i64) {
        // Scan keys via the backend's scan_all() — fine for the
        // expected sizes (a few thousand block_num entries at most;
        // pruning runs lazily, not in the hot path).
        for (k, _) in self.backend.scan_all() {
            if k.len() != 8 {
                continue;
            }
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&k);
            let n = i64::from_be_bytes(buf);
            if n < threshold {
                self.backend.delete(&k);
            }
        }
    }
}

fn num_key(block_num: i64) -> [u8; 8] {
    block_num.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemBackend;

    #[test]
    fn round_trip_empty_record() {
        let rec = BlockUndoRecord::new();
        let bytes = rec.encode();
        let decoded = BlockUndoRecord::decode(&bytes).unwrap();
        assert_eq!(rec, decoded);
    }

    #[test]
    fn round_trip_mixed_entries() {
        let rec = BlockUndoRecord {
            entries: vec![
                UndoEntry {
                    store: StoreId::Accounts,
                    key: vec![1, 2, 3],
                    before: Some(vec![0xff, 0xee]),
                },
                UndoEntry {
                    store: StoreId::DynProps,
                    key: b"LATEST_BLOCK_HEADER_NUMBER".to_vec(),
                    before: None,
                },
                UndoEntry {
                    store: StoreId::StorageRow,
                    key: vec![0; 64],
                    before: Some(vec![0; 32]),
                },
            ],
        };
        let bytes = rec.encode();
        let decoded = BlockUndoRecord::decode(&bytes).unwrap();
        assert_eq!(rec, decoded);
    }

    #[test]
    fn truncated_record_errors_cleanly() {
        let rec = BlockUndoRecord {
            entries: vec![UndoEntry {
                store: StoreId::Accounts,
                key: vec![1, 2, 3, 4, 5],
                before: Some(vec![9, 9, 9]),
            }],
        };
        let bytes = rec.encode();
        // Truncate halfway through.
        let truncated = &bytes[..bytes.len() / 2];
        assert!(matches!(
            BlockUndoRecord::decode(truncated),
            Err(DecodeError::Truncated)
        ));
    }

    #[test]
    fn unknown_store_id_errors_with_actual_byte() {
        // Hand-build a record whose first entry claims store_id = 99.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u32.to_be_bytes()); // 1 entry
        bytes.push(99); // bogus store id
        bytes.extend_from_slice(&0u32.to_be_bytes()); // 0-length key
        bytes.push(0); // no before
        let err = BlockUndoRecord::decode(&bytes).unwrap_err();
        assert!(matches!(err, DecodeError::UnknownStoreId(99)));
    }

    #[test]
    fn store_put_get_delete_round_trip() {
        let be: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
        let s = BlockUndoStore::new(be);
        let rec = BlockUndoRecord {
            entries: vec![UndoEntry {
                store: StoreId::Accounts,
                key: vec![1, 2],
                before: Some(vec![9]),
            }],
        };
        s.put(42, &rec);
        let got = s.get(42).unwrap().unwrap();
        assert_eq!(got, rec);
        s.delete(42);
        assert!(s.get(42).unwrap().is_none());
    }

    #[test]
    fn prune_below_drops_old_entries() {
        let be: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
        let s = BlockUndoStore::new(be);
        let rec = BlockUndoRecord::new();
        for n in 1..=10i64 {
            s.put(n, &rec);
        }
        s.prune_below(6);
        for n in 1..=5 {
            assert!(s.get(n).unwrap().is_none(), "block {n} should be pruned");
        }
        for n in 6..=10 {
            assert!(s.get(n).unwrap().is_some(), "block {n} should remain");
        }
    }
}
