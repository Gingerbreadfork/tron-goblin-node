//! BlockStore — directory name `block`.
//!
//! Key:   32-byte block hash (the full `BlockId`, with num in first 8 bytes).
//! Value: protobuf-encoded `Block` message.
//!
//! Source: `org.tron.core.db.BlockStore` + `BlockCapsule.getData()`.

use std::sync::Arc;

use prost::Message;
use tron_proto::Block;
use tron_types::BlockId;

use crate::backend::KvBackend;
use crate::stores::StoreError;

/// Mirrors java-tron's `chainbase` store-name constant.
pub const DB_NAME: &str = "block";

pub struct BlockStore {
    backend: Arc<dyn KvBackend>,
}

impl BlockStore {
    /// On-disk directory name. Must match java-tron exactly.
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    /// Store a block, keyed by its `BlockId`.
    ///
    /// NOTE: this persists a prost re-encode, which silently normalizes any
    /// non-canonical wire bytes (unknown fields, non-sorted map entries) the
    /// original network encoding carried — java stores the verbatim bytes.
    /// Callers holding the original wire bytes should use [`Self::put_raw`].
    pub fn put(&self, id: &BlockId, block: &Block) -> Result<(), StoreError> {
        let bytes = block.encode_to_vec();
        self.backend.put(id.as_bytes(), &bytes)?;
        Ok(())
    }

    /// Store a block's ORIGINAL wire bytes verbatim (java `BlockCapsule.getData()`
    /// semantics — the exact network encoding, unknown fields included). Decodes
    /// identically to a [`Self::put`] row; additionally preserves the bytes a
    /// prost round-trip would drop, so later raw reads ([`Self::get_raw`]) can
    /// recover per-tx wire ids and sizes byte-exactly.
    pub fn put_raw(&self, id: &BlockId, block_bytes: &[u8]) -> Result<(), StoreError> {
        self.backend.put(id.as_bytes(), block_bytes)?;
        Ok(())
    }

    pub fn get(&self, id: &BlockId) -> Result<Block, StoreError> {
        let bytes = self.backend.get(id.as_bytes())?.ok_or(StoreError::NotFound)?;
        Ok(Block::decode(bytes.as_slice())?)
    }

    /// The stored row bytes, undecoded. For rows written via [`Self::put_raw`]
    /// these are the block's original wire bytes; for legacy [`Self::put`] rows
    /// they are the prost re-encode (still a valid `Block` encoding).
    pub fn get_raw(&self, id: &BlockId) -> Result<Vec<u8>, StoreError> {
        self.backend.get(id.as_bytes())?.ok_or(StoreError::NotFound)
    }

    /// Per-transaction ids for a stored block, in block order — sha256 of each
    /// tx's ORIGINAL `raw_data` span read from the stored row bytes (java
    /// `TransactionCapsule.getRawHash`). Falls back per-tx to the prost
    /// re-encode hash when the row is missing or a span can't be derived; the
    /// two are identical for canonical txs, so the fallback only matters for
    /// legacy re-encoded rows of txs that carried unknown `raw_data` fields
    /// (whose original bytes are unrecoverable). A tx with no `raw_data`
    /// yields the all-zero id.
    ///
    /// `block` must be the decoded form of the stored row (the caller usually
    /// just fetched it via [`Self::get`]).
    pub fn tx_ids_for(&self, id: &BlockId, block: &Block) -> Vec<[u8; 32]> {
        let wire = self
            .get_raw(id)
            .ok()
            .and_then(|b| tron_types::tx_wire_infos_from_block_bytes(&b));
        block
            .transactions
            .iter()
            .enumerate()
            .map(|(i, tx)| {
                wire.as_ref()
                    .and_then(|w| w.get(i))
                    .and_then(|w| w.tx_id)
                    .unwrap_or_else(|| {
                        tx.raw_data
                            .as_ref()
                            .map(|r| tron_crypto::hash::sha256(&r.encode_to_vec()))
                            .unwrap_or([0u8; 32])
                    })
            })
            .collect()
    }

    pub fn contains(&self, id: &BlockId) -> Result<bool, StoreError> {
        Ok(self.backend.contains(id.as_bytes())?)
    }

    pub fn delete(&self, id: &BlockId) -> Result<(), StoreError> {
        self.backend.delete(id.as_bytes())?;
        Ok(())
    }

    /// Return up to `limit` consecutive blocks starting at block
    /// number `start_num` (inclusive), in ascending order. Mirrors
    /// java-tron's `BlockStore.getLimitNumber(startNum, limit)`,
    /// which constructs a `BlockId(ZERO_HASH, startNum)` and seeks
    /// forward through the key space.
    ///
    /// Implementation: our `BlockId` byte layout is `[num_be: 8][hash:
    /// 24]`, so byte-lexicographic ordering coincides with numeric
    /// ordering. A forward seek from `[start_num_be || 0u8; 24]`
    /// returns blocks in num order.
    ///
    /// Skips entries that fail to decode as `Block` (matches java-tron
    /// which logs and continues).
    pub fn get_limit_number(&self, start_num: i64, limit: usize) -> Result<Vec<Block>, StoreError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut start_key = [0u8; 32];
        start_key[..8].copy_from_slice(&start_num.to_be_bytes());
        Ok(self
            .backend
            .scan_from(&start_key, limit)?
            .into_iter()
            .filter_map(|(k, v)| match Block::decode(v.as_slice()) {
                Ok(block) => Some(block),
                Err(e) => {
                    // C-8: log-and-continue (java-tron parity). A row that
                    // won't decode as `Block` is corruption, not "end of
                    // range" — surface it instead of silently dropping it.
                    tracing::error!(
                        store = "block",
                        key = %hex::encode(&k),
                        error = %e,
                        "skipping undecodable Block row in get_limit_number"
                    );
                    None
                }
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MemBackend;

    fn synth_block(num: i64) -> (BlockId, Block) {
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&num.to_be_bytes());
        // Distinct tail per num so distinct keys.
        id[31] = (num & 0xff) as u8;
        let blk = Block {
            block_header: Some(tron_proto::BlockHeader {
                raw_data: Some(tron_proto::block_header::Raw {
                    number: num,
                    ..Default::default()
                }),
                witness_signature: Vec::new(),
            }),
            transactions: Vec::new(),
        };
        (BlockId::from_raw(id), blk)
    }

    #[test]
    fn tx_ids_for_uses_stored_wire_bytes_and_falls_back_to_reencode() {
        let backend: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
        let store = BlockStore::new(backend);

        // A tx whose raw_data carries a trailing unknown varint field
        // (field 20, `a0 01 03`) — dropped by a prost round-trip.
        let raw = tron_proto::transaction::Raw {
            ref_block_bytes: vec![0xab, 0xcd],
            expiration: 1_700_000_000_000,
            ..Default::default()
        };
        let mut raw_bytes = raw.encode_to_vec();
        raw_bytes.extend_from_slice(&[0xa0, 0x01, 0x03]);
        // tx wire: raw_data = field 1, signature = field 2.
        let mut tx_wire = vec![0x0a, raw_bytes.len() as u8];
        tx_wire.extend_from_slice(&raw_bytes);
        tx_wire.extend_from_slice(&[0x12, 65]);
        tx_wire.extend_from_slice(&[0xaa; 65]);
        // block wire: transactions = field 1.
        let mut block_wire = vec![0x0a, tx_wire.len() as u8];
        block_wire.extend_from_slice(&tx_wire);

        let block = Block::decode(block_wire.as_slice()).unwrap();
        let mut idb = [0u8; 32];
        idb[..8].copy_from_slice(&7i64.to_be_bytes());
        let id = BlockId::from_raw(idb);

        // Verbatim row → the wire id (full raw_data span incl. unknown bytes).
        store.put_raw(&id, &block_wire).unwrap();
        let wire_id = tron_crypto::hash::sha256(&raw_bytes);
        assert_eq!(store.tx_ids_for(&id, &block), vec![wire_id]);

        // Re-encoded row (legacy put) → falls back to the re-encode hash.
        store.put(&id, &block).unwrap();
        let reencode_id = tron_crypto::hash::sha256(
            &block.transactions[0].raw_data.as_ref().unwrap().encode_to_vec(),
        );
        assert_ne!(wire_id, reencode_id);
        assert_eq!(store.tx_ids_for(&id, &block), vec![reencode_id]);
    }

    #[test]
    fn get_limit_number_returns_consecutive_blocks() {
        let backend: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
        let store = BlockStore::new(backend);
        for n in 5..15 {
            let (id, blk) = synth_block(n);
            store.put(&id, &blk).unwrap();
        }
        let got = store.get_limit_number(7, 4).unwrap();
        let nums: Vec<i64> = got
            .iter()
            .map(|b| b.block_header.as_ref().unwrap().raw_data.as_ref().unwrap().number)
            .collect();
        assert_eq!(nums, vec![7, 8, 9, 10]);
    }

    #[test]
    fn get_limit_number_zero_limit_returns_empty() {
        let backend: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
        let store = BlockStore::new(backend);
        let (id, blk) = synth_block(1);
        store.put(&id, &blk).unwrap();
        assert!(store.get_limit_number(1, 0).unwrap().is_empty());
    }

    #[test]
    fn get_limit_number_past_end_returns_partial() {
        let backend: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
        let store = BlockStore::new(backend);
        for n in [3, 4, 5] {
            let (id, blk) = synth_block(n);
            store.put(&id, &blk).unwrap();
        }
        // Ask for 10 starting at 4 — only 2 exist.
        let got = store.get_limit_number(4, 10).unwrap();
        assert_eq!(got.len(), 2);
    }
}
