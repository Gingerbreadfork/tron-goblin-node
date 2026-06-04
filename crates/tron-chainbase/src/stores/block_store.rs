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
    pub fn put(&self, id: &BlockId, block: &Block) -> Result<(), StoreError> {
        let bytes = block.encode_to_vec();
        self.backend.put(id.as_bytes(), &bytes)?;
        Ok(())
    }

    pub fn get(&self, id: &BlockId) -> Result<Block, StoreError> {
        let bytes = self.backend.get(id.as_bytes())?.ok_or(StoreError::NotFound)?;
        Ok(Block::decode(bytes.as_slice())?)
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
