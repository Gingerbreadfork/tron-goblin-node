//! BlockIndexStore — directory name `block-index`.
//!
//! Maps block number → block id, so the chain can look up "which block was
//! at height N" without scanning the BlockStore.
//!
//! Key:   8-byte big-endian `i64` of the block number.
//! Value: 32-byte `BlockId` bytes (with the number in the first 8 bytes —
//!        redundant but it's how java-tron writes it).
//!
//! Source: `org.tron.core.db.BlockIndexStore`.

use std::sync::Arc;

use tron_types::BlockId;

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME: &str = "block-index";

pub struct BlockIndexStore {
    backend: Arc<dyn KvBackend>,
}

impl BlockIndexStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    /// Encode a block number as the 8-byte big-endian key java-tron writes.
    ///
    /// Critical: java-tron uses `Longs.toByteArray(long)` which is the
    /// signed-long big-endian representation. For non-negative numbers
    /// (block heights are always >= 0) this is identical to the u64
    /// big-endian encoding.
    pub fn key_for(num: i64) -> [u8; 8] {
        num.to_be_bytes()
    }

    pub fn put(&self, id: &BlockId) -> Result<(), StoreError> {
        self.backend
            .put(&Self::key_for(id.num() as i64), id.as_bytes())?;
        Ok(())
    }

    pub fn get(&self, num: i64) -> Result<BlockId, StoreError> {
        let bytes = self
            .backend
            .get(&Self::key_for(num))?
            .ok_or(StoreError::NotFound)?;
        if bytes.len() != 32 {
            return Err(StoreError::InvalidValueLength {
                got: bytes.len(),
                expected: 32,
            });
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&bytes);
        Ok(BlockId::from_raw(buf))
    }

    pub fn delete(&self, num: i64) -> Result<(), StoreError> {
        self.backend.delete(&Self::key_for(num))?;
        Ok(())
    }

    /// Return up to `limit` consecutive `BlockId`s starting at block
    /// number `start_num` (inclusive). Mirrors java-tron's
    /// `BlockIndexStore.getLimitNumber(startNumber, limit)` which the
    /// HTTP `/wallet/getblockbylimitnext` and the gRPC equivalent
    /// rely on for paginated block-range walks.
    ///
    /// Stops at the first missing block in the range — `[5, 6, 7, _,
    /// 9]` with `start_num=5, limit=10` returns `[5, 6, 7]`, not the
    /// disjoint pair `[5, 6, 7, 9]`. Matches java-tron behaviour.
    pub fn get_limit_number(
        &self,
        start_num: i64,
        limit: usize,
    ) -> Result<Vec<BlockId>, StoreError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut out = Vec::with_capacity(limit.min(64));
        for offset in 0..limit {
            let n = start_num.checked_add(offset as i64).ok_or(StoreError::NotFound)?;
            match self.get(n) {
                Ok(id) => out.push(id),
                Err(StoreError::NotFound) => break,
                Err(other) => return Err(other),
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MemBackend;
    use std::sync::Arc;

    fn id(num: i64) -> BlockId {
        // Synthesise a BlockId with the right number prefix.
        let mut buf = [0u8; 32];
        buf[..8].copy_from_slice(&num.to_be_bytes());
        BlockId::from_raw(buf)
    }

    #[test]
    fn get_limit_number_returns_consecutive_block_ids() {
        let backend: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
        let store = BlockIndexStore::new(backend);
        for n in 5..15 {
            store.put(&id(n)).unwrap();
        }
        let out = store.get_limit_number(7, 4).unwrap();
        assert_eq!(out.len(), 4);
        for (i, b) in out.iter().enumerate() {
            assert_eq!(b.num(), 7 + i as u64);
        }
    }

    #[test]
    fn get_limit_number_stops_at_first_gap() {
        let backend: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
        let store = BlockIndexStore::new(backend);
        store.put(&id(10)).unwrap();
        store.put(&id(11)).unwrap();
        // gap at 12
        store.put(&id(13)).unwrap();
        let out = store.get_limit_number(10, 5).unwrap();
        assert_eq!(out.iter().map(|b| b.num()).collect::<Vec<_>>(), vec![10, 11]);
    }

    #[test]
    fn get_limit_number_zero_limit_returns_empty() {
        let backend: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
        let store = BlockIndexStore::new(backend);
        store.put(&id(1)).unwrap();
        assert!(store.get_limit_number(1, 0).unwrap().is_empty());
    }
}
