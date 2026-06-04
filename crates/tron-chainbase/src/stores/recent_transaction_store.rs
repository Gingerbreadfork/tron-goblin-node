//! RecentTransactionStore — directory name `recent-transaction`.
//!
//! Sliding-window store mirroring [`super::RecentBlockStore`]: caches a
//! packed list of transaction ids per recent block so the node can
//! validate `ref_block_hash` quickly. Same low-16-bits wrapping rule.
//!
//! Key:   2-byte BE `(block_num & 0xFFFF)`.
//! Value: opaque packed bytes (32-byte tx ids concatenated, in
//!        java-tron — exposed here as raw bytes).

use std::sync::Arc;

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME: &str = "recent-transaction";

pub struct RecentTransactionStore {
    backend: Arc<dyn KvBackend>,
}

impl RecentTransactionStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    pub fn key_for(block_num: i64) -> [u8; 2] {
        ((block_num & 0xFFFF) as u16).to_be_bytes()
    }

    pub fn put(&self, block_num: i64, value: &[u8]) -> Result<(), StoreError> {
        self.backend.put(&Self::key_for(block_num), value)?;
        Ok(())
    }

    pub fn get(&self, block_num: i64) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.backend.get(&Self::key_for(block_num))?)
    }
}
