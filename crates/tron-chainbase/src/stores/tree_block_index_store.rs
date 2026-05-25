//! TreeBlockIndexStore — directory name `tree-block-index`.
//!
//! A secondary block-number → block-hash index used during chain
//! rollback / fork-tree maintenance. Same shape as
//! [`super::BlockIndexStore`] but in a separate keyspace.
//!
//! Key:   8-byte BE `i64` block number.
//! Value: 32-byte block hash (`BlockId` raw bytes).

use std::sync::Arc;

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME: &str = "tree-block-index";

pub struct TreeBlockIndexStore {
    backend: Arc<dyn KvBackend>,
}

impl TreeBlockIndexStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    pub fn key_for(block_num: i64) -> [u8; 8] {
        block_num.to_be_bytes()
    }

    pub fn put(&self, block_num: i64, block_id_bytes: &[u8]) {
        self.backend.put(&Self::key_for(block_num), block_id_bytes);
    }

    pub fn get(&self, block_num: i64) -> Result<Option<[u8; 32]>, StoreError> {
        let Some(bytes) = self.backend.get(&Self::key_for(block_num)) else {
            return Ok(None);
        };
        if bytes.len() != 32 {
            return Err(StoreError::InvalidValueLength {
                got: bytes.len(),
                expected: 32,
            });
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&bytes);
        Ok(Some(buf))
    }
}
