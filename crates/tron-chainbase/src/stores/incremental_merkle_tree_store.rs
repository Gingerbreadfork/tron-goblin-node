//! IncrementalMerkleTreeStore — directory name `IncrementalMerkleTree`
//! *(PascalCase, no separators!)*.
//!
//! Holds checkpointed states of the shielded-pool's incremental Merkle
//! tree for Sapling-style zk-SNARK note commitments.
//!
//! Key:   opaque bytes (typically a 32-byte rolling-anchor hash or a
//!        block-height-derived identifier).
//! Value: protobuf-encoded `IncrementalMerkleTree` message.
//!
//! **Directory-name trap**: this is the *only* TRON store whose directory
//! name is PascalCase. Every other store uses kebab-case (`block-index`),
//! snake_case (`witness_schedule`), or camelCase (`transactionRetStore`).

use std::sync::Arc;

use prost::Message;
use tron_proto::IncrementalMerkleTree;

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME: &str = "IncrementalMerkleTree";

pub struct IncrementalMerkleTreeStore {
    backend: Arc<dyn KvBackend>,
}

impl IncrementalMerkleTreeStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    pub fn put(&self, key: &[u8], tree: &IncrementalMerkleTree) -> Result<(), StoreError> {
        self.backend.put(key, &tree.encode_to_vec())?;
        Ok(())
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<IncrementalMerkleTree>, StoreError> {
        let Some(bytes) = self.backend.get(key)? else {
            return Ok(None);
        };
        Ok(Some(IncrementalMerkleTree::decode(bytes.as_slice())?))
    }

    pub fn contains(&self, key: &[u8]) -> Result<bool, StoreError> {
        Ok(self.backend.contains(key)?)
    }
}

/// Sentinel key for the "current" (in-progress) tree being built up as
/// shielded transactions execute within a block.
pub const CURRENT_TREE_KEY: &[u8] = b"CURRENT_TREE";

/// Sentinel key for the "last" (block-finalised) tree — the most
/// recently committed root, used as the default starting point at the
/// top of each new block.
pub const LAST_TREE_KEY: &[u8] = b"LAST_TREE";
