//! RecentBlockStore — directory name `recent-block`.
//!
//! Holds a sliding window of the most recent ~65,536 block hashes used
//! to validate `ref_block_hash` on incoming transactions.
//!
//! Key:   2-byte big-endian `(block_num & 0xFFFF)` — only the low 16 bits
//!        of the block height, so the window naturally wraps.
//! Value: 8 bytes — `BlockId.bytes[8..16]` of the block at that height,
//!        matching the canonical encoding the tx-builder writes into
//!        `raw_data.ref_block_hash` (see
//!        `tron_rpc::builder::build_unsigned_tx`: `id.as_bytes()[8..16]`).
//!
//! A transaction includes `ref_block_bytes` + `ref_block_hash` so the
//! node can confirm it was crafted against a recent chain head: look up
//! `ref_block_bytes` (the lookup key — low 16 bits of the referenced
//! block-num) and compare the stored value to `ref_block_hash`. A
//! match proves the tx targets this fork; a mismatch (or no entry)
//! means the tx is too old or was built against a different chain.
//!
//! Source: `org.tron.core.db.RecentBlockStore`. The store itself just
//! stores raw bytes; both the key truncation and the value slicing are
//! applied by the caller in `Manager.processBlock` when populating the
//! index. **Note**: nothing in the node currently populates this store
//! — ref_block validation queries `BlockIndexStore` instead (see
//! `tron-node::ref_block`). A future populator should wire it here, in
//! `execute_block_logic`'s step 3, so the byte layout matches java-tron
//! exactly.

use std::sync::Arc;

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME: &str = "recent-block";

pub struct RecentBlockStore {
    backend: Arc<dyn KvBackend>,
}

impl RecentBlockStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    /// Build the canonical 2-byte key from a block number: low 16 bits,
    /// big-endian.
    pub fn key_for(block_num: i64) -> [u8; 2] {
        ((block_num & 0xFFFF) as u16).to_be_bytes()
    }

    pub fn put(&self, block_num: i64, ref_block_bytes: &[u8]) -> Result<(), StoreError> {
        self.backend.put(&Self::key_for(block_num), ref_block_bytes)?;
        Ok(())
    }

    pub fn get(&self, block_num: i64) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.backend.get(&Self::key_for(block_num))?)
    }
}
