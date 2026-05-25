//! RecentBlockStore — directory name `recent-block`.
//!
//! Holds a sliding window of the most recent ~65,536 block hashes used
//! to validate `ref_block_hash` on incoming transactions.
//!
//! Key:   2-byte big-endian `(block_num & 0xFFFF)` — only the low 16 bits
//!        of the block height, so the window naturally wraps.
//! Value: 2-byte slice of the block hash (matches java-tron's
//!        `ref_block_bytes` field length).
//!
//! A transaction includes `ref_block_bytes` + `ref_block_hash` so the
//! node can confirm it was crafted against a recent chain head. The
//! 2-byte truncation is enough because ref_block validity is checked
//! within a 65k-block window — collisions across that window can't
//! occur fast enough to matter.
//!
//! Source: `org.tron.core.db.RecentBlockStore`. The store itself just
//! stores raw bytes; the truncation is applied by the caller in
//! `Manager.processBlock` when populating the index.

use std::sync::Arc;

use crate::backend::KvBackend;

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

    pub fn put(&self, block_num: i64, ref_block_bytes: &[u8]) {
        self.backend.put(&Self::key_for(block_num), ref_block_bytes);
    }

    pub fn get(&self, block_num: i64) -> Option<Vec<u8>> {
        self.backend.get(&Self::key_for(block_num))
    }
}
