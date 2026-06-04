//! CommonDataBaseStore — directory name `common-database`.
//!
//! Distinct from [`CommonStore`](crate::stores::CommonStore) (directory
//! `common`). Tracks PBFT-committed block numbers — the only entry is
//! `LATEST_PBFT_BLOCK_NUM`, holding the highest block number that has
//! received the 2/3+ SR-vote threshold via PBFT.
//!
//! Source: `org.tron.core.db.CommonDataBase` — single fixed key,
//! 8-byte big-endian i64 value, monotonic (writes are rejected when
//! `number <= current`).

use std::sync::Arc;

use crate::backend::KvBackend;

pub const DB_NAME: &str = "common-database";

const LATEST_PBFT_BLOCK_NUM: &[u8] = b"LATEST_PBFT_BLOCK_NUM";

pub struct CommonDataBaseStore {
    backend: Arc<dyn KvBackend>,
}

impl CommonDataBaseStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    /// Write the latest PBFT-committed block number. java-tron rejects
    /// non-monotonic writes (returns silently with a warn log) — we
    /// mirror that to keep on-disk values byte-identical across the
    /// two implementations.
    ///
    /// Backend IO errors are surfaced as panics with rich context —
    /// this single-key store is read on every block-apply via
    /// `latest_pbft_block_num()`, propagating Results through every
    /// caller would cascade across the codebase. The panic message
    /// names the store + key so triage is unambiguous.
    pub fn save_latest_pbft_block_num(&self, number: i64) {
        if number <= self.latest_pbft_block_num() {
            return;
        }
        self.backend
            .put(LATEST_PBFT_BLOCK_NUM, &number.to_be_bytes())
            .unwrap_or_else(|e| {
                panic!("common-database store: failed to write LATEST_PBFT_BLOCK_NUM: {e}")
            });
    }

    /// Read the latest PBFT-committed block number. `0` when the key
    /// hasn't been set yet. Backend IO failures panic with context
    /// (same rationale as [`save_latest_pbft_block_num`]).
    pub fn latest_pbft_block_num(&self) -> i64 {
        let Some(bytes) = self
            .backend
            .get(LATEST_PBFT_BLOCK_NUM)
            .unwrap_or_else(|e| {
                panic!("common-database store: failed to read LATEST_PBFT_BLOCK_NUM: {e}")
            })
        else {
            return 0;
        };
        if bytes.len() != 8 {
            return 0;
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes);
        i64::from_be_bytes(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MemBackend;

    #[test]
    fn save_and_read_round_trips() {
        let backend: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
        let store = CommonDataBaseStore::new(backend);
        assert_eq!(store.latest_pbft_block_num(), 0);
        store.save_latest_pbft_block_num(42);
        assert_eq!(store.latest_pbft_block_num(), 42);
    }

    #[test]
    fn save_rejects_non_monotonic_writes_silently() {
        let backend: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
        let store = CommonDataBaseStore::new(backend);
        store.save_latest_pbft_block_num(100);
        store.save_latest_pbft_block_num(50); // ignored
        store.save_latest_pbft_block_num(100); // equal, also ignored
        assert_eq!(store.latest_pbft_block_num(), 100);
        store.save_latest_pbft_block_num(101);
        assert_eq!(store.latest_pbft_block_num(), 101);
    }

    #[test]
    fn directory_name_matches_java_tron() {
        // The audit calls out that `common-database` is a SEPARATE
        // directory from `common` (java-tron's CommonStore). Pin both.
        assert_eq!(CommonDataBaseStore::DB_NAME, "common-database");
    }
}
