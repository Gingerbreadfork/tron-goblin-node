//! TransactionCacheStore — directory name `trans-cache`.
//!
//! Hot-path bloom-style lookup for "have we already seen tx_id X?"
//! Used during block validation to dedupe txs without a full
//! TransactionStore read. Value is a presence marker only.
//!
//! Source: `org.tron.core.db.TransactionCache` — wraps
//! `TxCacheDB(trans-cache)`. Java's implementation adds bloom-filter
//! caching on top; ours is straight key-presence for now.

use std::sync::Arc;

use crate::backend::KvBackend;

pub const DB_NAME: &str = "trans-cache";

pub struct TransactionCacheStore {
    backend: Arc<dyn KvBackend>,
}

impl TransactionCacheStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    /// Mark `tx_id` as seen. Idempotent — re-inserting the same key
    /// is a no-op at the storage layer.
    pub fn put(&self, tx_id: &[u8; 32]) {
        // java-tron stores an empty-bytes value (BytesCapsule wrapping
        // 0 bytes). Match the on-disk shape so a snapshot from
        // java-tron is readable as-is.
        self.backend.put(tx_id, &[]);
    }

    /// `true` if `tx_id` has been recorded.
    pub fn contains(&self, tx_id: &[u8; 32]) -> bool {
        self.backend.get(tx_id).is_some()
    }

    /// Remove an entry. Used by tooling (`prune-historical`) that
    /// trims the cache after a block ages out.
    pub fn remove(&self, tx_id: &[u8; 32]) {
        self.backend.delete(tx_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MemBackend;

    #[test]
    fn put_then_contains() {
        let backend: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
        let store = TransactionCacheStore::new(backend);
        let id = [0xab; 32];
        assert!(!store.contains(&id));
        store.put(&id);
        assert!(store.contains(&id));
        store.remove(&id);
        assert!(!store.contains(&id));
    }

    #[test]
    fn directory_name_matches_java_tron() {
        assert_eq!(TransactionCacheStore::DB_NAME, "trans-cache");
    }
}
