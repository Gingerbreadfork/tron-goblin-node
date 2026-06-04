//! NullifierStore — directory name `nullifier`.
//!
//! Records every shielded-transaction nullifier ever spent so the node
//! can reject double-spends in Sapling/zk-SNARK transactions.
//!
//! Used as a **set**: java-tron writes the same bytes as both the key
//! *and* the value. The presence of an entry is what matters — its
//! value is the same nullifier bytes by convention.
//!
//! Key:   nullifier bytes (typically 32 bytes from `librustzcash`).
//! Value: identical to key (by convention).

use std::sync::Arc;

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME: &str = "nullifier";

pub struct NullifierStore {
    backend: Arc<dyn KvBackend>,
}

impl NullifierStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    /// Record `nullifier` as spent. java-tron stores the nullifier as
    /// both key and value (`put(bytes.getData(), new BytesCapsule(bytes.getData()))`).
    pub fn put(&self, nullifier: &[u8]) -> Result<(), StoreError> {
        self.backend.put(nullifier, nullifier)?;
        Ok(())
    }

    /// Has this nullifier ever been recorded? java-tron's
    /// `NullifierStore.get` returns `null` for unseen entries.
    pub fn contains(&self, nullifier: &[u8]) -> Result<bool, StoreError> {
        Ok(self.backend.contains(nullifier)?)
    }
}
