//! CheckPointV2Store — directory name is **caller-supplied per checkpoint**.
//!
//! java-tron creates a new CheckPointV2Store for each checkpoint, passing
//! the directory path at construction. There is no single fixed DB_NAME.
//! Each checkpoint dir is named like `checkpoint/<block_num>/...` and is
//! a full snapshot of the state KV pairs at that point.
//!
//! As implemented in upstream java-tron, the `put` method is a no-op for
//! the checkpoint mechanism currently in use (the V2 checkpoint is
//! written by the snapshot infrastructure at a lower level); this Rust
//! port matches that behaviour for parity. Reads work as expected.

use std::sync::Arc;

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub struct CheckPointV2Store {
    backend: Arc<dyn KvBackend>,
}

impl CheckPointV2Store {
    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    /// **No-op**. Matches `CheckPointV2Store.put(byte[], byte[])` in
    /// java-tron, whose body is empty (`{}`). The checkpoint mechanism
    /// writes via a sibling code path; this method exists for API
    /// symmetry only.
    pub fn put(&self, _key: &[u8], _value: &[u8]) {
        // Intentionally empty — matches java-tron upstream.
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.backend.get(key)?)
    }

    pub fn delete(&self, key: &[u8]) -> Result<(), StoreError> {
        self.backend.delete(key)?;
        Ok(())
    }
}
