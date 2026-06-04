//! CheckTmpStore — directory name `tmp`.
//!
//! **`put` is a no-op in java-tron** (the method body is empty). The
//! store appears to be a legacy stub that was kept around for
//! Spring-bean wiring. We match the behaviour so a Rust node's
//! checkpoint directory layout doesn't diverge from java-tron's.

use std::sync::Arc;

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME: &str = "tmp";

pub struct CheckTmpStore {
    backend: Arc<dyn KvBackend>,
}

impl CheckTmpStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    /// **No-op**, matching `CheckTmpStore.put` in java-tron (empty body).
    pub fn put(&self, _key: &[u8], _value: &[u8]) {}

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.backend.get(key)?)
    }
}
