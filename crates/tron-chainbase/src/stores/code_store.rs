//! CodeStore — directory name `code`.
//!
//! Key:   contract code hash (typically 32-byte Keccak-256 of the bytecode).
//! Value: raw bytecode bytes (NOT protobuf-wrapped).
//!
//! Source: `CodeStore` — `CodeCapsule.getData()` returns the bytecode
//! bytes directly.

use std::sync::Arc;

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME: &str = "code";

pub struct CodeStore {
    backend: Arc<dyn KvBackend>,
}

impl CodeStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    pub fn put(&self, code_hash: &[u8], bytecode: &[u8]) -> Result<(), StoreError> {
        self.backend.put(code_hash, bytecode)?;
        Ok(())
    }

    pub fn get(&self, code_hash: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.backend.get(code_hash)?)
    }

    pub fn contains(&self, code_hash: &[u8]) -> Result<bool, StoreError> {
        Ok(self.backend.contains(code_hash)?)
    }
}
