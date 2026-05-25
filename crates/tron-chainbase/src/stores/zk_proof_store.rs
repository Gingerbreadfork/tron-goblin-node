//! ZKProofStore — directory name is caller-supplied.
//!
//! Caches "we already verified this proof" boolean results to short-
//! circuit duplicate verifications. Used by Sapling shielded-transfer
//! actuators.
//!
//! Key:   proof bytes (or a hash of them — caller chooses).
//! Value: **1 byte**, `0x01` for true / `0x00` for false.
//!
//! **Read panic in java-tron**: `get()` returns `dbSource.getData(key)[0] == 0x01`
//! which **NullPointerExceptions** if the key isn't present. The Rust
//! port surfaces that as `Option<bool>::None` instead.

use std::sync::Arc;

use crate::backend::KvBackend;

pub struct ZkProofStore {
    backend: Arc<dyn KvBackend>,
}

impl ZkProofStore {
    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    pub fn put(&self, key: &[u8], value: bool) {
        self.backend.put(key, &[if value { 0x01 } else { 0x00 }]);
    }

    pub fn get(&self, key: &[u8]) -> Option<bool> {
        let bytes = self.backend.get(key)?;
        bytes.first().map(|b| *b == 0x01)
    }
}
