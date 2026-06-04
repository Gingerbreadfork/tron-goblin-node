//! RewardViStore — directory name `reward-vi`.
//!
//! Holds per-witness, per-cycle reward-index ("Vi") accumulators used by
//! the new reward algorithm. Keyed by opaque bytes (the caller builds
//! the key from cycle/address); value is a serialised BigInteger.
//!
//! Same value-encoding convention as [`super::DelegationStore::set_witness_vi_raw`]:
//! Java's `BigInteger.toByteArray()` — signed two's-complement
//! big-endian, variable length. We pass bytes through unchanged.

use std::sync::Arc;

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME: &str = "reward-vi";

pub struct RewardViStore {
    backend: Arc<dyn KvBackend>,
}

impl RewardViStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StoreError> {
        self.backend.put(key, value)?;
        Ok(())
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.backend.get(key)?)
    }
}
