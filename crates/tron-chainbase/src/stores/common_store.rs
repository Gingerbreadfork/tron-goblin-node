//! CommonStore — directory name `common`.
//!
//! Generic byte-keyed kv store used for one-off pieces of node-local
//! state that don't fit any specific store (e.g. chain-id, db-version
//! markers). Keys and values are raw bytes.
//!
//! Source: `org.tron.core.db.CommonStore` — extends `TronDatabase<BytesCapsule>`
//! and is hard-coded with `super("common")` in its ctor.

use std::sync::Arc;

use crate::backend::KvBackend;

pub const DB_NAME: &str = "common";

pub struct CommonStore {
    backend: Arc<dyn KvBackend>,
}

impl CommonStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    pub fn put(&self, key: &[u8], value: &[u8]) {
        self.backend.put(key, value);
    }

    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.backend.get(key)
    }

    pub fn delete(&self, key: &[u8]) {
        self.backend.delete(key);
    }
}
