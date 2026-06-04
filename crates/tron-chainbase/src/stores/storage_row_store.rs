//! StorageRowStore — directory name `storage-row`.
//!
//! Holds per-contract EVM storage slots. The key is **always 32 bytes**:
//!
//! ```text
//! key[0..16]  = keccak256(contract_address)[0..16]   ← first half of address hash
//! key[16..32] = slot[16..32]                         ← second half of slot key
//! ```
//!
//! For contract version 1 the slot is first wrapped with another Keccak:
//! `slot' = keccak256(slot)`. For contract version 2 the slot is taken
//! as-is.
//!
//! Source: `org.tron.core.vm.program.Storage.compose` (key) +
//! `Storage.addrHash` (= `keccak256(address)`).
//!
//! The "first half of address hash, second half of slot" interleave is
//! a TVM-specific optimisation: it co-locates rows of the same contract
//! in RocksDB lex order while still hashing the slot, preventing
//! adjacent-slot pre-images from sorting predictably.
//!
//! Value: raw 32-byte storage value (no protobuf framing).

use std::sync::Arc;

use tron_crypto::address::Address;
use tron_crypto::hash::keccak256;

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME: &str = "storage-row";

/// Length of a fully-composed storage-row key.
pub const KEY_LEN: usize = 32;
const PREFIX_BYTES: usize = 16;

pub struct StorageRowStore {
    backend: Arc<dyn KvBackend>,
}

impl StorageRowStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    /// Compose the composite storage-row key for a v2 contract (slot
    /// taken as-is). For v1 contracts use [`compose_key_v1`].
    pub fn compose_key(address: &Address, slot: &[u8; 32]) -> [u8; KEY_LEN] {
        let addr_hash = keccak256(address.as_bytes());
        let mut out = [0u8; KEY_LEN];
        out[..PREFIX_BYTES].copy_from_slice(&addr_hash[..PREFIX_BYTES]);
        out[PREFIX_BYTES..].copy_from_slice(&slot[PREFIX_BYTES..]);
        out
    }

    /// V1-contract key: the slot is first hashed (`keccak256`) before
    /// composition. Used for contracts deployed before
    /// `ALLOW_TVM_VOTE` / TVM v2.
    pub fn compose_key_v1(address: &Address, slot: &[u8; 32]) -> [u8; KEY_LEN] {
        let addr_hash = keccak256(address.as_bytes());
        let slot_hash = keccak256(slot);
        let mut out = [0u8; KEY_LEN];
        out[..PREFIX_BYTES].copy_from_slice(&addr_hash[..PREFIX_BYTES]);
        out[PREFIX_BYTES..].copy_from_slice(&slot_hash[PREFIX_BYTES..]);
        out
    }

    pub fn put(&self, key: &[u8; KEY_LEN], value: &[u8]) -> Result<(), StoreError> {
        self.backend.put(key, value)?;
        Ok(())
    }

    pub fn get(&self, key: &[u8; KEY_LEN]) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.backend.get(key)?)
    }

    /// Snapshot every storage row belonging to `contract_address`.
    /// Filters [`scan_all`](crate::KvBackend::scan_all) by the
    /// `keccak256(address)[..16]` prefix that every row of this
    /// contract shares.
    ///
    /// Used by per-contract storage-root computation.
    pub fn scan_for_contract(
        &self,
        address: &Address,
    ) -> Result<Vec<([u8; KEY_LEN], Vec<u8>)>, StoreError> {
        let prefix = keccak256(address.as_bytes());
        Ok(self
            .backend
            .scan_all()?
            .into_iter()
            .filter_map(|(k, v)| {
                if k.len() != KEY_LEN || k[..PREFIX_BYTES] != prefix[..PREFIX_BYTES] {
                    return None;
                }
                let mut key = [0u8; KEY_LEN];
                key.copy_from_slice(&k);
                Some((key, v))
            })
            .collect())
    }
}
