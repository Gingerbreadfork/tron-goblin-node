//! DelegatedResourceAccountIndexStore — directory name
//! `DelegatedResourceAccountIndex`.
//!
//! A bidirectional index over delegations. Every delegate operation
//! writes **two** rows so that both ends of the (from, to) pair can be
//! looked up:
//!
//! | Side        | Prefix | Key payload          | Value           |
//! |-------------|--------|----------------------|-----------------|
//! | V1 FROM     | `0x01` | `from(21) ‖ to(21)`  | `to` + timestamp|
//! | V1 TO       | `0x02` | `to(21) ‖ from(21)`  | `from` + ts     |
//! | V2 FROM     | `0x03` | `from(21) ‖ to(21)`  | `to` + ts       |
//! | V2 TO       | `0x04` | `to(21) ‖ from(21)`  | `from` + ts     |
//!
//! There is also a **legacy** format: a 21-byte raw-address key with a
//! `DelegatedResourceAccountIndex` value holding aggregated `fromAccounts`
//! and `toAccounts` lists. `DelegatedResourceAccountIndexStore.convert`
//! migrates those to the prefixed form. Reads should accept both during
//! the migration window.
//!
//! Source: `DelegatedResourceAccountIndexStore`.

use std::sync::Arc;

use prost::Message;
use tron_crypto::address::{Address, ADDRESS_LENGTH};
use tron_proto::DelegatedResourceAccountIndex;

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME: &str = "DelegatedResourceAccountIndex";

/// V1 FROM-side prefix.
pub const V1_FROM_PREFIX: u8 = 0x01;
/// V1 TO-side prefix.
pub const V1_TO_PREFIX: u8 = 0x02;
/// V2 FROM-side prefix.
pub const V2_FROM_PREFIX: u8 = 0x03;
/// V2 TO-side prefix.
pub const V2_TO_PREFIX: u8 = 0x04;

pub struct DelegatedResourceAccountIndexStore {
    backend: Arc<dyn KvBackend>,
}

impl DelegatedResourceAccountIndexStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    // -------------------- Key builders --------------------------------

    /// V1 FROM key: `[0x01, from(21), to(21)]`. Pairs with [`v1_to_key`]
    /// — both are written on every V1 delegation.
    pub fn v1_from_key(from: &Address, to: &Address) -> [u8; 1 + ADDRESS_LENGTH * 2] {
        prefixed_pair(V1_FROM_PREFIX, from, to)
    }

    /// V1 TO key: `[0x02, to(21), from(21)]`. Note the swapped order.
    pub fn v1_to_key(from: &Address, to: &Address) -> [u8; 1 + ADDRESS_LENGTH * 2] {
        prefixed_pair(V1_TO_PREFIX, to, from)
    }

    pub fn v2_from_key(from: &Address, to: &Address) -> [u8; 1 + ADDRESS_LENGTH * 2] {
        prefixed_pair(V2_FROM_PREFIX, from, to)
    }

    pub fn v2_to_key(from: &Address, to: &Address) -> [u8; 1 + ADDRESS_LENGTH * 2] {
        prefixed_pair(V2_TO_PREFIX, to, from)
    }

    /// Legacy: aggregated index keyed by a raw 21-byte address.
    pub fn legacy_key(addr: &Address) -> [u8; ADDRESS_LENGTH] {
        *addr.as_bytes()
    }

    // -------------------- CRUD ----------------------------------------

    pub fn put_raw(&self, key: &[u8], index: &DelegatedResourceAccountIndex) {
        self.backend.put(key, &index.encode_to_vec());
    }

    pub fn get_raw(
        &self,
        key: &[u8],
    ) -> Result<Option<DelegatedResourceAccountIndex>, StoreError> {
        let Some(bytes) = self.backend.get(key) else {
            return Ok(None);
        };
        Ok(Some(DelegatedResourceAccountIndex::decode(bytes.as_slice())?))
    }

    pub fn delete_raw(&self, key: &[u8]) {
        self.backend.delete(key);
    }
}

fn prefixed_pair(prefix: u8, a: &Address, b: &Address) -> [u8; 1 + ADDRESS_LENGTH * 2] {
    let mut out = [0u8; 1 + ADDRESS_LENGTH * 2];
    out[0] = prefix;
    out[1..1 + ADDRESS_LENGTH].copy_from_slice(a.as_bytes());
    out[1 + ADDRESS_LENGTH..].copy_from_slice(b.as_bytes());
    out
}
