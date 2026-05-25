//! AccountIdIndexStore — directory name `accountid-index`.
//!
//! Secondary index: account *id* → account address. Distinct from
//! [`super::AccountIndexStore`] which indexes by account *name*.
//!
//! **Critical normalization**: keys are **lowercased** before storage
//! (java-tron uses `toLowerCase(Locale.ROOT)`). Any caller looking up a
//! mixed-case account id must lowercase it first, or the lookup misses.
//!
//! Key:   lowercase UTF-8 bytes of the account id.
//! Value: 21-byte account address.
//!
//! Source: `org.tron.core.store.AccountIdIndexStore.getLowerCaseAccountId`.

use std::sync::Arc;

use tron_crypto::address::{Address, ADDRESS_LENGTH};

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME: &str = "accountid-index";

pub struct AccountIdIndexStore {
    backend: Arc<dyn KvBackend>,
}

impl AccountIdIndexStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    /// Normalize an account id to its on-disk form (lowercase UTF-8).
    /// Java uses `Locale.ROOT` which is functionally identical to Rust's
    /// `str::to_lowercase` for the ASCII identifiers TRON uses in practice.
    pub fn normalize_id(id: &[u8]) -> Vec<u8> {
        // Defensive: handle non-ASCII bytes by passing them through.
        match std::str::from_utf8(id) {
            Ok(s) => s.to_lowercase().into_bytes(),
            Err(_) => id.to_vec(),
        }
    }

    pub fn put(&self, account_id: &[u8], address: &Address) {
        let key = Self::normalize_id(account_id);
        self.backend.put(&key, address.as_bytes());
    }

    pub fn get(&self, account_id: &[u8]) -> Result<Option<Address>, StoreError> {
        let key = Self::normalize_id(account_id);
        let Some(bytes) = self.backend.get(&key) else {
            return Ok(None);
        };
        if bytes.len() != ADDRESS_LENGTH {
            return Err(StoreError::InvalidValueLength {
                got: bytes.len(),
                expected: ADDRESS_LENGTH,
            });
        }
        let mut buf = [0u8; ADDRESS_LENGTH];
        buf.copy_from_slice(&bytes);
        Ok(Some(Address::from_raw(buf)))
    }
}
