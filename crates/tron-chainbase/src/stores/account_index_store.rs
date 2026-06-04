//! AccountIndexStore — directory name `account-index`.
//!
//! Secondary index: account name → account address. Lets the node look
//! up `getAccountByName` without scanning every Account.
//!
//! Key:   raw account name bytes (UTF-8).
//! Value: 21-byte account address.
//!
//! Source: `AccountIndexStore` — `put(accountCapsule.getAccountName(),
//! accountCapsule.createDbKey())`.

use std::sync::Arc;

use tron_crypto::address::{Address, ADDRESS_LENGTH};

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME: &str = "account-index";

pub struct AccountIndexStore {
    backend: Arc<dyn KvBackend>,
}

impl AccountIndexStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    pub fn put(&self, name: &[u8], address: &Address) -> Result<(), StoreError> {
        self.backend.put(name, address.as_bytes())?;
        Ok(())
    }

    pub fn get(&self, name: &[u8]) -> Result<Option<Address>, StoreError> {
        let Some(bytes) = self.backend.get(name)? else {
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
