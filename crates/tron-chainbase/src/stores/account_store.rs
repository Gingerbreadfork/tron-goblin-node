//! AccountStore — directory name `account`.
//!
//! Key:   21-byte TRON address (1 prefix byte + 20 hash bytes).
//! Value: protobuf-encoded `Account` message.
//!
//! Source: `org.tron.core.db.AccountStore` + `AccountCapsule.getData()`.

use std::sync::Arc;

use prost::Message;
use tron_crypto::address::{Address, ADDRESS_LENGTH};
use tron_proto::Account;

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME: &str = "account";

pub struct AccountStore {
    backend: Arc<dyn KvBackend>,
}

impl AccountStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    pub fn put(&self, address: &Address, account: &Account) {
        self.backend.put(address.as_bytes(), &account.encode_to_vec());
    }

    /// Read by `Address`. `None` if absent.
    pub fn get(&self, address: &Address) -> Result<Option<Account>, StoreError> {
        let Some(bytes) = self.backend.get(address.as_bytes()) else {
            return Ok(None);
        };
        Ok(Some(Account::decode(bytes.as_slice())?))
    }

    /// Read by raw 21-byte key. Useful when reading from a real disk store
    /// where keys are just byte slices.
    pub fn get_raw(&self, key: &[u8]) -> Result<Option<Account>, StoreError> {
        if key.len() != ADDRESS_LENGTH {
            return Err(StoreError::InvalidKeyLength {
                got: key.len(),
                expected: ADDRESS_LENGTH,
            });
        }
        let Some(bytes) = self.backend.get(key) else {
            return Ok(None);
        };
        Ok(Some(Account::decode(bytes.as_slice())?))
    }

    pub fn contains(&self, address: &Address) -> bool {
        self.backend.contains(address.as_bytes())
    }

    pub fn delete(&self, address: &Address) {
        self.backend.delete(address.as_bytes());
    }
}
