//! TransactionRetStore — directory name `transactionRetStore` *(camelCase!)*.
//!
//! Holds the per-block list of transaction execution results.
//!
//! Key:   8-byte BE `i64` block number.
//! Value: protobuf-encoded `TransactionRet` message (a list of
//!        per-transaction `TransactionInfo` entries).
//!
//! **Directory-name trap**: this is one of *two* stores java-tron names
//! in camelCase rather than the kebab-case used everywhere else. Easy
//! to mis-spell as `transaction-ret-store` or similar. See
//! [`super::TransactionHistoryStore`] for the other.

use std::sync::Arc;

use prost::Message;
use tron_proto::TransactionRet;

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME: &str = "transactionRetStore";

pub struct TransactionRetStore {
    backend: Arc<dyn KvBackend>,
}

impl TransactionRetStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    pub fn key_for(block_num: i64) -> [u8; 8] {
        block_num.to_be_bytes()
    }

    pub fn put(&self, block_num: i64, ret: &TransactionRet) {
        self.backend.put(&Self::key_for(block_num), &ret.encode_to_vec());
    }

    pub fn get(&self, block_num: i64) -> Result<Option<TransactionRet>, StoreError> {
        let Some(bytes) = self.backend.get(&Self::key_for(block_num)) else {
            return Ok(None);
        };
        Ok(Some(TransactionRet::decode(bytes.as_slice())?))
    }
}
