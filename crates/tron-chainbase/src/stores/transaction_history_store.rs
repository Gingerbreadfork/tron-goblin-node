//! TransactionHistoryStore — directory name `transactionHistoryStore`
//! *(camelCase!)*.
//!
//! Per-transaction execution receipt store, written when each tx is
//! executed during block processing.
//!
//! Key:   32-byte transaction id (the `sha256(raw_data)` hash).
//! Value: protobuf-encoded `TransactionInfo` message (gas/energy used,
//!        logs, internal txs, etc.).
//!
//! Second of the two camelCase-named stores. See
//! [`super::TransactionRetStore`].

use std::sync::Arc;

use prost::Message;
use tron_proto::TransactionInfo;

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME: &str = "transactionHistoryStore";

pub struct TransactionHistoryStore {
    backend: Arc<dyn KvBackend>,
}

impl TransactionHistoryStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    pub fn put(&self, tx_id: &[u8; 32], info: &TransactionInfo) {
        self.backend.put(tx_id, &info.encode_to_vec());
    }

    pub fn get(&self, tx_id: &[u8; 32]) -> Result<Option<TransactionInfo>, StoreError> {
        let Some(bytes) = self.backend.get(tx_id) else {
            return Ok(None);
        };
        Ok(Some(TransactionInfo::decode(bytes.as_slice())?))
    }
}
