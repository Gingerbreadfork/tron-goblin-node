//! BalanceTraceStore — directory name `balance-trace`.
//!
//! Per-block trace of every balance change (debit/credit operations).
//! Used by node operators for forensic accounting; not consensus-critical.
//!
//! Key:   8-byte BE `i64` block number.
//! Value: protobuf-encoded `BlockBalanceTrace` message.

use std::sync::Arc;

use prost::Message;
use tron_proto::BlockBalanceTrace;

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME: &str = "balance-trace";

pub struct BalanceTraceStore {
    backend: Arc<dyn KvBackend>,
}

impl BalanceTraceStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    pub fn key_for(block_num: i64) -> [u8; 8] {
        block_num.to_be_bytes()
    }

    pub fn put(&self, block_num: i64, trace: &BlockBalanceTrace) {
        self.backend.put(&Self::key_for(block_num), &trace.encode_to_vec());
    }

    pub fn get(&self, block_num: i64) -> Result<Option<BlockBalanceTrace>, StoreError> {
        let Some(bytes) = self.backend.get(&Self::key_for(block_num)) else {
            return Ok(None);
        };
        Ok(Some(BlockBalanceTrace::decode(bytes.as_slice())?))
    }
}
