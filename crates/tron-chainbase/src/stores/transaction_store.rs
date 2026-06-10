//! TransactionStore — directory name `trans`.
//!
//! **Important quirk**: java-tron uses a dual-format value scheme to save
//! space. Once a transaction is included in a block, only the block number
//! is stored here (8 bytes) and the full transaction is recovered by
//! looking up the block in `BlockStore`. Before inclusion (or for the
//! genesis case where `blockNum == -1`), the full encoded `Transaction` is
//! written.
//!
//! On read, the value's *length* disambiguates:
//! * 8 bytes → block-number reference
//! * any other length → encoded `Transaction` (proto3 default-encoded
//!   transactions can be 0 bytes; real signed transactions are always
//!   well above 8)
//!
//! Source: `org.tron.core.db.TransactionStore.put` and `.get`.

use std::sync::Arc;

use prost::Message;
use tron_proto::Transaction;

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME: &str = "trans";

/// The decoded shape of a `TransactionStore` value.
#[derive(Debug, Clone, PartialEq)]
pub enum StoredTransaction {
    /// The transaction is committed in a block at this height. Resolve the
    /// full body via `BlockStore` if needed.
    BlockRef(i64),
    /// Full transaction (pre-inclusion, or genesis case).
    Full(Transaction),
}

pub struct TransactionStore {
    backend: Arc<dyn KvBackend>,
}

impl TransactionStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    /// Put a block-reference: the transaction lives in block `block_num`.
    pub fn put_block_ref(&self, tx_id: &[u8; 32], block_num: i64) -> Result<(), StoreError> {
        self.backend.put(tx_id, &block_num.to_be_bytes())?;
        Ok(())
    }

    /// Put a whole block's worth of block-references in one atomic
    /// batch. Used by the apply hook (one batch per block beats
    /// hundreds of individual puts on the apply path).
    pub fn put_block_refs(
        &self,
        refs: impl IntoIterator<Item = ([u8; 32], i64)>,
    ) -> Result<(), StoreError> {
        let ops: Vec<crate::backend::WriteOp> = refs
            .into_iter()
            .map(|(tx_id, num)| {
                crate::backend::WriteOp::Put(tx_id.to_vec(), num.to_be_bytes().to_vec())
            })
            .collect();
        if !ops.is_empty() {
            self.backend.write_batch(&ops)?;
        }
        Ok(())
    }

    /// Put a full transaction (pre-inclusion).
    pub fn put_full(&self, tx_id: &[u8; 32], tx: &Transaction) -> Result<(), StoreError> {
        self.backend.put(tx_id, &tx.encode_to_vec())?;
        Ok(())
    }

    /// Read the raw value. `None` if absent.
    pub fn get(&self, tx_id: &[u8; 32]) -> Result<Option<StoredTransaction>, StoreError> {
        let Some(bytes) = self.backend.get(tx_id)? else {
            return Ok(None);
        };
        if bytes.len() == 8 {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes);
            Ok(Some(StoredTransaction::BlockRef(i64::from_be_bytes(buf))))
        } else {
            Ok(Some(StoredTransaction::Full(Transaction::decode(
                bytes.as_slice(),
            )?)))
        }
    }

    /// Convenience: return just the block height if this tx is a block ref.
    /// Matches `TransactionStore.getBlockNumber`. Returns `-1` if absent,
    /// or extracts `raw_data.timestamp`-adjacent height from a stored
    /// Transaction (java-tron pulls it from the `TransactionCapsule.blockNum`
    /// field which is not part of the proto; for the full-Transaction case
    /// callers must look up the block elsewhere — we return `None`).
    pub fn get_block_number(&self, tx_id: &[u8; 32]) -> Result<Option<i64>, StoreError> {
        match self.get(tx_id)? {
            Some(StoredTransaction::BlockRef(num)) => Ok(Some(num)),
            Some(StoredTransaction::Full(_)) => Ok(None),
            None => Ok(None),
        }
    }
}
