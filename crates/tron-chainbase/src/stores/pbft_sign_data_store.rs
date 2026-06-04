//! PbftSignDataStore — directory name `pbft-sign-data`.
//!
//! Holds the PBFT signature aggregates for finality:
//!
//! | Kind  | Key (UTF-8 bytes)              | Value                    |
//! |-------|---------------------------------|--------------------------|
//! | SRL   | `"SRL" + decimal_epoch`         | `PBFTMessage.Raw` proto  |
//! | BLOCK | `"BLOCK" + decimal_block_num`   | `PBFTMessage.Raw` proto  |
//!
//! The `DataType` enum value (`SRL` or `BLOCK`) is concatenated as the
//! string representation of the enum with the number's decimal text —
//! exactly what `("SRL"+epoch).getBytes()` produces in java-tron.
//!
//! Source: `org.tron.core.db.PbftSignDataStore.buildKey`.

use std::collections::BTreeMap;
use std::sync::Arc;

use prost::Message;
use tron_crypto::address::Address;
use tron_proto::pbft_message::Raw as PbftRaw;

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME: &str = "pbft-sign-data";

pub struct PbftSignDataStore {
    backend: Arc<dyn KvBackend>,
}

impl PbftSignDataStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    /// `"SRL" + epoch` UTF-8 bytes. Used for the SR-list signing data.
    pub fn sr_list_key(epoch: i64) -> Vec<u8> {
        format!("SRL{epoch}").into_bytes()
    }

    /// `"BLOCK" + block_num` UTF-8 bytes. Used for per-block PBFT
    /// finality signatures.
    pub fn block_key(block_num: i64) -> Vec<u8> {
        format!("BLOCK{block_num}").into_bytes()
    }

    pub fn put(&self, key: &[u8], value: &PbftRaw) -> Result<(), StoreError> {
        self.backend.put(key, &value.encode_to_vec())?;
        Ok(())
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<PbftRaw>, StoreError> {
        let Some(bytes) = self.backend.get(key)? else {
            return Ok(None);
        };
        Ok(Some(PbftRaw::decode(bytes.as_slice())?))
    }

    /// Store the full signature aggregate (Raw + every commit signer's
    /// signature) under `key`. Uses [`tron_proto::PbftCommitResult`] —
    /// `data` holds the encoded Raw, `signature` is the 65-byte
    /// signatures from the 2/3+ quorum, **sorted by signer address**.
    ///
    /// The sort order is part of the byte layout java-tron's
    /// `PbftSignCapsule` produces on disk: two nodes that observe the
    /// same quorum must persist byte-identical entries or the
    /// `LATEST_SOLIDIFIED_BLOCK_NUM` capsule will diverge on a state-root
    /// comparison.
    ///
    /// Taking a `BTreeMap` (rather than `&[Vec<u8>]`) encodes that
    /// invariant in the type — iteration is sorted-by-key — so a future
    /// caller that builds its own signature set can't accidentally write
    /// an unsorted entry. The `Address` keys are NOT persisted; only the
    /// signature values, in sort order, end up on disk.
    pub fn put_commit_result(
        &self,
        key: &[u8],
        raw: &PbftRaw,
        signatures: &BTreeMap<Address, Vec<u8>>,
    ) -> Result<(), StoreError> {
        let result = tron_proto::PbftCommitResult {
            data: raw.encode_to_vec(),
            signature: signatures.values().cloned().collect(),
        };
        self.backend.put(key, &result.encode_to_vec())?;
        Ok(())
    }

    /// Read back a commit-result: returns the (Raw, signatures) pair.
    /// `None` when no entry. Errors when the bytes don't decode.
    pub fn get_commit_result(
        &self,
        key: &[u8],
    ) -> Result<Option<(PbftRaw, Vec<Vec<u8>>)>, StoreError> {
        let Some(bytes) = self.backend.get(key)? else {
            return Ok(None);
        };
        let outer = tron_proto::PbftCommitResult::decode(bytes.as_slice())?;
        let raw = PbftRaw::decode(outer.data.as_slice())?;
        Ok(Some((raw, outer.signature)))
    }
}
