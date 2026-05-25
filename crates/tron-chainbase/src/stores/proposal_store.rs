//! ProposalStore — directory name `proposal`.
//!
//! Key:   8-byte big-endian `i64` of the proposal ID
//!        (`ProposalCapsule.calculateDbKey(long)` → `ByteArray.fromLong`).
//! Value: protobuf-encoded `Proposal` message.

use std::sync::Arc;

use prost::Message;
use tron_proto::Proposal;

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME: &str = "proposal";

pub struct ProposalStore {
    backend: Arc<dyn KvBackend>,
}

impl ProposalStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    pub fn key_for(id: i64) -> [u8; 8] {
        id.to_be_bytes()
    }

    pub fn put(&self, id: i64, proposal: &Proposal) {
        self.backend.put(&Self::key_for(id), &proposal.encode_to_vec());
    }

    pub fn get(&self, id: i64) -> Result<Option<Proposal>, StoreError> {
        let Some(bytes) = self.backend.get(&Self::key_for(id)) else {
            return Ok(None);
        };
        Ok(Some(Proposal::decode(bytes.as_slice())?))
    }

    pub fn delete(&self, id: i64) {
        self.backend.delete(&Self::key_for(id));
    }

    /// Snapshot every proposal in the store. Used by the maintenance
    /// round to find proposals whose `expiration_time` has just passed
    /// and that should transition to `Approved` / `Disapproved`.
    pub fn all(&self) -> Result<Vec<(i64, Proposal)>, StoreError> {
        let mut out = Vec::new();
        for (k, v) in self.backend.scan_all() {
            if k.len() != 8 {
                continue;
            }
            let mut id_bytes = [0u8; 8];
            id_bytes.copy_from_slice(&k);
            let id = i64::from_be_bytes(id_bytes);
            let proposal = Proposal::decode(v.as_slice())?;
            out.push((id, proposal));
        }
        Ok(out)
    }
}
