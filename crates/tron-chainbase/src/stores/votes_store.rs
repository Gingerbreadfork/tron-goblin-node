//! VotesStore — directory name `votes`.
//!
//! Key: 21-byte voter address.
//! Value: protobuf-encoded `Votes` message holding both the voter's
//!        previous votes (`old_votes`) and their newly-cast votes
//!        (`new_votes`) for the current cycle. The maintenance period
//!        promotes `new_votes` into the SR ranking and then resets.
//!
//! Source: `org.tron.core.store.VotesStore` + `VotesCapsule.getData()`.

use std::sync::Arc;

use prost::Message;
use tron_crypto::address::Address;
use tron_proto::Votes;

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME: &str = "votes";

pub struct VotesStore {
    backend: Arc<dyn KvBackend>,
}

impl VotesStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    pub fn put(&self, address: &Address, votes: &Votes) {
        self.backend.put(address.as_bytes(), &votes.encode_to_vec());
    }

    pub fn get(&self, address: &Address) -> Result<Option<Votes>, StoreError> {
        let Some(bytes) = self.backend.get(address.as_bytes()) else {
            return Ok(None);
        };
        Ok(Some(Votes::decode(bytes.as_slice())?))
    }

    pub fn contains(&self, address: &Address) -> bool {
        self.backend.contains(address.as_bytes())
    }

    pub fn delete(&self, address: &Address) {
        self.backend.delete(address.as_bytes());
    }

    /// Scan every voter row. Used by the maintenance pass to walk all
    /// cast votes when computing per-witness vote deltas — mirrors
    /// java-tron's `votesStore.iterator()`. Skips rows whose key isn't
    /// a 21-byte address or whose value doesn't decode as `Votes`.
    pub fn all(&self) -> Result<Vec<(Address, Votes)>, StoreError> {
        let mut out = Vec::new();
        for (k, v) in self.backend.scan_all() {
            if k.len() != tron_crypto::address::ADDRESS_LENGTH {
                continue;
            }
            let mut buf = [0u8; tron_crypto::address::ADDRESS_LENGTH];
            buf.copy_from_slice(&k);
            let Ok(votes) = Votes::decode(v.as_slice()) else {
                continue;
            };
            out.push((Address::from_raw(buf), votes));
        }
        Ok(out)
    }
}
