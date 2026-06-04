//! WitnessStore — directory name `witness`.
//!
//! Key:   21-byte TRON address.
//! Value: protobuf-encoded `Witness` message (vote count, brokerage, url).
//!
//! Source: `org.tron.core.db.WitnessStore` + `WitnessCapsule.getData()`.

use std::sync::Arc;

use prost::Message;
use tron_crypto::address::Address;
use tron_proto::Witness;

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME: &str = "witness";

pub struct WitnessStore {
    backend: Arc<dyn KvBackend>,
}

impl WitnessStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    pub fn put(&self, address: &Address, witness: &Witness) -> Result<(), StoreError> {
        self.backend.put(address.as_bytes(), &witness.encode_to_vec())?;
        Ok(())
    }

    pub fn get(&self, address: &Address) -> Result<Option<Witness>, StoreError> {
        let Some(bytes) = self.backend.get(address.as_bytes())? else {
            return Ok(None);
        };
        Ok(Some(Witness::decode(bytes.as_slice())?))
    }

    pub fn contains(&self, address: &Address) -> Result<bool, StoreError> {
        Ok(self.backend.contains(address.as_bytes())?)
    }

    pub fn delete(&self, address: &Address) -> Result<(), StoreError> {
        self.backend.delete(address.as_bytes())?;
        Ok(())
    }

    /// Snapshot every registered witness in the store.
    ///
    /// Used by:
    /// * Maintenance round (every 6 hours) to pick the active 27 SRs.
    /// * `TotalVoteCount` precompile (sum of all witness vote counts).
    ///
    /// Keys are 21 bytes (an [`Address`]). Anything shorter is a
    /// malformed write from a buggy upstream — skip it so a single bad
    /// row can't poison the entire iteration.
    pub fn all(&self) -> Result<Vec<(Address, Witness)>, StoreError> {
        let mut out = Vec::new();
        for (k, v) in self.backend.scan_all()? {
            let Ok(addr_bytes): Result<[u8; 21], _> = k.as_slice().try_into() else {
                // C-8: consensus store — a malformed key in the witness CF
                // would silently drop an SR from the maintenance ranking.
                // Log loudly; skip to match java-tron's iterate-and-continue.
                tracing::error!(
                    store = "witness",
                    key = %hex::encode(&k),
                    key_len = k.len(),
                    "skipping witness row with non-address key (expected 21 bytes)"
                );
                continue;
            };
            let addr = Address::from_raw(addr_bytes);
            let witness = Witness::decode(v.as_slice())?;
            out.push((addr, witness));
        }
        Ok(out)
    }
}
