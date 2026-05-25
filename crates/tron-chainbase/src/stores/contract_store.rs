//! ContractStore — directory name `contract`.
//!
//! Key:   21-byte contract address.
//! Value: protobuf-encoded `SmartContract` message **with its ABI
//!        cleared**. java-tron's `ContractStore.put` strips the ABI
//!        field before writing because the ABI is stored separately in
//!        [`super::AbiStore`]. Reading: callers who need the ABI must
//!        consult both stores.
//!
//! Source: `ContractStore.put` (`if (item.getInstance().hasAbi()) {
//! item = new ContractCapsule(item.getInstance().toBuilder().clearAbi().build()); }`).

use std::sync::Arc;

use prost::Message;
use tron_crypto::address::Address;
use tron_proto::SmartContract;

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME: &str = "contract";

pub struct ContractStore {
    backend: Arc<dyn KvBackend>,
}

impl ContractStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    /// Store a contract. **The ABI field is cleared before writing** —
    /// the ABI lives in `AbiStore`. Pass the contract through unchanged
    /// here; we strip it for you so the on-disk bytes match java-tron's
    /// convention.
    pub fn put(&self, address: &Address, contract: &SmartContract) {
        let mut to_write = contract.clone();
        to_write.abi = None;
        self.backend
            .put(address.as_bytes(), &to_write.encode_to_vec());
    }

    pub fn get(&self, address: &Address) -> Result<Option<SmartContract>, StoreError> {
        let Some(bytes) = self.backend.get(address.as_bytes()) else {
            return Ok(None);
        };
        Ok(Some(SmartContract::decode(bytes.as_slice())?))
    }

    pub fn contains(&self, address: &Address) -> bool {
        self.backend.contains(address.as_bytes())
    }
}
