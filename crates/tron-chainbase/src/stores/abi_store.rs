//! AbiStore — directory name `abi`.
//!
//! Key:   21-byte contract address.
//! Value: protobuf-encoded `SmartContract.Abi` message (the contract's ABI).
//!
//! The ABI is split out of `ContractStore` to save space — most reads of
//! a contract don't need the ABI, and ABIs can be large.
//!
//! Source: `AbiStore` (`put(byte[], byte[])` writes raw bytes).

use std::sync::Arc;

use prost::Message;
use tron_crypto::address::Address;
use tron_proto::smart_contract::Abi;

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME: &str = "abi";

pub struct AbiStore {
    backend: Arc<dyn KvBackend>,
}

impl AbiStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    pub fn put(&self, address: &Address, abi: &Abi) {
        self.backend.put(address.as_bytes(), &abi.encode_to_vec());
    }

    /// Convenience: write pre-encoded ABI bytes. java-tron's
    /// `AbiStore.put(byte[], byte[])` is used by call sites that already
    /// have the encoded bytes (e.g. when extracting from a SmartContract
    /// before clearing it for ContractStore).
    pub fn put_raw(&self, address: &Address, abi_bytes: &[u8]) {
        self.backend.put(address.as_bytes(), abi_bytes);
    }

    pub fn get(&self, address: &Address) -> Result<Option<Abi>, StoreError> {
        let Some(bytes) = self.backend.get(address.as_bytes()) else {
            return Ok(None);
        };
        Ok(Some(Abi::decode(bytes.as_slice())?))
    }
}
