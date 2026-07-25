//! StorageRowStore — directory name `storage-row`.
//!
//! Holds per-contract EVM storage slots. The key is **always 32 bytes**:
//!
//! ```text
//! key[0..16]  = keccak256(contract_address)[0..16]   ← first half of address hash
//! key[16..32] = slot[16..32]                         ← second half of slot key
//! ```
//!
//! For contract version 1 the slot is first wrapped with another Keccak:
//! `slot' = keccak256(slot)`. For contract version 2 the slot is taken
//! as-is.
//!
//! Source: `org.tron.core.vm.program.Storage.compose` (key) +
//! `Storage.addrHash` (= `keccak256(address)`).
//!
//! The "first half of address hash, second half of slot" interleave is
//! a TVM-specific optimisation: it co-locates rows of the same contract
//! in RocksDB lex order while still hashing the slot, preventing
//! adjacent-slot pre-images from sorting predictably.
//!
//! Value: raw 32-byte storage value (no protobuf framing).

use std::sync::Arc;

use tron_crypto::address::Address;
use tron_crypto::hash::keccak256;

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME: &str = "storage-row";

/// Length of a fully-composed storage-row key.
pub const KEY_LEN: usize = 32;
const PREFIX_BYTES: usize = 16;

pub struct StorageRowStore {
    backend: Arc<dyn KvBackend>,
}

impl StorageRowStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    /// java-tron's storage `addrHash` (the key's 16-byte prefix source).
    /// Normally `sha3(address)`, but for a CREATE2-deployed contract — one
    /// whose `SmartContract.trxHash` is non-empty — it is
    /// `sha3(address ++ trxHash)` (java `Storage.generateAddrHash`, set in
    /// `RepositoryImpl.getStorage`). Getting this wrong points every storage
    /// access for that contract at the wrong key, so reads come back zero.
    pub fn addr_hash(address: &Address, trx_hash: &[u8]) -> [u8; 32] {
        if trx_hash.is_empty() {
            keccak256(address.as_bytes())
        } else {
            let mut buf = Vec::with_capacity(address.as_bytes().len() + trx_hash.len());
            buf.extend_from_slice(address.as_bytes());
            buf.extend_from_slice(trx_hash);
            keccak256(&buf)
        }
    }

    /// Compose a storage-row key from a precomputed `addr_hash` (see
    /// [`addr_hash`](Self::addr_hash)). `v1 == true` hashes the slot first
    /// (pre-`ALLOW_TVM_VOTE` layout); v2 takes the slot raw.
    pub fn compose_key_with_addr_hash(
        addr_hash: &[u8; 32],
        slot: &[u8; 32],
        v1: bool,
    ) -> [u8; KEY_LEN] {
        let mut out = [0u8; KEY_LEN];
        out[..PREFIX_BYTES].copy_from_slice(&addr_hash[..PREFIX_BYTES]);
        if v1 {
            let slot_hash = keccak256(slot);
            out[PREFIX_BYTES..].copy_from_slice(&slot_hash[PREFIX_BYTES..]);
        } else {
            out[PREFIX_BYTES..].copy_from_slice(&slot[PREFIX_BYTES..]);
        }
        out
    }

    /// Compose the composite storage-row key for a v2 contract (slot
    /// taken as-is) using the plain `sha3(address)` prefix. For v1 contracts
    /// use [`compose_key_v1`]; for CREATE2 contracts compose via
    /// [`addr_hash`](Self::addr_hash) + [`compose_key_with_addr_hash`].
    pub fn compose_key(address: &Address, slot: &[u8; 32]) -> [u8; KEY_LEN] {
        Self::compose_key_with_addr_hash(&Self::addr_hash(address, &[]), slot, false)
    }

    /// V1-contract key: the slot is first hashed (`keccak256`) before
    /// composition. Used for contracts deployed before
    /// `ALLOW_TVM_VOTE` / TVM v2.
    pub fn compose_key_v1(address: &Address, slot: &[u8; 32]) -> [u8; KEY_LEN] {
        Self::compose_key_with_addr_hash(&Self::addr_hash(address, &[]), slot, true)
    }

    pub fn put(&self, key: &[u8; KEY_LEN], value: &[u8]) -> Result<(), StoreError> {
        self.backend.put(key, value)?;
        Ok(())
    }

    /// Remove a storage row. java `Storage.commit()` deletes the row when the
    /// committed value is zero (`new DataWord(value).isZero()`) rather than
    /// persisting a 32-byte-zero row, so SSTORE-to-zero leaves no key behind.
    /// Idempotent.
    pub fn delete(&self, key: &[u8; KEY_LEN]) -> Result<(), StoreError> {
        self.backend.delete(key)?;
        Ok(())
    }

    pub fn get(&self, key: &[u8; KEY_LEN]) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.backend.get(key)?)
    }

    /// Snapshot every storage row belonging to `contract_address`.
    /// Filters [`scan_all`](crate::KvBackend::scan_all) by the
    /// `keccak256(address)[..16]` prefix that every row of this
    /// contract shares.
    ///
    /// Used by per-contract storage-root computation.
    pub fn scan_for_contract(
        &self,
        address: &Address,
    ) -> Result<Vec<([u8; KEY_LEN], Vec<u8>)>, StoreError> {
        let prefix = keccak256(address.as_bytes());
        Ok(self
            .backend
            .scan_all()?
            .into_iter()
            .filter_map(|(k, v)| {
                if k.len() != KEY_LEN || k[..PREFIX_BYTES] != prefix[..PREFIX_BYTES] {
                    return None;
                }
                let mut key = [0u8; KEY_LEN];
                key.copy_from_slice(&k);
                Some((key, v))
            })
            .collect())
    }

    /// Every storage row sharing the 16-byte prefix of `addr_hash`, via the
    /// backend's NATIVE bounded [`scan_prefix`](crate::KvBackend::scan_prefix)
    /// rather than a full [`scan_all`](crate::KvBackend::scan_all).
    ///
    /// Unlike [`scan_for_contract`](Self::scan_for_contract), the caller
    /// supplies the already-resolved [`addr_hash`](Self::addr_hash), so this
    /// serves CREATE2 contracts (whose prefix is `sha3(address ++ trxHash)`)
    /// as well as plain ones. It also works over a parent that rejects
    /// unbounded `scan_all` — notably the at-height archive view — which the
    /// fork-simulation `state` (replace-all) override relies on.
    pub fn scan_prefix_by_addr_hash(
        &self,
        addr_hash: &[u8; 32],
    ) -> Result<Vec<([u8; KEY_LEN], Vec<u8>)>, StoreError> {
        Ok(self
            .backend
            .scan_prefix(&addr_hash[..PREFIX_BYTES])?
            .into_iter()
            .filter_map(|(k, v)| {
                if k.len() != KEY_LEN {
                    return None;
                }
                let mut key = [0u8; KEY_LEN];
                key.copy_from_slice(&k);
                Some((key, v))
            })
            .collect())
    }
}

#[cfg(test)]
mod addr_hash_tests {
    use super::*;

    fn hexvec(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Ground-truth from mainnet: the SunSwap pair
    /// `41c83479647bd52ebed75603368c84289cf119daef` is CREATE2-deployed with
    /// `trxHash = abfcccef…`, so java-tron addresses its storage at
    /// `sha3(address ++ trxHash)`, NOT `sha3(address)`. Reading it at the plain
    /// prefix returns zero (the bug that made every DEX swap revert with
    /// INSUFFICIENT_LIQUIDITY against a real java snapshot).
    #[test]
    fn create2_contract_uses_trxhash_prefixed_addr_hash() {
        let mut a = [0u8; 21];
        a.copy_from_slice(&hexvec("41c83479647bd52ebed75603368c84289cf119daef"));
        let addr = Address::from_raw(a);
        let trx = hexvec("abfcccef8d2493686308172a9caee8a378ba7652d7714e298058c33aa082a59b");

        let plain = StorageRowStore::addr_hash(&addr, &[]);
        let with_trx = StorageRowStore::addr_hash(&addr, &trx);
        assert_ne!(plain, with_trx, "trxHash prefix must differ from plain");
        assert_eq!(plain, keccak256(addr.as_bytes()), "plain = sha3(address)");
        let mut merged = addr.as_bytes().to_vec();
        merged.extend_from_slice(&trx);
        assert_eq!(with_trx, keccak256(&merged), "create2 = sha3(address ++ trxHash)");

        // Empty trxHash must fall back to the plain prefix (java
        // `ByteUtil.isNullOrZeroArray` guard).
        assert_eq!(StorageRowStore::addr_hash(&addr, &[]), plain);

        // The fully-composed keys for the reserves slot (8, v2/raw) must differ.
        let mut slot8 = [0u8; 32];
        slot8[31] = 8;
        let k_plain = StorageRowStore::compose_key(&addr, &slot8);
        let k_trx = StorageRowStore::compose_key_with_addr_hash(&with_trx, &slot8, false);
        assert_ne!(k_plain, k_trx);
        // compose_key_with_addr_hash(plain) must equal the legacy compose_key.
        assert_eq!(
            StorageRowStore::compose_key_with_addr_hash(&plain, &slot8, false),
            k_plain
        );
    }
}
