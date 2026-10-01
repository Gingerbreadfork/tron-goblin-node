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
//! Under `ALLOW_OPTIMIZE_TVM_STORAGE` (proposal 99) a row moves to a 48-byte
//! key, `addr_hash[0..16] ++ keccak256(addr_hash ++ slot)` (java
//! `Storage.getNewRowKey`), which cannot alias another slot. Reads consult
//! the 48-byte key first and fall back to the 32-byte one; a row is migrated
//! to the 48-byte key the first time it is touched. A zero value is stored
//! under the 48-byte key rather than deleted.
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
/// Length of a storage-row key under `ALLOW_OPTIMIZE_TVM_STORAGE`.
pub const NEW_KEY_LEN: usize = 48;
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

    /// java `Storage.getNewRowKey`: the alias-free 48-byte key a slot uses
    /// once `ALLOW_OPTIMIZE_TVM_STORAGE` is active. The slot is never
    /// pre-hashed here, whatever the contract version.
    pub fn new_row_key(addr_hash: &[u8; 32], slot: &[u8; 32]) -> [u8; NEW_KEY_LEN] {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(addr_hash);
        buf[32..].copy_from_slice(slot);
        let mut out = [0u8; NEW_KEY_LEN];
        out[..PREFIX_BYTES].copy_from_slice(&addr_hash[..PREFIX_BYTES]);
        out[PREFIX_BYTES..].copy_from_slice(&keccak256(&buf));
        out
    }

    /// Read one slot the way java `Storage.getValue` resolves it on a fresh
    /// instance: under `optimized` the 48-byte row wins when present (even
    /// holding zero), otherwise the 32-byte row is consulted.
    pub fn read_slot(
        &self,
        addr_hash: &[u8; 32],
        slot: &[u8; 32],
        v1: bool,
        optimized: bool,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        if optimized {
            if let Some(v) = self.backend.get(&Self::new_row_key(addr_hash, slot))? {
                return Ok(Some(v));
            }
        }
        Ok(self
            .backend
            .get(&Self::compose_key_with_addr_hash(addr_hash, slot, v1))?)
    }

    pub fn put_raw(&self, key: &[u8], value: &[u8]) -> Result<(), StoreError> {
        self.backend.put(key, value)?;
        Ok(())
    }

    pub fn delete_raw(&self, key: &[u8]) -> Result<(), StoreError> {
        self.backend.delete(key)?;
        Ok(())
    }

    pub fn get_raw(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.backend.get(key)?)
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
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StoreError> {
        let prefix = keccak256(address.as_bytes());
        Ok(self
            .backend
            .scan_all()?
            .into_iter()
            .filter(|(k, _)| is_row_key(k) && k[..PREFIX_BYTES] == prefix[..PREFIX_BYTES])
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
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StoreError> {
        Ok(self
            .backend
            .scan_prefix(&addr_hash[..PREFIX_BYTES])?
            .into_iter()
            .filter(|(k, _)| is_row_key(k))
            .collect())
    }

    /// Like [`scan_prefix_by_addr_hash`](Self::scan_prefix_by_addr_hash) but
    /// **bounded**: returns at most `limit` rows, using the backend's bounded
    /// `scan_from` so the enumeration never materializes the whole contract.
    /// A contract's rows are the contiguous run of 32- and 48-byte keys sharing the
    /// 16-byte `addr_hash` prefix, so the walk stops at the first key that no
    /// longer shares it. Callers detect "more than N" by passing `limit = N+1`
    /// and checking whether `N+1` rows came back.
    pub fn scan_prefix_by_addr_hash_bounded(
        &self,
        addr_hash: &[u8; 32],
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StoreError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let prefix = &addr_hash[..PREFIX_BYTES];
        let mut out = Vec::new();
        for (k, v) in self.backend.scan_from(prefix, limit)? {
            if !is_row_key(&k) || k[..PREFIX_BYTES] != *prefix {
                break;
            }
            out.push((k, v));
        }
        Ok(out)
    }
}

/// Both row-key shapes: the 32-byte legacy key and the 48-byte optimized key.
fn is_row_key(key: &[u8]) -> bool {
    key.len() == KEY_LEN || key.len() == NEW_KEY_LEN
}

#[cfg(test)]
mod new_row_key_tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    fn addr(s: &str) -> Address {
        let mut raw = [0u8; 21];
        raw.copy_from_slice(&hex(s));
        Address::from_raw(raw)
    }

    fn word(s: &str) -> [u8; 32] {
        let mut w = [0u8; 32];
        w.copy_from_slice(&hex(s));
        w
    }

    // Vectors produced by java-tron 4.8.1.1 `Hash.sha3` / `Storage` key
    // composition under JDK 8.
    const VECTORS: &[(&str, &str, &str, &str, &str, &str, &str)] = &[
        (
            "41a614f803b6fd780986a42c78ec9c7f77e6ded13c",
            "",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "cad811d03c5eee60f3797f676630988a4f9abc58dbc0cb420ec882a989bd8885",
            "cad811d03c5eee60f3797f676630988a00000000000000000000000000000000",
            "cad811d03c5eee60f3797f676630988a4ba6bc95484008f6362f93160ef3e563",
            "cad811d03c5eee60f3797f676630988a5db97f9776e4b78b33accb7972f9b15c6edf305a9990b2c9e502711e0c0bbb8b",
        ),
        (
            "41a614f803b6fd780986a42c78ec9c7f77e6ded13c",
            "",
            "0000000000000000000000000000000000000000000000000000000000000005",
            "cad811d03c5eee60f3797f676630988a4f9abc58dbc0cb420ec882a989bd8885",
            "cad811d03c5eee60f3797f676630988a00000000000000000000000000000005",
            "cad811d03c5eee60f3797f676630988a0604c104a5fb6f4eb0703f3154bb3db0",
            "cad811d03c5eee60f3797f676630988aad67cbfaee02c16f0c6375e1f66cc97991d9ac9d0f5fdc9596b40ca08ae85a8d",
        ),
        (
            "41e9d79cc47518930bc322d9bf7cddd260a0260a8d",
            "7b2b6a1e3d8a4f6a5c2e1d0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b",
            "c2575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85b",
            "62a24db17124e35c634447b8ce336186caf4b36821a0679cf5a6471c7fe8b1fe",
            "62a24db17124e35c634447b8ce33618669c3395a3b0502d05e2516446f71f85b",
            "62a24db17124e35c634447b8ce336186617c003374de6eb4b295e823e5beab01",
            "62a24db17124e35c634447b8ce3361860499adbd36f1b9a9527e538dc784d5809f51ae619f590c16e992477651fadd00",
        ),
        (
            "41e9d79cc47518930bc322d9bf7cddd260a0260a8d",
            "7b2b6a1e3d8a4f6a5c2e1d0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b",
            "ffffffffffffffffffffffffffffffff00000000000000000000000000000005",
            "62a24db17124e35c634447b8ce336186caf4b36821a0679cf5a6471c7fe8b1fe",
            "62a24db17124e35c634447b8ce33618600000000000000000000000000000005",
            "62a24db17124e35c634447b8ce3361867668b8a6e8034d5995c9a0f1547a780d",
            "62a24db17124e35c634447b8ce336186409fae23075501a5da0cb26e06d15280de7c741728a516d8a637787f72b96b3a",
        ),
    ];

    #[test]
    fn keys_match_java_vectors() {
        for (address, trx, slot, addr_hash, old2, old1, new) in VECTORS {
            let a = addr(address);
            let ah = StorageRowStore::addr_hash(&a, &hex(trx));
            assert_eq!(ah.to_vec(), hex(addr_hash));
            let s = word(slot);
            assert_eq!(StorageRowStore::compose_key_with_addr_hash(&ah, &s, false).to_vec(), hex(old2));
            assert_eq!(StorageRowStore::compose_key_with_addr_hash(&ah, &s, true).to_vec(), hex(old1));
            assert_eq!(StorageRowStore::new_row_key(&ah, &s).to_vec(), hex(new));
        }
    }

    #[test]
    fn aliasing_slots_share_the_legacy_key_but_not_the_new_one() {
        let ah = StorageRowStore::addr_hash(&addr(VECTORS[2].0), &hex(VECTORS[2].1));
        let a = word("0000000000000000000000000000000000000000000000000000000000000005");
        let b = word(VECTORS[3].2);
        assert_eq!(
            StorageRowStore::compose_key_with_addr_hash(&ah, &a, false),
            StorageRowStore::compose_key_with_addr_hash(&ah, &b, false)
        );
        assert_ne!(StorageRowStore::new_row_key(&ah, &a), StorageRowStore::new_row_key(&ah, &b));
    }

    #[test]
    fn read_slot_prefers_the_new_row_under_optimized_mode() {
        use crate::MemBackend;
        use std::sync::Arc;
        let store = StorageRowStore::new(Arc::new(MemBackend::new()));
        let a = addr(VECTORS[0].0);
        let ah = StorageRowStore::addr_hash(&a, &[]);
        let slot = word(VECTORS[1].2);
        let old = StorageRowStore::compose_key_with_addr_hash(&ah, &slot, false);
        store.put(&old, &[7u8; 32]).unwrap();
        assert_eq!(store.read_slot(&ah, &slot, false, false).unwrap(), Some(vec![7u8; 32]));
        assert_eq!(store.read_slot(&ah, &slot, false, true).unwrap(), Some(vec![7u8; 32]));
        store.put_raw(&StorageRowStore::new_row_key(&ah, &slot), &[0u8; 32]).unwrap();
        assert_eq!(store.read_slot(&ah, &slot, false, true).unwrap(), Some(vec![0u8; 32]));
        assert_eq!(store.read_slot(&ah, &slot, false, false).unwrap(), Some(vec![7u8; 32]));
        let rows = store.scan_prefix_by_addr_hash(&ah).unwrap();
        assert_eq!(rows.len(), 2);
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
