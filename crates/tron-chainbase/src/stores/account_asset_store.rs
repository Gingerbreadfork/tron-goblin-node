//! AccountAssetStore — directory name `account-asset`.
//!
//! Per-account TRC-10 asset balances, split out of `AccountStore` for
//! storage efficiency. Each row is one `(owner_address, asset_id) →
//! balance` entry; what's logically `Map<asset_id, balance>` inside an
//! Account becomes a flat namespace of composite-keyed rows.
//!
//! Key:   `address(21) ‖ asset_id_bytes` (variable length).
//!        java-tron computes `Bytes.concat(account.getAddress().toByteArray(),
//!        k.getBytes())` where `k` is the asset-id string.
//! Value: 8-byte BE `i64` balance (sun-denominated).
//!
//! Source: `org.tron.core.store.AccountAssetStore`.

use std::sync::Arc;

use tron_crypto::address::Address;

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME: &str = "account-asset";

pub struct AccountAssetStore {
    backend: Arc<dyn KvBackend>,
}

impl AccountAssetStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    /// Build the composite key `address ‖ asset_id_bytes` (asset id is
    /// the UTF-8 bytes of the decimal-string token id, just like
    /// [`super::AssetIssueV2Store`]).
    pub fn key_for(address: &Address, asset_id: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(address.as_bytes().len() + asset_id.len());
        out.extend_from_slice(address.as_bytes());
        out.extend_from_slice(asset_id);
        out
    }

    pub fn put(&self, address: &Address, asset_id: &[u8], balance: i64) -> Result<(), StoreError> {
        let key = Self::key_for(address, asset_id);
        self.backend.put(&key, &balance.to_be_bytes())?;
        Ok(())
    }

    pub fn get(&self, address: &Address, asset_id: &[u8]) -> Result<Option<i64>, StoreError> {
        let key = Self::key_for(address, asset_id);
        let Some(bytes) = self.backend.get(&key)? else {
            return Ok(None);
        };
        if bytes.len() != 8 {
            return Err(StoreError::InvalidValueLength {
                got: bytes.len(),
                expected: 8,
            });
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes);
        Ok(Some(i64::from_be_bytes(buf)))
    }

    /// Return every `(asset_id, balance)` row for the given owner.
    /// Mirrors java-tron's
    /// `AccountAssetStore.getAllAssets(byte[] owner_address)` (which
    /// uses a prefix scan over the address bytes). Used by
    /// `Wallet.getAccount` to populate the `asset_v2` map and by the
    /// account-deletion path to enumerate every row to remove.
    ///
    /// Skips rows whose value isn't exactly 8 bytes (corrupted entries
    /// log + continue, matching java-tron).
    pub fn get_all_assets(&self, owner: &Address) -> Result<Vec<(Vec<u8>, i64)>, StoreError> {
        Ok(self
            .backend
            .scan_prefix(owner.as_bytes())?
            .into_iter()
            .filter_map(|(k, v)| {
                if v.len() != 8 {
                    // C-8: asset balances are i64 (8 bytes); any other
                    // length is corruption. Log + continue (java-tron
                    // parity) — as the doc-comment above already promises.
                    tracing::error!(
                        store = "account-asset",
                        key = %hex::encode(&k),
                        value_len = v.len(),
                        "skipping account-asset row whose value isn't an 8-byte balance"
                    );
                    return None;
                }
                // Strip the 21-byte address prefix to leave the
                // asset_id portion of the composite key.
                let asset_id = k.get(owner.as_bytes().len()..)?.to_vec();
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&v);
                Some((asset_id, i64::from_be_bytes(buf)))
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MemBackend;
    use std::sync::Arc;

    fn addr(byte: u8) -> Address {
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[1..].fill(byte);
        Address::from_raw(a)
    }

    #[test]
    fn get_all_assets_returns_only_target_owner() {
        let backend: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
        let store = AccountAssetStore::new(backend);
        let alice = addr(0xaa);
        let bob = addr(0xbb);
        store.put(&alice, b"1000001", 100).unwrap();
        store.put(&alice, b"1000002", 200).unwrap();
        store.put(&bob, b"1000003", 300).unwrap();
        let alice_assets = store.get_all_assets(&alice).unwrap();
        assert_eq!(alice_assets.len(), 2);
        let mut found = alice_assets
            .iter()
            .map(|(id, bal)| (String::from_utf8_lossy(id).to_string(), *bal))
            .collect::<Vec<_>>();
        found.sort();
        assert_eq!(
            found,
            vec![("1000001".to_string(), 100), ("1000002".to_string(), 200)]
        );
    }

    #[test]
    fn get_all_assets_empty_for_unknown_owner() {
        let backend: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
        let store = AccountAssetStore::new(backend);
        assert!(store.get_all_assets(&addr(0xff)).unwrap().is_empty());
    }
}
