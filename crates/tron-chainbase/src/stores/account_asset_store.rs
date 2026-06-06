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

use std::sync::{Arc, OnceLock};

use tron_crypto::address::{Address, ADDRESS_LENGTH};
use tron_proto::Account;

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME: &str = "account-asset";

/// Process-wide account-asset backend, mirroring java-tron's static
/// `AssetUtil.accountAssetStore` (installed once at `ChainBaseManager` init).
/// Lets consensus actuators merge an optimized account's TRC10 balances
/// without threading the store through every `StateBackends`/dispatch call —
/// java takes exactly this shortcut for the same reason.
static ACCOUNT_ASSET_BACKEND: OnceLock<Arc<dyn KvBackend>> = OnceLock::new();

/// Install the global account-asset backend (java-tron's
/// `AssetUtil.setAccountAssetStore`). Set once at node startup; subsequent
/// calls are ignored. Never set in unit tests, so [`import_all_asset`] stays
/// a no-op there.
pub fn set_account_asset_backend(backend: Arc<dyn KvBackend>) {
    let _ = ACCOUNT_ASSET_BACKEND.set(backend);
}

/// java-tron's `AssetUtil.importAllAsset`: when `account` is asset-optimized
/// and the global backend is installed, merge its TRC10 balances out of the
/// account-asset store back into `asset_v2` so reads/debits see the real
/// balance. No-op for non-optimized accounts and when no backend is set.
pub fn import_all_asset(account: &mut Account) {
    if !account.asset_optimized {
        return;
    }
    if let Some(backend) = ACCOUNT_ASSET_BACKEND.get() {
        AccountAssetStore::new(backend.clone()).import_all_asset(account);
    }
}

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

    /// java-tron's `AssetUtil.importAllAsset`: merge this account's TRC10
    /// balances out of the store back into `asset_v2` — store rows first,
    /// then inline entries override (so an in-flight modification kept inline
    /// wins). Gated on `asset_optimized`; otherwise the balances are already
    /// inline and there's nothing to merge.
    pub fn import_all_asset(&self, account: &mut Account) {
        if !account.asset_optimized || account.address.len() != ADDRESS_LENGTH {
            return;
        }
        let mut addr = [0u8; ADDRESS_LENGTH];
        addr.copy_from_slice(&account.address);
        let owner = Address::from_raw(addr);
        let Ok(rows) = self.get_all_assets(&owner) else {
            return;
        };
        let mut merged: std::collections::BTreeMap<String, i64> = rows
            .into_iter()
            .map(|(id, bal)| (String::from_utf8_lossy(&id).into_owned(), bal))
            .collect();
        for (k, v) in &account.asset_v2 {
            merged.insert(k.clone(), *v);
        }
        account.asset_v2 = merged;
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
