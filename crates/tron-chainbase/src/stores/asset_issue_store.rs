//! AssetIssueStore (`asset-issue`) + AssetIssueV2Store (`asset-issue-v2`).
//!
//! **The V1/V2 split is the key encoding, not the value encoding.**
//! Both stores hold protobuf-encoded `AssetIssueContract` messages, but
//! the lookup key differs:
//!
//! * V1 (legacy): key is the asset's **name** (UTF-8 bytes of
//!   `AssetIssueContract.name`).
//! * V2 (current): key is the asset's **ID** (UTF-8 bytes of
//!   `AssetIssueContract.id`, a decimal string of the numeric token id).
//!
//! Source: `AssetIssueStore` / `AssetIssueV2Store` +
//! `AssetIssueCapsule.createDbV2Key` (= `ByteArray.fromString(getId())`).

use std::sync::Arc;

use prost::Message;
use tron_proto::AssetIssueContract;

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME_V1: &str = "asset-issue";
pub const DB_NAME_V2: &str = "asset-issue-v2";

pub struct AssetIssueStore {
    backend: Arc<dyn KvBackend>,
}

impl AssetIssueStore {
    pub const DB_NAME: &'static str = DB_NAME_V1;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    /// `put(name_bytes, asset)` — the key is the raw asset name.
    pub fn put(&self, name: &[u8], asset: &AssetIssueContract) -> Result<(), StoreError> {
        self.backend.put(name, &asset.encode_to_vec())?;
        Ok(())
    }

    pub fn get(&self, name: &[u8]) -> Result<Option<AssetIssueContract>, StoreError> {
        let Some(bytes) = self.backend.get(name)? else {
            return Ok(None);
        };
        Ok(Some(AssetIssueContract::decode(bytes.as_slice())?))
    }

    /// Snapshot every entry. Used by RPC list-by-name endpoints when
    /// the request name is empty (meaning "all of them") or for
    /// prefix-style scans. Returns `(name_bytes, asset)` pairs.
    pub fn all(&self) -> Result<Vec<(Vec<u8>, AssetIssueContract)>, StoreError> {
        let mut out = Vec::new();
        for (k, v) in self.backend.scan_all()? {
            let asset = AssetIssueContract::decode(v.as_slice())?;
            out.push((k, asset));
        }
        Ok(out)
    }
}

pub struct AssetIssueV2Store {
    backend: Arc<dyn KvBackend>,
}

impl AssetIssueV2Store {
    pub const DB_NAME: &'static str = DB_NAME_V2;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    /// `put(id, asset)` — key is the decimal-string id of the asset
    /// encoded as UTF-8 bytes (e.g. id `1000001` → `b"1000001"`).
    pub fn put(&self, id: i64, asset: &AssetIssueContract) -> Result<(), StoreError> {
        let key = id.to_string();
        self.backend.put(key.as_bytes(), &asset.encode_to_vec())?;
        Ok(())
    }

    pub fn get(&self, id: i64) -> Result<Option<AssetIssueContract>, StoreError> {
        let key = id.to_string();
        let Some(bytes) = self.backend.get(key.as_bytes())? else {
            return Ok(None);
        };
        Ok(Some(AssetIssueContract::decode(bytes.as_slice())?))
    }

    /// Build the canonical V2 key for `id`. Exposed so callers can
    /// inspect the on-disk key shape without going through put/get.
    pub fn key_for(id: i64) -> Vec<u8> {
        id.to_string().into_bytes()
    }

    /// Enumerate every asset. Returns `(decoded_id, asset)` pairs.
    pub fn all(&self) -> Result<Vec<(i64, AssetIssueContract)>, StoreError> {
        let mut out = Vec::new();
        for (k, v) in self.backend.scan_all()? {
            let Ok(id_str) = std::str::from_utf8(&k) else {
                // C-8: V2 asset keys are decimal-id UTF-8 strings; a
                // non-UTF-8 key is corruption. Log, then skip.
                tracing::error!(
                    store = "asset-issue-v2",
                    key = %hex::encode(&k),
                    "skipping asset row with non-UTF-8 key"
                );
                continue;
            };
            let Ok(id) = id_str.parse::<i64>() else {
                tracing::error!(
                    store = "asset-issue-v2",
                    key = %id_str,
                    "skipping asset row whose key isn't a decimal i64 id"
                );
                continue;
            };
            let asset = AssetIssueContract::decode(v.as_slice())?;
            out.push((id, asset));
        }
        Ok(out)
    }
}
