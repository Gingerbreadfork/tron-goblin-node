//! DelegatedResourceStore — directory name `DelegatedResource`.
//!
//! Holds per-(from, to) resource-delegation records (TRX frozen for
//! bandwidth/energy and delegated to another account). The store has
//! **three coexisting key formats** that callers must distinguish by
//! length and leading byte:
//!
//! | Format        | Length | Prefix    | Payload                |
//! |---------------|--------|-----------|------------------------|
//! | V1 (legacy)   | 42     | none      | `from(21) ‖ to(21)`    |
//! | V2 unlocked   | 43     | `0x01`    | `from(21) ‖ to(21)`    |
//! | V2 locked     | 43     | `0x02`    | `from(21) ‖ to(21)`    |
//!
//! **Trap**: the prefix bytes `0x01` and `0x02` in this store have
//! totally different meanings than `0x01..0x04` in
//! [`super::DelegatedResourceAccountIndexStore`]. Each store has its own
//! keyspace, so they don't collide, but a hand-written tool that pokes
//! into multiple stores must interpret the prefix per-store.
//!
//! Source: `DelegatedResourceStore` + `DelegatedResourceCapsule.createDbKey*`.

use std::sync::Arc;

use prost::Message;
use tron_crypto::address::{Address, ADDRESS_LENGTH};
use tron_proto::DelegatedResource;

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME: &str = "DelegatedResource";

/// V2 unlocked-prefix byte. **Distinct meaning** from the same byte in
/// `DelegatedResourceAccountIndexStore`.
pub const V2_PREFIX_UNLOCKED: u8 = 0x01;
/// V2 locked-prefix byte (resource is time-locked).
pub const V2_PREFIX_LOCKED: u8 = 0x02;

pub struct DelegatedResourceStore {
    backend: Arc<dyn KvBackend>,
}

impl DelegatedResourceStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    // -------------------- Key builders --------------------------------

    /// V1 (legacy) key: `from || to` — 42 bytes, no prefix.
    pub fn v1_key(from: &Address, to: &Address) -> [u8; ADDRESS_LENGTH * 2] {
        let mut out = [0u8; ADDRESS_LENGTH * 2];
        out[..ADDRESS_LENGTH].copy_from_slice(from.as_bytes());
        out[ADDRESS_LENGTH..].copy_from_slice(to.as_bytes());
        out
    }

    /// V2 key with the unlocked-prefix byte.
    pub fn v2_unlocked_key(from: &Address, to: &Address) -> [u8; 1 + ADDRESS_LENGTH * 2] {
        Self::v2_key(V2_PREFIX_UNLOCKED, from, to)
    }

    /// V2 key with the locked-prefix byte.
    pub fn v2_locked_key(from: &Address, to: &Address) -> [u8; 1 + ADDRESS_LENGTH * 2] {
        Self::v2_key(V2_PREFIX_LOCKED, from, to)
    }

    fn v2_key(prefix: u8, from: &Address, to: &Address) -> [u8; 1 + ADDRESS_LENGTH * 2] {
        let mut out = [0u8; 1 + ADDRESS_LENGTH * 2];
        out[0] = prefix;
        out[1..1 + ADDRESS_LENGTH].copy_from_slice(from.as_bytes());
        out[1 + ADDRESS_LENGTH..].copy_from_slice(to.as_bytes());
        out
    }

    // -------------------- CRUD ----------------------------------------

    pub fn put_raw(&self, key: &[u8], resource: &DelegatedResource) {
        self.backend.put(key, &resource.encode_to_vec());
    }

    pub fn get_raw(&self, key: &[u8]) -> Result<Option<DelegatedResource>, StoreError> {
        let Some(bytes) = self.backend.get(key) else {
            return Ok(None);
        };
        Ok(Some(DelegatedResource::decode(bytes.as_slice())?))
    }

    pub fn delete_raw(&self, key: &[u8]) {
        self.backend.delete(key);
    }

    /// Return every V1 delegation row where `from` is the sender.
    /// Mirrors java-tron's iteration pattern (no dedicated
    /// `getByFrom` method in upstream; the prefix walk is open-coded
    /// at every call site there).
    ///
    /// V1 keys are 42 bytes (`from || to`) with no leading prefix
    /// byte, so we scan with `from.as_bytes()` as the prefix. Skips
    /// rows that decode as malformed `DelegatedResource`.
    pub fn get_by_from_v1(&self, from: &Address) -> Vec<DelegatedResource> {
        self.backend
            .scan_prefix(from.as_bytes())
            .into_iter()
            // Defensive: skip any row whose key isn't a V1 entry shape.
            // V2 entries have a 1-byte prefix so they wouldn't start
            // with a 21-byte address — but be explicit.
            .filter(|(k, _)| k.len() == ADDRESS_LENGTH * 2)
            .filter_map(|(_, v)| DelegatedResource::decode(v.as_slice()).ok())
            .collect()
    }

    /// V2 variant — returns rows under either the locked or unlocked
    /// prefix that match `from`. Used by `Wallet.getDelegatedResourceV2`.
    pub fn get_by_from_v2(&self, from: &Address) -> Vec<DelegatedResource> {
        let mut out = Vec::new();
        for prefix_byte in [V2_PREFIX_UNLOCKED, V2_PREFIX_LOCKED] {
            let mut prefix = Vec::with_capacity(1 + ADDRESS_LENGTH);
            prefix.push(prefix_byte);
            prefix.extend_from_slice(from.as_bytes());
            for (k, v) in self.backend.scan_prefix(&prefix) {
                if k.len() != 1 + ADDRESS_LENGTH * 2 {
                    continue;
                }
                if let Ok(d) = DelegatedResource::decode(v.as_slice()) {
                    out.push(d);
                }
            }
        }
        out
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
    fn get_by_from_v1_returns_only_matching_sender() {
        let backend: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
        let store = DelegatedResourceStore::new(backend);
        let alice = addr(0xaa);
        let bob = addr(0xbb);
        let charlie = addr(0xcc);
        store.put_raw(
            &DelegatedResourceStore::v1_key(&alice, &bob),
            &DelegatedResource {
                from: alice.as_bytes().to_vec(),
                to: bob.as_bytes().to_vec(),
                frozen_balance_for_bandwidth: 100,
                ..Default::default()
            },
        );
        store.put_raw(
            &DelegatedResourceStore::v1_key(&alice, &charlie),
            &DelegatedResource {
                from: alice.as_bytes().to_vec(),
                to: charlie.as_bytes().to_vec(),
                frozen_balance_for_bandwidth: 200,
                ..Default::default()
            },
        );
        // Bob also delegates to charlie — must NOT appear in alice's results.
        store.put_raw(
            &DelegatedResourceStore::v1_key(&bob, &charlie),
            &DelegatedResource {
                from: bob.as_bytes().to_vec(),
                to: charlie.as_bytes().to_vec(),
                frozen_balance_for_bandwidth: 999,
                ..Default::default()
            },
        );
        let rows = store.get_by_from_v1(&alice);
        assert_eq!(rows.len(), 2);
        let amounts: Vec<i64> = rows
            .iter()
            .map(|d| d.frozen_balance_for_bandwidth)
            .collect();
        assert!(amounts.contains(&100));
        assert!(amounts.contains(&200));
        assert!(!amounts.contains(&999));
    }
}
