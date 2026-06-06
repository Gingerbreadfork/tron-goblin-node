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

    pub fn put_raw(&self, key: &[u8], resource: &DelegatedResource) -> Result<(), StoreError> {
        self.backend.put(key, &resource.encode_to_vec())?;
        Ok(())
    }

    pub fn get_raw(&self, key: &[u8]) -> Result<Option<DelegatedResource>, StoreError> {
        let Some(bytes) = self.backend.get(key)? else {
            return Ok(None);
        };
        Ok(Some(DelegatedResource::decode(bytes.as_slice())?))
    }

    pub fn delete_raw(&self, key: &[u8]) -> Result<(), StoreError> {
        self.backend.delete(key)?;
        Ok(())
    }

    /// Fold an *expired* locked delegation into the unlocked record for
    /// `(from, to)` — a direct port of java-tron's
    /// `DelegatedResourceStore.unLockExpireResource`.
    ///
    /// A `DelegateResourceContract` with `lock = true` is stored under the
    /// locked key (`0x02`) with a per-resource expiry. Once `now` passes
    /// that expiry the frozen balance becomes undelegate-able, but only
    /// after it's moved into the unlocked record (`0x01`) — which is the
    /// record an undelegate actually draws from. No-op when there's no
    /// locked record or neither resource has expired yet.
    ///
    /// Without this merge an undelegate of a once-locked (now-expired)
    /// delegation fails with "nothing to undelegate": a mempool-reject
    /// flood and, in block execution, a SILENT state divergence from
    /// java-tron — TRON block headers carry no state root, so a wrong
    /// delegated-resource balance never surfaces as a block-hash mismatch.
    pub fn unlock_expire_resource(
        &self,
        from: &Address,
        to: &Address,
        now: i64,
    ) -> Result<(), StoreError> {
        let lock_key = Self::v2_locked_key(from, to);
        let Some(mut lock) = self.get_raw(&lock_key)? else {
            return Ok(());
        };
        // Neither resource's lock has expired → nothing to move.
        if lock.expire_time_for_energy >= now && lock.expire_time_for_bandwidth >= now {
            return Ok(());
        }
        let unlock_key = Self::v2_unlocked_key(from, to);
        let mut unlock = self.get_raw(&unlock_key)?.unwrap_or_else(|| DelegatedResource {
            from: from.as_bytes().to_vec(),
            to: to.as_bytes().to_vec(),
            ..Default::default()
        });
        if lock.expire_time_for_energy < now {
            unlock.frozen_balance_for_energy += lock.frozen_balance_for_energy;
            unlock.expire_time_for_energy = 0;
            lock.frozen_balance_for_energy = 0;
            lock.expire_time_for_energy = 0;
        }
        if lock.expire_time_for_bandwidth < now {
            unlock.frozen_balance_for_bandwidth += lock.frozen_balance_for_bandwidth;
            unlock.expire_time_for_bandwidth = 0;
            lock.frozen_balance_for_bandwidth = 0;
            lock.expire_time_for_bandwidth = 0;
        }
        if lock.frozen_balance_for_bandwidth == 0 && lock.frozen_balance_for_energy == 0 {
            self.delete_raw(&lock_key)?;
        } else {
            self.put_raw(&lock_key, &lock)?;
        }
        self.put_raw(&unlock_key, &unlock)?;
        Ok(())
    }

    /// Return every V1 delegation row where `from` is the sender.
    /// Mirrors java-tron's iteration pattern (no dedicated
    /// `getByFrom` method in upstream; the prefix walk is open-coded
    /// at every call site there).
    ///
    /// V1 keys are 42 bytes (`from || to`) with no leading prefix
    /// byte, so we scan with `from.as_bytes()` as the prefix. Skips
    /// rows that decode as malformed `DelegatedResource`.
    pub fn get_by_from_v1(&self, from: &Address) -> Result<Vec<DelegatedResource>, StoreError> {
        Ok(self
            .backend
            .scan_prefix(from.as_bytes())?
            .into_iter()
            // Defensive: skip any row whose key isn't a V1 entry shape.
            // V2 entries have a 1-byte prefix so they wouldn't start
            // with a 21-byte address — but be explicit.
            .filter(|(k, _)| k.len() == ADDRESS_LENGTH * 2)
            .filter_map(|(k, v)| match DelegatedResource::decode(v.as_slice()) {
                Ok(d) => Some(d),
                Err(e) => {
                    // C-8: a V1-shaped key whose value won't decode is
                    // corruption — log instead of silently dropping it.
                    tracing::error!(
                        store = "DelegatedResource",
                        key = %hex::encode(&k),
                        error = %e,
                        "skipping undecodable DelegatedResource V1 row"
                    );
                    None
                }
            })
            .collect())
    }

    /// V2 variant — returns rows under either the locked or unlocked
    /// prefix that match `from`. Used by `Wallet.getDelegatedResourceV2`.
    pub fn get_by_from_v2(&self, from: &Address) -> Result<Vec<DelegatedResource>, StoreError> {
        let mut out = Vec::new();
        for prefix_byte in [V2_PREFIX_UNLOCKED, V2_PREFIX_LOCKED] {
            let mut prefix = Vec::with_capacity(1 + ADDRESS_LENGTH);
            prefix.push(prefix_byte);
            prefix.extend_from_slice(from.as_bytes());
            for (k, v) in self.backend.scan_prefix(&prefix)? {
                if k.len() != 1 + ADDRESS_LENGTH * 2 {
                    continue;
                }
                match DelegatedResource::decode(v.as_slice()) {
                    Ok(d) => out.push(d),
                    Err(e) => tracing::error!(
                        store = "DelegatedResource",
                        key = %hex::encode(&k),
                        error = %e,
                        "skipping undecodable DelegatedResource V2 row"
                    ),
                }
            }
        }
        Ok(out)
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
        )
        .unwrap();
        store.put_raw(
            &DelegatedResourceStore::v1_key(&alice, &charlie),
            &DelegatedResource {
                from: alice.as_bytes().to_vec(),
                to: charlie.as_bytes().to_vec(),
                frozen_balance_for_bandwidth: 200,
                ..Default::default()
            },
        )
        .unwrap();
        // Bob also delegates to charlie — must NOT appear in alice's results.
        store.put_raw(
            &DelegatedResourceStore::v1_key(&bob, &charlie),
            &DelegatedResource {
                from: bob.as_bytes().to_vec(),
                to: charlie.as_bytes().to_vec(),
                frozen_balance_for_bandwidth: 999,
                ..Default::default()
            },
        )
        .unwrap();
        let rows = store.get_by_from_v1(&alice).unwrap();
        assert_eq!(rows.len(), 2);
        let amounts: Vec<i64> = rows
            .iter()
            .map(|d| d.frozen_balance_for_bandwidth)
            .collect();
        assert!(amounts.contains(&100));
        assert!(amounts.contains(&200));
        assert!(!amounts.contains(&999));
    }

    #[test]
    fn unlock_expire_resource_merges_only_expired_resources() {
        let store = DelegatedResourceStore::new(Arc::new(MemBackend::new()));
        let from = addr(0xaa);
        let to = addr(0xbb);
        // Locked: energy expired (100 < now), bandwidth still locked (900 > now).
        store
            .put_raw(
                &DelegatedResourceStore::v2_locked_key(&from, &to),
                &DelegatedResource {
                    from: from.as_bytes().to_vec(),
                    to: to.as_bytes().to_vec(),
                    frozen_balance_for_bandwidth: 50,
                    frozen_balance_for_energy: 70,
                    expire_time_for_bandwidth: 900,
                    expire_time_for_energy: 100,
                    ..Default::default()
                },
            )
            .unwrap();

        store.unlock_expire_resource(&from, &to, 500).unwrap();

        // Energy (expired) moved to the unlocked record; bandwidth stayed locked.
        let unlocked = store
            .get_raw(&DelegatedResourceStore::v2_unlocked_key(&from, &to))
            .unwrap()
            .expect("unlocked record created");
        assert_eq!(unlocked.frozen_balance_for_energy, 70);
        assert_eq!(unlocked.frozen_balance_for_bandwidth, 0);
        let locked = store
            .get_raw(&DelegatedResourceStore::v2_locked_key(&from, &to))
            .unwrap()
            .expect("locked record persists (bandwidth still locked)");
        assert_eq!(locked.frozen_balance_for_energy, 0);
        assert_eq!(locked.frozen_balance_for_bandwidth, 50);
    }

    #[test]
    fn unlock_expire_resource_is_a_noop_when_nothing_expired() {
        let store = DelegatedResourceStore::new(Arc::new(MemBackend::new()));
        let from = addr(0xaa);
        let to = addr(0xbb);
        // BOTH expiries must be >= now to hit the early return — matching
        // java-tron, a zero expire_time counts as "expired" (it merges a
        // zero balance), so set both explicitly.
        store
            .put_raw(
                &DelegatedResourceStore::v2_locked_key(&from, &to),
                &DelegatedResource {
                    from: from.as_bytes().to_vec(),
                    to: to.as_bytes().to_vec(),
                    frozen_balance_for_bandwidth: 50,
                    frozen_balance_for_energy: 70,
                    expire_time_for_bandwidth: 900,
                    expire_time_for_energy: 900,
                    ..Default::default()
                },
            )
            .unwrap();
        // now=500 < both expiries → no merge, no unlocked record created.
        store.unlock_expire_resource(&from, &to, 500).unwrap();
        assert!(store
            .get_raw(&DelegatedResourceStore::v2_unlocked_key(&from, &to))
            .unwrap()
            .is_none());
        assert!(store
            .get_raw(&DelegatedResourceStore::v2_locked_key(&from, &to))
            .unwrap()
            .is_some());
    }
}
