//! DelegatedResourceAccountIndexStore — directory name
//! `DelegatedResourceAccountIndex`.
//!
//! A bidirectional index over delegations. Every delegate operation
//! writes **two** rows so that both ends of the (from, to) pair can be
//! looked up:
//!
//! | Side        | Prefix | Key payload          | Value           |
//! |-------------|--------|----------------------|-----------------|
//! | V1 FROM     | `0x01` | `from(21) ‖ to(21)`  | `to` + timestamp|
//! | V1 TO       | `0x02` | `to(21) ‖ from(21)`  | `from` + ts     |
//! | V2 FROM     | `0x03` | `from(21) ‖ to(21)`  | `to` + ts       |
//! | V2 TO       | `0x04` | `to(21) ‖ from(21)`  | `from` + ts     |
//!
//! There is also a **legacy** format: a 21-byte raw-address key with a
//! `DelegatedResourceAccountIndex` value holding aggregated `fromAccounts`
//! and `toAccounts` lists. `DelegatedResourceAccountIndexStore.convert`
//! migrates those to the prefixed form. Reads should accept both during
//! the migration window.
//!
//! Source: `DelegatedResourceAccountIndexStore`.

use std::sync::Arc;

use prost::Message;
use tron_crypto::address::{Address, ADDRESS_LENGTH};
use tron_proto::DelegatedResourceAccountIndex;

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME: &str = "DelegatedResourceAccountIndex";

/// V1 FROM-side prefix.
pub const V1_FROM_PREFIX: u8 = 0x01;
/// V1 TO-side prefix.
pub const V1_TO_PREFIX: u8 = 0x02;
/// V2 FROM-side prefix.
pub const V2_FROM_PREFIX: u8 = 0x03;
/// V2 TO-side prefix.
pub const V2_TO_PREFIX: u8 = 0x04;

pub struct DelegatedResourceAccountIndexStore {
    backend: Arc<dyn KvBackend>,
}

impl DelegatedResourceAccountIndexStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    // -------------------- Key builders --------------------------------

    /// V1 FROM key: `[0x01, from(21), to(21)]`. Pairs with [`v1_to_key`]
    /// — both are written on every V1 delegation.
    pub fn v1_from_key(from: &Address, to: &Address) -> [u8; 1 + ADDRESS_LENGTH * 2] {
        prefixed_pair(V1_FROM_PREFIX, from, to)
    }

    /// V1 TO key: `[0x02, to(21), from(21)]`. Note the swapped order.
    pub fn v1_to_key(from: &Address, to: &Address) -> [u8; 1 + ADDRESS_LENGTH * 2] {
        prefixed_pair(V1_TO_PREFIX, to, from)
    }

    pub fn v2_from_key(from: &Address, to: &Address) -> [u8; 1 + ADDRESS_LENGTH * 2] {
        prefixed_pair(V2_FROM_PREFIX, from, to)
    }

    pub fn v2_to_key(from: &Address, to: &Address) -> [u8; 1 + ADDRESS_LENGTH * 2] {
        prefixed_pair(V2_TO_PREFIX, to, from)
    }

    /// Legacy: aggregated index keyed by a raw 21-byte address.
    pub fn legacy_key(addr: &Address) -> [u8; ADDRESS_LENGTH] {
        *addr.as_bytes()
    }

    // -------------------- CRUD ----------------------------------------

    pub fn put_raw(
        &self,
        key: &[u8],
        index: &DelegatedResourceAccountIndex,
    ) -> Result<(), StoreError> {
        self.backend.put(key, &index.encode_to_vec())?;
        Ok(())
    }

    pub fn get_raw(
        &self,
        key: &[u8],
    ) -> Result<Option<DelegatedResourceAccountIndex>, StoreError> {
        let Some(bytes) = self.backend.get(key)? else {
            return Ok(None);
        };
        Ok(Some(DelegatedResourceAccountIndex::decode(bytes.as_slice())?))
    }

    pub fn delete_raw(&self, key: &[u8]) -> Result<(), StoreError> {
        self.backend.delete(key)?;
        Ok(())
    }

    // -------------------- V2 delegate/undelegate ----------------------

    /// java-tron `DelegatedResourceAccountIndexStore.delegateV2` — write
    /// the bidirectional V2 index rows for a `from → to` delegation. The
    /// from-side row (`0x03 ‖ from ‖ to`) holds the counterparty `to`; the
    /// to-side row (`0x04 ‖ to ‖ from`) holds `from`. Both stamp `time`.
    /// Overwrites any existing rows (java-tron `put`).
    pub fn delegate_v2(
        &self,
        from: &Address,
        to: &Address,
        time: i64,
    ) -> Result<(), StoreError> {
        self.put_raw(
            &Self::v2_from_key(from, to),
            &DelegatedResourceAccountIndex {
                account: to.as_bytes().to_vec(),
                timestamp: time,
                ..Default::default()
            },
        )?;
        self.put_raw(
            &Self::v2_to_key(from, to),
            &DelegatedResourceAccountIndex {
                account: from.as_bytes().to_vec(),
                timestamp: time,
                ..Default::default()
            },
        )?;
        Ok(())
    }

    /// java-tron `DelegatedResourceAccountIndexStore.unDelegateV2` — drop
    /// both V2 index rows once a `from → to` delegation is fully gone.
    pub fn undelegate_v2(&self, from: &Address, to: &Address) -> Result<(), StoreError> {
        self.delete_raw(&Self::v2_from_key(from, to))?;
        self.delete_raw(&Self::v2_to_key(from, to))?;
        Ok(())
    }

    // -------------------- V1 delegate/undelegate ----------------------

    /// java-tron `delegateV1` — write the bidirectional V1 index rows for
    /// a legacy `from → to` delegation.
    pub fn delegate_v1(&self, from: &Address, to: &Address, time: i64) -> Result<(), StoreError> {
        self.put_raw(
            &Self::v1_from_key(from, to),
            &DelegatedResourceAccountIndex {
                account: to.as_bytes().to_vec(),
                timestamp: time,
                ..Default::default()
            },
        )?;
        self.put_raw(
            &Self::v1_to_key(from, to),
            &DelegatedResourceAccountIndex {
                account: from.as_bytes().to_vec(),
                timestamp: time,
                ..Default::default()
            },
        )?;
        Ok(())
    }

    /// java-tron `unDelegateV1` — drop both V1 index rows.
    pub fn undelegate_v1(&self, from: &Address, to: &Address) -> Result<(), StoreError> {
        self.delete_raw(&Self::v1_from_key(from, to))?;
        self.delete_raw(&Self::v1_to_key(from, to))?;
        Ok(())
    }

    /// java-tron `convert(address)` — migrate the LEGACY aggregated index
    /// row (bare 21-byte key holding `from_accounts` / `to_accounts`
    /// lists) into the per-pair prefixed form, then delete the legacy
    /// row. A missing legacy row means "already converted or never
    /// delegated" — no-op. Pair timestamps use the list position (i + 1),
    /// exactly as java does, "just to keep index in order".
    pub fn convert(&self, address: &Address) -> Result<(), StoreError> {
        let Some(legacy) = self.get_raw(&Self::legacy_key(address))? else {
            return Ok(());
        };
        let addr_of = |raw: &[u8]| -> Option<Address> {
            if raw.len() != ADDRESS_LENGTH {
                return None;
            }
            let mut buf = [0u8; ADDRESS_LENGTH];
            buf.copy_from_slice(raw);
            Some(Address::from_raw(buf))
        };
        for (i, to) in legacy.to_accounts.iter().enumerate() {
            if let Some(to) = addr_of(to) {
                self.delegate_v1(address, &to, (i + 1) as i64)?;
            }
        }
        for (i, from) in legacy.from_accounts.iter().enumerate() {
            if let Some(from) = addr_of(from) {
                self.delegate_v1(&from, address, (i + 1) as i64)?;
            }
        }
        self.delete_raw(&Self::legacy_key(address))?;
        Ok(())
    }
}

fn prefixed_pair(prefix: u8, a: &Address, b: &Address) -> [u8; 1 + ADDRESS_LENGTH * 2] {
    let mut out = [0u8; 1 + ADDRESS_LENGTH * 2];
    out[0] = prefix;
    out[1..1 + ADDRESS_LENGTH].copy_from_slice(a.as_bytes());
    out[1 + ADDRESS_LENGTH..].copy_from_slice(b.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MemBackend;

    fn addr(b: u8) -> Address {
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[1..].fill(b);
        Address::from_raw(a)
    }

    #[test]
    fn delegate_v2_writes_both_sides_and_undelegate_v2_clears_them() {
        let store = DelegatedResourceAccountIndexStore::new(Arc::new(MemBackend::new()));
        let from = addr(0xaa);
        let to = addr(0xbb);

        store.delegate_v2(&from, &to, 1_234).unwrap();
        // From-side row (0x03 ‖ from ‖ to) holds the counterparty `to`.
        let from_row = store
            .get_raw(&DelegatedResourceAccountIndexStore::v2_from_key(&from, &to))
            .unwrap()
            .expect("from-side row");
        assert_eq!(from_row.account, to.as_bytes().to_vec());
        assert_eq!(from_row.timestamp, 1_234);
        // To-side row (0x04 ‖ to ‖ from) holds `from`.
        let to_row = store
            .get_raw(&DelegatedResourceAccountIndexStore::v2_to_key(&from, &to))
            .unwrap()
            .expect("to-side row");
        assert_eq!(to_row.account, from.as_bytes().to_vec());

        store.undelegate_v2(&from, &to).unwrap();
        assert!(store
            .get_raw(&DelegatedResourceAccountIndexStore::v2_from_key(&from, &to))
            .unwrap()
            .is_none());
        assert!(store
            .get_raw(&DelegatedResourceAccountIndexStore::v2_to_key(&from, &to))
            .unwrap()
            .is_none());
    }
}
