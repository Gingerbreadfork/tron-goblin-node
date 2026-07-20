//! `DelegatedResourceAccountIndexStore` write lifecycle, pinned against
//! java-tron's `org.tron.core.db.DelegatedResourceAccountIndexStoreTest`.
//!
//! The store keeps a **bidirectional** index: each delegation writes two rows,
//! one under the from-side prefix and one under the to-side prefix, and the
//! to-side row stores the address pair in **swapped** order. Both rows carry
//! the same timestamp, which is what `getIndex` sorts the returned account
//! lists by. Getting the prefix byte or the address order wrong would make the
//! delegation invisible from one direction while still occupying disk in the
//! other — and both halves are read straight out of a converted java snapshot.
//!
//! java asserts the exact key spellings by rebuilding them inline with
//! `Bytes.concat(PREFIX, a, b)`, so these tests do the same rather than going
//! through our key helpers, keeping the layout independently pinned.

use std::sync::Arc;

use tron_chainbase::{
    DelegatedResourceAccountIndexStore, KvBackend, MemBackend, V1_FROM_PREFIX, V1_TO_PREFIX,
    V2_FROM_PREFIX, V2_TO_PREFIX,
};
use tron_crypto::address::Address;
use tron_proto::DelegatedResourceAccountIndex;

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn addr(byte: u8) -> Address {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(byte);
    Address::from_raw(a)
}

/// java's `Bytes.concat(PREFIX, first, second)`.
fn concat_key(prefix: u8, first: &Address, second: &Address) -> Vec<u8> {
    let mut k = vec![prefix];
    k.extend_from_slice(first.as_bytes());
    k.extend_from_slice(second.as_bytes());
    k
}

/// java's prefix constants, restated literally so a change to ours is caught
/// here rather than only in the store's own module.
#[test]
fn prefix_bytes_match_java_constants() {
    assert_eq!(V1_FROM_PREFIX, 0x01);
    assert_eq!(V1_TO_PREFIX, 0x02);
    assert_eq!(V2_FROM_PREFIX, 0x03);
    assert_eq!(V2_TO_PREFIX, 0x04);
}

/// `DelegatedResourceAccountIndexStoreTest#testDelegate`: after
/// `delegate(from, to, 1)` both `0x01 || from || to` and `0x02 || to || from`
/// exist, each with `timestamp == 1`, and each holding the **counterparty**
/// address.
#[test]
fn delegate_v1_writes_both_directions_with_swapped_to_side_key() {
    let backend = mem();
    let store = DelegatedResourceAccountIndexStore::new(backend.clone());
    let from = addr(0xf1);
    let to = addr(0x70);

    store.delegate_v1(&from, &to, 1).unwrap();

    let from_key = concat_key(0x01, &from, &to);
    let to_key = concat_key(0x02, &to, &from);
    assert_eq!(from_key, DelegatedResourceAccountIndexStore::v1_from_key(&from, &to).to_vec());
    assert_eq!(to_key, DelegatedResourceAccountIndexStore::v1_to_key(&from, &to).to_vec());

    let from_row = store.get_raw(&from_key).unwrap().expect("from-side row");
    assert_eq!(from_row.timestamp, 1);
    assert_eq!(
        from_row.account,
        to.as_bytes().to_vec(),
        "the from-side row stores the delegation target"
    );

    let to_row = store.get_raw(&to_key).unwrap().expect("to-side row");
    assert_eq!(to_row.timestamp, 1);
    assert_eq!(
        to_row.account,
        from.as_bytes().to_vec(),
        "the to-side row stores the delegation source"
    );

    // Exactly two rows, and neither is reachable under the other's prefix.
    assert_eq!(backend.scan_all().unwrap().len(), 2);
    assert_eq!(store.get_raw(&concat_key(0x01, &to, &from)).unwrap(), None);
    assert_eq!(store.get_raw(&concat_key(0x02, &from, &to)).unwrap(), None);
}

/// `#testUnDelegate`: `unDelegate(from, to)` removes **both** rows, so the
/// delegation disappears from either direction.
#[test]
fn undelegate_v1_clears_both_directions() {
    let backend = mem();
    let store = DelegatedResourceAccountIndexStore::new(backend.clone());
    let from = addr(0xf1);
    let to = addr(0x70);

    store.delegate_v1(&from, &to, 1).unwrap();
    assert_eq!(backend.scan_all().unwrap().len(), 2);

    store.undelegate_v1(&from, &to).unwrap();
    assert_eq!(store.get_raw(&concat_key(0x01, &from, &to)).unwrap(), None);
    assert_eq!(store.get_raw(&concat_key(0x02, &to, &from)).unwrap(), None);
    assert!(backend.scan_all().unwrap().is_empty());
}

/// `#testDelegateV2` / `#testUnDelegateV2`: identical shape on the 0x03 / 0x04
/// prefixes, and the V1 and V2 halves are independent — undelegating one must
/// not touch the other.
#[test]
fn delegate_v2_uses_its_own_prefixes_and_is_independent_of_v1() {
    let backend = mem();
    let store = DelegatedResourceAccountIndexStore::new(backend.clone());
    let from = addr(0xf2);
    let to = addr(0x72);

    store.delegate_v1(&from, &to, 1).unwrap();
    store.delegate_v2(&from, &to, 2).unwrap();
    assert_eq!(backend.scan_all().unwrap().len(), 4);

    let v2_from = store
        .get_raw(&concat_key(0x03, &from, &to))
        .unwrap()
        .expect("v2 from-side row");
    assert_eq!(v2_from.timestamp, 2);
    assert_eq!(v2_from.account, to.as_bytes().to_vec());
    let v2_to = store
        .get_raw(&concat_key(0x04, &to, &from))
        .unwrap()
        .expect("v2 to-side row");
    assert_eq!(v2_to.timestamp, 2);
    assert_eq!(v2_to.account, from.as_bytes().to_vec());

    // Removing the V2 delegation leaves the V1 rows untouched.
    store.undelegate_v2(&from, &to).unwrap();
    assert_eq!(store.get_raw(&concat_key(0x03, &from, &to)).unwrap(), None);
    assert_eq!(store.get_raw(&concat_key(0x04, &to, &from)).unwrap(), None);
    assert!(store.get_raw(&concat_key(0x01, &from, &to)).unwrap().is_some());
    assert!(store.get_raw(&concat_key(0x02, &to, &from)).unwrap().is_some());
}

/// A later `delegate` for the same pair overwrites the earlier rows rather than
/// accumulating — java uses `put`, not an append.
#[test]
fn redelegating_the_same_pair_overwrites_rather_than_accumulates() {
    let backend = mem();
    let store = DelegatedResourceAccountIndexStore::new(backend.clone());
    let from = addr(0xf3);
    let to = addr(0x73);

    store.delegate_v1(&from, &to, 1).unwrap();
    store.delegate_v1(&from, &to, 99).unwrap();
    assert_eq!(backend.scan_all().unwrap().len(), 2);
    assert_eq!(
        store
            .get_raw(&concat_key(0x01, &from, &to))
            .unwrap()
            .unwrap()
            .timestamp,
        99
    );
    assert_eq!(
        store
            .get_raw(&concat_key(0x02, &to, &from))
            .unwrap()
            .unwrap()
            .timestamp,
        99
    );
}

/// `#testConvert`: a legacy aggregated row (bare 21-byte key holding
/// `to_accounts` / `from_accounts` lists) is migrated into the per-pair 0x01 /
/// 0x02 rows, after which the legacy row is deleted. java stamps each migrated
/// pair with its **list position + 1** as the timestamp, "just to keep index in
/// order" — that ordering is what `getIndex` later sorts by, so the positions
/// must be preserved exactly.
#[test]
fn convert_migrates_the_legacy_row_into_prefixed_pairs_then_deletes_it() {
    let backend = mem();
    let store = DelegatedResourceAccountIndexStore::new(backend.clone());
    let owner = addr(0x54);
    let to1 = addr(0xa1);
    let to2 = addr(0xa2);
    let from1 = addr(0xb1);

    let legacy_key = DelegatedResourceAccountIndexStore::legacy_key(&owner);
    assert_eq!(
        legacy_key.to_vec(),
        owner.as_bytes().to_vec(),
        "the legacy key is the bare 21-byte address, with no prefix"
    );
    store
        .put_raw(
            &legacy_key,
            &DelegatedResourceAccountIndex {
                account: owner.as_bytes().to_vec(),
                to_accounts: vec![to1.as_bytes().to_vec(), to2.as_bytes().to_vec()],
                from_accounts: vec![from1.as_bytes().to_vec()],
                timestamp: 0,
            },
        )
        .unwrap();

    store.convert(&owner).unwrap();

    // The owner's outbound delegations became from-side rows, in list order.
    for (i, to) in [&to1, &to2].iter().enumerate() {
        let row = store
            .get_raw(&concat_key(0x01, &owner, to))
            .unwrap()
            .unwrap_or_else(|| panic!("missing from-side row for to_accounts[{i}]"));
        assert_eq!(row.timestamp, (i + 1) as i64);
        assert_eq!(row.account, to.as_bytes().to_vec());
        // ...and the matching to-side row with the swapped key.
        let mirror = store
            .get_raw(&concat_key(0x02, to, &owner))
            .unwrap()
            .expect("mirror to-side row");
        assert_eq!(mirror.timestamp, (i + 1) as i64);
        assert_eq!(mirror.account, owner.as_bytes().to_vec());
    }

    // The owner's inbound delegation became a pair with `from1` as the source.
    let inbound = store
        .get_raw(&concat_key(0x01, &from1, &owner))
        .unwrap()
        .expect("inbound from-side row");
    assert_eq!(inbound.timestamp, 1);
    assert_eq!(inbound.account, owner.as_bytes().to_vec());
    let inbound_mirror = store
        .get_raw(&concat_key(0x02, &owner, &from1))
        .unwrap()
        .expect("inbound to-side row");
    assert_eq!(inbound_mirror.account, from1.as_bytes().to_vec());

    // The legacy row is gone, so a second convert is a no-op.
    assert_eq!(store.get_raw(&legacy_key).unwrap(), None);
    let after_first = backend.scan_all().unwrap();
    store.convert(&owner).unwrap();
    assert_eq!(
        backend.scan_all().unwrap(),
        after_first,
        "convert must be idempotent once the legacy row is consumed"
    );
    // 3 delegations x 2 rows each.
    assert_eq!(after_first.len(), 6);
}

/// Converting an address that never had a legacy row is a no-op, not an error —
/// java returns early on a `null` capsule ("convert complete or have no
/// delegate").
#[test]
fn convert_without_a_legacy_row_is_a_no_op() {
    let backend = mem();
    let store = DelegatedResourceAccountIndexStore::new(backend.clone());
    store.convert(&addr(0x99)).unwrap();
    assert!(backend.scan_all().unwrap().is_empty());
}

/// Prefixed rows must not be mistaken for the legacy aggregated row. The legacy
/// key is 21 bytes; every prefixed key is 43. A scan for one must never return
/// the other, which is what keeps `convert` from re-migrating its own output.
#[test]
fn legacy_and_prefixed_key_spaces_do_not_overlap() {
    let backend = mem();
    let store = DelegatedResourceAccountIndexStore::new(backend.clone());
    let from = addr(0xc1);
    let to = addr(0xc2);

    store.delegate_v1(&from, &to, 1).unwrap();
    store.delegate_v2(&from, &to, 1).unwrap();

    for (key, _) in backend.scan_all().unwrap() {
        assert_eq!(key.len(), 43, "prefixed rows are 1 + 21 + 21 bytes");
    }
    assert_eq!(
        store
            .get_raw(&DelegatedResourceAccountIndexStore::legacy_key(&from))
            .unwrap(),
        None,
        "a delegation must not create a legacy aggregated row"
    );
}
