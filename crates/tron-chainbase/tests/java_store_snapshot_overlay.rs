//! Snapshot / revoking-store semantics ported from java-tron's `core/db2`
//! test suite.
//!
//! java-tron layers a linked list of `SnapshotImpl` layers over a
//! `SnapshotRoot` (the physical LevelDB/RocksDB). Our equivalent is a stack of
//! [`SessionBackend`] overlays over a concrete [`KvBackend`]. The tests here
//! pin the behaviours java asserts on that stack — in particular **range and
//! prefix reads**, which must see the merged view (overlay writes shadow the
//! root, overlay deletes hide root rows) rather than the raw root.
//!
//! java references:
//! * `org.tron.core.db2.ChainbaseTest#testPrefixQueryForLeveldb` /
//!   `#testPrefixQueryForRocksdb`
//! * `org.tron.core.db2.SnapshotImplTest#testMergeRoot` / `#testMergeAhead` /
//!   `#testMergeOverride`
//! * `org.tron.core.db2.SnapshotRootTest#testRemove`
//! * `org.tron.core.db2.RevokingDbWithCacheNewValueTest#testGetlatestValues` /
//!   `#testGetValuesNext`

use std::sync::Arc;

use tron_chainbase::{KvBackend, MemBackend, SessionBackend};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn keys_of(rows: &[(Vec<u8>, Vec<u8>)]) -> Vec<String> {
    rows.iter()
        .map(|(k, _)| String::from_utf8_lossy(k).into_owned())
        .collect()
}

fn pairs_of(rows: &[(Vec<u8>, Vec<u8>)]) -> Vec<(String, String)> {
    rows.iter()
        .map(|(k, v)| {
            (
                String::from_utf8_lossy(k).into_owned(),
                String::from_utf8_lossy(v).into_owned(),
            )
        })
        .collect()
}

// === ChainbaseTest#testPrefixQuery ==========================================

/// Direct port of java-tron `ChainbaseTest#testDb`, the shared body of
/// `testPrefixQueryForLeveldb` / `testPrefixQueryForRocksdb`.
///
/// Three stacked overlay layers over a root, with writes and deletes spread
/// across all four, then a single prefix query. The expected result set pins:
/// * a key written **and** removed in the same layer is hidden even though the
///   root still holds a (different) value for it (`key7`);
/// * a key written in one layer and removed in a later one is hidden even
///   though the root still holds a value for it (`key8`);
/// * a key written and removed across two overlay layers is hidden (`key9`);
/// * a key removed **from the root** stays visible when an overlay layer holds
///   a value for it (`key3`);
/// * keys outside the prefix are excluded, and a prefix matching nothing
///   returns empty rather than erroring.
#[test]
fn prefix_query_over_stacked_sessions_merges_writes_and_deletes() {
    let prefix = b"1000000";
    let prefix2 = b"2000000";
    let prefix3 = b"0000000";

    let root = mem();

    // Layer 1.
    let head1 = Arc::new(SessionBackend::new(root.clone()));
    head1.put(b"0aa", b"00000").unwrap();
    head1.put(b"10000001aa", b"10000").unwrap();
    head1.put(b"10000006ac", b"70000").unwrap();
    head1.put(b"10000003aa", b"30000").unwrap();
    head1.put(b"10000006ab", b"80000").unwrap();
    head1.delete(b"10000006ac").unwrap();

    // Root writes land under every layer.
    root.put(b"10000002aa", b"20000").unwrap();
    root.put(b"10000006aa", b"60000").unwrap();
    root.put(b"10000003aa", b"30000").unwrap();
    root.put(b"10000006ac", b"root70000").unwrap();
    root.put(b"10000006ab", b"root80000").unwrap();
    root.put(b"123", b"v123").unwrap();

    // Layer 2.
    let head2 = Arc::new(SessionBackend::new(head1.clone() as Arc<dyn KvBackend>));
    head2.put(b"10000004aa", b"40000").unwrap();
    head2.put(b"10000005aa", b"50000").unwrap();
    head2.put(b"10000006dd", b"90000").unwrap();
    head2.delete(b"10000006ab").unwrap();
    head2.put(b"0000001", b"v0000001").unwrap();

    // Layer 3.
    let head3 = SessionBackend::new(head2.clone() as Arc<dyn KvBackend>);
    head3.delete(b"10000006dd").unwrap();
    root.delete(b"10000003aa").unwrap();

    let mut got = pairs_of(&head3.scan_prefix(prefix).unwrap());
    got.sort();
    let mut want: Vec<(String, String)> = vec![
        ("10000001aa", "10000"),
        ("10000002aa", "20000"),
        ("10000003aa", "30000"),
        ("10000004aa", "40000"),
        ("10000005aa", "50000"),
        ("10000006aa", "60000"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    want.sort();
    assert_eq!(got, want);

    assert!(head3.scan_prefix(prefix2).unwrap().is_empty());
    assert!(head3.scan_prefix(prefix3).unwrap().is_empty());
}

/// The root's own prefix query is unaffected by the overlay layers stacked on
/// top of it — java asserts this separately in `ChainbaseTest#testRoot`, where
/// the root still reports the pre-overlay values for `key7`/`key8`.
#[test]
fn prefix_query_on_root_ignores_overlay_layers() {
    let root = mem();
    let head = SessionBackend::new(root.clone());

    root.put(b"10000002aa", b"20000").unwrap();
    root.put(b"10000006aa", b"60000").unwrap();
    root.put(b"10000006ac", b"root70000").unwrap();
    root.put(b"10000006ab", b"root80000").unwrap();
    root.put(b"123", b"v123").unwrap();

    head.put(b"10000001aa", b"10000").unwrap();
    head.delete(b"10000006ac").unwrap();

    let mut got = pairs_of(&root.scan_prefix(b"1000000").unwrap());
    got.sort();
    let mut want: Vec<(String, String)> = vec![
        ("10000002aa", "20000"),
        ("10000006aa", "60000"),
        ("10000006ab", "root80000"),
        ("10000006ac", "root70000"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    want.sort();
    assert_eq!(got, want);

    assert!(root.scan_prefix(b"2000000").unwrap().is_empty());
    assert!(root.scan_prefix(b"0000000").unwrap().is_empty());
}

// === SnapshotImplTest =======================================================

/// `SnapshotImplTest#testMergeRoot`: a layer reads through to the root for keys
/// it does not hold itself, and its own writes are invisible to the root.
#[test]
fn overlay_reads_fall_through_to_root_and_own_writes_stay_local() {
    let root = mem();
    root.put(b"key1", b"value1").unwrap();
    root.put(b"key2", b"value2").unwrap();

    let from = SessionBackend::new(root.clone());
    from.put(b"key3", b"value3").unwrap();
    from.put(b"key4", b"value4").unwrap();

    assert_eq!(from.get(b"key1").unwrap(), Some(b"value1".to_vec()));
    assert_eq!(from.get(b"key2").unwrap(), Some(b"value2".to_vec()));
    assert_eq!(root.get(b"key3").unwrap(), None);
    assert_eq!(root.get(b"key4").unwrap(), None);
}

/// `SnapshotImplTest#testMergeAhead`: a two-deep stack. The upper layer reads
/// the lower layer's values by traversal; the lower layer cannot see the upper
/// layer's writes — before or after the upper layer merges its overlay down.
#[test]
fn merge_ahead_folds_lower_layer_values_without_leaking_upward_writes() {
    let root = mem();
    let from = Arc::new(SessionBackend::new(root.clone()));
    from.put(b"key1", b"value1").unwrap();
    from.put(b"key2", b"value2").unwrap();

    let from2 = SessionBackend::new(from.clone() as Arc<dyn KvBackend>);
    from2.put(b"key3", b"value3").unwrap();
    from2.put(b"key4", b"value4").unwrap();

    // Before the merge: from2 traverses one link to reach key1/key2.
    assert_eq!(from2.get(b"key1").unwrap(), Some(b"value1".to_vec()));
    assert_eq!(from2.get(b"key2").unwrap(), Some(b"value2".to_vec()));
    // from cannot see from2's writes.
    assert_eq!(from.get(b"key3").unwrap(), None);
    assert_eq!(from.get(b"key4").unwrap(), None);

    // After merging from2's overlay into from, the values are still the same
    // from from2's point of view.
    from2.commit().unwrap();
    assert_eq!(from2.get(b"key1").unwrap(), Some(b"value1".to_vec()));
    assert_eq!(from2.get(b"key2").unwrap(), Some(b"value2".to_vec()));
    // The root is still untouched — only the intermediate layer absorbed them.
    assert_eq!(root.get(b"key3").unwrap(), None);
    assert_eq!(root.get(b"key4").unwrap(), None);
}

/// `SnapshotImplTest#testMergeOverride`: when both layers hold a key, the
/// **upper** layer's value survives the merge.
#[test]
fn merge_ahead_upper_layer_value_overrides_lower() {
    let root = mem();
    let from = Arc::new(SessionBackend::new(root.clone()));
    from.put(b"key1", b"value1").unwrap();
    from.put(b"key2", b"value2").unwrap();
    from.put(b"key3", b"value31").unwrap();

    let from2 = SessionBackend::new(from.clone() as Arc<dyn KvBackend>);
    from2.put(b"key3", b"value32").unwrap();
    from2.put(b"key4", b"value4").unwrap();
    from2.commit().unwrap();

    assert_eq!(from.get(b"key1").unwrap(), Some(b"value1".to_vec()));
    assert_eq!(from.get(b"key2").unwrap(), Some(b"value2".to_vec()));
    assert_eq!(from.get(b"key3").unwrap(), Some(b"value32".to_vec()));
    assert_eq!(from.get(b"key4").unwrap(), Some(b"value4".to_vec()));
}

/// `SnapshotRootTest#testRemove`: a delete straight on the root makes the key
/// read back as absent (not as an empty value).
#[test]
fn root_delete_makes_key_absent() {
    let root = mem();
    root.put(b"test", b"test").unwrap();
    assert_eq!(root.get(b"test").unwrap(), Some(b"test".to_vec()));
    root.delete(b"test").unwrap();
    assert_eq!(root.get(b"test").unwrap(), None);
}

// === RevokingDbWithCacheNewValue iteration ==================================

/// `RevokingDbWithCacheNewValueTest#testGetValuesNext`: a forward range read
/// from a start key returns `limit` rows in ascending key order, starting at
/// the first key `>= start`. Pinned here through a session overlay, because
/// java's `getValuesNext` runs against the merged snapshot view, not the root.
#[test]
fn scan_from_through_session_returns_ascending_rows_from_start_key() {
    let root = mem();
    // Rows 1..=4 live in the root, 5..=9 in the overlay: the merged view must
    // interleave them by key order, not by layer.
    for i in 1..10u32 {
        let key = format!("getValuesNext{i}");
        if i <= 4 {
            root.put(key.as_bytes(), key.as_bytes()).unwrap();
        }
    }
    let session = SessionBackend::new(root.clone());
    for i in 5..10u32 {
        let key = format!("getValuesNext{i}");
        session.put(key.as_bytes(), key.as_bytes()).unwrap();
    }

    let rows = session.scan_from(b"getValuesNext2", 3).unwrap();
    assert_eq!(
        keys_of(&rows),
        vec![
            "getValuesNext2".to_string(),
            "getValuesNext3".to_string(),
            "getValuesNext4".to_string(),
        ]
    );

    // A start key past every row yields nothing rather than erroring.
    assert!(session.scan_from(b"getValuesNextZ", 3).unwrap().is_empty());
    // A zero limit is a no-op.
    assert!(session.scan_from(b"getValuesNext2", 0).unwrap().is_empty());
}

/// `RevokingDbWithCacheNewValueTest#testGetlatestValues`: the "latest N" read
/// walks the tail of the key space in **descending** order. Pinned through a
/// session so the overlay's writes and deletes participate.
#[test]
fn scan_back_from_through_session_returns_descending_tail() {
    let root = mem();
    for i in 1..10u32 {
        let key = format!("getLatestValues{i}");
        root.put(key.as_bytes(), key.as_bytes()).unwrap();
    }
    let session = SessionBackend::new(root.clone());
    // Hide one row and rewrite another: both must be reflected in the tail.
    session.delete(b"getLatestValues8").unwrap();
    session.put(b"getLatestValues7", b"rewritten").unwrap();

    let rows = session.scan_back_from(&[0xff], 4).unwrap();
    assert_eq!(
        keys_of(&rows),
        vec![
            "getLatestValues9".to_string(),
            "getLatestValues7".to_string(),
            "getLatestValues6".to_string(),
            "getLatestValues5".to_string(),
        ],
        "deleted row must be skipped and the remaining tail stay descending"
    );
    assert_eq!(rows[1].1, b"rewritten".to_vec());
}

/// A revert drops the overlay entirely: range reads go back to exactly what
/// the parent holds. Mirrors java's session `close()` without `commit()`
/// (`SnapshotManagerTest#testClose`), applied to the iteration path.
#[test]
fn revert_restores_range_reads_to_parent_state() {
    let root = mem();
    root.put(b"prefix-a", b"1").unwrap();
    root.put(b"prefix-b", b"2").unwrap();

    let session = SessionBackend::new(root.clone());
    session.put(b"prefix-c", b"3").unwrap();
    session.delete(b"prefix-a").unwrap();
    assert_eq!(
        keys_of(&session.scan_prefix(b"prefix-").unwrap()),
        vec!["prefix-b".to_string(), "prefix-c".to_string()]
    );

    session.revert();
    assert_eq!(
        keys_of(&session.scan_prefix(b"prefix-").unwrap()),
        vec!["prefix-a".to_string(), "prefix-b".to_string()]
    );
    assert_eq!(
        keys_of(&session.scan_from(b"prefix-", 10).unwrap()),
        vec!["prefix-a".to_string(), "prefix-b".to_string()]
    );
}
