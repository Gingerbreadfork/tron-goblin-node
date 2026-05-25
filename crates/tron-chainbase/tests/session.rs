//! Exhaustive tests for [`tron_chainbase::SessionBackend`].
//!
//! Each test pins one observable property. The session is the
//! foundation for per-tx rollback in the executor, so the behaviors
//! tested here are load-bearing for higher layers.

use std::sync::Arc;

use tron_chainbase::{KvBackend, MemBackend, SessionBackend};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

// === Basic single-session semantics =========================================

#[test]
fn write_then_read_within_session_returns_pending_value() {
    let parent = mem();
    let session = SessionBackend::new(parent);
    session.put(b"k", b"v");
    assert_eq!(session.get(b"k"), Some(b"v".to_vec()));
}

#[test]
fn read_misses_in_session_fall_through_to_parent() {
    let parent = mem();
    parent.put(b"k", b"parent-value");
    let session = SessionBackend::new(parent.clone());
    assert_eq!(session.get(b"k"), Some(b"parent-value".to_vec()));
}

#[test]
fn write_in_session_shadows_parent() {
    let parent = mem();
    parent.put(b"k", b"parent-value");
    let session = SessionBackend::new(parent.clone());
    session.put(b"k", b"session-value");
    assert_eq!(session.get(b"k"), Some(b"session-value".to_vec()));
    // Parent unchanged until commit.
    assert_eq!(parent.get(b"k"), Some(b"parent-value".to_vec()));
}

#[test]
fn delete_in_session_shadows_parent() {
    let parent = mem();
    parent.put(b"k", b"parent-value");
    let session = SessionBackend::new(parent.clone());
    session.delete(b"k");
    assert_eq!(session.get(b"k"), None);
    assert_eq!(parent.get(b"k"), Some(b"parent-value".to_vec()));
}

#[test]
fn writes_dont_touch_parent_before_commit() {
    let parent = mem();
    let session = SessionBackend::new(parent.clone());
    session.put(b"a", b"1");
    session.put(b"b", b"2");
    session.put(b"c", b"3");
    assert_eq!(parent.get(b"a"), None);
    assert_eq!(parent.get(b"b"), None);
    assert_eq!(parent.get(b"c"), None);
}

#[test]
fn pending_len_tracks_distinct_keys_not_writes() {
    let session = SessionBackend::new(mem());
    assert!(session.is_clean());
    session.put(b"a", b"1");
    assert_eq!(session.pending_len(), 1);
    // Overwriting the same key doesn't grow the pending set.
    session.put(b"a", b"2");
    assert_eq!(session.pending_len(), 1);
    session.put(b"b", b"3");
    assert_eq!(session.pending_len(), 2);
}

// === commit() ===============================================================

#[test]
fn commit_flushes_puts_to_parent() {
    let parent = mem();
    let session = SessionBackend::new(parent.clone());
    session.put(b"a", b"1");
    session.put(b"b", b"2");
    session.commit();
    assert_eq!(parent.get(b"a"), Some(b"1".to_vec()));
    assert_eq!(parent.get(b"b"), Some(b"2".to_vec()));
}

#[test]
fn commit_propagates_deletes_to_parent() {
    let parent = mem();
    parent.put(b"k", b"v");
    let session = SessionBackend::new(parent.clone());
    session.delete(b"k");
    session.commit();
    assert_eq!(parent.get(b"k"), None);
}

#[test]
fn commit_clears_overlay_so_session_reuse_starts_fresh() {
    let parent = mem();
    let session = SessionBackend::new(parent.clone());
    session.put(b"a", b"1");
    assert_eq!(session.pending_len(), 1);
    session.commit();
    assert!(session.is_clean());

    // Reuse: writes start a fresh overlay.
    session.put(b"b", b"2");
    assert_eq!(session.pending_len(), 1);
    // Parent reflects the first commit but not the new write yet.
    assert_eq!(parent.get(b"a"), Some(b"1".to_vec()));
    assert_eq!(parent.get(b"b"), None);
}

#[test]
fn commit_on_empty_session_is_noop() {
    let parent = mem();
    let session = SessionBackend::new(parent.clone());
    session.commit(); // doesn't panic
    assert!(session.is_clean());
}

#[test]
fn last_write_wins_on_commit() {
    let parent = mem();
    let session = SessionBackend::new(parent.clone());
    session.put(b"k", b"v1");
    session.put(b"k", b"v2");
    session.delete(b"k");
    session.put(b"k", b"v3");
    session.commit();
    assert_eq!(parent.get(b"k"), Some(b"v3".to_vec()));
}

// === revert() ===============================================================

#[test]
fn revert_discards_pending_writes() {
    let parent = mem();
    let session = SessionBackend::new(parent.clone());
    session.put(b"a", b"1");
    session.put(b"b", b"2");
    session.revert();
    assert!(session.is_clean());
    assert_eq!(parent.get(b"a"), None);
    assert_eq!(parent.get(b"b"), None);
}

#[test]
fn revert_restores_session_view_of_parent() {
    let parent = mem();
    parent.put(b"k", b"parent-value");
    let session = SessionBackend::new(parent.clone());
    session.put(b"k", b"overwritten");
    assert_eq!(session.get(b"k"), Some(b"overwritten".to_vec()));
    session.revert();
    // After revert, the session sees the parent unchanged.
    assert_eq!(session.get(b"k"), Some(b"parent-value".to_vec()));
}

#[test]
fn revert_then_write_then_commit_works_as_expected() {
    let parent = mem();
    let session = SessionBackend::new(parent.clone());
    session.put(b"k", b"discarded");
    session.revert();
    session.put(b"k", b"kept");
    session.commit();
    assert_eq!(parent.get(b"k"), Some(b"kept".to_vec()));
}

// === Isolation across sibling sessions ======================================

/// Two sessions over the same parent are isolated: writes in one don't
/// appear in the other.
#[test]
fn sibling_sessions_are_isolated() {
    let parent = mem();
    parent.put(b"k", b"parent");
    let a = SessionBackend::new(parent.clone());
    let b = SessionBackend::new(parent.clone());

    a.put(b"k", b"from-a");
    assert_eq!(a.get(b"k"), Some(b"from-a".to_vec()));
    assert_eq!(b.get(b"k"), Some(b"parent".to_vec()));
    assert_eq!(parent.get(b"k"), Some(b"parent".to_vec()));
}

/// One sibling commits; the other still sees its own pending state
/// (but reads that fall through to the parent now see the committed
/// value).
#[test]
fn commit_visible_to_later_sibling_reads_but_not_pending_writes() {
    let parent = mem();
    let a = SessionBackend::new(parent.clone());
    let b = SessionBackend::new(parent.clone());

    a.put(b"k", b"a-value");
    a.commit();

    // b's overlay is still empty → its reads fall through to parent
    // which now reflects a's commit.
    assert_eq!(b.get(b"k"), Some(b"a-value".to_vec()));

    b.put(b"k", b"b-value");
    // b's overlay now shadows parent.
    assert_eq!(b.get(b"k"), Some(b"b-value".to_vec()));
    // Parent still shows a's value because b hasn't committed.
    assert_eq!(parent.get(b"k"), Some(b"a-value".to_vec()));
}

// === Stacking sessions ======================================================

/// SessionBackend itself implements KvBackend, so a session can wrap a
/// session can wrap a MemBackend. The "all-the-way-down" reads work and
/// commits propagate one level at a time.
#[test]
fn stacked_sessions_propagate_commits_one_level() {
    let base = mem();
    base.put(b"k", b"base");
    let mid = Arc::new(SessionBackend::new(base.clone()));
    let top = SessionBackend::new(mid.clone() as Arc<dyn KvBackend>);

    top.put(b"k", b"from-top");
    // top sees its own write.
    assert_eq!(top.get(b"k"), Some(b"from-top".to_vec()));
    // mid sees only base.
    assert_eq!(mid.get(b"k"), Some(b"base".to_vec()));

    // Commit top → its overlay flushes into mid (not base).
    top.commit();
    assert_eq!(mid.get(b"k"), Some(b"from-top".to_vec()));
    assert_eq!(base.get(b"k"), Some(b"base".to_vec()));

    // Commit mid → finally reaches base.
    mid.commit();
    assert_eq!(base.get(b"k"), Some(b"from-top".to_vec()));
}

// === Larger-scale stress ====================================================

/// 1,000 distinct writes, commit, verify all visible in parent. Also
/// confirms HashMap-based pending doesn't drop entries.
#[test]
fn large_session_commits_all_pending_writes() {
    let parent = mem();
    let session = SessionBackend::new(parent.clone());
    for i in 0..1000u32 {
        session.put(&i.to_be_bytes(), &i.to_le_bytes());
    }
    assert_eq!(session.pending_len(), 1000);
    session.commit();
    for i in 0..1000u32 {
        assert_eq!(parent.get(&i.to_be_bytes()), Some(i.to_le_bytes().to_vec()));
    }
}

// === Integration with stores =================================================

/// SessionBackend can back a real Store. This proves the executor can
/// transparently swap in sessions without changing the actuator code.
#[test]
fn session_can_back_an_account_store_transparently() {
    use tron_chainbase::AccountStore;
    use tron_crypto::address::Address;
    use tron_proto::Account;

    let parent = mem();
    let session_typed = Arc::new(SessionBackend::new(parent.clone()));
    let session_dyn: Arc<dyn KvBackend> = session_typed.clone();
    let store = AccountStore::new(session_dyn);

    let addr = Address::from_raw([0x41; 21]);
    let alice = Account {
        address: addr.as_bytes().to_vec(),
        balance: 1234,
        ..Default::default()
    };
    store.put(&addr, &alice);

    // Visible through the session-backed store.
    assert_eq!(store.get(&addr).unwrap().unwrap().balance, 1234);
    // NOT visible through a parent-backed store yet.
    let parent_store = AccountStore::new(parent.clone());
    assert!(parent_store.get(&addr).unwrap().is_none());

    // Commit via the typed handle (Arc<SessionBackend>).
    session_typed.commit();

    // Now visible through parent.
    assert_eq!(parent_store.get(&addr).unwrap().unwrap().balance, 1234);
}

// === scan_all overlay semantics =============================================

#[test]
fn mem_backend_scan_all_returns_entries_in_byte_order() {
    let m = MemBackend::new();
    m.put(b"b", b"2");
    m.put(b"a", b"1");
    m.put(b"c", b"3");
    let snap = m.scan_all();
    assert_eq!(
        snap,
        vec![
            (b"a".to_vec(), b"1".to_vec()),
            (b"b".to_vec(), b"2".to_vec()),
            (b"c".to_vec(), b"3".to_vec()),
        ]
    );
}

#[test]
fn session_scan_all_overlays_pending_puts_over_parent() {
    let parent = mem();
    parent.put(b"a", b"parent-a");
    parent.put(b"b", b"parent-b");
    let session = SessionBackend::new(parent.clone());
    session.put(b"a", b"session-a");
    session.put(b"c", b"session-c");

    let snap = session.scan_all();
    assert_eq!(
        snap,
        vec![
            (b"a".to_vec(), b"session-a".to_vec()),
            (b"b".to_vec(), b"parent-b".to_vec()),
            (b"c".to_vec(), b"session-c".to_vec()),
        ]
    );
}

#[test]
fn session_scan_all_hides_pending_deletes_from_parent() {
    let parent = mem();
    parent.put(b"a", b"parent-a");
    parent.put(b"b", b"parent-b");
    let session = SessionBackend::new(parent);
    session.delete(b"a");

    let snap = session.scan_all();
    assert_eq!(snap, vec![(b"b".to_vec(), b"parent-b".to_vec())]);
}

#[test]
fn session_scan_all_after_revert_matches_parent() {
    let parent = mem();
    parent.put(b"a", b"parent-a");
    let session = SessionBackend::new(parent);
    session.put(b"a", b"session-a");
    session.delete(b"a");
    session.put(b"b", b"session-b");
    session.revert();

    let snap = session.scan_all();
    assert_eq!(snap, vec![(b"a".to_vec(), b"parent-a".to_vec())]);
}
