//! Exhaustive tests for [`tron_chainbase::SessionBackend`].
//!
//! Each test pins one observable property. The session is the
//! foundation for per-tx rollback in the executor, so the behaviors
//! tested here are load-bearing for higher layers.

use std::sync::Arc;

use tron_chainbase::{KvBackend, MemBackend, SessionBackend, WriteOp};

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

// === KvBackend::write_batch — H-12 atomic commit ============================

/// A `write_batch` against a `MemBackend` produces the same final state
/// as the equivalent per-key `put`/`delete` loop. The correctness pin;
/// atomicity is verified separately via the concurrent-reader test
/// below.
#[test]
fn write_batch_produces_equivalent_final_state() {
    let backend = MemBackend::new();
    backend.put(b"keep", b"original");
    backend.put(b"replace-me", b"old");
    backend.put(b"delete-me", b"goodbye");

    let ops = vec![
        WriteOp::Put(b"new-key".to_vec(), b"new-value".to_vec()),
        WriteOp::Put(b"replace-me".to_vec(), b"new".to_vec()),
        WriteOp::Delete(b"delete-me".to_vec()),
    ];
    backend.write_batch(&ops);

    assert_eq!(backend.get(b"keep"), Some(b"original".to_vec()));
    assert_eq!(backend.get(b"new-key"), Some(b"new-value".to_vec()));
    assert_eq!(backend.get(b"replace-me"), Some(b"new".to_vec()));
    assert_eq!(backend.get(b"delete-me"), None);
}

/// Empty op list is a no-op. `SessionBackend::commit` short-circuits
/// on empty pending; backend behaviour must match.
#[test]
fn write_batch_with_empty_ops_is_noop() {
    let backend = MemBackend::new();
    backend.put(b"a", b"unchanged");
    backend.write_batch(&[]);
    assert_eq!(backend.get(b"a"), Some(b"unchanged".to_vec()));
    assert_eq!(backend.scan_all().len(), 1);
}

/// Ops are processed in order — last write per key wins. Mirrors
/// `SessionBackend` pending-map semantics, no internal reordering.
#[test]
fn write_batch_processes_ops_in_order_last_op_wins() {
    let backend = MemBackend::new();
    let ops = vec![
        WriteOp::Put(b"k".to_vec(), b"first".to_vec()),
        WriteOp::Put(b"k".to_vec(), b"second".to_vec()),
        WriteOp::Delete(b"k".to_vec()),
        WriteOp::Put(b"k".to_vec(), b"final".to_vec()),
    ];
    backend.write_batch(&ops);
    assert_eq!(backend.get(b"k"), Some(b"final".to_vec()));
}

/// **Atomicity pin via a `scan_all` snapshot.** A reader that takes
/// a full snapshot of the backend (one read-lock acquisition over
/// every key) never observes a state where one key in the batch has
/// its post-batch value but another key in the same batch still has
/// its pre-batch value. Proves the batch is applied under a single
/// write-lock — the `MemBackend` end of the H-12 guarantee.
///
/// `get` against a single key can't catch torn-state because it only
/// reads one key per lock acquisition; the writer can legitimately
/// interleave between two consecutive `get`s. `scan_all` is the only
/// reader primitive that holds the lock across multiple keys.
/// RocksDB's WAL extends the same guarantee across process crashes
/// — `rocksdb::WriteBatch`'s native semantic.
#[test]
fn write_batch_is_atomic_against_concurrent_snapshot_reads() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::Duration;

    let backend = Arc::new(MemBackend::new());
    backend.put(b"a", b"old-a");
    backend.put(b"b", b"old-b");

    let stop = Arc::new(AtomicBool::new(false));
    let saw_torn = Arc::new(AtomicBool::new(false));

    let reader_backend = Arc::clone(&backend);
    let reader_stop = Arc::clone(&stop);
    let reader_torn = Arc::clone(&saw_torn);
    let reader = thread::spawn(move || {
        while !reader_stop.load(Ordering::Relaxed) {
            let snap: std::collections::HashMap<Vec<u8>, Vec<u8>> =
                reader_backend.scan_all().into_iter().collect();
            let a = snap.get(b"a".as_slice()).map(|v| v.as_slice());
            let b = snap.get(b"b".as_slice()).map(|v| v.as_slice());
            let a_old = a == Some(b"old-a".as_slice());
            let a_new = a == Some(b"new-a".as_slice());
            let b_old = b == Some(b"old-b".as_slice());
            let b_new = b == Some(b"new-b".as_slice());
            // Valid: both old, OR both new. Anything else means the
            // snapshot caught an intermediate batch state.
            if !((a_old && b_old) || (a_new && b_new)) {
                reader_torn.store(true, Ordering::Relaxed);
                return;
            }
        }
    });

    for i in 0..1000 {
        let (av, bv) = if i % 2 == 0 {
            (b"new-a".to_vec(), b"new-b".to_vec())
        } else {
            (b"old-a".to_vec(), b"old-b".to_vec())
        };
        backend.write_batch(&[
            WriteOp::Put(b"a".to_vec(), av),
            WriteOp::Put(b"b".to_vec(), bv),
        ]);
    }
    thread::sleep(Duration::from_millis(5));
    stop.store(true, Ordering::Relaxed);
    reader.join().unwrap();

    assert!(
        !saw_torn.load(Ordering::Relaxed),
        "scan_all observed a torn batch state — atomicity broken"
    );
}

/// `SessionBackend::commit` routes through `parent.write_batch`, so a
/// parent that records its calls sees ONE `write_batch` per commit
/// regardless of how many keys were pending — proves per-tx commits
/// are submitted as a single batch, not N independent `put`s.
#[test]
fn session_commit_invokes_parent_write_batch_once() {
    use std::sync::Mutex;

    struct RecordingBackend {
        inner: MemBackend,
        batches: Mutex<Vec<Vec<WriteOp>>>,
        per_call_writes: Mutex<usize>,
    }

    impl KvBackend for RecordingBackend {
        fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.inner.get(key)
        }
        fn put(&self, key: &[u8], value: &[u8]) {
            *self.per_call_writes.lock().unwrap() += 1;
            self.inner.put(key, value);
        }
        fn delete(&self, key: &[u8]) {
            *self.per_call_writes.lock().unwrap() += 1;
            self.inner.delete(key);
        }
        fn scan_all(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
            self.inner.scan_all()
        }
        fn write_batch(&self, ops: &[WriteOp]) {
            self.batches.lock().unwrap().push(ops.to_vec());
            self.inner.write_batch(ops);
        }
    }

    let parent = Arc::new(RecordingBackend {
        inner: MemBackend::new(),
        batches: Mutex::new(Vec::new()),
        per_call_writes: Mutex::new(0),
    });
    let session = SessionBackend::new(parent.clone() as Arc<dyn KvBackend>);
    session.put(b"a", b"1");
    session.put(b"b", b"2");
    session.delete(b"c");
    session.commit();

    let batches = parent.batches.lock().unwrap();
    assert_eq!(batches.len(), 1, "commit must produce exactly one batch");
    assert_eq!(
        batches[0].len(),
        3,
        "all pending ops should be in the single batch"
    );
    drop(batches);
    assert_eq!(
        *parent.per_call_writes.lock().unwrap(),
        0,
        "commit must NOT fall back to per-key put/delete"
    );
}

/// Empty commit doesn't even call `write_batch` — avoids a spurious
/// lock acquisition on a hot path.
#[test]
fn session_commit_with_no_pending_does_not_invoke_write_batch() {
    use std::sync::Mutex;

    struct CountingBackend {
        inner: MemBackend,
        batch_calls: Mutex<usize>,
    }

    impl KvBackend for CountingBackend {
        fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.inner.get(key)
        }
        fn put(&self, key: &[u8], value: &[u8]) {
            self.inner.put(key, value);
        }
        fn delete(&self, key: &[u8]) {
            self.inner.delete(key);
        }
        fn scan_all(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
            self.inner.scan_all()
        }
        fn write_batch(&self, ops: &[WriteOp]) {
            *self.batch_calls.lock().unwrap() += 1;
            self.inner.write_batch(ops);
        }
    }

    let parent = Arc::new(CountingBackend {
        inner: MemBackend::new(),
        batch_calls: Mutex::new(0),
    });
    let session = SessionBackend::new(parent.clone() as Arc<dyn KvBackend>);
    session.commit();
    assert_eq!(*parent.batch_calls.lock().unwrap(), 0);
}

/// `commit_with_undo` captures the parent's pre-image for every key
/// THEN applies the batch atomically. Pin both halves.
#[test]
fn commit_with_undo_captures_pre_image_then_applies_batch() {
    let parent = mem();
    parent.put(b"existing", b"pre-image");
    parent.put(b"will-delete", b"goes-away");
    let session = SessionBackend::new(parent.clone());
    session.put(b"existing", b"new-value");
    session.delete(b"will-delete");
    session.put(b"brand-new", b"first-write");

    let undo = session.commit_with_undo();

    let mut undo_map: std::collections::HashMap<Vec<u8>, Option<Vec<u8>>> =
        undo.into_iter().collect();
    assert_eq!(
        undo_map.remove(b"existing".as_slice()),
        Some(Some(b"pre-image".to_vec()))
    );
    assert_eq!(
        undo_map.remove(b"will-delete".as_slice()),
        Some(Some(b"goes-away".to_vec()))
    );
    assert_eq!(
        undo_map.remove(b"brand-new".as_slice()),
        Some(None),
        "brand-new had no pre-image — undo records None so rollback would `delete`"
    );
    assert!(undo_map.is_empty(), "no extra entries");

    assert_eq!(parent.get(b"existing"), Some(b"new-value".to_vec()));
    assert_eq!(parent.get(b"will-delete"), None);
    assert_eq!(parent.get(b"brand-new"), Some(b"first-write".to_vec()));
}

// === drain_pending / drain_pending_with_undo ================================

/// `drain_pending` extracts pending writes WITHOUT touching the parent.
#[test]
fn drain_pending_returns_ops_without_writing_parent() {
    let parent = mem();
    parent.put(b"untouched", b"keep");
    let session = SessionBackend::new(parent.clone());
    session.put(b"a", b"1");
    session.delete(b"b");
    session.put(b"c", b"3");

    let ops = session.drain_pending();
    assert_eq!(ops.len(), 3);
    assert!(session.is_clean(), "drain clears pending");

    // Parent unchanged: drain isn't a commit.
    assert_eq!(parent.get(b"untouched"), Some(b"keep".to_vec()));
    assert_eq!(parent.get(b"a"), None);
    assert_eq!(parent.get(b"b"), None);
    assert_eq!(parent.get(b"c"), None);

    // Re-applying the ops via parent.write_batch reaches the same
    // final state a normal commit() would have produced.
    parent.write_batch(&ops);
    let mut found = std::collections::HashSet::new();
    if parent.get(b"a") == Some(b"1".to_vec()) { found.insert("a"); }
    if parent.get(b"c") == Some(b"3".to_vec()) { found.insert("c"); }
    if parent.get(b"b") == None { found.insert("b"); }
    assert_eq!(found.len(), 3);
}

/// `drain_pending_with_undo` captures pre-images BEFORE the caller
/// applies the batch (the pre-image must reflect parent state at
/// drain time, not afterwards).
#[test]
fn drain_pending_with_undo_captures_pre_images_at_drain_time() {
    let parent = mem();
    parent.put(b"existing", b"pre");
    let session = SessionBackend::new(parent.clone());
    session.put(b"existing", b"new");
    session.put(b"brand-new", b"first");

    let (ops, undo) = session.drain_pending_with_undo();
    assert_eq!(ops.len(), 2);
    assert_eq!(undo.len(), 2);
    // Parent still has the pre-image (drain hasn't committed).
    assert_eq!(parent.get(b"existing"), Some(b"pre".to_vec()));

    let undo_map: std::collections::HashMap<Vec<u8>, Option<Vec<u8>>> =
        undo.into_iter().collect();
    assert_eq!(undo_map.get(b"existing".as_slice()), Some(&Some(b"pre".to_vec())));
    assert_eq!(undo_map.get(b"brand-new".as_slice()), Some(&None));
}

/// Drain on an empty session returns empty vecs and is a no-op.
#[test]
fn drain_pending_on_empty_session_is_noop() {
    let parent = mem();
    let session = SessionBackend::new(parent);
    assert!(session.drain_pending().is_empty());
    let (ops, undo) = session.drain_pending_with_undo();
    assert!(ops.is_empty());
    assert!(undo.is_empty());
}
