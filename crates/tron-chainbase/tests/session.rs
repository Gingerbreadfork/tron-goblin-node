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
    session.put(b"k", b"v").unwrap();
    assert_eq!(session.get(b"k").unwrap(), Some(b"v".to_vec()));
}

#[test]
fn read_misses_in_session_fall_through_to_parent() {
    let parent = mem();
    parent.put(b"k", b"parent-value").unwrap();
    let session = SessionBackend::new(parent.clone());
    assert_eq!(session.get(b"k").unwrap(), Some(b"parent-value".to_vec()));
}

#[test]
fn write_in_session_shadows_parent() {
    let parent = mem();
    parent.put(b"k", b"parent-value").unwrap();
    let session = SessionBackend::new(parent.clone());
    session.put(b"k", b"session-value").unwrap();
    assert_eq!(session.get(b"k").unwrap(), Some(b"session-value".to_vec()));
    // Parent unchanged until commit.
    assert_eq!(parent.get(b"k").unwrap(), Some(b"parent-value".to_vec()));
}

#[test]
fn delete_in_session_shadows_parent() {
    let parent = mem();
    parent.put(b"k", b"parent-value").unwrap();
    let session = SessionBackend::new(parent.clone());
    session.delete(b"k").unwrap();
    assert_eq!(session.get(b"k").unwrap(), None);
    assert_eq!(parent.get(b"k").unwrap(), Some(b"parent-value".to_vec()));
}

#[test]
fn writes_dont_touch_parent_before_commit() {
    let parent = mem();
    let session = SessionBackend::new(parent.clone());
    session.put(b"a", b"1").unwrap();
    session.put(b"b", b"2").unwrap();
    session.put(b"c", b"3").unwrap();
    assert_eq!(parent.get(b"a").unwrap(), None);
    assert_eq!(parent.get(b"b").unwrap(), None);
    assert_eq!(parent.get(b"c").unwrap(), None);
}

#[test]
fn pending_len_tracks_distinct_keys_not_writes() {
    let session = SessionBackend::new(mem());
    assert!(session.is_clean());
    session.put(b"a", b"1").unwrap();
    assert_eq!(session.pending_len(), 1);
    // Overwriting the same key doesn't grow the pending set.
    session.put(b"a", b"2").unwrap();
    assert_eq!(session.pending_len(), 1);
    session.put(b"b", b"3").unwrap();
    assert_eq!(session.pending_len(), 2);
}

// === commit() ===============================================================

#[test]
fn commit_flushes_puts_to_parent() {
    let parent = mem();
    let session = SessionBackend::new(parent.clone());
    session.put(b"a", b"1").unwrap();
    session.put(b"b", b"2").unwrap();
    session.commit().unwrap();
    assert_eq!(parent.get(b"a").unwrap(), Some(b"1".to_vec()));
    assert_eq!(parent.get(b"b").unwrap(), Some(b"2".to_vec()));
}

#[test]
fn commit_propagates_deletes_to_parent() {
    let parent = mem();
    parent.put(b"k", b"v").unwrap();
    let session = SessionBackend::new(parent.clone());
    session.delete(b"k").unwrap();
    session.commit().unwrap();
    assert_eq!(parent.get(b"k").unwrap(), None);
}

#[test]
fn commit_clears_overlay_so_session_reuse_starts_fresh() {
    let parent = mem();
    let session = SessionBackend::new(parent.clone());
    session.put(b"a", b"1").unwrap();
    assert_eq!(session.pending_len(), 1);
    session.commit().unwrap();
    assert!(session.is_clean());

    // Reuse: writes start a fresh overlay.
    session.put(b"b", b"2").unwrap();
    assert_eq!(session.pending_len(), 1);
    // Parent reflects the first commit but not the new write yet.
    assert_eq!(parent.get(b"a").unwrap(), Some(b"1".to_vec()));
    assert_eq!(parent.get(b"b").unwrap(), None);
}

#[test]
fn commit_on_empty_session_is_noop() {
    let parent = mem();
    let session = SessionBackend::new(parent.clone());
    session.commit().unwrap(); // doesn't panic
    assert!(session.is_clean());
}

#[test]
fn last_write_wins_on_commit() {
    let parent = mem();
    let session = SessionBackend::new(parent.clone());
    session.put(b"k", b"v1").unwrap();
    session.put(b"k", b"v2").unwrap();
    session.delete(b"k").unwrap();
    session.put(b"k", b"v3").unwrap();
    session.commit().unwrap();
    assert_eq!(parent.get(b"k").unwrap(), Some(b"v3".to_vec()));
}

// === revert() ===============================================================

#[test]
fn revert_discards_pending_writes() {
    let parent = mem();
    let session = SessionBackend::new(parent.clone());
    session.put(b"a", b"1").unwrap();
    session.put(b"b", b"2").unwrap();
    session.revert();
    assert!(session.is_clean());
    assert_eq!(parent.get(b"a").unwrap(), None);
    assert_eq!(parent.get(b"b").unwrap(), None);
}

#[test]
fn revert_restores_session_view_of_parent() {
    let parent = mem();
    parent.put(b"k", b"parent-value").unwrap();
    let session = SessionBackend::new(parent.clone());
    session.put(b"k", b"overwritten").unwrap();
    assert_eq!(session.get(b"k").unwrap(), Some(b"overwritten".to_vec()));
    session.revert();
    // After revert, the session sees the parent unchanged.
    assert_eq!(session.get(b"k").unwrap(), Some(b"parent-value".to_vec()));
}

#[test]
fn revert_then_write_then_commit_works_as_expected() {
    let parent = mem();
    let session = SessionBackend::new(parent.clone());
    session.put(b"k", b"discarded").unwrap();
    session.revert();
    session.put(b"k", b"kept").unwrap();
    session.commit().unwrap();
    assert_eq!(parent.get(b"k").unwrap(), Some(b"kept".to_vec()));
}

// === Isolation across sibling sessions ======================================

/// Two sessions over the same parent are isolated: writes in one don't
/// appear in the other.
#[test]
fn sibling_sessions_are_isolated() {
    let parent = mem();
    parent.put(b"k", b"parent").unwrap();
    let a = SessionBackend::new(parent.clone());
    let b = SessionBackend::new(parent.clone());

    a.put(b"k", b"from-a").unwrap();
    assert_eq!(a.get(b"k").unwrap(), Some(b"from-a".to_vec()));
    assert_eq!(b.get(b"k").unwrap(), Some(b"parent".to_vec()));
    assert_eq!(parent.get(b"k").unwrap(), Some(b"parent".to_vec()));
}

/// One sibling commits; the other still sees its own pending state
/// (but reads that fall through to the parent now see the committed
/// value).
#[test]
fn commit_visible_to_later_sibling_reads_but_not_pending_writes() {
    let parent = mem();
    let a = SessionBackend::new(parent.clone());
    let b = SessionBackend::new(parent.clone());

    a.put(b"k", b"a-value").unwrap();
    a.commit().unwrap();

    // b's overlay is still empty → its reads fall through to parent
    // which now reflects a's commit.
    assert_eq!(b.get(b"k").unwrap(), Some(b"a-value".to_vec()));

    b.put(b"k", b"b-value").unwrap();
    // b's overlay now shadows parent.
    assert_eq!(b.get(b"k").unwrap(), Some(b"b-value".to_vec()));
    // Parent still shows a's value because b hasn't committed.
    assert_eq!(parent.get(b"k").unwrap(), Some(b"a-value".to_vec()));
}

// === Stacking sessions ======================================================

/// SessionBackend itself implements KvBackend, so a session can wrap a
/// session can wrap a MemBackend. The "all-the-way-down" reads work and
/// commits propagate one level at a time.
#[test]
fn stacked_sessions_propagate_commits_one_level() {
    let base = mem();
    base.put(b"k", b"base").unwrap();
    let mid = Arc::new(SessionBackend::new(base.clone()));
    let top = SessionBackend::new(mid.clone() as Arc<dyn KvBackend>);

    top.put(b"k", b"from-top").unwrap();
    // top sees its own write.
    assert_eq!(top.get(b"k").unwrap(), Some(b"from-top".to_vec()));
    // mid sees only base.
    assert_eq!(mid.get(b"k").unwrap(), Some(b"base".to_vec()));

    // Commit top → its overlay flushes into mid (not base).
    top.commit().unwrap();
    assert_eq!(mid.get(b"k").unwrap(), Some(b"from-top".to_vec()));
    assert_eq!(base.get(b"k").unwrap(), Some(b"base".to_vec()));

    // Commit mid → finally reaches base.
    mid.commit().unwrap();
    assert_eq!(base.get(b"k").unwrap(), Some(b"from-top".to_vec()));
}

// === Larger-scale stress ====================================================

/// 1,000 distinct writes, commit, verify all visible in parent. Also
/// confirms HashMap-based pending doesn't drop entries.
#[test]
fn large_session_commits_all_pending_writes() {
    let parent = mem();
    let session = SessionBackend::new(parent.clone());
    for i in 0..1000u32 {
        session.put(&i.to_be_bytes(), &i.to_le_bytes()).unwrap();
    }
    assert_eq!(session.pending_len(), 1000);
    session.commit().unwrap();
    for i in 0..1000u32 {
        assert_eq!(parent.get(&i.to_be_bytes()).unwrap(), Some(i.to_le_bytes().to_vec()));
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
    store.put(&addr, &alice).unwrap();

    // Visible through the session-backed store.
    assert_eq!(store.get(&addr).unwrap().unwrap().balance, 1234);
    // NOT visible through a parent-backed store yet.
    let parent_store = AccountStore::new(parent.clone());
    assert!(parent_store.get(&addr).unwrap().is_none());

    // Commit via the typed handle (Arc<SessionBackend>).
    session_typed.commit().unwrap();

    // Now visible through parent.
    assert_eq!(parent_store.get(&addr).unwrap().unwrap().balance, 1234);
}

// === scan_all overlay semantics =============================================

#[test]
fn mem_backend_scan_all_returns_entries_in_byte_order() {
    let m = MemBackend::new();
    m.put(b"b", b"2").unwrap();
    m.put(b"a", b"1").unwrap();
    m.put(b"c", b"3").unwrap();
    let snap = m.scan_all().unwrap();
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
    parent.put(b"a", b"parent-a").unwrap();
    parent.put(b"b", b"parent-b").unwrap();
    let session = SessionBackend::new(parent.clone());
    session.put(b"a", b"session-a").unwrap();
    session.put(b"c", b"session-c").unwrap();

    let snap = session.scan_all().unwrap();
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
    parent.put(b"a", b"parent-a").unwrap();
    parent.put(b"b", b"parent-b").unwrap();
    let session = SessionBackend::new(parent);
    session.delete(b"a").unwrap();

    let snap = session.scan_all().unwrap();
    assert_eq!(snap, vec![(b"b".to_vec(), b"parent-b".to_vec())]);
}

#[test]
fn session_scan_all_after_revert_matches_parent() {
    let parent = mem();
    parent.put(b"a", b"parent-a").unwrap();
    let session = SessionBackend::new(parent);
    session.put(b"a", b"session-a").unwrap();
    session.delete(b"a").unwrap();
    session.put(b"b", b"session-b").unwrap();
    session.revert();

    let snap = session.scan_all().unwrap();
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
    backend.put(b"keep", b"original").unwrap();
    backend.put(b"replace-me", b"old").unwrap();
    backend.put(b"delete-me", b"goodbye").unwrap();

    let ops = vec![
        WriteOp::Put(b"new-key".to_vec(), b"new-value".to_vec()),
        WriteOp::Put(b"replace-me".to_vec(), b"new".to_vec()),
        WriteOp::Delete(b"delete-me".to_vec()),
    ];
    backend.write_batch(&ops).unwrap();

    assert_eq!(backend.get(b"keep").unwrap(), Some(b"original".to_vec()));
    assert_eq!(backend.get(b"new-key").unwrap(), Some(b"new-value".to_vec()));
    assert_eq!(backend.get(b"replace-me").unwrap(), Some(b"new".to_vec()));
    assert_eq!(backend.get(b"delete-me").unwrap(), None);
}

/// Empty op list is a no-op. `SessionBackend::commit` short-circuits
/// on empty pending; backend behaviour must match.
#[test]
fn write_batch_with_empty_ops_is_noop() {
    let backend = MemBackend::new();
    backend.put(b"a", b"unchanged").unwrap();
    backend.write_batch(&[]).unwrap();
    assert_eq!(backend.get(b"a").unwrap(), Some(b"unchanged".to_vec()));
    assert_eq!(backend.scan_all().unwrap().len(), 1);
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
    backend.write_batch(&ops).unwrap();
    assert_eq!(backend.get(b"k").unwrap(), Some(b"final".to_vec()));
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
    backend.put(b"a", b"old-a").unwrap();
    backend.put(b"b", b"old-b").unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let saw_torn = Arc::new(AtomicBool::new(false));

    let reader_backend = Arc::clone(&backend);
    let reader_stop = Arc::clone(&stop);
    let reader_torn = Arc::clone(&saw_torn);
    let reader = thread::spawn(move || {
        while !reader_stop.load(Ordering::Relaxed) {
            let snap: std::collections::HashMap<Vec<u8>, Vec<u8>> =
                reader_backend.scan_all().unwrap().into_iter().collect();
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
        backend
            .write_batch(&[
                WriteOp::Put(b"a".to_vec(), av),
                WriteOp::Put(b"b".to_vec(), bv),
            ])
            .unwrap();
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
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, tron_chainbase::KvError> {
            self.inner.get(key)
        }
        fn put(&self, key: &[u8], value: &[u8]) -> Result<(), tron_chainbase::KvError> {
            *self.per_call_writes.lock().unwrap() += 1;
            self.inner.put(key, value)
        }
        fn delete(&self, key: &[u8]) -> Result<(), tron_chainbase::KvError> {
            *self.per_call_writes.lock().unwrap() += 1;
            self.inner.delete(key)
        }
        fn scan_all(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, tron_chainbase::KvError> {
            self.inner.scan_all()
        }
        fn write_batch(&self, ops: &[WriteOp]) -> Result<(), tron_chainbase::KvError> {
            self.batches.lock().unwrap().push(ops.to_vec());
            self.inner.write_batch(ops)
        }
    }

    let parent = Arc::new(RecordingBackend {
        inner: MemBackend::new(),
        batches: Mutex::new(Vec::new()),
        per_call_writes: Mutex::new(0),
    });
    let session = SessionBackend::new(parent.clone() as Arc<dyn KvBackend>);
    session.put(b"a", b"1").unwrap();
    session.put(b"b", b"2").unwrap();
    session.delete(b"c").unwrap();
    session.commit().unwrap();

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
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, tron_chainbase::KvError> {
            self.inner.get(key)
        }
        fn put(&self, key: &[u8], value: &[u8]) -> Result<(), tron_chainbase::KvError> {
            self.inner.put(key, value)
        }
        fn delete(&self, key: &[u8]) -> Result<(), tron_chainbase::KvError> {
            self.inner.delete(key)
        }
        fn scan_all(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, tron_chainbase::KvError> {
            self.inner.scan_all()
        }
        fn write_batch(&self, ops: &[WriteOp]) -> Result<(), tron_chainbase::KvError> {
            *self.batch_calls.lock().unwrap() += 1;
            self.inner.write_batch(ops)
        }
    }

    let parent = Arc::new(CountingBackend {
        inner: MemBackend::new(),
        batch_calls: Mutex::new(0),
    });
    let session = SessionBackend::new(parent.clone() as Arc<dyn KvBackend>);
    session.commit().unwrap();
    assert_eq!(*parent.batch_calls.lock().unwrap(), 0);
}

/// `commit_with_undo` captures the parent's pre-image for every key
/// THEN applies the batch atomically. Pin both halves.
#[test]
fn commit_with_undo_captures_pre_image_then_applies_batch() {
    let parent = mem();
    parent.put(b"existing", b"pre-image").unwrap();
    parent.put(b"will-delete", b"goes-away").unwrap();
    let session = SessionBackend::new(parent.clone());
    session.put(b"existing", b"new-value").unwrap();
    session.delete(b"will-delete").unwrap();
    session.put(b"brand-new", b"first-write").unwrap();

    let undo = session.commit_with_undo().unwrap();

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

    assert_eq!(parent.get(b"existing").unwrap(), Some(b"new-value".to_vec()));
    assert_eq!(parent.get(b"will-delete").unwrap(), None);
    assert_eq!(parent.get(b"brand-new").unwrap(), Some(b"first-write".to_vec()));
}

// === drain_pending / drain_pending_with_undo ================================

/// `drain_pending` extracts pending writes WITHOUT touching the parent.
#[test]
fn drain_pending_returns_ops_without_writing_parent() {
    let parent = mem();
    parent.put(b"untouched", b"keep").unwrap();
    let session = SessionBackend::new(parent.clone());
    session.put(b"a", b"1").unwrap();
    session.delete(b"b").unwrap();
    session.put(b"c", b"3").unwrap();

    let ops = session.drain_pending();
    assert_eq!(ops.len(), 3);
    assert!(session.is_clean(), "drain clears pending");

    // Parent unchanged: drain isn't a commit.
    assert_eq!(parent.get(b"untouched").unwrap(), Some(b"keep".to_vec()));
    assert_eq!(parent.get(b"a").unwrap(), None);
    assert_eq!(parent.get(b"b").unwrap(), None);
    assert_eq!(parent.get(b"c").unwrap(), None);

    // Re-applying the ops via parent.write_batch reaches the same
    // final state a normal commit() would have produced.
    parent.write_batch(&ops).unwrap();
    let mut found = std::collections::HashSet::new();
    if parent.get(b"a").unwrap() == Some(b"1".to_vec()) { found.insert("a"); }
    if parent.get(b"c").unwrap() == Some(b"3".to_vec()) { found.insert("c"); }
    if parent.get(b"b").unwrap() == None { found.insert("b"); }
    assert_eq!(found.len(), 3);
}

/// `drain_pending_with_undo` captures pre-images BEFORE the caller
/// applies the batch (the pre-image must reflect parent state at
/// drain time, not afterwards).
#[test]
fn drain_pending_with_undo_captures_pre_images_at_drain_time() {
    let parent = mem();
    parent.put(b"existing", b"pre").unwrap();
    let session = SessionBackend::new(parent.clone());
    session.put(b"existing", b"new").unwrap();
    session.put(b"brand-new", b"first").unwrap();

    let (ops, undo) = session.drain_pending_with_undo().unwrap();
    assert_eq!(ops.len(), 2);
    assert_eq!(undo.len(), 2);
    // Parent still has the pre-image (drain hasn't committed).
    assert_eq!(parent.get(b"existing").unwrap(), Some(b"pre".to_vec()));

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
    let (ops, undo) = session.drain_pending_with_undo().unwrap();
    assert!(ops.is_empty());
    assert!(undo.is_empty());
}

// === write_batch_sync default delegation ====================================

/// The default `write_batch_sync` impl on `KvBackend` delegates to
/// `write_batch`. MemBackend doesn't override it (no persistent
/// storage to fsync), so this pins that delegation is in place —
/// callers that switch from `write_batch` to `write_batch_sync` for
/// durability get the same observable state from a memory backend.
#[test]
fn write_batch_sync_default_matches_write_batch_on_mem_backend() {
    let async_be = MemBackend::new();
    let sync_be = MemBackend::new();
    let ops = vec![
        WriteOp::Put(b"a".to_vec(), b"1".to_vec()),
        WriteOp::Delete(b"missing".to_vec()),
        WriteOp::Put(b"b".to_vec(), b"2".to_vec()),
    ];
    async_be.write_batch(&ops).unwrap();
    sync_be.write_batch_sync(&ops).unwrap();
    assert_eq!(async_be.scan_all().unwrap(), sync_be.scan_all().unwrap());
}

// === Bounded scans over a parent that doesn't support scan_all ==============
// Mirrors the at-height archive view (`ArchiveAtBackend`): point + bounded
// scans work, but unbounded `scan_all` is deliberately unsupported. A session
// over such a parent must serve `scan_from`/`scan_prefix` by delegating to the
// parent's native bounded scan, NOT by routing through `scan_all` (which would
// error — the bug this fixes).

/// A parent that serves get/put/delete/scan_from/scan_prefix from an inner
/// backend but ERRORS on `scan_all`.
struct ScanAllUnsupported(Arc<dyn KvBackend>);

impl KvBackend for ScanAllUnsupported {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, tron_chainbase::KvError> {
        self.0.get(key)
    }
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), tron_chainbase::KvError> {
        self.0.put(key, value)
    }
    fn delete(&self, key: &[u8]) -> Result<(), tron_chainbase::KvError> {
        self.0.delete(key)
    }
    fn scan_all(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, tron_chainbase::KvError> {
        Err(tron_chainbase::KvError::Backend("scan_all unsupported".into()))
    }
    fn scan_from(
        &self,
        start: &[u8],
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, tron_chainbase::KvError> {
        self.0.scan_from(start, limit)
    }
    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, tron_chainbase::KvError> {
        self.0.scan_prefix(prefix)
    }
}

fn seeded_scan_all_unsupported(n: u8) -> Arc<dyn KvBackend> {
    let inner = mem();
    for i in 0..n {
        inner.put(&[0x41, i], &[i]).unwrap();
    }
    Arc::new(ScanAllUnsupported(inner))
}

#[test]
fn bounded_scans_work_over_a_scan_all_unsupported_parent() {
    // Regression: a session over a scan_all-erroring parent used to error on
    // scan_from/scan_prefix (they routed through scan_all). Now they succeed.
    let session = SessionBackend::new(seeded_scan_all_unsupported(10));

    assert!(session.scan_all().is_err(), "scan_all still errors (unchanged)");

    let from = session.scan_from(&[0x41, 3], 4).unwrap();
    assert_eq!(
        from.iter().map(|(k, _)| k[1]).collect::<Vec<_>>(),
        vec![3, 4, 5, 6]
    );
    assert_eq!(session.scan_prefix(&[0x41]).unwrap().len(), 10);
}

#[test]
fn bounded_scans_merge_overlay_over_scan_all_unsupported_parent() {
    // Dirty overlay over the same parent: a shadow, a delete, and a new
    // in-prefix key must all be reflected without ever calling scan_all.
    let session = SessionBackend::new(seeded_scan_all_unsupported(10));
    session.put(&[0x41, 4], &[0xff]).unwrap(); // shadow parent key 4
    session.delete(&[0x41, 6]).unwrap(); // delete parent key 6
    session.put(&[0x41, 20], &[0x20]).unwrap(); // new key

    let pre = session.scan_prefix(&[0x41]).unwrap();
    assert_eq!(pre.len(), 10, "10 - 1 deleted + 1 new");
    assert_eq!(
        pre.iter().find(|(k, _)| k[1] == 4).unwrap().1,
        vec![0xff],
        "overlay shadows the parent value"
    );
    assert!(pre.iter().all(|(k, _)| k[1] != 6), "deleted key is gone");
    assert!(pre.iter().any(|(k, _)| k[1] == 20), "new overlay key present");
}

#[test]
fn scan_from_limit_is_exact_when_overlay_deletes_in_range() {
    // A delete of an in-range parent key must not shrink the result below
    // `limit`: the `limit + deletes` over-fetch pulls the next survivor.
    let parent = mem();
    for i in 0u8..10 {
        parent.put(&[0x41, i], &[i]).unwrap();
    }
    let session = SessionBackend::new(parent);
    session.delete(&[0x41, 2]).unwrap();

    let got = session.scan_from(&[0x41, 0], 3).unwrap();
    // Without the over-fetch this would be [0,1] (2 deleted, limit under-filled).
    assert_eq!(got.iter().map(|(k, _)| k[1]).collect::<Vec<_>>(), vec![0, 1, 3]);
}

#[test]
fn clean_session_scan_from_matches_parent() {
    // A never-written session delegates the bounded scan straight to the
    // parent (the O(log n) fast path that also lets an at-height parent serve).
    let parent = mem();
    for i in 0u8..5 {
        parent.put(&[0x41, i], &[i]).unwrap();
    }
    let session = SessionBackend::new(parent.clone());
    assert_eq!(
        session.scan_from(&[0x41, 1], 2).unwrap(),
        parent.scan_from(&[0x41, 1], 2).unwrap()
    );
}
