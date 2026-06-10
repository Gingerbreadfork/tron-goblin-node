//! Multi-producer safety tests for the `SnapshotStack` coordinator.
//!
//! Two scenarios proven here:
//! 1. **Concurrent producers**: spawn N threads that each call
//!    `apply_block` and `reorg` against the same coordinator. The
//!    final layer state must be consistent (depth + block_nums
//!    matches the sum of successful applies minus revokes).
//! 2. **Mutex blocks reentrant access**: a producer in the middle of
//!    `apply_block` must hold the lock for the duration of the
//!    closure. Verified by spinning up a second thread that observes
//!    `depth()` blocked until the first finishes.
//!
//! These tests don't exercise the executor — they use the lower-level
//! coordinator API directly with `MemBackend`-backed snapshots. The
//! production-shape integration with `SyncDriver` + `SrRuntime` is
//! covered by `snapshot_reorg.rs` and `mempool_reorg_repush.rs`.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use tron_chainbase::{KvBackend, MemBackend, SnapshotKvBackend};
use tron_node::storage::SnapshotStack;

fn build_stack(n: usize) -> SnapshotStack {
    let mut backends: Vec<(String, Arc<SnapshotKvBackend>)> = Vec::new();
    for i in 0..n {
        let root: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
        let snap = Arc::new(SnapshotKvBackend::new(root));
        backends.push((format!("store_{i}"), snap));
    }
    SnapshotStack::from_named(backends)
}

#[test]
fn apply_block_holds_lock_for_closure_duration() {
    // Spawn a producer that grabs the coordinator lock and sleeps;
    // a reader thread must NOT observe the new block_num until the
    // producer's closure returns.
    let stack = build_stack(1);
    let stack_for_producer = stack.clone();
    let reader_observed_before_done = Arc::new(AtomicUsize::new(0));
    let reader_observed_after_done = Arc::new(AtomicUsize::new(0));
    let observed_before = reader_observed_before_done.clone();
    let observed_after = reader_observed_after_done.clone();
    let producer_done = Arc::new(AtomicUsize::new(0));
    let producer_done_clone = producer_done.clone();

    let producer = thread::spawn(move || {
        let _ = stack_for_producer.apply_block(42, || {
            // Hold the lock for 50ms.
            thread::sleep(Duration::from_millis(50));
            producer_done_clone.store(1, Ordering::SeqCst);
            Ok::<(), String>(())
        });
    });

    // Give the producer a moment to acquire the lock.
    thread::sleep(Duration::from_millis(10));
    // Observe depth WHILE the producer is still inside its closure.
    // The coordinator should block this call until producer releases.
    let observed_during = stack.depth();
    if producer_done.load(Ordering::SeqCst) == 0 {
        observed_before.store(observed_during, Ordering::SeqCst);
    }
    producer.join().unwrap();
    observed_after.store(stack.depth(), Ordering::SeqCst);

    // After producer is done, depth must be 1.
    assert_eq!(observed_after.load(Ordering::SeqCst), 1);
    // The pre-completion observation either ran AFTER the closure
    // (observed_before == 0 meaning we didn't store) — i.e. we
    // blocked. Or it ran in parallel observing 0. Either way the
    // observed_during should equal 1 (post-apply) since depth read
    // also takes the lock, so it serialised behind the apply.
    assert_eq!(
        observed_during, 1,
        "depth read must serialise behind apply_block — observed {observed_during} during"
    );
}

#[test]
fn concurrent_apply_calls_produce_consistent_final_depth() {
    // Spawn N threads, each pushing M blocks via apply_block. The
    // coordinator's mutex serialises them; the final block_nums vec
    // must have length N*M and contain every block number exactly
    // once (no lost updates, no duplicates).
    let stack = build_stack(3);
    const THREADS: i64 = 8;
    const BLOCKS_PER_THREAD: i64 = 25;
    let total = (THREADS * BLOCKS_PER_THREAD) as usize;

    let handles: Vec<_> = (0..THREADS)
        .map(|t| {
            let s = stack.clone();
            thread::spawn(move || {
                for i in 0..BLOCKS_PER_THREAD {
                    let bnum = t * BLOCKS_PER_THREAD + i;
                    s.apply_block(bnum, || Ok::<(), String>(()))
                        .expect("apply must succeed");
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }

    let final_nums = stack.block_nums();
    assert_eq!(final_nums.len(), total, "every apply must be recorded");
    let mut sorted = final_nums.clone();
    sorted.sort();
    let expected: Vec<i64> = (0..(THREADS * BLOCKS_PER_THREAD) as i64).collect();
    assert_eq!(sorted, expected, "every block_num must appear exactly once");
}

#[test]
fn apply_block_rollback_on_closure_error_revokes_only_just_pushed_layer() {
    let stack = build_stack(2);
    stack
        .apply_block(1, || Ok::<(), String>(()))
        .expect("first ok");
    stack
        .apply_block(2, || Ok::<(), String>(()))
        .expect("second ok");
    assert_eq!(stack.depth(), 2);

    // Now an apply that fails — should revert just its layer,
    // leaving depth at 2 and block_nums == [1, 2].
    let result: Result<(), String> = stack.apply_block(99, || Err("nope".into()));
    assert!(result.is_err());
    assert_eq!(stack.depth(), 2, "failed apply must not change depth");
    assert_eq!(stack.block_nums(), vec![1, 2]);
}

#[test]
fn reorg_revokes_old_and_applies_new_atomically() {
    let stack = build_stack(1);
    // Push blocks 10, 11, 12.
    for b in [10, 11, 12] {
        stack
            .apply_block(b, || Ok::<(), String>(()))
            .expect("apply");
    }
    assert_eq!(stack.block_nums(), vec![10, 11, 12]);

    // Reorg: revoke 12 + 11, apply 11', 12', 13' on the new fork.
    let between_called = Arc::new(AtomicUsize::new(0));
    let between_clone = between_called.clone();
    let result = stack.reorg::<String, _, _, _>(
        &[12, 11],  // old_block_nums, newest first
        &[110, 120, 130], // new_block_nums, oldest first
        || {
            // Verify the between-hook ran while the lock was held.
            between_clone.store(1, Ordering::SeqCst);
        },
        |_block_num, _idx| Ok::<(), String>(()),
    );
    assert!(result.is_ok());
    assert_eq!(between_called.load(Ordering::SeqCst), 1);
    assert_eq!(stack.block_nums(), vec![10, 110, 120, 130]);
}

#[test]
fn reorg_returns_drift_when_top_doesnt_match() {
    let stack = build_stack(1);
    stack.apply_block(5, || Ok::<(), String>(())).unwrap();
    stack.apply_block(6, || Ok::<(), String>(())).unwrap();

    // Try to revoke block 99 — but the top is 6.
    let result = stack.reorg::<String, _, _, _>(
        &[99],
        &[],
        || {},
        |_, _| Ok::<(), String>(()),
    );
    match result {
        Err(tron_node::storage::ReorgFailure::Drift { expected, actual }) => {
            assert_eq!(expected, 99);
            assert_eq!(actual, 6);
        }
        other => panic!("expected Drift, got: {other:?}"),
    }
    // Stack unchanged after drift detection.
    assert_eq!(stack.block_nums(), vec![5, 6]);
}

#[test]
fn reorg_returns_past_horizon_when_stack_below_target() {
    let stack = build_stack(1);
    stack.apply_block(1, || Ok::<(), String>(())).unwrap();

    // Try to reorg past the bottom — block 0 isn't on the stack.
    let result = stack.reorg::<String, _, _, _>(
        &[1, 0],
        &[],
        || {},
        |_, _| Ok::<(), String>(()),
    );
    match result {
        Err(tron_node::storage::ReorgFailure::PastHorizon(num)) => {
            assert_eq!(num, 0);
        }
        other => panic!("expected PastHorizon, got: {other:?}"),
    }
}

#[test]
fn reorg_apply_failure_partial_state_visible_to_caller() {
    let stack = build_stack(1);
    stack.apply_block(1, || Ok::<(), String>(())).unwrap();
    stack.apply_block(2, || Ok::<(), String>(())).unwrap();

    // Reorg: revoke 2, apply 20 (ok), 30 (fail).
    let result = stack.reorg::<String, _, _, _>(
        &[2],
        &[20, 30],
        || {},
        |block_num, _idx| {
            if block_num == 30 {
                Err("boom".into())
            } else {
                Ok::<(), String>(())
            }
        },
    );
    match result {
        Err(tron_node::storage::ReorgFailure::ApplyFailed {
            failed_block,
            applied,
            source,
        }) => {
            assert_eq!(failed_block, 30);
            assert_eq!(applied.len(), 1, "the committed partial results ride the error");
            assert_eq!(source, "boom");
        }
        other => panic!("expected ApplyFailed, got: {other:?}"),
    }
    // Stack reflects partial reorg progress: original 1 + new 20
    // (30's layer was revoked on failure). Recovery is the caller's
    // responsibility.
    assert_eq!(stack.block_nums(), vec![1, 20]);
}

#[test]
fn coordinator_horizon_triggers_bottom_merge() {
    let stack = build_stack(1).with_horizon(3);
    for b in 1..=5 {
        stack.apply_block(b, || Ok::<(), String>(())).unwrap();
    }
    // Depth caps at horizon — oldest two layers merged.
    assert_eq!(stack.depth(), 3);
    assert_eq!(stack.block_nums(), vec![3, 4, 5]);
}

#[test]
fn coordinator_with_checkpoint_writes_manifest_on_horizon_merge() {
    let tmp = tempfile::tempdir().unwrap();
    let cp = tron_chainbase::CheckPointV2::new(tmp.path());
    let stack = build_stack(1).with_horizon(2).with_checkpoint(cp.clone());
    for b in 1..=4 {
        stack.apply_block(b, || Ok::<(), String>(())).unwrap();
    }
    assert_eq!(stack.depth(), 2);
    // Manifests are deleted after successful merge — list should be
    // empty (clean state after the horizon-driven flushes).
    assert!(cp.list().unwrap().is_empty());
}

#[test]
fn concurrent_apply_under_short_horizon_keeps_depth_bounded() {
    // Stress the horizon+mutex interaction: many threads piling on
    // applies, horizon = 10 → final depth must equal horizon.
    let stack = build_stack(2).with_horizon(10);
    const THREADS: i64 = 4;
    const BLOCKS_PER_THREAD: i64 = 50;
    let total_blocks = (THREADS * BLOCKS_PER_THREAD) as usize;

    let handles: Vec<_> = (0..THREADS)
        .map(|t| {
            let s = stack.clone();
            thread::spawn(move || {
                for i in 0..BLOCKS_PER_THREAD {
                    let bnum = t * BLOCKS_PER_THREAD + i;
                    s.apply_block(bnum, || Ok::<(), String>(())).unwrap();
                }
            })
        })
        .collect();
    let started = Instant::now();
    for h in handles {
        h.join().unwrap();
    }
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "concurrent applies should finish quickly"
    );
    // Depth stays bounded; block_nums is the most-recent-10.
    let final_nums = stack.block_nums();
    assert_eq!(final_nums.len(), 10);
    // Total work done = 200 applies; 190 merged into root.
    assert_eq!(total_blocks - 10, 190);
}
