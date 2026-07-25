//! `ForkOverlay` mechanics over `MemBackend` — isolation, accumulation,
//! checkpoint/revert, diffing, key-cap accounting, and historical-base
//! coverage gating. The deeper at-height read-through behavior is covered
//! by the RPC integration suite against the real archive harness; here we
//! prove the overlay-stacking core in isolation.

use std::sync::Arc;

use tron_chainbase::{KvBackend, MemBackend, UndoStoreId};
use tron_index::{ArchiveReader, ArchiveWriter, DeltaRef};
use tron_sim::{BaseBlock, ForkBackends, ForkOverlay, SimError};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

/// Fresh fork backends over independent in-memory stores. Returns the
/// `code` backend too, so tests can assert the live store stays untouched.
fn backends() -> (ForkBackends, Arc<dyn KvBackend>) {
    let code = mem();
    let fb = ForkBackends {
        accounts: mem(),
        code: code.clone(),
        storage: mem(),
        witnesses: mem(),
        contract_state: mem(),
        dyn_props: mem(),
        delegated_resources: mem(),
        delegation: mem(),
        contracts: mem(),
        votes: Some(mem()),
        abi: Some(mem()),
        block_index: Some(mem()),
    };
    (fb, code)
}

const K1: &[u8] = b"\x41\x01";
const K2: &[u8] = b"\x41\x02";

#[test]
fn latest_overlay_write_is_isolated_from_live() {
    let (fb, live_code) = backends();
    let ov = ForkOverlay::new(&fb, None).unwrap();
    assert_eq!(ov.base(), BaseBlock::Latest);

    ov.vm_stores().code.put(K1, b"payload").unwrap();

    // Visible through the overlay (a freshly built VmStores wraps the same
    // top session).
    assert_eq!(
        ov.vm_stores().code.get(K1).unwrap().as_deref(),
        Some(&b"payload"[..])
    );
    // The live backend never saw it.
    assert_eq!(live_code.get(K1).unwrap(), None);
}

#[test]
fn overlay_write_accumulates_across_calls() {
    let (fb, _live) = backends();
    let ov = ForkOverlay::new(&fb, None).unwrap();

    ov.vm_stores().code.put(K1, b"a").unwrap();
    ov.vm_stores().code.put(K2, b"b").unwrap();

    let vm = ov.vm_stores();
    assert_eq!(vm.code.get(K1).unwrap().as_deref(), Some(&b"a"[..]));
    assert_eq!(vm.code.get(K2).unwrap().as_deref(), Some(&b"b"[..]));
}

#[test]
fn checkpoint_and_revert() {
    let (fb, _live) = backends();
    let mut ov = ForkOverlay::new(&fb, None).unwrap();

    ov.vm_stores().code.put(K1, b"one").unwrap();
    let cp = ov.checkpoint();
    ov.vm_stores().code.put(K2, b"two").unwrap();
    assert_eq!(ov.vm_stores().code.get(K2).unwrap().as_deref(), Some(&b"two"[..]));

    ov.revert_to(cp);
    // Everything written after the checkpoint is gone.
    assert_eq!(ov.vm_stores().code.get(K2).unwrap(), None);
    // Everything written before it survives.
    assert_eq!(ov.vm_stores().code.get(K1).unwrap().as_deref(), Some(&b"one"[..]));
}

#[test]
fn nested_checkpoints_revert_independently() {
    let (fb, _live) = backends();
    let mut ov = ForkOverlay::new(&fb, None).unwrap();

    ov.vm_stores().code.put(K1, b"1").unwrap();
    let cp1 = ov.checkpoint();
    ov.vm_stores().code.put(K2, b"2").unwrap();
    let cp2 = ov.checkpoint();
    ov.vm_stores().code.put(b"\x41\x03", b"3").unwrap();

    // Revert to the inner checkpoint: only K3 disappears.
    ov.revert_to(cp2);
    assert_eq!(ov.vm_stores().code.get(b"\x41\x03").unwrap(), None);
    assert_eq!(ov.vm_stores().code.get(K2).unwrap().as_deref(), Some(&b"2"[..]));

    // Revert to the outer checkpoint: K2 disappears too, K1 remains.
    ov.revert_to(cp1);
    assert_eq!(ov.vm_stores().code.get(K2).unwrap(), None);
    assert_eq!(ov.vm_stores().code.get(K1).unwrap().as_deref(), Some(&b"1"[..]));
}

#[test]
fn cumulative_diff_reflects_new_write() {
    let (fb, _live) = backends();
    let ov = ForkOverlay::new(&fb, None).unwrap();

    ov.vm_stores().code.put(K1, b"v").unwrap();

    let d = ov.cumulative_diff().unwrap();
    assert_eq!(d.len(), 1);
    assert_eq!(d.code.len(), 1);
    assert_eq!(d.code[0].0, K1.to_vec());
    assert_eq!(d.code[0].1, None); // before: absent
    assert_eq!(d.code[0].2, Some(b"v".to_vec())); // after
}

#[test]
fn cumulative_diff_reports_before_when_base_had_the_key() {
    let (fb, live_code) = backends();
    live_code.put(K1, b"old").unwrap();
    let ov = ForkOverlay::new(&fb, None).unwrap();

    ov.vm_stores().code.put(K1, b"new").unwrap();

    let d = ov.cumulative_diff().unwrap();
    assert_eq!(d.code.len(), 1);
    assert_eq!(d.code[0].1, Some(b"old".to_vec()));
    assert_eq!(d.code[0].2, Some(b"new".to_vec()));
}

#[test]
fn diff_filters_noop_writes_but_overlay_keys_counts_the_touch() {
    let (fb, live_code) = backends();
    live_code.put(K1, b"same").unwrap();
    let ov = ForkOverlay::new(&fb, None).unwrap();

    // Write the identical value back.
    ov.vm_stores().code.put(K1, b"same").unwrap();

    // No net change → not in the diff.
    assert!(ov.cumulative_diff().unwrap().is_empty());
    // But the write did happen → counted against the overlay cap.
    assert_eq!(ov.overlay_keys(), 1);
}

#[test]
fn diff_since_only_shows_post_checkpoint_writes() {
    let (fb, _live) = backends();
    let mut ov = ForkOverlay::new(&fb, None).unwrap();

    ov.vm_stores().code.put(K1, b"one").unwrap();
    let cp = ov.checkpoint();
    ov.vm_stores().code.put(K2, b"two").unwrap();

    let since = ov.diff_since(cp).unwrap();
    assert_eq!(since.code.len(), 1);
    assert_eq!(since.code[0].0, K2.to_vec());

    // The cumulative diff still shows both.
    assert_eq!(ov.cumulative_diff().unwrap().code.len(), 2);
}

#[test]
fn overlay_keys_counts_writes() {
    let (fb, _live) = backends();
    let ov = ForkOverlay::new(&fb, None).unwrap();
    assert_eq!(ov.overlay_keys(), 0);

    ov.vm_stores().code.put(K1, b"a").unwrap();
    ov.vm_stores().code.put(K2, b"b").unwrap();
    assert_eq!(ov.overlay_keys(), 2);
}

#[test]
fn height_base_with_no_coverage_errors() {
    let reader = ArchiveReader::new(mem());
    let (fb, _live) = backends();
    match ForkOverlay::new(&fb, Some((&reader, 10))) {
        Err(SimError::NoCoverage) => {}
        Err(other) => panic!("expected NoCoverage, got {other:?}"),
        Ok(_) => panic!("expected NoCoverage, got Ok"),
    }
}

#[test]
fn height_base_coverage_gating() {
    // Establish coverage by applying one block through the writer.
    let w = ArchiveWriter::new(mem(), None, Vec::new());
    assert!(w.check_or_init().unwrap());
    let deltas = vec![DeltaRef {
        store: UndoStoreId::Code,
        key: K1,
        before: None,
        after: Some(b"x"),
    }];
    w.on_block_applied(10, Some(&deltas)).unwrap();
    let reader = w.reader();
    let (base, head) = reader.coverage().unwrap().expect("coverage established");

    let (fb, _live) = backends();

    // Below the window → OutOfCoverage carrying the exact window.
    match ForkOverlay::new(&fb, Some((&reader, base - 1))) {
        Err(SimError::OutOfCoverage { height, base: b, head: h }) => {
            assert_eq!(height, base - 1);
            assert_eq!(b, base);
            assert_eq!(h, head);
        }
        Err(other) => panic!("expected OutOfCoverage, got {other:?}"),
        Ok(_) => panic!("expected OutOfCoverage, got Ok"),
    }

    // Inside the window → constructs; a height base seeds head number = N.
    let ov = ForkOverlay::new(&fb, Some((&reader, head))).unwrap();
    assert_eq!(ov.base(), BaseBlock::Height(head));
    assert_eq!(ov.seed_head().0, head);
}

#[test]
fn height_base_overlay_writes_stay_isolated() {
    let w = ArchiveWriter::new(mem(), None, Vec::new());
    assert!(w.check_or_init().unwrap());
    let deltas = vec![DeltaRef {
        store: UndoStoreId::Code,
        key: K1,
        before: None,
        after: Some(b"archived"),
    }];
    w.on_block_applied(10, Some(&deltas)).unwrap();
    let reader = w.reader();
    let (_, head) = reader.coverage().unwrap().unwrap();

    let (fb, live_code) = backends();
    let ov = ForkOverlay::new(&fb, Some((&reader, head))).unwrap();

    // The archived value reads through the at-height base.
    assert_eq!(ov.vm_stores().code.get(K1).unwrap().as_deref(), Some(&b"archived"[..]));

    // Overlay write over an at-height base is buffered, never reaching the
    // (read-only) archive or the live store.
    ov.vm_stores().code.put(K2, b"fork-only").unwrap();
    assert_eq!(ov.vm_stores().code.get(K2).unwrap().as_deref(), Some(&b"fork-only"[..]));
    assert_eq!(live_code.get(K2).unwrap(), None);
    // And an overlay write can shadow the archived value without mutating it.
    ov.vm_stores().code.put(K1, b"shadow").unwrap();
    assert_eq!(ov.vm_stores().code.get(K1).unwrap().as_deref(), Some(&b"shadow"[..]));
}
