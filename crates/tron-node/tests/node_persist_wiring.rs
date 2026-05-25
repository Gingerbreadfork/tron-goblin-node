//! Integration test for the discovery-persist wire-up.
//!
//! The runtime ties `NodePersistService` to `stores.common` and a
//! periodic flush task. Direct tests of `runtime::run` are awkward
//! (it owns a tokio runtime + a hundred handles), so this test
//! exercises the same surface the runtime depends on:
//!
//!   1. Persist a discovery set via [`NodePersistService::write_batch`].
//!   2. Re-open the `CommonStore` against the same backend.
//!   3. Read back via [`NodePersistService::read`] — set is preserved.
//!
//! Plus a single duplex of the periodic-flush helper to confirm a
//! sequence of `write_batch` calls overwrites prior state correctly.

use std::sync::Arc;

use tron_chainbase::{CommonStore, KvBackend, MemBackend};
use tron_node::node_persist::{DbNode, NodePersistService};

fn shared_mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

#[test]
fn write_then_reopen_then_read_round_trip_through_common_store() {
    let backend = shared_mem();
    // First "run": persist some peers.
    {
        let store = Arc::new(CommonStore::new(backend.clone()));
        let svc = NodePersistService::new(store, true);
        let batch = vec![
            DbNode::new("10.0.0.1", 18888),
            DbNode::new("10.0.0.2", 18888),
            DbNode::new("10.0.0.3", 18888),
        ];
        let written = svc.write_batch(&batch);
        assert_eq!(written, 3);
    }
    // Second "run": fresh service over the same backend reads them back.
    {
        let store = Arc::new(CommonStore::new(backend.clone()));
        let svc = NodePersistService::new(store, true);
        let back = svc.read();
        assert_eq!(back.len(), 3);
        assert_eq!(back[0].host, "10.0.0.1");
        assert_eq!(back[2].port, 18888);
    }
}

#[test]
fn second_write_replaces_first_write() {
    let backend = shared_mem();
    let store = Arc::new(CommonStore::new(backend.clone()));
    let svc = NodePersistService::new(store, true);
    svc.write_batch(&[
        DbNode::new("a", 1),
        DbNode::new("b", 2),
        DbNode::new("c", 3),
    ]);
    // Second write with fewer peers — must overwrite, not append.
    svc.write_batch(&[DbNode::new("d", 4)]);
    let back = svc.read();
    assert_eq!(back, vec![DbNode::new("d", 4)]);
}

#[test]
fn disabled_service_does_not_read_or_write_when_flag_off() {
    let backend = shared_mem();
    // First write with persist ENABLED.
    {
        let svc = NodePersistService::new(
            Arc::new(CommonStore::new(backend.clone())),
            true,
        );
        svc.write_batch(&[DbNode::new("1.1.1.1", 18888)]);
    }
    // Then a service with persist DISABLED — even though the bytes
    // are on disk, read() returns empty (operator opted out).
    let svc = NodePersistService::new(
        Arc::new(CommonStore::new(backend.clone())),
        false,
    );
    assert!(svc.read().is_empty());
    // And write_batch is a hard no-op — the on-disk bytes are left
    // intact (next time persist is re-enabled, the old set should
    // come back).
    let written = svc.write_batch(&[DbNode::new("2.2.2.2", 18888)]);
    assert_eq!(written, 0);
    // Re-enable and confirm the original write is still there.
    let svc2 = NodePersistService::new(
        Arc::new(CommonStore::new(backend.clone())),
        true,
    );
    let back = svc2.read();
    assert_eq!(back, vec![DbNode::new("1.1.1.1", 18888)]);
}

#[test]
fn write_then_disabled_read_then_re_enabled_read_returns_original() {
    // Edge case mirroring an operator toggling
    // `node.discovery.persist` between restarts: writes performed
    // while the flag is on must still be readable next time the flag
    // is on again, with no leakage when it's off in between.
    let backend = shared_mem();
    let original = vec![
        DbNode::new("10.0.0.1", 18888),
        DbNode::new("10.0.0.2", 18888),
    ];
    NodePersistService::new(
        Arc::new(CommonStore::new(backend.clone())),
        true,
    )
    .write_batch(&original);

    // Run with flag off → no read.
    assert!(
        NodePersistService::new(
            Arc::new(CommonStore::new(backend.clone())),
            false,
        )
        .read()
        .is_empty()
    );

    // Run with flag on → see the original set.
    assert_eq!(
        NodePersistService::new(
            Arc::new(CommonStore::new(backend.clone())),
            true,
        )
        .read(),
        original
    );
}
