//! Discovery-table persistence.
//!
//! Mirrors java-tron's `NodePersistService`: every minute, write the
//! current discovery table (up to `MAX_NODES_WRITE_TO_DB`) into a
//! single JSON blob keyed by `"peers"` in `CommonStore`. On restart
//! `read()` returns the cached set so the bootstrap path can re-dial
//! the last-known good peers instead of starting from the hard-coded
//! seed list.
//!
//! The on-disk JSON shape matches java-tron's `DBNodes`/`DBNode` so a
//! database produced by one implementation can be opened by the other.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tron_chainbase::CommonStore;

/// Java-tron's hard limit on the persisted peer set.
pub const MAX_NODES_WRITE_TO_DB: usize = 30;

/// Java-tron's default flush interval. Override via the
/// [`NodePersistService::new`] constructor in tests.
pub const DEFAULT_COMMIT_RATE: Duration = Duration::from_secs(60);

/// Key under which the JSON blob is written. `CommonStore` is the
/// same store java-tron uses (`commonStore.get("peers")`).
pub const DB_KEY_PEERS: &[u8] = b"peers";

/// One persisted peer. Wire-compatible JSON with java-tron's
/// `DBNode`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbNode {
    pub host: String,
    pub port: u16,
}

impl DbNode {
    pub fn new<H: Into<String>>(host: H, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }
}

/// JSON envelope: `{"nodes": [...]}`. Matches java-tron's `DBNodes`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DbNodes {
    #[serde(default)]
    pub nodes: Vec<DbNode>,
}

/// Read/write the persisted set against a [`CommonStore`].
#[derive(Clone)]
pub struct NodePersistService {
    store: Arc<CommonStore>,
    /// java-tron `nodeDiscoveryPersist` flag — when `false`, [`write_batch`]
    /// is a no-op and [`read`] returns an empty list (the operator
    /// opted out).
    enabled: bool,
    /// How often the host runtime should flush. Pure data — this
    /// struct doesn't spawn a scheduler itself; the host wires
    /// [`write_batch`] into its own tokio interval.
    pub commit_rate: Duration,
    /// Hard cap on persisted set size.
    pub max_nodes: usize,
}

impl NodePersistService {
    pub fn new(store: Arc<CommonStore>, enabled: bool) -> Self {
        Self {
            store,
            enabled,
            commit_rate: DEFAULT_COMMIT_RATE,
            max_nodes: MAX_NODES_WRITE_TO_DB,
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Restore the persisted peer set. Returns `[]` when:
    /// * persistence is disabled,
    /// * the key isn't present,
    /// * the stored blob is empty or fails to deserialize (we treat
    ///   on-disk corruption as "no cached peers" rather than failing
    ///   startup).
    pub fn read(&self) -> Vec<DbNode> {
        if !self.enabled {
            return Vec::new();
        }
        let Some(bytes) = self.store.get(DB_KEY_PEERS) else {
            return Vec::new();
        };
        if bytes.is_empty() {
            return Vec::new();
        }
        match serde_json::from_slice::<DbNodes>(&bytes) {
            Ok(dbn) => dbn.nodes,
            Err(_) => Vec::new(),
        }
    }

    /// Persist up to `max_nodes` of `batch`. The caller is expected
    /// to have already ordered by recency (java-tron sorts by
    /// `updateTime DESC`); we just take the first slice.
    ///
    /// Returns the count actually written. A `false` enabled flag is
    /// a hard no-op (`Ok(0)`); the on-disk blob is left as-is.
    pub fn write_batch(&self, batch: &[DbNode]) -> usize {
        if !self.enabled {
            return 0;
        }
        let take = batch.len().min(self.max_nodes);
        let envelope = DbNodes {
            nodes: batch[..take].to_vec(),
        };
        let json = serde_json::to_vec(&envelope).expect("DbNodes never serializes to err");
        self.store.put(DB_KEY_PEERS, &json);
        take
    }
}

/// Run a periodic flush loop. Long-running; cancellable by dropping
/// the receiver attached to `peers_fn`. Pure-async wrapper around
/// [`NodePersistService::write_batch`]; callers that want different
/// scheduling can build their own loop with the same method.
pub async fn run_periodic_flush<F>(svc: NodePersistService, mut peers_fn: F)
where
    F: FnMut() -> Vec<DbNode> + Send + 'static,
{
    if !svc.enabled {
        return;
    }
    let mut ticker = tokio::time::interval(svc.commit_rate);
    ticker.tick().await; // discard the immediate tick
    loop {
        ticker.tick().await;
        let snap = peers_fn();
        let _ = svc.write_batch(&snap);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tron_chainbase::MemBackend;

    fn fresh() -> NodePersistService {
        let backend: Arc<dyn tron_chainbase::KvBackend> = Arc::new(MemBackend::new());
        let store = Arc::new(CommonStore::new(backend));
        NodePersistService::new(store, true)
    }

    #[test]
    fn read_returns_empty_when_nothing_written() {
        let svc = fresh();
        assert!(svc.read().is_empty());
    }

    #[test]
    fn round_trip_preserves_set() {
        let svc = fresh();
        let batch = vec![
            DbNode::new("1.2.3.4", 18888),
            DbNode::new("5.6.7.8", 18888),
        ];
        assert_eq!(svc.write_batch(&batch), 2);
        let back = svc.read();
        assert_eq!(back, batch);
    }

    #[test]
    fn write_caps_at_max_nodes() {
        let svc = fresh();
        let batch: Vec<DbNode> = (0..50)
            .map(|i| DbNode::new(format!("10.0.0.{i}"), 18888))
            .collect();
        let written = svc.write_batch(&batch);
        assert_eq!(written, MAX_NODES_WRITE_TO_DB);
        let back = svc.read();
        assert_eq!(back.len(), MAX_NODES_WRITE_TO_DB);
        // Keeps the leading (most-recent) slice.
        assert_eq!(back[0].host, "10.0.0.0");
    }

    #[test]
    fn disabled_service_is_a_no_op() {
        let backend: Arc<dyn tron_chainbase::KvBackend> = Arc::new(MemBackend::new());
        let store = Arc::new(CommonStore::new(backend));
        let svc = NodePersistService::new(store.clone(), false);
        assert_eq!(svc.write_batch(&[DbNode::new("a", 1)]), 0);
        assert!(svc.read().is_empty());
    }

    #[test]
    fn corrupt_blob_returns_empty_without_panic() {
        let svc = fresh();
        svc.store.put(DB_KEY_PEERS, b"this is not json");
        assert!(svc.read().is_empty());
    }
}
