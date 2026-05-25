//! Live peer registry shared between the SyncDriver instances and the
//! `ResilienceService` scheduler.
//!
//! Each SyncDriver registers a [`PeerSnapshot`] on handshake-success
//! and unregisters on task exit. The resilience service ticks against
//! the registry's snapshot to decide eviction candidates. Mirrors
//! java-tron's `TronNetDelegate.getActivePeer()` view.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::resilience::PeerSnapshot;

/// Shared live-peer registry. Cheap to clone (Arc'd internally) so the
/// SyncDriver, the resilience service, and any future observers can
/// all hold a handle.
#[derive(Clone, Debug, Default)]
pub struct PeerRegistry {
    inner: Arc<Mutex<HashMap<String, PeerSnapshot>>>,
}

impl PeerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert / replace the snapshot for `peer_key`. Called by the
    /// SyncDriver at handshake completion.
    pub fn register(&self, peer_key: &str, snapshot: PeerSnapshot) {
        if let Ok(mut g) = self.inner.lock() {
            g.insert(peer_key.to_string(), snapshot);
        }
    }

    /// Drop the entry for `peer_key`. Called by the SyncDriver on task
    /// exit (after PeerFailure / CapReached / shutdown).
    pub fn unregister(&self, peer_key: &str) {
        if let Ok(mut g) = self.inner.lock() {
            g.remove(peer_key);
        }
    }

    /// In-place mutation under the lock. Used to refresh fields like
    /// `last_interactive_ms` and `block_recv_ms` without rebuilding
    /// the whole snapshot.
    pub fn touch(&self, peer_key: &str, f: impl FnOnce(&mut PeerSnapshot)) {
        if let Ok(mut g) = self.inner.lock() {
            if let Some(s) = g.get_mut(peer_key) {
                f(s);
            }
        }
    }

    /// Materialise the registry as a list of snapshots — the shape
    /// `ResilienceService::run` expects from its `peers_fn`.
    pub fn snapshot(&self) -> Vec<PeerSnapshot> {
        self.inner
            .lock()
            .map(|g| g.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Active-peer count.
    pub fn len(&self) -> usize {
        self.inner.lock().map(|g| g.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(key: &str) -> PeerSnapshot {
        PeerSnapshot {
            key: key.into(),
            is_active_dialer: true,
            is_trust_peer: false,
            need_sync_from_peer: false,
            need_sync_from_us: false,
            last_interactive_ms: 1_000,
            block_recv_ms: 0,
        }
    }

    #[test]
    fn register_then_snapshot_returns_entry() {
        let r = PeerRegistry::new();
        r.register("a", sample("a"));
        let snap = r.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].key, "a");
    }

    #[test]
    fn unregister_removes_entry() {
        let r = PeerRegistry::new();
        r.register("a", sample("a"));
        r.register("b", sample("b"));
        r.unregister("a");
        let mut keys: Vec<String> = r.snapshot().into_iter().map(|p| p.key).collect();
        keys.sort();
        assert_eq!(keys, vec!["b".to_string()]);
    }

    #[test]
    fn touch_updates_fields_in_place() {
        let r = PeerRegistry::new();
        r.register("a", sample("a"));
        r.touch("a", |s| s.last_interactive_ms = 9_999);
        let snap = r.snapshot();
        assert_eq!(snap[0].last_interactive_ms, 9_999);
    }

    #[test]
    fn touch_on_missing_peer_is_noop() {
        let r = PeerRegistry::new();
        r.touch("ghost", |s| s.last_interactive_ms = 9_999);
        assert!(r.is_empty());
    }

    #[test]
    fn clone_shares_state() {
        let r1 = PeerRegistry::new();
        let r2 = r1.clone();
        r1.register("a", sample("a"));
        assert_eq!(r2.len(), 1);
    }
}
