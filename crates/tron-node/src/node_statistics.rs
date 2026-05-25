//! Per-peer disconnect / interaction statistics.
//!
//! Mirrors java-tron's `org.tron.core.net.service.statistics.NodeStatistics`
//! plus the surrounding `NodeStatisticsTable` aggregation that the
//! resilience services consult.
//!
//! Each [`NodeStatistics`] records:
//! * the most recent local-side disconnect reason,
//! * the most recent remote-side disconnect reason,
//! * the lifetime disconnect count,
//! * the wall-clock instant the entry was first opened,
//! * the wall-clock instant of the last inbound/outbound message
//!   (the "interactive time" the resilience scheduler ranks on).
//!
//! [`NodeStatisticsTable`] is the shareable map of `peer_key →
//! NodeStatistics` — a `tokio::sync::Mutex` wraps the inner state so
//! both the sync driver (write side) and the resilience scheduler
//! (read side) can use the same handle.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex;

/// Disconnect reasons. Wire-compatible with java-tron's
/// `protos/Protocol.ReasonCode` numeric values so the same byte tag
/// can be passed over the wire.
///
/// Only the codes the runtime currently produces are enumerated; new
/// reasons can be added without breaking existing matchers because the
/// type is `#[non_exhaustive]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum DisconnectReason {
    Unknown = 0,
    /// Random elimination by the resilience scheduler when peer count
    /// is at the configured ceiling.
    RandomElimination = 14,
    /// Generic protocol violation. Also used by the LAN-cleanup +
    /// isolation-recovery scheduler paths.
    BadProtocol = 16,
    /// Application-level disconnect (mirrors java-tron `FETCH_FAIL`
    /// — used when a peer serves a `ChainInventory` then drops on the
    /// follow-up fetch).
    FetchFail = 19,
    /// Repeated `TIME_BANNED` strikes — cooldown after the peer
    /// rejected us as banned three times in a row.
    TimeBanned = 3,
}

impl DisconnectReason {
    /// Numeric tag used by java-tron over the wire.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Per-peer disconnect / interaction record.
#[derive(Debug, Clone)]
pub struct NodeStatistics {
    /// `Some(reason)` when the remote dropped us; cleared on next
    /// successful reconnect.
    pub remote_disconnect_reason: Option<DisconnectReason>,
    /// `Some(reason)` when we dropped the remote.
    pub local_disconnect_reason: Option<DisconnectReason>,
    /// Lifetime disconnect counter. Useful as a soft-ban signal —
    /// peers with a high count are deprioritized.
    pub disconnect_times: u32,
    /// Wall-clock unix-ms when this peer was first observed.
    pub start_ms: u64,
    /// Wall-clock unix-ms of the most recent inbound or outbound
    /// message. The resilience LAN-disconnect rule picks the peer
    /// with the smallest `last_interactive_ms` as the eviction
    /// candidate.
    pub last_interactive_ms: u64,
}

impl Default for NodeStatistics {
    fn default() -> Self {
        let now = unix_now_ms();
        Self {
            remote_disconnect_reason: None,
            local_disconnect_reason: None,
            disconnect_times: 0,
            start_ms: now,
            last_interactive_ms: now,
        }
    }
}

impl NodeStatistics {
    /// Returns the effective reason: local takes precedence over
    /// remote (matches `NodeStatistics.getDisconnectReason` in
    /// java-tron), then [`DisconnectReason::Unknown`].
    pub fn effective_reason(&self) -> DisconnectReason {
        self.local_disconnect_reason
            .or(self.remote_disconnect_reason)
            .unwrap_or(DisconnectReason::Unknown)
    }

    /// We dropped the peer; record the reason and bump the counter.
    pub fn record_local_disconnect(&mut self, reason: DisconnectReason) {
        self.local_disconnect_reason = Some(reason);
        self.disconnect_times = self.disconnect_times.saturating_add(1);
    }

    /// Peer dropped us; record the reason and bump the counter.
    pub fn record_remote_disconnect(&mut self, reason: DisconnectReason) {
        self.remote_disconnect_reason = Some(reason);
        self.disconnect_times = self.disconnect_times.saturating_add(1);
    }

    /// Bump `last_interactive_ms` to now.
    pub fn touch_now(&mut self) {
        self.last_interactive_ms = unix_now_ms();
    }

    /// How long (ms) since the last inbound/outbound message.
    pub fn idle_ms(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.last_interactive_ms)
    }

    /// How long (ms) this peer has been on our books.
    pub fn uptime_ms(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.start_ms)
    }
}

/// Shared per-peer table. Cheap to clone (it's an `Arc` internally).
#[derive(Debug, Clone, Default)]
pub struct NodeStatisticsTable {
    inner: Arc<Mutex<HashMap<String, NodeStatistics>>>,
}

impl NodeStatisticsTable {
    /// Empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Async lock + closure pattern. The closure runs under the lock,
    /// so keep it short — long work (logging / RPC) should pull the
    /// data out first via [`NodeStatisticsTable::snapshot`].
    pub async fn with_mut<F, R>(&self, peer_key: &str, f: F) -> R
    where
        F: FnOnce(&mut NodeStatistics) -> R,
    {
        let mut guard = self.inner.lock().await;
        let entry = guard
            .entry(peer_key.to_string())
            .or_insert_with(NodeStatistics::default);
        f(entry)
    }

    /// Bump the interactive-timestamp for `peer_key`.
    pub async fn touch(&self, peer_key: &str) {
        self.with_mut(peer_key, |s| s.touch_now()).await;
    }

    /// Record that we disconnected the peer.
    pub async fn record_local_disconnect(&self, peer_key: &str, reason: DisconnectReason) {
        self.with_mut(peer_key, |s| s.record_local_disconnect(reason))
            .await;
    }

    /// Record that the peer disconnected us.
    pub async fn record_remote_disconnect(&self, peer_key: &str, reason: DisconnectReason) {
        self.with_mut(peer_key, |s| s.record_remote_disconnect(reason))
            .await;
    }

    /// Lookup-only: clone the current record. Returns `None` if the
    /// peer has never been touched.
    pub async fn get(&self, peer_key: &str) -> Option<NodeStatistics> {
        self.inner.lock().await.get(peer_key).cloned()
    }

    /// Materialize the whole table as a snapshot. Held under the lock
    /// only long enough to clone — the result can be inspected at
    /// leisure.
    pub async fn snapshot(&self) -> Vec<(String, NodeStatistics)> {
        self.inner
            .lock()
            .await
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Remove a peer's entry (used when a long-banned peer's slot is
    /// reaped). Returns whether something was removed.
    pub async fn remove(&self, peer_key: &str) -> bool {
        self.inner.lock().await.remove(peer_key).is_some()
    }

    /// Drop every record older than `max_age`. Returns the count
    /// removed. Mirrors `NodeStatisticsTable.prune` semantics
    /// (java-tron expires via Guava cache TTL; we periodic-sweep).
    pub async fn prune_older_than(&self, max_age: Duration) -> usize {
        let cutoff = unix_now_ms().saturating_sub(max_age.as_millis() as u64);
        let mut guard = self.inner.lock().await;
        let before = guard.len();
        guard.retain(|_, s| s.start_ms >= cutoff);
        before - guard.len()
    }
}

pub(crate) fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_reason_local_wins_over_remote() {
        let mut s = NodeStatistics::default();
        assert_eq!(s.effective_reason(), DisconnectReason::Unknown);
        s.record_remote_disconnect(DisconnectReason::BadProtocol);
        assert_eq!(s.effective_reason(), DisconnectReason::BadProtocol);
        s.record_local_disconnect(DisconnectReason::RandomElimination);
        assert_eq!(s.effective_reason(), DisconnectReason::RandomElimination);
    }

    #[test]
    fn record_disconnect_bumps_counter() {
        let mut s = NodeStatistics::default();
        s.record_local_disconnect(DisconnectReason::BadProtocol);
        s.record_remote_disconnect(DisconnectReason::FetchFail);
        s.record_local_disconnect(DisconnectReason::RandomElimination);
        assert_eq!(s.disconnect_times, 3);
    }

    #[tokio::test]
    async fn table_touch_and_lookup() {
        let table = NodeStatisticsTable::new();
        table.touch("peer-alpha").await;
        let rec = table.get("peer-alpha").await.expect("present");
        assert!(rec.last_interactive_ms >= rec.start_ms);
    }

    #[tokio::test]
    async fn table_records_disconnect_with_reason() {
        let table = NodeStatisticsTable::new();
        table
            .record_local_disconnect("peer-A", DisconnectReason::RandomElimination)
            .await;
        table
            .record_remote_disconnect("peer-A", DisconnectReason::FetchFail)
            .await;
        let rec = table.get("peer-A").await.unwrap();
        // Local takes precedence in effective_reason.
        assert_eq!(rec.effective_reason(), DisconnectReason::RandomElimination);
        assert_eq!(rec.disconnect_times, 2);
    }

    #[tokio::test]
    async fn snapshot_returns_every_entry() {
        let table = NodeStatisticsTable::new();
        for p in ["a", "b", "c"] {
            table.touch(p).await;
        }
        let snap = table.snapshot().await;
        assert_eq!(snap.len(), 3);
    }

    #[tokio::test]
    async fn remove_drops_entry() {
        let table = NodeStatisticsTable::new();
        table.touch("p").await;
        assert!(table.remove("p").await);
        assert!(table.get("p").await.is_none());
        // Second remove of the same key is a no-op.
        assert!(!table.remove("p").await);
    }
}
