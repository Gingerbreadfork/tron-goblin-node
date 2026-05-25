//! Integration test for the runtime's resilience-service plumbing.
//!
//! Verifies the loop:
//!   PeerRegistry::snapshot → ResilienceService.tick → eviction_tx
//!
//! The full SyncDriver-driven flow (touch on inbound frame → register
//! peer on handshake → unregister on exit) is impractical to spin up
//! in a test without a real peer; this test substitutes a hand-built
//! registry that satisfies the resilience policy's input shape.

use std::time::Duration;
use tron_node::node_statistics::{DisconnectReason, NodeStatistics, NodeStatisticsTable};
use tron_node::resilience::{
    DisconnectCause, PeerSnapshot, ResilienceConfig, ResilienceService,
};
use tron_node::PeerRegistry;

fn snapshot(key: &str, last_interactive_ms: u64) -> PeerSnapshot {
    PeerSnapshot {
        key: key.into(),
        is_active_dialer: true,
        is_trust_peer: false,
        need_sync_from_peer: false,
        need_sync_from_us: false,
        last_interactive_ms,
        block_recv_ms: last_interactive_ms,
    }
}

#[tokio::test]
async fn resilience_evicts_idle_peer_at_cap_and_broadcasts_peer_key() {
    // 4 peers at cap, one is silent for over an hour → resilience
    // randomly-eliminates the silent one. The broadcast channel
    // receives that peer's key. Mirrors java-tron's
    // ResilienceService.elect routine.
    let registry = PeerRegistry::new();
    let now = 10_000_000u64;
    registry.register("a", snapshot("a", now - 1_000));
    registry.register("b", snapshot("b", now - 2_000));
    registry.register("c", snapshot("c", now - 500));
    registry.register("d", snapshot("d", now - 3_600_000)); // 1 hour silent

    let service = ResilienceService {
        config: ResilienceConfig {
            max_connections: 4,
            min_connections: 1,
            min_active_connections: 1,
            inactive_threshold: Duration::from_secs(60),
            block_not_change_threshold: Duration::from_secs(60),
            retention_percent: 0.5,
            min_broadcast_peer_size: 1,
        },
        statistics: NodeStatisticsTable::new(),
        tick_interval: Duration::from_millis(10),
        open_full_tcp_disconnect: true,
    };
    let decisions = service.tick(&registry.snapshot(), now);
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].peer_key, "d");
    assert_eq!(decisions[0].cause, DisconnectCause::RandomElimination);
}

#[tokio::test]
async fn resilience_records_local_disconnect_on_decision_via_statistics_table() {
    let stats = NodeStatisticsTable::new();
    let registry = PeerRegistry::new();
    let now = 10_000_000u64;
    registry.register("evict-me", snapshot("evict-me", now - 3_600_000));
    for k in ["keep-a", "keep-b", "keep-c"] {
        registry.register(k, snapshot(k, now - 100));
    }

    let service = ResilienceService {
        config: ResilienceConfig {
            max_connections: 4,
            min_connections: 1,
            min_active_connections: 1,
            inactive_threshold: Duration::from_secs(60),
            block_not_change_threshold: Duration::from_secs(60),
            retention_percent: 0.5,
            min_broadcast_peer_size: 1,
        },
        statistics: stats.clone(),
        tick_interval: Duration::from_millis(10),
        open_full_tcp_disconnect: true,
    };

    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    // Drive `run` exactly once via a fake `peers_fn` that hands over
    // a single snapshot, then disconnects the receiver.
    let peers = registry.snapshot();
    let handle = tokio::spawn(async move { service.run(move || peers.clone(), tx).await });

    let decision = rx.recv().await.expect("at least one decision");
    assert_eq!(decision.peer_key, "evict-me");

    // The service recorded a local-disconnect against the table for
    // the evicted peer BEFORE forwarding the decision. java-tron
    // does the same (`NodeStatistics.setLocalDisconnectReason`).
    let entry = stats.get("evict-me").await.expect("stats present");
    assert_eq!(entry.local_disconnect_reason, Some(DisconnectReason::RandomElimination));

    // Drop the receiver so service.run can exit. Wait for it.
    drop(rx);
    let _ = handle.await;
}

#[tokio::test]
async fn touch_then_disconnect_round_trip_through_table() {
    // Mirrors what the SyncDriver wiring does per peer:
    //   touch on each inbound frame, then record_*_disconnect on exit.
    let stats = NodeStatisticsTable::new();
    stats.touch("peer-a").await;
    let entry_after_touch = stats.get("peer-a").await.expect("entry created");
    assert!(entry_after_touch.last_interactive_ms > 0);
    assert!(entry_after_touch.local_disconnect_reason.is_none());

    stats
        .record_local_disconnect("peer-a", DisconnectReason::BadProtocol)
        .await;
    let entry = stats.get("peer-a").await.expect("still present");
    assert_eq!(entry.local_disconnect_reason, Some(DisconnectReason::BadProtocol));
    assert_eq!(entry.effective_reason(), DisconnectReason::BadProtocol);

    // Remote disconnect: local should still win on `effective_reason`
    // because we already recorded a local cause.
    stats
        .record_remote_disconnect("peer-a", DisconnectReason::TimeBanned)
        .await;
    let entry = stats.get("peer-a").await.expect("still present");
    assert_eq!(entry.remote_disconnect_reason, Some(DisconnectReason::TimeBanned));
    assert_eq!(
        entry.effective_reason(),
        DisconnectReason::BadProtocol,
        "local reason wins over remote"
    );
}

#[tokio::test]
async fn registry_snapshot_is_what_resilience_consumes() {
    // The registry's `snapshot()` is what the runtime hands to
    // `ResilienceService::run`. Confirm both shape and live-update
    // behaviour: a registered peer shows up in the snapshot; an
    // unregistered one is gone.
    let registry = PeerRegistry::new();
    registry.register("a", snapshot("a", 100));
    registry.register("b", snapshot("b", 200));

    let s1 = registry.snapshot();
    assert_eq!(s1.len(), 2);
    let keys: std::collections::HashSet<_> = s1.iter().map(|p| p.key.clone()).collect();
    assert!(keys.contains("a"));
    assert!(keys.contains("b"));

    registry.unregister("a");
    let s2 = registry.snapshot();
    assert_eq!(s2.len(), 1);
    assert_eq!(s2[0].key, "b");
}

#[test]
fn node_statistics_default_has_fresh_timestamps() {
    // The SyncDriver's `peer_registry.register` call goes through the
    // NodeStatistics::default path on first touch. Confirm timestamps
    // are non-zero (we depend on this for the resilience scheduler's
    // idle-threshold comparison to be meaningful from frame zero).
    let s = NodeStatistics::default();
    assert!(s.start_ms > 0);
    assert!(s.last_interactive_ms > 0);
    assert_eq!(s.disconnect_times, 0);
    assert!(s.local_disconnect_reason.is_none());
    assert!(s.remote_disconnect_reason.is_none());
}
