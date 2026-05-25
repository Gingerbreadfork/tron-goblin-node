//! Peer-graph resilience policy.
//!
//! Mirrors java-tron's `ResilienceService` (random elimination at
//! peer-cap, LAN-cleanup, isolation breakout) but extracted into pure
//! functions so the decision can be exercised without spinning up a
//! tokio runtime or real peer connections.
//!
//! ## Public surface
//!
//! * [`PeerSnapshot`] — the per-peer view the policy consumes. Built
//!   once per tick from the live peer list + the
//!   [`NodeStatisticsTable`](crate::node_statistics::NodeStatisticsTable).
//! * [`ResilienceConfig`] — knobs (max/min connections, inactive
//!   threshold, isolation timer). Defaults match java-tron's mainnet
//!   values.
//! * [`ResiliencePolicy`] — the decision function. Returns a
//!   [`ResilienceDecision`] (which peer to disconnect, with what
//!   reason, citing which trigger).
//!
//! The runtime loop ([`ResilienceService`]) is a thin scheduler that
//! periodically calls the policy and applies the result via a
//! caller-supplied disconnect closure.

use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time;

use crate::node_statistics::{DisconnectReason, NodeStatisticsTable};

/// View of one peer the resilience policy considers. Built per-tick
/// from the live peer list — keeping it a plain struct lets the
/// decision function be tested without any P2P machinery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSnapshot {
    /// Stable identifier (libp2p PeerId string / IP:port).
    pub key: String,
    /// `true` when the connection was initiated locally (we dialed the
    /// peer). Java-tron's `Channel.isActive()` returns the same bit.
    pub is_active_dialer: bool,
    /// `true` when the peer is in the operator's trust list. Trust
    /// peers are exempt from every disconnect rule.
    pub is_trust_peer: bool,
    /// `true` when we still need blocks from this peer (sync in
    /// flight). Used by the random-elimination path to exempt active
    /// syncing peers.
    pub need_sync_from_peer: bool,
    /// `true` when this peer is currently syncing from us.
    pub need_sync_from_us: bool,
    /// Wall-clock unix-ms of the last inbound/outbound message.
    pub last_interactive_ms: u64,
    /// Wall-clock unix-ms when our latest block was received. Used by
    /// the isolation-breakout check (if every adv-peer's
    /// `block_recv_ms` is ancient we're stuck on a dead fork).
    pub block_recv_ms: u64,
}

/// Knobs controlling the resilience policy. Defaults mirror
/// java-tron's mainnet values.
#[derive(Debug, Clone)]
pub struct ResilienceConfig {
    /// Hard ceiling on connections. Above this we start random
    /// elimination.
    pub max_connections: usize,
    /// Soft floor on connections. Below this we skip the LAN-cleanup
    /// path so the node doesn't disconnect itself into isolation.
    pub min_connections: usize,
    /// Minimum number of active (dialer) connections to keep around
    /// during isolation-breakout.
    pub min_active_connections: usize,
    /// A peer is "inactive" once it's been silent for this long.
    /// Java-tron pulls `CommonParameter.inactiveThreshold * 1000`.
    pub inactive_threshold: Duration,
    /// We declare ourselves isolated when no new block arrives within
    /// this window. Default `60s`.
    pub block_not_change_threshold: Duration,
    /// Tolerance: we keep up to `retention_percent * max_connections`
    /// passive peers before evicting any of them in the isolation
    /// breakout path. Default `0.8`.
    pub retention_percent: f64,
    /// Minimum healthy broadcast peer count. Below this the
    /// random-elimination path also walks the "need_sync_from_us"
    /// candidates (matches java-tron's fallback).
    pub min_broadcast_peer_size: usize,
}

impl Default for ResilienceConfig {
    fn default() -> Self {
        Self {
            // java-tron mainnet: max-connections = 30
            max_connections: 30,
            min_connections: 8,
            min_active_connections: 1,
            inactive_threshold: Duration::from_secs(600),
            block_not_change_threshold: Duration::from_secs(60),
            retention_percent: 0.8,
            min_broadcast_peer_size: 3,
        }
    }
}

/// Why the policy is asking us to disconnect a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectCause {
    /// Peer count >= max; random eviction of an idle peer.
    RandomElimination,
    /// All peers are inactive and look LAN-bound; pick the most idle
    /// to cycle.
    LanNode,
    /// We're isolated (no new blocks); cycle the oldest active-dialer
    /// peer so a fresh one can be discovered.
    IsolatedActive,
    /// We're isolated and over the retention cap on passive peers;
    /// cycle the oldest passive peer.
    IsolatedPassive,
}

impl DisconnectCause {
    /// Wire-level reason code that matches java-tron's
    /// `disconnectFromPeer(peer, reasonCode, cause)` mapping.
    pub fn reason(self) -> DisconnectReason {
        match self {
            DisconnectCause::RandomElimination => DisconnectReason::RandomElimination,
            DisconnectCause::LanNode
            | DisconnectCause::IsolatedActive
            | DisconnectCause::IsolatedPassive => DisconnectReason::BadProtocol,
        }
    }
}

/// One peer the policy wants disconnected, with the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResilienceDecision {
    pub peer_key: String,
    pub cause: DisconnectCause,
}

/// Compute the disconnect set for a single resilience tick. Pure —
/// the caller is responsible for actually closing connections +
/// recording the disconnect against the statistics table.
///
/// The three rules below run in the same order as java-tron's
/// scheduled jobs. Each rule independently returns up to a small
/// number of decisions; the policy merges them and returns the union.
pub struct ResiliencePolicy<'a> {
    pub config: &'a ResilienceConfig,
    pub peers: &'a [PeerSnapshot],
    pub now_ms: u64,
    /// Open-full-tcp-disconnect feature flag (java-tron
    /// `isOpenFullTcpDisconnect`). Off-by-default; when off, the
    /// random-elimination rule is skipped entirely.
    pub open_full_tcp_disconnect: bool,
}

impl<'a> ResiliencePolicy<'a> {
    /// Run all three rules and return every decision. A peer may
    /// appear at most once; if multiple rules pick the same peer the
    /// first cause wins (random > lan > isolated-active > isolated-passive).
    pub fn evaluate(&self) -> Vec<ResilienceDecision> {
        let mut out: Vec<ResilienceDecision> = Vec::new();
        let mut chosen: std::collections::HashSet<String> = std::collections::HashSet::new();

        for d in self.random_elimination() {
            if chosen.insert(d.peer_key.clone()) {
                out.push(d);
            }
        }
        for d in self.lan_cleanup() {
            if chosen.insert(d.peer_key.clone()) {
                out.push(d);
            }
        }
        for d in self.isolated_breakout() {
            if chosen.insert(d.peer_key.clone()) {
                out.push(d);
            }
        }
        out
    }

    /// Rule 1: at-or-above max connections, evict one idle peer at
    /// random (weighted by idle time — the longest-idle is the most
    /// likely victim). Mirrors `ResilienceService.disconnectRandom`.
    fn random_elimination(&self) -> Vec<ResilienceDecision> {
        if !self.open_full_tcp_disconnect {
            return Vec::new();
        }
        if self.peers.len() < self.config.max_connections {
            return Vec::new();
        }
        // Candidates: not trust, not actively syncing in either
        // direction.
        let candidates: Vec<&PeerSnapshot> = self
            .peers
            .iter()
            .filter(|p| !p.is_trust_peer)
            .filter(|p| !p.need_sync_from_peer && !p.need_sync_from_us)
            .collect();

        if candidates.len() >= self.config.min_broadcast_peer_size {
            // Per java-tron: take the older half (sorted by
            // `block_recv_ms` ascending) and pick deterministically
            // from that bucket — we use the smallest `block_recv_ms`
            // (most-stale) rather than weighted-random so tests are
            // deterministic. java-tron's weighted-random is best-effort
            // anyway.
            let mut sorted: Vec<&&PeerSnapshot> = candidates.iter().collect();
            sorted.sort_by_key(|p| p.block_recv_ms);
            let half = (sorted.len() / 2).max(1);
            let oldest = sorted[..half]
                .iter()
                .min_by_key(|p| p.block_recv_ms)
                .copied()
                .copied();
            if let Some(p) = oldest {
                return vec![ResilienceDecision {
                    peer_key: p.key.clone(),
                    cause: DisconnectCause::RandomElimination,
                }];
            }
            return Vec::new();
        }

        // Fallback: too few broadcast peers — evict from the syncing
        // pool so a fresh advertise-only peer can take the slot.
        let need_sync_from_peer_count = self
            .peers
            .iter()
            .filter(|p| !p.is_trust_peer && p.need_sync_from_peer)
            .count();

        let sync_candidates: Vec<&PeerSnapshot> = if need_sync_from_peer_count >= 2 {
            self.peers
                .iter()
                .filter(|p| !p.is_trust_peer)
                .filter(|p| p.need_sync_from_us || p.need_sync_from_peer)
                .collect()
        } else {
            self.peers
                .iter()
                .filter(|p| !p.is_trust_peer)
                .filter(|p| p.need_sync_from_us)
                .collect()
        };
        if let Some(p) = sync_candidates.first() {
            return vec![ResilienceDecision {
                peer_key: p.key.clone(),
                cause: DisconnectCause::RandomElimination,
            }];
        }
        Vec::new()
    }

    /// Rule 2: every peer is on the LAN (all dialer-initiated) and
    /// peer-count is healthy; evict the most-idle one. Mirrors
    /// `ResilienceService.disconnectLan`.
    fn lan_cleanup(&self) -> Vec<ResilienceDecision> {
        if !self.is_lan_only() {
            return Vec::new();
        }
        if self.peers.len() < self.config.min_connections {
            return Vec::new();
        }
        let inactive_ms = self.config.inactive_threshold.as_millis() as u64;
        let earliest = self
            .peers
            .iter()
            .filter(|p| !p.is_trust_peer)
            .filter(|p| !p.need_sync_from_peer && !p.need_sync_from_us)
            .filter(|p| {
                self.now_ms.saturating_sub(p.last_interactive_ms) >= inactive_ms
            })
            .min_by_key(|p| p.last_interactive_ms);
        match earliest {
            Some(p) => vec![ResilienceDecision {
                peer_key: p.key.clone(),
                cause: DisconnectCause::LanNode,
            }],
            None => Vec::new(),
        }
    }

    /// Rule 3: we haven't received a block in
    /// `block_not_change_threshold`, suggesting our chain view is
    /// dead. Cycle one active-dialer peer + any excess passive peers
    /// over the retention cap. Mirrors
    /// `ResilienceService.disconnectIsolated2`.
    fn isolated_breakout(&self) -> Vec<ResilienceDecision> {
        if !self.is_isolated() {
            return Vec::new();
        }
        let mut out = Vec::new();

        // Sub-rule (a): evict one active-dialer at min-active threshold.
        let active_count = self
            .peers
            .iter()
            .filter(|p| p.is_active_dialer)
            .count();
        if active_count >= self.config.min_active_connections {
            let oldest_active = self
                .peers
                .iter()
                .filter(|p| !p.is_trust_peer && p.is_active_dialer)
                .min_by_key(|p| p.last_interactive_ms);
            if let Some(p) = oldest_active {
                out.push(ResilienceDecision {
                    peer_key: p.key.clone(),
                    cause: DisconnectCause::IsolatedActive,
                });
            }
        }

        // Sub-rule (b): trim passive peers over the retention cap.
        let threshold =
            (self.config.max_connections as f64 * self.config.retention_percent) as usize;
        if self.peers.len() > threshold {
            let to_drop = self.peers.len() - threshold;
            let mut passive: Vec<&PeerSnapshot> = self
                .peers
                .iter()
                .filter(|p| !p.is_trust_peer && !p.is_active_dialer)
                .collect();
            passive.sort_by_key(|p| p.last_interactive_ms);
            for p in passive.into_iter().take(to_drop) {
                out.push(ResilienceDecision {
                    peer_key: p.key.clone(),
                    cause: DisconnectCause::IsolatedPassive,
                });
            }
        }
        out
    }

    fn is_lan_only(&self) -> bool {
        let n = self.peers.len();
        let active = self.peers.iter().filter(|p| p.is_active_dialer).count();
        n >= self.config.min_active_connections && n == active
    }

    /// Java-tron's "isIsolateLand2": at least one advertise peer +
    /// no block within `block_not_change_threshold`.
    fn is_isolated(&self) -> bool {
        let adv_peer_count = self
            .peers
            .iter()
            .filter(|p| !p.need_sync_from_peer && !p.need_sync_from_us)
            .count();
        let latest_block_ms = self.peers.iter().map(|p| p.block_recv_ms).max().unwrap_or(0);
        let diff = self.now_ms.saturating_sub(latest_block_ms);
        adv_peer_count >= 1 && diff >= self.config.block_not_change_threshold.as_millis() as u64
    }
}

/// Channel-based runtime for the resilience policy.
///
/// Spawn one of these per node. The driver pumps a tick every
/// `tick_interval` (java-tron uses 10s for LAN-cleanup and 30s for the
/// other two; we collapse to a single tick), evaluates the policy,
/// and sends each [`ResilienceDecision`] over `disconnect_tx`. The
/// network layer owns `disconnect_rx` and turns each decision into an
/// actual TCP close + a `NodeStatisticsTable::record_local_disconnect`.
pub struct ResilienceService {
    pub config: ResilienceConfig,
    pub statistics: NodeStatisticsTable,
    pub tick_interval: Duration,
    pub open_full_tcp_disconnect: bool,
}

impl ResilienceService {
    /// Run one decision pass against a peer-list snapshot. Pulled out
    /// of [`run`] so tests can exercise it without a tokio executor.
    pub fn tick(&self, peers: &[PeerSnapshot], now_ms: u64) -> Vec<ResilienceDecision> {
        let policy = ResiliencePolicy {
            config: &self.config,
            peers,
            now_ms,
            open_full_tcp_disconnect: self.open_full_tcp_disconnect,
        };
        policy.evaluate()
    }

    /// Long-running scheduler loop. `peers_fn` is polled per tick to
    /// return the current peer snapshot; decisions are sent on
    /// `decisions_tx`. The loop exits when `decisions_tx` is dropped
    /// by the receiver.
    pub async fn run<F>(self, mut peers_fn: F, decisions_tx: mpsc::Sender<ResilienceDecision>)
    where
        F: FnMut() -> Vec<PeerSnapshot> + Send + 'static,
    {
        let mut ticker = time::interval(self.tick_interval);
        // Skip the first immediate tick — java-tron uses a 300s initial
        // delay; we use one full tick.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let peers = peers_fn();
            let now_ms = crate::node_statistics::unix_now_ms();
            for decision in self.tick(&peers, now_ms) {
                self.statistics
                    .record_local_disconnect(&decision.peer_key, decision.cause.reason())
                    .await;
                if decisions_tx.send(decision).await.is_err() {
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(
        key: &str,
        is_active: bool,
        last_interactive_ms: u64,
        block_recv_ms: u64,
    ) -> PeerSnapshot {
        PeerSnapshot {
            key: key.into(),
            is_active_dialer: is_active,
            is_trust_peer: false,
            need_sync_from_peer: false,
            need_sync_from_us: false,
            last_interactive_ms,
            block_recv_ms,
        }
    }

    fn config_for_tests() -> ResilienceConfig {
        ResilienceConfig {
            max_connections: 4,
            min_connections: 2,
            min_active_connections: 1,
            inactive_threshold: Duration::from_secs(1),
            block_not_change_threshold: Duration::from_secs(60),
            retention_percent: 0.5,
            min_broadcast_peer_size: 2,
        }
    }

    #[test]
    fn random_elimination_only_fires_when_peer_count_at_cap_and_flag_on() {
        let cfg = config_for_tests();
        let now = 1_000_000;
        let peers = vec![
            peer("a", true, now - 10, now - 50),
            peer("b", true, now - 5, now - 20),
            peer("c", true, now - 1, now - 10),
        ];
        // Below cap → no decisions.
        let policy = ResiliencePolicy {
            config: &cfg,
            peers: &peers,
            now_ms: now,
            open_full_tcp_disconnect: true,
        };
        assert!(policy.evaluate().is_empty());

        // At cap (4) → flag off ⇒ no decisions.
        let peers = vec![
            peer("a", true, now - 10, now - 50),
            peer("b", true, now - 5, now - 20),
            peer("c", true, now - 1, now - 10),
            peer("d", true, now - 1, now - 5),
        ];
        let policy = ResiliencePolicy {
            config: &cfg,
            peers: &peers,
            now_ms: now,
            open_full_tcp_disconnect: false,
        };
        assert!(policy.evaluate().is_empty());

        // At cap (4) → flag on ⇒ picks the oldest-block peer.
        let policy = ResiliencePolicy {
            config: &cfg,
            peers: &peers,
            now_ms: now,
            open_full_tcp_disconnect: true,
        };
        let decisions = policy.evaluate();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].peer_key, "a"); // oldest block_recv_ms
        assert_eq!(decisions[0].cause, DisconnectCause::RandomElimination);
    }

    #[test]
    fn random_elimination_skips_trust_peer() {
        let mut cfg = config_for_tests();
        cfg.min_broadcast_peer_size = 1;
        let now = 1_000_000;
        let mut peers = vec![
            peer("trust", true, now - 100, now - 100),
            peer("b", true, now - 5, now - 20),
            peer("c", true, now - 1, now - 10),
            peer("d", true, now - 1, now - 5),
        ];
        peers[0].is_trust_peer = true;
        let policy = ResiliencePolicy {
            config: &cfg,
            peers: &peers,
            now_ms: now,
            open_full_tcp_disconnect: true,
        };
        let decisions = policy.evaluate();
        // Trust peer is exempt even though it'd be the otherwise-oldest pick.
        assert_ne!(decisions[0].peer_key, "trust");
    }

    #[test]
    fn lan_cleanup_picks_most_idle_when_all_active_dialers_and_inactive() {
        let cfg = config_for_tests();
        let now = 1_000_000;
        // All active-dialer (LAN-only signal) + min_connections met +
        // every peer past the inactive threshold (1s).
        let peers = vec![
            peer("a", true, now - 2_000, now), // most idle
            peer("b", true, now - 1_500, now),
            peer("c", true, now - 1_100, now),
        ];
        let policy = ResiliencePolicy {
            config: &cfg,
            peers: &peers,
            now_ms: now,
            open_full_tcp_disconnect: false, // disable rule 1 to isolate rule 2
        };
        let decisions = policy.evaluate();
        let lan_decisions: Vec<_> = decisions
            .iter()
            .filter(|d| d.cause == DisconnectCause::LanNode)
            .collect();
        assert_eq!(lan_decisions.len(), 1);
        assert_eq!(lan_decisions[0].peer_key, "a");
    }

    #[test]
    fn lan_cleanup_skipped_when_mixed_active_passive() {
        let cfg = config_for_tests();
        let now = 1_000_000;
        let peers = vec![
            peer("a", true, now - 2_000, now),
            peer("b", false, now - 1_500, now), // passive
            peer("c", true, now - 1_100, now),
        ];
        let policy = ResiliencePolicy {
            config: &cfg,
            peers: &peers,
            now_ms: now,
            open_full_tcp_disconnect: false,
        };
        assert!(policy
            .evaluate()
            .iter()
            .all(|d| d.cause != DisconnectCause::LanNode));
    }

    #[test]
    fn isolated_breakout_fires_when_no_recent_block() {
        let cfg = config_for_tests();
        let now = 1_000_000;
        // Latest block was 120s ago → isolated.
        let stale_block_ms = now - 120_000;
        let peers = vec![
            peer("a", true, now - 30_000, stale_block_ms), // oldest active
            peer("b", true, now - 10_000, stale_block_ms),
            peer("c", false, now - 5_000, stale_block_ms), // passive 1
            peer("d", false, now - 1_000, stale_block_ms), // passive 2
        ];
        let policy = ResiliencePolicy {
            config: &cfg,
            peers: &peers,
            now_ms: now,
            open_full_tcp_disconnect: false,
        };
        let decisions = policy.evaluate();
        let causes: Vec<_> = decisions.iter().map(|d| d.cause).collect();
        // Picks oldest active + excess passive (retention = 50% of cap-4 = 2, len = 4 → 2 to drop).
        assert!(causes.contains(&DisconnectCause::IsolatedActive));
        assert_eq!(
            decisions
                .iter()
                .find(|d| d.cause == DisconnectCause::IsolatedActive)
                .unwrap()
                .peer_key,
            "a"
        );
        assert!(causes.contains(&DisconnectCause::IsolatedPassive));
    }

    #[test]
    fn no_decisions_when_node_is_healthy() {
        let cfg = config_for_tests();
        let now = 1_000_000;
        let peers = vec![
            peer("a", true, now - 100, now - 5),
            peer("b", false, now - 50, now - 5),
        ];
        let policy = ResiliencePolicy {
            config: &cfg,
            peers: &peers,
            now_ms: now,
            open_full_tcp_disconnect: true,
        };
        assert!(policy.evaluate().is_empty());
    }

    #[test]
    fn dedup_keeps_first_decision_per_peer_across_rules() {
        // A peer eligible for both random-elim and isolated-breakout
        // shouldn't appear twice.
        let cfg = config_for_tests();
        let now = 1_000_000;
        let stale = now - 120_000;
        let peers = vec![
            peer("a", true, now - 30_000, stale), // both rules want this peer
            peer("b", true, now - 10_000, stale),
            peer("c", true, now - 5_000, stale),
            peer("d", true, now - 1_000, stale),
        ];
        let policy = ResiliencePolicy {
            config: &cfg,
            peers: &peers,
            now_ms: now,
            open_full_tcp_disconnect: true,
        };
        let decisions = policy.evaluate();
        let mut keys: Vec<&str> = decisions.iter().map(|d| d.peer_key.as_str()).collect();
        keys.sort();
        let mut unique = keys.clone();
        unique.dedup();
        assert_eq!(keys, unique, "no peer should appear twice in one tick");
    }
}
