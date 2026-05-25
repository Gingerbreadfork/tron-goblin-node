//! Witness relay / fast-forward decision policy.
//!
//! Mirrors java-tron's `RelayService` — the piece that decides which
//! peers a freshly-produced block should be force-pushed to (rather
//! than waiting for the standard inventory-broadcast cycle).
//!
//! Two responsibilities:
//!
//! 1. **Fast-forward set**: an SR's own block needs to reach the next
//!    SR's machine before the next slot fires. Operators configure
//!    `fastForwardNodes` — direct sockets to the partner witnesses
//!    that bypass the normal peer-gossip path.
//! 2. **Witness-priority broadcast**: every other accepted block
//!    should preferentially go to peers identified as witnesses (the
//!    `WitnessScheduleStore` set) before the rest of the peer table.
//!
//! Pure decision logic (no real network coupling) so we can test the
//! routing without spinning up a network stack.

use std::collections::HashSet;

/// One peer the relay decision considers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayPeer {
    /// Stable identifier (libp2p peer-id string / IP:port).
    pub key: String,
    /// 21-byte witness address (with `0x41` prefix), or `None` for a
    /// non-witness peer.
    pub witness_address: Option<[u8; 21]>,
    /// `true` for the operator's configured `fastForwardNodes` set.
    /// Independent of the witness flag — a fast-forward peer may or
    /// may not be a witness.
    pub is_fast_forward: bool,
}

/// Knobs from `node.maxFastForwardNum` + related.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// java-tron's `MAX_PEER_COUNT_PER_ADDRESS`. Default `5`.
    pub max_peer_count_per_address: usize,
    /// java-tron's `maxFastForwardNum`. Default `3`.
    pub max_fast_forward_num: usize,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            max_peer_count_per_address: 5,
            max_fast_forward_num: 3,
        }
    }
}

/// Output of [`RelayPolicy::evaluate`]: the peers a block should be
/// force-pushed to, in priority order. Caller is responsible for
/// actually sending the BlockMessage frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayPlan {
    /// Fast-forward peers — push first, these are the latency-critical
    /// next-SR hand-offs.
    pub fast_forward: Vec<String>,
    /// Witness peers (excluding any already in `fast_forward`) — push
    /// next, the broader SR-set fan-out.
    pub witnesses: Vec<String>,
}

impl RelayPlan {
    pub fn is_empty(&self) -> bool {
        self.fast_forward.is_empty() && self.witnesses.is_empty()
    }
}

pub struct RelayPolicy<'a> {
    pub config: &'a RelayConfig,
    pub peers: &'a [RelayPeer],
    /// Active witness set (21-byte addresses). Looked up via
    /// `WitnessScheduleStore` in the host wiring.
    pub active_witnesses: &'a HashSet<[u8; 21]>,
}

impl<'a> RelayPolicy<'a> {
    /// Compute the priority routing plan for a freshly-accepted block.
    ///
    /// * Fast-forward peers come first (capped at
    ///   `max_fast_forward_num`), preserving the input order so the
    ///   operator-listed peers are walked deterministically.
    /// * Then witnesses currently in the active set, deduplicated
    ///   against the fast-forward slice. Witness peers whose address
    ///   doesn't appear in `active_witnesses` are skipped — they
    ///   self-identified but aren't currently scheduled.
    pub fn evaluate(&self) -> RelayPlan {
        let mut fast_forward: Vec<String> = self
            .peers
            .iter()
            .filter(|p| p.is_fast_forward)
            .take(self.config.max_fast_forward_num)
            .map(|p| p.key.clone())
            .collect();

        let fast_set: HashSet<&str> = fast_forward.iter().map(String::as_str).collect();
        let witnesses: Vec<String> = self
            .peers
            .iter()
            .filter(|p| !fast_set.contains(p.key.as_str()))
            .filter_map(|p| p.witness_address.map(|addr| (p, addr)))
            .filter(|(_, addr)| self.active_witnesses.contains(addr))
            .map(|(p, _)| p.key.clone())
            .collect();

        fast_forward.shrink_to_fit();
        RelayPlan {
            fast_forward,
            witnesses,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> [u8; 21] {
        let mut out = [0u8; 21];
        out[0] = 0x41;
        out[1] = b;
        out
    }

    fn peer_basic(key: &str, witness: Option<u8>, ff: bool) -> RelayPeer {
        RelayPeer {
            key: key.into(),
            witness_address: witness.map(addr),
            is_fast_forward: ff,
        }
    }

    #[test]
    fn fast_forward_peers_are_picked_first() {
        let cfg = RelayConfig::default();
        let peers = vec![
            peer_basic("ff-1", None, true),
            peer_basic("w-1", Some(1), false),
            peer_basic("ff-2", None, true),
        ];
        let active: HashSet<_> = [addr(1)].into_iter().collect();
        let plan = RelayPolicy {
            config: &cfg,
            peers: &peers,
            active_witnesses: &active,
        }
        .evaluate();
        assert_eq!(plan.fast_forward, vec!["ff-1", "ff-2"]);
        assert_eq!(plan.witnesses, vec!["w-1"]);
    }

    #[test]
    fn fast_forward_capped_at_max() {
        let cfg = RelayConfig {
            max_fast_forward_num: 2,
            ..RelayConfig::default()
        };
        let peers = vec![
            peer_basic("ff-1", None, true),
            peer_basic("ff-2", None, true),
            peer_basic("ff-3", None, true),
            peer_basic("ff-4", None, true),
        ];
        let plan = RelayPolicy {
            config: &cfg,
            peers: &peers,
            active_witnesses: &HashSet::new(),
        }
        .evaluate();
        assert_eq!(plan.fast_forward.len(), 2);
        assert_eq!(plan.fast_forward, vec!["ff-1", "ff-2"]);
    }

    #[test]
    fn witness_peer_not_in_active_set_is_skipped() {
        let cfg = RelayConfig::default();
        let peers = vec![
            peer_basic("w-1", Some(1), false), // active
            peer_basic("w-2", Some(2), false), // not active
        ];
        let active: HashSet<_> = [addr(1)].into_iter().collect();
        let plan = RelayPolicy {
            config: &cfg,
            peers: &peers,
            active_witnesses: &active,
        }
        .evaluate();
        assert_eq!(plan.witnesses, vec!["w-1"]);
    }

    #[test]
    fn fast_forward_peer_excluded_from_witness_dup() {
        let cfg = RelayConfig::default();
        // Peer is both fast-forward AND an active witness.
        let peers = vec![peer_basic("dual", Some(1), true)];
        let active: HashSet<_> = [addr(1)].into_iter().collect();
        let plan = RelayPolicy {
            config: &cfg,
            peers: &peers,
            active_witnesses: &active,
        }
        .evaluate();
        assert_eq!(plan.fast_forward, vec!["dual"]);
        assert!(
            plan.witnesses.is_empty(),
            "dual peer should not appear in both lists"
        );
    }

    #[test]
    fn empty_input_produces_empty_plan() {
        let cfg = RelayConfig::default();
        let plan = RelayPolicy {
            config: &cfg,
            peers: &[],
            active_witnesses: &HashSet::new(),
        }
        .evaluate();
        assert!(plan.is_empty());
    }
}
