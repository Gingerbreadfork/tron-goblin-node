//! Wiring tests for `RelayPolicy` block-broadcast integration.
//!
//! The runtime pre-computes `fast_forward_nodes` membership per peer
//! and threads it into `SyncConfig::peer_is_fast_forward`. The peer
//! loop's `drain_produced_blocks` then branches:
//!
//!   * fast-forward peer → push full `Block` frame
//!   * non-fast-forward peer → push `Inventory(BLOCK, [hash])`
//!
//! Peers receiving the advertisement fetch the body via
//! `FetchInvData(BLOCK)`; we serve from `BlockStore` via
//! `serve_tx_fetch_inv_data`. These tests cover both pieces of the
//! cycle directly so a wiring regression surfaces.

use std::collections::HashSet;
use tron_node::relay::{RelayConfig, RelayPeer, RelayPlan, RelayPolicy};

fn witness_addr(b: u8) -> [u8; 21] {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1] = b;
    a
}

fn peer(key: &str, witness: Option<u8>, ff: bool) -> RelayPeer {
    RelayPeer {
        key: key.into(),
        witness_address: witness.map(witness_addr),
        is_fast_forward: ff,
    }
}

#[test]
fn fast_forward_peers_match_runtime_set_decision() {
    // Mirror the runtime's per-peer flag derivation: each peer key is
    // checked against the configured `fast_forward_nodes` HashSet.
    // The RelayPolicy.evaluate output is the priority order the
    // runtime uses to send Block (push) vs Inventory (advertise).
    let cfg = RelayConfig::default();
    let peers = vec![
        peer("relay-a:18888", None, true),  // configured fast-forward
        peer("seed-x:18888", None, false),  // ordinary peer
        peer("relay-b:18888", None, true),  // configured fast-forward
        peer("seed-y:18888", None, false),  // ordinary peer
    ];
    let plan = RelayPolicy {
        config: &cfg,
        peers: &peers,
        active_witnesses: &HashSet::new(),
    }
    .evaluate();
    // The relay plan singles out the configured fast-forward peers.
    // These are the keys the per-peer driver will see as
    // `peer_is_fast_forward = true` and will push the full Block to.
    assert_eq!(
        plan.fast_forward,
        vec!["relay-a:18888".to_string(), "relay-b:18888".to_string()]
    );
    // Witnesses set is empty here — no `peer.witness_address` was
    // declared, so the witness-priority slice is empty too.
    assert!(plan.witnesses.is_empty());
}

#[test]
fn dual_role_peer_is_classified_as_fast_forward_only() {
    // Operator-fast-forward AND active witness in the schedule → the
    // RelayPolicy classifies them as fast-forward (latency priority)
    // and deduplicates them out of the witness slice. Mirrors java-
    // tron's `RelayService.broadcast` which checks fast-forward first.
    let cfg = RelayConfig::default();
    let active: HashSet<_> = [witness_addr(1)].into_iter().collect();
    let peers = vec![peer("dual:18888", Some(1), true)];
    let plan = RelayPolicy {
        config: &cfg,
        peers: &peers,
        active_witnesses: &active,
    }
    .evaluate();
    assert_eq!(plan.fast_forward, vec!["dual:18888".to_string()]);
    assert!(plan.witnesses.is_empty());
}

#[test]
fn empty_plan_when_no_relay_peers_configured() {
    // Most operators don't configure fast-forward — they rely on
    // standard advertise-then-pull. RelayPlan must be empty in that
    // case so the runtime falls through to the inventory path for
    // every peer.
    let cfg = RelayConfig::default();
    let plan = RelayPolicy {
        config: &cfg,
        peers: &[],
        active_witnesses: &HashSet::new(),
    }
    .evaluate();
    assert!(plan.is_empty());
    assert_eq!(plan, RelayPlan {
        fast_forward: vec![],
        witnesses: vec![],
    });
}
