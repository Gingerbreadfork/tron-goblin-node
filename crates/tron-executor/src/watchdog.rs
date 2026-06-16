//! Consensus self-audit watchdog.
//!
//! During block apply the executor cross-checks each tx's *computed* result
//! against the block's canonical `contractRet`/ret (the tripwire in
//! [`crate::apply_block`]). A success-vs-failure disagreement means our state
//! has silently diverged from consensus. This module turns that signal into a
//! process-wide, queryable record so operators can ALERT on it — a node that
//! tells you the instant it stops agreeing with the chain.
//!
//! The count + last record are surfaced as Prometheus metrics by the RPC layer
//! (`tron_node_consensus_divergences_total`), independent of whether
//! `verify_contract_ret` is set to also HARD-REJECT the block. Recording is a
//! single relaxed atomic add plus a mutex store on the (rare) divergence path,
//! so it is free on the hot path.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// A single observed consensus divergence (a tx whose success/failure outcome
/// disagreed with the canonical block).
#[derive(Clone, Debug)]
pub struct ConsensusDivergence {
    pub block: i64,
    pub tx_id: String,
    /// Canonical (block) outcome, e.g. `"SUCCESS"` / `"OUT_OF_ENERGY"`.
    pub block_result: String,
    /// What this node computed.
    pub computed_result: String,
    /// Decoded reason (revert message / halt / outcome variant).
    pub reason: String,
}

static DIVERGENCE_COUNT: AtomicU64 = AtomicU64::new(0);
static LAST_DIVERGENCE: Mutex<Option<ConsensusDivergence>> = Mutex::new(None);

/// Record a consensus divergence. Called from the apply-block tripwire.
pub fn record(divergence: ConsensusDivergence) {
    DIVERGENCE_COUNT.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut slot) = LAST_DIVERGENCE.lock() {
        *slot = Some(divergence);
    }
}

/// Total consensus divergences observed since process start.
pub fn divergence_count() -> u64 {
    DIVERGENCE_COUNT.load(Ordering::Relaxed)
}

/// The most recently observed divergence, if any.
pub fn last_divergence() -> Option<ConsensusDivergence> {
    LAST_DIVERGENCE.lock().ok().and_then(|s| s.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_increments_count_and_stores_last() {
        let before = divergence_count();
        record(ConsensusDivergence {
            block: 83_349_051,
            tx_id: "a7baf8e0".into(),
            block_result: "SUCCESS".into(),
            computed_result: "OUT_OF_ENERGY".into(),
            reason: "VM halt: OutOfGas(Basic)".into(),
        });
        assert_eq!(divergence_count(), before + 1);
        let last = last_divergence().expect("last divergence stored");
        assert_eq!(last.block, 83_349_051);
        assert_eq!(last.block_result, "SUCCESS");
        assert_eq!(last.computed_result, "OUT_OF_ENERGY");
    }
}
