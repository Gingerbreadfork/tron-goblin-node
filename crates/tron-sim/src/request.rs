//! The bundle request model: what to run, how to trace, what to diff.

use tron_crypto::address::Address;

use crate::override_set::OverrideSet;

/// How much trace detail to capture per call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceLevel {
    /// No tracer — status/return/energy/logs and the internal-tx tree only.
    None,
    /// Call tree (geth `callTracer`) — the CALL/CREATE frame hierarchy.
    CallTree,
    /// Full opcode struct-logs plus the call tree (geth default tracer).
    Full,
}

/// How much state diff to return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffLevel {
    /// No diff.
    None,
    /// One cumulative diff for the whole bundle.
    Final,
    /// A diff per call (and the cumulative one).
    PerCall,
}

/// A single call in a synthetic block.
#[derive(Debug, Clone)]
pub enum CallSpec {
    /// `TriggerSmartContract` — call an existing address (or transfer).
    Trigger {
        from: Address,
        to: Address,
        value: i64,
        data: Vec<u8>,
        energy: Option<u64>,
        /// TRC-10 top-level transfer (CALLTOKEN); `0` for none.
        token_id: i64,
        token_value: i64,
    },
    /// `CreateSmartContract` — deploy `init_code`.
    Create {
        from: Address,
        init_code: Vec<u8>,
        value: i64,
        energy: Option<u64>,
        consume_user_resource_percent: i64,
        name: String,
        token_id: i64,
        token_value: i64,
    },
}

/// One synthetic block: overrides applied before its calls run, then the
/// calls in order.
#[derive(Debug, Clone, Default)]
pub struct BlockSpec {
    pub overrides: OverrideSet,
    pub calls: Vec<CallSpec>,
}

/// A whole bundle to run against an already-constructed fork overlay. The
/// base (historical height vs latest) is baked into the overlay, so it is
/// not part of the request.
#[derive(Debug, Clone)]
pub struct SimRequest {
    pub blocks: Vec<BlockSpec>,
    pub trace: TraceLevel,
    pub return_state_diff: DiffLevel,
    /// Re-run block N+1's real VM txs and compare to stored receipts
    /// (parity self-check). Best-effort; wired by the caller.
    pub self_check: bool,
    /// Per-call energy ask; clamped to the config cap. `None` ⇒ use the cap.
    pub energy_cap: Option<u64>,
}

impl Default for SimRequest {
    fn default() -> Self {
        Self {
            blocks: Vec::new(),
            trace: TraceLevel::None,
            return_state_diff: DiffLevel::Final,
            self_check: false,
            energy_cap: None,
        }
    }
}
