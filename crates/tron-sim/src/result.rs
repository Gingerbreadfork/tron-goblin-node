//! The bundle result model — what a simulation returns, engine-side (the
//! RPC/REST layers format these into their JSON shapes).

use tron_crypto::address::Address;
use tron_tvm::tracer::{CallFrame, StructLog};

use crate::diff::DecodedStateDiff;

/// Outcome class of one call, mapped from `tron_tvm::execute::VmOutcome`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallStatus {
    Success,
    Revert,
    /// A value-transfer raised java's `TransferException` (consumed-only
    /// energy, whole tx unwound). Distinct from a plain revert.
    TransferFailed,
    /// VM halt (OOG, invalid opcode, …). Carries java's `contractResult`
    /// name for the halt.
    Halt(String),
    /// The VM could not even be built (malformed input, etc.).
    Error,
    /// The per-call wall-clock deadline tripped.
    Timeout,
}

impl CallStatus {
    /// Uppercase label for JSON (`"SUCCESS"`, `"REVERT"`, …).
    pub fn label(&self) -> &'static str {
        match self {
            CallStatus::Success => "SUCCESS",
            CallStatus::Revert => "REVERT",
            CallStatus::TransferFailed => "TRANSFER_FAILED",
            CallStatus::Halt(_) => "HALT",
            CallStatus::Error => "ERROR",
            CallStatus::Timeout => "TIMEOUT",
        }
    }
}

/// One LOG emission, addresses in 20-byte EVM form.
#[derive(Debug, Clone)]
pub struct VmLogOut {
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

/// Everything one call produced.
#[derive(Debug, Clone)]
pub struct CallResult {
    pub status: CallStatus,
    pub return_data: Vec<u8>,
    pub energy_used: u64,
    /// java `ProgramResult.energyPenaltyTotal` (dynamic-energy penalty).
    pub energy_penalty: u64,
    pub logs: Vec<VmLogOut>,
    /// Set for `Create` calls: the deterministic deployed address.
    pub contract_address: Option<Address>,
    pub internal_transactions: Vec<tron_proto::InternalTransaction>,
    /// Tracer call tree; empty when `trace = None`.
    pub call_frames: Vec<CallFrame>,
    /// Opcode struct-logs; only populated when `trace = Full`.
    pub struct_logs: Vec<StructLog>,
    /// True when the `max_struct_logs` cap dropped some opcode logs (the trace
    /// is partial).
    pub struct_logs_truncated: bool,
    /// Per-call diff; only when `return_state_diff = PerCall`.
    pub state_diff: Option<DecodedStateDiff>,
    /// Human-readable error detail (revert reason, halt reason, …).
    pub error: Option<String>,
}

/// Results for one synthetic block.
#[derive(Debug, Clone)]
pub struct SimBlockResult {
    pub number: i64,
    pub timestamp_ms: i64,
    pub energy_used: u64,
    pub calls: Vec<CallResult>,
}

/// The honesty header carried on every response (see the plan §7).
#[derive(Debug, Clone)]
pub struct Basis {
    /// The fork's base height (for a latest base, the current head number).
    pub base_block: i64,
    /// Always `"vm"` for v1 (real VM, real state, real energy — but no
    /// bandwidth charging / fee-limit admission / non-VM contract types).
    pub mode: &'static str,
    /// `[base, head]` the archive can serve, when forking historically.
    pub archive_coverage: Option<(i64, i64)>,
    /// Always `"block-boundary"` in v1 — a fork "at N" is the state after
    /// block N fully applied.
    pub granularity: &'static str,
    pub warnings: Vec<String>,
}

/// The whole bundle result.
#[derive(Debug, Clone)]
pub struct SimResult {
    pub basis: Basis,
    pub blocks: Vec<SimBlockResult>,
    /// Cumulative diff across the bundle; present when `return_state_diff`
    /// is `Final` or `PerCall`.
    pub state_diff: Option<DecodedStateDiff>,
    pub warnings: Vec<String>,
}
