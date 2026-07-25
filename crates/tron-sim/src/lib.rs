//! Chronos — deterministic time-travel fork simulation for TRON.
//!
//! Fork the chain at a historical block (or head), open a mutable,
//! never-committed overlay seeded from real archived state, and run
//! arbitrary *mutating* transactions through the TVM — with state, code,
//! balance, and block-environment overrides — returning per-call status,
//! return data, energy, logs, the internal-transaction tree, the opcode
//! trace, and state diffs. anvil-fork / Tenderly for TRON, byte-exact.
//!
//! This crate is the simulation engine only: it depends on
//! [`tron_chainbase`], [`tron_index`], and [`tron_tvm`], and deliberately
//! does **not** depend on `tron-rpc` (which wires it into the JSON-RPC /
//! REST surface). The overlay never reaches disk — height-based bases sit
//! on read-only at-height archive views and no session is ever committed.

mod config;
mod diff;
mod error;
mod execute;
mod overlay;
mod override_set;
mod registry;
mod request;
mod result;

pub use config::SimConfig;
pub use diff::{AccountDiff, CodeDiff, DecodedStateDiff, StorageDiff};
pub use error::SimError;
pub use execute::run_bundle;
pub use overlay::{
    BaseBlock, DiffEntry, ForkBackends, ForkCheckpoint, ForkOverlay, RawStateDiff,
};
pub use override_set::{AccountOverride, BlockOverride, OverrideSet};
pub use registry::{fork_id_from_hex, fork_id_hex, ForkId, ForkInfo, ForkSession, SimState};
pub use request::{BlockSpec, CallSpec, DiffLevel, SimRequest, TraceLevel};
pub use result::{Basis, CallResult, CallStatus, SimBlockResult, SimResult, VmLogOut};

// Re-export the tracer types the result model surfaces, so consumers don't
// need a direct tron-tvm dependency just to read a CallResult.
pub use tron_tvm::tracer::{CallFrame, StructLog};
