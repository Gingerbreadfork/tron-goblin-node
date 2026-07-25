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

mod error;
mod overlay;
mod override_set;

pub use error::SimError;
pub use overlay::{
    BaseBlock, DiffEntry, ForkBackends, ForkCheckpoint, ForkOverlay, RawStateDiff,
};
pub use override_set::{AccountOverride, BlockOverride, OverrideSet};
