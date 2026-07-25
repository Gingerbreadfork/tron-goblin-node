//! Error type for the fork-simulation layer.

use tron_chainbase::KvError;

/// Everything a Chronos fork operation can fail with. Kept a single
/// crate-wide error so the RPC layer maps one type to JSON-RPC codes.
#[derive(Debug, thiserror::Error)]
pub enum SimError {
    /// A historical (at-height) fork was requested for a block outside
    /// the archive's captured coverage window. Carries the requested
    /// height and the `[base, head]` the archive can actually serve, so
    /// the caller can surface the exact window (no silent clamping —
    /// see the plan's honesty rules).
    #[error("block {height} outside archive coverage [{base}, {head}] — history below the base was not captured")]
    OutOfCoverage { height: i64, base: i64, head: i64 },

    /// A historical fork was requested but the archive has no coverage
    /// at all (capture was never enabled, or the meta rows are missing).
    #[error("archive has no captured coverage; enable [index] capture_state_deltas to fork at a historical height")]
    NoCoverage,

    /// A per-fork overlay grew past its configured key cap. The
    /// offending operation is refused; the fork itself is left intact.
    #[error("fork overlay cap exceeded: {keys} keys > limit {limit}")]
    OverlayCapExceeded { keys: usize, limit: usize },

    /// A backend read/write failed underneath the overlay.
    #[error("backend error: {0}")]
    Backend(String),
}

impl From<KvError> for SimError {
    fn from(e: KvError) -> Self {
        SimError::Backend(e.to_string())
    }
}
