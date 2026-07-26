//! Fork-simulation limits & DoS posture. All caps live here so the node's
//! `[sim]` config maps one-to-one onto them.

/// Chronos runtime configuration (`[sim]` in the node config).
#[derive(Debug, Clone)]
pub struct SimConfig {
    /// Master switch. Default **off** — Chronos executes arbitrary code with
    /// large energy budgets and holds per-fork memory, so operators opt in.
    pub enabled: bool,
    /// Max concurrent named fork sessions before LRU eviction.
    pub max_forks: usize,
    /// A fork session is evicted this many seconds after its last use.
    pub fork_ttl_secs: u64,
    /// Hard cap on a single fork's overlay size (summed pending keys across
    /// every layer). Exceeded ⇒ the offending call fails; the fork survives.
    pub max_overlay_keys: usize,
    /// Max calls in one bundle request.
    pub max_calls_per_bundle: usize,
    /// Max synthetic blocks in one bundle request.
    pub max_blocks_per_bundle: usize,
    /// Per-call energy budget ceiling. A request may ask for less; a request
    /// that explicitly asks for more is lifted to its own `energy` up to this
    /// cap (mirrors `dispatch_constant_trigger`'s cap-lift).
    pub energy_cap: u64,
    /// Max slots a `state` (replace-all) override may enumerate before it
    /// errors (suggesting `stateDiff` instead) — honesty over truncation.
    pub max_state_override_slots: usize,
    /// Per-call cap on the NUMBER of opcode struct-logs (`trace = Full`).
    /// `0` = unlimited.
    pub max_struct_logs: usize,
    /// Per-call approximate BYTE budget for struct-logs. Each log clones the
    /// EVM stack (≤32 KiB), so the count cap alone doesn't bound memory; this
    /// does. `0` = unlimited.
    pub max_struct_log_bytes: usize,
    /// Per-call cap on retained call-tree frames (`trace = callTree`/`full`).
    /// Bounds a call-heavy contract's tree. `0` = unlimited.
    pub max_call_frames: usize,
    /// Per-call wall-clock deadline in ms; `0` disables it (the default). When
    /// enabled it preempts a runaway call, but a call that trips it becomes
    /// **non-deterministic across machines** (timeout on a slow host, success
    /// on a fast one) — so it is off by default to preserve byte-exact replay.
    /// The per-call energy budget (`energy_cap`) is the deterministic compute
    /// bound; this is an optional operator-chosen wall-clock guard on top.
    pub call_timeout_ms: u64,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_forks: 8,
            fork_ttl_secs: 3600,
            max_overlay_keys: 1_000_000,
            max_calls_per_bundle: 256,
            max_blocks_per_bundle: 64,
            // = rpc.eth_call_gas_cap default (50M).
            energy_cap: 50_000_000,
            max_state_override_slots: 10_000,
            max_struct_logs: 100_000,
            // ~128 MiB of struct-logs per call (bounds the deep-stack case).
            max_struct_log_bytes: 128 * 1024 * 1024,
            max_call_frames: 100_000,
            // Off by default: determinism (byte-exact replay) beats a
            // wall-clock guard, and energy_cap already bounds compute.
            call_timeout_ms: 0,
        }
    }
}

impl SimConfig {
    /// Resolve a call's energy budget: the request's ask (or the cap when
    /// unspecified), clamped so it never exceeds `energy_cap`. Mirrors the
    /// constant-call cap-lift: an explicit ask up to the cap is honoured.
    pub fn resolve_energy(&self, requested: Option<u64>) -> u64 {
        requested.unwrap_or(self.energy_cap).min(self.energy_cap)
    }
}
