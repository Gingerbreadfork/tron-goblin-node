//! Named fork sessions — anvil-style persistent forks the RPC layer keeps
//! alive across calls, with snapshot/revert, TTL + LRU eviction, and a hard
//! per-fork overlay-key cap.
//!
//! One `Mutex` guards the registry map; each fork sits behind its own `Mutex`,
//! so calls on one fork serialize (bundle ordering matters) while distinct
//! forks run concurrently. Fork ids are unguessable (CSPRNG) and node-local.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::SimConfig;
use crate::diff::DecodedStateDiff;
use crate::error::SimError;
use crate::execute::run_bundle;
use crate::overlay::{ForkCheckpoint, ForkOverlay};
use crate::request::SimRequest;
use crate::result::SimResult;

/// 16-byte unguessable fork identifier.
pub type ForkId = [u8; 16];

/// Lowercase-hex form of a fork id (the API-facing string).
pub fn fork_id_hex(id: &ForkId) -> String {
    let mut s = String::with_capacity(32);
    for b in id {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Parse a hex fork id back to bytes.
pub fn fork_id_from_hex(s: &str) -> Option<ForkId> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 32 {
        return None;
    }
    let mut id = [0u8; 16];
    for (i, out) in id.iter_mut().enumerate() {
        *out = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(id)
}

fn random_id() -> ForkId {
    let mut id = [0u8; 16];
    // CSPRNG; on the astronomically unlikely error the zero id is still
    // node-local and immediately overwritten by the next create.
    let _ = getrandom::getrandom(&mut id);
    id
}

/// One live fork: its overlay, snapshot stack, and bookkeeping.
pub struct ForkSession {
    pub overlay: ForkOverlay,
    pub fork_id: ForkId,
    /// `(snapshot_id, checkpoint)` in creation order.
    snapshots: Vec<(u64, ForkCheckpoint)>,
    next_snapshot: u64,
    pub created: Instant,
    pub last_used: Instant,
    /// Advancing synthetic head `(number, timestamp_ms)` so successive
    /// `forkCall`s continue block numbering instead of reusing numbers.
    pub synthetic_head: (i64, i64),
}

impl ForkSession {
    fn new(fork_id: ForkId, overlay: ForkOverlay) -> Self {
        let head = overlay.seed_head();
        let now = Instant::now();
        Self {
            overlay,
            fork_id,
            snapshots: Vec::new(),
            next_snapshot: 1,
            created: now,
            last_used: now,
            synthetic_head: head,
        }
    }

    /// Run a bundle, advancing the fork's synthetic head.
    pub fn run(&mut self, req: &SimRequest, cfg: &SimConfig) -> Result<SimResult, SimError> {
        let res = run_bundle(
            &mut self.overlay,
            req,
            cfg,
            self.fork_id,
            Some(self.synthetic_head),
        )?;
        if let Some(last) = res.blocks.last() {
            self.synthetic_head = (last.number, last.timestamp_ms);
        }
        self.last_used = Instant::now();
        Ok(res)
    }

    /// Take a snapshot; returns its id (anvil `evm_snapshot`).
    pub fn snapshot(&mut self) -> u64 {
        let cp = self.overlay.checkpoint();
        let id = self.next_snapshot;
        self.next_snapshot += 1;
        self.snapshots.push((id, cp));
        self.last_used = Instant::now();
        id
    }

    /// Revert to a snapshot (anvil `evm_revert`). Consumes that snapshot and
    /// every one taken after it.
    pub fn revert(&mut self, snapshot_id: u64) -> Result<(), SimError> {
        let pos = self
            .snapshots
            .iter()
            .position(|(sid, _)| *sid == snapshot_id)
            .ok_or_else(|| SimError::Backend(format!("unknown snapshot {snapshot_id}")))?;
        let (_, cp) = self.snapshots[pos];
        self.overlay.revert_to(cp);
        self.snapshots.truncate(pos);
        self.last_used = Instant::now();
        Ok(())
    }

    /// The fork's cumulative diff against its base.
    pub fn state_diff(&self) -> Result<DecodedStateDiff, SimError> {
        Ok(DecodedStateDiff::from_raw(self.overlay.cumulative_diff()?))
    }
}

/// Metadata for `tron_forkList`.
#[derive(Debug, Clone)]
pub struct ForkInfo {
    pub fork_id: ForkId,
    pub created: Instant,
    pub last_used: Instant,
    pub overlay_keys: usize,
}

/// The fork registry, `Arc`'d into the RPC state.
pub struct SimState {
    forks: Mutex<HashMap<ForkId, Arc<Mutex<ForkSession>>>>,
    config: SimConfig,
}

impl SimState {
    pub fn new(config: SimConfig) -> Self {
        Self { forks: Mutex::new(HashMap::new()), config }
    }

    pub fn config(&self) -> &SimConfig {
        &self.config
    }

    /// Register a new fork over `overlay`, evicting expired forks and, if at
    /// capacity, the least-recently-used one. Returns the new fork id.
    pub fn create(&self, overlay: ForkOverlay) -> ForkId {
        let mut forks = self.forks.lock().expect("sim registry poisoned");
        self.evict_expired(&mut forks);
        if forks.len() >= self.config.max_forks {
            if let Some(lru) = forks
                .iter()
                .min_by_key(|(_, s)| s.lock().expect("fork poisoned").last_used)
                .map(|(k, _)| *k)
            {
                forks.remove(&lru);
            }
        }
        let id = random_id();
        forks.insert(id, Arc::new(Mutex::new(ForkSession::new(id, overlay))));
        id
    }

    /// The fork handle, if it exists. The caller locks it to run/snapshot.
    pub fn get(&self, id: &ForkId) -> Option<Arc<Mutex<ForkSession>>> {
        self.forks.lock().expect("sim registry poisoned").get(id).cloned()
    }

    /// Remove a fork. Returns whether it existed.
    pub fn delete(&self, id: &ForkId) -> bool {
        self.forks.lock().expect("sim registry poisoned").remove(id).is_some()
    }

    /// Snapshot of all live forks (after evicting expired ones).
    pub fn list(&self) -> Vec<ForkInfo> {
        let mut forks = self.forks.lock().expect("sim registry poisoned");
        self.evict_expired(&mut forks);
        forks
            .values()
            .map(|s| {
                let g = s.lock().expect("fork poisoned");
                ForkInfo {
                    fork_id: g.fork_id,
                    created: g.created,
                    last_used: g.last_used,
                    overlay_keys: g.overlay.overlay_keys(),
                }
            })
            .collect()
    }

    fn evict_expired(&self, forks: &mut HashMap<ForkId, Arc<Mutex<ForkSession>>>) {
        let ttl = Duration::from_secs(self.config.fork_ttl_secs);
        let now = Instant::now();
        forks.retain(|_, s| {
            let last = s.lock().expect("fork poisoned").last_used;
            now.duration_since(last) < ttl
        });
    }
}
