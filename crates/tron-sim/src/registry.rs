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
    // Require ASCII so the fixed 2-byte slicing below always lands on char
    // boundaries — a multi-byte UTF-8 char in a 32-byte string would otherwise
    // panic (`byte index N is not a char boundary`) on attacker input.
    if !s.is_ascii() || s.len() != 32 {
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

    /// Lock the registry map, recovering from poisoning (a panic while the
    /// map lock was held must not brick the whole subsystem).
    fn lock_map(&self) -> std::sync::MutexGuard<'_, HashMap<ForkId, Arc<Mutex<ForkSession>>>> {
        self.forks.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Register a new fork over `overlay`, evicting expired forks and, if at
    /// capacity, the least-recently-used one. Returns the new fork id.
    pub fn create(&self, overlay: ForkOverlay) -> ForkId {
        let mut forks = self.lock_map();
        self.evict_expired(&mut forks);
        if forks.len() >= self.config.max_forks {
            // Pick the least-recently-used *idle* fork. Currently-locked forks
            // (a call is running) are skipped — they aren't idle, and we must
            // not block on their lock while holding the map lock.
            let lru = forks
                .iter()
                .filter_map(|(k, s)| session_last_used(s).map(|lu| (lu, *k)))
                .min()
                .map(|(_, k)| k);
            if let Some(k) = lru {
                forks.remove(&k);
            }
            // If every fork is busy, we proceed one over capacity rather than
            // block; the next create reclaims once one frees up.
        }
        let id = random_id();
        forks.insert(id, Arc::new(Mutex::new(ForkSession::new(id, overlay))));
        id
    }

    /// The fork handle, if it exists. The caller locks it to run/snapshot.
    pub fn get(&self, id: &ForkId) -> Option<Arc<Mutex<ForkSession>>> {
        self.lock_map().get(id).cloned()
    }

    /// Remove a fork. Returns whether it existed.
    pub fn delete(&self, id: &ForkId) -> bool {
        self.lock_map().remove(id).is_some()
    }

    /// Snapshot of all live forks (after evicting expired ones). A fork whose
    /// call is currently running is skipped (its lock is held) rather than
    /// blocking the listing.
    pub fn list(&self) -> Vec<ForkInfo> {
        let mut forks = self.lock_map();
        self.evict_expired(&mut forks);
        forks
            .values()
            .filter_map(|s| {
                let g = match s.try_lock() {
                    Ok(g) => g,
                    Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
                    Err(std::sync::TryLockError::WouldBlock) => return None,
                };
                Some(ForkInfo {
                    fork_id: g.fork_id,
                    created: g.created,
                    last_used: g.last_used,
                    overlay_keys: g.overlay.overlay_keys(),
                })
            })
            .collect()
    }

    fn evict_expired(&self, forks: &mut HashMap<ForkId, Arc<Mutex<ForkSession>>>) {
        let ttl = Duration::from_secs(self.config.fork_ttl_secs);
        let now = Instant::now();
        forks.retain(|_, s| match session_last_used(s) {
            // Idle long enough → evict.
            Some(last) => now.duration_since(last) < ttl,
            // Currently locked (a call is running) → clearly in use, keep it.
            None => true,
        });
    }
}

/// Read a session's `last_used` WITHOUT blocking: `None` if the session lock is
/// currently held (a call is running). Recovers a poisoned lock so a prior VM
/// panic can't cascade into the registry.
fn session_last_used(s: &Arc<Mutex<ForkSession>>) -> Option<Instant> {
    match s.try_lock() {
        Ok(g) => Some(g.last_used),
        Err(std::sync::TryLockError::Poisoned(e)) => Some(e.into_inner().last_used),
        Err(std::sync::TryLockError::WouldBlock) => None,
    }
}
