//! Per-peer dial-recency state persisted across binary restarts.
//!
//! Why: java-tron's `ChannelManager.notifyDisconnect` puts our IP into
//! a 60-second `bannedNodes` cache **on every disconnect we trigger**,
//! including the TIME_BANNED rejection of our own dial. If we stop the
//! binary mid-attempts and restart within that window, the first thing
//! we do is re-dial the same peers — which (a) gets us TIME_BANNED
//! again because they still have our IP cached, and (b) refreshes
//! their ban for another 60s. The bans compound across restarts.
//!
//! This module persists `(peer_addr -> last_attempt_unix_ms)` to a JSON
//! file under the data dir. On startup the runtime can skip any peer
//! dialed within the last [`SKIP_AFTER_DIAL_MS`] window, letting the
//! upstream `bannedNodes` cache age out before we try again. On each
//! peer attempt (success OR failure), the entry is updated. The file
//! is best-effort — read/write errors are logged, never fatal.
//!
//! Format:
//! ```json
//! {
//!   "3.225.171.164:18888": 1716579600123,
//!   "13.210.151.5:18888": 1716579605789
//! }
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

/// Skip a peer on startup if we dialed it more recently than this.
/// 90_000 ms = peer's 60s `bannedNodes` window + 30s margin.
pub const SKIP_AFTER_DIAL_MS: u64 = 90_000;

/// How long to avoid re-dialing a peer found to be far BEHIND our head (it has
/// no blocks we need for catch-up, so dialing it just burns a rotation slot). It
/// may catch up later, so this is a re-evaluation window, not a permanent ban.
pub const AVOID_BEHIND_MS: u64 = 10 * 60_000;

/// How long to avoid a peer that rejected us (BAD_PROTOCOL / version / refusal)
/// before its sync request — a bad fetch source. Shorter than behind, since a
/// rejection can be transient (the peer was busy / banned us briefly).
pub const AVOID_REJECT_MS: u64 = 5 * 60_000;

/// File name written under the data directory.
pub const STATE_FILE: &str = "peer_state.json";

/// On-disk + in-memory representation.
#[derive(Default, Serialize, Deserialize)]
struct PeerStateFile {
    /// Peer dial-attempt timestamps, unix-ms.
    #[serde(default)]
    last_dial_ms: HashMap<String, u64>,
    /// Peer → unix-ms timestamp until which the peer should be skipped in
    /// rotation because it's a poor sync source (far behind us, or it rejected
    /// us). Cleared the moment a peer actually serves us a block. Keeps the 24
    /// rotation drivers from burning slots on dead-end peers while a handful of
    /// ahead peers carry the fetch load.
    #[serde(default)]
    avoid_until_ms: HashMap<String, u64>,
}

/// Clone-friendly handle to the peer-state. Internally a single
/// `Mutex<HashMap>` shared across all sync drivers. Cheap to clone.
#[derive(Clone)]
pub struct PeerState {
    inner: std::sync::Arc<Mutex<PeerStateInner>>,
}

struct PeerStateInner {
    path: PathBuf,
    file: PeerStateFile,
    dirty: bool,
}

impl PeerState {
    /// Load the state file at `data_dir/peer_state.json` (or start
    /// empty if the file is absent / unreadable). Subsequent calls to
    /// [`Self::touch`] mutate in memory; [`Self::flush`] writes back
    /// to disk.
    pub fn load(data_dir: &Path) -> Self {
        let path = data_dir.join(STATE_FILE);
        let file = match std::fs::read_to_string(&path) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_else(|e| {
                warn!(path = %path.display(), error = %e,
                      "peer-state file unparseable; starting empty");
                PeerStateFile::default()
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                PeerStateFile::default()
            }
            Err(e) => {
                warn!(path = %path.display(), error = %e,
                      "peer-state file unreadable; starting empty");
                PeerStateFile::default()
            }
        };
        let inner = PeerStateInner { path, file, dirty: false };
        Self {
            inner: std::sync::Arc::new(Mutex::new(inner)),
        }
    }

    /// Record that we just attempted (or are about to attempt) a dial
    /// against `peer`. Stamps the current wall-clock time.
    pub fn touch(&self, peer: &str) {
        let now = now_ms();
        let mut g = self.inner.lock().expect("peer-state poisoned");
        g.file.last_dial_ms.insert(peer.to_string(), now);
        g.dirty = true;
    }

    /// True if `peer` was dialed within the last [`SKIP_AFTER_DIAL_MS`]
    /// window. Used at startup to filter the initial dial list.
    pub fn was_dialed_recently(&self, peer: &str) -> bool {
        let g = self.inner.lock().expect("peer-state poisoned");
        let Some(&ts) = g.file.last_dial_ms.get(peer) else {
            return false;
        };
        let now = now_ms();
        now.saturating_sub(ts) < SKIP_AFTER_DIAL_MS
    }

    /// Mark `peer` as a poor sync source to skip for `cooldown_ms` (use
    /// [`AVOID_BEHIND_MS`] for a far-behind peer, [`AVOID_REJECT_MS`] for a
    /// rejection). Extends an existing cooldown rather than shortening it.
    pub fn mark_avoid(&self, peer: &str, cooldown_ms: u64) {
        let until = now_ms().saturating_add(cooldown_ms);
        let mut g = self.inner.lock().expect("peer-state poisoned");
        let e = g.file.avoid_until_ms.entry(peer.to_string()).or_insert(0);
        if until > *e {
            *e = until;
            g.dirty = true;
        }
    }

    /// Clear any avoid-cooldown on `peer` — it just served us a block, so it's
    /// a useful peer; keep dialing it.
    pub fn mark_useful(&self, peer: &str) {
        let mut g = self.inner.lock().expect("peer-state poisoned");
        if g.file.avoid_until_ms.remove(peer).is_some() {
            g.dirty = true;
        }
    }

    /// True if `peer` is currently within an avoid-cooldown (far behind /
    /// rejected) and should be skipped in rotation while better peers exist.
    pub fn should_avoid(&self, peer: &str) -> bool {
        let g = self.inner.lock().expect("peer-state poisoned");
        g.file
            .avoid_until_ms
            .get(peer)
            .map(|&until| now_ms() < until)
            .unwrap_or(false)
    }

    /// Write the state to disk if it has been mutated since the last
    /// flush. Errors are logged but never returned — peer-state is
    /// purely advisory.
    pub fn flush(&self) {
        let mut g = self.inner.lock().expect("peer-state poisoned");
        if !g.dirty {
            return;
        }
        match serde_json::to_string_pretty(&g.file) {
            Ok(s) => match std::fs::write(&g.path, s) {
                Ok(_) => {
                    g.dirty = false;
                    debug!(path = %g.path.display(),
                           entries = g.file.last_dial_ms.len(),
                           "peer-state flushed");
                }
                Err(e) => warn!(path = %g.path.display(), error = %e,
                                "peer-state flush failed"),
            },
            Err(e) => warn!(error = %e, "peer-state serialize failed"),
        }
    }

    /// Drop entries older than `max_age_ms`. Keeps the file from
    /// growing without bound as we cycle through DNS-discovered peers.
    pub fn prune(&self, max_age_ms: u64) -> usize {
        let now = now_ms();
        let mut g = self.inner.lock().expect("peer-state poisoned");
        let before = g.file.last_dial_ms.len();
        g.file
            .last_dial_ms
            .retain(|_, ts| now.saturating_sub(*ts) < max_age_ms);
        let after = g.file.last_dial_ms.len();
        let removed = before - after;
        // Drop expired avoid-cooldowns too (a long-past `avoid_until` is dead
        // weight; `should_avoid` already treats it as not-avoided).
        let avoid_before = g.file.avoid_until_ms.len();
        g.file.avoid_until_ms.retain(|_, until| *until > now);
        if removed > 0 || g.file.avoid_until_ms.len() != avoid_before {
            g.dirty = true;
        }
        removed
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "tron-peer-state-{}-{}-{}",
            std::process::id(),
            now_ms(),
            n
        ))
    }

    #[test]
    fn load_missing_file_returns_empty() {
        let dir = tmpdir();
        std::fs::create_dir_all(&dir).unwrap();
        let s = PeerState::load(&dir);
        assert!(!s.was_dialed_recently("1.2.3.4:18888"));
    }

    #[test]
    fn touch_then_recent_check_returns_true() {
        let dir = tmpdir();
        std::fs::create_dir_all(&dir).unwrap();
        let s = PeerState::load(&dir);
        s.touch("1.2.3.4:18888");
        assert!(s.was_dialed_recently("1.2.3.4:18888"));
        assert!(!s.was_dialed_recently("5.6.7.8:18888"));
    }

    #[test]
    fn flush_then_reload_preserves_state() {
        let dir = tmpdir();
        std::fs::create_dir_all(&dir).unwrap();
        let s = PeerState::load(&dir);
        s.touch("1.2.3.4:18888");
        s.flush();
        // Fresh instance — should see the touch via the file.
        let s2 = PeerState::load(&dir);
        assert!(s2.was_dialed_recently("1.2.3.4:18888"));
    }

    #[test]
    fn prune_removes_old_entries() {
        let dir = tmpdir();
        std::fs::create_dir_all(&dir).unwrap();
        let s = PeerState::load(&dir);
        // Manually inject an ancient entry.
        {
            let mut g = s.inner.lock().unwrap();
            g.file.last_dial_ms.insert("ancient:18888".into(), 1_000);
            g.file.last_dial_ms.insert("recent:18888".into(), now_ms());
        }
        let removed = s.prune(60_000);
        assert_eq!(removed, 1);
        assert!(!s.was_dialed_recently("ancient:18888"));
        assert!(s.was_dialed_recently("recent:18888"));
    }

    #[test]
    fn mark_avoid_then_should_avoid_true_until_cleared() {
        let dir = tmpdir();
        std::fs::create_dir_all(&dir).unwrap();
        let s = PeerState::load(&dir);
        assert!(!s.should_avoid("p:18888"));
        s.mark_avoid("p:18888", 60_000);
        assert!(s.should_avoid("p:18888"), "cooldown active");
        // A short cooldown does not shorten a longer one.
        s.mark_avoid("p:18888", 1);
        assert!(s.should_avoid("p:18888"), "longer cooldown retained");
        // Serving a block clears it.
        s.mark_useful("p:18888");
        assert!(!s.should_avoid("p:18888"), "useful clears cooldown");
    }

    #[test]
    fn expired_avoid_is_not_avoided_and_pruned() {
        let dir = tmpdir();
        std::fs::create_dir_all(&dir).unwrap();
        let s = PeerState::load(&dir);
        {
            let mut g = s.inner.lock().unwrap();
            g.file.avoid_until_ms.insert("old:18888".into(), 1_000); // long past
        }
        assert!(!s.should_avoid("old:18888"), "past cooldown is not avoided");
        s.prune(60_000);
        let g = s.inner.lock().unwrap();
        assert!(!g.file.avoid_until_ms.contains_key("old:18888"), "pruned");
    }

    #[test]
    fn unparseable_file_starts_empty() {
        let dir = tmpdir();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(STATE_FILE), b"not json").unwrap();
        let s = PeerState::load(&dir);
        assert!(!s.was_dialed_recently("anything"));
    }
}
