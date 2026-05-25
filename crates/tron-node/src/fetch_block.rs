//! Single-block fetch with parallel-fetch backpressure.
//!
//! Mirrors java-tron's `FetchBlockService`. The runtime sees many
//! inventory advertisements per second; without a gate, we'd issue a
//! FetchInvData per peer per advertised hash. Instead, this service
//! keeps at most one fetch in flight at a time and waits for a
//! response (or its budget to expire) before dispatching the next.
//!
//! The budget is `fetch_timeout * BLOCK_FETCH_LEFT_TIME_PERCENT` —
//! when more than `BLOCK_FETCH_LEFT_TIME_PERCENT` of the timeout has
//! elapsed, the in-flight slot is released even if no body has
//! arrived yet (java-tron's "left-time" heuristic — assumes the body
//! is lost and lets the next try go).

use std::time::Duration;

/// java-tron's hard-coded percentage of the timeout after which the
/// fetch slot is considered "leftover available" and can be reused.
pub const BLOCK_FETCH_LEFT_TIME_PERCENT: f64 = 0.5;

/// A pending fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchBlockInfo {
    /// 32-byte block hash being requested.
    pub block_hash: [u8; 32],
    /// Peer key (libp2p id / IP:port string).
    pub peer_key: String,
    /// Wall-clock unix-ms when the fetch was dispatched.
    pub started_ms: u64,
}

/// Single-slot scheduler. Pure state machine — no I/O — so the host
/// driver wires it to its own peer-write surface.
#[derive(Debug, Clone)]
pub struct FetchBlockScheduler {
    pub fetch_timeout: Duration,
    in_flight: Option<FetchBlockInfo>,
}

/// Outcome of `try_fetch` — tells the caller whether to actually
/// send the FetchInvData frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchDecision {
    /// Slot was free; caller should issue the fetch. The scheduler
    /// has recorded the in-flight info already.
    Dispatch,
    /// A previous fetch is still in flight inside the budget window.
    /// Caller drops the request.
    Defer,
    /// Block isn't the next-expected number; java-tron silently
    /// ignores these (only fetches the very next block).
    NotNextBlock,
}

impl FetchBlockScheduler {
    pub fn new(fetch_timeout: Duration) -> Self {
        Self {
            fetch_timeout,
            in_flight: None,
        }
    }

    /// Returns the in-flight record, if any.
    pub fn in_flight(&self) -> Option<&FetchBlockInfo> {
        self.in_flight.as_ref()
    }

    /// Time budget in milliseconds (`fetch_timeout * left_pct`).
    pub fn budget_ms(&self) -> u64 {
        (self.fetch_timeout.as_millis() as f64 * BLOCK_FETCH_LEFT_TIME_PERCENT) as u64
    }

    /// Ask whether the host should dispatch a fetch for the given
    /// `(block_num, hash, peer)` triple.
    ///
    /// * `head_block_num` is the chain's current head — only blocks
    ///   at `head + 1` are eligible (java-tron parity).
    /// * `now_ms` is the wall-clock instant the decision is made.
    pub fn try_fetch(
        &mut self,
        block_num: i64,
        block_hash: [u8; 32],
        peer_key: &str,
        head_block_num: i64,
        now_ms: u64,
    ) -> FetchDecision {
        if block_num != head_block_num + 1 {
            return FetchDecision::NotNextBlock;
        }
        if let Some(existing) = &self.in_flight {
            let elapsed = now_ms.saturating_sub(existing.started_ms);
            if elapsed < self.budget_ms() {
                return FetchDecision::Defer;
            }
            // Budget exhausted — re-arm.
        }
        self.in_flight = Some(FetchBlockInfo {
            block_hash,
            peer_key: peer_key.into(),
            started_ms: now_ms,
        });
        FetchDecision::Dispatch
    }

    /// Mark the in-flight fetch as complete — called when a Block
    /// message arrives or after applying. Safe to call when nothing
    /// is in flight.
    pub fn complete(&mut self) -> Option<FetchBlockInfo> {
        self.in_flight.take()
    }

    /// Reclaim the slot when the fetch's hash matches the completed
    /// block. Returns whether the slot was actually released by this
    /// call (mismatches are ignored).
    pub fn complete_if_matches(&mut self, hash: &[u8; 32]) -> bool {
        if let Some(existing) = &self.in_flight {
            if &existing.block_hash == hash {
                self.in_flight = None;
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_of(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn first_fetch_dispatches() {
        let mut s = FetchBlockScheduler::new(Duration::from_secs(10));
        let dec = s.try_fetch(101, hash_of(1), "peer-a", 100, 1_000);
        assert_eq!(dec, FetchDecision::Dispatch);
        assert!(s.in_flight().is_some());
    }

    #[test]
    fn second_fetch_within_budget_defers() {
        let mut s = FetchBlockScheduler::new(Duration::from_secs(10));
        s.try_fetch(101, hash_of(1), "peer-a", 100, 1_000);
        let dec = s.try_fetch(101, hash_of(1), "peer-b", 100, 1_500);
        assert_eq!(dec, FetchDecision::Defer);
    }

    #[test]
    fn fetch_after_budget_re_arms() {
        let mut s = FetchBlockScheduler::new(Duration::from_secs(10));
        s.try_fetch(101, hash_of(1), "peer-a", 100, 1_000);
        // budget = 10s * 0.5 = 5s → after 6s the slot is reusable.
        let dec = s.try_fetch(101, hash_of(1), "peer-b", 100, 7_000);
        assert_eq!(dec, FetchDecision::Dispatch);
        assert_eq!(s.in_flight().unwrap().peer_key, "peer-b");
    }

    #[test]
    fn non_next_block_is_rejected() {
        let mut s = FetchBlockScheduler::new(Duration::from_secs(10));
        // Asking for head + 2 → not eligible.
        let dec = s.try_fetch(102, hash_of(1), "peer-a", 100, 1_000);
        assert_eq!(dec, FetchDecision::NotNextBlock);
        assert!(s.in_flight().is_none());
    }

    #[test]
    fn complete_clears_slot() {
        let mut s = FetchBlockScheduler::new(Duration::from_secs(10));
        s.try_fetch(101, hash_of(1), "peer-a", 100, 1_000);
        let cleared = s.complete().expect("present");
        assert_eq!(cleared.peer_key, "peer-a");
        assert!(s.in_flight().is_none());
    }

    #[test]
    fn complete_if_matches_ignores_wrong_hash() {
        let mut s = FetchBlockScheduler::new(Duration::from_secs(10));
        s.try_fetch(101, hash_of(1), "peer-a", 100, 1_000);
        assert!(!s.complete_if_matches(&hash_of(99))); // mismatch
        assert!(s.in_flight().is_some());
        assert!(s.complete_if_matches(&hash_of(1))); // matches
        assert!(s.in_flight().is_none());
    }
}
