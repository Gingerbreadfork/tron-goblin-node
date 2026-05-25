//! Server-side filter registry for the `eth_newFilter` family.
//!
//! Wallets and dapps poll for log/block/pending-tx updates via
//! `eth_getFilterChanges(filter_id)`. The server stores each filter
//! plus a high-water-mark (the last block-number we've reported); each
//! poll advances the mark and returns the delta since then.
//!
//! Three filter shapes (per EIP-?):
//!
//! * `Log` — block-range + address + topics, same shape as `eth_getLogs`.
//! * `BlockHeader` — incremental list of new block hashes since the
//!   last poll.
//! * `PendingTransaction` — incremental list of new pending tx hashes.
//!   We don't run a mempool here, so this always returns an empty
//!   delta on every poll; it's wired up so wallets that *create* the
//!   filter don't error out.
//!
//! Filters auto-expire after 5 minutes of inactivity to bound the
//! registry size.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;

/// Inactivity timeout for an idle filter. Matches go-ethereum's default.
pub const FILTER_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// What a registered filter is watching for.
#[derive(Debug, Clone)]
pub enum FilterKind {
    /// Block-range scan, same fields as `eth_getLogs`.
    Log(LogFilter),
    /// New block hashes since last poll.
    BlockHeader,
    /// New pending-tx hashes since last poll. With no mempool, this
    /// always reports empty.
    PendingTransaction,
}

#[derive(Debug, Clone, Default)]
pub struct LogFilter {
    /// Lower bound block number, inclusive.
    pub from_block: i64,
    /// Upper bound block number, inclusive. `i64::MAX` = follow head.
    pub to_block: i64,
    /// Addresses (any-of). Empty = match any.
    pub addresses: Vec<Vec<u8>>,
    /// Position-sensitive topic filter. Empty inner = match-any at that position.
    pub topics: Vec<Vec<Vec<u8>>>,
}

/// Filter registry entry.
struct Entry {
    kind: FilterKind,
    /// Block number through which we've already reported.
    cursor: i64,
    /// Last time `eth_getFilterChanges` (or creation) touched this filter.
    last_seen: Instant,
}

/// Thread-safe filter registry, shared across all RPC handlers via
/// `Arc<FilterRegistry>` on the `RpcState`.
#[derive(Default)]
pub struct FilterRegistry {
    next_id: Mutex<u64>,
    filters: Mutex<HashMap<u64, Entry>>,
}

impl FilterRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Create a new filter. `current_block` becomes the initial
    /// cursor: subsequent `get_changes` reports anything strictly
    /// newer than this point.
    pub fn create(&self, kind: FilterKind, current_block: i64) -> u64 {
        self.gc_expired();
        let id = {
            let mut next = self.next_id.lock().unwrap();
            *next = next.wrapping_add(1);
            // Skip 0 — wallets sometimes treat 0 as "no filter."
            if *next == 0 {
                *next = 1;
            }
            *next
        };
        let mut filters = self.filters.lock().unwrap();
        filters.insert(
            id,
            Entry {
                kind,
                cursor: current_block,
                last_seen: Instant::now(),
            },
        );
        id
    }

    /// Remove a filter. Returns `true` if it was present.
    pub fn uninstall(&self, id: u64) -> bool {
        let mut filters = self.filters.lock().unwrap();
        filters.remove(&id).is_some()
    }

    /// Fetch a clone of the filter's kind and the cursor at which
    /// changes should be reported from. Returns `None` if the filter
    /// has expired or never existed.
    pub fn touch(&self, id: u64, head: i64) -> Option<(FilterKind, i64)> {
        self.gc_expired();
        let mut filters = self.filters.lock().unwrap();
        let entry = filters.get_mut(&id)?;
        entry.last_seen = Instant::now();
        let prev_cursor = entry.cursor;
        // Advance to the head — successive calls return only newer changes.
        entry.cursor = head;
        Some((entry.kind.clone(), prev_cursor))
    }

    /// Read-only variant: returns the filter shape without bumping
    /// the cursor. Used by `eth_getFilterLogs` which returns ALL
    /// matching logs, not just the delta.
    pub fn peek(&self, id: u64) -> Option<FilterKind> {
        self.gc_expired();
        let mut filters = self.filters.lock().unwrap();
        let entry = filters.get_mut(&id)?;
        entry.last_seen = Instant::now();
        Some(entry.kind.clone())
    }

    fn gc_expired(&self) {
        let mut filters = self.filters.lock().unwrap();
        filters.retain(|_, e| e.last_seen.elapsed() < FILTER_TIMEOUT);
    }
}

/// Hex-encode a 64-bit filter id with `0x` prefix.
pub fn encode_filter_id(id: u64) -> Value {
    Value::String(format!("0x{id:x}"))
}

/// Decode a hex-encoded filter id back to its numeric value.
pub fn decode_filter_id(s: &str) -> Option<u64> {
    let stripped = s.strip_prefix("0x")?;
    u64::from_str_radix(stripped, 16).ok()
}
