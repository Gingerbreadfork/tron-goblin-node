//! Query side: bounded-read pages over the index.
//!
//! "Transactions for address X, page of N" is **one seek + a
//! sequential iterate** — O(page), not O(history). Newest-first is the
//! native key order (inverted height); oldest-first is the same range
//! walked backward. The pagination cursor (TronGrid's `fingerprint`)
//! is simply the last key returned: stateless, O(1) resume, no
//! server-side cursor state.
//!
//! Filters that can't bound the key range (direction bits, token,
//! exact-timestamp edges) post-filter the scan, with a hard per-request
//! scan budget so a pathological filter can't turn a page into an
//! unbounded walk — a budget-exhausted page returns fewer rows plus a
//! fingerprint, and the client simply continues.

use std::sync::Arc;

use prost::Message;
use tron_chainbase::{BlockIndexStore, BlockStore, DynamicPropertiesStore, KvBackend, StoreError};

use crate::db::{IndexDb, IndexError};
use crate::keys::{self, Addr, KeyParts};
use crate::rows::{InternalRow, LogRow, NativeRow, TokenMeta, Trc20Row, Trc721Row, DIR_FROM, DIR_TO};

/// Hard cap on keys examined per page request. Generous for real
/// filters (a page of 200 with a 100×-selective filter), small enough
/// that a worst-case request stays in the low milliseconds.
const SCAN_BUDGET: usize = 20_000;
/// Chunk size for the underlying range reads.
const CHUNK: usize = 512;

/// One page request — the TronGrid query params, resolved.
#[derive(Debug, Clone, Default)]
pub struct PageQuery {
    pub limit: usize,
    /// Opaque resume cursor: the raw last key of the previous page.
    pub fingerprint: Option<Vec<u8>>,
    pub only_from: bool,
    pub only_to: bool,
    pub only_confirmed: bool,
    pub only_unconfirmed: bool,
    pub min_timestamp_ms: Option<i64>,
    pub max_timestamp_ms: Option<i64>,
    /// Explicit height bounds (inclusive) — `block_number=N` in the
    /// events API is `min_block = max_block = Some(N)`.
    pub min_block: Option<i64>,
    pub max_block: Option<i64>,
    /// Restrict `idx_trc20` to one token contract.
    pub token: Option<Addr>,
    /// `order_by=block_timestamp,asc` — oldest first.
    pub ascending: bool,
}

#[derive(Debug, Clone)]
pub struct PageRow<T> {
    /// Full index key — pointer for hydration and the next
    /// fingerprint.
    pub key: Vec<u8>,
    pub parts: KeyParts,
    pub row: T,
    /// Derived at read time against the solidified mark (§4.3 of the
    /// plan) — never stored.
    pub confirmed: bool,
}

#[derive(Debug, Clone)]
pub struct Page<T> {
    pub rows: Vec<PageRow<T>>,
    /// Present when more data may exist — pass back to resume.
    pub fingerprint: Option<Vec<u8>>,
}

/// One `idx_logs` hit: the pointer row plus its decoded key parts
/// (the topics/data hydrate from stored transaction-info via
/// `(height, txidx, logidx)`).
#[derive(Debug, Clone)]
pub struct LogPageRow {
    pub key: Vec<u8>,
    pub topic0: [u8; 32],
    pub height: i64,
    pub txidx: u32,
    pub logidx: u32,
    pub row: LogRow,
    pub confirmed: bool,
}

#[derive(Debug, Clone)]
pub struct LogsPage {
    pub rows: Vec<LogPageRow>,
    pub fingerprint: Option<Vec<u8>>,
}

/// Backfill / liveness view served alongside every page
/// (`meta.backfill` in the API).
#[derive(Debug, Clone, Copy)]
pub struct ReaderStatus {
    pub cursor: Option<i64>,
    pub indexed_from: Option<i64>,
    pub floor: Option<i64>,
    pub backfill_complete: bool,
    pub at_tip: bool,
    pub head: i64,
    pub solidified: i64,
}

/// Read-only handle over the index DB + the consensus stores needed
/// for derived flags and timestamp seeks. Cheap to clone.
#[derive(Clone)]
pub struct IndexReader {
    db: IndexDb,
    blocks: Arc<dyn KvBackend>,
    block_index: Arc<dyn KvBackend>,
    dyn_props: Arc<dyn KvBackend>,
    /// Mirrors the engine's `stream = "solidified"` mode so the
    /// `at_tip` / `backfill.complete` markers measure against the same
    /// target the follower actually chases (otherwise a solidified-
    /// stream index would read as forever incomplete, ~19 blocks shy
    /// of the raw head).
    follow_solidified: bool,
}

impl IndexReader {
    pub fn new(
        db: IndexDb,
        blocks: Arc<dyn KvBackend>,
        block_index: Arc<dyn KvBackend>,
        dyn_props: Arc<dyn KvBackend>,
    ) -> Self {
        Self { db, blocks, block_index, dyn_props, follow_solidified: false }
    }

    /// Match the engine's `stream = "solidified"` target.
    pub fn with_solidified_stream(mut self, on: bool) -> Self {
        self.follow_solidified = on;
        self
    }

    pub fn status(&self) -> ReaderStatus {
        let dp = DynamicPropertiesStore::new(self.dyn_props.clone());
        let head = dp.latest_block_header_number().unwrap_or(0);
        let solidified = dp.latest_solidified_block_num().unwrap_or(0);
        let cursor = self.db.cursor_height().ok().flatten();
        let back_edge = self.db.back_edge().ok().flatten();
        let floor = self.db.floor().ok().flatten();
        let backfill_complete = matches!((back_edge, floor), (Some(b), Some(f)) if b <= f);
        let target = if self.follow_solidified { head.min(solidified) } else { head };
        ReaderStatus {
            cursor,
            indexed_from: back_edge,
            floor,
            backfill_complete,
            at_tip: cursor.map(|c| c >= target).unwrap_or(false),
            head,
            solidified,
        }
    }

    pub fn solidified(&self) -> i64 {
        DynamicPropertiesStore::new(self.dyn_props.clone())
            .latest_solidified_block_num()
            .unwrap_or(0)
    }

    // -- token metadata cache ------------------------------------------------

    pub fn token_meta(&self, contract: &Addr) -> Result<Option<TokenMeta>, IndexError> {
        self.db.token_meta(contract)
    }

    pub fn put_token_meta(&self, contract: &Addr, meta: &TokenMeta) -> Result<(), IndexError> {
        self.db.put_token_meta(contract, meta)
    }

    // -- pages ---------------------------------------------------------------

    pub fn native_page(&self, addr: &Addr, q: &PageQuery) -> Result<Page<NativeRow>, IndexError> {
        self.scan_page(keys::NS_NATIVE, addr, q, |_, _| true)
    }

    pub fn trc20_page(&self, addr: &Addr, q: &PageQuery) -> Result<Page<Trc20Row>, IndexError> {
        let token = q.token;
        self.scan_page(keys::NS_TRC20, addr, q, move |_, row: &Trc20Row| match &token {
            Some(t) => row.token.as_slice() == t.as_slice(),
            None => true,
        })
    }

    pub fn trc721_page(&self, addr: &Addr, q: &PageQuery) -> Result<Page<Trc721Row>, IndexError> {
        let token = q.token;
        self.scan_page(keys::NS_TRC721, addr, q, move |_, row: &Trc721Row| match &token {
            Some(t) => row.token.as_slice() == t.as_slice(),
            None => true,
        })
    }

    pub fn internal_page(
        &self,
        addr: &Addr,
        q: &PageQuery,
    ) -> Result<Page<InternalRow>, IndexError> {
        self.scan_page(keys::NS_INTERNAL, addr, q, |_, _| true)
    }

    /// Canonical block id at a height — hydration helper for the API
    /// layer.
    pub fn block_at(&self, height: i64) -> Result<Option<tron_proto::Block>, IndexError> {
        let bi = BlockIndexStore::new(self.block_index.clone());
        let id = match bi.get(height) {
            Ok(id) => id,
            Err(StoreError::NotFound) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        match BlockStore::new(self.blocks.clone()).get(&id) {
            Ok(b) => Ok(Some(b)),
            Err(StoreError::NotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn scan_page<T, F>(
        &self,
        ns: u8,
        addr: &Addr,
        q: &PageQuery,
        extra_filter: F,
    ) -> Result<Page<T>, IndexError>
    where
        T: Message + Default + RowCommon,
        F: Fn(&KeyParts, &T) -> bool,
    {
        let limit = q.limit.clamp(1, 1000);
        let prefix = keys::addr_prefix(ns, addr);
        let solidified = self.solidified();

        let (hmin, hmax) = self.height_bounds(q, solidified);
        if hmin > hmax {
            return Ok(Page { rows: Vec::new(), fingerprint: None });
        }

        // Range endpoints in key space (heights are inverted: a LOWER
        // key bound corresponds to the HIGHER height bound).
        let mut start_desc = prefix.clone(); // inclusive, forward scans
        if hmax < i64::MAX {
            start_desc.extend_from_slice(&keys::height_desc(hmax));
        }
        let upper_asc: Vec<u8> = if hmin > 0 {
            // Exclusive upper bound for backward scans: just past every
            // key at height hmin (= the first possible key at hmin−1).
            let mut k = prefix.clone();
            k.extend_from_slice(&keys::height_desc(hmin - 1));
            k
        } else {
            prefix_end(&prefix)
        };

        // Resume from the fingerprint when given (validated to be
        // inside this address's range; a foreign fingerprint is
        // ignored rather than leaking another range's rows).
        let mut cur: Vec<u8> = match &q.fingerprint {
            Some(fp) if fp.starts_with(&prefix) => {
                if q.ascending {
                    fp.clone() // scan_back_from is exclusive
                } else {
                    let mut k = fp.clone();
                    k.push(0); // forward: strictly after the last key
                    k
                }
            }
            _ => {
                if q.ascending {
                    upper_asc.clone()
                } else {
                    start_desc.clone()
                }
            }
        };

        let min_dir_mask = match (q.only_from, q.only_to) {
            (true, true) => DIR_FROM | DIR_TO,
            (true, false) => DIR_FROM,
            (false, true) => DIR_TO,
            (false, false) => 0,
        };

        let mut rows: Vec<PageRow<T>> = Vec::with_capacity(limit);
        let mut scanned = 0usize;
        let mut last_examined: Option<Vec<u8>> = None;
        let mut exhausted = false;

        'outer: while rows.len() < limit && scanned < SCAN_BUDGET {
            let chunk = if q.ascending {
                self.db.backend().scan_back_from(&cur, CHUNK)?
            } else {
                self.db.backend().scan_from(&cur, CHUNK)?
            };
            if chunk.is_empty() {
                exhausted = true;
                break;
            }
            for (k, v) in &chunk {
                scanned += 1;
                if !k.starts_with(&prefix) {
                    exhausted = true;
                    break 'outer;
                }
                let Some(parts) = keys::decode_row_key(k) else { continue };
                // Range stop conditions (heights are monotone along
                // the scan direction).
                if q.ascending {
                    if parts.height > hmax {
                        exhausted = true;
                        break 'outer;
                    }
                } else if parts.height < hmin {
                    exhausted = true;
                    break 'outer;
                }
                last_examined = Some(k.clone());
                let Ok(row) = T::decode(v.as_slice()) else { continue };
                if min_dir_mask != 0 && row.direction() & min_dir_mask != min_dir_mask {
                    continue;
                }
                // Exact-timestamp edges (block granularity above can
                // overshoot by one block on either side).
                let ts = row.timestamp_ms();
                if q.min_timestamp_ms.map(|m| ts < m).unwrap_or(false)
                    || q.max_timestamp_ms.map(|m| ts > m).unwrap_or(false)
                {
                    continue;
                }
                if !extra_filter(&parts, &row) {
                    continue;
                }
                rows.push(PageRow {
                    key: k.clone(),
                    parts,
                    confirmed: parts.height <= solidified,
                    row,
                });
                if rows.len() >= limit {
                    break 'outer;
                }
            }
            // Advance the scan cursor past the chunk.
            let last_key = &chunk.last().expect("non-empty chunk").0;
            if q.ascending {
                cur = last_key.clone();
            } else {
                cur = last_key.clone();
                cur.push(0);
            }
        }

        // A fingerprint is returned whenever the scan stopped early
        // (page full or budget hit) — i.e. whenever more rows may
        // exist past the last key we looked at. Resume from the last
        // *examined* key (≥ the last returned row), so keys already
        // rejected by filters aren't re-walked.
        let fingerprint = if exhausted { None } else { last_examined };
        Ok(Page { rows, fingerprint })
    }

    /// Height bounds from the range-boundable filters (confirmation
    /// state, timestamp range, explicit block range).
    fn height_bounds(&self, q: &PageQuery, solidified: i64) -> (i64, i64) {
        let mut hmax = i64::MAX;
        let mut hmin = 0i64;
        if q.only_confirmed {
            hmax = hmax.min(solidified);
        }
        if q.only_unconfirmed {
            hmin = hmin.max(solidified + 1);
        }
        if let Some(ts) = q.max_timestamp_ms {
            hmax = hmax.min(self.height_at_or_before_ts(ts));
        }
        if let Some(ts) = q.min_timestamp_ms {
            hmin = hmin.max(self.height_at_or_after_ts(ts));
        }
        if let Some(h) = q.max_block {
            hmax = hmax.min(h);
        }
        if let Some(h) = q.min_block {
            hmin = hmin.max(h);
        }
        (hmin, hmax)
    }

    /// Event-search page over `idx_logs` (`scope = "all"` rows): one
    /// contract, optionally one event signature (`topic0`).
    ///
    /// The logs namespace groups by `contract ‖ topic0` BEFORE height,
    /// so a single-signature query is one range scan, while the
    /// no-signature query merges the contract's signature groups by
    /// `(height, txidx, logidx)` to keep the page globally
    /// newest-first (or oldest-first under `ascending`). The merge
    /// holds one peeked key per group — group count is the number of
    /// distinct event signatures the contract ever emitted, small in
    /// practice and capped by the scan budget.
    pub fn logs_page(
        &self,
        contract: &Addr,
        topic0: Option<[u8; 32]>,
        q: &PageQuery,
    ) -> Result<LogsPage, IndexError> {
        let limit = q.limit.clamp(1, 1000);
        let solidified = self.solidified();
        let (hmin, hmax) = self.height_bounds(q, solidified);
        if hmin > hmax {
            return Ok(LogsPage { rows: Vec::new(), fingerprint: None });
        }

        let mut base = Vec::with_capacity(22);
        base.push(keys::NS_LOGS);
        base.extend_from_slice(contract);

        // The signature groups this query spans.
        let groups: Vec<[u8; 32]> = match topic0 {
            Some(t) => vec![t],
            None => {
                let mut groups = Vec::new();
                let mut probe = base.clone();
                while groups.len() < 1024 {
                    let chunk = self.db.backend().scan_from(&probe, 1)?;
                    let Some((k, _)) = chunk.first() else { break };
                    if !k.starts_with(&base) || k.len() != 70 {
                        break;
                    }
                    let mut t = [0u8; 32];
                    t.copy_from_slice(&k[22..54]);
                    groups.push(t);
                    let mut group_prefix = base.clone();
                    group_prefix.extend_from_slice(&t);
                    probe = prefix_end(&group_prefix);
                }
                groups
            }
        };

        // The 16-byte key suffix (`height_desc ‖ txidx ‖ logidx`) is
        // the global sort key: byte-ascending == newest-first.
        let fp_suffix: Option<[u8; 16]> = q
            .fingerprint
            .as_deref()
            .filter(|fp| fp.len() == 70 && fp.starts_with(&base))
            .map(|fp| fp[54..70].try_into().expect("16 bytes"));

        // One lazy cursor per group.
        struct GroupCursor {
            prefix: Vec<u8>, // ns ‖ contract ‖ topic0 (54 bytes)
            buf: std::collections::VecDeque<(Vec<u8>, Vec<u8>)>,
            next_seek: Option<Vec<u8>>, // None = exhausted
        }
        let mut cursors: Vec<GroupCursor> = groups
            .iter()
            .map(|t| {
                let mut prefix = base.clone();
                prefix.extend_from_slice(t);
                let seek = if q.ascending {
                    // Backward scan start: just past the low end of the
                    // height range (or of the whole group), exclusive —
                    // tightened to the fingerprint on resume.
                    let mut k = prefix.clone();
                    match fp_suffix {
                        Some(suffix) => k.extend_from_slice(&suffix),
                        None => {
                            if hmin > 0 {
                                k.extend_from_slice(&keys::height_desc(hmin - 1));
                            } else {
                                k = prefix_end(&prefix);
                            }
                        }
                    }
                    k
                } else {
                    // Forward scan start, inclusive: the high end of
                    // the height range, or strictly past the
                    // fingerprint's sort position on resume.
                    let mut k = prefix.clone();
                    match fp_suffix {
                        Some(suffix) => {
                            k.extend_from_slice(&suffix);
                            k.push(0);
                        }
                        None => {
                            if hmax < i64::MAX {
                                k.extend_from_slice(&keys::height_desc(hmax));
                            }
                        }
                    }
                    k
                };
                GroupCursor { prefix, buf: Default::default(), next_seek: Some(seek) }
            })
            .collect();

        const GROUP_CHUNK: usize = 64;
        let mut rows: Vec<LogPageRow> = Vec::with_capacity(limit);
        let mut scanned = 0usize;
        let mut last_examined: Option<Vec<u8>> = None;
        let mut exhausted_early = false;

        // Refill a group's buffer; returns whether it has a head.
        let refill = |c: &mut GroupCursor,
                      backend: &Arc<dyn KvBackend>,
                      scanned: &mut usize|
         -> Result<(), IndexError> {
            while c.buf.is_empty() {
                let Some(seek) = c.next_seek.clone() else { return Ok(()) };
                let chunk = if q.ascending {
                    backend.scan_back_from(&seek, GROUP_CHUNK)?
                } else {
                    backend.scan_from(&seek, GROUP_CHUNK)?
                };
                *scanned += chunk.len();
                if chunk.is_empty() {
                    c.next_seek = None;
                    return Ok(());
                }
                let last_key = chunk.last().expect("non-empty").0.clone();
                c.next_seek = if chunk.len() < GROUP_CHUNK {
                    None
                } else if q.ascending {
                    Some(last_key.clone())
                } else {
                    let mut k = last_key.clone();
                    k.push(0);
                    Some(k)
                };
                for (k, v) in chunk {
                    if !k.starts_with(&c.prefix) {
                        c.next_seek = None;
                        break;
                    }
                    let Some(parts) = keys::decode_logs_key(&k) else { continue };
                    // Height range stop (monotone along the scan).
                    if q.ascending {
                        if parts.height > hmax {
                            c.next_seek = None;
                            break;
                        }
                    } else if parts.height < hmin {
                        c.next_seek = None;
                        break;
                    }
                    c.buf.push_back((k, v));
                }
            }
            Ok(())
        };

        'page: while rows.len() < limit {
            if scanned >= SCAN_BUDGET {
                exhausted_early = true;
                break 'page;
            }
            for c in cursors.iter_mut() {
                refill(c, self.db.backend(), &mut scanned)?;
            }
            // Pick the group whose head sorts next: suffix bytes
            // ascending = newest-first; reversed under `ascending`.
            let mut best: Option<(usize, [u8; 16])> = None;
            for (i, c) in cursors.iter().enumerate() {
                let Some((k, _)) = c.buf.front() else { continue };
                let suffix: [u8; 16] = k[54..70].try_into().expect("70-byte key");
                let better = match &best {
                    None => true,
                    Some((_, b)) => {
                        if q.ascending {
                            suffix > *b
                        } else {
                            suffix < *b
                        }
                    }
                };
                if better {
                    best = Some((i, suffix));
                }
            }
            let Some((i, _)) = best else { break 'page }; // every group dry
            let (k, v) = cursors[i].buf.pop_front().expect("head present");
            last_examined = Some(k.clone());
            let Some(parts) = keys::decode_logs_key(&k) else { continue };
            let Ok(row) = LogRow::decode(v.as_slice()) else { continue };
            // Exact-timestamp edges (block-granular bounds above can
            // overshoot by one block on either side).
            let ts = row.timestamp_ms;
            if q.min_timestamp_ms.map(|m| ts < m).unwrap_or(false)
                || q.max_timestamp_ms.map(|m| ts > m).unwrap_or(false)
            {
                continue;
            }
            rows.push(LogPageRow {
                key: k,
                topic0: parts.topic0,
                height: parts.height,
                txidx: parts.txidx,
                logidx: parts.logidx,
                confirmed: parts.height <= solidified,
                row,
            });
        }

        // More may exist iff the budget cut the page short or any
        // group still has (or may have) items.
        let more = exhausted_early
            || cursors.iter().any(|c| !c.buf.is_empty() || c.next_seek.is_some());
        let fingerprint = if more { last_examined } else { None };
        Ok(LogsPage { rows, fingerprint })
    }

    // -- timestamp ↔ height seeks -------------------------------------------
    //
    // Height ↔ time is monotone, so a timestamp bound becomes a height
    // bound via binary search over the canonical index (~27 point
    // reads on mainnet history, cache-hot). Failures degrade to "no
    // bound" — the exact per-row timestamp post-filter stays correct
    // either way.

    fn block_ts(&self, height: i64) -> Option<i64> {
        let bi = BlockIndexStore::new(self.block_index.clone());
        let id = bi.get(height).ok()?;
        let block = BlockStore::new(self.blocks.clone()).get(&id).ok()?;
        block
            .block_header
            .as_ref()
            .and_then(|h| h.raw_data.as_ref())
            .map(|r| r.timestamp)
    }

    fn search_bounds(&self) -> Option<(i64, i64)> {
        let lo = self.db.back_edge().ok().flatten()?;
        let hi = self.db.cursor_height().ok().flatten()?;
        (lo <= hi).then_some((lo, hi))
    }

    /// Highest height whose block timestamp is <= `ts` (i64::MAX when
    /// unknown — no bound).
    fn height_at_or_before_ts(&self, ts: i64) -> i64 {
        let Some((mut lo, mut hi)) = self.search_bounds() else { return i64::MAX };
        if self.block_ts(lo).map(|t| t > ts).unwrap_or(false) {
            return lo - 1; // everything is newer than ts
        }
        while lo < hi {
            let mid = lo + (hi - lo + 1) / 2;
            match self.block_ts(mid) {
                Some(t) if t <= ts => lo = mid,
                Some(_) => hi = mid - 1,
                None => return i64::MAX,
            }
        }
        lo
    }

    /// Lowest height whose block timestamp is >= `ts` (0 when unknown
    /// — no bound).
    fn height_at_or_after_ts(&self, ts: i64) -> i64 {
        let Some((mut lo, mut hi)) = self.search_bounds() else { return 0 };
        if self.block_ts(hi).map(|t| t < ts).unwrap_or(false) {
            return hi + 1; // everything is older than ts
        }
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            match self.block_ts(mid) {
                Some(t) if t >= ts => hi = mid,
                Some(_) => lo = mid + 1,
                None => return 0,
            }
        }
        lo
    }
}

/// First key past every key starting with `prefix`.
fn prefix_end(prefix: &[u8]) -> Vec<u8> {
    let mut end = prefix.to_vec();
    for i in (0..end.len()).rev() {
        if end[i] != 0xff {
            end[i] += 1;
            end.truncate(i + 1);
            return end;
        }
    }
    // All-0xff prefix — unbounded; return a key past any real key.
    vec![0xff; prefix.len() + 9]
}

/// The fields every row type shares, for the generic scan.
pub trait RowCommon {
    fn direction(&self) -> u32;
    fn timestamp_ms(&self) -> i64;
}

impl RowCommon for NativeRow {
    fn direction(&self) -> u32 {
        self.direction
    }
    fn timestamp_ms(&self) -> i64 {
        self.timestamp_ms
    }
}

impl RowCommon for Trc20Row {
    fn direction(&self) -> u32 {
        self.direction
    }
    fn timestamp_ms(&self) -> i64 {
        self.timestamp_ms
    }
}

impl RowCommon for Trc721Row {
    fn direction(&self) -> u32 {
        self.direction
    }
    fn timestamp_ms(&self) -> i64 {
        self.timestamp_ms
    }
}

impl RowCommon for InternalRow {
    fn direction(&self) -> u32 {
        self.direction
    }
    fn timestamp_ms(&self) -> i64 {
        self.timestamp_ms
    }
}
