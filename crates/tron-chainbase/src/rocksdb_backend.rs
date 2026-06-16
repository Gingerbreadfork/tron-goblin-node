//! RocksDB-backed [`KvBackend`] implementation.
//!
//! Lets us open a directory written by java-tron (one DB per store) and
//! read/write entries with byte-identical key/value semantics — the whole
//! point of the store-level codecs in [`crate::stores`] is to round-trip
//! exactly the bytes a java-tron node would write here.
//!
//! Tuning: this implementation uses RocksDB defaults plus a couple of
//! parity-friendly options:
//!
//! * `create_if_missing = true` for the read-write open path.
//! * `compression = Snappy` (RocksDB's default; java-tron's `dbSettings`
//!   doesn't override compression by default).
//!
//! Java-tron also writes more knobs (`levelNumber`, `blocksize`,
//! `maxBytesForLevelBase`, `targetFileSizeBase`, `maxOpenFiles`) but
//! RocksDB embeds the file-format details in each SST so we can read
//! files written with different tuning. Operators who need exotic
//! tuning can plumb their own `Options` through [`RocksDbBackend::open_with`].

use std::cmp::Ordering;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use rocksdb::{
    BlockBasedOptions, Cache, Env, Options, WriteBatch, WriteBufferManager, WriteOptions, DB,
};

use crate::backend::{KvBackend, KvError, WriteOp};

impl From<rocksdb::Error> for KvError {
    fn from(e: rocksdb::Error) -> Self {
        KvError::Backend(format!("rocksdb: {e}"))
    }
}

/// Build an `Options` with the parity-friendly defaults this crate
/// applies to every RocksDB open path. Centralised so the four open
/// paths (rw, tuned, read-only, secondary) can't drift on which
/// safety knobs they enable.
///
/// * `paranoid_checks(true)` — RocksDB compares SST checksums
///   aggressively at open time and during compactions. Catches a
///   silently-bit-rotting SST early (load-time error rather than
///   serving wrong bytes for the rest of the run). Cheap — metadata
///   reads only at open; the per-block-read overhead is negligible.
fn safety_baseline() -> Options {
    let mut opts = Options::default();
    opts.set_paranoid_checks(true);
    opts.set_max_open_files(DEFAULT_MAX_OPEN_FILES);
    opts
}

/// Default capacity of the process-wide LRU block cache, shared by every
/// store this node opens. RocksDB's per-DB default is a tiny 8 MiB, which
/// thrashes badly during sync against multi-GB stores (the `account` store
/// alone is tens of GB). One shared cache bounds total memory globally
/// instead of letting it scale with the ~30 separate store DBs.
///
/// This is a *ceiling*, not a pre-allocation — the LRU fills lazily as
/// blocks are read, so it costs nothing on small/idle processes (tests,
/// tools).
const DEFAULT_BLOCK_CACHE_BYTES: usize = 1024 * 1024 * 1024;

/// Runtime-overridable shared block-cache size. The node sets this from
/// `storage.block_cache_mb` before opening any store; a larger cache keeps
/// more of the multi-GB state hot, which is the dominant lever on
/// catch-up apply throughput (sync is apply-bound, and per-tx state reads
/// that miss the cache hit disk). Set once, before the lazy `OnceLock`
/// init below — later changes are ignored.
static CONFIGURED_BLOCK_CACHE_BYTES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(DEFAULT_BLOCK_CACHE_BYTES);

/// Override the shared block-cache ceiling (bytes). No-op for 0 or if a
/// store has already opened (the cache is built lazily, first-call-wins).
pub fn set_block_cache_bytes(bytes: usize) {
    if bytes > 0 {
        CONFIGURED_BLOCK_CACHE_BYTES.store(bytes, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Background-compaction / flush threads for the shared [`Env`]. Because
/// each store is a *separate* RocksDB instance (one DB per directory, the
/// java-tron layout), per-DB `increase_parallelism` would spawn
/// `cpus × ~30` threads. A single shared Env bounds the pool across all
/// stores, matching java-tron's single-DB-with-column-families thread
/// model.
/// Detected logical CPU count (`available_parallelism`, 4 on failure). The
/// flush/compaction pools below scale off this — two fixed flush threads
/// throttled a 32-core host into periodic write stalls.
fn detected_cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

/// Total system RAM in bytes (Linux `/proc/meminfo`). Falls back to 8 GiB so
/// the write-buffer budget stays at its historical 1 GiB floor when unknown.
fn detected_mem_total_bytes() -> usize {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("MemTotal:"))
                .and_then(|v| v.trim().strip_suffix(" kB"))
                .and_then(|n| n.trim().parse::<usize>().ok())
        })
        .map(|kb| kb * 1024)
        .unwrap_or(8 * 1024 * 1024 * 1024)
}

/// Background COMPACTION threads for the shared [`Env`]. Because each store is
/// a *separate* RocksDB instance (one DB per directory, the java-tron layout),
/// per-DB `increase_parallelism` would spawn `cpus × ~30` threads; a single
/// shared Env bounds the pool across all stores. Scaled with cores and clamped
/// to `4..=16` — the floor preserves the old fixed default on small VMs.
fn background_threads() -> i32 {
    (detected_cores() as i32).clamp(4, 16)
}

/// High-priority FLUSH threads for the shared [`Env`], scaled with cores and
/// clamped to `2..=8`. Two (the old fixed value) was far too few for the ~88
/// separate store instances on a many-core host: when several hot stores
/// flushed at once they queued on two threads, a store's 2nd memtable filled
/// before its first flush drained, and RocksDB STOPPED that store's writes
/// (`max_write_buffer_number`) — stalling block apply and making the node fall
/// behind the tip every few minutes.
fn flush_threads() -> i32 {
    ((detected_cores() / 4) as i32).clamp(2, 8)
}

/// In-flight memtables allowed per store before writes stall. Raised from the
/// RocksDB default (2 — only ONE immutable memtable of headroom, which the
/// stall evidence showed a hot store routinely overran) to 4. The earlier
/// concern that this multiplies per-store memtable RAM no longer applies: the
/// shared [`WriteBufferManager`] caps the aggregate independently of this
/// per-store count, so the extra headroom rides out flush latency without
/// growing total memory.
const DEFAULT_MAX_WRITE_BUFFER_NUMBER: i32 = 4;

/// Aggregate memtable budget shared across EVERY store this process opens.
/// Each store is a separate RocksDB instance, so without a shared manager
/// total memtable RAM = `write_buffer_size × max_write_buffer_number ×
/// store_count` would be unbounded across ~88 instances. A single
/// `WriteBufferManager` caps the SUM regardless of store count — the fix for
/// the unbounded memtable growth that drove the node to ~18 GiB.
/// `allow_stall = true` applies write back-pressure when the budget is hit
/// instead of letting memory balloon.
///
/// Sized as `max(1 GiB, RAM/16)`, capped at 16 GiB: the 1 GiB floor preserves
/// small-VM behavior, while on a big box the higher ceiling stops the
/// `allow_stall` back-pressure from firing under normal tip write rates (a flat
/// 1 GiB on a 125 GiB host triggered flush cascades every few minutes). It's a
/// CAP, not an allocation — RAM actually used stays bounded by write rate ×
/// flush latency, which is small now that flushes keep up.
fn write_buffer_manager_bytes() -> usize {
    const ONE_GIB: usize = 1024 * 1024 * 1024;
    (detected_mem_total_bytes() / 16).clamp(ONE_GIB, 16 * ONE_GIB)
}

/// The shared block cache. Created once, referenced by every tuned open path so
/// memory is bounded process-wide. Uses RocksDB's **HyperClockCache** rather than
/// the sharded LRU: the LRU's per-shard mutex + LRU-list updates serialize
/// concurrent lookups, which under Block-STM's 32 reader threads is real
/// cache-line contention; HyperClockCache is a (near-)lock-free clock cache built
/// for exactly this many-reader workload. `estimated_entry_charge = 0` selects
/// the auto-tuning variant. Byte-neutral — cache choice never affects returned
/// values or on-disk format.
fn shared_block_cache() -> &'static Cache {
    static CACHE: OnceLock<Cache> = OnceLock::new();
    CACHE.get_or_init(|| {
        let cap = CONFIGURED_BLOCK_CACHE_BYTES.load(std::sync::atomic::Ordering::Relaxed);
        Cache::new_hyper_clock_cache(cap, 0)
    })
}

/// The shared write-buffer manager: caps total memtable memory across all
/// store instances in this process (see [`WRITE_BUFFER_MANAGER_BYTES`]).
fn shared_write_buffer_manager() -> &'static WriteBufferManager {
    static WBM: OnceLock<WriteBufferManager> = OnceLock::new();
    WBM.get_or_init(|| {
        WriteBufferManager::new_write_buffer_manager(
            write_buffer_manager_bytes(),
            /* allow_stall */ true,
        )
    })
}

/// The shared background-thread [`Env`]. `None` if RocksDB couldn't build
/// a custom Env (then each DB falls back to its own default Env — correct,
/// just unshared).
fn shared_env() -> Option<&'static Env> {
    static ENV: OnceLock<Option<Env>> = OnceLock::new();
    ENV.get_or_init(|| match Env::new() {
        Ok(mut env) => {
            env.set_background_threads(background_threads());
            env.set_high_priority_background_threads(flush_threads());
            Some(env)
        }
        Err(_) => None,
    })
    .as_ref()
}

/// A read-only snapshot of the process-wide RocksDB tuning the node derived
/// from the detected hardware at open time — for the startup summary log. Every
/// field is the exact value the open paths actually applied; reading it neither
/// opens a DB nor allocates.
#[derive(Clone, Copy, Debug)]
pub struct RocksdbTuning {
    pub cores: usize,
    pub mem_total_bytes: usize,
    pub write_buffer_manager_bytes: usize,
    pub block_cache_bytes: usize,
    pub background_threads: i32,
    pub flush_threads: i32,
    pub max_write_buffer_number: i32,
    pub bloom_bits_per_key: u32,
}

/// The resolved [`RocksdbTuning`]. Cheap: just returns the already-computed
/// hardware-scaled values (and the configured block-cache size).
pub fn rocksdb_tuning() -> RocksdbTuning {
    RocksdbTuning {
        cores: detected_cores(),
        mem_total_bytes: detected_mem_total_bytes(),
        write_buffer_manager_bytes: write_buffer_manager_bytes(),
        block_cache_bytes: CONFIGURED_BLOCK_CACHE_BYTES.load(std::sync::atomic::Ordering::Relaxed),
        background_threads: background_threads(),
        flush_threads: flush_threads(),
        max_write_buffer_number: DEFAULT_MAX_WRITE_BUFFER_NUMBER,
        bloom_bits_per_key: 10,
    }
}

/// Apply the runtime performance knobs the node's read-write open paths
/// share: a shared LRU block cache + bloom filters (point-lookup stores
/// like `account`/`code`/`storage-row` otherwise binary-search every
/// miss), index/filter blocks held in the bounded cache, a shared
/// background-compaction Env, and room for a few in-flight write buffers.
///
/// **All of these are runtime-only** — block cache, bloom filters, thread
/// pools and memtable counts live in memory and in *newly written* SSTs;
/// none change the on-disk key/value bytes or the SST format in a way that
/// breaks reading a java-tron snapshot (RocksDB records the table format
/// per-SST, so old filter-less SSTs still read fine). Byte-exact parity is
/// unaffected.
fn apply_runtime_tuning(opts: &mut Options) {
    let mut bbt = BlockBasedOptions::default();
    bbt.set_block_cache(shared_block_cache());
    // 10 bits/key full-filter bloom — skips the index/data binary search
    // on point-lookup misses, the dominant cost during sync.
    bbt.set_bloom_filter(10.0, false);
    bbt.set_cache_index_and_filter_blocks(true);
    bbt.set_pin_l0_filter_and_index_blocks_in_cache(true);
    // Keep the top-level (partitioned) index/filter blocks pinned too, so
    // point-lookup-heavy sync doesn't re-fetch them through the cache on every
    // miss — fewer cache operations under the 32-thread read load.
    bbt.set_pin_top_level_index_and_filter(true);
    opts.set_block_based_table_factory(&bbt);

    opts.set_max_write_buffer_number(DEFAULT_MAX_WRITE_BUFFER_NUMBER);
    // Cap aggregate memtable memory across ALL store instances — without
    // this each of the ~42 stores keeps its own independent budget and the
    // total grows to many GiB.
    opts.set_write_buffer_manager(shared_write_buffer_manager());

    if let Some(env) = shared_env() {
        opts.set_env(env);
    }
}

/// Wraps a single RocksDB instance (one store, one directory).
pub struct RocksDbBackend {
    db: Arc<DB>,
}

/// Bounded fallback for the per-store `max_open_files` setting on
/// every open path that doesn't get explicit tuning from the node
/// config. RocksDB's own default is `-1` (unlimited), which is a
/// foot-gun: a long-running node accumulates SST-cache handles until
/// it hits the process RLIMIT_NOFILE ceiling, and parallel tests open
/// ~20 stores at once and trip the same limit on developer machines.
///
/// 256 is the historical RocksDB default and is plenty for both tests
/// (where stores have 1–2 SSTs each) and a modestly-sized production
/// node. Production deployments that want a larger SST-handle cache
/// override via the `[storage]` config block or `OpenedStores::open_tuned`.
const DEFAULT_MAX_OPEN_FILES: i32 = 256;

impl RocksDbBackend {
    /// Open `path` read-write, creating it if absent. Caps
    /// `max_open_files` at [`DEFAULT_MAX_OPEN_FILES`]; pass a tuned
    /// [`Options`] via [`open_with`] or use [`open_tuned`] if you need
    /// to match a specific java-tron `dbSettings` value.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RocksDbError> {
        let mut opts = safety_baseline();
        opts.create_if_missing(true);
        apply_runtime_tuning(&mut opts);
        Self::open_with(path, opts)
    }

    /// Open `path` read-write with explicit tuning knobs that the
    /// `tron-node` config layer exposes. `write_buffer_mb` controls
    /// the in-memory MemTable flush threshold; `max_open_files` caps
    /// the per-process FD count.
    pub fn open_tuned(
        path: impl AsRef<Path>,
        write_buffer_mb: usize,
        max_open_files: i32,
    ) -> Result<Self, RocksDbError> {
        let mut opts = safety_baseline();
        opts.create_if_missing(true);
        opts.set_write_buffer_size(write_buffer_mb * 1024 * 1024);
        opts.set_max_open_files(max_open_files); // overrides safety_baseline default
        apply_runtime_tuning(&mut opts);
        Self::open_with(path, opts)
    }

    /// Open a store that java-tron created with a **custom key
    /// comparator**, registering an equivalent one so RocksDB will open it
    /// and order keys the way the on-disk SSTs were written.
    ///
    /// `comparator_name` MUST match the name recorded in the store's
    /// MANIFEST — RocksDB compares it at open and errors with `does not
    /// match existing comparator <name>` otherwise — and `compare_fn` MUST
    /// reproduce java-tron's ordering byte-for-byte, since RocksDB
    /// binary-searches the SST data/index blocks with it (a mismatch makes
    /// point/range reads silently miss keys rather than fail loudly).
    ///
    /// Only `market_pair_price_to_order` needs this today; see
    /// [`crate::market_order_price_comparator`]. `tuning` mirrors
    /// [`open_tuned`](Self::open_tuned) — `Some((write_buffer_mb,
    /// max_open_files))` to apply operator knobs, `None` for defaults.
    pub fn open_with_comparator(
        path: impl AsRef<Path>,
        tuning: Option<(usize, i32)>,
        comparator_name: &str,
        compare_fn: fn(&[u8], &[u8]) -> Ordering,
    ) -> Result<Self, RocksDbError> {
        let mut opts = safety_baseline();
        opts.create_if_missing(true);
        if let Some((write_buffer_mb, max_open_files)) = tuning {
            opts.set_write_buffer_size(write_buffer_mb * 1024 * 1024);
            opts.set_max_open_files(max_open_files); // overrides safety_baseline default
        }
        apply_runtime_tuning(&mut opts);
        opts.set_comparator(comparator_name, Box::new(compare_fn));
        Self::open_with(path, opts)
    }

    /// Trigger a manual full-range compaction. RocksDB normally
    /// compacts incrementally; this forces a one-shot full sweep
    /// (useful after a `prune-before` operation to reclaim disk
    /// space immediately).
    pub fn compact_range(&self) {
        // None bounds = "all keys".
        self.db.compact_range::<&[u8], &[u8]>(None, None);
    }

    /// Take a consistent point-in-time snapshot of this store into
    /// `dest`. Uses RocksDB's [`Checkpoint`](rocksdb::checkpoint::Checkpoint)
    /// API: SST files are hard-linked into `dest` (when on the same
    /// filesystem) and MemTable contents are flushed to a new file
    /// there — so the operation is fast (no full data copy) and the
    /// resulting directory is a complete standalone RocksDB store.
    ///
    /// **The destination directory must NOT exist** — RocksDB creates
    /// it and will error if it's already there. Callers handle that
    /// upstream (e.g. snapshot tooling that picks a fresh timestamped
    /// subdir per export).
    ///
    /// Safe to call on a running primary — that's the whole point of
    /// `Checkpoint` vs raw tar of the data dir. No need to stop the
    /// node first.
    pub fn checkpoint(&self, dest: impl AsRef<Path>) -> Result<(), RocksDbError> {
        let cp = rocksdb::checkpoint::Checkpoint::new(&*self.db)?;
        cp.create_checkpoint(dest)?;
        Ok(())
    }

    /// Open `path` read-only. Useful for `dump-blocks`-style tools that
    /// inspect a live java-tron data dir without risking a write.
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self, RocksDbError> {
        let opts = safety_baseline();
        let db = DB::open_for_read_only(&opts, path, /* error_if_log_file_exist */ false)?;
        Ok(Self { db: Arc::new(db) })
    }

    /// Open `primary_path` as a RocksDB secondary instance, with
    /// `secondary_path` as the local writable area RocksDB needs for
    /// per-instance metadata. Multiple secondaries can coexist with one
    /// primary (this is RocksDB's design for live mirroring / readonly
    /// replicas), so we can scan a live java-tron data dir while it's
    /// still being written to.
    ///
    /// Use `try_catch_up_with_primary` if you need to refresh the view
    /// after the primary writes more — otherwise the secondary sees
    /// only what was on disk at open time.
    ///
    /// Note: writes via `put`/`delete` will FAIL on a secondary; this
    /// backend is intended for read-and-copy paths only.
    pub fn open_as_secondary(
        primary_path: impl AsRef<Path>,
        secondary_path: impl AsRef<Path>,
    ) -> Result<Self, RocksDbError> {
        let opts = safety_baseline();
        // `DB::open_as_secondary` requires both paths to share one `P`
        // type parameter; convert both to `&Path` first.
        let db = DB::open_as_secondary(&opts, primary_path.as_ref(), secondary_path.as_ref())?;
        Ok(Self { db: Arc::new(db) })
    }

    /// Like [`open_as_secondary`](Self::open_as_secondary) but registers a
    /// custom comparator — RocksDB enforces the MANIFEST comparator-name
    /// check on secondary opens too, so the live-import read path needs
    /// this for `market_pair_price_to_order`. See
    /// [`open_with_comparator`](Self::open_with_comparator).
    pub fn open_as_secondary_with_comparator(
        primary_path: impl AsRef<Path>,
        secondary_path: impl AsRef<Path>,
        comparator_name: &str,
        compare_fn: fn(&[u8], &[u8]) -> Ordering,
    ) -> Result<Self, RocksDbError> {
        let mut opts = safety_baseline();
        opts.set_comparator(comparator_name, Box::new(compare_fn));
        let db = DB::open_as_secondary(&opts, primary_path.as_ref(), secondary_path.as_ref())?;
        Ok(Self { db: Arc::new(db) })
    }

    /// Refresh a secondary's view to the primary's latest **flushed +
    /// WAL'd** state. A freshly-opened secondary only sees the SST files
    /// that existed at open time — everything the primary has written
    /// since (and anything still in its memtable that hasn't reached an
    /// SST) is invisible until this is called. The live-import path MUST
    /// call this on every store right before scanning, otherwise it
    /// copies a stale, **per-store-skewed** view: each store's last-seen
    /// height differs, so chain-global accumulators in `properties`
    /// (head pointer, `TOTAL_NET_WEIGHT`, …) end up inconsistent with the
    /// per-account frozen balances in `account`. That skew bakes a
    /// permanent offset into every bandwidth/fee calculation and never
    /// re-converges (the weights are delta-accumulators on a wrong base).
    ///
    /// No-op / error on a non-secondary handle — only call on one opened
    /// via [`open_as_secondary`](Self::open_as_secondary).
    pub fn try_catch_up_with_primary(&self) -> Result<(), RocksDbError> {
        self.db.try_catch_up_with_primary()?;
        Ok(())
    }

    /// Open with a custom [`Options`] block. Use for byte-for-byte parity
    /// with a specific java-tron `dbSettings`.
    pub fn open_with(path: impl AsRef<Path>, opts: Options) -> Result<Self, RocksDbError> {
        let db = DB::open(&opts, path)?;
        Ok(Self { db: Arc::new(db) })
    }

    /// Seek to the first key `>= start` and return up to `limit`
    /// consecutive `(key, value)` pairs. RocksDB-native iterator
    /// (`seek`) — no full-table scan. Used by store-level range
    /// helpers (`BlockStore::get_limit_number`, etc.) that the
    /// trait's default `scan_from` would otherwise serve via O(N)
    /// `scan_all`.
    fn rocks_scan_from(&self, start: &[u8], limit: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
        if limit == 0 {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(limit.min(64));
        let mut iter = self.db.raw_iterator();
        iter.seek(start);
        while iter.valid() && out.len() < limit {
            if let (Some(k), Some(v)) = (iter.key(), iter.value()) {
                out.push((k.to_vec(), v.to_vec()));
            }
            iter.next();
        }
        out
    }

    /// Walk backward from (exclusive) `before`, returning up to
    /// `limit` pairs in descending key order. Native RocksDB
    /// `seek_for_prev` + `prev` — no full-table scan. The reverse
    /// mirror of [`rocks_scan_from`](Self::rocks_scan_from); used by
    /// the trait's `scan_back_from` for cursor-resumable reverse
    /// pagination (the `tron-index` ascending-order pages).
    fn rocks_scan_back_from(&self, before: &[u8], limit: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
        if limit == 0 {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(limit.min(64));
        let mut iter = self.db.raw_iterator();
        // `seek_for_prev` lands on the last key <= `before`; the bound
        // is exclusive, so step off an exact match before collecting.
        iter.seek_for_prev(before);
        if iter.valid() && iter.key() == Some(before) {
            iter.prev();
        }
        while iter.valid() && out.len() < limit {
            if let (Some(k), Some(v)) = (iter.key(), iter.value()) {
                out.push((k.to_vec(), v.to_vec()));
            }
            iter.prev();
        }
        out
    }

    /// Prefix-iterate via RocksDB's native iterator. Stops at the
    /// first key that doesn't start with `prefix`.
    fn rocks_scan_prefix(&self, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut out = Vec::new();
        let mut iter = self.db.raw_iterator();
        iter.seek(prefix);
        while iter.valid() {
            let Some(k) = iter.key() else { break };
            if !k.starts_with(prefix) {
                break;
            }
            if let Some(v) = iter.value() {
                out.push((k.to_vec(), v.to_vec()));
            }
            iter.next();
        }
        out
    }

    /// Iterate every `(key, value)` in ascending byte-lexicographic order.
    /// `f` is called once per entry; iteration stops on the first error.
    ///
    /// The closure error type is a boxed `Error` so callers can propagate
    /// their own error variants (e.g. an IO error from writing to stdout)
    /// without forcing them through `RocksDbError`. A backend-level
    /// iteration error is converted into a boxed `RocksDbError`.
    pub fn for_each<F>(&self, mut f: F) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        F: FnMut(&[u8], &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>>,
    {
        let mut iter = self.db.raw_iterator();
        iter.seek_to_first();
        while iter.valid() {
            let (k, v) = (
                iter.key().expect("valid iterator has key"),
                iter.value().expect("valid iterator has value"),
            );
            f(k, v)?;
            iter.next();
        }
        iter.status().map_err(|e| Box::new(RocksDbError::from(e)) as _)
    }
}

impl KvBackend for RocksDbBackend {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, KvError> {
        // Propagate RocksDB errors as `KvError::Backend` — no more
        // silent error-as-None. Real "key not found" is `Ok(None)`.
        self.db.get(key).map_err(Into::into)
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), KvError> {
        self.db.put(key, value).map_err(Into::into)
    }

    fn delete(&self, key: &[u8]) -> Result<(), KvError> {
        self.db.delete(key).map_err(Into::into)
    }

    fn scan_all(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, KvError> {
        let mut out = Vec::new();
        let mut iter = self.db.raw_iterator();
        iter.seek_to_first();
        while iter.valid() {
            let k = iter.key().expect("valid iterator has key").to_vec();
            let v = iter.value().expect("valid iterator has value").to_vec();
            out.push((k, v));
            iter.next();
        }
        // Iterator may have stopped due to a real error rather than
        // end-of-data. Propagate so the caller sees a partial scan
        // as a fault, not as "the store happens to be empty after
        // key K".
        iter.status().map_err(KvError::from)?;
        Ok(out)
    }

    fn scan_from(&self, start: &[u8], limit: usize) -> Result<Vec<(Vec<u8>, Vec<u8>)>, KvError> {
        Ok(self.rocks_scan_from(start, limit))
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, KvError> {
        Ok(self.rocks_scan_prefix(prefix))
    }

    fn scan_back_from(
        &self,
        before: &[u8],
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, KvError> {
        Ok(self.rocks_scan_back_from(before, limit))
    }

    fn write_batch(&self, ops: &[WriteOp]) -> Result<(), KvError> {
        // Native RocksDB `WriteBatch` — atomic across the whole batch.
        // RocksDB writes the batch to its WAL before applying to the
        // MemTable, so a crash mid-write either replays the whole
        // batch on recovery or none of it. The per-call `put`/`delete`
        // path gets the same WAL durability per-key, but loses the
        // cross-key atomicity that the executor's per-tx commit relies
        // on (one tx writing accounts A and B can't be split into
        // "wrote A but not B" by a crash).
        if ops.is_empty() {
            return Ok(());
        }
        let batch = build_batch(ops);
        self.db.write(batch).map_err(Into::into)
    }

    fn write_batch_sync(&self, ops: &[WriteOp]) -> Result<(), KvError> {
        // Same as `write_batch` but with `WriteOptions { sync: true }`.
        // RocksDB fsyncs the WAL before returning, so a kernel panic
        // / power loss between this call and the next can't lose the
        // writes. Used on the consensus-critical block-flush path
        // (cross-store CheckPointV2 commit) — once this returns,
        // deleting the manifest is safe because the per-store WAL is
        // durably on disk.
        if ops.is_empty() {
            return Ok(());
        }
        let batch = build_batch(ops);
        let mut wopts = WriteOptions::default();
        wopts.set_sync(true);
        self.db.write_opt(batch, &wopts).map_err(Into::into)
    }

    fn sync_wal(&self) -> Result<(), KvError> {
        // Flush RocksDB's WAL writer to the OS and fsync it, making every
        // prior non-sync `write_batch` durable. This is the per-store half
        // of the catch-up durability barrier (the cross-store manifest is
        // fsync'd separately by CheckPointV2). `flush_wal(true)` is a no-op
        // when there's nothing buffered, so calling it on an idle store is
        // cheap.
        self.db.flush_wal(true).map_err(Into::into)
    }
}

fn build_batch(ops: &[WriteOp]) -> WriteBatch {
    let mut batch = WriteBatch::default();
    for op in ops {
        match op {
            WriteOp::Put(k, v) => batch.put(k, v),
            WriteOp::Delete(k) => batch.delete(k),
        }
    }
    batch
}

#[derive(Debug, thiserror::Error)]
pub enum RocksDbError {
    #[error("rocksdb: {0}")]
    Inner(#[from] rocksdb::Error),
}
