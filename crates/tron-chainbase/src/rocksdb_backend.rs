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

use std::path::Path;
use std::sync::Arc;

use rocksdb::{Options, DB};

use crate::backend::KvBackend;

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
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_max_open_files(DEFAULT_MAX_OPEN_FILES);
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
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_write_buffer_size(write_buffer_mb * 1024 * 1024);
        opts.set_max_open_files(max_open_files);
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
        let mut opts = Options::default();
        opts.set_max_open_files(DEFAULT_MAX_OPEN_FILES);
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
        let mut opts = Options::default();
        opts.set_max_open_files(DEFAULT_MAX_OPEN_FILES);
        // `DB::open_as_secondary` requires both paths to share one `P`
        // type parameter; convert both to `&Path` first.
        let db = DB::open_as_secondary(&opts, primary_path.as_ref(), secondary_path.as_ref())?;
        Ok(Self { db: Arc::new(db) })
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
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        // `get` returns `Result<Option<Vec<u8>>, Error>`. We treat hard
        // errors as "not found" here because the `KvBackend` trait
        // doesn't expose a fallible read; higher-level code that needs
        // error visibility should use the inner DB directly.
        self.db.get(key).ok().flatten()
    }

    fn put(&self, key: &[u8], value: &[u8]) {
        // Same here — surface failure through logs in production, panic
        // in tests. The trait isn't fallible because most callsites
        // can't usefully recover from a DB write error mid-flight.
        if let Err(e) = self.db.put(key, value) {
            panic!("rocksdb put failed: {e}");
        }
    }

    fn delete(&self, key: &[u8]) {
        if let Err(e) = self.db.delete(key) {
            panic!("rocksdb delete failed: {e}");
        }
    }

    fn scan_all(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut out = Vec::new();
        let mut iter = self.db.raw_iterator();
        iter.seek_to_first();
        while iter.valid() {
            let k = iter.key().expect("valid iterator has key").to_vec();
            let v = iter.value().expect("valid iterator has value").to_vec();
            out.push((k, v));
            iter.next();
        }
        // Surface iterator status as a panic — same pattern as put/delete:
        // higher-level callers can't usefully recover, and most stores
        // would be left in an undefined state if scan returned partial
        // data silently.
        if let Err(e) = iter.status() {
            panic!("rocksdb scan_all failed: {e}");
        }
        out
    }

    fn scan_from(&self, start: &[u8], limit: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.rocks_scan_from(start, limit)
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.rocks_scan_prefix(prefix)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RocksDbError {
    #[error("rocksdb: {0}")]
    Inner(#[from] rocksdb::Error),
}
