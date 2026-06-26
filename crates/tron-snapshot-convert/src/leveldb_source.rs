//! A [`KvSource`](tron_chainbase::KvSource) backed by a java-tron LevelDB
//! store, read with the pure-Rust `rusty-leveldb`.
//!
//! java-tron writes its LevelDB stores with the native Google LevelDB C++
//! library (leveldbjni) — the standard on-disk LevelDB format — so any
//! conforming reader works. `rusty-leveldb` is used because it is pure
//! Rust (no C/JNI), reads that format directly, and lets us register a
//! comparator under an arbitrary *name* so the one store java writes with
//! a custom key comparator (`market_pair_price_to_order`) opens and
//! iterates correctly.
//!
//! ## Comparator handling
//!
//! LevelDB records the comparator name in its MANIFEST and (in the
//! reference implementation) refuses to open a store whose configured
//! comparator name differs. For a key-by-key *copy* the iteration ORDER is
//! irrelevant — the destination RocksDB re-sorts on insert — but the
//! reader still has to (a) satisfy the name check and (b) order its
//! internal multi-SST merge with a comparator that agrees with how the
//! on-disk keys are sorted, or the merge could surface keys out of order /
//! incompletely. So for `market_pair_price_to_order` we register a
//! comparator whose `id()` is java's `"MarketOrderPriceComparator"` and
//! whose `cmp()` reproduces java's price ordering byte-for-byte (reusing
//! `tron_chainbase::market_order_price_comparator`). Every other store
//! uses the default bytewise comparator, matching java.

use std::cmp::Ordering;
use std::path::Path;
use std::rc::Rc;

use rusty_leveldb::{Cmp, DefaultCmp, LdbIterator, Options, DB};
use tron_chainbase::{KvSource, VisitError};

/// A `rusty_leveldb::Cmp` that delegates ordering to a plain
/// `fn(&[u8], &[u8]) -> Ordering` and reports a fixed comparator name.
/// Used to mirror java-tron's custom market-order comparator (name +
/// ordering) so the LevelDB store opens and its multi-SST merge is exact.
struct NamedCmp {
    name: &'static str,
    cmp: fn(&[u8], &[u8]) -> Ordering,
}

impl Cmp for NamedCmp {
    fn cmp(&self, a: &[u8], b: &[u8]) -> Ordering {
        (self.cmp)(a, b)
    }

    fn id(&self) -> &'static str {
        self.name
    }

    // `find_shortest_sep` / `find_short_succ` are used only when *writing*
    // SSTs (table building / compaction). This reader never writes, so the
    // exact java semantics don't matter — but we mirror java-tron's custom
    // comparator, which returns an empty separator/successor, to be safe.
    fn find_shortest_sep(&self, _from: &[u8], _to: &[u8]) -> Vec<u8> {
        Vec::new()
    }

    fn find_short_succ(&self, _key: &[u8]) -> Vec<u8> {
        Vec::new()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LevelDbError {
    #[error("open leveldb store {store} at {path}: {source}")]
    Open {
        store: String,
        path: String,
        #[source]
        source: rusty_leveldb::Status,
    },
    #[error("leveldb iterate store {store}: {source}")]
    Iterate {
        store: String,
        #[source]
        source: rusty_leveldb::Status,
    },
}

/// Build read-only `rusty-leveldb` options for `store_name`, registering
/// the custom market comparator (matching java's name + ordering) for the
/// one store that needs it.
///
/// `create_if_missing = false` so a missing/​non-LevelDB directory errors
/// rather than being silently (re)created as an empty LevelDB. `reuse_logs`
/// is left at its default — we only read, and the open replays the WAL
/// into a fresh in-memory memtable, which is what we want (the snapshot's
/// last writes that never reached an SST are included in the copy).
fn options_for(store_name: &str) -> Options {
    let mut opt = Options::default();
    opt.create_if_missing = false;
    opt.paranoid_checks = true;
    if let Some((cmp_name, cmp_fn)) = tron_chainbase::comparator_for_store(store_name) {
        opt.cmp = Rc::new(Box::new(NamedCmp {
            name: cmp_name,
            cmp: cmp_fn,
        }));
    } else {
        // Explicit default — bytewise, name "leveldb.BytewiseComparator",
        // which is what java writes for every other store.
        opt.cmp = Rc::new(Box::new(DefaultCmp));
    }
    opt
}

/// A LevelDB store opened for reading, exposed as a [`KvSource`] so the
/// shared chainbase streaming helper can copy it into RocksDB.
pub struct LevelDbSource {
    store_name: String,
    db: DB,
}

impl LevelDbSource {
    /// Open the LevelDB store directory at `path` read-only.
    pub fn open(path: &Path, store_name: &str) -> Result<Self, LevelDbError> {
        let db = DB::open(path, options_for(store_name)).map_err(|source| LevelDbError::Open {
            store: store_name.to_string(),
            path: path.display().to_string(),
            source,
        })?;
        Ok(Self {
            store_name: store_name.to_string(),
            db,
        })
    }
}

impl KvSource for LevelDbSource {
    fn for_each_kv(
        &mut self,
        f: &mut dyn FnMut(&[u8], &[u8]) -> Result<(), VisitError>,
    ) -> Result<(), VisitError> {
        let mut iter = self.db.new_iter().map_err(|source| LevelDbError::Iterate {
            store: self.store_name.clone(),
            source,
        })?;
        // A fresh iterator is positioned *before* the first element.
        // `LdbIterator::next` advances then reads, so it yields the first
        // element on the first call — do NOT `seek_to_first()` first, which
        // would advance onto the first element and then `next()` would skip
        // it (rusty-leveldb's `next` = advance-then-current).
        //
        // `next` yields owned `(Vec<u8>, Vec<u8>)`; we hand the borrowed
        // slices to `f`, which copies what it needs into the write batch, so
        // each per-entry Vec lives only across one call.
        while let Some((k, v)) = iter.next() {
            f(&k, &v)?;
        }
        Ok(())
    }
}

/// Best-effort detection of whether `dir` is a LevelDB store directory.
///
/// A LevelDB store always has a `CURRENT` file pointing at its MANIFEST.
/// RocksDB stores have `CURRENT` too, so this is not a LevelDB-vs-RocksDB
/// discriminator on its own — that is what java-tron's `engine.properties`
/// marker is for (see [`crate::manifest`]). What this rules out is a plain
/// data directory (no `CURRENT`) that happens to sit alongside the stores.
pub fn looks_like_leveldb_store(dir: &Path) -> bool {
    dir.join("CURRENT").is_file()
}
