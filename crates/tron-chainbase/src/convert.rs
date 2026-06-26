//! Reusable per-store streaming + the canonical store-name list.
//!
//! java-tron stores the same serialized capsule bytes regardless of the
//! storage engine — LevelDB and RocksDB are a *format* difference, not a
//! semantic one. So moving state between engines (or mirroring a live
//! RocksDB tree) is a key-by-key copy: iterate every `(key, value)` from
//! a source store and `put` it into a destination [`RocksDbBackend`],
//! verbatim. No re-serialization, no semantic mapping.
//!
//! Two callers share this path today:
//!
//! * `tron-node`'s `import_live` — source is a RocksDB *secondary* opened
//!   against a still-running java-tron node.
//! * `tron-snapshot-convert` — source is a java-tron **LevelDB** store.
//!
//! Both differ only in how they read; the write half (batched `put` into
//! a `RocksDbBackend`, with the right per-store comparator registered) is
//! identical and lives here so the two can't drift.

use std::path::Path;

use crate::backend::KvBackend;
use crate::rocksdb_backend::{RocksDbBackend, RocksDbError};
use crate::stores::comparator_for_store;

/// The per-store batch size for destination writes. Matches java-tron's
/// own `DbConvert` tool (`BATCH = 256`): large enough to amortize the
/// RocksDB write path, small enough that a stalled/​busy destination
/// applies back-pressure promptly.
pub const CONVERT_BATCH: usize = 256;

/// The boxed error type the visitor and source iteration share — the same
/// shape [`RocksDbBackend::for_each`] uses — so a write error raised inside
/// the visitor and a read error raised by the source travel one channel
/// (no double-wrapping) and either can abort the scan.
pub type VisitError = Box<dyn std::error::Error + Send + Sync>;

/// A read-only source of `(key, value)` pairs for one store — the read
/// half of a store copy. Implemented by a RocksDB secondary
/// (`import_live`) and by a LevelDB reader (the converter), so the
/// batched-write half below stays source-agnostic.
///
/// The visitor is handed borrowed slices (no per-entry allocation forced
/// on the caller) and may abort iteration by returning `Err`.
pub trait KvSource {
    /// Visit every `(key, value)` in the store. Iteration order is
    /// unspecified and irrelevant — the destination RocksDB re-sorts on
    /// insert — so a source may yield in whatever order is cheapest.
    fn for_each_kv(
        &mut self,
        f: &mut dyn FnMut(&[u8], &[u8]) -> Result<(), VisitError>,
    ) -> Result<(), VisitError>;
}

/// A [`KvSource`] over a [`RocksDbBackend`] — the read half when the
/// source store is itself RocksDB (the live-import secondary path). The
/// converter supplies its own LevelDB-backed `KvSource` instead.
pub struct RocksDbSource<'a> {
    pub store_name: &'a str,
    pub backend: &'a RocksDbBackend,
}

impl KvSource for RocksDbSource<'_> {
    fn for_each_kv(
        &mut self,
        f: &mut dyn FnMut(&[u8], &[u8]) -> Result<(), VisitError>,
    ) -> Result<(), VisitError> {
        self.backend.for_each(|k, v| f(k, v))
    }
}

/// Outcome of streaming one store: counts + byte sums, mirroring the
/// integrity figures java-tron's `DbConvert.check()` compares between
/// source and destination. The byte sums are a cheap content fingerprint
/// (sum of every key/value byte) that, together with the key count,
/// catches a truncated or corrupted copy without a second full scan of
/// the source.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StreamStats {
    /// Number of `(key, value)` pairs streamed.
    pub key_count: u64,
    /// Sum of every key byte (wrapping). Content fingerprint, not a hash.
    pub key_byte_sum: u64,
    /// Sum of every value byte (wrapping).
    pub value_byte_sum: u64,
    /// Total bytes streamed (`key.len() + value.len()` summed) — the raw
    /// data volume, for progress / report figures. Not part of the
    /// integrity comparison (the count + byte sums are), so it is excluded
    /// from `PartialEq` via [`StreamStats::integrity_eq`].
    pub byte_volume: u64,
}

impl StreamStats {
    fn observe(&mut self, k: &[u8], v: &[u8]) {
        self.key_count += 1;
        let mut ks: u64 = 0;
        for &b in k {
            ks = ks.wrapping_add(b as u64);
        }
        let mut vs: u64 = 0;
        for &b in v {
            vs = vs.wrapping_add(b as u64);
        }
        self.key_byte_sum = self.key_byte_sum.wrapping_add(ks);
        self.value_byte_sum = self.value_byte_sum.wrapping_add(vs);
        self.byte_volume = self
            .byte_volume
            .wrapping_add(k.len() as u64)
            .wrapping_add(v.len() as u64);
    }

    /// Integrity equality: key count + both byte sums (java-tron's
    /// `DbConvert.check` triple). Excludes `byte_volume`, which is a
    /// reporting figure, not a content fingerprint — though for a faithful
    /// copy it matches too.
    pub fn integrity_eq(&self, other: &Self) -> bool {
        self.key_count == other.key_count
            && self.key_byte_sum == other.key_byte_sum
            && self.value_byte_sum == other.value_byte_sum
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConvertError {
    #[error("rocksdb (store {store}): {source}")]
    RocksDb {
        store: String,
        #[source]
        source: RocksDbError,
    },
    #[error("destination write (store {store}): {source}")]
    Write {
        store: String,
        #[source]
        source: crate::backend::KvError,
    },
    #[error("source read (store {store}): {source}")]
    Source {
        store: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error(
        "integrity check failed for store {store}: source {src:?} != destination {dst:?} \
         (the copied store does not match the source — re-run the conversion for it)"
    )]
    IntegrityMismatch {
        store: String,
        src: StreamStats,
        dst: StreamStats,
    },
}

/// Open the destination RocksDB store at `dest`, registering the custom
/// comparator java-tron uses for that store name if any. Centralised so
/// every write path (live-import, convert) opens the destination with the
/// same comparator and never trips RocksDB's MANIFEST comparator-name
/// check on a later read. `compression_zstd` selects Zstd over the
/// default Snappy for the *newly written* SSTs — a pure storage choice
/// (RocksDB records the codec per-SST, so reads stay transparent and
/// byte-faithful).
pub fn open_dest_store(
    dest: &Path,
    store_name: &str,
    compression_zstd: bool,
) -> Result<RocksDbBackend, RocksDbError> {
    match comparator_for_store(store_name) {
        Some((cmp_name, cmp_fn)) => RocksDbBackend::open_for_convert_with_comparator(
            dest,
            cmp_name,
            cmp_fn,
            compression_zstd,
        ),
        None => RocksDbBackend::open_for_convert(dest, compression_zstd),
    }
}

/// Stream every `(key, value)` from `source` into an already-open
/// destination `dst`, in [`CONVERT_BATCH`]-sized atomic write batches,
/// accumulating the integrity fingerprint. Does NOT fsync — the caller
/// decides when to flush (the converter fsyncs once per store, after this
/// returns, before marking the store done).
///
/// The destination is the read-write store the daemon will open later;
/// the source supplies the read half via [`KvSource`].
pub fn stream_source_into_dest(
    store_name: &str,
    source: &mut dyn KvSource,
    dst: &RocksDbBackend,
) -> Result<StreamStats, ConvertError> {
    use crate::backend::WriteOp;

    let mut stats = StreamStats::default();
    let mut batch: Vec<WriteOp> = Vec::with_capacity(CONVERT_BATCH);
    let store = store_name.to_string();

    // Write errors raised inside the visitor travel the source's boxed
    // error channel; we tag them with the store name and recover the typed
    // `ConvertError` below so the caller still gets a structured error.
    let flush = |dst: &RocksDbBackend, batch: &mut Vec<WriteOp>| -> Result<(), VisitError> {
        if batch.is_empty() {
            return Ok(());
        }
        dst.write_batch(batch).map_err(|e| {
            Box::new(ConvertError::Write {
                store: store.clone(),
                source: e,
            }) as VisitError
        })?;
        batch.clear();
        Ok(())
    };

    let scan = source.for_each_kv(&mut |k, v| {
        stats.observe(k, v);
        batch.push(WriteOp::Put(k.to_vec(), v.to_vec()));
        if batch.len() >= CONVERT_BATCH {
            flush(dst, &mut batch)?;
        }
        Ok(())
    });
    // A `ConvertError` raised by our own flush comes back boxed — unbox it;
    // anything else is a genuine source-read failure.
    if let Err(boxed) = scan.and_then(|()| flush(dst, &mut batch)) {
        return Err(unbox_convert_error(store_name, boxed));
    }

    Ok(stats)
}

/// Recover a structured [`ConvertError`] from the source's boxed error
/// channel: if the box already holds a `ConvertError` (raised by our own
/// flush), return it as-is; otherwise it's a genuine source-read failure,
/// so wrap it as [`ConvertError::Source`].
fn unbox_convert_error(store_name: &str, boxed: VisitError) -> ConvertError {
    match boxed.downcast::<ConvertError>() {
        Ok(ce) => *ce,
        Err(other) => ConvertError::Source {
            store: store_name.to_string(),
            source: other,
        },
    }
}

/// Re-iterate the destination store and verify its key count + byte
/// fingerprint match `expected` (the figure accumulated while writing).
/// Mirrors java-tron's `DbConvert.check()`: a cheap second pass that
/// catches a truncated / corrupted copy without re-reading the source.
pub fn verify_dest_store(
    store_name: &str,
    dst: &RocksDbBackend,
    expected: StreamStats,
) -> Result<(), ConvertError> {
    let mut got = StreamStats::default();
    dst.for_each(|k, v| {
        got.observe(k, v);
        Ok::<(), VisitError>(())
    })
    .map_err(|e| ConvertError::Source {
        store: store_name.to_string(),
        source: e,
    })?;
    if !got.integrity_eq(&expected) {
        return Err(ConvertError::IntegrityMismatch {
            store: store_name.to_string(),
            src: expected,
            dst: got,
        });
    }
    Ok(())
}

/// Every java-tron store directory name this node opens, as the exact
/// `@Value("…")` dbName each store carries in java's `ChainBaseManager`.
/// Single source of truth, in lockstep with
/// `tron_node::storage::OpenedStores::open_inner` (which opens these) and
/// `backend_for_store_name` (which resolves them).
///
/// A snapshot/​live tree may legitimately carry *more* directories than
/// this (auxiliary or rebuildable stores: `recent-block`,
/// `tree-block-index`, `section-bloom`, `trans-cache`, …). A converter
/// copies whatever LevelDB directories it finds — it does not restrict to
/// this list — but this list is the set the daemon will actually read, so
/// it is the right thing to validate completeness against.
pub const NODE_STORE_NAMES: &[&str] = &[
    "account",
    "account-asset",
    "witness",
    "votes",
    "delegation",
    "DelegatedResource",
    "DelegatedResourceAccountIndex",
    "properties",
    "proposal",
    "accountid-index",
    "account-index",
    "asset-issue",
    "asset-issue-v2",
    "contract",
    "abi",
    "exchange",
    "exchange-v2",
    "market_order",
    "market_account",
    "market_pair_to_price",
    "market_pair_price_to_order",
    "nullifier",
    "IncrementalMerkleTree",
    "code",
    "storage-row",
    "contract-state",
    "block-index",
    "block",
    "trans",
    "transactionHistoryStore",
    "transactionRetStore",
    "balance-trace",
    "witness_schedule",
    "reward-vi",
    "block-undo",
    "pbft-sign-data",
    "common-database",
    "common",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{KvBackend, MemBackend};

    /// A `KvSource` over an in-memory map — lets us exercise the streaming
    /// + integrity path without a real LevelDB/RocksDB source.
    struct MemSource<'a>(&'a MemBackend);
    impl KvSource for MemSource<'_> {
        fn for_each_kv(
            &mut self,
            f: &mut dyn FnMut(&[u8], &[u8]) -> Result<(), VisitError>,
        ) -> Result<(), VisitError> {
            // collect first so we don't hold the read lock across `f`
            let rows = self.0.scan_all().unwrap();
            for (k, v) in rows {
                f(&k, &v)?;
            }
            Ok(())
        }
    }

    fn tmp(label: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        p.push(format!("chainbase-convert-{label}-{n}"));
        p
    }

    #[test]
    fn stream_then_verify_round_trips() {
        let src = MemBackend::new();
        for i in 0u32..1000 {
            src.put(format!("k{i:06}").as_bytes(), format!("value-{i}").as_bytes())
                .unwrap();
        }
        let dest_dir = tmp("rt");
        {
            // Snappy here: the workspace `rocksdb` dep this test binary links
            // doesn't enable the `zstd` feature (only the converter crate
            // does), so the Zstd path is exercised in that crate's tests.
            let dst = open_dest_store(&dest_dir, "account", false).unwrap();
            let stats = stream_source_into_dest("account", &mut MemSource(&src), &dst).unwrap();
            assert_eq!(stats.key_count, 1000);
            dst.sync_wal().unwrap();
            verify_dest_store("account", &dst, stats).unwrap();
        }
        // Re-open the destination and confirm every row round-tripped
        // byte-for-byte.
        {
            let dst = RocksDbBackend::open(&dest_dir).unwrap();
            for i in 0u32..1000 {
                let got = dst.get(format!("k{i:06}").as_bytes()).unwrap();
                assert_eq!(got.as_deref(), Some(format!("value-{i}").as_bytes()));
            }
        }
        let _ = std::fs::remove_dir_all(&dest_dir);
    }

    #[test]
    fn verify_detects_mismatch() {
        let dest_dir = tmp("mismatch");
        let dst = open_dest_store(&dest_dir, "common", false).unwrap();
        dst.put(b"a", b"1").unwrap();
        // Claim a count that doesn't match what's on disk.
        let wrong = StreamStats {
            key_count: 99,
            key_byte_sum: 0,
            value_byte_sum: 0,
            byte_volume: 0,
        };
        let err = verify_dest_store("common", &dst, wrong).unwrap_err();
        assert!(matches!(err, ConvertError::IntegrityMismatch { .. }));
        drop(dst);
        let _ = std::fs::remove_dir_all(&dest_dir);
    }

    #[test]
    fn node_store_names_unique_and_nonempty() {
        let mut seen = std::collections::HashSet::new();
        for n in NODE_STORE_NAMES {
            assert!(!n.is_empty());
            assert!(seen.insert(*n), "duplicate store name {n}");
        }
        // market store with the custom comparator must be present.
        assert!(NODE_STORE_NAMES.contains(&"market_pair_price_to_order"));
    }
}
