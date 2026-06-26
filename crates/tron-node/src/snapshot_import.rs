//! Import a java-tron snapshot into our `data_dir/db/`.
//!
//! Mainnet TRON is too large to bootstrap from genesis in any
//! reasonable time, and the public peer pool is saturated for new
//! sync clients (see the live-sync notes in [`crate::sync`]). The
//! standard way to stand up a usable node is to fetch a pre-built
//! snapshot tarball and import it.
//!
//! `--from` accepts either:
//!
//! * A **directory** of per-store subdirs (account/, witness/, ...),
//! * A **tarball** (`.tar`, `.tar.gz`, `.tgz`) — auto-extracted to a
//!   temp dir, then imported.
//!
//! Snapshot layout — what we expect at `--from` (or inside the
//! tarball):
//!
//! ```text
//! /path/to/snapshot/
//!   account/            ← RocksDB / LevelDB directory
//!   witness/
//!   properties/
//!   block/
//!   block-index/
//!   ...                 ← every store java-tron writes
//! ```
//!
//! Tarballs that wrap the per-store dirs one level deeper (e.g., a
//! single `database/` subdirectory at the root) are auto-detected and
//! descended into.
//!
//! Import modes:
//!
//! * [`ImportMode::Copy`] — recursive `std::fs::copy`. Slow but safest.
//!   Use when the snapshot will be deleted after import.
//! * [`ImportMode::Symlink`] — one symlink per per-store subdir.
//!   Instant; the snapshot directory must stay where it is for the
//!   life of the node.
//! * [`ImportMode::Move`] — `std::fs::rename`. Same-FS only; fails
//!   across mount points. Fast when it works.

use std::path::{Path, PathBuf};

use crate::storage::OpenedStores;

/// How to plant the snapshot's per-store subdirs at the destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportMode {
    /// Deep-copy each subdir. Source can be deleted after.
    Copy,
    /// `std::fs::rename`. Fast, but fails across mount points.
    Move,
    /// `std::os::unix::fs::symlink` per subdir. Source must persist.
    Symlink,
}

impl ImportMode {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "copy" => Some(Self::Copy),
            "move" => Some(Self::Move),
            "symlink" | "symbol-link" | "link" => Some(Self::Symlink),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ImportReport {
    /// Number of per-store subdirs successfully planted.
    pub stores_imported: usize,
    /// Total bytes copied (only meaningful for [`ImportMode::Copy`];
    /// `0` for Move/Symlink).
    pub bytes_copied: u64,
    /// Head block number read from the imported properties store.
    /// `0` if the snapshot doesn't have a head pointer (unusual).
    pub head_block_number: i64,
    /// Head block hash (lowercase hex, no `0x`). Empty if missing.
    pub head_block_hash_hex: String,
    /// Solidified head number from `LATEST_SOLIDIFIED_BLOCK_NUM`.
    pub solidified_block_number: i64,
    /// Number of witnesses in the imported witness store.
    pub witness_count: usize,
    /// Per-store subdir names planted, in import order.
    pub stores: Vec<String>,
    /// Cross-store consistency problems detected in the imported state
    /// (empty = clean). A non-empty list means the snapshot's stores
    /// reflect *different heights* — the hallmark of a snapshot copied
    /// from a LIVE node without a quiescent flush. Such a base silently
    /// diverges from consensus once the node applies blocks on top of
    /// it, so the caller should refuse to run on it and re-import from a
    /// consistent snapshot.
    pub consistency_warnings: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("source does not exist: {0}")]
    SourceMissing(PathBuf),
    #[error("source is not a directory: {0}")]
    SourceNotDir(PathBuf),
    #[error("source has no per-store subdirectories")]
    SourceEmpty,
    #[error("destination already populated; pass --force to replace")]
    DestinationPopulated,
    #[error("io error at {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("post-import verification: {0}")]
    Verification(String),
    #[error("unsupported archive extension (expected .tar, .tar.gz, .tgz): {0:?}")]
    UnsupportedArchive(PathBuf),
    #[error("refusing unsafe archive entry (absolute path, `..` traversal, or symlink/hardlink): {0:?}")]
    UnsafeArchiveEntry(PathBuf),
    #[error("could not locate per-store subdirs inside extracted archive at {0:?}")]
    SnapshotLayout(PathBuf),
    #[error("rocksdb live-import failed for {store}: {source}")]
    RocksDb {
        store: String,
        #[source]
        source: tron_chainbase::RocksDbError,
    },
    #[error("live-import scan error for {store}: {source}")]
    LiveScan {
        store: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error(transparent)]
    Storage(#[from] crate::storage::StorageError),
}

/// Unified import entry point — accepts a directory OR a tarball.
///
/// Dispatch:
///
/// * **Directory** → calls [`import_from_directory`] directly.
/// * **Tarball** (`.tar`, `.tar.gz`, `.tgz`) → extracts to a temp
///   dir under `data_dir/.snapshot-extract/`, auto-detects whether
///   the per-store subdirs are at the root or wrapped one level
///   deeper, then calls [`import_from_directory`]. The temp dir is
///   removed on completion (success or failure).
///
/// `ImportMode::Move` and `ImportMode::Symlink` are honored after
/// extraction, but for tarballs they have little payoff since the
/// extracted tree lives in a temp dir that's about to be deleted —
/// `Move` may leave dangling files, `Symlink` would symlink to the
/// temp path which gets removed. Use `Copy` for tarball imports.
pub fn import_snapshot(
    from: &Path,
    data_dir: &Path,
    mode: ImportMode,
    force: bool,
) -> Result<ImportReport, ImportError> {
    if from.is_dir() {
        return import_from_directory(from, data_dir, mode, force);
    }
    if !from.exists() {
        return Err(ImportError::SourceMissing(from.to_path_buf()));
    }

    // Tarball path. Extract to a temp dir under data_dir, descend
    // into the snapshot root, import, clean up.
    let extract_root = data_dir.join(".snapshot-extract");
    if extract_root.exists() {
        std::fs::remove_dir_all(&extract_root).map_err(|e| ImportError::Io {
            path: extract_root.clone(),
            source: e,
        })?;
    }
    std::fs::create_dir_all(&extract_root).map_err(|e| ImportError::Io {
        path: extract_root.clone(),
        source: e,
    })?;

    let extract_result = extract_archive(from, &extract_root);
    let cleanup = || {
        let _ = std::fs::remove_dir_all(&extract_root);
    };
    let snapshot_root = match extract_result {
        Ok(()) => match find_snapshot_root(&extract_root) {
            Ok(p) => p,
            Err(e) => {
                cleanup();
                return Err(e);
            }
        },
        Err(e) => {
            cleanup();
            return Err(e);
        }
    };

    let result = import_from_directory(&snapshot_root, data_dir, mode, force);
    cleanup();
    result
}

/// Extract a `.tar` / `.tar.gz` / `.tgz` archive into `dest`. Errors
/// out cleanly on unsupported extensions.
fn extract_archive(archive: &Path, dest: &Path) -> Result<(), ImportError> {
    let file = std::fs::File::open(archive).map_err(|e| ImportError::Io {
        path: archive.to_path_buf(),
        source: e,
    })?;
    let name_lower = archive
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    if name_lower.ends_with(".tar.gz") || name_lower.ends_with(".tgz") {
        let decoder = flate2::read::GzDecoder::new(file);
        unpack_safely(tar::Archive::new(decoder), dest)?;
    } else if name_lower.ends_with(".tar") {
        unpack_safely(tar::Archive::new(file), dest)?;
    } else {
        return Err(ImportError::UnsupportedArchive(archive.to_path_buf()));
    }
    Ok(())
}

/// Unpack `archive` into `dest`, refusing any entry that could plant
/// something outside it (F-28). A snapshot is just RocksDB data dirs, so
/// we reject:
///
/// * absolute paths and `..` / root traversal components, and
/// * symlink and hardlink entries.
///
/// The library already skips `..` and blocks writes that resolve outside
/// `dest`, but it would still *create* a symlink entry inside `dest` —
/// which the subsequent directory import (copy / symlink / move) then
/// follows, escaping the data dir after the fact. Refusing link entries
/// outright closes that. We also stop preserving archive permissions and
/// ownerships (no suid / foreign-UID files) and never overwrite existing
/// files. Failures are explicit errors rather than silent skips.
fn unpack_safely<R: std::io::Read>(
    mut archive: tar::Archive<R>,
    dest: &Path,
) -> Result<(), ImportError> {
    use std::path::Component;

    archive.set_preserve_permissions(false);
    archive.set_preserve_ownerships(false);
    archive.set_overwrite(false);

    let io_err = |e: std::io::Error| ImportError::Io {
        path: dest.to_path_buf(),
        source: e,
    };

    let entries = archive.entries().map_err(io_err)?;
    for entry in entries {
        let mut entry = entry.map_err(io_err)?;
        let path = entry.path().map_err(io_err)?.into_owned();

        // Reject absolute paths and any parent-dir / root traversal.
        if path.components().any(|c| {
            matches!(
                c,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        }) {
            return Err(ImportError::UnsafeArchiveEntry(path));
        }

        // Reject symlink / hardlink entries outright — never legitimate
        // in a store snapshot, and the escape primitive.
        let kind = entry.header().entry_type();
        if kind.is_symlink() || kind.is_hard_link() {
            return Err(ImportError::UnsafeArchiveEntry(path));
        }

        // `unpack_in` re-validates containment within `dest` and returns
        // false if the entry would still escape — treat that as unsafe.
        if !entry.unpack_in(dest).map_err(io_err)? {
            return Err(ImportError::UnsafeArchiveEntry(path));
        }
    }
    Ok(())
}

/// After unpacking, locate the directory that contains the per-store
/// subdirs. Two common layouts:
///
/// 1. **Flat**: per-store subdirs live at the root of the extraction
///    (`extract/account`, `extract/witness`, ...). Use root as-is.
/// 2. **Wrapped**: the tarball contains a single top-level dir (e.g.,
///    `extract/database/account`, `extract/database/witness`, ...).
///    Descend into the single dir.
///
/// Heuristic: if the root contains a `properties` subdir (mandatory
/// for any real snapshot — it holds the head pointer), use the root.
/// Otherwise, if the root has exactly one subdirectory and that
/// subdirectory contains `properties`, descend.
fn find_snapshot_root(extract_root: &Path) -> Result<PathBuf, ImportError> {
    if extract_root.join("properties").is_dir() {
        return Ok(extract_root.to_path_buf());
    }
    let entries: Vec<PathBuf> = std::fs::read_dir(extract_root)
        .map_err(|e| ImportError::Io {
            path: extract_root.to_path_buf(),
            source: e,
        })?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    if entries.len() == 1 && entries[0].join("properties").is_dir() {
        return Ok(entries[0].clone());
    }
    // Two-level wrap (e.g. `output-directory/database/`): try walking
    // one more level under the single dir.
    if entries.len() == 1 {
        let inner: Vec<PathBuf> = std::fs::read_dir(&entries[0])
            .map_err(|e| ImportError::Io {
                path: entries[0].clone(),
                source: e,
            })?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        if inner.len() == 1 && inner[0].join("properties").is_dir() {
            return Ok(inner[0].clone());
        }
    }
    Err(ImportError::SnapshotLayout(extract_root.to_path_buf()))
}

/// Import a snapshot. Returns an [`ImportReport`] describing what was
/// imported plus the verified head pointer.
///
/// Steps:
///
/// 1. Validate `from` exists, is a directory, contains at least one
///    per-store subdir.
/// 2. If `data_dir/db/` exists and contains entries, refuse unless
///    `force == true`. With `force`, the old contents are wiped first.
/// 3. For each subdir in `from`, plant it at `data_dir/db/<subdir>`
///    via the chosen [`ImportMode`].
/// 4. Open the imported stores and read the head pointer + witness
///    count for the report. A snapshot that opens but has no head
///    pointer is reported (not erored) — it's a valid early-state
///    snapshot, just unusual.
pub fn import_from_directory(
    from: &Path,
    data_dir: &Path,
    mode: ImportMode,
    force: bool,
) -> Result<ImportReport, ImportError> {
    if !from.exists() {
        return Err(ImportError::SourceMissing(from.to_path_buf()));
    }
    if !from.is_dir() {
        return Err(ImportError::SourceNotDir(from.to_path_buf()));
    }

    // Enumerate per-store subdirs. We accept anything that looks like
    // a directory; the per-store typed wrappers in `OpenedStores` will
    // reject anything malformed when we open them at the end.
    let mut subdirs: Vec<PathBuf> = Vec::new();
    let entries = std::fs::read_dir(from).map_err(|e| ImportError::Io {
        path: from.to_path_buf(),
        source: e,
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| ImportError::Io {
            path: from.to_path_buf(),
            source: e,
        })?;
        let path = entry.path();
        if path.is_dir() {
            subdirs.push(path);
        }
    }
    if subdirs.is_empty() {
        return Err(ImportError::SourceEmpty);
    }

    // Compute destination root: data_dir/db. Wipe if force.
    let db_root = crate::storage::resolve_db_root(data_dir);
    if db_root.exists() {
        let mut populated = false;
        if let Ok(mut entries) = std::fs::read_dir(&db_root) {
            if entries.next().is_some() {
                populated = true;
            }
        }
        if populated && !force {
            return Err(ImportError::DestinationPopulated);
        }
        if force {
            std::fs::remove_dir_all(&db_root).map_err(|e| ImportError::Io {
                path: db_root.clone(),
                source: e,
            })?;
        }
    }
    std::fs::create_dir_all(&db_root).map_err(|e| ImportError::Io {
        path: db_root.clone(),
        source: e,
    })?;

    let mut bytes_copied: u64 = 0;
    let mut store_names: Vec<String> = Vec::with_capacity(subdirs.len());

    for src in &subdirs {
        let name = src
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| ImportError::Io {
                path: src.clone(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "subdir has non-UTF8 name",
                ),
            })?
            .to_string();
        let dest = db_root.join(&name);
        match mode {
            ImportMode::Copy => {
                bytes_copied += copy_dir_recursive(src, &dest)?;
            }
            ImportMode::Move => {
                std::fs::rename(src, &dest).map_err(|e| ImportError::Io {
                    path: dest.clone(),
                    source: e,
                })?;
            }
            ImportMode::Symlink => {
                let abs_src = src.canonicalize().map_err(|e| ImportError::Io {
                    path: src.clone(),
                    source: e,
                })?;
                #[cfg(unix)]
                std::os::unix::fs::symlink(&abs_src, &dest).map_err(|e| ImportError::Io {
                    path: dest.clone(),
                    source: e,
                })?;
                #[cfg(windows)]
                std::os::windows::fs::symlink_dir(&abs_src, &dest).map_err(|e| {
                    ImportError::Io {
                        path: dest.clone(),
                        source: e,
                    }
                })?;
            }
        }
        store_names.push(name);
    }

    // Verify: open every store the daemon would touch, read the head
    // pointer. Don't error on missing head — empty / pre-genesis
    // snapshots are valid input for a `tron-node init` followed by a
    // subsequent import. Do bubble up `OpenedStores::open` errors
    // (RocksDB corruption etc.) as `Storage`.
    let stores = OpenedStores::open(data_dir)?;
    // Replay any java-format checkpoint planted alongside the stores so
    // the imported base is fully flushed (see `merge_java_checkpoint`).
    merge_java_checkpoint(&stores, data_dir)?;
    let report = build_report(&stores, store_names, bytes_copied)?;
    Ok(report)
}

/// Replay a java-tron on-disk checkpoint (`database/tmp` V1 or
/// `database/checkpoint/<ts>` V2) into the freshly-opened stores, then
/// drop it so it is not replayed again.
///
/// java-tron persists the most-recent flush batch as a redo log and
/// replays it over the per-store databases on every startup
/// (`SnapshotManager.recover`); its LiteFullNode snapshot tool does the
/// same when producing a snapshot (`DbLite.mergeCheckpoint2Snapshot`).
/// A raw filesystem copy of a java data dir — the usual mainnet
/// snapshot form — carries that checkpoint un-merged. Without this
/// replay the imported base would sit up to one flush batch behind the
/// head pointer recorded in `properties`: a silent, permanent
/// divergence from consensus that no per-store decode check would
/// catch. Replaying is idempotent for an already-flushed base (the rows
/// re-write the same final state), so it is safe to run unconditionally.
///
/// The replayed checkpoint store is removed afterwards: this node uses
/// its own checkpoint format and never reads the java one again, so
/// leaving it would only mislead a later re-import.
fn merge_java_checkpoint(
    stores: &OpenedStores,
    data_dir: &Path,
) -> Result<(), ImportError> {
    let db_root = crate::storage::resolve_db_root(data_dir);
    let applied = tron_chainbase::replay_java_checkpoint(&db_root, |name| {
        stores.backend_for_store_name(name)
    })
    .map_err(|e| ImportError::Verification(format!("java checkpoint replay: {e}")))?;
    if applied > 0 {
        // Drop the now-merged checkpoint stores so a future re-import of
        // this data dir doesn't re-detect them as pending. A symlink
        // import points these at the source snapshot — unlink the symlink
        // itself rather than `remove_dir_all` through it, which would
        // delete the source's checkpoint.
        for sub in [
            tron_chainbase::JAVA_CHECKPOINT_V1_DIR,
            tron_chainbase::JAVA_CHECKPOINT_V2_DIR,
        ] {
            let p = db_root.join(sub);
            match std::fs::symlink_metadata(&p) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    let _ = std::fs::remove_file(&p);
                }
                Ok(_) => {
                    let _ = std::fs::remove_dir_all(&p);
                }
                Err(_) => {}
            }
        }
    }
    Ok(())
}

/// Import from a **live** java-tron RocksDB tree without requiring
/// java-tron to stop.
///
/// Strategy: each per-store subdirectory under `from` is a separate
/// RocksDB instance. We open each as a **secondary** instance (RocksDB
/// supports multiple read-only secondaries against a single primary),
/// scan every `(key, value)` pair, and write into our destination
/// store under `data_dir/db/<store>`. Java-tron keeps running.
///
/// Trade-offs vs. the directory/tarball import:
///
/// * **No downtime** for the source node.
/// * **No file copy**, just key-by-key streaming through RocksDB — so
///   we pay the read cost (decompress SSTs, walk MANIFEST) on top of
///   the write cost. Roughly the same total time as `--mode copy` on
///   the same disk.
/// * **Snapshot consistency is per-store, not chain-wide**. Between
///   opening `account/` and opening `block/`, java-tron may apply N
///   more blocks. The destination ends up at a slightly inconsistent
///   point-in-time view (different stores at slightly different
///   heights). For sync-to-tip this is fine — the daemon will catch
///   up the gap on first run via the regular SyncBlockChain flow.
///
/// `secondary_cache_dir` is the local writable area RocksDB needs for
/// per-secondary metadata. One subdir per imported store. Defaults to
/// `data_dir/.live-import-cache/` when `None`.
pub fn import_live(
    from: &Path,
    data_dir: &Path,
    secondary_cache_dir: Option<&Path>,
    force: bool,
) -> Result<ImportReport, ImportError> {
    use tron_chainbase::RocksDbBackend;

    if !from.exists() {
        return Err(ImportError::SourceMissing(from.to_path_buf()));
    }
    if !from.is_dir() {
        return Err(ImportError::SourceNotDir(from.to_path_buf()));
    }

    // Enumerate per-store subdirs under `from`.
    let mut subdirs: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(from).map_err(|e| ImportError::Io {
        path: from.to_path_buf(),
        source: e,
    })? {
        let entry = entry.map_err(|e| ImportError::Io {
            path: from.to_path_buf(),
            source: e,
        })?;
        let p = entry.path();
        if p.is_dir() {
            subdirs.push(p);
        }
    }
    if subdirs.is_empty() {
        return Err(ImportError::SourceEmpty);
    }

    let db_root = crate::storage::resolve_db_root(data_dir);
    if db_root.exists() {
        let mut populated = false;
        if let Ok(mut entries) = std::fs::read_dir(&db_root) {
            if entries.next().is_some() {
                populated = true;
            }
        }
        if populated && !force {
            return Err(ImportError::DestinationPopulated);
        }
        if force {
            std::fs::remove_dir_all(&db_root).map_err(|e| ImportError::Io {
                path: db_root.clone(),
                source: e,
            })?;
        }
    }
    std::fs::create_dir_all(&db_root).map_err(|e| ImportError::Io {
        path: db_root.clone(),
        source: e,
    })?;

    let default_cache = data_dir.join(".live-import-cache");
    let cache_root = secondary_cache_dir.unwrap_or(&default_cache);
    if cache_root.exists() {
        // Clear stale per-secondary metadata from any previous attempt.
        std::fs::remove_dir_all(cache_root).map_err(|e| ImportError::Io {
            path: cache_root.to_path_buf(),
            source: e,
        })?;
    }
    std::fs::create_dir_all(cache_root).map_err(|e| ImportError::Io {
        path: cache_root.to_path_buf(),
        source: e,
    })?;

    let mut store_names = Vec::with_capacity(subdirs.len());
    let mut total_bytes = 0u64;
    for subdir in &subdirs {
        let name = subdir
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| ImportError::SnapshotLayout(subdir.clone()))?
            .to_string();
        let dest = db_root.join(&name);
        let secondary_meta = cache_root.join(&name);
        std::fs::create_dir_all(&secondary_meta).map_err(|e| ImportError::Io {
            path: secondary_meta.clone(),
            source: e,
        })?;

        // `market_pair_price_to_order` is written with a custom comparator;
        // both the secondary read handle and the read-write destination must
        // register it or RocksDB refuses the open (MANIFEST name check).
        let comparator = tron_chainbase::comparator_for_store(&name);
        let src = match comparator {
            Some((cmp_name, cmp_fn)) => RocksDbBackend::open_as_secondary_with_comparator(
                subdir,
                &secondary_meta,
                cmp_name,
                cmp_fn,
            ),
            None => RocksDbBackend::open_as_secondary(subdir, &secondary_meta),
        }
        .map_err(|e| ImportError::RocksDb {
            store: name.clone(),
            source: e,
        })?;
        // Refresh the secondary to the primary's latest flushed + WAL'd
        // state BEFORE scanning. Without this the scan copies only the
        // SSTs that existed at open time (stale, and skewed differently
        // per store), which produces a cross-store-inconsistent import:
        // `properties` (head + TOTAL_NET_WEIGHT) ends up at a different
        // height than `account` (frozen balances), and that mismatch
        // permanently biases every bandwidth/fee calculation. It can't
        // make the import perfectly consistent (each store is still an
        // independent DB at its own catch-up point), but it minimises the
        // window — see the consistency caveat in this fn's doc.
        src.try_catch_up_with_primary().map_err(|e| ImportError::RocksDb {
            store: name.clone(),
            source: e,
        })?;
        let dst = match comparator {
            Some((cmp_name, cmp_fn)) => {
                RocksDbBackend::open_with_comparator(&dest, None, cmp_name, cmp_fn)
            }
            None => RocksDbBackend::open(&dest),
        }
        .map_err(|e| ImportError::RocksDb {
            store: name.clone(),
            source: e,
        })?;

        // Stream the secondary's key-space into the destination via the
        // shared chainbase helper — the same batched-write path the
        // standalone `tron-snapshot-convert` uses (its source is LevelDB;
        // ours is this RocksDB secondary). Keeps the two from drifting.
        let mut source = tron_chainbase::RocksDbSource {
            store_name: &name,
            backend: &src,
        };
        let stats = tron_chainbase::stream_source_into_dest(&name, &mut source, &dst)
            .map_err(|e| ImportError::LiveScan {
                store: name.clone(),
                source: Box::new(e),
            })?;

        total_bytes += stats.byte_volume;
        store_names.push(name);
        // Drop both backends here — the secondary releases its file
        // handles, the destination flushes on drop. Important so the
        // next store's `RocksDbBackend::open` doesn't race on
        // process-level locks.
        drop(src);
        drop(dst);
    }

    // Clean up secondary metadata cache — we won't need it again
    // unless the user re-runs.
    let _ = std::fs::remove_dir_all(cache_root);

    // Open the freshly-imported tree to verify + build the report.
    let stores = OpenedStores::open(data_dir)?;
    build_report(&stores, store_names, total_bytes)
}

/// Verify an already-populated `data_dir/db/`. Doesn't move any files;
/// just opens the stores and reads the head pointer + witness count.
pub fn verify_snapshot(data_dir: &Path) -> Result<ImportReport, ImportError> {
    let stores = OpenedStores::open(data_dir)?;
    // Enumerate what's actually on disk for the report.
    let db_root = crate::storage::resolve_db_root(data_dir);
    let mut names: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&db_root) {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    names.push(name.to_string());
                }
            }
        }
    }
    names.sort();
    build_report(&stores, names, 0)
}

fn build_report(
    stores: &OpenedStores,
    store_names: Vec<String>,
    bytes_copied: u64,
) -> Result<ImportReport, ImportError> {
    use tron_chainbase::{DynamicPropertiesStore, WitnessStore};

    let dp = DynamicPropertiesStore::new(stores.dyn_props.clone());
    let head_num = dp.latest_block_header_number().unwrap_or(0);
    let head_hash_hex = dp
        .latest_block_header_hash()
        .ok()
        .flatten()
        .map(hex_encode)
        .unwrap_or_default();
    let solid_num = dp.latest_solidified_block_num().unwrap_or(0);

    let ws = WitnessStore::new(stores.witnesses.clone());
    let witness_count = ws
        .all()
        .map_err(|e| ImportError::Verification(format!("witness scan: {e}")))?
        .len();

    let consistency_warnings = check_cross_store_consistency(stores, head_num);

    Ok(ImportReport {
        stores_imported: store_names.len(),
        bytes_copied,
        head_block_number: head_num,
        head_block_hash_hex: head_hash_hex,
        solidified_block_number: solid_num,
        witness_count,
        stores: store_names,
        consistency_warnings,
    })
}

/// Cheap cross-store consistency probe — catches a snapshot whose stores
/// were captured at *different heights* (a live-node copy without a
/// quiescent flush). Such a snapshot opens and reads fine but silently
/// diverges from consensus the moment the node applies a block on top,
/// because the head pointer (in `properties`) describes one height while
/// the account / block stores hold another.
///
/// We check the head pointer (`properties`) against the block stores,
/// which is robust and O(1):
///   * the block at the head NUMBER (`block_index[head]`) must resolve to
///     the head HASH stored in `properties`, and
///   * that block must actually exist in the block store.
///
/// A mismatch means `properties` is at a different height than
/// `block-index` / `block` — definitive cross-store skew. (It can't prove
/// `account` is consistent too, but in practice the same copy that skews
/// the block stores skews the account store, and this is the cheap,
/// false-positive-free signal.) Returns a human-readable warning per
/// problem found; empty means the head is internally consistent.
/// Public entry for the daemon startup guard — same probe
/// [`check_cross_store_consistency`] runs after an import, exposed so
/// `runtime` can re-check on every boot (an operator may have imported
/// with an older binary, or copied a data dir in by hand).
pub fn startup_consistency_warnings(
    stores: &crate::storage::OpenedStores,
    head_num: i64,
) -> Vec<String> {
    check_cross_store_consistency(stores, head_num)
}

fn check_cross_store_consistency(
    stores: &crate::storage::OpenedStores,
    head_num: i64,
) -> Vec<String> {
    use tron_chainbase::{
        BlockIndexStore, BlockStore, DynamicPropertiesStore,
    };

    let mut warnings = Vec::new();
    if head_num <= 0 {
        return warnings; // pre-genesis / empty snapshot — nothing to cross-check.
    }
    let dp = DynamicPropertiesStore::new(stores.dyn_props.clone());
    let Some(head_hash) = dp.latest_block_header_hash().ok().flatten() else {
        warnings.push(format!(
            "properties says head #{head_num} but carries no head hash (skewed/partial snapshot)"
        ));
        return warnings;
    };
    let head_id = tron_types::BlockId::from_raw(head_hash);

    let index = BlockIndexStore::new(stores.block_index.clone());
    match index.get(head_num) {
        Ok(indexed) if indexed == head_id => {}
        Ok(indexed) => warnings.push(format!(
            "head pointer skew: properties head #{head_num} = {} but block-index[#{head_num}] = {} \
             — the snapshot's stores are at DIFFERENT heights (likely a live-node copy without a \
             quiescent flush); the node will diverge from consensus. Re-import from a consistent \
             snapshot (stop the source node before copying, or use its snapshot export).",
            hex_encode(*head_id.as_bytes()),
            hex_encode(*indexed.as_bytes()),
        )),
        Err(e) => warnings.push(format!(
            "head pointer skew: properties head #{head_num} but block-index[#{head_num}] is \
             unreadable ({e}) — cross-store-inconsistent snapshot; re-import from a consistent source."
        )),
    }

    let block_store = BlockStore::new(stores.blocks.clone());
    if block_store.get(&head_id).is_err() {
        warnings.push(format!(
            "head pointer skew: properties head #{head_num} ({}) is absent from the block store \
             — cross-store-inconsistent snapshot; re-import from a consistent source.",
            hex_encode(*head_id.as_bytes()),
        ));
    }
    warnings
}

/// Recursive `std::fs::copy` walk. Returns the total bytes copied so
/// the report can surface "imported 14.2 GiB in 2m13s".
fn copy_dir_recursive(src: &Path, dest: &Path) -> Result<u64, ImportError> {
    std::fs::create_dir_all(dest).map_err(|e| ImportError::Io {
        path: dest.to_path_buf(),
        source: e,
    })?;
    let mut total: u64 = 0;
    let entries = std::fs::read_dir(src).map_err(|e| ImportError::Io {
        path: src.to_path_buf(),
        source: e,
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| ImportError::Io {
            path: src.to_path_buf(),
            source: e,
        })?;
        let src_path = entry.path();
        let dest_path = dest.join(entry.file_name());
        let ty = entry.file_type().map_err(|e| ImportError::Io {
            path: src_path.clone(),
            source: e,
        })?;
        if ty.is_dir() {
            total += copy_dir_recursive(&src_path, &dest_path)?;
        } else if ty.is_file() {
            total += std::fs::copy(&src_path, &dest_path).map_err(|e| ImportError::Io {
                path: dest_path.clone(),
                source: e,
            })?;
        } else if ty.is_symlink() {
            // Resolve the symlink and copy the target file. We don't
            // re-create the symlink — the snapshot's internal symlinks
            // would point at paths that don't exist in the destination.
            let target = std::fs::read_link(&src_path).map_err(|e| ImportError::Io {
                path: src_path.clone(),
                source: e,
            })?;
            let resolved = if target.is_absolute() {
                target
            } else {
                src.join(target)
            };
            if resolved.is_dir() {
                total += copy_dir_recursive(&resolved, &dest_path)?;
            } else if resolved.is_file() {
                total += std::fs::copy(&resolved, &dest_path).map_err(|e| ImportError::Io {
                    path: dest_path.clone(),
                    source: e,
                })?;
            }
        }
    }
    Ok(total)
}

fn hex_encode(b: [u8; 32]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in &b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        p.push(format!("tron-snap-{label}-{nanos}"));
        p
    }

    fn cleanup(p: &Path) {
        let _ = std::fs::remove_dir_all(p);
    }

    /// Build a `.tar` at `path` from a builder closure.
    fn build_tar(path: &Path, f: impl FnOnce(&mut tar::Builder<std::fs::File>)) {
        let file = std::fs::File::create(path).unwrap();
        let mut b = tar::Builder::new(file);
        f(&mut b);
        b.finish().unwrap();
    }

    /// F-28: a `..` entry must be refused with an explicit error, not
    /// silently skipped, and must not land outside the destination.
    #[test]
    fn extract_archive_rejects_parent_dir_traversal() {
        let dir = temp_dir("evil-dotdot");
        std::fs::create_dir_all(&dir).unwrap();
        let tar_path = dir.join("evil.tar");
        build_tar(&tar_path, |b| {
            let data = b"pwned";
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_entry_type(tar::EntryType::Regular);
            // Write the `..` path straight into the header's name field,
            // bypassing `set_path`'s own `..` guard — i.e. a hand-rolled
            // malicious archive, which is exactly the threat here.
            let name = b"../escape.txt";
            h.as_mut_bytes()[..name.len()].copy_from_slice(name);
            h.set_cksum();
            b.append(&h, &data[..]).unwrap();
        });
        let dest = dir.join("out");
        std::fs::create_dir_all(&dest).unwrap();

        let err = extract_archive(&tar_path, &dest).unwrap_err();
        assert!(matches!(err, ImportError::UnsafeArchiveEntry(_)), "got {err:?}");
        // `dest/../escape.txt` would be `dir/escape.txt` — must not exist.
        assert!(!dir.join("escape.txt").exists());
        cleanup(&dir);
    }

    /// F-28: a symlink entry is the escape primitive (the directory import
    /// that runs next would follow it out of the data dir). Refuse it.
    #[test]
    fn extract_archive_rejects_symlink_entry() {
        let dir = temp_dir("evil-symlink");
        std::fs::create_dir_all(&dir).unwrap();
        let tar_path = dir.join("evil.tar");
        build_tar(&tar_path, |b| {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_size(0);
            h.set_mode(0o777);
            b.append_link(&mut h, "db-link", "/tmp").unwrap();
        });
        let dest = dir.join("out");
        std::fs::create_dir_all(&dest).unwrap();

        let err = extract_archive(&tar_path, &dest).unwrap_err();
        assert!(matches!(err, ImportError::UnsafeArchiveEntry(_)), "got {err:?}");
        assert!(!dest.join("db-link").exists());
        cleanup(&dir);
    }

    /// A normal nested file extracts intact — the guard must not be
    /// overzealous.
    #[test]
    fn extract_archive_accepts_benign_nested_files() {
        let dir = temp_dir("benign-tar");
        std::fs::create_dir_all(&dir).unwrap();
        let tar_path = dir.join("ok.tar");
        build_tar(&tar_path, |b| {
            let mut dh = tar::Header::new_gnu();
            dh.set_entry_type(tar::EntryType::Directory);
            dh.set_size(0);
            dh.set_mode(0o755);
            b.append_data(&mut dh, "properties/", std::io::empty()).unwrap();
            let data = b"properties-data";
            let mut fh = tar::Header::new_gnu();
            fh.set_size(data.len() as u64);
            fh.set_mode(0o644);
            b.append_data(&mut fh, "properties/CURRENT", &data[..]).unwrap();
        });
        let dest = dir.join("out");
        std::fs::create_dir_all(&dest).unwrap();

        extract_archive(&tar_path, &dest).expect("benign archive extracts");
        let extracted = dest.join("properties").join("CURRENT");
        assert!(extracted.is_file());
        assert_eq!(std::fs::read(&extracted).unwrap(), b"properties-data");
        cleanup(&dir);
    }

    /// Build a minimum-viable "snapshot" by running `tron-node init`
    /// against a fresh data dir. Returns the path to the `db/`
    /// directory that's now populated with all the per-store RocksDB
    /// folders + the genesis-init state.
    fn build_minimal_snapshot() -> PathBuf {
        let data = temp_dir("source");
        std::fs::create_dir_all(&data).unwrap();
        let stores = OpenedStores::open(&data).expect("open stores");
        // Apply genesis so the snapshot has a head pointer + 27 SRs.
        use tron_chainbase::DynamicPropertiesStore;
        let dp = DynamicPropertiesStore::new(stores.dyn_props.clone());
        if dp.latest_block_header_number().is_none() {
            // Mirrors runtime::initialize_genesis — minimal version.
            use tron_chainbase::{BlockIndexStore, BlockStore};
            use tron_types::{build_genesis_block, genesis_block_id, mainnet_inputs};
            let inputs = mainnet_inputs();
            let block = build_genesis_block(&inputs);
            let id = genesis_block_id(&inputs);
            BlockStore::new(stores.blocks.clone()).put(&id, &block).unwrap();
            BlockIndexStore::new(stores.block_index.clone()).put(&id).unwrap();
            dp.save_latest_block_header_number(0);
            dp.save_latest_block_header_hash(id.as_bytes());
            // Apply allocations so witness_count > 0.
            let state = stores.to_state_backends();
            tron_executor::apply_genesis_allocations(
                &state,
                inputs.assets,
                tron_types::mainnet_witnesses(),
            ).unwrap();
        }
        // Drop the stores so RocksDB releases its locks before we copy.
        drop(stores);
        // Return the actual store root the node created (now `database/`).
        crate::storage::resolve_db_root(&data)
    }

    /// The cross-store consistency guard must PASS a snapshot whose head
    /// pointer agrees with the block stores, and FLAG one where the head
    /// pointer (properties) is at a different height than block-index —
    /// the signature of a live-node copy captured mid-write.
    #[serial_test::serial(snapshot)]
    #[test]
    fn consistency_check_flags_head_store_skew() {
        use tron_chainbase::{BlockIndexStore, BlockStore, DynamicPropertiesStore};
        use tron_types::{build_genesis_block, genesis_block_id, mainnet_inputs};

        let data = temp_dir("consistency");
        std::fs::create_dir_all(&data).unwrap();
        let stores = OpenedStores::open(&data).expect("open");
        let dp = DynamicPropertiesStore::new(stores.dyn_props.clone());
        let bi = BlockIndexStore::new(stores.block_index.clone());
        let bs = BlockStore::new(stores.blocks.clone());

        // A block id whose encoded height is 7 (first 8 bytes BE).
        let mut raw7 = [0u8; 32];
        raw7[..8].copy_from_slice(&7u64.to_be_bytes());
        raw7[8] = 0xab;
        let id7 = tron_types::BlockId::from_raw(raw7);
        // Store a real block under that id + index it at height 7.
        let inputs = mainnet_inputs();
        let block = build_genesis_block(&inputs);
        let _ = (genesis_block_id(&inputs),); // keep import used
        bs.put(&id7, &block).unwrap();
        bi.put(&id7).unwrap(); // indexes at id7.num() == 7

        // CONSISTENT: properties head #7 == block-index[7] == stored block.
        dp.save_latest_block_header_number(7);
        dp.save_latest_block_header_hash(id7.as_bytes());
        let clean = startup_consistency_warnings(&stores, 7);
        assert!(clean.is_empty(), "consistent snapshot wrongly flagged: {clean:?}");

        // SKEWED: bump the head pointer to #9 but leave block-index/block
        // at #7 — exactly what a mid-write live copy produces.
        dp.save_latest_block_header_number(9);
        let skewed = startup_consistency_warnings(&stores, 9);
        assert!(
            !skewed.is_empty(),
            "head-store skew not detected (head #9 but block-index has no #9)"
        );
        assert!(
            skewed.iter().any(|w| w.contains("skew") || w.contains("DIFFERENT heights") || w.contains("unreadable")),
            "warning lacks a skew explanation: {skewed:?}"
        );

        drop(stores);
        cleanup(&data);
    }

    #[serial_test::serial(snapshot)]
    #[test]
    fn import_copy_round_trips_head_pointer_and_witnesses() {
        let snap_db = build_minimal_snapshot();
        let dest = temp_dir("dest");

        let report =
            import_from_directory(&snap_db, &dest, ImportMode::Copy, false).expect("import");

        assert!(report.stores_imported >= 20, "imported {}", report.stores_imported);
        assert_eq!(report.head_block_number, 0);
        assert_eq!(report.head_block_hash_hex.len(), 64);
        // mainnet_witnesses() seeds 27 SRs at genesis.
        assert_eq!(report.witness_count, 27);

        cleanup(snap_db.parent().unwrap());
        cleanup(&dest);
    }

    /// A java-tron data dir copied straight from a node carries a redo
    /// log (`tmp` V1 checkpoint) of its most-recent flush batch. Import
    /// must replay that batch into the planted stores — exactly as
    /// java's startup `recover` and its LiteFullNode tool do — or the
    /// base sits a flush behind the head pointer. Verify the replay
    /// lands the row and removes the merged checkpoint afterwards.
    #[serial_test::serial(snapshot)]
    #[test]
    fn import_replays_java_tmp_checkpoint_into_stores() {
        use tron_chainbase::{KvBackend, RocksDbBackend};

        let snap_db = build_minimal_snapshot();

        // Plant a java-format V1 checkpoint (`tmp`) inside the snapshot's
        // database dir with one PUT for the `account` store and one for
        // the skippable `trans-cache` store. Key envelope is
        // `[4-byte BE name length][db_name][real key]`; value is
        // `[operator byte][payload]` with operator 3 = java PUT.
        let simple_encode = |name: &str| -> Vec<u8> {
            let b = name.as_bytes();
            let mut r = (b.len() as u32).to_be_bytes().to_vec();
            r.extend_from_slice(b);
            r
        };
        let cp_key = |db: &str, key: &[u8]| -> Vec<u8> {
            let mut k = simple_encode(db);
            k.extend_from_slice(key);
            k
        };
        let put_val = |payload: &[u8]| -> Vec<u8> {
            let mut v = vec![3u8];
            v.extend_from_slice(payload);
            v
        };
        let mut acct_addr = [0u8; 21];
        acct_addr[0] = 0x41;
        acct_addr[20] = 0x7c;
        {
            let tmp = snap_db.join("tmp");
            std::fs::create_dir_all(&tmp).unwrap();
            let cp = RocksDbBackend::open(&tmp).unwrap();
            cp.put(&cp_key("account", &acct_addr), &put_val(b"checkpoint-account-row"))
                .unwrap();
            cp.put(&cp_key("trans-cache", b"txid"), &put_val(b"ignored"))
                .unwrap();
        }

        let dest = temp_dir("dest-java-cp");
        import_from_directory(&snap_db, &dest, ImportMode::Copy, false).expect("import");

        // The account row from the checkpoint must be present in the
        // imported account store.
        let stores = OpenedStores::open(&dest).expect("open imported");
        assert_eq!(
            stores.accounts.get(&acct_addr).unwrap().as_deref(),
            Some(b"checkpoint-account-row".as_ref()),
            "java checkpoint account row was not merged on import"
        );
        // The merged checkpoint store must be gone so a re-import does
        // not re-detect it.
        drop(stores);
        assert!(
            !crate::storage::resolve_db_root(&dest).join("tmp").exists(),
            "merged java tmp checkpoint should be removed after import"
        );

        cleanup(snap_db.parent().unwrap());
        cleanup(&dest);
    }

    #[serial_test::serial(snapshot)]
    #[test]
    fn import_into_populated_dir_without_force_errors() {
        let snap_db = build_minimal_snapshot();
        let dest = temp_dir("dest-populated");
        // First import succeeds.
        import_from_directory(&snap_db, &dest, ImportMode::Copy, false).unwrap();
        // Second import without --force is rejected.
        let err =
            import_from_directory(&snap_db, &dest, ImportMode::Copy, false).unwrap_err();
        assert!(matches!(err, ImportError::DestinationPopulated));

        cleanup(snap_db.parent().unwrap());
        cleanup(&dest);
    }

    #[serial_test::serial(snapshot)]
    #[test]
    fn import_with_force_replaces_existing_data() {
        let snap_db = build_minimal_snapshot();
        let dest = temp_dir("dest-force");
        import_from_directory(&snap_db, &dest, ImportMode::Copy, false).unwrap();
        // Force re-import.
        let report =
            import_from_directory(&snap_db, &dest, ImportMode::Copy, true).expect("force");
        assert!(report.stores_imported >= 20);

        cleanup(snap_db.parent().unwrap());
        cleanup(&dest);
    }

    #[serial_test::serial(snapshot)]
    #[test]
    fn import_from_nonexistent_source_errors_cleanly() {
        let dest = temp_dir("dest-no-src");
        let err = import_from_directory(
            Path::new("/nonexistent-source-9999"),
            &dest,
            ImportMode::Copy,
            false,
        )
        .unwrap_err();
        assert!(matches!(err, ImportError::SourceMissing(_)));
    }

    #[serial_test::serial(snapshot)]
    #[test]
    fn import_from_empty_source_errors() {
        let empty = temp_dir("dest-empty-src");
        std::fs::create_dir_all(&empty).unwrap();
        let dest = temp_dir("dest-empty-out");
        let err = import_from_directory(&empty, &dest, ImportMode::Copy, false).unwrap_err();
        assert!(matches!(err, ImportError::SourceEmpty));
        cleanup(&empty);
    }

    #[serial_test::serial(snapshot)]
    #[test]
    fn verify_returns_same_report_shape() {
        let snap_db = build_minimal_snapshot();
        let dest = temp_dir("dest-verify");
        import_from_directory(&snap_db, &dest, ImportMode::Copy, false).unwrap();
        let report = verify_snapshot(&dest).expect("verify");
        assert_eq!(report.witness_count, 27);
        assert_eq!(report.head_block_number, 0);

        cleanup(snap_db.parent().unwrap());
        cleanup(&dest);
    }

    #[serial_test::serial(snapshot)]
    #[test]
    fn import_mode_from_str_accepts_documented_forms() {
        assert_eq!(ImportMode::from_str("copy"), Some(ImportMode::Copy));
        assert_eq!(ImportMode::from_str("move"), Some(ImportMode::Move));
        assert_eq!(ImportMode::from_str("symlink"), Some(ImportMode::Symlink));
        assert_eq!(ImportMode::from_str("link"), Some(ImportMode::Symlink));
        assert_eq!(ImportMode::from_str("bogus"), None);
    }

    /// Walk `dir` into an existing `tar::Builder`, packing every file
    /// + dir relative to `dir`. Used by the tarball-round-trip test.
    fn tar_dir<W: std::io::Write>(
        builder: &mut tar::Builder<W>,
        dir: &Path,
        prefix: &str,
    ) -> std::io::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name();
            let archive_path = if prefix.is_empty() {
                name.to_string_lossy().to_string()
            } else {
                format!("{prefix}/{}", name.to_string_lossy())
            };
            if path.is_dir() {
                tar_dir(builder, &path, &archive_path)?;
            } else if path.is_file() {
                let mut f = std::fs::File::open(&path)?;
                builder.append_file(&archive_path, &mut f)?;
            }
        }
        Ok(())
    }

    #[serial_test::serial(snapshot)]
    #[test]
    fn import_from_tar_gz_extracts_and_round_trips() {
        let snap_db = build_minimal_snapshot();
        // Build a .tar.gz of the snapshot db dir.
        let tarball_path = std::env::temp_dir()
            .join(format!("tron-snap-tarball-{}.tar.gz", std::process::id()));
        {
            let f = std::fs::File::create(&tarball_path).unwrap();
            let enc = flate2::write::GzEncoder::new(f, flate2::Compression::default());
            let mut builder = tar::Builder::new(enc);
            tar_dir(&mut builder, &snap_db, "").unwrap();
            builder.finish().unwrap();
        }

        let dest = temp_dir("dest-tar");
        let report =
            import_snapshot(&tarball_path, &dest, ImportMode::Copy, false).expect("import .tar.gz");

        assert_eq!(report.witness_count, 27);
        assert_eq!(report.head_block_number, 0);
        // Temp extract dir was cleaned up.
        assert!(!dest.join(".snapshot-extract").exists());

        let _ = std::fs::remove_file(&tarball_path);
        cleanup(snap_db.parent().unwrap());
        cleanup(&dest);
    }

    #[serial_test::serial(snapshot)]
    #[test]
    fn import_snapshot_directory_dispatch_works() {
        // Sanity check: passing a directory to import_snapshot is
        // identical to calling import_from_directory.
        let snap_db = build_minimal_snapshot();
        let dest = temp_dir("dest-dispatch");
        let report =
            import_snapshot(&snap_db, &dest, ImportMode::Copy, false).expect("import");
        assert_eq!(report.witness_count, 27);
        cleanup(snap_db.parent().unwrap());
        cleanup(&dest);
    }

    #[serial_test::serial(snapshot)]
    #[test]
    fn import_snapshot_rejects_unknown_extension() {
        let bogus = std::env::temp_dir().join(format!(
            "tron-snap-bogus-{}.zip",
            std::process::id()
        ));
        std::fs::write(&bogus, b"not a tarball").unwrap();
        let dest = temp_dir("dest-bogus");
        let err =
            import_snapshot(&bogus, &dest, ImportMode::Copy, false).unwrap_err();
        assert!(matches!(err, ImportError::UnsupportedArchive(_)), "got {err:?}");
        let _ = std::fs::remove_file(&bogus);
    }

    #[serial_test::serial(snapshot)]
    #[test]
    fn import_live_round_trips_head_pointer_and_witnesses() {
        // Setup: build a minimal snapshot, then leave the source
        // intact (don't `drop` and remove). `import_live` opens it as
        // a RocksDB secondary — that works whether the primary is
        // currently open or not. Here we test the not-currently-open
        // case (simpler to set up than racing a live writer).
        let snap_db = build_minimal_snapshot();
        let dest = temp_dir("dest-live");
        let report =
            import_live(&snap_db, &dest, None, false).expect("live import");
        assert!(report.stores_imported > 0);
        assert_eq!(report.witness_count, 27);
        assert!(
            report.bytes_copied > 0,
            "should have streamed at least the witness rows"
        );
        // Secondary cache should be cleaned up.
        assert!(
            !dest.join(".live-import-cache").exists(),
            "secondary cache should be cleaned up on success"
        );
        cleanup(snap_db.parent().unwrap());
        cleanup(&dest);
    }

    #[serial_test::serial(snapshot)]
    #[test]
    fn import_live_rejects_populated_destination_without_force() {
        let snap_db = build_minimal_snapshot();
        let dest = temp_dir("dest-live-conflict");
        // Plant something at the destination first.
        let import1 = import_live(&snap_db, &dest, None, false).expect("first import");
        assert!(import1.stores_imported > 0);
        // Second import without --force must refuse.
        let err = import_live(&snap_db, &dest, None, false).unwrap_err();
        assert!(
            matches!(err, ImportError::DestinationPopulated),
            "got {err:?}"
        );
        // With --force it succeeds.
        let import2 =
            import_live(&snap_db, &dest, None, true).expect("forced import");
        assert!(import2.stores_imported > 0);
        cleanup(snap_db.parent().unwrap());
        cleanup(&dest);
    }

    #[serial_test::serial(snapshot)]
    #[test]
    fn import_live_uses_explicit_secondary_cache_when_provided() {
        let snap_db = build_minimal_snapshot();
        let dest = temp_dir("dest-live-cache");
        let cache = temp_dir("live-secondary-scratch");
        let _ = import_live(&snap_db, &dest, Some(&cache), false).expect("live import");
        // On success the cache should be cleaned up regardless of
        // whether it was caller-specified or default.
        assert!(
            !cache.exists(),
            "explicit secondary cache should also be cleaned up"
        );
        cleanup(snap_db.parent().unwrap());
        cleanup(&dest);
    }

    #[serial_test::serial(snapshot)]
    #[test]
    fn import_live_rejects_missing_source() {
        let phantom = std::env::temp_dir().join(format!(
            "tron-snap-phantom-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let dest = temp_dir("dest-live-missing");
        let err = import_live(&phantom, &dest, None, false).unwrap_err();
        assert!(matches!(err, ImportError::SourceMissing(_)), "got {err:?}");
    }
}
