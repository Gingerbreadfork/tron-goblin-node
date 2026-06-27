//! Per-store convert-and-delete orchestration.
//!
//! Two inputs, one inner loop:
//!
//! * **Directory** (`--from DIR`): a directory of per-store LevelDB
//!   sub-dirs. For each store: open the LevelDB, stream every KV into the
//!   destination RocksDB store, fsync, mark it done, then `rm -rf` the
//!   source store (unless `--keep-source`). Deleting the source as we go
//!   keeps peak disk near 1x — the only high-water mark is the single
//!   largest store (`block`, TB-scale), which is accepted.
//!
//! * **Stream** (`--stream`): a `tar` (optionally gzip) read from stdin,
//!   so a downloaded snapshot pipes straight in and the *source* never
//!   lands on disk as a whole. Entries are grouped by their top-level
//!   directory; when one store's entries finish (the top-level name
//!   changes, or the stream ends) that store — staged in a temp dir — is
//!   converted and the temp store removed before the next begins. Peak
//!   disk ≈ one store's files + its converted output.
//!
//! Either way the destination is `data_dir/database/<store>` (java-tron's
//! layout, which this node opens in place) and resume is per-store via the
//! [`crate::manifest`] done-marker.

use std::io::Read;
use std::path::{Path, PathBuf};

use tron_chainbase::{
    open_dest_store, stream_source_into_dest, verify_dest_store, StreamStats, NODE_STORE_NAMES,
};

use crate::leveldb_source::{looks_like_leveldb_store, LevelDbSource};
use crate::manifest::{is_store_done, mark_store_done};

/// java-tron's RocksDB stores directory name. The node opens
/// `data_dir/database/<store>`, so the converter writes there.
const DB_DIR: &str = "database";

/// Checkpoint/​auxiliary directory names that are not stand-alone stores to
/// convert at the top level. `checkpoint` (V2) holds per-store sub-DBs that
/// java's own converter descends into; this node merges any java checkpoint
/// on import rather than carrying it, so we skip it. `tmp` is the V1
/// checkpoint redo log — likewise merged on import, not a store.
const SKIP_TOP_LEVEL: &[&str] = &["checkpoint", "tmp"];

#[derive(Debug, thiserror::Error)]
pub enum ConvertError {
    #[error("source does not exist: {0}")]
    SourceMissing(PathBuf),
    #[error("source is not a directory: {0}")]
    SourceNotDir(PathBuf),
    #[error("source has no per-store subdirectories")]
    SourceEmpty,
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("leveldb: {0}")]
    LevelDb(#[from] crate::leveldb_source::LevelDbError),
    #[error("convert/stream (store {store}): {source}")]
    Stream {
        store: String,
        #[source]
        source: tron_chainbase::ConvertError,
    },
    #[error("open destination store {store}: {source}")]
    OpenDest {
        store: String,
        #[source]
        source: tron_chainbase::RocksDbError,
    },
    #[error("flush destination store {store}: {source}")]
    FlushDest {
        store: String,
        #[source]
        source: tron_chainbase::RocksDbError,
    },
    #[error("done-marker (store {store}): {source}")]
    Manifest {
        store: String,
        #[source]
        source: crate::manifest::ManifestError,
    },
    #[error("refusing unsafe tar entry (absolute path, `..`, or link): {0}")]
    UnsafeTarEntry(String),
    #[error("tar stream error: {0}")]
    Tar(#[source] std::io::Error),
    #[error(
        "non-contiguous tar: store {store} re-appears after it was already \
         converted; use --from for a non-contiguous archive"
    )]
    NonContiguousTar { store: String },
}

/// Options controlling a conversion run.
#[derive(Debug, Clone)]
pub struct ConvertOptions {
    /// Destination node data dir; stores land in `data_dir/database/`.
    pub data_dir: PathBuf,
    /// Compress destination SSTs with Zstd (vs Snappy). Default FALSE
    /// (Snappy) — java-tron's snapshot format, the most portable choice.
    /// `--zstd` opts into ~30% smaller output; the node reads it natively
    /// (it links the Zstd codec).
    pub compression_zstd: bool,
    /// Keep (don't delete) each source store after converting it. Only
    /// meaningful for directory input; a `--stream` source is never on
    /// disk to keep.
    pub keep_source: bool,
}

impl Default for ConvertOptions {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./tron-data"),
            compression_zstd: false,
            keep_source: false,
        }
    }
}

/// What a single store's conversion produced — surfaced for the per-store
/// progress line and the final summary.
#[derive(Debug, Clone)]
pub struct StoreOutcome {
    pub store: String,
    pub stats: StreamStats,
    /// True if the store was skipped because its done-marker was already
    /// present (a resumed run).
    pub skipped_resume: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ConvertReport {
    pub stores: Vec<StoreOutcome>,
}

impl ConvertReport {
    pub fn total_keys(&self) -> u64 {
        self.stores.iter().map(|s| s.stats.key_count).sum()
    }
    pub fn total_bytes(&self) -> u64 {
        self.stores.iter().map(|s| s.stats.byte_volume).sum()
    }
    pub fn converted_count(&self) -> usize {
        self.stores.iter().filter(|s| !s.skipped_resume).count()
    }
    pub fn skipped_count(&self) -> usize {
        self.stores.iter().filter(|s| s.skipped_resume).count()
    }
}

/// Resolve the destination store directory `data_dir/database/<store>`.
fn dest_store_dir(data_dir: &Path, store: &str) -> PathBuf {
    data_dir.join(DB_DIR).join(store)
}

/// Convert a single store whose LevelDB lives at `src_store_dir` into the
/// destination, with resume + integrity verification. Does NOT delete the
/// source — the caller decides that (so the `--stream` path, which deletes
/// a temp staging dir, and the directory path, which deletes the real
/// source, share this).
///
/// Returns `Ok(None)` when the store was skipped (done-marker already
/// present); `Ok(Some(stats))` after a fresh conversion.
fn convert_one_store(
    src_store_dir: &Path,
    store: &str,
    opts: &ConvertOptions,
    progress: &mut dyn FnMut(&str),
) -> Result<Option<StreamStats>, ConvertError> {
    let dest = dest_store_dir(&opts.data_dir, store);

    if is_store_done(&dest).map_err(|source| ConvertError::Manifest {
        store: store.to_string(),
        source,
    })? {
        progress(&format!("  {store}: already done, skipping"));
        return Ok(None);
    }

    // A stale partial destination from a prior crashed attempt (no marker)
    // must be cleared so the fresh write starts from empty — otherwise its
    // leftover rows would corrupt the integrity count.
    if dest.exists() {
        std::fs::remove_dir_all(&dest).map_err(|source| ConvertError::Io {
            path: dest.clone(),
            source,
        })?;
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|source| ConvertError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let mut source = LevelDbSource::open(src_store_dir, store)?;
    let dst = open_dest_store(&dest, store, opts.compression_zstd).map_err(|source| {
        ConvertError::OpenDest {
            store: store.to_string(),
            source,
        }
    })?;

    let stats =
        stream_source_into_dest(store, &mut source, &dst).map_err(|source| ConvertError::Stream {
            store: store.to_string(),
            source,
        })?;
    // Release the LevelDB read handles before we (maybe) delete the source.
    drop(source);

    // Durability barrier: flush memtables + fsync WAL so the destination is
    // crash-safe BEFORE we mark it done and delete the source.
    dst.flush_and_sync().map_err(|source| ConvertError::FlushDest {
        store: store.to_string(),
        source,
    })?;
    // Integrity: re-scan the destination and confirm the count + byte sums
    // match what we wrote (java-tron's `DbConvert.check` triple).
    verify_dest_store(store, &dst, stats).map_err(|source| ConvertError::Stream {
        store: store.to_string(),
        source,
    })?;
    drop(dst);

    mark_store_done(&dest).map_err(|source| ConvertError::Manifest {
        store: store.to_string(),
        source,
    })?;

    progress(&format!(
        "  {store}: {} keys, {} bytes -> {}",
        stats.key_count,
        stats.byte_volume,
        dest.display()
    ));
    Ok(Some(stats))
}

/// Convert from an on-disk directory of per-store LevelDB sub-dirs,
/// deleting each source store after a successful, fsynced, marked
/// conversion (unless `keep_source`).
///
/// Peak disk: the source store is removed before the next one opens, so at
/// any moment only one source store coexists with the growing destination
/// plus whatever is already converted. When `from` and `data_dir` share a
/// filesystem (the common in-place case) total usage therefore stays near
/// 1× — its high-water mark is the single largest store (`block`,
/// TB-scale), which is unavoidable. Across two filesystems the source-FS
/// and dest-FS each see their own peak, which is still bounded the same way
/// per side.
pub fn convert_from_directory(
    from: &Path,
    opts: &ConvertOptions,
    progress: &mut dyn FnMut(&str),
) -> Result<ConvertReport, ConvertError> {
    if !from.exists() {
        return Err(ConvertError::SourceMissing(from.to_path_buf()));
    }
    if !from.is_dir() {
        return Err(ConvertError::SourceNotDir(from.to_path_buf()));
    }

    // Enumerate candidate store sub-dirs (sorted for deterministic order;
    // `block` — the big one — sorts early, but order doesn't affect peak
    // disk since each store is deleted before the next opens).
    let mut subdirs: Vec<PathBuf> = std::fs::read_dir(from)
        .map_err(|source| ConvertError::Io {
            path: from.to_path_buf(),
            source,
        })?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    subdirs.sort();
    if subdirs.is_empty() {
        return Err(ConvertError::SourceEmpty);
    }

    // Completeness warning (M1): a snapshot missing a required store would
    // convert "successfully" and — because each source store is deleted as it
    // converts — leave the operator with an incomplete, possibly-unopenable
    // node DB and no source to retry. Check up front, before any conversion or
    // deletion, and warn loudly so they can abort if a store is unexpectedly
    // absent.
    {
        let present: std::collections::HashSet<&str> = subdirs
            .iter()
            .filter_map(|p| p.file_name().and_then(|n| n.to_str()))
            .collect();
        let missing: Vec<&str> = NODE_STORE_NAMES
            .iter()
            .copied()
            .filter(|s| !present.contains(s))
            .collect();
        if !missing.is_empty() {
            eprintln!(
                "WARNING: source is missing {} expected store(s): {}.\n  \
                 The converted snapshot may be INCOMPLETE and the node could refuse \
                 to open it. Sources are deleted as they convert — abort now \
                 (Ctrl-C) if this is unexpected.",
                missing.len(),
                missing.join(", ")
            );
        }
    }

    let mut report = ConvertReport::default();
    for src in &subdirs {
        let Some(store) = src.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if SKIP_TOP_LEVEL.contains(&store) {
            progress(&format!("  {store}: auxiliary/checkpoint dir, skipping"));
            continue;
        }
        if !looks_like_leveldb_store(src) {
            progress(&format!("  {store}: not a store dir (no CURRENT), skipping"));
            continue;
        }

        match convert_one_store(src, store, opts, progress)? {
            Some(stats) => {
                if !opts.keep_source {
                    std::fs::remove_dir_all(src).map_err(|source| ConvertError::Io {
                        path: src.clone(),
                        source,
                    })?;
                }
                report.stores.push(StoreOutcome {
                    store: store.to_string(),
                    stats,
                    skipped_resume: false,
                });
            }
            None => {
                // Already done on a prior run. If the source still exists
                // and we're deleting, clean it up now so a re-run is
                // idempotent and reclaims the space.
                if !opts.keep_source && src.exists() {
                    let _ = std::fs::remove_dir_all(src);
                }
                report.stores.push(StoreOutcome {
                    store: store.to_string(),
                    stats: StreamStats::default(),
                    skipped_resume: true,
                });
            }
        }
    }
    Ok(report)
}

/// Convert from a `tar` stream on `reader` (optionally gzip-wrapped),
/// staging one store at a time to a temp dir so the whole source never
/// lands on disk. The temp staging area defaults to
/// `data_dir/.snapshot-convert-stage/`.
pub fn convert_from_stream<R: Read>(
    reader: R,
    gzip: bool,
    opts: &ConvertOptions,
    progress: &mut dyn FnMut(&str),
) -> Result<ConvertReport, ConvertError> {
    let stage_root = opts.data_dir.join(".snapshot-convert-stage");
    if stage_root.exists() {
        std::fs::remove_dir_all(&stage_root).map_err(|source| ConvertError::Io {
            path: stage_root.clone(),
            source,
        })?;
    }
    std::fs::create_dir_all(&stage_root).map_err(|source| ConvertError::Io {
        path: stage_root.clone(),
        source,
    })?;

    let result = if gzip {
        let dec = flate2::read::GzDecoder::new(reader);
        stream_tar(tar::Archive::new(dec), &stage_root, opts, progress)
    } else {
        stream_tar(tar::Archive::new(reader), &stage_root, opts, progress)
    };
    let _ = std::fs::remove_dir_all(&stage_root);
    result
}

/// Core tar streaming: extract entries to a per-store staging dir,
/// converting (and removing) a staged store as soon as its entries end —
/// detected by the top-level directory name changing, or by end-of-stream.
/// This keeps only ~one store's files on disk at a time (plus its
/// converted output), which is the whole point of `--stream`.
///
/// Assumes the conventional tar layout where each directory's entries are
/// written contiguously (`tar c account/ block/ …`, and every snapshot
/// tarball we target). If a store's entries were interleaved with another
/// store's, the store would be flushed at the first boundary and a later
/// re-appearance would be skipped via its done-marker — so prefer `--from`
/// for a non-contiguous archive. Path traversal and link entries are
/// rejected outright (snapshot tars are just store data dirs).
fn stream_tar<R: Read>(
    mut archive: tar::Archive<R>,
    stage_root: &Path,
    opts: &ConvertOptions,
    progress: &mut dyn FnMut(&str),
) -> Result<ConvertReport, ConvertError> {
    use std::path::Component;

    let mut report = ConvertReport::default();
    // The top-level dir currently being staged, and whether the stream
    // wraps stores one level deeper (root `database/` or `output-directory/`).
    let mut current_store: Option<String> = None;
    let mut wrap_prefix: Option<String> = None;
    // Stores already flushed/converted — used to detect a non-contiguous tar
    // (a store's entries split around another store's), which would otherwise
    // silently drop the re-appearing entries via the done-marker skip (M2).
    let mut flushed: std::collections::HashSet<String> = std::collections::HashSet::new();

    let entries = archive.entries().map_err(ConvertError::Tar)?;
    for entry in entries {
        let mut entry = entry.map_err(ConvertError::Tar)?;
        let raw_path = entry.path().map_err(ConvertError::Tar)?.into_owned();

        // Reject path traversal / links outright (snapshot tars are just
        // store data dirs).
        if raw_path.components().any(|c| {
            matches!(
                c,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        }) {
            return Err(ConvertError::UnsafeTarEntry(raw_path.display().to_string()));
        }
        let etype = entry.header().entry_type();
        if etype.is_symlink() || etype.is_hard_link() {
            return Err(ConvertError::UnsafeTarEntry(raw_path.display().to_string()));
        }

        // Determine the store this entry belongs to. Strip an optional
        // single wrapping dir (`database/` or `output-directory/database/`)
        // so `database/account/CURRENT` maps to store `account`.
        let Some((store, rel)) = classify_entry(&raw_path, &mut wrap_prefix) else {
            // Top-level file (e.g. a stray `engine.properties` at root) —
            // nothing to stage.
            continue;
        };
        if SKIP_TOP_LEVEL.contains(&store.as_str()) {
            continue;
        }

        // Store boundary: the staged store changed. Convert the one we just
        // finished staging before starting the new one.
        if current_store.as_deref() != Some(store.as_str()) {
            if let Some(done) = current_store.take() {
                flush_staged_store(stage_root, &done, opts, &mut report, progress)?;
                flushed.insert(done);
            }
            // A store re-appearing after it was already converted means the tar
            // is non-contiguous; its later entries would be silently dropped
            // (the store's done-marker skips the re-convert). Refuse instead.
            if flushed.contains(&store) {
                return Err(ConvertError::NonContiguousTar { store });
            }
            current_store = Some(store.clone());
        }

        // Unpack this entry under stage_root/<store>/<rel>.
        let out_dir = stage_root.join(&store);
        unpack_entry(&mut entry, &out_dir, &rel)?;
    }

    // Flush the final staged store.
    if let Some(done) = current_store.take() {
        flush_staged_store(stage_root, &done, opts, &mut report, progress)?;
    }

    if report.stores.is_empty() {
        return Err(ConvertError::SourceEmpty);
    }
    Ok(report)
}

/// Map a tar entry path to `(store_name, path_relative_to_store)`,
/// transparently stripping a single wrapping directory (`database/` or a
/// two-level `output-directory/database/`). Returns `None` for a path that
/// isn't inside a store dir (a bare top-level file).
fn classify_entry(path: &Path, wrap_prefix: &mut Option<String>) -> Option<(String, PathBuf)> {
    let comps: Vec<String> = path
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => s.to_str().map(|s| s.to_string()),
            _ => None,
        })
        .collect();

    // Detect / apply a wrapping prefix. We treat a top-level dir literally
    // named `database` as a wrapper. (`output-directory/database/...` ends
    // up as comps = [output-directory, database, store, ...]; we strip up
    // to and including the LAST `database`.)
    let mut idx = 0;
    if let Some(pos) = comps.iter().rposition(|c| c == "database") {
        // Everything up to and including `database` is the wrapper.
        idx = pos + 1;
        *wrap_prefix = Some(comps[..idx].join("/"));
    } else if let Some(prefix) = wrap_prefix.as_ref() {
        // A previously-detected wrapper; strip the same number of comps if
        // they match.
        let pcomps: Vec<&str> = prefix.split('/').collect();
        if comps.len() >= pcomps.len() && comps[..pcomps.len()] == pcomps[..] {
            idx = pcomps.len();
        }
    }

    let rest = &comps[idx..];
    // First remaining component is the store name; the rest is the path
    // inside the store (empty when the entry is the store dir itself).
    rest.split_first()
        .map(|(store, tail)| (store.clone(), tail.iter().collect()))
}

/// Unpack a single tar entry to `out_dir/rel`, creating parent dirs. Only
/// regular files and directories reach here (links rejected upstream).
fn unpack_entry<R: Read>(
    entry: &mut tar::Entry<R>,
    out_dir: &Path,
    rel: &Path,
) -> Result<(), ConvertError> {
    let etype = entry.header().entry_type();
    if etype.is_dir() || rel.as_os_str().is_empty() {
        let target = if rel.as_os_str().is_empty() {
            out_dir.to_path_buf()
        } else {
            out_dir.join(rel)
        };
        std::fs::create_dir_all(&target).map_err(|source| ConvertError::Io {
            path: target,
            source,
        })?;
        return Ok(());
    }
    let target = out_dir.join(rel);
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).map_err(|source| ConvertError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let mut out = std::fs::File::create(&target).map_err(|source| ConvertError::Io {
        path: target.clone(),
        source,
    })?;
    std::io::copy(entry, &mut out).map_err(ConvertError::Tar)?;
    Ok(())
}

/// Convert a fully-staged store from `stage_root/<store>` and remove the
/// staged copy (always — it's our temp dir, not the user's source).
fn flush_staged_store(
    stage_root: &Path,
    store: &str,
    opts: &ConvertOptions,
    report: &mut ConvertReport,
    progress: &mut dyn FnMut(&str),
) -> Result<(), ConvertError> {
    let staged = stage_root.join(store);
    if !looks_like_leveldb_store(&staged) {
        progress(&format!("  {store}: staged dir is not a store, skipping"));
        let _ = std::fs::remove_dir_all(&staged);
        return Ok(());
    }
    let outcome = convert_one_store(&staged, store, opts, progress)?;
    // The staged copy is always removed (it's our temp area).
    let _ = std::fs::remove_dir_all(&staged);
    match outcome {
        Some(stats) => report.stores.push(StoreOutcome {
            store: store.to_string(),
            stats,
            skipped_resume: false,
        }),
        None => report.stores.push(StoreOutcome {
            store: store.to_string(),
            stats: StreamStats::default(),
            skipped_resume: true,
        }),
    }
    Ok(())
}
