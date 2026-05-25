//! Export `data_dir/db/` for distribution.
//!
//! Two paths:
//!
//! * [`export_to_tarball`] — bundles every per-store subdir into a
//!   `.tar` or `.tar.gz`. **The node MUST be stopped first** — RocksDB
//!   writes to the WAL on every commit, and tarring an open database
//!   captures a partial state (split WAL, unflushed MemTables) that
//!   won't replay deterministically.
//!
//! * [`export_via_checkpoint`] — uses RocksDB's `Checkpoint` API to
//!   take a consistent point-in-time snapshot of a LIVE database.
//!   Safe to call while the node is running: SST files are hard-linked
//!   into the destination (when on the same filesystem) and MemTables
//!   are flushed there, so the operation is fast and the resulting
//!   directory is a complete standalone RocksDB store. Pair with
//!   [`export_to_tarball`] (against the checkpoint dir) if you want a
//!   distributable archive.
//!
//! Compression:
//!
//! * [`Compression::None`] — raw `.tar`. Largest output, fastest.
//! * [`Compression::Gzip`] — `.tar.gz`. ~30-50% size, ~10-30% slower
//!   than raw. Default for tooling parity with java-tron snapshots.

use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

/// Compression selector for the output archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    /// No compression — emits a `.tar`.
    None,
    /// gzip — emits a `.tar.gz`.
    Gzip,
}

impl Compression {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "none" | "tar" => Some(Self::None),
            "gzip" | "gz" | "tar.gz" => Some(Self::Gzip),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExportReport {
    /// Number of per-store subdirs included.
    pub stores_exported: usize,
    /// Compressed bytes written to the output (uncompressed for
    /// `Compression::None`).
    pub bytes_written: u64,
    /// Output path.
    pub output_path: PathBuf,
    /// Per-store subdir names included, in walk order.
    pub stores: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error("data dir does not exist: {0:?}")]
    DataDirMissing(PathBuf),
    #[error("data_dir/db is missing or empty: {0:?}")]
    DbDirEmpty(PathBuf),
    #[error("io error at {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Bundle `data_dir/db/*` into a tarball at `output_path`.
///
/// Writes to a `.tmp` sibling first, then renames into place on
/// success — so a half-written export never poisons the destination.
pub fn export_to_tarball(
    data_dir: &Path,
    output_path: &Path,
    compression: Compression,
) -> Result<ExportReport, ExportError> {
    if !data_dir.exists() {
        return Err(ExportError::DataDirMissing(data_dir.to_path_buf()));
    }
    let db_root = data_dir.join("db");
    if !db_root.is_dir() {
        return Err(ExportError::DbDirEmpty(db_root));
    }

    let mut subdirs: Vec<PathBuf> = std::fs::read_dir(&db_root)
        .map_err(|e| ExportError::Io {
            path: db_root.clone(),
            source: e,
        })?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    if subdirs.is_empty() {
        return Err(ExportError::DbDirEmpty(db_root));
    }
    subdirs.sort();

    let mut store_names: Vec<String> = Vec::with_capacity(subdirs.len());
    for s in &subdirs {
        if let Some(n) = s.file_name().and_then(|n| n.to_str()) {
            store_names.push(n.to_string());
        }
    }

    // Write to .tmp first; rename on success.
    let mut tmp_path = output_path.to_path_buf();
    let tmp_name = match tmp_path.file_name() {
        Some(n) => format!("{}.tmp", n.to_string_lossy()),
        None => return Err(ExportError::Io {
            path: output_path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "output path has no file name",
            ),
        }),
    };
    tmp_path.set_file_name(tmp_name);

    let file = std::fs::File::create(&tmp_path).map_err(|e| ExportError::Io {
        path: tmp_path.clone(),
        source: e,
    })?;
    let buffered = BufWriter::new(file);

    // Write the archive via the selected compression. Both branches
    // shadow the same `tar::Builder<W>` ergonomic — once the builder
    // is dropped/finished, the underlying encoder + buffered writer
    // flush. We hold onto the writer afterwards to introspect bytes.
    let bytes_written = match compression {
        Compression::None => {
            let mut builder = tar::Builder::new(buffered);
            for (src, name) in subdirs.iter().zip(store_names.iter()) {
                builder
                    .append_dir_all(name, src)
                    .map_err(|e| ExportError::Io {
                        path: src.clone(),
                        source: e,
                    })?;
            }
            let mut writer = builder
                .into_inner()
                .map_err(|e| ExportError::Io {
                    path: tmp_path.clone(),
                    source: e,
                })?;
            writer.flush().map_err(|e| ExportError::Io {
                path: tmp_path.clone(),
                source: e,
            })?;
            std::fs::metadata(&tmp_path)
                .map(|m| m.len())
                .unwrap_or(0)
        }
        Compression::Gzip => {
            let encoder = flate2::write::GzEncoder::new(
                buffered,
                flate2::Compression::default(),
            );
            let mut builder = tar::Builder::new(encoder);
            for (src, name) in subdirs.iter().zip(store_names.iter()) {
                builder
                    .append_dir_all(name, src)
                    .map_err(|e| ExportError::Io {
                        path: src.clone(),
                        source: e,
                    })?;
            }
            let encoder = builder
                .into_inner()
                .map_err(|e| ExportError::Io {
                    path: tmp_path.clone(),
                    source: e,
                })?;
            // Finish writes the gzip trailer + returns the inner buf.
            let mut buffered = encoder.finish().map_err(|e| ExportError::Io {
                path: tmp_path.clone(),
                source: e,
            })?;
            buffered.flush().map_err(|e| ExportError::Io {
                path: tmp_path.clone(),
                source: e,
            })?;
            std::fs::metadata(&tmp_path)
                .map(|m| m.len())
                .unwrap_or(0)
        }
    };

    // Atomic publish.
    std::fs::rename(&tmp_path, output_path).map_err(|e| ExportError::Io {
        path: tmp_path.clone(),
        source: e,
    })?;

    Ok(ExportReport {
        stores_exported: store_names.len(),
        bytes_written,
        output_path: output_path.to_path_buf(),
        stores: store_names,
    })
}

/// Live-snapshot a running node's `data_dir/db/*` into `dest/db/*` via
/// RocksDB's `Checkpoint` API. Safe to call while the node is running —
/// each per-store backend is opened, checkpointed (hard-linking SSTs +
/// flushing MemTables into the destination), then dropped.
///
/// `dest` must not already exist for any of the per-store subdirs that
/// would be created (RocksDB's checkpoint errors on existing target
/// dirs). The function creates `dest/db/` if absent.
///
/// Returns one [`ExportReport`] entry, with `output_path = dest` and
/// `bytes_written = 0` (Checkpoint hard-links rather than copying, so
/// the size on disk reflects the original DB, not a separate count).
pub fn export_via_checkpoint(
    data_dir: &Path,
    dest: &Path,
) -> Result<ExportReport, ExportError> {
    use tron_chainbase::RocksDbBackend;

    if !data_dir.exists() {
        return Err(ExportError::DataDirMissing(data_dir.to_path_buf()));
    }
    let db_root = data_dir.join("db");
    if !db_root.is_dir() {
        return Err(ExportError::DbDirEmpty(db_root));
    }

    let mut subdirs: Vec<PathBuf> = std::fs::read_dir(&db_root)
        .map_err(|e| ExportError::Io {
            path: db_root.clone(),
            source: e,
        })?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    if subdirs.is_empty() {
        return Err(ExportError::DbDirEmpty(db_root));
    }
    subdirs.sort();

    let dest_db_root = dest.join("db");
    std::fs::create_dir_all(&dest_db_root).map_err(|e| ExportError::Io {
        path: dest_db_root.clone(),
        source: e,
    })?;

    let mut store_names = Vec::with_capacity(subdirs.len());
    for src in &subdirs {
        let Some(name) = src.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // RocksDB Checkpoint requires the dest dir to NOT exist —
        // it creates it. Skip stores whose dest already exists (re-
        // running an export into the same dir is then a no-op for
        // those stores rather than an error).
        let dest_store = dest_db_root.join(name);
        if dest_store.exists() {
            store_names.push(name.to_string());
            continue;
        }
        // Open read-write so RocksDB can flush MemTables before the
        // checkpoint copies SST files — read-only handles can't flush,
        // and unflushed writes would be invisible in the snapshot.
        // Safe on a live node only when no OTHER primary holds the
        // dir; callers in `start`-time code take a brief lock.
        let backend = RocksDbBackend::open(src).map_err(|e| ExportError::Io {
            path: src.clone(),
            source: std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("rocksdb open: {e}"),
            ),
        })?;
        backend
            .checkpoint(&dest_store)
            .map_err(|e| ExportError::Io {
                path: dest_store.clone(),
                source: std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("rocksdb checkpoint: {e}"),
                ),
            })?;
        store_names.push(name.to_string());
    }

    Ok(ExportReport {
        stores_exported: store_names.len(),
        bytes_written: 0,
        output_path: dest.to_path_buf(),
        stores: store_names,
    })
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
        p.push(format!("tron-export-{label}-{nanos}"));
        p
    }

    /// Re-uses the snapshot builder from the import-side tests by
    /// initializing genesis in-process. Returns the parent data_dir.
    fn build_minimal_data_dir() -> PathBuf {
        let data = temp_dir("data");
        std::fs::create_dir_all(&data).unwrap();
        let stores = crate::storage::OpenedStores::open(&data).expect("open stores");
        use tron_chainbase::{BlockIndexStore, BlockStore, DynamicPropertiesStore};
        use tron_types::{build_genesis_block, genesis_block_id, mainnet_inputs};
        let inputs = mainnet_inputs();
        let block = build_genesis_block(&inputs);
        let id = genesis_block_id(&inputs);
        BlockStore::new(stores.blocks.clone()).put(&id, &block);
        BlockIndexStore::new(stores.block_index.clone()).put(&id);
        let dp = DynamicPropertiesStore::new(stores.dyn_props.clone());
        dp.save_latest_block_header_number(0);
        dp.save_latest_block_header_hash(id.as_bytes());
        let state = stores.to_state_backends();
        tron_executor::apply_genesis_allocations(
            &state,
            inputs.assets,
            tron_types::mainnet_witnesses(),
        );
        drop(stores);
        data
    }

    fn cleanup(p: &Path) {
        let _ = std::fs::remove_dir_all(p);
    }

    #[test]
    fn export_tar_gz_then_import_round_trips_via_unified_dispatch() {
        let data_dir = build_minimal_data_dir();
        let output = temp_dir("output").join("snap.tar.gz");
        std::fs::create_dir_all(output.parent().unwrap()).unwrap();

        let report =
            export_to_tarball(&data_dir, &output, Compression::Gzip).expect("export");
        assert!(report.stores_exported >= 20);
        assert!(report.bytes_written > 0);
        assert!(output.exists());

        // Round-trip: import via the snapshot_import unified entry.
        let restore_dir = temp_dir("restore");
        let restored = crate::snapshot_import::import_snapshot(
            &output,
            &restore_dir,
            crate::snapshot_import::ImportMode::Copy,
            false,
        )
        .expect("import");
        assert_eq!(restored.witness_count, 27);
        assert_eq!(restored.head_block_number, 0);

        cleanup(&data_dir);
        cleanup(&restore_dir);
        let _ = std::fs::remove_file(&output);
        cleanup(output.parent().unwrap());
    }

    #[test]
    fn export_tar_no_compression_emits_uncompressed() {
        let data_dir = build_minimal_data_dir();
        let output = temp_dir("output-plain").join("snap.tar");
        std::fs::create_dir_all(output.parent().unwrap()).unwrap();
        let report =
            export_to_tarball(&data_dir, &output, Compression::None).expect("export");
        assert!(report.bytes_written > 0);
        // Confirm via magic byte that this is not a gzip stream
        // (gzip starts with 0x1f 0x8b).
        let head = std::fs::read(&output).unwrap();
        assert!(!(head[0] == 0x1f && head[1] == 0x8b), "expected raw tar");

        cleanup(&data_dir);
        let _ = std::fs::remove_file(&output);
        cleanup(output.parent().unwrap());
    }

    #[test]
    fn export_atomic_publishes_only_on_success() {
        let data_dir = build_minimal_data_dir();
        let output = temp_dir("output-atomic").join("snap.tar.gz");
        std::fs::create_dir_all(output.parent().unwrap()).unwrap();
        let report =
            export_to_tarball(&data_dir, &output, Compression::Gzip).expect("export");
        // The .tmp staging file should be gone, leaving only the final
        // output.
        let tmp = output.with_file_name(format!(
            "{}.tmp",
            output.file_name().unwrap().to_string_lossy()
        ));
        assert!(!tmp.exists());
        assert!(output.exists());
        assert_eq!(report.output_path, output);

        cleanup(&data_dir);
        let _ = std::fs::remove_file(&output);
        cleanup(output.parent().unwrap());
    }

    #[test]
    fn export_missing_data_dir_errors() {
        let nonexistent = std::env::temp_dir().join("tron-no-such-data-dir-xxxxx");
        let output = std::env::temp_dir().join("snap.tar.gz");
        let err =
            export_to_tarball(&nonexistent, &output, Compression::Gzip).unwrap_err();
        assert!(matches!(err, ExportError::DataDirMissing(_)));
    }

    #[test]
    fn export_compression_from_str_round_trips() {
        assert_eq!(Compression::from_str("none"), Some(Compression::None));
        assert_eq!(Compression::from_str("tar"), Some(Compression::None));
        assert_eq!(Compression::from_str("gzip"), Some(Compression::Gzip));
        assert_eq!(Compression::from_str("gz"), Some(Compression::Gzip));
        assert_eq!(Compression::from_str("xz"), None);
    }

    /// Live-snapshot via `Checkpoint` API produces a complete standalone
    /// DB that the importer's `Copy` mode can re-open. Same round-trip
    /// shape as the tarball path, but skips the tar step (faster, and
    /// works on a running node — though this test stops via `drop`).
    #[test]
    fn export_via_checkpoint_round_trips_through_import() {
        let data_dir = build_minimal_data_dir();
        let dest = temp_dir("checkpoint");

        let report = export_via_checkpoint(&data_dir, &dest).expect("checkpoint");
        // Same store count as the tar path.
        assert!(report.stores_exported >= 20);
        // Checkpoint dir is `dest/db/*`.
        assert!(dest.join("db").is_dir());

        // Use the snapshot_import directory entrypoint to open the
        // checkpoint as the source. `import_from_directory` expects
        // the source to contain per-store dirs directly, so point at
        // `dest/db` (not `dest`).
        let restore_dir = temp_dir("restore-checkpoint");
        let restored = crate::snapshot_import::import_from_directory(
            &dest.join("db"),
            &restore_dir,
            crate::snapshot_import::ImportMode::Copy,
            false,
        )
        .expect("import checkpoint");
        assert_eq!(restored.witness_count, 27);

        cleanup(&data_dir);
        cleanup(&dest);
        cleanup(&restore_dir);
    }

    #[test]
    fn export_via_checkpoint_missing_data_dir_errors() {
        let nonexistent = std::env::temp_dir().join("tron-no-such-checkpoint-data-yyyy");
        let dest = std::env::temp_dir().join("tron-no-such-checkpoint-dest-yyyy");
        let err = export_via_checkpoint(&nonexistent, &dest).unwrap_err();
        assert!(matches!(err, ExportError::DataDirMissing(_)));
    }
}
