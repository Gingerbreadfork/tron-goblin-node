//! Resume / crash-safety: a per-store "done" marker.
//!
//! The converter deletes each source store after copying it, so a crash
//! must never strand the user halfway. After a destination store is fully
//! written **and fsynced** (and, for on-disk input, the source removed), we
//! drop a marker file in the destination store directory. On a re-run, a
//! store whose marker is present is skipped.
//!
//! The marker is byte-compatible with java-tron's own `DbConvert` /
//! `engine.properties` convention: a properties file in the store dir
//! containing `ENGINE=ROCKSDB`. java-tron's `FileUtils.isLevelDBEngine` /
//! `DbConvert.checkDone` read exactly this, so a snapshot half-converted by
//! one tool can be finished by the other, and a node opening the converted
//! dir sees the engine it expects.

use std::io::Write;
use std::path::{Path, PathBuf};

/// The marker file java-tron writes in each store dir to record its engine.
pub const ENGINE_FILE: &str = "engine.properties";
/// The property key inside [`ENGINE_FILE`].
pub const ENGINE_KEY: &str = "ENGINE";
/// Marker value once a store has been converted to RocksDB.
pub const ENGINE_ROCKSDB: &str = "ROCKSDB";

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("write done-marker {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("read done-marker {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

fn marker_path(dest_store_dir: &Path) -> PathBuf {
    dest_store_dir.join(ENGINE_FILE)
}

/// Is the destination store already marked converted? (`engine.properties`
/// exists in it and records `ENGINE=ROCKSDB`.) Used to skip completed
/// stores on a resumed run.
pub fn is_store_done(dest_store_dir: &Path) -> Result<bool, ManifestError> {
    let path = marker_path(dest_store_dir);
    match std::fs::read_to_string(&path) {
        Ok(contents) => Ok(parse_engine(&contents).as_deref() == Some(ENGINE_ROCKSDB)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(ManifestError::Read { path, source }),
    }
}

/// Write (and fsync) the `ENGINE=ROCKSDB` done-marker into the destination
/// store dir. fsync'd because it is the commit point: once this returns,
/// the store counts as converted and (for on-disk input) its source has
/// already been removed, so the marker must survive a crash. The parent
/// directory entry is fsync'd too so the new file is durably linked.
pub fn mark_store_done(dest_store_dir: &Path) -> Result<(), ManifestError> {
    let path = marker_path(dest_store_dir);
    let body = format!("{ENGINE_KEY}={ENGINE_ROCKSDB}\n");
    let write = || -> std::io::Result<()> {
        let mut f = std::fs::File::create(&path)?;
        f.write_all(body.as_bytes())?;
        f.sync_all()?;
        // fsync the directory so the new dir entry is durable.
        if let Ok(dir) = std::fs::File::open(dest_store_dir) {
            let _ = dir.sync_all();
        }
        Ok(())
    };
    write().map_err(|source| ManifestError::Write { path, source })
}

/// Parse the `ENGINE` value out of a properties-file body. Tolerant of
/// blank lines, `#` comments, and surrounding whitespace, matching how
/// java-tron's `FileUtils.getEngine` reads it.
fn parse_engine(contents: &str) -> Option<String> {
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == ENGINE_KEY {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(label: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        p.push(format!("snapconv-manifest-{label}-{n}"));
        p
    }

    #[test]
    fn marker_round_trips() {
        let dir = tmp("rt");
        std::fs::create_dir_all(&dir).unwrap();
        assert!(!is_store_done(&dir).unwrap());
        mark_store_done(&dir).unwrap();
        assert!(is_store_done(&dir).unwrap());
        // The on-disk form is java-compatible.
        let body = std::fs::read_to_string(dir.join(ENGINE_FILE)).unwrap();
        assert!(body.contains("ENGINE=ROCKSDB"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn leveldb_marker_is_not_done() {
        let dir = tmp("level");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(ENGINE_FILE), "ENGINE=LEVELDB\n").unwrap();
        // A store still marked LEVELDB has not been converted.
        assert!(!is_store_done(&dir).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_engine_tolerates_comments_and_blanks() {
        assert_eq!(parse_engine("\n# c\nENGINE = ROCKSDB \n").as_deref(), Some("ROCKSDB"));
        assert_eq!(parse_engine("ENGINE=LEVELDB").as_deref(), Some("LEVELDB"));
        assert_eq!(parse_engine("nope").as_deref(), None);
    }
}
