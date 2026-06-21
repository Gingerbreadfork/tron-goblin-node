//! Replay a java-tron on-disk checkpoint into per-store backends.
//!
//! java-tron persists a redo log of the most-recent flush batch so a
//! crash between writing the checkpoint and flushing the per-store
//! RocksDB instances is recoverable. On every startup java replays
//! the checkpoint over the stores (`SnapshotManager.recover`), and the
//! LiteFullNode snapshot tool replays it into the snapshot it produces
//! (`DbLite.mergeCheckpoint2Snapshot`). A raw filesystem copy of a
//! java data dir — the common way mainnet snapshots are distributed —
//! carries that checkpoint un-merged, so anything consuming such a
//! copy must replay it or it boots from a base that is up to one flush
//! batch behind the head pointer.
//!
//! ## On-disk layouts
//!
//! Two checkpoint versions exist; both encode the same row format.
//!
//! * **V1** — a single RocksDB store named `tmp` directly under the
//!   database directory (`database/tmp/`).
//! * **V2** — one RocksDB store per flush batch under
//!   `database/checkpoint/<timestamp>/`, replayed oldest-first.
//!
//! ## Row format
//!
//! Each checkpoint row keys the target store and the real key together,
//! and tags the value with an operator byte:
//!
//! ```text
//!   key   = [4-byte BE name length][db_name utf-8][real key bytes]
//!   value = [1-byte operator][real value bytes]
//! ```
//!
//! The operator byte is one of java's `Value.Operator` values:
//! `0=CREATE`, `1=MODIFY`, `2=DELETE`, `3=PUT`. A value of length 1
//! (operator only, no payload) is a tombstone: a `DELETE` removes the
//! key, any other operator writes an empty value (java's
//! `recover`/`DbLite.recover` both special-case this exactly). The
//! `trans-cache` store is skipped — it is a rebuildable bloom cache,
//! never base state, and java skips it on replay.

use std::path::Path;

use crate::backend::{KvBackend, KvError};
use crate::rocksdb_backend::{RocksDbBackend, RocksDbError};

/// java's `DbLite.recover` skips this store — it is a rebuildable
/// transaction-id bloom cache, not consensus base state.
const TRANS_CACHE_DB_NAME: &str = "trans-cache";

/// V1 checkpoint store directory name (`database/tmp/`).
pub const JAVA_CHECKPOINT_V1_DIR: &str = "tmp";

/// V2 checkpoint parent directory name (`database/checkpoint/`).
pub const JAVA_CHECKPOINT_V2_DIR: &str = "checkpoint";

/// Errors from java-checkpoint detection / replay.
#[derive(Debug, thiserror::Error)]
pub enum JavaCheckpointError {
    #[error("open checkpoint store {0:?}: {1}")]
    Open(std::path::PathBuf, RocksDbError),
    #[error("scan checkpoint store {0:?}: {1}")]
    Scan(std::path::PathBuf, String),
    #[error("apply to store {db_name}: {source}")]
    Apply {
        db_name: String,
        #[source]
        source: KvError,
    },
}

/// Decode a java checkpoint key into `(db_name, real_key)`.
///
/// Returns `None` for a key that does not carry a valid
/// `[4-byte BE length][name][real key]` envelope — such a row is not a
/// flush-batch entry and is skipped, mirroring java's `simpleDecode`
/// being called only on real batch rows.
fn decode_key(key: &[u8]) -> Option<(String, &[u8])> {
    if key.len() < 4 {
        return None;
    }
    let name_len = u32::from_be_bytes([key[0], key[1], key[2], key[3]]) as usize;
    let name_end = 4usize.checked_add(name_len)?;
    if name_end > key.len() {
        return None;
    }
    let name = std::str::from_utf8(&key[4..name_end]).ok()?.to_string();
    Some((name, &key[name_end..]))
}

/// One decoded checkpoint operation.
enum Op<'a> {
    /// Write `value` (possibly empty) at the real key.
    Put(&'a [u8]),
    /// Remove the real key.
    Delete,
}

/// Decode a java checkpoint value into an operation.
///
/// Mirrors `SnapshotManager.recover`: a value longer than one byte is a
/// PUT of the bytes after the operator tag; a one-byte value is the
/// operator alone — `DELETE` (2) removes the key, anything else writes
/// an empty value.
fn decode_value(value: &[u8]) -> Op<'_> {
    if value.len() > 1 {
        Op::Put(&value[1..])
    } else if value.first() == Some(&2) {
        // java Value.Operator.DELETE
        Op::Delete
    } else {
        // CREATE / MODIFY / PUT with an empty payload → empty value.
        Op::Put(&[])
    }
}

/// Whether a java-format checkpoint that we would replay exists under
/// `db_root` and carries at least one row for a store other than the
/// rebuildable `trans-cache`. Cheap O(checkpoint-size) read used by the
/// import path and the daemon startup guard to decide whether a base is
/// behind its head pointer.
///
/// Returns `Ok(false)` when no checkpoint store is present or every
/// present checkpoint is empty (a clean, fully-flushed base — the
/// common case for a tool-produced snapshot).
pub fn has_pending_java_checkpoint(db_root: &Path) -> Result<bool, JavaCheckpointError> {
    for store in java_checkpoint_stores(db_root)? {
        let mut pending = false;
        let path = store.clone();
        let be = open_ro(&store)?;
        be.for_each(|k, _v| {
            if let Some((name, _)) = decode_key(k) {
                if name != TRANS_CACHE_DB_NAME {
                    pending = true;
                }
            }
            Ok(())
        })
        .map_err(|e| JavaCheckpointError::Scan(path.clone(), e.to_string()))?;
        if pending {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Replay every java-format checkpoint found under `db_root` into the
/// matching per-store backends, exactly as java's `recover` does.
///
/// `resolve` maps a checkpoint `db_name` to the destination backend.
/// Returning `None` skips the row (a store this node does not open —
/// e.g. `recent-block`, `account-trace`); returning `Some(backend)`
/// applies the put/delete to it. `trans-cache` rows are always skipped.
///
/// V2 checkpoints replay oldest-first (timestamp order) so a later
/// batch's overwrite wins, matching java. Returns the number of rows
/// applied (skipped rows are not counted).
pub fn replay_java_checkpoint<F>(
    db_root: &Path,
    mut resolve: F,
) -> Result<usize, JavaCheckpointError>
where
    F: FnMut(&str) -> Option<std::sync::Arc<dyn KvBackend>>,
{
    let mut applied = 0usize;
    for store in java_checkpoint_stores(db_root)? {
        let path = store.clone();
        let be = open_ro(&store)?;
        // Buffer this batch's rows so the read handle is dropped before
        // any write handle to the same logical store could be opened by
        // the caller; checkpoint batches are bounded (one flush window),
        // so the memory cost is small.
        let mut batch: Vec<(String, Vec<u8>, Option<Vec<u8>>)> = Vec::new();
        be.for_each(|k, v| {
            if let Some((name, real_key)) = decode_key(k) {
                if name == TRANS_CACHE_DB_NAME {
                    return Ok(());
                }
                let op = match decode_value(v) {
                    Op::Put(val) => Some(val.to_vec()),
                    Op::Delete => None,
                };
                batch.push((name, real_key.to_vec(), op));
            }
            Ok(())
        })
        .map_err(|e| JavaCheckpointError::Scan(path.clone(), e.to_string()))?;
        drop(be);

        for (name, real_key, op) in batch {
            let Some(dst) = resolve(&name) else { continue };
            match op {
                Some(val) => dst.put(&real_key, &val),
                None => dst.delete(&real_key),
            }
            .map_err(|e| JavaCheckpointError::Apply {
                db_name: name,
                source: e,
            })?;
            applied += 1;
        }
    }
    Ok(applied)
}

/// Enumerate the checkpoint store directories under `db_root`, in the
/// order java replays them. Prefers V2 (`checkpoint/<timestamp>`,
/// oldest-first); falls back to V1 (`tmp/`) when no V2 batch exists —
/// the same precedence as `DbLite.mergeCheckpoint`.
fn java_checkpoint_stores(db_root: &Path) -> Result<Vec<std::path::PathBuf>, JavaCheckpointError> {
    let v2_parent = db_root.join(JAVA_CHECKPOINT_V2_DIR);
    if v2_parent.is_dir() {
        let mut batches: Vec<(u64, std::path::PathBuf)> = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&v2_parent) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                // Only timestamp-named RocksDB stores are flush batches;
                // a non-numeric name is a staging/temp dir to skip.
                if let Some(ts) = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .and_then(|n| n.parse::<u64>().ok())
                {
                    if path.join("CURRENT").is_file() {
                        batches.push((ts, path));
                    }
                }
            }
        }
        if !batches.is_empty() {
            batches.sort_by_key(|(ts, _)| *ts);
            return Ok(batches.into_iter().map(|(_, p)| p).collect());
        }
    }

    let v1 = db_root.join(JAVA_CHECKPOINT_V1_DIR);
    if v1.join("CURRENT").is_file() {
        return Ok(vec![v1]);
    }
    Ok(Vec::new())
}

/// Open a checkpoint store read-only. The checkpoint stores (`tmp`,
/// `checkpoint/<ts>`) carry the flat flush-batch envelope under the
/// default byte comparator — never the custom market-order comparator —
/// so a plain read-only open is correct.
fn open_ro(path: &Path) -> Result<RocksDbBackend, JavaCheckpointError> {
    RocksDbBackend::open_read_only(path).map_err(|e| JavaCheckpointError::Open(path.to_path_buf(), e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rocksdb_backend::RocksDbBackend;
    use std::sync::Arc;

    fn simple_encode(name: &str) -> Vec<u8> {
        let b = name.as_bytes();
        let mut r = (b.len() as u32).to_be_bytes().to_vec();
        r.extend_from_slice(b);
        r
    }

    fn cp_key(db: &str, key: &[u8]) -> Vec<u8> {
        let mut k = simple_encode(db);
        k.extend_from_slice(key);
        k
    }

    /// PUT value: operator byte 3 (java PUT) followed by payload.
    fn put_val(payload: &[u8]) -> Vec<u8> {
        let mut v = vec![3u8];
        v.extend_from_slice(payload);
        v
    }

    fn tmp_root() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "tron-javacp-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn decode_key_extracts_name_and_real_key() {
        let k = cp_key("account", b"alice");
        let (name, real) = decode_key(&k).unwrap();
        assert_eq!(name, "account");
        assert_eq!(real, b"alice");
    }

    #[test]
    fn decode_key_rejects_truncated_envelope() {
        // Length says 10 bytes of name but only 3 present.
        let mut k = 10u32.to_be_bytes().to_vec();
        k.extend_from_slice(b"abc");
        assert!(decode_key(&k).is_none());
    }

    #[test]
    fn decode_value_put_and_delete_and_empty() {
        assert!(matches!(decode_value(&put_val(b"hello")), Op::Put(b) if b == b"hello"));
        assert!(matches!(decode_value(&[2u8]), Op::Delete));
        // Operator-only PUT (op 3, no payload) → empty value, not delete.
        assert!(matches!(decode_value(&[3u8]), Op::Put(b) if b.is_empty()));
        // CREATE (0) operator-only → empty value.
        assert!(matches!(decode_value(&[0u8]), Op::Put(b) if b.is_empty()));
    }

    #[test]
    fn replay_v1_tmp_applies_puts_and_deletes() {
        let root = tmp_root();
        let db_root = root.join("database");
        let tmp = db_root.join(JAVA_CHECKPOINT_V1_DIR);
        std::fs::create_dir_all(&tmp).unwrap();
        {
            let cp = RocksDbBackend::open(&tmp).unwrap();
            cp.put(&cp_key("account", b"alice"), &put_val(b"100")).unwrap();
            cp.put(&cp_key("witness", b"w1"), &put_val(b"prod")).unwrap();
            // A tombstone for a pre-existing account key.
            cp.put(&cp_key("account", b"bob"), &[2u8]).unwrap();
            // trans-cache row must be skipped.
            cp.put(&cp_key("trans-cache", b"tx"), &put_val(b"x")).unwrap();
        }

        let accounts: Arc<dyn KvBackend> = Arc::new(crate::backend::MemBackend::new());
        let witnesses: Arc<dyn KvBackend> = Arc::new(crate::backend::MemBackend::new());
        // Pre-seed the key the tombstone should remove.
        accounts.put(b"bob", b"stale").unwrap();

        let accounts_c = accounts.clone();
        let witnesses_c = witnesses.clone();
        let applied = replay_java_checkpoint(&db_root, |name| match name {
            "account" => Some(accounts_c.clone()),
            "witness" => Some(witnesses_c.clone()),
            _ => None,
        })
        .unwrap();

        // alice put, bob delete, w1 put = 3 applied; trans-cache skipped.
        assert_eq!(applied, 3);
        assert_eq!(accounts.get(b"alice").unwrap().as_deref(), Some(b"100".as_ref()));
        assert_eq!(accounts.get(b"bob").unwrap(), None);
        assert_eq!(witnesses.get(b"w1").unwrap().as_deref(), Some(b"prod".as_ref()));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn has_pending_detects_non_trans_cache_rows() {
        let root = tmp_root();
        let db_root = root.join("database");
        let tmp = db_root.join(JAVA_CHECKPOINT_V1_DIR);
        std::fs::create_dir_all(&tmp).unwrap();
        {
            let cp = RocksDbBackend::open(&tmp).unwrap();
            cp.put(&cp_key("account", b"k"), &put_val(b"v")).unwrap();
        }
        assert!(has_pending_java_checkpoint(&db_root).unwrap());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn has_pending_false_for_only_trans_cache() {
        let root = tmp_root();
        let db_root = root.join("database");
        let tmp = db_root.join(JAVA_CHECKPOINT_V1_DIR);
        std::fs::create_dir_all(&tmp).unwrap();
        {
            let cp = RocksDbBackend::open(&tmp).unwrap();
            cp.put(&cp_key("trans-cache", b"k"), &put_val(b"v")).unwrap();
        }
        assert!(!has_pending_java_checkpoint(&db_root).unwrap());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn has_pending_false_when_no_checkpoint() {
        let root = tmp_root();
        let db_root = root.join("database");
        std::fs::create_dir_all(&db_root).unwrap();
        assert!(!has_pending_java_checkpoint(&db_root).unwrap());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn replay_v2_applies_oldest_first_so_latest_wins() {
        let root = tmp_root();
        let db_root = root.join("database");
        let cp_parent = db_root.join(JAVA_CHECKPOINT_V2_DIR);
        // Two timestamped batches: the newer one overwrites the key.
        for (ts, val) in [(100u64, b"old".as_ref()), (200u64, b"new".as_ref())] {
            let dir = cp_parent.join(ts.to_string());
            std::fs::create_dir_all(&dir).unwrap();
            let cp = RocksDbBackend::open(&dir).unwrap();
            cp.put(&cp_key("account", b"k"), &put_val(val)).unwrap();
        }
        let accounts: Arc<dyn KvBackend> = Arc::new(crate::backend::MemBackend::new());
        let accounts_c = accounts.clone();
        let applied = replay_java_checkpoint(&db_root, |name| {
            (name == "account").then(|| accounts_c.clone())
        })
        .unwrap();
        assert_eq!(applied, 2);
        assert_eq!(accounts.get(b"k").unwrap().as_deref(), Some(b"new".as_ref()));
        let _ = std::fs::remove_dir_all(&root);
    }
}
