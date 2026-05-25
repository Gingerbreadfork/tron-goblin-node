//! Cross-store atomic-flush primitive.
//!
//! Mirrors java-tron's `CheckPointV2` flow:
//!
//! 1. The SnapshotManager accumulates per-block writes in memory.
//! 2. Every `maxFlushCount` blocks it builds a flat batch over every
//!    store (`(db_name, key, value)` triples).
//! 3. The batch is written to a single timestamp-named subdirectory
//!    under `checkpoint/` — the on-disk appearance is atomic
//!    (write-temp + rename). If the process dies between the snapshot
//!    flush and the per-store flush, the next startup replays the
//!    checkpoint over each underlying store and resumes from a
//!    consistent point.
//! 4. After the per-store flush succeeds, the checkpoint is deleted.
//! 5. A pruner keeps the last few checkpoints so a partial-recovery
//!    can be re-attempted against the prior generation.
//!
//! In tron-goblin-node each store is its own RocksDB instance; RocksDB's
//! internal WAL gives intra-store atomicity but **cross-store**
//! atomicity needs this layer. Without it, a crash mid-flush can
//! leave one store ahead of the others.
//!
//! ## On-disk layout
//!
//! ```text
//! <data_dir>/checkpoint/
//!   1700000123456/manifest.bin   ← entries for that timestamp
//!   1700000125678/manifest.bin
//!   ...
//! ```
//!
//! The manifest is a length-prefixed format described in
//! [`encode_manifest`].

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Subdirectory name under the operator's data dir.
pub const CHECKPOINT_DIR_NAME: &str = "checkpoint";

/// File written inside each timestamped checkpoint dir.
const MANIFEST_NAME: &str = "manifest.bin";

/// One pending write captured in a checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointEntry {
    /// Target store directory name (`account`, `block`, etc.).
    pub db_name: String,
    /// Raw key bytes.
    pub key: Vec<u8>,
    /// `Some(bytes)` for puts; `None` for deletes (tombstone).
    pub value: Option<Vec<u8>>,
}

/// A timestamp id naming one checkpoint subdirectory.
pub type CheckpointId = u64;

/// Errors from the checkpoint API.
#[derive(Debug, thiserror::Error)]
pub enum CheckpointError {
    #[error("io: {0}")]
    Io(String),
    #[error("manifest decode: {0}")]
    Decode(String),
    #[error("checkpoint not found: {0}")]
    NotFound(CheckpointId),
}

impl From<io::Error> for CheckpointError {
    fn from(e: io::Error) -> Self {
        CheckpointError::Io(e.to_string())
    }
}

/// Filesystem-backed checkpoint manager. Cheap to clone — it's just
/// a `PathBuf`.
#[derive(Debug, Clone)]
pub struct CheckPointV2 {
    /// `<data_dir>/checkpoint/` — created lazily.
    root: PathBuf,
}

impl CheckPointV2 {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            root: data_dir.join(CHECKPOINT_DIR_NAME),
        }
    }

    /// Directory the checkpoints live under.
    pub fn root_path(&self) -> &Path {
        &self.root
    }

    /// Atomically write `entries` into a new timestamped checkpoint
    /// directory. Internally: write to `<root>/<id>.tmp/manifest.bin`,
    /// fsync, then rename to `<root>/<id>`. The rename is the atomic
    /// commit point — a partial write never appears under the live
    /// name.
    pub fn write(&self, entries: &[CheckpointEntry]) -> Result<CheckpointId, CheckpointError> {
        std::fs::create_dir_all(&self.root)?;
        let id = unique_ms();
        let dest = self.root.join(format!("{id}"));
        let staging = self.root.join(format!("{id}.tmp"));
        // Best-effort cleanup of any leftover from a previous failed
        // attempt at this exact millisecond (extremely unlikely but
        // cheap to guard against).
        let _ = std::fs::remove_dir_all(&staging);
        std::fs::create_dir_all(&staging)?;
        let manifest_path = staging.join(MANIFEST_NAME);
        let bytes = encode_manifest(entries);
        {
            let mut f = std::fs::File::create(&manifest_path)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&staging, &dest)?;
        Ok(id)
    }

    /// Replay a checkpoint into a closure that handles each entry.
    /// The closure is the place to actually write into the underlying
    /// per-store backends. Returns the entry count on success.
    pub fn replay<F>(
        &self,
        id: CheckpointId,
        mut apply: F,
    ) -> Result<usize, CheckpointError>
    where
        F: FnMut(&CheckpointEntry) -> Result<(), CheckpointError>,
    {
        let entries = self.read(id)?;
        let n = entries.len();
        for e in &entries {
            apply(e)?;
        }
        Ok(n)
    }

    /// Read a checkpoint without applying it. Useful for tests +
    /// diagnostic tooling.
    pub fn read(&self, id: CheckpointId) -> Result<Vec<CheckpointEntry>, CheckpointError> {
        let manifest = self.root.join(format!("{id}")).join(MANIFEST_NAME);
        if !manifest.exists() {
            return Err(CheckpointError::NotFound(id));
        }
        let mut f = std::fs::File::open(&manifest)?;
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes)?;
        decode_manifest(&bytes)
    }

    /// Drop one checkpoint dir.
    pub fn delete(&self, id: CheckpointId) -> Result<(), CheckpointError> {
        let dir = self.root.join(format!("{id}"));
        if !dir.exists() {
            return Err(CheckpointError::NotFound(id));
        }
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    /// List every checkpoint, sorted oldest → newest. Skips
    /// `*.tmp` staging dirs.
    pub fn list(&self) -> Result<Vec<CheckpointId>, CheckpointError> {
        if !self.root.exists() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.ends_with(".tmp") {
                continue;
            }
            if let Ok(id) = name.parse::<CheckpointId>() {
                out.push(id);
            }
        }
        out.sort_unstable();
        Ok(out)
    }

    /// Keep the most-recent `retain_last` checkpoints; delete the
    /// rest. Returns the count actually deleted.
    pub fn prune_keep_last(&self, retain_last: usize) -> Result<usize, CheckpointError> {
        let all = self.list()?;
        if all.len() <= retain_last {
            return Ok(0);
        }
        let to_drop = &all[..all.len() - retain_last];
        let mut deleted = 0;
        for id in to_drop {
            if self.delete(*id).is_ok() {
                deleted += 1;
            }
        }
        Ok(deleted)
    }
}

fn unique_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Length-prefixed binary encoding for a checkpoint manifest.
///
/// Format:
/// ```text
///   magic: 4 bytes "CKV2"
///   entry_count: u32 LE
///   for each entry:
///     db_name_len: u16 LE
///     db_name: utf-8 bytes
///     key_len: u32 LE
///     key bytes
///     value_present: u8 (1 = Some, 0 = None/tombstone)
///     if present:
///       value_len: u32 LE
///       value bytes
/// ```
pub fn encode_manifest(entries: &[CheckpointEntry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + entries.len() * 32);
    out.extend_from_slice(b"CKV2");
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        let name_bytes = e.db_name.as_bytes();
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(&(e.key.len() as u32).to_le_bytes());
        out.extend_from_slice(&e.key);
        match &e.value {
            Some(v) => {
                out.push(1);
                out.extend_from_slice(&(v.len() as u32).to_le_bytes());
                out.extend_from_slice(v);
            }
            None => {
                out.push(0);
            }
        }
    }
    out
}

pub fn decode_manifest(bytes: &[u8]) -> Result<Vec<CheckpointEntry>, CheckpointError> {
    fn read_slice<'a>(
        c: &mut usize,
        n: usize,
        src: &'a [u8],
    ) -> Result<&'a [u8], CheckpointError> {
        if *c + n > src.len() {
            return Err(CheckpointError::Decode(format!(
                "short read at {c} (want {n}, have {})",
                src.len() - *c
            )));
        }
        let s = &src[*c..*c + n];
        *c += n;
        Ok(s)
    }
    let mut cursor = 0usize;
    if read_slice(&mut cursor, 4, bytes)? != b"CKV2" {
        return Err(CheckpointError::Decode("bad magic".into()));
    }
    let count_bytes: [u8; 4] = read_slice(&mut cursor, 4, bytes)?
        .try_into()
        .expect("len-4 slice");
    let count = u32::from_le_bytes(count_bytes) as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let name_len_bytes: [u8; 2] = read_slice(&mut cursor, 2, bytes)?
            .try_into()
            .expect("len-2 slice");
        let name_len = u16::from_le_bytes(name_len_bytes) as usize;
        let name = std::str::from_utf8(read_slice(&mut cursor, name_len, bytes)?)
            .map_err(|e| CheckpointError::Decode(format!("db_name utf-8: {e}")))?
            .to_string();
        let key_len_bytes: [u8; 4] = read_slice(&mut cursor, 4, bytes)?
            .try_into()
            .expect("len-4 slice");
        let key_len = u32::from_le_bytes(key_len_bytes) as usize;
        let key = read_slice(&mut cursor, key_len, bytes)?.to_vec();
        let value_present_bytes = read_slice(&mut cursor, 1, bytes)?;
        let value = match value_present_bytes[0] {
            0 => None,
            1 => {
                let v_len_bytes: [u8; 4] = read_slice(&mut cursor, 4, bytes)?
                    .try_into()
                    .expect("len-4 slice");
                let v_len = u32::from_le_bytes(v_len_bytes) as usize;
                Some(read_slice(&mut cursor, v_len, bytes)?.to_vec())
            }
            other => {
                return Err(CheckpointError::Decode(format!(
                    "bad value_present tag {other}"
                )));
            }
        };
        out.push(CheckpointEntry {
            db_name: name,
            key,
            value,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "tron-ckv2-{}",
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn entry(db: &str, k: &[u8], v: Option<&[u8]>) -> CheckpointEntry {
        CheckpointEntry {
            db_name: db.into(),
            key: k.to_vec(),
            value: v.map(|x| x.to_vec()),
        }
    }

    #[test]
    fn manifest_encode_decode_roundtrips() {
        let entries = vec![
            entry("account", b"alice", Some(b"100")),
            entry("block", b"\x00\x00\x00\x01", Some(b"BLOCKBYTES")),
            entry("transactions", b"deadbeef", None), // tombstone
        ];
        let bytes = encode_manifest(&entries);
        let back = decode_manifest(&bytes).unwrap();
        assert_eq!(back, entries);
    }

    #[test]
    fn manifest_empty_round_trips() {
        let bytes = encode_manifest(&[]);
        assert_eq!(decode_manifest(&bytes).unwrap(), vec![]);
    }

    #[test]
    fn manifest_bad_magic_rejected() {
        let bytes = b"XXXX\x00\x00\x00\x00";
        assert!(matches!(
            decode_manifest(bytes),
            Err(CheckpointError::Decode(_))
        ));
    }

    #[test]
    fn write_then_read_roundtrips() {
        let root = tmp_root();
        let cpv2 = CheckPointV2::new(&root);
        let entries = vec![entry("account", b"k", Some(b"v"))];
        let id = cpv2.write(&entries).unwrap();
        let back = cpv2.read(id).unwrap();
        assert_eq!(back, entries);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn list_returns_sorted_ids() {
        let root = tmp_root();
        let cpv2 = CheckPointV2::new(&root);
        let id1 = cpv2.write(&[entry("a", b"1", Some(b"x"))]).unwrap();
        // Bump 1ms so the IDs differ.
        std::thread::sleep(std::time::Duration::from_millis(2));
        let id2 = cpv2.write(&[entry("b", b"2", Some(b"y"))]).unwrap();
        let listed = cpv2.list().unwrap();
        assert_eq!(listed, vec![id1, id2]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn replay_applies_each_entry_in_order() {
        let root = tmp_root();
        let cpv2 = CheckPointV2::new(&root);
        let entries = vec![
            entry("account", b"k1", Some(b"v1")),
            entry("account", b"k2", None),
            entry("block", b"k3", Some(b"v3")),
        ];
        let id = cpv2.write(&entries).unwrap();
        let mut seen: Vec<(String, Vec<u8>, Option<Vec<u8>>)> = Vec::new();
        let n = cpv2
            .replay(id, |e| {
                seen.push((e.db_name.clone(), e.key.clone(), e.value.clone()));
                Ok(())
            })
            .unwrap();
        assert_eq!(n, 3);
        assert_eq!(seen[0].0, "account");
        assert_eq!(seen[1].2, None);
        assert_eq!(seen[2].0, "block");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn delete_removes_dir() {
        let root = tmp_root();
        let cpv2 = CheckPointV2::new(&root);
        let id = cpv2.write(&[entry("a", b"k", Some(b"v"))]).unwrap();
        cpv2.delete(id).unwrap();
        assert!(matches!(cpv2.read(id), Err(CheckpointError::NotFound(_))));
        assert!(matches!(cpv2.delete(id), Err(CheckpointError::NotFound(_))));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn prune_keep_last_drops_oldest() {
        let root = tmp_root();
        let cpv2 = CheckPointV2::new(&root);
        let mut ids = Vec::new();
        for i in 0..5 {
            let v = format!("{i}");
            ids.push(cpv2.write(&[entry("a", v.as_bytes(), Some(b"x"))]).unwrap());
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        // Keep last 2 → drops 3 oldest.
        let dropped = cpv2.prune_keep_last(2).unwrap();
        assert_eq!(dropped, 3);
        let remaining = cpv2.list().unwrap();
        assert_eq!(remaining.len(), 2);
        assert_eq!(remaining[1], ids[4]); // most-recent retained
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn prune_keep_last_no_op_when_under_threshold() {
        let root = tmp_root();
        let cpv2 = CheckPointV2::new(&root);
        cpv2.write(&[entry("a", b"k", Some(b"v"))]).unwrap();
        assert_eq!(cpv2.prune_keep_last(5).unwrap(), 0);
        let _ = std::fs::remove_dir_all(&root);
    }
}
