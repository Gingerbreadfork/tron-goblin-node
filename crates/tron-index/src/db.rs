//! The index DB — meta bookkeeping, atomic batches, format versioning.
//!
//! One dedicated KV instance (RocksDB in production, `MemBackend` in
//! tests) holding every namespace, so a single `write_batch` spanning
//! rows + cursor is atomic: either a window's rows AND its cursor
//! advance land together, or neither does. The index is a pure
//! projection of committed consensus state, so it is **disposable by
//! contract** — every recovery and upgrade path resolves to "drop and
//! re-derive".

use std::sync::Arc;

use prost::Message as _;
use tron_chainbase::{KvBackend, KvError, WriteOp};

use crate::keys;
use crate::rows::TokenMeta;

/// Bumped on any change a reader could mis-interpret: key layouts, row
/// message semantics, namespace set, or extraction-rule changes that
/// alter *which* rows exist. Additive optional row fields ride prost
/// forward-compat without a bump.
pub const FORMAT_VERSION: u32 = 2;

#[derive(Debug, thiserror::Error)]
pub enum IndexError {
    #[error("index kv: {0}")]
    Kv(#[from] KvError),
    #[error("index store: {0}")]
    Store(#[from] tron_chainbase::StoreError),
    #[error(
        "format version on disk ({on_disk}) is newer than this binary supports ({supported}) — \
         refusing to touch it; upgrade the binary or delete the artifact's directory"
    )]
    NewerFormat { on_disk: u32, supported: u32 },
    /// Genuinely bad on-disk data. The message stays artifact-neutral
    /// — this error is shared by the tx-history index (disposable,
    /// rebuild remedy), the archive (NOT disposable), and the firehose
    /// log (store-derivable); each consumer attaches its own remedy
    /// when it surfaces the error.
    #[error("corrupt data: {0}")]
    Corrupt(String),
    /// Plain I/O failure (disk full, permissions, transient FS error)
    /// — distinct from corruption so operators are never told to
    /// delete healthy data over an ENOSPC.
    #[error("io: {0}")]
    Io(String),
    /// A repair source is missing (pruned undo records, detached
    /// stores) — an availability condition, not corruption.
    #[error("repair source unavailable: {0}")]
    Unavailable(String),
}

/// Outcome of the open-time compatibility check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitOutcome {
    /// Empty DB — stamped fresh; the follower cold-starts.
    Fresh,
    /// Version + scope fingerprint match — resume where we left off.
    Compatible,
    /// Version or scope fingerprint differ — the caller must wipe and
    /// re-stamp (the rebuild path IS the ordinary cold-start path).
    NeedsRebuild { reason: &'static str },
}

/// Thin typed wrapper over the index backend. Cheap to clone.
#[derive(Clone)]
pub struct IndexDb {
    backend: Arc<dyn KvBackend>,
}

impl IndexDb {
    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    pub fn backend(&self) -> &Arc<dyn KvBackend> {
        &self.backend
    }

    // -- format / scope ----------------------------------------------------

    /// Check the on-disk stamp against this binary + the effective
    /// capture-set fingerprint. Does NOT wipe by itself — the caller
    /// decides how (RocksDB: destroy the directory; tests: [`wipe`]).
    ///
    /// [`wipe`]: Self::wipe
    pub fn check_or_init(&self, scope_fingerprint: u64) -> Result<InitOutcome, IndexError> {
        match self.format_version()? {
            None => {
                self.stamp(scope_fingerprint)?;
                Ok(InitOutcome::Fresh)
            }
            Some(v) if v > FORMAT_VERSION => Err(IndexError::NewerFormat {
                on_disk: v,
                supported: FORMAT_VERSION,
            }),
            Some(v) if v < FORMAT_VERSION => Ok(InitOutcome::NeedsRebuild {
                reason: "index format version bumped by upgrade",
            }),
            Some(_) => match self.scope_fingerprint()? {
                Some(fp) if fp == scope_fingerprint => Ok(InitOutcome::Compatible),
                _ => Ok(InitOutcome::NeedsRebuild {
                    reason: "index scope / capture set changed",
                }),
            },
        }
    }

    /// Write the version + scope stamp (fresh DB or post-wipe).
    pub fn stamp(&self, scope_fingerprint: u64) -> Result<(), IndexError> {
        self.backend.write_batch(&[
            WriteOp::Put(
                keys::meta_format_version(),
                FORMAT_VERSION.to_be_bytes().to_vec(),
            ),
            WriteOp::Put(
                keys::meta_scope_fingerprint(),
                scope_fingerprint.to_be_bytes().to_vec(),
            ),
        ])?;
        Ok(())
    }

    pub fn format_version(&self) -> Result<Option<u32>, IndexError> {
        Ok(self
            .backend
            .get(&keys::meta_format_version())?
            .and_then(|v| v.try_into().ok())
            .map(u32::from_be_bytes))
    }

    pub fn scope_fingerprint(&self) -> Result<Option<u64>, IndexError> {
        Ok(self
            .backend
            .get(&keys::meta_scope_fingerprint())?
            .and_then(|v| v.try_into().ok())
            .map(u64::from_be_bytes))
    }

    /// Delete **everything** — the generic rebuild path. On a large
    /// RocksDB instance prefer destroying the directory before open
    /// (the node's open helper does); this exists for in-memory
    /// backends and small DBs where tombstoning is fine.
    pub fn wipe(&self) -> Result<(), IndexError> {
        let all = self.backend.scan_all()?;
        let ops: Vec<WriteOp> = all.into_iter().map(|(k, _)| WriteOp::Delete(k)).collect();
        for chunk in ops.chunks(100_000) {
            self.backend.write_batch(chunk)?;
        }
        Ok(())
    }

    // -- cursor / edges ------------------------------------------------------

    fn get_i64(&self, key: &[u8]) -> Result<Option<i64>, IndexError> {
        Ok(self
            .backend
            .get(key)?
            .and_then(|v| v.try_into().ok())
            .map(i64::from_be_bytes))
    }

    /// The composite live-edge cursor: `(height, recorded canonical
    /// id)`. The id is `None` until a window (or an init that could
    /// resolve one) stamps it — and `None` after any update that
    /// could not, which deliberately disarms by-hash reorg detection
    /// rather than leaving a stale height/id pairing.
    pub fn cursor(&self) -> Result<Option<(i64, Option<[u8; 32]>)>, IndexError> {
        let Some(bytes) = self.backend.get(&keys::meta_cursor())? else {
            return Ok(None);
        };
        if bytes.len() != 8 && bytes.len() != 40 {
            return Err(IndexError::Corrupt(format!(
                "cursor meta has {} bytes (want 8 or 40)",
                bytes.len()
            )));
        }
        let height = i64::from_be_bytes(bytes[..8].try_into().expect("8 bytes"));
        let id = (bytes.len() == 40).then(|| {
            let mut id = [0u8; 32];
            id.copy_from_slice(&bytes[8..]);
            id
        });
        Ok(Some((height, id)))
    }

    pub fn cursor_height(&self) -> Result<Option<i64>, IndexError> {
        Ok(self.cursor()?.map(|(h, _)| h))
    }

    pub fn cursor_id(&self) -> Result<Option<[u8; 32]>, IndexError> {
        Ok(self.cursor()?.and_then(|(_, id)| id))
    }

    pub fn back_edge(&self) -> Result<Option<i64>, IndexError> {
        self.get_i64(&keys::meta_back_edge())
    }

    pub fn floor(&self) -> Result<Option<i64>, IndexError> {
        self.get_i64(&keys::meta_floor())
    }

    /// Build the meta put for an edge update — appended to a window's
    /// batch so the edge advances atomically with its rows. Encoding
    /// height and id in ONE value means `id: None` clears any previous
    /// id instead of leaving a stale pairing behind.
    pub fn cursor_put_ops(height: i64, id: Option<[u8; 32]>) -> Vec<WriteOp> {
        let mut value = height.to_be_bytes().to_vec();
        if let Some(id) = id {
            value.extend_from_slice(&id);
        }
        vec![WriteOp::Put(keys::meta_cursor(), value)]
    }

    pub fn back_edge_put_op(height: i64) -> WriteOp {
        WriteOp::Put(keys::meta_back_edge(), height.to_be_bytes().to_vec())
    }

    pub fn floor_put_op(height: i64) -> WriteOp {
        WriteOp::Put(keys::meta_floor(), height.to_be_bytes().to_vec())
    }

    // -- recent ring ---------------------------------------------------------

    pub fn id_at(&self, height: i64) -> Result<Option<[u8; 32]>, IndexError> {
        Ok(self
            .backend
            .get(&keys::meta_id_at(height))?
            .and_then(|v| v.try_into().ok()))
    }

    pub fn keys_at(&self, height: i64) -> Result<Option<Vec<Vec<u8>>>, IndexError> {
        match self.backend.get(&keys::meta_keys_at(height))? {
            None => Ok(None),
            Some(bytes) => keys::decode_key_list(&bytes)
                .map(Some)
                .ok_or_else(|| IndexError::Corrupt(format!("ring keys_at/{height} undecodable"))),
        }
    }

    // -- batches ---------------------------------------------------------------

    /// Apply one atomic batch (a window's rows + ring + edge update).
    pub fn commit(&self, ops: &[WriteOp]) -> Result<(), IndexError> {
        self.backend.write_batch(ops)?;
        Ok(())
    }

    /// Durability barrier: fsync the WAL so every prior non-sync batch
    /// survives power loss. Called every N windows and when parking.
    pub fn sync(&self) -> Result<(), IndexError> {
        self.backend.sync_wal()?;
        Ok(())
    }

    // -- token-metadata cache ----------------------------------------------

    pub fn token_meta(&self, contract: &keys::Addr) -> Result<Option<TokenMeta>, IndexError> {
        match self.backend.get(&keys::meta_token(contract))? {
            None => Ok(None),
            Some(bytes) => Ok(TokenMeta::decode(bytes.as_slice()).ok()),
        }
    }

    /// Cache writes ride outside the cursor protocol deliberately —
    /// token metadata is not consistency-critical (re-resolvable any
    /// time).
    pub fn put_token_meta(
        &self,
        contract: &keys::Addr,
        meta: &TokenMeta,
    ) -> Result<(), IndexError> {
        self.backend
            .put(&keys::meta_token(contract), &meta.encode_to_vec())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tron_chainbase::MemBackend;

    fn db() -> IndexDb {
        IndexDb::new(Arc::new(MemBackend::new()))
    }

    #[test]
    fn fresh_stamp_then_compatible() {
        let db = db();
        assert_eq!(db.check_or_init(42).unwrap(), InitOutcome::Fresh);
        assert_eq!(db.check_or_init(42).unwrap(), InitOutcome::Compatible);
        assert_eq!(db.format_version().unwrap(), Some(FORMAT_VERSION));
    }

    #[test]
    fn scope_change_needs_rebuild() {
        let db = db();
        db.check_or_init(1).unwrap();
        assert!(matches!(
            db.check_or_init(2).unwrap(),
            InitOutcome::NeedsRebuild { .. }
        ));
    }

    #[test]
    fn newer_format_refuses() {
        let db = db();
        db.backend
            .put(
                &keys::meta_format_version(),
                &(FORMAT_VERSION + 1).to_be_bytes(),
            )
            .unwrap();
        assert!(matches!(
            db.check_or_init(1),
            Err(IndexError::NewerFormat { .. })
        ));
    }

    #[test]
    fn wipe_then_fresh() {
        let db = db();
        db.check_or_init(7).unwrap();
        db.commit(&IndexDb::cursor_put_ops(100, Some([9u8; 32])))
            .unwrap();
        db.wipe().unwrap();
        assert_eq!(db.cursor_height().unwrap(), None);
        assert_eq!(db.check_or_init(7).unwrap(), InitOutcome::Fresh);
    }
}
