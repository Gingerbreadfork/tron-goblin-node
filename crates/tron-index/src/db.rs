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

/// Reset-in-progress marker (empty value). [`IndexDb::wipe`] is a
/// multi-batch delete; the marker makes a crash mid-wipe re-resolve as
/// [`InitOutcome::NeedsRebuild`] rather than a fresh DB behind surviving
/// rows. Lives in `NS_META` alongside the other bookkeeping stamps.
fn meta_wiping() -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 6);
    k.push(keys::NS_META);
    k.extend_from_slice(b"wiping");
    k
}

/// The `NS_META ‖ "id_at/"` / `NS_META ‖ "keys_at/"` scan prefixes,
/// derived from the canonical key builder minus its 8-byte height
/// suffix so the layout stays defined in exactly one place.
fn ring_id_prefix() -> Vec<u8> {
    let mut p = keys::meta_id_at(0);
    p.truncate(p.len() - 8);
    p
}

fn ring_keys_prefix() -> Vec<u8> {
    let mut p = keys::meta_keys_at(0);
    p.truncate(p.len() - 8);
    p
}

/// Recover the height encoded in a ring key's 8-byte big-endian suffix.
fn ring_height_of(key: &[u8], prefix: &[u8]) -> Option<i64> {
    let suffix: [u8; 8] = key.get(prefix.len()..)?.try_into().ok()?;
    Some(u64::from_be_bytes(suffix) as i64)
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
        // A crash during a multi-batch [`wipe`] leaves this durable
        // marker set with the version stamp (which sorts first) already
        // deleted but later row namespaces still on disk. Resolve that
        // half-emptied state to a rebuild rather than a fresh cold-start,
        // so the stale rows are dropped instead of resumed as complete.
        if self.backend.get(&meta_wiping())?.is_some() {
            return Ok(InitOutcome::NeedsRebuild {
                reason: "index wipe interrupted before completion",
            });
        }
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
    ///
    /// The wipe spans several batches, and the meta stamps sort first,
    /// so a naive delete would drop the version stamp in the opening
    /// batch and leave later row namespaces behind — a crash there would
    /// re-open as a fresh empty DB shadowing stale rows. A durable
    /// `wiping` marker, set before the first delete and cleared only
    /// after the last, forces an interrupted wipe to re-resolve as
    /// [`InitOutcome::NeedsRebuild`] instead (see [`check_or_init`]).
    ///
    /// [`check_or_init`]: Self::check_or_init
    pub fn wipe(&self) -> Result<(), IndexError> {
        let wiping = meta_wiping();
        self.backend
            .write_batch(&[WriteOp::Put(wiping.clone(), Vec::new())])?;
        self.backend.sync_wal()?;
        let all = self.backend.scan_all()?;
        let ops: Vec<WriteOp> = all
            .into_iter()
            .map(|(k, _)| k)
            .filter(|k| *k != wiping)
            .map(WriteOp::Delete)
            .collect();
        for chunk in ops.chunks(100_000) {
            self.backend.write_batch(chunk)?;
        }
        // Clear the marker last: only now, with every row gone, is the DB
        // genuinely fresh. Make the clear durable so a fresh stamp is
        // never shadowed by a surviving marker.
        self.backend.write_batch(&[WriteOp::Delete(wiping)])?;
        self.backend.sync_wal()?;
        Ok(())
    }

    // -- cursor / edges ------------------------------------------------------

    fn get_i64(&self, key: &[u8]) -> Result<Option<i64>, IndexError> {
        let Some(bytes) = self.backend.get(key)? else {
            return Ok(None);
        };
        // A present-but-wrong-length value is corruption, not absence:
        // coercing it to `None` would silently re-trigger a full
        // re-backfill (or misreport a reorg deeper than the ring). Hard-
        // error like [`cursor`] does.
        //
        // [`cursor`]: Self::cursor
        let value: [u8; 8] = bytes.as_slice().try_into().map_err(|_| {
            IndexError::Corrupt(format!("meta i64 has {} bytes (want 8)", bytes.len()))
        })?;
        Ok(Some(i64::from_be_bytes(value)))
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
        let Some(bytes) = self.backend.get(&keys::meta_id_at(height))? else {
            return Ok(None);
        };
        // A wrong-length ring id is corruption, not a missing entry: a
        // reorg unwind mistaking it for absent would hard-error on a
        // phantom hole. Surface the real fault (matches [`cursor`]).
        //
        // [`cursor`]: Self::cursor
        let id: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            IndexError::Corrupt(format!(
                "ring id_at/{height} has {} bytes (want 32)",
                bytes.len()
            ))
        })?;
        Ok(Some(id))
    }

    pub fn keys_at(&self, height: i64) -> Result<Option<Vec<Vec<u8>>>, IndexError> {
        match self.backend.get(&keys::meta_keys_at(height))? {
            None => Ok(None),
            Some(bytes) => keys::decode_key_list(&bytes)
                .map(Some)
                .ok_or_else(|| IndexError::Corrupt(format!("ring keys_at/{height} undecodable"))),
        }
    }

    /// Delete `id_at/` + `keys_at/` ring entries recorded strictly below
    /// `threshold`, returning the number of entries removed. The engine's
    /// per-block prune only trims the single height leaving the ring
    /// window each block, so entries stranded below the window by
    /// downtime longer than the ring depth are never revisited; this
    /// reclaims them. The height-BE key order lets the scan stop at the
    /// first live entry, and `limit` bounds one call so a large gap drains
    /// across successive sweeps rather than in one unbounded batch.
    pub fn prune_ring_below(&self, threshold: i64, limit: usize) -> Result<usize, IndexError> {
        let mut ops: Vec<WriteOp> = Vec::new();
        for prefix in [ring_id_prefix(), ring_keys_prefix()] {
            for (k, _) in self.backend.scan_from(&prefix, limit)? {
                if !k.starts_with(&prefix) {
                    break; // left the ring namespace
                }
                match ring_height_of(&k, &prefix) {
                    Some(h) if h >= threshold => break, // ascending: rest are live
                    Some(_) => ops.push(WriteOp::Delete(k)),
                    None => continue,
                }
            }
        }
        let pruned = ops.len();
        if pruned > 0 {
            self.backend.write_batch(&ops)?;
        }
        Ok(pruned)
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

    #[test]
    fn interrupted_wipe_needs_rebuild() {
        let db = db();
        db.check_or_init(7).unwrap();
        db.commit(&IndexDb::cursor_put_ops(100, Some([9u8; 32])))
            .unwrap();
        // Simulate a crash mid-wipe: the durable marker is set while the
        // version stamp and some rows are still present.
        db.backend
            .write_batch(&[WriteOp::Put(meta_wiping(), Vec::new())])
            .unwrap();
        assert!(matches!(
            db.check_or_init(7).unwrap(),
            InitOutcome::NeedsRebuild { .. }
        ));
        // A completed wipe clears the marker → genuinely fresh again.
        db.wipe().unwrap();
        assert!(db.backend.get(&meta_wiping()).unwrap().is_none());
        assert_eq!(db.check_or_init(7).unwrap(), InitOutcome::Fresh);
    }

    #[test]
    fn wrong_length_meta_is_corrupt() {
        let db = db();
        // A truncated i64 meta value must hard-error, not read as absent
        // (absence would silently re-trigger a full backfill).
        db.backend.put(&keys::meta_back_edge(), &[1, 2, 3]).unwrap();
        assert!(matches!(db.back_edge(), Err(IndexError::Corrupt(_))));
        db.backend.put(&keys::meta_floor(), &[0u8; 9]).unwrap();
        assert!(matches!(db.floor(), Err(IndexError::Corrupt(_))));
        // Same for a wrong-length ring id.
        db.backend.put(&keys::meta_id_at(5), &[0u8; 16]).unwrap();
        assert!(matches!(db.id_at(5), Err(IndexError::Corrupt(_))));
    }

    #[test]
    fn prune_ring_below_reclaims_stranded_entries() {
        let db = db();
        for h in [10i64, 20, 30, 40] {
            db.backend
                .write_batch(&[
                    WriteOp::Put(keys::meta_id_at(h), vec![h as u8; 32]),
                    WriteOp::Put(keys::meta_keys_at(h), keys::encode_key_list(&[])),
                ])
                .unwrap();
        }
        // Heights 10 and 20 fall below the threshold → 2 entries each.
        assert_eq!(db.prune_ring_below(30, 1000).unwrap(), 4);
        assert!(db.id_at(10).unwrap().is_none());
        assert!(db.id_at(20).unwrap().is_none());
        assert!(db.id_at(30).unwrap().is_some());
        assert!(db.id_at(40).unwrap().is_some());
        assert!(db.keys_at(20).unwrap().is_none());
        assert!(db.keys_at(30).unwrap().is_some());
        // Idempotent: nothing left below the threshold.
        assert_eq!(db.prune_ring_below(30, 1000).unwrap(), 0);
    }
}
