//! RocksDB-backed node store + meta rows.
//!
//! Implements [`NodeBackend`] over an `Arc<dyn KvBackend>` (the same backend
//! abstraction the archive uses). All commitment rows live in ONE keyspace,
//! prefix-tagged like the archive (crates/tron-index/src/archive.rs:56-57):
//!
//! ```text
//! TAG_META = 0x00   format_version, committed_height, root, bootstrap_progress
//! TAG_NODE = 0x01   internal node: 0x01 ‖ level(2 BE) ‖ prefix(ceil(level/8) bytes)
//! TAG_LEAF = 0x02   leaf: 0x02 ‖ leaf_path(32) → value_hash(32)
//! ```
//!
//! A node at `level` is addressed by the top `level` bits of its subtree's
//! common prefix, packed MSB-first into `ceil(level/8)` bytes (the unused low
//! bits of the last byte are zero). Default nodes are never written — their
//! absence is the default. The format follows the archive's `check_or_init`
//! pattern: a format bump or a detected coverage break wipes and triggers a
//! full re-bootstrap (loudly — re-Merkleizing full state is expensive).

use std::sync::Arc;

use tron_chainbase::{KvBackend, WriteOp};

use crate::commitment::smt::{
    mask_prefix, CommitmentError, LeafPath, NodeBackend, NodeHash, NodeOp, DEPTH, EMPTY_ROOT,
};

/// Bumped on any layout/semantics change a reader could mis-interpret. A bump
/// wipes the node store and re-bootstraps at the current head.
///
/// v2: only branch nodes (two non-empty children) are persisted; single-child
/// and empty nodes are derived from the leaves on read. Roots and proofs are
/// byte-identical to v1, but the on-disk node set differs, so a v1 store must
/// be re-Merkleized.
pub const COMMITMENT_FORMAT_VERSION: u32 = 2;

const TAG_META: u8 = 0x00;
const TAG_NODE: u8 = 0x01;
const TAG_LEAF: u8 = 0x02;

/// Persisted meta snapshot read by the reader/builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentMeta {
    /// Folded-into-tree watermark; `None` before the first commit.
    pub committed_height: Option<i64>,
    /// Current root (EMPTY_ROOT before any leaves).
    pub root: NodeHash,
    /// In-progress bootstrap cursor, `None` once bootstrap completes.
    pub bootstrap_progress: Option<BootstrapCursor>,
    /// Cumulative leaves folded during the current bootstrap (progress
    /// reporting).
    pub bootstrap_keys_done: u64,
    /// Live chain head captured when the last bootstrap/re-bootstrap scan
    /// completed. The scan reflects a fuzzy cut of state up to (at most) this
    /// height, so a committed root BELOW it has not yet canonically
    /// converged — clients comparing roots across nodes must treat it as
    /// provisional. `None` before any bootstrap.
    pub bootstrap_horizon: Option<i64>,
}

/// Resumable bootstrap position: the store currently being scanned (its
/// `UndoStoreId` discriminant) and the next key to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapCursor {
    /// `UndoStoreId as u8` of the store being scanned.
    pub store_id: u8,
    /// Next key to read (`scan_from` start). Empty = the store's first key.
    pub next_key: Vec<u8>,
    /// Anchor height the bootstrap Merkleizes at.
    pub anchor: i64,
}

fn meta_key(name: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + name.len());
    k.push(TAG_META);
    k.extend_from_slice(name);
    k
}

/// The reset-in-progress marker. A coverage reset wipes everything; without a
/// durable marker a power loss mid-wipe could leave stale node rows behind a
/// fresh stamp.
fn meta_wiping() -> Vec<u8> {
    meta_key(b"wiping")
}

/// Encode an internal-node row key: `0x01 ‖ level(2 BE) ‖ prefix(ceil(level/8))`.
fn node_key(level: usize, prefix: &LeafPath) -> Vec<u8> {
    debug_assert!(level <= DEPTH);
    let canon = mask_prefix(prefix, level);
    let prefix_bytes = level.div_ceil(8);
    let mut k = Vec::with_capacity(1 + 2 + prefix_bytes);
    k.push(TAG_NODE);
    k.extend_from_slice(&(level as u16).to_be_bytes());
    k.extend_from_slice(&canon[..prefix_bytes]);
    k
}

/// Encode a leaf row key: `0x02 ‖ leaf_path(32)`.
fn leaf_key(path: &LeafPath) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 32);
    k.push(TAG_LEAF);
    k.extend_from_slice(path);
    k
}

/// RocksDB-backed commitment node store. The single background builder task is
/// the only writer; readers clone the `Arc<dyn KvBackend>` cheaply.
#[derive(Clone)]
pub struct CommitmentStore {
    backend: Arc<dyn KvBackend>,
}

impl CommitmentStore {
    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    /// Clone the underlying backend handle (cheap — it is an `Arc`).
    pub fn backend(&self) -> Arc<dyn KvBackend> {
        self.backend.clone()
    }

    fn be_err(e: tron_chainbase::KvError) -> CommitmentError {
        CommitmentError::Backend(e.to_string())
    }

    /// Read a fixed-width big-endian meta value. A **present** value of the
    /// wrong length is a `Corrupt` error, NOT `None`: coercing it to `None`
    /// (== "absent") would, for `committed_height`, silently trigger a fresh
    /// additive bootstrap over a non-empty tree and produce a permanently
    /// wrong root that nothing detects.
    fn get_fixed<const N: usize>(&self, name: &[u8]) -> Result<Option<[u8; N]>, CommitmentError> {
        match self.backend.get(&meta_key(name)).map_err(Self::be_err)? {
            None => Ok(None),
            Some(v) => <[u8; N]>::try_from(v.as_slice()).map(Some).map_err(|_| {
                CommitmentError::Corrupt(format!(
                    "commitment meta {} is {} bytes, expected {N}",
                    String::from_utf8_lossy(name),
                    v.len()
                ))
            }),
        }
    }

    fn get_u32(&self, name: &[u8]) -> Result<Option<u32>, CommitmentError> {
        Ok(self.get_fixed::<4>(name)?.map(u32::from_be_bytes))
    }

    fn get_i64(&self, name: &[u8]) -> Result<Option<i64>, CommitmentError> {
        Ok(self.get_fixed::<8>(name)?.map(i64::from_be_bytes))
    }

    fn get_u64(&self, name: &[u8]) -> Result<Option<u64>, CommitmentError> {
        Ok(self.get_fixed::<8>(name)?.map(u64::from_be_bytes))
    }

    /// Check or stamp the on-disk format. Returns `true` when this is a fresh
    /// (just-stamped or just-wiped) store that must be bootstrapped. Mirrors
    /// the archive's `check_or_init`: a format bump or an interrupted wipe
    /// wipes and re-bootstraps; a newer format is a hard error.
    pub fn check_or_init(&self) -> Result<bool, CommitmentError> {
        // Finish an interrupted wipe before trusting anything else on disk.
        if self
            .backend
            .get(&meta_wiping())
            .map_err(Self::be_err)?
            .is_some()
        {
            tracing::warn!("commitment: resuming an interrupted store reset");
            self.finish_reset()?;
            return Ok(true);
        }
        match self.get_u32(b"format_version")? {
            None => {
                self.backend
                    .write_batch(&[WriteOp::Put(
                        meta_key(b"format_version"),
                        COMMITMENT_FORMAT_VERSION.to_be_bytes().to_vec(),
                    )])
                    .map_err(Self::be_err)?;
                Ok(true)
            }
            Some(v) if v == COMMITMENT_FORMAT_VERSION => Ok(false),
            Some(v) if v < COMMITMENT_FORMAT_VERSION => {
                tracing::warn!(
                    on_disk = v,
                    current = COMMITMENT_FORMAT_VERSION,
                    "commitment: format version bumped — wiping and re-Merkleizing at head"
                );
                self.wipe()?;
                Ok(true)
            }
            Some(v) => Err(CommitmentError::NewerFormat {
                on_disk: v,
                supported: COMMITMENT_FORMAT_VERSION,
            }),
        }
    }

    /// Two-phase crash-safe wipe: stamp a durable `wiping` marker, then delete
    /// everything except the marker and re-stamp the format version. A crash
    /// at any point either leaves the marker (the next open finishes the wipe)
    /// or completes; stale rows can never survive behind a fresh stamp.
    pub fn wipe(&self) -> Result<(), CommitmentError> {
        self.backend
            .write_batch(&[WriteOp::Put(meta_wiping(), Vec::new())])
            .map_err(Self::be_err)?;
        self.backend.sync_wal().map_err(Self::be_err)?;
        self.finish_reset()
    }

    fn finish_reset(&self) -> Result<(), CommitmentError> {
        let wiping = meta_wiping();
        // Delete every row except the wiping marker, streaming in bounded
        // chunks. scan_all would materialize the entire node store (which for a
        // populated commitment is multi-GB to TB) in one allocation and OOM the
        // node — and the durable `wiping` marker then re-OOMs on every reopen.
        const CHUNK: usize = 50_000;
        let mut cursor: Vec<u8> = Vec::new();
        loop {
            let rows = self.backend.scan_from(&cursor, CHUNK).map_err(Self::be_err)?;
            let Some((last, _)) = rows.last() else {
                break;
            };
            let mut next = last.clone();
            let ops: Vec<WriteOp> = rows
                .iter()
                .filter(|(k, _)| *k != wiping)
                .map(|(k, _)| WriteOp::Delete(k.clone()))
                .collect();
            if !ops.is_empty() {
                self.backend.write_batch(&ops).map_err(Self::be_err)?;
            }
            next.push(0);
            cursor = next;
        }
        self.backend
            .write_batch(&[
                WriteOp::Put(
                    meta_key(b"format_version"),
                    COMMITMENT_FORMAT_VERSION.to_be_bytes().to_vec(),
                ),
                WriteOp::Delete(wiping),
            ])
            .map_err(Self::be_err)?;
        self.backend.sync_wal().map_err(Self::be_err)?;
        Ok(())
    }

    /// Folded-into-tree watermark; `None` before the first commit.
    pub fn committed_height(&self) -> Result<Option<i64>, CommitmentError> {
        self.get_i64(b"committed_height")
    }

    /// Current root — [`EMPTY_ROOT`] if no leaves have been folded yet.
    pub fn root(&self) -> Result<NodeHash, CommitmentError> {
        match self.backend.get(&meta_key(b"root")).map_err(Self::be_err)? {
            Some(v) => <[u8; 32]>::try_from(v.as_slice())
                .map_err(|_| CommitmentError::Corrupt("root meta is not 32 bytes".into())),
            None => Ok(EMPTY_ROOT),
        }
    }

    /// In-progress bootstrap cursor, `None` once bootstrap completes.
    pub fn bootstrap_progress(&self) -> Result<Option<BootstrapCursor>, CommitmentError> {
        let Some(bytes) = self
            .backend
            .get(&meta_key(b"bootstrap_progress"))
            .map_err(Self::be_err)?
        else {
            return Ok(None);
        };
        // Layout: store_id(1) ‖ anchor(8 BE) ‖ next_key(rest).
        if bytes.len() < 9 {
            return Err(CommitmentError::Corrupt(
                "bootstrap_progress meta too short".into(),
            ));
        }
        let store_id = bytes[0];
        let anchor = i64::from_be_bytes(bytes[1..9].try_into().unwrap());
        let next_key = bytes[9..].to_vec();
        Ok(Some(BootstrapCursor {
            store_id,
            next_key,
            anchor,
        }))
    }

    /// Cumulative leaves folded during the current bootstrap.
    pub fn bootstrap_keys_done(&self) -> Result<u64, CommitmentError> {
        Ok(self.get_u64(b"bootstrap_keys_done")?.unwrap_or(0))
    }

    /// Snapshot every meta field in one place.
    pub fn meta(&self) -> Result<CommitmentMeta, CommitmentError> {
        Ok(CommitmentMeta {
            committed_height: self.committed_height()?,
            root: self.root()?,
            bootstrap_progress: self.bootstrap_progress()?,
            bootstrap_keys_done: self.bootstrap_keys_done()?,
            bootstrap_horizon: self.bootstrap_horizon()?,
        })
    }

    /// Live head captured at the last bootstrap's scan completion (see
    /// [`CommitmentMeta::bootstrap_horizon`]).
    pub fn bootstrap_horizon(&self) -> Result<Option<i64>, CommitmentError> {
        self.get_i64(b"bootstrap_horizon")
    }

    /// Encode a [`BootstrapCursor`] into its meta row value.
    fn encode_cursor(cursor: &BootstrapCursor) -> Vec<u8> {
        let mut v = Vec::with_capacity(9 + cursor.next_key.len());
        v.push(cursor.store_id);
        v.extend_from_slice(&cursor.anchor.to_be_bytes());
        v.extend_from_slice(&cursor.next_key);
        v
    }

    /// Translate a batch of [`NodeOp`]s into backend [`WriteOp`]s.
    fn node_ops_to_writes(ops: &[NodeOp]) -> Vec<WriteOp> {
        let mut out = Vec::with_capacity(ops.len());
        for op in ops {
            match op {
                NodeOp::PutLeaf(p, h) => out.push(WriteOp::Put(leaf_key(p), h.to_vec())),
                NodeOp::DeleteLeaf(p) => out.push(WriteOp::Delete(leaf_key(p))),
                NodeOp::PutNode { level, prefix, hash } => {
                    out.push(WriteOp::Put(node_key(*level, prefix), hash.to_vec()))
                }
                NodeOp::DeleteNode { level, prefix } => {
                    out.push(WriteOp::Delete(node_key(*level, prefix)))
                }
            }
        }
        out
    }

    /// Persist a batch of node ops together with the new committed height and
    /// root, atomically. A crash leaves height/root consistent with the node
    /// set. `sync` flushes the WAL (the periodic durability barrier).
    pub fn commit_block(
        &self,
        ops: &[NodeOp],
        committed_height: i64,
        root: &NodeHash,
        sync: bool,
    ) -> Result<(), CommitmentError> {
        let mut writes = Self::node_ops_to_writes(ops);
        writes.push(WriteOp::Put(
            meta_key(b"committed_height"),
            committed_height.to_be_bytes().to_vec(),
        ));
        writes.push(WriteOp::Put(meta_key(b"root"), root.to_vec()));
        if sync {
            self.backend.write_batch_sync(&writes).map_err(Self::be_err)
        } else {
            self.backend.write_batch(&writes).map_err(Self::be_err)
        }
    }

    /// Persist a bootstrap chunk: node ops + an advanced cursor + the running
    /// key count, atomically so a crash resumes from a consistent position.
    pub fn commit_bootstrap_chunk(
        &self,
        ops: &[NodeOp],
        cursor: &BootstrapCursor,
        keys_done: u64,
    ) -> Result<(), CommitmentError> {
        let mut writes = Self::node_ops_to_writes(ops);
        writes.push(WriteOp::Put(
            meta_key(b"bootstrap_progress"),
            Self::encode_cursor(cursor),
        ));
        writes.push(WriteOp::Put(
            meta_key(b"bootstrap_keys_done"),
            keys_done.to_be_bytes().to_vec(),
        ));
        self.backend.write_batch(&writes).map_err(Self::be_err)
    }

    /// Finalize a completed bootstrap: record the anchor as `committed_height`
    /// and the root, the live head at scan completion as the convergence
    /// `horizon`, and clear the bootstrap cursor. Synced for durability.
    pub fn finish_bootstrap(
        &self,
        anchor: i64,
        root: &NodeHash,
        horizon: i64,
    ) -> Result<(), CommitmentError> {
        self.backend
            .write_batch_sync(&[
                WriteOp::Put(
                    meta_key(b"committed_height"),
                    anchor.to_be_bytes().to_vec(),
                ),
                WriteOp::Put(meta_key(b"root"), root.to_vec()),
                WriteOp::Put(
                    meta_key(b"bootstrap_horizon"),
                    horizon.to_be_bytes().to_vec(),
                ),
                WriteOp::Delete(meta_key(b"bootstrap_progress")),
            ])
            .map_err(Self::be_err)
    }

    /// Overwrite only the committed-height and root meta rows, atomically and
    /// synced, leaving the node/leaf rows untouched. Currently exercised only
    /// by the store's own unit tests; the builder's re-bootstrap path finalizes
    /// through [`Self::finish_bootstrap`] and keeps `committed_height = anchor`,
    /// so it does not use this.
    pub fn set_height_and_root(
        &self,
        committed_height: i64,
        root: &NodeHash,
    ) -> Result<(), CommitmentError> {
        self.backend
            .write_batch_sync(&[
                WriteOp::Put(
                    meta_key(b"committed_height"),
                    committed_height.to_be_bytes().to_vec(),
                ),
                WriteOp::Put(meta_key(b"root"), root.to_vec()),
            ])
            .map_err(Self::be_err)
    }
}

impl NodeBackend for CommitmentStore {
    fn get_node(&self, level: usize, prefix: &LeafPath) -> Result<Option<NodeHash>, CommitmentError> {
        match self.backend.get(&node_key(level, prefix)).map_err(Self::be_err)? {
            Some(v) => Ok(Some(<[u8; 32]>::try_from(v.as_slice()).map_err(|_| {
                CommitmentError::Corrupt("node row is not 32 bytes".into())
            })?)),
            None => Ok(None),
        }
    }

    fn write_nodes(&self, ops: &[NodeOp]) -> Result<(), CommitmentError> {
        let writes = Self::node_ops_to_writes(ops);
        self.backend.write_batch(&writes).map_err(Self::be_err)
    }

    fn get_leaf(&self, path: &LeafPath) -> Result<Option<NodeHash>, CommitmentError> {
        match self.backend.get(&leaf_key(path)).map_err(Self::be_err)? {
            Some(v) => Ok(Some(<[u8; 32]>::try_from(v.as_slice()).map_err(|_| {
                CommitmentError::Corrupt("leaf row is not 32 bytes".into())
            })?)),
            None => Ok(None),
        }
    }

    fn leaves_under(
        &self,
        level: usize,
        prefix: &LeafPath,
        limit: usize,
    ) -> Result<Vec<(LeafPath, NodeHash)>, CommitmentError> {
        let want = mask_prefix(prefix, level);
        // Leaves are keyed `0x02 ‖ path(32)`, so the subtree is a contiguous
        // range from its low bound. Scan `limit` rows and keep the leading run
        // that stays within the subtree; the first row past it (or a non-leaf
        // row) ends the run, since keys are in ascending order.
        let rows = self
            .backend
            .scan_from(&leaf_key(&want), limit)
            .map_err(Self::be_err)?;
        let mut out = Vec::with_capacity(rows.len());
        for (k, v) in rows {
            if k.first() != Some(&TAG_LEAF) || k.len() != 1 + 32 {
                break; // left the leaf keyspace
            }
            let mut path = [0u8; 32];
            path.copy_from_slice(&k[1..33]);
            if mask_prefix(&path, level) != want {
                break; // left the subtree
            }
            let vh = <[u8; 32]>::try_from(v.as_slice()).map_err(|_| {
                CommitmentError::Corrupt("leaf row is not 32 bytes".into())
            })?;
            out.push((path, vh));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tron_chainbase::MemBackend;

    fn store() -> CommitmentStore {
        CommitmentStore::new(Arc::new(MemBackend::new()))
    }

    #[test]
    fn check_or_init_is_fresh_then_clean() {
        let s = store();
        assert!(s.check_or_init().unwrap(), "first open is fresh");
        assert!(!s.check_or_init().unwrap(), "second open is clean");
        assert_eq!(s.committed_height().unwrap(), None);
        assert_eq!(s.root().unwrap(), EMPTY_ROOT);
    }

    #[test]
    fn wrong_length_committed_height_meta_is_corrupt_not_absent() {
        let s = store();
        s.check_or_init().unwrap();
        // Write a truncated (3-byte) committed_height value directly.
        s.backend
            .put(&meta_key(b"committed_height"), &[1, 2, 3])
            .unwrap();
        match s.committed_height() {
            Err(CommitmentError::Corrupt(_)) => {}
            other => panic!("expected Corrupt for a wrong-length meta, got {other:?}"),
        }
    }

    #[test]
    fn node_key_packs_prefix_bytes() {
        // Level 0 → 0 prefix bytes; level 8 → 1; level 9 → 2; level 256 → 32.
        let p = [0xFFu8; 32];
        assert_eq!(node_key(0, &p).len(), 1 + 2 + 0);
        assert_eq!(node_key(8, &p).len(), 1 + 2 + 1);
        assert_eq!(node_key(9, &p).len(), 1 + 2 + 2);
        assert_eq!(node_key(256, &p).len(), 1 + 2 + 32);
        // The boundary byte keeps only the significant bits.
        let k9 = node_key(9, &[0xFFu8; 32]);
        // level 9: byte 0 = 0xFF (8 bits) + byte 1 top bit only = 0x80.
        assert_eq!(k9[3], 0xFF);
        assert_eq!(k9[4], 0x80);
    }

    #[test]
    fn roundtrip_leaf_and_node_via_nodebackend() {
        let s = store();
        let path = [0x12u8; 32];
        let h = [0x34u8; 32];
        s.write_nodes(&[
            NodeOp::PutLeaf(path, h),
            NodeOp::PutNode { level: 5, prefix: path, hash: h },
        ])
        .unwrap();
        assert_eq!(s.get_leaf(&path).unwrap(), Some(h));
        assert_eq!(s.get_node(5, &path).unwrap(), Some(h));
        // A different prefix at the same level that masks to the same node IS
        // the same row (lower bits ignored).
        let mut p2 = path;
        p2[31] = 0x00; // below level 5, ignored
        assert_eq!(s.get_node(5, &p2).unwrap(), Some(h));
        s.write_nodes(&[NodeOp::DeleteLeaf(path), NodeOp::DeleteNode { level: 5, prefix: path }])
            .unwrap();
        assert_eq!(s.get_leaf(&path).unwrap(), None);
        assert_eq!(s.get_node(5, &path).unwrap(), None);
    }

    #[test]
    fn wipe_clears_rows_and_restamps() {
        let s = store();
        s.check_or_init().unwrap();
        s.write_nodes(&[NodeOp::PutLeaf([1u8; 32], [2u8; 32])]).unwrap();
        s.set_height_and_root(100, &[9u8; 32]).unwrap();
        s.wipe().unwrap();
        assert_eq!(s.get_leaf(&[1u8; 32]).unwrap(), None);
        assert_eq!(s.committed_height().unwrap(), None);
        // Format stamp survives the wipe.
        assert!(!s.check_or_init().unwrap());
    }
}
