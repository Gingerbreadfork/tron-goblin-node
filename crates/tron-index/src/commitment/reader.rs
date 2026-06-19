//! Cheap-clone read handle for the RPC layer.
//!
//! Mirrors [`crate::ArchiveReader`]: a `Clone` wrapper holding only an
//! `Arc`-backed [`CommitmentStore`] plus the shared live counters, with NO
//! write-side state. The background builder is the sole writer; the reader
//! sees the latest committed root/height through the store and the live
//! `head_height` through the shared [`CommitmentCounters`].

use std::sync::Arc;

use tron_chainbase::UndoStoreId;
use tron_crypto::keccak256;

use crate::commitment::builder::CommitmentCounters;
use crate::commitment::smt::{CommitmentError, LeafPath, NodeHash, Proof, Smt, EMPTY_ROOT};
use crate::commitment::store::CommitmentStore;

/// Read side of the commitment layer. Cheap to clone.
#[derive(Clone)]
pub struct CommitmentReader {
    store: CommitmentStore,
    counters: Arc<CommitmentCounters>,
    confirmation_lag_blocks: u64,
}

/// A point-in-time view of the commitment layer's progress, surfaced by the
/// RPC `/status` route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentStatus {
    /// Folded-into-tree watermark. Trails `head_height` by ~`confirmation_lag_blocks`.
    pub committed_height: Option<i64>,
    /// Max height the builder has seen on the channel (≈ live head).
    pub head_height: Option<i64>,
    /// The configured confirmation depth K (echoed for clients).
    pub confirmation_lag_blocks: u64,
    /// Current committed root (EMPTY_ROOT before any fold).
    pub root: NodeHash,
    /// `true` while the full-state Merkleize is still running.
    pub bootstrapping: bool,
    /// Leaves folded so far during bootstrap (progress reporting).
    pub bootstrap_keys_done: u64,
}

/// Derive the SMT leaf path for a raw store key: `keccak256(store_id ‖ key)`.
pub fn leaf_path_for(store: UndoStoreId, raw_key: &[u8]) -> LeafPath {
    let mut buf = Vec::with_capacity(1 + raw_key.len());
    buf.push(store as u8);
    buf.extend_from_slice(raw_key);
    keccak256(&buf)
}

impl CommitmentReader {
    pub fn new(
        store: CommitmentStore,
        counters: Arc<CommitmentCounters>,
        confirmation_lag_blocks: u64,
    ) -> Self {
        Self {
            store,
            counters,
            confirmation_lag_blocks,
        }
    }

    /// `(committed_height, root)`. Returns `(committed_height, EMPTY_ROOT)`
    /// when no leaves are folded yet; the height is `-1` before the first
    /// commit so callers can detect "not yet committed".
    pub fn root(&self) -> Result<(i64, NodeHash), CommitmentError> {
        let height = self.store.committed_height()?.unwrap_or(-1);
        let root = self.store.root()?;
        Ok((height, root))
    }

    /// Generate an inclusion/exclusion proof for `(store, raw_key)` against
    /// the current committed root.
    pub fn prove(&self, store: UndoStoreId, raw_key: &[u8]) -> Result<Proof, CommitmentError> {
        let root = self.store.root().unwrap_or(EMPTY_ROOT);
        let smt = Smt::open(&self.store, root);
        let path = leaf_path_for(store, raw_key);
        smt.prove(&path)
    }

    /// Full status snapshot for the `/status` route.
    pub fn status(&self) -> Result<CommitmentStatus, CommitmentError> {
        let meta = self.store.meta()?;
        let head = self.counters.head_height();
        Ok(CommitmentStatus {
            committed_height: meta.committed_height,
            head_height: if head < 0 { None } else { Some(head) },
            confirmation_lag_blocks: self.confirmation_lag_blocks,
            root: meta.root,
            bootstrapping: meta.bootstrap_progress.is_some(),
            bootstrap_keys_done: meta.bootstrap_keys_done,
        })
    }
}
