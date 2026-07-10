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
use crate::commitment::proof::reconstruct_root;
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
    /// `true` while the committed root has NOT yet canonically converged after
    /// a bootstrap/re-bootstrap: the committed height is still below the scan
    /// horizon, so the tree is a fuzzy cut that matches no single canonical
    /// height. A cross-node root comparison must ignore a provisional root
    /// (comparing one would raise a false divergence alarm).
    pub provisional: bool,
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
        self.consistent_height_root()
    }

    /// Read `(committed_height, root)` as one self-consistent pair.
    ///
    /// The committed height and root are independent point reads over the
    /// store, and the background builder commits both in a single atomic
    /// `commit_block` batch. A batch landing between the two reads could
    /// otherwise pair a height with a root from the adjacent generation,
    /// mislabelling the tuple — a transient false alarm for a cross-node root
    /// comparison. The committed height doubles as a seqlock: sample it, read
    /// the root, then re-sample the height, and accept the pair only when the
    /// two height samples agree (no commit intervened). A bounded number of
    /// retries covers a commit racing the read; sustained churn beyond that
    /// falls back to a plain read, since the pair is best-effort comparison
    /// metadata, not consensus state.
    fn consistent_height_root(&self) -> Result<(i64, NodeHash), CommitmentError> {
        const MAX_ATTEMPTS: usize = 8;
        for _ in 0..MAX_ATTEMPTS {
            let before = self.store.committed_height()?.unwrap_or(-1);
            let root = self.store.root()?;
            let after = self.store.committed_height()?.unwrap_or(-1);
            if before == after {
                return Ok((before, root));
            }
        }
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

    /// Generate a proof together with the root it reconstructs to and the
    /// committed height it is anchored at, as one self-consistent triple.
    ///
    /// The served root is the one the proof itself folds up to
    /// ([`reconstruct_root`]), NOT a root read separately from the store, so
    /// the returned `(root, proof)` ALWAYS verifies — there is no window in
    /// which a concurrent fold could make the served root and proof disagree.
    /// The background builder is the sole writer and commits each block's node
    /// rows, root, and height in one atomic batch; under the absence of a
    /// snapshot-isolated multi-key read at the backend layer, a proof walk
    /// racing a commit could in principle observe rows from two generations.
    /// Pinning the served root to the reconstruction makes such a pair benign:
    /// it stays internally consistent (the proof verifies against it). The
    /// anchor height and the root the proof is built against are read together
    /// through the seqlock in [`Self::consistent_height_root`], so the reported
    /// `height` reflects the same commit generation as that root rather than a
    /// separately-sampled one. `height` is `-1` before the first commit.
    pub fn prove_consistent(
        &self,
        store: UndoStoreId,
        raw_key: &[u8],
    ) -> Result<(i64, NodeHash, Proof), CommitmentError> {
        let (height, root) = self.consistent_height_root()?;
        let smt = Smt::open(&self.store, root);
        let path = leaf_path_for(store, raw_key);
        let proof = smt.prove(&path)?;
        // A proof drawn from a real tree always reconstructs (it is never
        // structurally malformed); fall back to the store root only if a
        // backend anomaly produced an unreconstructable proof.
        let served_root = reconstruct_root(&proof).unwrap_or(root);
        Ok((height, served_root, proof))
    }

    /// Whether the committed root is still provisional — the tree has not yet
    /// converged after a (re-)bootstrap (committed height below the scan
    /// horizon), so it matches no single canonical height.
    pub fn provisional(&self) -> Result<bool, CommitmentError> {
        Ok(match (self.store.committed_height()?, self.store.bootstrap_horizon()?) {
            (Some(c), Some(h)) => c < h,
            _ => false,
        })
    }

    /// Full status snapshot for the `/status` route.
    pub fn status(&self) -> Result<CommitmentStatus, CommitmentError> {
        let meta = self.store.meta()?;
        let head = self.counters.head_height();
        // Provisional until the fold-forward passes the bootstrap scan horizon.
        let provisional = match (meta.committed_height, meta.bootstrap_horizon) {
            (Some(c), Some(h)) => c < h,
            _ => false,
        };
        Ok(CommitmentStatus {
            committed_height: meta.committed_height,
            head_height: if head < 0 { None } else { Some(head) },
            confirmation_lag_blocks: self.confirmation_lag_blocks,
            root: meta.root,
            bootstrapping: meta.bootstrap_progress.is_some(),
            bootstrap_keys_done: meta.bootstrap_keys_done,
            provisional,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::builder::{
        CommitmentBuilder, CommitmentCounters, CommitmentDeltaRef,
    };
    use crate::commitment::proof::{verify_proof, ProofOutcome};
    use std::sync::Arc;
    use tron_chainbase::MemBackend;

    const K: u64 = 2;

    fn delta(store: UndoStoreId, key: &[u8], val: &[u8]) -> CommitmentDeltaRef {
        CommitmentDeltaRef {
            store,
            key: key.to_vec(),
            after: Some(val.to_vec()),
        }
    }

    /// Fold heights `1..=n` of single-key Accounts writes and return the
    /// reader plus the values that ended up committed (below the K ceiling).
    fn reader_with_blocks(n: i64) -> CommitmentReader {
        let store = CommitmentStore::new(Arc::new(MemBackend::new()));
        store.check_or_init().unwrap();
        let mut b = CommitmentBuilder::new(
            store,
            Vec::new(),
            K,
            Arc::new(CommitmentCounters::new()),
        )
        .unwrap();
        b.bootstrap_or_resume(0).unwrap();
        for h in 1..=n {
            let key = h.to_be_bytes().to_vec();
            b.ingest(h, vec![delta(UndoStoreId::Accounts, &key, &[h as u8])])
                .unwrap();
        }
        b.reader()
    }

    #[test]
    fn prove_consistent_pair_always_verifies() {
        let reader = reader_with_blocks(5); // committed up to 5 - K = 3.

        // Inclusion: a committed key (height 1, well below the ceiling).
        let key1 = 1i64.to_be_bytes().to_vec();
        let (h, root, proof) = reader
            .prove_consistent(UndoStoreId::Accounts, &key1)
            .unwrap();
        assert_eq!(h, 3);
        assert!(proof.leaf_value_hash.is_some());
        // The served root is exactly what the proof reconstructs to, so the
        // pair verifies with the committed value.
        assert_eq!(
            verify_proof(&root, &proof, Some(&[1u8])),
            ProofOutcome::Included
        );
        // The served root matches the store's committed root (no concurrency).
        assert_eq!(root, reader.root().unwrap().1);

        // Exclusion: a key that was never folded.
        let absent = b"never".to_vec();
        let (_, root_ex, proof_ex) = reader
            .prove_consistent(UndoStoreId::Accounts, &absent)
            .unwrap();
        assert!(proof_ex.leaf_value_hash.is_none());
        assert_eq!(verify_proof(&root_ex, &proof_ex, None), ProofOutcome::Excluded);
    }

    #[test]
    fn root_pairs_committed_height_with_current_root() {
        let reader = reader_with_blocks(5); // committed up to 5 - K = 3.
        let (h, root) = reader.root().unwrap();
        // The seqlock read returns the store's committed height paired with the
        // matching root.
        assert_eq!(h, 3);
        assert_eq!(Some(h), reader.store.committed_height().unwrap());
        assert_eq!(root, reader.store.root().unwrap());
    }

    #[test]
    fn root_is_provisional_until_committed_passes_the_bootstrap_horizon() {
        let store = CommitmentStore::new(Arc::new(MemBackend::new()));
        store.check_or_init().unwrap();
        // Bootstrap anchored at height 100 but the live head reached 150 during
        // the scan: the tree is a fuzzy cut, so the committed root is provisional.
        store.finish_bootstrap(100, &EMPTY_ROOT, 150).unwrap();
        let reader =
            CommitmentReader::new(store.clone(), Arc::new(CommitmentCounters::new()), K);
        assert!(reader.provisional().unwrap(), "below horizon → provisional");
        assert!(reader.status().unwrap().provisional);

        // Fold forward past the horizon: the tree is now canonical.
        store.commit_block(&[], 150, &EMPTY_ROOT, true).unwrap();
        assert!(!reader.provisional().unwrap(), "at/above horizon → converged");
        assert!(!reader.status().unwrap().provisional);
    }

    #[test]
    fn prove_consistent_on_empty_tree_excludes_against_empty_root() {
        let store = CommitmentStore::new(Arc::new(MemBackend::new()));
        store.check_or_init().unwrap();
        let reader =
            CommitmentReader::new(store, Arc::new(CommitmentCounters::new()), K);
        let (h, root, proof) = reader
            .prove_consistent(UndoStoreId::Accounts, b"anything")
            .unwrap();
        assert_eq!(h, -1, "no commit yet");
        assert_eq!(root, EMPTY_ROOT);
        assert!(proof.leaf_value_hash.is_none());
        assert_eq!(verify_proof(&root, &proof, None), ProofOutcome::Excluded);
    }
}
