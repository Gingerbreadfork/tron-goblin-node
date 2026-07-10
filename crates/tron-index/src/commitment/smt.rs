//! Byte-exact Sparse Merkle Tree core (pure, no I/O).
//!
//! A 256-level binary Sparse Merkle Tree over keccak256. The root is a pure
//! function of the current `path → value-hash` leaf set — never of the order
//! in which leaves were inserted or deleted — so two nodes that converge to
//! the same state compute the identical root (the history-independence
//! invariant). Every hash here is normative: an independent re-implementation
//! that follows the same formulas produces byte-identical roots.
//!
//! Hashing scheme (domain-separated to prevent a leaf being forged as an
//! internal node, and to bind each value to its key):
//!
//! ```text
//! leaf node     = keccak256( 0x00 ‖ leaf_path(32) ‖ value_hash(32) )
//! internal node = keccak256( 0x01 ‖ left(32) ‖ right(32) )
//! default[256]  = [0u8; 32]                                  (empty leaf slot)
//! default[i]    = keccak256( 0x01 ‖ default[i+1] ‖ default[i+1] )   i = 255..0
//! ```
//!
//! `default[0]` is [`EMPTY_ROOT`], the root of a tree with no leaves. The
//! empty-child short-circuit (an internal node whose children both equal
//! `default[level+1]` IS `default[level]`) is exact by construction — it is
//! the identical formula the default array was built with, so it changes no
//! hash; it only keeps empty subtrees unmaterialized.
//!
//! Path bits are read MSB-first: bit `i` (for `i` in `0..256`) is
//! `(path[i/8] >> (7 - (i % 8))) & 1`. Bit 0 (the top bit of byte 0) selects
//! the child of the root; bit 255 selects the leaf's slot. Left child = bit 0,
//! right child = bit 1.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::OnceLock;

use tron_crypto::keccak256;

/// A 32-byte keccak256 digest used for every node and the root.
pub type NodeHash = [u8; 32];

/// The 256-bit path of a leaf: `keccak256(store_id_byte ‖ raw_key)`.
pub type LeafPath = [u8; 32];

/// Tree depth in levels. Level 0 is the root; level 256 is a leaf slot.
pub const DEPTH: usize = 256;

/// Domain-separation prefix for a leaf node.
pub const LEAF_PREFIX: u8 = 0x00;
/// Domain-separation prefix for an internal node.
pub const INTERNAL_PREFIX: u8 = 0x01;

/// Error surfaced by the SMT and its backends.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum CommitmentError {
    /// A backend (in-memory map or RocksDB store) read/write failed.
    #[error("commitment backend: {0}")]
    Backend(String),
    /// The persisted store is in an inconsistent or corrupt state.
    #[error("commitment corrupt: {0}")]
    Corrupt(String),
    /// The on-disk format is newer than this build understands.
    #[error("commitment format too new: on_disk={on_disk} supported={supported}")]
    NewerFormat { on_disk: u32, supported: u32 },
}

/// The 257 empty-subtree default hashes, computed once. `[0]` is
/// [`EMPTY_ROOT`]; `[256]` is `[0u8; 32]` (an empty leaf slot).
pub fn default_hashes() -> &'static [NodeHash; 257] {
    static DEFAULTS: OnceLock<[NodeHash; 257]> = OnceLock::new();
    DEFAULTS.get_or_init(|| {
        let mut d = [[0u8; 32]; 257];
        // d[256] is the empty leaf slot, left as [0u8; 32]. Fold upward with
        // the internal-node formula so the empty short-circuit is exact.
        for i in (0..DEPTH).rev() {
            d[i] = hash_internal_raw(&d[i + 1], &d[i + 1]);
        }
        d
    })
}

/// keccak of the all-empty tree — the root of a tree with no leaves.
/// Equal to `default_hashes()[0]`; pinned as a const and asserted in a test.
pub const EMPTY_ROOT: NodeHash = [
    0xca, 0x35, 0xb6, 0x0c, 0x4c, 0xbb, 0x11, 0xbc, 0x17, 0xb9, 0x02, 0x98, 0x9f, 0x14, 0xc5, 0x1d,
    0x76, 0x4d, 0xfb, 0x86, 0x5e, 0x9a, 0xde, 0x93, 0xd5, 0x7d, 0xf3, 0xde, 0xf6, 0x2a, 0x1e, 0x05,
];

/// Bit `i` of a path, MSB-first (i in `0..256`). Left = `false` (0), right =
/// `true` (1).
#[inline]
pub fn path_bit(path: &LeafPath, i: usize) -> bool {
    (path[i / 8] >> (7 - (i % 8))) & 1 == 1
}

/// Leaf node contribution: `keccak256(0x00 ‖ path ‖ value_hash)`. Including
/// the full path binds the value to its exact key, so a value cannot be
/// replayed at a different key.
pub fn hash_leaf(path: &LeafPath, value_hash: &NodeHash) -> NodeHash {
    let mut buf = [0u8; 1 + 32 + 32];
    buf[0] = LEAF_PREFIX;
    buf[1..33].copy_from_slice(path);
    buf[33..65].copy_from_slice(value_hash);
    keccak256(&buf)
}

/// Raw internal-node hash with no short-circuit: `keccak256(0x01 ‖ L ‖ R)`.
#[inline]
fn hash_internal_raw(left: &NodeHash, right: &NodeHash) -> NodeHash {
    let mut buf = [0u8; 1 + 32 + 32];
    buf[0] = INTERNAL_PREFIX;
    buf[1..33].copy_from_slice(left);
    buf[33..65].copy_from_slice(right);
    keccak256(&buf)
}

/// Internal node at `level`: `keccak256(0x01 ‖ left ‖ right)`, with the
/// empty-child short-circuit — if both children equal `default[level+1]` the
/// node IS `default[level]`. The short-circuit is an identity (the default
/// array was built with the same formula), so it only avoids materializing
/// empty subtrees; it never changes a hash.
pub fn hash_internal(level: usize, left: &NodeHash, right: &NodeHash) -> NodeHash {
    debug_assert!(level < DEPTH, "internal node level must be < 256");
    let d = default_hashes();
    if *left == d[level + 1] && *right == d[level + 1] {
        return d[level];
    }
    hash_internal_raw(left, right)
}

/// A node-store write operation the SMT emits and the backend applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeOp {
    /// Set the value-hash leaf at `path`.
    PutLeaf(LeafPath, NodeHash),
    /// Remove the leaf at `path` (the key became absent).
    DeleteLeaf(LeafPath),
    /// Set an internal node identified by `(level, prefix)`.
    PutNode {
        level: usize,
        prefix: LeafPath,
        hash: NodeHash,
    },
    /// Remove an internal node that reverted to its level's default.
    DeleteNode { level: usize, prefix: LeafPath },
}

/// Persistence seam the SMT walks. Keys are `(level, subtree-prefix)`; the
/// production node-key encoding lives in `store.rs`. The SMT never stores
/// default nodes — `get_node`/`get_leaf` returning `None` means "default /
/// absent at this position".
///
/// `prefix` for a node at `level` is the leaf path with only its top `level`
/// bits significant; the lower bits MUST be ignored by an implementor (the
/// SMT masks them, but a backend that round-trips the bytes must agree on the
/// canonical packing — see `store.rs`).
pub trait NodeBackend {
    /// Internal node hash at `(level, prefix)`, or `None` for the default.
    fn get_node(&self, level: usize, prefix: &LeafPath) -> Result<Option<NodeHash>, CommitmentError>;
    /// Apply a batch of node/leaf ops.
    fn write_nodes(&self, ops: &[NodeOp]) -> Result<(), CommitmentError>;
    /// The current value-hash leaf at `path`, or `None` if the key is absent.
    fn get_leaf(&self, path: &LeafPath) -> Result<Option<NodeHash>, CommitmentError>;
}

/// Forwarding impl so a shared borrow of any backend is itself a backend.
/// `Smt::open(&store, root)` can then hold the store by reference without
/// moving it (the builder keeps a second handle for bootstrap/resume).
impl<B: NodeBackend + ?Sized> NodeBackend for &B {
    fn get_node(&self, level: usize, prefix: &LeafPath) -> Result<Option<NodeHash>, CommitmentError> {
        (**self).get_node(level, prefix)
    }
    fn write_nodes(&self, ops: &[NodeOp]) -> Result<(), CommitmentError> {
        (**self).write_nodes(ops)
    }
    fn get_leaf(&self, path: &LeafPath) -> Result<Option<NodeHash>, CommitmentError> {
        (**self).get_leaf(path)
    }
}

/// One step of a Merkle proof: a sibling hash at a level. Default siblings are
/// elided from the wire form (see [`Proof::sibling_mask`]); this type is used
/// only by the in-process reference walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofStep {
    /// Level of the parent that combines this sibling with the path node.
    pub level: usize,
    /// The sibling subtree root.
    pub sibling: NodeHash,
    /// `true` if the path descends right (bit 1) at this level, so the
    /// sibling is the left child.
    pub path_goes_right: bool,
}

/// A Merkle inclusion/exclusion proof.
///
/// The 256 sibling hashes along the path are needed to reconstruct the root,
/// but most are the level default for a sparse tree. Default siblings are
/// elided: `sibling_mask` bit `i` (MSB-first) set means the step descending
/// from level `i` to level `i+1` carries a real (non-default) sibling stored
/// in `siblings`, in path order (level 0 → 255). An unset bit means the
/// sibling at that step is `default[i+1]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    /// The leaf path proven (`keccak256(store_id ‖ raw_key)`).
    pub path: LeafPath,
    /// `Some(keccak256(value_bytes))` if the key is present, else `None`
    /// (an exclusion proof reconstructs the empty-leaf default at `path`).
    pub leaf_value_hash: Option<NodeHash>,
    /// 256-bit mask, MSB-first: bit `i` set ⇒ `siblings[k]` is the real
    /// sibling at the step from level `i` to `i+1`; unset ⇒ default sibling.
    pub sibling_mask: [u8; 32],
    /// Non-default siblings in path order (level 0 downward).
    pub siblings: Vec<NodeHash>,
}

impl Proof {
    /// Set mask bit `i` (MSB-first), marking a non-default sibling at the
    /// step descending from level `i`.
    #[inline]
    fn set_mask_bit(mask: &mut [u8; 32], i: usize) {
        mask[i / 8] |= 1 << (7 - (i % 8));
    }

    /// Read mask bit `i` (MSB-first).
    #[inline]
    pub fn mask_bit(&self, i: usize) -> bool {
        (self.sibling_mask[i / 8] >> (7 - (i % 8))) & 1 == 1
    }
}

/// The tree handle. Holds the current root and a [`NodeBackend`]. The single
/// background builder task is the only writer, so no internal locking is
/// needed beyond the backend's batch atomicity.
pub struct Smt<B: NodeBackend> {
    backend: B,
    root: NodeHash,
}

impl<B: NodeBackend> Smt<B> {
    /// Open a tree over `backend` whose persisted root is `root`. Pass
    /// [`EMPTY_ROOT`] for a fresh tree.
    pub fn open(backend: B, root: NodeHash) -> Self {
        Self { backend, root }
    }

    /// The current root.
    pub fn root(&self) -> NodeHash {
        self.root
    }

    /// Borrow the backend (read-only).
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Apply a set of `(path, Option<value_hash>)` upserts/removals,
    /// returning the new root and the persisted [`NodeOp`] batch. `None`
    /// removes the leaf (the key became absent).
    ///
    /// Order within `changes` does not affect the result: duplicate paths
    /// collapse last-write-wins, then a single bottom-up recompute touches
    /// each affected internal node exactly once. The recompute reads
    /// siblings from the backend, layering this batch's own leaf changes on
    /// top, so the new root reflects the post-batch leaf set regardless of
    /// arrival order.
    pub fn apply(
        &mut self,
        changes: &[(LeafPath, Option<NodeHash>)],
    ) -> Result<(NodeHash, Vec<NodeOp>), CommitmentError> {
        // Dedup last-write-wins per path. Determinism: the BTreeMap fixes a
        // canonical path order for the recompute.
        let mut final_leaf: BTreeMap<LeafPath, Option<NodeHash>> = BTreeMap::new();
        for (path, vh) in changes {
            final_leaf.insert(*path, *vh);
        }

        let mut ops: Vec<NodeOp> = Vec::new();

        // Filter to leaves that actually change, and emit the leaf ops.
        // Order-independence rests on a strictly bottom-up recompute (level
        // 256 → 0): before an internal node at level L is computed, every
        // child at level L+1 this batch touches is already in `current`, and
        // untouched children are read from the backend (or are the default),
        // so each node folds the FINAL post-batch state of both children —
        // never a transient one. `current` maps node positions at the level
        // being consumed to their recomputed hashes; it begins at level 256
        // (leaf slots) and is rebuilt one level up per iteration.
        let mut current: BTreeMap<LeafPath, NodeHash> = BTreeMap::new();

        for (path, vh) in &final_leaf {
            let existing = self.backend.get_leaf(path)?;
            match vh {
                Some(new_vh) => {
                    // Emit a leaf write only when the value-hash actually
                    // changes; an unchanged leaf still joins the recompute set
                    // so its ancestors fold over the current sibling state.
                    if existing.as_ref() != Some(new_vh) {
                        ops.push(NodeOp::PutLeaf(*path, *new_vh));
                    }
                    current.insert(*path, hash_leaf(path, new_vh));
                }
                None => {
                    if existing.is_some() {
                        ops.push(NodeOp::DeleteLeaf(*path));
                    }
                    // An absent leaf contributes the default at level 256.
                    current.insert(*path, default_hashes()[DEPTH]);
                }
            }
        }

        let d = default_hashes();

        // Fold upward one level at a time. At each level the keys of `current`
        // are node positions at `level + 1` (children); we combine siblings
        // into parents at `level`.
        for level in (0..DEPTH).rev() {
            let child_level = level + 1;
            let mut parents: BTreeMap<LeafPath, NodeHash> = BTreeMap::new();

            for (path, _) in &final_leaf {
                let parent_prefix = mask_prefix(path, level);
                if parents.contains_key(&parent_prefix) {
                    continue; // already built this parent from its first child
                }

                // Determine the two children of this parent at `child_level`.
                // The path's own node at child_level is in `current`; the
                // sibling is read from the backend (or default).
                let path_goes_right = path_bit(path, level);
                let own_prefix = mask_prefix(path, child_level);
                let own_hash = *current
                    .get(&own_prefix)
                    .expect("child node must have been computed at the level below");

                // The sibling shares the top `level` bits but flips bit `level`.
                let sib_prefix = sibling_prefix(path, level);
                // A sibling at child_level that this batch ALSO touches lives
                // in `current`; otherwise materialize it from the backend. At
                // the leaf-slot level (child_level == DEPTH) the sibling is a
                // LEAF row, not an internal node, so it must be read from the
                // leaf store and re-hashed — a pre-existing sibling leaf that
                // shares the top `level` bits would otherwise be folded in as
                // the empty default, corrupting the parent.
                let sib_hash = match current.get(&sib_prefix) {
                    Some(h) => *h,
                    None => self
                        .read_subtree_hash(child_level, &sib_prefix)?
                        .unwrap_or(d[child_level]),
                };

                let (left, right) = if path_goes_right {
                    (sib_hash, own_hash)
                } else {
                    (own_hash, sib_hash)
                };
                let parent_hash = hash_internal(level, &left, &right);

                if parent_hash == d[level] {
                    ops.push(NodeOp::DeleteNode {
                        level,
                        prefix: parent_prefix,
                    });
                } else {
                    ops.push(NodeOp::PutNode {
                        level,
                        prefix: parent_prefix,
                        hash: parent_hash,
                    });
                }
                parents.insert(parent_prefix, parent_hash);
            }

            current = parents;
        }

        // After folding a non-empty batch to level 0 there is exactly one
        // entry: the root. An empty batch never populates `current` (nothing
        // to fold), so the root is unchanged — fall back to it, NOT the
        // all-default `d[0]`, which would wrongly reset a populated tree to
        // EMPTY_ROOT. (Deleting the last leaf still populates `current` with
        // the default leaf slot, so that case folds to EMPTY_ROOT here.)
        let new_root = current
            .values()
            .next()
            .copied()
            .unwrap_or(self.root);
        self.root = new_root;
        Ok((new_root, ops))
    }

    /// Inclusion/exclusion proof for `path` against the current root.
    pub fn prove(&self, path: &LeafPath) -> Result<Proof, CommitmentError> {
        let d = default_hashes();
        let leaf_value_hash = self.backend.get_leaf(path)?;

        let mut mask = [0u8; 32];
        let mut siblings = Vec::new();
        // Collect siblings top-down (level 0 → 255) so they land in path
        // order, matching the verifier's reconstruction.
        for level in 0..DEPTH {
            let child_level = level + 1;
            let sib_prefix = sibling_prefix(path, level);
            let sib = self.read_subtree_hash(child_level, &sib_prefix)?;
            if let Some(h) = sib {
                if h != d[child_level] {
                    Proof::set_mask_bit(&mut mask, level);
                    siblings.push(h);
                }
            }
        }

        Ok(Proof {
            path: *path,
            leaf_value_hash,
            sibling_mask: mask,
            siblings,
        })
    }

    /// Materialized hash of the subtree rooted at `(level, prefix)`, or `None`
    /// when that subtree is empty (its level default).
    ///
    /// At an internal level (`level < DEPTH`) this reads the stored node,
    /// masking the prefix to its level so the backend key is canonical. At the
    /// leaf-slot level (`level == DEPTH`) the "subtree" is a single leaf: the
    /// leaf row is read by full path and re-hashed with [`hash_leaf`], because
    /// leaves are persisted as value-hash rows, not as internal nodes. Folding
    /// or proving over a sibling leaf therefore reconstructs its leaf-node hash
    /// rather than treating it as the empty default.
    fn read_subtree_hash(
        &self,
        level: usize,
        prefix: &LeafPath,
    ) -> Result<Option<NodeHash>, CommitmentError> {
        if level >= DEPTH {
            // `prefix` is the full leaf path at the leaf-slot level.
            return Ok(self
                .backend
                .get_leaf(prefix)?
                .map(|vh| hash_leaf(prefix, &vh)));
        }
        let canon = mask_prefix(prefix, level);
        self.backend.get_node(level, &canon)
    }
}

/// Zero every bit of `path` below the top `level` bits, producing the
/// canonical node prefix for a node at `level`. A node at level 0 (the root)
/// has an all-zero prefix; a leaf slot at level 256 uses the full path.
#[inline]
pub fn mask_prefix(path: &LeafPath, level: usize) -> LeafPath {
    let mut out = *path;
    if level >= DEPTH {
        return out;
    }
    let full_bytes = level / 8;
    let rem_bits = level % 8;
    // Keep the top `rem_bits` of the boundary byte; zero the rest.
    if rem_bits == 0 {
        for b in out.iter_mut().skip(full_bytes) {
            *b = 0;
        }
    } else {
        let keep_mask = 0xFFu8 << (8 - rem_bits);
        out[full_bytes] &= keep_mask;
        for b in out.iter_mut().skip(full_bytes + 1) {
            *b = 0;
        }
    }
    out
}

/// Canonical prefix of the SIBLING of `path`'s node at `level + 1`: shares the
/// top `level` bits with `path` but flips bit `level`.
#[inline]
fn sibling_prefix(path: &LeafPath, level: usize) -> LeafPath {
    let child_level = level + 1;
    let mut out = mask_prefix(path, child_level);
    // Flip bit `level` (the bit that distinguishes the two children at
    // child_level).
    out[level / 8] ^= 1 << (7 - (level % 8));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    /// In-memory `NodeBackend` for tests: a leaf map and a node map keyed by
    /// `(level, canonical-prefix)`. No RocksDB needed.
    #[derive(Default)]
    pub struct MemNodeBackend {
        leaves: RefCell<BTreeMap<LeafPath, NodeHash>>,
        nodes: RefCell<BTreeMap<(usize, LeafPath), NodeHash>>,
    }

    impl MemNodeBackend {
        fn new() -> Self {
            Self::default()
        }
    }

    impl NodeBackend for MemNodeBackend {
        fn get_node(
            &self,
            level: usize,
            prefix: &LeafPath,
        ) -> Result<Option<NodeHash>, CommitmentError> {
            Ok(self.nodes.borrow().get(&(level, mask_prefix(prefix, level))).copied())
        }

        fn write_nodes(&self, ops: &[NodeOp]) -> Result<(), CommitmentError> {
            let mut leaves = self.leaves.borrow_mut();
            let mut nodes = self.nodes.borrow_mut();
            for op in ops {
                match op {
                    NodeOp::PutLeaf(p, h) => {
                        leaves.insert(*p, *h);
                    }
                    NodeOp::DeleteLeaf(p) => {
                        leaves.remove(p);
                    }
                    NodeOp::PutNode { level, prefix, hash } => {
                        nodes.insert((*level, mask_prefix(prefix, *level)), *hash);
                    }
                    NodeOp::DeleteNode { level, prefix } => {
                        nodes.remove(&(*level, mask_prefix(prefix, *level)));
                    }
                }
            }
            Ok(())
        }

        fn get_leaf(&self, path: &LeafPath) -> Result<Option<NodeHash>, CommitmentError> {
            Ok(self.leaves.borrow().get(path).copied())
        }
    }

    /// Apply `changes` and persist the emitted ops, returning the new root.
    fn apply_persist(
        be: &MemNodeBackend,
        changes: &[(LeafPath, Option<NodeHash>)],
    ) -> NodeHash {
        let mut smt = Smt::open(be, current_root(be));
        let (root, ops) = smt.apply(changes).unwrap();
        be.write_nodes(&ops).unwrap();
        root
    }

    /// Reconstruct the current root by reading node (0, all-zero) or
    /// EMPTY_ROOT.
    fn current_root(be: &MemNodeBackend) -> NodeHash {
        be.get_node(0, &[0u8; 32]).unwrap().unwrap_or(EMPTY_ROOT)
    }

    fn vh(byte: u8) -> NodeHash {
        keccak256(&[byte])
    }

    fn path(seed: u64) -> LeafPath {
        keccak256(&seed.to_be_bytes())
    }

    /// Independent reference root over a `path → value_hash` set via the
    /// O(256) path-merge (§2.4 strategy 1). Used to cross-check `Smt::apply`.
    fn reference_root(leaves: &BTreeMap<LeafPath, NodeHash>) -> NodeHash {
        let d = default_hashes();
        if leaves.is_empty() {
            return d[0];
        }
        // Build a sparse map level by level, bottom-up. Start at level 256
        // with each leaf's node hash.
        let mut level_nodes: BTreeMap<LeafPath, NodeHash> = BTreeMap::new();
        for (p, v) in leaves {
            level_nodes.insert(*p, hash_leaf(p, v));
        }
        for level in (0..DEPTH).rev() {
            let mut parents: BTreeMap<LeafPath, NodeHash> = BTreeMap::new();
            for (p, _) in leaves {
                let parent_prefix = mask_prefix(p, level);
                if parents.contains_key(&parent_prefix) {
                    continue;
                }
                let own_prefix = mask_prefix(p, level + 1);
                let own = *level_nodes.get(&own_prefix).unwrap();
                let sib_prefix = sibling_prefix(p, level);
                let sib = level_nodes
                    .get(&sib_prefix)
                    .copied()
                    .unwrap_or(d[level + 1]);
                let (l, r) = if path_bit(p, level) {
                    (sib, own)
                } else {
                    (own, sib)
                };
                parents.insert(parent_prefix, hash_internal(level, &l, &r));
            }
            level_nodes = parents;
        }
        *level_nodes.values().next().unwrap()
    }

    // -- 1. Empty root is the documented constant. --------------------------

    #[test]
    fn empty_root_const_matches_default_array() {
        assert_eq!(EMPTY_ROOT, default_hashes()[0]);
        // default[256] is the empty leaf slot.
        assert_eq!(default_hashes()[256], [0u8; 32]);
    }

    #[test]
    fn empty_root_pinned_hex() {
        // Pin the exact bytes so a future hashing refactor can't silently
        // shift the root. Recompute the empty-tree root from scratch and
        // compare to both the const and the pinned hex.
        let expected = hex_literal::hex!(
            "ca35b60c4cbb11bc17b902989f14c51d764dfb865e9ade93d57df3def62a1e05"
        );
        assert_eq!(EMPTY_ROOT, expected);
        // Recompute the empty-tree root from the default array independently
        // of the const, so the pin actually guards the hashing scheme.
        assert_eq!(default_hashes()[0], expected);
        let be = MemNodeBackend::new();
        let smt = Smt::open(&be, EMPTY_ROOT);
        assert_eq!(smt.root(), expected);
    }

    // -- 2. Order-independence (the core invariant) -------------------------

    #[test]
    fn order_independence_many_permutations() {
        // A fixed leaf set; insert in many permutations into fresh trees and
        // assert every permutation yields the identical root.
        let n = 24usize;
        let leaves: Vec<(LeafPath, NodeHash)> =
            (0..n as u64).map(|i| (path(i * 7 + 1), vh((i % 251) as u8))).collect();

        let mut canonical: Option<NodeHash> = None;
        // Deterministic pseudo-random permutations (LCG-shuffled indices).
        for seed in 0..40u64 {
            let mut idx: Vec<usize> = (0..n).collect();
            // Fisher–Yates with a deterministic LCG.
            let mut state = seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(1);
            for i in (1..n).rev() {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let j = (state >> 33) as usize % (i + 1);
                idx.swap(i, j);
            }
            let be = MemNodeBackend::new();
            for &i in &idx {
                let (p, v) = leaves[i];
                apply_persist(&be, &[(p, Some(v))]);
            }
            let root = current_root(&be);
            match canonical {
                None => canonical = Some(root),
                Some(c) => assert_eq!(root, c, "permutation seed {seed} diverged"),
            }
        }

        // And it agrees with the reference path-merge root.
        let mut set = BTreeMap::new();
        for (p, v) in &leaves {
            set.insert(*p, *v);
        }
        assert_eq!(canonical.unwrap(), reference_root(&set));
        assert_ne!(canonical.unwrap(), EMPTY_ROOT);
    }

    // -- 3. Insert-then-delete returns to prior root ------------------------

    #[test]
    fn insert_then_delete_restores_root() {
        let be = MemNodeBackend::new();
        // Seed with some unrelated keys.
        for i in 0..5u64 {
            apply_persist(&be, &[(path(1000 + i), Some(vh(i as u8)))]);
        }
        let r0 = current_root(&be);

        // Insert a batch, then delete it in a DIFFERENT order.
        let batch: Vec<LeafPath> = (0..6u64).map(|i| path(2000 + i * 13)).collect();
        for (i, p) in batch.iter().enumerate() {
            apply_persist(&be, &[(*p, Some(vh(i as u8 + 50)))]);
        }
        let r1 = current_root(&be);
        assert_ne!(r0, r1);

        // Delete in reversed + interleaved order.
        let mut del_order = batch.clone();
        del_order.reverse();
        del_order.swap(0, 2);
        for p in &del_order {
            apply_persist(&be, &[(*p, None)]);
        }
        assert_eq!(current_root(&be), r0, "delete must restore the prior root");
    }

    /// Regression: an empty write-set must leave a populated tree's root
    /// unchanged (and emit no ops), NOT reset it to EMPTY_ROOT. The apply
    /// hook forwards every height including empty/absent write-sets, so an
    /// empty `apply` on a live tree is a routine event.
    #[test]
    fn empty_apply_preserves_a_populated_root() {
        let be = MemNodeBackend::new();
        for i in 0..7u64 {
            apply_persist(&be, &[(path(500 + i * 7), Some(vh(i as u8)))]);
        }
        let populated = current_root(&be);
        assert_ne!(populated, EMPTY_ROOT, "sanity: the tree is non-empty");

        let mut smt = Smt::open(&be, populated);
        let (root, ops) = smt.apply(&[]).unwrap();
        assert_eq!(root, populated, "empty apply must return the unchanged root");
        assert_eq!(smt.root(), populated, "empty apply must not mutate self.root");
        assert!(ops.is_empty(), "empty apply must emit no node ops");
        // A follow-up real change still folds against the preserved tree.
        let r2 = apply_persist(&be, &[(path(9999), Some(vh(42)))]);
        assert_ne!(r2, populated);
        assert_ne!(r2, EMPTY_ROOT);
    }

    /// An empty apply on a genuinely empty tree stays at EMPTY_ROOT.
    #[test]
    fn empty_apply_on_empty_tree_is_empty_root() {
        let be = MemNodeBackend::new();
        let mut smt = Smt::open(&be, EMPTY_ROOT);
        let (root, ops) = smt.apply(&[]).unwrap();
        assert_eq!(root, EMPTY_ROOT);
        assert!(ops.is_empty());
    }

    // -- 4. Single-vs-batch apply agree -------------------------------------

    #[test]
    fn single_vs_batch_agree() {
        let leaves: Vec<(LeafPath, NodeHash)> =
            (0..20u64).map(|i| (path(i * 31 + 3), vh((i * 5) as u8))).collect();

        // One-at-a-time.
        let be_single = MemNodeBackend::new();
        for (p, v) in &leaves {
            apply_persist(&be_single, &[(*p, Some(*v))]);
        }

        // One batched apply.
        let be_batch = MemNodeBackend::new();
        let changes: Vec<(LeafPath, Option<NodeHash>)> =
            leaves.iter().map(|(p, v)| (*p, Some(*v))).collect();
        apply_persist(&be_batch, &changes);

        assert_eq!(current_root(&be_single), current_root(&be_batch));
    }

    // -- 5. Known-vector tests ----------------------------------------------

    #[test]
    fn known_vector_one_leaf() {
        // Path with bit 0 = 0, value-hash a constant; pin the root and the
        // leaf-node hash so the 0x00 leaf prefix is locked.
        let p: LeafPath = [0u8; 32]; // descends left at every level
        let v: NodeHash = [0x11u8; 32];
        let leaf_node = hash_leaf(&p, &v);
        // Expected leaf-node hash = keccak(0x00 ‖ 0*32 ‖ 0x11*32).
        let mut buf = vec![0x00u8];
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(&[0x11u8; 32]);
        assert_eq!(leaf_node, keccak256(&buf));

        let be = MemNodeBackend::new();
        let root = apply_persist(&be, &[(p, Some(v))]);

        // Reference: fold leaf_node up 256 levels, always as the LEFT child
        // (path is all-zero), with the right sibling defaulting.
        let d = default_hashes();
        let mut acc = leaf_node;
        for level in (0..DEPTH).rev() {
            acc = hash_internal(level, &acc, &d[level + 1]);
        }
        assert_eq!(root, acc);
        assert_ne!(root, EMPTY_ROOT);

        let mut set = BTreeMap::new();
        set.insert(p, v);
        assert_eq!(root, reference_root(&set));

        // Pin the exact root so a future hashing change (prefixes, ordering,
        // short-circuit) can't silently shift it.
        assert_eq!(
            root,
            hex_literal::hex!(
                "0b179ac627bf8d4ffd1024823b652ea28cb9b89e44493ec4f8d5d8acd9c2b04b"
            )
        );
    }

    #[test]
    fn known_vector_two_leaves_diverge_at_bit0() {
        // One path all-zero (left at bit 0), one with the top bit set (right).
        let mut p_left = [0u8; 32];
        let mut p_right = [0u8; 32];
        p_left[0] = 0x00; // bit 0 = 0
        p_right[0] = 0x80; // bit 0 = 1
        let v_l: NodeHash = [0x22u8; 32];
        let v_r: NodeHash = [0x33u8; 32];

        let be = MemNodeBackend::new();
        let root = apply_persist(&be, &[(p_left, Some(v_l)), (p_right, Some(v_r))]);

        // Reference: each leaf folds independently up to level 1 (both
        // subtrees diverge only at the root's two children), then the root
        // combines them at level 0.
        let d = default_hashes();
        let mut left_acc = hash_leaf(&p_left, &v_l);
        for level in (1..DEPTH).rev() {
            // p_left descends left at every level after bit 0 (all zero), so
            // sibling is default on the right.
            left_acc = hash_internal(level, &left_acc, &d[level + 1]);
        }
        let mut right_acc = hash_leaf(&p_right, &v_r);
        for level in (1..DEPTH).rev() {
            // p_right has 0x80 then all zero, so after bit 0 it also descends
            // left; sibling default on the right.
            right_acc = hash_internal(level, &right_acc, &d[level + 1]);
        }
        let expected = hash_internal(0, &left_acc, &right_acc);
        assert_eq!(root, expected);

        let mut set = BTreeMap::new();
        set.insert(p_left, v_l);
        set.insert(p_right, v_r);
        assert_eq!(root, reference_root(&set));
    }

    #[test]
    fn known_vector_two_leaves_deep_shared_prefix() {
        // Two paths sharing a 250-bit prefix, diverging at bit 250.
        let mut a = [0xA5u8; 32];
        let mut b = a;
        // Bit 250 lives in byte 31 (250/8 = 31), bit 250%8 = 2, i.e. mask
        // 1 << (7-2) = 0x20. Force them to differ exactly there and share
        // everything above.
        // Zero the lower bits of byte 31 from bit 250 down for both, then set
        // the divergence bit on `b`.
        let boundary_keep = 0xFFu8 << (8 - 2); // keep top 2 bits of byte 31
        a[31] &= boundary_keep;
        b[31] &= boundary_keep;
        b[31] |= 1 << (7 - 2); // set bit 250 on b only
        assert_ne!(a, b);
        // They must share the top 250 bits.
        assert_eq!(mask_prefix(&a, 250), mask_prefix(&b, 250));
        assert!(!path_bit(&a, 250));
        assert!(path_bit(&b, 250));

        let v_a: NodeHash = [0x44u8; 32];
        let v_b: NodeHash = [0x55u8; 32];
        let be = MemNodeBackend::new();
        let root = apply_persist(&be, &[(a, Some(v_a)), (b, Some(v_b))]);

        let mut set = BTreeMap::new();
        set.insert(a, v_a);
        set.insert(b, v_b);
        assert_eq!(root, reference_root(&set));
        assert_ne!(root, EMPTY_ROOT);
    }

    // -- 6. Proof round-trip ------------------------------------------------

    #[test]
    fn proof_round_trip_inclusion_and_exclusion() {
        use crate::commitment::proof::{verify_proof, ProofOutcome};

        let be = MemNodeBackend::new();
        // Populate with several leaves; record their values.
        let mut vals: BTreeMap<LeafPath, Vec<u8>> = BTreeMap::new();
        for i in 0..12u64 {
            let p = path(i * 17 + 9);
            let raw = format!("value-{i}").into_bytes();
            let value_hash = keccak256(&raw);
            apply_persist(&be, &[(p, Some(value_hash))]);
            vals.insert(p, raw);
        }
        let root = current_root(&be);
        let smt = Smt::open(&be, root);

        // Inclusion proof for an existing key.
        let (p0, raw0) = vals.iter().next().map(|(k, v)| (*k, v.clone())).unwrap();
        let pr = smt.prove(&p0).unwrap();
        assert_eq!(verify_proof(&root, &pr, Some(&raw0)), ProofOutcome::Included);

        // Exclusion proof for an absent key.
        let absent = path(999_999);
        assert!(smt.backend().get_leaf(&absent).unwrap().is_none());
        let pr_ex = smt.prove(&absent).unwrap();
        assert_eq!(verify_proof(&root, &pr_ex, None), ProofOutcome::Excluded);

        // Wrong root → Invalid.
        let mut bad_root = root;
        bad_root[0] ^= 0xFF;
        assert_eq!(verify_proof(&bad_root, &pr, Some(&raw0)), ProofOutcome::Invalid);

        // Tampered sibling → Invalid (if there is a sibling to tamper).
        if !pr.siblings.is_empty() {
            let mut tampered = pr.clone();
            tampered.siblings[0][0] ^= 0xFF;
            assert_eq!(
                verify_proof(&root, &tampered, Some(&raw0)),
                ProofOutcome::Invalid
            );
        }

        // Wrong value for an inclusion proof → Invalid.
        assert_eq!(
            verify_proof(&root, &pr, Some(b"not-the-value")),
            ProofOutcome::Invalid
        );
    }

    // -- 7. Exclusion on a populated sibling path ---------------------------

    #[test]
    fn exclusion_with_populated_sibling() {
        use crate::commitment::proof::{verify_proof, ProofOutcome};

        let be = MemNodeBackend::new();
        // Two paths sharing a long prefix, diverging at bit 8: one present,
        // one absent. The absent key's proof must carry the present sibling
        // subtree (a non-default sibling), exercising the mask.
        let mut present = [0u8; 32];
        let mut absent = [0u8; 32];
        present[0] = 0xFF; // shared top byte
        absent[0] = 0xFF;
        present[1] = 0x00; // diverge at bit 8 (byte 1, top bit)
        absent[1] = 0x80;
        let raw = b"present-value".to_vec();
        apply_persist(&be, &[(present, Some(keccak256(&raw)))]);

        let root = current_root(&be);
        let smt = Smt::open(&be, root);
        let pr = smt.prove(&absent).unwrap();
        // There must be at least one real sibling (the present subtree).
        assert!(!pr.siblings.is_empty(), "expected a populated sibling");
        assert_eq!(verify_proof(&root, &pr, None), ProofOutcome::Excluded);

        // Inclusion of the present key still verifies.
        let pr_in = smt.prove(&present).unwrap();
        assert_eq!(verify_proof(&root, &pr_in, Some(&raw)), ProofOutcome::Included);
    }

    // -- 8. Value-binding ---------------------------------------------------

    #[test]
    fn value_binding_same_value_different_key() {
        let p1 = path(11);
        let p2 = path(22);
        let v: NodeHash = [0x77u8; 32];
        assert_ne!(p1, p2);
        // Same value-hash, different key ⇒ different leaf-node hash.
        assert_ne!(hash_leaf(&p1, &v), hash_leaf(&p2, &v));

        // A proof for p1 cannot be replayed as a proof for p2: even with the
        // same value, the reconstructed root binds the path.
        use crate::commitment::proof::{verify_proof, ProofOutcome};
        let be = MemNodeBackend::new();
        let raw = b"shared".to_vec();
        apply_persist(&be, &[(p1, Some(keccak256(&raw)))]);
        let root = current_root(&be);
        let smt = Smt::open(&be, root);
        let mut pr = smt.prove(&p1).unwrap();
        assert_eq!(verify_proof(&root, &pr, Some(&raw)), ProofOutcome::Included);
        // Swap the path to p2 while keeping p1's siblings/value-hash — must
        // not verify against the same root.
        pr.path = p2;
        assert_eq!(verify_proof(&root, &pr, Some(&raw)), ProofOutcome::Invalid);
    }

    // -- 9. Cross-store path disjointness -----------------------------------

    #[test]
    fn cross_store_path_disjointness() {
        // leaf_path = keccak(store_byte ‖ raw_key). Same raw key under two
        // different store bytes must map to different paths, and a property
        // sweep finds no collisions.
        fn leaf_path(store: u8, key: &[u8]) -> LeafPath {
            let mut buf = Vec::with_capacity(1 + key.len());
            buf.push(store);
            buf.extend_from_slice(key);
            keccak256(&buf)
        }

        let key = b"same-raw-key";
        assert_ne!(leaf_path(0, key), leaf_path(18, key)); // Accounts vs Code

        let mut seen: BTreeMap<LeafPath, (u8, Vec<u8>)> = BTreeMap::new();
        for store in 0u8..24 {
            for i in 0u64..200 {
                let k = i.to_be_bytes().to_vec();
                let lp = leaf_path(store, &k);
                if let Some(prev) = seen.insert(lp, (store, k.clone())) {
                    panic!("path collision: {prev:?} vs ({store}, {k:?})");
                }
            }
        }
    }

    // -- Forged-proof soundness ---------------------------------------------

    #[test]
    fn forged_proofs_do_not_validate() {
        use crate::commitment::proof::{verify_proof, ProofOutcome};

        let be = MemNodeBackend::new();
        for i in 0..16u64 {
            let p = path(i * 5 + 1);
            apply_persist(&be, &[(p, Some(keccak256(&i.to_be_bytes())))]);
        }
        let root = current_root(&be);
        let smt = Smt::open(&be, root);

        // A present key cannot be forged as ABSENT: drop the leaf value hash to
        // turn an inclusion proof into a (false) exclusion proof and verify it
        // against the real root.
        let present = path(1);
        let mut as_excluded = smt.prove(&present).unwrap();
        assert!(as_excluded.leaf_value_hash.is_some());
        as_excluded.leaf_value_hash = None;
        assert_eq!(
            verify_proof(&root, &as_excluded, None),
            ProofOutcome::Invalid,
            "a present key forged as absent must not verify"
        );

        // An absent key cannot be forged as PRESENT: attach a value hash to an
        // exclusion proof and try to bind a value to it.
        let absent = path(987_654);
        assert!(smt.backend().get_leaf(&absent).unwrap().is_none());
        let mut as_included = smt.prove(&absent).unwrap();
        let forged_raw = b"forged".to_vec();
        as_included.leaf_value_hash = Some(keccak256(&forged_raw));
        assert_eq!(
            verify_proof(&root, &as_included, Some(&forged_raw)),
            ProofOutcome::Invalid,
            "an absent key forged as present must not verify"
        );

        // Flipping a single mask bit (claiming a default sibling is real, or
        // vice versa) breaks reconstruction.
        let mut bit_flipped = smt.prove(&present).unwrap();
        bit_flipped.sibling_mask[0] ^= 0x80;
        assert_eq!(
            verify_proof(&root, &bit_flipped, Some(&0u64.to_be_bytes())),
            ProofOutcome::Invalid,
            "a tampered sibling mask must not verify"
        );

        // Re-ordering the sibling list (swapping two real siblings) changes the
        // reconstructed root.
        let mut reordered = smt.prove(&present).unwrap();
        if reordered.siblings.len() >= 2 {
            let n = reordered.siblings.len();
            reordered.siblings.swap(0, n - 1);
            assert_eq!(
                verify_proof(&root, &reordered, Some(&0u64.to_be_bytes())),
                ProofOutcome::Invalid,
                "re-ordered siblings must not verify"
            );
        }
    }

    // -- Sibling leaves at the deepest level --------------------------------

    #[test]
    fn sibling_leaves_at_leaf_slot_level_are_order_independent() {
        use crate::commitment::proof::{verify_proof, ProofOutcome};

        // Two paths that share the top 255 bits and differ only at bit 255.
        // Their leaf nodes are siblings at the leaf-slot level (256). Folding
        // them incrementally (each in its own apply, so neither sibling is in
        // the other's batch) must equal a single batch and the reference
        // path-merge: the incremental sibling read crosses into the leaf store.
        let mut a = [0u8; 32];
        a[0] = 0xAB;
        a[31] = 0xF0; // ...1111 0000 → bit 255 = 0
        let mut b = a;
        b[31] = 0xF1; // ...1111 0001 → bit 255 = 1
        assert_eq!(mask_prefix(&a, 255), mask_prefix(&b, 255));
        assert!(!path_bit(&a, 255));
        assert!(path_bit(&b, 255));

        let raw_a = b"value-a".to_vec();
        let raw_b = b"value-b".to_vec();
        let va = keccak256(&raw_a);
        let vb = keccak256(&raw_b);

        // Incremental: insert a, then b (and in the reverse order too).
        let be = MemNodeBackend::new();
        apply_persist(&be, &[(a, Some(va))]);
        apply_persist(&be, &[(b, Some(vb))]);
        let incr = current_root(&be);

        let be_rev = MemNodeBackend::new();
        apply_persist(&be_rev, &[(b, Some(vb))]);
        apply_persist(&be_rev, &[(a, Some(va))]);
        let incr_rev = current_root(&be_rev);

        // Single batch.
        let be2 = MemNodeBackend::new();
        apply_persist(&be2, &[(a, Some(va)), (b, Some(vb))]);
        let batch = current_root(&be2);

        // Reference path-merge.
        let mut set = BTreeMap::new();
        set.insert(a, va);
        set.insert(b, vb);
        let reference = reference_root(&set);

        assert_eq!(batch, reference, "single batch must match reference");
        assert_eq!(incr, reference, "insert a then b must match reference");
        assert_eq!(incr_rev, reference, "insert b then a must match reference");

        // Proofs over the incrementally-built tree must verify: each leaf's
        // sibling is the other leaf, so the proof carries a real bit-255
        // sibling that the verifier folds back to the same root.
        let smt = Smt::open(&be, incr);
        let pr_a = smt.prove(&a).unwrap();
        let pr_b = smt.prove(&b).unwrap();
        assert!(!pr_a.siblings.is_empty(), "a's deepest sibling is b's leaf");
        assert!(!pr_b.siblings.is_empty(), "b's deepest sibling is a's leaf");
        assert_eq!(verify_proof(&incr, &pr_a, Some(&raw_a)), ProofOutcome::Included);
        assert_eq!(verify_proof(&incr, &pr_b, Some(&raw_b)), ProofOutcome::Included);

        // Deleting one of the pair must leave a tree equal to the surviving
        // leaf alone — the parent at level 255 re-folds `a` against an empty
        // bit-255 slot, never against the stale `b` leaf.
        apply_persist(&be, &[(b, None)]);
        let after_delete = current_root(&be);
        let mut just_a = BTreeMap::new();
        just_a.insert(a, va);
        assert_eq!(after_delete, reference_root(&just_a));
        let be_solo = MemNodeBackend::new();
        let solo = apply_persist(&be_solo, &[(a, Some(va))]);
        assert_eq!(after_delete, solo);
    }

    // -- Extra: apply emits delete-node ops that round-trip to default ------

    #[test]
    fn deleting_last_leaf_returns_to_empty_root() {
        let be = MemNodeBackend::new();
        let p = path(5);
        apply_persist(&be, &[(p, Some(vh(9)))]);
        assert_ne!(current_root(&be), EMPTY_ROOT);
        apply_persist(&be, &[(p, None)]);
        assert_eq!(current_root(&be), EMPTY_ROOT);
        // The node store must be empty (every node reverted to default and
        // was deleted), and the leaf removed.
        assert!(be.get_leaf(&p).unwrap().is_none());
        assert!(be.get_node(0, &[0u8; 32]).unwrap().is_none());
    }
}
