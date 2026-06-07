//! Shielded TRC-20 zk-SNARK precompiles.
//!
//! TRON ports Zcash Sapling for its shielded TRC-20 contracts. Four
//! precompile addresses cover the cryptographic primitives the on-chain
//! contracts call into:
//!
//! | Address      | Name                  | Status                  |
//! |--------------|-----------------------|-------------------------|
//! | `0x01000001` | `VerifyMintProof`     | **Implemented**         |
//! | `0x01000002` | `VerifyTransferProof` | **Implemented**         |
//! | `0x01000003` | `VerifyBurnProof`     | **Implemented**         |
//! | `0x01000004` | `MerkleHash`          | **Implemented**         |
//!
//! ## Verifying-key embedding
//!
//! The Sapling spend/output verifying keys are embedded as raw bytes via
//! [`SPEND_VK_BYTES`] and [`OUTPUT_VK_BYTES`]. These were extracted
//! one-shot from java-tron's `sapling-spend.params` and
//! `sapling-output.params` using `bin/extract_sapling_vk.rs`. Sizes:
//! ~1.6 KB and ~1.4 KB respectively — small enough to embed.
//!
//! On first use, [`prepared_spend_vk`] and [`prepared_output_vk`] decode
//! the bytes via `bellman::groth16::VerifyingKey::read`, then call
//! `prepare_verifying_key` and cache the result in a `OnceLock`.
//!
//! ## Why not sapling-crypto's `SaplingVerificationContext`?
//!
//! sapling-crypto exposes `SaplingVerificationContext::check_spend` /
//! `check_output`, but those take a `&PreparedSpendVerifyingKey` whose
//! inner field is `pub(crate)` and can only be obtained via
//! `SpendParameters::read()` — which requires the full ~50 MB .params
//! file. We don't want to ship that.
//!
//! Instead, we mirror sapling-crypto's `verifier.rs` logic here using
//! only public types: `bellman::groth16::verify_proof` directly against
//! our `PreparedVerifyingKey<Bls12>`, plus `sapling_crypto::value::{
//! ValueCommitment, CommitmentSum}` for the binding-signature math.
//! Byte-for-byte equivalence is preserved.

use std::sync::OnceLock;

use bellman::groth16::{prepare_verifying_key, verify_proof, PreparedVerifyingKey, Proof, VerifyingKey};
use bls12_381::{Bls12, Scalar};
use ff::PrimeField;
use group::{Curve, GroupEncoding};
use redjubjub::{Binding, SpendAuth};
use sapling_crypto::{
    pedersen_hash::{pedersen_hash, Personalization},
    value::{CommitmentSum, ValueCommitment},
};

// Re-export so callers in tron-actuator can build `CommitmentSum`
// accumulations across multiple spend/output checks.
pub use sapling_crypto::value::{CommitmentSum as SaplingCommitmentSum, ValueCommitment as SaplingValueCommitment};

/// Sapling spend-circuit verifying key, uncompressed-G1/G2 encoding (1636 bytes).
pub const SPEND_VK_BYTES: &[u8] = include_bytes!("../assets/sapling-spend.vk");

/// Sapling output-circuit verifying key, uncompressed-G1/G2 encoding (1444 bytes).
pub const OUTPUT_VK_BYTES: &[u8] = include_bytes!("../assets/sapling-output.vk");

/// Cached, lazily-decoded `PreparedVerifyingKey` for the Sapling spend circuit.
pub fn prepared_spend_vk() -> &'static PreparedVerifyingKey<Bls12> {
    static CELL: OnceLock<PreparedVerifyingKey<Bls12>> = OnceLock::new();
    CELL.get_or_init(|| {
        let vk = VerifyingKey::<Bls12>::read(SPEND_VK_BYTES)
            .expect("embedded sapling-spend.vk must decode");
        prepare_verifying_key(&vk)
    })
}

/// Cached, lazily-decoded `PreparedVerifyingKey` for the Sapling output circuit.
pub fn prepared_output_vk() -> &'static PreparedVerifyingKey<Bls12> {
    static CELL: OnceLock<PreparedVerifyingKey<Bls12>> = OnceLock::new();
    CELL.get_or_init(|| {
        let vk = VerifyingKey::<Bls12>::read(OUTPUT_VK_BYTES)
            .expect("embedded sapling-output.vk must decode");
        prepare_verifying_key(&vk)
    })
}

// =============================================================================
// IncrementalMerkleTree (Sapling note-commitment accumulator)
// =============================================================================
//
// Mirrors java-tron's `IncrementalMerkleTreeContainer` byte-for-byte:
// a treap-shaped structure of {`left`, `right`, `parents[i]`} where each
// slot holds an optional 32-byte Pedersen hash. `append` adds a leaf;
// when both `left` and `right` are filled, they collapse into a
// `parents[0]` entry via `merkle_hash(depth=0, left, right)` and so on
// up the tree. The root is computed by combining the cursor (left,
// right) with all `parents` entries and padding empty slots with
// pre-computed empty-subtree hashes (`uncommitted_tree`).
//
// Tree depth: 32. Source: `IncrementalMerkleTreeContainer.DEPTH`.

/// Sapling tree depth (java-tron pinned constant).
pub const MERKLE_TREE_DEPTH: usize = 32;

/// On-chain incremental Merkle tree state. A `None` slot means the
/// position is unfilled; once both `left` and `right` are `Some`, a
/// fresh `append` collapses them into a parent and resets to a new
/// leaf cursor.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IncrementalMerkleTree {
    pub left: Option<[u8; 32]>,
    pub right: Option<[u8; 32]>,
    /// `parents[i]` is the combined-hash at tree level `i+1`, populated
    /// once `2^(i+2)` leaves have been appended.
    pub parents: Vec<Option<[u8; 32]>>,
}

impl IncrementalMerkleTree {
    pub fn new() -> Self {
        Self::default()
    }

    /// Convert from the on-disk proto representation. java-tron uses an
    /// "is_present" check: a `PedersenHash` with empty `content` is
    /// `None`; non-empty 32-byte content is `Some`.
    pub fn from_proto(p: &tron_proto::IncrementalMerkleTree) -> Self {
        fn opt(h: Option<&tron_proto::PedersenHash>) -> Option<[u8; 32]> {
            let h = h?;
            if h.content.len() == 32 {
                let mut a = [0u8; 32];
                a.copy_from_slice(&h.content);
                Some(a)
            } else {
                None
            }
        }
        Self {
            left: opt(p.left.as_ref()),
            right: opt(p.right.as_ref()),
            parents: p
                .parents
                .iter()
                .map(|h| {
                    if h.content.len() == 32 {
                        let mut a = [0u8; 32];
                        a.copy_from_slice(&h.content);
                        Some(a)
                    } else {
                        None
                    }
                })
                .collect(),
        }
    }

    pub fn to_proto(&self) -> tron_proto::IncrementalMerkleTree {
        fn ph(b: Option<&[u8; 32]>) -> Option<tron_proto::PedersenHash> {
            Some(tron_proto::PedersenHash {
                content: b.map(|b| b.to_vec()).unwrap_or_default(),
            })
        }
        tron_proto::IncrementalMerkleTree {
            left: ph(self.left.as_ref()),
            right: ph(self.right.as_ref()),
            parents: self
                .parents
                .iter()
                .map(|opt| tron_proto::PedersenHash {
                    content: opt.map(|b| b.to_vec()).unwrap_or_default(),
                })
                .collect(),
        }
    }

    /// Number of leaves currently committed.
    pub fn size(&self) -> u64 {
        let mut n = 0u64;
        if self.left.is_some() {
            n += 1;
        }
        if self.right.is_some() {
            n += 1;
        }
        for (i, p) in self.parents.iter().enumerate() {
            if p.is_some() {
                n += 1u64 << (i + 1);
            }
        }
        n
    }

    pub fn is_complete(&self) -> bool {
        self.left.is_some()
            && self.right.is_some()
            && self.parents.len() == MERKLE_TREE_DEPTH - 1
            && self.parents.iter().all(Option::is_some)
    }

    /// Append a 32-byte commitment. Mirrors java-tron's `append`.
    pub fn append(&mut self, leaf: [u8; 32]) -> Result<(), &'static str> {
        if self.is_complete() {
            return Err("tree is full");
        }
        if self.left.is_none() {
            self.left = Some(leaf);
            return Ok(());
        }
        if self.right.is_none() {
            self.right = Some(leaf);
            return Ok(());
        }
        // Both leaves filled — combine them at depth 0, then walk
        // upward.
        let mut combined = merkle_hash(0, self.left.as_ref().unwrap(), self.right.as_ref().unwrap());
        self.left = Some(leaf);
        self.right = None;
        for i in 0..MERKLE_TREE_DEPTH {
            if i < self.parents.len() {
                match self.parents[i] {
                    Some(parent_hash) => {
                        combined = merkle_hash(i + 1, &parent_hash, &combined);
                        self.parents[i] = None;
                    }
                    None => {
                        self.parents[i] = Some(combined);
                        return Ok(());
                    }
                }
            } else {
                self.parents.push(Some(combined));
                return Ok(());
            }
        }
        Err("tree overflow")
    }

    /// Compute the Merkle root. Uses precomputed empty-subtree hashes
    /// to pad any unfilled slots at the cursor and parents levels.
    pub fn root(&self) -> [u8; 32] {
        let empty = uncommitted_tree();
        let l = self.left.unwrap_or(empty[0]);
        let r = self.right.unwrap_or(empty[0]);
        let mut acc = merkle_hash(0, &l, &r);
        let mut depth = 1usize;
        for parent in &self.parents {
            match parent {
                Some(h) => acc = merkle_hash(depth, h, &acc),
                None => acc = merkle_hash(depth, &acc, &empty[depth]),
            }
            depth += 1;
        }
        while depth < MERKLE_TREE_DEPTH {
            acc = merkle_hash(depth, &acc, &empty[depth]);
            depth += 1;
        }
        acc
    }

    // ================================================================
    // Voucher-witness helpers — port of java-tron's
    // `IncrementalMerkleTreeContainer` methods needed to build merkle
    // authentication paths for shielded notes via
    // `IncrementalMerkleVoucherContainer`.
    // ================================================================

    /// `isComplete(depth)` — java-tron's depth-parameterized check.
    /// True when both leaf cells are populated AND parents are filled
    /// at every level up to `depth - 1`.
    pub fn is_complete_at(&self, depth: usize) -> bool {
        if depth == 0 {
            return false;
        }
        if self.left.is_none() || self.right.is_none() {
            return false;
        }
        if self.parents.len() != depth - 1 {
            return false;
        }
        self.parents.iter().all(Option::is_some)
    }

    /// `last()` — most-recently-appended commitment. `None` for an
    /// empty tree (no leaves).
    pub fn last_leaf(&self) -> Option<[u8; 32]> {
        self.right.or(self.left)
    }

    /// `nextDepth(skip)` — depth at which the next-appended
    /// commitment lands, after skipping `skip` already-filled cells.
    /// Used by [`IncrementalMerkleVoucher::append`] to decide whether
    /// a new commitment slots into the witness's `filled` list (depth
    /// 0) or starts a fresh `cursor` subtree (depth > 0).
    pub fn next_depth(&self, mut skip: usize) -> usize {
        if self.left.is_none() {
            if skip != 0 {
                skip -= 1;
            } else {
                return 0;
            }
        }
        if self.right.is_none() {
            if skip != 0 {
                skip -= 1;
            } else {
                return 0;
            }
        }
        let mut d = 1usize;
        for parent in &self.parents {
            if parent.is_none() {
                if skip != 0 {
                    skip -= 1;
                } else {
                    return d;
                }
            }
            d += 1;
        }
        d + skip
    }

    /// `root(depth, fillerHashes)` — compute the root assuming the
    /// tree extends to `depth` total levels, with missing slots
    /// filled from a [`PathFiller`] queue. The voucher uses this with
    /// its `partial_path` to compute the witness's anchor root.
    pub fn root_with_filler(&self, depth: usize, fillers: &mut PathFiller<'_>) -> [u8; 32] {
        let l = self.left.unwrap_or_else(|| fillers.next(0));
        let r = self.right.unwrap_or_else(|| fillers.next(0));
        let mut acc = merkle_hash(0, &l, &r);
        let mut d = 1usize;
        for parent in &self.parents {
            match parent {
                Some(h) => acc = merkle_hash(d, h, &acc),
                None => {
                    let f = fillers.next(d);
                    acc = merkle_hash(d, &acc, &f);
                }
            }
            d += 1;
        }
        while d < depth {
            let f = fillers.next(d);
            acc = merkle_hash(d, &acc, &f);
            d += 1;
        }
        acc
    }

    /// `path(fillerHashes)` — build a merkle authentication path
    /// from the most-recently-appended leaf up to the root. Returns
    /// `None` if the tree has no leaves at all (path undefined).
    /// java-tron's algorithm reverses both the sibling list and the
    /// index list so the root-side comes first — we mirror.
    pub fn merkle_path(&self, fillers: &mut PathFiller<'_>) -> Option<MerklePath> {
        if self.left.is_none() {
            return None;
        }
        let mut siblings: Vec<[u8; 32]> = Vec::new();
        let mut index: Vec<bool> = Vec::new();
        if self.right.is_some() {
            // The "current" leaf is `right` — its sibling is `left`,
            // and the path-index bit is true (we're the right child).
            index.push(true);
            siblings.push(self.left.unwrap());
        } else {
            // The "current" leaf is `left` — sibling comes from the
            // filler queue; we're the left child.
            index.push(false);
            siblings.push(fillers.next(0));
        }
        let mut d = 1usize;
        for parent in &self.parents {
            match parent {
                Some(h) => {
                    index.push(true);
                    siblings.push(*h);
                }
                None => {
                    index.push(false);
                    siblings.push(fillers.next(d));
                }
            }
            d += 1;
        }
        while d < MERKLE_TREE_DEPTH {
            index.push(false);
            siblings.push(fillers.next(d));
            d += 1;
        }
        siblings.reverse();
        index.reverse();
        Some(MerklePath { siblings, index })
    }
}

/// Queue of fill-in subtree hashes used when computing roots / paths
/// over an incomplete tree state. Hands out fillers in FIFO order;
/// once empty, falls back to the precomputed empty-subtree hashes for
/// the requested depth. Mirrors java-tron's
/// `IncrementalMerkleTreeContainer.PathFiller`.
pub struct PathFiller<'a> {
    queue: std::collections::VecDeque<[u8; 32]>,
    empties: &'a [[u8; 32]; 32],
}

impl<'a> PathFiller<'a> {
    /// Build an empty filler — every `next(d)` call returns the
    /// canonical empty-subtree root for depth `d`.
    pub fn empty() -> Self {
        Self {
            queue: std::collections::VecDeque::new(),
            empties: uncommitted_tree(),
        }
    }

    /// Build a filler from a list of pre-populated sibling hashes.
    /// Used by [`IncrementalMerkleVoucher`] to seed the queue with
    /// its `filled` + cursor-root.
    pub fn from_queue(queue: std::collections::VecDeque<[u8; 32]>) -> Self {
        Self {
            queue,
            empties: uncommitted_tree(),
        }
    }

    /// Pop the next filler. Returns the queue head if available, or
    /// the canonical empty-subtree root for `depth` otherwise.
    pub fn next(&mut self, depth: usize) -> [u8; 32] {
        self.queue.pop_front().unwrap_or(self.empties[depth])
    }
}

/// Merkle authentication path for a leaf in an incremental tree.
/// `siblings` is depth-ordered with the root-side sibling first
/// (the same convention java-tron's `MerklePath` uses after
/// reversing internally). `index` is a bitmap: true at level `i`
/// means our node is the RIGHT child at that level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerklePath {
    pub siblings: Vec<[u8; 32]>,
    pub index: Vec<bool>,
}

impl MerklePath {
    /// Encode in java-tron's `MerklePath.encode()` wire format.
    /// Layout:
    ///   `<compact_size(siblings.len())>`
    ///   for each sibling: `<compact_size(32)> <32 bytes>`
    ///   8-byte little-endian index (MSB-first bit packing: position
    ///     `siblings.len()-1` corresponds to bit 0 of the long).
    /// Total = 1 + N*(1+32) + 8 bytes for N siblings under compact
    /// encoding (N < 253).
    pub fn encode(&self) -> Vec<u8> {
        debug_assert_eq!(self.siblings.len(), self.index.len());
        let mut out = Vec::with_capacity(1 + self.siblings.len() * 33 + 8);
        write_compact_size(&mut out, self.siblings.len() as u64);
        for sibling in &self.siblings {
            write_compact_size(&mut out, 32);
            out.extend_from_slice(sibling);
        }
        // Bit-pack the index: bool at position `i` → bit
        // `(len - 1 - i)` of a u64, then write little-endian.
        let mut index_long: u64 = 0;
        let len = self.index.len();
        for (i, b) in self.index.iter().enumerate() {
            if *b {
                let shift = (len - 1 - i) as u32;
                index_long |= 1u64 << shift;
            }
        }
        // java-tron writes 8 BE bytes then reverses to LE — we just
        // write LE directly.
        out.extend_from_slice(&index_long.to_le_bytes());
        out
    }
}

/// Bitcoin-style compact-size varint matching java-tron's
/// `MerklePath.writeCompactSize`. Used in the path wire format.
fn write_compact_size(out: &mut Vec<u8>, n: u64) {
    if n < 253 {
        out.push(n as u8);
    } else if n <= 0xFFFF {
        out.push(253);
        out.push((n & 0xFF) as u8);
        out.push((n >> 8) as u8);
    } else if n <= 0xFFFFFFFF {
        // java-tron has a typo here (allocates 4 bytes, writes 8) —
        // but for our usage with 32 siblings + 32 bytes per sibling
        // we never hit this branch. We mirror the simpler-and-correct
        // form: 0xFE byte + 4-byte LE count.
        out.push(0xFE);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xFF);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

/// Snapshot of a tree at the moment a target leaf was appended, plus
/// the running witness as later leaves are added. Mirrors java-tron's
/// `IncrementalMerkleVoucherContainer` semantics:
///
///   * `tree` — the underlying tree containing leaves `[0..=target]`.
///   * `filled` — siblings that have been "filled in" by later
///     commitments at depth 0 (i.e., right-side leaves that pair
///     with the target's level-0 path).
///   * `cursor` — a partial subtree under construction for levels
///     above 0 (depth = `cursor_depth`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IncrementalMerkleVoucher {
    pub tree: IncrementalMerkleTree,
    pub filled: Vec<[u8; 32]>,
    pub cursor: IncrementalMerkleTree,
    pub cursor_depth: usize,
}

impl IncrementalMerkleVoucher {
    /// Build a fresh voucher whose initial state is `tree` (i.e., the
    /// snapshot taken just AFTER the target leaf was appended).
    pub fn from_tree(tree: IncrementalMerkleTree) -> Self {
        Self {
            tree,
            filled: Vec::new(),
            cursor: IncrementalMerkleTree::default(),
            cursor_depth: 0,
        }
    }

    fn cursor_exists(&self) -> bool {
        // java-tron's `!cursor.isEmptyTree()` — equivalent to "the
        // cursor has at least one cell populated."
        self.cursor.left.is_some()
            || self.cursor.right.is_some()
            || self.cursor.parents.iter().any(Option::is_some)
    }

    /// Extend the witness by one commitment. Each call routes the
    /// commitment to either:
    ///   * the cursor (and rolls it up to `filled` once full at
    ///     `cursor_depth`), or
    ///   * directly into `filled` (when `next_depth == 0`), or
    ///   * a fresh cursor subtree (when `next_depth > 0`).
    /// Mirrors java-tron's `IncrementalMerkleVoucherContainer.append`.
    pub fn append(&mut self, leaf: [u8; 32]) -> Result<(), &'static str> {
        if self.cursor_exists() {
            self.cursor.append(leaf)?;
            if self.cursor.is_complete_at(self.cursor_depth) {
                // Roll the completed cursor subtree's root into
                // `filled`.
                let mut empties = PathFiller::empty();
                let root = self.cursor.root_with_filler(self.cursor_depth, &mut empties);
                self.filled.push(root);
                self.cursor = IncrementalMerkleTree::default();
                self.cursor_depth = 0;
            }
        } else {
            let next_depth = self.tree.next_depth(self.filled.len());
            self.cursor_depth = next_depth;
            if next_depth >= MERKLE_TREE_DEPTH {
                return Err("tree is full");
            }
            if next_depth == 0 {
                self.filled.push(leaf);
            } else {
                self.cursor = IncrementalMerkleTree::default();
                self.cursor.append(leaf)?;
            }
        }
        Ok(())
    }

    /// Returns the `(filled || cursor_root)` queue used as the
    /// `PathFiller` seed by `path()` / `root()`. Mirrors java-tron's
    /// `partialPath()`.
    fn partial_path(&self) -> std::collections::VecDeque<[u8; 32]> {
        let mut q: std::collections::VecDeque<[u8; 32]> =
            self.filled.iter().copied().collect();
        if self.cursor_exists() {
            let mut empties = PathFiller::empty();
            q.push_back(
                self.cursor
                    .root_with_filler(self.cursor_depth, &mut empties),
            );
        }
        q
    }

    /// Compute the merkle authentication path from the target leaf
    /// (the most-recently-appended in `tree`) up to the witness's
    /// root. Returns `None` if the snapshot tree has no leaves.
    pub fn path(&self) -> Option<MerklePath> {
        let mut fillers = PathFiller::from_queue(self.partial_path());
        self.tree.merkle_path(&mut fillers)
    }

    /// Witness anchor root (java-tron `IncrementalMerkleVoucherContainer.root()`).
    pub fn root(&self) -> [u8; 32] {
        let mut fillers = PathFiller::from_queue(self.partial_path());
        self.tree.root_with_filler(MERKLE_TREE_DEPTH, &mut fillers)
    }

    /// Leaf position of the witness's target. Matches java-tron's
    /// `position() = tree.size() - 1`.
    pub fn position(&self) -> u64 {
        self.tree.size().saturating_sub(1)
    }

    /// The target leaf itself (the most-recently-appended one in
    /// `tree`).
    pub fn element(&self) -> Option<[u8; 32]> {
        self.tree.last_leaf()
    }

    /// Round-trip from / to the on-wire proto. The `IncrementalMerkleVoucher`
    /// proto carries `tree`, `filled`, `cursor`, `cursor_depth`, `rt`,
    /// `output_point` — we only consume `tree`, `filled`, `cursor`,
    /// `cursor_depth` here; `rt` (root) and `output_point` are caller
    /// concerns.
    pub fn from_proto(p: &tron_proto::IncrementalMerkleVoucher) -> Self {
        let tree = p
            .tree
            .as_ref()
            .map(IncrementalMerkleTree::from_proto)
            .unwrap_or_default();
        let filled: Vec<[u8; 32]> = p
            .filled
            .iter()
            .filter_map(|h| {
                if h.content.len() == 32 {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&h.content);
                    Some(a)
                } else {
                    None
                }
            })
            .collect();
        let cursor = p
            .cursor
            .as_ref()
            .map(IncrementalMerkleTree::from_proto)
            .unwrap_or_default();
        Self {
            tree,
            filled,
            cursor,
            cursor_depth: p.cursor_depth as usize,
        }
    }

    /// Convert to the on-wire `IncrementalMerkleVoucher` proto.
    /// Sets `rt` to the witness root by default; callers can
    /// override via `into_proto_with_output_point` if they need to
    /// fill `output_point`.
    pub fn to_proto(&self) -> tron_proto::IncrementalMerkleVoucher {
        tron_proto::IncrementalMerkleVoucher {
            tree: Some(self.tree.to_proto()),
            filled: self
                .filled
                .iter()
                .map(|h| tron_proto::PedersenHash {
                    content: h.to_vec(),
                })
                .collect(),
            cursor: Some(self.cursor.to_proto()),
            cursor_depth: self.cursor_depth as i64,
            rt: self.root().to_vec(),
            output_point: None,
        }
    }

    /// Like [`to_proto`] but with an explicit `output_point`. Used by
    /// `Wallet.getMerkleTreeVoucherInfo` so each voucher's
    /// `output_point` round-trips back to the caller.
    pub fn to_proto_with_output_point(
        &self,
        output_point: tron_proto::OutputPoint,
    ) -> tron_proto::IncrementalMerkleVoucher {
        let mut p = self.to_proto();
        p.output_point = Some(output_point);
        p
    }
}

// =============================================================================
// MerkleHash precompile (already-shipping)
// =============================================================================

/// Compute one Merkle-tree level: `Pedersen(MerkleTree(depth),
/// lhs.255_bits_LE || rhs.255_bits_LE)`. Matches
/// `librustzcash::merkle_hash` byte-for-byte.
pub fn merkle_hash(depth: usize, lhs: &[u8; 32], rhs: &[u8; 32]) -> [u8; 32] {
    fn bits(input: &[u8; 32]) -> impl Iterator<Item = bool> + '_ {
        input
            .iter()
            .enumerate()
            .flat_map(|(_, byte)| (0..8).map(move |bit| (byte >> bit) & 1 == 1))
            .take(255)
    }
    let hash =
        pedersen_hash(Personalization::MerkleTree(depth), bits(lhs).chain(bits(rhs)));
    let affine = jubjub::ExtendedPoint::from(hash).to_affine();
    affine.get_u().to_bytes()
}

/// Decode the standard `[depth(32)][lhs(32)][rhs(32)]` precompile input.
pub fn decode_merkle_hash_input(input: &[u8]) -> Option<(usize, [u8; 32], [u8; 32])> {
    if input.len() != 96 {
        return None;
    }
    let depth_bytes: [u8; 8] = input[24..32].try_into().ok()?;
    let depth = u64::from_be_bytes(depth_bytes) as usize;
    if depth >= 63 {
        return None;
    }
    let mut lhs = [0u8; 32];
    lhs.copy_from_slice(&input[32..64]);
    let mut rhs = [0u8; 32];
    rhs.copy_from_slice(&input[64..96]);
    Some((depth, lhs, rhs))
}

// =============================================================================
// SNARK verifier — single-spend / single-output primitives
// =============================================================================

/// Compute the public inputs to the Sapling spend circuit and verify the proof.
///
/// Returns the [`ValueCommitment`] on success so the caller can add it
/// to a `CommitmentSum` for the binding-signature check. Returns
/// `None` on any failure (malformed input, proof rejected, spend_auth
/// sig invalid).
///
/// Mirrors `sapling_crypto::verifier::SaplingVerificationContextInner::check_spend`
/// but uses public types only.
#[allow(clippy::too_many_arguments)]
pub fn check_spend(
    cv_bytes: &[u8; 32],
    anchor_bytes: &[u8; 32],
    nullifier: &[u8; 32],
    rk_bytes: &[u8; 32],
    proof_bytes: &[u8; 192],
    spend_auth_sig: &[u8; 64],
    sighash: &[u8; 32],
) -> Option<ValueCommitment> {
    // Decode value commitment (must not be small order).
    let cv = ValueCommitment::from_bytes_not_small_order(cv_bytes);
    let cv: ValueCommitment = if bool::from(cv.is_some()) {
        cv.unwrap()
    } else {
        return None;
    };

    // Decode rk = redjubjub spend-auth verification key.
    let rk_jubjub = jubjub::AffinePoint::from_bytes(*rk_bytes);
    if bool::from(rk_jubjub.is_none()) {
        return None;
    }
    let rk_affine = rk_jubjub.unwrap();
    if bool::from(rk_affine.is_small_order()) {
        return None;
    }
    let rk: redjubjub::VerificationKey<SpendAuth> =
        redjubjub::VerificationKey::try_from(*rk_bytes).ok()?;

    // Verify spend_auth_sig.
    let sig = redjubjub::Signature::<SpendAuth>::from(*spend_auth_sig);
    if rk.verify(sighash, &sig).is_err() {
        return None;
    }

    // Decode anchor as a BLS12-381 scalar.
    let anchor_opt: subtle::CtOption<Scalar> = Scalar::from_repr(*anchor_bytes);
    if bool::from(anchor_opt.is_none()) {
        return None;
    }
    let anchor = anchor_opt.unwrap();

    // Decode the Groth16 proof.
    let proof = Proof::<Bls12>::read(&proof_bytes[..]).ok()?;

    // Construct the 7 public inputs for the spend circuit.
    let mut public_input = [Scalar::zero(); 7];
    {
        let (u, v) = (rk_affine.get_u(), rk_affine.get_v());
        public_input[0] = u;
        public_input[1] = v;
    }
    {
        let affine = cv.as_inner().to_affine();
        let (u, v) = (affine.get_u(), affine.get_v());
        public_input[2] = u;
        public_input[3] = v;
    }
    public_input[4] = anchor;
    {
        let bits = bytes_to_bits_le(nullifier);
        let packed = compute_multipacking(&bits);
        public_input[5] = packed[0];
        public_input[6] = packed[1];
    }

    if verify_proof(prepared_spend_vk(), &proof, &public_input).is_err() {
        return None;
    }
    Some(cv)
}

/// Same as [`check_spend`] but for the output circuit (no nullifier, no
/// spend_auth sig). Returns the [`ValueCommitment`] on success.
pub fn check_output(
    cv_bytes: &[u8; 32],
    cmu_bytes: &[u8; 32],
    epk_bytes: &[u8; 32],
    proof_bytes: &[u8; 192],
) -> Option<ValueCommitment> {
    let cv = ValueCommitment::from_bytes_not_small_order(cv_bytes);
    let cv: ValueCommitment = if bool::from(cv.is_some()) {
        cv.unwrap()
    } else {
        return None;
    };

    // Decode epk (must not be small order).
    let epk = jubjub::ExtendedPoint::from_bytes(epk_bytes);
    if bool::from(epk.is_none()) {
        return None;
    }
    let epk = epk.unwrap();
    if bool::from(epk.is_small_order()) {
        return None;
    }

    let proof = Proof::<Bls12>::read(&proof_bytes[..]).ok()?;

    // cmu is a BLS12-381 scalar (the extracted note commitment).
    let cmu_opt = Scalar::from_repr(*cmu_bytes);
    if bool::from(cmu_opt.is_none()) {
        return None;
    }
    let cmu = cmu_opt.unwrap();

    // 5 public inputs: (cv.u, cv.v, epk.u, epk.v, cmu).
    let mut public_input = [Scalar::zero(); 5];
    {
        let affine = cv.as_inner().to_affine();
        public_input[0] = affine.get_u();
        public_input[1] = affine.get_v();
    }
    {
        let affine = epk.to_affine();
        public_input[2] = affine.get_u();
        public_input[3] = affine.get_v();
    }
    public_input[4] = cmu;

    if verify_proof(prepared_output_vk(), &proof, &public_input).is_err() {
        return None;
    }
    Some(cv)
}

/// Verify the Sapling binding signature using `bvk` derived from the
/// accumulated value-commitment sum and the explicit `value_balance`.
pub fn check_binding_sig(
    cv_sum: &CommitmentSum,
    value_balance: i64,
    sighash: &[u8; 32],
    binding_sig: &[u8; 64],
) -> bool {
    let bvk: redjubjub::VerificationKey<Binding> = cv_sum.clone().into_bvk(value_balance);
    let sig = redjubjub::Signature::<Binding>::from(*binding_sig);
    bvk.verify(sighash, &sig).is_ok()
}

// =============================================================================
// Bit-packing helpers (mirrors bellman::gadgets::multipack)
// =============================================================================

fn bytes_to_bits_le(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for i in 0..8 {
            bits.push((byte >> i) & 1 == 1);
        }
    }
    bits
}

fn compute_multipacking(bits: &[bool]) -> Vec<Scalar> {
    // Pack into Scalars, taking CAPACITY (255) bits at a time.
    let capacity = Scalar::CAPACITY as usize;
    let mut out = Vec::with_capacity(bits.len().div_ceil(capacity));
    for chunk in bits.chunks(capacity) {
        let mut scalar = Scalar::zero();
        let mut coeff = Scalar::one();
        for bit in chunk {
            if *bit {
                scalar += coeff;
            }
            coeff = coeff.double();
        }
        out.push(scalar);
    }
    out
}

// =============================================================================
// TRON precompile entry points
// =============================================================================

/// `VerifyMintProof` (0x01000001). Input layout:
/// `[cm(32)|cv(32)|epk(32)|proof(192)|<gap>|binding_sig(64)|value(32 BE)|sighash(32)|frontier(33*32)|leafCount(32 BE)] = 1504 bytes`
///
/// Returns: 32-byte zero on failure; on success, a packed result of
/// `[1u256 || frontier_updates...]` produced by [`insert_leaves`].
///
/// The caller is expected to encode the variable-length frontier output
/// in DataWord chunks; we return the raw bytes.
pub fn verify_mint_proof(data: &[u8]) -> Vec<u8> {
    const SIZE: usize = 1504;
    if data.len() != SIZE {
        return vec![0u8; 32];
    }
    let mut cm = [0u8; 32];
    let mut cv = [0u8; 32];
    let mut epk = [0u8; 32];
    let mut proof = [0u8; 192];
    let mut binding_sig = [0u8; 64];
    let mut sighash = [0u8; 32];
    cm.copy_from_slice(&data[0..32]);
    cv.copy_from_slice(&data[32..64]);
    epk.copy_from_slice(&data[64..96]);
    proof.copy_from_slice(&data[96..288]);
    binding_sig.copy_from_slice(&data[288..352]);
    let value = parse_long(&data[352..384]);
    sighash.copy_from_slice(&data[384..416]);

    let mut frontier = [[0u8; 32]; 33];
    for i in 0..33 {
        frontier[i].copy_from_slice(&data[416 + i * 32..416 + (i + 1) * 32]);
    }
    let leaf_count = parse_long(&data[1472..1504]);
    const TREE_WIDTH: u64 = 1u64 << 32;
    if leaf_count as u64 >= TREE_WIDTH {
        return vec![0u8; 32];
    }

    // Run the output proof + final binding-sig check.
    let Some(out_cv) = check_output(&cv, &cm, &epk, &proof) else {
        return vec![0u8; 32];
    };
    let mut sum = CommitmentSum::zero();
    sum -= &out_cv;
    // valueBalance = -value (java-tron line 1415).
    if !check_binding_sig(&sum, -value, &sighash, &binding_sig) {
        return vec![0u8; 32];
    }

    insert_leaves(&mut frontier, leaf_count, &[cm])
}

/// `VerifyBurnProof` (0x01000003). Input layout (512 bytes):
/// `[nullifier(32)|anchor(32)|cv(32)|rk(32)|proof(192)|spend_auth_sig(64)|value(32 BE)|binding_sig(64)|sighash(32)]`
///
/// Returns 32-byte 0 or 1.
pub fn verify_burn_proof(data: &[u8]) -> Vec<u8> {
    const SIZE: usize = 512;
    if data.len() != SIZE {
        return vec![0u8; 32];
    }
    let mut nullifier = [0u8; 32];
    let mut anchor = [0u8; 32];
    let mut cv = [0u8; 32];
    let mut rk = [0u8; 32];
    let mut proof = [0u8; 192];
    let mut spend_auth_sig = [0u8; 64];
    let mut binding_sig = [0u8; 64];
    let mut sighash = [0u8; 32];
    nullifier.copy_from_slice(&data[0..32]);
    anchor.copy_from_slice(&data[32..64]);
    cv.copy_from_slice(&data[64..96]);
    rk.copy_from_slice(&data[96..128]);
    proof.copy_from_slice(&data[128..320]);
    spend_auth_sig.copy_from_slice(&data[320..384]);
    let value = parse_long(&data[384..416]);
    binding_sig.copy_from_slice(&data[416..480]);
    sighash.copy_from_slice(&data[480..512]);

    let Some(spend_cv) = check_spend(&cv, &anchor, &nullifier, &rk, &proof, &spend_auth_sig, &sighash) else {
        return data_word(false);
    };
    let mut sum = CommitmentSum::zero();
    sum += &spend_cv;
    if !check_binding_sig(&sum, value, &sighash, &binding_sig) {
        return data_word(false);
    }
    data_word(true)
}

/// `VerifyTransferProof` (0x01000002). N spends + M outputs (1..=2 each)
/// with EVM-style dynamic-offset encoding. Mirrors java-tron's parser
/// at `PrecompiledContracts.VerifyTransferProof.execute`.
pub fn verify_transfer_proof(data: &[u8]) -> Vec<u8> {
    const VALID_SIZES: [usize; 4] = [2080, 2368, 2464, 2752];
    if !VALID_SIZES.contains(&data.len()) {
        return vec![0u8; 32];
    }
    // Fixed header.
    let spend_offset = parse_int(&data[0..32]) as usize;
    let spend_auth_sig_offset = parse_int(&data[32..64]) as usize;
    let receive_offset = parse_int(&data[64..96]) as usize;
    let mut binding_sig = [0u8; 64];
    binding_sig.copy_from_slice(&data[96..160]);
    let mut sighash = [0u8; 32];
    sighash.copy_from_slice(&data[160..192]);
    let value = parse_long(&data[192..224]);
    let mut frontier = [[0u8; 32]; 33];
    for i in 0..33 {
        frontier[i].copy_from_slice(&data[224 + i * 32..224 + (i + 1) * 32]);
    }
    let leaf_count = parse_long(&data[1280..1312]);
    const TREE_WIDTH: u64 = 1u64 << 32;
    if (leaf_count as u64) >= TREE_WIDTH - 1 {
        return vec![0u8; 32];
    }

    // Spend / output counts live at their respective offset words.
    if spend_offset + 32 > data.len()
        || spend_auth_sig_offset + 32 > data.len()
        || receive_offset + 32 > data.len()
    {
        return vec![0u8; 32];
    }
    let spend_count = parse_int(&data[spend_offset..spend_offset + 32]) as usize;
    let spend_auth_sig_count =
        parse_int(&data[spend_auth_sig_offset..spend_auth_sig_offset + 32]) as usize;
    let receive_count = parse_int(&data[receive_offset..receive_offset + 32]) as usize;
    if spend_count != spend_auth_sig_count
        || !(1..=2).contains(&spend_count)
        || !(1..=2).contains(&receive_count)
    {
        return vec![0u8; 32];
    }

    let spend_base = spend_offset + 32;
    let spend_auth_base = spend_auth_sig_offset + 32;
    let receive_base = receive_offset + 32;
    // Bounds: spend uses 320 bytes per slot, sig 64, receive 288.
    if spend_base + 320 * spend_count > data.len()
        || spend_auth_base + 64 * spend_count > data.len()
        || receive_base + 288 * receive_count > data.len()
    {
        return vec![0u8; 32];
    }

    let mut sum = CommitmentSum::zero();

    // Spends.
    let mut nullifiers: Vec<[u8; 32]> = Vec::with_capacity(spend_count);
    for i in 0..spend_count {
        let base = spend_base + 320 * i;
        let mut nullifier = [0u8; 32];
        let mut anchor = [0u8; 32];
        let mut cv = [0u8; 32];
        let mut rk = [0u8; 32];
        let mut proof = [0u8; 192];
        let mut spend_auth_sig = [0u8; 64];
        nullifier.copy_from_slice(&data[base..base + 32]);
        anchor.copy_from_slice(&data[base + 32..base + 64]);
        cv.copy_from_slice(&data[base + 64..base + 96]);
        rk.copy_from_slice(&data[base + 96..base + 128]);
        proof.copy_from_slice(&data[base + 128..base + 320]);
        spend_auth_sig.copy_from_slice(
            &data[spend_auth_base + 64 * i..spend_auth_base + 64 * (i + 1)],
        );

        // Reject duplicate nullifiers.
        if nullifiers.iter().any(|n| n == &nullifier) {
            return vec![0u8; 32];
        }
        nullifiers.push(nullifier);

        let Some(spend_cv) = check_spend(
            &cv, &anchor, &nullifier, &rk, &proof, &spend_auth_sig, &sighash,
        ) else {
            return vec![0u8; 32];
        };
        sum += &spend_cv;
    }

    // Outputs.
    let mut commitments: Vec<[u8; 32]> = Vec::with_capacity(receive_count);
    for i in 0..receive_count {
        let base = receive_base + 288 * i;
        let mut cm = [0u8; 32];
        let mut cv = [0u8; 32];
        let mut epk = [0u8; 32];
        let mut proof = [0u8; 192];
        cm.copy_from_slice(&data[base..base + 32]);
        cv.copy_from_slice(&data[base + 32..base + 64]);
        epk.copy_from_slice(&data[base + 64..base + 96]);
        proof.copy_from_slice(&data[base + 96..base + 288]);

        // Reject duplicate output commitments.
        if commitments.iter().any(|c| c == &cm) {
            return vec![0u8; 32];
        }
        commitments.push(cm);

        let Some(out_cv) = check_output(&cv, &cm, &epk, &proof) else {
            return vec![0u8; 32];
        };
        sum -= &out_cv;
    }

    if !check_binding_sig(&sum, value, &sighash, &binding_sig) {
        return vec![0u8; 32];
    }

    insert_leaves(&mut frontier, leaf_count, &commitments)
}

// =============================================================================
// Merkle frontier update (mirrors java-tron's `VerifyProof.insertLeaves`)
// =============================================================================

/// Compute the frontier-slot index used by the IMT (incremental Merkle
/// tree) algorithm. See java-tron `getFrontierSlot`.
fn frontier_slot(leaf_index: u64) -> usize {
    if leaf_index % 2 == 0 {
        return 0;
    }
    let mut exp1 = 1usize;
    let mut pow1: u64 = 2;
    let mut pow2: u64 = pow1 << 1;
    loop {
        if (leaf_index + 1 - pow1) % pow2 == 0 {
            return exp1;
        }
        pow1 = pow2;
        pow2 <<= 1;
        exp1 += 1;
    }
}

/// `UNCOMMITTED[i]` = the Pedersen hash of two `UNCOMMITTED[i-1]` values
/// at depth `i-1`. `UNCOMMITTED[0]` is the canonical "uncommitted note"
/// constant `0x0100..00` (Sapling spec).
fn uncommitted_tree() -> &'static [[u8; 32]; 32] {
    static CELL: OnceLock<[[u8; 32]; 32]> = OnceLock::new();
    CELL.get_or_init(|| {
        let mut arr = [[0u8; 32]; 32];
        // The Sapling "Uncommitted^Sapling" constant.
        arr[0][0] = 0x01;
        for i in 0..31 {
            arr[i + 1] = merkle_hash(i, &arr[i], &arr[i]);
        }
        arr
    })
}

/// Update the on-chain Merkle frontier with one or more new leaves.
/// Mirrors java-tron's `VerifyProof.insertLeaves`. The output is
/// `[0x00..01 || frontier_updates...]` — the first 32 bytes are `1` (success
/// marker), followed by the new frontier slot values written in order.
fn insert_leaves(frontier: &mut [[u8; 32]; 33], leaf_count: i64, leaves: &[[u8; 32]]) -> Vec<u8> {
    let cm_count = leaves.len();
    let uncommitted = uncommitted_tree();
    let mut node_index: u64 = 0;
    let slots: Vec<usize> = (0..cm_count)
        .map(|i| frontier_slot(leaf_count as u64 + i as u64))
        .collect();

    // Output layout (java-tron `VerifyProof.insertLeaves`):
    //   32 (success marker) + Σ (slotᵢ+1)·32 (per-leaf frontier path) +
    //   32 (the single new root appended at the end).
    let mut result_len = 32usize;
    for s in &slots {
        result_len += (s + 1) * 32;
    }
    result_len += 32; // final root, written at the end (line below).
    let mut result = vec![0u8; result_len];
    result[31] = 0x01; // success marker (a 32-byte big-endian 1).
    let mut offset = 32usize;

    let mut node_value = [0u8; 32];
    for i in 0..cm_count {
        let slot_array = data_word_u8(slots[i] as u8);
        result[offset..offset + 32].copy_from_slice(&slot_array);
        offset += 32;
        node_index = i as u64 + leaf_count as u64 + (1u64 << 32) - 1;
        node_value.copy_from_slice(&leaves[i]);
        if slots[i] == 0 {
            frontier[0] = node_value;
            continue;
        }
        for level in 1..=slots[i] {
            let (left, right) = if node_index % 2 == 0 {
                let l = frontier[level - 1];
                node_index = (node_index - 1) / 2;
                (l, node_value)
            } else {
                let r = uncommitted[level - 1];
                node_index /= 2;
                (node_value, r)
            };
            let hash = merkle_hash(level - 1, &left, &right);
            node_value = hash;
            result[offset..offset + 32].copy_from_slice(&hash);
            offset += 32;
        }
        frontier[slots[i]] = node_value;
    }

    // Walk remaining levels up to the root (32).
    let last_slot = slots[cm_count - 1];
    for level in (last_slot + 1)..=32 {
        let (left, right) = if node_index % 2 == 0 {
            let l = frontier[level - 1];
            node_index = (node_index - 1) / 2;
            (l, node_value)
        } else {
            let r = uncommitted[level - 1];
            node_index /= 2;
            (node_value, r)
        };
        let hash = merkle_hash(level - 1, &left, &right);
        node_value = hash;
    }
    // Final root: append the root.
    result[offset..offset + 32].copy_from_slice(&node_value);

    result
}

// =============================================================================
// Small helpers
// =============================================================================

fn parse_long(word: &[u8]) -> i64 {
    // EVM DataWord.longValueSafe: low 8 bytes (big-endian) of the word.
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&word[24..32]);
    i64::from_be_bytes(buf)
}

fn parse_int(word: &[u8]) -> i32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&word[28..32]);
    i32::from_be_bytes(buf)
}

fn data_word(b: bool) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    if b {
        out[31] = 1;
    }
    out
}

fn data_word_u8(b: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[31] = b;
    out
}

#[cfg(test)]
mod insert_leaves_tests {
    use super::*;

    /// Independent computation of the root of a depth-32 tree holding a
    /// single leaf at index 0 — that leaf is the LEFT child at every level,
    /// so each right sibling is the uncommitted node for that depth.
    fn single_leaf_root(leaf: [u8; 32]) -> [u8; 32] {
        let uncommitted = uncommitted_tree();
        let mut node = leaf;
        for depth in 0..32 {
            node = merkle_hash(depth, &node, &uncommitted[depth]);
        }
        node
    }

    // Regression: a single leaf landing in frontier slot 0 (leaf_count even)
    // produced a 64-byte buffer while the final root was written at 64..96,
    // panicking the sync driver with "range end index 96 out of range for
    // slice of length 64". The output must budget for the appended root.
    #[test]
    fn insert_single_leaf_slot0_appends_root_without_panic() {
        let mut frontier = [[0u8; 32]; 33];
        let leaf = [0x42u8; 32];
        let out = insert_leaves(&mut frontier, 0, &[leaf]);

        // 32 (marker) + (0+1)*32 (slot word) + 32 (root).
        assert_eq!(out.len(), 96, "slot-0 single-leaf output must be 96 bytes");
        assert!(out[..31].iter().all(|&b| b == 0));
        assert_eq!(out[31], 1, "success marker");
        assert!(out[32..64].iter().all(|&b| b == 0), "slot index word == 0");
        assert_eq!(
            &out[64..96],
            single_leaf_root(leaf).as_slice(),
            "appended root must match the independent IMT computation"
        );
        assert_eq!(frontier[0], leaf, "frontier slot 0 updated to the new leaf");
    }

    // A leaf in a non-zero slot (leaf_count odd) must also reserve the root.
    #[test]
    fn insert_single_leaf_slot1_has_room_for_root() {
        // leaf_count = 1 → frontier_slot(1) == 1.
        assert_eq!(frontier_slot(1), 1);
        let mut frontier = [[0u8; 32]; 33];
        let out = insert_leaves(&mut frontier, 1, &[[0x07u8; 32]]);
        // 32 (marker) + (1+1)*32 (slot word + one level hash) + 32 (root).
        assert_eq!(out.len(), 128);
        assert_eq!(out[31], 1);
    }
}
