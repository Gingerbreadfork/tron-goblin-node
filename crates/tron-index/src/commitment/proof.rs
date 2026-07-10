//! Standalone proof verification.
//!
//! [`verify_proof`] depends only on the [`crate::commitment::smt`] primitives
//! and the public constants — it holds no store and no node handle. This is
//! the function a third-party client (or a later on-chain verifier
//! re-implemented in Solidity) runs to check an inclusion/exclusion proof
//! against a published root, trusting nothing but keccak256 and the
//! domain-separation scheme.

use tron_crypto::keccak256;

use crate::commitment::smt::{
    default_hashes, hash_internal, hash_leaf, path_bit, NodeHash, Proof, DEPTH,
};

/// Result of verifying a [`Proof`] against an expected root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofOutcome {
    /// The key is present and `value_bytes` hashes to the proven leaf.
    Included,
    /// The key is provably absent at this root.
    Excluded,
    /// The proof does not reconstruct `expected_root` (wrong root, tampered
    /// sibling, wrong value, or a malformed proof).
    Invalid,
}

/// Recompute the root a `proof` reconstructs to, walking from the leaf slot
/// (level 256) up to the root (level 0). At each step the sibling is either the
/// next entry in `proof.siblings` (when the mask bit is set) or the level
/// default. The leaf's own contribution is its leaf-node hash when present, or
/// the empty-leaf default when absent — exactly the structure
/// [`crate::commitment::smt::Smt::apply`] produces, so a proof drawn from a
/// tree reconstructs that tree's root.
///
/// Returns `None` for a structurally malformed proof: the mask claims more
/// siblings than the list supplies, or the list carries siblings the mask never
/// references. This is the pure reconstruction shared by [`verify_proof`] and
/// by the proof generator, which adopts the reconstructed root so the served
/// `(root, proof)` pair is self-consistent by construction.
pub fn reconstruct_root(proof: &Proof) -> Option<NodeHash> {
    let d = default_hashes();

    // The node hash at the current level as we fold upward. Start at the leaf
    // slot (level 256).
    let mut acc: NodeHash = match proof.leaf_value_hash {
        Some(vh) => hash_leaf(&proof.path, &vh),
        None => d[DEPTH],
    };

    // Siblings are stored in path order (level 0 → 255); consume them from the
    // back as we fold from the deepest level upward.
    let mut next_sibling = proof.siblings.len();

    for level in (0..DEPTH).rev() {
        // The step descends from `level` to `level + 1`; its mask bit is at
        // index `level` (MSB-first).
        let sibling = if proof.mask_bit(level) {
            if next_sibling == 0 {
                // Mask claims a sibling the list can't supply — malformed.
                return None;
            }
            next_sibling -= 1;
            proof.siblings[next_sibling]
        } else {
            d[level + 1]
        };

        let path_goes_right = path_bit(&proof.path, level);
        let (l, r) = if path_goes_right {
            (sibling, acc)
        } else {
            (acc, sibling)
        };
        acc = hash_internal(level, &l, &r);
    }

    // Every claimed sibling must have been consumed; a leftover means a
    // malformed mask/siblings pairing.
    if next_sibling != 0 {
        return None;
    }

    Some(acc)
}

/// Recompute the root from `proof` and compare it to `expected_root`.
///
/// For an inclusion proof (`proof.leaf_value_hash` is `Some`), also require
/// `keccak256(value_bytes) == proof.leaf_value_hash`; `value_bytes` must be
/// supplied. For an exclusion check pass `value_bytes = None`.
pub fn verify_proof(
    expected_root: &NodeHash,
    proof: &Proof,
    value_bytes: Option<&[u8]>,
) -> ProofOutcome {
    // Inclusion proofs bind the supplied value to the proven leaf hash.
    let included = match proof.leaf_value_hash {
        Some(vh) => {
            let Some(value) = value_bytes else {
                // An inclusion proof demands the value to bind it.
                return ProofOutcome::Invalid;
            };
            if keccak256(value) != vh {
                return ProofOutcome::Invalid;
            }
            true
        }
        None => false,
    };

    let Some(acc) = reconstruct_root(proof) else {
        return ProofOutcome::Invalid;
    };

    if acc != *expected_root {
        return ProofOutcome::Invalid;
    }

    if included {
        ProofOutcome::Included
    } else {
        ProofOutcome::Excluded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::smt::{NodeOp, NodeBackend, Smt, EMPTY_ROOT, LeafPath, mask_prefix, CommitmentError};
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    // A minimal in-memory backend (mirrors smt.rs's test backend) so this
    // module's tests stand alone — proving verify_proof needs no store.
    #[derive(Default)]
    struct Mem {
        leaves: RefCell<BTreeMap<LeafPath, NodeHash>>,
        nodes: RefCell<BTreeMap<(usize, LeafPath), NodeHash>>,
    }
    impl NodeBackend for Mem {
        fn get_node(&self, level: usize, prefix: &LeafPath) -> Result<Option<NodeHash>, CommitmentError> {
            Ok(self.nodes.borrow().get(&(level, mask_prefix(prefix, level))).copied())
        }
        fn write_nodes(&self, ops: &[NodeOp]) -> Result<(), CommitmentError> {
            let mut l = self.leaves.borrow_mut();
            let mut n = self.nodes.borrow_mut();
            for op in ops {
                match op {
                    NodeOp::PutLeaf(p, h) => { l.insert(*p, *h); }
                    NodeOp::DeleteLeaf(p) => { l.remove(p); }
                    NodeOp::PutNode { level, prefix, hash } => { n.insert((*level, mask_prefix(prefix, *level)), *hash); }
                    NodeOp::DeleteNode { level, prefix } => { n.remove(&(*level, mask_prefix(prefix, *level))); }
                }
            }
            Ok(())
        }
        fn get_leaf(&self, path: &LeafPath) -> Result<Option<NodeHash>, CommitmentError> {
            Ok(self.leaves.borrow().get(path).copied())
        }
        fn leaves_under(&self, level: usize, prefix: &LeafPath, limit: usize) -> Result<Vec<(LeafPath, NodeHash)>, CommitmentError> {
            let want = mask_prefix(prefix, level);
            Ok(self.leaves.borrow().range(want..)
                .take_while(|(p, _)| mask_prefix(p, level) == want)
                .take(limit).map(|(p, h)| (*p, *h)).collect())
        }
    }

    fn lp(seed: u64) -> LeafPath {
        keccak256(&seed.to_be_bytes())
    }

    #[test]
    fn verify_depends_only_on_public_constants() {
        // Build a small tree, take a proof, verify with NO store — only the
        // proof bytes + expected root.
        let be = Mem::default();
        let mut root = EMPTY_ROOT;
        let mut raws: BTreeMap<LeafPath, Vec<u8>> = BTreeMap::new();
        for i in 0..8u64 {
            let p = lp(i * 3 + 1);
            let raw = format!("v{i}").into_bytes();
            let mut smt = Smt::open(&be, root);
            let (r, ops) = smt.apply(&[(p, Some(keccak256(&raw)))]).unwrap();
            be.write_nodes(&ops).unwrap();
            root = r;
            raws.insert(p, raw);
        }

        let smt = Smt::open(&be, root);
        for (p, raw) in &raws {
            let pr = smt.prove(p).unwrap();
            // verify_proof takes only (root, proof, value) — no backend.
            assert_eq!(verify_proof(&root, &pr, Some(raw)), ProofOutcome::Included);
        }

        // Absent key → Excluded.
        let absent = lp(424242);
        let pr = smt.prove(&absent).unwrap();
        assert_eq!(verify_proof(&root, &pr, None), ProofOutcome::Excluded);
    }

    #[test]
    fn inclusion_without_value_is_invalid() {
        let be = Mem::default();
        let p = lp(1);
        let raw = b"x".to_vec();
        let mut smt = Smt::open(&be, EMPTY_ROOT);
        let (root, ops) = smt.apply(&[(p, Some(keccak256(&raw)))]).unwrap();
        be.write_nodes(&ops).unwrap();
        let smt = Smt::open(&be, root);
        let pr = smt.prove(&p).unwrap();
        // An inclusion proof with no value cannot be bound → Invalid.
        assert_eq!(verify_proof(&root, &pr, None), ProofOutcome::Invalid);
    }

    #[test]
    fn extra_sibling_in_proof_is_invalid() {
        let be = Mem::default();
        let p = lp(2);
        let raw = b"y".to_vec();
        let mut smt = Smt::open(&be, EMPTY_ROOT);
        let (root, ops) = smt.apply(&[(p, Some(keccak256(&raw)))]).unwrap();
        be.write_nodes(&ops).unwrap();
        let smt = Smt::open(&be, root);
        let mut pr = smt.prove(&p).unwrap();
        // Append a stray sibling without setting its mask bit: leftover must
        // be rejected.
        pr.siblings.push([0xABu8; 32]);
        assert_eq!(verify_proof(&root, &pr, Some(&raw)), ProofOutcome::Invalid);
    }
}
