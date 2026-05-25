//! Binary Merkle tree used for `txTrieRoot` and `accountStateRoot`-adjacent
//! per-block transaction commitments. Matches
//! `org.tron.core.capsule.utils.MerkleTree`.
//!
//! Rules:
//! * Leaf hashes are 32-byte SHA-256 (not Keccak).
//! * Parents combine children as `sha256(left || right)`.
//! * If a level has an odd count, the last lone child is **promoted as-is**
//!   (no rehash, no duplication). This is a divergence from Bitcoin's
//!   "duplicate the last leaf" rule.
//! * The empty list has no defined root in java-tron (it throws
//!   `IndexOutOfBoundsException`). We surface that as `None` here.

use crate::hash::sha256_pair;

/// Compute the Merkle root over `leaves` using the java-tron rule set.
///
/// Returns `None` if `leaves` is empty (matching the "no root" semantics of
/// the reference implementation).
pub fn merkle_root(leaves: &[[u8; 32]]) -> Option<[u8; 32]> {
    if leaves.is_empty() {
        return None;
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        level = combine_level(&level);
    }
    Some(level[0])
}

fn combine_level(level: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut next = Vec::with_capacity(level.len().div_ceil(2));
    let mut i = 0;
    while i < level.len() {
        if i + 1 < level.len() {
            next.push(sha256_pair(&level[i], &level[i + 1]));
        } else {
            // Odd tail: promote as-is.
            next.push(level[i]);
        }
        i += 2;
    }
    next
}
