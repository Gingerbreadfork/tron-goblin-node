//! Hash primitives matching `org.tron.common.crypto.Hash`.
//!
//! Note: java-tron's `sha3` is **legacy Keccak-256**, not FIPS-202 SHA3-256.
//! These differ in padding bytes. We use `sha3::Keccak256`, which is the
//! legacy variant — verified against java-tron's `TRON-KECCAK-256` provider.

use sha3::Digest as _;

/// `keccak256("")` — the canonical empty-bytes hash. Used as the
/// `code_hash` of accounts with no deployed bytecode (matches
/// Ethereum's `KECCAK_EMPTY`).
pub const KECCAK_EMPTY: [u8; 32] = [
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
];

/// Legacy Keccak-256. Equivalent to `Hash.sha3(input)` in java-tron.
#[inline]
pub fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut hasher = sha3::Keccak256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// Concatenated-input Keccak-256. Equivalent to `Hash.sha3(a, b)`.
#[inline]
pub fn keccak256_pair(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut hasher = sha3::Keccak256::new();
    hasher.update(a);
    hasher.update(b);
    hasher.finalize().into()
}

/// SHA-256. Used for transaction-id hashes and the binary Merkle tree
/// (`txTrieRoot`), not for state-trie or address derivation.
#[inline]
pub fn sha256(input: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// Concatenated-input SHA-256. Matches the inner `Sha256Hash.of(left || right)`
/// call inside `MerkleTree.computeHash`.
#[inline]
pub fn sha256_pair(a: &[u8], b: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(a);
    hasher.update(b);
    hasher.finalize().into()
}

/// RIPEMD-160. Available for parity with `Hash.ripemd160`; not used in core
/// TRON address derivation.
#[inline]
pub fn ripemd160(input: &[u8]) -> [u8; 20] {
    use ripemd::Digest as _;
    let mut hasher = ripemd::Ripemd160::new();
    hasher.update(input);
    hasher.finalize().into()
}
