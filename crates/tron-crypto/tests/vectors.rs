//! Byte-for-byte parity tests against fixtures extracted from java-tron.
//!
//! Sources (paths relative to the java-tron submodule):
//! * `framework/src/test/java/org/tron/common/crypto/ECKeyTest.java`
//! * `framework/src/test/java/org/tron/core/capsule/utils/MerkleTreeTest.java`
//! * `crypto/src/main/java/org/tron/common/crypto/Hash.java` (EMPTY_TRIE_HASH)
//!
//! If a test in this file ever fails after a refactor, you have introduced a
//! consensus-breaking change. Don't "fix" the expected value.

use hex_literal::hex;
use tron_crypto::address::Address;
use tron_crypto::base58check::{decode_address, decode_check, encode_address, encode_check, Base58CheckError};
use tron_crypto::hash::{keccak256, sha256};
use tron_crypto::merkle::merkle_root;
use tron_crypto::rlp::encode_element;
use tron_crypto::signature::RecoverableSignature;

// --- Address derivation -----------------------------------------------------

/// `ECKeyTest.testGetAddress` — uncompressed pubkey → 21-byte address.
#[test]
fn address_from_uncompressed_pubkey_matches_eckey_test() {
    let pubkey = hex!(
        "04"
        "e90c7d3640a1568839c31b70a893ab6714ef8415b9de90cedfc1c8f353a6983e"
        "625529392df7fa514bdd65a2003f6619567d79bee89830e63e932dbd42362d34"
    );
    let expected = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");
    let addr = Address::from_uncompressed_pubkey(&pubkey).unwrap();
    assert_eq!(addr.as_bytes(), &expected);
    assert_eq!(addr.prefix(), 0x41);
}

/// `ECKeyTest.testGetAddress` (alternate form: X||Y without the 0x04 marker).
#[test]
fn address_from_pubkey_xy_matches_eckey_test() {
    let pubkey_xy = hex!(
        "e90c7d3640a1568839c31b70a893ab6714ef8415b9de90cedfc1c8f353a6983e"
        "625529392df7fa514bdd65a2003f6619567d79bee89830e63e932dbd42362d34"
    );
    let expected = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");
    let addr = Address::from_pubkey_xy(&pubkey_xy).unwrap();
    assert_eq!(addr.as_bytes(), &expected);
}

#[test]
fn address_rejects_wrong_pubkey_length() {
    let short = [0u8; 32];
    assert!(Address::from_uncompressed_pubkey(&short).is_err());
}

#[test]
fn address_rejects_missing_uncompressed_marker() {
    let mut bad = [0u8; 65];
    bad[0] = 0x02; // compressed marker, not allowed here
    assert!(Address::from_uncompressed_pubkey(&bad).is_err());
}

// --- Hash primitives --------------------------------------------------------

/// Cross-check: `keccak256(b"")` is a well-known constant. Distinguishes
/// legacy Keccak from FIPS-202 SHA3-256.
#[test]
fn keccak256_empty_matches_legacy_value() {
    let expected = hex!("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    assert_eq!(keccak256(b""), expected);
}

#[test]
fn sha256_empty_matches_known_value() {
    let expected = hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(sha256(b""), expected);
}

// --- ECDSA sign/recover -----------------------------------------------------

/// `ECKeyTest.testFromPrivateKey` — well-known private key produces the
/// expected uncompressed pubkey. This validates our secp256k1 mult is using
/// the same curve as java-tron.
#[test]
fn pubkey_from_private_key_matches_eckey_test() {
    // `generateOccupationConstantPrivateKey()` = "1234567890" × 6 + "1234"
    // = 64 hex chars, parsed as a BigInteger and used as a 256-bit scalar.
    let priv_key = hex!("1234567890123456789012345678901234567890123456789012345678901234");
    let expected_pubkey = hex!(
        "04"
        "e90c7d3640a1568839c31b70a893ab6714ef8415b9de90cedfc1c8f353a6983e"
        "625529392df7fa514bdd65a2003f6619567d79bee89830e63e932dbd42362d34"
    );

    use k256::ecdsa::SigningKey;
    let sk = SigningKey::from_bytes(&priv_key.into()).unwrap();
    let vk = sk.verifying_key();
    let encoded = vk.to_encoded_point(false);
    assert_eq!(encoded.as_bytes(), &expected_pubkey);
}

/// `ECKeyTest.testToString` — privkey 10 produces a specific pubkey.
#[test]
fn pubkey_from_private_key_ten() {
    let mut priv_key = [0u8; 32];
    priv_key[31] = 10;
    let expected_pubkey = hex!(
        "04"
        "a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7"
        "893aba425419bc27a3b6c7e693a24c696f794c2ed877a1593cbee53b037368d7"
    );
    use k256::ecdsa::SigningKey;
    let sk = SigningKey::from_bytes(&priv_key.into()).unwrap();
    let vk = sk.verifying_key();
    assert_eq!(vk.to_encoded_point(false).as_bytes(), &expected_pubkey);
}

/// Sign-then-recover round trip with the address check at the end. This is
/// the same flow that `ECKey.sign` + `signatureToAddress` perform.
#[test]
fn sign_and_recover_round_trips_to_correct_address() {
    let priv_key = hex!("1234567890123456789012345678901234567890123456789012345678901234");
    let expected_address = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");

    let prehash = keccak256(b"the quick brown fox jumps over the lazy dog");
    let sig = RecoverableSignature::sign_prehash(&priv_key, &prehash).unwrap();

    assert!(sig.is_canonical(), "signature must be low-S canonical");
    let recovered_pubkey = sig.recover_uncompressed_pubkey(&prehash).unwrap();
    let recovered_address = Address::from_uncompressed_pubkey(&recovered_pubkey).unwrap();
    assert_eq!(recovered_address.as_bytes(), &expected_address);
}

/// Encode/decode round trip via the on-chain (`[r||s||v]`) layout.
#[test]
fn signature_on_chain_layout_round_trip() {
    let priv_key = [42u8; 32]; // any non-zero scalar < N
    let prehash = keccak256(b"tron-rust");
    let sig = RecoverableSignature::sign_prehash(&priv_key, &prehash).unwrap();

    let bytes = sig.to_bytes();
    let decoded = RecoverableSignature::from_bytes(&bytes).unwrap();
    assert_eq!(decoded, sig);

    // Recovery still works after the round trip.
    let pk = decoded.recover_uncompressed_pubkey(&prehash).unwrap();
    sig.verify_prehash(&pk, &prehash).unwrap();
}

/// Regression: java-tron accepts signatures of length **>= 65** (it reads
/// r=[0..32], s=[32..64], v=byte[64] and ignores the rest). Some wallets pad
/// `v` to a 4-byte word → 68-byte on-chain signatures. We must parse them the
/// same (rejecting them made our node DEFAULT those txs while java executed).
#[test]
fn from_bytes_accepts_oversized_signature_ignoring_trailing_bytes() {
    let priv_key = [7u8; 32];
    let prehash = keccak256(b"oversized v");
    let sig = RecoverableSignature::sign_prehash(&priv_key, &prehash).unwrap();
    let bytes65 = sig.to_bytes();

    // Append 3 zero bytes (the wallet's 4-byte v padding) → 68 bytes.
    let mut bytes68 = bytes65.to_vec();
    bytes68.extend_from_slice(&[0, 0, 0]);
    let decoded = RecoverableSignature::from_bytes(&bytes68).unwrap();
    assert_eq!(decoded, sig, "68-byte sig parses identically to the 65-byte one");

    // And it still recovers the right key.
    let pk = decoded.recover_uncompressed_pubkey(&prehash).unwrap();
    sig.verify_prehash(&pk, &prehash).unwrap();

    // Shorter than 65 is still rejected (matches java's `< 65` guard).
    assert!(RecoverableSignature::from_bytes(&bytes65[..64]).is_err());
}

/// Encode/decode round trip via the header-prefix (`[v||r||s]`) layout.
#[test]
fn signature_header_prefix_layout_round_trip() {
    let priv_key = [99u8; 32];
    let prehash = keccak256(b"another message");
    let sig = RecoverableSignature::sign_prehash(&priv_key, &prehash).unwrap();

    let bytes = sig.to_header_prefix_bytes();
    assert!(bytes[0] >= 27 && bytes[0] <= 30, "header byte must be in 27..=30");
    let decoded = RecoverableSignature::from_header_prefix_bytes(&bytes).unwrap();
    assert_eq!(decoded, sig);
}

// --- Binary Merkle tree -----------------------------------------------------

/// `MerkleTreeTest.test1HashNum` — single leaf, root equals that leaf.
#[test]
fn merkle_root_of_one() {
    let leaf = sha256(b"\x00\x00\x00\x00");
    let root = merkle_root(&[leaf]).unwrap();
    assert_eq!(root, leaf);
}

/// `MerkleTreeTest.test2HashNum` — two leaves, root = sha256(left || right).
#[test]
fn merkle_root_of_two() {
    let l0 = sha256(b"\x00\x00\x00\x00");
    let l1 = sha256(b"\x00\x00\x00\x01");
    let root = merkle_root(&[l0, l1]).unwrap();

    let mut concat = Vec::with_capacity(64);
    concat.extend_from_slice(&l0);
    concat.extend_from_slice(&l1);
    let expected = sha256(&concat);
    assert_eq!(root, expected);
}

/// Odd-tail rule: with three leaves, the rightmost is promoted as-is, then
/// the resulting pair is hashed at the next level.
///
/// Level 0: [A, B, C]
/// Level 1: [sha256(A||B), C]
/// Level 2: [sha256(sha256(A||B) || C)]
#[test]
fn merkle_root_odd_tail_is_promoted_not_duplicated() {
    let a = sha256(b"\x00\x00\x00\x00");
    let b = sha256(b"\x00\x00\x00\x01");
    let c = sha256(b"\x00\x00\x00\x02");

    let mut ab_concat = Vec::with_capacity(64);
    ab_concat.extend_from_slice(&a);
    ab_concat.extend_from_slice(&b);
    let ab = sha256(&ab_concat);

    let mut abc_concat = Vec::with_capacity(64);
    abc_concat.extend_from_slice(&ab);
    abc_concat.extend_from_slice(&c);
    let expected = sha256(&abc_concat);

    let root = merkle_root(&[a, b, c]).unwrap();
    assert_eq!(root, expected);
}

#[test]
fn merkle_root_of_empty_is_none() {
    assert!(merkle_root(&[]).is_none());
}

/// Cross-validate against `MerkleTreeTest.testConcurrent`. Computes the same
/// `list1` of 10,000 leaves and checks the root.
#[test]
fn merkle_root_10000_leaves_list1_matches_java_tron() {
    let leaves: Vec<[u8; 32]> = (0..10_000)
        .map(|i| sha256(format!("byte1-{i}").as_bytes()))
        .collect();
    let expected = hex!("6cb38b4f493db8bacf26123cd4253bbfc530c708b97b3747e782f64097c3c482");
    let root = merkle_root(&leaves).unwrap();
    assert_eq!(root, expected);
}

#[test]
fn merkle_root_10000_leaves_list2_matches_java_tron() {
    let leaves: Vec<[u8; 32]> = (0..10_000)
        .map(|i| sha256(format!("byte2-{i}").as_bytes()))
        .collect();
    let expected = hex!("4bfc60ea3de4f5d1476f839874df0aba38eec4e524d6fa63f5b19c4bf527eaf3");
    let root = merkle_root(&leaves).unwrap();
    assert_eq!(root, expected);
}

// --- RLP encoding -----------------------------------------------------------

/// `EMPTY_TRIE_HASH` = `keccak256(rlp(empty_bytes))` = `keccak256([0x80])`.
/// This is the well-known Ethereum empty-trie root.
#[test]
fn empty_trie_hash_matches_ethereum_value() {
    let rlp_empty = encode_element(b"");
    assert_eq!(rlp_empty, vec![0x80]);
    let h = keccak256(&rlp_empty);
    let expected = hex!("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");
    assert_eq!(h, expected);
}

/// Single-byte string `[0x00..0x7f]` encodes to itself.
#[test]
fn rlp_single_low_byte_is_identity() {
    assert_eq!(encode_element(&[0x00]), vec![0x00]);
    assert_eq!(encode_element(&[0x7f]), vec![0x7f]);
}

/// Single byte `>= 0x80` gets the short-item prefix.
#[test]
fn rlp_single_high_byte_gets_prefix() {
    assert_eq!(encode_element(&[0x80]), vec![0x81, 0x80]);
    assert_eq!(encode_element(&[0xff]), vec![0x81, 0xff]);
}

/// 1..55-byte strings get the `0x80+len` prefix.
#[test]
fn rlp_short_string() {
    let data = b"dog";
    assert_eq!(encode_element(data), vec![0x83, b'd', b'o', b'g']);
}

// --- Base58Check ------------------------------------------------------------

/// Genesis "Zion" account from java-tron's main-net config. The Base58
/// string and its decoded 21-byte raw address are both publicly documented.
#[test]
fn base58check_decodes_mainnet_zion_address() {
    let addr = decode_address("TLLM21wteSPs4hKjbxgmH1L6poyMjeTbHm").unwrap();
    // First byte is mainnet prefix 0x41; round-trip back to string.
    assert_eq!(addr.prefix(), 0x41);
    assert_eq!(encode_address(&addr), "TLLM21wteSPs4hKjbxgmH1L6poyMjeTbHm");
}

#[test]
fn base58check_round_trips_arbitrary_payload() {
    let payload = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");
    let encoded = encode_check(&payload);
    let decoded = decode_check(&encoded).unwrap();
    assert_eq!(decoded, payload);
}

#[test]
fn base58check_rejects_bad_checksum() {
    let payload = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");
    let mut encoded = encode_check(&payload);
    // Corrupt the last char (part of the checksum tail).
    let last = encoded.pop().unwrap();
    let corrupted = if last == 'A' { 'B' } else { 'A' };
    encoded.push(corrupted);
    assert_eq!(decode_check(&encoded), Err(Base58CheckError::ChecksumMismatch));
}

#[test]
fn base58check_rejects_too_short() {
    // 3 bytes can't contain a 4-byte checksum.
    let s = bs58::encode([0u8, 1, 2]).into_string();
    assert_eq!(decode_check(&s), Err(Base58CheckError::TooShort));
}

/// 56+ byte strings use the length-of-length prefix.
#[test]
fn rlp_long_string() {
    let data = vec![0xabu8; 56];
    let out = encode_element(&data);
    assert_eq!(out[0], 0xb8); // 0xb7 + 1 (length fits in 1 byte)
    assert_eq!(out[1], 56);
    assert_eq!(&out[2..], &data[..]);
}
