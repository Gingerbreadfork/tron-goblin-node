//! Edge-case tests for the consensus-critical signature + hash
//! precompiles:
//!   * `MerkleHash`         (0x01000004) — Sapling Pedersen merkle node.
//!   * `BatchValidateSign`  (0x09)       — multi-sig validation, max 16.
//!   * `ValidateMultiSign`  (0x0a)       — permissioned threshold sig.
//!
//! Our existing `tests/precompiles.rs` covers the happy paths for each
//! plus a couple of validate-multi-sign cases. This file fills in the
//! boundary conditions, malformed-input rejections, and the cross-call
//! consistency invariants (e.g., `merkle_hash` deterministic over
//! depth).

use hex_literal::hex;
use tron_crypto::address::Address;
use tron_proto::{Account, DelegatedResource, Witness};
use tron_tvm::shielded::merkle_hash;
use tron_tvm::{EvmContext, EvmContextError, PrecompileImpl};

#[derive(Default)]
struct MockCtx {
    accounts: std::collections::HashMap<Address, Account>,
    witnesses: std::collections::HashMap<Address, Witness>,
    chain_params: std::collections::HashMap<Vec<u8>, i64>,
    delegated_resources: std::collections::HashMap<(Address, Address), DelegatedResource>,
    dynamic_factors: std::collections::HashMap<Address, i64>,
    block_number: i64,
    block_timestamp_ms: i64,
}

impl EvmContext for MockCtx {
    fn caller(&self) -> Address {
        Address::from_raw([0u8; 21])
    }
    fn callee(&self) -> Address {
        Address::from_raw([0u8; 21])
    }
    fn get_account(&self, a: &Address) -> Result<Option<Account>, EvmContextError> {
        Ok(self.accounts.get(a).cloned())
    }
    fn get_witness(&self, a: &Address) -> Result<Option<Witness>, EvmContextError> {
        Ok(self.witnesses.get(a).cloned())
    }
    fn chain_parameter_long(&self, key: &[u8]) -> Result<Option<i64>, EvmContextError> {
        Ok(self.chain_params.get(key).copied())
    }
    fn block_number(&self) -> i64 {
        self.block_number
    }
    fn block_timestamp_ms(&self) -> i64 {
        self.block_timestamp_ms
    }
    fn all_witnesses(&self) -> Result<Vec<Witness>, EvmContextError> {
        Ok(self.witnesses.values().cloned().collect())
    }
    fn get_delegated_resource(
        &self,
        from: &Address,
        to: &Address,
    ) -> Result<Option<DelegatedResource>, EvmContextError> {
        Ok(self.delegated_resources.get(&(*from, *to)).cloned())
    }
    fn dynamic_energy_factor(&self, c: &Address) -> Result<i64, EvmContextError> {
        Ok(self.dynamic_factors.get(c).copied().unwrap_or(0))
    }
}

fn alice() -> Address {
    Address::from_raw(hex!("412e988a386a799f506693793c6a5af6b54dfaabfb"))
}

fn addr_word(a: &Address) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..32].copy_from_slice(&a.as_bytes()[1..]);
    w
}

fn word_with_low(byte_val: usize) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..32].copy_from_slice(&(byte_val as u64).to_be_bytes());
    w
}

/// Build calldata for a Solidity `bytes[]` of 65-byte signatures laid out
/// the way java-tron's `extractSigArray` parses it (the active
/// `allowTvmSelfdestructRestriction` path): a length word, `N`
/// relative-offset pointer words, then each 65-byte signature padded to 3
/// words. java reads element `i` from word `ptr_i/32 + head + 2`, so for
/// contiguous data `ptr_i = (N - 1 + i*3) * 32` regardless of the head
/// word index (the `+head` cancels).
fn encode_sig_array(sigs: &[[u8; 65]]) -> Vec<u8> {
    let n = sigs.len();
    let mut words: Vec<[u8; 32]> = Vec::new();
    words.push(word_with_low(n)); // length
    for i in 0..n {
        words.push(word_with_low((n - 1 + i * 3) * 32)); // pointer
    }
    for sig in sigs {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        let mut c = [0u8; 32];
        a.copy_from_slice(&sig[0..32]);
        b.copy_from_slice(&sig[32..64]);
        c[0] = sig[64];
        words.push(a);
        words.push(b);
        words.push(c);
    }
    let mut out = Vec::with_capacity(words.len() * 32);
    for w in words {
        out.extend_from_slice(&w);
    }
    out
}

/// ValidateMultiSign prehash: `SHA256(addr(21) || int32_BE(perm_id) ||
/// payload(32))` — what java recovers signatures against.
fn multi_sign_prehash(addr: &Address, perm_id: i32, payload: &[u8; 32]) -> [u8; 32] {
    let mut combine = Vec::new();
    combine.extend_from_slice(addr.as_bytes());
    combine.extend_from_slice(&perm_id.to_be_bytes());
    combine.extend_from_slice(payload);
    tron_crypto::hash::sha256(&combine)
}

/// Full ValidateMultiSign calldata: 4 head words (addr, perm_id, payload,
/// sig-array byte offset = 0x80) followed by the `bytes[]` sig array.
fn multi_sign_input(addr: &Address, perm_id: i32, payload: &[u8; 32], sigs: &[[u8; 65]]) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&addr_word(addr));
    input.extend_from_slice(&word_with_low(perm_id as usize));
    input.extend_from_slice(payload);
    input.extend_from_slice(&word_with_low(0x80)); // offset → word index 4
    input.extend_from_slice(&encode_sig_array(sigs));
    input
}

fn sign_prehash(sk: &k256::ecdsa::SigningKey, hash: &[u8; 32]) -> [u8; 65] {
    let (sig, rec) = sk.sign_prehash_recoverable(hash).expect("sign");
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&sig.to_bytes());
    out[64] = rec.to_byte();
    out
}

fn key_with_prefix(low20: &[u8; 20]) -> Vec<u8> {
    let mut v = vec![0x41u8];
    v.extend_from_slice(low20);
    v
}

fn signer_low20(sk: &k256::ecdsa::SigningKey) -> [u8; 20] {
    let vk = sk.verifying_key();
    let enc = vk.to_encoded_point(false);
    let pub_hash = tron_crypto::hash::keccak256(&enc.as_bytes()[1..]);
    let mut low20 = [0u8; 20];
    low20.copy_from_slice(&pub_hash[12..32]);
    low20
}

// =============================================================================
// MerkleHash (0x01000004)
// =============================================================================

fn pack_depth(depth: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..32].copy_from_slice(&depth.to_be_bytes());
    w
}

fn merkle_input(depth: u64, lhs: [u8; 32], rhs: [u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(&pack_depth(depth));
    out.extend_from_slice(&lhs);
    out.extend_from_slice(&rhs);
    out
}

#[test]
fn merkle_hash_rejects_wrong_input_length() {
    let ctx = MockCtx::default();
    // Too short.
    let out = PrecompileImpl::MerkleHash.execute(&[0u8; 64], &ctx);
    assert!(out.is_err(), "merkle_hash must reject 64-byte input");
    // Too long.
    let out = PrecompileImpl::MerkleHash.execute(&[0u8; 128], &ctx);
    assert!(out.is_err(), "merkle_hash must reject 128-byte input");
    // Empty.
    let out = PrecompileImpl::MerkleHash.execute(&[], &ctx);
    assert!(out.is_err(), "merkle_hash must reject empty input");
}

#[test]
fn merkle_hash_rejects_depth_at_or_above_63() {
    let ctx = MockCtx::default();
    let lhs = [0xaau8; 32];
    let rhs = [0xbbu8; 32];
    for depth in [63u64, 64, 100, u64::MAX] {
        let input = merkle_input(depth, lhs, rhs);
        let out = PrecompileImpl::MerkleHash.execute(&input, &ctx);
        assert!(
            out.is_err(),
            "merkle_hash must reject depth={depth} (≥ 63)"
        );
    }
}

#[test]
fn merkle_hash_accepts_depth_zero_through_62() {
    let ctx = MockCtx::default();
    let lhs = [0x11u8; 32];
    let rhs = [0x22u8; 32];
    for depth in [0u64, 1, 31, 62] {
        let input = merkle_input(depth, lhs, rhs);
        let out = PrecompileImpl::MerkleHash.execute(&input, &ctx);
        assert!(out.is_ok(), "merkle_hash must accept depth={depth}");
        assert_eq!(out.unwrap().len(), 32);
    }
}

#[test]
fn merkle_hash_is_deterministic_under_repeated_calls() {
    let ctx = MockCtx::default();
    let input = merkle_input(5, [0xcc; 32], [0xdd; 32]);
    let a = PrecompileImpl::MerkleHash.execute(&input, &ctx).unwrap();
    let b = PrecompileImpl::MerkleHash.execute(&input, &ctx).unwrap();
    assert_eq!(a, b);
}

#[test]
fn merkle_hash_depth_affects_output() {
    let lhs = [0x11u8; 32];
    let rhs = [0x22u8; 32];
    let h0 = merkle_hash(0, &lhs, &rhs);
    let h1 = merkle_hash(1, &lhs, &rhs);
    let h5 = merkle_hash(5, &lhs, &rhs);
    assert_ne!(h0, h1);
    assert_ne!(h1, h5);
    assert_ne!(h0, h5);
}

#[test]
fn merkle_hash_lhs_rhs_swap_changes_output() {
    let a = [0x11u8; 32];
    let b = [0x22u8; 32];
    let ab = merkle_hash(0, &a, &b);
    let ba = merkle_hash(0, &b, &a);
    assert_ne!(ab, ba);
}

#[test]
fn merkle_hash_matches_direct_function_call() {
    // Wire-format precompile path and the direct function path must
    // produce identical output for the same input.
    let ctx = MockCtx::default();
    let lhs = [0xab; 32];
    let rhs = [0xcd; 32];
    let depth = 7;
    let input = merkle_input(depth as u64, lhs, rhs);
    let via_precompile = PrecompileImpl::MerkleHash.execute(&input, &ctx).unwrap();
    let via_direct = merkle_hash(depth, &lhs, &rhs);
    assert_eq!(via_precompile, via_direct.to_vec());
}

#[test]
fn merkle_hash_truncates_to_255_bits_each_side() {
    // The 256th bit of each side is discarded (Pedersen takes 255-bit
    // inputs). Inputs differing only in the high bit of the last
    // byte must produce the SAME output.
    let lhs_a = {
        let mut a = [0u8; 32];
        a[31] = 0x00;
        a
    };
    let lhs_b = {
        let mut a = [0u8; 32];
        a[31] = 0x80; // high bit set — should be discarded
        a
    };
    let rhs = [0x33u8; 32];
    assert_eq!(merkle_hash(0, &lhs_a, &rhs), merkle_hash(0, &lhs_b, &rhs));
}

// =============================================================================
// BatchValidateSign (0x09)
// =============================================================================

#[test]
fn batch_validate_sign_rejects_short_input() {
    let ctx = MockCtx::default();
    // < 5 words is automatic false.
    for n_words in 0..5 {
        let input = vec![0u8; n_words * 32];
        let out = PrecompileImpl::BatchValidateSign.execute(&input, &ctx).unwrap();
        assert_eq!(out.last(), Some(&0u8), "n={n_words} words must be false");
    }
}

/// BatchValidateSign calldata: `hash || sig-array byte offset || addr-array
/// byte offset || sig `bytes[]` || addr `bytes32[]``. The sig array head is
/// placed at word 3 (offset 0x60); the addr array head follows it.
fn batch_input(hash: &[u8; 32], sigs: &[[u8; 65]], addrs: &[[u8; 20]]) -> Vec<u8> {
    let sig_array = encode_sig_array(sigs);
    let sig_array_words = sig_array.len() / 32;
    // addr array head word index = 3 + sig_array_words.
    let addr_head_word = 3 + sig_array_words;

    let mut input = Vec::new();
    input.extend_from_slice(hash);
    input.extend_from_slice(&word_with_low(0x60)); // sig array offset → word 3
    input.extend_from_slice(&word_with_low(addr_head_word * 32)); // addr array offset
    input.extend_from_slice(&sig_array);
    // addr `bytes32[]`: length word + one 32-byte word per address.
    input.extend_from_slice(&word_with_low(addrs.len()));
    for a in addrs {
        let mut w = [0u8; 32];
        w[12..32].copy_from_slice(a);
        input.extend_from_slice(&w);
    }
    input
}

#[test]
fn batch_validate_sign_recovers_each_signature() {
    use k256::ecdsa::SigningKey;
    let ctx = MockCtx::default();
    let mut a = [0u8; 32];
    a[31] = 1;
    a[0] = 0x01;
    let sk_a = SigningKey::from_bytes(&a.into()).unwrap();
    let mut b = [0u8; 32];
    b[31] = 2;
    b[0] = 0x01;
    let sk_b = SigningKey::from_bytes(&b.into()).unwrap();

    let hash = [0x9cu8; 32];
    let sig_a = sign_prehash(&sk_a, &hash);
    let sig_b = sign_prehash(&sk_b, &hash);
    let low_a = signer_low20(&sk_a);
    let low_b = signer_low20(&sk_b);

    // First address correct, second deliberately wrong.
    let wrong = [0xffu8; 20];
    let input = batch_input(&hash, &[sig_a, sig_b], &[low_a, wrong]);
    let out = PrecompileImpl::BatchValidateSign.execute(&input, &ctx).unwrap();
    assert_eq!(out[0], 1, "sig 0 matches addr 0");
    assert_eq!(out[1], 0, "sig 1 does not match the wrong addr");

    // Both addresses correct → both bytes set.
    let input = batch_input(&hash, &[sig_a, sig_b], &[low_a, low_b]);
    let out = PrecompileImpl::BatchValidateSign.execute(&input, &ctx).unwrap();
    assert_eq!(out[0], 1);
    assert_eq!(out[1], 1);
}

#[test]
fn batch_validate_sign_rejects_mismatched_array_lengths() {
    use k256::ecdsa::SigningKey;
    let ctx = MockCtx::default();
    let mut a = [0u8; 32];
    a[31] = 1;
    a[0] = 0x01;
    let sk_a = SigningKey::from_bytes(&a.into()).unwrap();
    let hash = [0u8; 32];
    let sig_a = sign_prehash(&sk_a, &hash);
    // 2 signatures, 1 address → cnt mismatch → false.
    let input = batch_input(&hash, &[sig_a, sig_a], &[signer_low20(&sk_a)]);
    let out = PrecompileImpl::BatchValidateSign
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(out.last(), Some(&0u8));
}

#[test]
fn batch_validate_sign_rejects_size_above_max_16() {
    let ctx = MockCtx::default();
    // Declared sig-array length 17 (> MAX_SIZE = 16) → rejected up front.
    let mut input = Vec::new();
    input.extend_from_slice(&[0u8; 32]); // hash
    input.extend_from_slice(&word_with_low(0x60)); // sig offset → word 3
    input.extend_from_slice(&word_with_low(0x80)); // addr offset → word 4
    input.extend_from_slice(&word_with_low(17)); // sig array length = 17
    input.extend_from_slice(&word_with_low(17)); // addr array length = 17
    let out = PrecompileImpl::BatchValidateSign
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(out.last(), Some(&0u8));
}

#[test]
fn batch_validate_sign_rejects_zero_size() {
    let ctx = MockCtx::default();
    // Both arrays empty → cnt == 0 → false.
    let input = batch_input(&[0u8; 32], &[], &[]);
    let out = PrecompileImpl::BatchValidateSign
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(out.last(), Some(&0u8));
}

#[test]
fn batch_validate_sign_rejects_offset_out_of_bounds() {
    let ctx = MockCtx::default();
    let mut input = vec![0u8; 5 * 32];
    // sig_offset = 100_000 (way past end) — must be Ok(false) not panic.
    input[1 * 32 + 24..1 * 32 + 32].copy_from_slice(&100_000u64.to_be_bytes());
    input[2 * 32 + 31] = 128;
    input[4 * 32 + 31] = 1;
    let out = PrecompileImpl::BatchValidateSign
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(out.last(), Some(&0u8), "out-of-bounds offset must be false");
}

// =============================================================================
// ValidateMultiSign (0x0a)
// =============================================================================

#[test]
fn validate_multi_sign_rejects_short_input() {
    let ctx = MockCtx::default();
    for n in 0..5 {
        let input = vec![0u8; n * 32];
        let out = PrecompileImpl::ValidateMultiSign
            .execute(&input, &ctx)
            .unwrap();
        assert_eq!(out.last(), Some(&0u8), "n={n} words must be false");
    }
}

#[test]
fn validate_multi_sign_rejects_zero_sig_count() {
    let ctx = MockCtx::default();
    // 4 head words + a `bytes[]` array whose length word is 0.
    let mut input = Vec::new();
    input.extend_from_slice(&addr_word(&alice()));
    input.extend_from_slice(&word_with_low(0)); // perm_id
    input.extend_from_slice(&[0u8; 32]); // payload
    input.extend_from_slice(&word_with_low(0x80)); // sig array offset → word 4
    input.extend_from_slice(&word_with_low(0)); // array length = 0
    let out = PrecompileImpl::ValidateMultiSign
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(out.last(), Some(&0u8));
}

#[test]
fn validate_multi_sign_rejects_sig_count_above_max_5() {
    let ctx = MockCtx::default();
    // Declared array length 6 (> MAX_SIZE = 5) → rejected up front.
    let mut input = Vec::new();
    input.extend_from_slice(&addr_word(&alice()));
    input.extend_from_slice(&word_with_low(0)); // perm_id
    input.extend_from_slice(&[0u8; 32]); // payload
    input.extend_from_slice(&word_with_low(0x80)); // sig array offset → word 4
    input.extend_from_slice(&word_with_low(6)); // array length = 6
    let out = PrecompileImpl::ValidateMultiSign
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(out.last(), Some(&0u8));
}

#[test]
fn validate_multi_sign_rejects_unknown_account() {
    use k256::ecdsa::SigningKey;
    let ctx = MockCtx::default();
    // Account isn't in the store → false (after array extraction).
    let mut sk_bytes = [0u8; 32];
    sk_bytes[31] = 1;
    sk_bytes[0] = 0x01;
    let sk = SigningKey::from_bytes(&sk_bytes.into()).unwrap();
    let payload = [0u8; 32];
    let hash = multi_sign_prehash(&alice(), 0, &payload);
    let sig = sign_prehash(&sk, &hash);
    let input = multi_sign_input(&alice(), 0, &payload, &[sig]);
    let out = PrecompileImpl::ValidateMultiSign
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(out.last(), Some(&0u8));
}

#[test]
fn validate_multi_sign_rejects_empty_keys_permission() {
    use k256::ecdsa::SigningKey;
    let mut ctx = MockCtx::default();
    // A permission with no keys: every recovered signer has weight 0,
    // which java treats as an incorrect sign → DATA_FALSE.
    let perm = tron_proto::Permission {
        r#type: 0,
        id: 0,
        permission_name: "owner".into(),
        threshold: 1,
        parent_id: 0,
        operations: vec![],
        keys: vec![],
    };
    ctx.accounts.insert(
        alice(),
        Account {
            address: alice().as_bytes().to_vec(),
            owner_permission: Some(perm),
            ..Default::default()
        },
    );
    let mut sk_bytes = [0u8; 32];
    sk_bytes[31] = 1;
    sk_bytes[0] = 0x01;
    let sk = SigningKey::from_bytes(&sk_bytes.into()).unwrap();
    let payload = [0u8; 32];
    let hash = multi_sign_prehash(&alice(), 0, &payload);
    let sig = sign_prehash(&sk, &hash);
    let input = multi_sign_input(&alice(), 0, &payload, &[sig]);
    let out = PrecompileImpl::ValidateMultiSign
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(out.last(), Some(&0u8));
}

#[test]
fn validate_multi_sign_threshold_exact_match_passes() {
    use k256::ecdsa::SigningKey;
    let mut ctx = MockCtx::default();
    // Single-key permission: weight 5, threshold 5 (exact match).
    let mut sk_bytes = [0u8; 32];
    sk_bytes[31] = 1;
    sk_bytes[0] = 0x01;
    let sk = SigningKey::from_bytes(&sk_bytes.into()).unwrap();
    let low20 = signer_low20(&sk);

    let perm = tron_proto::Permission {
        r#type: 0,
        id: 0,
        permission_name: "owner".into(),
        threshold: 5,
        parent_id: 0,
        operations: vec![],
        keys: vec![tron_proto::Key {
            address: key_with_prefix(&low20),
            weight: 5,
        }],
    };
    ctx.accounts.insert(
        alice(),
        Account {
            address: alice().as_bytes().to_vec(),
            owner_permission: Some(perm),
            ..Default::default()
        },
    );

    let payload = [0xfeu8; 32];
    let hash = multi_sign_prehash(&alice(), 0, &payload);
    let sig = sign_prehash(&sk, &hash);
    let input = multi_sign_input(&alice(), 0, &payload, &[sig]);

    let out = PrecompileImpl::ValidateMultiSign
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(out.last(), Some(&1u8), "exact threshold (5/5) must pass");
}

#[test]
fn validate_multi_sign_rejects_duplicate_signature() {
    use k256::ecdsa::SigningKey;
    let mut ctx = MockCtx::default();
    let mut sk_bytes = [0u8; 32];
    sk_bytes[31] = 1;
    sk_bytes[0] = 0x01;
    let sk = SigningKey::from_bytes(&sk_bytes.into()).unwrap();
    let low20 = signer_low20(&sk);

    // Single key weight 1, threshold 2. Two byte-identical sigs are
    // de-duped (java's `(recoveredAddr, sign)`-pair check) → one count.
    let perm = tron_proto::Permission {
        r#type: 0,
        id: 0,
        permission_name: "owner".into(),
        threshold: 2,
        parent_id: 0,
        operations: vec![],
        keys: vec![tron_proto::Key {
            address: key_with_prefix(&low20),
            weight: 1,
        }],
    };
    ctx.accounts.insert(
        alice(),
        Account {
            address: alice().as_bytes().to_vec(),
            owner_permission: Some(perm),
            ..Default::default()
        },
    );

    let payload = [0xfeu8; 32];
    let hash = multi_sign_prehash(&alice(), 0, &payload);
    let sig = sign_prehash(&sk, &hash);
    let input = multi_sign_input(&alice(), 0, &payload, &[sig, sig]);

    let out = PrecompileImpl::ValidateMultiSign
        .execute(&input, &ctx)
        .unwrap();
    // Total weight = 1 (one unique signer) < threshold 2 → false.
    assert_eq!(out.last(), Some(&0u8));
}

#[test]
fn validate_multi_sign_rejects_foreign_signer_weight_zero() {
    use k256::ecdsa::SigningKey;
    let mut ctx = MockCtx::default();
    // Permission key is signer A (weight 5, threshold 5). Signer B is
    // a valid signature but NOT in the permission → weight 0 → java
    // short-circuits the whole call to false even though A alone would
    // have met the threshold.
    let mut a_bytes = [0u8; 32];
    a_bytes[31] = 1;
    a_bytes[0] = 0x01;
    let sk_a = SigningKey::from_bytes(&a_bytes.into()).unwrap();
    let low20_a = signer_low20(&sk_a);

    let mut b_bytes = [0u8; 32];
    b_bytes[31] = 2;
    b_bytes[0] = 0x01;
    let sk_b = SigningKey::from_bytes(&b_bytes.into()).unwrap();

    let perm = tron_proto::Permission {
        r#type: 0,
        id: 0,
        permission_name: "owner".into(),
        threshold: 5,
        parent_id: 0,
        operations: vec![],
        keys: vec![tron_proto::Key {
            address: key_with_prefix(&low20_a),
            weight: 5,
        }],
    };
    ctx.accounts.insert(
        alice(),
        Account {
            address: alice().as_bytes().to_vec(),
            owner_permission: Some(perm),
            ..Default::default()
        },
    );

    let payload = [0x11u8; 32];
    let hash = multi_sign_prehash(&alice(), 0, &payload);
    let sig_a = sign_prehash(&sk_a, &hash);
    let sig_b = sign_prehash(&sk_b, &hash);
    // A (weight 5) then the foreign B (weight 0) — B must fail the call.
    let input = multi_sign_input(&alice(), 0, &payload, &[sig_a, sig_b]);

    let out = PrecompileImpl::ValidateMultiSign
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(
        out.last(),
        Some(&0u8),
        "a recovered signer with weight 0 fails the whole call"
    );
}
