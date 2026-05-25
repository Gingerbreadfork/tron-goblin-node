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

#[test]
fn batch_validate_sign_rejects_mismatched_array_lengths() {
    let ctx = MockCtx::default();
    // hash (1 word) || sig_offset (1 word) || addr_offset (1 word) ||
    // sigs_array_len (1 word) || addrs_array_len (1 word). Different
    // counts → reject.
    let mut input = vec![0u8; 5 * 32];
    // hash = zeros (word 0)
    // sig_offset = 96 (word 1) → points to word index 3
    input[1 * 32 + 31] = 96;
    // addr_offset = 128 (word 2) → points to word index 4
    input[2 * 32 + 31] = 128;
    // sigs_array_len = 2 (word 3)
    input[3 * 32 + 31] = 2;
    // addrs_array_len = 1 (word 4) — MISMATCH
    input[4 * 32 + 31] = 1;
    let out = PrecompileImpl::BatchValidateSign
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(out.last(), Some(&0u8));
}

#[test]
fn batch_validate_sign_rejects_size_above_max_16() {
    let ctx = MockCtx::default();
    let mut input = vec![0u8; 5 * 32];
    input[1 * 32 + 31] = 96;
    input[2 * 32 + 31] = 128;
    // sigs_array_len = 17 (> MAX_SIZE = 16)
    input[3 * 32 + 31] = 17;
    input[4 * 32 + 31] = 17;
    let out = PrecompileImpl::BatchValidateSign
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(out.last(), Some(&0u8));
}

#[test]
fn batch_validate_sign_rejects_zero_size() {
    let ctx = MockCtx::default();
    let mut input = vec![0u8; 5 * 32];
    input[1 * 32 + 31] = 96;
    input[2 * 32 + 31] = 128;
    // sig_count = 0 and addr_count = 0 — even though they match,
    // zero size is invalid.
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
    let mut input = vec![0u8; 5 * 32];
    input[..32].copy_from_slice(&addr_word(&alice())); // some address
    input[1 * 32 + 31] = 0; // perm_id
    // word 2 = hash (zeros)
    // word 3 = offset (zeros, doesn't matter)
    // word 4 = sig_count = 0
    let out = PrecompileImpl::ValidateMultiSign
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(out.last(), Some(&0u8));
}

#[test]
fn validate_multi_sign_rejects_sig_count_above_max_5() {
    let ctx = MockCtx::default();
    let mut input = vec![0u8; 5 * 32];
    input[..32].copy_from_slice(&addr_word(&alice()));
    input[4 * 32 + 31] = 6; // > MAX_SIGS = 5
    let out = PrecompileImpl::ValidateMultiSign
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(out.last(), Some(&0u8));
}

#[test]
fn validate_multi_sign_rejects_unknown_account() {
    let ctx = MockCtx::default();
    // Account isn't in the store.
    let mut input = vec![0u8; 5 * 32 + 96];
    input[..32].copy_from_slice(&addr_word(&alice()));
    input[1 * 32 + 31] = 0; // perm_id
    input[4 * 32 + 31] = 1; // sig_count = 1
    // Junk sig bytes — but we never get there because account lookup
    // fails first.
    let out = PrecompileImpl::ValidateMultiSign
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(out.last(), Some(&0u8));
}

#[test]
fn validate_multi_sign_rejects_zero_threshold_permission() {
    let mut ctx = MockCtx::default();
    let perm = tron_proto::Permission {
        r#type: 0,
        id: 0,
        permission_name: "owner".into(),
        threshold: 0, // bogus: per-spec rejected
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
    let mut input = vec![0u8; 5 * 32 + 96];
    input[..32].copy_from_slice(&addr_word(&alice()));
    input[1 * 32 + 31] = 0;
    input[4 * 32 + 31] = 1;
    let out = PrecompileImpl::ValidateMultiSign
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(out.last(), Some(&0u8));
}

#[test]
fn validate_multi_sign_threshold_exact_match_passes() {
    let mut ctx = MockCtx::default();
    use k256::ecdsa::SigningKey;
    // Build a single-key permission where the only key has weight 5
    // and threshold = 5 (exact).
    let mut sk_bytes = [0u8; 32];
    sk_bytes[31] = 1;
    sk_bytes[0] = 0x01;
    let sk = SigningKey::from_bytes(&sk_bytes.into()).unwrap();
    let vk = sk.verifying_key();
    let enc = vk.to_encoded_point(false);
    let pub_hash = tron_crypto::hash::keccak256(&enc.as_bytes()[1..]);
    let mut key_addr_full = vec![0x41u8];
    key_addr_full.extend_from_slice(&pub_hash[12..32]);

    let perm = tron_proto::Permission {
        r#type: 0,
        id: 0,
        permission_name: "owner".into(),
        threshold: 5,
        parent_id: 0,
        operations: vec![],
        keys: vec![tron_proto::Key {
            address: key_addr_full,
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

    let hash = [0xfeu8; 32];
    let (sig, rec) = sk.sign_prehash_recoverable(&hash).unwrap();
    let mut sig_bytes = [0u8; 65];
    sig_bytes[..64].copy_from_slice(&sig.to_bytes());
    sig_bytes[64] = rec.to_byte();
    let mut sig_padded = [0u8; 96];
    sig_padded[..65].copy_from_slice(&sig_bytes);

    let mut input = Vec::new();
    input.extend_from_slice(&addr_word(&alice()));
    let mut perm_id = [0u8; 32];
    perm_id[31] = 0;
    input.extend_from_slice(&perm_id);
    input.extend_from_slice(&hash);
    let mut offset = [0u8; 32];
    offset[31] = 0x80;
    input.extend_from_slice(&offset);
    let mut sig_count = [0u8; 32];
    sig_count[31] = 1;
    input.extend_from_slice(&sig_count);
    input.extend_from_slice(&sig_padded);

    let out = PrecompileImpl::ValidateMultiSign
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(out.last(), Some(&1u8), "exact threshold (5/5) must pass");
}

#[test]
fn validate_multi_sign_rejects_duplicate_signature() {
    let mut ctx = MockCtx::default();
    use k256::ecdsa::SigningKey;
    let mut sk_bytes = [0u8; 32];
    sk_bytes[31] = 1;
    sk_bytes[0] = 0x01;
    let sk = SigningKey::from_bytes(&sk_bytes.into()).unwrap();
    let vk = sk.verifying_key();
    let enc = vk.to_encoded_point(false);
    let pub_hash = tron_crypto::hash::keccak256(&enc.as_bytes()[1..]);
    let mut key_addr_full = vec![0x41u8];
    key_addr_full.extend_from_slice(&pub_hash[12..32]);

    // Single key weight 1, threshold 2. Two copies of the same sig
    // should NOT pass the threshold (each unique signer counted once).
    let perm = tron_proto::Permission {
        r#type: 0,
        id: 0,
        permission_name: "owner".into(),
        threshold: 2,
        parent_id: 0,
        operations: vec![],
        keys: vec![tron_proto::Key {
            address: key_addr_full,
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

    let hash = [0xfeu8; 32];
    let (sig, rec) = sk.sign_prehash_recoverable(&hash).unwrap();
    let mut sig_bytes = [0u8; 65];
    sig_bytes[..64].copy_from_slice(&sig.to_bytes());
    sig_bytes[64] = rec.to_byte();
    let mut sig_padded = [0u8; 96];
    sig_padded[..65].copy_from_slice(&sig_bytes);

    let mut input = Vec::new();
    input.extend_from_slice(&addr_word(&alice()));
    let mut perm_id = [0u8; 32];
    perm_id[31] = 0;
    input.extend_from_slice(&perm_id);
    input.extend_from_slice(&hash);
    let mut offset = [0u8; 32];
    offset[31] = 0x80;
    input.extend_from_slice(&offset);
    let mut sig_count = [0u8; 32];
    sig_count[31] = 2;
    input.extend_from_slice(&sig_count);
    // Same signature twice.
    input.extend_from_slice(&sig_padded);
    input.extend_from_slice(&sig_padded);

    let out = PrecompileImpl::ValidateMultiSign
        .execute(&input, &ctx)
        .unwrap();
    // Total weight = 1 (one unique signer) < threshold 2 → false.
    assert_eq!(out.last(), Some(&0u8));
}
