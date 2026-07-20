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
    /// java `VMConfig.allowTvmSelfdestructRestriction()` (proposal #94).
    /// `None` selects the post-#94 mainnet era these fixtures assume; set
    /// `Some(false)` to exercise the pre-#94 `extractBytesArray` parser.
    selfdestruct_restriction: Option<bool>,
}

impl EvmContext for MockCtx {
    fn allow_tvm_selfdestruct_restriction(&self) -> bool {
        self.selfdestruct_restriction.unwrap_or(true)
    }
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
fn merkle_hash_rejects_short_input_accepts_long() {
    // java `MerkleHash.execute` (PrecompiledContracts.java:1686) reads exactly
    // the first three 32-byte words; the only failure is a `< 96`-byte input
    // (the `arraycopy(data, 64, …)` throws). A short input → `Pair.of(false, …)`
    // → spend-all-energy revert (`SpendAllRevert`); a LONGER input is accepted
    // and the tail beyond byte 96 is ignored.
    let ctx = MockCtx::default();
    // Too short → reject (spend-all).
    let out = PrecompileImpl::MerkleHash.execute(&[0u8; 64], &ctx);
    assert!(
        matches!(out, Err(tron_tvm::PrecompileError::SpendAllRevert)),
        "merkle_hash must spend-all-revert a 64-byte input, got {out:?}"
    );
    // Empty → reject (spend-all).
    let out = PrecompileImpl::MerkleHash.execute(&[], &ctx);
    assert!(
        matches!(out, Err(tron_tvm::PrecompileError::SpendAllRevert)),
        "merkle_hash must spend-all-revert empty input, got {out:?}"
    );
    // 128 bytes (>= 96) with a valid depth-0 → SUCCESS; the same as the
    // 96-byte form because the trailing 32 bytes are ignored.
    let mut long = merkle_input(0, [0x11u8; 32], [0x22u8; 32]);
    long.extend_from_slice(&[0xccu8; 32]); // ignored tail
    let long_out = PrecompileImpl::MerkleHash
        .execute(&long, &ctx)
        .expect("128-byte merkle_hash input must succeed (tail ignored)");
    let short_out = PrecompileImpl::MerkleHash
        .execute(&merkle_input(0, [0x11u8; 32], [0x22u8; 32]), &ctx)
        .expect("96-byte merkle_hash input must succeed");
    assert_eq!(
        long_out, short_out,
        "the 32-byte tail beyond word 3 must be ignored"
    );
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

// --- MerkleHash: java's `intValueSafe` depth decode ------------------------
//
// java reads the depth word with `new DataWord(bytes).intValueSafe()`, which
// saturates to `Integer.MAX_VALUE` whenever the word occupies more than four
// bytes or its low four bytes read as a negative `int`. `MerkleHashParams
// .valid()` then rejects anything outside `[0, 63)`, so a saturated word is
// always a rejection — no matter what the low four bytes hold.

#[test]
fn merkle_hash_rejects_dirty_high_depth_bytes() {
    let ctx = MockCtx::default();
    // A perfectly valid depth of 5 in the low word, but byte 0 set: java's
    // `bytesOccupied()` is 32 > 4 → Integer.MAX_VALUE → out of range.
    let mut input = merkle_input(5, [0xaau8; 32], [0xbbu8; 32]);
    input[0] = 0x01;
    let out = PrecompileImpl::MerkleHash.execute(&input, &ctx);
    assert!(
        matches!(out, Err(tron_tvm::PrecompileError::SpendAllRevert)),
        "a non-zero high byte must saturate the depth and reject, got {out:?}"
    );
}

#[test]
fn merkle_hash_rejects_any_dirty_byte_below_the_low_word() {
    let ctx = MockCtx::default();
    // Every byte in `input[0..24]` is above the four bytes `intValueSafe`
    // reads, so a non-zero value anywhere in that range is a rejection
    // regardless of the depth encoded in the low word.
    for dirty in [0usize, 12, 23] {
        for depth in [0u64, 62] {
            let mut input = merkle_input(depth, [0xaau8; 32], [0xbbu8; 32]);
            input[dirty] = 0x01;
            let out = PrecompileImpl::MerkleHash.execute(&input, &ctx);
            assert!(
                matches!(out, Err(tron_tvm::PrecompileError::SpendAllRevert)),
                "byte {dirty} set with depth={depth} must reject, got {out:?}"
            );
        }
    }
}

#[test]
fn merkle_hash_rejects_saturating_low_word() {
    let ctx = MockCtx::default();
    // `input[28] = 0x80` → low four bytes are 0x80000000, a negative int →
    // Integer.MAX_VALUE.
    let mut neg = merkle_input(0, [0xaau8; 32], [0xbbu8; 32]);
    neg[28] = 0x80;
    assert!(
        matches!(
            PrecompileImpl::MerkleHash.execute(&neg, &ctx),
            Err(tron_tvm::PrecompileError::SpendAllRevert)
        ),
        "a negative low word must saturate and reject"
    );
    // `input[24] = 0x01` with depth 5 in the low four bytes → bytesOccupied 8.
    let mut wide = merkle_input(5, [0xaau8; 32], [0xbbu8; 32]);
    wide[24] = 0x01;
    assert!(
        matches!(
            PrecompileImpl::MerkleHash.execute(&wide, &ctx),
            Err(tron_tvm::PrecompileError::SpendAllRevert)
        ),
        "a word occupying more than four bytes must saturate and reject"
    );
}

#[test]
fn merkle_hash_clean_high_bytes_still_accepted() {
    let ctx = MockCtx::default();
    // Guards against an off-by-one in the byte window (e.g. testing
    // `word[..29]` or reading `word[27..31]`): every in-range depth with a
    // clean `input[0..28]` must still hash.
    for depth in [0u64, 1, 31, 62] {
        let input = merkle_input(depth, [0x11u8; 32], [0x22u8; 32]);
        let out = PrecompileImpl::MerkleHash
            .execute(&input, &ctx)
            .unwrap_or_else(|e| panic!("depth={depth} must be accepted, got {e:?}"));
        assert_eq!(out.len(), 32);
    }
    // Byte-identical to the value the decoder produced before the depth
    // decode was tightened.
    let out = PrecompileImpl::MerkleHash
        .execute(&merkle_input(0, [0x11u8; 32], [0x22u8; 32]), &ctx)
        .unwrap();
    assert_eq!(out, merkle_hash(0, &[0x11u8; 32], &[0x22u8; 32]).to_vec());
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

// --- BatchValidateSign: the pre-#94 `extractBytesArray` era ----------------
//
// Before ALLOW_TVM_SELFDESTRUCT_RESTRICTION (proposal #94) java parsed the
// signature array with `extractBytesArray`, whose elements carry their own
// declared length instead of a fixed 65 bytes. Every failure on this address
// is still a success-with-zero-word: `BatchValidateSign.execute` wraps
// `doExecute` in `catch (Throwable t)`.
//
// The fixtures above use `encode_sig_array`, which emits NO per-element
// length word and so is only parseable by the post-#94 reader; `MockCtx`
// defaults to that era deliberately.

/// Restriction-OFF (pre-#94) variant of [`MockCtx`].
fn pre_94_ctx() -> MockCtx {
    MockCtx {
        selfdestruct_restriction: Some(false),
        ..Default::default()
    }
}

/// Canonical Solidity `bytes[]`, as java's pre-#94 `extractBytesArray`
/// parses it: a length word, `N` pointer words relative to the start of the
/// data area, then per element a declared-length word followed by
/// `ceil(bytes.len() / 32)` data words. `declared_len` is written verbatim so
/// a test can declare a length that differs from the bytes supplied.
fn encode_bytes_array(elems: &[(Vec<u8>, usize)], head_idx: usize) -> Vec<u8> {
    let n = elems.len();
    let mut starts = Vec::with_capacity(n);
    let mut cursor = head_idx + 1 + n;
    for (bytes, _) in elems {
        starts.push(cursor);
        cursor += 1 + bytes.len().div_ceil(32);
    }
    let mut words: Vec<[u8; 32]> = vec![word_with_low(n)];
    for s in &starts {
        words.push(word_with_low((s - head_idx - 1) * 32));
    }
    for (bytes, declared) in elems {
        words.push(word_with_low(*declared));
        for chunk in bytes.chunks(32) {
            let mut w = [0u8; 32];
            w[..chunk.len()].copy_from_slice(chunk);
            words.push(w);
        }
    }
    let mut out = Vec::with_capacity(words.len() * 32);
    for w in words {
        out.extend_from_slice(&w);
    }
    out
}

/// [`batch_input`] with a canonically-encoded signature array.
fn batch_input_canonical(
    hash: &[u8; 32],
    elems: &[(Vec<u8>, usize)],
    addrs: &[[u8; 20]],
) -> Vec<u8> {
    let sig_array = encode_bytes_array(elems, 3);
    let addr_head_word = 3 + sig_array.len() / 32;

    let mut input = Vec::new();
    input.extend_from_slice(hash);
    input.extend_from_slice(&word_with_low(0x60)); // sig array offset → word 3
    input.extend_from_slice(&word_with_low(addr_head_word * 32));
    input.extend_from_slice(&sig_array);
    input.extend_from_slice(&word_with_low(addrs.len()));
    for a in addrs {
        let mut w = [0u8; 32];
        w[12..32].copy_from_slice(a);
        input.extend_from_slice(&w);
    }
    input
}

fn seeded_key(seed: u8) -> k256::ecdsa::SigningKey {
    let mut b = [0u8; 32];
    b[31] = seed;
    b[0] = 0x01;
    k256::ecdsa::SigningKey::from_bytes(&b.into()).unwrap()
}

#[test]
fn batch_validate_sign_canonical_65_byte_elements_are_era_identical() {
    // Canonical encoding with a declared length of exactly 65 must give
    // byte-identical output in both eras — the fix is inert on well-formed
    // calldata.
    let sk = seeded_key(5);
    let hash = [0x21u8; 32];
    let sig = sign_prehash(&sk, &hash);
    let input = batch_input_canonical(&hash, &[(sig.to_vec(), 65)], &[signer_low20(&sk)]);

    let post = PrecompileImpl::BatchValidateSign
        .execute(&input, &MockCtx::default())
        .unwrap();
    let pre = PrecompileImpl::BatchValidateSign
        .execute(&input, &pre_94_ctx())
        .unwrap();
    assert_eq!(post, pre);
    assert_eq!(post[0], 1, "the real signer must verify in both eras");
}

#[test]
fn batch_validate_sign_short_element_is_zero_bit_pre_94() {
    // The same valid signature, but its declared length word says 64.
    // Pre-#94 java materialises 64 bytes and `recoverAddrBySign` rejects
    // `sign.length < 65` → no recovery → result byte 0. Post-#94 the fixed
    // 65-byte read recovers the signer → result byte 1.
    let sk = seeded_key(6);
    let hash = [0x22u8; 32];
    let sig = sign_prehash(&sk, &hash);
    let input = batch_input_canonical(&hash, &[(sig.to_vec(), 64)], &[signer_low20(&sk)]);

    let post = PrecompileImpl::BatchValidateSign
        .execute(&input, &MockCtx::default())
        .unwrap();
    assert_eq!(post[0], 1, "post-#94 reads a fixed 65 bytes");

    let pre = PrecompileImpl::BatchValidateSign
        .execute(&input, &pre_94_ctx())
        .unwrap();
    assert_eq!(pre[0], 0, "pre-#94 a 64-byte element cannot recover");
}

#[test]
fn batch_validate_sign_malformed_shapes_never_revert_in_either_era() {
    // java's outer `catch (Throwable t) { return Pair.of(true, new
    // byte[WORD_SIZE]); }` means 0x09 NEVER produces a spend-all revert or an
    // uncaught throw, whatever the layout — unlike 0x0a, whose identical
    // faults burn the calling frame's whole budget. Regression guard for the
    // shared array parsers.
    let mut shapes: Vec<Vec<u8>> = Vec::new();
    // Element pointer far past the call data.
    shapes.push({
        let mut v = Vec::new();
        v.extend_from_slice(&[0u8; 32]); // hash
        v.extend_from_slice(&word_with_low(0x60)); // sig head → word 3
        v.extend_from_slice(&word_with_low(0x80)); // addr head → word 4
        v.extend_from_slice(&word_with_low(1)); // sig array len = 1
        v.extend_from_slice(&word_with_low(0x10_000 * 32)); // wild pointer
        v
    });
    // Declared sizes past MAX_SIZE with no backing words.
    shapes.push({
        let mut v = Vec::new();
        v.extend_from_slice(&[0u8; 32]);
        v.extend_from_slice(&word_with_low(0x60));
        v.extend_from_slice(&word_with_low(0x80));
        v.extend_from_slice(&word_with_low(17));
        v.extend_from_slice(&word_with_low(17));
        v
    });
    // Array heads pointing past the words present.
    shapes.push({
        let mut v = Vec::new();
        v.extend_from_slice(&[0u8; 32]);
        v.extend_from_slice(&word_with_low(0x10_000 * 32));
        v.extend_from_slice(&word_with_low(0x10_000 * 32));
        v.extend_from_slice(&[0u8; 32]);
        v.extend_from_slice(&[0u8; 32]);
        v
    });
    // A canonical element whose declared length is Integer.MAX_VALUE.
    shapes.push(batch_input_canonical(
        &[0u8; 32],
        &[(vec![0xabu8; 65], i32::MAX as usize)],
        &[[0u8; 20]],
    ));

    for (i, input) in shapes.iter().enumerate() {
        for (era, ctx) in [("post-#94", MockCtx::default()), ("pre-#94", pre_94_ctx())] {
            let out = PrecompileImpl::BatchValidateSign
                .execute(input, &ctx)
                .unwrap_or_else(|e| panic!("shape {i} {era}: 0x09 must never error, got {e:?}"));
            assert_eq!(out.len(), 32, "shape {i} {era}: output is one word");
        }
    }
}

// =============================================================================
// ValidateMultiSign (0x0a)
// =============================================================================

#[test]
fn validate_multi_sign_rejects_short_input() {
    let ctx = MockCtx::default();
    // java-tron reads the four head words (hash, address, permissionId, the
    // bytes[] offset) BEFORE its try block, so fewer than four words throws an
    // uncaught ArrayIndexOutOfBoundsException → VM.spendAllEnergy() + revert.
    for n in 0..4 {
        let input = vec![0u8; n * 32];
        let out = PrecompileImpl::ValidateMultiSign.execute(&input, &ctx);
        assert!(out.is_err(), "n={n} words: too few head words must spend-all-revert");
    }
    // Four zero words: the head reads succeed, the (zero) offset points at a
    // zero-length signature array and the zero address has no account, so this
    // is an in-try false result, not a throw.
    let input = vec![0u8; 4 * 32];
    let out = PrecompileImpl::ValidateMultiSign
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(out.last(), Some(&0u8), "4 words, no account must be false");
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

// =============================================================================
// ECRecover (0x01)
// =============================================================================
//
// java-tron implements 0x01 itself rather than inheriting the EVM precompile,
// and diverges twice: the recovered address goes through `Hash.sha3omit12`, so
// the output word carries TRON's prefix byte at index 11; and every failure
// path returns an EMPTY payload rather than a zero word.

/// Standard secp256k1 recovery vector, laid out as java reads it:
/// `hash || v-word || r || s`.
fn ecrecover_input(v: u8) -> Vec<u8> {
    let mut input = Vec::with_capacity(128);
    input.extend_from_slice(&hex!(
        "456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3"
    ));
    let mut v_word = [0u8; 32];
    v_word[31] = v;
    input.extend_from_slice(&v_word);
    input.extend_from_slice(&hex!(
        "9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608"
    ));
    input.extend_from_slice(&hex!(
        "4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada"
    ));
    input
}

#[test]
fn ecrecover_returns_the_address_in_trons_21_byte_form() {
    let ctx = MockCtx::default();
    let out = PrecompileImpl::EcRecover
        .execute(&ecrecover_input(28), &ctx)
        .expect("ecrecover succeeds");
    assert_eq!(out.len(), 32);
    assert_eq!(&out[0..11], &[0u8; 11]);
    assert_eq!(
        out[11], 0x41,
        "java `sha3omit12` prefixes the recovered address before it becomes a DataWord"
    );
    assert_eq!(
        &out[12..32],
        &hex!("7156526fbd7a3c72969b54f64e42c10fbb768c8a"),
        "the 20-byte body still matches the standard recovery result"
    );
}

#[test]
fn ecrecover_returns_empty_on_failure_rather_than_a_zero_word() {
    let ctx = MockCtx::default();
    // java `ECDSASignature.validateComponents` accepts only v == 27 or 28.
    for bad_v in [0u8, 26, 29, 31] {
        let out = PrecompileImpl::EcRecover
            .execute(&ecrecover_input(bad_v), &ctx)
            .expect("the precompile itself still succeeds");
        assert!(
            out.is_empty(),
            "v={bad_v} must yield an empty payload, got {} bytes",
            out.len()
        );
    }
}

#[test]
fn ecrecover_rejects_a_v_word_with_bytes_above_the_last() {
    let ctx = MockCtx::default();
    // java `validateV` requires every byte above the last to be zero.
    let mut input = ecrecover_input(28);
    input[32] = 0x01;
    let out = PrecompileImpl::EcRecover
        .execute(&input, &ctx)
        .expect("the precompile itself still succeeds");
    assert!(out.is_empty(), "validateV must reject a dirty v word");
}

#[test]
fn ecrecover_returns_empty_for_input_shorter_than_the_three_fixed_words() {
    let ctx = MockCtx::default();
    // Below 96 bytes java's `System.arraycopy` of h/v/r throws; the surrounding
    // catch turns that into the empty result.
    for len in [0usize, 31, 64, 95] {
        let input = ecrecover_input(28)[..len].to_vec();
        let out = PrecompileImpl::EcRecover
            .execute(&input, &ctx)
            .expect("the precompile itself still succeeds");
        assert!(out.is_empty(), "len={len} must yield an empty payload");
    }
}

#[test]
fn ecrecover_zero_fills_a_truncated_s_word() {
    let ctx = MockCtx::default();
    // 96..128 bytes is legal: java left-aligns what it has into `s` and leaves
    // the rest zero, so this resolves to a (wrong but well-formed) signature
    // and must not panic.
    let input = ecrecover_input(28)[..100].to_vec();
    let out = PrecompileImpl::EcRecover
        .execute(&input, &ctx)
        .expect("the precompile itself still succeeds");
    assert!(out.is_empty() || out.len() == 32);
}

/// An account with NO stored owner permission still validates its own
/// signature. java's `getPermissionById(0)` falls back to
/// `createDefaultOwnerPermission` (AccountCapsule.java:194-208) — a synthetic
/// single-key permission over the account's own address, weight and threshold
/// 1. Accounts created before ALLOW_MULTI_SIGN never materialized a stored
/// permission, so on mainnet this fallback is the ordinary path: the USDT
/// contract and other pre-2019 accounts all carry an empty `owner_permission`.
#[test]
fn validate_multi_sign_synthesizes_the_default_owner_permission() {
    use k256::ecdsa::SigningKey;
    let mut ctx = MockCtx::default();

    // Derive the signer, then register the account under ITS address with no
    // owner_permission set — the shape mainnet accounts actually have.
    let mut sk_bytes = [0u8; 32];
    sk_bytes[31] = 1;
    sk_bytes[0] = 0x01;
    let sk = SigningKey::from_bytes(&sk_bytes.into()).unwrap();
    let mut raw = [0u8; 21];
    raw[0] = 0x41;
    raw[1..].copy_from_slice(&signer_low20(&sk));
    let signer = Address::from_raw(raw);

    ctx.accounts.insert(
        signer,
        tron_proto::Account {
            address: signer.as_bytes().to_vec(),
            // owner_permission deliberately absent
            ..Default::default()
        },
    );

    let payload = [0u8; 32];
    let hash = multi_sign_prehash(&signer, 0, &payload);
    let sig = sign_prehash(&sk, &hash);
    let input = multi_sign_input(&signer, 0, &payload, &[sig]);

    let out = PrecompileImpl::ValidateMultiSign.execute(&input, &ctx).unwrap();
    assert_eq!(
        out.last(),
        Some(&1u8),
        "the account's own signature must satisfy the synthesized default permission"
    );
}
