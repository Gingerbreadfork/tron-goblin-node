//! Multi-signature precompile behaviours pinned by java-tron's
//! `BatchValidateSignContractTest` and `ValidateMultiSignContractTest`
//! (`framework/src/test/java/org/tron/common/runtime/vm/`).
//!
//! Both java tests drive the precompile at full width — 16 signature/address
//! pairs for `batchvalidatesign`, a real two-key active permission for
//! `validatemultisign` — and assert the exact 32-byte return word rather
//! than just its last byte. That is the part our existing edge-case suite
//! does not pin: `BatchValidateSign` packs one result BIT PER INDEX into the
//! word, so the tail beyond the pair count, and the all-zero word a global
//! rejection produces, are separately observable outcomes.

use hex_literal::hex;
use k256::ecdsa::SigningKey;
use tron_crypto::address::Address;
use tron_proto::{Account, DelegatedResource, Witness};
use tron_tvm::{EvmContext, EvmContextError, PrecompileError, PrecompileImpl};

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
    fn allow_tvm_selfdestruct_restriction(&self) -> bool {
        true
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

fn word_with_low(byte_val: usize) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..32].copy_from_slice(&(byte_val as u64).to_be_bytes());
    w
}

fn addr_word(a: &Address) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..32].copy_from_slice(&a.as_bytes()[1..]);
    w
}

/// A Solidity `bytes[]` of 65-byte signatures in the layout java-tron's
/// `extractSigArray` parses: a length word, one relative-offset pointer per
/// element, then each signature padded to three words.
fn encode_sig_array(sigs: &[[u8; 65]]) -> Vec<u8> {
    let n = sigs.len();
    let mut words: Vec<[u8; 32]> = Vec::new();
    words.push(word_with_low(n));
    for i in 0..n {
        words.push(word_with_low((n - 1 + i * 3) * 32));
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

fn batch_input(hash: &[u8; 32], sigs: &[[u8; 65]], addrs: &[[u8; 20]]) -> Vec<u8> {
    let sig_array = encode_sig_array(sigs);
    let addr_head_word = 3 + sig_array.len() / 32;
    let mut input = Vec::new();
    input.extend_from_slice(hash);
    input.extend_from_slice(&word_with_low(0x60));
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

fn sign_prehash(sk: &SigningKey, hash: &[u8; 32]) -> [u8; 65] {
    let (sig, rec) = sk.sign_prehash_recoverable(hash).expect("sign");
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&sig.to_bytes());
    out[64] = rec.to_byte();
    out
}

fn signer_low20(sk: &SigningKey) -> [u8; 20] {
    let enc = sk.verifying_key().to_encoded_point(false);
    let pub_hash = tron_crypto::hash::keccak256(&enc.as_bytes()[1..]);
    let mut low20 = [0u8; 20];
    low20.copy_from_slice(&pub_hash[12..32]);
    low20
}

fn seeded_key(seed: u8) -> SigningKey {
    let mut bytes = [0u8; 32];
    bytes[0] = 0x01;
    bytes[31] = seed;
    SigningKey::from_bytes(&bytes.into()).expect("valid scalar")
}

fn key_with_prefix(low20: &[u8; 20]) -> Vec<u8> {
    let mut v = vec![0x41u8];
    v.extend_from_slice(low20);
    v
}

/// `ValidateMultiSign` prehash: `SHA256(addr(21) || int32_BE(perm_id) || payload)`.
fn multi_sign_prehash(addr: &Address, perm_id: i32, payload: &[u8; 32]) -> [u8; 32] {
    let mut combine = Vec::new();
    combine.extend_from_slice(addr.as_bytes());
    combine.extend_from_slice(&perm_id.to_be_bytes());
    combine.extend_from_slice(payload);
    tron_crypto::hash::sha256(&combine)
}

fn multi_sign_input(addr: &Address, perm_id: i32, payload: &[u8; 32], sigs: &[[u8; 65]]) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&addr_word(addr));
    input.extend_from_slice(&word_with_low(perm_id as usize));
    input.extend_from_slice(payload);
    input.extend_from_slice(&word_with_low(0x80));
    input.extend_from_slice(&encode_sig_array(sigs));
    input
}

// =============================================================================
// BatchValidateSign (0x09) — BatchValidateSignContractTest
// =============================================================================

/// `staticCallTest` / `correctionTest` build 16 pairs and spoil some of them:
/// every fifth signature is replaced by `DataWord.ONE` (a 32-byte word, not a
/// signature) and the address at index 13 is the zero address. The returned
/// word must carry 1 at every sound index and 0 at each spoiled one.
///
/// `correctionTest` additionally walks all 32 bytes and requires every byte
/// at or beyond the pair count to be 0 — the result word is bit-per-index,
/// so the 16 unused slots stay clear.
#[test]
fn batch_validate_sign_maps_sixteen_pairs_and_zeroes_the_tail() {
    let ctx = MockCtx::default();
    let hash = [0x9cu8; 32];

    let mut sigs: Vec<[u8; 65]> = Vec::new();
    let mut addrs: Vec<[u8; 20]> = Vec::new();
    for i in 0..16usize {
        let sk = seeded_key((i + 1) as u8);
        if i % 5 == 0 {
            // `DataWord.ONE` in the signature slot — not a recoverable sig.
            let mut bogus = [0u8; 65];
            bogus[31] = 1;
            sigs.push(bogus);
        } else {
            sigs.push(sign_prehash(&sk, &hash));
        }
        if i == 13 {
            addrs.push([0u8; 20]);
        } else {
            addrs.push(signer_low20(&sk));
        }
    }

    let input = batch_input(&hash, &sigs, &addrs);
    let out = PrecompileImpl::BatchValidateSign
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(out.len(), 32, "the result is always one word");

    for i in 0..16usize {
        let expected = if i % 5 == 0 || i == 13 { 0 } else { 1 };
        assert_eq!(
            out[i], expected,
            "index {i}: spoiled pairs must be 0 and sound pairs 1"
        );
    }
    for (i, byte) in out.iter().enumerate().skip(16) {
        assert_eq!(*byte, 0, "byte {i} is past the pair count and must be 0");
    }
}

/// `correctionTest`'s "incorrect hash" case: the same 16 well-formed pairs
/// verified against a different hash recover different addresses, so every
/// index is 0.
#[test]
fn batch_validate_sign_wrong_hash_zeroes_every_index() {
    let ctx = MockCtx::default();
    let hash = [0x9cu8; 32];
    let mut wrong_hash = [0u8; 32];
    wrong_hash[31] = 1; // java's `DataWord.ONE().getData()`

    let mut sigs: Vec<[u8; 65]> = Vec::new();
    let mut addrs: Vec<[u8; 20]> = Vec::new();
    for i in 0..16usize {
        let sk = seeded_key((i + 1) as u8);
        sigs.push(sign_prehash(&sk, &hash));
        addrs.push(signer_low20(&sk));
    }

    // Sanity: against the hash they were made for, all 16 verify.
    let good = PrecompileImpl::BatchValidateSign
        .execute(&batch_input(&hash, &sigs, &addrs), &ctx)
        .unwrap();
    assert_eq!(&good[..16], &[1u8; 16], "control: every pair verifies");

    let out = PrecompileImpl::BatchValidateSign
        .execute(&batch_input(&wrong_hash, &sigs, &addrs), &ctx)
        .unwrap();
    assert_eq!(out, vec![0u8; 32], "a wrong hash zeroes the whole word");
}

/// `staticCallTest`'s length case: adding a 17th pair pushes the arrays past
/// `MAX_SIZE`, and java returns `new byte[32]` — not a partial result over
/// the first 16.
#[test]
fn batch_validate_sign_seventeen_pairs_returns_an_all_zero_word() {
    let ctx = MockCtx::default();
    let hash = [0x9cu8; 32];
    let mut sigs: Vec<[u8; 65]> = Vec::new();
    let mut addrs: Vec<[u8; 20]> = Vec::new();
    for i in 0..17usize {
        let sk = seeded_key((i + 1) as u8);
        sigs.push(sign_prehash(&sk, &hash));
        addrs.push(signer_low20(&sk));
    }

    let out = PrecompileImpl::BatchValidateSign
        .execute(&batch_input(&hash, &sigs, &addrs), &ctx)
        .unwrap();
    assert_eq!(out, vec![0u8; 32]);
}

/// `correctionTest`'s "different length" case: 15 signatures against 16
/// addresses is rejected wholesale, again as an all-zero word rather than a
/// result over the common prefix.
#[test]
fn batch_validate_sign_length_mismatch_returns_an_all_zero_word() {
    let ctx = MockCtx::default();
    let hash = [0x9cu8; 32];
    let mut sigs: Vec<[u8; 65]> = Vec::new();
    let mut addrs: Vec<[u8; 20]> = Vec::new();
    for i in 0..16usize {
        let sk = seeded_key((i + 1) as u8);
        if i < 15 {
            sigs.push(sign_prehash(&sk, &hash));
        }
        addrs.push(signer_low20(&sk));
    }

    let out = PrecompileImpl::BatchValidateSign
        .execute(&batch_input(&hash, &sigs, &addrs), &ctx)
        .unwrap();
    assert_eq!(out, vec![0u8; 32]);
}

// =============================================================================
// ValidateMultiSign (0x0a) — ValidateMultiSignContractTest.testDifferentCase
// =============================================================================

/// The active permission `testDifferentCase` installs: threshold 2, two keys
/// of weight 1 each, at permission id 2.
fn two_key_active_permission(a: &[u8; 20], b: &[u8; 20]) -> tron_proto::Permission {
    tron_proto::Permission {
        r#type: tron_proto::permission::PermissionType::Active as i32,
        id: 2,
        permission_name: "active".into(),
        threshold: 2,
        parent_id: 0,
        operations: vec![0u8; 32],
        keys: vec![
            tron_proto::Key {
                address: key_with_prefix(a),
                weight: 1,
            },
            tron_proto::Key {
                address: key_with_prefix(b),
                weight: 1,
            },
        ],
    }
}

fn ctx_with_active_permission(a: &[u8; 20], b: &[u8; 20]) -> MockCtx {
    let mut ctx = MockCtx::default();
    ctx.accounts.insert(
        alice(),
        Account {
            address: alice().as_bytes().to_vec(),
            active_permission: vec![two_key_active_permission(a, b)],
            ..Default::default()
        },
    );
    ctx
}

/// The headline assertion of `testDifferentCase`: the signature list is
/// `[key1, key1, key2]` — key1's signature appears TWICE — and the call still
/// returns `DataWord.ONE`.
///
/// java de-dups on the `(recoveredAddr, sign)` pair, so the repeated
/// byte-identical signature is skipped rather than counted or treated as an
/// error. The surviving weights are key1's 1 plus key2's 1, which meets the
/// threshold of 2. A dedup that instead rejected the batch, or one that
/// double-counted key1, would both produce a different answer here.
#[test]
fn validate_multi_sign_repeated_signature_is_skipped_not_rejected() {
    let sk1 = seeded_key(1);
    let sk2 = seeded_key(2);
    let low1 = signer_low20(&sk1);
    let low2 = signer_low20(&sk2);
    let ctx = ctx_with_active_permission(&low1, &low2);

    let payload = [0x2eu8; 32];
    let hash = multi_sign_prehash(&alice(), 2, &payload);
    let sig1 = sign_prehash(&sk1, &hash);
    let sig2 = sign_prehash(&sk2, &hash);

    let input = multi_sign_input(&alice(), 2, &payload, &[sig1, sig1, sig2]);
    let out = PrecompileImpl::ValidateMultiSign
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(
        out,
        word_with_low(1).to_vec(),
        "a duplicated signature is skipped; key1 + key2 still meet the threshold"
    );
}

/// secp256k1 group order, big-endian.
const SECP256K1_N: [u8; 32] =
    hex!("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

/// `(r, s, v)` → `(r, n - s, v ^ 1)`: a second valid signature by the same
/// key over the same hash. Neither java nor the precompile enforces low-s.
fn malleability_twin(sig: &[u8; 65]) -> [u8; 65] {
    let mut out = *sig;
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = i16::from(SECP256K1_N[i]) - i16::from(sig[32 + i]) - borrow;
        if d < 0 {
            out[32 + i] = (d + 256) as u8;
            borrow = 1;
        } else {
            out[32 + i] = d as u8;
            borrow = 0;
        }
    }
    out[64] ^= 1;
    out
}

/// java `ValidateMultiSign.execute` de-dups on the `(recoveredAddr, sign)`
/// pair, so a second, DIFFERENT signature by an already-counted key is not
/// skipped. Post-`VERSION_4_7_1` that path runs `MUtil.checkCPUTime()`, which
/// throws `OutOfTimeException` and fails the whole transaction OUT_OF_TIME;
/// before the fork the key's weight was simply counted again.
#[test]
fn validate_multi_sign_same_key_distinct_signature_is_out_of_time_post_4_7_1() {
    let sk1 = seeded_key(1);
    let sk2 = seeded_key(2);
    let low1 = signer_low20(&sk1);
    let low2 = signer_low20(&sk2);
    let mut ctx = ctx_with_active_permission(&low1, &low2);

    let payload = [0x2eu8; 32];
    let hash = multi_sign_prehash(&alice(), 2, &payload);
    let sig1 = sign_prehash(&sk1, &hash);
    let twin = malleability_twin(&sig1);
    assert_ne!(sig1, twin);
    let input = multi_sign_input(&alice(), 2, &payload, &[sig1, twin]);

    ctx.block_timestamp_ms = 1_700_000_000_000;
    let err = PrecompileImpl::ValidateMultiSign
        .execute(&input, &ctx)
        .expect_err("post-4.7.1 a repeated signer with a new signature is OutOfTime");
    assert!(
        matches!(err, PrecompileError::OutOfTime),
        "expected PrecompileError::OutOfTime, got {err:?}"
    );

    // Pre-fork: key1's weight of 1 is counted twice and meets the threshold
    // of 2 on its own.
    ctx.block_timestamp_ms = 1_596_780_000_000 - 1;
    let out = PrecompileImpl::ValidateMultiSign
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(out, word_with_low(1).to_vec());
}

/// `testDifferentCase`'s "weight not enough" case: key1 alone carries weight
/// 1 against a threshold of 2, so the call returns `DataWord.ZERO`.
#[test]
fn validate_multi_sign_single_key_below_threshold_returns_zero() {
    let sk1 = seeded_key(1);
    let sk2 = seeded_key(2);
    let low1 = signer_low20(&sk1);
    let low2 = signer_low20(&sk2);
    let ctx = ctx_with_active_permission(&low1, &low2);

    let payload = [0x2eu8; 32];
    let hash = multi_sign_prehash(&alice(), 2, &payload);
    let sig1 = sign_prehash(&sk1, &hash);

    let out = PrecompileImpl::ValidateMultiSign
        .execute(&multi_sign_input(&alice(), 2, &payload, &[sig1]), &ctx)
        .unwrap();
    assert_eq!(out, vec![0u8; 32]);
}

/// `testDifferentCase`'s final case: key1 plus a signature from a key outside
/// the permission. The foreign signer's weight is 0, which java treats as an
/// immediate `DATA_FALSE` for the whole call rather than merely contributing
/// nothing — so even a set that would otherwise reach the threshold fails.
#[test]
fn validate_multi_sign_foreign_signer_fails_the_whole_call() {
    let sk1 = seeded_key(1);
    let sk2 = seeded_key(2);
    let outsider = seeded_key(9);
    let low1 = signer_low20(&sk1);
    let low2 = signer_low20(&sk2);
    let ctx = ctx_with_active_permission(&low1, &low2);

    let payload = [0x2eu8; 32];
    let hash = multi_sign_prehash(&alice(), 2, &payload);
    let sig1 = sign_prehash(&sk1, &hash);
    let sig2 = sign_prehash(&sk2, &hash);
    let sig_out = sign_prehash(&outsider, &hash);

    let out = PrecompileImpl::ValidateMultiSign
        .execute(
            &multi_sign_input(&alice(), 2, &payload, &[sig1, sig_out]),
            &ctx,
        )
        .unwrap();
    assert_eq!(out, vec![0u8; 32], "a weight-0 signer fails the call");

    // And the same set with the outsider LAST, after the threshold has
    // already been met by key1 + key2 — java still returns false, because the
    // rejection happens inside the accumulation loop.
    let out = PrecompileImpl::ValidateMultiSign
        .execute(
            &multi_sign_input(&alice(), 2, &payload, &[sig1, sig2, sig_out]),
            &ctx,
        )
        .unwrap();
    assert_eq!(
        out,
        vec![0u8; 32],
        "the weight-0 rejection outranks an already-met threshold"
    );
}

/// `testAddressNonExist`: a well-formed signature against an address with no
/// account row returns `DataWord.ZERO`.
#[test]
fn validate_multi_sign_unknown_account_returns_zero() {
    let ctx = MockCtx::default();
    let sk = seeded_key(1);
    let payload = [0x2eu8; 32];
    let hash = multi_sign_prehash(&alice(), 1, &payload);
    let sig = sign_prehash(&sk, &hash);

    let out = PrecompileImpl::ValidateMultiSign
        .execute(&multi_sign_input(&alice(), 1, &payload, &[sig]), &ctx)
        .unwrap();
    assert_eq!(out, vec![0u8; 32]);
}
