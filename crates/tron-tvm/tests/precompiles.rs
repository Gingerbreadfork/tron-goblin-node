//! Tests for the TRON precompile registry, the energy/gas model, and
//! the few precompiles implemented in Phase 1.

use hex_literal::hex;
use tron_crypto::address::Address;
use tron_proto::{Account, AccountType, DelegatedResource, Vote, Witness};
use tron_tvm::{
    energy_fee_in_sun, energy_to_gas, energy_with_dynamic_penalty, gas_to_energy, EnergyError,
    EvmContext, EvmContextError, PrecompileImpl, ALL_PRECOMPILES, DYNAMIC_ENERGY_FACTOR_DECIMAL,
};

// =============================================================================
// Mock EvmContext
// =============================================================================

#[derive(Default)]
struct MockContext {
    caller: Option<Address>,
    callee: Option<Address>,
    accounts: std::collections::HashMap<Address, Account>,
    witnesses: std::collections::HashMap<Address, Witness>,
    chain_params: std::collections::HashMap<Vec<u8>, i64>,
    delegated_resources: std::collections::HashMap<(Address, Address), DelegatedResource>,
    dynamic_factors: std::collections::HashMap<Address, i64>,
    block_number: i64,
    block_timestamp_ms: i64,
}

impl EvmContext for MockContext {
    fn caller(&self) -> Address {
        self.caller.unwrap_or_else(|| Address::from_raw([0u8; 21]))
    }
    fn callee(&self) -> Address {
        self.callee.unwrap_or_else(|| Address::from_raw([0u8; 21]))
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
        let mut v: Vec<_> = self.witnesses.values().cloned().collect();
        // Stable order for tests (address-sorted matches RocksDB scan order).
        v.sort_by_key(|w| w.address.clone());
        Ok(v)
    }
    fn get_delegated_resource(
        &self,
        from: &Address,
        to: &Address,
    ) -> Result<Option<DelegatedResource>, EvmContextError> {
        Ok(self.delegated_resources.get(&(*from, *to)).cloned())
    }
    fn dynamic_energy_factor(&self, contract: &Address) -> Result<i64, EvmContextError> {
        Ok(self.dynamic_factors.get(contract).copied().unwrap_or(0))
    }
}

fn alice() -> Address {
    Address::from_raw(hex!("412e988a386a799f506693793c6a5af6b54dfaabfb"))
}
fn bob() -> Address {
    Address::from_raw(hex!("41a614f803b6fd780986a42c78ec9c7f77e6ded13c"))
}

/// Pack `addr` (21 bytes) into a 32-byte right-padded word the way the
/// EVM does for address-typed arguments: zero-pad the high 12 bytes,
/// then place the LAST 20 bytes of the address (omitting the 0x41 prefix)
/// in the low 20.
fn addr_word(a: &Address) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..32].copy_from_slice(&a.as_bytes()[1..]);
    w
}

// =============================================================================
// Address registry
// =============================================================================

#[test]
fn precompile_addresses_match_java_tron_pinned_values() {
    use tron_tvm::address::*;
    assert_eq!(ADDR_ECRECOVER[19], 0x01);
    assert_eq!(ADDR_SHA256[19], 0x02);
    assert_eq!(ADDR_BATCH_VALIDATE_SIGN[19], 0x09);
    assert_eq!(ADDR_VALIDATE_MULTI_SIGN[19], 0x0a);
    // TRON-specific addresses start at 0x01000001.
    // 0x01000005 = 1.001.0005 in the bytes layout:
    assert_eq!(&ADDR_REWARD_BALANCE[16..20], &[0x01, 0x00, 0x00, 0x05]);
    assert_eq!(&ADDR_GET_CHAIN_PARAMETER[16..20], &[0x01, 0x00, 0x00, 0x0b]);
    assert_eq!(&ADDR_VERIFY_MINT_PROOF[16..20], &[0x01, 0x00, 0x00, 0x01]);
    assert_eq!(&ADDR_TOTAL_ACQUIRED_RESOURCE[16..20], &[0x01, 0x00, 0x00, 0x15]);
    // P256Verify = 0x100.
    assert_eq!(ADDR_P256_VERIFY[19], 0x00);
    assert_eq!(ADDR_P256_VERIFY[18], 0x01);
    // Blake2F = 0x20009.
    assert_eq!(&ADDR_BLAKE2F[16..20], &[0x00, 0x02, 0x00, 0x09]);
}

#[test]
fn registry_round_trips_address_to_impl() {
    for &p in ALL_PRECOMPILES {
        let addr = p.address();
        assert_eq!(
            PrecompileImpl::from_address(&addr),
            Some(p),
            "round-trip failed for {p:?}"
        );
    }
}

#[test]
fn registry_has_no_duplicate_addresses() {
    let mut seen = std::collections::HashSet::new();
    for &p in ALL_PRECOMPILES {
        assert!(seen.insert(p.address()), "duplicate address for {p:?}");
    }
}

// =============================================================================
// Energy model
// =============================================================================

#[test]
fn gas_to_energy_is_one_to_one() {
    assert_eq!(gas_to_energy(0), 0);
    assert_eq!(gas_to_energy(21_000), 21_000);
    assert_eq!(energy_to_gas(21_000), 21_000);
}

#[test]
fn energy_fee_multiplies_by_per_unit_sun() {
    assert_eq!(energy_fee_in_sun(1_000, 210).unwrap(), 210_000);
    assert_eq!(energy_fee_in_sun(0, 210).unwrap(), 0);
}

#[test]
fn energy_fee_overflow_is_reported() {
    let err = energy_fee_in_sun(u64::MAX, 1_000_000).unwrap_err();
    assert_eq!(err, EnergyError::Overflow);
}

#[test]
fn energy_fee_rejects_negative_per_unit() {
    assert_eq!(
        energy_fee_in_sun(100, -1),
        Err(EnergyError::NegativeFee)
    );
}

/// **The dynamic energy formula**:
/// `effective = base * (DECIMAL + factor) / DECIMAL`.
/// Pin specific numeric points.
#[test]
fn dynamic_energy_penalty_uses_decimal_basis_formula() {
    let base = 1_000;
    // factor = 0 → no penalty
    assert_eq!(energy_with_dynamic_penalty(base, 0).unwrap(), base);
    // factor = DECIMAL → effective doubled
    assert_eq!(
        energy_with_dynamic_penalty(base, DYNAMIC_ENERGY_FACTOR_DECIMAL).unwrap(),
        2 * base
    );
    // factor = DECIMAL/2 → effective += 50%
    assert_eq!(
        energy_with_dynamic_penalty(base, DYNAMIC_ENERGY_FACTOR_DECIMAL / 2).unwrap(),
        base + base / 2
    );
}

// =============================================================================
// IsSrCandidate
// =============================================================================

#[test]
fn is_sr_candidate_returns_true_for_registered_witness() {
    let mut ctx = MockContext::default();
    ctx.witnesses.insert(
        alice(),
        Witness {
            address: alice().as_bytes().to_vec(),
            ..Default::default()
        },
    );
    let input = addr_word(&alice());
    let out = PrecompileImpl::IsSrCandidate.execute(&input, &ctx).unwrap();
    // 32-byte boolean: last byte 1, rest 0.
    assert_eq!(out.len(), 32);
    assert_eq!(out[31], 1);
}

#[test]
fn is_sr_candidate_returns_false_for_unknown_witness() {
    let ctx = MockContext::default();
    let input = addr_word(&alice());
    let out = PrecompileImpl::IsSrCandidate.execute(&input, &ctx).unwrap();
    assert_eq!(out[31], 0);
}

#[test]
fn is_sr_candidate_with_wrong_input_length_is_false() {
    let ctx = MockContext::default();
    let input = vec![0u8; 16]; // not 32 bytes
    let out = PrecompileImpl::IsSrCandidate.execute(&input, &ctx).unwrap();
    assert_eq!(out[31], 0);
}

// =============================================================================
// VoteCount + UsedVoteCount + ReceivedVoteCount
// =============================================================================

#[test]
fn vote_count_sums_matching_witness_votes() {
    let mut ctx = MockContext::default();
    // Alice has voted bob:7 (and a third party z:5)
    ctx.accounts.insert(
        alice(),
        Account {
            address: alice().as_bytes().to_vec(),
            r#type: AccountType::Normal as i32,
            votes: vec![
                Vote { vote_address: bob().as_bytes().to_vec(), vote_count: 7 },
                Vote { vote_address: vec![0x41; 21], vote_count: 5 },
            ],
            ..Default::default()
        },
    );
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&addr_word(&alice()));
    input[32..].copy_from_slice(&addr_word(&bob()));
    let out = PrecompileImpl::VoteCount.execute(&input, &ctx).unwrap();
    // 7 in big-endian 32-byte form.
    let mut expected = [0u8; 32];
    expected[31] = 7;
    assert_eq!(out, expected);
}

#[test]
fn used_vote_count_sums_all_account_votes() {
    let mut ctx = MockContext::default();
    ctx.accounts.insert(
        alice(),
        Account {
            address: alice().as_bytes().to_vec(),
            r#type: AccountType::Normal as i32,
            votes: vec![
                Vote { vote_address: bob().as_bytes().to_vec(), vote_count: 7 },
                Vote { vote_address: vec![0x41; 21], vote_count: 5 },
            ],
            ..Default::default()
        },
    );
    let input = addr_word(&alice());
    let out = PrecompileImpl::UsedVoteCount.execute(&input, &ctx).unwrap();
    let mut expected = [0u8; 32];
    expected[31] = 12;
    assert_eq!(out, expected);
}

#[test]
fn received_vote_count_reads_witness_vote_count() {
    let mut ctx = MockContext::default();
    ctx.witnesses.insert(
        alice(),
        Witness {
            address: alice().as_bytes().to_vec(),
            vote_count: 999,
            ..Default::default()
        },
    );
    let input = addr_word(&alice());
    let out = PrecompileImpl::ReceivedVoteCount.execute(&input, &ctx).unwrap();
    // 999 = 0x3e7, little nibble at byte 31, high nibble at byte 30.
    assert_eq!(out[30], 0x03);
    assert_eq!(out[31], 0xe7);
}

#[test]
fn received_vote_count_zero_for_unknown_witness() {
    let ctx = MockContext::default();
    let input = addr_word(&alice());
    let out = PrecompileImpl::ReceivedVoteCount.execute(&input, &ctx).unwrap();
    assert_eq!(out, [0u8; 32]);
}

// =============================================================================
// GetChainParameter
// =============================================================================

#[test]
fn get_chain_parameter_returns_pinned_value_by_selector() {
    let mut ctx = MockContext::default();
    ctx.chain_params.insert(b"MAINTENANCE_TIME_INTERVAL".to_vec(), 21_600_000);
    // Selector 0 = MAINTENANCE_TIME_INTERVAL.
    let mut input = [0u8; 32];
    input[31] = 0;
    let out = PrecompileImpl::GetChainParameter.execute(&input, &ctx).unwrap();
    let mut expected = [0u8; 32];
    expected[24..].copy_from_slice(&21_600_000i64.to_be_bytes());
    assert_eq!(out, expected);
}

#[test]
fn get_chain_parameter_unknown_selector_returns_zero() {
    let ctx = MockContext::default();
    let mut input = [0u8; 32];
    input[31] = 99; // not in our pinned table
    let out = PrecompileImpl::GetChainParameter.execute(&input, &ctx).unwrap();
    assert_eq!(out, [0u8; 32]);
}

// =============================================================================
// RewardBalance
// =============================================================================

#[test]
fn reward_balance_returns_caller_allowance() {
    let mut ctx = MockContext::default();
    ctx.caller = Some(alice());
    ctx.accounts.insert(
        alice(),
        Account {
            address: alice().as_bytes().to_vec(),
            allowance: 1_234_567,
            ..Default::default()
        },
    );
    let out = PrecompileImpl::RewardBalance.execute(&[], &ctx).unwrap();
    // 1_234_567 = 0x12d687 (3 bytes).
    let mut expected = [0u8; 32];
    expected[29..].copy_from_slice(&[0x12, 0xd6, 0x87]);
    assert_eq!(out, expected);
}

// =============================================================================
// Energy cost lookups
// =============================================================================

#[test]
fn energy_costs_match_pinned_values_from_java_tron() {
    assert_eq!(PrecompileImpl::IsSrCandidate.energy_cost(&[]), 20);
    assert_eq!(PrecompileImpl::VoteCount.energy_cost(&[]), 500);
    assert_eq!(PrecompileImpl::RewardBalance.energy_cost(&[]), 500);
    assert_eq!(PrecompileImpl::GetChainParameter.energy_cost(&[]), 500);
    assert_eq!(PrecompileImpl::ValidateMultiSign.energy_cost(&[]), 1500);
}

/// BatchValidateSign charges 1500 energy per signature. Input layout is
/// `5 words header + 6 words per signature`. A call with 3 signatures
/// has 5 + 18 = 23 words = 736 bytes.
#[test]
fn batch_validate_sign_energy_scales_per_signature() {
    let input_3_sigs = vec![0u8; 23 * 32];
    assert_eq!(
        PrecompileImpl::BatchValidateSign.energy_cost(&input_3_sigs),
        3 * 1500
    );
    let input_0_sigs = vec![0u8; 5 * 32];
    assert_eq!(PrecompileImpl::BatchValidateSign.energy_cost(&input_0_sigs), 0);
}

// =============================================================================
// P256Verify (EIP-7951)
// =============================================================================

#[test]
fn p256_verify_returns_empty_on_wrong_length() {
    let ctx = MockContext::default();
    assert!(PrecompileImpl::P256Verify
        .execute(&[0u8; 159], &ctx)
        .unwrap()
        .is_empty());
    assert!(PrecompileImpl::P256Verify
        .execute(&[0u8; 161], &ctx)
        .unwrap()
        .is_empty());
    assert!(PrecompileImpl::P256Verify
        .execute(&[], &ctx)
        .unwrap()
        .is_empty());
}

#[test]
fn p256_verify_returns_empty_for_zero_public_key() {
    let ctx = MockContext::default();
    // All-zero public key (0, 0) is point-at-infinity-like; reject.
    let out = PrecompileImpl::P256Verify.execute(&[0u8; 160], &ctx).unwrap();
    assert!(out.is_empty());
}

#[test]
fn p256_verify_accepts_fips_186_4_vector() {
    // Adapted from FIPS 186-4 ECDSA test vector for P-256/SHA-256.
    // Source: NIST SigGen.txt — vector 0 from p256 crate's test fixtures.
    let ctx = MockContext::default();
    let m = hex::decode("44acf6b7e36c1342c2c5897204fe09504e1e2efb1a900377dbc4e7a6a133ec56").unwrap();
    let r = hex::decode("f3ac8061b514795b8843e3d6629527ed2afd6b1f6a555a7acabb5e6f79c8c2ac").unwrap();
    let s = hex::decode("8bf77819ca05a6b2786c76262bf7371cef97b218e96f175a3ccdda2acc058903").unwrap();
    let qx = hex::decode("1ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83").unwrap();
    let qy = hex::decode("ce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9").unwrap();
    let mut input = Vec::with_capacity(160);
    input.extend_from_slice(&m);
    input.extend_from_slice(&r);
    input.extend_from_slice(&s);
    input.extend_from_slice(&qx);
    input.extend_from_slice(&qy);
    assert_eq!(input.len(), 160);
    let out = PrecompileImpl::P256Verify.execute(&input, &ctx).unwrap();
    // Expected: 32-byte word ending in 0x01.
    let mut expected = vec![0u8; 32];
    expected[31] = 1;
    assert_eq!(out, expected);
}

#[test]
fn p256_verify_rejects_tampered_signature() {
    let ctx = MockContext::default();
    let m = hex::decode("44acf6b7e36c1342c2c5897204fe09504e1e2efb1a900377dbc4e7a6a133ec56").unwrap();
    let r = hex::decode("f3ac8061b514795b8843e3d6629527ed2afd6b1f6a555a7acabb5e6f79c8c2ac").unwrap();
    let mut s = hex::decode("8bf77819ca05a6b2786c76262bf7371cef97b218e96f175a3ccdda2acc058903").unwrap();
    s[0] ^= 0x01; // flip a bit
    let qx = hex::decode("1ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83").unwrap();
    let qy = hex::decode("ce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9").unwrap();
    let mut input = Vec::new();
    input.extend(m);
    input.extend(r);
    input.extend(s);
    input.extend(qx);
    input.extend(qy);
    let out = PrecompileImpl::P256Verify.execute(&input, &ctx).unwrap();
    assert!(out.is_empty(), "tampered signature must be rejected");
}

#[test]
fn p256_verify_rejects_off_curve_public_key() {
    let ctx = MockContext::default();
    let m = vec![0xaau8; 32];
    let r = vec![0xbbu8; 32];
    let s = vec![0xccu8; 32];
    let qx = vec![0xddu8; 32]; // garbage — almost certainly off-curve
    let qy = vec![0xeeu8; 32];
    let mut input = Vec::new();
    input.extend(m);
    input.extend(r);
    input.extend(s);
    input.extend(qx);
    input.extend(qy);
    let out = PrecompileImpl::P256Verify.execute(&input, &ctx).unwrap();
    assert!(out.is_empty(), "off-curve public key must be rejected");
}

// =============================================================================
// Deferred precompile reporting
// =============================================================================

// =============================================================================
// Blake2F (EIP-152)
// =============================================================================

#[test]
fn blake2f_rejects_wrong_input_length() {
    let ctx = MockContext::default();
    let err = PrecompileImpl::Blake2F.execute(&[0u8; 212], &ctx).unwrap_err();
    assert!(matches!(
        err,
        tron_tvm::PrecompileError::BadInputLength { got: 212, expected: 213 }
    ));
    let err = PrecompileImpl::Blake2F.execute(&[0u8; 214], &ctx).unwrap_err();
    assert!(matches!(
        err,
        tron_tvm::PrecompileError::BadInputLength { got: 214, expected: 213 }
    ));
}

#[test]
fn blake2f_rejects_invalid_finalization_flag() {
    let ctx = MockContext::default();
    let mut input = [0u8; 213];
    input[212] = 2; // not 0 or 1
    let err = PrecompileImpl::Blake2F.execute(&input, &ctx).unwrap_err();
    assert!(matches!(err, tron_tvm::PrecompileError::Malformed));
}

#[test]
fn blake2f_matches_eip152_reference_vector_4() {
    // EIP-152 test vector 4 (12 rounds, f=1): produces a specific 64-byte
    // output. Verified against go-ethereum's Blake2F precompile.
    let ctx = MockContext::default();
    let hex_input = "0000000c\
        48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5\
        d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b\
        6162630000000000000000000000000000000000000000000000000000000000\
        0000000000000000000000000000000000000000000000000000000000000000\
        0000000000000000000000000000000000000000000000000000000000000000\
        0000000000000000000000000000000000000000000000000000000000000000\
        03000000000000000000000000000000\
        01";
    let input = hex::decode(hex_input).expect("valid hex");
    assert_eq!(input.len(), 213);
    let out = PrecompileImpl::Blake2F.execute(&input, &ctx).expect("blake2f ok");
    // Output from EIP-152 vector 4:
    let expected = hex::decode(
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
         7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
    )
    .unwrap();
    assert_eq!(out, expected);
}

#[test]
fn shielded_snark_verifier_precompiles_return_32_byte_zero_on_empty_input() {
    // All four shielded precompiles are now implemented. With empty
    // input the SNARK verifiers reject (wrong length) and return a
    // 32-byte zero word. Detailed coverage lives in
    // `tron-tvm/tests/shielded.rs`.
    let ctx = MockContext::default();
    for p in [
        PrecompileImpl::VerifyMintProof,
        PrecompileImpl::VerifyTransferProof,
        PrecompileImpl::VerifyBurnProof,
    ] {
        let out = p.execute(&[], &ctx).expect("returns Ok with zero word");
        assert_eq!(out, vec![0u8; 32]);
    }
}

#[test]
fn standard_evm_precompiles_say_handled_by_interpreter() {
    let ctx = MockContext::default();
    for p in [
        PrecompileImpl::EcRecover,
        PrecompileImpl::Sha256,
        PrecompileImpl::Ripemd160,
        PrecompileImpl::Identity,
        PrecompileImpl::ModExp,
        PrecompileImpl::Bn128Add,
        PrecompileImpl::Bn128Mul,
        PrecompileImpl::Bn128Pairing,
    ] {
        let err = p.execute(&[], &ctx).unwrap_err();
        assert!(matches!(err, tron_tvm::PrecompileError::HandledByInterpreter));
    }
}

// =============================================================================
// TotalVoteCount (real implementation, post-Phase 2a)
// =============================================================================

#[test]
fn total_vote_count_sums_across_all_witnesses() {
    let mut ctx = MockContext::default();
    let a = alice();
    let b = bob();
    ctx.witnesses.insert(
        a,
        Witness {
            address: a.as_bytes().to_vec(),
            vote_count: 1_000,
            ..Default::default()
        },
    );
    ctx.witnesses.insert(
        b,
        Witness {
            address: b.as_bytes().to_vec(),
            vote_count: 250,
            ..Default::default()
        },
    );
    let out = PrecompileImpl::TotalVoteCount.execute(&[], &ctx).unwrap();
    assert_eq!(out.len(), 32);
    let mut be = [0u8; 8];
    be.copy_from_slice(&out[24..32]);
    assert_eq!(i64::from_be_bytes(be), 1250);
}

#[test]
fn total_vote_count_returns_zero_with_no_witnesses() {
    let ctx = MockContext::default();
    let out = PrecompileImpl::TotalVoteCount.execute(&[], &ctx).unwrap();
    let mut be = [0u8; 8];
    be.copy_from_slice(&out[24..32]);
    assert_eq!(i64::from_be_bytes(be), 0);
}

// =============================================================================
// ValidateMultiSign — uses on-chain Permission, weighted threshold check
// =============================================================================

/// Encode a 65-byte sig into the 3-word layout the TRON precompiles
/// expect: bytes [0..65] hold the signature, [65..96] is zero padding.
fn encode_sig(sig: &[u8; 65]) -> [u8; 96] {
    let mut out = [0u8; 96];
    out[..65].copy_from_slice(sig);
    out
}

/// Deterministic keypair from a fixed 32-byte seed. Avoids pulling in
/// `rand` as a dev-dep and keeps the multi-sign tests fully reproducible.
fn keypair_from_seed(seed: u8) -> (k256::ecdsa::SigningKey, [u8; 20]) {
    use k256::ecdsa::SigningKey;
    let mut bytes = [0u8; 32];
    bytes[31] = seed; // tiny non-zero scalar
    bytes[0] = 0x01; // ensure within secp256k1 order
    let sk = SigningKey::from_bytes(&bytes.into()).expect("valid scalar");
    let vk = sk.verifying_key();
    let enc = vk.to_encoded_point(false);
    let pub_hash = tron_crypto::hash::keccak256(&enc.as_bytes()[1..]);
    let mut low20 = [0u8; 20];
    low20.copy_from_slice(&pub_hash[12..32]);
    (sk, low20)
}

fn sign_prehash(sk: &k256::ecdsa::SigningKey, hash: &[u8; 32]) -> [u8; 65] {
    let (sig, rec) = sk.sign_prehash_recoverable(hash).expect("sign");
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&sig.to_bytes());
    out[64] = rec.to_byte();
    out
}

#[test]
fn validate_multi_sign_meets_threshold_when_weights_sum_to_target() {
    let mut ctx = MockContext::default();
    let target_addr = alice();

    // Two keys with weight 1 each; threshold = 2.
    let (sk1, k1) = keypair_from_seed(1);
    let (sk2, k2) = keypair_from_seed(2);
    let mut k1_addr_with_prefix = vec![0x41u8];
    k1_addr_with_prefix.extend_from_slice(&k1);
    let mut k2_addr_with_prefix = vec![0x41u8];
    k2_addr_with_prefix.extend_from_slice(&k2);

    let perm = tron_proto::Permission {
        r#type: 0,
        id: 0,
        permission_name: "owner".into(),
        threshold: 2,
        parent_id: 0,
        operations: vec![],
        keys: vec![
            tron_proto::Key {
                address: k1_addr_with_prefix.clone(),
                weight: 1,
            },
            tron_proto::Key {
                address: k2_addr_with_prefix.clone(),
                weight: 1,
            },
        ],
    };
    ctx.accounts.insert(
        target_addr,
        Account {
            address: target_addr.as_bytes().to_vec(),
            owner_permission: Some(perm),
            ..Default::default()
        },
    );

    let hash = [7u8; 32];
    let sig1 = sign_prehash(&sk1, &hash);
    let sig2 = sign_prehash(&sk2, &hash);

    // Build input: addr || permission_id (0) || hash || offset (0x80) ||
    //              sigs_array_len (2) || sig1_words || sig2_words
    let mut input = Vec::new();
    input.extend_from_slice(&addr_word(&target_addr));
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
    input.extend_from_slice(&encode_sig(&sig1));
    input.extend_from_slice(&encode_sig(&sig2));

    let out = PrecompileImpl::ValidateMultiSign.execute(&input, &ctx).unwrap();
    assert_eq!(out.last(), Some(&1u8), "should be true with both sigs");
}

#[test]
fn validate_multi_sign_fails_below_threshold() {
    let mut ctx = MockContext::default();
    let target_addr = alice();
    let (sk1, k1) = keypair_from_seed(1);
    let (_sk_other, k_other) = keypair_from_seed(3);
    let mut k1_addr_with_prefix = vec![0x41u8];
    k1_addr_with_prefix.extend_from_slice(&k1);
    let mut k_other_addr_with_prefix = vec![0x41u8];
    k_other_addr_with_prefix.extend_from_slice(&k_other);

    // Threshold = 2 but k1 only weighs 1; the other key isn't signed.
    let perm = tron_proto::Permission {
        r#type: 0,
        id: 0,
        permission_name: "owner".into(),
        threshold: 2,
        parent_id: 0,
        operations: vec![],
        keys: vec![
            tron_proto::Key {
                address: k1_addr_with_prefix,
                weight: 1,
            },
            tron_proto::Key {
                address: k_other_addr_with_prefix,
                weight: 1,
            },
        ],
    };
    ctx.accounts.insert(
        target_addr,
        Account {
            address: target_addr.as_bytes().to_vec(),
            owner_permission: Some(perm),
            ..Default::default()
        },
    );

    let hash = [0xaau8; 32];
    let sig1 = sign_prehash(&sk1, &hash);

    let mut input = Vec::new();
    input.extend_from_slice(&addr_word(&target_addr));
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
    input.extend_from_slice(&encode_sig(&sig1));

    let out = PrecompileImpl::ValidateMultiSign.execute(&input, &ctx).unwrap();
    assert_eq!(out.last(), Some(&0u8), "should be false: only weight 1 of 2");
}

#[test]
fn validate_multi_sign_rejects_when_account_has_no_permission() {
    let ctx = MockContext::default(); // alice not in store
    let target_addr = alice();
    let mut input = vec![0u8; 5 * 32];
    input[12..32].copy_from_slice(&target_addr.as_bytes()[1..]);
    let out = PrecompileImpl::ValidateMultiSign.execute(&input, &ctx).unwrap();
    assert_eq!(out.last(), Some(&0u8));
}

#[test]
fn validate_multi_sign_resolves_active_permission_by_id() {
    let mut ctx = MockContext::default();
    let target_addr = alice();
    let (sk, k_low) = keypair_from_seed(4);
    let mut k_addr = vec![0x41u8];
    k_addr.extend_from_slice(&k_low);

    let active = tron_proto::Permission {
        r#type: 2,
        id: 3, // Active permission with id=3
        permission_name: "active3".into(),
        threshold: 1,
        parent_id: 0,
        operations: vec![],
        keys: vec![tron_proto::Key {
            address: k_addr,
            weight: 1,
        }],
    };
    ctx.accounts.insert(
        target_addr,
        Account {
            address: target_addr.as_bytes().to_vec(),
            active_permission: vec![active],
            ..Default::default()
        },
    );

    let hash = [0x42u8; 32];
    let sig = sign_prehash(&sk, &hash);

    let mut input = Vec::new();
    input.extend_from_slice(&addr_word(&target_addr));
    let mut perm_id = [0u8; 32];
    perm_id[31] = 3;
    input.extend_from_slice(&perm_id);
    input.extend_from_slice(&hash);
    let mut offset = [0u8; 32];
    offset[31] = 0x80;
    input.extend_from_slice(&offset);
    let mut sig_count = [0u8; 32];
    sig_count[31] = 1;
    input.extend_from_slice(&sig_count);
    input.extend_from_slice(&encode_sig(&sig));

    let out = PrecompileImpl::ValidateMultiSign.execute(&input, &ctx).unwrap();
    assert_eq!(out.last(), Some(&1u8));
}

// =============================================================================
// FreezeV2 / resource queries — all reads of Account fields
// =============================================================================

fn account_with_freeze_v2(
    addr: &Address,
    bw_frozen: i64,
    bw_delegated_out: i64,
    bw_acquired: i64,
    bw_usage: i64,
    energy_frozen: i64,
    energy_delegated_out: i64,
    energy_acquired: i64,
    energy_usage: i64,
) -> Account {
    use tron_proto::account::{AccountResource, FreezeV2};
    Account {
        address: addr.as_bytes().to_vec(),
        frozen_v2: vec![
            FreezeV2 {
                r#type: 0, // Bandwidth
                amount: bw_frozen,
            },
            FreezeV2 {
                r#type: 1, // Energy
                amount: energy_frozen,
            },
        ],
        delegated_frozen_v2_balance_for_bandwidth: bw_delegated_out,
        acquired_delegated_frozen_v2_balance_for_bandwidth: bw_acquired,
        net_usage: bw_usage,
        account_resource: Some(AccountResource {
            delegated_frozen_v2_balance_for_energy: energy_delegated_out,
            acquired_delegated_frozen_v2_balance_for_energy: energy_acquired,
            energy_usage,
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn build_addr_type_input(addr: &Address, rtype: i64) -> Vec<u8> {
    let mut v = Vec::with_capacity(64);
    v.extend_from_slice(&addr_word(addr));
    let mut t = [0u8; 32];
    t[24..32].copy_from_slice(&rtype.to_be_bytes());
    v.extend_from_slice(&t);
    v
}

fn read_long(out: &[u8]) -> i64 {
    let mut be = [0u8; 8];
    be.copy_from_slice(&out[24..32]);
    i64::from_be_bytes(be)
}

#[test]
fn resource_v2_returns_frozen_amount_by_type() {
    let mut ctx = MockContext::default();
    let a = alice();
    ctx.accounts
        .insert(a, account_with_freeze_v2(&a, 1_000, 0, 0, 0, 5_000, 0, 0, 0));
    let bw = PrecompileImpl::ResourceV2
        .execute(&build_addr_type_input(&a, 0), &ctx)
        .unwrap();
    let en = PrecompileImpl::ResourceV2
        .execute(&build_addr_type_input(&a, 1), &ctx)
        .unwrap();
    assert_eq!(read_long(&bw), 1_000);
    assert_eq!(read_long(&en), 5_000);
}

#[test]
fn total_delegated_resource_reads_per_resource_field() {
    let mut ctx = MockContext::default();
    let a = alice();
    ctx.accounts.insert(
        a,
        account_with_freeze_v2(&a, 0, 200, 0, 0, 0, 800, 0, 0),
    );
    let bw = PrecompileImpl::TotalDelegatedResource
        .execute(&build_addr_type_input(&a, 0), &ctx)
        .unwrap();
    let en = PrecompileImpl::TotalDelegatedResource
        .execute(&build_addr_type_input(&a, 1), &ctx)
        .unwrap();
    assert_eq!(read_long(&bw), 200);
    assert_eq!(read_long(&en), 800);
}

#[test]
fn total_acquired_resource_reads_per_resource_field() {
    let mut ctx = MockContext::default();
    let a = alice();
    ctx.accounts
        .insert(a, account_with_freeze_v2(&a, 0, 0, 300, 0, 0, 0, 900, 0));
    let bw = PrecompileImpl::TotalAcquiredResource
        .execute(&build_addr_type_input(&a, 0), &ctx)
        .unwrap();
    let en = PrecompileImpl::TotalAcquiredResource
        .execute(&build_addr_type_input(&a, 1), &ctx)
        .unwrap();
    assert_eq!(read_long(&bw), 300);
    assert_eq!(read_long(&en), 900);
}

#[test]
fn total_resource_adds_own_plus_acquired() {
    let mut ctx = MockContext::default();
    let a = alice();
    ctx.accounts.insert(
        a,
        account_with_freeze_v2(&a, 1_000, 0, 300, 0, 5_000, 0, 900, 0),
    );
    let bw = PrecompileImpl::TotalResource
        .execute(&build_addr_type_input(&a, 0), &ctx)
        .unwrap();
    let en = PrecompileImpl::TotalResource
        .execute(&build_addr_type_input(&a, 1), &ctx)
        .unwrap();
    assert_eq!(read_long(&bw), 1_300);
    assert_eq!(read_long(&en), 5_900);
}

#[test]
fn delegatable_resource_subtracts_delegated_out_from_frozen() {
    let mut ctx = MockContext::default();
    let a = alice();
    ctx.accounts.insert(
        a,
        account_with_freeze_v2(&a, 1_000, 200, 0, 0, 5_000, 800, 0, 0),
    );
    let bw = PrecompileImpl::DelegatableResource
        .execute(&build_addr_type_input(&a, 0), &ctx)
        .unwrap();
    let en = PrecompileImpl::DelegatableResource
        .execute(&build_addr_type_input(&a, 1), &ctx)
        .unwrap();
    assert_eq!(read_long(&bw), 800);
    assert_eq!(read_long(&en), 4_200);
}

#[test]
fn resource_usage_reads_per_resource_usage_field() {
    let mut ctx = MockContext::default();
    let a = alice();
    ctx.accounts
        .insert(a, account_with_freeze_v2(&a, 0, 0, 0, 42, 0, 0, 0, 4_242));
    let bw = PrecompileImpl::ResourceUsage
        .execute(&build_addr_type_input(&a, 0), &ctx)
        .unwrap();
    let en = PrecompileImpl::ResourceUsage
        .execute(&build_addr_type_input(&a, 1), &ctx)
        .unwrap();
    assert_eq!(read_long(&bw), 42);
    assert_eq!(read_long(&en), 4_242);
}

#[test]
fn available_unfreeze_v2_size_counts_remaining_slots() {
    use tron_proto::account::UnFreezeV2;
    let mut ctx = MockContext::default();
    let a = alice();
    ctx.accounts.insert(
        a,
        Account {
            address: a.as_bytes().to_vec(),
            unfrozen_v2: vec![
                UnFreezeV2 {
                    r#type: 0,
                    unfreeze_amount: 100,
                    unfreeze_expire_time: 1000,
                },
                UnFreezeV2 {
                    r#type: 1,
                    unfreeze_amount: 100,
                    unfreeze_expire_time: 1000,
                },
            ],
            ..Default::default()
        },
    );
    let mut input = vec![0u8; 32];
    input[12..32].copy_from_slice(&a.as_bytes()[1..]);
    let out = PrecompileImpl::AvailableUnfreezeV2Size
        .execute(&input, &ctx)
        .unwrap();
    // 32 max - 2 used = 30.
    assert_eq!(read_long(&out), 30);
}

#[test]
fn available_unfreeze_v2_size_is_max_for_account_without_unfreezes() {
    let mut ctx = MockContext::default();
    let a = alice();
    ctx.accounts.insert(
        a,
        Account {
            address: a.as_bytes().to_vec(),
            ..Default::default()
        },
    );
    let mut input = vec![0u8; 32];
    input[12..32].copy_from_slice(&a.as_bytes()[1..]);
    let out = PrecompileImpl::AvailableUnfreezeV2Size
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(read_long(&out), 32);
}

#[test]
fn unfreezable_balance_v2_sums_only_mature_entries() {
    use tron_proto::account::UnFreezeV2;
    let mut ctx = MockContext::default();
    ctx.block_timestamp_ms = 5_000;
    let a = alice();
    ctx.accounts.insert(
        a,
        Account {
            address: a.as_bytes().to_vec(),
            unfrozen_v2: vec![
                UnFreezeV2 {
                    r#type: 0,
                    unfreeze_amount: 100,
                    unfreeze_expire_time: 4_000, // mature
                },
                UnFreezeV2 {
                    r#type: 0,
                    unfreeze_amount: 500,
                    unfreeze_expire_time: 6_000, // not mature
                },
                UnFreezeV2 {
                    r#type: 1,
                    unfreeze_amount: 999, // different type
                    unfreeze_expire_time: 1_000,
                },
            ],
            ..Default::default()
        },
    );
    let out = PrecompileImpl::UnfreezableBalanceV2
        .execute(&build_addr_type_input(&a, 0), &ctx)
        .unwrap();
    assert_eq!(read_long(&out), 100);
}

#[test]
fn expire_unfreeze_balance_v2_uses_caller_supplied_cutoff() {
    use tron_proto::account::UnFreezeV2;
    let mut ctx = MockContext::default();
    let a = alice();
    ctx.accounts.insert(
        a,
        Account {
            address: a.as_bytes().to_vec(),
            unfrozen_v2: vec![
                UnFreezeV2 {
                    r#type: 1,
                    unfreeze_amount: 100,
                    unfreeze_expire_time: 4_000,
                },
                UnFreezeV2 {
                    r#type: 1,
                    unfreeze_amount: 500,
                    unfreeze_expire_time: 6_000,
                },
            ],
            ..Default::default()
        },
    );
    // Build input: addr || cutoff || type
    let mut input = Vec::new();
    input.extend_from_slice(&addr_word(&a));
    let mut t = [0u8; 32];
    let cutoff: i64 = 6_500;
    t[24..32].copy_from_slice(&cutoff.to_be_bytes());
    input.extend_from_slice(&t);
    let mut rtype = [0u8; 32];
    rtype[31] = 1;
    input.extend_from_slice(&rtype);

    let out = PrecompileImpl::ExpireUnfreezeBalanceV2
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(read_long(&out), 600);
}

#[test]
fn check_un_delegate_resource_returns_three_words() {
    let mut ctx = MockContext::default();
    ctx.block_timestamp_ms = 10_000;
    ctx.caller = Some(alice());
    let from = alice();
    let to = bob();

    ctx.delegated_resources.insert(
        (from, to),
        DelegatedResource {
            from: from.as_bytes().to_vec(),
            to: to.as_bytes().to_vec(),
            frozen_balance_for_bandwidth: 1_000,
            frozen_balance_for_energy: 0,
            expire_time_for_bandwidth: 5_000, // already expired vs ctx.block_timestamp_ms
            expire_time_for_energy: 0,
        },
    );

    // Input: target=to, amount=400, type=0 (Bandwidth)
    let mut input = Vec::new();
    input.extend_from_slice(&addr_word(&to));
    let mut amt = [0u8; 32];
    let amount: i64 = 400;
    amt[24..32].copy_from_slice(&amount.to_be_bytes());
    input.extend_from_slice(&amt);
    let mut rtype = [0u8; 32];
    rtype[31] = 0;
    input.extend_from_slice(&rtype);

    let out = PrecompileImpl::CheckUnDelegateResource
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(out.len(), 96);

    let free = read_long(&out[0..32]);
    let max = read_long(&out[32..64]);
    let expire = read_long(&out[64..96]);
    // Expired delegation, so max_undelegate = 1000, free = min(400, 1000) = 400.
    assert_eq!(free, 400);
    assert_eq!(max, 1_000);
    assert_eq!(expire, 5_000);
}

#[test]
fn check_un_delegate_resource_locks_when_expiry_in_future() {
    let mut ctx = MockContext::default();
    ctx.block_timestamp_ms = 1_000;
    ctx.caller = Some(alice());
    let from = alice();
    let to = bob();
    ctx.delegated_resources.insert(
        (from, to),
        DelegatedResource {
            from: from.as_bytes().to_vec(),
            to: to.as_bytes().to_vec(),
            frozen_balance_for_bandwidth: 0,
            frozen_balance_for_energy: 2_000,
            expire_time_for_bandwidth: 0,
            expire_time_for_energy: 9_999, // future
        },
    );
    let mut input = Vec::new();
    input.extend_from_slice(&addr_word(&to));
    let mut amt = [0u8; 32];
    let amount: i64 = 1_000;
    amt[24..32].copy_from_slice(&amount.to_be_bytes());
    input.extend_from_slice(&amt);
    let mut rtype = [0u8; 32];
    rtype[31] = 1; // Energy
    input.extend_from_slice(&rtype);
    let out = PrecompileImpl::CheckUnDelegateResource
        .execute(&input, &ctx)
        .unwrap();
    let free = read_long(&out[0..32]);
    let max = read_long(&out[32..64]);
    let expire = read_long(&out[64..96]);
    assert_eq!(free, 0);
    assert_eq!(max, 0);
    assert_eq!(expire, 9_999);
}

#[test]
fn freeze_v2_precompiles_return_zero_for_unknown_account() {
    let ctx = MockContext::default();
    let a = alice();
    for p in [
        PrecompileImpl::ResourceV2,
        PrecompileImpl::TotalResource,
        PrecompileImpl::TotalDelegatedResource,
        PrecompileImpl::TotalAcquiredResource,
        PrecompileImpl::DelegatableResource,
        PrecompileImpl::ResourceUsage,
        PrecompileImpl::UnfreezableBalanceV2,
    ] {
        let out = p.execute(&build_addr_type_input(&a, 0), &ctx).unwrap();
        assert_eq!(read_long(&out), 0, "{p:?} should return 0 for missing account");
    }
}

// =============================================================================
// Per-contract dynamic energy penalty (Phase 2b)
// =============================================================================
//
// The flow at consensus time:
//   1. Interpreter dispatches CALL to a precompile address.
//   2. Computes `effective_energy_cost(input, ctx)`:
//      - Reads `ALLOW_DYNAMIC_ENERGY` from chain params.
//      - Reads the *callee's* (i.e. the contract being executed) factor
//        from `ContractStateStore` via the EvmContext seam.
//      - Returns `base * (DECIMAL + factor) / DECIMAL` if both on; else `base`.
//   3. Deducts that amount from the contract's energy budget.

#[test]
fn effective_energy_cost_returns_base_when_dynamic_energy_disabled() {
    let mut ctx = MockContext::default();
    ctx.callee = Some(alice());
    ctx.dynamic_factors.insert(alice(), DYNAMIC_ENERGY_FACTOR_DECIMAL); // +100%
    // ALLOW_DYNAMIC_ENERGY = 0 (default → not present).
    let base = PrecompileImpl::VoteCount.energy_cost(&[]);
    let eff = PrecompileImpl::VoteCount
        .effective_energy_cost(&[], &ctx)
        .unwrap();
    assert_eq!(base, eff, "factor must be ignored when flag is off");
}

#[test]
fn effective_energy_cost_doubles_when_factor_equals_decimal() {
    let mut ctx = MockContext::default();
    ctx.callee = Some(alice());
    ctx.dynamic_factors.insert(alice(), DYNAMIC_ENERGY_FACTOR_DECIMAL);
    ctx.chain_params
        .insert(b"ALLOW_DYNAMIC_ENERGY".to_vec(), 1);
    let base = PrecompileImpl::VoteCount.energy_cost(&[]);
    let eff = PrecompileImpl::VoteCount
        .effective_energy_cost(&[], &ctx)
        .unwrap();
    assert_eq!(eff, 2 * base, "factor=DECIMAL must double the cost");
}

#[test]
fn effective_energy_cost_falls_back_to_zero_factor_for_unknown_contract() {
    let mut ctx = MockContext::default();
    ctx.callee = Some(bob()); // bob isn't in dynamic_factors
    ctx.chain_params
        .insert(b"ALLOW_DYNAMIC_ENERGY".to_vec(), 1);
    let base = PrecompileImpl::IsSrCandidate.energy_cost(&[]);
    let eff = PrecompileImpl::IsSrCandidate
        .effective_energy_cost(&[], &ctx)
        .unwrap();
    assert_eq!(base, eff);
}

#[test]
fn effective_energy_cost_partial_factor_applies_correct_percentage() {
    let mut ctx = MockContext::default();
    ctx.callee = Some(alice());
    ctx.dynamic_factors
        .insert(alice(), DYNAMIC_ENERGY_FACTOR_DECIMAL / 4); // +25%
    ctx.chain_params
        .insert(b"ALLOW_DYNAMIC_ENERGY".to_vec(), 1);
    let base = PrecompileImpl::ValidateMultiSign.energy_cost(&[]); // 1500
    let eff = PrecompileImpl::ValidateMultiSign
        .effective_energy_cost(&[], &ctx)
        .unwrap();
    assert_eq!(eff, base + base / 4);
}
