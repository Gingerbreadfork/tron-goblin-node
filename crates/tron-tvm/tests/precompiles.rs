//! Tests for the TRON precompile registry, the energy/gas model, and
//! the few precompiles implemented in Phase 1.

use hex_literal::hex;
use tron_crypto::address::Address;
use tron_proto::account::{AccountResource, FreezeV2};
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
    // java `ChainParameterEnum`: only codes 1..=5 exist (1=TOTAL_NET_LIMIT,
    // 2=TOTAL_NET_WEIGHT, 3=TOTAL_ENERGY_CURRENT_LIMIT, 4=TOTAL_ENERGY_WEIGHT,
    // 5=UNFREEZE_DELAY_DAYS); code 0 and anything > 5 return 0.
    let mut ctx = MockContext::default();
    ctx.chain_params.insert(b"TOTAL_ENERGY_CURRENT_LIMIT".to_vec(), 180_000_000_000);
    ctx.chain_params.insert(b"TOTAL_ENERGY_WEIGHT".to_vec(), 19_700_000_000);
    ctx.chain_params.insert(b"UNFREEZE_DELAY_DAYS".to_vec(), 14);
    let read = |code: u8| -> i64 {
        let mut input = [0u8; 32];
        input[31] = code;
        let out = PrecompileImpl::GetChainParameter.execute(&input, &ctx).unwrap();
        read_long(&out)
    };
    assert_eq!(read(3), 180_000_000_000, "code 3 = TOTAL_ENERGY_CURRENT_LIMIT");
    assert_eq!(read(4), 19_700_000_000, "code 4 = TOTAL_ENERGY_WEIGHT");
    assert_eq!(read(5), 14, "code 5 = UNFREEZE_DELAY_DAYS");
    assert_eq!(read(0), 0, "code 0 = INVALID");
    assert_eq!(read(9), 0, "unknown code = 0");
    // code 1 = TOTAL_NET_LIMIT defaults to 43_200_000_000 when unset.
    assert_eq!(read(1), 43_200_000_000, "code 1 = TOTAL_NET_LIMIT (default)");
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
    // java-tron `GetChainParameter.getEnergyForData` = 50 (not 500), and
    // `AvailableUnfreezeV2Size` = 50 (not 20) — both verified live against the
    // mainnet reference node + PrecompiledContracts.java.
    assert_eq!(PrecompileImpl::GetChainParameter.energy_cost(&[]), 50);
    assert_eq!(PrecompileImpl::AvailableUnfreezeV2Size.energy_cost(&[]), 50);
    // java-tron `ValidateMultiSign.getEnergyForData` scales per signature:
    // `((data.length/32 - 5) / 5) * 1500`. Empty / <5-word input → 0; each
    // 5-word signature group beyond the 5-word header adds 1500.
    assert_eq!(PrecompileImpl::ValidateMultiSign.energy_cost(&[]), 0);
    assert_eq!(PrecompileImpl::ValidateMultiSign.energy_cost(&vec![0u8; 10 * 32]), 1500);
    assert_eq!(PrecompileImpl::ValidateMultiSign.energy_cost(&vec![0u8; 15 * 32]), 3000);
    // Shielded zk-SNARK verifiers. Constants pinned against java-tron's
    // `PrecompiledContracts.{VerifyMintProof,VerifyTransferProof,
    // VerifyBurnProof,MerkleHash}.getEnergyForData`. **Input-independent**:
    // VerifyTransferProof does NOT scale per spend/output despite the
    // payload encoding 1..=2 of each — java-tron charges a flat 200k.
    assert_eq!(PrecompileImpl::VerifyMintProof.energy_cost(&[]), 150_000);
    assert_eq!(PrecompileImpl::VerifyTransferProof.energy_cost(&[]), 200_000);
    assert_eq!(PrecompileImpl::VerifyBurnProof.energy_cost(&[]), 150_000);
    assert_eq!(PrecompileImpl::MerkleHash.energy_cost(&[]), 500);
    // Sanity: realistic payload sizes don't change the cost.
    assert_eq!(
        PrecompileImpl::VerifyTransferProof.energy_cost(&vec![0u8; 2080]),
        200_000
    );
    assert_eq!(
        PrecompileImpl::VerifyTransferProof.energy_cost(&vec![0u8; 2752]),
        200_000
    );
    // P256Verify is a flat 6900 per java-tron (matches RIP-7212's
    // 3450 doubled — java-tron's chosen value pre-dates the RIP).
    assert_eq!(PrecompileImpl::P256Verify.energy_cost(&[]), 6_900);
    assert_eq!(PrecompileImpl::P256Verify.energy_cost(&vec![0u8; 160]), 6_900);
}

/// Blake2F's energy is per-Blake2b-round (EIP-152): when input is the
/// canonical 213 bytes and the finalization flag (data[212]) is 0 or 1,
/// the cost is `u32` BE of data[0..4]. Otherwise 0 — a malformed input
/// returns an error from execute and costs nothing. Pinned against
/// java-tron's `PrecompiledContracts.Blake2F.getEnergyForData`.
#[test]
fn blake2f_energy_is_per_round_with_canonical_input() {
    // Build a well-formed input: 4 bytes rounds || 208 bytes payload ||
    // 1 byte finalization flag.
    let mut input = vec![0u8; 213];
    // 12 rounds (Blake2b standard).
    input[0..4].copy_from_slice(&12u32.to_be_bytes());
    input[212] = 1; // finalization
    assert_eq!(PrecompileImpl::Blake2F.energy_cost(&input), 12);

    // High round count: u32 BE → u64 promotion.
    input[0..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(PrecompileImpl::Blake2F.energy_cost(&input), u32::MAX as u64);

    // Other valid finalization flag.
    input[212] = 0;
    input[0..4].copy_from_slice(&5u32.to_be_bytes());
    assert_eq!(PrecompileImpl::Blake2F.energy_cost(&input), 5);
}

#[test]
fn blake2f_energy_is_zero_for_malformed_input() {
    // Wrong length entirely.
    assert_eq!(PrecompileImpl::Blake2F.energy_cost(&[]), 0);
    assert_eq!(PrecompileImpl::Blake2F.energy_cost(&[0u8; 212]), 0);
    assert_eq!(PrecompileImpl::Blake2F.energy_cost(&[0u8; 214]), 0);
    // Correct length but invalid finalization flag (any high bit set).
    let mut input = vec![0u8; 213];
    input[0..4].copy_from_slice(&100u32.to_be_bytes());
    input[212] = 2; // not 0 or 1 → java-tron returns 0
    assert_eq!(PrecompileImpl::Blake2F.energy_cost(&input), 0);
    input[212] = 0xff;
    assert_eq!(PrecompileImpl::Blake2F.energy_cost(&input), 0);
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
    // Ripemd160 (0x03) and ModExp (0x05) are NOT in this list: TRON's
    // behavior at those addresses diverges from the standard EVM
    // precompiles, so they're implemented locally (see the dedicated
    // tests below).
    for p in [
        PrecompileImpl::EcRecover,
        PrecompileImpl::Sha256,
        PrecompileImpl::Identity,
        PrecompileImpl::Bn128Add,
        PrecompileImpl::Bn128Mul,
        PrecompileImpl::Bn128Pairing,
    ] {
        let err = p.execute(&[], &ctx).unwrap_err();
        assert!(matches!(err, tron_tvm::PrecompileError::HandledByInterpreter));
    }
}

#[test]
fn ripemd160_returns_double_sha256_not_real_ripemd160() {
    let ctx = MockContext::default();
    // java-tron's 0x03 returns SHA256(SHA256(input)[0..20]) — a 32-byte
    // digest, NOT real ripemd160.
    for input in [b"".as_slice(), b"abc".as_slice(), &[0xffu8; 64]] {
        let first = tron_crypto::hash::sha256(input);
        let expected = tron_crypto::hash::sha256(&first[..20]).to_vec();
        let out = PrecompileImpl::Ripemd160.execute(input, &ctx).unwrap();
        assert_eq!(out.len(), 32, "0x03 output is a 32-byte sha256 digest");
        assert_eq!(out, expected);
    }
    // Energy: 600 + 120 per 32-byte word (java `Ripempd160.getEnergyForData`).
    assert_eq!(PrecompileImpl::Ripemd160.energy_cost(b""), 600);
    assert_eq!(PrecompileImpl::Ripemd160.energy_cost(&[0u8; 1]), 600 + 120);
    assert_eq!(PrecompileImpl::Ripemd160.energy_cost(&[0u8; 32]), 600 + 120);
    assert_eq!(PrecompileImpl::Ripemd160.energy_cost(&[0u8; 33]), 600 + 240);
}

#[test]
fn modexp_matches_eip198_energy_and_output() {
    let ctx = MockContext::default();
    // 3^2 mod 5 = 4. Each length = 1 byte. base=3, exp=2, mod=5.
    let mut input = vec![0u8; 96];
    input[31] = 1; // base_len
    input[63] = 1; // exp_len
    input[95] = 1; // mod_len
    input.push(3);
    input.push(2);
    input.push(5);
    let out = PrecompileImpl::ModExp.execute(&input, &ctx).unwrap();
    assert_eq!(out, vec![4u8], "3^2 mod 5 = 4, left-padded to mod_len=1");

    // EIP-198 energy: multComplexity(max(1,1)) = 1; adjExpLen for exp=2
    // (highest set bit index 1) = 1; energy = 1 * max(1,1) / 20 = 0.
    assert_eq!(PrecompileImpl::ModExp.energy_cost(&input), 0);

    // A bigger exponent to exercise non-zero EIP-198 energy: base=mod=32
    // bytes, exp=32 bytes all-0xff. multComplexity(32) = 32^2 = 1024;
    // adjExpLen = highest set bit of 0xff..ff (255) = 255; energy =
    // 1024 * 255 / 20 = 13056 — ~8x revm's EIP-2565 cost for the same.
    let mut big = vec![0u8; 96];
    big[31] = 32;
    big[63] = 32;
    big[95] = 32;
    big.extend_from_slice(&[1u8; 32]); // base
    big.extend_from_slice(&[0xffu8; 32]); // exp
    big.extend_from_slice(&[0x07u8; 32]); // mod (odd, non-zero)
    assert_eq!(PrecompileImpl::ModExp.energy_cost(&big), 1024 * 255 / 20);

    // Zero modulus → empty output (java returns EMPTY_BYTE_ARRAY, not
    // mod_len zeros).
    let mut zero_mod = vec![0u8; 96];
    zero_mod[31] = 1; // base_len
    zero_mod[63] = 1; // exp_len
    zero_mod[95] = 1; // mod_len
    zero_mod.push(3); // base
    zero_mod.push(2); // exp
    zero_mod.push(0); // mod = 0
    let out = PrecompileImpl::ModExp.execute(&zero_mod, &ctx).unwrap();
    assert!(out.is_empty(), "zero modulus → empty output");
}

// =============================================================================
// TotalVoteCount (0x0100000a) — despite the name, returns the queried
// account's TRON Power in TRX (java `getTronPower()/TRX_PRECISION` on mainnet).
// =============================================================================

fn total_vote_count_i64(ctx: &MockContext, input: &[u8]) -> i64 {
    let out = PrecompileImpl::TotalVoteCount.execute(input, ctx).unwrap();
    assert_eq!(out.len(), 32);
    let mut be = [0u8; 8];
    be.copy_from_slice(&out[24..32]);
    i64::from_be_bytes(be)
}

#[test]
fn total_vote_count_returns_account_tron_power_in_trx() {
    // Mainnet gating: ALLOW_NEW_RESOURCE_MODEL = 0 → the getTronPower() path.
    let mut ctx = MockContext::default();
    ctx.chain_params.insert(b"UNFREEZE_DELAY_DAYS".to_vec(), 14);
    let a = alice();
    // 4_000 TRX bandwidth + 3_000 TRX energy frozen-v2, plus 1_000 TRX
    // delegated out for energy (delegating out keeps the voting power).
    let mut acct = account_with_freeze_v2(
        &a,
        4_000_000_000, // bw_frozen
        0,             // bw_delegated_out
        0,             // bw_acquired
        0,             // bw_usage
        3_000_000_000, // energy_frozen
        1_000_000_000, // energy_delegated_out
        0,             // energy_acquired
        0,             // energy_usage
    );
    // getTronPower sums every frozen source except TRON_POWER-typed v2.
    acct.old_tron_power = 0;
    ctx.accounts.insert(a, acct);

    // TRON Power = (4_000 + 3_000 + 1_000) TRX in sun, / TRX_PRECISION = 8_000.
    assert_eq!(total_vote_count_i64(&ctx, &addr_word(&a)), 8_000);
}

#[test]
fn total_vote_count_uses_all_tron_power_when_new_model_active() {
    // When BOTH UNFREEZE_DELAY_DAYS > 0 and ALLOW_NEW_RESOURCE_MODEL == 1,
    // java switches to getAllTronPower(), which folds in TRON_POWER-typed v2.
    use tron_proto::account::FreezeV2;
    let mut ctx = MockContext::default();
    ctx.chain_params.insert(b"UNFREEZE_DELAY_DAYS".to_vec(), 14);
    ctx.chain_params.insert(b"ALLOW_NEW_RESOURCE_MODEL".to_vec(), 1);
    let a = alice();
    let mut acct = account_with_freeze_v2(&a, 4_000_000_000, 0, 0, 0, 0, 0, 0, 0);
    acct.old_tron_power = 0;
    // 2_000 TRX of TRON_POWER-typed v2 freeze — only counted by getAllTronPower.
    acct.frozen_v2.push(FreezeV2 {
        r#type: 2,
        amount: 2_000_000_000,
    });
    ctx.accounts.insert(a, acct);

    // getAllTronPower = getTronPower (4_000) + TRON_POWER v2 (2_000) = 6_000 TRX.
    assert_eq!(total_vote_count_i64(&ctx, &addr_word(&a)), 6_000);
}

#[test]
fn total_vote_count_returns_zero_for_absent_account_or_bad_input() {
    let ctx = MockContext::default();
    // Absent account.
    assert_eq!(total_vote_count_i64(&ctx, &addr_word(&alice())), 0);
    // Wrong-length input.
    assert_eq!(total_vote_count_i64(&ctx, &[]), 0);
}

// =============================================================================
// ValidateMultiSign — uses on-chain Permission, weighted threshold check
// =============================================================================

fn word_with_low(byte_val: usize) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..32].copy_from_slice(&(byte_val as u64).to_be_bytes());
    w
}

/// Solidity `bytes[]` of 65-byte signatures laid out as java-tron's
/// `extractSigArray` parses it (the active `allowTvmSelfdestructRestriction`
/// path): length word, `N` relative-offset pointers, then each 65-byte
/// signature padded to 3 words. java reads element `i` from word
/// `ptr_i/32 + head + 2`, so for contiguous data `ptr_i = (N-1 + i*3) * 32`.
fn encode_sig_array(sigs: &[[u8; 65]]) -> Vec<u8> {
    let n = sigs.len();
    let mut out = Vec::new();
    out.extend_from_slice(&word_with_low(n));
    for i in 0..n {
        out.extend_from_slice(&word_with_low((n - 1 + i * 3) * 32));
    }
    for sig in sigs {
        let mut block = [0u8; 96];
        block[..65].copy_from_slice(sig);
        out.extend_from_slice(&block);
    }
    out
}

/// ValidateMultiSign recovery prehash: `SHA256(addr(21) ||
/// int32_BE(perm_id) || payload(32))`.
fn multi_sign_prehash(addr: &Address, perm_id: i32, payload: &[u8; 32]) -> [u8; 32] {
    let mut combine = Vec::new();
    combine.extend_from_slice(addr.as_bytes());
    combine.extend_from_slice(&perm_id.to_be_bytes());
    combine.extend_from_slice(payload);
    tron_crypto::hash::sha256(&combine)
}

/// Full ValidateMultiSign calldata: 4 head words (addr, perm_id, payload,
/// sig-array byte offset = 0x80) + the `bytes[]` signature array.
fn multi_sign_input(addr: &Address, perm_id: i32, payload: &[u8; 32], sigs: &[[u8; 65]]) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&addr_word(addr));
    input.extend_from_slice(&word_with_low(perm_id as usize));
    input.extend_from_slice(payload);
    input.extend_from_slice(&word_with_low(0x80));
    input.extend_from_slice(&encode_sig_array(sigs));
    input
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

    let payload = [7u8; 32];
    let hash = multi_sign_prehash(&target_addr, 0, &payload);
    let sig1 = sign_prehash(&sk1, &hash);
    let sig2 = sign_prehash(&sk2, &hash);
    let input = multi_sign_input(&target_addr, 0, &payload, &[sig1, sig2]);

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

    let payload = [0xaau8; 32];
    let hash = multi_sign_prehash(&target_addr, 0, &payload);
    let sig1 = sign_prehash(&sk1, &hash);
    // Only k1 (weight 1) signs; k1 is a permission key so its weight is
    // non-zero, but 1 < threshold 2 → false.
    let input = multi_sign_input(&target_addr, 0, &payload, &[sig1]);

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

    let payload = [0x42u8; 32];
    let hash = multi_sign_prehash(&target_addr, 3, &payload);
    let sig = sign_prehash(&sk, &hash);
    let input = multi_sign_input(&target_addr, 3, &payload, &[sig]);

    let out = PrecompileImpl::ValidateMultiSign.execute(&input, &ctx).unwrap();
    assert_eq!(out.last(), Some(&1u8));
}

// --- ValidateMultiSign: malformed pre-try input → spend-all-revert ----------
//
// In java-tron the pre-try `words[0..3]` /
// `words[words[3].intValueSafe()/WORD_SIZE]` / `extractSigArray` accesses
// throw `ArrayIndexOutOfBoundsException` on malformed input. That throw is
// NOT caught by `ValidateMultiSign.execute`'s try-block, so it propagates to
// `VM.java`, which runs `spendAllEnergy()` and reverts the whole tx. We model
// this as `PrecompileError::SpendAllRevert` — distinct from the in-body
// `Pair.of(true, DATA_FALSE)` results, which stay `Ok(false-word)`.

#[test]
fn validate_multi_sign_too_few_words_is_spend_all_revert() {
    let ctx = MockContext::default();
    // Fewer than 4 words → `words[3]` (and earlier) is out of range in java,
    // an uncaught throw. Must be the spend-all-revert variant, NOT Ok(false).
    for word_count in [0usize, 1, 2, 3] {
        let input = vec![0u8; word_count * 32];
        let err = PrecompileImpl::ValidateMultiSign
            .execute(&input, &ctx)
            .unwrap_err();
        assert!(
            matches!(err, tron_tvm::PrecompileError::SpendAllRevert),
            "{word_count} words must spend-all-revert, got {err:?}"
        );
    }
}

#[test]
fn validate_multi_sign_out_of_range_sig_head_is_spend_all_revert() {
    let ctx = MockContext::default();
    // 4 head words present, `words[3]` = 0x80 → sig-array head index 4, which
    // is >= words.len() (4). java reads `words[4]` → AIOOBE → uncaught throw.
    let target_addr = alice();
    let mut input = Vec::new();
    input.extend_from_slice(&addr_word(&target_addr)); // words[0]
    input.extend_from_slice(&word_with_low(0)); // words[1] perm id
    input.extend_from_slice(&[0u8; 32]); // words[2] payload
    input.extend_from_slice(&word_with_low(0x80)); // words[3] → head idx 4
    assert_eq!(input.len(), 4 * 32);
    let err = PrecompileImpl::ValidateMultiSign
        .execute(&input, &ctx)
        .unwrap_err();
    assert!(
        matches!(err, tron_tvm::PrecompileError::SpendAllRevert),
        "out-of-range sig-array head must spend-all-revert, got {err:?}"
    );
}

#[test]
fn validate_multi_sign_sig_element_past_data_is_spend_all_revert() {
    let ctx = MockContext::default();
    // Well-formed head (head idx 4 in range), length word declares 1 element
    // whose pointer word puts the 65-byte signature read far past the end of
    // the call data → java `Arrays.copyOfRange` throws (pre-try) → spend-all.
    let target_addr = alice();
    let mut input = Vec::new();
    input.extend_from_slice(&addr_word(&target_addr)); // words[0]
    input.extend_from_slice(&word_with_low(0)); // words[1]
    input.extend_from_slice(&[0u8; 32]); // words[2]
    input.extend_from_slice(&word_with_low(0x80)); // words[3] → head idx 4
    input.extend_from_slice(&word_with_low(1)); // words[4] len = 1
    // words[5] element pointer: a huge byte offset so the signature read
    // starts well past `data.len()` → extractBytes returns None → revert.
    input.extend_from_slice(&word_with_low(0x10_000 * 32));
    let err = PrecompileImpl::ValidateMultiSign
        .execute(&input, &ctx)
        .unwrap_err();
    assert!(
        matches!(err, tron_tvm::PrecompileError::SpendAllRevert),
        "signature read past data must spend-all-revert, got {err:?}"
    );
}

#[test]
fn validate_multi_sign_oversized_sig_array_is_ok_false_not_revert() {
    // `sigArraySize > MAX_SIZE` is an explicit `Pair.of(true, DATA_FALSE)` in
    // java — a SUCCESSFUL precompile with a false word, NOT a throw. Must stay
    // Ok(false-word) so only one signature group's energy is charged.
    let ctx = MockContext::default();
    let target_addr = alice();
    let mut input = Vec::new();
    input.extend_from_slice(&addr_word(&target_addr)); // words[0]
    input.extend_from_slice(&word_with_low(0)); // words[1]
    input.extend_from_slice(&[0u8; 32]); // words[2]
    input.extend_from_slice(&word_with_low(0x80)); // words[3] → head idx 4
    input.extend_from_slice(&word_with_low(6)); // words[4] len = 6 > MAX_SIZE 5
    let out = PrecompileImpl::ValidateMultiSign
        .execute(&input, &ctx)
        .expect("oversized declared size is success-with-false, not a revert");
    assert_eq!(out.last(), Some(&0u8), "oversized array → false word");
}

#[test]
fn validate_multi_sign_no_permission_is_ok_false_not_revert() {
    // A well-formed, in-bounds call with one (garbage) signature against an
    // account that has no permission falls through java's body to the final
    // `Pair.of(true, DATA_FALSE)` — a success-with-false, NOT a revert.
    let ctx = MockContext::default(); // alice absent from the store
    let target_addr = alice();
    let payload = [0u8; 32];
    let sig = [0u8; 65]; // recovers to nothing meaningful; account is absent
    let input = multi_sign_input(&target_addr, 0, &payload, &[sig]);
    let out = PrecompileImpl::ValidateMultiSign
        .execute(&input, &ctx)
        .expect("absent account is success-with-false, not a revert");
    assert_eq!(out.last(), Some(&0u8));
}

// --- BatchValidateSign: declared address-array size past words → zero word --
//
// java `extractBytes32Array` reads `words[addr_head + i + 1]` for every
// declared address; an out-of-range index throws, which `BatchValidateSign`'s
// outer try-block catches and turns into the all-zero word. (Distinct from
// ValidateMultiSign, whose identical throw is uncaught → spend-all-revert.)
// BatchValidateSign always returns `Ok(..)` here — never a revert.

#[test]
fn batch_validate_sign_addr_array_past_words_is_zero_word() {
    // Equal declared sig/addr counts (1 each) so the call clears the
    // `cnt != addresses.length` gate, and a valid sig is extracted — but the
    // single declared address element word lies one past the end of the data.
    // java reads `words[addr_head + 1]` in extractBytes32Array → AIOOBE →
    // caught by BatchValidateSign's outer try → all-zero word (never a
    // revert). Our eager bounds check returns the same zero word instead of
    // partially filling the result.
    //
    // Layout (9 words, indices 0..=8):
    //   [0] hash
    //   [1] sig head pointer = 3*32  → sig head idx 3
    //   [2] addr head pointer = 8*32 → addr head idx 8 (the LAST word present)
    //   [3] sig array len = 1
    //   [4] sig element ptr = 0
    //   [5..8] 96-byte signature block
    //   [8] addr array len = 1  (its element word [9] is out of range)
    let mut input = Vec::new();
    input.extend_from_slice(&[0u8; 32]); // [0] hash
    input.extend_from_slice(&word_with_low(3 * 32)); // [1] sig head idx 3
    input.extend_from_slice(&word_with_low(8 * 32)); // [2] addr head idx 8
    input.extend_from_slice(&word_with_low(1)); // [3] sig array len = 1
    input.extend_from_slice(&word_with_low(0)); // [4] element ptr
    let mut block = [0u8; 96];
    block[..65].copy_from_slice(&[1u8; 65]);
    input.extend_from_slice(&block); // [5..8] sig bytes
    input.extend_from_slice(&word_with_low(1)); // [8] addr array len = 1
    assert_eq!(input.len(), 9 * 32);
    let out = PrecompileImpl::BatchValidateSign
        .execute(&input, &MockContext::default())
        .expect("BatchValidateSign never reverts — catches every throw");
    assert_eq!(out, vec![0u8; 32], "declared addr element past data → zero word");
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

/// 3-word `(target, from, type)` input for ResourceV2.
fn resource_v2_input(target: &Address, from: &Address, rtype: i64) -> Vec<u8> {
    let mut v = Vec::with_capacity(96);
    v.extend_from_slice(&addr_word(target));
    v.extend_from_slice(&addr_word(from));
    let mut t = [0u8; 32];
    t[24..32].copy_from_slice(&rtype.to_be_bytes());
    v.extend_from_slice(&t);
    v
}

#[test]
fn resource_v2_self_returns_frozen_v2_balance() {
    // from == target → the account's own frozen-v2 balance.
    let mut ctx = MockContext::default();
    let a = alice();
    ctx.accounts
        .insert(a, account_with_freeze_v2(&a, 1_000, 0, 0, 0, 5_000, 0, 0, 0));
    let bw = PrecompileImpl::ResourceV2
        .execute(&resource_v2_input(&a, &a, 0), &ctx)
        .unwrap();
    let en = PrecompileImpl::ResourceV2
        .execute(&resource_v2_input(&a, &a, 1), &ctx)
        .unwrap();
    assert_eq!(read_long(&bw), 1_000);
    assert_eq!(read_long(&en), 5_000);
}

#[test]
fn resource_v2_cross_returns_delegated_amount() {
    // from != target → the resource `from` delegated to `target`
    // (unlocked row; the mock returns no locked row).
    let mut ctx = MockContext::default();
    let from = alice();
    let to = bob();
    ctx.delegated_resources.insert(
        (from, to),
        DelegatedResource {
            from: from.as_bytes().to_vec(),
            to: to.as_bytes().to_vec(),
            frozen_balance_for_energy: 700,
            ..Default::default()
        },
    );
    let en = PrecompileImpl::ResourceV2
        .execute(&resource_v2_input(&to, &from, 1), &ctx)
        .unwrap();
    assert_eq!(read_long(&en), 700);
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
fn delegatable_resource_full_when_no_usage() {
    // No current usage → the whole frozen-v2 balance is delegatable.
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
    assert_eq!(read_long(&bw), 1_000);
    assert_eq!(read_long(&en), 5_000);
}

#[test]
fn delegatable_resource_subtracts_v2_usage() {
    // frozenV2=5_000, usageBalance=1_000, no v1/acquired → v2Usage=1_000,
    // delegatable = 5_000 - 1_000 = 4_000. (Same usage setup as the
    // CheckUnDelegateResource partial test.)
    let mut ctx = MockContext::default();
    ctx.block_timestamp_ms = 3_000_000; // now_slot 1_000
    ctx.chain_params.insert(b"TOTAL_ENERGY_WEIGHT".to_vec(), 1_000);
    ctx.chain_params
        .insert(b"TOTAL_ENERGY_CURRENT_LIMIT".to_vec(), 28_800_000_000);
    let a = alice();
    let acc = Account {
        address: a.as_bytes().to_vec(),
        frozen_v2: vec![FreezeV2 { r#type: 1, amount: 5_000 }],
        account_resource: Some(AccountResource {
            energy_usage: 28_800,
            latest_consume_time_for_energy: 1_000,
            energy_window_size: 0,
            ..Default::default()
        }),
        ..Default::default()
    };
    ctx.accounts.insert(a, acc);
    let en = PrecompileImpl::DelegatableResource
        .execute(&build_addr_type_input(&a, 1), &ctx)
        .unwrap();
    assert_eq!(read_long(&en), 4_000);
}

#[test]
fn resource_usage_returns_balance_and_restore_pair() {
    // java ResourceUsage returns the two-word (usageBalanceInSun, restoreSeconds)
    // pair — NOT the raw usage counter. Same math as CheckUnDelegateResource.
    let mut ctx = MockContext::default();
    ctx.block_timestamp_ms = 3_000_000; // now_slot 1_000
    ctx.chain_params.insert(b"TOTAL_ENERGY_WEIGHT".to_vec(), 1_000);
    ctx.chain_params
        .insert(b"TOTAL_ENERGY_CURRENT_LIMIT".to_vec(), 28_800_000_000);
    let a = alice();
    let acc = Account {
        address: a.as_bytes().to_vec(),
        account_resource: Some(AccountResource {
            energy_usage: 28_800,
            latest_consume_time_for_energy: 1_000,
            energy_window_size: 0,
            ..Default::default()
        }),
        ..Default::default()
    };
    ctx.accounts.insert(a, acc);
    let out = PrecompileImpl::ResourceUsage
        .execute(&build_addr_type_input(&a, 1), &ctx)
        .unwrap();
    assert_eq!(out.len(), 64, "two 32-byte words");
    assert_eq!(read_long(&out[0..32]), 1_000, "usage balance (sun)");
    assert_eq!(read_long(&out[32..64]), 86_400, "restore seconds");
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
fn unfreezable_balance_v2_returns_frozen_v2_balance() {
    // java UnfreezableBalanceV2 = the currently-frozen v2 balance for the
    // resource (eligible to be unfrozen), NOT the already-unfrozen amount.
    let mut ctx = MockContext::default();
    let a = alice();
    ctx.accounts
        .insert(a, account_with_freeze_v2(&a, 1_000, 0, 0, 0, 5_000, 0, 0, 0));
    let bw = PrecompileImpl::UnfreezableBalanceV2
        .execute(&build_addr_type_input(&a, 0), &ctx)
        .unwrap();
    let en = PrecompileImpl::UnfreezableBalanceV2
        .execute(&build_addr_type_input(&a, 1), &ctx)
        .unwrap();
    assert_eq!(read_long(&bw), 1_000);
    assert_eq!(read_long(&en), 5_000);
}

#[test]
fn expire_unfreeze_balance_v2_sums_all_types_up_to_time() {
    use tron_proto::account::UnFreezeV2;
    let mut ctx = MockContext::default();
    let a = alice();
    // Expiry stored in ms; the `time` arg is in SECONDS (×1000). There is no
    // resource-type argument — withdrawal returns plain TRX across all types.
    ctx.accounts.insert(
        a,
        Account {
            address: a.as_bytes().to_vec(),
            unfrozen_v2: vec![
                UnFreezeV2 {
                    r#type: 1,
                    unfreeze_amount: 100,
                    unfreeze_expire_time: 4_000_000, // 4_000_000 ms ≤ 5_000_000
                },
                UnFreezeV2 {
                    r#type: 0, // different type — still counted
                    unfreeze_amount: 500,
                    unfreeze_expire_time: 4_500_000,
                },
                UnFreezeV2 {
                    r#type: 1,
                    unfreeze_amount: 999,
                    unfreeze_expire_time: 6_000_000, // > 5_000_000 — excluded
                },
            ],
            ..Default::default()
        },
    );
    // Two words: addr || time(seconds). time=5_000s → 5_000_000 ms cutoff.
    let mut input = Vec::new();
    input.extend_from_slice(&addr_word(&a));
    let mut t = [0u8; 32];
    let time_secs: i64 = 5_000;
    t[24..32].copy_from_slice(&time_secs.to_be_bytes());
    input.extend_from_slice(&t);

    let out = PrecompileImpl::ExpireUnfreezeBalanceV2
        .execute(&input, &ctx)
        .unwrap();
    assert_eq!(read_long(&out), 600); // 100 + 500 across both types
}

/// Build the 3-word `(target, amount, type)` input the precompile decodes.
fn check_undelegate_input(target: &Address, amount: i64, rtype: u8) -> Vec<u8> {
    let mut input = Vec::with_capacity(96);
    input.extend_from_slice(&addr_word(target));
    let mut amt = [0u8; 32];
    amt[24..32].copy_from_slice(&amount.to_be_bytes());
    input.extend_from_slice(&amt);
    let mut t = [0u8; 32];
    t[31] = rtype;
    input.extend_from_slice(&t);
    input
}

/// java-tron `FreezeV2Util.checkUndelegateResource`: with the target account
/// fully recovered (no in-use resource), the whole requested amount is "clean"
/// (immediately undelegatable). `clean = amount`, `remaining = 0`, `restore = 0`.
#[test]
fn check_un_delegate_resource_fully_recovered_returns_full_amount() {
    let mut ctx = MockContext::default();
    // now_slot = 200_000_000 / 3000 = 66_666 ≥ default 24h window (28_800),
    // so the usage window has fully elapsed → usage balance 0.
    ctx.block_timestamp_ms = 200_000_000;
    let to = bob();
    let mut acc = Account::default();
    // 2_000 sun of frozen-v2 energy = the account's resource limit.
    acc.frozen_v2 = vec![FreezeV2 { r#type: 1, amount: 2_000 }];
    ctx.accounts.insert(to, acc);

    let out = PrecompileImpl::CheckUnDelegateResource
        .execute(&check_undelegate_input(&to, 1_000, 1), &ctx)
        .unwrap();
    assert_eq!(out.len(), 96);
    assert_eq!(read_long(&out[0..32]), 1_000, "clean = full amount");
    assert_eq!(read_long(&out[32..64]), 0, "nothing locked");
    assert_eq!(read_long(&out[64..96]), 0, "no restore time");
}

/// With the account currently using exactly half of its frozen balance, half
/// the amount is clean and half is still locked, and the restore time is the
/// full window. Every number here is hand-derived from java's formula.
#[test]
fn check_un_delegate_resource_partial_when_account_has_usage() {
    let mut ctx = MockContext::default();
    // now_slot = 3_000_000 / 3000 = 1_000.
    ctx.block_timestamp_ms = 3_000_000;
    // usageToBalance(28_800, weight=1_000, limit=28_800_000_000)
    //   = 28_800 * 1_000 * 1_000_000 / 28_800_000_000 = 1_000.
    ctx.chain_params.insert(b"TOTAL_ENERGY_WEIGHT".to_vec(), 1_000);
    ctx.chain_params
        .insert(b"TOTAL_ENERGY_CURRENT_LIMIT".to_vec(), 28_800_000_000);

    let to = bob();
    let res = AccountResource {
        energy_usage: 28_800,
        latest_consume_time_for_energy: 1_000, // == now_slot → no decay
        energy_window_size: 0,                 // → default window 28_800 slots
        ..Default::default()
    };
    let acc = Account {
        account_resource: Some(res),
        frozen_v2: vec![FreezeV2 { r#type: 1, amount: 2_000 }], // resource limit 2_000
        ..Default::default()
    };
    ctx.accounts.insert(to, acc);

    let out = PrecompileImpl::CheckUnDelegateResource
        .execute(&check_undelegate_input(&to, 2_000, 1), &ctx)
        .unwrap();
    // resourceLimit=2_000, usageBalance=1_000 → clean = 2_000 * (1_000/2_000) = 1_000.
    assert_eq!(read_long(&out[0..32]), 1_000, "half clean");
    assert_eq!(read_long(&out[32..64]), 1_000, "half locked");
    // restoreSlots = window = 28_800; restoreSeconds = 28_800 * 3000 / 1000.
    assert_eq!(read_long(&out[64..96]), 86_400, "restore = full window");
}

/// Permissive zero-return cases: `amount <= 0`, unknown resource type, and a
/// missing account all yield three zero words (java's early returns).
#[test]
fn check_un_delegate_resource_returns_zeros_on_bad_input() {
    let mut ctx = MockContext::default();
    ctx.block_timestamp_ms = 3_000_000;
    let to = bob();
    ctx.accounts.insert(
        to,
        Account {
            frozen_v2: vec![FreezeV2 { r#type: 1, amount: 2_000 }],
            ..Default::default()
        },
    );
    let zero = |inp: &[u8]| {
        let out = PrecompileImpl::CheckUnDelegateResource.execute(inp, &ctx).unwrap();
        assert_eq!(read_long(&out[0..32]), 0);
        assert_eq!(read_long(&out[32..64]), 0);
        assert_eq!(read_long(&out[64..96]), 0);
    };
    zero(&check_undelegate_input(&to, 0, 1)); // amount <= 0
    zero(&check_undelegate_input(&to, 1_000, 2)); // unknown resource type
    zero(&check_undelegate_input(&alice(), 1_000, 1)); // missing account
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
