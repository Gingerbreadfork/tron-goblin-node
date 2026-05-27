//! Precompile registry + implementations.
//!
//! Every precompile address java-tron exposes is enumerated as a
//! [`PrecompileImpl`] variant. Each variant has:
//!
//! * a constant address (from [`crate::address`])
//! * an energy cost function (`energy_cost(input)`)
//! * an execute function (`execute(input, ctx) -> Result<Vec<u8>, PrecompileError>`)
//!
//! Standard Ethereum precompiles (0x01-0x08) are listed but not
//! implemented here — they're the responsibility of the EVM
//! interpreter that calls into this registry.
//!
//! Shielded zk-SNARK precompiles (`MerkleHash`, `VerifyMintProof`,
//! `VerifyTransferProof`, `VerifyBurnProof`), `Blake2F`, and `P256Verify`
//! are all implemented locally.

use crate::address::*;
use crate::context::{EvmContext, EvmContextError};
use tron_crypto::address::{Address, ADDRESS_LENGTH};
use tron_crypto::hash::keccak256;

pub type PrecompileResult = Result<Vec<u8>, PrecompileError>;

/// Identifier for one TRON precompile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum PrecompileImpl {
    // Standard EVM — implemented by the interpreter, listed here for the
    // address ↔ identifier mapping.
    EcRecover,
    Sha256,
    Ripemd160,
    Identity,
    ModExp,
    Bn128Add,
    Bn128Mul,
    Bn128Pairing,
    // TRON multi-sig
    BatchValidateSign,
    ValidateMultiSign,
    // Shielded (deferred)
    VerifyMintProof,
    VerifyTransferProof,
    VerifyBurnProof,
    MerkleHash,
    // Vote / SR queries
    RewardBalance,
    IsSrCandidate,
    VoteCount,
    UsedVoteCount,
    ReceivedVoteCount,
    TotalVoteCount,
    // FreezeV2 / chain queries
    GetChainParameter,
    AvailableUnfreezeV2Size,
    UnfreezableBalanceV2,
    ExpireUnfreezeBalanceV2,
    DelegatableResource,
    ResourceV2,
    CheckUnDelegateResource,
    ResourceUsage,
    TotalResource,
    TotalDelegatedResource,
    TotalAcquiredResource,
    // Ethereum-compat extras
    EthRipemd160,
    Blake2F,
    P256Verify,
}

/// All defined precompiles, in declaration order. Useful for building a
/// dispatch table or asserting invariants in tests.
pub const ALL_PRECOMPILES: &[PrecompileImpl] = &[
    PrecompileImpl::EcRecover,
    PrecompileImpl::Sha256,
    PrecompileImpl::Ripemd160,
    PrecompileImpl::Identity,
    PrecompileImpl::ModExp,
    PrecompileImpl::Bn128Add,
    PrecompileImpl::Bn128Mul,
    PrecompileImpl::Bn128Pairing,
    PrecompileImpl::BatchValidateSign,
    PrecompileImpl::ValidateMultiSign,
    PrecompileImpl::VerifyMintProof,
    PrecompileImpl::VerifyTransferProof,
    PrecompileImpl::VerifyBurnProof,
    PrecompileImpl::MerkleHash,
    PrecompileImpl::RewardBalance,
    PrecompileImpl::IsSrCandidate,
    PrecompileImpl::VoteCount,
    PrecompileImpl::UsedVoteCount,
    PrecompileImpl::ReceivedVoteCount,
    PrecompileImpl::TotalVoteCount,
    PrecompileImpl::GetChainParameter,
    PrecompileImpl::AvailableUnfreezeV2Size,
    PrecompileImpl::UnfreezableBalanceV2,
    PrecompileImpl::ExpireUnfreezeBalanceV2,
    PrecompileImpl::DelegatableResource,
    PrecompileImpl::ResourceV2,
    PrecompileImpl::CheckUnDelegateResource,
    PrecompileImpl::ResourceUsage,
    PrecompileImpl::TotalResource,
    PrecompileImpl::TotalDelegatedResource,
    PrecompileImpl::TotalAcquiredResource,
    PrecompileImpl::EthRipemd160,
    PrecompileImpl::Blake2F,
    PrecompileImpl::P256Verify,
];

impl PrecompileImpl {
    pub const fn address(self) -> PrecompileAddress {
        match self {
            Self::EcRecover => ADDR_ECRECOVER,
            Self::Sha256 => ADDR_SHA256,
            Self::Ripemd160 => ADDR_RIPEMD160,
            Self::Identity => ADDR_IDENTITY,
            Self::ModExp => ADDR_MODEXP,
            Self::Bn128Add => ADDR_BN128_ADD,
            Self::Bn128Mul => ADDR_BN128_MUL,
            Self::Bn128Pairing => ADDR_BN128_PAIRING,
            Self::BatchValidateSign => ADDR_BATCH_VALIDATE_SIGN,
            Self::ValidateMultiSign => ADDR_VALIDATE_MULTI_SIGN,
            Self::VerifyMintProof => ADDR_VERIFY_MINT_PROOF,
            Self::VerifyTransferProof => ADDR_VERIFY_TRANSFER_PROOF,
            Self::VerifyBurnProof => ADDR_VERIFY_BURN_PROOF,
            Self::MerkleHash => ADDR_MERKLE_HASH,
            Self::RewardBalance => ADDR_REWARD_BALANCE,
            Self::IsSrCandidate => ADDR_IS_SR_CANDIDATE,
            Self::VoteCount => ADDR_VOTE_COUNT,
            Self::UsedVoteCount => ADDR_USED_VOTE_COUNT,
            Self::ReceivedVoteCount => ADDR_RECEIVED_VOTE_COUNT,
            Self::TotalVoteCount => ADDR_TOTAL_VOTE_COUNT,
            Self::GetChainParameter => ADDR_GET_CHAIN_PARAMETER,
            Self::AvailableUnfreezeV2Size => ADDR_AVAILABLE_UNFREEZE_V2_SIZE,
            Self::UnfreezableBalanceV2 => ADDR_UNFREEZABLE_BALANCE_V2,
            Self::ExpireUnfreezeBalanceV2 => ADDR_EXPIRE_UNFREEZE_BALANCE_V2,
            Self::DelegatableResource => ADDR_DELEGATABLE_RESOURCE,
            Self::ResourceV2 => ADDR_RESOURCE_V2,
            Self::CheckUnDelegateResource => ADDR_CHECK_UN_DELEGATE_RESOURCE,
            Self::ResourceUsage => ADDR_RESOURCE_USAGE,
            Self::TotalResource => ADDR_TOTAL_RESOURCE,
            Self::TotalDelegatedResource => ADDR_TOTAL_DELEGATED_RESOURCE,
            Self::TotalAcquiredResource => ADDR_TOTAL_ACQUIRED_RESOURCE,
            Self::EthRipemd160 => ADDR_ETH_RIPEMD160,
            Self::Blake2F => ADDR_BLAKE2F,
            Self::P256Verify => ADDR_P256_VERIFY,
        }
    }

    /// Look up the precompile assigned to a given 20-byte address.
    pub fn from_address(addr: &PrecompileAddress) -> Option<Self> {
        ALL_PRECOMPILES.iter().copied().find(|p| &p.address() == addr)
    }

    /// Final energy cost after applying the per-contract dynamic-energy
    /// penalty. Reads `dynamic_energy_factor(callee)` from `ctx` and the
    /// `ALLOW_DYNAMIC_ENERGY` chain parameter; multiplies the base
    /// `energy_cost(input)` by `(DECIMAL + factor) / DECIMAL` when both
    /// the flag is on and the factor is non-zero.
    ///
    /// Use this at the boundary between the interpreter and the
    /// precompile: it's the consensus-correct energy charge.
    pub fn effective_energy_cost(
        self,
        input: &[u8],
        ctx: &dyn EvmContext,
    ) -> Result<u64, crate::energy::EnergyError> {
        let base = self.energy_cost(input);
        // ALLOW_DYNAMIC_ENERGY is `0` (off) or `1` (on) under its
        // dynamic-properties key. java-tron also gates this behind the
        // proposal flag of the same name, which is checked elsewhere by
        // the call site; we read the flag for completeness so a single
        // call resolves the whole cost.
        let allow = ctx
            .chain_parameter_long(b"ALLOW_DYNAMIC_ENERGY")
            .ok()
            .flatten()
            .unwrap_or(0)
            == 1;
        let factor = ctx.dynamic_energy_factor(&ctx.callee()).unwrap_or(0);
        crate::energy::effective_energy_cost(base, factor, allow)
    }

    /// Compute the energy cost. Mirrors `getEnergyForData` in each
    /// java-tron precompile.
    pub fn energy_cost(self, input: &[u8]) -> u64 {
        match self {
            // Constants per java-tron.
            Self::IsSrCandidate => 20,
            Self::UsedVoteCount => 20,
            Self::ReceivedVoteCount => 20,
            Self::TotalVoteCount => 20,
            Self::AvailableUnfreezeV2Size => 20,
            Self::UnfreezableBalanceV2 => 50,
            Self::ExpireUnfreezeBalanceV2 => 50,
            Self::DelegatableResource => 50,
            Self::ResourceV2 => 50,
            Self::CheckUnDelegateResource => 50,
            Self::ResourceUsage => 50,
            Self::TotalResource => 50,
            Self::TotalDelegatedResource => 50,
            Self::TotalAcquiredResource => 50,
            Self::RewardBalance => 500,
            Self::VoteCount => 500,
            Self::GetChainParameter => 500,
            // 1 signature = 1500 energy; data layout has 5 header words + 6 words per sig
            Self::BatchValidateSign => {
                const WORD_SIZE: usize = 32;
                let total_words = input.len() / WORD_SIZE;
                if total_words < 5 {
                    return 0;
                }
                let entries = (total_words - 5) / 6;
                (entries as u64) * 1500
            }
            // 1500 + 10000 baseline (per java-tron)
            Self::ValidateMultiSign => 1500,
            // Shielded zk-SNARK verifiers — flat costs per java-tron's
            // `PrecompiledContracts.VerifyMintProof.getEnergyForData`
            // (and Burn/Transfer/MerkleHash siblings). NO per-spend or
            // per-output scaling — the cost is constant regardless of
            // how many spends/outputs the transfer payload encodes.
            // Source: org/tron/core/vm/PrecompiledContracts.java (the
            // upstream commit pinned in vendored/java-tron/).
            Self::VerifyMintProof => 150_000,
            Self::VerifyTransferProof => 200_000,
            Self::VerifyBurnProof => 150_000,
            Self::MerkleHash => 500,
            // EVM-compat extras with java-tron's pinned costs.
            Self::Blake2F => blake2f_energy_cost(input),
            Self::P256Verify => 6_900,
            // Standard EVM precompiles (EcRecover, Sha256, Ripemd160,
            // Identity, ModExp, Bn128Add, Bn128Mul, Bn128Pairing,
            // EthRipemd160) are handled by the interpreter — their
            // execute() returns HandledByInterpreter and the cost
            // calculation lives in revm.
            _ => 0,
        }
    }

    /// Execute the precompile. Standard EVM precompiles return
    /// `PrecompileError::HandledByInterpreter`; shielded ZK return
    /// `PrecompileError::NotImplemented`.
    pub fn execute(
        self,
        input: &[u8],
        ctx: &dyn EvmContext,
    ) -> PrecompileResult {
        match self {
            // === Implemented ===
            Self::BatchValidateSign => batch_validate_sign(input),
            Self::ValidateMultiSign => validate_multi_sign(input, ctx),
            Self::IsSrCandidate => is_sr_candidate(input, ctx),
            Self::VoteCount => vote_count(input, ctx),
            Self::UsedVoteCount => used_vote_count(input, ctx),
            Self::ReceivedVoteCount => received_vote_count(input, ctx),
            Self::TotalVoteCount => total_vote_count(input, ctx),
            Self::RewardBalance => reward_balance(ctx),
            Self::GetChainParameter => get_chain_parameter(input, ctx),
            Self::AvailableUnfreezeV2Size => available_unfreeze_v2_size(input, ctx),
            Self::UnfreezableBalanceV2 => unfreezable_balance_v2(input, ctx),
            Self::ExpireUnfreezeBalanceV2 => expire_unfreeze_balance_v2(input, ctx),
            Self::DelegatableResource => delegatable_resource(input, ctx),
            Self::ResourceV2 => resource_v2(input, ctx),
            Self::CheckUnDelegateResource => check_un_delegate_resource(input, ctx),
            Self::ResourceUsage => resource_usage_precompile(input, ctx),
            Self::TotalResource => total_resource(input, ctx),
            Self::TotalDelegatedResource => total_delegated_resource(input, ctx),
            Self::TotalAcquiredResource => total_acquired_resource(input, ctx),

            // === Standard EVM (handled upstream) ===
            Self::EcRecover
            | Self::Sha256
            | Self::Ripemd160
            | Self::Identity
            | Self::ModExp
            | Self::Bn128Add
            | Self::Bn128Mul
            | Self::Bn128Pairing
            | Self::EthRipemd160 => Err(PrecompileError::HandledByInterpreter),

            // === Shielded zk-SNARK precompiles — all four are implemented. ===
            Self::MerkleHash => merkle_hash_precompile(input),
            Self::VerifyMintProof => Ok(crate::shielded::verify_mint_proof(input)),
            Self::VerifyTransferProof => Ok(crate::shielded::verify_transfer_proof(input)),
            Self::VerifyBurnProof => Ok(crate::shielded::verify_burn_proof(input)),
            Self::Blake2F => blake2f_precompile(input),
            Self::P256Verify => Ok(p256_verify_precompile(input)),
        }
    }
}

/// `0x01000004` — Sapling `MerkleHash`. Wraps `tron_tvm::shielded::merkle_hash`.
fn merkle_hash_precompile(input: &[u8]) -> PrecompileResult {
    let Some((depth, lhs, rhs)) = crate::shielded::decode_merkle_hash_input(input) else {
        return Err(PrecompileError::Malformed);
    };
    Ok(crate::shielded::merkle_hash(depth, &lhs, &rhs).to_vec())
}

/// `0x0002_0009` — EIP-152 Blake2F compression. Input layout (213 bytes):
/// `[rounds(4 BE)|h(64 LE = 8×u64)|m(128 LE = 16×u64)|t(16 LE = 2×u64)|f(1)]`.
///
/// Energy cost for Blake2F. Mirrors java-tron's
/// `PrecompiledContracts.Blake2F.getEnergyForData`:
///
/// * Returns `0` if the input is malformed — exactly 213 bytes are
///   required AND `data[212]` must be 0 or 1 (the finalization flag).
///   A malformed input executes to an error and costs nothing.
/// * Otherwise returns the round count from `u32` BE of `data[0..4]`
///   (one energy per Blake2b round, matching EIP-152).
pub(crate) fn blake2f_energy_cost(input: &[u8]) -> u64 {
    const INPUT_LEN: usize = 213;
    if input.len() != INPUT_LEN || (input[212] & 0xFEu8) != 0 {
        return 0;
    }
    u32::from_be_bytes(input[0..4].try_into().unwrap()) as u64
}

/// Output: 64 bytes (the post-compression `h` state, little-endian).
/// Matches java-tron's `PrecompiledContracts.Blake2F.execute` byte-for-byte
/// by delegating to `revm::precompile::blake2::compress` for the actual
/// compression — same primitive, no re-implementation.
fn blake2f_precompile(input: &[u8]) -> PrecompileResult {
    const INPUT_LEN: usize = 213;
    if input.len() != INPUT_LEN {
        return Err(PrecompileError::BadInputLength {
            got: input.len(),
            expected: INPUT_LEN,
        });
    }
    // Finalization flag must be 0 or 1 (java-tron rejects anything else;
    // the bitmask `& 0xFE != 0` means any non-zero high bit).
    let f_byte = input[212];
    if f_byte & 0xFEu8 != 0 {
        return Err(PrecompileError::Malformed);
    }
    let f = f_byte == 1;

    let rounds = u32::from_be_bytes(input[0..4].try_into().unwrap());

    let mut h = [0u64; 8];
    for (i, chunk) in input[4..68].chunks_exact(8).enumerate() {
        h[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    let mut m = [0u64; 16];
    for (i, chunk) in input[68..196].chunks_exact(8).enumerate() {
        m[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    let t = [
        u64::from_le_bytes(input[196..204].try_into().unwrap()),
        u64::from_le_bytes(input[204..212].try_into().unwrap()),
    ];

    revm::precompile::blake2::compress(rounds, &mut h, &m, &t, f);

    let mut out = vec![0u8; 64];
    for (i, word) in h.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&word.to_le_bytes());
    }
    Ok(out)
}

/// `0x0000_0100` — EIP-7951 P256Verify (ECDSA over secp256r1 = NIST P-256).
///
/// Input layout (160 bytes): `[hash(32) | r(32) | s(32) | Qx(32) | Qy(32)]`.
///
/// Output: 32-byte word `0x...01` on successful verification, empty bytes
/// on any failure (per EIP-7951 the precompile never reverts). Mirrors
/// java-tron's `PrecompiledContracts.P256Verify` byte-for-byte.
#[allow(deprecated)] // GenericArray 0.x is the version p256 0.13 pins
fn p256_verify_precompile(input: &[u8]) -> Vec<u8> {
    use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
    use p256::elliptic_curve::generic_array::GenericArray;
    use p256::elliptic_curve::sec1::FromEncodedPoint;
    use p256::{AffinePoint, EncodedPoint};

    const INPUT_LEN: usize = 160;
    if input.len() != INPUT_LEN {
        return Vec::new();
    }
    let hash = &input[0..32];
    let r_bytes = GenericArray::clone_from_slice(&input[32..64]);
    let s_bytes = GenericArray::clone_from_slice(&input[64..96]);
    let qx = GenericArray::clone_from_slice(&input[96..128]);
    let qy = GenericArray::clone_from_slice(&input[128..160]);

    // Reject the (0, 0) "identity-like" public key explicitly — java-tron
    // does this before handing off to BouncyCastle. The other range
    // checks (r, s in [1, n-1]; Qx, Qy in [0, p-1]; on-curve) all fall
    // out of Signature::from_scalars / AffinePoint::from_encoded_point.
    if qx.iter().all(|b| *b == 0) && qy.iter().all(|b| *b == 0) {
        return Vec::new();
    }
    let encoded = EncodedPoint::from_affine_coordinates(&qx, &qy, false);
    let affine = match Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded)) {
        Some(p) => p,
        None => return Vec::new(),
    };
    let vk = match VerifyingKey::from_affine(affine) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let signature = match Signature::from_scalars(r_bytes, s_bytes) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    match vk.verify_prehash(hash, &signature) {
        Ok(()) => {
            let mut out = vec![0u8; 32];
            out[31] = 1;
            out
        }
        Err(_) => Vec::new(),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PrecompileError {
    #[error("input has wrong length: got {got}, expected {expected}")]
    BadInputLength { got: usize, expected: usize },
    #[error("malformed input")]
    Malformed,
    #[error("context error: {0}")]
    Context(#[from] EvmContextError),
    #[error("handled by the EVM interpreter, not here")]
    HandledByInterpreter,
    #[error("not yet implemented: {0}")]
    NotImplemented(&'static str),
}

// =============================================================================
// Helpers
// =============================================================================

const WORD_SIZE: usize = 32;

/// Big-endian 32-byte representation of a signed `i64`. java-tron's
/// `longTo32Bytes` — sign-extends.
fn long_to_32_bytes(v: i64) -> Vec<u8> {
    let mut out = vec![0u8; WORD_SIZE];
    let bytes = v.to_be_bytes();
    // Sign-extend: for v < 0, fill high bytes with 0xff.
    if v < 0 {
        for b in &mut out[..24] {
            *b = 0xff;
        }
    }
    out[24..].copy_from_slice(&bytes);
    out
}

/// `dataBoolean(true) = [0x..0x01]` (32 bytes, last byte = 0/1).
fn data_boolean(v: bool) -> Vec<u8> {
    let mut out = vec![0u8; WORD_SIZE];
    out[31] = u8::from(v);
    out
}

/// Decode a 32-byte word as a TRON address: take the last 20 bytes and
/// prepend the mainnet `0x41` prefix. Matches java-tron's
/// `DataWord.toTronAddress`.
fn word_to_tron_address(word: &[u8; WORD_SIZE]) -> Address {
    let mut buf = [0u8; ADDRESS_LENGTH];
    buf[0] = 0x41;
    buf[1..].copy_from_slice(&word[12..32]);
    Address::from_raw(buf)
}

/// Split `input` into 32-byte words. Trailing partial bytes are zero-padded.
fn parse_words(input: &[u8]) -> Vec<[u8; WORD_SIZE]> {
    let mut out = Vec::with_capacity(input.len().div_ceil(WORD_SIZE));
    for chunk in input.chunks(WORD_SIZE) {
        let mut w = [0u8; WORD_SIZE];
        w[..chunk.len()].copy_from_slice(chunk);
        out.push(w);
    }
    out
}

// =============================================================================
// IsSrCandidate (0x01000006)
// =============================================================================

fn is_sr_candidate(input: &[u8], ctx: &dyn EvmContext) -> PrecompileResult {
    if input.len() != WORD_SIZE {
        // java-tron returns false for malformed input rather than erroring.
        return Ok(data_boolean(false));
    }
    let mut word = [0u8; WORD_SIZE];
    word.copy_from_slice(input);
    let addr = word_to_tron_address(&word);
    let exists = ctx.get_witness(&addr)?.is_some();
    Ok(data_boolean(exists))
}

// =============================================================================
// VoteCount (0x01000007)
// =============================================================================

fn vote_count(input: &[u8], ctx: &dyn EvmContext) -> PrecompileResult {
    if input.len() != 2 * WORD_SIZE {
        return Ok(long_to_32_bytes(0));
    }
    let words = parse_words(input);
    let voter = word_to_tron_address(&words[0]);
    let witness = word_to_tron_address(&words[1]);

    let mut total = 0i64;
    if let Some(account) = ctx.get_account(&voter)? {
        for v in account.votes {
            if v.vote_address == witness.as_bytes() {
                total = total.saturating_add(v.vote_count);
            }
        }
    }
    Ok(long_to_32_bytes(total))
}

// =============================================================================
// UsedVoteCount (0x01000008): total votes the caller has cast
// =============================================================================

fn used_vote_count(input: &[u8], ctx: &dyn EvmContext) -> PrecompileResult {
    if input.len() != WORD_SIZE {
        return Ok(long_to_32_bytes(0));
    }
    let mut word = [0u8; WORD_SIZE];
    word.copy_from_slice(input);
    let addr = word_to_tron_address(&word);
    let mut total = 0i64;
    if let Some(account) = ctx.get_account(&addr)? {
        for v in account.votes {
            total = total.saturating_add(v.vote_count);
        }
    }
    Ok(long_to_32_bytes(total))
}

// =============================================================================
// ReceivedVoteCount (0x01000009): votes received by a witness
// =============================================================================

fn received_vote_count(input: &[u8], ctx: &dyn EvmContext) -> PrecompileResult {
    if input.len() != WORD_SIZE {
        return Ok(long_to_32_bytes(0));
    }
    let mut word = [0u8; WORD_SIZE];
    word.copy_from_slice(input);
    let addr = word_to_tron_address(&word);
    let count = ctx
        .get_witness(&addr)?
        .map(|w| w.vote_count)
        .unwrap_or(0);
    Ok(long_to_32_bytes(count))
}

// =============================================================================
// TotalVoteCount (0x0100000a): sum of all witness vote counts
// =============================================================================

fn total_vote_count(_input: &[u8], ctx: &dyn EvmContext) -> PrecompileResult {
    // java-tron sums `witness.vote_count` across the entire WitnessStore.
    // Now backed by `EvmContext::all_witnesses` which the chainbase
    // `WitnessStore::all` powers.
    let mut total = 0i64;
    for w in ctx.all_witnesses()? {
        total = total.saturating_add(w.vote_count);
    }
    Ok(long_to_32_bytes(total))
}

// =============================================================================
// RewardBalance (0x01000005): pending reward for caller
// =============================================================================

fn reward_balance(ctx: &dyn EvmContext) -> PrecompileResult {
    // Mirrors java-tron's `MortgageService.queryReward`. The default
    // `EvmContext::query_reward` returns just `Account.allowance`;
    // chainbase-backed contexts override with the full Vi-accumulator
    // walk that adds in unclaimed per-cycle rewards.
    let caller = ctx.caller();
    let total = ctx.query_reward(&caller)?;
    Ok(long_to_32_bytes(total))
}

// =============================================================================
// GetChainParameter (0x0100000b)
// =============================================================================

fn get_chain_parameter(input: &[u8], ctx: &dyn EvmContext) -> PrecompileResult {
    if input.len() != WORD_SIZE {
        return Ok(long_to_32_bytes(0));
    }
    // The input word's last 8 bytes hold the parameter selector.
    let mut be = [0u8; 8];
    be.copy_from_slice(&input[24..32]);
    let selector = i64::from_be_bytes(be);
    let key = parameter_key(selector);
    let value = ctx.chain_parameter_long(key)?.unwrap_or(0);
    Ok(long_to_32_bytes(value))
}

/// Selector → DynamicPropertiesStore key.
///
/// java-tron has a hardcoded switch over selectors in
/// `GetChainParameter.execute`. Most entries map 1:1 to a key in
/// `DynamicPropertiesStore`. This Phase-1 list covers the most-used
/// parameters; missing selectors fall back to a zero result.
fn parameter_key(selector: i64) -> &'static [u8] {
    match selector {
        0 => b"MAINTENANCE_TIME_INTERVAL",
        1 => b"ACCOUNT_UPGRADE_COST",
        2 => b"CREATE_ACCOUNT_FEE",
        3 => b"TRANSACTION_FEE",
        4 => b"ASSET_ISSUE_FEE",
        5 => b"WITNESS_PAY_PER_BLOCK",
        6 => b"WITNESS_STANDBY_ALLOWANCE",
        7 => b"CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT",
        // ... ~70 more selectors in java-tron. Falls through to "" below for
        // anything we haven't pinned yet — caller gets 0.
        _ => b"",
    }
}

// =============================================================================
// BatchValidateSign (0x09)
// =============================================================================
//
// ABI: hash(32) || offset(sigs) || offset(addrs) || padding || sigs_array || addrs_array
//
// where sigs_array = len || sig_0 || sig_1 || ... (each sig is up to 65 bytes,
// padded to multiples of 32) and addrs_array = len || addr_0 || addr_1 || ...
// (each addr in a 32-byte word).
//
// Returns a 32-byte word where byte `i` is 1 if signature `i` recovered to
// addresses[i], 0 otherwise.

fn batch_validate_sign(input: &[u8]) -> PrecompileResult {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    const MAX_SIZE: usize = 16;

    let words = parse_words(input);
    if words.len() < 5 {
        return Ok(data_boolean(false));
    }

    let hash = words[0];
    // Offsets are in *bytes*; divide by 32 to get word index.
    let sig_array_word_idx = i64::from_be_bytes(words[1][24..32].try_into().unwrap()) as usize / WORD_SIZE;
    let addr_array_word_idx = i64::from_be_bytes(words[2][24..32].try_into().unwrap()) as usize / WORD_SIZE;

    let sig_count = if let Some(w) = words.get(sig_array_word_idx) {
        i64::from_be_bytes(w[24..32].try_into().unwrap()) as usize
    } else {
        return Ok(data_boolean(false));
    };
    let addr_count = if let Some(w) = words.get(addr_array_word_idx) {
        i64::from_be_bytes(w[24..32].try_into().unwrap()) as usize
    } else {
        return Ok(data_boolean(false));
    };

    if sig_count == 0
        || sig_count > MAX_SIZE
        || sig_count != addr_count
    {
        return Ok(data_boolean(false));
    }

    let mut result = vec![0u8; WORD_SIZE];

    // For each sig, decode + recover + compare to expected address.
    // In java-tron the signatures are length-prefixed; for the common
    // case (each sig is exactly 65 bytes), they occupy 3 words (65 bytes
    // padded). We support that common case; the more exotic layouts are
    // Phase 2.
    for i in 0..sig_count {
        let sig_words_offset = sig_array_word_idx + 1 + i * 3;
        let addr_word_offset = addr_array_word_idx + 1 + i;

        let (Some(sig0), Some(sig1), Some(sig2), Some(addr_word)) = (
            words.get(sig_words_offset),
            words.get(sig_words_offset + 1),
            words.get(sig_words_offset + 2),
            words.get(addr_word_offset),
        ) else {
            continue;
        };

        // Concatenate the three words to 96 bytes; the signature is
        // left-aligned at bytes [0..65] with [65..96] zero padding.
        // This matches java-tron's `BatchValidateSign` encoding where
        // each signature in the input array is a `bytes32[3]` slot
        // (no per-sig length prefix; the outer array length is the
        // single header word that's already been consumed).
        let mut sig_buf = [0u8; 96];
        sig_buf[0..32].copy_from_slice(sig0);
        sig_buf[32..64].copy_from_slice(sig1);
        sig_buf[64..96].copy_from_slice(sig2);
        let sig_bytes = &sig_buf[0..65];
        // Recoverable ECDSA: [r||s||v] with v ∈ 0..=3.
        if sig_bytes.len() != 65 {
            continue;
        }
        let mut rs = [0u8; 64];
        rs.copy_from_slice(&sig_bytes[0..64]);
        let v = sig_bytes[64];
        let recid = if v >= 27 { v - 27 } else { v };
        let Ok(rec_id) = RecoveryId::try_from(recid) else {
            continue;
        };
        let Ok(sig) = Signature::from_slice(&rs) else {
            continue;
        };
        let Ok(vk) = VerifyingKey::recover_from_prehash(&hash, &sig, rec_id) else {
            continue;
        };
        // Derive a 21-byte TRON address from the recovered pubkey.
        let enc = vk.to_encoded_point(false);
        let pub_bytes = enc.as_bytes();
        if pub_bytes.len() != 65 {
            continue;
        }
        let pub_hash = keccak256(&pub_bytes[1..]);
        // The expected address in the input is given as a *20-byte*
        // EVM-style address in the low 20 bytes of `addr_word`.
        // We compare against the last 20 bytes of our derived hash.
        if pub_hash[12..32] == addr_word[12..32] {
            result[i] = 1;
        }
    }

    Ok(result)
}

// =============================================================================
// ValidateMultiSign (0x0a)
// =============================================================================
//
// ABI (per java-tron `ValidateMultiSign.execute`):
//   word[0]     = address (target account)
//   word[1]     = permission_id (int32 in low bytes)
//   word[2]     = hash to verify
//   word[3]     = offset to sigs array (in bytes; almost always 0x80 = 4*32)
//   words[4..]  = sigs_array := len || sig_0_words || sig_1_words || ...
//
// For each signature: recover the public key; derive its 20-byte EVM-style
// address; look that up in the named Permission's `keys` and accumulate
// the matching key's `weight`. Each key may contribute at most once.
// Return true iff total weight ≥ permission.threshold.

fn validate_multi_sign(input: &[u8], ctx: &dyn EvmContext) -> PrecompileResult {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    const MAX_SIGS: usize = 5;

    let words = parse_words(input);
    if words.len() < 5 {
        return Ok(data_boolean(false));
    }

    let addr = word_to_tron_address(&words[0]);
    let permission_id = i64::from_be_bytes(words[1][24..32].try_into().unwrap()) as i32;
    let hash = words[2];

    // words[3] is offset; with the typical layout (one head word per arg
    // = 4 head words), sigs_array length lives at words[4].
    let sig_count = i64::from_be_bytes(words[4][24..32].try_into().unwrap()) as usize;
    if sig_count == 0 || sig_count > MAX_SIGS {
        return Ok(data_boolean(false));
    }

    // Resolve the account's permission for this id.
    let account = match ctx.get_account(&addr)? {
        Some(a) => a,
        None => return Ok(data_boolean(false)),
    };
    let permission = match select_permission(&account, permission_id) {
        Some(p) => p,
        None => return Ok(data_boolean(false)),
    };
    if permission.threshold <= 0 {
        return Ok(data_boolean(false));
    }

    // Build a lookup of permission key low-20-bytes → weight.
    let mut key_table: Vec<([u8; 20], i64)> = Vec::with_capacity(permission.keys.len());
    for k in &permission.keys {
        if k.address.len() == ADDRESS_LENGTH {
            // Strip the 0x41 prefix; the EVM compares the low 20 bytes.
            let mut buf = [0u8; 20];
            buf.copy_from_slice(&k.address[1..]);
            key_table.push((buf, k.weight));
        }
    }

    // Walk signatures, recover, sum weights — but each key only counts once.
    let mut used = vec![false; key_table.len()];
    let mut total_weight: i64 = 0;
    for i in 0..sig_count {
        // Each signature is encoded as a 65-byte byte-array padded to 3 words.
        let off = 5 + i * 3;
        let (Some(s0), Some(s1), Some(s2)) =
            (words.get(off), words.get(off + 1), words.get(off + 2))
        else {
            break;
        };

        let mut sig_buf = [0u8; 96];
        sig_buf[0..32].copy_from_slice(s0);
        sig_buf[32..64].copy_from_slice(s1);
        sig_buf[64..96].copy_from_slice(s2);
        // Same convention as BatchValidateSign: sig left-aligned in
        // bytes [0..65] of the three-word block.
        let sig_bytes = &sig_buf[0..65];

        let mut rs = [0u8; 64];
        rs.copy_from_slice(&sig_bytes[0..64]);
        let v = sig_bytes[64];
        let recid = if v >= 27 { v - 27 } else { v };
        let Ok(rec_id) = RecoveryId::try_from(recid) else {
            continue;
        };
        let Ok(sig) = Signature::from_slice(&rs) else {
            continue;
        };
        let Ok(vk) = VerifyingKey::recover_from_prehash(&hash, &sig, rec_id) else {
            continue;
        };
        let enc = vk.to_encoded_point(false);
        let pub_bytes = enc.as_bytes();
        if pub_bytes.len() != 65 {
            continue;
        }
        let pub_hash = keccak256(&pub_bytes[1..]);
        let mut low20 = [0u8; 20];
        low20.copy_from_slice(&pub_hash[12..32]);

        for (idx, (k_low, weight)) in key_table.iter().enumerate() {
            if !used[idx] && k_low == &low20 {
                used[idx] = true;
                total_weight = total_weight.saturating_add(*weight);
                break;
            }
        }
    }

    Ok(data_boolean(total_weight >= permission.threshold))
}

/// Select the right `Permission` for the given id, mirroring java-tron's
/// `AccountCapsule.getPermissionById`:
///
/// * `0` → `owner_permission`
/// * `1` → `witness_permission`
/// * `2..` → `active_permission[id - 2]`
fn select_permission(account: &tron_proto::Account, id: i32) -> Option<tron_proto::Permission> {
    match id {
        0 => account.owner_permission.clone(),
        1 => account.witness_permission.clone(),
        n if n >= 2 => {
            // Active permissions are indexed by their own `id` field, not
            // by Vec position. Walk to find the matching one.
            account
                .active_permission
                .iter()
                .find(|p| p.id == n)
                .cloned()
        }
        _ => None,
    }
}

// =============================================================================
// FreezeV2 / resource queries
// =============================================================================
//
// All of these take (address, resource_type) — the address word holds a
// 20-byte EVM-style address; the type word holds an i64 in its low 8 bytes
// (matching `ResourceCode`).
//
// Input layouts vary slightly:
//   - 2 words (addr, type)              : ResourceV2 / DelegatableResource / etc.
//   - 1 word  (addr)                    : AvailableUnfreezeV2Size
//   - 3 words (addr, time, type)        : ExpireUnfreezeBalanceV2
//   - 3 words (addr, amount, type)      : CheckUnDelegateResource
//
// On malformed input most return `0`/`false`/three zeros without erroring,
// matching java-tron's permissive precompile semantics.

const RESOURCE_BANDWIDTH: i32 = 0;
const RESOURCE_ENERGY: i32 = 1;
// const RESOURCE_TRON_POWER: i32 = 2;  // not handled by these precompiles

fn parse_address_and_type(input: &[u8]) -> Option<(Address, i32)> {
    if input.len() != 2 * WORD_SIZE {
        return None;
    }
    let words = parse_words(input);
    let addr = word_to_tron_address(&words[0]);
    let resource_type = i64::from_be_bytes(words[1][24..32].try_into().ok()?) as i32;
    Some((addr, resource_type))
}

fn parse_address_only(input: &[u8]) -> Option<Address> {
    if input.len() != WORD_SIZE {
        return None;
    }
    let mut w = [0u8; WORD_SIZE];
    w.copy_from_slice(input);
    Some(word_to_tron_address(&w))
}

/// Sum of `frozen_v2[type=t].amount` for a single account. java-tron's
/// `AccountCapsule.getFrozenV2BalanceForBandwidth/Energy`.
fn frozen_v2_balance(account: &tron_proto::Account, resource_type: i32) -> i64 {
    account
        .frozen_v2
        .iter()
        .filter(|f| f.r#type == resource_type)
        .map(|f| f.amount)
        .sum()
}

/// Delegated-out v2 for the given resource type. The Bandwidth value
/// lives at the top level; Energy lives nested under `account_resource`.
fn delegated_v2(account: &tron_proto::Account, resource_type: i32) -> i64 {
    match resource_type {
        RESOURCE_BANDWIDTH => account.delegated_frozen_v2_balance_for_bandwidth,
        RESOURCE_ENERGY => account
            .account_resource
            .as_ref()
            .map(|r| r.delegated_frozen_v2_balance_for_energy)
            .unwrap_or(0),
        _ => 0,
    }
}

/// Delegated-in (acquired) v2 for the given resource type.
fn acquired_delegated_v2(account: &tron_proto::Account, resource_type: i32) -> i64 {
    match resource_type {
        RESOURCE_BANDWIDTH => account.acquired_delegated_frozen_v2_balance_for_bandwidth,
        RESOURCE_ENERGY => account
            .account_resource
            .as_ref()
            .map(|r| r.acquired_delegated_frozen_v2_balance_for_energy)
            .unwrap_or(0),
        _ => 0,
    }
}

/// Current usage. Bandwidth = `net_usage`; Energy = `energy_usage`.
fn resource_usage(account: &tron_proto::Account, resource_type: i32) -> i64 {
    match resource_type {
        RESOURCE_BANDWIDTH => account.net_usage,
        RESOURCE_ENERGY => account
            .account_resource
            .as_ref()
            .map(|r| r.energy_usage)
            .unwrap_or(0),
        _ => 0,
    }
}

// === 0x0100000c — AvailableUnfreezeV2Size ====================================

/// Number of *unused* unfreezeV2 slots. java-tron caps this at
/// `UNFREEZE_V2_MAX_NUM = 32` per resource type per account, total 32
/// across all resources (matches `Common.MAX_UNFREEZE_V2_SIZE`).
const MAX_UNFREEZE_V2_SIZE: i64 = 32;

fn available_unfreeze_v2_size(input: &[u8], ctx: &dyn EvmContext) -> PrecompileResult {
    let addr = match parse_address_only(input) {
        Some(a) => a,
        None => return Ok(long_to_32_bytes(0)),
    };
    let account = ctx.get_account(&addr)?;
    let used = account
        .map(|a| a.unfrozen_v2.len() as i64)
        .unwrap_or(0);
    Ok(long_to_32_bytes(MAX_UNFREEZE_V2_SIZE.saturating_sub(used).max(0)))
}

// === 0x0100000d — UnfreezableBalanceV2 ======================================

/// Sum of mature `unfrozen_v2` entries (expiry ≤ now). java-tron uses the
/// current block timestamp; we use `ctx.block_timestamp_ms`.
fn unfreezable_balance_v2(input: &[u8], ctx: &dyn EvmContext) -> PrecompileResult {
    let (addr, rtype) = match parse_address_and_type(input) {
        Some(p) => p,
        None => return Ok(long_to_32_bytes(0)),
    };
    let now = ctx.block_timestamp_ms();
    let account = match ctx.get_account(&addr)? {
        Some(a) => a,
        None => return Ok(long_to_32_bytes(0)),
    };
    let total: i64 = account
        .unfrozen_v2
        .iter()
        .filter(|u| u.r#type == rtype && u.unfreeze_expire_time <= now)
        .map(|u| u.unfreeze_amount)
        .sum();
    Ok(long_to_32_bytes(total))
}

// === 0x0100000e — ExpireUnfreezeBalanceV2 ===================================

/// Like `UnfreezableBalanceV2`, but the cut-off time is supplied as an
/// argument rather than read from the current block.
fn expire_unfreeze_balance_v2(input: &[u8], ctx: &dyn EvmContext) -> PrecompileResult {
    if input.len() != 3 * WORD_SIZE {
        return Ok(long_to_32_bytes(0));
    }
    let words = parse_words(input);
    let addr = word_to_tron_address(&words[0]);
    let cutoff = i64::from_be_bytes(words[1][24..32].try_into().unwrap());
    let rtype = i64::from_be_bytes(words[2][24..32].try_into().unwrap()) as i32;
    let account = match ctx.get_account(&addr)? {
        Some(a) => a,
        None => return Ok(long_to_32_bytes(0)),
    };
    let total: i64 = account
        .unfrozen_v2
        .iter()
        .filter(|u| u.r#type == rtype && u.unfreeze_expire_time <= cutoff)
        .map(|u| u.unfreeze_amount)
        .sum();
    Ok(long_to_32_bytes(total))
}

// === 0x0100000f — DelegatableResource =======================================

/// `frozen_v2[type] - delegated_v2[type]` — the amount this account can
/// still delegate out for the given resource.
fn delegatable_resource(input: &[u8], ctx: &dyn EvmContext) -> PrecompileResult {
    let (addr, rtype) = match parse_address_and_type(input) {
        Some(p) => p,
        None => return Ok(long_to_32_bytes(0)),
    };
    let account = match ctx.get_account(&addr)? {
        Some(a) => a,
        None => return Ok(long_to_32_bytes(0)),
    };
    let frozen = frozen_v2_balance(&account, rtype);
    let delegated = delegated_v2(&account, rtype);
    Ok(long_to_32_bytes(frozen.saturating_sub(delegated).max(0)))
}

// === 0x01000010 — ResourceV2 ================================================

/// Just `frozen_v2[type]`.
fn resource_v2(input: &[u8], ctx: &dyn EvmContext) -> PrecompileResult {
    let (addr, rtype) = match parse_address_and_type(input) {
        Some(p) => p,
        None => return Ok(long_to_32_bytes(0)),
    };
    let account = match ctx.get_account(&addr)? {
        Some(a) => a,
        None => return Ok(long_to_32_bytes(0)),
    };
    Ok(long_to_32_bytes(frozen_v2_balance(&account, rtype)))
}

// === 0x01000011 — CheckUnDelegateResource ===================================

/// Inspects a delegation between `caller` (the precompile callee context's
/// caller) and `target_addr` for `amount` of `resource_type`. Returns three
/// words concatenated:
///
///   (free_amount, max_undelegate, expire_time)
///
/// java-tron's exact semantics inspect `DelegatedResourceStore` for the
/// `(caller, target)` pair, compute how much of the requested amount is
/// in the "free" portion (no expiry constraint) vs locked until `expire_time`.
///
/// For now we treat the entire delegation as undelegatable iff the
/// stored expiry has elapsed, with `expire_time` returned as-is.
fn check_un_delegate_resource(input: &[u8], ctx: &dyn EvmContext) -> PrecompileResult {
    if input.len() != 3 * WORD_SIZE {
        let mut zero = vec![0u8; 3 * WORD_SIZE];
        // 3 × 32-byte words of zero.
        for chunk in zero.chunks_mut(WORD_SIZE) {
            let z = long_to_32_bytes(0);
            chunk.copy_from_slice(&z);
        }
        return Ok(zero);
    }
    let words = parse_words(input);
    let target = word_to_tron_address(&words[0]);
    let amount = i64::from_be_bytes(words[1][24..32].try_into().unwrap());
    let rtype = i64::from_be_bytes(words[2][24..32].try_into().unwrap()) as i32;

    let caller = ctx.caller();
    let entry = ctx.get_delegated_resource(&caller, &target)?;

    let (delegated, expire) = match entry {
        Some(dr) => match rtype {
            RESOURCE_BANDWIDTH => (dr.frozen_balance_for_bandwidth, dr.expire_time_for_bandwidth),
            RESOURCE_ENERGY => (dr.frozen_balance_for_energy, dr.expire_time_for_energy),
            _ => (0, 0),
        },
        None => (0, 0),
    };

    let now = ctx.block_timestamp_ms();
    let max_undelegate = if expire <= now { delegated } else { 0 };
    let free = max_undelegate.min(amount).max(0);

    // Concatenate three words: (free, max_undelegate, expire).
    let mut out = Vec::with_capacity(3 * WORD_SIZE);
    out.extend_from_slice(&long_to_32_bytes(free));
    out.extend_from_slice(&long_to_32_bytes(max_undelegate));
    out.extend_from_slice(&long_to_32_bytes(expire));
    Ok(out)
}

// === 0x01000012 — ResourceUsage =============================================

fn resource_usage_precompile(input: &[u8], ctx: &dyn EvmContext) -> PrecompileResult {
    let (addr, rtype) = match parse_address_and_type(input) {
        Some(p) => p,
        None => return Ok(long_to_32_bytes(0)),
    };
    let account = match ctx.get_account(&addr)? {
        Some(a) => a,
        None => return Ok(long_to_32_bytes(0)),
    };
    Ok(long_to_32_bytes(resource_usage(&account, rtype)))
}

// === 0x01000013 — TotalResource =============================================

/// `frozen_v2[type] + acquired_delegated_v2[type]` — everything available
/// to this account for the resource (own + acquired).
fn total_resource(input: &[u8], ctx: &dyn EvmContext) -> PrecompileResult {
    let (addr, rtype) = match parse_address_and_type(input) {
        Some(p) => p,
        None => return Ok(long_to_32_bytes(0)),
    };
    let account = match ctx.get_account(&addr)? {
        Some(a) => a,
        None => return Ok(long_to_32_bytes(0)),
    };
    let own = frozen_v2_balance(&account, rtype);
    let acquired = acquired_delegated_v2(&account, rtype);
    Ok(long_to_32_bytes(own.saturating_add(acquired)))
}

// === 0x01000014 — TotalDelegatedResource ====================================

fn total_delegated_resource(input: &[u8], ctx: &dyn EvmContext) -> PrecompileResult {
    let (addr, rtype) = match parse_address_and_type(input) {
        Some(p) => p,
        None => return Ok(long_to_32_bytes(0)),
    };
    let account = match ctx.get_account(&addr)? {
        Some(a) => a,
        None => return Ok(long_to_32_bytes(0)),
    };
    Ok(long_to_32_bytes(delegated_v2(&account, rtype)))
}

// === 0x01000015 — TotalAcquiredResource =====================================

fn total_acquired_resource(input: &[u8], ctx: &dyn EvmContext) -> PrecompileResult {
    let (addr, rtype) = match parse_address_and_type(input) {
        Some(p) => p,
        None => return Ok(long_to_32_bytes(0)),
    };
    let account = match ctx.get_account(&addr)? {
        Some(a) => a,
        None => return Ok(long_to_32_bytes(0)),
    };
    Ok(long_to_32_bytes(acquired_delegated_v2(&account, rtype)))
}
