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
use tron_crypto::hash::{keccak256, sha256};
use tron_types::resource::{
    account_usage_balance_and_restore_seconds, all_frozen_balance_for_bandwidth,
    all_frozen_balance_for_energy, ResourceKind, BLOCK_PRODUCED_INTERVAL_MS,
};

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
            Self::AvailableUnfreezeV2Size => 50,
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
            // java-tron `GetChainParameter.getEnergyForData` returns 50, not 500
            // (PrecompiledContracts.java) — a 10x over-charge that bit every
            // contract reading a chain parameter (e.g. SimpleEnergyV1: +450 per
            // call, +900 on its 2 calls).
            Self::GetChainParameter => 50,
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
            // java-tron `ValidateMultiSign.getEnergyForData` scales per signature:
            // `cnt = (data.length / WORD_SIZE - 5) / 5; return cnt * ENGERYPERSIGN`
            // (ENGERYPERSIGN = 1500). A flat 1500 over/under-charged depending on
            // the signature count. (Guard `< 5` words → 0, since the Rust subtraction
            // would underflow; java's negative-cnt case only arises on invalid input.)
            Self::ValidateMultiSign => {
                const WORD_SIZE: usize = 32;
                let total_words = input.len() / WORD_SIZE;
                if total_words < 5 {
                    return 0;
                }
                let entries = (total_words - 5) / 5;
                (entries as u64) * 1500
            }
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
            // java-tron `Ripempd160.getEnergyForData`: `600 + 120 per
            // 32-byte word (rounded up)`. Identical to revm's RIPEMD160
            // cost, but charged here because TRON's 0x03 output differs
            // from real ripemd160 (see `ripemd160_precompile`).
            Self::Ripemd160 => {
                600u64.saturating_add((input.len() as u64).div_ceil(32).saturating_mul(120))
            }
            // java-tron `ModExp.getEnergyForData` is permanently the
            // EIP-198 (Byzantium) formula — it never adopted EIP-2565,
            // so the energy is ~10x higher than revm's resolved
            // (≥ Berlin) cost. Computed locally to match java.
            Self::ModExp => modexp_energy_cost(input),
            // Standard EVM precompiles (EcRecover, Sha256, Identity,
            // Bn128Add, Bn128Mul, Bn128Pairing, EthRipemd160) are
            // handled by the interpreter — their execute() returns
            // HandledByInterpreter and the cost calculation lives in revm.
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
        let result = self.execute_inner(input, ctx);
        maybe_trace_resource_precompile(self, input, ctx, &result);
        result
    }

    fn execute_inner(
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

            // TRON's 0x03 / 0x05 diverge from the standard EVM
            // precompiles, so they're implemented here rather than
            // deferred to the interpreter.
            Self::Ripemd160 => Ok(ripemd160_precompile(input)),
            Self::ModExp => Ok(modexp_precompile(input)),

            // === Standard EVM (handled upstream) ===
            Self::EcRecover
            | Self::Sha256
            | Self::Identity
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

/// `0x03` — TRON's RIPEMD160 quirk. Despite the address, java-tron's
/// `PrecompiledContracts.Ripempd160.execute` does NOT compute ripemd160:
/// it takes the first 20 bytes of `SHA256(input)` and returns
/// `SHA256(those 20 bytes)` — a 32-byte digest, left-aligned, no padding.
/// (The real ripemd160 lives at `0x00020003` / `EthRipemd160`.)
fn ripemd160_precompile(input: &[u8]) -> Vec<u8> {
    let first = sha256(input);
    sha256(&first[..20]).to_vec()
}

/// java-tron `ModExp.parseLen` — the `idx`-th 32-byte big-endian length
/// word, run through `DataWord.intValueSafe` (saturates to
/// `Integer.MAX_VALUE` when more than 4 bytes are occupied or the value
/// would be negative as an `int`). Words past the end of `data` read as
/// zero (java's `parseBytes` right-pads).
fn modexp_parse_len(data: &[u8], idx: usize) -> usize {
    let off = idx * WORD_SIZE;
    let mut word = [0u8; WORD_SIZE];
    if off < data.len() {
        let n = (data.len() - off).min(WORD_SIZE);
        word[..n].copy_from_slice(&data[off..off + n]);
    }
    // intValueSafe: occupying more than 4 bytes, or a high bit in the
    // low 4 bytes (negative int), saturates to Integer.MAX_VALUE.
    if word[..28].iter().any(|&b| b != 0) || word[28] & 0x80 != 0 {
        return i32::MAX as usize;
    }
    u32::from_be_bytes(word[28..32].try_into().unwrap()) as usize
}

/// java-tron `BIUtil.addSafely` for the `int` offsets used in ModExp:
/// the sum saturates to `Integer.MAX_VALUE`.
fn modexp_add_safely(a: usize, b: usize) -> usize {
    a.saturating_add(b).min(i32::MAX as usize)
}

/// java-tron `ByteUtil.parseBytes(data, offset, len)` — `len` bytes from
/// `offset`, right-padded with zeros when `data` is too short; empty when
/// `offset >= data.len()` or `len == 0`.
fn modexp_parse_bytes(data: &[u8], offset: usize, len: usize) -> Vec<u8> {
    if offset >= data.len() || len == 0 {
        return Vec::new();
    }
    let mut out = vec![0u8; len];
    let avail = (data.len() - offset).min(len);
    out[..avail].copy_from_slice(&data[offset..offset + avail]);
    out
}

const MODEXP_ARGS_OFFSET: usize = 32 * 3;

/// java-tron `ModExp.getEnergyForData` — the permanent EIP-198 (Byzantium)
/// energy formula. java never adopted EIP-2565, so this is ~10x the gas
/// revm charges at the resolved (≥ Berlin) spec. The result is computed in
/// `i128` to avoid overflow and clamped to `i64` (`Long.MAX_VALUE` when it
/// would not fit), matching java's `BigInteger` math.
fn modexp_energy_cost(input: &[u8]) -> u64 {
    let base_len = modexp_parse_len(input, 0);
    let exp_len = modexp_parse_len(input, 1);
    let mod_len = modexp_parse_len(input, 2);

    // expHighBytes = parseBytes(data, ARGS_OFFSET + baseLen, min(expLen, 32)).
    let exp_high = modexp_parse_bytes(
        input,
        modexp_add_safely(MODEXP_ARGS_OFFSET, base_len),
        exp_len.min(32),
    );

    let mult_complexity = modexp_mult_complexity(base_len.max(mod_len));
    let adj_exp_len = modexp_adjusted_exp_length(&exp_high, exp_len);

    // energy = multComplexity * max(adjExpLen, 1) / GQUAD_DIVISOR(=20).
    let energy = (mult_complexity as i128)
        .saturating_mul(adj_exp_len.max(1) as i128)
        / 20;
    if energy >= i64::MAX as i128 {
        i64::MAX as u64
    } else {
        energy as u64
    }
}

/// java-tron `ModExp.getMultComplexity(x)` where `x = max(baseLen, modLen)`.
fn modexp_mult_complexity(x: usize) -> i128 {
    let x = x as i128;
    let x2 = x * x;
    if x <= 64 {
        x2
    } else if x <= 1024 {
        x2 / 4 + 96 * x - 3072
    } else {
        x2 / 16 + 480 * x - 199680
    }
}

/// java-tron `ModExp.getAdjustedExponentLength(expHighBytes, expLen)`.
/// `highestBit` is the index of the highest set bit across `expHighBytes`
/// (0 when none are set); for `expLen > 32` the high 8*(expLen-32) bits
/// are added.
fn modexp_adjusted_exp_length(exp_high: &[u8], exp_len: usize) -> i128 {
    // numberOfLeadingZeros over the big-endian byte array.
    let leading_zeros = exp_high
        .iter()
        .position(|&b| b != 0)
        .map(|i| i * 8 + (exp_high[i].leading_zeros() as usize))
        .unwrap_or(exp_high.len() * 8);
    let mut highest_bit = (8 * exp_high.len()).saturating_sub(leading_zeros);
    if highest_bit > 0 {
        highest_bit -= 1;
    }
    if exp_len <= 32 {
        highest_bit as i128
    } else {
        8 * (exp_len as i128 - 32) + highest_bit as i128
    }
}

/// `0x05` — modular exponentiation. The energy is java's EIP-198 cost
/// (see `modexp_energy_cost`); the OUTPUT bytes mirror java-tron's
/// `ModExp.execute` exactly: parse `base`/`exp`/`mod` as unsigned
/// big-endian, return empty bytes when the modulus is zero, otherwise
/// `base^exp mod m` left-padded to `modLen` bytes.
fn modexp_precompile(input: &[u8]) -> Vec<u8> {
    let base_len = modexp_parse_len(input, 0);
    let exp_len = modexp_parse_len(input, 1);
    let mod_len = modexp_parse_len(input, 2);

    let base = modexp_parse_bytes(input, MODEXP_ARGS_OFFSET, base_len);
    let exp = modexp_parse_bytes(
        input,
        modexp_add_safely(MODEXP_ARGS_OFFSET, base_len),
        exp_len,
    );
    let modulus = modexp_parse_bytes(
        input,
        modexp_add_safely(modexp_add_safely(MODEXP_ARGS_OFFSET, base_len), exp_len),
        mod_len,
    );

    // java `isZero(mod)` → empty output (NOT modLen zeros).
    if modulus.iter().all(|&b| b == 0) {
        return Vec::new();
    }

    // `aurora_engine_modexp::modexp` returns the stripped big-endian
    // result (the same primitive revm uses). Left-pad to `modLen`,
    // matching java's `adjRes` length adjustment.
    let res = aurora_engine_modexp::modexp(&base, &exp, &modulus);
    if res.len() >= mod_len {
        res
    } else {
        let mut adj = vec![0u8; mod_len];
        adj[mod_len - res.len()..].copy_from_slice(&res);
        adj
    }
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
    /// An access that throws an *uncaught* exception in java-tron's
    /// precompile body — e.g. an out-of-range `words[]` index or an
    /// `Arrays.copyOfRange` past the end of the call data in
    /// `ValidateMultiSign`/`extractSigArray`, whose try-block does not
    /// cover those statements. In java the resulting
    /// `ArrayIndexOutOfBoundsException` propagates to `VM.java`, which
    /// runs `program.spendAllEnergy()` and halts → the whole transaction
    /// reverts after burning the entire energy budget.
    ///
    /// The interpreter bridge (`evm.rs::dispatch_tron`) MUST map this
    /// variant to a revert that consumes the full `gas_limit`, NOT to a
    /// zero-cost revert (which is reserved for the success-with-false
    /// `Ok(..)` precompile outputs). This is distinct from `Malformed`,
    /// whose java counterpart returns a value rather than throwing.
    #[error("uncaught precompile throw: spend all energy and revert")]
    SpendAllRevert,
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

/// java-tron `DataWord.longValueSafe()` — the low 64 bits as a signed long,
/// saturated to `i64::MAX` when the word occupies more than 8 bytes (so an
/// out-of-range `amount`/`type` clamps instead of wrapping).
fn word_to_long_safe(word: &[u8; WORD_SIZE]) -> i64 {
    if word[..24].iter().any(|&b| b != 0) {
        return i64::MAX;
    }
    let v = i64::from_be_bytes(word[24..32].try_into().unwrap());
    if v < 0 {
        i64::MAX
    } else {
        v
    }
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
// TotalVoteCount (0x0100000a): the queried account's TRON Power (in TRX)
// =============================================================================

/// Despite the name, java-tron's `PrecompiledContracts.TotalVoteCount` returns
/// the **TRON Power of the account named in the input**, divided by
/// `TRX_PRECISION` — i.e. the total voting weight that account may cast, not a
/// sum of witness vote counts. The input is a single 32-byte word holding the
/// address; a missing/wrong-length input or an absent account yields 0.
///
/// The power source matches java's `getAllTronPower()`/`getTronPower()` switch:
/// when `supportUnfreezeDelay()` (`UNFREEZE_DELAY_DAYS > 0`) **and**
/// `supportAllowNewResourceModel()` (`ALLOW_NEW_RESOURCE_MODEL == 1`) are both
/// active it uses `getAllTronPower()`, otherwise `getTronPower()`. Mainnet runs
/// with `ALLOW_NEW_RESOURCE_MODEL = 0`, so the legacy `getTronPower()` path is
/// the live one — the same source the VOTEWITNESS validation caps against.
fn total_vote_count(input: &[u8], ctx: &dyn EvmContext) -> PrecompileResult {
    let addr = match parse_address_only(input) {
        Some(a) => a,
        None => return Ok(long_to_32_bytes(0)),
    };
    let account = match ctx.get_account(&addr)? {
        Some(a) => a,
        None => return Ok(long_to_32_bytes(0)),
    };
    let support_unfreeze_delay =
        ctx.chain_parameter_long(b"UNFREEZE_DELAY_DAYS")?.unwrap_or(0) > 0;
    let support_new_resource_model =
        ctx.chain_parameter_long(b"ALLOW_NEW_RESOURCE_MODEL")?.unwrap_or(0) == 1;
    let tron_power = if support_unfreeze_delay && support_new_resource_model {
        crate::votes::all_tron_power(&account)
    } else {
        crate::votes::tron_power(&account)
    };
    Ok(long_to_32_bytes(tron_power / crate::votes::TRX_PRECISION))
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

/// java-tron `GetChainParameter` — `ChainParameterEnum.fromCode(code)`. Only
/// SIX codes exist (java's enum); everything else (and code 0) returns 0. The
/// earlier mapping used a completely different, invented code table (code 3 →
/// TRANSACTION_FEE instead of TOTAL_ENERGY_CURRENT_LIMIT, etc.), so every
/// energy-rental contract that read the energy limit/weight here got garbage
/// and reverted "not enough energy".
fn get_chain_parameter(input: &[u8], ctx: &dyn EvmContext) -> PrecompileResult {
    if input.len() != WORD_SIZE {
        return Ok(long_to_32_bytes(0));
    }
    let mut word = [0u8; WORD_SIZE];
    word.copy_from_slice(input);
    let code = word_to_long_safe(&word);
    let value = match code {
        // 1 TOTAL_NET_LIMIT — getTotalNetLimit() (init default 43_200_000_000).
        1 => ctx
            .chain_parameter_long(b"TOTAL_NET_LIMIT")?
            .unwrap_or(43_200_000_000),
        // 2 TOTAL_NET_WEIGHT
        2 => ctx.chain_parameter_long(b"TOTAL_NET_WEIGHT")?.unwrap_or(0),
        // 3 TOTAL_ENERGY_CURRENT_LIMIT
        3 => ctx
            .chain_parameter_long(b"TOTAL_ENERGY_CURRENT_LIMIT")?
            .unwrap_or(0),
        // 4 TOTAL_ENERGY_WEIGHT
        4 => ctx.chain_parameter_long(b"TOTAL_ENERGY_WEIGHT")?.unwrap_or(0),
        // 5 UNFREEZE_DELAY_DAYS
        5 => ctx.chain_parameter_long(b"UNFREEZE_DELAY_DAYS")?.unwrap_or(0),
        // 0 INVALID_PARAMETER_KEY + any unknown code → 0.
        _ => 0,
    };
    Ok(long_to_32_bytes(value))
}

// =============================================================================
// Signature-array (Solidity `bytes[]`) parsing + recovery
// =============================================================================

const SIG_LENGTH: usize = 65;

/// java-tron `DataWord.intValueSafe()` — the low 32 bits as a non-negative
/// `int`, saturated to `Integer.MAX_VALUE` when the word occupies more than
/// 4 bytes or the low word would read as a negative `int`.
fn word_int_value_safe(word: &[u8; WORD_SIZE]) -> usize {
    if word[..28].iter().any(|&b| b != 0) || word[28] & 0x80 != 0 {
        return i32::MAX as usize;
    }
    u32::from_be_bytes(word[28..32].try_into().unwrap()) as usize
}

/// java-tron `ByteUtil.extractBytes(data, offset, len)` =
/// `Arrays.copyOfRange(data, offset, offset + len)`: `len` bytes from
/// `offset`, zero-padded when the slice runs past the end of `data`.
/// Returns `None` when `offset > data.len()` (java throws
/// `ArrayIndexOutOfBoundsException`, which fails the whole call).
fn extract_bytes(data: &[u8], offset: usize, len: usize) -> Option<Vec<u8>> {
    if offset > data.len() {
        return None;
    }
    let mut out = vec![0u8; len];
    let avail = (data.len() - offset).min(len);
    out[..avail].copy_from_slice(&data[offset..offset + avail]);
    Some(out)
}

/// java-tron `PrecompiledContracts.extractSigArray` — the
/// `allowTvmSelfdestructRestriction` (proposal #70, active on mainnet) path
/// for parsing the signature `bytes[]`. `offset` is the array-head word
/// index (`words[i].intValueSafe() / WORD_SIZE`). The `len` word is at
/// `offset`; the `N` words after it are per-element relative byte offsets,
/// and each 65-byte signature is read from
/// `(bytesOffset + offset + 2) * WORD_SIZE` in the raw input.
///
/// Returns `None` if any element word index is out of range or a 65-byte
/// signature read would start past the end of `data` — both throw an
/// `ArrayIndexOutOfBoundsException` in java (`words[...]` /
/// `Arrays.copyOfRange`). This throw is OUTSIDE `ValidateMultiSign`'s
/// try-block but INSIDE `BatchValidateSign.doExecute`'s, so each caller
/// maps `None` differently: `BatchValidateSign` returns the caught
/// all-zero word, while `ValidateMultiSign` propagates a spend-all
/// revert (`PrecompileError::SpendAllRevert`).
fn extract_sig_array(words: &[[u8; WORD_SIZE]], offset: usize, data: &[u8]) -> Option<Vec<Vec<u8>>> {
    if words.is_empty() || offset > words.len() - 1 {
        return Some(Vec::new());
    }
    let len = word_int_value_safe(&words[offset]);
    let mut out = Vec::with_capacity(len);
    for i in 0..len {
        let ptr_word = words.get(offset + i + 1)?;
        let bytes_offset = word_int_value_safe(ptr_word) / WORD_SIZE;
        let read_at = bytes_offset
            .saturating_add(offset)
            .saturating_add(2)
            .saturating_mul(WORD_SIZE);
        out.push(extract_bytes(data, read_at, SIG_LENGTH)?);
    }
    Some(out)
}

/// java-tron `recoverAddrBySign` — recover the signer's 20-byte (EVM-style,
/// low 20 of the keccak of the pubkey) address from a 65-byte `[r|s|v]`
/// signature over `hash`. Returns `None` on any failure (empty/short sig,
/// invalid components, recovery error) so the caller skips it (java returns
/// an empty address, which matches no permission key / address).
fn recover_addr_by_sign(sign: &[u8], hash: &[u8; WORD_SIZE]) -> Option<[u8; 20]> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    if sign.len() < SIG_LENGTH {
        return None;
    }
    let mut rs = [0u8; 64];
    rs.copy_from_slice(&sign[0..64]);
    let v = sign[64];
    let recid = if v >= 27 { v - 27 } else { v };
    let rec_id = RecoveryId::try_from(recid).ok()?;
    let sig = Signature::from_slice(&rs).ok()?;
    let vk = VerifyingKey::recover_from_prehash(hash, &sig, rec_id).ok()?;
    let enc = vk.to_encoded_point(false);
    let pub_bytes = enc.as_bytes();
    if pub_bytes.len() != 65 {
        return None;
    }
    let pub_hash = keccak256(&pub_bytes[1..]);
    let mut low20 = [0u8; 20];
    low20.copy_from_slice(&pub_hash[12..32]);
    Some(low20)
}

// =============================================================================
// BatchValidateSign (0x09)
// =============================================================================
//
// ABI (java-tron `BatchValidateSign.doExecute`):
//   word[0]    = hash to verify
//   word[1]    = byte offset to the signature `bytes[]` array
//   word[2]    = byte offset to the address `bytes32[]` array
//   ...        = the two arrays, encoded per Solidity ABI (offset indirection
//                for `bytes[]`, contiguous words for `bytes32[]`)
//
// Returns a 32-byte word where byte `i` is 1 iff signature `i` recovers to
// addresses[i], 0 otherwise. On any malformed input it returns the all-zero
// word (java's `execute` catches every Throwable and returns `new byte[32]`).

fn batch_validate_sign(input: &[u8]) -> PrecompileResult {
    const MAX_SIZE: usize = 16;

    // java `DataWord.parseArray` floors `len = data.length / WORD_SIZE`,
    // discarding any trailing partial word; `parse_words` rounds up. Truncate
    // to the floor count so `words.len()` and every `words[i]` access match
    // java's array exactly. (BatchValidateSign catches all throws and returns
    // the all-zero word, so the floor count only affects which path produces
    // that word, never the result.)
    let word_count = input.len() / WORD_SIZE;
    let parsed = parse_words(input);
    let words = &parsed[..word_count];
    if words.len() < 5 {
        return Ok(data_boolean(false));
    }

    let hash = words[0];
    // Array heads: java reads `words[wordIdx].intValueSafe()` where
    // `wordIdx = words[1|2].intValueSafe() / WORD_SIZE`.
    let sig_head_idx = word_int_value_safe(&words[1]) / WORD_SIZE;
    let addr_head_idx = word_int_value_safe(&words[2]) / WORD_SIZE;

    // `allowTvmSelfdestructRestriction` (proposal #70, active on mainnet):
    // java reads the declared array sizes and rejects oversized ones up
    // front, then parses the signatures with offset indirection.
    let (Some(sig_head), Some(addr_head)) = (words.get(sig_head_idx), words.get(addr_head_idx))
    else {
        return Ok(data_boolean(false));
    };
    let sig_array_size = word_int_value_safe(sig_head);
    let addr_array_size = word_int_value_safe(addr_head);
    if sig_array_size > MAX_SIZE || addr_array_size > MAX_SIZE {
        return Ok(data_boolean(false));
    }

    let signatures = match extract_sig_array(words, sig_head_idx, input) {
        Some(s) => s,
        None => return Ok(data_boolean(false)),
    };
    // addresses := contiguous 32-byte words after the array-length word
    // (java `extractBytes32Array`). java eagerly reads `words[addr_head_idx +
    // i + 1]` for every `i` in `0..addr_array_size`; an out-of-range index
    // throws `ArrayIndexOutOfBoundsException`, which `BatchValidateSign`'s
    // outer try-block catches and turns into the all-zero word. Mirror that
    // by rejecting up front when the declared address-array size runs past
    // the available words, rather than partially filling the result. The
    // well-formed path is unaffected: there `addr_array_size == cnt` and
    // every address word exists.
    let addr_count = addr_array_size;
    if addr_head_idx
        .saturating_add(addr_array_size)
        .saturating_add(1)
        > words.len()
    {
        return Ok(data_boolean(false));
    }

    let cnt = signatures.len();
    if cnt == 0 || cnt > MAX_SIZE || cnt != addr_count {
        return Ok(data_boolean(false));
    }

    let mut result = vec![0u8; WORD_SIZE];
    for (i, sig) in signatures.iter().enumerate() {
        let Some(addr_word) = words.get(addr_head_idx + i + 1) else {
            continue;
        };
        let Some(recovered) = recover_addr_by_sign(sig, &hash) else {
            continue;
        };
        // java `DataWord.equalAddressByteArray` compares the low 20 bytes.
        if recovered == addr_word[12..32] {
            result[i] = 1;
        }
    }

    Ok(result)
}

// =============================================================================
// ValidateMultiSign (0x0a)
// =============================================================================
//
// ABI (java-tron `ValidateMultiSign.execute`):
//   word[0]     = address (target account)
//   word[1]     = permission_id (int32 in low bytes)
//   word[2]     = 32-byte payload (mixed into the recovery prehash)
//   word[3]     = byte offset to the signature `bytes[]` array
//   ...         = the `bytes[]` array (offset indirection, 65-byte elements)
//
// The recovery prehash is `SHA256(address(21) || int32_BE(permissionId) ||
// words[2])`. For each signature: recover the signer's address; look up its
// weight in the named permission. A recovered signer whose weight is 0
// fails the whole call (`DATA_FALSE`). Each unique signer counts once.
// Returns true iff the total weight reaches the permission threshold.

fn validate_multi_sign(input: &[u8], ctx: &dyn EvmContext) -> PrecompileResult {
    const MAX_SIZE: usize = 5;

    // java `DataWord.parseArray` is FLOOR division: `len = data.length /
    // WORD_SIZE`, discarding any trailing partial word. Our `parse_words`
    // rounds UP (zero-padding the last partial word), so truncate to the
    // floor count to reproduce java's exact `words.length` — the value that
    // governs which `words[i]` accesses throw `ArrayIndexOutOfBoundsException`.
    let word_count = input.len() / WORD_SIZE;
    let parsed = parse_words(input);
    let words = &parsed[..word_count];

    // java-tron `ValidateMultiSign.execute` accesses `words[0]`, `words[1]`,
    // `words[2]`, `words[3]` and `words[words[3].intValueSafe() / WORD_SIZE]`
    // BEFORE its try-block. An out-of-range index here throws
    // `ArrayIndexOutOfBoundsException`, which is uncaught → `VM.java`
    // `spendAllEnergy()` + whole-tx revert. These are NOT the
    // success-with-false `Pair.of(true, DATA_FALSE)` returns inside the body;
    // they burn the full energy budget.
    let (Some(w0), Some(w1), Some(w2), Some(w3)) =
        (words.first(), words.get(1), words.get(2), words.get(3))
    else {
        return Err(PrecompileError::SpendAllRevert);
    };

    let addr = word_to_tron_address(w0);
    let permission_id = word_int_value_safe(w1) as i32;

    // Recovery prehash: SHA256(address(21) || ByteArray.fromInt(permissionId)
    // || words[2].getData()). `ByteArray.fromInt` is a 4-byte big-endian int.
    let mut combine = Vec::with_capacity(ADDRESS_LENGTH + 4 + WORD_SIZE);
    combine.extend_from_slice(addr.as_bytes());
    combine.extend_from_slice(&permission_id.to_be_bytes());
    combine.extend_from_slice(w2);
    let hash: [u8; WORD_SIZE] = sha256(&combine);

    // `allowTvmSelfdestructRestriction` (proposal #70, active on mainnet):
    // reject oversized arrays up front, then parse the `bytes[]` with offset
    // indirection. `words[words[3].intValueSafe() / WORD_SIZE]` is a pre-try
    // access in java — an out-of-range head index throws → spend-all-revert,
    // NOT a false result.
    let sig_head_idx = word_int_value_safe(w3) / WORD_SIZE;
    let Some(sig_head) = words.get(sig_head_idx) else {
        return Err(PrecompileError::SpendAllRevert);
    };
    // `sigArraySize > MAX_SIZE` is an explicit `Pair.of(true, DATA_FALSE)`
    // return in java — a successful precompile with a false word.
    if word_int_value_safe(sig_head) > MAX_SIZE {
        return Ok(data_boolean(false));
    }

    // `extractSigArray` is also pre-try in `ValidateMultiSign`: an
    // out-of-range element word or a signature read past the end of the call
    // data throws → spend-all-revert (see `extract_sig_array`). This differs
    // from `BatchValidateSign`, whose identical throw is caught and returns a
    // false word.
    let signatures = match extract_sig_array(words, sig_head_idx, input) {
        Some(s) => s,
        None => return Err(PrecompileError::SpendAllRevert),
    };
    // `signatures.length == 0 || > MAX_SIZE` is an explicit
    // `Pair.of(true, DATA_FALSE)` return — a successful false result.
    if signatures.is_empty() || signatures.len() > MAX_SIZE {
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

    // java `TransactionCapsule.getWeight` matches the recovered signer
    // against each key's full 21-byte address; the 0x41 prefix is constant,
    // so comparing the low 20 bytes is equivalent.
    let weight_of = |signer: &[u8; 20]| -> i64 {
        for k in &permission.keys {
            if k.address.len() == ADDRESS_LENGTH && &k.address[1..] == signer {
                return k.weight;
            }
        }
        0
    };

    // java walks the recovered signers, summing weights. A recovered signer
    // whose weight is 0 (foreign / not in the permission) fails the whole
    // call. The same `(addr, sig)` pair is skipped on a repeat; a repeated
    // signer with a *different* sig still passes through (its weight is added
    // again — but java de-dups exact `(recoveredAddr, sign)` pairs, so a
    // byte-identical signature counts once).
    let mut executed: Vec<(Vec<u8>, [u8; 20])> = Vec::new();
    let mut total_weight: i64 = 0;
    for sign in &signatures {
        let Some(recovered) = recover_addr_by_sign(sign, &hash) else {
            // recoverAddrBySign returns an empty address → getWeight == 0.
            return Ok(data_boolean(false));
        };
        let merged: Vec<u8> = recovered.iter().chain(sign.iter()).copied().collect();
        let seen_addr = executed.iter().any(|(_, a)| a == &recovered);
        if seen_addr {
            let seen_pair = executed.iter().any(|(m, _)| m == &merged);
            if seen_pair {
                continue;
            }
        }
        let weight = weight_of(&recovered);
        if weight == 0 {
            return Ok(data_boolean(false));
        }
        total_weight += weight;
        executed.push((merged, recovered));
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

/// Diagnostic: when `TRON_PRECOMPILE_TRACE_BLOCK` is set to a block number,
/// log every FreezeV2 resource-precompile call (address, input, output) made
/// while executing that block. Off (zero overhead) unless the env var is set —
/// used to capture clean-state precompile I/O at a known divergence block
/// without a debugger or archive replay.
fn maybe_trace_resource_precompile(
    p: PrecompileImpl,
    input: &[u8],
    ctx: &dyn EvmContext,
    result: &PrecompileResult,
) {
    use std::sync::OnceLock;
    // Temporary investigation default: trace the first known divergence blocks
    // (a56d573d @83316753 + the next two REVERTs) automatically, so a normal
    // fresh-snapshot re-sync captures the clean-state precompile I/O with no env
    // var to remember. Override with TRON_PRECOMPILE_TRACE_BLOCK=<n> (single
    // block), or disable with TRON_PRECOMPILE_TRACE_BLOCK=0.
    static TRACE_BLOCKS: OnceLock<Vec<i64>> = OnceLock::new();
    let targets = TRACE_BLOCKS.get_or_init(|| {
        // Off by default now that the precompiles are confirmed byte-exact;
        // re-enable for a specific block with TRON_PRECOMPILE_TRACE_BLOCK=<n>.
        match std::env::var("TRON_PRECOMPILE_TRACE_BLOCK") {
            Ok(s) => s.trim().parse::<i64>().ok().filter(|&n| n != 0).into_iter().collect(),
            Err(_) => Vec::new(),
        }
    });
    let blk = ctx.block_number();
    if !targets.contains(&blk) {
        return;
    }
    let target = blk;
    let name = match p {
        PrecompileImpl::GetChainParameter
        | PrecompileImpl::AvailableUnfreezeV2Size
        | PrecompileImpl::UnfreezableBalanceV2
        | PrecompileImpl::ExpireUnfreezeBalanceV2
        | PrecompileImpl::DelegatableResource
        | PrecompileImpl::ResourceV2
        | PrecompileImpl::CheckUnDelegateResource
        | PrecompileImpl::ResourceUsage
        | PrecompileImpl::TotalResource
        | PrecompileImpl::TotalDelegatedResource
        | PrecompileImpl::TotalAcquiredResource => format!("{p:?}"),
        _ => return,
    };
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let out = match result {
        Ok(o) => hex(o),
        Err(e) => format!("<err {e:?}>"),
    };
    eprintln!(
        "PRECOMPILE_TRACE blk={} {} caller={} in={} out={}",
        target,
        name,
        hex(ctx.caller().as_bytes()),
        hex(input),
        out,
    );
    // Dump the resolved target account's resource fields + the chain-global
    // weights/limits so the precompile math can be verified against java
    // byte-for-byte from the log alone (word[0] is the target for every member).
    if input.len() >= WORD_SIZE {
        let mut w = [0u8; WORD_SIZE];
        w.copy_from_slice(&input[..WORD_SIZE]);
        let addr = word_to_tron_address(&w);
        if let Ok(Some(a)) = ctx.get_account(&addr) {
            let ar = a.account_resource.clone().unwrap_or_default();
            let g = |k: &[u8]| ctx.chain_parameter_long(k).ok().flatten().unwrap_or(0);
            eprintln!(
                "  TRACE_ACCT {} now_slot={} TEW={} TEL={} TNW={} TNL={} \
                 e_usage={} e_lct={} e_winsz={} e_winopt={} n_usage={} n_lct={} n_winsz={} n_winopt={} \
                 fv2_e={} fv2_n={} v1_e={} dlg_v1e={} dlg_v2e={} acq_v1e={} acq_v2e={}",
                hex(addr.as_bytes()),
                ctx.latest_block_timestamp_ms() / BLOCK_PRODUCED_INTERVAL_MS,
                g(b"TOTAL_ENERGY_WEIGHT"), g(b"TOTAL_ENERGY_CURRENT_LIMIT"),
                g(b"TOTAL_NET_WEIGHT"), g(b"TOTAL_NET_LIMIT"),
                ar.energy_usage, ar.latest_consume_time_for_energy, ar.energy_window_size, ar.energy_window_optimized,
                a.net_usage, a.latest_consume_time, a.net_window_size, a.net_window_optimized,
                frozen_v2_balance(&a, RESOURCE_ENERGY), frozen_v2_balance(&a, RESOURCE_BANDWIDTH),
                ar.frozen_balance_for_energy.as_ref().map(|f| f.frozen_balance).unwrap_or(0),
                ar.delegated_frozen_balance_for_energy, ar.delegated_frozen_v2_balance_for_energy,
                ar.acquired_delegated_frozen_balance_for_energy, ar.acquired_delegated_frozen_v2_balance_for_energy,
            );
        }
    }
}

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

/// Own v1 (Stake-1.0) frozen balance — java `AccountCapsule.getFrozenBalance`
/// (bandwidth = sum of the `frozen` list) / `getEnergyFrozenBalance`.
fn frozen_v1(account: &tron_proto::Account, resource_type: i32) -> i64 {
    match resource_type {
        RESOURCE_BANDWIDTH => account.frozen.iter().map(|f| f.frozen_balance).sum(),
        RESOURCE_ENERGY => account
            .account_resource
            .as_ref()
            .and_then(|r| r.frozen_balance_for_energy.as_ref())
            .map(|f| f.frozen_balance)
            .unwrap_or(0),
        _ => 0,
    }
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

/// Delegated-out v1 (Stake-1.0) for the given resource type.
fn delegated_v1(account: &tron_proto::Account, resource_type: i32) -> i64 {
    match resource_type {
        RESOURCE_BANDWIDTH => account.delegated_frozen_balance_for_bandwidth,
        RESOURCE_ENERGY => account
            .account_resource
            .as_ref()
            .map(|r| r.delegated_frozen_balance_for_energy)
            .unwrap_or(0),
        _ => 0,
    }
}

/// Delegated-in (acquired) v1 for the given resource type.
fn acquired_delegated_v1(account: &tron_proto::Account, resource_type: i32) -> i64 {
    match resource_type {
        RESOURCE_BANDWIDTH => account.acquired_delegated_frozen_balance_for_bandwidth,
        RESOURCE_ENERGY => account
            .account_resource
            .as_ref()
            .map(|r| r.acquired_delegated_frozen_balance_for_energy)
            .unwrap_or(0),
        _ => 0,
    }
}

/// java-tron `AccountCapsule.getTotalDelegatedFrozenBalanceFor{Bandwidth,Energy}`
/// — Stake-1.0 + Stake-2.0 delegated-out.
fn total_delegated(account: &tron_proto::Account, resource_type: i32) -> i64 {
    delegated_v1(account, resource_type).saturating_add(delegated_v2(account, resource_type))
}

/// java-tron `AccountCapsule.getTotalAcquiredDelegatedFrozenBalanceFor{…}` —
/// Stake-1.0 + Stake-2.0 acquired (delegated-in).
fn total_acquired(account: &tron_proto::Account, resource_type: i32) -> i64 {
    acquired_delegated_v1(account, resource_type)
        .saturating_add(acquired_delegated_v2(account, resource_type))
}

/// Map the precompile's `i32` resource selector to [`ResourceKind`].
fn resource_kind(resource_type: i32) -> Option<ResourceKind> {
    match resource_type {
        RESOURCE_BANDWIDTH => Some(ResourceKind::Bandwidth),
        RESOURCE_ENERGY => Some(ResourceKind::Energy),
        _ => None,
    }
}

/// `(usageBalanceInSun, restoreSeconds)` for an account's current decayed usage
/// — java's `getAccount{Net,Energy}UsageBalanceAndRestoreSeconds`. Reads the
/// chain-global weights/limits from dyn-props.
fn account_usage_balance(
    account: &tron_proto::Account,
    kind: ResourceKind,
    ctx: &dyn EvmContext,
) -> Result<(i64, i64), EvmContextError> {
    // java `getHeadSlot()` = getLatestBlockHeaderTimestamp()/interval — the
    // committed head (block N-1 during apply), NOT the executing block.
    let now_slot = ctx.latest_block_timestamp_ms() / BLOCK_PRODUCED_INTERVAL_MS;
    let (total_weight, total_limit) = match kind {
        ResourceKind::Bandwidth => (
            ctx.chain_parameter_long(b"TOTAL_NET_WEIGHT")?.unwrap_or(0),
            ctx.chain_parameter_long(b"TOTAL_NET_LIMIT")?.unwrap_or(0),
        ),
        ResourceKind::Energy => (
            ctx.chain_parameter_long(b"TOTAL_ENERGY_WEIGHT")?.unwrap_or(0),
            ctx.chain_parameter_long(b"TOTAL_ENERGY_CURRENT_LIMIT")?.unwrap_or(0),
        ),
    };
    // ALLOW_HARDEN_RESOURCE_CALCULATION (proposal #97) is OFF on mainnet → the
    // legacy double/long arithmetic is the byte-exact path.
    let harden = ctx
        .chain_parameter_long(b"ALLOW_HARDEN_RESOURCE_CALCULATION")?
        .unwrap_or(0)
        == 1;
    Ok(account_usage_balance_and_restore_seconds(
        account, kind, now_slot, total_weight, total_limit, harden,
    ))
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
    let account = match ctx.get_account(&addr)? {
        Some(a) => a,
        None => return Ok(long_to_32_bytes(0)),
    };
    // java `getUnfreezingV2Count(now)` counts only entries still unfreezing
    // (expire > now); matured ones have freed their slot. java's
    // `now = getLatestBlockHeaderTimestamp()` = the committed head.
    let now = ctx.latest_block_timestamp_ms();
    let unfreezing = account
        .unfrozen_v2
        .iter()
        .filter(|u| u.unfreeze_expire_time > now)
        .count() as i64;
    Ok(long_to_32_bytes(MAX_UNFREEZE_V2_SIZE.saturating_sub(unfreezing).max(0)))
}

// === 0x0100000d — UnfreezableBalanceV2 ======================================

/// java-tron `FreezeV2Util.queryUnfreezableBalanceV2` — the account's currently
/// **frozen-v2 balance** for the resource (what is eligible to be unfrozen), NOT
/// the already-unfrozen/withdrawable amount (that is `ExpireUnfreezeBalanceV2`).
/// `getFrozenV2BalanceFor{Bandwidth,Energy}` / `getTronPowerFrozenV2Balance`.
fn unfreezable_balance_v2(input: &[u8], ctx: &dyn EvmContext) -> PrecompileResult {
    let (addr, rtype) = match parse_address_and_type(input) {
        Some(p) => p,
        None => return Ok(long_to_32_bytes(0)),
    };
    let account = match ctx.get_account(&addr)? {
        Some(a) => a,
        None => return Ok(long_to_32_bytes(0)),
    };
    // type 0/1/2 (BANDWIDTH/ENERGY/TRON_POWER) all map to a frozen_v2 sum;
    // any other type yields 0 (no matching frozen_v2 entries).
    Ok(long_to_32_bytes(frozen_v2_balance(&account, rtype)))
}

// === 0x0100000e — ExpireUnfreezeBalanceV2 ===================================

/// java-tron `ExpireUnfreezeBalanceV2` — the total withdrawable amount across
/// **all resource types** whose unfreeze matures at or before `time` (supplied
/// in **seconds**, converted to ms). Input is two words `(address, time)`; there
/// is no resource-type argument (withdrawal returns plain TRX).
fn expire_unfreeze_balance_v2(input: &[u8], ctx: &dyn EvmContext) -> PrecompileResult {
    if input.len() != 2 * WORD_SIZE {
        return Ok(long_to_32_bytes(0));
    }
    let words = parse_words(input);
    let addr = word_to_tron_address(&words[0]);
    let time_secs = word_to_long_safe(&words[1]);
    if time_secs < 0 {
        return Ok(long_to_32_bytes(0));
    }
    // java: `time >= Long.MAX/1000 ? Long.MAX : time * 1000`.
    let time_ms = if time_secs >= i64::MAX / 1_000 {
        i64::MAX
    } else {
        time_secs * 1_000
    };
    let account = match ctx.get_account(&addr)? {
        Some(a) => a,
        None => return Ok(long_to_32_bytes(0)),
    };
    let total: i64 = account
        .unfrozen_v2
        .iter()
        .filter(|u| u.unfreeze_expire_time <= time_ms)
        .map(|u| u.unfreeze_amount)
        .sum();
    Ok(long_to_32_bytes(total))
}

// === 0x0100000f — DelegatableResource =======================================

/// `frozen_v2[type] - delegated_v2[type]` — the amount this account can
/// still delegate out for the given resource.
/// java-tron `FreezeV2Util.queryDelegatableResource` — how much of the account's
/// own frozen-v2 balance is free to delegate: `frozenV2 - v2Usage`, where
/// `v2Usage = usageBalance - v1Frozen - acquiredV1 - acquiredV2` (clamped ≥ 0).
/// When the account has no current usage, the whole frozen-v2 balance is free.
fn delegatable_resource(input: &[u8], ctx: &dyn EvmContext) -> PrecompileResult {
    let (addr, rtype) = match parse_address_and_type(input) {
        Some(p) => p,
        None => return Ok(long_to_32_bytes(0)),
    };
    let Some(kind) = resource_kind(rtype) else {
        return Ok(long_to_32_bytes(0));
    };
    let account = match ctx.get_account(&addr)? {
        Some(a) => a,
        None => return Ok(long_to_32_bytes(0)),
    };
    let frozen_v2_resource = frozen_v2_balance(&account, rtype);
    let (usage_balance, _restore) = account_usage_balance(&account, kind, ctx)?;
    if usage_balance <= 0 {
        return Ok(long_to_32_bytes(frozen_v2_resource));
    }
    // java `getV2{Net,Energy}Usage`.
    let v2_usage = usage_balance
        .saturating_sub(frozen_v1(&account, rtype))
        .saturating_sub(acquired_delegated_v1(&account, rtype))
        .saturating_sub(acquired_delegated_v2(&account, rtype))
        .max(0);
    Ok(long_to_32_bytes(frozen_v2_resource.saturating_sub(v2_usage).max(0)))
}

// === 0x01000010 — ResourceV2 ================================================

/// Just `frozen_v2[type]`.
/// java-tron `ResourceV2` — input is **three** words `(target, from, type)`.
/// When `from == target` it is the account's own frozen-v2 balance
/// (`queryUnfreezableBalanceV2`); otherwise it is the resource `from`
/// delegated to `target` (`queryResourceV2`), summing the unlocked + locked
/// v2 delegation rows.
fn resource_v2(input: &[u8], ctx: &dyn EvmContext) -> PrecompileResult {
    if input.len() != 3 * WORD_SIZE {
        return Ok(long_to_32_bytes(0));
    }
    let words = parse_words(input);
    let target = word_to_tron_address(&words[0]);
    let from = word_to_tron_address(&words[1]);
    let rtype = word_to_long_safe(&words[2]) as i32;

    if from == target {
        // queryUnfreezableBalanceV2(from, type)
        let balance = match ctx.get_account(&from)? {
            Some(a) => frozen_v2_balance(&a, rtype),
            None => 0,
        };
        return Ok(long_to_32_bytes(balance));
    }

    // queryResourceV2(from, target, type): unlocked + locked delegation rows.
    let pick = |dr: &tron_proto::DelegatedResource| match rtype {
        RESOURCE_BANDWIDTH => dr.frozen_balance_for_bandwidth,
        RESOURCE_ENERGY => dr.frozen_balance_for_energy,
        _ => 0,
    };
    let unlocked = ctx.get_delegated_resource(&from, &target)?;
    let locked = ctx.get_locked_delegated_resource(&from, &target)?;
    if unlocked.is_none() && locked.is_none() {
        return Ok(long_to_32_bytes(0));
    }
    if !matches!(rtype, RESOURCE_BANDWIDTH | RESOURCE_ENERGY) {
        return Ok(long_to_32_bytes(0));
    }
    let amount = unlocked.as_ref().map(pick).unwrap_or(0)
        .saturating_add(locked.as_ref().map(pick).unwrap_or(0));
    Ok(long_to_32_bytes(amount))
}

// === 0x01000011 — CheckUnDelegateResource ===================================

/// java-tron `FreezeV2Util.checkUndelegateResource(address, amount, type)`.
///
/// Returns three concatenated words `(clean, amount - clean, restoreSeconds)`
/// where `clean` is the portion of `amount` covered by the *target account's*
/// currently-unused (decayed) frozen balance for the resource, and
/// `restoreSeconds` is how long until its in-use portion fully recovers.
///
/// NB: despite the opcode name this inspects the **target account's own
/// resource usage vs. its total frozen balance** — it does *not* look at a
/// delegation between caller and target. (The earlier placeholder did, which
/// returned zeros and reverted every energy-rental contract that called it.)
///
/// Reference: `FreezeV2Util.checkUndelegateResource` +
/// `RepositoryImpl.getAccount{Net,Energy}UsageBalanceAndRestoreSeconds`.
fn check_un_delegate_resource(input: &[u8], ctx: &dyn EvmContext) -> PrecompileResult {
    let zeros = || {
        let mut z = vec![0u8; 3 * WORD_SIZE];
        z.fill(0);
        z
    };
    if input.len() != 3 * WORD_SIZE {
        return Ok(zeros());
    }
    let words = parse_words(input);
    let target = word_to_tron_address(&words[0]);
    let amount = word_to_long_safe(&words[1]);
    let rtype = word_to_long_safe(&words[2]) as i32;

    // `amount <= 0` / unknown resource type / missing account → zeros.
    if amount <= 0 {
        return Ok(zeros());
    }
    let account = match ctx.get_account(&target)? {
        Some(a) => a,
        None => return Ok(zeros()),
    };
    let (kind, resource_limit) = match rtype {
        RESOURCE_BANDWIDTH => (ResourceKind::Bandwidth, all_frozen_balance_for_bandwidth(&account)),
        RESOURCE_ENERGY => (ResourceKind::Energy, all_frozen_balance_for_energy(&account)),
        _ => return Ok(zeros()),
    };

    let (usage_balance, restore_seconds) = account_usage_balance(&account, kind, ctx)?;

    // java: `amount = min(amount, resourceLimit)`.
    let amount = amount.min(resource_limit);
    let (clean, remaining) = if resource_limit <= usage_balance {
        (0, amount)
    } else {
        // java: `(long)(amount * ((double)(resourceLimit - usageBalance) / resourceLimit))`.
        let clean =
            (amount as f64 * ((resource_limit - usage_balance) as f64 / resource_limit as f64)) as i64;
        (clean, amount - clean)
    };

    // Env-gated diagnostic (TRON_PCDUMP): dump the CheckUnDelegateResource
    // precompile internals (resource_limit / usage_balance / energy_usage),
    // gated on the queried address so the volume stays tiny. Off by default.
    if std::env::var("TRON_PCDUMP").is_ok() {
        let th: String = target.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        if th.contains("ed396169118f826b1001231180b3609d6f120a48")
            || th.contains("e40803bc8cfc145176656d79257a6a478a226839")
            || th.contains("5a03038f0753dcde97c1c8ca81bde7b168778b63")
        {
            let r = account.account_resource.clone().unwrap_or_default();
            let fv2 = frozen_v2_balance(&account, rtype);
            let fv1 = frozen_v1(&account, rtype);
            let aq1 = acquired_delegated_v1(&account, rtype);
            let aq2 = acquired_delegated_v2(&account, rtype);
            let tew = ctx.chain_parameter_long(b"TOTAL_ENERGY_WEIGHT").ok().flatten().unwrap_or(0);
            let tel = ctx
                .chain_parameter_long(b"TOTAL_ENERGY_CURRENT_LIMIT")
                .ok()
                .flatten()
                .unwrap_or(0);
            eprintln!(
                "PCDUMP addr={th} type={rtype} amount={amount} rl={resource_limit} ub={usage_balance} \
                 restore={restore_seconds} clean={clean} remaining={remaining} \
                 e_usage={} lct={} win_raw={} win_opt={} fv2={fv2} fv1={fv1} aq1={aq1} aq2={aq2} \
                 TEW={tew} TEL={tel}",
                r.energy_usage, r.latest_consume_time_for_energy, r.energy_window_size,
                r.energy_window_optimized,
            );
        }
    }

    let mut out = Vec::with_capacity(3 * WORD_SIZE);
    out.extend_from_slice(&long_to_32_bytes(clean));
    out.extend_from_slice(&long_to_32_bytes(remaining));
    out.extend_from_slice(&long_to_32_bytes(restore_seconds));
    Ok(out)
}

// === 0x01000012 — ResourceUsage =============================================

/// java-tron `FreezeV2Util.queryFrozenBalanceUsage` — returns the **two-word**
/// pair `(usageBalanceInSun, restoreSeconds)` (java `encodeRes`), the same
/// `getAccount{Net,Energy}UsageBalanceAndRestoreSeconds` used by
/// CheckUnDelegateResource — NOT the raw usage counter.
fn resource_usage_precompile(input: &[u8], ctx: &dyn EvmContext) -> PrecompileResult {
    let zeros = || {
        let mut z = vec![0u8; 2 * WORD_SIZE];
        z.fill(0);
        z
    };
    let (addr, rtype) = match parse_address_and_type(input) {
        Some(p) => p,
        None => return Ok(zeros()),
    };
    let Some(kind) = resource_kind(rtype) else {
        return Ok(zeros());
    };
    let account = match ctx.get_account(&addr)? {
        Some(a) => a,
        None => return Ok(zeros()),
    };
    let (balance, restore_seconds) = account_usage_balance(&account, kind, ctx)?;
    let mut out = Vec::with_capacity(2 * WORD_SIZE);
    out.extend_from_slice(&long_to_32_bytes(balance));
    out.extend_from_slice(&long_to_32_bytes(restore_seconds));
    Ok(out)
}

// === 0x01000013 — TotalResource =============================================

/// java-tron `AccountCapsule.getAllFrozenBalanceFor{Bandwidth,Energy}` — every
/// weight source: own v1 frozen + own v2 frozen + acquired-delegated (v1 + v2).
fn total_resource(input: &[u8], ctx: &dyn EvmContext) -> PrecompileResult {
    let (addr, rtype) = match parse_address_and_type(input) {
        Some(p) => p,
        None => return Ok(long_to_32_bytes(0)),
    };
    let account = match ctx.get_account(&addr)? {
        Some(a) => a,
        None => return Ok(long_to_32_bytes(0)),
    };
    let total = match rtype {
        RESOURCE_BANDWIDTH => all_frozen_balance_for_bandwidth(&account),
        RESOURCE_ENERGY => all_frozen_balance_for_energy(&account),
        _ => 0,
    };
    Ok(long_to_32_bytes(total))
}

// === 0x01000014 — TotalDelegatedResource ====================================

/// java-tron `AccountCapsule.getTotalDelegatedFrozenBalanceFor{…}` — v1 + v2
/// delegated-out (the placeholder returned v2 only, undercounting v1 rentals).
fn total_delegated_resource(input: &[u8], ctx: &dyn EvmContext) -> PrecompileResult {
    let (addr, rtype) = match parse_address_and_type(input) {
        Some(p) => p,
        None => return Ok(long_to_32_bytes(0)),
    };
    let account = match ctx.get_account(&addr)? {
        Some(a) => a,
        None => return Ok(long_to_32_bytes(0)),
    };
    Ok(long_to_32_bytes(total_delegated(&account, rtype)))
}

// === 0x01000015 — TotalAcquiredResource =====================================

/// java-tron `AccountCapsule.getTotalAcquiredDelegatedFrozenBalanceFor{…}` —
/// v1 + v2 acquired (delegated-in).
fn total_acquired_resource(input: &[u8], ctx: &dyn EvmContext) -> PrecompileResult {
    let (addr, rtype) = match parse_address_and_type(input) {
        Some(p) => p,
        None => return Ok(long_to_32_bytes(0)),
    };
    let account = match ctx.get_account(&addr)? {
        Some(a) => a,
        None => return Ok(long_to_32_bytes(0)),
    };
    Ok(long_to_32_bytes(total_acquired(&account, rtype)))
}
