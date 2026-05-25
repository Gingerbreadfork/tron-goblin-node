//! 20-byte precompile addresses, pinned from java-tron's
//! `PrecompiledContracts.java`.
//!
//! TRON precompiles live at three address ranges:
//!
//! | Range                            | Use                                |
//! |----------------------------------|------------------------------------|
//! | `0x01..=0x08`                    | Standard Ethereum precompiles      |
//! | `0x09..=0x0a`                    | Multi-sig validation               |
//! | `0x0100_0001..=0x0100_0015`      | TRON-specific (votes, freeze, ZK)  |
//! | `0x0002_0003`, `0x0002_0009`     | Ethereum-compat (Ripemd160, Blake2)|
//! | `0x0000_0100`                    | P256Verify                         |
//!
//! All addresses are 20 bytes (EVM convention), big-endian, with the
//! significant bits in the low bytes.

/// 20-byte precompile address bytes.
pub type PrecompileAddress = [u8; 20];

/// Build a precompile address from a `u32` of the significant low bytes.
/// Const-fn variant: indexes the bytes directly (no `copy_from_slice`,
/// which isn't yet const-stable).
pub const fn make_addr(low: u32) -> PrecompileAddress {
    let bytes = low.to_be_bytes();
    let mut out = [0u8; 20];
    out[16] = bytes[0];
    out[17] = bytes[1];
    out[18] = bytes[2];
    out[19] = bytes[3];
    out
}

// === Standard Ethereum precompiles ==========================================
pub const ADDR_ECRECOVER: PrecompileAddress = make_addr(0x01);
pub const ADDR_SHA256: PrecompileAddress = make_addr(0x02);
pub const ADDR_RIPEMD160: PrecompileAddress = make_addr(0x03);
pub const ADDR_IDENTITY: PrecompileAddress = make_addr(0x04);
pub const ADDR_MODEXP: PrecompileAddress = make_addr(0x05);
pub const ADDR_BN128_ADD: PrecompileAddress = make_addr(0x06);
pub const ADDR_BN128_MUL: PrecompileAddress = make_addr(0x07);
pub const ADDR_BN128_PAIRING: PrecompileAddress = make_addr(0x08);

// === TRON multi-sig ========================================================
pub const ADDR_BATCH_VALIDATE_SIGN: PrecompileAddress = make_addr(0x09);
pub const ADDR_VALIDATE_MULTI_SIGN: PrecompileAddress = make_addr(0x0a);

// === Shielded TRC-20 (zk-SNARK; deferred) ===================================
pub const ADDR_VERIFY_MINT_PROOF: PrecompileAddress = make_addr(0x0100_0001);
pub const ADDR_VERIFY_TRANSFER_PROOF: PrecompileAddress = make_addr(0x0100_0002);
pub const ADDR_VERIFY_BURN_PROOF: PrecompileAddress = make_addr(0x0100_0003);
pub const ADDR_MERKLE_HASH: PrecompileAddress = make_addr(0x0100_0004);

// === Vote / SR queries =====================================================
pub const ADDR_REWARD_BALANCE: PrecompileAddress = make_addr(0x0100_0005);
pub const ADDR_IS_SR_CANDIDATE: PrecompileAddress = make_addr(0x0100_0006);
pub const ADDR_VOTE_COUNT: PrecompileAddress = make_addr(0x0100_0007);
pub const ADDR_USED_VOTE_COUNT: PrecompileAddress = make_addr(0x0100_0008);
pub const ADDR_RECEIVED_VOTE_COUNT: PrecompileAddress = make_addr(0x0100_0009);
pub const ADDR_TOTAL_VOTE_COUNT: PrecompileAddress = make_addr(0x0100_000a);

// === Chain / FreezeV2 queries ==============================================
pub const ADDR_GET_CHAIN_PARAMETER: PrecompileAddress = make_addr(0x0100_000b);
pub const ADDR_AVAILABLE_UNFREEZE_V2_SIZE: PrecompileAddress = make_addr(0x0100_000c);
pub const ADDR_UNFREEZABLE_BALANCE_V2: PrecompileAddress = make_addr(0x0100_000d);
pub const ADDR_EXPIRE_UNFREEZE_BALANCE_V2: PrecompileAddress = make_addr(0x0100_000e);
pub const ADDR_DELEGATABLE_RESOURCE: PrecompileAddress = make_addr(0x0100_000f);
pub const ADDR_RESOURCE_V2: PrecompileAddress = make_addr(0x0100_0010);
pub const ADDR_CHECK_UN_DELEGATE_RESOURCE: PrecompileAddress = make_addr(0x0100_0011);
pub const ADDR_RESOURCE_USAGE: PrecompileAddress = make_addr(0x0100_0012);
pub const ADDR_TOTAL_RESOURCE: PrecompileAddress = make_addr(0x0100_0013);
pub const ADDR_TOTAL_DELEGATED_RESOURCE: PrecompileAddress = make_addr(0x0100_0014);
pub const ADDR_TOTAL_ACQUIRED_RESOURCE: PrecompileAddress = make_addr(0x0100_0015);

// === Ethereum-compat extras =================================================
pub const ADDR_ETH_RIPEMD160: PrecompileAddress = make_addr(0x0002_0003);
pub const ADDR_BLAKE2F: PrecompileAddress = make_addr(0x0002_0009);
pub const ADDR_P256_VERIFY: PrecompileAddress = make_addr(0x0000_0100);
