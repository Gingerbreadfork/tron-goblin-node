//! `BlockId` — the TRON-specific 32-byte block identifier.
//!
//! **Critical quirk:** unlike Ethereum, a TRON block id is *not* simply the
//! hash of the block header. The 32-byte id is constructed as
//!
//! ```text
//! id[0..8]  = block_num as big-endian u64
//! id[8..32] = sha256(block_header.raw_data.encode())[8..32]
//! ```
//!
//! The high 64 bits of the SHA-256 are *replaced* by the block number, so
//! the first 8 bytes of any block id directly encode the height. This
//! property is exploited throughout java-tron for fast indexing.
//!
//! Source: `Sha256Hash.generateBlockId` in java-tron.

use prost::Message;
use tron_crypto::hash::sha256;
use tron_proto::block_header::Raw as BlockHeaderRaw;
use tron_proto::Block;

/// 32-byte block identifier. See module docs for layout.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockId(pub [u8; 32]);

impl BlockId {
    /// Build a `BlockId` from a raw 32-byte hash and a block number. The
    /// first 8 bytes of `hash` are *discarded* and replaced by `num`.
    pub fn from_hash_and_num(hash: &[u8; 32], num: u64) -> Self {
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&num.to_be_bytes());
        out[8..32].copy_from_slice(&hash[8..32]);
        Self(out)
    }

    /// The block number, extracted from the first 8 bytes.
    #[inline]
    pub fn num(&self) -> u64 {
        let mut be = [0u8; 8];
        be.copy_from_slice(&self.0[0..8]);
        u64::from_be_bytes(be)
    }

    /// The raw 32 bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Wrap raw bytes that are already in the BlockId layout (e.g. read
    /// from disk). No transformation is applied.
    pub fn from_raw(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl core::fmt::Debug for BlockId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BlockId(num={}, hash=0x{})", self.num(), hex::encode(self.0))
    }
}

impl core::fmt::Display for BlockId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}:0x{}", self.num(), hex::encode(self.0))
    }
}

/// Compute a `BlockId` from a [`BlockHeaderRaw`].
pub fn block_id_from_header_raw(raw: &BlockHeaderRaw) -> BlockId {
    let encoded = raw.encode_to_vec();
    let hash = sha256(&encoded);
    BlockId::from_hash_and_num(&hash, raw.number as u64)
}

/// Compute a `BlockId` from a full [`Block`]. Errors if the header is missing.
pub fn block_id_from_block(block: &Block) -> Result<BlockId, BlockIdError> {
    let header = block.block_header.as_ref().ok_or(BlockIdError::MissingHeader)?;
    let raw = header.raw_data.as_ref().ok_or(BlockIdError::MissingHeader)?;
    Ok(block_id_from_header_raw(raw))
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BlockIdError {
    #[error("block header or raw data missing")]
    MissingHeader,
}
