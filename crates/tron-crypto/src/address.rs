//! TRON address type and derivation, matching `Hash.computeAddress` and
//! `Hash.sha3omit12` in java-tron.
//!
//! A TRON address is **21 bytes**: a single network-prefix byte followed by
//! the 20 trailing bytes of `keccak256(uncompressed_pubkey_without_04_prefix)`.
//! Mainnet uses prefix `0x41`. No checksum is included in the raw form;
//! Base58Check encoding (the user-visible "T..." form) is a separate concern.

use crate::hash::keccak256;

/// Mainnet address prefix byte. See `DecodeUtil.addressPreFixByte` and
/// `Constant.ADD_PRE_FIX_BYTE_MAINNET` in java-tron.
pub const ADDRESS_PREFIX_MAINNET: u8 = 0x41;

/// Testnet (Shasta/Nile) address prefix.
pub const ADDRESS_PREFIX_TESTNET: u8 = 0xa0;

/// Length of a raw TRON address in bytes (1 prefix + 20 hash bytes).
pub const ADDRESS_LENGTH: usize = 21;

/// A 21-byte TRON address.
///
/// Layout: `[prefix_byte, h_12, h_13, ..., h_31]` where `h` is
/// `keccak256(pubkey_x || pubkey_y)` and the prefix is `0x41` on mainnet.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address(pub [u8; ADDRESS_LENGTH]);

impl Address {
    /// Derive an address from an SEC1-uncompressed public key.
    ///
    /// `pubkey_uncompressed` must be exactly 65 bytes and start with `0x04`.
    /// Equivalent to `Hash.computeAddress(byte[] pubBytes)`.
    pub fn from_uncompressed_pubkey(pubkey_uncompressed: &[u8]) -> Result<Self, AddressError> {
        if pubkey_uncompressed.len() != 65 {
            return Err(AddressError::InvalidPubkeyLength(pubkey_uncompressed.len()));
        }
        if pubkey_uncompressed[0] != 0x04 {
            return Err(AddressError::NotUncompressed(pubkey_uncompressed[0]));
        }
        // java-tron strips byte 0 (the 0x04 marker) and hashes the X||Y pair.
        let hash = keccak256(&pubkey_uncompressed[1..]);
        Ok(Self::from_pubkey_hash(&hash, ADDRESS_PREFIX_MAINNET))
    }

    /// Derive an address from the raw 64-byte X||Y public-key pair (no 0x04 prefix).
    ///
    /// This is the form a TRON "node id" takes on the wire.
    pub fn from_pubkey_xy(pubkey_xy: &[u8]) -> Result<Self, AddressError> {
        if pubkey_xy.len() != 64 {
            return Err(AddressError::InvalidPubkeyLength(pubkey_xy.len()));
        }
        let hash = keccak256(pubkey_xy);
        Ok(Self::from_pubkey_hash(&hash, ADDRESS_PREFIX_MAINNET))
    }

    /// Construct an address from a precomputed keccak256 hash, applying the
    /// `sha3omit12` rule: take bytes `[11..32]` of the hash, then overwrite
    /// byte `[0]` with the network prefix. The byte at hash[11] is discarded.
    fn from_pubkey_hash(hash: &[u8; 32], prefix: u8) -> Self {
        let mut out = [0u8; ADDRESS_LENGTH];
        out[0] = prefix;
        out[1..].copy_from_slice(&hash[12..32]);
        Self(out)
    }

    /// The raw 21 bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; ADDRESS_LENGTH] {
        &self.0
    }

    /// The network prefix byte (e.g. `0x41` for mainnet).
    #[inline]
    pub fn prefix(&self) -> u8 {
        self.0[0]
    }

    /// Construct from raw 21 bytes. No validation beyond length.
    pub fn from_raw(bytes: [u8; ADDRESS_LENGTH]) -> Self {
        Self(bytes)
    }
}

impl core::fmt::Debug for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Address(0x{})", hex::encode(self.0))
    }
}

impl core::fmt::Display for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AddressError {
    #[error("invalid public key length: {0} (expected 64 or 65)")]
    InvalidPubkeyLength(usize),
    #[error("public key must be SEC1-uncompressed (start with 0x04), got 0x{0:02x}")]
    NotUncompressed(u8),
}
