//! TRON Base58Check codec — the encoding behind user-visible `T…` addresses.
//!
//! Algorithm (identical to Bitcoin's Base58Check):
//! 1. Encode/decode payload bytes ↔ Base58 alphabet.
//! 2. Checksum = first 4 bytes of `sha256(sha256(payload))` (**double** SHA-256).
//! 3. Wire form: `[payload(21) || checksum(4)]` → Base58 → string.
//!
//! For TRON the payload is the 21-byte raw address: `[0x41 || keccak[12..32]]`
//! on mainnet, which makes encoded addresses start with `T` after Base58.
//!
//! Source: `org.tron.common.utils.Commons.decode58Check` / `encode58Check`.

use sha2::Digest as _;

use crate::address::{Address, ADDRESS_LENGTH};

/// Encode raw payload bytes (typically a 21-byte TRON address) as Base58Check.
pub fn encode_check(payload: &[u8]) -> String {
    let checksum = double_sha256(payload);
    let mut buf = Vec::with_capacity(payload.len() + 4);
    buf.extend_from_slice(payload);
    buf.extend_from_slice(&checksum[0..4]);
    bs58::encode(buf).into_string()
}

/// Decode a Base58Check string to raw payload bytes, validating the checksum.
pub fn decode_check(s: &str) -> Result<Vec<u8>, Base58CheckError> {
    let raw = bs58::decode(s)
        .into_vec()
        .map_err(|e| Base58CheckError::Base58(e.to_string()))?;
    if raw.len() <= 4 {
        return Err(Base58CheckError::TooShort);
    }
    let split = raw.len() - 4;
    let payload = &raw[..split];
    let provided = &raw[split..];

    let computed = double_sha256(payload);
    if computed[0..4] != *provided {
        return Err(Base58CheckError::ChecksumMismatch);
    }
    Ok(payload.to_vec())
}

/// Decode a `T…` address into a typed [`Address`]. Errors if the decoded
/// payload isn't exactly 21 bytes.
pub fn decode_address(s: &str) -> Result<Address, Base58CheckError> {
    let bytes = decode_check(s)?;
    if bytes.len() != ADDRESS_LENGTH {
        return Err(Base58CheckError::WrongPayloadLength {
            got: bytes.len(),
            expected: ADDRESS_LENGTH,
        });
    }
    let mut buf = [0u8; ADDRESS_LENGTH];
    buf.copy_from_slice(&bytes);
    Ok(Address::from_raw(buf))
}

/// Encode an [`Address`] as a user-facing `T…` string.
pub fn encode_address(addr: &Address) -> String {
    encode_check(addr.as_bytes())
}

fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first: [u8; 32] = sha2::Sha256::new().chain_update(data).finalize().into();
    sha2::Sha256::new().chain_update(first).finalize().into()
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Base58CheckError {
    #[error("base58 decode error: {0}")]
    Base58(String),
    #[error("input too short to contain a checksum")]
    TooShort,
    #[error("checksum mismatch")]
    ChecksumMismatch,
    #[error("wrong payload length: got {got}, expected {expected}")]
    WrongPayloadLength { got: usize, expected: usize },
}
