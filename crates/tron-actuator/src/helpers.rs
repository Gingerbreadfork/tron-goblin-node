//! Shared helpers used across every actuator.
//!
//! Address decoding, balance arithmetic, and store-error conversion live
//! here so per-actuator files stay focused on their specific rules.

use tron_crypto::address::{Address, ADDRESS_LENGTH, ADDRESS_PREFIX_MAINNET};

use crate::ActuatorError;

/// Validate that `bytes` is a 21-byte address with the mainnet `0x41`
/// prefix and return the typed [`Address`].
pub fn decode_address(bytes: &[u8]) -> Option<Address> {
    if bytes.len() != ADDRESS_LENGTH || bytes[0] != ADDRESS_PREFIX_MAINNET {
        return None;
    }
    let mut buf = [0u8; ADDRESS_LENGTH];
    buf.copy_from_slice(bytes);
    Some(Address::from_raw(buf))
}

/// Same, but as a `Result` with a contextual error tag (`"owner"`, `"to"`,
/// etc.). Returns either `InvalidOwnerAddress`, `InvalidToAddress`, or a
/// generic `InvalidAddress`.
pub fn require_owner(bytes: &[u8]) -> Result<Address, ActuatorError> {
    decode_address(bytes).ok_or(ActuatorError::InvalidOwnerAddress)
}

pub fn require_to(bytes: &[u8]) -> Result<Address, ActuatorError> {
    decode_address(bytes).ok_or(ActuatorError::InvalidToAddress)
}

pub fn require_address(bytes: &[u8]) -> Result<Address, ActuatorError> {
    decode_address(bytes).ok_or(ActuatorError::InvalidAddress)
}

/// Checked add returning [`ActuatorError::Overflow`].
#[inline]
pub fn check_add(a: i64, b: i64) -> Result<i64, ActuatorError> {
    a.checked_add(b).ok_or(ActuatorError::Overflow)
}

/// Checked subtract returning [`ActuatorError::Overflow`].
#[inline]
pub fn check_sub(a: i64, b: i64) -> Result<i64, ActuatorError> {
    a.checked_sub(b).ok_or(ActuatorError::Overflow)
}

/// Checked multiply returning [`ActuatorError::Overflow`].
#[inline]
pub fn check_mul(a: i64, b: i64) -> Result<i64, ActuatorError> {
    a.checked_mul(b).ok_or(ActuatorError::Overflow)
}
