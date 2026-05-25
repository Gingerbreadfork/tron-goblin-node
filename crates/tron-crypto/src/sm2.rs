//! SM2 signature support (Chinese national standard GM/T 0003-2012).
//!
//! TRON exposes SM2 as an optional alternative to secp256k1 for the
//! transaction signing path. Use cases include domestic Chinese
//! deployments + dApps that must comply with Cryptography Law.
//!
//! Backed by RustCrypto's `sm2` crate — pure Rust, no FFI, same
//! maintainer org as our `k256` dep. **Status**: signature + verify
//! work; address derivation from an SM2 public key follows the same
//! `keccak256(uncompressed_pubkey[1..])[12..]` rule as ECDSA (the
//! 20-byte payload that becomes the TRON address suffix).
//!
//! What's *not* exposed:
//! * SM2 key exchange (KX) — not used in TRON's signing path
//! * SM2 encryption — TRON only signs transactions; it doesn't encrypt
//!   transaction bodies
//! * Recoverable signatures — SM2 DSA doesn't define a recovery byte
//!   the way secp256k1 does, so the verifier must already know the
//!   signer's public key. TRON's SM2 path attaches the pubkey to the
//!   transaction or resolves it from an account record.

use sm2::dsa::signature::{Signer, Verifier};
use sm2::dsa::{Signature, SigningKey, VerifyingKey};
use thiserror::Error;

use crate::address::Address;
use crate::hash::keccak256;

/// SM2-signing private key. Wraps `sm2::dsa::SigningKey` with the
/// signer's "distinguishing identifier" (Z value); TRON convention is
/// to use an empty user-id for transaction signatures, matching
/// java-tron's `SM2Signer.DEFAULT_USER_ID`.
#[derive(Debug)]
pub struct Sm2Key {
    inner: SigningKey,
}

/// TRON's default SM2 user identifier — the GM/T 0009-2012 default
/// `"1234567812345678"`. Same string java-tron's SM2Signer uses unless
/// the caller overrides it. The `sm2` crate types this as `&str`.
pub const TRON_SM2_USER_ID: &str = "1234567812345678";

impl Sm2Key {
    /// Build a key from a 32-byte private scalar. The scalar must be a
    /// valid element of the SM2 curve's scalar field.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Sm2Error> {
        let inner = SigningKey::from_slice(TRON_SM2_USER_ID, bytes)
            .map_err(|_| Sm2Error::InvalidPrivateKey)?;
        Ok(Self { inner })
    }

    /// Sign `msg` using SM2 DSA. The signature includes the standard
    /// SM2 pre-processing (Z value computed from the user id + public
    /// key), so the verifier needs the same user id (see
    /// [`TRON_SM2_USER_ID`]) and public key.
    ///
    /// Returns the 64-byte `(r || s)` encoding.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let sig: Signature = self.inner.sign(msg);
        let bytes = sig.to_bytes();
        let mut out = [0u8; 64];
        out.copy_from_slice(&bytes);
        out
    }

    /// 65-byte SEC1 uncompressed pubkey (`0x04 || X || Y`). Used both
    /// for verification and to derive the TRON address (see
    /// [`Sm2Key::address`]).
    pub fn pubkey_uncompressed(&self) -> [u8; 65] {
        let vk = self.inner.verifying_key();
        let pk: sm2::PublicKey = vk.into();
        let enc = pk.to_sec1_bytes();
        debug_assert_eq!(enc.len(), 65, "SM2 SEC1 uncompressed pubkey is always 65 bytes");
        let mut out = [0u8; 65];
        out.copy_from_slice(&enc);
        out
    }

    /// Derive the TRON address from this SM2 key. Uses the same
    /// `keccak256(uncompressed_pubkey[1..])[12..]` rule as ECDSA:
    /// strip the SEC1 `0x04` byte, hash, take the low 20 bytes,
    /// prepend the mainnet `0x41` prefix.
    pub fn address(&self) -> Address {
        let pk = self.pubkey_uncompressed();
        let h = keccak256(&pk[1..]);
        let mut bytes = [0u8; 21];
        bytes[0] = 0x41;
        bytes[1..].copy_from_slice(&h[12..]);
        Address::from_raw(bytes)
    }
}

/// Verify an SM2 signature against a SEC1-uncompressed public key.
///
/// `sig` is the 64-byte `(r || s)` from [`Sm2Key::sign`]. Returns `Ok`
/// on a valid signature.
pub fn verify(pubkey_uncompressed: &[u8; 65], msg: &[u8], sig: &[u8; 64]) -> Result<(), Sm2Error> {
    let pk = sm2::PublicKey::from_sec1_bytes(pubkey_uncompressed)
        .map_err(|_| Sm2Error::InvalidPublicKey)?;
    let vk = VerifyingKey::new(TRON_SM2_USER_ID, pk).map_err(|_| Sm2Error::InvalidPublicKey)?;
    let signature = Signature::from_slice(sig).map_err(|_| Sm2Error::InvalidSignature)?;
    vk.verify(msg, &signature)
        .map_err(|_| Sm2Error::VerificationFailed)
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Sm2Error {
    #[error("private key bytes do not form a valid SM2 scalar")]
    InvalidPrivateKey,
    #[error("public key bytes do not decode as a valid SM2 point")]
    InvalidPublicKey,
    #[error("signature bytes malformed (expected 64 bytes r||s)")]
    InvalidSignature,
    #[error("SM2 signature verification failed")]
    VerificationFailed,
}
