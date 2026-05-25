//! Recoverable ECDSA over secp256k1 matching java-tron's `ECKey.ECDSASignature`.
//!
//! Two byte-order conventions exist in java-tron and we expose both:
//!
//! * **Transaction-on-chain layout** (`to_bytes` / `from_bytes`): `[r(32) || s(32) || v(1)]`
//!   with `v ∈ {0, 1, 2, 3}` — the raw recovery id. This is what
//!   `ECDSASignature.toByteArray()` produces and what gets stored on-chain.
//! * **Header-prefix layout** (`to_header_prefix_bytes` / `from_header_prefix_bytes`):
//!   `[v(1) || r(32) || s(32)]` with `v ∈ {27..30}` — the "Bitcoin-message"
//!   convention. Used by `signatureToKeyBytes(messageHash, signatureBase64)`.
//!
//! Both layouts share the same `(r, s, recovery_id)` triple internally.
//!
//! TRON does **not** apply EIP-155 chain-id mixing to the recovery byte.

use ecdsa::hazmat::SignPrimitive;
use ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};

/// secp256k1 curve order N.
const SECP256K1_N_HEX: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

/// `27` — the offset applied to recovery id in the header-prefix layout.
pub const HEADER_PREFIX_BASE: u8 = 27;

/// 65 bytes: `[r(32) || s(32) || v(1)]`.
pub const SIGNATURE_BYTES: usize = 65;

/// A recoverable ECDSA signature over secp256k1.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RecoverableSignature {
    /// 32-byte r component.
    pub r: [u8; 32],
    /// 32-byte s component (low-S canonical: s ≤ N/2).
    pub s: [u8; 32],
    /// Recovery id ∈ {0, 1, 2, 3}.
    pub recovery_id: u8,
}

impl RecoverableSignature {
    /// Sign a 32-byte digest with `priv_key`, using RFC 6979 deterministic nonces
    /// and low-S canonicalisation. Matches `ECKey.doSign` + `sign`.
    pub fn sign_prehash(priv_key: &[u8; 32], prehash: &[u8; 32]) -> Result<Self, SigError> {
        let signing_key = SigningKey::from_bytes(priv_key.into())
            .map_err(|_| SigError::InvalidPrivateKey)?;

        let secret_scalar = signing_key.as_nonzero_scalar();
        let (sig, recid) = secret_scalar
            .try_sign_prehashed_rfc6979::<sha2::Sha256>(prehash.into(), &[])
            .map_err(|_| SigError::SigningFailed)?;

        // Low-S canonicalisation (RustCrypto already enforces this in
        // `try_sign_prehashed_rfc6979`, but we double-check and flip the
        // recovery bit if needed for safety).
        let (sig, recid) = match sig.normalize_s() {
            Some(normalized) => {
                // Normalisation flipped s; flip the parity bit of the rec id.
                let rid = recid.ok_or(SigError::SigningFailed)?;
                let flipped = RecoveryId::from_byte(rid.to_byte() ^ 1)
                    .ok_or(SigError::SigningFailed)?;
                (normalized, flipped)
            }
            None => (sig, recid.ok_or(SigError::SigningFailed)?),
        };

        let bytes = sig.to_bytes();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[0..32]);
        s.copy_from_slice(&bytes[32..64]);

        Ok(Self {
            r,
            s,
            recovery_id: recid.to_byte(),
        })
    }

    /// Recover the SEC1-uncompressed (65-byte, `0x04`-prefixed) public key
    /// from this signature and the message digest. Matches
    /// `ECKey.recoverPubBytesFromSignature`.
    pub fn recover_uncompressed_pubkey(&self, prehash: &[u8; 32]) -> Result<[u8; 65], SigError> {
        let mut sig_bytes = [0u8; 64];
        sig_bytes[0..32].copy_from_slice(&self.r);
        sig_bytes[32..64].copy_from_slice(&self.s);
        let sig = Signature::from_slice(&sig_bytes).map_err(|_| SigError::InvalidSignature)?;
        let recid =
            RecoveryId::from_byte(self.recovery_id).ok_or(SigError::InvalidRecoveryId)?;

        let vk = VerifyingKey::recover_from_prehash(prehash, &sig, recid)
            .map_err(|_| SigError::RecoveryFailed)?;

        let encoded = vk.to_encoded_point(false);
        let bytes = encoded.as_bytes();
        if bytes.len() != 65 {
            return Err(SigError::RecoveryFailed);
        }
        let mut out = [0u8; 65];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    /// Verify a signature against a known public key and prehash. Useful for
    /// tests; production code generally recovers the address and compares.
    pub fn verify_prehash(
        &self,
        pubkey_uncompressed: &[u8; 65],
        prehash: &[u8; 32],
    ) -> Result<(), SigError> {
        let vk = VerifyingKey::from_sec1_bytes(pubkey_uncompressed)
            .map_err(|_| SigError::InvalidPublicKey)?;
        let mut sig_bytes = [0u8; 64];
        sig_bytes[0..32].copy_from_slice(&self.r);
        sig_bytes[32..64].copy_from_slice(&self.s);
        let sig = Signature::from_slice(&sig_bytes).map_err(|_| SigError::InvalidSignature)?;
        vk.verify_prehash(prehash, &sig)
            .map_err(|_| SigError::VerificationFailed)
    }

    /// Encode in the **on-chain transaction layout**: `[r(32) || s(32) || v(1)]`
    /// where `v` is the raw recovery id (0..3). Matches `ECDSASignature.toByteArray`.
    pub fn to_bytes(&self) -> [u8; SIGNATURE_BYTES] {
        let mut out = [0u8; SIGNATURE_BYTES];
        out[0..32].copy_from_slice(&self.r);
        out[32..64].copy_from_slice(&self.s);
        out[64] = self.recovery_id;
        out
    }

    /// Decode from the on-chain transaction layout.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SigError> {
        if bytes.len() != SIGNATURE_BYTES {
            return Err(SigError::InvalidSignature);
        }
        // java-tron's `ECDSASignature.toByteArray` normalises v by subtracting
        // 27 if it was in the header-prefix range, so on the wire we can see
        // either 0..3 (canonical) or 27..30 (legacy). Accept both.
        let raw_v = bytes[64];
        let recovery_id = if raw_v >= HEADER_PREFIX_BASE {
            // Same "subtract 4 if >= 31" trick that ECKey.signatureToKeyBytes uses
            // for the compressed-pubkey marker. recId always ends up in 0..3.
            let normalised = if raw_v >= HEADER_PREFIX_BASE + 4 {
                raw_v - 4
            } else {
                raw_v
            };
            normalised - HEADER_PREFIX_BASE
        } else {
            raw_v
        };
        if recovery_id > 3 {
            return Err(SigError::InvalidRecoveryId);
        }
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[0..32]);
        s.copy_from_slice(&bytes[32..64]);
        Ok(Self {
            r,
            s,
            recovery_id,
        })
    }

    /// Encode in the **header-prefix layout**: `[v(1) || r(32) || s(32)]`
    /// with `v ∈ {27..30}`. Matches `ECDSASignature.toBase64` (pre-Base64).
    pub fn to_header_prefix_bytes(&self) -> [u8; SIGNATURE_BYTES] {
        let mut out = [0u8; SIGNATURE_BYTES];
        out[0] = self.recovery_id + HEADER_PREFIX_BASE;
        out[1..33].copy_from_slice(&self.r);
        out[33..65].copy_from_slice(&self.s);
        out
    }

    /// Decode from the header-prefix layout.
    pub fn from_header_prefix_bytes(bytes: &[u8]) -> Result<Self, SigError> {
        if bytes.len() != SIGNATURE_BYTES {
            return Err(SigError::InvalidSignature);
        }
        // Header byte: see ECKey.signatureToKeyBytes — valid range 27..=34,
        // values 31..=34 indicate a compressed pubkey marker (subtract 4).
        let raw_v = bytes[0];
        if !(HEADER_PREFIX_BASE..=HEADER_PREFIX_BASE + 7).contains(&raw_v) {
            return Err(SigError::InvalidHeaderByte(raw_v));
        }
        let normalised = if raw_v >= HEADER_PREFIX_BASE + 4 {
            raw_v - 4
        } else {
            raw_v
        };
        let recovery_id = normalised - HEADER_PREFIX_BASE;
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[1..33]);
        s.copy_from_slice(&bytes[33..65]);
        Ok(Self {
            r,
            s,
            recovery_id,
        })
    }

    /// Returns true if `(r, s)` are canonical: `1 ≤ r,s < N` and `s ≤ N/2`.
    pub fn is_canonical(&self) -> bool {
        let n = secp256k1_n();
        let half_n = secp256k1_half_n();
        let r_big = u256_be(&self.r);
        let s_big = u256_be(&self.s);
        !u256_is_zero(&r_big)
            && !u256_is_zero(&s_big)
            && u256_lt(&r_big, &n)
            && u256_lt(&s_big, &n)
            && !u256_gt(&s_big, &half_n)
    }
}

impl core::fmt::Debug for RecoverableSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "RecoverableSignature {{ r: 0x{}, s: 0x{}, v: {} }}",
            hex::encode(self.r),
            hex::encode(self.s),
            self.recovery_id
        )
    }
}

/// Derive the SEC1-uncompressed (65-byte, `0x04`-prefixed) public key
/// from a 32-byte private key. Used by the wallet CLI to print an
/// address without first having to sign anything.
pub fn public_key_from_private(priv_key: &[u8; 32]) -> Result<[u8; 65], SigError> {
    let signing_key = SigningKey::from_bytes(priv_key.into())
        .map_err(|_| SigError::InvalidPrivateKey)?;
    let vk = signing_key.verifying_key();
    let encoded = vk.to_encoded_point(false);
    let bytes = encoded.as_bytes();
    if bytes.len() != 65 {
        return Err(SigError::InvalidPublicKey);
    }
    let mut out = [0u8; 65];
    out.copy_from_slice(bytes);
    Ok(out)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SigError {
    #[error("invalid private key")]
    InvalidPrivateKey,
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("invalid signature encoding")]
    InvalidSignature,
    #[error("invalid recovery id (must be 0..=3)")]
    InvalidRecoveryId,
    #[error("invalid header byte: 0x{0:02x} (expected 27..=34)")]
    InvalidHeaderByte(u8),
    #[error("signing failed")]
    SigningFailed,
    #[error("pubkey recovery failed")]
    RecoveryFailed,
    #[error("signature verification failed")]
    VerificationFailed,
}

// --- Big-endian 256-bit comparison helpers (no extra deps) ------------------

fn secp256k1_n() -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(SECP256K1_N_HEX, &mut out).expect("static hex");
    out
}

fn secp256k1_half_n() -> [u8; 32] {
    let n = secp256k1_n();
    shr1_be(&n)
}

#[inline]
fn u256_be(b: &[u8; 32]) -> [u8; 32] {
    *b
}

fn u256_is_zero(a: &[u8; 32]) -> bool {
    a.iter().all(|&x| x == 0)
}

fn u256_lt(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

fn u256_gt(a: &[u8; 32], b: &[u8; 32]) -> bool {
    u256_lt(b, a)
}

fn shr1_be(a: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry: u8 = 0;
    for i in 0..32 {
        let v = a[i];
        out[i] = (carry << 7) | (v >> 1);
        carry = v & 1;
    }
    out
}
