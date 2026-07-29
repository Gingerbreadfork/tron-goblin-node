//! Transaction signing — the operation every wallet and SR performs.
//!
//! Recipe (matches `TransactionCapsule.sign` in java-tron):
//!
//! 1. Compute the transaction id: `sha256(transaction.raw_data.encode())`.
//! 2. Sign the id with recoverable ECDSA (low-S canonical, RFC 6979 nonces).
//! 3. Append the signature bytes to `transaction.signature` (a `repeated bytes`
//!    field — multi-sig appends multiple).
//!
//! The on-the-wire signature layout is `[r(32) || s(32) || v(1)]` with `v`
//! ∈ {0, 1, 2, 3} — see [`tron_crypto::signature::RecoverableSignature::to_bytes`].
//!
//! Verification: recover the public key from the signature + tx id and
//! derive its address. Compare to the expected signer.

use prost::Message;
use tron_crypto::address::Address;
use tron_crypto::signature::{RecoverableSignature, SigError};
use tron_proto::Transaction;

use crate::tx_id::{tx_id, TxIdError};

/// Sign `transaction` with `priv_key` and append the signature.
///
/// The transaction's existing signatures (if any) are preserved — this
/// matches `TransactionCapsule.sign`, which calls `addSignature` rather
/// than replacing. Multi-sig transactions accumulate signatures by
/// calling this once per signer.
pub fn sign_transaction(
    transaction: &mut Transaction,
    priv_key: &[u8; 32],
) -> Result<RecoverableSignature, SignError> {
    let id = tx_id(transaction).map_err(SignError::TxId)?;
    let sig = RecoverableSignature::sign_prehash(priv_key, &id).map_err(SignError::Sig)?;
    transaction.signature.push(sig.to_bytes().to_vec());
    Ok(sig)
}

/// Recover the signer's [`Address`] from the first signature on this
/// transaction. Returns `Err` if the transaction has no signature or
/// the signature bytes don't decode.
pub fn recover_signer_address(transaction: &Transaction) -> Result<Address, SignError> {
    let sig_bytes = transaction
        .signature
        .first()
        .ok_or(SignError::MissingSignature)?;
    let sig = RecoverableSignature::from_bytes(sig_bytes).map_err(SignError::Sig)?;
    let id = tx_id(transaction).map_err(SignError::TxId)?;
    let pubkey = sig.recover_uncompressed_pubkey(&id).map_err(SignError::Sig)?;
    Address::from_uncompressed_pubkey(&pubkey).map_err(|e| SignError::Address(e.to_string()))
}

/// Recover all signers (one per attached signature). Order matches the
/// `signature` field. Useful for multi-sig validation.
///
/// The recovery preimage is the prost re-encode tx id ([`tx_id`]), which
/// silently drops unknown `raw_data` fields the original wire bytes may
/// have carried. When the original bytes (or a wire-derived id) are
/// available, use [`recover_all_signers_with_id`] instead — java-tron
/// verifies signatures against `sha256(getRawData().toByteArray())`,
/// which preserves those bytes.
pub fn recover_all_signers(transaction: &Transaction) -> Result<Vec<Address>, SignError> {
    let id = tx_id(transaction).map_err(SignError::TxId)?;
    recover_all_signers_with_id(transaction, &id)
}

/// [`recover_all_signers`] against a caller-supplied transaction id —
/// the signing preimage. Callers holding the transaction's ORIGINAL
/// wire bytes derive `id` via [`crate::tx_id_from_tx_bytes`] so the
/// recovery preimage matches java byte-for-byte even when `raw_data`
/// carries unknown fields a prost re-encode would drop.
pub fn recover_all_signers_with_id(
    transaction: &Transaction,
    id: &[u8; 32],
) -> Result<Vec<Address>, SignError> {
    let mut out = Vec::with_capacity(transaction.signature.len());
    for sig_bytes in &transaction.signature {
        let sig = RecoverableSignature::from_bytes(sig_bytes).map_err(SignError::Sig)?;
        let pubkey = sig.recover_uncompressed_pubkey(id).map_err(SignError::Sig)?;
        out.push(Address::from_uncompressed_pubkey(&pubkey).map_err(|e| SignError::Address(e.to_string()))?);
    }
    Ok(out)
}

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("transaction id error: {0}")]
    TxId(#[from] TxIdError),
    #[error("signature error: {0}")]
    Sig(#[from] SigError),
    #[error("transaction has no signature attached")]
    MissingSignature,
    #[error("address derivation: {0}")]
    Address(String),
}

/// `Message::clone` for downstream callers that don't want to pull in
/// the `prost` trait. Re-exported here so tests can compute a tx id over
/// a freshly-cloned mutable transaction.
pub fn clone_transaction(t: &Transaction) -> Transaction {
    let bytes = t.encode_to_vec();
    Transaction::decode(bytes.as_slice()).expect("re-decoding our own encoding")
}

#[cfg(test)]
mod preimage_tests {
    use super::*;
    use tron_crypto::signature::RecoverableSignature;

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    /// Real mainnet vector — a DelegateResourceContract whose raw_data ends
    /// with an unknown varint field (`a0 01 03`). The same signature recovers
    /// the permission's key over the id of the ORIGINAL raw_data bytes, but a
    /// different (garbage) address over the id of the prost re-encode that
    /// drops the field.
    #[test]
    fn recovery_preimage_decides_the_signer_mainnet_vector() {
        let sig_bytes = hex::decode(
            "61d4e42c1d985ee6bbc734f5832539056334a013b520a254c9761141d2c9bdd9\
             21473b744cc97cb1d93402151b9dfbab38a8361e13704f32865f4731ac30e5b5\
             01",
        )
        .unwrap();
        let sig = RecoverableSignature::from_bytes(&sig_bytes).unwrap();

        // sha256(original raw_data) — the REAL mainnet txID.
        let wire_id = hex32("d8c3ccf62767660c560fb179f60e1b7978474c2ef80976703bd29a9bc05fc714");
        // sha256(raw_data with the 3 trailing unknown bytes dropped) — the
        // prost re-encode id.
        let reencode_id = hex32("1021e5a8a62f5d98a429d42e3a65d52b1a2ec1a55c479a83c11a518bdcc12bc2");

        let addr_for = |id: &[u8; 32]| {
            let pk = sig.recover_uncompressed_pubkey(id).unwrap();
            Address::from_uncompressed_pubkey(&pk).unwrap()
        };
        // Original-bytes preimage → the permission's actual key (java SUCCESS).
        assert_eq!(
            hex::encode(addr_for(&wire_id).as_bytes()),
            "414cde0d40b465ed8c1cf95e2bdca990c74b3562be"
        );
        // Re-encode preimage → a different (garbage) signer. Only the prefix
        // is pinned; the inequality is the point.
        let bogus = addr_for(&reencode_id);
        assert_ne!(bogus.as_bytes()[..], addr_for(&wire_id).as_bytes()[..]);
        assert_eq!(&bogus.as_bytes()[..4], &[0x41, 0x07, 0xbf, 0x0c]);
    }
}
