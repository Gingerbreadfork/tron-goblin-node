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
pub fn recover_all_signers(transaction: &Transaction) -> Result<Vec<Address>, SignError> {
    let id = tx_id(transaction).map_err(SignError::TxId)?;
    let mut out = Vec::with_capacity(transaction.signature.len());
    for sig_bytes in &transaction.signature {
        let sig = RecoverableSignature::from_bytes(sig_bytes).map_err(SignError::Sig)?;
        let pubkey = sig.recover_uncompressed_pubkey(&id).map_err(SignError::Sig)?;
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
