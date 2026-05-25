//! Tests for the SM2 signing module.

use tron_crypto::{sm2_verify, Sm2Error, Sm2Key};

fn make_seeded_key(seed: u8) -> Sm2Key {
    let mut bytes = [0u8; 32];
    bytes[0] = 0x01; // ensure non-zero high byte to stay within scalar field
    bytes[31] = seed;
    Sm2Key::from_bytes(&bytes).expect("seeded scalar should be valid")
}

#[test]
fn sm2_sign_then_verify_round_trips() {
    let key = make_seeded_key(0x42);
    let msg = b"hello tron from sm2";
    let sig = key.sign(msg);
    let pk = key.pubkey_uncompressed();

    sm2_verify(&pk, msg, &sig).expect("freshly produced signature must verify");
}

#[test]
fn sm2_verify_rejects_wrong_message() {
    let key = make_seeded_key(0x42);
    let sig = key.sign(b"original message");
    let pk = key.pubkey_uncompressed();

    let err = sm2_verify(&pk, b"different message", &sig).unwrap_err();
    assert_eq!(err, Sm2Error::VerificationFailed);
}

#[test]
fn sm2_verify_rejects_signature_from_other_key() {
    let key_a = make_seeded_key(1);
    let key_b = make_seeded_key(2);
    let msg = b"some payload";
    let sig_a = key_a.sign(msg);
    let pk_b = key_b.pubkey_uncompressed();

    // Signature made by A should NOT verify against B's pubkey.
    let err = sm2_verify(&pk_b, msg, &sig_a).unwrap_err();
    assert_eq!(err, Sm2Error::VerificationFailed);
}

#[test]
fn sm2_pubkey_is_65_byte_sec1_uncompressed() {
    let key = make_seeded_key(0x10);
    let pk = key.pubkey_uncompressed();
    assert_eq!(pk.len(), 65);
    assert_eq!(pk[0], 0x04, "SEC1 uncompressed prefix");
}

#[test]
fn sm2_address_has_mainnet_prefix_and_21_bytes() {
    let key = make_seeded_key(0x77);
    let addr = key.address();
    assert_eq!(addr.as_bytes().len(), 21);
    assert_eq!(addr.as_bytes()[0], 0x41);
}

#[test]
fn sm2_address_matches_keccak_derivation() {
    let key = make_seeded_key(0x77);
    let pk = key.pubkey_uncompressed();
    let h = tron_crypto::hash::keccak256(&pk[1..]);
    let mut expected = [0u8; 21];
    expected[0] = 0x41;
    expected[1..].copy_from_slice(&h[12..]);
    assert_eq!(key.address().as_bytes(), &expected);
}

#[test]
fn sm2_from_bytes_rejects_zero_scalar() {
    let zero = [0u8; 32];
    let err = Sm2Key::from_bytes(&zero).unwrap_err();
    assert_eq!(err, Sm2Error::InvalidPrivateKey);
}

#[test]
fn sm2_signature_is_64_bytes() {
    let key = make_seeded_key(0x55);
    let sig = key.sign(b"x");
    assert_eq!(sig.len(), 64);
}
