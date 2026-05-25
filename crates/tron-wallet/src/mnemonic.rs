//! BIP-39 mnemonic generation + seed derivation.
//!
//! Wraps the `bip39` crate with TRON-shaped defaults so callers can
//! generate a 12- or 24-word English mnemonic, derive the 64-byte
//! seed bytes (with optional passphrase), and round-trip through
//! string form for paper-backup and wallet-cli compatibility.
//!
//! BIP-32 HD-derivation on top of the seed is a separate module
//! (`hd_derive.rs`) — also a follow-up.
//!
//! All public API uses `&str` for the phrase, which is the canonical
//! human-readable form, and `&[u8]` for the seed. Errors funnel into
//! [`MnemonicError`].

use bip39::{Language, Mnemonic};

/// 12 or 24 — the two word counts every TRON wallet UI offers.
#[derive(Debug, Clone, Copy)]
pub enum WordCount {
    Twelve,
    TwentyFour,
}

impl WordCount {
    fn entropy_bytes(self) -> usize {
        match self {
            // 128 bits → 12 words; 256 bits → 24 words. Standard BIP-39.
            WordCount::Twelve => 16,
            WordCount::TwentyFour => 32,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MnemonicError {
    #[error("os random failed: {0}")]
    Random(String),
    #[error("invalid phrase: {0}")]
    InvalidPhrase(String),
}

/// Generate a fresh English mnemonic of the requested word count.
/// Uses OS randomness via `getrandom`; never `rand::thread_rng()` so
/// the produced phrase is suitable for real-money keys.
pub fn generate(words: WordCount) -> Result<String, MnemonicError> {
    let mut entropy = vec![0u8; words.entropy_bytes()];
    getrandom::getrandom(&mut entropy).map_err(|e| MnemonicError::Random(e.to_string()))?;
    let m = Mnemonic::from_entropy_in(Language::English, &entropy)
        .map_err(|e| MnemonicError::InvalidPhrase(e.to_string()))?;
    Ok(m.to_string())
}

/// Validate a user-supplied mnemonic phrase. Returns `Ok(())` if every
/// word is in the English BIP-39 wordlist AND the checksum matches.
pub fn validate(phrase: &str) -> Result<(), MnemonicError> {
    Mnemonic::parse_in(Language::English, phrase.trim())
        .map(|_| ())
        .map_err(|e| MnemonicError::InvalidPhrase(e.to_string()))
}

/// Derive the BIP-39 seed bytes for `phrase`. Passphrase is the
/// optional 25th word — empty string is the common case. The result
/// is the 64-byte input every BIP-32 HD derivation starts from.
pub fn to_seed(phrase: &str, passphrase: &str) -> Result<[u8; 64], MnemonicError> {
    let m = Mnemonic::parse_in(Language::English, phrase.trim())
        .map_err(|e| MnemonicError::InvalidPhrase(e.to_string()))?;
    Ok(m.to_seed(passphrase))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_phrases_round_trip_through_validate() {
        let phrase = generate(WordCount::Twelve).expect("generate");
        assert_eq!(phrase.split_whitespace().count(), 12);
        validate(&phrase).expect("validate own phrase");

        let long = generate(WordCount::TwentyFour).expect("generate 24");
        assert_eq!(long.split_whitespace().count(), 24);
        validate(&long).expect("validate 24-word phrase");
    }

    #[test]
    fn validate_rejects_obvious_bad_input() {
        assert!(validate("foo bar baz").is_err(), "non-wordlist words rejected");
        assert!(validate("").is_err(), "empty rejected");
        // Wrong checksum (12 valid words but mis-ordered).
        assert!(
            validate("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zoo")
                .is_err(),
            "wrong checksum rejected"
        );
    }

    /// BIP-39 test vector: 12 zeros → known seed. Pins our seed
    /// derivation against the spec — same vector every BIP-39 library
    /// uses for testing.
    #[test]
    fn known_zero_phrase_derives_expected_seed() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = to_seed(phrase, "").unwrap();
        // From the BIP-39 spec's English test vectors.
        let expected_hex = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
                           9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
        assert_eq!(hex::encode(seed), expected_hex);
    }

    #[test]
    fn passphrase_changes_seed() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let bare = to_seed(phrase, "").unwrap();
        let with_pw = to_seed(phrase, "test password").unwrap();
        assert_ne!(bare, with_pw, "passphrase must affect derived seed");
    }
}
