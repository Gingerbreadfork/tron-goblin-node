//! V3 keystore JSON: encrypt a 32-byte secp256k1 private key under a
//! user-chosen password.
//!
//! Wire format matches java-tron's `Wallet.java` (which itself is the
//! Web3 Secret Storage Definition v3). Two KDFs supported on read:
//! `scrypt` (default; java-tron writes this) and `pbkdf2`. We always
//! write `scrypt`.
//!
//! ## Encryption recipe
//!
//! 1. `derived = scrypt(password, salt, n=131072, r=8, p=1, dklen=32)`
//!    or `pbkdf2_hmac_sha256(password, salt, c, dklen=32)`.
//! 2. `cipher_key = derived[..16]`, `mac_key = derived[16..32]`.
//! 3. `ciphertext = AES-128-CTR(cipher_key, iv, private_key)`.
//! 4. `mac = keccak256(mac_key || ciphertext)`.
//!
//! ## Decryption
//!
//! 1. Re-derive `derived` from password + stored salt + stored
//!    KDF params.
//! 2. Recompute `mac` and compare against the stored value. **Constant-
//!    time** compare to avoid leaking how-much-was-correct via timing.
//! 3. Decrypt the ciphertext under `derived[..16]` + the stored IV.

use aes::cipher::{KeyIvInit, StreamCipher};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type Aes128Ctr = ctr::Ctr64BE<aes::Aes128>;

/// Top-level keystore file. `serde` (de)serialization gives us the
/// canonical JSON shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Keystore {
    /// TRON address in Base58Check (`T...`) form. java-tron writes
    /// this here (not hex), and we mirror it.
    pub address: String,
    /// Crypto envelope.
    pub crypto: Crypto,
    /// File id (uuid v4). Not consensus-meaningful; helps the user
    /// distinguish multiple keystores in the same directory.
    pub id: String,
    /// Spec version. We only write v3; older versions are rejected.
    pub version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Crypto {
    pub cipher: String,
    pub ciphertext: String,
    pub cipherparams: CipherParams,
    pub kdf: String,
    pub kdfparams: KdfParams,
    pub mac: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherParams {
    pub iv: String,
}

/// KDF parameters, tagged by the surrounding `kdf` field. We
/// deserialize via `serde(untagged)` so the same struct works for both.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum KdfParams {
    Scrypt(ScryptParams),
    Pbkdf2(Pbkdf2Params),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScryptParams {
    pub dklen: u32,
    pub n: u32,
    pub p: u32,
    pub r: u32,
    pub salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pbkdf2Params {
    pub dklen: u32,
    pub c: u32,
    pub prf: String,
    pub salt: String,
}

/// Default scrypt parameters — match java-tron's
/// `Wallet.java` "standard" defaults.
pub const STANDARD_SCRYPT_N: u32 = 1 << 18;
pub const STANDARD_SCRYPT_R: u32 = 8;
pub const STANDARD_SCRYPT_P: u32 = 1;
pub const DKLEN: u32 = 32;

/// "Light" scrypt parameters — much faster (~10ms vs ~1s) at the cost
/// of a smaller memory wall against brute force. Use for tests; the
/// CLI's `--light` flag selects this profile.
pub const LIGHT_SCRYPT_N: u32 = 1 << 12;

impl Keystore {
    /// Encrypt `private_key` under `password` using scrypt + AES-128-CTR.
    ///
    /// `n_log2` is the log2 of the scrypt N parameter. Use
    /// `log2(STANDARD_SCRYPT_N) = 18` for production-grade defaults,
    /// or `log2(LIGHT_SCRYPT_N) = 12` for fast tests.
    pub fn create(
        private_key: &[u8; 32],
        password: &str,
        address_base58: &str,
        n_log2: u8,
    ) -> Result<Self, KeystoreError> {
        let mut salt = [0u8; 32];
        getrandom::getrandom(&mut salt).map_err(|e| KeystoreError::Rng(format!("{e}")))?;
        let mut iv = [0u8; 16];
        getrandom::getrandom(&mut iv).map_err(|e| KeystoreError::Rng(format!("{e}")))?;

        let n = 1u32 << n_log2;
        let derived = scrypt_derive(password.as_bytes(), &salt, n_log2, STANDARD_SCRYPT_R, STANDARD_SCRYPT_P)?;
        let cipher_key: &[u8; 16] = derived[..16].try_into().expect("32-byte derived");
        let mac_key = &derived[16..32];

        // AES-128-CTR encrypt the private key in place.
        let mut ciphertext = *private_key;
        let mut cipher = Aes128Ctr::new(cipher_key.into(), (&iv).into());
        cipher.apply_keystream(&mut ciphertext);

        // mac = keccak256(mac_key || ciphertext)
        let mut mac_input = Vec::with_capacity(16 + 32);
        mac_input.extend_from_slice(mac_key);
        mac_input.extend_from_slice(&ciphertext);
        let mac = tron_crypto::hash::keccak256(&mac_input);

        Ok(Self {
            address: address_base58.to_string(),
            crypto: Crypto {
                cipher: "aes-128-ctr".into(),
                ciphertext: hex::encode(ciphertext),
                cipherparams: CipherParams {
                    iv: hex::encode(iv),
                },
                kdf: "scrypt".into(),
                kdfparams: KdfParams::Scrypt(ScryptParams {
                    dklen: DKLEN,
                    n,
                    p: STANDARD_SCRYPT_P,
                    r: STANDARD_SCRYPT_R,
                    salt: hex::encode(salt),
                }),
                mac: hex::encode(mac),
            },
            id: uuid::Uuid::new_v4().to_string(),
            version: 3,
        })
    }

    /// Decrypt the keystore with `password` and return the 32-byte
    /// private key. Errors on wrong password, malformed JSON, or
    /// unsupported KDF/cipher.
    pub fn decrypt(&self, password: &str) -> Result<[u8; 32], KeystoreError> {
        if self.version != 3 {
            return Err(KeystoreError::UnsupportedVersion(self.version));
        }
        if self.crypto.cipher != "aes-128-ctr" {
            return Err(KeystoreError::UnsupportedCipher(self.crypto.cipher.clone()));
        }
        let iv: [u8; 16] = decode_hex_fixed(&self.crypto.cipherparams.iv, "iv")?;
        let ciphertext = decode_hex(&self.crypto.ciphertext, "ciphertext")?;
        if ciphertext.len() != 32 {
            return Err(KeystoreError::Malformed(format!(
                "ciphertext is {} bytes, expected 32",
                ciphertext.len()
            )));
        }
        let expected_mac = decode_hex_fixed::<32>(&self.crypto.mac, "mac")?;

        let derived = match (&self.crypto.kdfparams, self.crypto.kdf.as_str()) {
            (KdfParams::Scrypt(p), "scrypt") => {
                if p.dklen != DKLEN {
                    return Err(KeystoreError::Malformed(format!(
                        "scrypt dklen={} unsupported (only 32)",
                        p.dklen
                    )));
                }
                let n_log2 = log2_exact(p.n)
                    .ok_or_else(|| KeystoreError::Malformed(format!("scrypt n={} not a power of two", p.n)))?;
                let salt = decode_hex(&p.salt, "scrypt salt")?;
                scrypt_derive(password.as_bytes(), &salt, n_log2, p.r, p.p)?
            }
            (KdfParams::Pbkdf2(p), "pbkdf2") => {
                if p.dklen != DKLEN {
                    return Err(KeystoreError::Malformed(format!(
                        "pbkdf2 dklen={} unsupported (only 32)",
                        p.dklen
                    )));
                }
                if p.prf != "hmac-sha256" {
                    return Err(KeystoreError::Malformed(format!(
                        "pbkdf2 prf '{}' unsupported (only hmac-sha256)",
                        p.prf
                    )));
                }
                let salt = decode_hex(&p.salt, "pbkdf2 salt")?;
                pbkdf2_derive(password.as_bytes(), &salt, p.c)?
            }
            (KdfParams::Scrypt(_), other) | (KdfParams::Pbkdf2(_), other) => {
                return Err(KeystoreError::Malformed(format!(
                    "kdf/kdfparams mismatch: kdf='{}'",
                    other
                )))
            }
        };

        // mac = keccak256(derived[16..32] || ciphertext)
        let mut mac_input = Vec::with_capacity(16 + 32);
        mac_input.extend_from_slice(&derived[16..32]);
        mac_input.extend_from_slice(&ciphertext);
        let actual_mac = tron_crypto::hash::keccak256(&mac_input);

        if !constant_time_eq(&actual_mac, &expected_mac) {
            return Err(KeystoreError::WrongPassword);
        }

        let cipher_key: &[u8; 16] = derived[..16].try_into().expect("32-byte derived");
        let mut plaintext = [0u8; 32];
        plaintext.copy_from_slice(&ciphertext);
        let mut cipher = Aes128Ctr::new(cipher_key.into(), (&iv).into());
        cipher.apply_keystream(&mut plaintext);
        Ok(plaintext)
    }

    /// Read a keystore from a JSON file.
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, KeystoreError> {
        let bytes = std::fs::read(path)
            .map_err(|e| KeystoreError::Io(format!("read {}: {e}", path.display())))?;
        serde_json::from_slice(&bytes).map_err(|e| KeystoreError::Malformed(format!("{e}")))
    }

    /// Write the keystore to `path` as pretty-printed JSON.
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<(), KeystoreError> {
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| KeystoreError::Malformed(format!("serialize: {e}")))?;
        std::fs::write(path, bytes)
            .map_err(|e| KeystoreError::Io(format!("write {}: {e}", path.display())))?;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("io: {0}")]
    Io(String),
    #[error("malformed keystore: {0}")]
    Malformed(String),
    #[error("unsupported version {0} (only v3)")]
    UnsupportedVersion(u32),
    #[error("unsupported cipher '{0}' (only aes-128-ctr)")]
    UnsupportedCipher(String),
    #[error("scrypt failed: {0}")]
    Scrypt(String),
    #[error("pbkdf2 failed: {0}")]
    Pbkdf2(String),
    #[error("rng: {0}")]
    Rng(String),
    #[error("wrong password")]
    WrongPassword,
}

fn scrypt_derive(
    password: &[u8],
    salt: &[u8],
    n_log2: u8,
    r: u32,
    p: u32,
) -> Result<[u8; 32], KeystoreError> {
    let params = scrypt::Params::new(n_log2, r, p, DKLEN as usize)
        .map_err(|e| KeystoreError::Scrypt(format!("bad params (n_log2={n_log2},r={r},p={p}): {e}")))?;
    let mut out = [0u8; 32];
    scrypt::scrypt(password, salt, &params, &mut out)
        .map_err(|e| KeystoreError::Scrypt(format!("{e}")))?;
    Ok(out)
}

fn pbkdf2_derive(password: &[u8], salt: &[u8], iterations: u32) -> Result<[u8; 32], KeystoreError> {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut out);
    Ok(out)
}

fn decode_hex(s: &str, field: &str) -> Result<Vec<u8>, KeystoreError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|e| KeystoreError::Malformed(format!("{field} hex: {e}")))
}

fn decode_hex_fixed<const N: usize>(s: &str, field: &str) -> Result<[u8; N], KeystoreError> {
    let v = decode_hex(s, field)?;
    if v.len() != N {
        return Err(KeystoreError::Malformed(format!(
            "{field} is {} bytes, expected {N}",
            v.len()
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&v);
    Ok(out)
}

fn log2_exact(n: u32) -> Option<u8> {
    if n == 0 || !n.is_power_of_two() {
        return None;
    }
    Some(n.trailing_zeros() as u8)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn round_trip_with_light_params() {
        let priv_key = hex!("1234567890123456789012345678901234567890123456789012345678901234");
        let ks = Keystore::create(&priv_key, "hunter2", "TXxxx", 12).unwrap();
        assert_eq!(ks.version, 3);
        assert_eq!(ks.crypto.cipher, "aes-128-ctr");
        assert_eq!(ks.crypto.kdf, "scrypt");
        let recovered = ks.decrypt("hunter2").unwrap();
        assert_eq!(recovered, priv_key);
    }

    #[test]
    fn wrong_password_is_rejected() {
        let priv_key = hex!("0000000000000000000000000000000000000000000000000000000000000001");
        let ks = Keystore::create(&priv_key, "correct", "TXxxx", 12).unwrap();
        let err = ks.decrypt("wrong").unwrap_err();
        assert!(matches!(err, KeystoreError::WrongPassword), "got: {err:?}");
    }

    #[test]
    fn json_round_trip_preserves_all_fields() {
        let priv_key = hex!("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899");
        let ks = Keystore::create(&priv_key, "pw", "TXxxx", 12).unwrap();
        let json = serde_json::to_string(&ks).unwrap();
        let parsed: Keystore = serde_json::from_str(&json).unwrap();
        let recovered = parsed.decrypt("pw").unwrap();
        assert_eq!(recovered, priv_key);
    }

    #[test]
    fn pbkdf2_keystore_is_readable() {
        // Build a pbkdf2 keystore by hand and verify decrypt works.
        let priv_key = hex!("0101010101010101010101010101010101010101010101010101010101010101");
        let password = "pw";
        let salt = hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let iv = hex!("cccccccccccccccccccccccccccccccc");
        let iterations: u32 = 1024; // small for test speed

        let derived = pbkdf2_derive(password.as_bytes(), &salt, iterations).unwrap();
        let cipher_key: &[u8; 16] = derived[..16].try_into().unwrap();
        let mac_key = &derived[16..];

        let mut ciphertext = priv_key;
        let mut cipher = Aes128Ctr::new(cipher_key.into(), (&iv).into());
        cipher.apply_keystream(&mut ciphertext);

        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(mac_key);
        mac_input.extend_from_slice(&ciphertext);
        let mac = tron_crypto::hash::keccak256(&mac_input);

        let ks = Keystore {
            address: "TXxxx".into(),
            id: "00000000-0000-0000-0000-000000000000".into(),
            version: 3,
            crypto: Crypto {
                cipher: "aes-128-ctr".into(),
                ciphertext: hex::encode(ciphertext),
                cipherparams: CipherParams {
                    iv: hex::encode(iv),
                },
                kdf: "pbkdf2".into(),
                kdfparams: KdfParams::Pbkdf2(Pbkdf2Params {
                    dklen: 32,
                    c: iterations,
                    prf: "hmac-sha256".into(),
                    salt: hex::encode(salt),
                }),
                mac: hex::encode(mac),
            },
        };
        let recovered = ks.decrypt(password).unwrap();
        assert_eq!(recovered, priv_key);
    }

    #[test]
    fn corrupted_mac_rejects_decrypt_as_wrong_password() {
        let priv_key = [0x42u8; 32];
        let mut ks = Keystore::create(&priv_key, "pw", "TXxxx", 12).unwrap();
        // Flip one nibble in the mac.
        let mut mac_bytes = hex::decode(&ks.crypto.mac).unwrap();
        mac_bytes[0] ^= 0xff;
        ks.crypto.mac = hex::encode(mac_bytes);
        assert!(matches!(ks.decrypt("pw"), Err(KeystoreError::WrongPassword)));
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let priv_key = [0x01u8; 32];
        let mut ks = Keystore::create(&priv_key, "pw", "TXxxx", 12).unwrap();
        ks.version = 1;
        assert!(matches!(ks.decrypt("pw"), Err(KeystoreError::UnsupportedVersion(1))));
    }

    #[test]
    fn log2_exact_handles_edge_cases() {
        assert_eq!(log2_exact(0), None);
        assert_eq!(log2_exact(1), Some(0));
        assert_eq!(log2_exact(2), Some(1));
        assert_eq!(log2_exact(1 << 18), Some(18));
        assert_eq!(log2_exact(7), None); // not a power of 2
        assert_eq!(log2_exact(u32::MAX), None);
    }

    #[test]
    fn constant_time_eq_returns_correct_results() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
    }
}
