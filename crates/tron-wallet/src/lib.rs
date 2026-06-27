//! Wallet primitives — keystore round-trip + transaction signing +
//! broadcast over JSON-RPC.
//!
//! ## Keystore
//!
//! [`Keystore`] mirrors the **Web3 Secret Storage Definition v3** JSON
//! shape, which is what java-tron's `org.tron.keystore.Wallet` writes
//! and reads. The same files round-trip cleanly between this CLI and
//! java-tron's wallet-cli:
//!
//! ```text
//! {
//!   "address":  "TXxxx..." (Base58Check, NOT 0x-prefixed hex),
//!   "id":       "uuid",
//!   "version":  3,
//!   "crypto": {
//!     "cipher":       "aes-128-ctr",
//!     "ciphertext":   hex(encrypted private key, 32 bytes),
//!     "cipherparams": { "iv": hex(16-byte IV) },
//!     "kdf":          "scrypt" | "pbkdf2",
//!     "kdfparams":    { ... },
//!     "mac":          hex(keccak256(derived[16..32] || ciphertext))
//!   }
//! }
//! ```
//!
//! Two KDFs are supported on the read path. We always write `scrypt`
//! (matching java-tron's default) with the parameters they use:
//! `n = 1 << 18`, `r = 8`, `p = 1`, `dklen = 32`.
//!
//! ## Signing
//!
//! [`sign_transaction_bytes`] decodes a protobuf `Transaction`, computes
//! `tx_id = sha256(raw_data)`, signs with secp256k1 (RFC 6979), and
//! re-encodes the signed transaction. Matches `tron_types::sign_transaction`.
//!
//! ## Broadcast
//!
//! [`broadcast_signed_tx`] POSTs the JSON-RPC request to the configured
//! node URL using a hand-rolled HTTP/1.1 client (raw TCP + tokio). We
//! avoid pulling in `reqwest` / `hyper` to keep the binary small —
//! one well-known endpoint shape is enough.

pub mod hd;
pub mod keystore;
pub mod mnemonic;

pub use hd::{derive_from_seed, derive_tron_default, tron_default_path, HdError, TRON_COIN_TYPE};
pub use keystore::{Keystore, KeystoreError, KdfParams};
pub use mnemonic::{MnemonicError, WordCount};

use tron_crypto::address::Address;

/// Sign an already-built unsigned `Transaction` (protobuf bytes) with
/// `private_key` and return the signed transaction bytes. The
/// transaction's `signature` field is appended to (java-tron's multisig
/// model — repeated bytes); other fields are preserved.
pub fn sign_transaction_bytes(
    tx_bytes: &[u8],
    private_key: &[u8; 32],
) -> Result<Vec<u8>, WalletError> {
    sign_transaction_bytes_with_memo(tx_bytes, private_key, None)
}

/// Like [`sign_transaction_bytes`], but first attaches `memo` to the
/// transaction's `data` field — TRON's on-chain note. The memo lives in
/// `raw_data`, so it must be set before signing: it changes the txID
/// (this is what TronWeb's `addUpdateData` does client-side). The
/// network charges the chain memo fee (`getMemoFee`, 1 TRX on mainnet)
/// for any transaction carrying a non-empty `data` field. A `None` or
/// empty memo leaves the transaction untouched.
pub fn sign_transaction_bytes_with_memo(
    tx_bytes: &[u8],
    private_key: &[u8; 32],
    memo: Option<&str>,
) -> Result<Vec<u8>, WalletError> {
    use prost::Message as _;
    let mut tx = tron_proto::Transaction::decode(tx_bytes)
        .map_err(|e| WalletError::Decode(format!("transaction proto: {e}")))?;
    if let Some(memo) = memo.filter(|m| !m.is_empty()) {
        let raw = tx.raw_data.as_mut().ok_or_else(|| {
            WalletError::Decode("transaction has no raw_data to attach a memo to".into())
        })?;
        raw.data = memo.as_bytes().to_vec();
    }
    tron_types::sign_transaction(&mut tx, private_key)
        .map_err(|e| WalletError::Sign(format!("{e:?}")))?;
    let mut out = Vec::with_capacity(tx.encoded_len());
    tx.encode(&mut out)
        .expect("Vec write is infallible");
    Ok(out)
}

/// Derive the TRON Base58Check (`T...`) address for a private key
/// without touching the keystore.
pub fn address_from_private(private_key: &[u8; 32]) -> Result<Address, WalletError> {
    let pubkey = tron_crypto::signature::public_key_from_private(private_key)
        .map_err(|e| WalletError::Sign(format!("derive pubkey: {e:?}")))?;
    Address::from_uncompressed_pubkey(&pubkey)
        .map_err(|e| WalletError::Sign(format!("address derive: {e:?}")))
}

/// Render an address in canonical `T...` Base58Check form.
pub fn address_to_base58(addr: &Address) -> String {
    tron_crypto::base58check::encode_address(addr)
}

/// Generate a fresh, cryptographically-random 32-byte secp256k1
/// private key. Rejects all-zero and N-or-greater values (out of the
/// valid scalar range), retrying once if the OS RNG returns one —
/// astronomically unlikely.
pub fn generate_private_key() -> Result<[u8; 32], WalletError> {
    for _ in 0..16 {
        let mut buf = [0u8; 32];
        getrandom::getrandom(&mut buf)
            .map_err(|e| WalletError::Rng(format!("{e}")))?;
        // Re-derive a pubkey to confirm the scalar is in range; the
        // SigningKey constructor enforces 0 < k < N. We never expect
        // this to fail in practice.
        if tron_crypto::signature::public_key_from_private(&buf).is_ok() {
            return Ok(buf);
        }
    }
    Err(WalletError::Rng(
        "exhausted retries generating a valid scalar".into(),
    ))
}

/// POST a JSON-RPC `broadcastTransaction` call to `rpc_url` with the
/// raw-hex form of the signed transaction. Returns the server's
/// parsed response body.
///
/// `rpc_url` is the full HTTP URL of the JSON-RPC endpoint (e.g.
/// `http://127.0.0.1:9090/`). We POST raw HTTP/1.1 over TCP — no
/// dependency on a full client like reqwest.
pub async fn broadcast_signed_tx(
    rpc_url: &str,
    signed_tx_bytes: &[u8],
) -> Result<serde_json::Value, WalletError> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "broadcastTransaction",
        "params": [format!("0x{}", hex::encode(signed_tx_bytes))],
        "id": 1,
    })
    .to_string();
    raw_http_post(rpc_url, &body).await
}

async fn raw_http_post(url: &str, body: &str) -> Result<serde_json::Value, WalletError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (host, port, path) = parse_http_url(url)?;
    let mut stream = tokio::net::TcpStream::connect((host.as_str(), port))
        .await
        .map_err(|e| WalletError::Http(format!("connect {host}:{port}: {e}")))?;
    let req = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    );
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| WalletError::Http(format!("write: {e}")))?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .await
        .map_err(|e| WalletError::Http(format!("read: {e}")))?;
    // Split off HTTP headers from the JSON body. We don't validate
    // status codes — JSON-RPC errors come through with HTTP 200 and a
    // body-level `error` field anyway.
    let body = response
        .split("\r\n\r\n")
        .nth(1)
        .ok_or_else(|| WalletError::Http("response missing body separator".into()))?;
    serde_json::from_str(body)
        .map_err(|e| WalletError::Http(format!("response not JSON: {e}; body: {body}")))
}

fn parse_http_url(url: &str) -> Result<(String, u16, String), WalletError> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| WalletError::Http(format!("only http:// URLs supported; got {url}")))?;
    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.find(':') {
        Some(idx) => (
            authority[..idx].to_string(),
            authority[idx + 1..]
                .parse::<u16>()
                .map_err(|e| WalletError::Http(format!("bad port: {e}")))?,
        ),
        None => (authority.to_string(), 80),
    };
    Ok((host, port, path.to_string()))
}

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("keystore: {0}")]
    Keystore(#[from] KeystoreError),
    #[error("decode: {0}")]
    Decode(String),
    #[error("sign: {0}")]
    Sign(String),
    #[error("rng: {0}")]
    Rng(String),
    #[error("http: {0}")]
    Http(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn generate_private_key_returns_a_valid_scalar() {
        let key = generate_private_key().unwrap();
        let addr = address_from_private(&key).unwrap();
        let b58 = address_to_base58(&addr);
        assert!(b58.starts_with('T'), "expected T-prefixed address, got {b58}");
        assert!(b58.len() >= 34, "T-address should be ~34 chars, got {}", b58.len());
    }

    #[test]
    fn address_from_known_private_matches_java_tron() {
        // This is the same keypair / address used in the sync tests
        // (ALICE_PRIV / ALICE). Verifies derivation matches the
        // canonical TRON path: keccak256(pubkey_xy)[12..] prefixed
        // with 0x41.
        let priv_key = hex!("1234567890123456789012345678901234567890123456789012345678901234");
        let addr = address_from_private(&priv_key).unwrap();
        assert_eq!(addr.as_bytes(), &hex!("412e988a386a799f506693793c6a5af6b54dfaabfb"));
    }

    #[test]
    fn sign_transaction_bytes_round_trips_through_decode() {
        use prost::Message as _;
        use tron_proto::{
            transaction::{contract::ContractType, Contract as TxContract, Raw as TxRaw},
            Transaction, TransferContract,
        };
        // Build an unsigned TransferContract tx and sign it.
        let from: [u8; 21] = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");
        let to: [u8; 21] = {
            let mut b = [0u8; 21];
            b[0] = 0x41;
            b[1..].fill(0xaa);
            b
        };
        let transfer = TransferContract {
            owner_address: from.to_vec(),
            to_address: to.to_vec(),
            amount: 1_000_000,
        };
        let mut value = Vec::new();
        transfer.encode(&mut value).unwrap();
        let tx = Transaction {
            raw_data: Some(TxRaw {
                contract: vec![TxContract {
                    r#type: ContractType::TransferContract as i32,
                    parameter: Some(prost_types::Any {
                        type_url: "type.googleapis.com/protocol.TransferContract".into(),
                        value,
                    }),
                    ..Default::default()
                }],
                timestamp: 1_700_000_000_000,
                ..Default::default()
            }),
            signature: Vec::new(),
            ret: Vec::new(),
            unparsed_field10: None,
        };
        let mut unsigned = Vec::new();
        tx.encode(&mut unsigned).unwrap();

        let priv_key = hex!("1234567890123456789012345678901234567890123456789012345678901234");
        let signed = sign_transaction_bytes(&unsigned, &priv_key).unwrap();
        let decoded = Transaction::decode(&*signed).unwrap();
        assert_eq!(decoded.signature.len(), 1, "exactly one signature appended");
        assert_eq!(
            decoded.signature[0].len(),
            65,
            "signature is r(32) || s(32) || v(1)"
        );
    }

    #[test]
    fn sign_with_memo_attaches_to_raw_data() {
        use prost::Message as _;
        use tron_proto::{
            transaction::{contract::ContractType, Contract as TxContract, Raw as TxRaw},
            Transaction, TransferContract,
        };
        let from: [u8; 21] = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");
        let transfer = TransferContract {
            owner_address: from.to_vec(),
            to_address: {
                let mut b = [0u8; 21];
                b[0] = 0x41;
                b[1..].fill(0xbb);
                b
            }
            .to_vec(),
            amount: 1,
        };
        let mut value = Vec::new();
        transfer.encode(&mut value).unwrap();
        let tx = Transaction {
            raw_data: Some(TxRaw {
                contract: vec![TxContract {
                    r#type: ContractType::TransferContract as i32,
                    parameter: Some(prost_types::Any {
                        type_url: "type.googleapis.com/protocol.TransferContract".into(),
                        value,
                    }),
                    ..Default::default()
                }],
                timestamp: 1_700_000_000_000,
                ..Default::default()
            }),
            signature: Vec::new(),
            ret: Vec::new(),
            unparsed_field10: None,
        };
        let mut unsigned = Vec::new();
        tx.encode(&mut unsigned).unwrap();
        let priv_key = hex!("1234567890123456789012345678901234567890123456789012345678901234");

        // A memo lands in raw_data.data and the tx is still signed.
        let memo = "Broadcasted with Tron Goblin Node";
        let signed = sign_transaction_bytes_with_memo(&unsigned, &priv_key, Some(memo)).unwrap();
        let decoded = Transaction::decode(&*signed).unwrap();
        assert_eq!(decoded.signature.len(), 1, "still signed with a memo");
        assert_eq!(
            decoded.raw_data.unwrap().data,
            memo.as_bytes(),
            "memo attached to raw_data.data"
        );

        // No / empty memo leaves data empty (and equals the plain signer).
        let plain = sign_transaction_bytes(&unsigned, &priv_key).unwrap();
        let none = sign_transaction_bytes_with_memo(&unsigned, &priv_key, None).unwrap();
        let empty = sign_transaction_bytes_with_memo(&unsigned, &priv_key, Some("")).unwrap();
        assert_eq!(none, plain, "None memo == plain sign");
        assert_eq!(empty, plain, "empty memo == plain sign");
        assert!(
            Transaction::decode(&*none).unwrap().raw_data.unwrap().data.is_empty(),
            "no memo -> empty data"
        );
    }

    #[test]
    fn parse_http_url_handles_host_port_and_path() {
        let (h, p, path) = parse_http_url("http://localhost:8090/").unwrap();
        assert_eq!(h, "localhost");
        assert_eq!(p, 8090);
        assert_eq!(path, "/");

        let (h, p, path) = parse_http_url("http://127.0.0.1:9090/api/v1").unwrap();
        assert_eq!(h, "127.0.0.1");
        assert_eq!(p, 9090);
        assert_eq!(path, "/api/v1");

        // Default port = 80.
        let (h, p, path) = parse_http_url("http://example.com/").unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 80);
        assert_eq!(path, "/");
    }

    #[test]
    fn parse_http_url_rejects_non_http_schemes() {
        assert!(parse_http_url("https://example.com/").is_err());
        assert!(parse_http_url("ftp://example.com/").is_err());
        assert!(parse_http_url("example.com/").is_err());
    }
}
