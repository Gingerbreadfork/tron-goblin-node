//! Cryptographic primitives for the TRON protocol.
//!
//! Port target: java-tron's `crypto/` module. Every public function in this
//! crate is expected to produce byte-identical output to its java-tron
//! counterpart. Tests in `tests/vectors.rs` enforce this against fixtures
//! extracted from the reference implementation.

pub mod address;
pub mod base58check;
pub mod hash;
pub mod merkle;
pub mod rlp;
pub mod signature;
pub mod sm2;

pub use address::{Address, ADDRESS_PREFIX_MAINNET};
pub use base58check::{decode_address, decode_check, encode_address, encode_check, Base58CheckError};
pub use hash::{keccak256, sha256};
pub use signature::{RecoverableSignature, SigError};
pub use sm2::{verify as sm2_verify, Sm2Error, Sm2Key, TRON_SM2_USER_ID};
