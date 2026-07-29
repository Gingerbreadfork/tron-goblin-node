//! Domain types and capsule wrappers over `tron-proto`.
//!
//! This crate captures java-tron's *non-obvious* conventions: the way a
//! `BlockId` is laid out (first 8 bytes are the big-endian block number),
//! the distinction between a transaction's *id* (hash of raw data) and its
//! *merkle hash* (hash of the entire signed transaction), and the rule for
//! computing the `txTrieRoot`.
//!
//! Code in higher layers (chainbase, consensus, networking) should depend
//! on this crate rather than `tron-proto` directly, so the conventions are
//! enforced in one place.

pub mod account_state_root;
pub mod block_id;
pub mod block_validate;
pub mod genesis;
pub mod resource;
pub mod strict_math;
pub mod tx_id;
pub mod tx_sign;

/// How this software identifies itself to the outside world: the P2P
/// handshake's `code_version`, `web3_clientVersion`, and `getNodeInfo`.
///
/// Built from the workspace version that every tron-* crate shares, so the
/// identity a running node reports always matches the tag it was built from.
/// This lives here because both `tron-net` (handshake) and `tron-rpc`
/// (JSON-RPC) need it and neither depends on the other.
///
/// Not to be confused with the `*_P2P_VERSION` protocol numbers in
/// `tron-net`, which gate peer compatibility and must not track releases.
pub const CODE_VERSION: &str = concat!("tron-goblin/", env!("CARGO_PKG_VERSION"));

/// [`CODE_VERSION`] as raw UTF-8, the form the P2P wire field takes.
pub const CODE_VERSION_BYTES: &[u8] = CODE_VERSION.as_bytes();

pub use account_state_root::{
    compute_account_state_root, compute_account_state_root_with_storage, compute_storage_root,
    AccountState, KECCAK_EMPTY_STORAGE_ROOT,
};
pub use block_id::{block_id_from_block, block_id_from_header_raw, BlockId, BlockIdError};
pub use block_validate::{
    block_raw_hash, sign_block, verify_parent_link, verify_tx_trie_root, verify_tx_trie_root_raw,
    verify_witness_signature, BlockValidateError,
};
pub use strict_math::strict_pow;
pub use genesis::{
    build_genesis_block, genesis_block_id, mainnet_inputs, mainnet_witnesses, GenesisAsset,
    GenesisInputs, GenesisWitness, GENESIS_OWNER_ADDRESS, MAINNET_ASSETS, MAINNET_PARENT_HASH,
    MAINNET_WITNESS_QUOTE,
};
pub use tx_id::{
    calc_tx_trie_root, tx_id, tx_id_from_tx_bytes, tx_merkle_hash, tx_sizes_from_block_bytes,
    tx_spans_from_block_bytes, tx_trie_root_from_block_bytes, tx_wire_infos_from_block_bytes,
    TxIdError, TxWireInfo,
};
pub use tx_sign::{
    recover_all_signers, recover_all_signers_with_id, recover_signer_address, sign_transaction,
    SignError,
};
