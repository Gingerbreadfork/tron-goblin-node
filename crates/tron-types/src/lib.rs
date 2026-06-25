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
    calc_tx_trie_root, tx_id, tx_merkle_hash, tx_sizes_from_block_bytes,
    tx_trie_root_from_block_bytes, TxIdError,
};
pub use tx_sign::{recover_all_signers, recover_signer_address, sign_transaction, SignError};
