//! Compute the **accountStateRoot** field of a TRON block header.
//!
//! TRON inherits Ethereum's Merkle-Patricia Trie (MPT) semantics for
//! the state-root commitment. The trie is keyed by `keccak256(address)`
//! (the EVM address — TRON's 20-byte low half, NOT the 21-byte with-prefix
//! form) and valued by `RLP(account)` where `account` is the encoded
//! state tuple `[nonce, balance, storage_root, code_hash]`.
//!
//! ## Why eth_trie
//!
//! The MPT itself is consensus-critical and surprisingly subtle
//! (hex-prefix encoding, extension/branch/leaf node packing, RLP
//! everywhere). Using the official `eth_trie` crate — published by the
//! Ethereum project — sidesteps a hundreds-of-lines correctness
//! liability. The trie is generic over a backing DB; we use the
//! in-memory variant since the trie state lives only as long as the
//! computation.
//!
//! ## Storage roots
//!
//! Each contract account has its own storage trie. For Phase 5 we use
//! a placeholder `KECCAK_EMPTY_STORAGE_ROOT` (≡ keccak256(rlp(""))) for
//! every account. Real per-contract storage-root computation walks the
//! `StorageRowStore` and is a focused follow-up — the **outer** trie
//! shape is the consensus-critical bit pinned here.

use std::sync::Arc;

use eth_trie::{EthTrie, MemoryDB, Trie};
use tron_crypto::address::Address;
use tron_crypto::hash::keccak256;
use tron_proto::Account;

/// `keccak256(rlp(""))` — the storage root of an account with no
/// storage. Same constant Ethereum uses.
pub const KECCAK_EMPTY_STORAGE_ROOT: [u8; 32] = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];

/// One account's state entry as serialized into the trie.
///
/// Mirrors `web3j`'s `AccountState` and Ethereum's `[nonce, balance,
/// storage_root, code_hash]` 4-tuple. Encoded as RLP — the trie value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountState {
    /// TRON doesn't have a per-account nonce; pinned to 0 for parity
    /// with Ethereum-style state-root computation.
    pub nonce: u64,
    /// TRX balance in sun.
    pub balance: i64,
    /// Per-contract storage root. `KECCAK_EMPTY_STORAGE_ROOT` for EOAs
    /// and contracts with no storage.
    pub storage_root: [u8; 32],
    /// `keccak256(code)` of the deployed bytecode, or `KECCAK_EMPTY`
    /// for EOAs.
    pub code_hash: [u8; 32],
}

impl AccountState {
    /// Build the state tuple from a TRON `Account` proto. Uses the
    /// account's `balance` and `code_hash`; storage root is the empty
    /// constant unless the caller supplies one.
    pub fn from_account(account: &Account, storage_root: Option<[u8; 32]>) -> Self {
        let mut code_hash = tron_crypto::hash::KECCAK_EMPTY;
        if account.code_hash.len() == 32 {
            code_hash.copy_from_slice(&account.code_hash);
        }
        Self {
            nonce: 0,
            balance: account.balance,
            storage_root: storage_root.unwrap_or(KECCAK_EMPTY_STORAGE_ROOT),
            code_hash,
        }
    }

    /// Empty-account `AccountState` — used as the "default" entry for
    /// addresses that don't exist. Pinned constants only.
    pub const fn empty() -> Self {
        Self {
            nonce: 0,
            balance: 0,
            storage_root: KECCAK_EMPTY_STORAGE_ROOT,
            code_hash: tron_crypto::hash::KECCAK_EMPTY,
        }
    }

    /// RLP-encode the state tuple. Order: `[nonce, balance,
    /// storage_root, code_hash]`.
    pub fn rlp_encode(&self) -> Vec<u8> {
        let mut items: Vec<Vec<u8>> = Vec::with_capacity(4);
        items.push(tron_crypto::rlp::encode_uint(self.nonce as u128));
        // Balance is i64 but always non-negative for accounts; encode
        // as unsigned.
        items.push(tron_crypto::rlp::encode_uint(self.balance.max(0) as u128));
        items.push(tron_crypto::rlp::encode_bytes(&self.storage_root));
        items.push(tron_crypto::rlp::encode_bytes(&self.code_hash));
        tron_crypto::rlp::encode_list(&items)
    }
}

/// Compute the **per-contract storage root** by feeding a contract's
/// storage rows into a fresh Merkle-Patricia trie.
///
/// Each row contributes `(trie_key, trie_value)` where:
/// * `trie_key = keccak256(composite_row_key)` — the composite key is
///   already the 32-byte `keccak256(addr)[..16] || slot[16..]`
///   composite that `StorageRowStore` writes to disk. Hashing it once
///   more gives the trie key.
/// * `trie_value = RLP(slot_value)` — the raw stored bytes, RLP-wrapped
///   as the trie expects.
///
/// For a contract with no storage rows the result is
/// [`KECCAK_EMPTY_STORAGE_ROOT`].
///
/// **Cost**: O(n) where `n` is the number of storage rows belonging to
/// the contract. Incremental MPT updates would be a follow-up — this
/// is the brute-force "rebuild from scratch" variant.
pub fn compute_storage_root(rows: &[([u8; 32], Vec<u8>)]) -> [u8; 32] {
    if rows.is_empty() {
        return KECCAK_EMPTY_STORAGE_ROOT;
    }
    let db = Arc::new(MemoryDB::new(true));
    let mut trie = EthTrie::new(db);
    for (composite_key, value) in rows {
        let trie_key = keccak256(composite_key);
        let trie_value = tron_crypto::rlp::encode_bytes(value);
        trie.insert(&trie_key, &trie_value)
            .expect("MPT insert never fails for non-empty value");
    }
    let root = trie
        .root_hash()
        .expect("MPT root_hash is infallible against MemoryDB");
    let mut out = [0u8; 32];
    out.copy_from_slice(root.as_slice());
    out
}

/// Compute the account-state-root for a set of `(address, account)`
/// pairs. Returns the 32-byte root hash that should match the block
/// header's `account_state_root` field.
///
/// The trie key is `keccak256(address.low20_bytes)` — i.e. the
/// Ethereum-style 20-byte address, derived from TRON's 21-byte address
/// by stripping the leading `0x41`.
///
/// **Empty input** → returns Ethereum's well-known empty-trie root:
/// `keccak256(rlp(""))` = `KECCAK_EMPTY_STORAGE_ROOT`.
pub fn compute_account_state_root(accounts: &[(Address, Account)]) -> [u8; 32] {
    compute_account_state_root_with_storage(accounts, |_| None)
}

/// Variant that lets the caller plug in per-account storage roots.
/// `storage_root_lookup(address)` returns `Some(root)` to override the
/// default `KECCAK_EMPTY_STORAGE_ROOT` placeholder for a given account.
///
/// Real consumers (the block executor on commit) pass a closure that
/// reads from `StorageRowStore::scan_for_contract` + `compute_storage_root`.
pub fn compute_account_state_root_with_storage(
    accounts: &[(Address, Account)],
    mut storage_root_lookup: impl FnMut(&Address) -> Option<[u8; 32]>,
) -> [u8; 32] {
    let db = Arc::new(MemoryDB::new(true));
    let mut trie = EthTrie::new(db);

    for (address, account) in accounts {
        let evm_addr = &address.as_bytes()[1..]; // strip 0x41 prefix
        let key = keccak256(evm_addr);
        let storage_root = storage_root_lookup(address);
        let state = AccountState::from_account(account, storage_root);
        let value = state.rlp_encode();
        trie.insert(&key, &value)
            .expect("MPT insert never fails for non-empty value");
    }

    let root = trie
        .root_hash()
        .expect("MPT root_hash is infallible against MemoryDB");
    let mut out = [0u8; 32];
    out.copy_from_slice(root.as_slice());
    out
}
