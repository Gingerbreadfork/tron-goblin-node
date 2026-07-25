//! Decode a [`RawStateDiff`] into typed account/storage/code diffs on top of
//! the always-present raw entries, so tooling gets structured output without
//! losing anything.

use prost::Message;
use tron_crypto::address::Address;
use tron_proto::Account;

use crate::overlay::{DiffEntry, RawStateDiff};

/// A changed account row, decoded from the `Account` proto where possible.
#[derive(Debug, Clone)]
pub struct AccountDiff {
    pub address: Option<Address>,
    pub raw_key: Vec<u8>,
    pub before: Option<Account>,
    pub after: Option<Account>,
}

/// A changed storage row. The key is the raw composite storage-row key
/// (`addr_hash[..16] ‖ slot[16..]`); the plain slot is not recoverable from
/// it (a TVM layout property), so the composite key is reported as-is.
#[derive(Debug, Clone)]
pub struct StorageDiff {
    pub key: [u8; 32],
    pub before: Option<[u8; 32]>,
    pub after: Option<[u8; 32]>,
}

/// A changed code row (keyed by 21-byte address).
#[derive(Debug, Clone)]
pub struct CodeDiff {
    pub address: Option<Address>,
    pub raw_key: Vec<u8>,
    pub before: Option<Vec<u8>>,
    pub after: Option<Vec<u8>>,
}

/// Typed decode of a raw diff, with the raw entries retained.
#[derive(Debug, Clone)]
pub struct DecodedStateDiff {
    pub accounts: Vec<AccountDiff>,
    pub storage: Vec<StorageDiff>,
    pub code: Vec<CodeDiff>,
    pub raw: RawStateDiff,
}

fn as_addr(key: &[u8]) -> Option<Address> {
    if key.len() == 21 {
        let mut a = [0u8; 21];
        a.copy_from_slice(key);
        Some(Address::from_raw(a))
    } else {
        None
    }
}

fn as_word(v: &Option<Vec<u8>>) -> Option<[u8; 32]> {
    v.as_ref().map(|b| {
        // Right-align into a 32-byte word (storage values are stored as 32
        // bytes; be defensive about anything shorter/longer).
        let mut w = [0u8; 32];
        let n = b.len().min(32);
        w[32 - n..].copy_from_slice(&b[b.len() - n..]);
        w
    })
}

fn decode_account(v: &Option<Vec<u8>>) -> Option<Account> {
    v.as_ref().and_then(|b| Account::decode(&b[..]).ok())
}

impl DecodedStateDiff {
    pub fn from_raw(raw: RawStateDiff) -> Self {
        let accounts = raw
            .accounts
            .iter()
            .map(|(k, before, after)| AccountDiff {
                address: as_addr(k),
                raw_key: k.clone(),
                before: decode_account(before),
                after: decode_account(after),
            })
            .collect();

        let storage = raw
            .storage
            .iter()
            .filter_map(|(k, before, after)| {
                if k.len() != 32 {
                    return None;
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(k);
                Some(StorageDiff { key, before: as_word(before), after: as_word(after) })
            })
            .collect();

        let code = raw
            .code
            .iter()
            .map(|(k, before, after): &DiffEntry| CodeDiff {
                address: as_addr(k),
                raw_key: k.clone(),
                before: before.clone(),
                after: after.clone(),
            })
            .collect();

        DecodedStateDiff { accounts, storage, code, raw }
    }

    /// Total changed keys across all stores.
    pub fn len(&self) -> usize {
        self.raw.len()
    }

    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }
}
