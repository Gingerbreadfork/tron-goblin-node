//! DelegationStore — directory name `delegation`.
//!
//! Tracks per-cycle vote / reward / brokerage / Vi (vote-index) values per
//! Super Representative. Keys are **UTF-8 composite strings** that
//! concatenate the cycle number (decimal), the witness address (lowercase
//! hex, no `0x` prefix), and a per-shape suffix.
//!
//! Six key shapes (all bytes are UTF-8):
//!
//! | Shape          | Format                                  |
//! |----------------|-----------------------------------------|
//! | Vote           | `"<cycle>-<addr_hex>-vote"`             |
//! | Reward         | `"<cycle>-<addr_hex>-reward"`           |
//! | Brokerage      | `"<cycle>-<addr_hex>-brokerage"`        |
//! | Vi (index)     | `"<cycle>-<addr_hex>-vi"`               |
//! | AccountVote    | `"<cycle>-<addr_hex>-account-vote"`     |
//! | EndCycle       | `"end-<addr_hex>"` (no cycle prefix)    |
//! | BeginCycle     | the raw 21-byte address (no transform)  |
//!
//! Source: `org.tron.core.store.DelegationStore`. The hex encoding uses
//! BouncyCastle's lowercase `Hex.toHexString` — a 21-byte TRON address
//! becomes 42 lowercase hex chars with no separators.

use std::sync::Arc;

use prost::Message;
use tron_crypto::address::Address;
use tron_proto::Account;

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME: &str = "delegation";

/// Sentinel value returned for missing entries (`-1L` in java-tron).
pub const REMARK: i64 = -1;

/// Default brokerage rate (20 = 20%) returned when a witness has not
/// explicitly set one. Matches `DelegationStore.DEFAULT_BROKERAGE`.
pub const DEFAULT_BROKERAGE: i32 = 20;

pub struct DelegationStore {
    backend: Arc<dyn KvBackend>,
}

impl DelegationStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    // -------------------- Key builders --------------------------------
    //
    // Public so callers can construct keys for direct backend access (e.g.
    // for read-only inspection of a captured DB).

    pub fn vote_key(cycle: i64, address: &Address) -> Vec<u8> {
        compose_key(cycle, address, "vote")
    }

    pub fn reward_key(cycle: i64, address: &Address) -> Vec<u8> {
        compose_key(cycle, address, "reward")
    }

    pub fn brokerage_key(cycle: i64, address: &Address) -> Vec<u8> {
        compose_key(cycle, address, "brokerage")
    }

    pub fn vi_key(cycle: i64, address: &Address) -> Vec<u8> {
        compose_key(cycle, address, "vi")
    }

    pub fn account_vote_key(cycle: i64, address: &Address) -> Vec<u8> {
        compose_key(cycle, address, "account-vote")
    }

    pub fn end_cycle_key(address: &Address) -> Vec<u8> {
        // Distinct shape: no cycle prefix.
        let mut out = b"end-".to_vec();
        out.extend_from_slice(hex::encode(address.as_bytes()).as_bytes());
        out
    }

    /// `setBeginCycle(address, n)` uses the raw 21-byte address as the
    /// key. This shares the keyspace with `end-<hex>` and the cycle/hex
    /// composites — they never collide because they have distinct length
    /// and prefix shapes (21 bytes vs. 4+ ASCII chars).
    pub fn begin_cycle_key(address: &Address) -> [u8; 21] {
        *address.as_bytes()
    }

    // -------------------- Reward (i64) --------------------------------
    //
    // The reward/vote/brokerage getters return primitives directly, not
    // `Result`. They're called from per-block reward accounting in many
    // places. Backend IO failures panic with rich context so triage is
    // unambiguous — see [`super::dynamic_properties_store`] for the same
    // pattern rationale.

    pub fn get_reward(&self, cycle: i64, address: &Address) -> i64 {
        let key = Self::reward_key(cycle, address);
        match self
            .backend
            .get(&key)
            .unwrap_or_else(|e| panic!("delegation store: failed to read reward key: {e}"))
        {
            Some(bytes) => parse_long_permissive(&bytes),
            None => 0,
        }
    }

    /// Atomic add: read current value, add `value`, write back. Matches
    /// `DelegationStore.addReward`.
    pub fn add_reward(&self, cycle: i64, address: &Address, value: i64) {
        let key = Self::reward_key(cycle, address);
        let new_total = match self
            .backend
            .get(&key)
            .unwrap_or_else(|e| panic!("delegation store: failed to read reward key: {e}"))
        {
            Some(bytes) => parse_long_permissive(&bytes).wrapping_add(value),
            None => value,
        };
        self.backend
            .put(&key, &new_total.to_be_bytes())
            .unwrap_or_else(|e| panic!("delegation store: failed to write reward key: {e}"));
    }

    // -------------------- Witness vote (i64) --------------------------

    /// Returns [`REMARK`] (`-1`) when the entry is missing — matches
    /// java-tron's sentinel semantics.
    pub fn get_witness_vote(&self, cycle: i64, address: &Address) -> i64 {
        let key = Self::vote_key(cycle, address);
        match self
            .backend
            .get(&key)
            .unwrap_or_else(|e| panic!("delegation store: failed to read vote key: {e}"))
        {
            Some(bytes) => parse_long_permissive(&bytes),
            None => REMARK,
        }
    }

    pub fn set_witness_vote(&self, cycle: i64, address: &Address, value: i64) {
        self.backend
            .put(&Self::vote_key(cycle, address), &value.to_be_bytes())
            .unwrap_or_else(|e| panic!("delegation store: failed to write vote key: {e}"));
    }

    // -------------------- Begin / end cycle ---------------------------

    pub fn get_begin_cycle(&self, address: &Address) -> i64 {
        match self
            .backend
            .get(&Self::begin_cycle_key(address))
            .unwrap_or_else(|e| panic!("delegation store: failed to read begin_cycle key: {e}"))
        {
            Some(bytes) => parse_long_permissive(&bytes),
            None => 0,
        }
    }

    pub fn set_begin_cycle(&self, address: &Address, number: i64) {
        self.backend
            .put(&Self::begin_cycle_key(address), &number.to_be_bytes())
            .unwrap_or_else(|e| panic!("delegation store: failed to write begin_cycle key: {e}"));
    }

    /// Returns [`REMARK`] (`-1`) when absent.
    pub fn get_end_cycle(&self, address: &Address) -> i64 {
        match self
            .backend
            .get(&Self::end_cycle_key(address))
            .unwrap_or_else(|e| panic!("delegation store: failed to read end_cycle key: {e}"))
        {
            Some(bytes) => parse_long_permissive(&bytes),
            None => REMARK,
        }
    }

    pub fn set_end_cycle(&self, address: &Address, number: i64) {
        self.backend
            .put(&Self::end_cycle_key(address), &number.to_be_bytes())
            .unwrap_or_else(|e| panic!("delegation store: failed to write end_cycle key: {e}"));
    }

    // -------------------- Brokerage (i32) -----------------------------

    /// Returns [`DEFAULT_BROKERAGE`] (`20`) when absent.
    pub fn get_brokerage(&self, cycle: i64, address: &Address) -> i32 {
        match self
            .backend
            .get(&Self::brokerage_key(cycle, address))
            .unwrap_or_else(|e| panic!("delegation store: failed to read brokerage key: {e}"))
        {
            Some(bytes) => parse_int_permissive(&bytes),
            None => DEFAULT_BROKERAGE,
        }
    }

    pub fn set_brokerage(&self, cycle: i64, address: &Address, brokerage: i32) {
        self.backend
            .put(&Self::brokerage_key(cycle, address), &brokerage.to_be_bytes())
            .unwrap_or_else(|e| panic!("delegation store: failed to write brokerage key: {e}"));
    }

    /// Convenience: `setBrokerage(address, b)` uses `cycle = -1`.
    pub fn set_brokerage_global(&self, address: &Address, brokerage: i32) {
        self.set_brokerage(-1, address, brokerage);
    }

    pub fn get_brokerage_global(&self, address: &Address) -> i32 {
        self.get_brokerage(-1, address)
    }

    // -------------------- Vi (signed BigInteger bytes) ----------------
    //
    // java-tron stores `BigInteger.toByteArray()` — Java's signed,
    // two's-complement, big-endian, smallest-length representation. We
    // pass the bytes through unchanged; arithmetic is done at a higher
    // layer that knows it's a bigint.

    pub fn get_witness_vi_raw(&self, cycle: i64, address: &Address) -> Option<Vec<u8>> {
        self.backend
            .get(&Self::vi_key(cycle, address))
            .unwrap_or_else(|e| panic!("delegation store: failed to read vi key: {e}"))
    }

    pub fn set_witness_vi_raw(&self, cycle: i64, address: &Address, value: &[u8]) {
        self.backend
            .put(&Self::vi_key(cycle, address), value)
            .unwrap_or_else(|e| panic!("delegation store: failed to write vi key: {e}"));
    }

    // -------------------- Account vote --------------------------------

    pub fn get_account_vote(
        &self,
        cycle: i64,
        address: &Address,
    ) -> Result<Option<Account>, StoreError> {
        let Some(bytes) = self.backend.get(&Self::account_vote_key(cycle, address))? else {
            return Ok(None);
        };
        Ok(Some(Account::decode(bytes.as_slice())?))
    }

    pub fn set_account_vote(&self, cycle: i64, address: &Address, account: &Account) -> Result<(), StoreError> {
        self.backend
            .put(&Self::account_vote_key(cycle, address), &account.encode_to_vec())?;
        Ok(())
    }

    // -------------------- Raw key access ------------------------------
    //
    // Untyped backend access keyed by a pre-built composite key (the
    // `*_key` builders above). Used by the TVM staking-journal's
    // `Delegation` reverser, which must snapshot and restore the exact
    // on-disk bytes of a begin-cycle / end-cycle / account-vote row
    // regardless of its logical type — mirroring java-tron's
    // `RepositoryImpl.putDelegation`, whose per-frame `delegationCache`
    // is keyed/valued by raw bytes and discarded wholesale on revert.

    pub fn get_raw(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.backend.get(key)?)
    }

    pub fn put_raw(&self, key: &[u8], value: &[u8]) -> Result<(), StoreError> {
        self.backend.put(key, value)?;
        Ok(())
    }

    pub fn delete_raw(&self, key: &[u8]) -> Result<(), StoreError> {
        self.backend.delete(key)?;
        Ok(())
    }
}

// --- Helpers -----------------------------------------------------------------

/// Build `"<cycle>-<addr_hex>-<suffix>"` as UTF-8 bytes.
fn compose_key(cycle: i64, address: &Address, suffix: &str) -> Vec<u8> {
    // Java: `cycle + "-" + Hex.toHexString(address) + "-" + suffix`
    // Decimal cycle (with leading `-` for negatives), lowercase hex address.
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(cycle.to_string().as_bytes());
    out.push(b'-');
    out.extend_from_slice(hex::encode(address.as_bytes()).as_bytes());
    out.push(b'-');
    out.extend_from_slice(suffix.as_bytes());
    out
}

/// See [`crate::stores::dynamic_properties_store`] for the rationale —
/// java-tron's `ByteArray.toLong` is permissive about input length.
fn parse_long_permissive(bytes: &[u8]) -> i64 {
    if bytes.is_empty() {
        return 0;
    }
    let len = bytes.len();
    let mut buf = [0u8; 8];
    if len >= 8 {
        buf.copy_from_slice(&bytes[len - 8..]);
    } else {
        buf[8 - len..].copy_from_slice(bytes);
    }
    i64::from_be_bytes(buf)
}

/// Same permissive parsing for 4-byte (i32) values: `ByteArray.toInt` uses
/// `new BigInteger(1, bytes).intValue()`.
fn parse_int_permissive(bytes: &[u8]) -> i32 {
    if bytes.is_empty() {
        return 0;
    }
    let len = bytes.len();
    let mut buf = [0u8; 4];
    if len >= 4 {
        buf.copy_from_slice(&bytes[len - 4..]);
    } else {
        buf[4 - len..].copy_from_slice(bytes);
    }
    i32::from_be_bytes(buf)
}
