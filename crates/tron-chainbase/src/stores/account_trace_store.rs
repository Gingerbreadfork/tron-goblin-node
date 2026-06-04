//! AccountTraceStore — directory name `account-trace`.
//!
//! Per-account balance history with a **descending-block-order** twist.
//! Lets the node answer "what was account X's balance at block N?" by
//! scanning forward from the (address, N) key — the next entry holds the
//! *most-recent ≤ N* balance.
//!
//! Key:   `address(21) ‖ xor_block_num(8)`
//!        where `xor_block_num = block_num ^ i64::MAX`.
//! Value: protobuf-encoded `AccountTrace` message (currently just a balance).
//!
//! **XOR trick**: java-tron stores the *complement* of the block number so
//! that ascending-key iteration yields **descending** block order.
//! `revokingDB.getNext(key, 1)` on this key then returns the first entry
//! with the same address whose stored xor-key ≥ the requested xor-key —
//! which translates to the closest earlier block number.
//!
//! Source: `org.tron.core.store.AccountTraceStore.xor` (= `l ^ Long.MAX_VALUE`).

use std::sync::Arc;

use prost::Message;
use tron_crypto::address::{Address, ADDRESS_LENGTH};
use tron_proto::AccountTrace;

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME: &str = "account-trace";

pub struct AccountTraceStore {
    backend: Arc<dyn KvBackend>,
}

impl AccountTraceStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    /// Apply the descending-order XOR: `block_num ^ i64::MAX`. Pinned by
    /// a test — getting this wrong silently inverts iteration order.
    pub fn xor_block_num(block_num: i64) -> i64 {
        block_num ^ i64::MAX
    }

    pub fn key_for(address: &Address, block_num: i64) -> [u8; ADDRESS_LENGTH + 8] {
        let mut out = [0u8; ADDRESS_LENGTH + 8];
        out[..ADDRESS_LENGTH].copy_from_slice(address.as_bytes());
        out[ADDRESS_LENGTH..].copy_from_slice(&Self::xor_block_num(block_num).to_be_bytes());
        out
    }

    pub fn put(&self, address: &Address, block_num: i64, trace: &AccountTrace) -> Result<(), StoreError> {
        let key = Self::key_for(address, block_num);
        self.backend.put(&key, &trace.encode_to_vec())?;
        Ok(())
    }

    pub fn get(
        &self,
        address: &Address,
        block_num: i64,
    ) -> Result<Option<AccountTrace>, StoreError> {
        let key = Self::key_for(address, block_num);
        let Some(bytes) = self.backend.get(&key)? else {
            return Ok(None);
        };
        Ok(Some(AccountTrace::decode(bytes.as_slice())?))
    }

    /// Return the balance at the most-recent block `<= block_num` for
    /// `address`. Mirrors java-tron's
    /// `AccountTraceStore.getPrevBalance(address, blockNum)`: build
    /// the (address, xor(blockNum)) key, seek forward (which is
    /// descending block order thanks to the XOR), and take the first
    /// entry that still has our address prefix.
    ///
    /// Returns:
    /// * `Ok((found_block_num, balance))` — the entry at or before `block_num`.
    /// * `Err(StoreError::NotFound)` — no trace exists for this account.
    pub fn get_prev_balance(
        &self,
        address: &Address,
        block_num: i64,
    ) -> Result<(i64, i64), StoreError> {
        let start_key = Self::key_for(address, block_num);
        let rows = self.backend.scan_from(&start_key, 1)?;
        let Some((k, v)) = rows.into_iter().next() else {
            return Err(StoreError::NotFound);
        };
        // Verify the returned row is still for our address (the scan
        // would otherwise drift into the next account's range).
        if !k.starts_with(address.as_bytes()) {
            return Err(StoreError::NotFound);
        }
        // Recover the original block number from the XOR suffix.
        let mut xor_buf = [0u8; 8];
        xor_buf.copy_from_slice(&k[ADDRESS_LENGTH..]);
        let xor_num = i64::from_be_bytes(xor_buf);
        let found_block = Self::xor_block_num(xor_num); // self-inverse
        let trace = AccountTrace::decode(v.as_slice())?;
        Ok((found_block, trace.balance))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MemBackend;
    use std::sync::Arc;

    fn addr(byte: u8) -> Address {
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[1..].fill(byte);
        Address::from_raw(a)
    }

    #[test]
    fn get_prev_balance_finds_exact_block() {
        let backend: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
        let store = AccountTraceStore::new(backend);
        let alice = addr(0xaa);
        store.put(
            &alice,
            100,
            &AccountTrace {
                balance: 5_000,
                ..Default::default()
            },
        ).unwrap();
        let (block_found, balance) = store.get_prev_balance(&alice, 100).unwrap();
        assert_eq!(block_found, 100);
        assert_eq!(balance, 5_000);
    }

    #[test]
    fn get_prev_balance_returns_closest_earlier_block() {
        let backend: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
        let store = AccountTraceStore::new(backend);
        let alice = addr(0xaa);
        // Sparse history: balances written at 50, 100, 200.
        for (n, bal) in [(50, 100), (100, 200), (200, 300)] {
            store.put(
                &alice,
                n,
                &AccountTrace {
                    balance: bal,
                    ..Default::default()
                },
            ).unwrap();
        }
        let (b, bal) = store.get_prev_balance(&alice, 150).unwrap();
        assert_eq!(b, 100);
        assert_eq!(bal, 200);
    }

    #[test]
    fn get_prev_balance_unknown_account_returns_not_found() {
        let backend: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
        let store = AccountTraceStore::new(backend);
        assert!(matches!(
            store.get_prev_balance(&addr(0xff), 100),
            Err(StoreError::NotFound)
        ));
    }
}
