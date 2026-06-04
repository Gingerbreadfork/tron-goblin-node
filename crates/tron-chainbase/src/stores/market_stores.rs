//! TRON Market (DEX) stores — four directories that all use **underscores**:
//!
//! | Store                       | Directory                       |
//! |-----------------------------|---------------------------------|
//! | MarketAccountStore          | `market_account`                |
//! | MarketOrderStore            | `market_order`                  |
//! | MarketPairPriceToOrderStore | `market_pair_price_to_order`    |
//! | MarketPairToPriceStore      | `market_pair_to_price`          |
//!
//! Like [`super::WitnessScheduleStore`], every name uses `_` separators
//! rather than the project-wide `-`. java-tron's `Constant` interface
//! holds the canonical strings — pinning them here as `pub const`.

use std::sync::Arc;

use prost::Message;
use tron_crypto::address::Address;
use tron_proto::{MarketAccountOrder, MarketOrder, MarketOrderIdList};

use crate::backend::KvBackend;
use crate::stores::StoreError;

// === MarketAccountStore =====================================================

pub const MARKET_ACCOUNT_DB_NAME: &str = "market_account";

/// Holds per-owner aggregate order info. Key = 21-byte owner address.
pub struct MarketAccountStore {
    backend: Arc<dyn KvBackend>,
}

impl MarketAccountStore {
    pub const DB_NAME: &'static str = MARKET_ACCOUNT_DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    pub fn put(&self, owner: &Address, order: &MarketAccountOrder) -> Result<(), StoreError> {
        self.backend.put(owner.as_bytes(), &order.encode_to_vec())?;
        Ok(())
    }

    pub fn get(&self, owner: &Address) -> Result<Option<MarketAccountOrder>, StoreError> {
        let Some(bytes) = self.backend.get(owner.as_bytes())? else {
            return Ok(None);
        };
        Ok(Some(MarketAccountOrder::decode(bytes.as_slice())?))
    }
}

// === MarketOrderStore =======================================================

pub const MARKET_ORDER_DB_NAME: &str = "market_order";

/// Holds individual orders. Key = opaque order-id bytes.
pub struct MarketOrderStore {
    backend: Arc<dyn KvBackend>,
}

impl MarketOrderStore {
    pub const DB_NAME: &'static str = MARKET_ORDER_DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    pub fn put(&self, order_id: &[u8], order: &MarketOrder) -> Result<(), StoreError> {
        self.backend.put(order_id, &order.encode_to_vec())?;
        Ok(())
    }

    pub fn get(&self, order_id: &[u8]) -> Result<Option<MarketOrder>, StoreError> {
        let Some(bytes) = self.backend.get(order_id)? else {
            return Ok(None);
        };
        Ok(Some(MarketOrder::decode(bytes.as_slice())?))
    }

    pub fn delete(&self, order_id: &[u8]) -> Result<(), StoreError> {
        self.backend.delete(order_id)?;
        Ok(())
    }
}

// === MarketPairPriceToOrderStore ============================================

pub const MARKET_PAIR_PRICE_TO_ORDER_DB_NAME: &str = "market_pair_price_to_order";

/// Maps a composite `(pair, price)` key to the list of orders at that
/// price level. Key shape is opaque to this layer — callers pass the
/// already-encoded composite bytes.
pub struct MarketPairPriceToOrderStore {
    backend: Arc<dyn KvBackend>,
}

impl MarketPairPriceToOrderStore {
    pub const DB_NAME: &'static str = MARKET_PAIR_PRICE_TO_ORDER_DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    pub fn put(&self, key: &[u8], list: &MarketOrderIdList) -> Result<(), StoreError> {
        self.backend.put(key, &list.encode_to_vec())?;
        Ok(())
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<MarketOrderIdList>, StoreError> {
        let Some(bytes) = self.backend.get(key)? else {
            return Ok(None);
        };
        Ok(Some(MarketOrderIdList::decode(bytes.as_slice())?))
    }

    /// Scan every entry whose key starts with `prefix`. Used by
    /// `getMarketOrderListByPair` — the pair is the prefix and the
    /// remaining key bytes are the per-price suffix. Returns
    /// `(full_key, MarketOrderIdList)` pairs in lexicographic order
    /// (RocksDB native ordering).
    ///
    /// Uses the backend's native `scan_prefix` primitive — RocksDB
    /// seeks directly to the first matching key, so this is O(log N
    /// + result-size) rather than the old O(N) full-table scan. Real
    /// market pairs have very deep price ladders (~10k+ levels in
    /// the popular pairs), so the cursor matters once mainnet
    /// traffic starts hitting `getMarketOrderListByPair`.
    pub fn scan_prefix(
        &self,
        prefix: &[u8],
    ) -> Result<Vec<(Vec<u8>, MarketOrderIdList)>, StoreError> {
        self.backend
            .scan_prefix(prefix)?
            .into_iter()
            .map(|(k, v)| {
                MarketOrderIdList::decode(v.as_slice()).map(|list| (k, list))
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }
}

// === MarketPairToPriceStore =================================================

pub const MARKET_PAIR_TO_PRICE_DB_NAME: &str = "market_pair_to_price";

/// Per-trading-pair "best price" pointer. Key = pair bytes. Value =
/// 8-byte BE `i64` price-level counter (java-tron's `BytesCapsule`
/// wraps the result of `ByteArray.fromLong(number)`).
pub struct MarketPairToPriceStore {
    backend: Arc<dyn KvBackend>,
}

impl MarketPairToPriceStore {
    pub const DB_NAME: &'static str = MARKET_PAIR_TO_PRICE_DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    pub fn put(&self, pair_key: &[u8], count: i64) -> Result<(), StoreError> {
        self.backend.put(pair_key, &count.to_be_bytes())?;
        Ok(())
    }

    pub fn get(&self, pair_key: &[u8]) -> Result<Option<i64>, StoreError> {
        let Some(bytes) = self.backend.get(pair_key)? else {
            return Ok(None);
        };
        if bytes.len() != 8 {
            return Err(StoreError::InvalidValueLength {
                got: bytes.len(),
                expected: 8,
            });
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes);
        Ok(Some(i64::from_be_bytes(buf)))
    }

    /// Enumerate every `(pair_key, price_count)` pair. The pair_key is
    /// java-tron's `createPairKey(sellTokenId, buyTokenId)` =
    /// `sellTokenId(19) || buyTokenId(19)` (TOKEN_ID_LENGTH = 19, the
    /// decimal-string length of `Long.MAX_VALUE`). Used by
    /// `getMarketPairList`.
    pub fn all(&self) -> Result<Vec<(Vec<u8>, i64)>, StoreError> {
        Ok(self
            .backend
            .scan_all()?
            .into_iter()
            .filter_map(|(k, v)| {
                if v.len() != 8 {
                    // C-8: market price-counts are i64 (8 bytes); any
                    // other length is corruption. Log, then skip.
                    tracing::error!(
                        store = "market-pair-price-to-order",
                        key = %hex::encode(&k),
                        value_len = v.len(),
                        "skipping market-pair row whose value isn't an 8-byte count"
                    );
                    return None;
                }
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&v);
                Some((k, i64::from_be_bytes(buf)))
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MemBackend;

    fn pair_prefix(label: u8) -> Vec<u8> {
        // Synthesised 38-byte pair key (matching java-tron's 19+19
        // sellTokenId/buyTokenId layout). The first byte varies so
        // different test pairs don't collide.
        let mut p = vec![label; 38];
        p[0] = label;
        p
    }

    fn price_key(pair: &[u8], price_marker: u8) -> Vec<u8> {
        let mut k = pair.to_vec();
        // Append a single-byte price suffix — keeps tests readable.
        k.push(price_marker);
        k
    }

    #[test]
    fn scan_prefix_returns_only_matching_pair_orders_in_order() {
        let backend: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
        let store = MarketPairPriceToOrderStore::new(backend);

        let pair_a = pair_prefix(0xaa);
        let pair_b = pair_prefix(0xbb);

        store.put(&price_key(&pair_a, 0x05), &MarketOrderIdList::default()).unwrap();
        store.put(&price_key(&pair_a, 0x10), &MarketOrderIdList::default()).unwrap();
        store.put(&price_key(&pair_a, 0x20), &MarketOrderIdList::default()).unwrap();
        // Different pair — must NOT appear in the pair_a scan.
        store.put(&price_key(&pair_b, 0x05), &MarketOrderIdList::default()).unwrap();

        let got = store.scan_prefix(&pair_a).expect("scan");
        assert_eq!(got.len(), 3, "exactly 3 pair_a price levels");

        // Lexicographic order — the 0x05/0x10/0x20 markers come back
        // sorted, which matters for the price ladder semantics that
        // java-tron's getMarketOrderListByPair relies on.
        let suffixes: Vec<u8> = got.iter().map(|(k, _)| *k.last().unwrap()).collect();
        assert_eq!(suffixes, vec![0x05, 0x10, 0x20]);
    }

    #[test]
    fn scan_prefix_returns_empty_for_unknown_pair() {
        let backend: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
        let store = MarketPairPriceToOrderStore::new(backend);
        let pair = pair_prefix(0xaa);
        store.put(&price_key(&pair, 0x05), &MarketOrderIdList::default()).unwrap();

        let other = pair_prefix(0xff);
        let got = store.scan_prefix(&other).expect("scan");
        assert!(got.is_empty(), "no entries for unknown pair");
    }
}
