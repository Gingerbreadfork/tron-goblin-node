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

use std::cmp::Ordering;
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

// === MarketOrderPriceComparator =============================================
//
// java-tron does NOT open `market_pair_price_to_order` with the default
// bytewise comparator — it registers a custom RocksDB comparator named
// `MarketOrderPriceComparator` (port of `MarketUtils.comparePriceKey`).
// RocksDB persists that name in the store's MANIFEST and refuses to open
// unless the comparator we supply reports an identical name, so we MUST
// re-register an equivalent one. Two reasons it has to be byte-exact:
//
//   1. Open-time: name mismatch → `does not match existing comparator`.
//   2. Read correctness: the SSTs were physically ordered by this
//      comparator, and RocksDB binary-searches data/index blocks with it.
//      Any disagreement with java-tron's ordering makes lookups silently
//      miss keys — not an error, just wrong reads.
//
// Because the order book is grouped by trading pair (the comparator sorts
// by pair bytes first), registering it also makes `scan_prefix`'s seek +
// `starts_with` walk return each pair's price ladder in true price order
// rather than lexicographic order — which is what java-tron's matching
// engine and `getMarketOrderListByPair` rely on.

/// java-tron's RocksDB comparator name for `market_pair_price_to_order`,
/// as stored in that store's MANIFEST. The registered comparator must
/// report exactly this or RocksDB refuses the open.
pub const MARKET_ORDER_PRICE_COMPARATOR_NAME: &str = "MarketOrderPriceComparator";

/// One token-id field in a market pair key is fixed at the decimal-string
/// length of `Long.MAX_VALUE` (9223372036854775807 → 19 chars), matching
/// java-tron's `MarketUtils.TOKEN_ID_LENGTH`.
const TOKEN_ID_LENGTH: usize = 19;
/// A market pair key is `sellTokenId(19) || buyTokenId(19)`.
const PAIR_KEY_LEN: usize = TOKEN_ID_LENGTH * 2; // 38
/// A full price key appends `sellQuantity(8) || buyQuantity(8)`, each a
/// big-endian `i64` (java-tron's `ByteArray.fromLong`).
const SELL_QTY_OFF: usize = PAIR_KEY_LEN; // 38
const BUY_QTY_OFF: usize = PAIR_KEY_LEN + 8; // 46

/// Port of java-tron's `MarketUtils.comparePriceKey` — the ordering the
/// `market_pair_price_to_order` SSTs were written with.
///
/// Key layout: `pair(38) || sellQuantity(8 BE) || buyQuantity(8 BE)`.
/// Ordering: the 38-byte pair prefix lexicographically first (so all
/// orders for one pair stay contiguous); within a pair, by price, where
/// price = `buyQuantity / sellQuantity` compared via cross-multiplication
/// (`buy1*sell2` vs `buy2*sell1`). i128 holds any `i64 * i64` product
/// exactly, so — unlike java-tron's `long` path — there is never an
/// overflow that needs a `BigInteger` fallback; the result is identical.
///
/// **Zero-quantity keys sort first.** Before comparing prices java-tron
/// short-circuits any key whose sell *or* buy quantity is zero: two such
/// keys compare equal, and one such key is always less than a key with
/// both quantities non-zero. This is not an edge case — `addNewPriceKey`
/// seeds every trading pair with the head key
/// `createPairPriceKey(sell, buy, 0, 0)`, whose price is undefined. Without
/// the short-circuit the cross-multiplication yields `0 == 0` for the head
/// key against *every* price level in its pair, and RocksDB — which treats
/// a comparator's `Equal` as key identity — would collapse them into one
/// row.
///
/// Robust to short keys: a bare 38-byte pair prefix (used as a seek
/// target by [`MarketPairPriceToOrderStore::scan_prefix`]) reads its
/// absent quantities as 0, so the zero-quantity rule places it before
/// every full key of the same pair and the seek lands on that pair's
/// first entry — exactly where the ladder walk must start.
pub fn market_order_price_comparator(a: &[u8], b: &[u8]) -> Ordering {
    // 1. Trading pair, unsigned-byte lexicographic (java's FastByteComparisons
    //    and Rust's slice `cmp` both treat bytes as unsigned — they agree).
    let pa = &a[..PAIR_KEY_LEN.min(a.len())];
    let pb = &b[..PAIR_KEY_LEN.min(b.len())];
    match pa.cmp(pb) {
        Ordering::Equal => {}
        non_eq => return non_eq,
    }
    // 2. Same pair → compare by price via cross-multiplication.
    let buy1 = read_be_i64(a, BUY_QTY_OFF) as i128;
    let sell1 = read_be_i64(a, SELL_QTY_OFF) as i128;
    let buy2 = read_be_i64(b, BUY_QTY_OFF) as i128;
    let sell2 = read_be_i64(b, SELL_QTY_OFF) as i128;
    // 2a. Keys with an undefined price (either quantity zero) sort ahead of
    //     every priced key, and tie with each other.
    let undefined1 = sell1 == 0 || buy1 == 0;
    let undefined2 = sell2 == 0 || buy2 == 0;
    match (undefined1, undefined2) {
        (true, true) => return Ordering::Equal,
        (true, false) => return Ordering::Less,
        (false, true) => return Ordering::Greater,
        (false, false) => {}
    }
    (buy1 * sell2).cmp(&(buy2 * sell1))
}

/// The custom RocksDB comparator a java-tron store directory requires, if
/// any, keyed by its directory name. Centralises the
/// `market_pair_price_to_order` special-case so every open path — the live
/// store opener (`storage::open_store`), live snapshot import (secondary
/// read + read-write write), and checkpoint export — registers the same
/// comparator and never trips RocksDB's MANIFEST comparator-name check.
pub fn comparator_for_store(name: &str) -> Option<(&'static str, fn(&[u8], &[u8]) -> Ordering)> {
    if name == MARKET_PAIR_PRICE_TO_ORDER_DB_NAME {
        Some((MARKET_ORDER_PRICE_COMPARATOR_NAME, market_order_price_comparator))
    } else {
        None
    }
}

/// Read an 8-byte big-endian `i64` at `off`, treating any bytes past the
/// end of `key` as zero. Mirrors java-tron's `ByteArray.toLong(
/// Arrays.copyOfRange(key, off, off + 8))`, whose `copyOfRange` zero-fills
/// (right-pads) when the source runs short — the case that arises only for
/// the 38-byte pair-prefix seek target, never for a stored 54-byte key.
fn read_be_i64(key: &[u8], off: usize) -> i64 {
    let mut buf = [0u8; 8];
    let end = (off + 8).min(key.len());
    if off < end {
        let avail = &key[off..end];
        buf[..avail.len()].copy_from_slice(avail);
    }
    i64::from_be_bytes(buf)
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

        // This is the `MemBackend` (bytewise) path, so the synthetic
        // single-byte suffixes come back lexicographically. The real
        // RocksDB store is opened with `market_order_price_comparator`
        // and returns each pair's ladder in *price* order — see the
        // `market_order_price_comparator_*` unit tests and the
        // `market_pair_price_to_order_*` RocksDB end-to-end test.
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

    // --- MarketOrderPriceComparator -----------------------------------------

    /// Build a full 54-byte price key: `pair(38) || sell(8 BE) || buy(8 BE)`.
    fn full_price_key(pair_label: u8, sell: i64, buy: i64) -> Vec<u8> {
        let mut k = vec![pair_label; PAIR_KEY_LEN];
        k.extend_from_slice(&sell.to_be_bytes());
        k.extend_from_slice(&buy.to_be_bytes());
        k
    }

    #[test]
    fn market_order_price_comparator_orders_same_pair_by_ascending_price() {
        // price = buy / sell. Insert deliberately out of price order.
        let mut keys = vec![
            full_price_key(0xaa, 10, 20), // 2.0
            full_price_key(0xaa, 20, 10), // 0.5
            full_price_key(0xaa, 10, 15), // 1.5
            full_price_key(0xaa, 10, 10), // 1.0
        ];
        keys.sort_by(|a, b| market_order_price_comparator(a, b));
        // Expected ascending price: 0.5, 1.0, 1.5, 2.0 → identified by buy/sell.
        let prices: Vec<(i64, i64)> = keys
            .iter()
            .map(|k| (read_be_i64(k, SELL_QTY_OFF), read_be_i64(k, BUY_QTY_OFF)))
            .collect();
        assert_eq!(prices, vec![(20, 10), (10, 10), (10, 15), (10, 20)]);
    }

    #[test]
    fn market_order_price_comparator_orders_by_pair_before_price() {
        // pair 0xaa with a very high price must still sort before pair 0xbb
        // with a very low price — the pair prefix dominates.
        let a = full_price_key(0xaa, 1, i64::MAX); // huge price, pair aa
        let b = full_price_key(0xbb, i64::MAX, 1); // tiny price, pair bb
        assert_eq!(market_order_price_comparator(&a, &b), Ordering::Less);
        assert_eq!(market_order_price_comparator(&b, &a), Ordering::Greater);
    }

    #[test]
    fn market_order_price_comparator_treats_equal_ratios_as_equal() {
        // 2/1 and 4/2 are the same price — java-tron's comparator returns 0,
        // and so must ours (java-tron canonicalises so two such keys never
        // actually coexist; we just have to agree on the ordering).
        let a = full_price_key(0xaa, 1, 2);
        let b = full_price_key(0xaa, 2, 4);
        assert_eq!(market_order_price_comparator(&a, &b), Ordering::Equal);
    }

    #[test]
    fn market_order_price_comparator_is_exact_for_huge_quantities() {
        // Cross-multiplication of two i64 near MAX overflows i64 (java-tron
        // falls back to BigInteger here); our i128 path is exact with no
        // fallback. buy/sell: (MAX-1)/MAX  <  MAX/MAX.
        let a = full_price_key(0xaa, i64::MAX, i64::MAX - 1);
        let b = full_price_key(0xaa, i64::MAX, i64::MAX);
        assert_eq!(market_order_price_comparator(&a, &b), Ordering::Less);
        assert_eq!(market_order_price_comparator(&b, &a), Ordering::Greater);
        // Same numbers → equal, no panic.
        assert_eq!(market_order_price_comparator(&a, &a), Ordering::Equal);
    }

    #[test]
    fn market_order_price_comparator_bare_pair_prefix_seeks_to_ladder_head() {
        // A bare 38-byte pair prefix is what `scan_prefix` seeks with. Its
        // absent quantities read as zero, so the undefined-price rule places
        // it strictly before every full key of the same pair — the RocksDB
        // seek therefore lands on that pair's first entry — while pair bytes
        // still order it against other pairs.
        let prefix = vec![0xaa; PAIR_KEY_LEN];
        let same_pair = full_price_key(0xaa, 7, 3);
        assert_eq!(
            market_order_price_comparator(&prefix, &same_pair),
            Ordering::Less,
            "bare prefix sorts at the head of its own pair's ladder"
        );
        let later_pair = full_price_key(0xbb, 1, 1);
        assert_eq!(market_order_price_comparator(&prefix, &later_pair), Ordering::Less);
        let earlier_pair = full_price_key(0x09, 1, 1);
        assert_eq!(market_order_price_comparator(&prefix, &earlier_pair), Ordering::Greater);
    }
}
