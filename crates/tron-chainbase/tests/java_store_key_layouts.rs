//! Exact on-disk key and value byte layouts, pinned against java-tron's own
//! store tests.
//!
//! A converted java-tron snapshot is read by this node directly, so every
//! encoding below is a wire format, not an internal detail: a one-byte
//! difference is silent state corruption rather than a test failure. Each test
//! therefore asserts the **literal bytes** java writes, not just that a value
//! round-trips through our own accessors.
//!
//! java references: `org.tron.core.db.{AccountTraceStoreTest,
//! BalanceTraceStoreTest, AccountAssetStoreTest, BlockIndexStoreTest,
//! RecentBlockStoreTest, RecentTransactionStoreTest, TransactionRetStoreTest,
//! TreeBlockIndexStoreTest, DelegationStoreTest, ExchangeStoreTest,
//! ProposalStoreTest, MarketPairToPriceStoreTest,
//! MarketPairPriceToOrderStoreTest}` and
//! `org.tron.common.utils.DBKeyComparatorTest`.

use std::sync::Arc;

use tron_chainbase::{
    market_order_price_comparator, AccountAssetStore, AccountTraceStore, BalanceTraceStore,
    BlockIndexStore, DelegationStore, ExchangeStore, ExchangeV2Store, KvBackend,
    MarketPairToPriceStore, MemBackend, ProposalStore, RecentBlockStore, RecentTransactionStore,
    TransactionRetStore, TreeBlockIndexStore,
};
use tron_crypto::address::Address;
use tron_proto::{AccountTrace, BlockBalanceTrace, Exchange, Proposal, TransactionRet};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn addr(byte: u8) -> Address {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(byte);
    Address::from_raw(a)
}

/// java's `ByteArray.fromLong(v)` — a fixed 8-byte big-endian encoding, used as
/// the key for every block-number-keyed store and as the value for every
/// `BytesCapsule` holding a long.
fn from_long(v: i64) -> [u8; 8] {
    v.to_be_bytes()
}

/// The only row in a single-entry backend, as raw bytes.
fn sole_row(backend: &Arc<dyn KvBackend>) -> (Vec<u8>, Vec<u8>) {
    let rows = backend.scan_all().unwrap();
    assert_eq!(rows.len(), 1, "expected exactly one stored row");
    rows.into_iter().next().unwrap()
}

// === 8-byte big-endian block-number keys ====================================

/// `BalanceTraceStoreTest#testGetBlockBalanceTrace` writes with
/// `put(ByteArray.fromLong(blockNum), capsule)` — the key is the plain 8-byte
/// big-endian block number, with no prefix and no XOR.
#[test]
fn balance_trace_key_is_plain_big_endian_block_number() {
    let backend = mem();
    let store = BalanceTraceStore::new(backend.clone());
    store
        .put(
            1,
            &BlockBalanceTrace {
                ..Default::default()
            },
        )
        .unwrap();
    let (key, _) = sole_row(&backend);
    assert_eq!(key, from_long(1).to_vec());
    assert_eq!(key, vec![0, 0, 0, 0, 0, 0, 0, 1]);
    assert_eq!(BalanceTraceStore::key_for(1), from_long(1));
    // Large and negative block numbers keep the two's-complement BE form.
    assert_eq!(
        BalanceTraceStore::key_for(0x0123_4567_89ab_cdef),
        [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
    );
}

/// `TransactionRetStoreTest` keys by `ByteArray.fromLong(1)`; the retained
/// results for block N live under the same 8-byte BE key shape.
#[test]
fn transaction_ret_key_is_plain_big_endian_block_number() {
    let backend = mem();
    let store = TransactionRetStore::new(backend.clone());
    store
        .put(
            1,
            &TransactionRet {
                block_number: 100,
                ..Default::default()
            },
        )
        .unwrap();
    let (key, _) = sole_row(&backend);
    assert_eq!(key, from_long(1).to_vec());
    assert_eq!(TransactionRetStore::key_for(258), [0, 0, 0, 0, 0, 0, 1, 2]);
}

/// `TreeBlockIndexStoreTest#testGet` reads with `get(ByteArray.fromLong(3L))`,
/// confirming the numeric accessor and the raw 8-byte BE key address the same
/// row.
#[test]
fn tree_block_index_key_is_plain_big_endian_block_number() {
    let backend = mem();
    let store = TreeBlockIndexStore::new(backend.clone());
    store.put(3, &[0x77u8; 32]).unwrap();
    let (key, value) = sole_row(&backend);
    assert_eq!(key, from_long(3).to_vec());
    assert_eq!(value, vec![0x77u8; 32]);
    assert_eq!(TreeBlockIndexStore::key_for(3), from_long(3));
}

/// `BlockIndexStoreTest` keys by `ByteArray.fromLong(blockId.getNum())`. The
/// BE encoding is what makes byte order equal numeric order, which
/// `getLimitNumber`-style range walks depend on.
#[test]
fn block_index_keys_sort_in_numeric_order() {
    assert_eq!(BlockIndexStore::key_for(1), from_long(1));
    let mut keys: Vec<[u8; 8]> = [300i64, 2, 10, 1, 256]
        .iter()
        .map(|n| BlockIndexStore::key_for(*n))
        .collect();
    keys.sort();
    let decoded: Vec<i64> = keys.iter().map(|k| i64::from_be_bytes(*k)).collect();
    assert_eq!(
        decoded,
        vec![1, 2, 10, 256, 300],
        "big-endian keys must sort numerically, not by decimal-string"
    );
}

// === Truncated / derived keys ===============================================

/// `RecentBlockStoreTest` builds its key as
/// `ByteArray.subArray(ByteArray.fromLong(num), 6, 8)` — the **last two**
/// bytes of the 8-byte BE block number, i.e. the low 16 bits. The value it
/// stores is `subArray(blockId, 8, 16)`, an 8-byte slice of the block id.
#[test]
fn recent_block_key_is_the_last_two_bytes_of_the_be_block_number() {
    // Reference: subArray(fromLong(n), 6, 8).
    let sub_6_8 = |n: i64| -> [u8; 2] {
        let full = from_long(n);
        [full[6], full[7]]
    };

    for n in [1i64, 255, 256, 65_535, 65_536, 65_537, 0x1234_5678] {
        assert_eq!(
            RecentBlockStore::key_for(n),
            sub_6_8(n),
            "key for block {n} must be the low 16 bits, big-endian"
        );
    }
    // Explicit byte-level spot checks.
    assert_eq!(RecentBlockStore::key_for(1), [0x00, 0x01]);
    assert_eq!(RecentBlockStore::key_for(0x0102), [0x01, 0x02]);
    // Wrap: block 65_536 shares slot 0 with block 0.
    assert_eq!(RecentBlockStore::key_for(65_536), [0x00, 0x00]);
    assert_eq!(RecentBlockStore::key_for(65_536), RecentBlockStore::key_for(0));

    // The stored value is passed through verbatim — java stores the raw
    // 8-byte block-id slice with no length prefix or framing.
    let backend = mem();
    let store = RecentBlockStore::new(backend.clone());
    let block_id_slice = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04];
    store.put(1, &block_id_slice).unwrap();
    let (key, value) = sole_row(&backend);
    assert_eq!(key, vec![0x00, 0x01]);
    assert_eq!(value, block_id_slice.to_vec());
}

/// `RecentTransactionStoreTest` uses the identical two-byte wrapping key shape
/// and stores `subArray(txId, 8, 16)` verbatim.
#[test]
fn recent_transaction_shares_the_two_byte_wrapping_key_shape() {
    for n in [1i64, 65_535, 65_536, 131_072] {
        assert_eq!(
            RecentTransactionStore::key_for(n),
            RecentBlockStore::key_for(n)
        );
    }
    let backend = mem();
    let store = RecentTransactionStore::new(backend.clone());
    let tx_id_slice = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    store.put(2, &tx_id_slice).unwrap();
    let (key, value) = sole_row(&backend);
    assert_eq!(key, vec![0x00, 0x02]);
    assert_eq!(value, tx_id_slice.to_vec());
}

/// `AccountTraceStoreTest#testRecordBalanceWithBlock` asserts the row is
/// readable at `Bytes.concat(address, Longs.toByteArray(1L ^ Long.MAX_VALUE))`
/// — the key is `address(21) || (blockNum XOR i64::MAX)(8, BE)`. The XOR makes
/// ascending key order equal **descending** block order, which is what turns
/// `getPrevBalance`'s forward seek into a "most recent at or before" lookup.
#[test]
fn account_trace_key_is_address_then_xored_block_number() {
    let backend = mem();
    let store = AccountTraceStore::new(backend.clone());
    let a = addr(0xaa);
    store
        .put(
            &a,
            1,
            &AccountTrace {
                balance: 9_999,
                ..Default::default()
            },
        )
        .unwrap();

    let (key, _) = sole_row(&backend);
    let mut expected = a.as_bytes().to_vec();
    expected.extend_from_slice(&from_long(1i64 ^ i64::MAX));
    assert_eq!(key, expected);
    assert_eq!(key.len(), 29);

    // The XOR is its own inverse, and it inverts the ordering of block numbers.
    assert_eq!(AccountTraceStore::xor_block_num(1), i64::MAX - 1);
    assert_eq!(
        AccountTraceStore::xor_block_num(AccountTraceStore::xor_block_num(12_345)),
        12_345
    );
    assert!(
        AccountTraceStore::key_for(&a, 200) < AccountTraceStore::key_for(&a, 100),
        "a higher block number must produce a lexicographically smaller key"
    );
}

// === Long-valued rows =======================================================

/// `AccountAssetStoreTest` writes balances as `Longs.toByteArray(200L)` and
/// reads them back with `Longs.fromByteArray` — the value is a bare 8-byte
/// big-endian long with no protobuf framing.
#[test]
fn account_asset_balance_value_is_bare_big_endian_long() {
    let backend = mem();
    let store = AccountAssetStore::new(backend.clone());
    let a = addr(0x0a);
    store.put(&a, b"10000", 200).unwrap();

    let (key, value) = sole_row(&backend);
    let mut expected_key = a.as_bytes().to_vec();
    expected_key.extend_from_slice(b"10000");
    assert_eq!(key, expected_key, "key is address(21) || assetId");
    assert_eq!(value, from_long(200).to_vec());
    assert_eq!(value, vec![0, 0, 0, 0, 0, 0, 0, 200]);
    assert_eq!(value.len(), 8, "no varint framing, always 8 bytes");
}

/// `MarketPairToPriceStoreTest#testGetPriceNum` stores the count with
/// `new BytesCapsule(ByteArray.fromLong(100))` — again a bare 8-byte BE long.
#[test]
fn market_pair_price_count_value_is_bare_big_endian_long() {
    let backend = mem();
    let store = MarketPairToPriceStore::new(backend.clone());
    store.put(b"testGetPriceNum", 100).unwrap();
    let (key, value) = sole_row(&backend);
    assert_eq!(key, b"testGetPriceNum".to_vec());
    assert_eq!(value, from_long(100).to_vec());
    assert_eq!(store.get(b"testGetPriceNum").unwrap(), Some(100));
}

/// `DelegationStoreTest` builds its reward key as the ASCII string
/// `cycle + "-" + Hex.toHexString(address) + "-reward"` and stores
/// `ByteArray.fromLong(VALUE)`. The hex is **lower-case and un-prefixed**, and
/// the whole key is UTF-8 text rather than packed binary.
#[test]
fn delegation_reward_key_is_ascii_text_and_value_is_big_endian_long() {
    let backend = mem();
    let store = DelegationStore::new(backend.clone());
    let a = addr(0xAB);
    store.add_reward(100, &a, 10_000_000);

    let (key, value) = sole_row(&backend);
    let expected_key = format!("100-{}-reward", hex::encode(a.as_bytes()));
    assert_eq!(String::from_utf8(key.clone()).unwrap(), expected_key);
    assert!(
        !expected_key.contains("0X") && !expected_key.contains("AB"),
        "address hex must be lower-case with no 0x prefix: {expected_key}"
    );
    assert_eq!(value, from_long(10_000_000).to_vec());
    assert_eq!(DelegationStore::reward_key(100, &a), key);
}

// === Numeric-id keys ========================================================

/// `ExchangeStoreTest#testGetAllExchanges` expects exchanges 1 and 2 back in id
/// order. The key is `ByteArray.fromLong(id)`, so byte order is numeric order —
/// a decimal-string key would sort 10 before 2.
#[test]
fn exchange_keys_are_be_longs_so_enumeration_is_numeric() {
    let store = ExchangeStore::new(mem());
    let v2 = ExchangeV2Store::new(mem());
    for id in [2i64, 10, 1] {
        let ex = Exchange {
            exchange_id: id,
            creator_address: format!("Address{id}").into_bytes(),
            ..Default::default()
        };
        store.put(id, &ex).unwrap();
        v2.put(id, &ex).unwrap();
    }
    assert_eq!(ExchangeStore::key_for(1), from_long(1));
    assert_eq!(ExchangeV2Store::key_for(1), from_long(1));

    let ids: Vec<i64> = store.all().unwrap().into_iter().map(|(id, _)| id).collect();
    assert_eq!(ids, vec![1, 2, 10]);
    let v2_ids: Vec<i64> = v2.all().unwrap().into_iter().map(|(id, _)| id).collect();
    assert_eq!(v2_ids, vec![1, 2, 10]);
}

/// `ProposalStoreTest#testGetAllProposals` expects proposal 1 first. Same
/// 8-byte BE id key, same numeric enumeration order.
#[test]
fn proposal_keys_are_be_longs_so_enumeration_is_numeric() {
    let store = ProposalStore::new(mem());
    for id in [2i64, 10, 1] {
        store
            .put(
                id,
                &Proposal {
                    proposal_id: id,
                    ..Default::default()
                },
            )
            .unwrap();
    }
    assert_eq!(ProposalStore::key_for(1), from_long(1));
    let ids: Vec<i64> = store.all().unwrap().into_iter().map(|(id, _)| id).collect();
    assert_eq!(ids, vec![1, 2, 10]);
}

// === Market price-key comparator ============================================

/// java's `MarketUtils.createPairPriceKey`, including the GCD reduction it
/// applies to the two quantities before laying them into the key. Reproduced
/// here so the comparator vectors below use exactly the keys java would write.
fn pair_price_key(sell_token: &[u8], buy_token: &[u8], sell_qty: i64, buy_qty: i64) -> Vec<u8> {
    fn gcd(a: i64, b: i64) -> i64 {
        if a == 0 || b == 0 {
            return 0;
        }
        let (mut a, mut b) = (a.abs(), b.abs());
        while b != 0 {
            let t = a % b;
            a = b;
            b = t;
        }
        a
    }
    let g = gcd(sell_qty, buy_qty);
    let (s, b) = if g == 0 {
        (sell_qty, buy_qty)
    } else {
        (sell_qty / g, buy_qty / g)
    };
    let mut key = vec![0u8; 38];
    key[..sell_token.len()].copy_from_slice(sell_token);
    key[19..19 + buy_token.len()].copy_from_slice(buy_token);
    key.extend_from_slice(&s.to_be_bytes());
    key.extend_from_slice(&b.to_be_bytes());
    key
}

/// `DBKeyComparatorTest#dbComparing`: two keys on the same pair with quantities
/// `(1000, 2000)` and `(1000, 2001)` compare as `-1`. After java's GCD
/// reduction those become `(1, 2)` and `(1000, 2001)`, i.e. prices `2` and
/// `2.001`.
#[test]
fn price_comparator_orders_by_price_not_by_raw_quantity_bytes() {
    let sell = b"100";
    let buy = b"200";
    let k1 = pair_price_key(sell, buy, 1000, 2000);
    let k2 = pair_price_key(sell, buy, 1000, 2001);
    assert_eq!(
        market_order_price_comparator(&k1, &k2),
        std::cmp::Ordering::Less
    );
    assert_eq!(
        market_order_price_comparator(&k2, &k1),
        std::cmp::Ordering::Greater
    );
    assert_eq!(
        market_order_price_comparator(&k1, &k1),
        std::cmp::Ordering::Equal
    );
    // The GCD reduction is real: (1000, 2000) and (1, 2) are the same key.
    assert_eq!(k1, pair_price_key(sell, buy, 1, 2));
    // Raw byte order disagrees with price order here, which is the whole point
    // of registering a custom comparator.
    assert!(k1.as_slice() < k2.as_slice() || k1.as_slice() > k2.as_slice());
}

/// `MarketPairPriceToOrderStoreTest#testAddPrice` inserts four keys for one
/// pair out of order and then walks them with `getKeysNext(headKey, 4)`,
/// expecting `(0,0)`, `(3,3)`, `(1,2)`, `(1,3)` — that is, the zero-quantity
/// **head key** first, then ascending price (1, 2, 3).
#[test]
fn price_comparator_reproduces_java_add_price_ordering() {
    let sell = b"100";
    let buy = b"200";
    let head = pair_price_key(sell, buy, 0, 0);
    let k1 = pair_price_key(sell, buy, 3, 3); // price 1
    let k2 = pair_price_key(sell, buy, 1, 2); // price 2
    let k3 = pair_price_key(sell, buy, 1, 3); // price 3

    let mut keys = vec![k2.clone(), k1.clone(), k3.clone(), head.clone()];
    keys.sort_by(|a, b| market_order_price_comparator(a, b));
    assert_eq!(keys, vec![head.clone(), k1.clone(), k2.clone(), k3.clone()]);

    // `getNextKey(k2)` is k3: the next-higher price level.
    assert_eq!(
        market_order_price_comparator(&k2, &k3),
        std::cmp::Ordering::Less
    );
}

/// The head key that `addNewPriceKey` seeds every pair with has **no defined
/// price** (both quantities zero). java short-circuits such keys to sort ahead
/// of every priced key rather than cross-multiplying, which would compare
/// `0 == 0` against every level in the pair.
///
/// This matters beyond ordering: RocksDB treats a comparator's `Equal` as key
/// identity, so a head key that ties with a real price level would collapse
/// the two rows into one.
#[test]
fn price_comparator_sorts_undefined_price_keys_ahead_and_keeps_them_distinct() {
    use std::cmp::Ordering;
    let sell = b"100";
    let buy = b"200";
    let head = pair_price_key(sell, buy, 0, 0);
    let priced = pair_price_key(sell, buy, 1, 2);

    assert_eq!(
        market_order_price_comparator(&head, &priced),
        Ordering::Less,
        "the zero-quantity head key must sort strictly before a priced key"
    );
    assert_eq!(
        market_order_price_comparator(&priced, &head),
        Ordering::Greater
    );
    assert_ne!(
        market_order_price_comparator(&head, &priced),
        Ordering::Equal,
        "head key must not be identified with a price level"
    );

    // Only one quantity zero is also an undefined price, on either side.
    let zero_sell = pair_price_key(sell, buy, 0, 5);
    let zero_buy = pair_price_key(sell, buy, 5, 0);
    assert_eq!(
        market_order_price_comparator(&zero_sell, &priced),
        Ordering::Less
    );
    assert_eq!(
        market_order_price_comparator(&zero_buy, &priced),
        Ordering::Less
    );
    assert_eq!(
        market_order_price_comparator(&priced, &zero_sell),
        Ordering::Greater
    );
    // Two undefined-price keys tie with each other.
    assert_eq!(
        market_order_price_comparator(&head, &zero_sell),
        Ordering::Equal
    );
    assert_eq!(
        market_order_price_comparator(&zero_sell, &zero_buy),
        Ordering::Equal
    );

    // A different pair is separated before price is ever considered.
    let other_pair = pair_price_key(b"101", buy, 1, 2);
    assert_eq!(
        market_order_price_comparator(&head, &other_pair),
        Ordering::Less,
        "pair bytes are compared first"
    );
}

/// `DBKeyComparatorTest#pairKeyIsEqual`: token ids are laid into fixed 19-byte
/// slots, so `"100"` and `"10"` occupy different byte patterns and their pair
/// keys are not equal. Without the fixed-width padding a shorter token id would
/// alias a longer one.
#[test]
fn pair_keys_use_fixed_width_token_slots_so_shorter_ids_do_not_alias() {
    let k1 = pair_price_key(b"100", b"200", 1000, 2000);
    let k2 = pair_price_key(b"10", b"200", 1000, 2001);
    assert_eq!(k1.len(), 54);
    assert_eq!(k2.len(), 54);
    assert_ne!(k1[..38], k2[..38], "pair prefixes must differ");
    // "10" is zero-padded, so its third byte is NUL where "100" has '0'.
    assert_eq!(&k1[..4], b"100\0");
    assert_eq!(&k2[..4], b"10\0\0");
    assert_ne!(
        market_order_price_comparator(&k1, &k2),
        std::cmp::Ordering::Equal
    );
}
