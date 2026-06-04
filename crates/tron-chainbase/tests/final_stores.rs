//! Tests for the final batch of stores (22 of them). Focus is on the
//! per-store traps — directory-name casing, key encoding tricks (xor,
//! hex string, lowercase normalisation), no-op puts, set-style writes.

use std::sync::Arc;

use hex_literal::hex;
use tron_chainbase::{
    AccountAssetStore, AccountIdIndexStore, AccountTraceStore, BalanceTraceStore,
    CheckPointV2Store, CheckTmpStore, CommonStore, ContractStateStore, IncrementalMerkleTreeStore,
    KvBackend, MarketAccountStore, MarketOrderStore, MarketPairPriceToOrderStore,
    MarketPairToPriceStore, MemBackend, NullifierStore, PbftSignDataStore, RecentTransactionStore,
    RewardViStore, SectionBloomStore, TransactionHistoryStore, TransactionRetStore,
    TreeBlockIndexStore, ZkProofStore,
};
use tron_crypto::address::Address;

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn alice() -> Address {
    Address::from_raw(hex!("412e988a386a799f506693793c6a5af6b54dfaabfb"))
}

// --- DB_NAME parity --------------------------------------------------------

/// **One pin per directory name.** Mis-spelling any of these silently
/// invalidates the on-disk layout when reading a java-tron data dir.
#[test]
fn db_names_match_java_tron_directories() {
    assert_eq!(RecentTransactionStore::DB_NAME, "recent-transaction");

    // CAMEL_CASE: these two are the only stores with camelCase names.
    assert_eq!(TransactionRetStore::DB_NAME, "transactionRetStore");
    assert_eq!(TransactionHistoryStore::DB_NAME, "transactionHistoryStore");

    assert_eq!(CommonStore::DB_NAME, "common");
    assert_eq!(PbftSignDataStore::DB_NAME, "pbft-sign-data");
    assert_eq!(TreeBlockIndexStore::DB_NAME, "tree-block-index");
    assert_eq!(AccountAssetStore::DB_NAME, "account-asset");
    assert_eq!(AccountIdIndexStore::DB_NAME, "accountid-index");
    assert_eq!(BalanceTraceStore::DB_NAME, "balance-trace");
    assert_eq!(AccountTraceStore::DB_NAME, "account-trace");
    assert_eq!(ContractStateStore::DB_NAME, "contract-state");

    // Market stores: underscores!
    assert_eq!(MarketAccountStore::DB_NAME, "market_account");
    assert_eq!(MarketOrderStore::DB_NAME, "market_order");
    assert_eq!(MarketPairPriceToOrderStore::DB_NAME, "market_pair_price_to_order");
    assert_eq!(MarketPairToPriceStore::DB_NAME, "market_pair_to_price");

    assert_eq!(CheckTmpStore::DB_NAME, "tmp");
    assert_eq!(RewardViStore::DB_NAME, "reward-vi");
    assert_eq!(SectionBloomStore::DB_NAME, "section-bloom");

    // PascalCase — the only one of its kind.
    assert_eq!(IncrementalMerkleTreeStore::DB_NAME, "IncrementalMerkleTree");

    assert_eq!(NullifierStore::DB_NAME, "nullifier");
}

#[test]
fn naming_conventions_are_inconsistent_pinned_for_visibility() {
    // Document the four naming styles in one place so a reader can see
    // them at a glance. Any port that "normalises" these will silently
    // break against java-tron.
    let kebab = ["recent-transaction", "pbft-sign-data", "tree-block-index",
                 "account-asset", "accountid-index", "balance-trace",
                 "account-trace", "contract-state", "reward-vi", "section-bloom"];
    let underscore = ["market_account", "market_order",
                      "market_pair_price_to_order", "market_pair_to_price"];
    let camel = ["transactionRetStore", "transactionHistoryStore"];
    let pascal = ["IncrementalMerkleTree"];
    let plain = ["common", "tmp", "nullifier"];

    assert_eq!(kebab.len(), 10);
    assert_eq!(underscore.len(), 4);
    assert_eq!(camel.len(), 2);
    assert_eq!(pascal.len(), 1);
    assert_eq!(plain.len(), 3);
}

// --- RecentTransactionStore -------------------------------------------------

#[test]
fn recent_transaction_uses_2byte_wrapping_key_like_recent_block() {
    assert_eq!(RecentTransactionStore::key_for(0), [0, 0]);
    assert_eq!(RecentTransactionStore::key_for(65_537), [0, 1]);
}

// --- PbftSignDataStore -----------------------------------------------------

/// **Critical key shape**: `"SRL" + decimal_epoch` (no separator!) and
/// `"BLOCK" + decimal_block_num`. Add a `:` or `_` between and the keys
/// no longer match what java-tron writes.
#[test]
fn pbft_sign_data_keys_concatenate_directly() {
    assert_eq!(PbftSignDataStore::sr_list_key(0), b"SRL0");
    assert_eq!(PbftSignDataStore::sr_list_key(42), b"SRL42");
    assert_eq!(PbftSignDataStore::block_key(0), b"BLOCK0");
    assert_eq!(PbftSignDataStore::block_key(1_000_000), b"BLOCK1000000");
}

/// **Critical byte layout**: `PbftCommitResult.signature` is persisted
/// in signer-address sort order. java-tron's `PbftSignCapsule`
/// serializer writes the signatures in the same order — if our output
/// differs, the on-disk capsule diverges and any future state-root
/// computation that hashes the commit-result will mismatch.
///
/// The store's API takes `&BTreeMap<Address, Vec<u8>>` to make the sort
/// invariant type-enforced (caller can't construct an unsorted input).
/// This test exercises that promise: building the map insertion order
/// at random has no effect on the on-disk byte layout.
#[test]
fn pbft_commit_result_persists_signatures_in_address_sort_order() {
    use std::collections::BTreeMap;
    use prost::Message as _;

    let store = PbftSignDataStore::new(mem());
    let key = PbftSignDataStore::block_key(100);
    let raw = tron_proto::pbft_message::Raw {
        msg_type: 0,
        data_type: 0,
        view_n: 0,
        epoch: 0,
        data: b"payload".to_vec(),
    };

    // Three distinct signer addresses, deliberately constructed with the
    // last byte controlling the sort key so the expected order is clear.
    let addr_aa = Address::from_raw(hex!("4100000000000000000000000000000000000000aa"));
    let addr_bb = Address::from_raw(hex!("4100000000000000000000000000000000000000bb"));
    let addr_cc = Address::from_raw(hex!("4100000000000000000000000000000000000000cc"));
    let sig_aa = vec![0xaa; 65];
    let sig_bb = vec![0xbb; 65];
    let sig_cc = vec![0xcc; 65];

    // Insert into the BTreeMap in reverse address order to prove
    // insertion order doesn't matter for on-disk layout.
    let mut sigs = BTreeMap::new();
    sigs.insert(addr_cc, sig_cc.clone());
    sigs.insert(addr_aa, sig_aa.clone());
    sigs.insert(addr_bb, sig_bb.clone());

    store.put_commit_result(&key, &raw, &sigs).unwrap();

    // Read back and confirm the on-disk byte order is address-sorted.
    let (_, persisted) = store.get_commit_result(&key).unwrap().unwrap();
    assert_eq!(persisted.len(), 3);
    assert_eq!(persisted[0], sig_aa); // 0x...aa
    assert_eq!(persisted[1], sig_bb); // 0x...bb
    assert_eq!(persisted[2], sig_cc); // 0x...cc

    // Belt-and-braces: re-write with the same logical content via a
    // DIFFERENT BTreeMap instance (rebuilt in yet another order) and
    // assert the raw on-disk bytes are byte-identical to the first
    // write. This is the property java-tron parity actually depends on.
    let backend1_bytes = {
        let backend = Arc::new(MemBackend::new());
        let store1 = PbftSignDataStore::new(backend.clone());
        let mut sigs1 = BTreeMap::new();
        sigs1.insert(addr_aa, sig_aa.clone());
        sigs1.insert(addr_bb, sig_bb.clone());
        sigs1.insert(addr_cc, sig_cc.clone());
        store1.put_commit_result(&key, &raw, &sigs1).unwrap();
        backend.get(&key).unwrap().unwrap()
    };
    let backend2_bytes = {
        let backend = Arc::new(MemBackend::new());
        let store2 = PbftSignDataStore::new(backend.clone());
        let mut sigs2 = BTreeMap::new();
        sigs2.insert(addr_bb, sig_bb.clone());
        sigs2.insert(addr_cc, sig_cc.clone());
        sigs2.insert(addr_aa, sig_aa.clone());
        store2.put_commit_result(&key, &raw, &sigs2).unwrap();
        backend.get(&key).unwrap().unwrap()
    };
    assert_eq!(
        backend1_bytes, backend2_bytes,
        "two writes of the same logical quorum (insertion-order varied) must \
         produce byte-identical PbftCommitResult bytes"
    );

    // And the persisted bytes must decode back to a `PbftCommitResult`
    // whose `signature` field is in the same address-sorted order.
    let decoded = tron_proto::PbftCommitResult::decode(backend1_bytes.as_slice()).unwrap();
    assert_eq!(decoded.signature[0][0], 0xaa);
    assert_eq!(decoded.signature[1][0], 0xbb);
    assert_eq!(decoded.signature[2][0], 0xcc);
}

// --- AccountAssetStore -----------------------------------------------------

#[test]
fn account_asset_key_is_address_then_asset_id_concatenated() {
    let k = AccountAssetStore::key_for(&alice(), b"1000001");
    assert_eq!(k.len(), 21 + 7);
    assert_eq!(&k[..21], alice().as_bytes());
    assert_eq!(&k[21..], b"1000001");
}

#[test]
fn account_asset_round_trip_balance() {
    let store = AccountAssetStore::new(mem());
    store.put(&alice(), b"1000001", 12345).unwrap();
    assert_eq!(store.get(&alice(), b"1000001").unwrap(), Some(12345));
    assert_eq!(store.get(&alice(), b"missing").unwrap(), None);
}

// --- AccountIdIndexStore ---------------------------------------------------

/// **Case-normalisation trap**: keys are lowercased on the way in.
/// Looking up "ALICE" must find an entry stored under "alice".
#[test]
fn account_id_index_normalises_to_lowercase() {
    assert_eq!(AccountIdIndexStore::normalize_id(b"Alice"), b"alice");
    assert_eq!(AccountIdIndexStore::normalize_id(b"BOB"), b"bob");
    // ASCII-clean is the practical case; pin it.

    let store = AccountIdIndexStore::new(mem());
    store.put(b"Alice", &alice()).unwrap();
    // Cross-case lookups all hit the same entry.
    assert_eq!(store.get(b"alice").unwrap().unwrap(), alice());
    assert_eq!(store.get(b"ALICE").unwrap().unwrap(), alice());
    assert_eq!(store.get(b"AlIcE").unwrap().unwrap(), alice());
}

// --- AccountTraceStore -----------------------------------------------------

/// **XOR-with-i64::MAX trick**: stores `block_num ^ i64::MAX`, so
/// ascending-key iteration in RocksDB yields descending block numbers.
#[test]
fn account_trace_xor_inverts_block_num() {
    assert_eq!(AccountTraceStore::xor_block_num(0), i64::MAX);
    assert_eq!(AccountTraceStore::xor_block_num(i64::MAX), 0);
    assert_eq!(AccountTraceStore::xor_block_num(1), i64::MAX - 1);
    // Critical property: ordering inverts (smaller block num → larger xor).
    assert!(AccountTraceStore::xor_block_num(1) > AccountTraceStore::xor_block_num(2));
}

#[test]
fn account_trace_key_is_address_then_xor_block_num_be() {
    let k = AccountTraceStore::key_for(&alice(), 42);
    assert_eq!(k.len(), 21 + 8);
    assert_eq!(&k[..21], alice().as_bytes());
    assert_eq!(&k[21..], &(42i64 ^ i64::MAX).to_be_bytes());
}

// --- SectionBloomStore -----------------------------------------------------

/// java-tron composes `section * 1_000_000 + bit_index` in **decimal**
/// (not a bit-shift), then renders the result with `Long.toHexString`
/// (no-leading-zero, lowercase).
#[test]
fn section_bloom_key_matches_java_decimal_composition() {
    assert_eq!(SectionBloomStore::key_for(0, 0), b"0");
    assert_eq!(SectionBloomStore::key_for(0, 1), b"1");
    assert_eq!(SectionBloomStore::key_for(0, 0x0f), b"f");
    assert_eq!(SectionBloomStore::key_for(0, 0x10), b"10");
    // Section 1, bit 0 = 1 * 1_000_000 = 1_000_000 = 0xF4240 → "f4240".
    assert_eq!(SectionBloomStore::key_for(1, 0), b"f4240");
    // Section 2, bit 5 = 2_000_005 = 0x1E_8485 → "1e8485".
    assert_eq!(SectionBloomStore::key_for(2, 5), b"1e8485");
}

// --- NullifierStore --------------------------------------------------------

/// **Set semantics**: java-tron stores the nullifier as both key and value.
/// Pin that — a port that uses a sentinel value would still pass
/// "contains" but produces different on-disk bytes.
#[test]
fn nullifier_stores_value_equal_to_key() {
    let backend = mem();
    let store = NullifierStore::new(backend.clone());
    let nf = [0xab; 32];
    store.put(&nf).unwrap();
    assert!(store.contains(&nf).unwrap());
    // The stored value bytes are the nullifier itself.
    let value = backend.get(&nf).unwrap().unwrap();
    assert_eq!(value.as_slice(), &nf);
}

// --- ZkProofStore ----------------------------------------------------------

#[test]
fn zk_proof_store_writes_single_byte_boolean() {
    let backend = mem();
    let store = ZkProofStore::new(backend.clone());
    store.put(b"proof-1", true).unwrap();
    store.put(b"proof-2", false).unwrap();
    assert_eq!(backend.get(b"proof-1").unwrap(), Some(vec![0x01]));
    assert_eq!(backend.get(b"proof-2").unwrap(), Some(vec![0x00]));
    assert_eq!(store.get(b"proof-1").unwrap(), Some(true));
    assert_eq!(store.get(b"proof-2").unwrap(), Some(false));
    // Unlike java-tron (which throws NPE), missing key → None.
    assert_eq!(store.get(b"missing").unwrap(), None);
}

// --- CheckTmpStore / CheckPointV2Store no-op puts ---------------------------

#[test]
fn check_tmp_put_is_no_op_matching_java_tron() {
    let backend = mem();
    let store = CheckTmpStore::new(backend.clone());
    store.put(b"key", b"value");
    // Java's put is empty-bodied, so nothing reaches the backend.
    assert_eq!(backend.get(b"key").unwrap(), None);
}

#[test]
fn checkpoint_v2_put_is_no_op_matching_java_tron() {
    let backend = mem();
    let store = CheckPointV2Store::new(backend.clone());
    store.put(b"key", b"value");
    assert_eq!(backend.get(b"key").unwrap(), None);
}

// --- Tree, Common, Reward-Vi simple round trips ----------------------------

#[test]
fn tree_block_index_round_trip() {
    let store = TreeBlockIndexStore::new(mem());
    let id = [0xcd; 32];
    store.put(42, &id).unwrap();
    assert_eq!(store.get(42).unwrap().unwrap(), id);
}

#[test]
fn common_store_round_trip() {
    let store = CommonStore::new(mem());
    store.put(b"chain-id", b"mainnet").unwrap();
    assert_eq!(store.get(b"chain-id").unwrap(), Some(b"mainnet".to_vec()));
}

#[test]
fn reward_vi_passes_bigint_bytes_through_unchanged() {
    let store = RewardViStore::new(mem());
    // A typical signed-big-endian BigInteger.toByteArray() payload —
    // small positive value with a leading zero for sign clarity.
    let bigint_bytes = vec![0x00, 0x80, 0x00, 0x00];
    store.put(b"cycle-42-witness-X-vi", &bigint_bytes).unwrap();
    assert_eq!(store.get(b"cycle-42-witness-X-vi").unwrap(), Some(bigint_bytes));
}

// --- Market stores: smoke tests on the underscore directories --------------

#[test]
fn market_pair_to_price_round_trip_be_long() {
    let backend = mem();
    let store = MarketPairToPriceStore::new(backend.clone());
    store.put(b"pair-AB", 1_000_000).unwrap();
    assert_eq!(store.get(b"pair-AB").unwrap(), Some(1_000_000));
    // Raw on-disk value is BE i64.
    assert_eq!(
        backend.get(b"pair-AB").unwrap().unwrap(),
        1_000_000_i64.to_be_bytes().to_vec()
    );
}

// --- ContractStateStore: per-contract dynamic-energy factor -----------------

#[test]
fn contract_state_store_dynamic_energy_factor_defaults_to_zero() {
    let backend = mem();
    let store = ContractStateStore::new(backend);
    let addr = Address::from_raw([0x41u8; 21]);
    // Never written → 0.
    assert_eq!(store.dynamic_energy_factor(&addr).unwrap(), 0);
}

#[test]
fn contract_state_store_round_trips_dynamic_energy_factor() {
    let backend = mem();
    let store = ContractStateStore::new(backend);
    let addr = Address::from_raw([0x42u8; 21]);

    let state = tron_proto::ContractState {
        energy_usage: 12_345,
        energy_factor: 5_000, // +50% in DECIMAL=10_000 units
        update_cycle: 7,
    };
    store.put(&addr, &state).unwrap();
    assert_eq!(store.dynamic_energy_factor(&addr).unwrap(), 5_000);

    // Full struct round-trips too.
    let got = store.get(&addr).unwrap().unwrap();
    assert_eq!(got.energy_usage, 12_345);
    assert_eq!(got.update_cycle, 7);
}

// --- StorageRowStore::scan_for_contract -----------------------------------

#[test]
fn storage_row_store_scan_for_contract_filters_by_prefix() {
    use tron_chainbase::StorageRowStore;

    let backend = mem();
    let store = StorageRowStore::new(backend);

    // Two contracts; insert 2 rows each.
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(0xa1);
    let addr_a = Address::from_raw(a);

    let mut b = [0u8; 21];
    b[0] = 0x41;
    b[1..].fill(0xb2);
    let addr_b = Address::from_raw(b);

    let slot0 = [0u8; 32];
    let mut slot1 = [0u8; 32];
    slot1[31] = 1;

    let k_a_0 = StorageRowStore::compose_key(&addr_a, &slot0);
    let k_a_1 = StorageRowStore::compose_key(&addr_a, &slot1);
    let k_b_0 = StorageRowStore::compose_key(&addr_b, &slot0);
    let k_b_1 = StorageRowStore::compose_key(&addr_b, &slot1);

    store.put(&k_a_0, b"a-zero").unwrap();
    store.put(&k_a_1, b"a-one").unwrap();
    store.put(&k_b_0, b"b-zero").unwrap();
    store.put(&k_b_1, b"b-one").unwrap();

    let rows_a = store.scan_for_contract(&addr_a).unwrap();
    assert_eq!(rows_a.len(), 2);
    let mut values: Vec<Vec<u8>> = rows_a.iter().map(|(_, v)| v.clone()).collect();
    values.sort();
    assert_eq!(values, vec![b"a-one".to_vec(), b"a-zero".to_vec()]);

    let rows_b = store.scan_for_contract(&addr_b).unwrap();
    assert_eq!(rows_b.len(), 2);

    // Empty for unknown address.
    let mut c = [0u8; 21];
    c[0] = 0x41;
    c[1..].fill(0xc3);
    let addr_c = Address::from_raw(c);
    assert!(store.scan_for_contract(&addr_c).unwrap().is_empty());
}
