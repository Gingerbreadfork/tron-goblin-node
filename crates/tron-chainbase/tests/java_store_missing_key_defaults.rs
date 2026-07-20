//! What each store returns for a **key that isn't there**, pinned against
//! java-tron's own store tests.
//!
//! java-tron has three distinct "absent" answers, and which one a store uses is
//! part of its contract:
//!
//! * `get(key)` throws `ItemNotFoundException` — the strict accessor;
//! * `getUnchecked(key)` returns `null` — used by proto-capsule stores;
//! * `getUnchecked(key)` returns a **non-null capsule whose data is null**, or
//!   a typed zero (`0L`, an empty list) — used by `BytesCapsule`-backed stores
//!   and by the aggregate accessors layered over them.
//!
//! We surface all three through `Option` / `Result`, so the value of these
//! tests is fixing which of ours corresponds to which of java's. A store that
//! answers `0` where java answers "absent" (or the reverse) silently
//! mis-reports state read straight out of a converted java snapshot.
//!
//! java references: `org.tron.core.db.{AccountIdIndexStoreTest,
//! AssetIssueStoreTest, AssetIssueV2StoreTest, BlockIndexStoreTest,
//! BlockStoreTest, ContractStoreTest, DelegationStoreTest,
//! ExchangeStoreTest, ExchangeV2StoreTest, MarketAccountStoreTest,
//! MarketOrderStoreTest, MarketPairToPriceStoreTest, ProposalStoreTest,
//! RecentBlockStoreTest, TransactionHistoryTest, TransactionRetStoreTest,
//! TreeBlockIndexStoreTest, AccountTraceStoreTest}`.

use std::sync::Arc;

use prost::Message;
use tron_chainbase::{
    AccountIdIndexStore, AccountTraceStore, AssetIssueStore, AssetIssueV2Store, BlockIndexStore,
    ContractStore, DelegationStore, ExchangeStore, ExchangeV2Store, KvBackend, MarketAccountStore,
    MarketOrderStore, MarketPairToPriceStore, MemBackend, ProposalStore, RecentBlockStore,
    RecentTransactionStore, StoreError, TransactionHistoryStore, TransactionRetStore,
    TreeBlockIndexStore, WitnessStore,
};
use tron_crypto::address::Address;
use tron_proto::{
    AccountTrace, AssetIssueContract, Exchange, MarketAccountOrder, MarketOrder, Proposal,
    SmartContract, TransactionInfo, TransactionRet, Witness,
};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn addr(byte: u8) -> Address {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(byte);
    Address::from_raw(a)
}

// === Stores where java throws ItemNotFoundException / returns null ==========

/// `ProposalStoreTest#testGet` asserts `proposalStore.get("testGet1")` throws
/// `ItemNotFoundException` for an unknown key, and `ProposalStore` is a
/// proto-capsule store, so no zero-valued `Proposal` is ever synthesised.
#[test]
fn proposal_store_missing_id_is_absent_not_a_default_proposal() {
    let store = ProposalStore::new(mem());
    assert_eq!(store.get(7).unwrap(), None);

    store
        .put(
            1,
            &Proposal {
                proposal_id: 1,
                ..Default::default()
            },
        )
        .unwrap();
    // A neighbouring id must not be reachable through the 8-byte BE key space.
    assert_eq!(store.get(2).unwrap(), None);
    assert_eq!(store.get(0).unwrap(), None);
    assert!(store.get(1).unwrap().is_some());
}

/// `ExchangeStoreTest#testDelete` / `ExchangeV2StoreTest#testDelete`:
/// `getUnchecked` on a deleted exchange returns `null`, not a zero-id
/// `Exchange`.
#[test]
fn exchange_stores_report_deleted_ids_as_absent() {
    let backend = mem();
    let v1 = ExchangeStore::new(backend.clone());
    let v2 = ExchangeV2Store::new(mem());

    let ex = Exchange {
        exchange_id: 1,
        creator_address: b"Address1".to_vec(),
        ..Default::default()
    };
    v1.put(1, &ex).unwrap();
    v2.put(1, &ex).unwrap();
    assert!(v1.get(1).unwrap().is_some());
    assert!(v2.get(1).unwrap().is_some());

    backend.delete(&ExchangeStore::key_for(1)).unwrap();
    assert_eq!(v1.get(1).unwrap(), None);
    assert_eq!(v1.get(2).unwrap(), None);
    assert_eq!(v2.get(2).unwrap(), None);
}

/// `MarketAccountStoreTest#testGet` opens by asserting
/// `marketAccountStore.getUnchecked("Address1")` is `null` **before** any put —
/// an unknown market account is absent, not an empty order capsule.
#[test]
fn market_account_store_missing_owner_is_absent() {
    let store = MarketAccountStore::new(mem());
    let owner = addr(0xa1);
    assert_eq!(store.get(&owner).unwrap(), None);

    store
        .put(
            &owner,
            &MarketAccountOrder {
                owner_address: owner.as_bytes().to_vec(),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(store.get(&owner).unwrap().is_some());
    assert_eq!(store.get(&addr(0xa2)).unwrap(), None);
}

/// `MarketOrderStoreTest#testDelete`: `getUnchecked` on a deleted order id is
/// `null`.
#[test]
fn market_order_store_reports_deleted_orders_as_absent() {
    let store = MarketOrderStore::new(mem());
    let order_id = b"testDelete";
    store
        .put(
            order_id,
            &MarketOrder {
                order_id: order_id.to_vec(),
                sell_token_id: b"addr1".to_vec(),
                sell_token_quantity: 200,
                buy_token_id: b"addr2".to_vec(),
                buy_token_quantity: 100,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(store.get(order_id).unwrap().is_some());

    store.delete(order_id).unwrap();
    assert_eq!(store.get(order_id).unwrap(), None);
}

/// `TransactionHistoryTest#testDelete`: after a delete the history store yields
/// `null`, never a zero-fee `TransactionInfo`.
#[test]
fn transaction_history_store_reports_deleted_ids_as_absent() {
    let backend = mem();
    let store = TransactionHistoryStore::new(backend.clone());
    let tx_id = [0x11u8; 32];
    store
        .put(
            &tx_id,
            &TransactionInfo {
                id: tx_id.to_vec(),
                fee: 1000,
                block_number: 100,
                block_time_stamp: 200,
                ..Default::default()
            },
        )
        .unwrap();
    let got = store.get(&tx_id).unwrap().expect("stored info readable");
    assert_eq!(got.fee, 1000);
    assert_eq!(got.block_number, 100);
    assert_eq!(got.block_time_stamp, 200);

    backend.delete(&tx_id).unwrap();
    assert_eq!(store.get(&tx_id).unwrap(), None);
}

/// `TransactionRetStoreTest#put` asserts `getUnchecked` is `null` **before**
/// the put and non-null after — pinned here on the 8-byte block-number key.
#[test]
fn transaction_ret_store_missing_block_is_absent() {
    let store = TransactionRetStore::new(mem());
    assert_eq!(store.get(1).unwrap(), None);
    store
        .put(
            1,
            &TransactionRet {
                block_number: 100,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(store.get(1).unwrap().is_some());
    assert_eq!(store.get(2).unwrap(), None);
}

/// `TreeBlockIndexStoreTest#testGetByNum` / `#testGet` assert that block 0 —
/// never written — throws `ItemNotFoundException`, while a written block reads
/// back. Absence must not be confused with the all-zero 32-byte id.
#[test]
fn tree_block_index_store_missing_block_is_absent_not_zero_hash() {
    let store = TreeBlockIndexStore::new(mem());
    assert_eq!(store.get(0).unwrap(), None);
    store.put(1, &[0x22u8; 32]).unwrap();
    assert_eq!(store.get(1).unwrap(), Some([0x22u8; 32]));
    assert_eq!(store.get(0).unwrap(), None);
    assert_eq!(store.get(2).unwrap(), None);
}

/// `BlockIndexStoreTest#testDelete` deletes the index row and then reads it
/// back — java's `BytesCapsule` wrapper is non-null but its `getData()` is
/// `null`. Our strict accessor reports the absence directly rather than
/// handing back a zero-filled `BlockId`.
#[test]
fn block_index_store_missing_number_is_not_found() {
    let backend = mem();
    let store = BlockIndexStore::new(backend.clone());
    assert!(matches!(store.get(1), Err(StoreError::NotFound)));

    let id_bytes = {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&1i64.to_be_bytes());
        b
    };
    backend.put(&BlockIndexStore::key_for(1), &id_bytes).unwrap();
    assert!(store.get(1).is_ok());

    backend.delete(&BlockIndexStore::key_for(1)).unwrap();
    assert!(matches!(store.get(1), Err(StoreError::NotFound)));
}

/// `ContractStoreTest#testDelete`: a deleted contract address reads back as
/// `null`, not as a `SmartContract` with an empty name.
#[test]
fn contract_store_reports_deleted_addresses_as_absent() {
    let store = ContractStore::new(mem());
    let a = addr(0xc1);
    assert_eq!(store.get(&a).unwrap(), None);
    store
        .put(
            &a,
            &SmartContract {
                name: "test_contract_name".into(),
                contract_address: a.as_bytes().to_vec(),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(store.get(&a).unwrap().is_some());
    store.delete(&a).unwrap();
    assert_eq!(store.get(&a).unwrap(), None);
    assert_eq!(store.get(&addr(0xc2)).unwrap(), None);
}

/// `AssetIssueStoreTest#testDelete` / `AssetIssueV2StoreTest#testDelete`. The
/// two stores are keyed differently (v1 by asset **name**, v2 by the decimal
/// **id** string), so a lookup that hits in one must miss in the other.
#[test]
fn asset_issue_stores_do_not_answer_for_each_others_keys() {
    let v1 = AssetIssueStore::new(mem());
    let v2 = AssetIssueV2Store::new(mem());

    let contract = AssetIssueContract {
        name: b"abc".to_vec(),
        id: "1".into(),
        ..Default::default()
    };
    v1.put(b"abc", &contract).unwrap();
    v2.put(1, &contract).unwrap();

    assert!(v1.get(b"abc").unwrap().is_some());
    assert!(v2.get(1).unwrap().is_some());
    // The v1 name key is not a v2 id key, and vice versa.
    assert_eq!(v1.get(b"1").unwrap(), None);
    assert_eq!(v2.get(2).unwrap(), None);
    assert_eq!(v1.get(b"test-asset-delete").unwrap(), None);
}

/// `WitnessStoreTest` reads back only witnesses it wrote; an unregistered
/// address must be absent rather than a zero-vote `Witness`, because a
/// synthesised zero-vote row would join the standby ranking.
#[test]
fn witness_store_unregistered_address_is_absent_not_zero_votes() {
    let store = WitnessStore::new(mem());
    let a = addr(0x77);
    assert_eq!(store.get(&a).unwrap(), None);
    assert!(!store.contains(&a).unwrap());
    store
        .put(
            &a,
            &Witness {
                address: a.as_bytes().to_vec(),
                vote_count: 100,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(store.get(&a).unwrap().unwrap().vote_count, 100);
    store.delete(&a).unwrap();
    assert_eq!(store.get(&a).unwrap(), None);
    assert!(store.all().unwrap().is_empty());
}

// === Stores where java returns a typed zero / empty aggregate ===============

/// `MarketPairToPriceStoreTest#testGetPriceNum` pins java's
/// `getPriceNum(unknownKey) == 0L` — the accessor folds "absent" into a zero
/// count so `addNewPriceKey` can increment unconditionally.
/// `#testGetPriceNumByTokenId` additionally pins that the pair key is
/// **directional**: `(a, b)` and `(b, a)` are separate rows.
#[test]
fn market_pair_to_price_absent_pair_reads_as_zero_and_is_directional() {
    let store = MarketPairToPriceStore::new(mem());

    // java: getPriceNum on a never-written key is 0, not an error.
    assert_eq!(store.get(b"testGetPriceNum1").unwrap().unwrap_or(0), 0);

    store.put(b"testGetPriceNum", 100).unwrap();
    assert_eq!(store.get(b"testGetPriceNum").unwrap(), Some(100));

    // Directional pair keys: sell||buy is not buy||sell.
    let mut forward = b"tokenId1".to_vec();
    forward.extend_from_slice(b"tokenId2");
    let mut reverse = b"tokenId2".to_vec();
    reverse.extend_from_slice(b"tokenId1");
    store.put(&forward, 99).unwrap();
    assert_eq!(store.get(&forward).unwrap(), Some(99));
    assert_eq!(store.get(&reverse).unwrap().unwrap_or(0), 0);
}

/// `AccountTraceStoreTest#testGetPrevBalance`: when the seek lands on no row —
/// or on a row belonging to a **different** account — java returns
/// `Pair.of(number, 0L)`, echoing back the requested block number with a zero
/// balance. It does not signal an error.
#[test]
fn account_trace_prev_balance_falls_back_to_requested_block_and_zero() {
    let store = AccountTraceStore::new(mem());
    let alice = addr(0xaa);
    let bob = addr(0xbb);

    // Nothing recorded at all.
    assert_eq!(store.get_prev_balance(&alice, 2).unwrap(), (2, 0));

    // A row for a *later* block only: the descending seek walks past the end of
    // alice's range, so there is no balance at or before block 2.
    store
        .put(
            &alice,
            9,
            &AccountTrace {
                balance: 9_999,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(store.get_prev_balance(&alice, 2).unwrap(), (2, 0));

    // A row belonging to another account must not be borrowed: bob's seek
    // drifts into alice's range and must still report (number, 0).
    assert_eq!(store.get_prev_balance(&bob, 3).unwrap(), (3, 0));

    // Once alice has a row at or before the requested block, that row wins.
    store
        .put(
            &alice,
            1,
            &AccountTrace {
                balance: 99,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(store.get_prev_balance(&alice, 3).unwrap(), (1, 99));
}

/// `AccountIdIndexStoreTest#putAndGet` / `#putAndHas`: an unknown account id
/// yields `null` / `false`. `#testCaseInsensitive` pins that lookups are
/// case-folded — a name stored in mixed case is reachable through its
/// lower- **and** upper-case spellings, so an upper-case miss would be a bug,
/// not an absence.
#[test]
fn account_id_index_missing_id_is_absent_but_case_is_folded() {
    let store = AccountIdIndexStore::new(mem());
    let a = addr(0x1d);

    assert_eq!(store.get(b"never-written").unwrap(), None);

    store.put(b"aABbCcDd_ssd1234", &a).unwrap();
    assert_eq!(store.get(b"aABbCcDd_ssd1234").unwrap(), Some(a));
    assert_eq!(store.get(b"aabbccdd_ssd1234").unwrap(), Some(a));
    assert_eq!(store.get(b"AABBCCDD_SSD1234").unwrap(), Some(a));
    // Case folding must not make unrelated ids collide.
    assert_eq!(store.get(b"aabbccdd_ssd1235").unwrap(), None);
}

/// `DelegationStoreTest#testDelete` reads a deleted reward key back through
/// `getUnchecked` and asserts the capsule's data is `null` — i.e. the reward is
/// gone, not zero-but-present. Our reward accessor folds that to `0`, matching
/// java's `getReward`, while the raw row is genuinely absent.
#[test]
fn delegation_reward_absent_row_reads_as_zero_reward() {
    let backend = mem();
    let store = DelegationStore::new(backend.clone());
    let a = addr(0x33);

    assert_eq!(store.get_reward(100, &a), 0);
    store.add_reward(100, &a, 20_000_000);
    assert_eq!(store.get_reward(100, &a), 20_000_000);

    // Deleting the underlying row returns the accessor to its zero default.
    let key = DelegationStore::reward_key(100, &a);
    backend.delete(&key).unwrap();
    assert_eq!(store.get_reward(100, &a), 0);
    // A neighbouring cycle was never written and reads as zero too.
    assert_eq!(store.get_reward(101, &a), 0);
}

/// `RecentBlockStoreTest#testDelete` and `RecentTransactionStoreTest`: both are
/// keyed by the **low 16 bits** of the block number, so the table wraps every
/// 65,536 blocks. A miss must be reported as absent — but a key 65,536 blocks
/// away is the *same* key and therefore a hit, which is the wrap behaviour the
/// TAPOS ref-block check depends on.
#[test]
fn recent_block_stores_are_absent_until_written_then_alias_every_65536_blocks() {
    let backend = mem();
    let recent_block = RecentBlockStore::new(backend.clone());
    let recent_tx = RecentTransactionStore::new(mem());

    assert_eq!(recent_block.get(1).unwrap(), None);
    assert_eq!(recent_tx.get(1).unwrap(), None);

    recent_block.put(1, &[0xab; 8]).unwrap();
    recent_tx.put(1, &[0xcd; 8]).unwrap();
    assert_eq!(recent_block.get(1).unwrap(), Some(vec![0xab; 8]));
    assert_eq!(recent_tx.get(1).unwrap(), Some(vec![0xcd; 8]));

    // Same low 16 bits => same slot.
    assert_eq!(recent_block.get(1 + 65_536).unwrap(), Some(vec![0xab; 8]));
    assert_eq!(recent_tx.get(1 + 65_536).unwrap(), Some(vec![0xcd; 8]));
    // Different low 16 bits => still absent.
    assert_eq!(recent_block.get(2).unwrap(), None);
    assert_eq!(recent_tx.get(2).unwrap(), None);
}

/// A store must not answer for a key that merely **starts with** the one it
/// holds, nor for one that its key is a prefix of. java's stores are exact-key
/// maps; a prefix-tolerant `get` would let a shorter asset name shadow a longer
/// one on a converted snapshot.
#[test]
fn stores_match_keys_exactly_not_by_prefix() {
    let v1 = AssetIssueStore::new(mem());
    let contract = AssetIssueContract {
        name: b"test-asset".to_vec(),
        id: "1".into(),
        ..Default::default()
    };
    v1.put(b"test-asset", &contract).unwrap();
    assert!(v1.get(b"test-asset").unwrap().is_some());
    assert_eq!(v1.get(b"test").unwrap(), None, "prefix must not hit");
    assert_eq!(
        v1.get(b"test-asset2").unwrap(),
        None,
        "extension must not hit"
    );
    assert_eq!(v1.get(b"").unwrap(), None, "empty key must not hit");
}

/// Round-tripping an empty proto message must still register as **present**:
/// java distinguishes "row absent" from "row holding a default-valued
/// capsule", and a zero-length protobuf encoding is a legitimate stored value.
#[test]
fn zero_length_encoded_value_is_present_not_absent() {
    let store = ProposalStore::new(mem());
    let empty = Proposal::default();
    assert!(
        empty.encode_to_vec().is_empty(),
        "a default Proposal encodes to zero bytes"
    );
    store.put(5, &empty).unwrap();
    assert_eq!(
        store.get(5).unwrap(),
        Some(empty),
        "a zero-byte row must read back as present"
    );
}
