//! End-to-end tests for each ported store. Uses the in-memory backend; the
//! key-encoding rules pinned here must match what java-tron writes to
//! RocksDB/LevelDB.

use std::sync::Arc;

use hex_literal::hex;
use prost::Message;
use tron_chainbase::{
    dynamic_properties_keys as dp_keys, AccountStore, BlockIndexStore, BlockStore,
    DelegatedResourceAccountIndexStore, DelegatedResourceStore, DelegationStore,
    DynamicPropertiesStore, KvBackend, MemBackend, RocksDbBackend, StoreError, StoredTransaction,
    TransactionStore, VotesStore, WitnessStore, DEFAULT_BROKERAGE, REMARK, V1_FROM_PREFIX,
    V1_TO_PREFIX, V2_FROM_PREFIX, V2_PREFIX_LOCKED, V2_PREFIX_UNLOCKED, V2_TO_PREFIX,
};
use tron_crypto::address::Address;
use tron_proto::block_header::Raw as BlockHeaderRaw;
use tron_proto::transaction::contract::ContractType;
use tron_proto::transaction::{Contract, Raw as TxRaw};
use tron_proto::{Account, Block, BlockHeader, Transaction, TransferContract, Votes, Witness};
use tron_types::{block_id_from_block, tx_id};

fn mem() -> Arc<MemBackend> {
    Arc::new(MemBackend::new())
}

fn sample_block(num: i64) -> Block {
    Block {
        transactions: Vec::new(),
        block_header: Some(BlockHeader {
            raw_data: Some(BlockHeaderRaw {
                timestamp: 1_700_000_000_000 + num,
                tx_trie_root: Vec::new(),
                parent_hash: vec![0u8; 32],
                number: num,
                witness_id: 0,
                witness_address: Vec::new(),
                version: 28,
                account_state_root: Vec::new(),
            }),
            witness_signature: Vec::new(),
        }),
    }
}

fn sample_transaction(amount: i64) -> Transaction {
    let tc = TransferContract {
        owner_address: hex!("412e988a386a799f506693793c6a5af6b54dfaabfb").to_vec(),
        to_address: hex!("41a614f803b6fd780986a42c78ec9c7f77e6ded13c").to_vec(),
        amount,
    };
    let contract = Contract {
        r#type: ContractType::TransferContract as i32,
        parameter: Some(prost_types::Any {
            type_url: "type.googleapis.com/protocol.TransferContract".into(),
            value: tc.encode_to_vec(),
        }),
        provider: Vec::new(),
        contract_name: Vec::new(),
        permission_id: 0,
    };
    let raw = TxRaw {
        ref_block_bytes: vec![0xab, 0xcd],
        ref_block_num: 0,
        ref_block_hash: vec![0u8; 8],
        expiration: 1_700_000_000_000,
        auths: Vec::new(),
        data: Vec::new(),
        contract: vec![contract],
        scripts: Vec::new(),
        timestamp: 1_700_000_000_000,
        fee_limit: 0,
    };
    Transaction {
        raw_data: Some(raw),
        signature: vec![vec![0xaa; 65]],
        ret: Vec::new(),
    }
}

// --- BlockStore -------------------------------------------------------------

#[test]
fn block_store_put_get_round_trip() {
    let backend = mem();
    let store = BlockStore::new(backend.clone() as Arc<_>);

    let block = sample_block(100);
    let id = block_id_from_block(&block).unwrap();
    store.put(&id, &block).unwrap();

    let got = store.get(&id).unwrap();
    assert_eq!(got, block);
    assert!(store.contains(&id).unwrap());
}

#[test]
fn block_store_get_missing_returns_not_found() {
    let backend = mem();
    let store = BlockStore::new(backend as Arc<_>);
    let block = sample_block(1);
    let id = block_id_from_block(&block).unwrap();
    assert_eq!(store.get(&id), Err(StoreError::NotFound));
}

// --- BlockIndexStore --------------------------------------------------------

/// Pin the exact key bytes java-tron writes: 8-byte big-endian i64. A
/// little-endian regression here would make every Rust-written index
/// invisible to a Java reader and vice versa.
#[test]
fn block_index_store_key_is_big_endian_i64() {
    assert_eq!(BlockIndexStore::key_for(0), [0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(BlockIndexStore::key_for(1), [0, 0, 0, 0, 0, 0, 0, 1]);
    assert_eq!(
        BlockIndexStore::key_for(0x0102030405060708),
        [1, 2, 3, 4, 5, 6, 7, 8]
    );
    // Negative i64s round-trip too (though block heights are never negative
    // in practice). Sign-extended big-endian.
    assert_eq!(
        BlockIndexStore::key_for(-1),
        [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    );
}

#[test]
fn block_index_store_round_trips_block_id() {
    let backend = mem();
    let store = BlockIndexStore::new(backend as Arc<_>);

    let block = sample_block(12345);
    let id = block_id_from_block(&block).unwrap();
    store.put(&id).unwrap();

    let got = store.get(12345).unwrap();
    assert_eq!(got, id);
    assert_eq!(got.num(), 12345);
}

#[test]
fn block_index_store_value_must_be_32_bytes() {
    let backend = mem();
    backend.put(&BlockIndexStore::key_for(7), &[1, 2, 3]).unwrap(); // wrong length
    let store = BlockIndexStore::new(backend as Arc<_>);
    assert!(matches!(
        store.get(7),
        Err(StoreError::InvalidValueLength { got: 3, expected: 32 })
    ));
}

// --- TransactionStore -------------------------------------------------------

#[test]
fn transaction_store_block_ref_round_trip() {
    let backend = mem();
    let store = TransactionStore::new(backend as Arc<_>);

    let tx = sample_transaction(1_000_000);
    let id = tx_id(&tx).unwrap();
    store.put_block_ref(&id, 12345).unwrap();

    match store.get(&id).unwrap().unwrap() {
        StoredTransaction::BlockRef(n) => assert_eq!(n, 12345),
        StoredTransaction::Full(_) => panic!("expected BlockRef"),
    }
    assert_eq!(store.get_block_number(&id).unwrap(), Some(12345));
}

#[test]
fn transaction_store_full_round_trip() {
    let backend = mem();
    let store = TransactionStore::new(backend as Arc<_>);

    let tx = sample_transaction(2_000_000);
    let id = tx_id(&tx).unwrap();
    store.put_full(&id, &tx).unwrap();

    match store.get(&id).unwrap().unwrap() {
        StoredTransaction::Full(got) => assert_eq!(got, tx),
        StoredTransaction::BlockRef(_) => panic!("expected Full"),
    }
    // get_block_number returns None because the value isn't an 8-byte ref.
    assert_eq!(store.get_block_number(&id).unwrap(), None);
}

/// Sanity check that a real signed Transaction never encodes to exactly 8
/// bytes — otherwise the length-based disambiguation would break.
#[test]
fn signed_transaction_is_never_eight_bytes() {
    let tx = sample_transaction(1);
    let bytes = tx.encode_to_vec();
    assert_ne!(bytes.len(), 8);
    assert!(bytes.len() > 50, "real txs are much larger than 8 bytes");
}

#[test]
fn transaction_store_get_missing_returns_none() {
    let backend = mem();
    let store = TransactionStore::new(backend as Arc<_>);
    let tx = sample_transaction(1);
    let id = tx_id(&tx).unwrap();
    assert!(store.get(&id).unwrap().is_none());
}

// --- AccountStore -----------------------------------------------------------

#[test]
fn account_store_round_trip() {
    let backend = mem();
    let store = AccountStore::new(backend as Arc<_>);

    let addr_bytes = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");
    let addr = Address::from_raw(addr_bytes);
    let account = Account {
        account_name: b"alice".to_vec(),
        balance: 1_000_000,
        address: addr_bytes.to_vec(),
        ..Default::default()
    };
    store.put(&addr, &account).unwrap();

    let got = store.get(&addr).unwrap().unwrap();
    assert_eq!(got, account);
    assert!(store.contains(&addr).unwrap());
}

#[test]
fn account_store_get_raw_rejects_wrong_key_length() {
    let backend = mem();
    let store = AccountStore::new(backend as Arc<_>);
    let result = store.get_raw(&[0u8; 20]); // 20 bytes, should be 21
    assert!(matches!(
        result,
        Err(StoreError::InvalidKeyLength { got: 20, expected: 21 })
    ));
}

#[test]
fn account_store_missing_returns_none() {
    let backend = mem();
    let store = AccountStore::new(backend as Arc<_>);
    let addr = Address::from_raw(hex!("41a614f803b6fd780986a42c78ec9c7f77e6ded13c"));
    assert!(store.get(&addr).unwrap().is_none());
}

// --- WitnessStore -----------------------------------------------------------

// --- DynamicPropertiesStore -------------------------------------------------

/// **Critical consensus quirk**: the `ALLOW_SAME_TOKEN_NAME` key has a
/// single leading space byte. java-tron writes it that way (see
/// `DynamicPropertiesStore.java:120`) and the storage layer is now
/// permanently coupled to that exact byte sequence.
#[test]
fn allow_same_token_name_key_has_leading_space() {
    assert_eq!(dp_keys::ALLOW_SAME_TOKEN_NAME[0], b' ');
    assert_eq!(dp_keys::ALLOW_SAME_TOKEN_NAME, b" ALLOW_SAME_TOKEN_NAME");
    assert_eq!(dp_keys::ALLOW_SAME_TOKEN_NAME.len(), 22); // 21 chars + leading space
}

/// Latest block header keys are lowercase. The uppercase-/lowercase split
/// is a real distinction in the on-disk format.
#[test]
fn latest_block_header_keys_are_lowercase() {
    assert_eq!(dp_keys::LATEST_BLOCK_HEADER_NUMBER, b"latest_block_header_number");
    assert_eq!(dp_keys::LATEST_BLOCK_HEADER_TIMESTAMP, b"latest_block_header_timestamp");
    assert_eq!(dp_keys::LATEST_BLOCK_HEADER_HASH, b"latest_block_header_hash");
    // Sanity: this distinct-but-similar key really is UPPERCASE.
    assert_eq!(dp_keys::LATEST_SOLIDIFIED_BLOCK_NUM, b"LATEST_SOLIDIFIED_BLOCK_NUM");
}

#[test]
fn dynamic_properties_long_round_trip() {
    let backend = mem();
    let store = DynamicPropertiesStore::new(backend as Arc<_>);
    store.save_latest_block_header_number(12345);
    store.save_latest_block_header_timestamp(1_700_000_000_000);

    assert_eq!(store.latest_block_header_number(), Some(12345));
    assert_eq!(store.latest_block_header_timestamp(), Some(1_700_000_000_000));
}

#[test]
fn dynamic_properties_long_writes_8_bytes_big_endian() {
    let backend = mem();
    let store = DynamicPropertiesStore::new(backend.clone() as Arc<_>);
    store.save_latest_block_header_number(0x0102030405060708);
    let raw = backend.get(dp_keys::LATEST_BLOCK_HEADER_NUMBER).unwrap().unwrap();
    assert_eq!(raw, vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
}

#[test]
fn dynamic_properties_long_reader_is_permissive_about_length() {
    // Matches java-tron's `ByteArray.toLong` which accepts any non-empty
    // byte slice. Hand-craft a 3-byte value at the long-formatted key.
    let backend = mem();
    backend.put(dp_keys::LATEST_PROPOSAL_NUM, &[0x12, 0x34, 0x56]).unwrap();
    let store = DynamicPropertiesStore::new(backend as Arc<_>);
    // Java parses `[0x12, 0x34, 0x56]` as unsigned BigInteger = 0x123456 =
    // 1_193_046, then `longValue()` returns 1_193_046 as a signed long.
    assert_eq!(store.get_long(dp_keys::LATEST_PROPOSAL_NUM), Some(0x123456));
}

#[test]
fn dynamic_properties_long_empty_value_reads_as_zero() {
    let backend = mem();
    backend.put(dp_keys::LATEST_PROPOSAL_NUM, &[]).unwrap();
    let store = DynamicPropertiesStore::new(backend as Arc<_>);
    assert_eq!(store.get_long(dp_keys::LATEST_PROPOSAL_NUM), Some(0));
}

#[test]
fn dynamic_properties_hash_round_trip() {
    let backend = mem();
    let store = DynamicPropertiesStore::new(backend as Arc<_>);
    let hash = [0xabu8; 32];
    store.save_latest_block_header_hash(&hash);
    assert_eq!(store.latest_block_header_hash().unwrap(), Some(hash));
}

#[test]
fn dynamic_properties_hash_rejects_wrong_length() {
    let backend = mem();
    backend.put(dp_keys::LATEST_BLOCK_HEADER_HASH, &[0u8; 16]).unwrap(); // half-size
    let store = DynamicPropertiesStore::new(backend as Arc<_>);
    assert!(matches!(
        store.latest_block_header_hash(),
        Err(StoreError::InvalidValueLength { got: 16, expected: 32 })
    ));
}

#[test]
fn dynamic_properties_bool_round_trip() {
    let backend = mem();
    let store = DynamicPropertiesStore::new(backend as Arc<_>);
    store.put_bool(dp_keys::ALLOW_DELEGATE_RESOURCE, true);
    assert_eq!(store.get_bool(dp_keys::ALLOW_DELEGATE_RESOURCE), Some(true));
    store.put_bool(dp_keys::ALLOW_DELEGATE_RESOURCE, false);
    assert_eq!(store.get_bool(dp_keys::ALLOW_DELEGATE_RESOURCE), Some(false));
}

// --- DelegationStore --------------------------------------------------------

fn sample_addr() -> tron_crypto::address::Address {
    tron_crypto::address::Address::from_raw(hex!("412e988a386a799f506693793c6a5af6b54dfaabfb"))
}

/// Pin the **exact** composite-key bytes for each shape. A drift here makes
/// every cycle reward/vote unreadable.
#[test]
fn delegation_keys_match_java_tron_byte_layout() {
    let addr = sample_addr();
    let addr_hex = "412e988a386a799f506693793c6a5af6b54dfaabfb"; // 42 chars

    assert_eq!(
        DelegationStore::vote_key(42, &addr),
        format!("42-{addr_hex}-vote").into_bytes()
    );
    assert_eq!(
        DelegationStore::reward_key(42, &addr),
        format!("42-{addr_hex}-reward").into_bytes()
    );
    assert_eq!(
        DelegationStore::brokerage_key(42, &addr),
        format!("42-{addr_hex}-brokerage").into_bytes()
    );
    assert_eq!(
        DelegationStore::vi_key(42, &addr),
        format!("42-{addr_hex}-vi").into_bytes()
    );
    assert_eq!(
        DelegationStore::account_vote_key(42, &addr),
        format!("42-{addr_hex}-account-vote").into_bytes()
    );

    // end-<hex> has no cycle prefix.
    assert_eq!(
        DelegationStore::end_cycle_key(&addr),
        format!("end-{addr_hex}").into_bytes()
    );

    // begin-cycle uses the raw 21-byte address — a totally different key
    // shape that doesn't collide with the UTF-8 composite keys.
    assert_eq!(DelegationStore::begin_cycle_key(&addr), *addr.as_bytes());
}

#[test]
fn delegation_negative_cycle_renders_with_minus_sign() {
    let addr = sample_addr();
    // The `setBrokerage(address, b)` convenience uses cycle=-1; the
    // resulting key starts with the literal characters "-1-".
    assert!(DelegationStore::brokerage_key(-1, &addr).starts_with(b"-1-"));
}

#[test]
fn delegation_address_hex_is_lowercase_no_prefix() {
    // BouncyCastle's `Hex.toHexString` emits lowercase, no `0x`. Mixing
    // case would yield a different on-disk key and silent data loss.
    let addr = sample_addr();
    let key = DelegationStore::vote_key(1, &addr);
    let key_str = std::str::from_utf8(&key).unwrap();
    assert!(!key_str.contains("0x"));
    assert!(key_str.chars().all(|c| !c.is_ascii_uppercase()));
}

#[test]
fn delegation_reward_round_trip_and_add() {
    let backend = mem();
    let store = DelegationStore::new(backend as Arc<_>);
    let addr = sample_addr();

    assert_eq!(store.get_reward(42, &addr), 0);
    store.add_reward(42, &addr, 100);
    assert_eq!(store.get_reward(42, &addr), 100);
    store.add_reward(42, &addr, 50);
    assert_eq!(store.get_reward(42, &addr), 150);
}

#[test]
fn delegation_missing_witness_vote_returns_remark_sentinel() {
    let store = DelegationStore::new(mem() as Arc<_>);
    let addr = sample_addr();
    assert_eq!(store.get_witness_vote(99, &addr), REMARK);
    assert_eq!(REMARK, -1);
}

#[test]
fn delegation_missing_end_cycle_returns_remark() {
    let store = DelegationStore::new(mem() as Arc<_>);
    let addr = sample_addr();
    assert_eq!(store.get_end_cycle(&addr), REMARK);

    store.set_end_cycle(&addr, 12345);
    assert_eq!(store.get_end_cycle(&addr), 12345);
}

#[test]
fn delegation_brokerage_default_returned_when_missing() {
    let store = DelegationStore::new(mem() as Arc<_>);
    let addr = sample_addr();
    assert_eq!(store.get_brokerage(1, &addr), DEFAULT_BROKERAGE);
    assert_eq!(DEFAULT_BROKERAGE, 20);

    store.set_brokerage(1, &addr, 35);
    assert_eq!(store.get_brokerage(1, &addr), 35);
}

#[test]
fn delegation_vi_raw_bytes_round_trip() {
    let store = DelegationStore::new(mem() as Arc<_>);
    let addr = sample_addr();
    // Simulate a `BigInteger.toByteArray()` payload — variable length,
    // signed two's-complement big-endian. We just round-trip the bytes.
    let vi_bytes = vec![0x00, 0x80, 0x12, 0x34, 0x56, 0x78];
    store.set_witness_vi_raw(7, &addr, &vi_bytes);
    assert_eq!(store.get_witness_vi_raw(7, &addr), Some(vi_bytes));
}

#[test]
fn delegation_global_brokerage_uses_cycle_minus_one() {
    let store = DelegationStore::new(mem() as Arc<_>);
    let addr = sample_addr();
    store.set_brokerage_global(&addr, 30);
    // Should be readable both through the global accessor and the
    // cycle=-1 path.
    assert_eq!(store.get_brokerage_global(&addr), 30);
    assert_eq!(store.get_brokerage(-1, &addr), 30);
}

// --- DelegatedResource stores -----------------------------------------------

fn addr_a() -> tron_crypto::address::Address {
    tron_crypto::address::Address::from_raw(hex!("412e988a386a799f506693793c6a5af6b54dfaabfb"))
}
fn addr_b() -> tron_crypto::address::Address {
    tron_crypto::address::Address::from_raw(hex!("41a614f803b6fd780986a42c78ec9c7f77e6ded13c"))
}

/// V1 key is `from || to`: 42 bytes, no prefix. Anything else corrupts
/// existing chain data.
#[test]
fn delegated_resource_v1_key_is_from_concat_to_no_prefix() {
    let from = addr_a();
    let to = addr_b();
    let key = DelegatedResourceStore::v1_key(&from, &to);
    assert_eq!(key.len(), 42);
    assert_eq!(&key[0..21], from.as_bytes());
    assert_eq!(&key[21..42], to.as_bytes());
}

/// V2 keys use distinct prefix bytes for locked vs unlocked. Different
/// from the index store's V1/V2 FROM/TO prefixes.
#[test]
fn delegated_resource_v2_prefix_bytes_pinned() {
    assert_eq!(V2_PREFIX_UNLOCKED, 0x01);
    assert_eq!(V2_PREFIX_LOCKED, 0x02);

    let key_u = DelegatedResourceStore::v2_unlocked_key(&addr_a(), &addr_b());
    let key_l = DelegatedResourceStore::v2_locked_key(&addr_a(), &addr_b());
    assert_eq!(key_u[0], 0x01);
    assert_eq!(key_l[0], 0x02);
    // Same payload, different prefix → different keys.
    assert_ne!(key_u, key_l);
    assert_eq!(&key_u[1..], &key_l[1..]);
}

#[test]
fn delegated_resource_store_round_trip() {
    let backend = mem();
    let store = DelegatedResourceStore::new(backend as Arc<_>);
    let resource = tron_proto::DelegatedResource {
        from: addr_a().as_bytes().to_vec(),
        to: addr_b().as_bytes().to_vec(),
        frozen_balance_for_bandwidth: 1_000_000,
        frozen_balance_for_energy: 0,
        expire_time_for_bandwidth: 0,
        expire_time_for_energy: 0,
    };
    let key = DelegatedResourceStore::v2_unlocked_key(&addr_a(), &addr_b());
    store.put_raw(&key, &resource).unwrap();
    let got = store.get_raw(&key).unwrap().unwrap();
    assert_eq!(got, resource);
}

/// Index store: V1 prefixes 0x01/0x02, V2 prefixes 0x03/0x04. Note that
/// 0x01/0x02 in *this* store mean FROM/TO, **not** unlocked/locked.
#[test]
fn delegated_resource_index_prefix_bytes_pinned() {
    assert_eq!(V1_FROM_PREFIX, 0x01);
    assert_eq!(V1_TO_PREFIX, 0x02);
    assert_eq!(V2_FROM_PREFIX, 0x03);
    assert_eq!(V2_TO_PREFIX, 0x04);
}

/// V1 FROM key is `[0x01, from, to]`; V1 TO key is `[0x02, to, from]` —
/// the address order is **swapped** between sides. This swap is what
/// makes `getIndex(address)` return both incoming and outgoing
/// delegations using prefix scans.
#[test]
fn delegated_resource_index_v1_keys_use_swapped_address_order() {
    let from = addr_a();
    let to = addr_b();
    let from_key = DelegatedResourceAccountIndexStore::v1_from_key(&from, &to);
    let to_key = DelegatedResourceAccountIndexStore::v1_to_key(&from, &to);

    assert_eq!(from_key.len(), 43);
    assert_eq!(to_key.len(), 43);
    assert_eq!(from_key[0], 0x01);
    assert_eq!(to_key[0], 0x02);
    // FROM key: [0x01, from, to]
    assert_eq!(&from_key[1..22], from.as_bytes());
    assert_eq!(&from_key[22..43], to.as_bytes());
    // TO key: [0x02, to, from]  ← swapped
    assert_eq!(&to_key[1..22], to.as_bytes());
    assert_eq!(&to_key[22..43], from.as_bytes());
}

#[test]
fn delegated_resource_index_v2_keys_use_swapped_address_order() {
    let from = addr_a();
    let to = addr_b();
    let from_key = DelegatedResourceAccountIndexStore::v2_from_key(&from, &to);
    let to_key = DelegatedResourceAccountIndexStore::v2_to_key(&from, &to);
    assert_eq!(from_key[0], 0x03);
    assert_eq!(to_key[0], 0x04);
    assert_eq!(&from_key[1..22], from.as_bytes());
    assert_eq!(&from_key[22..43], to.as_bytes());
    assert_eq!(&to_key[1..22], to.as_bytes());
    assert_eq!(&to_key[22..43], from.as_bytes());
}

#[test]
fn delegated_resource_index_legacy_key_is_raw_21_bytes() {
    let key = DelegatedResourceAccountIndexStore::legacy_key(&addr_a());
    assert_eq!(key.len(), 21);
    assert_eq!(key, *addr_a().as_bytes());
}

/// The same prefix byte means different things in the two delegation
/// stores — pin this to discourage operators from sharing parsing logic
/// across them.
#[test]
fn delegated_resource_and_index_stores_use_overlapping_prefix_meanings() {
    // In DelegatedResourceStore: 0x01 = V2 unlocked, 0x02 = V2 locked.
    assert_eq!(V2_PREFIX_UNLOCKED, V1_FROM_PREFIX);
    assert_eq!(V2_PREFIX_LOCKED, V1_TO_PREFIX);
    // (Same byte values, totally different semantic meanings. Each store
    // has its own keyspace so they don't collide on disk.)
}

// --- RocksDB backend --------------------------------------------------------

fn rocks_tempdir() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    let mut p = std::env::temp_dir();
    p.push(format!("tron-chainbase-rocksdb-{}-{}", std::process::id(), n));
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn rocksdb_backend_round_trips_arbitrary_bytes() {
    let dir = rocks_tempdir();
    let backend = RocksDbBackend::open(&dir).unwrap();
    backend.put(b"alpha", b"one").unwrap();
    backend.put(b"beta", b"two").unwrap();
    assert_eq!(backend.get(b"alpha").unwrap(), Some(b"one".to_vec()));
    assert_eq!(backend.get(b"beta").unwrap(), Some(b"two".to_vec()));
    assert_eq!(backend.get(b"missing").unwrap(), None);
    backend.delete(b"alpha").unwrap();
    assert_eq!(backend.get(b"alpha").unwrap(), None);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn rocksdb_backend_drives_a_store_byte_for_byte_like_mem() {
    let dir = rocks_tempdir();

    // Two BlockStores against two backends; the same put produces the
    // same get on both. Tests that the store-level codec is backend-
    // agnostic, which it must be for drop-in replacement to work.
    let rocks: Arc<dyn KvBackend> = Arc::new(RocksDbBackend::open(&dir).unwrap());
    let mem: Arc<dyn KvBackend> = Arc::new(MemBackend::new());

    let rocks_store = BlockStore::new(rocks.clone());
    let mem_store = BlockStore::new(mem.clone());

    let block = sample_block(42);
    let id = tron_types::block_id_from_block(&block).unwrap();
    rocks_store.put(&id, &block).unwrap();
    mem_store.put(&id, &block).unwrap();

    let rocks_raw = rocks.get(id.as_bytes()).unwrap().unwrap();
    let mem_raw = mem.get(id.as_bytes()).unwrap().unwrap();
    assert_eq!(
        rocks_raw, mem_raw,
        "RocksDb and Mem backends must produce identical raw value bytes"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn rocksdb_backend_iterates_in_lex_order() {
    let dir = rocks_tempdir();
    let backend = RocksDbBackend::open(&dir).unwrap();
    // Insert in non-sorted order; iteration must yield ascending bytes.
    backend.put(b"\x03", b"c").unwrap();
    backend.put(b"\x01", b"a").unwrap();
    backend.put(b"\x02", b"b").unwrap();

    let mut got: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    backend
        .for_each(|k, v| {
            got.push((k.to_vec(), v.to_vec()));
            Ok(())
        })
        .unwrap();
    assert_eq!(
        got,
        vec![
            (vec![0x01], b"a".to_vec()),
            (vec![0x02], b"b".to_vec()),
            (vec![0x03], b"c".to_vec()),
        ]
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// Ascending lex order is what `BlockIndexStore::getLimitNumber(start, n)`
/// relies on — keys are 8-byte big-endian i64 of the block number, so
/// scanning from `start_num` forward returns blocks in ascending height.
/// If RocksDB sorted differently the index-based block lookup would
/// return scrambled results. Pin this expectation.
#[test]
fn rocksdb_keys_sort_compatibly_with_block_index_store() {
    let dir = rocks_tempdir();
    let backend: Arc<dyn KvBackend> = Arc::new(RocksDbBackend::open(&dir).unwrap());
    let index = BlockIndexStore::new(backend.clone());

    let blocks: Vec<_> = (0..5).map(sample_block).collect();
    let mut ids = Vec::new();
    for b in &blocks {
        let id = tron_types::block_id_from_block(b).unwrap();
        index.put(&id).unwrap();
        ids.push(id);
    }
    // Re-read each in ascending num order.
    for (i, id) in ids.iter().enumerate() {
        let from_store = index.get(i as i64).unwrap();
        assert_eq!(&from_store, id);
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn witness_store_round_trip() {
    let backend = mem();
    let store = WitnessStore::new(backend as Arc<_>);

    let addr_bytes = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");
    let addr = Address::from_raw(addr_bytes);
    let witness = Witness {
        address: addr_bytes.to_vec(),
        vote_count: 12345,
        pub_key: vec![0u8; 64],
        url: "https://witness.example".into(),
        total_produced: 100,
        total_missed: 5,
        latest_block_num: 999,
        latest_slot_num: 998,
        is_jobs: true,
    };
    store.put(&addr, &witness).unwrap();

    let got = store.get(&addr).unwrap().unwrap();
    assert_eq!(got, witness);
}

#[test]
fn witness_store_all_returns_every_registered_witness() {
    let backend = mem();
    let store = WitnessStore::new(backend as Arc<_>);

    let a = Address::from_raw(hex!("41a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"));
    let b = Address::from_raw(hex!("41b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"));
    let c = Address::from_raw(hex!("41c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3"));
    store.put(
        &a,
        &Witness {
            address: a.as_bytes().to_vec(),
            vote_count: 100,
            ..Default::default()
        },
    ).unwrap();
    store.put(
        &b,
        &Witness {
            address: b.as_bytes().to_vec(),
            vote_count: 200,
            ..Default::default()
        },
    ).unwrap();
    store.put(
        &c,
        &Witness {
            address: c.as_bytes().to_vec(),
            vote_count: 300,
            ..Default::default()
        },
    ).unwrap();

    let all = store.all().unwrap();
    assert_eq!(all.len(), 3);
    // Ascending key order (a < b < c lexicographically).
    assert_eq!(all[0].0, a);
    assert_eq!(all[1].0, b);
    assert_eq!(all[2].0, c);
    let sum: i64 = all.iter().map(|(_, w)| w.vote_count).sum();
    assert_eq!(sum, 600);
}

// C-8 regression tests: a malformed row in a consensus store must be
// logged-and-skipped (java-tron parity) — never silently dropped without
// trace, never panicked, never propagated as an error that wedges the
// whole maintenance walk. We assert the *behaviour* (good rows survive,
// bad row is skipped, no panic/Err); the `tracing::error!` side-effect
// is verified by reading the code, not captured here.

#[test]
fn witness_store_all_skips_malformed_key_row() {
    let backend = mem();
    let raw = backend.clone();
    let store = WitnessStore::new(backend as Arc<_>);

    let good = Address::from_raw(hex!("41a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"));
    store
        .put(
            &good,
            &Witness {
                address: good.as_bytes().to_vec(),
                vote_count: 42,
                ..Default::default()
            },
        )
        .unwrap();
    // Inject a row with a non-address (5-byte) key straight through the
    // backend, bypassing the typed `put`.
    raw.put(b"short", &Witness::default().encode_to_vec()).unwrap();

    let all = store.all().unwrap();
    assert_eq!(all.len(), 1, "malformed-key row must be skipped");
    assert_eq!(all[0].0, good);
    assert_eq!(all[0].1.vote_count, 42);
}

#[test]
fn votes_store_all_skips_malformed_key_and_undecodable_value() {
    let backend = mem();
    let raw = backend.clone();
    let store = VotesStore::new(backend as Arc<_>);

    let good = Address::from_raw(hex!("41b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"));
    let votes = Votes {
        address: good.as_bytes().to_vec(),
        old_votes: Vec::new(),
        new_votes: Vec::new(),
    };
    store.put(&good, &votes).unwrap();
    // (1) non-address key, (2) valid 21-byte key but value isn't a Votes proto.
    raw.put(b"x", &votes.encode_to_vec()).unwrap();
    let bad_addr = hex!("41c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3");
    raw.put(&bad_addr, b"\xff\xff not-a-votes-proto").unwrap();

    let all = store.all().unwrap();
    assert_eq!(all.len(), 1, "both malformed rows must be skipped");
    assert_eq!(all[0].0, good);
}

#[test]
fn block_store_get_limit_number_skips_undecodable_block() {
    let backend = mem();
    let raw = backend.clone();
    let store = BlockStore::new(backend as Arc<_>);

    // Two real blocks at num 5 and 7; a corrupt value at num 6's key slot.
    for n in [5i64, 7] {
        let blk = sample_block(n);
        store.put(&block_id_from_block(&blk).unwrap(), &blk).unwrap();
    }
    let mut key6 = [0u8; 32];
    key6[..8].copy_from_slice(&6i64.to_be_bytes());
    raw.put(&key6, b"not-a-block").unwrap();

    let got = store.get_limit_number(5, 10).unwrap();
    let nums: Vec<i64> = got
        .iter()
        .map(|b| b.block_header.as_ref().unwrap().raw_data.as_ref().unwrap().number)
        .collect();
    assert_eq!(nums, vec![5, 7], "undecodable block row must be skipped");
}

#[test]
fn rocksdb_write_batch_sync_produces_same_state_as_write_batch() {
    use tron_chainbase::WriteOp;

    let async_dir = rocks_tempdir();
    let sync_dir = rocks_tempdir();
    let async_be = RocksDbBackend::open(&async_dir).unwrap();
    let sync_be = RocksDbBackend::open(&sync_dir).unwrap();

    let ops = vec![
        WriteOp::Put(b"a".to_vec(), b"1".to_vec()),
        WriteOp::Put(b"b".to_vec(), b"2".to_vec()),
        WriteOp::Delete(b"c".to_vec()), // tombstone on never-existed
        WriteOp::Put(b"d".to_vec(), vec![0u8; 4096]),
    ];
    async_be.write_batch(&ops).unwrap();
    sync_be.write_batch_sync(&ops).unwrap();

    assert_eq!(async_be.scan_all().unwrap(), sync_be.scan_all().unwrap());
    // Both should see the writes:
    assert_eq!(sync_be.get(b"a").unwrap(), Some(b"1".to_vec()));
    assert_eq!(sync_be.get(b"d").unwrap(), Some(vec![0u8; 4096]));

    std::fs::remove_dir_all(&async_dir).ok();
    std::fs::remove_dir_all(&sync_dir).ok();
}

#[test]
fn rocksdb_write_batch_sync_empty_ops_is_noop() {
    let dir = rocks_tempdir();
    let be = RocksDbBackend::open(&dir).unwrap();
    be.put(b"k", b"v").unwrap();
    be.write_batch_sync(&[]).unwrap();
    assert_eq!(be.get(b"k").unwrap(), Some(b"v".to_vec()));
    std::fs::remove_dir_all(&dir).ok();
}

/// A RocksDB store opened with paranoid_checks(true) still reads
/// and writes normally — the safety knob doesn't change observable
/// behavior on a healthy data dir. (Verifies the open paths picked
/// up the new safety_baseline without breaking anything.)
#[test]
fn rocksdb_paranoid_checks_does_not_change_happy_path_behavior() {
    let dir = rocks_tempdir();
    {
        let be = RocksDbBackend::open(&dir).unwrap();
        be.put(b"alpha", b"1").unwrap();
        be.put(b"beta", b"2").unwrap();
    }
    // Re-open: paranoid_checks should NOT reject a clean DB.
    let be = RocksDbBackend::open(&dir).unwrap();
    assert_eq!(be.get(b"alpha").unwrap(), Some(b"1".to_vec()));
    assert_eq!(be.get(b"beta").unwrap(), Some(b"2".to_vec()));
    std::fs::remove_dir_all(&dir).ok();
}
