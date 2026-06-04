//! Tests for the second batch of ported stores: Proposal, Exchange (v1/v2),
//! AssetIssue (v1/v2), Contract, Code, Abi, StorageRow, WitnessSchedule,
//! AccountIndex, RecentBlock. Each store has its own key encoding pinned
//! here so a regression on any byte fires loudly.

use std::sync::Arc;

use hex_literal::hex;
use tron_chainbase::{
    witness_schedule_keys, AbiStore, AccountIndexStore, AssetIssueStore, AssetIssueV2Store,
    CodeStore, ContractStore, ExchangeStore, ExchangeV2Store, KvBackend, MemBackend, ProposalStore,
    RecentBlockStore, StorageRowStore, WitnessScheduleStore,
};
use tron_crypto::address::Address;

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn alice() -> Address {
    Address::from_raw(hex!("412e988a386a799f506693793c6a5af6b54dfaabfb"))
}

fn bob() -> Address {
    Address::from_raw(hex!("41a614f803b6fd780986a42c78ec9c7f77e6ded13c"))
}

// --- DB_NAME constants pinned ----------------------------------------------

/// java-tron writes one directory per store under `output-directory/database/`.
/// A drifted directory name means the Rust node and the Java node disagree on
/// where to find the same store. This single test pins every DB_NAME so any
/// rename triggers a failure.
#[test]
fn db_names_match_java_tron_directories() {
    assert_eq!(ProposalStore::DB_NAME, "proposal");
    assert_eq!(ExchangeStore::DB_NAME, "exchange");
    assert_eq!(ExchangeV2Store::DB_NAME, "exchange-v2");
    assert_eq!(AssetIssueStore::DB_NAME, "asset-issue");
    assert_eq!(AssetIssueV2Store::DB_NAME, "asset-issue-v2");
    assert_eq!(ContractStore::DB_NAME, "contract");
    assert_eq!(CodeStore::DB_NAME, "code");
    assert_eq!(AbiStore::DB_NAME, "abi");
    assert_eq!(StorageRowStore::DB_NAME, "storage-row");
    assert_eq!(AccountIndexStore::DB_NAME, "account-index");
    assert_eq!(RecentBlockStore::DB_NAME, "recent-block");
    // WitnessScheduleStore uses an UNDERSCORE, not a hyphen — easy mistake.
    assert_eq!(WitnessScheduleStore::DB_NAME, "witness_schedule");
}

// --- ProposalStore ---------------------------------------------------------

#[test]
fn proposal_key_is_be_i64() {
    assert_eq!(ProposalStore::key_for(0), [0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(ProposalStore::key_for(1), [0, 0, 0, 0, 0, 0, 0, 1]);
    assert_eq!(
        ProposalStore::key_for(0x0102030405060708),
        [1, 2, 3, 4, 5, 6, 7, 8]
    );
}

#[test]
fn proposal_round_trip() {
    let store = ProposalStore::new(mem());
    let p = tron_proto::Proposal {
        proposal_id: 42,
        proposer_address: alice().as_bytes().to_vec(),
        parameters: std::collections::BTreeMap::from([(1i64, 1000i64)]),
        expiration_time: 1_700_000_000_000,
        create_time: 1_690_000_000_000,
        approvals: vec![bob().as_bytes().to_vec()],
        state: tron_proto::proposal::State::Pending as i32,
    };
    store.put(42, &p).unwrap();
    assert_eq!(store.get(42).unwrap().unwrap(), p);
    assert!(store.get(43).unwrap().is_none());
}

// --- ExchangeStore + ExchangeV2Store ---------------------------------------

#[test]
fn exchange_keys_are_8_byte_be_i64() {
    assert_eq!(ExchangeStore::key_for(1), [0, 0, 0, 0, 0, 0, 0, 1]);
    assert_eq!(ExchangeV2Store::key_for(1), [0, 0, 0, 0, 0, 0, 0, 1]);
    // V1 and V2 use *identical* key encoding — the split is the directory,
    // not the bytes.
    assert_eq!(ExchangeStore::key_for(999), ExchangeV2Store::key_for(999));
}

#[test]
fn exchange_round_trip() {
    let store = ExchangeStore::new(mem());
    let exchange = tron_proto::Exchange {
        exchange_id: 7,
        creator_address: alice().as_bytes().to_vec(),
        create_time: 1_700_000_000_000,
        first_token_id: b"_".to_vec(),
        first_token_balance: 1_000_000_000,
        second_token_id: b"TEST".to_vec(),
        second_token_balance: 5_000_000_000,
    };
    store.put(7, &exchange).unwrap();
    assert_eq!(store.get(7).unwrap().unwrap(), exchange);
}

// --- AssetIssueStore + V2 --------------------------------------------------

/// **V1/V2 distinction**: V1 keys are the asset's *name* (raw bytes);
/// V2 keys are the asset's *id* as a decimal-string (UTF-8 bytes).
/// Same proto value, completely different keyspaces.
#[test]
fn asset_issue_v2_key_is_decimal_string_bytes() {
    assert_eq!(AssetIssueV2Store::key_for(1), b"1");
    assert_eq!(AssetIssueV2Store::key_for(1_000_001), b"1000001");
    assert_eq!(AssetIssueV2Store::key_for(0), b"0");
}

#[test]
fn asset_issue_v1_uses_name_as_key() {
    let store = AssetIssueStore::new(mem());
    let asset = tron_proto::AssetIssueContract {
        owner_address: alice().as_bytes().to_vec(),
        name: b"MyToken".to_vec(),
        abbr: b"MTK".to_vec(),
        total_supply: 1_000_000_000_000,
        id: "1000001".into(),
        ..Default::default()
    };
    store.put(b"MyToken", &asset).unwrap();
    assert_eq!(store.get(b"MyToken").unwrap().unwrap(), asset);
    // Looking up by V2 id against the V1 store yields nothing.
    assert!(store.get(b"1000001").unwrap().is_none());
}

#[test]
fn asset_issue_v2_uses_decimal_id_as_key() {
    let backend = mem();
    let store = AssetIssueV2Store::new(backend.clone());
    let asset = tron_proto::AssetIssueContract {
        name: b"MyToken".to_vec(),
        id: "1000001".into(),
        ..Default::default()
    };
    store.put(1_000_001, &asset).unwrap();
    // The key on disk is the UTF-8 bytes of the decimal id.
    assert!(backend.get(b"1000001").unwrap().is_some());
    assert!(backend.get(b"MyToken").unwrap().is_none());
    assert_eq!(store.get(1_000_001).unwrap().unwrap(), asset);
}

// --- ContractStore ----------------------------------------------------------

/// **Critical write-time behaviour**: java-tron strips the ABI before
/// writing a contract to ContractStore (it lives in AbiStore). We replicate
/// that here so the on-disk value bytes match.
#[test]
fn contract_store_strips_abi_on_put() {
    let store = ContractStore::new(mem());
    let abi = tron_proto::smart_contract::Abi {
        entrys: vec![tron_proto::smart_contract::abi::Entry::default()],
    };
    let contract = tron_proto::SmartContract {
        origin_address: alice().as_bytes().to_vec(),
        contract_address: bob().as_bytes().to_vec(),
        abi: Some(abi.clone()),
        bytecode: b"\x60\x80\x60\x40".to_vec(),
        ..Default::default()
    };
    store.put(&bob(), &contract).unwrap();
    let got = store.get(&bob()).unwrap().unwrap();
    assert_eq!(got.bytecode, contract.bytecode);
    assert!(got.abi.is_none(), "ABI must be cleared on write");
}

// --- CodeStore + AbiStore --------------------------------------------------

#[test]
fn code_store_writes_raw_bytecode() {
    let store = CodeStore::new(mem());
    let hash = [0xabu8; 32];
    let code = vec![0x60, 0x80, 0x60, 0x40, 0x52];
    store.put(&hash, &code).unwrap();
    assert_eq!(store.get(&hash).unwrap(), Some(code));
}

#[test]
fn abi_store_round_trip() {
    let store = AbiStore::new(mem());
    let abi = tron_proto::smart_contract::Abi {
        entrys: vec![tron_proto::smart_contract::abi::Entry {
            r#type: tron_proto::smart_contract::abi::entry::EntryType::Function as i32,
            name: "transfer".into(),
            ..Default::default()
        }],
    };
    store.put(&bob(), &abi).unwrap();
    assert_eq!(store.get(&bob()).unwrap().unwrap(), abi);
}

// --- StorageRowStore --------------------------------------------------------

/// Pin the composite key shape: `addrHash[0..16] || slot[16..32]`.
/// Pinning this guards against the very specific bug of using
/// `addrHash[16..32] || slot[0..16]` or other interleavings.
#[test]
fn storage_row_key_layout_is_addrhash_lower_half_then_slot_upper_half() {
    let addr = alice();
    let slot = [0xccu8; 32];
    let key = StorageRowStore::compose_key(&addr, &slot);

    let addr_hash = tron_crypto::hash::keccak256(addr.as_bytes());
    assert_eq!(&key[0..16], &addr_hash[0..16], "first 16 bytes must be addr_hash[0..16]");
    assert_eq!(&key[16..32], &slot[16..32], "last 16 bytes must be slot[16..32]");
}

#[test]
fn storage_row_v1_key_hashes_slot_first() {
    let addr = alice();
    let slot = [0xccu8; 32];
    let key = StorageRowStore::compose_key_v1(&addr, &slot);
    let slot_hash = tron_crypto::hash::keccak256(&slot);
    let addr_hash = tron_crypto::hash::keccak256(addr.as_bytes());
    assert_eq!(&key[0..16], &addr_hash[0..16]);
    assert_eq!(&key[16..32], &slot_hash[16..32]);
}

#[test]
fn storage_row_round_trip() {
    let store = StorageRowStore::new(mem());
    let key = StorageRowStore::compose_key(&alice(), &[1u8; 32]);
    let value = vec![0xde, 0xad, 0xbe, 0xef];
    store.put(&key, &value).unwrap();
    assert_eq!(store.get(&key).unwrap(), Some(value));
}

// --- WitnessScheduleStore --------------------------------------------------

/// java-tron uses the wonderfully easy-to-mistype `witness_schedule`
/// with an underscore. Every other store name uses hyphens.
#[test]
fn witness_schedule_directory_uses_underscore() {
    assert_eq!(WitnessScheduleStore::DB_NAME, "witness_schedule");
    assert!(!WitnessScheduleStore::DB_NAME.contains('-'));
}

#[test]
fn witness_schedule_keys_pinned() {
    assert_eq!(witness_schedule_keys::ACTIVE_WITNESSES, b"active_witnesses");
    assert_eq!(
        witness_schedule_keys::CURRENT_SHUFFLED_WITNESSES,
        b"current_shuffled_witnesses"
    );
}

#[test]
fn witness_schedule_packs_addresses_flat() {
    let store = WitnessScheduleStore::new(mem());
    let witnesses = vec![alice(), bob(), alice()];
    store.save_active(&witnesses).unwrap();
    let got = store.load_active().unwrap().unwrap();
    assert_eq!(got.len(), 3);
    assert_eq!(got[0], alice());
    assert_eq!(got[1], bob());
    assert_eq!(got[2], alice());
}

#[test]
fn witness_schedule_rejects_misaligned_buffer() {
    let backend = mem();
    backend.put(witness_schedule_keys::ACTIVE_WITNESSES, &[0u8; 20]).unwrap(); // not a multiple of 21
    let store = WitnessScheduleStore::new(backend);
    assert!(store.load_active().is_err());
}

// --- AccountIndexStore ------------------------------------------------------

#[test]
fn account_index_round_trip() {
    let store = AccountIndexStore::new(mem());
    store.put(b"Alice", &alice()).unwrap();
    assert_eq!(store.get(b"Alice").unwrap().unwrap(), alice());
    assert!(store.get(b"Bob").unwrap().is_none());
}

#[test]
fn account_index_rejects_wrong_length_value() {
    let backend = mem();
    backend.put(b"Alice", &[0u8; 20]).unwrap(); // 20, not 21
    let store = AccountIndexStore::new(backend);
    assert!(store.get(b"Alice").is_err());
}

// --- RecentBlockStore -------------------------------------------------------

/// Window wraps every 65,536 blocks. Two heights 65,536 apart map to the
/// same key — the older entry is overwritten. Pinning the formula.
#[test]
fn recent_block_key_is_low_16_bits_big_endian() {
    assert_eq!(RecentBlockStore::key_for(0), [0, 0]);
    assert_eq!(RecentBlockStore::key_for(1), [0, 1]);
    assert_eq!(RecentBlockStore::key_for(0xFFFF), [0xFF, 0xFF]);
    // 65_536 wraps back to 0.
    assert_eq!(RecentBlockStore::key_for(65_536), [0, 0]);
    assert_eq!(RecentBlockStore::key_for(65_537), RecentBlockStore::key_for(1));
}

#[test]
fn recent_block_round_trip_via_wrapping_key() {
    let store = RecentBlockStore::new(mem());
    store.put(100, &[0xa1, 0xa2]).unwrap();
    assert_eq!(store.get(100).unwrap(), Some(vec![0xa1, 0xa2]));
    // A height 65,536 blocks later overwrites the earlier slot.
    store.put(100 + 65_536, &[0xb1, 0xb2]).unwrap();
    assert_eq!(store.get(100).unwrap(), Some(vec![0xb1, 0xb2]));
}
