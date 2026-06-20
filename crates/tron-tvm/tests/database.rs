//! Tests for `TronDatabase` — the bridge between revm's `Database`
//! trait and our chainbase stores.
//!
//! Each test pins one observable property:
//! * EVM ↔ TRON address mapping is involutive.
//! * Balance round-trips lossy-ish (i64 ↔ U256) without corruption for
//!   in-range values.
//! * Storage uses the v2 composite key layout.
//! * `code_by_hash` returns `Bytecode::default()` for the empty-hash
//!   sentinel (`KECCAK_EMPTY`) without hitting the backing store.
//! * Commit preserves TRON-only fields (votes etc.) on existing
//!   accounts.

use std::sync::Arc;

use revm::primitives::{Address as EvmAddress, U256};
use revm::state::{Account, AccountInfo, AccountStatus, Bytecode, EvmStorageSlot};
use revm::{Database, DatabaseCommit, DatabaseRef};
use tron_chainbase::{AccountStore, CodeStore, KvBackend, MemBackend, StorageRowStore};
use tron_tvm::database::{code_hash, evm_to_tron_address, tron_to_evm_address, TronDatabase};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn fresh_db() -> TronDatabase {
    TronDatabase::new(
        Arc::new(AccountStore::new(mem())),
        Arc::new(CodeStore::new(mem())),
        Arc::new(StorageRowStore::new(mem())),
    )
}

#[test]
fn evm_to_tron_to_evm_round_trips() {
    let original = EvmAddress::from([0xab; 20]);
    let tron = evm_to_tron_address(&original);
    assert_eq!(tron.as_bytes()[0], 0x41);
    let back = tron_to_evm_address(&tron);
    assert_eq!(back, original);
}

#[test]
fn basic_returns_none_for_unknown_account() {
    let mut db = fresh_db();
    let addr = EvmAddress::from([0x11; 20]);
    assert!(db.basic(addr).unwrap().is_none());
}

#[test]
fn basic_reads_balance_and_code_hash_from_tron_account_store() {
    let mut db = fresh_db();
    let evm_addr = EvmAddress::from([0x22; 20]);
    let tron_addr = evm_to_tron_address(&evm_addr);

    db.accounts.put(
        &tron_addr,
        &tron_proto::Account {
            address: tron_addr.as_bytes().to_vec(),
            balance: 1_000_000,
            code_hash: vec![0x33u8; 32],
            ..Default::default()
        },
    ).unwrap();

    let info = db.basic(evm_addr).unwrap().unwrap();
    assert_eq!(info.balance, U256::from(1_000_000u64));
    assert_eq!(info.code_hash.as_slice(), &[0x33u8; 32]);
}

#[test]
fn basic_returns_keccak_empty_for_account_without_code_hash() {
    let mut db = fresh_db();
    let evm_addr = EvmAddress::from([0x55; 20]);
    let tron_addr = evm_to_tron_address(&evm_addr);
    db.accounts.put(
        &tron_addr,
        &tron_proto::Account {
            address: tron_addr.as_bytes().to_vec(),
            balance: 0,
            ..Default::default()
        },
    ).unwrap();
    let info = db.basic(evm_addr).unwrap().unwrap();
    assert_eq!(info.code_hash, revm::primitives::KECCAK_EMPTY);
}

#[test]
fn code_by_hash_short_circuits_for_keccak_empty_sentinel() {
    let mut db = fresh_db();
    let bc = db.code_by_hash(revm::primitives::KECCAK_EMPTY).unwrap();
    assert!(bc.is_empty(), "empty hash should yield empty bytecode");
}

#[test]
fn code_by_hash_reads_back_what_was_written_to_code_store() {
    let mut db = fresh_db();
    let bytes = vec![0x60, 0x00, 0x60, 0x00, 0xf3]; // PUSH1 0 PUSH1 0 RETURN
    let hash = code_hash(&bytes);
    db.code.put(hash.as_slice(), &bytes).unwrap();

    let bc = db.code_by_hash(hash).unwrap();
    assert_eq!(bc.original_byte_slice(), bytes.as_slice());
}

#[test]
fn storage_reads_zero_for_unset_slot() {
    let mut db = fresh_db();
    let addr = EvmAddress::from([0x77; 20]);
    let val = db.storage(addr, U256::from(0u8)).unwrap();
    assert_eq!(val, U256::ZERO);
}

#[test]
fn storage_round_trips_via_v2_composite_key() {
    let mut db = fresh_db();
    let evm_addr = EvmAddress::from([0x88; 20]);
    let tron_addr = evm_to_tron_address(&evm_addr);

    let slot_key = U256::from(42u8);
    let slot_bytes: [u8; 32] = slot_key.to_be_bytes();
    let composite = StorageRowStore::compose_key(&tron_addr, &slot_bytes);

    let value = U256::from(0x12345678u64);
    let value_bytes: [u8; 32] = value.to_be_bytes();
    db.storage.put(&composite, &value_bytes).unwrap();

    let read_back = db.storage(evm_addr, slot_key).unwrap();
    assert_eq!(read_back, value);
}

// === Commit ================================================================

fn make_touched_account(balance: u64) -> Account {
    let mut a = Account::default();
    a.info = AccountInfo {
        balance: U256::from(balance),
        nonce: 1,
        code_hash: revm::primitives::KECCAK_EMPTY,
        account_id: None,
        code: None,
    };
    a.status = AccountStatus::Touched;
    a
}

#[test]
fn commit_writes_new_account_balance() {
    let mut db = fresh_db();
    let evm_addr = EvmAddress::from([0xaa; 20]);
    let tron_addr = evm_to_tron_address(&evm_addr);

    let mut changes = revm::primitives::AddressMap::default();
    changes.insert(evm_addr, make_touched_account(42_000_000));
    db.commit(changes);

    let acct = db.accounts.get(&tron_addr).unwrap().unwrap();
    assert_eq!(acct.balance, 42_000_000);
}

#[test]
fn commit_preserves_tron_only_fields_on_existing_account() {
    let mut db = fresh_db();
    let evm_addr = EvmAddress::from([0xbb; 20]);
    let tron_addr = evm_to_tron_address(&evm_addr);

    // Seed the account with TRON-only data: votes, frozen, asset map.
    db.accounts.put(
        &tron_addr,
        &tron_proto::Account {
            address: tron_addr.as_bytes().to_vec(),
            balance: 100,
            votes: vec![tron_proto::Vote {
                vote_address: vec![0x41; 21],
                vote_count: 5,
            }],
            allowance: 999,
            ..Default::default()
        },
    ).unwrap();

    // Touch the account through revm with a new balance only.
    let mut changes = revm::primitives::AddressMap::default();
    changes.insert(evm_addr, make_touched_account(200));
    db.commit(changes);

    let after = db.accounts.get(&tron_addr).unwrap().unwrap();
    assert_eq!(after.balance, 200, "balance updated");
    assert_eq!(after.votes.len(), 1, "TRON-only votes preserved");
    assert_eq!(after.allowance, 999, "TRON-only allowance preserved");
}

#[test]
fn commit_writes_code_and_code_hash_on_contract_deployment() {
    let mut db = fresh_db();
    let evm_addr = EvmAddress::from([0xcc; 20]);
    let tron_addr = evm_to_tron_address(&evm_addr);

    let runtime_code = vec![0x60u8, 0x42, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];
    let hash = code_hash(&runtime_code);

    let mut account = make_touched_account(0);
    account.info.code = Some(Bytecode::new_raw(runtime_code.clone().into()));
    account.info.code_hash = hash;

    let mut changes = revm::primitives::AddressMap::default();
    changes.insert(evm_addr, account);
    db.commit(changes);

    // CodeStore got the bytecode keyed by ADDRESS (java-tron layout).
    assert_eq!(db.code.get(tron_addr.as_bytes()).unwrap().unwrap(), runtime_code);
    // Account got both the inline code and the hash.
    let acct = db.accounts.get(&tron_addr).unwrap().unwrap();
    assert_eq!(acct.code, runtime_code);
    assert_eq!(acct.code_hash, hash.as_slice());
}

#[test]
fn commit_writes_changed_storage_slots() {
    let mut db = fresh_db();
    let evm_addr = EvmAddress::from([0xdd; 20]);
    let tron_addr = evm_to_tron_address(&evm_addr);

    let mut account = make_touched_account(0);
    let slot = U256::from(7u8);
    let new_value = U256::from(0xdeadbeefu64);
    // present != original → "changed".
    account.storage.insert(
        slot,
        EvmStorageSlot::new_changed(U256::ZERO, new_value, Default::default()),
    );

    let mut changes = revm::primitives::AddressMap::default();
    changes.insert(evm_addr, account);
    db.commit(changes);

    let slot_bytes: [u8; 32] = slot.to_be_bytes();
    let composite = StorageRowStore::compose_key(&tron_addr, &slot_bytes);
    let stored = db.storage.get(&composite).unwrap().unwrap();
    let expected: [u8; 32] = new_value.to_be_bytes();
    assert_eq!(stored, expected.to_vec());
}

#[test]
fn commit_deletes_selfdestructed_accounts() {
    let mut db = fresh_db();
    let evm_addr = EvmAddress::from([0xee; 20]);
    let tron_addr = evm_to_tron_address(&evm_addr);

    db.accounts.put(
        &tron_addr,
        &tron_proto::Account {
            address: tron_addr.as_bytes().to_vec(),
            balance: 1_000,
            ..Default::default()
        },
    ).unwrap();

    let mut account = make_touched_account(0);
    account.status |= AccountStatus::SelfDestructed;

    let mut changes = revm::primitives::AddressMap::default();
    changes.insert(evm_addr, account);
    db.commit(changes);

    assert!(db.accounts.get(&tron_addr).unwrap().is_none());
}

#[test]
fn commit_skips_loaded_but_untouched_accounts() {
    let mut db = fresh_db();
    let evm_addr = EvmAddress::from([0xff; 20]);
    let tron_addr = evm_to_tron_address(&evm_addr);

    db.accounts.put(
        &tron_addr,
        &tron_proto::Account {
            address: tron_addr.as_bytes().to_vec(),
            balance: 500,
            ..Default::default()
        },
    ).unwrap();

    let mut untouched = Account::default();
    untouched.info = AccountInfo {
        balance: U256::from(999u64), // would overwrite if applied
        ..Default::default()
    };
    untouched.status = AccountStatus::default(); // NOT Touched

    let mut changes = revm::primitives::AddressMap::default();
    changes.insert(evm_addr, untouched);
    db.commit(changes);

    // Balance unchanged — untouched accounts don't get written.
    let after = db.accounts.get(&tron_addr).unwrap().unwrap();
    assert_eq!(after.balance, 500);
}

// === BLOCKHASH ==============================================================

#[test]
fn block_hash_returns_zero_without_index_attached() {
    let db = fresh_db();
    let h = db.block_hash_ref(42).unwrap();
    assert_eq!(h, revm::primitives::B256::ZERO);
}

#[test]
fn block_hash_returns_stored_id_when_index_attached() {
    use tron_chainbase::BlockIndexStore;
    use tron_types::BlockId;

    let index_backend = mem();
    let index = Arc::new(BlockIndexStore::new(index_backend));

    // Synthesize a BlockId: high 8 bytes encode the block number; the
    // remaining 24 bytes can be anything (we use 0xab).
    let mut raw = [0xabu8; 32];
    raw[0..8].copy_from_slice(&100u64.to_be_bytes());
    let id = BlockId::from_raw(raw);
    index.put(&id).unwrap();

    let mut db = fresh_db();
    db.block_index = Some(index);

    let h = db.block_hash_ref(100).unwrap();
    assert_eq!(h.as_slice(), id.as_bytes());

    // Unknown block number → zero.
    let h_missing = db.block_hash_ref(999).unwrap();
    assert_eq!(h_missing, revm::primitives::B256::ZERO);
}

// === v1 vs v2 storage-key layout selection ================================

#[test]
fn storage_uses_v2_layout_when_no_contract_store_attached() {
    let mut db = fresh_db();
    let evm_addr = EvmAddress::from([0xab; 20]);
    let tron_addr = evm_to_tron_address(&evm_addr);

    // Pre-write a value via the v2 composite key.
    let slot = U256::from(7u8);
    let slot_bytes: [u8; 32] = slot.to_be_bytes();
    let v2_key = tron_chainbase::StorageRowStore::compose_key(&tron_addr, &slot_bytes);
    db.storage.put(&v2_key, &[0xffu8; 32]).unwrap();

    // Read should hit the v2 key.
    let val = db.storage(evm_addr, slot).unwrap();
    assert_ne!(val, U256::ZERO, "v2 read should find the row");
}

#[test]
fn storage_uses_v1_layout_when_contract_version_is_1() {
    use tron_chainbase::ContractStore;
    use tron_proto::SmartContract;

    let mut db = fresh_db();
    let contracts = Arc::new(ContractStore::new(mem()));
    let evm_addr = EvmAddress::from([0xcd; 20]);
    let tron_addr = evm_to_tron_address(&evm_addr);

    // Register the contract with version=1.
    contracts.put(
        &tron_addr,
        &SmartContract {
            origin_address: tron_addr.as_bytes().to_vec(),
            contract_address: tron_addr.as_bytes().to_vec(),
            version: 1,
            ..Default::default()
        },
    ).unwrap();
    db.contracts = Some(contracts);

    // Write to the v1 key (slot pre-hashed).
    let slot = U256::from(42u8);
    let slot_bytes: [u8; 32] = slot.to_be_bytes();
    let v1_key = tron_chainbase::StorageRowStore::compose_key_v1(&tron_addr, &slot_bytes);
    let v2_key = tron_chainbase::StorageRowStore::compose_key(&tron_addr, &slot_bytes);
    assert_ne!(v1_key, v2_key, "v1 and v2 keys must differ for sanity");

    db.storage.put(&v1_key, &[0x77u8; 32]).unwrap();

    // With v1 routing in place, the read should find the value at v1_key.
    let val = db.storage(evm_addr, slot).unwrap();
    assert_ne!(val, U256::ZERO, "v1 contract should read via the v1 layout");

    // Writing to the v2 key only should NOT be visible.
    let other_slot = U256::from(99u8);
    let other_slot_bytes: [u8; 32] = other_slot.to_be_bytes();
    let v2_other = tron_chainbase::StorageRowStore::compose_key(&tron_addr, &other_slot_bytes);
    db.storage.put(&v2_other, &[0xaau8; 32]).unwrap();
    let val2 = db.storage(evm_addr, other_slot).unwrap();
    assert_eq!(
        val2, U256::ZERO,
        "v1 contract reading a slot only written via v2 must miss"
    );
}

#[test]
fn commit_skips_touched_empty_new_account() {
    // EIP-161 / java parity: a CALL that merely touches a previously
    // non-existent address with no value, code, or storage must NOT create an
    // account (java gates createAccountIfNotExist on endowment > 0).
    let mut db = fresh_db();
    let evm_addr = EvmAddress::from([0xab; 20]);
    let tron_addr = evm_to_tron_address(&evm_addr);

    let account = make_touched_account(0); // balance 0, no code, no storage
    let mut changes = revm::primitives::AddressMap::default();
    changes.insert(evm_addr, account);
    db.commit(changes);

    assert!(
        db.accounts.get(&tron_addr).unwrap().is_none(),
        "a touched-but-empty new account must not be persisted"
    );
}

#[test]
fn commit_persists_value_funded_new_account() {
    // The flip side: a CALL that transfers value to a new address DOES create
    // it — the empty-account skip must not drop a value-funded account.
    let mut db = fresh_db();
    let evm_addr = EvmAddress::from([0xac; 20]);
    let tron_addr = evm_to_tron_address(&evm_addr);

    let account = make_touched_account(500); // balance > 0
    let mut changes = revm::primitives::AddressMap::default();
    changes.insert(evm_addr, account);
    db.commit(changes);

    let acct = db
        .accounts
        .get(&tron_addr)
        .unwrap()
        .expect("a value-funded new account must be persisted");
    assert_eq!(acct.balance, 500);
}
