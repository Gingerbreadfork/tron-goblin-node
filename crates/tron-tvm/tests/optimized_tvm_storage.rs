//! java-tron 4.8.2.3 storage-row rules: the 48-byte key scheme under
//! `ALLOW_OPTIMIZE_TVM_STORAGE` (proposal 99) — new-key-first reads, zero
//! values stored explicitly, legacy rows deleted on write and migrated on
//! read — and, without it, `Storage.checkAlias` once `VERSION_4_8_2_3` passed:
//! two slots of one contract that share a legacy key fail the transaction.

use std::sync::Arc;

use tron_chainbase::fork::VERSION_4_8_2_3;
use tron_chainbase::{
    AccountStore, CodeStore, ContractStateStore, DelegatedResourceStore, DelegationStore,
    DynamicPropertiesStore, KvBackend, MemBackend, StorageRowStore, VotesStore, WitnessStore,
};
use tron_crypto::address::Address;
use tron_proto::transaction::result::ContractResult;
use tron_proto::{Account, TriggerSmartContract};
use tron_tvm::database::code_hash;
use tron_tvm::execute::{execute_trigger, VmBlockEnv, VmOutcome, VmStores};

const NOW_MS: i64 = 1_700_000_000_000;
const LIMIT: u64 = 1_000_000;

const CONTRACT: [u8; 21] = [
    0x41, 0xa6, 0x14, 0xf8, 0x03, 0xb6, 0xfd, 0x78, 0x09, 0x86, 0xa4, 0x2c, 0x78, 0xec, 0x9c,
    0x7f, 0x77, 0xe6, 0xde, 0xd1, 0x3c,
];
const CALLER: [u8; 21] = [
    0x41, 0xc5, 0x87, 0xea, 0x9a, 0xde, 0xe6, 0xdf, 0xd6, 0x92, 0x80, 0x95, 0xe4, 0x32, 0xcd,
    0x89, 0xae, 0x37, 0x9f, 0xf7, 0xf9,
];

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn stores() -> VmStores {
    let dp = Arc::new(DynamicPropertiesStore::new(mem()));
    for k in [
        "ALLOW_TVM_CONSTANTINOPLE",
        "ALLOW_TVM_SOLIDITY_059",
        "ALLOW_TVM_ISTANBUL",
        "ALLOW_TVM_LONDON",
        "ALLOW_TVM_SHANGHAI",
        "ALLOW_ENERGY_ADJUSTMENT",
        "ALLOW_HIGHER_LIMIT_FOR_MAX_CPU_TIME_OF_ONE_TX",
    ] {
        dp.put_long(k.as_bytes(), 1);
    }
    dp.save_latest_block_header_timestamp(NOW_MS);
    VmStores {
        accounts: Arc::new(AccountStore::new(mem())),
        code: Arc::new(CodeStore::new(mem())),
        storage: Arc::new(StorageRowStore::new(mem())),
        witnesses: Arc::new(WitnessStore::new(mem())),
        contract_state: Arc::new(ContractStateStore::new(mem())),
        dynamic_properties: dp,
        delegated_resources: Arc::new(DelegatedResourceStore::new(mem())),
        delegated_resource_account_index: None,
        delegation: Arc::new(DelegationStore::new(mem())),
        block_index: None,
        contracts: None,
        votes: Some(Arc::new(VotesStore::new(mem()))),
        reward_vi: None,
        abi: None,
    }
}

fn optimized_stores() -> VmStores {
    let stores = stores();
    stores
        .dynamic_properties
        .put_long(b"ALLOW_OPTIMIZE_TVM_STORAGE", 1);
    stores
}

fn pass_alias_fork(stores: &VmStores) {
    stores
        .dynamic_properties
        .save_fork_stats(VERSION_4_8_2_3, &[1u8; 27]);
    assert!(stores.dynamic_properties.fork_passed(VERSION_4_8_2_3));
}

fn slot(n: u8) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[31] = n;
    w
}

/// A slot whose legacy key coincides with `slot(n)`'s: only the lower 16
/// bytes of the slot word reach the 32-byte row key.
fn aliasing_slot(n: u8) -> [u8; 32] {
    let mut w = slot(n);
    w[..16].fill(0xff);
    w
}

fn addr_hash() -> [u8; 32] {
    StorageRowStore::addr_hash(&Address::from_raw(CONTRACT), &[])
}

fn legacy_key(s: &[u8; 32]) -> [u8; 32] {
    StorageRowStore::compose_key_with_addr_hash(&addr_hash(), s, false)
}

fn new_key(s: &[u8; 32]) -> [u8; 48] {
    StorageRowStore::new_row_key(&addr_hash(), s)
}

fn word(v: u8) -> [u8; 32] {
    slot(v)
}

fn legacy_row(stores: &VmStores, s: &[u8; 32]) -> Option<Vec<u8>> {
    stores.storage.get(&legacy_key(s)).unwrap()
}

fn new_row(stores: &VmStores, s: &[u8; 32]) -> Option<Vec<u8>> {
    stores.storage.get_raw(&new_key(s)).unwrap()
}

fn push_u256(w: [u8; 32]) -> Vec<u8> {
    let mut out = vec![0x7f];
    out.extend_from_slice(&w);
    out
}

/// `SSTORE(dst, SLOAD(src))`.
fn copy_slot(src: [u8; 32], dst: [u8; 32]) -> Vec<u8> {
    let mut bc = push_u256(src);
    bc.push(0x54); // SLOAD
    bc.extend(push_u256(dst));
    bc.push(0x55); // SSTORE
    bc
}

/// `SLOAD(src); POP`.
fn read_slot(src: [u8; 32]) -> Vec<u8> {
    let mut bc = push_u256(src);
    bc.push(0x54);
    bc.push(0x50);
    bc
}

/// `SSTORE(dst, value)`.
fn write_slot(dst: [u8; 32], value: [u8; 32]) -> Vec<u8> {
    let mut bc = push_u256(value);
    bc.extend(push_u256(dst));
    bc.push(0x55);
    bc
}

/// Installs (or replaces) the contract's runtime code. The code is keyed by
/// address as well, the way a committed deploy leaves it, so a re-install
/// after a run replaces what the VM will load.
fn install(stores: &VmStores, bytecode: Vec<u8>) {
    let hash = code_hash(&bytecode);
    stores.code.put(hash.as_slice(), &bytecode).unwrap();
    stores.code.put(&CONTRACT, &bytecode).unwrap();
    stores
        .accounts
        .put(
            &Address::from_raw(CONTRACT),
            &Account {
                address: CONTRACT.to_vec(),
                code: bytecode,
                code_hash: hash.as_slice().to_vec(),
                ..Default::default()
            },
        )
        .unwrap();
    stores
        .accounts
        .put(
            &Address::from_raw(CALLER),
            &Account {
                address: CALLER.to_vec(),
                balance: 1_000_000_000,
                ..Default::default()
            },
        )
        .unwrap();
}

fn run(stores: &VmStores) -> VmOutcome {
    execute_trigger(
        stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: NOW_MS,
            ..Default::default()
        },
        &TriggerSmartContract {
            owner_address: CALLER.to_vec(),
            contract_address: CONTRACT.to_vec(),
            call_value: 0,
            data: vec![],
            call_token_value: 0,
            token_id: 0,
        },
        LIMIT,
    )
}

fn run_ok(stores: &VmStores) {
    let out = run(stores);
    assert!(matches!(out, VmOutcome::Success { .. }), "expected Success, got {out:?}");
}

#[test]
fn write_lands_under_the_new_key_and_drops_the_legacy_row() {
    let stores = optimized_stores();
    stores.storage.put(&legacy_key(&slot(5)), &word(7)).unwrap();
    let mut code = copy_slot(slot(5), slot(6));
    code.extend(write_slot(slot(5), word(9)));
    code.push(0x00);
    install(&stores, code);
    run_ok(&stores);
    assert_eq!(new_row(&stores, &slot(5)), Some(word(9).to_vec()));
    assert_eq!(legacy_row(&stores, &slot(5)), None);
    // Slot 6 was never read before its write: new key only.
    assert_eq!(new_row(&stores, &slot(6)), Some(word(7).to_vec()));
    assert_eq!(legacy_row(&stores, &slot(6)), None);
    assert_eq!(
        stores.storage.read_slot(&addr_hash(), &slot(5), false, true).unwrap(),
        Some(word(9).to_vec())
    );
}

#[test]
fn a_slot_that_is_only_read_is_migrated() {
    let stores = optimized_stores();
    stores.storage.put(&legacy_key(&slot(5)), &word(7)).unwrap();
    let mut code = read_slot(slot(5));
    code.push(0x00);
    install(&stores, code);
    run_ok(&stores);
    assert_eq!(new_row(&stores, &slot(5)), Some(word(7).to_vec()));
    assert_eq!(legacy_row(&stores, &slot(5)), None);
}

#[test]
fn a_zero_write_persists_as_an_explicit_zero_row() {
    let stores = optimized_stores();
    stores.storage.put(&legacy_key(&slot(5)), &word(7)).unwrap();
    let mut code = write_slot(slot(5), [0u8; 32]);
    code.push(0x00);
    install(&stores, code);
    run_ok(&stores);
    assert_eq!(new_row(&stores, &slot(5)), Some(vec![0u8; 32]));
    assert_eq!(legacy_row(&stores, &slot(5)), None);
    // The zero row now answers every later read.
    stores.storage.put(&legacy_key(&slot(5)), &word(7)).unwrap();
    let mut code = copy_slot(slot(5), slot(6));
    code.push(0x00);
    install(&stores, code);
    run_ok(&stores);
    assert_eq!(new_row(&stores, &slot(6)), Some([0u8; 32].to_vec()));
    assert_eq!(legacy_row(&stores, &slot(5)), Some(word(7).to_vec()));
}

#[test]
fn an_existing_new_row_shadows_the_legacy_row() {
    let stores = optimized_stores();
    stores.storage.put(&legacy_key(&slot(5)), &word(7)).unwrap();
    stores.storage.put_raw(&new_key(&slot(5)), &word(3)).unwrap();
    let mut code = copy_slot(slot(5), slot(6));
    code.push(0x00);
    install(&stores, code);
    run_ok(&stores);
    assert_eq!(new_row(&stores, &slot(6)), Some(word(3).to_vec()));
    assert_eq!(new_row(&stores, &slot(5)), Some(word(3).to_vec()));
    // A slot served by its new row leaves the legacy row alone.
    assert_eq!(legacy_row(&stores, &slot(5)), Some(word(7).to_vec()));
}

#[test]
fn an_unread_slot_write_deletes_an_aliasing_legacy_row() {
    let stores = optimized_stores();
    let a = slot(5);
    let b = aliasing_slot(5);
    assert_eq!(legacy_key(&a), legacy_key(&b));
    stores.storage.put(&legacy_key(&a), &word(7)).unwrap();
    let mut code = write_slot(b, word(9));
    code.push(0x00);
    install(&stores, code);
    run_ok(&stores);
    assert_eq!(new_row(&stores, &b), Some(word(9).to_vec()));
    assert_eq!(legacy_row(&stores, &a), None);
    assert_eq!(new_row(&stores, &a), None);
}

#[test]
fn aliasing_slots_resolve_by_first_touch() {
    let stores = optimized_stores();
    let a = slot(5);
    let b = aliasing_slot(5);
    stores.storage.put(&legacy_key(&a), &word(7)).unwrap();
    let mut code = copy_slot(a, slot(6));
    code.extend(copy_slot(b, slot(7)));
    code.push(0x00);
    install(&stores, code);
    run_ok(&stores);
    // A claimed the legacy key, so B reads empty.
    assert_eq!(new_row(&stores, &slot(6)), Some(word(7).to_vec()));
    assert_eq!(new_row(&stores, &slot(7)), Some([0u8; 32].to_vec()));
    assert_eq!(new_row(&stores, &a), Some(word(7).to_vec()));
    assert_eq!(new_row(&stores, &b), None);
    assert_eq!(legacy_row(&stores, &a), None);
}

#[test]
fn legacy_scheme_alias_check_fails_the_transaction_after_the_fork() {
    let stores = stores();
    pass_alias_fork(&stores);
    let a = slot(5);
    let b = aliasing_slot(5);
    stores.storage.put(&legacy_key(&a), &word(7)).unwrap();
    let mut code = read_slot(a);
    code.extend(read_slot(b));
    code.push(0x00);
    install(&stores, code);
    match run(&stores) {
        VmOutcome::Halt {
            result, energy_used, ..
        } => {
            assert_eq!(result, ContractResult::OutOfTime);
            assert_eq!(energy_used, LIMIT);
        }
        other => panic!("expected OUT_OF_TIME, got {other:?}"),
    }
}

#[test]
fn legacy_scheme_alias_check_allows_repeated_access_to_one_slot() {
    let stores = stores();
    pass_alias_fork(&stores);
    let a = slot(5);
    stores.storage.put(&legacy_key(&a), &word(7)).unwrap();
    let mut code = copy_slot(a, slot(6));
    code.extend(write_slot(a, word(9)));
    code.extend(read_slot(a));
    code.push(0x00);
    install(&stores, code);
    run_ok(&stores);
    assert_eq!(legacy_row(&stores, &a), Some(word(9).to_vec()));
    assert_eq!(legacy_row(&stores, &slot(6)), Some(word(7).to_vec()));
}

#[test]
fn legacy_scheme_without_the_fork_lets_aliasing_slots_share_a_row() {
    let stores = stores();
    let a = slot(5);
    let b = aliasing_slot(5);
    stores.storage.put(&legacy_key(&a), &word(7)).unwrap();
    let mut code = copy_slot(a, slot(6));
    code.extend(copy_slot(b, slot(7)));
    code.push(0x00);
    install(&stores, code);
    run_ok(&stores);
    assert_eq!(legacy_row(&stores, &slot(6)), Some(word(7).to_vec()));
    assert_eq!(legacy_row(&stores, &slot(7)), Some(word(7).to_vec()));
}
