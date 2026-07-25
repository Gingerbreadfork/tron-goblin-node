//! `OverrideSet` application over `MemBackend` — the v1/v2/CREATE2 slot-key
//! matrix (proving overridden slots land on the byte-exact key the VM's SLOAD
//! composes), balance/code/trc10 overrides, `state` replace-all + its cap, and
//! the ignored-`nonce` warning.

use std::collections::BTreeMap;
use std::sync::Arc;

use tron_chainbase::{KvBackend, MemBackend, StorageRowStore};
use tron_crypto::address::Address;
use tron_crypto::hash::keccak256;
use tron_proto::SmartContract;
use tron_tvm::execute::VmStores;

use tron_sim::{AccountOverride, ForkBackends, ForkOverlay, OverrideSet};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn fork() -> ForkOverlay {
    let fb = ForkBackends {
        accounts: mem(),
        code: mem(),
        storage: mem(),
        witnesses: mem(),
        contract_state: mem(),
        dyn_props: mem(),
        delegated_resources: mem(),
        delegation: mem(),
        contracts: mem(),
        votes: Some(mem()),
        abi: Some(mem()),
        block_index: Some(mem()),
    };
    ForkOverlay::new(&fb, None).unwrap()
}

fn addr(n: u8) -> Address {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[20] = n;
    Address::from_raw(a)
}

fn word(n: u8) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[31] = n;
    w
}

fn one(a: Address, ov: AccountOverride) -> OverrideSet {
    let mut set = OverrideSet::default();
    set.accounts.insert(a, ov);
    set
}

fn put_contract(vm: &VmStores, a: &Address, version: i32, trx_hash: Vec<u8>) {
    vm.contracts
        .as_ref()
        .unwrap()
        .put(
            a,
            &SmartContract {
                contract_address: a.as_bytes().to_vec(),
                version,
                trx_hash,
                ..Default::default()
            },
        )
        .unwrap();
}

#[test]
fn balance_override_creates_and_updates() {
    let ov = fork();
    let vm = ov.vm_stores();
    let a = addr(1);

    let w = one(a, AccountOverride { balance: Some(5_000_000), ..Default::default() })
        .apply(&vm, 10_000)
        .unwrap();
    assert!(w.is_empty());
    assert_eq!(vm.accounts.get(&a).unwrap().unwrap().balance, 5_000_000);

    // Update the existing account.
    one(a, AccountOverride { balance: Some(9), ..Default::default() })
        .apply(&vm, 10_000)
        .unwrap();
    assert_eq!(vm.accounts.get(&a).unwrap().unwrap().balance, 9);
}

#[test]
fn code_override_sets_code_account_and_contract_row() {
    let ov = fork();
    let vm = ov.vm_stores();
    let a = addr(2);
    let code = vec![0x60, 0x00, 0x60, 0x00, 0xf3];

    one(a, AccountOverride { code: Some(code.clone()), ..Default::default() })
        .apply(&vm, 10_000)
        .unwrap();

    // Code store is keyed by the 21-byte address (how the VM loads it).
    assert_eq!(vm.code.get(a.as_bytes()).unwrap().as_deref(), Some(&code[..]));
    let acct = vm.accounts.get(&a).unwrap().unwrap();
    assert_eq!(acct.code_hash, keccak256(&code).to_vec());
    // A v2, non-CREATE2 contract row is created.
    let sc = vm.contracts.as_ref().unwrap().get(&a).unwrap().unwrap();
    assert_eq!(sc.version, 0);
    assert!(sc.trx_hash.is_empty());
}

#[test]
fn state_diff_v2_lands_on_compose_key() {
    let ov = fork();
    let vm = ov.vm_stores();
    let a = addr(3);
    let slot = word(2);
    let value = word(0xef);

    let mut diff = BTreeMap::new();
    diff.insert(slot, value);
    one(a, AccountOverride { state_diff: Some(diff), ..Default::default() })
        .apply(&vm, 10_000)
        .unwrap();

    // No contract row → v2, non-CREATE2 layout.
    let key = StorageRowStore::compose_key(&a, &slot);
    assert_eq!(vm.storage.get(&key).unwrap().as_deref(), Some(&value[..]));
}

#[test]
fn state_diff_v1_uses_hashed_slot() {
    let ov = fork();
    let vm = ov.vm_stores();
    let a = addr(4);
    put_contract(&vm, &a, 1, Vec::new());
    let slot = word(7);
    let value = word(0x11);

    let mut diff = BTreeMap::new();
    diff.insert(slot, value);
    one(a, AccountOverride { state_diff: Some(diff), ..Default::default() })
        .apply(&vm, 10_000)
        .unwrap();

    let v1_key = StorageRowStore::compose_key_v1(&a, &slot);
    let v2_key = StorageRowStore::compose_key(&a, &slot);
    assert_ne!(v1_key, v2_key, "v1 hashes the slot, so the keys must differ");
    assert_eq!(vm.storage.get(&v1_key).unwrap().as_deref(), Some(&value[..]));
    assert_eq!(vm.storage.get(&v2_key).unwrap(), None);
}

#[test]
fn state_diff_create2_uses_trxhash_addr_hash() {
    let ov = fork();
    let vm = ov.vm_stores();
    let a = addr(5);
    let trx = vec![0xab; 32];
    put_contract(&vm, &a, 0, trx.clone());
    let slot = word(3);
    let value = word(0x22);

    let mut diff = BTreeMap::new();
    diff.insert(slot, value);
    one(a, AccountOverride { state_diff: Some(diff), ..Default::default() })
        .apply(&vm, 10_000)
        .unwrap();

    let ah = StorageRowStore::addr_hash(&a, &trx);
    let key = StorageRowStore::compose_key_with_addr_hash(&ah, &slot, false);
    assert_eq!(vm.storage.get(&key).unwrap().as_deref(), Some(&value[..]));
    // The plain (non-CREATE2) key must be empty.
    assert_eq!(vm.storage.get(&StorageRowStore::compose_key(&a, &slot)).unwrap(), None);
}

#[test]
fn state_replace_all_clears_then_writes() {
    let ov = fork();
    let vm = ov.vm_stores();
    let a = addr(6);
    let (sa, sb, sc) = (word(1), word(2), word(3));

    // Seed two slots.
    let mut seed = BTreeMap::new();
    seed.insert(sa, word(0xaa));
    seed.insert(sb, word(0xbb));
    one(a, AccountOverride { state_diff: Some(seed), ..Default::default() })
        .apply(&vm, 10_000)
        .unwrap();

    // Replace-all with a single new slot.
    let mut repl = BTreeMap::new();
    repl.insert(sc, word(0xcc));
    one(a, AccountOverride { state: Some(repl), ..Default::default() })
        .apply(&vm, 10_000)
        .unwrap();

    assert_eq!(vm.storage.get(&StorageRowStore::compose_key(&a, &sa)).unwrap(), None);
    assert_eq!(vm.storage.get(&StorageRowStore::compose_key(&a, &sb)).unwrap(), None);
    assert_eq!(
        vm.storage.get(&StorageRowStore::compose_key(&a, &sc)).unwrap().as_deref(),
        Some(&word(0xcc)[..])
    );
}

#[test]
fn state_replace_all_respects_cap() {
    let ov = fork();
    let vm = ov.vm_stores();
    let a = addr(7);

    let mut seed = BTreeMap::new();
    seed.insert(word(1), word(0xaa));
    seed.insert(word(2), word(0xbb));
    seed.insert(word(3), word(0xcc));
    one(a, AccountOverride { state_diff: Some(seed), ..Default::default() })
        .apply(&vm, 10_000)
        .unwrap();

    let mut repl = BTreeMap::new();
    repl.insert(word(9), word(0x99));
    match one(a, AccountOverride { state: Some(repl), ..Default::default() }).apply(&vm, 2) {
        Err(tron_sim::SimError::Backend(msg)) => assert!(msg.contains("cap"), "msg: {msg}"),
        other => panic!("expected a cap error, got {other:?}"),
    }
}

#[test]
fn trc10_override_merges_asset_v2() {
    let ov = fork();
    let vm = ov.vm_stores();
    let a = addr(8);

    let mut tokens = BTreeMap::new();
    tokens.insert(1002000i64, 5_000_000i64);
    one(a, AccountOverride { token_balances: Some(tokens), ..Default::default() })
        .apply(&vm, 10_000)
        .unwrap();

    let acct = vm.accounts.get(&a).unwrap().unwrap();
    assert_eq!(acct.asset_v2.get("1002000").copied(), Some(5_000_000));
}

#[test]
fn nonce_override_warns_and_is_ignored() {
    let ov = fork();
    let vm = ov.vm_stores();
    let a = addr(9);

    let w = one(a, AccountOverride { nonce: Some(7), ..Default::default() })
        .apply(&vm, 10_000)
        .unwrap();
    assert_eq!(w.len(), 1);
    assert!(w[0].contains("nonce"), "warning: {}", w[0]);
    // No account was created for a nonce-only override.
    assert!(vm.accounts.get(&a).unwrap().is_none());
}
