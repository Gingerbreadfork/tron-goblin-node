//! Pre-`ENERGY_LIMIT_HARD_FORK` shared-`Storage` semantics.
//!
//! java-tron's `RepositoryImpl.getStorage` builds a child repository's `Storage`
//! for an address by deep-copying the parent's object only once
//! `StorageUtils.getEnergyLimitHardFork()` is true (mainnet block 4,727,890).
//! Before that height the child is handed the *same* object, so a reverting
//! inner frame's SSTOREs to an address a live ancestor already touched are not
//! taken back — they stay visible to the ancestor and reach the row store when
//! the transaction commits. `getStorageInternal` is the sole cache-populating
//! path and runs for reads as well as writes, and `commitStorageCache` passes
//! the object up unguarded.
//!
//! The gate reads the *persisted* head (`getLatestBlockHeaderNumber`), which
//! during the application of block N still holds N-1, so these fixtures set the
//! head rather than the block environment's number.

use std::sync::Arc;

use tron_chainbase::{
    AbiStore, AccountStore, CodeStore, ContractStateStore, ContractStore, DelegatedResourceStore,
    DelegationStore, DynamicPropertiesStore, KvBackend, MemBackend, StorageRowStore, VotesStore,
    WitnessStore, ENERGY_LIMIT_HARD_FORK_BLOCK,
};
use tron_crypto::address::Address;
use tron_proto::{Account, TriggerSmartContract};
use tron_tvm::database::code_hash;
use tron_tvm::execute::{execute_trigger, VmBlockEnv, VmOutcome, VmStores};

/// Last block at which a child repository still aliases its parent's `Storage`.
const PRE_FORK_HEAD: i64 = ENERGY_LIMIT_HARD_FORK_BLOCK - 1;
/// First block at which `getStorage` deep-copies, isolating child frames.
const POST_FORK_HEAD: i64 = ENERGY_LIMIT_HARD_FORK_BLOCK;
/// A head far past the fork, standing in for the validated mainnet snapshot
/// window.
const MAINNET_HEAD: i64 = 83_000_000;

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn stores_at_head(head: i64) -> VmStores {
    let dynamic_properties = Arc::new(DynamicPropertiesStore::new(mem()));
    dynamic_properties.save_latest_block_header_number(head);
    dynamic_properties.save_latest_block_header_timestamp(1_700_000_000_000);
    VmStores {
        accounts: Arc::new(AccountStore::new(mem())),
        code: Arc::new(CodeStore::new(mem())),
        storage: Arc::new(StorageRowStore::new(mem())),
        witnesses: Arc::new(WitnessStore::new(mem())),
        contract_state: Arc::new(ContractStateStore::new(mem())),
        dynamic_properties,
        delegated_resources: Arc::new(DelegatedResourceStore::new(mem())),
        delegated_resource_account_index: None,
        delegation: Arc::new(DelegationStore::new(mem())),
        block_index: None,
        contracts: Some(Arc::new(ContractStore::new(mem()))),
        votes: Some(Arc::new(VotesStore::new(mem()))),
        reward_vi: None,
        abi: Some(Arc::new(AbiStore::new(mem()))),
    }
}

fn tron_addr(byte: u8) -> [u8; 21] {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(byte);
    a
}

const CALLER: u8 = 0x11;
const ENTRY: u8 = 0xaa;
const CALLEE: u8 = 0xbb;

fn install_caller(stores: &VmStores, addr: [u8; 21]) {
    stores
        .accounts
        .put(
            &Address::from_raw(addr),
            &Account {
                address: addr.to_vec(),
                balance: 1_000_000_000,
                ..Default::default()
            },
        )
        .unwrap();
}

fn install_contract(stores: &VmStores, addr: [u8; 21], bytecode: Vec<u8>) {
    let hash = code_hash(&bytecode);
    stores.code.put(hash.as_slice(), &bytecode).unwrap();
    stores.code.put(&addr, &bytecode).unwrap();
    stores
        .accounts
        .put(
            &Address::from_raw(addr),
            &Account {
                address: addr.to_vec(),
                balance: 0,
                code: bytecode,
                code_hash: hash.as_slice().to_vec(),
                r#type: tron_proto::AccountType::Contract as i32,
                ..Default::default()
            },
        )
        .unwrap();
}

// ---------------------------------------------------------------------------
// Bytecode builders
// ---------------------------------------------------------------------------

fn push1(v: u8) -> Vec<u8> {
    vec![0x60, v]
}

/// `PUSH20 <evm address>` — the EVM half of a 21-byte TRON address.
fn push_addr(addr: [u8; 21]) -> Vec<u8> {
    let mut bc = vec![0x73];
    bc.extend_from_slice(&addr[1..]);
    bc
}

/// `SSTORE slot = value`. SSTORE pops the key first, so the value is pushed
/// first.
fn sstore(slot: u8, value: u8) -> Vec<u8> {
    let mut bc = push1(value);
    bc.extend(push1(slot));
    bc.push(0x55);
    bc
}

/// `SLOAD slot; POP` — reads the slot back, which re-warms it if a revert marked
/// it cold.
fn sload_pop(slot: u8) -> Vec<u8> {
    let mut bc = push1(slot);
    bc.push(0x54);
    bc.push(0x50);
    bc
}

/// `DELEGATECALL target` with empty args and return area, forwarding all gas.
/// The callee executes against the caller's storage, so both frames touch the
/// same address.
fn delegatecall(target: [u8; 21]) -> Vec<u8> {
    let mut bc = Vec::new();
    bc.extend(push1(0)); // retLength
    bc.extend(push1(0)); // retOffset
    bc.extend(push1(0)); // argsLength
    bc.extend(push1(0)); // argsOffset
    bc.extend(push_addr(target));
    bc.push(0x5a); // GAS
    bc.push(0xf4); // DELEGATECALL
    bc.push(0x50); // POP success flag
    bc
}

/// `CALL target` with zero value. The callee executes against its own storage.
fn call(target: [u8; 21]) -> Vec<u8> {
    let mut bc = Vec::new();
    bc.extend(push1(0)); // retLength
    bc.extend(push1(0)); // retOffset
    bc.extend(push1(0)); // argsLength
    bc.extend(push1(0)); // argsOffset
    bc.extend(push1(0)); // value
    bc.extend(push_addr(target));
    bc.push(0x5a); // GAS
    bc.push(0xf1); // CALL
    bc.push(0x50); // POP success flag
    bc
}

/// `REVERT` with an empty return payload.
fn revert() -> Vec<u8> {
    let mut bc = push1(0);
    bc.extend(push1(0));
    bc.push(0xfd);
    bc
}

fn stop() -> Vec<u8> {
    vec![0x00]
}

// ---------------------------------------------------------------------------
// Execution + assertions
// ---------------------------------------------------------------------------

fn run(stores: &VmStores, contract: [u8; 21], block_number: i64) -> VmOutcome {
    let trigger = TriggerSmartContract {
        owner_address: tron_addr(CALLER).to_vec(),
        contract_address: contract.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };
    execute_trigger(
        stores,
        VmBlockEnv {
            block_number,
            block_timestamp_ms: 1_700_000_000_000,
            ..Default::default()
        },
        &trigger,
        10_000_000,
    )
}

/// Reads the value actually persisted to the storage row store, not the
/// in-memory journal. A surviving write that never reaches this store is the
/// silent failure mode this suite exists to catch.
fn persisted_slot(stores: &VmStores, addr: [u8; 21], slot: u8) -> u8 {
    let mut key = [0u8; 32];
    key[31] = slot;
    let composed = StorageRowStore::compose_key(&Address::from_raw(addr), &key);
    let raw = stores.storage.get(&composed).unwrap().unwrap_or_default();
    if raw.len() == 32 {
        raw[31]
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// The real-world shape: a library called by DELEGATECALL writes the caller's
/// slot and then reverts. Pre-fork both frames share one `Storage` object, so
/// the library's write is what commits.
#[test]
fn delegatecall_revert_keeps_storage_pre_fork() {
    for (head, expected) in [(PRE_FORK_HEAD, 2u8), (POST_FORK_HEAD, 1u8)] {
        let stores = stores_at_head(head);
        install_caller(&stores, tron_addr(CALLER));

        let mut library = sstore(0, 2);
        library.extend(revert());
        install_contract(&stores, tron_addr(CALLEE), library);

        let mut entry = sstore(0, 1);
        entry.extend(delegatecall(tron_addr(CALLEE)));
        entry.extend(stop());
        install_contract(&stores, tron_addr(ENTRY), entry);

        let outcome = run(&stores, tron_addr(ENTRY), head + 1);
        assert!(matches!(outcome, VmOutcome::Success { .. }), "head={head}: {outcome:?}");
        assert_eq!(
            persisted_slot(&stores, tron_addr(ENTRY), 0),
            expected,
            "head={head}"
        );
    }
}

/// The same divergence reached by re-entrancy: the entry contract calls a peer
/// which calls back into the entry contract, and that inner frame reverts.
#[test]
fn reentrant_call_revert_keeps_storage_pre_fork() {
    for (head, expected) in [(PRE_FORK_HEAD, 2u8), (POST_FORK_HEAD, 1u8)] {
        let stores = stores_at_head(head);
        install_caller(&stores, tron_addr(CALLER));

        // The peer calls back into the entry contract, whose re-entered frame
        // writes the entry contract's own slot and reverts.
        let mut peer = call(tron_addr(ENTRY));
        peer.extend(stop());
        install_contract(&stores, tron_addr(CALLEE), peer);

        // Both passes enter the same code, so branch on whether slot 0 is
        // already set: the first pass writes 1 and calls the peer, the
        // re-entered pass writes 2 and reverts.
        let first_pass = {
            let mut b = sstore(0, 1);
            b.extend(call(tron_addr(CALLEE)));
            b.extend(stop());
            b
        };
        // PUSH1 0 (2) + SLOAD (1) + PUSH1 dest (2) + JUMPI (1).
        const GUARD_PREFIX_LEN: usize = 6;
        let reentered_branch = GUARD_PREFIX_LEN + first_pass.len();
        let mut entry = Vec::new();
        entry.extend(push1(0));
        entry.push(0x54); // SLOAD slot 0
        entry.extend(push1(u8::try_from(reentered_branch).unwrap()));
        entry.push(0x57); // JUMPI — taken once slot 0 is non-zero
        assert_eq!(entry.len(), GUARD_PREFIX_LEN);
        entry.extend(first_pass);
        entry.push(0x5b); // JUMPDEST
        entry.extend(sstore(0, 2));
        entry.extend(revert());
        install_contract(&stores, tron_addr(ENTRY), entry);

        let outcome = run(&stores, tron_addr(ENTRY), head + 1);
        assert!(matches!(outcome, VmOutcome::Success { .. }), "head={head}: {outcome:?}");
        assert_eq!(
            persisted_slot(&stores, tron_addr(ENTRY), 0),
            expected,
            "head={head}"
        );
    }
}

/// A callee writing a slot of its *own* address, which no ancestor has touched,
/// owns that `Storage` object itself. Dropping the child repository drops the
/// object, so the write is discarded in both eras.
#[test]
fn callee_first_touch_revert_discards_in_both_eras() {
    for head in [PRE_FORK_HEAD, POST_FORK_HEAD] {
        let stores = stores_at_head(head);
        install_caller(&stores, tron_addr(CALLER));

        let mut callee = sstore(0, 9);
        callee.extend(revert());
        install_contract(&stores, tron_addr(CALLEE), callee);

        let mut entry = sstore(0, 1);
        entry.extend(call(tron_addr(CALLEE)));
        entry.extend(stop());
        install_contract(&stores, tron_addr(ENTRY), entry);

        let outcome = run(&stores, tron_addr(ENTRY), head + 1);
        assert!(matches!(outcome, VmOutcome::Success { .. }), "head={head}: {outcome:?}");
        assert_eq!(
            persisted_slot(&stores, tron_addr(CALLEE), 0),
            0,
            "callee's own first-touch write must never survive its revert (head={head})"
        );
        assert_eq!(persisted_slot(&stores, tron_addr(ENTRY), 0), 1, "head={head}");
    }
}

/// A surviving write to a slot the ancestor had *not* touched must still reach
/// the row store. Reverting the slot's warming entry marks it cold; the
/// ancestor's later SLOAD then re-warms it, which resets the slot's original
/// value to its present value and would make the flush skip the row as
/// unchanged. The write disappears with no error raised anywhere.
#[test]
fn delegatecall_revert_new_slot_flushes_pre_fork() {
    for (head, expected) in [(PRE_FORK_HEAD, 7u8), (POST_FORK_HEAD, 0u8)] {
        let stores = stores_at_head(head);
        install_caller(&stores, tron_addr(CALLER));

        // The library writes slot 1, which the entry contract never touched.
        let mut library = sstore(1, 7);
        library.extend(revert());
        install_contract(&stores, tron_addr(CALLEE), library);

        let mut entry = sstore(0, 1);
        entry.extend(delegatecall(tron_addr(CALLEE)));
        entry.extend(sload_pop(1)); // re-warms slot 1 after the revert
        entry.extend(stop());
        install_contract(&stores, tron_addr(ENTRY), entry);

        let outcome = run(&stores, tron_addr(ENTRY), head + 1);
        assert!(matches!(outcome, VmOutcome::Success { .. }), "head={head}: {outcome:?}");
        assert_eq!(
            persisted_slot(&stores, tron_addr(ENTRY), 1),
            expected,
            "surviving write must reach the row store (head={head})"
        );
    }
}

/// The entry frame is the shallowest live frame, so a top-level revert has no
/// ancestor to leave writes with. java never commits `rootRepository` for a
/// failed transaction, and nothing may be persisted.
#[test]
fn top_level_revert_persists_nothing_pre_fork() {
    let stores = stores_at_head(PRE_FORK_HEAD);
    install_caller(&stores, tron_addr(CALLER));

    let mut entry = sstore(0, 5);
    entry.extend(revert());
    install_contract(&stores, tron_addr(ENTRY), entry);

    let outcome = run(&stores, tron_addr(ENTRY), PRE_FORK_HEAD + 1);
    assert!(matches!(outcome, VmOutcome::Revert { .. }), "{outcome:?}");
    assert_eq!(persisted_slot(&stores, tron_addr(ENTRY), 0), 0);
}

/// Regression pin for the validated mainnet snapshot window: far past the fork,
/// a reverting inner frame changes nothing.
#[test]
fn post_fork_nested_revert_unchanged() {
    let stores = stores_at_head(MAINNET_HEAD);
    install_caller(&stores, tron_addr(CALLER));

    let mut library = sstore(0, 2);
    library.extend(revert());
    install_contract(&stores, tron_addr(CALLEE), library);

    let mut entry = sstore(0, 1);
    entry.extend(delegatecall(tron_addr(CALLEE)));
    entry.extend(stop());
    install_contract(&stores, tron_addr(ENTRY), entry);

    let outcome = run(&stores, tron_addr(ENTRY), MAINNET_HEAD + 1);
    assert!(matches!(outcome, VmOutcome::Success { .. }), "{outcome:?}");
    assert_eq!(persisted_slot(&stores, tron_addr(ENTRY), 0), 1);
}

/// The gate must read the persisted head, not the number of the block being
/// applied. java advances the head pointer only after every transaction in a
/// block has been applied, so while block N executes the store still reads
/// N-1. Reading the block number instead would activate the fork one block
/// early — invisible to a fixture that keeps the two in step.
#[test]
fn fork_gate_reads_persisted_head_not_block_number() {
    // Persisted head one below the fork while the block being applied is the
    // activation block itself: this is exactly the boundary block, and it must
    // still take the pre-fork arm.
    let stores = stores_at_head(PRE_FORK_HEAD);
    install_caller(&stores, tron_addr(CALLER));

    let mut library = sstore(0, 2);
    library.extend(revert());
    install_contract(&stores, tron_addr(CALLEE), library);

    let mut entry = sstore(0, 1);
    entry.extend(delegatecall(tron_addr(CALLEE)));
    entry.extend(stop());
    install_contract(&stores, tron_addr(ENTRY), entry);

    let outcome = run(&stores, tron_addr(ENTRY), ENERGY_LIMIT_HARD_FORK_BLOCK);
    assert!(matches!(outcome, VmOutcome::Success { .. }), "{outcome:?}");
    assert_eq!(
        persisted_slot(&stores, tron_addr(ENTRY), 0),
        2,
        "block {ENERGY_LIMIT_HARD_FORK_BLOCK} runs with head {PRE_FORK_HEAD}, so pre-fork \
         semantics still apply"
    );
}
