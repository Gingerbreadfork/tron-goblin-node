//! SELFDESTRUCT parity tests — java-tron `Program.suicide` / `suicide2`
//! (TIP-6780 / proposal #94 `ALLOW_TVM_SELFDESTRUCT_RESTRICTION`).
//!
//! Pinned behavior:
//!   * Pre-#94, other-beneficiary: balance + TRC-10 sweep to the
//!     beneficiary; the contract's account / code / contract / abi rows
//!     are deleted at commit (`TransactionTrace.deleteContract`).
//!   * Pre-#94, self-beneficiary: balance goes to the BURN account
//!     (java's blackhole), not silently zeroed.
//!   * #94 on, pre-existing contract, other-beneficiary: balance +
//!     TRC-10 move, but the contract SURVIVES (no deletion).
//!   * #94 on, pre-existing contract, self-beneficiary: pure no-op.
//!   * `canSuicide`: outstanding v1 delegated balance REVERTs the frame.

use std::sync::Arc;

use tron_chainbase::{
    AbiStore, AccountAssetStore, AccountStore, CodeStore, ContractStateStore, ContractStore,
    DelegatedResourceStore, DelegationStore, DynamicPropertiesStore, KvBackend, MemBackend,
    StorageRowStore, VotesStore, WitnessStore,
};
use tron_crypto::address::Address;
use tron_proto::{Account, TriggerSmartContract};
use tron_tvm::database::code_hash;
use tron_tvm::execute::{execute_trigger, VmBlockEnv, VmOutcome, VmStores};

/// Mainnet burn account (`TLsV52sRDL79HXGGm9yzwKibb6BeruhUzy`).
const BLACKHOLE: [u8; 21] = [
    0x41, 0x77, 0x94, 0x4d, 0x19, 0xc0, 0x52, 0xb7, 0x3e, 0xe2, 0x28, 0x68, 0x23, 0xaa, 0x83,
    0xf8, 0x13, 0x8c, 0xb7, 0x03, 0x2f,
];

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn fresh_stores(restriction: bool) -> VmStores {
    let dynamic_properties = Arc::new(DynamicPropertiesStore::new(mem()));
    dynamic_properties.put_long(b"ALLOW_TVM_TRANSFER_TRC10", 1);
    dynamic_properties.put_long(b"ALLOW_TVM_FREEZE", 1);
    dynamic_properties.put_long(b"ALLOW_TVM_VOTE", 1);
    // FreezeV2 = supportUnfreezeDelay() = UNFREEZE_DELAY_DAYS > 0.
    dynamic_properties.put_long(b"UNFREEZE_DELAY_DAYS", 14);
    if restriction {
        dynamic_properties.put_long(b"ALLOW_TVM_SELFDESTRUCT_RESTRICTION", 1);
    }
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

/// Runtime bytecode: `PUSH20 <beneficiary-evm> SELFDESTRUCT`.
fn suicide_bytecode(beneficiary: [u8; 21]) -> Vec<u8> {
    let mut code = vec![0x73];
    code.extend_from_slice(&beneficiary[1..]);
    code.push(0xff);
    code
}

fn install_contract(stores: &VmStores, addr: [u8; 21], bytecode: Vec<u8>, balance: i64) {
    let hash = code_hash(&bytecode);
    stores.code.put(hash.as_slice(), &bytecode).unwrap();
    // Address-keyed row too — what `deleteContract` removes on mainnet.
    stores.code.put(&addr, &bytecode).unwrap();
    stores
        .accounts
        .put(
            &Address::from_raw(addr),
            &Account {
                address: addr.to_vec(),
                balance,
                code: bytecode,
                code_hash: hash.as_slice().to_vec(),
                ..Default::default()
            },
        )
        .unwrap();
    if let Some(contracts) = &stores.contracts {
        contracts
            .put(
                &Address::from_raw(addr),
                &tron_proto::SmartContract {
                    contract_address: addr.to_vec(),
                    ..Default::default()
                },
            )
            .unwrap();
    }
}

fn install_caller(stores: &VmStores, addr: [u8; 21], balance: i64) {
    stores
        .accounts
        .put(
            &Address::from_raw(addr),
            &Account {
                address: addr.to_vec(),
                balance,
                ..Default::default()
            },
        )
        .unwrap();
}

fn run(stores: &VmStores, caller: [u8; 21], contract: [u8; 21]) -> VmOutcome {
    let trigger = TriggerSmartContract {
        owner_address: caller.to_vec(),
        contract_address: contract.to_vec(),
        ..Default::default()
    };
    let block = VmBlockEnv {
        block_number: 100,
        block_timestamp_ms: 1_700_000_000_000,
    };
    execute_trigger(stores, block, &trigger, 1_000_000)
}

fn balance_of(stores: &VmStores, addr: [u8; 21]) -> i64 {
    stores
        .accounts
        .get(&Address::from_raw(addr))
        .unwrap()
        .map(|a| a.balance)
        .unwrap_or(0)
}

#[test]
fn pre_restriction_suicide_transfers_and_deletes_all_rows() {
    let stores = fresh_stores(false);
    let caller = tron_addr(0x11);
    let contract = tron_addr(0x22);
    let heir = tron_addr(0x33);
    install_caller(&stores, caller, 1_000_000);
    install_caller(&stores, heir, 5);
    install_contract(&stores, contract, suicide_bytecode(heir), 777);
    // TRC-10 holdings sweep to the heir too.
    {
        let a = Address::from_raw(contract);
        let mut acc = stores.accounts.get(&a).unwrap().unwrap();
        acc.asset_v2.insert("1000001".to_string(), 42);
        stores.accounts.put(&a, &acc).unwrap();
    }

    let out = run(&stores, caller, contract);
    assert!(matches!(out, VmOutcome::Success { .. }), "{out:?}");

    assert_eq!(balance_of(&stores, heir), 5 + 777, "TRX inherited");
    let heir_acc = stores.accounts.get(&Address::from_raw(heir)).unwrap().unwrap();
    assert_eq!(heir_acc.asset_v2.get("1000001"), Some(&42), "TRC-10 swept");

    // deleteContract: account + code(address row) + contract + abi gone.
    assert!(stores.accounts.get(&Address::from_raw(contract)).unwrap().is_none());
    assert!(stores.code.get(&contract).unwrap().is_none());
    assert!(stores
        .contracts
        .as_ref()
        .unwrap()
        .get(&Address::from_raw(contract))
        .unwrap()
        .is_none());
}

#[test]
fn pre_restriction_self_suicide_burns_to_blackhole() {
    let stores = fresh_stores(false);
    let caller = tron_addr(0x11);
    let contract = tron_addr(0x44);
    install_caller(&stores, caller, 1_000_000);
    install_contract(&stores, contract, suicide_bytecode(contract), 999);

    let out = run(&stores, caller, contract);
    assert!(matches!(out, VmOutcome::Success { .. }), "{out:?}");

    assert!(
        stores.accounts.get(&Address::from_raw(contract)).unwrap().is_none(),
        "contract destroyed"
    );
    assert_eq!(
        balance_of(&stores, BLACKHOLE),
        999,
        "self-beneficiary balance goes to the burn account, not thin air"
    );
}

#[test]
fn restriction_preexisting_contract_transfers_but_survives() {
    let stores = fresh_stores(true);
    let caller = tron_addr(0x11);
    let contract = tron_addr(0x55);
    let heir = tron_addr(0x66);
    install_caller(&stores, caller, 1_000_000);
    install_caller(&stores, heir, 0);
    install_contract(&stores, contract, suicide_bytecode(heir), 321);

    let out = run(&stores, caller, contract);
    assert!(matches!(out, VmOutcome::Success { .. }), "{out:?}");

    assert_eq!(balance_of(&stores, heir), 321, "balance transferred");
    let acc = stores.accounts.get(&Address::from_raw(contract)).unwrap();
    assert!(acc.is_some(), "pre-existing contract NOT destroyed under #94");
    assert_eq!(acc.unwrap().balance, 0, "but emptied");
    assert!(
        stores.code.get(&contract).unwrap().is_some(),
        "code row survives under #94"
    );
}

#[test]
fn restriction_self_suicide_is_a_noop() {
    let stores = fresh_stores(true);
    let caller = tron_addr(0x11);
    let contract = tron_addr(0x77);
    install_caller(&stores, caller, 1_000_000);
    install_contract(&stores, contract, suicide_bytecode(contract), 555);

    let out = run(&stores, caller, contract);
    assert!(matches!(out, VmOutcome::Success { .. }), "{out:?}");

    let acc = stores.accounts.get(&Address::from_raw(contract)).unwrap();
    assert!(acc.is_some(), "contract untouched");
    assert_eq!(acc.unwrap().balance, 555, "balance untouched (java suicide2 early return)");
    assert_eq!(balance_of(&stores, BLACKHOLE), 0, "nothing burned");
}

#[test]
fn outstanding_delegation_reverts_the_suicide() {
    let stores = fresh_stores(false);
    let caller = tron_addr(0x11);
    let contract = tron_addr(0x88);
    let heir = tron_addr(0x99);
    install_caller(&stores, caller, 1_000_000);
    install_contract(&stores, contract, suicide_bytecode(heir), 100);
    // Outstanding v1 delegation → canSuicide == false → frame reverts.
    {
        let a = Address::from_raw(contract);
        let mut acc = stores.accounts.get(&a).unwrap().unwrap();
        acc.delegated_frozen_balance_for_bandwidth = 1_000_000;
        stores.accounts.put(&a, &acc).unwrap();
    }

    let out = run(&stores, caller, contract);
    assert!(matches!(out, VmOutcome::Revert { .. }), "{out:?}");
    assert!(
        stores.accounts.get(&Address::from_raw(contract)).unwrap().is_some(),
        "revert leaves the contract alone"
    );
    assert_eq!(balance_of(&stores, heir), 0);
}

/// SELFDESTRUCT's `NEW_ACCT_CALL` (25000) top-up keys on java-tron's
/// `isDeadAccount` — store non-existence (`getAccount == null`), NOT EIP-161
/// emptiness. A beneficiary that EXISTS in the account store but is empty
/// (zero balance/nonce/no code) is alive in TRON (accounts are never pruned),
/// so it must NOT incur the 25000 top-up. Pins the energy at the bare
/// `PUSH20 (3) + SUICIDE_V2 (5000)` = 5003 for an existing-but-empty heir.
#[test]
fn restriction_suicide_existing_empty_heir_no_new_acct_topup() {
    let stores = fresh_stores(true);
    let caller = tron_addr(0x11);
    let contract = tron_addr(0xaa);
    let heir = tron_addr(0xbb);
    install_caller(&stores, caller, 1_000_000);
    // Heir EXISTS in the store but is empty (balance 0).
    install_caller(&stores, heir, 0);
    install_contract(&stores, contract, suicide_bytecode(heir), 0);

    let out = run(&stores, caller, contract);
    let VmOutcome::Success { energy_used, .. } = out else {
        panic!("expected success, got {out:?}");
    };
    assert_eq!(
        energy_used, 5003,
        "PUSH20 (3) + SUICIDE_V2 (5000); the 25000 NEW_ACCT_CALL top-up must \
         NOT apply to an existing-but-empty beneficiary (java isDeadAccount = \
         getAccount == null)"
    );
}

/// Counterpart: a beneficiary with NO store row IS a dead account, so the
/// 25000 top-up DOES apply — `PUSH20 (3) + SUICIDE_V2 (5000) + NEW_ACCT_CALL
/// (25000)` = 30003.
#[test]
fn restriction_suicide_absent_heir_charges_new_acct_topup() {
    let stores = fresh_stores(true);
    let caller = tron_addr(0x11);
    let contract = tron_addr(0xac);
    let heir = tron_addr(0xad); // never installed → no store row
    install_caller(&stores, caller, 1_000_000);
    install_contract(&stores, contract, suicide_bytecode(heir), 0);

    let out = run(&stores, caller, contract);
    let VmOutcome::Success { energy_used, .. } = out else {
        panic!("expected success, got {out:?}");
    };
    assert_eq!(
        energy_used, 30003,
        "PUSH20 (3) + SUICIDE_V2 (5000) + NEW_ACCT_CALL (25000) for a \
         store-absent (dead) beneficiary"
    );
}

/// VM-4 / #81 isolation: with the SELFDESTRUCT restriction (#94) OFF, the
/// dead-beneficiary NEW_ACCT_CALL (25000) top-up is gated SOLELY on
/// `ALLOW_ENERGY_ADJUSTMENT` (#81). java `getSuicideCost` (pre-#81) charges no
/// top-up; `getSuicideCost2` (#81) adds 25000 for a dead heir. The SUICIDE base
/// is 0 without the restriction (no SUICIDE_V2 = 5000).
#[test]
fn absent_heir_topup_gated_on_energy_adjustment_without_restriction() {
    let caller = tron_addr(0x11);
    let contract = tron_addr(0xac);
    let heir = tron_addr(0xad); // never installed → dead account

    // #81 ON: PUSH20 (3) + SUICIDE (0) + NEW_ACCT_CALL (25000).
    let stores = fresh_stores(false);
    stores
        .dynamic_properties
        .put_long(b"ALLOW_ENERGY_ADJUSTMENT", 1);
    install_caller(&stores, caller, 1_000_000);
    install_contract(&stores, contract, suicide_bytecode(heir), 0);
    let out = run(&stores, caller, contract);
    let VmOutcome::Success { energy_used, .. } = out else {
        panic!("expected success, got {out:?}");
    };
    assert_eq!(
        energy_used, 25003,
        "#81 on, restriction off: PUSH20 (3) + NEW_ACCT_CALL (25000)"
    );

    // #81 OFF (pre-#81): no top-up — PUSH20 (3) + SUICIDE (0) only.
    let stores0 = fresh_stores(false);
    install_caller(&stores0, caller, 1_000_000);
    install_contract(&stores0, contract, suicide_bytecode(heir), 0);
    let out0 = run(&stores0, caller, contract);
    let VmOutcome::Success { energy_used, .. } = out0 else {
        panic!("expected success, got {out0:?}");
    };
    assert_eq!(
        energy_used, 3,
        "pre-#81: no NEW_ACCT_CALL top-up for a dead beneficiary"
    );
}

/// The GasFree-withdrawal shape (mainnet block 83,324,067, tx 73b9ba50…):
/// an `asset_optimized` deposit shell whose TRC-10 holdings live ONLY in the
/// separate account-asset store (empty inline `asset_v2`) SELFDESTRUCTs with a
/// STORE-ABSENT beneficiary. java `MUtil.transferAllToken` reads the dying
/// account's `getAssetMapV2()` — which imports the optimized balances first —
/// and forwards every token to the freshly-created obtainer.
///
/// This pins the two coupled requirements that the 83,324,209 DelegateResource
/// divergence depended on:
///   1. `tron_suicide` must `import_all_asset` the optimized owner BEFORE the
///      sweep, or it reads an empty inline map and forwards nothing.
///   2. The obtainer, created fresh holding ONLY TRC-10 (zero TRX, no code),
///      must survive the commit-time empty-account skip because its imported
///      asset map is non-empty.
/// Without (1) the obtainer is created token-less and (2) then prunes it away,
/// leaving the receiver absent — exactly the symptom that failed the later
/// DelegateResource to that address.
#[test]
fn optimized_shell_suicide_forwards_store_assets_to_fresh_heir() {
    // Install the process-wide account-asset backend (java
    // `AssetUtil.setAccountAssetStore`) so `import_all_asset` is live. Keyed by
    // address, so the other tests in this binary (all non-optimized accounts)
    // are unaffected. `OnceLock::set` is idempotent across this file's tests.
    let asset_backend = mem();
    tron_chainbase::set_account_asset_backend(asset_backend.clone());
    let asset_store = AccountAssetStore::new(asset_backend);

    let stores = fresh_stores(false);
    let caller = tron_addr(0x11);
    let contract = tron_addr(0xc2); // the deposit shell
    let heir = tron_addr(0xc3); // fresh GasFree wallet — NO store row
    install_caller(&stores, caller, 1_000_000);
    install_contract(&stores, contract, suicide_bytecode(heir), 0);

    // Mark the shell asset-optimized with its TRC-10 balances held ONLY in the
    // account-asset store and an EMPTY inline `asset_v2` — the real on-chain
    // representation of an optimized account (java
    // `AssetUtil.getAssetOptimization`).
    {
        let a = Address::from_raw(contract);
        let mut acc = stores.accounts.get(&a).unwrap().unwrap();
        acc.asset_optimized = true;
        acc.asset_v2.clear();
        stores.accounts.put(&a, &acc).unwrap();
        asset_store.put(&a, b"1005074", 2_222_222).unwrap();
        asset_store.put(&a, b"1005157", 8_888_888).unwrap();
        asset_store.put(&a, b"1005155", 2_000_000).unwrap();
    }

    let out = run(&stores, caller, contract);
    assert!(matches!(out, VmOutcome::Success { .. }), "{out:?}");

    // The heir must exist (NOT pruned) and carry every swept token inline.
    let heir_acc = stores
        .accounts
        .get(&Address::from_raw(heir))
        .unwrap()
        .expect("fresh token-only heir survives commit (non-empty asset map is not pruned)");
    assert_eq!(heir_acc.asset_v2.get("1005074"), Some(&2_222_222));
    assert_eq!(heir_acc.asset_v2.get("1005157"), Some(&8_888_888));
    assert_eq!(heir_acc.asset_v2.get("1005155"), Some(&2_000_000));

    // The shell is destroyed; its inline asset map is gone with it.
    assert!(
        stores.accounts.get(&Address::from_raw(contract)).unwrap().is_none(),
        "dying shell account deleted at commit"
    );
}

/// The actual GasFree-withdrawal shape on mainnet (block 83,324,067, tx
/// 73b9ba50…): the deposit shell is CREATE2-deployed IN THE SAME TX, and its
/// constructor immediately SELFDESTRUCTs to a fresh GasFree wallet. The dying
/// owner therefore has NO row in the committed `AccountStore` — it lives only
/// in the in-flight revm journal until the final commit.
///
/// java reads the owner from the in-flight `Repository`
/// (`getContractState().getAccount(owner)`), which sees the same-tx deployment,
/// so `Program.suicide` still runs `createAccountIfNotExist(obtainer)` and
/// persists the freshly-created (empty) beneficiary. Our host reads the
/// COMMITTED store, which doesn't reflect the same-tx CREATE2 — so `tron_suicide`
/// used to bail before creating the obtainer, and the empty beneficiary revm
/// independently touched was then pruned by the commit-time empty-account skip,
/// leaving the address ABSENT. A later `DelegateResourceContract` to that
/// address then failed `TargetAccountMissing` (the 83,324,209 divergence).
///
/// Fix: when the dying owner was created locally this tx, synthesize the empty
/// account the in-flight Repository would return and proceed, so the obtainer is
/// created and persists.
///
/// The reproduction needs a NESTED deploy: a top-level factory contract (which
/// IS pre-installed in the store) runs a CREATE2 whose child's constructor
/// SELFDESTRUCTs to a fresh heir. Only the nested child is journal-only (the
/// `in_store=false` case); a top-level `execute_create` contract is pre-written
/// to the store before its constructor runs, so it would never hit the bail.
#[test]
fn same_tx_created_contract_suicide_persists_fresh_heir() {
    let stores = fresh_stores(false);
    // CREATE2 needs ALLOW_TVM_CONSTANTINOPLE (revm PETERSBURG); the suicide's
    // `createAccountIfNotExist` is gated on ALLOW_TVM_SOLIDITY_059 (java).
    stores.dynamic_properties.put_long(b"ALLOW_TVM_CONSTANTINOPLE", 1);
    stores.dynamic_properties.put_long(b"ALLOW_TVM_SOLIDITY_059", 1);
    let caller = tron_addr(0x11);
    let factory = tron_addr(0xf0);
    let heir = tron_addr(0xd1); // fresh GasFree wallet — NO store row
    install_caller(&stores, caller, 1_000_000_000);

    // The child's init code = its constructor: PUSH20 <heir-evm> SELFDESTRUCT.
    // It self-destructs before returning runtime, so the child is created and
    // destroyed within this one tx and never reaches the committed store.
    let mut child_init = vec![0x73u8]; // PUSH20
    child_init.extend_from_slice(&heir[1..]);
    child_init.push(0xff); // SELFDESTRUCT
    assert_eq!(child_init.len(), 22);

    // Factory runtime: place the 22-byte child init code at memory offset 0,
    // then CREATE2(value=0, offset=0, size=22, salt=0).
    //   PUSH32 <child_init left-aligned, right-padded to 32>  ; the init bytes
    //   PUSH1 0   MSTORE                                      ; mem[0..32]=word
    //   PUSH1 0   ; salt
    //   PUSH1 22  ; size
    //   PUSH1 0   ; offset
    //   PUSH1 0   ; value
    //   CREATE2
    //   STOP
    let mut word = [0u8; 32];
    word[..22].copy_from_slice(&child_init); // left-aligned, MSTORE keeps order
    let mut factory_runtime = vec![0x7fu8]; // PUSH32
    factory_runtime.extend_from_slice(&word);
    factory_runtime.extend_from_slice(&[
        0x60, 0x00, // PUSH1 0  (mem offset)
        0x52, // MSTORE
        0x60, 0x00, // PUSH1 0  (salt)
        0x60, 0x16, // PUSH1 22 (size)
        0x60, 0x00, // PUSH1 0  (offset)
        0x60, 0x00, // PUSH1 0  (value)
        0xf5, // CREATE2
        0x00, // STOP
    ]);
    install_contract(&stores, factory, factory_runtime, 0);

    let out = run(&stores, caller, factory);
    assert!(matches!(out, VmOutcome::Success { .. }), "{out:?}");

    // The fresh heir MUST exist after commit — java's createAccountIfNotExist
    // creates it and never prunes it; our synthetic-owner path must do the same.
    let heir_acc = stores
        .accounts
        .get(&Address::from_raw(heir))
        .unwrap()
        .expect("fresh heir of a same-tx (nested CREATE2) self-destructing contract must persist");
    assert_eq!(heir_acc.address, heir.to_vec());
    // Stamped with the head-block timestamp (java createNormalAccount).
    assert_eq!(heir_acc.create_time, 1_700_000_000_000);
}
