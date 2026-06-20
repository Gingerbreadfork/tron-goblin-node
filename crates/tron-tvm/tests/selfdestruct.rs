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
    AbiStore, AccountStore, CodeStore, ContractStateStore, ContractStore,
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
