//! Stake 1.0 TVM opcode behaviours pinned by java-tron's
//! `framework/src/test/java/org/tron/common/runtime/vm/FreezeTest.java`.
//!
//! `FreezeTest` drives the deprecated `FREEZE` (0xd5) / `UNFREEZE` (0xd6)
//! opcodes through a deployed contract with `allowTvmFreezeV2` off, and
//! asserts a full post-state after every call: the owner's balance delta,
//! the legacy `frozen` list or `accountResource.frozenBalanceForEnergy`
//! slot, and the matching `TOTAL_NET_WEIGHT` / `TOTAL_ENERGY_WEIGHT` move.
//! Calls it expects to fail are asserted `REVERT`, which for a stake opcode
//! means pushing 0 with every store left untouched.
//!
//! Two groups are reproduced here:
//!
//! * The `freezeForSelfWithException` / `unfreezeForSelfWithException`
//!   argument matrix of `testFreezeAndUnfreeze`, which pins
//!   `FreezeBalanceProcessor.validate`'s four amount rules.
//! * The `suicideToAccount` helper's staking accounting, shared by
//!   `testContractSuicideToBlackHole` and its four siblings: the inheritor
//!   receives the dying contract's balance PLUS its TRON Power, and the
//!   chain-wide weights shed exactly the contract's own frozen balances.

use std::sync::Arc;

use tron_chainbase::{
    AbiStore, AccountStore, CodeStore, ContractStateStore, ContractStore, DelegatedResourceStore,
    DelegationStore, DynamicPropertiesStore, KvBackend, MemBackend, StorageRowStore, VotesStore,
    WitnessStore,
};
use tron_crypto::address::Address;
use tron_proto::account::{AccountResource, FreezeV2, Frozen, UnFreezeV2};
use tron_proto::{Account, TriggerSmartContract};
use tron_tvm::database::code_hash;
use tron_tvm::execute::{execute_trigger, VmBlockEnv, VmOutcome, VmStores};

const NOW_MS: i64 = 1_700_000_000_000;

/// Mainnet burn account (`TLsV52sRDL79HXGGm9yzwKibb6BeruhUzy`) — java's
/// blackhole, the inheritor `suicideToAccount` substitutes when a contract
/// names itself.
const BLACKHOLE: [u8; 21] = [
    0x41, 0x77, 0x94, 0x4d, 0x19, 0xc0, 0x52, 0xb7, 0x3e, 0xe2, 0x28, 0x68, 0x23, 0xaa, 0x83, 0xf8,
    0x13, 0x8c, 0xb7, 0x03, 0x2f,
];

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

/// `FreezeTest.init`'s configuration: ALLOW_TVM_FREEZE on,
/// `initAllowTvmFreezeV2(0)` — the window in which the V1 FREEZE opcode
/// still reaches `Program.freeze` instead of `OperationActions.freezeAction`'s
/// push-zero short circuit.
fn fresh_stores() -> VmStores {
    let dynamic_properties = Arc::new(DynamicPropertiesStore::new(mem()));
    dynamic_properties.put_long(b"ALLOW_TVM_TRANSFER_TRC10", 1);
    dynamic_properties.put_long(b"ALLOW_TVM_FREEZE", 1);
    dynamic_properties.put_long(b"ALLOW_TVM_VOTE", 1);
    dynamic_properties.put_long(b"ALLOW_TVM_SOLIDITY_059", 1);
    // supportUnfreezeDelay() off — `initAllowTvmFreezeV2(0)`.
    dynamic_properties.put_long(b"UNFREEZE_DELAY_DAYS", 0);
    dynamic_properties.save_latest_block_header_timestamp(NOW_MS);
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

fn push1(v: u8) -> Vec<u8> {
    vec![0x60, v]
}

fn push_u256(word: [u8; 32]) -> Vec<u8> {
    let mut out = vec![0x7f];
    out.extend_from_slice(&word);
    out
}

fn word_u64(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

/// The 256-bit two's-complement encoding of a negative amount — what
/// solidity passes for `FreezeTest`'s `freeze(receiver, -frozenBalance, res)`.
fn word_neg(v: u64) -> [u8; 32] {
    let mut w = [0xffu8; 32];
    let neg = (v as u128).wrapping_neg();
    w[16..].copy_from_slice(&neg.to_be_bytes());
    w
}

/// `FREEZE` (0xd5) pops `[resource_type, frozen_balance, receiver_address]`,
/// so the push order is receiver, amount, resource. The pushed flag lands in
/// storage slot 0.
fn freeze_v1_code(receiver: [u8; 21], amount: [u8; 32], resource: [u8; 32]) -> Vec<u8> {
    let mut bc = vec![0x73];
    bc.extend_from_slice(&receiver[1..]);
    bc.extend(push_u256(amount));
    bc.extend(push_u256(resource));
    bc.push(0xd5);
    bc.extend(push1(0));
    bc.push(0x55);
    bc.push(0x00);
    bc
}

/// `UNFREEZE` (0xd6) pops `[resource_type, receiver_address]`.
fn unfreeze_v1_code(receiver: [u8; 21], resource: [u8; 32]) -> Vec<u8> {
    let mut bc = vec![0x73];
    bc.extend_from_slice(&receiver[1..]);
    bc.extend(push_u256(resource));
    bc.push(0xd6);
    bc.extend(push1(0));
    bc.push(0x55);
    bc.push(0x00);
    bc
}

/// Runtime bytecode: `PUSH20 <beneficiary-evm> SELFDESTRUCT`.
fn suicide_code(beneficiary: [u8; 21]) -> Vec<u8> {
    let mut code = vec![0x73];
    code.extend_from_slice(&beneficiary[1..]);
    code.push(0xff);
    code
}

fn install_contract_with(stores: &VmStores, addr: [u8; 21], bytecode: Vec<u8>, mut account: Account) {
    let hash = code_hash(&bytecode);
    stores.code.put(hash.as_slice(), &bytecode).unwrap();
    stores.code.put(&addr, &bytecode).unwrap();
    account.address = addr.to_vec();
    account.code = bytecode;
    account.code_hash = hash.as_slice().to_vec();
    stores.accounts.put(&Address::from_raw(addr), &account).unwrap();
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

fn install_eoa(stores: &VmStores, addr: [u8; 21], balance: i64) {
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
    install_eoa(stores, caller, 1_000_000_000);
    execute_trigger(
        stores,
        VmBlockEnv {
            block_number: 100,
            block_timestamp_ms: NOW_MS,
            ..Default::default()
        },
        &TriggerSmartContract {
            owner_address: caller.to_vec(),
            contract_address: contract.to_vec(),
            ..Default::default()
        },
        1_000_000,
    )
}

fn run_ok(stores: &VmStores, caller: [u8; 21], contract: [u8; 21]) {
    let outcome = run(stores, caller, contract);
    assert!(
        matches!(outcome, VmOutcome::Success { .. }),
        "expected Success, got: {outcome:?}"
    );
}

fn pushed_flag(stores: &VmStores, addr: [u8; 21]) -> u8 {
    let key = tron_chainbase::StorageRowStore::compose_key(&Address::from_raw(addr), &[0u8; 32]);
    match stores.storage.get(&key).unwrap() {
        Some(bytes) => bytes[31],
        None => 0,
    }
}

fn account_of(stores: &VmStores, addr: [u8; 21]) -> Option<Account> {
    stores.accounts.get(&Address::from_raw(addr)).unwrap()
}

fn balance_of(stores: &VmStores, addr: [u8; 21]) -> i64 {
    account_of(stores, addr).map(|a| a.balance).unwrap_or(0)
}

fn weights(stores: &VmStores) -> (i64, i64) {
    (
        stores.dynamic_properties.total_net_weight(),
        stores.dynamic_properties.total_energy_weight(),
    )
}

// =============================================================================
// FREEZE argument validation — FreezeTest.freezeForSelfWithException
// =============================================================================

/// Assert a self-directed `FREEZE` was rejected: pushed 0, nothing staked,
/// balance intact, weights unmoved.
fn assert_freeze_v1_rejected(label: &str, amount: [u8; 32], resource: [u8; 32], balance: i64) {
    let stores = fresh_stores();
    let caller = tron_addr(0xa0);
    let contract = tron_addr(0xc0);
    install_contract_with(
        &stores,
        contract,
        freeze_v1_code(contract, amount, resource),
        Account {
            balance,
            ..Default::default()
        },
    );
    run_ok(&stores, caller, contract);

    let acct = account_of(&stores, contract).unwrap();
    assert_eq!(pushed_flag(&stores, contract), 0, "{label}: must push 0");
    assert!(acct.frozen.is_empty(), "{label}: bandwidth stake must not appear");
    assert!(
        acct.account_resource
            .as_ref()
            .and_then(|r| r.frozen_balance_for_energy.as_ref())
            .is_none(),
        "{label}: energy stake must not appear"
    );
    assert_eq!(acct.balance, balance, "{label}: balance must not move");
    assert_eq!(weights(&stores), (0, 0), "{label}: weights must not move");
}

/// `freezeForSelfWithException(contract, 0, 0)` — "FrozenBalance must be
/// positive".
#[test]
fn freeze_v1_rejects_zero_amount() {
    assert_freeze_v1_rejected("zero amount", word_u64(0), word_u64(0), 50_000_000);
}

/// `freezeForSelfWithException(contract, -frozenBalance, 0)`.
#[test]
fn freeze_v1_rejects_negative_amount() {
    assert_freeze_v1_rejected(
        "negative amount",
        word_neg(1_000_000),
        word_u64(0),
        50_000_000,
    );
}

/// `freezeForSelfWithException(contract, frozenBalance - 1, 1)` with
/// `frozenBalance` at 1 TRX — "FrozenBalance must be greater than or equal
/// to 1 TRX". One sun below the floor is rejected.
#[test]
fn freeze_v1_rejects_amount_one_sun_below_one_trx() {
    assert_freeze_v1_rejected("999_999 sun", word_u64(999_999), word_u64(1), 50_000_000);
}

/// The boundary the previous test brackets: exactly 1 TRX for ENERGY is
/// accepted, lands in `accountResource.frozenBalanceForEnergy` and credits
/// `TOTAL_ENERGY_WEIGHT` alone.
#[test]
fn freeze_v1_accepts_exactly_one_trx() {
    let stores = fresh_stores();
    let caller = tron_addr(0xa1);
    let contract = tron_addr(0xc1);
    install_contract_with(
        &stores,
        contract,
        freeze_v1_code(contract, word_u64(1_000_000), word_u64(1)),
        Account {
            balance: 50_000_000,
            ..Default::default()
        },
    );
    run_ok(&stores, caller, contract);

    let acct = account_of(&stores, contract).unwrap();
    assert_eq!(pushed_flag(&stores, contract), 1);
    assert_eq!(
        acct.account_resource
            .as_ref()
            .and_then(|r| r.frozen_balance_for_energy.as_ref())
            .map(|f| f.frozen_balance),
        Some(1_000_000)
    );
    assert_eq!(acct.balance, 49_000_000);
    assert_eq!(weights(&stores), (0, 1));
}

/// `freezeForSelfWithException(contract, value, 0)` where `value` dwarfs the
/// contract's balance — "FrozenBalance must be less than or equal to
/// accountBalance".
#[test]
fn freeze_v1_rejects_amount_above_balance() {
    assert_freeze_v1_rejected(
        "amount above balance",
        word_u64(60_000_000),
        word_u64(0),
        50_000_000,
    );
}

// =============================================================================
// UNFREEZE argument validation — FreezeTest.unfreezeForSelfWithException
// =============================================================================

/// `unfreezeForSelfWithException(contract, 0)` / `(contract, 1)` after the
/// stake has already been released: with nothing frozen for the resource
/// there is no expired entry to unfreeze and `UnfreezeBalanceProcessor`
/// throws. Pinned for both resources.
#[test]
fn unfreeze_v1_rejects_when_nothing_is_frozen() {
    for (label, resource) in [("bandwidth", 0u8), ("energy", 1u8)] {
        let stores = fresh_stores();
        let caller = tron_addr(0xa2);
        let contract = tron_addr(0xc2);
        install_contract_with(
            &stores,
            contract,
            unfreeze_v1_code(contract, word_u64(resource as u64)),
            Account {
                balance: 50_000_000,
                ..Default::default()
            },
        );
        run_ok(&stores, caller, contract);

        let acct = account_of(&stores, contract).unwrap();
        assert_eq!(pushed_flag(&stores, contract), 0, "{label}: must push 0");
        assert_eq!(acct.balance, 50_000_000, "{label}: balance must not move");
        assert_eq!(weights(&stores), (0, 0), "{label}: weights must not move");
    }
}

/// The successful counterpart from `FreezeTest.unfreezeForSelf`: once the
/// entry has matured the stake returns to balance in full, the entry is
/// cleared and `TOTAL_NET_WEIGHT` sheds `frozenBalance / TRX_PRECISION`.
/// The opcode pushes 1.
#[test]
fn unfreeze_v1_matured_bandwidth_returns_stake_and_sheds_weight() {
    let stores = fresh_stores();
    let caller = tron_addr(0xa3);
    let contract = tron_addr(0xc3);
    stores.dynamic_properties.save_total_net_weight(10);
    install_contract_with(
        &stores,
        contract,
        unfreeze_v1_code(contract, word_u64(0)),
        Account {
            balance: 40_000_000,
            frozen: vec![Frozen {
                frozen_balance: 10_000_000,
                expire_time: NOW_MS - 1,
            }],
            ..Default::default()
        },
    );
    run_ok(&stores, caller, contract);

    let acct = account_of(&stores, contract).unwrap();
    assert_eq!(pushed_flag(&stores, contract), 1);
    assert!(acct.frozen.is_empty(), "the matured entry is cleared");
    assert_eq!(acct.balance, 50_000_000, "the stake returns to balance");
    assert_eq!(weights(&stores), (0, 0));
}

// =============================================================================
// SELFDESTRUCT with stake — FreezeTest.suicideToAccount
// =============================================================================

/// `suicideToAccount` asserts the inheritor's balance grows by
/// `contract.getBalance() + contract.getTronPower()` — the dying contract's
/// liquid balance PLUS both legacy frozen balances — and that the chain-wide
/// weights shed exactly the contract's own frozen amounts:
///
/// ```java
/// Assert.assertEquals(contract.getFrozenBalance(),
///     (oldTotalNetWeight - newTotalNetWeight) * TRX_PRECISION);
/// Assert.assertEquals(contract.getEnergyFrozenBalance(),
///     (oldTotalEnergyWeight - newTotalEnergyWeight) * TRX_PRECISION);
/// ```
#[test]
fn suicide_forwards_frozen_v1_stake_and_sheds_both_weights() {
    let stores = fresh_stores();
    let caller = tron_addr(0x11);
    let contract = tron_addr(0xc4);
    let heir = tron_addr(0xd4);
    stores.dynamic_properties.save_total_net_weight(30);
    stores.dynamic_properties.save_total_energy_weight(20);
    install_eoa(&stores, heir, 5);
    install_contract_with(
        &stores,
        contract,
        suicide_code(heir),
        Account {
            balance: 777,
            frozen: vec![Frozen {
                frozen_balance: 12_000_000,
                expire_time: NOW_MS - 1,
            }],
            account_resource: Some(AccountResource {
                frozen_balance_for_energy: Some(Frozen {
                    frozen_balance: 8_000_000,
                    expire_time: NOW_MS - 1,
                }),
                ..Default::default()
            }),
            ..Default::default()
        },
    );

    let out = run(&stores, caller, contract);
    assert!(matches!(out, VmOutcome::Success { .. }), "{out:?}");

    assert_eq!(
        balance_of(&stores, heir),
        5 + 777 + 12_000_000 + 8_000_000,
        "inheritor receives balance + TRON Power"
    );
    assert_eq!(
        weights(&stores),
        (30 - 12, 20 - 8),
        "each weight sheds the contract's own frozen balance / TRX_PRECISION"
    );
    assert!(
        account_of(&stores, contract).is_none(),
        "the contract row is deleted"
    );
}

/// The same accounting when the contract names itself: `suicideToAccount`
/// substitutes the blackhole address as the inheritor, so the stake is burned
/// rather than lost, and the weights still shed.
#[test]
fn self_targeted_suicide_burns_frozen_v1_stake_to_the_blackhole() {
    let stores = fresh_stores();
    let caller = tron_addr(0x11);
    let contract = tron_addr(0xc5);
    stores.dynamic_properties.save_total_net_weight(6);
    install_contract_with(
        &stores,
        contract,
        suicide_code(contract),
        Account {
            balance: 999,
            frozen: vec![Frozen {
                frozen_balance: 6_000_000,
                expire_time: NOW_MS - 1,
            }],
            ..Default::default()
        },
    );

    let out = run(&stores, caller, contract);
    assert!(matches!(out, VmOutcome::Success { .. }), "{out:?}");

    assert_eq!(
        balance_of(&stores, BLACKHOLE),
        999 + 6_000_000,
        "balance and stake both burn"
    );
    assert_eq!(weights(&stores), (0, 0));
}

/// `FreezeTest`'s `suicideWithException` cases: every one of the five suicide
/// tests first asserts the destroy REVERTs while the contract still has a
/// delegation outstanding, and only succeeds once it has been unfrozen. The
/// delegated-out ENERGY field blocks it exactly as the bandwidth field does.
#[test]
fn outstanding_v1_energy_delegation_reverts_the_suicide() {
    let stores = fresh_stores();
    let caller = tron_addr(0x11);
    let contract = tron_addr(0xc6);
    let heir = tron_addr(0xd6);
    install_eoa(&stores, heir, 0);
    install_contract_with(
        &stores,
        contract,
        suicide_code(heir),
        Account {
            balance: 100,
            account_resource: Some(AccountResource {
                delegated_frozen_balance_for_energy: 1_000_000,
                ..Default::default()
            }),
            ..Default::default()
        },
    );

    let out = run(&stores, caller, contract);
    assert!(matches!(out, VmOutcome::Revert { .. }), "{out:?}");
    assert!(
        account_of(&stores, contract).is_some(),
        "revert leaves the contract alone"
    );
    assert_eq!(balance_of(&stores, heir), 0);
}

// =============================================================================
// SELFDESTRUCT with a Stake 2.0 unfreeze queue — FreezeV2Test.testSuicideToOtherAccount
// =============================================================================

/// `FreezeV2Test.testSuicideToOtherAccount` walks two blockers in sequence.
/// The second: after `unfreezeV2` has queued a still-maturing entry,
/// `suicideWithException` requires the destroy to REVERT — `canSuicide`'s
/// freezeV2 check rejects a non-empty unfreezing list.
#[test]
fn pending_unfreeze_v2_entry_reverts_the_suicide() {
    let stores = fresh_stores();
    stores.dynamic_properties.put_long(b"UNFREEZE_DELAY_DAYS", 14);
    let caller = tron_addr(0x11);
    let contract = tron_addr(0xc7);
    let heir = tron_addr(0xd7);
    install_eoa(&stores, heir, 0);
    install_contract_with(
        &stores,
        contract,
        suicide_code(heir),
        Account {
            balance: 100,
            unfrozen_v2: vec![UnFreezeV2 {
                r#type: 1,
                unfreeze_amount: 5_000_000,
                unfreeze_expire_time: NOW_MS + 30_000,
            }],
            ..Default::default()
        },
    );

    let out = run(&stores, caller, contract);
    assert!(matches!(out, VmOutcome::Revert { .. }), "{out:?}");
    assert!(account_of(&stores, contract).is_some());
    assert_eq!(balance_of(&stores, heir), 0);
}

/// The complement `FreezeV2Test.suicide` asserts: an entry that HAS matured
/// does not block the destroy, and its amount is added to the inheritor's
/// balance —
/// `expectedIncreasingBalance = oldContract.getBalance() + Σ matured unfreezeAmount`.
/// Un-unstaked `frozenV2` moves across as stake, not as balance.
#[test]
fn matured_unfreeze_v2_entry_is_paid_to_the_inheritor() {
    let stores = fresh_stores();
    stores.dynamic_properties.put_long(b"UNFREEZE_DELAY_DAYS", 14);
    let caller = tron_addr(0x11);
    let contract = tron_addr(0xc8);
    let heir = tron_addr(0xd8);
    install_eoa(&stores, heir, 11);
    install_contract_with(
        &stores,
        contract,
        suicide_code(heir),
        Account {
            balance: 100,
            frozen_v2: vec![FreezeV2 {
                r#type: 1,
                amount: 9_000_000,
            }],
            unfrozen_v2: vec![
                UnFreezeV2 {
                    r#type: 1,
                    unfreeze_amount: 5_000_000,
                    unfreeze_expire_time: NOW_MS - 1,
                },
                UnFreezeV2 {
                    r#type: 0,
                    unfreeze_amount: 3_000_000,
                    unfreeze_expire_time: NOW_MS,
                },
            ],
            ..Default::default()
        },
    );

    let out = run(&stores, caller, contract);
    assert!(matches!(out, VmOutcome::Success { .. }), "{out:?}");

    assert_eq!(
        balance_of(&stores, heir),
        11 + 100 + 5_000_000 + 3_000_000,
        "both matured entries are paid out as TRX"
    );
    let heir_acct = account_of(&stores, heir).unwrap();
    assert_eq!(
        heir_acct
            .frozen_v2
            .iter()
            .find(|f| f.r#type == 1)
            .map(|f| f.amount),
        Some(9_000_000),
        "the live stake transfers as stake, not balance"
    );
}
