//! Error-path tests covering the remaining MEDIUM gaps:
//!   * `MarketSellAsset` / `MarketCancelOrder` — DEX order lifecycle.
//!   * `CreateAccount` — auto-account creation rules.
//!   * `SetAccountId` — once-per-account id assignment.
//!   * `UpdateBrokerage` — witness commission percentage [0,100].
//!   * `WithdrawBalance` — SR allowance claim cooldown.
//!   * `UnfreezeAsset` — legacy frozen-supply expiration release.
//!
//! Java references: `MarketSellAssetActuatorTest` + `MarketCancelOrderActuatorTest`
//! (~36 cases), `CreateAccountActuatorTest` (7), `SetAccountIdActuatorTest`
//! (~7), `UpdateBrokerageActuatorTest` (~9), `WithdrawBalanceActuatorTest`
//! (~12), `UnfreezeAssetActuatorTest` (~9). Each previously had at
//! most a single happy-path in `full_layer.rs`.

use std::collections::BTreeMap;
use std::sync::Arc;

use hex_literal::hex;
use tron_actuator::{account, asset, market, witness, ActuatorError};
use tron_chainbase::{
    AccountIdIndexStore, AccountStore, DelegationStore, DynamicPropertiesStore, KvBackend,
    MarketOrderStore, MemBackend, WitnessStore,
};
use tron_crypto::address::Address;
use tron_proto::account::Frozen;
use tron_proto::market_order::State as OrderState;
use tron_proto::{
    Account, AccountCreateContract, AccountType, MarketCancelOrderContract,
    MarketSellAssetContract, SetAccountIdContract, UnfreezeAssetContract,
    UpdateBrokerageContract, Witness, WithdrawBalanceContract,
};

const ALICE: [u8; 21] = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");
const BOB: [u8; 21] = hex!("41a614f803b6fd780986a42c78ec9c7f77e6ded13c");
const CAROL: [u8; 21] = hex!("41cccccccccccccccccccccccccccccccccccccccc");

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}
fn addr(b: [u8; 21]) -> Address {
    Address::from_raw(b)
}

fn put_account(accounts: &AccountStore, who: [u8; 21], balance: i64) {
    accounts.put(
        &addr(who),
        &Account {
            address: who.to_vec(),
            balance,
            r#type: AccountType::Normal as i32,
            ..Default::default()
        },
    ).unwrap();
}

// ============================================================
// MarketSellAsset
// ============================================================

#[test]
fn market_sell_rejects_when_proposal_disabled() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_account(&accounts, ALICE, 1_000_000_000);
    let c = MarketSellAssetContract {
        owner_address: ALICE.to_vec(),
        sell_token_id: b"_".to_vec(),
        sell_token_quantity: 100,
        buy_token_id: b"1000001".to_vec(),
        buy_token_quantity: 50,
    };
    let err = market::validate_market_sell_asset(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::MarketDisabled));
}

#[test]
fn market_sell_rejects_same_token_on_both_sides() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(b"ALLOW_MARKET_TRANSACTION", 1);
    put_account(&accounts, ALICE, 1_000_000_000);
    let c = MarketSellAssetContract {
        owner_address: ALICE.to_vec(),
        sell_token_id: b"_".to_vec(),
        sell_token_quantity: 100,
        buy_token_id: b"_".to_vec(),
        buy_token_quantity: 50,
    };
    let err = market::validate_market_sell_asset(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::MarketSameTokens));
}

#[test]
fn market_sell_rejects_non_positive_quantities() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(b"ALLOW_MARKET_TRANSACTION", 1);
    put_account(&accounts, ALICE, 1_000_000_000);
    for (s, b) in [(0, 50), (100, 0), (-1, 50), (100, -1)] {
        let c = MarketSellAssetContract {
            owner_address: ALICE.to_vec(),
            sell_token_id: b"_".to_vec(),
            sell_token_quantity: s,
            buy_token_id: b"1000001".to_vec(),
            buy_token_quantity: b,
        };
        let err = market::validate_market_sell_asset(&accounts, &dp, &c).unwrap_err();
        assert!(
            matches!(err, ActuatorError::NonPositiveTokenQuant),
            "({s},{b}) got: {err:?}"
        );
    }
}

#[test]
fn market_sell_rejects_insufficient_balance_for_fee() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(b"ALLOW_MARKET_TRANSACTION", 1);
    dp.put_long(b"MARKET_SELL_FEE", 1_000_000);
    put_account(&accounts, ALICE, 100); // < fee
    let c = MarketSellAssetContract {
        owner_address: ALICE.to_vec(),
        sell_token_id: b"_".to_vec(),
        sell_token_quantity: 100,
        buy_token_id: b"1000001".to_vec(),
        buy_token_quantity: 50,
    };
    let err = market::validate_market_sell_asset(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::InsufficientBalance { .. }));
}

#[test]
fn market_cancel_rejects_missing_order() {
    let accounts = AccountStore::new(mem());
    let orders = MarketOrderStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(b"ALLOW_MARKET_TRANSACTION", 1);
    put_account(&accounts, ALICE, 1_000_000_000);
    let c = MarketCancelOrderContract {
        owner_address: ALICE.to_vec(),
        order_id: vec![0xab; 32],
    };
    let err = market::validate_market_cancel_order(&accounts, &orders, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::MarketOrderMissing));
}

#[test]
fn market_cancel_rejects_order_owned_by_someone_else() {
    let accounts = AccountStore::new(mem());
    let orders = MarketOrderStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(b"ALLOW_MARKET_TRANSACTION", 1);
    put_account(&accounts, ALICE, 1_000_000_000);
    put_account(&accounts, BOB, 1_000_000_000);
    let order_id = vec![0x11u8; 32];
    let order = tron_proto::MarketOrder {
        order_id: order_id.clone(),
        owner_address: BOB.to_vec(),
        sell_token_id: b"_".to_vec(),
        sell_token_quantity: 100,
        buy_token_id: b"1000001".to_vec(),
        buy_token_quantity: 50,
        sell_token_quantity_remain: 100,
        sell_token_quantity_return: 0,
        state: OrderState::Active as i32,
        ..Default::default()
    };
    orders.put(&order_id, &order).unwrap();
    let c = MarketCancelOrderContract {
        owner_address: ALICE.to_vec(), // Alice tries to cancel Bob's order
        order_id,
    };
    let err = market::validate_market_cancel_order(&accounts, &orders, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::NotExchangeOwner));
}

#[test]
fn market_cancel_rejects_already_canceled_order() {
    let accounts = AccountStore::new(mem());
    let orders = MarketOrderStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(b"ALLOW_MARKET_TRANSACTION", 1);
    put_account(&accounts, ALICE, 1_000_000_000);
    let order_id = vec![0x22u8; 32];
    let order = tron_proto::MarketOrder {
        order_id: order_id.clone(),
        owner_address: ALICE.to_vec(),
        state: OrderState::Canceled as i32,
        ..Default::default()
    };
    orders.put(&order_id, &order).unwrap();
    let c = MarketCancelOrderContract {
        owner_address: ALICE.to_vec(),
        order_id,
    };
    let err = market::validate_market_cancel_order(&accounts, &orders, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::MarketOrderNotActive));
}

#[test]
fn market_sell_then_cancel_returns_unfilled_quantity() {
    let accounts = AccountStore::new(mem());
    let orders = MarketOrderStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(b"ALLOW_MARKET_TRANSACTION", 1);
    accounts.put(
        &addr(ALICE),
        &Account {
            address: ALICE.to_vec(),
            balance: 1_000_000_000,
            r#type: AccountType::Normal as i32,
            asset_v2: BTreeMap::from([("1000001".to_string(), 200i64)]),
            ..Default::default()
        },
    ).unwrap();
    let sell = MarketSellAssetContract {
        owner_address: ALICE.to_vec(),
        sell_token_id: b"1000001".to_vec(),
        sell_token_quantity: 100,
        buy_token_id: b"_".to_vec(),
        buy_token_quantity: 50,
    };
    market::execute_market_sell_asset(&accounts, &orders, &dp, &sell).unwrap();
    let alice_after = accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(*alice_after.asset_v2.get("1000001").unwrap(), 100);
    // Locate the order id (sha256(owner || timestamp); timestamp=0 here).
    use tron_crypto::hash::sha256;
    let mut buf = Vec::with_capacity(29);
    buf.extend_from_slice(addr(ALICE).as_bytes());
    buf.extend_from_slice(&0i64.to_be_bytes());
    let order_id = sha256(&buf).to_vec();
    assert!(orders.get(&order_id).unwrap().is_some());
    let cancel = MarketCancelOrderContract {
        owner_address: ALICE.to_vec(),
        order_id: order_id.clone(),
    };
    market::execute_market_cancel_order(&accounts, &orders, &dp, &cancel).unwrap();
    let alice_back = accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(*alice_back.asset_v2.get("1000001").unwrap(), 200);
    let o = orders.get(&order_id).unwrap().unwrap();
    assert_eq!(o.state, OrderState::Canceled as i32);
    assert_eq!(o.sell_token_quantity_return, 100);
    assert_eq!(o.sell_token_quantity_remain, 0);
}

// ============================================================
// CreateAccount
// ============================================================

#[test]
fn create_account_rejects_missing_owner() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let c = AccountCreateContract {
        owner_address: ALICE.to_vec(),
        account_address: BOB.to_vec(),
        r#type: AccountType::Normal as i32,
    };
    let err = account::validate_create_account(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::OwnerAccountMissing));
}

#[test]
fn create_account_rejects_invalid_new_address() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_account(&accounts, ALICE, 1_000_000_000);
    let c = AccountCreateContract {
        owner_address: ALICE.to_vec(),
        account_address: vec![0u8; 10], // wrong length
        r#type: AccountType::Normal as i32,
    };
    let err = account::validate_create_account(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::InvalidAddress));
}

#[test]
fn create_account_rejects_insufficient_fee() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(b"CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT", 1_000_000);
    put_account(&accounts, ALICE, 100); // < fee
    let c = AccountCreateContract {
        owner_address: ALICE.to_vec(),
        account_address: BOB.to_vec(),
        r#type: AccountType::Normal as i32,
    };
    let err = account::validate_create_account(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::InsufficientBalance { .. }));
}

#[test]
fn create_account_rejects_already_existing_target() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_account(&accounts, ALICE, 1_000_000_000);
    put_account(&accounts, BOB, 0);
    let c = AccountCreateContract {
        owner_address: ALICE.to_vec(),
        account_address: BOB.to_vec(),
        r#type: AccountType::Normal as i32,
    };
    let err = account::validate_create_account(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::AccountAlreadyExists));
}

#[test]
fn create_account_writes_new_account_with_create_time() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(b"CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT", 100_000);
    dp.save_latest_block_header_timestamp(1_700_000_000);
    put_account(&accounts, ALICE, 1_000_000_000);
    let c = AccountCreateContract {
        owner_address: ALICE.to_vec(),
        account_address: BOB.to_vec(),
        r#type: AccountType::Normal as i32,
    };
    account::validate_create_account(&accounts, &dp, &c).unwrap();
    account::execute_create_account(&accounts, &dp, &c).unwrap();
    let bob = accounts.get(&addr(BOB)).unwrap().unwrap();
    assert_eq!(bob.address, BOB);
    assert_eq!(bob.create_time, 1_700_000_000);
    let alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(alice.balance, 1_000_000_000 - 100_000);
}

// ============================================================
// SetAccountId
// ============================================================

#[test]
fn set_account_id_rejects_invalid_id() {
    let accounts = AccountStore::new(mem());
    let idx = AccountIdIndexStore::new(mem());
    put_account(&accounts, ALICE, 0);
    // Empty + non-ASCII + too-short ids fail. Pick empty.
    let c = SetAccountIdContract {
        owner_address: ALICE.to_vec(),
        account_id: Vec::new(),
    };
    let err = account::validate_set_account_id(&accounts, &idx, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::InvalidAccountId));
}

#[test]
fn set_account_id_rejects_missing_owner() {
    let accounts = AccountStore::new(mem());
    let idx = AccountIdIndexStore::new(mem());
    let c = SetAccountIdContract {
        owner_address: ALICE.to_vec(),
        account_id: b"my-account-id".to_vec(),
    };
    let err = account::validate_set_account_id(&accounts, &idx, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::OwnerAccountMissing));
}

#[test]
fn set_account_id_rejects_account_with_existing_id() {
    let accounts = AccountStore::new(mem());
    let idx = AccountIdIndexStore::new(mem());
    let mut alice = Account {
        address: ALICE.to_vec(),
        r#type: AccountType::Normal as i32,
        ..Default::default()
    };
    alice.account_id = b"already-set".to_vec();
    accounts.put(&addr(ALICE), &alice).unwrap();
    let c = SetAccountIdContract {
        owner_address: ALICE.to_vec(),
        account_id: b"new-id-12345".to_vec(),
    };
    let err = account::validate_set_account_id(&accounts, &idx, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::AccountAlreadyHasId));
}

#[test]
fn set_account_id_rejects_taken_id() {
    let accounts = AccountStore::new(mem());
    let idx = AccountIdIndexStore::new(mem());
    put_account(&accounts, ALICE, 0);
    idx.put(b"my-id-12345", &addr(BOB)).unwrap();
    let c = SetAccountIdContract {
        owner_address: ALICE.to_vec(),
        account_id: b"my-id-12345".to_vec(),
    };
    let err = account::validate_set_account_id(&accounts, &idx, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::AccountIdTaken));
}

#[test]
fn set_account_id_writes_account_field_and_index() {
    let accounts = AccountStore::new(mem());
    let idx = AccountIdIndexStore::new(mem());
    put_account(&accounts, ALICE, 0);
    let c = SetAccountIdContract {
        owner_address: ALICE.to_vec(),
        account_id: b"alice-id".to_vec(),
    };
    account::validate_set_account_id(&accounts, &idx, &c).unwrap();
    account::execute_set_account_id(&accounts, &idx, &c).unwrap();
    let alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(alice.account_id, b"alice-id");
    let stored = idx.get(b"alice-id").unwrap().unwrap();
    assert_eq!(stored.as_bytes(), &ALICE);
}

// ============================================================
// UpdateBrokerage
// ============================================================

#[test]
fn update_brokerage_rejects_out_of_range() {
    let accounts = AccountStore::new(mem());
    let witnesses = WitnessStore::new(mem());
    put_account(&accounts, ALICE, 0);
    witnesses.put(&addr(ALICE), &Witness::default()).unwrap();
    for b in [-1, 101, 200, i32::MAX] {
        let c = UpdateBrokerageContract {
            owner_address: ALICE.to_vec(),
            brokerage: b,
        };
        let err = witness::validate_update_brokerage(&accounts, &witnesses, &c).unwrap_err();
        assert!(
            matches!(err, ActuatorError::BrokerageOutOfRange),
            "b={b} got: {err:?}"
        );
    }
}

#[test]
fn update_brokerage_rejects_missing_owner() {
    let accounts = AccountStore::new(mem());
    let witnesses = WitnessStore::new(mem());
    let c = UpdateBrokerageContract {
        owner_address: ALICE.to_vec(),
        brokerage: 30,
    };
    let err = witness::validate_update_brokerage(&accounts, &witnesses, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::OwnerAccountMissing));
}

#[test]
fn update_brokerage_rejects_non_witness() {
    let accounts = AccountStore::new(mem());
    let witnesses = WitnessStore::new(mem());
    put_account(&accounts, ALICE, 0); // exists, but not a witness
    let c = UpdateBrokerageContract {
        owner_address: ALICE.to_vec(),
        brokerage: 30,
    };
    let err = witness::validate_update_brokerage(&accounts, &witnesses, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::WitnessMissing));
}

#[test]
fn update_brokerage_accepts_boundary_values() {
    let accounts = AccountStore::new(mem());
    let witnesses = WitnessStore::new(mem());
    let delegation = DelegationStore::new(mem());
    put_account(&accounts, ALICE, 0);
    witnesses.put(&addr(ALICE), &Witness::default()).unwrap();
    for b in [0, 100] {
        let c = UpdateBrokerageContract {
            owner_address: ALICE.to_vec(),
            brokerage: b,
        };
        witness::validate_update_brokerage(&accounts, &witnesses, &c).unwrap();
        witness::execute_update_brokerage(&delegation, &c).unwrap();
    }
}

// ============================================================
// WithdrawBalance
// ============================================================

#[test]
fn withdraw_rejects_missing_owner() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let c = WithdrawBalanceContract {
        owner_address: ALICE.to_vec(),
    };
    let delegation = DelegationStore::new(mem());
    let err = witness::validate_withdraw_balance(&accounts, &dp, &delegation, None, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::OwnerAccountMissing));
}

#[test]
fn withdraw_rejects_no_allowance() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_account(&accounts, ALICE, 0);
    let c = WithdrawBalanceContract {
        owner_address: ALICE.to_vec(),
    };
    let delegation = DelegationStore::new(mem());
    let err = witness::validate_withdraw_balance(&accounts, &dp, &delegation, None, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::NoAllowance));
}

#[test]
fn withdraw_rejects_too_soon_after_previous() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.save_latest_block_header_timestamp(1_000_000);
    let mut alice = Account {
        address: ALICE.to_vec(),
        r#type: AccountType::Normal as i32,
        allowance: 1_000_000,
        ..Default::default()
    };
    alice.latest_withdraw_time = 1_000_000 - 1; // very recent withdraw
    accounts.put(&addr(ALICE), &alice).unwrap();
    let c = WithdrawBalanceContract {
        owner_address: ALICE.to_vec(),
    };
    let delegation = DelegationStore::new(mem());
    let err = witness::validate_withdraw_balance(&accounts, &dp, &delegation, None, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::WithdrawTooSoon { .. }));
}

#[test]
fn withdraw_drains_allowance_into_balance() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.save_latest_block_header_timestamp(1_700_000_000);
    let alice = Account {
        address: ALICE.to_vec(),
        r#type: AccountType::Normal as i32,
        balance: 50_000,
        allowance: 1_000_000,
        ..Default::default()
    };
    accounts.put(&addr(ALICE), &alice).unwrap();
    let c = WithdrawBalanceContract {
        owner_address: ALICE.to_vec(),
    };
    let delegation = DelegationStore::new(mem());
    witness::validate_withdraw_balance(&accounts, &dp, &delegation, None, &c).unwrap();
    witness::execute_withdraw_balance(&accounts, &dp, &delegation, None, &c).unwrap();
    let post = accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(post.balance, 1_050_000);
    assert_eq!(post.allowance, 0);
    assert_eq!(post.latest_withdraw_time, 1_700_000_000);
}

// ============================================================
// UnfreezeAsset (legacy)
// ============================================================

#[test]
fn unfreeze_asset_rejects_missing_owner() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let c = UnfreezeAssetContract {
        owner_address: ALICE.to_vec(),
    };
    let err = asset::validate_unfreeze_asset(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::OwnerAccountMissing));
}

#[test]
fn unfreeze_asset_rejects_when_no_frozen_supply() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_account(&accounts, ALICE, 0);
    let c = UnfreezeAssetContract {
        owner_address: ALICE.to_vec(),
    };
    let err = asset::validate_unfreeze_asset(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::NoUnfreezableAsset));
}

#[test]
fn unfreeze_asset_rejects_when_all_entries_still_locked() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.save_latest_block_header_timestamp(1_000_000);
    let alice = Account {
        address: ALICE.to_vec(),
        r#type: AccountType::Normal as i32,
        frozen_supply: vec![Frozen {
            frozen_balance: 1000,
            expire_time: 2_000_000, // future
        }],
        ..Default::default()
    };
    accounts.put(&addr(ALICE), &alice).unwrap();
    let c = UnfreezeAssetContract {
        owner_address: ALICE.to_vec(),
    };
    let err = asset::validate_unfreeze_asset(&accounts, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::NoUnfreezableAsset));
}

#[test]
fn unfreeze_asset_releases_only_expired_entries() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.save_latest_block_header_timestamp(5_000);
    let mut alice = Account {
        address: ALICE.to_vec(),
        r#type: AccountType::Normal as i32,
        ..Default::default()
    };
    alice.asset_issued_id = b"1000001".to_vec();
    alice.frozen_supply = vec![
        Frozen {
            frozen_balance: 100,
            expire_time: 4_000, // expired
        },
        Frozen {
            frozen_balance: 200,
            expire_time: 9_000, // future
        },
    ];
    accounts.put(&addr(ALICE), &alice).unwrap();
    let c = UnfreezeAssetContract {
        owner_address: ALICE.to_vec(),
    };
    asset::validate_unfreeze_asset(&accounts, &dp, &c).unwrap();
    asset::execute_unfreeze_asset(&accounts, &dp, &c).unwrap();
    let alice_after = accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(alice_after.frozen_supply.len(), 1);
    assert_eq!(alice_after.frozen_supply[0].frozen_balance, 200);
    // Released 100 units credited to the issued asset slot.
    assert_eq!(*alice_after.asset_v2.get("1000001").unwrap(), 100);
}

// Reference Carol so unused-const warning stays quiet across refactors.
#[allow(dead_code)]
fn _carol_warm() {
    let _ = CAROL;
}
