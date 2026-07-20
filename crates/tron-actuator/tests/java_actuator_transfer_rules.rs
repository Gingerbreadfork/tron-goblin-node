//! `TransferActuator` / `TransferAssetActuator` behaviours asserted by
//! `TransferActuatorTest` and `TransferAssetActuatorTest`.
//!
//! Covers the proposal-gated transfer-to-contract prohibition, the exact
//! balance deltas java's `rightTransfer` / `perfectTransfer` / `moreTransfer`
//! cases pin, and the arithmetic-overflow rejections (`addOverflowTest`).

use std::sync::Arc;

use hex_literal::hex;
use tron_actuator::{asset, transfer, ActuatorError};
use tron_chainbase::{
    AccountStore, AssetIssueStore, DynamicPropertiesStore, KvBackend, MemBackend,
};
use tron_crypto::address::Address;
use tron_proto::{Account, AccountType, AssetIssueContract, TransferAssetContract, TransferContract};

const ALICE: [u8; 21] = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");
const BOB: [u8; 21] = hex!("41a614f803b6fd780986a42c78ec9c7f77e6ded13c");
const CONTRACT: [u8; 21] = hex!("41dddddddddddddddddddddddddddddddddddddddd");

const TOKEN: &[u8] = b"TESTASSET";

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn addr(b: [u8; 21]) -> Address {
    Address::from_raw(b)
}

fn put_account(accounts: &AccountStore, who: [u8; 21], balance: i64) {
    accounts
        .put(
            &addr(who),
            &Account {
                address: who.to_vec(),
                balance,
                r#type: AccountType::Normal as i32,
                ..Default::default()
            },
        )
        .unwrap();
}

/// A contract-typed recipient — what `FORBID_TRANSFER_TO_CONTRACT` guards
/// against. java marks these `AccountType.Contract` when the TVM deploys them.
fn put_contract_account(accounts: &AccountStore, who: [u8; 21], balance: i64) {
    accounts
        .put(
            &addr(who),
            &Account {
                address: who.to_vec(),
                balance,
                r#type: AccountType::Contract as i32,
                ..Default::default()
            },
        )
        .unwrap();
}

fn put_token_holder(accounts: &AccountStore, who: [u8; 21], balance: i64, tokens: i64) {
    let mut a = Account {
        address: who.to_vec(),
        balance,
        r#type: AccountType::Normal as i32,
        ..Default::default()
    };
    a.asset
        .insert(String::from_utf8_lossy(TOKEN).into_owned(), tokens);
    accounts.put(&addr(who), &a).unwrap();
}

fn dp_with_forbid(on: i64) -> DynamicPropertiesStore {
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(b"FORBID_TRANSFER_TO_CONTRACT", on);
    dp
}

// =============================================================================
// FORBID_TRANSFER_TO_CONTRACT (proposal #35)
// =============================================================================

/// java `TransferActuator.validate`: with `getForbidTransferToContract() == 1`
/// a transfer whose recipient is an `AccountType.Contract` account is rejected
/// with "Cannot transfer TRX to a smartContract." (`transferToSmartContractAddress`
/// in `TransferActuatorTest`). Value must reach a contract through
/// `TriggerSmartContract` so the callee's fallback runs.
#[test]
fn transfer_to_contract_rejected_when_proposal_active() {
    let accounts = AccountStore::new(mem());
    let dp = dp_with_forbid(1);
    put_account(&accounts, ALICE, 1_000_000);
    put_contract_account(&accounts, CONTRACT, 0);
    let c = TransferContract {
        owner_address: ALICE.to_vec(),
        to_address: CONTRACT.to_vec(),
        amount: 1_000,
    };
    assert_eq!(
        transfer::validate_transfer(&accounts, &dp, &c),
        Err(ActuatorError::TransferToContract)
    );
}

/// The same transfer is legal while the proposal is inactive — the rule is
/// gated, not unconditional, so historical blocks below the activation stay
/// valid.
#[test]
fn transfer_to_contract_allowed_before_proposal() {
    let accounts = AccountStore::new(mem());
    let dp = dp_with_forbid(0);
    put_account(&accounts, ALICE, 1_000_000);
    put_contract_account(&accounts, CONTRACT, 0);
    let c = TransferContract {
        owner_address: ALICE.to_vec(),
        to_address: CONTRACT.to_vec(),
        amount: 1_000,
    };
    assert_eq!(transfer::validate_transfer(&accounts, &dp, &c), Ok(()));
}

/// The prohibition keys off the recipient's account *type*, not its address:
/// a normal recipient is unaffected while the proposal is active.
#[test]
fn transfer_to_normal_account_unaffected_by_proposal() {
    let accounts = AccountStore::new(mem());
    let dp = dp_with_forbid(1);
    put_account(&accounts, ALICE, 1_000_000);
    put_account(&accounts, BOB, 0);
    let c = TransferContract {
        owner_address: ALICE.to_vec(),
        to_address: BOB.to_vec(),
        amount: 1_000,
    };
    assert_eq!(transfer::validate_transfer(&accounts, &dp, &c), Ok(()));
}

/// java guards the check with `toAccount != null`: a transfer to an address
/// with no account at all is an auto-create, never a contract, so the
/// proposal does not apply.
#[test]
fn transfer_to_absent_account_unaffected_by_proposal() {
    let accounts = AccountStore::new(mem());
    let dp = dp_with_forbid(1);
    put_account(&accounts, ALICE, 1_000_000);
    let c = TransferContract {
        owner_address: ALICE.to_vec(),
        to_address: BOB.to_vec(),
        amount: 1_000,
    };
    assert_eq!(transfer::validate_transfer(&accounts, &dp, &c), Ok(()));
}

/// java `TransferAssetActuator.validate` applies the same proposal to TRC-10:
/// "Cannot transfer asset to smartContract."
#[test]
fn transfer_asset_to_contract_rejected_when_proposal_active() {
    let accounts = AccountStore::new(mem());
    let dp = dp_with_forbid(1);
    put_token_holder(&accounts, ALICE, 1_000_000, 500);
    put_contract_account(&accounts, CONTRACT, 0);
    let c = TransferAssetContract {
        owner_address: ALICE.to_vec(),
        to_address: CONTRACT.to_vec(),
        asset_name: TOKEN.to_vec(),
        amount: 10,
    };
    assert_eq!(
        asset::validate_transfer_asset(&accounts, &dp, &c),
        Err(ActuatorError::TransferToContract)
    );
}

#[test]
fn transfer_asset_to_contract_allowed_before_proposal() {
    let accounts = AccountStore::new(mem());
    let dp = dp_with_forbid(0);
    put_token_holder(&accounts, ALICE, 1_000_000, 500);
    put_contract_account(&accounts, CONTRACT, 0);
    let c = TransferAssetContract {
        owner_address: ALICE.to_vec(),
        to_address: CONTRACT.to_vec(),
        asset_name: TOKEN.to_vec(),
        amount: 10,
    };
    assert_eq!(asset::validate_transfer_asset(&accounts, &dp, &c), Ok(()));
}

// =============================================================================
// Balance deltas (rightTransfer / perfectTransfer / moreTransfer)
// =============================================================================

/// java `rightTransfer`: owner loses exactly `amount`, recipient gains exactly
/// `amount`, and the recorded fee is 0 when the recipient already exists.
#[test]
fn transfer_moves_exact_amount_with_zero_fee() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_account(&accounts, ALICE, 10_000_000);
    put_account(&accounts, BOB, 7);
    let c = TransferContract {
        owner_address: ALICE.to_vec(),
        to_address: BOB.to_vec(),
        amount: 1_000_000,
    };
    transfer::validate_transfer(&accounts, &dp, &c).unwrap();
    let result = transfer::execute_transfer(&accounts, &dp, &c).unwrap();

    assert_eq!(result.fee, 0);
    assert!(!result.created_recipient);
    assert_eq!(
        accounts.get(&addr(ALICE)).unwrap().unwrap().balance,
        9_000_000
    );
    assert_eq!(accounts.get(&addr(BOB)).unwrap().unwrap().balance, 1_000_007);
}

/// java `perfectTransfer`: sending the entire balance succeeds and leaves the
/// owner at exactly 0 — the balance check is `balance < amount + fee`, not
/// `<=`.
#[test]
fn transfer_of_entire_balance_succeeds_and_zeroes_owner() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_account(&accounts, ALICE, 10_000_000);
    put_account(&accounts, BOB, 0);
    let c = TransferContract {
        owner_address: ALICE.to_vec(),
        to_address: BOB.to_vec(),
        amount: 10_000_000,
    };
    transfer::validate_transfer(&accounts, &dp, &c).unwrap();
    transfer::execute_transfer(&accounts, &dp, &c).unwrap();
    assert_eq!(accounts.get(&addr(ALICE)).unwrap().unwrap().balance, 0);
    assert_eq!(
        accounts.get(&addr(BOB)).unwrap().unwrap().balance,
        10_000_000
    );
}

/// java `moreTransfer`: one sun over the balance is rejected as
/// "balance is not sufficient.".
#[test]
fn transfer_one_over_balance_rejected() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_account(&accounts, ALICE, 10_000_000);
    put_account(&accounts, BOB, 0);
    let c = TransferContract {
        owner_address: ALICE.to_vec(),
        to_address: BOB.to_vec(),
        amount: 10_000_001,
    };
    assert!(matches!(
        transfer::validate_transfer(&accounts, &dp, &c),
        Err(ActuatorError::InsufficientBalance { .. })
    ));
}

/// java `insufficientFee`: when the recipient does not exist the
/// create-new-account fee is added to the required amount, and the owner must
/// cover `amount + fee`.
#[test]
fn transfer_to_new_account_requires_amount_plus_create_fee() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(b"CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT", 100_000);
    put_account(&accounts, ALICE, 1_000_000);

    // amount + fee == balance + 1 → rejected.
    let too_much = TransferContract {
        owner_address: ALICE.to_vec(),
        to_address: BOB.to_vec(),
        amount: 900_001,
    };
    assert!(matches!(
        transfer::validate_transfer(&accounts, &dp, &too_much),
        Err(ActuatorError::InsufficientBalance { .. })
    ));

    // amount + fee == balance → accepted, and the fee is reported.
    let exact = TransferContract {
        owner_address: ALICE.to_vec(),
        to_address: BOB.to_vec(),
        amount: 900_000,
    };
    transfer::validate_transfer(&accounts, &dp, &exact).unwrap();
    let result = transfer::execute_transfer(&accounts, &dp, &exact).unwrap();
    assert_eq!(result.fee, 100_000);
    assert!(result.created_recipient);
    assert_eq!(accounts.get(&addr(ALICE)).unwrap().unwrap().balance, 0);
    assert_eq!(accounts.get(&addr(BOB)).unwrap().unwrap().balance, 900_000);
}

/// java `addOverflowTest`: the recipient-side `addExact(toBalance, amount)`
/// rejects a credit that would overflow a signed 64-bit balance.
#[test]
fn transfer_rejects_recipient_balance_overflow() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_account(&accounts, ALICE, i64::MAX);
    put_account(&accounts, BOB, i64::MAX);
    let c = TransferContract {
        owner_address: ALICE.to_vec(),
        to_address: BOB.to_vec(),
        amount: i64::MAX,
    };
    assert_eq!(
        transfer::validate_transfer(&accounts, &dp, &c),
        Err(ActuatorError::Overflow)
    );
}

/// java `zeroAmountTest` / `negativeAmountTest`: "Amount must be greater than
/// 0." for both, with the owner account present so the amount bound is what
/// fires.
#[test]
fn transfer_rejects_zero_and_negative_amounts() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_account(&accounts, ALICE, 10_000_000);
    put_account(&accounts, BOB, 0);
    for amount in [0i64, -1, i64::MIN] {
        let c = TransferContract {
            owner_address: ALICE.to_vec(),
            to_address: BOB.to_vec(),
            amount,
        };
        assert_eq!(
            transfer::validate_transfer(&accounts, &dp, &c),
            Err(ActuatorError::NonPositiveAmount),
            "amount={amount}"
        );
    }
}

// =============================================================================
// TransferAsset amounts
// =============================================================================

/// java `TransferAssetActuator.validate`: "assetBalance is not sufficient."
/// once the requested amount exceeds the holding, and the exact holding
/// transfers cleanly.
#[test]
fn transfer_asset_bounds_amount_by_holding() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let v1 = AssetIssueStore::new(mem());
    v1.put(
        TOKEN,
        &AssetIssueContract {
            owner_address: ALICE.to_vec(),
            name: TOKEN.to_vec(),
            total_supply: 1_000,
            ..Default::default()
        },
    )
    .unwrap();
    put_token_holder(&accounts, ALICE, 0, 100);
    put_account(&accounts, BOB, 0);

    let over = TransferAssetContract {
        owner_address: ALICE.to_vec(),
        to_address: BOB.to_vec(),
        asset_name: TOKEN.to_vec(),
        amount: 101,
    };
    assert!(matches!(
        asset::validate_transfer_asset(&accounts, &dp, &over),
        Err(ActuatorError::InsufficientAssetBalance { .. })
    ));

    let exact = TransferAssetContract {
        owner_address: ALICE.to_vec(),
        to_address: BOB.to_vec(),
        asset_name: TOKEN.to_vec(),
        amount: 100,
    };
    asset::validate_transfer_asset(&accounts, &dp, &exact).unwrap();
    asset::execute_transfer_asset(&accounts, &dp, &v1, &exact).unwrap();

    let key = String::from_utf8_lossy(TOKEN).into_owned();
    assert_eq!(
        accounts
            .get(&addr(ALICE))
            .unwrap()
            .unwrap()
            .asset
            .get(&key)
            .copied()
            .unwrap_or(0),
        0
    );
    assert_eq!(
        accounts
            .get(&addr(BOB))
            .unwrap()
            .unwrap()
            .asset
            .get(&key)
            .copied()
            .unwrap_or(0),
        100
    );
}
