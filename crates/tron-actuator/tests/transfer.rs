//! Parity tests for [`tron_actuator::transfer`] against
//! `org.tron.core.actuator.TransferActuator`.

use std::sync::Arc;

use hex_literal::hex;
use tron_actuator::{execute_transfer, validate_transfer, ActuatorError, ExecutionResult};
use tron_chainbase::{AccountStore, DynamicPropertiesStore, KvBackend, MemBackend};
use tron_crypto::address::Address;
use tron_proto::{Account, AccountType, TransferContract};

fn fresh() -> (Arc<MemBackend>, AccountStore, DynamicPropertiesStore) {
    let backend = Arc::new(MemBackend::new());
    let trait_backend: Arc<dyn KvBackend> = backend.clone();
    let accounts = AccountStore::new(trait_backend.clone());
    let dyn_props = DynamicPropertiesStore::new(trait_backend);
    (backend, accounts, dyn_props)
}

fn addr(bytes: [u8; 21]) -> Address {
    Address::from_raw(bytes)
}

const ALICE: [u8; 21] = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");
const BOB: [u8; 21] = hex!("41a614f803b6fd780986a42c78ec9c7f77e6ded13c");

fn fund(accounts: &AccountStore, address: [u8; 21], balance: i64) {
    accounts.put(
        &addr(address),
        &Account {
            address: address.to_vec(),
            balance,
            r#type: AccountType::Normal as i32,
            ..Default::default()
        },
    ).unwrap();
}

fn transfer(owner: [u8; 21], to: [u8; 21], amount: i64) -> TransferContract {
    TransferContract {
        owner_address: owner.to_vec(),
        to_address: to.to_vec(),
        amount,
    }
}

// --- validate -------------------------------------------------------------

/// `TRANSFER_FEE = 0` (`ChainConstant.TRANSFER_FEE`). A bytecode-trivial
/// constant, but pinning it here means anyone tempted to refactor the
/// fee into a per-network config trips this test.
#[test]
fn transfer_fee_is_zero() {
    assert_eq!(tron_actuator::transfer::TRANSFER_FEE, 0);
}

#[test]
fn validate_rejects_invalid_owner_address() {
    let (_b, accounts, dyn_props) = fresh();
    let bad = vec![0u8; 20]; // too short
    let contract = TransferContract {
        owner_address: bad,
        to_address: BOB.to_vec(),
        amount: 1,
    };
    assert_eq!(
        validate_transfer(&accounts, &dyn_props, &contract),
        Err(ActuatorError::InvalidOwnerAddress)
    );
}

#[test]
fn validate_rejects_wrong_prefix_byte() {
    let (_b, accounts, dyn_props) = fresh();
    // 21-byte length, but wrong prefix (testnet byte instead of mainnet).
    let mut bad = vec![0xa0u8; 21];
    bad[0] = 0xa0;
    let contract = TransferContract {
        owner_address: bad,
        to_address: BOB.to_vec(),
        amount: 1,
    };
    assert_eq!(
        validate_transfer(&accounts, &dyn_props, &contract),
        Err(ActuatorError::InvalidOwnerAddress)
    );
}

#[test]
fn validate_rejects_self_transfer() {
    let (_b, accounts, dyn_props) = fresh();
    fund(&accounts, ALICE, 100);
    let contract = transfer(ALICE, ALICE, 10);
    assert_eq!(
        validate_transfer(&accounts, &dyn_props, &contract),
        Err(ActuatorError::SelfTransfer)
    );
}

#[test]
fn validate_rejects_non_positive_amount() {
    let (_b, accounts, dyn_props) = fresh();
    fund(&accounts, ALICE, 100);
    let contract = transfer(ALICE, BOB, 0);
    assert_eq!(
        validate_transfer(&accounts, &dyn_props, &contract),
        Err(ActuatorError::NonPositiveAmount)
    );

    let contract = transfer(ALICE, BOB, -1);
    assert_eq!(
        validate_transfer(&accounts, &dyn_props, &contract),
        Err(ActuatorError::NonPositiveAmount)
    );
}

#[test]
fn validate_rejects_missing_owner_account() {
    let (_b, accounts, dyn_props) = fresh();
    // Alice never funded.
    let contract = transfer(ALICE, BOB, 1);
    assert_eq!(
        validate_transfer(&accounts, &dyn_props, &contract),
        Err(ActuatorError::OwnerAccountMissing)
    );
}

#[test]
fn validate_rejects_insufficient_balance() {
    let (_b, accounts, dyn_props) = fresh();
    fund(&accounts, ALICE, 5);
    let contract = transfer(ALICE, BOB, 10);
    match validate_transfer(&accounts, &dyn_props, &contract) {
        Err(ActuatorError::InsufficientBalance { balance: 5, needed: 10 }) => {}
        other => panic!("expected InsufficientBalance(5, 10), got {other:?}"),
    }
}

#[test]
fn validate_passes_with_exact_balance() {
    let (_b, accounts, dyn_props) = fresh();
    fund(&accounts, ALICE, 10);
    fund(&accounts, BOB, 0);
    let contract = transfer(ALICE, BOB, 10);
    assert!(validate_transfer(&accounts, &dyn_props, &contract).is_ok());
}

#[test]
fn validate_accounts_for_create_fee_when_recipient_absent() {
    let (_b, accounts, dyn_props) = fresh();
    fund(&accounts, ALICE, 10);
    // Set create-account fee to 5. Alice has 10 → can afford amount=5 + fee=5.
    dyn_props.put_long(b"CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT", 5);

    let contract = transfer(ALICE, BOB, 5); // exact
    assert!(validate_transfer(&accounts, &dyn_props, &contract).is_ok());

    // amount=6 + fee=5 = 11 > balance=10 → reject.
    let contract = transfer(ALICE, BOB, 6);
    assert!(matches!(
        validate_transfer(&accounts, &dyn_props, &contract),
        Err(ActuatorError::InsufficientBalance { balance: 10, needed: 11 })
    ));
}

#[test]
fn validate_detects_recipient_balance_overflow() {
    let (_b, accounts, dyn_props) = fresh();
    fund(&accounts, ALICE, 100);
    fund(&accounts, BOB, i64::MAX - 5);
    let contract = transfer(ALICE, BOB, 10); // would overflow Bob's balance
    assert_eq!(
        validate_transfer(&accounts, &dyn_props, &contract),
        Err(ActuatorError::Overflow)
    );
}

// --- execute ---------------------------------------------------------------

#[test]
fn execute_moves_balance_between_existing_accounts() {
    let (_b, accounts, dyn_props) = fresh();
    fund(&accounts, ALICE, 100);
    fund(&accounts, BOB, 50);

    let contract = transfer(ALICE, BOB, 30);
    validate_transfer(&accounts, &dyn_props, &contract).unwrap();
    let result = execute_transfer(&accounts, &dyn_props, &contract).unwrap();

    assert_eq!(
        result,
        ExecutionResult {
            fee: 0,
            created_recipient: false,
            ..Default::default()
        }
    );
    assert_eq!(accounts.get(&addr(ALICE)).unwrap().unwrap().balance, 70);
    assert_eq!(accounts.get(&addr(BOB)).unwrap().unwrap().balance, 80);
}

#[test]
fn execute_creates_recipient_when_absent() {
    let (_b, accounts, dyn_props) = fresh();
    fund(&accounts, ALICE, 100);
    // Bob has never been seen.
    let contract = transfer(ALICE, BOB, 30);
    validate_transfer(&accounts, &dyn_props, &contract).unwrap();
    let result = execute_transfer(&accounts, &dyn_props, &contract).unwrap();

    assert!(result.created_recipient);
    assert_eq!(result.fee, 0); // no create fee configured
    let bob = accounts.get(&addr(BOB)).unwrap().unwrap();
    assert_eq!(bob.balance, 30);
    assert_eq!(bob.r#type, AccountType::Normal as i32);
    assert_eq!(bob.address, BOB.to_vec());
    // ALLOW_MULTI_SIGN not set in `fresh()` → java's `withDefaultPermission`
    // is false, so the new account carries no permission.
    assert!(bob.owner_permission.is_none());
    assert!(bob.active_permission.is_empty());
}

#[test]
fn execute_attaches_default_permission_to_new_recipient_under_multisign() {
    // java attaches the default owner + active[id=2] permission to every
    // account it creates when ALLOW_MULTI_SIGN == 1 (mainnet). Without this a
    // later multi-sig tx (Permission_id=2) from the freshly-created account
    // diverges from java with "permission_id 2 not found".
    let (_b, accounts, dyn_props) = fresh();
    fund(&accounts, ALICE, 100);
    dyn_props.put_long(b"ALLOW_MULTI_SIGN", 1);

    let contract = transfer(ALICE, BOB, 30);
    validate_transfer(&accounts, &dyn_props, &contract).unwrap();
    let result = execute_transfer(&accounts, &dyn_props, &contract).unwrap();
    assert!(result.created_recipient);

    let bob = accounts.get(&addr(BOB)).unwrap().unwrap();
    // Default owner permission: id 0, threshold 1, single self-key.
    let owner = bob.owner_permission.expect("default owner permission");
    assert_eq!(owner.id, 0);
    assert_eq!(owner.threshold, 1);
    assert_eq!(owner.keys.len(), 1);
    assert_eq!(owner.keys[0].address, BOB.to_vec());
    assert_eq!(owner.keys[0].weight, 1);
    // Default active permission: exactly one, id 2, threshold 1, self-key.
    assert_eq!(bob.active_permission.len(), 1);
    let active = &bob.active_permission[0];
    assert_eq!(active.id, 2);
    assert_eq!(active.threshold, 1);
    assert_eq!(active.keys.len(), 1);
    assert_eq!(active.keys[0].address, BOB.to_vec());
    // operations bitmap falls back to the mainnet default (no dyn-prop set).
    assert_eq!(active.operations.len(), 32);
    assert_eq!(&active.operations[..8], &[0x7f, 0xff, 0x1f, 0xc0, 0x03, 0x3e, 0xc3, 0x0f]);
}

#[test]
fn execute_charges_create_fee_when_recipient_absent() {
    let (_b, accounts, dyn_props) = fresh();
    fund(&accounts, ALICE, 100);
    dyn_props.put_long(b"CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT", 5);

    let contract = transfer(ALICE, BOB, 30);
    validate_transfer(&accounts, &dyn_props, &contract).unwrap();
    let result = execute_transfer(&accounts, &dyn_props, &contract).unwrap();

    assert_eq!(result.fee, 5);
    assert!(result.created_recipient);
    // Alice: 100 - 30 - 5 = 65
    assert_eq!(accounts.get(&addr(ALICE)).unwrap().unwrap().balance, 65);
    // Bob: 30
    assert_eq!(accounts.get(&addr(BOB)).unwrap().unwrap().balance, 30);
    // java TransferActuator.execute burns the fee (supportBlackHoleOptimization),
    // so BURN_TRX_AMOUNT must increase by exactly the create fee.
    assert_eq!(dyn_props.burn_trx_amount(), 5, "create fee added to BURN_TRX_AMOUNT");
}

#[test]
fn execute_uses_latest_block_timestamp_for_new_account_create_time() {
    let (_b, accounts, dyn_props) = fresh();
    fund(&accounts, ALICE, 100);
    dyn_props.save_latest_block_header_timestamp(1_700_000_000_000);

    let contract = transfer(ALICE, BOB, 30);
    execute_transfer(&accounts, &dyn_props, &contract).unwrap();
    let bob = accounts.get(&addr(BOB)).unwrap().unwrap();
    assert_eq!(bob.create_time, 1_700_000_000_000);
}

/// **Conservation of TRX**: for an in-system transfer with no create
/// fee, the total balance across both accounts is unchanged.
#[test]
fn execute_conserves_total_balance_with_no_fee() {
    let (_b, accounts, dyn_props) = fresh();
    fund(&accounts, ALICE, 100);
    fund(&accounts, BOB, 50);

    let total_before = accounts.get(&addr(ALICE)).unwrap().unwrap().balance
        + accounts.get(&addr(BOB)).unwrap().unwrap().balance;
    assert_eq!(total_before, 150);

    let contract = transfer(ALICE, BOB, 30);
    execute_transfer(&accounts, &dyn_props, &contract).unwrap();

    let total_after = accounts.get(&addr(ALICE)).unwrap().unwrap().balance
        + accounts.get(&addr(BOB)).unwrap().unwrap().balance;
    assert_eq!(total_after, 150);
}

/// **Conservation with create fee**: the create fee leaves the
/// owner→to flow but must equal `result.fee`. Total TRX in the (owner,
/// to) pair drops by exactly `fee`.
#[test]
fn execute_loses_exactly_fee_trx_with_create_fee() {
    let (_b, accounts, dyn_props) = fresh();
    fund(&accounts, ALICE, 100);
    dyn_props.put_long(b"CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT", 7);

    let total_before = accounts.get(&addr(ALICE)).unwrap().unwrap().balance; // Bob = 0
    let contract = transfer(ALICE, BOB, 30);
    let result = execute_transfer(&accounts, &dyn_props, &contract).unwrap();
    let total_after = accounts.get(&addr(ALICE)).unwrap().unwrap().balance
        + accounts.get(&addr(BOB)).unwrap().unwrap().balance;
    assert_eq!(total_before - total_after, result.fee);
    assert_eq!(result.fee, 7);
}
