//! Error-path tests for the witness lifecycle actuators:
//!   * `WitnessCreate`  — upgrade an account to SR candidate
//!   * `WitnessUpdate`  — change a witness's URL after creation
//!   * `UpdateAccount`  — change account name (with ALLOW_UPDATE_ACCOUNT_NAME gating)
//!
//! Java reference: `WitnessCreateActuatorTest` (~8), `WitnessUpdateActuatorTest`
//! (~4), `UpdateAccountActuatorTest` (~7). The existing `full_layer.rs`
//! had one happy-path round-trip per actuator; these tests cover the
//! URL validation, the upgrade-fee mechanics, and the name-update
//! gating.

use std::sync::Arc;

use hex_literal::hex;
use tron_actuator::{account, witness, ActuatorError};
use tron_chainbase::{
    AccountIndexStore, AccountStore, DelegationStore, DynamicPropertiesStore, KvBackend, MemBackend,
    WitnessStore,
};
use tron_crypto::address::Address;
use tron_proto::{
    Account, AccountType, AccountUpdateContract, Witness, WitnessCreateContract,
    WitnessUpdateContract, WithdrawBalanceContract,
};

const ALICE: [u8; 21] = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");
const BOB: [u8; 21] = hex!("41a614f803b6fd780986a42c78ec9c7f77e6ded13c");

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}
fn addr(b: [u8; 21]) -> Address {
    Address::from_raw(b)
}

fn put_funded(accounts: &AccountStore, who: [u8; 21], balance: i64) {
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
// WitnessCreate
// ============================================================

#[test]
fn create_witness_rejects_invalid_url_empty() {
    let accounts = AccountStore::new(mem());
    let witnesses = WitnessStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_funded(&accounts, ALICE, 100_000_000_000_000);
    let c = WitnessCreateContract {
        owner_address: ALICE.to_vec(),
        url: Vec::new(),
    };
    let err = witness::validate_witness_create(&accounts, &witnesses, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::InvalidUrl));
}

#[test]
fn create_witness_rejects_url_too_long() {
    let accounts = AccountStore::new(mem());
    let witnesses = WitnessStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_funded(&accounts, ALICE, 100_000_000_000_000);
    let c = WitnessCreateContract {
        owner_address: ALICE.to_vec(),
        url: vec![b'a'; 257], // > MAX_URL_BYTES (256)
    };
    let err = witness::validate_witness_create(&accounts, &witnesses, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::InvalidUrl));
}

#[test]
fn create_witness_rejects_missing_owner_account() {
    let accounts = AccountStore::new(mem());
    let witnesses = WitnessStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let c = WitnessCreateContract {
        owner_address: ALICE.to_vec(),
        url: b"https://example.test".to_vec(),
    };
    let err = witness::validate_witness_create(&accounts, &witnesses, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::OwnerAccountMissing));
}

#[test]
fn create_witness_rejects_when_already_a_witness() {
    let accounts = AccountStore::new(mem());
    let witnesses = WitnessStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_funded(&accounts, ALICE, 100_000_000_000_000);
    witnesses.put(
        &addr(ALICE),
        &Witness {
            address: ALICE.to_vec(),
            url: "https://existing.test".to_string(),
            ..Default::default()
        },
    ).unwrap();
    let c = WitnessCreateContract {
        owner_address: ALICE.to_vec(),
        url: b"https://new.test".to_vec(),
    };
    let err = witness::validate_witness_create(&accounts, &witnesses, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::WitnessAlreadyExists));
}

#[test]
fn create_witness_rejects_insufficient_upgrade_fee() {
    let accounts = AccountStore::new(mem());
    let witnesses = WitnessStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(b"ACCOUNT_UPGRADE_COST", 9_999_000_000);
    put_funded(&accounts, ALICE, 1_000_000); // way below fee
    let c = WitnessCreateContract {
        owner_address: ALICE.to_vec(),
        url: b"https://example.test".to_vec(),
    };
    let err = witness::validate_witness_create(&accounts, &witnesses, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::InsufficientBalance { .. }));
}

#[test]
fn create_witness_at_exact_fee_succeeds() {
    let accounts = AccountStore::new(mem());
    let witnesses = WitnessStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(b"ACCOUNT_UPGRADE_COST", 9_999_000_000);
    put_funded(&accounts, ALICE, 9_999_000_000);
    let c = WitnessCreateContract {
        owner_address: ALICE.to_vec(),
        url: b"https://example.test".to_vec(),
    };
    // Mainnet has the blackhole optimization on, so the upgrade cost is burned.
    dp.put_long(b"ALLOW_BLACKHOLE_OPTIMIZATION", 1);
    witness::validate_witness_create(&accounts, &witnesses, &dp, &c).unwrap();
    witness::execute_witness_create(&accounts, &witnesses, &dp, &c).unwrap();
    let alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(alice.balance, 0);
    assert!(alice.is_witness);
    let w = witnesses.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(w.address, ALICE);
    assert_eq!(w.url, "https://example.test");
    assert_eq!(w.vote_count, 0);
    // java WitnessCreateActuator.createWitness burns the upgrade cost into
    // BURN_TRX_AMOUNT (supportBlackHoleOptimization).
    assert_eq!(dp.burn_trx_amount(), 9_999_000_000);
}

#[test]
fn create_witness_at_maximum_url_length_succeeds() {
    let accounts = AccountStore::new(mem());
    let witnesses = WitnessStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(b"ACCOUNT_UPGRADE_COST", 0);
    put_funded(&accounts, ALICE, 1_000_000);
    let c = WitnessCreateContract {
        owner_address: ALICE.to_vec(),
        url: vec![b'a'; 256],
    };
    witness::validate_witness_create(&accounts, &witnesses, &dp, &c).unwrap();
}

// ============================================================
// WitnessUpdate
// ============================================================

#[test]
fn update_witness_rejects_invalid_url() {
    let accounts = AccountStore::new(mem());
    let witnesses = WitnessStore::new(mem());
    put_funded(&accounts, ALICE, 1_000_000);
    witnesses.put(
        &addr(ALICE),
        &Witness {
            address: ALICE.to_vec(),
            url: "https://old.test".to_string(),
            ..Default::default()
        },
    ).unwrap();
    for url in [Vec::new(), vec![b'a'; 300]] {
        let c = WitnessUpdateContract {
            owner_address: ALICE.to_vec(),
            update_url: url,
        };
        let err = witness::validate_witness_update(&accounts, &witnesses, &c).unwrap_err();
        assert!(matches!(err, ActuatorError::InvalidUrl), "got: {err:?}");
    }
}

#[test]
fn update_witness_rejects_missing_owner() {
    let accounts = AccountStore::new(mem());
    let witnesses = WitnessStore::new(mem());
    let c = WitnessUpdateContract {
        owner_address: ALICE.to_vec(),
        update_url: b"https://new.test".to_vec(),
    };
    let err = witness::validate_witness_update(&accounts, &witnesses, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::OwnerAccountMissing));
}

#[test]
fn update_witness_rejects_non_witness_account() {
    let accounts = AccountStore::new(mem());
    let witnesses = WitnessStore::new(mem());
    put_funded(&accounts, ALICE, 1_000_000); // exists but not a witness
    let c = WitnessUpdateContract {
        owner_address: ALICE.to_vec(),
        update_url: b"https://new.test".to_vec(),
    };
    let err = witness::validate_witness_update(&accounts, &witnesses, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::WitnessMissing));
}

#[test]
fn update_witness_changes_url_only() {
    let accounts = AccountStore::new(mem());
    let witnesses = WitnessStore::new(mem());
    put_funded(&accounts, ALICE, 1_000_000);
    witnesses.put(
        &addr(ALICE),
        &Witness {
            address: ALICE.to_vec(),
            url: "https://old.test".to_string(),
            vote_count: 12345,
            total_produced: 999,
            total_missed: 1,
            ..Default::default()
        },
    ).unwrap();
    let c = WitnessUpdateContract {
        owner_address: ALICE.to_vec(),
        update_url: b"https://new.test".to_vec(),
    };
    witness::validate_witness_update(&accounts, &witnesses, &c).unwrap();
    witness::execute_witness_update(&witnesses, &c).unwrap();
    let w = witnesses.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(w.url, "https://new.test");
    // Other fields preserved.
    assert_eq!(w.vote_count, 12345);
    assert_eq!(w.total_produced, 999);
    assert_eq!(w.total_missed, 1);
}

// ============================================================
// UpdateAccount (name)
// ============================================================

#[test]
fn update_account_accepts_empty_name() {
    // java TransactionUtil.validAccountName = validBytes(name, 200,
    // allowEmpty=true): an EMPTY account name is VALID. Rejecting it (the
    // previous behavior) would flip a SUCCESS to FAILED versus the chain.
    let accounts = AccountStore::new(mem());
    let idx = AccountIndexStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_funded(&accounts, ALICE, 0);
    let c = AccountUpdateContract {
        owner_address: ALICE.to_vec(),
        account_name: Vec::new(),
    };
    account::validate_update_account(&accounts, &idx, &dp, &c).unwrap();
}

#[test]
fn update_account_rejects_name_over_200_bytes() {
    // java validBytes upper bound: a name longer than 200 bytes is invalid.
    let accounts = AccountStore::new(mem());
    let idx = AccountIndexStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_funded(&accounts, ALICE, 0);
    let c = AccountUpdateContract {
        owner_address: ALICE.to_vec(),
        account_name: vec![b'a'; 201],
    };
    let err = account::validate_update_account(&accounts, &idx, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::InvalidAccountName));
}

#[test]
fn update_account_rejects_missing_owner() {
    let accounts = AccountStore::new(mem());
    let idx = AccountIndexStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let c = AccountUpdateContract {
        owner_address: ALICE.to_vec(),
        account_name: b"alice".to_vec(),
    };
    let err = account::validate_update_account(&accounts, &idx, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::OwnerAccountMissing));
}

#[test]
fn update_account_rejects_renaming_when_already_named_and_proposal_disabled() {
    let accounts = AccountStore::new(mem());
    let idx = AccountIndexStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    // ALLOW_UPDATE_ACCOUNT_NAME defaults to 0 (disabled).
    let mut alice = Account {
        address: ALICE.to_vec(),
        r#type: AccountType::Normal as i32,
        ..Default::default()
    };
    alice.account_name = b"existing".to_vec();
    accounts.put(&addr(ALICE), &alice).unwrap();
    let c = AccountUpdateContract {
        owner_address: ALICE.to_vec(),
        account_name: b"renamed".to_vec(),
    };
    let err = account::validate_update_account(&accounts, &idx, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::AccountAlreadyNamed));
}

#[test]
fn update_account_rejects_name_taken_by_another_account() {
    let accounts = AccountStore::new(mem());
    let idx = AccountIndexStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_funded(&accounts, ALICE, 0);
    idx.put(b"taken", &addr(BOB)).unwrap();
    let c = AccountUpdateContract {
        owner_address: ALICE.to_vec(),
        account_name: b"taken".to_vec(),
    };
    let err = account::validate_update_account(&accounts, &idx, &dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::AccountNameTaken));
}

#[test]
fn update_account_allows_rename_when_proposal_enabled() {
    let accounts = AccountStore::new(mem());
    let idx = AccountIndexStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(b"ALLOW_UPDATE_ACCOUNT_NAME", 1);
    let mut alice = Account {
        address: ALICE.to_vec(),
        r#type: AccountType::Normal as i32,
        ..Default::default()
    };
    alice.account_name = b"old".to_vec();
    accounts.put(&addr(ALICE), &alice).unwrap();
    let c = AccountUpdateContract {
        owner_address: ALICE.to_vec(),
        account_name: b"new".to_vec(),
    };
    account::validate_update_account(&accounts, &idx, &dp, &c).unwrap();
    account::execute_update_account(&accounts, &idx, &c).unwrap();
    let alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(alice.account_name, b"new");
    assert!(idx.get(b"new").unwrap().is_some());
}

#[test]
fn update_account_writes_index_on_first_naming() {
    let accounts = AccountStore::new(mem());
    let idx = AccountIndexStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    put_funded(&accounts, ALICE, 0);
    let c = AccountUpdateContract {
        owner_address: ALICE.to_vec(),
        account_name: b"alice".to_vec(),
    };
    account::validate_update_account(&accounts, &idx, &dp, &c).unwrap();
    account::execute_update_account(&accounts, &idx, &c).unwrap();
    let alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(alice.account_name, b"alice");
    let stored = idx.get(b"alice").unwrap().unwrap();
    assert_eq!(stored.as_bytes(), &ALICE);
}

// ============================================================
// WithdrawBalance — F4 receipt fidelity
// ============================================================

/// java `WithdrawBalanceActuator.execute` sets
/// `ret.setWithdrawAmount(allowance)` (line 69). The actuator's
/// `ExecutionResult.ret.withdraw_amount` must carry the same value so the
/// stored `TransactionInfo.withdraw_amount` matches java's
/// `gettransactioninfobyid`. With `ALLOW_CHANGE_DELEGATION` off (default),
/// reward settlement is a no-op, so the pre-set allowance is withdrawn
/// verbatim.
#[test]
fn withdraw_balance_carries_withdraw_amount() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let delegation = DelegationStore::new(mem());
    // Head timestamp past the 24h allowance-frozen window measured from
    // `latest_withdraw_time == 0`, which java applies with no exemption for a
    // never-withdrawn account.
    dp.save_latest_block_header_timestamp(1_700_000_000_000);
    let allowance = 4_242_000i64;
    accounts
        .put(
            &addr(ALICE),
            &Account {
                address: ALICE.to_vec(),
                balance: 0,
                allowance,
                latest_withdraw_time: 0,
                r#type: AccountType::Normal as i32,
                ..Default::default()
            },
        )
        .unwrap();
    let c = WithdrawBalanceContract { owner_address: ALICE.to_vec() };
    witness::validate_withdraw_balance(&accounts, &dp, &delegation, None, &c).unwrap();
    let result =
        witness::execute_withdraw_balance(&accounts, &dp, &delegation, None, &c).unwrap();

    assert_eq!(
        result.ret.withdraw_amount, allowance,
        "ret.withdraw_amount must equal the withdrawn allowance"
    );
    // State side-effect unchanged: allowance moved into balance, zeroed.
    let alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(alice.balance, allowance);
    assert_eq!(alice.allowance, 0);
}
