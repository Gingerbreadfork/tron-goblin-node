//! Rejection catalogue and state deltas asserted by java's asset, account and
//! witness actuator tests.
//!
//! References: `UnfreezeAssetActuatorTest`, `UpdateAssetActuatorTest`,
//! `AssetIssueActuatorTest`, `UpdateAccountActuatorTest`,
//! `SetAccountIdActuatorTest`, `WithdrawBalanceActuatorTest`,
//! `ClearABIContractActuatorTest`, `UpdateSettingContractActuatorTest`,
//! `UpdateEnergyLimitContractActuatorTest`.

use std::sync::Arc;

use hex_literal::hex;
use tron_actuator::{account, asset, contract_admin, witness, ActuatorError};
use tron_chainbase::{
    AbiStore, AccountIdIndexStore, AccountIndexStore, AccountStore, AssetIssueStore,
    AssetIssueV2Store, ContractStore, DelegationStore, DynamicPropertiesStore, KvBackend,
    MemBackend,
};
use tron_crypto::address::Address;
use tron_proto::account::Frozen;
use tron_proto::{
    Account, AccountType, AccountUpdateContract, AssetIssueContract, ClearAbiContract,
    SetAccountIdContract, SmartContract, UnfreezeAssetContract, UpdateAssetContract,
    UpdateEnergyLimitContract, UpdateSettingContract, WithdrawBalanceContract,
};

const ALICE: [u8; 21] = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");
const BOB: [u8; 21] = hex!("41a614f803b6fd780986a42c78ec9c7f77e6ded13c");
const CONTRACT: [u8; 21] = hex!("41dddddddddddddddddddddddddddddddddddddddd");

/// A head timestamp comfortably past the 24h allowance-frozen window measured
/// from `latest_withdraw_time == 0`, mirroring any real chain.
const REALISTIC_NOW_MS: i64 = 1_700_000_000_000;

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn addr(b: [u8; 21]) -> Address {
    Address::from_raw(b)
}

// =============================================================================
// UnfreezeAssetActuator
// =============================================================================

fn issuer_with_frozen_supply(
    accounts: &AccountStore,
    issued_name: &[u8],
    issued_id: &[u8],
    entries: Vec<Frozen>,
) {
    accounts
        .put(
            &addr(ALICE),
            &Account {
                address: ALICE.to_vec(),
                r#type: AccountType::Normal as i32,
                asset_issued_name: issued_name.to_vec(),
                asset_issued_id: issued_id.to_vec(),
                frozen_supply: entries,
                ..Default::default()
            },
        )
        .unwrap();
}

/// java `UnfreezeAssetActuator.validate` rejects "this account has not issued
/// any asset" for an account holding a frozen supply with no issuance record.
/// While `allowSameTokenName == 0` the check reads `assetIssuedName`.
#[test]
fn unfreeze_asset_requires_issued_name_before_same_token_name() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.save_latest_block_header_timestamp(10_000);
    issuer_with_frozen_supply(
        &accounts,
        b"", // no issuance
        b"1000001",
        vec![Frozen {
            frozen_balance: 1_000,
            expire_time: 1, // already expired
        }],
    );
    let c = UnfreezeAssetContract {
        owner_address: ALICE.to_vec(),
    };
    assert_eq!(
        asset::validate_unfreeze_asset(&accounts, &dp, &c),
        Err(ActuatorError::AssetMissing)
    );
}

/// After `allowSameTokenName` activates java reads `assetIssuedID` instead, so
/// an account carrying only the legacy name is rejected on mainnet.
#[test]
fn unfreeze_asset_requires_issued_id_after_same_token_name() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.save_allow_same_token_name(1);
    dp.save_latest_block_header_timestamp(10_000);
    issuer_with_frozen_supply(
        &accounts,
        b"TESTASSET",
        b"", // no V2 id
        vec![Frozen {
            frozen_balance: 1_000,
            expire_time: 1,
        }],
    );
    let c = UnfreezeAssetContract {
        owner_address: ALICE.to_vec(),
    };
    assert_eq!(
        asset::validate_unfreeze_asset(&accounts, &dp, &c),
        Err(ActuatorError::AssetMissing)
    );
}

/// java checks `getFrozenSupplyCount() <= 0` ("no frozen supply balance")
/// *before* the issuance check, so an issuer with nothing frozen is rejected
/// on the supply count.
#[test]
fn unfreeze_asset_checks_frozen_supply_before_issuance() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.save_latest_block_header_timestamp(10_000);
    issuer_with_frozen_supply(&accounts, b"", b"", Vec::new());
    let c = UnfreezeAssetContract {
        owner_address: ALICE.to_vec(),
    };
    assert_eq!(
        asset::validate_unfreeze_asset(&accounts, &dp, &c),
        Err(ActuatorError::NoUnfreezableAsset)
    );
}

/// A well-formed issuer with an expired entry passes — the anchor that keeps
/// the two rejection tests above from passing vacuously.
#[test]
fn unfreeze_asset_accepts_expired_entry_for_issuer() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.save_latest_block_header_timestamp(10_000);
    issuer_with_frozen_supply(
        &accounts,
        b"TESTASSET",
        b"1000001",
        vec![Frozen {
            frozen_balance: 1_000,
            expire_time: 1,
        }],
    );
    let c = UnfreezeAssetContract {
        owner_address: ALICE.to_vec(),
    };
    assert_eq!(asset::validate_unfreeze_asset(&accounts, &dp, &c), Ok(()));
}

// =============================================================================
// UpdateAssetActuator
// =============================================================================

fn asset_owner_ctx() -> (AccountStore, AssetIssueStore, AssetIssueV2Store, DynamicPropertiesStore)
{
    let accounts = AccountStore::new(mem());
    let v1 = AssetIssueStore::new(mem());
    let v2 = AssetIssueV2Store::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    v1.put(
        b"TESTASSET",
        &AssetIssueContract {
            owner_address: ALICE.to_vec(),
            name: b"TESTASSET".to_vec(),
            total_supply: 1_000,
            ..Default::default()
        },
    )
    .unwrap();
    accounts
        .put(
            &addr(ALICE),
            &Account {
                address: ALICE.to_vec(),
                r#type: AccountType::Normal as i32,
                asset_issued_name: b"TESTASSET".to_vec(),
                ..Default::default()
            },
        )
        .unwrap();
    (accounts, v1, v2, dp)
}

fn update_asset(url: &[u8], description: &[u8], new_limit: i64, new_public: i64)
    -> UpdateAssetContract
{
    UpdateAssetContract {
        owner_address: ALICE.to_vec(),
        description: description.to_vec(),
        url: url.to_vec(),
        new_limit,
        new_public_limit: new_public,
    }
}

/// java `UpdateAssetActuator.validate` order is address → account → issuance →
/// url → description → newLimit → newPublicLimit. `invalidAssetUrl` pins an
/// empty url as "Invalid url"; the limits are checked only afterwards, so a
/// contract violating both reports the url.
#[test]
fn update_asset_checks_url_before_limits() {
    let (accounts, v1, v2, dp) = asset_owner_ctx();
    let c = update_asset(b"", b"desc", -1, -1);
    assert_eq!(
        asset::validate_update_asset(&accounts, &v1, &v2, &dp, &c),
        Err(ActuatorError::InvalidUrl)
    );
}

/// java bounds both net limits by `[0, oneDayNetLimit)` — the upper bound is
/// exclusive, so `oneDayNetLimit` itself is rejected while `oneDayNetLimit - 1`
/// is accepted (`invalidNewLimit` / `invalidNewPublicLimit`).
#[test]
fn update_asset_net_limit_upper_bound_is_exclusive() {
    let (accounts, v1, v2, dp) = asset_owner_ctx();
    let one_day = 57_600_000_000i64;

    let at_limit = update_asset(b"https://tron.network", b"desc", one_day, 0);
    assert!(asset::validate_update_asset(&accounts, &v1, &v2, &dp, &at_limit).is_err());

    let below = update_asset(b"https://tron.network", b"desc", one_day - 1, one_day - 1);
    assert_eq!(
        asset::validate_update_asset(&accounts, &v1, &v2, &dp, &below),
        Ok(())
    );

    let public_at_limit = update_asset(b"https://tron.network", b"desc", 0, one_day);
    assert!(asset::validate_update_asset(&accounts, &v1, &v2, &dp, &public_at_limit).is_err());
}

/// java rejects negative limits with the same message as over-large ones.
#[test]
fn update_asset_rejects_negative_limits() {
    let (accounts, v1, v2, dp) = asset_owner_ctx();
    let neg = update_asset(b"https://tron.network", b"desc", -1, 0);
    assert!(asset::validate_update_asset(&accounts, &v1, &v2, &dp, &neg).is_err());
    let neg_public = update_asset(b"https://tron.network", b"desc", 0, -1);
    assert!(asset::validate_update_asset(&accounts, &v1, &v2, &dp, &neg_public).is_err());
}

/// `invalidAssetDescription`: descriptions run to 200 bytes; 201 is rejected.
#[test]
fn update_asset_description_length_bound() {
    let (accounts, v1, v2, dp) = asset_owner_ctx();
    let ok = update_asset(b"https://tron.network", &vec![b'd'; 200], 0, 0);
    assert_eq!(
        asset::validate_update_asset(&accounts, &v1, &v2, &dp, &ok),
        Ok(())
    );
    let too_long = update_asset(b"https://tron.network", &vec![b'd'; 201], 0, 0);
    assert!(asset::validate_update_asset(&accounts, &v1, &v2, &dp, &too_long).is_err());
}

/// `noAsset`: an existing account that never issued a token is rejected before
/// any of the field bounds are examined.
#[test]
fn update_asset_rejects_non_issuer() {
    let (accounts, v1, v2, dp) = asset_owner_ctx();
    accounts
        .put(
            &addr(BOB),
            &Account {
                address: BOB.to_vec(),
                r#type: AccountType::Normal as i32,
                ..Default::default()
            },
        )
        .unwrap();
    let mut c = update_asset(b"", b"desc", -1, -1);
    c.owner_address = BOB.to_vec();
    assert_eq!(
        asset::validate_update_asset(&accounts, &v1, &v2, &dp, &c),
        Err(ActuatorError::AccountAlreadyIssuedAsset)
    );
}

// =============================================================================
// AssetIssueActuator
// =============================================================================

fn base_issue(now: i64) -> AssetIssueContract {
    AssetIssueContract {
        owner_address: ALICE.to_vec(),
        name: b"TESTASSET".to_vec(),
        abbr: b"TST".to_vec(),
        total_supply: 1_000_000,
        trx_num: 1,
        num: 1,
        start_time: now + 1_000,
        end_time: now + 2_000,
        url: b"https://tron.network".to_vec(),
        description: b"desc".to_vec(),
        precision: 0,
        ..Default::default()
    }
}

fn issue_ctx() -> (AccountStore, AssetIssueStore, DynamicPropertiesStore) {
    let accounts = AccountStore::new(mem());
    let v1 = AssetIssueStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.save_latest_block_header_timestamp(1_000_000);
    dp.save_allow_same_token_name(1);
    dp.put_long(b"ASSET_ISSUE_FEE", 1_024_000_000);
    accounts
        .put(
            &addr(ALICE),
            &Account {
                address: ALICE.to_vec(),
                balance: 2_048_000_000,
                r#type: AccountType::Normal as i32,
                ..Default::default()
            },
        )
        .unwrap();
    (accounts, v1, dp)
}

/// java `AssetIssueActuator.validate` rejects the reserved name once
/// `allowSameTokenName != 0`: "assetName can't be trx", case-insensitively.
#[test]
fn asset_issue_rejects_reserved_trx_name() {
    let (accounts, v1, dp) = issue_ctx();
    for name in [&b"trx"[..], b"TRX", b"Trx"] {
        let mut c = base_issue(1_000_000);
        c.name = name.to_vec();
        assert!(
            asset::validate_asset_issue(&accounts, &v1, &dp, &c).is_err(),
            "name={:?} must be rejected",
            String::from_utf8_lossy(name)
        );
    }
}

/// The reserved-name rule is gated: while `allowSameTokenName == 0` java never
/// applies it.
#[test]
fn asset_issue_allows_trx_name_before_same_token_name() {
    let (accounts, v1, dp) = issue_ctx();
    dp.save_allow_same_token_name(0);
    let mut c = base_issue(1_000_000);
    c.name = b"trx".to_vec();
    assert_eq!(asset::validate_asset_issue(&accounts, &v1, &dp, &c), Ok(()));
}

/// "precision cannot exceed 6" — the bound is inclusive at 6 and only applies
/// once `allowSameTokenName != 0`.
#[test]
fn asset_issue_precision_bound() {
    let (accounts, v1, dp) = issue_ctx();
    for precision in [1i32, 6] {
        let mut c = base_issue(1_000_000);
        c.precision = precision;
        assert_eq!(
            asset::validate_asset_issue(&accounts, &v1, &dp, &c),
            Ok(()),
            "precision={precision}"
        );
    }
    let mut c = base_issue(1_000_000);
    c.precision = 7;
    assert!(asset::validate_asset_issue(&accounts, &v1, &dp, &c).is_err());
}

/// "Start time should be greater than HeadBlockTime" — the comparison is
/// `startTime <= now`, so a start equal to the head timestamp is rejected.
#[test]
fn asset_issue_start_time_must_be_strictly_future() {
    let (accounts, v1, dp) = issue_ctx();
    let now = 1_000_000i64;
    let mut c = base_issue(now);
    c.start_time = now;
    assert!(asset::validate_asset_issue(&accounts, &v1, &dp, &c).is_err());
    c.start_time = now + 1;
    c.end_time = now + 2;
    assert_eq!(asset::validate_asset_issue(&accounts, &v1, &dp, &c), Ok(()));
}

/// "End time should be greater than start time" — also strict.
#[test]
fn asset_issue_end_time_must_exceed_start_time() {
    let (accounts, v1, dp) = issue_ctx();
    let mut c = base_issue(1_000_000);
    c.end_time = c.start_time;
    assert!(asset::validate_asset_issue(&accounts, &v1, &dp, &c).is_err());
}

/// "Frozen supply cannot exceed total supply" is *cumulative*: java decrements
/// a running `remainSupply` per entry in list order, so two entries that each
/// fit but together exceed the supply are rejected on the second.
#[test]
fn asset_issue_frozen_supply_limit_is_cumulative() {
    let (accounts, v1, dp) = issue_ctx();
    let mut c = base_issue(1_000_000);
    c.total_supply = 1_000;
    c.frozen_supply = vec![
        tron_proto::asset_issue_contract::FrozenSupply {
            frozen_amount: 600,
            frozen_days: 1,
        },
        tron_proto::asset_issue_contract::FrozenSupply {
            frozen_amount: 600,
            frozen_days: 1,
        },
    ];
    assert!(asset::validate_asset_issue(&accounts, &v1, &dp, &c).is_err());

    // Together within the supply → accepted.
    c.frozen_supply[1].frozen_amount = 400;
    assert_eq!(asset::validate_asset_issue(&accounts, &v1, &dp, &c), Ok(()));
}

/// "PublicFreeAssetNetUsage must be 0!" — the field is an output, never an
/// input, so any non-zero value is rejected.
#[test]
fn asset_issue_rejects_non_zero_public_free_asset_net_usage() {
    let (accounts, v1, dp) = issue_ctx();
    let mut c = base_issue(1_000_000);
    c.public_free_asset_net_usage = 1;
    assert!(asset::validate_asset_issue(&accounts, &v1, &dp, &c).is_err());
}

/// "No enough balance for fee!" — the owner must hold at least the issue fee,
/// and the bound is `balance < fee`.
#[test]
fn asset_issue_fee_bound_is_exclusive() {
    let (accounts, v1, dp) = issue_ctx();
    let c = base_issue(1_000_000);

    accounts
        .put(
            &addr(ALICE),
            &Account {
                address: ALICE.to_vec(),
                balance: 1_024_000_000 - 1,
                r#type: AccountType::Normal as i32,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(matches!(
        asset::validate_asset_issue(&accounts, &v1, &dp, &c),
        Err(ActuatorError::InsufficientBalance { .. })
    ));

    accounts
        .put(
            &addr(ALICE),
            &Account {
                address: ALICE.to_vec(),
                balance: 1_024_000_000,
                r#type: AccountType::Normal as i32,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(asset::validate_asset_issue(&accounts, &v1, &dp, &c), Ok(()));
}

// =============================================================================
// UpdateAccountActuator / SetAccountIdActuator
// =============================================================================

/// java `UpdateAccountActuator.validate` checks the *account name* before the
/// owner address — the reverse of every other actuator. A contract with both
/// an oversize name and a malformed address reports the name.
#[test]
fn update_account_checks_name_before_owner_address() {
    let accounts = AccountStore::new(mem());
    let name_index = AccountIndexStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let c = AccountUpdateContract {
        account_name: vec![b'n'; 201], // over the 200-byte bound
        owner_address: vec![0u8; 10],  // malformed
    };
    assert_eq!(
        account::validate_update_account(&accounts, &name_index, &dp, &c),
        Err(ActuatorError::InvalidAccountName)
    );
}

/// `twiceUpdateAccountFail`: renaming an already-named account is rejected
/// while `allowUpdateAccountName == 0` ("This account name is already
/// existed"), and `twiceUpdateAccountSuccess`: permitted once the proposal is
/// active.
#[test]
fn update_account_rename_gated_on_allow_update_account_name() {
    let accounts = AccountStore::new(mem());
    let name_index = AccountIndexStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    accounts
        .put(
            &addr(ALICE),
            &Account {
                address: ALICE.to_vec(),
                account_name: b"first".to_vec(),
                r#type: AccountType::Normal as i32,
                ..Default::default()
            },
        )
        .unwrap();
    let c = AccountUpdateContract {
        account_name: b"second".to_vec(),
        owner_address: ALICE.to_vec(),
    };
    assert_eq!(
        account::validate_update_account(&accounts, &name_index, &dp, &c),
        Err(ActuatorError::AccountAlreadyNamed)
    );

    dp.put_long(b"ALLOW_UPDATE_ACCOUNT_NAME", 1);
    assert_eq!(
        account::validate_update_account(&accounts, &name_index, &dp, &c),
        Ok(())
    );
}

/// `updateSameNameFail`: a name already present in the index is rejected
/// ("This name is existed") — and that check is likewise lifted once
/// `allowUpdateAccountName` is on, so duplicates become legal.
#[test]
fn update_account_duplicate_name_gated_on_allow_update_account_name() {
    let accounts = AccountStore::new(mem());
    let name_index = AccountIndexStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    accounts
        .put(
            &addr(ALICE),
            &Account {
                address: ALICE.to_vec(),
                r#type: AccountType::Normal as i32,
                ..Default::default()
            },
        )
        .unwrap();
    name_index.put(b"taken", &addr(BOB)).unwrap();
    let c = AccountUpdateContract {
        account_name: b"taken".to_vec(),
        owner_address: ALICE.to_vec(),
    };
    assert_eq!(
        account::validate_update_account(&accounts, &name_index, &dp, &c),
        Err(ActuatorError::AccountNameTaken)
    );

    dp.put_long(b"ALLOW_UPDATE_ACCOUNT_NAME", 1);
    assert_eq!(
        account::validate_update_account(&accounts, &name_index, &dp, &c),
        Ok(())
    );
}

/// java's `validAccountName` allows an empty name, so an update that clears
/// the name is accepted — rejecting it would flip a recorded SUCCESS to
/// FAILED.
#[test]
fn update_account_accepts_empty_name() {
    let accounts = AccountStore::new(mem());
    let name_index = AccountIndexStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    accounts
        .put(
            &addr(ALICE),
            &Account {
                address: ALICE.to_vec(),
                r#type: AccountType::Normal as i32,
                ..Default::default()
            },
        )
        .unwrap();
    let c = AccountUpdateContract {
        account_name: Vec::new(),
        owner_address: ALICE.to_vec(),
    };
    assert_eq!(
        account::validate_update_account(&accounts, &name_index, &dp, &c),
        Ok(())
    );
}

/// java `SetAccountIdActuator.validate` likewise checks the *id* before the
/// owner address.
#[test]
fn set_account_id_checks_id_before_owner_address() {
    let accounts = AccountStore::new(mem());
    let id_index = AccountIdIndexStore::new(mem());
    let c = SetAccountIdContract {
        owner_address: vec![0u8; 10], // malformed
        account_id: b"short".to_vec(), // under the 8-byte minimum
    };
    assert_eq!(
        account::validate_set_account_id(&accounts, &id_index, &c),
        Err(ActuatorError::InvalidAccountId)
    );
}

/// `invalidName` in `SetAccountIdActuatorTest`: ids run 8..=32 bytes of
/// printable ASCII. The bounds are inclusive at both ends.
#[test]
fn set_account_id_length_and_charset_bounds() {
    let accounts = AccountStore::new(mem());
    let id_index = AccountIdIndexStore::new(mem());
    accounts
        .put(
            &addr(ALICE),
            &Account {
                address: ALICE.to_vec(),
                r#type: AccountType::Normal as i32,
                ..Default::default()
            },
        )
        .unwrap();

    let check = |id: Vec<u8>| {
        account::validate_set_account_id(
            &accounts,
            &id_index,
            &SetAccountIdContract {
                owner_address: ALICE.to_vec(),
                account_id: id,
            },
        )
    };

    assert_eq!(check(vec![b'a'; 8]), Ok(()));
    assert_eq!(check(vec![b'a'; 32]), Ok(()));
    assert_eq!(check(vec![b'a'; 7]), Err(ActuatorError::InvalidAccountId));
    assert_eq!(check(vec![b'a'; 33]), Err(ActuatorError::InvalidAccountId));
    assert_eq!(check(Vec::new()), Err(ActuatorError::InvalidAccountId));
    // Space (0x20) and NUL are below the printable range java's
    // `validReadableBytes` accepts.
    assert_eq!(
        check(b"abc defg".to_vec()),
        Err(ActuatorError::InvalidAccountId)
    );
    assert_eq!(
        check(b"abc\0defg".to_vec()),
        Err(ActuatorError::InvalidAccountId)
    );
}

/// `twiceUpdateAccount`: an id can only ever be set once ("This account id
/// already set") — there is no proposal that lifts this.
#[test]
fn set_account_id_is_write_once() {
    let accounts = AccountStore::new(mem());
    let id_index = AccountIdIndexStore::new(mem());
    accounts
        .put(
            &addr(ALICE),
            &Account {
                address: ALICE.to_vec(),
                account_id: b"existing".to_vec(),
                r#type: AccountType::Normal as i32,
                ..Default::default()
            },
        )
        .unwrap();
    let c = SetAccountIdContract {
        owner_address: ALICE.to_vec(),
        account_id: b"replacement".to_vec(),
    };
    assert_eq!(
        account::validate_set_account_id(&accounts, &id_index, &c),
        Err(ActuatorError::AccountAlreadyHasId)
    );
}

// =============================================================================
// WithdrawBalanceActuator
// =============================================================================

/// java `WithdrawBalanceActuator.validate` applies
/// `now - latestWithdrawTime < witnessAllowanceFrozenTime` with no exemption
/// for an account that has never withdrawn: `latestWithdrawTime == 0` is a
/// real value, not a sentinel. `notTimeToWithdraw` pins the rejection.
#[test]
fn withdraw_cooldown_applies_to_never_withdrawn_account() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let delegation = DelegationStore::new(mem());
    // A head timestamp inside the first 24h of the epoch: java rejects.
    dp.save_latest_block_header_timestamp(1_000);
    accounts
        .put(
            &addr(ALICE),
            &Account {
                address: ALICE.to_vec(),
                allowance: 1_000_000,
                latest_withdraw_time: 0,
                r#type: AccountType::Normal as i32,
                ..Default::default()
            },
        )
        .unwrap();
    let c = WithdrawBalanceContract {
        owner_address: ALICE.to_vec(),
    };
    assert!(matches!(
        witness::validate_withdraw_balance(&accounts, &dp, &delegation, None, &c),
        Err(ActuatorError::WithdrawTooSoon { .. })
    ));
}

/// The cooldown boundary is `now - latestWithdrawTime < 24h`, so exactly 24h
/// later is permitted and one millisecond short is not.
#[test]
fn withdraw_cooldown_boundary_is_exact() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let delegation = DelegationStore::new(mem());
    let last = REALISTIC_NOW_MS;
    let frozen = 24 * 60 * 60 * 1000i64;
    accounts
        .put(
            &addr(ALICE),
            &Account {
                address: ALICE.to_vec(),
                allowance: 1_000_000,
                latest_withdraw_time: last,
                r#type: AccountType::Normal as i32,
                ..Default::default()
            },
        )
        .unwrap();
    let c = WithdrawBalanceContract {
        owner_address: ALICE.to_vec(),
    };

    dp.save_latest_block_header_timestamp(last + frozen - 1);
    assert!(matches!(
        witness::validate_withdraw_balance(&accounts, &dp, &delegation, None, &c),
        Err(ActuatorError::WithdrawTooSoon { .. })
    ));

    dp.save_latest_block_header_timestamp(last + frozen);
    assert_eq!(
        witness::validate_withdraw_balance(&accounts, &dp, &delegation, None, &c),
        Ok(())
    );
}

/// java closes `validate` with `LongMath.checkedAdd(balance, allowance)`, so a
/// credit that would overflow the balance is rejected at validate rather than
/// failing part-way through execute.
#[test]
fn withdraw_rejects_balance_allowance_overflow() {
    let accounts = AccountStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let delegation = DelegationStore::new(mem());
    dp.save_latest_block_header_timestamp(REALISTIC_NOW_MS);
    accounts
        .put(
            &addr(ALICE),
            &Account {
                address: ALICE.to_vec(),
                balance: i64::MAX,
                allowance: 1,
                r#type: AccountType::Normal as i32,
                ..Default::default()
            },
        )
        .unwrap();
    let c = WithdrawBalanceContract {
        owner_address: ALICE.to_vec(),
    };
    assert_eq!(
        witness::validate_withdraw_balance(&accounts, &dp, &delegation, None, &c),
        Err(ActuatorError::Overflow)
    );
}

// =============================================================================
// Contract admin: repeated updates
// =============================================================================

fn contract_admin_ctx() -> (AccountStore, ContractStore, AbiStore, DynamicPropertiesStore) {
    let accounts = AccountStore::new(mem());
    let contracts = ContractStore::new(mem());
    let abi = AbiStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    accounts
        .put(
            &addr(ALICE),
            &Account {
                address: ALICE.to_vec(),
                r#type: AccountType::Normal as i32,
                ..Default::default()
            },
        )
        .unwrap();
    contracts
        .put(
            &addr(CONTRACT),
            &SmartContract {
                origin_address: ALICE.to_vec(),
                contract_address: CONTRACT.to_vec(),
                consume_user_resource_percent: 50,
                origin_energy_limit: 10_000_000,
                ..Default::default()
            },
        )
        .unwrap();
    (accounts, contracts, abi, dp)
}

/// `twiceUpdateSettingContract`: consecutive updates are each applied in full,
/// the second overwriting the first — there is no once-per-contract limit.
#[test]
fn update_setting_applies_repeatedly() {
    let (accounts, contracts, _abi, _dp) = contract_admin_ctx();
    for percent in [30i64, 0, 100] {
        let c = UpdateSettingContract {
            owner_address: ALICE.to_vec(),
            contract_address: CONTRACT.to_vec(),
            consume_user_resource_percent: percent,
        };
        contract_admin::validate_update_setting(&accounts, &contracts, &c).unwrap();
        contract_admin::execute_update_setting(&contracts, &c).unwrap();
        assert_eq!(
            contracts
                .get(&addr(CONTRACT))
                .unwrap()
                .unwrap()
                .consume_user_resource_percent,
            percent
        );
    }
}

/// `twiceUpdateEnergyLimitContract`: same for the origin energy limit, and the
/// consume-percent is left untouched by it.
#[test]
fn update_energy_limit_applies_repeatedly_and_preserves_percent() {
    let (accounts, contracts, _abi, dp) = contract_admin_ctx();
    dp.save_latest_block_header_number(10_000_000);
    for limit in [90_000_000i64, 1] {
        let c = UpdateEnergyLimitContract {
            owner_address: ALICE.to_vec(),
            contract_address: CONTRACT.to_vec(),
            origin_energy_limit: limit,
        };
        contract_admin::validate_update_energy_limit(&accounts, &contracts, &dp, &c).unwrap();
        contract_admin::execute_update_energy_limit(&contracts, &c).unwrap();
        let sc = contracts.get(&addr(CONTRACT)).unwrap().unwrap();
        assert_eq!(sc.origin_energy_limit, limit);
        assert_eq!(sc.consume_user_resource_percent, 50);
    }
}

/// `ClearABIContractActuatorTest.successClearABIContract`: clearing is
/// idempotent and leaves the contract row itself intact.
#[test]
fn clear_abi_is_idempotent_and_preserves_contract() {
    let (accounts, contracts, abi, dp) = contract_admin_ctx();
    dp.put_long(b"ALLOW_TVM_CONSTANTINOPLE", 1);
    let c = ClearAbiContract {
        owner_address: ALICE.to_vec(),
        contract_address: CONTRACT.to_vec(),
    };
    for _ in 0..2 {
        contract_admin::validate_clear_abi(&accounts, &contracts, &dp, &c).unwrap();
        contract_admin::execute_clear_abi(&abi, &c).unwrap();
        assert!(abi.get(&addr(CONTRACT)).unwrap().unwrap().entrys.is_empty());
    }
    let sc = contracts.get(&addr(CONTRACT)).unwrap().unwrap();
    assert_eq!(sc.origin_energy_limit, 10_000_000);
    assert_eq!(sc.consume_user_resource_percent, 50);
}
