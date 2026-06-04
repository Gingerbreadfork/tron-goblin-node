//! Error-path tests for `ParticipateAssetIssueActuator`.
//!
//! Java reference: `ParticipateAssetIssueActuatorTest` (~37 cases).
//! Our existing coverage was a single happy-path in `full_layer.rs`.
//! These tests cover all the validation predicates + the AMM-style
//! exchange-rate math that can silently produce wrong asset amounts
//! on extreme `num/trx_num` ratios.

use std::collections::BTreeMap;
use std::sync::Arc;

use hex_literal::hex;
use tron_actuator::{asset, ActuatorError};
use tron_chainbase::{
    AccountStore, AssetIssueStore, DynamicPropertiesStore, KvBackend, MemBackend,
};
use tron_crypto::address::Address;
use tron_proto::{
    Account, AccountType, AssetIssueContract, ParticipateAssetIssueContract,
};

const OWNER: [u8; 21] = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");
const ISSUER: [u8; 21] = hex!("41a614f803b6fd780986a42c78ec9c7f77e6ded13c");

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}
fn addr(b: [u8; 21]) -> Address {
    Address::from_raw(b)
}

struct Ctx {
    accounts: AccountStore,
    v1: AssetIssueStore,
    dp: DynamicPropertiesStore,
}

fn ctx() -> Ctx {
    Ctx {
        accounts: AccountStore::new(mem()),
        v1: AssetIssueStore::new(mem()),
        dp: DynamicPropertiesStore::new(mem()),
    }
}

const ASSET_NAME: &[u8] = b"TestCoin";

fn seed_issuer_with_asset(
    ctx: &Ctx,
    trx_num: i32,
    asset_num: i32,
    start_time: i64,
    end_time: i64,
    issuer_asset_balance: i64,
) {
    let asset = AssetIssueContract {
        id: "1000001".to_string(),
        owner_address: ISSUER.to_vec(),
        name: ASSET_NAME.to_vec(),
        trx_num,
        num: asset_num,
        start_time,
        end_time,
        total_supply: 1_000_000_000,
        ..Default::default()
    };
    ctx.v1.put(ASSET_NAME, &asset).unwrap();
    ctx.accounts.put(
        &addr(ISSUER),
        &Account {
            address: ISSUER.to_vec(),
            balance: 0,
            r#type: AccountType::Normal as i32,
            asset: BTreeMap::from([("TestCoin".to_string(), issuer_asset_balance)]),
            asset_v2: BTreeMap::from([("TestCoin".to_string(), issuer_asset_balance)]),
            ..Default::default()
        },
    ).unwrap();
}

fn put_owner(ctx: &Ctx, trx_balance: i64) {
    ctx.accounts.put(
        &addr(OWNER),
        &Account {
            address: OWNER.to_vec(),
            balance: trx_balance,
            r#type: AccountType::Normal as i32,
            ..Default::default()
        },
    ).unwrap();
}

fn base_contract(amount: i64) -> ParticipateAssetIssueContract {
    ParticipateAssetIssueContract {
        owner_address: OWNER.to_vec(),
        to_address: ISSUER.to_vec(),
        asset_name: ASSET_NAME.to_vec(),
        amount,
    }
}

// ============================================================
// validate
// ============================================================

#[test]
fn rejects_self_participate() {
    let ctx = ctx();
    put_owner(&ctx, 1_000_000);
    seed_issuer_with_asset(&ctx, 1, 10, 0, i64::MAX, 1_000_000);
    let mut c = base_contract(100);
    c.to_address = OWNER.to_vec(); // self
    let err = asset::validate_participate_asset_issue(&ctx.accounts, &ctx.v1, &ctx.dp, &c)
        .unwrap_err();
    assert!(matches!(err, ActuatorError::SelfTransfer), "got: {err:?}");
}

#[test]
fn rejects_non_positive_amount() {
    let ctx = ctx();
    put_owner(&ctx, 1_000_000);
    seed_issuer_with_asset(&ctx, 1, 10, 0, i64::MAX, 1_000_000);
    for amt in [0i64, -1, -100] {
        let c = base_contract(amt);
        let err = asset::validate_participate_asset_issue(&ctx.accounts, &ctx.v1, &ctx.dp, &c)
            .unwrap_err();
        assert!(
            matches!(err, ActuatorError::NonPositiveAmount),
            "amt={amt} got: {err:?}"
        );
    }
}

#[test]
fn rejects_missing_owner_account() {
    let ctx = ctx();
    seed_issuer_with_asset(&ctx, 1, 10, 0, i64::MAX, 1_000_000);
    let c = base_contract(100);
    let err = asset::validate_participate_asset_issue(&ctx.accounts, &ctx.v1, &ctx.dp, &c)
        .unwrap_err();
    assert!(matches!(err, ActuatorError::OwnerAccountMissing), "got: {err:?}");
}

#[test]
fn rejects_insufficient_balance() {
    let ctx = ctx();
    put_owner(&ctx, 10); // not enough
    seed_issuer_with_asset(&ctx, 1, 10, 0, i64::MAX, 1_000_000);
    let c = base_contract(100);
    let err = asset::validate_participate_asset_issue(&ctx.accounts, &ctx.v1, &ctx.dp, &c)
        .unwrap_err();
    assert!(
        matches!(
            err,
            ActuatorError::InsufficientBalance {
                balance: 10,
                needed: 100
            }
        ),
        "got: {err:?}"
    );
}

#[test]
fn rejects_unknown_asset_name() {
    let ctx = ctx();
    put_owner(&ctx, 1_000_000);
    // Don't seed asset.
    let c = base_contract(100);
    let err = asset::validate_participate_asset_issue(&ctx.accounts, &ctx.v1, &ctx.dp, &c)
        .unwrap_err();
    assert!(matches!(err, ActuatorError::AssetMissing), "got: {err:?}");
}

#[test]
fn rejects_to_address_not_matching_asset_owner() {
    let ctx = ctx();
    put_owner(&ctx, 1_000_000);
    seed_issuer_with_asset(&ctx, 1, 10, 0, i64::MAX, 1_000_000);
    let mut c = base_contract(100);
    let mut wrong_to = [0u8; 21];
    wrong_to[0] = 0x41;
    wrong_to[20] = 0x99;
    c.to_address = wrong_to.to_vec();
    let err = asset::validate_participate_asset_issue(&ctx.accounts, &ctx.v1, &ctx.dp, &c)
        .unwrap_err();
    assert!(
        matches!(err, ActuatorError::InvalidToAddress),
        "got: {err:?}"
    );
}

#[test]
fn rejects_before_asset_start_time() {
    let ctx = ctx();
    put_owner(&ctx, 1_000_000);
    seed_issuer_with_asset(&ctx, 1, 10, 1_000_000, 5_000_000, 1_000_000);
    ctx.dp.save_latest_block_header_timestamp(500_000); // before start
    let c = base_contract(100);
    let err = asset::validate_participate_asset_issue(&ctx.accounts, &ctx.v1, &ctx.dp, &c)
        .unwrap_err();
    assert!(
        matches!(err, ActuatorError::AssetIssueNotStarted),
        "got: {err:?}"
    );
}

#[test]
fn rejects_at_or_after_asset_end_time() {
    let ctx = ctx();
    put_owner(&ctx, 1_000_000);
    seed_issuer_with_asset(&ctx, 1, 10, 0, 5_000_000, 1_000_000);
    ctx.dp.save_latest_block_header_timestamp(5_000_000); // exactly end
    let c = base_contract(100);
    let err = asset::validate_participate_asset_issue(&ctx.accounts, &ctx.v1, &ctx.dp, &c)
        .unwrap_err();
    assert!(matches!(err, ActuatorError::AssetIssueEnded), "got: {err:?}");
    ctx.dp.save_latest_block_header_timestamp(6_000_000); // past end
    let err2 = asset::validate_participate_asset_issue(&ctx.accounts, &ctx.v1, &ctx.dp, &c)
        .unwrap_err();
    assert!(matches!(err2, ActuatorError::AssetIssueEnded));
}

#[test]
fn validate_passes_at_start_time_boundary() {
    let ctx = ctx();
    put_owner(&ctx, 1_000_000);
    seed_issuer_with_asset(&ctx, 1, 10, 1_000_000, 5_000_000, 1_000_000);
    ctx.dp.save_latest_block_header_timestamp(1_000_000); // exactly start
    let c = base_contract(100);
    asset::validate_participate_asset_issue(&ctx.accounts, &ctx.v1, &ctx.dp, &c).unwrap();
}

// ============================================================
// execute — math + state coherence
// ============================================================

#[test]
fn execute_swaps_trx_for_asset_at_configured_ratio() {
    let ctx = ctx();
    put_owner(&ctx, 1_000_000);
    // 1 TRX = 10 asset units (trx_num=1, num=10).
    seed_issuer_with_asset(&ctx, 1, 10, 0, i64::MAX, 1_000_000);
    let c = base_contract(100); // 100 sun -> 1000 asset units
    asset::validate_participate_asset_issue(&ctx.accounts, &ctx.v1, &ctx.dp, &c).unwrap();
    asset::execute_participate_asset_issue(&ctx.accounts, &ctx.v1, &c).unwrap();
    let owner = ctx.accounts.get(&addr(OWNER)).unwrap().unwrap();
    let issuer = ctx.accounts.get(&addr(ISSUER)).unwrap().unwrap();
    assert_eq!(owner.balance, 1_000_000 - 100);
    assert_eq!(issuer.balance, 100);
    assert_eq!(*owner.asset_v2.get("TestCoin").unwrap(), 1000);
    assert_eq!(*issuer.asset_v2.get("TestCoin").unwrap(), 1_000_000 - 1000);
}

#[test]
fn execute_rejects_when_exchange_amount_rounds_to_zero() {
    let ctx = ctx();
    put_owner(&ctx, 1_000_000);
    // 1000 TRX = 1 asset (trx_num=1000, num=1). 100 sun → floor(100*1/1000) = 0.
    seed_issuer_with_asset(&ctx, 1000, 1, 0, i64::MAX, 1_000_000);
    let c = base_contract(100);
    asset::validate_participate_asset_issue(&ctx.accounts, &ctx.v1, &ctx.dp, &c).unwrap();
    let err = asset::execute_participate_asset_issue(&ctx.accounts, &ctx.v1, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::Overflow), "got: {err:?}");
}

#[test]
fn execute_rejects_when_issuer_runs_out_of_asset() {
    let ctx = ctx();
    put_owner(&ctx, 1_000_000);
    // Issuer has tiny asset stock (1 unit), but ratio asks for many units.
    seed_issuer_with_asset(&ctx, 1, 1000, 0, i64::MAX, 1);
    let c = base_contract(100); // 100 sun * 1000 / 1 = 100_000 units, way more than 1.
    asset::validate_participate_asset_issue(&ctx.accounts, &ctx.v1, &ctx.dp, &c).unwrap();
    let err = asset::execute_participate_asset_issue(&ctx.accounts, &ctx.v1, &c).unwrap_err();
    // Either InsufficientAssetBalance or Overflow depending on path.
    assert!(
        matches!(
            err,
            ActuatorError::InsufficientAssetBalance { .. } | ActuatorError::Overflow
        ),
        "got: {err:?}"
    );
}

#[test]
fn execute_overflow_on_large_amount_extreme_ratio() {
    let ctx = ctx();
    put_owner(&ctx, i64::MAX);
    // num = i32::MAX, trx_num = 1 → exchange = amount * 2^31. For
    // amount near i64::MAX/2^31 this overflows the i64 output.
    seed_issuer_with_asset(&ctx, 1, i32::MAX, 0, i64::MAX, i64::MAX);
    let c = base_contract(1_000_000_000_000_i64); // 1 TT sun
    asset::validate_participate_asset_issue(&ctx.accounts, &ctx.v1, &ctx.dp, &c).unwrap();
    let err = asset::execute_participate_asset_issue(&ctx.accounts, &ctx.v1, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::Overflow), "got: {err:?}");
}

#[test]
fn execute_rejects_when_to_account_missing() {
    let ctx = ctx();
    put_owner(&ctx, 1_000_000);
    // Seed asset but NOT the issuer's account record.
    let asset_record = AssetIssueContract {
        id: "1000001".to_string(),
        owner_address: ISSUER.to_vec(),
        name: ASSET_NAME.to_vec(),
        trx_num: 1,
        num: 10,
        start_time: 0,
        end_time: i64::MAX,
        total_supply: 1_000_000_000,
        ..Default::default()
    };
    ctx.v1.put(ASSET_NAME, &asset_record).unwrap();
    let c = base_contract(100);
    // Validate passes (it doesn't load the to-account record).
    asset::validate_participate_asset_issue(&ctx.accounts, &ctx.v1, &ctx.dp, &c).unwrap();
    // Execute fails on missing target account.
    let err = asset::execute_participate_asset_issue(&ctx.accounts, &ctx.v1, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::TargetAccountMissing), "got: {err:?}");
}

#[test]
fn execute_chains_multiple_participates_correctly() {
    let ctx = ctx();
    put_owner(&ctx, 10_000_000);
    seed_issuer_with_asset(&ctx, 1, 5, 0, i64::MAX, 10_000_000);
    let c = base_contract(1000);
    for _ in 0..3 {
        asset::validate_participate_asset_issue(&ctx.accounts, &ctx.v1, &ctx.dp, &c).unwrap();
        asset::execute_participate_asset_issue(&ctx.accounts, &ctx.v1, &c).unwrap();
    }
    let owner = ctx.accounts.get(&addr(OWNER)).unwrap().unwrap();
    let issuer = ctx.accounts.get(&addr(ISSUER)).unwrap().unwrap();
    assert_eq!(owner.balance, 10_000_000 - 3 * 1000);
    assert_eq!(issuer.balance, 3 * 1000);
    // 3 × 1000 sun × 5/1 = 15_000 asset units total.
    assert_eq!(*owner.asset_v2.get("TestCoin").unwrap(), 3 * 5000);
    assert_eq!(
        *issuer.asset_v2.get("TestCoin").unwrap(),
        10_000_000 - 3 * 5000
    );
}
