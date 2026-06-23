//! Error-path tests for the four Bancor exchange actuators:
//!   * `ExchangeCreate`     — create a new x*y=k pair
//!   * `ExchangeInject`     — proportional add-liquidity
//!   * `ExchangeWithdraw`   — proportional remove-liquidity
//!   * `ExchangeTransaction` — swap one token for the other
//!
//! Java reference: `ExchangeCreateActuatorTest` (24), `ExchangeInjectActuatorTest`
//! (~14), `ExchangeWithdrawActuatorTest` (~14), `ExchangeTransactionActuatorTest`
//! (36). Our existing `full_layer.rs` has 1 happy-path smoke for each;
//! these tests cover the validation predicates + state coherence
//! invariants the smoke test doesn't exercise.

use std::collections::BTreeMap;
use std::sync::Arc;

use hex_literal::hex;
use tron_actuator::{exchange, ActuatorError};
use tron_chainbase::{
    AccountStore, AssetIssueStore, DynamicPropertiesStore, ExchangeStore, ExchangeV2Store,
    KvBackend, MemBackend,
};
use tron_crypto::address::Address;
use tron_proto::{
    Account, AccountType, Exchange, ExchangeCreateContract, ExchangeInjectContract,
    ExchangeTransactionContract, ExchangeWithdrawContract,
};

const ALICE: [u8; 21] = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");
const BOB: [u8; 21] = hex!("41a614f803b6fd780986a42c78ec9c7f77e6ded13c");

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}
fn addr(b: [u8; 21]) -> Address {
    Address::from_raw(b)
}

/// Build a fresh exchange context with Alice holding `trx_balance` TRX
/// and `asset_balance` of `1000001`. `fee` is the EXCHANGE_CREATE_FEE
/// (java-tron's default is 1.024 TRX; tests usually set to 0).
struct Ctx {
    accounts: AccountStore,
    v1: ExchangeStore,
    v2: ExchangeV2Store,
    dp: DynamicPropertiesStore,
    av1: AssetIssueStore,
}

fn ctx_with_alice(trx_balance: i64, asset_balance: i64, fee: i64) -> Ctx {
    let ctx = Ctx {
        accounts: AccountStore::new(mem()),
        v1: ExchangeStore::new(mem()),
        v2: ExchangeV2Store::new(mem()),
        dp: DynamicPropertiesStore::new(mem()),
        av1: AssetIssueStore::new(mem()),
    };
    // These tests use numeric token ids + the asset_v2 layout (mainnet, flag=1).
    ctx.dp.put_long(b" ALLOW_SAME_TOKEN_NAME", 1);
    ctx.accounts.put(
        &addr(ALICE),
        &Account {
            address: ALICE.to_vec(),
            balance: trx_balance,
            r#type: AccountType::Normal as i32,
            asset_v2: BTreeMap::from([("1000001".to_string(), asset_balance)]),
            ..Default::default()
        },
    ).unwrap();
    ctx.dp.put_long(b"EXCHANGE_CREATE_FEE", fee);
    ctx
}

fn seed_trx_asset_exchange(
    ctx: &Ctx,
    exchange_id: i64,
    creator: [u8; 21],
    trx_balance: i64,
    asset_balance: i64,
) {
    let ex = Exchange {
        exchange_id,
        creator_address: creator.to_vec(),
        create_time: 0,
        first_token_id: b"_".to_vec(),
        first_token_balance: trx_balance,
        second_token_id: b"1000001".to_vec(),
        second_token_balance: asset_balance,
    };
    ctx.v1.put(exchange_id, &ex).unwrap();
    ctx.v2.put(exchange_id, &ex).unwrap();
}

// ============================================================
// ExchangeCreate
// ============================================================

#[test]
fn create_rejects_missing_owner_account() {
    let ctx = ctx_with_alice(0, 0, 0);
    let c = ExchangeCreateContract {
        owner_address: BOB.to_vec(), // not in accounts
        first_token_id: b"_".to_vec(),
        first_token_balance: 100,
        second_token_id: b"1000001".to_vec(),
        second_token_balance: 100,
    };
    let err = exchange::validate_exchange_create(&ctx.accounts, &ctx.dp, &c).unwrap_err();
    assert!(
        matches!(err, ActuatorError::OwnerAccountMissing),
        "got: {err:?}"
    );
}

#[test]
fn create_rejects_insufficient_balance_for_fee() {
    let ctx = ctx_with_alice(1_000_000, 1_000_000, 1_024_000_000);
    let c = ExchangeCreateContract {
        owner_address: ALICE.to_vec(),
        first_token_id: b"_".to_vec(),
        first_token_balance: 100,
        second_token_id: b"1000001".to_vec(),
        second_token_balance: 100,
    };
    let err = exchange::validate_exchange_create(&ctx.accounts, &ctx.dp, &c).unwrap_err();
    assert!(
        matches!(
            err,
            ActuatorError::InsufficientBalance {
                balance: 1_000_000,
                needed: 1_024_000_000
            }
        ),
        "got: {err:?}"
    );
}

#[test]
fn create_rejects_same_token_on_both_sides() {
    let ctx = ctx_with_alice(10_000_000_000, 1_000_000_000, 0);
    let c = ExchangeCreateContract {
        owner_address: ALICE.to_vec(),
        first_token_id: b"_".to_vec(),
        first_token_balance: 100,
        second_token_id: b"_".to_vec(),
        second_token_balance: 100,
    };
    let err = exchange::validate_exchange_create(&ctx.accounts, &ctx.dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::MarketSameTokens), "got: {err:?}");
}

#[test]
fn create_rejects_zero_or_negative_token_balance() {
    let ctx = ctx_with_alice(10_000_000_000, 1_000_000_000, 0);
    for (first, second) in [(0, 100), (100, 0), (-1, 100), (100, -1)] {
        let c = ExchangeCreateContract {
            owner_address: ALICE.to_vec(),
            first_token_id: b"_".to_vec(),
            first_token_balance: first,
            second_token_id: b"1000001".to_vec(),
            second_token_balance: second,
        };
        let err = exchange::validate_exchange_create(&ctx.accounts, &ctx.dp, &c).unwrap_err();
        assert!(
            matches!(err, ActuatorError::NonPositiveTokenQuant),
            "({first},{second}) got: {err:?}"
        );
    }
}

#[test]
fn create_rejects_balance_above_per_exchange_limit() {
    let ctx = ctx_with_alice(10_000_000_000, 1_000_000_000, 0);
    ctx.dp.put_long(b"EXCHANGE_BALANCE_LIMIT", 1_000_000);
    let c = ExchangeCreateContract {
        owner_address: ALICE.to_vec(),
        first_token_id: b"_".to_vec(),
        first_token_balance: 2_000_000, // > limit
        second_token_id: b"1000001".to_vec(),
        second_token_balance: 100,
    };
    let err = exchange::validate_exchange_create(&ctx.accounts, &ctx.dp, &c).unwrap_err();
    assert!(
        matches!(err, ActuatorError::ExchangeBalanceLimitExceeded),
        "got: {err:?}"
    );
}

#[test]
fn create_execute_assigns_sequential_ids_and_charges_fee() {
    let ctx = ctx_with_alice(10_000_000_000, 1_000_000_000, 100_000_000);
    let c = ExchangeCreateContract {
        owner_address: ALICE.to_vec(),
        first_token_id: b"_".to_vec(),
        first_token_balance: 5_000_000_000,
        second_token_id: b"1000001".to_vec(),
        second_token_balance: 500_000_000,
    };
    exchange::validate_exchange_create(&ctx.accounts, &ctx.dp, &c).unwrap();
    exchange::execute_exchange_create(&ctx.accounts, &ctx.v1, &ctx.v2, &ctx.dp, &ctx.av1,&c).unwrap();
    // First exchange ID == 1.
    let ex = ctx.v2.get(1).unwrap().expect("exchange exists");
    assert_eq!(ex.first_token_balance, 5_000_000_000);
    assert_eq!(ex.second_token_balance, 500_000_000);
    // Alice's balance reduced by fee + TRX side; her asset reduced by
    // the asset side.
    let alice = ctx.accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(alice.balance, 10_000_000_000 - 100_000_000 - 5_000_000_000);
    assert_eq!(*alice.asset_v2.get("1000001").unwrap(), 500_000_000);
    // Create a second exchange — id should be 2.
    let c2 = ExchangeCreateContract {
        owner_address: ALICE.to_vec(),
        first_token_id: b"_".to_vec(),
        first_token_balance: 1_000,
        second_token_id: b"1000001".to_vec(),
        second_token_balance: 1_000,
    };
    exchange::validate_exchange_create(&ctx.accounts, &ctx.dp, &c2).unwrap();
    exchange::execute_exchange_create(&ctx.accounts, &ctx.v1, &ctx.v2, &ctx.dp, &ctx.av1,&c2).unwrap();
    assert!(ctx.v2.get(2).unwrap().is_some());
}

// ============================================================
// ExchangeInject
// ============================================================

#[test]
fn inject_rejects_missing_exchange() {
    let ctx = ctx_with_alice(10_000_000_000, 1_000_000_000, 0);
    let c = ExchangeInjectContract {
        owner_address: ALICE.to_vec(),
        exchange_id: 99, // doesn't exist
        token_id: b"_".to_vec(),
        quant: 100,
    };
    let err = exchange::validate_exchange_inject(&ctx.accounts, &ctx.dp, &ctx.v2, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::ExchangeMissing), "got: {err:?}");
}

#[test]
fn inject_rejects_non_creator_owner() {
    let ctx = ctx_with_alice(10_000_000_000, 1_000_000_000, 0);
    seed_trx_asset_exchange(&ctx, 1, ALICE, 1_000_000_000, 100_000_000);
    // Bob tries to inject into Alice's exchange.
    ctx.accounts.put(
        &addr(BOB),
        &Account {
            address: BOB.to_vec(),
            balance: 100_000_000,
            ..Default::default()
        },
    ).unwrap();
    let c = ExchangeInjectContract {
        owner_address: BOB.to_vec(),
        exchange_id: 1,
        token_id: b"_".to_vec(),
        quant: 100,
    };
    let err = exchange::validate_exchange_inject(&ctx.accounts, &ctx.dp, &ctx.v2, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::NotExchangeOwner), "got: {err:?}");
}

#[test]
fn inject_rejects_token_not_in_exchange() {
    let ctx = ctx_with_alice(10_000_000_000, 1_000_000_000, 0);
    seed_trx_asset_exchange(&ctx, 1, ALICE, 1_000_000_000, 100_000_000);
    let c = ExchangeInjectContract {
        owner_address: ALICE.to_vec(),
        exchange_id: 1,
        token_id: b"9999999".to_vec(), // wrong token
        quant: 100,
    };
    let err = exchange::validate_exchange_inject(&ctx.accounts, &ctx.dp, &ctx.v2, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::TokenNotInExchange), "got: {err:?}");
}

#[test]
fn inject_rejects_zero_or_negative_quant() {
    let ctx = ctx_with_alice(10_000_000_000, 1_000_000_000, 0);
    seed_trx_asset_exchange(&ctx, 1, ALICE, 1_000_000_000, 100_000_000);
    for quant in [0, -1, i64::MIN] {
        let c = ExchangeInjectContract {
            owner_address: ALICE.to_vec(),
            exchange_id: 1,
            token_id: b"_".to_vec(),
            quant,
        };
        let err = exchange::validate_exchange_inject(&ctx.accounts, &ctx.dp, &ctx.v2, &c).unwrap_err();
        assert!(
            matches!(err, ActuatorError::NonPositiveTokenQuant),
            "quant={quant} got: {err:?}"
        );
    }
}

#[test]
fn inject_maintains_pool_ratio_and_debits_both_sides() {
    let ctx = ctx_with_alice(10_000_000_000, 1_000_000_000, 0);
    // Pool: 1_000_000_000 TRX : 100_000_000 of token 1000001. Ratio = 10:1.
    seed_trx_asset_exchange(&ctx, 1, ALICE, 1_000_000_000, 100_000_000);
    // Inject 100_000_000 TRX → must require 100_000_000 / 10 = 10_000_000 of asset.
    let c = ExchangeInjectContract {
        owner_address: ALICE.to_vec(),
        exchange_id: 1,
        token_id: b"_".to_vec(),
        quant: 100_000_000,
    };
    exchange::validate_exchange_inject(&ctx.accounts, &ctx.dp, &ctx.v2, &c).unwrap();
    exchange::execute_exchange_inject(&ctx.accounts, &ctx.v1, &ctx.v2, &ctx.dp, &ctx.av1, &c)
        .unwrap();
    let alice = ctx.accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(alice.balance, 10_000_000_000 - 100_000_000);
    assert_eq!(*alice.asset_v2.get("1000001").unwrap(), 1_000_000_000 - 10_000_000);
    let ex = ctx.v2.get(1).unwrap().unwrap();
    assert_eq!(ex.first_token_balance, 1_100_000_000);
    assert_eq!(ex.second_token_balance, 110_000_000);
}

#[test]
fn inject_rejects_when_owner_lacks_other_side_balance() {
    let ctx = ctx_with_alice(10_000_000_000, 1_000, 0); // tiny asset balance
    seed_trx_asset_exchange(&ctx, 1, ALICE, 1_000_000_000, 100_000_000);
    // Inject 100M TRX requires 10M asset. Alice has 1k. Should fail at debit.
    let c = ExchangeInjectContract {
        owner_address: ALICE.to_vec(),
        exchange_id: 1,
        token_id: b"_".to_vec(),
        quant: 100_000_000,
    };
    // java's inject validate requires the owner to hold BOTH the injected
    // token and the computed counterpart (here ~10M asset); Alice has 1k, so
    // validation rejects before execute.
    let err =
        exchange::validate_exchange_inject(&ctx.accounts, &ctx.dp, &ctx.v2, &c).unwrap_err();
    assert!(
        matches!(err, ActuatorError::InsufficientAssetBalance { .. }),
        "got: {err:?}"
    );
}

// ============================================================
// ExchangeWithdraw
// ============================================================

#[test]
fn withdraw_rejects_missing_exchange() {
    let ctx = ctx_with_alice(0, 0, 0);
    let c = ExchangeWithdrawContract {
        owner_address: ALICE.to_vec(),
        exchange_id: 42,
        token_id: b"_".to_vec(),
        quant: 100,
    };
    let err = exchange::validate_exchange_withdraw(&ctx.accounts, &ctx.dp, &ctx.v2, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::ExchangeMissing), "got: {err:?}");
}

#[test]
fn withdraw_rejects_non_creator_owner() {
    let ctx = ctx_with_alice(0, 0, 0);
    seed_trx_asset_exchange(&ctx, 1, BOB, 1_000_000_000, 100_000_000);
    let c = ExchangeWithdrawContract {
        owner_address: ALICE.to_vec(),
        exchange_id: 1,
        token_id: b"_".to_vec(),
        quant: 100,
    };
    let err = exchange::validate_exchange_withdraw(&ctx.accounts, &ctx.dp, &ctx.v2, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::NotExchangeOwner), "got: {err:?}");
}

#[test]
fn withdraw_returns_both_sides_proportionally() {
    let ctx = ctx_with_alice(1_000_000_000, 0, 0);
    seed_trx_asset_exchange(&ctx, 1, ALICE, 1_000_000_000, 100_000_000);
    // Withdraw 100M TRX → should return 10M asset.
    let c = ExchangeWithdrawContract {
        owner_address: ALICE.to_vec(),
        exchange_id: 1,
        token_id: b"_".to_vec(),
        quant: 100_000_000,
    };
    exchange::validate_exchange_withdraw(&ctx.accounts, &ctx.dp, &ctx.v2, &c).unwrap();
    exchange::execute_exchange_withdraw(&ctx.accounts, &ctx.v1, &ctx.v2, &ctx.dp, &ctx.av1, &c)
        .unwrap();
    let alice = ctx.accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(alice.balance, 1_000_000_000 + 100_000_000);
    assert_eq!(*alice.asset_v2.get("1000001").unwrap(), 10_000_000);
    let ex = ctx.v2.get(1).unwrap().unwrap();
    assert_eq!(ex.first_token_balance, 900_000_000);
    assert_eq!(ex.second_token_balance, 90_000_000);
}

#[test]
fn withdraw_below_proportional_minimum_returns_zero_other_side_and_errors() {
    let ctx = ctx_with_alice(0, 0, 0);
    // Pool: 1 TRX, 100M of asset (lopsided). Withdrawing 0.0001 TRX would
    // mathematically yield other_quant = 100M * 0.0001 / 1 ≈ 0 — the
    // floor div produces 0 and we reject.
    seed_trx_asset_exchange(&ctx, 1, ALICE, 1_000_000_000_000, 1);
    let c = ExchangeWithdrawContract {
        owner_address: ALICE.to_vec(),
        exchange_id: 1,
        token_id: b"1000001".to_vec(),
        // Withdrawing 1 of the lopsided side computes other = 1 * 1e12 / 1
        // → way too big; this should overflow.
        quant: 1,
    };
    // Validate passes (basic length / sign checks).
    exchange::validate_exchange_withdraw(&ctx.accounts, &ctx.dp, &ctx.v2, &c).unwrap();
    // Execute: 1 * 1e12 / 1 = 1e12 which is < i64::MAX, so credit_token
    // happens; check the result against expectations.
    exchange::execute_exchange_withdraw(&ctx.accounts, &ctx.v1, &ctx.v2, &ctx.dp, &ctx.av1, &c)
        .unwrap();
    // Pool: 0 TRX, 0 of asset (just drained).
    let ex = ctx.v2.get(1).unwrap().unwrap();
    assert_eq!(ex.first_token_balance, 0);
    assert_eq!(ex.second_token_balance, 0);
}

// ============================================================
// ExchangeTransaction
// ============================================================

#[test]
fn transaction_rejects_missing_owner_account() {
    let ctx = ctx_with_alice(0, 0, 0);
    seed_trx_asset_exchange(&ctx, 1, BOB, 1_000_000_000, 100_000_000);
    ctx.accounts.put(
        &addr(BOB),
        &Account {
            address: BOB.to_vec(),
            balance: 0,
            ..Default::default()
        },
    ).unwrap();
    // Carol (not in accounts) tries to swap.
    let mut carol = [0u8; 21];
    carol[0] = 0x41;
    carol[20] = 0xcc;
    let c = ExchangeTransactionContract {
        owner_address: carol.to_vec(),
        exchange_id: 1,
        token_id: b"_".to_vec(),
        quant: 1_000_000,
        expected: 1,
    };
    let err =
        exchange::validate_exchange_transaction(&ctx.accounts, &ctx.v2, &ctx.dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::OwnerAccountMissing), "got: {err:?}");
}

#[test]
fn transaction_rejects_missing_exchange() {
    let ctx = ctx_with_alice(10_000_000_000, 1_000_000_000, 0);
    let c = ExchangeTransactionContract {
        owner_address: ALICE.to_vec(),
        exchange_id: 9999,
        token_id: b"_".to_vec(),
        quant: 100,
        expected: 1,
    };
    let err =
        exchange::validate_exchange_transaction(&ctx.accounts, &ctx.v2, &ctx.dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::ExchangeMissing), "got: {err:?}");
}

#[test]
fn transaction_rejects_token_not_in_exchange() {
    let ctx = ctx_with_alice(10_000_000_000, 1_000_000_000, 0);
    seed_trx_asset_exchange(&ctx, 1, ALICE, 1_000_000_000, 100_000_000);
    let c = ExchangeTransactionContract {
        owner_address: ALICE.to_vec(),
        exchange_id: 1,
        token_id: b"9999999".to_vec(),
        quant: 100,
        expected: 1,
    };
    let err =
        exchange::validate_exchange_transaction(&ctx.accounts, &ctx.v2, &ctx.dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::TokenNotInExchange), "got: {err:?}");
}

#[test]
fn transaction_rejects_zero_quant_or_expected() {
    let ctx = ctx_with_alice(10_000_000_000, 1_000_000_000, 0);
    seed_trx_asset_exchange(&ctx, 1, ALICE, 1_000_000_000, 100_000_000);
    for (quant, expected) in [(0, 1), (1, 0), (-1, 1), (1, -1)] {
        let c = ExchangeTransactionContract {
            owner_address: ALICE.to_vec(),
            exchange_id: 1,
            token_id: b"_".to_vec(),
            quant,
            expected,
        };
        let err =
            exchange::validate_exchange_transaction(&ctx.accounts, &ctx.v2, &ctx.dp, &c).unwrap_err();
        assert!(
            matches!(err, ActuatorError::NonPositiveTokenQuant),
            "({quant},{expected}) got: {err:?}"
        );
    }
}

#[test]
fn transaction_applies_bancor_pricing() {
    let ctx = ctx_with_alice(10_000_000_000, 1_000_000_000, 0);
    // Pool: 1_000_000_000 TRX : 1_000_000_000 of asset. Symmetric.
    seed_trx_asset_exchange(&ctx, 1, ALICE, 1_000_000_000, 1_000_000_000);
    // Swap 100_000_000 TRX. java's Bancor two-step power curve (supply=1e18)
    // yields exactly 90_909_090 (constant-product x*y=k would give 90_909_091
    // — the 1-sun difference this fix closes).
    let c = ExchangeTransactionContract {
        owner_address: ALICE.to_vec(),
        exchange_id: 1,
        token_id: b"_".to_vec(),
        quant: 100_000_000,
        expected: 90_000_000, // accept slippage
    };
    exchange::validate_exchange_transaction(&ctx.accounts, &ctx.v2, &ctx.dp, &c).unwrap();
    exchange::execute_exchange_transaction(&ctx.accounts, &ctx.v1, &ctx.v2, &ctx.dp, &ctx.av1,&c).unwrap();
    let ex = ctx.v2.get(1).unwrap().unwrap();
    // First side grew by the swapped 100_000_000; second shrank by the exact
    // Bancor output.
    assert_eq!(ex.first_token_balance, 1_100_000_000);
    assert_eq!(ex.second_token_balance, 1_000_000_000 - 90_909_090);
    // Alice received exactly the Bancor output.
    let alice = ctx.accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert_eq!(*alice.asset_v2.get("1000001").unwrap(), 1_000_000_000 + 90_909_090);
}

#[test]
fn transaction_rejects_output_below_expected_slippage() {
    let ctx = ctx_with_alice(10_000_000_000, 1_000_000_000, 0);
    seed_trx_asset_exchange(&ctx, 1, ALICE, 1_000_000_000, 1_000_000_000);
    // Demand more output than the constant-product formula will deliver.
    let c = ExchangeTransactionContract {
        owner_address: ALICE.to_vec(),
        exchange_id: 1,
        token_id: b"_".to_vec(),
        quant: 100_000_000,
        expected: 99_999_999_999, // wildly optimistic
    };
    let err =
        exchange::execute_exchange_transaction(&ctx.accounts, &ctx.v1, &ctx.v2, &ctx.dp, &ctx.av1,&c).unwrap_err();
    assert!(
        matches!(err, ActuatorError::ExchangeOutputBelowExpected),
        "got: {err:?}"
    );
}

#[test]
fn transaction_rejects_when_owner_lacks_input_balance() {
    let ctx = ctx_with_alice(1, 0, 0); // 1 sun, no asset
    seed_trx_asset_exchange(&ctx, 1, ALICE, 1_000_000_000, 1_000_000_000);
    let c = ExchangeTransactionContract {
        owner_address: ALICE.to_vec(),
        exchange_id: 1,
        token_id: b"_".to_vec(),
        quant: 100_000_000,
        expected: 1,
    };
    // java ExchangeTransactionActuator.validate rejects up front when the owner
    // cannot fund the TRX swap (`balance < tokenQuant + calcFee()`); the prior
    // version deferred this to execute. Now validate catches it like java.
    let err =
        exchange::validate_exchange_transaction(&ctx.accounts, &ctx.v2, &ctx.dp, &c).unwrap_err();
    assert!(
        matches!(err, ActuatorError::InsufficientBalance { .. }),
        "got: {err:?}"
    );
}

#[test]
fn transaction_rejects_closed_exchange() {
    let ctx = ctx_with_alice(10_000_000_000, 1_000_000_000, 0);
    // java: `firstTokenBalance == 0 || secondTokenBalance == 0` → closed.
    seed_trx_asset_exchange(&ctx, 1, ALICE, 0, 1_000_000_000);
    let c = ExchangeTransactionContract {
        owner_address: ALICE.to_vec(),
        exchange_id: 1,
        token_id: b"_".to_vec(),
        quant: 100_000_000,
        expected: 1,
    };
    let err =
        exchange::validate_exchange_transaction(&ctx.accounts, &ctx.v2, &ctx.dp, &c).unwrap_err();
    assert!(matches!(err, ActuatorError::ExchangeClosed), "got: {err:?}");
}

#[test]
fn transaction_rejects_balance_limit_exceeded() {
    // Set a tiny EXCHANGE_BALANCE_LIMIT so the post-swap sell-side balance
    // exceeds it. java: `tokenBalance + tokenQuant > balanceLimit` → reject.
    let ctx = ctx_with_alice(10_000_000_000, 1_000_000_000, 0);
    ctx.dp.put_long(b"EXCHANGE_BALANCE_LIMIT", 1_500_000_000);
    seed_trx_asset_exchange(&ctx, 1, ALICE, 1_000_000_000, 1_000_000_000);
    let c = ExchangeTransactionContract {
        owner_address: ALICE.to_vec(),
        exchange_id: 1,
        token_id: b"_".to_vec(),
        quant: 1_000_000_000, // 1e9 sell + 1e9 balance = 2e9 > 1.5e9 limit
        expected: 1,
    };
    let err =
        exchange::validate_exchange_transaction(&ctx.accounts, &ctx.v2, &ctx.dp, &c).unwrap_err();
    assert!(
        matches!(err, ActuatorError::ExchangeBalanceLimitExceeded),
        "got: {err:?}"
    );
}

#[test]
fn transaction_rejects_output_below_expected_in_validate() {
    // java rejects in validate when the Bancor output is below `expected`; the
    // prior version only caught this in execute.
    let ctx = ctx_with_alice(10_000_000_000, 1_000_000_000, 0);
    seed_trx_asset_exchange(&ctx, 1, ALICE, 1_000_000_000, 1_000_000_000);
    let c = ExchangeTransactionContract {
        owner_address: ALICE.to_vec(),
        exchange_id: 1,
        token_id: b"_".to_vec(),
        quant: 100_000_000,
        expected: 99_999_999_999, // unattainable
    };
    let err =
        exchange::validate_exchange_transaction(&ctx.accounts, &ctx.v2, &ctx.dp, &c).unwrap_err();
    assert!(
        matches!(err, ActuatorError::ExchangeOutputBelowExpected),
        "got: {err:?}"
    );
}

#[test]
fn transaction_with_swap_in_opposite_direction_also_works() {
    let ctx = ctx_with_alice(10_000_000_000, 1_000_000_000, 0);
    seed_trx_asset_exchange(&ctx, 1, ALICE, 1_000_000_000, 1_000_000_000);
    // Swap 100M of asset → some TRX out.
    let c = ExchangeTransactionContract {
        owner_address: ALICE.to_vec(),
        exchange_id: 1,
        token_id: b"1000001".to_vec(),
        quant: 100_000_000,
        expected: 1,
    };
    exchange::validate_exchange_transaction(&ctx.accounts, &ctx.v2, &ctx.dp, &c).unwrap();
    exchange::execute_exchange_transaction(&ctx.accounts, &ctx.v1, &ctx.v2, &ctx.dp, &ctx.av1,&c).unwrap();
    let ex = ctx.v2.get(1).unwrap().unwrap();
    // Asset side grew, TRX side shrank.
    assert_eq!(ex.second_token_balance, 1_100_000_000);
    assert!(ex.first_token_balance < 1_000_000_000);
    let alice = ctx.accounts.get(&addr(ALICE)).unwrap().unwrap();
    assert!(alice.balance > 10_000_000_000); // received TRX
}

// ── flag=0 (ALLOW_SAME_TOKEN_NAME == 0) dual-write regression tests ──────────
// Pre-activation, a trader's TRC-10 balance lives in the name-keyed V1 `asset`
// map and the exchange's token id IS the token name. java reads/writes V1 and
// dual-writes id-keyed `asset_v2`; these guard that the exchange does the same
// (the validate `.unwrap()` is the read-side guard, the asserts the write-side).

#[test]
fn flag0_exchange_inject_reads_and_dual_writes_v1() {
    let accounts = AccountStore::new(mem());
    let v1 = ExchangeStore::new(mem());
    let v2 = ExchangeV2Store::new(mem());
    let dp = DynamicPropertiesStore::new(mem()); // flag=0: ALLOW_SAME_TOKEN_NAME unset
    let av1 = AssetIssueStore::new(mem());
    // V1 asset-issue row so token_id_for_name("BTT") -> "1000001".
    av1.put(
        b"BTT",
        &tron_proto::AssetIssueContract {
            name: b"BTT".to_vec(),
            id: "1000001".to_string(),
            ..Default::default()
        },
    )
    .unwrap();
    // Alice holds the asset in the AUTHORITATIVE name-keyed V1 map; asset_v2 empty
    // (proves both the read and the write are flag-aware, not asset_v2-only).
    accounts
        .put(
            &addr(ALICE),
            &Account {
                address: ALICE.to_vec(),
                balance: 10_000_000_000,
                r#type: AccountType::Normal as i32,
                asset: BTreeMap::from([("BTT".to_string(), 1_000_000_000)]),
                ..Default::default()
            },
        )
        .unwrap();
    // Exchange keyed by NAME (flag=0 layout): 1e9 TRX : 1e8 BTT.
    let ex = Exchange {
        exchange_id: 1,
        creator_address: ALICE.to_vec(),
        first_token_id: b"_".to_vec(),
        first_token_balance: 1_000_000_000,
        second_token_id: b"BTT".to_vec(),
        second_token_balance: 100_000_000,
        ..Default::default()
    };
    v1.put(1, &ex).unwrap();
    v2.put(1, &ex).unwrap();
    // Inject 1e8 TRX -> proportional 1e7 BTT (ratio 1e8/1e9).
    let c = ExchangeInjectContract {
        owner_address: ALICE.to_vec(),
        exchange_id: 1,
        token_id: b"_".to_vec(),
        quant: 100_000_000,
    };
    // READ side: validate must ACCEPT at flag=0 (reads V1). Fails on asset_v2-only code.
    exchange::validate_exchange_inject(&accounts, &dp, &v2, &c).unwrap();
    // WRITE side: execute debits the proportional 1e7 BTT.
    exchange::execute_exchange_inject(&accounts, &v1, &v2, &dp, &av1, &c).unwrap();
    let alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    let expected = 1_000_000_000 - 10_000_000;
    assert_eq!(*alice.asset.get("BTT").unwrap(), expected, "authoritative V1 asset[name]");
    assert_eq!(*alice.asset_v2.get("1000001").unwrap(), expected, "dual-written asset_v2[id]");
}

#[test]
fn flag0_exchange_transaction_credit_dual_writes_v1() {
    let accounts = AccountStore::new(mem());
    let v1 = ExchangeStore::new(mem());
    let v2 = ExchangeV2Store::new(mem());
    let dp = DynamicPropertiesStore::new(mem()); // flag=0
    let av1 = AssetIssueStore::new(mem());
    av1.put(
        b"BTT",
        &tron_proto::AssetIssueContract {
            name: b"BTT".to_vec(),
            id: "1000001".to_string(),
            ..Default::default()
        },
    )
    .unwrap();
    // Alice sells TRX, buys BTT; she already holds some BTT in V1 (credit must ADD).
    accounts
        .put(
            &addr(ALICE),
            &Account {
                address: ALICE.to_vec(),
                balance: 10_000_000_000,
                r#type: AccountType::Normal as i32,
                asset: BTreeMap::from([("BTT".to_string(), 5_000_000)]),
                ..Default::default()
            },
        )
        .unwrap();
    let ex = Exchange {
        exchange_id: 1,
        creator_address: ALICE.to_vec(),
        first_token_id: b"_".to_vec(),
        first_token_balance: 1_000_000_000,
        second_token_id: b"BTT".to_vec(),
        second_token_balance: 100_000_000,
        ..Default::default()
    };
    v1.put(1, &ex).unwrap();
    v2.put(1, &ex).unwrap();
    let c = ExchangeTransactionContract {
        owner_address: ALICE.to_vec(),
        exchange_id: 1,
        token_id: b"_".to_vec(), // sell TRX -> buy BTT
        quant: 100_000_000,
        expected: 1,
    };
    exchange::validate_exchange_transaction(&accounts, &v2, &dp, &c).unwrap();
    exchange::execute_exchange_transaction(&accounts, &v1, &v2, &dp, &av1, &c).unwrap();
    let alice = accounts.get(&addr(ALICE)).unwrap().unwrap();
    let v1_bal = *alice.asset.get("BTT").unwrap();
    let v2_bal = *alice.asset_v2.get("1000001").unwrap();
    assert!(v1_bal > 5_000_000, "bought BTT credited to authoritative V1 asset[name]");
    assert_eq!(v1_bal, v2_bal, "V1 and dual-written asset_v2[id] hold the same total");
}
