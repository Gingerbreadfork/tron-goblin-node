//! Bancor exchange actuators: ExchangeCreate, ExchangeInject,
//! ExchangeWithdraw, ExchangeTransaction.
//!
//! Source: `ExchangeCreateActuator`, `ExchangeInjectActuator`,
//! `ExchangeWithdrawActuator`, `ExchangeTransactionActuator`.
//!
//! **Pricing**: ExchangeTransaction uses java's two-step Bancor power curve
//! over a fixed virtual supply (1e18), reproduced in
//! [`execute_exchange_transaction`]. The `pow` calls go through
//! [`tron_types::strict_math::pow`], which selects the bit-exact fdlibm
//! `StrictMath.pow` port when `ALLOW_STRICT_MATH` (proposal #87) is active and
//! `f64::powf` (== pre-#87 `Math.pow`) otherwise. Inject/withdraw use exact
//! integer (i128) ratio math.

use tron_chainbase::{
    AccountStore, AssetIssueStore, DynamicPropertiesStore, ExchangeStore, ExchangeV2Store,
};
use tron_proto::{
    Exchange, ExchangeCreateContract, ExchangeInjectContract, ExchangeTransactionContract,
    ExchangeWithdrawContract,
};

use tron_types::strict_math::pow;

use crate::helpers::{check_add, check_sub, require_owner};
use crate::transfer::ExecutionResult;
use crate::ActuatorError;

/// The "TRX" token id sentinel in exchange contexts. java-tron uses
/// `"_"` (single underscore) to mean "TRX, not an asset".
pub const TRX_TOKEN_ID: &[u8] = b"_";

// =============================================================================
// ExchangeCreateActuator
// =============================================================================

pub fn validate_exchange_create(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &ExchangeCreateContract,
) -> Result<(), ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    let fee = dyn_props.get_long(b"EXCHANGE_CREATE_FEE").unwrap_or(1_024_000_000);
    if account.balance < fee {
        return Err(ActuatorError::InsufficientBalance {
            balance: account.balance,
            needed: fee,
        });
    }
    // java ExchangeCreateActuator.validate (lines 44-50): at ALLOW_SAME_TOKEN_NAME
    // == 1 a non-TRX token id must be a valid numeric token id. The other three
    // exchange validates already enforce this; create was the omission.
    if dyn_props.allow_same_token_name().unwrap_or(0) == 1 {
        if contract.first_token_id.as_slice() != TRX_TOKEN_ID
            && !is_number(contract.first_token_id.as_slice())
        {
            return Err(ActuatorError::Validate("first token id is not a valid number"));
        }
        if contract.second_token_id.as_slice() != TRX_TOKEN_ID
            && !is_number(contract.second_token_id.as_slice())
        {
            return Err(ActuatorError::Validate("second token id is not a valid number"));
        }
    }
    if contract.first_token_id == contract.second_token_id {
        return Err(ActuatorError::MarketSameTokens);
    }
    if contract.first_token_balance <= 0 || contract.second_token_balance <= 0 {
        return Err(ActuatorError::NonPositiveTokenQuant);
    }
    let limit = dyn_props.exchange_balance_limit();
    if contract.first_token_balance > limit || contract.second_token_balance > limit {
        return Err(ActuatorError::ExchangeBalanceLimitExceeded);
    }
    // java ExchangeCreateActuator.validate (lines 66-82): the owner must hold
    // enough of each seeded side. A TRX side must cover its seed amount PLUS the
    // create fee; a token side checks the trader's TRC-10 balance flag-aware
    // (V1 `asset[name]` at flag=0, `asset_v2[id]` at flag=1 — java
    // `assetBalanceEnoughV2`). In-block creates are always funded, so this never
    // changes a replay outcome, but it brings the validate to java parity.
    for (token_id, token_balance) in [
        (contract.first_token_id.as_slice(), contract.first_token_balance),
        (contract.second_token_id.as_slice(), contract.second_token_balance),
    ] {
        if token_id == TRX_TOKEN_ID {
            let needed = token_balance.saturating_add(fee);
            if account.balance < needed {
                return Err(ActuatorError::InsufficientBalance { balance: account.balance, needed });
            }
        } else if !exchange_balance_enough(&account, dyn_props, token_id, token_balance) {
            return Err(ActuatorError::InsufficientAssetBalance {
                has: exchange_token_balance(&account, dyn_props, token_id),
                needs: token_balance,
            });
        }
    }
    Ok(())
}

pub fn execute_exchange_create(
    accounts: &AccountStore,
    v1: &ExchangeStore,
    v2: &ExchangeV2Store,
    dyn_props: &DynamicPropertiesStore,
    asset_v1: &AssetIssueStore,
    contract: &ExchangeCreateContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let mut account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    let fee = dyn_props.get_long(b"EXCHANGE_CREATE_FEE").unwrap_or(1_024_000_000);
    account.balance = check_sub(account.balance, fee)?;
    // java ExchangeCreateActuator: dispose the fee after debiting the owner —
    // burnTrx once supportBlackHoleOptimization is on, else credit the blackhole
    // account (the from-genesis arm).
    tron_chainbase::dispose_fee_to_blackhole(accounts, dyn_props, fee)?;

    // Debit owner's TRX or asset balance for each side.
    debit_exchange_token(
        &mut account,
        dyn_props,
        asset_v1,
        &contract.first_token_id,
        contract.first_token_balance,
    )?;
    debit_exchange_token(
        &mut account,
        dyn_props,
        asset_v1,
        &contract.second_token_id,
        contract.second_token_balance,
    )?;
    accounts.put(&owner, &account)?;

    let next_id = dyn_props
        .get_long(tron_chainbase::dynamic_properties_keys::LATEST_EXCHANGE_NUM)
        .unwrap_or(0)
        + 1;
    let exchange = Exchange {
        exchange_id: next_id,
        creator_address: owner.as_bytes().to_vec(),
        create_time: dyn_props.latest_block_header_timestamp().unwrap_or(0),
        first_token_id: contract.first_token_id.clone(),
        first_token_balance: contract.first_token_balance,
        second_token_id: contract.second_token_id.clone(),
        second_token_balance: contract.second_token_balance,
    };
    put_exchange_final(v1, v2, dyn_props, asset_v1, &exchange)?;
    dyn_props.put_long(
        tron_chainbase::dynamic_properties_keys::LATEST_EXCHANGE_NUM,
        next_id,
    );

    // java `ExchangeCreateActuator.execute` sets `ret.setExchangeId(id)`
    // (ExchangeCreateActuator.java:125) — the id of the new exchange.
    // Surfaced as TransactionInfo.exchange_id.
    Ok(ExecutionResult {
        fee,
        ret: crate::TransactionRetExtras {
            exchange_id: next_id,
            ..Default::default()
        },
        ..Default::default()
    })
}

// =============================================================================
// ExchangeInjectActuator
// =============================================================================

pub fn validate_exchange_inject(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    v1: &ExchangeStore,
    v2: &ExchangeV2Store,
    contract: &ExchangeInjectContract,
) -> Result<(), ActuatorError> {
    // java ExchangeInjectActuator.validate.
    let owner = require_owner(&contract.owner_address)?;
    let mut account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    // Merge an asset-optimized account's TRC-10 balances inline before the
    // owner-balance checks below, so they see the full balance java's
    // getAssetMapV2 reports (the transfer path does the same).
    tron_chainbase::import_all_asset(&mut account);
    // calcFee() == 0 for exchange inject; the fee balance check is a no-op.
    let exchange = read_exchange_final(v1, v2, dyn_props, contract.exchange_id)?;
    if exchange.creator_address != owner.as_bytes() {
        return Err(ActuatorError::NotExchangeOwner);
    }

    let first_token_id = &exchange.first_token_id;
    let second_token_id = &exchange.second_token_id;
    let first_token_balance = exchange.first_token_balance;
    let second_token_balance = exchange.second_token_balance;
    let token_id = &contract.token_id;
    let token_quant = contract.quant;

    // java: allowSameTokenName == 1 requires a non-TRX token id to be a valid
    // numeric token id.
    if dyn_props.allow_same_token_name().unwrap_or(0) == 1
        && token_id.as_slice() != TRX_TOKEN_ID
        && !is_number(token_id)
    {
        return Err(ActuatorError::Validate("token id is not a valid number"));
    }

    if token_id != first_token_id && token_id != second_token_id {
        return Err(ActuatorError::TokenNotInExchange);
    }

    // java: an exchange with a zero-balance side is closed.
    if first_token_balance == 0 || second_token_balance == 0 {
        return Err(ActuatorError::Validate(
            "Token balance in exchange is equal with 0,the exchange has been closed",
        ));
    }

    if token_quant <= 0 {
        return Err(ActuatorError::NonPositiveTokenQuant);
    }

    // java BigInteger: anotherTokenQuant = otherBalance * tokenQuant / tokenBalance
    // (exact integer division). `longValueExact()` throws on overflow, mapped to
    // our Overflow rejection.
    let (another_id, another_token_quant, new_token_balance, new_another_token_balance) =
        if token_id == first_token_id {
            let another = (second_token_balance as i128) * (token_quant as i128)
                / (first_token_balance as i128);
            (
                second_token_id,
                another,
                first_token_balance as i128 + token_quant as i128,
                second_token_balance as i128 + another,
            )
        } else {
            let another = (first_token_balance as i128) * (token_quant as i128)
                / (second_token_balance as i128);
            (
                first_token_id,
                another,
                second_token_balance as i128 + token_quant as i128,
                first_token_balance as i128 + another,
            )
        };
    if another_token_quant > i64::MAX as i128 || another_token_quant < i64::MIN as i128 {
        return Err(ActuatorError::Overflow);
    }
    let another_token_quant = another_token_quant as i64;

    if another_token_quant <= 0 {
        return Err(ActuatorError::NonPositiveTokenQuant);
    }

    let balance_limit = dyn_props
        .get_long(b"EXCHANGE_BALANCE_LIMIT")
        .unwrap_or(i64::MAX) as i128;
    if new_token_balance > balance_limit || new_another_token_balance > balance_limit {
        return Err(ActuatorError::ExchangeBalanceLimitExceeded);
    }

    // java: the owner must hold enough of both the injected token and the
    // computed counterpart token. For TRX the check includes calcFee() (== 0).
    if token_id.as_slice() == TRX_TOKEN_ID {
        if account.balance < token_quant {
            return Err(ActuatorError::InsufficientBalance {
                balance: account.balance,
                needed: token_quant,
            });
        }
    } else if !exchange_balance_enough(&account, dyn_props,token_id, token_quant) {
        return Err(ActuatorError::InsufficientAssetBalance {
            has: exchange_token_balance(&account, dyn_props,token_id),
            needs: token_quant,
        });
    }

    if another_id.as_slice() == TRX_TOKEN_ID {
        if account.balance < another_token_quant {
            return Err(ActuatorError::InsufficientBalance {
                balance: account.balance,
                needed: another_token_quant,
            });
        }
    } else if !exchange_balance_enough(&account, dyn_props,another_id, another_token_quant) {
        return Err(ActuatorError::InsufficientAssetBalance {
            has: exchange_token_balance(&account, dyn_props,another_id),
            needs: another_token_quant,
        });
    }

    Ok(())
}

pub fn execute_exchange_inject(
    accounts: &AccountStore,
    v1: &ExchangeStore,
    v2: &ExchangeV2Store,
    dyn_props: &DynamicPropertiesStore,
    asset_v1: &AssetIssueStore,
    contract: &ExchangeInjectContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    // java reads the authoritative store: V1 (name-bearing ids) at flag=0,
    // V2 (numeric ids) at flag=1 — `Commons.getExchangeStoreFinal`.
    let mut exchange = read_exchange_final(v1, v2, dyn_props, contract.exchange_id)?;

    let (my_balance, my_id, other_balance, other_id) =
        if contract.token_id == exchange.first_token_id {
            (
                exchange.first_token_balance,
                &exchange.first_token_id,
                exchange.second_token_balance,
                &exchange.second_token_id,
            )
        } else {
            (
                exchange.second_token_balance,
                &exchange.second_token_id,
                exchange.first_token_balance,
                &exchange.first_token_id,
            )
        };

    // java `ExchangeInjectActuator.execute` computes the paired amount via
    // `floorDiv(Math.multiplyExact(otherBalance, tokenQuant), thisBalance)`.
    // `multiplyExact` throws ArithmeticException when the i64 PRODUCT overflows
    // (> i64::MAX); execute()'s catch only handles ItemNotFound /
    // InvalidProtocolBuffer, so the exception propagates through processBlock
    // (no per-tx catch) and rejects the WHOLE block. java's validate uses
    // BigInteger and bounds only the QUOTIENT (always <= i64 given
    // EXCHANGE_BALANCE_LIMIT), so it passes — reproduce the i64-product
    // rejection HERE in execute, not validate. Not reachable on honest
    // canonical replay (java never commits such a block); this is
    // block-production / adversarial-block fidelity.
    if other_balance.checked_mul(contract.quant).is_none() {
        return Err(ActuatorError::Overflow);
    }
    // Maintain ratio: new_other = floor(other * quant / my_balance).
    let other_quant = (other_balance as i128) * (contract.quant as i128) / (my_balance as i128);
    if other_quant <= 0 || other_quant > i64::MAX as i128 {
        return Err(ActuatorError::Overflow);
    }
    let other_quant = other_quant as i64;

    let my_id = my_id.clone();
    let other_id = other_id.clone();

    let mut account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    debit_exchange_token(&mut account, dyn_props, asset_v1, &my_id, contract.quant)?;
    debit_exchange_token(&mut account, dyn_props, asset_v1, &other_id, other_quant)?;
    accounts.put(&owner, &account)?;

    if contract.token_id == exchange.first_token_id {
        exchange.first_token_balance = check_add(exchange.first_token_balance, contract.quant)?;
        exchange.second_token_balance = check_add(exchange.second_token_balance, other_quant)?;
    } else {
        exchange.second_token_balance = check_add(exchange.second_token_balance, contract.quant)?;
        exchange.first_token_balance = check_add(exchange.first_token_balance, other_quant)?;
    }
    put_exchange_final(v1, v2, dyn_props, asset_v1, &exchange)?;

    // java `ExchangeInjectActuator.execute` sets
    // `ret.setExchangeInjectAnotherAmount(anotherTokenQuant)`
    // (ExchangeInjectActuator.java:106) — the paired other-token amount
    // injected. It does NOT set exchangeId. Surfaced as
    // TransactionInfo.exchange_inject_another_amount.
    Ok(ExecutionResult {
        ret: crate::TransactionRetExtras {
            exchange_inject_another_amount: other_quant,
            ..Default::default()
        },
        ..Default::default()
    })
}

// =============================================================================
// ExchangeWithdrawActuator
// =============================================================================

pub fn validate_exchange_withdraw(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    v1: &ExchangeStore,
    v2: &ExchangeV2Store,
    contract: &ExchangeWithdrawContract,
) -> Result<(), ActuatorError> {
    // java ExchangeWithdrawActuator.validate.
    let owner = require_owner(&contract.owner_address)?;
    if accounts.get(&owner)?.is_none() {
        return Err(ActuatorError::OwnerAccountMissing);
    }
    // calcFee() == 0 for exchange withdraw; the fee balance check is a no-op.
    let exchange = read_exchange_final(v1, v2, dyn_props, contract.exchange_id)?;
    if exchange.creator_address != owner.as_bytes() {
        return Err(ActuatorError::NotExchangeOwner);
    }

    let first_token_id = &exchange.first_token_id;
    let second_token_id = &exchange.second_token_id;
    let first_token_balance = exchange.first_token_balance;
    let second_token_balance = exchange.second_token_balance;
    let token_id = &contract.token_id;
    let token_quant = contract.quant;

    // java: allowSameTokenName == 1 requires a non-TRX token id to be a valid
    // numeric token id.
    if dyn_props.allow_same_token_name().unwrap_or(0) == 1
        && token_id.as_slice() != TRX_TOKEN_ID
        && !is_number(token_id)
    {
        return Err(ActuatorError::Validate("token id is not a valid number"));
    }

    if token_id != first_token_id && token_id != second_token_id {
        return Err(ActuatorError::TokenNotInExchange);
    }

    if token_quant <= 0 {
        return Err(ActuatorError::NonPositiveTokenQuant);
    }

    // java: an exchange with a zero-balance side is closed.
    if first_token_balance == 0 || second_token_balance == 0 {
        return Err(ActuatorError::Validate(
            "Token balance in exchange is equal with 0,the exchange has been closed",
        ));
    }

    // java BigDecimal.divideToIntegralValue: anotherTokenQuant is the integer
    // part of otherBalance * tokenQuant / tokenBalance (truncated toward zero;
    // operands are non-negative here). `longValueExact()` throws on overflow,
    // mapped to our Overflow rejection.
    let (token_balance, other_balance) = if token_id == first_token_id {
        (first_token_balance, second_token_balance)
    } else {
        (second_token_balance, first_token_balance)
    };
    let another_token_quant =
        (other_balance as i128) * (token_quant as i128) / (token_balance as i128);
    if another_token_quant > i64::MAX as i128 || another_token_quant < i64::MIN as i128 {
        return Err(ActuatorError::Overflow);
    }
    let another_token_quant = another_token_quant as i64;

    // java: the withdrawn side and its counterpart cannot exceed the pool
    // balances.
    if token_balance < token_quant || other_balance < another_token_quant {
        return Err(ActuatorError::Validate("exchange balance is not enough"));
    }

    if another_token_quant <= 0 {
        return Err(ActuatorError::NonPositiveTokenQuant);
    }

    // java "Not precise enough": the scale-4 HALF_UP rational quotient must be
    // within 0.0001 (one-sided) of the truncated integer quotient.
    //   remainder = round_half_up(otherBalance * tokenQuant / tokenBalance, 4)
    //               - anotherTokenQuant
    //   reject if remainder / anotherTokenQuant > 0.0001
    if dyn_props.allow_harden_exchange_calculation() {
        // TIP-836 (#98): the same comparison in exact BigDecimal arithmetic.
        // `remainder` is the scale-4 fraction, so `remainder > quant * 0.0001`
        // is `fraction_1e4 > quant`.
        let fraction = scale4_fraction_half_up(
            other_balance as i128 * token_quant as i128,
            token_balance as i128,
        );
        if fraction > another_token_quant as i128 {
            return Err(ActuatorError::Validate("Not precise enough"));
        }
        return Ok(());
    }
    let rounded4 = div_round_half_up_scale4(
        other_balance as i128 * token_quant as i128,
        token_balance as i128,
    );
    let remainder = rounded4 - another_token_quant as f64;
    if remainder / another_token_quant as f64 > 0.0001 {
        return Err(ActuatorError::Validate("Not precise enough"));
    }

    Ok(())
}

pub fn execute_exchange_withdraw(
    accounts: &AccountStore,
    v1: &ExchangeStore,
    v2: &ExchangeV2Store,
    dyn_props: &DynamicPropertiesStore,
    asset_v1: &AssetIssueStore,
    contract: &ExchangeWithdrawContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let mut exchange = read_exchange_final(v1, v2, dyn_props, contract.exchange_id)?;

    let (my_balance, my_id, other_balance, other_id) =
        if contract.token_id == exchange.first_token_id {
            (
                exchange.first_token_balance,
                &exchange.first_token_id,
                exchange.second_token_balance,
                &exchange.second_token_id,
            )
        } else {
            (
                exchange.second_token_balance,
                &exchange.second_token_id,
                exchange.first_token_balance,
                &exchange.first_token_id,
            )
        };

    let other_quant = (other_balance as i128) * (contract.quant as i128) / (my_balance as i128);
    if other_quant <= 0 || other_quant > i64::MAX as i128 {
        return Err(ActuatorError::Overflow);
    }
    let other_quant = other_quant as i64;
    let my_id = my_id.clone();
    let other_id = other_id.clone();

    let mut account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    credit_exchange_token(&mut account, dyn_props, asset_v1, &my_id, contract.quant)?;
    credit_exchange_token(&mut account, dyn_props, asset_v1, &other_id, other_quant)?;
    accounts.put(&owner, &account)?;

    if contract.token_id == exchange.first_token_id {
        exchange.first_token_balance = check_sub(exchange.first_token_balance, contract.quant)?;
        exchange.second_token_balance = check_sub(exchange.second_token_balance, other_quant)?;
    } else {
        exchange.second_token_balance = check_sub(exchange.second_token_balance, contract.quant)?;
        exchange.first_token_balance = check_sub(exchange.first_token_balance, other_quant)?;
    }
    put_exchange_final(v1, v2, dyn_props, asset_v1, &exchange)?;

    // java `ExchangeWithdrawActuator.execute` sets
    // `ret.setExchangeWithdrawAnotherAmount(anotherTokenQuant)`
    // (ExchangeWithdrawActuator.java:111) — the paired other-token amount
    // withdrawn. It does NOT set exchangeId. Surfaced as
    // TransactionInfo.exchange_withdraw_another_amount.
    Ok(ExecutionResult {
        ret: crate::TransactionRetExtras {
            exchange_withdraw_another_amount: other_quant,
            ..Default::default()
        },
        ..Default::default()
    })
}

// =============================================================================
// ExchangeTransactionActuator
// =============================================================================

pub fn validate_exchange_transaction(
    accounts: &AccountStore,
    v1: &ExchangeStore,
    v2: &ExchangeV2Store,
    dyn_props: &DynamicPropertiesStore,
    contract: &ExchangeTransactionContract,
) -> Result<(), ActuatorError> {
    // Ported from java ExchangeTransactionActuator.validate, in java's exact
    // order so the first failing check fires the same rejection java records.
    // The fee is 0 here, so java's `balance < calcFee()` and TRX-fee guards are
    // inert; the substantive divergence is the closed-exchange and
    // balance-limit checks, which our execute-only path could not catch
    // (java rejects at validate → recorded contractRet FAILED, not SUCCESS).
    //
    // java `Manager.rejectExchangeTransaction` (1886-1891): once VERSION_4_8_0_1
    // is active, the Bancor swap (ExchangeTransactionContract ONLY — create /
    // inject / withdraw stay enabled) is permanently DISABLED. java's gate fires
    // in the mempool/producer path AND processBlock's per-tx loop (no per-tx
    // catch → the whole block is rejected). Not reachable on honest canonical
    // replay (post-fork blocks carry no swap, so this never fires there); it is
    // block-production / adversarial-block validity. Gate on VERSION_4_8_0_1's
    // hardForkTime (2020-08-07); the real 80%-witness activation lands a few
    // maintenance cycles later — exact awaits the ForkController (audit
    // coverage-gap #1). [Adversarial-block fidelity: java rejects the WHOLE
    // block; here only the tx is rejected — moot on honest replay.]
    // java `Manager.isExchangeTransaction` (4.8.2): the swap ban lifts once
    // ALLOW_HARDEN_EXCHANGE_CALCULATION (#98) is set — the swap then runs on
    // the hardened `SafeExchangeProcessor`. Before that, VERSION_4_8_0_1
    // permanently rejects it.
    const VERSION_4_8_0_1_HARD_FORK_TIME_MS: i64 = 1_596_780_000_000;
    if !dyn_props.allow_harden_exchange_calculation()
        && dyn_props.latest_block_header_timestamp().unwrap_or(0) >= VERSION_4_8_0_1_HARD_FORK_TIME_MS
    {
        return Err(ActuatorError::Validate(
            "exchange transaction is forbidden once VERSION_4_8_0_1 is active",
        ));
    }
    let owner = require_owner(&contract.owner_address)?;
    let account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;

    let exchange = read_exchange_final(v1, v2, dyn_props, contract.exchange_id)?;

    let token_id = &contract.token_id;
    let token_quant = contract.quant;
    let token_expected = contract.expected;

    // java: allowSameTokenName==1 && tokenID != "_" && !isNumber(tokenID) →
    // "token id is not a valid number". TRX is the "_" sentinel.
    if dyn_props.allow_same_token_name().unwrap_or(0) == 1
        && token_id.as_slice() != TRX_TOKEN_ID
        && !is_number(token_id)
    {
        return Err(ActuatorError::MarketInvalidTokenId);
    }

    // token is one of the pair.
    if token_id != &exchange.first_token_id && token_id != &exchange.second_token_id {
        return Err(ActuatorError::TokenNotInExchange);
    }
    if token_quant <= 0 {
        return Err(ActuatorError::NonPositiveTokenQuant);
    }
    if token_expected <= 0 {
        return Err(ActuatorError::NonPositiveTokenQuant);
    }

    // Closed exchange: either side at zero balance.
    if exchange.first_token_balance == 0 || exchange.second_token_balance == 0 {
        return Err(ActuatorError::ExchangeClosed);
    }

    // Balance limit: the SELL side's balance after adding `token_quant` must
    // not exceed EXCHANGE_BALANCE_LIMIT (1e15 at genesis).
    let balance_limit = dyn_props.exchange_balance_limit();
    let sell_balance = if token_id == &exchange.first_token_id {
        exchange.first_token_balance
    } else {
        exchange.second_token_balance
    };
    let token_balance = sell_balance.wrapping_add(token_quant);
    if token_balance > balance_limit {
        return Err(ActuatorError::ExchangeBalanceLimitExceeded);
    }

    // Owner balance/asset sufficiency. For TRX (the "_" sentinel) java checks
    // `balance < tokenQuant + calcFee()`; calcFee() is 0.
    if token_id.as_slice() == TRX_TOKEN_ID {
        let needed = token_quant.wrapping_add(0); // + calcFee()
        if account.balance < needed {
            return Err(ActuatorError::InsufficientBalance {
                balance: account.balance,
                needed,
            });
        }
    } else {
        let mut acct = account.clone();
        tron_chainbase::import_all_asset(&mut acct);
        if !exchange_balance_enough(&acct, dyn_props, token_id, token_quant) {
            return Err(ActuatorError::InsufficientAssetBalance {
                has: exchange_token_balance(&acct, dyn_props, token_id),
                needs: token_quant,
            });
        }
    }

    // java: anotherTokenQuant = exchangeCapsule.transaction(tokenID, tokenQuant)
    // and reject when it is below `tokenExpected`. Mirror the Bancor curve
    // exactly via the shared helper so validate and execute never drift.
    let (sell_balance_before, buy_balance_before) = if token_id == &exchange.first_token_id {
        (exchange.first_token_balance, exchange.second_token_balance)
    } else {
        (exchange.second_token_balance, exchange.first_token_balance)
    };
    let another_token_quant =
        exchange_swap(dyn_props, sell_balance_before, buy_balance_before, token_quant)?;
    if another_token_quant < token_expected {
        return Err(ActuatorError::ExchangeOutputBelowExpected);
    }
    Ok(())
}

const EXCHANGE_SUPPLY: i128 = 1_000_000_000_000_000_000;

/// The buy-token amount for a swap, plus the swapped pool balances, matching
/// java `ExchangeCapsule.transaction`. Under `ALLOW_HARDEN_EXCHANGE_CALCULATION`
/// (#98) it runs `SafeExchangeProcessor` and applies java's `addExact` /
/// `subtractExact` + non-negative-balance guard; otherwise the legacy
/// `ExchangeProcessor`. Shared by validate and execute so they cannot diverge.
fn exchange_swap(
    dyn_props: &DynamicPropertiesStore,
    sell_balance_before: i64,
    buy_balance_before: i64,
    sell_quant: i64,
) -> Result<i64, ActuatorError> {
    if !dyn_props.allow_harden_exchange_calculation() {
        return Ok(exchange_transaction_output(
            sell_balance_before,
            buy_balance_before,
            sell_quant,
            dyn_props.allow_strict_math(),
        ));
    }
    let output = safe_exchange(sell_balance_before, buy_balance_before, sell_quant)?;
    // java: newSell = addExact(sell, quant); newBuy = subtractExact(buy, output);
    // then reject if either is negative.
    let new_sell = sell_balance_before
        .checked_add(sell_quant)
        .ok_or(ActuatorError::Overflow)?;
    let new_buy = buy_balance_before
        .checked_sub(output)
        .ok_or(ActuatorError::Overflow)?;
    if new_sell < 0 || new_buy < 0 {
        return Err(ActuatorError::Validate(
            "Exchange balance must be >=0 after transaction",
        ));
    }
    Ok(output)
}

/// Test hook for the JDK8 differential fixtures.
#[doc(hidden)]
pub fn safe_exchange_for_test(
    sell_balance: i64,
    buy_balance: i64,
    sell_quant: i64,
) -> Result<i64, ActuatorError> {
    safe_exchange(sell_balance, buy_balance, sell_quant)
}

/// java `SafeExchangeProcessor.exchange` — the two-step Bancor curve in exact
/// `BigDecimal` (scale-18 HALF_UP) with `StrictMath.pow`.
fn safe_exchange(
    sell_balance: i64,
    buy_balance: i64,
    sell_quant: i64,
) -> Result<i64, ActuatorError> {
    let relay = safe_exchange_to_supply(sell_balance, sell_quant)?;
    safe_exchange_from_supply(buy_balance, relay)
}

/// java `SafeExchangeProcessor.exchangeToSupply`:
/// `-SUPPLY * (1 - StrictMath.pow(1 + quant/newBalance, 0.0005))`, `setScale(0,
/// DOWN)`. Returns the (non-negative, integer-valued) relay amount.
fn safe_exchange_to_supply(balance: i64, quant: i64) -> Result<i128, ActuatorError> {
    let new_balance = balance.checked_add(quant).ok_or(ActuatorError::Overflow)?;
    if new_balance <= 0 {
        return Err(ActuatorError::Overflow);
    }
    // BigDecimal.valueOf(quant).divide(valueOf(newBalance), 18, HALF_UP).
    let q18 = div_round_half_up((quant as i128) * EXCHANGE_SUPPLY, new_balance as i128);
    let base = one_plus_ratio_1e18_as_f64(q18);
    let pow = tron_types::strict_math::strict_pow(base, 0.0005);
    // -SUPPLY * (1 - D(pow)) = SUPPLY * (D(pow) - 1), truncated toward zero.
    Ok(scale_times_decimal_minus_one(EXCHANGE_SUPPLY, pow))
}

/// java `SafeExchangeProcessor.exchangeFromSupply`:
/// `balance * (StrictMath.pow(1 + supplyQuant/SUPPLY, 2000) - 1)`, `setScale(0,
/// DOWN).longValueExact()`.
fn safe_exchange_from_supply(balance: i64, supply_quant: i128) -> Result<i64, ActuatorError> {
    // supplyQuant/SUPPLY at scale 18 is exact (SUPPLY == 1e18), so q18 == supplyQuant.
    let base = one_plus_ratio_1e18_as_f64(supply_quant);
    let pow = tron_types::strict_math::strict_pow(base, 2000.0);
    let out = scale_times_decimal_minus_one(balance as i128, pow);
    if out > i64::MAX as i128 || out < i64::MIN as i128 {
        return Err(ActuatorError::Overflow);
    }
    Ok(out as i64)
}

/// `floor((num + den/2) / den)` for non-negative operands — java
/// `BigDecimal.divide(_, HALF_UP)`.
fn div_round_half_up(num: i128, den: i128) -> i128 {
    let q = num / den;
    let r = num % den;
    if 2 * r >= den {
        q + 1
    } else {
        q
    }
}

/// The exact `f64` value of `1 + q18 / 1e18` for `q18 in [0, 1e18]`, matching
/// java `BigDecimal(1 + q18/1e18, scale 18).doubleValue()`. The result lies in
/// `(1, 2]`, so its mantissa is `round_half_even(q18 * 2^52 / 1e18)`.
fn one_plus_ratio_1e18_as_f64(q18: i128) -> f64 {
    debug_assert!((0..=EXCHANGE_SUPPLY).contains(&q18));
    let scaled = q18 << 52;
    let den = EXCHANGE_SUPPLY;
    let q = scaled / den;
    let r = scaled % den;
    // round half to even
    let m = if 2 * r > den || (2 * r == den && (q & 1) == 1) {
        q + 1
    } else {
        q
    };
    if m >= (1i128 << 52) {
        2.0
    } else {
        1.0 + (m as f64) / ((1u64 << 52) as f64)
    }
}

/// `scale * (D(x) - 1)` truncated toward zero, where `D(x)` is the decimal of
/// java `BigDecimal.valueOf(x)` (see [`crate::jdk_dtoa`]). `x >= 1`, so
/// `D(x) - 1 >= 0` and truncation toward zero equals a floor.
fn scale_times_decimal_minus_one(scale: i128, x: f64) -> i128 {
    let (mant, k) = crate::jdk_dtoa::to_decimal(x);
    let ten_k = pow10_i128(k);
    // scale * (mant - 10^k) / 10^k, truncating toward zero.
    (scale * (mant - ten_k)) / ten_k
}

fn pow10_i128(k: u32) -> i128 {
    let mut v: i128 = 1;
    for _ in 0..k {
        v *= 10;
    }
    v
}

/// java `ExchangeCapsule.transaction` / `ExchangeProcessor.exchange`: the
/// two-step Bancor power curve over a fixed virtual supply (1e18), returning the
/// amount of the *buy* token received for `sell_quant` of the *sell* token.
/// Shared by validate and execute so they cannot diverge. See
/// [`execute_exchange_transaction`] for the arithmetic-fidelity notes.
fn exchange_transaction_output(
    sell_balance_before: i64,
    buy_balance_before: i64,
    sell_quant: i64,
    use_strict_math: bool,
) -> i64 {
    let mut supply: i64 = 1_000_000_000_000_000_000;
    let new_balance = sell_balance_before.wrapping_add(sell_quant) as f64;
    let issued = -(supply as f64)
        * (1.0 - pow(1.0 + sell_quant as f64 / new_balance, 0.0005, use_strict_math));
    let relay = issued as i64;
    supply = supply.wrapping_add(relay);
    supply = supply.wrapping_sub(relay);
    let exchange_balance = buy_balance_before as f64
        * (pow(1.0 + relay as f64 / supply as f64, 2000.0, use_strict_math) - 1.0);
    exchange_balance as i64
}

pub fn execute_exchange_transaction(
    accounts: &AccountStore,
    v1: &ExchangeStore,
    v2: &ExchangeV2Store,
    dyn_props: &DynamicPropertiesStore,
    asset_v1: &AssetIssueStore,
    contract: &ExchangeTransactionContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let mut exchange = read_exchange_final(v1, v2, dyn_props, contract.exchange_id)?;

    let (my_balance_before, my_id, other_balance_before, other_id) =
        if contract.token_id == exchange.first_token_id {
            (
                exchange.first_token_balance,
                exchange.first_token_id.clone(),
                exchange.second_token_balance,
                exchange.second_token_id.clone(),
            )
        } else {
            (
                exchange.second_token_balance,
                exchange.second_token_id.clone(),
                exchange.first_token_balance,
                exchange.first_token_id.clone(),
            )
        };

    // java `ExchangeCapsule.transaction` / `ExchangeProcessor.exchange`: a
    // two-step Bancor power curve over a fixed virtual supply, NOT constant
    // product. `supply` is a long (so the `+= relay; -= relay` round-trip is
    // exact and the step-2 denominator is exactly the original supply), and
    // both `pow` results truncate toward zero via the `(long)` cast (`as i64`).
    // The `+ quant` and supply steps use wrapping i64 arithmetic to mirror
    // java's `long` overflow. java's `Maths.pow` selects `StrictMath.pow`
    // (fdlibm) over `Math.pow` on `allowStrictMath` (proposal 87); the `pow`
    // helper mirrors that — `strict_pow` (bit-exact fdlibm) when the flag is on,
    // `f64::powf` (== pre-87 `Math.pow`) when off.
    let output = exchange_swap(dyn_props, my_balance_before, other_balance_before, contract.quant)?;
    if output < contract.expected {
        return Err(ActuatorError::ExchangeOutputBelowExpected);
    }

    let mut account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    debit_exchange_token(&mut account, dyn_props, asset_v1, &my_id, contract.quant)?;
    credit_exchange_token(&mut account, dyn_props, asset_v1, &other_id, output)?;
    accounts.put(&owner, &account)?;

    if contract.token_id == exchange.first_token_id {
        exchange.first_token_balance = check_add(exchange.first_token_balance, contract.quant)?;
        exchange.second_token_balance = check_sub(exchange.second_token_balance, output)?;
    } else {
        exchange.second_token_balance = check_add(exchange.second_token_balance, contract.quant)?;
        exchange.first_token_balance = check_sub(exchange.first_token_balance, output)?;
    }
    put_exchange_final(v1, v2, dyn_props, asset_v1, &exchange)?;

    // java `ExchangeTransactionActuator.execute` sets
    // `ret.setExchangeReceivedAmount(anotherTokenQuant)`
    // (ExchangeTransactionActuator.java:99) — the other-token amount received
    // from the swap (`output` here). Surfaced as
    // TransactionInfo.exchange_received_amount.
    Ok(ExecutionResult {
        ret: crate::TransactionRetExtras {
            exchange_received_amount: output,
            ..Default::default()
        },
        ..Default::default()
    })
}

// =============================================================================
// Helpers
// =============================================================================

/// Build the V2-store copy of an exchange capsule, mirroring java
/// `Commons.putExchangeCapsule` + `ExchangeCapsule.resetTokenWithID`. At
/// `ALLOW_SAME_TOKEN_NAME == 0` java's V1 store holds the name-bearing token ids
/// while its V2 store holds the *numeric* token ids (each non-TRX name resolved
/// via `assetIssueStore.get(name).getId()`), so that the V2 view is already
/// correct for the eventual flag flip. At flag == 1 the capsule already carries
/// numeric ids, so the V2 copy is identical to the V1 copy. Pre-activation
/// exchanges created/updated by a from-genesis sync would otherwise store
/// name-bearing ids in V2, which java never does — diverging post-activation
/// when reads switch to V2 and `token_id` comparisons no longer match.
fn exchange_v2_copy(
    exchange: &Exchange,
    dyn_props: &DynamicPropertiesStore,
    asset_v1: &AssetIssueStore,
) -> Result<Exchange, ActuatorError> {
    if dyn_props.allow_same_token_name().unwrap_or(0) != 0 {
        return Ok(exchange.clone());
    }
    let reset = |token_id: &[u8]| -> Result<Vec<u8>, ActuatorError> {
        if token_id == TRX_TOKEN_ID {
            return Ok(token_id.to_vec());
        }
        let name = String::from_utf8_lossy(token_id);
        match crate::asset::token_id_for_name(asset_v1, &name)? {
            Some(id) => Ok(id.into_bytes()),
            None => Ok(token_id.to_vec()),
        }
    };
    let mut v2 = exchange.clone();
    v2.first_token_id = reset(&exchange.first_token_id)?;
    v2.second_token_id = reset(&exchange.second_token_id)?;
    Ok(v2)
}

/// Read an exchange capsule from the authoritative store, mirroring java
/// `Commons.getExchangeStoreFinal`: the V1 `ExchangeStore` (name-bearing token
/// ids) at `ALLOW_SAME_TOKEN_NAME == 0`, the V2 `ExchangeV2Store` (numeric token
/// ids) at flag == 1. Selecting the right store is essential at flag == 0: the
/// contract's `token_id` is the token *name* there, so it must be compared
/// against the V1 capsule's name-bearing ids — reading V2 (numeric ids) would
/// fail the `token_id in exchange` comparison and wrongly reject.
fn read_exchange_final(
    v1: &ExchangeStore,
    v2: &ExchangeV2Store,
    dyn_props: &DynamicPropertiesStore,
    exchange_id: i64,
) -> Result<Exchange, ActuatorError> {
    let row = if dyn_props.allow_same_token_name().unwrap_or(0) == 0 {
        v1.get(exchange_id)?
    } else {
        v2.get(exchange_id)?
    };
    row.ok_or(ActuatorError::ExchangeMissing)
}

/// Persist an exchange capsule to both stores, mirroring java
/// `Commons.putExchangeCapsule`: at flag == 0 write the name-bearing capsule to
/// V1 and the `resetTokenWithID` (numeric-id) copy to V2; at flag == 1 java
/// writes only V2 (V1 untouched), which a numeric-id capsule satisfies for both.
fn put_exchange_final(
    v1: &ExchangeStore,
    v2: &ExchangeV2Store,
    dyn_props: &DynamicPropertiesStore,
    asset_v1: &AssetIssueStore,
    exchange: &Exchange,
) -> Result<(), ActuatorError> {
    if dyn_props.allow_same_token_name().unwrap_or(0) == 0 {
        v1.put(exchange.exchange_id, exchange)?;
    }
    v2.put(exchange.exchange_id, &exchange_v2_copy(exchange, dyn_props, asset_v1)?)?;
    Ok(())
}

/// Mirrors java `TransactionUtil.isNumber`: a non-empty id whose bytes are all
/// ASCII digits, with no leading zero when the id has more than one digit.
fn is_number(id: &[u8]) -> bool {
    if id.is_empty() {
        return false;
    }
    for &b in id {
        if !b.is_ascii_digit() {
            return false;
        }
    }
    !(id.len() > 1 && id[0] == b'0')
}

/// Mirrors java `AccountCapsule.assetBalanceEnoughV2` on the allowSameTokenName
/// == 1 path: the asset-V2 slot must exist and hold at least `amount`, and
/// `amount` must be positive.
fn asset_balance_enough_v2(account: &tron_proto::Account, token_id: &[u8], amount: i64) -> bool {
    if amount <= 0 {
        return false;
    }
    let key = String::from_utf8_lossy(token_id).into_owned();
    matches!(account.asset_v2.get(&key), Some(&balance) if amount <= balance)
}

/// Current asset-V2 balance for `token_id` (0 if absent), for error reporting.
fn asset_v2_balance(account: &tron_proto::Account, token_id: &[u8]) -> i64 {
    let key = String::from_utf8_lossy(token_id).into_owned();
    account.asset_v2.get(&key).copied().unwrap_or(0)
}

// Flag-aware versions of the two reads above, for the exchange validates. java's
// `AccountCapsule.assetBalanceEnoughV2` reads the name-keyed V1 `asset` map at
// `ALLOW_SAME_TOKEN_NAME == 0` (AccountCapsule.java:701-718) and the id-keyed
// `asset_v2` map at flag=1; the asset_v2-only versions above match only flag=1.
// Without these, a flag=0 exchange whose trader balance lives in V1 would read 0
// and be REJECTED while java accepts it — a flag=0 consensus divergence. (`token_id`
// is the exchange's token id: the token name at flag=0, the numeric id at flag=1.
// `market` keeps the asset_v2-only `_impl` reads — it is always flag=1.)
fn exchange_token_balance(
    account: &tron_proto::Account,
    dyn_props: &DynamicPropertiesStore,
    token_id: &[u8],
) -> i64 {
    let key = String::from_utf8_lossy(token_id).into_owned();
    if dyn_props.allow_same_token_name().unwrap_or(0) == 0 {
        account.asset.get(&key).copied().unwrap_or(0)
    } else {
        account.asset_v2.get(&key).copied().unwrap_or(0)
    }
}

fn exchange_balance_enough(
    account: &tron_proto::Account,
    dyn_props: &DynamicPropertiesStore,
    token_id: &[u8],
    amount: i64,
) -> bool {
    if amount <= 0 {
        return false;
    }
    exchange_token_balance(account, dyn_props, token_id) >= amount
}

/// Mirrors java `BigDecimal(numer).divide(BigDecimal(denom), 4,
/// RoundingMode.HALF_UP).doubleValue()` for non-negative operands: scale the
/// quotient to four decimal places with half-up rounding, then convert to f64.
fn div_round_half_up_scale4(numer: i128, denom: i128) -> f64 {
    // Scale-4 HALF_UP of numer/denom, matching java's
    // BigDecimal.divide(.., 4, ROUND_HALF_UP).doubleValue(). Scale only the
    // REMAINDER (r < denom) rather than `numer * 10_000`, which would overflow
    // i128 for large exchange balances (numer can approach 2^120; ×10_000 ≈
    // 2^133). The integer quotient `q` equals anotherTokenQuant, already shown
    // to fit i64, so `q * 10_000` is safe. Operands are non-negative here.
    let q = numer / denom;
    let frac = scale4_fraction_half_up(numer, denom);
    (q * 10_000 + frac) as f64 / 10_000.0
}

/// The fractional part of `numer / denom` rounded HALF_UP to four decimals,
/// in units of 1e-4 (so `0..=10_000`). Operands are non-negative.
fn scale4_fraction_half_up(numer: i128, denom: i128) -> i128 {
    let r = numer % denom;
    let frac_scaled = r * 10_000;
    let fq = frac_scaled / denom;
    let fr = frac_scaled % denom;
    if 2 * fr >= denom {
        fq + 1
    } else {
        fq
    }
}

/// Public re-export of [`is_number`] for use by [`crate::market`]. Mirrors
/// java `TransactionUtil.isNumber`.
pub fn is_number_impl(id: &[u8]) -> bool {
    is_number(id)
}

/// Public re-export of [`asset_balance_enough_v2`] for use by [`crate::market`].
/// Mirrors java `AccountCapsule.assetBalanceEnoughV2` on the
/// `allowSameTokenName == 1` path.
pub fn asset_balance_enough_v2_impl(
    account: &tron_proto::Account,
    token_id: &[u8],
    amount: i64,
) -> bool {
    asset_balance_enough_v2(account, token_id, amount)
}

/// Public re-export of [`asset_v2_balance`] for use by [`crate::market`].
pub fn asset_v2_balance_impl(account: &tron_proto::Account, token_id: &[u8]) -> i64 {
    asset_v2_balance(account, token_id)
}

/// Public re-export of [`debit_token`] for use by [`crate::market`].
pub fn debit_token_impl(
    account: &mut tron_proto::Account,
    token_id: &[u8],
    amount: i64,
) -> Result<(), ActuatorError> {
    debit_token(account, token_id, amount)
}

/// Public re-export of [`credit_token`] for use by [`crate::market`].
pub fn credit_token_impl(
    account: &mut tron_proto::Account,
    token_id: &[u8],
    amount: i64,
) -> Result<(), ActuatorError> {
    credit_token(account, token_id, amount)
}

fn debit_token(
    account: &mut tron_proto::Account,
    token_id: &[u8],
    amount: i64,
) -> Result<(), ActuatorError> {
    if amount < 0 {
        return Err(ActuatorError::NonPositiveTokenQuant);
    }
    if token_id == TRX_TOKEN_ID {
        if account.balance < amount {
            return Err(ActuatorError::InsufficientBalance {
                balance: account.balance,
                needed: amount,
            });
        }
        account.balance = check_sub(account.balance, amount)?;
        return Ok(());
    }
    let key = String::from_utf8_lossy(token_id).into_owned();
    let slot = account
        .asset_v2
        .get_mut(&key)
        .ok_or(ActuatorError::InsufficientAssetBalance {
            has: 0,
            needs: amount,
        })?;
    if *slot < amount {
        return Err(ActuatorError::InsufficientAssetBalance {
            has: *slot,
            needs: amount,
        });
    }
    *slot = check_sub(*slot, amount)?;
    Ok(())
}

fn credit_token(
    account: &mut tron_proto::Account,
    token_id: &[u8],
    amount: i64,
) -> Result<(), ActuatorError> {
    if token_id == TRX_TOKEN_ID {
        account.balance = check_add(account.balance, amount)?;
        return Ok(());
    }
    let key = String::from_utf8_lossy(token_id).into_owned();
    let slot = account.asset_v2.entry(key).or_insert(0);
    *slot = check_add(*slot, amount)?;
    Ok(())
}

// The Bancor-exchange actuators mutate a trader's TRC-10 balance; java does it
// through `reduceAssetAmountV2` / `addAssetAmountV2`, which at
// `ALLOW_SAME_TOKEN_NAME == 0` write the name-keyed V1 `asset` map AND dual-write
// the id-keyed `asset_v2` map (and at flag=1 write only `asset_v2` by id). The
// asset_v2-only `debit_token`/`credit_token` above match only the flag=1 case;
// these flag-aware variants route the non-TRX branch through the shared
// `crate::asset` helpers so a flag=0 exchange keeps V1 (the authoritative map
// pre-activation) correct — and therefore the asset_v2 the rebuild reconstructs
// from it at activation. (`market` is always flag=1, so it keeps the simpler
// helpers.) `token_id` is the exchange's token id: the token name at flag=0, the
// numeric id at flag=1.
fn debit_exchange_token(
    account: &mut tron_proto::Account,
    dyn_props: &DynamicPropertiesStore,
    asset_v1: &AssetIssueStore,
    token_id: &[u8],
    amount: i64,
) -> Result<(), ActuatorError> {
    if amount < 0 {
        return Err(ActuatorError::NonPositiveTokenQuant);
    }
    if token_id == TRX_TOKEN_ID {
        if account.balance < amount {
            return Err(ActuatorError::InsufficientBalance {
                balance: account.balance,
                needed: amount,
            });
        }
        account.balance = check_sub(account.balance, amount)?;
        return Ok(());
    }
    let key = String::from_utf8_lossy(token_id).into_owned();
    crate::asset::debit_asset(account, dyn_props, asset_v1, &key, amount)
}

fn credit_exchange_token(
    account: &mut tron_proto::Account,
    dyn_props: &DynamicPropertiesStore,
    asset_v1: &AssetIssueStore,
    token_id: &[u8],
    amount: i64,
) -> Result<(), ActuatorError> {
    if token_id == TRX_TOKEN_ID {
        account.balance = check_add(account.balance, amount)?;
        return Ok(());
    }
    let key = String::from_utf8_lossy(token_id).into_owned();
    crate::asset::credit_asset(account, dyn_props, asset_v1, &key, amount)
}
