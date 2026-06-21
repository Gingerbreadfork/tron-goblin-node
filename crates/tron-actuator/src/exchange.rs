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
    AccountStore, DynamicPropertiesStore, ExchangeStore, ExchangeV2Store,
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
    Ok(())
}

pub fn execute_exchange_create(
    accounts: &AccountStore,
    v1: &ExchangeStore,
    v2: &ExchangeV2Store,
    dyn_props: &DynamicPropertiesStore,
    contract: &ExchangeCreateContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let mut account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    let fee = dyn_props.get_long(b"EXCHANGE_CREATE_FEE").unwrap_or(1_024_000_000);
    account.balance = check_sub(account.balance, fee)?;
    // java ExchangeCreateActuator: burn the fee after debiting the owner
    // (supportBlackHoleOptimization → burnTrx) to keep BURN_TRX_AMOUNT in sync.
    dyn_props.burn_trx(fee);

    // Debit owner's TRX or asset balance for each side.
    debit_token(
        &mut account,
        &contract.first_token_id,
        contract.first_token_balance,
    )?;
    debit_token(
        &mut account,
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
    v1.put(next_id, &exchange)?;
    v2.put(next_id, &exchange)?;
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
    let exchange = v2
        .get(contract.exchange_id)?
        .ok_or(ActuatorError::ExchangeMissing)?;
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
    } else if !asset_balance_enough_v2(&account, token_id, token_quant) {
        return Err(ActuatorError::InsufficientAssetBalance {
            has: asset_v2_balance(&account, token_id),
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
    } else if !asset_balance_enough_v2(&account, another_id, another_token_quant) {
        return Err(ActuatorError::InsufficientAssetBalance {
            has: asset_v2_balance(&account, another_id),
            needs: another_token_quant,
        });
    }

    Ok(())
}

pub fn execute_exchange_inject(
    accounts: &AccountStore,
    v1: &ExchangeStore,
    v2: &ExchangeV2Store,
    contract: &ExchangeInjectContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let mut exchange = v2
        .get(contract.exchange_id)?
        .ok_or(ActuatorError::ExchangeMissing)?;

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
    debit_token(&mut account, &my_id, contract.quant)?;
    debit_token(&mut account, &other_id, other_quant)?;
    accounts.put(&owner, &account)?;

    if contract.token_id == exchange.first_token_id {
        exchange.first_token_balance = check_add(exchange.first_token_balance, contract.quant)?;
        exchange.second_token_balance = check_add(exchange.second_token_balance, other_quant)?;
    } else {
        exchange.second_token_balance = check_add(exchange.second_token_balance, contract.quant)?;
        exchange.first_token_balance = check_add(exchange.first_token_balance, other_quant)?;
    }
    v1.put(exchange.exchange_id, &exchange)?;
    v2.put(exchange.exchange_id, &exchange)?;

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
    v2: &ExchangeV2Store,
    contract: &ExchangeWithdrawContract,
) -> Result<(), ActuatorError> {
    // java ExchangeWithdrawActuator.validate.
    let owner = require_owner(&contract.owner_address)?;
    if accounts.get(&owner)?.is_none() {
        return Err(ActuatorError::OwnerAccountMissing);
    }
    // calcFee() == 0 for exchange withdraw; the fee balance check is a no-op.
    let exchange = v2
        .get(contract.exchange_id)?
        .ok_or(ActuatorError::ExchangeMissing)?;
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
    contract: &ExchangeWithdrawContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let mut exchange = v2
        .get(contract.exchange_id)?
        .ok_or(ActuatorError::ExchangeMissing)?;

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
    credit_token(&mut account, &my_id, contract.quant)?;
    credit_token(&mut account, &other_id, other_quant)?;
    accounts.put(&owner, &account)?;

    if contract.token_id == exchange.first_token_id {
        exchange.first_token_balance = check_sub(exchange.first_token_balance, contract.quant)?;
        exchange.second_token_balance = check_sub(exchange.second_token_balance, other_quant)?;
    } else {
        exchange.second_token_balance = check_sub(exchange.second_token_balance, contract.quant)?;
        exchange.first_token_balance = check_sub(exchange.first_token_balance, other_quant)?;
    }
    v1.put(exchange.exchange_id, &exchange)?;
    v2.put(exchange.exchange_id, &exchange)?;

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
    let owner = require_owner(&contract.owner_address)?;
    let account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;

    let exchange = v2
        .get(contract.exchange_id)?
        .ok_or(ActuatorError::ExchangeMissing)?;

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
        if !asset_balance_enough_v2(&acct, token_id, token_quant) {
            return Err(ActuatorError::InsufficientAssetBalance {
                has: asset_v2_balance(&acct, token_id),
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
    let another_token_quant = exchange_transaction_output(
        sell_balance_before,
        buy_balance_before,
        token_quant,
        dyn_props.allow_strict_math(),
    );
    if another_token_quant < token_expected {
        return Err(ActuatorError::ExchangeOutputBelowExpected);
    }
    Ok(())
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
    contract: &ExchangeTransactionContract,
) -> Result<ExecutionResult, ActuatorError> {
    let use_strict_math = dyn_props.allow_strict_math();
    let owner = require_owner(&contract.owner_address)?;
    let mut exchange = v2
        .get(contract.exchange_id)?
        .ok_or(ActuatorError::ExchangeMissing)?;

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
    let output = exchange_transaction_output(
        my_balance_before,
        other_balance_before,
        contract.quant,
        use_strict_math,
    );
    if output < contract.expected {
        return Err(ActuatorError::ExchangeOutputBelowExpected);
    }

    let mut account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    debit_token(&mut account, &my_id, contract.quant)?;
    credit_token(&mut account, &other_id, output)?;
    accounts.put(&owner, &account)?;

    if contract.token_id == exchange.first_token_id {
        exchange.first_token_balance = check_add(exchange.first_token_balance, contract.quant)?;
        exchange.second_token_balance = check_sub(exchange.second_token_balance, output)?;
    } else {
        exchange.second_token_balance = check_add(exchange.second_token_balance, contract.quant)?;
        exchange.first_token_balance = check_sub(exchange.first_token_balance, output)?;
    }
    v1.put(exchange.exchange_id, &exchange)?;
    v2.put(exchange.exchange_id, &exchange)?;

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
    let r = numer % denom;
    let frac_scaled = r * 10_000;
    let fq = frac_scaled / denom;
    let fr = frac_scaled % denom;
    let frac = if 2 * fr >= denom { fq + 1 } else { fq };
    (q * 10_000 + frac) as f64 / 10_000.0
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
