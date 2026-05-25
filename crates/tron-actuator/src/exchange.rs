//! Bancor exchange actuators: ExchangeCreate, ExchangeInject,
//! ExchangeWithdraw, ExchangeTransaction.
//!
//! Source: `ExchangeCreateActuator`, `ExchangeInjectActuator`,
//! `ExchangeWithdrawActuator`, `ExchangeTransactionActuator`.
//!
//! **Pricing**: TRON's exchanges use a constant-product (`x * y = k`)
//! formula. We implement the basic math here; java-tron has additional
//! `allowHarden` / `allowStrictMath` flags that toggle alternate
//! precision rules — those are not yet ported.

use tron_chainbase::{
    AccountStore, DynamicPropertiesStore, ExchangeStore, ExchangeV2Store,
};
use tron_proto::{
    Exchange, ExchangeCreateContract, ExchangeInjectContract, ExchangeTransactionContract,
    ExchangeWithdrawContract,
};

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
    let limit = dyn_props.get_long(b"EXCHANGE_BALANCE_LIMIT").unwrap_or(i64::MAX);
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
    accounts.put(&owner, &account);

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
    v1.put(next_id, &exchange);
    v2.put(next_id, &exchange);
    dyn_props.put_long(
        tron_chainbase::dynamic_properties_keys::LATEST_EXCHANGE_NUM,
        next_id,
    );

    Ok(ExecutionResult {
        fee,
        created_recipient: false,
    })
}

// =============================================================================
// ExchangeInjectActuator
// =============================================================================

pub fn validate_exchange_inject(
    accounts: &AccountStore,
    v2: &ExchangeV2Store,
    contract: &ExchangeInjectContract,
) -> Result<(), ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    let exchange = v2
        .get(contract.exchange_id)?
        .ok_or(ActuatorError::ExchangeMissing)?;
    if exchange.creator_address != owner.as_bytes() {
        return Err(ActuatorError::NotExchangeOwner);
    }
    if contract.token_id != exchange.first_token_id && contract.token_id != exchange.second_token_id
    {
        return Err(ActuatorError::TokenNotInExchange);
    }
    if contract.quant <= 0 {
        return Err(ActuatorError::NonPositiveTokenQuant);
    }
    let _ = account; // balance check happens in execute when we know the other side
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
    accounts.put(&owner, &account);

    if contract.token_id == exchange.first_token_id {
        exchange.first_token_balance = check_add(exchange.first_token_balance, contract.quant)?;
        exchange.second_token_balance = check_add(exchange.second_token_balance, other_quant)?;
    } else {
        exchange.second_token_balance = check_add(exchange.second_token_balance, contract.quant)?;
        exchange.first_token_balance = check_add(exchange.first_token_balance, other_quant)?;
    }
    v1.put(exchange.exchange_id, &exchange);
    v2.put(exchange.exchange_id, &exchange);

    Ok(ExecutionResult::default())
}

// =============================================================================
// ExchangeWithdrawActuator
// =============================================================================

pub fn validate_exchange_withdraw(
    accounts: &AccountStore,
    v2: &ExchangeV2Store,
    contract: &ExchangeWithdrawContract,
) -> Result<(), ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    if accounts.get(&owner)?.is_none() {
        return Err(ActuatorError::OwnerAccountMissing);
    }
    let exchange = v2
        .get(contract.exchange_id)?
        .ok_or(ActuatorError::ExchangeMissing)?;
    if exchange.creator_address != owner.as_bytes() {
        return Err(ActuatorError::NotExchangeOwner);
    }
    if contract.token_id != exchange.first_token_id && contract.token_id != exchange.second_token_id
    {
        return Err(ActuatorError::TokenNotInExchange);
    }
    if contract.quant <= 0 {
        return Err(ActuatorError::NonPositiveTokenQuant);
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
    accounts.put(&owner, &account);

    if contract.token_id == exchange.first_token_id {
        exchange.first_token_balance = check_sub(exchange.first_token_balance, contract.quant)?;
        exchange.second_token_balance = check_sub(exchange.second_token_balance, other_quant)?;
    } else {
        exchange.second_token_balance = check_sub(exchange.second_token_balance, contract.quant)?;
        exchange.first_token_balance = check_sub(exchange.first_token_balance, other_quant)?;
    }
    v1.put(exchange.exchange_id, &exchange);
    v2.put(exchange.exchange_id, &exchange);

    Ok(ExecutionResult::default())
}

// =============================================================================
// ExchangeTransactionActuator
// =============================================================================

pub fn validate_exchange_transaction(
    accounts: &AccountStore,
    v2: &ExchangeV2Store,
    contract: &ExchangeTransactionContract,
) -> Result<(), ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    if accounts.get(&owner)?.is_none() {
        return Err(ActuatorError::OwnerAccountMissing);
    }
    let exchange = v2
        .get(contract.exchange_id)?
        .ok_or(ActuatorError::ExchangeMissing)?;
    if contract.token_id != exchange.first_token_id && contract.token_id != exchange.second_token_id
    {
        return Err(ActuatorError::TokenNotInExchange);
    }
    if contract.quant <= 0 || contract.expected <= 0 {
        return Err(ActuatorError::NonPositiveTokenQuant);
    }
    Ok(())
}

pub fn execute_exchange_transaction(
    accounts: &AccountStore,
    v1: &ExchangeStore,
    v2: &ExchangeV2Store,
    contract: &ExchangeTransactionContract,
) -> Result<ExecutionResult, ActuatorError> {
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

    // x*y=k: output = other_balance - (my_balance * other_balance) / (my_balance + quant).
    let new_my = (my_balance_before as i128) + (contract.quant as i128);
    let new_other =
        (my_balance_before as i128) * (other_balance_before as i128) / new_my;
    let output = (other_balance_before as i128) - new_other;
    if output <= 0 || output > i64::MAX as i128 {
        return Err(ActuatorError::Overflow);
    }
    let output = output as i64;
    if output < contract.expected {
        return Err(ActuatorError::ExchangeOutputBelowExpected);
    }

    let mut account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    debit_token(&mut account, &my_id, contract.quant)?;
    credit_token(&mut account, &other_id, output)?;
    accounts.put(&owner, &account);

    if contract.token_id == exchange.first_token_id {
        exchange.first_token_balance = check_add(exchange.first_token_balance, contract.quant)?;
        exchange.second_token_balance = check_sub(exchange.second_token_balance, output)?;
    } else {
        exchange.second_token_balance = check_add(exchange.second_token_balance, contract.quant)?;
        exchange.first_token_balance = check_sub(exchange.first_token_balance, output)?;
    }
    v1.put(exchange.exchange_id, &exchange);
    v2.put(exchange.exchange_id, &exchange);

    Ok(ExecutionResult::default())
}

// =============================================================================
// Helpers
// =============================================================================

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
