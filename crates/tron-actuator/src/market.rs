//! Market (DEX) actuators: MarketSellAsset, MarketCancelOrder.
//!
//! Sources: `MarketSellAssetActuator`, `MarketCancelOrderActuator`.
//!
//! **Scope notes**: java-tron's market actuators do order matching across
//! `MarketPairPriceToOrderStore` + `MarketPairToPriceStore` with
//! sorted-price-level discovery. This port handles the order-book
//! state-machine (insert / cancel / set status) but does not run the
//! matching loop — that's a sizable algorithm tracked for follow-up.
//! Sell orders are inserted as ACTIVE without matching; cancel
//! returns the locked sell-token to the owner.

use tron_chainbase::{
    AccountStore, DynamicPropertiesStore, MarketOrderStore,
};
use tron_proto::market_order::State as OrderState;
use tron_proto::{MarketCancelOrderContract, MarketOrder, MarketSellAssetContract};

use crate::exchange::{credit_token_impl, debit_token_impl};
use crate::helpers::{check_sub, require_owner};
use crate::transfer::ExecutionResult;
use crate::ActuatorError;

fn require_market_enabled(dyn_props: &DynamicPropertiesStore) -> Result<(), ActuatorError> {
    if dyn_props.get_long(b"ALLOW_MARKET_TRANSACTION").unwrap_or(0) != 1 {
        return Err(ActuatorError::MarketDisabled);
    }
    Ok(())
}

// =============================================================================
// MarketSellAssetActuator
// =============================================================================

pub fn validate_market_sell_asset(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &MarketSellAssetContract,
) -> Result<(), ActuatorError> {
    require_market_enabled(dyn_props)?;
    let owner = require_owner(&contract.owner_address)?;
    if contract.sell_token_id == contract.buy_token_id {
        return Err(ActuatorError::MarketSameTokens);
    }
    if contract.sell_token_quantity <= 0 || contract.buy_token_quantity <= 0 {
        return Err(ActuatorError::NonPositiveTokenQuant);
    }
    let account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    let fee = dyn_props.get_long(b"MARKET_SELL_FEE").unwrap_or(0);
    if account.balance < fee {
        return Err(ActuatorError::InsufficientBalance {
            balance: account.balance,
            needed: fee,
        });
    }
    Ok(())
}

pub fn execute_market_sell_asset(
    accounts: &AccountStore,
    orders: &MarketOrderStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &MarketSellAssetContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let mut account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    let fee = dyn_props.get_long(b"MARKET_SELL_FEE").unwrap_or(0);
    account.balance = check_sub(account.balance, fee)?;
    debit_token_impl(&mut account, &contract.sell_token_id, contract.sell_token_quantity)?;
    accounts.put(&owner, &account)?;

    let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);
    let order_id = make_order_id(&owner, now);
    let order = MarketOrder {
        order_id: order_id.clone(),
        owner_address: owner.as_bytes().to_vec(),
        create_time: now,
        sell_token_id: contract.sell_token_id.clone(),
        sell_token_quantity: contract.sell_token_quantity,
        buy_token_id: contract.buy_token_id.clone(),
        buy_token_quantity: contract.buy_token_quantity,
        sell_token_quantity_remain: contract.sell_token_quantity,
        sell_token_quantity_return: 0,
        state: OrderState::Active as i32,
        prev: Vec::new(),
        next: Vec::new(),
    };
    orders.put(&order_id, &order)?;

    Ok(ExecutionResult {
        fee,
        created_recipient: false,
    })
}

// =============================================================================
// MarketCancelOrderActuator
// =============================================================================

pub fn validate_market_cancel_order(
    accounts: &AccountStore,
    orders: &MarketOrderStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &MarketCancelOrderContract,
) -> Result<(), ActuatorError> {
    require_market_enabled(dyn_props)?;
    let owner = require_owner(&contract.owner_address)?;
    let account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    let fee = dyn_props.get_long(b"MARKET_CANCEL_FEE").unwrap_or(0);
    if account.balance < fee {
        return Err(ActuatorError::InsufficientBalance {
            balance: account.balance,
            needed: fee,
        });
    }
    let order = orders
        .get(&contract.order_id)?
        .ok_or(ActuatorError::MarketOrderMissing)?;
    if order.state != OrderState::Active as i32 {
        return Err(ActuatorError::MarketOrderNotActive);
    }
    if order.owner_address != owner.as_bytes() {
        return Err(ActuatorError::NotExchangeOwner);
    }
    Ok(())
}

pub fn execute_market_cancel_order(
    accounts: &AccountStore,
    orders: &MarketOrderStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &MarketCancelOrderContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let mut order = orders
        .get(&contract.order_id)?
        .ok_or(ActuatorError::MarketOrderMissing)?;

    let mut account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    let fee = dyn_props.get_long(b"MARKET_CANCEL_FEE").unwrap_or(0);
    account.balance = check_sub(account.balance, fee)?;
    // Return the unfilled sell quantity to the owner.
    credit_token_impl(&mut account, &order.sell_token_id, order.sell_token_quantity_remain)?;
    accounts.put(&owner, &account)?;

    order.state = OrderState::Canceled as i32;
    order.sell_token_quantity_return = order.sell_token_quantity_remain;
    order.sell_token_quantity_remain = 0;
    orders.put(&contract.order_id, &order)?;

    Ok(ExecutionResult {
        fee,
        created_recipient: false,
    })
}

/// Build an opaque order id from `(owner, timestamp)`. java-tron uses
/// the SHA-256 of the transaction id; we use a similar deterministic
/// hash over the owner + timestamp so the store key is unique.
fn make_order_id(owner: &tron_crypto::address::Address, timestamp: i64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(21 + 8);
    buf.extend_from_slice(owner.as_bytes());
    buf.extend_from_slice(&timestamp.to_be_bytes());
    tron_crypto::hash::sha256(&buf).to_vec()
}
