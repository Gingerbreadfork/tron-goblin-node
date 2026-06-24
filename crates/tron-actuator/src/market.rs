//! Market (DEX) actuators: MarketSellAsset, MarketCancelOrder.
//!
//! Sources: `MarketSellAssetActuator`, `MarketCancelOrderActuator`.
//!
//! **Scope notes**: java-tron's market actuators match orders across
//! `MarketPairPriceToOrderStore` + `MarketPairToPriceStore` with
//! sorted-price-level discovery. This port handles the order-book
//! state-machine (order-id derivation, per-owner order accounting,
//! insert / cancel / set status) but does not run the matching loop —
//! that's a sizable algorithm tracked for follow-up. Sell orders rest
//! ACTIVE without matching; cancel returns the locked sell-token to the
//! owner. TRON's native Market is permanently disabled on mainnet
//! (proposal #44 was never approved), so [`require_market_enabled`]
//! rejects every market tx and the bodies below never run on the live
//! chain — they exist for parity and future activation.

use tron_chainbase::{
    AccountStore, AssetIssueStore, AssetIssueV2Store, DynamicPropertiesStore, MarketAccountStore,
    MarketOrderStore,
};
use tron_crypto::address::Address;
use tron_proto::market_order::State as OrderState;
use tron_proto::{
    MarketAccountOrder, MarketCancelOrderContract, MarketOrder, MarketSellAssetContract,
};

use crate::exchange::{
    asset_balance_enough_v2_impl, asset_v2_balance_impl, credit_token_impl, debit_token_impl,
    is_number_impl,
};
use crate::helpers::{check_sub, require_owner};
use crate::transfer::ExecutionResult;
use crate::ActuatorError;

/// java `MarketUtils.TOKEN_ID_LENGTH` — the decimal-string length of
/// `Long.MAX_VALUE` (9223372036854775807 → 19 chars). Each token id is
/// laid into a fixed slot of this width inside the order-id preimage.
const TOKEN_ID_LENGTH: usize = 19;

/// The TRX pseudo-token id (`"_"`) used in market contracts to mean
/// "native TRX" rather than a TRC-10 asset.
const TRX_TOKEN_ID: &[u8] = b"_";

/// java `MarketSellAssetActuator.MAX_ACTIVE_ORDER_NUM`.
const MAX_ACTIVE_ORDER_NUM: i64 = 100;

fn require_market_enabled(dyn_props: &DynamicPropertiesStore) -> Result<(), ActuatorError> {
    if dyn_props.get_long(b"ALLOW_MARKET_TRANSACTION").unwrap_or(0) != 1 {
        return Err(ActuatorError::MarketDisabled);
    }
    Ok(())
}

/// Look up a TRC-10 asset by its (already validated) numeric token id,
/// mirroring java `Commons.getAssetIssueStoreFinal(...).get(tokenId)`:
/// on the `allowSameTokenName == 1` path (mainnet) the AssetIssueV2 store
/// is queried by the decimal-string id; otherwise the legacy AssetIssue
/// store is queried by the same id bytes (in practice every live asset
/// is V2). Returns `true` when the asset exists.
fn asset_exists(
    dyn_props: &DynamicPropertiesStore,
    asset_v1: &AssetIssueStore,
    asset_v2: &AssetIssueV2Store,
    token_id: &[u8],
) -> Result<bool, ActuatorError> {
    if dyn_props.allow_same_token_name().unwrap_or(0) == 1 {
        // `token_id` is a valid number here (caller checked `is_number`),
        // so the parse cannot fail. V2 keys are the decimal-string id.
        let id: i64 = match std::str::from_utf8(token_id).ok().and_then(|s| s.parse().ok()) {
            Some(id) => id,
            None => return Ok(false),
        };
        Ok(asset_v2.get(id)?.is_some())
    } else {
        Ok(asset_v1.get(token_id)?.is_some())
    }
}

// =============================================================================
// MarketSellAssetActuator
// =============================================================================

pub fn validate_market_sell_asset(
    accounts: &AccountStore,
    market_account: &MarketAccountStore,
    asset_v1: &AssetIssueStore,
    asset_v2: &AssetIssueV2Store,
    dyn_props: &DynamicPropertiesStore,
    contract: &MarketSellAssetContract,
) -> Result<(), ActuatorError> {
    require_market_enabled(dyn_props)?;
    let owner = require_owner(&contract.owner_address)?;

    let account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;

    let sell_id = contract.sell_token_id.as_slice();
    let buy_id = contract.buy_token_id.as_slice();

    // java: token ids must be "_" (TRX) or a valid number.
    if sell_id != TRX_TOKEN_ID && !is_number_impl(sell_id) {
        return Err(ActuatorError::MarketInvalidTokenId);
    }
    if buy_id != TRX_TOKEN_ID && !is_number_impl(buy_id) {
        return Err(ActuatorError::MarketInvalidTokenId);
    }

    if sell_id == buy_id {
        return Err(ActuatorError::MarketSameTokens);
    }

    if contract.sell_token_quantity <= 0 || contract.buy_token_quantity <= 0 {
        return Err(ActuatorError::NonPositiveTokenQuant);
    }

    // java: getMarketQuantityLimit() (dyn-prop, default 1e15) caps both sides.
    let quantity_limit = dyn_props
        .get_long(b"MARKET_QUANTITY_LIMIT")
        .unwrap_or(1_000_000_000_000_000);
    if contract.sell_token_quantity > quantity_limit
        || contract.buy_token_quantity > quantity_limit
    {
        return Err(ActuatorError::MarketQuantityLimitExceeded);
    }

    // java: an owner may hold at most MAX_ACTIVE_ORDER_NUM active orders.
    if let Some(account_order) = market_account.get(&owner)? {
        if account_order.count >= MAX_ACTIVE_ORDER_NUM {
            return Err(ActuatorError::MarketTooManyOrders);
        }
    }

    let fee = dyn_props.get_long(b"MARKET_SELL_FEE").unwrap_or(0);

    if sell_id == TRX_TOKEN_ID {
        // java addExact(sellQuantity, fee); checked add → Overflow on wrap.
        let needed = contract
            .sell_token_quantity
            .checked_add(fee)
            .ok_or(ActuatorError::Overflow)?;
        if account.balance < needed {
            return Err(ActuatorError::InsufficientBalance {
                balance: account.balance,
                needed,
            });
        }
    } else {
        if account.balance < fee {
            return Err(ActuatorError::InsufficientBalance {
                balance: account.balance,
                needed: fee,
            });
        }
        if !asset_exists(dyn_props, asset_v1, asset_v2, sell_id)? {
            return Err(ActuatorError::MarketSellTokenMissing);
        }
        if !asset_balance_enough_v2_impl(&account, sell_id, contract.sell_token_quantity) {
            return Err(ActuatorError::InsufficientAssetBalance {
                has: asset_v2_balance_impl(&account, sell_id),
                needs: contract.sell_token_quantity,
            });
        }
    }

    if buy_id != TRX_TOKEN_ID && !asset_exists(dyn_props, asset_v1, asset_v2, buy_id)? {
        return Err(ActuatorError::MarketBuyTokenMissing);
    }

    Ok(())
}

pub fn execute_market_sell_asset(
    accounts: &AccountStore,
    orders: &MarketOrderStore,
    market_account: &MarketAccountStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &MarketSellAssetContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let mut account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    let fee = dyn_props.get_long(b"MARKET_SELL_FEE").unwrap_or(0);
    account.balance = check_sub(account.balance, fee)?;
    // java MarketSellAssetActuator.execute (MarketSellAssetActuator.java:127-132):
    // after debiting the owner it sends `fee` to the blackhole — `burnTrx(fee)`
    // on the supportBlackHoleOptimization path, else crediting the blackhole
    // account (the from-genesis arm); `dispose_fee_to_blackhole` does both.
    // Market is disabled on mainnet and MARKET_SELL_FEE defaults to 0, so this
    // is doubly inert, but stays exact if the market is ever activated.
    tron_chainbase::dispose_fee_to_blackhole(accounts, dyn_props, fee)?;
    debit_token_impl(&mut account, &contract.sell_token_id, contract.sell_token_quantity)?;
    accounts.put(&owner, &account)?;

    // java createAndSaveOrder: load-or-create the owner's MarketAccountOrder,
    // derive the order id from total_count (PRE-increment), then bump both
    // count (+1) and total_count (+1).
    let mut account_order = market_account.get(&owner)?.unwrap_or_else(|| MarketAccountOrder {
        owner_address: owner.as_bytes().to_vec(),
        ..Default::default()
    });

    let order_id = make_order_id(
        &owner,
        &contract.sell_token_id,
        &contract.buy_token_id,
        account_order.total_count,
    );

    let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);
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

    account_order.orders.push(order_id.clone());
    account_order.count += 1;
    account_order.total_count += 1;
    market_account.put(&owner, &account_order)?;

    // java `MarketSellAssetActuator.execute` sets `ret.setOrderId(
    // orderCapsule.getID())` (MarketSellAssetActuator.java:151). The matching
    // engine (`matchOrder`) is the only producer of `ret.addOrderDetails`;
    // this port does not run it, so no fills are matched and `order_details`
    // stays empty — identical to java's no-match case (market is dormant on
    // mainnet). Surfaced as TransactionInfo.order_id.
    Ok(ExecutionResult {
        fee,
        ret: crate::TransactionRetExtras {
            order_id,
            ..Default::default()
        },
        ..Default::default()
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
    let order = orders
        .get(&contract.order_id)?
        .ok_or(ActuatorError::MarketOrderMissing)?;
    if order.state != OrderState::Active as i32 {
        return Err(ActuatorError::MarketOrderNotActive);
    }
    if order.owner_address != owner.as_bytes() {
        return Err(ActuatorError::NotExchangeOwner);
    }
    let fee = dyn_props.get_long(b"MARKET_CANCEL_FEE").unwrap_or(0);
    if account.balance < fee {
        return Err(ActuatorError::InsufficientBalance {
            balance: account.balance,
            needed: fee,
        });
    }
    Ok(())
}

pub fn execute_market_cancel_order(
    accounts: &AccountStore,
    orders: &MarketOrderStore,
    market_account: &MarketAccountStore,
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
    // java MarketCancelOrderActuator.execute (MarketCancelOrderActuator.java:97-102):
    // after debiting the owner it sends `fee` to the blackhole — `burnTrx(fee)`
    // on the supportBlackHoleOptimization path, else crediting the blackhole
    // account (the from-genesis arm); `dispose_fee_to_blackhole` does both.
    // Market is disabled on mainnet and MARKET_CANCEL_FEE defaults to 0, so this
    // is doubly inert, but stays exact if the market is ever activated.
    tron_chainbase::dispose_fee_to_blackhole(accounts, dyn_props, fee)?;
    // Return the unfilled sell quantity to the owner.
    credit_token_impl(&mut account, &order.sell_token_id, order.sell_token_quantity_remain)?;
    accounts.put(&owner, &account)?;

    order.state = OrderState::Canceled as i32;
    // java returnSellTokenRemain refunds the remaining quantity (credited
    // above) and zeroes it, but does NOT set sell_token_quantity_return —
    // that field records only matching-time dust returns, so a canceled
    // order keeps it at its prior value.
    order.sell_token_quantity_remain = 0;
    orders.put(&contract.order_id, &order)?;

    // java MarketUtils.updateOrderState(.., CANCELED, ..) →
    // MarketAccountOrderCapsule.removeOrder: drop the order id from the
    // owner's list and decrement count (total_count is untouched).
    if let Some(mut account_order) = market_account.get(&owner)? {
        if let Some(pos) = account_order
            .orders
            .iter()
            .position(|id| id == &contract.order_id)
        {
            account_order.orders.remove(pos);
        }
        account_order.count -= 1;
        market_account.put(&owner, &account_order)?;
    }

    Ok(ExecutionResult {
        fee,
        created_recipient: false,
        ..Default::default()
    })
}

/// Derive a market order id, byte-exact with java `MarketUtils.calculateOrderId`
/// (keccak256 / `Hash.sha3`, not sha256).
///
/// Preimage layout (length = `addr.len + 19 + 19 + 8`):
/// `ownerAddress(21) ‖ sellTokenId(in a 19-byte zero-padded slot) ‖
/// buyTokenId(in a 19-byte zero-padded slot) ‖ count(8 big-endian)`.
/// Each token id is the raw ASCII decimal bytes (e.g. `"1000001"`, or
/// `"_"` for TRX) copied into the low bytes of its fixed 19-byte slot,
/// the rest left zero. `count` is the owner's `total_count` taken
/// PRE-increment.
fn make_order_id(owner: &Address, sell_token_id: &[u8], buy_token_id: &[u8], count: i64) -> Vec<u8> {
    let addr = owner.as_bytes();
    let mut buf = vec![0u8; addr.len() + TOKEN_ID_LENGTH + TOKEN_ID_LENGTH + 8];

    let mut off = 0;
    buf[off..off + addr.len()].copy_from_slice(addr);
    off += addr.len();

    // Token ids are copied only their own length into a fixed 19-byte slot
    // (java System.arraycopy with the id's length), leaving the slot's
    // trailing bytes zero.
    let sell_len = sell_token_id.len().min(TOKEN_ID_LENGTH);
    buf[off..off + sell_len].copy_from_slice(&sell_token_id[..sell_len]);
    off += TOKEN_ID_LENGTH;

    let buy_len = buy_token_id.len().min(TOKEN_ID_LENGTH);
    buf[off..off + buy_len].copy_from_slice(&buy_token_id[..buy_len]);
    off += TOKEN_ID_LENGTH;

    buf[off..off + 8].copy_from_slice(&count.to_be_bytes());

    tron_crypto::hash::keccak256(&buf).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_owner() -> Address {
        // 0x41 mainnet prefix + 20 deterministic bytes.
        let mut bytes = [0u8; 21];
        bytes[0] = 0x41;
        for (i, b) in bytes.iter_mut().enumerate().skip(1) {
            *b = i as u8;
        }
        Address::from_raw(bytes)
    }

    #[test]
    fn order_id_matches_independent_keccak_preimage() {
        let owner = test_owner();
        let sell = b"1000001";
        let buy = b"1000002";
        let count: i64 = 7;

        // Build the expected preimage by hand: 21 + 19 + 19 + 8 = 67 bytes.
        let mut expected_preimage = vec![0u8; 21 + 19 + 19 + 8];
        expected_preimage[0..21].copy_from_slice(owner.as_bytes());
        // sellTokenId into the first 19-byte slot (offset 21).
        expected_preimage[21..21 + sell.len()].copy_from_slice(sell);
        // buyTokenId into the second 19-byte slot (offset 21 + 19 = 40).
        expected_preimage[40..40 + buy.len()].copy_from_slice(buy);
        // count, 8 big-endian bytes (offset 21 + 19 + 19 = 59).
        expected_preimage[59..67].copy_from_slice(&count.to_be_bytes());

        let expected = tron_crypto::hash::keccak256(&expected_preimage).to_vec();
        let got = make_order_id(&owner, sell, buy, count);

        assert_eq!(got, expected, "order id must equal keccak256 of the exact preimage");
        assert_eq!(got.len(), 32, "keccak256 output is 32 bytes");
    }

    #[test]
    fn order_id_handles_trx_pseudo_token() {
        let owner = test_owner();
        // "_" (TRX) is 1 byte; the slot's remaining 18 bytes stay zero.
        let mut expected_preimage = vec![0u8; 21 + 19 + 19 + 8];
        expected_preimage[0..21].copy_from_slice(owner.as_bytes());
        expected_preimage[21] = b'_';
        expected_preimage[40..47].copy_from_slice(b"1000001");
        // count = 0.
        let expected = tron_crypto::hash::keccak256(&expected_preimage).to_vec();
        let got = make_order_id(&owner, b"_", b"1000001", 0);
        assert_eq!(got, expected);
    }

    #[test]
    fn account_counter_increments_on_create_and_decrements_on_cancel() {
        // Pure counter logic over MarketAccountOrder, matching java
        // createAndSaveOrder (count+1, total_count+1) and removeOrder
        // (count-1, total_count untouched).
        let owner = test_owner();
        let mut order = MarketAccountOrder {
            owner_address: owner.as_bytes().to_vec(),
            ..Default::default()
        };
        assert_eq!(order.count, 0);
        assert_eq!(order.total_count, 0);

        // First create: id derived from total_count (0), then bump both.
        let id0 = make_order_id(&owner, b"1000001", b"1000002", order.total_count);
        order.orders.push(id0.clone());
        order.count += 1;
        order.total_count += 1;
        assert_eq!(order.count, 1);
        assert_eq!(order.total_count, 1);

        // Second create: id derived from total_count (1).
        let id1 = make_order_id(&owner, b"1000001", b"1000002", order.total_count);
        assert_ne!(id0, id1, "different counts give different order ids");
        order.orders.push(id1.clone());
        order.count += 1;
        order.total_count += 1;
        assert_eq!(order.count, 2);
        assert_eq!(order.total_count, 2);

        // Cancel id0: remove from list, count-1, total_count untouched.
        let pos = order.orders.iter().position(|id| id == &id0).unwrap();
        order.orders.remove(pos);
        order.count -= 1;
        assert_eq!(order.count, 1);
        assert_eq!(order.total_count, 2, "total_count is never decremented");
        assert_eq!(order.orders, vec![id1]);
    }

    #[test]
    fn validate_rejects_quantity_over_limit() {
        use std::sync::Arc;
        use tron_chainbase::backend::MemBackend;
        use tron_chainbase::DynamicPropertiesStore;
        use tron_proto::Account;

        let accounts = AccountStore::new(Arc::new(MemBackend::new()));
        let market_account = MarketAccountStore::new(Arc::new(MemBackend::new()));
        let asset_v1 = AssetIssueStore::new(Arc::new(MemBackend::new()));
        let asset_v2 = AssetIssueV2Store::new(Arc::new(MemBackend::new()));
        let dyn_props = DynamicPropertiesStore::new(Arc::new(MemBackend::new()));

        let owner = test_owner();
        dyn_props.put_long(b"ALLOW_MARKET_TRANSACTION", 1);
        dyn_props.put_long(b"MARKET_QUANTITY_LIMIT", 1_000_000);
        accounts
            .put(
                &owner,
                &Account {
                    address: owner.as_bytes().to_vec(),
                    balance: 1_000_000_000,
                    ..Default::default()
                },
            )
            .unwrap();

        let contract = MarketSellAssetContract {
            owner_address: owner.as_bytes().to_vec(),
            sell_token_id: b"_".to_vec(),
            sell_token_quantity: 2_000_000, // over the 1_000_000 limit
            buy_token_id: b"1000001".to_vec(),
            buy_token_quantity: 1,
        };

        let err = validate_market_sell_asset(
            &accounts,
            &market_account,
            &asset_v1,
            &asset_v2,
            &dyn_props,
            &contract,
        )
        .unwrap_err();
        assert!(matches!(err, ActuatorError::MarketQuantityLimitExceeded));
    }

    #[test]
    fn validate_rejects_invalid_token_id() {
        use std::sync::Arc;
        use tron_chainbase::backend::MemBackend;
        use tron_chainbase::DynamicPropertiesStore;
        use tron_proto::Account;

        let accounts = AccountStore::new(Arc::new(MemBackend::new()));
        let market_account = MarketAccountStore::new(Arc::new(MemBackend::new()));
        let asset_v1 = AssetIssueStore::new(Arc::new(MemBackend::new()));
        let asset_v2 = AssetIssueV2Store::new(Arc::new(MemBackend::new()));
        let dyn_props = DynamicPropertiesStore::new(Arc::new(MemBackend::new()));

        let owner = test_owner();
        dyn_props.put_long(b"ALLOW_MARKET_TRANSACTION", 1);
        accounts
            .put(
                &owner,
                &Account {
                    address: owner.as_bytes().to_vec(),
                    balance: 1_000_000_000,
                    ..Default::default()
                },
            )
            .unwrap();

        let contract = MarketSellAssetContract {
            owner_address: owner.as_bytes().to_vec(),
            // "01" has a leading zero → not a valid number per java isNumber.
            sell_token_id: b"01".to_vec(),
            sell_token_quantity: 10,
            buy_token_id: b"_".to_vec(),
            buy_token_quantity: 10,
        };

        let err = validate_market_sell_asset(
            &accounts,
            &market_account,
            &asset_v1,
            &asset_v2,
            &dyn_props,
            &contract,
        )
        .unwrap_err();
        assert!(matches!(err, ActuatorError::MarketInvalidTokenId));
    }

    #[test]
    fn execute_market_sell_debits_and_burns_fee() {
        use std::sync::Arc;
        use tron_chainbase::backend::MemBackend;
        use tron_chainbase::{DynamicPropertiesStore, MarketOrderStore};
        use tron_proto::Account;

        const FEE: i64 = 1_000_000;
        let accounts = AccountStore::new(Arc::new(MemBackend::new()));
        let orders = MarketOrderStore::new(Arc::new(MemBackend::new()));
        let market_account = MarketAccountStore::new(Arc::new(MemBackend::new()));
        let dyn_props = DynamicPropertiesStore::new(Arc::new(MemBackend::new()));

        let owner = test_owner();
        dyn_props.put_long(b"MARKET_SELL_FEE", FEE);
        // Model the post-#49 mainnet era so the fee is burned (the pre-#49
        // blackhole-account credit is covered by chainbase's fee unit tests).
        dyn_props.put_long(b"ALLOW_BLACKHOLE_OPTIMIZATION", 1);
        accounts
            .put(
                &owner,
                &Account {
                    address: owner.as_bytes().to_vec(),
                    balance: 10_000_000,
                    ..Default::default()
                },
            )
            .unwrap();

        // Sell TRX (the "_" pseudo-token) so the only asset plumbing is the
        // owner's TRX balance: balance pays both the fee and the sell quantity.
        let contract = MarketSellAssetContract {
            owner_address: owner.as_bytes().to_vec(),
            sell_token_id: b"_".to_vec(),
            sell_token_quantity: 500_000,
            buy_token_id: b"1000001".to_vec(),
            buy_token_quantity: 1,
        };

        let result = execute_market_sell_asset(
            &accounts,
            &orders,
            &market_account,
            &dyn_props,
            &contract,
        )
        .unwrap();

        assert_eq!(result.fee, FEE, "result fee == MARKET_SELL_FEE");
        let acct = accounts.get(&owner).unwrap().unwrap();
        // balance = 10_000_000 - fee - sell_quantity.
        assert_eq!(acct.balance, 10_000_000 - FEE - 500_000, "fee + sell debited");
        // java MarketSellAssetActuator.execute burns the fee.
        assert_eq!(dyn_props.burn_trx_amount(), FEE, "fee added to BURN_TRX_AMOUNT");
    }

    #[test]
    fn execute_market_cancel_debits_and_burns_fee() {
        use std::sync::Arc;
        use tron_chainbase::backend::MemBackend;
        use tron_chainbase::{DynamicPropertiesStore, MarketOrderStore};
        use tron_proto::Account;

        const FEE: i64 = 1_000_000;
        let accounts = AccountStore::new(Arc::new(MemBackend::new()));
        let orders = MarketOrderStore::new(Arc::new(MemBackend::new()));
        let market_account = MarketAccountStore::new(Arc::new(MemBackend::new()));
        let dyn_props = DynamicPropertiesStore::new(Arc::new(MemBackend::new()));

        let owner = test_owner();
        dyn_props.put_long(b"MARKET_CANCEL_FEE", FEE);
        // Model the post-#49 mainnet era so the fee is burned (the pre-#49
        // blackhole-account credit is covered by chainbase's fee unit tests).
        dyn_props.put_long(b"ALLOW_BLACKHOLE_OPTIMIZATION", 1);
        accounts
            .put(
                &owner,
                &Account {
                    address: owner.as_bytes().to_vec(),
                    balance: 10_000_000,
                    ..Default::default()
                },
            )
            .unwrap();

        // Rest an ACTIVE order selling TRX so the cancel refunds TRX to the
        // owner and the fee debit/burn is observable independently.
        let order_id = make_order_id(&owner, b"_", b"1000001", 0);
        let order = MarketOrder {
            order_id: order_id.clone(),
            owner_address: owner.as_bytes().to_vec(),
            create_time: 0,
            sell_token_id: b"_".to_vec(),
            sell_token_quantity: 500_000,
            buy_token_id: b"1000001".to_vec(),
            buy_token_quantity: 1,
            sell_token_quantity_remain: 500_000,
            sell_token_quantity_return: 0,
            state: OrderState::Active as i32,
            prev: Vec::new(),
            next: Vec::new(),
        };
        orders.put(&order_id, &order).unwrap();
        market_account
            .put(
                &owner,
                &MarketAccountOrder {
                    owner_address: owner.as_bytes().to_vec(),
                    orders: vec![order_id.clone()],
                    count: 1,
                    total_count: 1,
                },
            )
            .unwrap();

        let contract = MarketCancelOrderContract {
            owner_address: owner.as_bytes().to_vec(),
            order_id: order_id.clone(),
        };

        let result = execute_market_cancel_order(
            &accounts,
            &orders,
            &market_account,
            &dyn_props,
            &contract,
        )
        .unwrap();

        assert_eq!(result.fee, FEE, "result fee == MARKET_CANCEL_FEE");
        let acct = accounts.get(&owner).unwrap().unwrap();
        // balance = 10_000_000 - fee + refunded remain (500_000 TRX).
        assert_eq!(acct.balance, 10_000_000 - FEE + 500_000, "fee debited, remain refunded");
        // java MarketCancelOrderActuator.execute burns the fee.
        assert_eq!(dyn_props.burn_trx_amount(), FEE, "fee added to BURN_TRX_AMOUNT");
    }
}
