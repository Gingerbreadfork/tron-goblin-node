//! Asset actuators: TransferAsset, AssetIssue, UpdateAsset,
//! ParticipateAssetIssue, UnfreezeAsset.
//!
//! **Scope notes**:
//!
//! * For V1/V2 asset stores java-tron's behavior is gated by
//!   `ALLOW_SAME_TOKEN_NAME`. v1 uses asset names, v2 uses decimal-id
//!   strings (see [`tron_chainbase::AssetIssueV2Store`]). This port
//!   exposes both stores explicitly to callers — picking which one to
//!   query is the caller's responsibility per the proposal flag.
//! * `AssetIssueActuator.validate` has ~20 rules; we implement the
//!   critical structural ones (name/length, supply > 0, time window,
//!   account exists, balance >= fee, uniqueness via name lookup).
//!   Edge cases (precision range, frozen-supply duration ranges) are
//!   tracked in the doc comment for each rule that's deferred.

use tron_chainbase::{
    AccountStore, AssetIssueStore, AssetIssueV2Store, DynamicPropertiesStore,
};
use tron_crypto::address::Address;
use tron_proto::{
    AssetIssueContract, ParticipateAssetIssueContract, TransferAssetContract,
    UnfreezeAssetContract, UpdateAssetContract,
};

use crate::helpers::{check_add, check_sub, require_owner, require_to};
use crate::transfer::ExecutionResult;
use crate::ActuatorError;

/// 32-byte max for asset names. java-tron's `TransactionUtil.validAssetName`.
pub const MAX_ASSET_NAME_BYTES: usize = 32;

// =============================================================================
// TransferAssetActuator
// =============================================================================

pub fn validate_transfer_asset(
    accounts: &AccountStore,
    contract: &TransferAssetContract,
) -> Result<(), ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let to = require_to(&contract.to_address)?;
    if owner == to {
        return Err(ActuatorError::SelfTransfer);
    }
    if contract.amount <= 0 {
        return Err(ActuatorError::NonPositiveAmount);
    }
    if contract.asset_name.is_empty() || contract.asset_name.len() > MAX_ASSET_NAME_BYTES {
        return Err(ActuatorError::AssetMissing);
    }
    let mut owner_account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    // Optimized accounts hold TRC10 balances in the account-asset store, not
    // inline — merge them in (java's importAllAsset) before reading.
    tron_chainbase::import_all_asset(&mut owner_account);

    let key = String::from_utf8_lossy(&contract.asset_name);
    let asset_balance = lookup_asset_balance(&owner_account, &key);
    if asset_balance < contract.amount {
        return Err(ActuatorError::InsufficientAssetBalance {
            has: asset_balance,
            needs: contract.amount,
        });
    }
    Ok(())
}

pub fn execute_transfer_asset(
    accounts: &AccountStore,
    contract: &TransferAssetContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let to = require_to(&contract.to_address)?;

    let key = String::from_utf8_lossy(&contract.asset_name).into_owned();
    let mut owner_account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    let mut to_account = accounts.get(&to)?.unwrap_or_else(|| tron_proto::Account {
        address: to.as_bytes().to_vec(),
        r#type: tron_proto::AccountType::Normal as i32,
        ..Default::default()
    });

    // Merge optimized accounts' TRC10 balances inline before mutating, so the
    // debit sees the real balance and the credit adds to (not overwrites) any
    // existing store balance for the receiver (java's importAllAsset). New
    // (non-optimized) accounts are a no-op. We then write the balances back
    // inline; the RPC read-merge (store ∪ inline, inline wins) keeps reads
    // correct. NOTE: this does NOT re-split back to the account-asset store on
    // commit the way java's SnapshotRoot does — functionally correct
    // (balances right, RPC consistent) but the on-disk layout drifts from
    // java's (optimized accounts accumulate inline asset_v2). Pending: a
    // store-write-back to restore byte-exact storage parity.
    tron_chainbase::import_all_asset(&mut owner_account);
    tron_chainbase::import_all_asset(&mut to_account);

    debit_asset(&mut owner_account, &key, contract.amount)?;
    credit_asset(&mut to_account, &key, contract.amount)?;

    accounts.put(&owner, &owner_account)?;
    accounts.put(&to, &to_account)?;
    Ok(ExecutionResult::default())
}

// =============================================================================
// AssetIssueActuator
// =============================================================================

pub fn validate_asset_issue(
    accounts: &AccountStore,
    v1: &AssetIssueStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &AssetIssueContract,
) -> Result<(), ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    if contract.name.is_empty() || contract.name.len() > MAX_ASSET_NAME_BYTES {
        return Err(ActuatorError::AssetMissing);
    }
    if contract.total_supply <= 0 {
        return Err(ActuatorError::NonPositiveAmount);
    }
    if contract.num <= 0 || contract.trx_num <= 0 {
        return Err(ActuatorError::NonPositiveAmount);
    }
    if contract.end_time <= contract.start_time || contract.start_time <= 0 {
        return Err(ActuatorError::AssetIssueEnded);
    }
    let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);
    if contract.start_time <= now {
        return Err(ActuatorError::AssetIssueNotStarted);
    }
    let owner_account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    if !owner_account.asset_issued_name.is_empty() || !owner_account.asset_issued_id.is_empty() {
        return Err(ActuatorError::AccountAlreadyIssuedAsset);
    }
    let fee = dyn_props.get_long(b"ASSET_ISSUE_FEE").unwrap_or(1_024_000_000); // 1024 TRX default
    if owner_account.balance < fee {
        return Err(ActuatorError::InsufficientBalance {
            balance: owner_account.balance,
            needed: fee,
        });
    }
    if v1.get(&contract.name)?.is_some() {
        return Err(ActuatorError::AssetNameTaken);
    }
    Ok(())
}

pub fn execute_asset_issue(
    accounts: &AccountStore,
    v1: &AssetIssueStore,
    v2: &AssetIssueV2Store,
    dyn_props: &DynamicPropertiesStore,
    contract: &AssetIssueContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let mut owner_account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    let fee = dyn_props.get_long(b"ASSET_ISSUE_FEE").unwrap_or(1_024_000_000);
    owner_account.balance = check_sub(owner_account.balance, fee)?;

    let next_token_id = dyn_props.get_long(b"TOKEN_ID_NUM").unwrap_or(1_000_000) + 1;
    dyn_props.put_long(b"TOKEN_ID_NUM", next_token_id);

    let mut to_store = contract.clone();
    to_store.id = next_token_id.to_string();
    to_store.owner_address = owner.as_bytes().to_vec();

    v1.put(&contract.name, &to_store)?;
    v2.put(next_token_id, &to_store)?;

    // Credit the issuer with the (non-frozen) supply.
    let frozen_supply: i64 = contract.frozen_supply.iter().map(|f| f.frozen_amount).sum();
    let liquid = check_sub(contract.total_supply, frozen_supply)?;
    let id_str = next_token_id.to_string();
    owner_account
        .asset_v2
        .entry(id_str.clone())
        .and_modify(|v| *v = v.saturating_add(liquid))
        .or_insert(liquid);
    owner_account.asset_issued_name = contract.name.clone();
    owner_account.asset_issued_id = id_str.into_bytes();
    accounts.put(&owner, &owner_account)?;

    Ok(ExecutionResult {
        fee,
        created_recipient: false,
    })
}

// =============================================================================
// UpdateAssetActuator
// =============================================================================

pub fn validate_update_asset(
    accounts: &AccountStore,
    contract: &UpdateAssetContract,
) -> Result<(), ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    if account.asset_issued_id.is_empty() {
        return Err(ActuatorError::AccountAlreadyIssuedAsset); // misnomer — used as "no asset to update"
    }
    if contract.new_limit < 0 || contract.new_public_limit < 0 {
        return Err(ActuatorError::NonPositiveAmount);
    }
    Ok(())
}

pub fn execute_update_asset(
    accounts: &AccountStore,
    v1: &AssetIssueStore,
    v2: &AssetIssueV2Store,
    contract: &UpdateAssetContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;

    let id_str = String::from_utf8_lossy(&account.asset_issued_id).into_owned();
    let id_num: i64 = id_str.parse().unwrap_or(0);
    if let Some(mut asset) = v2.get(id_num)? {
        asset.url = contract.url.clone();
        asset.description = contract.description.clone();
        asset.free_asset_net_limit = contract.new_limit;
        asset.public_free_asset_net_limit = contract.new_public_limit;
        v2.put(id_num, &asset)?;
        // Mirror to V1 if a v1 entry exists (pre-fork compat).
        if v1.get(&asset.name)?.is_some() {
            v1.put(&asset.name, &asset)?;
        }
    }
    Ok(ExecutionResult::default())
}

// =============================================================================
// ParticipateAssetIssueActuator
// =============================================================================

pub fn validate_participate_asset_issue(
    accounts: &AccountStore,
    v1: &AssetIssueStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &ParticipateAssetIssueContract,
) -> Result<(), ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let to = require_to(&contract.to_address)?;
    if owner == to {
        return Err(ActuatorError::SelfTransfer);
    }
    if contract.amount <= 0 {
        return Err(ActuatorError::NonPositiveAmount);
    }
    let owner_account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    if owner_account.balance < contract.amount {
        return Err(ActuatorError::InsufficientBalance {
            balance: owner_account.balance,
            needed: contract.amount,
        });
    }
    let asset = v1.get(&contract.asset_name)?.ok_or(ActuatorError::AssetMissing)?;
    if asset.owner_address != to.as_bytes() {
        return Err(ActuatorError::InvalidToAddress);
    }
    let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);
    if now < asset.start_time {
        return Err(ActuatorError::AssetIssueNotStarted);
    }
    if now >= asset.end_time {
        return Err(ActuatorError::AssetIssueEnded);
    }
    Ok(())
}

pub fn execute_participate_asset_issue(
    accounts: &AccountStore,
    v1: &AssetIssueStore,
    contract: &ParticipateAssetIssueContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let to = require_to(&contract.to_address)?;

    let asset = v1.get(&contract.asset_name)?.ok_or(ActuatorError::AssetMissing)?;
    let exchange_amount = (contract.amount as i128) * (asset.num as i128) / (asset.trx_num as i128);
    if exchange_amount <= 0 || exchange_amount > i64::MAX as i128 {
        return Err(ActuatorError::Overflow);
    }
    let exchange_amount = exchange_amount as i64;

    let mut owner_account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    let mut to_account = accounts
        .get(&to)?
        .ok_or(ActuatorError::TargetAccountMissing)?;

    // TRX flow: owner -> to.
    owner_account.balance = check_sub(owner_account.balance, contract.amount)?;
    to_account.balance = check_add(to_account.balance, contract.amount)?;

    // Asset flow: to -> owner. Merge optimized accounts' TRC10 balances inline
    // first (java's importAllAsset) so the issuer's debit sees its real
    // balance and the participant's credit adds to any existing one.
    tron_chainbase::import_all_asset(&mut to_account);
    tron_chainbase::import_all_asset(&mut owner_account);
    let key = String::from_utf8_lossy(&contract.asset_name).into_owned();
    debit_asset(&mut to_account, &key, exchange_amount)?;
    credit_asset(&mut owner_account, &key, exchange_amount)?;

    accounts.put(&owner, &owner_account)?;
    accounts.put(&to, &to_account)?;
    Ok(ExecutionResult::default())
}

// =============================================================================
// UnfreezeAssetActuator (legacy)
// =============================================================================

pub fn validate_unfreeze_asset(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &UnfreezeAssetContract,
) -> Result<(), ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    if account.frozen_supply.is_empty() {
        return Err(ActuatorError::NoUnfreezableAsset);
    }
    let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);
    if !account.frozen_supply.iter().any(|f| f.expire_time <= now) {
        return Err(ActuatorError::NoUnfreezableAsset);
    }
    Ok(())
}

pub fn execute_unfreeze_asset(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &UnfreezeAssetContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let mut account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);

    let mut unlocked = 0i64;
    account.frozen_supply.retain(|f| {
        if f.expire_time <= now {
            unlocked = unlocked.saturating_add(f.frozen_balance);
            false
        } else {
            true
        }
    });
    // Merge optimized balances inline so the credit adds to (not overwrites)
    // any existing store balance for this asset (java's importAllAsset).
    tron_chainbase::import_all_asset(&mut account);
    let key = String::from_utf8_lossy(&account.asset_issued_id).into_owned();
    credit_asset(&mut account, &key, unlocked)?;
    accounts.put(&owner, &account)?;
    Ok(ExecutionResult::default())
}

// =============================================================================
// Helpers
// =============================================================================

fn lookup_asset_balance(account: &tron_proto::Account, key: &str) -> i64 {
    account
        .asset_v2
        .get(key)
        .copied()
        .or_else(|| account.asset.get(key).copied())
        .unwrap_or(0)
}

fn debit_asset(
    account: &mut tron_proto::Account,
    key: &str,
    amount: i64,
) -> Result<(), ActuatorError> {
    if amount < 0 {
        return Err(ActuatorError::NonPositiveAmount);
    }
    // Try v2 first (proposal ALLOW_SAME_TOKEN_NAME era), fall back to v1.
    if let Some(slot) = account.asset_v2.get_mut(key) {
        if *slot < amount {
            return Err(ActuatorError::InsufficientAssetBalance {
                has: *slot,
                needs: amount,
            });
        }
        *slot = check_sub(*slot, amount)?;
        return Ok(());
    }
    if let Some(slot) = account.asset.get_mut(key) {
        if *slot < amount {
            return Err(ActuatorError::InsufficientAssetBalance {
                has: *slot,
                needs: amount,
            });
        }
        *slot = check_sub(*slot, amount)?;
        return Ok(());
    }
    Err(ActuatorError::InsufficientAssetBalance {
        has: 0,
        needs: amount,
    })
}

fn credit_asset(
    account: &mut tron_proto::Account,
    key: &str,
    amount: i64,
) -> Result<(), ActuatorError> {
    let slot = account
        .asset_v2
        .entry(key.to_string())
        .or_insert(0);
    *slot = check_add(*slot, amount)?;
    Ok(())
}

#[allow(dead_code)]
fn _unused(_a: &Address) {}
