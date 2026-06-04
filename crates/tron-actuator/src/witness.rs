//! Witness-related actuators: WitnessCreate, WitnessUpdate, UpdateBrokerage,
//! WithdrawBalance.
//!
//! Sources: `WitnessCreateActuator`, `WitnessUpdateActuator`,
//! `UpdateBrokerageActuator`, `WithdrawBalanceActuator`.

use tron_chainbase::{AccountStore, DelegationStore, DynamicPropertiesStore, WitnessStore};
use tron_proto::{
    UpdateBrokerageContract, Witness, WitnessCreateContract, WitnessUpdateContract,
    WithdrawBalanceContract,
};

use crate::helpers::{check_sub, require_owner};
use crate::transfer::ExecutionResult;
use crate::ActuatorError;

/// 24h in **milliseconds** — the cooldown between SR reward withdrawals.
/// Sourced from `ChainConstant.WITNESS_ALLOWANCE_FROZEN_TIME` (24 hours).
pub const WITNESS_ALLOWANCE_FROZEN_TIME_MS: i64 = 24 * 60 * 60 * 1000;

/// Maximum URL length for a witness (256 bytes). Sourced from
/// `TransactionUtil.validUrl`.
pub const MAX_URL_BYTES: usize = 256;

/// URL validation: non-empty and ≤ [`MAX_URL_BYTES`]. java-tron is more
/// permissive than the docs suggest — it just checks `0 < len <= 256`.
pub fn url_valid(url: &[u8]) -> bool {
    !url.is_empty() && url.len() <= MAX_URL_BYTES
}

// =============================================================================
// WitnessCreateActuator
// =============================================================================

pub fn validate_witness_create(
    accounts: &AccountStore,
    witnesses: &WitnessStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &WitnessCreateContract,
) -> Result<(), ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    if !url_valid(&contract.url) {
        return Err(ActuatorError::InvalidUrl);
    }
    let owner_account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    if witnesses.contains(&owner)? {
        return Err(ActuatorError::WitnessAlreadyExists);
    }
    let fee = dyn_props
        .get_long(b"ACCOUNT_UPGRADE_COST")
        .unwrap_or(9_999_000_000); // 9999 TRX — mainnet default
    if owner_account.balance < fee {
        return Err(ActuatorError::InsufficientBalance {
            balance: owner_account.balance,
            needed: fee,
        });
    }
    Ok(())
}

pub fn execute_witness_create(
    accounts: &AccountStore,
    witnesses: &WitnessStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &WitnessCreateContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let mut owner_account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;

    let fee = dyn_props
        .get_long(b"ACCOUNT_UPGRADE_COST")
        .unwrap_or(9_999_000_000);
    owner_account.balance = check_sub(owner_account.balance, fee)?;
    owner_account.is_witness = true;
    accounts.put(&owner, &owner_account)?;

    let witness = Witness {
        address: owner.as_bytes().to_vec(),
        vote_count: 0,
        pub_key: Vec::new(),
        url: String::from_utf8_lossy(&contract.url).into_owned(),
        total_produced: 0,
        total_missed: 0,
        latest_block_num: 0,
        latest_slot_num: 0,
        is_jobs: false,
    };
    witnesses.put(&owner, &witness)?;

    Ok(ExecutionResult {
        fee,
        created_recipient: false,
    })
}

// =============================================================================
// WitnessUpdateActuator
// =============================================================================

pub fn validate_witness_update(
    accounts: &AccountStore,
    witnesses: &WitnessStore,
    contract: &WitnessUpdateContract,
) -> Result<(), ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    if !url_valid(&contract.update_url) {
        return Err(ActuatorError::InvalidUrl);
    }
    if accounts.get(&owner)?.is_none() {
        return Err(ActuatorError::OwnerAccountMissing);
    }
    if !witnesses.contains(&owner)? {
        return Err(ActuatorError::WitnessMissing);
    }
    Ok(())
}

pub fn execute_witness_update(
    witnesses: &WitnessStore,
    contract: &WitnessUpdateContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let mut witness = witnesses
        .get(&owner)?
        .ok_or(ActuatorError::WitnessMissing)?;
    witness.url = String::from_utf8_lossy(&contract.update_url).into_owned();
    witnesses.put(&owner, &witness)?;
    Ok(ExecutionResult::default())
}

// =============================================================================
// UpdateBrokerageActuator
// =============================================================================

pub fn validate_update_brokerage(
    accounts: &AccountStore,
    witnesses: &WitnessStore,
    contract: &UpdateBrokerageContract,
) -> Result<(), ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    if contract.brokerage < 0 || contract.brokerage > 100 {
        return Err(ActuatorError::BrokerageOutOfRange);
    }
    if accounts.get(&owner)?.is_none() {
        return Err(ActuatorError::OwnerAccountMissing);
    }
    if !witnesses.contains(&owner)? {
        return Err(ActuatorError::WitnessMissing);
    }
    Ok(())
}

pub fn execute_update_brokerage(
    delegation: &DelegationStore,
    contract: &UpdateBrokerageContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    delegation.set_brokerage_global(&owner, contract.brokerage);
    Ok(ExecutionResult::default())
}

// =============================================================================
// WithdrawBalanceActuator
// =============================================================================
//
// **Deferred**: `MortgageService.withdrawReward` (computes accumulated
// voter rewards and adds them to `allowance`) is not yet ported. This
// implementation only drains an existing `allowance` field — sufficient
// for SRs claiming block production rewards but missing the voter-side
// reward computation.

pub fn validate_withdraw_balance(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &WithdrawBalanceContract,
) -> Result<(), ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;

    let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);
    let ready_at = account.latest_withdraw_time + WITNESS_ALLOWANCE_FROZEN_TIME_MS;
    if account.latest_withdraw_time > 0 && now < ready_at {
        return Err(ActuatorError::WithdrawTooSoon { ready_at, now });
    }
    if account.allowance == 0 {
        return Err(ActuatorError::NoAllowance);
    }
    Ok(())
}

pub fn execute_withdraw_balance(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &WithdrawBalanceContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let mut account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;

    let allowance = account.allowance;
    account.balance = account
        .balance
        .checked_add(allowance)
        .ok_or(ActuatorError::Overflow)?;
    account.allowance = 0;
    account.latest_withdraw_time = dyn_props.latest_block_header_timestamp().unwrap_or(0);
    accounts.put(&owner, &account)?;

    Ok(ExecutionResult::default())
}
