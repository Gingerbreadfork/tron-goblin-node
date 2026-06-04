//! v1 Freeze actuators (deprecated): FreezeBalance, UnfreezeBalance.
//!
//! These are deprecated since the V2 resource model rolled out; new
//! transactions should use [`crate::freeze_v2`]. We implement them at
//! minimal fidelity (basic validation + account-level balance moves)
//! since they're still accepted on-chain for backwards compatibility.
//!
//! Sources: `FreezeBalanceActuator`, `UnfreezeBalanceActuator`.

use tron_chainbase::{AccountStore, DynamicPropertiesStore};
use tron_proto::account::Frozen;
use tron_proto::{FreezeBalanceContract, UnfreezeBalanceContract};

use crate::helpers::{check_add, check_sub, require_owner};
use crate::transfer::ExecutionResult;
use crate::ActuatorError;

/// 1 TRX = 1,000,000 sun. Smallest freeze amount.
pub const TRX_PRECISION: i64 = 1_000_000;
/// 3 days in **milliseconds** — minimum freeze duration.
pub const FROZEN_PERIOD_MS: i64 = 3 * 24 * 60 * 60 * 1000;

// =============================================================================
// FreezeBalanceActuator (v1)
// =============================================================================

pub fn validate_freeze_balance(
    accounts: &AccountStore,
    contract: &FreezeBalanceContract,
) -> Result<(), ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    if contract.frozen_balance <= 0 || contract.frozen_balance < TRX_PRECISION {
        return Err(ActuatorError::FreezeTooSmall);
    }
    let account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    if account.balance < contract.frozen_balance {
        return Err(ActuatorError::InsufficientBalance {
            balance: account.balance,
            needed: contract.frozen_balance,
        });
    }
    // Resource code 0=BANDWIDTH, 1=ENERGY, 2=TRON_POWER (per ResourceCode enum).
    if contract.resource < 0 || contract.resource > 2 {
        return Err(ActuatorError::InvalidResourceCode);
    }
    Ok(())
}

pub fn execute_freeze_balance(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &FreezeBalanceContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let mut account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    account.balance = check_sub(account.balance, contract.frozen_balance)?;

    let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);
    let expire = now + contract.frozen_duration * FROZEN_PERIOD_MS / 3; // duration is in days; we treat 1 = 3-day base
    let new_frozen = Frozen {
        frozen_balance: contract.frozen_balance,
        expire_time: expire,
    };
    // Coalesce into the single legacy `frozen` entry (java-tron keeps at
    // most 1 there).
    if let Some(existing) = account.frozen.first_mut() {
        existing.frozen_balance = check_add(existing.frozen_balance, contract.frozen_balance)?;
        existing.expire_time = expire;
    } else {
        account.frozen.push(new_frozen);
    }
    accounts.put(&owner, &account)?;

    // Bump chain-wide weight. java-tron's `FreezeBalanceActuator.execute`:
    //   weight = freezeBalance / TRX_PRECISION
    //   addTotalNetWeight(weight) for BANDWIDTH (resource=0)
    //   addTotalEnergyWeight(weight) for ENERGY (resource=1)
    // (Unlike v2, v1 doesn't compute oldWeight — it just adds the full
    // newly-frozen weight since v1 freezes are append-style with a
    // single rolling timer.)
    let weight = contract.frozen_balance / TRX_PRECISION;
    match contract.resource {
        0 => dyn_props.add_total_net_weight(weight),
        1 => dyn_props.add_total_energy_weight(weight),
        _ => {}
    }

    Ok(ExecutionResult::default())
}

// =============================================================================
// UnfreezeBalanceActuator (v1)
// =============================================================================

pub fn validate_unfreeze_balance(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &UnfreezeBalanceContract,
) -> Result<(), ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    if account.frozen.is_empty() {
        return Err(ActuatorError::NothingToUnfreeze);
    }
    let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);
    if !account.frozen.iter().any(|f| f.expire_time <= now) {
        return Err(ActuatorError::NothingToUnfreeze);
    }
    Ok(())
}

pub fn execute_unfreeze_balance(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &UnfreezeBalanceContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let mut account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);

    // v1 unfreeze branches on `contract.resource`: bandwidth pulls from
    // `account.frozen`, energy pulls from
    // `account.account_resource.frozen_balance_for_energy`. We only model
    // the bandwidth path here — v1 energy unfreeze (`resource=1`) is rare
    // (mostly happens on the migration boundary to v2) and pinned as a
    // separate gap. Bumping TOTAL_ENERGY_WEIGHT for that path would
    // require touching the AccountResource frozen entry too.
    let mut unlocked = 0i64;
    account.frozen.retain(|f| {
        if f.expire_time <= now {
            unlocked = unlocked.saturating_add(f.frozen_balance);
            false
        } else {
            true
        }
    });
    account.balance = check_add(account.balance, unlocked)?;
    accounts.put(&owner, &account)?;

    // Shrink chain-wide weight by the unlocked amount, for the
    // resource declared on the contract.
    let weight = unlocked / TRX_PRECISION;
    match contract.resource {
        0 => dyn_props.add_total_net_weight(-weight),
        1 => dyn_props.add_total_energy_weight(-weight),
        _ => {}
    }

    Ok(ExecutionResult::default())
}
