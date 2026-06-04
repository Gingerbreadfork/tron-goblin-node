//! Resource delegation actuators: DelegateResource, UnDelegateResource.
//!
//! Source: `DelegateResourceActuator`, `UnDelegateResourceActuator`.
//!
//! These let an owner lend their frozen-V2 bandwidth/energy capacity to
//! another account without giving up ownership of the underlying TRX.

use tron_chainbase::{
    AccountStore, DelegatedResourceStore, DynamicPropertiesStore,
};
use tron_proto::{DelegateResourceContract, DelegatedResource, UnDelegateResourceContract};

use crate::freeze::TRX_PRECISION;
use crate::helpers::{check_add, check_sub, require_owner, require_to};
use crate::transfer::ExecutionResult;
use crate::ActuatorError;

fn require_delegation_enabled(dyn_props: &DynamicPropertiesStore) -> Result<(), ActuatorError> {
    if dyn_props.get_long(b"ALLOW_DELEGATE_RESOURCE").unwrap_or(0) != 1
        || dyn_props.get_long(b"UNFREEZE_DELAY_DAYS").unwrap_or(0) <= 0
    {
        return Err(ActuatorError::DelegationDisabled);
    }
    Ok(())
}

fn resource_valid(r: i32) -> bool {
    r == 0 || r == 1 // BANDWIDTH or ENERGY (TRON_POWER cannot be delegated)
}

// =============================================================================
// DelegateResourceActuator
// =============================================================================

pub fn validate_delegate_resource(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &DelegateResourceContract,
) -> Result<(), ActuatorError> {
    require_delegation_enabled(dyn_props)?;
    let owner = require_owner(&contract.owner_address)?;
    let to = require_to(&contract.receiver_address)?;
    if owner == to {
        return Err(ActuatorError::InvalidDelegationReceiver);
    }
    if contract.balance < TRX_PRECISION {
        return Err(ActuatorError::FreezeTooSmall);
    }
    if !resource_valid(contract.resource) {
        return Err(ActuatorError::InvalidResourceCode);
    }
    let owner_account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    let frozen = owner_account
        .frozen_v2
        .iter()
        .find(|f| f.r#type == contract.resource)
        .map(|f| f.amount)
        .unwrap_or(0);
    if frozen < contract.balance {
        return Err(ActuatorError::InsufficientBalance {
            balance: frozen,
            needed: contract.balance,
        });
    }
    let to_account = accounts
        .get(&to)?
        .ok_or(ActuatorError::TargetAccountMissing)?;
    if to_account.r#type == tron_proto::AccountType::Contract as i32 {
        return Err(ActuatorError::DelegationToContract);
    }
    Ok(())
}

pub fn execute_delegate_resource(
    accounts: &AccountStore,
    resources: &DelegatedResourceStore,
    contract: &DelegateResourceContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let to = require_to(&contract.receiver_address)?;

    // 1. Debit owner's frozen-V2 pool.
    let mut owner_account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    if let Some(slot) = owner_account
        .frozen_v2
        .iter_mut()
        .find(|f| f.r#type == contract.resource)
    {
        slot.amount = check_sub(slot.amount, contract.balance)?;
    }

    // 2. Credit owner's `delegated_*_for_*` bookkeeping fields.
    match contract.resource {
        0 => {
            owner_account.delegated_frozen_v2_balance_for_bandwidth = check_add(
                owner_account.delegated_frozen_v2_balance_for_bandwidth,
                contract.balance,
            )?;
        }
        1 => {
            let r = owner_account
                .account_resource
                .get_or_insert_with(Default::default);
            r.delegated_frozen_v2_balance_for_energy =
                check_add(r.delegated_frozen_v2_balance_for_energy, contract.balance)?;
        }
        _ => unreachable!(),
    }
    accounts.put(&owner, &owner_account)?;

    // 3. Credit recipient's `acquired_*` bookkeeping fields.
    let mut to_account = accounts
        .get(&to)?
        .ok_or(ActuatorError::TargetAccountMissing)?;
    match contract.resource {
        0 => {
            to_account.acquired_delegated_frozen_v2_balance_for_bandwidth = check_add(
                to_account.acquired_delegated_frozen_v2_balance_for_bandwidth,
                contract.balance,
            )?;
        }
        1 => {
            let r = to_account
                .account_resource
                .get_or_insert_with(Default::default);
            r.acquired_delegated_frozen_v2_balance_for_energy =
                check_add(r.acquired_delegated_frozen_v2_balance_for_energy, contract.balance)?;
        }
        _ => unreachable!(),
    }
    accounts.put(&to, &to_account)?;

    // 4. Update DelegatedResourceStore with the per-(from,to) record.
    let key = DelegatedResourceStore::v2_unlocked_key(&owner, &to);
    let mut resource = resources.get_raw(&key)?.unwrap_or_else(|| DelegatedResource {
        from: owner.as_bytes().to_vec(),
        to: to.as_bytes().to_vec(),
        ..Default::default()
    });
    match contract.resource {
        0 => {
            resource.frozen_balance_for_bandwidth =
                check_add(resource.frozen_balance_for_bandwidth, contract.balance)?;
        }
        1 => {
            resource.frozen_balance_for_energy =
                check_add(resource.frozen_balance_for_energy, contract.balance)?;
        }
        _ => unreachable!(),
    }
    resources.put_raw(&key, &resource)?;

    Ok(ExecutionResult::default())
}

// =============================================================================
// UnDelegateResourceActuator
// =============================================================================

pub fn validate_undelegate_resource(
    accounts: &AccountStore,
    resources: &DelegatedResourceStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &UnDelegateResourceContract,
) -> Result<(), ActuatorError> {
    require_delegation_enabled(dyn_props)?;
    let owner = require_owner(&contract.owner_address)?;
    let to = require_to(&contract.receiver_address)?;
    if owner == to {
        return Err(ActuatorError::InvalidDelegationReceiver);
    }
    if contract.balance <= 0 {
        return Err(ActuatorError::NonPositiveAmount);
    }
    if accounts.get(&owner)?.is_none() {
        return Err(ActuatorError::OwnerAccountMissing);
    }
    if !resource_valid(contract.resource) {
        return Err(ActuatorError::InvalidResourceCode);
    }
    let key = DelegatedResourceStore::v2_unlocked_key(&owner, &to);
    let resource = resources
        .get_raw(&key)?
        .ok_or(ActuatorError::NothingToUndelegate)?;
    let available = match contract.resource {
        0 => resource.frozen_balance_for_bandwidth,
        1 => resource.frozen_balance_for_energy,
        _ => 0,
    };
    if available < contract.balance {
        return Err(ActuatorError::InsufficientBalance {
            balance: available,
            needed: contract.balance,
        });
    }
    Ok(())
}

pub fn execute_undelegate_resource(
    accounts: &AccountStore,
    resources: &DelegatedResourceStore,
    contract: &UnDelegateResourceContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let to = require_to(&contract.receiver_address)?;

    // 1. Decrement the per-(owner, to) record.
    let key = DelegatedResourceStore::v2_unlocked_key(&owner, &to);
    let mut resource = resources
        .get_raw(&key)?
        .ok_or(ActuatorError::NothingToUndelegate)?;
    match contract.resource {
        0 => {
            resource.frozen_balance_for_bandwidth =
                check_sub(resource.frozen_balance_for_bandwidth, contract.balance)?;
        }
        1 => {
            resource.frozen_balance_for_energy =
                check_sub(resource.frozen_balance_for_energy, contract.balance)?;
        }
        _ => unreachable!(),
    }
    if resource.frozen_balance_for_bandwidth == 0 && resource.frozen_balance_for_energy == 0 {
        resources.delete_raw(&key)?;
    } else {
        resources.put_raw(&key, &resource)?;
    }

    // 2. Decrement owner's `delegated_*` and credit owner's `frozen_v2`.
    let mut owner_account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    match contract.resource {
        0 => {
            owner_account.delegated_frozen_v2_balance_for_bandwidth = check_sub(
                owner_account.delegated_frozen_v2_balance_for_bandwidth,
                contract.balance,
            )?;
        }
        1 => {
            let r = owner_account
                .account_resource
                .get_or_insert_with(Default::default);
            r.delegated_frozen_v2_balance_for_energy =
                check_sub(r.delegated_frozen_v2_balance_for_energy, contract.balance)?;
        }
        _ => unreachable!(),
    }
    match owner_account
        .frozen_v2
        .iter_mut()
        .find(|f| f.r#type == contract.resource)
    {
        Some(slot) => slot.amount = check_add(slot.amount, contract.balance)?,
        None => owner_account.frozen_v2.push(tron_proto::account::FreezeV2 {
            r#type: contract.resource,
            amount: contract.balance,
        }),
    }
    accounts.put(&owner, &owner_account)?;

    // 3. Decrement recipient's `acquired_*`.
    let mut to_account = accounts
        .get(&to)?
        .ok_or(ActuatorError::TargetAccountMissing)?;
    match contract.resource {
        0 => {
            to_account.acquired_delegated_frozen_v2_balance_for_bandwidth = check_sub(
                to_account.acquired_delegated_frozen_v2_balance_for_bandwidth,
                contract.balance,
            )?;
        }
        1 => {
            let r = to_account
                .account_resource
                .get_or_insert_with(Default::default);
            r.acquired_delegated_frozen_v2_balance_for_energy =
                check_sub(r.acquired_delegated_frozen_v2_balance_for_energy, contract.balance)?;
        }
        _ => unreachable!(),
    }
    accounts.put(&to, &to_account)?;

    Ok(ExecutionResult::default())
}
