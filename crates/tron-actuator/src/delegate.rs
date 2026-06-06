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
    // java-tron's UnDelegateResourceActuator.validate reads BOTH the
    // unlocked and the locked record and counts the locked balance once
    // its per-resource lock has expired (`expire < now`). Reading only the
    // unlocked record wrongly rejected every undelegate of a still-recorded
    // *locked* (e.g. snapshot-imported) delegation as "nothing to
    // undelegate" — a mempool-reject flood and a silent execute-time state
    // divergence (TRON headers carry no state root). `unLockExpireResource`
    // in execute then folds the expired-locked balance into the unlocked
    // record before drawing on it.
    let unlocked = resources.get_raw(&DelegatedResourceStore::v2_unlocked_key(&owner, &to))?;
    let locked = resources.get_raw(&DelegatedResourceStore::v2_locked_key(&owner, &to))?;
    if unlocked.is_none() && locked.is_none() {
        return Err(ActuatorError::NothingToUndelegate);
    }
    let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);
    let available =
        undelegatable_balance(unlocked.as_ref(), locked.as_ref(), contract.resource, now);
    if available < contract.balance {
        return Err(ActuatorError::InsufficientBalance {
            balance: available,
            needed: contract.balance,
        });
    }
    Ok(())
}

/// Undelegate-able balance for `resource` (0 = bandwidth, 1 = energy): the
/// unlocked record's frozen balance plus the locked record's, but the
/// locked part only once its per-resource lock has expired. Mirrors
/// java-tron's `UnDelegateResourceActuator.validate`.
fn undelegatable_balance(
    unlocked: Option<&DelegatedResource>,
    locked: Option<&DelegatedResource>,
    resource: i32,
    now: i64,
) -> i64 {
    let mut total = 0i64;
    match resource {
        0 => {
            if let Some(u) = unlocked {
                total += u.frozen_balance_for_bandwidth;
            }
            if let Some(l) = locked {
                if l.expire_time_for_bandwidth < now {
                    total += l.frozen_balance_for_bandwidth;
                }
            }
        }
        1 => {
            if let Some(u) = unlocked {
                total += u.frozen_balance_for_energy;
            }
            if let Some(l) = locked {
                if l.expire_time_for_energy < now {
                    total += l.frozen_balance_for_energy;
                }
            }
        }
        _ => {}
    }
    total
}

pub fn execute_undelegate_resource(
    accounts: &AccountStore,
    resources: &DelegatedResourceStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &UnDelegateResourceContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let to = require_to(&contract.receiver_address)?;

    // 0. Fold any expired *locked* delegation into the unlocked record
    //    before drawing on it — java-tron's
    //    `DelegatedResourceStore.unLockExpireResource`. Without this an
    //    undelegate of a once-locked (now-expired) delegation fails as
    //    "nothing to undelegate" and our delegated-resource state silently
    //    diverges from java-tron.
    let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);
    resources.unlock_expire_resource(&owner, &to, now)?;

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

    // 3. Decrement recipient's `acquired_*`. java-tron guards the entire
    //    receiver update with `if (receiverCapsule != null)` — a receiver
    //    whose account was since deleted is simply skipped, not an error.
    if let Some(mut to_account) = accounts.get(&to)? {
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
                r.acquired_delegated_frozen_v2_balance_for_energy = check_sub(
                    r.acquired_delegated_frozen_v2_balance_for_energy,
                    contract.balance,
                )?;
            }
            _ => unreachable!(),
        }
        accounts.put(&to, &to_account)?;
    }

    Ok(ExecutionResult::default())
}
