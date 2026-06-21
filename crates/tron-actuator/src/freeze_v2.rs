//! v2 Freeze actuators: FreezeBalanceV2, UnfreezeBalanceV2,
//! WithdrawExpireUnfreeze, CancelAllUnfreezeV2.
//!
//! Source: `FreezeBalanceV2Actuator`, `UnfreezeBalanceV2Actuator`,
//! `WithdrawExpireUnfreezeActuator`, `CancelAllUnfreezeV2Actuator`.

use tron_chainbase::{AccountStore, DelegationStore, DynamicPropertiesStore, VotesStore};
use tron_proto::account::{FreezeV2, UnFreezeV2};
use tron_proto::{
    Account, CancelAllUnfreezeV2Contract, FreezeBalanceV2Contract, UnfreezeBalanceV2Contract,
    WithdrawExpireUnfreezeContract,
};

use crate::freeze::{FROZEN_PERIOD_MS, TRX_PRECISION};
use crate::helpers::{check_add, check_sub, require_owner};
use crate::transfer::ExecutionResult;
use crate::ActuatorError;

/// `UNFREEZE_MAX_TIMES = 32` in java-tron. Caps the concurrent
/// in-progress unfreezes per account.
pub const UNFREEZE_MAX_TIMES: usize = 32;

fn require_unfreeze_delay(dyn_props: &DynamicPropertiesStore) -> Result<(), ActuatorError> {
    if dyn_props.get_long(b"UNFREEZE_DELAY_DAYS").unwrap_or(0) <= 0 {
        // ALLOW_UNFREEZE_DELAY proposal sets this to the delay-in-days.
        // 0 means the V2 path isn't enabled.
        return Err(ActuatorError::UnfreezeDelayDisabled);
    }
    Ok(())
}

fn unfreeze_delay_ms(dyn_props: &DynamicPropertiesStore) -> i64 {
    let days = dyn_props.get_long(b"UNFREEZE_DELAY_DAYS").unwrap_or(14);
    days * (FROZEN_PERIOD_MS / 3)
}

fn resource_valid(r: i32) -> bool {
    (0..=2).contains(&r)
}

// =============================================================================
// FreezeBalanceV2Actuator
// =============================================================================

pub fn validate_freeze_balance_v2(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &FreezeBalanceV2Contract,
) -> Result<(), ActuatorError> {
    require_unfreeze_delay(dyn_props)?;
    let owner = require_owner(&contract.owner_address)?;
    if contract.frozen_balance <= 0 || contract.frozen_balance < TRX_PRECISION {
        return Err(ActuatorError::FreezeTooSmall);
    }
    if !resource_valid(contract.resource) {
        return Err(ActuatorError::InvalidResourceCode);
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
    Ok(())
}

pub fn execute_freeze_balance_v2(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &FreezeBalanceV2Contract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let mut account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    account.balance = check_sub(account.balance, contract.frozen_balance)?;

    // Capture the old weight basis BEFORE mutating frozen_v2 — java-tron's
    // `getFrozenV2BalanceWithDelegated(resource)` (held + delegated-out).
    let old_basis = frozen_v2_with_delegated(&account, contract.resource);

    let slot = account
        .frozen_v2
        .iter_mut()
        .find(|f| f.r#type == contract.resource);
    match slot {
        Some(f) => f.amount = check_add(f.amount, contract.frozen_balance)?,
        None => account.frozen_v2.push(FreezeV2 {
            r#type: contract.resource,
            amount: contract.frozen_balance,
        }),
    }
    accounts.put(&owner, &account)?;

    // Update chain-wide TOTAL_*_WEIGHT — mirrors java-tron's
    // `FreezeBalanceV2Actuator.execute`:
    //   oldWeight = getFrozenV2BalanceWithDelegated(res) / TRX_PRECISION
    //   newWeight = (that + frozenBalance)             / TRX_PRECISION
    //   addTotal*Weight(newWeight - oldWeight)
    // The basis includes the delegated-out portion (freeze only grows the
    // held part, so `new = old + frozenBalance`).
    let new_basis = old_basis.saturating_add(contract.frozen_balance);
    let weight_delta = new_basis / TRX_PRECISION - old_basis / TRX_PRECISION;
    apply_weight_delta(dyn_props, contract.resource, weight_delta);
    if std::env::var("TRON_WTRACE").is_ok() {
        eprintln!("WTRACE op=freezeV2 owner={} res={} amount={} old_basis={} new_basis={} delta={} tew={} tnw={}",
            contract.owner_address.iter().map(|b| format!("{:02x}", b)).collect::<String>(), contract.resource, contract.frozen_balance, old_basis, new_basis, weight_delta,
            dyn_props.total_energy_weight(), dyn_props.total_net_weight());
    }
    Ok(ExecutionResult::default())
}

/// The weight *basis* for `resource` (0 = bandwidth, 1 = energy): the
/// account's held frozen-V2 for that resource **plus what it has delegated
/// out**. Mirrors java-tron's `AccountCapsule.getFrozenV2BalanceWithDelegated`
/// — the value `Freeze/UnfreezeBalanceV2Actuator` divides by `TRX_PRECISION`
/// to get the chain-weight contribution.
///
/// Using only the held `frozen_v2` (excluding the delegated portion) is a
/// **consensus bug**: because the weight is `floor(basis / TRX_PRECISION)`,
/// dropping the delegated amount shifts the rounding boundary, so every
/// freeze/unfreeze by an account that has delegated resources out computes a
/// different `floor(new) - floor(old)` delta than java-tron — and the
/// chain-global `TOTAL_*_WEIGHT` drifts (caught by `tron-state-diff`).
fn frozen_v2_with_delegated(account: &Account, resource: i32) -> i64 {
    let held: i64 = account
        .frozen_v2
        .iter()
        .filter(|f| f.r#type == resource)
        .map(|f| f.amount)
        .sum();
    let delegated = match resource {
        0 => account.delegated_frozen_v2_balance_for_bandwidth,
        1 => account
            .account_resource
            .as_ref()
            .map(|r| r.delegated_frozen_v2_balance_for_energy)
            .unwrap_or(0),
        _ => 0,
    };
    held.saturating_add(delegated)
}

/// Apply `delta` (TRX-unit weight) to the chain-wide weight accumulator
/// keyed by `resource`: 0 = BANDWIDTH (`TOTAL_NET_WEIGHT`), 1 = ENERGY
/// (`TOTAL_ENERGY_WEIGHT`), 2 = TRON_POWER (`TOTAL_TRON_POWER_WEIGHT`).
/// java-tron's `FreezeBalanceV2Actuator` updates all three (including
/// `addTotalTronPowerWeight` for voting power).
fn apply_weight_delta(dyn_props: &DynamicPropertiesStore, resource: i32, delta: i64) {
    if delta == 0 {
        return;
    }
    match resource {
        0 => dyn_props.add_total_net_weight(delta),
        1 => dyn_props.add_total_energy_weight(delta),
        2 => dyn_props.add_total_tron_power_weight(delta),
        _ => {}
    }
}

// =============================================================================
// UnfreezeBalanceV2Actuator
// =============================================================================

pub fn validate_unfreeze_balance_v2(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &UnfreezeBalanceV2Contract,
) -> Result<(), ActuatorError> {
    require_unfreeze_delay(dyn_props)?;
    let owner = require_owner(&contract.owner_address)?;
    if !resource_valid(contract.resource) {
        return Err(ActuatorError::InvalidResourceCode);
    }
    let account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    let frozen = account
        .frozen_v2
        .iter()
        .find(|f| f.r#type == contract.resource)
        .map(|f| f.amount)
        .unwrap_or(0);
    if frozen <= 0 {
        return Err(ActuatorError::NothingToUnfreeze);
    }
    if contract.unfreeze_balance <= 0 || contract.unfreeze_balance > frozen {
        return Err(ActuatorError::UnfreezeExceedsFrozen);
    }
    // java counts only UNEXPIRED entries against the cap
    // (`AccountCapsule.getUnfreezingV2Count(now)`): expired ones are
    // swept into balance by the execute below, so they don't occupy a
    // slot. Counting the raw list length rejected unstakes java accepts
    // whenever expired entries were still awaiting their sweep.
    let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);
    let unfreezing = account
        .unfrozen_v2
        .iter()
        .filter(|u| u.unfreeze_expire_time > now)
        .count();
    if unfreezing >= UNFREEZE_MAX_TIMES {
        return Err(ActuatorError::TooManyUnfreezes {
            max: UNFREEZE_MAX_TIMES,
        });
    }
    Ok(())
}

pub fn execute_unfreeze_balance_v2(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    votes_store: &VotesStore,
    delegation: &DelegationStore,
    reward_vi: Option<&tron_chainbase::RewardViStore>,
    contract: &UnfreezeBalanceV2Contract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;

    // java-tron settles pending voter rewards FIRST
    // (`mortgageService.withdrawReward` at the top of
    // `UnfreezeBalanceV2Actuator.execute`) — before the stake, and
    // therefore the vote list below, changes.
    tron_tvm::reward::withdraw_reward_actuator(&owner, accounts, delegation, dyn_props, reward_vi)?;

    let mut account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);

    // Sweep EXPIRED unfreeze entries into balance (java's
    // `unfreezeExpire`, run on every v2 unstake before the new entry is
    // added). Skipping this left expired entries parked in `unfrozen_v2`
    // until an explicit WithdrawExpireUnfreeze — diverging both the
    // balance and the unfrozen list from java for accounts that unstake
    // repeatedly. (java records the swept amount in the tx receipt's
    // `withdraw_expire_amount`; `ExecutionResult` doesn't carry receipt
    // fields yet — state effects are identical.)
    let mut swept = 0i64;
    account.unfrozen_v2.retain(|u| {
        if u.unfreeze_expire_time <= now {
            swept = swept.saturating_add(u.unfreeze_amount);
            false
        } else {
            true
        }
    });
    account.balance = check_add(account.balance, swept)?;

    // Capture the old weight basis BEFORE deducting — java-tron's
    // `getFrozenV2BalanceWithDelegated(resource)` (held + delegated-out).
    let old_basis = frozen_v2_with_delegated(&account, contract.resource);

    // Deduct from the resource-typed FreezeV2 entry.
    if let Some(slot) = account
        .frozen_v2
        .iter_mut()
        .find(|f| f.r#type == contract.resource)
    {
        slot.amount = check_sub(slot.amount, contract.unfreeze_balance)?;
    }
    let withdraw_expire = now + unfreeze_delay_ms(dyn_props);
    account.unfrozen_v2.push(UnFreezeV2 {
        r#type: contract.resource,
        unfreeze_amount: contract.unfreeze_balance,
        unfreeze_expire_time: withdraw_expire,
    });

    // Shrink chain-wide weight by the freed amount. Java-tron:
    //   oldWeight = getFrozenV2BalanceWithDelegated(res) / TRX_PRECISION
    //   newWeight = (that - unfreezeBalance)            / TRX_PRECISION
    //   addTotal*Weight(newWeight - oldWeight)  // negative
    let new_basis = old_basis.saturating_sub(contract.unfreeze_balance);
    let weight_delta = new_basis / TRX_PRECISION - old_basis / TRX_PRECISION;
    apply_weight_delta(dyn_props, contract.resource, weight_delta);
    if std::env::var("TRON_WTRACE").is_ok() {
        eprintln!("WTRACE op=unfreezeV2 owner={} res={} amount={} old_basis={} new_basis={} delta={} tew={} tnw={}",
            contract.owner_address.iter().map(|b| format!("{:02x}", b)).collect::<String>(), contract.resource, contract.unfreeze_balance, old_basis, new_basis, weight_delta,
            dyn_props.total_energy_weight(), dyn_props.total_net_weight());
    }

    // Trim votes the unstake no longer backs — java's `updateVote`
    // (proportional reduction when remaining TRON Power < voted total;
    // shared with the TVM unstake opcode, see `tron_tvm::votes`).
    // Without this, witness `vote_count`s stayed inflated after every
    // unstake-below-votes — java's count dropped at the next
    // maintenance, ours didn't.
    tron_tvm::votes::update_vote_after_unstake(votes_store, &owner, &mut account)?;

    accounts.put(&owner, &account)?;
    // java `UnfreezeBalanceV2Actuator.execute` sets `ret.setWithdrawExpireAmount(
    // unfreezeAmount)` (UnfreezeBalanceV2Actuator.java:98), where `unfreezeAmount`
    // is the expired-unfreeze balance swept to the owner by `unfreezeExpire`
    // (`swept` here) — NOT the just-unstaked `unfreezeBalance`. Surfaced as
    // TransactionInfo.withdraw_expire_amount.
    Ok(ExecutionResult {
        ret: crate::TransactionRetExtras {
            withdraw_expire_amount: swept,
            ..Default::default()
        },
        ..Default::default()
    })
}

// =============================================================================
// WithdrawExpireUnfreezeActuator
// =============================================================================

pub fn validate_withdraw_expire_unfreeze(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &WithdrawExpireUnfreezeContract,
) -> Result<(), ActuatorError> {
    require_unfreeze_delay(dyn_props)?;
    let owner = require_owner(&contract.owner_address)?;
    let account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);
    if !account
        .unfrozen_v2
        .iter()
        .any(|u| u.unfreeze_expire_time <= now)
    {
        return Err(ActuatorError::NoExpiredUnfreeze);
    }
    Ok(())
}

pub fn execute_withdraw_expire_unfreeze(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &WithdrawExpireUnfreezeContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let mut account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);

    let mut withdrawn = 0i64;
    account.unfrozen_v2.retain(|u| {
        if u.unfreeze_expire_time <= now {
            withdrawn = withdrawn.saturating_add(u.unfreeze_amount);
            false
        } else {
            true
        }
    });
    account.balance = check_add(account.balance, withdrawn)?;
    accounts.put(&owner, &account)?;
    // java `WithdrawExpireUnfreezeActuator.execute` sets
    // `ret.setWithdrawExpireAmount(totalWithdrawUnfreeze)`
    // (WithdrawExpireUnfreezeActuator.java:63) — the total expired-unfreeze
    // balance withdrawn. Surfaced as TransactionInfo.withdraw_expire_amount.
    Ok(ExecutionResult {
        ret: crate::TransactionRetExtras {
            withdraw_expire_amount: withdrawn,
            ..Default::default()
        },
        ..Default::default()
    })
}

// =============================================================================
// CancelAllUnfreezeV2Actuator
// =============================================================================

pub fn validate_cancel_all_unfreeze_v2(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &CancelAllUnfreezeV2Contract,
) -> Result<(), ActuatorError> {
    if dyn_props
        .get_long(b"ALLOW_CANCEL_ALL_UNFREEZE_V2")
        .unwrap_or(0)
        != 1
    {
        return Err(ActuatorError::UnfreezeDelayDisabled);
    }
    let owner = require_owner(&contract.owner_address)?;
    let account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    if account.unfrozen_v2.is_empty() {
        return Err(ActuatorError::NothingToUnfreeze);
    }
    Ok(())
}

pub fn execute_cancel_all_unfreeze_v2(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &CancelAllUnfreezeV2Contract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let mut account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);

    // Track restore-to-frozen amounts per resource so we can update
    // chain-wide weight in one pass. Expired-to-balance entries don't
    // change weight (they were already removed from frozen when
    // unfreeze_balance_v2 was called).
    let mut restored_net: i64 = 0;
    let mut restored_energy: i64 = 0;
    let mut restored_tron_power: i64 = 0;
    // Old weight basis = held frozen-V2 + delegated-out (java-tron's
    // `getFrozenV2BalanceWithDelegated`), captured before restoring.
    let old_net = frozen_v2_with_delegated(&account, 0);
    let old_energy = frozen_v2_with_delegated(&account, 1);
    let old_tron_power = frozen_v2_with_delegated(&account, 2);

    // Expired-unfreeze balance swept to the owner — java's
    // `atomicWithdrawExpireBalance` (CancelAllUnfreezeV2Actuator.java:60,108).
    let mut withdraw_expire: i64 = 0;

    let pending = std::mem::take(&mut account.unfrozen_v2);
    for entry in pending {
        if entry.unfreeze_expire_time <= now {
            // Expired → withdraw to balance.
            withdraw_expire = withdraw_expire.saturating_add(entry.unfreeze_amount);
            account.balance = check_add(account.balance, entry.unfreeze_amount)?;
        } else {
            // Not yet expired → restore to FreezeV2 of the same resource type.
            match entry.r#type {
                0 => restored_net = restored_net.saturating_add(entry.unfreeze_amount),
                1 => restored_energy = restored_energy.saturating_add(entry.unfreeze_amount),
                2 => restored_tron_power = restored_tron_power.saturating_add(entry.unfreeze_amount),
                _ => {}
            }
            match account
                .frozen_v2
                .iter_mut()
                .find(|f| f.r#type == entry.r#type)
            {
                Some(slot) => slot.amount = check_add(slot.amount, entry.unfreeze_amount)?,
                None => account.frozen_v2.push(FreezeV2 {
                    r#type: entry.r#type,
                    amount: entry.unfreeze_amount,
                }),
            }
        }
    }
    accounts.put(&owner, &account)?;

    // Bump chain-wide weight for any restored entries (all three resources).
    let net_delta = (old_net + restored_net) / TRX_PRECISION - old_net / TRX_PRECISION;
    let energy_delta = (old_energy + restored_energy) / TRX_PRECISION - old_energy / TRX_PRECISION;
    let tp_delta =
        (old_tron_power + restored_tron_power) / TRX_PRECISION - old_tron_power / TRX_PRECISION;
    apply_weight_delta(dyn_props, 0, net_delta);
    apply_weight_delta(dyn_props, 1, energy_delta);
    apply_weight_delta(dyn_props, 2, tp_delta);
    if std::env::var("TRON_WTRACE").is_ok() {
        eprintln!("WTRACE op=cancelV2 owner={} restored_net={} restored_energy={} old_net={} old_energy={} net_delta={} energy_delta={} tew={} tnw={}",
            contract.owner_address.iter().map(|b| format!("{:02x}", b)).collect::<String>(), restored_net, restored_energy, old_net, old_energy, net_delta, energy_delta,
            dyn_props.total_energy_weight(), dyn_props.total_net_weight());
    }

    // java `CancelAllUnfreezeV2Actuator.execute`:
    //   ret.setWithdrawExpireAmount(withdrawExpireBalance)        // line 83
    //   ret.putAllCancelUnfreezeV2AmountMap(cancelUnfreezeV2AmountMap)  // line 88
    // where the map keys are the ResourceCode enum names and the values are
    // the per-resource amounts restored to frozen-V2 (the triple's "number of
    // unfreeze resources" = `restored_*` here). All three keys are written
    // unconditionally, even when the value is 0.
    let mut cancel_unfreeze_v2_amount = std::collections::BTreeMap::new();
    cancel_unfreeze_v2_amount.insert("BANDWIDTH".to_string(), restored_net);
    cancel_unfreeze_v2_amount.insert("ENERGY".to_string(), restored_energy);
    cancel_unfreeze_v2_amount.insert("TRON_POWER".to_string(), restored_tron_power);

    Ok(ExecutionResult {
        ret: crate::TransactionRetExtras {
            withdraw_expire_amount: withdraw_expire,
            cancel_unfreeze_v2_amount,
            ..Default::default()
        },
        ..Default::default()
    })
}
