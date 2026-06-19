//! Resource delegation actuators: DelegateResource, UnDelegateResource.
//!
//! Source: `DelegateResourceActuator`, `UnDelegateResourceActuator`.
//!
//! These let an owner lend their frozen-V2 bandwidth/energy capacity to
//! another account without giving up ownership of the underlying TRX.

use tron_chainbase::{
    AccountStore, DelegatedResourceAccountIndexStore, DelegatedResourceStore,
    DynamicPropertiesStore,
};
use tron_proto::{
    Account, DelegateResourceContract, DelegatedResource, UnDelegateResourceContract,
};
use tron_types::resource::{
    all_frozen_balance_for_bandwidth, all_frozen_balance_for_energy, delegatable_frozen_v2,
    set_latest_time, set_usage, undelegate_increase, update_usage, usage, ResourceGates,
    ResourceKind,
};

use crate::freeze::TRX_PRECISION;
use crate::helpers::{check_add, check_sub, require_owner, require_to};
use crate::transfer::ExecutionResult;
use crate::ActuatorError;

/// Map the contract's resource code (0 = bandwidth, 1 = energy) to the
/// shared [`ResourceKind`].
fn resource_kind(resource: i32) -> ResourceKind {
    if resource == 0 {
        ResourceKind::Bandwidth
    } else {
        ResourceKind::Energy
    }
}

/// java-tron `AccountCapsule.getAcquiredDelegatedFrozenV2BalanceFor{Bandwidth,
/// Energy}` — the v2 balance this account has *received* from delegators.
fn acquired_delegated_v2(account: &Account, kind: ResourceKind) -> i64 {
    match kind {
        ResourceKind::Bandwidth => account.acquired_delegated_frozen_v2_balance_for_bandwidth,
        ResourceKind::Energy => account
            .account_resource
            .as_ref()
            .map(|r| r.acquired_delegated_frozen_v2_balance_for_energy)
            .unwrap_or(0),
    }
}

fn set_acquired_delegated_v2(account: &mut Account, kind: ResourceKind, v: i64) {
    match kind {
        ResourceKind::Bandwidth => account.acquired_delegated_frozen_v2_balance_for_bandwidth = v,
        ResourceKind::Energy => {
            account
                .account_resource
                .get_or_insert_with(Default::default)
                .acquired_delegated_frozen_v2_balance_for_energy = v;
        }
    }
}

fn resource_gates(dyn_props: &DynamicPropertiesStore) -> ResourceGates {
    ResourceGates {
        support_unfreeze_delay: dyn_props.support_unfreeze_delay(),
        support_allow_cancel_all_unfreeze_v2: dyn_props.support_allow_cancel_all_unfreeze_v2(),
    }
}

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

/// `ChainConstant.BLOCK_PRODUCED_INTERVAL` — 3 s, in ms.
const BLOCK_PRODUCED_INTERVAL: i64 = 3000;
/// `ChainConstant.DELEGATE_PERIOD` — the default lock duration, 3 days in ms.
const DELEGATE_PERIOD_MS: i64 = 3 * 86_400_000;
/// Default lock period in *blocks*: `DELEGATE_PERIOD / BLOCK_PRODUCED_INTERVAL`
/// = 86 400. Used both as the `lockPeriod==0` default and as the baseline
/// that `supportMaxDelegateLockPeriod` compares against.
const DEFAULT_LOCK_PERIOD_BLOCKS: i64 = DELEGATE_PERIOD_MS / BLOCK_PRODUCED_INTERVAL;

/// `DynamicPropertiesStore.getMaxDelegateLockPeriod` — the committee-set
/// cap on a delegation's lock period (in blocks); defaults to the baseline
/// 86 400 when the proposal hasn't set `MAX_DELEGATE_LOCK_PERIOD`.
fn max_delegate_lock_period(dyn_props: &DynamicPropertiesStore) -> i64 {
    dyn_props
        .get_long(b"MAX_DELEGATE_LOCK_PERIOD")
        .unwrap_or(DEFAULT_LOCK_PERIOD_BLOCKS)
}

/// `DynamicPropertiesStore.supportMaxDelegateLockPeriod` — the lock-period
/// feature is live once the committee raised `MAX_DELEGATE_LOCK_PERIOD`
/// above the baseline AND unfreeze-delay is on (mainnet: true).
fn support_max_delegate_lock_period(dyn_props: &DynamicPropertiesStore) -> bool {
    max_delegate_lock_period(dyn_props) > DEFAULT_LOCK_PERIOD_BLOCKS
        && dyn_props.get_long(b"UNFREEZE_DELAY_DAYS").unwrap_or(0) > 0
}

/// `DelegateResourceActuator.getLockPeriod` — the lock period (in blocks)
/// applied to a `lock = true` delegation. With the feature live a zero
/// `lock_period` means "use the 3-day default"; without it the contract's
/// value is ignored and the default is always used.
fn resolved_lock_period(dyn_props: &DynamicPropertiesStore, contract_lock_period: i64) -> i64 {
    if support_max_delegate_lock_period(dyn_props) {
        if contract_lock_period == 0 {
            DEFAULT_LOCK_PERIOD_BLOCKS
        } else {
            contract_lock_period
        }
    } else {
        DEFAULT_LOCK_PERIOD_BLOCKS
    }
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
    // java `DelegateResourceActuator.validate`: the delegatable amount is the
    // owner's frozen-V2 pool MINUS the usage that pool currently backs
    // (`getFrozenV2BalanceFor{Bandwidth,Energy}() - getV2{Net,Energy}Usage`),
    // not the raw frozen-V2 pool. Mirrors the TVM `DELEGATERESOURCE` opcode
    // path (`DelegateResourceProcessor.validate`).
    let kind = resource_kind(contract.resource);
    let (total_limit, total_weight) = match kind {
        ResourceKind::Bandwidth => (dyn_props.total_net_limit(), dyn_props.total_net_weight()),
        ResourceKind::Energy => (
            dyn_props.total_energy_current_limit(),
            dyn_props.total_energy_weight(),
        ),
    };
    let available = delegatable_frozen_v2(
        &owner_account,
        kind,
        dyn_props.head_slot(),
        total_weight,
        total_limit,
        ResourceGates {
            support_unfreeze_delay: dyn_props.support_unfreeze_delay(),
            support_allow_cancel_all_unfreeze_v2: dyn_props.support_allow_cancel_all_unfreeze_v2(),
        },
        dyn_props.allow_harden_resource_calculation(),
    );
    if available < contract.balance {
        return Err(ActuatorError::InsufficientBalance {
            balance: available,
            needed: contract.balance,
        });
    }
    let to_account = accounts
        .get(&to)?
        .ok_or(ActuatorError::TargetAccountMissing)?;
    if to_account.r#type == tron_proto::AccountType::Contract as i32 {
        return Err(ActuatorError::DelegationToContract);
    }
    // java-tron bounds the requested lock period once the feature is live.
    if support_max_delegate_lock_period(dyn_props) {
        let max = max_delegate_lock_period(dyn_props);
        if contract.lock_period < 0 || contract.lock_period > max {
            return Err(ActuatorError::Validate(
                "lock period must be in 0..=maxDelegateLockPeriod",
            ));
        }
    }
    Ok(())
}

pub fn execute_delegate_resource(
    accounts: &AccountStore,
    resources: &DelegatedResourceStore,
    index: Option<&DelegatedResourceAccountIndexStore>,
    dyn_props: &DynamicPropertiesStore,
    contract: &DelegateResourceContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let to = require_to(&contract.receiver_address)?;
    let now_ts = dyn_props.latest_block_header_timestamp().unwrap_or(0);

    // 0. Unlock any expired locked delegation first — java-tron's
    //    `delegateResource` calls `unLockExpireResource` before reading the
    //    per-(from,to) record, so an expired locked record is folded into
    //    the unlocked record before the new balance is added.
    resources.unlock_expire_resource(&owner, &to, now_ts)?;

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
    //    java-tron stores a `lock = true` delegation under the LOCKED key
    //    (0x02) with a per-resource expiry of `now + lockPeriod *
    //    BLOCK_PRODUCED_INTERVAL`; an unlocked delegation goes under the
    //    UNLOCKED key (0x01) with expiry 0. The old code always used the
    //    unlocked key and never set an expiry, so a locked delegation was
    //    mis-stored and immediately undelegate-able — diverging from
    //    java-tron (silently, since TRON headers have no state root).
    let expire_time = if contract.lock {
        let lock_period = resolved_lock_period(dyn_props, contract.lock_period);
        check_add(
            now_ts,
            lock_period
                .checked_mul(BLOCK_PRODUCED_INTERVAL)
                .ok_or(ActuatorError::Overflow)?,
        )?
    } else {
        0
    };
    let key = if contract.lock {
        DelegatedResourceStore::v2_locked_key(&owner, &to)
    } else {
        DelegatedResourceStore::v2_unlocked_key(&owner, &to)
    };
    let mut resource = resources.get_raw(&key)?.unwrap_or_else(|| DelegatedResource {
        from: owner.as_bytes().to_vec(),
        to: to.as_bytes().to_vec(),
        ..Default::default()
    });
    // `addFrozenBalanceFor*` adds the balance and OVERWRITES the expiry.
    match contract.resource {
        0 => {
            resource.frozen_balance_for_bandwidth =
                check_add(resource.frozen_balance_for_bandwidth, contract.balance)?;
            resource.expire_time_for_bandwidth = expire_time;
        }
        1 => {
            resource.frozen_balance_for_energy =
                check_add(resource.frozen_balance_for_energy, contract.balance)?;
            resource.expire_time_for_energy = expire_time;
        }
        _ => unreachable!(),
    }
    resources.put_raw(&key, &resource)?;

    // 5. Update the bidirectional account index — java-tron
    //    `DelegatedResourceAccountIndexStore.delegateV2(owner, to, now)`.
    if let Some(index) = index {
        index.delegate_v2(&owner, &to, now_ts)?;
    }

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
    index: Option<&DelegatedResourceAccountIndexStore>,
    dyn_props: &DynamicPropertiesStore,
    contract: &UnDelegateResourceContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let to = require_to(&contract.receiver_address)?;
    let balance = contract.balance;
    let kind = resource_kind(contract.resource);
    let gates = resource_gates(dyn_props);
    // `now_ts` (block timestamp) gates the locked-record expiry;
    // `now_slot` (java `getHeadSlot`) is the usage-window time unit.
    let now_ts = dyn_props.latest_block_header_timestamp().unwrap_or(0);
    let now_slot = dyn_props.head_slot();

    // 1. Receiver: transfer the usage attributable to the un-delegated
    //    balance back to the owner. java-tron decays the receiver's usage
    //    (`updateUsageForDelegated` / `updateUsage`), computes
    //    `transferUsage = min(unDelegateMaxUsage, netUsage * balance/allFrozen)`,
    //    then debits the receiver's `acquired_*` and usage. Skipped entirely
    //    if the receiver account no longer exists (TVM suicide/re-create).
    let mut transfer_usage = 0i64;
    let mut receiver_account = accounts.get(&to)?;
    if let Some(receiver) = receiver_account.as_mut() {
        // Decay the receiver's usage to `now_slot` (writes its window back).
        update_usage(
            receiver,
            kind,
            now_slot,
            gates,
            dyn_props.allow_harden_resource_calculation(),
        );
        let acquired = acquired_delegated_v2(receiver, kind);
        if acquired < balance {
            // A TVM contract suicide + re-create can leave acquired < balance.
            set_acquired_delegated_v2(receiver, kind, 0);
        } else {
            let (total_limit, total_weight) = match kind {
                ResourceKind::Bandwidth => {
                    (dyn_props.total_net_limit(), dyn_props.total_net_weight())
                }
                ResourceKind::Energy => (
                    dyn_props.total_energy_current_limit(),
                    dyn_props.total_energy_weight(),
                ),
            };
            // java: `(long)((double)balance / TRX_PRECISION
            //               * ((double)totalLimit / totalWeight))`.
            let undelegate_max_usage = if total_weight > 0 {
                ((balance as f64 / TRX_PRECISION as f64)
                    * (total_limit as f64 / total_weight as f64)) as i64
            } else {
                0
            };
            // java: `(long)(netUsage * ((double)balance / allFrozenBalance))`
            // — `allFrozenBalance` still includes the `acquired_*` being
            // removed (read before the debit below).
            let all_frozen = match kind {
                ResourceKind::Bandwidth => all_frozen_balance_for_bandwidth(receiver),
                ResourceKind::Energy => all_frozen_balance_for_energy(receiver),
            };
            let recv_usage = usage(receiver, kind); // decayed
            transfer_usage = if all_frozen > 0 {
                (recv_usage as f64 * (balance as f64 / all_frozen as f64)) as i64
            } else {
                0
            };
            transfer_usage = undelegate_max_usage.min(transfer_usage);
            if let Ok(__tgt) = std::env::var("TRON_ETRAJ") {
                let __t = __tgt.trim_start_matches("0x");
                let oh: String = owner.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
                let rh: String = to.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
                if kind == ResourceKind::Energy && (oh.contains(__t) || rh.contains(__t)) {
                    eprintln!(
                        "ETRAJ_UNDEL_RECV owner={oh} recv={rh} balance={balance} recv_usage_decayed={recv_usage} all_frozen={all_frozen} undel_max={undelegate_max_usage} transfer_usage={transfer_usage} L={total_limit} W={total_weight}"
                    );
                }
            }
            set_acquired_delegated_v2(receiver, kind, acquired - balance);
        }
        let new_recv_usage = usage(receiver, kind) - transfer_usage;
        set_usage(receiver, kind, new_recv_usage);
        set_latest_time(receiver, kind, now_slot);
    }

    // 2. Fold any expired *locked* delegation into the unlocked record
    //    before drawing on it — java-tron's `unLockExpireResource`.
    resources.unlock_expire_resource(&owner, &to, now_ts)?;

    // 3. Decrement the unlocked per-(owner, to) record (java sets its
    //    expiry to 0 on every `addFrozenBalanceFor*(-balance, 0)`).
    let unlock_key = DelegatedResourceStore::v2_unlocked_key(&owner, &to);
    let mut unlock_resource = resources
        .get_raw(&unlock_key)?
        .ok_or(ActuatorError::NothingToUndelegate)?;
    match kind {
        ResourceKind::Bandwidth => {
            unlock_resource.frozen_balance_for_bandwidth =
                check_sub(unlock_resource.frozen_balance_for_bandwidth, balance)?;
            unlock_resource.expire_time_for_bandwidth = 0;
        }
        ResourceKind::Energy => {
            unlock_resource.frozen_balance_for_energy =
                check_sub(unlock_resource.frozen_balance_for_energy, balance)?;
            unlock_resource.expire_time_for_energy = 0;
        }
    }

    // 4. Owner: decrement `delegated_*`, credit back `frozen_v2`, then fold
    //    the transferred usage in via `unDelegateIncrease`.
    let mut owner_account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    match kind {
        ResourceKind::Bandwidth => {
            owner_account.delegated_frozen_v2_balance_for_bandwidth = check_sub(
                owner_account.delegated_frozen_v2_balance_for_bandwidth,
                balance,
            )?;
        }
        ResourceKind::Energy => {
            let r = owner_account.account_resource.get_or_insert_with(Default::default);
            r.delegated_frozen_v2_balance_for_energy =
                check_sub(r.delegated_frozen_v2_balance_for_energy, balance)?;
        }
    }
    match owner_account
        .frozen_v2
        .iter_mut()
        .find(|f| f.r#type == contract.resource)
    {
        Some(slot) => slot.amount = check_add(slot.amount, balance)?,
        None => owner_account.frozen_v2.push(tron_proto::account::FreezeV2 {
            r#type: contract.resource,
            amount: balance,
        }),
    }
    if let Some(receiver) = receiver_account.as_ref() {
        if transfer_usage > 0 {
            undelegate_increase(
                &mut owner_account,
                receiver,
                transfer_usage,
                kind,
                now_slot,
                gates,
                dyn_props.allow_harden_resource_calculation(),
            );
        }
    }
    accounts.put(&owner, &owner_account)?;

    // 5. Delete or persist the (now-decremented) unlocked record.
    let unlock_gone = unlock_resource.frozen_balance_for_bandwidth == 0
        && unlock_resource.frozen_balance_for_energy == 0;
    if unlock_gone {
        resources.delete_raw(&unlock_key)?;
    } else {
        resources.put_raw(&unlock_key, &unlock_resource)?;
    }

    // 6. Once both the locked and unlocked records are gone, drop the
    //    bidirectional index rows — java-tron `unDelegateV2`.
    let lock_key = DelegatedResourceStore::v2_locked_key(&owner, &to);
    let lock_exists = resources.get_raw(&lock_key)?.is_some();
    if unlock_gone && !lock_exists {
        if let Some(index) = index {
            index.undelegate_v2(&owner, &to)?;
        }
    }

    // 7. Persist the receiver (mutated in step 1) last — java puts it
    //    earlier, but it is not modified after, so the end state matches.
    if let Some(receiver) = receiver_account.as_ref() {
        accounts.put(&to, receiver)?;
    }

    Ok(ExecutionResult::default())
}
