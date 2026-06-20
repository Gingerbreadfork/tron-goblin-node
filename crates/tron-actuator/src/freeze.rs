//! v1 Freeze actuators (deprecated): FreezeBalance, UnfreezeBalance.
//!
//! These are deprecated since the V2 resource model rolled out; new
//! transactions should use [`crate::freeze_v2`]. We implement them at
//! minimal fidelity (basic validation + account-level balance moves)
//! since they're still accepted on-chain for backwards compatibility.
//!
//! Sources: `FreezeBalanceActuator`, `UnfreezeBalanceActuator`.

use tron_chainbase::{
    AccountStore, DelegatedResourceAccountIndexStore, DelegatedResourceStore, DelegationStore,
    DynamicPropertiesStore, VotesStore,
};
use tron_crypto::address::{Address, ADDRESS_LENGTH, ADDRESS_PREFIX_MAINNET};
use tron_proto::account::Frozen;
use tron_proto::{
    AccountType, DelegatedResource, FreezeBalanceContract, UnfreezeBalanceContract, Votes,
};

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
    dyn_props: &DynamicPropertiesStore,
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
    // java `FreezeBalanceActuator.validate`: TRON_POWER is only valid under the
    // new resource model (mainnet off → InvalidResourceCode), and even then
    // cannot be delegated to a receiver. BANDWIDTH/ENERGY are always valid.
    if contract.resource < 0 || contract.resource > 2 {
        return Err(ActuatorError::InvalidResourceCode);
    }
    if contract.resource == 2 {
        // ALLOW_NEW_RESOURCE_MODEL is off on mainnet; java then rejects
        // TRON_POWER v1 freeze outright. With it on, only delegation is
        // forbidden (the receiver-set case below would carry TRON_POWER).
        if dyn_props.get_long(b"ALLOW_NEW_RESOURCE_MODEL").unwrap_or(0) != 1 {
            return Err(ActuatorError::InvalidResourceCode);
        }
        if !contract.receiver_address.is_empty() {
            return Err(ActuatorError::InvalidDelegationReceiver);
        }
    }

    // java `FreezeBalanceActuator.validate` receiver branch: when a receiver is
    // set and ALLOW_DELEGATE_RESOURCE is on, the freeze delegates the resource.
    // The receiver must be a valid, existing, non-self account; once
    // ALLOW_TVM_CONSTANTINOPLE is live a contract receiver is rejected.
    let receiver = decode_receiver(&contract.receiver_address)?;
    let support_dr = dyn_props.get_long(b"ALLOW_DELEGATE_RESOURCE").unwrap_or(0) == 1;
    if let (Some(receiver), true) = (receiver, support_dr) {
        if receiver == owner {
            return Err(ActuatorError::ReceiverSameAsOwner);
        }
        let receiver_account = accounts
            .get(&receiver)?
            .ok_or(ActuatorError::TargetAccountMissing)?;
        if dyn_props.get_long(b"ALLOW_TVM_CONSTANTINOPLE").unwrap_or(0) == 1
            && receiver_account.r#type == AccountType::Contract as i32
        {
            return Err(ActuatorError::DelegationToContract);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn execute_freeze_balance(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    delegated_resources: &DelegatedResourceStore,
    index: Option<&DelegatedResourceAccountIndexStore>,
    contract: &FreezeBalanceContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let mut account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    // java computes `newBalance` up front from the value read before any
    // delegate-side mutation, then assigns it last; the owner debit is
    // independent of the delegate bookkeeping, so the order matches.
    let new_balance = check_sub(account.balance, contract.frozen_balance)?;

    let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);
    let expire = now + contract.frozen_duration * FROZEN_PERIOD_MS / 3; // duration is in days; we treat 1 = 3-day base

    let receiver = decode_receiver(&contract.receiver_address)?;
    let support_dr = dyn_props.get_long(b"ALLOW_DELEGATE_RESOURCE").unwrap_or(0) == 1;

    // Chain-wide weight delta. java-tron's `FreezeBalanceActuator.addTotalWeight`:
    //   weight = allowNewReward() ? increment : freezeBalance / TRX_PRECISION
    // For a SELF freeze `increment = floor(newFrozen / TRX_PRECISION) -
    // floor(oldFrozen / TRX_PRECISION)` over the resource's coalesced V1 frozen
    // balance (`getFrozenBalance()` for BANDWIDTH, `getEnergyFrozenBalance()`
    // for ENERGY); for a DELEGATE freeze `increment` is the receiver-side
    // acquired-balance floored difference returned by `delegateResource`.
    // Mainnet runs with ALLOW_NEW_REWARD = 1, so the floored *difference* is the
    // byte-exact value — the prior `freezeBalance / TRX_PRECISION` form drifted
    // by up to 1 per freeze whenever the existing frozen/acquired balance held a
    // fractional TRX (the same flooring-boundary class as the V2 fix), leaking
    // into TOTAL_*_WEIGHT.
    let allow_new_reward = dyn_props.get_long(b"ALLOW_NEW_REWARD").unwrap_or(0) == 1;
    let weight_of = |increment: i64| -> i64 {
        if allow_new_reward {
            increment
        } else {
            contract.frozen_balance / TRX_PRECISION
        }
    };

    match contract.resource {
        // BANDWIDTH.
        0 => {
            let increment = if let (Some(receiver), true) = (receiver, support_dr) {
                // === Delegate (receiver) branch — java `delegateResource(...,
                // isBandwidth=true, ...)` + `addDelegatedFrozenBalanceForBandwidth`. ===
                let inc = delegate_resource_v1(
                    accounts,
                    dyn_props,
                    delegated_resources,
                    index,
                    &owner,
                    &receiver,
                    true,
                    contract.frozen_balance,
                    expire,
                )?;
                account.delegated_frozen_balance_for_bandwidth = check_add(
                    account.delegated_frozen_balance_for_bandwidth,
                    contract.frozen_balance,
                )?;
                inc
            } else {
                // === Self branch — coalesce into the single legacy `frozen`
                // entry (java keeps at most 1 there — `getFrozenBalance()`). ===
                let old_balance = account.frozen.first().map(|f| f.frozen_balance).unwrap_or(0);
                let new_frozen = check_add(old_balance, contract.frozen_balance)?;
                if let Some(existing) = account.frozen.first_mut() {
                    existing.frozen_balance = new_frozen;
                    existing.expire_time = expire;
                } else {
                    account.frozen.push(Frozen {
                        frozen_balance: new_frozen,
                        expire_time: expire,
                    });
                }
                new_frozen / TRX_PRECISION - old_balance / TRX_PRECISION
            };
            dyn_props.add_total_net_weight(weight_of(increment));
        }
        // ENERGY: coalesce into `AccountResource.frozen_balance_for_energy`
        // (java `getEnergyFrozenBalance()` / `setFrozenForEnergy`) on the self
        // path; on the delegate path bump `delegated_frozen_balance_for_energy`.
        1 => {
            let increment = if let (Some(receiver), true) = (receiver, support_dr) {
                // === Delegate (receiver) branch — java `delegateResource(...,
                // isBandwidth=false, ...)` + `addDelegatedFrozenBalanceForEnergy`. ===
                let inc = delegate_resource_v1(
                    accounts,
                    dyn_props,
                    delegated_resources,
                    index,
                    &owner,
                    &receiver,
                    false,
                    contract.frozen_balance,
                    expire,
                )?;
                let res = account.account_resource.get_or_insert_with(Default::default);
                res.delegated_frozen_balance_for_energy = check_add(
                    res.delegated_frozen_balance_for_energy,
                    contract.frozen_balance,
                )?;
                inc
            } else {
                // === Self branch. The prior code wrote energy freezes into the
                // BANDWIDTH `frozen` list — a wrong bucket that the V1 unfreeze
                // (which reads `frozen_balance_for_energy`) would never see. ===
                let res = account.account_resource.get_or_insert_with(Default::default);
                let old_balance = res
                    .frozen_balance_for_energy
                    .as_ref()
                    .map(|f| f.frozen_balance)
                    .unwrap_or(0);
                let new_frozen = check_add(old_balance, contract.frozen_balance)?;
                res.frozen_balance_for_energy = Some(Frozen {
                    frozen_balance: new_frozen,
                    expire_time: expire,
                });
                new_frozen / TRX_PRECISION - old_balance / TRX_PRECISION
            };
            dyn_props.add_total_energy_weight(weight_of(increment));
        }
        // TRON_POWER (new-resource-model only; not exercised on mainnet, where
        // TRON Power is frozen via the V2 path). Persist the balance move
        // without a weight change, matching the prior behaviour for this arm.
        _ => {}
    }

    account.balance = new_balance;
    accounts.put(&owner, &account)?;
    Ok(ExecutionResult::default())
}

/// java-tron `FreezeBalanceActuator.delegateResource` — record a V1
/// `from → to` delegation of `balance` sun of BANDWIDTH (`is_bandwidth`)
/// or ENERGY, expiring at `expire`. Coalesces into the per-(from,to)
/// `DelegatedResource` V1 row, updates the bidirectional account index,
/// credits the receiver's `acquired_delegated_frozen_balance_for_*`, and
/// returns the receiver-side floored weight increment
/// (`floor(newAcquired/1e6) - floor(oldAcquired/1e6)`).
#[allow(clippy::too_many_arguments)]
fn delegate_resource_v1(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    delegated_resources: &DelegatedResourceStore,
    index: Option<&DelegatedResourceAccountIndexStore>,
    owner: &Address,
    receiver: &Address,
    is_bandwidth: bool,
    balance: i64,
    expire: i64,
) -> Result<i64, ActuatorError> {
    // 1. Coalesce into the per-(from,to) V1 row. java's `addFrozenBalanceFor*`
    //    (existing row) adds the balance and overwrites the expiry;
    //    `setFrozenBalanceFor*` (new row) sets both — identical end state.
    let key = DelegatedResourceStore::v1_key(owner, receiver);
    let mut row = delegated_resources
        .get_raw(&key)?
        .unwrap_or_else(|| DelegatedResource {
            from: owner.as_bytes().to_vec(),
            to: receiver.as_bytes().to_vec(),
            ..Default::default()
        });
    if is_bandwidth {
        row.frozen_balance_for_bandwidth =
            check_add(row.frozen_balance_for_bandwidth, balance)?;
        row.expire_time_for_bandwidth = expire;
    } else {
        row.frozen_balance_for_energy = check_add(row.frozen_balance_for_energy, balance)?;
        row.expire_time_for_energy = expire;
    }
    delegated_resources.put_raw(&key, &row)?;

    // 2. Bidirectional account index. java writes the per-pair rows directly
    //    once ALLOW_DELEGATE_OPTIMIZATION is on (lazily converting any legacy
    //    aggregate row first); the pre-optimization branch appends the
    //    counterparty to each side's aggregate list (dead on mainnet, kept for
    //    parity).
    if let Some(index) = index {
        if dyn_props.get_long(b"ALLOW_DELEGATE_OPTIMIZATION").unwrap_or(0) == 1 {
            index.convert(owner)?;
            index.convert(receiver)?;
            index.delegate_v1(owner, receiver, now_ts(dyn_props))?;
        } else {
            let okey = DelegatedResourceAccountIndexStore::legacy_key(owner);
            let mut o = index.get_raw(&okey)?.unwrap_or_default();
            if !o.to_accounts.iter().any(|a| a == receiver.as_bytes()) {
                o.to_accounts.push(receiver.as_bytes().to_vec());
            }
            index.put_raw(&okey, &o)?;

            let rkey = DelegatedResourceAccountIndexStore::legacy_key(receiver);
            let mut r = index.get_raw(&rkey)?.unwrap_or_default();
            if !r.from_accounts.iter().any(|a| a == owner.as_bytes()) {
                r.from_accounts.push(owner.as_bytes().to_vec());
            }
            index.put_raw(&rkey, &r)?;
        }
    }

    // 3. Credit the receiver's acquired balance and return its floored weight
    //    increment. java uses the plain `addAcquiredDelegatedFrozenBalanceFor*`
    //    (no max(0) clamp on the delegate path).
    let mut receiver_account = accounts
        .get(receiver)?
        .ok_or(ActuatorError::TargetAccountMissing)?;
    let increment = if is_bandwidth {
        let old_w = receiver_account.acquired_delegated_frozen_balance_for_bandwidth / TRX_PRECISION;
        receiver_account.acquired_delegated_frozen_balance_for_bandwidth = check_add(
            receiver_account.acquired_delegated_frozen_balance_for_bandwidth,
            balance,
        )?;
        receiver_account.acquired_delegated_frozen_balance_for_bandwidth / TRX_PRECISION - old_w
    } else {
        let res = receiver_account
            .account_resource
            .get_or_insert_with(Default::default);
        let old_w = res.acquired_delegated_frozen_balance_for_energy / TRX_PRECISION;
        res.acquired_delegated_frozen_balance_for_energy = check_add(
            res.acquired_delegated_frozen_balance_for_energy,
            balance,
        )?;
        res.acquired_delegated_frozen_balance_for_energy / TRX_PRECISION - old_w
    };
    accounts.put(receiver, &receiver_account)?;
    Ok(increment)
}

/// `DynamicPropertiesStore.getLatestBlockHeaderTimestamp` — the index
/// `delegate_v1` timestamp source on the optimized path.
fn now_ts(dyn_props: &DynamicPropertiesStore) -> i64 {
    dyn_props.latest_block_header_timestamp().unwrap_or(0)
}

// =============================================================================
// UnfreezeBalanceActuator (v1)
// =============================================================================

/// Decode the optional `receiver_address`. `None` when empty; error on a
/// malformed non-empty value (java's `DecodeUtil.addressValid`).
fn decode_receiver(raw: &[u8]) -> Result<Option<Address>, ActuatorError> {
    if raw.is_empty() {
        return Ok(None);
    }
    if raw.len() != ADDRESS_LENGTH || raw[0] != ADDRESS_PREFIX_MAINNET {
        return Err(ActuatorError::InvalidToAddress);
    }
    let mut buf = [0u8; ADDRESS_LENGTH];
    buf.copy_from_slice(raw);
    Ok(Some(Address::from_raw(buf)))
}

pub fn validate_unfreeze_balance(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    delegated_resources: &DelegatedResourceStore,
    contract: &UnfreezeBalanceContract,
) -> Result<(), ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);
    let receiver = decode_receiver(&contract.receiver_address)?;
    let support_dr = dyn_props.get_long(b"ALLOW_DELEGATE_RESOURCE").unwrap_or(0) == 1;

    if let (Some(receiver), true) = (receiver, support_dr) {
        // === Delegated (receiver) branch — java validate ===
        if receiver == owner {
            return Err(ActuatorError::ReceiverSameAsOwner);
        }
        let allow_constantinople =
            dyn_props.get_long(b"ALLOW_TVM_CONSTANTINOPLE").unwrap_or(0);
        let receiver_account = accounts.get(&receiver)?;
        if allow_constantinople == 0 && receiver_account.is_none() {
            return Err(ActuatorError::TargetAccountMissing);
        }
        let key = DelegatedResourceStore::v1_key(&owner, &receiver);
        let row = delegated_resources
            .get_raw(&key)?
            .ok_or(ActuatorError::DelegatedResourceMissing)?;
        let allow_solidity_059 =
            dyn_props.get_long(b"ALLOW_TVM_SOLIDITY_059").unwrap_or(0);
        // The acquired-balance consistency check only applies to a real,
        // non-contract receiver in the pre-Solidity059 era (java's nested
        // gates) — on mainnet (both flags = 1) it never fires.
        let acquired_check = |acquired: i64, delegated: i64| -> Result<(), ActuatorError> {
            let applies = if allow_constantinople == 0 {
                true
            } else {
                allow_solidity_059 != 1
                    && matches!(&receiver_account, Some(r)
                        if r.r#type != AccountType::Contract as i32)
            };
            if applies && acquired < delegated {
                return Err(ActuatorError::UnfreezeExceedsFrozen);
            }
            Ok(())
        };
        match contract.resource {
            0 => {
                if row.frozen_balance_for_bandwidth <= 0 {
                    return Err(ActuatorError::NothingToUnfreeze);
                }
                acquired_check(
                    receiver_account
                        .as_ref()
                        .map(|r| r.acquired_delegated_frozen_balance_for_bandwidth)
                        .unwrap_or(0),
                    row.frozen_balance_for_bandwidth,
                )?;
                if row.expire_time_for_bandwidth > now {
                    return Err(ActuatorError::NothingToUnfreeze);
                }
            }
            1 => {
                if row.frozen_balance_for_energy <= 0 {
                    return Err(ActuatorError::NothingToUnfreeze);
                }
                acquired_check(
                    receiver_account
                        .as_ref()
                        .and_then(|r| r.account_resource.as_ref())
                        .map(|r| r.acquired_delegated_frozen_balance_for_energy)
                        .unwrap_or(0),
                    row.frozen_balance_for_energy,
                )?;
                // java `getExpireTimeForEnergy(store)`: pre-multisign-fork
                // databases stored the energy expiry in the bandwidth slot;
                // mainnet (ALLOW_MULTI_SIGN = 1) reads the energy field.
                let expire = if dyn_props.get_long(b"ALLOW_MULTI_SIGN").unwrap_or(0) == 0 {
                    row.expire_time_for_bandwidth
                } else {
                    row.expire_time_for_energy
                };
                if expire > now {
                    return Err(ActuatorError::NothingToUnfreeze);
                }
            }
            _ => return Err(ActuatorError::InvalidResourceCode),
        }
        return Ok(());
    }

    // === Owner branch — java validate ===
    match contract.resource {
        0 => {
            if account.frozen.is_empty() {
                return Err(ActuatorError::NothingToUnfreeze);
            }
            if !account.frozen.iter().any(|f| f.expire_time <= now) {
                return Err(ActuatorError::NothingToUnfreeze);
            }
        }
        1 => {
            let frozen_energy = account
                .account_resource
                .as_ref()
                .and_then(|r| r.frozen_balance_for_energy.as_ref());
            match frozen_energy {
                Some(f) if f.frozen_balance > 0 => {
                    if f.expire_time > now {
                        return Err(ActuatorError::NothingToUnfreeze);
                    }
                }
                _ => return Err(ActuatorError::NothingToUnfreeze),
            }
        }
        // TRON_POWER unfreeze exists only under the NEW resource model
        // (mainnet: ALLOW_NEW_RESOURCE_MODEL = 0 → java rejects).
        _ => return Err(ActuatorError::InvalidResourceCode),
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn execute_unfreeze_balance(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    votes_store: &VotesStore,
    delegation: &DelegationStore,
    delegated_resources: &DelegatedResourceStore,
    index: Option<&DelegatedResourceAccountIndexStore>,
    reward_vi: Option<&tron_chainbase::RewardViStore>,
    contract: &UnfreezeBalanceContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;

    // java-tron settles pending voter rewards BEFORE touching the stake
    // (`mortgageService.withdrawReward(ownerAddress)` at the top of
    // `UnfreezeBalanceActuator.execute`) — the reward window must close
    // against the votes/cycle markers as they stood.
    tron_tvm::reward::withdraw_reward_actuator(&owner, accounts, delegation, dyn_props, reward_vi)?;

    let mut account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);
    let receiver = decode_receiver(&contract.receiver_address)?;
    let support_dr = dyn_props.get_long(b"ALLOW_DELEGATE_RESOURCE").unwrap_or(0) == 1;

    // `unfreeze_balance` (sun) and `decrease` (TRX-unit weight delta as a
    // floor-DIFFERENCE — java computes `new/1e6 − old/1e6` per branch,
    // which differs from `−unfrozen/1e6` whenever fractional TRX remains;
    // using the naive form drifted TOTAL_NET/ENERGY_WEIGHT).
    let mut unfreeze_balance: i64 = 0;
    let mut decrease: i64 = 0;

    if let (Some(receiver), true) = (receiver, support_dr) {
        // === Delegated (receiver) branch — java execute ===
        let key = DelegatedResourceStore::v1_key(&owner, &receiver);
        let mut row = delegated_resources
            .get_raw(&key)?
            .ok_or(ActuatorError::DelegatedResourceMissing)?;
        match contract.resource {
            0 => {
                unfreeze_balance = row.frozen_balance_for_bandwidth;
                row.frozen_balance_for_bandwidth = 0;
                row.expire_time_for_bandwidth = 0;
                account.delegated_frozen_balance_for_bandwidth = account
                    .delegated_frozen_balance_for_bandwidth
                    .saturating_sub(unfreeze_balance);
            }
            1 => {
                unfreeze_balance = row.frozen_balance_for_energy;
                row.frozen_balance_for_energy = 0;
                row.expire_time_for_energy = 0;
                let res = account.account_resource.get_or_insert_with(Default::default);
                res.delegated_frozen_balance_for_energy = res
                    .delegated_frozen_balance_for_energy
                    .saturating_sub(unfreeze_balance);
            }
            _ => return Err(ActuatorError::InvalidResourceCode),
        }

        // Receiver-side acquired-balance return. java skips it when
        // Constantinople is active AND the receiver is missing or a
        // contract (a contract can't hold acquired balance post-fork);
        // the weight then shrinks by the full delegation.
        let allow_constantinople =
            dyn_props.get_long(b"ALLOW_TVM_CONSTANTINOPLE").unwrap_or(0);
        let allow_solidity_059 =
            dyn_props.get_long(b"ALLOW_TVM_SOLIDITY_059").unwrap_or(0);
        let receiver_account = accounts.get(&receiver)?;
        let take_receiver_path = allow_constantinople == 0
            || matches!(&receiver_account, Some(r)
                if r.r#type != AccountType::Contract as i32);
        if take_receiver_path {
            let mut r = receiver_account.ok_or(ActuatorError::TargetAccountMissing)?;
            match contract.resource {
                0 => {
                    let mut old_w =
                        r.acquired_delegated_frozen_balance_for_bandwidth / TRX_PRECISION;
                    if allow_solidity_059 == 1
                        && r.acquired_delegated_frozen_balance_for_bandwidth
                            < unfreeze_balance
                    {
                        old_w = unfreeze_balance / TRX_PRECISION;
                        r.acquired_delegated_frozen_balance_for_bandwidth = 0;
                    } else {
                        r.acquired_delegated_frozen_balance_for_bandwidth = r
                            .acquired_delegated_frozen_balance_for_bandwidth
                            .saturating_sub(unfreeze_balance);
                    }
                    let new_w =
                        r.acquired_delegated_frozen_balance_for_bandwidth / TRX_PRECISION;
                    decrease = new_w - old_w;
                }
                1 => {
                    let res = r.account_resource.get_or_insert_with(Default::default);
                    let mut old_w =
                        res.acquired_delegated_frozen_balance_for_energy / TRX_PRECISION;
                    if allow_solidity_059 == 1
                        && res.acquired_delegated_frozen_balance_for_energy
                            < unfreeze_balance
                    {
                        old_w = unfreeze_balance / TRX_PRECISION;
                        res.acquired_delegated_frozen_balance_for_energy = 0;
                    } else {
                        res.acquired_delegated_frozen_balance_for_energy = res
                            .acquired_delegated_frozen_balance_for_energy
                            .saturating_sub(unfreeze_balance);
                    }
                    let new_w =
                        res.acquired_delegated_frozen_balance_for_energy / TRX_PRECISION;
                    decrease = new_w - old_w;
                }
                _ => {}
            }
            accounts.put(&receiver, &r)?;
        } else {
            decrease = -(unfreeze_balance / TRX_PRECISION);
        }

        account.balance = check_add(account.balance, unfreeze_balance)?;

        if row.frozen_balance_for_bandwidth == 0 && row.frozen_balance_for_energy == 0 {
            delegated_resources.delete_raw(&key)?;
            if let Some(idx) = index {
                if dyn_props.get_long(b"ALLOW_DELEGATE_OPTIMIZATION").unwrap_or(0) == 1 {
                    // New index model: lazily convert any legacy aggregate
                    // rows, then drop the per-pair rows.
                    idx.convert(&owner)?;
                    idx.convert(&receiver)?;
                    idx.undelegate_v1(&owner, &receiver)?;
                } else {
                    // Legacy aggregate model: remove the counterparty from
                    // each side's list (java's pre-optimization branch;
                    // dead on mainnet, kept for parity).
                    let okey = DelegatedResourceAccountIndexStore::legacy_key(&owner);
                    if let Some(mut o) = idx.get_raw(&okey)? {
                        o.to_accounts.retain(|a| a != receiver.as_bytes());
                        idx.put_raw(&okey, &o)?;
                    }
                    let rkey = DelegatedResourceAccountIndexStore::legacy_key(&receiver);
                    if let Some(mut rrow) = idx.get_raw(&rkey)? {
                        rrow.from_accounts.retain(|a| a != owner.as_bytes());
                        idx.put_raw(&rkey, &rrow)?;
                    }
                }
            }
        } else {
            delegated_resources.put_raw(&key, &row)?;
        }
    } else {
        // === Owner branch — java execute ===
        match contract.resource {
            0 => {
                let old_w: i64 =
                    account.frozen.iter().map(|f| f.frozen_balance).sum::<i64>()
                        / TRX_PRECISION;
                account.frozen.retain(|f| {
                    if f.expire_time <= now {
                        unfreeze_balance = unfreeze_balance.saturating_add(f.frozen_balance);
                        false
                    } else {
                        true
                    }
                });
                let new_w: i64 =
                    account.frozen.iter().map(|f| f.frozen_balance).sum::<i64>()
                        / TRX_PRECISION;
                decrease = new_w - old_w;
                account.balance = check_add(account.balance, unfreeze_balance)?;
            }
            1 => {
                // java unfreezes the ENTIRE frozenBalanceForEnergy (expiry
                // was checked in validate) and clears the field. The old
                // code swept the BANDWIDTH list for resource=1 — wrong
                // bucket AND wrong weight accumulator basis.
                let res = account.account_resource.get_or_insert_with(Default::default);
                let old_w = res
                    .frozen_balance_for_energy
                    .as_ref()
                    .map(|f| f.frozen_balance)
                    .unwrap_or(0)
                    / TRX_PRECISION;
                unfreeze_balance = res
                    .frozen_balance_for_energy
                    .take()
                    .map(|f| f.frozen_balance)
                    .unwrap_or(0);
                decrease = -old_w;
                account.balance = check_add(account.balance, unfreeze_balance)?;
            }
            // TRON_POWER unfreeze is new-resource-model only (mainnet off).
            _ => return Err(ActuatorError::InvalidResourceCode),
        }
    }

    // Chain-wide weight. java: `allowNewReward() ? decrease :
    // -unfreezeBalance / TRX_PRECISION` — mainnet has ALLOW_NEW_REWARD = 1,
    // i.e. the floor-difference form.
    let weight = if dyn_props.get_long(b"ALLOW_NEW_REWARD").unwrap_or(0) == 1 {
        decrease
    } else {
        -(unfreeze_balance / TRX_PRECISION)
    };
    match contract.resource {
        0 => dyn_props.add_total_net_weight(weight),
        1 => dyn_props.add_total_energy_weight(weight),
        2 => dyn_props.add_total_tron_power_weight(weight),
        _ => {}
    }

    // java-tron clears the owner's votes on EVERY v1 unfreeze
    // (`UnfreezeBalanceActuator.execute`, the `needToClearVote` block —
    // unconditionally true on mainnet, where `ALLOW_NEW_RESOURCE_MODEL = 0`
    // keeps the skip branch unreachable). The VotesStore record is written
    // even when the account holds no votes, matching java exactly: the
    // record's `old_votes` (captured at first mutation this cycle) is what
    // the next maintenance debits from each witness's `vote_count`, and
    // the cleared `new_votes` credits nothing back.
    let mut votes_record = match votes_store.get(&owner)? {
        Some(v) => v,
        None => Votes {
            address: owner.as_bytes().to_vec(),
            old_votes: account.votes.clone(),
            new_votes: Vec::new(),
        },
    };
    account.votes.clear();
    votes_record.new_votes.clear();
    votes_store.put(&owner, &votes_record)?;

    accounts.put(&owner, &account)?;
    Ok(ExecutionResult::default())
}
