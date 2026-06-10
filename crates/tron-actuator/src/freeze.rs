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
use tron_proto::{AccountType, FreezeBalanceContract, UnfreezeBalanceContract, Votes};

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
    contract: &UnfreezeBalanceContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;

    // java-tron settles pending voter rewards BEFORE touching the stake
    // (`mortgageService.withdrawReward(ownerAddress)` at the top of
    // `UnfreezeBalanceActuator.execute`) — the reward window must close
    // against the votes/cycle markers as they stood.
    tron_tvm::reward::withdraw_reward(&owner, accounts, delegation, dyn_props)?;

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
