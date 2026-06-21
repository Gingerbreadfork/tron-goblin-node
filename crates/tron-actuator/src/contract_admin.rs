//! Smart-contract admin actuators: ClearABIContract,
//! UpdateEnergyLimitContract, UpdateSettingContract.
//!
//! These don't invoke the VM — they're metadata edits on existing
//! contracts. The VM-execution actuators (`CreateSmartContract`,
//! `TriggerSmartContract`) live in [`crate::deferred`] because they
//! depend on the full TVM port (a fork of `revm`).

use tron_chainbase::{AbiStore, AccountStore, ContractStore, DynamicPropertiesStore};
use tron_crypto::address::Address;
use tron_proto::{ClearAbiContract, UpdateEnergyLimitContract, UpdateSettingContract};

use crate::helpers::{decode_address, require_owner};
use crate::transfer::ExecutionResult;
use crate::ActuatorError;

fn require_constantinople(dyn_props: &DynamicPropertiesStore) -> Result<(), ActuatorError> {
    if dyn_props.get_long(b"ALLOW_TVM_CONSTANTINOPLE").unwrap_or(0) != 1 {
        return Err(ActuatorError::ConstantinopleDisabled);
    }
    Ok(())
}

fn require_contract_owner(
    accounts: &AccountStore,
    contracts: &ContractStore,
    owner: &Address,
    contract_addr: &Address,
) -> Result<(), ActuatorError> {
    if accounts.get(owner)?.is_none() {
        return Err(ActuatorError::OwnerAccountMissing);
    }
    let contract = contracts
        .get(contract_addr)?
        .ok_or(ActuatorError::ContractMissing)?;
    if contract.origin_address != owner.as_bytes() {
        return Err(ActuatorError::NotContractOwner);
    }
    Ok(())
}

// =============================================================================
// ClearABIContractActuator
// =============================================================================

pub fn validate_clear_abi(
    accounts: &AccountStore,
    contracts: &ContractStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &ClearAbiContract,
) -> Result<(), ActuatorError> {
    require_constantinople(dyn_props)?;
    let owner = require_owner(&contract.owner_address)?;
    let target =
        decode_address(&contract.contract_address).ok_or(ActuatorError::InvalidAddress)?;
    require_contract_owner(accounts, contracts, &owner, &target)
}

pub fn execute_clear_abi(
    abi: &AbiStore,
    contract: &ClearAbiContract,
) -> Result<ExecutionResult, ActuatorError> {
    let target =
        decode_address(&contract.contract_address).ok_or(ActuatorError::InvalidAddress)?;
    // Clear by writing an empty ABI proto.
    abi.put(&target, &Default::default())?;
    Ok(ExecutionResult::default())
}

// =============================================================================
// UpdateEnergyLimitContractActuator
// =============================================================================

/// java `CommonParameter.blockNumForEnergyLimit` — node-config gate (default
/// `enery.limit.block.num`). On mainnet it is the historical activation height
/// of the per-contract `origin_energy_limit` field; before it,
/// `UpdateEnergyLimitContract` is not a recognized contract type and the tx
/// FAILs. The replay/snapshot window is far past this height, so the gate is
/// satisfied — it is added for full-history parity.
const BLOCK_NUM_FOR_ENERGY_LIMIT: i64 = 4_727_890;

pub fn validate_update_energy_limit(
    accounts: &AccountStore,
    contracts: &ContractStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &UpdateEnergyLimitContract,
) -> Result<(), ActuatorError> {
    // java UpdateEnergyLimitContractActuator.validate opens with
    // `ReceiptCapsule.checkForEnergyLimit(ds)` = `latestBlockHeaderNumber >=
    // blockNumForEnergyLimit`; failing it throws ("unexpected type
    // [UpdateEnergyLimitContract]") → the tx FAILs.
    if dyn_props.latest_block_header_number().unwrap_or(0) < BLOCK_NUM_FOR_ENERGY_LIMIT {
        return Err(ActuatorError::EnergyLimitNotActivated);
    }
    let owner = require_owner(&contract.owner_address)?;
    let target =
        decode_address(&contract.contract_address).ok_or(ActuatorError::InvalidAddress)?;
    if contract.origin_energy_limit <= 0 {
        return Err(ActuatorError::NonPositiveEnergyLimit);
    }
    require_contract_owner(accounts, contracts, &owner, &target)
}

pub fn execute_update_energy_limit(
    contracts: &ContractStore,
    contract: &UpdateEnergyLimitContract,
) -> Result<ExecutionResult, ActuatorError> {
    let target =
        decode_address(&contract.contract_address).ok_or(ActuatorError::InvalidAddress)?;
    let mut sc = contracts
        .get(&target)?
        .ok_or(ActuatorError::ContractMissing)?;
    sc.origin_energy_limit = contract.origin_energy_limit;
    contracts.put(&target, &sc)?;
    Ok(ExecutionResult::default())
}

// =============================================================================
// UpdateSettingContractActuator
// =============================================================================

pub fn validate_update_setting(
    accounts: &AccountStore,
    contracts: &ContractStore,
    contract: &UpdateSettingContract,
) -> Result<(), ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let target =
        decode_address(&contract.contract_address).ok_or(ActuatorError::InvalidAddress)?;
    if contract.consume_user_resource_percent < 0 || contract.consume_user_resource_percent > 100 {
        return Err(ActuatorError::PercentOutOfRange);
    }
    require_contract_owner(accounts, contracts, &owner, &target)
}

pub fn execute_update_setting(
    contracts: &ContractStore,
    contract: &UpdateSettingContract,
) -> Result<ExecutionResult, ActuatorError> {
    let target =
        decode_address(&contract.contract_address).ok_or(ActuatorError::InvalidAddress)?;
    let mut sc = contracts
        .get(&target)?
        .ok_or(ActuatorError::ContractMissing)?;
    sc.consume_user_resource_percent = contract.consume_user_resource_percent;
    contracts.put(&target, &sc)?;
    Ok(ExecutionResult::default())
}
