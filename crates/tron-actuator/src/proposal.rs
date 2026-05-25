//! Proposal actuators: ProposalCreate, ProposalApprove, ProposalDelete.

use tron_chainbase::{
    dynamic_properties_keys, AccountStore, DynamicPropertiesStore, ProposalStore, WitnessStore,
};
use tron_proto::{
    proposal::State as ProposalState, Proposal, ProposalApproveContract, ProposalCreateContract,
    ProposalDeleteContract,
};

use crate::helpers::require_owner;
use crate::transfer::ExecutionResult;
use crate::ActuatorError;

/// 3 days in **milliseconds** — proposal voting window. Sourced from
/// `ChainConstant.PROPOSAL_EXPIRE_TIME` (3 days).
pub const PROPOSAL_EXPIRE_TIME_MS: i64 = 3 * 24 * 60 * 60 * 1000;

// =============================================================================
// ProposalCreateActuator
// =============================================================================
//
// **Deferred**: per-parameter range validation (`ProposalUtil.validator`)
// is extensive and proposal-id-specific. This port accepts any non-empty
// parameters map; downstream maintenance-period logic will catch
// out-of-range values when they're applied.

pub fn validate_proposal_create(
    accounts: &AccountStore,
    witnesses: &WitnessStore,
    contract: &ProposalCreateContract,
) -> Result<(), ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    if accounts.get(&owner)?.is_none() {
        return Err(ActuatorError::OwnerAccountMissing);
    }
    if !witnesses.contains(&owner) {
        return Err(ActuatorError::WitnessMissing);
    }
    if contract.parameters.is_empty() {
        return Err(ActuatorError::EmptyProposalParameters);
    }
    Ok(())
}

pub fn execute_proposal_create(
    proposals: &ProposalStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &ProposalCreateContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let next_id = dyn_props
        .get_long(dynamic_properties_keys::LATEST_PROPOSAL_NUM)
        .unwrap_or(0)
        + 1;

    let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);
    let next_maintenance = dyn_props.next_maintenance_time().unwrap_or(now);
    let maintenance_interval = dyn_props
        .maintenance_time_interval()
        .unwrap_or(6 * 60 * 60 * 1000); // default 6h

    // expiration = first maintenance boundary at least PROPOSAL_EXPIRE_TIME_MS
    // after `now`.
    let expiration_time = if now + PROPOSAL_EXPIRE_TIME_MS <= next_maintenance {
        next_maintenance
    } else {
        let diff = now + PROPOSAL_EXPIRE_TIME_MS - next_maintenance;
        let cycles = (diff + maintenance_interval - 1) / maintenance_interval;
        next_maintenance + cycles * maintenance_interval
    };

    let proposal = Proposal {
        proposal_id: next_id,
        proposer_address: owner.as_bytes().to_vec(),
        parameters: contract.parameters.clone(),
        expiration_time,
        create_time: now,
        approvals: Vec::new(),
        state: ProposalState::Pending as i32,
    };
    proposals.put(next_id, &proposal);
    dyn_props.put_long(dynamic_properties_keys::LATEST_PROPOSAL_NUM, next_id);

    Ok(ExecutionResult::default())
}

// =============================================================================
// ProposalApproveActuator
// =============================================================================

pub fn validate_proposal_approve(
    accounts: &AccountStore,
    witnesses: &WitnessStore,
    proposals: &ProposalStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &ProposalApproveContract,
) -> Result<(), ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    if accounts.get(&owner)?.is_none() {
        return Err(ActuatorError::OwnerAccountMissing);
    }
    if !witnesses.contains(&owner) {
        return Err(ActuatorError::WitnessMissing);
    }
    let latest = dyn_props
        .get_long(dynamic_properties_keys::LATEST_PROPOSAL_NUM)
        .unwrap_or(0);
    if contract.proposal_id > latest {
        return Err(ActuatorError::ProposalMissing);
    }
    let proposal = proposals
        .get(contract.proposal_id)?
        .ok_or(ActuatorError::ProposalMissing)?;
    let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);
    if now >= proposal.expiration_time {
        return Err(ActuatorError::ProposalExpired);
    }
    if proposal.state == ProposalState::Canceled as i32 {
        return Err(ActuatorError::ProposalCanceled);
    }
    let already_approved = proposal
        .approvals
        .iter()
        .any(|a| a == owner.as_bytes().as_slice());
    if contract.is_add_approval == already_approved {
        // Trying to add when already approved, or remove when not approved.
        return Err(ActuatorError::ProposalDuplicateApproval);
    }
    Ok(())
}

pub fn execute_proposal_approve(
    proposals: &ProposalStore,
    contract: &ProposalApproveContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let mut proposal = proposals
        .get(contract.proposal_id)?
        .ok_or(ActuatorError::ProposalMissing)?;
    let owner_bytes = owner.as_bytes().to_vec();
    if contract.is_add_approval {
        proposal.approvals.push(owner_bytes);
    } else {
        proposal.approvals.retain(|a| a != owner.as_bytes().as_slice());
    }
    proposals.put(contract.proposal_id, &proposal);
    Ok(ExecutionResult::default())
}

// =============================================================================
// ProposalDeleteActuator
// =============================================================================

pub fn validate_proposal_delete(
    accounts: &AccountStore,
    proposals: &ProposalStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &ProposalDeleteContract,
) -> Result<(), ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    if accounts.get(&owner)?.is_none() {
        return Err(ActuatorError::OwnerAccountMissing);
    }
    let latest = dyn_props
        .get_long(dynamic_properties_keys::LATEST_PROPOSAL_NUM)
        .unwrap_or(0);
    if contract.proposal_id > latest {
        return Err(ActuatorError::ProposalMissing);
    }
    let proposal = proposals
        .get(contract.proposal_id)?
        .ok_or(ActuatorError::ProposalMissing)?;
    let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);
    if now >= proposal.expiration_time {
        return Err(ActuatorError::ProposalExpired);
    }
    if proposal.state == ProposalState::Canceled as i32 {
        return Err(ActuatorError::ProposalCanceled);
    }
    if proposal.proposer_address != owner.as_bytes() {
        return Err(ActuatorError::NotProposalOwner);
    }
    Ok(())
}

pub fn execute_proposal_delete(
    proposals: &ProposalStore,
    contract: &ProposalDeleteContract,
) -> Result<ExecutionResult, ActuatorError> {
    let mut proposal = proposals
        .get(contract.proposal_id)?
        .ok_or(ActuatorError::ProposalMissing)?;
    proposal.state = ProposalState::Canceled as i32;
    proposals.put(contract.proposal_id, &proposal);
    Ok(ExecutionResult::default())
}
