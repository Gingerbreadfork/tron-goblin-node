//! Account-management actuators: CreateAccount, UpdateAccount,
//! AccountPermissionUpdate, SetAccountId.

use std::collections::HashSet;

use tron_chainbase::{AccountIdIndexStore, AccountIndexStore, AccountStore, DynamicPropertiesStore};
use tron_proto::{
    permission::PermissionType, Account, AccountCreateContract, AccountPermissionUpdateContract,
    AccountType, AccountUpdateContract, Permission, SetAccountIdContract,
};

use crate::helpers::{check_sub, decode_address, require_owner};
use crate::transfer::ExecutionResult;
use crate::ActuatorError;

/// 200-byte max for account names. Sourced from `TransactionUtil.validAccountName`.
pub const MAX_ACCOUNT_NAME_BYTES: usize = 200;

/// 32-byte max for account IDs (8 min). Sourced from
/// `TransactionUtil.validAccountId`.
pub const MIN_ACCOUNT_ID_BYTES: usize = 8;
pub const MAX_ACCOUNT_ID_BYTES: usize = 32;

fn name_valid(name: &[u8]) -> bool {
    !name.is_empty() && name.len() <= MAX_ACCOUNT_NAME_BYTES
}

fn id_valid(id: &[u8]) -> bool {
    (MIN_ACCOUNT_ID_BYTES..=MAX_ACCOUNT_ID_BYTES).contains(&id.len())
}

// =============================================================================
// CreateAccountActuator
// =============================================================================

pub fn validate_create_account(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &AccountCreateContract,
) -> Result<(), ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let new_addr =
        decode_address(&contract.account_address).ok_or(ActuatorError::InvalidAddress)?;

    let owner_account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    let fee = dyn_props
        .get_long(b"CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT")
        .unwrap_or(0);
    if owner_account.balance < fee {
        return Err(ActuatorError::InsufficientBalance {
            balance: owner_account.balance,
            needed: fee,
        });
    }
    if accounts.contains(&new_addr) {
        return Err(ActuatorError::AccountAlreadyExists);
    }
    Ok(())
}

pub fn execute_create_account(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &AccountCreateContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let new_addr =
        decode_address(&contract.account_address).ok_or(ActuatorError::InvalidAddress)?;

    let mut owner_account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    let fee = dyn_props
        .get_long(b"CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT")
        .unwrap_or(0);
    owner_account.balance = check_sub(owner_account.balance, fee)?;
    accounts.put(&owner, &owner_account);

    let new_account = Account {
        address: new_addr.as_bytes().to_vec(),
        r#type: contract.r#type, // matches enum value passed in
        create_time: dyn_props.latest_block_header_timestamp().unwrap_or(0),
        ..Default::default()
    };
    accounts.put(&new_addr, &new_account);

    Ok(ExecutionResult {
        fee,
        created_recipient: true,
    })
}

// =============================================================================
// UpdateAccountActuator
// =============================================================================

pub fn validate_update_account(
    accounts: &AccountStore,
    name_index: &AccountIndexStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &AccountUpdateContract,
) -> Result<(), ActuatorError> {
    if !name_valid(&contract.account_name) {
        return Err(ActuatorError::InvalidAccountName);
    }
    let owner = require_owner(&contract.owner_address)?;
    let account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;

    let allow_update = dyn_props
        .get_long(b"ALLOW_UPDATE_ACCOUNT_NAME")
        .unwrap_or(0)
        == 1;
    if !account.account_name.is_empty() && !allow_update {
        return Err(ActuatorError::AccountAlreadyNamed);
    }
    if name_index.get(&contract.account_name)?.is_some() && !allow_update {
        return Err(ActuatorError::AccountNameTaken);
    }
    Ok(())
}

pub fn execute_update_account(
    accounts: &AccountStore,
    name_index: &AccountIndexStore,
    contract: &AccountUpdateContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let mut account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    account.account_name = contract.account_name.clone();
    accounts.put(&owner, &account);
    name_index.put(&contract.account_name, &owner);
    Ok(ExecutionResult::default())
}

// =============================================================================
// SetAccountIdActuator
// =============================================================================

pub fn validate_set_account_id(
    accounts: &AccountStore,
    id_index: &AccountIdIndexStore,
    contract: &SetAccountIdContract,
) -> Result<(), ActuatorError> {
    if !id_valid(&contract.account_id) {
        return Err(ActuatorError::InvalidAccountId);
    }
    let owner = require_owner(&contract.owner_address)?;
    let account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    if !account.account_id.is_empty() {
        return Err(ActuatorError::AccountAlreadyHasId);
    }
    if id_index.get(&contract.account_id)?.is_some() {
        return Err(ActuatorError::AccountIdTaken);
    }
    Ok(())
}

pub fn execute_set_account_id(
    accounts: &AccountStore,
    id_index: &AccountIdIndexStore,
    contract: &SetAccountIdContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let mut account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    account.account_id = contract.account_id.clone();
    accounts.put(&owner, &account);
    id_index.put(&contract.account_id, &owner);
    Ok(ExecutionResult::default())
}

// =============================================================================
// AccountPermissionUpdateActuator
// =============================================================================
//
// Mirrors java-tron's `AccountPermissionUpdateActuator.validate()` plus
// its private `checkPermission(Permission)` helper. Three layers of
// checks (in order):
//
// 1. **Top-level structure**: `ALLOW_MULTI_SIGN` is enabled, owner
//    address is valid, the owner account exists, the contract has
//    `owner`, the witness slot is present iff the account is a
//    witness, and `actives.len()` is in `1..=8`.
// 2. **Permission types**: `owner.type == Owner`, each `actives[i].type
//    == Active`, and (if account is a witness) `witness.type ==
//    Witness`.
// 3. **Per-permission `checkPermission`**: key-count limits, distinct
//    key addresses, threshold > 0, sum-of-weights ≥ threshold,
//    permission-name length, parent_id == 0, and (for Active only)
//    a 32-byte `operations` bitmap whose set bits are a subset of
//    `AVAILABLE_CONTRACT_TYPE`.

/// Maximum number of active permissions per account (java-tron).
const MAX_ACTIVE_PERMISSIONS: usize = 8;
/// Default `TOTAL_SIGN_NUM` from java-tron when unset.
const DEFAULT_TOTAL_SIGN_NUM: i64 = 5;
/// Maximum permission name length (java-tron `Permission.MAX_NAME_LENGTH`).
const MAX_PERMISSION_NAME_LEN: usize = 32;
/// `operations` bitmap is 32 bytes (256 bits, one per ContractType).
const OPERATIONS_BYTES: usize = 32;

pub fn validate_account_permission_update(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &AccountPermissionUpdateContract,
) -> Result<(), ActuatorError> {
    if dyn_props.get_long(b"ALLOW_MULTI_SIGN").unwrap_or(0) != 1 {
        return Err(ActuatorError::MultiSignNotAllowed);
    }
    let owner = require_owner(&contract.owner_address)?;
    let account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;

    let owner_perm = contract
        .owner
        .as_ref()
        .ok_or(ActuatorError::Validate("owner permission is missed"))?;

    // Witness slot: required iff the account is a witness.
    if account.is_witness {
        if contract.witness.is_none() {
            return Err(ActuatorError::Validate("witness permission is missed"));
        }
    } else if contract.witness.is_some() {
        return Err(ActuatorError::Validate(
            "account isn't witness can't set witness permission",
        ));
    }

    // Active slot: 1..=8.
    if contract.actives.is_empty() {
        return Err(ActuatorError::Validate("active permission is missed"));
    }
    if contract.actives.len() > MAX_ACTIVE_PERMISSIONS {
        return Err(ActuatorError::Validate("active permission is too many"));
    }

    // Per-permission type tag + check.
    if owner_perm.r#type != PermissionType::Owner as i32 {
        return Err(ActuatorError::Validate("owner permission type is error"));
    }
    check_permission(owner_perm, dyn_props)?;

    if account.is_witness {
        // unwrap safe: checked above.
        let witness_perm = contract.witness.as_ref().unwrap();
        if witness_perm.r#type != PermissionType::Witness as i32 {
            return Err(ActuatorError::Validate("witness permission type is error"));
        }
        check_permission(witness_perm, dyn_props)?;
    }

    for active in &contract.actives {
        if active.r#type != PermissionType::Active as i32 {
            return Err(ActuatorError::Validate("active permission type is error"));
        }
        check_permission(active, dyn_props)?;
    }

    Ok(())
}

/// Mirrors java-tron's `AccountPermissionUpdateActuator.checkPermission`.
fn check_permission(
    permission: &Permission,
    dyn_props: &DynamicPropertiesStore,
) -> Result<(), ActuatorError> {
    let total_sign_num = dyn_props
        .get_long(b"TOTAL_SIGN_NUM")
        .unwrap_or(DEFAULT_TOTAL_SIGN_NUM);
    if permission.keys.len() as i64 > total_sign_num {
        return Err(ActuatorError::Validate(
            "number of keys in permission exceeds TOTAL_SIGN_NUM",
        ));
    }
    if permission.keys.is_empty() {
        return Err(ActuatorError::Validate(
            "key's count should be greater than 0",
        ));
    }
    if permission.r#type == PermissionType::Witness as i32 && permission.keys.len() != 1 {
        return Err(ActuatorError::Validate(
            "Witness permission's key count should be 1",
        ));
    }
    if permission.threshold <= 0 {
        return Err(ActuatorError::Validate(
            "permission's threshold should be greater than 0",
        ));
    }
    if permission.permission_name.len() > MAX_PERMISSION_NAME_LEN {
        return Err(ActuatorError::Validate("permission's name is too long"));
    }
    if permission.parent_id != 0 {
        return Err(ActuatorError::Validate("permission's parent should be owner"));
    }

    // Distinct addresses + valid address + positive weight + weight-sum ≥ threshold.
    let mut seen: HashSet<&[u8]> = HashSet::new();
    let mut weight_sum: i64 = 0;
    for key in &permission.keys {
        if !seen.insert(&key.address) {
            return Err(ActuatorError::Validate(
                "address should be distinct in permission",
            ));
        }
        if !address_valid(&key.address) {
            return Err(ActuatorError::Validate("key is not a validate address"));
        }
        if key.weight <= 0 {
            return Err(ActuatorError::Validate(
                "key's weight should be greater than 0",
            ));
        }
        weight_sum = weight_sum
            .checked_add(key.weight)
            .ok_or(ActuatorError::Validate("weight sum overflow"))?;
    }
    if weight_sum < permission.threshold {
        return Err(ActuatorError::Validate(
            "sum of all key's weight should not be less than threshold",
        ));
    }

    // Operations bitmap (only for Active permissions).
    if permission.r#type != PermissionType::Active as i32 {
        if !permission.operations.is_empty() {
            return Err(ActuatorError::Validate(
                "non-Active permission needn't operations",
            ));
        }
        return Ok(());
    }
    if permission.operations.len() != OPERATIONS_BYTES {
        return Err(ActuatorError::Validate("operations size must 32"));
    }
    // Every set bit in `operations` must be a set bit in
    // AVAILABLE_CONTRACT_TYPE (the chain-configured allow-list).
    let available = dyn_props
        .get_bytes(b"AVAILABLE_CONTRACT_TYPE")
        .unwrap_or_else(default_available_contract_type);
    if available.len() != OPERATIONS_BYTES {
        return Err(ActuatorError::Validate(
            "AVAILABLE_CONTRACT_TYPE bitmap is not 32 bytes",
        ));
    }
    for byte_idx in 0..OPERATIONS_BYTES {
        let op_byte = permission.operations[byte_idx];
        let avail_byte = available[byte_idx];
        // Any bit set in op_byte but not in avail_byte is an error.
        if op_byte & !avail_byte != 0 {
            return Err(ActuatorError::Validate(
                "contract type is not allowed in operations",
            ));
        }
    }
    Ok(())
}

/// 21-byte address with the mainnet 0x41 prefix.
fn address_valid(address: &[u8]) -> bool {
    address.len() == 21 && address[0] == tron_crypto::address::ADDRESS_PREFIX_MAINNET
}

/// Java-tron initialises AVAILABLE_CONTRACT_TYPE to all-bits-set for
/// the documented ContractTypes at genesis (then narrows it via
/// proposals). For tests that haven't put a value, treat it as
/// "all 256 bits set" — a permission permitting any contract is the
/// java-tron default behaviour before genesis hooks run.
fn default_available_contract_type() -> Vec<u8> {
    vec![0xffu8; OPERATIONS_BYTES]
}

pub fn execute_account_permission_update(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &AccountPermissionUpdateContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let mut account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;

    let fee = dyn_props
        .get_long(b"UPDATE_ACCOUNT_PERMISSION_FEE")
        .unwrap_or(0);
    account.balance = check_sub(account.balance, fee)?;
    account.owner_permission = contract.owner.clone();
    account.witness_permission = contract.witness.clone();
    account.active_permission = contract.actives.clone();
    accounts.put(&owner, &account);

    Ok(ExecutionResult {
        fee,
        created_recipient: false,
    })
}

#[allow(dead_code)]
fn _account_type_normal() -> i32 {
    AccountType::Normal as i32
}
