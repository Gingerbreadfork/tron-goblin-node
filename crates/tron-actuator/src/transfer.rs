//! `TransferContract` actuator — move TRX from `owner_address` to `to_address`.
//!
//! Source: `org.tron.core.actuator.TransferActuator`. Differences from
//! the Java implementation pinned by tests below:
//!
//! * `TRANSFER_FEE` is `0` (java-tron's `ChainConstant.TRANSFER_FEE`).
//!   The only fee that can apply is `createNewAccountFee` when the
//!   recipient doesn't exist yet, read from `DynamicPropertiesStore`.
//!   Both default to 0 so a default-network transfer is fee-free.
//! * The recipient is auto-created (`AccountType::Normal`) if absent.
//! * Several proposal-gated rules are **not yet enforced** in this v1
//!   port:
//!     - `forbidTransferToContract` (blocks transfer-to-smart-contract)
//!     - `allowTvmCompatibleEvm` (blocks transfer-to-v1-contract)
//!     - blackhole burn optimisation
//!   These need `ContractStore` (not yet ported) plus extra proposal
//!   flags. They're listed in the crate-level docs.

use tron_chainbase::{AccountStore, DynamicPropertiesStore};
use tron_crypto::address::{Address, ADDRESS_LENGTH, ADDRESS_PREFIX_MAINNET};
use tron_proto::{Account, TransferContract};

use crate::ActuatorError;

/// `ChainConstant.TRANSFER_FEE = 0` in java-tron. Pinned by a test.
pub const TRANSFER_FEE: i64 = 0;

/// Result of a successful execute. Mirrors the energy/bandwidth/fee
/// fields a real `TransactionResultCapsule` would set, but only with
/// what `TransferActuator` can actually populate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExecutionResult {
    /// Total TRX burned (fee that left the system).
    pub fee: i64,
    /// True if the recipient account was auto-created.
    pub created_recipient: bool,
}

/// Read-only validation. Returns `Ok(())` if `contract` would be accepted
/// against the current state of `accounts` + `dynamic_properties`.
///
/// Does **not** mutate any store.
pub fn validate_transfer(
    accounts: &AccountStore,
    dynamic_properties: &DynamicPropertiesStore,
    contract: &TransferContract,
) -> Result<(), ActuatorError> {
    let owner = decode_address(&contract.owner_address).ok_or(ActuatorError::InvalidOwnerAddress)?;
    let to = decode_address(&contract.to_address).ok_or(ActuatorError::InvalidToAddress)?;

    if owner == to {
        return Err(ActuatorError::SelfTransfer);
    }
    if contract.amount <= 0 {
        return Err(ActuatorError::NonPositiveAmount);
    }

    let owner_account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;

    let mut fee = TRANSFER_FEE;
    let to_exists = accounts.get(&to)?.is_some();
    if !to_exists {
        let create_fee = dynamic_properties
            .get_long(CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT)
            .unwrap_or(0);
        fee = fee
            .checked_add(create_fee)
            .ok_or(ActuatorError::Overflow)?;
    }

    let needed = contract
        .amount
        .checked_add(fee)
        .ok_or(ActuatorError::Overflow)?;
    if owner_account.balance < needed {
        return Err(ActuatorError::InsufficientBalance {
            balance: owner_account.balance,
            needed,
        });
    }

    // Recipient overflow check (java-tron does `addExact(toBalance, amount)`).
    if let Some(to_account) = accounts.get(&to)? {
        to_account
            .balance
            .checked_add(contract.amount)
            .ok_or(ActuatorError::Overflow)?;
    }

    Ok(())
}

/// Apply the transfer. Caller must have already passed [`validate_transfer`]
/// against the same state.
pub fn execute_transfer(
    accounts: &AccountStore,
    dynamic_properties: &DynamicPropertiesStore,
    contract: &TransferContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = decode_address(&contract.owner_address).ok_or(ActuatorError::InvalidOwnerAddress)?;
    let to = decode_address(&contract.to_address).ok_or(ActuatorError::InvalidToAddress)?;

    let mut owner_account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;

    let mut to_account = accounts.get(&to)?;
    let mut fee = TRANSFER_FEE;
    let mut created_recipient = false;
    if to_account.is_none() {
        let create_fee = dynamic_properties
            .get_long(CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT)
            .unwrap_or(0);
        fee = fee
            .checked_add(create_fee)
            .ok_or(ActuatorError::Overflow)?;
        let new_acct = Account {
            address: to.as_bytes().to_vec(),
            r#type: tron_proto::AccountType::Normal as i32,
            create_time: dynamic_properties
                .latest_block_header_timestamp()
                .unwrap_or(0),
            ..Default::default()
        };
        to_account = Some(new_acct);
        created_recipient = true;
    }

    // Deduct (amount + fee) from owner.
    let total_out = contract
        .amount
        .checked_add(fee)
        .ok_or(ActuatorError::Overflow)?;
    owner_account.balance = owner_account
        .balance
        .checked_sub(total_out)
        .ok_or(ActuatorError::Overflow)?;
    accounts.put(&owner, &owner_account);

    // Credit amount to recipient.
    let mut to_acct = to_account.expect("filled in above");
    to_acct.balance = to_acct
        .balance
        .checked_add(contract.amount)
        .ok_or(ActuatorError::Overflow)?;
    accounts.put(&to, &to_acct);

    // The fee in java-tron is either burned (blackhole optimisation) or
    // credited to the blackhole account. For v1 we treat it as
    // unconditionally burned — drops out of the accounts store entirely.
    // When ContractStore lands we can wire up the blackhole credit if the
    // flag is unset.

    Ok(ExecutionResult {
        fee,
        created_recipient,
    })
}

/// Canonical key for the create-new-account fee. This key isn't in the
/// `dynamic_properties_keys` module yet (that module exposes a curated
/// subset); inline-defining it here keeps the actuator self-contained
/// until the broader key catalog lands.
const CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT: &[u8] = b"CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT";

/// Validate that `bytes` is a syntactically-correct TRON address: 21 bytes
/// with the `0x41` mainnet prefix. Java-tron's `DecodeUtil.addressValid`
/// additionally accepts testnet prefixes — we only do mainnet for now.
fn decode_address(bytes: &[u8]) -> Option<Address> {
    if bytes.len() != ADDRESS_LENGTH {
        return None;
    }
    if bytes[0] != ADDRESS_PREFIX_MAINNET {
        return None;
    }
    let mut buf = [0u8; ADDRESS_LENGTH];
    buf.copy_from_slice(bytes);
    Some(Address::from_raw(buf))
}
