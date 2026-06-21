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

use std::collections::BTreeMap;

use tron_chainbase::{AccountStore, DynamicPropertiesStore};
use tron_crypto::address::{Address, ADDRESS_LENGTH, ADDRESS_PREFIX_MAINNET};
use tron_proto::{Account, MarketOrderDetail, TransferContract};

use crate::ActuatorError;

/// `ChainConstant.TRANSFER_FEE = 0` in java-tron. Pinned by a test.
pub const TRANSFER_FEE: i64 = 0;

/// The non-fee fields a java-tron `TransactionResultCapsule` (`ret`)
/// carries beyond `fee`/`contractRet`, surfaced into the stored
/// `TransactionInfo` by `TransactionUtil.buildTransactionInfoInstance`
/// (`chainbase/.../capsule/utils/TransactionUtil.java:98-110`).
///
/// Each field maps 1:1 to a `programResult.getRet().getX()` read in that
/// method and is set by exactly the actuator(s) that produce the value
/// (see each `execute_*`). Non-VM actuators populate these; VM txs leave
/// them at their defaults (the VM path fills the proto fields elsewhere).
/// Defaults mean "unset" and serialise to the proto default (0 / empty),
/// matching java's behaviour when an actuator never touches the field.
///
/// `Eq` is intentionally not derived: `MarketOrderDetail` (a prost message)
/// implements only `PartialEq`, which is all the actuator tests need.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TransactionRetExtras {
    /// `ret.unfreezeAmount` — set by `UnfreezeBalanceActuator` (v1) to the
    /// unfrozen balance (`TransactionUtil:98`).
    pub unfreeze_amount: i64,
    /// `ret.assetIssueID` — `Long.toString(tokenIdNum)` of the asset
    /// created by `AssetIssueActuator` (`TransactionUtil:99`).
    pub asset_issue_id: String,
    /// `ret.exchangeId` — id of the exchange created by
    /// `ExchangeCreateActuator` (`TransactionUtil:100`).
    pub exchange_id: i64,
    /// `ret.withdrawAmount` — the reward allowance withdrawn by
    /// `WithdrawBalanceActuator` (`TransactionUtil:101`).
    pub withdraw_amount: i64,
    /// `ret.withdrawExpireAmount` — the expired-unfreeze balance swept to
    /// the owner's balance by `WithdrawExpireUnfreezeActuator`,
    /// `UnfreezeBalanceV2Actuator`, or `CancelAllUnfreezeV2Actuator`
    /// (`TransactionUtil:102`).
    pub withdraw_expire_amount: i64,
    /// `ret.cancelUnfreezeV2AmountMap` — per-resource (`BANDWIDTH` /
    /// `ENERGY` / `TRON_POWER`) amount restored to frozen-V2 by
    /// `CancelAllUnfreezeV2Actuator` (`TransactionUtil:103`).
    pub cancel_unfreeze_v2_amount: BTreeMap<String, i64>,
    /// `ret.exchangeReceivedAmount` — the other-token amount received by
    /// `ExchangeTransactionActuator` (`TransactionUtil:104`).
    pub exchange_received_amount: i64,
    /// `ret.exchangeInjectAnotherAmount` — the other-token amount injected
    /// alongside the named token by `ExchangeInjectActuator`
    /// (`TransactionUtil:105`).
    pub exchange_inject_another_amount: i64,
    /// `ret.exchangeWithdrawAnotherAmount` — the other-token amount
    /// withdrawn by `ExchangeWithdrawActuator` (`TransactionUtil:106`).
    pub exchange_withdraw_another_amount: i64,
    /// `ret.shieldedTransactionFee` — fee charged by
    /// `ShieldedTransferActuator` (`TransactionUtil:108`).
    pub shielded_transaction_fee: i64,
    /// `ret.orderId` — id of the market order created by
    /// `MarketSellAssetActuator` (`TransactionUtil:109`).
    pub order_id: Vec<u8>,
    /// `ret.orderDetailsList` — per-match fill details appended by the
    /// `MarketSellAssetActuator` matching engine (`TransactionUtil:110`).
    pub order_details: Vec<MarketOrderDetail>,
}

/// Result of a successful execute. Mirrors the energy/bandwidth/fee
/// fields a real `TransactionResultCapsule` would set, but only with
/// what the actuator can actually populate.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ExecutionResult {
    /// Total TRX burned (fee that left the system).
    pub fee: i64,
    /// True if the recipient account was auto-created.
    pub created_recipient: bool,
    /// The java `ret`-derived fields the stored `TransactionInfo` carries
    /// beyond `fee` — populated only by the actuators that produce them.
    pub ret: TransactionRetExtras,
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
        let mut new_acct = Account {
            address: to.as_bytes().to_vec(),
            r#type: tron_proto::AccountType::Normal as i32,
            create_time: dynamic_properties
                .latest_block_header_timestamp()
                .unwrap_or(0),
            ..Default::default()
        };
        // java attaches the default owner+active[id=2] permission to every
        // account it creates when ALLOW_MULTI_SIGN is on (TransferActuator →
        // `new AccountCapsule(.., withDefaultPermission, ..)`).
        crate::permission::apply_default_account_permissions(&mut new_acct, dynamic_properties);
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
    accounts.put(&owner, &owner_account)?;

    // java TransferActuator.execute (TransferActuator.java:60-65): after
    // debiting the owner it sends `fee` to the blackhole — `burnTrx(fee)` on
    // the `supportBlackHoleOptimization()` path (mainnet), else crediting the
    // blackhole *account*. The owner balance and TransactionInfo.fee already
    // match without this; only the chain-wide BURN_TRX_AMOUNT accumulator
    // would drift. The fee is the create-new-account fee, 0 on mainnet, so
    // this is inert in practice but keeps BURN_TRX_AMOUNT exact if a proposal
    // ever raises CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT.
    dynamic_properties.burn_trx(fee);

    // Credit amount to recipient.
    let mut to_acct = to_account.expect("filled in above");
    to_acct.balance = to_acct
        .balance
        .checked_add(contract.amount)
        .ok_or(ActuatorError::Overflow)?;
    accounts.put(&to, &to_acct)?;

    Ok(ExecutionResult {
        fee,
        created_recipient,
        ..Default::default()
    })
}

/// Canonical key for the create-new-account fee. This key isn't in the
/// `dynamic_properties_keys` module yet (that module exposes a curated
/// subset); inline-defining it here keeps the actuator self-contained
/// until the broader key catalog lands. Shared with `TransferAsset`, which
/// charges the same fee when it auto-creates a recipient.
pub(crate) const CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT: &[u8] =
    b"CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT";

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
