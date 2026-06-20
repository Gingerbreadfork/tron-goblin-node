//! Transaction-level permission / multi-sig enforcement.
//!
//! Mirrors java-tron's `TransactionCapsule::validateSignature` +
//! `checkWeight` flow:
//!
//! 1. Pull the owner address out of the contract proto (varies by
//!    contract type — `TransferContract.owner_address`,
//!    `WitnessCreateContract.owner_address`, etc.).
//! 2. Look up the account; pick the active `Permission` by the
//!    `Contract.permission_id` field (0 = owner, 1 = witness, ≥ 2 =
//!    match by `Permission.id` against the account's `active_permission`
//!    vector). java-tron's `AccountCapsule.getPermissionById` does
//!    the same — iterate, match, don't index. When the account has
//!    none configured, fall back to a synthetic default permission
//!    (single key = the owner address, weight = 1, threshold = 1).
//! 3. For each signature on the transaction:
//!    * Recover the signer address.
//!    * Reject if it's not a key in the permission.
//!    * Reject if the same signer signed twice.
//!    * Add the key's weight to the running total.
//! 4. Reject if the running total `< threshold`.
//! 5. For non-owner active permissions, also verify the contract type
//!    bit in `permission.operations` is set.
//!
//! Other rules enforced:
//! * `signature_count > 0` and ≤ `TOTAL_SIGN_NUM`.
//! * `signature_count <= permission.keys.len()`.

use tron_chainbase::{AccountStore, DynamicPropertiesStore};
use tron_crypto::address::Address;
use tron_proto::transaction::contract::ContractType;
use tron_proto::transaction::Contract;
use tron_proto::{permission::PermissionType, Account, Permission, Transaction};
use tron_types::recover_all_signers;

/// All the ways a permission check can fail.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum PermissionError {
    #[error("transaction has no signature")]
    MissingSignature,
    #[error("too many signatures: {got} > TOTAL_SIGN_NUM ({cap})")]
    TooManySigs { got: usize, cap: i64 },
    #[error("more signatures ({got}) than keys in permission ({keys})")]
    MoreSigsThanKeys { got: usize, keys: usize },
    #[error("owner account not found")]
    OwnerAccountMissing,
    #[error("permission_id {0} not found on account")]
    PermissionIdNotFound(i32),
    #[error("permission type is wrong for this contract")]
    PermissionTypeMismatch,
    #[error("operations bitmap does not allow this contract type")]
    OperationsDisallowedContract,
    #[error("signer recovery failed: {0}")]
    Recover(String),
    #[error("signer {0:?} is not in permission")]
    SignerNotInPermission(Address),
    #[error("signer {0:?} signed twice")]
    DuplicateSigner(Address),
    #[error("sum of signer weights ({weight}) < threshold ({threshold})")]
    BelowThreshold { weight: i64, threshold: i64 },
    #[error("couldn't decode owner from contract: {0}")]
    DecodeOwner(&'static str),
}

/// Run the full permission/multi-sig check against a transaction. The
/// caller has already decoded `Contract` + `ContractType`; this
/// function pulls the owner address out of the typed contract and
/// runs the rest of the check.
pub fn check_transaction_permission(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    tx: &Transaction,
    contract: &Contract,
    contract_type: ContractType,
) -> Result<(), PermissionError> {
    check_transaction_permission_inner(accounts, dyn_props, tx, contract, contract_type, None)
}

/// Like [`check_transaction_permission`] but consumes signer addresses
/// recovered ahead of time instead of running ECDSA recovery inline.
///
/// The block executor recovers every transaction's signers in parallel
/// (a pure, per-tx-independent operation) before the serial
/// state-application loop, then feeds the result here. `precomputed` MUST
/// equal what [`tron_types::recover_all_signers`] would return for `tx`
/// (mapped to `String` on error) — the recovery step is the only thing it
/// replaces; all structural checks still run first and in the same order,
/// so a recovery error surfaces at exactly the same point (step 4) it
/// would have inline. This keeps the validation outcome byte-identical to
/// the serial path.
pub fn check_transaction_permission_with_signers(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    tx: &Transaction,
    contract: &Contract,
    contract_type: ContractType,
    precomputed: &Result<Vec<Address>, String>,
) -> Result<(), PermissionError> {
    check_transaction_permission_inner(
        accounts,
        dyn_props,
        tx,
        contract,
        contract_type,
        Some(precomputed),
    )
}

fn check_transaction_permission_inner(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    tx: &Transaction,
    contract: &Contract,
    contract_type: ContractType,
    precomputed: Option<&Result<Vec<Address>, String>>,
) -> Result<(), PermissionError> {
    // === 0. Quick structural checks. ===
    let sigs = &tx.signature;
    if sigs.is_empty() {
        return Err(PermissionError::MissingSignature);
    }
    let total_sign_num = dyn_props.get_long(b"TOTAL_SIGN_NUM").unwrap_or(5);
    if sigs.len() as i64 > total_sign_num {
        return Err(PermissionError::TooManySigs {
            got: sigs.len(),
            cap: total_sign_num,
        });
    }

    // === 1. Pull the owner address out of the contract proto. ===
    let owner = extract_owner_address(contract, contract_type)?;

    // === 2. Pick the active permission. ===
    let account = accounts
        .get(&owner)
        .map_err(|_| PermissionError::OwnerAccountMissing)?
        .ok_or(PermissionError::OwnerAccountMissing)?;
    let permission = resolve_permission(&account, contract.permission_id, &owner)?;

    if sigs.len() > permission.keys.len() {
        return Err(PermissionError::MoreSigsThanKeys {
            got: sigs.len(),
            keys: permission.keys.len(),
        });
    }

    // === 3. Active-permission gate: contract type must be allowed. ===
    if contract.permission_id != 0 {
        if permission.r#type != PermissionType::Active as i32 {
            return Err(PermissionError::PermissionTypeMismatch);
        }
        check_operation_allowed(&permission, contract_type)?;
    }

    // === 4. Recover signers + sum weights. ===
    //
    // Use the executor's parallel pre-pass result when supplied; otherwise
    // recover inline. Either way the recovery error surfaces here (after
    // steps 0-3), so the rejection outcome is identical to the serial path.
    let signers_owned;
    let signers: &[Address] = match precomputed {
        Some(Ok(s)) => s.as_slice(),
        Some(Err(e)) => return Err(PermissionError::Recover(e.clone())),
        None => {
            signers_owned =
                recover_all_signers(tx).map_err(|e| PermissionError::Recover(e.to_string()))?;
            signers_owned.as_slice()
        }
    };
    let mut seen: Vec<Address> = Vec::with_capacity(signers.len());
    let mut total_weight: i64 = 0;
    for signer in signers {
        let Some(key) = permission
            .keys
            .iter()
            .find(|k| k.address == signer.as_bytes())
        else {
            return Err(PermissionError::SignerNotInPermission(signer.clone()));
        };
        if seen.iter().any(|s| s == signer) {
            return Err(PermissionError::DuplicateSigner(signer.clone()));
        }
        seen.push(signer.clone());
        total_weight = total_weight.saturating_add(key.weight);
    }
    if total_weight < permission.threshold {
        return Err(PermissionError::BelowThreshold {
            weight: total_weight,
            threshold: permission.threshold,
        });
    }
    Ok(())
}

/// Aggregate signer-weight info for a transaction. Computed by
/// [`compute_sign_weight`] without raising on under-threshold or
/// missing-signer conditions — the caller (typically the JSON-RPC
/// `getSignWeight` handler) inspects `code` to decide the response.
#[derive(Debug, Clone)]
pub struct SignWeight {
    pub permission: Permission,
    /// Addresses recovered from `tx.signature[]` in order. Includes
    /// every recoverable signature, even ones not in the permission.
    pub approved_list: Vec<Address>,
    /// Sum of weights for signers that ARE in the permission, with
    /// duplicates counted once.
    pub current_weight: i64,
    pub code: SignWeightCode,
    pub message: String,
}

/// Mirrors java-tron's `TransactionSignWeight.Result.response_code`
/// enum so the JSON-RPC layer can surface the same names wire-clients
/// already know.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignWeightCode {
    EnoughPermission,
    NotEnoughPermission,
    SignatureFormatError,
    ComputeAddressError,
    /// At least one recovered signer wasn't a key in the permission.
    PermissionError,
    OtherError,
}

impl SignWeightCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EnoughPermission => "ENOUGH_PERMISSION",
            Self::NotEnoughPermission => "NOT_ENOUGH_PERMISSION",
            Self::SignatureFormatError => "SIGNATURE_FORMAT_ERROR",
            Self::ComputeAddressError => "COMPUTE_ADDRESS_ERROR",
            Self::PermissionError => "PERMISSION_ERROR",
            Self::OtherError => "OTHER_ERROR",
        }
    }
}

/// Compute the sign-weight summary for `tx`. Mirrors
/// `Wallet.getTransactionSignWeight`. Unlike
/// [`check_transaction_permission`], this function does NOT raise on
/// insufficient weight or unknown signers — it records them in the
/// returned struct so the RPC layer can return a structured
/// `{code, message}` response.
///
/// Returns `Err` only for hard structural problems (missing
/// `raw_data`/`contract`, malformed owner field, account lookup IO
/// error) — same error class as `check_transaction_permission`'s early
/// returns. The "soft" failures (sig format, recovery, permission)
/// surface as `SignWeightCode` variants.
pub fn compute_sign_weight(
    accounts: &AccountStore,
    _dyn_props: &DynamicPropertiesStore,
    tx: &Transaction,
) -> Result<SignWeight, PermissionError> {
    let raw = tx
        .raw_data
        .as_ref()
        .ok_or(PermissionError::DecodeOwner("missing raw_data"))?;
    let contract = raw
        .contract
        .first()
        .ok_or(PermissionError::DecodeOwner("missing contract"))?;
    let contract_type = ContractType::try_from(contract.r#type)
        .map_err(|_| PermissionError::DecodeOwner("unknown contract type"))?;

    let owner = extract_owner_address(contract, contract_type)?;
    let account = accounts
        .get(&owner)
        .map_err(|_| PermissionError::OwnerAccountMissing)?
        .ok_or(PermissionError::OwnerAccountMissing)?;
    let permission = resolve_permission(&account, contract.permission_id, &owner)?;

    // Recover every signature — track format errors as a soft code.
    let mut approved_list: Vec<Address> = Vec::with_capacity(tx.signature.len());
    let mut format_err = false;
    let mut compute_err = false;
    for sig_bytes in &tx.signature {
        match tron_crypto::signature::RecoverableSignature::from_bytes(sig_bytes) {
            Ok(sig) => {
                let id = match tron_types::tx_id(tx) {
                    Ok(id) => id,
                    Err(_) => {
                        compute_err = true;
                        continue;
                    }
                };
                match sig.recover_uncompressed_pubkey(&id) {
                    Ok(pubkey) => match Address::from_uncompressed_pubkey(&pubkey) {
                        Ok(addr) => approved_list.push(addr),
                        Err(_) => compute_err = true,
                    },
                    Err(_) => compute_err = true,
                }
            }
            Err(_) => format_err = true,
        }
    }

    // Sum the weights of signers IN the permission (dedup by address).
    let mut seen: Vec<Address> = Vec::new();
    let mut current_weight: i64 = 0;
    let mut not_in_permission = false;
    for signer in &approved_list {
        if seen.iter().any(|s| s == signer) {
            continue;
        }
        seen.push(signer.clone());
        if let Some(key) = permission
            .keys
            .iter()
            .find(|k| k.address == signer.as_bytes())
        {
            current_weight = current_weight.saturating_add(key.weight);
        } else {
            not_in_permission = true;
        }
    }

    let (code, message) = if format_err {
        (
            SignWeightCode::SignatureFormatError,
            "one or more signatures had invalid format".into(),
        )
    } else if compute_err {
        (
            SignWeightCode::ComputeAddressError,
            "signer recovery failed for one or more signatures".into(),
        )
    } else if not_in_permission {
        (
            SignWeightCode::PermissionError,
            "one or more signers not in permission".into(),
        )
    } else if current_weight >= permission.threshold {
        (SignWeightCode::EnoughPermission, String::new())
    } else {
        (
            SignWeightCode::NotEnoughPermission,
            format!(
                "current_weight {current_weight} < threshold {}",
                permission.threshold
            ),
        )
    };

    Ok(SignWeight {
        permission,
        approved_list,
        current_weight,
        code,
        message,
    })
}

/// Recover the signer list from `tx.signature[]`, returning the
/// addresses or surfacing a recovery error. Convenience wrapper used
/// by the JSON-RPC `getApprovedList` handler. The full `SignWeight`
/// flow is in [`compute_sign_weight`].
pub fn approved_list(tx: &Transaction) -> Result<Vec<Address>, PermissionError> {
    tron_types::recover_all_signers(tx).map_err(|e| PermissionError::Recover(e.to_string()))
}

/// Resolve the active permission for the given `permission_id`.
/// Falls back to a synthetic single-signer permission keyed on the
/// owner address when the account has none configured (the common
/// case before any user runs `AccountPermissionUpdate`).
fn resolve_permission(
    account: &Account,
    permission_id: i32,
    owner: &Address,
) -> Result<Permission, PermissionError> {
    match permission_id {
        0 => {
            if let Some(p) = &account.owner_permission {
                return Ok(p.clone());
            }
            // Synthetic default for accounts that never set a custom
            // owner permission: a single key (the owner) with weight 1
            // and threshold 1.
            Ok(default_permission(
                PermissionType::Owner,
                owner.as_bytes(),
                "owner",
            ))
        }
        1 => {
            if let Some(p) = &account.witness_permission {
                Ok(p.clone())
            } else {
                Ok(default_permission(
                    PermissionType::Witness,
                    owner.as_bytes(),
                    "witness",
                ))
            }
        }
        n if n >= 2 => {
            // Match on the stored `Permission.id` field — NOT the
            // array index. `AccountPermissionUpdateActuator.validate`
            // enforces `actives[i].id == 2 + i` so in practice the
            // index lookup would also work, but the array-index
            // assumption is fragile against (a) state imported from a
            // java-tron snapshot that predates the validator's strict
            // gate, or (b) any future writer that lands actives with
            // non-contiguous IDs. Mirrors java-tron's
            // `AccountCapsule.getPermissionById`.
            account
                .active_permission
                .iter()
                .find(|p| p.id == n)
                .cloned()
                .ok_or(PermissionError::PermissionIdNotFound(n))
        }
        n => Err(PermissionError::PermissionIdNotFound(n)),
    }
}

// The default-permission-on-create logic (java's `withDefaultPermission`
// branch) lives in `tron-chainbase` so the VM commit path can share it; the
// actuators reach it through this re-export.
pub(crate) use tron_chainbase::apply_default_account_permissions;

fn default_permission(ty: PermissionType, owner: &[u8; 21], name: &str) -> Permission {
    Permission {
        r#type: ty as i32,
        id: ty as i32, // 0 for Owner, 1 for Witness — matches the legacy default.
        permission_name: name.to_string(),
        threshold: 1,
        parent_id: 0,
        operations: Vec::new(),
        keys: vec![tron_proto::Key {
            address: owner.to_vec(),
            weight: 1,
        }],
    }
}

/// Check that `contract_type`'s bit is set in `permission.operations`
/// (the 32-byte bitmap on Active permissions).
fn check_operation_allowed(
    permission: &Permission,
    contract_type: ContractType,
) -> Result<(), PermissionError> {
    let bit_index = contract_type as usize;
    let byte_idx = bit_index / 8;
    let bit = 1u8 << (bit_index % 8);
    if byte_idx >= permission.operations.len() {
        return Err(PermissionError::OperationsDisallowedContract);
    }
    if permission.operations[byte_idx] & bit == 0 {
        return Err(PermissionError::OperationsDisallowedContract);
    }
    Ok(())
}

/// Pull the owner address bytes out of the contract proto. java-tron
/// has a switch over every ContractType returning the appropriate
/// owner-bearing field; we hand-roll the common cases and fall back
/// to `Validate("unsupported contract type")` for the long tail.
fn extract_owner_address(
    contract: &Contract,
    ty: ContractType,
) -> Result<Address, PermissionError> {
    use prost::Message;
    let parameter = contract
        .parameter
        .as_ref()
        .ok_or(PermissionError::DecodeOwner("missing parameter"))?;
    macro_rules! unpack {
        ($T:ty) => {{
            let c = <$T as Message>::decode(parameter.value.as_slice())
                .map_err(|_| PermissionError::DecodeOwner(concat!("decode ", stringify!($T))))?;
            c.owner_address
        }};
    }
    let owner_bytes = match ty {
        ContractType::TransferContract => unpack!(tron_proto::TransferContract),
        ContractType::TransferAssetContract => unpack!(tron_proto::TransferAssetContract),
        ContractType::VoteWitnessContract => unpack!(tron_proto::VoteWitnessContract),
        // java extracts owner_address reflectively for ANY contract type with an
        // owner_address field (TransactionCapsule.getOwner), so the permission
        // gate must accept these too — the bandwidth extractor and dispatch
        // already handle them. Omitting them rejected a canonical ClearABIContract
        // tx (PermissionDenied) that java commits → silent state divergence.
        ContractType::VoteAssetContract => unpack!(tron_proto::VoteAssetContract),
        ContractType::ClearAbiContract => unpack!(tron_proto::ClearAbiContract),
        ContractType::WitnessCreateContract => unpack!(tron_proto::WitnessCreateContract),
        ContractType::WitnessUpdateContract => unpack!(tron_proto::WitnessUpdateContract),
        ContractType::UpdateBrokerageContract => unpack!(tron_proto::UpdateBrokerageContract),
        ContractType::WithdrawBalanceContract => unpack!(tron_proto::WithdrawBalanceContract),
        ContractType::AccountCreateContract => unpack!(tron_proto::AccountCreateContract),
        ContractType::AccountUpdateContract => unpack!(tron_proto::AccountUpdateContract),
        ContractType::SetAccountIdContract => unpack!(tron_proto::SetAccountIdContract),
        ContractType::AccountPermissionUpdateContract => {
            unpack!(tron_proto::AccountPermissionUpdateContract)
        }
        ContractType::AssetIssueContract => unpack!(tron_proto::AssetIssueContract),
        ContractType::UpdateAssetContract => unpack!(tron_proto::UpdateAssetContract),
        ContractType::ParticipateAssetIssueContract => {
            unpack!(tron_proto::ParticipateAssetIssueContract)
        }
        ContractType::UnfreezeAssetContract => unpack!(tron_proto::UnfreezeAssetContract),
        ContractType::FreezeBalanceContract => unpack!(tron_proto::FreezeBalanceContract),
        ContractType::UnfreezeBalanceContract => unpack!(tron_proto::UnfreezeBalanceContract),
        ContractType::FreezeBalanceV2Contract => unpack!(tron_proto::FreezeBalanceV2Contract),
        ContractType::UnfreezeBalanceV2Contract => unpack!(tron_proto::UnfreezeBalanceV2Contract),
        ContractType::WithdrawExpireUnfreezeContract => {
            unpack!(tron_proto::WithdrawExpireUnfreezeContract)
        }
        ContractType::DelegateResourceContract => unpack!(tron_proto::DelegateResourceContract),
        ContractType::UnDelegateResourceContract => unpack!(tron_proto::UnDelegateResourceContract),
        ContractType::CancelAllUnfreezeV2Contract => {
            unpack!(tron_proto::CancelAllUnfreezeV2Contract)
        }
        ContractType::CreateSmartContract => {
            let c = tron_proto::CreateSmartContract::decode(parameter.value.as_slice())
                .map_err(|_| PermissionError::DecodeOwner("decode CreateSmartContract"))?;
            c.owner_address
        }
        ContractType::TriggerSmartContract => unpack!(tron_proto::TriggerSmartContract),
        ContractType::UpdateSettingContract => unpack!(tron_proto::UpdateSettingContract),
        ContractType::UpdateEnergyLimitContract => unpack!(tron_proto::UpdateEnergyLimitContract),
        ContractType::ProposalCreateContract => unpack!(tron_proto::ProposalCreateContract),
        ContractType::ProposalApproveContract => unpack!(tron_proto::ProposalApproveContract),
        ContractType::ProposalDeleteContract => unpack!(tron_proto::ProposalDeleteContract),
        ContractType::ExchangeCreateContract => unpack!(tron_proto::ExchangeCreateContract),
        ContractType::ExchangeInjectContract => unpack!(tron_proto::ExchangeInjectContract),
        ContractType::ExchangeWithdrawContract => unpack!(tron_proto::ExchangeWithdrawContract),
        ContractType::ExchangeTransactionContract => {
            unpack!(tron_proto::ExchangeTransactionContract)
        }
        ContractType::MarketSellAssetContract => unpack!(tron_proto::MarketSellAssetContract),
        ContractType::MarketCancelOrderContract => unpack!(tron_proto::MarketCancelOrderContract),
        ContractType::ShieldedTransferContract => {
            let c = tron_proto::ShieldedTransferContract::decode(parameter.value.as_slice())
                .map_err(|_| PermissionError::DecodeOwner("decode ShieldedTransferContract"))?;
            // For shielded txs, the "owner" for permission purposes is
            // the transparent-from address. If it's empty (fully
            // shielded), permission enforcement is a no-op — the
            // shielded actuator does its own checks.
            c.transparent_from_address
        }
        _ => return Err(PermissionError::DecodeOwner("unsupported contract type")),
    };
    if owner_bytes.len() != 21 {
        return Err(PermissionError::DecodeOwner("owner not 21 bytes"));
    }
    let mut buf = [0u8; 21];
    buf.copy_from_slice(&owner_bytes);
    Ok(Address::from_raw(buf))
}
