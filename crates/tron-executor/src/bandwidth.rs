//! Bandwidth accounting per java-tron's `BandwidthProcessor`.
//!
//! For every non-shielded transaction, the sender pays for the bytes
//! they put on the wire. Java-tron's priority order, in
//! `BandwidthProcessor.consume()`:
//!
//! 1. **`contractCreateNewAccount`** — if the contract creates a fresh
//!    account, pay the new-account net cost (`createNewAccountBandwidthRate
//!    * bytes`) from frozen net, falling back to `createAccountFee` in TRX.
//! 2. **`useAssetAccountNet`** — for `TransferAssetContract` only: try
//!    the asset-issuer-funded public/free quota first. If the issuer hasn't
//!    funded enough, fall through to (3).
//! 3. **`useAccountNet`** — windowed-average decay of `net_usage` against
//!    the **global-scaled** `net_limit` derived from `frozen_v2[BANDWIDTH]`
//!    via `TOTAL_NET_LIMIT / TOTAL_NET_WEIGHT`.
//! 4. **`useFreeNet`** — every account gets a daily free quota
//!    (`FREE_NET_LIMIT`, default 5000 bytes); spending it also bumps the
//!    chain-wide `PUBLIC_NET_USAGE` against `PUBLIC_NET_LIMIT`.
//! 5. **`useTransactionFee`** — last resort: `bytes * TRANSACTION_FEE` sun
//!    is debited from the sender's TRX balance and either burned (default),
//!    pushed to `TRANSACTION_FEE_POOL` (if active), or sent to the blackhole
//!    account.
//!
//! All quota paths use the windowed-average math from [`crate::resource`]
//! with a 28_800-block (24h / 3s) window and `PRECISION = 1_000_000`.
//! Times are slot units (`latest_block_header_number`), not wall-clock.
//!
//! Byte accounting mirrors java-tron's `supportVM()` branch: the
//! clear-ret serialized size plus `MAX_RESULT_SIZE_IN_TX` (64) padding
//! per contract when the VM fork is active, the full serialized size
//! otherwise.
//!
//! **What's still not modeled** (deferred): the pre-blackhole-
//! optimization fee disposal credits the burn counter instead of the
//! blackhole *account* (identical supply tracking; see
//! [`pay_bandwidth_fee`] / [`dispose_fee`]).

use prost::Message;
use tron_chainbase::{
    AccountStore, AssetIssueStore, AssetIssueV2Store, DynamicPropertiesStore, StoreError,
};
use tron_crypto::address::Address;
use tron_proto::transaction::contract::ContractType;
use tron_proto::transaction::Contract;
use tron_proto::{Account, Transaction, TransferAssetContract};

use crate::resource::{
    calculate_global_limit_v1, calculate_global_net_limit_v2, increase_account, increase_default,
    recovery_account, ResourceGates, ResourceKind, TRX_PRECISION,
};

// Re-export the shared constants here so existing callers (and tests
// that import them under this module path) keep compiling.
pub use crate::resource::{
    increase_default as increase, PRECISION, WINDOW_SIZE_BLOCKS,
};

/// java-tron default `FREE_NET_LIMIT` value. Kept here for downstream
/// callers / tests that imported it under this module path; prefer
/// `DynamicPropertiesStore::DEFAULT_FREE_NET_LIMIT` for new code.
pub const DEFAULT_FREE_NET_LIMIT: i64 = DynamicPropertiesStore::DEFAULT_FREE_NET_LIMIT;
/// java-tron default `TRANSACTION_FEE` value.
pub const DEFAULT_TRANSACTION_FEE: i64 = DynamicPropertiesStore::DEFAULT_TRANSACTION_FEE;

/// What happened during a `consume_bandwidth` call. The driver/RPC
/// layer can map these to receipt fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BandwidthCharge {
    /// Charged against the account's frozen-bandwidth quota.
    Frozen { bytes: i64, new_net_usage: i64 },
    /// Charged against the daily free quota (and chain-wide
    /// `PUBLIC_NET_USAGE`).
    Free { bytes: i64, new_free_usage: i64 },
    /// Charged against the asset issuer's quotas (the TRC-10
    /// `useAssetAccountNet` path).
    AssetIssuer {
        bytes: i64,
        token_id: i64,
        /// The asset-issuer account's `net_usage` after this charge.
        new_issuer_net_usage: i64,
    },
    /// Paid in TRX (deducted from balance).
    Fee { bytes: i64, fee_sun: i64 },
    /// The contract creates a fresh account and the owner's frozen
    /// bandwidth covered the special new-account net cost
    /// (`bytes × createNewAccountBandwidthRate`). Maps to
    /// `receipt.net_usage = net_cost` (java-tron
    /// `setNetBillForCreateNewAccount(netCost, 0)`).
    CreateNewAccountFrozen { net_cost: i64, new_net_usage: i64 },
    /// The contract creates a fresh account and frozen bandwidth could
    /// not cover it: the flat `CREATE_ACCOUNT_FEE` (0.1 TRX default)
    /// was debited and burned. Maps to `receipt.net_fee = fee_sun`.
    CreateNewAccountFee { fee_sun: i64 },
}

/// Hard errors — caller should reject the transaction.
#[derive(Debug, thiserror::Error)]
pub enum BandwidthError {
    #[error("account not found")]
    AccountMissing,
    #[error("account has insufficient bandwidth + balance to cover {bytes} bytes ({fee_sun} sun fee)")]
    Insufficient { bytes: i64, fee_sun: i64 },
    #[error("asset issuer account missing for token {0}")]
    AssetIssuerMissing(i64),
    #[error("transfer asset contract references unknown asset {0:?}")]
    UnknownAsset(Vec<u8>),
    #[error(
        "account has insufficient bandwidth[{bytes}] and balance[{fee_sun}] to create new account"
    )]
    InsufficientForNewAccount { bytes: i64, fee_sun: i64 },
    #[error("too big new account transaction, the size is {size} bytes, maxTxSize {max}")]
    TooBigCreateAccountTx { size: i64, max: i64 },
    #[error("too big transaction result, the result size is {size} bytes, maxResultSize {max}")]
    TooBigTransactionResult { size: i64, max: i64 },
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Bundle of stores the bandwidth path may consult. `asset_v1` and
/// `asset_v2` are only read for `TransferAssetContract` (the
/// `useAssetAccountNet` branch).
pub struct BandwidthStores<'a> {
    pub accounts: &'a AccountStore,
    pub dyn_props: &'a DynamicPropertiesStore,
    pub asset_v1: &'a AssetIssueStore,
    pub asset_v2: &'a AssetIssueV2Store,
}

/// Consume bandwidth for `tx` at slot-time `now_slot`. Mirrors
/// `BandwidthProcessor.consume()`. Mutates the owner's account row in
/// `accounts` (and possibly the asset issuer's account + the asset row).
///
/// `contract` is the first (and currently only) [`Contract`] inside
/// `tx.raw_data` — passed in so the asset path can read its parameter
/// without a redundant decode.
///
/// Returns the kind of charge applied. The serialized size is computed
/// on a tx with `ret` cleared (java-tron's
/// `clear_ret().getSerializedSize()` in the VM-enabled branch).
pub fn consume_bandwidth(
    stores: BandwidthStores<'_>,
    tx: &Transaction,
    contract: &Contract,
    owner: &Address,
    now_slot: i64,
) -> Result<BandwidthCharge, BandwidthError> {
    // java unconditionally rejects an oversized stored result before
    // any charging (`getResultSerializedSize() > MAX_RESULT_SIZE_IN_TX
    // * contracts.size()`); honest blocks never trip it (`ret` is just
    // the contractRet verdict).
    let result_size: i64 = tx.ret.iter().map(|r| r.encoded_len() as i64).sum();
    if result_size > MAX_RESULT_SIZE_IN_TX {
        return Err(BandwidthError::TooBigTransactionResult {
            size: result_size,
            max: MAX_RESULT_SIZE_IN_TX,
        });
    }

    // Byte accounting, both supportVM branches: clear-ret size plus
    // the per-contract MAX_RESULT_SIZE_IN_TX padding when the VM fork
    // is active (mainnet), the full serialized size otherwise.
    let support_vm = stores.dyn_props.support_vm();
    let bytes = if support_vm {
        serialized_bytes(tx) as i64 + MAX_RESULT_SIZE_IN_TX
    } else {
        tx.encoded_len() as i64
    };
    let mut account = stores
        .accounts
        .get(owner)?
        .ok_or(BandwidthError::AccountMissing)?;

    let ty = ContractType::try_from(contract.r#type).unwrap_or(ContractType::AccountCreateContract);

    // === contractCreateNewAccount — the special new-account charge ===
    //
    // A contract that creates a fresh account (AccountCreateContract,
    // or a Transfer/TransferAsset to a non-existent address) pays
    // `bytes × createNewAccountBandwidthRate` from frozen bandwidth,
    // falling back to the flat CREATE_ACCOUNT_FEE in TRX — it never
    // touches the free quota or the per-byte fee path.
    if contract_creates_new_account(stores.accounts, contract)? {
        // The in-block size gate rides the consensus-logic-optimization
        // fork (java's `optimizeTxs` is true for in-block txs only when
        // that flag is active).
        if stores.dyn_props.allow_consensus_logic_optimization() {
            let max = stores.dyn_props.max_create_account_tx_size();
            let create_size =
                serialized_bytes(tx) as i64 - tx.signature.len() as i64 * PER_SIGN_LENGTH;
            if create_size > max {
                return Err(BandwidthError::TooBigCreateAccountTx { size: create_size, max });
            }
        }
        return consume_for_create_new_account(&stores, &mut account, owner, bytes, now_slot);
    }

    // === useAssetAccountNet (TransferAssetContract only) ===
    //
    // Try the issuer-funded path first. On failure (insufficient public
    // quota / free-asset quota / issuer net), fall through to the normal
    // account-net path.
    if matches!(ty, ContractType::TransferAssetContract) {
        match try_use_asset_account_net(&stores, contract, &mut account, owner, bytes, now_slot)? {
            Some(charge) => return Ok(charge),
            None => { /* fall through */ }
        }
    }

    // === useAccountNet — frozen-bandwidth quota with global scaling ===
    if let Some(charge) = try_use_account_net(
        stores.accounts,
        stores.dyn_props,
        &mut account,
        owner,
        bytes,
        now_slot,
    )? {
        return Ok(charge);
    }

    // === useFreeNet — daily free quota + chain-wide PUBLIC_NET tracking ===
    if let Some(charge) = try_use_free_net(
        stores.accounts,
        stores.dyn_props,
        &mut account,
        owner,
        bytes,
        now_slot,
    )? {
        return Ok(charge);
    }

    // === useTransactionFee — last resort: TRX fee ===
    let fee_per_byte = stores.dyn_props.transaction_fee();
    let fee = bytes.saturating_mul(fee_per_byte);
    if account.balance < fee {
        return Err(BandwidthError::Insufficient {
            bytes,
            fee_sun: fee,
        });
    }
    account.balance -= fee;
    account.latest_opration_time = head_block_timestamp(stores.dyn_props);
    stores.accounts.put(owner, &account)?;
    pay_bandwidth_fee(stores.dyn_props, fee);
    Ok(BandwidthCharge::Fee {
        bytes,
        fee_sun: fee,
    })
}

/// Try the `useAssetAccountNet` path. Returns:
/// * `Ok(Some(charge))` — the issuer's quotas covered the cost.
/// * `Ok(None)`         — quotas insufficient; the caller should fall
///   through to `useAccountNet`/`useFreeNet`/`useTransactionFee`.
/// * `Err(e)`           — the contract is malformed or references an
///   unknown asset (no fallthrough makes sense — reject the tx).
///
/// Mirrors `BandwidthProcessor.useAssetAccountNet`. The flow:
///
/// 1. Decode the [`TransferAssetContract`], look up the asset by id
///    (v2) or name (v1, when `ALLOW_SAME_TOKEN_NAME == 0`).
/// 2. If the sender *is* the issuer, defer to `useAccountNet` (return
///    `Ok(None)` and let the caller handle it).
/// 3. Decay-check the issuer's `public_free_asset_net_usage` vs the
///    asset's `public_free_asset_net_limit`. Decay-check the sender's
///    `free_asset_net_usage` vs `free_asset_net_limit`. Decay-check
///    the issuer's `net_usage` vs their global net limit.
/// 4. On success: bump all three usages, persist (sender, issuer,
///    asset row).
fn try_use_asset_account_net(
    stores: &BandwidthStores<'_>,
    contract: &Contract,
    account: &mut Account,
    owner: &Address,
    bytes: i64,
    now_slot: i64,
) -> Result<Option<BandwidthCharge>, BandwidthError> {
    let parameter = match contract.parameter.as_ref() {
        Some(p) => p,
        None => return Ok(None),
    };
    let transfer = TransferAssetContract::decode(parameter.value.as_slice())
        .map_err(|e| BandwidthError::Store(StoreError::Decode(e.to_string())))?;

    let asset_name = transfer.asset_name;
    if asset_name.is_empty() {
        return Err(BandwidthError::UnknownAsset(asset_name));
    }

    // V1 (lookup by name) when ALLOW_SAME_TOKEN_NAME is *not* set;
    // otherwise V2 (lookup by id-string). For v2 the asset_name field
    // is the id encoded as decimal-string ASCII bytes.
    let allow_same_token_name = stores.dyn_props.allow_same_token_name().unwrap_or(0);
    let mut asset = if allow_same_token_name == 0 {
        // V1 lookup by name; fallback to V2 by parsed-id if absent
        // (mirrors `Commons.getAssetIssueStoreFinal` precedence).
        if let Some(a) = stores.asset_v1.get(&asset_name)? {
            a
        } else if let Ok(id) = std::str::from_utf8(&asset_name)
            .map_err(|_| ())
            .and_then(|s| s.parse::<i64>().map_err(|_| ()))
        {
            stores
                .asset_v2
                .get(id)?
                .ok_or(BandwidthError::UnknownAsset(asset_name.clone()))?
        } else {
            return Err(BandwidthError::UnknownAsset(asset_name));
        }
    } else {
        // V2: asset_name is the id (decimal string ascii).
        let id = std::str::from_utf8(&asset_name)
            .map_err(|_| BandwidthError::UnknownAsset(asset_name.clone()))?
            .parse::<i64>()
            .map_err(|_| BandwidthError::UnknownAsset(asset_name.clone()))?;
        stores
            .asset_v2
            .get(id)?
            .ok_or(BandwidthError::UnknownAsset(asset_name))?
    };

    // If sender IS the issuer, defer to useAccountNet.
    if asset.owner_address == owner.as_bytes() {
        return Ok(None);
    }

    let token_id_str: String = asset.id.clone();
    let token_id_num: i64 = token_id_str.parse().unwrap_or(0);
    let token_name_str: String = String::from_utf8_lossy(&asset.name).into_owned();

    // --- 1. Issuer public-free-asset-net quota ---
    let pub_limit = asset.public_free_asset_net_limit;
    let pub_usage = asset.public_free_asset_net_usage;
    let pub_last = asset.public_latest_free_net_time;
    let new_pub_usage = increase_default(pub_usage, 0, pub_last, now_slot);
    if bytes > pub_limit.saturating_sub(new_pub_usage) {
        return Ok(None);
    }

    // --- 2. Sender per-asset free quota ---
    let asset_free_limit = asset.free_asset_net_limit;
    let (free_asset_usage, latest_asset_op_time) = if allow_same_token_name == 0 {
        // V1 path uses the name-keyed map.
        (
            *account
                .free_asset_net_usage
                .get(&token_name_str)
                .unwrap_or(&0),
            *account
                .latest_asset_operation_time
                .get(&token_name_str)
                .unwrap_or(&0),
        )
    } else {
        // V2 uses the id-keyed map.
        (
            *account
                .free_asset_net_usage_v2
                .get(&token_id_str)
                .unwrap_or(&0),
            *account
                .latest_asset_operation_time_v2
                .get(&token_id_str)
                .unwrap_or(&0),
        )
    };
    let new_free_asset_usage = increase_default(free_asset_usage, 0, latest_asset_op_time, now_slot);
    if bytes > asset_free_limit.saturating_sub(new_free_asset_usage) {
        return Ok(None);
    }

    // --- 3. Issuer's global net quota ---
    let issuer_addr = address_from_proto(&asset.owner_address)
        .ok_or(BandwidthError::AssetIssuerMissing(token_id_num))?;
    let mut issuer = stores
        .accounts
        .get(&issuer_addr)?
        .ok_or(BandwidthError::AssetIssuerMissing(token_id_num))?;

    let issuer_net_usage = issuer.net_usage;
    let issuer_last_consume = issuer.latest_consume_time;
    let issuer_net_limit = calculate_global_net_limit(&issuer, stores.dyn_props);
    let support_unfreeze_delay = stores.dyn_props.support_unfreeze_delay();
    let new_issuer_net_usage = if support_unfreeze_delay {
        // Window-interpreted decay — see `try_use_account_net`.
        recovery_account(
            &issuer,
            ResourceKind::Bandwidth,
            issuer_net_usage,
            issuer_last_consume,
            now_slot,
            stores.dyn_props.allow_harden_resource_calculation(),
        )
    } else {
        increase_default(issuer_net_usage, 0, issuer_last_consume, now_slot)
    };
    if bytes > issuer_net_limit.saturating_sub(new_issuer_net_usage) {
        return Ok(None);
    }

    // --- All three quotas have headroom. Apply and persist. ---
    let final_pub_usage = increase_default(new_pub_usage, bytes, now_slot, now_slot);
    let final_free_asset_usage =
        increase_default(new_free_asset_usage, bytes, now_slot, now_slot);
    let final_issuer_net_usage = if support_unfreeze_delay {
        // Account-aware growth (java `increase(issuerAccountCapsule,
        // BANDWIDTH, …)`): decays with the issuer's interpreted window
        // and recomputes + writes the window fields back, exactly like
        // the `useAccountNet` path. The previous default-window
        // shortcut both ignored non-default issuer windows and never
        // maintained them.
        let gates = ResourceGates {
            support_unfreeze_delay: true,
            support_allow_cancel_all_unfreeze_v2: stores
                .dyn_props
                .support_allow_cancel_all_unfreeze_v2(),
        };
        increase_account(
            &mut issuer,
            ResourceKind::Bandwidth,
            issuer_net_usage,
            bytes,
            issuer_last_consume,
            now_slot,
            gates,
        )
    } else {
        increase_default(new_issuer_net_usage, bytes, now_slot, now_slot)
    };
    // Max-out overshoot cap (see `try_use_account_net`).
    let final_issuer_net_usage = if bytes == issuer_net_limit.saturating_sub(new_issuer_net_usage) {
        final_issuer_net_usage.min(issuer_net_limit)
    } else {
        final_issuer_net_usage
    };

    // Persist the asset row.
    asset.public_free_asset_net_usage = final_pub_usage;
    asset.public_latest_free_net_time = now_slot;

    // Persist the issuer account.
    issuer.net_usage = final_issuer_net_usage;
    issuer.latest_consume_time = now_slot;

    // Persist the sender account: free-asset usage + latest-op times.
    if allow_same_token_name == 0 {
        // V1 mode writes BOTH maps (name and id keys) on the sender,
        // and BOTH the v1 and v2 store rows. java-tron parity.
        account
            .latest_asset_operation_time
            .insert(token_name_str.clone(), now_slot);
        account
            .free_asset_net_usage
            .insert(token_name_str.clone(), final_free_asset_usage);
        account
            .latest_asset_operation_time_v2
            .insert(token_id_str.clone(), now_slot);
        account
            .free_asset_net_usage_v2
            .insert(token_id_str.clone(), final_free_asset_usage);
        // Mirror the issuer's public-quota update into the v2 asset row.
        if let Some(mut v2_row) = stores.asset_v2.get(token_id_num)? {
            v2_row.public_free_asset_net_usage = final_pub_usage;
            v2_row.public_latest_free_net_time = now_slot;
            stores.asset_v2.put(token_id_num, &v2_row)?;
        }
        stores.asset_v1.put(&asset.name.clone(), &asset)?;
    } else {
        account
            .latest_asset_operation_time_v2
            .insert(token_id_str.clone(), now_slot);
        account
            .free_asset_net_usage_v2
            .insert(token_id_str.clone(), final_free_asset_usage);
        stores.asset_v2.put(token_id_num, &asset)?;
    }
    account.latest_opration_time = head_block_timestamp(stores.dyn_props);

    stores.accounts.put(owner, account)?;
    stores.accounts.put(&issuer_addr, &issuer)?;

    Ok(Some(BandwidthCharge::AssetIssuer {
        bytes,
        token_id: token_id_num,
        new_issuer_net_usage: final_issuer_net_usage,
    }))
}

/// Try the `useAccountNet` path. Returns `Some(charge)` on success;
/// `None` if the account's frozen-bandwidth quota can't cover `bytes`
/// (caller must try free → fee).
fn try_use_account_net(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    account: &mut Account,
    owner: &Address,
    bytes: i64,
    now_slot: i64,
) -> Result<Option<BandwidthCharge>, StoreError> {
    let net_limit = calculate_global_net_limit(account, dyn_props);
    if net_limit <= 0 {
        return Ok(None);
    }
    let last_consume = account.latest_consume_time;
    let support_unfreeze_delay = dyn_props.support_unfreeze_delay();
    let decayed = if support_unfreeze_delay {
        // Window-INTERPRETED decay (java `recovery(accountCapsule, …)` →
        // `getWindowSize`): an optimized window stores its value
        // precision-scaled ×1000, so passing the raw field here (the
        // previous code) read a 28800000-valued window as 28.8M slots —
        // usage then barely decayed and txs spilled to the free/fee paths
        // java serves from the staked quota.
        recovery_account(
            account,
            ResourceKind::Bandwidth,
            account.net_usage,
            last_consume,
            now_slot,
            dyn_props.allow_harden_resource_calculation(),
        )
    } else {
        increase_default(account.net_usage, 0, last_consume, now_slot)
    };
    if bytes > net_limit.saturating_sub(decayed) {
        return Ok(None);
    }

    // Growth. java-tron's `useAccountNet`: with supportUnfreezeDelay the
    // account-aware `increase()` recomputes AND writes back the per-account
    // net window size (net_window_size / net_window_optimized); without it,
    // a plain default-window increase on the decayed value.
    let cur_usage = account.net_usage;
    let new_usage = if support_unfreeze_delay {
        let gates = ResourceGates {
            support_unfreeze_delay: true,
            support_allow_cancel_all_unfreeze_v2: dyn_props.support_allow_cancel_all_unfreeze_v2(),
        };
        increase_account(account, ResourceKind::Bandwidth, cur_usage, bytes, last_consume, now_slot, gates)
    } else {
        increase_default(decayed, bytes, now_slot, now_slot)
    };
    // Max-out overshoot cap (mirrors the energy path): staking the exact full
    // quota (`bytes == net_limit - decayed`) is 100% usage, so the stored
    // windowed net_usage must land on net_limit, not net_limit+1 (the budget
    // floors `decayed` but increase() adds `bytes` to the un-floored decayed
    // average, carrying one extra). Only the full-quota case can overshoot.
    let new_usage = if bytes == net_limit.saturating_sub(decayed) {
        new_usage.min(net_limit)
    } else {
        new_usage
    };
    account.net_usage = new_usage;
    account.latest_consume_time = now_slot;
    account.latest_opration_time = head_block_timestamp(dyn_props);
    accounts.put(owner, account)?;
    Ok(Some(BandwidthCharge::Frozen {
        bytes,
        new_net_usage: new_usage,
    }))
}

/// `Constant.MAX_RESULT_SIZE_IN_TX` — the per-contract byte padding
/// java adds under `supportVM()`, and the stored-result size cap.
pub const MAX_RESULT_SIZE_IN_TX: i64 = 64;
/// `Constant.PER_SIGN_LENGTH` — bytes attributed to one signature in
/// the max-create-account-tx-size check.
const PER_SIGN_LENGTH: i64 = 65;

/// `BandwidthProcessor.contractCreateNewAccount`: does this contract
/// create a fresh account? `AccountCreateContract` always; a Transfer /
/// TransferAsset when the destination account doesn't exist. Malformed
/// parameters resolve as "creates" (java NPEs into rejection either
/// way — the actuator validate rejects the tx and the charge reverts
/// with it).
fn contract_creates_new_account(
    accounts: &AccountStore,
    contract: &Contract,
) -> Result<bool, BandwidthError> {
    let param = contract.parameter.as_ref().map(|p| p.value.as_slice()).unwrap_or(&[]);
    let to_missing = |to_bytes: &[u8], accounts: &AccountStore| -> Result<bool, BandwidthError> {
        match address_from_proto(to_bytes) {
            Some(to) => Ok(accounts.get(&to)?.is_none()),
            None => Ok(true),
        }
    };
    match ContractType::try_from(contract.r#type).ok() {
        Some(ContractType::AccountCreateContract) => Ok(true),
        Some(ContractType::TransferContract) => match tron_proto::TransferContract::decode(param)
        {
            Ok(c) => to_missing(&c.to_address, accounts),
            Err(_) => Ok(true),
        },
        Some(ContractType::TransferAssetContract) => {
            match TransferAssetContract::decode(param) {
                Ok(c) => to_missing(&c.to_address, accounts),
                Err(_) => Ok(true),
            }
        }
        _ => Ok(false),
    }
}

/// `BandwidthProcessor.consumeForCreateNewAccount`: frozen bandwidth at
/// the new-account rate, falling back to the flat create-account fee.
fn consume_for_create_new_account(
    stores: &BandwidthStores<'_>,
    account: &mut Account,
    owner: &Address,
    bytes: i64,
    now_slot: i64,
) -> Result<BandwidthCharge, BandwidthError> {
    if let Some(charge) = try_use_net_for_create_new_account(
        stores.accounts,
        stores.dyn_props,
        account,
        owner,
        bytes,
        now_slot,
    )? {
        return Ok(charge);
    }
    // `consumeFeeForCreateNewAccount` → `consumeFeeForNewAccount`: the
    // flat fee burns (no fee-pool branch, unlike the per-byte
    // bandwidth fee) and bumps TOTAL_CREATE_ACCOUNT_COST.
    let fee = stores.dyn_props.create_account_fee();
    if account.balance < fee {
        return Err(BandwidthError::InsufficientForNewAccount { bytes, fee_sun: fee });
    }
    account.latest_opration_time = head_block_timestamp(stores.dyn_props);
    account.balance -= fee;
    stores.accounts.put(owner, account)?;
    dispose_fee(stores.dyn_props, fee);
    stores.dyn_props.add_total_create_account_cost(fee);
    Ok(BandwidthCharge::CreateNewAccountFee { fee_sun: fee })
}

/// `BandwidthProcessor.consumeBandwidthForCreateNewAccount`: identical
/// quota math to [`try_use_account_net`], but the cost is
/// `bytes × createNewAccountBandwidthRate` and there is no
/// `net_limit <= 0` early-out (java charges a zero cost successfully —
/// only reachable with a zero rate, never on mainnet).
fn try_use_net_for_create_new_account(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    account: &mut Account,
    owner: &Address,
    bytes: i64,
    now_slot: i64,
) -> Result<Option<BandwidthCharge>, StoreError> {
    let rate = dyn_props.create_new_account_bandwidth_rate();
    let net_limit = calculate_global_net_limit(account, dyn_props);
    let net_usage = account.net_usage;
    let last_consume = account.latest_consume_time;
    let support_unfreeze_delay = dyn_props.support_unfreeze_delay();
    let decayed = if support_unfreeze_delay {
        recovery_account(
            account,
            ResourceKind::Bandwidth,
            net_usage,
            last_consume,
            now_slot,
            dyn_props.allow_harden_resource_calculation(),
        )
    } else {
        increase_default(net_usage, 0, last_consume, now_slot)
    };
    let net_cost = bytes.saturating_mul(rate);
    if net_cost > net_limit.saturating_sub(decayed) {
        return Ok(None);
    }
    let new_usage = if support_unfreeze_delay {
        let gates = ResourceGates {
            support_unfreeze_delay: true,
            support_allow_cancel_all_unfreeze_v2: dyn_props.support_allow_cancel_all_unfreeze_v2(),
        };
        increase_account(
            account,
            ResourceKind::Bandwidth,
            net_usage,
            net_cost,
            last_consume,
            now_slot,
            gates,
        )
    } else {
        increase_default(decayed, net_cost, now_slot, now_slot)
    };
    // Max-out overshoot cap (see `try_use_account_net`).
    let new_usage = if net_cost == net_limit.saturating_sub(decayed) {
        new_usage.min(net_limit)
    } else {
        new_usage
    };
    account.net_usage = new_usage;
    account.latest_consume_time = now_slot;
    account.latest_opration_time = head_block_timestamp(dyn_props);
    accounts.put(owner, account)?;
    Ok(Some(BandwidthCharge::CreateNewAccountFrozen { net_cost, new_net_usage: new_usage }))
}

/// Flat-fee disposal shared by the create-account fee here and the
/// executor's multi-sign / memo fees (java-tron
/// `ResourceProcessor.consumeFeeForNewAccount` /
/// `Manager.consumeMultiSignFee` / `consumeMemoFee`): burn under the
/// blackhole optimization. The fee pool is deliberately NOT consulted —
/// java only routes `useTransactionFee` bandwidth fees through it.
/// Pre-optimization the credit goes to the blackhole *account*; we burn
/// instead (same compromise as [`pay_bandwidth_fee`], identical supply
/// tracking).
pub fn dispose_fee(dyn_props: &DynamicPropertiesStore, fee: i64) {
    dyn_props.burn_trx(fee);
}

/// Try the `useFreeNet` path. Mirrors `BandwidthProcessor.useFreeNet`,
/// including the chain-wide `PUBLIC_NET_USAGE` accumulator check + bump.
fn try_use_free_net(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    account: &mut Account,
    owner: &Address,
    bytes: i64,
    now_slot: i64,
) -> Result<Option<BandwidthCharge>, StoreError> {
    let free_limit = dyn_props.free_net_limit();
    let last_free = account.latest_consume_free_time;
    let decayed_free = increase_default(account.free_net_usage, 0, last_free, now_slot);
    if bytes > free_limit.saturating_sub(decayed_free) {
        return Ok(None);
    }

    // Chain-wide public-net cap check.
    let pub_limit = dyn_props.public_net_limit();
    let pub_usage = dyn_props.public_net_usage();
    let pub_time = dyn_props.public_net_time();
    let new_pub = increase_default(pub_usage, 0, pub_time, now_slot);
    if bytes > pub_limit.saturating_sub(new_pub) {
        return Ok(None);
    }

    // java `useFreeNet` grows in TWO steps: it first decays the usage to `now`
    // (`newFreeNetUsage = increase(freeNetUsage, 0, latestConsumeFreeTime, now)`
    // — our `decayed_free` above), then sets `latestConsumeFreeTime = now` and
    // grows FROM THE DECAYED VALUE AT `now`
    // (`increase(newFreeNetUsage, bytes, now, now)`). That is NOT equivalent to a
    // single decay-and-grow from the original (`free_net_usage`, `last_free`):
    // the intermediate `getUsage` requantization between the two steps shifts the
    // recorded usage by up to 1 byte on ~2.4% of free-net charges, always
    // upward. Because `free_net_usage` is persisted and free-net consumption
    // burns no TRX (invisible to fee accounting), that drift accumulates
    // silently until a free-net-only account near its 600-byte daily cap is
    // wrongly rejected for "insufficient bandwidth". Every other quota path here
    // already grows from the decayed value at `now` (`try_use_account_net`, the
    // asset path, and `final_pub` immediately below).
    let new_free = increase_default(decayed_free, bytes, now_slot, now_slot);
    let final_pub = increase_default(new_pub, bytes, now_slot, now_slot);
    account.free_net_usage = new_free;
    account.latest_consume_free_time = now_slot;
    account.latest_opration_time = head_block_timestamp(dyn_props);
    accounts.put(owner, account)?;
    dyn_props.save_public_net_usage(final_pub);
    dyn_props.save_public_net_time(now_slot);
    Ok(Some(BandwidthCharge::Free {
        bytes,
        new_free_usage: new_free,
    }))
}

/// Serialized size of the transaction, excluding the `ret` field —
/// java-tron's `tx.toBuilder().clearRet().build().getSerializedSize()`
/// when the VM is supported. We pin that branch as the v1 behavior.
fn serialized_bytes(tx: &Transaction) -> usize {
    // Equivalent to `tx.toBuilder().clearRet().build().getSerializedSize()`
    // but without deep-cloning the whole transaction (the `raw_data`
    // calldata can be large for contract calls) just to drop `ret`.
    //
    // protobuf encoded length is additive over fields and order-independent,
    // so the ret-cleared length is exactly the full length minus the `ret`
    // field's contribution. `ret` is repeated message field 5: each element
    // encodes as a 1-byte key (tag 5, wire type 2) + a length varint + the
    // element payload. Pinned byte-identical to the old clear-and-encode in
    // `serialized_bytes_matches_clear_ret`.
    fn varint_len(mut v: u64) -> usize {
        let mut n = 1usize;
        while v >= 0x80 {
            v >>= 7;
            n += 1;
        }
        n
    }
    let ret_contribution: usize = tx
        .ret
        .iter()
        .map(|r| {
            let len = r.encoded_len();
            1 + varint_len(len as u64) + len
        })
        .sum();
    tx.encoded_len() - ret_contribution
}

/// Effective net limit for `account`. Mirrors
/// `BandwidthProcessor.calculateGlobalNetLimit` (and its `V2` variant).
/// Sums the account's frozen-bandwidth balance, then scales by the chain's
/// `TOTAL_NET_LIMIT / TOTAL_NET_WEIGHT` ratio.
///
/// When `TOTAL_NET_WEIGHT == 0` (a fresh chain with no one frozen),
/// returns 0 — every account falls through to the free quota until
/// someone freezes. java-tron behaves the same way.
pub fn calculate_global_net_limit(account: &Account, dyn_props: &DynamicPropertiesStore) -> i64 {
    let froze_balance = all_frozen_balance_for_bandwidth(account);
    let total_limit = dyn_props.total_net_limit();
    let total_weight = dyn_props.total_net_weight();
    // Off on mainnet → java's legacy `double` scaling (see energy.rs).
    let harden = dyn_props.allow_harden_resource_calculation();

    if dyn_props.support_unfreeze_delay() {
        // V2 path: preserves fractional weight via end-truncation (java
        // `calculateGlobalNetLimitV2`). NOT the energy `calculate_global_limit_v2`,
        // which floors the weight — flooring drops net_limit by up to 1 byte and
        // wrongly rejects frozen-net txs java covers.
        return calculate_global_net_limit_v2(froze_balance, total_limit, total_weight, harden);
    }
    if froze_balance < TRX_PRECISION {
        return 0;
    }
    if total_weight == 0 {
        return 0;
    }
    if dyn_props.allow_new_reward() && total_weight <= 0 {
        return 0;
    }
    calculate_global_limit_v1(froze_balance, total_limit, total_weight, harden)
}

/// Sum of all sources of bandwidth weight for `account`. Mirrors
/// java-tron's `AccountCapsule.getAllFrozenBalanceForBandwidth`:
///
/// `frozen_v2[BANDWIDTH] + acquired_delegated_frozen_v2 + (legacy frozen.balance)`
///
/// The legacy `frozen` list (v1 freeze) is only populated for accounts
/// that froze before the v2 fork — its first entry's `balance` is the
/// frozen-for-bandwidth amount.
fn all_frozen_balance_for_bandwidth(account: &Account) -> i64 {
    let v2: i64 = account
        .frozen_v2
        .iter()
        .filter(|fb| fb.r#type == 0) // BANDWIDTH
        .map(|fb| fb.amount)
        .sum();
    let v1: i64 = account
        .frozen
        .iter()
        .map(|fb| fb.frozen_balance)
        .sum();
    v2.saturating_add(v1)
        .saturating_add(account.acquired_delegated_frozen_v2_balance_for_bandwidth)
        .saturating_add(account.acquired_delegated_frozen_balance_for_bandwidth)
}

/// Read the block-header timestamp for use as
/// `latest_operation_time`. Falls back to 0 on a fresh node.
pub fn head_block_timestamp(dyn_props: &DynamicPropertiesStore) -> i64 {
    dyn_props.latest_block_header_timestamp().unwrap_or(0)
}

/// java-tron's `BandwidthProcessor.useTransactionFee` payment effect:
/// pushes the fee to either the fee pool, the burn counter, or the
/// blackhole account, depending on which forks are active. Always bumps
/// `TOTAL_TRANSACTION_COST`.
fn pay_bandwidth_fee(dyn_props: &DynamicPropertiesStore, fee: i64) {
    dyn_props.add_total_transaction_cost(fee);
    if dyn_props.support_transaction_fee_pool() {
        dyn_props.add_transaction_fee_pool(fee);
    } else if dyn_props.support_blackhole_optimization() {
        dyn_props.burn_trx(fee);
    } else {
        // Legacy: credit the blackhole account. We don't yet have a
        // canonical blackhole-address constant exposed, so for now we
        // mirror the post-fork behavior (burn). The blackhole account
        // credit can be wired once a canonical
        // `tron_types::BLACKHOLE_ADDRESS` lands; the on-chain effect is
        // identical (the address receives the burned TRX rather than
        // it being "destroyed", but the supply tracking is the same).
        dyn_props.burn_trx(fee);
    }
}

/// Decode a 21-byte address slice into an [`Address`]. Returns `None`
/// for malformed lengths.
fn address_from_proto(bytes: &[u8]) -> Option<Address> {
    if bytes.len() != 21 {
        return None;
    }
    let mut buf = [0u8; 21];
    buf.copy_from_slice(bytes);
    Some(Address::from_raw(buf))
}

#[cfg(test)]
mod serialized_bytes_tests {
    use super::*;
    use tron_proto::transaction::{Raw, Result as TxResult};

    /// The pre-optimization implementation: clone the whole tx, clear
    /// `ret`, encode. `serialized_bytes` must match this byte-for-byte
    /// because the value feeds consensus bandwidth charging.
    fn clear_ret_len(tx: &Transaction) -> usize {
        let mut cleared = tx.clone();
        cleared.ret = Vec::new();
        cleared.encoded_len()
    }

    fn tx_with(ret: Vec<TxResult>, raw_data_len: usize, sigs: usize) -> Transaction {
        Transaction {
            raw_data: Some(Raw {
                ref_block_bytes: vec![0xab; 2],
                ref_block_num: 123456,
                ref_block_hash: vec![0xcd; 8],
                expiration: 1_700_000_000_000,
                data: vec![0x11; raw_data_len],
                timestamp: 1_699_999_999_000,
                ..Default::default()
            }),
            signature: (0..sigs).map(|i| vec![i as u8; 65]).collect(),
            ret,
            unparsed_field10: None,
        }
    }

    #[test]
    fn serialized_bytes_matches_clear_ret() {
        let cases = vec![
            // No ret at all.
            tx_with(vec![], 0, 1),
            // One default (empty) ret entry — exercises the 1-byte key +
            // zero-length payload path.
            tx_with(vec![TxResult::default()], 0, 1),
            // One populated ret entry.
            tx_with(
                vec![TxResult {
                    fee: 1_000_000,
                    contract_ret: 1,
                    ..Default::default()
                }],
                32,
                2,
            ),
            // Multiple ret entries (multi-result tx).
            tx_with(
                vec![
                    TxResult { fee: 1, ..Default::default() },
                    TxResult { fee: 2, contract_ret: 1, ..Default::default() },
                    TxResult::default(),
                ],
                8,
                1,
            ),
            // Large raw_data (the case the clone used to be expensive for)
            // with a large ret payload that crosses the single-byte varint
            // length boundary (>127 bytes).
            tx_with(
                vec![TxResult {
                    fee: i64::MAX,
                    asset_issue_id: "x".repeat(200),
                    ..Default::default()
                }],
                4096,
                3,
            ),
        ];
        for (i, tx) in cases.iter().enumerate() {
            assert_eq!(
                serialized_bytes(tx),
                clear_ret_len(tx),
                "serialized_bytes diverged from clear-ret on case {i}"
            );
        }
    }

    /// Ground-truth regression: real mainnet transactions whose Transaction
    /// wrapper carries a stray field-10 (unknown to java's schema, preserved
    /// by java's protobuf and BILLED for bandwidth). These bytes were read
    /// directly from a java-tron 4.8.1.1 LiteFullNode's block store at the
    /// stated heights; `bandwidth cost` values were captured from java's own
    /// `BandwidthProcessor` DEBUG log. Before modelling field 10, prost
    /// dropped it and `serialized_bytes` under-counted by the field's framed
    /// size (2..214 bytes), under-charging net bandwidth.
    #[test]
    fn serialized_bytes_includes_field10_like_java() {
        fn hx(s: &str) -> Vec<u8> {
            (0..s.len() / 2)
                .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
                .collect()
        }
        // tx 9bb2f5e8@83317795 — USDT transfer from 41fe4792. field10 = a
        // verbatim 211-byte copy of raw_data. java full=499, clearRet=495,
        // bandwidth cost (clearRet+64) = 559.
        let usdt = hx("0ad3010a02540f220838fa3a5a2874200140e8a3feaae9335aae01081f12a9010a31747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e54726967676572536d617274436f6e747261637412740a1541fe4792ec35f2c300dc3b4722b3b5fcd2d2b0156a121541a614f803b6fd780986a42c78ec9c7f77e6ded13c2244a9059cbb0000000000000000000000003d93998b456c0366ef4f6a4c973d987196c440f700000000000000000000000000000000000000000000000000000000123d308070fdeafaaae933900180a3c347124134515bd7068e7a71d305f2462c366f7b6edec21ba862b587f2a85ed202d414358247da3515a2972bc387fd58a7ae11ab7bd1d832c2c195f797d3edfc887b25b01c2a02180152d3010a02540f220838fa3a5a2874200140e8a3feaae9335aae01081f12a9010a31747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e54726967676572536d617274436f6e747261637412740a1541fe4792ec35f2c300dc3b4722b3b5fcd2d2b0156a121541a614f803b6fd780986a42c78ec9c7f77e6ded13c2244a9059cbb0000000000000000000000003d93998b456c0366ef4f6a4c973d987196c440f700000000000000000000000000000000000000000000000000000000123d308070fdeafaaae933900180a3c347");
        let tx = Transaction::decode(usdt.as_slice()).expect("decode usdt tx");
        // Re-encode must be byte-identical to the consensus tx (full size 499).
        assert_eq!(tx.encoded_len(), 499, "usdt full re-encode size");
        assert_eq!(tx.encode_to_vec(), usdt, "usdt re-encode not byte-identical");
        // clearRet serialized = 495; bandwidth cost (clearRet + 64) = 559.
        assert_eq!(serialized_bytes(&tx), 495, "usdt clearRet size");
        assert_eq!(
            serialized_bytes(&tx) as i64 + MAX_RESULT_SIZE_IN_TX,
            559,
            "usdt bandwidth bytesSize must equal java's"
        );
        assert_eq!(serialized_bytes(&tx), clear_ret_len(&tx));

        // The other observed shape is an EMPTY field-10 (the two 41fe4792
        // Transfers 28f55e77@83317791 / a8bc75de@83317803): java still counts
        // its framing as 2 bytes (`0x52 0x00`). Because field 10 is `optional`,
        // a present-but-empty value (`Some(vec![])`) re-emits those 2 bytes;
        // absent (`None`) is a no-op. Assert all three deterministically.
        let mut t = Transaction {
            raw_data: Some(tron_proto::transaction::Raw {
                ref_block_bytes: vec![0xab; 2],
                ref_block_num: 1,
                ref_block_hash: vec![0xcd; 8],
                expiration: 1,
                timestamp: 1,
                ..Default::default()
            }),
            signature: vec![vec![0u8; 65]],
            ret: vec![tron_proto::transaction::Result::default()],
            unparsed_field10: None,
        };
        let without = t.encoded_len();
        // Absent field-10 (well-formed tx) → no size change.
        assert_eq!(t.encoded_len(), without, "absent field10 must be a no-op");
        // Present-but-empty field-10 → 2 bytes (key + zero-length varint),
        // exactly java's accounting for the Transfers.
        t.unparsed_field10 = Some(Vec::new());
        assert_eq!(
            t.encoded_len(),
            without + 2,
            "empty field10 must add 2 bytes like java"
        );
        // Non-empty field-10 adds key(1) + len-varint(1) + payload.
        t.unparsed_field10 = Some(vec![0x42; 5]);
        assert_eq!(
            t.encoded_len(),
            without + 1 + 1 + 5,
            "field10 framing must match java's wire accounting"
        );

        // prost must DECODE a present-but-empty field 10 as Some(empty) (not
        // None) and re-emit its 2 bytes — otherwise the 41fe4792 Transfers,
        // which carry exactly `0x52 0x00`, would lose those 2 bytes on the
        // decode→serialized_bytes round trip and stay under-charged.
        let wire = [0x0au8, 0x00, 0x52, 0x00]; // empty raw_data + empty field10
        let decoded = Transaction::decode(wire.as_slice()).expect("decode empty field10");
        assert_eq!(
            decoded.unparsed_field10,
            Some(Vec::new()),
            "empty field10 must decode as Some(empty), not None"
        );
        assert_eq!(decoded.encode_to_vec(), wire, "must re-emit the empty field10");
        assert_eq!(serialized_bytes(&decoded), 4);
    }
}
