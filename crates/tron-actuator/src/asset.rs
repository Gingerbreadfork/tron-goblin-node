//! Asset actuators: TransferAsset, AssetIssue, UpdateAsset,
//! ParticipateAssetIssue, UnfreezeAsset.
//!
//! **Scope notes**:
//!
//! * For V1/V2 asset stores java-tron's behavior is gated by
//!   `ALLOW_SAME_TOKEN_NAME`. v1 uses asset names, v2 uses decimal-id
//!   strings (see [`tron_chainbase::AssetIssueV2Store`]). This port
//!   exposes both stores explicitly to callers — picking which one to
//!   query is the caller's responsibility per the proposal flag.
//! * `AssetIssueActuator.validate` has ~20 rules; we implement the
//!   critical structural ones (name/length, supply > 0, time window,
//!   account exists, balance >= fee, uniqueness via name lookup).
//!   Edge cases (precision range, frozen-supply duration ranges) are
//!   tracked in the doc comment for each rule that's deferred.

use tron_chainbase::{
    AccountStore, AssetIssueStore, AssetIssueV2Store, DynamicPropertiesStore,
};
use tron_crypto::address::Address;
use tron_proto::{
    AssetIssueContract, ParticipateAssetIssueContract, TransferAssetContract,
    UnfreezeAssetContract, UpdateAssetContract,
};

use crate::helpers::{check_add, check_sub, require_owner, require_to};
use crate::transfer::{ExecutionResult, CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT};
use crate::ActuatorError;

/// 32-byte max for asset names. java-tron's `TransactionUtil.validAssetName`.
/// Also the limit for an AssetIssue abbreviation: `AssetIssueActuator.validate`
/// checks the abbr with `validAssetName`, not `validTokenAbbrName` (the latter's
/// 5-byte limit is test-only in java and never applied to a real AssetIssue).
pub const MAX_ASSET_NAME_BYTES: usize = 32;
/// 200-byte max for asset description. java `MAX_ASSET_DESCRIPTION_LEN`.
const MAX_ASSET_DESCRIPTION_BYTES: usize = 200;
/// 256-byte max for asset URL. java `MAX_URL_LEN`.
const MAX_URL_BYTES: usize = 256;
/// Precision ceiling. java `ActuatorConstant.PRECISION_DECIMAL`.
const PRECISION_DECIMAL: i32 = 6;
/// Milliseconds per frozen-supply day. java
/// `Parameter.ChainConstant.FROZEN_PERIOD`.
const FROZEN_PERIOD: i64 = 86_400_000;

/// java `TransactionUtil.validReadableBytes`: non-empty, length <= max,
/// every byte in the printable ASCII range `0x21..=0x7E`. Used for the
/// asset name and abbreviation.
fn valid_readable_bytes(bytes: &[u8], max_len: usize) -> bool {
    if bytes.is_empty() || bytes.len() > max_len {
        return false;
    }
    bytes.iter().all(|&b| (0x21..=0x7E).contains(&b))
}

/// java `TransactionUtil.validBytes`: empty is accepted only when
/// `allow_empty`; otherwise length must be <= max (no byte-range check).
/// Backs `validUrl` (allow_empty = false) and `validAssetDescription`
/// (allow_empty = true).
fn valid_bytes(bytes: &[u8], max_len: usize, allow_empty: bool) -> bool {
    if bytes.is_empty() {
        return allow_empty;
    }
    bytes.len() <= max_len
}

/// java `TransactionUtil.validAssetName`.
fn valid_asset_name(name: &[u8]) -> bool {
    valid_readable_bytes(name, MAX_ASSET_NAME_BYTES)
}

/// java `TransactionUtil.validUrl` (`validBytes(url, MAX_URL_LEN, false)`):
/// an empty URL is INVALID, otherwise length must be <= 256.
fn valid_url(url: &[u8]) -> bool {
    valid_bytes(url, MAX_URL_BYTES, false)
}

/// java `TransactionUtil.validAssetDescription`
/// (`validBytes(desc, MAX_ASSET_DESCRIPTION_LEN, true)`): empty is valid,
/// otherwise length must be <= 200.
fn valid_asset_description(desc: &[u8]) -> bool {
    valid_bytes(desc, MAX_ASSET_DESCRIPTION_BYTES, true)
}

// =============================================================================
// TransferAssetActuator
// =============================================================================

pub fn validate_transfer_asset(
    accounts: &AccountStore,
    dynamic_properties: &DynamicPropertiesStore,
    contract: &TransferAssetContract,
) -> Result<(), ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let to = require_to(&contract.to_address)?;
    if owner == to {
        return Err(ActuatorError::SelfTransfer);
    }
    if contract.amount <= 0 {
        return Err(ActuatorError::NonPositiveAmount);
    }
    if contract.asset_name.is_empty() || contract.asset_name.len() > MAX_ASSET_NAME_BYTES {
        return Err(ActuatorError::AssetMissing);
    }
    let mut owner_account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    // Optimized accounts hold TRC10 balances in the account-asset store, not
    // inline — merge them in (java's importAllAsset) before reading.
    tron_chainbase::import_all_asset(&mut owner_account);

    let key = String::from_utf8_lossy(&contract.asset_name);
    let asset_balance = lookup_asset_balance(&owner_account, &key);
    if asset_balance < contract.amount {
        return Err(ActuatorError::InsufficientAssetBalance {
            has: asset_balance,
            needs: contract.amount,
        });
    }

    // java TransferAssetActuator.validate (TransferAssetActuator.java:168-176):
    // calcFee() is 0, but on a NEW recipient the create-new-account fee is
    // added and the owner must hold at least that much TRX. (When the
    // recipient already exists java instead does the addExact recipient-balance
    // overflow check, which is harmless for assets and elided here.)
    if accounts.get(&to)?.is_none() {
        let create_fee = dynamic_properties
            .get_long(CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT)
            .unwrap_or(0);
        if owner_account.balance < create_fee {
            return Err(ActuatorError::InsufficientBalance {
                balance: owner_account.balance,
                needed: create_fee,
            });
        }
    }
    Ok(())
}

pub fn execute_transfer_asset(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    v1: &AssetIssueStore,
    contract: &TransferAssetContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let to = require_to(&contract.to_address)?;

    let key = String::from_utf8_lossy(&contract.asset_name).into_owned();
    let mut owner_account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    // java TransferAssetActuator.execute: calcFee() == 0; a new recipient adds
    // the create-new-account fee. We accumulate it here and apply the
    // debit + burn after the asset moves (java debits, then burns, then sets
    // the result fee).
    let mut fee = 0i64;
    let mut created_recipient = false;
    let mut to_account = match accounts.get(&to)? {
        Some(a) => a,
        None => {
            // New recipient: java's TransferAssetActuator builds the
            // AccountCapsule with create_time + the default owner+active[id=2]
            // permission (`withDefaultPermission = getAllowMultiSign() == 1`),
            // then charges getCreateNewAccountFeeInSystemContract().
            let mut a = tron_proto::Account {
                address: to.as_bytes().to_vec(),
                r#type: tron_proto::AccountType::Normal as i32,
                create_time: dyn_props.latest_block_header_timestamp().unwrap_or(0),
                ..Default::default()
            };
            crate::permission::apply_default_account_permissions(&mut a, dyn_props);
            fee = dyn_props
                .get_long(CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT)
                .unwrap_or(0);
            created_recipient = true;
            a
        }
    };

    // Merge optimized accounts' TRC10 balances inline before mutating, so the
    // debit sees the real balance and the credit adds to (not overwrites) any
    // existing store balance for the receiver (java's importAllAsset). New
    // (non-optimized) accounts are a no-op. We then write the balances back
    // inline; the RPC read-merge (store ∪ inline, inline wins) keeps reads
    // correct. NOTE: this does NOT re-split back to the account-asset store on
    // commit the way java's SnapshotRoot does — functionally correct
    // (balances right, RPC consistent) but the on-disk layout drifts from
    // java's (optimized accounts accumulate inline asset_v2). Pending: a
    // store-write-back to restore byte-exact storage parity.
    tron_chainbase::import_all_asset(&mut owner_account);
    tron_chainbase::import_all_asset(&mut to_account);

    debit_asset(&mut owner_account, dyn_props, v1, &key, contract.amount)?;
    credit_asset(&mut to_account, dyn_props, v1, &key, contract.amount)?;

    // java: adjustBalance(owner, -fee) then burnTrx(fee) on the
    // supportBlackHoleOptimization path (mainnet); the legacy else-branch
    // credits the blackhole account, which we approximate as a burn to match
    // the other actuators. The fee debit lands on the same owner_account so it
    // is written by the single put below and reverts atomically with the tx on
    // failure. With the default-0 fee this is inert; it keeps the owner
    // balance, TransactionInfo.fee, and BURN_TRX_AMOUNT exact if a proposal
    // ever raises CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT.
    owner_account.balance = check_sub(owner_account.balance, fee)?;
    dyn_props.burn_trx(fee);

    accounts.put(&owner, &owner_account)?;
    accounts.put(&to, &to_account)?;
    Ok(ExecutionResult {
        fee,
        created_recipient,
        ..Default::default()
    })
}

// =============================================================================
// AssetIssueActuator
// =============================================================================

pub fn validate_asset_issue(
    accounts: &AccountStore,
    v1: &AssetIssueStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &AssetIssueContract,
) -> Result<(), ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let allow_same_token_name = dyn_props.allow_same_token_name().unwrap_or(0);

    // java: TransactionUtil.validAssetName (readable bytes, 1..=32).
    if !valid_asset_name(&contract.name) {
        return Err(ActuatorError::AssetMissing);
    }

    // java: when allowSameTokenName != 0, the (lower-cased) name can't be
    // "trx". On mainnet allowSameTokenName == 1, so this is enforced.
    if allow_same_token_name != 0
        && contract.name.eq_ignore_ascii_case(b"trx")
    {
        return Err(ActuatorError::AssetMissing);
    }

    // java: precision in [0, PRECISION_DECIMAL] when nonzero and
    // allowSameTokenName != 0 (precision==0 always allowed).
    if contract.precision != 0
        && allow_same_token_name != 0
        && (contract.precision < 0 || contract.precision > PRECISION_DECIMAL)
    {
        return Err(ActuatorError::AssetMissing);
    }

    // java AssetIssueActuator.validate checks the abbr (when non-empty) with
    // validAssetName — readable bytes up to the 32-byte asset-name limit — NOT
    // validTokenAbbrName (whose 5-byte limit is test-only in java and never
    // applied to a real AssetIssue). e.g. abbr "PGON.PRO" (8 bytes) is valid.
    if !contract.abbr.is_empty() && !valid_asset_name(&contract.abbr) {
        return Err(ActuatorError::AssetMissing);
    }

    // java: validUrl (non-empty, <= 256) and validAssetDescription
    // (empty allowed, <= 200).
    if !valid_url(&contract.url) {
        return Err(ActuatorError::InvalidUrl);
    }
    if !valid_asset_description(&contract.description) {
        return Err(ActuatorError::AssetMissing);
    }

    // java: start/end must be non-empty (== 0 rejected), end > start, and
    // start strictly after the head-block timestamp.
    if contract.start_time == 0 {
        return Err(ActuatorError::AssetIssueNotStarted);
    }
    if contract.end_time == 0 {
        return Err(ActuatorError::AssetIssueEnded);
    }
    if contract.end_time <= contract.start_time {
        return Err(ActuatorError::AssetIssueEnded);
    }
    let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);
    if contract.start_time <= now {
        return Err(ActuatorError::AssetIssueNotStarted);
    }

    // java: V1 name-uniqueness is checked ONLY when allowSameTokenName == 0.
    // On mainnet this is SKIPPED.
    if allow_same_token_name == 0 && v1.get(&contract.name)?.is_some() {
        return Err(ActuatorError::AssetNameTaken);
    }

    if contract.total_supply <= 0 {
        return Err(ActuatorError::NonPositiveAmount);
    }
    if contract.trx_num <= 0 {
        return Err(ActuatorError::NonPositiveAmount);
    }
    if contract.num <= 0 {
        return Err(ActuatorError::NonPositiveAmount);
    }

    // java: publicFreeAssetNetUsage must be 0.
    if contract.public_free_asset_net_usage != 0 {
        return Err(ActuatorError::NonPositiveAmount);
    }

    // java: frozen-supply list length <= MAX_FROZEN_SUPPLY_NUMBER (default 10).
    let max_frozen_supply_number = dyn_props
        .get_long(b"MAX_FROZEN_SUPPLY_NUMBER")
        .unwrap_or(10);
    if contract.frozen_supply.len() as i64 > max_frozen_supply_number {
        return Err(ActuatorError::NonPositiveAmount);
    }

    // java: free/public net limits in [0, oneDayNetLimit) (default 57.6e9).
    let one_day_net_limit = dyn_props
        .get_long(b"ONE_DAY_NET_LIMIT")
        .unwrap_or(57_600_000_000);
    if contract.free_asset_net_limit < 0
        || contract.free_asset_net_limit >= one_day_net_limit
    {
        return Err(ActuatorError::NonPositiveAmount);
    }
    if contract.public_free_asset_net_limit < 0
        || contract.public_free_asset_net_limit >= one_day_net_limit
    {
        return Err(ActuatorError::NonPositiveAmount);
    }

    // java: per-frozen-supply checks. remainSupply starts at totalSupply and
    // is decremented by each entry's frozenAmount in list order, so the
    // "exceeds total supply" check is cumulative (left-to-right).
    let min_frozen_supply_time = dyn_props
        .get_long(b"MIN_FROZEN_SUPPLY_TIME")
        .unwrap_or(1);
    let max_frozen_supply_time = dyn_props
        .get_long(b"MAX_FROZEN_SUPPLY_TIME")
        .unwrap_or(3652);
    let mut remain_supply = contract.total_supply;
    for entry in &contract.frozen_supply {
        if entry.frozen_amount <= 0 {
            return Err(ActuatorError::NonPositiveAmount);
        }
        if entry.frozen_amount > remain_supply {
            return Err(ActuatorError::NonPositiveAmount);
        }
        if !(entry.frozen_days >= min_frozen_supply_time
            && entry.frozen_days <= max_frozen_supply_time)
        {
            return Err(ActuatorError::NonPositiveAmount);
        }
        // java VERSION_4_8_1: StrictMathWrapper.addExact(startTime,
        // frozenDays * FROZEN_PERIOD) must not overflow. frozenDays is
        // already bounded by maxFrozenSupplyTime (default 3652) above, so
        // frozenDays*FROZEN_PERIOD <= ~3.15e14 and startTime is a ms
        // timestamp, making the sum unable to overflow i64 — the guard can
        // never trigger. We still compute it (wrapping multiply mirrors
        // java's plain long multiply; checked add mirrors addExact) so the
        // semantics stay byte-exact if either bound ever changes.
        let frozen_period = entry.frozen_days.wrapping_mul(FROZEN_PERIOD);
        if contract.start_time.checked_add(frozen_period).is_none() {
            return Err(ActuatorError::Overflow);
        }
        remain_supply -= entry.frozen_amount;
    }

    let owner_account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    // java: "An account can only issue one asset" — checked on
    // assetIssuedName only (not id).
    if !owner_account.asset_issued_name.is_empty() {
        return Err(ActuatorError::AccountAlreadyIssuedAsset);
    }
    let fee = dyn_props.get_long(b"ASSET_ISSUE_FEE").unwrap_or(1_024_000_000); // 1024 TRX default
    if owner_account.balance < fee {
        return Err(ActuatorError::InsufficientBalance {
            balance: owner_account.balance,
            needed: fee,
        });
    }
    Ok(())
}

pub fn execute_asset_issue(
    accounts: &AccountStore,
    v1: &AssetIssueStore,
    v2: &AssetIssueV2Store,
    dyn_props: &DynamicPropertiesStore,
    contract: &AssetIssueContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let mut owner_account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    let fee = dyn_props.get_long(b"ASSET_ISSUE_FEE").unwrap_or(1_024_000_000);
    owner_account.balance = check_sub(owner_account.balance, fee)?;
    // java AssetIssueActuator: after debiting the owner, burn the fee
    // (supportBlackHoleOptimization → burnTrx) so the chain-wide BURN_TRX_AMOUNT
    // accounting matches. Balances already match without this; only the burn
    // statistic would drift.
    dyn_props.burn_trx(fee);

    let next_token_id = dyn_props.get_long(b"TOKEN_ID_NUM").unwrap_or(1_000_000) + 1;
    dyn_props.put_long(b"TOKEN_ID_NUM", next_token_id);

    let mut to_store = contract.clone();
    to_store.id = next_token_id.to_string();
    to_store.owner_address = owner.as_bytes().to_vec();

    // java `AssetIssueActuator.execute` (AssetIssueActuator.java:76-86): the V1
    // store is written ONLY on the legacy `getAllowSameTokenName() == 0` path
    // (alongside V2, with V2 precision forced to 0); when the flag is on
    // (mainnet) it takes the else-branch and writes V2 ONLY. Gate the V1 write
    // accordingly so mainnet leaves no stray name-keyed V1 asset-issue row.
    let allow_same_token_name = dyn_props.allow_same_token_name().unwrap_or(0);
    if allow_same_token_name == 0 {
        // Legacy arm: V1 keeps the contract's precision; the parallel V2 row
        // is written with `precision` forced to 0
        // (`assetIssueCapsuleV2.setPrecision(0)` at AssetIssueActuator.java:78).
        // Mainnet (flag on) never enters here, so the V2 row keeps its
        // declared precision via the shared `to_store` below.
        v1.put(&contract.name, &to_store)?;
        let mut v2_store = to_store.clone();
        v2_store.precision = 0;
        v2.put(next_token_id, &v2_store)?;
    } else {
        v2.put(next_token_id, &to_store)?;
    }

    // java: build a Frozen entry per FrozenSupply
    // (frozenBalance = frozenAmount, expireTime = startTime +
    // frozenDays * FROZEN_PERIOD) and append them to the issuer account's
    // frozen_supply list; remainSupply (total minus the frozen amounts) is
    // the liquid balance credited to the issuer.
    let mut remain_supply = contract.total_supply;
    let start_time = contract.start_time;
    let mut frozen_entries: Vec<tron_proto::account::Frozen> =
        Vec::with_capacity(contract.frozen_supply.len());
    for entry in &contract.frozen_supply {
        // Mirrors java's startTime + frozenDays * FROZEN_PERIOD. validate
        // bounds frozenDays so this cannot overflow; wrapping_mul matches
        // java's plain long multiply and we saturate the add as a guard.
        let expire_time =
            start_time.saturating_add(entry.frozen_days.wrapping_mul(FROZEN_PERIOD));
        frozen_entries.push(tron_proto::account::Frozen {
            frozen_balance: entry.frozen_amount,
            expire_time,
        });
        remain_supply = check_sub(remain_supply, entry.frozen_amount)?;
    }

    // Credit the issuer with the (non-frozen) remaining supply. java
    // `AssetIssueActuator.execute` credits the V1 name-keyed `asset` map
    // (`addAsset`, flag=0 only) AND the V2 id-keyed `asset_v2` map
    // (`addAssetV2`, always). Without the V1 credit, flag=0 participation and
    // transfers — which read the name-keyed balance — see zero and reject.
    let liquid = remain_supply;
    let id_str = next_token_id.to_string();
    if allow_same_token_name == 0 {
        let name_key = String::from_utf8_lossy(&contract.name).into_owned();
        owner_account
            .asset
            .entry(name_key)
            .and_modify(|v| *v = v.saturating_add(liquid))
            .or_insert(liquid);
    }
    owner_account
        .asset_v2
        .entry(id_str.clone())
        .and_modify(|v| *v = v.saturating_add(liquid))
        .or_insert(liquid);
    owner_account.asset_issued_name = contract.name.clone();
    owner_account.asset_issued_id = id_str.into_bytes();
    owner_account.frozen_supply.extend(frozen_entries);
    accounts.put(&owner, &owner_account)?;

    // java `AssetIssueActuator.execute` sets `ret.assetIssueID =
    // Long.toString(tokenIdNum)` (AssetIssueActuator.java:123); the stored
    // TransactionInfo carries it as `asset_issue_id`.
    Ok(ExecutionResult {
        fee,
        ret: crate::TransactionRetExtras {
            asset_issue_id: next_token_id.to_string(),
            ..Default::default()
        },
        ..Default::default()
    })
}

// =============================================================================
// UpdateAssetActuator
// =============================================================================

pub fn validate_update_asset(
    accounts: &AccountStore,
    v1: &AssetIssueStore,
    v2: &AssetIssueV2Store,
    dyn_props: &DynamicPropertiesStore,
    contract: &UpdateAssetContract,
) -> Result<(), ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;

    let allow_same_token_name = dyn_props.allow_same_token_name().unwrap_or(0);
    // java: gate the "has issued an asset" + store-existence check on the
    // V1 name (allowSameTokenName == 0) or V2 id (== 1, mainnet).
    if allow_same_token_name == 0 {
        if account.asset_issued_name.is_empty() {
            return Err(ActuatorError::AccountAlreadyIssuedAsset); // "Account has not issued any asset"
        }
        if v1.get(&account.asset_issued_name)?.is_none() {
            return Err(ActuatorError::AssetMissing); // "Asset is not existed in AssetIssueStore"
        }
    } else {
        if account.asset_issued_id.is_empty() {
            return Err(ActuatorError::AccountAlreadyIssuedAsset); // "Account has not issued any asset"
        }
        let id_num: i64 = String::from_utf8_lossy(&account.asset_issued_id)
            .parse()
            .unwrap_or(0);
        if v2.get(id_num)?.is_none() {
            return Err(ActuatorError::AssetMissing); // "Asset is not existed in AssetIssueV2Store"
        }
    }

    // java: validUrl(newUrl) — non-empty, <= 256.
    if !valid_url(&contract.url) {
        return Err(ActuatorError::InvalidUrl);
    }
    // java: validAssetDescription(newDescription) — empty allowed, <= 200.
    if !valid_asset_description(&contract.description) {
        return Err(ActuatorError::AssetMissing);
    }

    // java: newLimit / newPublicLimit must be in [0, oneDayNetLimit).
    let one_day_net_limit = dyn_props
        .get_long(b"ONE_DAY_NET_LIMIT")
        .unwrap_or(57_600_000_000);
    if contract.new_limit < 0 || contract.new_limit >= one_day_net_limit {
        return Err(ActuatorError::NonPositiveAmount);
    }
    if contract.new_public_limit < 0 || contract.new_public_limit >= one_day_net_limit {
        return Err(ActuatorError::NonPositiveAmount);
    }
    Ok(())
}

pub fn execute_update_asset(
    accounts: &AccountStore,
    v1: &AssetIssueStore,
    v2: &AssetIssueV2Store,
    contract: &UpdateAssetContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;

    let id_str = String::from_utf8_lossy(&account.asset_issued_id).into_owned();
    let id_num: i64 = id_str.parse().unwrap_or(0);
    if let Some(mut asset) = v2.get(id_num)? {
        asset.url = contract.url.clone();
        asset.description = contract.description.clone();
        asset.free_asset_net_limit = contract.new_limit;
        asset.public_free_asset_net_limit = contract.new_public_limit;
        v2.put(id_num, &asset)?;
        // Mirror to V1 if a v1 entry exists (pre-fork compat).
        if v1.get(&asset.name)?.is_some() {
            v1.put(&asset.name, &asset)?;
        }
    }
    Ok(ExecutionResult::default())
}

// =============================================================================
// ParticipateAssetIssueActuator
// =============================================================================

pub fn validate_participate_asset_issue(
    accounts: &AccountStore,
    v1: &AssetIssueStore,
    v2: &AssetIssueV2Store,
    dyn_props: &DynamicPropertiesStore,
    contract: &ParticipateAssetIssueContract,
) -> Result<(), ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let to = require_to(&contract.to_address)?;
    // java checks `amount <= 0` BEFORE the self-participate check.
    if contract.amount <= 0 {
        return Err(ActuatorError::NonPositiveAmount);
    }
    if owner == to {
        return Err(ActuatorError::SelfTransfer);
    }
    let owner_account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    // java: balance < addExact(amount, fee); calcFee() == 0 for participate.
    let fee = 0i64;
    let needed = check_add(contract.amount, fee)?;
    if owner_account.balance < needed {
        return Err(ActuatorError::InsufficientBalance {
            balance: owner_account.balance,
            needed,
        });
    }

    // java: Commons.getAssetIssueStoreFinal — V2 store when
    // allowSameTokenName == 1 (mainnet), keyed by the numeric token id;
    // V1 store (name-keyed) otherwise.
    let asset = lookup_asset_final(v1, v2, dyn_props, &contract.asset_name)?
        .ok_or(ActuatorError::AssetMissing)?;

    if asset.owner_address != to.as_bytes() {
        return Err(ActuatorError::InvalidToAddress);
    }
    let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);
    // java: now >= endTime || now < startTime  -> "No longer valid period!".
    if now >= asset.end_time {
        return Err(ActuatorError::AssetIssueEnded);
    }
    if now < asset.start_time {
        return Err(ActuatorError::AssetIssueNotStarted);
    }

    // java: exchangeAmount = floorDiv(multiplyExact(amount, num), trxNum).
    // i128 keeps the multiply exact; multiplyExact would throw on i64
    // overflow, which we surface as Overflow. floorDiv matches Java
    // Math.floorDiv (both operands positive here, so it equals /).
    let product = (contract.amount as i128) * (asset.num as i128);
    if product > i64::MAX as i128 || product < i64::MIN as i128 {
        return Err(ActuatorError::Overflow);
    }
    let exchange_amount = product.div_euclid(asset.trx_num as i128);
    if exchange_amount <= 0 {
        return Err(ActuatorError::NonPositiveAmount); // "Can not process the exchange!"
    }
    if exchange_amount > i64::MAX as i128 {
        return Err(ActuatorError::Overflow);
    }
    let exchange_amount = exchange_amount as i64;

    // java: toAccount must exist and hold >= exchangeAmount of the asset
    // (assetBalanceEnoughV2: reads asset_v2 on mainnet, asset on legacy).
    let mut to_account = accounts
        .get(&to)?
        .ok_or(ActuatorError::TargetAccountMissing)?;
    tron_chainbase::import_all_asset(&mut to_account);
    let key = String::from_utf8_lossy(&contract.asset_name);
    let issuer_balance = lookup_asset_balance_final(&to_account, dyn_props, &key);
    if !(exchange_amount > 0 && issuer_balance >= exchange_amount) {
        return Err(ActuatorError::InsufficientAssetBalance {
            has: issuer_balance,
            needs: exchange_amount,
        });
    }
    Ok(())
}

pub fn execute_participate_asset_issue(
    accounts: &AccountStore,
    v1: &AssetIssueStore,
    v2: &AssetIssueV2Store,
    dyn_props: &DynamicPropertiesStore,
    contract: &ParticipateAssetIssueContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let to = require_to(&contract.to_address)?;

    // java: Commons.getAssetIssueStoreFinal — V2 (id-keyed) on mainnet.
    let asset = lookup_asset_final(v1, v2, dyn_props, &contract.asset_name)?
        .ok_or(ActuatorError::AssetMissing)?;
    // java: exchangeAmount = floorDiv(multiplyExact(cost, num), trxNum).
    let product = (contract.amount as i128) * (asset.num as i128);
    if product > i64::MAX as i128 || product < i64::MIN as i128 {
        return Err(ActuatorError::Overflow);
    }
    let exchange_amount = product.div_euclid(asset.trx_num as i128);
    if exchange_amount <= 0 || exchange_amount > i64::MAX as i128 {
        return Err(ActuatorError::Overflow);
    }
    let exchange_amount = exchange_amount as i64;

    let mut owner_account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    let mut to_account = accounts
        .get(&to)?
        .ok_or(ActuatorError::TargetAccountMissing)?;

    // TRX flow: owner -> to.
    owner_account.balance = check_sub(owner_account.balance, contract.amount)?;
    to_account.balance = check_add(to_account.balance, contract.amount)?;

    // Asset flow: to -> owner. Merge optimized accounts' TRC10 balances inline
    // first (java's importAllAsset) so the issuer's debit sees its real
    // balance and the participant's credit adds to any existing one.
    tron_chainbase::import_all_asset(&mut to_account);
    tron_chainbase::import_all_asset(&mut owner_account);
    let key = String::from_utf8_lossy(&contract.asset_name).into_owned();
    debit_asset(&mut to_account, dyn_props, v1, &key, exchange_amount)?;
    credit_asset(&mut owner_account, dyn_props, v1, &key, exchange_amount)?;

    accounts.put(&owner, &owner_account)?;
    accounts.put(&to, &to_account)?;
    Ok(ExecutionResult::default())
}

// =============================================================================
// UnfreezeAssetActuator (legacy)
// =============================================================================

pub fn validate_unfreeze_asset(
    accounts: &AccountStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &UnfreezeAssetContract,
) -> Result<(), ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    if account.frozen_supply.is_empty() {
        return Err(ActuatorError::NoUnfreezableAsset);
    }
    let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);
    if !account.frozen_supply.iter().any(|f| f.expire_time <= now) {
        return Err(ActuatorError::NoUnfreezableAsset);
    }
    Ok(())
}

pub fn execute_unfreeze_asset(
    accounts: &AccountStore,
    v1: &AssetIssueStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &UnfreezeAssetContract,
) -> Result<ExecutionResult, ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    let mut account = accounts
        .get(&owner)?
        .ok_or(ActuatorError::OwnerAccountMissing)?;
    let now = dyn_props.latest_block_header_timestamp().unwrap_or(0);

    let mut unlocked = 0i64;
    account.frozen_supply.retain(|f| {
        if f.expire_time <= now {
            unlocked = unlocked.saturating_add(f.frozen_balance);
            false
        } else {
            true
        }
    });
    // Merge optimized balances inline so the credit adds to (not overwrites)
    // any existing store balance for this asset (java's importAllAsset).
    tron_chainbase::import_all_asset(&mut account);

    // java UnfreezeAssetActuator.execute → `addAssetAmountV2(key, unfreeze)`:
    // the key and the maps written are gated on `allowSameTokenName`.
    if dyn_props.allow_same_token_name().unwrap_or(0) == 0 {
        // Legacy: key is the V1 issued *name*. java's addAssetAmountV2 looks up
        // the V1 asset capsule by name to find its token id, then writes the
        // SAME total to both the V1 `asset` map (keyed by name) and the V2
        // `asset_v2` map (keyed by id).
        let name_key = String::from_utf8_lossy(&account.asset_issued_name).into_owned();
        let token_id = v1
            .get(&account.asset_issued_name)?
            .map(|c| c.id)
            .unwrap_or_default();
        let current = account.asset.get(&name_key).copied().unwrap_or(0);
        let updated = check_add(current, unlocked)?;
        account.asset.insert(name_key, updated);
        account.asset_v2.insert(token_id, updated);
    } else {
        // Mainnet: key is the V2 issued *id*; only the V2 map is written.
        let id_key = String::from_utf8_lossy(&account.asset_issued_id).into_owned();
        credit_asset(&mut account, dyn_props, v1, &id_key, unlocked)?;
    }
    accounts.put(&owner, &account)?;
    Ok(ExecutionResult::default())
}

// =============================================================================
// Helpers
// =============================================================================

fn lookup_asset_balance(account: &tron_proto::Account, key: &str) -> i64 {
    account
        .asset_v2
        .get(key)
        .copied()
        .or_else(|| account.asset.get(key).copied())
        .unwrap_or(0)
}

/// java `Commons.getAssetIssueStoreFinal(...).get(key)`: read the V2 store
/// (keyed by numeric token id) when `allowSameTokenName == 1` (mainnet),
/// the V1 store (keyed by name) otherwise.
///
/// java does a raw byte-key lookup; on mainnet the contract's `asset_name`
/// is the decimal token-id string, so parsing it to an i64 and using the
/// V2 store reproduces the identical key bytes.
fn lookup_asset_final(
    v1: &AssetIssueStore,
    v2: &AssetIssueV2Store,
    dyn_props: &DynamicPropertiesStore,
    key: &[u8],
) -> Result<Option<tron_proto::AssetIssueContract>, ActuatorError> {
    if dyn_props.allow_same_token_name().unwrap_or(0) == 0 {
        Ok(v1.get(key)?)
    } else {
        let Ok(id_str) = std::str::from_utf8(key) else {
            return Ok(None);
        };
        let Ok(id) = id_str.parse::<i64>() else {
            return Ok(None);
        };
        Ok(v2.get(id)?)
    }
}

/// java `AccountCapsule.assetBalanceEnoughV2` map selection: read the
/// asset_v2 map (token-id keyed) when `allowSameTokenName == 1`, the asset
/// map (name keyed) otherwise. Returns 0 when the asset is absent. The
/// caller must have imported optimized balances (java's `importAsset`).
fn lookup_asset_balance_final(
    account: &tron_proto::Account,
    dyn_props: &DynamicPropertiesStore,
    key: &str,
) -> i64 {
    if dyn_props.allow_same_token_name().unwrap_or(0) == 0 {
        account.asset.get(key).copied().unwrap_or(0)
    } else {
        account.asset_v2.get(key).copied().unwrap_or(0)
    }
}

fn debit_asset(
    account: &mut tron_proto::Account,
    dyn_props: &DynamicPropertiesStore,
    v1: &AssetIssueStore,
    key: &str,
    amount: i64,
) -> Result<(), ActuatorError> {
    if amount < 0 {
        return Err(ActuatorError::NonPositiveAmount);
    }
    // java `reduceAssetAmountV2`: at `ALLOW_SAME_TOKEN_NAME == 0` the balance
    // lives in the V1 `asset` map (keyed by token name); once the proposal is
    // active it lives in the V2 `asset_v2` map (keyed by token id). The caller
    // passes the name at flag=0 and the id at flag=1 to match.
    let flag0 = dyn_props.allow_same_token_name().unwrap_or(0) == 0;
    let map = if flag0 { &mut account.asset } else { &mut account.asset_v2 };
    let updated = match map.get_mut(key) {
        Some(slot) if *slot >= amount => {
            *slot = check_sub(*slot, amount)?;
            *slot
        }
        Some(slot) => {
            return Err(ActuatorError::InsufficientAssetBalance {
                has: *slot,
                needs: amount,
            })
        }
        None => {
            return Err(ActuatorError::InsufficientAssetBalance {
                has: 0,
                needs: amount,
            })
        }
    };
    // flag=0 java parity: `reduceAssetAmountV2` writes the same V1-derived total
    // to BOTH the V1 `asset` (name) map and the V2 `asset_v2` (id) map, so the V2
    // view stays correct for the eventual `ALLOW_SAME_TOKEN_NAME` switch. `key`
    // is the token name here; resolve it to the token id to mirror the write.
    if flag0 {
        if let Some(id) = token_id_for_name(v1, key)? {
            account.asset_v2.insert(id, updated);
        }
    }
    Ok(())
}

fn credit_asset(
    account: &mut tron_proto::Account,
    dyn_props: &DynamicPropertiesStore,
    v1: &AssetIssueStore,
    key: &str,
    amount: i64,
) -> Result<(), ActuatorError> {
    // Mirror [`debit_asset`]: java `addAssetAmountV2` writes the V1 `asset`
    // (name-keyed) map before the proposal and the V2 `asset_v2` (id-keyed) map
    // after it.
    let flag0 = dyn_props.allow_same_token_name().unwrap_or(0) == 0;
    let map = if flag0 { &mut account.asset } else { &mut account.asset_v2 };
    let slot = map.entry(key.to_string()).or_insert(0);
    *slot = check_add(*slot, amount)?;
    let updated = *slot;
    // flag=0 java parity: `addAssetAmountV2` writes the same V1-derived total to
    // BOTH the V1 `asset` (name) map and the V2 `asset_v2` (id) map. `key` is the
    // token name here; resolve it to the token id to mirror the write.
    if flag0 {
        if let Some(id) = token_id_for_name(v1, key)? {
            account.asset_v2.insert(id, updated);
        }
    }
    Ok(())
}

/// Resolve a TRC-10 token *name* to its numeric token-id string via the V1
/// `AssetIssueStore`, for the flag=0 `asset_v2` dual-write. At
/// `ALLOW_SAME_TOKEN_NAME == 0` names are unique, so the lookup is unambiguous.
/// Returns `None` when the asset is absent or carries no id (defensive: the
/// caller's validation has already confirmed the asset exists for real txs).
fn token_id_for_name(
    v1: &AssetIssueStore,
    name: &str,
) -> Result<Option<String>, ActuatorError> {
    Ok(v1
        .get(name.as_bytes())?
        .map(|c| c.id)
        .filter(|id| !id.is_empty()))
}

#[allow(dead_code)]
fn _unused(_a: &Address) {}
