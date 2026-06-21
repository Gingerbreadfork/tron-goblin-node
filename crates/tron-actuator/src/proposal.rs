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

/// 3 days in **milliseconds** — the default proposal voting window
/// (`Constant.DEFAULT_PROPOSAL_EXPIRE_TIME`). The live value is read through
/// [`DynamicPropertiesStore::proposal_expire_time`], which honors proposal #92.
pub const PROPOSAL_EXPIRE_TIME_MS: i64 = 3 * 24 * 60 * 60 * 1000;

// =============================================================================
// ProposalCreateActuator
// =============================================================================

pub fn validate_proposal_create(
    accounts: &AccountStore,
    witnesses: &WitnessStore,
    dyn_props: &DynamicPropertiesStore,
    contract: &ProposalCreateContract,
) -> Result<(), ActuatorError> {
    let owner = require_owner(&contract.owner_address)?;
    if accounts.get(&owner)?.is_none() {
        return Err(ActuatorError::OwnerAccountMissing);
    }
    if !witnesses.contains(&owner)? {
        return Err(ActuatorError::WitnessMissing);
    }
    if contract.parameters.is_empty() {
        return Err(ActuatorError::EmptyProposalParameters);
    }
    // java ProposalCreateActuator.validate iterates the parameters map and runs
    // `ProposalUtil.validator` on every (code, value) entry. The map is keyed by
    // chain-parameter code; BTreeMap iteration is ascending-by-key, matching the
    // deterministic order java relies on (any out-of-range entry rejects the
    // whole tx, so order only affects which message fires first).
    for (&code, &value) in contract.parameters.iter() {
        validate_proposal_value(dyn_props, code, value)?;
    }
    Ok(())
}

/// Port of java `ProposalUtil.validator(dynamicPropertiesStore, forkController,
/// code, value)`.
///
/// **Fork gating**: java guards most parameter codes behind
/// `forkController.pass(VERSION_X)`, which tracks SR block-version adoption — a
/// mechanism this node does not model (it gates behavior off the resulting
/// dynamic-property flags instead). Every fork relevant here (3.2.2 through
/// 4.8.1) is long-active across the entire replay/snapshot window, so the
/// version gate is effectively always-true and is treated as passed. The
/// *value-range* and *dependency* checks below are the reachable, parity-
/// relevant logic and are ported verbatim. The two `forkController.pass(...) ==
/// false`-only error paths (e.g. proposing a 3.2.2-era parameter before that
/// fork, or the deprecated `TOTAL_ENERGY_LIMIT` after 3.2.2) are unreachable on
/// the post-fork window and are the only behavior not reproduced exactly.
fn validate_proposal_value(
    dyn_props: &DynamicPropertiesStore,
    code: i64,
    value: i64,
) -> Result<(), ActuatorError> {
    // java `ProposalUtil` numeric bounds.
    const LONG_VALUE: i64 = 100_000_000_000_000_000;
    const MAX_SUPPLY: i64 = 100_000_000_000;
    const DYNAMIC_ENERGY_INCREASE_FACTOR_RANGE: i64 = 10_000;
    const DYNAMIC_ENERGY_MAX_FACTOR_RANGE: i64 = 100_000;
    const CREATE_ACCOUNT_TRANSACTION_MIN_BYTE_SIZE: i64 = 500;
    const CREATE_ACCOUNT_TRANSACTION_MAX_BYTE_SIZE: i64 = 10_000;
    const ONE_YEAR_BLOCK_NUMBERS: i64 = 10_512_000;
    // java `Constant.MIN/MAX_PROPOSAL_EXPIRE_TIME`.
    const MIN_PROPOSAL_EXPIRE_TIME: i64 = 0;
    const MAX_PROPOSAL_EXPIRE_TIME: i64 = 31_536_003_000;
    // `getMaxDelegateLockPeriod()` default = `DELEGATE_PERIOD / BLOCK_PRODUCED`
    // = 3*86_400_000 / 3000.
    const DEFAULT_MAX_DELEGATE_LOCK_PERIOD: i64 = (3 * 86_400_000) / 3000;

    let out_of_long_range = || ActuatorError::ProposalParameterOutOfRange;
    let only_one = |_name: &str| ActuatorError::ProposalParameterOutOfRange;
    let bad = || ActuatorError::ProposalParameterOutOfRange;
    // java reads each dependency flag through a typed getter; the underlying
    // store key is identical, so a raw `get_long` over the same key bytes
    // reproduces it. Defaults of 0 match java's pre-activation state.
    let flag = |key: &[u8]| dyn_props.get_long(key).unwrap_or(0);

    let proposal_type = match ProposalType::from_code(code) {
        Some(t) => t,
        // java `ProposalType.getEnum` throws "Does not support code" for any
        // code not in the enum, rejecting the proposal.
        None => return Err(ActuatorError::ProposalParameterOutOfRange),
    };

    use ProposalType::*;
    match proposal_type {
        MaintenanceTimeInterval => {
            if value < 3 * 27 * 1000 || value > 24 * 3600 * 1000 {
                return Err(bad());
            }
        }
        AccountUpgradeCost
        | CreateAccountFee
        | TransactionFee
        | AssetIssueFee
        | WitnessPayPerBlock
        | WitnessStandbyAllowance
        | CreateNewAccountFeeInSystemContract
        | CreateNewAccountBandwidthRate => {
            if value < 0 || value > LONG_VALUE {
                return Err(out_of_long_range());
            }
        }
        AllowCreationOfContracts => {
            if value != 1 {
                return Err(only_one("ALLOW_CREATION_OF_CONTRACTS"));
            }
        }
        RemoveThePowerOfTheGr => {
            // java: REMOVE_THE_POWER_OF_THE_GR can only ever execute once
            // (sentinel -1 once spent).
            if flag(b"REMOVE_THE_POWER_OF_THE_GR") == -1 {
                return Err(bad());
            }
            if value != 1 {
                return Err(only_one("REMOVE_THE_POWER_OF_THE_GR"));
            }
        }
        EnergyFee | ExchangeCreateFee => {
            // java: no value check (break immediately).
        }
        MaxCpuTimeOfOneTx => {
            if flag(b"ALLOW_HIGHER_LIMIT_FOR_MAX_CPU_TIME_OF_ONE_TX") == 1 {
                if value < 10 || value > 400 {
                    return Err(bad());
                }
            } else if value < 10 || value > 100 {
                return Err(bad());
            }
        }
        AllowUpdateAccountName => {
            if value != 1 {
                return Err(only_one("ALLOW_UPDATE_ACCOUNT_NAME"));
            }
        }
        AllowSameTokenName => {
            if value != 1 {
                return Err(only_one("ALLOW_SAME_TOKEN_NAME"));
            }
        }
        AllowDelegateResource => {
            if value != 1 {
                return Err(only_one("ALLOW_DELEGATE_RESOURCE"));
            }
        }
        TotalEnergyLimit => {
            // Deprecated after VERSION_3_2_2; on the post-fork window this code
            // is no longer proposable. The fork-controller gate that produces
            // that rejection is not modeled, but the value-range check is.
            if value < 0 || value > LONG_VALUE {
                return Err(out_of_long_range());
            }
        }
        AllowTvmTransferTrc10 => {
            if value != 1 {
                return Err(only_one("ALLOW_TVM_TRANSFER_TRC10"));
            }
            if flag(b" ALLOW_SAME_TOKEN_NAME") == 0 {
                return Err(bad());
            }
        }
        TotalCurrentEnergyLimit => {
            if value < 0 || value > LONG_VALUE {
                return Err(out_of_long_range());
            }
        }
        AllowMultiSign => {
            if value != 1 {
                return Err(only_one("ALLOW_MULTI_SIGN"));
            }
        }
        AllowAdaptiveEnergy => {
            if value != 1 {
                return Err(only_one("ALLOW_ADAPTIVE_ENERGY"));
            }
        }
        UpdateAccountPermissionFee | MultiSignFee => {
            if value < 0 || value > MAX_SUPPLY {
                return Err(bad());
            }
        }
        AllowProtoFilterNum | AllowAccountStateRoot => {
            if value != 1 && value != 0 {
                return Err(bad());
            }
        }
        AllowTvmConstantinople => {
            if value != 1 {
                return Err(only_one("ALLOW_TVM_CONSTANTINOPLE"));
            }
            if flag(b"ALLOW_TVM_TRANSFER_TRC10") == 0 {
                return Err(bad());
            }
        }
        AllowTvmSolidity059 => {
            if value != 1 {
                return Err(only_one("ALLOW_TVM_SOLIDITY_059"));
            }
            if flag(b"ALLOW_CREATION_OF_CONTRACTS") == 0 {
                return Err(bad());
            }
        }
        AdaptiveResourceLimitTargetRatio => {
            if value < 1 || value > 1_000 {
                return Err(bad());
            }
        }
        AdaptiveResourceLimitMultiplier => {
            if value < 1 || value > 10_000 {
                return Err(bad());
            }
        }
        AllowChangeDelegation => {
            if value != 1 && value != 0 {
                return Err(bad());
            }
        }
        Witness127PayPerBlock => {
            if value < 0 || value > LONG_VALUE {
                return Err(out_of_long_range());
            }
        }
        ForbidTransferToContract => {
            if value != 1 {
                return Err(only_one("FORBID_TRANSFER_TO_CONTRACT"));
            }
            if flag(b"ALLOW_CREATION_OF_CONTRACTS") == 0 {
                return Err(bad());
            }
        }
        AllowShieldedTrc20Transaction => {
            if value != 1 && value != 0 {
                return Err(bad());
            }
        }
        AllowPbft => {
            if value != 1 {
                return Err(only_one("ALLOW_PBFT"));
            }
        }
        AllowTvmIstanbul => {
            if value != 1 {
                return Err(only_one("ALLOW_TVM_ISTANBUL"));
            }
        }
        AllowMarketTransaction => {
            // java rejects this code once VERSION_4_8_1 has passed (the param is
            // removed in 4.8.1). On the post-4.8.1 window it is no longer
            // proposable; reproduce the rejection (the fork is active).
            return Err(bad());
        }
        MarketSellFee | MarketCancelFee => {
            // java guards on `supportAllowMarketTransaction()`; on mainnet that
            // flag is on once 4.1 passed.
            if value < 0 || value > 10_000_000_000 {
                return Err(bad());
            }
        }
        MaxFeeLimit => {
            if value < 0 {
                return Err(bad());
            } else if value > 10_000_000_000 {
                if flag(b"ALLOW_TVM_LONDON") == 0 {
                    return Err(bad());
                }
                if value > LONG_VALUE {
                    return Err(out_of_long_range());
                }
            }
        }
        AllowTransactionFeePool => {
            if value != 1 && value != 0 {
                return Err(bad());
            }
        }
        AllowBlackholeOptimization => {
            if value != 1 && value != 0 {
                return Err(bad());
            }
        }
        AllowNewResourceModel => {
            if value != 1 {
                return Err(only_one("ALLOW_NEW_RESOURCE_MODEL"));
            }
        }
        AllowTvmFreeze => {
            if value != 1 {
                return Err(only_one("ALLOW_TVM_FREEZE"));
            }
            if flag(b"ALLOW_DELEGATE_RESOURCE") == 0
                || flag(b"ALLOW_MULTI_SIGN") == 0
                || flag(b"ALLOW_TVM_CONSTANTINOPLE") == 0
                || flag(b"ALLOW_TVM_SOLIDITY_059") == 0
            {
                return Err(bad());
            }
        }
        AllowTvmVote => {
            if value != 1 {
                return Err(only_one("ALLOW_TVM_VOTE"));
            }
            if flag(b"CHANGE_DELEGATION") == 0 {
                return Err(bad());
            }
        }
        FreeNetLimit => {
            if value < 0 || value > 100_000 {
                return Err(bad());
            }
        }
        TotalNetLimit => {
            if value < 0 || value > 1_000_000_000_000 {
                return Err(bad());
            }
        }
        AllowAccountAssetOptimization => {
            if value != 1 {
                return Err(only_one("ALLOW_ACCOUNT_ASSET_OPTIMIZATION"));
            }
        }
        AllowTvmLondon => {
            if value != 1 {
                return Err(only_one("ALLOW_TVM_LONDON"));
            }
        }
        AllowTvmCompatibleEvm => {
            if value != 1 {
                return Err(only_one("ALLOW_TVM_COMPATIBLE_EVM"));
            }
        }
        AllowHigherLimitForMaxCpuTimeOfOneTx => {
            if value != 1 {
                return Err(only_one("ALLOW_HIGHER_LIMIT_FOR_MAX_CPU_TIME_OF_ONE_TX"));
            }
        }
        AllowAssetOptimization => {
            if value != 1 {
                return Err(only_one("ALLOW_ASSET_OPTIMIZATION"));
            }
        }
        AllowNewReward => {
            // java: rejects if new reward already valid.
            if flag(b"ALLOW_NEW_REWARD") == 1 {
                return Err(bad());
            }
            if value != 1 {
                return Err(only_one("ALLOW_NEW_REWARD"));
            }
        }
        MemoFee => {
            if value < 0 || value > 1_000_000_000 {
                return Err(bad());
            }
        }
        AllowDelegateOptimization => {
            if value != 1 {
                return Err(only_one("ALLOW_DELEGATE_OPTIMIZATION"));
            }
        }
        UnfreezeDelayDays => {
            if value < 1 || value > 365 {
                return Err(bad());
            }
        }
        AllowOptimizedReturnValueOfChainId => {
            if value != 1 {
                return Err(only_one("ALLOW_OPTIMIZED_RETURN_VALUE_OF_CHAIN_ID"));
            }
        }
        AllowDynamicEnergy => {
            if value < 0 || value > 1 {
                return Err(bad());
            }
            if value == 1 && flag(b"CHANGE_DELEGATION") == 0 {
                return Err(bad());
            }
        }
        DynamicEnergyThreshold => {
            if value < 0 || value > LONG_VALUE {
                return Err(out_of_long_range());
            }
        }
        DynamicEnergyIncreaseFactor => {
            if value < 0 || value > DYNAMIC_ENERGY_INCREASE_FACTOR_RANGE {
                return Err(bad());
            }
        }
        DynamicEnergyMaxFactor => {
            if value < 0 || value > DYNAMIC_ENERGY_MAX_FACTOR_RANGE {
                return Err(bad());
            }
        }
        AllowTvmShanghai => {
            if value != 1 {
                return Err(only_one("ALLOW_TVM_SHANGHAI"));
            }
        }
        AllowCancelAllUnfreezeV2 => {
            if value != 1 {
                return Err(only_one("ALLOW_CANCEL_ALL_UNFREEZE_V2"));
            }
            if dyn_props.unfreeze_delay_days() == 0 {
                return Err(bad());
            }
        }
        MaxDelegateLockPeriod => {
            let current = dyn_props
                .get_long(b"MAX_DELEGATE_LOCK_PERIOD")
                .unwrap_or(DEFAULT_MAX_DELEGATE_LOCK_PERIOD);
            if value <= current || value > ONE_YEAR_BLOCK_NUMBERS {
                return Err(bad());
            }
            if dyn_props.unfreeze_delay_days() == 0 {
                return Err(bad());
            }
        }
        AllowOldRewardOpt => {
            if flag(b"ALLOW_OLD_REWARD_OPT") == 1 {
                return Err(bad());
            }
            if value != 1 {
                return Err(only_one("ALLOW_OLD_REWARD_OPT"));
            }
            // java `useNewRewardAlgorithm()` = NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE
            // != Long.MAX_VALUE. When the key is absent (never activated) java's
            // getter throws — but on any reachable post-VERSION_4_7_4 state the
            // marker is present, so an unset key here means "new algorithm not
            // yet effective" → reject.
            let new_reward_cycle = dyn_props
                .get_long(b"NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE")
                .unwrap_or(i64::MAX);
            if new_reward_cycle == i64::MAX {
                return Err(bad());
            }
        }
        AllowEnergyAdjustment => {
            if flag(b"ALLOW_ENERGY_ADJUSTMENT") == 1 {
                return Err(bad());
            }
            if value != 1 {
                return Err(only_one("ALLOW_ENERGY_ADJUSTMENT"));
            }
        }
        MaxCreateAccountTxSize => {
            if value < CREATE_ACCOUNT_TRANSACTION_MIN_BYTE_SIZE
                || value > CREATE_ACCOUNT_TRANSACTION_MAX_BYTE_SIZE
            {
                return Err(bad());
            }
        }
        AllowStrictMath => {
            if flag(b"ALLOW_STRICT_MATH") == 1 {
                return Err(bad());
            }
            if value != 1 {
                return Err(only_one("ALLOW_STRICT_MATH"));
            }
        }
        ConsensusLogicOptimization => {
            if flag(b"CONSENSUS_LOGIC_OPTIMIZATION") == 1 {
                return Err(bad());
            }
            if value != 1 {
                return Err(only_one("CONSENSUS_LOGIC_OPTIMIZATION"));
            }
        }
        AllowTvmCancun => {
            if flag(b"ALLOW_TVM_CANCUN") == 1 {
                return Err(bad());
            }
            if value != 1 {
                return Err(only_one("ALLOW_TVM_CANCUN"));
            }
        }
        AllowTvmBlob => {
            if flag(b"ALLOW_TVM_BLOB") == 1 {
                return Err(bad());
            }
            if value != 1 {
                return Err(only_one("ALLOW_TVM_BLOB"));
            }
        }
        AllowTvmSelfdestructRestriction => {
            if flag(b"ALLOW_TVM_SELFDESTRUCT_RESTRICTION") == 1 {
                return Err(bad());
            }
            if value != 1 {
                return Err(only_one("ALLOW_TVM_SELFDESTRUCT_RESTRICTION"));
            }
        }
        ProposalExpireTime => {
            if value <= MIN_PROPOSAL_EXPIRE_TIME || value >= MAX_PROPOSAL_EXPIRE_TIME {
                return Err(bad());
            }
        }
    }
    Ok(())
}

/// Mirrors java `ProposalUtil.ProposalType` — the set of valid chain-parameter
/// codes and their numeric ids. A code not present here is rejected by
/// [`validate_proposal_value`] exactly as java's `ProposalType.getEnum` throws
/// "Does not support code". The commented-out java entries (shielded-tx codes
/// 27/28/34) are intentionally omitted, matching java.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ProposalType {
    MaintenanceTimeInterval,
    AccountUpgradeCost,
    CreateAccountFee,
    TransactionFee,
    AssetIssueFee,
    WitnessPayPerBlock,
    WitnessStandbyAllowance,
    CreateNewAccountFeeInSystemContract,
    CreateNewAccountBandwidthRate,
    AllowCreationOfContracts,
    RemoveThePowerOfTheGr,
    EnergyFee,
    ExchangeCreateFee,
    MaxCpuTimeOfOneTx,
    AllowUpdateAccountName,
    AllowSameTokenName,
    AllowDelegateResource,
    TotalEnergyLimit,
    AllowTvmTransferTrc10,
    TotalCurrentEnergyLimit,
    AllowMultiSign,
    AllowAdaptiveEnergy,
    UpdateAccountPermissionFee,
    MultiSignFee,
    AllowProtoFilterNum,
    AllowAccountStateRoot,
    AllowTvmConstantinople,
    AdaptiveResourceLimitMultiplier,
    AllowChangeDelegation,
    Witness127PayPerBlock,
    AllowTvmSolidity059,
    AdaptiveResourceLimitTargetRatio,
    ForbidTransferToContract,
    AllowShieldedTrc20Transaction,
    AllowPbft,
    AllowTvmIstanbul,
    AllowMarketTransaction,
    MarketSellFee,
    MarketCancelFee,
    MaxFeeLimit,
    AllowTransactionFeePool,
    AllowBlackholeOptimization,
    AllowNewResourceModel,
    AllowTvmFreeze,
    AllowAccountAssetOptimization,
    AllowTvmVote,
    AllowTvmCompatibleEvm,
    FreeNetLimit,
    TotalNetLimit,
    AllowTvmLondon,
    AllowHigherLimitForMaxCpuTimeOfOneTx,
    AllowAssetOptimization,
    AllowNewReward,
    MemoFee,
    AllowDelegateOptimization,
    UnfreezeDelayDays,
    AllowOptimizedReturnValueOfChainId,
    AllowDynamicEnergy,
    DynamicEnergyThreshold,
    DynamicEnergyIncreaseFactor,
    DynamicEnergyMaxFactor,
    AllowTvmShanghai,
    AllowCancelAllUnfreezeV2,
    MaxDelegateLockPeriod,
    AllowOldRewardOpt,
    AllowEnergyAdjustment,
    MaxCreateAccountTxSize,
    AllowTvmCancun,
    AllowStrictMath,
    ConsensusLogicOptimization,
    AllowTvmBlob,
    ProposalExpireTime,
    AllowTvmSelfdestructRestriction,
}

impl ProposalType {
    /// Mirrors java `ProposalType(code)` id mapping verbatim.
    fn from_code(code: i64) -> Option<ProposalType> {
        use ProposalType::*;
        Some(match code {
            0 => MaintenanceTimeInterval,
            1 => AccountUpgradeCost,
            2 => CreateAccountFee,
            3 => TransactionFee,
            4 => AssetIssueFee,
            5 => WitnessPayPerBlock,
            6 => WitnessStandbyAllowance,
            7 => CreateNewAccountFeeInSystemContract,
            8 => CreateNewAccountBandwidthRate,
            9 => AllowCreationOfContracts,
            10 => RemoveThePowerOfTheGr,
            11 => EnergyFee,
            12 => ExchangeCreateFee,
            13 => MaxCpuTimeOfOneTx,
            14 => AllowUpdateAccountName,
            15 => AllowSameTokenName,
            16 => AllowDelegateResource,
            17 => TotalEnergyLimit,
            18 => AllowTvmTransferTrc10,
            19 => TotalCurrentEnergyLimit,
            20 => AllowMultiSign,
            21 => AllowAdaptiveEnergy,
            22 => UpdateAccountPermissionFee,
            23 => MultiSignFee,
            24 => AllowProtoFilterNum,
            25 => AllowAccountStateRoot,
            26 => AllowTvmConstantinople,
            // 27/28 (shielded-tx) commented out in java.
            29 => AdaptiveResourceLimitMultiplier,
            30 => AllowChangeDelegation,
            31 => Witness127PayPerBlock,
            32 => AllowTvmSolidity059,
            33 => AdaptiveResourceLimitTargetRatio,
            // 34 (shielded-tx create-account fee) commented out in java.
            35 => ForbidTransferToContract,
            39 => AllowShieldedTrc20Transaction,
            40 => AllowPbft,
            41 => AllowTvmIstanbul,
            // 42/43 (tvm asset-issue/stake) commented out in java.
            44 => AllowMarketTransaction,
            45 => MarketSellFee,
            46 => MarketCancelFee,
            47 => MaxFeeLimit,
            48 => AllowTransactionFeePool,
            49 => AllowBlackholeOptimization,
            51 => AllowNewResourceModel,
            52 => AllowTvmFreeze,
            53 => AllowAccountAssetOptimization,
            // 58 (new-reward-algorithm) commented out in java.
            59 => AllowTvmVote,
            60 => AllowTvmCompatibleEvm,
            61 => FreeNetLimit,
            62 => TotalNetLimit,
            63 => AllowTvmLondon,
            65 => AllowHigherLimitForMaxCpuTimeOfOneTx,
            66 => AllowAssetOptimization,
            67 => AllowNewReward,
            68 => MemoFee,
            69 => AllowDelegateOptimization,
            70 => UnfreezeDelayDays,
            71 => AllowOptimizedReturnValueOfChainId,
            72 => AllowDynamicEnergy,
            73 => DynamicEnergyThreshold,
            74 => DynamicEnergyIncreaseFactor,
            75 => DynamicEnergyMaxFactor,
            76 => AllowTvmShanghai,
            77 => AllowCancelAllUnfreezeV2,
            78 => MaxDelegateLockPeriod,
            79 => AllowOldRewardOpt,
            81 => AllowEnergyAdjustment,
            82 => MaxCreateAccountTxSize,
            83 => AllowTvmCancun,
            87 => AllowStrictMath,
            88 => ConsensusLogicOptimization,
            89 => AllowTvmBlob,
            92 => ProposalExpireTime,
            94 => AllowTvmSelfdestructRestriction,
            _ => return None,
        })
    }
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
    let maintenance_interval = dyn_props
        .maintenance_time_interval()
        .unwrap_or(6 * 60 * 60 * 1000); // default 6h
    let current_maintenance_time = dyn_props.next_maintenance_time().unwrap_or(now);

    // java ProposalCreateActuator.execute (verbatim):
    //   long now3 = now + getProposalExpireTime();   // 259_200_000 default
    //   long round = (now3 - currentMaintenanceTime) / maintenanceTimeInterval;
    //   long expirationTime = currentMaintenanceTime + (round + 1) * interval;
    // `round` is a plain `long` division — it truncates toward zero, NOT a
    // floor/ceil. When `now3 < currentMaintenanceTime` (the proposal would
    // expire before the next maintenance) `round` is 0 or negative and the
    // formula still lands on a maintenance boundary, exactly as java does.
    let now3 = now + dyn_props.proposal_expire_time();
    let round = (now3 - current_maintenance_time) / maintenance_interval;
    let expiration_time = current_maintenance_time + (round + 1) * maintenance_interval;

    let proposal = Proposal {
        proposal_id: next_id,
        proposer_address: owner.as_bytes().to_vec(),
        parameters: contract.parameters.clone(),
        expiration_time,
        create_time: now,
        approvals: Vec::new(),
        state: ProposalState::Pending as i32,
    };
    proposals.put(next_id, &proposal)?;
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
    if !witnesses.contains(&owner)? {
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
    proposals.put(contract.proposal_id, &proposal)?;
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
    proposals.put(contract.proposal_id, &proposal)?;
    Ok(ExecutionResult::default())
}
