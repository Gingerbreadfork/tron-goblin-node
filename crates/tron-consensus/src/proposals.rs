//! Proposal-pass → chain-parameter activation.
//!
//! Every block at a maintenance boundary, java-tron walks the
//! `ProposalStore` and:
//!
//! 1. Finds proposals whose `expiration_time` ≤ this block's timestamp
//!    AND whose state is `Pending`.
//! 2. Counts unique approvals against the SR-supermajority threshold
//!    (70% of active witnesses, currently 19/27).
//! 3. If threshold met → state ⇢ `Approved`, write every
//!    `(parameter_id, value)` from the proposal into
//!    `DynamicPropertiesStore` so subsequent blocks see the new value.
//! 4. If threshold not met → state ⇢ `Disapproved`. Either way the
//!    proposal becomes terminal — `Pending` cleared.
//!
//! Source: `org.tron.core.actuator.utils.ProposalUtil.applyProposal`
//! + `Manager.updateActiveWitnesses`.

use tron_chainbase::{DynamicPropertiesStore, ProposalStore, StoreError};
use tron_proto::proposal::State as ProposalState;

/// Summary of a proposal-activation pass.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ProposalActivationReport {
    /// Proposal IDs that just became `Approved` and whose parameters
    /// were applied. Sorted ascending.
    pub approved: Vec<i64>,
    /// Proposal IDs that just became `Disapproved` (expired without
    /// meeting threshold). Sorted ascending.
    pub disapproved: Vec<i64>,
    /// `(proposal_id, parameter_id, value)` triples — every parameter
    /// write that landed in DynamicPropertiesStore. Pinned for tests.
    pub parameter_updates: Vec<(i64, i64, i64)>,
}

/// Walk the proposal store and resolve any expired Pending proposals
/// against `now_ms`. Returns a report of state changes.
///
/// `active_witness_count` is the **current** active set size (typically
/// 27 on mainnet). Threshold is `⌈active * 0.7⌉` distinct signers per
/// java-tron's `ChainConstant.SOLIDIFIED_THRESHOLD`. (TRON uses 70% for
/// proposal acceptance, distinct from the 2/3 used for block solidity.)
pub fn activate_expired_proposals(
    proposals: &ProposalStore,
    dyn_props: &DynamicPropertiesStore,
    now_ms: i64,
    active_witness_count: usize,
) -> Result<ProposalActivationReport, StoreError> {
    let threshold = ((active_witness_count * 7) + 9) / 10; // ⌈n * 0.7⌉
    let mut report = ProposalActivationReport::default();

    let mut all = proposals.all()?;
    all.sort_by_key(|(id, _)| *id);

    for (id, mut proposal) in all {
        if proposal.state != ProposalState::Pending as i32 {
            continue;
        }
        if proposal.expiration_time > now_ms {
            continue;
        }

        // Count distinct approving witnesses. java-tron uses the
        // `approvals` list directly — every entry is a distinct
        // 21-byte witness address by construction (the actuator
        // dedupes on add).
        let approvals = proposal.approvals.len();
        let approved = approvals >= threshold;

        if approved {
            // Apply each (parameter_id, value) to DynamicPropertiesStore.
            // The key naming convention: java-tron's `ProposalUtil`
            // has a switch over `parameter_id` mapping to specific
            // keys (e.g. 0 → "MAINTENANCE_TIME_INTERVAL"). We mirror
            // that mapping in `parameter_id_to_key` below.
            for (param_id, value) in &proposal.parameters {
                if let Some(key) = parameter_id_to_key(*param_id) {
                    dyn_props.put_long(key, *value);
                    report
                        .parameter_updates
                        .push((id, *param_id, *value));
                }
                // Unknown parameter ids are silently dropped — same as
                // java-tron, which validates `parameter_id` at proposal
                // *creation*, not at activation.
            }
            proposal.state = ProposalState::Approved as i32;
            report.approved.push(id);
        } else {
            proposal.state = ProposalState::Disapproved as i32;
            report.disapproved.push(id);
        }
        proposals.put(id, &proposal);
    }

    Ok(report)
}

/// Map a TRON proposal parameter id to its `DynamicPropertiesStore`
/// key. This is the lookup table java-tron has in
/// `ProposalUtil.applyProposal`. We list the most commonly used
/// parameters; missing ones fall through to `None` and the activation
/// silently drops them (matches java-tron's "unknown id = no-op"
/// behaviour when proposals were created under an older version).
pub fn parameter_id_to_key(id: i64) -> Option<&'static [u8]> {
    Some(match id {
        0 => b"MAINTENANCE_TIME_INTERVAL",
        1 => b"ACCOUNT_UPGRADE_COST",
        2 => b"CREATE_ACCOUNT_FEE",
        3 => b"TRANSACTION_FEE",
        4 => b"ASSET_ISSUE_FEE",
        5 => b"WITNESS_PAY_PER_BLOCK",
        6 => b"WITNESS_STANDBY_ALLOWANCE",
        7 => b"CREATE_NEW_ACCOUNT_FEE_IN_SYSTEM_CONTRACT",
        8 => b"CREATE_NEW_ACCOUNT_BANDWIDTH_RATE",
        9 => b"ALLOW_CREATION_OF_CONTRACTS",
        10 => b"REMOVE_THE_POWER_OF_THE_GR",
        11 => b"ENERGY_FEE",
        12 => b"EXCHANGE_CREATE_FEE",
        13 => b"MAX_CPU_TIME_OF_ONE_TX",
        14 => b"ALLOW_UPDATE_ACCOUNT_NAME",
        15 => b"ALLOW_SAME_TOKEN_NAME",
        16 => b"ALLOW_DELEGATE_RESOURCE",
        17 => b"TOTAL_ENERGY_LIMIT",
        18 => b"ALLOW_TVM_TRANSFER_TRC10",
        19 => b"TOTAL_CURRENT_ENERGY_LIMIT",
        20 => b"ALLOW_MULTI_SIGN",
        21 => b"ALLOW_ADAPTIVE_ENERGY",
        22 => b"UPDATE_ACCOUNT_PERMISSION_FEE",
        23 => b"MULTI_SIGN_FEE",
        24 => b"ALLOW_PROTO_FILTER_NUM",
        25 => b"ALLOW_ACCOUNT_STATE_ROOT",
        26 => b"ALLOW_TVM_CONSTANTINOPLE",
        27 => b"ALLOW_TVM_SOLIDITY_059",
        28 => b"ADAPTIVE_RESOURCE_LIMIT_TARGET_RATIO",
        29 => b"ADAPTIVE_RESOURCE_LIMIT_MULTIPLIER",
        30 => b"ALLOW_CHANGE_DELEGATION",
        31 => b"WITNESS_127_PAY_PER_BLOCK",
        32 => b"ALLOW_TVM_SHIELDED_TRC20",
        33 => b"ALLOW_TVM_ISTANBUL",
        34 => b"ALLOW_MARKET_TRANSACTION",
        35 => b"MARKET_SELL_FEE",
        36 => b"MARKET_CANCEL_FEE",
        37 => b"ALLOW_PBFT",
        38 => b"ALLOW_TRANSACTION_FEE_POOL",
        39 => b"MAX_FEE_LIMIT",
        40 => b"ALLOW_OPTIMIZE_BLACK_HOLE",
        41 => b"ALLOW_NEW_RESOURCE_MODEL",
        42 => b"ALLOW_TVM_FREEZE",
        43 => b"ALLOW_TVM_VOTE",
        44 => b"ALLOW_TVM_LONDON",
        45 => b"ALLOW_TVM_COMPATIBLE_EVM",
        46 => b"FREE_NET_LIMIT",
        47 => b"TOTAL_NET_LIMIT",
        48 => b"ALLOW_ACCOUNT_ASSET_OPTIMIZATION",
        49 => b"ALLOW_HIGHER_LIMIT_FOR_MAX_CPU_TIME_OF_ONE_TX",
        50 => b"ALLOW_ASSET_OPTIMIZATION",
        51 => b"ALLOW_NEW_REWARD",
        52 => b"MEMO_FEE",
        53 => b"ALLOW_DELEGATE_OPTIMIZATION",
        54 => b"ALLOW_DYNAMIC_ENERGY",
        55 => b"DYNAMIC_ENERGY_THRESHOLD",
        56 => b"DYNAMIC_ENERGY_INCREASE_FACTOR",
        57 => b"DYNAMIC_ENERGY_MAX_FACTOR",
        58 => b"ALLOW_TVM_SHANGHAI",
        59 => b"ALLOW_CANCEL_ALL_UNFREEZE_V2",
        60 => b"ALLOW_OLD_REWARD_OPT",
        61 => b"ALLOW_TVM_CANCUN",
        62 => b"ALLOW_ENERGY_ADJUSTMENT",
        63 => b"MAX_CREATE_ACCOUNT_TX_SIZE",
        _ => return None,
    })
}
