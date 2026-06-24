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
use tron_crypto::address::Address;
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
/// `active_witnesses` is the **current** active SR set. java
/// `ProposalCapsule.hasMostApprovals` counts only approvals from witnesses
/// presently in that set (an approver that has since dropped out of the
/// active list no longer counts) and accepts at
/// `floor(activeWitnesses.size() * 7 / 10)` — 18 for the 27-SR mainnet, NOT
/// the ceiling. (TRON's 70% proposal threshold is distinct from the 2/3 used
/// for block solidity.)
pub fn activate_expired_proposals(
    proposals: &ProposalStore,
    dyn_props: &DynamicPropertiesStore,
    now_ms: i64,
    active_witnesses: &[Address],
) -> Result<ProposalActivationReport, StoreError> {
    let threshold = active_witnesses.len() * 7 / 10; // java: size * 7 / 10 (floor)
    let active_set: std::collections::HashSet<&[u8]> = active_witnesses
        .iter()
        .map(|w| w.as_bytes().as_slice())
        .collect();
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

        // Count approvals from witnesses CURRENTLY in the active set, per
        // java `hasMostApprovals` (`approvals.stream().filter(activeWitnesses
        // ::contains).count()`). Each approval entry is a distinct 21-byte
        // address (the actuator dedupes on add); an approver no longer in the
        // active SR list does not count toward the threshold.
        let approvals = proposal
            .approvals
            .iter()
            .filter(|a| active_set.contains(a.as_slice()))
            .count();
        let approved = approvals >= threshold;

        if approved {
            // Apply each (parameter_id, value) to DynamicPropertiesStore.
            // The key naming convention: java-tron's `ProposalUtil`
            // has a switch over `parameter_id` mapping to specific
            // keys (e.g. 0 → "MAINTENANCE_TIME_INTERVAL"). We mirror
            // that mapping in `parameter_id_to_key` below.
            for (param_id, value) in &proposal.parameters {
                if let Some(key) = parameter_id_to_key(*param_id) {
                    // ALLOW_ADAPTIVE_ENERGY(21) is idempotent: java only writes
                    // the flag (and its derived keys) on the 0 -> 1 transition,
                    // inside `if getAllowAdaptiveEnergy() == 0`
                    // (ProposalService.process, lines 128-141). Capture the
                    // prior value before the write so the side-effects below
                    // can replicate that guard.
                    let prev_allow_adaptive_energy = if *param_id == 21 {
                        dyn_props.allow_adaptive_energy()
                    } else {
                        0
                    };
                    if *param_id == 21 && prev_allow_adaptive_energy != 0 {
                        // Already enabled — java's guard skips the write and all
                        // derived effects; mirror that and still record the
                        // (no-op) parameter update for the report.
                        report.parameter_updates.push((id, *param_id, *value));
                        continue;
                    }
                    // REMOVE_THE_POWER_OF_THE_GR(10) writes the proposal value
                    // only while the flag is still the genesis default `0`
                    // (java `ProposalService.process`: `if
                    // getRemoveThePowerOfTheGr() == 0`). Once
                    // `MaintenanceManager.tryRemoveThePowerOfTheGr` has spent
                    // it (`-1`), re-applying the value would re-arm the flag
                    // and double-debit the genesis SR votes at the next
                    // maintenance. Skip the write but still record the
                    // (no-op) parameter update for the report.
                    if *param_id == 10
                        && dyn_props.get_long(b"REMOVE_THE_POWER_OF_THE_GR") != Some(0)
                    {
                        report.parameter_updates.push((id, *param_id, *value));
                        continue;
                    }
                    dyn_props.put_long(key, *value);
                    // Price changes also append to the historic schedule
                    // (java's `ProposalService.process`, TRANSACTION_FEE /
                    // ENERGY_FEE cases): `old + "," + expiration:value` —
                    // the proposal's expiration is the instant the new
                    // price takes effect. `getBandwidthPrices` /
                    // `getEnergyPrices` serve this string verbatim, and
                    // at-timestamp fee lookups walk it.
                    match *param_id {
                        3 => {
                            let appended = format!(
                                "{},{}:{}",
                                dyn_props.bandwidth_price_history(),
                                proposal.expiration_time,
                                value
                            );
                            dyn_props.save_bandwidth_price_history(&appended);
                        }
                        11 => {
                            let appended = format!(
                                "{},{}:{}",
                                dyn_props.energy_price_history(),
                                proposal.expiration_time,
                                value
                            );
                            dyn_props.save_energy_price_history(&appended);
                        }
                        // ADAPTIVE_RESOURCE_LIMIT_TARGET_RATIO(33) is
                        // stored SCALED — java's ProposalService writes
                        // `24 * 60 * value` (periods per day × ratio) and
                        // re-derives the energy target limit from it.
                        33 => {
                            let ratio = 24 * 60 * *value;
                            dyn_props.put_long(
                                b"ADAPTIVE_RESOURCE_LIMIT_TARGET_RATIO",
                                ratio,
                            );
                            let total = dyn_props
                                .get_long(b"TOTAL_ENERGY_LIMIT")
                                .unwrap_or(0);
                            if ratio > 0 {
                                dyn_props.put_long(
                                    b"TOTAL_ENERGY_TARGET_LIMIT",
                                    total / ratio,
                                );
                            }
                        }
                        // Energy-limit proposals write derived keys too:
                        //   17 — `saveTotalEnergyLimit`: target = v / ratio.
                        //   19 — `saveTotalEnergyLimit2`: target = v / ratio,
                        //        plus current = v when adaptive energy is
                        //        off (it is on mainnet:
                        //        ALLOW_ADAPTIVE_ENERGY = 0).
                        // java reads the LIVE `getAdaptiveResourceLimitTargetRatio()`
                        // as the divisor (DynamicPropertiesStore.saveTotalEnergyLimit
                        // /saveTotalEnergyLimit2, lines 1319-1336), NOT a literal —
                        // its init seed is 14400, but enabling ALLOW_ADAPTIVE_ENERGY
                        // (code 21) sets it to 2880 and proposal 33 sets it to
                        // `24 * 60 * value`. Mirror that by reading the current ratio.
                        17 | 19 => {
                            let ratio = dyn_props.adaptive_resource_limit_target_ratio();
                            if ratio != 0 {
                                dyn_props
                                    .put_long(b"TOTAL_ENERGY_TARGET_LIMIT", value / ratio);
                            }
                            if *param_id == 19
                                && dyn_props
                                    .get_long(b"ALLOW_ADAPTIVE_ENERGY")
                                    .unwrap_or(0)
                                    == 0
                            {
                                dyn_props
                                    .put_long(b"TOTAL_ENERGY_CURRENT_LIMIT", *value);
                            }
                        }
                        // ALLOW_TVM_VOTE(59) / ALLOW_NEW_REWARD(67) also arm
                        // the Vi reward algorithm — java's
                        // `saveNewRewardAlgorithmEffectiveCycle()`:
                        // NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE =
                        // currentCycle + 1, STICKY (written only while the
                        // key is still unset / Long.MAX_VALUE, so whichever
                        // of the two proposals activates first pins it).
                        59 | 67 => {
                            let existing = dyn_props
                                .get_long(b"NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE")
                                .unwrap_or(i64::MAX);
                            if existing == i64::MAX {
                                let current = dyn_props
                                    .get_long(b"CURRENT_CYCLE_NUMBER")
                                    .unwrap_or(0);
                                dyn_props.put_long(
                                    b"NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE",
                                    current + 1,
                                );
                            }
                        }
                        // MEMO_FEE(68) appends to its historic schedule the
                        // same way the energy/bandwidth price histories do —
                        // java's ProposalService.process lines 294-300:
                        // `old + "," + proposalExpirationTime + ":" + value`.
                        // The live fee is read from MEMO_FEE; this string is
                        // RPC-query only (`getMemoFeePrices`), no state-root
                        // effect.
                        68 => {
                            let appended = format!(
                                "{},{}:{}",
                                dyn_props.memo_fee_history(),
                                proposal.expiration_time,
                                value
                            );
                            dyn_props.save_memo_fee_history(&appended);
                        }
                        // ALLOW_ADAPTIVE_ENERGY(21): on the 0 -> 1 transition
                        // (already guarded above by `prev_allow_adaptive_energy`)
                        // java re-seeds the adaptive sub-state to its
                        // "adaptive on" defaults — ProposalService.process
                        // lines 128-141, gated on fork VERSION_3_6_5 which is
                        // long-active on every mainnet database:
                        //   ratio      = 2880  (24 * 60 * 2 — one minute = 1/2
                        //                        of the daily energy target),
                        //   target     = totalEnergyLimit / 2880,
                        //   multiplier = 50.
                        21 => {
                            dyn_props
                                .put_long(b"ADAPTIVE_RESOURCE_LIMIT_TARGET_RATIO", 2_880);
                            let total = dyn_props
                                .get_long(b"TOTAL_ENERGY_LIMIT")
                                .unwrap_or(0);
                            dyn_props
                                .put_long(b"TOTAL_ENERGY_TARGET_LIMIT", total / 2_880);
                            dyn_props
                                .put_long(b"ADAPTIVE_RESOURCE_LIMIT_MULTIPLIER", 50);
                        }
                        // java `ProposalService.process` calls
                        // `addSystemContractAndSetPermission(id)` as each newly
                        // enabled contract type becomes proposable — OR-setting
                        // bit `id` in BOTH the AVAILABLE_CONTRACT_TYPE and
                        // ACTIVE_DEFAULT_OPERATIONS bitmaps. The bitmaps feed
                        // every auto-created account's default permission, so
                        // missing this forks the account/state root once
                        // ALLOW_MULTI_SIGN is live. The OR is idempotent, so we
                        // set unconditionally; java guards 44/77 on the 0->1
                        // transition, but since a bit is only ever set (never
                        // cleared) the resulting bitmap is identical.
                        26 => add_system_contract_and_set_permission(dyn_props, 48),
                        30 => add_system_contract_and_set_permission(dyn_props, 49),
                        44 => {
                            add_system_contract_and_set_permission(dyn_props, 52);
                            add_system_contract_and_set_permission(dyn_props, 53);
                        }
                        70 => {
                            // FreezeBalanceV2 / UnfreezeBalanceV2 /
                            // WithdrawExpireUnfreeze / DelegateResource /
                            // UnDelegateResource contract types (54..=58).
                            for cid in 54..=58 {
                                add_system_contract_and_set_permission(dyn_props, cid);
                            }
                        }
                        77 => add_system_contract_and_set_permission(dyn_props, 59),
                        _ => {}
                    }
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
        proposals.put(id, &proposal)?;
    }

    Ok(report)
}

/// java `DynamicPropertiesStore.addSystemContractAndSetPermission(id)`
/// (DynamicPropertiesStore.java:1911-1919): OR-set bit `id` into BOTH the
/// `AVAILABLE_CONTRACT_TYPE` and `ACTIVE_DEFAULT_OPERATIONS` bitmaps as a newly
/// proposed contract type becomes enabled. `ACTIVE_DEFAULT_OPERATIONS` is the
/// operations mask stamped onto every auto-created account's default active
/// permission, so the bitmap must evolve in lock-step with java or account rows
/// (and the state root) diverge. The OR is idempotent.
fn add_system_contract_and_set_permission(dyn_props: &DynamicPropertiesStore, id: usize) {
    // Genesis defaults (java `init()`: AVAILABLE = 7fff1fc0037e0000…, ACTIVE =
    // 7fff1fc0033e0000…), used only if the key is somehow absent — a from-genesis
    // chain seeds both at bootstrap and a snapshot import carries the live ones.
    for (key, seed6) in [
        (b"AVAILABLE_CONTRACT_TYPE".as_slice(), [0x7f, 0xff, 0x1f, 0xc0, 0x03, 0x7e]),
        (b"ACTIVE_DEFAULT_OPERATIONS".as_slice(), [0x7f, 0xff, 0x1f, 0xc0, 0x03, 0x3e]),
    ] {
        let mut bitmap = dyn_props.get_bytes(key).unwrap_or_else(|| {
            let mut b = vec![0u8; 32];
            b[..6].copy_from_slice(&seed6);
            b
        });
        let byte = id / 8;
        if byte < bitmap.len() {
            bitmap[byte] |= 1u8 << (id % 8);
            dyn_props.put_bytes(key, &bitmap);
        }
    }
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
        // java quirk: stored with a leading space (the canonical typo —
        // see the chainbase keys doc).
        15 => b" ALLOW_SAME_TOKEN_NAME",
        16 => b"ALLOW_DELEGATE_RESOURCE",
        17 => b"TOTAL_ENERGY_LIMIT",
        18 => b"ALLOW_TVM_TRANSFER_TRC10",
        // java's TOTAL_CURRENT_ENERGY_LIMIT(19) routes through
        // `saveTotalEnergyLimit2`, whose primary write is the same
        // TOTAL_ENERGY_LIMIT key (derived keys handled at activation).
        19 => b"TOTAL_ENERGY_LIMIT",
        20 => b"ALLOW_MULTI_SIGN",
        21 => b"ALLOW_ADAPTIVE_ENERGY",
        22 => b"UPDATE_ACCOUNT_PERMISSION_FEE",
        23 => b"MULTI_SIGN_FEE",
        24 => b"ALLOW_PROTO_FILTER_NUM",
        25 => b"ALLOW_ACCOUNT_STATE_ROOT",
        26 => b"ALLOW_TVM_CONSTANTINOPLE",
        // Ids below follow java's `ProposalUtil.ProposalType` enum
        // EXACTLY, including its gaps (27/28, 34, 36-38, 42/43, 50,
        // 54-58, 64, 80, 84-86, 90/91, 93 are unassigned or were
        // removed before activation). The previous table numbered these
        // sequentially, so every id ≥ 27 mapped to the WRONG chain
        // parameter — historic proposals were applied by java before
        // our snapshot, but any FUTURE proposal would have activated
        // against the wrong key.
        29 => b"ADAPTIVE_RESOURCE_LIMIT_MULTIPLIER",
        // java quirk: the on-disk key has no ALLOW_ prefix.
        30 => b"CHANGE_DELEGATION",
        31 => b"WITNESS_127_PAY_PER_BLOCK",
        32 => b"ALLOW_TVM_SOLIDITY_059",
        33 => b"ADAPTIVE_RESOURCE_LIMIT_TARGET_RATIO",
        35 => b"FORBID_TRANSFER_TO_CONTRACT",
        39 => b"ALLOW_SHIELDED_TRC20_TRANSACTION",
        40 => b"ALLOW_PBFT",
        41 => b"ALLOW_TVM_ISTANBUL",
        44 => b"ALLOW_MARKET_TRANSACTION",
        45 => b"MARKET_SELL_FEE",
        46 => b"MARKET_CANCEL_FEE",
        47 => b"MAX_FEE_LIMIT",
        48 => b"ALLOW_TRANSACTION_FEE_POOL",
        49 => b"ALLOW_BLACKHOLE_OPTIMIZATION",
        51 => b"ALLOW_NEW_RESOURCE_MODEL",
        52 => b"ALLOW_TVM_FREEZE",
        53 => b"ALLOW_ACCOUNT_ASSET_OPTIMIZATION",
        59 => b"ALLOW_TVM_VOTE",
        60 => b"ALLOW_TVM_COMPATIBLE_EVM",
        61 => b"FREE_NET_LIMIT",
        62 => b"TOTAL_NET_LIMIT",
        63 => b"ALLOW_TVM_LONDON",
        65 => b"ALLOW_HIGHER_LIMIT_FOR_MAX_CPU_TIME_OF_ONE_TX",
        66 => b"ALLOW_ASSET_OPTIMIZATION",
        67 => b"ALLOW_NEW_REWARD",
        68 => b"MEMO_FEE",
        69 => b"ALLOW_DELEGATE_OPTIMIZATION",
        70 => b"UNFREEZE_DELAY_DAYS",
        71 => b"ALLOW_OPTIMIZED_RETURN_VALUE_OF_CHAIN_ID",
        72 => b"ALLOW_DYNAMIC_ENERGY",
        73 => b"DYNAMIC_ENERGY_THRESHOLD",
        74 => b"DYNAMIC_ENERGY_INCREASE_FACTOR",
        75 => b"DYNAMIC_ENERGY_MAX_FACTOR",
        76 => b"ALLOW_TVM_SHANGHAI",
        77 => b"ALLOW_CANCEL_ALL_UNFREEZE_V2",
        78 => b"MAX_DELEGATE_LOCK_PERIOD",
        79 => b"ALLOW_OLD_REWARD_OPT",
        81 => b"ALLOW_ENERGY_ADJUSTMENT",
        82 => b"MAX_CREATE_ACCOUNT_TX_SIZE",
        83 => b"ALLOW_TVM_CANCUN",
        87 => b"ALLOW_STRICT_MATH",
        88 => b"CONSENSUS_LOGIC_OPTIMIZATION",
        89 => b"ALLOW_TVM_BLOB",
        92 => b"PROPOSAL_EXPIRE_TIME",
        94 => b"ALLOW_TVM_SELFDESTRUCT_RESTRICTION",
        95 => b"ALLOW_TVM_PRAGUE",
        96 => b"ALLOW_TVM_OSAKA",
        97 => b"ALLOW_HARDEN_RESOURCE_CALCULATION",
        98 => b"ALLOW_HARDEN_EXCHANGE_CALCULATION",
        _ => return None,
    })
}

#[cfg(test)]
mod bitmap_evolution_tests {
    use std::sync::Arc;

    use tron_chainbase::{DynamicPropertiesStore, MemBackend};

    use super::add_system_contract_and_set_permission;

    fn seeded_store() -> DynamicPropertiesStore {
        let dp = DynamicPropertiesStore::new(Arc::new(MemBackend::new()));
        // Genesis seeds (java init()): AVAILABLE = 7fff1fc0037e0000…,
        // ACTIVE = 7fff1fc0033e0000… (rest zero).
        let mut available = vec![0u8; 32];
        available[..6].copy_from_slice(&[0x7f, 0xff, 0x1f, 0xc0, 0x03, 0x7e]);
        dp.put_bytes(b"AVAILABLE_CONTRACT_TYPE", &available);
        let mut active = vec![0u8; 32];
        active[..6].copy_from_slice(&[0x7f, 0xff, 0x1f, 0xc0, 0x03, 0x3e]);
        dp.put_bytes(b"ACTIVE_DEFAULT_OPERATIONS", &active);
        dp
    }

    fn bit_set(bytes: &[u8], id: usize) -> bool {
        bytes[id / 8] & (1u8 << (id % 8)) != 0
    }

    /// java `addSystemContractAndSetPermission(id)` OR-sets bit `id` in BOTH
    /// bitmaps. UnfreezeDelay (#70) enables contract types 54..=58.
    #[test]
    fn sets_bit_in_both_bitmaps_and_is_idempotent() {
        let dp = seeded_store();
        for id in 54..=58 {
            add_system_contract_and_set_permission(&dp, id);
        }
        let avail = dp.get_bytes(b"AVAILABLE_CONTRACT_TYPE").unwrap();
        let act = dp.get_bytes(b"ACTIVE_DEFAULT_OPERATIONS").unwrap();
        for id in 54..=58 {
            assert!(bit_set(&avail, id), "AVAILABLE bit {id} must be set");
            assert!(bit_set(&act, id), "ACTIVE bit {id} must be set");
        }
        // Idempotent: re-applying changes nothing (the OR is a no-op).
        add_system_contract_and_set_permission(&dp, 54);
        assert_eq!(dp.get_bytes(b"AVAILABLE_CONTRACT_TYPE").unwrap(), avail);
        assert_eq!(dp.get_bytes(b"ACTIVE_DEFAULT_OPERATIONS").unwrap(), act);
    }

    /// Constantinople (#26 → id 48) + ChangeDelegation (#30 → id 49) set bits
    /// 48 and 49 (byte 6 bits 0+1 → 0x03), building toward the mainnet
    /// ACTIVE_DEFAULT_OPERATIONS prefix.
    #[test]
    fn constantinople_and_change_delegation_set_bits_48_49() {
        let dp = seeded_store();
        add_system_contract_and_set_permission(&dp, 48);
        add_system_contract_and_set_permission(&dp, 49);
        let act = dp.get_bytes(b"ACTIVE_DEFAULT_OPERATIONS").unwrap();
        assert_eq!(act[6], 0x03, "byte 6 gains bits 48 and 49");
        assert!(bit_set(&act, 48) && bit_set(&act, 49));
    }
}
