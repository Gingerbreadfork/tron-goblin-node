//! Maintenance period boundary detection + SR-ranking update.
//!
//! Source: `org.tron.consensus.dpos.MaintenanceManager.applyBlock` +
//! `doMaintenance`.
//!
//! Every `maintenance_time_interval_ms` (default 6 hours), the chain
//! enters a maintenance period:
//!
//! 1. Vote counts roll up from [`tron_chainbase::VotesStore`].
//! 2. Each [`tron_chainbase::Witness`] gets the *delta* vote count
//!    added (note: not replaced — accumulated).
//! 3. The top 27 by total vote count become the new active SR list.
//! 4. The new list is written to
//!    `WitnessScheduleStore::active_witnesses`.
//! 5. Rewards are distributed (deferred — see crate docs).
//! 6. `next_maintenance_time` advances by one interval.
//!
//! **Iteration constraint**: java-tron iterates `VotesStore` and
//! `WitnessStore` by walking RocksDB. Our [`tron_chainbase::KvBackend`]
//! trait deliberately omits iteration to keep the abstraction thin —
//! so [`update_active_witnesses`] takes the lists of *known* voters
//! and witness addresses as inputs. The caller (typically a maintenance
//! coordinator at a higher layer) is responsible for tracking those.
//! This trade-off is documented at the call site.

use std::collections::HashMap;

use tron_chainbase::{
    AccountStore, DelegationStore, DynamicPropertiesStore, VotesStore, WitnessScheduleStore,
    WitnessStore,
};
use tron_crypto::address::Address;

use crate::slot::MAX_ACTIVE_WITNESS_NUM;

/// 6 hours in milliseconds — the default value of the
/// `MAINTENANCE_TIME_INTERVAL` proposal parameter on mainnet.
pub const DEFAULT_MAINTENANCE_INTERVAL_MS: i64 = 6 * 60 * 60 * 1000;

/// A block at `block_time_ms` crosses a maintenance boundary iff its
/// timestamp is at or past the next scheduled maintenance time.
///
/// Source: `MaintenanceManager.applyBlock` —
/// `consensusDelegate.getNextMaintenanceTime() <= blockTime`.
#[inline]
pub fn is_maintenance_boundary(block_time_ms: i64, next_maintenance_time_ms: i64) -> bool {
    next_maintenance_time_ms <= block_time_ms
}

/// Advance `next_maintenance_time` past `block_time_ms` in whole
/// `interval_ms` increments. If `prev_next` is already in the future
/// (no boundary), returns `prev_next` unchanged.
///
/// Mirrors `ConsensusDelegate.updateNextMaintenanceTime`.
pub fn compute_next_maintenance_time(
    block_time_ms: i64,
    prev_next_ms: i64,
    interval_ms: i64,
) -> i64 {
    if block_time_ms < prev_next_ms {
        return prev_next_ms;
    }
    let elapsed = block_time_ms - prev_next_ms;
    let cycles = (elapsed / interval_ms) + 1;
    prev_next_ms + cycles * interval_ms
}

/// Summary returned by [`update_active_witnesses`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaintenanceReport {
    /// The new active witness list (top 27 by total vote count).
    pub new_active: Vec<Address>,
    /// Whether the active list changed from the previous round.
    pub changed: bool,
    /// Per-witness delta vote counts that were tallied this round.
    pub vote_deltas: Vec<(Address, i64)>,
}

/// Run the SR ranking update.
///
/// **Inputs:**
/// * `voters` — every address that has cast votes in [`VotesStore`].
///   The caller maintains this list (e.g. by indexing every
///   `VoteWitnessContract` they execute). For tests, just pass every
///   known voter.
/// * `candidate_witnesses` — every address registered in [`WitnessStore`].
///
/// **Effects:**
/// * For each candidate, sum the `new_votes` votes pointing at them
///   across every voter's [`tron_proto::Votes`] record.
/// * Add those deltas to each `WitnessCapsule.vote_count` (accumulate;
///   do not replace).
/// * Sort by `vote_count desc`, take the top 27.
/// * Persist the new list as `WitnessScheduleStore::active_witnesses`.
///
/// **Returns:** [`MaintenanceReport`] summarising the changes.
///
/// **Deferred behaviors** (documented; not implemented):
/// * `useNewRewardAlgorithm` path that accumulates per-cycle Vi values
///   in `DelegationStore` / `RewardViStore` for proportional reward
///   payouts. The current v1 update only re-ranks SRs; reward math is
///   the next pass.
/// * `IncentiveManager.reward(newList)` — the per-block fee pool
///   distribution at maintenance time.
/// * The `isJobs` flag flip on witnesses entering or leaving the
///   active list. Java-tron sets this for monitoring; consensus
///   doesn't actually read it during validation.
pub fn update_active_witnesses(
    witnesses: &WitnessStore,
    votes: &VotesStore,
    schedule: &WitnessScheduleStore,
    voters: &[Address],
    candidate_witnesses: &[Address],
) -> Result<MaintenanceReport, tron_chainbase::StoreError> {
    // 1. Tally vote deltas from each voter's `new_votes` list.
    let mut deltas: HashMap<Address, i64> = HashMap::new();
    for voter in voters {
        let Some(record) = votes.get(voter)? else {
            continue;
        };
        for v in &record.new_votes {
            let Some(witness_addr) = (|| -> Option<Address> {
                if v.vote_address.len() != tron_crypto::address::ADDRESS_LENGTH {
                    return None;
                }
                let mut buf = [0u8; tron_crypto::address::ADDRESS_LENGTH];
                buf.copy_from_slice(&v.vote_address);
                Some(Address::from_raw(buf))
            })() else {
                continue;
            };
            *deltas.entry(witness_addr).or_insert(0) += v.vote_count;
        }
    }

    // 2. For each candidate, load the witness, add the delta, save back.
    //    Track effective `(address, vote_count)` for the ranking step.
    let mut ranked: Vec<(Address, i64)> = Vec::with_capacity(candidate_witnesses.len());
    for addr in candidate_witnesses {
        let Some(mut witness) = witnesses.get(addr)? else {
            continue;
        };
        let delta = *deltas.get(addr).unwrap_or(&0);
        witness.vote_count = witness.vote_count.saturating_add(delta);
        witnesses.put(addr, &witness)?;
        ranked.push((*addr, witness.vote_count));
    }

    // 3. Sort by vote_count desc; on tie, by address bytes (deterministic).
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.as_bytes().cmp(b.0.as_bytes())));
    let new_active: Vec<Address> = ranked
        .iter()
        .take(MAX_ACTIVE_WITNESS_NUM)
        .map(|(addr, _)| *addr)
        .collect();

    // 4. Compare to previous list and persist.
    let prev_active = schedule.load_active()?.unwrap_or_default();
    let changed = prev_active != new_active;
    schedule.save_active(&new_active)?;

    // 5. Build the per-witness delta report (only entries with non-zero deltas).
    let mut vote_deltas: Vec<(Address, i64)> = deltas.into_iter().collect();
    vote_deltas.sort_by_key(|(a, _)| *a.as_bytes());

    Ok(MaintenanceReport {
        new_active,
        changed,
        vote_deltas,
    })
}

// =============================================================================
// Maintenance orchestrator — the "do everything at the cycle boundary" pass
// =============================================================================

/// Summary returned by [`apply_maintenance`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaintenanceOutcome {
    /// Previously-active witness list, captured BEFORE this rotation
    /// overwrote `WitnessScheduleStore`. Surface this back to callers
    /// so they can populate the in-memory [`crate::SrEpochSnapshot`]
    /// `before` slot for cross-rotation PBFT verification.
    pub prev_active: Vec<Address>,
    /// New active witness list (top 27 by vote_count).
    pub new_active: Vec<Address>,
    /// Whether the active list changed from the previous round.
    pub changed: bool,
    /// Cycle number after the increment.
    pub new_cycle: i64,
    /// Number of witnesses whose Vi got rolled forward this cycle.
    pub vi_accumulated_count: usize,
}

/// Run the full maintenance-period pass at a cycle boundary.
///
/// Mirrors java-tron's `MaintenanceManager.doMaintenance`:
///   1. **Vi accumulation** (only when `ALLOW_CHANGE_DELEGATION == 1`):
///      For every witness, fold the current-cycle reward pool into
///      `delegation.witness_vi(current_cycle, witness)`. This is the
///      "freeze the per-vote share" step — voters' future
///      `withdraw_reward` calls walk these Vi deltas.
///   2. **Vote tally + SR re-rank**: scan every voter's `new_votes`,
///      add deltas to per-witness vote counts, re-rank, save top 27 as
///      the new active list, **clear the votes store** (java-tron does
///      this so the next cycle starts fresh).
///   3. **Legacy `IncentiveManager.reward`** (only when
///      `ALLOW_CHANGE_DELEGATION == 0`): distribute
///      `WITNESS_STANDBY_ALLOWANCE` proportionally across the new
///      top-127 by vote_count. Mainnet has the flag on, so this is a
///      compat path.
///   4. **`isJobs` flip**: every active witness has `is_jobs = true`;
///      witnesses leaving the active list flip to `false`. java-tron
///      reads this flag for monitoring; we mirror.
///   5. **Cycle advance** (only when `ALLOW_CHANGE_DELEGATION == 1`):
///      `current_cycle_number += 1`, then snapshot
///      `delegation.brokerage(next_cycle, w) = brokerage_global(w)`
///      and `delegation.witness_vote(next_cycle, w) = w.vote_count`
///      for every witness — the baselines the next cycle will Vi-
///      accumulate against.
///
/// **Iteration note**: java-tron walks RocksDB iterators directly. We
/// use [`VotesStore::all`] / [`WitnessStore::all`] which call
/// `scan_all()` on the underlying KvBackend. Both stores stay small
/// (hundreds of voters, ~150 candidate witnesses on mainnet); the
/// full scan runs O(maintenance-period) — every 6 hours — and is not
/// in the hot path.
#[allow(clippy::too_many_arguments)]
pub fn apply_maintenance(
    witnesses: &WitnessStore,
    votes: &VotesStore,
    schedule: &WitnessScheduleStore,
    accounts: &AccountStore,
    delegation: &DelegationStore,
    dyn_props: &DynamicPropertiesStore,
) -> Result<MaintenanceOutcome, tron_chainbase::StoreError> {
    let allow_change_delegation = dyn_props.allow_change_delegation();
    let mut vi_accumulated_count = 0usize;

    // ── Step 1: Vi accumulation against the JUST-ENDED cycle's reward pool.
    if allow_change_delegation {
        let cur_cycle = dyn_props.current_cycle_number();
        for (addr, witness) in witnesses.all()? {
            accumulate_witness_vi(delegation, cur_cycle, &addr, witness.vote_count);
            vi_accumulated_count += 1;
        }
    }

    // ── Step 2: vote tally + SR re-rank.
    let all_votes = votes.all()?;
    let voters: Vec<Address> = all_votes.iter().map(|(a, _)| *a).collect();
    let candidate_witnesses: Vec<Address> = witnesses
        .all()?
        .into_iter()
        .map(|(a, _)| a)
        .collect();
    let prev_active = schedule.load_active()?.unwrap_or_default();
    let report = update_active_witnesses(
        witnesses,
        votes,
        schedule,
        &voters,
        &candidate_witnesses,
    )?;
    // Clear the votes store so the next cycle starts fresh.
    for (voter, _) in &all_votes {
        votes.delete(voter)?;
    }

    // ── Step 3: legacy IncentiveManager.reward (only when flag off).
    if !allow_change_delegation {
        // Top 127 by vote_count.
        let mut by_vote: Vec<(Address, i64)> = witnesses
            .all()?
            .into_iter()
            .map(|(addr, w)| (addr, w.vote_count))
            .collect();
        by_vote.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.as_bytes().cmp(b.0.as_bytes())));
        const STANDBY_LEN: usize = 127;
        by_vote.truncate(STANDBY_LEN);
        let vote_sum: i64 = by_vote.iter().map(|(_, v)| *v).sum();
        if vote_sum > 0 {
            let total_pay = dyn_props.witness_standby_allowance();
            let each_vote_pay = total_pay as f64 / vote_sum as f64;
            for (addr, vc) in &by_vote {
                let pay = (*vc as f64 * each_vote_pay) as i64;
                if pay <= 0 {
                    continue;
                }
                if let Some(mut acct) = accounts.get(addr)? {
                    acct.allowance = acct.allowance.saturating_add(pay);
                    accounts.put(addr, &acct)?;
                }
            }
        }
    }

    // ── Step 4: isJobs flip — mirror java-tron's MaintenanceManager line 134.
    let prev_set: std::collections::HashSet<_> = prev_active.iter().copied().collect();
    let new_set: std::collections::HashSet<_> = report.new_active.iter().copied().collect();
    if prev_set != new_set {
        for addr in prev_set.difference(&new_set) {
            if let Some(mut w) = witnesses.get(addr)? {
                w.is_jobs = false;
                witnesses.put(addr, &w)?;
            }
        }
        for addr in new_set.difference(&prev_set) {
            if let Some(mut w) = witnesses.get(addr)? {
                w.is_jobs = true;
                witnesses.put(addr, &w)?;
            }
        }
    }

    // ── Step 5: advance cycle + snapshot brokerage/vote for next cycle.
    let new_cycle = if allow_change_delegation {
        let cur = dyn_props.current_cycle_number();
        let next = cur + 1;
        dyn_props.save_current_cycle_number(next);
        for (addr, w) in witnesses.all()? {
            let brokerage_global = delegation.get_brokerage_global(&addr);
            // java-tron seeds DEFAULT_BROKERAGE (20%) on first read;
            // mirror that. The global brokerage is set by SR config;
            // the per-cycle brokerage is what reward calc reads.
            let brokerage_for_cycle = if brokerage_global == 0 {
                tron_chainbase::DEFAULT_BROKERAGE
            } else {
                brokerage_global
            };
            delegation.set_brokerage(next, &addr, brokerage_for_cycle);
            delegation.set_witness_vote(next, &addr, w.vote_count);
        }
        // java-tron keeps the previous SR set in `MaintenanceManager`
        // (in-memory `getBeforeWitness()` / `getCurrentWitness()`),
        // NOT in `WitnessScheduleStore`. PBFT here uses the current
        // active list only; cross-rotation messages signed by the old
        // set will be rejected during the brief post-maintenance
        // window. Matching java-tron persistent-state shape exactly
        // means we don't snapshot per-cycle SR lists in this store.
        next
    } else {
        dyn_props.current_cycle_number()
    };

    Ok(MaintenanceOutcome {
        prev_active,
        new_active: report.new_active,
        changed: report.changed,
        new_cycle,
        vi_accumulated_count,
    })
}

// =============================================================================
// Vi-accumulator step (inline to avoid pulling tron-tvm into tron-consensus)
// =============================================================================

/// `1e18` — the `Decimal` constant from java-tron's reward algorithm.
const REWARD_VI_DECIMAL: i128 = 1_000_000_000_000_000_000;

/// Roll the current cycle's reward pool for `witness` into its Vi
/// (vote-index) and persist. Mirrors `DelegationStore.accumulateWitnessVi`:
///
/// ```text
/// pre_vi = get_witness_vi(cycle - 1, address)
/// reward = get_reward(cycle, address)
/// if reward == 0 || vote_count == 0:
///     if pre_vi != 0: set_witness_vi(cycle, address, pre_vi)
/// else:
///     delta = reward * 1e18 / vote_count
///     set_witness_vi(cycle, address, pre_vi + delta)
/// ```
///
/// The Vi values are stored as Java `BigInteger.toByteArray()` —
/// signed two's-complement big-endian, minimum-length representation.
fn accumulate_witness_vi(
    delegation: &DelegationStore,
    cycle: i64,
    witness: &Address,
    vote_count: i64,
) {
    let pre_vi = read_vi(delegation, cycle - 1, witness);
    let reward = delegation.get_reward(cycle, witness);
    if reward == 0 || vote_count == 0 {
        if pre_vi != 0 {
            delegation.set_witness_vi_raw(cycle, witness, &encode_signed_be(pre_vi));
        }
        return;
    }
    let delta = (reward as i128).saturating_mul(REWARD_VI_DECIMAL) / (vote_count as i128);
    let new_vi = pre_vi.saturating_add(delta);
    delegation.set_witness_vi_raw(cycle, witness, &encode_signed_be(new_vi));
}

fn read_vi(delegation: &DelegationStore, cycle: i64, witness: &Address) -> i128 {
    let Some(bytes) = delegation.get_witness_vi_raw(cycle, witness) else {
        return 0;
    };
    decode_signed_be_i128(&bytes)
}

/// Decode Java `BigInteger.toByteArray()` form — signed BE, variable
/// length, smallest representation — into an i128. Saturates on
/// overflow. Mirrors `tron_tvm::reward::decode_signed_be_i128`.
fn decode_signed_be_i128(bytes: &[u8]) -> i128 {
    if bytes.is_empty() {
        return 0;
    }
    let is_negative = bytes[0] & 0x80 != 0;
    if bytes.len() > 16 {
        return if is_negative { i128::MIN } else { i128::MAX };
    }
    let mut buf = if is_negative { [0xffu8; 16] } else { [0u8; 16] };
    let start = 16 - bytes.len();
    buf[start..].copy_from_slice(bytes);
    i128::from_be_bytes(buf)
}

/// Encode an i128 in Java `BigInteger.toByteArray()` form. Mirrors
/// `tron_tvm::reward::encode_signed_be`.
fn encode_signed_be(v: i128) -> Vec<u8> {
    if v == 0 {
        return vec![0];
    }
    let bytes = v.to_be_bytes();
    let mut start = 0;
    if v < 0 {
        while start < 15 && bytes[start] == 0xff && (bytes[start + 1] & 0x80 != 0) {
            start += 1;
        }
    } else {
        while start < 15 && bytes[start] == 0x00 && (bytes[start + 1] & 0x80 == 0) {
            start += 1;
        }
    }
    bytes[start..].to_vec()
}
