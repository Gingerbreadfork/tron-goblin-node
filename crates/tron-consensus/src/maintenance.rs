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

use std::collections::{BTreeMap, HashMap};

use tron_chainbase::{
    AccountStore, AssetIssueStore, DelegationStore, DynamicPropertiesStore, VotesStore,
    WitnessScheduleStore, WitnessStore,
};
use tron_crypto::address::Address;

use crate::slot::MAX_ACTIVE_WITNESS_NUM;

/// Lowercase-hex encode, used only by the env-gated maintenance vote trace
/// (keeps the instrument self-contained without pulling `hex` into the lib).
fn votelog_hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Parse a `41…` (optionally `0x`-prefixed) hex address from the
/// `TRON_VOTELOG_TARGET` env var. Returns `None` on any malformed input.
fn votelog_hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.is_empty() || s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

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
/// * For each candidate, tally the NET vote delta across every voter's
///   [`tron_proto::Votes`] record: `Σ new_votes − Σ old_votes`
///   (java-tron's `MaintenanceManager.countVote`). `old_votes` is the
///   voter's vote list as it stood at its first vote-mutation of the
///   cycle, so subtracting it is what makes a re-vote net out to zero
///   and a vote-move debit the abandoned witness. Summing only
///   `new_votes` double-counts every re-vote and never reduces a
///   witness when votes move away or are cut by an unstake.
/// * Add those deltas to each `WitnessCapsule.vote_count` (accumulate;
///   do not replace).
/// * Sort by `vote_count desc`, breaking ties by java's `isSortOpt`-gated
///   rule (`allow_consensus_logic_optimization`), and take the top 27.
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
    allow_consensus_logic_optimization: bool,
) -> Result<MaintenanceReport, tron_chainbase::StoreError> {
    // 1. Tally NET vote deltas: `new_votes − old_votes` per voter record
    //    (java-tron's `countVote`). The old list is the voter's votes at
    //    its first mutation this cycle — already reflected in each
    //    witness's accumulated `vote_count` — so it must be debited or
    //    re-votes double-count and moved/reduced votes never come off.
    fn vote_addr(raw: &[u8]) -> Option<Address> {
        if raw.len() != tron_crypto::address::ADDRESS_LENGTH {
            return None;
        }
        let mut buf = [0u8; tron_crypto::address::ADDRESS_LENGTH];
        buf.copy_from_slice(raw);
        Some(Address::from_raw(buf))
    }
    // Divergence-hunt instrument (env-gated, inert in production): when
    // TRON_VOTELOG_TARGET names one or more `41…`-hex witness addresses,
    // emit every voter record's old/new contribution to those witnesses this
    // cycle. Paired with the per-maintenance countVote line the executor
    // emits under TRON_MAINT_VOTELOG, this isolates the exact voter whose
    // tally drifts from java-tron at a witness-schedule divergence.
    let votelog_targets: Vec<Vec<u8>> = std::env::var("TRON_VOTELOG_TARGET")
        .ok()
        .map(|s| s.split(',').filter_map(|h| votelog_hex_decode(h.trim())).collect())
        .unwrap_or_default();
    let mut deltas: HashMap<Address, i64> = HashMap::new();
    for voter in voters {
        let Some(record) = votes.get(voter)? else {
            continue;
        };
        for v in &record.old_votes {
            if let Some(witness_addr) = vote_addr(&v.vote_address) {
                *deltas.entry(witness_addr).or_insert(0) -= v.vote_count;
            }
        }
        for v in &record.new_votes {
            if let Some(witness_addr) = vote_addr(&v.vote_address) {
                *deltas.entry(witness_addr).or_insert(0) += v.vote_count;
            }
        }
        for t in &votelog_targets {
            let old: i64 = record
                .old_votes
                .iter()
                .filter(|v| v.vote_address == *t)
                .map(|v| v.vote_count)
                .sum();
            let new: i64 = record
                .new_votes
                .iter()
                .filter(|v| v.vote_address == *t)
                .map(|v| v.vote_count)
                .sum();
            if old != 0 || new != 0 {
                eprintln!(
                    "MAINTVOTE_VOTER voter={} witness={} old={} new={}",
                    votelog_hex_encode(voter.as_bytes()),
                    votelog_hex_encode(t),
                    old,
                    new
                );
            }
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

    // 3. Sort by vote_count desc, breaking ties exactly as java
    //    `WitnessStore.sortWitnesses(list, isSortOpt)`, where `isSortOpt` is
    //    `allowConsensusLogicOptimization` (proposal #88):
    //      * flag ON  — `createReadableString().reversed()`: the hex of the
    //        address DESCENDING, identical to address-bytes DESCENDING.
    //      * flag OFF — `ByteString.hashCode()` DESCENDING over the 21-byte
    //        address (see [`bytestring_hash_code`]).
    //    A snapshot taken after #88 only ever exercises the first arm, but a
    //    sync from genesis runs the second until #88 activates mid-chain — the
    //    two orderings disagree, so getting the gate right is what keeps the
    //    early-chain witness schedule in step with the network.
    ranked.sort_by(|a, b| {
        b.1.cmp(&a.1).then_with(|| {
            if allow_consensus_logic_optimization {
                b.0.as_bytes().cmp(a.0.as_bytes())
            } else {
                bytestring_hash_code(b.0.as_bytes()).cmp(&bytestring_hash_code(a.0.as_bytes()))
            }
        })
    });
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

/// Java protobuf `ByteString.hashCode()` over `bytes`, reproducing the
/// pre-`CONSENSUS_LOGIC_OPTIMIZATION` witness tie-break. Protobuf seeds the
/// accumulator with the byte length, folds in each byte as a *signed* `i8`
/// under 32-bit `int` wraparound (`h = h * 31 + b`), and maps a zero result to
/// `1`. The witness address is hashed in its 21-byte `0x41`-prefixed form, the
/// same bytes java's `WitnessCapsule.getAddress()` carries.
pub fn bytestring_hash_code(bytes: &[u8]) -> i32 {
    let mut h = bytes.len() as i32;
    for &b in bytes {
        h = h.wrapping_mul(31).wrapping_add(b as i8 as i32);
    }
    if h == 0 {
        1
    } else {
        h
    }
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
///   2. **Vote tally + SR re-rank**: scan every voter's record, apply
///      the net `new_votes − old_votes` delta to per-witness vote
///      counts, re-rank, save top 27 as the new active list, **clear
///      the votes store** (java-tron does this so the next cycle
///      starts fresh).
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

    // ── Step 0: strip the genesis Super-Representative bootstrap votes once
    //    the REMOVE_THE_POWER_OF_THE_GR proposal has armed the flag. java
    //    runs this as the very first action of `doMaintenance`
    //    (MaintenanceManager line 91), before Vi accumulation and the vote
    //    tally, so the de-boosted vote counts feed the same-cycle re-rank.
    try_remove_the_power_of_the_gr(witnesses, dyn_props)?;

    // java `MaintenanceManager.doMaintenance` gates Vi accumulation on
    // `useNewRewardAlgorithm()` (NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE set by
    // proposal 59/67), NOT `allowChangeDelegation`. The two coincide on a
    // long-active mainnet but diverge in the window between the two flags'
    // activations on a from-genesis re-sync, where gating on the wrong flag
    // would accumulate per-cycle Vi values java never wrote (perturbing
    // new-algorithm rewards for voters whose window spans the switch). The
    // cycle-advance/brokerage snapshot below stays on `allowChangeDelegation`,
    // matching java line 151.
    let use_new_reward_algorithm = dyn_props
        .get_long(b"NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE")
        .unwrap_or(i64::MAX)
        != i64::MAX;
    let mut vi_accumulated_count = 0usize;

    // ── Step 1: Vi accumulation against the JUST-ENDED cycle's reward pool.
    if use_new_reward_algorithm {
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

    // java-tron `MaintenanceManager.doMaintenance` (lines 102-149) wraps the
    // entire `updateWitness` + `incentiveManager.reward` + `isJobs` flip block
    // in `if (!countWitness.isEmpty())`. `countWitness` is this cycle's vote
    // tally (`countVote`), which inserts a key for EVERY vote entry across
    // every voter's `old_votes` / `new_votes` — so it is empty iff no voter
    // record carried any vote entry at all. When it is empty java touches
    // NOTHING: no vote-count accumulation, no re-rank, no `save_active`, no
    // reward payout, no `isJobs` flip — the persisted active list is left
    // exactly as the previous cycle wrote it. We must do the same, or a
    // zero-vote-mutation cycle would re-rank/persist (and, on the legacy path,
    // pay rewards) where java is a no-op. The vote-store clear, the Vi
    // accumulation (Step 1) and the cycle-advance / brokerage snapshot (Step 5)
    // stay OUTSIDE the gate, matching java (lines 95-100 and 151-159 sit
    // outside the `if`, and the iterator in `countVote` deletes as it walks).
    let count_witness_empty = all_votes
        .iter()
        .all(|(_, v)| v.old_votes.is_empty() && v.new_votes.is_empty());

    let report = if count_witness_empty {
        // No vote mutations this cycle — leave the active list untouched.
        MaintenanceReport {
            new_active: prev_active.clone(),
            changed: false,
            vote_deltas: Vec::new(),
        }
    } else {
        update_active_witnesses(
            witnesses,
            votes,
            schedule,
            &voters,
            &candidate_witnesses,
            dyn_props.allow_consensus_logic_optimization(),
        )?
    };
    // Clear the votes store so the next cycle starts fresh. java-tron clears
    // unconditionally — `countVote`'s iterator deletes every record as it
    // walks, regardless of whether the tally ends up empty.
    for (voter, _) in &all_votes {
        votes.delete(voter)?;
    }

    // ── Step 3: legacy IncentiveManager.reward (only when flag off).
    //    Gated on a non-empty vote tally to mirror java's `if (!countWitness
    //    .isEmpty())` wrapper around `incentiveManager.reward`.
    if !allow_change_delegation && !count_witness_empty {
        // java `MaintenanceManager` builds `newWitnessAddressList` from
        // `getAllWitnesses()` (address order), but then calls
        // `dposService.updateWitness(newWitnessAddressList)`, which runs
        // `consensusDelegate.sortWitness(list)` — sorting that SAME list object
        // IN-PLACE by vote_count DESC (with the `isSortOpt`/#88-gated tie-break).
        // It then passes the now-vote-sorted list to
        // `incentiveManager.reward`, which takes `subList(0,
        // WITNESS_STANDBY_LENGTH=127)`. So the standby-reward set is the TOP 127
        // BY VOTE_COUNT (the same ranking as the active SR list), NOT the
        // address-ordered store iteration. We must sort identically to
        // [`update_active_witnesses`] before taking the first 127, or a
        // high-address standby SR with enough votes is starved of allowance
        // while a low-address one is overpaid. That starvation compounds for a
        // self-voting witness — no reward → no extra stake → no extra self-vote
        // → still no reward — so its stake/votes drift far below mainnet over
        // many cycles (root of the 2,586,234 schedule divergence). `reward` then
        // sums the subset's `getVoteCount()` into `voteSum`, returns early on
        // `voteSum <= 0`, and pays each `(long)(voteCount * ((double) totalPay /
        // voteSum))` into `allowance` unconditionally (no `pay > 0` skip).
        let mut ranked: Vec<(Address, i64)> = witnesses
            .all()?
            .into_iter()
            .map(|(addr, w)| (addr, w.vote_count))
            .collect();
        let sort_opt = dyn_props.allow_consensus_logic_optimization();
        ranked.sort_by(|a, b| {
            b.1.cmp(&a.1).then_with(|| {
                if sort_opt {
                    b.0.as_bytes().cmp(a.0.as_bytes())
                } else {
                    bytestring_hash_code(b.0.as_bytes()).cmp(&bytestring_hash_code(a.0.as_bytes()))
                }
            })
        });
        const STANDBY_LEN: usize = 127;
        let subset = &ranked[..ranked.len().min(STANDBY_LEN)];
        let vote_sum: i64 = subset.iter().map(|(_, v)| *v).sum();
        if vote_sum > 0 {
            let total_pay = dyn_props.witness_standby_allowance();
            let each_vote_pay = total_pay as f64 / vote_sum as f64;
            for (addr, vc) in subset {
                // java: `(long)(voteCount * ((double) totalPay / voteSum))`,
                // credited even when it rounds to 0 (java has no skip and
                // `setAllowance` is always called).
                let pay = (*vc as f64 * each_vote_pay) as i64;
                if let Some(mut acct) = accounts.get(addr)? {
                    acct.allowance = acct.allowance.saturating_add(pay);
                    accounts.put(addr, &acct)?;
                }
            }
        }
    }

    // ── Step 4: isJobs flip — mirror java-tron's MaintenanceManager line 134.
    //    Inside the same `!countWitness.isEmpty()` wrapper as Step 2/3.
    if !count_witness_empty {
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
    }

    // ── Step 5: advance cycle + snapshot brokerage/vote for next cycle.
    let new_cycle = if allow_change_delegation {
        let cur = dyn_props.current_cycle_number();
        let next = cur + 1;
        dyn_props.save_current_cycle_number(next);
        for (addr, w) in witnesses.all()? {
            // java-tron (MaintenanceManager): propagate the SR-configured
            // global brokerage (cycle = -1) verbatim into the next cycle:
            //   setBrokerage(nextCycle, w, getBrokerage(w))
            // `get_brokerage_global` already returns DEFAULT_BROKERAGE (20%)
            // when no row exists, and the stored value otherwise — including
            // a deliberate 0% (SR gives 100% of rewards to voters). We must
            // NOT rewrite 0 → 20: doing so credited such SRs 20% of every
            // cycle's reward into `allowance`, where java credits nothing.
            let brokerage_for_cycle = delegation.get_brokerage_global(&addr);
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
// Genesis-SR power removal
// =============================================================================

/// `REMOVE_THE_POWER_OF_THE_GR` dynamic-property key — mirrors java-tron's
/// `DynamicPropertiesStore.REMOVE_THE_POWER_OF_THE_GR` byte literal.
const REMOVE_THE_POWER_OF_THE_GR: &[u8] = b"REMOVE_THE_POWER_OF_THE_GR";

/// Cancel the artificial bootstrap votes the 27 genesis Super
/// Representatives were seeded with at block 0.
///
/// Mirrors `MaintenanceManager.tryRemoveThePowerOfTheGr`: when the
/// `REMOVE_THE_POWER_OF_THE_GR` flag is exactly `1` (armed by an approved
/// proposal #10 — see `proposals::activate_expired_proposals`), subtract
/// each genesis witness's original `vote_count` from its accumulated total
/// and then mark the flag spent (`-1`) so it never fires again.
///
/// The genesis vote counts come from [`tron_types::mainnet_witnesses`] —
/// the same `config.conf` table used to seed the witnesses at genesis, so
/// the subtraction exactly undoes the seed. java reads them from
/// `dposService.getGenesisBlock().getWitnesses()`, which is the parsed
/// `genesis.block.witnesses` config.
///
/// Lifecycle of the flag:
///   * genesis init  → `0` (DynamicPropertiesStore default).
///   * proposal #10 approved → `1` (write guarded on the prior value being
///     `0`, see `proposals.rs`).
///   * first maintenance after arming → this function debits the votes and
///     writes `-1`.
/// Any other stored value (`0`, `-1`, or absent) is a no-op.
///
/// On a from-genesis re-sync this fires once, at the historical maintenance
/// after proposal #10 passed. When booting from a post-removal snapshot the
/// flag is already `-1`, so this is a no-op.
fn try_remove_the_power_of_the_gr(
    witnesses: &WitnessStore,
    dyn_props: &DynamicPropertiesStore,
) -> Result<(), tron_chainbase::StoreError> {
    if dyn_props.get_long(REMOVE_THE_POWER_OF_THE_GR) != Some(1) {
        return Ok(());
    }
    for gr in tron_types::mainnet_witnesses() {
        let addr = Address::from_raw(gr.address);
        if let Some(mut witness) = witnesses.get(&addr)? {
            witness.vote_count = witness.vote_count.saturating_sub(gr.vote_count);
            witnesses.put(&addr, &witness)?;
        }
    }
    dyn_props.put_long(REMOVE_THE_POWER_OF_THE_GR, -1);
    Ok(())
}

/// Reconstruct every account's id-keyed `asset_v2` map from its name-keyed
/// `asset` map at the `ALLOW_SAME_TOKEN_NAME` activation.
///
/// At `ALLOW_SAME_TOKEN_NAME == 0` java keeps `asset_v2[id] == asset[name]`: its
/// TRC-10 actuators dual-write the same V1-derived total to both maps. The flip
/// then switches balance reads from `asset[name]` to `asset_v2[id]`
/// (`AccountCapsule.getAsset`). java carries no migration here — it relies on the
/// V2 map having been kept in lock-step all along.
///
/// Rebuilding the V2 view from the consensus-correct V1 balances yields the exact
/// map java holds at the flip, so a node whose flag=0 `asset_v2` drifted — e.g. an
/// existing sync built before the dual-write was added — reaches the activation
/// byte-identical to java without re-syncing from genesis. It is **idempotent**:
/// a node that dual-wrote every flag=0 op already matches the reconstruction and
/// rewrites nothing. The caller runs it once, in the same maintenance pass that
/// sets the flag, before any flag=1 balance read. Returns the accounts rewritten.
///
/// `asset_v1` (the name-keyed `AssetIssueStore`) resolves each token name to its
/// id; at flag=0 names are unique, so the mapping is unambiguous.
pub fn rebuild_asset_v2_from_v1(
    accounts: &AccountStore,
    asset_v1: &AssetIssueStore,
) -> Result<usize, tron_chainbase::StoreError> {
    let mut rewritten = 0usize;
    for (addr, mut account) in accounts.all()? {
        if account.asset.is_empty() {
            continue;
        }
        let mut v2 = BTreeMap::new();
        for (name, &balance) in &account.asset {
            if let Some(c) = asset_v1.get(name.as_bytes())? {
                if !c.id.is_empty() {
                    v2.insert(c.id, balance);
                }
            }
        }
        if account.asset_v2 != v2 {
            account.asset_v2 = v2;
            accounts.put(&addr, &account)?;
            rewritten += 1;
        }
    }
    Ok(rewritten)
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
