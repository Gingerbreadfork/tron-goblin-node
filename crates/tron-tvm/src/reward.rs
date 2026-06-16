//! Reward computation (the Vi-accumulator algorithm).
//!
//! Mirrors java-tron's `MortgageService.queryReward`. The Vi (Vote-index)
//! accumulator is a running per-witness, per-cycle counter that
//! represents the cumulative reward share per vote unit. The amount a
//! voter has earned between cycle `a` and cycle `b` for witness `W` is:
//!
//! ```text
//! reward = vote_count * (Vi(b - 1, W) - Vi(a - 1, W)) / DECIMAL
//! ```
//!
//! where `DECIMAL = 10^18` (pinned by java-tron's `Decimal` constant).
//! Vi values are stored as variable-length two's-complement big-endian
//! bytes — Java `BigInteger.toByteArray()`. We decode with [`i128`] for
//! the common case; larger values fall back to `i64::MAX` (deliberate:
//! a Vi that overflows i128 would mean ~3.4×10^38 reward, which is far
//! beyond any plausible TRON state).

use tron_chainbase::{
    AccountStore, DelegationStore, DynamicPropertiesStore, RewardViStore, StoreError,
};
use tron_crypto::address::Address;

/// `1e18` — the `Decimal` constant from java-tron's reward algorithm.
pub const REWARD_VI_DECIMAL: i128 = 1_000_000_000_000_000_000;

/// `CURRENT_CYCLE_NUMBER` key in DynamicPropertiesStore.
pub const CURRENT_CYCLE_NUMBER_KEY: &[u8] = b"CURRENT_CYCLE_NUMBER";

/// Change-delegation flag key. java's on-disk key is `CHANGE_DELEGATION`
/// (no `ALLOW_` prefix — a java naming quirk; see the chainbase keys doc).
pub const ALLOW_CHANGE_DELEGATION_KEY: &[u8] = b"CHANGE_DELEGATION";

/// First cycle the Vi-accumulator ("new reward") algorithm applies to.
/// Set once when `ALLOW_NEW_REWARD` / `ALLOW_TVM_VOTE` activated;
/// `i64::MAX` (java `Long.MAX_VALUE`) when the new algorithm was never
/// enabled. Cycles BEFORE this use the legacy per-cycle ratio math —
/// see [`old_reward`].
pub const NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE_KEY: &[u8] =
    b"NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE";

/// Proposal #79. When on, legacy-cycle rewards are served from the
/// background-computed `reward-vi` store (java's `RewardViCalService`,
/// merkle-pinned) instead of the O(cycles) per-cycle ratio loop.
pub const ALLOW_OLD_REWARD_OPT_KEY: &[u8] = b"ALLOW_OLD_REWARD_OPT";

// =============================================================================
// Per-block + per-maintenance reward distribution
// =============================================================================
//
// Mirrors java-tron's `MortgageService.payReward`, `payBlockReward`,
// `payTransactionFeeReward`, and `payStandbyWitness`. These are the
// WRITE side that produces the Vi-reward cycle pool that
// `query_reward` / `withdraw_reward` later consume.
//
// Flow:
//   apply_block: pay_block_reward(witness, WITNESS_PAY_PER_BLOCK)
//                pay_transaction_fee_reward(witness, total_tx_fees)
//                pay_standby_witness(top_127_active_witnesses)
//   apply_maintenance (cycle boundary):
//                accumulate_witness_vi(cycle, witness, vote_count) for every
//                witness, advancing the Vi numerator into the storable Vi.

/// Credit `witness_address` with the block-production reward (the
/// `WITNESS_PAY_PER_BLOCK` constant value). The brokerage cut goes
/// straight to the witness's `Account.allowance`; the remainder is
/// added to the cycle's reward pool (`DelegationStore::add_reward`).
pub fn pay_block_reward(
    accounts: &AccountStore,
    delegation: &DelegationStore,
    dyn_props: &DynamicPropertiesStore,
    witness_address: &Address,
    value: i64,
) -> Result<(), StoreError> {
    pay_reward_inner(accounts, delegation, dyn_props, witness_address, value)
}

/// Credit `witness_address` with the cumulative transaction-fee
/// reward for the block. Same brokerage / cycle-pool split as
/// [`pay_block_reward`].
pub fn pay_transaction_fee_reward(
    accounts: &AccountStore,
    delegation: &DelegationStore,
    dyn_props: &DynamicPropertiesStore,
    witness_address: &Address,
    value: i64,
) -> Result<(), StoreError> {
    pay_reward_inner(accounts, delegation, dyn_props, witness_address, value)
}

/// Distribute `WITNESS_127_PAY_PER_BLOCK` across the top-127 standby
/// witness set, proportionally to each witness's vote_count. Java-tron
/// calls this from every produced block (not just at maintenance).
///
/// `standby_set` must be the top 127 witnesses by vote_count (caller
/// computes this — typically `WitnessStore::all().sorted().take(127)`).
pub fn pay_standby_witness(
    accounts: &AccountStore,
    delegation: &DelegationStore,
    dyn_props: &DynamicPropertiesStore,
    standby_set: &[(Address, i64)],
) -> Result<(), StoreError> {
    let total_pay = dyn_props.witness_127_pay_per_block();
    if total_pay <= 0 {
        return Ok(());
    }
    let vote_sum: i64 = standby_set.iter().map(|(_, v)| *v).sum();
    if vote_sum < 1 {
        return Ok(());
    }
    // Java uses double division: `pay = vote_count * (totalPay / voteSum)`.
    // Match that EXACTLY (including rounding) so reward totals agree
    // bit-for-bit with java-tron.
    let each_vote_pay = total_pay as f64 / vote_sum as f64;
    for (addr, vote_count) in standby_set {
        let pay = (*vote_count as f64 * each_vote_pay) as i64;
        if pay > 0 {
            pay_reward_inner(accounts, delegation, dyn_props, addr, pay)?;
        }
    }
    Ok(())
}

/// Split `value` between the witness's brokerage allowance and the
/// cycle's voter-share pool, then persist both.
///
/// Steps (mirrors `MortgageService.payReward`):
///   1. brokerage = delegation.get_brokerage(cycle, witness) (% out of 100)
///   2. brokerage_amount = value * brokerage / 100 → into account.allowance
///   3. voter_share = value - brokerage_amount → into delegation.add_reward(cycle, witness)
/// The witness's brokerage cut of a `value` reward, as a percentage.
///
/// java-tron `MortgageService.payReward` computes this in IEEE-754 double:
/// `brokerageRate = (double) brokerage / 100; brokerageAmount = (long)
/// (brokerageRate * value)`. Integer `value * brokerage / 100` differs by 1 for
/// rates whose `/100` is not exactly representable in f64 (e.g. 29, 47, 70),
/// which would drift every voter payout and the witness allowance. Mirror
/// java's f64 path exactly.
fn brokerage_cut(value: i64, brokerage_pct: i64) -> i64 {
    ((brokerage_pct as f64 / 100.0) * value as f64) as i64
}

fn pay_reward_inner(
    accounts: &AccountStore,
    delegation: &DelegationStore,
    dyn_props: &DynamicPropertiesStore,
    witness_address: &Address,
    value: i64,
) -> Result<(), StoreError> {
    if value <= 0 {
        return Ok(());
    }
    let cycle = dyn_props.current_cycle_number();
    // Brokerage is a percentage (0..=100). Default value when no row
    // exists is 20 — matches java-tron's `DEFAULT_BROKERAGE`.
    let brokerage = delegation.get_brokerage(cycle, witness_address);
    let brokerage_amount = brokerage_cut(value, brokerage as i64);
    let voter_share = value.saturating_sub(brokerage_amount);
    // 1. Voter-share pool — adds to cycle's reward bucket.
    if voter_share > 0 {
        delegation.add_reward(cycle, witness_address, voter_share);
    }
    // 2. Brokerage — direct to the witness's account allowance.
    if brokerage_amount > 0 {
        adjust_allowance(accounts, witness_address, brokerage_amount)?;
    }
    Ok(())
}

/// Add `amount` (may be negative) to `address.allowance`. Saturates
/// at zero on negative balances (java-tron silently clamps too).
/// No-op if the account doesn't exist — matches java-tron's
/// `AccountStore.put(get(...).setAllowance(...))` which creates a
/// dangling row we'd rather avoid.
fn adjust_allowance(
    accounts: &AccountStore,
    address: &Address,
    amount: i64,
) -> Result<(), StoreError> {
    let Some(mut account) = accounts.get(address)? else {
        return Ok(());
    };
    account.allowance = account.allowance.saturating_add(amount).max(0);
    accounts.put(address, &account)?;
    Ok(())
}

/// Roll the current cycle's reward pool into a per-witness Vi
/// (vote-index) delta and persist `witness_vi(cycle, witness)`.
///
/// Mirrors `DelegationStore.accumulateWitnessVi(cycle, address, voteCount)`:
///   pre_vi = get_witness_vi(cycle - 1, address)
///   reward = get_reward(cycle, address)
///   if reward == 0 or vote_count == 0:
///       # No new reward to distribute this cycle — just forward
///       # pre_vi so future cycles see the running total.
///       if pre_vi != 0: set_witness_vi(cycle, address, pre_vi)
///   else:
///       delta_vi = reward * 1e18 / vote_count
///       set_witness_vi(cycle, address, pre_vi + delta_vi)
pub fn accumulate_witness_vi(
    delegation: &DelegationStore,
    cycle: i64,
    witness: &Address,
    vote_count: i64,
) {
    let pre_vi = read_vi(delegation, cycle - 1, witness);
    let reward = delegation.get_reward(cycle, witness);
    if reward == 0 || vote_count == 0 {
        if pre_vi != 0 {
            // Encode pre_vi back to BigInteger.toByteArray() form so
            // round-trip parity with java-tron is preserved.
            delegation.set_witness_vi_raw(cycle, witness, &encode_signed_be(pre_vi));
        }
        return;
    }
    let delta_vi = (reward as i128).saturating_mul(REWARD_VI_DECIMAL) / (vote_count as i128);
    let new_vi = pre_vi.saturating_add(delta_vi);
    delegation.set_witness_vi_raw(cycle, witness, &encode_signed_be(new_vi));
}

/// Encode an i128 to Java `BigInteger.toByteArray()` form: signed
/// two's-complement big-endian, **minimum-length** representation
/// (drop leading 0x00 bytes from positives, drop leading 0xFF bytes
/// from negatives, but never collapse the sign bit).
pub fn encode_signed_be(v: i128) -> Vec<u8> {
    if v == 0 {
        return vec![0];
    }
    let bytes = v.to_be_bytes();
    let is_negative = v < 0;
    let mut start = 0;
    if is_negative {
        // Strip leading 0xFF bytes, but keep at least one byte whose
        // top bit is set (preserve the sign).
        while start < 15 && bytes[start] == 0xff && (bytes[start + 1] & 0x80 != 0) {
            start += 1;
        }
    } else {
        // Strip leading 0x00 bytes, but keep at least one byte whose
        // top bit is clear (preserve the sign).
        while start < 15 && bytes[start] == 0x00 && (bytes[start + 1] & 0x80 == 0) {
            start += 1;
        }
    }
    bytes[start..].to_vec()
}

#[cfg(test)]
mod encode_tests {
    use super::*;

    #[test]
    fn encode_signed_be_round_trips_zero() {
        assert_eq!(encode_signed_be(0), vec![0]);
        assert_eq!(decode_signed_be_i128(&encode_signed_be(0)), 0);
    }

    #[test]
    fn encode_signed_be_round_trips_positives() {
        for v in [1i128, 127, 128, 255, 256, 65535, 1 << 32, i64::MAX as i128, i128::MAX] {
            assert_eq!(decode_signed_be_i128(&encode_signed_be(v)), v, "v={v}");
        }
    }

    #[test]
    fn encode_signed_be_round_trips_negatives() {
        for v in [-1i128, -128, -129, -256, -(1 << 32), i64::MIN as i128, i128::MIN] {
            assert_eq!(decode_signed_be_i128(&encode_signed_be(v)), v, "v={v}");
        }
    }

    #[test]
    fn encode_signed_be_is_minimum_length() {
        // 0 → [0]
        assert_eq!(encode_signed_be(0).len(), 1);
        // 1 → [0x01] (single byte; sign bit clear is fine since 1 is +)
        assert_eq!(encode_signed_be(1), vec![0x01]);
        // 127 → [0x7F]
        assert_eq!(encode_signed_be(127), vec![0x7f]);
        // 128 → [0x00, 0x80] (need leading zero so sign bit stays +)
        assert_eq!(encode_signed_be(128), vec![0x00, 0x80]);
        // -1 → [0xFF]
        assert_eq!(encode_signed_be(-1), vec![0xff]);
        // -128 → [0x80]
        assert_eq!(encode_signed_be(-128), vec![0x80]);
        // -129 → [0xFF, 0x7F]
        assert_eq!(encode_signed_be(-129), vec![0xff, 0x7f]);
    }

    #[test]
    fn brokerage_cut_matches_java_f64_not_integer_division() {
        // value=100, rate=29: java's f64 path = (long)(0.29 * 100). 0.29 is not
        // exactly representable, so the product lands just below 29.0 and
        // truncates to 28, while integer `100 * 29 / 100` yields 29. We must
        // match java (28) — over-crediting the witness by 1 would drift every
        // voter payout in that cycle.
        assert_eq!(brokerage_cut(100, 29), 28);
        assert_ne!(brokerage_cut(100, 29), 100 * 29 / 100);
        // Another divergent case (rate=57).
        assert_eq!(brokerage_cut(100, 57), 56);
        // Exactly-representable rates agree with integer division.
        assert_eq!(brokerage_cut(1_000_000, 20), 200_000);
        assert_eq!(brokerage_cut(1_000_000, 50), 500_000);
        // 0% and 100% boundaries.
        assert_eq!(brokerage_cut(123_456, 0), 0);
        assert_eq!(brokerage_cut(123_456, 100), 123_456);
    }
}

/// Compute `MortgageService.queryReward(voter)` against the live stores —
/// an exact port, including the legacy-algorithm branch:
///
/// 1. `0` when `ALLOW_CHANGE_DELEGATION` is off or the account is missing.
/// 2. `allowance` when `begin_cycle > current_cycle`.
/// 3. Latest-cycle catch-up: when `begin_cycle + 1 == end_cycle` and the
///    cycle has finalised, the single-cycle reward is computed against
///    the votes SNAPSHOT stored in `account_vote(begin_cycle)` (the votes
///    active when that cycle ran), then `begin_cycle += 1` (unconditional
///    — java increments even when no snapshot exists).
/// 4. `end_cycle = current_cycle`; empty live votes → `reward + allowance`.
/// 5. Bulk window `[begin_cycle, current_cycle)` against the live votes.
///
/// Each window goes through [`compute_reward_window`], which routes
/// pre-new-algorithm cycles to the legacy math (see [`old_reward`]).
///
/// `reward_vi` is the `reward-vi` store used by the `ALLOW_OLD_REWARD_OPT`
/// fast path; pass `None` only in contexts that never see pre-switch
/// accounts (the production node always wires it).
pub fn query_reward(
    voter: &Address,
    accounts: &AccountStore,
    delegation: &DelegationStore,
    dyn_props: &DynamicPropertiesStore,
    reward_vi: Option<&RewardViStore>,
) -> Result<i64, StoreError> {
    if dyn_props.get_long(ALLOW_CHANGE_DELEGATION_KEY).unwrap_or(0) == 0 {
        return Ok(0);
    }
    let Some(account) = accounts.get(voter)? else {
        return Ok(0);
    };
    let allowance = account.allowance;

    let mut begin_cycle = delegation.get_begin_cycle(voter);
    let mut end_cycle = delegation.get_end_cycle(voter);
    let current_cycle = dyn_props.get_long(CURRENT_CYCLE_NUMBER_KEY).unwrap_or(0);
    let mut reward: i64 = 0;

    if begin_cycle > current_cycle {
        return Ok(allowance);
    }
    // Latest-cycle catch-up — computed against the SNAPSHOT votes.
    if begin_cycle + 1 == end_cycle && begin_cycle < current_cycle {
        if let Some(snap) = delegation.get_account_vote(begin_cycle, voter)? {
            reward = compute_reward_window(
                begin_cycle,
                end_cycle,
                &snap.votes,
                delegation,
                dyn_props,
                reward_vi,
            );
        }
        begin_cycle += 1;
    }
    end_cycle = current_cycle;
    if account.votes.is_empty() {
        return Ok(reward.saturating_add(allowance));
    }
    if begin_cycle < end_cycle {
        reward = reward.saturating_add(compute_reward_window(
            begin_cycle,
            end_cycle,
            &account.votes,
            delegation,
            dyn_props,
            reward_vi,
        ));
    }
    Ok(reward.saturating_add(allowance))
}

/// `MortgageService.computeReward(beginCycle, endCycle, account)` — sum
/// the voter's reward across `[begin_cycle, end_cycle)`, routing cycles
/// before `NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE` through the legacy math
/// and the rest through the Vi-accumulator walk.
pub fn compute_reward_window(
    mut begin_cycle: i64,
    end_cycle: i64,
    votes: &[tron_proto::Vote],
    delegation: &DelegationStore,
    dyn_props: &DynamicPropertiesStore,
    reward_vi: Option<&RewardViStore>,
) -> i64 {
    if begin_cycle >= end_cycle {
        return 0;
    }
    let mut reward: i64 = 0;
    let new_algorithm_cycle = dyn_props
        .get_long(NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE_KEY)
        .unwrap_or(i64::MAX);
    if begin_cycle < new_algorithm_cycle {
        let old_end_cycle = end_cycle.min(new_algorithm_cycle);
        reward = old_reward(begin_cycle, old_end_cycle, votes, delegation, dyn_props, reward_vi);
        begin_cycle = old_end_cycle;
    }
    if begin_cycle < end_cycle {
        reward = reward.saturating_add(vi_window_reward(begin_cycle, end_cycle, votes, |cycle, witness| {
            read_vi(delegation, cycle, witness)
        }));
    }
    reward
}

/// The Vi-accumulator window: per witness,
/// `delta = Vi(end - 1) - Vi(begin - 1)`; non-positive deltas are
/// SKIPPED (java: `if (deltaVi.signum() <= 0) continue`), then
/// `delta * vote_count / 1e18` floor-divided like java's BigInteger.
fn vi_window_reward(
    begin_cycle: i64,
    end_cycle: i64,
    votes: &[tron_proto::Vote],
    read_vi_at: impl Fn(i64, &Address) -> i128,
) -> i64 {
    let mut reward: i64 = 0;
    for vote in votes {
        if vote.vote_address.len() != 21 {
            continue;
        }
        let mut buf = [0u8; 21];
        buf.copy_from_slice(&vote.vote_address);
        let witness = Address::from_raw(buf);
        let begin_vi = read_vi_at(begin_cycle - 1, &witness);
        let end_vi = read_vi_at(end_cycle - 1, &witness);
        let delta = end_vi - begin_vi;
        if delta <= 0 {
            continue;
        }
        let contribution = delta.saturating_mul(vote.vote_count as i128) / REWARD_VI_DECIMAL;
        reward = reward
            .saturating_add(contribution.clamp(i64::MIN as i128, i64::MAX as i128) as i64);
    }
    reward
}

/// `MortgageService.getOldReward` — rewards for cycles BEFORE the new
/// algorithm activated.
///
/// With `ALLOW_OLD_REWARD_OPT` (proposal #79) on AND the `reward-vi`
/// store available, the answer is a Vi walk over the background-computed
/// store (java's `RewardViCalService.getNewRewardAlgorithmReward` —
/// values merkle-pinned in java's config, present in any imported
/// mainnet DB). Otherwise the legacy O(cycles) loop: per cycle, per
/// vote, `reward += userVote/totalVote * totalReward` in `double` with
/// java's compound-assignment narrowing (the whole sum is computed in
/// `double` and truncated on every addition — replicated bit-for-bit).
fn old_reward(
    begin_cycle: i64,
    end_cycle: i64,
    votes: &[tron_proto::Vote],
    delegation: &DelegationStore,
    dyn_props: &DynamicPropertiesStore,
    reward_vi: Option<&RewardViStore>,
) -> i64 {
    if begin_cycle >= end_cycle {
        return 0;
    }
    if dyn_props.get_long(ALLOW_OLD_REWARD_OPT_KEY).unwrap_or(0) == 1 {
        if let Some(store) = reward_vi {
            return vi_window_reward(begin_cycle, end_cycle, votes, |cycle, witness| {
                match store.get(&DelegationStore::vi_key(cycle, witness)) {
                    Ok(Some(bytes)) => decode_signed_be_i128(&bytes),
                    _ => 0,
                }
            });
        }
        // Opt flag on but no store wired — fall through to the exact
        // legacy loop. Same values up to double-vs-BigInteger rounding;
        // production always wires the store so this branch is test-only.
    }
    let mut reward: i64 = 0;
    for cycle in begin_cycle..end_cycle {
        reward = old_reward_one_cycle(cycle, votes, delegation, reward);
    }
    reward
}

/// One legacy cycle: java's `computeReward(cycle, votes)` folded into the
/// running total with `long += double` semantics (`reward = (long)(reward
/// + voteRate * totalReward)` — the addition happens in `double`).
fn old_reward_one_cycle(
    cycle: i64,
    votes: &[tron_proto::Vote],
    delegation: &DelegationStore,
    mut reward: i64,
) -> i64 {
    use tron_chainbase::REMARK;
    for vote in votes {
        if vote.vote_address.len() != 21 {
            continue;
        }
        let mut buf = [0u8; 21];
        buf.copy_from_slice(&vote.vote_address);
        let witness = Address::from_raw(buf);
        let total_reward = delegation.get_reward(cycle, &witness);
        if total_reward <= 0 {
            continue;
        }
        let total_vote = delegation.get_witness_vote(cycle, &witness);
        if total_vote == REMARK || total_vote == 0 {
            continue;
        }
        let vote_rate = vote.vote_count as f64 / total_vote as f64;
        reward = (reward as f64 + vote_rate * total_reward as f64) as i64;
    }
    reward
}

/// Persist the reward claim — the write-side counterpart to
/// [`query_reward`]. Mirrors java-tron's `MortgageService.withdrawReward`
/// exactly:
///
/// 1. No-op if `ALLOW_CHANGE_DELEGATION` is disabled or the account
///    doesn't exist.
/// 2. No-op if `begin_cycle > current_cycle` (nothing to settle).
/// 3. No-op if `begin_cycle == current_cycle` AND the voter already has
///    an `account_vote(begin_cycle)` (they've already claimed this cycle).
/// 4. Latest-cycle catch-up: if `begin_cycle + 1 == end_cycle` and there's
///    a stored `account_vote(begin_cycle)`, pay out that single cycle's
///    reward using the *stored* account snapshot (not the current votes),
///    then advance `begin_cycle += 1`.
/// 5. Sum rewards for `[begin_cycle, current_cycle)` against the current
///    votes list and add to `account.allowance`.
/// 6. Final state writes: `begin_cycle = current_cycle`,
///    `end_cycle = current_cycle + 1`,
///    `account_vote(current_cycle, address) = account` — marking the
///    voter as participating in the next cycle's payout window.
///
/// Returns the amount paid out (added to allowance). 0 if nothing was
/// settled. The function is idempotent within a cycle — a second call
/// hits the early-return in step 3.
pub fn withdraw_reward(
    address: &Address,
    accounts: &AccountStore,
    delegation: &DelegationStore,
    dyn_props: &DynamicPropertiesStore,
    reward_vi: Option<&RewardViStore>,
) -> Result<i64, StoreError> {
    use tron_proto::Account;

    if dyn_props.get_long(ALLOW_CHANGE_DELEGATION_KEY).unwrap_or(0) == 0 {
        return Ok(0);
    }
    let Some(mut account) = accounts.get(address)? else {
        return Ok(0);
    };

    let mut begin_cycle = delegation.get_begin_cycle(address);
    let mut end_cycle = delegation.get_end_cycle(address);
    let current_cycle = dyn_props.get_long(CURRENT_CYCLE_NUMBER_KEY).unwrap_or(0);

    if begin_cycle > current_cycle {
        return Ok(0);
    }
    if begin_cycle == current_cycle
        && delegation.get_account_vote(begin_cycle, address)?.is_some()
    {
        return Ok(0);
    }

    let mut paid: i64 = 0;

    // ── 1. Latest-cycle catch-up ───────────────────────────────────────
    // If end_cycle is exactly one ahead of begin_cycle (the voter has
    // gone unpaid for a single finalised cycle), and the cycle has
    // already finalised (begin < current), pay it out using the snapshot
    // recorded in account_vote(begin_cycle) — that's the votes list
    // active at the time the cycle ran.
    if begin_cycle + 1 == end_cycle && begin_cycle < current_cycle {
        if let Some(snap) = delegation.get_account_vote(begin_cycle, address)? {
            let reward_one = compute_reward_window(
                begin_cycle,
                end_cycle,
                &snap.votes,
                delegation,
                dyn_props,
                reward_vi,
            );
            paid = paid.saturating_add(reward_one);
        }
        // java increments OUTSIDE the snapshot null-check — a voter with
        // no recorded snapshot still skips past the finalised cycle.
        begin_cycle += 1;
    }

    // ── 2. Bulk window [begin_cycle, current_cycle) ───────────────────
    end_cycle = current_cycle;
    if account.votes.is_empty() {
        // No live votes — fast-forward begin_cycle so the next call
        // doesn't re-walk this window. Note: end_cycle + 1 (NOT just
        // end_cycle) matches java-tron's behaviour for the no-votes
        // bail path; the empty-votes voter is "skipped" by a cycle so
        // they aren't constantly considered in the next iteration.
        delegation.set_begin_cycle(address, end_cycle + 1);
        if paid > 0 {
            account.allowance = account.allowance.saturating_add(paid);
            accounts.put(address, &account)?;
        }
        return Ok(paid);
    }

    if begin_cycle < end_cycle {
        let reward_bulk = compute_reward_window(
            begin_cycle,
            end_cycle,
            &account.votes,
            delegation,
            dyn_props,
            reward_vi,
        );
        paid = paid.saturating_add(reward_bulk);
    }

    // ── 3. Apply allowance + record this cycle's snapshot ──────────────
    if paid > 0 {
        account.allowance = account.allowance.saturating_add(paid);
        accounts.put(address, &account)?;
    }
    delegation.set_begin_cycle(address, end_cycle);
    delegation.set_end_cycle(address, end_cycle + 1);
    // Persist the current votes snapshot so the *next* withdraw can
    // pay out this cycle's reward against the same vote list. Only the
    // votes/address are read from this snapshot later (see step 1).
    let snapshot = Account {
        address: address.as_bytes().to_vec(),
        votes: account.votes.clone(),
        ..Default::default()
    };
    delegation.set_account_vote(end_cycle, address, &snapshot)?;

    Ok(paid)
}

/// Read the Vi-accumulator value for `(cycle, witness)` and decode it
/// as a signed i128. Missing rows are treated as zero. Vi is stored as
/// Java `BigInteger.toByteArray()`: signed two's-complement big-endian,
/// variable length, smallest representation.
fn read_vi(delegation: &DelegationStore, cycle: i64, witness: &Address) -> i128 {
    let Some(bytes) = delegation.get_witness_vi_raw(cycle, witness) else {
        return 0;
    };
    decode_signed_be_i128(&bytes)
}

/// Decode a Java `BigInteger.toByteArray()` to `i128`. Pads/truncates as
/// needed; saturates on overflow.
pub fn decode_signed_be_i128(bytes: &[u8]) -> i128 {
    if bytes.is_empty() {
        return 0;
    }
    let is_negative = bytes[0] & 0x80 != 0;
    let mut buf = if is_negative { [0xffu8; 16] } else { [0u8; 16] };

    if bytes.len() > 16 {
        // Saturate. For positive values use i128::MAX; for negatives use MIN.
        return if is_negative { i128::MIN } else { i128::MAX };
    }

    // Copy bytes into the low end (right-align).
    let start = 16 - bytes.len();
    buf[start..].copy_from_slice(bytes);
    i128::from_be_bytes(buf)
}
