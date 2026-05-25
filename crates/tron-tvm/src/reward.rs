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
    AccountStore, DelegationStore, DynamicPropertiesStore, StoreError,
};
use tron_crypto::address::Address;

/// `1e18` — the `Decimal` constant from java-tron's reward algorithm.
pub const REWARD_VI_DECIMAL: i128 = 1_000_000_000_000_000_000;

/// `CURRENT_CYCLE_NUMBER` key in DynamicPropertiesStore.
pub const CURRENT_CYCLE_NUMBER_KEY: &[u8] = b"CURRENT_CYCLE_NUMBER";

/// `ALLOW_CHANGE_DELEGATION` key in DynamicPropertiesStore.
pub const ALLOW_CHANGE_DELEGATION_KEY: &[u8] = b"ALLOW_CHANGE_DELEGATION";

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
    let brokerage_amount = (value as i128 * brokerage as i128 / 100) as i64;
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
    accounts.put(address, &account);
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
}

/// Compute `MortgageService.queryReward(voter)` against the live stores.
///
/// Reads:
/// * `accounts.get(voter)` → votes list + allowance
/// * `delegation.get_begin_cycle` / `get_end_cycle`
/// * `delegation.get_witness_vi_raw(cycle, witness)` for each `(cycle,
///   witness)` window
/// * `dyn_props.get_long(CURRENT_CYCLE_NUMBER)`
///
/// Returns `0` for accounts with no votes (matches java-tron: they have
/// no claim on cycle-emitted rewards). The terminal cycle range walked
/// is `[begin_cycle, end_cycle)`; for the "current cycle" partial reward
/// the simple short-circuit matches java-tron's pre-`ALLOW_NEW_RESOURCE_MODEL`
/// behavior.
pub fn query_reward(
    voter: &Address,
    accounts: &AccountStore,
    delegation: &DelegationStore,
    dyn_props: &DynamicPropertiesStore,
) -> Result<i64, StoreError> {
    let Some(account) = accounts.get(voter)? else {
        return Ok(0);
    };
    let allowance = account.allowance;

    if account.votes.is_empty() {
        return Ok(allowance);
    }

    let begin_cycle = delegation.get_begin_cycle(voter);
    let end_cycle = delegation.get_end_cycle(voter);

    // No cycles to walk → just whatever's already finalized in allowance.
    if begin_cycle >= end_cycle {
        return Ok(allowance);
    }

    // Vi delta from `begin_cycle - 1` to `end_cycle - 1` per witness.
    // For each vote: vote_count * (Vi_end - Vi_begin) / DECIMAL.
    let mut reward: i128 = 0;
    for vote in &account.votes {
        if vote.vote_address.len() != 21 {
            continue;
        }
        let mut buf = [0u8; 21];
        buf.copy_from_slice(&vote.vote_address);
        let witness = Address::from_raw(buf);

        let vi_end = read_vi(delegation, end_cycle - 1, &witness);
        let vi_begin = read_vi(delegation, begin_cycle - 1, &witness);
        let delta = vi_end - vi_begin;

        // i128 math; saturate at i64 on the way out.
        let contribution = (delta as i128).saturating_mul(vote.vote_count as i128) / REWARD_VI_DECIMAL;
        reward = reward.saturating_add(contribution);
    }

    // ====================================================================
    // Partial current-cycle reward
    // ====================================================================
    //
    // If the voter has voted in `current_cycle` but the cycle isn't
    // finalised yet (no Vi has been written for `current_cycle`), they
    // still earn a partial reward up to NOW based on the witness's
    // current `vote_count` share.
    //
    // java-tron's `MortgageService.queryReward` extends the loop by one
    // more step: `Vi(current_cycle) - Vi(end_cycle - 1)` if the voter
    // has an entry in `delegation.account_vote(current_cycle, voter)`.
    // We mirror that here when the cycle keys are present.
    let current_cycle = dyn_props.get_long(CURRENT_CYCLE_NUMBER_KEY).unwrap_or(0);
    if current_cycle >= end_cycle {
        // Was the voter active in the most recent cycle window? java-tron
        // reads `delegation.account_vote(current_cycle, voter)`. If
        // present, the voter participates in the current-cycle reward.
        if delegation.get_account_vote(current_cycle, voter)?.is_some() {
            for vote in &account.votes {
                if vote.vote_address.len() != 21 {
                    continue;
                }
                let mut buf = [0u8; 21];
                buf.copy_from_slice(&vote.vote_address);
                let witness = Address::from_raw(buf);
                let vi_now = read_vi(delegation, current_cycle, &witness);
                let vi_ref = read_vi(delegation, end_cycle - 1, &witness);
                let delta = vi_now - vi_ref;
                let contribution =
                    delta.saturating_mul(vote.vote_count as i128) / REWARD_VI_DECIMAL;
                reward = reward.saturating_add(contribution);
            }
        }
    }

    let total = reward.saturating_add(allowance as i128);
    Ok(total.min(i64::MAX as i128).max(0) as i64)
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
) -> Result<i64, StoreError> {
    use tron_proto::Account;

    if dyn_props.get_long(b"ALLOW_CHANGE_DELEGATION").unwrap_or(0) == 0 {
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
            let reward_one = reward_for_window(&snap, delegation, begin_cycle, end_cycle);
            paid = paid.saturating_add(reward_one);
            begin_cycle += 1;
        }
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
            accounts.put(address, &account);
        }
        return Ok(paid);
    }

    if begin_cycle < end_cycle {
        let reward_bulk = reward_for_window(&account, delegation, begin_cycle, end_cycle);
        paid = paid.saturating_add(reward_bulk);
    }

    // ── 3. Apply allowance + record this cycle's snapshot ──────────────
    if paid > 0 {
        account.allowance = account.allowance.saturating_add(paid);
        accounts.put(address, &account);
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
    delegation.set_account_vote(end_cycle, address, &snapshot);

    Ok(paid)
}

/// Pure helper: sum rewards across `[begin_cycle, end_cycle)` for the
/// votes in `account` using `Vi(end-1) - Vi(begin-1)` per witness. Used
/// by both the catch-up and bulk paths of `withdraw_reward`.
fn reward_for_window(
    account: &tron_proto::Account,
    delegation: &DelegationStore,
    begin_cycle: i64,
    end_cycle: i64,
) -> i64 {
    if begin_cycle >= end_cycle {
        return 0;
    }
    let mut total: i128 = 0;
    for vote in &account.votes {
        if vote.vote_address.len() != 21 {
            continue;
        }
        let mut buf = [0u8; 21];
        buf.copy_from_slice(&vote.vote_address);
        let witness = Address::from_raw(buf);
        let vi_end = read_vi(delegation, end_cycle - 1, &witness);
        let vi_begin = read_vi(delegation, begin_cycle - 1, &witness);
        let delta = vi_end - vi_begin;
        let contribution = delta.saturating_mul(vote.vote_count as i128) / REWARD_VI_DECIMAL;
        total = total.saturating_add(contribution);
    }
    total.min(i64::MAX as i128).max(0) as i64
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
