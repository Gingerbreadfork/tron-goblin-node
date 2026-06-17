//! Tests for the Vi-accumulator reward computation.

use std::sync::Arc;

use tron_chainbase::{
    AccountStore, DelegationStore, DynamicPropertiesStore, KvBackend, MemBackend,
};
use tron_crypto::address::Address;
use tron_proto::{Account, Vote};
use tron_tvm::reward::{
    decode_signed_be_i128, query_reward, query_reward_actuator, query_reward_tvm, withdraw_reward,
    withdraw_reward_actuator, withdraw_reward_tvm, ALLOW_CHANGE_DELEGATION_KEY, ALLOW_OLD_REWARD_OPT_KEY,
    ALLOW_TVM_VOTE_KEY, CURRENT_CYCLE_NUMBER_KEY, NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE_KEY,
    REWARD_VI_DECIMAL,
};

/// Arm the gates `query_reward`/`withdraw_reward` consult, mirroring a
/// post-upgrade mainnet DB: change-delegation on, the Vi (new) reward
/// algorithm effective since cycle 0, and the chain at `current_cycle`.
fn arm_reward_state(dp: &DynamicPropertiesStore, current_cycle: i64) {
    dp.put_long(ALLOW_CHANGE_DELEGATION_KEY, 1);
    dp.put_long(NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE_KEY, 0);
    dp.put_long(NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE_KEY, 0);
    dp.put_long(CURRENT_CYCLE_NUMBER_KEY, current_cycle);
}

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn addr(byte: u8) -> Address {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(byte);
    Address::from_raw(a)
}

/// java's `BigInteger(bigEndianBytes).toByteArray()` for a positive value
/// — strip any leading 0xff (we only need positive values for these
/// tests; the decoder handles negatives separately).
fn encode_vi(value: i128) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    // Find the first significant byte for a positive value (strip leading zeros
    // unless the next byte's high bit is set — in which case keep one leading 0).
    let mut start = 0;
    while start < 15 && bytes[start] == 0 && bytes[start + 1] & 0x80 == 0 {
        start += 1;
    }
    bytes[start..].to_vec()
}

#[test]
fn decode_signed_be_i128_handles_zero_and_positive() {
    assert_eq!(decode_signed_be_i128(&[]), 0);
    assert_eq!(decode_signed_be_i128(&[0]), 0);
    assert_eq!(decode_signed_be_i128(&[0x12, 0x34]), 0x1234);
}

#[test]
fn decode_signed_be_i128_handles_negative() {
    // -1 encoded as one byte: 0xff.
    assert_eq!(decode_signed_be_i128(&[0xff]), -1);
    // -256 encoded as [0xff, 0x00].
    assert_eq!(decode_signed_be_i128(&[0xff, 0x00]), -256);
}

#[test]
fn query_reward_returns_allowance_for_account_with_no_votes() {
    let accounts = AccountStore::new(mem());
    let delegation = DelegationStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());

    arm_reward_state(&dp, 0);
    let voter = addr(0xa1);
    accounts.put(
        &voter,
        &Account {
            address: voter.as_bytes().to_vec(),
            allowance: 7_000_000, // already-claimable
            votes: vec![],
            ..Default::default()
        },
    ).unwrap();

    let reward = query_reward(&voter, &accounts, &delegation, &dp, None).unwrap();
    assert_eq!(reward, 7_000_000);
}

#[test]
fn query_reward_sums_vi_delta_times_vote_count_per_witness() {
    let accounts = AccountStore::new(mem());
    let delegation = DelegationStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());

    arm_reward_state(&dp, 20);
    let voter = addr(0xa2);
    let witness_a = addr(0xb1);
    let witness_b = addr(0xb2);

    // Voter votes 100 for witness A and 50 for witness B.
    accounts.put(
        &voter,
        &Account {
            address: voter.as_bytes().to_vec(),
            allowance: 1_000,
            votes: vec![
                Vote {
                    vote_address: witness_a.as_bytes().to_vec(),
                    vote_count: 100,
                },
                Vote {
                    vote_address: witness_b.as_bytes().to_vec(),
                    vote_count: 50,
                },
            ],
            ..Default::default()
        },
    ).unwrap();

    // Cycle window [10, 20).
    delegation.set_begin_cycle(&voter, 10);
    delegation.set_end_cycle(&voter, 20);

    // Set Vi values: Vi(begin-1=9) = 0 for both (no prior); Vi(end-1=19):
    // witness A accumulated 5e18 units; witness B accumulated 2e18.
    delegation.set_witness_vi_raw(19, &witness_a, &encode_vi(5 * REWARD_VI_DECIMAL));
    delegation.set_witness_vi_raw(19, &witness_b, &encode_vi(2 * REWARD_VI_DECIMAL));

    let reward = query_reward(&voter, &accounts, &delegation, &dp, None).unwrap();
    // 100 * 5 + 50 * 2 = 500 + 100 = 600 sun, plus allowance 1000 = 1600.
    assert_eq!(reward, 1600);
}

#[test]
fn query_reward_returns_just_allowance_when_begin_cycle_equals_end_cycle() {
    let accounts = AccountStore::new(mem());
    let delegation = DelegationStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());

    arm_reward_state(&dp, 5);
    let voter = addr(0xa3);
    let witness = addr(0xb3);
    accounts.put(
        &voter,
        &Account {
            address: voter.as_bytes().to_vec(),
            allowance: 42,
            votes: vec![Vote {
                vote_address: witness.as_bytes().to_vec(),
                vote_count: 1,
            }],
            ..Default::default()
        },
    ).unwrap();
    // No cycles to walk — begin == end.
    delegation.set_begin_cycle(&voter, 5);
    delegation.set_end_cycle(&voter, 5);

    let reward = query_reward(&voter, &accounts, &delegation, &dp, None).unwrap();
    assert_eq!(reward, 42);
}

#[test]
fn query_reward_returns_zero_for_unknown_account() {
    let accounts = AccountStore::new(mem());
    let delegation = DelegationStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let reward = query_reward(&addr(0xa4), &accounts, &delegation, &dp, None).unwrap();
    assert_eq!(reward, 0);
}

#[test]
fn query_reward_handles_vi_progression_across_cycles() {
    let accounts = AccountStore::new(mem());
    let delegation = DelegationStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());

    arm_reward_state(&dp, 110);
    let voter = addr(0xa5);
    let witness = addr(0xb5);
    accounts.put(
        &voter,
        &Account {
            address: voter.as_bytes().to_vec(),
            allowance: 0,
            votes: vec![Vote {
                vote_address: witness.as_bytes().to_vec(),
                vote_count: 1_000_000,
            }],
            ..Default::default()
        },
    ).unwrap();
    delegation.set_begin_cycle(&voter, 100);
    delegation.set_end_cycle(&voter, 110);

    // Voter was already at Vi=3*DECIMAL at cycle 99 (begin-1); witness
    // has accumulated to 7*DECIMAL at cycle 109 (end-1). Delta = 4.
    delegation.set_witness_vi_raw(99, &witness, &encode_vi(3 * REWARD_VI_DECIMAL));
    delegation.set_witness_vi_raw(109, &witness, &encode_vi(7 * REWARD_VI_DECIMAL));

    let reward = query_reward(&voter, &accounts, &delegation, &dp, None).unwrap();
    assert_eq!(reward, 1_000_000 * 4); // 1M votes * 4 = 4M sun
}

#[test]
fn query_reward_bulk_window_extends_to_current_cycle() {
    // java's queryReward sets `endCycle = currentCycle` for the bulk
    // window unconditionally — the on-disk end marker only matters for
    // the single-cycle catch-up. (Replaces the old "partial current
    // cycle" behavior that gated on account_vote(current).)
    let accounts = AccountStore::new(mem());
    let delegation = DelegationStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());

    let voter = addr(0xa6);
    let witness = addr(0xb6);
    accounts.put(
        &voter,
        &Account {
            address: voter.as_bytes().to_vec(),
            allowance: 0,
            votes: vec![Vote {
                vote_address: witness.as_bytes().to_vec(),
                vote_count: 100,
            }],
            ..Default::default()
        },
    ).unwrap();
    // Markers say [5, 10); the chain is at cycle 12 — the bulk window
    // is [5, 12) regardless of the end marker.
    delegation.set_begin_cycle(&voter, 5);
    delegation.set_end_cycle(&voter, 10);
    delegation.set_witness_vi_raw(4, &witness, &encode_vi(0));
    delegation.set_witness_vi_raw(9, &witness, &encode_vi(2 * REWARD_VI_DECIMAL));
    delegation.set_witness_vi_raw(11, &witness, &encode_vi(4 * REWARD_VI_DECIMAL));
    arm_reward_state(&dp, 12);

    let reward = query_reward(&voter, &accounts, &delegation, &dp, None).unwrap();
    // Bulk [5, 12): Vi(11) - Vi(4) = 4 × 100 = 400.
    assert_eq!(reward, 400);
}

#[test]
fn query_reward_latest_cycle_catchup_uses_snapshot_votes() {
    // begin+1 == end and begin < current → the single finalised cycle
    // pays against the votes SNAPSHOT in account_vote(begin), not the
    // live votes; then the bulk window pays the live votes.
    let accounts = AccountStore::new(mem());
    let delegation = DelegationStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());

    let voter = addr(0xa7);
    let witness = addr(0xb7);
    // Live votes: 100.
    accounts.put(
        &voter,
        &Account {
            address: voter.as_bytes().to_vec(),
            votes: vec![Vote {
                vote_address: witness.as_bytes().to_vec(),
                vote_count: 100,
            }],
            ..Default::default()
        },
    ).unwrap();
    // Snapshot at cycle 5: only 40 votes (the list as the cycle ran).
    delegation.set_account_vote(
        5,
        &voter,
        &Account {
            address: voter.as_bytes().to_vec(),
            votes: vec![Vote {
                vote_address: witness.as_bytes().to_vec(),
                vote_count: 40,
            }],
            ..Default::default()
        },
    ).unwrap();
    delegation.set_begin_cycle(&voter, 5);
    delegation.set_end_cycle(&voter, 6);
    // Vi: cycle 4 → 0, cycle 5 → 1×D, cycle 9 → 3×D.
    delegation.set_witness_vi_raw(4, &witness, &encode_vi(0));
    delegation.set_witness_vi_raw(5, &witness, &encode_vi(REWARD_VI_DECIMAL));
    delegation.set_witness_vi_raw(9, &witness, &encode_vi(3 * REWARD_VI_DECIMAL));
    arm_reward_state(&dp, 10);

    let reward = query_reward(&voter, &accounts, &delegation, &dp, None).unwrap();
    // Catch-up [5,6): (Vi(5)-Vi(4)) × 40  = 1 × 40  = 40   (snapshot)
    // Bulk    [6,10): (Vi(9)-Vi(5)) × 100 = 2 × 100 = 200  (live)
    assert_eq!(reward, 240);
}

#[test]
fn query_reward_returns_zero_when_change_delegation_disabled() {
    // java `MortgageService.queryReward`: `if (!allowChangeDelegation())
    // return 0` — even the cached allowance is not reported.
    let accounts = AccountStore::new(mem());
    let delegation = DelegationStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let voter = addr(0xa8);
    accounts.put(
        &voter,
        &Account {
            address: voter.as_bytes().to_vec(),
            allowance: 12345,
            ..Default::default()
        },
    ).unwrap();
    let reward = query_reward_actuator(&voter, &accounts, &delegation, &dp, None).unwrap();
    assert_eq!(reward, 0);
}

/// Regression for the two-entry-point gate split: java gates
/// `MortgageService` (actuator/RPC) on ALLOW_CHANGE_DELEGATION and
/// `VoteRewardUtil` (TVM precompile/opcodes) on ALLOW_TVM_VOTE. When the
/// flags differ, the two wrappers must diverge — each follows its own gate,
/// not a single shared one.
#[test]
fn reward_gates_are_independent_per_entry_point() {
    // A voter earning a 600-sun Vi-delta reward (no allowance), in a
    // post-upgrade DB where the new algorithm has always been effective.
    fn build() -> (AccountStore, DelegationStore, DynamicPropertiesStore, Address) {
        let accounts = AccountStore::new(mem());
        let delegation = DelegationStore::new(mem());
        let dp = DynamicPropertiesStore::new(mem());
        dp.put_long(NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE_KEY, 0);
        dp.put_long(CURRENT_CYCLE_NUMBER_KEY, 20);
        let voter = addr(0xe1);
        let witness = addr(0xe2);
        accounts.put(
            &voter,
            &Account {
                address: voter.as_bytes().to_vec(),
                votes: vec![Vote {
                    vote_address: witness.as_bytes().to_vec(),
                    vote_count: 100,
                }],
                ..Default::default()
            },
        ).unwrap();
        delegation.set_begin_cycle(&voter, 10);
        delegation.set_end_cycle(&voter, 20);
        delegation.set_witness_vi_raw(19, &witness, &encode_vi(6 * REWARD_VI_DECIMAL));
        (accounts, delegation, dp, voter)
    }

    // TVM_VOTE on, CHANGE_DELEGATION off: only the TVM wrappers pay out.
    {
        let (accounts, delegation, dp, voter) = build();
        dp.put_long(ALLOW_TVM_VOTE_KEY, 1);
        dp.put_long(ALLOW_CHANGE_DELEGATION_KEY, 0);
        // query: TVM path sees 600, actuator path is gated to 0.
        assert_eq!(query_reward_tvm(&voter, &accounts, &delegation, &dp, None).unwrap(), 600);
        assert_eq!(query_reward_actuator(&voter, &accounts, &delegation, &dp, None).unwrap(), 0);
        // withdraw: actuator path is a no-op (allowance stays 0)...
        assert_eq!(withdraw_reward_actuator(&voter, &accounts, &delegation, &dp, None).unwrap(), 0);
        assert_eq!(accounts.get(&voter).unwrap().unwrap().allowance, 0);
        // ...while the TVM path settles the 600 into allowance.
        assert_eq!(withdraw_reward_tvm(&voter, &accounts, &delegation, &dp, None).unwrap(), 600);
        assert_eq!(accounts.get(&voter).unwrap().unwrap().allowance, 600);
    }

    // CHANGE_DELEGATION on, TVM_VOTE off: only the actuator wrappers pay out.
    {
        let (accounts, delegation, dp, voter) = build();
        dp.put_long(ALLOW_TVM_VOTE_KEY, 0);
        dp.put_long(ALLOW_CHANGE_DELEGATION_KEY, 1);
        assert_eq!(query_reward_tvm(&voter, &accounts, &delegation, &dp, None).unwrap(), 0);
        assert_eq!(query_reward_actuator(&voter, &accounts, &delegation, &dp, None).unwrap(), 600);
        assert_eq!(withdraw_reward_tvm(&voter, &accounts, &delegation, &dp, None).unwrap(), 0);
        assert_eq!(accounts.get(&voter).unwrap().unwrap().allowance, 0);
        assert_eq!(withdraw_reward_actuator(&voter, &accounts, &delegation, &dp, None).unwrap(), 600);
        assert_eq!(accounts.get(&voter).unwrap().unwrap().allowance, 600);
    }
}

#[test]
fn legacy_window_uses_per_cycle_ratio_with_java_double_semantics() {
    // Cycles BEFORE the new-algorithm effective cycle pay via the
    // per-cycle `userVote/totalVote × totalReward` double loop —
    // including java's `long += double` compound-assignment narrowing.
    let accounts = AccountStore::new(mem());
    let delegation = DelegationStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());

    let voter = addr(0xa9);
    let witness = addr(0xb9);
    accounts.put(
        &voter,
        &Account {
            address: voter.as_bytes().to_vec(),
            votes: vec![Vote {
                vote_address: witness.as_bytes().to_vec(),
                vote_count: 100,
            }],
            ..Default::default()
        },
    ).unwrap();
    delegation.set_begin_cycle(&voter, 5);
    delegation.set_end_cycle(&voter, 9); // ≠ begin+1 → no catch-up
    // Legacy data: per-cycle pool + total vote rows for cycles 5..8.
    for cycle in 5..8 {
        delegation.add_reward(cycle, &witness, 1_000_003);
        delegation.set_witness_vote(cycle, &witness, 300);
    }
    dp.put_long(ALLOW_CHANGE_DELEGATION_KEY, 1);
    dp.put_long(NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE_KEY, 0);
    // New algorithm only from cycle 8 → cycles 5..8 are legacy.
    dp.put_long(NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE_KEY, 8);
    dp.put_long(CURRENT_CYCLE_NUMBER_KEY, 8);

    let reward = query_reward(&voter, &accounts, &delegation, &dp, None).unwrap();
    // Java per cycle: reward = (long)(reward + (100/300) × 1_000_003)
    // — replicate the exact f64 fold for 3 cycles.
    let mut expected = 0i64;
    for _ in 0..3 {
        expected = (expected as f64 + (100f64 / 300f64) * 1_000_003f64) as i64;
    }
    assert_eq!(reward, expected);
    // Sanity: the fold actually pays ~1/3 of the pool 3 times.
    assert!((expected - 1_000_003) .abs() < 10);
}

#[test]
fn legacy_window_uses_reward_vi_store_when_old_reward_opt_is_on() {
    // With ALLOW_OLD_REWARD_OPT(79) on, the legacy window reads the
    // background-computed `reward-vi` store (java's RewardViCalService)
    // instead of looping cycles — values are merkle-pinned upstream.
    use tron_chainbase::RewardViStore;

    let accounts = AccountStore::new(mem());
    let delegation = DelegationStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let reward_vi = RewardViStore::new(mem());

    let voter = addr(0xaa);
    let witness = addr(0xba);
    accounts.put(
        &voter,
        &Account {
            address: voter.as_bytes().to_vec(),
            votes: vec![Vote {
                vote_address: witness.as_bytes().to_vec(),
                vote_count: 100,
            }],
            ..Default::default()
        },
    ).unwrap();
    delegation.set_begin_cycle(&voter, 5);
    delegation.set_end_cycle(&voter, 9);
    // reward-vi store rows (same key/value shapes as DelegationStore vi).
    reward_vi
        .put(&DelegationStore::vi_key(4, &witness), &encode_vi(0))
        .unwrap();
    reward_vi
        .put(
            &DelegationStore::vi_key(7, &witness),
            &encode_vi(3 * REWARD_VI_DECIMAL),
        )
        .unwrap();
    dp.put_long(ALLOW_CHANGE_DELEGATION_KEY, 1);
    dp.put_long(NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE_KEY, 0);
    dp.put_long(NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE_KEY, 8);
    dp.put_long(ALLOW_OLD_REWARD_OPT_KEY, 1);
    dp.put_long(CURRENT_CYCLE_NUMBER_KEY, 8);

    let reward =
        query_reward(&voter, &accounts, &delegation, &dp, Some(&reward_vi)).unwrap();
    // Legacy window [5, 8) via reward-vi: (Vi(7) - Vi(4)) × 100 = 300.
    assert_eq!(reward, 300);
}

#[test]
fn window_straddling_the_new_algorithm_cycle_uses_both_paths() {
    // begin < newAlgorithmCycle < end → legacy math up to the switch,
    // Vi math after, summed.
    let accounts = AccountStore::new(mem());
    let delegation = DelegationStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());

    let voter = addr(0xab);
    let witness = addr(0xbb);
    accounts.put(
        &voter,
        &Account {
            address: voter.as_bytes().to_vec(),
            votes: vec![Vote {
                vote_address: witness.as_bytes().to_vec(),
                vote_count: 100,
            }],
            ..Default::default()
        },
    ).unwrap();
    delegation.set_begin_cycle(&voter, 5);
    delegation.set_end_cycle(&voter, 12); // ≠ begin+1
    // Legacy cycles 5..7 (switch at 7): one funded cycle (6).
    delegation.add_reward(6, &witness, 900);
    delegation.set_witness_vote(6, &witness, 300);
    // Vi cycles 7..10: Vi(6)=0 (missing), Vi(9)=2×D.
    delegation.set_witness_vi_raw(9, &witness, &encode_vi(2 * REWARD_VI_DECIMAL));
    dp.put_long(ALLOW_CHANGE_DELEGATION_KEY, 1);
    dp.put_long(NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE_KEY, 0);
    dp.put_long(NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE_KEY, 7);
    dp.put_long(CURRENT_CYCLE_NUMBER_KEY, 10);

    let reward = query_reward(&voter, &accounts, &delegation, &dp, None).unwrap();
    // Legacy [5,7): (100/300)×900 = 300. Vi [7,10): (Vi(9)-Vi(6))×100 = 200.
    assert_eq!(reward, 500);
}

// =================================================================
// withdraw_reward tests
// =================================================================

#[test]
fn withdraw_reward_noop_when_allow_change_delegation_disabled() {
    let accounts = AccountStore::new(mem());
    let delegation = DelegationStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let voter = addr(0xc0);
    accounts.put(
        &voter,
        &Account {
            address: voter.as_bytes().to_vec(),
            allowance: 500,
            votes: vec![Vote {
                vote_address: addr(0xd0).as_bytes().to_vec(),
                vote_count: 1,
            }],
            ..Default::default()
        },
    ).unwrap();
    // ALLOW_CHANGE_DELEGATION not set ⇒ 0 ⇒ disabled (the actuator gate).
    let paid = withdraw_reward_actuator(&voter, &accounts, &delegation, &dp, None).unwrap();
    assert_eq!(paid, 0);
    // Allowance untouched.
    assert_eq!(accounts.get(&voter).unwrap().unwrap().allowance, 500);
}

#[test]
fn withdraw_reward_noop_for_unknown_account() {
    let accounts = AccountStore::new(mem());
    let delegation = DelegationStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(ALLOW_CHANGE_DELEGATION_KEY, 1);
    dp.put_long(NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE_KEY, 0);
    let paid = withdraw_reward(&addr(0xc1), &accounts, &delegation, &dp, None).unwrap();
    assert_eq!(paid, 0);
}

#[test]
fn withdraw_reward_noop_when_already_claimed_this_cycle() {
    let accounts = AccountStore::new(mem());
    let delegation = DelegationStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(ALLOW_CHANGE_DELEGATION_KEY, 1);
    dp.put_long(NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE_KEY, 0);
    dp.put_long(tron_tvm::reward::CURRENT_CYCLE_NUMBER_KEY, 10);

    let voter = addr(0xc2);
    accounts.put(
        &voter,
        &Account {
            address: voter.as_bytes().to_vec(),
            allowance: 0,
            votes: vec![Vote {
                vote_address: addr(0xd2).as_bytes().to_vec(),
                vote_count: 100,
            }],
            ..Default::default()
        },
    ).unwrap();
    // begin_cycle == current_cycle AND account_vote already recorded
    // ⇒ already claimed.
    delegation.set_begin_cycle(&voter, 10);
    delegation.set_end_cycle(&voter, 11);
    delegation.set_account_vote(
        10,
        &voter,
        &Account {
            address: voter.as_bytes().to_vec(),
            ..Default::default()
        },
    ).unwrap();
    let paid = withdraw_reward(&voter, &accounts, &delegation, &dp, None).unwrap();
    assert_eq!(paid, 0);
}

#[test]
fn withdraw_reward_bulk_window_pays_finalised_cycles_and_advances_state() {
    let accounts = AccountStore::new(mem());
    let delegation = DelegationStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(ALLOW_CHANGE_DELEGATION_KEY, 1);
    dp.put_long(NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE_KEY, 0);
    dp.put_long(tron_tvm::reward::CURRENT_CYCLE_NUMBER_KEY, 10);

    let voter = addr(0xc3);
    let witness = addr(0xd3);
    accounts.put(
        &voter,
        &Account {
            address: voter.as_bytes().to_vec(),
            allowance: 50,
            votes: vec![Vote {
                vote_address: witness.as_bytes().to_vec(),
                vote_count: 100,
            }],
            ..Default::default()
        },
    ).unwrap();
    // Window [5, 10): Vi grew from 0 to 3×DECIMAL → 100 × 3 = 300 sun.
    delegation.set_begin_cycle(&voter, 5);
    delegation.set_end_cycle(&voter, 10);
    delegation.set_witness_vi_raw(4, &witness, &encode_vi(0));
    delegation.set_witness_vi_raw(9, &witness, &encode_vi(3 * REWARD_VI_DECIMAL));

    let paid = withdraw_reward(&voter, &accounts, &delegation, &dp, None).unwrap();
    assert_eq!(paid, 300);

    // Allowance bumped by the reward.
    let after = accounts.get(&voter).unwrap().unwrap();
    assert_eq!(after.allowance, 350);
    // State advanced: begin=current, end=current+1, snapshot recorded.
    assert_eq!(delegation.get_begin_cycle(&voter), 10);
    assert_eq!(delegation.get_end_cycle(&voter), 11);
    let snap = delegation.get_account_vote(10, &voter).unwrap();
    assert!(snap.is_some(), "account_vote(current_cycle) should be set");
    assert_eq!(snap.unwrap().votes.len(), 1);

    // Second call within the same cycle ⇒ no-op (already claimed).
    let paid2 = withdraw_reward(&voter, &accounts, &delegation, &dp, None).unwrap();
    assert_eq!(paid2, 0);
    assert_eq!(accounts.get(&voter).unwrap().unwrap().allowance, 350);
}

#[test]
fn withdraw_reward_latest_cycle_catchup_uses_snapshot_not_current_votes() {
    let accounts = AccountStore::new(mem());
    let delegation = DelegationStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(ALLOW_CHANGE_DELEGATION_KEY, 1);
    dp.put_long(NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE_KEY, 0);
    dp.put_long(tron_tvm::reward::CURRENT_CYCLE_NUMBER_KEY, 10);

    let voter = addr(0xc4);
    let old_witness = addr(0xd4); // who they voted for in the snapshot
    let new_witness = addr(0xe4); // who they vote for now
    // Currently votes 100 for new_witness.
    accounts.put(
        &voter,
        &Account {
            address: voter.as_bytes().to_vec(),
            allowance: 0,
            votes: vec![Vote {
                vote_address: new_witness.as_bytes().to_vec(),
                vote_count: 100,
            }],
            ..Default::default()
        },
    ).unwrap();
    // begin+1 == end & begin < current ⇒ latest-cycle catch-up path.
    // begin=7, end=8, current=10. Snapshot at cycle 7 says voted for old_witness.
    delegation.set_begin_cycle(&voter, 7);
    delegation.set_end_cycle(&voter, 8);
    delegation.set_account_vote(
        7,
        &voter,
        &Account {
            address: voter.as_bytes().to_vec(),
            votes: vec![Vote {
                vote_address: old_witness.as_bytes().to_vec(),
                vote_count: 50,
            }],
            ..Default::default()
        },
    ).unwrap();
    // Catch-up window [7, 8): Vi(6→7) on OLD witness: 0 → 4×DECIMAL.
    delegation.set_witness_vi_raw(6, &old_witness, &encode_vi(0));
    delegation.set_witness_vi_raw(7, &old_witness, &encode_vi(4 * REWARD_VI_DECIMAL));
    // Bulk window [8, 10): Vi(7→9) on NEW witness: 0 → 6×DECIMAL.
    delegation.set_witness_vi_raw(7, &new_witness, &encode_vi(0));
    delegation.set_witness_vi_raw(9, &new_witness, &encode_vi(6 * REWARD_VI_DECIMAL));

    let paid = withdraw_reward(&voter, &accounts, &delegation, &dp, None).unwrap();
    // Catch-up:  50 × 4 = 200 (snapshot votes count)
    // Bulk:     100 × 6 = 600 (current votes count)
    // Total:    800
    assert_eq!(paid, 800);
    assert_eq!(accounts.get(&voter).unwrap().unwrap().allowance, 800);
    assert_eq!(delegation.get_begin_cycle(&voter), 10);
    assert_eq!(delegation.get_end_cycle(&voter), 11);
}

#[test]
fn withdraw_reward_no_votes_account_fast_forwards_begin_cycle() {
    let accounts = AccountStore::new(mem());
    let delegation = DelegationStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(ALLOW_CHANGE_DELEGATION_KEY, 1);
    dp.put_long(NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE_KEY, 0);
    dp.put_long(tron_tvm::reward::CURRENT_CYCLE_NUMBER_KEY, 10);

    let voter = addr(0xc5);
    accounts.put(
        &voter,
        &Account {
            address: voter.as_bytes().to_vec(),
            allowance: 100,
            votes: vec![], // no live votes
            ..Default::default()
        },
    ).unwrap();
    delegation.set_begin_cycle(&voter, 5);
    delegation.set_end_cycle(&voter, 6);

    let paid = withdraw_reward(&voter, &accounts, &delegation, &dp, None).unwrap();
    assert_eq!(paid, 0); // no votes ⇒ no bulk reward, and no catch-up snapshot
    // begin_cycle fast-forwarded to current_cycle + 1.
    assert_eq!(delegation.get_begin_cycle(&voter), 11);
    // Allowance unchanged.
    assert_eq!(accounts.get(&voter).unwrap().unwrap().allowance, 100);
}

#[test]
fn withdraw_reward_noop_when_begin_cycle_in_future() {
    let accounts = AccountStore::new(mem());
    let delegation = DelegationStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(ALLOW_CHANGE_DELEGATION_KEY, 1);
    dp.put_long(NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE_KEY, 0);
    dp.put_long(tron_tvm::reward::CURRENT_CYCLE_NUMBER_KEY, 5);

    let voter = addr(0xc6);
    accounts.put(
        &voter,
        &Account {
            address: voter.as_bytes().to_vec(),
            allowance: 0,
            votes: vec![Vote {
                vote_address: addr(0xe6).as_bytes().to_vec(),
                vote_count: 1,
            }],
            ..Default::default()
        },
    ).unwrap();
    // Voter's begin is somehow ahead of current — must bail with no state change.
    delegation.set_begin_cycle(&voter, 10);
    delegation.set_end_cycle(&voter, 11);

    let paid = withdraw_reward(&voter, &accounts, &delegation, &dp, None).unwrap();
    assert_eq!(paid, 0);
    assert_eq!(delegation.get_begin_cycle(&voter), 10);
    assert_eq!(delegation.get_end_cycle(&voter), 11);
}
