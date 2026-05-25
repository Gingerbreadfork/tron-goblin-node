//! Tests for the Vi-accumulator reward computation.

use std::sync::Arc;

use tron_chainbase::{
    AccountStore, DelegationStore, DynamicPropertiesStore, KvBackend, MemBackend,
};
use tron_crypto::address::Address;
use tron_proto::{Account, Vote};
use tron_tvm::reward::{
    decode_signed_be_i128, query_reward, withdraw_reward, ALLOW_CHANGE_DELEGATION_KEY,
    REWARD_VI_DECIMAL,
};

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

    let voter = addr(0xa1);
    accounts.put(
        &voter,
        &Account {
            address: voter.as_bytes().to_vec(),
            allowance: 7_000_000, // already-claimable
            votes: vec![],
            ..Default::default()
        },
    );

    let reward = query_reward(&voter, &accounts, &delegation, &dp).unwrap();
    assert_eq!(reward, 7_000_000);
}

#[test]
fn query_reward_sums_vi_delta_times_vote_count_per_witness() {
    let accounts = AccountStore::new(mem());
    let delegation = DelegationStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());

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
    );

    // Cycle window [10, 20).
    delegation.set_begin_cycle(&voter, 10);
    delegation.set_end_cycle(&voter, 20);

    // Set Vi values: Vi(begin-1=9) = 0 for both (no prior); Vi(end-1=19):
    // witness A accumulated 5e18 units; witness B accumulated 2e18.
    delegation.set_witness_vi_raw(19, &witness_a, &encode_vi(5 * REWARD_VI_DECIMAL));
    delegation.set_witness_vi_raw(19, &witness_b, &encode_vi(2 * REWARD_VI_DECIMAL));

    let reward = query_reward(&voter, &accounts, &delegation, &dp).unwrap();
    // 100 * 5 + 50 * 2 = 500 + 100 = 600 sun, plus allowance 1000 = 1600.
    assert_eq!(reward, 1600);
}

#[test]
fn query_reward_returns_just_allowance_when_begin_cycle_equals_end_cycle() {
    let accounts = AccountStore::new(mem());
    let delegation = DelegationStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());

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
    );
    // No cycles to walk — begin == end.
    delegation.set_begin_cycle(&voter, 5);
    delegation.set_end_cycle(&voter, 5);

    let reward = query_reward(&voter, &accounts, &delegation, &dp).unwrap();
    assert_eq!(reward, 42);
}

#[test]
fn query_reward_returns_zero_for_unknown_account() {
    let accounts = AccountStore::new(mem());
    let delegation = DelegationStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    let reward = query_reward(&addr(0xa4), &accounts, &delegation, &dp).unwrap();
    assert_eq!(reward, 0);
}

#[test]
fn query_reward_handles_vi_progression_across_cycles() {
    let accounts = AccountStore::new(mem());
    let delegation = DelegationStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());

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
    );
    delegation.set_begin_cycle(&voter, 100);
    delegation.set_end_cycle(&voter, 110);

    // Voter was already at Vi=3*DECIMAL at cycle 99 (begin-1); witness
    // has accumulated to 7*DECIMAL at cycle 109 (end-1). Delta = 4.
    delegation.set_witness_vi_raw(99, &witness, &encode_vi(3 * REWARD_VI_DECIMAL));
    delegation.set_witness_vi_raw(109, &witness, &encode_vi(7 * REWARD_VI_DECIMAL));

    let reward = query_reward(&voter, &accounts, &delegation, &dp).unwrap();
    assert_eq!(reward, 1_000_000 * 4); // 1M votes * 4 = 4M sun
}

#[test]
fn query_reward_includes_partial_current_cycle_when_voter_has_voted() {
    use tron_tvm::reward::CURRENT_CYCLE_NUMBER_KEY;

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
    );
    // Finalised window: cycles 5..10 — voter has earned through cycle 9.
    delegation.set_begin_cycle(&voter, 5);
    delegation.set_end_cycle(&voter, 10);
    delegation.set_witness_vi_raw(4, &witness, &encode_vi(0));
    delegation.set_witness_vi_raw(9, &witness, &encode_vi(2 * REWARD_VI_DECIMAL));
    // Current cycle = 10. Voter HAS voted in current cycle (account_vote
    // entry exists). Vi at cycle 10 = 4×DECIMAL, so the partial gain is
    // (4 - 2) × 100 / DECIMAL = 200 sun.
    dp.put_long(CURRENT_CYCLE_NUMBER_KEY, 10);
    delegation.set_witness_vi_raw(10, &witness, &encode_vi(4 * REWARD_VI_DECIMAL));
    delegation.set_account_vote(
        10,
        &voter,
        &Account {
            address: voter.as_bytes().to_vec(),
            ..Default::default()
        },
    );

    let reward = query_reward(&voter, &accounts, &delegation, &dp).unwrap();
    // Finalised: 100 × (2 - 0) = 200
    // Partial:   100 × (4 - 2) = 200
    // Total:     400
    assert_eq!(reward, 400);
}

#[test]
fn query_reward_skips_partial_when_voter_didnt_vote_in_current_cycle() {
    use tron_tvm::reward::CURRENT_CYCLE_NUMBER_KEY;

    let accounts = AccountStore::new(mem());
    let delegation = DelegationStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());

    let voter = addr(0xa7);
    let witness = addr(0xb7);
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
    );
    delegation.set_begin_cycle(&voter, 5);
    delegation.set_end_cycle(&voter, 10);
    delegation.set_witness_vi_raw(4, &witness, &encode_vi(0));
    delegation.set_witness_vi_raw(9, &witness, &encode_vi(2 * REWARD_VI_DECIMAL));
    // Current cycle is set, Vi exists, but voter did NOT cast a vote
    // in the current cycle (no account_vote entry).
    dp.put_long(CURRENT_CYCLE_NUMBER_KEY, 10);
    delegation.set_witness_vi_raw(10, &witness, &encode_vi(4 * REWARD_VI_DECIMAL));

    let reward = query_reward(&voter, &accounts, &delegation, &dp).unwrap();
    // Only the finalised window counts: 100 × 2 = 200.
    assert_eq!(reward, 200);
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
    );
    // ALLOW_CHANGE_DELEGATION not set ⇒ 0 ⇒ disabled.
    let paid = withdraw_reward(&voter, &accounts, &delegation, &dp).unwrap();
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
    let paid = withdraw_reward(&addr(0xc1), &accounts, &delegation, &dp).unwrap();
    assert_eq!(paid, 0);
}

#[test]
fn withdraw_reward_noop_when_already_claimed_this_cycle() {
    let accounts = AccountStore::new(mem());
    let delegation = DelegationStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(ALLOW_CHANGE_DELEGATION_KEY, 1);
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
    );
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
    );
    let paid = withdraw_reward(&voter, &accounts, &delegation, &dp).unwrap();
    assert_eq!(paid, 0);
}

#[test]
fn withdraw_reward_bulk_window_pays_finalised_cycles_and_advances_state() {
    let accounts = AccountStore::new(mem());
    let delegation = DelegationStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(ALLOW_CHANGE_DELEGATION_KEY, 1);
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
    );
    // Window [5, 10): Vi grew from 0 to 3×DECIMAL → 100 × 3 = 300 sun.
    delegation.set_begin_cycle(&voter, 5);
    delegation.set_end_cycle(&voter, 10);
    delegation.set_witness_vi_raw(4, &witness, &encode_vi(0));
    delegation.set_witness_vi_raw(9, &witness, &encode_vi(3 * REWARD_VI_DECIMAL));

    let paid = withdraw_reward(&voter, &accounts, &delegation, &dp).unwrap();
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
    let paid2 = withdraw_reward(&voter, &accounts, &delegation, &dp).unwrap();
    assert_eq!(paid2, 0);
    assert_eq!(accounts.get(&voter).unwrap().unwrap().allowance, 350);
}

#[test]
fn withdraw_reward_latest_cycle_catchup_uses_snapshot_not_current_votes() {
    let accounts = AccountStore::new(mem());
    let delegation = DelegationStore::new(mem());
    let dp = DynamicPropertiesStore::new(mem());
    dp.put_long(ALLOW_CHANGE_DELEGATION_KEY, 1);
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
    );
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
    );
    // Catch-up window [7, 8): Vi(6→7) on OLD witness: 0 → 4×DECIMAL.
    delegation.set_witness_vi_raw(6, &old_witness, &encode_vi(0));
    delegation.set_witness_vi_raw(7, &old_witness, &encode_vi(4 * REWARD_VI_DECIMAL));
    // Bulk window [8, 10): Vi(7→9) on NEW witness: 0 → 6×DECIMAL.
    delegation.set_witness_vi_raw(7, &new_witness, &encode_vi(0));
    delegation.set_witness_vi_raw(9, &new_witness, &encode_vi(6 * REWARD_VI_DECIMAL));

    let paid = withdraw_reward(&voter, &accounts, &delegation, &dp).unwrap();
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
    );
    delegation.set_begin_cycle(&voter, 5);
    delegation.set_end_cycle(&voter, 6);

    let paid = withdraw_reward(&voter, &accounts, &delegation, &dp).unwrap();
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
    );
    // Voter's begin is somehow ahead of current — must bail with no state change.
    delegation.set_begin_cycle(&voter, 10);
    delegation.set_end_cycle(&voter, 11);

    let paid = withdraw_reward(&voter, &accounts, &delegation, &dp).unwrap();
    assert_eq!(paid, 0);
    assert_eq!(delegation.get_begin_cycle(&voter), 10);
    assert_eq!(delegation.get_end_cycle(&voter), 11);
}
