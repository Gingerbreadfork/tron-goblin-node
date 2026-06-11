//! End-to-end tests for per-block + per-maintenance reward
//! distribution.
//!
//! What's exercised:
//!   * Per-block: producing a block credits the producer's
//!     `Account.allowance` with the brokerage cut and bumps the
//!     cycle's `delegation.reward(cycle, producer)` with the
//!     remainder.
//!   * Per-block: the standby-pool distribution (top 127 by votes)
//!     accumulates into the same cycle's reward pool.
//!   * Maintenance: at a cycle boundary, `accumulate_witness_vi`
//!     turns the cycle pool into a per-vote Vi delta; the cycle
//!     number advances; brokerage + vote snapshots land for the next
//!     cycle.
//!   * Voter side: `withdraw_reward` walks the Vi delta and credits
//!     the voter's allowance — full E2E from block production through
//!     to voter claim.

use std::sync::Arc;

use tron_chainbase::{
    AccountStore, DelegationStore, DynamicPropertiesStore, KvBackend, MemBackend, VotesStore,
    WitnessStore, DEFAULT_BROKERAGE,
};
use tron_crypto::address::Address;
use tron_executor::{
    execute_block_with_config, BlockExecError, BlockExecutionReport, ExecConfig, StateBackends,
};
use tron_proto::{
    block_header::Raw as BlockHeaderRaw, Account, Block, BlockHeader, Vote, Votes, Witness,
};
use tron_types::BlockId;

/// Apply a synthetic UNSIGNED block. See note on the same helper in
/// `maintenance_rotation.rs` — these tests exercise reward / brokerage
/// logic, not the witness-sig path, so they opt out of the strict gate.
fn apply_unsigned(
    state: &StateBackends,
    block: &Block,
    prev: Option<BlockId>,
) -> Result<BlockExecutionReport, BlockExecError> {
    execute_block_with_config(state, block, prev, &ExecConfig::unsigned())
}

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn fresh_state() -> StateBackends {
    StateBackends {
        accounts: mem(),
        witnesses: mem(),
        votes: mem(),
        delegation: mem(),
        delegated_resources: mem(),
        delegated_resource_account_index: None,
        dyn_props: mem(),
        proposals: mem(),
        name_index: mem(),
        id_index: mem(),
        asset_v1: mem(),
        asset_v2: mem(),
        contracts: mem(),
        abi: mem(),
        exchange_v1: mem(),
        exchange_v2: mem(),
        market_orders: mem(),
        nullifiers: mem(),
        merkle_trees: None,
        code: Some(mem()),
        storage_row: Some(mem()),
        contract_state: Some(mem()),
        block_index: Some(mem()),
        witness_schedule: Some(mem()),
        reward_vi: None,
    }
}

fn addr(byte: u8) -> [u8; 21] {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(byte);
    a
}

fn empty_block(num: i64, parent_hash: [u8; 32], witness: [u8; 21], timestamp_ms: i64) -> Block {
    Block {
        block_header: Some(BlockHeader {
            raw_data: Some(BlockHeaderRaw {
                number: num,
                parent_hash: parent_hash.to_vec(),
                timestamp: timestamp_ms,
                tx_trie_root: tron_types::calc_tx_trie_root(&[])
                    .map(|h| h.to_vec())
                    .unwrap_or_default(),
                witness_address: witness.to_vec(),
                ..Default::default()
            }),
            witness_signature: Vec::new(),
        }),
        transactions: Vec::new(),
    }
}

#[test]
fn producer_gets_brokerage_into_allowance_and_remainder_into_cycle_pool() {
    let state = fresh_state();
    let producer = addr(0xa1);

    // Seed witness + account; witness has 100 votes (any positive
    // count, just exercises the bump-counter path).
    let ws = WitnessStore::new(state.witnesses.clone());
    ws.put(
        &Address::from_raw(producer),
        &Witness {
            address: producer.to_vec(),
            vote_count: 100,
            ..Default::default()
        },
    ).unwrap();
    let accts = AccountStore::new(state.accounts.clone());
    accts.put(
        &Address::from_raw(producer),
        &Account {
            address: producer.to_vec(),
            balance: 0,
            allowance: 0,
            ..Default::default()
        },
    ).unwrap();

    // Default DPS values: witness_pay_per_block = 32_000_000,
    //   witness_127_pay_per_block = 16_000_000.
    // Producer is the only witness → vote_sum = 100, gets 100% of standby = 16_000_000.
    // Total credited to producer this block = 32_000_000 + 16_000_000 = 48_000_000.
    // Default brokerage is 20% → producer allowance += 9_600_000;
    //   cycle pool += 38_400_000.

    apply_unsigned(&state, &empty_block(1, [0u8; 32], producer, 1_700_000_000_000), None)
        .expect("execute");

    let updated_acct = accts
        .get(&Address::from_raw(producer))
        .unwrap()
        .expect("producer account");
    assert_eq!(updated_acct.allowance, 9_600_000, "brokerage cut to allowance");

    let dlg = DelegationStore::new(state.delegation.clone());
    let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
    let cycle = dp.current_cycle_number();
    let cycle_pool = dlg.get_reward(cycle, &Address::from_raw(producer));
    assert_eq!(cycle_pool, 38_400_000, "remainder to cycle pool");
}

#[test]
fn standby_pool_distributes_proportionally_across_top_127() {
    // Three witnesses: A=100 votes, B=200 votes, C=50 votes.
    // standby_pay = 16_000_000, vote_sum = 350.
    //   A: 16_000_000 * 100 / 350 ≈ 4_571_428.57 → 4_571_428 (truncation)
    //   B: 16_000_000 * 200 / 350 ≈ 9_142_857.14 → 9_142_857
    //   C: 16_000_000 * 50 / 350 ≈ 2_285_714.28 → 2_285_714
    // Plus the producer (B in this test) also gets WITNESS_PAY_PER_BLOCK = 32M.
    // Brokerage 20% each.
    let state = fresh_state();
    let a = addr(0xa1);
    let b = addr(0xb2);
    let c = addr(0xc3);
    let ws = WitnessStore::new(state.witnesses.clone());
    let accts = AccountStore::new(state.accounts.clone());
    for (addr_bytes, votes) in [(a, 100i64), (b, 200), (c, 50)] {
        ws.put(
            &Address::from_raw(addr_bytes),
            &Witness {
                address: addr_bytes.to_vec(),
                vote_count: votes,
                ..Default::default()
            },
        ).unwrap();
        accts.put(
            &Address::from_raw(addr_bytes),
            &Account {
                address: addr_bytes.to_vec(),
                ..Default::default()
            },
        ).unwrap();
    }

    apply_unsigned(&state, &empty_block(1, [0u8; 32], b, 1_700_000_000_000), None)
        .expect("execute");

    let dlg = DelegationStore::new(state.delegation.clone());
    let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
    let cycle = dp.current_cycle_number();

    // A's standby share: 4_571_428 total.
    // brokerage = 4_571_428 * 20 / 100 = 914_285 (integer truncation);
    // voter_share = 4_571_428 - 914_285 = 3_657_143.
    let a_pool = dlg.get_reward(cycle, &Address::from_raw(a));
    assert_eq!(
        a_pool, 3_657_143,
        "A's share of standby pool (4_571_428 - 914_285)"
    );
    // B's share = block-production (32_000_000) + standby (9_142_857).
    // Each call computes brokerage = value * 20 / 100 then voter_share = value - brokerage:
    //   block: brokerage=6_400_000, voter_share=25_600_000
    //   standby: brokerage=1_828_571 (=9_142_857*20/100), voter_share=7_314_286
    //   total to pool: 25_600_000 + 7_314_286 = 32_914_286.
    let b_pool = dlg.get_reward(cycle, &Address::from_raw(b));
    assert_eq!(
        b_pool, 32_914_286,
        "B's share = standby + block-production, voter-share each call"
    );
    // C's standby share: 2_285_714 total.
    // brokerage = 2_285_714 * 20 / 100 = 457_142; voter_share = 1_828_572.
    let c_pool = dlg.get_reward(cycle, &Address::from_raw(c));
    assert_eq!(c_pool, 1_828_572);
}

#[test]
fn maintenance_pass_advances_cycle_and_writes_vi() {
    // Set up: cycle 0, witness W with 100 votes and a reward pool of
    // some sun. Trigger maintenance via a block crossing the boundary.
    // Expected: cycle advances to 1; witness_vi(0, W) = pool * 1e18 / votes;
    // brokerage + vote snapshot for cycle 1.
    let state = fresh_state();
    let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
    dp.save_allow_change_delegation(1);
    dp.save_maintenance_time_interval(6 * 3600 * 1000);
    dp.save_next_maintenance_time(1_700_000_000_000); // boundary at t=baseline

    let w = addr(0xaa);
    let ws = WitnessStore::new(state.witnesses.clone());
    ws.put(
        &Address::from_raw(w),
        &Witness {
            address: w.to_vec(),
            vote_count: 1000,
            ..Default::default()
        },
    ).unwrap();
    let dlg = DelegationStore::new(state.delegation.clone());
    // Seed a known reward pool for cycle 0.
    dlg.add_reward(0, &Address::from_raw(w), 100_000_000);

    // Block at the boundary timestamp triggers maintenance.
    // Block num must be > 1 for doMaintenance to actually fire.
    // Apply genesis first (num=1) so the head pointer advances and
    // num=2 lands on the boundary.
    apply_unsigned(
        &state,
        &empty_block(1, [0u8; 32], w, 1_699_999_997_000),
        None,
    )
    .expect("genesis");

    let id1 = tron_types::block_id_from_block(&empty_block(1, [0u8; 32], w, 1_699_999_997_000))
        .unwrap();
    let _ = id1;

    // Now block 2 at the maintenance-boundary timestamp.
    let dp2 = DynamicPropertiesStore::new(state.dyn_props.clone());
    let head_hash = dp2.latest_block_header_hash().unwrap().unwrap();
    apply_unsigned(
        &state,
        &empty_block(2, head_hash, w, 1_700_000_000_000),
        None,
    )
    .expect("block 2 at boundary");

    // Cycle advanced 0 → 1.
    assert_eq!(dp.current_cycle_number(), 1, "cycle number must advance");

    // Vi(0, W) must be set. With pool=100_000_000 + block-2 reward
    // (32M for producing + 16M standby = 48M; 80% = 38_400_000 added
    // to cycle 0 pool ON the boundary block BEFORE accumulate runs)
    // — wait, no: the per-block reward happens BEFORE the maintenance
    // pass in our execute_block, so cycle 0's pool at the moment of
    // Vi accumulation is 100_000_000 (seeded) + 38_400_000 (block 2's
    // contribution to cycle 0) = 138_400_000.
    // Vi delta = 138_400_000 * 1e18 / 1000 = 138_400_000 * 1e15.
    let vi_bytes = dlg
        .get_witness_vi_raw(0, &Address::from_raw(w))
        .expect("Vi must be written");
    assert!(
        !vi_bytes.is_empty(),
        "Vi bytes must be non-empty after accumulation"
    );

    // The brokerage snapshot for cycle 1 must equal DEFAULT_BROKERAGE
    // (20) since we never set a per-witness brokerage.
    let b1 = dlg.get_brokerage(1, &Address::from_raw(w));
    assert_eq!(b1, DEFAULT_BROKERAGE);

    // The vote snapshot for cycle 1 must equal the witness's current
    // vote_count.
    let v1 = dlg.get_witness_vote(1, &Address::from_raw(w));
    assert_eq!(v1, 1000);
}

#[test]
fn maintenance_propagates_explicit_zero_brokerage_verbatim() {
    // Regression: an SR that deliberately sets brokerage = 0% (gives
    // 100% of rewards to voters) must have that 0 propagated verbatim
    // into the next cycle's per-cycle brokerage row. A prior bug
    // rewrote 0 → DEFAULT_BROKERAGE (20) at the maintenance boundary,
    // which then credited the SR 20% of every cycle's reward into its
    // `allowance` where java-tron credits nothing — the dominant cause
    // of "java allowance = 0, ours = billions" divergence on mainnet.
    let state = fresh_state();
    let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
    dp.save_allow_change_delegation(1);
    dp.save_maintenance_time_interval(6 * 3600 * 1000);
    dp.save_next_maintenance_time(1_700_000_000_000);

    let w = addr(0xbb);
    let ws = WitnessStore::new(state.witnesses.clone());
    ws.put(
        &Address::from_raw(w),
        &Witness {
            address: w.to_vec(),
            vote_count: 1000,
            ..Default::default()
        },
    )
    .unwrap();
    let dlg = DelegationStore::new(state.delegation.clone());
    // SR explicitly chooses 0% brokerage (cycle = -1 global row).
    dlg.set_brokerage_global(&Address::from_raw(w), 0);

    apply_unsigned(&state, &empty_block(1, [0u8; 32], w, 1_699_999_997_000), None)
        .expect("genesis");
    let dp2 = DynamicPropertiesStore::new(state.dyn_props.clone());
    let head_hash = dp2.latest_block_header_hash().unwrap().unwrap();
    apply_unsigned(&state, &empty_block(2, head_hash, w, 1_700_000_000_000), None)
        .expect("block 2 at boundary");

    assert_eq!(dp.current_cycle_number(), 1, "cycle number must advance");

    // The crux: the next cycle's brokerage row must be 0, NOT 20.
    let b1 = dlg.get_brokerage(1, &Address::from_raw(w));
    assert_eq!(
        b1, 0,
        "explicit 0% brokerage must propagate verbatim, not be rewritten to DEFAULT_BROKERAGE"
    );
}

#[test]
fn voter_withdraws_reward_after_full_cycle() {
    // The end-to-end happy path: voter has 100 votes for witness W.
    // We seed cycle 0's reward pool for W, run maintenance to roll
    // it into Vi, then call withdraw_reward and verify the voter's
    // allowance gets the proportional share.
    let state = fresh_state();
    let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
    dp.save_allow_change_delegation(1);
    // The Vi (new) reward algorithm has been effective since cycle 0 —
    // without this the withdraw routes through the legacy per-cycle
    // path (java's pre-ALLOW_NEW_REWARD behavior).
    dp.put_long(b"NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE", 0);
    dp.save_maintenance_time_interval(6 * 3600 * 1000);
    dp.save_next_maintenance_time(1_700_000_000_000);

    let w = addr(0xaa);
    let voter = addr(0xbb);

    // Witness W has 1000 votes total (across all voters).
    let ws = WitnessStore::new(state.witnesses.clone());
    ws.put(
        &Address::from_raw(w),
        &Witness {
            address: w.to_vec(),
            vote_count: 1000,
            ..Default::default()
        },
    ).unwrap();

    // Voter holds 100 of those 1000 votes.
    let accts = AccountStore::new(state.accounts.clone());
    accts.put(
        &Address::from_raw(voter),
        &Account {
            address: voter.to_vec(),
            balance: 0,
            allowance: 0,
            votes: vec![Vote {
                vote_address: w.to_vec(),
                vote_count: 100,
            }],
            ..Default::default()
        },
    ).unwrap();

    // Seed cycle 0 pool for W.
    let dlg = DelegationStore::new(state.delegation.clone());
    dlg.add_reward(0, &Address::from_raw(w), 1_000_000_000);

    // Voter's begin/end cycles default to 0 with REMARK semantics;
    // explicitly initialize so withdraw walks the right window. The
    // chain ALWAYS writes the account_vote snapshot alongside these
    // markers (java's withdrawReward tail / vote settlement), and the
    // single-cycle catch-up pays from that snapshot — so seed it too.
    dlg.set_begin_cycle(&Address::from_raw(voter), 0);
    dlg.set_end_cycle(&Address::from_raw(voter), 1);
    dlg.set_account_vote(
        0,
        &Address::from_raw(voter),
        &Account {
            address: voter.to_vec(),
            votes: vec![Vote {
                vote_address: w.to_vec(),
                vote_count: 100,
            }],
            ..Default::default()
        },
    )
    .unwrap();

    // Apply genesis (num=1) then a boundary block (num=2).
    apply_unsigned(
        &state,
        &empty_block(1, [0u8; 32], w, 1_699_999_997_000),
        None,
    )
    .unwrap();
    let head_hash = dp.latest_block_header_hash().unwrap().unwrap();
    apply_unsigned(
        &state,
        &empty_block(2, head_hash, w, 1_700_000_000_000),
        None,
    )
    .unwrap();

    assert_eq!(dp.current_cycle_number(), 1);

    // Voter claims. Expected reward:
    //   pool_at_accumulation = 1_000_000_000 (seeded)
    //                        + 38_400_000 (block 1 production + standby, 80% to pool)
    //                        + 38_400_000 (block 2 same shape)
    //                        = 1_076_800_000
    //   delta_vi = pool * 1e18 / vote_count = 1_076_800_000 * 1e15
    //   voter share = 100 * delta_vi / 1e18 = 107_680_000
    let paid = tron_tvm::reward::withdraw_reward(
        &Address::from_raw(voter),
        &accts,
        &dlg,
        &dp,
        None,
    )
    .expect("withdraw");
    assert_eq!(
        paid, 107_680_000,
        "voter gets 100/1000 share of (seeded + block 1 + block 2) cycle pool"
    );

    // Allowance reflects the payout.
    let after = accts.get(&Address::from_raw(voter)).unwrap().unwrap();
    assert_eq!(after.allowance, 107_680_000);
}

#[test]
fn maintenance_clears_votes_store_after_tally() {
    // The votes store must be cleared at the end of each maintenance
    // pass — java-tron does this so the next cycle starts fresh. Our
    // apply_maintenance mirrors that.
    let state = fresh_state();
    let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
    dp.save_allow_change_delegation(1);
    dp.save_maintenance_time_interval(6 * 3600 * 1000);
    dp.save_next_maintenance_time(1_700_000_000_000);

    let voter = addr(0xcc);
    let w = addr(0xdd);
    let ws = WitnessStore::new(state.witnesses.clone());
    ws.put(
        &Address::from_raw(w),
        &Witness {
            address: w.to_vec(),
            ..Default::default()
        },
    ).unwrap();

    // Seed a vote.
    let vs = VotesStore::new(state.votes.clone());
    vs.put(
        &Address::from_raw(voter),
        &Votes {
            address: voter.to_vec(),
            old_votes: vec![],
            new_votes: vec![Vote {
                vote_address: w.to_vec(),
                vote_count: 42,
            }],
        },
    ).unwrap();
    assert!(vs.contains(&Address::from_raw(voter)).unwrap());

    apply_unsigned(
        &state,
        &empty_block(1, [0u8; 32], w, 1_699_999_997_000),
        None,
    )
    .unwrap();
    let head_hash = dp.latest_block_header_hash().unwrap().unwrap();
    apply_unsigned(
        &state,
        &empty_block(2, head_hash, w, 1_700_000_000_000),
        None,
    )
    .unwrap();

    // After the maintenance pass, the vote row must be gone.
    assert!(
        !vs.contains(&Address::from_raw(voter)).unwrap(),
        "votes_store must be cleared after maintenance"
    );

    // The witness's vote_count must reflect the 42 we just tallied.
    let updated = ws.get(&Address::from_raw(w)).unwrap().unwrap();
    assert_eq!(updated.vote_count, 42);

    // Witness should now be marked is_jobs=true (joined active list).
    assert!(updated.is_jobs);
}

#[test]
fn block_one_skips_maintenance_but_advances_next_time() {
    // java-tron treats block 1 specially: it's at or past the next
    // maintenance time (because next defaults to 0 and any timestamp
    // qualifies), but doMaintenance is skipped. next_maintenance_time
    // still advances. Mirror that.
    let state = fresh_state();
    let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
    let interval = 6 * 3600 * 1000;
    dp.save_maintenance_time_interval(interval);
    // next_maintenance_time = 0 (default) → block 1 is always at/past
    // the boundary.
    dp.save_allow_change_delegation(1);

    let w = addr(0xee);
    WitnessStore::new(state.witnesses.clone()).put(
        &Address::from_raw(w),
        &Witness {
            address: w.to_vec(),
            ..Default::default()
        },
    ).unwrap();

    let t = 1_700_000_000_000;
    apply_unsigned(&state, &empty_block(1, [0u8; 32], w, t), None).expect("genesis");

    // Cycle MUST still be 0 — doMaintenance didn't run.
    assert_eq!(dp.current_cycle_number(), 0);

    // But next_maintenance_time must have advanced past the block time.
    let next = dp.next_maintenance_time().unwrap_or(0);
    assert!(next > t, "next_maintenance_time must move past block 1");
}
