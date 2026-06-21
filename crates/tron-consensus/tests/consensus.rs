//! Exhaustive consensus tests: slot math, block-witness validation,
//! maintenance boundary detection + SR ranking, fork choice.

use std::sync::Arc;

use tron_chainbase::{
    AccountStore, DelegationStore, DynamicPropertiesStore, KvBackend, MemBackend, VotesStore,
    WitnessScheduleStore, WitnessStore,
};
use tron_consensus::{
    ab_slot, apply_maintenance, best_head, compute_next_maintenance_time, is_maintenance_boundary,
    scheduled_witness, scheduled_witness_index, slot_from_head, slot_time_ms,
    update_active_witnesses, validate_block_consensus, verify_block_witness, ConsensusError,
    ForkChoice, BLOCK_PRODUCED_INTERVAL_MS, MAINTENANCE_SKIP_SLOTS, MAX_ACTIVE_WITNESS_NUM,
};
use tron_crypto::address::Address;
use tron_proto::block_header::Raw as BlockHeaderRaw;
use tron_proto::{Account, Block, BlockHeader, Vote as AccountVote, Votes, Witness};
use tron_types::BlockId;

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn addr(seed: u8) -> Address {
    let mut bytes = [0u8; 21];
    bytes[0] = 0x41;
    for b in bytes.iter_mut().skip(1) {
        *b = seed;
    }
    Address::from_raw(bytes)
}

// =============================================================================
// Slot math
// =============================================================================

/// Genesis is slot 0 exactly. Slot 1 starts at genesis + 3000ms.
#[test]
fn ab_slot_starts_at_zero_and_advances_per_3000ms() {
    let g = 1_700_000_000_000i64;
    assert_eq!(ab_slot(g, g), 0);
    assert_eq!(ab_slot(g + 2_999, g), 0);
    assert_eq!(ab_slot(g + 3_000, g), 1);
    assert_eq!(ab_slot(g + 3_000 + 2_999, g), 1);
    assert_eq!(ab_slot(g + 6_000, g), 2);
    assert_eq!(ab_slot(g + 27 * 3_000, g), 27);
}

#[test]
fn scheduled_witness_index_cycles_through_all_27() {
    let n = MAX_ACTIVE_WITNESS_NUM;
    for slot in 0i64..(2 * n as i64 + 5) {
        let idx = scheduled_witness_index(slot, n);
        assert!(idx < n);
        // Slot k and slot k + n hash to the same index.
        assert_eq!(idx, scheduled_witness_index(slot + n as i64, n));
    }
    // Spot-check three points.
    assert_eq!(scheduled_witness_index(0, 27), 0);
    assert_eq!(scheduled_witness_index(26, 27), 26);
    assert_eq!(scheduled_witness_index(27, 27), 0);
}

#[test]
fn scheduled_witness_returns_correct_address_from_list() {
    let witnesses: Vec<Address> = (0u8..27).map(addr).collect();
    assert_eq!(scheduled_witness(0, &witnesses), witnesses[0]);
    assert_eq!(scheduled_witness(13, &witnesses), witnesses[13]);
    assert_eq!(scheduled_witness(27, &witnesses), witnesses[0]);
    assert_eq!(scheduled_witness(28, &witnesses), witnesses[1]);
}

#[test]
fn scheduled_witness_handles_negative_slot_via_rem_euclid() {
    let _witnesses: Vec<Address> = (0u8..27).map(addr).collect();
    // -1 % 27 in Rust is -1 (truncating). rem_euclid wraps to 26.
    // We expect index 26 for slot=-1.
    assert_eq!(scheduled_witness_index(-1, 27), 26);
    assert_eq!(scheduled_witness_index(-27, 27), 0);
}

#[test]
fn slot_time_ms_advances_by_block_interval() {
    let g = 1_700_000_000_000i64;
    let head = g; // head at genesis exactly
    assert_eq!(slot_time_ms(1, head, g, false, 0), g + BLOCK_PRODUCED_INTERVAL_MS);
    assert_eq!(slot_time_ms(2, head, g, false, 0), g + 2 * BLOCK_PRODUCED_INTERVAL_MS);

    // Head misaligned by 500ms (shouldn't happen for real blocks, but verify
    // the aligning math: the head-time is rounded down to the slot boundary).
    let head_off = g + 5_500; // somewhere between slot 1 and slot 2
    let result = slot_time_ms(1, head_off, g, false, 0);
    // Expect the next slot at g + 6_000 (slot 2) + 1 * interval = g + 9_000 — no,
    // re-reading: `head_aligned = head_off - ((head_off - g) % interval)
    //   = head_off - (5500 % 3000) = head_off - 2500 = g + 3000`. Then add 1 slot
    //   → g + 6_000.
    assert_eq!(result, g + 6_000);
}

// Fix #4 (producer slot math): `slot_from_head` = java `DposSlot.getSlot`,
// which adds `MAINTENANCE_SKIP_SLOTS` to the `getTime(1)` baseline when the
// head block crossed a maintenance boundary. A producer that hardcodes
// `(false, 0)` would fire for the wrong slot right after maintenance.
#[test]
fn slot_from_head_no_maintenance_matches_simple_grid() {
    let g = 1_700_000_001_000i64; // grid-aligned genesis
    let head = g + 10 * BLOCK_PRODUCED_INTERVAL_MS; // slot 10
    // getTime(1) (no maint) = head + 3000. A `now` one interval past it
    // sits in relative slot 2.
    let now = head + 2 * BLOCK_PRODUCED_INTERVAL_MS;
    assert_eq!(slot_from_head(now, head, g, false, 0), 2);
    // Exactly at getTime(1) → relative slot 1.
    assert_eq!(slot_from_head(head + BLOCK_PRODUCED_INTERVAL_MS, head, g, false, 0), 1);
    // Before getTime(1) → 0.
    assert_eq!(slot_from_head(head + 1, head, g, false, 0), 0);
}

#[test]
fn slot_from_head_maintenance_skip_pushes_first_slot_out() {
    assert_eq!(MAINTENANCE_SKIP_SLOTS, 2);
    let g = 1_700_000_001_000i64;
    let head = g + 10 * BLOCK_PRODUCED_INTERVAL_MS; // slot 10
    // With the head a maintenance block, getTime(1) = head + (1+2)*3000.
    let first = head + (1 + MAINTENANCE_SKIP_SLOTS) * BLOCK_PRODUCED_INTERVAL_MS;
    // A `now` that WOULD be relative slot 1 without the skip is still 0 with it.
    let now_no_skip_slot1 = head + BLOCK_PRODUCED_INTERVAL_MS;
    assert_eq!(slot_from_head(now_no_skip_slot1, head, g, false, 0), 1);
    assert_eq!(
        slot_from_head(now_no_skip_slot1, head, g, true, MAINTENANCE_SKIP_SLOTS),
        0,
        "the maintenance skip suppresses the first 2 post-maintenance slots"
    );
    // At the skipped first slot → relative slot 1.
    assert_eq!(slot_from_head(first, head, g, true, MAINTENANCE_SKIP_SLOTS), 1);
    assert_eq!(
        slot_from_head(first + BLOCK_PRODUCED_INTERVAL_MS, head, g, true, MAINTENANCE_SKIP_SLOTS),
        2
    );
}

// =============================================================================
// Block-witness validation
// =============================================================================

fn make_block(num: i64, timestamp: i64, witness: &Address) -> Block {
    Block {
        transactions: Vec::new(),
        block_header: Some(BlockHeader {
            raw_data: Some(BlockHeaderRaw {
                timestamp,
                tx_trie_root: Vec::new(),
                parent_hash: vec![0u8; 32],
                number: num,
                witness_id: 0,
                witness_address: witness.as_bytes().to_vec(),
                version: 28,
                account_state_root: Vec::new(),
            }),
            witness_signature: Vec::new(),
        }),
    }
}

#[test]
fn verify_block_witness_accepts_correctly_scheduled_witness() {
    let witnesses: Vec<Address> = (0u8..27).map(addr).collect();
    let g = 1_700_000_000_000i64;
    // Slot 13 → witness index 13 → witnesses[13].
    let ts = g + 13 * BLOCK_PRODUCED_INTERVAL_MS;
    let block = make_block(14, ts, &witnesses[13]);
    assert!(verify_block_witness(&block, &witnesses, g).is_ok());
}

#[test]
fn verify_block_witness_rejects_wrong_witness() {
    let witnesses: Vec<Address> = (0u8..27).map(addr).collect();
    let g = 1_700_000_000_000i64;
    let ts = g + 13 * BLOCK_PRODUCED_INTERVAL_MS;
    // Block claims witnesses[14] for slot 13's block.
    let block = make_block(14, ts, &witnesses[14]);
    match verify_block_witness(&block, &witnesses, g) {
        Err(ConsensusError::WrongWitness { slot: 13, expected, got }) => {
            assert_eq!(expected, witnesses[13]);
            assert_eq!(got, witnesses[14]);
        }
        other => panic!("expected WrongWitness, got {other:?}"),
    }
}

#[test]
fn verify_block_witness_rejects_invalid_witness_bytes() {
    let witnesses: Vec<Address> = (0u8..27).map(addr).collect();
    let mut block = make_block(1, 1_700_000_000_000, &witnesses[0]);
    block
        .block_header
        .as_mut()
        .unwrap()
        .raw_data
        .as_mut()
        .unwrap()
        .witness_address = vec![1, 2, 3]; // wrong length
    assert_eq!(
        verify_block_witness(&block, &witnesses, 1_700_000_000_000),
        Err(ConsensusError::InvalidWitnessAddress)
    );
}

#[test]
fn verify_block_witness_rejects_empty_active_list() {
    let block = make_block(1, 1_700_000_000_000, &addr(0));
    assert_eq!(
        verify_block_witness(&block, &[], 1_700_000_000_000),
        Err(ConsensusError::EmptyActiveWitnesses)
    );
}

// =============================================================================
// Full block-acceptance gate — java DposService.validBlock
// =============================================================================
//
// Fixtures: 27 witnesses, genesis `G`, head at absolute slot 100 (aligned).
// The first expected slot after the head is `getTime(1) = G + 101*3000`
// (no maintenance), so a block at `G + 101*3000` has relative slot 1 and
// `currentSlot = getAbSlot(head) + 1 = 101`, scheduled witness index
// `101 % 27 = 20`.

// Genesis chosen as a multiple of BLOCK_PRODUCED_INTERVAL_MS so the slot
// grid lines up with java's absolute-epoch alignment check
// (`timeStamp % BLOCK_PRODUCED_INTERVAL == 0`, measured from epoch 0, not
// from genesis). Real mainnet block timestamps are likewise grid-aligned.
const G: i64 = 1_700_000_001_000;
fn head_ts() -> i64 {
    G + 100 * BLOCK_PRODUCED_INTERVAL_MS // absolute slot 100, grid-aligned
}

#[test]
fn validate_block_consensus_accepts_scheduled_next_slot() {
    let witnesses: Vec<Address> = (0u8..27).map(addr).collect();
    let ts = G + 101 * BLOCK_PRODUCED_INTERVAL_MS; // relative slot 1
    let block = make_block(101, ts, &witnesses[20]); // index (100+1)%27 = 20
    assert!(
        validate_block_consensus(&block, &witnesses, head_ts(), G, false, true).is_ok(),
        "a correctly-scheduled next-slot block must pass"
    );
}

#[test]
fn validate_block_consensus_rejects_unscheduled_witness() {
    // Fix #1: correctly-signed-but-wrong-SR. Witness index 20 is due;
    // claim witness 19 instead.
    let witnesses: Vec<Address> = (0u8..27).map(addr).collect();
    let ts = G + 101 * BLOCK_PRODUCED_INTERVAL_MS;
    let block = make_block(101, ts, &witnesses[19]);
    match validate_block_consensus(&block, &witnesses, head_ts(), G, false, true) {
        Err(ConsensusError::WrongWitness { expected, got, .. }) => {
            assert_eq!(expected, witnesses[20]);
            assert_eq!(got, witnesses[19]);
        }
        other => panic!("expected WrongWitness, got {other:?}"),
    }
}

#[test]
fn validate_block_consensus_rejects_same_slot_block() {
    // Fix #3: bSlot <= hSlot is rejected (ungated) even with a correct
    // witness for that slot. A block at the head's own slot (100).
    let witnesses: Vec<Address> = (0u8..27).map(addr).collect();
    let ts = head_ts(); // same absolute slot as head → bSlot == hSlot
    // index for slot 100 = 100 % 27 = 19.
    let block = make_block(100, ts, &witnesses[19]);
    match validate_block_consensus(&block, &witnesses, head_ts(), G, false, false) {
        Err(ConsensusError::NonAdvancingSlot { b_slot: 100, h_slot: 100 }) => {}
        other => panic!("expected NonAdvancingSlot, got {other:?}"),
    }
}

#[test]
fn validate_block_consensus_rejects_backwards_time_block() {
    // Fix #3: a block whose slot is BEFORE the head's is rejected.
    let witnesses: Vec<Address> = (0u8..27).map(addr).collect();
    let ts = G + 99 * BLOCK_PRODUCED_INTERVAL_MS; // slot 99 < head slot 100
    let block = make_block(99, ts, &witnesses[99 % 27]);
    assert!(matches!(
        validate_block_consensus(&block, &witnesses, head_ts(), G, false, false),
        Err(ConsensusError::NonAdvancingSlot { b_slot: 99, h_slot: 100 })
    ));
}

#[test]
fn validate_block_consensus_misalignment_gated_on_optimization() {
    // Fix #3: timestamp not on the 3s grid. Rejected only when
    // allowConsensusLogicOptimization is on.
    let witnesses: Vec<Address> = (0u8..27).map(addr).collect();
    let ts = G + 101 * BLOCK_PRODUCED_INTERVAL_MS + 17; // off the grid by 17ms
    let block = make_block(101, ts, &witnesses[20]);

    // Optimization ON → rejected for misalignment.
    assert!(matches!(
        validate_block_consensus(&block, &witnesses, head_ts(), G, false, true),
        Err(ConsensusError::Misaligned { .. })
    ));

    // Optimization OFF → alignment not enforced. The 17ms still lands in
    // relative slot 1 / currentSlot 101, so the scheduled-witness check
    // (ungated) passes for witness 20.
    assert!(validate_block_consensus(&block, &witnesses, head_ts(), G, false, false).is_ok());
}

#[test]
fn validate_block_consensus_zero_slot_gated_on_optimization() {
    // Fix #3: getSlot == 0 (timestamp hasn't reached the first expected
    // slot after the head). Force it with a timestamp one slot AFTER the
    // head's slot but BEFORE getTime(1): there is none in the aligned case,
    // so use a head misaligned so getTime(1) sits a slot further out.
    //
    // Simpler: a block exactly at getTime(1) minus a hair still advances
    // bSlot, but getSlot rounds to 0. Build head at slot 100 and a block at
    // absolute slot 101 timestamp but shifted just under getTime(1).
    let witnesses: Vec<Address> = (0u8..27).map(addr).collect();
    // getTime(1) = G + 101*3000. A block at G + 101*3000 - 1 has bSlot
    // = (101*3000 - 1)/3000 = 100... that fails monotonicity, not zero-slot.
    // To isolate ZeroSlot we need bSlot > hSlot AND getSlot == 0, which the
    // aligned grid can't produce. Use a maintenance head: getTime(1) jumps
    // by MAINTENANCE_SKIP_SLOTS, leaving a window where bSlot advances but
    // getSlot is still 0.
    let ts = G + 101 * BLOCK_PRODUCED_INTERVAL_MS; // bSlot 101 > hSlot 100
    let block = make_block(101, ts, &witnesses[20]);
    // Head WAS maintenance → getTime(1) = aligned + (1+2)*3000 = G + 103*3000,
    // so ts < getTime(1) → getSlot == 0.
    assert!(matches!(
        validate_block_consensus(&block, &witnesses, head_ts(), G, true, true),
        Err(ConsensusError::ZeroSlot)
    ));
    // Optimization OFF → zero-slot not enforced; falls through to the
    // scheduled-witness check. currentSlot = hSlot + 0 = 100 → index 19,
    // so witness 20 is now WRONG.
    assert!(matches!(
        validate_block_consensus(&block, &witnesses, head_ts(), G, true, false),
        Err(ConsensusError::WrongWitness { .. })
    ));
}

#[test]
fn validate_block_consensus_maintenance_skip_shifts_scheduled_witness() {
    // Fix #3/#4 parity: the maintenance skip is folded into getSlot, and
    // getScheduledWitness indexes (getAbSlot(head) + getSlot) — NOT
    // getAbSlot(blockTime). With a maintenance head, a later block's
    // relative slot is `(ts - getTime(1))/3000 + 1` where getTime(1) is
    // pushed out by MAINTENANCE_SKIP_SLOTS.
    assert_eq!(MAINTENANCE_SKIP_SLOTS, 2);
    let witnesses: Vec<Address> = (0u8..27).map(addr).collect();
    // First producible slot after a maintenance head = G + (100+1+2)*3000.
    let ts = G + 103 * BLOCK_PRODUCED_INTERVAL_MS; // = getTime(1) for maint head
    // getSlot = 1, currentSlot = 100 + 1 = 101, index 20.
    let block = make_block(104, ts, &witnesses[20]);
    assert!(
        validate_block_consensus(&block, &witnesses, head_ts(), G, true, true).is_ok(),
        "maintenance-skip block targets witness via (head_abs_slot + relative_slot)"
    );
    // The naive getAbSlot(blockTime) % 27 would be 103 % 27 = 22 — a
    // DIFFERENT witness — proving the skip-aware path is exercised.
    let block_wrong = make_block(104, ts, &witnesses[22]);
    assert!(matches!(
        validate_block_consensus(&block_wrong, &witnesses, head_ts(), G, true, true),
        Err(ConsensusError::WrongWitness { .. })
    ));
}

// =============================================================================
// Maintenance period
// =============================================================================

#[test]
fn is_maintenance_boundary_fires_at_or_past_next_time() {
    assert!(!is_maintenance_boundary(99, 100));
    assert!(is_maintenance_boundary(100, 100));
    assert!(is_maintenance_boundary(101, 100));
}

#[test]
fn compute_next_maintenance_time_advances_one_interval_past_block() {
    let interval = 6 * 60 * 60 * 1000; // 6h
    let prev = 1_700_000_000_000i64;
    // Block right at the boundary → next is one interval later.
    assert_eq!(
        compute_next_maintenance_time(prev, prev, interval),
        prev + interval
    );
    // Block 2 intervals after prev → jump 3 intervals (so next is past block).
    assert_eq!(
        compute_next_maintenance_time(prev + 2 * interval, prev, interval),
        prev + 3 * interval
    );
}

#[test]
fn compute_next_maintenance_time_noop_when_no_boundary_crossed() {
    let interval = 6 * 60 * 60 * 1000;
    let prev = 1_700_000_000_000i64;
    let block = prev - 1; // before prev → no boundary
    assert_eq!(compute_next_maintenance_time(block, prev, interval), prev);
}

#[test]
fn update_active_witnesses_promotes_top_by_vote_count() {
    let witnesses_be = mem();
    let votes_be = mem();
    let schedule_be = mem();
    let witnesses = WitnessStore::new(witnesses_be);
    let votes = VotesStore::new(votes_be);
    let schedule = WitnessScheduleStore::new(schedule_be);

    // Register 5 candidate witnesses with varying baseline vote_count.
    let candidates: Vec<Address> = (1u8..=5).map(addr).collect();
    for (i, w) in candidates.iter().enumerate() {
        witnesses.put(
            w,
            &Witness {
                address: w.as_bytes().to_vec(),
                vote_count: (i as i64) * 10, // 0, 10, 20, 30, 40
                ..Default::default()
            },
        ).unwrap();
    }

    // Three voters cast new_votes: voter1 → w0 (+100), voter2 → w0 (+50), w3 (+200).
    let voter1 = addr(100);
    let voter2 = addr(101);
    votes.put(
        &voter1,
        &Votes {
            address: voter1.as_bytes().to_vec(),
            old_votes: Vec::new(),
            new_votes: vec![AccountVote {
                vote_address: candidates[0].as_bytes().to_vec(),
                vote_count: 100,
            }],
        },
    ).unwrap();
    votes.put(
        &voter2,
        &Votes {
            address: voter2.as_bytes().to_vec(),
            old_votes: Vec::new(),
            new_votes: vec![
                AccountVote {
                    vote_address: candidates[0].as_bytes().to_vec(),
                    vote_count: 50,
                },
                AccountVote {
                    vote_address: candidates[3].as_bytes().to_vec(),
                    vote_count: 200,
                },
            ],
        },
    ).unwrap();

    let report = update_active_witnesses(
        &witnesses,
        &votes,
        &schedule,
        &[voter1, voter2],
        &candidates,
    )
    .unwrap();

    // After update:
    //   w0: 0 + 150 = 150
    //   w1: 10 + 0 = 10
    //   w2: 20 + 0 = 20
    //   w3: 30 + 200 = 230  ← winner
    //   w4: 40 + 0 = 40
    // Ranking: w3 (230), w0 (150), w4 (40), w2 (20), w1 (10)
    assert_eq!(report.new_active.len(), 5);
    assert_eq!(report.new_active[0], candidates[3]);
    assert_eq!(report.new_active[1], candidates[0]);
    assert_eq!(report.new_active[2], candidates[4]);
    assert_eq!(report.new_active[3], candidates[2]);
    assert_eq!(report.new_active[4], candidates[1]);
    assert!(report.changed); // previous was empty
    // Vote counts accumulated, not replaced.
    assert_eq!(witnesses.get(&candidates[0]).unwrap().unwrap().vote_count, 150);
    assert_eq!(witnesses.get(&candidates[3]).unwrap().unwrap().vote_count, 230);
}

#[test]
fn update_active_witnesses_nets_old_votes_against_new() {
    // java-tron's countVote: delta = Σ new_votes − Σ old_votes. The old
    // list (the voter's votes at its first mutation this cycle) is already
    // baked into each witness's accumulated vote_count, so it must come
    // OFF — a re-vote nets to zero, a moved vote debits the abandoned
    // witness, an unstake-trimmed vote shrinks it.
    let witnesses = WitnessStore::new(mem());
    let votes = VotesStore::new(mem());
    let schedule = WitnessScheduleStore::new(mem());

    let candidates: Vec<Address> = (1u8..=3).map(addr).collect();
    for (w, base) in candidates.iter().zip([1000i64, 500, 0]) {
        witnesses
            .put(
                w,
                &Witness {
                    address: w.as_bytes().to_vec(),
                    vote_count: base,
                    ..Default::default()
                },
            )
            .unwrap();
    }
    let av = |w: &Address, n: i64| AccountVote {
        vote_address: w.as_bytes().to_vec(),
        vote_count: n,
    };

    // voter1 re-votes the exact same 300 on w0 → net 0 (the old code
    // double-counted this as +300).
    let voter1 = addr(100);
    votes
        .put(
            &voter1,
            &Votes {
                address: voter1.as_bytes().to_vec(),
                old_votes: vec![av(&candidates[0], 300)],
                new_votes: vec![av(&candidates[0], 300)],
            },
        )
        .unwrap();
    // voter2 moves 200 votes from w1 to w2 → w1 −200, w2 +200.
    let voter2 = addr(101);
    votes
        .put(
            &voter2,
            &Votes {
                address: voter2.as_bytes().to_vec(),
                old_votes: vec![av(&candidates[1], 200)],
                new_votes: vec![av(&candidates[2], 200)],
            },
        )
        .unwrap();
    // voter3's votes were trimmed by an unstake: 100 → 40 on w1.
    let voter3 = addr(102);
    votes
        .put(
            &voter3,
            &Votes {
                address: voter3.as_bytes().to_vec(),
                old_votes: vec![av(&candidates[1], 100)],
                new_votes: vec![av(&candidates[1], 40)],
            },
        )
        .unwrap();

    update_active_witnesses(
        &witnesses,
        &votes,
        &schedule,
        &[voter1, voter2, voter3],
        &candidates,
    )
    .unwrap();

    // w0: 1000 + (300 − 300) = 1000
    // w1: 500 − 200 + (40 − 100) = 240
    // w2: 0 + 200 = 200
    assert_eq!(witnesses.get(&candidates[0]).unwrap().unwrap().vote_count, 1000);
    assert_eq!(witnesses.get(&candidates[1]).unwrap().unwrap().vote_count, 240);
    assert_eq!(witnesses.get(&candidates[2]).unwrap().unwrap().vote_count, 200);
}

#[test]
fn update_active_witnesses_caps_at_27() {
    let witnesses_be = mem();
    let votes_be = mem();
    let schedule_be = mem();
    let witnesses = WitnessStore::new(witnesses_be);
    let votes = VotesStore::new(votes_be);
    let schedule = WitnessScheduleStore::new(schedule_be);

    // 30 candidates, distinct vote_counts.
    let candidates: Vec<Address> = (1u8..=30).map(addr).collect();
    for (i, w) in candidates.iter().enumerate() {
        witnesses.put(
            w,
            &Witness {
                address: w.as_bytes().to_vec(),
                vote_count: i as i64, // 0..29
                ..Default::default()
            },
        ).unwrap();
    }
    let report =
        update_active_witnesses(&witnesses, &votes, &schedule, &[], &candidates).unwrap();
    assert_eq!(report.new_active.len(), MAX_ACTIVE_WITNESS_NUM); // capped
    // Highest 27 by vote_count: indices 3..30 (vote_count 3..29).
    assert_eq!(report.new_active[0], candidates[29]);
    assert_eq!(report.new_active[26], candidates[3]);
}

#[test]
fn update_active_witnesses_breaks_vote_tie_by_address_bytes_desc() {
    // java `WitnessStore.sortWitnesses` with `isSortOpt = true` (the
    // `allowWitnessSortOptimization` proposal, active on mainnet for years)
    // sorts vote DESC then `createReadableString().reversed()` — the hex of
    // the address DESCENDING, which is byte-order DESCENDING. On a vote tie
    // at the top of the ranking the HIGHER address must come first.
    let witnesses = WitnessStore::new(mem());
    let votes = VotesStore::new(mem());
    let schedule = WitnessScheduleStore::new(mem());

    // Two candidates with identical vote_count; distinct address bytes.
    let low = addr(1);
    let high = addr(2);
    for a in [low, high] {
        witnesses
            .put(
                &a,
                &Witness {
                    address: a.as_bytes().to_vec(),
                    vote_count: 500,
                    ..Default::default()
                },
            )
            .unwrap();
    }

    let report =
        update_active_witnesses(&witnesses, &votes, &schedule, &[], &[low, high]).unwrap();

    // Equal votes → higher address bytes ranks first (DESC tie-break).
    assert_eq!(report.new_active[0], high);
    assert_eq!(report.new_active[1], low);
}

#[test]
fn apply_maintenance_empty_vote_cycle_leaves_active_list_untouched() {
    // java `MaintenanceManager.doMaintenance` wraps updateWitness + reward +
    // isJobs in `if (!countWitness.isEmpty())`. A cycle with no vote
    // mutations (empty `countWitness`) must NOT re-rank, re-`save_active`, pay
    // legacy rewards, or flip `isJobs`: the persisted active list stays
    // exactly as the previous cycle wrote it.
    let witnesses = WitnessStore::new(mem());
    let votes = VotesStore::new(mem());
    let schedule = WitnessScheduleStore::new(mem());
    let accounts = AccountStore::new(mem());
    let delegation = DelegationStore::new(mem());
    let dyn_props = DynamicPropertiesStore::new(mem());

    // Two registered witnesses, ranked low → high by vote_count.
    let w_lo = addr(10);
    let w_hi = addr(20);
    witnesses
        .put(
            &w_lo,
            &Witness {
                address: w_lo.as_bytes().to_vec(),
                vote_count: 100,
                ..Default::default()
            },
        )
        .unwrap();
    witnesses
        .put(
            &w_hi,
            &Witness {
                address: w_hi.as_bytes().to_vec(),
                vote_count: 200,
                ..Default::default()
            },
        )
        .unwrap();

    // Seed a STALE persisted active list that does NOT match the current
    // vote-count ranking — if the gate is broken, the no-op cycle would
    // re-rank and overwrite this with [w_hi, w_lo].
    let stale_active = vec![w_lo];
    schedule.save_active(&stale_active).unwrap();

    // No voter records at all → countWitness is empty.
    let outcome = apply_maintenance(
        &witnesses,
        &votes,
        &schedule,
        &accounts,
        &delegation,
        &dyn_props,
    )
    .unwrap();

    // Active list left exactly as it was — no re-rank, no save.
    assert_eq!(schedule.load_active().unwrap().unwrap(), stale_active);
    assert_eq!(outcome.new_active, stale_active);
    assert!(!outcome.changed);
    // Vote counts untouched (no accumulation step ran).
    assert_eq!(witnesses.get(&w_lo).unwrap().unwrap().vote_count, 100);
    assert_eq!(witnesses.get(&w_hi).unwrap().unwrap().vote_count, 200);
    // Legacy reward (flag off by default in fresh dyn_props) did not pay out.
    assert!(accounts.get(&w_lo).unwrap().is_none());
    assert!(accounts.get(&w_hi).unwrap().is_none());
}

#[test]
fn apply_maintenance_nonempty_vote_cycle_reranks_and_saves() {
    // The companion to the empty-cycle no-op: with a real vote mutation,
    // `countWitness` is non-empty so the re-rank + save_active DO run.
    let witnesses = WitnessStore::new(mem());
    let votes = VotesStore::new(mem());
    let schedule = WitnessScheduleStore::new(mem());
    let accounts = AccountStore::new(mem());
    let delegation = DelegationStore::new(mem());
    let dyn_props = DynamicPropertiesStore::new(mem());

    let w_a = addr(10);
    let w_b = addr(20);
    witnesses
        .put(
            &w_a,
            &Witness {
                address: w_a.as_bytes().to_vec(),
                vote_count: 100,
                ..Default::default()
            },
        )
        .unwrap();
    witnesses
        .put(
            &w_b,
            &Witness {
                address: w_b.as_bytes().to_vec(),
                vote_count: 200,
                ..Default::default()
            },
        )
        .unwrap();
    schedule.save_active(&[w_b, w_a]).unwrap();

    // A voter pushes w_a past w_b: +500 to w_a.
    let voter = addr(100);
    votes
        .put(
            &voter,
            &Votes {
                address: voter.as_bytes().to_vec(),
                old_votes: Vec::new(),
                new_votes: vec![AccountVote {
                    vote_address: w_a.as_bytes().to_vec(),
                    vote_count: 500,
                }],
            },
        )
        .unwrap();

    let outcome = apply_maintenance(
        &witnesses,
        &votes,
        &schedule,
        &accounts,
        &delegation,
        &dyn_props,
    )
    .unwrap();

    // w_a now 600 > w_b 200 → re-ranked and persisted.
    assert_eq!(witnesses.get(&w_a).unwrap().unwrap().vote_count, 600);
    assert_eq!(outcome.new_active, vec![w_a, w_b]);
    assert!(outcome.changed);
    assert_eq!(schedule.load_active().unwrap().unwrap(), vec![w_a, w_b]);
    // Votes store cleared for the next cycle.
    assert!(votes.get(&voter).unwrap().is_none());
}

#[test]
fn apply_maintenance_legacy_reward_selects_first_127_by_address_not_vote() {
    // Legacy `IncentiveManager.reward` (allowChangeDelegation == 0, the default
    // on a fresh store) pays the FIRST 127 witnesses in `getAllWitnesses()`
    // DB-iteration order (address ascending) — NOT the top-127 by vote. With
    // more than 127 registered witnesses these are different sets: the
    // highest-address witness is excluded even if it holds the largest vote.
    let witnesses = WitnessStore::new(mem());
    let votes = VotesStore::new(mem());
    let schedule = WitnessScheduleStore::new(mem());
    let accounts = AccountStore::new(mem());
    let delegation = DelegationStore::new(mem());
    let dyn_props = DynamicPropertiesStore::new(mem());

    // 128 registered witnesses, addresses ascending by seed 1..=128.
    // Give every witness a uniform vote of 100 EXCEPT the highest-address
    // one (seed 128), which holds the largest vote (10_000). A vote-sorted
    // top-127 would keep seed 128 and drop a uniform-vote witness; the
    // DB-order first-127 keeps seeds 1..=127 and drops seed 128.
    const N: u8 = 128;
    for seed in 1..=N {
        let a = addr(seed);
        let vote = if seed == N { 10_000 } else { 100 };
        witnesses
            .put(
                &a,
                &Witness {
                    address: a.as_bytes().to_vec(),
                    vote_count: vote,
                    ..Default::default()
                },
            )
            .unwrap();
        // A registered witness always has an account on a real chain (java's
        // `getAccount` returns it). Seed it with zero allowance so the legacy
        // reward only adds to an existing row.
        accounts
            .put(
                &a,
                &Account {
                    address: a.as_bytes().to_vec(),
                    ..Default::default()
                },
            )
            .unwrap();
    }

    // A vote mutation so `countWitness` is non-empty (java wraps the reward in
    // `if (!countWitness.isEmpty())`). Vote for the lowest-address witness.
    let voter = addr(200);
    votes
        .put(
            &voter,
            &Votes {
                address: voter.as_bytes().to_vec(),
                old_votes: Vec::new(),
                new_votes: vec![AccountVote {
                    vote_address: addr(1).as_bytes().to_vec(),
                    vote_count: 0,
                }],
            },
        )
        .unwrap();

    apply_maintenance(
        &witnesses,
        &votes,
        &schedule,
        &accounts,
        &delegation,
        &dyn_props,
    )
    .unwrap();

    // The first-127 subset is seeds 1..=127 (all vote 100). voteSum = 127*100
    // = 12_700, totalPay = 115_200_000_000 (default WITNESS_STANDBY_ALLOWANCE).
    // Each is paid (long)(100 * (115_200_000_000 / 12_700)).
    let total_pay: i64 = dyn_props.witness_standby_allowance();
    let vote_sum: i64 = 127 * 100;
    let each_vote_pay = total_pay as f64 / vote_sum as f64;
    let expected_pay = (100.0_f64 * each_vote_pay) as i64;
    assert!(expected_pay > 0);

    // An included low-address witness is paid the expected amount.
    assert_eq!(
        accounts.get(&addr(1)).unwrap().unwrap().allowance,
        expected_pay
    );
    // The highest-address witness (seed 128) is OUTSIDE the first-127 even
    // though it holds the largest vote — its allowance stays 0.
    assert_eq!(accounts.get(&addr(N)).unwrap().unwrap().allowance, 0);
}

#[test]
fn apply_maintenance_legacy_reward_pays_unconditionally_when_rounding_to_zero() {
    // java `IncentiveManager.reward` calls `setAllowance(allowance + pay)` for
    // every witness in the subset with NO `pay > 0` guard. A witness whose
    // floored share rounds to 0 is still touched (allowance unchanged, account
    // persisted). Verify a tiny-vote witness alongside a whale rounds to 0 pay
    // yet the dominant witness is still paid the bulk.
    let witnesses = WitnessStore::new(mem());
    let votes = VotesStore::new(mem());
    let schedule = WitnessScheduleStore::new(mem());
    let accounts = AccountStore::new(mem());
    let delegation = DelegationStore::new(mem());
    let dyn_props = DynamicPropertiesStore::new(mem());

    // Two witnesses: a whale (huge vote) and a dust witness whose floored
    // share `(long)(1 * (totalPay / voteSum))` rounds to 0 because the whale
    // dominates voteSum.
    let whale = addr(10);
    let dust = addr(20);
    let whale_vote = 115_200_000_000i64; // makes per-vote pay ~= 1 sun
    witnesses
        .put(
            &whale,
            &Witness {
                address: whale.as_bytes().to_vec(),
                vote_count: whale_vote,
                ..Default::default()
            },
        )
        .unwrap();
    witnesses
        .put(
            &dust,
            &Witness {
                address: dust.as_bytes().to_vec(),
                vote_count: 0, // contributes nothing, rounds to 0 pay
                ..Default::default()
            },
        )
        .unwrap();
    // Both witnesses have accounts (java's `getAccount` is non-null for a
    // registered witness). Seed both with zero allowance.
    for w in [&whale, &dust] {
        accounts
            .put(
                w,
                &Account {
                    address: w.as_bytes().to_vec(),
                    ..Default::default()
                },
            )
            .unwrap();
    }

    let voter = addr(200);
    votes
        .put(
            &voter,
            &Votes {
                address: voter.as_bytes().to_vec(),
                old_votes: Vec::new(),
                new_votes: vec![AccountVote {
                    vote_address: whale.as_bytes().to_vec(),
                    vote_count: 0,
                }],
            },
        )
        .unwrap();

    apply_maintenance(
        &witnesses,
        &votes,
        &schedule,
        &accounts,
        &delegation,
        &dyn_props,
    )
    .unwrap();

    // voteSum = whale_vote + 0. each_vote_pay = totalPay / whale_vote.
    let total_pay: i64 = dyn_props.witness_standby_allowance();
    let each_vote_pay = total_pay as f64 / whale_vote as f64;
    let whale_pay = (whale_vote as f64 * each_vote_pay) as i64;
    assert_eq!(accounts.get(&whale).unwrap().unwrap().allowance, whale_pay);
    // Dust witness: pay rounds to 0. java still calls setAllowance/saveAccount,
    // so the account row is written with an unchanged (zero) allowance.
    let dust_acct = accounts.get(&dust).unwrap();
    assert!(dust_acct.is_some());
    assert_eq!(dust_acct.unwrap().allowance, 0);
}

// =============================================================================
// Fork choice
// =============================================================================

fn bid(num: i64, last_byte: u8) -> BlockId {
    let mut bytes = [0u8; 32];
    bytes[0..8].copy_from_slice(&num.to_be_bytes());
    bytes[31] = last_byte;
    BlockId::from_raw(bytes)
}

#[test]
fn best_head_picks_highest_number() {
    let candidates = vec![
        ForkChoice { head: bid(100, 0xaa), number: 100 },
        ForkChoice { head: bid(105, 0xff), number: 105 },
        ForkChoice { head: bid(102, 0x00), number: 102 },
    ];
    let best = best_head(&candidates).unwrap();
    assert_eq!(best.number, 105);
}

#[test]
fn best_head_breaks_tie_by_lex_block_id_smaller_wins() {
    let lo = bid(100, 0x01);
    let hi = bid(100, 0xff);
    let candidates = vec![
        ForkChoice { head: hi, number: 100 },
        ForkChoice { head: lo, number: 100 },
    ];
    let best = best_head(&candidates).unwrap();
    assert_eq!(best.head, lo);
}

#[test]
fn best_head_returns_error_on_empty_input() {
    let candidates: Vec<ForkChoice> = vec![];
    assert!(best_head(&candidates).is_err());
}

// =============================================================================
// REMOVE_THE_POWER_OF_THE_GR (genesis SR power removal)
// =============================================================================

/// When `REMOVE_THE_POWER_OF_THE_GR == 1`, the next maintenance subtracts
/// each genesis Super Representative's original bootstrap vote_count from its
/// accumulated total, then marks the flag spent (`-1`). Mirrors
/// `MaintenanceManager.tryRemoveThePowerOfTheGr`.
#[test]
fn apply_maintenance_removes_gr_power_when_armed() {
    let witnesses = WitnessStore::new(mem());
    let votes = VotesStore::new(mem());
    let schedule = WitnessScheduleStore::new(mem());
    let accounts = AccountStore::new(mem());
    let delegation = DelegationStore::new(mem());
    let dyn_props = DynamicPropertiesStore::new(mem());

    // Seed two real genesis SRs with their bootstrap vote plus some
    // accumulated real votes on top.
    let grs = tron_types::mainnet_witnesses();
    let g0 = &grs[0]; // GR1, bootstrap vote 100_000_026
    let g1 = &grs[1]; // GR2, bootstrap vote 100_000_025
    let a0 = Address::from_raw(g0.address);
    let a1 = Address::from_raw(g1.address);
    let extra0 = 500i64;
    let extra1 = 700i64;
    witnesses
        .put(
            &a0,
            &Witness {
                address: a0.as_bytes().to_vec(),
                vote_count: g0.vote_count + extra0,
                ..Default::default()
            },
        )
        .unwrap();
    witnesses
        .put(
            &a1,
            &Witness {
                address: a1.as_bytes().to_vec(),
                vote_count: g1.vote_count + extra1,
                ..Default::default()
            },
        )
        .unwrap();

    // Arm the flag (as an approved proposal #10 would).
    dyn_props.put_long(b"REMOVE_THE_POWER_OF_THE_GR", 1);

    apply_maintenance(
        &witnesses,
        &votes,
        &schedule,
        &accounts,
        &delegation,
        &dyn_props,
    )
    .unwrap();

    // The genesis bootstrap votes are gone; only the real votes remain.
    assert_eq!(witnesses.get(&a0).unwrap().unwrap().vote_count, extra0);
    assert_eq!(witnesses.get(&a1).unwrap().unwrap().vote_count, extra1);
    // Flag is now spent.
    assert_eq!(dyn_props.get_long(b"REMOVE_THE_POWER_OF_THE_GR"), Some(-1));
}

/// The removal is a strict once-only: a second maintenance with the flag at
/// `-1` must NOT subtract the genesis votes again.
#[test]
fn apply_maintenance_gr_power_removal_is_once_only() {
    let witnesses = WitnessStore::new(mem());
    let votes = VotesStore::new(mem());
    let schedule = WitnessScheduleStore::new(mem());
    let accounts = AccountStore::new(mem());
    let delegation = DelegationStore::new(mem());
    let dyn_props = DynamicPropertiesStore::new(mem());

    let g0 = &tron_types::mainnet_witnesses()[0];
    let a0 = Address::from_raw(g0.address);
    witnesses
        .put(
            &a0,
            &Witness {
                address: a0.as_bytes().to_vec(),
                vote_count: 1234,
                ..Default::default()
            },
        )
        .unwrap();

    // Already-spent flag → no-op.
    dyn_props.put_long(b"REMOVE_THE_POWER_OF_THE_GR", -1);
    apply_maintenance(
        &witnesses, &votes, &schedule, &accounts, &delegation, &dyn_props,
    )
    .unwrap();
    assert_eq!(witnesses.get(&a0).unwrap().unwrap().vote_count, 1234);
    assert_eq!(dyn_props.get_long(b"REMOVE_THE_POWER_OF_THE_GR"), Some(-1));

    // Default `0` (never armed) → also a no-op.
    let dyn_props2 = DynamicPropertiesStore::new(mem());
    dyn_props2.put_long(b"REMOVE_THE_POWER_OF_THE_GR", 0);
    apply_maintenance(
        &witnesses, &votes, &schedule, &accounts, &delegation, &dyn_props2,
    )
    .unwrap();
    assert_eq!(witnesses.get(&a0).unwrap().unwrap().vote_count, 1234);
    assert_eq!(dyn_props2.get_long(b"REMOVE_THE_POWER_OF_THE_GR"), Some(0));
}
