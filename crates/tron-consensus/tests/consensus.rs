//! Exhaustive consensus tests: slot math, block-witness validation,
//! maintenance boundary detection + SR ranking, fork choice.

use std::sync::Arc;

use tron_chainbase::{KvBackend, MemBackend, VotesStore, WitnessScheduleStore, WitnessStore};
use tron_consensus::{
    ab_slot, best_head, compute_next_maintenance_time, is_maintenance_boundary, scheduled_witness,
    scheduled_witness_index, slot_time_ms, update_active_witnesses, verify_block_witness,
    ConsensusError, ForkChoice, BLOCK_PRODUCED_INTERVAL_MS, MAX_ACTIVE_WITNESS_NUM,
};
use tron_crypto::address::Address;
use tron_proto::block_header::Raw as BlockHeaderRaw;
use tron_proto::{Block, BlockHeader, Vote as AccountVote, Votes, Witness};
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
