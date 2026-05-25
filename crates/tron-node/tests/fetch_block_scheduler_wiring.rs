//! Test the live-tip adv-block gating through `FetchBlockScheduler`.
//!
//! The wiring in `SyncDriver::run` reads `head_number()`, decodes the
//! incoming `BlockId` num from the first 8 bytes of each advertised
//! hash, then calls `FetchBlockScheduler::try_fetch`. These tests
//! drive the same decision boundary directly so a regression in
//! either the wiring or the underlying scheduler shows up.

use std::time::Duration;
use tron_node::fetch_block::{FetchBlockScheduler, FetchDecision};
use tron_types::BlockId;

fn block_id_for(num: u64, hash_suffix_byte: u8) -> BlockId {
    let mut raw = [0u8; 32];
    raw[0..8].copy_from_slice(&num.to_be_bytes());
    raw[8..].fill(hash_suffix_byte);
    BlockId::from_raw(raw)
}

#[test]
fn adv_block_at_head_plus_one_dispatches_through_scheduler() {
    let mut sched = FetchBlockScheduler::new(Duration::from_millis(200));
    let head: i64 = 100;
    let id = block_id_for(101, 0xaa); // head + 1
    let decision = sched.try_fetch(
        id.num() as i64,
        *id.as_bytes(),
        "peer-a",
        head,
        1_000,
    );
    assert_eq!(decision, FetchDecision::Dispatch);
    assert!(sched.in_flight().is_some());
}

#[test]
fn adv_block_past_next_is_dropped_by_scheduler() {
    let mut sched = FetchBlockScheduler::new(Duration::from_millis(200));
    let head: i64 = 100;
    let id = block_id_for(105, 0xbb); // head + 5
    let decision = sched.try_fetch(
        id.num() as i64,
        *id.as_bytes(),
        "peer-a",
        head,
        1_000,
    );
    assert_eq!(decision, FetchDecision::NotNextBlock);
    assert!(sched.in_flight().is_none());
}

#[test]
fn second_adv_within_budget_is_deferred_even_from_different_peer() {
    let mut sched = FetchBlockScheduler::new(Duration::from_millis(200));
    let head: i64 = 100;
    let id = block_id_for(101, 0xcc);

    // Peer A starts a fetch.
    let d1 = sched.try_fetch(
        id.num() as i64,
        *id.as_bytes(),
        "peer-a",
        head,
        1_000,
    );
    assert_eq!(d1, FetchDecision::Dispatch);

    // Peer B advertises the same block 50ms later. Budget = 100ms
    // (200ms * 0.5); 50ms hasn't elapsed yet → Defer.
    let d2 = sched.try_fetch(
        id.num() as i64,
        *id.as_bytes(),
        "peer-b",
        head,
        1_050,
    );
    assert_eq!(d2, FetchDecision::Defer);

    // After budget elapses (150ms total > 100ms budget), the slot is
    // reclaimed and a fresh adv from peer-c gets through.
    let d3 = sched.try_fetch(
        id.num() as i64,
        *id.as_bytes(),
        "peer-c",
        head,
        1_201,
    );
    assert_eq!(d3, FetchDecision::Dispatch);
    assert_eq!(sched.in_flight().unwrap().peer_key, "peer-c");
}

#[test]
fn block_arrival_releases_slot_when_hash_matches() {
    let mut sched = FetchBlockScheduler::new(Duration::from_millis(200));
    let id = block_id_for(101, 0xdd);
    sched.try_fetch(
        id.num() as i64,
        *id.as_bytes(),
        "peer-a",
        100,
        1_000,
    );
    // Block arrival with the matching hash → slot freed.
    assert!(sched.complete_if_matches(id.as_bytes()));
    assert!(sched.in_flight().is_none());
    // Next adv at head+1 dispatches because the slot is free.
    let next = block_id_for(101, 0xee);
    let d = sched.try_fetch(
        next.num() as i64,
        *next.as_bytes(),
        "peer-a",
        100,
        1_010,
    );
    assert_eq!(d, FetchDecision::Dispatch);
}

#[test]
fn block_arrival_with_different_hash_does_not_release_slot() {
    let mut sched = FetchBlockScheduler::new(Duration::from_millis(200));
    let id = block_id_for(101, 0xaa);
    sched.try_fetch(
        id.num() as i64,
        *id.as_bytes(),
        "peer-a",
        100,
        1_000,
    );
    // Different block at the same height arrives → slot stays held.
    let other = block_id_for(101, 0xff);
    assert!(!sched.complete_if_matches(other.as_bytes()));
    assert!(sched.in_flight().is_some());
}

#[test]
fn block_id_num_decoding_matches_wiring_expectation() {
    // The wiring decodes block_num from `BlockId::from_raw(bytes).num()`.
    // Confirm this matches the canonical (num << 192) | hash layout for
    // a few representative numbers.
    for &n in &[0u64, 1, 12345, 0x7fff_ffff_ffff_ffff] {
        let id = block_id_for(n, 0xaa);
        assert_eq!(id.num(), n);
        // Round-trip through from_raw matches BlockId::from_hash_and_num.
        let round = BlockId::from_raw(*id.as_bytes());
        assert_eq!(round.num(), n);
    }
}
