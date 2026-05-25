//! Tests for the PBFT block-solidification pure function.

use tron_consensus::{latest_solid_block, solidity_threshold, RecentBlock};
use tron_crypto::address::Address;

fn witness(byte: u8) -> Address {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(byte);
    Address::from_raw(a)
}

fn block(num: i64, w: u8) -> RecentBlock {
    RecentBlock {
        num,
        witness: witness(w),
    }
}

#[test]
fn threshold_is_two_thirds_ceil() {
    assert_eq!(solidity_threshold(27), 18, "27 * 2/3 = 18");
    assert_eq!(solidity_threshold(3), 2);
    assert_eq!(solidity_threshold(1), 1);
    assert_eq!(solidity_threshold(0), 0);
    assert_eq!(solidity_threshold(6), 4);
    assert_eq!(solidity_threshold(7), 5); // 14/3 = 4.67 → 5
}

#[test]
fn latest_solid_with_enough_distinct_witnesses() {
    // 27 active, threshold = 18. Provide a window where 18 distinct
    // witnesses signed the recent 20 blocks. The earliest block that
    // saw the threshold reached should be returned.
    let mut recent = Vec::new();
    // Newest first: block 100 down to 81.
    // Witnesses 0..17 sign one each = 18 distinct (block 100..83).
    // Block 83 is the one that first reaches threshold (it's where
    // the 18th distinct witness appears).
    for i in 0..18u8 {
        recent.push(block(100 - i as i64, i));
    }
    // Pad with duplicates further back.
    for i in 18..25u8 {
        recent.push(block(100 - i as i64, 0));
    }
    let solid = latest_solid_block(&recent, 27).unwrap();
    assert_eq!(solid, 100 - 17, "expected the 18th block back (block 83)");
}

#[test]
fn latest_solid_returns_none_when_window_too_small() {
    // Only 5 distinct witnesses in the window, but threshold = 18.
    let recent: Vec<RecentBlock> = (0..5u8).map(|i| block(100 - i as i64, i)).collect();
    assert!(latest_solid_block(&recent, 27).is_none());
}

#[test]
fn duplicate_witnesses_dont_count_twice() {
    // Active = 3, threshold = 2.
    // Recent: [A, A, A, A, B] — only 2 distinct, threshold met at block 1.
    let recent = vec![
        block(5, 0),
        block(4, 0),
        block(3, 0),
        block(2, 0),
        block(1, 1),
    ];
    let solid = latest_solid_block(&recent, 3).unwrap();
    assert_eq!(solid, 1);
}

#[test]
fn single_witness_active_set_solidifies_immediately() {
    // Active = 1, threshold = 1: the head is always solid.
    let recent = vec![block(42, 0)];
    let solid = latest_solid_block(&recent, 1).unwrap();
    assert_eq!(solid, 42);
}

#[test]
fn empty_window_is_none() {
    assert!(latest_solid_block(&[], 27).is_none());
}
