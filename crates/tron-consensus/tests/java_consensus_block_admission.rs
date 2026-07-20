//! Block-message admission and producer packing bounds, pinned against the
//! behaviour java-tron's own test suite and handlers assert.
//!
//! Sources:
//!   * `org.tron.core.net.messagehandler.BlockMsgHandler.processMessage` — the
//!     two checks every inbound `Block` message faces before any handler sees
//!     it (`maxBlockSize = BLOCK_SIZE + Constant.ONE_THOUSAND`, and
//!     `timeStamp - now >= BLOCK_PRODUCED_INTERVAL`).
//!   * `org.tron.core.db.Manager.generateBlock` — the running
//!     `currentSize + trxPackSize > ChainConstant.BLOCK_SIZE` packing budget.
//!   * `org.tron.core.capsule.TransactionCapsule.computeTrxSizeForBlockMessage`
//!     — `CodedOutputStream.computeMessageSize(1, transaction)`.
//!
//! These bounds are not consensus rules in the state-transition sense: a block
//! past them is still structurally valid. They are *network* rules. A block
//! that violates either is discarded by every java peer before validation, so
//! producing or relaying one strands it.

use tron_consensus::{
    check_block_message_admission, tx_fits_in_block, tx_pack_size, BlockAdmissionError, BLOCK_SIZE,
    MAX_BLOCK_MESSAGE_SIZE,
};

/// java `BlockMsgHandler.maxBlockSize = BLOCK_SIZE + Constant.ONE_THOUSAND`,
/// with `ChainConstant.BLOCK_SIZE = 2_000_000` and `Constant.ONE_THOUSAND =
/// 1000`.
#[test]
fn block_size_constants_match_java_tron() {
    assert_eq!(BLOCK_SIZE, 2_000_000);
    assert_eq!(MAX_BLOCK_MESSAGE_SIZE, 2_001_000);
}

#[test]
fn block_at_the_wire_size_limit_is_admitted() {
    // java compares with `>`, so exactly `maxBlockSize` passes.
    assert_eq!(
        check_block_message_admission(MAX_BLOCK_MESSAGE_SIZE, 1_000, 1_000),
        Ok(())
    );
}

#[test]
fn block_over_the_wire_size_limit_is_rejected() {
    assert_eq!(
        check_block_message_admission(MAX_BLOCK_MESSAGE_SIZE + 1, 1_000, 1_000),
        Err(BlockAdmissionError::SizeOverLimit {
            size: MAX_BLOCK_MESSAGE_SIZE + 1
        })
    );
}

/// java: `gap = timestamp - now; if (gap >= BLOCK_PRODUCED_INTERVAL) throw`.
/// A block up to one slot early is fine — SR/peer clock skew routinely puts a
/// fresh tip a few hundred ms ahead — but a full slot or more is not.
#[test]
fn block_less_than_one_slot_ahead_is_admitted() {
    let now = 1_700_000_000_000i64;
    assert_eq!(check_block_message_admission(1_000, now + 2_999, now), Ok(()));
    assert_eq!(check_block_message_admission(1_000, now, now), Ok(()));
}

#[test]
fn block_a_full_slot_ahead_is_rejected() {
    let now = 1_700_000_000_000i64;
    assert_eq!(
        check_block_message_admission(1_000, now + 3_000, now),
        Err(BlockAdmissionError::TimeTooFarAhead {
            timestamp: now + 3_000,
            gap_ms: 3_000,
        })
    );
}

/// Historical blocks — every block a syncing node replays — are far in the
/// past, so the future-time bound never touches bulk sync.
#[test]
fn historical_blocks_are_always_admitted_on_time() {
    let now = 1_700_000_000_000i64;
    assert_eq!(check_block_message_admission(500_000, 1_529_891_469_000, now), Ok(()));
}

/// The size check runs before the time check, matching java's order, so an
/// oversize block reports the size failure even when its timestamp is also bad.
#[test]
fn size_is_checked_before_time() {
    let now = 1_700_000_000_000i64;
    assert!(matches!(
        check_block_message_admission(MAX_BLOCK_MESSAGE_SIZE + 1, now + 10_000, now),
        Err(BlockAdmissionError::SizeOverLimit { .. })
    ));
}

/// java `computeTrxSizeForBlockMessage` = `computeMessageSize(1, tx)`: one tag
/// byte, a varint length prefix, then the payload.
#[test]
fn tx_pack_size_matches_coded_output_stream_message_size() {
    // < 128 bytes → 1-byte varint length.
    assert_eq!(tx_pack_size(0), 2);
    assert_eq!(tx_pack_size(1), 3);
    assert_eq!(tx_pack_size(127), 129);
    // 128..=16383 → 2-byte varint length.
    assert_eq!(tx_pack_size(128), 131);
    assert_eq!(tx_pack_size(16_383), 16_386);
    // 16384..=2097151 → 3-byte varint length.
    assert_eq!(tx_pack_size(16_384), 16_388);
}

/// java compares `(currentSize + trxPackSize) > BLOCK_SIZE`, so landing
/// exactly on the budget is allowed.
#[test]
fn packing_budget_admits_a_tx_landing_exactly_on_block_size() {
    assert!(tx_fits_in_block(BLOCK_SIZE - 100, 100));
    assert!(!tx_fits_in_block(BLOCK_SIZE - 100, 101));
}

/// java `continue`s rather than `break`s on an overflowing transaction, so a
/// smaller one later in the queue is still packed. A producer that packs by
/// count alone, with no byte budget, would blow past the network's limit — the
/// gap this budget closes.
#[test]
fn packing_budget_skips_oversize_and_keeps_room_for_smaller() {
    let mut current = 0usize;
    let mut packed = Vec::new();
    // A count-only cap of 1000 with these sizes would serialize to ~3.1MB,
    // over `MAX_BLOCK_MESSAGE_SIZE`, and be dropped by every java peer.
    for (i, tx_size) in [1_500_000usize, 900_000, 1_400_000, 90_000]
        .into_iter()
        .enumerate()
    {
        let pack = tx_pack_size(tx_size);
        if !tx_fits_in_block(current, pack) {
            continue;
        }
        current += pack;
        packed.push(i);
    }
    assert_eq!(packed, vec![0, 3], "skip the two that overflow, keep the small one");
    assert!(current <= BLOCK_SIZE);
    assert!(current <= MAX_BLOCK_MESSAGE_SIZE);
}
