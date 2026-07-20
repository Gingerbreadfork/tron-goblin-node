//! The `ChainInventory` we serve, checked against the rules a java-tron peer
//! applies to it on receipt.
//!
//! `SyncBlockChainMsgHandler` answers a peer's locator with
//! `ChainInventoryMessage(blockIds, remainNum)`, and the peer runs
//! `ChainInventoryMsgHandler.check` over it. That check throws `BAD_MESSAGE`
//! — and the connection is torn down — on any of:
//!
//!   * `blockIds` empty;
//!   * `blockIds.size() > SYNC_FETCH_BATCH_NUM + 1` (2001);
//!   * `remainNum != 0 && blockIds.size() < SYNC_FETCH_BATCH_NUM` (2000);
//!   * ids not consecutive by block number ("not continuous block");
//!   * `blockIds.get(0)` absent from the locator the peer sent
//!     ("unlinked block").
//!
//! java's own answer satisfies these by construction:
//! `getBlockIds(unForkNum, headID)` walks `unForkNum..=min(headNum, unForkNum +
//! SYNC_FETCH_BATCH_NUM)` and `remainNum` is `headID.getNum() -
//! blockIds.peekLast().getNum()`, reported as 0 for a single-id answer. These
//! tests hold our `serve_sync_block_chain_ids` to the same invariants, since
//! violating any of them makes java peers drop us mid-sync.

use std::sync::Arc;
use tron_chainbase::{BlockIndexStore, KvBackend, MemBackend};
use tron_node::sync::serve_sync_block_chain_ids;
use tron_types::BlockId;

/// java `NetConstants.SYNC_FETCH_BATCH_NUM`.
const SYNC_FETCH_BATCH_NUM: i64 = 2000;

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

/// A `BlockId` carries its number in the leading 8 bytes, so a distinct
/// `suffix` per chain gives two chains that disagree at every height.
fn id_at(num: i64, suffix: u8) -> BlockId {
    let mut raw = [0u8; 32];
    raw[0..8].copy_from_slice(&(num as u64).to_be_bytes());
    raw[8..].fill(suffix);
    BlockId::from_raw(raw)
}

/// Index blocks `1..=head` under `suffix` and return the store.
fn indexed_chain(head: i64, suffix: u8) -> BlockIndexStore {
    let bi = BlockIndexStore::new(mem());
    for num in 1..=head {
        bi.put(&id_at(num, suffix)).unwrap();
    }
    bi
}

fn locator(nums: &[i64], suffix: u8) -> Vec<tron_proto::block_inventory::BlockId> {
    nums.iter()
        .map(|&n| tron_proto::block_inventory::BlockId {
            hash: id_at(n, suffix).as_bytes().to_vec(),
            number: n,
        })
        .collect()
}

/// Re-implementation of java `ChainInventoryMsgHandler.check`, restricted to
/// the parts that depend only on the answer itself plus the locator. Returns
/// the java exception message on rejection.
fn java_chain_inventory_check(
    ids: &[BlockId],
    remain_num: i64,
    peer_locator: &[tron_proto::block_inventory::BlockId],
) -> Result<(), String> {
    if ids.is_empty() {
        return Err("blockIds is empty".into());
    }
    if ids.len() as i64 > SYNC_FETCH_BATCH_NUM + 1 {
        return Err(format!("big blockIds size: {}", ids.len()));
    }
    if remain_num != 0 && (ids.len() as i64) < SYNC_FETCH_BATCH_NUM {
        return Err(format!(
            "remain: {}, blockIds size: {}",
            remain_num,
            ids.len()
        ));
    }
    let mut expected = ids[0].num();
    for id in ids {
        if id.num() != expected {
            return Err("not continuous block".into());
        }
        expected += 1;
    }
    if !peer_locator
        .iter()
        .any(|e| e.hash.as_slice() == ids[0].as_bytes().as_slice())
    {
        return Err("unlinked block".into());
    }
    Ok(())
}

#[test]
fn answer_from_shared_block_starts_at_the_common_ancestor() {
    let bi = indexed_chain(50, 0xaa);
    let loc = locator(&[1, 10, 30], 0xaa);
    let (ids, remain) = serve_sync_block_chain_ids(&bi, 50, &loc);
    assert_eq!(ids.first().unwrap().num(), 30, "highest matching locator entry");
    assert_eq!(ids.last().unwrap().num(), 50);
    assert_eq!(remain, 0, "batch reaches head");
    java_chain_inventory_check(&ids, remain, &loc).unwrap();
}

/// java sets `needSyncFromUs = false` and `remainNum = 0` when the answer is a
/// single id — the peer is already at our head.
#[test]
fn peer_at_our_head_gets_one_id_and_zero_remain() {
    let bi = indexed_chain(50, 0xaa);
    let loc = locator(&[50], 0xaa);
    let (ids, remain) = serve_sync_block_chain_ids(&bi, 50, &loc);
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0].num(), 50);
    assert_eq!(remain, 0);
    java_chain_inventory_check(&ids, remain, &loc).unwrap();
}

/// `getBlockIds` walks `unForkNum..=unForkNum + SYNC_FETCH_BATCH_NUM`
/// inclusive, so a full batch is 2001 ids — exactly java's
/// `SYNC_FETCH_BATCH_NUM + 1` receive limit, not one over it.
#[test]
fn full_batch_is_exactly_2001_ids_and_survives_the_receive_limit() {
    let head = 5_000i64;
    let bi = indexed_chain(head, 0xaa);
    let loc = locator(&[1], 0xaa);
    let (ids, remain) = serve_sync_block_chain_ids(&bi, head, &loc);
    assert_eq!(ids.len() as i64, SYNC_FETCH_BATCH_NUM + 1);
    assert_eq!(ids.first().unwrap().num(), 1);
    assert_eq!(ids.last().unwrap().num(), 1 + SYNC_FETCH_BATCH_NUM as u64);
    assert_eq!(remain, head - (1 + SYNC_FETCH_BATCH_NUM));
    java_chain_inventory_check(&ids, remain, &loc).unwrap();
}

/// The pairing java cross-checks: a non-zero `remainNum` must come with a full
/// batch. Sweeping the boundary catches an off-by-one in either the batch cap
/// or the remain arithmetic, both of which cost a `BAD_PROTOCOL` disconnect.
#[test]
fn remain_and_batch_size_stay_consistent_across_the_batch_boundary() {
    for head in [1i64, 2, 1_999, 2_000, 2_001, 2_002, 4_002, 4_003] {
        let bi = indexed_chain(head, 0xaa);
        let loc = locator(&[1], 0xaa);
        let (ids, remain) = serve_sync_block_chain_ids(&bi, head, &loc);
        java_chain_inventory_check(&ids, remain, &loc)
            .unwrap_or_else(|e| panic!("head {head} produced an answer java rejects: {e}"));
        // Whatever the batching, the peer's next locator picks up exactly
        // where this answer left off.
        assert_eq!(
            ids.last().unwrap().num() as i64 + remain,
            head,
            "head {head}: last id + remain must land on our head"
        );
    }
}

/// A gap in the block index truncates the walk short of the intended batch end.
/// Deriving `remainNum` from the intended end instead of the last id actually
/// emitted advertises blocks we did not send, and java scores that as
/// "remain: N, blockIds size: M" and disconnects with `BAD_PROTOCOL`. A short
/// batch cannot carry a non-zero remain at all, so the truncated answer reports
/// 0 — "this is all I have" — which java accepts.
#[test]
fn truncated_index_walk_answers_within_javas_receive_rules() {
    let bi = BlockIndexStore::new(mem());
    for num in 1..=20 {
        bi.put(&id_at(num, 0xaa)).unwrap();
    }
    // 21..=29 missing; head claims 30.
    bi.put(&id_at(30, 0xaa)).unwrap();
    let loc = locator(&[5], 0xaa);
    let (ids, remain) = serve_sync_block_chain_ids(&bi, 30, &loc);
    assert_eq!(ids.last().unwrap().num(), 20, "walk stops at the gap");
    assert_eq!(remain, 0, "a short batch may not advertise a remainder");
    java_chain_inventory_check(&ids, remain, &loc).unwrap();
}

/// java `getUnForkId` scans the locator from the back and takes the first entry
/// on its main chain; entries that disagree with our chain are skipped. A
/// locator with no shared block yields no answer at all rather than a bogus one
/// (java disconnects with `INCOMPATIBLE_CHAIN` at that point).
#[test]
fn locator_from_a_foreign_chain_yields_no_answer() {
    let bi = indexed_chain(50, 0xaa);
    let loc = locator(&[10, 20, 30], 0xbb);
    let (ids, remain) = serve_sync_block_chain_ids(&bi, 50, &loc);
    assert!(ids.is_empty());
    assert_eq!(remain, 0);
}

/// A locator whose upper entries forked away from us falls back to the highest
/// entry we do share, and the answer still links to something the peer sent.
#[test]
fn forked_locator_tail_falls_back_to_the_shared_prefix() {
    let bi = indexed_chain(50, 0xaa);
    let mut loc = locator(&[1, 15], 0xaa);
    loc.extend(locator(&[40, 45], 0xbb));
    let (ids, remain) = serve_sync_block_chain_ids(&bi, 50, &loc);
    assert_eq!(ids.first().unwrap().num(), 15, "highest shared entry");
    java_chain_inventory_check(&ids, remain, &loc).unwrap();
}

/// Ids must be strictly consecutive; java rejects any hole with "not
/// continuous block".
#[test]
fn served_ids_are_consecutive() {
    let bi = indexed_chain(120, 0xaa);
    let loc = locator(&[7], 0xaa);
    let (ids, _) = serve_sync_block_chain_ids(&bi, 120, &loc);
    for pair in ids.windows(2) {
        assert_eq!(pair[1].num(), pair[0].num() + 1);
    }
}
