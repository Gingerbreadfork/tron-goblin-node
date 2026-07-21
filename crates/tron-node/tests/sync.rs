//! Tests for the block-sync driver.
//!
//! Focus is on the behaviour the simple `tron_replay::run_sync_loop`
//! doesn't have:
//!
//! * `accept_block` persists to BlockStore + BlockIndexStore.
//! * `resume_head` reads from `DynamicPropertiesStore`.
//! * Validation rejects malformed blocks (parent link, witness sig).
//! * Backoff math follows the documented schedule.

use std::sync::Arc;
use std::time::Duration;

use hex_literal::hex;
use tron_chainbase::{
    AccountStore, BlockIndexStore, BlockStore, DynamicPropertiesStore, KvBackend, MemBackend,
};
use tron_executor::StateBackends;
use tron_node::sync::{backoff_for, AcceptOutcome, SyncConfig, SyncDriver};
use tron_proto::block_header::Raw as BlockHeaderRaw;
use tron_proto::{Account, AccountType, Block, BlockHeader};
use tron_types::{block_id_from_block, sign_block};

const ALICE: [u8; 21] = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");
const ALICE_PRIV: [u8; 32] =
    hex!("1234567890123456789012345678901234567890123456789012345678901234");

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn fresh_state() -> (StateBackends, Arc<dyn KvBackend>) {
    let blocks_be = mem();
    let state = StateBackends {
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
        market_account: mem(),
        nullifiers: mem(),
        merkle_trees: None,
        code: Some(mem()),
        storage_row: Some(mem()),
        contract_state: Some(mem()),
        block_index: Some(mem()),
        witness_schedule: Some(mem()),
        reward_vi: None,
    };
    (state, blocks_be)
}

fn seed_alice(state: &StateBackends) {
    let accounts = AccountStore::new(state.accounts.clone());
    use tron_crypto::address::Address;
    accounts.put(
        &Address::from_raw(ALICE),
        &Account {
            address: ALICE.to_vec(),
            balance: 1_000_000_000,
            r#type: AccountType::Normal as i32,
            ..Default::default()
        },
    ).unwrap();
}

fn build_block(num: i64, parent_hash: [u8; 32]) -> Block {
    build_block_salted(num, parent_hash, 0)
}

/// Like `build_block` but `salt` perturbs the timestamp so two blocks at
/// the same height with the same parent get distinct ids — i.e. genuine
/// sibling forks for reorg tests.
fn build_block_salted(num: i64, parent_hash: [u8; 32], salt: i64) -> Block {
    let mut block = Block {
        transactions: Vec::new(),
        block_header: Some(BlockHeader {
            raw_data: Some(BlockHeaderRaw {
                timestamp: 1_700_000_000_000 + num * 3000 + salt,
                tx_trie_root: tron_types::calc_tx_trie_root(&[])
                    .map(|h| h.to_vec())
                    .unwrap_or_default(),
                parent_hash: parent_hash.to_vec(),
                number: num,
                witness_id: 0,
                witness_address: ALICE.to_vec(),
                version: 28,
                account_state_root: Vec::new(),
            }),
            witness_signature: Vec::new(),
        }),
    };
    sign_block(&mut block, &ALICE_PRIV).expect("sign");
    block
}

fn make_driver(state: StateBackends, blocks_be: Arc<dyn KvBackend>) -> SyncDriver {
    let cfg = SyncConfig {
        peers: vec![],
        max_blocks: None,
        tail_interval: Duration::from_millis(1),
        initial_backoff: Duration::from_millis(1),
        blocks_backend: blocks_be,
        progress_log_interval: 0,
        advertise_port: 18_888,
        tip_test: false,
        p2p_rate_limits: Default::default(),
        fetch_block_timeout: Duration::from_millis(200),
        fetch_inflight_per_peer: 64,
        peer_is_fast_forward: false,
        follow_tip: false,
    };
    SyncDriver::new(state, cfg)
}

#[test]
fn accept_block_persists_to_block_store_and_index() {
    let (state, blocks_be) = fresh_state();
    seed_alice(&state);
    let mut driver = make_driver(state.clone(), blocks_be.clone());
    let block = build_block(1, [0u8; 32]);
    let id = block_id_from_block(&block).unwrap();
    let outcome = driver.accept_block(&block, None);
    assert!(matches!(outcome, AcceptOutcome::Accepted(_)));
    // The block must be readable from BlockStore via the synthesised id.
    let block_store = BlockStore::new(blocks_be);
    let fetched = block_store.get(&id).expect("block in store");
    assert_eq!(fetched.block_header.unwrap().raw_data.unwrap().number, 1);
    // BlockIndexStore should also map num → BlockId.
    let bi = BlockIndexStore::new(state.block_index.unwrap());
    assert_eq!(bi.get(1).expect("index entry"), id);
}

#[test]
fn accept_block_updates_dyn_props_head() {
    let (state, blocks_be) = fresh_state();
    seed_alice(&state);
    let mut driver = make_driver(state.clone(), blocks_be);
    let block = build_block(1, [0u8; 32]);
    let id = block_id_from_block(&block).unwrap();
    driver.accept_block(&block, None);
    let dp = DynamicPropertiesStore::new(state.dyn_props);
    assert_eq!(dp.latest_block_header_number(), Some(1));
    assert_eq!(
        dp.latest_block_header_hash().unwrap().unwrap(),
        *id.as_bytes()
    );
}

#[test]
fn resume_head_returns_block_id_after_accept() {
    let (state, blocks_be) = fresh_state();
    seed_alice(&state);
    let mut driver = make_driver(state, blocks_be);
    assert!(
        driver.resume_head().is_none(),
        "fresh state has no head"
    );
    let block = build_block(1, [0u8; 32]);
    let id = block_id_from_block(&block).unwrap();
    driver.accept_block(&block, None);
    assert_eq!(driver.resume_head(), Some(id));
    assert_eq!(driver.head_number(), 1);
}

#[test]
fn accept_block_rejects_unlinked_block() {
    // Parent-link authority moved from the caller's `prev_id` hint to the
    // fork tree: a block whose parent isn't in KhaosDb (a genuine orphan)
    // is rejected as unlinked, regardless of what `prev_id` says. A stale
    // `prev_id` alone must NOT cause a rejection — that was the bug that
    // made public peers refuse to sync.
    let (state, blocks_be) = fresh_state();
    seed_alice(&state);
    let mut driver = make_driver(state, blocks_be);

    // Establish a head at block 1.
    let b1 = build_block(1, [0u8; 32]);
    let id1 = block_id_from_block(&b1).unwrap();
    assert!(matches!(driver.accept_block(&b1, None), AcceptOutcome::Accepted(_)));

    // A block whose parent_hash points at something not in the fork tree.
    // Even though we hand it a *valid* prev_id (id1), KhaosDb can't link
    // it → unlinked rejection.
    let orphan = build_block(2, [0xffu8; 32]);
    let outcome = driver.accept_block(&orphan, Some(id1));
    match outcome {
        AcceptOutcome::RejectedValidation(reason) => {
            assert!(reason.contains("unlinked"), "got: {reason}");
        }
        other => panic!("expected RejectedValidation(unlinked), got {other:?}"),
    }
}

#[test]
fn fork_block_with_stale_prev_id_reorgs_instead_of_rejecting() {
    // The real-sync / leadership-handoff scenario the gate removal fixes:
    // a sibling-fork block arrives while `prev_id` still points at the
    // canonical head (the stream cursor lags the fork). Pre-fix, the early
    // parent-link gate hard-rejected it, wedging the head. Now KhaosDb
    // classifies it as a side fork, and a taller extension triggers a
    // clean reorg — all with `prev_id` pinned at the (stale) canonical
    // head throughout.
    let (state, blocks_be) = fresh_state();
    seed_alice(&state);
    let mut driver = make_driver(state.clone(), blocks_be)
        .with_undo_store(tron_chainbase::BlockUndoStore::new(mem()));

    // Block 1 (head).
    let b1 = build_block(1, [0u8; 32]);
    let id1 = block_id_from_block(&b1).unwrap();
    assert!(matches!(driver.accept_block(&b1, None), AcceptOutcome::Accepted(_)));

    // Canonical block 2a.
    let b2a = build_block_salted(2, *id1.as_bytes(), 0);
    let id2a = block_id_from_block(&b2a).unwrap();
    assert!(matches!(
        driver.accept_block(&b2a, Some(id1)),
        AcceptOutcome::Accepted(_)
    ));
    assert_eq!(driver.head_number(), 2);

    // Sibling 2b — but prev_id is the canonical head (id2a), NOT 2b's
    // real parent (id1). Pre-fix: hard parent-link reject. Now: side fork.
    let b2b = build_block_salted(2, *id1.as_bytes(), 1);
    let id2b = block_id_from_block(&b2b).unwrap();
    let outcome = driver.accept_block(&b2b, Some(id2a));
    assert!(
        matches!(outcome, AcceptOutcome::SideFork(_)),
        "sibling fork must be classified, not rejected on stale prev_id; got {outcome:?}"
    );
    assert_eq!(driver.head_number(), 2, "still on canonical 2a");

    // 3b extends 2b → taller fork → reorg, again with the stale prev_id.
    let b3b = build_block_salted(3, *id2b.as_bytes(), 1);
    let id3b = block_id_from_block(&b3b).unwrap();
    let outcome = driver.accept_block(&b3b, Some(id2a));
    assert!(
        matches!(outcome, AcceptOutcome::Accepted(_)),
        "taller fork must reorg in, not reject on stale prev_id; got {outcome:?}"
    );
    assert_eq!(driver.head_number(), 3);
    assert_eq!(
        driver.resume_head(),
        Some(id3b),
        "head switched to the taller fork"
    );
}

#[test]
fn accept_block_rejects_corrupt_witness_signature() {
    let (state, blocks_be) = fresh_state();
    seed_alice(&state);
    let mut driver = make_driver(state, blocks_be);
    let mut block = build_block(1, [0u8; 32]);
    // Corrupt the signature.
    if let Some(h) = block.block_header.as_mut() {
        if !h.witness_signature.is_empty() {
            h.witness_signature[0] ^= 0xff;
        }
    }
    let outcome = driver.accept_block(&block, None);
    match outcome {
        AcceptOutcome::RejectedValidation(reason) => {
            assert!(
                reason.contains("witness sig") || reason.contains("witness signature"),
                "got: {reason}"
            );
        }
        other => panic!("expected RejectedValidation, got {other:?}"),
    }
}

#[test]
fn chain_of_three_blocks_lands_in_storage_with_correct_links() {
    let (state, blocks_be) = fresh_state();
    seed_alice(&state);
    let mut driver = make_driver(state.clone(), blocks_be.clone());

    let block1 = build_block(1, [0u8; 32]);
    let id1 = block_id_from_block(&block1).unwrap();
    driver.accept_block(&block1, None);
    let block2 = build_block(2, *id1.as_bytes());
    let id2 = block_id_from_block(&block2).unwrap();
    driver.accept_block(&block2, Some(id1));
    let block3 = build_block(3, *id2.as_bytes());
    let id3 = block_id_from_block(&block3).unwrap();
    driver.accept_block(&block3, Some(id2));

    assert_eq!(driver.stats().blocks_applied, 3);
    assert_eq!(driver.head_number(), 3);
    assert_eq!(driver.resume_head(), Some(id3));

    // Each block is retrievable by its id.
    let bs = BlockStore::new(blocks_be);
    assert_eq!(
        bs.get(&id1).unwrap().block_header.unwrap().raw_data.unwrap().number,
        1
    );
    assert_eq!(
        bs.get(&id3).unwrap().block_header.unwrap().raw_data.unwrap().number,
        3
    );
}

#[test]
fn backoff_schedule_caps_at_five_minutes() {
    let base = Duration::from_secs(5);
    assert_eq!(backoff_for(base, 0), Duration::from_secs(5));
    assert_eq!(backoff_for(base, 1), Duration::from_secs(10));
    assert_eq!(backoff_for(base, 2), Duration::from_secs(20));
    assert_eq!(backoff_for(base, 4), Duration::from_secs(80));
    // After 8 doublings, the cap kicks in.
    assert_eq!(backoff_for(base, 100), Duration::from_secs(300));
}

// =============================================================================
// KhaosDb integration tests
// =============================================================================
//
// The KhaosDb-aware accept_block path adds three new outcomes
// (AlreadyKnown, SideFork, ReorgRequired). Verify each.

/// Build a sibling of `build_block(num, parent)` that has a different
/// timestamp — same parent + same witness, distinct block hash.
fn build_sibling(num: i64, parent_hash: [u8; 32], ts_offset: i64) -> Block {
    let mut block = Block {
        transactions: Vec::new(),
        block_header: Some(BlockHeader {
            raw_data: Some(BlockHeaderRaw {
                timestamp: 1_700_000_000_000 + num * 3000 + ts_offset,
                tx_trie_root: tron_types::calc_tx_trie_root(&[])
                    .map(|h| h.to_vec())
                    .unwrap_or_default(),
                parent_hash: parent_hash.to_vec(),
                number: num,
                witness_id: 0,
                witness_address: ALICE.to_vec(),
                version: 28,
                account_state_root: Vec::new(),
            }),
            witness_signature: Vec::new(),
        }),
    };
    sign_block(&mut block, &ALICE_PRIV).expect("sign");
    block
}

#[test]
fn accept_block_dedups_via_khaos_on_second_push() {
    let (state, blocks_be) = fresh_state();
    seed_alice(&state);
    let mut driver = make_driver(state, blocks_be);
    let block = build_block(1, [0u8; 32]);
    let id = block_id_from_block(&block).unwrap();

    // First push lands.
    assert!(matches!(driver.accept_block(&block, None), AcceptOutcome::Accepted(_)));

    // Second push of the same block — KhaosDb dedups, no execution.
    let stats_before = driver.stats();
    let outcome = driver.accept_block(&block, None);
    match outcome {
        AcceptOutcome::AlreadyKnown(returned_id) => {
            assert_eq!(returned_id, id);
        }
        other => panic!("expected AlreadyKnown, got {other:?}"),
    }
    // blocks_applied must NOT have incremented.
    assert_eq!(driver.stats().blocks_applied, stats_before.blocks_applied);
}

#[test]
fn accept_block_records_side_fork_without_changing_state() {
    let (state, blocks_be) = fresh_state();
    seed_alice(&state);
    let mut driver = make_driver(state.clone(), blocks_be);

    // Apply genesis (block 1).
    let g = build_block(1, [0u8; 32]);
    let gid = block_id_from_block(&g).unwrap();
    driver.accept_block(&g, None);

    // Apply canonical block 2.
    let b2a = build_block(2, *gid.as_bytes());
    let id_2a = block_id_from_block(&b2a).unwrap();
    driver.accept_block(&b2a, Some(gid));
    assert_eq!(driver.head_number(), 2);

    // Now push a sibling block 2 (different timestamp → distinct id).
    let b2b = build_sibling(2, *gid.as_bytes(), 17);
    let id_2b = block_id_from_block(&b2b).unwrap();
    assert_ne!(id_2a, id_2b, "sibling must hash differently");

    let outcome = driver.accept_block(&b2b, Some(gid));
    match outcome {
        AcceptOutcome::SideFork(returned_id) => {
            assert_eq!(returned_id, id_2b);
        }
        other => panic!("expected SideFork, got {other:?}"),
    }
    // Executed head is still the original (canonical) block 2.
    let dp = DynamicPropertiesStore::new(state.dyn_props);
    assert_eq!(
        dp.latest_block_header_hash().unwrap().unwrap(),
        *id_2a.as_bytes(),
        "executed head must NOT switch on a same-height sibling"
    );
    // Fork tree should still have both blocks plus genesis.
    assert_eq!(driver.khaos().linked_size(), 3);
}

#[test]
fn accept_block_flags_reorg_when_sibling_fork_overtakes_head() {
    let (state, blocks_be) = fresh_state();
    seed_alice(&state);
    let mut driver = make_driver(state, blocks_be);

    // Build canonical chain: g → 2a (executed head at num=2).
    let g = build_block(1, [0u8; 32]);
    let gid = block_id_from_block(&g).unwrap();
    driver.accept_block(&g, None);

    let b2a = build_block(2, *gid.as_bytes());
    driver.accept_block(&b2a, Some(gid));
    assert_eq!(driver.head_number(), 2);

    // Apply a sibling 2b (side fork).
    let b2b = build_sibling(2, *gid.as_bytes(), 31);
    let id_2b = block_id_from_block(&b2b).unwrap();
    let _ = driver.accept_block(&b2b, Some(gid));

    // Now push a 3b that extends the SIBLING chain. KhaosDb head now
    // jumps from 2 → 3 via the sibling chain — a true reorg is
    // required.
    let b3b = build_sibling(3, *id_2b.as_bytes(), 0);
    let id_3b = block_id_from_block(&b3b).unwrap();
    let outcome = driver.accept_block(&b3b, Some(id_2b));
    match outcome {
        AcceptOutcome::ReorgRequired(returned_id, new_head_num) => {
            assert_eq!(returned_id, id_3b);
            assert_eq!(new_head_num, 3);
        }
        other => panic!("expected ReorgRequired, got {other:?}"),
    }
    // Executed head must still be 2a — Phase B reorg not implemented.
    assert_eq!(driver.head_number(), 2);
    // KhaosDb head IS 3b (the fork tree tracks correctly).
    assert_eq!(driver.khaos().head().unwrap().id, id_3b);
}

#[test]
fn khaos_get_branch_finds_common_ancestor_via_driver() {
    let (state, blocks_be) = fresh_state();
    seed_alice(&state);
    let mut driver = make_driver(state, blocks_be);

    // Build a tree:  g → 2a → 3a
    //                  ↘ 2b → 3b
    let g = build_block(1, [0u8; 32]);
    let gid = block_id_from_block(&g).unwrap();
    driver.accept_block(&g, None);
    let b2a = build_block(2, *gid.as_bytes());
    let id_2a = block_id_from_block(&b2a).unwrap();
    driver.accept_block(&b2a, Some(gid));
    let b3a = build_block(3, *id_2a.as_bytes());
    let id_3a = block_id_from_block(&b3a).unwrap();
    driver.accept_block(&b3a, Some(id_2a));
    let b2b = build_sibling(2, *gid.as_bytes(), 17);
    let id_2b = block_id_from_block(&b2b).unwrap();
    driver.accept_block(&b2b, Some(gid));
    let b3b = build_sibling(3, *id_2b.as_bytes(), 0);
    let id_3b = block_id_from_block(&b3b).unwrap();
    let _ = driver.accept_block(&b3b, Some(id_2b));

    // get_branch(3a, 3b) → ([3a, 2a], [3b, 2b]); common ancestor = g.
    let (path_a, path_b) = driver.khaos().get_branch(&id_3a, &id_3b).unwrap();
    assert_eq!(path_a.len(), 2);
    assert_eq!(path_b.len(), 2);
    assert_eq!(path_a[0].id, id_3a);
    assert_eq!(path_a[1].id, id_2a);
    assert_eq!(path_b[0].id, id_3b);
    assert_eq!(path_b[1].id, id_2b);
}

#[test]
fn reorg_with_undo_actually_switches_canonical_head() {
    use tron_chainbase::BlockUndoStore;
    // Driver with an undo store performs a real reorg: rolls back the
    // canonical chain, applies the new fork, head pointer updates.
    let (state, blocks_be) = fresh_state();
    seed_alice(&state);
    let undo_be: Arc<dyn KvBackend> = mem();
    let mut driver = make_driver(state.clone(), blocks_be)
        .with_undo_store(BlockUndoStore::new(undo_be));

    // Genesis (block 1).
    let g = build_block(1, [0u8; 32]);
    let gid = block_id_from_block(&g).unwrap();
    driver.accept_block(&g, None);

    // Apply canonical block 2a.
    let b2a = build_block(2, *gid.as_bytes());
    let id_2a = block_id_from_block(&b2a).unwrap();
    driver.accept_block(&b2a, Some(gid));
    assert_eq!(driver.head_number(), 2);
    let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
    assert_eq!(
        dp.latest_block_header_hash().unwrap(),
        Some(*id_2a.as_bytes()),
        "head is 2a before reorg"
    );

    // Push sibling 2b (SideFork — head stays at 2a).
    let b2b = build_sibling(2, *gid.as_bytes(), 31);
    let id_2b = block_id_from_block(&b2b).unwrap();
    driver.accept_block(&b2b, Some(gid));
    assert_eq!(
        dp.latest_block_header_hash().unwrap(),
        Some(*id_2a.as_bytes()),
        "still 2a after side-fork push"
    );

    // Now extend the b-chain with 3b. This triggers a reorg.
    let b3b = build_sibling(3, *id_2b.as_bytes(), 0);
    let id_3b = block_id_from_block(&b3b).unwrap();
    let outcome = driver.accept_block(&b3b, Some(id_2b));
    match outcome {
        AcceptOutcome::Accepted(id) => assert_eq!(id, id_3b),
        other => panic!("expected Accepted after reorg, got {other:?}"),
    }

    // After reorg, executed head must be 3b.
    assert_eq!(driver.head_number(), 3);
    assert_eq!(
        dp.latest_block_header_hash().unwrap(),
        Some(*id_3b.as_bytes()),
        "head pointer switched to 3b after reorg"
    );
}

#[test]
fn block_index_tracks_canonical_chain_across_reorg() {
    use tron_chainbase::BlockUndoStore;
    // The num → id index must follow the *canonical* chain: a side fork
    // must NOT repoint it, and a reorg must repoint it at the winning
    // branch. (Regression test for the block_index caveat — side-fork
    // pollution + reorg not reindexing.)
    let (state, blocks_be) = fresh_state();
    seed_alice(&state);
    let undo_be: Arc<dyn KvBackend> = mem();
    let mut driver = make_driver(state.clone(), blocks_be)
        .with_undo_store(BlockUndoStore::new(undo_be));
    let bi = BlockIndexStore::new(state.block_index.clone().unwrap());

    // g (1) → 2a (canonical head).
    let g = build_block(1, [0u8; 32]);
    let gid = block_id_from_block(&g).unwrap();
    driver.accept_block(&g, None);
    let b2a = build_block(2, *gid.as_bytes());
    let id_2a = block_id_from_block(&b2a).unwrap();
    driver.accept_block(&b2a, Some(gid));
    assert_eq!(bi.get(2).unwrap(), id_2a, "block_index[2] = canonical 2a");

    // Sibling 2b (SideFork) must NOT touch block_index[2].
    let b2b = build_sibling(2, *gid.as_bytes(), 31);
    let id_2b = block_id_from_block(&b2b).unwrap();
    driver.accept_block(&b2b, Some(gid));
    assert_eq!(
        bi.get(2).unwrap(),
        id_2a,
        "side fork must NOT repoint block_index[2] away from canonical 2a"
    );

    // 3b extends the b-chain → reorg. block_index must now track b.
    let b3b = build_sibling(3, *id_2b.as_bytes(), 0);
    let id_3b = block_id_from_block(&b3b).unwrap();
    assert!(matches!(
        driver.accept_block(&b3b, Some(id_2b)),
        AcceptOutcome::Accepted(_)
    ));
    assert_eq!(driver.head_number(), 3);
    assert_eq!(bi.get(2).unwrap(), id_2b, "reorg repointed block_index[2] → 2b");
    assert_eq!(bi.get(3).unwrap(), id_3b, "reorg indexed the new tip 3b");
}

#[test]
fn reorg_without_undo_still_flags_only() {
    // Same test as above but WITHOUT an undo store attached. Driver
    // must still flag ReorgRequired (preserving the informational
    // behavior for tests / read-only nodes).
    let (state, blocks_be) = fresh_state();
    seed_alice(&state);
    let mut driver = make_driver(state, blocks_be);

    let g = build_block(1, [0u8; 32]);
    let gid = block_id_from_block(&g).unwrap();
    driver.accept_block(&g, None);

    let b2a = build_block(2, *gid.as_bytes());
    driver.accept_block(&b2a, Some(gid));
    let b2b = build_sibling(2, *gid.as_bytes(), 31);
    let id_2b = block_id_from_block(&b2b).unwrap();
    driver.accept_block(&b2b, Some(gid));

    let b3b = build_sibling(3, *id_2b.as_bytes(), 0);
    let id_3b = block_id_from_block(&b3b).unwrap();
    let outcome = driver.accept_block(&b3b, Some(id_2b));
    match outcome {
        AcceptOutcome::ReorgRequired(id, new_head_num) => {
            assert_eq!(id, id_3b);
            assert_eq!(new_head_num, 3);
        }
        other => panic!("expected ReorgRequired (no undo), got {other:?}"),
    }
    assert_eq!(driver.head_number(), 2, "no undo store → no reorg performed");
}

/// Build a block whose `account_state_root` field is deliberately set
/// to a value that won't match `compute_state_root(state)`. Combined
/// with `ALLOW_ACCOUNT_STATE_ROOT == 1` on the dyn_props store, this
/// is the cleanest way to engineer an apply failure that gets past
/// `accept_block`'s structural checks (tx_trie_root + witness_sig) but
/// fails inside `execute_block_with_undo`'s post-tx state-root verify.
fn build_bad_state_root_block(num: i64, parent_hash: [u8; 32], ts_offset: i64) -> Block {
    let mut block = Block {
        transactions: Vec::new(),
        block_header: Some(BlockHeader {
            raw_data: Some(BlockHeaderRaw {
                timestamp: 1_700_000_000_000 + num * 3000 + ts_offset,
                tx_trie_root: tron_types::calc_tx_trie_root(&[])
                    .map(|h| h.to_vec())
                    .unwrap_or_default(),
                parent_hash: parent_hash.to_vec(),
                number: num,
                witness_id: 0,
                witness_address: ALICE.to_vec(),
                version: 28,
                account_state_root: vec![0xff; 32], // deliberately wrong
            }),
            witness_signature: Vec::new(),
        }),
    };
    sign_block(&mut block, &ALICE_PRIV).expect("sign");
    block
}

#[test]
fn reorg_recovery_restores_old_chain_when_new_fork_block_fails() {
    use tron_chainbase::{BlockUndoStore, DynamicPropertiesStore};
    // Build: g → 2a → 3a (canonical, head)
    //          ↘ 2b → 3b → 4b (sibling, 4b deliberately broken)
    // Pushing 4b triggers a reorg: rollback 3a + 2a, apply 2b + 3b + 4b.
    // 4b fails at the state-root check → recovery rollbacks 2b + 3b
    // and re-applies 2a + 3a, leaving head at 3a (unchanged from
    // pre-reorg).
    let (state, blocks_be) = fresh_state();
    seed_alice(&state);
    let undo_be: Arc<dyn KvBackend> = mem();
    let mut driver = make_driver(state.clone(), blocks_be)
        .with_undo_store(BlockUndoStore::new(undo_be));

    // Apply genesis-like chain g → 2a → 3a.
    let g = build_block(1, [0u8; 32]);
    let gid = block_id_from_block(&g).unwrap();
    driver.accept_block(&g, None);
    let b2a = build_block(2, *gid.as_bytes());
    let id_2a = block_id_from_block(&b2a).unwrap();
    driver.accept_block(&b2a, Some(gid));
    let b3a = build_block(3, *id_2a.as_bytes());
    let id_3a = block_id_from_block(&b3a).unwrap();
    driver.accept_block(&b3a, Some(id_2a));
    assert_eq!(driver.head_number(), 3);

    // Enable state-root verification — now blocks with a wrong
    // account_state_root will fail apply.
    let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
    dp.put_long(b"ALLOW_ACCOUNT_STATE_ROOT", 1);

    // Build the sibling chain: 2b → 3b are both VALID (their
    // account_state_root is empty so the executor skips the check
    // because `raw.account_state_root.is_empty()`).
    let b2b = build_sibling(2, *gid.as_bytes(), 31);
    let id_2b = block_id_from_block(&b2b).unwrap();
    let b3b = build_sibling(3, *id_2b.as_bytes(), 0);
    let id_3b = block_id_from_block(&b3b).unwrap();
    let _ = driver.accept_block(&b2b, Some(gid));
    let _ = driver.accept_block(&b3b, Some(id_2b));
    // Both should land as SideFork — head stays at 3a.
    assert_eq!(driver.head_number(), 3);

    // 4b is the broken one — non-empty bogus account_state_root.
    let b4b = build_bad_state_root_block(4, *id_3b.as_bytes(), 0);
    let id_4b = block_id_from_block(&b4b).unwrap();
    // Pushing 4b triggers reorg → rollback 2a/3a, apply 2b/3b/4b.
    // 4b fails state-root check → recovery rolls back 2b/3b and
    // re-applies 2a/3a. Expected: RejectedExecution with "original
    // chain restored" in the message.
    let outcome = driver.accept_block(&b4b, Some(id_3b));
    match outcome {
        AcceptOutcome::RejectedExecution(msg) => {
            assert!(
                msg.contains("original chain restored") || msg.contains("apply failed"),
                "expected recovery message; got: {msg}"
            );
        }
        other => panic!("expected RejectedExecution after failed reorg; got {other:?}"),
    }
    // The KEY assertion: head pointer is back at 3a, not stuck on a
    // partial new-fork application.
    assert_eq!(driver.head_number(), 3, "head must be restored to pre-reorg");
    let dp_after = DynamicPropertiesStore::new(state.dyn_props.clone());
    assert_eq!(
        dp_after.latest_block_header_hash().unwrap(),
        Some(*id_3a.as_bytes()),
        "head pointer must be 3a after failed reorg"
    );
    let _ = (id_4b,);
}

/// Verify SyncDriver emits BlockEvent + TransactionEvent through the
/// attached eventer bus on every accepted block. This is what
/// downstream Kafka/Mongo plugins (and the analytics layer) subscribe
/// to. Uses the in-process ChannelListener for sync verification.
#[test]
fn accept_block_emits_event_to_attached_eventer_bus() {
    use tron_eventer::listeners::{ChannelListener, TriggerMessage};
    use tron_eventer::EventBus;

    let (state, blocks_be) = fresh_state();
    seed_alice(&state);
    let mut driver = make_driver(state, blocks_be);

    let (listener, mut rx) = ChannelListener::pair(16);
    let bus = EventBus::builder().add(listener).build();
    driver = driver.with_event_bus(bus);

    let block = build_block(1, [0u8; 32]);
    let outcome = driver.accept_block(&block, None);
    assert!(matches!(outcome, AcceptOutcome::Accepted(_)));

    // Block trigger must arrive synchronously (try_send on a 16-slot
    // channel never blocks). No transactions in this fixture, so the
    // only message is the block trigger.
    match rx.try_recv() {
        Ok(TriggerMessage::Block(b)) => {
            assert_eq!(b.block_number, 1);
            assert_eq!(b.transaction_size, 0);
            // Same hex as the block_id we expected.
            let id = block_id_from_block(&block).unwrap();
            assert_eq!(b.block_hash, hex::encode(id.as_bytes()));
        }
        other => panic!("expected Block trigger, got: {other:?}"),
    }
    assert!(
        rx.try_recv().is_err(),
        "no further triggers expected (0 txs in fixture)"
    );
}

/// Without an attached bus, accept_block emits nothing — verifies the
/// zero-cost "feature disabled" path.
#[test]
fn accept_block_without_bus_emits_nothing() {
    let (state, blocks_be) = fresh_state();
    seed_alice(&state);
    let mut driver = make_driver(state, blocks_be);
    // No with_event_bus call.
    let block = build_block(1, [0u8; 32]);
    let outcome = driver.accept_block(&block, None);
    assert!(matches!(outcome, AcceptOutcome::Accepted(_)));
    // No assertion possible — we're just verifying no panic + no
    // dependency on event-bus state in the happy path.
}

// =============================================================================
// Solidified-containment gate (best_head_with_solidified wired into accept_block)
// =============================================================================
//
// TRON's full fork-choice rule: "longest chain containing the last
// solidified block". KhaosDb does the longest-chain pick; the gate
// enforces the containment side. Pre-PBFT (no solidified set yet)
// the gate is a no-op so the boot path behaves exactly as before.

#[test]
fn solidified_gate_is_noop_when_no_solidified_set() {
    // Without a solidified block, the gate must NOT change observed
    // behavior — a sibling fork that overtakes head still produces
    // ReorgRequired (matches the pre-gate semantics).
    let (state, blocks_be) = fresh_state();
    seed_alice(&state);
    let mut driver = make_driver(state.clone(), blocks_be);

    // No save_latest_solidified_block_num call — DPS is empty for that key.
    let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
    assert_eq!(dp.latest_solidified_block_num(), None);

    // Set up canonical g → 2a, then push sibling 2b → 3b that overtakes.
    let g = build_block(1, [0u8; 32]);
    let gid = block_id_from_block(&g).unwrap();
    driver.accept_block(&g, None);
    let b2a = build_block(2, *gid.as_bytes());
    driver.accept_block(&b2a, Some(gid));

    let b2b = build_sibling(2, *gid.as_bytes(), 41);
    let id_2b = block_id_from_block(&b2b).unwrap();
    let _ = driver.accept_block(&b2b, Some(gid));

    let b3b = build_sibling(3, *id_2b.as_bytes(), 0);
    let outcome = driver.accept_block(&b3b, Some(id_2b));
    // Gate skipped (no solidified) → standard ReorgRequired surface.
    assert!(
        matches!(outcome, AcceptOutcome::ReorgRequired(_, _)),
        "without solidified set, sibling-overtake should still produce ReorgRequired, got {outcome:?}"
    );
}

#[test]
fn solidified_gate_accepts_extension_whose_chain_contains_solidified() {
    // Canonical chain that walks back to the solidified block must
    // be accepted normally.
    let (state, blocks_be) = fresh_state();
    seed_alice(&state);
    let mut driver = make_driver(state.clone(), blocks_be);

    // Build canonical g → 2 → 3 (all on the same chain).
    let g = build_block(1, [0u8; 32]);
    let gid = block_id_from_block(&g).unwrap();
    driver.accept_block(&g, None);
    let b2 = build_block(2, *gid.as_bytes());
    let id_2 = block_id_from_block(&b2).unwrap();
    driver.accept_block(&b2, Some(gid));

    // Mark block 1 as solidified — the chain from any descendant
    // walks back to it.
    let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
    dp.save_latest_solidified_block_num(1);

    // Now push block 3 extending canonical. Gate should pass.
    let b3 = build_block(3, *id_2.as_bytes());
    let outcome = driver.accept_block(&b3, Some(id_2));
    assert!(
        matches!(outcome, AcceptOutcome::Accepted(_)),
        "extension whose chain walks back to solidified must be Accepted, got {outcome:?}"
    );
    assert_eq!(driver.head_number(), 3);
}

#[test]
fn solidified_gate_rejects_head_promotion_that_diverges_from_solidified() {
    // Canonical chain g → 2a → 3a is on disk; solidified = 2a.
    // A sibling fork 2b → 3b → 4b tries to overtake — but its chain
    // back from 4b goes 4b → 3b → 2b, and 2b at height-2 is NOT 2a.
    // The gate must reject the head promotion.
    let (state, blocks_be) = fresh_state();
    seed_alice(&state);
    let mut driver = make_driver(state.clone(), blocks_be);

    // Canonical: g → 2a → 3a.
    let g = build_block(1, [0u8; 32]);
    let gid = block_id_from_block(&g).unwrap();
    driver.accept_block(&g, None);
    let b2a = build_block(2, *gid.as_bytes());
    let id_2a = block_id_from_block(&b2a).unwrap();
    driver.accept_block(&b2a, Some(gid));
    let b3a = build_block(3, *id_2a.as_bytes());
    let id_3a = block_id_from_block(&b3a).unwrap();
    driver.accept_block(&b3a, Some(id_2a));
    assert_eq!(driver.head_number(), 3);

    // Mark 2a as solidified.
    let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
    dp.save_latest_solidified_block_num(2);

    // Sibling chain rooted at genesis: 2b → 3b → 4b. (2b is a side
    // fork at height 2 → SideFork on push.)
    let b2b = build_sibling(2, *gid.as_bytes(), 51);
    let id_2b = block_id_from_block(&b2b).unwrap();
    let out2b = driver.accept_block(&b2b, Some(gid));
    assert!(
        matches!(out2b, AcceptOutcome::SideFork(_)),
        "2b at same height as canonical 2a must be SideFork, got {out2b:?}"
    );

    // 3b ties height with 3a — KhaosDb prefers the first-seen at a
    // given num, so head stays at 3a; 3b is also SideFork.
    let b3b = build_sibling(3, *id_2b.as_bytes(), 0);
    let id_3b = block_id_from_block(&b3b).unwrap();
    let out3b = driver.accept_block(&b3b, Some(id_2b));
    assert!(
        matches!(out3b, AcceptOutcome::SideFork(_)),
        "3b at same height as canonical 3a must be SideFork, got {out3b:?}"
    );

    // 4b extends the sibling chain to height 4 — KhaosDb now wants to
    // promote 4b as the new head (longest chain). The gate must catch
    // this: walking 4b → 3b → 2b lands at height-2 with id 2b, which
    // is NOT the solidified id 2a → divergence.
    let b4b = build_sibling(4, *id_3b.as_bytes(), 0);
    let id_4b = block_id_from_block(&b4b).unwrap();
    let out4b = driver.accept_block(&b4b, Some(id_3b));
    match out4b {
        AcceptOutcome::RejectedSolidifiedDiverged(returned_id) => {
            assert_eq!(returned_id, id_4b);
        }
        other => panic!("expected RejectedSolidifiedDiverged, got {other:?}"),
    }

    // KhaosDb head must have been reverted to the canonical 3a — the
    // rejected promotion shouldn't keep 4b as the head pointer.
    assert_eq!(driver.khaos().head().unwrap().id, id_3a);
    // Executed canonical head also unchanged.
    assert_eq!(driver.head_number(), 3);
    let _ = id_4b; // silence unused warning on the early-return path
}

#[test]
fn reorg_to_fork_two_blocks_deeper_switches_in_one_promotion() {
    use tron_chainbase::BlockUndoStore;
    // Adversarial shape: the sibling fork grows SILENTLY (side-fork
    // pushes) until it is 2+ blocks past the canonical head, then the
    // single promoting push must roll back the canonical chain and
    // apply EVERY fork block (java Manager.switchFork walks the whole
    // branch, not just one block).
    let (state, blocks_be) = fresh_state();
    seed_alice(&state);
    let undo_be: Arc<dyn KvBackend> = mem();
    let mut driver = make_driver(state.clone(), blocks_be)
        .with_undo_store(BlockUndoStore::new(undo_be));

    let g = build_block(1, [0u8; 32]);
    let gid = block_id_from_block(&g).unwrap();
    driver.accept_block(&g, None);

    // Canonical: 2a, 3a.
    let b2a = build_block(2, *gid.as_bytes());
    let id_2a = block_id_from_block(&b2a).unwrap();
    driver.accept_block(&b2a, Some(gid));
    let b3a = build_block(3, *id_2a.as_bytes());
    let id_3a = block_id_from_block(&b3a).unwrap();
    driver.accept_block(&b3a, Some(id_2a));
    assert_eq!(driver.head_number(), 3);

    // Fork: 2b (side), 3b (same height as head — still side).
    let b2b = build_block_salted(2, *gid.as_bytes(), 77);
    let id_2b = block_id_from_block(&b2b).unwrap();
    assert!(matches!(
        driver.accept_block(&b2b, Some(gid)),
        AcceptOutcome::SideFork(_)
    ));
    let b3b = build_block_salted(3, *id_2b.as_bytes(), 77);
    let id_3b = block_id_from_block(&b3b).unwrap();
    assert!(matches!(
        driver.accept_block(&b3b, Some(id_2b)),
        AcceptOutcome::SideFork(_)
    ));
    let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
    assert_eq!(
        dp.latest_block_header_hash().unwrap(),
        Some(*id_3a.as_bytes()),
        "canonical untouched while the fork grows level"
    );

    // 4b promotes the fork — the reorg must re-apply 2b AND 3b AND 4b.
    let b4b = build_block_salted(4, *id_3b.as_bytes(), 77);
    let id_4b = block_id_from_block(&b4b).unwrap();
    match driver.accept_block(&b4b, Some(id_3b)) {
        AcceptOutcome::Accepted(id) => assert_eq!(id, id_4b),
        other => panic!("expected Accepted after deep reorg, got {other:?}"),
    }
    assert_eq!(driver.head_number(), 4);
    assert_eq!(
        dp.latest_block_header_hash().unwrap(),
        Some(*id_4b.as_bytes()),
        "head switched to the deeper fork"
    );
    // The num → id index must point at the b-chain on every height.
    let bi = BlockIndexStore::new(state.block_index.clone().unwrap());
    assert_eq!(bi.get(2).unwrap(), id_2b);
    assert_eq!(bi.get(3).unwrap(), id_3b);
    assert_eq!(bi.get(4).unwrap(), id_4b);
}

#[test]
fn orphan_chain_recovers_via_reorg_after_parent_arrives() {
    use tron_chainbase::BlockUndoStore;
    // Out-of-order delivery at the tip: child 3x arrives before its
    // parent 2x. The child is stashed as unlinked; when 2x arrives,
    // KhaosDb cascade-promotes the orphan to fork-tree head WITHOUT
    // executing it (the push outcome for 2x reports the head moved away
    // from 2x). The chain must still converge: the next push triggers
    // the reorg path, which replays the whole un-executed branch.
    let (state, blocks_be) = fresh_state();
    seed_alice(&state);
    let undo_be: Arc<dyn KvBackend> = mem();
    let mut driver = make_driver(state.clone(), blocks_be)
        .with_undo_store(BlockUndoStore::new(undo_be));

    let g = build_block(1, [0u8; 32]);
    let gid = block_id_from_block(&g).unwrap();
    driver.accept_block(&g, None);

    let b2 = build_block(2, *gid.as_bytes());
    let id_2 = block_id_from_block(&b2).unwrap();
    let b3 = build_block(3, *id_2.as_bytes());
    let id_3 = block_id_from_block(&b3).unwrap();
    let b4 = build_block(4, *id_3.as_bytes());
    let id_4 = block_id_from_block(&b4).unwrap();

    // Child first — rejected as unlinked (stashed).
    assert!(matches!(
        driver.accept_block(&b3, Some(id_2)),
        AcceptOutcome::RejectedValidation(reason) if reason.contains("unlinked")
    ));

    // Parent arrives: khaos promotes 2→3, head moves PAST 2 — the push
    // reports a non-extension outcome and nothing executes yet.
    let outcome_2 = driver.accept_block(&b2, Some(gid));
    assert!(
        !matches!(outcome_2, AcceptOutcome::Accepted(_)),
        "parent push must not report Accepted when the orphan cascade moved the head: {outcome_2:?}"
    );

    // The NEXT block converges the executed chain onto the fork-tree
    // head via the reorg path (replays 2, 3, then 4).
    match driver.accept_block(&b4, Some(id_3)) {
        AcceptOutcome::Accepted(id) => assert_eq!(id, id_4),
        other => panic!("expected Accepted via reorg replay, got {other:?}"),
    }
    assert_eq!(driver.head_number(), 4);
    let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
    assert_eq!(
        dp.latest_block_header_hash().unwrap(),
        Some(*id_4.as_bytes()),
        "executed head converged onto the promoted orphan chain"
    );
}

// ===========================================================================
// Deep-bulk-sync recovery (sync-recovery-v2): fleet apply-lock + shared fork
// tree. Each test below exercises a FAILURE MODE the wedge/BROKEN review
// called out, and is written so it discriminates: it passes with the fix and
// fails when the fix is ablated (documented per-test).
// ===========================================================================

use std::sync::Barrier;
use tron_chainbase::BlockUndoStore;
use tron_consensus::KhaosDb;
use tron_node::sync::SyncLeadership;

/// Build a linear canonical chain `1..=n` (block 1 is genesis-like), apply it
/// through `driver`, and return every block with its id in height order.
fn build_and_apply_chain(driver: &mut SyncDriver, n: i64) -> Vec<(Block, tron_types::BlockId)> {
    let mut out: Vec<(Block, tron_types::BlockId)> = Vec::new();
    let mut parent = [0u8; 32];
    for num in 1..=n {
        let b = build_block(num, parent);
        let id = block_id_from_block(&b).unwrap();
        let prev = if num == 1 { None } else { Some(out.last().unwrap().1) };
        match driver.accept_block(&b, prev) {
            AcceptOutcome::Accepted(got) => assert_eq!(got, id, "clean extension at {num}"),
            other => panic!("setup apply of block {num} failed: {other:?}"),
        }
        parent = *id.as_bytes();
        out.push((b, id));
    }
    out
}

/// The wedge and its structural fix, side by side. A driver promoted to leader
/// after a standby stretch holds a fork tree anchored far below the shared
/// executed head. With PRIVATE trees the block it drains has no parent in its
/// tree → orphan-stash → head pins (the observed wedge). With ONE shared tree
/// the parent is already linked → the block executes → the head advances.
///
/// Ablation: drop the `with_shared_khaos` on `b_shared` (private trees) and the
/// shared half wedges exactly like the private half — the recovery assertion
/// fails.
#[test]
fn stale_promotion_wedges_with_private_trees_but_recovers_with_shared_tree() {
    // --- Private trees: reproduce the wedge ---
    {
        let (state, blocks_be) = fresh_state();
        seed_alice(&state);
        // Driver B was briefly active early (tree anchored at height 2), then
        // stood by.
        let mut b_priv = make_driver(state.clone(), blocks_be.clone());
        let early = build_and_apply_chain(&mut b_priv, 2);
        assert_eq!(b_priv.head_number(), 2);

        // Driver A leads and advances the SHARED executed head far past B's
        // tree, on its OWN private tree.
        let mut a = make_driver(state.clone(), blocks_be.clone());
        // A re-seeds from disk (window ending at the shared head 2), then
        // extends to 20.
        let mut parent = *early[1].1.as_bytes();
        let mut top_id = early[1].1;
        for num in 3..=20 {
            let blk = build_block(num, parent);
            let id = block_id_from_block(&blk).unwrap();
            assert!(matches!(a.accept_block(&blk, Some(top_id)), AcceptOutcome::Accepted(_)));
            parent = *id.as_bytes();
            top_id = id;
        }
        assert_eq!(a.head_number(), 20);

        // Promote B: its private tree is still at height 2, so block 21
        // orphan-stashes and the head PINS. This is the wedge.
        let blk21 = build_block(21, *top_id.as_bytes());
        let out = b_priv.accept_block(&blk21, Some(top_id));
        assert!(
            matches!(&out, AcceptOutcome::RejectedValidation(r) if r.contains("unlinked")),
            "private stale tree must orphan-stash block 21 (the wedge): {out:?}"
        );
        assert_eq!(b_priv.head_number(), 20, "head pinned — no progress");
    }

    // --- Shared tree: recover ---
    {
        let (state, blocks_be) = fresh_state();
        seed_alice(&state);
        let shared = Arc::new(KhaosDb::new());

        let mut b_shared = make_driver(state.clone(), blocks_be.clone())
            .with_shared_khaos(shared.clone());
        let early = build_and_apply_chain(&mut b_shared, 2);
        assert_eq!(b_shared.head_number(), 2);

        let mut a = make_driver(state.clone(), blocks_be.clone())
            .with_shared_khaos(shared.clone());
        let mut parent = *early[1].1.as_bytes();
        let mut top_id = early[1].1;
        for num in 3..=20 {
            let blk = build_block(num, parent);
            let id = block_id_from_block(&blk).unwrap();
            assert!(matches!(a.accept_block(&blk, Some(top_id)), AcceptOutcome::Accepted(_)));
            parent = *id.as_bytes();
            top_id = id;
        }
        assert_eq!(a.head_number(), 20);

        // Promote B: with the shared tree, block 20's parent chain is present,
        // so block 21 links and EXECUTES. The head advances — no wedge.
        let blk21 = build_block(21, *top_id.as_bytes());
        let out = b_shared.accept_block(&blk21, Some(top_id));
        assert!(
            matches!(out, AcceptOutcome::Accepted(_)),
            "shared tree must let the promoted driver apply block 21: {out:?}"
        );
        assert_eq!(b_shared.head_number(), 21, "head advanced — wedge resolved");
    }
}

/// The shared-tree recovery must not depend on the 256-block re-seed window: a
/// promotion gap DEEPER than that window still recovers, because the shared
/// tree already holds the ancestry (a re-seed would only cover the last 256).
///
/// Ablation: private trees + a >256 gap can't be repaired by re-seeding the
/// promoted driver either, so this is a shared-tree-only property.
#[test]
fn deep_stale_promotion_beyond_seed_window_recovers_with_shared_tree() {
    let (state, blocks_be) = fresh_state();
    seed_alice(&state);
    let shared = Arc::new(KhaosDb::new());

    let mut b = make_driver(state.clone(), blocks_be.clone())
        .with_shared_khaos(shared.clone());
    let early = build_and_apply_chain(&mut b, 2);

    // Advance ~400 blocks (well past the 256 seed window, under the 1024 LRU).
    let mut a = make_driver(state.clone(), blocks_be.clone())
        .with_shared_khaos(shared.clone());
    let mut parent = *early[1].1.as_bytes();
    let mut top_id = early[1].1;
    for num in 3..=400 {
        let blk = build_block(num, parent);
        let id = block_id_from_block(&blk).unwrap();
        assert!(matches!(a.accept_block(&blk, Some(top_id)), AcceptOutcome::Accepted(_)));
        parent = *id.as_bytes();
        top_id = id;
    }
    assert_eq!(a.head_number(), 400);

    let blk401 = build_block(401, *top_id.as_bytes());
    let out = b.accept_block(&blk401, Some(top_id));
    assert!(matches!(out, AcceptOutcome::Accepted(_)), "deep-gap promotion applies: {out:?}");
    assert_eq!(b.head_number(), 401);
}

/// The lost-peer → churn scenario, bounded. Model repeated leadership takeovers
/// where each promoted driver re-drains the SAME window the pool re-offers.
/// With the shared tree every takeover makes progress and re-delivered blocks
/// are exactly-once (`AlreadyKnown`), so the head keeps advancing instead of
/// pinning, and nothing double-applies.
#[test]
fn repeated_leadership_takeover_applies_each_block_exactly_once() {
    let (state, blocks_be) = fresh_state();
    seed_alice(&state);
    let shared = Arc::new(KhaosDb::new());
    let leadership = Arc::new(SyncLeadership::new());

    // A rotating fleet of drivers, all sharing state + tree + leadership.
    let mut fleet: Vec<SyncDriver> = (0..4)
        .map(|_| {
            make_driver(state.clone(), blocks_be.clone())
                .with_shared_khaos(shared.clone())
                .with_leadership(leadership.clone())
        })
        .collect();

    // Genesis via the first driver.
    let g = build_block(1, [0u8; 32]);
    let gid = block_id_from_block(&g).unwrap();
    assert!(matches!(fleet[0].accept_block_synced(&g, None), AcceptOutcome::Accepted(_)));

    // Build a 30-block window.
    let mut blocks: Vec<(Block, tron_types::BlockId)> = Vec::new();
    let mut parent = *gid.as_bytes();
    for num in 2..=31 {
        let b = build_block(num, parent);
        let id = block_id_from_block(&b).unwrap();
        parent = *id.as_bytes();
        blocks.push((b, id));
    }

    let mut total_applied_deltas = 0usize;
    let baseline: Vec<usize> = fleet.iter().map(|d| d.stats().blocks_applied).collect();

    // Deliver the window one block at a time, but rotate the "leader" every
    // block AND re-deliver the previous block to the new leader (the churn +
    // re-offer pattern). Each block must apply exactly once across the fleet.
    for (i, (blk, _id)) in blocks.iter().enumerate() {
        let leader = i % fleet.len();
        // Re-deliver the already-applied previous block to this leader first
        // (pool re-offer): must be AlreadyKnown / no-op, never re-executed.
        if i > 0 {
            let (pblk, _pid) = &blocks[i - 1];
            let out = fleet[leader].accept_block_synced(pblk, None);
            assert!(
                matches!(out, AcceptOutcome::AlreadyKnown(_) | AcceptOutcome::SideFork(_)),
                "re-delivered block must not re-execute: {out:?}"
            );
        }
        let out = fleet[leader].accept_block_synced(blk, None);
        assert!(matches!(out, AcceptOutcome::Accepted(_)), "block {} applies: {out:?}", i + 2);
    }

    for (d, base) in fleet.iter().zip(baseline) {
        total_applied_deltas += d.stats().blocks_applied - base;
    }
    // Exactly the 30 window blocks executed, once each — no double-apply from
    // the churn/re-offer.
    assert_eq!(total_applied_deltas, 30, "each window block applied exactly once");
    assert_eq!(fleet[0].head_number(), 31, "head advanced across all the takeovers");
}

/// A genuinely divergent fork — one whose chain does NOT contain the latest
/// solidified block — is STILL rejected under the shared tree + apply lock. The
/// fix must not weaken fork choice.
#[test]
fn divergent_fork_still_rejected_under_shared_tree_and_lock() {
    let (state, blocks_be) = fresh_state();
    seed_alice(&state);
    let shared = Arc::new(KhaosDb::new());
    let leadership = Arc::new(SyncLeadership::new());
    let mut driver = make_driver(state.clone(), blocks_be.clone())
        .with_shared_khaos(shared.clone())
        .with_leadership(leadership.clone());

    let chain = build_and_apply_chain(&mut driver, 3);
    let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
    // Solidify block 2 — any winning chain must contain it.
    dp.save_latest_solidified_block_num(2);

    // A fork that diverges at block 1 (salted), so it does NOT contain the
    // solidified block 2: f2' → f3' → f4' (height 4, would top the head).
    let block1_id = chain[0].1;
    let store = BlockStore::new(blocks_be.clone());
    let f2 = build_block_salted(2, *block1_id.as_bytes(), 7);
    let f2id = block_id_from_block(&f2).unwrap();
    let f3 = build_block_salted(3, *f2id.as_bytes(), 7);
    let f3id = block_id_from_block(&f3).unwrap();
    let f4 = build_block_salted(4, *f3id.as_bytes(), 7);
    // Persist the fork blocks so the containment walk can traverse them and
    // reach a GENUINE divergence verdict (not a chain-gap skip).
    store.put(&f2id, &f2).unwrap();
    store.put(&f3id, &f3).unwrap();
    // Record the siblings in the shared tree, then present the fork tip.
    assert!(matches!(driver.accept_block_synced(&f2, Some(block1_id)), AcceptOutcome::SideFork(_)));
    assert!(matches!(driver.accept_block_synced(&f3, Some(f2id)), AcceptOutcome::SideFork(_)));
    let out = driver.accept_block_synced(&f4, Some(f3id));
    assert!(
        matches!(out, AcceptOutcome::RejectedSolidifiedDiverged(_)),
        "divergent fork must be rejected by the solidified-containment gate: {out:?}"
    );
    assert_eq!(driver.head_number(), 3, "canonical head unchanged after rejecting the fork");
}

/// A reorg whose old chain runs past undo-record coverage is refused CLEANLY —
/// with the chain untouched — rather than rolling back the covered blocks and
/// then getting stuck (a partial-rollback hybrid state).
///
/// Ablation: remove the up-front undo-coverage gate in `perform_reorg` and the
/// rollback loop unwinds block 4, then fails on block 3's missing record,
/// leaving the head at 3 with block 4 gone — a hybrid state; the "head
/// unchanged" assertion below then fails.
#[test]
fn reorg_refused_cleanly_when_undo_coverage_incomplete() {
    let (state, blocks_be) = fresh_state();
    seed_alice(&state);
    let undo_be: Arc<dyn KvBackend> = mem();
    let undo = BlockUndoStore::new(undo_be);
    let mut driver = make_driver(state.clone(), blocks_be.clone())
        .with_undo_store(undo.clone());

    // Canonical 1..=4.
    let chain = build_and_apply_chain(&mut driver, 4);
    assert_eq!(driver.head_number(), 4);

    // Simulate undo coverage that has been pruned below the reorg depth: drop
    // block 3's undo record (block 4's is kept). A reorg forking at block 2
    // must roll back [4, 3] — block 3 is now uncovered.
    undo.delete(3).unwrap();

    // Fork branching at block 2: f3' → f4' → f5' (height 5, tops the head).
    let block2_id = chain[1].1;
    let f3 = build_block_salted(3, *block2_id.as_bytes(), 9);
    let f3id = block_id_from_block(&f3).unwrap();
    let f4 = build_block_salted(4, *f3id.as_bytes(), 9);
    let f4id = block_id_from_block(&f4).unwrap();
    let f5 = build_block_salted(5, *f4id.as_bytes(), 9);
    assert!(matches!(driver.accept_block(&f3, Some(block2_id)), AcceptOutcome::SideFork(_)));
    assert!(matches!(driver.accept_block(&f4, Some(f3id)), AcceptOutcome::SideFork(_)));

    let out = driver.accept_block(&f5, Some(f4id));
    assert!(
        matches!(&out, AcceptOutcome::RejectedValidation(r) if r.contains("undo")),
        "reorg past undo coverage must be refused cleanly: {out:?}"
    );
    // Chain UNTOUCHED — no partial rollback.
    assert_eq!(driver.head_number(), 4, "head unchanged after the clean refusal");
    let bi = BlockIndexStore::new(state.block_index.clone().unwrap());
    assert_eq!(bi.get(4).unwrap(), chain[3].1, "canonical index unchanged at height 4");
    assert_eq!(bi.get(3).unwrap(), chain[2].1, "canonical index unchanged at height 3");
}

/// Forced concurrent takeover during a reorg: two drivers, sharing state +
/// undo + leadership, both attempt the SAME fork switch at the same instant.
/// The fleet apply lock must serialise them so the reorg happens exactly once —
/// no double rollback, no double-apply, no `MissingUndoRecord` from a consumed
/// undo record. Runs the race many times; with the lock it is deterministic.
///
/// Ablation: drop the `lock_apply` acquisition in `accept_block_synced` (or in
/// `drain_pool` / the near-tip path) and the two threads race the undo log —
/// one thread hits `MissingUndoRecord` (undo consumed by the other) or the
/// applied-count/ index diverges, tripping an assertion in some iteration.
#[test]
fn concurrent_reorg_takeover_is_single_applier_exactly_once() {
    for iter in 0..40 {
        let (state, blocks_be) = fresh_state();
        seed_alice(&state);
        let undo_be: Arc<dyn KvBackend> = mem();
        let undo = BlockUndoStore::new(undo_be);
        let leadership = Arc::new(SyncLeadership::new());

        // Driver A applies canonical 1..=3 (writes undo for 2 and 3). It keeps
        // a PRIVATE tree on purpose, so the shared-tree dedup can't mask the
        // lock: this isolates the apply lock as the thing under test.
        let mut a = make_driver(state.clone(), blocks_be.clone())
            .with_undo_store(undo.clone())
            .with_leadership(leadership.clone());
        let chain = build_and_apply_chain(&mut a, 3);

        // Driver B: separate tree, same shared state/undo/leadership. Seed B's
        // tree WITHOUT executing (so it can classify the same reorg) by pushing
        // the blocks straight into its fork tree.
        let mut b = make_driver(state.clone(), blocks_be.clone())
            .with_undo_store(undo.clone())
            .with_leadership(leadership.clone());
        b.khaos().start(chain[0].0.clone()).unwrap();
        b.khaos().push(chain[1].0.clone()).unwrap();
        b.khaos().push(chain[2].0.clone()).unwrap();

        // A fork branching at block 2 that tops the head: f3' → f4' (height 4).
        let block2_id = chain[1].1;
        let f3 = build_block_salted(3, *block2_id.as_bytes(), 3);
        let f3id = block_id_from_block(&f3).unwrap();
        let f4 = build_block_salted(4, *f3id.as_bytes(), 3);
        let f4id = block_id_from_block(&f4).unwrap();
        // Record the fork sibling f3 in BOTH trees (as a side fork). f4 is
        // presented live to trigger the reorg.
        assert!(matches!(a.accept_block(&f3, Some(block2_id)), AcceptOutcome::SideFork(_)));
        b.khaos().push(f3.clone()).unwrap();

        let a_base = a.stats().blocks_applied;
        let b_base = b.stats().blocks_applied;

        // Both drivers race to switch to f4 at the same instant. Each thread
        // returns its outcome AND its driver (moved in), so the post-race
        // per-driver applied counts are readable.
        let barrier = Arc::new(Barrier::new(2));
        let (oa, a, ob, b) = std::thread::scope(|s| {
            let ba = barrier.clone();
            let f4a = f4.clone();
            let ha = s.spawn(move || {
                ba.wait();
                let o = a.accept_block_synced(&f4a, Some(f3id));
                (o, a)
            });
            let bb = barrier.clone();
            let f4b = f4.clone();
            let hb = s.spawn(move || {
                bb.wait();
                let o = b.accept_block_synced(&f4b, Some(f3id));
                (o, b)
            });
            let (ra, a) = ha.join().unwrap();
            let (rb, b) = hb.join().unwrap();
            (ra, a, rb, b)
        });

        // Neither driver may report a corruption (a MissingUndoRecord rollback
        // fault surfaces as RejectedExecution). Both must end Accepted(f4).
        for (who, o) in [("A", &oa), ("B", &ob)] {
            match o {
                AcceptOutcome::Accepted(id) => assert_eq!(*id, f4id, "iter {iter}: {who} head=f4"),
                other => panic!("iter {iter}: {who} did not cleanly converge: {other:?}"),
            }
        }

        // Reload the state to read the committed head/index (both drivers wrote
        // to the same backends).
        let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
        assert_eq!(
            dp.latest_block_header_hash().unwrap(),
            Some(*f4id.as_bytes()),
            "iter {iter}: executed head is the fork tip"
        );
        let bi = BlockIndexStore::new(state.block_index.clone().unwrap());
        assert_eq!(bi.get(3).unwrap(), f3id, "iter {iter}: index repointed to fork at 3");
        assert_eq!(bi.get(4).unwrap(), f4id, "iter {iter}: index repointed to fork at 4");

        // The new fork's two blocks (f3, f4) executed EXACTLY ONCE across the
        // whole fleet — not once per driver.
        let applied = (a.stats().blocks_applied - a_base) + (b.stats().blocks_applied - b_base);
        assert_eq!(applied, 2, "iter {iter}: fork applied exactly once across the fleet");
    }
}
