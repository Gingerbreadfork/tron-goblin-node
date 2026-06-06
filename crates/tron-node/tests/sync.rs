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
        nullifiers: mem(),
        merkle_trees: None,
        code: Some(mem()),
        storage_row: Some(mem()),
        contract_state: Some(mem()),
        block_index: Some(mem()),
        witness_schedule: Some(mem()),
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
    let mut block = Block {
        transactions: Vec::new(),
        block_header: Some(BlockHeader {
            raw_data: Some(BlockHeaderRaw {
                timestamp: 1_700_000_000_000 + num * 3000,
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
        peer_is_fast_forward: false,
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
fn accept_block_rejects_wrong_parent_link() {
    let (state, blocks_be) = fresh_state();
    seed_alice(&state);
    let mut driver = make_driver(state, blocks_be);
    let block = build_block(1, [0u8; 32]);
    // Lie about prev_id — driver should reject.
    let bogus = tron_types::BlockId::from_raw([0xffu8; 32]);
    let outcome = driver.accept_block(&block, Some(bogus));
    match outcome {
        AcceptOutcome::RejectedValidation(reason) => {
            assert!(reason.contains("parent link"), "got: {reason}");
        }
        other => panic!("expected RejectedValidation, got {other:?}"),
    }
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
