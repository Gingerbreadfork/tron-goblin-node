//! End-to-end tests for the snapshot-stack-driven SyncDriver reorg
//! path. Mirrors the canonical reorg test in `sync.rs` but with the
//! snapshot stack attached so `accept_block` uses `advance` per block
//! and `perform_reorg_via_snapshot` uses `revoke` instead of the
//! `BlockUndoStore` undo log.

use std::sync::Arc;
use std::time::Duration;

use hex_literal::hex;
use tron_chainbase::{
    AccountStore, DynamicPropertiesStore, KvBackend, MemBackend, SnapshotKvBackend,
};
use tron_executor::StateBackends;
use tron_node::storage::SnapshotStack;
use tron_node::sync::{AcceptOutcome, SyncConfig, SyncDriver};
use tron_proto::block_header::Raw as BlockHeaderRaw;
use tron_proto::{Account, AccountType, Block, BlockHeader};
use tron_types::{block_id_from_block, sign_block, BlockId};

const ALICE: [u8; 21] = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");
const ALICE_PRIV: [u8; 32] =
    hex!("1234567890123456789012345678901234567890123456789012345678901234");

/// Build an `OpenedStores`-shaped state where every state-mutating
/// backend is a `SnapshotKvBackend` over an in-memory root, paired
/// with the snapshot stack that owns the layer-management API.
fn snapshot_state(stores: &mut Vec<(String, Arc<SnapshotKvBackend>)>) -> Arc<dyn KvBackend> {
    let root: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
    let snap = Arc::new(SnapshotKvBackend::new(root));
    let name = format!("store_{}", stores.len());
    stores.push((name, snap.clone()));
    snap as Arc<dyn KvBackend>
}

fn build_snapshot_state() -> (StateBackends, Arc<dyn KvBackend>, SnapshotStack) {
    let mut stores: Vec<(String, Arc<SnapshotKvBackend>)> = Vec::new();
    let blocks_be: Arc<dyn KvBackend> = Arc::new(MemBackend::new()); // append-only, no snapshot
    let state = StateBackends {
        accounts: snapshot_state(&mut stores),
        witnesses: snapshot_state(&mut stores),
        votes: snapshot_state(&mut stores),
        delegation: snapshot_state(&mut stores),
        delegated_resources: snapshot_state(&mut stores),
        delegated_resource_account_index: None,
        dyn_props: snapshot_state(&mut stores),
        proposals: snapshot_state(&mut stores),
        name_index: snapshot_state(&mut stores),
        id_index: snapshot_state(&mut stores),
        asset_v1: snapshot_state(&mut stores),
        asset_v2: snapshot_state(&mut stores),
        contracts: snapshot_state(&mut stores),
        abi: snapshot_state(&mut stores),
        exchange_v1: snapshot_state(&mut stores),
        exchange_v2: snapshot_state(&mut stores),
        market_orders: snapshot_state(&mut stores),
        nullifiers: snapshot_state(&mut stores),
        merkle_trees: None,
        code: Some(snapshot_state(&mut stores)),
        storage_row: Some(snapshot_state(&mut stores)),
        contract_state: Some(snapshot_state(&mut stores)),
        block_index: Some(Arc::new(MemBackend::new())),
        witness_schedule: Some(snapshot_state(&mut stores)),
        reward_vi: None,
    };
    let stack = SnapshotStack::from_named(stores);
    (state, blocks_be, stack)
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
    build_block_with_ts(num, parent_hash, 1_700_000_000_000 + num * 3000)
}

fn build_block_with_ts(num: i64, parent_hash: [u8; 32], timestamp: i64) -> Block {
    let mut block = Block {
        transactions: Vec::new(),
        block_header: Some(BlockHeader {
            raw_data: Some(BlockHeaderRaw {
                timestamp,
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

fn make_driver_with_snapshot(
    state: StateBackends,
    blocks_be: Arc<dyn KvBackend>,
    stack: SnapshotStack,
) -> SyncDriver {
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
        follow_tip: false,
    };
    SyncDriver::new(state, cfg).with_snapshot_stack(stack.with_horizon(64))
}

#[test]
fn snapshot_path_applies_blocks_and_advances_head() {
    // Sanity: with the snapshot stack attached, a clean append-only
    // chain still applies blocks and the head advances. Mirrors the
    // baseline `accept_block_persists_to_block_store_and_index` test
    // shape but on the snapshot path.
    let (state, blocks_be, stack) = build_snapshot_state();
    seed_alice(&state);
    let mut driver = make_driver_with_snapshot(state.clone(), blocks_be, stack.clone());

    let g = build_block(1, [0u8; 32]);
    let gid = block_id_from_block(&g).unwrap();
    let outcome = driver.accept_block(&g, None);
    assert!(matches!(outcome, AcceptOutcome::Accepted(_)));

    let b2 = build_block(2, *gid.as_bytes());
    let id_2 = block_id_from_block(&b2).unwrap();
    let outcome = driver.accept_block(&b2, Some(gid));
    assert!(matches!(outcome, AcceptOutcome::Accepted(_)));

    let dp = DynamicPropertiesStore::new(state.dyn_props);
    assert_eq!(dp.latest_block_header_hash().unwrap().unwrap(), *id_2.as_bytes());
    // Two blocks applied → stack depth = 2 (one layer per applied
    // block, under the horizon).
    assert_eq!(stack.depth(), 2);
}

#[test]
fn snapshot_path_revokes_old_fork_on_reorg() {
    let (state, blocks_be, stack) = build_snapshot_state();
    seed_alice(&state);
    let mut driver = make_driver_with_snapshot(state.clone(), blocks_be, stack.clone());

    // Build canonical chain: g → 2a.
    let g = build_block(1, [0u8; 32]);
    let gid = block_id_from_block(&g).unwrap();
    driver.accept_block(&g, None);
    let b2a = build_block(2, *gid.as_bytes());
    let id_2a = block_id_from_block(&b2a).unwrap();
    driver.accept_block(&b2a, Some(gid));
    assert_eq!(stack.depth(), 2);

    // Sibling 2b on a different timestamp.
    let b2b = build_block_with_ts(2, *gid.as_bytes(), 1_700_000_000_999);
    let id_2b = block_id_from_block(&b2b).unwrap();
    driver.accept_block(&b2b, Some(gid));
    // Same-height sibling — SideFork, no state change, depth unchanged.
    assert_eq!(stack.depth(), 2);

    // 3b extends the sibling chain → reorg required.
    let b3b = build_block_with_ts(3, *id_2b.as_bytes(), 1_700_000_005_000);
    let outcome = driver.accept_block(&b3b, Some(id_2b));
    match outcome {
        AcceptOutcome::Accepted(_) => {
            // Snapshot-driven reorg should have:
            //   1. Revoked layer for block 2a.
            //   2. Applied block 2b under a fresh layer.
            //   3. Applied block 3b under another fresh layer.
            // Net depth: 3 (g, 2b, 3b).
            assert_eq!(stack.depth(), 3);
        }
        other => panic!("expected Accepted, got {other:?}"),
    }

    // Executed head must now be on the sibling chain.
    let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
    let head_hash = dp.latest_block_header_hash().unwrap().unwrap();
    assert_ne!(head_hash, *id_2a.as_bytes(), "head must have switched off 2a");
}

#[test]
fn snapshot_path_caps_depth_at_horizon() {
    // Apply more blocks than the horizon allows; bottom layers must
    // be merged into the root as they age out, keeping depth ≤ horizon.
    let (state, blocks_be, stack) = build_snapshot_state();
    seed_alice(&state);
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
        follow_tip: false,
    };
    let horizon = 4usize;
    let mut driver = SyncDriver::new(state, cfg).with_snapshot_stack(stack.clone().with_horizon(horizon));

    let mut last_hash = [0u8; 32];
    let mut prev_id: Option<BlockId> = None;
    for n in 1..=8 {
        let block = build_block(n, last_hash);
        let id = block_id_from_block(&block).unwrap();
        let outcome = driver.accept_block(&block, prev_id);
        assert!(matches!(outcome, AcceptOutcome::Accepted(_)), "block {n}");
        last_hash = *id.as_bytes();
        prev_id = Some(id);
    }

    // Depth is capped at horizon — older layers merged into root.
    assert!(
        stack.depth() <= horizon,
        "depth {} exceeds horizon {}",
        stack.depth(),
        horizon
    );
}

// Helper: SnapshotStack::from_named is a test-only constructor on the
// crate-public type. We expose it via tron_node::storage so tests can
// build a stack from named backends without invoking OpenedStores
// (which only supports real RocksDB).
//
// The actual constructor lives in `tron-node/src/storage.rs` — see
// `SnapshotStack::from_named`.
