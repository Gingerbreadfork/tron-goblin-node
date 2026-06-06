//! Proves `Manager.popTransactions` parity: when a block is reorged
//! off the canonical chain, every transaction it carried gets pushed
//! back into the mempool so it can be re-included in a future block.
//!
//! Setup mirrors `snapshot_reorg.rs`: a tron_executor::StateBackends
//! built from MemBackends, an in-memory TxMempool attached to the
//! SyncDriver, then a deliberate fork-switch via KhaosDb to trigger
//! `perform_reorg_via_snapshot`. We seed the old-fork block with a
//! signed transfer tx whose owner was funded in genesis, simulate the
//! SR runtime's post-apply `mempool.remove`, then verify the tx ends
//! up back in `pending` after the reorg.

use std::sync::Arc;
use std::time::Duration;

use hex_literal::hex;
use prost::Message as _;
use tron_chainbase::{AccountStore, KvBackend, MemBackend, SnapshotKvBackend};
use tron_crypto::address::Address;
use tron_executor::StateBackends;
use tron_mempool::{MempoolConfig, TxMempool};
use tron_node::storage::SnapshotStack;
use tron_node::sync::{AcceptOutcome, SyncConfig, SyncDriver};
use tron_proto::block_header::Raw as BlockHeaderRaw;
use tron_proto::transaction::{contract::ContractType, Contract as TxContract, Raw as TxRaw};
use tron_proto::{Account, AccountType, Block, BlockHeader, Transaction, TransferContract};
use tron_types::{block_id_from_block, sign_block, tx_id};

const ALICE: [u8; 21] = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");
const ALICE_PRIV: [u8; 32] =
    hex!("1234567890123456789012345678901234567890123456789012345678901234");

fn snapshot_state(stores: &mut Vec<(String, Arc<SnapshotKvBackend>)>) -> Arc<dyn KvBackend> {
    let root: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
    let snap = Arc::new(SnapshotKvBackend::new(root));
    let name = format!("store_{}", stores.len());
    stores.push((name, snap.clone()));
    snap as Arc<dyn KvBackend>
}

fn build_snapshot_state() -> (StateBackends, Arc<dyn KvBackend>, SnapshotStack) {
    let mut stores: Vec<(String, Arc<SnapshotKvBackend>)> = Vec::new();
    let blocks_be: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
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
    };
    let stack = SnapshotStack::from_named(stores);
    (state, blocks_be, stack)
}

fn seed_alice(state: &StateBackends) {
    let accounts = AccountStore::new(state.accounts.clone());
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

/// Build a signed transfer tx from a deterministic owner derived from
/// `seed` so distinct seeds produce distinct tx_ids. Owner is funded
/// in the mempool's view (the validator runs against an empty
/// stateless mempool, no need to seed the chain for these tests).
fn signed_transfer(seed: u8, expiration_offset_ms: i64) -> (Transaction, [u8; 32], Vec<u8>) {
    let mut owner = [0u8; 21];
    owner[0] = 0x41;
    owner[1..].fill(seed);
    let mut to = [0u8; 21];
    to[0] = 0x41;
    to[1..].fill(seed.wrapping_add(1));
    let tc = TransferContract {
        owner_address: owner.to_vec(),
        to_address: to.to_vec(),
        amount: 100,
    };
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let mut tx = Transaction {
        raw_data: Some(TxRaw {
            contract: vec![TxContract {
                r#type: ContractType::TransferContract as i32,
                parameter: Some(prost_types::Any {
                    type_url: "type.googleapis.com/protocol.TransferContract".into(),
                    value: tc.encode_to_vec(),
                }),
                ..Default::default()
            }],
            expiration: now_ms + expiration_offset_ms,
            timestamp: now_ms,
            ..Default::default()
        }),
        signature: vec![],
        ret: vec![],
    };
    let priv_key = {
        let mut k = [0u8; 32];
        k[0] = 0x10;
        k[31] = seed;
        k
    };
    tron_types::sign_transaction(&mut tx, &priv_key).unwrap();
    let id = tx_id(&tx).unwrap();
    let raw = tx.encode_to_vec();
    (tx, id, raw)
}

/// A transfer signed by ALICE (who is funded by `seed_alice`), so it
/// actually executes and mutates state — unlike `signed_transfer`, whose
/// seed-derived owner is unfunded and whose tx fails execution. Used to
/// prove a reorg rolls the resulting *state* back, not just the head.
fn alice_transfer(to: [u8; 21], amount: i64, expiration_offset_ms: i64) -> Transaction {
    let tc = TransferContract {
        owner_address: ALICE.to_vec(),
        to_address: to.to_vec(),
        amount,
    };
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let mut tx = Transaction {
        raw_data: Some(TxRaw {
            contract: vec![TxContract {
                r#type: ContractType::TransferContract as i32,
                parameter: Some(prost_types::Any {
                    type_url: "type.googleapis.com/protocol.TransferContract".into(),
                    value: tc.encode_to_vec(),
                }),
                ..Default::default()
            }],
            expiration: now_ms + expiration_offset_ms,
            timestamp: now_ms,
            ..Default::default()
        }),
        signature: vec![],
        ret: vec![],
    };
    tron_types::sign_transaction(&mut tx, &ALICE_PRIV).unwrap();
    tx
}

fn block_with_tx(num: i64, parent_hash: [u8; 32], ts: i64, tx: Transaction) -> Block {
    let txs = vec![tx];
    let tx_trie = tron_types::calc_tx_trie_root(&txs)
        .map(|h| h.to_vec())
        .unwrap_or_default();
    let mut block = Block {
        transactions: txs,
        block_header: Some(BlockHeader {
            raw_data: Some(BlockHeaderRaw {
                timestamp: ts,
                tx_trie_root: tx_trie,
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

fn empty_block(num: i64, parent_hash: [u8; 32], ts: i64) -> Block {
    let mut block = Block {
        transactions: Vec::new(),
        block_header: Some(BlockHeader {
            raw_data: Some(BlockHeaderRaw {
                timestamp: ts,
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

fn make_driver(
    state: StateBackends,
    blocks_be: Arc<dyn KvBackend>,
    stack: SnapshotStack,
    mempool: Arc<TxMempool>,
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
    };
    SyncDriver::new(state, cfg)
        .with_snapshot_stack(stack.with_horizon(64))
        .with_mempool(mempool)
}

#[test]
fn reorged_out_tx_lands_back_in_mempool() {
    // Snapshot-stack reorg path: build a fork tree where the
    // old-fork block carries a signed transfer; trigger the reorg;
    // verify the tx is back in the mempool's pending pool.
    let (state, blocks_be, stack) = build_snapshot_state();
    seed_alice(&state);
    let mempool = Arc::new(TxMempool::new(MempoolConfig::default()));
    let mut driver = make_driver(state.clone(), blocks_be, stack, mempool.clone());

    // Build the tx we'll smuggle into the old fork.
    let (tx, tx_id_bytes, _raw) = signed_transfer(0x42, 600_000);

    // Genesis.
    let g = empty_block(1, [0u8; 32], 1_700_000_000_000);
    let gid = block_id_from_block(&g).unwrap();
    let outcome = driver.accept_block(&g, None);
    assert!(matches!(outcome, AcceptOutcome::Accepted(_)));

    // Old-fork block 2a — contains our tx.
    let b2a = block_with_tx(2, *gid.as_bytes(), 1_700_000_003_000, tx);
    let outcome = driver.accept_block(&b2a, Some(gid));
    assert!(matches!(outcome, AcceptOutcome::Accepted(_)));

    // SyncDriver's post-apply mempool removal: every successful
    // `accept_block` drops the block's tx_ids from pending. Without
    // this, the mempool would still contain the tx and the
    // reorg repush would be a Duplicate no-op — uninteresting test.
    assert_eq!(mempool.pending_count(), 0, "pre-reorg mempool must be empty");

    // Sibling block 2b on a different timestamp + a 3b extending it
    // to force a fork switch.
    let b2b = empty_block(2, *gid.as_bytes(), 1_700_000_000_999);
    let id_2b = block_id_from_block(&b2b).unwrap();
    driver.accept_block(&b2b, Some(gid));

    let b3b = empty_block(3, *id_2b.as_bytes(), 1_700_000_005_000);
    let outcome = driver.accept_block(&b3b, Some(id_2b));
    assert!(
        matches!(outcome, AcceptOutcome::Accepted(_)),
        "reorg should have succeeded, got: {outcome:?}"
    );

    // Repush: the tx that was in the reorged-out block 2a is now
    // back in the mempool.
    assert_eq!(
        mempool.pending_count(),
        1,
        "reorged-out tx must be re-pushed into pending"
    );
    assert!(
        mempool.get(&tx_id_bytes).is_some(),
        "the exact reorged-out tx_id should be present"
    );
}

#[test]
fn tx_in_both_forks_stays_in_pending_only_once() {
    // Both old- and new-fork blocks carry the SAME tx. After reorg,
    // mempool repushes the old-fork's copy; since the new-fork
    // block-apply path does NOT remove from mempool (mempool can't
    // see chain inclusion today), we'd expect the tx to remain
    // pending. Either way, repush dedup means we never end up with
    // two copies of the same tx in pending.
    let (state, blocks_be, stack) = build_snapshot_state();
    seed_alice(&state);
    let mempool = Arc::new(TxMempool::new(MempoolConfig::default()));
    let mut driver = make_driver(state.clone(), blocks_be, stack, mempool.clone());

    let (tx, tx_id_bytes, _raw) = signed_transfer(0x77, 600_000);

    let g = empty_block(1, [0u8; 32], 1_700_000_000_000);
    let gid = block_id_from_block(&g).unwrap();
    driver.accept_block(&g, None);

    let b2a = block_with_tx(2, *gid.as_bytes(), 1_700_000_003_000, tx.clone());
    driver.accept_block(&b2a, Some(gid));

    // Sibling 2b ALSO carries the tx (same content, same tx_id).
    let b2b = block_with_tx(2, *gid.as_bytes(), 1_700_000_000_999, tx);
    let id_2b = block_id_from_block(&b2b).unwrap();
    driver.accept_block(&b2b, Some(gid));

    let b3b = empty_block(3, *id_2b.as_bytes(), 1_700_000_005_000);
    driver.accept_block(&b3b, Some(id_2b));

    // Post-reorg: the tx is now on the NEW fork (block 2b) too.
    // Repush from old 2a pushes it back; the new 2b's apply then
    // dropped it from pending. Net: NOT in pending — it's on chain.
    assert_eq!(
        mempool.pending_count(),
        0,
        "tx is on the new fork ⇒ apply removed it from pending after repush"
    );
    assert!(mempool.get(&tx_id_bytes).is_none());
}

#[test]
fn expired_tx_dropped_during_repush() {
    // A reorged-out tx whose expiration has elapsed by the time
    // we repush must NOT enter the pending pool — matches
    // java-tron's rePushLoop where validation rejects expired txs.
    let (state, blocks_be, stack) = build_snapshot_state();
    seed_alice(&state);
    let mempool = Arc::new(TxMempool::new(MempoolConfig::default()));
    let mut driver = make_driver(state.clone(), blocks_be, stack, mempool.clone());

    // Tx with a 1ms expiration window — by the time the reorg runs
    // it'll be expired. Block-apply doesn't check expiration so the
    // block accepts; mempool.submit DOES check.
    let (tx, tx_id_bytes, _raw) = signed_transfer(0x99, 1);

    let g = empty_block(1, [0u8; 32], 1_700_000_000_000);
    let gid = block_id_from_block(&g).unwrap();
    driver.accept_block(&g, None);

    let b2a = block_with_tx(2, *gid.as_bytes(), 1_700_000_003_000, tx);
    driver.accept_block(&b2a, Some(gid));

    // Sleep enough to make the tx expire.
    std::thread::sleep(Duration::from_millis(50));

    let b2b = empty_block(2, *gid.as_bytes(), 1_700_000_000_999);
    let id_2b = block_id_from_block(&b2b).unwrap();
    driver.accept_block(&b2b, Some(gid));
    let b3b = empty_block(3, *id_2b.as_bytes(), 1_700_000_005_000);
    driver.accept_block(&b3b, Some(id_2b));

    // Expired tx must not have entered pending.
    assert_eq!(
        mempool.pending_count(),
        0,
        "expired tx must be dropped, not re-pushed"
    );
    assert!(mempool.get(&tx_id_bytes).is_none());
}

#[test]
fn repush_is_a_noop_when_no_blocks_are_reorged() {
    // Sanity: pushing a clean append-only chain (no fork-switch)
    // must NOT trigger any repush behaviour — the mempool stays
    // exactly as configured by accept_block.
    let (state, blocks_be, stack) = build_snapshot_state();
    seed_alice(&state);
    let mempool = Arc::new(TxMempool::new(MempoolConfig::default()));
    let mut driver = make_driver(state.clone(), blocks_be, stack, mempool.clone());

    let g = empty_block(1, [0u8; 32], 1_700_000_000_000);
    let gid = block_id_from_block(&g).unwrap();
    driver.accept_block(&g, None);

    let b2 = empty_block(2, *gid.as_bytes(), 1_700_000_003_000);
    let id_2 = block_id_from_block(&b2).unwrap();
    driver.accept_block(&b2, Some(gid));

    let b3 = empty_block(3, *id_2.as_bytes(), 1_700_000_006_000);
    driver.accept_block(&b3, Some(id_2));

    assert_eq!(mempool.pending_count(), 0, "no reorg → mempool untouched");
}

// =============================================================================
// Legacy BlockUndoStore path (no snapshot stack) — same fixture
// shape, exercised through `perform_reorg` instead of
// `perform_reorg_via_snapshot`.
// =============================================================================

fn legacy_state() -> (StateBackends, Arc<dyn KvBackend>) {
    let blocks_be: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
    let raw_state = StateBackends {
        accounts: Arc::new(MemBackend::new()),
        witnesses: Arc::new(MemBackend::new()),
        votes: Arc::new(MemBackend::new()),
        delegation: Arc::new(MemBackend::new()),
        delegated_resources: Arc::new(MemBackend::new()),
        delegated_resource_account_index: None,
        dyn_props: Arc::new(MemBackend::new()),
        proposals: Arc::new(MemBackend::new()),
        name_index: Arc::new(MemBackend::new()),
        id_index: Arc::new(MemBackend::new()),
        asset_v1: Arc::new(MemBackend::new()),
        asset_v2: Arc::new(MemBackend::new()),
        contracts: Arc::new(MemBackend::new()),
        abi: Arc::new(MemBackend::new()),
        exchange_v1: Arc::new(MemBackend::new()),
        exchange_v2: Arc::new(MemBackend::new()),
        market_orders: Arc::new(MemBackend::new()),
        nullifiers: Arc::new(MemBackend::new()),
        merkle_trees: None,
        code: Some(Arc::new(MemBackend::new())),
        storage_row: Some(Arc::new(MemBackend::new())),
        contract_state: Some(Arc::new(MemBackend::new())),
        block_index: Some(Arc::new(MemBackend::new())),
        witness_schedule: Some(Arc::new(MemBackend::new())),
    };
    (raw_state, blocks_be)
}

fn make_driver_legacy(
    state: StateBackends,
    blocks_be: Arc<dyn KvBackend>,
    mempool: Arc<TxMempool>,
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
    };
    let undo_be: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
    SyncDriver::new(state, cfg)
        .with_undo_store(tron_chainbase::BlockUndoStore::new(undo_be))
        .with_mempool(mempool)
}

#[test]
fn legacy_reorg_path_also_repushes_old_fork_txs() {
    // Same shape as `reorged_out_tx_lands_back_in_mempool` but
    // without a snapshot stack attached — exercises the legacy
    // `perform_reorg` + `rollback_block` path. Both paths call the
    // shared `repush_reorged_txs` helper, but having a dedicated
    // test means future refactors that touch only one path can't
    // silently regress the other.
    let (state, blocks_be) = legacy_state();
    seed_alice(&state);
    let mempool = Arc::new(TxMempool::new(MempoolConfig::default()));
    let mut driver = make_driver_legacy(state.clone(), blocks_be, mempool.clone());

    let (tx, tx_id_bytes, _raw) = signed_transfer(0x55, 600_000);

    let g = empty_block(1, [0u8; 32], 1_700_000_000_000);
    let gid = block_id_from_block(&g).unwrap();
    let outcome = driver.accept_block(&g, None);
    assert!(matches!(outcome, AcceptOutcome::Accepted(_)));

    let b2a = block_with_tx(2, *gid.as_bytes(), 1_700_000_003_000, tx);
    let outcome = driver.accept_block(&b2a, Some(gid));
    assert!(matches!(outcome, AcceptOutcome::Accepted(_)));
    assert_eq!(mempool.pending_count(), 0, "drop_included_txs ran");

    let b2b = empty_block(2, *gid.as_bytes(), 1_700_000_000_999);
    let id_2b = block_id_from_block(&b2b).unwrap();
    driver.accept_block(&b2b, Some(gid));

    let b3b = empty_block(3, *id_2b.as_bytes(), 1_700_000_005_000);
    let outcome = driver.accept_block(&b3b, Some(id_2b));
    assert!(
        matches!(outcome, AcceptOutcome::Accepted(_)),
        "legacy reorg should have succeeded, got: {outcome:?}"
    );

    // The reorged-out tx is back in pending.
    assert_eq!(mempool.pending_count(), 1);
    assert!(mempool.get(&tx_id_bytes).is_some());
}

#[test]
fn legacy_reorg_path_drops_expired_tx_during_repush() {
    let (state, blocks_be) = legacy_state();
    seed_alice(&state);
    let mempool = Arc::new(TxMempool::new(MempoolConfig::default()));
    let mut driver = make_driver_legacy(state.clone(), blocks_be, mempool.clone());

    let (tx, tx_id_bytes, _raw) = signed_transfer(0x66, 1);

    let g = empty_block(1, [0u8; 32], 1_700_000_000_000);
    let gid = block_id_from_block(&g).unwrap();
    driver.accept_block(&g, None);

    let b2a = block_with_tx(2, *gid.as_bytes(), 1_700_000_003_000, tx);
    driver.accept_block(&b2a, Some(gid));

    std::thread::sleep(Duration::from_millis(50));

    let b2b = empty_block(2, *gid.as_bytes(), 1_700_000_000_999);
    let id_2b = block_id_from_block(&b2b).unwrap();
    driver.accept_block(&b2b, Some(gid));
    let b3b = empty_block(3, *id_2b.as_bytes(), 1_700_000_005_000);
    driver.accept_block(&b3b, Some(id_2b));

    assert_eq!(
        mempool.pending_count(),
        0,
        "expired tx must be dropped, not re-pushed"
    );
    assert!(mempool.get(&tx_id_bytes).is_none());
}

#[test]
fn legacy_reorg_rolls_back_account_state_to_the_winning_fork() {
    // The core of "reorg-driven state rollback": prove that a block's
    // STATE effect (not just the head pointer) is undone when the block
    // is reorged off the chain. Branch A applies a real ALICE→BOB
    // transfer that creates BOB; branch B (taller, no transfer) wins.
    // After the reorg BOB's account must be gone — block 2a's writes
    // were reversed via its undo record (`rollback_block`).
    let (state, blocks_be) = legacy_state();
    seed_alice(&state); // ALICE balance = 1_000_000_000
    let mempool = Arc::new(TxMempool::new(MempoolConfig::default()));
    let mut driver = make_driver_legacy(state.clone(), blocks_be, mempool.clone());
    let accounts = AccountStore::new(state.accounts.clone());

    let mut bob = [0u8; 21];
    bob[0] = 0x41;
    bob[1..].fill(0xbb);
    let bob_addr = Address::from_raw(bob);

    // Genesis.
    let g = empty_block(1, [0u8; 32], 1_700_000_000_000);
    let gid = block_id_from_block(&g).unwrap();
    assert!(matches!(driver.accept_block(&g, None), AcceptOutcome::Accepted(_)));
    assert!(accounts.get(&bob_addr).unwrap().is_none(), "BOB absent at genesis");

    // Branch A — block 2a carries an ALICE→BOB transfer that creates BOB.
    let tx = alice_transfer(bob, 500_000, 600_000);
    let b2a = block_with_tx(2, *gid.as_bytes(), 1_700_000_003_000, tx);
    assert!(
        matches!(driver.accept_block(&b2a, Some(gid)), AcceptOutcome::Accepted(_)),
        "block 2a applied"
    );
    assert_eq!(driver.head_number(), 2);
    assert_eq!(
        accounts.get(&bob_addr).unwrap().map(|a| a.balance),
        Some(500_000),
        "branch A executed the transfer → BOB funded"
    );

    // Branch B — taller (2b + 3b), no transfer → triggers the reorg.
    let b2b = empty_block(2, *gid.as_bytes(), 1_700_000_000_999);
    let id_2b = block_id_from_block(&b2b).unwrap();
    driver.accept_block(&b2b, Some(gid));
    let b3b = empty_block(3, *id_2b.as_bytes(), 1_700_000_005_000);
    assert!(
        matches!(driver.accept_block(&b3b, Some(id_2b)), AcceptOutcome::Accepted(_)),
        "reorg to branch B succeeded"
    );

    // Head switched AND block 2a's state effect was rolled back: BOB,
    // created only on branch A, no longer exists.
    assert_eq!(driver.head_number(), 3, "head is on branch B");
    assert!(
        accounts.get(&bob_addr).unwrap().is_none(),
        "BOB's account creation was rolled back by the reorg (state, not just head)"
    );
}

#[test]
fn peer_block_apply_drops_included_txs_from_mempool() {
    // (b) Direct test: a tx in the mempool that's then included in
    // a block we apply (no reorg, no SR) gets removed from pending.
    // Before this change the tx would have stayed in pending until
    // expiration.
    let (state, blocks_be) = legacy_state();
    seed_alice(&state);
    let mempool = Arc::new(TxMempool::new(MempoolConfig::default()));
    let mut driver = make_driver_legacy(state.clone(), blocks_be, mempool.clone());

    let (tx, tx_id_bytes, raw) = signed_transfer(0x88, 600_000);
    mempool.submit(&raw).expect("tx accepted into mempool");
    assert_eq!(mempool.pending_count(), 1);

    let g = empty_block(1, [0u8; 32], 1_700_000_000_000);
    let gid = block_id_from_block(&g).unwrap();
    driver.accept_block(&g, None);

    let b2 = block_with_tx(2, *gid.as_bytes(), 1_700_000_003_000, tx);
    let outcome = driver.accept_block(&b2, Some(gid));
    assert!(matches!(outcome, AcceptOutcome::Accepted(_)));

    assert_eq!(
        mempool.pending_count(),
        0,
        "peer-block apply must drop the tx_id from mempool"
    );
    assert!(mempool.get(&tx_id_bytes).is_none());
}

