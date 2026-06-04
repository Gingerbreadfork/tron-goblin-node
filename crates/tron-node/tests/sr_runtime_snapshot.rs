//! SR runtime + snapshot coordinator integration.
//!
//! Mirrors `sr_runtime.rs::runtime_produces_a_block_when_it_owns_the_slot`
//! but wraps every state backend in `SnapshotKvBackend` and attaches
//! the SR runtime to the shared `SnapshotStack`. Verifies that SR's
//! produced block lands as a tentative-write layer (depth = 1 after
//! one block, the layer tracks the produced block_num).

use std::sync::Arc;

use hex_literal::hex;
use tron_chainbase::{
    AccountStore, BlockIndexStore, BlockStore, BlockUndoStore, DynamicPropertiesStore, KvBackend,
    MemBackend, SnapshotKvBackend, WitnessScheduleStore, WitnessStore,
};
use tron_crypto::address::Address;
use tron_executor::StateBackends;
use tron_node::storage::SnapshotStack;
use tron_node::{SrIdentity, SrRuntime, WitnessConfig};
use tron_proto::{block_header::Raw as BlockHeaderRaw, Account, Block, BlockHeader, Witness};

const ALICE_PRIV: [u8; 32] =
    hex!("1234567890123456789012345678901234567890123456789012345678901234");
const ALICE_ADDR: [u8; 21] = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn snapshot_wrap(
    backends: &mut Vec<(String, Arc<SnapshotKvBackend>)>,
) -> Arc<dyn KvBackend> {
    let root: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
    let snap = Arc::new(SnapshotKvBackend::new(root));
    let name = format!("store_{}", backends.len());
    backends.push((name, snap.clone()));
    snap as Arc<dyn KvBackend>
}

fn fresh_snapshot_state() -> (StateBackends, Arc<dyn KvBackend>, Arc<dyn KvBackend>, SnapshotStack) {
    let mut backends: Vec<(String, Arc<SnapshotKvBackend>)> = Vec::new();
    let blocks_be: Arc<dyn KvBackend> = mem(); // append-only, not wrapped
    let witness_schedule_be = snapshot_wrap(&mut backends);
    let state = StateBackends {
        accounts: snapshot_wrap(&mut backends),
        witnesses: snapshot_wrap(&mut backends),
        votes: snapshot_wrap(&mut backends),
        delegation: snapshot_wrap(&mut backends),
        delegated_resources: snapshot_wrap(&mut backends),
        dyn_props: snapshot_wrap(&mut backends),
        proposals: snapshot_wrap(&mut backends),
        name_index: snapshot_wrap(&mut backends),
        id_index: snapshot_wrap(&mut backends),
        asset_v1: snapshot_wrap(&mut backends),
        asset_v2: snapshot_wrap(&mut backends),
        contracts: snapshot_wrap(&mut backends),
        abi: snapshot_wrap(&mut backends),
        exchange_v1: snapshot_wrap(&mut backends),
        exchange_v2: snapshot_wrap(&mut backends),
        market_orders: snapshot_wrap(&mut backends),
        nullifiers: snapshot_wrap(&mut backends),
        merkle_trees: None,
        code: Some(snapshot_wrap(&mut backends)),
        storage_row: Some(snapshot_wrap(&mut backends)),
        contract_state: Some(snapshot_wrap(&mut backends)),
        block_index: Some(mem()),
        witness_schedule: Some(witness_schedule_be.clone()),
    };
    let stack = SnapshotStack::from_named(backends);
    (state, blocks_be, witness_schedule_be, stack)
}

fn seed_head(
    state: &StateBackends,
    blocks_be: &Arc<dyn KvBackend>,
    khaos: &tron_consensus::KhaosDb,
) {
    use tron_executor::execute_block;
    use tron_types::sign_block;

    let mut block = Block {
        block_header: Some(BlockHeader {
            raw_data: Some(BlockHeaderRaw {
                number: 1,
                parent_hash: vec![0u8; 32],
                timestamp: 1_700_000_000_000,
                tx_trie_root: tron_types::calc_tx_trie_root(&[])
                    .map(|h| h.to_vec())
                    .unwrap_or_default(),
                witness_address: ALICE_ADDR.to_vec(),
                version: 28,
                ..Default::default()
            }),
            witness_signature: Vec::new(),
        }),
        transactions: Vec::new(),
    };
    sign_block(&mut block, &ALICE_PRIV).expect("sign");
    let block_id = tron_types::block_id_from_block(&block).unwrap();
    BlockStore::new(blocks_be.clone()).put(&block_id, &block).unwrap();
    if let Some(bi_be) = &state.block_index {
        BlockIndexStore::new(bi_be.clone()).put(&block_id).unwrap();
    }
    execute_block(state, &block, None).expect("execute genesis");
    khaos.start(block).expect("seed khaos");
    let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
    dp.save_genesis_block_timestamp(1_700_000_000_000);
}

#[tokio::test]
async fn sr_runtime_pushes_layer_when_snapshot_stack_attached() {
    let (state, blocks_be, witness_schedule_be, stack) = fresh_snapshot_state();
    let khaos = Arc::new(tron_consensus::KhaosDb::new());
    let undo_be: Arc<dyn KvBackend> = mem();

    // Seed witness row + head.
    {
        let ws = WitnessStore::new(state.witnesses.clone());
        ws.put(
            &Address::from_raw(ALICE_ADDR),
            &Witness {
                address: ALICE_ADDR.to_vec(),
                vote_count: 100,
                ..Default::default()
            },
        ).unwrap();
        let accts = AccountStore::new(state.accounts.clone());
        accts.put(
            &Address::from_raw(ALICE_ADDR),
            &Account {
                address: ALICE_ADDR.to_vec(),
                balance: 0,
                ..Default::default()
            },
        ).unwrap();
    }
    seed_head(&state, &blocks_be, &khaos);
    WitnessScheduleStore::new(witness_schedule_be).save_active(&[Address::from_raw(ALICE_ADDR)]).unwrap();

    // Past slot boundary.
    let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    dp.save_latest_block_header_timestamp(now - 10_000);
    dp.save_genesis_block_timestamp(now - 1_000_000_000);

    // Stack starts empty — seed_head used execute_block (no snapshot
    // path), so block 1 went straight to root.
    assert_eq!(stack.depth(), 0, "stack starts empty before SR produces");

    let identity = SrIdentity::from_config(&WitnessConfig {
        key_hex: Some(hex::encode(ALICE_PRIV)),
        ..Default::default()
    })
    .expect("identity");
    let mempool = Arc::new(tron_mempool::TxMempool::new(
        tron_mempool::MempoolConfig::default(),
    ));
    let runtime = SrRuntime::new(
        state.clone(),
        blocks_be.clone(),
        state.witness_schedule.as_ref().unwrap().clone(),
        khaos.clone(),
        BlockUndoStore::new(undo_be),
        mempool,
        identity,
        100,
    )
    .with_snapshot_stack(stack.clone());

    let notice = runtime
        .try_produce_for_test(i64::MIN)
        .expect("try_produce")
        .expect("expected a produced block");
    assert_eq!(notice.block_num, 2);

    // SR's apply ran through the coordinator → exactly one layer on
    // the stack, tracking the produced block's number.
    assert_eq!(stack.depth(), 1, "SR apply pushed one layer");
    assert_eq!(
        stack.block_nums(),
        vec![2],
        "layer tracks the produced block_num"
    );
}
