//! java-tron `ForkController` accounting during block apply: every applied
//! block folds its witness and version into the statistics after the block,
//! and a maintenance boundary resets the pending forks.

use std::sync::Arc;

use tron_chainbase::fork::{VERSION_4_8_2, VERSION_4_8_2_2};
use tron_chainbase::{
    DynamicPropertiesStore, KvBackend, MemBackend, WitnessScheduleStore, WitnessStore,
};
use tron_crypto::address::Address;
use tron_executor::{execute_block_with_config, ExecConfig, StateBackends};
use tron_proto::{block_header::Raw as BlockHeaderRaw, Block, BlockHeader, Witness};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn fresh_state() -> StateBackends {
    StateBackends {
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
    }
}

fn addr(byte: u8) -> [u8; 21] {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(byte);
    a
}

fn block(num: i64, parent: [u8; 32], witness: [u8; 21], ts: i64, version: i32) -> Block {
    Block {
        block_header: Some(BlockHeader {
            raw_data: Some(BlockHeaderRaw {
                number: num,
                parent_hash: parent.to_vec(),
                timestamp: ts,
                tx_trie_root: tron_types::calc_tx_trie_root(&[])
                    .map(|h| h.to_vec())
                    .unwrap_or_default(),
                witness_address: witness.to_vec(),
                version,
                ..Default::default()
            }),
            witness_signature: Vec::new(),
        }),
        transactions: Vec::new(),
    }
}

struct Chain {
    state: StateBackends,
    dp: DynamicPropertiesStore,
    witnesses: Vec<[u8; 21]>,
    head: [u8; 32],
    next_num: i64,
    next_ts: i64,
}

impl Chain {
    fn new(next_maintenance_ms: i64) -> Self {
        let state = fresh_state();
        let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
        dp.save_maintenance_time_interval(6 * 3600 * 1000);
        dp.save_next_maintenance_time(next_maintenance_ms);
        let witnesses = vec![addr(0xaa), addr(0xbb), addr(0xcc)];
        let ws = WitnessStore::new(state.witnesses.clone());
        for (i, w) in witnesses.iter().enumerate() {
            ws.put(
                &Address::from_raw(*w),
                &Witness {
                    address: w.to_vec(),
                    vote_count: 300 - 100 * i as i64,
                    ..Default::default()
                },
            )
            .unwrap();
        }
        WitnessScheduleStore::new(state.witness_schedule.as_ref().unwrap().clone())
            .save_active(&witnesses.iter().map(|w| Address::from_raw(*w)).collect::<Vec<_>>())
            .unwrap();
        let mut chain = Chain {
            state,
            dp,
            witnesses,
            head: [0u8; 32],
            next_num: 1,
            next_ts: 1_700_000_000_000,
        };
        chain.apply(0, 36);
        chain
    }

    fn apply(&mut self, witness_idx: usize, version: i32) {
        let b = block(
            self.next_num,
            self.head,
            self.witnesses[witness_idx],
            self.next_ts,
            version,
        );
        execute_block_with_config(&self.state, &b, None, &ExecConfig::unsigned())
            .unwrap_or_else(|e| panic!("block {} failed: {e:?}", self.next_num));
        self.head = self.dp.latest_block_header_hash().unwrap().unwrap();
        self.next_num += 1;
        self.next_ts += 3_000;
    }
}

#[test]
fn block_versions_accumulate_until_the_fork_passes() {
    let mut chain = Chain::new(1_800_000_000_000);
    assert_eq!(chain.dp.fork_stats(VERSION_4_8_2).unwrap(), vec![1, 0, 0]);
    // 70% of three witnesses is three.
    chain.apply(0, VERSION_4_8_2_2);
    chain.apply(1, VERSION_4_8_2_2);
    assert_eq!(chain.dp.fork_stats(VERSION_4_8_2_2).unwrap(), vec![1, 1, 0]);
    assert!(!chain.dp.fork_passed(VERSION_4_8_2_2));
    chain.apply(2, VERSION_4_8_2_2);
    assert!(chain.dp.fork_passed(VERSION_4_8_2_2));
    assert_eq!(chain.dp.latest_fork_version(), 0);
    // The next block of that version records the pass and fills in version 36.
    chain.apply(0, VERSION_4_8_2_2);
    assert_eq!(chain.dp.latest_fork_version(), VERSION_4_8_2_2);
    assert!(chain.dp.fork_passed(VERSION_4_8_2));
}

#[test]
fn a_maintenance_boundary_resets_pending_fork_stats() {
    // Block 1 at t0, block 2 at t0+3s, block 3 at t0+6s crosses the boundary.
    let mut chain = Chain::new(1_700_000_006_000);
    chain.apply(0, VERSION_4_8_2_2);
    assert_eq!(chain.dp.fork_stats(VERSION_4_8_2_2).unwrap(), vec![1, 0, 0]);
    chain.apply(1, VERSION_4_8_2_2);
    // The reset ran before this block's own update was folded in.
    assert_eq!(chain.dp.fork_stats(VERSION_4_8_2_2).unwrap(), vec![0, 1, 0]);
    assert!(!chain.dp.fork_passed(VERSION_4_8_2_2));
}

#[test]
fn a_block_from_an_unscheduled_witness_leaves_the_stats_alone() {
    let mut chain = Chain::new(1_800_000_000_000);
    chain.witnesses.push(addr(0xdd));
    WitnessStore::new(chain.state.witnesses.clone())
        .put(
            &Address::from_raw(addr(0xdd)),
            &Witness {
                address: addr(0xdd).to_vec(),
                vote_count: 1,
                ..Default::default()
            },
        )
        .unwrap();
    chain.apply(3, VERSION_4_8_2_2);
    assert!(chain.dp.fork_stats(VERSION_4_8_2_2).is_none());
}
