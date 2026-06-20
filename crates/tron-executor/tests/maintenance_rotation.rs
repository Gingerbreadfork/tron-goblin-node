//! End-to-end test for `BlockExecutionReport.maintenance`.
//!
//! Confirms that when a block crosses the `next_maintenance_time`
//! boundary AND runs `doMaintenance` (i.e. block_num != 1), the
//! returned report surfaces the pre/post-rotation SR lists and the
//! pre-bump `next_maintenance_time` value. Downstream
//! [`tron_node::sync::SyncDriver`] consumes this to update the
//! cross-rotation [`tron_consensus::SrEpochSnapshot`] used by PBFT
//! vote validation.

use std::sync::Arc;

use tron_chainbase::{
    AccountStore, DynamicPropertiesStore, KvBackend, MemBackend, VotesStore, WitnessScheduleStore,
    WitnessStore,
};
use tron_crypto::address::Address;
use tron_executor::{
    execute_block_with_config, BlockExecError, BlockExecutionReport, ExecConfig, StateBackends,
};
use tron_proto::{
    block_header::Raw as BlockHeaderRaw, Account, Block, BlockHeader, Vote, Votes, Witness,
};
use tron_types::BlockId;

/// Apply a synthetic UNSIGNED block. Production code path runs through
/// `execute_block`/`execute_block_with_config` with the default-strict
/// `ExecConfig` (sig required); these tests skip that gate because they
/// exercise maintenance/rotation logic, not the witness-sig path.
fn apply_unsigned(
    state: &StateBackends,
    block: &Block,
    prev: Option<BlockId>,
) -> Result<BlockExecutionReport, BlockExecError> {
    execute_block_with_config(state, block, prev, &ExecConfig::unsigned())
}

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

fn empty_block(num: i64, parent_hash: [u8; 32], witness: [u8; 21], timestamp_ms: i64) -> Block {
    Block {
        block_header: Some(BlockHeader {
            raw_data: Some(BlockHeaderRaw {
                number: num,
                parent_hash: parent_hash.to_vec(),
                timestamp: timestamp_ms,
                tx_trie_root: tron_types::calc_tx_trie_root(&[])
                    .map(|h| h.to_vec())
                    .unwrap_or_default(),
                witness_address: witness.to_vec(),
                ..Default::default()
            }),
            witness_signature: Vec::new(),
        }),
        transactions: Vec::new(),
    }
}

fn put_witness(state: &StateBackends, who: [u8; 21], votes: i64) {
    WitnessStore::new(state.witnesses.clone()).put(
        &Address::from_raw(who),
        &Witness {
            address: who.to_vec(),
            vote_count: votes,
            ..Default::default()
        },
    ).unwrap();
}

fn cast_vote(state: &StateBackends, voter: [u8; 21], for_who: [u8; 21], votes: i64) {
    // Seed the voter's account with frozen balance so the vote tally
    // pass picks them up. apply_maintenance reads VotesStore directly.
    AccountStore::new(state.accounts.clone()).put(
        &Address::from_raw(voter),
        &Account {
            address: voter.to_vec(),
            balance: 1_000_000,
            ..Default::default()
        },
    ).unwrap();
    VotesStore::new(state.votes.clone()).put(
        &Address::from_raw(voter),
        &Votes {
            address: voter.to_vec(),
            old_votes: vec![],
            new_votes: vec![Vote {
                vote_address: for_who.to_vec(),
                vote_count: votes,
            }],
        },
    ).unwrap();
}

#[test]
fn maintenance_block_surfaces_rotation_on_report() {
    let state = fresh_state();
    let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
    dp.save_maintenance_time_interval(6 * 3600 * 1000);
    dp.save_next_maintenance_time(1_700_000_000_000);

    // Initial SR set = [w_old]. After maintenance, the votes flip the
    // active list to [w_new] (since w_new gets all the votes).
    let w_old = addr(0xaa);
    let w_new = addr(0xbb);
    put_witness(&state, w_old, 0);
    put_witness(&state, w_new, 1_000);
    cast_vote(&state, addr(0xcc), w_new, 1_000);

    // Seed the on-disk active set as [w_old] so apply_maintenance can
    // capture it as `prev_active`.
    WitnessScheduleStore::new(state.witness_schedule.as_ref().unwrap().clone())
        .save_active(&[Address::from_raw(w_old)]).unwrap();

    // Genesis at num=1 doesn't run doMaintenance (java-tron's special
    // case) — apply it just to bump the head pointer.
    apply_unsigned(
        &state,
        &empty_block(1, [0u8; 32], w_old, 1_699_999_997_000),
        None,
    )
    .expect("genesis");

    // Block 2 at the boundary: runs doMaintenance, swaps active set
    // from [w_old] to [w_new], and surfaces the rotation.
    let head = dp.latest_block_header_hash().unwrap().unwrap();
    let report = apply_unsigned(&state, &empty_block(2, head, w_old, 1_700_000_000_000), None)
        .expect("block 2 at boundary");

    let rot = report
        .maintenance
        .as_ref()
        .expect("MaintenanceRotation must be surfaced when doMaintenance runs");
    assert_eq!(
        rot.prev_active,
        vec![Address::from_raw(w_old)],
        "prev_active must be the pre-rotation SR list"
    );
    // The maintenance pass returns the top-27 candidates by vote_count
    // (then address-ascending tiebreak). With only 2 candidates both
    // make the cut; w_new ranks first by votes.
    assert_eq!(
        rot.new_active,
        vec![Address::from_raw(w_new), Address::from_raw(w_old)],
        "new_active must rank by vote_count descending"
    );
    // The key parity invariant: the previously-only-active witness
    // (w_old) must still be flagged, and w_new must now be flagged as
    // a post-rotation SR.
    assert!(rot.new_active.contains(&Address::from_raw(w_new)));
    assert_ne!(
        rot.prev_active, rot.new_active,
        "rotation must produce a different active set when votes flip the ranking"
    );
    // before_maintenance_time_ms must be the PRE-BUMP next_maintenance_time
    // value (the value we saved above before the bump).
    assert_eq!(
        rot.before_maintenance_time_ms, 1_700_000_000_000,
        "before_maintenance_time_ms must capture the pre-rotation NEXT_MAINTENANCE_TIME"
    );
    // Sanity: the bumped value is one interval later.
    assert_eq!(
        dp.next_maintenance_time().unwrap_or(0),
        1_700_000_000_000 + 6 * 3600 * 1000,
        "NEXT_MAINTENANCE_TIME must advance one interval"
    );
}

#[test]
fn genesis_block_has_no_maintenance_rotation_even_at_boundary() {
    // java-tron's `blockNum != 1` special case: a block 1 that
    // crosses the maintenance boundary BUMPS `next_maintenance_time`
    // but DOES NOT run doMaintenance — so no rotation surfaces.
    let state = fresh_state();
    let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
    dp.save_maintenance_time_interval(6 * 3600 * 1000);
    dp.save_next_maintenance_time(1_700_000_000_000);

    let w = addr(0xaa);
    put_witness(&state, w, 100);

    let report = apply_unsigned(
        &state,
        &empty_block(1, [0u8; 32], w, 1_700_000_000_000),
        None,
    )
    .expect("block 1 at boundary");
    assert!(
        report.maintenance.is_none(),
        "block 1 must skip doMaintenance and report no rotation"
    );
}

#[test]
fn non_boundary_block_has_no_maintenance_rotation() {
    let state = fresh_state();
    let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
    dp.save_maintenance_time_interval(6 * 3600 * 1000);
    dp.save_next_maintenance_time(1_700_000_000_000);

    let w = addr(0xaa);
    put_witness(&state, w, 100);
    WitnessScheduleStore::new(state.witness_schedule.as_ref().unwrap().clone())
        .save_active(&[Address::from_raw(w)]).unwrap();

    apply_unsigned(
        &state,
        &empty_block(1, [0u8; 32], w, 1_699_999_900_000),
        None,
    )
    .expect("genesis");
    let head = dp.latest_block_header_hash().unwrap().unwrap();
    // Block 2 a hair before the boundary — must NOT trigger maintenance.
    let report = apply_unsigned(
        &state,
        &empty_block(2, head, w, 1_699_999_990_000),
        None,
    )
    .expect("block 2 before boundary");
    assert!(
        report.maintenance.is_none(),
        "non-boundary block must not surface rotation"
    );
}
