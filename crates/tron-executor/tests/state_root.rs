//! Tests for `account_state_root` computation and verification at
//! block-execution time.
//!
//! java-tron only computes/verifies this when
//! `DynamicPropertiesStore.ALLOW_ACCOUNT_STATE_ROOT == 1`. Mainnet
//! currently has this disabled (= 0), but testnets and future mainnet
//! upgrades may enable it. When enabled, a block's `account_state_root`
//! field is compared against the computed root after applying all
//! transactions; a mismatch is a consensus error.

use std::sync::Arc;

use tron_chainbase::{
    AccountStore, DynamicPropertiesStore, KvBackend, MemBackend,
};
use tron_crypto::address::Address;
use tron_executor::{
    compute_state_root, execute_block_with_config, BlockExecError, BlockExecutionReport,
    ExecConfig, StateBackends,
};
use tron_proto::{block_header::Raw as BlockHeaderRaw, Account, Block, BlockHeader};
use tron_types::BlockId;

/// Apply a synthetic UNSIGNED block. See note on the same helper in
/// `maintenance_rotation.rs` — these tests exercise account-state-root
/// behaviour, not the witness-sig path.
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

fn addr(seed: u8) -> [u8; 21] {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(seed);
    a
}

fn seed_account(state: &StateBackends, raw_address: [u8; 21], balance: i64) {
    let accounts = AccountStore::new(state.accounts.clone());
    accounts.put(
        &Address::from_raw(raw_address),
        &Account {
            address: raw_address.to_vec(),
            balance,
            ..Default::default()
        },
    ).unwrap();
}

fn block_with_root(num: i64, parent: [u8; 32], state_root: Vec<u8>) -> Block {
    Block {
        block_header: Some(BlockHeader {
            raw_data: Some(BlockHeaderRaw {
                number: num,
                parent_hash: parent.to_vec(),
                timestamp: 1_700_000_000_000,
                account_state_root: state_root,
                ..Default::default()
            }),
            // No signature → executor skips witness-sig check.
            ..Default::default()
        }),
        transactions: Vec::new(),
    }
}

#[test]
fn state_root_is_deterministic_over_equal_account_sets() {
    let state_a = fresh_state();
    let state_b = fresh_state();
    seed_account(&state_a, addr(0xa1), 1_000);
    seed_account(&state_a, addr(0xa2), 2_000);
    seed_account(&state_b, addr(0xa1), 1_000);
    seed_account(&state_b, addr(0xa2), 2_000);

    let root_a = compute_state_root(&state_a).unwrap();
    let root_b = compute_state_root(&state_b).unwrap();
    assert_eq!(
        root_a, root_b,
        "two equal account sets must produce the same root"
    );
    // Sanity: a non-empty trie must NOT collapse to the empty-trie hash.
    assert_ne!(root_a, [0u8; 32]);
}

#[test]
fn state_root_changes_when_a_balance_changes() {
    let state = fresh_state();
    seed_account(&state, addr(0xa1), 1_000);
    let before = compute_state_root(&state).unwrap();
    seed_account(&state, addr(0xa1), 1_001); // overwrite with new balance
    let after = compute_state_root(&state).unwrap();
    assert_ne!(
        before, after,
        "changing a balance must change the state root"
    );
}

#[test]
fn execute_block_skips_root_check_when_flag_is_off() {
    // Mainnet's current default: flag = 0 (or absent). Even a
    // garbage `account_state_root` in the header must NOT fail the
    // block, because the chain hasn't activated the check.
    let state = fresh_state();
    seed_account(&state, addr(0xa1), 1_000);
    let garbage_root = vec![0xff; 32];
    let block = block_with_root(1, [0u8; 32], garbage_root);

    let result = apply_unsigned(&state, &block, None);
    assert!(
        result.is_ok(),
        "flag=0 path must ignore garbage state_root; got {:?}",
        result
    );
}

#[test]
fn execute_block_skips_root_check_when_header_field_is_empty() {
    // Producers leave the field empty when the chain hasn't activated
    // the root. Even with the flag ON, an empty header field must be
    // tolerated — verification is opt-in per block.
    let state = fresh_state();
    seed_account(&state, addr(0xa1), 1_000);
    let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
    dp.put_long(b"ALLOW_ACCOUNT_STATE_ROOT", 1);

    let block = block_with_root(1, [0u8; 32], Vec::new());
    let result = apply_unsigned(&state, &block, None);
    assert!(
        result.is_ok(),
        "empty header field must skip verification even with flag on; got {:?}",
        result
    );
}

#[test]
fn execute_block_rejects_state_root_mismatch_when_flag_is_on() {
    let state = fresh_state();
    seed_account(&state, addr(0xa1), 1_000);
    let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
    dp.put_long(b"ALLOW_ACCOUNT_STATE_ROOT", 1);

    let bogus_root = vec![0xab; 32];
    let block = block_with_root(1, [0u8; 32], bogus_root);

    let err = apply_unsigned(&state, &block, None).expect_err("must reject");
    assert!(
        matches!(err, BlockExecError::StateRootMismatch { .. }),
        "expected StateRootMismatch, got {:?}",
        err
    );
}

#[test]
fn execute_block_accepts_matching_state_root() {
    let state = fresh_state();
    seed_account(&state, addr(0xa1), 1_000);
    seed_account(&state, addr(0xa2), 2_000);
    let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
    dp.put_long(b"ALLOW_ACCOUNT_STATE_ROOT", 1);

    // Compute what the root SHOULD be (no txs in this block, so post-exec
    // state == pre-exec state), then put it in the header.
    let expected = compute_state_root(&state).unwrap();
    let block = block_with_root(1, [0u8; 32], expected.to_vec());

    let result = apply_unsigned(&state, &block, None);
    assert!(
        result.is_ok(),
        "matching root must pass; got {:?}",
        result
    );
}
