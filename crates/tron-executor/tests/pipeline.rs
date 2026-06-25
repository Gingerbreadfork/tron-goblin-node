//! Integration tests for the pipelined block applier (`ApplyPipeline`).
//!
//! The model under test: `ApplyPipeline::apply` must be observably
//! IDENTICAL to the classic synchronous
//! `execute_block_with_undo_checkpoint_and_config` — same final state
//! across every store, same undo logs, same captured deltas, same
//! checkpoint-manifest lifecycle — with the only difference being WHEN
//! durability happens (joined by the next apply / flush instead of
//! inline).
//!
//! These tests pin:
//!   * Byte-identical end state + undo logs + deltas vs the classic
//!     path, across a multi-block chain (steady-state fsync mode).
//!   * Deferred-fsync mode retains manifests exactly like the classic
//!     path does.
//!   * The pipeline view exposes a pending block's writes before the
//!     background commit is joined; base catches up by `flush`.
//!   * A failed execution leaves the previous pending block intact.

use std::path::PathBuf;
use std::sync::Arc;

use tron_chainbase::{
    BlockUndoStore, CheckPointV2, DynamicPropertiesStore, KvBackend, MemBackend, UndoEntry,
};
use tron_crypto::address::Address;
use tron_executor::{
    execute_block_with_undo_checkpoint_and_config, ApplyPipeline, ExecConfig, StateBackends,
};
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

fn empty_block(num: i64) -> Block {
    Block {
        block_header: Some(BlockHeader {
            raw_data: Some(BlockHeaderRaw {
                number: num,
                parent_hash: vec![0u8; 32],
                timestamp: 1_700_000_000_000 + num * 3000,
                tx_trie_root: tron_types::calc_tx_trie_root(&[])
                    .map(|h| h.to_vec())
                    .unwrap_or_default(),
                witness_address: addr(0xaa).to_vec(),
                ..Default::default()
            }),
            witness_signature: Vec::new(),
        }),
        transactions: Vec::new(),
    }
}

fn seed_witness(state: &StateBackends) {
    let ws = tron_chainbase::WitnessStore::new(state.witnesses.clone());
    ws.put(
        &Address::from_raw(addr(0xaa)),
        &Witness {
            address: addr(0xaa).to_vec(),
            ..Default::default()
        },
    )
    .unwrap();
}

fn tmp_checkpoint_root(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "tron-pipeline-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

/// Snapshot every store as sorted (key, value) lists — enough to
/// byte-compare two state trees.
fn snapshot_state(state: &StateBackends) -> Vec<(&'static str, Vec<(Vec<u8>, Vec<u8>)>)> {
    let mut all: Vec<(&'static str, Vec<(Vec<u8>, Vec<u8>)>)> = vec![
        ("accounts", state.accounts.scan_all().unwrap()),
        ("witnesses", state.witnesses.scan_all().unwrap()),
        ("votes", state.votes.scan_all().unwrap()),
        ("delegation", state.delegation.scan_all().unwrap()),
        ("delegated_resources", state.delegated_resources.scan_all().unwrap()),
        ("dyn_props", state.dyn_props.scan_all().unwrap()),
        ("proposals", state.proposals.scan_all().unwrap()),
        ("name_index", state.name_index.scan_all().unwrap()),
        ("id_index", state.id_index.scan_all().unwrap()),
        ("asset_v1", state.asset_v1.scan_all().unwrap()),
        ("asset_v2", state.asset_v2.scan_all().unwrap()),
        ("contracts", state.contracts.scan_all().unwrap()),
        ("abi", state.abi.scan_all().unwrap()),
        ("exchange_v1", state.exchange_v1.scan_all().unwrap()),
        ("exchange_v2", state.exchange_v2.scan_all().unwrap()),
        ("market_orders", state.market_orders.scan_all().unwrap()),
        ("nullifiers", state.nullifiers.scan_all().unwrap()),
    ];
    if let Some(b) = &state.code {
        all.push(("code", b.scan_all().unwrap()));
    }
    if let Some(b) = &state.storage_row {
        all.push(("storage_row", b.scan_all().unwrap()));
    }
    if let Some(b) = &state.contract_state {
        all.push(("contract_state", b.scan_all().unwrap()));
    }
    if let Some(b) = &state.block_index {
        all.push(("block_index", b.scan_all().unwrap()));
    }
    if let Some(b) = &state.witness_schedule {
        all.push(("witness_schedule", b.scan_all().unwrap()));
    }
    for (_, kvs) in &mut all {
        kvs.sort();
    }
    all
}

/// Per-block undo logs as ORDER-INSENSITIVE sets. Entry order within
/// a store follows HashMap drain order (non-deterministic on both the
/// classic and pipelined paths), so compare sorted.
fn undo_logs_sorted(backend: &Arc<dyn KvBackend>) -> Vec<(Vec<u8>, Vec<UndoEntry>)> {
    let undo = BlockUndoStore::new(backend.clone());
    backend
        .scan_all()
        .unwrap()
        .into_iter()
        .map(|(k, _)| {
            let num = i64::from_be_bytes(k.as_slice().try_into().unwrap());
            let mut entries = undo.get(num).unwrap().unwrap().entries;
            entries.sort_by(|a, b| {
                (a.store as u8, &a.key, &a.before).cmp(&(b.store as u8, &b.key, &b.before))
            });
            (k, entries)
        })
        .collect()
}

const BLOCKS: i64 = 5;

/// Classic-path reference run over `BLOCKS` empty blocks. Returns the
/// state + undo backend + checkpoint root + per-block deltas.
#[allow(clippy::type_complexity)]
fn run_classic(
    config: &ExecConfig,
    tag: &str,
) -> (StateBackends, Arc<dyn KvBackend>, PathBuf, Vec<Option<Vec<tron_executor::CapturedDelta>>>) {
    let state = fresh_state();
    seed_witness(&state);
    let undo_backend = mem();
    let undo = BlockUndoStore::new(undo_backend.clone());
    let root = tmp_checkpoint_root(tag);
    let cp = CheckPointV2::new(&root);
    let mut deltas = Vec::new();
    for n in 1..=BLOCKS {
        let report = execute_block_with_undo_checkpoint_and_config(
            &state,
            &empty_block(n),
            None,
            &undo,
            &cp,
            config,
            None,
        )
        .unwrap();
        deltas.push(report.state_deltas);
    }
    (state, undo_backend, root, deltas)
}

/// Pipelined run over the same chain. Returns the same observables.
#[allow(clippy::type_complexity)]
fn run_pipelined(
    config: &ExecConfig,
    tag: &str,
) -> (StateBackends, Arc<dyn KvBackend>, PathBuf, Vec<Option<Vec<tron_executor::CapturedDelta>>>) {
    let state = fresh_state();
    seed_witness(&state);
    let undo_backend = mem();
    let undo = BlockUndoStore::new(undo_backend.clone());
    let root = tmp_checkpoint_root(tag);
    let cp = CheckPointV2::new(&root);
    let mut pipeline = ApplyPipeline::new(&state, undo, cp);
    let mut deltas = Vec::new();
    for n in 1..=BLOCKS {
        let report = pipeline.apply(&empty_block(n), None, config, None).unwrap();
        deltas.push(report.state_deltas);
    }
    pipeline.flush().unwrap();
    (state, undo_backend, root, deltas)
}

#[test]
fn pipelined_apply_matches_classic_path_steady_state() {
    let mut config = ExecConfig::unsigned();
    config.capture_state_deltas = true;

    let (state_ref, undo_ref, root_ref, deltas_ref) = run_classic(&config, "classic");
    let (state_pip, undo_pip, root_pip, deltas_pip) = run_pipelined(&config, "pipelined");

    assert_eq!(
        snapshot_state(&state_ref),
        snapshot_state(&state_pip),
        "pipelined apply must produce identical state to the classic path"
    );
    assert_eq!(
        undo_logs_sorted(&undo_ref),
        undo_logs_sorted(&undo_pip),
        "pipelined apply must persist identical per-block undo logs"
    );
    assert_eq!(
        deltas_ref, deltas_pip,
        "pipelined apply must capture identical state deltas"
    );

    // Steady state deletes each manifest after its per-store flush.
    let cp_ref = CheckPointV2::new(&root_ref);
    let cp_pip = CheckPointV2::new(&root_pip);
    assert!(cp_ref.list().unwrap().is_empty());
    assert!(
        cp_pip.list().unwrap().is_empty(),
        "pipelined steady-state commit must clean up manifests like the classic path"
    );

    let _ = std::fs::remove_dir_all(&root_ref);
    let _ = std::fs::remove_dir_all(&root_pip);
}

#[test]
fn pipelined_apply_matches_classic_path_with_deferred_fsync() {
    let mut config = ExecConfig::unsigned();
    config.defer_store_fsync = true;

    let (state_ref, undo_ref, root_ref, _) = run_classic(&config, "classic-defer");
    let (state_pip, undo_pip, root_pip, _) = run_pipelined(&config, "pipelined-defer");

    assert_eq!(snapshot_state(&state_ref), snapshot_state(&state_pip));
    assert_eq!(undo_logs_sorted(&undo_ref), undo_logs_sorted(&undo_pip));

    // Deferred mode retains one manifest per applied block (BLOCKS is
    // far below the barrier threshold) on BOTH paths.
    let cp_ref = CheckPointV2::new(&root_ref);
    let cp_pip = CheckPointV2::new(&root_pip);
    assert_eq!(
        cp_ref.list().unwrap().len(),
        cp_pip.list().unwrap().len(),
        "deferred-fsync manifest retention must match the classic path"
    );
    assert_eq!(cp_pip.list().unwrap().len(), BLOCKS as usize);

    let _ = std::fs::remove_dir_all(&root_ref);
    let _ = std::fs::remove_dir_all(&root_pip);
}

#[test]
fn view_exposes_pending_block_and_flush_lands_it_in_base() {
    let state = fresh_state();
    seed_witness(&state);
    let undo = BlockUndoStore::new(mem());
    let root = tmp_checkpoint_root("view");
    let cp = CheckPointV2::new(&root);
    let mut pipeline = ApplyPipeline::new(&state, undo, cp);

    let config = ExecConfig::unsigned();
    pipeline.apply(&empty_block(1), None, &config, None).unwrap();

    // The view must show block 1's head pointer immediately —
    // regardless of whether the background commit already landed.
    let dp_view = DynamicPropertiesStore::new(pipeline.view().dyn_props.clone());
    assert_eq!(
        dp_view.latest_block_header_number().unwrap(),
        1,
        "pipeline view must expose the pending block's writes"
    );

    pipeline.flush().unwrap();

    // After flush, the base stores hold the block and the view (now
    // overlay-free) agrees with them.
    let dp_base = DynamicPropertiesStore::new(state.dyn_props.clone());
    assert_eq!(dp_base.latest_block_header_number().unwrap(), 1);
    assert_eq!(dp_view.latest_block_header_number().unwrap(), 1);

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn failed_execution_leaves_previous_pending_block_intact() {
    let state = fresh_state();
    seed_witness(&state);
    let undo = BlockUndoStore::new(mem());
    let root = tmp_checkpoint_root("fail");
    let cp = CheckPointV2::new(&root);
    let mut pipeline = ApplyPipeline::new(&state, undo, cp);

    let config = ExecConfig::unsigned();
    pipeline.apply(&empty_block(1), None, &config, None).unwrap();

    // A structurally-broken block (no header) fails execution without
    // touching the overlay or the in-flight commit.
    let garbage = Block { block_header: None, transactions: Vec::new() };
    assert!(pipeline.apply(&garbage, None, &config, None).is_err());

    let dp_view = DynamicPropertiesStore::new(pipeline.view().dyn_props.clone());
    assert_eq!(
        dp_view.latest_block_header_number().unwrap(),
        1,
        "failed execution must not disturb the pending block"
    );

    pipeline.flush().unwrap();
    let dp_base = DynamicPropertiesStore::new(state.dyn_props.clone());
    assert_eq!(dp_base.latest_block_header_number().unwrap(), 1);

    let _ = std::fs::remove_dir_all(&root);
}
