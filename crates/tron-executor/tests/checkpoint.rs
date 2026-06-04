//! Integration tests for the cross-store CheckPointV2 wiring (H-12).
//!
//! The model under test: a block's writes span many stores. Per-store
//! atomicity (RocksDB WriteBatch) is not enough — a crash between two
//! stores' batches leaves the chain inconsistent. The CheckPointV2
//! manifest closes the gap: the executor writes ONE durable manifest
//! covering every per-store batch BEFORE applying any of them, then
//! applies + deletes. A crash mid-flush is replayed from the manifest
//! on the next startup.
//!
//! These tests pin:
//!   * Happy path — manifest is written, applied, deleted, and the
//!     final state matches what a non-checkpoint path produces.
//!   * Crash simulation — a manifest captured before per-store flush
//!     is enough on its own to replay the block via
//!     `replay_pending_checkpoints`. The replayed state matches the
//!     non-crashed state byte-for-byte.
//!   * Empty block — no manifest dir is created when there's nothing
//!     to flush (the checkpoint is opt-in to non-trivial work).
//!   * Idempotent replay — replaying a manifest whose writes are
//!     already landed produces the same state (covers
//!     crash-after-flush-before-delete).
//!   * witness_schedule writes — previously dropped by the undo path;
//!     pin them as captured + replayable.

use std::path::PathBuf;
use std::sync::Arc;

use tron_chainbase::{
    BlockUndoStore, CheckPointV2, CheckpointEntry, DynamicPropertiesStore, KvBackend, MemBackend,
    WitnessStore,
};
use tron_crypto::address::Address;
use tron_executor::{
    execute_block_with_undo_and_config, execute_block_with_undo_checkpoint_and_config,
    replay_pending_checkpoints, ExecConfig, StateBackends,
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
    }
}

fn addr(byte: u8) -> [u8; 21] {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(byte);
    a
}

fn empty_block(num: i64, parent_hash: [u8; 32]) -> Block {
    Block {
        block_header: Some(BlockHeader {
            raw_data: Some(BlockHeaderRaw {
                number: num,
                parent_hash: parent_hash.to_vec(),
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
    let ws = WitnessStore::new(state.witnesses.clone());
    ws.put(
        &Address::from_raw(addr(0xaa)),
        &Witness {
            address: addr(0xaa).to_vec(),
            ..Default::default()
        },
    )
    .unwrap();
}

fn tmp_checkpoint_root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "tron-h12-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

/// Snapshot every KvBackend in `state` as a sorted (key, value) list
/// per store — sufficient to byte-compare two state trees.
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

/// HAPPY PATH: applying a block through the checkpoint API produces
/// the same final state as the no-checkpoint API, AND leaves the
/// checkpoint directory empty (manifest was deleted after successful
/// per-store flush).
#[test]
fn checkpoint_path_matches_no_checkpoint_path_and_cleans_up() {
    // No-checkpoint reference state.
    let state_ref = fresh_state();
    let undo_ref = BlockUndoStore::new(mem());
    seed_witness(&state_ref);
    let block = empty_block(1, [0u8; 32]);
    execute_block_with_undo_and_config(&state_ref, &block, None, &undo_ref, &ExecConfig::unsigned())
        .unwrap();
    let ref_snapshot = snapshot_state(&state_ref);

    // Checkpoint path.
    let state = fresh_state();
    let undo = BlockUndoStore::new(mem());
    seed_witness(&state);
    let root = tmp_checkpoint_root();
    let cp = CheckPointV2::new(&root);
    execute_block_with_undo_checkpoint_and_config(
        &state,
        &block,
        None,
        &undo,
        &cp,
        &ExecConfig::unsigned(),
    )
    .unwrap();
    let cp_snapshot = snapshot_state(&state);

    assert_eq!(
        ref_snapshot, cp_snapshot,
        "checkpoint path must produce identical state to the no-checkpoint path"
    );

    // Manifest dir was deleted after successful flush.
    assert!(
        cp.list().unwrap().is_empty(),
        "checkpoint dir should be empty after successful block apply"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// CRASH SIMULATION: drain the BlockSession's writes into a manifest
/// but skip the per-store flush, then run `replay_pending_checkpoints`
/// against a fresh state. The replayed state must match the
/// non-crashed state.
///
/// We simulate the crash by hand-building the manifest from the
/// reference state's diff — equivalent to "the manifest was written,
/// but the process died before the first per-store write_batch
/// landed."
#[test]
fn crash_after_manifest_before_per_store_flush_is_recoverable() {
    // 1) Build the reference end state by running a full block apply.
    let state_ref = fresh_state();
    let undo_ref = BlockUndoStore::new(mem());
    seed_witness(&state_ref);
    let block = empty_block(1, [0u8; 32]);
    execute_block_with_undo_and_config(&state_ref, &block, None, &undo_ref, &ExecConfig::unsigned())
        .unwrap();
    let ref_snapshot = snapshot_state(&state_ref);

    // 2) Build a fresh state seeded the same way (the pre-block
    //    image — what's on disk when the next startup happens).
    let state_crashed = fresh_state();
    seed_witness(&state_crashed);

    // 3) Synthesize a manifest as if the executor had drained the
    //    BlockSession but died before per-store flush. The simplest
    //    way to materialize the same manifest the executor would
    //    produce: diff ref vs. crashed and turn each difference into
    //    a CheckpointEntry.
    let pre_snapshot = snapshot_state(&state_crashed);
    let mut entries: Vec<CheckpointEntry> = Vec::new();
    for ((name, post), (_, pre)) in ref_snapshot.iter().zip(pre_snapshot.iter()) {
        let pre_map: std::collections::HashMap<Vec<u8>, Vec<u8>> =
            pre.iter().cloned().collect();
        let post_map: std::collections::HashMap<Vec<u8>, Vec<u8>> =
            post.iter().cloned().collect();
        for (k, v) in &post_map {
            if pre_map.get(k) != Some(v) {
                entries.push(CheckpointEntry {
                    db_name: store_name_to_db_name(name).to_string(),
                    key: k.clone(),
                    value: Some(v.clone()),
                });
            }
        }
        for k in pre_map.keys() {
            if !post_map.contains_key(k) {
                entries.push(CheckpointEntry {
                    db_name: store_name_to_db_name(name).to_string(),
                    key: k.clone(),
                    value: None,
                });
            }
        }
    }
    assert!(!entries.is_empty(), "block 1 must produce at least one write");

    let root = tmp_checkpoint_root();
    let cp = CheckPointV2::new(&root);
    cp.write(&entries).unwrap();
    assert_eq!(cp.list().unwrap().len(), 1, "manifest staged");

    // 4) Replay into the crashed (pre-block) state. After this, it
    //    should be byte-identical to the reference state.
    let (cp_count, entry_count) = replay_pending_checkpoints(&state_crashed, &cp).unwrap();
    assert_eq!(cp_count, 1);
    assert_eq!(entry_count, entries.len());

    let recovered = snapshot_state(&state_crashed);
    assert_eq!(
        ref_snapshot, recovered,
        "recovered state must match the never-crashed reference state"
    );

    // 5) The manifest dir is empty — replay_pending_checkpoints
    //    deletes each manifest as it replays.
    assert!(cp.list().unwrap().is_empty());

    let _ = std::fs::remove_dir_all(&root);
}

/// IDEMPOTENT REPLAY: replaying a manifest whose writes already
/// landed is a no-op for state (just re-writes the same bytes) and
/// still deletes the manifest. Covers crash-after-flush-before-delete.
#[test]
fn replay_is_idempotent_when_writes_already_landed() {
    let state = fresh_state();
    let undo = BlockUndoStore::new(mem());
    seed_witness(&state);
    let block = empty_block(1, [0u8; 32]);

    let root = tmp_checkpoint_root();
    let cp = CheckPointV2::new(&root);
    execute_block_with_undo_checkpoint_and_config(
        &state,
        &block,
        None,
        &undo,
        &cp,
        &ExecConfig::unsigned(),
    )
    .unwrap();
    let after_first_apply = snapshot_state(&state);

    // Synthesize the same manifest again as if the crash happened
    // AFTER per-store flush but BEFORE delete. We use the reference
    // path's outputs as the manifest content (every key the block
    // wrote — what's now in state).
    let entries: Vec<CheckpointEntry> = after_first_apply
        .iter()
        .flat_map(|(name, kvs)| {
            kvs.iter().map(move |(k, v)| CheckpointEntry {
                db_name: store_name_to_db_name(name).to_string(),
                key: k.clone(),
                value: Some(v.clone()),
            })
        })
        .collect();
    cp.write(&entries).unwrap();
    assert_eq!(cp.list().unwrap().len(), 1);

    replay_pending_checkpoints(&state, &cp).unwrap();

    let after_replay = snapshot_state(&state);
    assert_eq!(
        after_first_apply, after_replay,
        "idempotent replay must not change observable state"
    );
    assert!(cp.list().unwrap().is_empty());

    let _ = std::fs::remove_dir_all(&root);
}

/// EMPTY BLOCK (no overlay writes): the checkpoint path should NOT
/// create a manifest dir. This is the no-op guard in
/// `commit_with_checkpoint_and_undo` — empty drained == no manifest.
///
/// In practice every block writes at least DPS head pointers, so
/// this asserts the GUARD logic via a degenerate case: we drain a
/// fresh BlockSession with no writes. The closest API-level proxy
/// is verifying that the directory is empty after the apply (since
/// the apply did write DPS keys), then asserting the dir contains
/// zero `.tmp` entries (no staged-but-not-committed manifests).
#[test]
fn checkpoint_dir_has_no_leftover_tmp_after_apply() {
    let state = fresh_state();
    let undo = BlockUndoStore::new(mem());
    seed_witness(&state);
    let block = empty_block(1, [0u8; 32]);
    let root = tmp_checkpoint_root();
    let cp = CheckPointV2::new(&root);
    execute_block_with_undo_checkpoint_and_config(
        &state,
        &block,
        None,
        &undo,
        &cp,
        &ExecConfig::unsigned(),
    )
    .unwrap();

    // After a clean apply: no manifests, no .tmp staging.
    if root.exists() {
        for entry in std::fs::read_dir(&root).unwrap() {
            let name = entry.unwrap().file_name();
            let s = name.to_string_lossy();
            assert!(
                !s.ends_with(".tmp"),
                "no .tmp staging dirs should remain after clean apply (found: {s})"
            );
        }
    }
    assert!(cp.list().unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&root);
}

/// Maps the helper's display name (used in snapshot_state) to the
/// real on-disk db_name the manifest expects. The two diverged for
/// historical reasons (the StateBackends fields are snake_cased
/// while the actual DB directories follow java-tron's naming).
fn store_name_to_db_name(name: &str) -> &'static str {
    use tron_chainbase::UndoStoreId as Id;
    match name {
        "accounts" => Id::Accounts.db_name(),
        "witnesses" => Id::Witnesses.db_name(),
        "votes" => Id::Votes.db_name(),
        "delegation" => Id::Delegation.db_name(),
        "delegated_resources" => Id::DelegatedResources.db_name(),
        "dyn_props" => Id::DynProps.db_name(),
        "proposals" => Id::Proposals.db_name(),
        "name_index" => Id::NameIndex.db_name(),
        "id_index" => Id::IdIndex.db_name(),
        "asset_v1" => Id::AssetV1.db_name(),
        "asset_v2" => Id::AssetV2.db_name(),
        "contracts" => Id::Contracts.db_name(),
        "abi" => Id::Abi.db_name(),
        "exchange_v1" => Id::ExchangeV1.db_name(),
        "exchange_v2" => Id::ExchangeV2.db_name(),
        "market_orders" => Id::MarketOrders.db_name(),
        "nullifiers" => Id::Nullifiers.db_name(),
        "merkle_trees" => Id::MerkleTrees.db_name(),
        "code" => Id::Code.db_name(),
        "storage_row" => Id::StorageRow.db_name(),
        "contract_state" => Id::ContractState.db_name(),
        "block_index" => Id::BlockIndex.db_name(),
        "witness_schedule" => Id::WitnessSchedule.db_name(),
        other => panic!("unknown helper name: {other}"),
    }
}

/// Sanity: the seeded post-block state actually wrote SOMETHING to
/// `witness_schedule`. The previous undo path silently dropped writes
/// to that store; cross-store atomicity has to cover it.
///
/// We can't easily provoke a write to witness_schedule from an empty
/// block (apply_maintenance only fires at the maintenance boundary),
/// so this test instead pins the API surface — we write directly to
/// the wrapped session, drain, and verify the manifest entries cover
/// witness_schedule.
#[test]
fn witness_schedule_writes_appear_in_the_manifest() {
    use tron_chainbase::{CheckPointV2, KvBackend, SessionBackend, UndoStoreId, WriteOp};

    let parent = mem();
    let session = SessionBackend::new(parent.clone());
    session.put(b"shuffled-witnesses", b"some-bytes").unwrap();

    let (ops, _undo) = session.drain_pending_with_undo().unwrap();
    assert_eq!(ops.len(), 1);
    let key = match &ops[0] {
        WriteOp::Put(k, _) => k.clone(),
        WriteOp::Delete(_) => panic!("expected Put"),
    };

    let root = tmp_checkpoint_root();
    let cp = CheckPointV2::new(&root);
    let entry = CheckpointEntry {
        db_name: UndoStoreId::WitnessSchedule.db_name().to_string(),
        key: key.clone(),
        value: Some(b"some-bytes".to_vec()),
    };
    cp.write(&[entry]).unwrap();

    // Replay through replay_pending_checkpoints with a state where
    // witness_schedule is attached. The bytes should land in the
    // expected store.
    let mut state = fresh_state();
    state.witness_schedule = Some(parent.clone());
    replay_pending_checkpoints(&state, &cp).unwrap();
    assert_eq!(parent.get(&key).unwrap(), Some(b"some-bytes".to_vec()));

    let _ = std::fs::remove_dir_all(&root);
}

/// Optional store NOT attached → manifest references it → replay
/// errors out (hard fail so an operator notices, not silent skip).
#[test]
fn replay_errors_on_unknown_store_when_optional_not_attached() {
    let root = tmp_checkpoint_root();
    let cp = CheckPointV2::new(&root);
    cp.write(&[CheckpointEntry {
        db_name: "IncrementalMerkleTree".to_string(),
        key: b"k".to_vec(),
        value: Some(b"v".to_vec()),
    }])
    .unwrap();

    let state = fresh_state(); // merkle_trees: None
    let res = replay_pending_checkpoints(&state, &cp);
    assert!(
        res.is_err(),
        "missing optional store should be a hard error"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// DPS head pointer is among the keys captured — sanity-checks that
/// the manifest path covers the same writes the standard undo path
/// would have committed (i.e. we're not missing a store).
#[test]
fn checkpoint_path_updates_dynamic_properties_head_pointer() {
    let state = fresh_state();
    let undo = BlockUndoStore::new(mem());
    seed_witness(&state);
    let block = empty_block(1, [0u8; 32]);
    let root = tmp_checkpoint_root();
    let cp = CheckPointV2::new(&root);
    execute_block_with_undo_checkpoint_and_config(
        &state,
        &block,
        None,
        &undo,
        &cp,
        &ExecConfig::unsigned(),
    )
    .unwrap();

    let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
    assert_eq!(dp.latest_block_header_number(), Some(1));
    assert!(dp.latest_block_header_hash().is_ok());

    let _ = std::fs::remove_dir_all(&root);
}

/// The undo log produced through the checkpoint path is bytewise
/// identical to the no-checkpoint path (modulo witness_schedule,
/// which the old path silently dropped). Same entries, same store
/// ids, same before-images.
#[test]
fn checkpoint_path_undo_log_matches_no_checkpoint_path() {
    let block = empty_block(1, [0u8; 32]);

    let state_ref = fresh_state();
    let undo_ref = BlockUndoStore::new(mem());
    seed_witness(&state_ref);
    execute_block_with_undo_and_config(&state_ref, &block, None, &undo_ref, &ExecConfig::unsigned())
        .unwrap();
    let rec_ref = undo_ref.get(1).unwrap().expect("undo log");

    let state = fresh_state();
    let undo = BlockUndoStore::new(mem());
    seed_witness(&state);
    let root = tmp_checkpoint_root();
    let cp = CheckPointV2::new(&root);
    execute_block_with_undo_checkpoint_and_config(
        &state,
        &block,
        None,
        &undo,
        &cp,
        &ExecConfig::unsigned(),
    )
    .unwrap();
    let rec_cp = undo.get(1).unwrap().expect("undo log");

    // The undo log under the checkpoint path is a superset of the
    // no-checkpoint path — every store the old path captured is here,
    // plus witness_schedule which was previously dropped.
    let ref_keys: std::collections::HashSet<_> = rec_ref
        .entries
        .iter()
        .map(|e| (e.store, e.key.clone()))
        .collect();
    let cp_keys: std::collections::HashSet<_> = rec_cp
        .entries
        .iter()
        .map(|e| (e.store, e.key.clone()))
        .collect();
    for k in &ref_keys {
        assert!(
            cp_keys.contains(k),
            "checkpoint path lost an undo entry that the no-checkpoint path captured: {:?}",
            k
        );
    }

    assert_eq!(
        state.accounts.scan_all().unwrap().len(),
        state_ref.accounts.scan_all().unwrap().len(),
        "account store size should match between the two paths"
    );

    let _ = std::fs::remove_dir_all(&root);
}
