//! Operator admin commands — backup / restore are covered by
//! `export-snapshot` / `import-snapshot`; this module adds the
//! remaining two: **compact** (full RocksDB compaction) and
//! **prune-before** (drop historical block bodies + tx receipts
//! below a given height, leaving current account state intact).
//!
//! ## When to use
//!
//! * `compact`: after a `prune-before` to reclaim disk space, or
//!   after a long-running write phase where the LSM tree has built
//!   up obsolete tombstones / overlapping SST levels.
//! * `prune-before BLOCK`: drop historical block bodies + tx
//!   receipts older than `BLOCK`. Account state (balances, contract
//!   code, storage rows) is preserved — pruning blocks doesn't
//!   change the chain's current state, only its block-by-block
//!   queryability. After a prune, `getBlockByNum(N)` for `N < BLOCK`
//!   returns null; `getBlockByNum(N)` for `N >= BLOCK` still works.
//!
//! ## What's NOT pruned
//!
//! * AccountStore, StorageRowStore, ContractStateStore, every other
//!   "current state" store. Their rows are addressed by account /
//!   contract address, not by block height; pruning them would lose
//!   live state.
//! * `block-index` rows below the threshold ARE pruned (the block
//!   they pointed to is gone), so num → BlockId lookups also fail
//!   for pruned heights — which is the right consistency.

use std::path::Path;
use std::sync::Arc;

use tracing::{info, warn};
use tron_chainbase::{
    AccountStore, BlockIndexStore, BlockStore, DynamicPropertiesStore, KvBackend, RocksDbBackend,
    StorageRowStore,
};
use tron_crypto::address::Address;
use tron_proto::Account;

use crate::storage::OpenedStores;

/// Drop historical block bodies + their block_index entries for
/// heights `[1, before)`. Returns the count actually removed.
///
/// Skips blocks above the current solidified head — pruning blocks
/// that might still be in a reorg window would corrupt the chain.
/// Caller is expected to pass `before <= latest_solidified_block_num`.
pub fn prune_before(stores: &OpenedStores, before: i64) -> Result<usize, AdminError> {
    if before < 1 {
        return Err(AdminError::Invalid("prune-before BLOCK must be ≥ 1".into()));
    }
    let block_store = BlockStore::new(stores.blocks.clone());
    let block_index = BlockIndexStore::new(stores.block_index.clone());
    let mut pruned = 0usize;
    for num in 1..before {
        let Ok(id) = block_index.get(num) else {
            continue;
        };
        // Skip if already pruned (idempotent).
        if !block_store.contains(&id) {
            continue;
        }
        block_store.delete(&id);
        block_index.delete(num);
        pruned += 1;
    }
    Ok(pruned)
}

/// Trigger a manual full-range compaction on every store. Walks the
/// `data_dir/db/` subtree, opens each directory as its own
/// RocksDbBackend, and calls [`RocksDbBackend::compact_range`] on
/// each. Returns the list of stores compacted.
///
/// Note: this opens each store fresh; calling it while a node is
/// running against the same data_dir will fail because RocksDB
/// holds an exclusive lock. Call only when the daemon is stopped.
pub fn compact_all(data_dir: &Path) -> Result<Vec<String>, AdminError> {
    let db_root = data_dir.join("db");
    if !db_root.exists() {
        return Err(AdminError::Io(format!(
            "no db/ subdirectory under {}; nothing to compact",
            data_dir.display()
        )));
    }
    let mut compacted = Vec::new();
    let entries = std::fs::read_dir(&db_root).map_err(|e| {
        AdminError::Io(format!("read {}: {e}", db_root.display()))
    })?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        match RocksDbBackend::open(&path) {
            Ok(backend) => {
                info!(store = name.as_str(), "compacting");
                backend.compact_range();
                compacted.push(name);
            }
            Err(e) => {
                warn!(store = name.as_str(), error = %e, "skip compact (open failed)");
            }
        }
    }
    Ok(compacted)
}

/// `db move SRC DST` — atomically rename / move a database directory
/// from `src` to `dst`. Cross-filesystem moves fall back to copy+remove
/// (we don't try to be clever about it — `std::fs::rename` errors on
/// EXDEV, which our caller surfaces as `AdminError::Io`).
///
/// **The node MUST be stopped first** — RocksDB holds an exclusive
/// lock on the source dir; the rename will succeed but the running
/// node's open file descriptors will keep pointing at the original
/// inode, and the next checkpoint flush will be split across the two
/// locations. Stop the daemon, run the move, restart pointing at
/// `dst`.
///
/// Safety: refuses to overwrite an existing destination (returns
/// `AdminError::Invalid`). Refuses to operate when the source doesn't
/// exist.
pub fn db_move(src: &Path, dst: &Path) -> Result<(), AdminError> {
    if !src.exists() {
        return Err(AdminError::Invalid(format!(
            "source does not exist: {}",
            src.display()
        )));
    }
    if dst.exists() {
        return Err(AdminError::Invalid(format!(
            "destination already exists: {} — refusing to overwrite",
            dst.display()
        )));
    }
    if let Some(parent) = dst.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)
                .map_err(|e| AdminError::Io(format!("create dst parent: {e}")))?;
        }
    }
    std::fs::rename(src, dst).map_err(|e| {
        AdminError::Io(format!(
            "rename {} → {}: {e}",
            src.display(),
            dst.display()
        ))
    })?;
    info!(
        from = %src.display(),
        to = %dst.display(),
        "db move complete"
    );
    Ok(())
}

/// `db copy SRC DST` — recursively copy a database directory to a new
/// location. Used by operators making local snapshots before risky
/// upgrades. Same "node must be stopped" caveat as [`db_move`] —
/// copying an open RocksDB dir may capture a torn state (split WAL,
/// half-flushed MemTables).
///
/// For consistent live snapshots, use
/// [`crate::snapshot_export::export_via_checkpoint`] instead — that
/// uses the RocksDB Checkpoint API which is safe on a running node.
pub fn db_copy(src: &Path, dst: &Path) -> Result<u64, AdminError> {
    if !src.exists() {
        return Err(AdminError::Invalid(format!(
            "source does not exist: {}",
            src.display()
        )));
    }
    if !src.is_dir() {
        return Err(AdminError::Invalid(format!(
            "source is not a directory: {}",
            src.display()
        )));
    }
    if dst.exists() {
        return Err(AdminError::Invalid(format!(
            "destination already exists: {} — refusing to overwrite",
            dst.display()
        )));
    }
    let bytes = copy_dir_recursive(src, dst)?;
    info!(
        from = %src.display(),
        to = %dst.display(),
        bytes,
        "db copy complete"
    );
    Ok(bytes)
}

/// Recursive directory copy returning total bytes written. Internal
/// helper for [`db_copy`].
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<u64, AdminError> {
    std::fs::create_dir_all(dst)
        .map_err(|e| AdminError::Io(format!("create {}: {e}", dst.display())))?;
    let mut total: u64 = 0;
    let entries = std::fs::read_dir(src)
        .map_err(|e| AdminError::Io(format!("read {}: {e}", src.display())))?;
    for entry in entries {
        let entry =
            entry.map_err(|e| AdminError::Io(format!("entry in {}: {e}", src.display())))?;
        let path = entry.path();
        let name = entry.file_name();
        let dst_path = dst.join(&name);
        let ty = entry
            .file_type()
            .map_err(|e| AdminError::Io(format!("file_type {}: {e}", path.display())))?;
        if ty.is_dir() {
            total = total.saturating_add(copy_dir_recursive(&path, &dst_path)?);
        } else if ty.is_file() {
            let bytes = std::fs::copy(&path, &dst_path).map_err(|e| {
                AdminError::Io(format!(
                    "copy {} → {}: {e}",
                    path.display(),
                    dst_path.display()
                ))
            })?;
            total = total.saturating_add(bytes);
        }
        // Skip symlinks + other unusual entries — RocksDB dirs are
        // plain file trees.
    }
    Ok(total)
}

/// `db root` — recompute the Ethereum-style account-state-root over the
/// current AccountStore (+ per-contract storage roots from
/// StorageRowStore if present). Returns the 32-byte hash.
///
/// Mirrors java-tron's `DbRoot` toolkit subcommand and the live
/// `account_state_root` field of block headers when
/// `ALLOW_ACCOUNT_STATE_ROOT == 1`. Uses
/// [`tron_types::compute_account_state_root_with_storage`] — the same
/// primitive the executor's `compute_state_root` is built on.
///
/// Same "node must be stopped" caveat as the other `db` subcommands:
/// RocksDB holds an exclusive lock on the account dir; opening it while
/// the daemon is running will fail.
///
/// `data_dir` must contain `db/account/`. `db/storage-row/` is optional
/// — when present, per-contract storage roots are folded in; when
/// absent, every contract uses `KECCAK_EMPTY_STORAGE_ROOT` (the same
/// placeholder `compute_account_state_root` plugs in by default).
pub fn db_root(data_dir: &Path) -> Result<[u8; 32], AdminError> {
    let db_root_path = data_dir.join("db");
    let account_path = db_root_path.join(AccountStore::DB_NAME);
    if !account_path.is_dir() {
        return Err(AdminError::Invalid(format!(
            "no account store at {}",
            account_path.display()
        )));
    }
    let account_backend: Arc<dyn KvBackend> = Arc::new(
        RocksDbBackend::open(&account_path)
            .map_err(|e| AdminError::Io(format!("open {}: {e}", account_path.display())))?,
    );

    let storage_path = db_root_path.join("storage-row");
    let storage_backend: Option<Arc<dyn KvBackend>> = if storage_path.is_dir() {
        Some(Arc::new(RocksDbBackend::open(&storage_path).map_err(
            |e| AdminError::Io(format!("open {}: {e}", storage_path.display())),
        )?))
    } else {
        None
    };

    compute_db_root(account_backend, storage_backend)
}

/// Backend-level core of [`db_root`] — extracted so tests can exercise
/// it against MemBackend without spinning up a RocksDB.
pub(crate) fn compute_db_root(
    accounts_be: Arc<dyn KvBackend>,
    storage_row_be: Option<Arc<dyn KvBackend>>,
) -> Result<[u8; 32], AdminError> {
    let storage_lookup = |addr: &Address| -> Option<[u8; 32]> {
        let rows_be = storage_row_be.as_ref()?;
        let rows = StorageRowStore::new(rows_be.clone()).scan_for_contract(addr);
        if rows.is_empty() {
            None
        } else {
            Some(tron_types::compute_storage_root(&rows))
        }
    };

    let mut accounts: Vec<(Address, Account)> = Vec::new();
    for (key, value) in accounts_be.scan_all() {
        if key.len() != 21 {
            continue;
        }
        let mut addr_bytes = [0u8; 21];
        addr_bytes.copy_from_slice(&key);
        let Ok(account) = <Account as prost::Message>::decode(value.as_slice()) else {
            continue;
        };
        accounts.push((Address::from_raw(addr_bytes), account));
    }

    info!(account_count = accounts.len(), "computing db root");
    Ok(tron_types::compute_account_state_root_with_storage(
        &accounts,
        storage_lookup,
    ))
}

/// java-tron's `DbLite` keeps this many recent blocks in a `snapshot`
/// distribution (~65k * 3s = ~54h of recent history). Operators can
/// override via `--recent-blocks`.
pub const DEFAULT_LITE_RECENT_BLOCKS: i64 = 65_536;

/// `db lite` — produce a "slim distribution" copy of `src`: full
/// current state preserved, historical blocks + their tx receipts
/// pruned below `(latest_block - recent_blocks)`. Mirrors java-tron's
/// `DbLite --operate split --type snapshot` (plugins/DbLite.java).
///
/// `src` is left untouched; `dst` receives a recursive copy + the
/// prune. A `lite.info` file is written into `dst/db/` so consumers
/// can tell at a glance that this is a lite distribution.
///
/// Returns `(blocks_pruned, recent_blocks_kept, latest_block)`.
///
/// Same "node must be stopped" caveat as the other `db` subcommands —
/// the copy step opens `src` for reading and the prune step opens
/// `dst` for writing.
pub fn db_lite(
    src: &Path,
    dst: &Path,
    recent_blocks: i64,
) -> Result<DbLiteReport, AdminError> {
    if recent_blocks < 1 {
        return Err(AdminError::Invalid(format!(
            "recent_blocks must be >= 1, got {recent_blocks}"
        )));
    }
    if !src.is_dir() {
        return Err(AdminError::Invalid(format!(
            "src is not a directory: {}",
            src.display()
        )));
    }
    let src_db = src.join("db");
    if !src_db.is_dir() {
        return Err(AdminError::Invalid(format!(
            "src has no db/ subdirectory: {}",
            src_db.display()
        )));
    }
    if dst.exists() {
        return Err(AdminError::Invalid(format!(
            "destination already exists: {} — refusing to overwrite",
            dst.display()
        )));
    }

    // Step 1: full recursive copy of src → dst.
    let dst_db = dst.join("db");
    let bytes_copied = copy_dir_recursive(&src_db, &dst_db)?;

    // Step 2: read the latest block num from the copy.
    let props_path = dst_db.join(DynamicPropertiesStore::DB_NAME);
    if !props_path.is_dir() {
        return Err(AdminError::Invalid(format!(
            "copy is missing properties store at {}",
            props_path.display()
        )));
    }
    let props_be: Arc<dyn KvBackend> = Arc::new(
        RocksDbBackend::open(&props_path)
            .map_err(|e| AdminError::Io(format!("open {}: {e}", props_path.display())))?,
    );
    let props = DynamicPropertiesStore::new(props_be);
    let latest_block = props.latest_block_header_number().unwrap_or(0);
    drop(props);

    let prune_below = (latest_block - recent_blocks + 1).max(1);

    // Step 3: prune block + block-index below the threshold.
    let block_path = dst_db.join(BlockStore::DB_NAME);
    let block_index_path = dst_db.join(BlockIndexStore::DB_NAME);
    let mut pruned = 0usize;
    if block_path.is_dir() && block_index_path.is_dir() {
        let block_be: Arc<dyn KvBackend> = Arc::new(
            RocksDbBackend::open(&block_path)
                .map_err(|e| AdminError::Io(format!("open {}: {e}", block_path.display())))?,
        );
        let index_be: Arc<dyn KvBackend> = Arc::new(
            RocksDbBackend::open(&block_index_path).map_err(|e| {
                AdminError::Io(format!("open {}: {e}", block_index_path.display()))
            })?,
        );
        let block_store = BlockStore::new(block_be);
        let index_store = BlockIndexStore::new(index_be);
        for num in 1..prune_below {
            let Ok(id) = index_store.get(num) else {
                continue;
            };
            if !block_store.contains(&id) {
                continue;
            }
            block_store.delete(&id);
            index_store.delete(num);
            pruned += 1;
        }
    }

    // Step 4: write lite.info marker.
    let info_path = dst_db.join("lite.info");
    let info_body = format!(
        "kind=snapshot\nlatest_block={latest_block}\nrecent_blocks={recent_blocks}\nprune_below={prune_below}\nblocks_pruned={pruned}\n",
    );
    std::fs::write(&info_path, info_body)
        .map_err(|e| AdminError::Io(format!("write {}: {e}", info_path.display())))?;

    info!(
        from = %src.display(),
        to = %dst.display(),
        latest_block,
        recent_blocks,
        prune_below,
        pruned,
        bytes_copied,
        "db lite complete"
    );
    Ok(DbLiteReport {
        latest_block,
        prune_below,
        blocks_pruned: pruned,
        bytes_copied,
    })
}

/// Outcome of a [`db_lite`] run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbLiteReport {
    /// Latest block number in the source at the time of split.
    pub latest_block: i64,
    /// First block number kept (blocks `[1, prune_below)` were
    /// dropped).
    pub prune_below: i64,
    /// Count of block bodies actually deleted.
    pub blocks_pruned: usize,
    /// Total bytes written by the initial recursive copy.
    pub bytes_copied: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("invalid: {0}")]
    Invalid(String),
    #[error("io: {0}")]
    Io(String),
    #[error("store: {0}")]
    Store(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tron_chainbase::{DynamicPropertiesStore, KvBackend, MemBackend};
    use tron_proto::{block_header::Raw as BlockHeaderRaw, Block, BlockHeader};
    use tron_types::block_id_from_block;

    fn mem() -> Arc<dyn KvBackend> {
        Arc::new(MemBackend::new())
    }

    fn make_block(num: i64) -> Block {
        Block {
            block_header: Some(BlockHeader {
                raw_data: Some(BlockHeaderRaw {
                    number: num,
                    timestamp: num * 3000,
                    parent_hash: vec![0u8; 32],
                    witness_address: vec![0x41u8; 21],
                    ..Default::default()
                }),
                witness_signature: Vec::new(),
            }),
            transactions: Vec::new(),
        }
    }

    fn fresh_stores() -> OpenedStores {
        // Build an OpenedStores backed entirely by MemBackend so
        // prune_before can be exercised without hitting RocksDB
        // exclusive-lock contention.
        OpenedStores {
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
            merkle_trees: mem(),
            code: mem(),
            storage_row: mem(),
            contract_state: mem(),
            block_index: mem(),
            blocks: mem(),
            transactions: mem(),
            tx_history: mem(),
            delegated_resource_account_index: mem(),
            market_account: mem(),
            market_pair_to_price: mem(),
            market_pair_price_to_order: mem(),
            balance_trace: mem(),
            witness_schedule: mem(),
            block_undo: mem(),
            pbft_sign_data: mem(),
            common_database: mem(),
            common: mem(),
            mempool: mem(),
            snapshots: crate::storage::SnapshotStack::empty(),
        }
    }

    #[test]
    fn prune_before_drops_blocks_below_threshold_and_keeps_others() {
        let stores = fresh_stores();
        let bs = BlockStore::new(stores.blocks.clone());
        let bi = BlockIndexStore::new(stores.block_index.clone());

        // Seed blocks 1..=10.
        for n in 1..=10 {
            let block = make_block(n);
            let id = block_id_from_block(&block).unwrap();
            bs.put(&id, &block);
            bi.put(&id);
        }
        // Sanity: all 10 present.
        for n in 1..=10 {
            assert!(bi.get(n).is_ok(), "block {n} should be present");
        }

        let pruned = prune_before(&stores, 6).unwrap();
        assert_eq!(pruned, 5, "blocks 1..5 should be pruned");

        // 1..5 are gone.
        for n in 1..6 {
            assert!(
                bi.get(n).is_err(),
                "block {n} should be pruned from index"
            );
        }
        // 6..=10 remain.
        for n in 6..=10 {
            assert!(bi.get(n).is_ok(), "block {n} should remain");
        }
    }

    #[test]
    fn prune_before_is_idempotent() {
        let stores = fresh_stores();
        let bs = BlockStore::new(stores.blocks.clone());
        let bi = BlockIndexStore::new(stores.block_index.clone());

        for n in 1..=5 {
            let block = make_block(n);
            let id = block_id_from_block(&block).unwrap();
            bs.put(&id, &block);
            bi.put(&id);
        }
        assert_eq!(prune_before(&stores, 4).unwrap(), 3);
        assert_eq!(
            prune_before(&stores, 4).unwrap(),
            0,
            "second call should be a no-op"
        );
    }

    #[test]
    fn prune_before_rejects_zero() {
        let stores = fresh_stores();
        let err = prune_before(&stores, 0).unwrap_err();
        assert!(matches!(err, AdminError::Invalid(_)));
    }

    #[test]
    fn prune_before_preserves_account_state() {
        // Account rows are unrelated to block history; pruning must
        // not touch them.
        use tron_chainbase::AccountStore;
        use tron_crypto::address::Address;
        use tron_proto::Account;

        let stores = fresh_stores();
        let accts = AccountStore::new(stores.accounts.clone());
        let alice = {
            let mut b = [0u8; 21];
            b[0] = 0x41;
            b
        };
        accts.put(
            &Address::from_raw(alice),
            &Account {
                address: alice.to_vec(),
                balance: 100,
                ..Default::default()
            },
        );

        // Plant some blocks + prune them.
        let bs = BlockStore::new(stores.blocks.clone());
        let bi = BlockIndexStore::new(stores.block_index.clone());
        for n in 1..=5 {
            let block = make_block(n);
            let id = block_id_from_block(&block).unwrap();
            bs.put(&id, &block);
            bi.put(&id);
        }
        prune_before(&stores, 5).unwrap();

        let acct = accts.get(&Address::from_raw(alice)).unwrap().unwrap();
        assert_eq!(acct.balance, 100, "account row preserved through prune");
    }

    #[test]
    fn compact_all_errors_when_db_dir_missing() {
        let tmp = std::env::temp_dir().join(format!(
            "tron-admin-compact-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        // Don't create the directory.
        let err = compact_all(&tmp).unwrap_err();
        assert!(matches!(err, AdminError::Io(_)));

        // Suppress unused if any.
        let _ = DynamicPropertiesStore::new(mem());
    }

    // ---- db_move + db_copy ----

    fn unique_tmp(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "tron-admin-{label}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn db_move_renames_in_place() {
        let src = unique_tmp("dbmove-src");
        let dst = unique_tmp("dbmove-dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("sentinel.bin"), b"hello").unwrap();

        db_move(&src, &dst).expect("move");
        assert!(!src.exists(), "src removed after move");
        assert!(dst.is_dir(), "dst exists after move");
        assert_eq!(std::fs::read(dst.join("sentinel.bin")).unwrap(), b"hello");

        let _ = std::fs::remove_dir_all(&dst);
    }

    #[test]
    fn db_move_rejects_missing_source() {
        let src = unique_tmp("dbmove-nope");
        let dst = unique_tmp("dbmove-dst-2");
        let err = db_move(&src, &dst).unwrap_err();
        assert!(matches!(err, AdminError::Invalid(_)));
    }

    #[test]
    fn db_move_refuses_to_overwrite_existing_destination() {
        let src = unique_tmp("dbmove-src-3");
        let dst = unique_tmp("dbmove-dst-3");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        let err = db_move(&src, &dst).unwrap_err();
        assert!(
            matches!(err, AdminError::Invalid(s) if s.contains("destination already exists")),
            "should refuse pre-existing dst"
        );
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&dst);
    }

    #[test]
    fn db_copy_recursively_duplicates_directory_tree() {
        let src = unique_tmp("dbcopy-src");
        let dst = unique_tmp("dbcopy-dst");
        std::fs::create_dir_all(src.join("subdir/nested")).unwrap();
        std::fs::write(src.join("root.txt"), b"R").unwrap();
        std::fs::write(src.join("subdir/mid.txt"), b"M").unwrap();
        std::fs::write(src.join("subdir/nested/leaf.txt"), b"LEAFY").unwrap();

        let bytes = db_copy(&src, &dst).expect("copy");
        // 1 (R) + 1 (M) + 5 (LEAFY) = 7
        assert_eq!(bytes, 7);

        // Source untouched.
        assert!(src.join("root.txt").exists());
        // Destination mirrors structure.
        assert_eq!(std::fs::read(dst.join("root.txt")).unwrap(), b"R");
        assert_eq!(std::fs::read(dst.join("subdir/mid.txt")).unwrap(), b"M");
        assert_eq!(
            std::fs::read(dst.join("subdir/nested/leaf.txt")).unwrap(),
            b"LEAFY"
        );

        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&dst);
    }

    #[test]
    fn db_copy_refuses_existing_destination() {
        let src = unique_tmp("dbcopy-src-2");
        let dst = unique_tmp("dbcopy-dst-2");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        let err = db_copy(&src, &dst).unwrap_err();
        assert!(matches!(err, AdminError::Invalid(_)));
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&dst);
    }

    // ---- db_root ----

    fn addr_of(byte: u8) -> Address {
        let mut b = [0u8; 21];
        b[0] = 0x41;
        b[1] = byte;
        Address::from_raw(b)
    }

    #[test]
    fn db_root_empty_account_store_matches_empty_trie_constant() {
        // No accounts → trie root is the well-known empty-trie hash
        // (`KECCAK_EMPTY_STORAGE_ROOT`).
        let accounts = mem();
        let root = compute_db_root(accounts, None).expect("root");
        assert_eq!(root, tron_types::KECCAK_EMPTY_STORAGE_ROOT);
    }

    #[test]
    fn db_root_matches_direct_compute_for_seeded_accounts() {
        // Whatever scan-and-fold path admin uses must agree with the
        // direct `compute_account_state_root` over the same input.
        let accounts_be = mem();
        let store = AccountStore::new(accounts_be.clone());
        let alice = addr_of(0xa1);
        let bob = addr_of(0xb2);
        let acct_a = Account {
            address: alice.as_bytes().to_vec(),
            balance: 100,
            ..Default::default()
        };
        let acct_b = Account {
            address: bob.as_bytes().to_vec(),
            balance: 250,
            ..Default::default()
        };
        store.put(&alice, &acct_a);
        store.put(&bob, &acct_b);

        let via_admin = compute_db_root(accounts_be, None).expect("root");

        // Direct compute over the same accounts.
        let direct = tron_types::compute_account_state_root(&[
            (alice, acct_a),
            (bob, acct_b),
        ]);
        assert_eq!(via_admin, direct);
    }

    #[test]
    fn db_root_with_storage_differs_from_without_when_rows_present() {
        let accounts_be = mem();
        let storage_be = mem();

        // Plant one contract account.
        let alice = addr_of(0xcd);
        AccountStore::new(accounts_be.clone()).put(
            &alice,
            &Account {
                address: alice.as_bytes().to_vec(),
                balance: 1,
                ..Default::default()
            },
        );

        // Plant one storage row under alice.
        let rows = StorageRowStore::new(storage_be.clone());
        let mut slot = [0u8; 32];
        slot[31] = 0x01;
        let key = StorageRowStore::compose_key(&alice, &slot);
        rows.put(&key, &[0x42][..]);

        let without = compute_db_root(accounts_be.clone(), None).expect("no-storage");
        let with = compute_db_root(accounts_be, Some(storage_be)).expect("with-storage");
        assert_ne!(
            without, with,
            "non-empty storage rows must change the account state root"
        );
    }

    #[test]
    fn db_root_rejects_missing_account_dir() {
        let tmp = unique_tmp("dbroot-nope");
        // tmp doesn't exist → db/account isn't there either.
        let err = db_root(&tmp).unwrap_err();
        assert!(matches!(err, AdminError::Invalid(_)));
    }

    // ---- db_lite ----

    #[test]
    fn db_lite_rejects_zero_recent_blocks() {
        let src = unique_tmp("dblite-src-rej");
        let dst = unique_tmp("dblite-dst-rej");
        let err = db_lite(&src, &dst, 0).unwrap_err();
        assert!(matches!(err, AdminError::Invalid(_)));
    }

    #[test]
    fn db_lite_rejects_missing_src() {
        let src = unique_tmp("dblite-nope");
        let dst = unique_tmp("dblite-dst-2");
        let err = db_lite(&src, &dst, 100).unwrap_err();
        assert!(matches!(err, AdminError::Invalid(_)));
    }

    #[test]
    fn db_lite_refuses_existing_dst() {
        let src = unique_tmp("dblite-src-3");
        let dst = unique_tmp("dblite-dst-3");
        std::fs::create_dir_all(src.join("db")).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        let err = db_lite(&src, &dst, 100).unwrap_err();
        assert!(matches!(err, AdminError::Invalid(_)));
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&dst);
    }

    #[test]
    fn db_lite_rejects_src_without_db_subdir() {
        let src = unique_tmp("dblite-nodb");
        let dst = unique_tmp("dblite-nodb-dst");
        std::fs::create_dir_all(&src).unwrap(); // no db/ child
        let err = db_lite(&src, &dst, 100).unwrap_err();
        assert!(matches!(err, AdminError::Invalid(_)));
        let _ = std::fs::remove_dir_all(&src);
    }
}
