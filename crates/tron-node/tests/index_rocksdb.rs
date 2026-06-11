//! RocksDB-backed integration tests for the indexer stack. The
//! MemBackend suites prove the logic; these run the same flows over
//! the real storage engine — one RocksDB instance per store, exactly
//! like the node's data dir — to cover what mem can't: reopen
//! durability, on-disk iterator semantics (prefix scans, reverse
//! seeks behind newest-first paging and the archive's at-height
//! merge), batched writes, and the store-derived repair paths.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use prost::Message;
use prost_types::Any;
use tron_chainbase::{
    AccountStore, BlockIndexStore, BlockStore, BlockUndoStore, DynamicPropertiesStore, KvBackend,
    MemBackend, RocksDbBackend, TransactionRetStore, UndoEntry, UndoStoreId, WitnessScheduleStore,
};
use tron_crypto::address::Address;
use tron_executor::StateBackends;
use tron_grpc::firehose_proto as fh;
use tron_index::{
    ArchiveWriter, AtHeight, CaptureSet, EngineOptions, IndexDb, IndexEngine, IndexReader,
    InitOutcome, PageQuery, Tick,
};
use tron_node::firehose::FirehoseWriter;
use tron_node::index_hook::IndexHook;
use tron_node::sync::{AcceptOutcome, SyncConfig, SyncDriver};
use tron_proto::{
    transaction::{contract::ContractType, Contract as TxContract, Raw as TxRaw},
    Account, Block, BlockHeader, Transaction, TransactionInfo, TransactionRet,
};
use tron_types::{block_id_from_block, sign_block, BlockId};

fn rocks(dir: &Path, name: &str) -> Arc<dyn KvBackend> {
    Arc::new(RocksDbBackend::open(dir.join(name)).expect("open rocksdb"))
}

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn caller_keypair(seed: u8) -> ([u8; 32], [u8; 21]) {
    use tron_crypto::signature::RecoverableSignature;
    let mut priv_key = [0u8; 32];
    priv_key[0] = 0x10;
    priv_key[31] = seed;
    let dummy_hash = [0x42u8; 32];
    let sig = RecoverableSignature::sign_prehash(&priv_key, &dummy_hash).expect("sign");
    let pub_key = sig.recover_uncompressed_pubkey(&dummy_hash).expect("recover");
    let h = tron_crypto::hash::keccak256(&pub_key[1..]);
    let mut addr = [0u8; 21];
    addr[0] = 0x41;
    addr[1..].copy_from_slice(&h[12..]);
    (priv_key, addr)
}

fn transfer(priv_key: &[u8; 32], from: [u8; 21], to: [u8; 21], amount: i64, salt: u8) -> Transaction {
    let c = tron_proto::TransferContract {
        owner_address: from.to_vec(),
        to_address: to.to_vec(),
        amount,
    };
    let mut tx = Transaction {
        raw_data: Some(TxRaw {
            contract: vec![TxContract {
                r#type: ContractType::TransferContract as i32,
                parameter: Some(Any {
                    type_url: "type.googleapis.com/protocol.TransferContract".into(),
                    value: c.encode_to_vec(),
                }),
                ..Default::default()
            }],
            timestamp: 1_700_000_000_000,
            expiration: 1_700_000_000_000 + 86_400_000,
            data: vec![salt],
            ..Default::default()
        }),
        signature: Vec::new(),
        ret: vec![tron_proto::transaction::Result {
            contract_ret: tron_proto::transaction::result::ContractResult::Success as i32,
            ..Default::default()
        }],
    };
    tron_types::sign_transaction(&mut tx, priv_key).expect("sign");
    tx
}

fn build_block(
    num: i64,
    parent: [u8; 32],
    witness: [u8; 21],
    witness_priv: &[u8; 32],
    txs: Vec<Transaction>,
) -> Block {
    let mut block = Block {
        block_header: Some(BlockHeader {
            raw_data: Some(tron_proto::block_header::Raw {
                number: num,
                parent_hash: parent.to_vec(),
                timestamp: 1_700_000_000_000 + num * 3000,
                tx_trie_root: tron_types::calc_tx_trie_root(&txs)
                    .map(|h| h.to_vec())
                    .unwrap_or_default(),
                witness_address: witness.to_vec(),
                witness_id: 0,
                version: 28,
                account_state_root: Vec::new(),
            }),
            witness_signature: Vec::new(),
        }),
        transactions: txs,
    };
    sign_block(&mut block, witness_priv).expect("sign block");
    block
}

fn tick_to_park(engine: &IndexEngine) {
    for _ in 0..1000 {
        if matches!(engine.tick().unwrap(), Tick::Parked) {
            return;
        }
    }
    panic!("engine never parked");
}

/// The engine over RocksDB: real blocks flow through the driver into
/// rocks-backed canonical stores, the index backfills, then every
/// handle closes and reopens cold — the index must resume (not
/// rebuild), keep serving exact pages off on-disk reverse iteration,
/// and follow a block written straight to the stores.
#[test]
fn engine_backfills_and_resumes_over_rocksdb() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    let (alice_priv, alice) = caller_keypair(0xa1);
    let (_bob_priv, bob) = caller_keypair(0xb2);
    let caps =
        CaptureSet { native: true, trc20: true, trc721: true, internal: true, logs: false, callee_contract: false };
    let opts = EngineOptions { head_first: false, ..Default::default() };

    // Phase 1: apply three transfer blocks; index to the tip; close.
    let ids: Vec<BlockId> = {
        let blocks_be = rocks(dir, "block");
        let block_index_be = rocks(dir, "block-index");
        let txret_be = rocks(dir, "transactionRetStore");
        let dyn_props_be = rocks(dir, "properties");
        let index_be = rocks(dir, "index");

        let state = StateBackends {
            accounts: mem(),
            witnesses: mem(),
            votes: mem(),
            delegation: mem(),
            delegated_resources: mem(),
            delegated_resource_account_index: None,
            dyn_props: dyn_props_be.clone(),
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
            block_index: Some(block_index_be.clone()),
            witness_schedule: Some(mem()),
            reward_vi: None,
    };
        AccountStore::new(state.accounts.clone())
            .put(
                &Address::from_raw(alice),
                &Account { address: alice.to_vec(), balance: 1_000_000_000, ..Default::default() },
            )
            .unwrap();
        WitnessScheduleStore::new(state.witness_schedule.as_ref().unwrap().clone())
            .save_active(&[Address::from_raw(alice)])
            .unwrap();

        let hook = Arc::new(IndexHook::new(txret_be.clone()));
        let cfg = SyncConfig {
            peers: vec![],
            max_blocks: None,
            tail_interval: Duration::from_millis(1),
            initial_backoff: Duration::from_millis(1),
            blocks_backend: blocks_be.clone(),
            progress_log_interval: 0,
            advertise_port: 18_888,
            tip_test: false,
            p2p_rate_limits: Default::default(),
            fetch_block_timeout: Duration::from_millis(200),
            peer_is_fast_forward: false,
        };
        let mut driver = SyncDriver::new(state, cfg).with_index_hook(hook);

        let mut parent = [0u8; 32];
        let mut ids = Vec::new();
        for n in 1..=3i64 {
            let b = build_block(
                n,
                parent,
                alice,
                &alice_priv,
                vec![transfer(&alice_priv, alice, bob, 1000 * n, n as u8)],
            );
            let id = block_id_from_block(&b).unwrap();
            let outcome = driver.accept_block(&b, None);
            assert!(matches!(outcome, AcceptOutcome::Accepted(_)), "block {n}: {outcome:?}");
            parent = *id.as_bytes();
            ids.push(id);
        }

        let db = IndexDb::new(index_be);
        assert!(matches!(
            db.check_or_init(caps.fingerprint(0)).unwrap(),
            InitOutcome::Fresh
        ));
        let engine = IndexEngine::new(
            db,
            blocks_be,
            block_index_be,
            txret_be,
            dyn_props_be,
            caps,
            opts.clone(),
        );
        tick_to_park(&engine);
        let st = engine.status();
        assert_eq!(st.cursor, Some(3));
        assert!(st.backfill_complete);
        ids
    };

    // Phase 2: cold reopen of every store.
    let blocks_be = rocks(dir, "block");
    let block_index_be = rocks(dir, "block-index");
    let txret_be = rocks(dir, "transactionRetStore");
    let dyn_props_be = rocks(dir, "properties");
    let index_be = rocks(dir, "index");

    let db = IndexDb::new(index_be);
    assert!(
        matches!(db.check_or_init(caps.fingerprint(0)).unwrap(), InitOutcome::Compatible),
        "same scope fingerprint resumes without a wipe"
    );
    let engine = IndexEngine::new(
        db.clone(),
        blocks_be.clone(),
        block_index_be.clone(),
        txret_be.clone(),
        dyn_props_be.clone(),
        caps,
        opts,
    );
    let st = engine.status();
    assert_eq!(st.cursor, Some(3), "cursor persisted across reopen");
    assert!(st.backfill_complete, "backfill state persisted across reopen");
    tick_to_park(&engine);
    assert_eq!(engine.status().cursor, Some(3), "nothing new — no spurious re-index");

    // Block 4 lands in the canonical stores directly (what apply
    // does); store-as-the-queue means the engine follows from disk.
    let b4 = build_block(
        4,
        *ids[2].as_bytes(),
        alice,
        &alice_priv,
        vec![transfer(&alice_priv, alice, bob, 4000, 4)],
    );
    let id4 = block_id_from_block(&b4).unwrap();
    let tx_id =
        tron_crypto::hash::sha256(&b4.transactions[0].raw_data.as_ref().unwrap().encode_to_vec());
    BlockStore::new(blocks_be.clone()).put(&id4, &b4).unwrap();
    BlockIndexStore::new(block_index_be.clone()).put(&id4).unwrap();
    TransactionRetStore::new(txret_be.clone())
        .put(
            4,
            &TransactionRet {
                block_number: 4,
                block_time_stamp: 1_700_000_000_000 + 4 * 3000,
                transactioninfo: vec![TransactionInfo {
                    id: tx_id.to_vec(),
                    block_number: 4,
                    ..Default::default()
                }],
            },
        )
        .unwrap();
    DynamicPropertiesStore::new(dyn_props_be.clone()).save_latest_block_header_number(4);
    tick_to_park(&engine);
    assert_eq!(engine.status().cursor, Some(4));

    // Newest-first paging over real on-disk reverse iteration, with
    // the resume fingerprint crossing pages exactly.
    let reader = IndexReader::new(db, blocks_be, block_index_be, dyn_props_be);
    let p1 = reader
        .native_page(&alice, &PageQuery { limit: 3, ..Default::default() })
        .unwrap();
    let amounts: Vec<i64> = p1.rows.iter().map(|r| r.row.amount).collect();
    assert_eq!(amounts, vec![4000, 3000, 2000], "newest first");
    let p2 = reader
        .native_page(
            &alice,
            &PageQuery { limit: 3, fingerprint: p1.fingerprint.clone(), ..Default::default() },
        )
        .unwrap();
    let amounts: Vec<i64> = p2.rows.iter().map(|r| r.row.amount).collect();
    assert_eq!(amounts, vec![1000], "resume cursor lands exactly after page 1");
}

/// The archive over RocksDB: exact at-height reads, coverage and
/// version rows surviving a cold reopen, reorg unwind, exact gap
/// repair from the undo log, and the crash-safe coverage reset (the
/// multi-batch wipe) — all against the real engine's iterators.
#[test]
fn archive_unwind_repair_and_reset_over_rocksdb() {
    const S: UndoStoreId = UndoStoreId::Accounts;
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    fn open_writer(dir: &Path) -> (ArchiveWriter, Arc<dyn KvBackend>, Arc<dyn KvBackend>) {
        let live = rocks(dir, "accounts");
        let undo_be = rocks(dir, "undo");
        let writer = ArchiveWriter::new(
            rocks(dir, "archive"),
            Some(BlockUndoStore::new(undo_be.clone())),
            vec![(S, live.clone())],
        );
        (writer, live, undo_be)
    }

    /// One block writing `(key, value)` pairs (`None` = delete), fed
    /// to live + undo + archive exactly like the production hook.
    fn apply(
        writer: &ArchiveWriter,
        live: &Arc<dyn KvBackend>,
        undo_be: &Arc<dyn KvBackend>,
        height: i64,
        writes: &[(&[u8], Option<&[u8]>)],
    ) {
        let befores: Vec<Option<Vec<u8>>> =
            writes.iter().map(|(k, _)| live.get(k).unwrap()).collect();
        let mut record = tron_chainbase::BlockUndoRecord::new();
        for ((key, _), before) in writes.iter().zip(befores.iter()) {
            record.push(UndoEntry { store: S, key: key.to_vec(), before: before.clone() });
        }
        BlockUndoStore::new(undo_be.clone()).put(height, &record).unwrap();
        for (key, value) in writes {
            match value {
                Some(v) => live.put(key, v).unwrap(),
                None => live.delete(key).unwrap(),
            }
        }
        let deltas: Vec<tron_index::DeltaRef<'_>> = writes
            .iter()
            .zip(befores.iter())
            .map(|((key, after), before)| tron_index::DeltaRef {
                store: S,
                key,
                before: before.as_deref(),
                after: *after,
            })
            .collect();
        writer.on_block_applied(height, Some(&deltas)).unwrap();
    }

    // Phase 1: capture heights 10..=13 (create, untouched-carry,
    // overwrite, delete), with a pre-capture live value for the base
    // pre-image path. Close everything.
    {
        let (writer, live, undo_be) = open_writer(dir);
        assert!(writer.check_or_init().unwrap(), "fresh archive");
        live.put(b"old", b"pre").unwrap();
        apply(&writer, &live, &undo_be, 10, &[(b"acct", Some(b"v10")), (b"old", Some(b"changed"))]);
        apply(&writer, &live, &undo_be, 11, &[(b"other", Some(b"x"))]);
        apply(&writer, &live, &undo_be, 12, &[(b"acct", Some(b"v12"))]);
        apply(&writer, &live, &undo_be, 13, &[(b"acct", None)]);
        assert_eq!(writer.reader().coverage().unwrap(), Some((9, 13)));
    }

    // Phase 2: cold reopen — history is durable and exact.
    let (writer, live, undo_be) = open_writer(dir);
    assert!(!writer.check_or_init().unwrap(), "existing archive resumes");
    assert_eq!(writer.reader().coverage().unwrap(), Some((9, 13)));
    let at = |k: &[u8], h: i64| writer.reader().value_at(S, k, h).unwrap();
    assert_eq!(at(b"old", 9), AtHeight::Value(b"pre".to_vec()), "base pre-image survived reopen");
    assert_eq!(at(b"old", 13), AtHeight::Value(b"changed".to_vec()));
    assert_eq!(at(b"acct", 9), AtHeight::Deleted);
    assert_eq!(at(b"acct", 10), AtHeight::Value(b"v10".to_vec()));
    assert_eq!(at(b"acct", 11), AtHeight::Value(b"v10".to_vec()), "carried forward");
    assert_eq!(at(b"acct", 12), AtHeight::Value(b"v12".to_vec()));
    assert_eq!(at(b"acct", 13), AtHeight::Deleted);
    assert_eq!(at(b"untouched", 12), AtHeight::NotCovered);

    // Reorg: height 13 re-applies on a new branch — the orphaned
    // delete unwinds, the new write versions on top.
    apply(&writer, &live, &undo_be, 13, &[(b"acct", Some(b"v13-new"))]);
    assert_eq!(at(b"acct", 12), AtHeight::Value(b"v12".to_vec()), "pre-fork history intact");
    assert_eq!(at(b"acct", 13), AtHeight::Value(b"v13-new".to_vec()));
    assert_eq!(
        writer.counters().reorg_unwinds.load(std::sync::atomic::Ordering::Relaxed),
        1
    );

    // Gap: height 14 happens without the archive (live + undo only);
    // height 15 arrives and the gap repairs exactly from the undo log.
    {
        let mut record = tron_chainbase::BlockUndoRecord::new();
        record.push(UndoEntry { store: S, key: b"acct".to_vec(), before: live.get(b"acct").unwrap() });
        BlockUndoStore::new(undo_be.clone()).put(14, &record).unwrap();
        live.put(b"acct", b"v14-silent").unwrap();
    }
    apply(&writer, &live, &undo_be, 15, &[(b"other", Some(b"y"))]);
    assert_eq!(at(b"acct", 13), AtHeight::Value(b"v13-new".to_vec()));
    assert_eq!(at(b"acct", 14), AtHeight::Value(b"v14-silent".to_vec()), "gap repaired exactly");
    assert_eq!(at(b"acct", 15), AtHeight::Value(b"v14-silent".to_vec()));
    assert!(
        writer.counters().gap_repaired_blocks.load(std::sync::atomic::Ordering::Relaxed) >= 1
    );

    // A block with no captured write-set breaks coverage: the loud
    // reset — a multi-batch wipe behind the durable `wiping` marker —
    // runs against real RocksDB and restarts coverage at the break.
    writer.on_block_applied(16, None).unwrap();
    assert_eq!(writer.reader().coverage().unwrap(), Some((16, 16)));
    assert_eq!(at(b"acct", 16), AtHeight::NotCovered, "wiped history is gone, live applies");
    assert_eq!(
        writer.counters().coverage_resets.load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    drop(writer);
    drop(live);
    drop(undo_be);

    // Phase 3: the reset state is durable across reopen.
    let (writer, _live, _undo) = open_writer(dir);
    assert!(!writer.check_or_init().unwrap());
    assert_eq!(writer.reader().coverage().unwrap(), Some((16, 16)));
    assert_eq!(
        writer.reader().value_at(S, b"acct", 16).unwrap(),
        AtHeight::NotCovered
    );
}

/// The firehose over rocks-backed canonical stores: entries append
/// and survive writer restarts, a gap (blocks applied while the
/// firehose was off) repairs by re-deriving from the RocksDB stores,
/// a reorg re-apply emits UNWIND+APPLY, and a log ahead of recovered
/// consensus unwinds at open.
#[test]
fn firehose_repairs_and_unwinds_over_rocksdb_stores() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let log_dir = dir.join("firehose");
    std::fs::create_dir_all(&log_dir).unwrap();

    let blocks = rocks(dir, "block");
    let block_index = rocks(dir, "block-index");
    let txret = rocks(dir, "transactionRetStore");
    let dyn_props = rocks(dir, "properties");

    let make_block = |height: i64, fork: u8| -> (Block, BlockId, TransactionRet) {
        let c = tron_proto::TransferContract {
            owner_address: vec![0x41; 21],
            to_address: vec![0x42; 21],
            amount: height * 10,
        };
        let tx = Transaction {
            raw_data: Some(TxRaw {
                contract: vec![TxContract {
                    r#type: ContractType::TransferContract as i32,
                    parameter: Some(Any {
                        type_url: String::new(),
                        value: c.encode_to_vec(),
                    }),
                    ..Default::default()
                }],
                data: vec![height as u8, fork],
                ..Default::default()
            }),
            ret: vec![tron_proto::transaction::Result {
                contract_ret: tron_proto::transaction::result::ContractResult::Success as i32,
                ..Default::default()
            }],
            ..Default::default()
        };
        let tx_id = tron_crypto::hash::sha256(&tx.raw_data.as_ref().unwrap().encode_to_vec());
        let block = Block {
            transactions: vec![tx],
            block_header: Some(BlockHeader {
                raw_data: Some(tron_proto::block_header::Raw {
                    number: height,
                    timestamp: 1_700_000_000_000 + height * 3000,
                    witness_address: vec![fork; 21],
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };
        let id = block_id_from_block(&block).unwrap();
        let ret = TransactionRet {
            block_number: height,
            block_time_stamp: 1_700_000_000_000 + height * 3000,
            transactioninfo: vec![TransactionInfo {
                id: tx_id.to_vec(),
                block_number: height,
                ..Default::default()
            }],
        };
        (block, id, ret)
    };
    let persist = |block: &Block, id: &BlockId, ret: &TransactionRet| {
        BlockStore::new(blocks.clone()).put(id, block).unwrap();
        BlockIndexStore::new(block_index.clone()).put(id).unwrap();
        TransactionRetStore::new(txret.clone()).put(id.num() as i64, ret).unwrap();
        let dp = DynamicPropertiesStore::new(dyn_props.clone());
        if dp.latest_block_header_number().unwrap_or(0) < id.num() as i64 {
            dp.save_latest_block_header_number(id.num() as i64);
        }
    };
    let open = || {
        FirehoseWriter::open(
            &log_dir,
            u64::MAX,
            blocks.clone(),
            block_index.clone(),
            txret.clone(),
            dyn_props.clone(),
        )
        .unwrap()
    };
    let entries = || -> Vec<(char, i64)> {
        tron_index::FirehoseLogReader::new(log_dir.clone())
            .read_from(1, 1000)
            .unwrap()
            .into_iter()
            .map(|(_, p)| match fh::Entry::decode(p.as_slice()).unwrap().event {
                Some(fh::entry::Event::Apply(a)) => ('A', a.height),
                Some(fh::entry::Event::Unwind(u)) => ('U', u.to_height),
                None => ('?', 0),
            })
            .collect()
    };

    // Blocks 1-2 live; then the firehose closes.
    {
        let w = open();
        for h in 1..=2 {
            let (block, id, ret) = make_block(h, 0);
            persist(&block, &id, &ret);
            w.on_block_applied(&block, &id, &ret).unwrap();
        }
    }

    // Block 3 happens with the firehose off — rocks stores only.
    let (b3, id3, ret3) = make_block(3, 0);
    persist(&b3, &id3, &ret3);

    // Reopen: block 4 applies → 3 re-derives from the rocks stores.
    let w = open();
    let (b4, id4, ret4) = make_block(4, 0);
    persist(&b4, &id4, &ret4);
    w.on_block_applied(&b4, &id4, &ret4).unwrap();
    assert_eq!(entries(), vec![('A', 1), ('A', 2), ('A', 3), ('A', 4)]);
    assert_eq!(
        w.counters().gap_repaired_blocks.load(std::sync::atomic::Ordering::Relaxed),
        1
    );

    // Reorg: height 4 re-applies on a new branch → UNWIND + APPLY.
    let (b4b, id4b, ret4b) = make_block(4, 1);
    persist(&b4b, &id4b, &ret4b);
    w.on_block_applied(&b4b, &id4b, &ret4b).unwrap();
    assert_eq!(
        entries(),
        vec![('A', 1), ('A', 2), ('A', 3), ('A', 4), ('U', 3), ('A', 4)]
    );
    assert_eq!(w.counters().unwinds.load(std::sync::atomic::Ordering::Relaxed), 1);
    drop(w);

    // Power loss: consensus recovered behind the log → UNWIND at open.
    DynamicPropertiesStore::new(dyn_props.clone()).save_latest_block_header_number(3);
    let _w = open();
    assert_eq!(entries().last(), Some(&('U', 3)), "startup unwind to the recovered head");
}
