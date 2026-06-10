//! End-to-end engine tests over in-memory stores: backfill, resume,
//! idempotence, head-first ordering, reorg unwind, scope rebuild.
//!
//! The fixture builds a synthetic canonical chain directly in the
//! consensus stores (BlockStore / BlockIndexStore /
//! TransactionRetStore / DynamicPropertiesStore) — exactly the
//! committed state the engine reads in production; no executor needed.

use std::sync::Arc;

use prost::Message as _;
use tron_chainbase::{
    BlockIndexStore, BlockStore, DynamicPropertiesStore, KvBackend, MemBackend,
    TransactionRetStore,
};
use tron_index::{
    extract_block, CaptureSet, EngineOptions, IndexDb, IndexEngine, IndexReader, PageQuery, Tick,
    TRANSFER_TOPIC,
};
use tron_proto::transaction::contract::ContractType;
use tron_types::{block_id_from_block, BlockId};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn addr(b: u8) -> [u8; 21] {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(b);
    a
}

const ALICE: u8 = 0xaa;
const BOB: u8 = 0xbb;
const CAROL: u8 = 0xcc;
const TOKEN: u8 = 0xee;

fn transfer_tx(from: u8, to: u8, amount: i64, salt: u8) -> tron_proto::Transaction {
    let c = tron_proto::TransferContract {
        owner_address: addr(from).to_vec(),
        to_address: addr(to).to_vec(),
        amount,
    };
    tron_proto::Transaction {
        raw_data: Some(tron_proto::transaction::Raw {
            contract: vec![tron_proto::transaction::Contract {
                r#type: ContractType::TransferContract as i32,
                parameter: Some(prost_types::Any {
                    type_url: "type.googleapis.com/protocol.TransferContract".into(),
                    value: c.encode_to_vec(),
                }),
                ..Default::default()
            }],
            // Salt keeps tx ids distinct across blocks.
            data: vec![salt],
            ..Default::default()
        }),
        ret: vec![tron_proto::transaction::Result {
            contract_ret: tron_proto::transaction::result::ContractResult::Success as i32,
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn trigger_tx(caller: u8, contract: u8, salt: u8) -> tron_proto::Transaction {
    let c = tron_proto::TriggerSmartContract {
        owner_address: addr(caller).to_vec(),
        contract_address: addr(contract).to_vec(),
        ..Default::default()
    };
    tron_proto::Transaction {
        raw_data: Some(tron_proto::transaction::Raw {
            contract: vec![tron_proto::transaction::Contract {
                r#type: ContractType::TriggerSmartContract as i32,
                parameter: Some(prost_types::Any {
                    type_url: "type.googleapis.com/protocol.TriggerSmartContract".into(),
                    value: c.encode_to_vec(),
                }),
                ..Default::default()
            }],
            data: vec![salt, 1],
            ..Default::default()
        }),
        ret: vec![tron_proto::transaction::Result {
            contract_ret: tron_proto::transaction::result::ContractResult::Success as i32,
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn tx_id(tx: &tron_proto::Transaction) -> [u8; 32] {
    tron_crypto::hash::sha256(&tx.raw_data.as_ref().unwrap().encode_to_vec())
}

fn topic_addr(a: &[u8; 21]) -> Vec<u8> {
    let mut t = vec![0u8; 12];
    t.extend_from_slice(&a[1..]);
    t
}

/// A `Transfer(from, to, amount)` log in stored transaction-info form.
fn transfer_log(from: u8, to: u8, amount: u64) -> tron_proto::transaction_info::Log {
    let mut data = vec![0u8; 32];
    data[24..].copy_from_slice(&amount.to_be_bytes());
    tron_proto::transaction_info::Log {
        address: addr(TOKEN)[1..].to_vec(), // 20-byte VM form
        topics: vec![TRANSFER_TOPIC.to_vec(), topic_addr(&addr(from)), topic_addr(&addr(to))],
        data,
    }
}

/// Test-harness view of the consensus stores the engine reads.
struct Chain {
    blocks: Arc<dyn KvBackend>,
    block_index: Arc<dyn KvBackend>,
    txret: Arc<dyn KvBackend>,
    dyn_props: Arc<dyn KvBackend>,
}

impl Chain {
    fn new() -> Self {
        Self { blocks: mem(), block_index: mem(), txret: mem(), dyn_props: mem() }
    }

    /// Append a canonical block at `num` with the given txs +
    /// per-block transaction-info, and advance the head pointers.
    /// `parent` distinguishes forks (mixed into the header so ids
    /// differ across branches).
    fn put_block(
        &self,
        num: i64,
        fork_tag: u8,
        txs: Vec<tron_proto::Transaction>,
        infos: Option<Vec<tron_proto::TransactionInfo>>,
    ) -> BlockId {
        let block = tron_proto::Block {
            transactions: txs,
            block_header: Some(tron_proto::BlockHeader {
                raw_data: Some(tron_proto::block_header::Raw {
                    number: num,
                    timestamp: 1_700_000_000_000 + num * 3_000,
                    witness_address: vec![fork_tag; 21],
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };
        let id = block_id_from_block(&block).unwrap();
        BlockStore::new(self.blocks.clone()).put(&id, &block).unwrap();
        BlockIndexStore::new(self.block_index.clone()).put(&id).unwrap();
        if let Some(infos) = infos {
            // id-stamp each info like java-tron does.
            let mut infos = infos;
            for (i, tx) in block.transactions.iter().enumerate() {
                if let Some(info) = infos.get_mut(i) {
                    if info.id.is_empty() {
                        info.id = tx_id(tx).to_vec();
                    }
                }
            }
            TransactionRetStore::new(self.txret.clone())
                .put(
                    num,
                    &tron_proto::TransactionRet {
                        block_number: num,
                        block_time_stamp: 1_700_000_000_000 + num * 3_000,
                        transactioninfo: infos,
                    },
                )
                .unwrap();
        }
        let dp = DynamicPropertiesStore::new(self.dyn_props.clone());
        if dp.latest_block_header_number().unwrap_or(-1) < num {
            dp.save_latest_block_header_number(num);
            dp.save_latest_block_header_hash(id.as_bytes());
        }
        id
    }

    fn engine(&self, caps: CaptureSet, opts: EngineOptions) -> (IndexEngine, IndexDb) {
        let backend = mem();
        let db = IndexDb::new(backend.clone());
        db.check_or_init(caps.fingerprint(opts.start_height)).unwrap();
        let engine = IndexEngine::new(
            db.clone(),
            self.blocks.clone(),
            self.block_index.clone(),
            self.txret.clone(),
            self.dyn_props.clone(),
            caps,
            opts,
        );
        (engine, db)
    }

    fn reader(&self, db: &IndexDb) -> IndexReader {
        IndexReader::new(
            db.clone(),
            self.blocks.clone(),
            self.block_index.clone(),
            self.dyn_props.clone(),
        )
    }
}

fn caps_default() -> CaptureSet {
    CaptureSet { native: true, trc20: true, trc721: true, internal: true, logs: false, callee_contract: false }
}

fn opts_floor_first() -> EngineOptions {
    EngineOptions { head_first: false, window_blocks: 4, sync_every_windows: 2, ..Default::default() }
}

/// Drive the engine until it parks; panics if it never settles.
fn run_to_park(engine: &IndexEngine) {
    for _ in 0..10_000 {
        match engine.tick().unwrap() {
            Tick::Parked | Tick::NotReady => return,
            _ => {}
        }
    }
    panic!("engine never parked");
}

/// Build the standard 1..=20 chain: TRX transfers Alice→Bob, plus a
/// USDT Transfer log Alice→Bob in every 5th block.
fn standard_chain() -> Chain {
    let chain = Chain::new();
    for n in 1..=20i64 {
        let mut txs = vec![transfer_tx(ALICE, BOB, n * 10, n as u8)];
        let mut infos = vec![tron_proto::TransactionInfo::default()];
        if n % 5 == 0 {
            txs.push(trigger_tx(CAROL, TOKEN, n as u8));
            infos.push(tron_proto::TransactionInfo {
                log: vec![transfer_log(ALICE, BOB, 1_000_000)],
                internal_transactions: vec![tron_proto::InternalTransaction {
                    hash: vec![0; 32],
                    caller_address: addr(TOKEN).to_vec(),
                    transfer_to_address: addr(BOB).to_vec(),
                    call_value_info: vec![tron_proto::internal_transaction::CallValueInfo {
                        call_value: 77,
                        token_id: String::new(),
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            });
        }
        chain.put_block(n, 0, txs, Some(infos));
    }
    chain
}

fn dump_index(db: &IndexDb) -> Vec<(Vec<u8>, Vec<u8>)> {
    db.backend().scan_all().unwrap()
}

#[test]
fn floor_first_backfill_indexes_everything_then_parks() {
    let chain = standard_chain();
    let (engine, db) = chain.engine(caps_default(), opts_floor_first());
    run_to_park(&engine);

    let status = engine.status();
    assert_eq!(status.cursor, Some(20));
    assert_eq!(status.back_edge, Some(1));
    assert!(status.backfill_complete && status.at_tip);

    let reader = chain.reader(&db);
    // Alice: 20 native transfers (newest first) + 4 trc20.
    let page = reader.native_page(&addr(ALICE), &PageQuery { limit: 100, ..Default::default() }).unwrap();
    assert_eq!(page.rows.len(), 20);
    assert!(page.fingerprint.is_none());
    let heights: Vec<i64> = page.rows.iter().map(|r| r.parts.height).collect();
    let mut sorted = heights.clone();
    sorted.sort_by(|a, b| b.cmp(a));
    assert_eq!(heights, sorted, "newest-first by construction");

    let trc20 = reader.trc20_page(&addr(BOB), &PageQuery { limit: 100, ..Default::default() }).unwrap();
    assert_eq!(trc20.rows.len(), 4);
    assert_eq!(trc20.rows[0].row.token, addr(TOKEN).to_vec());

    // Carol called the token contract: caller-side native rows exist…
    let carol = reader.native_page(&addr(CAROL), &PageQuery { limit: 100, ..Default::default() }).unwrap();
    assert_eq!(carol.rows.len(), 4);
    // …but the CALLED contract has no native history (callee capture off).
    let token_native = reader.native_page(&addr(TOKEN), &PageQuery { limit: 100, ..Default::default() }).unwrap();
    assert!(token_native.rows.is_empty());
    // The token contract DOES appear as an internal-tx caller.
    let token_internal = reader.internal_page(&addr(TOKEN), &PageQuery { limit: 100, ..Default::default() }).unwrap();
    assert_eq!(token_internal.rows.len(), 4);
}

#[test]
fn head_first_serves_recent_history_before_backfill_completes() {
    let chain = standard_chain();
    let opts = EngineOptions { head_first: true, window_blocks: 4, ..Default::default() };
    let (engine, db) = chain.engine(caps_default(), opts);

    // First tick initializes edges at head; next ticks walk backward.
    let t = engine.tick().unwrap();
    // With cursor == head there is no forward gap; first work is backward.
    assert!(matches!(t, Tick::Backward { .. }), "got {t:?}");
    let status = engine.status();
    assert_eq!(status.cursor, Some(20));
    assert!(!status.backfill_complete);

    // Recent rows are already queryable mid-backfill.
    let reader = chain.reader(&db);
    let page = reader.native_page(&addr(ALICE), &PageQuery { limit: 5, ..Default::default() }).unwrap();
    assert!(!page.rows.is_empty());
    assert_eq!(page.rows[0].parts.height, 20, "newest block first");

    run_to_park(&engine);
    assert!(engine.status().backfill_complete);
    // Final contents must be identical to a floor-first build.
    let (engine2, db2) = chain.engine(caps_default(), opts_floor_first());
    run_to_park(&engine2);
    assert_eq!(dump_index(&db), dump_index(&db2), "ordering must not change the result");
}

#[test]
fn indexing_is_idempotent_and_resumable() {
    let chain = standard_chain();

    // Reference: uninterrupted run.
    let (engine_ref, db_ref) = chain.engine(caps_default(), opts_floor_first());
    run_to_park(&engine_ref);

    // Interrupted run: tick a few windows, "crash" (drop engine), then
    // resume with a fresh engine over the same DB.
    let backend = {
        let (engine, db) = chain.engine(caps_default(), opts_floor_first());
        engine.tick().unwrap();
        engine.tick().unwrap();
        db.backend().clone()
    };
    let db = IndexDb::new(backend);
    let resumed = IndexEngine::new(
        db.clone(),
        chain.blocks.clone(),
        chain.block_index.clone(),
        chain.txret.clone(),
        chain.dyn_props.clone(),
        caps_default(),
        opts_floor_first(),
    );
    run_to_park(&resumed);
    assert_eq!(dump_index(&db), dump_index(&db_ref), "resume == uninterrupted, byte-compared");
}

#[test]
fn live_blocks_extend_the_index_after_park() {
    let chain = standard_chain();
    let (engine, db) = chain.engine(caps_default(), opts_floor_first());
    run_to_park(&engine);

    // A new block lands (the apply hook would notify; here we just
    // tick again).
    chain.put_block(21, 0, vec![transfer_tx(BOB, CAROL, 5, 21)], Some(vec![Default::default()]));
    let t = engine.tick().unwrap();
    assert!(matches!(t, Tick::Forward { upto: 21, .. }), "got {t:?}");

    let reader = chain.reader(&db);
    let page = reader.native_page(&addr(CAROL), &PageQuery { limit: 1, ..Default::default() }).unwrap();
    assert_eq!(page.rows[0].parts.height, 21);
    assert_eq!(page.rows[0].row.direction, tron_index::DIR_TO);
}

#[test]
fn reorg_unwinds_to_common_ancestor_and_converges_byte_identically() {
    // Chain A: 1..=12. Reorg replaces 11..12 with 11'..13'.
    let chain = standard_chain();
    // Trim to height 12 by rebuilding head pointers (fixture chain is 20
    // long; build a dedicated shorter chain instead).
    let chain = {
        let c = Chain::new();
        for n in 1..=12i64 {
            c.put_block(n, 0, vec![transfer_tx(ALICE, BOB, n, n as u8)], Some(vec![Default::default()]));
        }
        drop(chain);
        c
    };
    let (engine, db) = chain.engine(caps_default(), opts_floor_first());
    run_to_park(&engine);
    assert_eq!(engine.status().cursor, Some(12));

    // The reorg: heights 11-12 get DIFFERENT canonical blocks (fork
    // tag 1, different txs), plus a new height 13. BlockIndexStore is
    // repointed — exactly what `reindex_canonical_branch` does — and
    // the new chain's txinfo overwrites the old at the same heights.
    for n in 11..=13i64 {
        chain.put_block(n, 1, vec![transfer_tx(CAROL, BOB, n * 100, n as u8)], Some(vec![Default::default()]));
    }
    let t = engine.tick().unwrap();
    assert!(matches!(t, Tick::Unwound { ancestor: 10, .. }), "got {t:?}");
    run_to_park(&engine);

    // Alice's rows from orphaned 11-12 are gone; Carol's new rows are in.
    let reader = chain.reader(&db);
    let alice = reader.native_page(&addr(ALICE), &PageQuery { limit: 100, ..Default::default() }).unwrap();
    assert_eq!(alice.rows.len(), 10, "old-chain rows above the ancestor were un-indexed");
    let carol = reader.native_page(&addr(CAROL), &PageQuery { limit: 100, ..Default::default() }).unwrap();
    assert_eq!(carol.rows.iter().map(|r| r.parts.height).collect::<Vec<_>>(), vec![13, 12, 11]);

    // Byte-identical to an index built fresh on the post-reorg chain.
    let (engine2, db2) = chain.engine(caps_default(), opts_floor_first());
    run_to_park(&engine2);
    assert_eq!(dump_index(&db), dump_index(&db2), "post-reorg index == fresh build on chain B");
}

#[test]
fn reorg_detected_after_restart_without_witnessing_it() {
    // Same as above but the reorg happens while the engine is "off" —
    // a fresh engine instance over the same DB must reconcile by hash
    // at startup.
    let chain = Chain::new();
    for n in 1..=12i64 {
        chain.put_block(n, 0, vec![transfer_tx(ALICE, BOB, n, n as u8)], Some(vec![Default::default()]));
    }
    let (engine, db) = chain.engine(caps_default(), opts_floor_first());
    run_to_park(&engine);
    drop(engine); // index "off"

    for n in 11..=13i64 {
        chain.put_block(n, 1, vec![transfer_tx(CAROL, BOB, n * 100, n as u8)], Some(vec![Default::default()]));
    }

    let restarted = IndexEngine::new(
        db.clone(),
        chain.blocks.clone(),
        chain.block_index.clone(),
        chain.txret.clone(),
        chain.dyn_props.clone(),
        caps_default(),
        opts_floor_first(),
    );
    let t = restarted.tick().unwrap();
    assert!(matches!(t, Tick::Unwound { ancestor: 10, .. }), "got {t:?}");
    run_to_park(&restarted);
    let reader = chain.reader(&db);
    let carol = reader.native_page(&addr(CAROL), &PageQuery { limit: 100, ..Default::default() }).unwrap();
    assert_eq!(carol.rows.len(), 3);
}

#[test]
fn missing_txinfo_blocks_index_native_only_and_are_counted() {
    let chain = Chain::new();
    for n in 1..=6i64 {
        // Blocks 3-4 carry a Transfer log but NO stored txinfo.
        let txs = vec![trigger_tx(CAROL, TOKEN, n as u8)];
        let infos = if (3..=4).contains(&n) {
            None
        } else {
            Some(vec![tron_proto::TransactionInfo {
                log: vec![transfer_log(ALICE, BOB, 9)],
                ..Default::default()
            }])
        };
        chain.put_block(n, 0, txs, infos);
    }
    let (engine, db) = chain.engine(caps_default(), opts_floor_first());
    run_to_park(&engine);

    let reader = chain.reader(&db);
    // Native rows exist for all 6 blocks; trc20 only for the 4 with txinfo.
    let carol = reader.native_page(&addr(CAROL), &PageQuery { limit: 100, ..Default::default() }).unwrap();
    assert_eq!(carol.rows.len(), 6);
    let bob = reader.trc20_page(&addr(BOB), &PageQuery { limit: 100, ..Default::default() }).unwrap();
    assert_eq!(bob.rows.len(), 4);
    assert_eq!(
        engine.counters().missing_txinfo_blocks.load(std::sync::atomic::Ordering::Relaxed),
        2
    );
}

#[test]
fn start_height_clamps_the_floor() {
    let chain = standard_chain();
    let opts = EngineOptions { start_height: 15, ..opts_floor_first() };
    let (engine, db) = chain.engine(
        CaptureSet { ..caps_default() },
        opts,
    );
    run_to_park(&engine);
    let status = engine.status();
    assert_eq!(status.floor, Some(15));
    assert_eq!(status.back_edge, Some(15));
    let reader = chain.reader(&db);
    let page = reader.native_page(&addr(ALICE), &PageQuery { limit: 100, ..Default::default() }).unwrap();
    assert_eq!(page.rows.len(), 6, "only heights 15..=20 indexed");
}

#[test]
fn pagination_fingerprint_resumes_without_dup_or_skip() {
    let chain = standard_chain();
    let (engine, db) = chain.engine(caps_default(), opts_floor_first());
    run_to_park(&engine);
    let reader = chain.reader(&db);

    // Walk Alice's 20 native rows in pages of 3 (desc), then asc.
    for ascending in [false, true] {
        let mut seen: Vec<i64> = Vec::new();
        let mut fp: Option<Vec<u8>> = None;
        loop {
            let page = reader
                .native_page(
                    &addr(ALICE),
                    &PageQuery { limit: 3, fingerprint: fp.clone(), ascending, ..Default::default() },
                )
                .unwrap();
            seen.extend(page.rows.iter().map(|r| r.parts.height));
            match page.fingerprint {
                Some(next) => fp = Some(next),
                None => break,
            }
        }
        let expected: Vec<i64> =
            if ascending { (1..=20).collect() } else { (1..=20).rev().collect() };
        assert_eq!(seen, expected, "ascending={ascending}");
    }
}

#[test]
fn filters_match_brute_force() {
    let chain = standard_chain();
    let (engine, db) = chain.engine(caps_default(), opts_floor_first());
    run_to_park(&engine);
    // Mark blocks ≤ 18 solidified.
    DynamicPropertiesStore::new(chain.dyn_props.clone()).save_latest_solidified_block_num(18);
    let reader = chain.reader(&db);
    let a = addr(ALICE);

    let all = reader.native_page(&a, &PageQuery { limit: 1000, ..Default::default() }).unwrap();
    assert_eq!(all.rows.len(), 20);

    // only_confirmed → heights ≤ 18, and the confirmed flag agrees.
    let conf = reader
        .native_page(&a, &PageQuery { limit: 1000, only_confirmed: true, ..Default::default() })
        .unwrap();
    assert_eq!(conf.rows.len(), 18);
    assert!(conf.rows.iter().all(|r| r.confirmed && r.parts.height <= 18));

    let unconf = reader
        .native_page(&a, &PageQuery { limit: 1000, only_unconfirmed: true, ..Default::default() })
        .unwrap();
    assert_eq!(unconf.rows.iter().map(|r| r.parts.height).collect::<Vec<_>>(), vec![20, 19]);

    // Direction: Alice is always FROM in the fixture.
    let from_only = reader
        .native_page(&a, &PageQuery { limit: 1000, only_from: true, ..Default::default() })
        .unwrap();
    assert_eq!(from_only.rows.len(), 20);
    let to_only = reader
        .native_page(&a, &PageQuery { limit: 1000, only_to: true, ..Default::default() })
        .unwrap();
    assert!(to_only.rows.is_empty());

    // Timestamp window: blocks 5..=10 inclusive (fixture: ts = base + n*3000).
    let base = 1_700_000_000_000i64;
    let page = reader
        .native_page(
            &a,
            &PageQuery {
                limit: 1000,
                min_timestamp_ms: Some(base + 5 * 3000),
                max_timestamp_ms: Some(base + 10 * 3000),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        page.rows.iter().map(|r| r.parts.height).collect::<Vec<_>>(),
        vec![10, 9, 8, 7, 6, 5]
    );

    // Token filter on Bob's trc20 page.
    let bob = addr(BOB);
    let tok = reader
        .trc20_page(&bob, &PageQuery { limit: 1000, token: Some(addr(TOKEN)), ..Default::default() })
        .unwrap();
    assert_eq!(tok.rows.len(), 4);
    let none = reader
        .trc20_page(&bob, &PageQuery { limit: 1000, token: Some(addr(0x01)), ..Default::default() })
        .unwrap();
    assert!(none.rows.is_empty());
}

#[test]
fn scope_change_is_detected_and_wipe_rebuild_converges() {
    let chain = standard_chain();
    let caps_a = caps_default();
    let (engine, db) = chain.engine(caps_a, opts_floor_first());
    run_to_park(&engine);

    // Re-open with a different capture set → NeedsRebuild → wipe →
    // stamp → fresh cold start, exactly the follower's ordinary path.
    let caps_b = CaptureSet { callee_contract: true, ..caps_a };
    match db.check_or_init(caps_b.fingerprint(0)).unwrap() {
        tron_index::InitOutcome::NeedsRebuild { .. } => {
            db.wipe().unwrap();
            db.stamp(caps_b.fingerprint(0)).unwrap();
        }
        other => panic!("expected NeedsRebuild, got {other:?}"),
    }
    let rebuilt = IndexEngine::new(
        db.clone(),
        chain.blocks.clone(),
        chain.block_index.clone(),
        chain.txret.clone(),
        chain.dyn_props.clone(),
        caps_b,
        opts_floor_first(),
    );
    run_to_park(&rebuilt);
    // Callee rows now exist for the called token contract.
    let reader = chain.reader(&db);
    let token_native =
        reader.native_page(&addr(TOKEN), &PageQuery { limit: 100, ..Default::default() }).unwrap();
    assert_eq!(token_native.rows.len(), 4);
}

#[test]
fn extraction_matches_engine_output_for_a_block() {
    // Sanity link between the unit-level extractor and what the engine
    // persists: same puts.
    let chain = standard_chain();
    let (engine, db) = chain.engine(caps_default(), opts_floor_first());
    run_to_park(&engine);

    let bi = BlockIndexStore::new(chain.block_index.clone());
    let id = bi.get(5).unwrap();
    let block = BlockStore::new(chain.blocks.clone()).get(&id).unwrap();
    let info = TransactionRetStore::new(chain.txret.clone()).get(5).unwrap();
    let entries = extract_block(5, &block, info.as_ref(), &caps_default());
    assert!(!entries.puts.is_empty());
    for (k, v) in entries.puts {
        assert_eq!(db.backend().get(&k).unwrap().as_deref(), Some(v.as_slice()));
    }
}

#[test]
fn trc721_transfers_index_and_page_under_both_parties() {
    let chain = Chain::new();
    let nft_log = |from: u8, to: u8, token_id: u64| {
        let mut id = vec![0u8; 32];
        id[24..].copy_from_slice(&token_id.to_be_bytes());
        tron_proto::transaction_info::Log {
            address: addr(TOKEN)[1..].to_vec(),
            topics: vec![
                TRANSFER_TOPIC.to_vec(),
                topic_addr(&addr(from)),
                topic_addr(&addr(to)),
                id,
            ],
            data: vec![],
        }
    };
    for n in 1..=3i64 {
        let txs = vec![trigger_tx(ALICE, TOKEN, n as u8)];
        let infos = vec![tron_proto::TransactionInfo {
            log: vec![nft_log(ALICE, BOB, 100 + n as u64)],
            ..Default::default()
        }];
        chain.put_block(n, 0, txs, Some(infos));
    }
    let (engine, db) = chain.engine(caps_default(), opts_floor_first());
    run_to_park(&engine);
    let reader = chain.reader(&db);

    let bob = reader
        .trc721_page(&addr(BOB), &PageQuery { limit: 100, ..Default::default() })
        .unwrap();
    assert_eq!(bob.rows.len(), 3);
    assert_eq!(bob.rows[0].row.token, addr(TOKEN).to_vec());
    assert_eq!(bob.rows[0].row.direction, tron_index::DIR_TO);
    // Newest first: tokenIds 103, 102, 101.
    let ids: Vec<u64> = bob
        .rows
        .iter()
        .map(|r| u64::from_be_bytes(r.row.token_id[24..].try_into().unwrap()))
        .collect();
    assert_eq!(ids, vec![103, 102, 101]);

    // Token filter: the NFT contract matches, another address doesn't.
    let q = PageQuery { limit: 100, token: Some(addr(TOKEN)), ..Default::default() };
    assert_eq!(reader.trc721_page(&addr(BOB), &q).unwrap().rows.len(), 3);
    let q = PageQuery { limit: 100, token: Some(addr(0x77)), ..Default::default() };
    assert!(reader.trc721_page(&addr(BOB), &q).unwrap().rows.is_empty());

    // The 4-topic NFT logs never leak into the TRC20 namespace.
    let trc20 = reader
        .trc20_page(&addr(BOB), &PageQuery { limit: 100, ..Default::default() })
        .unwrap();
    assert!(trc20.rows.is_empty());
}

#[test]
fn logs_page_merges_event_groups_newest_first() {
    let chain = Chain::new();
    let ev = |topic0: u8, n: i64| tron_proto::transaction_info::Log {
        address: addr(TOKEN)[1..].to_vec(),
        topics: vec![vec![topic0; 32], vec![n as u8; 32]],
        data: vec![n as u8],
    };
    // Heights 1..=6 alternate between two event signatures, so the two
    // `contract ‖ topic0` groups interleave by height and only a real
    // merge produces global newest-first.
    for n in 1..=6i64 {
        let txs = vec![trigger_tx(ALICE, TOKEN, n as u8)];
        let t0 = if n % 2 == 0 { 0x22 } else { 0x11 };
        let infos =
            vec![tron_proto::TransactionInfo { log: vec![ev(t0, n)], ..Default::default() }];
        chain.put_block(n, 0, txs, Some(infos));
    }
    let caps = CaptureSet { logs: true, ..caps_default() };
    let (engine, db) = chain.engine(caps, opts_floor_first());
    run_to_park(&engine);
    let reader = chain.reader(&db);

    // No signature filter: globally newest-first across both groups.
    let page = reader
        .logs_page(&addr(TOKEN), None, &PageQuery { limit: 100, ..Default::default() })
        .unwrap();
    let heights: Vec<i64> = page.rows.iter().map(|r| r.height).collect();
    assert_eq!(heights, vec![6, 5, 4, 3, 2, 1]);
    assert!(page.fingerprint.is_none(), "exhausted page carries no fingerprint");

    // One signature: a single group's range.
    let page = reader
        .logs_page(&addr(TOKEN), Some([0x11; 32]), &PageQuery { limit: 100, ..Default::default() })
        .unwrap();
    assert_eq!(page.rows.iter().map(|r| r.height).collect::<Vec<_>>(), vec![5, 3, 1]);
    assert!(page.rows.iter().all(|r| r.topic0 == [0x11; 32]));

    // Fingerprint pagination resumes across the group merge exactly.
    let p1 = reader
        .logs_page(&addr(TOKEN), None, &PageQuery { limit: 2, ..Default::default() })
        .unwrap();
    assert_eq!(p1.rows.iter().map(|r| r.height).collect::<Vec<_>>(), vec![6, 5]);
    let fp = p1.fingerprint.clone().expect("more pages exist");
    let p2 = reader
        .logs_page(
            &addr(TOKEN),
            None,
            &PageQuery { limit: 2, fingerprint: Some(fp), ..Default::default() },
        )
        .unwrap();
    assert_eq!(p2.rows.iter().map(|r| r.height).collect::<Vec<_>>(), vec![4, 3]);

    // Ascending: oldest first, same merge.
    let page = reader
        .logs_page(
            &addr(TOKEN),
            None,
            &PageQuery { limit: 100, ascending: true, ..Default::default() },
        )
        .unwrap();
    assert_eq!(page.rows.iter().map(|r| r.height).collect::<Vec<_>>(), vec![1, 2, 3, 4, 5, 6]);

    // Exact-block bound (the events API's block_number param).
    let q = PageQuery { limit: 100, min_block: Some(4), max_block: Some(4), ..Default::default() };
    let page = reader.logs_page(&addr(TOKEN), None, &q).unwrap();
    assert_eq!(page.rows.iter().map(|r| r.height).collect::<Vec<_>>(), vec![4]);

    // A contract that never emitted: empty.
    let page = reader
        .logs_page(&addr(0x55), None, &PageQuery { limit: 10, ..Default::default() })
        .unwrap();
    assert!(page.rows.is_empty());
}
