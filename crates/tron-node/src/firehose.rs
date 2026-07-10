//! The firehose writer — appends one durable log entry per applied
//! block for external sinks (P3).
//!
//! Entries are **store-derivable by construction**: an `APPLY` entry
//! is a pure function of `(block, TransactionRet)`, both of which the
//! node persists — so any gap between the log and the chain (crash
//! tail, node ran with the firehose off) is repaired by re-deriving
//! the missing entries from `BlockStore` + `TransactionRetStore`.
//! Chain unwinds (reorgs, or the log being *ahead* of consensus after
//! a power loss) become explicit `UNWIND` entries; consumers must
//! handle them anyway, so crash recovery and reorgs share one
//! protocol. This is why the log needs **no** CheckPointV2 cursor
//! binding: it can neither lose blocks (store repair) nor claim a
//! block that didn't commit (startup unwind), and external consumers
//! get exactly-once semantics by persisting their cursor
//! transactionally with their own writes (see `working/FIREHOSE.md`).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use prost::Message as _;
use tron_chainbase::{
    BlockIndexStore, BlockStore, DynamicPropertiesStore, KvBackend, StoreError,
    TransactionRetStore,
};
use tron_grpc::firehose_proto as fh;
use tron_index::{FirehoseLogWriter, FirehoseTailHandle, IndexError};
use tron_proto::{Block, TransactionRet};
use tron_types::BlockId;

/// Blocks between WAL fsyncs while catching up; recent (near-tip)
/// blocks fsync every entry — at one block per ~3s that is cheap, and
/// it minimizes the repair window for live consumers.
const SYNC_EVERY: u32 = 16;
const RECENT_MS: i64 = 5 * 60 * 1000;
/// Max store-derived gap-repair heights processed in a single
/// `on_block_applied` call. A gap larger than this is repaired
/// incrementally across successive applies so a huge gap (firehose
/// re-enabled after a long off period, or a snapshot swap to a much
/// higher head) can't re-derive hundreds of thousands of heights
/// synchronously under the writer lock and stall block apply. The chain
/// advances one block per apply while a repair pass closes this many, so
/// the window converges.
const GAP_REPAIR_MAX: i64 = 512;

#[derive(Debug, Default)]
pub struct FirehoseCounters {
    pub entries: AtomicU64,
    pub unwinds: AtomicU64,
    pub gap_repaired_blocks: AtomicU64,
}

pub struct FirehoseWriter {
    inner: Mutex<Inner>,
    blocks: Arc<dyn KvBackend>,
    block_index: Arc<dyn KvBackend>,
    txret: Arc<dyn KvBackend>,
    dyn_props: Arc<dyn KvBackend>,
    counters: Arc<FirehoseCounters>,
}

struct Inner {
    log: FirehoseLogWriter,
    /// Height of the newest entry (`-1` = empty log).
    head_height: i64,
    blocks_since_sync: u32,
}

impl FirehoseWriter {
    /// Open the log under `dir` and reconcile it against consensus:
    /// a log *ahead* of the recovered chain head gets an immediate
    /// `UNWIND` so consumers can never hold blocks the chain lost.
    pub fn open(
        dir: impl Into<std::path::PathBuf>,
        retain_bytes: u64,
        blocks: Arc<dyn KvBackend>,
        block_index: Arc<dyn KvBackend>,
        txret: Arc<dyn KvBackend>,
        dyn_props: Arc<dyn KvBackend>,
    ) -> Result<Self, IndexError> {
        let mut log = FirehoseLogWriter::open(dir, retain_bytes)?;
        // The log head's height AND (for an Apply) the block_id it recorded —
        // the id is needed to detect an abandoned-branch head that height
        // alone cannot see (see the reconciliation below).
        let (mut head_height, head_block_id) = match log.reader().head()? {
            Some((_, payload)) => match fh::Entry::decode(payload.as_slice()) {
                Ok(e) => match e.event {
                    Some(fh::entry::Event::Apply(a)) => (a.height, Some(a.block_id)),
                    Some(fh::entry::Event::Unwind(u)) => (u.to_height, None),
                    None => (-1, None),
                },
                Err(e) => {
                    return Err(IndexError::Corrupt(format!(
                        "firehose head entry undecodable: {e}"
                    )))
                }
            },
            None => (-1, None),
        };
        let consensus_head_opt = DynamicPropertiesStore::new(dyn_props.clone())
            .latest_block_header_number();
        let consensus_head = consensus_head_opt.unwrap_or(0);
        let counters = Arc::new(FirehoseCounters::default());

        // Reconcile the log against the recovered consensus chain. Two
        // independent conditions force an UNWIND; a height comparison alone
        // catches only the first:
        //   (1) the log is AHEAD of the recovered head — power loss rolled the
        //       chain back below what the log already emitted.
        //   (2) the log head sits at (or below) the consensus head but on an
        //       ABANDONED branch: a tip reorg replaced block N, the executor
        //       committed N′ durably, but a crash landed before the log's
        //       UNWIND + APPLY(N′) were fsynced, so the torn tail was truncated
        //       and the log head is still old-branch APPLY(N). Heights match
        //       (both N), so (1) never fires and consumers would keep the
        //       orphaned block forever. Compare the recorded block_id to the
        //       canonical id at that height; on a mismatch, unwind to the last
        //       provably-common height — the solidified/irreversible head is at
        //       or below the true fork point — and let the canonical branch
        //       re-derive above it (via the store-derived gap repair on the
        //       next apply). If solidified can't be read, drop just the
        //       orphaned head block (correct for the dominant 1-block tip fork).
        let reconcile_to = if head_height > consensus_head {
            // Guard against a firehose directory that does not belong to this
            // data directory. A legitimate power-loss rollback leaves the log
            // ahead by at most the fsync window plus a reorg (tens of blocks).
            // No consensus head at all (a wiped/fresh state store), or an
            // implausibly large gap, instead means the firehose dir survived a
            // wiped/replaced data dir. UNWIND(consensus_head) here would tell
            // every consumer to DELETE all derived data (WHERE height >
            // consensus_head, i.e. > 0), so refuse to open and let the operator
            // remove the stale firehose dir intentionally.
            const MAX_PLAUSIBLE_ROLLBACK: i64 = 10_000;
            if consensus_head_opt.is_none()
                || head_height - consensus_head > MAX_PLAUSIBLE_ROLLBACK
            {
                return Err(IndexError::Corrupt(format!(
                    "firehose log head {head_height} is implausibly far ahead of the \
                     consensus head {consensus_head} — the firehose directory does not \
                     match this data directory (wiped or replaced?). Refusing to \
                     auto-UNWIND, which would wipe all consumer state; remove the stale \
                     firehose directory to reset it."
                )));
            }
            Some(consensus_head)
        } else if head_height >= 0 {
            let canonical = BlockIndexStore::new(block_index.clone())
                .get(head_height)
                .ok()
                .map(|id| id.as_bytes().to_vec());
            match (&head_block_id, canonical) {
                (Some(logged), Some(canon)) if *logged != canon => {
                    let solidified = DynamicPropertiesStore::new(dyn_props.clone())
                        .latest_solidified_block_num();
                    Some(solidified.map(|s| s.min(head_height - 1)).unwrap_or(head_height - 1))
                }
                _ => None,
            }
        } else {
            None
        };

        if let Some(to) = reconcile_to {
            tracing::warn!(
                log_head = head_height,
                consensus_head,
                unwind_to = to,
                "firehose: reconciling log to consensus — emitting UNWIND (chain rolled back, \
                 or a reorg's entries were lost to a crash before fsync)"
            );
            let seq = log.next_seq();
            let entry = fh::Entry {
                seq,
                event: Some(fh::entry::Event::Unwind(fh::Unwind { to_height: to })),
            };
            log.append(&entry.encode_to_vec())?;
            log.sync()?;
            counters.unwinds.fetch_add(1, Ordering::Relaxed);
            head_height = to;
        }
        tracing::info!(head_height, consensus_head, "firehose: log open");
        Ok(Self {
            inner: Mutex::new(Inner { log, head_height, blocks_since_sync: 0 }),
            blocks,
            block_index,
            txret,
            dyn_props,
            counters,
        })
    }

    pub fn counters(&self) -> Arc<FirehoseCounters> {
        self.counters.clone()
    }

    pub fn tail_handle(&self) -> FirehoseTailHandle {
        self.inner.lock().expect("firehose poisoned").log.tail_handle()
    }

    /// Append entries for one applied block: an `UNWIND` first when
    /// this is a reorg re-apply, store-derived repair entries first
    /// when the log missed blocks. Never fails the apply (caller logs
    /// errors).
    pub fn on_block_applied(
        &self,
        block: &Block,
        block_id: &BlockId,
        ret: &TransactionRet,
    ) -> Result<(), IndexError> {
        let mut inner = self.inner.lock().expect("firehose poisoned");
        let h = block_id.num() as i64;
        let solidified = DynamicPropertiesStore::new(self.dyn_props.clone())
            .latest_solidified_block_num()
            .unwrap_or(0);

        if inner.head_height >= 0 {
            if h <= inner.head_height {
                // Reorg re-apply: consumers drop everything above the
                // common ancestor, then re-consume.
                self.append(
                    &mut inner,
                    fh::entry::Event::Unwind(fh::Unwind { to_height: h - 1 }),
                )?;
                self.counters.unwinds.fetch_add(1, Ordering::Relaxed);
                tracing::info!(to_height = h - 1, "firehose: reorg unwind appended");
            } else if h > inner.head_height + 1 {
                // The log missed blocks (firehose was off / crash tail
                // truncated): re-derive them from the stores — but only up to
                // GAP_REPAIR_MAX heights per apply so a huge gap can't stall
                // block apply under the writer lock. A gap wider than the cap
                // is closed incrementally: repair a bounded prefix now, DON'T
                // append APPLY(h) (that would leave a hole), and let later
                // applies continue from where this one stopped. Block h itself
                // re-derives from the stores when the window reaches it.
                let from = inner.head_height + 1;
                let repair_end = h.min(from + GAP_REPAIR_MAX);
                for g in from..repair_end {
                    match self.derive_from_stores(g, solidified)? {
                        Some(event) => {
                            self.append(&mut inner, event)?;
                            self.counters.gap_repaired_blocks.fetch_add(1, Ordering::Relaxed);
                        }
                        None => {
                            // Canonical block below head missing from the
                            // stores — store-level inconsistency. Surface
                            // loudly; the height jump is the consumer's
                            // fault signal.
                            tracing::error!(
                                height = g,
                                "firehose: cannot repair gap (canonical block missing); \
                                 consumers will observe a height jump"
                            );
                        }
                    }
                }
                if repair_end < h {
                    // Gap exceeds the per-apply cap. Record progress, persist
                    // it, and return without appending APPLY(h).
                    inner.head_height = repair_end - 1;
                    inner.log.sync()?;
                    inner.blocks_since_sync = 0;
                    tracing::warn!(
                        from,
                        repaired_to = repair_end - 1,
                        target = h,
                        "firehose: repairing large gap incrementally (will continue on next apply)"
                    );
                    return Ok(());
                }
                tracing::warn!(from, to = h - 1, "firehose: repaired log gap from stores");
            }
        }

        let event = fh::entry::Event::Apply(build_apply(h, block, Some(ret), solidified));
        self.append(&mut inner, event)?;
        self.counters.entries.fetch_add(1, Ordering::Relaxed);
        inner.head_height = h;

        // Durability: every entry near the tip, batched during
        // catch-up. Lost (un-fsynced) tails self-repair from the
        // stores on the next append.
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let block_ts = block
            .block_header
            .as_ref()
            .and_then(|hd| hd.raw_data.as_ref())
            .map(|r| r.timestamp)
            .unwrap_or(0);
        inner.blocks_since_sync += 1;
        if now_ms.saturating_sub(block_ts) < RECENT_MS || inner.blocks_since_sync >= SYNC_EVERY {
            inner.log.sync()?;
            inner.blocks_since_sync = 0;
        }
        Ok(())
    }

    fn append(&self, inner: &mut Inner, event: fh::entry::Event) -> Result<u64, IndexError> {
        let seq = inner.log.next_seq();
        let entry = fh::Entry { seq, event: Some(event) };
        inner.log.append(&entry.encode_to_vec())
    }

    /// Re-derive one canonical block's APPLY event from the stores —
    /// the same `(block, txinfo)` inputs the live path uses, so
    /// repaired entries are byte-equivalent to what would have been
    /// written live (modulo the solidified watermark, which is "as of
    /// now").
    fn derive_from_stores(
        &self,
        height: i64,
        solidified: i64,
    ) -> Result<Option<fh::entry::Event>, IndexError> {
        let id = match BlockIndexStore::new(self.block_index.clone()).get(height) {
            Ok(id) => id,
            Err(StoreError::NotFound) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let block = match BlockStore::new(self.blocks.clone()).get(&id) {
            Ok(b) => b,
            Err(StoreError::NotFound) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let ret = TransactionRetStore::new(self.txret.clone()).get(height)?;
        Ok(Some(fh::entry::Event::Apply(build_apply(
            height,
            &block,
            ret.as_ref(),
            solidified,
        ))))
    }
}

/// Build a `BlockApplied` event from committed inputs. Pure —
/// unit-tested directly; identical for the live and repair paths.
pub fn build_apply(
    height: i64,
    block: &Block,
    ret: Option<&TransactionRet>,
    solidified: i64,
) -> fh::BlockApplied {
    let raw = block.block_header.as_ref().and_then(|h| h.raw_data.as_ref());
    let block_id = tron_types::block_id_from_block(block)
        .map(|id| id.as_bytes().to_vec())
        .unwrap_or_default();

    // transaction-info matched through the SAME rulebook the index
    // extractor uses (32-byte id match, positional fallback only for
    // id-less infos) — a private fork here had already drifted and
    // would have made firehose entries disagree with index rows over
    // identical blocks.
    let matcher = tron_index::TxInfoMatcher::new(ret);

    let txs = block
        .transactions
        .iter()
        .enumerate()
        .filter_map(|(i, tx)| {
            let raw_tx = tx.raw_data.as_ref()?;
            let tx_id = tron_crypto::hash::sha256(&raw_tx.encode_to_vec());
            let facts = tron_index::tx_facts(tx, &tx_id);
            let info = matcher.for_tx(&tx_id, i);
            let success = tx
                .ret
                .first()
                .map(|r| {
                    r.contract_ret
                        == tron_proto::transaction::result::ContractResult::Success as i32
                })
                .unwrap_or(false);
            Some(fh::Tx {
                txid: tx_id.to_vec(),
                contract_type: facts.as_ref().map(|f| f.contract_type).unwrap_or(0),
                success,
                from: facts.as_ref().map(|f| f.from.clone()).unwrap_or_default(),
                to: facts.as_ref().and_then(|f| f.to.clone()).unwrap_or_default(),
                amount: facts.as_ref().map(|f| f.amount).unwrap_or(0),
                asset: facts.as_ref().and_then(|f| f.asset.clone()).unwrap_or_default(),
                vm_contract: info.map(|i| i.contract_address.clone()).unwrap_or_default(),
                logs: info
                    .map(|i| {
                        i.log
                            .iter()
                            .map(|l| fh::Log {
                                address: l.address.clone(),
                                topics: l.topics.clone(),
                                data: l.data.clone(),
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
                internal_txs: info
                    .map(|i| {
                        i.internal_transactions
                            .iter()
                            .map(|itx| fh::InternalTx {
                                caller: itx.caller_address.clone(),
                                transfer_to: itx.transfer_to_address.clone(),
                                call_value: itx
                                    .call_value_info
                                    .iter()
                                    .find(|cv| cv.token_id.is_empty())
                                    .map(|cv| cv.call_value)
                                    .unwrap_or(0),
                                // java's `InternalTransaction` writes "0"
                                // as the no-token sentinel for a plain
                                // (TRX-only) call leg; real TRC10 ids are
                                // positive. Skip both the empty and the
                                // "0" entries so a non-token call never
                                // emits a phantom token leg downstream.
                                token_id: itx
                                    .call_value_info
                                    .iter()
                                    .find(|cv| !cv.token_id.is_empty() && cv.token_id != "0")
                                    .map(|cv| cv.token_id.clone())
                                    .unwrap_or_default(),
                                rejected: itx.rejected,
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            })
        })
        .collect();

    fh::BlockApplied {
        height,
        block_id,
        parent_id: raw.map(|r| r.parent_hash.clone()).unwrap_or_default(),
        timestamp_ms: raw.map(|r| r.timestamp).unwrap_or(0),
        witness: raw.map(|r| r.witness_address.clone()).unwrap_or_default(),
        solidified_height: solidified,
        txinfo_missing: ret.is_none() && !block.transactions.is_empty(),
        txs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tron_chainbase::MemBackend;

    fn mem() -> Arc<dyn KvBackend> {
        Arc::new(MemBackend::new())
    }

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "tron-fh-writer-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Test rig mirroring what the hook + stores provide: applying a
    /// block writes it to the consensus stores (canonical) and bumps
    /// the head, exactly what `accept_block` guarantees before the
    /// hook fires.
    struct Rig {
        blocks: Arc<dyn KvBackend>,
        block_index: Arc<dyn KvBackend>,
        txret: Arc<dyn KvBackend>,
        dyn_props: Arc<dyn KvBackend>,
        dir: std::path::PathBuf,
    }

    impl Rig {
        fn new(tag: &str) -> Self {
            Self {
                blocks: mem(),
                block_index: mem(),
                txret: mem(),
                dyn_props: mem(),
                dir: tmp_dir(tag),
            }
        }

        fn open(&self) -> FirehoseWriter {
            FirehoseWriter::open(
                &self.dir,
                u64::MAX,
                self.blocks.clone(),
                self.block_index.clone(),
                self.txret.clone(),
                self.dyn_props.clone(),
            )
            .unwrap()
        }

        fn make_block(&self, height: i64, fork: u8) -> (Block, BlockId, TransactionRet) {
            let c = tron_proto::TransferContract {
                owner_address: vec![0x41; 21],
                to_address: vec![0x42; 21],
                amount: height * 10,
            };
            let tx = tron_proto::Transaction {
                raw_data: Some(tron_proto::transaction::Raw {
                    contract: vec![tron_proto::transaction::Contract {
                        r#type:
                            tron_proto::transaction::contract::ContractType::TransferContract
                                as i32,
                        parameter: Some(prost_types::Any {
                            type_url: String::new(),
                            value: c.encode_to_vec(),
                        }),
                        ..Default::default()
                    }],
                    data: vec![height as u8, fork],
                    ..Default::default()
                }),
                ret: vec![tron_proto::transaction::Result {
                    contract_ret:
                        tron_proto::transaction::result::ContractResult::Success as i32,
                    ..Default::default()
                }],
                ..Default::default()
            };
            let tx_id =
                tron_crypto::hash::sha256(&tx.raw_data.as_ref().unwrap().encode_to_vec());
            let block = Block {
                transactions: vec![tx],
                block_header: Some(tron_proto::BlockHeader {
                    raw_data: Some(tron_proto::block_header::Raw {
                        number: height,
                        timestamp: 1_700_000_000_000 + height * 3000,
                        witness_address: vec![fork; 21],
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
            };
            let id = tron_types::block_id_from_block(&block).unwrap();
            let ret = TransactionRet {
                block_number: height,
                block_time_stamp: 1_700_000_000_000 + height * 3000,
                transactioninfo: vec![tron_proto::TransactionInfo {
                    id: tx_id.to_vec(),
                    block_number: height,
                    ..Default::default()
                }],
            };
            (block, id, ret)
        }

        /// Persist a block to the stores + advance the head — what the
        /// node has already done by the time the hook fires.
        fn persist(&self, block: &Block, id: &BlockId, ret: &TransactionRet) {
            BlockStore::new(self.blocks.clone()).put(id, block).unwrap();
            BlockIndexStore::new(self.block_index.clone()).put(id).unwrap();
            TransactionRetStore::new(self.txret.clone())
                .put(id.num() as i64, ret)
                .unwrap();
            let dp = DynamicPropertiesStore::new(self.dyn_props.clone());
            if dp.latest_block_header_number().unwrap_or(0) < id.num() as i64 {
                dp.save_latest_block_header_number(id.num() as i64);
            }
        }

        fn apply(&self, w: &FirehoseWriter, height: i64) {
            let (block, id, ret) = self.make_block(height, 0);
            self.persist(&block, &id, &ret);
            w.on_block_applied(&block, &id, &ret).unwrap();
        }

        fn entries(&self) -> Vec<fh::Entry> {
            tron_index::FirehoseLogReader::new(self.dir.clone())
                .read_from(1, 1000)
                .unwrap()
                .into_iter()
                .map(|(_, p)| fh::Entry::decode(p.as_slice()).unwrap())
                .collect()
        }
    }

    fn heights(entries: &[fh::Entry]) -> Vec<(char, i64)> {
        entries
            .iter()
            .map(|e| match &e.event {
                Some(fh::entry::Event::Apply(a)) => ('A', a.height),
                Some(fh::entry::Event::Unwind(u)) => ('U', u.to_height),
                None => ('?', 0),
            })
            .collect()
    }

    #[test]
    fn applies_carry_decoded_tx_facts() {
        let rig = Rig::new("facts");
        let w = rig.open();
        rig.apply(&w, 1);
        rig.apply(&w, 2);
        let entries = rig.entries();
        assert_eq!(heights(&entries), vec![('A', 1), ('A', 2)]);
        let Some(fh::entry::Event::Apply(a)) = &entries[1].event else { panic!() };
        assert_eq!(a.txs.len(), 1);
        let tx = &a.txs[0];
        assert!(tx.success);
        assert_eq!(tx.from, vec![0x41; 21]);
        assert_eq!(tx.to, vec![0x42; 21]);
        assert_eq!(tx.amount, 20);
        assert_eq!(entries[0].seq, 1);
        assert_eq!(entries[1].seq, 2);
    }

    #[test]
    fn reorg_reapply_emits_unwind_then_apply() {
        let rig = Rig::new("reorg");
        let w = rig.open();
        for h in 1..=3 {
            rig.apply(&w, h);
        }
        // Reorg: height 2 re-applies on a new branch.
        let (block, id, ret) = rig.make_block(2, 1);
        rig.persist(&block, &id, &ret);
        w.on_block_applied(&block, &id, &ret).unwrap();
        rig.apply(&w, 3);
        assert_eq!(
            heights(&rig.entries()),
            vec![('A', 1), ('A', 2), ('A', 3), ('U', 1), ('A', 2), ('A', 3)]
        );
        assert_eq!(w.counters().unwinds.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn missed_blocks_are_repaired_from_the_stores() {
        let rig = Rig::new("gap");
        {
            let w = rig.open();
            rig.apply(&w, 1);
        } // firehose "off"

        // Blocks 2-3 happen without the writer (persisted to stores only).
        for h in 2..=3 {
            let (block, id, ret) = rig.make_block(h, 0);
            rig.persist(&block, &id, &ret);
        }

        // Reopen; block 4 applies → 2..3 derive from the stores first.
        let w = rig.open();
        rig.apply(&w, 4);
        let entries = rig.entries();
        assert_eq!(heights(&entries), vec![('A', 1), ('A', 2), ('A', 3), ('A', 4)]);
        // Repaired entries carry the same decoded facts as live ones.
        let Some(fh::entry::Event::Apply(a)) = &entries[1].event else { panic!() };
        assert_eq!(a.txs[0].amount, 20);
        assert!(!a.txinfo_missing);
        assert_eq!(w.counters().gap_repaired_blocks.load(Ordering::Relaxed), 2);
    }

    /// java's `InternalTransaction` records a plain (TRX-only) call leg
    /// with the no-token sentinel `tokenId == "0"`; only a positive id
    /// is a real TRC10 move. `build_apply` must not surface that "0" as
    /// a token leg, or external consumers would see a phantom token on
    /// every ordinary contract call.
    #[test]
    fn internal_tx_zero_token_sentinel_is_not_emitted() {
        let owner = vec![0x41; 21];
        let to = vec![0x42; 21];
        let raw = tron_proto::transaction::Raw {
            contract: vec![tron_proto::transaction::Contract {
                r#type: tron_proto::transaction::contract::ContractType::TriggerSmartContract
                    as i32,
                parameter: Some(prost_types::Any {
                    type_url: String::new(),
                    value: tron_proto::TriggerSmartContract {
                        owner_address: owner.clone(),
                        contract_address: to.clone(),
                        ..Default::default()
                    }
                    .encode_to_vec(),
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        let tx = tron_proto::Transaction {
            raw_data: Some(raw),
            ret: vec![tron_proto::transaction::Result {
                contract_ret: tron_proto::transaction::result::ContractResult::Success as i32,
                ..Default::default()
            }],
            ..Default::default()
        };
        let tx_id = tron_crypto::hash::sha256(&tx.raw_data.as_ref().unwrap().encode_to_vec());
        let block = Block {
            transactions: vec![tx],
            block_header: Some(tron_proto::BlockHeader {
                raw_data: Some(tron_proto::block_header::Raw {
                    number: 100,
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };
        // Two internal transactions: one a plain TRX-only call (the "0"
        // sentinel), one a real TRC10 move (positive id).
        let ret = TransactionRet {
            block_number: 100,
            block_time_stamp: 0,
            transactioninfo: vec![tron_proto::TransactionInfo {
                id: tx_id.to_vec(),
                block_number: 100,
                internal_transactions: vec![
                    tron_proto::InternalTransaction {
                        caller_address: owner.clone(),
                        transfer_to_address: to.clone(),
                        call_value_info: vec![
                            tron_proto::internal_transaction::CallValueInfo {
                                call_value: 7,
                                token_id: String::new(),
                            },
                            tron_proto::internal_transaction::CallValueInfo {
                                call_value: 0,
                                token_id: "0".to_string(),
                            },
                        ],
                        ..Default::default()
                    },
                    tron_proto::InternalTransaction {
                        caller_address: owner.clone(),
                        transfer_to_address: to.clone(),
                        call_value_info: vec![tron_proto::internal_transaction::CallValueInfo {
                            call_value: 5,
                            token_id: "1000001".to_string(),
                        }],
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
        };

        let a = build_apply(100, &block, Some(&ret), 0);
        let itxs = &a.txs[0].internal_txs;
        assert_eq!(itxs.len(), 2);
        // Plain call leg: TRX value carried, no phantom token id.
        assert_eq!(itxs[0].call_value, 7);
        assert_eq!(itxs[0].token_id, "", "the \"0\" sentinel must not surface as a token");
        // Real TRC10 move: positive id preserved.
        assert_eq!(itxs[1].token_id, "1000001");
    }

    #[test]
    fn log_ahead_of_consensus_unwinds_at_open() {
        let rig = Rig::new("ahead");
        {
            let w = rig.open();
            for h in 1..=5 {
                rig.apply(&w, h);
            }
        }
        // Power loss: consensus recovered to height 3.
        DynamicPropertiesStore::new(rig.dyn_props.clone()).save_latest_block_header_number(3);
        let w = rig.open();
        let entries = rig.entries();
        assert_eq!(entries.len(), 6);
        assert_eq!(heights(&entries)[5], ('U', 3), "startup unwind to the recovered head");
        // Re-applying 4 continues normally (no extra unwind).
        rig.apply(&w, 4);
        assert_eq!(heights(&rig.entries())[6], ('A', 4));
    }
}
