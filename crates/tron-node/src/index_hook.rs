//! Apply-path hook for the address-history indexer.
//!
//! Fired once per successfully-applied block (clean extension, both
//! reorg-reapply paths, SR-produced blocks). It does exactly two
//! things, in order:
//!
//! 1. **Persist the block's `TransactionRet`** (the per-tx
//!    `TransactionInfo` list) into `transactionRetStore`, built from
//!    the executor's `BlockExecutionReport`. This is the wiring that
//!    makes "store-as-the-queue" hold for the VM-derived index kinds
//!    (TRC20 transfers, internal txs): without it those facts exist
//!    only in the in-memory report and an index that was off while the
//!    node advanced could never recover them. (INDEXER_PLAN.md §3.5 —
//!    the node previously wrote transaction-info nowhere.)
//! 2. **Wake the follower** — a payload-free signal that the head
//!    moved. The follower then reads block + transaction-info from the
//!    stores, so a dropped or coalesced wake-up costs nothing (the
//!    3-second poll re-derives the gap from the stores).
//!
//! The hook must never fail the apply: a store error here is logged
//! and the block stands — the index simply records that range as
//! missing transaction-info and indexes what the block alone provides.
//!
//! Fidelity note: the constructed `TransactionInfo` carries id, block
//! number/timestamp, result code, VM logs, internal transactions, the
//! contract address for VM txs, the full `ResourceReceipt`, the VM
//! return data (`contract_result`), and `fee` aggregated exactly as
//! java-tron does (`ret.fee + energyFee + netFee + multiSignFee +
//! memoFee`). Byte-exactness against a real java-tron-exported store
//! remains a pending end-to-end acceptance check.

use std::sync::Arc;

use tron_chainbase::{KvBackend, TransactionRetStore};
use tron_proto::transaction::contract::ContractType;
use tron_proto::{Block, TransactionInfo, TransactionRet};
use tron_types::BlockId;

/// Shared between the apply paths (writers) and the follower task
/// (waiter). Cheap to clone.
pub struct IndexHook {
    ret_store: TransactionRetStore,
    /// `trans` store — tx-id → block-num refs, written per block so
    /// `gettransactionbyid` / `gettransactioninfobyid` resolve live
    /// transactions (snapshots bring their own refs; live blocks
    /// previously wrote none).
    tx_refs: Option<tron_chainbase::TransactionStore>,
    /// Raw backend handle for the WAL durability barrier below.
    ret_backend: Arc<dyn KvBackend>,
    /// Blocks since the last txinfo WAL fsync (see `on_block_applied`).
    ret_since_sync: std::sync::atomic::AtomicU32,
    notify: Arc<tokio::sync::Notify>,
    /// Optional historical-state archive (P2). When attached, every
    /// applied block's captured write-set is recorded as per-key
    /// versions — synchronously, because deltas exist only in the
    /// in-memory report (they are not re-derivable later).
    archive: Option<Arc<tron_index::ArchiveWriter>>,
    /// Optional firehose writer (P3). When attached, every applied
    /// block appends a durable log entry for external sinks.
    firehose: Option<Arc<crate::firehose::FirehoseWriter>>,
    /// Optional state-commitment channel. When attached, every applied
    /// block's write-set is handed to the background commitment builder
    /// via a non-blocking `try_send` — the commitment is computed OFF the
    /// apply path (folding one block can recompute hundreds of node
    /// hashes), so this hook must never block on it. A full channel drops
    /// the message and flags a resync; the dropped height is re-derivable.
    commitment_tx: Option<tokio::sync::mpsc::Sender<tron_index::CommitmentMsg>>,
    /// Counters shared with the commitment builder, bumped here only to
    /// record backpressure (a dropped write-set) without blocking apply.
    commitment_counters: Option<Arc<tron_index::CommitmentCounters>>,
}

impl IndexHook {
    pub fn new(transaction_ret_backend: Arc<dyn KvBackend>) -> Self {
        Self {
            ret_store: TransactionRetStore::new(transaction_ret_backend.clone()),
            tx_refs: None,
            ret_backend: transaction_ret_backend,
            ret_since_sync: std::sync::atomic::AtomicU32::new(0),
            notify: Arc::new(tokio::sync::Notify::new()),
            archive: None,
            firehose: None,
            commitment_tx: None,
            commitment_counters: None,
        }
    }

    /// Attach the `trans` store so applied blocks also persist
    /// tx-id → block-num refs (the lookups behind the by-id RPCs).
    pub fn with_tx_refs(mut self, backend: Arc<dyn KvBackend>) -> Self {
        self.tx_refs = Some(tron_chainbase::TransactionStore::new(backend));
        self
    }

    /// Attach the historical-state archive writer.
    pub fn with_archive(mut self, writer: Arc<tron_index::ArchiveWriter>) -> Self {
        self.archive = Some(writer);
        self
    }

    /// Attach the firehose writer (the durable external-sink log).
    pub fn with_firehose(mut self, writer: Arc<crate::firehose::FirehoseWriter>) -> Self {
        self.firehose = Some(writer);
        self
    }

    /// Attach the state-commitment channel and its shared counters. The
    /// sender is non-blocking (`try_send`); the background builder drains it.
    pub fn with_commitment(
        mut self,
        tx: tokio::sync::mpsc::Sender<tron_index::CommitmentMsg>,
        counters: Arc<tron_index::CommitmentCounters>,
    ) -> Self {
        self.commitment_tx = Some(tx);
        self.commitment_counters = Some(counters);
        self
    }

    /// The follower parks on this between gap-closing passes.
    pub fn notify_handle(&self) -> Arc<tokio::sync::Notify> {
        self.notify.clone()
    }

    /// Persist the block's transaction-info, then wake the follower.
    /// Infallible by design — errors are logged, never propagated into
    /// the apply path.
    pub fn on_block_applied(
        &self,
        block: &Block,
        block_id: &BlockId,
        report: &tron_executor::BlockExecutionReport,
    ) {
        let ret = build_transaction_ret(block, block_id, report);
        if let Some(tx_refs) = &self.tx_refs {
            let refs = report.tx_results.iter().map(|r| (r.tx_id, block_id.num() as i64));
            if let Err(e) = tx_refs.put_block_refs(refs) {
                tracing::warn!(
                    block = block_id.num(),
                    error = %e,
                    "index hook: tx block-ref batch failed; by-id lookups will miss these txs"
                );
            }
        }
        if let Err(e) = self.ret_store.put(block_id.num() as i64, &ret) {
            tracing::warn!(
                block = block_id.num(),
                error = %e,
                "index hook: transactionRetStore put failed; block stands, range will lack txinfo"
            );
        }
        // Durability barrier for the txinfo store. It sits OUTSIDE the
        // consensus checkpoint manifest, so a power loss could keep a
        // block (manifest-recovered) while losing its txinfo — a
        // permanent gap, since VM facts are not re-derivable. fsync the
        // WAL per block near the tip and every 16 blocks during
        // catch-up (mirroring the node's own defer-fsync philosophy):
        // the worst-case power-loss hole shrinks from "everything since
        // the OS last flushed" to ≤16 catch-up blocks.
        {
            use std::sync::atomic::Ordering;
            let n = self.ret_since_sync.fetch_add(1, Ordering::Relaxed) + 1;
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0);
            let block_ts = block
                .block_header
                .as_ref()
                .and_then(|h| h.raw_data.as_ref())
                .map(|r| r.timestamp)
                .unwrap_or(0);
            let near_tip = now_ms.saturating_sub(block_ts) < 5 * 60 * 1000;
            if near_tip || n >= 16 {
                self.ret_since_sync.store(0, Ordering::Relaxed);
                if let Err(e) = self.ret_backend.sync_wal() {
                    tracing::warn!(error = %e, "index hook: transactionRetStore WAL sync failed");
                }
            }
        }
        if let Some(firehose) = &self.firehose {
            if let Err(e) = firehose.on_block_applied(block, block_id, &ret) {
                tracing::error!(
                    block = block_id.num(),
                    error = %e,
                    "index hook: firehose append failed; block stands, log repairs on next apply"
                );
            }
        }
        if let Some(archive) = &self.archive {
            let deltas: Option<Vec<tron_index::DeltaRef<'_>>> =
                report.state_deltas.as_ref().map(|ds| {
                    ds.iter()
                        .map(|d| tron_index::DeltaRef {
                            store: d.store,
                            key: &d.key,
                            before: d.before.as_deref(),
                            after: d.after.as_deref(),
                        })
                        .collect()
                });
            if let Err(e) = archive.on_block_applied(block_id.num() as i64, deltas.as_deref()) {
                tracing::error!(
                    block = block_id.num(),
                    error = %e,
                    "index hook: archive capture failed; block stands, archive coverage may reset"
                );
            }
        }
        if let Some(tx) = &self.commitment_tx {
            // Hand the block's write-set to the off-path commitment builder.
            // Every height is sent (an empty write-set still advances the
            // committed watermark, keeping the fold contiguous). The message
            // owns its bytes — the hook holds only borrows into the report.
            let height = block_id.num() as i64;
            let deltas: Vec<tron_index::CommitmentDeltaRef> = report
                .state_deltas
                .as_ref()
                .map(|ds| {
                    ds.iter()
                        .map(|d| tron_index::CommitmentDeltaRef {
                            store: d.store,
                            key: d.key.clone(),
                            after: d.after.clone(),
                        })
                        .collect()
                })
                .unwrap_or_default();
            if tx.try_send(tron_index::CommitmentMsg::Block { height, deltas }).is_err() {
                // Drop-and-flag: never block apply on the builder. The dropped
                // height becomes a gap the builder repairs (resume source, else
                // re-bootstrap); record the backpressure for metrics.
                if let Some(counters) = &self.commitment_counters {
                    use std::sync::atomic::Ordering;
                    counters.lagged.fetch_add(1, Ordering::Relaxed);
                    counters.resync_needed.store(true, Ordering::Relaxed);
                }
                tracing::debug!(
                    block = height,
                    "index hook: commitment channel full; dropped write-set (builder will resync)"
                );
            }
        }
        // notify_one stores a permit when no waiter is parked, so a
        // wake-up that lands mid-tick is never lost.
        self.notify.notify_one();
    }
}

/// Build the block's `TransactionRet` from the execution report. Pure
/// — unit-tested directly.
pub fn build_transaction_ret(
    block: &Block,
    block_id: &BlockId,
    report: &tron_executor::BlockExecutionReport,
) -> TransactionRet {
    let block_number = block_id.num() as i64;
    let block_time_stamp = block
        .block_header
        .as_ref()
        .and_then(|h| h.raw_data.as_ref())
        .map(|r| r.timestamp)
        .unwrap_or(0);

    let infos = block
        .transactions
        .iter()
        .zip(report.tx_results.iter())
        .map(|(tx, res)| {
            let result = if res.outcome.is_success() {
                tron_proto::transaction_info::Code::Sucess as i32 // java-tron typo preserved
            } else {
                tron_proto::transaction_info::Code::Failed as i32
            };
            let r = &res.receipt;
            let has_receipt = *r != tron_executor::TxReceipt::default();
            TransactionInfo {
                id: res.tx_id.to_vec(),
                // java-tron's exact aggregation
                // (`TransactionUtil.buildTransactionInfoInstance`):
                // `ret.fee + energyFee + netFee + multiSignFee + memoFee`.
                fee: res.actuator_fee
                    + r.energy_fee
                    + r.net_fee
                    + r.multi_sign_fee
                    + r.memo_fee,
                block_number,
                block_time_stamp,
                contract_address: vm_contract_address(tx, &res.tx_id),
                // The VM's return value / revert payload. java-tron's
                // `TransactionUtil.buildTransactionInfoInstance`
                // unconditionally `addContractResult(hReturn)`, so the
                // list length is always exactly 1 — a zero-length
                // `bytes` entry when there is no return data (halts /
                // OOG / non-VM txs), never an empty list.
                contract_result: vec![res.vm_return_data.clone()],
                receipt: has_receipt.then(|| tron_proto::ResourceReceipt {
                    energy_usage: r.energy_usage,
                    energy_fee: r.energy_fee,
                    origin_energy_usage: r.origin_energy_usage,
                    energy_usage_total: r.energy_usage_total,
                    net_usage: r.net_usage,
                    net_fee: r.net_fee,
                    result: r.result,
                    energy_penalty_total: r.energy_penalty_total,
                }),
                log: res
                    .vm_logs
                    .iter()
                    .map(|l| tron_proto::transaction_info::Log {
                        // 20-byte VM form, matching java-tron's stored
                        // logs (presentation layers re-prefix 0x41).
                        address: l.address.to_vec(),
                        topics: l.topics.iter().map(|t| t.to_vec()).collect(),
                        data: l.data.clone(),
                    })
                    .collect(),
                result,
                // java-tron stamps `runtimeError` here. For a VM REVERT
                // it is exactly the literal `"REVERT opcode executed"`
                // (`VMActuator.java:247`); we reproduce that string
                // byte-for-byte. Other failures keep our own outcome
                // description (java's halt-exception text needs
                // structured halt detail not yet plumbed here).
                res_message: if res.outcome.is_success() {
                    Vec::new()
                } else if r.result
                    == tron_proto::transaction::result::ContractResult::Revert as i32
                {
                    b"REVERT opcode executed".to_vec()
                } else {
                    format!("{:?}", res.outcome).into_bytes()
                },
                internal_transactions: res.internal_transactions.clone(),
                ..Default::default()
            }
        })
        .collect();

    TransactionRet { block_number, block_time_stamp, transactioninfo: infos }
}

/// The `contract_address` java-tron stamps on a VM tx's
/// `TransactionInfo`: the called contract for a trigger, the derived
/// address (`0x41 ‖ keccak256(owner ‖ tx_id)[12..]`) for a create.
/// Empty for non-VM txs.
fn vm_contract_address(tx: &tron_proto::Transaction, tx_id: &[u8; 32]) -> Vec<u8> {
    let Some(contract) = tx.raw_data.as_ref().and_then(|r| r.contract.first()) else {
        return Vec::new();
    };
    let param = contract.parameter.as_ref().map(|p| p.value.as_slice()).unwrap_or(&[]);
    match ContractType::try_from(contract.r#type).ok() {
        Some(ContractType::TriggerSmartContract) => {
            tron_proto::decode_lenient::<tron_proto::TriggerSmartContract>(param)
                .map(|c| c.contract_address)
                .unwrap_or_default()
        }
        Some(ContractType::CreateSmartContract) => {
            let Ok(c) = tron_proto::decode_lenient::<tron_proto::CreateSmartContract>(param) else {
                return Vec::new();
            };
            // One shared copy of the consensus-critical derivation —
            // the same function the index extractor uses.
            tron_index::created_contract_address(&c.owner_address, tx_id).to_vec()
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message as _;
    use tron_chainbase::MemBackend;
    use tron_executor::{TxOutcome, TxResult};

    fn block_with_transfer() -> (Block, BlockId, [u8; 32]) {
        let c = tron_proto::TransferContract {
            owner_address: vec![0x41; 21],
            to_address: vec![0x42; 21],
            amount: 9,
        };
        let tx = tron_proto::Transaction {
            raw_data: Some(tron_proto::transaction::Raw {
                contract: vec![tron_proto::transaction::Contract {
                    r#type: ContractType::TransferContract as i32,
                    parameter: Some(prost_types::Any {
                        type_url: String::new(),
                        value: c.encode_to_vec(),
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let tx_id =
            tron_crypto::hash::sha256(&tx.raw_data.as_ref().unwrap().encode_to_vec());
        let block = Block {
            transactions: vec![tx],
            block_header: Some(tron_proto::BlockHeader {
                raw_data: Some(tron_proto::block_header::Raw {
                    number: 7,
                    timestamp: 123_000,
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };
        let id = tron_types::block_id_from_block(&block).unwrap();
        (block, id, tx_id)
    }

    fn report_for(id: &BlockId, tx_id: [u8; 32], success: bool) -> tron_executor::BlockExecutionReport {
        tron_executor::BlockExecutionReport {
            block_id: *id,
            tx_results: vec![TxResult {
                tx_id,
                contract_type: None,
                outcome: if success {
                    TxOutcome::Success
                } else {
                    TxOutcome::InvalidFeeLimit { fee_limit: 0 }
                },
                internal_transactions: vec![],
                vm_logs: vec![tron_tvm::execute::VmLog {
                    address: [0xee; 20],
                    topics: vec![[0x11; 32]],
                    data: vec![1, 2, 3],
                }],
                receipt: tron_executor::TxReceipt {
                    net_usage: 265,
                    energy_usage_total: 13_000,
                    energy_fee: 1_000,
                    ..Default::default()
                },
                vm_return_data: vec![0xAB],
                actuator_fee: 0,
            }],
            maintenance: None,
            state_deltas: None,
        }
    }

    /// Single-tx report with an explicit `TxResult`, for the
    /// `TransactionInfo` data-fidelity assertions (contractResult shape,
    /// res_message text).
    fn report_with(id: &BlockId, res: TxResult) -> tron_executor::BlockExecutionReport {
        tron_executor::BlockExecutionReport {
            block_id: *id,
            tx_results: vec![res],
            maintenance: None,
            state_deltas: None,
        }
    }

    #[test]
    fn builds_block_keyed_ret_with_logs_and_result() {
        let (block, id, tx_id) = block_with_transfer();
        let ret = build_transaction_ret(&block, &id, &report_for(&id, tx_id, true));
        assert_eq!(ret.block_number, 7);
        assert_eq!(ret.block_time_stamp, 123_000);
        assert_eq!(ret.transactioninfo.len(), 1);
        let info = &ret.transactioninfo[0];
        assert_eq!(info.id, tx_id.to_vec());
        assert_eq!(info.result, tron_proto::transaction_info::Code::Sucess as i32);
        assert_eq!(info.log.len(), 1);
        assert_eq!(info.log[0].address.len(), 20, "VM 20-byte form, java-tron stored shape");
        // Receipt + fee + return data ride through.
        let receipt = info.receipt.as_ref().expect("receipt present");
        assert_eq!(receipt.net_usage, 265);
        assert_eq!(receipt.energy_usage_total, 13_000);
        assert_eq!(receipt.energy_fee, 1_000);
        assert_eq!(info.fee, 1_000, "fee = net_fee + energy_fee");
        // java-tron always stores contractResult as a one-element list.
        assert_eq!(info.contract_result, vec![vec![0xAB]]);
        assert_eq!(info.contract_result.len(), 1);
        assert!(info.res_message.is_empty(), "success carries no res_message");

        let failed = build_transaction_ret(&block, &id, &report_for(&id, tx_id, false));
        assert_eq!(
            failed.transactioninfo[0].result,
            tron_proto::transaction_info::Code::Failed as i32
        );
    }

    /// A halted / OOG tx carries no VM return data — java-tron still
    /// stores a length-1 `contractResult` list whose single entry is
    /// zero-length bytes, never an empty list.
    #[test]
    fn halt_yields_length_one_empty_contract_result() {
        let (block, id, tx_id) = block_with_transfer();
        let mut receipt = tron_executor::TxReceipt::default();
        receipt.result = tron_proto::transaction::result::ContractResult::OutOfEnergy as i32;
        let res = TxResult {
            tx_id,
            contract_type: None,
            outcome: TxOutcome::ExecutionFailed(tron_actuator::ActuatorError::Store(
                "VM halt: OutOfGas".to_string(),
            )),
            internal_transactions: vec![],
            vm_logs: vec![],
            receipt,
            vm_return_data: vec![],
            actuator_fee: 0,
        };
        let ret = build_transaction_ret(&block, &id, &report_with(&id, res));
        let info = &ret.transactioninfo[0];
        assert_eq!(info.contract_result.len(), 1, "always a one-element list");
        assert!(info.contract_result[0].is_empty(), "single zero-length entry");
        // Non-revert failure keeps our outcome description, not the
        // java REVERT literal.
        assert_ne!(info.res_message, b"REVERT opcode executed".to_vec());
        assert!(!info.res_message.is_empty());
    }

    /// A reverted tx: java-tron's `runtimeError` for a REVERT opcode is
    /// exactly `"REVERT opcode executed"` (VMActuator.java:247), and the
    /// revert payload rides through as the single `contractResult` entry.
    #[test]
    fn revert_yields_java_message_and_carries_payload() {
        let (block, id, tx_id) = block_with_transfer();
        let mut receipt = tron_executor::TxReceipt::default();
        receipt.result = tron_proto::transaction::result::ContractResult::Revert as i32;
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let res = TxResult {
            tx_id,
            contract_type: None,
            outcome: TxOutcome::ExecutionFailed(tron_actuator::ActuatorError::Store(
                "VM revert".to_string(),
            )),
            internal_transactions: vec![],
            vm_logs: vec![],
            receipt,
            vm_return_data: payload.clone(),
            actuator_fee: 0,
        };
        let ret = build_transaction_ret(&block, &id, &report_with(&id, res));
        let info = &ret.transactioninfo[0];
        assert_eq!(info.res_message, b"REVERT opcode executed".to_vec());
        assert_eq!(info.contract_result.len(), 1, "always a one-element list");
        assert_eq!(info.contract_result[0], payload, "revert payload rides through");
    }

    #[test]
    fn hook_persists_and_is_readable_back() {
        let backend: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
        let hook = IndexHook::new(backend.clone());
        let (block, id, tx_id) = block_with_transfer();
        hook.on_block_applied(&block, &id, &report_for(&id, tx_id, true));
        let got = TransactionRetStore::new(backend).get(7).unwrap().expect("persisted");
        assert_eq!(got.transactioninfo[0].id, tx_id.to_vec());
    }
}
