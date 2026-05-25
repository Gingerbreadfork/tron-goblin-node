//! Helpers that convert raw block + per-tx outcome data into the
//! trigger payloads the bus expects, so the caller can hand off a
//! `Block` + tx outcome list and get triggers emitted in one call.
//!
//! These take primitives (no dependency on `tron-executor`), so any
//! caller with a `tron_proto::Block` and per-tx outcomes can use them.

use tron_proto::transaction::contract::ContractType;
use tron_proto::Block;

use crate::bus::EventBus;
use crate::trigger::{names, BlockEvent, TransactionEvent};

/// One tx's post-execution data — the minimal slice the eventer needs
/// from a per-tx execution outcome. Decouples this crate from the
/// executor's `TxResult`.
#[derive(Debug, Clone)]
pub struct TxOutcomeSlice {
    pub tx_id: [u8; 32],
    /// `"SUCCESS"` / `"REVERT"` / `"FAILED"` etc. — the textual form
    /// java-tron writes into `contractResult`.
    pub contract_result: String,
}

/// Emit a block-level trigger plus one transaction-level trigger per
/// tx in the block. Skips work entirely when the bus has no listeners.
///
/// `latest_solidified` is the latest solidified block number at emit
/// time — passed through to the `latestSolidifiedBlockNumber` field on
/// every trigger so consumers can filter by finality.
pub fn emit_block_and_transactions(
    bus: &EventBus,
    block: &Block,
    block_id: &[u8; 32],
    tx_outcomes: &[TxOutcomeSlice],
    latest_solidified: i64,
) {
    if bus.is_empty() {
        return;
    }
    let Some(header) = block.block_header.as_ref().and_then(|h| h.raw_data.as_ref()) else {
        return;
    };
    let block_number = header.number;
    let timestamp_ms = header.timestamp;

    // Block trigger first.
    let tx_ids: Vec<[u8; 32]> = tx_outcomes.iter().map(|t| t.tx_id).collect();
    let block_event = BlockEvent::new(
        block_number,
        block_id,
        timestamp_ms,
        latest_solidified,
        tx_ids,
    );
    bus.emit_block(&block_event);

    // One transaction trigger per tx, with the basic shape filled in
    // from the proto. Contract-specific fields (energy/net usage,
    // contract address, asset amount) are zero / empty unless the
    // caller provides a richer outcome slice — keeping this helper
    // dep-free of the executor.
    for (index, (tx, outcome)) in block.transactions.iter().zip(tx_outcomes.iter()).enumerate() {
        let (contract_type, from_address, to_address) = inspect_first_contract(tx);
        let tx_event = TransactionEvent {
            trigger_name: names::TRANSACTION,
            time_stamp: timestamp_ms,
            transaction_id: hex::encode(outcome.tx_id),
            block_hash: hex::encode(block_id),
            block_number,
            transaction_index: index as i32,
            contract_type,
            contract_result: outcome.contract_result.clone(),
            from_address,
            to_address,
            contract_address: String::new(),
            fee_limit: tx.raw_data.as_ref().map(|r| r.fee_limit).unwrap_or(0),
            energy_usage_total: 0,
            energy_fee: 0,
            net_usage: 0,
            net_fee: 0,
            contract_call_value: 0,
            asset_name: String::new(),
            asset_amount: 0,
            latest_solidified_block_number: latest_solidified,
            data: String::new(),
        };
        bus.emit_transaction(&tx_event);
    }
}

/// Extract `(contract_type_name, owner_address_hex, to_address_hex)`
/// from the first contract in the tx. java-tron's
/// `TransactionLogTriggerCapsule` uses the same "first contract"
/// shortcut — multi-contract txs are unusual on mainnet.
fn inspect_first_contract(tx: &tron_proto::Transaction) -> (String, String, String) {
    let Some(raw) = tx.raw_data.as_ref() else {
        return (String::new(), String::new(), String::new());
    };
    let Some(contract) = raw.contract.first() else {
        return (String::new(), String::new(), String::new());
    };
    let name = ContractType::try_from(contract.r#type)
        .map(|t| format!("{t:?}"))
        .unwrap_or_else(|_| format!("Unknown({})", contract.r#type));
    // Common pattern across most contract types: the first 21-byte
    // field in the `Any.value` is `owner_address`. We can't decode the
    // typed contract without knowing the type, so leave addresses
    // blank — caller can provide richer extraction if needed.
    let _ = contract;
    (name, String::new(), String::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listeners::{ChannelListener, TriggerMessage};
    use crate::EventBus;
    use prost::Message as _;
    use tron_proto::block_header::Raw as HeaderRaw;
    use tron_proto::transaction::{contract::ContractType as Ct, Contract, Raw as TxRaw};
    use tron_proto::{BlockHeader, Transaction, TransferContract};

    #[tokio::test]
    async fn block_with_one_tx_emits_block_then_tx_triggers() {
        let (l, mut rx) = ChannelListener::pair(8);
        let bus = EventBus::builder().add(l).build();

        let tc = TransferContract {
            owner_address: vec![0x41u8; 21],
            to_address: vec![0x42u8; 21],
            amount: 1000,
        };
        let any = prost_types::Any {
            type_url: "type.googleapis.com/protocol.TransferContract".into(),
            value: tc.encode_to_vec(),
        };
        let tx = Transaction {
            raw_data: Some(TxRaw {
                contract: vec![Contract {
                    r#type: Ct::TransferContract as i32,
                    parameter: Some(any),
                    ..Default::default()
                }],
                fee_limit: 100_000,
                ..Default::default()
            }),
            signature: vec![],
            ret: vec![],
        };
        let block = tron_proto::Block {
            block_header: Some(BlockHeader {
                raw_data: Some(HeaderRaw {
                    number: 42,
                    timestamp: 1_700_000_000_000,
                    ..Default::default()
                }),
                witness_signature: Vec::new(),
            }),
            transactions: vec![tx],
        };
        let outcomes = vec![TxOutcomeSlice {
            tx_id: [0xcd; 32],
            contract_result: "SUCCESS".into(),
        }];

        emit_block_and_transactions(&bus, &block, &[0xab; 32], &outcomes, 41);

        let first = rx.recv().await.expect("block trigger");
        match first {
            TriggerMessage::Block(b) => {
                assert_eq!(b.block_number, 42);
                assert_eq!(b.transaction_size, 1);
                assert_eq!(b.latest_solidified_block_number, 41);
            }
            other => panic!("expected Block trigger first, got {other:?}"),
        }
        let second = rx.recv().await.expect("tx trigger");
        match second {
            TriggerMessage::Transaction(t) => {
                assert_eq!(t.block_number, 42);
                assert_eq!(t.transaction_index, 0);
                assert_eq!(t.contract_type, "TransferContract");
                assert_eq!(t.contract_result, "SUCCESS");
                assert_eq!(t.fee_limit, 100_000);
            }
            other => panic!("expected Transaction trigger second, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn empty_bus_skips_work_entirely() {
        let bus = EventBus::default();
        // Pass nonsense block — function must early-return without
        // touching it because the bus has no listeners.
        let block = tron_proto::Block {
            block_header: None,
            transactions: vec![],
        };
        emit_block_and_transactions(&bus, &block, &[0; 32], &[], 0);
    }
}
