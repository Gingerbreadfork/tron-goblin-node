//! Trigger event types — wire-compatible with java-tron's
//! `org.tron.common.logsfilter.trigger.*` JSON shapes.
//!
//! Field naming: Rust uses snake_case internally but the serde-JSON
//! output uses java-tron's camelCase via per-field `rename`. This means
//! a TronGrid analytics worker that today reads java-tron's Kafka
//! topic can read ours without code changes.

use serde::{Deserialize, Serialize};

/// Trigger-name discriminator strings — copied verbatim from java-tron's
/// `Trigger.java` so JSON consumers can route by name.
pub mod names {
    pub const BLOCK: &str = "blockTrigger";
    pub const TRANSACTION: &str = "transactionTrigger";
    pub const CONTRACT_LOG: &str = "contractLogTrigger";
    pub const CONTRACT_EVENT: &str = "contractEventTrigger";
    pub const SOLIDITY: &str = "solidityTrigger";
    pub const SOLIDITY_LOG: &str = "solidityLogTrigger";
    pub const SOLIDITY_EVENT: &str = "solidityEventTrigger";
}

/// Per-block trigger fired right after a block applies to state.
///
/// Mirrors `BlockLogTrigger.java`. The `transaction_list` field carries
/// the tx_ids (lowercase hex, no `0x`) in the order they appear in the
/// block, matching java-tron's serialization.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BlockEvent {
    #[serde(rename = "triggerName")]
    pub trigger_name: &'static str,
    #[serde(rename = "timeStamp")]
    pub time_stamp: i64,
    #[serde(rename = "blockNumber")]
    pub block_number: i64,
    #[serde(rename = "blockHash")]
    pub block_hash: String,
    #[serde(rename = "transactionSize")]
    pub transaction_size: i64,
    #[serde(rename = "latestSolidifiedBlockNumber")]
    pub latest_solidified_block_number: i64,
    #[serde(rename = "transactionList")]
    pub transaction_list: Vec<String>,
}

impl BlockEvent {
    pub fn new(
        block_number: i64,
        block_hash: &[u8],
        timestamp_ms: i64,
        latest_solidified: i64,
        tx_ids: Vec<[u8; 32]>,
    ) -> Self {
        Self {
            trigger_name: names::BLOCK,
            time_stamp: timestamp_ms,
            block_number,
            block_hash: hex::encode(block_hash),
            transaction_size: tx_ids.len() as i64,
            latest_solidified_block_number: latest_solidified,
            transaction_list: tx_ids.iter().map(hex::encode).collect(),
        }
    }
}

/// Per-transaction trigger fired after the tx has been applied.
///
/// Mirrors `TransactionLogTrigger.java`. Fields that are non-applicable
/// to a given contract type are zero / empty (matches java-tron, which
/// uses primitive defaults).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TransactionEvent {
    #[serde(rename = "triggerName")]
    pub trigger_name: &'static str,
    #[serde(rename = "timeStamp")]
    pub time_stamp: i64,
    #[serde(rename = "transactionId")]
    pub transaction_id: String,
    #[serde(rename = "blockHash")]
    pub block_hash: String,
    #[serde(rename = "blockNumber")]
    pub block_number: i64,
    #[serde(rename = "transactionIndex")]
    pub transaction_index: i32,
    #[serde(rename = "contractType")]
    pub contract_type: String,
    /// java-tron `TransactionLogTrigger.result` — the transaction's
    /// `contractRet` as an uppercase enum string (`"SUCCESS"`,
    /// `"REVERT"`, `"OUT_OF_TIME"`, ...). Distinct from
    /// [`Self::contract_result`].
    #[serde(rename = "result")]
    pub result: String,
    /// java-tron `TransactionLogTrigger.contractResult` — the lowercase
    /// hex of the VM's return data (`ProgramResult.getHReturn()`), NOT
    /// the `contractRet` string. Empty for non-VM transactions and when
    /// the VM produced no return value.
    #[serde(rename = "contractResult")]
    pub contract_result: String,
    #[serde(rename = "fromAddress")]
    pub from_address: String,
    #[serde(rename = "toAddress")]
    pub to_address: String,
    #[serde(rename = "contractAddress")]
    pub contract_address: String,
    #[serde(rename = "feeLimit")]
    pub fee_limit: i64,
    /// java-tron `TransactionLogTrigger.energyUsage` — energy covered by
    /// the caller's frozen quota (`ResourceReceipt.energyUsage`).
    #[serde(rename = "energyUsage")]
    pub energy_usage: i64,
    /// java-tron `TransactionLogTrigger.originEnergyUsage` — energy
    /// covered by the contract origin's quota.
    #[serde(rename = "originEnergyUsage")]
    pub origin_energy_usage: i64,
    #[serde(rename = "energyUsageTotal")]
    pub energy_usage_total: i64,
    #[serde(rename = "energyFee")]
    pub energy_fee: i64,
    #[serde(rename = "netUsage")]
    pub net_usage: i64,
    #[serde(rename = "netFee")]
    pub net_fee: i64,
    #[serde(rename = "contractCallValue")]
    pub contract_call_value: i64,
    #[serde(rename = "assetName")]
    pub asset_name: String,
    #[serde(rename = "assetAmount")]
    pub asset_amount: i64,
    #[serde(rename = "latestSolidifiedBlockNumber")]
    pub latest_solidified_block_number: i64,
    #[serde(rename = "data")]
    pub data: String,
}

/// Per-LOG trigger fired for every smart-contract `LOG*` opcode whose
/// topic-0 didn't match an event in the contract's ABI (i.e. we
/// couldn't decode it — the consumer gets the raw topics + data).
///
/// Mirrors `ContractLogTrigger.java`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContractLogEvent {
    #[serde(rename = "triggerName")]
    pub trigger_name: &'static str,
    #[serde(rename = "timeStamp")]
    pub time_stamp: i64,
    #[serde(rename = "blockNumber")]
    pub block_number: i64,
    #[serde(rename = "blockHash")]
    pub block_hash: String,
    #[serde(rename = "transactionId")]
    pub transaction_id: String,
    #[serde(rename = "contractAddress")]
    pub contract_address: String,
    #[serde(rename = "originAddress")]
    pub origin_address: String,
    #[serde(rename = "callerAddress")]
    pub caller_address: String,
    #[serde(rename = "creatorAddress")]
    pub creator_address: String,
    #[serde(rename = "topicList")]
    pub topic_list: Vec<String>,
    #[serde(rename = "data")]
    pub data: String,
    #[serde(rename = "uniqueId")]
    pub unique_id: String,
    #[serde(rename = "removed")]
    pub removed: bool,
    #[serde(rename = "latestSolidifiedBlockNumber")]
    pub latest_solidified_block_number: i64,
}

/// Per-event trigger fired when a `LOG*` opcode's topic-0 matched a
/// known event in the contract's ABI — the consumer gets the decoded
/// event name + named args.
///
/// Mirrors `ContractEventTrigger.java`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContractEvent {
    #[serde(rename = "triggerName")]
    pub trigger_name: &'static str,
    #[serde(rename = "timeStamp")]
    pub time_stamp: i64,
    #[serde(rename = "blockNumber")]
    pub block_number: i64,
    #[serde(rename = "blockHash")]
    pub block_hash: String,
    #[serde(rename = "transactionId")]
    pub transaction_id: String,
    #[serde(rename = "contractAddress")]
    pub contract_address: String,
    #[serde(rename = "originAddress")]
    pub origin_address: String,
    #[serde(rename = "callerAddress")]
    pub caller_address: String,
    #[serde(rename = "creatorAddress")]
    pub creator_address: String,
    #[serde(rename = "eventName")]
    pub event_name: String,
    #[serde(rename = "eventSignature")]
    pub event_signature: String,
    #[serde(rename = "eventSignatureFull")]
    pub event_signature_full: String,
    /// Decoded topic params: ABI-indexed-name → hex value.
    #[serde(rename = "topicMap")]
    pub topic_map: std::collections::BTreeMap<String, String>,
    /// Decoded data params: ABI-non-indexed-name → string value.
    #[serde(rename = "dataMap")]
    pub data_map: std::collections::BTreeMap<String, String>,
    #[serde(rename = "uniqueId")]
    pub unique_id: String,
    #[serde(rename = "removed")]
    pub removed: bool,
    #[serde(rename = "latestSolidifiedBlockNumber")]
    pub latest_solidified_block_number: i64,
}

/// Solidity-block trigger — fired when a block crosses the solidified
/// threshold (PBFT 2/3 + commit). Mirrors `SolidityTrigger.java`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SolidifiedBlockEvent {
    #[serde(rename = "triggerName")]
    pub trigger_name: &'static str,
    #[serde(rename = "timeStamp")]
    pub time_stamp: i64,
    #[serde(rename = "latestSolidifiedBlockNumber")]
    pub latest_solidified_block_number: i64,
}

impl SolidifiedBlockEvent {
    pub fn new(latest_solidified: i64, timestamp_ms: i64) -> Self {
        Self {
            trigger_name: names::SOLIDITY,
            time_stamp: timestamp_ms,
            latest_solidified_block_number: latest_solidified,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_event_json_matches_java_tron_camelcase() {
        let ev = BlockEvent::new(42, &[0xab; 32], 1_700_000_000_000, 41, vec![[0xcd; 32]]);
        let j = serde_json::to_value(&ev).unwrap();
        assert_eq!(j["triggerName"], "blockTrigger");
        assert_eq!(j["blockNumber"], 42);
        assert_eq!(j["transactionSize"], 1);
        assert_eq!(j["latestSolidifiedBlockNumber"], 41);
        assert_eq!(j["blockHash"].as_str().unwrap().len(), 64);
        assert_eq!(j["transactionList"][0].as_str().unwrap().len(), 64);
    }

    #[test]
    fn solidified_block_event_round_trips() {
        let ev = SolidifiedBlockEvent::new(99, 1_700_000_000_000);
        let s = serde_json::to_string(&ev).unwrap();
        assert!(s.contains("\"solidityTrigger\""));
        assert!(s.contains("\"latestSolidifiedBlockNumber\":99"));
    }
}
