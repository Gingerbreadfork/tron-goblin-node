//! Decode raw VM log entries into either an ABI-decoded
//! [`ContractEvent`] or a raw [`ContractLogEvent`] based on whether
//! the contract's ABI has a matching event entry for `topic[0]`.
//!
//! Sits between the executor (which produces raw `(address, topics,
//! data)` log records) and the eventer crate (which wants typed
//! triggers). The ABI lookup is a closure so the caller wires it
//! against whatever ABI cache the runtime exposes (likely the
//! `AbiStore`).

use std::collections::BTreeMap;

use tron_eventer::{ContractEvent, ContractLogEvent};
use tron_proto::smart_contract::Abi;
use tron_rpc::abi::{decode_event_log, decoded_value_to_json, AbiError, DecodedParam};

/// Outcome of an ABI-decode attempt.
#[derive(Debug, Clone)]
pub enum DecodedLog {
    /// Topic0 matched a known event entry; payload is the decoded
    /// trigger with `topic_map` + `data_map` populated.
    Event(ContractEvent),
    /// No matching ABI entry — wire the raw topics + data and let the
    /// consumer ABI-decode on their end if they wish.
    Log(ContractLogEvent),
}

/// Inputs the decoder needs that aren't part of the raw log itself —
/// the surrounding tx context the trigger structs expect.
#[derive(Debug, Clone, Default)]
pub struct EventLogContext {
    pub time_stamp: i64,
    pub block_number: i64,
    pub block_hash_hex: String,
    pub transaction_id_hex: String,
    pub contract_address_hex: String,
    pub origin_address_hex: String,
    pub caller_address_hex: String,
    pub creator_address_hex: String,
    pub unique_id: String,
    pub removed: bool,
    pub latest_solidified_block_number: i64,
}

/// Decode one VM log entry.
///
/// * `abi_lookup(contract_addr_bytes) -> Option<&Abi>` resolves the
///   contract's ABI. Return `None` when the runtime hasn't indexed
///   the contract yet — the caller is downgraded to
///   [`DecodedLog::Log`].
/// * `topics` are the LOG opcode's topics (max 4). `topics[0]` is the
///   event signature hash for non-anonymous events.
/// * `data` is the LOG opcode's data slice.
///
/// `topics` of length 0 → always [`DecodedLog::Log`] (no signature to
/// look up).
pub fn decode_one_log<F>(
    ctx: &EventLogContext,
    contract_addr_bytes: &[u8],
    topics: &[[u8; 32]],
    data: &[u8],
    abi_lookup: F,
) -> DecodedLog
where
    F: FnOnce(&[u8]) -> Option<Abi>,
{
    // No topic0 → cannot do an ABI lookup; fall back to raw log.
    if topics.is_empty() {
        return DecodedLog::Log(make_log_event(ctx, topics, data));
    }
    let Some(abi) = abi_lookup(contract_addr_bytes) else {
        return DecodedLog::Log(make_log_event(ctx, topics, data));
    };
    match decode_event_log(&abi, topics, data) {
        Ok(decoded) => {
            let event_name = decoded.name.clone();
            let (topic_map, data_map) = split_params(&decoded.params);
            DecodedLog::Event(ContractEvent {
                trigger_name: tron_eventer::trigger::names::CONTRACT_EVENT,
                time_stamp: ctx.time_stamp,
                block_number: ctx.block_number,
                block_hash: ctx.block_hash_hex.clone(),
                transaction_id: ctx.transaction_id_hex.clone(),
                contract_address: ctx.contract_address_hex.clone(),
                origin_address: ctx.origin_address_hex.clone(),
                caller_address: ctx.caller_address_hex.clone(),
                creator_address: ctx.creator_address_hex.clone(),
                event_name,
                event_signature: hex::encode(topics[0]),
                event_signature_full: decoded
                    .params
                    .iter()
                    .map(|p| p.r#type.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
                topic_map,
                data_map,
                unique_id: ctx.unique_id.clone(),
                removed: ctx.removed,
                latest_solidified_block_number: ctx.latest_solidified_block_number,
            })
        }
        Err(AbiError::NoMatchingEvent(_))
        | Err(AbiError::AnonymousEventNeedsEntry)
        | Err(AbiError::TopicCountMismatch { .. }) => {
            // Any decode failure → fall back to raw log. This matches
            // java-tron: a malformed/unrecognised event still produces
            // a `ContractLogTrigger`.
            DecodedLog::Log(make_log_event(ctx, topics, data))
        }
        Err(_) => DecodedLog::Log(make_log_event(ctx, topics, data)),
    }
}

fn make_log_event(ctx: &EventLogContext, topics: &[[u8; 32]], data: &[u8]) -> ContractLogEvent {
    ContractLogEvent {
        trigger_name: tron_eventer::trigger::names::CONTRACT_LOG,
        time_stamp: ctx.time_stamp,
        block_number: ctx.block_number,
        block_hash: ctx.block_hash_hex.clone(),
        transaction_id: ctx.transaction_id_hex.clone(),
        contract_address: ctx.contract_address_hex.clone(),
        origin_address: ctx.origin_address_hex.clone(),
        caller_address: ctx.caller_address_hex.clone(),
        creator_address: ctx.creator_address_hex.clone(),
        topic_list: topics.iter().map(hex::encode).collect(),
        data: hex::encode(data),
        unique_id: ctx.unique_id.clone(),
        removed: ctx.removed,
        latest_solidified_block_number: ctx.latest_solidified_block_number,
    }
}

/// Split a decoded param vector into the two maps `ContractEvent`
/// expects:
///
/// * `topic_map` — every `indexed` param keyed by name (or empty
///   placeholder when the ABI entry has no name).
/// * `data_map` — every non-indexed param.
///
/// Values are stringified via [`decoded_value_to_json`] →
/// `to_string()` to keep the schema field type narrow (java-tron
/// stores stringified values everywhere too).
fn split_params(
    params: &[DecodedParam],
) -> (BTreeMap<String, String>, BTreeMap<String, String>) {
    let mut topic_map = BTreeMap::new();
    let mut data_map = BTreeMap::new();
    for (i, p) in params.iter().enumerate() {
        let key = if p.name.is_empty() {
            format!("arg{i}")
        } else {
            p.name.clone()
        };
        let value = decoded_value_to_json(&p.value).to_string();
        if p.indexed {
            topic_map.insert(key, value);
        } else {
            data_map.insert(key, value);
        }
    }
    (topic_map, data_map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;
    use tron_proto::smart_contract::abi::entry::{EntryType, Param};
    use tron_proto::smart_contract::abi::Entry;
    use tron_rpc::abi::event_topic0;

    fn erc20_transfer_abi() -> Abi {
        Abi {
            entrys: vec![Entry {
                anonymous: false,
                constant: false,
                name: "Transfer".into(),
                inputs: vec![
                    Param {
                        indexed: true,
                        name: "from".into(),
                        r#type: "address".into(),
                    },
                    Param {
                        indexed: true,
                        name: "to".into(),
                        r#type: "address".into(),
                    },
                    Param {
                        indexed: false,
                        name: "value".into(),
                        r#type: "uint256".into(),
                    },
                ],
                outputs: vec![],
                r#type: EntryType::Event as i32,
                payable: false,
                state_mutability: 0,
            }],
        }
    }

    fn padded_addr(byte: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[12..].fill(byte); // last 20 bytes is the eth-addr space
        out
    }

    fn padded_u256(v: u64) -> Vec<u8> {
        let mut out = vec![0u8; 32];
        out[24..].copy_from_slice(&v.to_be_bytes());
        out
    }

    #[test]
    fn empty_topics_fall_back_to_log_event() {
        let ctx = EventLogContext::default();
        let result = decode_one_log(&ctx, &[0x41; 21], &[], &[1, 2, 3], |_| {
            Some(erc20_transfer_abi())
        });
        assert!(matches!(result, DecodedLog::Log(_)));
    }

    #[test]
    fn missing_abi_falls_back_to_log_event() {
        let ctx = EventLogContext::default();
        let topics = vec![padded_addr(0xab)];
        let result = decode_one_log(&ctx, &[0x41; 21], &topics, &[], |_| None);
        assert!(matches!(result, DecodedLog::Log(_)));
    }

    #[test]
    fn matching_event_decodes_to_contract_event() {
        let abi = erc20_transfer_abi();
        let topic0 = event_topic0(&abi.entrys[0]);
        let topics = vec![topic0, padded_addr(0x11), padded_addr(0x22)];
        let data = padded_u256(1000);
        let ctx = EventLogContext {
            time_stamp: 1_700_000_000_000,
            block_number: 42,
            transaction_id_hex: "deadbeef".repeat(8),
            ..Default::default()
        };
        let result = decode_one_log(&ctx, &[0x41; 21], &topics, &data, |_| Some(abi.clone()));
        match result {
            DecodedLog::Event(ev) => {
                assert_eq!(ev.event_name, "Transfer");
                assert_eq!(ev.event_signature, hex::encode(topic0));
                assert!(ev.event_signature_full.contains("address"));
                assert!(ev.event_signature_full.contains("uint256"));
                assert_eq!(ev.topic_map.len(), 2);
                assert!(ev.topic_map.contains_key("from"));
                assert!(ev.topic_map.contains_key("to"));
                assert_eq!(ev.data_map.len(), 1);
                assert!(ev.data_map.contains_key("value"));
            }
            DecodedLog::Log(_) => panic!("expected ContractEvent, got Log"),
        }
    }

    #[test]
    fn unrelated_topic0_falls_back_to_log_event() {
        let abi = erc20_transfer_abi();
        let topics = vec![[0xff; 32]]; // not the Transfer topic0
        let result = decode_one_log(&EventLogContext::default(), &[0x41; 21], &topics, &[], |_| {
            Some(abi.clone())
        });
        assert!(matches!(result, DecodedLog::Log(_)));
    }

    #[test]
    fn malformed_data_falls_back_to_log_event() {
        let abi = erc20_transfer_abi();
        let topic0 = event_topic0(&abi.entrys[0]);
        // topics[1] / topics[2] padded addresses are valid, but data
        // is empty when uint256 is required.
        let topics = vec![topic0, padded_addr(0x11), padded_addr(0x22)];
        let result = decode_one_log(&EventLogContext::default(), &[0x41; 21], &topics, &[], |_| {
            Some(abi.clone())
        });
        assert!(matches!(result, DecodedLog::Log(_)));
    }

    #[test]
    fn anonymous_event_falls_back_to_log_event() {
        let mut abi = erc20_transfer_abi();
        abi.entrys[0].anonymous = true;
        // Need topic0 just to enter the lookup path.
        let topics = vec![[0xaa; 32]];
        let result = decode_one_log(&EventLogContext::default(), &[0x41; 21], &topics, &[], |_| {
            Some(abi.clone())
        });
        assert!(matches!(result, DecodedLog::Log(_)));
    }

    #[test]
    fn proto_roundtrip_does_not_break_decoder() {
        // Sanity: ensures Abi survives encode/decode + the decoder
        // still finds the entry.
        let abi = erc20_transfer_abi();
        let bytes = abi.encode_to_vec();
        let abi2 = Abi::decode(bytes.as_slice()).unwrap();
        let topic0 = event_topic0(&abi2.entrys[0]);
        let topics = vec![topic0, padded_addr(0x11), padded_addr(0x22)];
        let data = padded_u256(1);
        let result = decode_one_log(&EventLogContext::default(), &[0x41; 21], &topics, &data, |_| {
            Some(abi2.clone())
        });
        assert!(matches!(result, DecodedLog::Event(_)));
    }
}
