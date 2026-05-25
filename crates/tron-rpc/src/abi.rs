//! Solidity-ABI decoder for contract calls + event logs.
//!
//! Given a `tron_proto::smart_contract::Abi` (loaded from `AbiStore`),
//! decode raw call data into typed parameter values and event topics +
//! data into typed event fields. Powers the typed-decoding paths in
//! `triggerSmartContract`-introspection RPCs and `eth_getLogs`.
//!
//! Built on `alloy_dyn_abi`, which parses Solidity type strings
//! (`uint256`, `address[]`, `tuple(uint256,address)[]`, ...) at runtime
//! — exactly what we need, since the proto's `Param.type` field stores
//! the canonical Solidity type as a string.
//!
//! ## Function call decoding
//!
//! [`decode_function_input`] takes a 4-byte selector + the rest of the
//! calldata, walks every `Function`-typed entry in the ABI computing
//! `keccak256(canonical_signature)[..4]`, and decodes against the
//! matching entry's input list. Returns `[`DecodedCall`]` with the
//! function name + parameter list.
//!
//! ## Event log decoding
//!
//! [`decode_event_log`] takes the log's topics + data, walks every
//! `Event`-typed entry computing `keccak256(canonical_signature)`
//! against `topics[0]` (for non-anonymous events), and decodes:
//! * indexed params → from `topics[1..]` (one 32-byte word each)
//! * non-indexed params → from the data buffer
//!
//! ## Output format
//!
//! [`DecodedValue::to_json`] renders an alloy `DynSolValue` as a
//! `serde_json::Value` with these rules:
//! * `uint` / `int` → decimal string (JavaScript can't represent
//!   > 2^53 safely; java-tron's HTTP API also does this)
//! * `address` → `0x`-prefixed hex of the 20-byte EVM address (no
//!   TRON `T...` prefix — callers wanting the TRON form should
//!   convert via `tron_crypto::base58check::encode_address` against
//!   the 21-byte `0x41 || addr` form)
//! * `bytes` / `bytesN` → `0x`-prefixed hex
//! * `string` → JSON string
//! * `bool` → JSON bool
//! * arrays / tuples → JSON arrays

use alloy_dyn_abi::{DynSolType, DynSolValue};
use serde_json::{json, Value};
use tron_crypto::hash::keccak256;
use tron_proto::smart_contract::abi::entry::EntryType;
use tron_proto::smart_contract::abi::Entry;
use tron_proto::smart_contract::Abi;

/// One decoded parameter of a function call or event log.
#[derive(Debug, Clone)]
pub struct DecodedParam {
    /// Parameter name from the ABI (may be empty for unnamed params).
    pub name: String,
    /// Canonical Solidity type string (`uint256`, `address[]`, etc.).
    pub r#type: String,
    /// Decoded value (alloy's typed representation; convert via
    /// [`decoded_value_to_json`] for serde-friendly output).
    pub value: DynSolValue,
    /// `true` if the param was indexed (events only).
    pub indexed: bool,
}

/// A successfully-decoded function call.
#[derive(Debug, Clone)]
pub struct DecodedCall {
    /// Function name from the ABI.
    pub name: String,
    /// 4-byte selector (`keccak256(canonical_signature)[..4]`).
    pub selector: [u8; 4],
    /// Inputs, in declaration order.
    pub params: Vec<DecodedParam>,
}

/// A successfully-decoded event log.
#[derive(Debug, Clone)]
pub struct DecodedEvent {
    /// Event name from the ABI.
    pub name: String,
    /// `true` when the event entry is marked `anonymous` — topics[0]
    /// is not the signature hash in that case.
    pub anonymous: bool,
    /// All params in declaration order; indexed ones came from topics,
    /// the rest from `data`.
    pub params: Vec<DecodedParam>,
}

/// Errors from [`decode_function_input`] / [`decode_event_log`].
#[derive(Debug, thiserror::Error)]
pub enum AbiError {
    #[error("no matching function entry for selector 0x{0}")]
    NoMatchingFunction(String),
    #[error("no matching event entry for topic0 0x{0}")]
    NoMatchingEvent(String),
    #[error("anonymous-event decoding requires the caller to pass the entry directly")]
    AnonymousEventNeedsEntry,
    #[error("event has {indexed_count} indexed params but only {topic_count} topic(s) after topic0")]
    TopicCountMismatch {
        indexed_count: usize,
        topic_count: usize,
    },
    #[error("failed to parse Solidity type '{ty}': {source}")]
    InvalidType {
        ty: String,
        source: alloy_dyn_abi::Error,
    },
    #[error("ABI decode failed: {0}")]
    Decode(String),
}

/// Compute the canonical Solidity signature for an entry:
/// `name(type1,type2,...)`. Used both as the input to the 4-byte
/// selector (functions) and the 32-byte topic-0 hash (events).
pub fn canonical_signature(entry: &Entry) -> String {
    let mut sig = String::with_capacity(entry.name.len() + 4 + 8 * entry.inputs.len());
    sig.push_str(&entry.name);
    sig.push('(');
    for (i, p) in entry.inputs.iter().enumerate() {
        if i > 0 {
            sig.push(',');
        }
        sig.push_str(&p.r#type);
    }
    sig.push(')');
    sig
}

/// `keccak256(canonical_signature(entry))[..4]` — the 4-byte function
/// selector that prefixes the calldata for a call to this function.
pub fn function_selector(entry: &Entry) -> [u8; 4] {
    let h = keccak256(canonical_signature(entry).as_bytes());
    let mut sel = [0u8; 4];
    sel.copy_from_slice(&h[..4]);
    sel
}

/// `keccak256(canonical_signature(entry))` — the 32-byte event topic0
/// hash for a non-anonymous event.
pub fn event_topic0(entry: &Entry) -> [u8; 32] {
    keccak256(canonical_signature(entry).as_bytes())
}

/// Decode a function call's calldata against `abi`.
///
/// `data` is the full calldata including the 4-byte selector prefix.
/// Returns `NoMatchingFunction` if no entry in the ABI matches.
pub fn decode_function_input(abi: &Abi, data: &[u8]) -> Result<DecodedCall, AbiError> {
    if data.len() < 4 {
        return Err(AbiError::Decode(format!(
            "calldata too short ({} bytes) — needs at least 4 for the selector",
            data.len()
        )));
    }
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&data[..4]);
    let body = &data[4..];

    for entry in &abi.entrys {
        if entry.r#type != EntryType::Function as i32 {
            continue;
        }
        if function_selector(entry) != selector {
            continue;
        }
        let params = decode_param_list(&entry.inputs, body, &[], false)?;
        return Ok(DecodedCall {
            name: entry.name.clone(),
            selector,
            params,
        });
    }
    Err(AbiError::NoMatchingFunction(hex::encode(selector)))
}

/// Decode an event log against `abi`.
///
/// `topics` is the full topic list as logged. For non-anonymous events
/// (the common case), `topics[0]` MUST be the event signature hash;
/// remaining topics are the indexed params in declaration order.
/// `data` is the ABI-encoded non-indexed params.
pub fn decode_event_log(
    abi: &Abi,
    topics: &[[u8; 32]],
    data: &[u8],
) -> Result<DecodedEvent, AbiError> {
    if topics.is_empty() {
        return Err(AbiError::AnonymousEventNeedsEntry);
    }
    for entry in &abi.entrys {
        if entry.r#type != EntryType::Event as i32 {
            continue;
        }
        if entry.anonymous {
            // Anonymous events have no signature topic — caller must
            // pre-select the entry; we skip them in the auto-match
            // path because every anonymous event would otherwise
            // shadow the next non-anonymous one with the same shape.
            continue;
        }
        if event_topic0(entry) != topics[0] {
            continue;
        }
        let indexed_topics: Vec<&[u8; 32]> = topics[1..].iter().collect();
        let params = decode_param_list(&entry.inputs, data, &indexed_topics, true)?;
        return Ok(DecodedEvent {
            name: entry.name.clone(),
            anonymous: false,
            params,
        });
    }
    Err(AbiError::NoMatchingEvent(hex::encode(topics[0])))
}

/// Decode the non-indexed slice of params from `data` and (if `event`)
/// the indexed ones from `indexed_topics`. For functions, set `event =
/// false` and `indexed_topics = &[]`.
///
/// java-tron's HTTP and gRPC paths both treat indexed params as one
/// 32-byte word per topic, regardless of the underlying Solidity type's
/// dynamic-ness — for dynamic types (string, bytes, arrays) the topic
/// is keccak256 of the value (a hash, not the data). We expose those
/// as `FixedBytes(32)` because we have no way to recover the original
/// value from a hash.
fn decode_param_list(
    params: &[tron_proto::smart_contract::abi::entry::Param],
    data: &[u8],
    indexed_topics: &[&[u8; 32]],
    event: bool,
) -> Result<Vec<DecodedParam>, AbiError> {
    // Separate indexed vs non-indexed for events.
    let mut indexed_indices = Vec::new();
    let mut nonindexed_types = Vec::new();
    let mut nonindexed_indices = Vec::new();
    for (i, p) in params.iter().enumerate() {
        if event && p.indexed {
            indexed_indices.push(i);
        } else {
            let ty = parse_sol_type(&p.r#type)?;
            nonindexed_types.push(ty);
            nonindexed_indices.push(i);
        }
    }

    if event && indexed_indices.len() != indexed_topics.len() {
        return Err(AbiError::TopicCountMismatch {
            indexed_count: indexed_indices.len(),
            topic_count: indexed_topics.len(),
        });
    }

    // Decode the non-indexed buffer as a tuple of the corresponding
    // types — that's the canonical calldata-arg layout per Solidity
    // ABI spec.
    let decoded_nonindexed = if nonindexed_types.is_empty() {
        Vec::new()
    } else {
        let tuple_ty = DynSolType::Tuple(nonindexed_types);
        match tuple_ty.abi_decode_params(data) {
            Ok(DynSolValue::Tuple(values)) => values,
            Ok(other) => {
                return Err(AbiError::Decode(format!(
                    "expected Tuple result, got {other:?}"
                )))
            }
            Err(e) => return Err(AbiError::Decode(format!("{e}"))),
        }
    };

    // Splice indexed + non-indexed back into original declaration
    // order.
    let mut out: Vec<Option<DecodedParam>> = (0..params.len()).map(|_| None).collect();
    for (slot, original_idx) in nonindexed_indices.iter().enumerate() {
        let p = &params[*original_idx];
        out[*original_idx] = Some(DecodedParam {
            name: p.name.clone(),
            r#type: p.r#type.clone(),
            value: decoded_nonindexed[slot].clone(),
            indexed: false,
        });
    }
    for (slot, original_idx) in indexed_indices.iter().enumerate() {
        let p = &params[*original_idx];
        let topic = indexed_topics[slot];
        let value = decode_indexed_topic(&p.r#type, topic)?;
        out[*original_idx] = Some(DecodedParam {
            name: p.name.clone(),
            r#type: p.r#type.clone(),
            value,
            indexed: true,
        });
    }

    Ok(out.into_iter().map(|o| o.expect("every slot filled")).collect())
}

fn parse_sol_type(s: &str) -> Result<DynSolType, AbiError> {
    DynSolType::parse(s).map_err(|e| AbiError::InvalidType {
        ty: s.to_string(),
        source: e,
    })
}

/// Decode an indexed event topic. Static types fit in the 32-byte
/// topic word directly; dynamic types (string, bytes, T[]) get hashed
/// before being placed in the topic, so we surface those as a
/// `FixedBytes(32)` hash.
fn decode_indexed_topic(ty: &str, topic: &[u8; 32]) -> Result<DynSolValue, AbiError> {
    let sol_ty = parse_sol_type(ty)?;
    // Dynamic types: the topic IS the hash, no further decoding
    // possible. Return as a 32-byte FixedBytes.
    if is_dynamic_type(&sol_ty) {
        return Ok(DynSolValue::FixedBytes(
            alloy_primitives::FixedBytes::from(*topic),
            32,
        ));
    }
    // Static types: decode as a single ABI value (left-padded to 32
    // bytes in the standard encoding, which matches how indexed
    // topics are written).
    sol_ty
        .abi_decode(topic)
        .map_err(|e| AbiError::Decode(format!("topic decode for type '{ty}': {e}")))
}

fn is_dynamic_type(ty: &DynSolType) -> bool {
    use DynSolType::*;
    matches!(ty, Bytes | String | Array(_)) || {
        if let Tuple(types) = ty {
            types.iter().any(is_dynamic_type)
        } else if let FixedArray(inner, _) = ty {
            is_dynamic_type(inner)
        } else {
            false
        }
    }
}

/// Render a [`DynSolValue`] as a serde JSON value using the rules
/// described in the module docs.
pub fn decoded_value_to_json(v: &DynSolValue) -> Value {
    match v {
        DynSolValue::Bool(b) => json!(*b),
        DynSolValue::Int(i, _bits) => json!(i.to_string()),
        DynSolValue::Uint(u, _bits) => json!(u.to_string()),
        DynSolValue::FixedBytes(b, n) => {
            json!(format!("0x{}", hex::encode(&b.as_slice()[..*n])))
        }
        DynSolValue::Address(a) => json!(format!("0x{}", hex::encode(a.as_slice()))),
        DynSolValue::Function(f) => json!(format!("0x{}", hex::encode(f.as_slice()))),
        DynSolValue::Bytes(b) => json!(format!("0x{}", hex::encode(b))),
        DynSolValue::String(s) => json!(s),
        DynSolValue::Array(items)
        | DynSolValue::FixedArray(items)
        | DynSolValue::Tuple(items) => {
            json!(items.iter().map(decoded_value_to_json).collect::<Vec<_>>())
        }
    }
}

/// Convenience: render a full [`DecodedCall`] as JSON suitable for
/// embedding in an RPC response.
pub fn decoded_call_to_json(call: &DecodedCall) -> Value {
    json!({
        "name": call.name,
        "selector": format!("0x{}", hex::encode(call.selector)),
        "params": call
            .params
            .iter()
            .map(|p| json!({
                "name": p.name,
                "type": p.r#type,
                "value": decoded_value_to_json(&p.value),
            }))
            .collect::<Vec<_>>(),
    })
}

/// Convenience: render a full [`DecodedEvent`] as JSON.
pub fn decoded_event_to_json(ev: &DecodedEvent) -> Value {
    json!({
        "name": ev.name,
        "anonymous": ev.anonymous,
        "params": ev
            .params
            .iter()
            .map(|p| json!({
                "name": p.name,
                "type": p.r#type,
                "indexed": p.indexed,
                "value": decoded_value_to_json(&p.value),
            }))
            .collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tron_proto::smart_contract::abi::entry::Param;

    fn func(name: &str, inputs: &[(&str, &str)]) -> Entry {
        Entry {
            r#type: EntryType::Function as i32,
            name: name.to_string(),
            inputs: inputs
                .iter()
                .map(|(n, t)| Param {
                    indexed: false,
                    name: n.to_string(),
                    r#type: t.to_string(),
                })
                .collect(),
            outputs: vec![],
            ..Default::default()
        }
    }

    fn event(name: &str, params: &[(&str, &str, bool)]) -> Entry {
        Entry {
            r#type: EntryType::Event as i32,
            name: name.to_string(),
            inputs: params
                .iter()
                .map(|(n, t, indexed)| Param {
                    indexed: *indexed,
                    name: n.to_string(),
                    r#type: t.to_string(),
                })
                .collect(),
            outputs: vec![],
            ..Default::default()
        }
    }

    #[test]
    fn canonical_signature_matches_solidity_examples() {
        // ERC-20 `transfer(address,uint256)` → 0xa9059cbb selector.
        let entry = func("transfer", &[("to", "address"), ("amount", "uint256")]);
        assert_eq!(canonical_signature(&entry), "transfer(address,uint256)");
        assert_eq!(hex::encode(function_selector(&entry)), "a9059cbb");
    }

    #[test]
    fn canonical_signature_for_tuple_and_array_types() {
        let entry = func(
            "swap",
            &[
                ("path", "address[]"),
                ("amounts", "uint256[2]"),
                ("data", "(bytes32,bool)"),
            ],
        );
        assert_eq!(
            canonical_signature(&entry),
            "swap(address[],uint256[2],(bytes32,bool))"
        );
    }

    #[test]
    fn decode_erc20_transfer_call() {
        // ERC-20 transfer(address recipient, uint256 amount).
        // Calldata = selector || pad32(recipient) || pad32(amount).
        let abi = Abi {
            entrys: vec![func("transfer", &[("to", "address"), ("amount", "uint256")])],
        };

        let recipient: [u8; 20] = [0x11; 20];
        let amount = 1_000_000_000u64; // 1 token at 9 decimals

        let mut calldata = Vec::new();
        calldata.extend_from_slice(&hex::decode("a9059cbb").unwrap());
        // pad32(recipient): 12 zero bytes + 20-byte addr.
        calldata.extend_from_slice(&[0u8; 12]);
        calldata.extend_from_slice(&recipient);
        // pad32(amount): 32-byte BE.
        let mut amt_bytes = [0u8; 32];
        amt_bytes[24..].copy_from_slice(&amount.to_be_bytes());
        calldata.extend_from_slice(&amt_bytes);

        let call = decode_function_input(&abi, &calldata).expect("decode");
        assert_eq!(call.name, "transfer");
        assert_eq!(call.selector, hex::decode("a9059cbb").unwrap().as_slice());
        assert_eq!(call.params.len(), 2);
        assert_eq!(call.params[0].name, "to");
        assert_eq!(call.params[0].r#type, "address");
        assert!(matches!(call.params[0].value, DynSolValue::Address(_)));
        if let DynSolValue::Address(a) = call.params[0].value {
            assert_eq!(a.as_slice(), &recipient);
        }
        assert!(matches!(call.params[1].value, DynSolValue::Uint(_, 256)));
        if let DynSolValue::Uint(u, _) = &call.params[1].value {
            assert_eq!(u.to_string(), amount.to_string());
        }
    }

    #[test]
    fn decode_unknown_selector_returns_error() {
        let abi = Abi {
            entrys: vec![func("transfer", &[("to", "address"), ("amount", "uint256")])],
        };
        // Bogus selector + empty body.
        let calldata = vec![0xde, 0xad, 0xbe, 0xef];
        let err = decode_function_input(&abi, &calldata).unwrap_err();
        assert!(matches!(err, AbiError::NoMatchingFunction(_)));
    }

    #[test]
    fn decode_calldata_too_short_returns_error() {
        let abi = Abi { entrys: vec![] };
        let err = decode_function_input(&abi, &[1, 2, 3]).unwrap_err();
        assert!(matches!(err, AbiError::Decode(_)));
    }

    #[test]
    fn decode_zero_arg_function() {
        let abi = Abi {
            entrys: vec![func("getX", &[])],
        };
        let selector = function_selector(&abi.entrys[0]);
        let calldata = selector.to_vec();
        let call = decode_function_input(&abi, &calldata).expect("decode");
        assert_eq!(call.name, "getX");
        assert_eq!(call.params.len(), 0);
    }

    #[test]
    fn decode_erc20_transfer_event() {
        // event Transfer(address indexed from, address indexed to, uint256 value)
        let abi = Abi {
            entrys: vec![event(
                "Transfer",
                &[
                    ("from", "address", true),
                    ("to", "address", true),
                    ("value", "uint256", false),
                ],
            )],
        };
        let topic0 = event_topic0(&abi.entrys[0]);
        // The canonical Transfer topic0 is well-known:
        assert_eq!(
            hex::encode(topic0),
            "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        );

        let from_addr = [0x22u8; 20];
        let to_addr = [0x33u8; 20];
        let value = 42_000u64;

        // topics[0] = sig, topics[1] = pad32(from), topics[2] = pad32(to)
        let mut topic_from = [0u8; 32];
        topic_from[12..].copy_from_slice(&from_addr);
        let mut topic_to = [0u8; 32];
        topic_to[12..].copy_from_slice(&to_addr);
        let topics = vec![topic0, topic_from, topic_to];

        let mut data = [0u8; 32];
        data[24..].copy_from_slice(&value.to_be_bytes());

        let ev = decode_event_log(&abi, &topics, &data).expect("decode");
        assert_eq!(ev.name, "Transfer");
        assert_eq!(ev.params.len(), 3);
        // Order preserved (from, to, value).
        assert_eq!(ev.params[0].name, "from");
        assert!(ev.params[0].indexed);
        if let DynSolValue::Address(a) = &ev.params[0].value {
            assert_eq!(a.as_slice(), &from_addr);
        } else {
            panic!("expected Address");
        }
        assert_eq!(ev.params[1].name, "to");
        assert!(ev.params[1].indexed);
        assert_eq!(ev.params[2].name, "value");
        assert!(!ev.params[2].indexed);
        if let DynSolValue::Uint(u, _) = &ev.params[2].value {
            assert_eq!(u.to_string(), value.to_string());
        } else {
            panic!("expected Uint");
        }
    }

    #[test]
    fn dynamic_indexed_param_surfaces_as_topic_hash() {
        // event Hashed(string indexed s) — the topic for `s` is
        // keccak256(s), not the string itself. Decoded value should be
        // FixedBytes(32) of the topic.
        let abi = Abi {
            entrys: vec![event("Hashed", &[("s", "string", true)])],
        };
        let topic0 = event_topic0(&abi.entrys[0]);
        let s_hash = keccak256(b"hello");
        let topics = vec![topic0, s_hash];
        let ev = decode_event_log(&abi, &topics, &[]).expect("decode");
        if let DynSolValue::FixedBytes(b, 32) = &ev.params[0].value {
            assert_eq!(b.as_slice(), &s_hash);
        } else {
            panic!("expected FixedBytes(32) for dynamic indexed param, got {:?}", ev.params[0].value);
        }
    }

    #[test]
    fn anonymous_event_is_skipped_by_topic_match() {
        // Anonymous events don't have a signature topic, so the
        // auto-match path can't find them — confirm it returns
        // NoMatchingEvent rather than silently misattributing.
        let mut anon_event = event("Secret", &[("x", "uint256", false)]);
        anon_event.anonymous = true;
        let abi = Abi { entrys: vec![anon_event] };
        // Even if we pass a topic0 that happens to match the
        // theoretical signature hash, the entry should be skipped
        // because it's flagged anonymous.
        let entry = &abi.entrys[0];
        let topic0 = event_topic0(entry);
        let mut data = [0u8; 32];
        data[31] = 7;
        let err = decode_event_log(&abi, &[topic0], &data).unwrap_err();
        assert!(matches!(err, AbiError::NoMatchingEvent(_)));
    }

    #[test]
    fn event_topic_count_mismatch_is_reported() {
        // Event expects 1 indexed; topic count is 0 (after topic0).
        let abi = Abi {
            entrys: vec![event(
                "OneIndexed",
                &[("x", "uint256", true), ("y", "uint256", false)],
            )],
        };
        let topic0 = event_topic0(&abi.entrys[0]);
        let mut data = [0u8; 32];
        data[31] = 5;
        // Missing the indexed `x` topic.
        let err = decode_event_log(&abi, &[topic0], &data).unwrap_err();
        assert!(matches!(
            err,
            AbiError::TopicCountMismatch {
                indexed_count: 1,
                topic_count: 0
            }
        ));
    }

    #[test]
    fn json_render_for_uint_is_decimal_string() {
        let v = DynSolValue::Uint(alloy_primitives::U256::from(123456789u64), 256);
        let j = decoded_value_to_json(&v);
        assert_eq!(j.as_str(), Some("123456789"));
    }

    #[test]
    fn json_render_for_address_is_0x_hex() {
        let a = alloy_primitives::Address::from([0xab; 20]);
        let v = DynSolValue::Address(a);
        let j = decoded_value_to_json(&v);
        assert_eq!(
            j.as_str(),
            Some(&*format!("0x{}", "ab".repeat(20))),
        );
    }

    #[test]
    fn json_render_for_array_is_json_array() {
        let v = DynSolValue::Array(vec![
            DynSolValue::Uint(alloy_primitives::U256::from(1u64), 256),
            DynSolValue::Uint(alloy_primitives::U256::from(2u64), 256),
        ]);
        let j = decoded_value_to_json(&v);
        let arr = j.as_array().expect("array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0].as_str(), Some("1"));
        assert_eq!(arr[1].as_str(), Some("2"));
    }
}
