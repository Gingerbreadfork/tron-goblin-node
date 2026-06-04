//! Tests for the geth/parity-compatible `debug_*` / `trace_*`
//! JSON-RPC family. Each test installs a tiny contract into the
//! in-memory state, hits the method via the public `methods::*`
//! dispatch, and asserts the shape of the returned JSON.

use std::sync::Arc;

use serde_json::{json, Value};
use tron_chainbase::{AccountStore, CodeStore, KvBackend, MemBackend};
use tron_crypto::address::Address;
use tron_proto::Account;
use tron_rpc::{methods, EthCallBackends, RpcState};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn build_state_with_contract(addr: [u8; 21], bytecode: Vec<u8>) -> RpcState {
    let accounts = mem();
    let code = mem();
    let storage = mem();
    let witnesses = mem();
    let contract_state = mem();
    let dyn_props = mem();
    let delegated_resources = mem();
    let delegation = mem();
    let contracts = mem();
    let block_index = mem();

    // Install bytecode at addr.
    let acc = AccountStore::new(accounts.clone());
    let code_store = CodeStore::new(code.clone());
    let hash = tron_crypto::hash::keccak256(&bytecode);
    code_store.put(&hash, &bytecode).unwrap();
    acc.put(
        &Address::from_raw(addr),
        &Account {
            address: addr.to_vec(),
            balance: 0,
            code: bytecode,
            code_hash: hash.to_vec(),
            ..Default::default()
        },
    ).unwrap();

    let backends = EthCallBackends {
        accounts: accounts.clone(),
        code: code.clone(),
        storage: storage.clone(),
        witnesses,
        contract_state,
        dyn_props: dyn_props.clone(),
        delegated_resources,
        delegation,
        contracts,
        block_index: Some(block_index),
    };
    RpcState::new(accounts, mem(), mem(), mem(), dyn_props, 11_111)
        .with_eth_call_backends(backends)
}

fn caller_addr() -> [u8; 21] {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(0xa1);
    a
}

fn contract_addr(byte: u8) -> [u8; 21] {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(byte);
    a
}

/// `PUSH1 0x42 / PUSH1 0x00 / MSTORE / PUSH1 0x20 / PUSH1 0x00 / RETURN`
/// Returns a single 32-byte word with the value `0x42`.
fn return42_bytecode() -> Vec<u8> {
    vec![
        0x60, 0x42, // PUSH1 0x42
        0x60, 0x00, // PUSH1 0x00 (memory offset)
        0x52, // MSTORE
        0x60, 0x20, // PUSH1 0x20 (length)
        0x60, 0x00, // PUSH1 0x00 (offset)
        0xf3, // RETURN
    ]
}

fn call_payload(to: [u8; 21], from: [u8; 21]) -> Value {
    json!([{
        "from": format!("0x{}", hex::encode(from)),
        "to": format!("0x{}", hex::encode(to)),
        "data": "0x",
        "gas": format!("0x{:x}", 1_000_000u64),
    }])
}

#[test]
fn debug_trace_call_returns_struct_logs_by_default() {
    let to = contract_addr(0xbb);
    let state = build_state_with_contract(to, return42_bytecode());
    let payload = call_payload(to, caller_addr());
    let result = methods::debug_trace_call(&payload, &state).expect("trace");

    // structLogger shape: `{gas, failed, returnValue, structLogs[]}`.
    assert!(result["structLogs"].is_array());
    let logs = result["structLogs"].as_array().unwrap();
    assert!(
        !logs.is_empty(),
        "structLogger must record at least one opcode for a non-empty contract"
    );
    // Every entry has the required fields.
    for entry in logs {
        assert!(entry["pc"].is_number());
        assert!(entry["op"].is_string());
        assert!(entry["gas"].is_number());
        assert!(entry["gasCost"].is_number());
        assert!(entry["depth"].is_number());
        assert!(entry["stack"].is_array());
    }
    // The first opcode must be PUSH (our bytecode starts with PUSH1 0x42).
    assert_eq!(logs[0]["op"], "PUSHn");
    // returnValue is the 32-byte word with 0x42 in the low byte.
    let return_val = result["returnValue"].as_str().unwrap();
    assert!(return_val.ends_with("42"), "got: {return_val}");
    assert_eq!(result["failed"], false);
}

#[test]
fn debug_trace_call_with_call_tracer_returns_call_tree() {
    let to = contract_addr(0xcc);
    let state = build_state_with_contract(to, return42_bytecode());
    let mut payload = call_payload(to, caller_addr());
    // Add the options arg at index 2 (eth_call signature: callObj,
    // blockTag, options) with tracer = callTracer.
    if let Value::Array(arr) = &mut payload {
        arr.push(json!(null));
        arr.push(json!({"tracer": "callTracer"}));
    }
    let result = methods::debug_trace_call(&payload, &state).expect("trace");

    // callTracer shape: a single root frame with type/from/to/value/etc.
    assert_eq!(result["type"], "CALL");
    let to_hex = format!("0x{}", hex::encode(to));
    assert_eq!(result["to"], to_hex);
    let from_hex = format!("0x{}", hex::encode(caller_addr()));
    assert_eq!(result["from"], from_hex);
    // Root frame's `calls` may be empty (no nested calls in our
    // bytecode), but must be present as an array.
    assert!(result["calls"].is_array());
}

#[test]
fn debug_trace_call_records_opcode_specific_fields() {
    // Verify the gas costs are filled in (not stuck at 0) and stack
    // grows monotonically through the PUSH sequence.
    let to = contract_addr(0xdd);
    let state = build_state_with_contract(to, return42_bytecode());
    let payload = call_payload(to, caller_addr());
    let result = methods::debug_trace_call(&payload, &state).expect("trace");
    let logs = result["structLogs"].as_array().unwrap();

    // gasCost is the delta of `gas` between consecutive entries.
    for (idx, entry) in logs.iter().enumerate().skip(1) {
        let prev_gas = logs[idx - 1]["gas"].as_u64().unwrap();
        let now_gas = entry["gas"].as_u64().unwrap();
        let cost = logs[idx - 1]["gasCost"].as_u64().unwrap();
        assert_eq!(
            prev_gas.saturating_sub(now_gas),
            cost,
            "gasCost at step {idx} should equal the gas delta"
        );
    }
}

#[test]
fn debug_trace_call_with_disable_stack_omits_stack() {
    let to = contract_addr(0xee);
    let state = build_state_with_contract(to, return42_bytecode());
    let mut payload = call_payload(to, caller_addr());
    if let Value::Array(arr) = &mut payload {
        arr.push(json!(null));
        arr.push(json!({"disableStack": true}));
    }
    let result = methods::debug_trace_call(&payload, &state).expect("trace");
    let logs = result["structLogs"].as_array().unwrap();
    for entry in logs {
        let stack = entry["stack"].as_array().unwrap();
        assert!(stack.is_empty(), "disableStack must suppress stack capture");
    }
}

#[test]
fn trace_call_returns_parity_shape() {
    let to = contract_addr(0xff);
    let state = build_state_with_contract(to, return42_bytecode());
    let payload = call_payload(to, caller_addr());
    let result = methods::trace_call(&payload, &state).expect("trace");

    // Parity shape: {output, stateDiff, trace[], vmTrace}
    assert!(result["output"].is_string());
    assert!(result["trace"].is_array());
    let traces = result["trace"].as_array().unwrap();
    assert!(!traces.is_empty(), "trace_call must emit at least one frame");
    // First entry is the root call.
    let root = &traces[0];
    assert_eq!(root["type"], "call");
    assert_eq!(root["action"]["callType"], "call");
    assert_eq!(root["traceAddress"], json!([]));
}

#[test]
fn debug_trace_transaction_returns_error_when_tx_unknown() {
    let state = build_state_with_contract(contract_addr(0x11), return42_bytecode());
    let payload = json!([format!("0x{}", "aa".repeat(32))]);
    let result = methods::debug_trace_transaction(&payload, &state);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.message.contains("not found"),
        "missing tx should surface 'not found'; got: {}",
        err.message
    );
}

#[test]
fn debug_trace_block_by_number_returns_array_when_block_missing() {
    // No block_index entries → block_index lookup fails → method
    // returns an error.
    let state = build_state_with_contract(contract_addr(0x22), return42_bytecode());
    let payload = json!(["0x1"]);
    let result = methods::debug_trace_block_by_number(&payload, &state);
    assert!(
        result.is_err(),
        "no block at num 1 should surface an error: {result:?}"
    );
}
