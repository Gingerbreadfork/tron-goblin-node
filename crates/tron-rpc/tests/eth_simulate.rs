//! Integration tests for `eth_simulateV1`: state accumulation across calls and
//! blocks, balance override, revert reporting, and the rejected (not-yet-
//! supported) modes.
use std::sync::Arc;

use serde_json::json;
use tron_chainbase::{AccountStore, CodeStore, KvBackend, MemBackend};
use tron_crypto::address::Address;
use tron_proto::Account;
use tron_rpc::eth_simulate::eth_simulate_v1;
use tron_rpc::{EthCallBackends, RpcState};
use tron_tvm::database::code_hash;

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn tron_addr(b: u8) -> [u8; 21] {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(b);
    a
}

fn hex_addr(a: [u8; 21]) -> String {
    hex::encode(a)
}

fn empty_evm_state() -> RpcState {
    let backends = EthCallBackends {
        accounts: mem(),
        code: mem(),
        storage: mem(),
        witnesses: mem(),
        contract_state: mem(),
        dyn_props: mem(),
        delegated_resources: mem(),
        delegation: mem(),
        contracts: mem(),
        block_index: Some(mem()),
    };
    RpcState::new(mem(), mem(), mem(), mem(), mem(), 11_111)
        .with_support_constant(true)
        .with_eth_call_backends(backends)
}

/// State with `bytecode` installed at `contract` and a funded `caller`.
fn state_with_contract(contract: [u8; 21], bytecode: Vec<u8>, caller: [u8; 21]) -> RpcState {
    let accounts = mem();
    let code = mem();
    let hash = code_hash(&bytecode).as_slice().to_vec();
    CodeStore::new(code.clone()).put(&hash, &bytecode).unwrap();
    let acct = AccountStore::new(accounts.clone());
    acct.put(
        &Address::from_raw(contract),
        &Account {
            address: contract.to_vec(),
            code: bytecode.clone(),
            code_hash: hash,
            ..Default::default()
        },
    )
    .unwrap();
    acct.put(
        &Address::from_raw(caller),
        &Account {
            address: caller.to_vec(),
            balance: 1_000_000_000,
            ..Default::default()
        },
    )
    .unwrap();
    let backends = EthCallBackends {
        accounts,
        code,
        storage: mem(),
        witnesses: mem(),
        contract_state: mem(),
        dyn_props: mem(),
        delegated_resources: mem(),
        delegation: mem(),
        contracts: mem(),
        block_index: Some(mem()),
    };
    RpcState::new(mem(), mem(), mem(), mem(), mem(), 11_111)
        .with_support_constant(true)
        .with_eth_call_backends(backends)
}

/// `val = SLOAD(0); SSTORE(0, val+1); return val` (32-byte word).
const COUNTER: &[u8] = &[
    0x60, 0x00, 0x54, // PUSH1 0; SLOAD          -> [val]
    0x80, // DUP1                                 -> [val, val]
    0x60, 0x01, 0x01, // PUSH1 1; ADD             -> [val, val+1]
    0x60, 0x00, 0x55, // PUSH1 0; SSTORE          -> [val]   (slot0 := val+1)
    0x60, 0x00, 0x52, // PUSH1 0; MSTORE          -> []      (mem0 := val)
    0x60, 0x20, 0x60, 0x00, 0xf3, // PUSH1 0x20; PUSH1 0; RETURN
];

fn ret_u64(call: &serde_json::Value) -> u64 {
    let rd = call["returnData"].as_str().unwrap();
    let h = rd.trim_start_matches("0x");
    u64::from_str_radix(&h[h.len() - 16..], 16).unwrap()
}

#[test]
fn accumulates_within_and_across_blocks() {
    let contract = tron_addr(0x22);
    let caller = tron_addr(0x11);
    let s = state_with_contract(contract, COUNTER.to_vec(), caller);
    let call = json!({ "from": hex_addr(caller), "to": hex_addr(contract), "data": "0x" });
    let p = json!([{
        "blockStateCalls": [
            { "calls": [call, call] }, // block 1
            { "calls": [call, call] }, // block 2
        ]
    }]);
    let r = eth_simulate_v1(&p, &s).expect("simulate ok");
    assert_eq!(r[0]["calls"][0]["status"], "0x1");
    // Global counter 0,1 (block 1) then 2,3 (block 2): proves the overlay
    // accumulates across calls AND across blocks (never resetting per call).
    assert_eq!(ret_u64(&r[0]["calls"][0]), 0, "block0/call0");
    assert_eq!(ret_u64(&r[0]["calls"][1]), 1, "block0/call1 (within-block accumulation)");
    assert_eq!(ret_u64(&r[1]["calls"][0]), 2, "block1/call0 (cross-block accumulation)");
    assert_eq!(ret_u64(&r[1]["calls"][1]), 3, "block1/call1");
    assert_eq!(r.as_array().unwrap().len(), 2, "two block results");
}

#[test]
fn applies_balance_override() {
    // ADDRESS; BALANCE; return it (Frontier opcodes, no hardfork gating).
    let bytecode = vec![0x30, 0x31, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];
    let contract = tron_addr(0x33);
    let caller = tron_addr(0x11);
    let s = state_with_contract(contract, bytecode, caller);
    let p = json!([{
        "blockStateCalls": [{
            "stateOverrides": { hex_addr(contract): { "balance": "0x7b" } }, // 123
            "calls": [{ "from": hex_addr(caller), "to": hex_addr(contract), "data": "0x" }],
        }]
    }]);
    let r = eth_simulate_v1(&p, &s).expect("simulate ok");
    assert_eq!(r[0]["calls"][0]["status"], "0x1");
    assert_eq!(ret_u64(&r[0]["calls"][0]), 123, "SELFBALANCE must reflect the balance override");
}

#[test]
fn revert_reports_status_0_and_error() {
    // PUSH1 0; PUSH1 0; REVERT.
    let bytecode = vec![0x60, 0x00, 0x60, 0x00, 0xfd];
    let contract = tron_addr(0x44);
    let caller = tron_addr(0x11);
    let s = state_with_contract(contract, bytecode, caller);
    let p = json!([{
        "blockStateCalls": [{
            "calls": [{ "from": hex_addr(caller), "to": hex_addr(contract), "data": "0x" }]
        }]
    }]);
    let r = eth_simulate_v1(&p, &s).expect("simulate ok");
    assert_eq!(r[0]["calls"][0]["status"], "0x0");
    assert!(
        r[0]["calls"][0]["error"].is_object(),
        "a reverted call must carry an error object"
    );
}

#[test]
fn rejects_unsupported_modes() {
    let s = empty_evm_state();
    let cases = [
        (json!([{ "blockStateCalls": [], "validation": true }]), "validation"),
        (json!([{ "blockStateCalls": [], "traceTransfers": true }]), "traceTransfers"),
        (
            json!([{ "blockStateCalls": [{ "stateOverrides": { hex_addr(tron_addr(0x55)): { "code": "0x00" } } }] }]),
            "code",
        ),
        (
            json!([{ "blockStateCalls": [{ "calls": [{ "from": hex_addr(tron_addr(0x11)) }] }] }]),
            "to",
        ),
    ];
    for (p, needle) in cases {
        let err = eth_simulate_v1(&p, &s).unwrap_err();
        assert!(
            err.message.contains(needle),
            "expected `{needle}` in error; got: {}",
            err.message
        );
    }
}

#[test]
fn eth_estimate_gas_revert_returns_code_3_with_data() {
    // A contract that always reverts (PUSH1 0; PUSH1 0; REVERT). eth_estimateGas
    // on a reverting call must return the eth-standard revert error (code 3 with
    // the return data in `data`), like eth_call — not a generic -32603 internal.
    let bytecode = vec![0x60, 0x00, 0x60, 0x00, 0xfd];
    let contract = tron_addr(0x44);
    let caller = tron_addr(0x11);
    let s = state_with_contract(contract, bytecode, caller);
    let p = json!([{ "from": hex_addr(caller), "to": hex_addr(contract), "data": "0x" }]);
    let err = tron_rpc::methods::eth_estimate_gas(&p, &s).unwrap_err();
    assert_eq!(err.code, 3, "revert -> eth standard code 3, not -32603 internal");
    assert_eq!(err.data.as_deref(), Some("0x"), "revert return data surfaced in `data`");
}
