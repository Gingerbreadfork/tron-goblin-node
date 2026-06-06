//! Test the `vm.supportConstant` gate at the
//! `triggerConstantContract` RPC.
//!
//! When the flag is off (default), the method returns an "invalid
//! request" error matching java-tron's `CONTRACT_VALIDATE_ERROR`
//! shape. When on, it falls through to `eth_call` normally.

use std::sync::Arc;
use tron_chainbase::{KvBackend, MemBackend};
use tron_rpc::{methods, EthCallBackends, RpcState};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn fresh_state(support_constant: bool) -> RpcState {
    RpcState::new(mem(), mem(), mem(), mem(), mem(), 11_111)
        .with_support_constant(support_constant)
}

fn fresh_state_with_evm(support_constant: bool) -> RpcState {
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
        .with_support_constant(support_constant)
        .with_eth_call_backends(backends)
}

#[test]
fn trigger_constant_contract_blocked_by_default() {
    let s = fresh_state(false);
    // Object-form: matches the `eth_call` shape exactly.
    let p = serde_json::json!([{
        "from": "411111111111111111111111111111111111111111",
        "to": "412222222222222222222222222222222222222222",
        "data": "0x",
    }]);
    let err = methods::trigger_constant_contract(&p, &s).unwrap_err();
    assert_eq!(err.code, -32600, "InvalidRequest = -32600");
    assert!(
        err.message.contains("triggerConstantContract is disabled"),
        "should explain the gate; got: {}",
        err.message
    );
}

#[test]
fn trigger_constant_contract_passes_through_when_supported() {
    // With flag on, the request is forwarded to eth_call. Against an
    // empty store the eth_call returns success with empty data. We
    // just need to confirm we DIDN'T get the gating error.
    let s = fresh_state(true);
    let p = serde_json::json!([{
        "from": "411111111111111111111111111111111111111111",
        "to": "412222222222222222222222222222222222222222",
        "data": "0x",
    }]);
    let result = methods::trigger_constant_contract(&p, &s);
    // The eth_call inner may succeed (against empty state) or fail
    // with a non-gating error. The key check is: NOT -32600.
    match result {
        Ok(_) => {}
        Err(e) => assert_ne!(e.code, -32600, "must not be gated when flag is on"),
    }
}

#[test]
fn positional_form_also_gated_by_support_constant() {
    let s = fresh_state(false);
    // Positional form: [owner, contract, data].
    let p = serde_json::json!([
        "411111111111111111111111111111111111111111",
        "412222222222222222222222222222222222222222",
        "0x",
    ]);
    let err = methods::trigger_constant_contract(&p, &s).unwrap_err();
    assert_eq!(err.code, -32600);
}

#[test]
fn tron_native_body_shape_returns_java_response_shape() {
    // java-tron's native /wallet/triggerconstantcontract body uses
    // `contract_address` + `function_selector` (not eth_call's `to`/`data`).
    // Our endpoint must accept it and reply in java-tron's response shape
    // (constant_result array + result.result + energy_used) so a state-diff
    // harness can compare TVM execution between the two nodes.
    let s = fresh_state_with_evm(true);
    // Addresses arrive here already 0x-normalized by the REST layer
    // (translate_addresses_to_hex); this test calls the method directly.
    let p = serde_json::json!([{
        "owner_address": "0x411111111111111111111111111111111111111111",
        "contract_address": "0x412222222222222222222222222222222222222222",
        "function_selector": "decimals()",
    }]);
    let v = methods::trigger_constant_contract(&p, &s)
        .expect("java-tron native body must be accepted");
    assert!(
        v.get("constant_result").and_then(|x| x.as_array()).is_some(),
        "must return a constant_result array; got {v}"
    );
    assert_eq!(
        v["result"]["result"],
        serde_json::json!(true),
        "a call to a no-code address succeeds with empty data; got {v}"
    );
    assert!(
        v.get("energy_used").is_some(),
        "must report energy_used for TVM-exactness diffing; got {v}"
    );
}
