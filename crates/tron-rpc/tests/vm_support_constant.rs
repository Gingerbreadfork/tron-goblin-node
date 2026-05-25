//! Test the `vm.supportConstant` gate at the
//! `triggerConstantContract` RPC.
//!
//! When the flag is off (default), the method returns an "invalid
//! request" error matching java-tron's `CONTRACT_VALIDATE_ERROR`
//! shape. When on, it falls through to `eth_call` normally.

use std::sync::Arc;
use tron_chainbase::{KvBackend, MemBackend};
use tron_rpc::{methods, RpcState};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn fresh_state(support_constant: bool) -> RpcState {
    RpcState::new(mem(), mem(), mem(), mem(), mem(), 11_111)
        .with_support_constant(support_constant)
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
