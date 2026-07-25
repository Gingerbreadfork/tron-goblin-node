//! `eth_simulateV1` — go-ethereum-style transaction simulation
//! (<https://github.com/ethereum/execution-apis> `eth_simulateV1`).
//!
//! Simulates one or more blocks, each a sequence of calls with optional state +
//! block overrides, and returns per-call results (status, returnData, gasUsed,
//! logs). Unlike `eth_call` (single, stateless), calls here run against ONE
//! session-backed overlay reused across every call and block, so state
//! **accumulates** — call N sees call N-1's writes, and block N+1 sees block N's.
//! The overlay (a [`tron_chainbase::SessionBackend`]) is **never committed**, so
//! this never touches canonical state — it is exactly as side-effect-free as
//! `eth_call`.
//!
//! Supported today: `blockStateCalls[]` with `calls[]`
//! (`from`/`to`/`value`/`data`|`input`/`gas`), `blockOverrides.{number,time}`,
//! and `stateOverrides.<addr>.balance`. Deliberately **rejected** (rather than
//! silently ignored, which would return wrong results): `validation: true`,
//! `traceTransfers: true`, `stateOverrides.{code,state,stateDiff,nonce}` (the
//! TVM v1/v2 storage-key + code-hash schemes are version-dependent — a follow-up
//! will add them correctly), contract-creation calls (`to` omitted), and
//! historical base blocks (need the archive; only `latest`/`pending`).
use crate::methods::{
    build_call_vm_stores, dispatch_constant_trigger, parse_eth_address, parse_hex_bytes,
    parse_hex_quantity, RpcError,
};
use crate::state::RpcState;
use serde_json::{json, Map, Value};
use tron_proto::{Account, TriggerSmartContract};
use tron_tvm::execute::{VmBlockEnv, VmLog, VmOutcome, VmStores};

pub fn eth_simulate_v1(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    // When Chronos is enabled (and the archive is present), route through the
    // fork-simulation engine: this adds a historical base block, full
    // `stateOverrides` (code/state/stateDiff), and contract-creation calls
    // that the legacy path below rejects. With `[sim]` off, behaviour is
    // exactly as before (latest base, balance-only overrides).
    if let Some(sim) = &s.sim {
        if sim.config().enabled && s.archive.is_some() {
            return crate::sim::eth_simulate_v1_via_engine(p, s);
        }
    }

    let Some(b) = &s.eth_call_backends else {
        return Err(RpcError::internal(
            "eth_simulateV1 not available: server built without EVM call backends",
        ));
    };
    let sim = p
        .get(0)
        .and_then(|v| v.as_object())
        .ok_or_else(|| RpcError::invalid_params("missing simulation payload object"))?;

    // Reject unsupported modes loudly so callers never get silently-wrong output.
    if sim.get("validation").and_then(Value::as_bool).unwrap_or(false) {
        return Err(RpcError::invalid_params(
            "eth_simulateV1: `validation: true` is not yet supported",
        ));
    }
    if sim.get("traceTransfers").and_then(Value::as_bool).unwrap_or(false) {
        return Err(RpcError::invalid_params(
            "eth_simulateV1: `traceTransfers: true` is not yet supported",
        ));
    }
    if let Some(tag) = p.get(1).and_then(Value::as_str) {
        if !matches!(tag, "latest" | "pending" | "") {
            return Err(RpcError::invalid_params(
                "eth_simulateV1: only the `latest`/`pending` base block is supported",
            ));
        }
    }

    let block_calls = sim
        .get("blockStateCalls")
        .and_then(Value::as_array)
        .ok_or_else(|| RpcError::invalid_params("missing `blockStateCalls`"))?;

    // One session-backed overlay, reused across all calls/blocks → accumulation;
    // never committed → canonical state untouched.
    let vm_stores = build_call_vm_stores(b);
    let gas_cap = s.eth_call_gas_cap;
    let mut prev_number = s.dyn_props.latest_block_header_number().unwrap_or(0);
    let mut prev_ts_ms = s.dyn_props.latest_block_header_timestamp().unwrap_or(0);

    let mut blocks = Vec::with_capacity(block_calls.len());
    for entry in block_calls {
        let bc = entry
            .as_object()
            .ok_or_else(|| RpcError::invalid_params("each blockStateCalls entry must be an object"))?;

        // Block env: overridden number/time, else +1 block / +3s (TRON block time).
        let ov = bc.get("blockOverrides").and_then(Value::as_object);
        let number = match ov.and_then(|o| o.get("number")).and_then(Value::as_str) {
            Some(q) => parse_hex_quantity(q)? as i64,
            None => prev_number + 1,
        };
        if number <= prev_number {
            return Err(RpcError::invalid_params(
                "eth_simulateV1: block numbers must strictly increase",
            ));
        }
        let ts_ms = match ov.and_then(|o| o.get("time")).and_then(Value::as_str) {
            Some(q) => (parse_hex_quantity(q)? as i64).saturating_mul(1000),
            None => prev_ts_ms + 3000,
        };
        prev_number = number;
        prev_ts_ms = ts_ms;
        let block_env = VmBlockEnv {
            block_number: number,
            block_timestamp_ms: ts_ms, ..Default::default()
        };

        if let Some(overrides) = bc.get("stateOverrides").and_then(Value::as_object) {
            apply_state_overrides(&vm_stores, overrides)?;
        }

        let mut call_results = Vec::new();
        let mut block_gas: u64 = 0;
        let mut log_index: u64 = 0;
        if let Some(calls) = bc.get("calls").and_then(Value::as_array) {
            for call in calls {
                let c = parse_sim_call(call, gas_cap)?;
                let trigger = TriggerSmartContract {
                    owner_address: c.from.to_vec(),
                    contract_address: c.to.to_vec(),
                    call_value: c.value,
                    data: c.data,
                    call_token_value: 0,
                    token_id: 0,
                };
                let (outcome, _penalty) =
                    dispatch_constant_trigger(s, &vm_stores, block_env, &trigger, c.gas);
                let (result, gas_used) = build_call_result(outcome, number, &mut log_index);
                block_gas = block_gas.saturating_add(gas_used);
                call_results.push(result);
            }
        }

        blocks.push(json!({
            "number": format!("0x{number:x}"),
            "timestamp": format!("0x{:x}", ts_ms / 1000),
            "gasLimit": format!("0x{gas_cap:x}"),
            "gasUsed": format!("0x{block_gas:x}"),
            "baseFeePerGas": "0x0",
            "calls": call_results,
        }));
    }

    Ok(json!(blocks))
}

struct SimCall {
    from: [u8; 21],
    to: [u8; 21],
    value: i64,
    data: Vec<u8>,
    gas: u64,
}

fn parse_sim_call(call: &Value, gas_cap: u64) -> Result<SimCall, RpcError> {
    let obj = call
        .as_object()
        .ok_or_else(|| RpcError::invalid_params("each call must be an object"))?;
    let to = match obj.get("to").and_then(Value::as_str) {
        Some(s) => addr21(parse_eth_address(s)?.as_bytes()),
        None => {
            return Err(RpcError::invalid_params(
                "eth_simulateV1: call `to` is required (contract creation is not yet supported)",
            ))
        }
    };
    let from = match obj.get("from").and_then(Value::as_str) {
        Some(s) => addr21(parse_eth_address(s)?.as_bytes()),
        None => {
            let mut b = [0u8; 21];
            b[0] = 0x41;
            b
        }
    };
    let data = match obj
        .get("input")
        .or_else(|| obj.get("data"))
        .and_then(Value::as_str)
    {
        Some(s) => parse_hex_bytes(s)?,
        None => Vec::new(),
    };
    let value = obj
        .get("value")
        .and_then(Value::as_str)
        .map(parse_hex_quantity)
        .transpose()?
        .unwrap_or(0) as i64;
    let default_gas = gas_cap.saturating_sub(1_000_000).min(15_000_000);
    let gas = obj
        .get("gas")
        .and_then(Value::as_str)
        .map(parse_hex_quantity)
        .transpose()?
        .unwrap_or(default_gas)
        .min(gas_cap);
    Ok(SimCall { from, to, value, data, gas })
}

fn addr21(b: &[u8]) -> [u8; 21] {
    let mut a = [0u8; 21];
    a.copy_from_slice(b);
    a
}

/// Apply `stateOverrides` into the session overlay. Only `balance` is supported;
/// other override kinds are rejected upstream of any execution so a partially
/// applied override never yields a silently-wrong simulation.
fn apply_state_overrides(
    vm_stores: &VmStores,
    overrides: &Map<String, Value>,
) -> Result<(), RpcError> {
    for (addr_str, ov) in overrides {
        let ov = ov
            .as_object()
            .ok_or_else(|| RpcError::invalid_params("each state override must be an object"))?;
        for k in ["code", "state", "stateDiff", "nonce", "movePrecompileToAddress"] {
            if ov.contains_key(k) {
                return Err(RpcError::invalid_params(format!(
                    "eth_simulateV1: state override `{k}` is not yet supported (only `balance`)"
                )));
            }
        }
        if let Some(bal) = ov.get("balance").and_then(Value::as_str) {
            let addr = parse_eth_address(addr_str)?;
            let mut account = vm_stores
                .accounts
                .get(&addr)
                .ok()
                .flatten()
                .unwrap_or_else(|| Account {
                    address: addr.as_bytes().to_vec(),
                    ..Default::default()
                });
            account.balance = parse_hex_quantity(bal)? as i64;
            vm_stores
                .accounts
                .put(&addr, &account)
                .map_err(|e| RpcError::internal(format!("apply balance override: {e:?}")))?;
        }
    }
    Ok(())
}

fn build_call_result(outcome: VmOutcome, block_num: i64, log_index: &mut u64) -> (Value, u64) {
    let hexs = |b: &[u8]| format!("0x{}", hex::encode(b));
    match outcome {
        VmOutcome::Success {
            return_data,
            energy_used,
            logs,
        } => (
            json!({
                "status": "0x1",
                "returnData": hexs(&return_data),
                "gasUsed": format!("0x{energy_used:x}"),
                "logs": format_logs(&logs, block_num, log_index),
            }),
            energy_used,
        ),
        VmOutcome::Revert {
            return_data,
            energy_used,
        } => (
            json!({
                "status": "0x0",
                "returnData": hexs(&return_data),
                "gasUsed": format!("0x{energy_used:x}"),
                "logs": [],
                "error": { "code": 3, "message": "execution reverted", "data": hexs(&return_data) },
            }),
            energy_used,
        ),
        VmOutcome::TransferFailed { energy_used } => (
            json!({
                "status": "0x0", "returnData": "0x", "gasUsed": format!("0x{energy_used:x}"),
                "logs": [],
                "error": { "code": 3, "message": "execution reverted: transfer failed" },
            }),
            energy_used,
        ),
        VmOutcome::Halt {
            reason, energy_used, ..
        } => (
            json!({
                "status": "0x0", "returnData": "0x", "gasUsed": format!("0x{energy_used:x}"),
                "logs": [],
                "error": { "code": -32015, "message": format!("execution halted: {reason}") },
            }),
            energy_used,
        ),
        VmOutcome::PreflightError(msg) => (
            json!({
                "status": "0x0", "returnData": "0x", "gasUsed": "0x0", "logs": [],
                "error": { "code": -32000, "message": msg },
            }),
            0,
        ),
        VmOutcome::Timeout { deadline_ms, .. } => (
            json!({
                "status": "0x0", "returnData": "0x", "gasUsed": "0x0", "logs": [],
                "error": { "code": -32000, "message": format!("call timed out after {deadline_ms}ms") },
            }),
            0,
        ),
        VmOutcome::CallTokenIgnored { .. } => (
            json!({
                "status": "0x0", "returnData": "0x", "gasUsed": "0x0", "logs": [],
                "error": { "code": -32000, "message": "top-level CALLTOKEN is not supported in eth_simulateV1" },
            }),
            0,
        ),
    }
}

fn format_logs(logs: &[VmLog], block_num: i64, log_index: &mut u64) -> Value {
    let arr: Vec<Value> = logs
        .iter()
        .map(|l| {
            let li = *log_index;
            *log_index += 1;
            json!({
                "address": format!("0x{}", hex::encode(l.address)),
                "topics": l.topics.iter().map(|t| format!("0x{}", hex::encode(t))).collect::<Vec<_>>(),
                "data": format!("0x{}", hex::encode(&l.data)),
                "blockNumber": format!("0x{block_num:x}"),
                "logIndex": format!("0x{li:x}"),
            })
        })
        .collect();
    json!(arr)
}
