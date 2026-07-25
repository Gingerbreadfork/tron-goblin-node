//! Chronos JSON-RPC surface: `tron_simulateBundle` (native, full-power) and
//! the `tron_fork*` named-session family, plus the shared JSON <-> engine
//! translation. The engine itself lives in `tron-sim`; this module only
//! parses requests, builds the fork overlay from the archive's live
//! backends, runs the bundle, and formats the result.
//!
//! Availability is gated on `[sim] enabled` (the `RpcState.sim` registry)
//! AND the historical archive (`RpcState.archive`) — historical forks read
//! at-height state, and even latest-base forks pull their raw backends
//! (including `votes`/`abi`) from the archive's live set.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{json, Map, Value};
use tron_crypto::address::Address;
use tron_sim::{
    fork_id_from_hex, fork_id_hex, AccountOverride, BaseBlock, BlockOverride, BlockSpec, CallResult,
    CallSpec, CallStatus, DecodedStateDiff, DiffLevel, ForkOverlay, ForkSession, OverrideSet,
    SimError, SimRequest, SimResult, SimState, TraceLevel,
};

use crate::methods::{parse_eth_address, parse_hex_bytes, RpcError};
use crate::state::RpcState;

// ---------------------------------------------------------------------------
// REST surface — POST /v1/sim/bundle (the tron_simulateBundle payload as the
// request body). JSON-RPC is the primary surface; this is a convenience.
// ---------------------------------------------------------------------------

/// Router for the Chronos REST endpoint. Merged into the HTTP REST app.
pub fn sim_router() -> axum::Router<RpcState> {
    axum::Router::new().route("/v1/sim/bundle", axum::routing::post(rest_sim_bundle))
}

async fn rest_sim_bundle(
    axum::extract::State(state): axum::extract::State<RpcState>,
    axum::Json(body): axum::Json<Value>,
) -> (axum::http::StatusCode, axum::Json<Value>) {
    use axum::http::StatusCode;
    match tron_simulate_bundle(&json!([body]), &state) {
        Ok(v) => (StatusCode::OK, axum::Json(json!({ "success": true, "data": v }))),
        Err(e) => {
            let code = if e.code == -32602 {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (code, axum::Json(json!({ "success": false, "error": e.message })))
        }
    }
}

// ---------------------------------------------------------------------------
// Method entry points
// ---------------------------------------------------------------------------

/// `tron_simulateBundle` — run a one-shot (ephemeral) bundle and return the
/// full result. See the module docs for the payload shape.
pub fn tron_simulate_bundle(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let sim = require_sim(s)?;
    let body = obj_param(p, 0, "simulation payload")?;
    let base = parse_base(body)?;
    let req = parse_bundle(body, sim)?;

    let mut overlay = build_overlay(s, base)?;
    let mut result = tron_sim::run_bundle(&mut overlay, &req, sim.config(), [0u8; 16], None)
        .map_err(sim_to_rpc)?;
    result.basis.archive_coverage = s.archive.as_ref().and_then(|a| a.coverage());
    Ok(format_sim_result(&result))
}

/// `tron_forkCreate [{ base, overrides? }]` → fork handle.
pub fn tron_fork_create(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let sim = require_sim(s)?;
    let body = p.get(0).and_then(Value::as_object);
    let base = match body {
        Some(b) => parse_base(b)?,
        None => BaseBlock::Latest,
    };
    let overlay = build_overlay(s, base)?;
    if let Some(ovr) = body.and_then(|b| b.get("overrides")) {
        let oset = parse_override_set(ovr)?;
        oset.apply(&overlay.vm_stores(), sim.config().max_state_override_slots)
            .map_err(sim_to_rpc)?;
    }
    let (seed_num, seed_ts) = overlay.seed_head();
    let coverage = s.archive.as_ref().and_then(|a| a.coverage());
    let id = sim.create(overlay);
    Ok(json!({
        "forkId": fork_id_hex(&id),
        "seedBlock": seed_num,
        "seedTimestampMs": seed_ts,
        "coverage": coverage_json(coverage),
        "ttlSecs": sim.config().fork_ttl_secs,
    }))
}

/// `tron_forkCall [forkId, { blocks | calls, trace?, returnStateDiff? }]`.
pub fn tron_fork_call(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let sim = require_sim(s)?;
    let id = fork_id_param(p, 0)?;
    let body = obj_param(p, 1, "fork-call payload")?;
    let req = parse_bundle(body, sim)?;
    let session = sim
        .get(&id)
        .ok_or_else(|| RpcError::invalid_params("unknown or expired forkId"))?;
    let mut result = with_fork(&session, |f| f.run(&req, sim.config())).map_err(sim_to_rpc)?;
    result.basis.archive_coverage = s.archive.as_ref().and_then(|a| a.coverage());
    Ok(format_sim_result(&result))
}

/// `tron_forkSnapshot [forkId]` → `{ snapshotId }`.
pub fn tron_fork_snapshot(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let sim = require_sim(s)?;
    let id = fork_id_param(p, 0)?;
    let session = sim
        .get(&id)
        .ok_or_else(|| RpcError::invalid_params("unknown or expired forkId"))?;
    let snap = with_fork(&session, |f| Ok(f.snapshot())).map_err(sim_to_rpc)?;
    Ok(json!({ "snapshotId": snap }))
}

/// `tron_forkRevert [forkId, snapshotId]` → `{ reverted: true }`.
pub fn tron_fork_revert(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let sim = require_sim(s)?;
    let id = fork_id_param(p, 0)?;
    let snap = p
        .get(1)
        .and_then(Value::as_u64)
        .ok_or_else(|| RpcError::invalid_params("snapshotId (u64) required"))?;
    let session = sim
        .get(&id)
        .ok_or_else(|| RpcError::invalid_params("unknown or expired forkId"))?;
    with_fork(&session, |f| f.revert(snap)).map_err(sim_to_rpc)?;
    Ok(json!({ "reverted": true }))
}

/// `tron_forkStateDiff [forkId]` → cumulative decoded diff.
pub fn tron_fork_state_diff(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let sim = require_sim(s)?;
    let id = fork_id_param(p, 0)?;
    let session = sim
        .get(&id)
        .ok_or_else(|| RpcError::invalid_params("unknown or expired forkId"))?;
    let diff = with_fork(&session, |f| f.state_diff()).map_err(sim_to_rpc)?;
    Ok(format_diff(&diff))
}

/// `tron_forkDelete [forkId]` → `{ deleted: bool }`.
pub fn tron_fork_delete(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let sim = require_sim(s)?;
    let id = fork_id_param(p, 0)?;
    Ok(json!({ "deleted": sim.delete(&id) }))
}

/// `tron_forkList []` → live fork metadata.
pub fn tron_fork_list(_p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let sim = require_sim(s)?;
    let forks: Vec<Value> = sim
        .list()
        .into_iter()
        .map(|f| {
            json!({
                "forkId": fork_id_hex(&f.fork_id),
                "overlayKeys": f.overlay_keys,
                "ageSecs": f.created.elapsed().as_secs(),
                "idleSecs": f.last_used.elapsed().as_secs(),
            })
        })
        .collect();
    Ok(json!(forks))
}

// ---------------------------------------------------------------------------
// eth_simulateV1 (geth shape) routed through the Chronos engine — adds the
// historical base, full state overrides (code/state/stateDiff), and creation
// calls that the standalone eth_simulate path rejects. Used only when [sim] is
// enabled and the archive is present; otherwise the caller keeps the legacy
// latest-only path (backward compatible).
// ---------------------------------------------------------------------------

pub fn eth_simulate_v1_via_engine(p: &Value, s: &RpcState) -> Result<Value, RpcError> {
    let sim = require_sim(s)?;
    let payload = obj_param(p, 0, "simulation payload")?;

    // Base: param[1] is a hex height or latest/pending tag.
    let base = match p.get(1).and_then(Value::as_str) {
        None | Some("latest") | Some("pending") | Some("") => BaseBlock::Latest,
        Some(tag) => BaseBlock::Height(parse_i64_flex(&json!(tag), "block tag")?),
    };

    if payload.get("validation").and_then(Value::as_bool).unwrap_or(false)
        || payload.get("traceTransfers").and_then(Value::as_bool).unwrap_or(false)
    {
        return Err(RpcError::invalid_params(
            "eth_simulateV1: validation / traceTransfers are not supported",
        ));
    }

    let bsc = payload
        .get("blockStateCalls")
        .and_then(Value::as_array)
        .ok_or_else(|| RpcError::invalid_params("missing `blockStateCalls`"))?;
    let mut blocks = Vec::with_capacity(bsc.len());
    for (i, entry) in bsc.iter().enumerate() {
        let e = entry
            .as_object()
            .ok_or_else(|| RpcError::invalid_params(format!("blockStateCalls[{i}] must be an object")))?;
        blocks.push(parse_geth_block(e)?);
    }

    let req = SimRequest {
        blocks,
        trace: TraceLevel::None,
        return_state_diff: DiffLevel::None,
        self_check: false,
        energy_cap: None,
    };
    let mut overlay = build_overlay(s, base)?;
    let result = tron_sim::run_bundle(&mut overlay, &req, sim.config(), [0u8; 16], None)
        .map_err(sim_to_rpc)?;
    Ok(format_geth_result(&result, sim.config().energy_cap))
}

fn parse_geth_block(e: &Map<String, Value>) -> Result<BlockSpec, RpcError> {
    let mut overrides = OverrideSet::default();
    if let Some(so) = e.get("stateOverrides").and_then(Value::as_object) {
        for (addr, ov) in so {
            overrides.accounts.insert(parse_eth_address(addr)?, parse_account_override(ov)?);
        }
    }
    if let Some(bo) = e.get("blockOverrides").and_then(Value::as_object) {
        let number = match bo.get("number") {
            Some(v) if !v.is_null() => Some(parse_i64_flex(v, "number")?),
            _ => None,
        };
        let time_s = match bo.get("time").or_else(|| bo.get("timestamp")) {
            Some(v) if !v.is_null() => Some(parse_i64_flex(v, "time")?),
            _ => None,
        };
        overrides.block = Some(BlockOverride { number, time_s, coinbase: None });
    }
    let mut calls = Vec::new();
    if let Some(arr) = e.get("calls").and_then(Value::as_array) {
        for (i, c) in arr.iter().enumerate() {
            calls.push(parse_geth_call(c).map_err(|err| {
                RpcError::invalid_params(format!("calls[{i}]: {}", err.message))
            })?);
        }
    }
    Ok(BlockSpec { overrides, calls })
}

fn parse_geth_call(c: &Value) -> Result<CallSpec, RpcError> {
    let o = c.as_object().ok_or_else(|| RpcError::invalid_params("call must be an object"))?;
    let from = match o.get("from").and_then(Value::as_str) {
        Some(s) => parse_eth_address(s)?,
        None => Address::from_raw({
            let mut a = [0u8; 21];
            a[0] = 0x41;
            a
        }),
    };
    let value = opt_i64(o, &["value"])?.unwrap_or(0);
    let energy = opt_u64(o, &["gas"])?;
    let data = match o.get("input").or_else(|| o.get("data")).and_then(Value::as_str) {
        Some(s) => parse_hex_bytes(s)?,
        None => Vec::new(),
    };
    // geth convention: a call with no `to` is a contract creation.
    match o.get("to").and_then(Value::as_str) {
        Some(to) => Ok(CallSpec::Trigger {
            from,
            to: parse_eth_address(to)?,
            value,
            data,
            energy,
            token_id: 0,
            token_value: 0,
        }),
        None => Ok(CallSpec::Create {
            from,
            init_code: data,
            value,
            energy,
            consume_user_resource_percent: 100,
            name: String::new(),
            token_id: 0,
            token_value: 0,
        }),
    }
}

fn format_geth_result(res: &SimResult, gas_cap: u64) -> Value {
    let blocks: Vec<Value> = res
        .blocks
        .iter()
        .map(|b| {
            let mut log_index = 0u64;
            let calls: Vec<Value> = b
                .calls
                .iter()
                .map(|c| format_geth_call_result(c, b.number, &mut log_index))
                .collect();
            json!({
                "number": format!("0x{:x}", b.number),
                "timestamp": format!("0x{:x}", b.timestamp_ms / 1000),
                "gasLimit": format!("0x{gas_cap:x}"),
                "gasUsed": format!("0x{:x}", b.energy_used),
                "baseFeePerGas": "0x0",
                "calls": calls,
            })
        })
        .collect();
    json!(blocks)
}

fn format_geth_call_result(c: &CallResult, block_num: i64, log_index: &mut u64) -> Value {
    let mut m = Map::new();
    let ok = c.status == CallStatus::Success;
    m.insert("status".into(), json!(if ok { "0x1" } else { "0x0" }));
    m.insert("returnData".into(), json!(hexs(&c.return_data)));
    m.insert("gasUsed".into(), json!(format!("0x{:x}", c.energy_used)));
    let logs: Vec<Value> = c
        .logs
        .iter()
        .map(|l| {
            let li = *log_index;
            *log_index += 1;
            json!({
                "address": hexs(&l.address),
                "topics": l.topics.iter().map(|t| hexs(t)).collect::<Vec<_>>(),
                "data": hexs(&l.data),
                "blockNumber": format!("0x{block_num:x}"),
                "logIndex": format!("0x{li:x}"),
            })
        })
        .collect();
    m.insert("logs".into(), json!(logs));
    if let Some(addr) = &c.contract_address {
        // geth reports the 20-byte EVM form.
        m.insert("contractAddress".into(), json!(hexs(&addr.as_bytes()[1..])));
    }
    if !ok {
        let msg = c.error.clone().unwrap_or_else(|| "execution failed".to_string());
        m.insert(
            "error".into(),
            json!({ "code": 3, "message": msg, "data": hexs(&c.return_data) }),
        );
    }
    Value::Object(m)
}

// ---------------------------------------------------------------------------
// Wiring helpers
// ---------------------------------------------------------------------------

fn require_sim(s: &RpcState) -> Result<&Arc<SimState>, RpcError> {
    match &s.sim {
        Some(sim) if sim.config().enabled => Ok(sim),
        Some(_) => Err(RpcError::invalid_params(
            "Chronos fork simulation is disabled; set [sim] enabled = true",
        )),
        None => Err(RpcError::invalid_params(
            "Chronos fork simulation is not available on this node",
        )),
    }
}

/// Lock a fork and run `f` against it. The per-fork mutex serializes calls.
fn with_fork<R>(
    session: &Arc<std::sync::Mutex<ForkSession>>,
    f: impl FnOnce(&mut ForkSession) -> Result<R, SimError>,
) -> Result<R, SimError> {
    let mut guard = session.lock().expect("fork session poisoned");
    f(&mut guard)
}

/// Build a fresh overlay at `base` from the archive's live backends.
fn build_overlay(s: &RpcState, base: BaseBlock) -> Result<ForkOverlay, RpcError> {
    let arch = s.archive.as_ref().ok_or_else(|| {
        RpcError::invalid_params(
            "Chronos requires the historical archive; enable [index] capture_state_deltas",
        )
    })?;
    let fb = arch
        .fork_backends()
        .ok_or_else(|| RpcError::internal("archive backend set is incomplete"))?;
    match base {
        BaseBlock::Latest => ForkOverlay::new(&fb, None).map_err(sim_to_rpc),
        BaseBlock::Height(h) => {
            let reader = arch.reader();
            ForkOverlay::new(&fb, Some((&reader, h))).map_err(sim_to_rpc)
        }
    }
}

fn sim_to_rpc(e: SimError) -> RpcError {
    match e {
        SimError::OutOfCoverage { .. } | SimError::NoCoverage | SimError::OverlayCapExceeded { .. } => {
            RpcError::invalid_params(e.to_string())
        }
        SimError::Backend(_) => RpcError::internal(e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Request parsing
// ---------------------------------------------------------------------------

fn obj_param<'a>(p: &'a Value, idx: usize, what: &str) -> Result<&'a Map<String, Value>, RpcError> {
    p.get(idx)
        .and_then(Value::as_object)
        .ok_or_else(|| RpcError::invalid_params(format!("missing {what} (param {idx})")))
}

fn fork_id_param(p: &Value, idx: usize) -> Result<[u8; 16], RpcError> {
    let s = p
        .get(idx)
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params(format!("forkId (hex string) required (param {idx})")))?;
    fork_id_from_hex(s).ok_or_else(|| RpcError::invalid_params("malformed forkId"))
}

fn parse_base(body: &Map<String, Value>) -> Result<BaseBlock, RpcError> {
    match body.get("base") {
        None | Some(Value::Null) => Ok(BaseBlock::Latest),
        Some(Value::String(tag)) => match tag.as_str() {
            "latest" | "pending" | "" => Ok(BaseBlock::Latest),
            other => Ok(BaseBlock::Height(parse_i64_flex(&json!(other), "base")?)),
        },
        Some(Value::Object(o)) => {
            if let Some(b) = o.get("block") {
                Ok(BaseBlock::Height(parse_i64_flex(b, "base.block")?))
            } else if matches!(o.get("tag").and_then(Value::as_str), Some("latest") | Some("pending")) {
                Ok(BaseBlock::Latest)
            } else {
                Err(RpcError::invalid_params("base must be { block } or { tag: \"latest\" }"))
            }
        }
        Some(n) => Ok(BaseBlock::Height(parse_i64_flex(n, "base")?)),
    }
}

fn parse_bundle(body: &Map<String, Value>, sim: &SimState) -> Result<SimRequest, RpcError> {
    let trace = match body.get("trace").and_then(Value::as_str) {
        None | Some("none") | Some("") => TraceLevel::None,
        Some("callTree") | Some("calltree") => TraceLevel::CallTree,
        Some("full") => TraceLevel::Full,
        Some(other) => {
            return Err(RpcError::invalid_params(format!(
                "trace must be none | callTree | full (got {other})"
            )))
        }
    };
    let return_state_diff = match body.get("returnStateDiff").and_then(Value::as_str) {
        None | Some("final") => DiffLevel::Final,
        Some("none") => DiffLevel::None,
        Some("perCall") | Some("percall") => DiffLevel::PerCall,
        Some(other) => {
            return Err(RpcError::invalid_params(format!(
                "returnStateDiff must be none | final | perCall (got {other})"
            )))
        }
    };
    let self_check = body.get("selfCheck").and_then(Value::as_bool).unwrap_or(false);
    let energy_cap = match body.get("energyCap") {
        Some(v) if !v.is_null() => Some(parse_u64_flex(v, "energyCap")?),
        _ => None,
    };

    // Accept either `blocks: [...]` or a single-block shorthand `calls: [...]`.
    let mut blocks = Vec::new();
    if let Some(arr) = body.get("blocks").and_then(Value::as_array) {
        for (i, b) in arr.iter().enumerate() {
            let bo = b
                .as_object()
                .ok_or_else(|| RpcError::invalid_params(format!("blocks[{i}] must be an object")))?;
            blocks.push(parse_block_spec(bo)?);
        }
    } else if body.contains_key("calls") || body.contains_key("overrides") {
        blocks.push(parse_block_spec(body)?);
    } else {
        return Err(RpcError::invalid_params("bundle needs `blocks` or `calls`"));
    }
    // Enforce the block cap early with a clear message.
    if blocks.len() > sim.config().max_blocks_per_bundle {
        return Err(RpcError::invalid_params(format!(
            "bundle has {} blocks > cap {}",
            blocks.len(),
            sim.config().max_blocks_per_bundle
        )));
    }

    Ok(SimRequest { blocks, trace, return_state_diff, self_check, energy_cap })
}

fn parse_block_spec(bo: &Map<String, Value>) -> Result<BlockSpec, RpcError> {
    let overrides = match bo.get("overrides") {
        Some(v) if !v.is_null() => parse_override_set(v)?,
        _ => OverrideSet::default(),
    };
    let mut calls = Vec::new();
    if let Some(arr) = bo.get("calls").and_then(Value::as_array) {
        for (i, c) in arr.iter().enumerate() {
            calls.push(parse_call(c).map_err(|e| {
                RpcError::invalid_params(format!("calls[{i}]: {}", e.message))
            })?);
        }
    }
    Ok(BlockSpec { overrides, calls })
}

fn parse_override_set(v: &Value) -> Result<OverrideSet, RpcError> {
    let o = v
        .as_object()
        .ok_or_else(|| RpcError::invalid_params("overrides must be an object"))?;
    let mut set = OverrideSet::default();

    if let Some(accts) = o.get("accounts").and_then(Value::as_object) {
        for (addr_str, ov) in accts {
            let addr = parse_eth_address(addr_str)?;
            set.accounts.insert(addr, parse_account_override(ov)?);
        }
    }
    if let Some(b) = o.get("block").and_then(Value::as_object) {
        set.block = Some(parse_block_override(b)?);
    }
    Ok(set)
}

fn parse_account_override(v: &Value) -> Result<AccountOverride, RpcError> {
    let o = v
        .as_object()
        .ok_or_else(|| RpcError::invalid_params("each account override must be an object"))?;
    let mut ov = AccountOverride::default();
    if let Some(b) = o.get("balance") {
        ov.balance = Some(parse_i64_flex(b, "balance")?);
    }
    if let Some(c) = o.get("code").and_then(Value::as_str) {
        ov.code = Some(parse_hex_bytes(c)?);
    }
    if let Some(state) = o.get("state").and_then(Value::as_object) {
        ov.state = Some(parse_slot_map(state)?);
    }
    if let Some(diff) = o.get("stateDiff").and_then(Value::as_object) {
        ov.state_diff = Some(parse_slot_map(diff)?);
    }
    if let Some(trc10) = o.get("trc10").or_else(|| o.get("tokenBalances")).and_then(Value::as_object) {
        let mut m = BTreeMap::new();
        for (id, amt) in trc10 {
            let id: i64 = id
                .parse()
                .map_err(|_| RpcError::invalid_params(format!("bad trc10 token id {id}")))?;
            m.insert(id, parse_i64_flex(amt, "trc10 amount")?);
        }
        ov.token_balances = Some(m);
    }
    if let Some(n) = o.get("nonce") {
        ov.nonce = Some(parse_u64_flex(n, "nonce")?);
    }
    Ok(ov)
}

fn parse_slot_map(m: &Map<String, Value>) -> Result<BTreeMap<[u8; 32], [u8; 32]>, RpcError> {
    let mut out = BTreeMap::new();
    for (slot, val) in m {
        let key = parse_word(slot)?;
        let value = parse_word(
            val.as_str()
                .ok_or_else(|| RpcError::invalid_params("storage value must be a 32-byte hex string"))?,
        )?;
        out.insert(key, value);
    }
    Ok(out)
}

fn parse_block_override(o: &Map<String, Value>) -> Result<BlockOverride, RpcError> {
    let number = match o.get("number") {
        Some(v) if !v.is_null() => Some(parse_i64_flex(v, "block.number")?),
        _ => None,
    };
    let time_s = match o.get("time").or_else(|| o.get("timestamp")) {
        Some(v) if !v.is_null() => Some(parse_i64_flex(v, "block.time")?),
        _ => None,
    };
    let coinbase = match o.get("coinbase").and_then(Value::as_str) {
        Some(s) => {
            let a = parse_eth_address(s)?;
            let mut b = [0u8; 20];
            b.copy_from_slice(&a.as_bytes()[1..]);
            Some(b)
        }
        None => None,
    };
    Ok(BlockOverride { number, time_s, coinbase })
}

fn parse_call(c: &Value) -> Result<CallSpec, RpcError> {
    let o = c
        .as_object()
        .ok_or_else(|| RpcError::invalid_params("each call must be an object"))?;
    let kind = o.get("type").and_then(Value::as_str).unwrap_or("trigger");
    let from = addr_field(o, &["ownerAddress", "from"])?;
    let value = opt_i64(o, &["callValue", "value"])?.unwrap_or(0);
    let energy = opt_u64(o, &["energy", "gas"])?;
    let token_id = opt_i64(o, &["tokenId"])?.unwrap_or(0);
    let token_value = opt_i64(o, &["tokenValue", "callTokenValue"])?.unwrap_or(0);

    match kind {
        "trigger" | "call" => {
            let to = addr_field(o, &["contractAddress", "to"])?;
            let data = match o.get("data").or_else(|| o.get("input")).and_then(Value::as_str) {
                Some(s) => parse_hex_bytes(s)?,
                None => Vec::new(),
            };
            Ok(CallSpec::Trigger { from, to, value, data, energy, token_id, token_value })
        }
        "create" | "deploy" => {
            let init_code = o
                .get("initCode")
                .or_else(|| o.get("data"))
                .and_then(Value::as_str)
                .map(parse_hex_bytes)
                .transpose()?
                .ok_or_else(|| RpcError::invalid_params("create call needs `initCode`"))?;
            let consume_user_resource_percent =
                opt_i64(o, &["consumeUserResourcePercent"])?.unwrap_or(100);
            let name = o.get("name").and_then(Value::as_str).unwrap_or("").to_string();
            Ok(CallSpec::Create {
                from,
                init_code,
                value,
                energy,
                consume_user_resource_percent,
                name,
                token_id,
                token_value,
            })
        }
        other => Err(RpcError::invalid_params(format!("call type must be trigger | create (got {other})"))),
    }
}

// ---------------------------------------------------------------------------
// Small value parsers
// ---------------------------------------------------------------------------

fn addr_field(o: &Map<String, Value>, keys: &[&str]) -> Result<Address, RpcError> {
    for k in keys {
        if let Some(s) = o.get(*k).and_then(Value::as_str) {
            return parse_eth_address(s);
        }
    }
    Err(RpcError::invalid_params(format!("missing address field ({})", keys.join("/"))))
}

fn opt_i64(o: &Map<String, Value>, keys: &[&str]) -> Result<Option<i64>, RpcError> {
    for k in keys {
        if let Some(v) = o.get(*k) {
            if !v.is_null() {
                return Ok(Some(parse_i64_flex(v, k)?));
            }
        }
    }
    Ok(None)
}

fn opt_u64(o: &Map<String, Value>, keys: &[&str]) -> Result<Option<u64>, RpcError> {
    for k in keys {
        if let Some(v) = o.get(*k) {
            if !v.is_null() {
                return Ok(Some(parse_u64_flex(v, k)?));
            }
        }
    }
    Ok(None)
}

/// Accept a JSON number, a `0x`-hex string, or a decimal string.
fn parse_i64_flex(v: &Value, what: &str) -> Result<i64, RpcError> {
    if let Some(n) = v.as_i64() {
        return Ok(n);
    }
    if let Some(s) = v.as_str() {
        if let Some(hex) = s.strip_prefix("0x") {
            return i64::from_str_radix(hex, 16)
                .map_err(|_| RpcError::invalid_params(format!("bad hex {what}: {s}")));
        }
        return s
            .parse::<i64>()
            .map_err(|_| RpcError::invalid_params(format!("bad {what}: {s}")));
    }
    Err(RpcError::invalid_params(format!("{what} must be a number or numeric string")))
}

fn parse_u64_flex(v: &Value, what: &str) -> Result<u64, RpcError> {
    if let Some(n) = v.as_u64() {
        return Ok(n);
    }
    if let Some(s) = v.as_str() {
        if let Some(hex) = s.strip_prefix("0x") {
            return u64::from_str_radix(hex, 16)
                .map_err(|_| RpcError::invalid_params(format!("bad hex {what}: {s}")));
        }
        return s
            .parse::<u64>()
            .map_err(|_| RpcError::invalid_params(format!("bad {what}: {s}")));
    }
    Err(RpcError::invalid_params(format!("{what} must be a number or numeric string")))
}

/// Parse a 32-byte word from hex (`0x`-prefixed or bare), left-padded.
fn parse_word(s: &str) -> Result<[u8; 32], RpcError> {
    let bytes = parse_hex_bytes(s)?;
    if bytes.len() > 32 {
        return Err(RpcError::invalid_params(format!("storage word > 32 bytes: {s}")));
    }
    let mut w = [0u8; 32];
    w[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(w)
}

// ---------------------------------------------------------------------------
// Result formatting
// ---------------------------------------------------------------------------

fn b58(bytes: &[u8]) -> String {
    if bytes.len() == 21 {
        let mut a = [0u8; 21];
        a.copy_from_slice(bytes);
        tron_crypto::base58check::encode_address(&Address::from_raw(a))
    } else {
        format!("0x{}", hex::encode(bytes))
    }
}

fn hexs(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn coverage_json(cov: Option<(i64, i64)>) -> Value {
    match cov {
        Some((base, head)) => json!({ "base": base, "head": head }),
        None => Value::Null,
    }
}

fn format_sim_result(res: &SimResult) -> Value {
    let blocks: Vec<Value> = res
        .blocks
        .iter()
        .map(|b| {
            json!({
                "number": b.number,
                "timestampMs": b.timestamp_ms,
                "energyUsed": b.energy_used,
                "calls": b.calls.iter().map(format_call_result).collect::<Vec<_>>(),
            })
        })
        .collect();
    json!({
        "basis": {
            "baseBlock": res.basis.base_block,
            "mode": res.basis.mode,
            "archiveCoverage": coverage_json(res.basis.archive_coverage),
            "granularity": res.basis.granularity,
            "warnings": res.basis.warnings,
        },
        "blocks": blocks,
        "stateDiff": res.state_diff.as_ref().map(format_diff).unwrap_or(Value::Null),
        "warnings": res.warnings,
    })
}

fn format_call_result(c: &CallResult) -> Value {
    let mut m = Map::new();
    m.insert("status".into(), json!(c.status.label()));
    m.insert("returnData".into(), json!(hexs(&c.return_data)));
    m.insert("energyUsed".into(), json!(c.energy_used));
    m.insert("energyPenalty".into(), json!(c.energy_penalty));
    m.insert(
        "logs".into(),
        json!(c
            .logs
            .iter()
            .map(|l| json!({
                "address": hexs(&l.address),
                "topics": l.topics.iter().map(|t| hexs(t)).collect::<Vec<_>>(),
                "data": hexs(&l.data),
            }))
            .collect::<Vec<_>>()),
    );
    if let Some(addr) = &c.contract_address {
        m.insert("contractAddress".into(), json!(b58(addr.as_bytes())));
    }
    m.insert(
        "internalTransactions".into(),
        json!(c.internal_transactions.iter().map(format_internal_tx).collect::<Vec<_>>()),
    );
    if !c.call_frames.is_empty() {
        m.insert(
            "callFrames".into(),
            json!(c.call_frames.iter().map(format_call_frame).collect::<Vec<_>>()),
        );
    }
    if !c.struct_logs.is_empty() {
        m.insert(
            "structLogs".into(),
            json!(c
                .struct_logs
                .iter()
                .map(|l| json!({
                    "pc": l.pc,
                    "op": l.op_name,
                    "gas": l.gas,
                    "gasCost": l.gas_cost,
                    "depth": l.depth,
                    "stack": l.stack.iter().map(|w| format!("0x{w:x}")).collect::<Vec<_>>(),
                    "error": l.error,
                }))
                .collect::<Vec<_>>()),
        );
    }
    if let Some(d) = &c.state_diff {
        m.insert("stateDiff".into(), format_diff(d));
    }
    if let Some(e) = &c.error {
        m.insert("error".into(), json!(e));
    }
    if let CallStatus::Halt(code) = &c.status {
        m.insert("haltReason".into(), json!(code));
    }
    Value::Object(m)
}

fn format_internal_tx(tx: &tron_proto::InternalTransaction) -> Value {
    json!({
        "hash": hexs(&tx.hash),
        "callerAddress": b58(&tx.caller_address),
        "transferToAddress": b58(&tx.transfer_to_address),
        "callValueInfo": tx.call_value_info.iter().map(|cv| json!({
            "callValue": cv.call_value,
            "tokenId": cv.token_id,
        })).collect::<Vec<_>>(),
        "note": String::from_utf8_lossy(&tx.note),
        "rejected": tx.rejected,
    })
}

fn format_call_frame(f: &tron_sim::CallFrame) -> Value {
    json!({
        "type": f.call_type,
        "from": hexs(&f.from),
        "to": f.to.map(|t| hexs(&t)),
        "value": format!("0x{:x}", f.value),
        "input": hexs(&f.input),
        "output": hexs(&f.output),
        "gas": f.gas,
        "gasUsed": f.gas_used,
        "error": f.error,
        "calls": f.calls.iter().map(format_call_frame).collect::<Vec<_>>(),
    })
}

fn format_diff(d: &DecodedStateDiff) -> Value {
    let accounts: Vec<Value> = d
        .accounts
        .iter()
        .map(|a| {
            json!({
                "address": a.address.as_ref().map(|x| b58(x.as_bytes())),
                "balanceBefore": a.before.as_ref().map(|acct| acct.balance),
                "balanceAfter": a.after.as_ref().map(|acct| acct.balance),
                "created": a.before.is_none() && a.after.is_some(),
            })
        })
        .collect();
    let storage: Vec<Value> = d
        .storage
        .iter()
        .map(|s| {
            json!({
                "slotKey": hexs(&s.key),
                "before": s.before.map(|w| hexs(&w)),
                "after": s.after.map(|w| hexs(&w)),
            })
        })
        .collect();
    let code: Vec<Value> = d
        .code
        .iter()
        .map(|c| {
            json!({
                "address": c.address.as_ref().map(|x| b58(x.as_bytes())),
                "beforeLen": c.before.as_ref().map(|b| b.len()),
                "afterLen": c.after.as_ref().map(|b| b.len()),
            })
        })
        .collect();
    json!({
        "accounts": accounts,
        "storage": storage,
        "code": code,
        "totalChangedKeys": d.len(),
    })
}
