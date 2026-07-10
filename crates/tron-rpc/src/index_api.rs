//! TronGrid-compatible `/v1` address-history endpoints, served from
//! the embedded index (`tron-index`).
//!
//! ```text
//! GET /v1/accounts/{address}/transactions            — native + contract calls
//! GET /v1/accounts/{address}/transactions/trc20      — TRC20 transfers
//! GET /v1/accounts/{address}/transactions/trc721     — tron-goblin extension
//! GET /v1/accounts/{address}/transactions/internal   — tron-goblin extension
//! GET /v1/contracts/{address}/events                  — event search (scope = "all")
//! ```
//!
//! Same query params as TronGrid (`limit`, `fingerprint`,
//! `only_from`/`only_to`, `only_confirmed`/`only_unconfirmed`,
//! `contract_address`, `min_timestamp`/`max_timestamp`, `order_by`),
//! so existing TronWeb / TronGrid client code is a drop-in. The
//! endpoints serve **whatever is indexed so far** while a backfill is
//! still running; every response carries a `meta.backfill` object
//! (`complete` + `indexed_from`) so clients can see history filling
//! in. `/transactions/internal` has no TronGrid equivalent — it is a
//! documented tron-goblin extension following the same conventions.

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};

use crate::state::RpcState;
use tron_index::{IndexReader, PageQuery, TokenMeta};

/// TronGrid caps `limit` at 200 (default 20); mirror it.
const DEFAULT_LIMIT: usize = 20;
const MAX_LIMIT: usize = 200;

/// Routes for the `/v1` history surface. Mounted unconditionally; the
/// handlers answer with a clear error when no index is attached.
pub fn router() -> Router<RpcState> {
    Router::new()
        .route("/v1/accounts/:address/transactions", get(account_transactions))
        .route("/v1/accounts/:address/transactions/trc20", get(account_trc20))
        .route("/v1/accounts/:address/transactions/trc721", get(account_trc721))
        .route("/v1/accounts/:address/transactions/internal", get(account_internal))
        .route("/v1/contracts/:address/events", get(contract_events))
}

fn err_response(code: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<Value>) {
    (code, Json(json!({ "success": false, "error": msg.into(), "data": [] })))
}

/// Record an internal fault server-side and answer the client with a stable,
/// generic 500 body. An inner error's `Display` text can carry store
/// internals or filesystem paths, so it is logged via `tracing` for the
/// operator and never surfaced to the caller — the same containment
/// `rpc_error_response` gives `-32603` internal errors. `context` names the
/// failing operation for the log only.
fn internal_error_response(
    context: &str,
    detail: impl std::fmt::Display,
) -> (StatusCode, Json<Value>) {
    tracing::error!(error = %detail, "index API internal error: {context}");
    err_response(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
}

/// Parse a TRON address path/query param: base58 `T…`, `41…` hex, or
/// (`0x`-)20-byte hex.
fn parse_tron_address(s: &str) -> Result<[u8; 21], String> {
    let s = s.trim();
    if s.starts_with('T') {
        return tron_crypto::base58check::decode_address(s)
            .map(|a| *a.as_bytes())
            .map_err(|e| format!("bad base58 address: {e}"));
    }
    let hexstr = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    let bytes = hex::decode(hexstr).map_err(|e| format!("bad hex address: {e}"))?;
    match bytes.len() {
        21 if bytes[0] == 0x41 => {
            let mut a = [0u8; 21];
            a.copy_from_slice(&bytes);
            Ok(a)
        }
        20 => {
            let mut a = [0u8; 21];
            a[0] = 0x41;
            a[1..].copy_from_slice(&bytes);
            Ok(a)
        }
        _ => Err("address must be 21 bytes (0x41-prefixed) or 20 bytes".into()),
    }
}

fn base58(addr: &[u8]) -> String {
    if addr.len() == 21 {
        let mut a = [0u8; 21];
        a.copy_from_slice(addr);
        tron_crypto::base58check::encode_address(&tron_crypto::address::Address::from_raw(a))
    } else {
        hex::encode(addr)
    }
}

fn parse_bool(q: &HashMap<String, String>, key: &str) -> bool {
    q.get(key).map(|v| v == "true" || v == "1").unwrap_or(false)
}

/// Build the engine-side query from the TronGrid params.
fn parse_page_query(q: &HashMap<String, String>) -> Result<PageQuery, String> {
    let limit = q
        .get("limit")
        .map(|v| v.parse::<usize>().map_err(|_| "bad limit".to_string()))
        .transpose()?
        .unwrap_or(DEFAULT_LIMIT)
        .clamp(1, MAX_LIMIT);
    let fingerprint = q
        .get("fingerprint")
        .filter(|v| !v.is_empty())
        .map(|v| hex::decode(v).map_err(|_| "bad fingerprint".to_string()))
        .transpose()?;
    let parse_ts = |key: &str| -> Result<Option<i64>, String> {
        q.get(key)
            .filter(|v| !v.is_empty())
            .map(|v| v.parse::<i64>().map_err(|_| format!("bad {key}")))
            .transpose()
    };
    let ascending = match q.get("order_by").map(|s| s.as_str()) {
        None | Some("block_timestamp,desc") | Some("block_timestamp desc") => false,
        Some("block_timestamp,asc") | Some("block_timestamp asc") => true,
        Some(other) => return Err(format!("unsupported order_by: {other}")),
    };
    let token = q
        .get("contract_address")
        .filter(|v| !v.is_empty())
        .map(|v| parse_tron_address(v))
        .transpose()?;
    Ok(PageQuery {
        limit,
        fingerprint,
        only_from: parse_bool(q, "only_from"),
        only_to: parse_bool(q, "only_to"),
        only_confirmed: parse_bool(q, "only_confirmed"),
        only_unconfirmed: parse_bool(q, "only_unconfirmed"),
        min_timestamp_ms: parse_ts("min_timestamp")?,
        max_timestamp_ms: parse_ts("max_timestamp")?,
        token,
        ascending,
        min_block: None,
        max_block: None,
    })
}

/// The TronGrid response envelope + our serve-during-backfill marker.
fn envelope(data: Vec<Value>, fingerprint: Option<Vec<u8>>, reader: &IndexReader) -> Value {
    let status = reader.status();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let mut meta = json!({
        "at": now_ms,
        "page_size": data.len(),
        "backfill": {
            "complete": status.backfill_complete && status.at_tip,
            "indexed_from": status.indexed_from,
        },
    });
    if let Some(fp) = fingerprint {
        meta["fingerprint"] = Value::String(hex::encode(fp));
    }
    json!({ "data": data, "success": true, "meta": meta })
}

/// `value` for a 32-byte big-endian amount, decimal-rendered (no
/// decimals applied — TronGrid semantics: raw token units).
fn be_bytes_to_decimal(bytes: &[u8]) -> String {
    // Repeated divmod by 10 over the big-endian digits — 32 bytes max,
    // so this is at most ~78 iterations of a 32-step inner loop.
    let mut digits: Vec<u8> = bytes.to_vec();
    let mut out = Vec::new();
    loop {
        let mut rem: u32 = 0;
        let mut all_zero = true;
        for d in digits.iter_mut() {
            let cur = (rem << 8) | *d as u32;
            *d = (cur / 10) as u8;
            rem = cur % 10;
            if *d != 0 {
                all_zero = false;
            }
        }
        out.push(b'0' + rem as u8);
        if all_zero {
            break;
        }
    }
    out.reverse();
    String::from_utf8(out).expect("ascii digits")
}

// ---------------------------------------------------------------------------
// Token-metadata cache (name / symbol / decimals via constant call)
// ---------------------------------------------------------------------------

fn selector(sig: &str) -> [u8; 4] {
    let h = tron_crypto::hash::keccak256(sig.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

/// ABI-decode a `string` return (offset ‖ len ‖ bytes), falling back
/// to a `bytes32` short string for non-standard tokens.
fn decode_abi_string(data: &[u8]) -> Option<String> {
    if data.len() >= 64 {
        // `data` is contract-controlled: a hostile token can return any offset
        // word. Use checked arithmetic throughout so a huge offset yields
        // `None`, never a wrapping add that slips past a bounds guard into a
        // panicking slice (`data[offset + 24..offset + 32]` with start > end).
        let offset = u64::from_be_bytes(data[24..32].try_into().ok()?) as usize;
        let len_end = offset.checked_add(32)?;
        if data.len() >= len_end {
            let len = u64::from_be_bytes(data[len_end - 8..len_end].try_into().ok()?) as usize;
            let str_end = len_end.checked_add(len)?;
            if len <= 1024 && data.len() >= str_end {
                return String::from_utf8(data[len_end..str_end].to_vec()).ok();
            }
        }
    }
    if data.len() == 32 {
        // bytes32-style: NUL-trimmed.
        let trimmed: Vec<u8> = data.iter().copied().take_while(|b| *b != 0).collect();
        if !trimmed.is_empty() {
            return String::from_utf8(trimmed).ok();
        }
    }
    None
}

/// Max DISTINCT unresolved tokens a single history request will spend VM
/// constant-calls to resolve (each token costs up to 3 calls). Bounds the
/// per-request VM work an unauthenticated caller can trigger regardless of
/// how many distinct token contracts a page spans; tokens beyond the cap
/// serve their cached-or-empty metadata and self-heal on later requests.
const TOKEN_RESOLVE_BUDGET: u32 = 32;

/// One read-only call against current state; `None` on revert/halt, when
/// constant-call backends aren't wired, or when the operator has disabled
/// constant calls (`vm.supportConstant = false`) — the same gate
/// `trigger_constant_contract` enforces, so disabling public constant
/// calls also disables this internal metadata-resolution surface.
fn constant_call(s: &RpcState, contract: &[u8; 21], data: Vec<u8>) -> Option<Vec<u8>> {
    if !s.support_constant {
        return None;
    }
    let backends = s.eth_call_backends.as_ref()?;
    let vm_stores = crate::methods::build_call_vm_stores(backends);
    let block_env = tron_tvm::execute::VmBlockEnv {
        block_number: s.dyn_props.latest_block_header_number().unwrap_or(0),
        block_timestamp_ms: s.dyn_props.latest_block_header_timestamp().unwrap_or(0), ..Default::default()
    };
    let trigger = tron_proto::TriggerSmartContract {
        owner_address: vec![0x41; 21],
        contract_address: contract.to_vec(),
        data,
        ..Default::default()
    };
    // Metadata reads are tiny; 3M energy is far more than enough and
    // keeps a pathological token from burning the whole call cap.
    match crate::methods::dispatch_constant_trigger(s, &vm_stores, block_env, &trigger, 3_000_000).0
    {
        tron_tvm::execute::VmOutcome::Success { return_data, .. } => Some(return_data),
        _ => None,
    }
}

/// Resolve (and cache) a TRC20 token's metadata. Unresolved entries are
/// cached too and re-attempted so a token that starts answering later
/// self-heals — but only while `resolve_budget` (a per-request counter)
/// is non-zero, so one request can't fan out into unbounded VM work.
fn token_info(
    s: &RpcState,
    reader: &IndexReader,
    contract: &[u8; 21],
    resolve_budget: &mut u32,
) -> Value {
    let cached = reader.token_meta(contract).ok().flatten();
    let meta = match cached {
        Some(m) if m.resolved => m,
        cached => {
            // Spend a resolution only when the operator permits constant
            // calls and this request still has budget; otherwise serve the
            // cached (possibly unresolved) entry or an empty placeholder.
            if !s.support_constant || *resolve_budget == 0 {
                cached.unwrap_or(TokenMeta {
                    name: String::new(),
                    symbol: String::new(),
                    decimals: 0,
                    resolved: false,
                })
            } else {
                *resolve_budget -= 1;
                let name = constant_call(s, contract, selector("name()").to_vec())
                    .and_then(|d| decode_abi_string(&d));
                let symbol = constant_call(s, contract, selector("symbol()").to_vec())
                    .and_then(|d| decode_abi_string(&d));
                let decimals = constant_call(s, contract, selector("decimals()").to_vec())
                    .filter(|d| d.len() >= 32)
                    .map(|d| d[31] as i32);
                let resolved = name.is_some() || symbol.is_some() || decimals.is_some();
                let meta = TokenMeta {
                    name: name.unwrap_or_default(),
                    symbol: symbol.unwrap_or_default(),
                    decimals: decimals.unwrap_or(0),
                    resolved,
                };
                let _ = reader.put_token_meta(contract, &meta);
                meta
            }
        }
    };
    json!({
        "symbol": meta.symbol,
        "address": base58(contract),
        "decimals": meta.decimals,
        "name": meta.name,
    })
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

macro_rules! get_reader {
    ($state:expr) => {
        match $state.index.as_ref() {
            Some(r) => r,
            None => {
                return err_response(
                    StatusCode::NOT_IMPLEMENTED,
                    "address-history index not enabled on this node (set [index] enable = true)",
                )
            }
        }
    };
}

async fn account_trc20(
    State(state): State<RpcState>,
    Path(address): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let reader = get_reader!(state);
    let addr = match parse_tron_address(&address) {
        Ok(a) => a,
        Err(e) => return err_response(StatusCode::BAD_REQUEST, e),
    };
    let query = match parse_page_query(&q) {
        Ok(p) => p,
        Err(e) => return err_response(StatusCode::BAD_REQUEST, e),
    };
    let page = match reader.trc20_page(&addr, &query) {
        Ok(p) => p,
        Err(e) => return internal_error_response("trc20_page", e),
    };
    // One resolution per DISTINCT token per request: token_info can run
    // up to three constant calls for an unresolved token, and a page
    // has up to 200 rows that are usually the same token.
    let mut token_memo: HashMap<[u8; 21], Value> = HashMap::new();
    let mut resolve_budget = TOKEN_RESOLVE_BUDGET;
    let data: Vec<Value> = page
        .rows
        .iter()
        .map(|r| {
            let mut token = [0u8; 21];
            if r.row.token.len() == 21 {
                token.copy_from_slice(&r.row.token);
            }
            let info = token_memo
                .entry(token)
                .or_insert_with(|| token_info(&state, reader, &token, &mut resolve_budget))
                .clone();
            json!({
                "transaction_id": hex::encode(&r.row.txid),
                "token_info": info,
                "block_timestamp": r.row.timestamp_ms,
                "block": r.parts.height,
                "from": base58(&r.row.from),
                "to": base58(&r.row.to),
                "type": "Transfer",
                "value": be_bytes_to_decimal(&r.row.amount),
                "confirmed": r.confirmed,
            })
        })
        .collect();
    (StatusCode::OK, Json(envelope(data, page.fingerprint, reader)))
}

/// `/trc721` — NFT transfer history. No TronGrid equivalent route; a
/// documented tron-goblin extension following the `/trc20` shape, with
/// `token_id` (decimal) in place of `value`.
async fn account_trc721(
    State(state): State<RpcState>,
    Path(address): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let reader = get_reader!(state);
    let addr = match parse_tron_address(&address) {
        Ok(a) => a,
        Err(e) => return err_response(StatusCode::BAD_REQUEST, e),
    };
    let query = match parse_page_query(&q) {
        Ok(p) => p,
        Err(e) => return err_response(StatusCode::BAD_REQUEST, e),
    };
    let page = match reader.trc721_page(&addr, &query) {
        Ok(p) => p,
        Err(e) => return internal_error_response("trc721_page", e),
    };
    let mut token_memo: HashMap<[u8; 21], Value> = HashMap::new();
    let mut resolve_budget = TOKEN_RESOLVE_BUDGET;
    let data: Vec<Value> = page
        .rows
        .iter()
        .map(|r| {
            let mut token = [0u8; 21];
            if r.row.token.len() == 21 {
                token.copy_from_slice(&r.row.token);
            }
            let info = token_memo
                .entry(token)
                .or_insert_with(|| token_info(&state, reader, &token, &mut resolve_budget))
                .clone();
            json!({
                "transaction_id": hex::encode(&r.row.txid),
                "token_info": info,
                "block_timestamp": r.row.timestamp_ms,
                "block": r.parts.height,
                "from": base58(&r.row.from),
                "to": base58(&r.row.to),
                "type": "Transfer",
                "token_id": be_bytes_to_decimal(&r.row.token_id),
                "confirmed": r.confirmed,
            })
        })
        .collect();
    (StatusCode::OK, Json(envelope(data, page.fingerprint, reader)))
}

async fn account_transactions(
    State(state): State<RpcState>,
    Path(address): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let reader = get_reader!(state);
    let addr = match parse_tron_address(&address) {
        Ok(a) => a,
        Err(e) => return err_response(StatusCode::BAD_REQUEST, e),
    };
    let query = match parse_page_query(&q) {
        Ok(p) => p,
        Err(e) => return err_response(StatusCode::BAD_REQUEST, e),
    };
    let page = match reader.native_page(&addr, &query) {
        Ok(p) => p,
        Err(e) => return internal_error_response("native_page", e),
    };

    // Hydrate full tx bodies from BlockStore — page-bounded (≤ limit
    // distinct blocks; rows in the same block share the decode).
    let mut block_cache: HashMap<i64, Option<tron_proto::Block>> = HashMap::new();
    let data: Vec<Value> = page
        .rows
        .iter()
        .map(|r| {
            let block = block_cache
                .entry(r.parts.height)
                .or_insert_with(|| reader.block_at(r.parts.height).ok().flatten());
            let tx_json = block
                .as_ref()
                .and_then(|b| b.transactions.get(r.parts.txidx as usize))
                .map(transaction_to_json);
            let mut v = json!({
                "txID": hex::encode(&r.row.txid),
                "blockNumber": r.parts.height,
                "block_timestamp": r.row.timestamp_ms,
                "direction": if r.row.direction == tron_index::DIR_FROM { "from" }
                             else if r.row.direction == tron_index::DIR_TO { "to" }
                             else { "both" },
                "confirmed": r.confirmed,
            });
            if let Some(tx) = tx_json {
                for (k, val) in tx.as_object().into_iter().flatten() {
                    v[k] = val.clone();
                }
            }
            v
        })
        .collect();
    (StatusCode::OK, Json(envelope(data, page.fingerprint, reader)))
}

async fn account_internal(
    State(state): State<RpcState>,
    Path(address): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let reader = get_reader!(state);
    let addr = match parse_tron_address(&address) {
        Ok(a) => a,
        Err(e) => return err_response(StatusCode::BAD_REQUEST, e),
    };
    let query = match parse_page_query(&q) {
        Ok(p) => p,
        Err(e) => return err_response(StatusCode::BAD_REQUEST, e),
    };
    let page = match reader.internal_page(&addr, &query) {
        Ok(p) => p,
        Err(e) => return internal_error_response("internal_page", e),
    };
    let data: Vec<Value> = page
        .rows
        .iter()
        .map(|r| {
            json!({
                "transaction_id": hex::encode(&r.row.txid),
                "caller_address": base58(&r.row.caller),
                "transferTo_address": base58(&r.row.transfer_to),
                "call_value": r.row.call_value,
                "token_id": r.row.token_id,
                "rejected": r.row.rejected,
                "block_timestamp": r.row.timestamp_ms,
                "block": r.parts.height,
                "confirmed": r.confirmed,
            })
        })
        .collect();
    (StatusCode::OK, Json(envelope(data, page.fingerprint, reader)))
}

/// `/v1/contracts/{address}/events` — event search over the
/// `idx_logs` rows (written under `scope = "all"` / `capture_logs`).
/// TronGrid-style params: `event_name` (resolved to its topic0 hash
/// through the contract's stored ABI), or a raw 32-byte `topic0`;
/// `block_number` for one block; `min_block_timestamp` /
/// `max_block_timestamp`; `order_by=block_timestamp,asc|desc`;
/// `limit` / `fingerprint`. Topics + data hydrate from stored
/// transaction-info, and each event is ABI-decoded into `event_name`
/// + `result` when the contract's ABI is on chain.
async fn contract_events(
    State(state): State<RpcState>,
    Path(address): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let reader = get_reader!(state);
    let addr = match parse_tron_address(&address) {
        Ok(a) => a,
        Err(e) => return err_response(StatusCode::BAD_REQUEST, e),
    };
    // TronGrid's timestamp params for this route carry a `block_`
    // prefix; normalize onto the shared parser's names.
    let mut q = q;
    for (from, to) in
        [("min_block_timestamp", "min_timestamp"), ("max_block_timestamp", "max_timestamp")]
    {
        if let Some(v) = q.get(from).cloned() {
            q.entry(to.to_string()).or_insert(v);
        }
    }
    let mut query = match parse_page_query(&q) {
        Ok(p) => p,
        Err(e) => return err_response(StatusCode::BAD_REQUEST, e),
    };
    query.token = None; // `contract_address` filter is not for this route
    if let Some(b) = q.get("block_number").filter(|v| !v.is_empty()) {
        let Ok(h) = b.parse::<i64>() else {
            return err_response(StatusCode::BAD_REQUEST, "bad block_number");
        };
        query.min_block = Some(h);
        query.max_block = Some(h);
    }

    // The contract's stored ABI — used both to resolve `event_name`
    // and to decode results.
    let abi = state.abis.as_ref().and_then(|abis| {
        abis.get(&tron_crypto::address::Address::from_raw(addr)).ok().flatten()
    });

    let topic0: Option<[u8; 32]> = match (
        q.get("event_name").filter(|v| !v.is_empty()),
        q.get("topic0").filter(|v| !v.is_empty()),
    ) {
        (Some(name), _) => {
            let Some(abi) = abi.as_ref() else {
                return err_response(
                    StatusCode::BAD_REQUEST,
                    "event_name requires the contract's ABI on chain — pass topic0 instead",
                );
            };
            use tron_proto::smart_contract::abi::entry::EntryType;
            let topic = abi
                .entrys
                .iter()
                .find(|e| e.r#type == EntryType::Event as i32 && e.name == *name)
                .map(crate::abi::event_topic0);
            match topic {
                Some(t) => Some(t),
                None => {
                    return err_response(
                        StatusCode::BAD_REQUEST,
                        format!("no event named '{name}' in the contract ABI"),
                    )
                }
            }
        }
        (None, Some(hexstr)) => {
            let stripped = hexstr.strip_prefix("0x").unwrap_or(hexstr);
            match hex::decode(stripped).ok().filter(|b| b.len() == 32) {
                Some(b) => {
                    let mut t = [0u8; 32];
                    t.copy_from_slice(&b);
                    Some(t)
                }
                None => return err_response(StatusCode::BAD_REQUEST, "topic0 must be 32 bytes hex"),
            }
        }
        (None, None) => None,
    };

    let page = match reader.logs_page(&addr, topic0, &query) {
        Ok(p) => p,
        Err(e) => return internal_error_response("logs_page", e),
    };

    // Hydrate topics/data from the block-keyed transaction-info, one
    // store read per distinct block on the page.
    let mut ret_cache: HashMap<i64, Option<tron_proto::TransactionRet>> = HashMap::new();
    let data: Vec<Value> = page
        .rows
        .iter()
        .map(|r| {
            let log = state.transaction_ret.as_ref().and_then(|store| {
                ret_cache
                    .entry(r.height)
                    .or_insert_with(|| store.get(r.height).ok().flatten())
                    .as_ref()
                    .and_then(|ret| ret.transactioninfo.get(r.txidx as usize))
                    .and_then(|info| info.log.get(r.logidx as usize))
                    .cloned()
            });
            let mut v = json!({
                "block_number": r.height,
                "block_timestamp": r.row.timestamp_ms,
                "contract_address": base58(&addr),
                "event_index": r.logidx,
                "transaction_id": hex::encode(&r.row.txid),
                "confirmed": r.confirmed,
            });
            if let Some(log) = log {
                v["topics"] = json!(log.topics.iter().map(hex::encode).collect::<Vec<_>>());
                v["data"] = json!(hex::encode(&log.data));
                if let Some(abi) = abi.as_ref() {
                    let topics: Vec<[u8; 32]> = log
                        .topics
                        .iter()
                        .filter(|t| t.len() == 32)
                        .map(|t| {
                            let mut b = [0u8; 32];
                            b.copy_from_slice(t);
                            b
                        })
                        .collect();
                    if topics.len() == log.topics.len() {
                        if let Ok(ev) = crate::abi::decode_event_log(abi, &topics, &log.data) {
                            v["event_name"] = json!(ev.name);
                            v["result"] = crate::abi::decoded_event_to_json(&ev);
                        }
                    }
                }
            } else {
                // The pointer row exists but its txinfo is gone
                // (overwritten by a reorg-reapply before unwind, or a
                // pruned store) — surface the pointer honestly.
                v["data_unavailable"] = json!(true);
            }
            v
        })
        .collect();
    (StatusCode::OK, Json(envelope(data, page.fingerprint, reader)))
}

/// Stored-transaction → JSON in the full java/TronGrid shape (decoded
/// contract `parameter.value`, enum-name `type`), reusing the same
/// `format_raw_data_for_http` decoder `getblockbynum` renders with.
fn transaction_to_json(tx: &tron_proto::Transaction) -> Value {
    json!({
        "raw_data": tx
            .raw_data
            .as_ref()
            .map(crate::http_rest::format_raw_data_for_http)
            .unwrap_or_else(|| json!({})),
        "signature": tx.signature.iter().map(hex::encode).collect::<Vec<_>>(),
        "ret": tx.ret.iter().map(|r| json!({
            "fee": r.fee,
            "contractRet": tron_proto::transaction::result::ContractResult::try_from(r.contract_ret)
                .map(|c| c.as_str_name().to_string())
                .unwrap_or_else(|_| r.contract_ret.to_string()),
        })).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_abi_string_rejects_hostile_offsets_without_panicking() {
        // A well-formed dynamic string: offset=32, len=3, "abc".
        let mut ok = vec![0u8; 96];
        ok[31] = 32; // offset word = 32
        ok[63] = 3; // length word = 3
        ok[64..67].copy_from_slice(b"abc");
        assert_eq!(decode_abi_string(&ok), Some("abc".to_string()));

        // Hostile offset near usize::MAX: offset + 32 wraps in a release
        // build; checked arithmetic must yield None, never a panicking slice.
        let mut evil = vec![0u8; 64];
        evil[24..32].copy_from_slice(&0xFFFF_FFFF_FFFF_FFE4u64.to_be_bytes());
        assert_eq!(decode_abi_string(&evil), None);

        // Offset just past the buffer, and an oversized length: both None.
        let mut oob = vec![0u8; 64];
        oob[31] = 200; // offset 200 > data.len()
        assert_eq!(decode_abi_string(&oob), None);
        let mut biglen = vec![0u8; 96];
        biglen[31] = 32;
        biglen[56..64].copy_from_slice(&u64::MAX.to_be_bytes()); // len = u64::MAX
        assert_eq!(decode_abi_string(&biglen), None);
    }

    #[test]
    fn decimal_rendering_handles_zero_small_and_u256_max() {
        assert_eq!(be_bytes_to_decimal(&[0u8; 32]), "0");
        let mut one_e9 = [0u8; 32];
        one_e9[24..].copy_from_slice(&1_000_000_000u64.to_be_bytes());
        assert_eq!(be_bytes_to_decimal(&one_e9), "1000000000");
        assert_eq!(
            be_bytes_to_decimal(&[0xff; 32]),
            "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        );
    }

    #[test]
    fn address_parsing_accepts_base58_and_hex_forms() {
        let a41 = "41a614f803b6fd780986a42c78ec9c7f77e6ded13c";
        let parsed = parse_tron_address(a41).unwrap();
        assert_eq!(parsed[0], 0x41);
        // 20-byte form gets the 0x41 prefix.
        let a20 = "a614f803b6fd780986a42c78ec9c7f77e6ded13c";
        assert_eq!(parse_tron_address(a20).unwrap(), parsed);
        // Base58 round-trip.
        let b58 = base58(&parsed);
        assert!(b58.starts_with('T'));
        assert_eq!(parse_tron_address(&b58).unwrap(), parsed);
        assert!(parse_tron_address("zzz").is_err());
    }

    #[test]
    fn abi_string_decoding_standard_and_bytes32() {
        // Standard: offset=32, len=4, "USDT".
        let mut data = vec![0u8; 96];
        data[31] = 32;
        data[63] = 4;
        data[64..68].copy_from_slice(b"USDT");
        assert_eq!(decode_abi_string(&data).as_deref(), Some("USDT"));
        // bytes32 short-string fallback.
        let mut b32 = vec![0u8; 32];
        b32[..3].copy_from_slice(b"TRX");
        assert_eq!(decode_abi_string(&b32).as_deref(), Some("TRX"));
        assert_eq!(decode_abi_string(&[]), None);
    }

    #[test]
    fn selectors_match_known_erc20_values() {
        assert_eq!(selector("name()"), [0x06, 0xfd, 0xde, 0x03]);
        assert_eq!(selector("symbol()"), [0x95, 0xd8, 0x9b, 0x41]);
        assert_eq!(selector("decimals()"), [0x31, 0x3c, 0xe5, 0x67]);
    }

    #[test]
    fn internal_errors_are_sanitized_to_a_generic_body() {
        // The inner detail (which can carry store internals or filesystem
        // paths) must never reach the client body — the caller sees a stable
        // generic message; the detail goes to the server log instead.
        let (status, body) =
            internal_error_response("unit", "rocksdb: /var/lib/tron/index corrupt at cf=logs");
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        let err = body.0["error"].as_str().unwrap();
        assert_eq!(err, "internal server error");
        assert!(!err.contains("rocksdb"), "leaked store internal: {err}");
        assert!(!err.contains("/var/lib/tron"), "leaked filesystem path: {err}");
    }
}

// ---------------------------------------------------------------------------
// /v1/archive — historical-state reads (P2, `capture_state_deltas`)
// ---------------------------------------------------------------------------

use std::sync::Arc;
use tron_chainbase::{KvBackend, UndoStoreId};
use tron_index::{ArchiveAtBackend, ArchiveReader};

/// Everything the `/v1/archive` surface needs: the versioned-KV reader
/// plus the live backend per archived store (the fall-through half of
/// every at-height view). Built by the node runtime.
#[derive(Clone)]
pub struct ArchiveApiState {
    reader: ArchiveReader,
    backends: Arc<Vec<(UndoStoreId, Arc<dyn KvBackend>)>>,
}

impl ArchiveApiState {
    pub fn new(
        reader: ArchiveReader,
        backends: Vec<(UndoStoreId, Arc<dyn KvBackend>)>,
    ) -> Self {
        Self { reader, backends: Arc::new(backends) }
    }

    fn live(&self, id: UndoStoreId) -> Option<Arc<dyn KvBackend>> {
        self.backends.iter().find(|(i, _)| *i == id).map(|(_, b)| b.clone())
    }

    /// An at-height `KvBackend` view of one store.
    fn at(&self, id: UndoStoreId, height: i64) -> Option<Arc<dyn KvBackend>> {
        let live = self.live(id)?;
        Some(Arc::new(ArchiveAtBackend::new(live, self.reader.clone(), id, height)))
    }

    /// Whether the archive can serve at-height reads for block `h` (i.e. `h`
    /// is within the captured coverage window). Used by `debug_traceTransaction`
    /// to decide whether it can time-travel to the tx's historical state.
    pub fn covers(&self, h: i64) -> bool {
        matches!(self.reader.coverage(), Ok(Some((base, head))) if h >= base && h <= head)
    }
}

/// Routes for the at-height read surface.
pub fn archive_router() -> Router<RpcState> {
    use axum::routing::post;
    Router::new()
        .route("/v1/archive/coverage", get(archive_coverage))
        .route("/v1/archive/account", get(archive_account).post(archive_account))
        .route(
            "/v1/archive/accountresource",
            get(archive_account_resource).post(archive_account_resource),
        )
        .route("/v1/archive/storage", get(archive_storage).post(archive_storage))
        .route(
            "/v1/archive/triggerconstantcontract",
            post(archive_trigger_constant),
        )
}

/// Clone the RPC state with every archived store swapped for its
/// at-height view. The existing read methods then run **unchanged**
/// over historical state — including the presentation transforms
/// (decay, optimized-asset merge) and the constant-call VM, whose
/// block env derives from the archived dyn-props (which hold block
/// `H`'s head number/timestamp exactly, because the executor writes
/// them every block). `account_asset` is deliberately left live: the
/// executor never writes it (TRC10 balances go inline to
/// `Account.asset_v2`), so its live contents ARE its at-height
/// contents.
pub(crate) fn state_at_height(s: &RpcState, arch: &ArchiveApiState, h: i64) -> RpcState {
    use tron_chainbase as cb;
    use UndoStoreId as Id;
    let mut at = s.clone();
    if let Some(b) = arch.at(Id::Accounts, h) {
        at.accounts = Arc::new(cb::AccountStore::new(b));
    }
    if let Some(b) = arch.at(Id::DynProps, h) {
        at.dyn_props = Arc::new(cb::DynamicPropertiesStore::new(b));
    }
    if let Some(b) = arch.at(Id::Witnesses, h) {
        at.witnesses = Some(Arc::new(cb::WitnessStore::new(b)));
    }
    if let Some(b) = arch.at(Id::Delegation, h) {
        at.delegation = Some(Arc::new(cb::DelegationStore::new(b)));
    }
    if let Some(b) = arch.at(Id::DelegatedResources, h) {
        at.delegated_resources = Some(Arc::new(cb::DelegatedResourceStore::new(b)));
    }
    if let Some(b) = arch.at(Id::Proposals, h) {
        at.proposals = Some(Arc::new(cb::ProposalStore::new(b)));
    }
    if let Some(b) = arch.at(Id::AssetV1, h) {
        at.assets_v1 = Some(Arc::new(cb::AssetIssueStore::new(b)));
    }
    if let Some(b) = arch.at(Id::AssetV2, h) {
        at.assets_v2 = Some(Arc::new(cb::AssetIssueV2Store::new(b)));
    }
    if let Some(b) = arch.at(Id::ExchangeV2, h) {
        at.exchanges_v2 = Some(Arc::new(cb::ExchangeV2Store::new(b)));
    }
    if let Some(b) = arch.at(Id::Contracts, h) {
        at.contracts = Some(Arc::new(cb::ContractStore::new(b)));
    }
    if let Some(b) = arch.at(Id::Abi, h) {
        at.abis = Some(Arc::new(cb::AbiStore::new(b)));
    }
    if let Some(b) = arch.at(Id::IdIndex, h) {
        at.account_id_index = Some(Arc::new(cb::AccountIdIndexStore::new(b)));
    }
    if let Some(b) = arch.at(Id::Nullifiers, h) {
        at.nullifiers = Some(Arc::new(cb::NullifierStore::new(b)));
    }
    if let Some(b) = arch.at(Id::Code, h) {
        at.code = Some(Arc::new(cb::CodeStore::new(b)));
    }
    if let Some(b) = arch.at(Id::StorageRow, h) {
        at.storage = Some(Arc::new(cb::StorageRowStore::new(b)));
    }
    // Constant-call backends: same swap at the raw-backend level. The
    // block_index stays live (append-only by height; BLOCKHASH only
    // looks at heights ≤ H because the block env says the head is H).
    if let Some(live) = &s.eth_call_backends {
        let swap = |id: Id, fallback: &Arc<dyn KvBackend>| -> Arc<dyn KvBackend> {
            arch.at(id, h).unwrap_or_else(|| fallback.clone())
        };
        at.eth_call_backends = Some(crate::state::EthCallBackends {
            accounts: swap(Id::Accounts, &live.accounts),
            code: swap(Id::Code, &live.code),
            storage: swap(Id::StorageRow, &live.storage),
            witnesses: swap(Id::Witnesses, &live.witnesses),
            contract_state: swap(Id::ContractState, &live.contract_state),
            dyn_props: swap(Id::DynProps, &live.dyn_props),
            delegated_resources: swap(Id::DelegatedResources, &live.delegated_resources),
            delegation: swap(Id::Delegation, &live.delegation),
            contracts: swap(Id::Contracts, &live.contracts),
            block_index: live.block_index.clone(),
        });
    }
    at
}

/// Resolve + validate the `block` param against archive coverage.
fn parse_block_param(
    arch: &ArchiveApiState,
    q: &HashMap<String, String>,
    body: Option<&Value>,
) -> Result<i64, String> {
    let from_body = body.and_then(|b| b.get("block")).and_then(|v| v.as_i64());
    let h = match from_body {
        Some(h) => h,
        None => q
            .get("block")
            .ok_or("missing 'block' parameter")?
            .parse::<i64>()
            .map_err(|_| "bad 'block' parameter")?,
    };
    let (base, head) = arch
        .reader
        .coverage()
        .map_err(|e| e.to_string())?
        .ok_or("archive has no coverage yet (no blocks captured)")?;
    if h < base || h > head {
        return Err(format!(
            "block {h} outside archive coverage [{base}, {head}] — history below the base \
             was not captured (coverage starts when capture_state_deltas is first enabled)"
        ));
    }
    Ok(h)
}

/// Map an inner `RpcError` to a REST status: client mistakes
/// (bad/missing params, gated method) become 400, everything else 500.
/// The clean `message` is surfaced — never the `{:?}` struct dump.
fn rpc_error_response(e: crate::methods::RpcError) -> (StatusCode, Json<Value>) {
    // -32602 invalid params / -32600 invalid request → caller error.
    let code = if e.code == -32602 || e.code == -32600 {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    err_response(code, e.message)
}

/// Resolve the queried height (validating coverage), build the
/// at-height `RpcState`, and run `method` with caller-built `params`.
/// All `/v1/archive` read handlers funnel through here so the gating,
/// coverage check, response envelope, and `visible` rewrite stay
/// identical across the surface.
fn run_archive_method(
    method: fn(&Value, &RpcState) -> Result<Value, crate::methods::RpcError>,
    state: &RpcState,
    q: &HashMap<String, String>,
    body: Option<&Value>,
    build_params: impl FnOnce(&ArchiveApiState) -> Result<Value, (StatusCode, Json<Value>)>,
) -> (StatusCode, Json<Value>) {
    let Some(arch) = state.archive.as_ref() else {
        return err_response(
            StatusCode::NOT_IMPLEMENTED,
            "historical-state archive not enabled on this node (set [index] capture_state_deltas = true)",
        );
    };
    let h = match parse_block_param(arch, q, body) {
        Ok(h) => h,
        Err(e) => return err_response(StatusCode::BAD_REQUEST, e),
    };
    let params = match build_params(arch) {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let at_state = state_at_height(state, arch, h);
    match method(&params, &at_state) {
        Ok(v) => {
            let mut out = json!({ "success": true, "block": h, "data": v });
            let visible = q.get("visible").map(|v| v == "true").unwrap_or(false);
            if visible {
                crate::http_rest::rewrite_addresses(&mut out, true);
            }
            (StatusCode::OK, Json(out))
        }
        Err(e) => rpc_error_response(e),
    }
}

/// Build the at-height `params` for an address-keyed method:
/// `params[0]` = the contract/account address as hex.
fn archive_method(
    method: fn(&Value, &RpcState) -> Result<Value, crate::methods::RpcError>,
    state: &RpcState,
    address: Option<&str>,
    q: &HashMap<String, String>,
    body: Option<&Value>,
) -> (StatusCode, Json<Value>) {
    run_archive_method(method, state, q, body, |_arch| match address {
        Some(a) => {
            let addr =
                parse_tron_address(a).map_err(|e| err_response(StatusCode::BAD_REQUEST, e))?;
            Ok(Value::Array(vec![Value::String(format!("0x{}", hex::encode(&addr[1..])))]))
        }
        None => {
            // Pass the JSON body through as params[0] (the builder
            // convention), addresses normalized to hex.
            let mut b = body.cloned().unwrap_or_else(|| json!({}));
            crate::http_rest::translate_addresses_to_hex(&mut b);
            Ok(Value::Array(vec![b]))
        }
    })
}

/// GET takes `address`/`block` as query params; POST also accepts
/// them in the JSON body (body wins). One handler serves both —
/// `Option<Json<...>>` extracts `None` on a body-less GET — so the
/// precedence rules cannot drift between verbs.
async fn archive_account(
    State(state): State<RpcState>,
    Query(q): Query<HashMap<String, String>>,
    body: Option<Json<Value>>,
) -> (StatusCode, Json<Value>) {
    archive_address_method(crate::methods::get_account, state, q, body)
}

async fn archive_account_resource(
    State(state): State<RpcState>,
    Query(q): Query<HashMap<String, String>>,
    body: Option<Json<Value>>,
) -> (StatusCode, Json<Value>) {
    archive_address_method(crate::methods::get_account_resource, state, q, body)
}

fn archive_address_method(
    method: fn(&Value, &RpcState) -> Result<Value, crate::methods::RpcError>,
    state: RpcState,
    q: HashMap<String, String>,
    body: Option<Json<Value>>,
) -> (StatusCode, Json<Value>) {
    let body = body.map(|Json(b)| b);
    let address = body
        .as_ref()
        .and_then(|b| b.get("address"))
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .or_else(|| q.get("address").cloned());
    let Some(address) = address else {
        return err_response(StatusCode::BAD_REQUEST, "missing 'address' parameter");
    };
    archive_method(method, &state, Some(&address), &q, body.as_ref())
}

/// `GET|POST /v1/archive/storage` — one contract storage slot as of a
/// height. `address` (the contract), `slot` (a `0x` QUANTITY or full
/// 32-byte hex word), and `block` come from query params or the JSON
/// body (body wins, mirroring the other archive handlers). Reuses the
/// live `eth_getStorageAt` handler over the at-height `StorageRowStore`,
/// so the slot-key composition and zero-fill stay byte-identical to the
/// live path. Returns `data` = the 32-byte slot value as `0x…64-hex`.
async fn archive_storage(
    State(state): State<RpcState>,
    Query(q): Query<HashMap<String, String>>,
    body: Option<Json<Value>>,
) -> (StatusCode, Json<Value>) {
    let body = body.map(|Json(b)| b);
    let field = |name: &str| -> Option<String> {
        body.as_ref()
            .and_then(|b| b.get(name))
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| q.get(name).cloned())
    };
    let Some(address) = field("address") else {
        return err_response(StatusCode::BAD_REQUEST, "missing 'address' parameter");
    };
    let Some(slot) = field("slot") else {
        return err_response(StatusCode::BAD_REQUEST, "missing 'slot' parameter");
    };
    run_archive_method(
        crate::methods::eth_get_storage_at,
        &state,
        &q,
        body.as_ref(),
        |_arch| {
            let addr = parse_tron_address(&address)
                .map_err(|e| err_response(StatusCode::BAD_REQUEST, e))?;
            // `eth_getStorageAt` expects a `0x`-prefixed slot (QUANTITY
            // or full word); normalize a bare-hex slot so either form
            // works from the REST surface.
            let slot_hex = if slot.starts_with("0x") || slot.starts_with("0X") {
                slot.clone()
            } else {
                format!("0x{slot}")
            };
            Ok(Value::Array(vec![
                Value::String(format!("0x{}", hex::encode(&addr[1..]))),
                Value::String(slot_hex),
            ]))
        },
    )
}

/// `POST /v1/archive/triggerconstantcontract` — the standard
/// `/wallet/triggerconstantcontract` body plus a `block` field. The
/// whole VM environment comes out of the archived dyn-props at H, so
/// `block.number` / `block.timestamp` opcodes see block H's values.
async fn archive_trigger_constant(
    State(state): State<RpcState>,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    archive_method(
        crate::methods::trigger_constant_contract,
        &state,
        None,
        &q,
        Some(&body),
    )
}

/// `GET /v1/archive/coverage` — the served at-height window. Lets a
/// client discover the valid `block` range before issuing reads (every
/// other archive route rejects out-of-range heights with this same
/// window in the error). Returns `404`-shaped `success:false` when the
/// archive is off, `{base, head, ...}` otherwise.
async fn archive_coverage(State(state): State<RpcState>) -> (StatusCode, Json<Value>) {
    let Some(arch) = state.archive.as_ref() else {
        return err_response(
            StatusCode::NOT_IMPLEMENTED,
            "historical-state archive not enabled on this node (set [index] capture_state_deltas = true)",
        );
    };
    match arch.reader.coverage() {
        Ok(Some((base, head))) => (
            StatusCode::OK,
            Json(json!({
                "success": true,
                "data": { "base": base, "head": head, "blocks": head - base + 1 },
            })),
        ),
        Ok(None) => (
            StatusCode::OK,
            Json(json!({
                "success": true,
                "data": Value::Null,
                "note": "archive enabled but no blocks captured yet",
            })),
        ),
        Err(e) => internal_error_response("archive coverage", e),
    }
}

// ---------------------------------------------------------------------------
// /v1/commitment — verifiable state-commitment layer ([index.commitment])
// ---------------------------------------------------------------------------

use tron_chainbase::StorageRowStore;
use tron_crypto::address::Address;
use tron_index::{leaf_path_for, CommitmentReader, EMPTY_ROOT};

/// `0x`-prefixed lowercase hex of a byte slice, matching the archive routes.
fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// Routes for the verifiable state-commitment surface. Mounted
/// unconditionally; the handlers answer `501` when no reader is attached.
pub fn commitment_router() -> Router<RpcState> {
    Router::new()
        .route("/v1/commitment/root", get(commitment_root))
        .route("/v1/commitment/status", get(commitment_status))
        .route("/v1/commitment/proof", get(commitment_proof).post(commitment_proof))
}

/// 501 body returned when `[index.commitment]` is off — the same shape the
/// archive uses for its disabled surface.
fn commitment_disabled() -> (StatusCode, Json<Value>) {
    err_response(
        StatusCode::NOT_IMPLEMENTED,
        "state-commitment layer not enabled on this node (set [index.commitment] enabled = true)",
    )
}

/// Resolve the commitment reader or short-circuit with the 501 body.
macro_rules! get_commitment {
    ($state:expr) => {
        match $state.commitment.as_ref() {
            Some(r) => r,
            None => return commitment_disabled(),
        }
    };
}

/// Map an `UndoStoreId` to its lowercase variant name for the response. The
/// inverse of [`store_from_name`].
fn store_name(store: UndoStoreId) -> &'static str {
    use UndoStoreId as Id;
    match store {
        Id::Accounts => "accounts",
        Id::Witnesses => "witnesses",
        Id::Votes => "votes",
        Id::Delegation => "delegation",
        Id::DelegatedResources => "delegatedresources",
        Id::DynProps => "dynprops",
        Id::Proposals => "proposals",
        Id::NameIndex => "nameindex",
        Id::IdIndex => "idindex",
        Id::AssetV1 => "assetv1",
        Id::AssetV2 => "assetv2",
        Id::Contracts => "contracts",
        Id::Abi => "abi",
        Id::ExchangeV1 => "exchangev1",
        Id::ExchangeV2 => "exchangev2",
        Id::MarketOrders => "marketorders",
        Id::MarketAccount => "marketaccount",
        Id::Nullifiers => "nullifiers",
        Id::MerkleTrees => "merkletrees",
        Id::Code => "code",
        Id::StorageRow => "storagerow",
        Id::ContractState => "contractstate",
        Id::BlockIndex => "blockindex",
        Id::WitnessSchedule => "witnessschedule",
        Id::DelegatedResourceAccountIndex => "delegatedresourceaccountindex",
    }
}

/// Parse a `store` param into an `UndoStoreId`: either a variant NAME
/// (case-insensitive, e.g. `accounts`, `storagerow`, `code`) or its numeric
/// discriminant (`0..24`). The numeric form goes through `UndoStoreId::from_u8`
/// so the accepted range stays in lockstep with the enum.
fn store_from_name(s: &str) -> Result<UndoStoreId, String> {
    let t = s.trim();
    if let Ok(n) = t.parse::<u8>() {
        return UndoStoreId::from_u8(n)
            .ok_or_else(|| format!("unknown store discriminant: {n} (valid range 0..=24)"));
    }
    use UndoStoreId as Id;
    let id = match t.to_ascii_lowercase().as_str() {
        "accounts" => Id::Accounts,
        "witnesses" => Id::Witnesses,
        "votes" => Id::Votes,
        "delegation" => Id::Delegation,
        "delegatedresources" => Id::DelegatedResources,
        "dynprops" => Id::DynProps,
        "proposals" => Id::Proposals,
        "nameindex" => Id::NameIndex,
        "idindex" => Id::IdIndex,
        "assetv1" => Id::AssetV1,
        "assetv2" => Id::AssetV2,
        "contracts" => Id::Contracts,
        "abi" => Id::Abi,
        "exchangev1" => Id::ExchangeV1,
        "exchangev2" => Id::ExchangeV2,
        "marketorders" => Id::MarketOrders,
        "marketaccount" => Id::MarketAccount,
        "nullifiers" => Id::Nullifiers,
        "merkletrees" => Id::MerkleTrees,
        "code" => Id::Code,
        "storagerow" => Id::StorageRow,
        "contractstate" => Id::ContractState,
        "blockindex" => Id::BlockIndex,
        "witnessschedule" => Id::WitnessSchedule,
        "delegatedresourceaccountindex" => Id::DelegatedResourceAccountIndex,
        other => return Err(format!("unknown store name: {other}")),
    };
    Ok(id)
}

/// Decode a `0x`-optional hex string into raw bytes.
fn parse_hex_key(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    let stripped = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    hex::decode(stripped).map_err(|e| format!("bad hex key: {e}"))
}

/// Compose the raw `StorageRow` key for `(address, slot)` byte-for-byte the
/// way `/v1/archive/storage` does (via `eth_getStorageAt` →
/// [`StorageRowStore::compose_key`], v2 layout, plain `sha3(address)` prefix),
/// so a proof key matches the live read key exactly. `slot` is `0x`-optional,
/// a QUANTITY or a full 32-byte word, left-padded to 32 bytes.
fn storage_row_key(address: &str, slot: &str) -> Result<Vec<u8>, String> {
    let addr = parse_tron_address(address)?;
    let stripped = slot
        .trim()
        .strip_prefix("0x")
        .or_else(|| slot.trim().strip_prefix("0X"))
        .unwrap_or_else(|| slot.trim());
    if stripped.len() > 64 {
        return Err("slot exceeds 32 bytes".into());
    }
    let padded = format!("{stripped:0>64}");
    let bytes = hex::decode(&padded).map_err(|e| format!("bad slot hex: {e}"))?;
    let mut slot_word = [0u8; 32];
    slot_word.copy_from_slice(&bytes);
    let key = StorageRowStore::compose_key(&Address::from_raw(addr), &slot_word);
    Ok(key.to_vec())
}

/// Resolve the `(store, raw_key)` pair a `/proof` request names, applying the
/// `account=` and `address`+`slot` sugar. `field` reads a param from the body
/// (when present) else the query string (body wins, mirroring the archive
/// handlers).
fn resolve_proof_target(
    field: impl Fn(&str) -> Option<String>,
) -> Result<(UndoStoreId, Vec<u8>), String> {
    // Sugar 1: `account=<T-addr|41-hex>` ⇒ Accounts store, 21-byte raw key.
    if let Some(account) = field("account") {
        let addr = parse_tron_address(&account)?;
        return Ok((UndoStoreId::Accounts, addr.to_vec()));
    }
    // Sugar 2: `address`+`slot` ⇒ StorageRow store, composite raw key.
    match (field("address"), field("slot")) {
        (Some(address), Some(slot)) => {
            let key = storage_row_key(&address, &slot)?;
            return Ok((UndoStoreId::StorageRow, key));
        }
        (Some(_), None) => return Err("'address' requires 'slot' (contract storage sugar)".into()),
        (None, Some(_)) => return Err("'slot' requires 'address' (contract storage sugar)".into()),
        (None, None) => {}
    }
    // Explicit form: `store` (name or discriminant) + `key` (raw hex).
    let store = field("store").ok_or("missing 'store' parameter")?;
    let store = store_from_name(&store)?;
    let key = field("key").ok_or("missing 'key' parameter")?;
    let key = parse_hex_key(&key)?;
    Ok((store, key))
}

/// `GET /v1/commitment/root` — the current committed root and the height it
/// commits to. By design the height trails the live head by
/// ~`confirmation_lag_blocks` (the builder folds only past-finality blocks),
/// so the root is never a reorg-able tip; `height` is `null` and a
/// `bootstrapping` note is returned before the first committed height.
async fn commitment_root(State(state): State<RpcState>) -> (StatusCode, Json<Value>) {
    let reader = get_commitment!(state);
    // `provisional` warns a cross-node comparator that the tree has not yet
    // converged after a (re-)bootstrap, so this root matches no canonical
    // height and must not be compared. Best-effort; a read error defaults to
    // not-provisional (the height/root read below would surface a real fault).
    let provisional = reader.provisional().unwrap_or(false);
    match reader.root() {
        Ok((height, root)) => {
            // The reader returns `-1` before the first commit (still
            // bootstrapping / no folded height yet) — report `height: null`.
            if height < 0 {
                (
                    StatusCode::OK,
                    Json(json!({
                        "success": true,
                        "data": {
                            "height": Value::Null,
                            "root": hex0x(&root),
                            "provisional": provisional,
                            "note": "commitment bootstrapping",
                        },
                    })),
                )
            } else {
                (
                    StatusCode::OK,
                    Json(json!({
                        "success": true,
                        "data": {
                            "height": height,
                            "root": hex0x(&root),
                            "provisional": provisional,
                        },
                    })),
                )
            }
        }
        Err(e) => internal_error_response("commitment root", e),
    }
}

/// `GET /v1/commitment/status` — the committed height/root, the live head the
/// builder has seen, the configured confirmation lag, and bootstrap progress.
/// `committed_height` trails `head_height` by ~`confirmation_lag_blocks`.
async fn commitment_status(State(state): State<RpcState>) -> (StatusCode, Json<Value>) {
    let reader = get_commitment!(state);
    match reader.status() {
        Ok(s) => (
            StatusCode::OK,
            Json(json!({
                "success": true,
                "data": {
                    "committed_height": s.committed_height,
                    "head_height": s.head_height,
                    "confirmation_lag_blocks": s.confirmation_lag_blocks,
                    "root": hex0x(&s.root),
                    "bootstrapping": s.bootstrapping,
                    "bootstrap_keys_done": s.bootstrap_keys_done,
                    "provisional": s.provisional,
                    "empty_root": hex0x(&EMPTY_ROOT),
                },
            })),
        ),
        Err(e) => internal_error_response("commitment status", e),
    }
}

/// `GET|POST /v1/commitment/proof` — an inclusion/exclusion proof for a state
/// key against the current committed root. Params come from query (GET) or the
/// JSON body (POST, body wins): `store` (variant name or discriminant) + `key`
/// (raw store key, `0x`-optional hex), or the `account=` / `address`+`slot`
/// sugar. The response carries the served root + height; a zero-trust client
/// recomputes `leaf_path = keccak256(store_byte ‖ key)`, walks the proof to a
/// root, and checks it equals `root` (and, for inclusion, that
/// `keccak256(value) == value_hash`).
async fn commitment_proof(
    State(state): State<RpcState>,
    Query(q): Query<HashMap<String, String>>,
    body: Option<Json<Value>>,
) -> (StatusCode, Json<Value>) {
    let reader: &CommitmentReader = get_commitment!(state);
    let body = body.map(|Json(b)| b);
    let field = |name: &str| -> Option<String> {
        body.as_ref()
            .and_then(|b| b.get(name))
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| q.get(name).cloned())
    };
    let (store, raw_key) = match resolve_proof_target(field) {
        Ok(t) => t,
        Err(e) => return err_response(StatusCode::BAD_REQUEST, e),
    };

    // One self-consistent (height, root, proof) triple: the served root is the
    // one the proof reconstructs to, so the response always verifies even if
    // the background builder folds a block during the walk.
    let (height, root, proof) = match reader.prove_consistent(store, &raw_key) {
        Ok(t) => t,
        Err(e) => return internal_error_response("commitment proof", e),
    };

    let leaf_path = leaf_path_for(store, &raw_key);
    let included = proof.leaf_value_hash.is_some();
    let mut data = json!({
        "height": if height < 0 { Value::Null } else { json!(height) },
        "root": hex0x(&root),
        "included": included,
        "store": store_name(store),
        "key": hex0x(&raw_key),
        "leaf_path": hex0x(&leaf_path),
        "proof": {
            "sibling_mask": hex0x(&proof.sibling_mask),
            "siblings": proof.siblings.iter().map(|s| hex0x(s)).collect::<Vec<_>>(),
        },
    });
    // Inclusion proofs carry the value hash. The raw value is not held by the
    // commitment reader (the leaf stores only `keccak256(value)`), so `value`
    // is omitted; a client fetches it independently (e.g. via `/v1/archive`)
    // and checks `keccak256(value) == value_hash`.
    if let Some(vh) = proof.leaf_value_hash {
        data["value_hash"] = json!(hex0x(&vh));
    }
    (StatusCode::OK, Json(json!({ "success": true, "data": data })))
}

#[cfg(test)]
mod archive_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use tron_chainbase::MemBackend;
    use tron_index::ArchiveWriter;

    fn mem() -> Arc<dyn KvBackend> {
        Arc::new(MemBackend::new())
    }

    /// A fresh `RpcState` with no archive attached.
    fn fresh_state() -> RpcState {
        RpcState::new(mem(), mem(), mem(), mem(), mem(), 11_111)
    }

    /// A `RpcState` whose archive covers `[base, base + 1]`. The
    /// writer's first captured block sets `base = head = height - 1`,
    /// then advances `head` to `height`; capturing block `base + 1`
    /// over empty deltas therefore yields coverage `[base, base + 1]`.
    /// Live backends are empty `MemBackend`s, so every at-height read
    /// falls through to "absent".
    fn state_with_archive(base: i64) -> RpcState {
        let archive_backend = mem();
        let writer = ArchiveWriter::new(archive_backend.clone(), None, Vec::new());
        writer.check_or_init().expect("init archive");
        writer.on_block_applied(base + 1, Some(&[])).expect("capture");
        let reader = ArchiveReader::new(archive_backend);
        assert_eq!(reader.coverage().unwrap(), Some((base, base + 1)));
        // One live backend per store the at-height views might touch;
        // empty MemBackends are enough to exercise routing + coverage.
        let backends: Vec<(UndoStoreId, Arc<dyn KvBackend>)> = [
            UndoStoreId::Accounts,
            UndoStoreId::DynProps,
            UndoStoreId::StorageRow,
            UndoStoreId::Code,
            UndoStoreId::Contracts,
        ]
        .iter()
        .map(|id| (*id, mem()))
        .collect();
        fresh_state().with_archive(ArchiveApiState::new(reader, backends))
    }

    async fn get(state: RpcState, uri: &str) -> (StatusCode, Value) {
        let app = crate::http_rest::router(state);
        let resp = app
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, json)
    }

    #[test]
    fn rpc_error_status_mapping() {
        use crate::methods::RpcError;
        assert_eq!(
            rpc_error_response(RpcError::invalid_params("x")).0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            rpc_error_response(RpcError::invalid_request("x")).0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            rpc_error_response(RpcError::internal("x")).0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        // The clean message is surfaced, not the `{:?}` struct dump.
        let (_, body) = rpc_error_response(RpcError::invalid_params("bad slot"));
        assert_eq!(body.0["error"], "bad slot");
    }

    #[tokio::test]
    async fn archive_disabled_returns_501_on_every_route() {
        for uri in [
            "/v1/archive/coverage",
            "/v1/archive/account?address=410000000000000000000000000000000000000000&block=5",
            "/v1/archive/accountresource?address=410000000000000000000000000000000000000000&block=5",
            "/v1/archive/storage?address=410000000000000000000000000000000000000000&slot=0x0&block=5",
        ] {
            let (status, body) = get(fresh_state(), uri).await;
            assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "uri={uri}");
            assert_eq!(body["success"], Value::Bool(false), "uri={uri}");
        }
    }

    #[tokio::test]
    async fn coverage_endpoint_reports_the_window() {
        let (status, body) = get(state_with_archive(100), "/v1/archive/coverage").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["success"], Value::Bool(true));
        assert_eq!(body["data"]["base"], 100);
        assert_eq!(body["data"]["head"], 101);
        assert_eq!(body["data"]["blocks"], 2);
    }

    #[tokio::test]
    async fn out_of_range_block_is_rejected_with_the_window() {
        let addr = "410000000000000000000000000000000000000000";
        // Above head.
        let (status, body) =
            get(state_with_archive(100), &format!("/v1/archive/account?address={addr}&block=999")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["success"], Value::Bool(false));
        assert!(
            body["error"].as_str().unwrap().contains("[100, 101]"),
            "error names the window: {body:?}"
        );
        // Below base.
        let (status, _) =
            get(state_with_archive(100), &format!("/v1/archive/account?address={addr}&block=1")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn missing_required_params_are_400() {
        let st = state_with_archive(100);
        // Missing block.
        let (status, _) = get(
            st.clone(),
            "/v1/archive/account?address=410000000000000000000000000000000000000000",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        // Missing address.
        let (status, _) = get(st.clone(), "/v1/archive/account?block=100").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        // Storage missing slot.
        let (status, _) = get(
            st,
            "/v1/archive/storage?address=410000000000000000000000000000000000000000&block=100",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn in_range_account_read_succeeds_and_is_null_for_absent() {
        // Live backends are empty, so an in-range account read resolves
        // to an absent account — `get_account` returns JSON null. The
        // point is the route runs end-to-end at a historical height.
        let addr = "410000000000000000000000000000000000000000";
        let (status, body) =
            get(state_with_archive(100), &format!("/v1/archive/account?address={addr}&block=100")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["success"], Value::Bool(true));
        assert_eq!(body["block"], 100);
        assert_eq!(body["data"], Value::Null);
    }

    #[tokio::test]
    async fn in_range_storage_read_returns_zero_word_for_absent_slot() {
        let addr = "410000000000000000000000000000000000000000";
        // Slot accepted both as a `0x` QUANTITY and as bare hex.
        for slot in ["0x0", "0", "0x00000000000000000000000000000000000000000000000000000000000000ff"]
        {
            let uri = format!("/v1/archive/storage?address={addr}&slot={slot}&block=100");
            let (status, body) = get(state_with_archive(100), &uri).await;
            assert_eq!(status, StatusCode::OK, "slot={slot}");
            assert_eq!(body["success"], Value::Bool(true), "slot={slot}");
            // Absent slot → 32 zero bytes.
            assert_eq!(
                body["data"].as_str().unwrap(),
                "0x0000000000000000000000000000000000000000000000000000000000000000",
                "slot={slot}"
            );
        }
    }
}

#[cfg(test)]
mod commitment_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use tron_chainbase::MemBackend;
    use tron_index::{
        verify_proof, CommitmentBuilder, CommitmentCounters, CommitmentDeltaRef, CommitmentReader,
        CommitmentStore, NodeHash, Proof, ProofOutcome,
    };

    /// Confirmation lag used across these tests. Small so a short fold stream
    /// commits a few heights while leaving a tip buffer.
    const K: u64 = 2;

    fn mem() -> Arc<dyn KvBackend> {
        Arc::new(MemBackend::new())
    }

    /// A fresh `RpcState` with no commitment reader attached.
    fn fresh_state() -> RpcState {
        RpcState::new(mem(), mem(), mem(), mem(), mem(), 11_111)
    }

    fn delta(store: UndoStoreId, key: &[u8], val: &[u8]) -> CommitmentDeltaRef {
        CommitmentDeltaRef {
            store,
            key: key.to_vec(),
            after: Some(val.to_vec()),
        }
    }

    /// Build a `CommitmentReader` over an in-memory commitment store, folding a
    /// supplied set of blocks (the engine's own builder path). Returns the
    /// reader plus the raw key/value pairs that ended up COMMITTED (folded
    /// below the confirmation ceiling), so callers can prove against them.
    ///
    /// `anchor` is the bootstrap anchor (empty live surface ⇒ empty tree at
    /// `anchor`); blocks are ingested as heights `anchor+1..`.
    fn reader_with_blocks(
        anchor: i64,
        blocks: &[(i64, Vec<CommitmentDeltaRef>)],
    ) -> CommitmentReader {
        let store = CommitmentStore::new(mem());
        store.check_or_init().expect("init commitment store");
        let counters = Arc::new(CommitmentCounters::new());
        let mut builder =
            CommitmentBuilder::new(store, Vec::new(), K, counters).expect("build commitment");
        builder.bootstrap_or_resume(anchor).expect("bootstrap");
        for (h, deltas) in blocks {
            builder.ingest(*h, deltas.clone()).expect("ingest");
        }
        builder.reader()
    }

    fn state_with_commitment(reader: CommitmentReader) -> RpcState {
        fresh_state().with_commitment(reader)
    }

    async fn get(state: RpcState, uri: &str) -> (StatusCode, Value) {
        let app = crate::http_rest::router(state);
        let resp = app
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, json)
    }

    async fn post(state: RpcState, uri: &str, body: Value) -> (StatusCode, Value) {
        let app = crate::http_rest::router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, json)
    }

    /// Decode a `0x…64hex` field into a `NodeHash`.
    fn node_hash(v: &Value) -> NodeHash {
        let s = v.as_str().expect("hex string");
        let raw = hex::decode(s.strip_prefix("0x").unwrap_or(s)).expect("hex");
        let mut h = [0u8; 32];
        h.copy_from_slice(&raw);
        h
    }

    /// Reconstruct a `Proof` from a `/proof` response body's `data`, so the
    /// served proof can be fed back into `verify_proof`.
    fn proof_from_data(data: &Value) -> Proof {
        let path = node_hash(&data["leaf_path"]);
        let leaf_value_hash = data
            .get("value_hash")
            .filter(|v| !v.is_null())
            .map(node_hash);
        let mut sibling_mask = [0u8; 32];
        let mask = hex::decode(
            data["proof"]["sibling_mask"]
                .as_str()
                .unwrap()
                .strip_prefix("0x")
                .unwrap(),
        )
        .unwrap();
        sibling_mask.copy_from_slice(&mask);
        let siblings: Vec<NodeHash> = data["proof"]["siblings"]
            .as_array()
            .unwrap()
            .iter()
            .map(node_hash)
            .collect();
        Proof {
            path,
            leaf_value_hash,
            sibling_mask,
            siblings,
        }
    }

    #[test]
    fn store_name_parsing_round_trips_names_and_discriminants() {
        for n in 0u8..=24 {
            let id = UndoStoreId::from_u8(n).unwrap();
            // Name round-trips through the parser.
            assert_eq!(store_from_name(store_name(id)).unwrap(), id);
            // Numeric discriminant parses to the same variant.
            assert_eq!(store_from_name(&n.to_string()).unwrap(), id);
        }
        // Case-insensitive names.
        assert_eq!(store_from_name("ACCOUNTS").unwrap(), UndoStoreId::Accounts);
        assert_eq!(store_from_name("StorageRow").unwrap(), UndoStoreId::StorageRow);
        // Out-of-range discriminant and unknown name are errors.
        assert!(store_from_name("25").is_err());
        assert!(store_from_name("nope").is_err());
    }

    #[test]
    fn storage_row_sugar_matches_eth_get_storage_at_key() {
        // The sugar must compose the exact key the live `eth_getStorageAt`
        // path uses, so a proof key matches the live read key byte-for-byte.
        let addr = "410000000000000000000000000000000000000001";
        let from_sugar = storage_row_key(addr, "0x5").unwrap();
        let parsed = parse_tron_address(addr).unwrap();
        let mut slot = [0u8; 32];
        slot[31] = 0x5;
        let expected =
            tron_chainbase::StorageRowStore::compose_key(&Address::from_raw(parsed), &slot);
        assert_eq!(from_sugar, expected.to_vec());
        // Bare-hex and `0x` QUANTITY forms agree.
        assert_eq!(storage_row_key(addr, "5").unwrap(), from_sugar);
    }

    #[tokio::test]
    async fn disabled_returns_501_on_every_route() {
        for uri in [
            "/v1/commitment/root",
            "/v1/commitment/status",
            "/v1/commitment/proof?store=accounts&key=0x00",
        ] {
            let (status, body) = get(fresh_state(), uri).await;
            assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "uri={uri}");
            assert_eq!(body["success"], Value::Bool(false), "uri={uri}");
            assert!(
                body["error"]
                    .as_str()
                    .unwrap()
                    .contains("[index.commitment] enabled = true"),
                "uri={uri}: {body:?}"
            );
        }
    }

    #[tokio::test]
    async fn root_is_bootstrapping_before_first_commit() {
        // A fresh store with no committed height: the reader reports height -1
        // ⇒ the route returns null height + a bootstrapping note + EMPTY_ROOT.
        let store = CommitmentStore::new(mem());
        store.check_or_init().unwrap();
        let reader = CommitmentReader::new(store, Arc::new(CommitmentCounters::new()), K);
        let (status, body) =
            get(state_with_commitment(reader), "/v1/commitment/root").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["success"], Value::Bool(true));
        assert_eq!(body["data"]["height"], Value::Null);
        assert_eq!(body["data"]["note"], "commitment bootstrapping");
        assert_eq!(body["data"]["root"].as_str().unwrap(), hex0x(&EMPTY_ROOT));
    }

    #[tokio::test]
    async fn root_and_status_report_committed_height_and_lag() {
        // Fold heights 1..=5 over K=2: committed_height = 5 - 2 = 3, head = 5.
        let blocks: Vec<(i64, Vec<CommitmentDeltaRef>)> = (1..=5i64)
            .map(|h| {
                (
                    h,
                    vec![delta(UndoStoreId::Accounts, &h.to_be_bytes(), &[h as u8])],
                )
            })
            .collect();
        let reader = reader_with_blocks(0, &blocks);

        let (status, body) =
            get(state_with_commitment(reader.clone()), "/v1/commitment/root").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"]["height"], 3);
        let root_hex = body["data"]["root"].as_str().unwrap().to_owned();
        assert!(root_hex.starts_with("0x") && root_hex.len() == 66);
        assert_ne!(root_hex, hex0x(&EMPTY_ROOT));

        let (status, body) =
            get(state_with_commitment(reader), "/v1/commitment/status").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"]["committed_height"], 3);
        assert_eq!(body["data"]["head_height"], 5);
        assert_eq!(body["data"]["confirmation_lag_blocks"], K);
        assert_eq!(body["data"]["bootstrapping"], Value::Bool(false));
        assert_eq!(body["data"]["root"].as_str().unwrap(), root_hex);
        assert_eq!(body["data"]["empty_root"].as_str().unwrap(), hex0x(&EMPTY_ROOT));
    }

    #[tokio::test]
    async fn proof_inclusion_round_trips_through_verify_proof() {
        // Commit a known Accounts key (height 1, well below the K=2 ceiling
        // once head reaches 5). The served proof + value must verify against
        // the served root.
        let key = 1i64.to_be_bytes().to_vec();
        let value = b"committed-account-value".to_vec();
        let mut blocks: Vec<(i64, Vec<CommitmentDeltaRef>)> = vec![(
            1,
            vec![CommitmentDeltaRef {
                store: UndoStoreId::Accounts,
                key: key.clone(),
                after: Some(value.clone()),
            }],
        )];
        for h in 2..=5i64 {
            blocks.push((
                h,
                vec![delta(UndoStoreId::Accounts, &h.to_be_bytes(), &[h as u8])],
            ));
        }
        let reader = reader_with_blocks(0, &blocks);

        let uri = format!("/v1/commitment/proof?store=accounts&key=0x{}", hex::encode(&key));
        let (status, body) = get(state_with_commitment(reader), &uri).await;
        assert_eq!(status, StatusCode::OK);
        let data = &body["data"];
        assert_eq!(data["included"], Value::Bool(true));
        assert_eq!(data["store"], "accounts");
        assert_eq!(data["key"].as_str().unwrap(), hex0x(&key));
        assert!(data.get("value_hash").is_some());
        // The served proof verifies against the served root with the value.
        let root = node_hash(&data["root"]);
        let proof = proof_from_data(data);
        assert_eq!(verify_proof(&root, &proof, Some(&value)), ProofOutcome::Included);
        // Wrong value → Invalid.
        assert_eq!(
            verify_proof(&root, &proof, Some(b"wrong")),
            ProofOutcome::Invalid
        );
    }

    #[tokio::test]
    async fn proof_exclusion_round_trips_through_verify_proof() {
        let blocks: Vec<(i64, Vec<CommitmentDeltaRef>)> = (1..=5i64)
            .map(|h| {
                (
                    h,
                    vec![delta(UndoStoreId::Accounts, &h.to_be_bytes(), &[h as u8])],
                )
            })
            .collect();
        let reader = reader_with_blocks(0, &blocks);

        // A key that was never folded ⇒ exclusion proof.
        let absent = hex::encode(b"never-committed-key");
        let uri = format!("/v1/commitment/proof?store=accounts&key=0x{absent}");
        let (status, body) = get(state_with_commitment(reader), &uri).await;
        assert_eq!(status, StatusCode::OK);
        let data = &body["data"];
        assert_eq!(data["included"], Value::Bool(false));
        // Exclusion omits value_hash (and value).
        assert!(data.get("value_hash").is_none());
        assert!(data.get("value").is_none());
        let root = node_hash(&data["root"]);
        let proof = proof_from_data(data);
        assert_eq!(verify_proof(&root, &proof, None), ProofOutcome::Excluded);
    }

    #[tokio::test]
    async fn account_sugar_proves_the_accounts_key() {
        // Fold an Accounts row keyed by a 21-byte address; the `account=`
        // sugar must resolve to that exact leaf.
        let addr_hex = "41a614f803b6fd780986a42c78ec9c7f77e6ded13c";
        let raw_addr = parse_tron_address(addr_hex).unwrap().to_vec();
        let value = b"acct".to_vec();
        let mut blocks: Vec<(i64, Vec<CommitmentDeltaRef>)> = vec![(
            1,
            vec![CommitmentDeltaRef {
                store: UndoStoreId::Accounts,
                key: raw_addr.clone(),
                after: Some(value.clone()),
            }],
        )];
        for h in 2..=5i64 {
            blocks.push((
                h,
                vec![delta(UndoStoreId::Accounts, &h.to_be_bytes(), &[h as u8])],
            ));
        }
        let reader = reader_with_blocks(0, &blocks);

        // Base58 / 41-hex both go through parse_tron_address; use the 41-hex.
        let uri = format!("/v1/commitment/proof?account={addr_hex}");
        let (status, body) = get(state_with_commitment(reader), &uri).await;
        assert_eq!(status, StatusCode::OK);
        let data = &body["data"];
        assert_eq!(data["store"], "accounts");
        assert_eq!(data["key"].as_str().unwrap(), hex0x(&raw_addr));
        assert_eq!(data["included"], Value::Bool(true));
        let root = node_hash(&data["root"]);
        let proof = proof_from_data(data);
        assert_eq!(verify_proof(&root, &proof, Some(&value)), ProofOutcome::Included);
    }

    #[tokio::test]
    async fn address_slot_sugar_proves_the_storage_row_key() {
        // Fold a StorageRow row at the exact composed key, then prove it via
        // the address+slot sugar.
        let addr_hex = "41a614f803b6fd780986a42c78ec9c7f77e6ded13c";
        let storage_key = storage_row_key(addr_hex, "0x7").unwrap();
        let value = vec![0x42u8; 32];
        let mut blocks: Vec<(i64, Vec<CommitmentDeltaRef>)> = vec![(
            1,
            vec![CommitmentDeltaRef {
                store: UndoStoreId::StorageRow,
                key: storage_key.clone(),
                after: Some(value.clone()),
            }],
        )];
        for h in 2..=5i64 {
            blocks.push((
                h,
                vec![delta(UndoStoreId::Accounts, &h.to_be_bytes(), &[h as u8])],
            ));
        }
        let reader = reader_with_blocks(0, &blocks);

        // POST with body params (body wins) exercises the JSON path too.
        let (status, body) = post(
            state_with_commitment(reader),
            "/v1/commitment/proof",
            json!({ "address": addr_hex, "slot": "0x7" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let data = &body["data"];
        assert_eq!(data["store"], "storagerow");
        assert_eq!(data["key"].as_str().unwrap(), hex0x(&storage_key));
        assert_eq!(data["included"], Value::Bool(true));
        let root = node_hash(&data["root"]);
        let proof = proof_from_data(data);
        assert_eq!(verify_proof(&root, &proof, Some(&value)), ProofOutcome::Included);
    }

    #[tokio::test]
    async fn numeric_store_discriminant_is_accepted() {
        let key = 1i64.to_be_bytes().to_vec();
        let value = b"v".to_vec();
        let mut blocks: Vec<(i64, Vec<CommitmentDeltaRef>)> = vec![(
            1,
            vec![CommitmentDeltaRef {
                store: UndoStoreId::Accounts,
                key: key.clone(),
                after: Some(value.clone()),
            }],
        )];
        for h in 2..=5i64 {
            blocks.push((
                h,
                vec![delta(UndoStoreId::Accounts, &h.to_be_bytes(), &[h as u8])],
            ));
        }
        let reader = reader_with_blocks(0, &blocks);
        // Accounts = discriminant 0.
        let uri = format!("/v1/commitment/proof?store=0&key=0x{}", hex::encode(&key));
        let (status, body) = get(state_with_commitment(reader), &uri).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"]["store"], "accounts");
        assert_eq!(body["data"]["included"], Value::Bool(true));
    }

    #[tokio::test]
    async fn bad_proof_inputs_are_400() {
        let reader = reader_with_blocks(
            0,
            &(1..=5i64)
                .map(|h| {
                    (
                        h,
                        vec![delta(UndoStoreId::Accounts, &h.to_be_bytes(), &[h as u8])],
                    )
                })
                .collect::<Vec<_>>(),
        );
        let st = state_with_commitment(reader);
        for (uri, why) in [
            ("/v1/commitment/proof", "missing store and key"),
            ("/v1/commitment/proof?store=accounts", "missing key"),
            ("/v1/commitment/proof?key=0x00", "missing store"),
            ("/v1/commitment/proof?store=bogus&key=0x00", "unknown store name"),
            ("/v1/commitment/proof?store=99&key=0x00", "out-of-range discriminant"),
            ("/v1/commitment/proof?store=accounts&key=0xzz", "malformed hex key"),
            ("/v1/commitment/proof?account=not-an-address", "bad address"),
            ("/v1/commitment/proof?address=410000000000000000000000000000000000000001", "address without slot"),
        ] {
            let (status, body) = get(st.clone(), uri).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{why}: {uri}");
            assert_eq!(body["success"], Value::Bool(false), "{why}: {uri}");
        }
    }
}
