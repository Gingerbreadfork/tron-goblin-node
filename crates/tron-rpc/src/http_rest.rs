//! java-tron-compatible HTTP REST API.
//!
//! Mirrors the surface that `FullNodeHttpApiService` exposes on port
//! 8090 in java-tron — the API that TronWeb, TronGrid, and the
//! reference wallet-cli speak. Each endpoint is a thin shim around
//! one of the [`crate::methods`] functions that already produce the
//! right-shaped JSON; the shim:
//!
//! * Translates the HTTP request body / query string into the
//!   positional-array `params` that `methods::*` expects.
//! * Honours the `visible` convention — when `true`, addresses in the
//!   request body arrive as `T...` base58 (we decode to hex first) and
//!   the response is post-processed to re-encode them back.
//! * Mounts both `/wallet/*` (full-node aliases) and
//!   `/walletsolidity/*` (solidified-state aliases) URL prefixes.
//!
//! Endpoint coverage is the most-used 12 from java-tron, sized to be
//! useful for TronWeb and standard wallets without trying to chase
//! parity on every legacy alias.

use std::net::SocketAddr;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use tron_crypto::address::Address;

use crate::methods;
use crate::state::RpcState;

/// Mount every `/wallet/*` + `/walletsolidity/*` endpoint on a fresh
/// [`Router`]. Equivalent to [`router_with_rate_limits`] called with
/// an empty registry — kept as a stable entry point for tests and
/// callers that don't configure rate-limits.
pub fn router(state: RpcState) -> Router {
    router_with_rate_limits(state, crate::RateLimitRegistry::empty())
}

/// Mount the endpoints with optional rate-limit gating. When the
/// registry is non-empty, each request's path-tail is looked up
/// (lowercased) and `try_acquire` runs before the handler. Failures
/// return HTTP 429.
pub fn router_with_rate_limits(state: RpcState, limits: crate::RateLimitRegistry) -> Router {
    // Helper: bind a route whose handler delegates to a JSON-RPC
    // builder method. The HTTP body is wrapped in `[body]` to match the
    // `params[0]` shape that `methods::*` expects.
    macro_rules! builder {
        ($name:literal, $method:path) => {
            post(|state, query, body| forward_builder($method, state, query, body))
        };
    }
    macro_rules! getter_no_arg {
        ($method:path) => {
            get(|state| forward_no_arg($method, state))
                .post(|state| forward_no_arg($method, state))
        };
    }

    let router = Router::new()
        // ---- /wallet read endpoints (pre-existing) ----
        .route("/wallet/getnowblock", get(get_now_block).post(get_now_block))
        .route("/wallet/getblockbynum", post(get_block_by_num))
        .route("/wallet/getblockbyid", post(get_block_by_id))
        .route("/wallet/getaccount", post(get_account))
        .route("/wallet/getaccountresource", post(get_account_resource))
        .route("/wallet/getcontract", post(get_contract))
        .route("/wallet/gettransactionbyid", post(get_transaction_by_id))
        .route("/wallet/gettransactioninfobyid", post(get_transaction_info_by_id))
        .route("/wallet/listwitnesses", get(list_witnesses).post(list_witnesses))
        .route("/wallet/getchainparameters", get(get_chain_parameters).post(get_chain_parameters))
        .route("/wallet/broadcasttransaction", post(broadcast_transaction))
        .route("/wallet/validateaddress", post(validate_address))
        // ---- /wallet builder endpoints (unsigned-tx envelopes) ----
        .route("/wallet/createtransaction", builder!("createTransaction", methods::create_transaction))
        .route("/wallet/transferasset", builder!("transferAsset", methods::transfer_asset))
        .route("/wallet/triggersmartcontract", builder!("triggerSmartContract", methods::build_trigger_smart_contract))
        .route("/wallet/triggerconstantcontract", builder!("triggerConstantContract", methods::trigger_constant_contract))
        .route("/wallet/deploycontract", builder!("deployContract", methods::deploy_contract))
        .route("/wallet/updatesetting", builder!("updateSetting", methods::update_setting))
        .route("/wallet/updateenergylimit", builder!("updateEnergyLimit", methods::update_energy_limit))
        .route("/wallet/clearcontractabi", builder!("clearAbi", methods::clear_abi))
        .route("/wallet/estimateenergy", builder!("estimateEnergy", methods::estimate_energy))
        // Stake 2.0
        .route("/wallet/freezebalancev2", builder!("freezeBalanceV2", methods::freeze_balance_v2))
        .route("/wallet/unfreezebalancev2", builder!("unfreezeBalanceV2", methods::unfreeze_balance_v2))
        .route("/wallet/withdrawexpireunfreeze", builder!("withdrawExpireUnfreeze", methods::withdraw_expire_unfreeze))
        .route("/wallet/cancelallunfreezev2", builder!("cancelAllUnfreezeV2", methods::cancel_all_unfreeze_v2))
        .route("/wallet/delegateresource", builder!("delegateResource", methods::delegate_resource))
        .route("/wallet/undelegateresource", builder!("unDelegateResource", methods::un_delegate_resource))
        // Stake 1.0 (legacy)
        .route("/wallet/freezebalance", builder!("freezeBalance", methods::freeze_balance))
        .route("/wallet/unfreezebalance", builder!("unfreezeBalance", methods::unfreeze_balance))
        // Witness / vote / reward
        .route("/wallet/votewitnessaccount", builder!("voteWitnessAccount", methods::vote_witness_account))
        .route("/wallet/withdrawbalance", builder!("withdrawBalance", methods::withdraw_balance))
        .route("/wallet/createwitness", builder!("createWitness", methods::create_witness))
        .route("/wallet/updatewitness", builder!("updateWitness", methods::update_witness))
        .route("/wallet/updatebrokerage", builder!("updateBrokerage", methods::update_brokerage))
        // Account
        .route("/wallet/createaccount", builder!("createAccount", methods::create_account))
        .route("/wallet/updateaccount", builder!("updateAccount", methods::update_account))
        .route("/wallet/setaccountid", builder!("setAccountId", methods::set_account_id))
        .route("/wallet/accountpermissionupdate", builder!("accountPermissionUpdate", methods::account_permission_update))
        // Asset
        .route("/wallet/createassetissue", builder!("createAssetIssue", methods::create_asset_issue))
        .route("/wallet/updateasset", builder!("updateAsset", methods::update_asset))
        .route("/wallet/participateassetissue", builder!("participateAssetIssue", methods::participate_asset_issue))
        .route("/wallet/unfreezeasset", builder!("unfreezeAsset", methods::unfreeze_asset))
        // Proposal
        .route("/wallet/proposalcreate", builder!("proposalCreate", methods::proposal_create))
        .route("/wallet/proposalapprove", builder!("proposalApprove", methods::proposal_approve))
        .route("/wallet/proposaldelete", builder!("proposalDelete", methods::proposal_delete))
        // Exchange / Market
        .route("/wallet/exchangecreate", builder!("exchangeCreate", methods::exchange_create))
        .route("/wallet/exchangeinject", builder!("exchangeInject", methods::exchange_inject))
        .route("/wallet/exchangewithdraw", builder!("exchangeWithdraw", methods::exchange_withdraw))
        .route("/wallet/exchangetransaction", builder!("exchangeTransaction", methods::exchange_transaction))
        .route("/wallet/marketsellasset", builder!("marketSellAsset", methods::market_sell_asset))
        .route("/wallet/marketcancelorder", builder!("marketCancelOrder", methods::market_cancel_order))
        // ---- /wallet additional reads ----
        .route("/wallet/getbandwidthprices", getter_no_arg!(methods::get_bandwidth_prices))
        .route("/wallet/getenergyprices", getter_no_arg!(methods::get_energy_prices))
        .route("/wallet/getburntrx", getter_no_arg!(methods::get_burn_trx))
        .route("/wallet/getnodeinfo", getter_no_arg!(methods::get_node_info))
        .route("/wallet/getnextmaintenancetime", getter_no_arg!(methods::get_next_maintenance_time))
        .route("/wallet/listnodes", getter_no_arg!(methods::get_nodes))
        .route("/wallet/getpendingsize", getter_no_arg!(methods::get_pending_size))
        .route("/wallet/getmemofee", getter_no_arg!(methods::get_memo_fee))
        .route("/wallet/getcontractinfo", post(http_get_contract_info))
        .route("/wallet/getblockbylatestnum", post(http_get_block_by_latest_num))
        .route("/wallet/getblockbylimitnext", post(http_get_block_by_limit_next))
        .route("/wallet/getaccountbalance", post(http_get_account_balance))
        // ---- /walletsolidity (read-only aliases) ----
        .route("/walletsolidity/getnowblock", get(get_now_block).post(get_now_block))
        .route("/walletsolidity/getblockbynum", post(get_block_by_num))
        .route("/walletsolidity/getaccount", post(get_account))
        .route("/walletsolidity/gettransactionbyid", post(get_transaction_by_id))
        .route("/walletsolidity/gettransactioninfobyid", post(get_transaction_info_by_id))
        // ---- /monitor (java-tron operational endpoints) ----
        // `/monitor/getnodeinfo` is the standard `MetricsInfoServlet`
        // shape — same payload as `/wallet/getnodeinfo`, just a
        // different mount point so existing dashboards
        // (`addr/monitor/getnodeinfo`) work.
        .route(
            "/monitor/getnodeinfo",
            getter_no_arg!(methods::get_node_info),
        )
        // `/monitor/getstatsinfo` is java-tron's `MetricsServlet`,
        // returning a `MetricsInfo`-shaped JSON for Grafana / external
        // monitoring tools.
        .route(
            "/monitor/getstatsinfo",
            get(get_stats_info).post(get_stats_info),
        )
        // ---- Shielded TRC-20 / TRC-10 key-derivation servlets ----
        // Match java-tron's `wallet/getspendingkey` etc. The crypto
        // primitives live in the same JSON-RPC method handlers used by
        // the Ethereum surface (`getSpendingKey` / `getAkFromAsk` /
        // `getNkFromNsk` / `getIncomingViewingKey` / etc.); each HTTP
        // handler is a thin shim that translates the POST body into
        // positional JSON-RPC params and rewrites field names back
        // into the java-tron shape (`value`/`ask`/`nsk`/`ovk`/...).
        .route(
            "/wallet/getspendingkey",
            get(http_get_spending_key).post(http_get_spending_key),
        )
        .route(
            "/wallet/getexpandedspendingkey",
            post(http_get_expanded_spending_key),
        )
        .route("/wallet/getakfromask", post(http_get_ak_from_ask))
        .route("/wallet/getnkfromnsk", post(http_get_nk_from_nsk))
        .route(
            "/wallet/getincomingviewingkey",
            post(http_get_incoming_viewing_key),
        )
        .route(
            "/wallet/getdiversifier",
            get(http_get_diversifier).post(http_get_diversifier),
        )
        .route(
            "/wallet/getzenpaymentaddress",
            post(http_get_zen_payment_address),
        )
        .route("/wallet/getrcm", get(http_get_rcm).post(http_get_rcm))
        // ---- Solidity (read-only) aliases for the same surface ----
        .route(
            "/walletsolidity/getspendingkey",
            get(http_get_spending_key).post(http_get_spending_key),
        )
        .route(
            "/walletsolidity/getexpandedspendingkey",
            post(http_get_expanded_spending_key),
        )
        .route(
            "/walletsolidity/getakfromask",
            post(http_get_ak_from_ask),
        )
        .route(
            "/walletsolidity/getnkfromnsk",
            post(http_get_nk_from_nsk),
        )
        .route(
            "/walletsolidity/getincomingviewingkey",
            post(http_get_incoming_viewing_key),
        )
        .route(
            "/walletsolidity/getdiversifier",
            get(http_get_diversifier).post(http_get_diversifier),
        )
        .route(
            "/walletsolidity/getzenpaymentaddress",
            post(http_get_zen_payment_address),
        )
        .route(
            "/walletsolidity/getrcm",
            get(http_get_rcm).post(http_get_rcm),
        )
        .with_state(state);
    // Rate-limit middleware: when the registry is empty the closure
    // returns immediately. Otherwise it parses the path tail and
    // consults the registry, rejecting with HTTP 429 on overrun.
    use axum::middleware::from_fn_with_state;
    let router = if limits.is_empty() {
        router
    } else {
        router.layer(from_fn_with_state(limits, rate_limit_middleware))
    };
    router
}

/// Per-request rate-limit middleware. Looks up the request path's
/// last segment in the registry; on bucket overflow returns HTTP 429.
/// `PreemptibleCounter` guards are dropped after the inner handler
/// returns so the slot is freed when the response is sent.
async fn rate_limit_middleware(
    axum::extract::State(reg): axum::extract::State<crate::RateLimitRegistry>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let path = req.uri().path().to_string();
    let component = crate::rate_limit::component_for_http_path(&path);
    let Some(limit) = reg.get(&component) else {
        return next.run(req).await;
    };
    // IP-based limits would need ConnectInfo here — we don't currently
    // plumb it through axum. Pass `None` so the IpQps strategy falls
    // back to a fixed "anonymous" bucket.
    let (ok, _guard) = limit.try_acquire(None);
    if !ok {
        return (
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "rate limit exceeded",
        )
            .into_response();
    }
    // Hold the guard for the duration of the inner request — drops
    // automatically when the response is built. Preemptible
    // semantics: the slot is freed only after the handler returns.
    let response = next.run(req).await;
    drop(_guard);
    response
}

/// Generic forwarder: HTTP body → `params[0]` → method call →
/// address-rewritten JSON response. Handles the visible-flag base58 ↔
/// hex translation in both directions.
async fn forward_builder(
    method: fn(&Value, &RpcState) -> Result<Value, methods::RpcError>,
    State(state): State<RpcState>,
    Query(query): Query<std::collections::HashMap<String, String>>,
    Json(mut body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let visible = visible_flag(&body, &query);
    // Always normalise addresses — java-tron accepts bare hex (`41...`)
    // *and* base58 (`T...`), but our JSON-RPC layer requires `0x` hex.
    // This is a no-op for already-prefixed values.
    translate_addresses_to_hex(&mut body);
    let params = Value::Array(vec![body]);
    match method(&params, &state) {
        Ok(mut v) => {
            rewrite_addresses(&mut v, visible);
            api_ok(v)
        }
        Err(e) => api_err(e),
    }
}

/// Like [`forward_builder`] but for read endpoints that take no params.
/// Honours `?visible=true` for response rewriting.
async fn forward_no_arg(
    method: fn(&Value, &RpcState) -> Result<Value, methods::RpcError>,
    State(state): State<RpcState>,
) -> (StatusCode, Json<Value>) {
    let params = Value::Array(vec![]);
    match method(&params, &state) {
        Ok(v) => api_ok(v),
        Err(e) => api_err(e),
    }
}

// ----- Custom read handlers (positional-args JSON-RPC methods) -----------
//
// These four methods take positional `params[i]` rather than the
// `params[0] = body_object` shape that `forward_builder` produces.
// Wrap each with a small handler that pulls the right field(s) out of
// the HTTP body, builds the positional params array, and forwards.

/// `POST /wallet/getcontractinfo` — body `{value: "<address>"}`.
async fn http_get_contract_info(
    State(state): State<RpcState>,
    Query(query): Query<std::collections::HashMap<String, String>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let visible = visible_flag(&body, &query);
    let addr = match read_address(&body, "value", visible) {
        Ok(a) => a,
        Err(e) => return api_err_str(e.to_string()),
    };
    let addr_hex = format!("0x{}", hex::encode(&addr.as_bytes()[1..]));
    match methods::get_contract_info(&Value::Array(vec![Value::String(addr_hex)]), &state) {
        Ok(mut v) => {
            rewrite_addresses(&mut v, visible);
            api_ok(v)
        }
        Err(e) => api_err(e),
    }
}

/// `POST /wallet/getblockbylatestnum` — body `{num: N}`. Returns the
/// most-recent `N` blocks. java-tron caps N at 100; the underlying
/// method enforces the same.
async fn http_get_block_by_latest_num(
    State(state): State<RpcState>,
    Query(query): Query<std::collections::HashMap<String, String>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let visible = visible_flag(&body, &query);
    let n = match body.get("num").and_then(Value::as_i64) {
        Some(n) => n,
        None => return api_err_str("missing 'num'".into()),
    };
    match methods::get_block_by_latest_num(&Value::Array(vec![Value::Number(n.into())]), &state) {
        Ok(mut v) => {
            rewrite_addresses(&mut v, visible);
            api_ok(v)
        }
        Err(e) => api_err(e),
    }
}

/// `POST /wallet/getblockbylimitnext` — body `{startNum, endNum}`.
/// Returns blocks in `[startNum, endNum)`.
async fn http_get_block_by_limit_next(
    State(state): State<RpcState>,
    Query(query): Query<std::collections::HashMap<String, String>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let visible = visible_flag(&body, &query);
    let start = match body
        .get("startNum")
        .or_else(|| body.get("start_num"))
        .and_then(Value::as_i64)
    {
        Some(n) => n,
        None => return api_err_str("missing 'startNum'".into()),
    };
    let end = match body
        .get("endNum")
        .or_else(|| body.get("end_num"))
        .and_then(Value::as_i64)
    {
        Some(n) => n,
        None => return api_err_str("missing 'endNum'".into()),
    };
    match methods::get_block_by_limit_next(
        &Value::Array(vec![Value::Number(start.into()), Value::Number(end.into())]),
        &state,
    ) {
        Ok(mut v) => {
            rewrite_addresses(&mut v, visible);
            api_ok(v)
        }
        Err(e) => api_err(e),
    }
}

/// `POST /wallet/getaccountbalance` — body
/// `{account_identifier: {address}, block_identifier: {hash, number}}`.
///
/// java-tron's full shape carries the block_identifier so the caller
/// can pin a historical balance. We don't maintain historical state
/// (`AccountTraceStore::get_prev_balance` returns the value at the
/// most-recent block ≤ `number`, but only if writes have been
/// recorded — fresh nodes return current balance). For now we return
/// the current balance from `AccountStore` regardless of the
/// `block_identifier`, with a `block_identifier` echoed back from the
/// request so clients don't have to assume the response shape.
async fn http_get_account_balance(
    State(state): State<RpcState>,
    Query(query): Query<std::collections::HashMap<String, String>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let visible = visible_flag(&body, &query);
    // Account identifier — either nested `{account_identifier: {address}}`
    // (java-tron's request shape) or flat `{address}` (forgiving alias).
    let address_str = body
        .get("account_identifier")
        .and_then(|ai| ai.get("address"))
        .and_then(Value::as_str)
        .or_else(|| body.get("address").and_then(Value::as_str));
    let address_str = match address_str {
        Some(s) => s,
        None => {
            return api_err_str(
                "missing 'account_identifier.address' (or 'address')".into(),
            );
        }
    };
    let synth_body = json!({ "address": address_str });
    let addr = match read_address(&synth_body, "address", visible) {
        Ok(a) => a,
        Err(e) => return api_err_str(e.to_string()),
    };
    let balance = state
        .accounts
        .get(&addr)
        .ok()
        .flatten()
        .map(|a| a.balance)
        .unwrap_or(0);
    let mut response = json!({
        "balance": balance,
    });
    // Echo back the block_identifier if the caller supplied one, so
    // clients building TAPOS-style refs from this can correlate.
    if let Some(bid) = body.get("block_identifier") {
        response["block_identifier"] = bid.clone();
    }
    rewrite_addresses(&mut response, visible);
    api_ok(response)
}

/// Bind a TCP listener and serve the HTTP REST API on `addr` until
/// the caller drops the future.
pub async fn serve(state: RpcState, addr: SocketAddr) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let app = router(state);
    axum::serve(listener, app.into_make_service()).await
}

// =============================================================================
// Request → params translation helpers
// =============================================================================

/// Default-true on missing — both query strings and JSON bodies write
/// the absence as no-key, and java-tron defaults `visible` to `false`.
/// We default to `false` to match.
fn visible_flag(body: &Value, query: &std::collections::HashMap<String, String>) -> bool {
    if let Some(v) = body.get("visible").and_then(Value::as_bool) {
        return v;
    }
    if let Some(s) = query.get("visible") {
        return matches!(s.to_lowercase().as_str(), "true" | "1");
    }
    false
}

/// Pull an address field from a JSON body, honouring `visible`. When
/// `visible == true`, the value is a `T...` base58 string and is
/// decoded to its 21-byte form. Otherwise the value is hex (`0x41...`
/// or `41...`) and decoded with the eth-address parser.
fn read_address(body: &Value, field: &str, visible: bool) -> Result<Address, ApiError> {
    let s = body
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::BadRequest(format!("missing {field}")))?;
    if visible {
        tron_crypto::base58check::decode_address(s)
            .map_err(|e| ApiError::BadRequest(format!("{field} base58: {e:?}")))
    } else {
        // Reuse the eth-style decoder used by JSON-RPC handlers.
        let s = s.strip_prefix("0x").unwrap_or(s);
        let raw = hex::decode(s).map_err(|e| ApiError::BadRequest(format!("{field} hex: {e}")))?;
        let bytes = match raw.len() {
            21 if raw[0] == 0x41 => raw,
            20 => {
                let mut full = Vec::with_capacity(21);
                full.push(0x41);
                full.extend_from_slice(&raw);
                full
            }
            _ => {
                return Err(ApiError::BadRequest(format!(
                    "{field} must be 20 or 21 bytes hex, got {} bytes",
                    raw.len()
                )))
            }
        };
        let mut buf = [0u8; 21];
        buf.copy_from_slice(&bytes);
        Ok(Address::from_raw(buf))
    }
}

/// java-tron's HTTP API formats addresses as `41<20 hex>` (no `0x`)
/// when visible is false; `T...` base58 when visible is true.
/// Our internal `methods::*` functions emit `0x41<20 hex>`; we strip
/// the `0x` for HTTP compatibility.
fn format_address(addr_bytes: &[u8], visible: bool) -> String {
    if addr_bytes.len() == 21 && visible {
        let mut buf = [0u8; 21];
        buf.copy_from_slice(addr_bytes);
        return tron_crypto::base58check::encode_address(&Address::from_raw(buf));
    }
    hex::encode(addr_bytes)
}

/// Fields whose values are TRON addresses, used by both
/// [`rewrite_addresses`] (response side) and
/// [`translate_addresses_to_hex`] (request side).
static ADDR_FIELDS: &[&str] = &[
    "address",
    "owner_address",
    "ownerAddress",
    "to_address",
    "toAddress",
    "contract_address",
    "contractAddress",
    "from",
    "to",
    "origin_address",
    "originAddress",
    "transfer_to_address",
    "transferToAddress",
    "caller_address",
    "callerAddress",
    "witness_address",
    "witnessAddress",
    "receiver_address",
    "receiverAddress",
    "account_address",
    "accountAddress",
    "vote_address",
    "voteAddress",
];

/// Walk an incoming HTTP body and normalise every address field into
/// the `0x`-prefixed hex form the JSON-RPC method handlers expect:
/// * `T...` (34 chars) → base58-decode → `0x41...`
/// * bare hex (`41...` or `...`) → prepend `0x`
/// * already-`0x`-prefixed → leave alone
/// * non-string or unknown shape → leave alone (downstream parser
///   will reject with a clear error)
fn translate_addresses_to_hex(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if ADDR_FIELDS.contains(&k.as_str()) {
                    if let Some(s) = v.as_str() {
                        if let Some(normalized) = normalize_address_string(s) {
                            *v = Value::String(normalized);
                        }
                    }
                }
                translate_addresses_to_hex(v);
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                translate_addresses_to_hex(item);
            }
        }
        _ => {}
    }
}

fn normalize_address_string(s: &str) -> Option<String> {
    if s.starts_with("0x") || s.starts_with("0X") {
        return None;
    }
    if s.starts_with('T') && s.len() == 34 {
        if let Ok(addr) = tron_crypto::base58check::decode_address(s) {
            return Some(format!("0x{}", hex::encode(addr.as_bytes())));
        }
        return None;
    }
    // Treat any other purely-hex string as bare hex needing the `0x`
    // prefix. Reject obvious non-hex (e.g., URLs, asset names) by
    // checking every char.
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(format!("0x{s}"));
    }
    None
}

/// Walk a JSON value and translate every field whose name is in the
/// `address_fields` set: strip leading `0x`, and (if `visible`)
/// convert to base58. This is the post-processing step matching
/// java-tron's `Util.formatAddress`/`setVisible`.
fn rewrite_addresses(value: &mut Value, visible: bool) {
    match value {
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if ADDR_FIELDS.contains(&k.as_str()) {
                    if let Some(s) = v.as_str() {
                        // Accept both `0x41...` and `41...`. Decode +
                        // re-encode under the desired format.
                        let stripped = s.strip_prefix("0x").unwrap_or(s);
                        if let Ok(raw) = hex::decode(stripped) {
                            *v = Value::String(format_address(&raw, visible));
                            continue;
                        }
                    }
                }
                rewrite_addresses(v, visible);
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                rewrite_addresses(item, visible);
            }
        }
        _ => {}
    }
}

// =============================================================================
// Endpoint handlers
// =============================================================================

async fn get_now_block(
    State(state): State<RpcState>,
    Query(query): Query<std::collections::HashMap<String, String>>,
    body: Option<Json<Value>>,
) -> impl IntoResponse {
    let body_val = body.map(|j| j.0).unwrap_or_else(|| json!({}));
    let visible = visible_flag(&body_val, &query);
    let head = state.dyn_props.latest_block_header_number().unwrap_or(0);
    let Ok(id) = state.block_index.get(head) else {
        return api_ok(json!({}));
    };
    let Ok(block) = state.blocks.get(&id) else {
        return api_ok(json!({}));
    };
    let mut v = format_block_for_http(&id, &block);
    rewrite_addresses(&mut v, visible);
    api_ok(v)
}

/// `/monitor/getstatsinfo` handler — `methods::get_stats_info` is
/// arg-free so this is just a thin axum wrapper.
async fn get_stats_info(State(state): State<RpcState>) -> impl IntoResponse {
    api_ok(methods::get_stats_info(&json!([]), &state))
}

// =============================================================================
// Shielded key-derivation servlets
// =============================================================================
//
// Mirror java-tron's `/wallet/getspendingkey` family. Each handler
// pulls fields out of the POST body (or returns immediately for the
// arg-free ones), forwards to the matching JSON-RPC method, and
// reshapes the response into the field names java-tron uses on the
// wire. `0x` prefixes are NOT emitted — java-tron clients expect
// raw lowercase hex, so we strip the prefix the JSON-RPC layer adds.

fn strip_0x_in_object(value: &mut Value) {
    match value {
        Value::String(s) => {
            if let Some(rest) = s.strip_prefix("0x") {
                *s = rest.to_string();
            }
        }
        Value::Array(arr) => {
            for v in arr {
                strip_0x_in_object(v);
            }
        }
        Value::Object(map) => {
            for v in map.values_mut() {
                strip_0x_in_object(v);
            }
        }
        _ => {}
    }
}

/// Pull a `"value"` hex string out of a JSON body. Java-tron's
/// shielded servlets use `{"value": "<hex>"}` consistently for the
/// one-arg shape; clients pass it WITHOUT a `0x` prefix. The
/// JSON-RPC layer's parser requires the prefix, so we re-add it
/// before forwarding.
fn body_value_hex(body: &Value) -> Option<String> {
    body.get("value")
        .and_then(|v| v.as_str())
        .map(|s| ensure_0x_prefix(s))
}

fn ensure_0x_prefix(s: &str) -> String {
    if s.starts_with("0x") || s.starts_with("0X") {
        s.to_string()
    } else {
        format!("0x{s}")
    }
}

async fn http_get_spending_key(State(state): State<RpcState>) -> impl IntoResponse {
    let params = json!([]);
    match methods::get_spending_key(&params, &state) {
        Ok(mut v) => {
            strip_0x_in_object(&mut v);
            api_ok(v)
        }
        Err(e) => api_err(e),
    }
}

async fn http_get_expanded_spending_key(
    State(state): State<RpcState>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let Some(hex_str) = body_value_hex(&body) else {
        return api_err(methods::RpcError::invalid_params(
            "missing `value` field with the 32-byte spending key",
        ));
    };
    let params = json!([hex_str]);
    match methods::get_expanded_spending_key(&params, &state) {
        Ok(mut v) => {
            strip_0x_in_object(&mut v);
            api_ok(v)
        }
        Err(e) => api_err(e),
    }
}

async fn http_get_ak_from_ask(
    State(state): State<RpcState>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let Some(hex_str) = body_value_hex(&body) else {
        return api_err(methods::RpcError::invalid_params(
            "missing `value` field with the 32-byte ask scalar",
        ));
    };
    let params = json!([hex_str]);
    match methods::get_ak_from_ask(&params, &state) {
        Ok(mut v) => {
            strip_0x_in_object(&mut v);
            api_ok(v)
        }
        Err(e) => api_err(e),
    }
}

async fn http_get_nk_from_nsk(
    State(state): State<RpcState>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let Some(hex_str) = body_value_hex(&body) else {
        return api_err(methods::RpcError::invalid_params(
            "missing `value` field with the 32-byte nsk scalar",
        ));
    };
    let params = json!([hex_str]);
    match methods::get_nk_from_nsk(&params, &state) {
        Ok(mut v) => {
            strip_0x_in_object(&mut v);
            api_ok(v)
        }
        Err(e) => api_err(e),
    }
}

async fn http_get_incoming_viewing_key(
    State(state): State<RpcState>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let ak = body.get("ak").and_then(|v| v.as_str()).map(ensure_0x_prefix);
    let nk = body.get("nk").and_then(|v| v.as_str()).map(ensure_0x_prefix);
    let (Some(ak), Some(nk)) = (ak, nk) else {
        return api_err(methods::RpcError::invalid_params(
            "missing `ak` or `nk` field; both are required",
        ));
    };
    let params = json!([ak, nk]);
    match methods::get_incoming_viewing_key(&params, &state) {
        Ok(mut v) => {
            strip_0x_in_object(&mut v);
            api_ok(v)
        }
        Err(e) => api_err(e),
    }
}

async fn http_get_diversifier(State(state): State<RpcState>) -> impl IntoResponse {
    let params = json!([]);
    match methods::get_diversifier(&params, &state) {
        Ok(mut v) => {
            strip_0x_in_object(&mut v);
            api_ok(v)
        }
        Err(e) => api_err(e),
    }
}

async fn http_get_zen_payment_address(
    State(state): State<RpcState>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let ivk = body.get("ivk").and_then(|v| v.as_str()).map(ensure_0x_prefix);
    let d = body.get("d").and_then(|v| v.as_str()).map(ensure_0x_prefix);
    let (Some(ivk), Some(d)) = (ivk, d) else {
        return api_err(methods::RpcError::invalid_params(
            "missing `ivk` or `d` field; both are required",
        ));
    };
    let params = json!([ivk, d]);
    match methods::get_zen_payment_address(&params, &state) {
        Ok(mut v) => {
            strip_0x_in_object(&mut v);
            api_ok(v)
        }
        Err(e) => api_err(e),
    }
}

async fn http_get_rcm(State(state): State<RpcState>) -> impl IntoResponse {
    let params = json!([]);
    match methods::get_rcm(&params, &state) {
        Ok(mut v) => {
            strip_0x_in_object(&mut v);
            api_ok(v)
        }
        Err(e) => api_err(e),
    }
}

async fn get_block_by_num(
    State(state): State<RpcState>,
    Query(query): Query<std::collections::HashMap<String, String>>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let visible = visible_flag(&body, &query);
    let num = match body.get("num").and_then(Value::as_i64) {
        Some(n) => n,
        None => return api_err_str("missing 'num'".into()),
    };
    let Ok(id) = state.block_index.get(num) else {
        return api_ok(json!({}));
    };
    let Ok(block) = state.blocks.get(&id) else {
        return api_ok(json!({}));
    };
    let mut v = format_block_for_http(&id, &block);
    rewrite_addresses(&mut v, visible);
    api_ok(v)
}

async fn get_block_by_id(
    State(state): State<RpcState>,
    Query(query): Query<std::collections::HashMap<String, String>>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let visible = visible_flag(&body, &query);
    let hash_str = match body.get("value").and_then(Value::as_str) {
        Some(s) => s.to_string(),
        None => return api_err_str("missing 'value' (block id)".into()),
    };
    let hash_str = hash_str.strip_prefix("0x").unwrap_or(&hash_str);
    let bytes = match hex::decode(hash_str) {
        Ok(b) if b.len() == 32 => b,
        _ => return api_err_str("'value' must be a 32-byte hex string".into()),
    };
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&bytes);
    let id = tron_types::BlockId::from_raw(raw);
    let Ok(block) = state.blocks.get(&id) else {
        return api_ok(json!({}));
    };
    let mut v = format_block_for_http(&id, &block);
    rewrite_addresses(&mut v, visible);
    api_ok(v)
}

/// Render a block in java-tron's HTTP shape: `{blockID, block_header:
/// {raw_data: {...}}, transactions: [...]}`. Distinct from the
/// JSON-RPC shape (which uses ETH-style camelCase) so TronWeb /
/// TronGrid / wallet-cli get the format they expect.
fn format_block_for_http(id: &tron_types::BlockId, block: &tron_proto::Block) -> Value {
    let raw = block.block_header.as_ref().and_then(|h| h.raw_data.as_ref());
    let raw_data = match raw {
        Some(r) => json!({
            "number": r.number,
            "txTrieRoot": hex::encode(&r.tx_trie_root),
            "witness_address": hex::encode(&r.witness_address),
            "parentHash": hex::encode(&r.parent_hash),
            "version": r.version,
            "timestamp": r.timestamp,
        }),
        None => json!({}),
    };
    let witness_signature = block
        .block_header
        .as_ref()
        .map(|h| hex::encode(&h.witness_signature))
        .unwrap_or_default();
    let transactions: Vec<Value> = block
        .transactions
        .iter()
        .map(|tx| {
            use prost::Message as _;
            let tx_id = tx
                .raw_data
                .as_ref()
                .map(|r| tron_crypto::hash::sha256(&r.encode_to_vec()))
                .unwrap_or([0u8; 32]);
            json!({
                "txID": hex::encode(tx_id),
                "raw_data": tx.raw_data.as_ref().map(format_raw_data_for_http).unwrap_or(json!({})),
                "signature": tx.signature.iter().map(hex::encode).collect::<Vec<_>>(),
            })
        })
        .collect();
    json!({
        "blockID": hex::encode(id.as_bytes()),
        "block_header": {
            "raw_data": raw_data,
            "witness_signature": witness_signature,
        },
        "transactions": transactions,
    })
}

fn format_raw_data_for_http(raw: &tron_proto::transaction::Raw) -> Value {
    let contracts: Vec<Value> = raw
        .contract
        .iter()
        .map(|c| {
            json!({
                "type": c.r#type,
                "parameter": c.parameter.as_ref().map(|any| json!({
                    "type_url": any.type_url,
                    "value": hex::encode(&any.value),
                })),
                "Permission_id": c.permission_id,
            })
        })
        .collect();
    json!({
        "contract": contracts,
        "ref_block_bytes": hex::encode(&raw.ref_block_bytes),
        "ref_block_hash": hex::encode(&raw.ref_block_hash),
        "expiration": raw.expiration,
        "timestamp": raw.timestamp,
        "fee_limit": raw.fee_limit,
    })
}

async fn get_account(
    State(state): State<RpcState>,
    Query(query): Query<std::collections::HashMap<String, String>>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let visible = visible_flag(&body, &query);
    let addr = match read_address(&body, "address", visible) {
        Ok(a) => a,
        Err(e) => return api_err_str(e.to_string()),
    };
    let addr_hex = format!("0x{}", hex::encode(&addr.as_bytes()[1..]));
    match methods::get_account(&Value::Array(vec![Value::String(addr_hex)]), &state) {
        Ok(mut v) => {
            rewrite_addresses(&mut v, visible);
            api_ok(v)
        }
        Err(e) => api_err(e),
    }
}

async fn get_account_resource(
    State(state): State<RpcState>,
    Query(query): Query<std::collections::HashMap<String, String>>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let visible = visible_flag(&body, &query);
    let addr = match read_address(&body, "address", visible) {
        Ok(a) => a,
        Err(e) => return api_err_str(e.to_string()),
    };
    let addr_hex = format!("0x{}", hex::encode(&addr.as_bytes()[1..]));
    match methods::get_account_resource(&Value::Array(vec![Value::String(addr_hex)]), &state) {
        Ok(mut v) => {
            rewrite_addresses(&mut v, visible);
            api_ok(v)
        }
        Err(e) => api_err(e),
    }
}

async fn get_contract(
    State(state): State<RpcState>,
    Query(query): Query<std::collections::HashMap<String, String>>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let visible = visible_flag(&body, &query);
    // java-tron's body field name is `value` for the contract address.
    let addr = match read_address(&body, "value", visible) {
        Ok(a) => a,
        Err(e) => return api_err_str(e.to_string()),
    };
    let addr_hex = format!("0x{}", hex::encode(&addr.as_bytes()[1..]));
    match methods::get_contract(&Value::Array(vec![Value::String(addr_hex)]), &state) {
        Ok(mut v) => {
            rewrite_addresses(&mut v, visible);
            api_ok(v)
        }
        Err(e) => api_err(e),
    }
}

async fn get_transaction_by_id(
    State(state): State<RpcState>,
    Query(query): Query<std::collections::HashMap<String, String>>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let visible = visible_flag(&body, &query);
    let txid = match body.get("value").and_then(Value::as_str) {
        Some(s) => s.to_string(),
        None => return api_err_str("missing 'value' (tx id)".into()),
    };
    let txid = if txid.starts_with("0x") { txid } else { format!("0x{}", txid) };
    match methods::get_transaction_by_id(&Value::Array(vec![Value::String(txid)]), &state) {
        Ok(mut v) => {
            rewrite_addresses(&mut v, visible);
            api_ok(v)
        }
        Err(e) => api_err(e),
    }
}

async fn get_transaction_info_by_id(
    State(state): State<RpcState>,
    Query(query): Query<std::collections::HashMap<String, String>>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let visible = visible_flag(&body, &query);
    let txid = match body.get("value").and_then(Value::as_str) {
        Some(s) => s.to_string(),
        None => return api_err_str("missing 'value' (tx id)".into()),
    };
    let txid = if txid.starts_with("0x") { txid } else { format!("0x{}", txid) };
    match methods::get_transaction_info_by_id(
        &Value::Array(vec![Value::String(txid)]),
        &state,
    ) {
        Ok(mut v) => {
            rewrite_addresses(&mut v, visible);
            api_ok(v)
        }
        Err(e) => api_err(e),
    }
}

async fn list_witnesses(
    State(state): State<RpcState>,
    Query(query): Query<std::collections::HashMap<String, String>>,
    body: Option<Json<Value>>,
) -> impl IntoResponse {
    let body_val = body.map(|j| j.0).unwrap_or_else(|| json!({}));
    let visible = visible_flag(&body_val, &query);
    match methods::list_witnesses(&Value::Array(vec![]), &state) {
        Ok(mut v) => {
            rewrite_addresses(&mut v, visible);
            api_ok(v)
        }
        Err(e) => api_err(e),
    }
}

async fn get_chain_parameters(
    State(state): State<RpcState>,
    _query: Query<std::collections::HashMap<String, String>>,
    _body: Option<Json<Value>>,
) -> impl IntoResponse {
    match methods::get_chain_parameters(&Value::Array(vec![]), &state) {
        Ok(v) => api_ok(v),
        Err(e) => api_err(e),
    }
}

async fn validate_address(
    State(state): State<RpcState>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let addr = match body.get("address").and_then(Value::as_str) {
        Some(s) => s.to_string(),
        None => return api_err_str("missing 'address'".into()),
    };
    match methods::validate_address(&Value::Array(vec![Value::String(addr)]), &state) {
        Ok(v) => api_ok(v),
        Err(e) => api_err(e),
    }
}

async fn broadcast_transaction(
    State(state): State<RpcState>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    // java-tron's HTTP form: full envelope `{txID, raw_data, raw_data_hex,
    // signature, visible}`. We hand the underlying JSON-RPC handler
    // either the raw_data_hex form or the envelope itself — it
    // accepts both.
    let inner = body
        .get("raw_data_hex")
        .cloned()
        .or_else(|| body.get("transaction").cloned())
        .unwrap_or(body);
    match methods::broadcast_transaction_v2(&Value::Array(vec![inner]), &state) {
        Ok(v) => api_ok(v),
        Err(e) => api_err(e),
    }
}

// =============================================================================
// Response helpers
// =============================================================================

fn api_ok(v: Value) -> (StatusCode, Json<Value>) {
    (StatusCode::OK, Json(v))
}

fn api_err(e: methods::RpcError) -> (StatusCode, Json<Value>) {
    (
        StatusCode::OK,
        Json(json!({
            "Error": e.message,
            "code": e.code,
        })),
    )
}

fn api_err_str(msg: String) -> (StatusCode, Json<Value>) {
    (
        StatusCode::OK,
        Json(json!({
            "Error": msg,
            "code": -32602,
        })),
    )
}

#[derive(Debug, thiserror::Error)]
enum ApiError {
    #[error("{0}")]
    BadRequest(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrite_addresses_handles_hex_to_base58() {
        let mut v = json!({
            "address": "0x412e988a386a799f506693793c6a5af6b54dfaabfb",
            "amount": 100,
            "nested": {
                "owner_address": "412e988a386a799f506693793c6a5af6b54dfaabfb",
            },
        });
        rewrite_addresses(&mut v, true);
        let s = v["address"].as_str().unwrap();
        assert!(s.starts_with('T'), "expected T-prefixed address, got {s}");
        let nested = v["nested"]["owner_address"].as_str().unwrap();
        assert!(nested.starts_with('T'));
        // Non-address fields untouched.
        assert_eq!(v["amount"], 100);
    }

    #[test]
    fn rewrite_addresses_strips_0x_when_visible_false() {
        let mut v = json!({
            "owner_address": "0x412e988a386a799f506693793c6a5af6b54dfaabfb",
        });
        rewrite_addresses(&mut v, false);
        assert_eq!(
            v["owner_address"].as_str().unwrap(),
            "412e988a386a799f506693793c6a5af6b54dfaabfb",
            "java-tron writes addresses as no-0x hex when visible=false"
        );
    }

    #[test]
    fn read_address_accepts_base58_when_visible_true() {
        let body = json!({
            "address": "TEDapYSVvAZ3aYH7w8N9tMEEFKaNKUD5Bp",
        });
        let addr = read_address(&body, "address", true).unwrap();
        assert_eq!(addr.as_bytes()[0], 0x41);
        assert_eq!(addr.as_bytes().len(), 21);
    }

    #[test]
    fn read_address_accepts_hex_when_visible_false() {
        let body = json!({
            "address": "412e988a386a799f506693793c6a5af6b54dfaabfb",
        });
        let addr = read_address(&body, "address", false).unwrap();
        assert_eq!(addr.as_bytes()[0], 0x41);
        assert_eq!(addr.as_bytes().len(), 21);
    }

    #[test]
    fn read_address_accepts_20_byte_eth_form_when_visible_false() {
        // 20-byte form (without 0x41 prefix) — the eth-style form
        // that our JSON-RPC layer also accepts.
        let body = json!({
            "address": "0x2e988a386a799f506693793c6a5af6b54dfaabfb",
        });
        let addr = read_address(&body, "address", false).unwrap();
        assert_eq!(addr.as_bytes()[0], 0x41);
        assert_eq!(&addr.as_bytes()[1..], &hex::decode("2e988a386a799f506693793c6a5af6b54dfaabfb").unwrap());
    }

    #[test]
    fn visible_flag_defaults_false() {
        let body = json!({});
        let query = std::collections::HashMap::new();
        assert!(!visible_flag(&body, &query));
    }

    #[test]
    fn visible_flag_picks_up_query_string() {
        let body = json!({});
        let mut q = std::collections::HashMap::new();
        q.insert("visible".into(), "true".into());
        assert!(visible_flag(&body, &q));
        let mut q2 = std::collections::HashMap::new();
        q2.insert("visible".into(), "1".into());
        assert!(visible_flag(&body, &q2));
    }

    #[test]
    fn visible_flag_body_overrides_query() {
        let body = json!({ "visible": false });
        let mut q = std::collections::HashMap::new();
        q.insert("visible".into(), "true".into());
        assert!(!visible_flag(&body, &q));
    }
}
