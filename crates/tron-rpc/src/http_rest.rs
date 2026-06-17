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

/// [`router_with_limits`] with the global limiter disabled — kept as a
/// stable entry point for existing callers.
pub fn router_with_rate_limits(state: RpcState, limits: crate::RateLimitRegistry) -> Router {
    router_with_limits(state, limits, crate::GlobalRateLimiter::disabled())
}

/// Mount the endpoints with rate-limit gating. When the registry is
/// non-empty, each request's path-tail is looked up (lowercased) and
/// `try_acquire` runs before the handler; the node-wide
/// [`GlobalRateLimiter`](crate::GlobalRateLimiter) is consulted after
/// the per-component check (java-tron's ordering). Failures return
/// HTTP 429. Per-IP buckets use the socket peer address when the
/// server is built with `into_make_service_with_connect_info`.
pub fn router_with_limits(
    state: RpcState,
    limits: crate::RateLimitRegistry,
    global: crate::GlobalRateLimiter,
) -> Router {
    // Helper: bind a route whose handler delegates to a JSON-RPC
    // builder method. The HTTP body is wrapped in `[body]` to match the
    // `params[0]` shape that `methods::*` expects.
    macro_rules! builder {
        ($name:literal, $method:path) => {
            post(|state, query, body| forward_builder($method, state, query, body))
        };
    }
    // Forward a java-shaped POST body to a positional-params method:
    // each listed field is plucked from the body (Null when absent)
    // and passed in order. `[]` with "@body" passes the WHOLE body as
    // params[0] (tx-shaped endpoints).
    macro_rules! mapped {
        ($method:path, @body) => {
            post(|state, query, body| forward_mapped($method, &["@body"], state, query, body))
        };
        ($method:path, [$($field:literal),*]) => {
            post(|state, query, body| {
                forward_mapped($method, &[$($field),*], state, query, body)
            })
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
        // ---- java parity sweep (4.8.x servlet list) ----
        // Reads forwarded onto the same positional-params methods the
        // JSON-RPC surface dispatches to; bodies use java's field names.
        .route("/wallet/getreward", mapped!(methods::get_reward, ["address"]))
        .route("/wallet/getbrokerage", mapped!(methods::get_brokerage, ["address"]))
        .route(
            "/wallet/getdelegatedresource",
            mapped!(methods::get_delegated_resource, ["fromAddress", "toAddress"]),
        )
        .route(
            "/wallet/getdelegatedresourcev2",
            mapped!(methods::get_delegated_resource_v2, ["fromAddress", "toAddress"]),
        )
        .route(
            "/wallet/getdelegatedresourceaccountindex",
            mapped!(methods::get_delegated_resource_account_index, ["value"]),
        )
        .route(
            "/wallet/getdelegatedresourceaccountindexv2",
            mapped!(methods::get_delegated_resource_account_index_v2, ["value"]),
        )
        .route(
            "/wallet/getcandelegatedmaxsize",
            mapped!(methods::get_can_delegated_max_size, ["owner_address", "type"]),
        )
        .route(
            "/wallet/getavailableunfreezecount",
            mapped!(methods::get_available_unfreeze_count, ["owner_address"]),
        )
        .route(
            "/wallet/getcanwithdrawunfreezeamount",
            mapped!(
                methods::get_can_withdraw_unfreeze_amount,
                ["owner_address", "timestamp"]
            ),
        )
        .route("/wallet/getaccountbyid", mapped!(methods::get_account_by_id, ["account_id"]))
        .route("/wallet/getaccountnet", mapped!(methods::get_account_net, ["address"]))
        .route(
            "/wallet/getassetissuebyaccount",
            mapped!(methods::get_asset_issue_by_account, ["address"]),
        )
        .route(
            "/wallet/getassetissuebyid",
            mapped!(methods::get_asset_issue_by_id, ["value"]),
        )
        .route(
            "/wallet/getassetissuebyname",
            mapped!(methods::get_asset_issue_by_name, ["value"]),
        )
        .route(
            "/wallet/getassetissuelistbyname",
            mapped!(methods::get_asset_issue_list_by_name, ["value"]),
        )
        .route("/wallet/getassetissuelist", getter_no_arg!(methods::list_assets))
        .route(
            "/wallet/getpaginatedassetissuelist",
            mapped!(methods::get_paginated_asset_issue_list, ["offset", "limit"]),
        )
        .route(
            "/wallet/getpaginatedproposallist",
            mapped!(methods::get_paginated_proposal_list, ["offset", "limit"]),
        )
        .route(
            "/wallet/getpaginatedexchangelist",
            mapped!(methods::get_paginated_exchange_list, ["offset", "limit"]),
        )
        .route("/wallet/listproposals", getter_no_arg!(methods::list_proposals))
        .route("/wallet/listexchanges", getter_no_arg!(methods::list_exchanges))
        .route("/wallet/getproposalbyid", mapped!(methods::get_proposal_by_id, ["id"]))
        .route("/wallet/getexchangebyid", mapped!(methods::get_exchange_by_id, ["id"]))
        .route(
            "/wallet/getmarketorderbyaccount",
            mapped!(methods::get_market_order_by_account, ["value"]),
        )
        .route(
            "/wallet/getmarketorderbyid",
            mapped!(methods::get_market_order_by_id, ["value"]),
        )
        .route(
            "/wallet/getmarketorderlistbypair",
            mapped!(
                methods::get_market_order_list_by_pair,
                ["sell_token_id", "buy_token_id"]
            ),
        )
        .route(
            "/wallet/getmarketpricebypair",
            mapped!(
                methods::get_market_price_by_pair,
                ["sell_token_id", "buy_token_id"]
            ),
        )
        .route("/wallet/getmarketpairlist", getter_no_arg!(methods::get_market_pair_list))
        .route("/wallet/getblock", mapped!(methods::get_block, ["id_or_num", "detail"]))
        .route(
            "/wallet/getblockbalance",
            mapped!(methods::get_block_balance_trace, ["number"]),
        )
        .route(
            "/wallet/gettransactioninfobyblocknum",
            mapped!(methods::get_transaction_info_by_block_num, ["num"]),
        )
        .route(
            "/wallet/gettransactioncountbyblocknum",
            mapped!(methods::get_transaction_count_by_block_num, ["num"]),
        )
        .route("/wallet/totaltransaction", getter_no_arg!(methods::get_total_transaction))
        .route("/wallet/getsignweight", mapped!(methods::get_sign_weight, @body))
        .route("/wallet/getapprovedlist", mapped!(methods::get_approved_list, @body))
        .route(
            "/wallet/broadcasthex",
            mapped!(methods::broadcast_transaction_v2, ["transaction"]),
        )
        // java's name for what we already serve at clearcontractabi.
        .route("/wallet/clearabi", builder!("clearabi", methods::clear_abi))
        // Solidity mirrors for the read set java exposes there.
        .route(
            "/walletsolidity/getdelegatedresource",
            mapped!(methods::get_delegated_resource, ["fromAddress", "toAddress"]),
        )
        .route(
            "/walletsolidity/getdelegatedresourcev2",
            mapped!(methods::get_delegated_resource_v2, ["fromAddress", "toAddress"]),
        )
        .route(
            "/walletsolidity/getassetissuelist",
            getter_no_arg!(methods::list_assets),
        )
        .route("/walletsolidity/getreward", mapped!(methods::get_reward, ["address"]))
        .route(
            "/walletsolidity/getbrokerage",
            mapped!(methods::get_brokerage, ["address"]),
        )
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
        // TronGrid-style /v1 address-history surface (served from the
        // embedded index when [index] is enabled; a clear error
        // otherwise).
        .merge(crate::index_api::router())
        .merge(crate::index_api::archive_router())
        .with_state(state);
    // Rate-limit middleware: when the registry is empty the closure
    // returns immediately. Otherwise it parses the path tail and
    // consults the registry, rejecting with HTTP 429 on overrun.
    use axum::middleware::from_fn_with_state;
    let router = if limits.is_empty() && global.is_disabled() {
        router
    } else {
        router.layer(from_fn_with_state((limits, global), rate_limit_middleware))
    };
    router
}

/// Per-request rate-limit middleware. Looks up the request path's
/// last segment in the registry; on bucket overflow returns HTTP 429.
/// `PreemptibleCounter` guards are dropped after the inner handler
/// returns so the slot is freed when the response is sent.
async fn rate_limit_middleware(
    axum::extract::State((reg, global)): axum::extract::State<(
        crate::RateLimitRegistry,
        crate::GlobalRateLimiter,
    )>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let path = req.uri().path().to_string();
    let component = crate::rate_limit::component_for_http_path(&path);
    // Source IP for per-IP buckets — present when the server was built
    // with `into_make_service_with_connect_info::<SocketAddr>()`;
    // absent (anonymous shared bucket) otherwise.
    let ip = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip());
    let mut _guard = None;
    // Per-component first, then the node-wide limiter — java-tron's
    // RateLimiterServlet ordering (an exhausted global still consumes
    // the per-component token).
    let component_ok = match reg.get(&component) {
        Some(limit) => {
            let (ok, guard) = limit.try_acquire(ip);
            _guard = guard;
            ok
        }
        None => true,
    };
    if !component_ok || !global.try_acquire(ip) {
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
    // The method reads RocksDB-backed stores synchronously; keep it off
    // the async worker so a disk-blocked read can't starve the server
    // under heavy sync load (see `crate::blocking`).
    match crate::blocking::run_blocking(|| method(&params, &state)) {
        Ok(mut v) => {
            rewrite_addresses(&mut v, visible);
            api_ok(v)
        }
        Err(e) => api_err(e),
    }
}

/// Like [`forward_builder`] but for read endpoints that take no params.
/// Honours `?visible=true` for response rewriting.
/// Pluck java's named body fields into a positional params array and
/// call the method. `"@body"` passes the whole body as params[0].
async fn forward_mapped(
    method: fn(&Value, &RpcState) -> Result<Value, methods::RpcError>,
    fields: &'static [&'static str],
    State(state): State<RpcState>,
    Query(_query): Query<std::collections::HashMap<String, String>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let params = if fields == ["@body"] {
        Value::Array(vec![body])
    } else {
        Value::Array(
            fields
                .iter()
                .map(|f| body.get(*f).cloned().unwrap_or(Value::Null))
                .collect(),
        )
    };
    match crate::blocking::run_blocking(|| method(&params, &state)) {
        Ok(v) => api_ok(v),
        Err(e) => api_err(e),
    }
}

async fn forward_no_arg(
    method: fn(&Value, &RpcState) -> Result<Value, methods::RpcError>,
    State(state): State<RpcState>,
) -> (StatusCode, Json<Value>) {
    let params = Value::Array(vec![]);
    match crate::blocking::run_blocking(|| method(&params, &state)) {
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
    let result = crate::blocking::run_blocking(|| {
        methods::get_contract_info(&Value::Array(vec![Value::String(addr_hex)]), &state)
    });
    match result {
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
    let result = crate::blocking::run_blocking(|| {
        methods::get_block_by_latest_num(&Value::Array(vec![Value::Number(n.into())]), &state)
    });
    match result {
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
    let result = crate::blocking::run_blocking(|| {
        methods::get_block_by_limit_next(
            &Value::Array(vec![Value::Number(start.into()), Value::Number(end.into())]),
            &state,
        )
    });
    match result {
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
    let balance = crate::blocking::run_blocking(|| state.accounts.get(&addr))
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
pub(crate) fn translate_addresses_to_hex(value: &mut Value) {
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
pub(crate) fn rewrite_addresses(value: &mut Value, visible: bool) {
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
                // java's `visible=true` also renders `account_name` as
                // readable text (the serializer emits hex bytes under the
                // default visible=false, matching proto3 JsonFormat).
                if visible && k == "account_name" {
                    if let Some(s) = v.as_str() {
                        if let Ok(raw) = hex::decode(s) {
                            *v = Value::String(String::from_utf8_lossy(&raw).into_owned());
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
    // Synchronous store reads — run off the async worker so a
    // disk-blocked read can't starve the server under heavy sync load
    // (see `crate::blocking`).
    let resolved = crate::blocking::run_blocking(|| resolve_head_block(&state));
    let Some((id, block)) = resolved else {
        // Genuinely no head yet (pre-genesis). java-tron's getNowBlock
        // returns an empty block envelope in that case.
        return api_ok(json!({}));
    };
    let mut v = format_block_for_http(&id, &block);
    rewrite_addresses(&mut v, visible);
    api_ok(v)
}

/// Resolve the current head block (`getNowBlock` / java's
/// `dbManager.getHead()`).
///
/// The head pointer (`latest_block_header_hash`) is written *after* the
/// block bytes and the `block_index` row during apply, so a read that
/// observes the hash always finds the block. Resolving via the hash is a
/// single cross-store hop (dyn_props → blocks); the number→index→blocks
/// path is kept only as a fallback for snapshots that pre-date the hash
/// key. Returns `None` only when there is genuinely no head yet.
fn resolve_head_block(state: &RpcState) -> Option<(tron_types::BlockId, tron_proto::Block)> {
    if let Ok(Some(raw)) = state.dyn_props.latest_block_header_hash() {
        let id = tron_types::BlockId::from_raw(raw);
        if let Ok(block) = state.blocks.get(&id) {
            return Some((id, block));
        }
    }
    let head = state.dyn_props.latest_block_header_number().unwrap_or(0);
    let id = state.block_index.get(head).ok()?;
    let block = state.blocks.get(&id).ok()?;
    Some((id, block))
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
    let resolved = crate::blocking::run_blocking(|| {
        let id = state.block_index.get(num).ok()?;
        let block = state.blocks.get(&id).ok()?;
        Some((id, block))
    });
    let Some((id, block)) = resolved else {
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
    let Ok(block) = crate::blocking::run_blocking(|| state.blocks.get(&id)) else {
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
            let raw_data_hex = tx
                .raw_data
                .as_ref()
                .map(|r| r.encode_to_vec())
                .unwrap_or_default();
            let tx_id = tron_crypto::hash::sha256(&raw_data_hex);
            json!({
                "txID": hex::encode(tx_id),
                "raw_data": tx.raw_data.as_ref().map(format_raw_data_for_http).unwrap_or(json!({})),
                // java includes the canonical wire bytes alongside the
                // decoded form.
                "raw_data_hex": hex::encode(&raw_data_hex),
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
    use serde_json::Map;
    let contracts: Vec<Value> = raw
        .contract
        .iter()
        .map(|c| {
            // java renders `type` as the enum NAME and `parameter.value`
            // as the DECODED contract message (proto3 JsonFormat with a
            // type registry) — not raw hex.
            let type_name = tron_proto::transaction::contract::ContractType::try_from(c.r#type)
                .map(|t| t.as_str_name().to_string())
                .unwrap_or_else(|_| c.r#type.to_string());
            let mut m = Map::new();
            if let Some(any) = c.parameter.as_ref() {
                let value = decode_contract_parameter(c.r#type, &any.value)
                    // Unknown / not-yet-modeled types keep the raw hex so
                    // no information is lost.
                    .unwrap_or_else(|| json!(hex::encode(&any.value)));
                m.insert(
                    "parameter".into(),
                    json!({ "value": value, "type_url": any.type_url }),
                );
            }
            m.insert("type".into(), json!(type_name));
            if c.permission_id != 0 {
                m.insert("Permission_id".into(), json!(c.permission_id));
            }
            Value::Object(m)
        })
        .collect();
    let mut m = Map::new();
    m.insert("contract".into(), json!(contracts));
    m.insert("ref_block_bytes".into(), json!(hex::encode(&raw.ref_block_bytes)));
    m.insert("ref_block_hash".into(), json!(hex::encode(&raw.ref_block_hash)));
    m.insert("expiration".into(), json!(raw.expiration));
    if raw.fee_limit != 0 {
        m.insert("fee_limit".into(), json!(raw.fee_limit));
    }
    if !raw.data.is_empty() {
        m.insert("data".into(), json!(hex::encode(&raw.data)));
    }
    m.insert("timestamp".into(), json!(raw.timestamp));
    Value::Object(m)
}

/// Insert `v` unless it is a proto3 default (0 / empty / false) — java's
/// JsonFormat omits default-valued fields.
fn jput(m: &mut serde_json::Map<String, Value>, k: &str, v: Value) {
    let omit = match &v {
        Value::Number(n) => n.as_i64() == Some(0) || n.as_u64() == Some(0),
        Value::String(s) => s.is_empty(),
        Value::Bool(b) => !*b,
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
        Value::Null => true,
    };
    if !omit {
        m.insert(k.to_string(), v);
    }
}

/// `Common.ResourceCode` as proto3 JSON renders it: the enum NAME, with
/// the zero value (`BANDWIDTH`) omitted entirely.
fn jput_resource(m: &mut serde_json::Map<String, Value>, code: i32) {
    match code {
        1 => jput(m, "resource", json!("ENERGY")),
        2 => jput(m, "resource", json!("TRON_POWER")),
        _ => {}
    }
}

/// Decode a contract `Any` payload into java-tron's typed JSON form.
/// Covers every contract type that appears in normal mainnet traffic;
/// returns `None` for the rest (caller falls back to raw hex).
fn decode_contract_parameter(contract_type: i32, value: &[u8]) -> Option<Value> {
    use prost::Message as _;
    use serde_json::Map;
    use tron_proto::transaction::contract::ContractType as CT;

    let hexb = |b: &[u8]| json!(hex::encode(b));
    let ty = CT::try_from(contract_type).ok()?;
    let mut m = Map::new();
    match ty {
        CT::TransferContract => {
            let c = tron_proto::TransferContract::decode(value).ok()?;
            jput(&mut m, "amount", json!(c.amount));
            jput(&mut m, "owner_address", hexb(&c.owner_address));
            jput(&mut m, "to_address", hexb(&c.to_address));
        }
        CT::TransferAssetContract => {
            let c = tron_proto::TransferAssetContract::decode(value).ok()?;
            jput(&mut m, "amount", json!(c.amount));
            jput(&mut m, "asset_name", hexb(&c.asset_name));
            jput(&mut m, "owner_address", hexb(&c.owner_address));
            jput(&mut m, "to_address", hexb(&c.to_address));
        }
        CT::TriggerSmartContract => {
            let c = tron_proto::TriggerSmartContract::decode(value).ok()?;
            jput(&mut m, "data", hexb(&c.data));
            jput(&mut m, "owner_address", hexb(&c.owner_address));
            jput(&mut m, "contract_address", hexb(&c.contract_address));
            jput(&mut m, "call_value", json!(c.call_value));
            jput(&mut m, "call_token_value", json!(c.call_token_value));
            jput(&mut m, "token_id", json!(c.token_id));
        }
        CT::DelegateResourceContract => {
            let c = tron_proto::DelegateResourceContract::decode(value).ok()?;
            jput(&mut m, "owner_address", hexb(&c.owner_address));
            jput_resource(&mut m, c.resource);
            jput(&mut m, "balance", json!(c.balance));
            jput(&mut m, "receiver_address", hexb(&c.receiver_address));
            jput(&mut m, "lock", json!(c.lock));
            jput(&mut m, "lock_period", json!(c.lock_period));
        }
        CT::UnDelegateResourceContract => {
            let c = tron_proto::UnDelegateResourceContract::decode(value).ok()?;
            jput(&mut m, "owner_address", hexb(&c.owner_address));
            jput_resource(&mut m, c.resource);
            jput(&mut m, "balance", json!(c.balance));
            jput(&mut m, "receiver_address", hexb(&c.receiver_address));
        }
        CT::FreezeBalanceV2Contract => {
            let c = tron_proto::FreezeBalanceV2Contract::decode(value).ok()?;
            jput(&mut m, "owner_address", hexb(&c.owner_address));
            jput(&mut m, "frozen_balance", json!(c.frozen_balance));
            jput_resource(&mut m, c.resource);
        }
        CT::UnfreezeBalanceV2Contract => {
            let c = tron_proto::UnfreezeBalanceV2Contract::decode(value).ok()?;
            jput(&mut m, "owner_address", hexb(&c.owner_address));
            jput(&mut m, "unfreeze_balance", json!(c.unfreeze_balance));
            jput_resource(&mut m, c.resource);
        }
        CT::WithdrawExpireUnfreezeContract => {
            let c = tron_proto::WithdrawExpireUnfreezeContract::decode(value).ok()?;
            jput(&mut m, "owner_address", hexb(&c.owner_address));
        }
        CT::CancelAllUnfreezeV2Contract => {
            let c = tron_proto::CancelAllUnfreezeV2Contract::decode(value).ok()?;
            jput(&mut m, "owner_address", hexb(&c.owner_address));
        }
        CT::WithdrawBalanceContract => {
            let c = tron_proto::WithdrawBalanceContract::decode(value).ok()?;
            jput(&mut m, "owner_address", hexb(&c.owner_address));
        }
        CT::FreezeBalanceContract => {
            let c = tron_proto::FreezeBalanceContract::decode(value).ok()?;
            jput(&mut m, "owner_address", hexb(&c.owner_address));
            jput(&mut m, "frozen_balance", json!(c.frozen_balance));
            jput(&mut m, "frozen_duration", json!(c.frozen_duration));
            jput_resource(&mut m, c.resource);
            jput(&mut m, "receiver_address", hexb(&c.receiver_address));
        }
        CT::UnfreezeBalanceContract => {
            let c = tron_proto::UnfreezeBalanceContract::decode(value).ok()?;
            jput(&mut m, "owner_address", hexb(&c.owner_address));
            jput_resource(&mut m, c.resource);
            jput(&mut m, "receiver_address", hexb(&c.receiver_address));
        }
        CT::VoteWitnessContract => {
            let c = tron_proto::VoteWitnessContract::decode(value).ok()?;
            jput(&mut m, "owner_address", hexb(&c.owner_address));
            let votes: Vec<Value> = c
                .votes
                .iter()
                .map(|v| {
                    let mut vm = Map::new();
                    jput(&mut vm, "vote_address", hexb(&v.vote_address));
                    jput(&mut vm, "vote_count", json!(v.vote_count));
                    Value::Object(vm)
                })
                .collect();
            jput(&mut m, "votes", json!(votes));
            jput(&mut m, "support", json!(c.support));
        }
        CT::AccountCreateContract => {
            let c = tron_proto::AccountCreateContract::decode(value).ok()?;
            jput(&mut m, "owner_address", hexb(&c.owner_address));
            jput(&mut m, "account_address", hexb(&c.account_address));
            jput(&mut m, "type", json!(c.r#type));
        }
        CT::AccountUpdateContract => {
            let c = tron_proto::AccountUpdateContract::decode(value).ok()?;
            jput(&mut m, "account_name", hexb(&c.account_name));
            jput(&mut m, "owner_address", hexb(&c.owner_address));
        }
        CT::SetAccountIdContract => {
            let c = tron_proto::SetAccountIdContract::decode(value).ok()?;
            jput(&mut m, "account_id", hexb(&c.account_id));
            jput(&mut m, "owner_address", hexb(&c.owner_address));
        }
        CT::ParticipateAssetIssueContract => {
            let c = tron_proto::ParticipateAssetIssueContract::decode(value).ok()?;
            jput(&mut m, "owner_address", hexb(&c.owner_address));
            jput(&mut m, "to_address", hexb(&c.to_address));
            jput(&mut m, "asset_name", hexb(&c.asset_name));
            jput(&mut m, "amount", json!(c.amount));
        }
        CT::UnfreezeAssetContract => {
            let c = tron_proto::UnfreezeAssetContract::decode(value).ok()?;
            jput(&mut m, "owner_address", hexb(&c.owner_address));
        }
        CT::UpdateBrokerageContract => {
            let c = tron_proto::UpdateBrokerageContract::decode(value).ok()?;
            jput(&mut m, "owner_address", hexb(&c.owner_address));
            jput(&mut m, "brokerage", json!(c.brokerage));
        }
        CT::WitnessCreateContract => {
            let c = tron_proto::WitnessCreateContract::decode(value).ok()?;
            jput(&mut m, "owner_address", hexb(&c.owner_address));
            jput(&mut m, "url", hexb(&c.url));
        }
        CT::WitnessUpdateContract => {
            let c = tron_proto::WitnessUpdateContract::decode(value).ok()?;
            jput(&mut m, "owner_address", hexb(&c.owner_address));
            jput(&mut m, "update_url", hexb(&c.update_url));
        }
        CT::ProposalCreateContract => {
            let c = tron_proto::ProposalCreateContract::decode(value).ok()?;
            jput(&mut m, "owner_address", hexb(&c.owner_address));
            let params: Vec<Value> = c
                .parameters
                .iter()
                .map(|(k, v)| json!({ "key": k, "value": v }))
                .collect();
            jput(&mut m, "parameters", json!(params));
        }
        CT::ProposalApproveContract => {
            let c = tron_proto::ProposalApproveContract::decode(value).ok()?;
            jput(&mut m, "owner_address", hexb(&c.owner_address));
            jput(&mut m, "proposal_id", json!(c.proposal_id));
            jput(&mut m, "is_add_approval", json!(c.is_add_approval));
        }
        CT::ProposalDeleteContract => {
            let c = tron_proto::ProposalDeleteContract::decode(value).ok()?;
            jput(&mut m, "owner_address", hexb(&c.owner_address));
            jput(&mut m, "proposal_id", json!(c.proposal_id));
        }
        CT::UpdateSettingContract => {
            let c = tron_proto::UpdateSettingContract::decode(value).ok()?;
            jput(&mut m, "owner_address", hexb(&c.owner_address));
            jput(&mut m, "contract_address", hexb(&c.contract_address));
            jput(
                &mut m,
                "consume_user_resource_percent",
                json!(c.consume_user_resource_percent),
            );
        }
        CT::UpdateEnergyLimitContract => {
            let c = tron_proto::UpdateEnergyLimitContract::decode(value).ok()?;
            jput(&mut m, "owner_address", hexb(&c.owner_address));
            jput(&mut m, "contract_address", hexb(&c.contract_address));
            jput(&mut m, "origin_energy_limit", json!(c.origin_energy_limit));
        }
        CT::ClearAbiContract => {
            let c = tron_proto::ClearAbiContract::decode(value).ok()?;
            jput(&mut m, "owner_address", hexb(&c.owner_address));
            jput(&mut m, "contract_address", hexb(&c.contract_address));
        }
        CT::MarketSellAssetContract => {
            let c = tron_proto::MarketSellAssetContract::decode(value).ok()?;
            jput(&mut m, "owner_address", hexb(&c.owner_address));
            jput(&mut m, "sell_token_id", hexb(&c.sell_token_id));
            jput(&mut m, "sell_token_quantity", json!(c.sell_token_quantity));
            jput(&mut m, "buy_token_id", hexb(&c.buy_token_id));
            jput(&mut m, "buy_token_quantity", json!(c.buy_token_quantity));
        }
        CT::MarketCancelOrderContract => {
            let c = tron_proto::MarketCancelOrderContract::decode(value).ok()?;
            jput(&mut m, "owner_address", hexb(&c.owner_address));
            jput(&mut m, "order_id", hexb(&c.order_id));
        }
        CT::ExchangeCreateContract => {
            let c = tron_proto::ExchangeCreateContract::decode(value).ok()?;
            jput(&mut m, "owner_address", hexb(&c.owner_address));
            jput(&mut m, "first_token_id", hexb(&c.first_token_id));
            jput(&mut m, "first_token_balance", json!(c.first_token_balance));
            jput(&mut m, "second_token_id", hexb(&c.second_token_id));
            jput(&mut m, "second_token_balance", json!(c.second_token_balance));
        }
        CT::ExchangeInjectContract => {
            let c = tron_proto::ExchangeInjectContract::decode(value).ok()?;
            jput(&mut m, "owner_address", hexb(&c.owner_address));
            jput(&mut m, "exchange_id", json!(c.exchange_id));
            jput(&mut m, "token_id", hexb(&c.token_id));
            jput(&mut m, "quant", json!(c.quant));
        }
        CT::ExchangeWithdrawContract => {
            let c = tron_proto::ExchangeWithdrawContract::decode(value).ok()?;
            jput(&mut m, "owner_address", hexb(&c.owner_address));
            jput(&mut m, "exchange_id", json!(c.exchange_id));
            jput(&mut m, "token_id", hexb(&c.token_id));
            jput(&mut m, "quant", json!(c.quant));
        }
        CT::ExchangeTransactionContract => {
            let c = tron_proto::ExchangeTransactionContract::decode(value).ok()?;
            jput(&mut m, "owner_address", hexb(&c.owner_address));
            jput(&mut m, "exchange_id", json!(c.exchange_id));
            jput(&mut m, "token_id", hexb(&c.token_id));
            jput(&mut m, "quant", json!(c.quant));
            jput(&mut m, "expected", json!(c.expected));
        }
        // CreateSmartContract / AccountPermissionUpdate / AssetIssue /
        // ShieldedTransfer carry deeply-nested messages (ABI, permission
        // trees, zk proofs); they keep the hex fallback until a full
        // nested renderer lands.
        _ => return None,
    }
    Some(Value::Object(m))
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
    fn contract_parameter_decodes_to_typed_json_like_java() {
        use prost::Message as _;
        use tron_proto::transaction::contract::ContractType as CT;
        // Wire bytes captured from a live mainnet UnDelegateResourceContract
        // (java decodes these to {owner_address, balance, receiver_address};
        // resource=BANDWIDTH is the proto3 default and must be omitted).
        let value = hex::decode(
            "0a1541df4c13530f20bd279f60257ee7db35563155f50c18e3c8bd9603\
             221541c1ad43b988ed5f2799b715953820e283372ff62b",
        )
        .unwrap();
        let v = decode_contract_parameter(CT::UnDelegateResourceContract as i32, &value)
            .expect("decodes");
        assert_eq!(
            v["owner_address"],
            json!("41df4c13530f20bd279f60257ee7db35563155f50c")
        );
        assert_eq!(
            v["receiver_address"],
            json!("41c1ad43b988ed5f2799b715953820e283372ff62b")
        );
        let expected = tron_proto::UnDelegateResourceContract::decode(value.as_slice())
            .unwrap()
            .balance;
        assert!(expected > 0);
        assert_eq!(v["balance"], json!(expected));
        assert!(v.get("resource").is_none(), "default BANDWIDTH omitted");

        // Unknown / unmodeled types fall back to None (caller keeps hex).
        assert!(decode_contract_parameter(CT::CreateSmartContract as i32, &value).is_none());
    }

    #[test]
    fn visible_true_renders_account_name_as_text() {
        let mut v = json!({ "account_name": hex::encode("Blackhole") });
        rewrite_addresses(&mut v, true);
        assert_eq!(v["account_name"], json!("Blackhole"));
        // visible=false leaves the hex untouched (java parity).
        let mut v = json!({ "account_name": hex::encode("Blackhole") });
        rewrite_addresses(&mut v, false);
        assert_eq!(v["account_name"], json!(hex::encode("Blackhole")));
    }

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
