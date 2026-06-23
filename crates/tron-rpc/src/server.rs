//! Axum-based HTTP transport for JSON-RPC.
//!
//! One POST endpoint at `/` (or `/jsonrpc`) that accepts JSON-RPC 2.0
//! requests, dispatches to method functions by name, and returns
//! JSON-RPC 2.0 responses.
//!
//! The dispatch table lives in this module; method implementations
//! live in [`crate::methods`].

use std::net::SocketAddr;

use axum::{
    extract::State,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::methods::{self, RpcError};
use crate::state::RpcState;

/// One JSON-RPC 2.0 request as defined at
/// <https://www.jsonrpc.org/specification#request_object>.
#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: Option<String>,
    method: String,
    #[serde(default)]
    params: Value,
    id: Value,
}

/// Build an axum [`Router`] that handles JSON-RPC at `/`. When the
/// `RpcState` carries a pubsub broker, the router also mounts the
/// `/ws` WebSocket endpoint for `eth_subscribe`.
pub fn router(state: RpcState) -> Router {
    router_with_limits(
        state,
        crate::RateLimitRegistry::empty(),
        crate::GlobalRateLimiter::disabled(),
    )
}

/// [`router`] with rate-limit gating. java-tron's JSON-RPC endpoint is
/// an HTTP servlet behind the same `rate.limiter.http` filter chain
/// (component `JsonRpcServlet`) plus the node-wide GlobalRateLimiter —
/// we mirror that: a configured `jsonrpc` component limits every
/// JSON-RPC POST, and the global limiter applies regardless.
pub fn router_with_limits(
    state: RpcState,
    limits: crate::RateLimitRegistry,
    global: crate::GlobalRateLimiter,
) -> Router {
    let mut r = Router::new().route("/", post(handle));
    if state.pubsub.is_some() {
        r = r.route("/ws", axum::routing::get(crate::pubsub::ws_upgrade_handler));
    }
    let r = r.with_state(state);
    if limits.get("jsonrpc").is_none() && global.is_disabled() {
        return r;
    }
    r.layer(axum::middleware::from_fn_with_state(
        (limits, global),
        jsonrpc_rate_limit_middleware,
    ))
}

/// Whole-endpoint rate limit for JSON-RPC: one `jsonrpc` component
/// (matches java's `JsonRpcServlet` after servlet-suffix
/// normalization) + the global limiter. 429 on overrun.
async fn jsonrpc_rate_limit_middleware(
    axum::extract::State((reg, global)): axum::extract::State<(
        crate::RateLimitRegistry,
        crate::GlobalRateLimiter,
    )>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let ip = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip());
    let mut _guard = None;
    let component_ok = match reg.get("jsonrpc") {
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
    let response = next.run(req).await;
    drop(_guard);
    response
}

/// Convenience: bind a TCP listener and serve the JSON-RPC API on
/// `addr` until the future is cancelled.
pub async fn serve(state: RpcState, addr: SocketAddr) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let app = router(state);
    axum::serve(listener, app.into_make_service()).await
}

/// Lightweight handle type so callers can hold onto the bound address
/// (e.g. when binding to port 0 to let the OS choose).
pub struct RpcServer {
    pub local_addr: SocketAddr,
    pub state: RpcState,
}

/// One handler — dispatches by `method` string.
async fn handle(
    State(state): State<RpcState>,
    Json(req): Json<JsonRpcRequest>,
) -> impl IntoResponse {
    let id = req.id.clone();
    // `dispatch` is synchronous and reads RocksDB-backed stores; run it
    // off the async worker so a disk-blocked read can't starve the
    // server's accept loop under heavy sync load (see `crate::blocking`).
    let result = crate::blocking::run_blocking(|| dispatch(&req.method, &req.params, &state));
    // Per-method counter — records both success and failure paths
    // so operators can spot a method that's erroring at a high rate.
    if let Some(m) = &state.metrics {
        m.record_rpc_request(&req.method, result.is_ok());
    }
    match result {
        Ok(value) => Json(json!({
            "jsonrpc": "2.0",
            "result": value,
            "id": id,
        })),
        Err(err) => Json(json!({
            "jsonrpc": "2.0",
            "error": err.to_error_object(),
            "id": id,
        })),
    }
}

/// Build a dedicated metrics-only axum router that serves the
/// Prometheus exposition format at `/metrics`. Run on a separate
/// port from the main JSON-RPC so the two endpoints can be exposed
/// to different audiences (RPC public, metrics internal).
pub fn metrics_router(metrics: std::sync::Arc<crate::metrics::Metrics>) -> Router {
    Router::new()
        .route(
            "/metrics",
            axum::routing::get(move || {
                let m = metrics.clone();
                async move {
                    (
                        [(
                            axum::http::header::CONTENT_TYPE,
                            "text/plain; version=0.0.4; charset=utf-8",
                        )],
                        m.to_prometheus_text(),
                    )
                }
            }),
        )
}

/// Pub-visible alias of [`dispatch`] so [`crate::pubsub`]'s WS
/// handler can forward non-subscription requests through the same
/// method table. Keeps the WS surface identical to the HTTP one.
pub fn ws_dispatch(method: &str, params: &Value, state: &RpcState) -> Result<Value, RpcError> {
    // Mirror the HTTP path: the WS frame loop is async, so keep the
    // synchronous store reads off its worker thread (see `crate::blocking`).
    crate::blocking::run_blocking(|| dispatch(method, params, state))
}

fn dispatch(method: &str, params: &Value, state: &RpcState) -> Result<Value, RpcError> {
    use methods::*;
    match method {
        "web3_clientVersion" => web3_client_version(params, state),
        "web3_sha3" => web3_sha3(params, state),
        "net_version" => net_version(params, state),
        "net_listening" => net_listening(params, state),
        "eth_chainId" => eth_chain_id(params, state),
        "eth_protocolVersion" => eth_protocol_version(params, state),
        "eth_blockNumber" => eth_block_number(params, state),
        "eth_gasPrice" => eth_gas_price(params, state),
        "eth_getBalance" => eth_get_balance(params, state),
        "eth_getBlockByNumber" => eth_get_block_by_number(params, state),
        "eth_getBlockByHash" => eth_get_block_by_hash(params, state),
        "eth_getTransactionByHash" => eth_get_transaction_by_hash(params, state),
        "eth_getTransactionCount" => eth_get_transaction_count(params, state),
        "eth_getCode" => eth_get_code(params, state),
        "eth_getStorageAt" => eth_get_storage_at(params, state),
        "eth_getBlockTransactionCountByNumber" => {
            eth_get_block_transaction_count_by_number(params, state)
        }
        "eth_getBlockTransactionCountByHash" => {
            eth_get_block_transaction_count_by_hash(params, state)
        }
        "eth_syncing" => eth_syncing(params, state),
        "eth_mining" => eth_mining(params, state),
        "eth_hashrate" => eth_hashrate(params, state),
        "eth_accounts" => eth_accounts(params, state),
        "eth_coinbase" => eth_coinbase(params, state),
        "eth_maxPriorityFeePerGas" => eth_max_priority_fee_per_gas(params, state),
        "eth_feeHistory" => eth_fee_history(params, state),
        "eth_getTransactionByBlockNumberAndIndex" => {
            eth_get_transaction_by_block_number_and_index(params, state)
        }
        "eth_getTransactionByBlockHashAndIndex" => {
            eth_get_transaction_by_block_hash_and_index(params, state)
        }
        "eth_blobBaseFee" => eth_blob_base_fee(params, state),
        "net_peerCount" => net_peer_count(params, state),

        // TRON wallet-style methods.
        "getAccount" => get_account(params, state),
        "getNowBlock" => get_now_block(params, state),
        "getBlockByNum" => get_block_by_num(params, state),
        "getChainParameters" => get_chain_parameters(params, state),
        "listWitnesses" => list_witnesses(params, state),
        "getDelegatedResource" => get_delegated_resource(params, state),
        "getBrokerage" => get_brokerage(params, state),
        "getReward" => get_reward(params, state),
        "getBurnTrx" => get_burn_trx(params, state),
        "listProposals" => list_proposals(params, state),
        "getAssetIssueById" => get_asset_issue_by_id(params, state),
        "getExchangeById" => get_exchange_by_id(params, state),
        "getNodeInfo" => get_node_info(params, state),
        "getBandwidthPrices" => get_bandwidth_prices(params, state),
        "getEnergyPrices" => get_energy_prices(params, state),

        // TVM read-only execution.
        "eth_call" => eth_call(params, state),
        "eth_simulateV1" => crate::eth_simulate::eth_simulate_v1(params, state),
        "eth_supportedEntryPoints" => crate::bundler::eth_supported_entry_points(state),
        "eth_sendUserOperation" => crate::bundler::eth_send_user_operation(params, state),
        "eth_getUserOperationByHash" => crate::bundler::eth_get_user_operation_by_hash(params, state),
        "eth_getUserOperationReceipt" => crate::bundler::eth_get_user_operation_receipt(params, state),
        "eth_estimateUserOperationGas" => crate::bundler::eth_estimate_user_operation_gas(params, state),
        "debug_bundler_sendBundleNow" => crate::bundler::debug_bundler_send_bundle_now(state),
        "debug_bundler_setBundlingMode" => crate::bundler::debug_bundler_set_bundling_mode(params, state),
        "debug_bundler_dumpMempool" => crate::bundler::debug_bundler_dump_mempool(params, state),
        "debug_bundler_clearMempool" => crate::bundler::debug_bundler_clear_mempool(state),
        "debug_bundler_clearState" => crate::bundler::debug_bundler_clear_state(state),
        "debug_bundler_dumpReputation" => crate::bundler::debug_bundler_dump_reputation(params, state),
        "debug_bundler_setReputation" => crate::bundler::debug_bundler_set_reputation(params, state),
        "debug_bundler_clearReputation" => crate::bundler::debug_bundler_clear_reputation(state),
        "debug_bundler_getStakeStatus" => crate::bundler::debug_bundler_get_stake_status(params, state),
        "eth_estimateGas" => eth_estimate_gas(params, state),
        "eth_getTransactionReceipt" => eth_get_transaction_receipt(params, state),
        "eth_getLogs" => eth_get_logs(params, state),

        // TRON-flavoured RPCs that mirror the same things.
        "getTransactionInfoById" => get_transaction_info_by_id(params, state),
        "getTransactionInfoByBlockNum" => get_transaction_info_by_block_num(params, state),
        "listAssets" | "getAssetIssueList" => list_assets(params, state),
        "listExchanges" => list_exchanges(params, state),
        "getNextMaintenanceTime" => get_next_maintenance_time(params, state),
        "getNodes" | "listNodes" => get_nodes(params, state),
        "getAccountById" => get_account_by_id(params, state),
        "triggerConstantContract" => trigger_constant_contract(params, state),

        // Broadcast — mempool-backed when attached, otherwise rejecting.
        "broadcastTransaction" | "broadcastHex" => broadcast_transaction_v2(params, state),
        "eth_sendRawTransaction" => eth_send_raw_transaction_v2(params, state),

        // txpool_* (geth-compat mempool inspection).
        "txpool_status" => txpool_status(params, state),
        "txpool_content" => txpool_content(params, state),
        "txpool_inspect" => txpool_inspect(params, state),

        // debug_* / trace_* (EVM trace surface).
        "debug_traceCall" => debug_trace_call(params, state),
        "debug_traceTransaction" => debug_trace_transaction(params, state),
        "debug_traceBlockByNumber" => debug_trace_block_by_number(params, state),
        "debug_traceBlockByHash" => debug_trace_block_by_hash(params, state),
        "trace_call" => trace_call(params, state),
        "trace_transaction" => trace_transaction(params, state),
        "trace_block" => trace_block(params, state),

        // Filter family.
        "eth_newFilter" => eth_new_filter(params, state),
        "eth_newBlockFilter" => eth_new_block_filter(params, state),
        "eth_newPendingTransactionFilter" => eth_new_pending_transaction_filter(params, state),
        "eth_uninstallFilter" => eth_uninstall_filter(params, state),
        "eth_getFilterChanges" => eth_get_filter_changes(params, state),
        "eth_getFilterLogs" => eth_get_filter_logs(params, state),

        // Account-state proofs (EIP-1186). TRON has no MPT; method
        // returns empty proof arrays but populated values.
        "eth_getProof" => eth_get_proof(params, state),

        // ============================
        // Account / resource (TRON HTTP API parity)
        // ============================
        "getAccountResource" => get_account_resource(params, state),
        "getAccountNet" => get_account_net(params, state),

        // ============================
        // Delegate / unfreeze (v2 staking)
        // ============================
        "getDelegatedResourceV2" => get_delegated_resource_v2(params, state),
        "getDelegatedResourceAccountIndex" => get_delegated_resource_account_index(params, state),
        "getDelegatedResourceAccountIndexV2" => {
            get_delegated_resource_account_index_v2(params, state)
        }
        "getCanWithdrawUnfreezeAmount" => get_can_withdraw_unfreeze_amount(params, state),
        "getAvailableUnfreezeCount" => get_available_unfreeze_count(params, state),

        // ============================
        // Block pagination
        // ============================
        "getBlock" => get_block(params, state),
        "getBlockById" => get_block_by_id(params, state),
        "getBlockByLimitNext" => get_block_by_limit_next(params, state),
        "getBlockByLatestNum" => get_block_by_latest_num(params, state),

        // ============================
        // Contract / asset / proposal lookups
        // ============================
        "getContract" => get_contract(params, state),
        "getContractInfo" => get_contract_info(params, state),
        "decodeContractData" | "decodecontractdata" => decode_contract_data(params, state),
        "decodeEventLog" | "decodeeventlog" => decode_event_log(params, state),
        "getProposalById" => get_proposal_by_id(params, state),
        "getAssetIssueByAccount" => get_asset_issue_by_account(params, state),
        "validateAddress" => validate_address(params, state),
        "getPendingSize" => get_pending_size(params, state),

        // ============================
        // Market (DEX) read methods
        // ============================
        "getMarketOrderById" => get_market_order_by_id(params, state),
        "getMarketOrderByAccount" => get_market_order_by_account(params, state),
        "getMarketPriceByPair" => get_market_price_by_pair(params, state),
        "getMarketPairList" => get_market_pair_list(params, state),
        "getMarketOrderListByPair" => get_market_order_list_by_pair(params, state),

        // ============================
        // Asset-by-name + pagination
        // ============================
        "getAssetIssueByName" => get_asset_issue_by_name(params, state),
        "getAssetIssueListByName" => get_asset_issue_list_by_name(params, state),
        "getPaginatedAssetIssueList" => get_paginated_asset_issue_list(params, state),
        "getPaginatedProposalList" => get_paginated_proposal_list(params, state),
        "getPaginatedExchangeList" => get_paginated_exchange_list(params, state),

        // ============================
        // Transaction + misc
        // ============================
        "getTransactionById" => get_transaction_by_id(params, state),
        "getTotalTransaction" | "totalTransaction" => get_total_transaction(params, state),
        "getTransactionCountByBlockNum" => get_transaction_count_by_block_num(params, state),
        "getCanDelegatedMaxSize" => get_can_delegated_max_size(params, state),
        "getMemoFee" => get_memo_fee(params, state),
        "estimateEnergy" => estimate_energy(params, state),

        // ============================
        // Multi-sig
        // ============================
        "getApprovedList" => get_approved_list(params, state),
        "getSignWeight" => get_sign_weight(params, state),

        // ============================
        // Solidified-state aliases (walletsolidity/* namespace)
        // ============================
        "getNowBlockSolidity" | "walletsolidity_getNowBlock" => {
            get_now_block_solidity(params, state)
        }
        "getBlockByNumSolidity" | "walletsolidity_getBlockByNum" => {
            get_block_by_num_solidity(params, state)
        }
        "getTransactionByIdSolidity" | "walletsolidity_getTransactionById" => {
            get_transaction_by_id_solidity(params, state)
        }
        "getTransactionInfoByIdSolidity" | "walletsolidity_getTransactionInfoById" => {
            get_transaction_info_by_id_solidity(params, state)
        }
        "getAccountSolidity" | "walletsolidity_getAccount" => {
            get_account_solidity(params, state)
        }
        "getDelegatedResourceSolidity" | "walletsolidity_getDelegatedResource" => {
            get_delegated_resource_solidity(params, state)
        }

        // ============================
        // Per-block balance trace
        // ============================
        "getBlockBalanceTrace" => get_block_balance_trace(params, state),

        // ============================
        // Builder endpoints (Tier 1) — return unsigned Transaction envelopes
        // ============================
        "createTransaction" => create_transaction(params, state),
        "transferAsset" => transfer_asset(params, state),
        "triggerSmartContract" => build_trigger_smart_contract(params, state),
        "freezeBalanceV2" => freeze_balance_v2(params, state),
        "unfreezeBalanceV2" => unfreeze_balance_v2(params, state),
        "withdrawExpireUnfreeze" => withdraw_expire_unfreeze(params, state),
        "cancelAllUnfreezeV2" => cancel_all_unfreeze_v2(params, state),
        "delegateResource" => delegate_resource(params, state),
        "unDelegateResource" => un_delegate_resource(params, state),
        "voteWitnessAccount" => vote_witness_account(params, state),
        "withdrawBalance" => withdraw_balance(params, state),
        "accountPermissionUpdate" => account_permission_update(params, state),
        "updateBrokerage" => update_brokerage(params, state),

        // ============================
        // Builder endpoints (Tier 2) — account, witness, proposal, asset
        // ============================
        "createAccount" => create_account(params, state),
        "updateAccount" => update_account(params, state),
        "setAccountId" => set_account_id(params, state),
        "createWitness" => create_witness(params, state),
        "updateWitness" => update_witness(params, state),
        "proposalCreate" => proposal_create(params, state),
        "proposalApprove" => proposal_approve(params, state),
        "proposalDelete" => proposal_delete(params, state),
        "createAssetIssue" => create_asset_issue(params, state),
        "updateAsset" => update_asset(params, state),
        "participateAssetIssue" => participate_asset_issue(params, state),
        "unfreezeAsset" => unfreeze_asset(params, state),

        // ============================
        // Builder endpoints (Tier 3) — contract deploy/admin, exchange, market
        // ============================
        "deployContract" => deploy_contract(params, state),
        "updateSetting" => update_setting(params, state),
        "updateEnergyLimit" => update_energy_limit(params, state),
        "clearAbi" | "clearABI" | "clearContractABI" => clear_abi(params, state),
        "exchangeCreate" => exchange_create(params, state),
        "exchangeInject" => exchange_inject(params, state),
        "exchangeWithdraw" => exchange_withdraw(params, state),
        "exchangeTransaction" => exchange_transaction(params, state),
        "marketSellAsset" => market_sell_asset(params, state),
        "marketCancelOrder" => market_cancel_order(params, state),
        "freezeBalance" => freeze_balance(params, state),
        "unfreezeBalance" => unfreeze_balance(params, state),

        // ============================
        // Shielded TRC-20 key helpers
        // ============================
        "getSpendingKey" => get_spending_key(params, state),
        "getExpandedSpendingKey" => get_expanded_spending_key(params, state),
        "getAkFromAsk" => get_ak_from_ask(params, state),
        "getNkFromNsk" => get_nk_from_nsk(params, state),
        "getIncomingViewingKey" => get_incoming_viewing_key(params, state),
        "getDiversifier" => get_diversifier(params, state),
        "getZenPaymentAddress" => get_zen_payment_address(params, state),
        "getRcm" => get_rcm(params, state),

        // ============================
        // eth_* parity additions (java-tron exposes; we'd been
        // returning MethodNotFound). Real impls for getBlockReceipts /
        // parity_nextNonce / buildTransaction; no-op shapes for
        // uncle / work; documented MethodNotFound for the
        // node-manages-keys + deprecated-compiler families.
        // ============================
        "eth_getBlockReceipts" => eth_get_block_receipts(params, state),
        "eth_getUncleByBlockHashAndIndex" => {
            eth_get_uncle_by_block_hash_and_index(params, state)
        }
        "eth_getUncleByBlockNumberAndIndex" => {
            eth_get_uncle_by_block_number_and_index(params, state)
        }
        "eth_getUncleCountByBlockHash" => eth_get_uncle_count_by_block_hash(params, state),
        "eth_getUncleCountByBlockNumber" => eth_get_uncle_count_by_block_number(params, state),
        "eth_getWork" => eth_get_work(params, state),
        "parity_nextNonce" => parity_next_nonce(params, state),
        "buildTransaction" => build_transaction(params, state),
        // Node-managed keys — not supported.
        "eth_sendTransaction" => eth_send_transaction(params, state),
        "eth_sign" => eth_sign(params, state),
        "eth_signTransaction" => eth_sign_transaction(params, state),
        // PoW / deprecated.
        "eth_submitWork" => eth_submit_work(params, state),
        "eth_submitHashrate" => eth_submit_hashrate(params, state),
        "eth_getCompilers" => eth_get_compilers(params, state),
        "eth_compileSolidity" => eth_compile_solidity(params, state),
        "eth_compileLLL" => eth_compile_lll(params, state),
        "eth_compileSerpent" => eth_compile_serpent(params, state),

        other => Err(RpcError::method_not_found(other)),
    }
}
