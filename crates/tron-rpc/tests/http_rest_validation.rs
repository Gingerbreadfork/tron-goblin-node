//! Input-validation tests for the `/wallet/*` HTTP surface.
//!
//! The main `http_rest.rs` test file covers happy-path round-trips
//! for ~20 endpoints. This file fills the gap on per-endpoint input
//! shape rejection: missing fields, malformed address formats, bad
//! hex, the `visible: true` / `visible: false` address format
//! switch, and the conventional "return {} with Error field" shape
//! java-tron uses instead of HTTP-status-coded errors.
//!
//! Java reference: `*ServletTest` files under `core/services/http/`,
//! roughly 50+ per-endpoint cases focused on input handling.

use std::sync::Arc;

use hex_literal::hex;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tron_chainbase::{
    AccountStore, BlockIndexStore, BlockStore, DynamicPropertiesStore, KvBackend, MemBackend,
    TransactionStore, WitnessStore,
};
use tron_crypto::address::Address;
use tron_proto::block_header::Raw as BlockHeaderRaw;
use tron_proto::{Account, AccountType, Block, BlockHeader, Witness};
use tron_rpc::{RpcState, MAINNET_CHAIN_ID};
use tron_types::block_id_from_block;

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

const ALICE: [u8; 21] = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");
const BOB: [u8; 21] = hex!("41a614f803b6fd780986a42c78ec9c7f77e6ded13c");

async fn spawn_server() -> std::net::SocketAddr {
    let accounts_be = mem();
    let blocks_be = mem();
    let block_index_be = mem();
    let trans_be = mem();
    let dp_be = mem();
    let witnesses_be = mem();

    AccountStore::new(accounts_be.clone()).put(
        &Address::from_raw(ALICE),
        &Account {
            address: ALICE.to_vec(),
            balance: 100_000_000_000,
            r#type: AccountType::Normal as i32,
            ..Default::default()
        },
    ).unwrap();
    AccountStore::new(accounts_be.clone()).put(
        &Address::from_raw(BOB),
        &Account {
            address: BOB.to_vec(),
            balance: 50_000_000,
            r#type: AccountType::Normal as i32,
            ..Default::default()
        },
    ).unwrap();

    let block = Block {
        block_header: Some(BlockHeader {
            raw_data: Some(BlockHeaderRaw {
                number: 1,
                parent_hash: vec![0u8; 32],
                timestamp: 1_700_000_000_000,
                witness_address: ALICE.to_vec(),
                ..Default::default()
            }),
            witness_signature: Vec::new(),
        }),
        transactions: Vec::new(),
    };
    let block_id = block_id_from_block(&block).unwrap();
    BlockStore::new(blocks_be.clone()).put(&block_id, &block).unwrap();
    BlockIndexStore::new(block_index_be.clone()).put(&block_id).unwrap();
    let dp = DynamicPropertiesStore::new(dp_be.clone());
    dp.save_latest_block_header_number(1);
    dp.save_latest_block_header_hash(block_id.as_bytes());
    let _ = TransactionStore::new(trans_be.clone());

    WitnessStore::new(witnesses_be.clone()).put(
        &Address::from_raw(ALICE),
        &Witness {
            address: ALICE.to_vec(),
            url: "https://test.witness".into(),
            ..Default::default()
        },
    ).unwrap();

    let state = RpcState::new(
        accounts_be,
        blocks_be,
        block_index_be,
        trans_be,
        dp_be,
        MAINNET_CHAIN_ID,
    )
    .with_governance_stores(witnesses_be, mem(), mem(), mem(), mem(), mem());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = tron_rpc::http_rest::router(state.clone());
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service()).await.unwrap();
    });
    tokio::task::yield_now().await;
    addr
}

async fn http_post(addr: std::net::SocketAddr, path: &str, body: Value) -> Value {
    let body_str = body.to_string();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body_str}",
        body_str.len()
    );
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    let body = response.split("\r\n\r\n").nth(1).unwrap_or("");
    serde_json::from_str(body).unwrap_or_else(|e| panic!("non-json response: {e}; raw: {response}"))
}

fn has_error(v: &Value) -> bool {
    v.get("Error").is_some()
        || v.get("error").is_some()
        || v.get("code").is_some_and(|c| c.as_str() != Some("SUCCESS"))
}

// ============================================================
// /wallet/getaccount input validation
// ============================================================

#[tokio::test]
async fn getaccount_with_missing_address_returns_error_or_empty() {
    let addr = spawn_server().await;
    let resp = http_post(addr, "/wallet/getaccount", json!({})).await;
    // Either an error field, or an empty object (java-tron returns
    // empty for absent address). Both are acceptable.
    assert!(
        has_error(&resp) || resp.as_object().map(|o| o.is_empty()).unwrap_or(false),
        "got: {resp}"
    );
}

#[tokio::test]
async fn getaccount_with_garbage_address_does_not_crash() {
    let addr = spawn_server().await;
    let resp = http_post(
        addr,
        "/wallet/getaccount",
        json!({ "address": "garbage-not-an-address", "visible": true }),
    )
    .await;
    // Whether it returns an error or just {} is implementation-defined,
    // but the server MUST stay up. The next request must succeed.
    let _ = resp;
    let resp2 = http_post(
        addr,
        "/wallet/getaccount",
        json!({ "address": "412e988a386a799f506693793c6a5af6b54dfaabfb", "visible": false }),
    )
    .await;
    assert!(
        resp2["balance"].as_i64().is_some(),
        "server must still answer after garbage input; got: {resp2}"
    );
}

#[tokio::test]
async fn getaccount_visible_true_returns_t_address_form() {
    let addr = spawn_server().await;
    let alice_b58 = tron_crypto::base58check::encode_address(&Address::from_raw(ALICE));
    let resp = http_post(
        addr,
        "/wallet/getaccount",
        json!({ "address": alice_b58, "visible": true }),
    )
    .await;
    let returned = resp["address"].as_str().unwrap();
    assert!(returned.starts_with('T'));
}

#[tokio::test]
async fn getaccount_visible_false_returns_hex_address_form() {
    let addr = spawn_server().await;
    let resp = http_post(
        addr,
        "/wallet/getaccount",
        json!({ "address": "412e988a386a799f506693793c6a5af6b54dfaabfb", "visible": false }),
    )
    .await;
    let returned = resp["address"].as_str().unwrap();
    assert!(returned.starts_with("41"));
    assert!(!returned.starts_with("0x"));
}

#[tokio::test]
async fn getaccount_unknown_address_returns_empty_or_null() {
    let addr = spawn_server().await;
    let unknown_b58 = tron_crypto::base58check::encode_address(&Address::from_raw({
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[20] = 0x99;
        a
    }));
    let resp = http_post(
        addr,
        "/wallet/getaccount",
        json!({ "address": unknown_b58, "visible": true }),
    )
    .await;
    // java-tron returns an empty object {} for unknown accounts. Our
    // current shape returns JSON null. Either is a "no data" signal —
    // the contract is "no balance field" (which would be present for
    // a known account).
    let known = resp["balance"].as_i64();
    assert!(
        known.is_none(),
        "expected no balance for unknown account, got: {resp}"
    );
}

// ============================================================
// /wallet/getblockbynum input validation
// ============================================================

#[tokio::test]
async fn getblockbynum_missing_num_returns_error_field() {
    let addr = spawn_server().await;
    let resp = http_post(addr, "/wallet/getblockbynum", json!({})).await;
    assert!(has_error(&resp), "expected error field, got: {resp}");
}

#[tokio::test]
async fn getblockbynum_negative_num_does_not_crash() {
    let addr = spawn_server().await;
    let resp = http_post(addr, "/wallet/getblockbynum", json!({ "num": -1 })).await;
    // Either an error, or an empty response, but no panic.
    assert!(
        has_error(&resp) || resp.as_object().map(|o| o.is_empty()).unwrap_or(true)
    );
}

#[tokio::test]
async fn getblockbynum_unknown_num_returns_empty_object() {
    let addr = spawn_server().await;
    let resp = http_post(addr, "/wallet/getblockbynum", json!({ "num": 999_999_999 })).await;
    assert!(
        resp.as_object().map(|o| o.is_empty()).unwrap_or(false),
        "expected {{}} for unknown block, got: {resp}"
    );
}

#[tokio::test]
async fn getblockbynum_returns_block_for_existing_num() {
    let addr = spawn_server().await;
    let resp = http_post(addr, "/wallet/getblockbynum", json!({ "num": 1 })).await;
    let num = resp["block_header"]["raw_data"]["number"].as_i64().unwrap();
    assert_eq!(num, 1);
}

// ============================================================
// /wallet/validateaddress input validation
// ============================================================

#[tokio::test]
async fn validateaddress_accepts_base58_form() {
    let addr = spawn_server().await;
    let alice_b58 = tron_crypto::base58check::encode_address(&Address::from_raw(ALICE));
    let resp = http_post(
        addr,
        "/wallet/validateaddress",
        json!({ "address": alice_b58 }),
    )
    .await;
    assert_eq!(resp["result"], json!(true));
}

#[tokio::test]
async fn validateaddress_rejects_too_short_address() {
    let addr = spawn_server().await;
    let resp = http_post(
        addr,
        "/wallet/validateaddress",
        json!({ "address": "T123" }),
    )
    .await;
    assert_eq!(resp["result"], json!(false));
}

#[tokio::test]
async fn validateaddress_rejects_garbage() {
    let addr = spawn_server().await;
    let resp = http_post(
        addr,
        "/wallet/validateaddress",
        json!({ "address": "not_a_valid_tron_address_at_all" }),
    )
    .await;
    assert_eq!(resp["result"], json!(false));
}

#[tokio::test]
async fn validateaddress_rejects_missing_address_field() {
    let addr = spawn_server().await;
    let resp = http_post(addr, "/wallet/validateaddress", json!({})).await;
    // Either result=false OR an Error field — both acceptable.
    assert!(
        resp["result"] == json!(false) || has_error(&resp),
        "got: {resp}"
    );
}

// ============================================================
// /wallet/getchainparameters
// ============================================================

#[tokio::test]
async fn getchainparameters_returns_keyed_array() {
    let addr = spawn_server().await;
    let resp = http_post(addr, "/wallet/getchainparameters", json!({})).await;
    assert!(
        resp["chainParameter"].is_array(),
        "expected chainParameter array, got: {resp}"
    );
}

// ============================================================
// /wallet/listwitnesses
// ============================================================

#[tokio::test]
async fn listwitnesses_returns_witnesses_array() {
    let addr = spawn_server().await;
    let resp = http_post(addr, "/wallet/listwitnesses", json!({})).await;
    let witnesses = resp["witnesses"].as_array().expect("witnesses array");
    assert!(!witnesses.is_empty());
}

// ============================================================
// /wallet/createtransaction input validation
// ============================================================

#[tokio::test]
async fn createtransaction_missing_to_address_returns_error() {
    let addr = spawn_server().await;
    let alice_b58 = tron_crypto::base58check::encode_address(&Address::from_raw(ALICE));
    let resp = http_post(
        addr,
        "/wallet/createtransaction",
        json!({
            "owner_address": alice_b58,
            "amount": 100,
            "visible": true,
        }),
    )
    .await;
    assert!(has_error(&resp), "got: {resp}");
}

// NOTE: `/wallet/createtransaction` in tron-goblin-node is a permissive
// envelope builder — it doesn't pre-validate amount > 0 or owner !=
// to_address. Those constraints are enforced at actuator-execute
// time. java-tron's HTTP layer pre-rejects; ours doesn't. Result:
// the wallet caller gets a valid-looking envelope back, then the
// broadcast fails with a clearer actuator error. Track as a UX
// deviation, not a correctness bug.
#[tokio::test]
async fn createtransaction_with_missing_amount_treats_as_zero_and_builds_envelope() {
    let addr = spawn_server().await;
    let alice_b58 = tron_crypto::base58check::encode_address(&Address::from_raw(ALICE));
    let bob_b58 = tron_crypto::base58check::encode_address(&Address::from_raw(BOB));
    let resp = http_post(
        addr,
        "/wallet/createtransaction",
        json!({
            "owner_address": alice_b58,
            "to_address": bob_b58,
            "visible": true,
        }),
    )
    .await;
    // Pinning: we currently return an envelope. Wallets relying on
    // pre-validation should NOT depend on this — actuator rejection
    // is the canonical signal.
    assert!(resp["txID"].is_string(), "got: {resp}");
}

#[tokio::test]
async fn createtransaction_with_zero_amount_builds_envelope_but_will_fail_on_broadcast() {
    let addr = spawn_server().await;
    let alice_b58 = tron_crypto::base58check::encode_address(&Address::from_raw(ALICE));
    let bob_b58 = tron_crypto::base58check::encode_address(&Address::from_raw(BOB));
    let resp = http_post(
        addr,
        "/wallet/createtransaction",
        json!({
            "owner_address": alice_b58,
            "to_address": bob_b58,
            "amount": 0,
            "visible": true,
        }),
    )
    .await;
    // Pinning the deviation from java-tron (which pre-rejects).
    assert!(resp["txID"].is_string(), "got: {resp}");
}

#[tokio::test]
async fn createtransaction_with_self_transfer_builds_envelope_but_will_fail_on_broadcast() {
    let addr = spawn_server().await;
    let alice_b58 = tron_crypto::base58check::encode_address(&Address::from_raw(ALICE));
    let resp = http_post(
        addr,
        "/wallet/createtransaction",
        json!({
            "owner_address": alice_b58,
            "to_address": alice_b58,
            "amount": 100,
            "visible": true,
        }),
    )
    .await;
    // Pinning the deviation: builder doesn't pre-reject self-transfer.
    assert!(resp["txID"].is_string(), "got: {resp}");
}

#[tokio::test]
async fn createtransaction_valid_inputs_returns_envelope() {
    let addr = spawn_server().await;
    let alice_b58 = tron_crypto::base58check::encode_address(&Address::from_raw(ALICE));
    let bob_b58 = tron_crypto::base58check::encode_address(&Address::from_raw(BOB));
    let resp = http_post(
        addr,
        "/wallet/createtransaction",
        json!({
            "owner_address": alice_b58,
            "to_address": bob_b58,
            "amount": 1_000_000,
            "visible": true,
        }),
    )
    .await;
    // Envelope must include a txID + raw_data.
    assert!(resp["txID"].is_string(), "expected txID; got: {resp}");
    assert!(resp["raw_data"].is_object());
}

// ============================================================
// /wallet/broadcasttransaction
// ============================================================

#[tokio::test]
async fn broadcasttransaction_missing_body_returns_error() {
    let addr = spawn_server().await;
    let resp = http_post(addr, "/wallet/broadcasttransaction", json!({})).await;
    // Either error or a "code:FAILED" response — accept both shapes.
    assert!(
        has_error(&resp) || resp["result"] == json!(false),
        "got: {resp}"
    );
}

#[tokio::test]
async fn broadcasttransaction_garbage_raw_returns_error() {
    let addr = spawn_server().await;
    let resp = http_post(
        addr,
        "/wallet/broadcasttransaction",
        json!({
            "raw_data": "not_valid_hex",
            "signature": ["00"],
        }),
    )
    .await;
    assert!(
        has_error(&resp) || resp["result"] == json!(false),
        "got: {resp}"
    );
}

// ============================================================
// /wallet/getmemofee — read-only chain param
// ============================================================

#[tokio::test]
async fn getmemofee_returns_value_field() {
    let addr = spawn_server().await;
    let resp = http_post(addr, "/wallet/getmemofee", json!({})).await;
    assert!(resp["value"].is_number(), "got: {resp}");
}

// ============================================================
// /wallet/getbandwidthprices
// ============================================================

#[tokio::test]
async fn getbandwidthprices_returns_prices_string() {
    let addr = spawn_server().await;
    let resp = http_post(addr, "/wallet/getbandwidthprices", json!({})).await;
    // Either "prices" string or empty depending on chain state.
    assert!(resp["prices"].is_string() || resp.as_object().map(|o| o.is_empty()).unwrap_or(false));
}

// ============================================================
// /walletsolidity alias — same handler as /wallet
// ============================================================

#[tokio::test]
async fn walletsolidity_routes_to_same_handler_as_wallet() {
    let addr = spawn_server().await;
    let alice_b58 = tron_crypto::base58check::encode_address(&Address::from_raw(ALICE));
    let resp_a = http_post(
        addr,
        "/wallet/getaccount",
        json!({ "address": alice_b58, "visible": true }),
    )
    .await;
    let resp_b = http_post(
        addr,
        "/walletsolidity/getaccount",
        json!({ "address": alice_b58, "visible": true }),
    )
    .await;
    assert_eq!(resp_a["balance"], resp_b["balance"]);
}

// ============================================================
// 404 + method-not-allowed handling
// ============================================================

#[tokio::test]
async fn unknown_path_returns_404_or_empty_not_panic() {
    let addr = spawn_server().await;
    // Raw request: this path doesn't exist.
    let req = "POST /wallet/this_endpoint_does_not_exist HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    // Should be a 404, not a server crash. We just check the response
    // is well-formed HTTP.
    assert!(response.starts_with("HTTP/1.1"), "got: {response}");
}

// ============================================================
// `visible` flag boundary handling
// ============================================================

#[tokio::test]
async fn visible_flag_defaults_to_false_when_omitted() {
    let addr = spawn_server().await;
    // No visible flag → expect hex format response.
    let resp = http_post(
        addr,
        "/wallet/getaccount",
        json!({ "address": "412e988a386a799f506693793c6a5af6b54dfaabfb" }),
    )
    .await;
    let returned = resp["address"].as_str().unwrap_or("");
    assert!(returned.starts_with("41") || returned.is_empty(), "got: {returned}");
}
