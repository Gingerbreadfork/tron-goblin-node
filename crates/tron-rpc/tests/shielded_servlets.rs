//! HTTP smoke tests for the shielded TRC-20 / TRC-10 key-derivation
//! servlets. Each test hits the route via axum's `oneshot` test
//! transport and asserts the shape java-tron clients expect (raw
//! lowercase hex, no `0x` prefix; field names matching
//! `wallet/getexpandedspendingkey` etc.).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;
use tron_chainbase::{KvBackend, MemBackend};
use tron_rpc::RpcState;

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn build_state() -> RpcState {
    RpcState::new(mem(), mem(), mem(), mem(), mem(), 11_111)
}

async fn post(
    router: axum::Router,
    path: &str,
    body: Value,
) -> Value {
    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK, "{}", path);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

async fn get(router: axum::Router, path: &str) -> Value {
    let req = Request::builder()
        .method("GET")
        .uri(path)
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK, "{}", path);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn getspendingkey_returns_64_char_hex_no_prefix() {
    let router = tron_rpc::http_rest::router(build_state());
    let value = get(router, "/wallet/getspendingkey").await;
    let hex = value["value"].as_str().expect("value field");
    assert!(!hex.starts_with("0x"), "no 0x prefix: {hex}");
    assert_eq!(hex.len(), 64, "32 bytes = 64 hex chars: {hex}");
    // Hex-validate.
    hex::decode(hex).expect("valid hex");
}

#[tokio::test]
async fn getexpandedspendingkey_returns_three_components() {
    let router = tron_rpc::http_rest::router(build_state());
    // Generate a key first.
    let key = get(router.clone(), "/wallet/getspendingkey").await;
    let sk_hex = key["value"].as_str().unwrap().to_string();
    let router2 = tron_rpc::http_rest::router(build_state());
    let resp = post(
        router2,
        "/wallet/getexpandedspendingkey",
        json!({"value": sk_hex.clone()}),
    )
    .await;
    eprintln!("expanded response: {}", resp);
    let ask = resp["ask"].as_str().unwrap_or_else(|| panic!("ask field; full response: {resp}"));
    let nsk = resp["nsk"].as_str().expect("nsk field");
    let ovk = resp["ovk"].as_str().expect("ovk field");
    for h in [ask, nsk, ovk] {
        assert!(!h.starts_with("0x"));
        assert_eq!(h.len(), 64);
        hex::decode(h).expect("valid hex");
    }
}

#[tokio::test]
async fn getakfromask_returns_compressed_jubjub_point() {
    let router = tron_rpc::http_rest::router(build_state());
    // Pull an ask out of a fresh expanded spending key.
    let key = get(router.clone(), "/wallet/getspendingkey").await;
    let sk_hex = key["value"].as_str().unwrap().to_string();
    let router2 = tron_rpc::http_rest::router(build_state());
    let exp = post(
        router2,
        "/wallet/getexpandedspendingkey",
        json!({"value": sk_hex}),
    )
    .await;
    let ask_hex = exp["ask"].as_str().unwrap().to_string();

    let router3 = tron_rpc::http_rest::router(build_state());
    let resp = post(
        router3,
        "/wallet/getakfromask",
        json!({"value": ask_hex}),
    )
    .await;
    let ak = resp["value"].as_str().expect("value");
    assert_eq!(ak.len(), 64, "ak is a 32-byte compressed point");
    hex::decode(ak).expect("valid hex");
}

#[tokio::test]
async fn getdiversifier_returns_22_char_hex() {
    let router = tron_rpc::http_rest::router(build_state());
    let resp = get(router, "/wallet/getdiversifier").await;
    let d = resp["value"].as_str().expect("value");
    assert!(!d.starts_with("0x"));
    assert_eq!(d.len(), 22, "diversifier is 11 bytes = 22 hex chars: {d}");
    hex::decode(d).expect("valid hex");
}

#[tokio::test]
async fn getrcm_returns_64_char_hex() {
    let router = tron_rpc::http_rest::router(build_state());
    let resp = get(router, "/wallet/getrcm").await;
    let r = resp["value"].as_str().expect("value");
    assert!(!r.starts_with("0x"));
    assert_eq!(r.len(), 64);
    hex::decode(r).expect("valid hex");
}

#[tokio::test]
async fn missing_value_field_returns_clear_error() {
    let router = tron_rpc::http_rest::router(build_state());
    let req = Request::builder()
        .method("POST")
        .uri("/wallet/getakfromask")
        .header("content-type", "application/json")
        .body(Body::from(json!({}).to_string()))
        .unwrap();
    let response = router.oneshot(req).await.unwrap();
    // java-tron pattern: HTTP 200 with an `Error` field in the body.
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert!(
        value.get("Error").is_some(),
        "missing `value` should surface an Error field; got {value}"
    );
}

#[tokio::test]
async fn walletsolidity_aliases_route_to_same_handlers() {
    let router = tron_rpc::http_rest::router(build_state());
    // Same shape as /wallet/getspendingkey but mounted under
    // /walletsolidity (read-only namespace). Both should return a
    // 64-char hex without prefix.
    let resp = get(router, "/walletsolidity/getspendingkey").await;
    let hex = resp["value"].as_str().unwrap();
    assert_eq!(hex.len(), 64);
}
