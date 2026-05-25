//! End-to-end test for the HTTP rate-limit middleware.
//!
//! Sets up a `router_with_rate_limits` configured for a specific
//! servlet, fires more requests than the bucket allows, and confirms
//! the over-rate requests get HTTP 429. Also verifies that an
//! unconfigured route passes through unlimited.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;
use tron_chainbase::{KvBackend, MemBackend};
use tron_rpc::{
    http_rest::router_with_rate_limits, QpsBucket, RateLimit, RateLimitRegistry, RpcState,
};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn fresh_state() -> RpcState {
    RpcState::new(mem(), mem(), mem(), mem(), mem(), 11_111)
}

/// One QPS bucket on `/wallet/getaccount`.
fn registry_with_qps_1_on_getaccount() -> RateLimitRegistry {
    let mut m: HashMap<String, RateLimit> = HashMap::new();
    m.insert("getaccount".into(), RateLimit::Qps(QpsBucket::new(1.0)));
    RateLimitRegistry::new(m)
}

fn post_getaccount_req() -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/wallet/getaccount")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"address": "411111111111111111111111111111111111111111"}).to_string(),
        ))
        .unwrap()
}

#[tokio::test]
async fn rate_limited_route_returns_429_after_bucket_drains() {
    let state = fresh_state();
    let app = router_with_rate_limits(state, registry_with_qps_1_on_getaccount());

    // First request consumes the initial 1-permit burst.
    let r1 = app.clone().oneshot(post_getaccount_req()).await.unwrap();
    // The underlying handler may return 200 or some other code based
    // on the empty store — we only care that the rate limiter let it
    // through (NOT 429).
    assert_ne!(r1.status(), StatusCode::TOO_MANY_REQUESTS);

    // Second request immediately afterwards must be 429.
    let r2 = app.clone().oneshot(post_getaccount_req()).await.unwrap();
    assert_eq!(r2.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn unconfigured_route_passes_through_unlimited() {
    let state = fresh_state();
    let app = router_with_rate_limits(state, registry_with_qps_1_on_getaccount());
    // `getnowblock` isn't in the registry → all requests pass.
    for _ in 0..5 {
        let r = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/wallet/getnowblock")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(
            r.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "unconfigured route must not be rate-limited"
        );
    }
}

#[tokio::test]
async fn empty_registry_disables_middleware_entirely() {
    let state = fresh_state();
    let app = router_with_rate_limits(state, RateLimitRegistry::empty());
    // Fire many requests on what would otherwise be the limited
    // route — empty registry means the layer is never installed.
    for _ in 0..10 {
        let r = app.clone().oneshot(post_getaccount_req()).await.unwrap();
        assert_ne!(r.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
