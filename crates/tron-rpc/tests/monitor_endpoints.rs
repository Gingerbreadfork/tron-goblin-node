//! Integration test for the `/monitor/*` HTTP endpoints.
//!
//! Mirrors java-tron's `MetricsServlet` (`/monitor/getstatsinfo`) and
//! `GetNodeInfoServlet` (`/monitor/getnodeinfo`) — both are read-only
//! operational endpoints consumed by Grafana / Prometheus exporters /
//! TronGrid-style dashboards.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use tron_chainbase::{KvBackend, MemBackend};
use tron_rpc::{http_rest::router, Metrics, RpcState};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn fresh_state() -> RpcState {
    RpcState::new(mem(), mem(), mem(), mem(), mem(), 11_111)
}

async fn body_to_json(
    response: axum::http::Response<Body>,
) -> serde_json::Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).expect("response body is JSON")
}

#[tokio::test]
async fn monitor_getnodeinfo_returns_200_with_node_info_shape() {
    let app = router(fresh_state());
    let res = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/monitor/getnodeinfo")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let v = body_to_json(res).await;
    // The shape must match `/wallet/getnodeinfo` exactly so dashboards
    // can be re-pointed at the `/monitor/` mount without surface
    // changes.
    assert!(v.get("configNodeInfo").is_some());
    assert!(v.get("block").is_some());
    assert!(v.get("activeConnectCount").is_some());
}

#[tokio::test]
async fn monitor_getstatsinfo_returns_metrics_info_shape() {
    let app = router(fresh_state());
    let res = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/monitor/getstatsinfo")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let v = body_to_json(res).await;
    // Top-level keys match java-tron's `MetricsInfo`.
    assert!(v.get("interval").is_some(), "must have interval");
    assert!(v.get("node").is_some(), "must have node sub-object");
    assert!(
        v.get("blockchain").is_some(),
        "must have blockchain sub-object"
    );
    assert!(v.get("net").is_some(), "must have net sub-object");
    // `blockchain` carries head + solid pointers.
    let chain = v.get("blockchain").unwrap();
    assert!(chain.get("headBlockNum").is_some());
    assert!(chain.get("solidifiedBlockNum").is_some());
    // Without Metrics attached, interval defaults to 0.
    assert_eq!(v["interval"], 0);
}

#[tokio::test]
async fn monitor_getstatsinfo_populates_metrics_when_attached() {
    let metrics = Arc::new(Metrics::new());
    metrics.set_head_block_number(42);
    metrics.set_solidified_block_number(40);
    metrics.inc_blocks_applied();
    metrics.inc_blocks_applied();
    let state = fresh_state().with_metrics(metrics);
    let app = router(state);
    let res = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/monitor/getstatsinfo")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let v = body_to_json(res).await;
    assert!(
        v["interval"].as_i64().unwrap_or(-1) >= 0,
        "interval should be a non-negative seconds count"
    );
    let chain = &v["blockchain"];
    assert_eq!(chain["blocksApplied"], 2);
    // headBlockNum reads from dyn_props (not metrics); dyn_props is
    // empty here so it returns 0. That's fine — Grafana plots both
    // pointers and the metrics counter independently.
}

#[tokio::test]
async fn monitor_getstatsinfo_post_also_works() {
    // java-tron accepts both GET and POST on `/monitor/*`. Confirm
    // POST works so non-GET clients are happy.
    let app = router(fresh_state());
    let res = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/monitor/getstatsinfo")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}
