//! Integration tests for the `/v1/archive/*` historical-state
//! endpoints: coverage validation, at-height account reads through the
//! ordinary presentation path, and the disabled-archive error shape.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use prost::Message as _;
use tower::ServiceExt;
use tron_chainbase::{BlockUndoStore, KvBackend, MemBackend, UndoStoreId};
use tron_index::{ArchiveWriter, DeltaRef};
use tron_rpc::{http_rest::router, ArchiveApiState, RpcState};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn addr(b: u8) -> [u8; 21] {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(b);
    a
}

fn account(balance: i64, who: [u8; 21]) -> Vec<u8> {
    tron_proto::Account { address: who.to_vec(), balance, ..Default::default() }.encode_to_vec()
}

async fn body_to_json(response: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).expect("response body is JSON")
}

/// State with an archive whose account store has history: Alice's
/// balance changes at heights 11 and 12.
fn state_with_archive() -> RpcState {
    let accounts = mem();
    let alice = addr(0xaa);

    // Live (current) state: balance after every block.
    accounts.put(&alice, &account(300, alice)).unwrap();

    // The archive saw blocks 11 and 12 mutate Alice.
    let writer = ArchiveWriter::new(
        mem(),
        Some(BlockUndoStore::new(mem())),
        vec![(UndoStoreId::Accounts, accounts.clone())],
    );
    writer.check_or_init().unwrap();
    let v100 = account(100, alice);
    let v200 = account(200, alice);
    let v300 = account(300, alice);
    writer
        .on_block_applied(
            11,
            Some(&[DeltaRef {
                store: UndoStoreId::Accounts,
                key: &alice,
                before: Some(&v100),
                after: Some(&v200),
            }]),
        )
        .unwrap();
    writer
        .on_block_applied(
            12,
            Some(&[DeltaRef {
                store: UndoStoreId::Accounts,
                key: &alice,
                before: Some(&v200),
                after: Some(&v300),
            }]),
        )
        .unwrap();

    let backends: Vec<(UndoStoreId, Arc<dyn KvBackend>)> =
        vec![(UndoStoreId::Accounts, accounts.clone())];
    RpcState::new(accounts, mem(), mem(), mem(), mem(), 11_111)
        .with_archive(ArchiveApiState::new(writer.reader(), backends))
}

async fn get_account_at(app: axum::Router, block: i64) -> (StatusCode, serde_json::Value) {
    let alice_hex = hex::encode(addr(0xaa));
    let res = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/v1/archive/account?address={alice_hex}&block={block}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    (status, body_to_json(res).await)
}

#[tokio::test]
async fn archive_account_returns_balance_as_of_each_height() {
    for (block, expected) in [(10i64, 100i64), (11, 200), (12, 300)] {
        let (status, v) = get_account_at(router(state_with_archive()), block).await;
        assert_eq!(status, StatusCode::OK, "block {block}: {v}");
        assert_eq!(v["success"], true);
        assert_eq!(v["block"], block);
        assert_eq!(
            v["data"]["balance"], expected,
            "balance as of block {block}: {v}"
        );
    }
}

#[tokio::test]
async fn archive_account_rejects_blocks_outside_coverage() {
    // Coverage is [10, 12]; block 9 and 100 must be refused with a
    // message that explains the coverage window.
    for block in [9i64, 100] {
        let (status, v) = get_account_at(router(state_with_archive()), block).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "block {block}");
        let msg = v["error"].as_str().unwrap_or_default();
        assert!(msg.contains("coverage"), "error should explain coverage: {msg}");
    }
}

#[tokio::test]
async fn archive_endpoints_error_clearly_when_not_enabled() {
    let app = router(RpcState::new(mem(), mem(), mem(), mem(), mem(), 1));
    let alice_hex = hex::encode(addr(0xaa));
    let res = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/v1/archive/account?address={alice_hex}&block=5"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_IMPLEMENTED);
    let v = body_to_json(res).await;
    assert!(v["error"]
        .as_str()
        .unwrap_or_default()
        .contains("capture_state_deltas"));
}

#[tokio::test]
async fn v1_history_endpoints_error_clearly_when_index_not_enabled() {
    // Companion check for the P1 surface on a bare node.
    let app = router(RpcState::new(mem(), mem(), mem(), mem(), mem(), 1));
    let res = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/accounts/TLsV52sRDL79HXGGm9yzwKibb6BeruhUzy/transactions")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_IMPLEMENTED);
}
