//! End-to-end tests for the `eth_subscribe` WebSocket pubsub. Boots
//! an axum server with a `PubSubBroker` attached, connects a
//! tungstenite client over loopback, and exercises every
//! subscription type plus unsubscribe + clean-disconnect paths.

use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;
use tron_chainbase::{KvBackend, MemBackend};
use tron_rpc::pubsub::{HeadEvent, LogEvent, PubSubBroker, SyncEvent};
use tron_rpc::RpcState;

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

/// Spin up the WS server on an ephemeral port. Returns the bound
/// address and a shared `Arc<PubSubBroker>` for the test to publish
/// events through.
async fn spawn_server() -> (std::net::SocketAddr, Arc<PubSubBroker>) {
    let broker = PubSubBroker::new_arc();
    let state = RpcState::new(mem(), mem(), mem(), mem(), mem(), 11_111).with_pubsub(broker.clone());
    let app = tron_rpc::server::router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });
    // Wait a moment for the bind to settle.
    tokio::time::sleep(Duration::from_millis(20)).await;
    (addr, broker)
}

/// Connect a tungstenite client to `/ws` on `addr`.
async fn connect(
    addr: std::net::SocketAddr,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>
{
    let url = format!("ws://{}/ws", addr);
    let (ws, _) = tokio_tungstenite::connect_async(url)
        .await
        .expect("ws connect");
    ws
}

async fn send_json<S>(ws: &mut S, value: Value)
where
    S: futures_util::SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    ws.send(Message::Text(value.to_string())).await.unwrap();
}

/// Receive the next text frame as JSON. Times out after 2s so a
/// stalled subscription fails the test rather than hanging.
async fn recv_json<S>(ws: &mut S) -> Value
where
    S: futures_util::StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
        + Unpin,
{
    let msg = tokio::time::timeout(Duration::from_secs(2), ws.next())
        .await
        .expect("recv timeout")
        .expect("stream closed")
        .expect("ws error");
    match msg {
        Message::Text(text) => serde_json::from_str(&text).expect("invalid json"),
        other => panic!("expected text frame, got {other:?}"),
    }
}

#[tokio::test]
async fn subscribe_to_new_heads_and_receive_published_event() {
    let (addr, broker) = spawn_server().await;
    let mut ws = connect(addr).await;
    send_json(
        &mut ws,
        json!({"jsonrpc":"2.0","id":1,"method":"eth_subscribe","params":["newHeads"]}),
    )
    .await;
    let ack = recv_json(&mut ws).await;
    let sub_id = ack["result"].as_str().expect("sub id").to_string();
    assert!(sub_id.starts_with("0x"));

    // Publish a head event after subscribe to ensure the per-sub
    // task has time to attach. We can wait until receiver_count > 0
    // to make this race-free.
    for _ in 0..50 {
        if broker.heads_receiver_count() > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    broker.publish_head(HeadEvent(json!({"number":"0x42"})));

    let note = recv_json(&mut ws).await;
    assert_eq!(note["method"], "eth_subscription");
    assert_eq!(note["params"]["subscription"], sub_id);
    assert_eq!(note["params"]["result"]["number"], "0x42");
}

#[tokio::test]
async fn subscribe_to_pending_transactions_receives_hex_tx_id() {
    let (addr, broker) = spawn_server().await;
    let mut ws = connect(addr).await;
    send_json(
        &mut ws,
        json!({"jsonrpc":"2.0","id":1,"method":"eth_subscribe","params":["newPendingTransactions"]}),
    )
    .await;
    let _ack = recv_json(&mut ws).await;
    for _ in 0..50 {
        if broker.pending_txs_receiver_count() > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let tx_id = [0xab; 32];
    broker.publish_pending_tx(tx_id);
    let note = recv_json(&mut ws).await;
    let hex_id = note["params"]["result"].as_str().unwrap();
    assert_eq!(hex_id, format!("0x{}", "ab".repeat(32)));
}

#[tokio::test]
async fn subscribe_to_syncing_receives_caughtup_then_progress() {
    let (addr, broker) = spawn_server().await;
    let mut ws = connect(addr).await;
    send_json(
        &mut ws,
        json!({"jsonrpc":"2.0","id":1,"method":"eth_subscribe","params":["syncing"]}),
    )
    .await;
    let _ack = recv_json(&mut ws).await;
    for _ in 0..50 {
        if broker.syncing_receiver_count() > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    broker.publish_syncing(SyncEvent::CaughtUp);
    let note1 = recv_json(&mut ws).await;
    assert_eq!(note1["params"]["result"], false);
    broker.publish_syncing(SyncEvent::Syncing {
        current: 100,
        highest: 200,
    });
    let note2 = recv_json(&mut ws).await;
    let obj = note2["params"]["result"].as_object().unwrap();
    assert_eq!(obj["currentBlock"], "0x64");
    assert_eq!(obj["highestBlock"], "0xc8");
}

#[tokio::test]
async fn subscribe_to_logs_with_filter_only_delivers_matching() {
    let (addr, broker) = spawn_server().await;
    let mut ws = connect(addr).await;
    let watch_addr = format!("0x{}", "ab".repeat(20));
    send_json(
        &mut ws,
        json!({
            "jsonrpc":"2.0","id":1,"method":"eth_subscribe",
            "params":["logs", {"address": watch_addr.clone()}]
        }),
    )
    .await;
    let _ack = recv_json(&mut ws).await;
    for _ in 0..50 {
        if broker.logs_receiver_count() > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // Non-matching address: should NOT deliver.
    broker.publish_log(LogEvent(json!({
        "address": "0xcccccccccccccccccccccccccccccccccccccccc",
        "topics": [],
        "data": "0x",
        "blockNumber": "0x1",
    })));
    // Matching address: should deliver.
    broker.publish_log(LogEvent(json!({
        "address": watch_addr,
        "topics": [],
        "data": "0xbeef",
        "blockNumber": "0x2",
    })));
    let note = recv_json(&mut ws).await;
    assert_eq!(note["params"]["result"]["data"], "0xbeef");
}

#[tokio::test]
async fn eth_unsubscribe_stops_delivery_and_returns_true() {
    let (addr, broker) = spawn_server().await;
    let mut ws = connect(addr).await;
    send_json(
        &mut ws,
        json!({"jsonrpc":"2.0","id":1,"method":"eth_subscribe","params":["newHeads"]}),
    )
    .await;
    let ack = recv_json(&mut ws).await;
    let sub_id = ack["result"].as_str().unwrap().to_string();
    for _ in 0..50 {
        if broker.heads_receiver_count() > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // First publish: delivered.
    broker.publish_head(HeadEvent(json!({"number":"0x1"})));
    let _note1 = recv_json(&mut ws).await;

    // Unsubscribe.
    send_json(
        &mut ws,
        json!({"jsonrpc":"2.0","id":2,"method":"eth_unsubscribe","params":[sub_id.clone()]}),
    )
    .await;
    let ack = recv_json(&mut ws).await;
    assert_eq!(ack["result"], true);

    // Allow the abort to propagate so the broker no longer sees the
    // receiver.
    for _ in 0..50 {
        if broker.heads_receiver_count() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // Subsequent publishes are dropped (no recv on the broker
    // channel for this sub anymore).
    broker.publish_head(HeadEvent(json!({"number":"0x2"})));
    // Try to receive — should time out since the per-sub task is
    // cancelled.
    let race = tokio::time::timeout(Duration::from_millis(100), ws.next()).await;
    assert!(
        race.is_err() || matches!(race, Ok(None)),
        "no further notifications expected after unsubscribe; got {race:?}"
    );
}

#[tokio::test]
async fn eth_unsubscribe_with_unknown_id_returns_false() {
    let (addr, _broker) = spawn_server().await;
    let mut ws = connect(addr).await;
    send_json(
        &mut ws,
        json!({
            "jsonrpc":"2.0","id":1,"method":"eth_unsubscribe",
            "params":[format!("0x{}", "aa".repeat(8))]
        }),
    )
    .await;
    let ack = recv_json(&mut ws).await;
    assert_eq!(ack["result"], false);
}

#[tokio::test]
async fn multiple_subscriptions_on_one_connection_route_correctly() {
    let (addr, broker) = spawn_server().await;
    let mut ws = connect(addr).await;
    send_json(
        &mut ws,
        json!({"jsonrpc":"2.0","id":1,"method":"eth_subscribe","params":["newHeads"]}),
    )
    .await;
    let ack_heads = recv_json(&mut ws).await;
    let sub_heads = ack_heads["result"].as_str().unwrap().to_string();
    send_json(
        &mut ws,
        json!({"jsonrpc":"2.0","id":2,"method":"eth_subscribe","params":["newPendingTransactions"]}),
    )
    .await;
    let ack_tx = recv_json(&mut ws).await;
    let sub_tx = ack_tx["result"].as_str().unwrap().to_string();
    assert_ne!(sub_heads, sub_tx);

    for _ in 0..50 {
        if broker.heads_receiver_count() > 0 && broker.pending_txs_receiver_count() > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    broker.publish_head(HeadEvent(json!({"number":"0x9"})));
    broker.publish_pending_tx([0x11; 32]);

    // Both notifications should arrive, each labelled with its own
    // subscription id. Order isn't guaranteed; sort by which id we
    // see first.
    let mut got_heads = false;
    let mut got_pending = false;
    for _ in 0..2 {
        let note = recv_json(&mut ws).await;
        let sub_id = note["params"]["subscription"].as_str().unwrap();
        if sub_id == sub_heads {
            assert_eq!(note["params"]["result"]["number"], "0x9");
            got_heads = true;
        } else if sub_id == sub_tx {
            assert_eq!(
                note["params"]["result"].as_str().unwrap(),
                format!("0x{}", "11".repeat(32))
            );
            got_pending = true;
        } else {
            panic!("unknown subscription id in notification: {sub_id}");
        }
    }
    assert!(got_heads && got_pending);
}

#[tokio::test]
async fn unknown_subscription_kind_returns_invalid_params_error() {
    let (addr, _) = spawn_server().await;
    let mut ws = connect(addr).await;
    send_json(
        &mut ws,
        json!({"jsonrpc":"2.0","id":1,"method":"eth_subscribe","params":["pony"]}),
    )
    .await;
    let response = recv_json(&mut ws).await;
    assert!(
        response["error"].is_object(),
        "expected error for unknown kind; got {response:?}"
    );
    assert!(
        response["error"]["message"]
            .as_str()
            .unwrap()
            .contains("pony")
    );
}

#[tokio::test]
async fn ws_forwards_non_subscription_methods_through_dispatch() {
    let (addr, _) = spawn_server().await;
    let mut ws = connect(addr).await;
    send_json(
        &mut ws,
        json!({"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}),
    )
    .await;
    let response = recv_json(&mut ws).await;
    // The RpcState was built with chain_id = 11_111 = 0x2b67.
    assert_eq!(response["result"], format!("0x{:x}", 11_111));
}

#[tokio::test]
async fn pubsub_broker_unattached_means_subscribe_returns_error() {
    // Build a state without a pubsub broker; the WS endpoint
    // shouldn't even mount, so client gets connection refused / 404.
    let state = RpcState::new(mem(), mem(), mem(), mem(), mem(), 11_111);
    let app = tron_rpc::server::router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    let url = format!("ws://{}/ws", addr);
    let result = tokio_tungstenite::connect_async(url).await;
    assert!(
        result.is_err(),
        "expected ws connect to fail when pubsub broker missing; got Ok"
    );
}

#[tokio::test]
async fn client_disconnect_cancels_per_sub_tasks() {
    let (addr, broker) = spawn_server().await;
    let mut ws = connect(addr).await;
    send_json(
        &mut ws,
        json!({"jsonrpc":"2.0","id":1,"method":"eth_subscribe","params":["newHeads"]}),
    )
    .await;
    let _ack = recv_json(&mut ws).await;
    for _ in 0..50 {
        if broker.heads_receiver_count() > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(broker.heads_receiver_count(), 1);
    // Drop the client — broker's receiver count should drop.
    drop(ws);
    for _ in 0..100 {
        if broker.heads_receiver_count() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        broker.heads_receiver_count(),
        0,
        "per-sub task should be cancelled on client disconnect"
    );
}
