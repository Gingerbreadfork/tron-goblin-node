//! Smoke test for the daemon. Spawns a node in-process against a
//! tempdir, hits its RPC over loopback, then signals shutdown.

use std::path::PathBuf;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn temp_dir() -> PathBuf {
    let mut p = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    p.push(format!("tron-node-smoke-{nanos}"));
    p
}

async fn http_call(addr: std::net::SocketAddr, body: Value) -> Value {
    let body_str = body.to_string();
    let req = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body_str}",
        body_str.len()
    );
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream.write_all(req.as_bytes()).await.expect("write");
    let mut response = String::new();
    stream.read_to_string(&mut response).await.expect("read");
    let body = response.split("\r\n\r\n").nth(1).unwrap_or("");
    serde_json::from_str(body).expect("non-json response")
}

#[tokio::test]
async fn node_starts_serves_rpc_and_shuts_down_cleanly() {
    let data_dir = temp_dir();
    let mut config = tron_node::NodeConfig::default();
    config.data_dir = data_dir.clone();
    // Bind on :0 by tweaking the host+port via TcpListener pre-binding —
    // we ask the OS for a free port up front and pass it through.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let bound = listener.local_addr().unwrap();
    drop(listener); // give the port back; the daemon will rebind.
    config.rpc.host = "127.0.0.1".into();
    config.rpc.port = bound.port();
    config.p2p.disabled = true; // no peers — RPC-only
    // Disable every other server so two parallel smoke tests don't
    // fight over their default ports.
    config.metrics.disabled = true;
    config.grpc.disabled = true;
    config.http.disabled = true;

    let shutdown = tron_node::ShutdownSignal::new();
    let shutdown_handle = shutdown.clone();

    let run_task = tokio::spawn(async move { tron_node::run(config, shutdown).await });

    // Wait for the RPC server to come up. Poll until we get a valid
    // response, capping at 5 seconds.
    let start = std::time::Instant::now();
    let resp = loop {
        if start.elapsed() > Duration::from_secs(5) {
            shutdown_handle.shutdown();
            let _ = run_task.await;
            std::fs::remove_dir_all(&data_dir).ok();
            panic!("RPC never came up");
        }
        if let Ok(stream) = TcpStream::connect(bound).await {
            drop(stream);
            // Port is open — issue the actual request.
            break http_call(
                bound,
                json!({"jsonrpc":"2.0","method":"eth_chainId","id":1}),
            )
            .await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(resp["result"], "0x2b67");

    // Verify the head block was initialized to 0 (genesis applied).
    let resp = http_call(
        bound,
        json!({"jsonrpc":"2.0","method":"eth_blockNumber","id":2}),
    )
    .await;
    assert_eq!(resp["result"], "0x0");

    shutdown_handle.shutdown();
    let result = tokio::time::timeout(Duration::from_secs(6), run_task)
        .await
        .expect("node didn't shut down in time");
    result.expect("join").expect("run");

    // Tidy up the on-disk state.
    std::fs::remove_dir_all(&data_dir).ok();
}

#[tokio::test]
async fn node_no_rpc_no_sync_still_opens_storage() {
    let data_dir = temp_dir();
    let mut config = tron_node::NodeConfig::default();
    config.data_dir = data_dir.clone();
    config.rpc.disabled = true;
    config.p2p.disabled = true;
    config.metrics.disabled = true;
    config.grpc.disabled = true;
    config.http.disabled = true;

    let shutdown = tron_node::ShutdownSignal::new();
    let shutdown_handle = shutdown.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        shutdown_handle.shutdown();
    });
    tron_node::run(config, shutdown).await.expect("run");
    // Storage tree should exist on disk now.
    assert!(data_dir.join("db").exists());
    std::fs::remove_dir_all(&data_dir).ok();
}
