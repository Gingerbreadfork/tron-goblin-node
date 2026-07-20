//! WebSocket pubsub broker for `eth_subscribe` / `eth_unsubscribe`.
//!
//! Mirrors geth's subscription surface so EVM tooling (ethers,
//! wagmi, Hardhat scripts) can pull realtime events from a TRON node
//! without polling. The four subscription kinds geth ships:
//!
//! * `newHeads` — every applied block's header. We emit a flat JSON
//!   object (eth-shape) with `number`, `hash`, `parentHash`,
//!   `timestamp`, plus the TRON-natural `witnessAddress`.
//! * `logs` — VM log emissions filtered by `LogFilter`. Same shape
//!   `eth_getLogs` returns: object with `address`, `topics`,
//!   `data`, `blockNumber`, `transactionHash`, `logIndex`.
//! * `newPendingTransactions` — every tx_id accepted into the
//!   mempool. We hex-encode the 32-byte tx_id; clients call
//!   `eth_getTransactionByHash` to inflate.
//! * `syncing` — pushed manually by the sync layer when its idea of
//!   `latest_block - head_block > 0` transitions in either direction.
//!   Geth emits `false` when caught up and an object when not; we
//!   match that.
//!
//! Lifecycle: the `PubSubBroker` is constructed once at runtime
//! startup, shared via `Arc`, and plugged into:
//!   1. The `EventBus` as an `EventListener` so per-block / per-log
//!      triggers fan in.
//!   2. The `TxMempool` channel (subscribed at WS-handler creation
//!      time).
//!   3. The `RpcState` so WS handlers can reach it.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use serde_json::{json, Value};
use tokio::sync::broadcast;

use crate::filters::LogFilter;

/// Capacity of each broadcast channel. When a slow subscriber falls
/// behind by more than this many events, the oldest are dropped from
/// the channel — the subscriber sees a `RecvError::Lagged(n)` and
/// can decide whether to keep going or reconnect. 1024 buffers ~1
/// minute of mainnet activity at peak (~17 tx/s).
const BROADCAST_CAPACITY: usize = 1024;

/// One log emission ready for client fan-out. Built from the
/// executor's per-block `VmLog` + block context. Kept as a flat JSON
/// object so the WS handler can `serde_json::to_string` without
/// re-encoding.
#[derive(Debug, Clone)]
pub struct LogEvent(pub Value);

/// One new-head emission. Same shape `eth_getBlockByNumber` returns,
/// but without the `transactions` array (clients call
/// `eth_getBlockByHash` to inflate).
#[derive(Debug, Clone)]
pub struct HeadEvent(pub Value);

/// Sync status flip. `false` = caught up; `Some(obj)` = currently
/// syncing. The object's shape matches `eth_syncing`'s populated
/// response: `{startingBlock, currentBlock, highestBlock}`.
#[derive(Debug, Clone)]
pub enum SyncEvent {
    CaughtUp,
    Syncing { current: i64, highest: i64 },
}

/// Multi-channel broadcaster the WS handler subscribes to. Cheap to
/// clone — channels are `Arc`-backed internally.
#[derive(Clone)]
pub struct PubSubBroker {
    heads: broadcast::Sender<HeadEvent>,
    logs: broadcast::Sender<LogEvent>,
    pending_txs: broadcast::Sender<[u8; 32]>,
    syncing: broadcast::Sender<SyncEvent>,
}

impl PubSubBroker {
    pub fn new() -> Self {
        let (heads, _) = broadcast::channel(BROADCAST_CAPACITY);
        let (logs, _) = broadcast::channel(BROADCAST_CAPACITY);
        let (pending_txs, _) = broadcast::channel(BROADCAST_CAPACITY);
        let (syncing, _) = broadcast::channel(16);
        Self {
            heads,
            logs,
            pending_txs,
            syncing,
        }
    }

    pub fn new_arc() -> Arc<Self> {
        Arc::new(Self::new())
    }

    /// Fan a freshly-applied block header out to `newHeads`
    /// subscribers. Caller composes the JSON in eth shape — see
    /// `head_event_from_block` below.
    pub fn publish_head(&self, event: HeadEvent) {
        // send() errors with NoReceivers when nothing is listening
        // — that's expected when no WS clients are connected.
        let _ = self.heads.send(event);
    }

    pub fn publish_log(&self, event: LogEvent) {
        let _ = self.logs.send(event);
    }

    pub fn publish_pending_tx(&self, tx_id: [u8; 32]) {
        let _ = self.pending_txs.send(tx_id);
    }

    pub fn publish_syncing(&self, event: SyncEvent) {
        let _ = self.syncing.send(event);
    }

    pub fn subscribe_heads(&self) -> broadcast::Receiver<HeadEvent> {
        self.heads.subscribe()
    }
    pub fn subscribe_logs(&self) -> broadcast::Receiver<LogEvent> {
        self.logs.subscribe()
    }
    pub fn subscribe_pending_txs(&self) -> broadcast::Receiver<[u8; 32]> {
        self.pending_txs.subscribe()
    }
    pub fn subscribe_syncing(&self) -> broadcast::Receiver<SyncEvent> {
        self.syncing.subscribe()
    }

    pub fn heads_receiver_count(&self) -> usize {
        self.heads.receiver_count()
    }
    pub fn logs_receiver_count(&self) -> usize {
        self.logs.receiver_count()
    }
    pub fn pending_txs_receiver_count(&self) -> usize {
        self.pending_txs.receiver_count()
    }
    pub fn syncing_receiver_count(&self) -> usize {
        self.syncing.receiver_count()
    }
}

impl Default for PubSubBroker {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a `newHeads`-shaped JSON object from a block. eth tooling
/// expects: `number`, `hash`, `parentHash`, `timestamp`,
/// `transactionsRoot`, `miner` (or `witnessAddress` in our case).
pub fn head_event_from_block(block: &tron_proto::Block, block_id: &[u8; 32]) -> HeadEvent {
    let header = block.block_header.as_ref();
    let raw = header.and_then(|h| h.raw_data.as_ref());
    let number = raw.map(|r| r.number).unwrap_or(0);
    let parent_hash = raw.map(|r| hex::encode(&r.parent_hash)).unwrap_or_default();
    let timestamp = raw.map(|r| r.timestamp).unwrap_or(0);
    let tx_trie_root = raw.map(|r| hex::encode(&r.tx_trie_root)).unwrap_or_default();
    let witness = raw.map(|r| hex::encode(&r.witness_address)).unwrap_or_default();
    HeadEvent(json!({
        "number": format!("0x{:x}", number),
        "hash": format!("0x{}", hex::encode(block_id)),
        "parentHash": format!("0x{parent_hash}"),
        "timestamp": format!("0x{:x}", timestamp / 1000), // seconds, eth convention
        "transactionsRoot": format!("0x{tx_trie_root}"),
        "miner": format!("0x{witness}"),
    }))
}

/// Build a `logs`-shaped JSON object from a `VmLog` + block + tx
/// context. Same shape `eth_getLogs` produces; the WS handler can
/// filter via [`LogFilter`] before sending.
pub fn log_event_from_vm_log(
    log: &tron_tvm::execute::VmLog,
    block_number: i64,
    block_hash: &[u8; 32],
    tx_id: &[u8; 32],
    log_index: usize,
) -> LogEvent {
    let topics: Vec<String> = log
        .topics
        .iter()
        .map(|t| format!("0x{}", hex::encode(t)))
        .collect();
    LogEvent(json!({
        "address": format!("0x{}", hex::encode(log.address)),
        "topics": topics,
        "data": format!("0x{}", hex::encode(&log.data)),
        "blockNumber": format!("0x{:x}", block_number),
        "blockHash": format!("0x{}", hex::encode(block_hash)),
        "transactionHash": format!("0x{}", hex::encode(tx_id)),
        "logIndex": format!("0x{:x}", log_index),
        "removed": false,
    }))
}

/// Does `filter` match the log? Mirrors the matching logic in
/// `methods::eth_get_logs`: address must be in the filter's address
/// list (or list empty), and every topic position must match (with
/// `[]` at a position meaning "any").
pub fn log_matches_filter(log: &Value, filter: &LogFilter) -> bool {
    let addr_str = log["address"].as_str().unwrap_or("");
    if !filter.addresses.is_empty() {
        let log_addr_bytes = match hex::decode(addr_str.trim_start_matches("0x")) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let any_match = filter
            .addresses
            .iter()
            .any(|f| f == &log_addr_bytes);
        if !any_match {
            return false;
        }
    }
    // Topics: each position is an OR set; log topics beyond the filter's
    // length are unrestricted.
    //
    // java `LogFilter.matchesExactly` tests `i >= logTopics.size()` BEFORE it
    // looks at the position's OR set, so a filter position the log has no topic
    // for fails the match even when that position is a wildcard: `[sig, null]`
    // requires the log to carry at least two topics. Skipping the bound check
    // for wildcards would let a one-topic log through a two-position filter.
    let log_topics = log["topics"].as_array().cloned().unwrap_or_default();
    for (i, position) in filter.topics.iter().enumerate() {
        if i >= log_topics.len() {
            return false;
        }
        if position.is_empty() {
            continue;
        }
        let Some(t) = log_topics.get(i).and_then(|v| v.as_str()) else {
            return false;
        };
        let t_bytes = match hex::decode(t.trim_start_matches("0x")) {
            Ok(b) => b,
            Err(_) => return false,
        };
        if !position.iter().any(|p| p == &t_bytes) {
            return false;
        }
    }
    true
}

// =============================================================================
// WebSocket handler
// =============================================================================

/// Per-connection subscription registry. Each `eth_subscribe`
/// allocates a `SubId`; the handler spawns one background task per
/// active subscription which receives broadcast events and writes
/// JSON-RPC notifications to the WS sink. `eth_unsubscribe` cancels
/// the matching task.
type SubId = [u8; 8];

/// Render a SubId as the `0x<hex>` string clients see.
fn fmt_sub_id(id: SubId) -> String {
    format!("0x{}", hex::encode(id))
}

/// Parse a `0x...` SubId back from a client. Returns `None` on bad
/// length / encoding so the handler can return an "invalid params"
/// error to the client.
fn parse_sub_id(s: &str) -> Option<SubId> {
    let trimmed = s.trim_start_matches("0x");
    let bytes = hex::decode(trimmed).ok()?;
    if bytes.len() != 8 {
        return None;
    }
    let mut id = [0u8; 8];
    id.copy_from_slice(&bytes);
    Some(id)
}

/// Generate a fresh SubId. 8 random bytes is enough that collisions
/// inside a single connection are negligible (`2^-32` per allocation
/// against a registry of up to `2^32` active subs).
fn random_sub_id() -> SubId {
    use getrandom::getrandom;
    let mut id = [0u8; 8];
    let _ = getrandom(&mut id);
    id
}

/// Standalone router for tests / dev setups that want the WS
/// endpoint without the rest of the JSON-RPC surface. Production
/// wiring shares the same router via `server::router` which mounts
/// `/ws` automatically when `RpcState::pubsub` is set.
pub fn ws_router(state: crate::RpcState) -> axum::Router {
    axum::Router::new()
        .route("/ws", axum::routing::get(ws_upgrade_handler))
        .with_state(state)
}

/// Public axum handler for the WS upgrade. Called by the main
/// router in `server.rs` when pubsub is attached.
pub async fn ws_upgrade_handler(
    State(state): State<crate::RpcState>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

/// One outbound notification waiting to be flushed to the client.
/// The per-sub task pushes; the main task pulls and writes — keeps
/// all socket writes on a single thread of control.
#[derive(Debug, Clone)]
struct Notification(String);

/// Per-connection bound on queued-but-unsent notifications. Caps memory
/// when a slow or stalled WS client can't keep up: once this many
/// notifications are buffered, the fan-out tasks backpressure (and the
/// upstream broadcast ring drops its oldest) instead of the channel
/// growing without limit (C3). At ~1 KiB/notification that's ≤ ~1 MiB
/// per stuck connection rather than unbounded → OOM.
const NOTIFY_BUFFER: usize = 1024;

/// Run a single WS connection until the client disconnects or sends
/// a close frame. Owns:
///   * The split WS sender/receiver.
///   * A bounded `mpsc::Sender` shared with every sub-task so they
///     can fan notifications back to the writer half (backpressured,
///     so a slow client can't make the queue grow without bound).
///   * A per-sub `tokio::task::JoinHandle` map for clean cancel on
///     `eth_unsubscribe` / connection close.
async fn handle_ws(socket: WebSocket, state: crate::RpcState) {
    use futures_util::{SinkExt, StreamExt};
    let (mut tx, mut rx) = socket.split();
    let (note_tx, mut note_rx) = tokio::sync::mpsc::channel::<Notification>(NOTIFY_BUFFER);

    // Per-sub cancellation handles.
    let mut subs: HashMap<SubId, tokio::task::JoinHandle<()>> = HashMap::new();

    loop {
        tokio::select! {
            // Outbound: drain queued notifications.
            Some(Notification(payload)) = note_rx.recv() => {
                if tx.send(Message::Text(payload)).await.is_err() {
                    break;
                }
            }
            // Inbound: dispatch JSON-RPC frames from the client.
            msg = rx.next() => {
                let Some(Ok(msg)) = msg else { break };
                match msg {
                    Message::Text(text) => {
                        let response = dispatch_ws_request(
                            &text,
                            &state,
                            &mut subs,
                            &note_tx,
                        );
                        if tx.send(Message::Text(response)).await.is_err() {
                            break;
                        }
                    }
                    Message::Close(_) => break,
                    Message::Ping(p) => {
                        let _ = tx.send(Message::Pong(p)).await;
                    }
                    _ => {}
                }
            }
        }
    }

    // Clean shutdown: cancel every per-sub task.
    for (_, handle) in subs {
        handle.abort();
    }
}

/// Handle one inbound JSON-RPC request on a WS connection. Returns
/// the JSON string to send back to the client.
fn dispatch_ws_request(
    text: &str,
    state: &crate::RpcState,
    subs: &mut HashMap<SubId, tokio::task::JoinHandle<()>>,
    note_tx: &tokio::sync::mpsc::Sender<Notification>,
) -> String {
    let Ok(req): Result<Value, _> = serde_json::from_str(text) else {
        return json!({
            "jsonrpc": "2.0",
            "id": null,
            "error": {"code": -32700, "message": "parse error"},
        })
        .to_string();
    };
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let params = req.get("params").cloned().unwrap_or(Value::Array(Vec::new()));

    match method {
        "eth_subscribe" => match handle_subscribe(state, &params, subs, note_tx) {
            Ok(sub_id) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": fmt_sub_id(sub_id),
            })
            .to_string(),
            Err(err) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": err.to_error_object(),
            })
            .to_string(),
        },
        "eth_unsubscribe" => {
            let arr = params.as_array().cloned().unwrap_or_default();
            let Some(sub_id_str) = arr.first().and_then(|v| v.as_str()) else {
                return json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {"code": -32602, "message": "missing subscription id"},
                })
                .to_string();
            };
            let Some(sub_id) = parse_sub_id(sub_id_str) else {
                return json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {"code": -32602, "message": "invalid subscription id"},
                })
                .to_string();
            };
            let cancelled = subs.remove(&sub_id).map(|h| {
                h.abort();
                true
            });
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": cancelled.unwrap_or(false),
            })
            .to_string()
        }
        // Any other method over WS: delegate to the same HTTP
        // dispatch table so clients can use one connection for both
        // requests and subscriptions (matches geth's WS surface).
        other => {
            let result = crate::server::ws_dispatch(other, &params, state);
            match result {
                Ok(value) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": value,
                })
                .to_string(),
                Err(err) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": err.to_error_object(),
                })
                .to_string(),
            }
        }
    }
}

fn handle_subscribe(
    state: &crate::RpcState,
    params: &Value,
    subs: &mut HashMap<SubId, tokio::task::JoinHandle<()>>,
    note_tx: &tokio::sync::mpsc::Sender<Notification>,
) -> Result<SubId, crate::methods::RpcError> {
    let Some(broker) = state.pubsub.clone() else {
        return Err(crate::methods::RpcError::method_not_found(
            "eth_subscribe (no pubsub broker attached)",
        ));
    };
    let arr = params
        .as_array()
        .ok_or_else(|| crate::methods::RpcError::invalid_params("params must be an array"))?;
    let kind = arr
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| crate::methods::RpcError::invalid_params("missing subscription kind"))?;
    // Allocate a fresh SubId; rejection-free (collision-free at
    // realistic per-connection sub counts).
    let sub_id = random_sub_id();
    let note_tx = note_tx.clone();
    let handle = match kind {
        "newHeads" => spawn_heads_sub(sub_id, broker.subscribe_heads(), note_tx),
        "newPendingTransactions" => {
            spawn_pending_tx_sub(sub_id, broker.subscribe_pending_txs(), note_tx)
        }
        "syncing" => spawn_syncing_sub(sub_id, broker.subscribe_syncing(), note_tx),
        "logs" => {
            // Second arg is the optional log filter object. When
            // absent or `{}`, match everything.
            let filter = parse_log_filter_arg(arr.get(1));
            spawn_logs_sub(sub_id, broker.subscribe_logs(), filter, note_tx)
        }
        other => {
            return Err(crate::methods::RpcError::invalid_params(format!(
                "unknown subscription kind {other}"
            )));
        }
    };
    subs.insert(sub_id, handle);
    Ok(sub_id)
}

fn parse_log_filter_arg(v: Option<&Value>) -> LogFilter {
    let Some(Value::Object(obj)) = v else {
        return LogFilter {
            from_block: 0,
            to_block: i64::MAX,
            addresses: Vec::new(),
            topics: Vec::new(),
        };
    };
    let addresses: Vec<Vec<u8>> = match obj.get("address") {
        Some(Value::String(s)) => hex::decode(s.trim_start_matches("0x"))
            .ok()
            .map(|b| vec![b])
            .unwrap_or_default(),
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|x| x.as_str())
            .filter_map(|x| hex::decode(x.trim_start_matches("0x")).ok())
            .collect(),
        _ => Vec::new(),
    };
    let topics: Vec<Vec<Vec<u8>>> = obj
        .get("topics")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|pos| match pos {
                    Value::String(s) => hex::decode(s.trim_start_matches("0x"))
                        .ok()
                        .map(|b| vec![b])
                        .unwrap_or_default(),
                    Value::Array(alts) => alts
                        .iter()
                        .filter_map(|x| x.as_str())
                        .filter_map(|x| hex::decode(x.trim_start_matches("0x")).ok())
                        .collect(),
                    _ => Vec::new(),
                })
                .collect()
        })
        .unwrap_or_default();
    LogFilter {
        from_block: 0,
        to_block: i64::MAX,
        addresses,
        topics,
    }
}

fn spawn_heads_sub(
    sub_id: SubId,
    mut rx: broadcast::Receiver<HeadEvent>,
    note_tx: tokio::sync::mpsc::Sender<Notification>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(HeadEvent(value)) => {
                    let payload = notification_envelope(sub_id, value);
                    if note_tx.send(Notification(payload)).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    })
}

fn spawn_pending_tx_sub(
    sub_id: SubId,
    mut rx: broadcast::Receiver<[u8; 32]>,
    note_tx: tokio::sync::mpsc::Sender<Notification>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(tx_id) => {
                    let payload = notification_envelope(
                        sub_id,
                        Value::String(format!("0x{}", hex::encode(tx_id))),
                    );
                    if note_tx.send(Notification(payload)).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    })
}

fn spawn_syncing_sub(
    sub_id: SubId,
    mut rx: broadcast::Receiver<SyncEvent>,
    note_tx: tokio::sync::mpsc::Sender<Notification>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(SyncEvent::CaughtUp) => {
                    let payload = notification_envelope(sub_id, Value::Bool(false));
                    if note_tx.send(Notification(payload)).await.is_err() {
                        break;
                    }
                }
                Ok(SyncEvent::Syncing { current, highest }) => {
                    let payload = notification_envelope(
                        sub_id,
                        json!({
                            "startingBlock": "0x0",
                            "currentBlock": format!("0x{:x}", current),
                            "highestBlock": format!("0x{:x}", highest),
                        }),
                    );
                    if note_tx.send(Notification(payload)).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    })
}

fn spawn_logs_sub(
    sub_id: SubId,
    mut rx: broadcast::Receiver<LogEvent>,
    filter: LogFilter,
    note_tx: tokio::sync::mpsc::Sender<Notification>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(LogEvent(value)) => {
                    if !log_matches_filter(&value, &filter) {
                        continue;
                    }
                    let payload = notification_envelope(sub_id, value);
                    if note_tx.send(Notification(payload)).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    })
}

/// Wrap a `result` value in the JSON-RPC `eth_subscription`
/// notification envelope geth-style clients expect.
fn notification_envelope(sub_id: SubId, result: Value) -> String {
    json!({
        "jsonrpc": "2.0",
        "method": "eth_subscription",
        "params": {
            "subscription": fmt_sub_id(sub_id),
            "result": result,
        },
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_with_no_subscribers_is_a_noop() {
        let broker = PubSubBroker::new();
        broker.publish_head(HeadEvent(json!({"x": 1})));
        broker.publish_log(LogEvent(json!({"y": 2})));
        broker.publish_pending_tx([0u8; 32]);
        broker.publish_syncing(SyncEvent::CaughtUp);
        // Just verifying no panic.
        assert_eq!(broker.heads_receiver_count(), 0);
    }

    #[tokio::test]
    async fn subscribe_then_publish_delivers_to_each_subscriber() {
        let broker = PubSubBroker::new();
        let mut rx1 = broker.subscribe_heads();
        let mut rx2 = broker.subscribe_heads();
        broker.publish_head(HeadEvent(json!({"number": "0x1"})));
        let e1 = rx1.recv().await.unwrap();
        let e2 = rx2.recv().await.unwrap();
        assert_eq!(e1.0["number"], "0x1");
        assert_eq!(e2.0["number"], "0x1");
    }

    #[test]
    fn head_event_from_block_renders_eth_shape() {
        use tron_proto::block_header::Raw as BlockHeaderRaw;
        use tron_proto::{Block, BlockHeader};
        let block = Block {
            transactions: Vec::new(),
            block_header: Some(BlockHeader {
                raw_data: Some(BlockHeaderRaw {
                    number: 42,
                    parent_hash: vec![1u8; 32],
                    timestamp: 1_700_000_000_000,
                    tx_trie_root: vec![2u8; 32],
                    witness_address: vec![0x41; 21],
                    ..Default::default()
                }),
                witness_signature: Vec::new(),
            }),
        };
        let HeadEvent(value) = head_event_from_block(&block, &[0xff; 32]);
        assert_eq!(value["number"], "0x2a");
        assert_eq!(
            value["hash"],
            format!("0x{}", "ff".repeat(32)),
            "block hash hex"
        );
        assert_eq!(value["parentHash"], format!("0x{}", "01".repeat(32)));
        // Timestamp converted to seconds.
        assert_eq!(value["timestamp"], format!("0x{:x}", 1_700_000_000_000u64 / 1000));
    }

    #[test]
    fn log_event_from_vm_log_renders_eth_shape() {
        let log = tron_tvm::execute::VmLog {
            address: [0xab; 20],
            topics: vec![[0x11; 32], [0x22; 32]],
            data: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let LogEvent(value) =
            log_event_from_vm_log(&log, 100, &[0xcc; 32], &[0xdd; 32], 7);
        assert_eq!(value["address"], format!("0x{}", "ab".repeat(20)));
        assert_eq!(value["data"], format!("0x{}", "deadbeef"));
        assert_eq!(value["blockNumber"], "0x64");
        assert_eq!(value["logIndex"], "0x7");
        assert_eq!(value["removed"], false);
        let topics = value["topics"].as_array().unwrap();
        assert_eq!(topics.len(), 2);
    }

    #[test]
    fn log_filter_matches_by_address() {
        let log_val = json!({
            "address": "0xabababababababababababababababababababab",
            "topics": [],
        });
        let filter_match = LogFilter {
            from_block: 0,
            to_block: i64::MAX,
            addresses: vec![hex::decode("ab".repeat(20)).unwrap()],
            topics: Vec::new(),
        };
        let filter_no_match = LogFilter {
            from_block: 0,
            to_block: i64::MAX,
            addresses: vec![hex::decode("cc".repeat(20)).unwrap()],
            topics: Vec::new(),
        };
        assert!(log_matches_filter(&log_val, &filter_match));
        assert!(!log_matches_filter(&log_val, &filter_no_match));
    }

    #[test]
    fn log_filter_topic_position_with_or_set() {
        let log_val = json!({
            "address": "0x00",
            "topics": ["0x11", "0x22"],
        });
        let filter = LogFilter {
            from_block: 0,
            to_block: i64::MAX,
            addresses: Vec::new(),
            topics: vec![
                vec![hex::decode("11").unwrap(), hex::decode("99").unwrap()],
                vec![], // any
            ],
        };
        assert!(log_matches_filter(&log_val, &filter));
    }

    #[test]
    fn log_filter_topic_mismatch_rejects() {
        let log_val = json!({
            "address": "0x00",
            "topics": ["0x11"],
        });
        let filter = LogFilter {
            from_block: 0,
            to_block: i64::MAX,
            addresses: Vec::new(),
            topics: vec![vec![hex::decode("22").unwrap()]],
        };
        assert!(!log_matches_filter(&log_val, &filter));
    }
}
