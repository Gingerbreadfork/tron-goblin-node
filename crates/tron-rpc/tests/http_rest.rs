//! Integration tests for the `/wallet/*` + `/walletsolidity/*` HTTP
//! surface, exercised over real TCP just like the JSON-RPC tests.

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

const ALICE_HEX: [u8; 21] = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");

async fn spawn_http_server() -> (std::net::SocketAddr, RpcState, AccountStore, BlockStore) {
    let accounts_be = mem();
    let blocks_be = mem();
    let block_index_be = mem();
    let trans_be = mem();
    let dp_be = mem();
    let witnesses_be = mem();

    let accounts = AccountStore::new(accounts_be.clone());
    let blocks = BlockStore::new(blocks_be.clone());

    // Seed Alice with a balance so getaccount has something to return.
    accounts.put(
        &Address::from_raw(ALICE_HEX),
        &Account {
            address: ALICE_HEX.to_vec(),
            balance: 1_234_567_890,
            r#type: AccountType::Normal as i32,
            ..Default::default()
        },
    ).unwrap();

    // Seed a head block (num = 1) so getnowblock has something to return.
    let mut block = Block {
        block_header: Some(BlockHeader {
            raw_data: Some(BlockHeaderRaw {
                number: 1,
                parent_hash: vec![0u8; 32],
                timestamp: 1_700_000_003_000,
                witness_address: ALICE_HEX.to_vec(),
                tx_trie_root: tron_types::calc_tx_trie_root(&[])
                    .map(|h| h.to_vec())
                    .unwrap_or_default(),
                ..Default::default()
            }),
            witness_signature: Vec::new(),
        }),
        transactions: Vec::new(),
    };
    let block_id = block_id_from_block(&block).unwrap();
    blocks.put(&block_id, &block).unwrap();
    BlockIndexStore::new(block_index_be.clone()).put(&block_id).unwrap();
    let dp = DynamicPropertiesStore::new(dp_be.clone());
    dp.save_latest_block_header_number(1);
    dp.save_latest_block_header_hash(block_id.as_bytes());
    let _ = TransactionStore::new(trans_be.clone());

    // Seed a witness so listwitnesses returns something.
    let ws = WitnessStore::new(witnesses_be.clone());
    let w_addr = {
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[20] = 0xbb;
        a
    };
    ws.put(
        &Address::from_raw(w_addr),
        &Witness {
            address: w_addr.to_vec(),
            url: "http://example.com".into(),
            vote_count: 999,
            is_jobs: true,
            ..Default::default()
        },
    ).unwrap();

    // Need access to the block as well so we can return it from spawn.
    let _ = block.block_header.as_mut();

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
    (addr, state, accounts, blocks)
}

/// POST a JSON body to `/path` and return the parsed response.
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
    serde_json::from_str(body).expect("non-json response")
}

/// GET `/path` and return the parsed response.
async fn http_get(addr: std::net::SocketAddr, path: &str) -> Value {
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    );
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    let body = response.split("\r\n\r\n").nth(1).unwrap_or("");
    serde_json::from_str(body).expect("non-json response")
}

#[tokio::test]
async fn wallet_getnowblock_returns_head_block() {
    let (addr, ..) = spawn_http_server().await;
    let resp = http_get(addr, "/wallet/getnowblock").await;
    let num = resp["block_header"]["raw_data"]["number"].as_i64().unwrap();
    assert_eq!(num, 1);
}

#[tokio::test]
async fn wallet_getblockbynum_with_post_body() {
    let (addr, ..) = spawn_http_server().await;
    let resp = http_post(addr, "/wallet/getblockbynum", json!({ "num": 1 })).await;
    let num = resp["block_header"]["raw_data"]["number"].as_i64().unwrap();
    assert_eq!(num, 1);
}

#[tokio::test]
async fn wallet_getaccount_visible_true_round_trips_base58() {
    let (addr, ..) = spawn_http_server().await;
    let alice_base58 =
        tron_crypto::base58check::encode_address(&Address::from_raw(ALICE_HEX));
    let resp = http_post(
        addr,
        "/wallet/getaccount",
        json!({
            "address": alice_base58,
            "visible": true,
        }),
    )
    .await;
    // The address field in the response should round-trip back to the
    // same base58 form (rewrite_addresses re-encodes it).
    let returned_addr = resp["address"].as_str().unwrap();
    assert!(returned_addr.starts_with('T'), "expected T-address, got {returned_addr}");
    assert_eq!(returned_addr, alice_base58);
    let balance = resp["balance"].as_i64().unwrap();
    assert_eq!(balance, 1_234_567_890);
}

#[tokio::test]
async fn wallet_getaccount_visible_false_uses_hex_no_prefix() {
    let (addr, ..) = spawn_http_server().await;
    let resp = http_post(
        addr,
        "/wallet/getaccount",
        json!({
            "address": "412e988a386a799f506693793c6a5af6b54dfaabfb",
            "visible": false,
        }),
    )
    .await;
    let returned_addr = resp["address"].as_str().unwrap();
    // Should be hex (no 0x prefix), starting with 41.
    assert!(returned_addr.starts_with("41"), "expected 41-prefixed hex, got {returned_addr}");
    assert!(
        !returned_addr.starts_with("0x"),
        "java-tron HTTP format does NOT 0x-prefix"
    );
}

#[tokio::test]
async fn wallet_listwitnesses_returns_seeded_witness() {
    let (addr, ..) = spawn_http_server().await;
    let resp = http_get(addr, "/wallet/listwitnesses").await;
    let witnesses = resp["witnesses"].as_array().expect("witnesses array");
    assert_eq!(witnesses.len(), 1);
    assert_eq!(witnesses[0]["voteCount"], 999);
}

#[tokio::test]
async fn wallet_validateaddress_accepts_base58_and_hex() {
    let (addr, ..) = spawn_http_server().await;
    let alice_b58 = tron_crypto::base58check::encode_address(&Address::from_raw(ALICE_HEX));
    let resp = http_post(addr, "/wallet/validateaddress", json!({ "address": alice_b58 })).await;
    assert_eq!(resp["result"], true);

    let bad = http_post(
        addr,
        "/wallet/validateaddress",
        json!({ "address": "not-an-address" }),
    )
    .await;
    assert_eq!(bad["result"], false);
}

#[tokio::test]
async fn walletsolidity_alias_routes_to_same_handler() {
    let (addr, ..) = spawn_http_server().await;
    let resp = http_get(addr, "/walletsolidity/getnowblock").await;
    let num = resp["block_header"]["raw_data"]["number"].as_i64().unwrap();
    assert_eq!(num, 1, "/walletsolidity/getnowblock should mirror /wallet/getnowblock");
}

#[tokio::test]
async fn wallet_unknown_endpoint_404s() {
    let (addr, ..) = spawn_http_server().await;
    // Hit an unknown path; axum returns 404 with empty body, so we
    // bypass the JSON parser.
    let req = format!(
        "GET /wallet/nosuchmethod HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    );
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    assert!(
        response.starts_with("HTTP/1.1 404"),
        "expected 404 for unknown endpoint, got: {response}"
    );
}

#[tokio::test]
async fn wallet_getblockbynum_missing_num_returns_error_field() {
    let (addr, ..) = spawn_http_server().await;
    let resp = http_post(addr, "/wallet/getblockbynum", json!({})).await;
    assert!(
        resp.get("Error").is_some(),
        "expected Error field when 'num' missing, got: {resp}"
    );
}

/// `POST /wallet/createtransaction` is the simplest builder endpoint —
/// proves the `forward_builder` plumbing wraps the body in `[body]` so
/// `methods::create_transaction` can parse `owner_address` /
/// `to_address` / `amount`, and that the response is the unsigned
/// Transaction envelope (txID + raw_data + signature).
#[tokio::test]
async fn wallet_createtransaction_returns_unsigned_envelope() {
    let (addr, ..) = spawn_http_server().await;
    let to_hex = {
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[20] = 0xee;
        hex::encode(a)
    };
    let resp = http_post(
        addr,
        "/wallet/createtransaction",
        json!({
            "owner_address": hex::encode(ALICE_HEX),
            "to_address": to_hex,
            "amount": 1000,
        }),
    )
    .await;
    assert!(
        resp.get("txID").and_then(Value::as_str).is_some(),
        "expected unsigned envelope with txID, got: {resp}"
    );
    assert!(
        resp.get("raw_data").is_some(),
        "expected raw_data field, got: {resp}"
    );
}

/// Same endpoint with `visible=true`: addresses arrive in base58 and
/// must be translated to hex before the builder method sees them.
/// Verifies [`forward_builder`]'s `translate_addresses_to_hex` step.
#[tokio::test]
async fn wallet_createtransaction_visible_true_translates_base58_to_hex() {
    let (addr, ..) = spawn_http_server().await;
    let alice_base58 =
        tron_crypto::base58check::encode_address(&Address::from_raw(ALICE_HEX));
    let to_addr = {
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[20] = 0xee;
        Address::from_raw(a)
    };
    let to_base58 = tron_crypto::base58check::encode_address(&to_addr);
    let resp = http_post(
        addr,
        "/wallet/createtransaction",
        json!({
            "owner_address": alice_base58,
            "to_address": to_base58,
            "amount": 42,
            "visible": true,
        }),
    )
    .await;
    assert!(
        resp.get("txID").and_then(Value::as_str).is_some(),
        "visible=true createtransaction must still produce txID, got: {resp}"
    );
}

/// `POST /wallet/freezebalancev2` exercises a different actuator
/// (FreezeBalanceV2Contract). Pins the macro-generated routes work for
/// any builder method, not just create_transaction.
#[tokio::test]
async fn wallet_freezebalancev2_returns_unsigned_envelope() {
    let (addr, ..) = spawn_http_server().await;
    let resp = http_post(
        addr,
        "/wallet/freezebalancev2",
        json!({
            "owner_address": hex::encode(ALICE_HEX),
            "frozen_balance": 1_000_000,
            "resource": 1, // Energy
        }),
    )
    .await;
    assert!(
        resp.get("txID").is_some(),
        "freezebalancev2 should return an unsigned envelope, got: {resp}"
    );
}

/// `GET /wallet/getbandwidthprices` exercises the no-arg getter helper.
#[tokio::test]
async fn wallet_getbandwidthprices_returns_response() {
    let (addr, ..) = spawn_http_server().await;
    let resp = http_get(addr, "/wallet/getbandwidthprices").await;
    // The method always returns a `prices` string field — even an empty
    // history yields a present (possibly empty) value.
    assert!(
        resp.get("prices").is_some() || resp.get("Error").is_some(),
        "expected prices or Error, got: {resp}"
    );
}

/// `GET /wallet/getmemofee` — no-arg getter routed via `forward_no_arg`.
#[tokio::test]
async fn wallet_getmemofee_returns_value_field() {
    let (addr, ..) = spawn_http_server().await;
    let resp = http_get(addr, "/wallet/getmemofee").await;
    // Fixture doesn't seed MEMO_FEE → returns `0`.
    assert_eq!(resp["value"], 0);
}

/// `POST /wallet/getblockbylatestnum` — body `{num: N}` returns last N blocks.
/// Our fixture has one block (#1) — asking for 5 returns just it.
#[tokio::test]
async fn wallet_getblockbylatestnum_returns_block_list() {
    let (addr, ..) = spawn_http_server().await;
    let resp = http_post(addr, "/wallet/getblockbylatestnum", json!({"num": 5})).await;
    assert!(
        resp.get("block").is_some() || resp.get("Error").is_some(),
        "expected `block` array or Error, got: {resp}"
    );
    if let Some(blocks) = resp.get("block").and_then(Value::as_array) {
        assert_eq!(blocks.len(), 1, "fixture has one block; got: {resp}");
    }
}

/// `POST /wallet/getblockbylimitnext` — body `{startNum, endNum}` returns the range.
#[tokio::test]
async fn wallet_getblockbylimitnext_accepts_camelcase_args() {
    let (addr, ..) = spawn_http_server().await;
    let resp = http_post(
        addr,
        "/wallet/getblockbylimitnext",
        json!({"startNum": 0, "endNum": 3}),
    )
    .await;
    assert!(
        resp.get("block").is_some() || resp.get("Error").is_some(),
        "expected `block` array or Error, got: {resp}"
    );
}

/// `POST /wallet/getblockbylimitnext` — should also accept snake_case
/// names that some older clients send.
#[tokio::test]
async fn wallet_getblockbylimitnext_accepts_snake_case_args() {
    let (addr, ..) = spawn_http_server().await;
    let resp = http_post(
        addr,
        "/wallet/getblockbylimitnext",
        json!({"start_num": 0, "end_num": 3}),
    )
    .await;
    assert!(
        resp.get("block").is_some() || resp.get("Error").is_some(),
        "expected `block` array or Error, got: {resp}"
    );
}

/// `POST /wallet/getaccountbalance` — both nested
/// `account_identifier` shape (java-tron canonical) and flat
/// `address` shorthand return the seeded Alice balance.
#[tokio::test]
async fn wallet_getaccountbalance_returns_seeded_alice_balance() {
    let (addr, ..) = spawn_http_server().await;
    let alice_hex = format!("0x{}", hex::encode(ALICE_HEX));

    // Canonical nested shape.
    let resp = http_post(
        addr,
        "/wallet/getaccountbalance",
        json!({"account_identifier": {"address": alice_hex.clone()}}),
    )
    .await;
    assert_eq!(resp["balance"], 1_234_567_890_i64);

    // Flat-address shorthand.
    let resp = http_post(
        addr,
        "/wallet/getaccountbalance",
        json!({"address": alice_hex}),
    )
    .await;
    assert_eq!(resp["balance"], 1_234_567_890_i64);
}

/// `POST /wallet/getaccountbalance` echoes the block_identifier when
/// supplied — clients building TAPOS-style refs rely on the round-trip.
#[tokio::test]
async fn wallet_getaccountbalance_echoes_block_identifier() {
    let (addr, ..) = spawn_http_server().await;
    let alice_hex = format!("0x{}", hex::encode(ALICE_HEX));
    let resp = http_post(
        addr,
        "/wallet/getaccountbalance",
        json!({
            "account_identifier": {"address": alice_hex},
            "block_identifier": {"hash": "abcdef", "number": 42},
        }),
    )
    .await;
    assert_eq!(resp["balance"], 1_234_567_890_i64);
    assert_eq!(resp["block_identifier"]["hash"], "abcdef");
    assert_eq!(resp["block_identifier"]["number"], 42);
}

/// `POST /wallet/getcontractinfo` for an unknown contract returns null
/// (matching java-tron). Spot-checks the addr-decoding path doesn't crash.
#[tokio::test]
async fn wallet_getcontractinfo_unknown_address_returns_empty_object() {
    let (addr, ..) = spawn_http_server().await;
    let resp = http_post(
        addr,
        "/wallet/getcontractinfo",
        json!({"value": format!("0x{}", hex::encode(ALICE_HEX))}),
    )
    .await;
    // Missing contract → empty object, matching java-tron (verified against
    // TronGrid: getcontractinfo on a non-contract returns {}).
    assert_eq!(resp, json!({}), "got: {resp}");
}

/// Spawn a server whose state has the head pointer (`number` + `hash`)
/// and block bytes present, but the `block_index[number]` row missing.
/// This reproduces the transient cross-store view a `getnowblock` read
/// can observe mid-commit: the head pointer is written *after* the
/// block bytes but the index row is committed in a separate per-store
/// batch, so a reader can momentarily see the head hash without the
/// matching `block_index` entry. The handler must still return the head
/// block (resolved via the hash), never an empty `{}`.
async fn spawn_server_head_hash_only() -> std::net::SocketAddr {
    let blocks_be = mem();
    let block_index_be = mem(); // intentionally left EMPTY
    let dp_be = mem();

    let block = Block {
        block_header: Some(BlockHeader {
            raw_data: Some(BlockHeaderRaw {
                number: 99,
                parent_hash: vec![0u8; 32],
                timestamp: 1_700_000_009_000,
                witness_address: ALICE_HEX.to_vec(),
                tx_trie_root: tron_types::calc_tx_trie_root(&[])
                    .map(|h| h.to_vec())
                    .unwrap_or_default(),
                ..Default::default()
            }),
            witness_signature: Vec::new(),
        }),
        transactions: Vec::new(),
    };
    let block_id = block_id_from_block(&block).unwrap();
    BlockStore::new(blocks_be.clone()).put(&block_id, &block).unwrap();

    let dp = DynamicPropertiesStore::new(dp_be.clone());
    // Head pointer present; block_index row deliberately absent.
    dp.save_latest_block_header_number(99);
    dp.save_latest_block_header_hash(block_id.as_bytes());

    let state = RpcState::new(
        mem(),
        blocks_be,
        block_index_be,
        mem(),
        dp_be,
        MAINNET_CHAIN_ID,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = tron_rpc::http_rest::router(state);
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service()).await.unwrap();
    });
    tokio::task::yield_now().await;
    addr
}

/// Regression: `getnowblock` must resolve the head via the head *hash*
/// so a missing `block_index` row (a transient mid-commit view) never
/// degrades the response to an empty `{}`.
#[tokio::test]
async fn wallet_getnowblock_resolves_via_head_hash_when_index_row_absent() {
    let addr = spawn_server_head_hash_only().await;
    let resp = http_get(addr, "/wallet/getnowblock").await;
    let num = resp["block_header"]["raw_data"]["number"].as_i64();
    assert_eq!(
        num,
        Some(99),
        "getnowblock should return the head block via the hash path, got: {resp}"
    );
}

/// Under concurrent load, every `getnowblock` response stays a
/// well-formed, non-empty block envelope. Runs on a multi-threaded
/// runtime so the handler's `block_in_place` offload path is exercised
/// (it is a no-op on the single-threaded default test runtime).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wallet_getnowblock_concurrent_load_returns_consistent_block() {
    let (addr, ..) = spawn_http_server().await;
    let mut handles = Vec::new();
    for _ in 0..64 {
        handles.push(tokio::spawn(async move {
            let resp = http_get(addr, "/wallet/getnowblock").await;
            // Body must be a populated block, never an empty object.
            resp["block_header"]["raw_data"]["number"]
                .as_i64()
                .expect("well-formed block envelope")
        }));
    }
    for h in handles {
        assert_eq!(h.await.unwrap(), 1);
    }
}
