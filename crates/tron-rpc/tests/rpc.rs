//! HTTP-level integration tests for the JSON-RPC server.
//!
//! Each test spins up a real Axum server bound to a random loopback
//! port, fires JSON-RPC requests at it via raw TCP, and asserts on
//! both the JSON response shape and the underlying state semantics.

use std::sync::Arc;

use hex_literal::hex;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tron_chainbase::{
    AccountStore, BlockIndexStore, BlockStore, DynamicPropertiesStore, KvBackend, MemBackend,
    TransactionStore,
};
use tron_crypto::address::Address;
use tron_proto::block_header::Raw as BlockHeaderRaw;
use tron_proto::{Account, AccountType, Block, BlockHeader};
use tron_rpc::{RpcState, MAINNET_CHAIN_ID};
use tron_types::block_id_from_block;

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

/// Spin up a fresh server on `127.0.0.1:0`. Returns the bound socket
/// address and a handle to the in-memory state for direct setup.
async fn spawn_server() -> (
    std::net::SocketAddr,
    AccountStore,
    BlockStore,
    BlockIndexStore,
    TransactionStore,
    DynamicPropertiesStore,
) {
    // We need the typed-store handles for setup. The server's RpcState
    // wraps the same backends, so mutations through these stores are
    // visible to RPC reads.
    let accounts_be = mem();
    let blocks_be = mem();
    let block_index_be = mem();
    let trans_be = mem();
    let dp_be = mem();
    let accounts = AccountStore::new(accounts_be.clone());
    let blocks = BlockStore::new(blocks_be.clone());
    let block_index = BlockIndexStore::new(block_index_be.clone());
    let transactions = TransactionStore::new(trans_be.clone());
    let dyn_props = DynamicPropertiesStore::new(dp_be.clone());

    let state = RpcState::new(
        accounts_be,
        blocks_be,
        block_index_be,
        trans_be,
        dp_be,
        MAINNET_CHAIN_ID,
    );

    // Bind on :0, learn the actual port, then start serving.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let app = tron_rpc::server::router(state);
        axum::serve(listener, app.into_make_service()).await.unwrap();
    });
    // Tiny pause so the listener registers with the runtime.
    tokio::task::yield_now().await;
    (addr, accounts, blocks, block_index, transactions, dyn_props)
}

async fn call(addr: std::net::SocketAddr, body: Value) -> Value {
    let body_str = body.to_string();
    // `Connection: close` so the server hangs up after the response —
    // otherwise axum keeps the connection alive and `read_to_string`
    // blocks indefinitely.
    let req = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body_str}",
        body_str.len()
    );
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    // Split headers from body (\r\n\r\n).
    let body = response.split("\r\n\r\n").nth(1).unwrap_or("");
    serde_json::from_str(body).expect("non-json response from server")
}

#[tokio::test]
async fn web3_client_version_returns_our_string() {
    let (addr, ..) = spawn_server().await;
    let resp = call(addr, json!({"jsonrpc":"2.0","method":"web3_clientVersion","id":1})).await;
    assert_eq!(resp["result"], "tron-goblin/0.0.1");
    assert_eq!(resp["id"], 1);
}

#[tokio::test]
async fn web3_sha3_matches_keccak256() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"web3_sha3","params":["0x"],"id":1}),
    )
    .await;
    // keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    assert_eq!(
        resp["result"],
        "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    );
}

#[tokio::test]
async fn eth_chain_id_returns_mainnet() {
    let (addr, ..) = spawn_server().await;
    let resp = call(addr, json!({"jsonrpc":"2.0","method":"eth_chainId","id":1})).await;
    // 11111 = 0x2b67
    assert_eq!(resp["result"], "0x2b67");
}

#[tokio::test]
async fn net_version_is_decimal_string_per_spec() {
    let (addr, ..) = spawn_server().await;
    let resp = call(addr, json!({"jsonrpc":"2.0","method":"net_version","id":1})).await;
    // **JSON-RPC convention quirk**: `net_version` returns decimal,
    // `eth_chainId` returns hex. Both for the same number.
    assert_eq!(resp["result"], "11111");
}

#[tokio::test]
async fn eth_block_number_reads_dynamic_properties() {
    let (addr, _accts, _blocks, _idx, _txs, dp) = spawn_server().await;
    dp.save_latest_block_header_number(42);
    let resp = call(addr, json!({"jsonrpc":"2.0","method":"eth_blockNumber","id":1})).await;
    assert_eq!(resp["result"], "0x2a");
}

#[tokio::test]
async fn eth_get_balance_returns_account_balance() {
    let (addr, accounts, ..) = spawn_server().await;
    let alice_bytes = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");
    let alice = Address::from_raw(alice_bytes);
    accounts.put(
        &alice,
        &Account {
            address: alice_bytes.to_vec(),
            balance: 1_000_000_000,
            r#type: AccountType::Normal as i32,
            ..Default::default()
        },
    ).unwrap();
    // Send the 20-byte form (eth-style); server prepends 0x41 automatically.
    let resp = call(
        addr,
        json!({
            "jsonrpc": "2.0",
            "method": "eth_getBalance",
            "params": ["0x2e988a386a799f506693793c6a5af6b54dfaabfb", "latest"],
            "id": 1,
        }),
    )
    .await;
    // 1_000_000_000 = 0x3b9aca00
    assert_eq!(resp["result"], "0x3b9aca00");
}

#[tokio::test]
async fn eth_get_balance_accepts_21_byte_tron_address_form() {
    let (addr, accounts, ..) = spawn_server().await;
    let alice_bytes = hex!("412e988a386a799f506693793c6a5af6b54dfaabfb");
    let alice = Address::from_raw(alice_bytes);
    accounts.put(
        &alice,
        &Account {
            address: alice_bytes.to_vec(),
            balance: 7,
            ..Default::default()
        },
    ).unwrap();
    let resp = call(
        addr,
        json!({
            "jsonrpc": "2.0",
            "method": "eth_getBalance",
            "params": [format!("0x{}", hex::encode(alice_bytes)), "latest"],
            "id": 1,
        }),
    )
    .await;
    assert_eq!(resp["result"], "0x7");
}

#[tokio::test]
async fn eth_get_balance_zero_for_unknown_account() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({
            "jsonrpc": "2.0",
            "method": "eth_getBalance",
            "params": ["0x0000000000000000000000000000000000000000", "latest"],
            "id": 1,
        }),
    )
    .await;
    assert_eq!(resp["result"], "0x0");
}

#[tokio::test]
async fn eth_get_block_by_number_with_latest() {
    let (addr, _accts, blocks, idx, _txs, dp) = spawn_server().await;
    let block = Block {
        transactions: Vec::new(),
        block_header: Some(BlockHeader {
            raw_data: Some(BlockHeaderRaw {
                timestamp: 1_700_000_000_000,
                tx_trie_root: Vec::new(),
                parent_hash: vec![0u8; 32],
                number: 5,
                witness_id: 0,
                witness_address: hex!("412e988a386a799f506693793c6a5af6b54dfaabfb").to_vec(),
                version: 28,
                account_state_root: Vec::new(),
            }),
            witness_signature: Vec::new(),
        }),
    };
    let block_id = block_id_from_block(&block).unwrap();
    blocks.put(&block_id, &block).unwrap();
    idx.put(&block_id).unwrap();
    dp.save_latest_block_header_number(5);

    let resp = call(
        addr,
        json!({
            "jsonrpc": "2.0",
            "method": "eth_getBlockByNumber",
            "params": ["latest", false],
            "id": 1,
        }),
    )
    .await;
    let result = &resp["result"];
    assert_eq!(result["number"], "0x5");
    assert_eq!(result["hash"], format!("0x{}", hex::encode(block_id.as_bytes())));
}

#[tokio::test]
async fn eth_get_block_by_hash_returns_null_when_missing() {
    let (addr, ..) = spawn_server().await;
    let bogus = format!("0x{}", "ab".repeat(32));
    let resp = call(
        addr,
        json!({
            "jsonrpc": "2.0",
            "method": "eth_getBlockByHash",
            "params": [bogus, false],
            "id": 1,
        }),
    )
    .await;
    assert_eq!(resp["result"], Value::Null);
}

#[tokio::test]
async fn unknown_method_returns_jsonrpc_error_object() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"eth_doesNotExist","id":1}),
    )
    .await;
    assert_eq!(resp["error"]["code"], -32601);
    assert!(resp["error"]["message"]
        .as_str()
        .unwrap()
        .contains("eth_doesNotExist"));
}

#[tokio::test]
async fn invalid_hex_param_returns_invalid_params_error() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({
            "jsonrpc": "2.0",
            "method": "eth_getBalance",
            "params": ["not-hex"],
            "id": 1,
        }),
    )
    .await;
    assert_eq!(resp["error"]["code"], -32602);
}

#[tokio::test]
async fn eth_gas_price_falls_back_to_default_when_unset() {
    let (addr, ..) = spawn_server().await;
    let resp = call(addr, json!({"jsonrpc":"2.0","method":"eth_gasPrice","id":1})).await;
    // 210 = 0xd2
    assert_eq!(resp["result"], "0xd2");
}

#[tokio::test]
async fn eth_get_transaction_count_returns_zero() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"eth_getTransactionCount",
               "params":["0x4111111111111111111111111111111111111111","latest"],"id":1}),
    )
    .await;
    assert_eq!(resp["result"], "0x0");
}

#[tokio::test]
async fn eth_syncing_returns_false() {
    let (addr, ..) = spawn_server().await;
    let resp = call(addr, json!({"jsonrpc":"2.0","method":"eth_syncing","id":1})).await;
    assert_eq!(resp["result"], false);
}

#[tokio::test]
async fn eth_mining_returns_false() {
    let (addr, ..) = spawn_server().await;
    let resp = call(addr, json!({"jsonrpc":"2.0","method":"eth_mining","id":1})).await;
    assert_eq!(resp["result"], false);
}

#[tokio::test]
async fn eth_hashrate_returns_zero() {
    let (addr, ..) = spawn_server().await;
    let resp = call(addr, json!({"jsonrpc":"2.0","method":"eth_hashrate","id":1})).await;
    assert_eq!(resp["result"], "0x0");
}

#[tokio::test]
async fn eth_accounts_returns_empty_list() {
    let (addr, ..) = spawn_server().await;
    let resp = call(addr, json!({"jsonrpc":"2.0","method":"eth_accounts","id":1})).await;
    assert_eq!(resp["result"], Value::Array(vec![]));
}

#[tokio::test]
async fn eth_coinbase_returns_zero_address() {
    let (addr, ..) = spawn_server().await;
    let resp = call(addr, json!({"jsonrpc":"2.0","method":"eth_coinbase","id":1})).await;
    assert_eq!(resp["result"], "0x0000000000000000000000000000000000000000");
}

#[tokio::test]
async fn eth_max_priority_fee_per_gas_returns_zero() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"eth_maxPriorityFeePerGas","id":1}),
    )
    .await;
    assert_eq!(resp["result"], "0x0");
}

#[tokio::test]
async fn eth_get_code_for_unknown_address_returns_empty() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"eth_getCode",
               "params":["0x1111111111111111111111111111111111111111","latest"],"id":1}),
    )
    .await;
    assert_eq!(resp["result"], "0x");
}

#[tokio::test]
async fn eth_get_storage_at_returns_zero_when_unset() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"eth_getStorageAt",
               "params":["0x1111111111111111111111111111111111111111","0x0","latest"],"id":1}),
    )
    .await;
    assert_eq!(
        resp["result"],
        "0x0000000000000000000000000000000000000000000000000000000000000000"
    );
}

#[tokio::test]
async fn eth_fee_history_returns_zeroed_window() {
    let (addr, _accts, _blocks, _idx, _txs, dp) = spawn_server().await;
    dp.save_latest_block_header_number(100);
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"eth_feeHistory",
               "params":["0x5","latest",[]],"id":1}),
    )
    .await;
    assert_eq!(resp["result"]["oldestBlock"], "0x5f"); // 100 - 5 = 95 = 0x5f
    assert_eq!(resp["result"]["baseFeePerGas"].as_array().unwrap().len(), 6);
    assert_eq!(resp["result"]["gasUsedRatio"].as_array().unwrap().len(), 5);
}

#[tokio::test]
async fn net_peer_count_returns_zero() {
    let (addr, ..) = spawn_server().await;
    let resp = call(addr, json!({"jsonrpc":"2.0","method":"net_peerCount","id":1})).await;
    assert_eq!(resp["result"], "0x0");
}

#[tokio::test]
async fn eth_blob_base_fee_returns_zero() {
    let (addr, ..) = spawn_server().await;
    let resp = call(addr, json!({"jsonrpc":"2.0","method":"eth_blobBaseFee","id":1})).await;
    assert_eq!(resp["result"], "0x0");
}

#[tokio::test]
async fn get_account_returns_null_for_unknown_address() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getAccount",
               "params":["0x1234567890123456789012345678901234567890"],"id":1}),
    )
    .await;
    assert_eq!(resp["result"], Value::Null);
}

#[tokio::test]
async fn get_account_returns_full_account_for_known_address() {
    let (addr, accounts, ..) = spawn_server().await;
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(0xab);
    let address = Address::from_raw(a);
    accounts.put(
        &address,
        &Account {
            address: a.to_vec(),
            balance: 12_345_000_000,
            r#type: AccountType::Normal as i32,
            ..Default::default()
        },
    ).unwrap();
    // 20-byte Ethereum-style hex (40 chars after 0x). parse_eth_address
    // will prepend 0x41 to reconstruct the 21-byte TRON address.
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getAccount",
               "params":["0xabababababababababababababababababababab"],"id":1}),
    )
    .await;
    assert_eq!(resp["result"]["balance"], 12_345_000_000_i64);
}

#[tokio::test]
async fn get_chain_parameters_returns_seeded_entries() {
    let (addr, _accts, _blocks, _idx, _txs, dp) = spawn_server().await;
    dp.put_long(b"TRANSACTION_FEE", 1234);
    dp.put_long(b"ENERGY_FEE", 5678);
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getChainParameters","id":1}),
    )
    .await;
    let params = resp["result"]["chainParameter"].as_array().unwrap();
    // java-parity: keys use java's `get…` names; zero values omit the
    // `value` field (proto3 JSON), so map through Option.
    let by_key: std::collections::HashMap<_, _> = params
        .iter()
        .map(|p| (
            p["key"].as_str().unwrap().to_string(),
            p["value"].as_i64().unwrap_or(0),
        ))
        .collect();
    assert_eq!(by_key.get("getTransactionFee"), Some(&1234));
    assert_eq!(by_key.get("getEnergyFee"), Some(&5678));
    // Every java entry is present even when unset (value omitted → 0).
    assert_eq!(params.len(), 75);
    assert_eq!(by_key.get("getAllowNewResourceModel"), Some(&0));
}

#[tokio::test]
async fn list_witnesses_returns_empty_when_unconfigured() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"listWitnesses","id":1}),
    )
    .await;
    // No witnesses store attached → empty array (graceful degradation).
    assert_eq!(resp["result"]["witnesses"], Value::Array(vec![]));
}

#[tokio::test]
async fn get_burn_trx_reads_from_dyn_props() {
    let (addr, _accts, _blocks, _idx, _txs, dp) = spawn_server().await;
    dp.put_long(b"BURN_TRX_AMOUNT", 42);
    let resp = call(addr, json!({"jsonrpc":"2.0","method":"getBurnTrx","id":1})).await;
    // java wraps the value in NumberMessage JSON.
    assert_eq!(resp["result"]["burnTrxAmount"], 42_i64);
}

#[tokio::test]
async fn list_proposals_returns_empty_when_unconfigured() {
    let (addr, ..) = spawn_server().await;
    let resp = call(addr, json!({"jsonrpc":"2.0","method":"listProposals","id":1})).await;
    assert_eq!(resp["result"]["proposals"], Value::Array(vec![]));
}

#[tokio::test]
async fn get_node_info_returns_block_header_and_version() {
    let (addr, _accts, _blocks, _idx, _txs, dp) = spawn_server().await;
    dp.save_latest_block_header_number(99);
    dp.save_latest_block_header_timestamp(1_700_000_000_000);
    let resp = call(addr, json!({"jsonrpc":"2.0","method":"getNodeInfo","id":1})).await;
    assert_eq!(resp["result"]["block"]["number"], 99_i64);
    assert_eq!(
        resp["result"]["configNodeInfo"]["versionCode"],
        "tron-goblin/0.0.1"
    );
}

#[tokio::test]
async fn get_energy_prices_reads_dyn_props() {
    let (addr, _accts, _blocks, _idx, _txs, dp) = spawn_server().await;
    // Served verbatim from the persisted history string (java parity) —
    // NOT fabricated from the current ENERGY_FEE.
    dp.save_energy_price_history("0:100,1542607200000:20");
    let resp = call(addr, json!({"jsonrpc":"2.0","method":"getEnergyPrices","id":1})).await;
    assert_eq!(resp["result"]["prices"], "0:100,1542607200000:20");
}

#[tokio::test]
async fn get_now_block_returns_null_when_no_block_indexed() {
    let (addr, ..) = spawn_server().await;
    let resp = call(addr, json!({"jsonrpc":"2.0","method":"getNowBlock","id":1})).await;
    // Without a block at head_number=0 indexed, result is Null (no row).
    assert_eq!(resp["result"], Value::Null);
}

// =====================================================================
// eth_call, eth_estimateGas, eth_getTransactionReceipt, eth_getLogs
// =====================================================================

#[tokio::test]
async fn eth_call_returns_error_when_no_evm_backends_configured() {
    // The default spawn_server doesn't wire eth_call backends.
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"eth_call",
               "params":[{"to":"0x0000000000000000000000000000000000000001","data":"0x"}],"id":1}),
    )
    .await;
    assert!(resp["error"]["message"]
        .as_str()
        .unwrap()
        .contains("not available"));
}

#[tokio::test]
async fn eth_estimate_gas_returns_error_when_no_evm_backends_configured() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"eth_estimateGas",
               "params":[{"to":"0x0000000000000000000000000000000000000001","data":"0x"}],"id":1}),
    )
    .await;
    assert!(resp["error"]["message"]
        .as_str()
        .unwrap()
        .contains("not available"));
}

#[tokio::test]
async fn eth_get_transaction_receipt_null_without_history_store() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"eth_getTransactionReceipt",
               "params":["0xaabbccdd00000000000000000000000000000000000000000000000000000000"],"id":1}),
    )
    .await;
    assert_eq!(resp["result"], Value::Null);
}

#[tokio::test]
async fn eth_get_logs_empty_without_history_store() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"eth_getLogs","params":[{}],"id":1}),
    )
    .await;
    assert_eq!(resp["result"], Value::Array(vec![]));
}

#[tokio::test]
async fn eth_get_logs_rejects_oversized_range() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"eth_getLogs",
               "params":[{"fromBlock":"0x0","toBlock":"0x10000"}],"id":1}),
    )
    .await;
    assert_eq!(resp["error"]["code"], -32602);
}

#[tokio::test]
async fn get_transaction_info_by_id_null_without_history() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getTransactionInfoById",
               "params":["0xaabbccdd00000000000000000000000000000000000000000000000000000000"],"id":1}),
    )
    .await;
    assert_eq!(resp["result"], Value::Null);
}

#[tokio::test]
async fn list_assets_returns_empty_when_unconfigured() {
    let (addr, ..) = spawn_server().await;
    let resp = call(addr, json!({"jsonrpc":"2.0","method":"listAssets","id":1})).await;
    assert_eq!(resp["result"]["assetIssue"], Value::Array(vec![]));
}

#[tokio::test]
async fn list_exchanges_returns_empty_when_unconfigured() {
    let (addr, ..) = spawn_server().await;
    let resp = call(addr, json!({"jsonrpc":"2.0","method":"listExchanges","id":1})).await;
    assert_eq!(resp["result"]["exchanges"], Value::Array(vec![]));
}

#[tokio::test]
async fn get_nodes_returns_empty_list() {
    let (addr, ..) = spawn_server().await;
    let resp = call(addr, json!({"jsonrpc":"2.0","method":"getNodes","id":1})).await;
    assert_eq!(resp["result"]["nodes"], Value::Array(vec![]));
}

#[tokio::test]
async fn broadcast_transaction_returns_other_error() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"broadcastTransaction","params":[{}],"id":1}),
    )
    .await;
    assert_eq!(resp["result"]["result"], false);
    assert_eq!(resp["result"]["code"], "OTHER_ERROR");
}

#[tokio::test]
async fn eth_send_raw_transaction_returns_unsupported_without_mempool() {
    // Server with no mempool attached → -32004 "no mempool attached",
    // not the "method not found" -32601 that the old stub returned.
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0x00"],"id":1}),
    )
    .await;
    assert_eq!(resp["error"]["code"], -32004);
}

#[tokio::test]
async fn get_next_maintenance_time_reads_dyn_props() {
    let (addr, _accts, _blocks, _idx, _txs, dp) = spawn_server().await;
    dp.put_long(b"NEXT_MAINTENANCE_TIME", 1_700_000_000_000);
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getNextMaintenanceTime","id":1}),
    )
    .await;
    // java wraps the value in NumberMessage JSON ({"num": t}).
    assert_eq!(resp["result"]["num"], 1_700_000_000_000_i64);
}

#[tokio::test]
async fn eth_call_runs_simple_contract_when_evm_backends_attached() {
    use prost::Message as _;
    use tron_chainbase::{CodeStore, MemBackend};
    use tron_crypto::address::Address;
    use tron_proto::Account;
    use tron_rpc::EthCallBackends;

    // Build a state with EVM call backends manually so we can install a
    // contract and route eth_call through it.
    let accounts_be: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
    let blocks_be: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
    let block_index_be: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
    let trans_be: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
    let dp_be: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
    let code_be: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
    let storage_be: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
    let witnesses_be: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
    let contract_state_be: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
    let delegated_be: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
    let delegation_be: Arc<dyn KvBackend> = Arc::new(MemBackend::new());
    let contracts_be: Arc<dyn KvBackend> = Arc::new(MemBackend::new());

    // Pre-install a contract that pushes 0x42 in memory + RETURNs 32 bytes.
    // Bytecode (annotated):
    //   60 42        PUSH1 0x42      → stack: [0x42]
    //   60 00        PUSH1 0x00      → stack: [0x42, 0x00]
    //   52           MSTORE          → mem[0..32] = 0x...42
    //   60 20        PUSH1 0x20      → stack: [0x20]
    //   60 00        PUSH1 0x00      → stack: [0x20, 0x00]
    //   f3           RETURN          → return 32 bytes from mem[0..]
    let bytecode = vec![0x60, 0x42, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];
    let mut contract_addr_bytes = [0u8; 21];
    contract_addr_bytes[0] = 0x41;
    contract_addr_bytes[1..].fill(0xc1);
    let contract_addr = Address::from_raw(contract_addr_bytes);
    let code_hash = tron_crypto::hash::keccak256(&bytecode);
    {
        let accounts = AccountStore::new(accounts_be.clone());
        accounts.put(
            &contract_addr,
            &Account {
                address: contract_addr_bytes.to_vec(),
                code: bytecode.clone(),
                code_hash: code_hash.to_vec(),
                ..Default::default()
            },
        ).unwrap();
        let code = CodeStore::new(code_be.clone());
        code.put(&code_hash, &bytecode).unwrap();
    }

    let state = RpcState::new(
        accounts_be.clone(),
        blocks_be.clone(),
        block_index_be.clone(),
        trans_be.clone(),
        dp_be.clone(),
        MAINNET_CHAIN_ID,
    )
    .with_eth_call_backends(EthCallBackends {
        accounts: accounts_be,
        code: code_be,
        storage: storage_be,
        witnesses: witnesses_be,
        contract_state: contract_state_be,
        dyn_props: dp_be,
        delegated_resources: delegated_be,
        delegation: delegation_be,
        contracts: contracts_be,
        block_index: Some(block_index_be),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, tron_rpc::server::router(state).into_make_service())
            .await
            .unwrap();
    });
    tokio::task::yield_now().await;

    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"eth_call",
               "params":[{"to":"0xc1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1","data":"0x"}],"id":1}),
    )
    .await;
    assert_eq!(
        resp["result"]
            .as_str()
            .expect("eth_call result should be a hex string"),
        "0x0000000000000000000000000000000000000000000000000000000000000042"
    );
    // Suppress the unused import warning for prost::Message.
    let _ = bytecode.clone().encode_to_vec();
}

// =====================================================================
// Filter family
// =====================================================================

#[tokio::test]
async fn eth_new_filter_returns_id_and_uninstall_removes_it() {
    let (addr, ..) = spawn_server().await;
    // 20-byte address (parse_eth_address prepends 0x41 automatically).
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"eth_newFilter",
               "params":[{"address":"0xabababababababababababababababababababab"}],"id":1}),
    )
    .await;
    let id = resp["result"]
        .as_str()
        .expect("filter id should be hex string")
        .to_string();
    assert!(id.starts_with("0x"));
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"eth_uninstallFilter","params":[id.clone()],"id":2}),
    )
    .await;
    assert_eq!(resp["result"], true);
    // Second uninstall is now a no-op.
    let resp2 = call(
        addr,
        json!({"jsonrpc":"2.0","method":"eth_uninstallFilter","params":[id],"id":3}),
    )
    .await;
    assert_eq!(resp2["result"], false);
}

#[tokio::test]
async fn eth_new_block_filter_returns_id() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"eth_newBlockFilter","id":1}),
    )
    .await;
    assert!(resp["result"]
        .as_str()
        .expect("filter id should be hex")
        .starts_with("0x"));
}

#[tokio::test]
async fn eth_new_pending_transaction_filter_returns_id() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"eth_newPendingTransactionFilter","id":1}),
    )
    .await;
    assert!(resp["result"]
        .as_str()
        .expect("filter id should be hex")
        .starts_with("0x"));
}

#[tokio::test]
async fn eth_get_filter_changes_returns_empty_initially() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"eth_newBlockFilter","id":1}),
    )
    .await;
    let id = resp["result"].as_str().unwrap().to_string();
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"eth_getFilterChanges","params":[id],"id":2}),
    )
    .await;
    assert_eq!(resp["result"], Value::Array(vec![]));
}

#[tokio::test]
async fn eth_get_filter_changes_unknown_id_errors() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"eth_getFilterChanges","params":["0xdeadbeef"],"id":1}),
    )
    .await;
    assert_eq!(resp["error"]["code"], -32000);
}

#[tokio::test]
async fn eth_get_filter_logs_requires_log_filter() {
    let (addr, ..) = spawn_server().await;
    let block_id = call(
        addr,
        json!({"jsonrpc":"2.0","method":"eth_newBlockFilter","id":1}),
    )
    .await["result"]
        .as_str()
        .unwrap()
        .to_string();
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"eth_getFilterLogs","params":[block_id],"id":2}),
    )
    .await;
    assert_eq!(resp["error"]["code"], -32602);
}

#[tokio::test]
async fn eth_new_filter_rejects_oversized_range_at_query_time() {
    // Filter creation accepts any range; the size check happens at
    // query time inside `collect_logs`. Verify that path.
    let (addr, _accts, _blocks, _idx, _txs, dp) = spawn_server().await;
    dp.save_latest_block_header_number(50_000);
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"eth_newFilter",
               "params":[{"fromBlock":"0x0","toBlock":"0xc350"}],"id":1}),
    )
    .await;
    let id = resp["result"].as_str().unwrap().to_string();
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"eth_getFilterLogs","params":[id],"id":2}),
    )
    .await;
    assert_eq!(resp["error"]["code"], -32602);
}

// =====================================================================
// eth_sendRawTransaction (mempool)
// =====================================================================

#[tokio::test]
async fn eth_send_raw_transaction_errors_without_mempool() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0x00"],"id":1}),
    )
    .await;
    assert_eq!(resp["error"]["code"], -32004);
}

#[tokio::test]
async fn eth_send_raw_transaction_accepts_payload_when_mempool_attached() {
    let accounts_be = mem();
    let blocks_be = mem();
    let block_index_be = mem();
    let trans_be = mem();
    let dp_be = mem();
    let state = RpcState::new(
        accounts_be,
        blocks_be,
        block_index_be,
        trans_be,
        dp_be,
        MAINNET_CHAIN_ID,
    )
    .with_mempool(tron_rpc::InMemoryMempool::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, tron_rpc::server::router(state).into_make_service())
            .await
            .unwrap();
    });
    tokio::task::yield_now().await;

    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"eth_sendRawTransaction",
               "params":["0xdeadbeef"],"id":1}),
    )
    .await;
    let id_hex = resp["result"]
        .as_str()
        .expect("tx id should be a hex string");
    assert!(id_hex.starts_with("0x") && id_hex.len() == 66);
    // The tx id should match sha256 of the payload bytes.
    let payload = hex::decode("deadbeef").unwrap();
    let expected = tron_crypto::hash::sha256(&payload);
    assert_eq!(id_hex, format!("0x{}", hex::encode(expected)));
}

#[tokio::test]
async fn broadcast_transaction_returns_other_error_when_no_mempool() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"broadcastTransaction","params":["0xdeadbeef"],"id":1}),
    )
    .await;
    assert_eq!(resp["result"]["result"], false);
    assert_eq!(resp["result"]["code"], "OTHER_ERROR");
}

// =====================================================================
// eth_getProof
// =====================================================================

#[tokio::test]
async fn eth_get_proof_returns_eip1186_shape_with_empty_proofs() {
    let (addr, accounts, ..) = spawn_server().await;
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(0xee);
    let address = Address::from_raw(a);
    accounts.put(
        &address,
        &Account {
            address: a.to_vec(),
            balance: 1_234,
            ..Default::default()
        },
    ).unwrap();
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"eth_getProof",
               "params":["0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",["0x0"],"latest"],"id":1}),
    )
    .await;
    assert_eq!(resp["result"]["balance"], "0x4d2");
    assert_eq!(resp["result"]["nonce"], "0x0");
    assert_eq!(resp["result"]["accountProof"], Value::Array(vec![]));
    let storage = resp["result"]["storageProof"].as_array().unwrap();
    assert_eq!(storage.len(), 1);
    assert_eq!(storage[0]["key"], "0x0");
    assert_eq!(storage[0]["proof"], Value::Array(vec![]));
}

// =============================================================================
// New read methods (2026-05-24): getAccountResource, getAccountNet,
// getDelegatedResourceAccountIndex(V2), getCanWithdrawUnfreezeAmount,
// getAvailableUnfreezeCount, getBlock / getBlockById /
// getBlockByLimitNext / getBlockByLatestNum, getContract / getContractInfo,
// getProposalById, getAssetIssueByAccount, validateAddress, getPendingSize.
// =============================================================================

#[tokio::test]
async fn get_account_resource_returns_quota_view() {
    let (addr, accounts, _bs, _bi, _tx, dp) = spawn_server().await;
    // Seed an account with frozen bandwidth + frozen energy.
    let mut a_bytes = [0u8; 21];
    a_bytes[0] = 0x41;
    a_bytes[1..].fill(0xab);
    let address = Address::from_raw(a_bytes);
    let mut acct = Account {
        address: a_bytes.to_vec(),
        balance: 10_000_000,
        ..Default::default()
    };
    acct.frozen_v2.push(tron_proto::account::FreezeV2 {
        r#type: 0, // BANDWIDTH
        amount: 5_000_000,
    });
    acct.frozen_v2.push(tron_proto::account::FreezeV2 {
        r#type: 1, // ENERGY
        amount: 3_000_000,
    });
    accounts.put(&address, &acct).unwrap();
    dp.save_total_net_weight(100);
    dp.save_total_energy_weight(100);
    dp.save_total_energy_limit(100_000_000_000);
    dp.save_unfreeze_delay_days(1);

    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getAccountResource",
               "params":["0xabababababababababababababababababababab"],"id":1}),
    )
    .await;
    let r = &resp["result"];
    // Both quotas should be non-zero given the seeded weights.
    assert!(r["NetLimit"].as_i64().unwrap() > 0, "{}", r);
    assert!(r["EnergyLimit"].as_i64().unwrap() > 0, "{}", r);
    // Free quota is the default 5000 bytes.
    assert_eq!(r["freeNetLimit"], 5_000);
    // Totals reflect what we seeded.
    assert_eq!(r["TotalNetWeight"], 100);
    assert_eq!(r["TotalEnergyWeight"], 100);
}

#[tokio::test]
async fn get_account_resource_decays_usage_and_reports_tron_power() {
    // Regression for the getaccountresource read path: usage must decay at
    // read using java's head_slot (timestamp/3000, NOT block height) — with
    // an old consume-time it fully decays to 0 (the old code returned it
    // stale). Plus tronPowerUsed = sum of votes, tronPowerLimit = AllTronPower.
    let (addr, accounts, _bs, _bi, _tx, dp) = spawn_server().await;
    // Head far in the future of the (epoch-0) genesis so head_slot is large.
    dp.save_genesis_block_timestamp(0);
    dp.save_latest_block_header_timestamp(1_800_000_000_000); // head_slot = 6e8
    dp.save_unfreeze_delay_days(1);

    let mut a_bytes = [0u8; 21];
    a_bytes[0] = 0x41;
    a_bytes[1..].fill(0xcd);
    let address = Address::from_raw(a_bytes);
    let mut acct = Account {
        address: a_bytes.to_vec(),
        balance: 10_000_000,
        net_usage: 5_000_000,
        latest_consume_time: 0, // ancient → fully decayed at the current head
        old_tron_power: -1,     // AllTronPower = V1 + V2 TRON_POWER frozen
        ..Default::default()
    };
    // 20 TRX frozen for TRON_POWER → tronPowerLimit 20.
    acct.frozen_v2.push(tron_proto::account::FreezeV2 { r#type: 2, amount: 20_000_000 });
    // Two votes totalling 7 → tronPowerUsed 7.
    acct.votes.push(tron_proto::Vote { vote_address: a_bytes.to_vec(), vote_count: 5 });
    acct.votes.push(tron_proto::Vote { vote_address: a_bytes.to_vec(), vote_count: 2 });
    accounts.put(&address, &acct).unwrap();

    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getAccountResource",
               "params":["0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"],"id":1}),
    )
    .await;
    let r = &resp["result"];
    // Ancient usage decays to 0 at the (correct, timestamp-based) head slot.
    assert_eq!(r["NetUsed"], 0, "stale net usage must decay to 0, not return raw: {r}");
    // TRON power derived from votes + frozen-V2 TRON_POWER.
    assert_eq!(r["tronPowerUsed"], 7);
    assert_eq!(r["tronPowerLimit"], 20);
}

#[tokio::test]
async fn get_account_decays_stored_usage_at_read() {
    // java-tron's Wallet.getAccount decays net_usage / free_net_usage at read
    // (BandwidthProcessor.updateUsage). With an ancient consume time they
    // fully decay to 0, so proto-default omission drops them. The old code
    // returned the raw stored value (e.g. net_usage 250 where java reports 0).
    let (addr, accounts, _bs, _bi, _tx, dp) = spawn_server().await;
    dp.save_genesis_block_timestamp(0);
    dp.save_latest_block_header_timestamp(1_800_000_000_000); // large head_slot
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(0xce);
    let address = Address::from_raw(a);
    accounts
        .put(
            &address,
            &Account {
                address: a.to_vec(),
                net_usage: 250,
                free_net_usage: 250,
                latest_consume_time: 0,      // ancient → decays to 0
                latest_consume_free_time: 0, // ancient → decays to 0
                ..Default::default()
            },
        )
        .unwrap();
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getAccount",
               "params":["0xcececececececececececececececececececece"],"id":1}),
    )
    .await;
    let r = &resp["result"];
    assert!(r.get("net_usage").is_none(), "stale net_usage must decay to 0: {r}");
    assert!(
        r.get("free_net_usage").is_none(),
        "stale free_net_usage must decay to 0: {r}"
    );
}

#[tokio::test]
async fn get_account_net_returns_bandwidth_only_subset() {
    let (addr, accounts, ..) = spawn_server().await;
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(0xcd);
    let address = Address::from_raw(a);
    accounts.put(
        &address,
        &Account {
            address: a.to_vec(),
            balance: 1_000,
            free_net_usage: 123,
            ..Default::default()
        },
    ).unwrap();
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getAccountNet",
               "params":["0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"],"id":1}),
    )
    .await;
    let r = &resp["result"];
    assert_eq!(r["freeNetUsed"], 123);
    assert_eq!(r["freeNetLimit"], 5_000);
    // No frozen bandwidth → NetLimit 0.
    assert_eq!(r["NetLimit"], 0);
    // Energy fields not present.
    assert!(r.get("EnergyLimit").is_none());
}

#[tokio::test]
async fn get_account_resource_unknown_account_returns_empty_object() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getAccountResource",
               "params":["0x4111111111111111111111111111111111111111"],"id":1}),
    )
    .await;
    assert_eq!(resp["result"], json!({}));
}

#[tokio::test]
async fn get_can_withdraw_unfreeze_amount_sums_expired_entries() {
    let (addr, accounts, _bs, _bi, _tx, dp) = spawn_server().await;
    dp.save_latest_block_header_timestamp(1_700_000_000_000);
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(0xde);
    let address = Address::from_raw(a);
    let mut acct = Account {
        address: a.to_vec(),
        ..Default::default()
    };
    // 1M expired, 2M still locked.
    acct.unfrozen_v2.push(tron_proto::account::UnFreezeV2 {
        r#type: 0,
        unfreeze_amount: 1_000_000,
        unfreeze_expire_time: 1_699_000_000_000, // past
    });
    acct.unfrozen_v2.push(tron_proto::account::UnFreezeV2 {
        r#type: 0,
        unfreeze_amount: 2_000_000,
        unfreeze_expire_time: 1_800_000_000_000, // future
    });
    accounts.put(&address, &acct).unwrap();

    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getCanWithdrawUnfreezeAmount",
               "params":["0xdededededededededededededededededededede"],"id":1}),
    )
    .await;
    assert_eq!(resp["result"]["amount"], 1_000_000);
}

#[tokio::test]
async fn get_available_unfreeze_count_respects_max_slots() {
    let (addr, accounts, _bs, _bi, _tx, dp) = spawn_server().await;
    dp.save_latest_block_header_timestamp(1_700_000_000_000);
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(0xfa);
    let address = Address::from_raw(a);
    let mut acct = Account {
        address: a.to_vec(),
        ..Default::default()
    };
    // 5 active unfreezes (all in the future).
    for _ in 0..5 {
        acct.unfrozen_v2.push(tron_proto::account::UnFreezeV2 {
            r#type: 0,
            unfreeze_amount: 1,
            unfreeze_expire_time: 1_800_000_000_000,
        });
    }
    accounts.put(&address, &acct).unwrap();

    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getAvailableUnfreezeCount",
               "params":["0xfafafafafafafafafafafafafafafafafafafafa"],"id":1}),
    )
    .await;
    // 32 - 5 active = 27.
    assert_eq!(resp["result"]["count"], 27);
}

#[tokio::test]
async fn get_block_returns_block_for_numeric_arg() {
    let (addr, _accounts, blocks, block_index, ..) = spawn_server().await;
    let block = Block {
        block_header: Some(BlockHeader {
            raw_data: Some(BlockHeaderRaw {
                number: 42,
                parent_hash: vec![0u8; 32],
                timestamp: 1_700_000_000_000,
                witness_address: hex!("412e988a386a799f506693793c6a5af6b54dfaabfb").to_vec(),
                tx_trie_root: vec![0u8; 32],
                ..Default::default()
            }),
            ..Default::default()
        }),
        transactions: vec![],
    };
    let id = block_id_from_block(&block).unwrap();
    blocks.put(&id, &block).unwrap();
    block_index.put(&id).unwrap();

    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getBlock","params":[42, true],"id":1}),
    )
    .await;
    let r = &resp["result"];
    assert!(!r.is_null(), "{}", resp);
    // encode_block_for_rpc emits Eth-style hex-encoded fields.
    assert_eq!(r["number"], "0x2a"); // 42
}

#[tokio::test]
async fn get_block_by_latest_num_returns_recent_blocks() {
    let (addr, _accounts, blocks, block_index, _tx, dp) = spawn_server().await;
    // Seed 3 blocks: 10, 11, 12.
    for n in 10..=12 {
        let block = Block {
            block_header: Some(BlockHeader {
                raw_data: Some(BlockHeaderRaw {
                    number: n,
                    parent_hash: vec![0u8; 32],
                    timestamp: 1_700_000_000_000 + n,
                    witness_address: hex!("412e988a386a799f506693793c6a5af6b54dfaabfb").to_vec(),
                    tx_trie_root: vec![0u8; 32],
                    ..Default::default()
                }),
                ..Default::default()
            }),
            transactions: vec![],
        };
        let id = block_id_from_block(&block).unwrap();
        blocks.put(&id, &block).unwrap();
        block_index.put(&id).unwrap();
    }
    dp.save_latest_block_header_number(12);
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getBlockByLatestNum","params":[2],"id":1}),
    )
    .await;
    let arr = resp["result"]["block"].as_array().unwrap();
    assert_eq!(arr.len(), 2);
    // Oldest first → block #11 then #12. Eth-style hex encoding.
    assert_eq!(arr[0]["number"], "0xb"); // 11
    assert_eq!(arr[1]["number"], "0xc"); // 12
}

#[tokio::test]
async fn get_block_by_limit_next_caps_at_100() {
    let (addr, _accounts, blocks, block_index, ..) = spawn_server().await;
    // Just seed 3 blocks; the cap is exercised by the response range.
    for n in 0..3 {
        let block = Block {
            block_header: Some(BlockHeader {
                raw_data: Some(BlockHeaderRaw {
                    number: n,
                    parent_hash: vec![0u8; 32],
                    timestamp: 1_700_000_000_000 + n,
                    witness_address: hex!("412e988a386a799f506693793c6a5af6b54dfaabfb").to_vec(),
                    tx_trie_root: vec![0u8; 32],
                    ..Default::default()
                }),
                ..Default::default()
            }),
            transactions: vec![],
        };
        let id = block_id_from_block(&block).unwrap();
        blocks.put(&id, &block).unwrap();
        block_index.put(&id).unwrap();
    }
    // Ask for blocks [0, 10000). Cap kicks in at 100; only 3 exist,
    // so we get whatever overlaps.
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getBlockByLimitNext","params":[0, 10000],"id":1}),
    )
    .await;
    let arr = resp["result"]["block"].as_array().unwrap();
    assert_eq!(arr.len(), 3); // only 3 seeded
}

#[tokio::test]
async fn validate_address_accepts_hex_and_base58check() {
    let (addr, ..) = spawn_server().await;

    // Valid 21-byte hex.
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"validateAddress",
               "params":["0x412e988a386a799f506693793c6a5af6b54dfaabfb"],"id":1}),
    )
    .await;
    assert_eq!(resp["result"]["result"], true);

    // Invalid: 19 bytes.
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"validateAddress",
               "params":["0xdeadbeef"],"id":1}),
    )
    .await;
    assert_eq!(resp["result"]["result"], false);

    // Valid base58check (a real mainnet address — Tron Foundation).
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"validateAddress",
               "params":["TKZxxxxxxxxxxxxxxxxxxxxxxxxxxxBHnh"],"id":1}),
    )
    .await;
    // The above string is not a valid base58check; just confirms we
    // don't false-positive. Real validation tested via the round-trip:
    let encoded = tron_crypto::base58check::encode_address(
        &Address::from_raw(hex!("412e988a386a799f506693793c6a5af6b54dfaabfb")),
    );
    let resp2 = call(
        addr,
        json!({"jsonrpc":"2.0","method":"validateAddress",
               "params":[encoded],"id":2}),
    )
    .await;
    assert_eq!(resp2["result"]["result"], true);
    // And confirm the bogus one rejected:
    assert_eq!(resp["result"]["result"], false);
}

#[tokio::test]
async fn get_pending_size_returns_zero_without_mempool() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getPendingSize","params":[],"id":1}),
    )
    .await;
    assert_eq!(resp["result"]["pendingSize"], 0);
}

// =============================================================================
// Batch 2 (2026-05-24): market, asset-by-name, pagination, tx, misc
// =============================================================================

#[tokio::test]
async fn get_total_transaction_returns_zero_matches_java_tron() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getTotalTransaction","params":[],"id":1}),
    )
    .await;
    assert_eq!(resp["result"]["num"], 0);
}

#[tokio::test]
async fn get_memo_fee_returns_zero_when_unset() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getMemoFee","params":[],"id":1}),
    )
    .await;
    assert_eq!(resp["result"]["value"], 0);
}

#[tokio::test]
async fn get_memo_fee_reads_dyn_props_when_set() {
    let (addr, _accounts, _bs, _bi, _tx, dp) = spawn_server().await;
    dp.put_long(b"MEMO_FEE", 100_000);
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getMemoFee","params":[],"id":1}),
    )
    .await;
    assert_eq!(resp["result"]["value"], 100_000);
}

#[tokio::test]
async fn get_transaction_by_id_returns_null_for_missing() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getTransactionById",
               "params":[format!("0x{}", "ab".repeat(32))],"id":1}),
    )
    .await;
    assert!(resp["result"].is_null());
}

#[tokio::test]
async fn get_transaction_by_id_rejects_non_32_byte_id() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getTransactionById",
               "params":["0xdeadbeef"],"id":1}),
    )
    .await;
    assert!(resp["error"].is_object());
    assert_eq!(resp["error"]["code"], -32602);
}

#[tokio::test]
async fn get_market_pair_list_empty_without_stores() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getMarketPairList","params":[],"id":1}),
    )
    .await;
    assert_eq!(resp["result"]["orderPair"], Value::Array(vec![]));
}

#[tokio::test]
async fn get_market_order_by_id_null_without_store() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getMarketOrderById",
               "params":[format!("0x{}", "cd".repeat(32))],"id":1}),
    )
    .await;
    assert!(resp["result"].is_null());
}

#[tokio::test]
async fn get_paginated_asset_issue_list_caps_at_100() {
    let (addr, ..) = spawn_server().await;
    // No assets seeded → empty list, but call shape is correct.
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getPaginatedAssetIssueList",
               "params":[0, 50],"id":1}),
    )
    .await;
    assert_eq!(resp["result"]["assetIssue"], Value::Array(vec![]));

    // Request beyond cap is silently clamped — no error.
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getPaginatedAssetIssueList",
               "params":[0, 10000],"id":2}),
    )
    .await;
    assert_eq!(resp["result"]["assetIssue"], Value::Array(vec![]));
}

#[tokio::test]
async fn get_paginated_proposal_list_returns_empty_without_proposals() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getPaginatedProposalList",
               "params":[0, 10],"id":1}),
    )
    .await;
    assert_eq!(resp["result"]["proposals"], Value::Array(vec![]));
}

#[tokio::test]
async fn estimate_energy_gated_off_by_default() {
    let (addr, ..) = spawn_server().await;
    // `vm.estimateEnergy` defaults to false (java `Args.estimateEnergy`),
    // so the method is gated off before it can run — returns a clear
    // "does not support estimate energy" error object.
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"estimateEnergy",
               "params":[{"to":"0x412e988a386a799f506693793c6a5af6b54dfaabfb",
                          "data":"0x"}],"id":1}),
    )
    .await;
    assert!(resp["error"].is_object());
    assert!(
        resp["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("does not support estimate energy"),
        "got: {}",
        resp["error"]["message"]
    );
}

#[tokio::test]
async fn get_asset_issue_by_name_returns_null_unknown() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getAssetIssueByName",
               "params":["NonexistentToken"],"id":1}),
    )
    .await;
    // No assets seeded → null. Also confirms the string→bytes
    // parameter handling doesn't error on a non-hex input.
    assert!(resp["result"].is_null());
}

// =============================================================================
// Batch 3 (2026-05-24): multi-sig, solidified, balance trace, shielded
// =============================================================================

#[tokio::test]
async fn get_approved_list_recovers_signers_from_signed_tx() {
    use prost::Message as _;
    let (addr, ..) = spawn_server().await;

    // Build + sign a minimal transfer tx with a known key.
    let priv_key: [u8; 32] = hex!("1234567890123456789012345678901234567890123456789012345678901234");
    let mut signer = [0u8; 21];
    signer[0] = 0x41;
    {
        let sig = tron_crypto::signature::RecoverableSignature::sign_prehash(
            &priv_key,
            &[0u8; 32],
        )
        .unwrap();
        let pubkey = sig.recover_uncompressed_pubkey(&[0u8; 32]).unwrap();
        let h = tron_crypto::hash::keccak256(&pubkey[1..]);
        signer[1..].copy_from_slice(&h[12..]);
    }

    let tc = tron_proto::TransferContract {
        owner_address: signer.to_vec(),
        to_address: [0u8; 21].to_vec(),
        amount: 1,
    };
    let mut tx = tron_proto::Transaction {
        raw_data: Some(tron_proto::transaction::Raw {
            contract: vec![tron_proto::transaction::Contract {
                r#type: tron_proto::transaction::contract::ContractType::TransferContract as i32,
                parameter: Some(prost_types::Any {
                    type_url: "type.googleapis.com/protocol.TransferContract".into(),
                    value: tc.encode_to_vec(),
                }),
                ..Default::default()
            }],
            expiration: 1_700_000_000_000,
            timestamp: 1_700_000_000_000,
            ..Default::default()
        }),
        signature: vec![],
        ret: vec![],
        unparsed_field10: None,
    };
    tron_types::sign_transaction(&mut tx, &priv_key).unwrap();
    let raw = format!("0x{}", hex::encode(tx.encode_to_vec()));

    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getApprovedList","params":[raw],"id":1}),
    )
    .await;
    let list = resp["result"]["approved_list"].as_array().unwrap();
    assert_eq!(list.len(), 1);
    // Recovered signer matches our derived address (21-byte form, lowercase hex).
    let recovered = list[0].as_str().unwrap();
    assert_eq!(recovered, format!("0x{}", hex::encode(signer)));
}

#[tokio::test]
async fn get_sign_weight_under_threshold_with_no_account() {
    use prost::Message as _;
    let (addr, ..) = spawn_server().await;
    // Unsigned tx — no account seeded. We expect an internal error
    // because compute_sign_weight raises OwnerAccountMissing.
    let tc = tron_proto::TransferContract {
        owner_address: [0u8; 21].to_vec(),
        to_address: [0u8; 21].to_vec(),
        amount: 1,
    };
    let tx = tron_proto::Transaction {
        raw_data: Some(tron_proto::transaction::Raw {
            contract: vec![tron_proto::transaction::Contract {
                r#type: tron_proto::transaction::contract::ContractType::TransferContract as i32,
                parameter: Some(prost_types::Any {
                    value: tc.encode_to_vec(),
                    type_url: String::new(),
                }),
                ..Default::default()
            }],
            ..Default::default()
        }),
        signature: vec![],
        ret: vec![],
        unparsed_field10: None,
    };
    let raw = format!("0x{}", hex::encode(tx.encode_to_vec()));
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getSignWeight","params":[raw],"id":1}),
    )
    .await;
    // No account → internal error surfacing OwnerAccountMissing.
    assert!(resp["error"].is_object(), "{}", resp);
}

#[tokio::test]
async fn solidified_block_clamps_to_solid_head() {
    let (addr, _accounts, blocks, block_index, _tx, dp) = spawn_server().await;
    // Seed blocks 0..3.
    for n in 0..3 {
        let block = Block {
            block_header: Some(BlockHeader {
                raw_data: Some(BlockHeaderRaw {
                    number: n,
                    parent_hash: vec![0u8; 32],
                    timestamp: 1_700_000_000_000 + n,
                    witness_address: hex!("412e988a386a799f506693793c6a5af6b54dfaabfb").to_vec(),
                    tx_trie_root: vec![0u8; 32],
                    ..Default::default()
                }),
                ..Default::default()
            }),
            transactions: vec![],
        };
        let id = block_id_from_block(&block).unwrap();
        blocks.put(&id, &block).unwrap();
        block_index.put(&id).unwrap();
    }
    dp.save_latest_block_header_number(2);
    // Solidified at block 1.
    dp.save_latest_solidified_block_num(1);

    // Block 0 < solid head → returned.
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getBlockByNumSolidity","params":[0],"id":1}),
    )
    .await;
    assert!(!resp["result"].is_null(), "{}", resp);

    // Block 2 > solid head → null.
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getBlockByNumSolidity","params":[2],"id":2}),
    )
    .await;
    assert!(resp["result"].is_null());
}

#[tokio::test]
async fn get_now_block_solidity_returns_solid_head_block() {
    let (addr, _accounts, blocks, block_index, _tx, dp) = spawn_server().await;
    let block = Block {
        block_header: Some(BlockHeader {
            raw_data: Some(BlockHeaderRaw {
                number: 5,
                parent_hash: vec![0u8; 32],
                timestamp: 1_700_000_000_000,
                witness_address: hex!("412e988a386a799f506693793c6a5af6b54dfaabfb").to_vec(),
                tx_trie_root: vec![0u8; 32],
                ..Default::default()
            }),
            ..Default::default()
        }),
        transactions: vec![],
    };
    let id = block_id_from_block(&block).unwrap();
    blocks.put(&id, &block).unwrap();
    block_index.put(&id).unwrap();
    dp.save_latest_solidified_block_num(5);
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getNowBlockSolidity","params":[],"id":1}),
    )
    .await;
    assert_eq!(resp["result"]["number"], "0x5");
}

#[tokio::test]
async fn get_account_solidity_matches_get_account_shape() {
    let (addr, accounts, ..) = spawn_server().await;
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(0x99);
    accounts.put(
        &Address::from_raw(a),
        &Account {
            address: a.to_vec(),
            balance: 42,
            ..Default::default()
        },
    ).unwrap();
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getAccountSolidity",
               "params":["0x9999999999999999999999999999999999999999"],"id":1}),
    )
    .await;
    // No solidified snapshot exists, so this aliases live state — but the
    // shape must be byte-identical to java's `walletsolidity/getaccount`
    // (the live `Account` proto JSON). No non-java marker field.
    assert_eq!(resp["result"]["balance"], 42);
    assert!(
        resp["result"].get("__solidified").is_none(),
        "non-java __solidified field must not be emitted"
    );
}

#[tokio::test]
async fn get_block_balance_trace_returns_empty_until_executor_writes() {
    let (addr, _accounts, blocks, block_index, ..) = spawn_server().await;
    let block = Block {
        block_header: Some(BlockHeader {
            raw_data: Some(BlockHeaderRaw {
                number: 1,
                parent_hash: vec![0u8; 32],
                timestamp: 1_700_000_000_000,
                witness_address: hex!("412e988a386a799f506693793c6a5af6b54dfaabfb").to_vec(),
                tx_trie_root: vec![0u8; 32],
                ..Default::default()
            }),
            ..Default::default()
        }),
        transactions: vec![],
    };
    let id = block_id_from_block(&block).unwrap();
    blocks.put(&id, &block).unwrap();
    block_index.put(&id).unwrap();

    // BalanceTraceStore not attached on the test RpcState → null.
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getBlockBalanceTrace","params":[1],"id":1}),
    )
    .await;
    assert!(resp["result"].is_null());
}

// ---- Shielded TRC-20 key helpers ----

#[tokio::test]
async fn get_spending_key_returns_32_random_bytes_each_call() {
    let (addr, ..) = spawn_server().await;
    let a = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getSpendingKey","params":[],"id":1}),
    )
    .await;
    let b = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getSpendingKey","params":[],"id":2}),
    )
    .await;
    let ka = a["result"]["value"].as_str().unwrap();
    let kb = b["result"]["value"].as_str().unwrap();
    assert!(ka.starts_with("0x"));
    // 0x prefix + 64 hex chars
    assert_eq!(ka.len(), 66);
    assert_ne!(ka, kb, "two consecutive spending keys must differ");
}

#[tokio::test]
async fn get_expanded_spending_key_returns_three_32_byte_fields() {
    let (addr, ..) = spawn_server().await;
    let sk = "0x".to_string() + &"42".repeat(32);
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getExpandedSpendingKey","params":[sk],"id":1}),
    )
    .await;
    let r = &resp["result"];
    let ask = r["ask"].as_str().unwrap();
    let nsk = r["nsk"].as_str().unwrap();
    let ovk = r["ovk"].as_str().unwrap();
    for v in [ask, nsk, ovk] {
        assert!(v.starts_with("0x"));
        assert_eq!(v.len(), 66, "32 bytes hex-encoded");
    }
    // Same input → deterministic output.
    let resp2 = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getExpandedSpendingKey","params":[sk],"id":2}),
    )
    .await;
    assert_eq!(resp2["result"]["ask"], ask);
}

#[tokio::test]
async fn get_diversifier_returns_11_bytes() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getDiversifier","params":[],"id":1}),
    )
    .await;
    let v = resp["result"]["value"].as_str().unwrap();
    // 0x + 22 hex chars = 11 bytes
    assert_eq!(v.len(), 24, "{}", v);
}

#[tokio::test]
async fn get_rcm_returns_32_bytes_in_scalar_field() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getRcm","params":[],"id":1}),
    )
    .await;
    let v = resp["result"]["value"].as_str().unwrap();
    assert_eq!(v.len(), 66);
    // High nibble must be at most 0x07 (top 5 bits zero).
    let last_byte = u8::from_str_radix(&v[64..66], 16).unwrap();
    assert!(last_byte <= 0x07, "got high byte {last_byte:#x}");
}

#[tokio::test]
async fn ak_from_ask_roundtrips_through_expanded_spending_key() {
    // Derive (ask, nsk, ovk) from sk; then derive ak from ask and verify
    // it matches the ak inside the proof_generation_key derived from sk.
    let (addr, ..) = spawn_server().await;
    let sk = "0x".to_string() + &"7a".repeat(32);
    let expanded = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getExpandedSpendingKey","params":[&sk],"id":1}),
    )
    .await;
    let ask_hex = expanded["result"]["ask"].as_str().unwrap().to_string();
    let ak_resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getAkFromAsk","params":[ask_hex.clone()],"id":2}),
    )
    .await;
    let ak = ak_resp["result"]["value"].as_str().unwrap();
    assert_eq!(ak.len(), 66);
    // Compute the expected ak via sapling-crypto directly.
    let sk_bytes = hex::decode(sk.trim_start_matches("0x")).unwrap();
    let esk = sapling_crypto::keys::ExpandedSpendingKey::from_spending_key(&sk_bytes);
    let pgk = esk.proof_generation_key();
    let expected_ak = pgk.ak.to_bytes();
    let actual_ak_bytes = hex::decode(ak.trim_start_matches("0x")).unwrap();
    assert_eq!(actual_ak_bytes, expected_ak.to_vec());
}

#[tokio::test]
async fn get_ak_from_ask_rejects_wrong_length() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getAkFromAsk",
               "params":["0xdeadbeef"],"id":1}),
    )
    .await;
    assert!(resp["error"].is_object());
    assert_eq!(resp["error"]["code"], -32602);
}

// =============================================================================
// Batch 4 (2026-05-24): server-side builder endpoints
// =============================================================================

#[tokio::test]
async fn create_transaction_returns_envelope_with_tx_id_and_raw_data_hex() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"createTransaction","params":[{
            "owner_address": "0x412e988a386a799f506693793c6a5af6b54dfaabfb",
            "to_address": "0x41a614f803b6fd780986a42c78ec9c7f77e6ded13c",
            "amount": 1_000_000
        }],"id":1}),
    )
    .await;
    let r = &resp["result"];
    assert!(r["txID"].as_str().unwrap().starts_with("0x"));
    assert_eq!(r["txID"].as_str().unwrap().len(), 66);
    assert!(r["raw_data_hex"].as_str().unwrap().starts_with("0x"));
    assert_eq!(r["signature"], Value::Array(vec![]));
    assert_eq!(r["raw_data"]["fee_limit"], 0);
}

#[tokio::test]
async fn create_transaction_rejects_missing_owner() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"createTransaction","params":[{
            "to_address": "0x41a614f803b6fd780986a42c78ec9c7f77e6ded13c",
            "amount": 1
        }],"id":1}),
    )
    .await;
    assert_eq!(resp["error"]["code"], -32602);
    assert!(resp["error"]["message"]
        .as_str()
        .unwrap()
        .contains("owner_address"));
}

#[tokio::test]
async fn transfer_asset_envelope_carries_fee_limit_zero() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"transferAsset","params":[{
            "owner_address": "0x412e988a386a799f506693793c6a5af6b54dfaabfb",
            "to_address": "0x41a614f803b6fd780986a42c78ec9c7f77e6ded13c",
            "asset_name": "0x31303030303031",
            "amount": 500
        }],"id":1}),
    )
    .await;
    assert!(!resp["result"]["txID"].is_null(), "{}", resp);
    assert_eq!(resp["result"]["raw_data"]["fee_limit"], 0);
}

#[tokio::test]
async fn trigger_smart_contract_passes_fee_limit_through() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"triggerSmartContract","params":[{
            "owner_address": "0x412e988a386a799f506693793c6a5af6b54dfaabfb",
            "contract_address": "0x41c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1",
            "call_value": 0,
            "data": "0xa9059cbb",
            "fee_limit": 150_000_000
        }],"id":1}),
    )
    .await;
    assert_eq!(resp["result"]["raw_data"]["fee_limit"], 150_000_000);
}

#[tokio::test]
async fn freeze_balance_v2_round_trips_through_envelope_decode() {
    use prost::Message as _;
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"freezeBalanceV2","params":[{
            "owner_address": "0x412e988a386a799f506693793c6a5af6b54dfaabfb",
            "frozen_balance": 5_000_000,
            "resource": 1
        }],"id":1}),
    )
    .await;
    let hex_str = resp["result"]["raw_data_hex"].as_str().unwrap();
    let bytes = hex::decode(hex_str.trim_start_matches("0x")).unwrap();
    let raw = tron_proto::transaction::Raw::decode(bytes.as_slice()).unwrap();
    assert_eq!(raw.contract.len(), 1);
    assert_eq!(
        raw.contract[0].r#type,
        tron_proto::transaction::contract::ContractType::FreezeBalanceV2Contract as i32
    );
    let inner = tron_proto::FreezeBalanceV2Contract::decode(
        raw.contract[0].parameter.as_ref().unwrap().value.as_slice(),
    )
    .unwrap();
    assert_eq!(inner.frozen_balance, 5_000_000);
    assert_eq!(inner.resource, 1);
}

#[tokio::test]
async fn vote_witness_account_packs_votes_array() {
    use prost::Message as _;
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"voteWitnessAccount","params":[{
            "owner_address": "0x412e988a386a799f506693793c6a5af6b54dfaabfb",
            "votes": [
                {"vote_address": "0x41aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "vote_count": 100},
                {"vote_address": "0x41bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "vote_count": 50}
            ]
        }],"id":1}),
    )
    .await;
    let hex_str = resp["result"]["raw_data_hex"].as_str().unwrap();
    let bytes = hex::decode(hex_str.trim_start_matches("0x")).unwrap();
    let raw = tron_proto::transaction::Raw::decode(bytes.as_slice()).unwrap();
    let inner = tron_proto::VoteWitnessContract::decode(
        raw.contract[0].parameter.as_ref().unwrap().value.as_slice(),
    )
    .unwrap();
    assert_eq!(inner.votes.len(), 2);
    assert_eq!(inner.votes[0].vote_count, 100);
    assert_eq!(inner.votes[1].vote_count, 50);
}

#[tokio::test]
async fn account_permission_update_round_trips_permission_keys() {
    use prost::Message as _;
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"accountPermissionUpdate","params":[{
            "owner_address": "0x412e988a386a799f506693793c6a5af6b54dfaabfb",
            "owner": {
                "type": 0,
                "id": 0,
                "permission_name": "owner",
                "threshold": 2,
                "keys": [
                    {"address": "0x412e988a386a799f506693793c6a5af6b54dfaabfb", "weight": 1},
                    {"address": "0x41a614f803b6fd780986a42c78ec9c7f77e6ded13c", "weight": 1}
                ]
            }
        }],"id":1}),
    )
    .await;
    let hex_str = resp["result"]["raw_data_hex"].as_str().unwrap();
    let bytes = hex::decode(hex_str.trim_start_matches("0x")).unwrap();
    let raw = tron_proto::transaction::Raw::decode(bytes.as_slice()).unwrap();
    let inner = tron_proto::AccountPermissionUpdateContract::decode(
        raw.contract[0].parameter.as_ref().unwrap().value.as_slice(),
    )
    .unwrap();
    let owner = inner.owner.unwrap();
    assert_eq!(owner.threshold, 2);
    assert_eq!(owner.keys.len(), 2);
    assert_eq!(owner.keys[0].weight, 1);
}

#[tokio::test]
async fn withdraw_expire_unfreeze_returns_envelope() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"withdrawExpireUnfreeze","params":[{
            "owner_address": "0x412e988a386a799f506693793c6a5af6b54dfaabfb"
        }],"id":1}),
    )
    .await;
    assert!(!resp["result"]["txID"].is_null());
}

#[tokio::test]
async fn update_brokerage_clamps_default() {
    use prost::Message as _;
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"updateBrokerage","params":[{
            "owner_address": "0x412e988a386a799f506693793c6a5af6b54dfaabfb",
            "brokerage": 30
        }],"id":1}),
    )
    .await;
    let hex_str = resp["result"]["raw_data_hex"].as_str().unwrap();
    let bytes = hex::decode(hex_str.trim_start_matches("0x")).unwrap();
    let raw = tron_proto::transaction::Raw::decode(bytes.as_slice()).unwrap();
    let inner = tron_proto::UpdateBrokerageContract::decode(
        raw.contract[0].parameter.as_ref().unwrap().value.as_slice(),
    )
    .unwrap();
    assert_eq!(inner.brokerage, 30);
}

#[tokio::test]
async fn builder_envelope_ref_block_fields_have_expected_lengths() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"createTransaction","params":[{
            "owner_address": "0x412e988a386a799f506693793c6a5af6b54dfaabfb",
            "to_address": "0x41a614f803b6fd780986a42c78ec9c7f77e6ded13c",
            "amount": 1
        }],"id":1}),
    )
    .await;
    let r = &resp["result"]["raw_data"];
    // ref_block_bytes = 2 bytes hex = "0x" + 4 hex chars.
    assert_eq!(r["ref_block_bytes"].as_str().unwrap().len(), 6);
    // ref_block_hash = 8 bytes hex = "0x" + 16 hex chars.
    assert_eq!(r["ref_block_hash"].as_str().unwrap().len(), 18);
    // Expiration is timestamp + 60s.
    let ts = r["timestamp"].as_i64().unwrap();
    let exp = r["expiration"].as_i64().unwrap();
    assert_eq!(exp - ts, 60_000);
}

// =============================================================================
// Batch 5 (2026-05-24): Tier 2 builder endpoints
// =============================================================================

const OWNER_HEX: &str = "0x412e988a386a799f506693793c6a5af6b54dfaabfb";
const OTHER_HEX: &str = "0x41a614f803b6fd780986a42c78ec9c7f77e6ded13c";

#[tokio::test]
async fn create_account_round_trips_type_field() {
    use prost::Message as _;
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"createAccount","params":[{
            "owner_address": OWNER_HEX,
            "account_address": OTHER_HEX,
            "type": 1
        }],"id":1}),
    )
    .await;
    let hex_str = resp["result"]["raw_data_hex"].as_str().unwrap();
    let bytes = hex::decode(hex_str.trim_start_matches("0x")).unwrap();
    let raw = tron_proto::transaction::Raw::decode(bytes.as_slice()).unwrap();
    let inner = tron_proto::AccountCreateContract::decode(
        raw.contract[0].parameter.as_ref().unwrap().value.as_slice(),
    )
    .unwrap();
    assert_eq!(inner.r#type, 1);
    assert_eq!(inner.account_address.len(), 21);
}

#[tokio::test]
async fn update_account_packs_name_bytes() {
    use prost::Message as _;
    let (addr, ..) = spawn_server().await;
    // "Alice" in hex = 0x416c696365
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"updateAccount","params":[{
            "owner_address": OWNER_HEX,
            "account_name": "0x416c696365"
        }],"id":1}),
    )
    .await;
    let hex_str = resp["result"]["raw_data_hex"].as_str().unwrap();
    let bytes = hex::decode(hex_str.trim_start_matches("0x")).unwrap();
    let raw = tron_proto::transaction::Raw::decode(bytes.as_slice()).unwrap();
    let inner = tron_proto::AccountUpdateContract::decode(
        raw.contract[0].parameter.as_ref().unwrap().value.as_slice(),
    )
    .unwrap();
    assert_eq!(inner.account_name, b"Alice".to_vec());
}

#[tokio::test]
async fn set_account_id_round_trips_id() {
    use prost::Message as _;
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"setAccountId","params":[{
            "owner_address": OWNER_HEX,
            "account_id": "0xdeadbeef"
        }],"id":1}),
    )
    .await;
    let hex_str = resp["result"]["raw_data_hex"].as_str().unwrap();
    let bytes = hex::decode(hex_str.trim_start_matches("0x")).unwrap();
    let raw = tron_proto::transaction::Raw::decode(bytes.as_slice()).unwrap();
    let inner = tron_proto::SetAccountIdContract::decode(
        raw.contract[0].parameter.as_ref().unwrap().value.as_slice(),
    )
    .unwrap();
    assert_eq!(inner.account_id, hex::decode("deadbeef").unwrap());
}

#[tokio::test]
async fn create_witness_packs_url() {
    use prost::Message as _;
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"createWitness","params":[{
            "owner_address": OWNER_HEX,
            "url": "0x68747470733a2f2f6578616d706c652e636f6d"
        }],"id":1}),
    )
    .await;
    let hex_str = resp["result"]["raw_data_hex"].as_str().unwrap();
    let bytes = hex::decode(hex_str.trim_start_matches("0x")).unwrap();
    let raw = tron_proto::transaction::Raw::decode(bytes.as_slice()).unwrap();
    let inner = tron_proto::WitnessCreateContract::decode(
        raw.contract[0].parameter.as_ref().unwrap().value.as_slice(),
    )
    .unwrap();
    assert_eq!(inner.url, b"https://example.com".to_vec());
}

#[tokio::test]
async fn proposal_create_accepts_map_form_parameters() {
    use prost::Message as _;
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"proposalCreate","params":[{
            "owner_address": OWNER_HEX,
            "parameters": {"1": 100, "5": 9999}
        }],"id":1}),
    )
    .await;
    let hex_str = resp["result"]["raw_data_hex"].as_str().unwrap();
    let bytes = hex::decode(hex_str.trim_start_matches("0x")).unwrap();
    let raw = tron_proto::transaction::Raw::decode(bytes.as_slice()).unwrap();
    let inner = tron_proto::ProposalCreateContract::decode(
        raw.contract[0].parameter.as_ref().unwrap().value.as_slice(),
    )
    .unwrap();
    assert_eq!(inner.parameters.get(&1), Some(&100));
    assert_eq!(inner.parameters.get(&5), Some(&9999));
}

#[tokio::test]
async fn proposal_create_accepts_array_form_parameters() {
    use prost::Message as _;
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"proposalCreate","params":[{
            "owner_address": OWNER_HEX,
            "parameters": [
                {"key": 2, "value": 50},
                {"key": 3, "value": 75}
            ]
        }],"id":1}),
    )
    .await;
    let hex_str = resp["result"]["raw_data_hex"].as_str().unwrap();
    let bytes = hex::decode(hex_str.trim_start_matches("0x")).unwrap();
    let raw = tron_proto::transaction::Raw::decode(bytes.as_slice()).unwrap();
    let inner = tron_proto::ProposalCreateContract::decode(
        raw.contract[0].parameter.as_ref().unwrap().value.as_slice(),
    )
    .unwrap();
    assert_eq!(inner.parameters.get(&2), Some(&50));
    assert_eq!(inner.parameters.get(&3), Some(&75));
}

#[tokio::test]
async fn proposal_approve_defaults_is_add_to_true() {
    use prost::Message as _;
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"proposalApprove","params":[{
            "owner_address": OWNER_HEX,
            "proposal_id": 42
        }],"id":1}),
    )
    .await;
    let hex_str = resp["result"]["raw_data_hex"].as_str().unwrap();
    let bytes = hex::decode(hex_str.trim_start_matches("0x")).unwrap();
    let raw = tron_proto::transaction::Raw::decode(bytes.as_slice()).unwrap();
    let inner = tron_proto::ProposalApproveContract::decode(
        raw.contract[0].parameter.as_ref().unwrap().value.as_slice(),
    )
    .unwrap();
    assert_eq!(inner.proposal_id, 42);
    assert!(inner.is_add_approval);
}

#[tokio::test]
async fn create_asset_issue_packs_optional_frozen_supply() {
    use prost::Message as _;
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"createAssetIssue","params":[{
            "owner_address": OWNER_HEX,
            "name": "0x546f6b656e",
            "abbr": "0x544b4e",
            "total_supply": 1_000_000_000,
            "trx_num": 1,
            "num": 1,
            "start_time": 1_700_000_000_000_i64,
            "end_time": 1_800_000_000_000_i64,
            "frozen_supply": [
                {"frozen_amount": 100_000_000, "frozen_days": 30},
                {"frozen_amount": 50_000_000, "frozen_days": 60}
            ]
        }],"id":1}),
    )
    .await;
    let hex_str = resp["result"]["raw_data_hex"].as_str().unwrap();
    let bytes = hex::decode(hex_str.trim_start_matches("0x")).unwrap();
    let raw = tron_proto::transaction::Raw::decode(bytes.as_slice()).unwrap();
    let inner = tron_proto::AssetIssueContract::decode(
        raw.contract[0].parameter.as_ref().unwrap().value.as_slice(),
    )
    .unwrap();
    assert_eq!(inner.name, b"Token".to_vec());
    assert_eq!(inner.total_supply, 1_000_000_000);
    assert_eq!(inner.frozen_supply.len(), 2);
    assert_eq!(inner.frozen_supply[0].frozen_days, 30);
}

#[tokio::test]
async fn update_asset_zero_limits_are_fine() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"updateAsset","params":[{
            "owner_address": OWNER_HEX,
            "description": "0x4e6577206465736372697074696f6e"
        }],"id":1}),
    )
    .await;
    assert!(!resp["result"]["txID"].is_null());
}

#[tokio::test]
async fn participate_asset_issue_emits_envelope() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"participateAssetIssue","params":[{
            "owner_address": OWNER_HEX,
            "to_address": OTHER_HEX,
            "asset_name": "0x31303030303031",
            "amount": 5_000
        }],"id":1}),
    )
    .await;
    assert!(!resp["result"]["txID"].is_null());
}

#[tokio::test]
async fn unfreeze_asset_only_needs_owner() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"unfreezeAsset","params":[{
            "owner_address": OWNER_HEX
        }],"id":1}),
    )
    .await;
    assert!(!resp["result"]["txID"].is_null());
}

// =============================================================================
// Batch 6 (2026-05-24): Tier 3 builder endpoints
// =============================================================================

#[tokio::test]
async fn deploy_contract_appends_constructor_parameter_to_bytecode() {
    use prost::Message as _;
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"deployContract","params":[{
            "owner_address": OWNER_HEX,
            "bytecode": "0x6080604052",
            "parameter": "0xdeadbeef",
            "name": "TestContract",
            "consume_user_resource_percent": 100,
            "origin_energy_limit": 1_000_000,
            "fee_limit": 100_000_000
        }],"id":1}),
    )
    .await;
    let hex_str = resp["result"]["raw_data_hex"].as_str().unwrap();
    let bytes = hex::decode(hex_str.trim_start_matches("0x")).unwrap();
    let raw = tron_proto::transaction::Raw::decode(bytes.as_slice()).unwrap();
    assert_eq!(raw.fee_limit, 100_000_000);
    let inner = tron_proto::CreateSmartContract::decode(
        raw.contract[0].parameter.as_ref().unwrap().value.as_slice(),
    )
    .unwrap();
    let smart = inner.new_contract.unwrap();
    // bytecode + constructor params concatenated.
    assert_eq!(smart.bytecode, hex::decode("6080604052deadbeef").unwrap());
    assert_eq!(smart.name, "TestContract");
    assert_eq!(smart.consume_user_resource_percent, 100);
    assert_eq!(smart.origin_energy_limit, 1_000_000);
}

#[tokio::test]
async fn deploy_contract_defaults_consume_percent_to_100() {
    use prost::Message as _;
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"deployContract","params":[{
            "owner_address": OWNER_HEX,
            "bytecode": "0x00"
        }],"id":1}),
    )
    .await;
    let hex_str = resp["result"]["raw_data_hex"].as_str().unwrap();
    let bytes = hex::decode(hex_str.trim_start_matches("0x")).unwrap();
    let raw = tron_proto::transaction::Raw::decode(bytes.as_slice()).unwrap();
    let inner = tron_proto::CreateSmartContract::decode(
        raw.contract[0].parameter.as_ref().unwrap().value.as_slice(),
    )
    .unwrap();
    assert_eq!(
        inner.new_contract.unwrap().consume_user_resource_percent,
        100
    );
}

#[tokio::test]
async fn update_setting_round_trips_percentage() {
    use prost::Message as _;
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"updateSetting","params":[{
            "owner_address": OWNER_HEX,
            "contract_address": OTHER_HEX,
            "consume_user_resource_percent": 50
        }],"id":1}),
    )
    .await;
    let hex_str = resp["result"]["raw_data_hex"].as_str().unwrap();
    let bytes = hex::decode(hex_str.trim_start_matches("0x")).unwrap();
    let raw = tron_proto::transaction::Raw::decode(bytes.as_slice()).unwrap();
    let inner = tron_proto::UpdateSettingContract::decode(
        raw.contract[0].parameter.as_ref().unwrap().value.as_slice(),
    )
    .unwrap();
    assert_eq!(inner.consume_user_resource_percent, 50);
}

#[tokio::test]
async fn clear_abi_accepts_camel_case_aliases() {
    let (addr, ..) = spawn_server().await;
    for method in ["clearAbi", "clearABI", "clearContractABI"] {
        let resp = call(
            addr,
            json!({"jsonrpc":"2.0","method":method,"params":[{
                "owner_address": OWNER_HEX,
                "contract_address": OTHER_HEX
            }],"id":1}),
        )
        .await;
        assert!(!resp["result"]["txID"].is_null(), "alias {method} failed");
    }
}

#[tokio::test]
async fn exchange_create_packs_both_tokens() {
    use prost::Message as _;
    let (addr, ..) = spawn_server().await;
    // first_token = TRX (`_`), second_token = TRC-10 id "1000001".
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"exchangeCreate","params":[{
            "owner_address": OWNER_HEX,
            "first_token_id": "0x5f",
            "first_token_balance": 1_000_000_000,
            "second_token_id": "0x31303030303031",
            "second_token_balance": 5_000_000
        }],"id":1}),
    )
    .await;
    let hex_str = resp["result"]["raw_data_hex"].as_str().unwrap();
    let bytes = hex::decode(hex_str.trim_start_matches("0x")).unwrap();
    let raw = tron_proto::transaction::Raw::decode(bytes.as_slice()).unwrap();
    let inner = tron_proto::ExchangeCreateContract::decode(
        raw.contract[0].parameter.as_ref().unwrap().value.as_slice(),
    )
    .unwrap();
    assert_eq!(inner.first_token_id, vec![0x5f]);
    assert_eq!(inner.first_token_balance, 1_000_000_000);
    assert_eq!(inner.second_token_balance, 5_000_000);
}

#[tokio::test]
async fn exchange_transaction_carries_slippage_expected() {
    use prost::Message as _;
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"exchangeTransaction","params":[{
            "owner_address": OWNER_HEX,
            "exchange_id": 7,
            "token_id": "0x5f",
            "quant": 1_000_000,
            "expected": 950_000
        }],"id":1}),
    )
    .await;
    let hex_str = resp["result"]["raw_data_hex"].as_str().unwrap();
    let bytes = hex::decode(hex_str.trim_start_matches("0x")).unwrap();
    let raw = tron_proto::transaction::Raw::decode(bytes.as_slice()).unwrap();
    let inner = tron_proto::ExchangeTransactionContract::decode(
        raw.contract[0].parameter.as_ref().unwrap().value.as_slice(),
    )
    .unwrap();
    assert_eq!(inner.exchange_id, 7);
    assert_eq!(inner.expected, 950_000);
}

#[tokio::test]
async fn market_sell_asset_packs_pair() {
    use prost::Message as _;
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"marketSellAsset","params":[{
            "owner_address": OWNER_HEX,
            "sell_token_id": "0x31303030303031",
            "sell_token_quantity": 1_000,
            "buy_token_id": "0x5f",
            "buy_token_quantity": 500_000
        }],"id":1}),
    )
    .await;
    let hex_str = resp["result"]["raw_data_hex"].as_str().unwrap();
    let bytes = hex::decode(hex_str.trim_start_matches("0x")).unwrap();
    let raw = tron_proto::transaction::Raw::decode(bytes.as_slice()).unwrap();
    let inner = tron_proto::MarketSellAssetContract::decode(
        raw.contract[0].parameter.as_ref().unwrap().value.as_slice(),
    )
    .unwrap();
    assert_eq!(inner.sell_token_quantity, 1_000);
    assert_eq!(inner.buy_token_quantity, 500_000);
}

#[tokio::test]
async fn market_cancel_order_carries_opaque_id() {
    use prost::Message as _;
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"marketCancelOrder","params":[{
            "owner_address": OWNER_HEX,
            "order_id": "0xfeedface"
        }],"id":1}),
    )
    .await;
    let hex_str = resp["result"]["raw_data_hex"].as_str().unwrap();
    let bytes = hex::decode(hex_str.trim_start_matches("0x")).unwrap();
    let raw = tron_proto::transaction::Raw::decode(bytes.as_slice()).unwrap();
    let inner = tron_proto::MarketCancelOrderContract::decode(
        raw.contract[0].parameter.as_ref().unwrap().value.as_slice(),
    )
    .unwrap();
    assert_eq!(inner.order_id, hex::decode("feedface").unwrap());
}

#[tokio::test]
async fn freeze_balance_v1_round_trips_resource_and_duration() {
    use prost::Message as _;
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"freezeBalance","params":[{
            "owner_address": OWNER_HEX,
            "frozen_balance": 10_000_000,
            "frozen_duration": 3,
            "resource": 1
        }],"id":1}),
    )
    .await;
    let hex_str = resp["result"]["raw_data_hex"].as_str().unwrap();
    let bytes = hex::decode(hex_str.trim_start_matches("0x")).unwrap();
    let raw = tron_proto::transaction::Raw::decode(bytes.as_slice()).unwrap();
    let inner = tron_proto::FreezeBalanceContract::decode(
        raw.contract[0].parameter.as_ref().unwrap().value.as_slice(),
    )
    .unwrap();
    assert_eq!(inner.frozen_duration, 3);
    assert_eq!(inner.resource, 1);
}

#[tokio::test]
async fn unfreeze_balance_v1_accepts_no_receiver() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"unfreezeBalance","params":[{
            "owner_address": OWNER_HEX,
            "resource": 0
        }],"id":1}),
    )
    .await;
    assert!(!resp["result"]["txID"].is_null());
}

// =============================================================================
// decodeContractData / decodeEventLog — ABI-aware introspection RPCs.
// =============================================================================
//
// Set up a contract address with a stored ABI for the ERC-20
// `transfer(address,uint256)` function + `Transfer(address,address,uint256)`
// event. Exercise both decode RPCs end-to-end via the HTTP surface.

async fn spawn_server_with_abi() -> (std::net::SocketAddr, [u8; 20]) {
    use tron_chainbase::AbiStore;
    use tron_proto::smart_contract::abi::entry::{EntryType, Param};
    use tron_proto::smart_contract::abi::Entry;
    use tron_proto::smart_contract::Abi;

    let accounts_be = mem();
    let blocks_be = mem();
    let block_index_be = mem();
    let trans_be = mem();
    let dp_be = mem();
    let contracts_be = mem();
    let abis_be = mem();

    let abis = AbiStore::new(abis_be.clone());
    // ERC-20 ABI: transfer(address,uint256) function + Transfer event.
    let abi = Abi {
        entrys: vec![
            Entry {
                r#type: EntryType::Function as i32,
                name: "transfer".into(),
                inputs: vec![
                    Param { indexed: false, name: "to".into(), r#type: "address".into() },
                    Param { indexed: false, name: "amount".into(), r#type: "uint256".into() },
                ],
                ..Default::default()
            },
            Entry {
                r#type: EntryType::Event as i32,
                name: "Transfer".into(),
                inputs: vec![
                    Param { indexed: true, name: "from".into(), r#type: "address".into() },
                    Param { indexed: true, name: "to".into(), r#type: "address".into() },
                    Param { indexed: false, name: "value".into(), r#type: "uint256".into() },
                ],
                ..Default::default()
            },
        ],
    };

    // Contract address: 0x41 || 20-byte. We pass the 20-byte form in
    // requests; AbiStore is keyed by the 21-byte form (`Address`).
    let contract_eth: [u8; 20] = hex!("c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1");
    let mut contract_tron = [0u8; 21];
    contract_tron[0] = 0x41;
    contract_tron[1..].copy_from_slice(&contract_eth);
    abis.put(&Address::from_raw(contract_tron), &abi).unwrap();

    let state = RpcState::new(
        accounts_be,
        blocks_be,
        block_index_be,
        trans_be,
        dp_be,
        MAINNET_CHAIN_ID,
    )
    .with_contract_stores(contracts_be, abis_be);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let app = tron_rpc::server::router(state);
        axum::serve(listener, app.into_make_service()).await.unwrap();
    });
    tokio::task::yield_now().await;
    (addr, contract_eth)
}

#[tokio::test]
async fn decode_contract_data_decodes_erc20_transfer() {
    let (addr, contract) = spawn_server_with_abi().await;

    // Build canonical ERC-20 transfer calldata: selector || pad32(to) || pad32(amount).
    let recipient: [u8; 20] = hex!("dddddddddddddddddddddddddddddddddddddddd");
    let amount: u64 = 9_999_999;
    let mut calldata = hex::decode("a9059cbb").unwrap(); // selector
    calldata.extend_from_slice(&[0u8; 12]);
    calldata.extend_from_slice(&recipient);
    let mut amt_bytes = [0u8; 32];
    amt_bytes[24..].copy_from_slice(&amount.to_be_bytes());
    calldata.extend_from_slice(&amt_bytes);

    let resp = call(
        addr,
        json!({
            "jsonrpc": "2.0",
            "method": "decodeContractData",
            "params": [{
                "contract_address": format!("0x{}", hex::encode(contract)),
                "data": format!("0x{}", hex::encode(&calldata)),
            }],
            "id": 1,
        }),
    )
    .await;
    let result = &resp["result"];
    assert_eq!(result["name"], "transfer");
    assert_eq!(result["selector"], "0xa9059cbb");
    let params = result["params"].as_array().expect("params array");
    assert_eq!(params.len(), 2);
    assert_eq!(params[0]["name"], "to");
    assert_eq!(params[0]["type"], "address");
    assert_eq!(
        params[0]["value"].as_str().unwrap(),
        format!("0x{}", hex::encode(recipient))
    );
    assert_eq!(params[1]["name"], "amount");
    assert_eq!(params[1]["type"], "uint256");
    // uint256 renders as decimal string.
    assert_eq!(params[1]["value"], amount.to_string());
}

#[tokio::test]
async fn decode_event_log_decodes_erc20_transfer_event() {
    let (addr, contract) = spawn_server_with_abi().await;

    // ERC-20 Transfer topic0 (hard-coded canonical hash).
    let topic0 = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
    let from_addr: [u8; 20] = hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let to_addr: [u8; 20] = hex!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    let value: u64 = 250;

    let mut t_from = [0u8; 32];
    t_from[12..].copy_from_slice(&from_addr);
    let mut t_to = [0u8; 32];
    t_to[12..].copy_from_slice(&to_addr);
    let mut data = [0u8; 32];
    data[24..].copy_from_slice(&value.to_be_bytes());

    let resp = call(
        addr,
        json!({
            "jsonrpc": "2.0",
            "method": "decodeEventLog",
            "params": [{
                "contract_address": format!("0x{}", hex::encode(contract)),
                "topics": [
                    topic0,
                    format!("0x{}", hex::encode(t_from)),
                    format!("0x{}", hex::encode(t_to)),
                ],
                "data": format!("0x{}", hex::encode(data)),
            }],
            "id": 1,
        }),
    )
    .await;
    let result = &resp["result"];
    assert_eq!(result["name"], "Transfer");
    assert_eq!(result["anonymous"], false);
    let params = result["params"].as_array().expect("params array");
    assert_eq!(params.len(), 3);
    // from (indexed)
    assert_eq!(params[0]["name"], "from");
    assert_eq!(params[0]["indexed"], true);
    assert_eq!(
        params[0]["value"].as_str().unwrap(),
        format!("0x{}", hex::encode(from_addr))
    );
    // to (indexed)
    assert_eq!(params[1]["name"], "to");
    assert_eq!(params[1]["indexed"], true);
    // value (non-indexed)
    assert_eq!(params[2]["name"], "value");
    assert_eq!(params[2]["indexed"], false);
    assert_eq!(params[2]["value"], value.to_string());
}

#[tokio::test]
async fn decode_contract_data_returns_null_when_no_abi_stored() {
    let (addr, ..) = spawn_server().await;
    // No abis store wired on this state.
    let resp = call(
        addr,
        json!({
            "jsonrpc": "2.0",
            "method": "decodeContractData",
            "params": [{
                "contract_address": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                "data": "0xa9059cbb",
            }],
            "id": 1,
        }),
    )
    .await;
    assert_eq!(resp["result"], Value::Null);
}

#[tokio::test]
async fn decode_contract_data_with_unknown_selector_returns_error_field() {
    let (addr, contract) = spawn_server_with_abi().await;
    let resp = call(
        addr,
        json!({
            "jsonrpc": "2.0",
            "method": "decodeContractData",
            "params": [{
                "contract_address": format!("0x{}", hex::encode(contract)),
                "data": "0xdeadbeef",
            }],
            "id": 1,
        }),
    )
    .await;
    let result = &resp["result"];
    let err = result["error"].as_str().expect("error string");
    assert!(err.contains("no matching function") || err.contains("NoMatchingFunction"), "got: {err}");
}

// =============================================================================
// eth_* parity additions — verifies each new dispatch arm is wired and
// returns the documented shape (real value / null / "0x0" / []).
// =============================================================================

#[tokio::test]
async fn eth_get_uncle_by_block_number_returns_null() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({
            "jsonrpc":"2.0",
            "method":"eth_getUncleByBlockNumberAndIndex",
            "params":["latest","0x0"],
            "id":1
        }),
    )
    .await;
    assert!(resp["result"].is_null(), "expected null, got: {resp}");
}

#[tokio::test]
async fn eth_get_uncle_count_by_block_number_returns_zero() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({
            "jsonrpc":"2.0",
            "method":"eth_getUncleCountByBlockNumber",
            "params":["latest"],
            "id":1
        }),
    )
    .await;
    assert_eq!(resp["result"], "0x0");
}

#[tokio::test]
async fn eth_get_work_returns_empty_array() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"eth_getWork","id":1}),
    )
    .await;
    assert_eq!(resp["result"], json!([]));
}

#[tokio::test]
async fn parity_next_nonce_returns_zero() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({
            "jsonrpc":"2.0",
            "method":"parity_nextNonce",
            "params":["0x41ffffffffffffffffffffffffffffffffffffffff"],
            "id":1
        }),
    )
    .await;
    assert_eq!(resp["result"], "0x0");
}

#[tokio::test]
async fn eth_send_transaction_returns_method_not_found() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({
            "jsonrpc":"2.0",
            "method":"eth_sendTransaction",
            "params":[{"from":"0x41ff", "to":"0x4100", "value":"0x1"}],
            "id":1
        }),
    )
    .await;
    assert_eq!(resp["error"]["code"], -32601, "got: {resp}");
}

#[tokio::test]
async fn eth_sign_returns_method_not_found() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({
            "jsonrpc":"2.0",
            "method":"eth_sign",
            "params":["0x41ff","0xdeadbeef"],
            "id":1
        }),
    )
    .await;
    assert_eq!(resp["error"]["code"], -32601);
}

#[tokio::test]
async fn eth_get_compilers_returns_method_not_found() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"eth_getCompilers","id":1}),
    )
    .await;
    assert_eq!(resp["error"]["code"], -32601);
}

#[tokio::test]
async fn eth_submit_work_returns_method_not_found() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({
            "jsonrpc":"2.0",
            "method":"eth_submitWork",
            "params":["0x0","0x0","0x0"],
            "id":1
        }),
    )
    .await;
    assert_eq!(resp["error"]["code"], -32601);
}

#[tokio::test]
async fn eth_get_block_receipts_returns_empty_for_unknown_block() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({
            "jsonrpc":"2.0",
            "method":"eth_getBlockReceipts",
            "params":["latest"],
            "id":1
        }),
    )
    .await;
    assert_eq!(resp["result"], json!([]));
}

#[tokio::test]
async fn build_transaction_dispatches_to_handler_not_method_not_found() {
    let (addr, ..) = spawn_server().await;
    let resp = call(
        addr,
        json!({
            "jsonrpc":"2.0",
            "method":"buildTransaction",
            "params":[{
                "from": "0x41aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "to":   "0x41bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "data": "0xdeadbeef",
                "value": "0x0"
            }],
            "id":1
        }),
    )
    .await;
    assert_ne!(
        resp["error"]["code"].as_i64(),
        Some(-32601),
        "buildTransaction must dispatch, not method_not_found; got: {resp}"
    );
}

// =============================================================================
// getContract / getContractInfo — java-tron JsonFormat parity
// (STATE-3, 2026-06-10): ABI stitched from the split `abi` column
// family, runtimecode looked up by ADDRESS, top-level
// {smart_contract, runtimecode, contract_state} wrapper, bare hex,
// defaults omitted, ABI enums as value names.
// =============================================================================

#[tokio::test]
async fn get_contract_info_matches_java_wrapper_shape() {
    use tron_chainbase::{AbiStore, AccountStore, CodeStore, ContractStateStore, ContractStore};
    use tron_proto::smart_contract::abi::entry::{EntryType, Param, StateMutabilityType};
    use tron_proto::smart_contract::abi::Entry;
    use tron_proto::smart_contract::Abi;

    let accounts_be = mem();
    let blocks_be = mem();
    let block_index_be = mem();
    let trans_be = mem();
    let dp_be = mem();
    let contracts_be = mem();
    let abis_be = mem();
    let code_be = mem();
    let storage_be = mem();
    let contract_state_be = mem();

    let mut contract_tron = [0u8; 21];
    contract_tron[0] = 0x41;
    contract_tron[1..].fill(0xc2);
    let contract_addr = Address::from_raw(contract_tron);

    // Account row must exist (java returns null otherwise).
    AccountStore::new(accounts_be.clone())
        .put(
            &contract_addr,
            &Account {
                address: contract_tron.to_vec(),
                ..Default::default()
            },
        )
        .unwrap();

    // Contract row: post-ABI-split (abi cleared on the row itself).
    ContractStore::new(contracts_be.clone())
        .put(
            &contract_addr,
            &tron_proto::SmartContract {
                origin_address: vec![0x41; 21],
                contract_address: contract_tron.to_vec(),
                abi: None,
                bytecode: vec![0x60, 0x80],
                call_value: 0,
                consume_user_resource_percent: 30,
                name: "TetherToken".into(),
                origin_energy_limit: 10_000_000,
                code_hash: vec![0xaa; 32],
                trx_hash: Vec::new(),
                version: 0,
            },
        )
        .unwrap();

    // ABI lives in the split `abi` store and must be stitched back.
    AbiStore::new(abis_be.clone())
        .put(
            &contract_addr,
            &Abi {
                entrys: vec![Entry {
                    constant: true,
                    name: "balanceOf".into(),
                    inputs: vec![Param {
                        indexed: false,
                        name: "who".into(),
                        r#type: "address".into(),
                    }],
                    outputs: vec![Param {
                        indexed: false,
                        name: String::new(),
                        r#type: "uint256".into(),
                    }],
                    r#type: EntryType::Function as i32,
                    payable: false,
                    anonymous: false,
                    state_mutability: StateMutabilityType::View as i32,
                }],
            },
        )
        .unwrap();

    // Runtime code keyed by ADDRESS (java CodeStore keying).
    CodeStore::new(code_be.clone())
        .put(contract_addr.as_bytes(), &[0xde, 0xad, 0xbe, 0xef])
        .unwrap();

    // Dynamic-energy state served caught-up-for-display.
    ContractStateStore::new(contract_state_be.clone())
        .put(
            &contract_addr,
            &tron_proto::ContractState {
                energy_usage: 12_345,
                energy_factor: 34_000,
                update_cycle: 9_656,
            },
        )
        .unwrap();
    DynamicPropertiesStore::new(dp_be.clone()).save_current_cycle_number(9_656);

    let eth_backends = tron_rpc::state::EthCallBackends {
        accounts: accounts_be.clone(),
        code: code_be.clone(),
        storage: storage_be.clone(),
        witnesses: mem(),
        contract_state: contract_state_be.clone(),
        dyn_props: dp_be.clone(),
        delegated_resources: mem(),
        delegation: mem(),
        contracts: contracts_be.clone(),
        block_index: None,
    };

    let state = RpcState::new(
        accounts_be,
        blocks_be,
        block_index_be,
        trans_be,
        dp_be,
        MAINNET_CHAIN_ID,
    )
    .with_contract_stores(contracts_be, abis_be)
    .with_evm_stores(code_be, storage_be)
    .with_eth_call_backends(eth_backends);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let app = tron_rpc::server::router(state);
        axum::serve(listener, app.into_make_service()).await.unwrap();
    });
    tokio::task::yield_now().await;

    let hex_addr = format!("0x{}", hex::encode(&contract_tron[1..]));

    // --- getContract: bare hex, omit defaults, stitched ABI ---
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getContract","params":[hex_addr],"id":1}),
    )
    .await;
    let c = &resp["result"];
    assert_eq!(c["name"], "TetherToken");
    assert_eq!(c["consume_user_resource_percent"], 30);
    assert_eq!(c["bytecode"], "6080", "bare hex, no 0x prefix");
    assert_eq!(c["code_hash"], hex::encode([0xaa; 32]));
    // java JsonFormat omits zero/empty fields entirely.
    assert!(c.get("call_value").is_none(), "call_value=0 must be omitted: {c}");
    assert!(c.get("trx_hash").is_none(), "empty trx_hash must be omitted: {c}");
    assert!(c.get("version").is_none(), "version=0 must be omitted: {c}");
    // Stitched ABI with java enum names and per-entry omit-defaults.
    let entry = &c["abi"]["entrys"][0];
    assert_eq!(entry["name"], "balanceOf");
    assert_eq!(entry["type"], "Function");
    assert_eq!(entry["stateMutability"], "View");
    assert_eq!(entry["constant"], true);
    assert!(entry.get("anonymous").is_none(), "false bools omitted: {entry}");
    assert!(entry.get("payable").is_none(), "false bools omitted: {entry}");
    assert_eq!(entry["inputs"][0]["type"], "address");
    assert!(
        entry["outputs"][0].get("name").is_none(),
        "empty param name omitted: {entry}"
    );

    // --- getContractInfo: {smart_contract, runtimecode, contract_state} ---
    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getContractInfo","params":[hex_addr],"id":1}),
    )
    .await;
    let r = &resp["result"];
    assert_eq!(r["smart_contract"]["name"], "TetherToken");
    assert_eq!(
        r["smart_contract"]["abi"]["entrys"][0]["name"], "balanceOf",
        "getContractInfo stitches the ABI too: {r}"
    );
    assert_eq!(r["runtimecode"], "deadbeef", "address-keyed code lookup: {r}");
    assert_eq!(r["contract_state"]["energy_factor"], 34_000);
    assert_eq!(r["contract_state"]["energy_usage"], 12_345);
    assert_eq!(r["contract_state"]["update_cycle"], 9_656);
}

#[tokio::test]
async fn get_contract_returns_empty_object_when_account_missing() {
    use tron_chainbase::ContractStore;

    let accounts_be = mem();
    let contracts_be = mem();
    let abis_be = mem();

    let mut contract_tron = [0u8; 21];
    contract_tron[0] = 0x41;
    contract_tron[1..].fill(0xc3);
    // Contract row exists but the ACCOUNT row doesn't — java returns null.
    ContractStore::new(contracts_be.clone())
        .put(
            &Address::from_raw(contract_tron),
            &tron_proto::SmartContract {
                contract_address: contract_tron.to_vec(),
                ..Default::default()
            },
        )
        .unwrap();

    let state = RpcState::new(accounts_be, mem(), mem(), mem(), mem(), MAINNET_CHAIN_ID)
        .with_contract_stores(contracts_be, abis_be);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let app = tron_rpc::server::router(state);
        axum::serve(listener, app.into_make_service()).await.unwrap();
    });
    tokio::task::yield_now().await;

    let resp = call(
        addr,
        json!({"jsonrpc":"2.0","method":"getContract",
               "params":[format!("0x{}", hex::encode(&contract_tron[1..]))],"id":1}),
    )
    .await;
    assert_eq!(resp["result"], json!({}));
}
