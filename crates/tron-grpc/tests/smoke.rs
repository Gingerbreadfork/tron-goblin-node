//! End-to-end smoke: spin up the gRPC server on a random port, hit
//! it with the auto-generated client, verify a couple of real
//! methods work and that the stubbed methods return Unimplemented.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::oneshot;
use tron_chainbase::{
    AccountStore, BlockIndexStore, BlockStore, DynamicPropertiesStore, KvBackend, MemBackend,
    TransactionStore, WitnessStore,
};
use tron_crypto::address::Address;
use tron_grpc::proto::wallet_client::WalletClient;
use tron_proto::protocol::{EmptyMessage, NumberMessage};
use tron_proto::{block_header::Raw as BlockHeaderRaw, Account, Block, BlockHeader, Witness};
use tron_rpc::RpcState;

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

/// Build a minimal `RpcState` with one applied block and one witness
/// preloaded, so the smoke methods have something to return.
fn fixture() -> RpcState {
    let accounts_be = mem();
    let blocks_be = mem();
    let block_index_be = mem();
    let dp_be = mem();
    let witnesses_be = mem();

    // ---- seed a head block (number = 1, hash = [0xAA; 32]) ----
    let mut block = Block {
        block_header: Some(BlockHeader {
            raw_data: Some(BlockHeaderRaw {
                number: 1,
                parent_hash: vec![0u8; 32],
                timestamp: 1_700_000_003_000,
                witness_address: vec![0x41; 21],
                ..Default::default()
            }),
            ..Default::default()
        }),
        transactions: Vec::new(),
    };
    // tx_trie_root for empty txs is well-defined; calc it.
    if let Some(h) = tron_types::calc_tx_trie_root(&block.transactions) {
        block.block_header.as_mut().unwrap().raw_data.as_mut().unwrap().tx_trie_root =
            h.to_vec();
    }
    let block_id = tron_types::block_id_from_block(&block).expect("block id");

    BlockStore::new(blocks_be.clone()).put(&block_id, &block).unwrap();
    BlockIndexStore::new(block_index_be.clone()).put(&block_id).unwrap();
    let dp = DynamicPropertiesStore::new(dp_be.clone());
    dp.save_latest_block_header_number(1);
    dp.save_latest_block_header_hash(block_id.as_bytes());

    // ---- seed an account and a witness ----
    let alice = [0x41u8; 21];
    AccountStore::new(accounts_be.clone()).put(
        &Address::from_raw(alice),
        &Account {
            address: alice.to_vec(),
            balance: 1_234_567,
            ..Default::default()
        },
    ).unwrap();
    let ws = WitnessStore::new(witnesses_be.clone());
    let w_addr = {
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[20] = 0xBB;
        a
    };
    ws.put(
        &Address::from_raw(w_addr),
        &Witness {
            address: w_addr.to_vec(),
            vote_count: 100,
            url: "http://gr-test.example".into(),
            is_jobs: true,
            ..Default::default()
        },
    ).unwrap();

    RpcState {
        accounts: Arc::new(AccountStore::new(accounts_be)),
        blocks: Arc::new(BlockStore::new(blocks_be)),
        block_index: Arc::new(BlockIndexStore::new(block_index_be)),
        transactions: Arc::new(TransactionStore::new(mem())),
        dyn_props: Arc::new(dp),
        code: None,
        storage: None,
        witnesses: Some(Arc::new(ws)),
        delegation: None,
        delegated_resources: None,
        proposals: None,
        assets_v2: None,
        exchanges_v2: None,
        eth_call_backends: None,
        tx_history: None,
        account_id_index: None,
        contracts: None,
        abis: None,
        delegated_resource_account_index: None,
        market_orders: None,
        market_accounts: None,
        market_pair_to_price: None,
        market_pair_price_to_order: None,
        balance_trace: None,
        chain_id: 1,
        metrics: None,
        mempool: None,
        filters: Arc::new(tron_rpc::FilterRegistry::default()),
        assets_v1: None,
        account_assets: None,
        nullifiers: None,
        eth_call_gas_cap: 50_000_000,
        support_constant: false,
        constant_call_timeout_ms: 0,
        pubsub: None,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn grpc_server_serves_basic_read_methods() {
    let state = fixture();

    // Bind to a random port so parallel test runs don't clash.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    drop(listener); // tonic re-binds itself in start_server

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server_state = state.clone();
    let server = tokio::spawn(async move {
        let shut = async move {
            let _ = shutdown_rx.await;
        };
        tron_grpc::start_server(server_state, addr, shut).await
    });

    // Give the server a beat to bind.
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut client =
        WalletClient::connect(format!("http://{}", addr)).await.expect("connect");

    // ---- get_now_block ----
    let block = client
        .get_now_block(EmptyMessage::default())
        .await
        .expect("get_now_block")
        .into_inner();
    let header = block.block_header.expect("header present");
    let raw = header.raw_data.expect("raw_data present");
    assert_eq!(raw.number, 1, "head block num");

    // ---- get_block_by_num(1) ----
    let block_one = client
        .get_block_by_num(NumberMessage { num: 1 })
        .await
        .expect("get_block_by_num")
        .into_inner();
    assert_eq!(
        block_one
            .block_header
            .as_ref()
            .and_then(|h| h.raw_data.as_ref())
            .map(|r| r.number)
            .unwrap_or(0),
        1,
    );

    // ---- get_account(alice) ----
    let alice_resp = client
        .get_account(Account {
            address: vec![0x41; 21],
            ..Default::default()
        })
        .await
        .expect("get_account")
        .into_inner();
    assert_eq!(alice_resp.balance, 1_234_567);
    // gRPC getAccount now applies java-tron's Wallet.getAccount read-time
    // transforms — frozenV2 is padded to all three ResourceCodes
    // (sortFrozenV2List), matching the HTTP surface.
    assert_eq!(
        alice_resp.frozen_v2.len(),
        3,
        "gRPC getAccount must pad frozenV2 to 3 entries like java/HTTP"
    );

    // ---- list_witnesses ----
    let wits = client
        .list_witnesses(EmptyMessage::default())
        .await
        .expect("list_witnesses")
        .into_inner();
    assert_eq!(wits.witnesses.len(), 1);
    assert_eq!(wits.witnesses[0].vote_count, 100);

    // ---- get_block_by_id ----
    let block_id_bytes = tron_proto::Block::default(); // placeholder usage
    let _ = block_id_bytes; // silence unused
    let block_id = tron_types::block_id_from_block(
        &block_one,
    )
    .expect("block id");
    let by_id = client
        .get_block_by_id(tron_proto::protocol::BytesMessage {
            value: block_id.as_bytes().to_vec(),
        })
        .await
        .expect("get_block_by_id")
        .into_inner();
    assert_eq!(
        by_id
            .block_header
            .and_then(|h| h.raw_data)
            .map(|r| r.number)
            .unwrap_or(0),
        1
    );

    // ---- get_block_by_latest_num(5) — head is at 1, expect 1 block ----
    let latest = client
        .get_block_by_latest_num(NumberMessage { num: 5 })
        .await
        .expect("get_block_by_latest_num")
        .into_inner();
    assert_eq!(latest.block.len(), 1);

    // ---- get_block_by_limit_next(0..3) — only block 1 exists ----
    let range = client
        .get_block_by_limit_next(tron_proto::protocol::BlockLimit {
            start_num: 0,
            end_num: 3,
        })
        .await
        .expect("get_block_by_limit_next")
        .into_inner();
    assert_eq!(range.block.len(), 1, "only block 1 exists in fixture");

    // ---- get_chain_parameters — fixture has none, so empty list ----
    let params = client
        .get_chain_parameters(EmptyMessage::default())
        .await
        .expect("get_chain_parameters")
        .into_inner();
    // Empty by default (no chain params seeded in fixture). Not an
    // error — just an empty list.
    assert_eq!(params.chain_parameter.len(), 0);

    // ---- broadcast_transaction with no mempool — returns ServerBusy ----
    let broadcast = client
        .broadcast_transaction(tron_proto::Transaction::default())
        .await
        .expect("broadcast_transaction call")
        .into_inner();
    assert!(!broadcast.result, "no mempool means broadcast fails");
    assert_eq!(
        broadcast.code,
        tron_proto::protocol::r#return::ResponseCode::ServerBusy as i32
    );

    // ---- get_pending_size with no mempool — returns 0 ----
    let pending = client
        .get_pending_size(EmptyMessage::default())
        .await
        .expect("get_pending_size")
        .into_inner();
    assert_eq!(pending.num, 0);

    // ---- list_nodes — empty (we don't track gossip table) ----
    let nodes = client
        .list_nodes(EmptyMessage::default())
        .await
        .expect("list_nodes")
        .into_inner();
    assert_eq!(nodes.nodes.len(), 0);

    // ---- freeze_balance is now a real builder; assert it returns a
    //      structured (unsigned) Transaction. ----
    let freeze_resp = client
        .freeze_balance(tron_proto::FreezeBalanceContract::default())
        .await
        .expect("freeze_balance builder")
        .into_inner();
    let raw = freeze_resp
        .raw_data
        .as_ref()
        .expect("builder must populate raw_data");
    assert_eq!(raw.contract.len(), 1);
    assert_eq!(
        raw.contract[0].r#type,
        tron_proto::transaction::contract::ContractType::FreezeBalanceContract as i32,
    );
    assert!(
        freeze_resp.signature.is_empty(),
        "builder must leave signature empty for client-side signing"
    );

    // ---- Sapling key derivation: get_spending_key returns 32 random
    //      bytes; round-trip through get_expanded_spending_key gives a
    //      typed (ask, nsk, ovk). Validates the shielded module is
    //      wired in and actually exercising sapling-crypto. ----
    let sk = client
        .get_spending_key(EmptyMessage::default())
        .await
        .expect("get_spending_key")
        .into_inner();
    assert_eq!(sk.value.len(), 32);
    let esk = client
        .get_expanded_spending_key(tron_proto::protocol::BytesMessage {
            value: sk.value.clone(),
        })
        .await
        .expect("get_expanded_spending_key")
        .into_inner();
    assert_eq!(esk.ask.len(), 32);
    assert_eq!(esk.nsk.len(), 32);
    assert_eq!(esk.ovk.len(), 32);

    // ---- get_new_shielded_address composes the full key derivation
    //      pipeline in one call. ----
    let shielded_addr = client
        .get_new_shielded_address(EmptyMessage::default())
        .await
        .expect("get_new_shielded_address")
        .into_inner();
    assert_eq!(shielded_addr.sk.len(), 32);
    assert_eq!(shielded_addr.ak.len(), 32);
    assert_eq!(shielded_addr.ivk.len(), 32);
    assert_eq!(shielded_addr.d.len(), 11);
    // payment_address is hex of `d || pk_d` (11 + 32 = 43 bytes,
    // 86 hex chars).
    assert_eq!(shielded_addr.payment_address.len(), 86);

    // ---- Removed-mainnet contracts return FailedPrecondition with
    //      a clear message — verifies the deprecation-error path. ----
    let err = client
        .buy_storage(tron_proto::protocol::BuyStorageContract::default())
        .await
        .expect_err("buy_storage was removed from mainnet");
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(
        err.message().contains("removed from mainnet"),
        "expected deprecation message; got: {}",
        err.message()
    );

    // ---- Shielded TX construction now ships end-to-end with the
    //      embedded Sapling MPC parameters. With a default-empty
    //      `PrivateParameters` (no ask, no transparent_from), the
    //      builder rejects the input source as `InvalidArgument`. ----
    let err = client
        .create_shielded_transaction(tron_proto::protocol::PrivateParameters::default())
        .await
        .expect_err("default-empty params should be rejected");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(
        err.message().to_lowercase().contains("input source")
            || err.message().to_lowercase().contains("transparent_from"),
        "expected message to name the missing input source; got: {}",
        err.message()
    );

    // ---- WalletSolidity (port-50061 surface) — same server, different
    //      service. Just confirm a couple of reads return the same data
    //      as the Wallet service. ----
    {
        use tron_grpc::proto::wallet_solidity_client::WalletSolidityClient;
        let mut sol_client = WalletSolidityClient::connect(format!("http://{}", addr))
            .await
            .expect("connect WalletSolidity");
        let block = sol_client
            .get_now_block(EmptyMessage::default())
            .await
            .expect("WalletSolidity::get_now_block")
            .into_inner();
        let raw = block.block_header.unwrap().raw_data.unwrap();
        assert_eq!(raw.number, 1, "WalletSolidity head matches Wallet head");

        let alice = sol_client
            .get_account(Account {
                address: vec![0x41; 21],
                ..Default::default()
            })
            .await
            .expect("WalletSolidity::get_account")
            .into_inner();
        assert_eq!(alice.balance, 1_234_567);
    }

    // ---- shutdown ----
    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
}
