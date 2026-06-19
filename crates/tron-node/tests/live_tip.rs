//! Live-tip protocol test.
//!
//! Verifies the `BlockInventory` adv path end-to-end at the wire
//! level: when a peer (here, a TCP mock) pushes a tip-block
//! announcement, the `SyncDriver` queues it and responds with a
//! `FetchInvData` carrying the announced hash.
//!
//! This proves the dispatch wiring that takes effect *after* the sync
//! catches up to peer's head — at which point `needSyncFromUs` flips
//! to false on the peer side and live tip blocks arrive as adv
//! broadcasts instead of via the `SyncBlockChain` / `ChainInventory`
//! request/response pair.
//!
//! The mock peer doesn't deliver an actual `Block` payload (we only
//! care that the FetchInvData request is well-formed), so the driver
//! never calls `accept_block`; we don't need to construct signed
//! blocks just to validate the protocol-level interaction.

use std::sync::Arc;
use std::time::Duration;

use prost::Message as _;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tron_chainbase::{KvBackend, MemBackend};
use tron_executor::StateBackends;
use tron_net::{
    Frame, HelloInputs, Libp2pHelloInputs, MessageType, PeerConnection,
    MAINNET_P2P_VERSION,
};
use tron_node::sync::{SyncConfig, SyncDriver};
use tron_proto::{chain_inventory, inventory, ChainInventory, Endpoint, Inventory};
use tron_types::{genesis_block_id, mainnet_inputs};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn fresh_state() -> (StateBackends, Arc<dyn KvBackend>) {
    let blocks_be = mem();
    let state = StateBackends {
        accounts: mem(),
        witnesses: mem(),
        votes: mem(),
        delegation: mem(),
        delegated_resources: mem(),
        delegated_resource_account_index: None,
        dyn_props: mem(),
        proposals: mem(),
        name_index: mem(),
        id_index: mem(),
        asset_v1: mem(),
        asset_v2: mem(),
        contracts: mem(),
        abi: mem(),
        exchange_v1: mem(),
        exchange_v2: mem(),
        market_orders: mem(),
        nullifiers: mem(),
        merkle_trees: None,
        code: Some(mem()),
        storage_row: Some(mem()),
        contract_state: Some(mem()),
        block_index: Some(mem()),
        witness_schedule: Some(mem()),
        reward_vi: None,
    };
    (state, blocks_be)
}

#[tokio::test(flavor = "current_thread")]
async fn block_inventory_adv_triggers_fetch_inv_data() {
    // 1. Listen for the driver's outbound TCP dial. Port 0 → OS picks.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bound = listener.local_addr().unwrap();
    let peer_addr = format!("{bound}");

    // 2. The tip-block hash the mock will advertise. The first 8 bytes
    //    of a BlockId must be the block number in big-endian — the
    //    peer reconstructs `BlockId(hash, num)` and overlays them. We
    //    set num=1 here; the rest is filler.
    const TIP_NUM: u64 = 1;
    let mut tip_id_bytes = [0u8; 32];
    tip_id_bytes[0..8].copy_from_slice(&TIP_NUM.to_be_bytes());
    for (i, b) in tip_id_bytes[8..].iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(0x37).wrapping_add(0x99);
    }
    let tip_id_vec = tip_id_bytes.to_vec();

    // 3. Mock peer task. Uses `PeerConnection` symmetrically — the
    //    libp2p + app handshakes are valid on both sides as long as
    //    both call `libp2p_handshake` / `handshake` (they each send
    //    then read; the TCP buffer absorbs the simultaneous sends).
    let genesis = genesis_block_id(&mainnet_inputs());
    let mock_tip = tip_id_vec.clone();
    let mock = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut conn = PeerConnection::new(stream);

        // libp2p connection-layer handshake. Matches what the driver
        // is sending (network_id=11_111 = mainnet, version=2 = v0.2).
        conn.libp2p_handshake(Libp2pHelloInputs {
            from: Endpoint {
                address: b"127.0.0.1".to_vec(),
                address_ipv6: Vec::new(),
                port: bound.port() as i32,
                node_id: vec![0xAA; 64],
            },
            network_id: 11_111,
            version: 2,
            timestamp_ms: 0,
        })
        .await
        .expect("mock libp2p handshake");

        // App-level handshake. Mock claims to be at genesis (head =
        // genesis) so the driver's subsequent `SyncBlockChain` will
        // resolve to a 1-id `ChainInventory` (nothing more to sync).
        conn.handshake(HelloInputs {
            from: Endpoint {
                address: b"127.0.0.1".to_vec(),
                address_ipv6: Vec::new(),
                port: bound.port() as i32,
                node_id: vec![0xAA; 64],
            },
            version: MAINNET_P2P_VERSION,
            timestamp_ms: 0,
            genesis,
            solid: genesis,
            head: genesis,
            node_type: 0,
            lowest_block_num: 0,
            code_version: b"mock/0.0.1",
        })
        .await
        .expect("mock app handshake");

        // Read the driver's initial `SyncBlockChain`.
        let frame = conn
            .next_frame()
            .await
            .expect("read SyncBlockChain")
            .expect("non-EOF");
        assert_eq!(
            frame.ty,
            MessageType::SyncBlockChain,
            "driver should send SyncBlockChain right after handshake"
        );

        // Respond with `ChainInventory([genesis])` — peer reports
        // we're at head. java-tron's SyncBlockChainMsgHandler treats
        // a 1-id response as "needSyncFromUs = false" → we're now in
        // the AdvService.broadcast eligible set.
        let chain_inv = ChainInventory {
            ids: vec![chain_inventory::BlockId {
                hash: genesis.as_bytes().to_vec(),
                number: 0,
            }],
            remain_num: 0,
        };
        conn.send_frame(Frame {
            ty: MessageType::BlockChainInventory,
            payload: chain_inv.encode_to_vec().into(),
        })
        .await
        .expect("send ChainInventory");

        // Push a tip-block adv (the live-tip scenario). Real mainnet
        // peers use `MessageType::Inventory` (0x06) with the
        // `Inventory` proto here — NOT `BlockInventory` (0x12).
        // `AdvService.broadcast` constructs `InventoryMessage(hashList,
        // InventoryType.BLOCK)` and `peer.sendMessage()`s it. The
        // wire shape is `Inventory{type=BLOCK, ids=[raw_hash, ...]}`,
        // not the `{hash, number}` pair list used by sync.
        let inv = Inventory {
            r#type: inventory::InventoryType::Block as i32,
            ids: vec![mock_tip.clone()],
        };
        conn.send_frame(Frame {
            ty: MessageType::Inventory,
            payload: inv.encode_to_vec().into(),
        })
        .await
        .expect("send Inventory (adv)");

        // **The assertion this test exists for**: read the driver's
        // response and confirm it's a `FetchInvData` carrying our
        // tip hash. Wait up to 5s — the driver's REQ_MIN_INTERVAL
        // throttle (400ms) gates the send.
        let frame = tokio::time::timeout(
            Duration::from_secs(5),
            conn.next_frame(),
        )
        .await
        .expect("FetchInvData should arrive within 5s")
        .expect("read FetchInvData")
        .expect("non-EOF");
        assert_eq!(
            frame.ty,
            MessageType::FetchInvData,
            "driver should respond to Inventory adv with FetchInvData"
        );
        let inv = Inventory::decode(frame.payload).expect("decode Inventory");
        assert!(
            inv.ids.iter().any(|h| h == &mock_tip),
            "FetchInvData must carry the adv'd hash; got {:?}",
            inv.ids
        );
    });

    // 4. Driver setup. `max_blocks = Some(1)` is a soft cap that the
    //    driver checks at the top of each dispatch iteration — since
    //    the mock never sends an actual `Block`, the cap doesn't
    //    fire; the driver exits when the mock closes the connection
    //    (on a successful assertion the task returns Ok and the
    //    socket drops, surfacing as a clean EOF / PeerFailure).
    let (state, blocks_be) = fresh_state();
    let cfg = SyncConfig {
        peers: vec![peer_addr],
        max_blocks: Some(1),
        tail_interval: Duration::from_secs(1),
        initial_backoff: Duration::from_millis(50),
        blocks_backend: blocks_be,
        progress_log_interval: 1,
        advertise_port: 18888,
        tip_test: false,
        p2p_rate_limits: Default::default(),
        fetch_block_timeout: Duration::from_millis(200),
        fetch_inflight_per_peer: 64,
        peer_is_fast_forward: false,
        follow_tip: false,
    };
    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let driver_task = tokio::spawn(async move {
        let mut driver = SyncDriver::new(state, cfg);
        driver.run(shutdown_rx).await
    });

    // 5. Wait for the mock to finish asserting (it returns when the
    //    FetchInvData verification is done). If the mock panics, this
    //    `.unwrap()` propagates the failure.
    mock.await.expect("mock peer assertion");

    // 6. Tell the driver to exit. It may still be looping if the mock
    //    connection didn't close yet; we don't care about its final
    //    stats — only the assertion above matters for this test.
    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(2), driver_task).await;
}
