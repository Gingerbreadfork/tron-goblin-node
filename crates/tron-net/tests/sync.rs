//! End-to-end sync-protocol tests.
//!
//! Each test wires two `PeerConnection`s back-to-back via
//! `tokio::io::duplex`: one acts as the "fresh node syncing", the
//! other as a "peer with a chain to share". Drives the four-message
//! sync handshake (`SyncBlockChain` → `BlockChainInventory` →
//! `FetchInvData` → `Block`...) and confirms the receiver sees the
//! correct block data on the other side.

use std::sync::Arc;

use prost::Message as _;
use tron_net::{
    recv_block, recv_chain_inventory, recv_fetch_inv_data, recv_sync_request, send_block,
    send_chain_inventory, send_fetch_inv_data, send_sync_request, HelloInputs, PeerConnection,
    MAINNET_P2P_VERSION,
};
use tron_proto::block_header::Raw as BlockHeaderRaw;
use tron_proto::{Block, BlockHeader, ChainInventory, Endpoint};
use tron_types::{genesis_block_id, mainnet_inputs, BlockId};

// === Shared test fixtures ===================================================

fn synthetic_chain(count: i64) -> Vec<(BlockId, Block)> {
    let mut chain = Vec::with_capacity(count as usize);
    let mut prev = [0u8; 32];
    for n in 0..count {
        let block = Block {
            transactions: Vec::new(),
            block_header: Some(BlockHeader {
                raw_data: Some(BlockHeaderRaw {
                    timestamp: 1_700_000_000_000 + n * 3000,
                    tx_trie_root: Vec::new(),
                    parent_hash: prev.to_vec(),
                    number: n,
                    witness_id: 0,
                    witness_address: Vec::new(),
                    version: 28,
                    account_state_root: Vec::new(),
                }),
                witness_signature: Vec::new(),
            }),
        };
        let id = tron_types::block_id_from_block(&block).unwrap();
        prev = *id.as_bytes();
        chain.push((id, block));
    }
    chain
}

fn local_hello(version: i32, genesis: BlockId) -> HelloInputs<'static> {
    HelloInputs {
        from: Endpoint {
            address: b"127.0.0.1".to_vec(),
            address_ipv6: Vec::new(),
            port: 18888,
            node_id: vec![0xab; 64],
        },
        version,
        timestamp_ms: 1_700_000_000_000,
        genesis,
        solid: genesis,
        head: genesis,
        node_type: 0,
        lowest_block_num: 0,
        code_version: b"tron-goblin/0.0.1",
    }
}

// === SyncBlockChain round-trip ==============================================

#[tokio::test]
async fn sync_request_carries_caller_summary_bytes() {
    let genesis = genesis_block_id(&mainnet_inputs());
    let (a_s, b_s) = tokio::io::duplex(64 * 1024);
    let mut a = PeerConnection::new(a_s);
    let mut b = PeerConnection::new(b_s);

    // Handshake first.
    let (_, _) = tokio::join!(
        a.handshake(local_hello(MAINNET_P2P_VERSION, genesis)),
        b.handshake(local_hello(MAINNET_P2P_VERSION, genesis))
    );

    let summary = vec![genesis];
    let send_fut = send_sync_request(&mut a, &summary);
    let recv_fut = recv_sync_request(&mut b);

    let (s, r) = tokio::join!(send_fut, recv_fut);
    s.unwrap();
    let received = r.unwrap();
    assert_eq!(received.ids.len(), 1);
    assert_eq!(received.ids[0].hash, genesis.as_bytes());
    assert_eq!(received.ids[0].number, 0);
    // java-tron's SyncBlockChainMessage carries a BlockInventory with
    // `type = SYNC`; the request side never sets `remain_num`.
    assert_eq!(received.r#type, tron_proto::block_inventory::Type::Sync as i32);
}

// === Full sync flow ========================================================

/// **End-to-end** sync: A is fresh, B has 5 synthetic blocks. A sends
/// SyncBlockChain with just genesis. B responds with the IDs of blocks
/// 1..=4. A sends FetchInvData for those four. B streams them back as
/// Block frames. A receives and decodes all 4.
#[tokio::test]
async fn sync_loop_transfers_blocks_in_order() {
    let chain = synthetic_chain(5);
    let genesis_id = chain[0].0;

    let (a_s, b_s) = tokio::io::duplex(256 * 1024);
    let mut a = PeerConnection::new(a_s);
    let mut b = PeerConnection::new(b_s);

    // Handshake using the same genesis on both sides.
    let (_, _) = tokio::join!(
        a.handshake(local_hello(MAINNET_P2P_VERSION, genesis_id)),
        b.handshake(local_hello(MAINNET_P2P_VERSION, genesis_id))
    );

    // The two halves of the test below run concurrently.

    let chain_for_provider = Arc::new(chain.clone());
    let provider = async move {
        // 1. Receive the SyncBlockChain.
        let sync_req = recv_sync_request(&mut b).await.unwrap();
        // Caller (A) only knows genesis. Reply with blocks 1..=4.
        assert_eq!(sync_req.ids.len(), 1);
        assert_eq!(sync_req.ids[0].number, 0);

        let inv = ChainInventory {
            ids: chain_for_provider
                .iter()
                .skip(1) // skip genesis (A already has it)
                .map(|(id, _)| tron_proto::chain_inventory::BlockId {
                    hash: id.as_bytes().to_vec(),
                    number: id.num() as i64,
                })
                .collect(),
            remain_num: 0,
        };
        send_chain_inventory(&mut b, &inv).await.unwrap();

        // 2. Receive FetchInvData and reply with the requested blocks
        //    one per frame.
        let fetch = recv_fetch_inv_data(&mut b).await.unwrap();
        assert_eq!(fetch.ids.len(), 4);

        for requested_id in &fetch.ids {
            let (_, block) = chain_for_provider
                .iter()
                .find(|(id, _)| id.as_bytes() == requested_id.as_slice())
                .expect("provider has every requested id");
            send_block(&mut b, block).await.unwrap();
        }
    };

    let consumer = async move {
        // 1. Send SyncBlockChain with just genesis.
        send_sync_request(&mut a, std::slice::from_ref(&genesis_id))
            .await
            .unwrap();
        let inv = recv_chain_inventory(&mut a).await.unwrap();
        assert_eq!(inv.ids.len(), 4);

        // 2. Request all 4 blocks in one FetchInvData.
        let ids: Vec<Vec<u8>> = inv.ids.iter().map(|b| b.hash.clone()).collect();
        send_fetch_inv_data(&mut a, &ids).await.unwrap();

        // 3. Receive one Block per id, in order.
        let mut received = Vec::with_capacity(4);
        for _ in 0..4 {
            received.push(recv_block(&mut a).await.unwrap());
        }
        received
    };

    let (_, received) = tokio::join!(provider, consumer);
    assert_eq!(received.len(), 4);
    for (i, block) in received.iter().enumerate() {
        let expected_num = (i + 1) as i64;
        assert_eq!(
            block
                .block_header
                .as_ref()
                .unwrap()
                .raw_data
                .as_ref()
                .unwrap()
                .number,
            expected_num,
            "block at index {i} should have number {expected_num}"
        );
    }
}

// === Error path: unexpected frame ==========================================

/// If the peer responds with the wrong message type to a sync request,
/// we surface `UnexpectedFrame` and don't apply anything.
#[tokio::test]
async fn unexpected_response_yields_typed_error() {
    use bytes::Bytes;
    use tron_net::{Frame, MessageType};

    let genesis = genesis_block_id(&mainnet_inputs());
    let (a_s, b_s) = tokio::io::duplex(64 * 1024);
    let mut a = PeerConnection::new(a_s);
    let mut b = PeerConnection::new(b_s);
    let (_, _) = tokio::join!(
        a.handshake(local_hello(MAINNET_P2P_VERSION, genesis)),
        b.handshake(local_hello(MAINNET_P2P_VERSION, genesis))
    );

    let provider = async move {
        // Pretend to be a peer that responds to SyncBlockChain with a
        // P2pPing — utter protocol violation.
        let _ = recv_sync_request(&mut b).await.unwrap();
        b.send_frame(Frame {
            ty: MessageType::P2pPing,
            payload: Bytes::new(),
        })
        .await
        .unwrap();
    };

    let consumer = async move {
        send_sync_request(&mut a, std::slice::from_ref(&genesis))
            .await
            .unwrap();
        recv_chain_inventory(&mut a).await
    };

    let (_, res) = tokio::join!(provider, consumer);
    let err = res.unwrap_err();
    assert!(
        matches!(err, tron_net::SyncError::UnexpectedFrame { .. }),
        "got {err:?}"
    );
}

// === Frame payload pinning =================================================

/// Validate the on-wire bytes of a FetchInvData payload. `Inventory`
/// with `type = BLOCK (1)` and one id encodes as a specific protobuf
/// byte sequence — pin it.
#[test]
fn fetch_inv_data_payload_encoding_pinned() {
    use tron_proto::inventory::InventoryType;
    use tron_proto::Inventory;
    let inv = Inventory {
        r#type: InventoryType::Block as i32,
        ids: vec![vec![0xaa, 0xbb]],
    };
    let bytes = inv.encode_to_vec();
    // tag(1, VARINT=0) for r#type = 0x08, value = 0x01 (Block)
    // tag(2, LEN=2)   for ids[0] = 0x12, length 2, bytes [aa, bb]
    assert_eq!(bytes, vec![0x08, 0x01, 0x12, 0x02, 0xaa, 0xbb]);
}
