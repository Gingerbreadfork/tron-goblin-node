//! Live-tip observation against a real mainnet peer.
//!
//! Two-phase: discover peer's current head, then reconnect with our
//! `head` spoofed equal to it (a few blocks ahead, to absorb the
//! couple-block drift while we reconnect). This puts the peer-side
//! `PeerConnection` in the adv-eligible state.
//!
//! **Critical gotcha**: java-tron's `PeerConnection` field
//! `needSyncFromUs` is initialized to **true** (not false as Java
//! booleans normally default — the field has an explicit `= true`
//! initializer). The peer-side `onConnect()` handler only flips it
//! to false if `peerHeadBlockNum == headBlockNum` (i.e., we claim
//! the exact head) OR `peerHeadBlockNum > headBlockNum` (we claim
//! ahead, triggering peer-side `syncService.startSync(us)`).
//! Without that, the `AdvService.broadcast` filter
//! (`!isNeedSyncFromPeer && !isNeedSyncFromUs`) excludes us and we
//! get nothing but keep-alive pings.
//!
//! Phase 1 (discovery): connect, hand-shake with `head=genesis`,
//! read the peer's `HelloMessage`, extract `peer.head_block_id`.
//! Phase 2 (observation): close, reconnect with `head = peer.head + N`
//! for some small N. The "+N" overshoot pushes us into the
//! `peerHeadBlockNum > headBlockNum` branch on the peer side, which
//! sets `needSyncFromUs = false` AND triggers peer-initiated
//! `SyncBlockChain` against us. We ignore that — the rate limit and
//! disconnect threshold are generous enough that we observe at least
//! one tip-block adv within the 45s window before peer gives up on
//! the doomed sync.
//!
//! Marked `#[ignore]` because it requires:
//!   - A reachable mainnet peer (default `192.168.0.36:18888`, override
//!     via `TRON_PEER` env var).
//!   - The peer must accept us — being trust-listed in `node.passive`
//!     bypasses `TIME_BANNED` / `DUPLICATE_PEER` and makes iteration
//!     reliable. Without trust-peer status, the test may flake on
//!     reconnects.
//!   - Mainnet block production (a new block within the observation
//!     window — default 45s, mainnet block time ≈ 3s).
//!
//! Run with:
//!
//! ```text
//! cargo test --test live_tip_observation --ignored -- --nocapture
//! ```

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use prost::Message as _;
use tron_net::{
    Frame, HelloInputs, Libp2pHelloInputs, MessageType, PeerConnection,
    MAINNET_P2P_VERSION,
};
use tron_proto::{
    chain_inventory, inventory, libp2p::KeepAliveMessage, ChainInventory, Endpoint, Inventory,
};
use tron_types::{genesis_block_id, mainnet_inputs};

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Unique-ish 64-byte node id. Mainnet peers dedup by node_id, so
/// reusing one across rapid reconnects trips `DUPLICATE_PEER` until
/// the peer's window expires. Seeding from nanos gives a fresh value
/// every test invocation.
fn unique_node_id() -> Vec<u8> {
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let n = now_ns.to_le_bytes();
    let mut out = vec![0u8; 64];
    for (i, b) in out.iter_mut().enumerate() {
        *b = n[i % 8].wrapping_add(i as u8);
    }
    out
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires live mainnet peer; run with: cargo test --test live_tip_observation --ignored -- --nocapture"]
async fn observe_tip_block_announcements_from_live_peer() {
    let peer_addr =
        std::env::var("TRON_PEER").unwrap_or_else(|_| "192.168.0.36:18888".into());
    let observation_timeout = Duration::from_secs(45);

    let genesis = genesis_block_id(&mainnet_inputs());

    // ============================================================
    // PHASE 1: discover peer's current head.
    // ============================================================
    eprintln!("[phase 1] dialing {peer_addr} to discover peer head...");
    let mut discovery_conn = PeerConnection::dial(&peer_addr).await.expect("phase1 dial");
    let discovery_endpoint = Endpoint {
        address: b"127.0.0.1".to_vec(),
        address_ipv6: Vec::new(),
        port: 18888,
        node_id: unique_node_id(),
    };
    discovery_conn
        .libp2p_handshake(Libp2pHelloInputs {
            from: discovery_endpoint.clone(),
            network_id: 11_111,
            version: 2,
            timestamp_ms: now_ms(),
        })
        .await
        .expect("phase1 libp2p handshake");
    let peer_hello = discovery_conn
        .handshake(HelloInputs {
            from: discovery_endpoint,
            version: MAINNET_P2P_VERSION,
            timestamp_ms: now_ms(),
            genesis,
            solid: genesis,
            head: genesis,
            node_type: 0,
            lowest_block_num: 0,
            code_version: b"tron-goblin observer/discovery",
        })
        .await
        .expect("phase1 app handshake")
        .into_hello()
        .expect("discovery peer must send a verified Hello");

    let peer_head_bytes: [u8; 32] = peer_hello
        .head_block_id
        .as_ref()
        .expect("peer hello must carry head_block_id")
        .hash
        .as_slice()
        .try_into()
        .expect("peer head must be 32 bytes");
    let peer_head_num = u64::from_be_bytes(
        peer_head_bytes[..8].try_into().unwrap_or([0u8; 8]),
    );
    eprintln!(
        "[phase 1] peer head: num={} hash={}",
        peer_head_num,
        hex::encode(peer_head_bytes)
    );

    // Drop the discovery connection cleanly (don't `disconnect()`
    // since that sends a P2pDisconnect which would put us in peer's
    // recent-disconnect cache).
    drop(discovery_conn);

    // ============================================================
    // PHASE 2: reconnect, claim head a few blocks ahead of peer.
    // Triggers peer's `if (peerHeadBlockNum > headBlockNum)` branch,
    // which sets `needSyncFromUs = false` AND calls
    // `syncService.startSync(us)` (peer asks us for blocks via a
    // `SyncBlockChain` — we ignore it). We're now in
    // `AdvService.broadcast`'s eligible bucket.
    // ============================================================
    const SPOOF_OVERSHOOT: u64 = 64;
    let spoof_num = peer_head_num + SPOOF_OVERSHOOT;
    let mut spoof_id_bytes = peer_head_bytes;
    spoof_id_bytes[..8].copy_from_slice(&spoof_num.to_be_bytes());
    let spoof_head_id =
        tron_types::BlockId::from_raw(spoof_id_bytes);
    eprintln!(
        "[phase 2] reconnecting; spoof head: num={} (peer head +{})",
        spoof_num, SPOOF_OVERSHOOT
    );

    let mut conn = PeerConnection::dial(&peer_addr).await.expect("phase2 dial");
    let local_endpoint = Endpoint {
        address: b"127.0.0.1".to_vec(),
        address_ipv6: Vec::new(),
        port: 18888,
        node_id: unique_node_id(),
    };
    conn.libp2p_handshake(Libp2pHelloInputs {
        from: local_endpoint.clone(),
        network_id: 11_111,
        version: 2,
        timestamp_ms: now_ms(),
    })
    .await
    .expect("phase2 libp2p handshake");
    conn.handshake(HelloInputs {
        from: local_endpoint,
        version: MAINNET_P2P_VERSION,
        timestamp_ms: now_ms(),
        genesis,
        solid: spoof_head_id,
        head: spoof_head_id,
        node_type: 0,
        lowest_block_num: 0,
        code_version: b"tron-goblin observer/spoofed",
    })
    .await
    .expect("phase2 app handshake");

    eprintln!(
        "[phase 2] handshake complete; observing for {:?}...",
        observation_timeout
    );

    // Listen loop. Respond to peer-initiated keep-alive pings so we
    // don't get dropped mid-observation, but otherwise stay quiet.
    let deadline = Instant::now() + observation_timeout;
    let mut frame_log: Vec<String> = Vec::new();

    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let result = tokio::time::timeout(remaining, conn.next_frame()).await;

        match result {
            Ok(Ok(Some(frame))) => {
                let summary = format!("{:?} ({} bytes)", frame.ty, frame.payload.len());
                eprintln!("recv: {summary}");
                frame_log.push(summary);

                match frame.ty {
                    MessageType::Inventory => {
                        // `AdvService.broadcast` → `InventoryMessage` →
                        // wire type 0x06. Payload is `Inventory{type,
                        // ids}`; type 0 = BLOCK, 1 = TRX. Only the
                        // BLOCK adv is the live-tip notification we
                        // care about — tx advs are also broadcast on
                        // this wire but represent pending pool entries
                        // (Tier-2 territory).
                        let inv = Inventory::decode(frame.payload)
                            .expect("decode Inventory");
                        let is_block = inv.r#type
                            == inventory::InventoryType::Block as i32;
                        eprintln!(
                            "✓ Inventory adv received from live peer (type={} {}, {} ids)",
                            inv.r#type,
                            if is_block { "BLOCK" } else { "TRX" },
                            inv.ids.len()
                        );
                        for hash in &inv.ids {
                            // First 8 bytes of a BLOCK id are the
                            // block number in BE.
                            let display = if is_block && hash.len() >= 8 {
                                let num = u64::from_be_bytes(
                                    hash[..8].try_into().unwrap_or([0u8; 8]),
                                );
                                format!("block {} hash {}", num, hex::encode(hash))
                            } else {
                                format!("hash {}", hex::encode(hash))
                            };
                            eprintln!("  {display}");
                        }
                        if is_block {
                            // Live-tip BLOCK adv observed. Done.
                            return;
                        }
                        // tx adv — keep listening for a BLOCK one.
                    }
                    MessageType::P2pPing => {
                        // java-tron's PingMessage payload is the
                        // fixed RLP-empty-list byte 0xC0; an empty
                        // pong would fail PongMessage.valid() and
                        // trigger BAD_MESSAGE.
                        let _ = conn
                            .send_frame(Frame {
                                ty: MessageType::P2pPong,
                                payload: Bytes::from_static(&[0xC0]),
                            })
                            .await;
                    }
                    MessageType::Libp2pKeepAlivePing => {
                        // libp2p's PongMessage requires a fresh
                        // timestamp in the KeepAliveMessage proto;
                        // empty/zero would fail validation.
                        let pong = KeepAliveMessage { timestamp: now_ms() };
                        let _ = conn
                            .send_frame(Frame {
                                ty: MessageType::Libp2pKeepAlivePong,
                                payload: pong.encode_to_vec().into(),
                            })
                            .await;
                    }
                    MessageType::SyncBlockChain => {
                        // Peer is asking us for blocks (because we
                        // claimed to be ahead via SPOOF_OVERSHOOT).
                        // Respond with a 1-id `ChainInventory`
                        // pointing at peer's own head — which peer
                        // will recognize via
                        // `tronNetDelegate.containBlock(blockIdWeGet.peek())`
                        // and immediately call
                        // `peer.setNeedSyncFromPeer(false)`
                        // + `setTronState(SYNC_COMPLETED)`. That
                        // flips us into the `AdvService.broadcast`
                        // eligible bucket without our needing to
                        // serve up real blocks.
                        let resp = ChainInventory {
                            ids: vec![chain_inventory::BlockId {
                                hash: peer_head_bytes.to_vec(),
                                number: peer_head_num as i64,
                            }],
                            remain_num: 0,
                        };
                        conn.send_frame(Frame {
                            ty: MessageType::BlockChainInventory,
                            payload: resp.encode_to_vec().into(),
                        })
                        .await
                        .expect("send ChainInventory response");
                        eprintln!("  → responded with ChainInventory([peer_head], 0)");
                    }
                    MessageType::P2pDisconnect => {
                        panic!(
                            "peer app-disconnected mid-observation; frames: {:?}",
                            frame_log
                        );
                    }
                    MessageType::Libp2pDisconnect => {
                        panic!(
                            "peer libp2p-disconnected mid-observation; frames: {:?}",
                            frame_log
                        );
                    }
                    _ => {} // ignore — Trx broadcasts, etc.
                }
            }
            Ok(Ok(None)) => panic!(
                "peer closed connection; frames seen: {:?}",
                frame_log
            ),
            Ok(Err(e)) => panic!(
                "frame error: {e}; frames seen: {:?}",
                frame_log
            ),
            Err(_) => break, // overall timeout
        }
    }

    panic!(
        "no BlockInventory adv received within {:?}; frames seen: {:?}",
        observation_timeout, frame_log
    );
}
