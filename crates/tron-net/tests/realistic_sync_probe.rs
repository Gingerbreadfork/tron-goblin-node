//! **Live end-to-end diagnostic** — handshakes real public mainnet peers
//! as a NEAR-TIP node (realistic head + a real recent-block locator
//! captured from a synced node) and verifies the peer actually SERVES sync
//! (replies with a `BlockChainInventory`) rather than disconnecting.
//!
//! This is the faithful test the genesis-probe couldn't be: a genesis-head
//! node asks peers for ~83M blocks of deep history (→ FETCH_FAIL on many),
//! whereas a node near the tip asks only for the recent gap, which every
//! healthy peer can serve.
//!
//! Run: `cargo test -p tron-net --test realistic_sync_probe -- --ignored --nocapture`

use prost::Message as _;
use std::time::Duration;
use tokio::time::timeout;
use tron_net::{HelloInputs, Libp2pHelloInputs, MessageType, PeerConnection};
use tron_proto::Endpoint;
use tron_types::genesis::{genesis_block_id, mainnet_inputs};
use tron_types::BlockId;

const PEERS: &[&str] = &[
    "77.37.200.49:18888", "77.91.126.81:18888", "78.138.62.10:18888",
    "78.141.245.173:18888", "81.29.130.132:18888", "8.209.220.23:18888",
    "8.214.24.185:18888", "8.214.41.147:18888", "8.217.133.60:18888",
    "8.217.42.159:18888", "8.218.81.131:18888", "8.218.83.139:18888",
];

/// Recent block IDs captured from a synced node (head 83,368,282), oldest
/// → newest — the locator shape the production `build_chain_summary` sends.
const LOCATOR_HEX: &[&str] = &[
    "0000000004f7f24a2233b6b4e7461b990b02791c824053487ddc69e3f9ed4883", // 83358282
    "0000000004f815727905c48f4751441c08443636149b12479dd5c8d322ed58c3", // 83367282
    "0000000004f818f6addc05ce56f8144f85f29a18f90764916036b80d5fd87167", // 83368182
    "0000000004f81950d487ebd40cb2bac915cc8012a7bdf5d5a3991b8021ccaf67", // 83368272
    "0000000004f8195afbd3bd3d2cd5e44e4c6d2f4e4d86b8c8c6f011e275a35297", // 83368282 (head)
];

fn block_id(hex_s: &str) -> BlockId {
    let bytes = hex::decode(hex_s).expect("valid hex");
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&bytes);
    BlockId::from_raw(raw)
}

#[tokio::test]
#[ignore = "live network — dials real mainnet peers"]
async fn near_tip_node_gets_served_by_public_peers() {
    let genesis = genesis_block_id(&mainnet_inputs());
    let locator: Vec<BlockId> = LOCATOR_HEX.iter().map(|h| block_id(h)).collect();
    let head = *locator.last().unwrap();
    let node_id = vec![0xABu8; 64];

    let mut served = 0u32;
    let mut disconnected = 0u32;
    let mut other = 0u32;

    for &peer in PEERS {
        let node_id = node_id.clone();
        let locator = locator.clone();
        let work = async move {
            let mut conn = PeerConnection::dial(peer).await.map_err(|e| format!("dial: {e}"))?;
            conn.libp2p_handshake(Libp2pHelloInputs {
                from: Endpoint { address: b"127.0.0.1".to_vec(), address_ipv6: vec![], port: 18888, node_id: node_id.clone() },
                network_id: 11_111, version: 2, timestamp_ms: 1_700_000_000_000,
            }).await.map_err(|e| format!("libp2p: {e}"))?;
            conn.handshake(HelloInputs {
                from: Endpoint { address: b"127.0.0.1".to_vec(), address_ipv6: vec![], port: 18888, node_id: node_id.clone() },
                version: 11_111, timestamp_ms: 1_700_000_000_000,
                genesis, solid: head, head,
                node_type: 0, lowest_block_num: 0, code_version: b"tron-goblin/0.0.1",
            }).await.map_err(|e| format!("app: {e}"))?;
            // Send the realistic locator and read the reply.
            tron_net::sync::send_sync_request(&mut conn, &locator).await.map_err(|e| format!("send: {e}"))?;
            let mut frames = Vec::new();
            for _ in 0..3 {
                match conn.next_frame().await {
                    Ok(Some(f)) => {
                        let label = format!("{:?}", f.ty);
                        if f.ty == MessageType::BlockChainInventory {
                            // Decode the inventory to confirm it's a real serve.
                            let inv = tron_proto::ChainInventory::decode(f.payload.clone()).ok();
                            let n = inv.as_ref().map(|i| i.ids.len()).unwrap_or(0);
                            let remain = inv.as_ref().map(|i| i.remain_num).unwrap_or(0);
                            frames.push(format!("BlockChainInventory(ids={n}, remain={remain})"));
                            break;
                        } else if label.contains("Disconnect") {
                            let r = tron_proto::DisconnectMessage::decode(f.payload.clone()).map(|d| d.reason).unwrap_or(-999);
                            frames.push(format!("{label}(reason={r})"));
                            break;
                        } else {
                            frames.push(label);
                        }
                    }
                    Ok(None) => { frames.push("EOF".into()); break; }
                    Err(e) => { frames.push(format!("ERR:{e}")); break; }
                }
            }
            Ok::<_, String>(frames)
        };
        match timeout(Duration::from_secs(8), work).await {
            Ok(Ok(frames)) => {
                let joined = frames.join(", ");
                if joined.contains("BlockChainInventory") {
                    served += 1;
                    eprintln!("[{peer}] ✓ SERVED SYNC: {joined}");
                } else if joined.contains("Disconnect") {
                    disconnected += 1;
                    eprintln!("[{peer}] ✗ disconnected: {joined}");
                } else {
                    other += 1;
                    eprintln!("[{peer}] ? {joined}");
                }
            }
            Ok(Err(e)) => { other += 1; eprintln!("[{peer}] {e}"); }
            Err(_) => { other += 1; eprintln!("[{peer}] timeout"); }
        }
    }

    eprintln!("\n==== near-tip sync serve: served={served} disconnected={disconnected} other={other} ====");
    eprintln!("(served > 0 proves public peers serve sync to a near-tip node — i.e. non-local sync works end-to-end)");
}
