//! **Live diagnostic** — runs the FULL handshake (libp2p connection layer
//! + application HelloMessage) against a pool of real, recently-seen
//! mainnet full nodes (not the always-saturated hardcoded seeds), and
//! classifies exactly where each peer accepts or rejects us.
//!
//! Purpose: the saturated seeds disconnect at the libp2p layer with
//! TOO_MANY_PEERS before we can test the APP-level Hello, which is where
//! `BAD_PROTOCOL` was observed in production. This probe reaches that layer.
//!
//! Run: `cargo test -p tron-net --test app_handshake_probe -- --ignored --nocapture`

use std::time::Duration;

use prost::Message as _;
use tokio::time::timeout;
use tron_net::{HandshakeOutcome, HelloInputs, Libp2pHelloInputs, PeerConnection};
use tron_proto::Endpoint;
use tron_types::genesis::{genesis_block_id, mainnet_inputs};

/// Recently-seen mainnet full nodes (from a live node's peer_state.json).
const PEERS: &[&str] = &[
    "134.199.141.141:18888", "138.201.152.19:18888", "174.138.103.97:18888",
    "103.161.224.78:18888", "103.236.100.131:18888", "103.57.60.162:18888",
    "103.81.87.82:18888", "104.156.237.116:18888", "104.196.225.61:18888",
    "106.195.5.3:18888", "107.167.35.82:18888", "107.191.50.251:18888",
    "107.191.50.60:18888", "111.119.234.40:18888", "112.95.162.131:18888",
    "116.202.157.52:18888", "116.202.84.179:18888", "118.253.150.146:18888",
    "122.10.112.135:18888", "123.118.13.223:18888", "123.245.3.106:18888",
    "1.234.54.78:18888", "125.119.154.236:18888", "125.70.99.114:18888",
    "128.130.122.72:18888", "128.241.236.68:18888", "129.127.218.245:18888",
    "129.80.30.43:18888", "130.61.111.231:18888", "131.130.126.84:18888",
    "13.213.16.27:18888", "13.213.36.147:18888", "13.215.184.117:18888",
    "13.222.106.11:18888", "132.226.202.1:18888", "13.223.97.187:18888",
    "13.228.119.63:18888", "13.228.174.157:18888", "13.228.221.81:18888",
    "13.229.85.196:18888", "134.199.141.141:18888", "134.65.195.124:18888",
    "135.125.87.178:18888", "136.107.136.112:18888", "136.243.106.37:18888",
    "136.243.131.143:18888", "138.124.187.18:18888", "138.197.60.5:18888",
    "138.201.152.19:18888", "138.2.22.150:18888", "139.180.152.184:18888",
    "159.223.151.127:18888", "174.138.103.97:18888",
];

#[tokio::test]
#[ignore = "live network — dials real mainnet peers"]
async fn app_handshake_against_real_peers() {
    let genesis = genesis_block_id(&mainnet_inputs());
    // Match the production node's advertised handshake fields exactly.
    let node_id = vec![0xABu8; 64];

    let (mut libp2p_sat, mut libp2p_other) = (0u32, 0u32);
    let (mut app_verified, mut app_implicit, mut app_badproto, mut app_other) = (0u32, 0u32, 0u32, 0u32);
    let (mut conn_fail, mut total) = (0u32, 0u32);

    for &peer in PEERS.iter().take(3) {
        total += 1;
        let node_id = node_id.clone();
        let work = async move {
            let mut conn = PeerConnection::dial(peer).await
                .map_err(|e| format!("dial: {e}"))?;
            conn.libp2p_handshake(Libp2pHelloInputs {
                from: Endpoint { address: b"127.0.0.1".to_vec(), address_ipv6: vec![], port: 18888, node_id: node_id.clone() },
                network_id: 11_111,
                version: 2,
                timestamp_ms: 1_700_000_000_000,
            }).await.map_err(|e| format!("libp2p: {e}"))?;

            let outcome = conn.handshake(HelloInputs {
                from: Endpoint { address: b"127.0.0.1".to_vec(), address_ipv6: vec![], port: 18888, node_id: node_id.clone() },
                version: 11_111,
                timestamp_ms: 1_700_000_000_000,
                genesis,
                solid: genesis,
                head: genesis,
                node_type: 0,
                lowest_block_num: 0,
                code_version: b"tron-goblin/0.0.1",
            }).await.map_err(|e| format!("app: {e}"))?;
            Ok::<_, String>((conn, outcome))
        };

        match timeout(Duration::from_secs(6), work).await {
            Ok(Ok((mut conn, outcome))) => {
                match &outcome {
                    HandshakeOutcome::Verified(h) => {
                        app_verified += 1;
                        eprintln!("[{peer}] APP VERIFIED (peer head={})",
                            h.head_block_id.as_ref().map(|b| b.number).unwrap_or(-1));
                    }
                    HandshakeOutcome::ImplicitAccept => {
                        app_implicit += 1;
                        eprintln!("[{peer}] APP IMPLICIT-ACCEPT (peer streamed instead of Hello)");
                    }
                }
                // PHASE A: read what the peer sends UNPROMPTED right after
                // handshake (we send nothing) — reveals whether it asks us
                // to serve it (SyncBlockChain / FetchInvData) and disconnects
                // when we don't.
                let unprompted = timeout(Duration::from_secs(8), async {
                    let mut seen = Vec::new();
                    for _ in 0..4 {
                        match conn.next_frame().await {
                            Ok(Some(f)) => {
                                let label = format!("{:?}", f.ty);
                                if label.contains("Disconnect") {
                                    let reason = tron_proto::DisconnectMessage::decode(f.payload.clone()).map(|d| d.reason).unwrap_or(-999);
                                    seen.push(format!("{label}(reason={reason})"));
                                    break;
                                }
                                seen.push(label);
                            }
                            Ok(None) => { seen.push("EOF".into()); break; }
                            Err(e) => { seen.push(format!("ERR:{e}")); break; }
                        }
                    }
                    seen
                }).await;
                eprintln!("[{peer}]   UNPROMPTED post-handshake frames: {:?}", unprompted);

                // Now test SYNC SERVING: send a SyncBlockChain anchored at
                // genesis (a fresh-node locator every peer can satisfy) and
                // see what comes back over the next few seconds.
                let genesis_id = genesis;
                if let Err(e) = tron_net::sync::send_sync_request(&mut conn, &[genesis_id]).await {
                    eprintln!("[{peer}]   sync: send_sync_request failed: {e}");
                } else {
                    let sync_probe = timeout(Duration::from_secs(5), async {
                        let mut seen = Vec::new();
                        for _ in 0..3 {
                            match conn.next_frame().await {
                                Ok(Some(f)) => {
                                    let label = format!("{:?}", f.ty);
                                    let stop = label.contains("Disconnect");
                                    if stop {
                                        // Decode the disconnect reason.
                                        let reason = tron_proto::DisconnectMessage::decode(f.payload.clone())
                                            .map(|d| d.reason)
                                            .unwrap_or(-999);
                                        seen.push(format!("{label}(reason={reason})"));
                                        break;
                                    }
                                    seen.push(label);
                                }
                                Ok(None) => { seen.push("EOF".into()); break; }
                                Err(e) => { seen.push(format!("ERR:{e}")); break; }
                            }
                        }
                        seen
                    }).await;
                    match sync_probe {
                        Ok(frames) => eprintln!("[{peer}]   sync reply frames: {:?}", frames),
                        Err(_) => eprintln!("[{peer}]   sync: NO reply within 5s (peer ignored SyncBlockChain)"),
                    }
                }
            }
            Ok(Err(e)) => {
                if e.starts_with("libp2p:") {
                    // Saturation/cooldown codes are benign.
                    if e.contains("Libp2pDisconnected(1)") || e.contains("Libp2pDisconnected(3)")
                        || e.contains("Libp2pDisconnected(4)") || e.contains("Libp2pDisconnected(5)") {
                        libp2p_sat += 1;
                    } else {
                        libp2p_other += 1;
                        eprintln!("[{peer}] {e}");
                    }
                } else if e.starts_with("app:") {
                    if e.contains("BadProtocol") || e.contains("BAD_PROTOCOL") || e.contains("(2)") {
                        app_badproto += 1;
                        eprintln!("[{peer}] {e}  <<< APP BAD_PROTOCOL");
                    } else {
                        app_other += 1;
                        eprintln!("[{peer}] {e}");
                    }
                } else {
                    conn_fail += 1;
                }
            }
            Err(_) => { conn_fail += 1; }
        }
    }

    eprintln!("\n================ SUMMARY ({total} peers) ================");
    eprintln!("conn refused/timeout         : {conn_fail}");
    eprintln!("libp2p saturated (1/3/4/5)   : {libp2p_sat}");
    eprintln!("libp2p OTHER reject          : {libp2p_other}");
    eprintln!("APP verified (full hello)    : {app_verified}");
    eprintln!("APP implicit-accept          : {app_implicit}");
    eprintln!("APP BAD_PROTOCOL             : {app_badproto}  <<<");
    eprintln!("APP other reject             : {app_other}");
    eprintln!("reached-app-layer total      : {}", app_verified + app_implicit + app_badproto + app_other);
}
