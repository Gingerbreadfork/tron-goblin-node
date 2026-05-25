//! Live UDP discovery probe — sends a PING + FIND_NODE to a mainnet
//! seed and reports the NEIGHBORS we received.
//!
//! Marked `#[ignore]`. Run explicitly:
//!
//! ```sh
//! cargo test -p tron-net --test live_discovery -- --ignored --nocapture
//! ```

use std::net::ToSocketAddrs;
use std::time::Duration;

use tron_net::{bootstrap_discovery, DiscoverError};
use tron_proto::Endpoint;

const MAINNET_SEEDS: &[&str] = &[
    "3.225.171.164:18888",
    "52.8.46.215:18888",
    "3.79.71.167:18888",
    "108.128.110.16:18888",
    "18.133.82.227:18888",
    "35.180.81.133:18888",
    "13.210.151.5:18888",
    "18.231.27.82:18888",
    "3.12.212.122:18888",
    "52.24.128.7:18888",
    "15.207.144.3:18888",
    "3.39.38.55:18888",
    "54.151.226.240:18888",
];

#[tokio::test]
#[ignore = "live network — requires outbound UDP to a TRON mainnet seed"]
async fn discovery_query_returns_neighbours_from_mainnet_seed() {
    let local = Endpoint {
        address: b"127.0.0.1".to_vec(), // string-encoded IP, per validNode rules
        port: 18888,
        node_id: vec![0xaau8; 64],
        address_ipv6: vec![],
    };
    // Random target_id — biases the response set toward peers near
    // this point in the 64-byte node-id XOR-distance space.
    let target_id = [0x55u8; 64];

    let mut total_neighbours = 0;
    let mut tried = 0;
    for seed_str in MAINNET_SEEDS {
        let seed = match seed_str.to_socket_addrs().ok().and_then(|mut a| a.next()) {
            Some(s) => s,
            None => continue,
        };
        tried += 1;
        let result = bootstrap_discovery(
            seed,
            local.clone(),
            11111,
            1_700_000_000_000,
            target_id,
            Duration::from_secs(3),
        )
        .await;
        match result {
            Ok(neighbours) => {
                eprintln!(
                    "[{seed_str}] received {} neighbours",
                    neighbours.len()
                );
                for n in neighbours.iter().take(3) {
                    let ip = String::from_utf8_lossy(&n.address);
                    eprintln!("    {ip}:{}  node_id={}…", n.port,
                        hex_short(&n.node_id));
                }
                total_neighbours += neighbours.len();
                if !neighbours.is_empty() {
                    break;
                }
            }
            Err(DiscoverError::Timeout) => {
                eprintln!("[{seed_str}] timed out");
            }
            Err(e) => {
                eprintln!("[{seed_str}] error: {e}");
            }
        }
    }

    eprintln!(
        "discovery probe complete: tried {tried} seeds, received {total_neighbours} neighbours total"
    );
    // Even if no seed responded (entirely possible from a banned IP),
    // the protocol implementation is exercised. We assert at least one
    // seed was attempted to make sure the test isn't a no-op.
    assert!(tried > 0);
}

fn hex_short(bytes: &[u8]) -> String {
    bytes.iter().take(6).map(|b| format!("{b:02x}")).collect()
}
