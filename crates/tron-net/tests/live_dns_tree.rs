//! Live DNS tree-discovery probe — walks the mainnet TRON tree and
//! reports the endpoints it found.
//!
//! Marked `#[ignore]`. Run explicitly:
//!
//! ```sh
//! cargo test -p tron-net --test live_dns_tree -- --ignored --nocapture
//! ```

use std::time::Duration;

use tron_net::resolve_dns_tree;

const MAINNET_TREE: &str =
    "tree://AKMQMNAJJBL73LXWPXDI4I5ZWWIZ4AWO34DWQ636QOBBXNFXH3LQS@main.trondisco.net";

#[tokio::test]
#[ignore = "live network — requires outbound DNS"]
async fn resolve_mainnet_tree_returns_endpoints() {
    let started = std::time::Instant::now();
    let result = resolve_dns_tree(MAINNET_TREE, Duration::from_secs(5)).await;
    let elapsed = started.elapsed();
    match result {
        Ok(endpoints) => {
            eprintln!(
                "resolved {} endpoints from mainnet tree in {:.2?}",
                endpoints.len(),
                elapsed
            );
            for ep in endpoints.iter().take(10) {
                eprintln!("  {ep}");
            }
            if endpoints.len() > 10 {
                eprintln!("  … plus {} more", endpoints.len() - 10);
            }
        }
        Err(e) => {
            panic!("tree walk failed: {e}");
        }
    }
}
