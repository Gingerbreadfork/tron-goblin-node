//! Wiring tests for `P2pRateLimiter` + `RateLimiterP2pConfig`.
//!
//! The runtime / SyncDriver registers per-frame-type buckets at peer
//! handshake time. These tests confirm:
//!   * defaults match java-tron exactly (3/3/1 qps for
//!     SYNC_BLOCK_CHAIN / FETCH_INV_DATA / P2P_DISCONNECT),
//!   * unregistered frame types pass through unlimited,
//!   * exhausted buckets reject subsequent acquires until refill,
//!   * the time-based refill restores tokens at the configured rate.
//!
//! Frame-receive-side enforcement (drop on `!try_acquire`) is part
//! of the SyncDriver inner loop — covered indirectly by the
//! tron-node integration tests against a live duplex; this file
//! covers the configuration boundary.

use std::time::Duration;
use tron_net::MessageType;
use tron_node::config::RateLimiterP2pConfig;
use tron_node::p2p_rate_limiter::P2pRateLimiter;

fn install_defaults(limiter: &P2pRateLimiter, cfg: &RateLimiterP2pConfig) {
    limiter.register(
        MessageType::SyncBlockChain.as_byte(),
        cfg.sync_block_chain,
    );
    limiter.register(MessageType::FetchInvData.as_byte(), cfg.fetch_inv_data);
    limiter.register(MessageType::P2pDisconnect.as_byte(), cfg.disconnect);
}

#[test]
fn default_config_matches_java_tron_qps() {
    let cfg = RateLimiterP2pConfig::default();
    assert_eq!(cfg.sync_block_chain, 3.0);
    assert_eq!(cfg.fetch_inv_data, 3.0);
    assert_eq!(cfg.disconnect, 1.0);
}

#[test]
fn registered_frame_types_consume_one_permit_per_acquire() {
    let cfg = RateLimiterP2pConfig::default();
    let lim = P2pRateLimiter::new();
    install_defaults(&lim, &cfg);

    // Each bucket starts with one permit. First acquire succeeds,
    // second (within < 1/rate seconds) fails.
    assert!(lim.try_acquire(MessageType::SyncBlockChain.as_byte()));
    assert!(!lim.try_acquire(MessageType::SyncBlockChain.as_byte()));

    assert!(lim.try_acquire(MessageType::FetchInvData.as_byte()));
    assert!(!lim.try_acquire(MessageType::FetchInvData.as_byte()));

    assert!(lim.try_acquire(MessageType::P2pDisconnect.as_byte()));
    assert!(!lim.try_acquire(MessageType::P2pDisconnect.as_byte()));
}

#[test]
fn unregistered_frame_types_pass_through_unlimited() {
    let cfg = RateLimiterP2pConfig::default();
    let lim = P2pRateLimiter::new();
    install_defaults(&lim, &cfg);

    // Block / Trx / Inventory / TrxInventory / Trxs / BlockChainInventory
    // / Inventory / ItemNotFound / PbftMsg / KeepAlive frame types are
    // NOT registered — must always permit.
    let unrestricted = [
        MessageType::Block,
        MessageType::Trx,
        MessageType::Trxs,
        MessageType::Inventory,
        MessageType::BlockChainInventory,
        MessageType::ItemNotFound,
        MessageType::PbftMsg,
        MessageType::Libp2pKeepAlivePing,
        MessageType::Libp2pKeepAlivePong,
    ];
    for ty in unrestricted {
        for _ in 0..100 {
            assert!(
                lim.try_acquire(ty.as_byte()),
                "unregistered type {ty:?} must always permit"
            );
        }
    }
}

#[test]
fn bucket_refills_after_sleep_at_configured_rate() {
    let cfg = RateLimiterP2pConfig::default();
    let lim = P2pRateLimiter::new();
    install_defaults(&lim, &cfg);
    // Drain the SYNC_BLOCK_CHAIN bucket.
    assert!(lim.try_acquire(MessageType::SyncBlockChain.as_byte()));
    assert!(!lim.try_acquire(MessageType::SyncBlockChain.as_byte()));
    // At 3/sec, one permit refills in ~333ms. Sleep 400ms to be safe.
    std::thread::sleep(Duration::from_millis(400));
    assert!(lim.try_acquire(MessageType::SyncBlockChain.as_byte()));
}

#[test]
fn config_with_zero_rate_blocks_after_initial_burst() {
    // Operator-tuned override: zero-rate effectively disables the
    // frame type after the initial 1-permit burst. Confirms our
    // bucket impl is sane under rate=0 (no division-by-zero, etc).
    let cfg = RateLimiterP2pConfig {
        sync_block_chain: 0.0,
        fetch_inv_data: 3.0,
        disconnect: 1.0,
    };
    let lim = P2pRateLimiter::new();
    install_defaults(&lim, &cfg);
    // Initial burst permit available, then permanently denied.
    assert!(lim.try_acquire(MessageType::SyncBlockChain.as_byte()));
    for _ in 0..10 {
        assert!(!lim.try_acquire(MessageType::SyncBlockChain.as_byte()));
    }
    // Even after sleep, no refill happens at rate=0.
    std::thread::sleep(Duration::from_millis(50));
    assert!(!lim.try_acquire(MessageType::SyncBlockChain.as_byte()));
}

#[test]
fn config_with_high_rate_allows_burst() {
    // 100 qps → initial 1-permit burst, then refill every 10ms.
    let cfg = RateLimiterP2pConfig {
        sync_block_chain: 100.0,
        fetch_inv_data: 100.0,
        disconnect: 1.0,
    };
    let lim = P2pRateLimiter::new();
    install_defaults(&lim, &cfg);

    // First permit consumed immediately.
    assert!(lim.try_acquire(MessageType::SyncBlockChain.as_byte()));
    // After 25ms sleep: ~2.5 permits worth of refill but capped at 1.
    std::thread::sleep(Duration::from_millis(25));
    assert!(lim.try_acquire(MessageType::SyncBlockChain.as_byte()));
}
