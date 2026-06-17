//! Ethereum-compatible + TRON-native JSON-RPC server backed by
//! `tron-chainbase` state. Covers the most-used read-side methods that
//! wallets, block explorers, and dapps expect, plus the TRON-native
//! endpoints java-tron exposes via gRPC.
//!
//! **Not implemented** (require infrastructure outside this crate):
//!
//! * `eth_sendRawTransaction` / `broadcastTransaction` — needs P2P
//!   broadcast + mempool. Returns method-not-supported.
//! * `eth_getProof` — Merkle Patricia state proofs are not yet built.
//! * `eth_newFilter` family — server-side filter state machine.

pub mod abi;
pub mod blocking;
pub mod builder;
pub mod filters;
pub mod http_rest;
pub mod index_api;
pub use index_api::ArchiveApiState;
pub mod mempool;
pub mod metrics;
pub mod pubsub;
pub mod rate_limit;
pub mod server;
pub mod methods;
pub mod state;

pub use filters::{FilterKind, FilterRegistry, LogFilter};
pub use mempool::{InMemoryMempool, Mempool, SubmitOutcome};
pub use metrics::Metrics;
pub use pubsub::{HeadEvent, LogEvent, PubSubBroker, SyncEvent};
pub mod lite_gate;
pub use rate_limit::{
    build_rate_limit, component_for_http_path, normalize_component, parse_params,
    GlobalRateLimiter, IpQpsBuckets, PreemptibleCounter, QpsBucket, RateLimit,
    RateLimitRegistry,
};
pub use server::{serve, RpcServer};
pub use state::{EthCallBackends, RpcState};

/// TRON mainnet chain id used by `eth_chainId` and `net_version`. java-tron
/// returns this as the hex-encoded chain id; we expose the raw integer.
pub const MAINNET_CHAIN_ID: u64 = 11_111;
