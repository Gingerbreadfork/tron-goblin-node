//! gRPC server for the java-tron Wallet / WalletSolidity / Network /
//! Database / Monitor surface.
//!
//! Mirrors java-tron's port-50051 API so TronWeb, the Java SDK, and
//! TronGrid clients can connect to a tron-goblin-node unchanged.
//!
//! ## Architecture
//!
//! 1. `tron-proto` compiles `api/api.proto` for the message types
//!    (lands at `tron_proto::protocol::*`).
//! 2. This crate's `build.rs` uses tonic-build with
//!    `extern_path(".protocol", "::tron_proto::protocol")` so service
//!    stubs reference the existing types without regenerating them.
//! 3. The generated module — the `mod proto` below — exposes the
//!    `wallet_server::Wallet` trait + `WalletServer<T>` wrapper, plus
//!    the same shape for `WalletSolidity` / `Database` / `Monitor` /
//!    `Network`.
//! 4. We `impl Wallet for WalletService` (and the other traits for the
//!    other services), delegating each method to a small wrapper
//!    around existing `tron-rpc` handlers — converting between
//!    Status/proto and the JSON-RPC method signatures.
//! 5. `start_server(state, addr)` boots `tonic::transport::Server` on
//!    the chosen address; the daemon spawns it alongside the JSON-RPC
//!    server.

/// Generated tonic stubs from `api/api.proto`. The crate's
/// pre-compiled message types come from `tron_proto::protocol::*` via
/// the `extern_path` in `build.rs`.
pub mod proto {
    tonic::include_proto!("protocol");
}

mod database;
mod monitor;
mod prover;
mod service;
mod shielded;
mod wallet_extension;
mod wallet_solidity;
mod zen_builder;

pub use service::{start_server, WalletService};
