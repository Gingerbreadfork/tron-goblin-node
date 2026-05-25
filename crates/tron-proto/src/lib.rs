//! Protobuf-generated types for the TRON protocol.
//!
//! All messages live under the `protocol` package in java-tron's `.proto`
//! files; prost generates a single `protocol` module that mirrors that.
//!
//! Re-exported from the crate root so call sites can write
//! `tron_proto::Transaction` instead of `tron_proto::protocol::Transaction`.

#![allow(clippy::all)]

pub mod protocol {
    include!(concat!(env!("OUT_DIR"), "/protocol.rs"));
}

/// Vendored libp2p connection-layer messages — the wire layer that
/// wraps every application-level message during a TRON peer session.
/// Generated from `vendored/Connect.proto`. Lives under `tron::libp2p`
/// (one nesting level deeper than `crate::libp2p`) because prost
/// resolves cross-package references with `super::super::protocol::*`,
/// which only works when the package's Rust path matches its dotted
/// proto path.
pub mod tron {
    pub mod libp2p {
        include!(concat!(env!("OUT_DIR"), "/tron.libp2p.rs"));
    }
}
/// Backwards-compat re-export: callers that used `tron_proto::libp2p::*`
/// keep working.
pub use tron::libp2p;

pub use protocol::*;

pub use prost::Message;
