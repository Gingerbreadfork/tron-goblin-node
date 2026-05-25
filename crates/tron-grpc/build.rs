//! Generate **service-only** Rust stubs from `api/api.proto` via
//! tonic-build.
//!
//! Message types (Account, Transaction, TransactionExtention, ...)
//! are already compiled by `tron-proto`'s `prost-build` pass into
//! `tron_proto::protocol::*`. We use tonic-build's `extern_path` to
//! tell it: "every `.protocol.Foo` reference resolves to
//! `tron_proto::protocol::Foo`, don't regenerate the type". The only
//! Rust this crate emits is the gRPC service trait + server +
//! client stubs.

use std::path::PathBuf;

fn main() {
    let proto_root: PathBuf =
        ["..", "..", "java-tron", "protocol", "src", "main", "protos"]
            .iter()
            .collect();
    // Same google/api stub `tron-proto` uses — annotations.proto is
    // imported by api.proto but never referenced.
    let vendored: PathBuf = ["..", "tron-proto", "vendored"].iter().collect();

    let api_proto = proto_root.join("api").join("api.proto");

    println!("cargo:rerun-if-changed={}", api_proto.display());

    tonic_build::configure()
        .build_client(true) // client stubs used by integration tests + downstream consumers
        .build_server(true)
        .build_transport(true)
        .compile_well_known_types(true)
        // Every `.protocol.*` type is already in tron_proto::protocol.
        // Crucially, this prevents tonic-build from regenerating data
        // types (which would conflict with the ones in tron-proto and
        // also break across-crate type identity).
        .extern_path(".protocol", "::tron_proto::protocol")
        .compile_protos(&[api_proto], &[proto_root, vendored])
        .expect("tonic codegen failed");
}
