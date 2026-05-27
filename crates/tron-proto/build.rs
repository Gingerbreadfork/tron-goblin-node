//! Generate Rust types from java-tron's `.proto` files via `prost-build`.
//!
//! Scope: data messages + `api/api.proto` message types (the request /
//! response shapes for the wallet gRPC). Service definitions
//! themselves live in `tron-grpc` via `tonic-build`, which uses
//! `extern_path` to reference the types generated here.
//!
//! `api/api.proto` imports `google/api/annotations.proto` but never
//! uses anything from it — we vendor a STUB at
//! `vendored/google/api/annotations.proto` so the import resolves
//! without dragging in the real `googleapis` types.
//!
//! ## Proto source
//!
//! By default reads the vendored java-tron protos from
//! `vendored/java-tron/`. To rebuild against a live java-tron checkout
//! (useful when chasing an upstream wire change before re-vendoring),
//! set the `JAVA_TRON_PROTO_ROOT` env var to a directory containing
//! `core/`, `core/contract/`, and `api/` subtrees — typically
//! `<java-tron>/protocol/src/main/protos`.

use std::path::PathBuf;

fn main() {
    // Live override → vendored fallback. Vendored is what the public
    // repo ships; the override is a development convenience.
    let proto_root: PathBuf = match std::env::var_os("JAVA_TRON_PROTO_ROOT") {
        Some(p) => PathBuf::from(p),
        None => ["vendored", "java-tron"].iter().collect(),
    };
    println!("cargo:rerun-if-env-changed=JAVA_TRON_PROTO_ROOT");
    let vendored: PathBuf = ["vendored"].iter().collect();

    let core = proto_root.join("core");
    let contract = core.join("contract");
    let api = proto_root.join("api");

    let inputs: Vec<PathBuf> = vec![
        core.join("Tron.proto"),
        core.join("Discover.proto"),
        core.join("TronInventoryItems.proto"),
        contract.join("common.proto"),
        contract.join("account_contract.proto"),
        contract.join("asset_issue_contract.proto"),
        contract.join("balance_contract.proto"),
        contract.join("exchange_contract.proto"),
        contract.join("market_contract.proto"),
        contract.join("proposal_contract.proto"),
        contract.join("shield_contract.proto"),
        contract.join("smart_contract.proto"),
        contract.join("storage_contract.proto"),
        contract.join("vote_asset_contract.proto"),
        contract.join("witness_contract.proto"),
        // Vendored libp2p connection-layer messages — not present in
        // java-tron's submodule because libp2p is a separate repo.
        vendored.join("Connect.proto"),
        // Vendored libp2p DNS-discovery messages (DnsRoot, EndPoints) —
        // same reason: they live in the libp2p submodule, not core.
        vendored.join("Dns.proto"),
        // gRPC wallet API. Message types only (TransactionExtention,
        // AccountBalanceRequest, NodeList, etc.); the `service` blocks
        // are picked up separately in `tron-grpc`'s tonic-build pass
        // via `extern_path` referencing back to the types compiled
        // here.
        api.join("api.proto"),
    ];

    for path in &inputs {
        println!("cargo:rerun-if-changed={}", path.display());
        assert!(path.exists(), "missing proto: {}", path.display());
    }

    let mut config = prost_build::Config::new();
    // Use BTreeMap for every proto `map<K,V>` field. The prost default
    // is HashMap, which iterates in random order — and protobuf map
    // fields are encoded as repeated MapEntry records in encounter
    // order, so HashMap produces non-deterministic bytes. java-tron's
    // LinkedHashMap-backed encoders write keys in a deterministic
    // order; BTreeMap (sorted by key) matches that and gives us a
    // stable serialized form. Without this, two writes of the same
    // logical Account / Proposal produce different bytes and the
    // byte-exact RocksDB / state-root parity claim breaks for any
    // entity carrying multiple map entries.
    config.btree_map(["."]);
    config
        .compile_protos(&inputs, &[&proto_root, &vendored])
        .expect("prost codegen failed");

    // Re-run if api.proto or the google stub change.
    println!("cargo:rerun-if-changed={}", api.join("api.proto").display());
    println!(
        "cargo:rerun-if-changed={}",
        vendored.join("google/api/annotations.proto").display()
    );
}
