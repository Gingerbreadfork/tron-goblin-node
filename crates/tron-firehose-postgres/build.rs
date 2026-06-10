//! Generate the firehose client stubs from this crate's own copy of
//! `firehose.proto`, so the reference consumer builds standalone
//! (vendored, published, or checked out without the workspace). The
//! copy is pinned against the node's authoritative file by an
//! in-workspace test (`proto_copy_matches_the_nodes`) — drift fails CI
//! rather than silently diverging the wire format.

fn main() {
    let proto = std::path::PathBuf::from("proto/firehose.proto");
    println!("cargo:rerun-if-changed={}", proto.display());
    tonic_build::configure()
        .build_client(true)
        .build_server(false)
        .compile_protos(&[proto], &[std::path::PathBuf::from("proto")])
        .expect("firehose client codegen failed");
}
