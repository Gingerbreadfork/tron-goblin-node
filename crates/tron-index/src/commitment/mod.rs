//! Verifiable historical-state commitment layer (opt-in).
//!
//! Manufactures a deterministic keccak256 root over the node's
//! executor-written state surface — the same surface the historical-state
//! archive versions. The root lets a node self-verify it is byte-exact with
//! the canonical chain (compare roots with an independently-bootstrapped node)
//! and serve verifiable inclusion/exclusion proofs ("key K had value V — or
//! was absent — at committed height H").
//!
//! The root is a Sparse Merkle Tree over a fixed-width hash of each composite
//! state key, so it is a pure function of the current `key → value` set —
//! never of the order of per-block deltas. Two nodes that converge to the same
//! state compute byte-identical roots (the history-independence invariant).
//!
//! This subsystem is NOT consensus-critical: it is computed downstream of
//! block commit, may lag head by the configured confirmation lag, and never
//! blocks the apply/sync loop.
//!
//! Module map:
//! * [`smt`] — the pure, byte-exact SMT core (no I/O).
//! * [`store`] — the RocksDB-backed node/leaf/meta store.
//! * [`builder`] — the off-hook fold of write-sets + bootstrap + reorg
//!   handling, with a tokio-free API the runtime task drives.
//! * [`proof`] — standalone proof verification (third-party / on-chain style).
//! * [`reader`] — the cheap-clone read handle for the RPC layer.

pub mod builder;
pub mod proof;
pub mod reader;
pub mod smt;
pub mod store;

pub use builder::{
    ArchiveResume, BuildState, Committed, CommitmentBuilder, CommitmentCounters,
    CommitmentDeltaRef, CommitmentMsg, ResumeSource,
};
pub use proof::{reconstruct_root, verify_proof, ProofOutcome};
pub use reader::{leaf_path_for, CommitmentReader, CommitmentStatus};
pub use smt::{
    default_hashes, hash_internal, hash_leaf, path_bit, CommitmentError, LeafPath, NodeBackend,
    NodeHash, NodeOp, Proof, ProofStep, Smt, DEPTH, EMPTY_ROOT,
};
pub use store::{BootstrapCursor, CommitmentMeta, CommitmentStore, COMMITMENT_FORMAT_VERSION};
