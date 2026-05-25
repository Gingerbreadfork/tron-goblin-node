//! Library surface for the `tron-replay` CLI.
//!
//! Most of the work lives in `src/main.rs`. This lib file is
//! intentionally near-empty after the `run_sync_loop` deprecation —
//! production sync is now in `tron-node::sync::SyncDriver`, which
//! persists blocks to `BlockStore` + integrates with KhaosDb fork
//! detection + the BlockUndo log for reorg support.
//!
//! Future re-additions go here when we extract reusable helpers from
//! `main.rs` for integration tests to drive without spawning the
//! binary.
