//! `tron-snapshot-convert` — convert a java-tron **LevelDB** snapshot into
//! this node's **RocksDB** format, deleting each source store as it is
//! converted so peak disk stays near 1x.
//!
//! java-tron stores byte-identical serialized capsule values regardless of
//! the storage engine, so the conversion is a pure key-by-key copy: read
//! every `(key, value)` from each LevelDB store and write it into the
//! corresponding RocksDB store at `data_dir/database/<store>`. No
//! re-serialization, no semantic mapping — a converted snapshot runs
//! identically to the original.
//!
//! This is a separate crate from `tron-node` so the LevelDB reader
//! dependency (`rusty-leveldb`) stays out of the node binary. It depends
//! *down* on `tron-chainbase` for the RocksDB write path, the per-store
//! comparator table, and the shared per-store streaming helper (the same
//! one `tron-node`'s live-import uses).
//!
//! See [`convert`] for the orchestration and [`leveldb_source`] for the
//! reader. Crash-safety / resume is per-store via [`manifest`].

pub mod convert;
pub mod leveldb_source;
pub mod manifest;

pub use convert::{
    convert_from_directory, convert_from_stream, ConvertError, ConvertOptions, ConvertReport,
    StoreOutcome,
};
