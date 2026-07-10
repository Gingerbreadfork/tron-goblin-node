//! tron-index — the node's built-in address-history indexer.
//!
//! A **secondary index** over committed consensus state: the node's
//! own `BlockStore` / `BlockIndexStore` / `TransactionRetStore` are
//! the only inputs, so the index cannot diverge from consensus — it
//! *is* consensus state, re-read. It self-heals by re-reading: every
//! failure mode (crash, reorg, deletion, version bump, scope change)
//! resolves to "re-derive from committed state and close the gap".
//! The index directory is disposable at any time.
//!
//! Architecture (see `working/INDEXER_PLAN.md` for the full design and
//! `working/INDEXER_IMPL_NOTES.md` for where this implementation
//! deliberately deviates):
//!
//! * [`keys`] — namespace-prefixed key codecs in ONE keyspace, so the
//!   cursor commits atomically with rows across namespaces.
//! * [`rows`] — prost-encoded denormalized list-view rows.
//! * [`extract`] — the per-contract-type participant rules + the TRC20
//!   `Transfer` log rule; blocks + stored transaction-info in, index
//!   entries out. One extraction path for backfill and live follow.
//! * [`db`] — meta bookkeeping, atomic batches, format versioning
//!   ("stamp + rebuild", no migrations).
//! * [`engine`] — the unified gap-closing follower (backfill IS the
//!   follower with a large gap) + by-hash reorg reconciliation.
//! * [`query`] — fingerprint-paginated, filterable page reads.

pub mod archive;
pub mod commitment;
pub mod db;
pub mod engine;
pub mod extract;
pub mod firehose_log;
pub mod keys;
pub mod query;
pub mod rows;

pub use archive::{
    ArchiveAtBackend, ArchiveCounters, ArchiveReader, ArchiveWriter, AtHeight, DeltaRef,
    PruneStats, ARCHIVE_FORMAT_VERSION,
};
pub use commitment::{
    default_hashes, leaf_path_for, reconstruct_root, verify_proof, ArchiveResume, BootstrapCursor,
    BuildState, Committed,
    CommitmentBuilder, CommitmentCounters, CommitmentDeltaRef, CommitmentError, CommitmentMeta,
    CommitmentMsg, CommitmentReader, CommitmentStatus, CommitmentStore, LeafPath, NodeBackend,
    NodeHash, NodeOp, Proof, ProofOutcome, ProofStep, ResumeSource, Smt, COMMITMENT_FORMAT_VERSION,
    EMPTY_ROOT,
};
pub use db::{IndexDb, IndexError, InitOutcome, FORMAT_VERSION};
pub use engine::{EngineOptions, IndexCounters, IndexEngine, IndexStatus, Tick};
pub use extract::{
    created_contract_address, extract_block, tx_facts, CaptureSet, TxFacts, TxInfoMatcher,
    TRANSFER_TOPIC,
};
pub use firehose_log::{
    FirehoseLogReader, FirehoseLogWriter, FirehoseTailHandle, ReadPos,
    MAX_FRAME_PAYLOAD as FIREHOSE_MAX_FRAME_PAYLOAD,
};
pub use keys::{Addr, KeyParts};
pub use query::{IndexReader, LogPageRow, LogsPage, Page, PageQuery, PageRow, ReaderStatus};
pub use rows::{InternalRow, LogRow, NativeRow, TokenMeta, Trc20Row, Trc721Row, DIR_FROM, DIR_TO};
