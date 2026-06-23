//! DPoS consensus primitives for TRON.
//!
//! Four sub-modules, each independently testable:
//!
//! * [`slot`] — pure math: given a timestamp and the genesis time,
//!   which absolute slot are we in? Which of the 27 SRs is scheduled
//!   to produce it?
//!
//! * [`validate`] — block-level consensus check: was this block
//!   produced by the SR that the slot scheduler says owns the slot?
//!   This is the consensus gate the executor currently lacks — a
//!   block that's structurally valid but witnessed by the wrong SR
//!   must be rejected.
//!
//! * [`maintenance`] — every ~6 hours (`MAINTENANCE_TIME_INTERVAL`)
//!   the chain enters a maintenance period: vote counts roll over,
//!   the top 27 by vote become the new active SR list, and brokerage
//!   rewards distribute. This module detects the boundary and
//!   provides the SR-ranking update; reward distribution is documented
//!   as deferred (needs cycle-aware reward accumulation that we can
//!   layer on later — see crate-level note on Vi accumulators).
//!
//! * [`fork_choice`] — TRON's fork-choice rule: the longest chain
//!   containing the last solidified block wins. The v1 helper here
//!   implements the simpler "longest by block number, BlockId
//!   tiebreak" form that matches java-tron's behaviour when both
//!   competing heads are on chains containing the same solidified
//!   point. Solidity-aware multi-fork resolution is a follow-up.
//!
//! All four are deliberately stateless: callers pass in the relevant
//! pieces of state (head time, active witness list, etc.) so that the
//! same functions are usable from a syncing node, a block producer,
//! and a fork-choice walker without context switching.

pub mod fork_choice;
pub mod khaos;
pub mod maintenance;
pub mod pbft;
pub mod producer;
pub mod proposals;
pub mod slot;
pub mod solidify;
pub mod sr_epoch;
pub mod validate;

pub use fork_choice::{best_head, best_head_with_solidified, ForkChoice, ForkChoiceError};
pub use khaos::{
    KhaosBlock, KhaosDb, NonCommonBlockError, PushError as KhaosPushError, PushOutcome,
};
pub use pbft::{
    agree_node_count, block_data_payload, cast_commit, cast_prepare, parse_block_data_payload,
    recover_signer, sign_pbft_raw, BlockVoteTally, PbftVoteTally,
};
pub use maintenance::{
    apply_maintenance, compute_next_maintenance_time, is_maintenance_boundary,
    rebuild_asset_v2_from_v1, update_active_witnesses, MaintenanceOutcome, MaintenanceReport,
    DEFAULT_MAINTENANCE_INTERVAL_MS,
};
pub use slot::{
    ab_slot, scheduled_witness, scheduled_witness_index, slot_from_head, slot_time_ms,
    BLOCK_FILLED_SLOTS_NUMBER, BLOCK_PRODUCED_INTERVAL_MS, MAX_ACTIVE_WITNESS_NUM, SINGLE_REPEAT,
    SOLIDIFIED_THRESHOLD_PCT,
};
pub use producer::{assemble_block, encode_for_broadcast, produce_block, ProducerError};
pub use proposals::{activate_expired_proposals, parameter_id_to_key, ProposalActivationReport};
pub use solidify::{latest_solid_block, solid_block_from_witnesses, solidity_threshold, RecentBlock};
pub use sr_epoch::{shared_from_current, SharedSrEpochSnapshot, SrEpochSnapshot};
pub use validate::{
    validate_block_consensus, verify_block_witness, ConsensusError, MAINTENANCE_SKIP_SLOTS,
};
