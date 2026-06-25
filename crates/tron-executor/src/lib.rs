//! Block-level orchestrator.
//!
//! [`execute_block`] is the entry point. Given a [`StateBackends`]
//! handle to the per-store base KV backends, a [`Block`], and the
//! expected parent [`BlockId`] (or `None` for the genesis case), it:
//!
//! 1. **Structural validation** via [`tron_types`] (read-only against base):
//!    * `parent_hash` links to `expected_parent`
//!    * `tx_trie_root` matches the recomputed Merkle root
//!    * `witness_signature` recovers to `witness_address`
//!
//! 2. **Per-transaction loop with atomic rollback**: for each tx:
//!    * Fork a [`TxSession`] — wraps every store's backend in a
//!      [`tron_chainbase::SessionBackend`], so writes during validate /
//!      execute go to a private overlay.
//!    * Compute `tx_id = sha256(raw_data.encode())`
//!    * `dispatch_validate` → on error: revert the session, record
//!      [`TxOutcome::Invalid`].
//!    * `dispatch_execute` → on error: revert, record
//!      [`TxOutcome::ExecutionFailed`]. On success: commit, record
//!      [`TxOutcome::Success`].
//!    * Either way the session's writes don't leak across tx boundaries —
//!      a failed tx leaves the state untouched.
//!
//! 3. **Head-pointer update** on the base [`DynamicPropertiesStore`]:
//!    * `latest_block_header_number`
//!    * `latest_block_header_timestamp`
//!    * `latest_block_header_hash` (32-byte BlockId)
//!
//! Returns a [`BlockExecutionReport`] with the new head BlockId and
//! per-transaction outcomes.

pub mod adaptive;
pub mod bandwidth;
pub mod energy;
pub mod parallel;
pub mod pipeline;
pub mod resource;
pub mod watchdog;

pub use pipeline::ApplyPipeline;

use std::sync::Arc;

use prost::Message;
use rayon::prelude::*;
use tron_actuator::{
    dispatch_execute, dispatch_validate,
    permission::check_transaction_permission_with_signers, ActuatorError, ActuatorStores,
};
use tron_chainbase::{
    AbiStore, AccountIdIndexStore, AccountIndexStore, AccountStore, AssetIssueStore,
    AssetIssueV2Store, ContractStore, DelegatedResourceStore, DelegationStore,
    DynamicPropertiesStore, ExchangeStore, ExchangeV2Store, IncrementalMerkleTreeStore,
    KvBackend, MarketAccountStore, MarketOrderStore, NullifierStore, ProposalStore, SessionBackend,
    VotesStore, WitnessStore,
};
use tron_crypto::hash::sha256;
use tron_proto::transaction::contract::ContractType;
use tron_proto::{Block, Transaction};
use tron_types::{
    block_id_from_block, recover_all_signers, verify_parent_link, verify_tx_trie_root,
    verify_witness_signature, BlockId, BlockValidateError,
};
use tron_crypto::address::Address;

// =============================================================================
// Exec config
// =============================================================================

/// Executor-side knobs driven by `vm.*` in the node config. Defaults
/// match java-tron's `VmConfig` defaults — all recording is OFF — so
/// `execute_block` (which uses `ExecConfig::default()`) matches mainnet
/// behavior. Callers that want internal-tx traces materialised must opt
/// in by passing an explicit config via [`execute_block_with_config`] /
/// [`execute_block_with_undo_with_config`].
#[derive(Debug, Clone, Copy)]
pub struct ExecConfig {
    /// `vm.saveInternalTx`. When set, every per-frame CALL / CREATE /
    /// SELFDESTRUCT trace captured by the TVM inspector is materialised
    /// onto [`TxResult::internal_transactions`]. Defaults to `false`
    /// (java-tron parity).
    pub save_internal_tx: bool,
    /// `vm.vmTrace`. Today acts as a companion to `save_internal_tx`
    /// — when set, traces are recorded the same way. java-tron uses
    /// this for per-opcode traces; tron-tvm doesn't emit per-opcode
    /// traces yet, so the knob is wired but its only visible effect is
    /// to enable the same internal-tx recording.
    pub vm_trace: bool,
    /// `vm.saveFeaturedInternalTx`. Reserved for actuator-side recording
    /// of system-contract internal transactions (delegate / freeze / etc.).
    /// Plumbed end-to-end so future actuator hooks can read it; today
    /// no actuator emits featured internal txs, so toggling this has no
    /// observable effect at the executor.
    pub save_featured_internal_tx: bool,
    /// Require the block to carry a valid `witness_signature`. Defaults
    /// to `true` (production safety). Set to `false` ONLY for the
    /// block-production dry-run path that computes `account_state_root`
    /// on an in-construction, not-yet-signed block — see
    /// `dry_run_for_state_root` and `sr_runtime`'s state-root branch.
    pub require_signature: bool,
    /// Enforce `Transaction.raw_data.fee_limit` as the per-tx VM
    /// energy budget. Defaults to `true` — VM execution computes
    /// `vm_energy_limit = fee_limit / dyn_props.energy_fee()` and txs
    /// with `fee_limit <= 0` are rejected with
    /// `TxOutcome::InvalidFeeLimit`, mirroring java-tron's
    /// `validateFeeLimit` gate.
    ///
    /// Set to `false` for synthetic test fixtures that build VM txs
    /// via `..Default::default()` (which leaves `fee_limit = 0`) —
    /// the executor falls back to a generous fixed cap so the test's
    /// VM call has room to run. Production must keep this on or
    /// every node will compute a different energy charge than its
    /// peers for the same tx (consensus break).
    pub require_fee_limit: bool,
    /// Recompute and check the block's `txTrieRoot` during execution.
    /// Defaults to `true`. The **sync driver sets this `false`**: it
    /// validates `txTrieRoot` against each block's *original wire bytes*
    /// in `accept_block` (M-20), whereas the executor only sees the
    /// decoded block, whose prost re-encode reorders `ret` map entries and
    /// would spuriously mismatch. Genesis / replay / direct `execute_block`
    /// callers keep it on (their blocks are canonical).
    pub verify_tx_trie: bool,
    /// Defer per-store fsync on block commit (catch-up fast path).
    ///
    /// Defaults to `false` → every block fsyncs each mutated store's WAL
    /// (full per-block durability). The **sync driver sets this `true`
    /// while catching up** (block timestamp far behind wall-clock): the
    /// per-block cross-store manifest is still written and fsync'd (the
    /// durable consistency anchor), but the per-store WAL fsyncs — the
    /// expensive part — are batched into a barrier every
    /// [`DEFER_FSYNC_BARRIER_BLOCKS`] blocks. A crash loses nothing: on
    /// restart `replay_pending_checkpoints` replays the retained manifests
    /// (idempotent, cross-store-atomic) so the stores reach the latest
    /// committed block. Only the WAL-fsync *frequency* changes, never
    /// durability or consistency. Reverts to per-block fsync at the tip.
    pub defer_store_fsync: bool,
    /// Execute a block's transactions with the Block-STM optimistic parallel
    /// scheduler instead of the serial loop. Produces byte-identical state (the
    /// serial path stays the source of truth and the safe fallback). Defaults to
    /// `false` until the parallel==serial equivalence is exhaustively validated;
    /// the sync driver opts in for bulk catch-up where the multi-core speedup
    /// matters most. See `crate::parallel`.
    pub parallel_exec: bool,
    /// Capture the block's committed write-set (per-store post-images +
    /// pre-images) onto [`BlockExecutionReport::state_deltas`]. Pure
    /// observation of the block-session drain — zero effect on what is
    /// written or how. Powers the opt-in historical-state archive
    /// (`[index] capture_state_deltas`); requires the undo (BlockSession)
    /// commit path, since that is where the write-set is materialized —
    /// on the snapshot-stack path the report's `state_deltas` stays
    /// `None`. Defaults to `false` (no allocation, no clone).
    pub capture_state_deltas: bool,
    /// **Tripwire** for silent VM state divergence. When a VM tx
    /// (`TriggerSmartContract` / `CreateSmartContract`) executes to a
    /// *success-vs-failure* result that disagrees with the block's stored
    /// `ret[0].contractRet`, java-tron's `TransactionTrace.check()` rejects the
    /// block ("different resultCode"). A SUCCESS tx mutates state while a failed
    /// one doesn't, so this disagreement is exactly the class of silent
    /// divergence the address-derivation bugs produced (a tx that canon
    /// SUCCEEDed but we no-opped). The success/failure mismatch is **always**
    /// logged regardless of this flag (it can't false-positive on our coarser
    /// failure-*code* mapping — REVERT vs OUT_OF_ENERGY vs UNKNOWN detail
    /// mismatches are ignored entirely, since both sides agree the tx failed
    /// and a failed tx mutates no state beyond fees). With this flag
    /// `true`, a success/failure disagreement also hard-rejects the block
    /// instead of poisoning state. `OUT_OF_TIME` is excluded both ways (it is
    /// node-local; java retries rather than failing). Defaults to `false`
    /// (log-only) so an imperfect mapping can't wedge sync.
    pub verify_contract_ret: bool,
}

impl Default for ExecConfig {
    fn default() -> Self {
        Self {
            save_internal_tx: false,
            vm_trace: false,
            save_featured_internal_tx: false,
            // Default-strict: anything that touches state with an
            // unsigned block must opt out explicitly. Avoids the
            // accidental "executor trusted the caller" footgun where a
            // bypass of `sync::accept_block` (the layer that normally
            // validates) silently applies a peer-injected block.
            require_signature: true,
            // Same reasoning — without this, a tx with `fee_limit = 0`
            // (the proto default; trivially the case for any test
            // fixture using `..Default::default()`) would get the old
            // 10M fallback energy budget, masking the fact that
            // production should be deriving the VM's budget from the
            // caller's stated `fee_limit`.
            require_fee_limit: true,
            // Strict by default; the sync driver opts out because it does
            // the authoritative raw-bytes check itself (see field docs).
            verify_tx_trie: true,
            // Full per-block durability by default; the sync driver opts
            // into deferral only while catching up (see field docs).
            defer_store_fsync: false,
            // Serial execution by default (the validated source of truth);
            // opt into Block-STM parallel execution explicitly.
            parallel_exec: false,
            // Archive capture is an explicit archive-node opt-in.
            capture_state_deltas: false,
            // Log-only by default: the success/failure tripwire always logs,
            // but hard-rejection is opt-in so a coarse failure-code mapping
            // can never wedge sync.
            verify_contract_ret: false,
        }
    }
}

/// During catch-up (`defer_store_fsync`), flush every store's WAL + clear
/// the retained cross-store manifests once this many blocks have
/// accumulated. Bounds how much WAL replay a crash-recovery has to do and
/// how many manifest dirs pile up, while keeping the expensive per-store
/// fsync amortized ~1/N. Recovery is correct for any value (replay handles
/// whatever is retained); this only trades barrier frequency vs. accumulated
/// manifests.
pub const DEFER_FSYNC_BARRIER_BLOCKS: usize = 64;

impl ExecConfig {
    /// Convenience: do any of the trace knobs require populating
    /// [`TxResult::internal_transactions`]? Used inside `execute_vm_tx`
    /// to gate the per-frame trace materialisation.
    pub fn record_internal_txs(&self) -> bool {
        self.save_internal_tx || self.vm_trace
    }

    /// Defaults with the peer-block-level policy gates relaxed:
    /// `require_signature = false` and `require_fee_limit = false`. For
    /// the block-production dry-run path (which applies an UNSIGNED,
    /// in-construction block to compute its `account_state_root`) and
    /// for tests that exercise `execute_block*` directly with synthetic
    /// blocks whose VM-bound txs are built via `..Default::default()`
    /// (so `fee_limit = 0`).
    ///
    /// Production code paths that actually apply peer-received blocks
    /// must NEVER use this helper — the strict default applies.
    pub fn unsigned() -> Self {
        Self {
            require_signature: false,
            require_fee_limit: false,
            ..Self::default()
        }
    }
}

#[cfg(test)]
mod exec_config_tests {
    use super::*;

    #[test]
    fn default_is_java_tron_parity() {
        let c = ExecConfig::default();
        assert!(!c.save_internal_tx);
        assert!(!c.vm_trace);
        assert!(!c.save_featured_internal_tx);
        assert!(!c.record_internal_txs());
        // Default-strict gates: anything that touches state must opt
        // out of these explicitly. Mirrors the on-wire policies a
        // real peer-received block goes through.
        assert!(c.require_signature);
        assert!(c.require_fee_limit);
    }

    #[test]
    fn unsigned_helper_relaxes_peer_block_gates() {
        let c = ExecConfig::unsigned();
        assert!(!c.require_signature);
        assert!(!c.require_fee_limit);
        // Trace knobs untouched — `unsigned` is about peer-block-level
        // policy, not about whether internal-tx recording is on.
        assert!(!c.save_internal_tx);
        assert!(!c.vm_trace);
        assert!(!c.save_featured_internal_tx);
    }

    #[test]
    fn record_internal_txs_truth_table() {
        // OFF / OFF → no.
        assert!(!ExecConfig::default().record_internal_txs());
        // save_internal_tx alone → yes.
        assert!(ExecConfig { save_internal_tx: true, ..Default::default() }.record_internal_txs());
        // vm_trace alone → yes.
        assert!(ExecConfig { vm_trace: true, ..Default::default() }.record_internal_txs());
        // Both → still yes.
        assert!(ExecConfig {
            save_internal_tx: true,
            vm_trace: true,
            ..Default::default()
        }
        .record_internal_txs());
        // save_featured_internal_tx alone does NOT enable executor-side
        // recording — it's reserved for future actuator hooks.
        assert!(!ExecConfig {
            save_featured_internal_tx: true,
            ..Default::default()
        }
        .record_internal_txs());
    }
}

#[cfg(test)]
mod fee_limit_tests {
    use super::*;

    /// Strict mode + the canonical mainnet `DEFAULT_ENERGY_FEE = 100`:
    /// every 100 sun of `fee_limit` buys one unit of energy.
    /// A generous `max_fee_limit` for tests that exercise the energy-division
    /// path rather than the upper-bound gate (java's genesis default is
    /// 1_000_000_000 sun; `i64::MAX` keeps any fee_limit below the cap).
    const TEST_MAX_FEE_LIMIT: i64 = i64::MAX;

    #[test]
    fn strict_mode_divides_fee_limit_by_energy_fee() {
        assert_eq!(compute_vm_energy_limit(1_000_000, 100, TEST_MAX_FEE_LIMIT, true), Ok(10_000));
        assert_eq!(compute_vm_energy_limit(100, 100, TEST_MAX_FEE_LIMIT, true), Ok(1));
        // Truncates toward zero (i.e. caller paid for partial energy
        // but doesn't get a full unit — matches java-tron's integer
        // division).
        assert_eq!(compute_vm_energy_limit(99, 100, TEST_MAX_FEE_LIMIT, true), Ok(0));
    }

    /// `fee_limit == 0` is VALID in java (`feeLimit >= 0`): a caller who pays
    /// energy entirely from staked resources sets no TRX burn cap. The energy
    /// budget derived from it is simply 0 (the VM then runs on the contract's
    /// own staked energy). Rejecting it diverged from java.
    #[test]
    fn strict_mode_accepts_zero_fee_limit() {
        assert_eq!(compute_vm_energy_limit(0, 100, TEST_MAX_FEE_LIMIT, true), Ok(0));
    }

    /// Strict mode rejects `fee_limit < 0` and `fee_limit > max_fee_limit` —
    /// byte-for-byte java's `VMActuator.validate` gate.
    #[test]
    fn strict_mode_rejects_negative_or_over_max_fee_limit() {
        assert_eq!(
            compute_vm_energy_limit(-1, 100, TEST_MAX_FEE_LIMIT, true),
            Err(TxOutcome::InvalidFeeLimit { fee_limit: -1 })
        );
        assert_eq!(
            compute_vm_energy_limit(i64::MIN, 100, TEST_MAX_FEE_LIMIT, true),
            Err(TxOutcome::InvalidFeeLimit { fee_limit: i64::MIN })
        );
        // Over the mainnet ceiling (1e9 sun): rejected before energy derivation.
        let max = 1_000_000_000;
        assert_eq!(compute_vm_energy_limit(max, 100, max, true), Ok(max as u64 / 100));
        assert_eq!(
            compute_vm_energy_limit(max + 1, 100, max, true),
            Err(TxOutcome::InvalidFeeLimit { fee_limit: max + 1 })
        );
    }

    /// Lenient mode (`ExecConfig::unsigned()` / test fixtures): the
    /// fee_limit is ignored entirely and the historical 10M fallback
    /// is returned. Required so test fixtures built via
    /// `..Default::default()` (so `fee_limit = 0`) keep running.
    #[test]
    fn lenient_mode_always_returns_test_fallback() {
        assert_eq!(compute_vm_energy_limit(0, 100, TEST_MAX_FEE_LIMIT, false), Ok(TEST_FALLBACK_ENERGY_LIMIT));
        assert_eq!(compute_vm_energy_limit(-1, 100, TEST_MAX_FEE_LIMIT, false), Ok(TEST_FALLBACK_ENERGY_LIMIT));
        // Even a real-looking fee_limit is ignored in lenient mode —
        // the helper's job is to keep test fixtures predictable, not
        // to interpolate.
        assert_eq!(compute_vm_energy_limit(1_000_000, 100, TEST_MAX_FEE_LIMIT, false), Ok(TEST_FALLBACK_ENERGY_LIMIT));
    }

    /// Defensive clamp against a misconfigured `energy_fee = 0` (or
    /// negative). Division-by-zero would panic; the helper substitutes
    /// 1 sun/energy so the derived budget is large but finite.
    #[test]
    fn clamps_energy_fee_to_at_least_one() {
        // energy_fee = 0 → treated as 1 → energy_limit = fee_limit
        // (capped by MAX).
        assert_eq!(
            compute_vm_energy_limit(500, 0, TEST_MAX_FEE_LIMIT, true),
            Ok(500)
        );
        assert_eq!(
            compute_vm_energy_limit(500, -42, TEST_MAX_FEE_LIMIT, true),
            Ok(500)
        );
    }

    /// The safety ceiling fires when `fee_limit / energy_fee` would
    /// otherwise exceed 1B energy. Keeps the revm `u64` gas counter
    /// well within arithmetic safety bounds. (Uses `TEST_MAX_FEE_LIMIT`
    /// so the upper-bound gate doesn't reject these large fee_limits first.)
    #[test]
    fn safety_ceiling_caps_runaway_fee_limits() {
        // fee_limit = i64::MAX, energy_fee = 1 → would derive
        // i64::MAX-as-u64 = 9.2e18; expect clamp at 1B.
        assert_eq!(
            compute_vm_energy_limit(i64::MAX, 1, TEST_MAX_FEE_LIMIT, true),
            Ok(MAX_VM_ENERGY_LIMIT)
        );
        // Just over the ceiling → still clamped.
        let just_over = (MAX_VM_ENERGY_LIMIT + 1) as i64 * 100;
        assert_eq!(
            compute_vm_energy_limit(just_over, 100, TEST_MAX_FEE_LIMIT, true),
            Ok(MAX_VM_ENERGY_LIMIT)
        );
        // Exactly at the ceiling → returned unchanged.
        let at_cap = (MAX_VM_ENERGY_LIMIT as i64) * 100;
        assert_eq!(
            compute_vm_energy_limit(at_cap, 100, TEST_MAX_FEE_LIMIT, true),
            Ok(MAX_VM_ENERGY_LIMIT)
        );
    }
}

// =============================================================================
// State backends
// =============================================================================

/// The 16 base KV backends that together form one TRON node's state.
/// `execute_block` forks per-tx [`SessionBackend`]s over each of these
/// to give atomic per-tx commit/revert semantics.
#[derive(Clone)]
pub struct StateBackends {
    pub accounts: Arc<dyn KvBackend>,
    pub witnesses: Arc<dyn KvBackend>,
    pub votes: Arc<dyn KvBackend>,
    pub delegation: Arc<dyn KvBackend>,
    pub delegated_resources: Arc<dyn KvBackend>,
    /// Bidirectional `(from, to)` delegation index. `None` in unit-test
    /// setups that don't exercise delegate/undelegate; the production node
    /// always attaches it so the RPC index stays in sync with java-tron.
    pub delegated_resource_account_index: Option<Arc<dyn KvBackend>>,
    pub dyn_props: Arc<dyn KvBackend>,
    pub proposals: Arc<dyn KvBackend>,
    pub name_index: Arc<dyn KvBackend>,
    pub id_index: Arc<dyn KvBackend>,
    pub asset_v1: Arc<dyn KvBackend>,
    pub asset_v2: Arc<dyn KvBackend>,
    pub contracts: Arc<dyn KvBackend>,
    pub abi: Arc<dyn KvBackend>,
    pub exchange_v1: Arc<dyn KvBackend>,
    pub exchange_v2: Arc<dyn KvBackend>,
    pub market_orders: Arc<dyn KvBackend>,
    pub market_account: Arc<dyn KvBackend>,
    pub nullifiers: Arc<dyn KvBackend>,
    /// Optional shielded-transfer incremental Merkle tree store.
    /// When `None`, anchor checks and commitment appends are skipped.
    pub merkle_trees: Option<Arc<dyn KvBackend>>,
    /// EVM-side stores. Only consulted on `CreateSmartContract` /
    /// `TriggerSmartContract`. Optional for the v1 path because not
    /// every caller (e.g. unit tests of non-VM contracts) wants to
    /// stand up the full EVM state.
    pub code: Option<Arc<dyn KvBackend>>,
    pub storage_row: Option<Arc<dyn KvBackend>>,
    pub contract_state: Option<Arc<dyn KvBackend>>,
    pub block_index: Option<Arc<dyn KvBackend>>,
    /// Witness-schedule store (active witness list + shuffled order).
    /// Read at block-execution time to know which witness was scheduled
    /// for each slot — needed by `total_missed` attribution. Optional
    /// because unit tests of single-contract paths don't need it; in
    /// production it's always attached.
    pub witness_schedule: Option<Arc<dyn KvBackend>>,
    /// `reward-vi` store — READ-ONLY pass-through (block execution never
    /// writes it; java-tron's `RewardViCalService` computes it once,
    /// merkle-pinned). Consulted by reward settlement / queries for
    /// voters whose reward window predates the new reward algorithm
    /// (`ALLOW_OLD_REWARD_OPT`). Not session-wrapped, not undo-logged,
    /// not checkpointed — there is nothing to roll back.
    pub reward_vi: Option<Arc<dyn KvBackend>>,
}

// =============================================================================
// Per-transaction session (the new layer that fixes the old "no rollback" gap)
// =============================================================================

/// A bundle of 16 session-wrapped backends that all commit/revert
/// together. Constructed once per transaction by the executor.
struct TxSession {
    accounts: Arc<SessionBackend>,
    witnesses: Arc<SessionBackend>,
    votes: Arc<SessionBackend>,
    delegation: Arc<SessionBackend>,
    delegated_resources: Arc<SessionBackend>,
    delegated_resource_account_index: Option<Arc<SessionBackend>>,
    dyn_props: Arc<SessionBackend>,
    proposals: Arc<SessionBackend>,
    name_index: Arc<SessionBackend>,
    id_index: Arc<SessionBackend>,
    asset_v1: Arc<SessionBackend>,
    asset_v2: Arc<SessionBackend>,
    contracts: Arc<SessionBackend>,
    abi: Arc<SessionBackend>,
    exchange_v1: Arc<SessionBackend>,
    exchange_v2: Arc<SessionBackend>,
    market_orders: Arc<SessionBackend>,
    market_account: Arc<SessionBackend>,
    nullifiers: Arc<SessionBackend>,
    merkle_trees: Option<Arc<SessionBackend>>,
    /// EVM-side session-wrapped backends. `None` when the executor was
    /// built without EVM stores; VM-bound contracts then reject.
    code: Option<Arc<SessionBackend>>,
    storage_row: Option<Arc<SessionBackend>>,
    contract_state: Option<Arc<SessionBackend>>,
    block_index: Option<Arc<SessionBackend>>,
    /// READ-ONLY pass-through (never session-wrapped — block execution
    /// never writes the reward-vi store).
    reward_vi: Option<Arc<dyn KvBackend>>,
}

impl TxSession {
    fn fork(base: &StateBackends) -> Self {
        Self {
            accounts: Arc::new(SessionBackend::new(base.accounts.clone())),
            witnesses: Arc::new(SessionBackend::new(base.witnesses.clone())),
            votes: Arc::new(SessionBackend::new(base.votes.clone())),
            delegation: Arc::new(SessionBackend::new(base.delegation.clone())),
            delegated_resources: Arc::new(SessionBackend::new(base.delegated_resources.clone())),
            delegated_resource_account_index: base
                .delegated_resource_account_index
                .as_ref()
                .map(|b| Arc::new(SessionBackend::new(b.clone()))),
            dyn_props: Arc::new(SessionBackend::new(base.dyn_props.clone())),
            proposals: Arc::new(SessionBackend::new(base.proposals.clone())),
            name_index: Arc::new(SessionBackend::new(base.name_index.clone())),
            id_index: Arc::new(SessionBackend::new(base.id_index.clone())),
            asset_v1: Arc::new(SessionBackend::new(base.asset_v1.clone())),
            asset_v2: Arc::new(SessionBackend::new(base.asset_v2.clone())),
            contracts: Arc::new(SessionBackend::new(base.contracts.clone())),
            abi: Arc::new(SessionBackend::new(base.abi.clone())),
            exchange_v1: Arc::new(SessionBackend::new(base.exchange_v1.clone())),
            exchange_v2: Arc::new(SessionBackend::new(base.exchange_v2.clone())),
            market_orders: Arc::new(SessionBackend::new(base.market_orders.clone())),
            market_account: Arc::new(SessionBackend::new(base.market_account.clone())),
            nullifiers: Arc::new(SessionBackend::new(base.nullifiers.clone())),
            merkle_trees: base
                .merkle_trees
                .as_ref()
                .map(|b| Arc::new(SessionBackend::new(b.clone()))),
            code: base
                .code
                .as_ref()
                .map(|b| Arc::new(SessionBackend::new(b.clone()))),
            storage_row: base
                .storage_row
                .as_ref()
                .map(|b| Arc::new(SessionBackend::new(b.clone()))),
            contract_state: base
                .contract_state
                .as_ref()
                .map(|b| Arc::new(SessionBackend::new(b.clone()))),
            block_index: base
                .block_index
                .as_ref()
                .map(|b| Arc::new(SessionBackend::new(b.clone()))),
            reward_vi: base.reward_vi.clone(),
        }
    }

    fn commit(&self) -> Result<(), tron_chainbase::KvError> {
        self.accounts.commit()?;
        self.witnesses.commit()?;
        self.votes.commit()?;
        self.delegation.commit()?;
        self.delegated_resources.commit()?;
        self.dyn_props.commit()?;
        self.proposals.commit()?;
        self.name_index.commit()?;
        self.id_index.commit()?;
        self.asset_v1.commit()?;
        self.asset_v2.commit()?;
        self.contracts.commit()?;
        self.abi.commit()?;
        self.exchange_v1.commit()?;
        self.exchange_v2.commit()?;
        self.market_orders.commit()?;
        self.market_account.commit()?;
        self.nullifiers.commit()?;
        if let Some(s) = &self.delegated_resource_account_index {
            s.commit()?;
        }
        if let Some(s) = &self.merkle_trees {
            s.commit()?;
        }
        if let Some(s) = &self.code {
            s.commit()?;
        }
        if let Some(s) = &self.storage_row {
            s.commit()?;
        }
        if let Some(s) = &self.contract_state {
            s.commit()?;
        }
        if let Some(s) = &self.block_index {
            s.commit()?;
        }
        Ok(())
    }

    fn revert(&self) {
        self.accounts.revert();
        self.witnesses.revert();
        self.votes.revert();
        self.delegation.revert();
        self.delegated_resources.revert();
        self.dyn_props.revert();
        self.proposals.revert();
        self.name_index.revert();
        self.id_index.revert();
        self.asset_v1.revert();
        self.asset_v2.revert();
        self.contracts.revert();
        self.abi.revert();
        self.exchange_v1.revert();
        self.exchange_v2.revert();
        self.market_orders.revert();
        self.market_account.revert();
        self.nullifiers.revert();
        if let Some(s) = &self.delegated_resource_account_index {
            s.revert();
        }
        if let Some(s) = &self.merkle_trees {
            s.revert();
        }
        if let Some(s) = &self.code {
            s.revert();
        }
        if let Some(s) = &self.storage_row {
            s.revert();
        }
        if let Some(s) = &self.contract_state {
            s.revert();
        }
        if let Some(s) = &self.block_index {
            s.revert();
        }
    }

    /// A [`StateBackends`] view over this session's per-store overlays (each
    /// `Arc<SessionBackend>` upcast to `Arc<dyn KvBackend>`). Lets the shared
    /// `execute_one_tx_isolated` core run over the session exactly as the
    /// parallel path runs it over the versioned backend — writes flow into the
    /// session's `pending`, `commit`/`revert` are driven by [`TxIsolation`].
    /// `witness_schedule` is `None` (never mutated per-tx; the session doesn't
    /// wrap it).
    fn view(&self) -> StateBackends {
        let up = |b: &Arc<SessionBackend>| -> Arc<dyn KvBackend> { b.clone() };
        let upo = |b: &Option<Arc<SessionBackend>>| -> Option<Arc<dyn KvBackend>> {
            b.as_ref().map(|x| x.clone() as Arc<dyn KvBackend>)
        };
        StateBackends {
            accounts: up(&self.accounts),
            witnesses: up(&self.witnesses),
            votes: up(&self.votes),
            delegation: up(&self.delegation),
            delegated_resources: up(&self.delegated_resources),
            delegated_resource_account_index: upo(&self.delegated_resource_account_index),
            dyn_props: up(&self.dyn_props),
            proposals: up(&self.proposals),
            name_index: up(&self.name_index),
            id_index: up(&self.id_index),
            asset_v1: up(&self.asset_v1),
            asset_v2: up(&self.asset_v2),
            contracts: up(&self.contracts),
            abi: up(&self.abi),
            exchange_v1: up(&self.exchange_v1),
            exchange_v2: up(&self.exchange_v2),
            market_orders: up(&self.market_orders),
            market_account: up(&self.market_account),
            nullifiers: up(&self.nullifiers),
            merkle_trees: upo(&self.merkle_trees),
            code: upo(&self.code),
            storage_row: upo(&self.storage_row),
            contract_state: upo(&self.contract_state),
            block_index: upo(&self.block_index),
            witness_schedule: None,
            reward_vi: self.reward_vi.clone(),
        }
    }
}

/// Per-tx write isolation for the shared `execute_one_tx_isolated` core. The
/// serial path commits/reverts a [`TxSession`] (a copy-on-write overlay over the
/// block state); the Block-STM parallel path writes straight into the
/// [`VersionedBackend`] capture, so "commit" is a no-op (the scheduler publishes
/// the capture's write-set afterward) and "revert" discards this tx's buffered
/// writes + accumulator deltas (keeping the read-set, which still drives
/// validation/dependencies). Both produce byte-identical state.
enum TxIsolation<'a> {
    Session(&'a TxSession),
    Capture(&'a tron_chainbase::blockstm::TxCaptureCell),
}

impl TxIsolation<'_> {
    fn revert(&self) {
        match self {
            Self::Session(s) => s.revert(),
            Self::Capture(c) => {
                let mut g = c.borrow_mut();
                g.writes.clear();
                g.deltas.clear();
                // The deferred free-net contribution dies with the write-set:
                // a reverted tx drops its bandwidth charge (the serial session
                // would discard the PUBLIC_NET write too), so it must contribute
                // nothing to the commit-time fold. Mirrors the `writes.clear()`.
                g.public_net_bytes = None;
                // Same for the deferred per-contract energy deltas: a serial outer
                // revert here would undo the ContractState writes too. (A VM-frame
                // revert is already handled upstream — those writes never reach
                // the versioned backend, so nothing was captured.)
                g.contract_energy.clear();
                g.contract_energy_boundary = false;
            }
        }
    }
    fn commit(&self) -> Result<(), tron_chainbase::KvError> {
        match self {
            Self::Session(s) => s.commit(),
            // Writes are already in the capture; the scheduler publishes them.
            Self::Capture(_) => Ok(()),
        }
    }

    /// Record this tx's free-net `bytes` contribution to the chain-global
    /// `PUBLIC_NET_USAGE` for the deferred-sequential fold (parallel/Capture
    /// only). No-op in the serial path, where the bandwidth charge is applied to
    /// the per-tx session normally. Called right after a `BandwidthCharge::Free`,
    /// so it shares the bandwidth write's revert/commit lifecycle exactly.
    fn record_public_net_bytes(&self, bytes: i64) {
        if let Self::Capture(c) = self {
            c.borrow_mut().public_net_bytes = Some(bytes);
        }
    }
}

/// Holder for the typed Store wrappers around a [`TxSession`]'s backends.
/// Existence is just to keep the stores alive for the borrow checker —
/// the [`ActuatorStores`] handed to actuators borrows from here.
struct SessionStoreOwners {
    accounts: AccountStore,
    witnesses: WitnessStore,
    votes: VotesStore,
    delegation: DelegationStore,
    delegated_resources: DelegatedResourceStore,
    delegated_resource_account_index: Option<tron_chainbase::DelegatedResourceAccountIndexStore>,
    dyn_props: DynamicPropertiesStore,
    proposals: ProposalStore,
    name_index: AccountIndexStore,
    id_index: AccountIdIndexStore,
    asset_v1: AssetIssueStore,
    asset_v2: AssetIssueV2Store,
    contracts: ContractStore,
    abi: AbiStore,
    exchange_v1: ExchangeStore,
    exchange_v2: ExchangeV2Store,
    market_orders: MarketOrderStore,
    market_account: MarketAccountStore,
    nullifiers: NullifierStore,
    merkle_trees: Option<IncrementalMerkleTreeStore>,
    reward_vi: Option<tron_chainbase::RewardViStore>,
}

impl SessionStoreOwners {
    /// Build typed actuator stores over a [`StateBackends`] view — either a
    /// serial [`TxSession`]'s overlay (via [`TxSession::view`]) or the Block-STM
    /// versioned backend. Writes land wherever the view's backends route them.
    fn from_state(state: &StateBackends) -> Self {
        Self {
            accounts: AccountStore::new(state.accounts.clone()),
            witnesses: WitnessStore::new(state.witnesses.clone()),
            votes: VotesStore::new(state.votes.clone()),
            delegation: DelegationStore::new(state.delegation.clone()),
            delegated_resources: DelegatedResourceStore::new(state.delegated_resources.clone()),
            delegated_resource_account_index: state
                .delegated_resource_account_index
                .as_ref()
                .map(|b| tron_chainbase::DelegatedResourceAccountIndexStore::new(b.clone())),
            dyn_props: DynamicPropertiesStore::new(state.dyn_props.clone()),
            proposals: ProposalStore::new(state.proposals.clone()),
            name_index: AccountIndexStore::new(state.name_index.clone()),
            id_index: AccountIdIndexStore::new(state.id_index.clone()),
            asset_v1: AssetIssueStore::new(state.asset_v1.clone()),
            asset_v2: AssetIssueV2Store::new(state.asset_v2.clone()),
            contracts: ContractStore::new(state.contracts.clone()),
            abi: AbiStore::new(state.abi.clone()),
            exchange_v1: ExchangeStore::new(state.exchange_v1.clone()),
            exchange_v2: ExchangeV2Store::new(state.exchange_v2.clone()),
            market_orders: MarketOrderStore::new(state.market_orders.clone()),
            market_account: MarketAccountStore::new(state.market_account.clone()),
            nullifiers: NullifierStore::new(state.nullifiers.clone()),
            merkle_trees: state
                .merkle_trees
                .as_ref()
                .map(|b| IncrementalMerkleTreeStore::new(b.clone())),
            reward_vi: state
                .reward_vi
                .as_ref()
                .map(|b| tron_chainbase::RewardViStore::new(b.clone())),
        }
    }

    fn as_actuator_stores(&self) -> ActuatorStores<'_> {
        ActuatorStores {
            accounts: &self.accounts,
            witnesses: &self.witnesses,
            votes: &self.votes,
            delegation: &self.delegation,
            delegated_resources: &self.delegated_resources,
            delegated_resource_account_index: self.delegated_resource_account_index.as_ref(),
            dyn_props: &self.dyn_props,
            proposals: &self.proposals,
            name_index: &self.name_index,
            id_index: &self.id_index,
            asset_v1: &self.asset_v1,
            asset_v2: &self.asset_v2,
            contracts: &self.contracts,
            abi: &self.abi,
            exchange_v1: &self.exchange_v1,
            exchange_v2: &self.exchange_v2,
            market_orders: &self.market_orders,
            market_account: &self.market_account,
            nullifiers: &self.nullifiers,
            merkle_trees: self.merkle_trees.as_ref(),
            reward_vi: self.reward_vi.as_ref(),
        }
    }
}

// =============================================================================
// Per-VM-call inner session (nested over TxSession)
// =============================================================================

/// Inner session layer dedicated to VM-frame state mutations. Wraps
/// every backend the TVM (revm + precompiles + TronHost staking + TRC-10
/// inspector) may write to in a second [`SessionBackend`] over the
/// per-tx session. On [`commit`](Self::commit) the buffered writes
/// flow into the per-tx session; on [`revert`](Self::revert) they're
/// discarded.
///
/// Mirrors java-tron's `Program.java` `Deposit` pattern — every VM
/// frame runs against a child deposit committed on success, dropped
/// on revert. Without this layer, a `VmOutcome::Revert` (or `Halt`,
/// `Timeout`) followed by `session.commit()` on the per-tx session
/// would persist contract storage writes / balance changes / freeze /
/// vote / delegate effects that revm's journal said should be undone
/// — a hard consensus break against every other node.
///
/// Backends the VM only READS (`witnesses`, `delegation`, `block_index`,
/// `contracts`) pass through unwrapped — nothing to revert. `dyn_props` IS
/// wrapped here because the staking opcodes write the chain-global
/// TOTAL_*_WEIGHT accumulators through it, and those must roll back on a frame
/// revert (java scopes them to the frame's child repository). The per-tx
/// session's bandwidth + energy charge writes use the OUTER `TxSession`
/// dyn_props handle (a different, unwrapped handle) and so survive regardless
/// of VM-side commit/revert — matching java-tron's "energy is paid even on
/// revert" rule.
struct VmSession {
    accounts: Arc<SessionBackend>,
    code: Arc<SessionBackend>,
    storage_row: Arc<SessionBackend>,
    contract_state: Arc<SessionBackend>,
    votes: Arc<SessionBackend>,
    delegated_resources: Arc<SessionBackend>,
    // DELEGATERESOURCE / UNDELEGATERESOURCE opcode bridges write the
    // bidirectional `DelegatedResourceAccountIndex` rows through this handle
    // (java `DelegateResourceProcessor`/`UnDelegateResourceProcessor`). The
    // store is RPC-only (never read into consensus). Like the delegation
    // record, it uses BOTH rollback mechanisms: the staking journal reverses
    // inner-frame writes (per-frame revert) and this session discards them on
    // a whole-tx revert (committed once on the top-level VM success). `None`
    // in setups that don't attach the index (read-only callers / unit tests).
    delegated_resource_account_index: Option<Arc<SessionBackend>>,
    // Staking opcodes (FREEZEBALANCEV2 / UNFREEZEBALANCEV2 / CANCELALLUNFREEZEV2
    // / suicide) write the chain-global TOTAL_*_WEIGHT accumulators through this
    // handle. java-tron runs those in the contract frame's child repository,
    // committed only when the frame succeeds — so they must be discarded on a
    // frame revert exactly like the account writes.
    dyn_props: Arc<SessionBackend>,
    // The TVM reward-settle path (VOTEWITNESS / WITHDRAWREWARD /
    // UNFREEZEBALANCEV2 / SELFDESTRUCT → `VoteRewardUtil.withdrawReward`) writes
    // the voter's begin-cycle / end-cycle / account-vote rows through this
    // handle. java scopes those to the frame's `RepositoryImpl.delegationCache`,
    // flushed to the parent only on frame `commit()` and discarded on revert —
    // so a WHOLE-tx VM revert must drop them here, exactly like the votes /
    // delegated-resource writes. (The inner-frame-revert variant is covered by
    // the staking journal's `Delegation` reverser, the same dual mechanism the
    // votes / delegated-resource rows use.)
    delegation: Arc<SessionBackend>,
}

impl VmSession {
    /// Wrap the per-tx session's VM-writeable backends in a fresh
    /// inner session. The four EVM-store handles (`code`, `storage`,
    /// `contract_state`) are required by the caller's gate above —
    /// `execute_vm_tx` rejects with `NotImplemented` if any of them
    /// is missing on the per-tx session.
    fn wrap(
        // Parents are `Arc<dyn KvBackend>` so the VM frame nests over EITHER a
        // serial per-tx `SessionBackend` or a Block-STM `VersionedBackend` — the
        // VM-frame revert semantics (commit on Success, discard on Revert/Halt)
        // are identical either way.
        accounts: Arc<dyn KvBackend>,
        code: Arc<dyn KvBackend>,
        storage_row: Arc<dyn KvBackend>,
        contract_state: Arc<dyn KvBackend>,
        votes: Arc<dyn KvBackend>,
        delegated_resources: Arc<dyn KvBackend>,
        delegated_resource_account_index: Option<Arc<dyn KvBackend>>,
        dyn_props: Arc<dyn KvBackend>,
        delegation: Arc<dyn KvBackend>,
    ) -> Self {
        Self {
            accounts: Arc::new(SessionBackend::new(accounts)),
            code: Arc::new(SessionBackend::new(code)),
            storage_row: Arc::new(SessionBackend::new(storage_row)),
            contract_state: Arc::new(SessionBackend::new(contract_state)),
            votes: Arc::new(SessionBackend::new(votes)),
            delegated_resources: Arc::new(SessionBackend::new(delegated_resources)),
            delegated_resource_account_index: delegated_resource_account_index
                .map(|b| Arc::new(SessionBackend::new(b))),
            dyn_props: Arc::new(SessionBackend::new(dyn_props)),
            delegation: Arc::new(SessionBackend::new(delegation)),
        }
    }

    /// Flush every wrapped backend's pending writes into the per-tx
    /// session. Called once per VM frame on `VmOutcome::Success`.
    fn commit(&self) -> Result<(), tron_chainbase::KvError> {
        self.accounts.commit()?;
        self.code.commit()?;
        self.storage_row.commit()?;
        self.contract_state.commit()?;
        self.votes.commit()?;
        self.delegated_resources.commit()?;
        if let Some(s) = &self.delegated_resource_account_index {
            s.commit()?;
        }
        self.dyn_props.commit()?;
        self.delegation.commit()?;
        Ok(())
    }

    /// Discard every wrapped backend's pending writes. Called once per
    /// VM frame on `VmOutcome::Revert` / `Halt` / `Timeout` /
    /// `CallTokenIgnored` / `PreflightError`. The per-tx session is
    /// untouched.
    fn revert(&self) {
        self.accounts.revert();
        self.code.revert();
        self.storage_row.revert();
        self.contract_state.revert();
        self.votes.revert();
        self.delegated_resources.revert();
        if let Some(s) = &self.delegated_resource_account_index {
            s.revert();
        }
        self.dyn_props.revert();
        self.delegation.revert();
    }
}

// =============================================================================
// Per-tx outcome + report
// =============================================================================

#[derive(Debug, Clone, PartialEq)]
pub enum TxOutcome {
    Success,
    MissingRawData,
    NoContract,
    MissingParameter,
    UnknownContractType(i32),
    Invalid(ActuatorError),
    ExecutionFailed(ActuatorError),
    /// `raw_data.expiration` was already in the past at the moment this
    /// block was applied. The mempool catches this at submit time
    /// against wall-clock — but a peer-pushed block bypasses the
    /// mempool, so the executor enforces against the block's timestamp.
    /// Matches java-tron's `TransactionUtil.validateTransactionExpiration`
    /// rejection at block-apply.
    Expired {
        expiration_ms: i64,
        block_timestamp_ms: i64,
    },
    /// VM-bound contract tx had `raw_data.fee_limit <= 0` while the
    /// executor's `require_fee_limit` gate was on. java-tron's
    /// `validateFeeLimit` rejects these at validation; we enforce at
    /// block-apply so the VM's energy budget is always derived from
    /// the caller's stated `fee_limit`, never a hardcoded fallback.
    InvalidFeeLimit { fee_limit: i64 },
    /// The transaction exceeds `Constant.TRANSACTION_MAX_BYTE_SIZE`
    /// (500 KiB). java-tron's `Manager.validateCommon` rejects these with
    /// `TooBigTransactionException` (lines 814-828): either the serialized
    /// size with cleared `ret` plus `2 * MAX_RESULT_SIZE_IN_TX` (128) headroom,
    /// or the raw tx data length, exceeds the limit. Enforced at block-apply
    /// for the same reason as the expiration check — a peer-pushed block
    /// bypasses the mempool's pre-acceptance validation.
    TooBig { size_bytes: i64, max_size: i64 },
}

impl TxOutcome {
    pub fn is_success(&self) -> bool {
        matches!(self, TxOutcome::Success)
    }
}

/// Per-transaction resource receipt, mirroring java-tron's
/// `protocol.ResourceReceipt` semantics. Captured at execution time —
/// the bandwidth charge fills the net side, `pay_energy_bill`'s
/// returned split fills the energy side — identically on the serial
/// and Block-STM paths (both run `execute_one_tx_isolated`).
///
/// The flat multi-sign / memo fees ride here as well — java-tron keeps
/// them as transient `ReceiptCapsule` members that never enter the
/// proto `ResourceReceipt`, and the stored `TransactionInfo.fee` sums
/// them in (`TransactionUtil.buildTransactionInfoInstance`):
/// `fee = ret.fee + energy_fee + net_fee + multi_sign_fee + memo_fee`.
/// The actuator side (`ret.fee`) lives on [`TxResult::actuator_fee`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TxReceipt {
    /// Energy covered by the caller's frozen quota.
    pub energy_usage: i64,
    /// Energy paid in TRX (sun).
    pub energy_fee: i64,
    /// Energy covered by the contract origin's quota (the
    /// `consume_user_resource_percent` split).
    pub origin_energy_usage: i64,
    /// Total energy the VM consumed.
    pub energy_usage_total: i64,
    /// Bandwidth bytes covered by quotas (frozen / free / asset-issuer).
    pub net_usage: i64,
    /// Bandwidth paid in TRX (sun).
    pub net_fee: i64,
    /// `protocol.Transaction.Result.contractResult` value: DEFAULT(0)
    /// for non-VM contracts (java-tron leaves it unset there),
    /// SUCCESS/REVERT/OUT_OF_ENERGY/OUT_OF_TIME/UNKNOWN for VM txs.
    pub result: i32,
    /// Dynamic-energy penalty included in `energy_usage_total`
    /// (java-tron `ProgramResult.energyPenaltyTotal` →
    /// `ResourceReceipt.energy_penalty_total`). `0` when the tx touched
    /// no penalized contract.
    pub energy_penalty_total: i64,
    /// Flat fee for a transaction carrying more than one signature
    /// (java-tron `Manager.consumeMultiSignFee` →
    /// `ReceiptCapsule.multiSignFee`, transient — never in the proto
    /// `ResourceReceipt`, but summed into `TransactionInfo.fee`).
    pub multi_sign_fee: i64,
    /// Flat fee for a non-empty memo (`raw_data.data`) — java-tron
    /// `Manager.consumeMemoFee` → `ReceiptCapsule.memoFee`, transient.
    pub memo_fee: i64,
}

#[derive(Debug, Clone)]
pub struct TxResult {
    pub tx_id: [u8; 32],
    pub contract_type: Option<ContractType>,
    pub outcome: TxOutcome,
    /// Per-frame CALL / CREATE traces recorded by the TVM inspector,
    /// in execution order. Empty for non-VM contracts. Each entry is
    /// already wire-encoded (`tron_proto::InternalTransaction`) with
    /// `hash` pointing at the parent transaction id and `rejected`
    /// reflecting both this frame's outcome and any ancestor revert.
    pub internal_transactions: Vec<tron_proto::InternalTransaction>,
    /// Successful LOG opcode emissions from the VM, in emission order.
    /// Only populated when `outcome == TxOutcome::Success`; reverted /
    /// halted txs surface no logs (java-tron behavior — logsfilter
    /// only fires for committed contract executions).
    pub vm_logs: Vec<tron_tvm::execute::VmLog>,
    /// Resource receipt — see [`TxReceipt`].
    pub receipt: TxReceipt,
    /// The VM's return data (SUCCESS return value or REVERT payload).
    /// Empty for non-VM contracts and halts.
    pub vm_return_data: Vec<u8>,
    /// TRX burned by the actuator itself (java-tron's
    /// `ProgramResult.ret.fee`): account-creation fee in system
    /// contracts, asset-issue fee, witness-create fee, exchange-create
    /// fee, permission-update fee, … Summed into the stored
    /// `TransactionInfo.fee` alongside the receipt fees.
    pub actuator_fee: i64,
    /// The non-fee `ret`-derived fields (`unfreezeAmount`, `assetIssueID`,
    /// `exchangeId`, …) a non-VM actuator records in its
    /// `TransactionResultCapsule`. `TransactionUtil.buildTransactionInfoInstance`
    /// copies these straight onto the stored `TransactionInfo`; the index
    /// hook does the same from here. Empty for VM txs (the VM path fills the
    /// proto fields directly) and for rejected/failed txs.
    pub ret_extras: tron_actuator::TransactionRetExtras,
}

impl TxResult {
    /// All-empty scaffold for struct-update syntax at the many
    /// early-reject construction sites (`TxResult { tx_id, outcome,
    /// ..TxResult::empty() }`) — rejected txs charge nothing, so every
    /// auxiliary field is its default.
    fn empty() -> Self {
        Self {
            tx_id: [0u8; 32],
            contract_type: None,
            outcome: TxOutcome::MissingRawData,
            internal_transactions: Vec::new(),
            vm_logs: Vec::new(),
            receipt: TxReceipt::default(),
            vm_return_data: Vec::new(),
            actuator_fee: 0,
            ret_extras: tron_actuator::TransactionRetExtras::default(),
        }
    }
}

/// SR-list rotation observed during block apply. Populated only when
/// the block crossed a maintenance boundary and a real rotation ran
/// (i.e. not on block 1, which skips `doMaintenance` per java-tron).
/// Callers — primarily the sync driver — feed this into the in-memory
/// [`tron_consensus::SrEpochSnapshot`] so the PBFT runtime can accept
/// cross-rotation votes signed by the pre-rotation SR set.
#[derive(Debug, Clone)]
pub struct MaintenanceRotation {
    /// Active list **before** this block's rotation overwrote
    /// `WitnessScheduleStore`. Becomes the snapshot's `before`.
    pub prev_active: Vec<tron_crypto::address::Address>,
    /// Active list installed by this block's rotation. Becomes the
    /// snapshot's `current`.
    pub new_active: Vec<tron_crypto::address::Address>,
    /// `NEXT_MAINTENANCE_TIME` value AT the moment of rotation —
    /// before this block bumped it. PBFT messages with `epoch <=`
    /// this value validate against the `before` list; messages with
    /// strictly greater epoch validate against `current`. Mirrors
    /// java-tron's `MaintenanceManager.beforeMaintenanceTime`.
    pub before_maintenance_time_ms: i64,
}

/// One committed key mutation from a block's write-set, captured at
/// the block-session drain when [`ExecConfig::capture_state_deltas`]
/// is on. `before` is the value prior to the block (the undo
/// pre-image), `after` the committed post-image (`None` = deleted).
/// Exactly one entry per `(store, key)` — the session overlay
/// collapses intra-block rewrites to the final value, which is
/// precisely the per-height version the historical-state archive
/// stores. Byte-identical on the serial and parallel execution paths
/// (the deferred-fold keys land in the drain as ordinary puts).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedDelta {
    pub store: tron_chainbase::UndoStoreId,
    pub key: Vec<u8>,
    pub before: Option<Vec<u8>>,
    pub after: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct BlockExecutionReport {
    pub block_id: BlockId,
    pub tx_results: Vec<TxResult>,
    /// Set when this block crossed a maintenance boundary AND ran
    /// `doMaintenance` (i.e. `block_num != 1`). Callers apply it to
    /// the shared [`tron_consensus::SrEpochSnapshot`] so PBFT
    /// validates cross-rotation votes the way java-tron does. `None`
    /// for ordinary blocks.
    pub maintenance: Option<MaintenanceRotation>,
    /// The block's committed write-set, present iff
    /// [`ExecConfig::capture_state_deltas`] was on AND the block ran
    /// the undo (BlockSession) commit path. Sorted by `(store, key)`
    /// for deterministic consumption.
    pub state_deltas: Option<Vec<CapturedDelta>>,
}

impl BlockExecutionReport {
    pub fn successes(&self) -> usize {
        self.tx_results.iter().filter(|r| r.outcome.is_success()).count()
    }
    pub fn failures(&self) -> usize {
        self.tx_results.len() - self.successes()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BlockExecError {
    #[error("block structural validation failed: {0}")]
    Structural(#[from] BlockValidateError),
    #[error("block has no header / raw_data")]
    NoHeader,
    #[error(
        "account_state_root mismatch at block {block_num}: expected {expected}, computed {computed}"
    )]
    StateRootMismatch {
        block_num: i64,
        expected: String,
        computed: String,
    },
    #[error(
        "contractRet mismatch at block {block_num} tx {tx_id}: \
         block says {expected}, we computed {computed} (success/failure disagreement)"
    )]
    ContractRetMismatch {
        block_num: i64,
        tx_id: String,
        expected: String,
        computed: String,
    },
    #[error("cross-store checkpoint flush failed: {0}")]
    Checkpoint(#[from] tron_chainbase::CheckpointError),
    #[error("store error: {0}")]
    Store(#[from] tron_chainbase::StoreError),
    #[error("kv backend error: {0}")]
    Kv(#[from] tron_chainbase::KvError),
}

// =============================================================================
// Entry point
// =============================================================================

/// Execute `block` against `state`. Each transaction runs inside its own
/// [`TxSession`]; failures **do not leak** to subsequent transactions.
///
/// Uses [`ExecConfig::default`] — i.e. java-tron defaults (no internal-
/// tx recording). For test or operator setups that want traces, call
/// [`execute_block_with_config`].
pub fn execute_block(
    state: &StateBackends,
    block: &Block,
    expected_parent: Option<BlockId>,
) -> Result<BlockExecutionReport, BlockExecError> {
    execute_block_inner(state, block, expected_parent, None, None, &ExecConfig::default(), None)
}

/// As [`execute_block`], but with an explicit `ExecConfig`. The config
/// flows through to `execute_vm_tx`, where it gates per-frame trace
/// materialisation onto `TxResult::internal_transactions`.
pub fn execute_block_with_config(
    state: &StateBackends,
    block: &Block,
    expected_parent: Option<BlockId>,
    config: &ExecConfig,
) -> Result<BlockExecutionReport, BlockExecError> {
    execute_block_inner(state, block, expected_parent, None, None, config, None)
}

/// Execute `block` and persist a complete undo log to `undo_store`
/// keyed by the block's number. The log captures every (store, key,
/// before_image) needed by [`rollback_block`] to reverse this block's
/// state mutations during a KhaosDb Phase B reorg.
///
/// On the happy path this is exactly [`execute_block`] plus a single
/// write to the undo store. Performance overhead: one extra `get` per
/// key written during the block (to capture pre-images). Block-time
/// overhead is small relative to the EVM work.
pub fn execute_block_with_undo(
    state: &StateBackends,
    block: &Block,
    expected_parent: Option<BlockId>,
    undo_store: &tron_chainbase::BlockUndoStore,
) -> Result<BlockExecutionReport, BlockExecError> {
    execute_block_inner(
        state,
        block,
        expected_parent,
        Some(undo_store),
        None,
        &ExecConfig::default(),
        None,
    )
}

/// As [`execute_block_with_undo`], but with an explicit `ExecConfig`.
pub fn execute_block_with_undo_and_config(
    state: &StateBackends,
    block: &Block,
    expected_parent: Option<BlockId>,
    undo_store: &tron_chainbase::BlockUndoStore,
    config: &ExecConfig,
    original_tx_sizes: Option<&[i64]>,
) -> Result<BlockExecutionReport, BlockExecError> {
    execute_block_inner(
        state,
        block,
        expected_parent,
        Some(undo_store),
        None,
        config,
        original_tx_sizes,
    )
}

/// Like [`execute_block_with_undo`] but additionally wires the cross-
/// store atomic-flush primitive ([`tron_chainbase::CheckPointV2`]) so
/// every per-store write a block makes lands behind one durable
/// manifest. On crash mid-flush, the next startup replays the
/// manifest and restores cross-store consistency.
///
/// This is the production-runtime path. Tests that only care about
/// per-store atomicity (or that don't want a temp checkpoint dir on
/// disk) can keep using [`execute_block_with_undo`].
pub fn execute_block_with_undo_and_checkpoint(
    state: &StateBackends,
    block: &Block,
    expected_parent: Option<BlockId>,
    undo_store: &tron_chainbase::BlockUndoStore,
    checkpoint: &tron_chainbase::CheckPointV2,
) -> Result<BlockExecutionReport, BlockExecError> {
    execute_block_inner(
        state,
        block,
        expected_parent,
        Some(undo_store),
        Some(checkpoint),
        &ExecConfig::default(),
        None,
    )
}

/// [`execute_block_with_undo_and_checkpoint`] with an explicit
/// `ExecConfig`.
pub fn execute_block_with_undo_checkpoint_and_config(
    state: &StateBackends,
    block: &Block,
    expected_parent: Option<BlockId>,
    undo_store: &tron_chainbase::BlockUndoStore,
    checkpoint: &tron_chainbase::CheckPointV2,
    config: &ExecConfig,
    original_tx_sizes: Option<&[i64]>,
) -> Result<BlockExecutionReport, BlockExecError> {
    execute_block_inner(
        state,
        block,
        expected_parent,
        Some(undo_store),
        Some(checkpoint),
        config,
        original_tx_sizes,
    )
}

/// Decisive apply-phase profiler, env-gated by `APPLY_TIMING` (set to anything
/// but `0`/empty). When catch-up sync is apply-bound, this answers the one
/// question that picks the optimization: is the per-block cost *transaction
/// execution* (the only thing Block-STM parallelism cuts) or *commit I/O* the
/// block-session flush + per-block checkpoint-manifest fsync + undo-log write,
/// none of which parallelism touches? Accumulates the three phases and prints
/// one averaged line every `SAMPLE` blocks via `eprintln!` (matching
/// `BLOCKSTM_DEBUG` — the executor has no `tracing` dep). The single active
/// syncer drives this, so the relaxed atomics never really contend.
mod apply_timing {
    use std::sync::atomic::{AtomicU64, Ordering};

    static EXEC_US: AtomicU64 = AtomicU64::new(0);
    static COMMIT_US: AtomicU64 = AtomicU64::new(0);
    static UNDO_US: AtomicU64 = AtomicU64::new(0);
    static N: AtomicU64 = AtomicU64::new(0);

    const SAMPLE: u64 = 200;

    pub fn enabled() -> bool {
        static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *ON.get_or_init(|| {
            std::env::var("APPLY_TIMING")
                .map(|v| v != "0" && !v.is_empty())
                .unwrap_or(false)
        })
    }

    /// `exec` = `execute_block_logic` (tx execution, parallel or serial).
    /// `commit` = block-session flush + checkpoint manifest write/fsync.
    /// `undo` = undo-log `put`.
    pub fn record(exec_us: u64, commit_us: u64, undo_us: u64) {
        EXEC_US.fetch_add(exec_us, Ordering::Relaxed);
        COMMIT_US.fetch_add(commit_us, Ordering::Relaxed);
        UNDO_US.fetch_add(undo_us, Ordering::Relaxed);
        let n = N.fetch_add(1, Ordering::Relaxed) + 1;
        if n % SAMPLE == 0 {
            let e = EXEC_US.swap(0, Ordering::Relaxed) as f64 / n as f64 / 1000.0;
            let c = COMMIT_US.swap(0, Ordering::Relaxed) as f64 / n as f64 / 1000.0;
            let u = UNDO_US.swap(0, Ordering::Relaxed) as f64 / n as f64 / 1000.0;
            N.store(0, Ordering::Relaxed);
            eprintln!(
                "[apply] /{n} blk: exec_avg={e:.1}ms  commit_avg={c:.1}ms  \
                 undo_avg={u:.2}ms  (exec+commit+undo={:.1}ms/blk → {:.0} blk/s)",
                e + c + u,
                1000.0 / (e + c + u).max(0.001),
            );
        }
    }
}

fn execute_block_inner(
    state: &StateBackends,
    block: &Block,
    expected_parent: Option<BlockId>,
    undo_store: Option<&tron_chainbase::BlockUndoStore>,
    checkpoint: Option<&tron_chainbase::CheckPointV2>,
    config: &ExecConfig,
    original_tx_sizes: Option<&[i64]>,
) -> Result<BlockExecutionReport, BlockExecError> {
    // Undo path: wrap every base backend in a top-level SessionBackend
    // ("block session"). The per-tx sessions inside execute_one_tx
    // become nested overlays — when they commit, writes flow to the
    // block session's overlay, not directly to base. At the end of
    // execute_block_logic we capture the undo log + commit the block
    // session to base.
    //
    // Two commit paths:
    //   * With a CheckPointV2 attached — writes go through a manifest
    //     for cross-store atomicity (the production path).
    //   * Without — each store's session commits independently via
    //     its own write_batch; per-store atomicity only (tests + the
    //     pre-checkpoint code path).
    if let Some(undo_store) = undo_store {
        let timing = apply_timing::enabled();
        let block_session = BlockSession::wrap(state);
        let wrapped = block_session.as_state_backends();
        let t_exec = timing.then(std::time::Instant::now);
        let mut report =
            execute_block_logic(&wrapped, block, expected_parent, config, original_tx_sizes)?;
        let exec_us = t_exec.map(|t| t.elapsed().as_micros() as u64).unwrap_or(0);
        let t_commit = timing.then(std::time::Instant::now);
        let (record, deltas) = if let Some(checkpoint) = checkpoint {
            block_session
                .commit_with_checkpoint_and_undo(
                    checkpoint,
                    state,
                    config.defer_store_fsync,
                    config.capture_state_deltas,
                )
                .map_err(BlockExecError::Checkpoint)?
        } else {
            block_session.commit_with_undo(config.capture_state_deltas)?
        };
        report.state_deltas = deltas;
        let commit_us = t_commit.map(|t| t.elapsed().as_micros() as u64).unwrap_or(0);
        let block_num = block
            .block_header
            .as_ref()
            .and_then(|h| h.raw_data.as_ref())
            .map(|r| r.number)
            .unwrap_or(0);
        let t_undo = timing.then(std::time::Instant::now);
        undo_store.put(block_num, &record)?;
        if timing {
            let undo_us = t_undo.map(|t| t.elapsed().as_micros() as u64).unwrap_or(0);
            apply_timing::record(exec_us, commit_us, undo_us);
        }
        return Ok(report);
    }
    execute_block_logic(state, block, expected_parent, config, original_tx_sizes)
}

/// Block-level session: wraps every base backend on a [`StateBackends`]
/// in a [`SessionBackend`]. Per-tx sessions inside the executor nest
/// over this block-level session so they commit to the block overlay
/// rather than directly to base. At the end of block execution,
/// [`BlockSession::commit_with_undo`] flushes the overlay to base and
/// returns the captured undo log.
struct BlockSession {
    accounts: Arc<SessionBackend>,
    witnesses: Arc<SessionBackend>,
    votes: Arc<SessionBackend>,
    delegation: Arc<SessionBackend>,
    delegated_resources: Arc<SessionBackend>,
    delegated_resource_account_index: Option<Arc<SessionBackend>>,
    dyn_props: Arc<SessionBackend>,
    proposals: Arc<SessionBackend>,
    name_index: Arc<SessionBackend>,
    id_index: Arc<SessionBackend>,
    asset_v1: Arc<SessionBackend>,
    asset_v2: Arc<SessionBackend>,
    contracts: Arc<SessionBackend>,
    abi: Arc<SessionBackend>,
    exchange_v1: Arc<SessionBackend>,
    exchange_v2: Arc<SessionBackend>,
    market_orders: Arc<SessionBackend>,
    market_account: Arc<SessionBackend>,
    nullifiers: Arc<SessionBackend>,
    merkle_trees: Option<Arc<SessionBackend>>,
    code: Option<Arc<SessionBackend>>,
    storage_row: Option<Arc<SessionBackend>>,
    contract_state: Option<Arc<SessionBackend>>,
    block_index: Option<Arc<SessionBackend>>,
    witness_schedule: Option<Arc<SessionBackend>>,
    /// READ-ONLY pass-through — see `StateBackends::reward_vi`.
    reward_vi: Option<Arc<dyn tron_chainbase::KvBackend>>,
}

impl BlockSession {
    fn wrap(state: &StateBackends) -> Self {
        Self {
            accounts: Arc::new(SessionBackend::new(state.accounts.clone())),
            witnesses: Arc::new(SessionBackend::new(state.witnesses.clone())),
            votes: Arc::new(SessionBackend::new(state.votes.clone())),
            delegation: Arc::new(SessionBackend::new(state.delegation.clone())),
            delegated_resources: Arc::new(SessionBackend::new(state.delegated_resources.clone())),
            delegated_resource_account_index: state
                .delegated_resource_account_index
                .as_ref()
                .map(|b| Arc::new(SessionBackend::new(b.clone()))),
            dyn_props: Arc::new(SessionBackend::new(state.dyn_props.clone())),
            proposals: Arc::new(SessionBackend::new(state.proposals.clone())),
            name_index: Arc::new(SessionBackend::new(state.name_index.clone())),
            id_index: Arc::new(SessionBackend::new(state.id_index.clone())),
            asset_v1: Arc::new(SessionBackend::new(state.asset_v1.clone())),
            asset_v2: Arc::new(SessionBackend::new(state.asset_v2.clone())),
            contracts: Arc::new(SessionBackend::new(state.contracts.clone())),
            abi: Arc::new(SessionBackend::new(state.abi.clone())),
            exchange_v1: Arc::new(SessionBackend::new(state.exchange_v1.clone())),
            exchange_v2: Arc::new(SessionBackend::new(state.exchange_v2.clone())),
            market_orders: Arc::new(SessionBackend::new(state.market_orders.clone())),
            market_account: Arc::new(SessionBackend::new(state.market_account.clone())),
            nullifiers: Arc::new(SessionBackend::new(state.nullifiers.clone())),
            merkle_trees: state
                .merkle_trees
                .as_ref()
                .map(|b| Arc::new(SessionBackend::new(b.clone()))),
            code: state.code.as_ref().map(|b| Arc::new(SessionBackend::new(b.clone()))),
            storage_row: state
                .storage_row
                .as_ref()
                .map(|b| Arc::new(SessionBackend::new(b.clone()))),
            contract_state: state
                .contract_state
                .as_ref()
                .map(|b| Arc::new(SessionBackend::new(b.clone()))),
            block_index: state
                .block_index
                .as_ref()
                .map(|b| Arc::new(SessionBackend::new(b.clone()))),
            witness_schedule: state
                .witness_schedule
                .as_ref()
                .map(|b| Arc::new(SessionBackend::new(b.clone()))),
            reward_vi: state.reward_vi.clone(),
        }
    }

    /// Produce a [`StateBackends`] whose backends are the session
    /// overlays from this `BlockSession`. The executor calls into this
    /// for the duration of one block.
    fn as_state_backends(&self) -> StateBackends {
        StateBackends {
            accounts: self.accounts.clone(),
            witnesses: self.witnesses.clone(),
            votes: self.votes.clone(),
            delegation: self.delegation.clone(),
            delegated_resources: self.delegated_resources.clone(),
            delegated_resource_account_index: self
                .delegated_resource_account_index
                .clone()
                .map(|s| s as Arc<dyn tron_chainbase::KvBackend>),
            dyn_props: self.dyn_props.clone(),
            proposals: self.proposals.clone(),
            name_index: self.name_index.clone(),
            id_index: self.id_index.clone(),
            asset_v1: self.asset_v1.clone(),
            asset_v2: self.asset_v2.clone(),
            contracts: self.contracts.clone(),
            abi: self.abi.clone(),
            exchange_v1: self.exchange_v1.clone(),
            exchange_v2: self.exchange_v2.clone(),
            market_orders: self.market_orders.clone(),
            market_account: self.market_account.clone(),
            nullifiers: self.nullifiers.clone(),
            merkle_trees: self.merkle_trees.clone().map(|s| s as Arc<dyn tron_chainbase::KvBackend>),
            code: self.code.clone().map(|s| s as Arc<dyn tron_chainbase::KvBackend>),
            storage_row: self.storage_row.clone().map(|s| s as Arc<dyn tron_chainbase::KvBackend>),
            contract_state: self
                .contract_state
                .clone()
                .map(|s| s as Arc<dyn tron_chainbase::KvBackend>),
            block_index: self.block_index.clone().map(|s| s as Arc<dyn tron_chainbase::KvBackend>),
            witness_schedule: self
                .witness_schedule
                .clone()
                .map(|s| s as Arc<dyn tron_chainbase::KvBackend>),
            reward_vi: self.reward_vi.clone(),
        }
    }

    /// Commit every store's overlay to its base backend, capturing
    /// `(store_id, key, before_image)` triples for each write. The
    /// result is one [`BlockUndoRecord`] suitable for persistence.
    fn commit_with_undo(
        self,
        capture_deltas: bool,
    ) -> Result<
        (tron_chainbase::BlockUndoRecord, Option<Vec<CapturedDelta>>),
        tron_chainbase::KvError,
    > {
        use tron_chainbase::{UndoStoreId as Id, WriteOp};
        let mut record = tron_chainbase::BlockUndoRecord::new();
        let mut deltas: Option<Vec<CapturedDelta>> = capture_deltas.then(Vec::new);
        // `commit_with_undo_and_ops` builds the ops vec internally
        // either way; the only capture-mode cost is moving entries
        // into `CapturedDelta` (ops and undo are parallel, same key
        // order — see `SessionBackend::drain_pending_with_undo`).
        let mut push = |id: Id,
                        (ops, undo): (Vec<WriteOp>, Vec<(Vec<u8>, Option<Vec<u8>>)>)| {
            if let Some(deltas) = deltas.as_mut() {
                for (op, (_, before)) in ops.into_iter().zip(undo.iter()) {
                    let (key, after) = match op {
                        WriteOp::Put(k, v) => (k, Some(v)),
                        WriteOp::Delete(k) => (k, None),
                    };
                    deltas.push(CapturedDelta { store: id, key, before: before.clone(), after });
                }
            }
            for (key, before) in undo {
                record.push(tron_chainbase::UndoEntry { store: id, key, before });
            }
        };
        push(Id::Accounts, self.accounts.commit_with_undo_and_ops()?);
        push(Id::Witnesses, self.witnesses.commit_with_undo_and_ops()?);
        push(Id::Votes, self.votes.commit_with_undo_and_ops()?);
        push(Id::Delegation, self.delegation.commit_with_undo_and_ops()?);
        push(Id::DelegatedResources, self.delegated_resources.commit_with_undo_and_ops()?);
        push(Id::DynProps, self.dyn_props.commit_with_undo_and_ops()?);
        push(Id::Proposals, self.proposals.commit_with_undo_and_ops()?);
        push(Id::NameIndex, self.name_index.commit_with_undo_and_ops()?);
        push(Id::IdIndex, self.id_index.commit_with_undo_and_ops()?);
        push(Id::AssetV1, self.asset_v1.commit_with_undo_and_ops()?);
        push(Id::AssetV2, self.asset_v2.commit_with_undo_and_ops()?);
        push(Id::Contracts, self.contracts.commit_with_undo_and_ops()?);
        push(Id::Abi, self.abi.commit_with_undo_and_ops()?);
        push(Id::ExchangeV1, self.exchange_v1.commit_with_undo_and_ops()?);
        push(Id::ExchangeV2, self.exchange_v2.commit_with_undo_and_ops()?);
        push(Id::MarketOrders, self.market_orders.commit_with_undo_and_ops()?);
        push(Id::MarketAccount, self.market_account.commit_with_undo_and_ops()?);
        push(Id::Nullifiers, self.nullifiers.commit_with_undo_and_ops()?);
        if let Some(s) = self.delegated_resource_account_index {
            push(Id::DelegatedResourceAccountIndex, s.commit_with_undo_and_ops()?);
        }
        if let Some(s) = self.merkle_trees {
            push(Id::MerkleTrees, s.commit_with_undo_and_ops()?);
        }
        if let Some(s) = self.code {
            push(Id::Code, s.commit_with_undo_and_ops()?);
        }
        if let Some(s) = self.storage_row {
            push(Id::StorageRow, s.commit_with_undo_and_ops()?);
        }
        if let Some(s) = self.contract_state {
            push(Id::ContractState, s.commit_with_undo_and_ops()?);
        }
        if let Some(s) = self.block_index {
            push(Id::BlockIndex, s.commit_with_undo_and_ops()?);
        }
        if let Some(s) = self.witness_schedule {
            push(Id::WitnessSchedule, s.commit_with_undo_and_ops()?);
        }
        if let Some(d) = deltas.as_mut() {
            d.sort_by(|a, b| (a.store as u8, &a.key).cmp(&(b.store as u8, &b.key)));
        }
        Ok((record, deltas))
    }

    /// Commit every store's overlay to its base backend under one
    /// cross-store atomicity boundary: the [`CheckPointV2`] manifest.
    ///
    /// Composition of [`drain_block_session`] (capture pre-images +
    /// build the undo record) and [`commit_drained`] (manifest +
    /// per-store flush + durability barriers) — the same two halves
    /// the pipelined applier runs on separate threads. Keeping one
    /// implementation for both paths means a future correctness change
    /// can't land on only one of them.
    fn commit_with_checkpoint_and_undo(
        self,
        checkpoint: &tron_chainbase::CheckPointV2,
        state: &StateBackends,
        defer_store_fsync: bool,
        capture_deltas: bool,
    ) -> Result<
        (tron_chainbase::BlockUndoRecord, Option<Vec<CapturedDelta>>),
        tron_chainbase::CheckpointError,
    > {
        let drained = drain_block_session(self, state, capture_deltas)
            .map_err(|e| tron_chainbase::CheckpointError::Decode(e.to_string()))?;
        commit_drained(&drained.stores, checkpoint, state, defer_store_fsync)?;
        Ok((drained.record, drained.deltas))
    }
}

/// One block's fully-drained write-set, ready to commit: per-store
/// batches paired with the base backend they flush to, plus the undo
/// record (pre-images) and optional captured deltas built from the
/// same drain pass.
pub(crate) struct DrainedBlock {
    /// `(store, base_backend, ops)` for every store the block wrote,
    /// in `StoreId` variant order (replay determinism). Stores with
    /// no writes are omitted.
    pub(crate) stores: Vec<(
        tron_chainbase::UndoStoreId,
        Arc<dyn tron_chainbase::KvBackend>,
        Vec<tron_chainbase::WriteOp>,
    )>,
    pub(crate) record: tron_chainbase::BlockUndoRecord,
    pub(crate) deltas: Option<Vec<CapturedDelta>>,
}

/// Drain every per-store session of `session`, capturing pre-images
/// for undo. The pre-image reads go through each session's PARENT
/// (whatever the session was wrapped over — base stores on the
/// classic path, the pending overlay on the pipelined path), so they
/// capture the true pre-block state in both. `targets` supplies the
/// BASE backend each batch will later flush to via [`commit_drained`].
pub(crate) fn drain_block_session(
    session: BlockSession,
    targets: &StateBackends,
    capture_deltas: bool,
) -> Result<DrainedBlock, tron_chainbase::KvError> {
    use tron_chainbase::{KvBackend, UndoStoreId as Id, WriteOp};

    let mut record = tron_chainbase::BlockUndoRecord::new();
    let mut deltas: Option<Vec<CapturedDelta>> = capture_deltas.then(Vec::new);
    let mut stores: Vec<(Id, Arc<dyn KvBackend>, Vec<WriteOp>)> = Vec::new();
    let mut take = |id: Id,
                    session: Arc<tron_chainbase::SessionBackend>,
                    base: Arc<dyn KvBackend>|
     -> Result<(), tron_chainbase::KvError> {
        let (ops, undo) = session.drain_pending_with_undo()?;
        if ops.is_empty() {
            return Ok(());
        }
        // Capture before `undo` is consumed for the record — ops and
        // undo are parallel (same drain loop, same key order).
        if let Some(deltas) = deltas.as_mut() {
            for (op, (_, before)) in ops.iter().zip(undo.iter()) {
                let (key, after) = match op {
                    WriteOp::Put(k, v) => (k.clone(), Some(v.clone())),
                    WriteOp::Delete(k) => (k.clone(), None),
                };
                deltas.push(CapturedDelta { store: id, key, before: before.clone(), after });
            }
        }
        for (key, before) in undo {
            record.push(tron_chainbase::UndoEntry { store: id, key, before });
        }
        stores.push((id, base, ops));
        Ok(())
    };
    take(Id::Accounts, session.accounts, targets.accounts.clone())?;
    take(Id::Witnesses, session.witnesses, targets.witnesses.clone())?;
    take(Id::Votes, session.votes, targets.votes.clone())?;
    take(Id::Delegation, session.delegation, targets.delegation.clone())?;
    take(Id::DelegatedResources, session.delegated_resources, targets.delegated_resources.clone())?;
    take(Id::DynProps, session.dyn_props, targets.dyn_props.clone())?;
    take(Id::Proposals, session.proposals, targets.proposals.clone())?;
    take(Id::NameIndex, session.name_index, targets.name_index.clone())?;
    take(Id::IdIndex, session.id_index, targets.id_index.clone())?;
    take(Id::AssetV1, session.asset_v1, targets.asset_v1.clone())?;
    take(Id::AssetV2, session.asset_v2, targets.asset_v2.clone())?;
    take(Id::Contracts, session.contracts, targets.contracts.clone())?;
    take(Id::Abi, session.abi, targets.abi.clone())?;
    take(Id::ExchangeV1, session.exchange_v1, targets.exchange_v1.clone())?;
    take(Id::ExchangeV2, session.exchange_v2, targets.exchange_v2.clone())?;
    take(Id::MarketOrders, session.market_orders, targets.market_orders.clone())?;
    take(Id::MarketAccount, session.market_account, targets.market_account.clone())?;
    take(Id::Nullifiers, session.nullifiers, targets.nullifiers.clone())?;
    if let (Some(s), Some(b)) = (
        session.delegated_resource_account_index,
        targets.delegated_resource_account_index.clone(),
    ) {
        take(Id::DelegatedResourceAccountIndex, s, b)?;
    }
    if let (Some(s), Some(b)) = (session.merkle_trees, targets.merkle_trees.clone()) {
        take(Id::MerkleTrees, s, b)?;
    }
    if let (Some(s), Some(b)) = (session.code, targets.code.clone()) {
        take(Id::Code, s, b)?;
    }
    if let (Some(s), Some(b)) = (session.storage_row, targets.storage_row.clone()) {
        take(Id::StorageRow, s, b)?;
    }
    if let (Some(s), Some(b)) = (session.contract_state, targets.contract_state.clone()) {
        take(Id::ContractState, s, b)?;
    }
    if let (Some(s), Some(b)) = (session.block_index, targets.block_index.clone()) {
        take(Id::BlockIndex, s, b)?;
    }
    if let (Some(s), Some(b)) = (session.witness_schedule, targets.witness_schedule.clone()) {
        take(Id::WitnessSchedule, s, b)?;
    }
    if let Some(d) = deltas.as_mut() {
        d.sort_by(|a, b| (a.store as u8, &a.key).cmp(&(b.store as u8, &b.key)));
    }
    Ok(DrainedBlock { stores, record, deltas })
}

/// Flush a drained block's per-store batches under one cross-store
/// atomicity boundary: the [`CheckPointV2`] manifest.
///
/// Mirrors java-tron's `SnapshotManager.flush`:
///   2. Build a flat manifest of every `(db_name, key, value)`.
///   3. Atomically write the manifest (tmp + rename + fsync).
///   4. Apply each per-store `write_batch` against the base
///      backend (skipping the session overlay — already drained).
///   5. Delete the checkpoint.
///
/// If the process crashes between (3) and (4) — or between (4)
/// and (5) — the next startup runs `replay_checkpoints` which
/// re-applies the manifest entries and deletes the checkpoint.
/// (3)→(4) is the critical window: the manifest gives us a
/// durable, atomic record of *all* the writes the block intended,
/// so re-applying it restores the cross-store invariant. The
/// (4)→(5) replay is harmless — re-applying writes that already
/// landed produces the same state.
pub(crate) fn commit_drained(
    stores: &[(
        tron_chainbase::UndoStoreId,
        Arc<dyn tron_chainbase::KvBackend>,
        Vec<tron_chainbase::WriteOp>,
    )],
    checkpoint: &tron_chainbase::CheckPointV2,
    state: &StateBackends,
    defer_store_fsync: bool,
) -> Result<(), tron_chainbase::CheckpointError> {
    use tron_chainbase::{CheckpointEntry, WriteOp};

    // (2) Build the manifest. Empty block? Skip the manifest
    //     write entirely — there's nothing to make atomic and no
    //     point creating a checkpoint dir we'll immediately delete.
    if stores.is_empty() {
        return Ok(());
    }
    let mut entries: Vec<CheckpointEntry> = Vec::new();
    for (id, _, ops) in stores {
        let db_name = id.db_name();
        for op in ops {
            let (key, value) = match op {
                WriteOp::Put(k, v) => (k.clone(), Some(v.clone())),
                WriteOp::Delete(k) => (k.clone(), None),
            };
            entries.push(CheckpointEntry {
                db_name: db_name.to_string(),
                key,
                value,
            });
        }
    }

    // (3) Atomic commit point — the manifest is now durable.
    //     If we crash anywhere from here on, recovery replays it.
    let checkpoint_id = checkpoint.write(&entries)?;

    // (4) Per-store flush. Each call goes straight to the base
    //     backend (not the drained session).
    //
    //     Steady state (`defer_store_fsync == false`): use
    //     `write_batch_sync` — RocksDB native WriteBatch with
    //     `WriteOptions { sync: true }`. The fsync is required so
    //     step (5)'s manifest delete is safe: once we return from
    //     write_batch_sync the per-store WAL is on disk, so losing
    //     the manifest no longer means losing the writes.
    //
    //     Catch-up (`defer_store_fsync == true`): use the non-sync
    //     `write_batch`. The writes still go to each store's WAL
    //     (just without the fsync); the manifest written in step (3)
    //     IS fsync'd, so it remains a complete, durable record of
    //     this block's cross-store writes. We therefore RETAIN the
    //     manifest (skip step 5) — on a crash the startup replay
    //     re-applies it idempotently, so nothing is lost. The
    //     expensive per-store fsync is amortized by the barrier below.
    for (_, base, ops) in stores {
        if defer_store_fsync {
            base.write_batch(ops)
                .map_err(|e| tron_chainbase::CheckpointError::Decode(e.to_string()))?;
        } else {
            base.write_batch_sync(ops)
                .map_err(|e| tron_chainbase::CheckpointError::Decode(e.to_string()))?;
        }
    }

    if defer_store_fsync {
        // (5-defer) Retain THIS block's manifest (writes aren't fsync'd
        //     yet). Every DEFER_FSYNC_BARRIER_BLOCKS accumulated
        //     manifests, run the durability barrier: fsync every base
        //     store's WAL FIRST, THEN drop all retained manifests.
        //     Order is critical — fsync before delete — so a crash
        //     mid-barrier (stores durable, manifests still present)
        //     only causes a harmless idempotent replay, never loss.
        if checkpoint.list()?.len() >= DEFER_FSYNC_BARRIER_BLOCKS {
            flush_state_wals_and_clear_checkpoints(state, checkpoint)?;
        }
    } else {
        // (5) Steady state: this block's writes are durable.
        checkpoint.delete(checkpoint_id)?;
        // If we just transitioned out of catch-up, deferred manifests
        // from earlier blocks may still be retained. This block's
        // per-store write_batch_sync only fsync'd the stores IT wrote,
        // so explicitly barrier (fsync ALL stores, then clear) to make
        // those earlier deferred writes durable before dropping their
        // manifests.
        if !checkpoint.list()?.is_empty() {
            flush_state_wals_and_clear_checkpoints(state, checkpoint)?;
        }
    }
    Ok(())
}

/// Durability barrier for the deferred-fsync catch-up path: fsync every
/// base store's WAL, THEN delete all retained cross-store manifests.
///
/// The ordering (fsync-all before delete-any) is the safety invariant: a
/// crash after the fsyncs but before/within the deletes just leaves
/// manifests to be replayed idempotently on restart; we never delete a
/// manifest whose writes aren't yet durable.
pub fn flush_state_wals_and_clear_checkpoints(
    state: &StateBackends,
    checkpoint: &tron_chainbase::CheckPointV2,
) -> Result<(), tron_chainbase::CheckpointError> {
    sync_all_state_wals(state).map_err(|e| tron_chainbase::CheckpointError::Decode(e.to_string()))?;
    for id in checkpoint.list()? {
        // A concurrent reader/pruner could have removed it already; treat
        // NotFound as success.
        match checkpoint.delete(id) {
            Ok(()) | Err(tron_chainbase::CheckpointError::NotFound(_)) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// fsync the WAL of every base backend referenced by `state`. No-op for
/// in-memory backends. Covers every store `commit_with_checkpoint_and_undo`
/// can write, so after this returns all deferred (non-sync) writes are
/// durable.
fn sync_all_state_wals(state: &StateBackends) -> Result<(), tron_chainbase::KvError> {
    use tron_chainbase::KvBackend;
    let sync = |b: &Arc<dyn KvBackend>| b.sync_wal();
    sync(&state.accounts)?;
    sync(&state.witnesses)?;
    sync(&state.votes)?;
    sync(&state.delegation)?;
    sync(&state.delegated_resources)?;
    sync(&state.dyn_props)?;
    sync(&state.proposals)?;
    sync(&state.name_index)?;
    sync(&state.id_index)?;
    sync(&state.asset_v1)?;
    sync(&state.asset_v2)?;
    sync(&state.contracts)?;
    sync(&state.abi)?;
    sync(&state.exchange_v1)?;
    sync(&state.exchange_v2)?;
    sync(&state.market_orders)?;
    sync(&state.market_account)?;
    sync(&state.nullifiers)?;
    if let Some(b) = &state.delegated_resource_account_index {
        sync(b)?;
    }
    if let Some(b) = &state.merkle_trees {
        sync(b)?;
    }
    if let Some(b) = &state.code {
        sync(b)?;
    }
    if let Some(b) = &state.storage_row {
        sync(b)?;
    }
    if let Some(b) = &state.contract_state {
        sync(b)?;
    }
    if let Some(b) = &state.block_index {
        sync(b)?;
    }
    if let Some(b) = &state.witness_schedule {
        sync(b)?;
    }
    Ok(())
}

/// Replay every leftover cross-store checkpoint into `state`, then
/// delete each as it succeeds. This is the daemon startup path —
/// must run BEFORE the node starts serving blocks. Idempotent:
/// re-applying writes that already landed produces the same state.
///
/// Manifest entries are routed to backends by `db_name`. An unknown
/// name is a hard error — it means the checkpoint was produced by a
/// different node build with stores this one doesn't know about, and
/// silently dropping the entry could leave the on-disk state
/// inconsistent. The operator should investigate (typically: roll
/// back to a matching build or wipe the checkpoint dir).
///
/// Returns `(checkpoints_replayed, entries_applied)`.
pub fn replay_pending_checkpoints(
    state: &StateBackends,
    checkpoint: &tron_chainbase::CheckPointV2,
) -> Result<(usize, usize), tron_chainbase::CheckpointError> {
    use tron_chainbase::{CheckpointEntry, KvBackend};

    // Build a name → backend lookup. The full set covers every
    // store BlockSession::commit_with_checkpoint_and_undo can write.
    let mut by_name: std::collections::HashMap<&'static str, Arc<dyn KvBackend>> =
        std::collections::HashMap::new();
    use tron_chainbase::UndoStoreId as Id;
    by_name.insert(Id::Accounts.db_name(), state.accounts.clone());
    by_name.insert(Id::Witnesses.db_name(), state.witnesses.clone());
    by_name.insert(Id::Votes.db_name(), state.votes.clone());
    by_name.insert(Id::Delegation.db_name(), state.delegation.clone());
    by_name.insert(Id::DelegatedResources.db_name(), state.delegated_resources.clone());
    by_name.insert(Id::DynProps.db_name(), state.dyn_props.clone());
    by_name.insert(Id::Proposals.db_name(), state.proposals.clone());
    by_name.insert(Id::NameIndex.db_name(), state.name_index.clone());
    by_name.insert(Id::IdIndex.db_name(), state.id_index.clone());
    by_name.insert(Id::AssetV1.db_name(), state.asset_v1.clone());
    by_name.insert(Id::AssetV2.db_name(), state.asset_v2.clone());
    by_name.insert(Id::Contracts.db_name(), state.contracts.clone());
    by_name.insert(Id::Abi.db_name(), state.abi.clone());
    by_name.insert(Id::ExchangeV1.db_name(), state.exchange_v1.clone());
    by_name.insert(Id::ExchangeV2.db_name(), state.exchange_v2.clone());
    by_name.insert(Id::MarketOrders.db_name(), state.market_orders.clone());
    by_name.insert(Id::MarketAccount.db_name(), state.market_account.clone());
    by_name.insert(Id::Nullifiers.db_name(), state.nullifiers.clone());
    if let Some(b) = state.delegated_resource_account_index.clone() {
        by_name.insert(Id::DelegatedResourceAccountIndex.db_name(), b);
    }
    if let Some(b) = state.merkle_trees.clone() {
        by_name.insert(Id::MerkleTrees.db_name(), b);
    }
    if let Some(b) = state.code.clone() {
        by_name.insert(Id::Code.db_name(), b);
    }
    if let Some(b) = state.storage_row.clone() {
        by_name.insert(Id::StorageRow.db_name(), b);
    }
    if let Some(b) = state.contract_state.clone() {
        by_name.insert(Id::ContractState.db_name(), b);
    }
    if let Some(b) = state.block_index.clone() {
        by_name.insert(Id::BlockIndex.db_name(), b);
    }
    if let Some(b) = state.witness_schedule.clone() {
        by_name.insert(Id::WitnessSchedule.db_name(), b);
    }

    let ids = checkpoint.list()?;
    let mut total_entries = 0;
    let mut total_checkpoints = 0;
    for id in &ids {
        let n = checkpoint.replay(*id, |entry: &CheckpointEntry| {
            match by_name.get(entry.db_name.as_str()) {
                Some(backend) => match &entry.value {
                    Some(v) => backend
                        .put(&entry.key, v)
                        .map_err(|e| tron_chainbase::CheckpointError::Decode(e.to_string()))?,
                    None => backend
                        .delete(&entry.key)
                        .map_err(|e| tron_chainbase::CheckpointError::Decode(e.to_string()))?,
                },
                None => {
                    return Err(tron_chainbase::CheckpointError::Decode(format!(
                        "checkpoint {} references unknown store '{}' — operator must investigate before continuing",
                        id, entry.db_name
                    )));
                }
            }
            Ok(())
        })?;
        checkpoint.delete(*id)?;
        total_entries += n;
        total_checkpoints += 1;
    }
    Ok((total_checkpoints, total_entries))
}

/// Replay a previously-captured undo log to restore base-store state
/// to its pre-block contents. The log is read from `undo_store` keyed
/// by `block_num` and then deleted (records aren't useful after
/// successful rollback). Order doesn't matter — each entry is an
/// independent (store, key) point overwrite.
///
/// Returns the number of entries replayed. Errors only on a malformed
/// undo record or an unknown store id.
pub fn rollback_block(
    state: &StateBackends,
    block_num: i64,
    undo_store: &tron_chainbase::BlockUndoStore,
) -> Result<usize, RollbackError> {
    use tron_chainbase::UndoStoreId as Id;
    let record = undo_store
        .get(block_num)
        .map_err(|e| RollbackError::Decode(format!("{e:?}")))?
        .ok_or(RollbackError::MissingUndoRecord(block_num))?;
    let n = record.entries.len();
    for entry in &record.entries {
        let backend: &Arc<dyn tron_chainbase::KvBackend> = match entry.store {
            Id::Accounts => &state.accounts,
            Id::Witnesses => &state.witnesses,
            Id::Votes => &state.votes,
            Id::Delegation => &state.delegation,
            Id::DelegatedResources => &state.delegated_resources,
            Id::DynProps => &state.dyn_props,
            Id::Proposals => &state.proposals,
            Id::NameIndex => &state.name_index,
            Id::IdIndex => &state.id_index,
            Id::AssetV1 => &state.asset_v1,
            Id::AssetV2 => &state.asset_v2,
            Id::Contracts => &state.contracts,
            Id::Abi => &state.abi,
            Id::ExchangeV1 => &state.exchange_v1,
            Id::ExchangeV2 => &state.exchange_v2,
            Id::MarketOrders => &state.market_orders,
            Id::MarketAccount => &state.market_account,
            Id::Nullifiers => &state.nullifiers,
            Id::MerkleTrees => state
                .merkle_trees
                .as_ref()
                .ok_or(RollbackError::OptionalStoreNotAttached("merkle_trees"))?,
            Id::Code => state.code.as_ref().ok_or(RollbackError::OptionalStoreNotAttached("code"))?,
            Id::StorageRow => state
                .storage_row
                .as_ref()
                .ok_or(RollbackError::OptionalStoreNotAttached("storage_row"))?,
            Id::ContractState => state
                .contract_state
                .as_ref()
                .ok_or(RollbackError::OptionalStoreNotAttached("contract_state"))?,
            Id::BlockIndex => state
                .block_index
                .as_ref()
                .ok_or(RollbackError::OptionalStoreNotAttached("block_index"))?,
            Id::WitnessSchedule => state
                .witness_schedule
                .as_ref()
                .ok_or(RollbackError::OptionalStoreNotAttached("witness_schedule"))?,
            Id::DelegatedResourceAccountIndex => state
                .delegated_resource_account_index
                .as_ref()
                .ok_or(RollbackError::OptionalStoreNotAttached(
                    "delegated_resource_account_index",
                ))?,
        };
        match &entry.before {
            Some(v) => backend.put(&entry.key, v)?,
            None => backend.delete(&entry.key)?,
        }
    }
    undo_store.delete(block_num)?;
    Ok(n)
}

#[derive(Debug, thiserror::Error)]
pub enum RollbackError {
    #[error("no undo record stored for block {0}")]
    MissingUndoRecord(i64),
    #[error("undo record decode failed: {0}")]
    Decode(String),
    #[error("rollback log references store '{0}' but it isn't attached on this node")]
    OptionalStoreNotAttached(&'static str),
    #[error("kv backend error during rollback: {0}")]
    Kv(#[from] tron_chainbase::KvError),
    #[error("store error during rollback: {0}")]
    Store(#[from] tron_chainbase::StoreError),
}

/// The address whose key must have produced `block`'s signature, per
/// java-tron's `BlockCapsule.validateSignature`.
///
/// When `ALLOW_MULTI_SIGN == 1` (the mainnet default for years) a witness
/// may sign blocks with a delegated **witness-permission** key rather than
/// its account key — cold/hot key separation. In that mode the signature
/// must recover to `witness_permission.keys[0].address`, falling back to
/// the account address when the producer set no witness permission (or its
/// account row is somehow absent). When multi-sign is off, the witness
/// account address itself must have signed.
///
/// The producer is `block.witness_address`; its account is read from
/// current state — i.e. as of the parent block, before this block is
/// applied — exactly as java-tron reads `accountStore` at `pushBlock`.
///
/// Pass the result as the `expected_signer` override to
/// [`verify_witness_signature`]. Passing `None` there instead silently
/// demands the account key and so rejects every delegated-signer block —
/// roughly a quarter of mainnet's blocks.
pub fn expected_block_signer(
    block: &Block,
    state: &StateBackends,
) -> Result<tron_crypto::address::Address, BlockExecError> {
    use tron_crypto::address::Address;

    let raw = block
        .block_header
        .as_ref()
        .and_then(|h| h.raw_data.as_ref())
        .ok_or(BlockValidateError::MissingHeader)?;
    if raw.witness_address.len() != 21 {
        return Err(BlockValidateError::WitnessAddressLength(raw.witness_address.len()).into());
    }
    let mut buf = [0u8; 21];
    buf.copy_from_slice(&raw.witness_address);
    let witness_address = Address::from_raw(buf);

    // Multi-sign disabled → the witness account key signs directly.
    let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
    if dp.get_long(b"ALLOW_MULTI_SIGN") != Some(1) {
        return Ok(witness_address);
    }

    // Multi-sign enabled → the witness-permission key signs. Fall back to
    // the account address if no witness permission is set, the key list is
    // empty, the key is malformed, or the account row is absent.
    let accounts = AccountStore::new(state.accounts.clone());
    let signer = accounts
        .get(&witness_address)?
        .and_then(|acct| acct.witness_permission)
        .and_then(|perm| perm.keys.into_iter().next())
        .map(|key| key.address)
        .filter(|addr| addr.len() == 21)
        .map(|addr| {
            let mut b = [0u8; 21];
            b.copy_from_slice(&addr);
            Address::from_raw(b)
        })
        .unwrap_or(witness_address);
    Ok(signer)
}

/// Pure executor logic — operates on whatever [`StateBackends`] is
/// handed in. The top-level [`execute_block_inner`] dispatches here
/// either against base backends directly (no undo) or against a
/// [`BlockSession`] overlay (undo path).
fn execute_block_logic(
    state: &StateBackends,
    block: &Block,
    expected_parent: Option<BlockId>,
    config: &ExecConfig,
    // Per-tx ORIGINAL serialized wire sizes (java's getSerializedSize), in
    // block order, captured at ingest from the raw block bytes. `None` for
    // in-memory callers whose blocks are already prost-canonical.
    original_tx_sizes: Option<&[i64]>,
) -> Result<BlockExecutionReport, BlockExecError> {
    // === 1. Structural validation (read-only; safe to use base directly) ===
    if let Some(parent) = expected_parent {
        verify_parent_link(block, parent)?;
    }
    if config.verify_tx_trie {
        verify_tx_trie_root(block)?;
    }
    // Witness-signature gate. `config.require_signature` defaults to
    // `true`; the block-production dry-run path (and a few tests that
    // build synthetic unsigned blocks) opt out via `ExecConfig::unsigned`.
    // The underlying `verify_witness_signature` returns
    // `BlockValidateError::MissingSignature` on an empty `witness_signature`
    // — so under strict mode an unsigned block is rejected here, not
    // silently applied.
    if config.require_signature {
        // Authorize against the producer's witness-permission key when
        // `ALLOW_MULTI_SIGN` is on (mainnet), else the account key. Passing
        // `None` would demand the account key unconditionally and reject
        // every delegated cold/hot-key SR. See [`expected_block_signer`].
        let expected = expected_block_signer(block, state)?;
        verify_witness_signature(block, Some(&expected))?;
    }

    // Lift the header out once — needed both by the per-tx loop (for
    // `block_timestamp`, the reference frame for expiration checks) and
    // by the head-pointer update in step 3.
    let block_id = block_id_from_block(block).map_err(|_| BlockExecError::NoHeader)?;
    let header = block.block_header.as_ref().ok_or(BlockExecError::NoHeader)?;
    let raw = header.raw_data.as_ref().ok_or(BlockExecError::NoHeader)?;
    let block_timestamp_ms = raw.timestamp;

    // === 2. Parallel signer-recovery pre-pass ===
    //
    // ECDSA signer recovery is the dominant per-tx CPU cost on the
    // non-VM path and is a *pure* function of `(raw_data, signature[])` —
    // independent across transactions, reads no chain state, mutates
    // nothing. Recover every tx's signers across cores here, then hand the
    // positionally-indexed results into the strictly-serial per-tx loop
    // below (which still applies state in order). This mirrors java-tron's
    // CountDownLatch signature-verify pool.
    //
    // Correctness: `collect()` preserves order, so `precomputed[i]`
    // corresponds to `block.transactions[i]`; errors are carried as
    // `String` and surfaced by `check_transaction_permission_with_signers`
    // at the exact same validation step (after the structural checks) they
    // would have been raised inline — so the per-tx outcome is identical to
    // the old serial recovery.
    let precomputed_signers: Vec<Result<Vec<Address>, String>> = block
        .transactions
        .par_iter()
        .map(|tx| recover_all_signers(tx).map_err(|e| e.to_string()))
        .collect();

    // === 2b. Per-tx atomic loop (serial — state application is ordered) ===
    //
    // `now_slot` (the bandwidth-recovery reference slot) depends only on
    // the genesis timestamp and the parent block's header time — both
    // fixed for this whole block — so compute it once here instead of
    // per-tx inside the bandwidth charge.
    let now_slot = head_slot(&DynamicPropertiesStore::new(state.dyn_props.clone()));
    // Parent block (N-1) raw stored timestamp — java's `getHeadBlockTimeStamp()`,
    // the reference for the per-tx expiration window (`Manager.validateCommon`).
    // The head pointer is still N-1 here: `save_latest_block_header_timestamp(N)`
    // runs only AFTER this tx loop. Read it ONCE at the block level and thread
    // it into every tx exactly like `now_slot`, so the serial and Block-STM
    // paths see byte-identical input. Falls back to the lossy slot-derived value
    // (genesis ts = 0, 3 s slots) only if the key is somehow absent — which on a
    // real chain it never is past genesis.
    let head_block_time_ms = DynamicPropertiesStore::new(state.dyn_props.clone())
        .latest_block_header_timestamp()
        .unwrap_or_else(|| now_slot.saturating_mul(3_000));
    // Block-STM parallel execution when enabled, else the serial loop. The
    // parallel path commits writes to `state` in tx order itself and returns the
    // ordered results; it returns `None` only on the (should-never-happen)
    // non-convergence safety hatch, in which case we fall through to serial. The
    // serial path remains the byte-identical source of truth.
    //
    // The work gate (skip parallel for light blocks) lives in the sync driver
    // via [`block_worth_parallel`], which sets `config.parallel_exec`. Here we
    // simply honor it — so tests that force `parallel_exec = true` always
    // exercise the parallel path regardless of block size.
    // COINBASE (0x41): the block's producing witness in 20-byte EVM form (strip
    // the TRON 0x41 prefix), threaded into every tx's VM block env.
    let block_beneficiary: [u8; 20] = {
        let w = &raw.witness_address;
        let mut b = [0u8; 20];
        if w.len() >= 20 {
            b.copy_from_slice(&w[w.len() - 20..]);
        }
        b
    };
    let tx_results: Vec<TxResult> = if config.parallel_exec {
        crate::parallel::execute_block_parallel(
            state,
            &block.transactions,
            config,
            raw.number,
            block_timestamp_ms,
            block_beneficiary,
            now_slot,
            head_block_time_ms,
            &precomputed_signers,
            original_tx_sizes,
        )
    } else {
        None
    }
    .unwrap_or_else(|| {
        block
            .transactions
            .iter()
            .enumerate()
            .map(|(i, tx)| {
                execute_one_tx(
                    state,
                    tx,
                    config,
                    raw.number,
                    block_timestamp_ms,
                    block_beneficiary,
                    now_slot,
                    head_block_time_ms,
                    &precomputed_signers[i],
                    original_tx_sizes.and_then(|s| s.get(i).copied()),
                )
            })
            .collect()
    });

    // === 2c. contractRet tripwire (silent-divergence guard) ===
    //
    // Compare each VM tx's computed result against the block's stored
    // `ret[0].contractRet`, but only on the consensus-critical axis:
    // did we agree on success vs failure? A SUCCESS tx mutates state; a
    // failed one does not (beyond fees) — so a success/failure disagreement
    // is real divergence (java-tron `TransactionTrace.check`). Failure-code
    // *detail* mismatches (our coarse Halt→UNKNOWN mapping vs java's specific
    // code) are ignored. `OUT_OF_TIME` is node-local (java retries) and
    // excluded on either side. Always logged; hard-rejects only when
    // `verify_contract_ret` is set.
    {
        use tron_proto::transaction::result::ContractResult;
        const SUCCESS: i32 = ContractResult::Success as i32;
        const OUT_OF_TIME: i32 = ContractResult::OutOfTime as i32;
        let ret_name = |x: i32| {
            ContractResult::try_from(x)
                .map(|c| c.as_str_name())
                .unwrap_or("?")
        };
        use tron_proto::transaction::result::Code;
        const RET_SUCCESS: i32 = Code::Sucess as i32;
        // Env-gated diagnostic: per-tx fee/energy/net trace over a block window, so
        // SILENT charge divergences (fees/energy our node computes differently
        // from java — which the success/failure contractRet tripwire can't see)
        // can be diffed against java's `gettransactioninfobyblocknum`. Gated by
        // TRON_FEE_TRACE_FROM / TRON_FEE_TRACE_TO (block numbers); off by default.
        let fee_trace = std::env::var("TRON_FEE_TRACE_FROM")
            .ok()
            .and_then(|f| f.parse::<i64>().ok())
            .zip(
                std::env::var("TRON_FEE_TRACE_TO")
                    .ok()
                    .and_then(|t| t.parse::<i64>().ok()),
            )
            .map(|(from, to)| raw.number >= from && raw.number <= to)
            .unwrap_or(false);
        // Env-gated diagnostic: per-block balance/frozen snapshot for ONE target
        // account (TRON_BAL_TRACE_ADDR=<42-char 41-hex>). State is committed in
        // tx order before this point, so `state.accounts` holds the post-block
        // value. Lets a balance-drift root invisible to the fee/contractRet
        // tripwires be diffed per-block against java's oracle acct dump.
        if let Ok(hex) = std::env::var("TRON_BAL_TRACE_ADDR") {
            let bytes: Vec<u8> = (0..hex.len() / 2)
                .filter_map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok())
                .collect();
            if bytes.len() == 21 {
                let mut b = [0u8; 21];
                b.copy_from_slice(&bytes);
                let acct_store = AccountStore::new(state.accounts.clone());
                if let Ok(Some(a)) = acct_store.get(&Address::from_raw(b)) {
                    let fz_bw: i64 = a.frozen_v2.iter().filter(|f| f.r#type == 0).map(|f| f.amount).sum();
                    let fz_en: i64 = a.frozen_v2.iter().filter(|f| f.r#type == 1).map(|f| f.amount).sum();
                    let ar = a.account_resource.as_ref();
                    eprintln!(
                        "BAL_TRACE blk={} balance={} frozenV2_bw={} frozenV2_energy={} energy_usage={} net_usage={} deleg_energy={} acq_deleg_energy={} net_window_size={} latest_consume_time={} net_window_optimized={}",
                        raw.number,
                        a.balance,
                        fz_bw,
                        fz_en,
                        ar.map(|r| r.energy_usage).unwrap_or(0),
                        a.net_usage,
                        ar.map(|r| r.delegated_frozen_v2_balance_for_energy).unwrap_or(0),
                        ar.map(|r| r.acquired_delegated_frozen_v2_balance_for_energy).unwrap_or(0),
                        a.net_window_size,
                        a.latest_consume_time,
                        a.net_window_optimized,
                    );
                }
            }
        }
        // Env-gated diagnostic: per-block chain-wide resource-weight totals
        // (TRON_TNW_TRACE=1). Diffs the TOTAL_*_WEIGHT accumulators against
        // java's per-block totals to localize a weight-accounting drift.
        if std::env::var("TRON_TNW_TRACE").is_ok() {
            let dp = tron_chainbase::DynamicPropertiesStore::new(state.dyn_props.clone());
            eprintln!(
                "TNW blk={} tnw={} tew={} ttpw={}",
                raw.number,
                dp.total_net_weight(),
                dp.total_energy_weight(),
                dp.total_tron_power_weight(),
            );
        }
        // Env-gated diagnostic: per-block delegation reward-cycle snapshot for ONE
        // voter (TRON_REWARD_TRACE_ADDR=<42-char 41-hex>). Tracks begin_cycle /
        // end_cycle against the chain's current_cycle to catch a begin_cycle that
        // advances out of step with java — an early/skipped reward settlement that
        // empties later reward windows (invisible to the fee/contractRet tripwires).
        if let Ok(hex) = std::env::var("TRON_REWARD_TRACE_ADDR") {
            let bytes: Vec<u8> = (0..hex.len() / 2)
                .filter_map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok())
                .collect();
            if bytes.len() == 21 {
                let mut b = [0u8; 21];
                b.copy_from_slice(&bytes);
                let addr = Address::from_raw(b);
                let deleg = DelegationStore::new(state.delegation.clone());
                let dynp = DynamicPropertiesStore::new(state.dyn_props.clone());
                let (votes_n, votes_sum, allowance) =
                    match AccountStore::new(state.accounts.clone()).get(&addr) {
                        Ok(Some(a)) => (
                            a.votes.len(),
                            a.votes.iter().map(|v| v.vote_count).sum::<i64>(),
                            a.allowance,
                        ),
                        _ => (0, 0, 0),
                    };
                eprintln!(
                    "REWARD_TRACE blk={} begin_cycle={} end_cycle={} current_cycle={} votes_n={} votes_sum={} allowance={}",
                    raw.number,
                    deleg.get_begin_cycle(&addr),
                    deleg.get_end_cycle(&addr),
                    dynp.get_long(b"CURRENT_CYCLE_NUMBER").unwrap_or(0),
                    votes_n,
                    votes_sum,
                    allowance,
                );
            }
        }
        for (tx, res) in block.transactions.iter().zip(tx_results.iter()) {
            if fee_trace {
                let id: String = res.tx_id.iter().map(|b| format!("{b:02x}")).collect();
                let total_fee = res.actuator_fee
                    + res.receipt.energy_fee
                    + res.receipt.net_fee
                    + res.receipt.multi_sign_fee
                    + res.receipt.memo_fee;
                // Event-log fingerprint: count + keccak4 of the canonical
                // serialization (per log: addr(20) ‖ ntopics(1) ‖ topics ‖
                // data_len(4 BE) ‖ data). Lets a per-tx diff vs java's receipt
                // logs catch SILENT storage divergences (a wrong stored value
                // changes the emitted event — e.g. a DEX pair's Sync reserves —
                // even when fee/energy/outcome all still match).
                let log_fp = {
                    let mut buf = Vec::new();
                    for lg in &res.vm_logs {
                        buf.extend_from_slice(&lg.address);
                        buf.push(lg.topics.len() as u8);
                        for t in &lg.topics {
                            buf.extend_from_slice(t);
                        }
                        buf.extend_from_slice(&(lg.data.len() as u32).to_be_bytes());
                        buf.extend_from_slice(&lg.data);
                    }
                    let h = sha256(&buf);
                    format!(
                        "{}:{:02x}{:02x}{:02x}{:02x}",
                        res.vm_logs.len(),
                        h[0],
                        h[1],
                        h[2],
                        h[3]
                    )
                };
                eprintln!(
                    "FEE_TRACE blk={} tx={} fee={} energy_total={} energy_fee={} net_usage={} net_fee={} penalty={} logs={}",
                    raw.number, id, total_fee, res.receipt.energy_usage_total,
                    res.receipt.energy_fee, res.receipt.net_usage, res.receipt.net_fee,
                    res.receipt.energy_penalty_total, log_fp,
                );
                if let Ok(target) = std::env::var("TRON_LOGDUMP") {
                    if id.starts_with(&target) {
                        for (i, lg) in res.vm_logs.iter().enumerate() {
                            let addr: String =
                                lg.address.iter().map(|b| format!("{b:02x}")).collect();
                            let topics: String = lg
                                .topics
                                .iter()
                                .map(|t| t.iter().map(|b| format!("{b:02x}")).collect::<String>())
                                .collect::<Vec<_>>()
                                .join(",");
                            let data: String =
                                lg.data.iter().map(|b| format!("{b:02x}")).collect();
                            eprintln!("LOGDUMP tx={id} log{i} addr={addr} topics=[{topics}] data={data}");
                        }
                    }
                }
            }
            let is_vm = matches!(
                res.contract_type,
                Some(ContractType::TriggerSmartContract | ContractType::CreateSmartContract)
            );
            // VM txs need the stored contract_ret to compare against, so a VM tx
            // with no recorded ret is genuinely uncomparable — skip it. NON-VM
            // txs are different: an honest block producer only includes a tx that
            // passed validation, so a non-VM tx present in the canonical block
            // executed to SUCCESS on-chain even when its tx-level `ret` is empty.
            // Treating a missing ret as "nothing to compare" let a silently
            // self-rejected non-VM tx (e.g. a vote/freeze our node refused for a
            // diverged balance/power, whose mainnet ret happened to be empty)
            // hide a real STATE divergence — exactly the 2,586,234 case. So for
            // non-VM a missing ret means expected SUCCESS, and we MUST still
            // compare.
            let stored = tx.ret.first();
            if is_vm && stored.is_none() {
                continue;
            }
            // Whether the tx succeeded on-chain (java) vs in our node. VM txs
            // compare the contractRet; non-VM txs (Transfer, AccountPermission-
            // Update, Freeze, …) compare the tx-level `ret` code — the old
            // tripwire skipped these, so a non-VM tx our node wrongly rejected
            // silently diverged balances/permissions and cascaded into the VM
            // reverts we then saw.
            let (expected, computed, expected_ok, computed_ok) = if is_vm {
                let stored = stored.expect("VM tx without a stored ret is skipped above");
                let expected = stored.contract_ret;
                let computed = res.receipt.result;
                if expected == computed || expected == OUT_OF_TIME || computed == OUT_OF_TIME {
                    continue;
                }
                (
                    ret_name(expected).to_string(),
                    ret_name(computed).to_string(),
                    expected == SUCCESS,
                    computed == SUCCESS,
                )
            } else {
                let expected_ok = stored.map_or(true, |s| s.ret == RET_SUCCESS);
                let computed_ok = matches!(res.outcome, TxOutcome::Success);
                (
                    format!("ret={}", if expected_ok { "SUCCESS" } else { "FAILED" }),
                    format!("{:?}", res.contract_type),
                    expected_ok,
                    computed_ok,
                )
            };
            // A success/failure disagreement is a real STATE divergence. For VM
            // txs a same-outcome contractRet *code* mismatch (both failed, with
            // a different code — e.g. BAD_JUMP_DESTINATION vs UNKNOWN) is a
            // recorded-result fidelity gap with no state or fee effect. Reaching
            // here for a VM tx already implies expected != computed (exact
            // matches and OUT_OF_TIME `continue` above), so any non-state
            // mismatch is exactly a code mismatch.
            let state_diverged = expected_ok != computed_ok;
            let code_mismatch = is_vm && !state_diverged;
            if state_diverged || code_mismatch {
                let tx_hex: String =
                    res.tx_id.iter().map(|b| format!("{b:02x}")).collect();
                // Decode the VM revert payload so the line carries *why* it
                // reverted (Error(string) / Panic(code)), plus the outcome
                // variant for DEFAULTs that never reached the VM.
                let reason = {
                    let d = &res.vm_return_data;
                    if d.len() >= 4 && d[..4] == [0x08, 0xc3, 0x79, 0xa0] && d.len() >= 68 {
                        let off = 4 + 64;
                        let len = u32::from_be_bytes(d[off - 4..off].try_into().unwrap()) as usize;
                        let s = d.get(off..off + len.min(d.len().saturating_sub(off))).unwrap_or(&[]);
                        format!("Error({:?})", String::from_utf8_lossy(s))
                    } else if d.len() >= 36 && d[..4] == [0x4e, 0x48, 0x7b, 0x71] {
                        format!("Panic(0x{:x})", u64::from_be_bytes(d[28..36].try_into().unwrap()))
                    } else if d.is_empty() {
                        format!("{:?}", res.outcome)
                    } else {
                        format!("raw:0x{}", d.iter().take(8).map(|b| format!("{b:02x}")).collect::<String>())
                    }
                };
                if state_diverged {
                    // A success/failure disagreement with the canonical block is
                    // a real consensus divergence — log at ERROR so it lands in
                    // the log file and stands out (the message text is preserved
                    // for existing `CONTRACTRET DIVERGENCE` grep workflows).
                    tracing::error!(
                        "CONTRACTRET DIVERGENCE block {} tx {}: block={} computed={} reason={} \
                         (success/failure disagreement — state may have diverged)",
                        raw.number, tx_hex, expected, computed, reason,
                    );
                    // Consensus self-audit watchdog: STATE divergence only, so
                    // the `tron_node_consensus_divergences_total` alarm stays
                    // clean (the code-only mismatch below is intentionally not
                    // recorded). Surfaced even when we don't hard-reject.
                    crate::watchdog::record(crate::watchdog::ConsensusDivergence {
                        block: raw.number,
                        tx_id: tx_hex.clone(),
                        block_result: expected.clone(),
                        computed_result: computed.clone(),
                        reason: reason.clone(),
                    });
                    if config.verify_contract_ret {
                        return Err(BlockExecError::ContractRetMismatch {
                            block_num: raw.number,
                            tx_id: tx_hex,
                            expected,
                            computed,
                        });
                    }
                } else {
                    // Same success/failure, different contractRet code: state and
                    // fee are identical, so this is a recorded-code fidelity gap,
                    // not a consensus divergence. Log at WARN (distinct
                    // `CONTRACTRET CODE MISMATCH` text) so a regression in the
                    // HaltReason -> contractResult mapping is caught, without
                    // alarming the watchdog or hard-rejecting the block.
                    tracing::warn!(
                        "CONTRACTRET CODE MISMATCH block {} tx {}: block={} computed={} reason={} \
                         (same success/failure; recorded code differs)",
                        raw.number, tx_hex, expected, computed, reason,
                    );
                }
            }
        }
    }

    // Divergence-hunt instrument (env-gated, inert in production): when
    // TRON_TRACE_ACCT names a `41…`-hex account, emit its balance / total
    // frozen / allowance whenever they change, with the block number — to
    // localize an upstream balance/stake divergence (e.g. the 2,586,234
    // TZBABURn frozen gap) to the exact block where it first appears.
    if let Some(hexaddr) = std::env::var_os("TRON_TRACE_ACCT") {
        if let Some(raw_addr) = hexaddr.to_str().and_then(|s| hex::decode(s).ok()) {
            if raw_addr.len() == 21 {
                let mut a = [0u8; 21];
                a.copy_from_slice(&raw_addr);
                if let Ok(Some(acct)) =
                    AccountStore::new(state.accounts.clone()).get(&Address::from_raw(a))
                {
                    let frozen: i64 = acct.frozen.iter().map(|f| f.frozen_balance).sum::<i64>()
                        + acct
                            .account_resource
                            .as_ref()
                            .and_then(|r| r.frozen_balance_for_energy.as_ref())
                            .map(|f| f.frozen_balance)
                            .unwrap_or(0);
                    let cur = (acct.balance, frozen, acct.allowance);
                    thread_local! {
                        static TRACE_LAST: std::cell::Cell<Option<(i64, i64, i64)>> =
                            const { std::cell::Cell::new(None) };
                    }
                    TRACE_LAST.with(|last| {
                        if last.get() != Some(cur) {
                            eprintln!(
                                "ACCTTRACE block={} balance={} frozen={} allowance={}",
                                raw.number, cur.0, cur.1, cur.2
                            );
                            last.set(Some(cur));
                        }
                    });
                }
            }
        }
    }

    // === 3. Head-pointer update (directly on base) ===
    let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
    // Snapshot the previous block's timestamp BEFORE overwriting —
    // step 5 needs it for slot-gap attribution (`total_missed`).
    let prev_block_ts = dp.latest_block_header_timestamp();
    dp.save_latest_block_header_number(raw.number);
    dp.save_latest_block_header_timestamp(raw.timestamp);
    dp.save_latest_block_header_hash(block_id.as_bytes());

    // === 4. Adaptive-energy: fold BLOCK_ENERGY_USAGE into the
    //        chain-wide rolling average and adjust the global cap. ===
    //
    // Runs once per block after every tx has been processed. No-op
    // when ALLOW_ADAPTIVE_ENERGY != 1.
    adaptive::run_per_block_adaptive_update(&dp, raw.number);

    // === 5. Witness counter updates ===
    //
    // Bump `total_produced` on the witness that signed this block AND
    // attribute every missed slot since the previous block to the SR
    // that was scheduled for it. Mirrors java-tron's
    // `consensus.dpos.StatisticManager.applyBlock`.
    //
    // Slot attribution: number of slots elapsed since the parent block
    // = `(raw.timestamp - prev_block_ts) / BLOCK_PRODUCED_INTERVAL_MS`.
    // If that's > 1, the gap minus 1 blocks were missed. For each
    // missed slot index `i`, the SR scheduled to produce it is
    // `active_witnesses[(absolute_slot_i - 1) % 27]`. Walk those and
    // bump `total_missed`.
    //
    // Requirements: `state.witness_schedule` must be attached (the
    // shuffled active-witness list lives there) and the genesis
    // timestamp must be pinned via `save_genesis_block_timestamp`
    // (runtime does this once at init). If either is missing we only
    // bump `total_produced` and skip the miss attribution — better to
    // under-report than to attribute misses to the wrong SR.
    {
        use tron_chainbase::{WitnessScheduleStore, WitnessStore};
        use tron_crypto::address::Address;
        let ws = WitnessStore::new(state.witnesses.clone());

        // 5a — `total_produced` + `latest_block_num` + `latest_slot_num`
        // on the producer. `latest_slot_num` mirrors java-tron's
        // `wc.setLatestSlotNum(dposSlot.getAbSlot(blockTime))` —
        // absolute slot since genesis, used by SR-rotation tooling +
        // external explorers reading per-witness timing.
        if raw.witness_address.len() == 21 {
            let mut addr_bytes = [0u8; 21];
            addr_bytes.copy_from_slice(&raw.witness_address);
            let addr = Address::from_raw(addr_bytes);
            if let Ok(Some(mut w)) = ws.get(&addr) {
                w.total_produced = w.total_produced.saturating_add(1);
                w.latest_block_num = raw.number;
                let genesis_ts_for_slot = dp.genesis_block_timestamp().unwrap_or(0);
                const BLOCK_INTERVAL_MS: i64 = 3_000;
                // Negative genesis-ts is impossible on a real chain
                // (genesis writes timestamp); saturate at 0 if it ever is.
                w.latest_slot_num = (raw.timestamp - genesis_ts_for_slot)
                    .max(0)
                    / BLOCK_INTERVAL_MS;
                ws.put(&addr, &w)?;
            }
        }

        // 5b — `total_missed` on every SR who was scheduled but didn't
        // produce in the gap between the previous block and this one.
        let active_witnesses = state
            .witness_schedule
            .as_ref()
            .and_then(|be| {
                WitnessScheduleStore::new(be.clone())
                    .load_active()
                    .ok()
                    .flatten()
            })
            .unwrap_or_default();
        let genesis_ts = dp.genesis_block_timestamp().unwrap_or(0);
        // Block 1 is special: java-tron's StatisticManager hard-codes
        // `slot = 1` for it (no miss attribution because there is no
        // previous-producer baseline). Mirror that.
        if raw.number > 1
            && !active_witnesses.is_empty()
            && prev_block_ts.is_some()
        {
            const BLOCK_INTERVAL_MS: i64 = 3_000;
            // java `ChainConstant.MAINTENANCE_SKIP_SLOTS`.
            const MAINTENANCE_SKIP_SLOTS: i64 = 2;
            let prev_ts = prev_block_ts.unwrap();
            // java `DposSlot.getTime(1)`: the first expected production
            // slot after the head block — head timestamp aligned DOWN to
            // a slot boundary, plus one interval, plus
            // MAINTENANCE_SKIP_SLOTS intervals when the head block was a
            // maintenance block (`state_flag == 1`; production pauses
            // around maintenance and those slots must NOT count as
            // misses — skipping this skip over-counted every SR
            // scheduled right after a maintenance boundary). The flag
            // still holds the PREVIOUS block's value here: this step
            // runs before the maintenance pass below updates it.
            let skip = if dp.state_flag() == 1 {
                MAINTENANCE_SKIP_SLOTS
            } else {
                0
            };
            let head_aligned =
                prev_ts - (prev_ts - genesis_ts).rem_euclid(BLOCK_INTERVAL_MS);
            let first_slot_time = head_aligned + (1 + skip) * BLOCK_INTERVAL_MS;
            // java `DposSlot.getSlot(blockTime)`.
            let slot = if raw.timestamp < first_slot_time {
                0
            } else {
                (raw.timestamp - first_slot_time) / BLOCK_INTERVAL_MS + 1
            };
            // java `StatisticManager.applyBlock`: for i in 1..slot the
            // missed SR is `DposSlot.getScheduledWitness(i)` =
            // `active[(abSlot(head_ts) + i) % N]` (SINGLE_REPEAT == 1).
            // The index is relative to the HEAD block's absolute slot —
            // `(slot − 1) % N` (the previous formula here) attributed
            // every miss to the witness one schedule position early.
            let prev_abs = (prev_ts - genesis_ts) / BLOCK_INTERVAL_MS;
            for i in 1..slot {
                let idx =
                    (prev_abs + i).rem_euclid(active_witnesses.len() as i64) as usize;
                let missed_addr = active_witnesses[idx];
                if let Ok(Some(mut w)) = ws.get(&missed_addr) {
                    w.total_missed = w.total_missed.saturating_add(1);
                    ws.put(&missed_addr, &w)?;
                }
            }
        }
    }

    // === 5c. Per-block reward distribution ===
    //
    // Mirrors java-tron's per-block `MortgageService.payBlockReward`
    // + `payStandbyWitness` calls (driven by `DposService` after each
    // block apply). For each produced block:
    //
    //   * The producer is credited `WITNESS_PAY_PER_BLOCK` (default
    //     32 TRX). The witness's brokerage cut goes straight to their
    //     `Account.allowance`; the remainder is added to the current
    //     cycle's reward pool, to be distributed to voters via the
    //     Vi-accumulator math at the next maintenance boundary.
    //
    //   * Every active SR in the top 127 by vote_count shares
    //     `WITNESS_127_PAY_PER_BLOCK` (default 16 TRX) prorated by
    //     vote count. Same brokerage / cycle-pool split per witness.
    //
    // Gated on `state.witness_schedule` being attached and the
    // producer being a real witness with a backing account row — if
    // either is missing, we silently skip rather than misattribute
    // rewards.
    if raw.witness_address.len() == 21 {
        use tron_chainbase::{DelegationStore, WitnessStore};
        use tron_crypto::address::Address;
        let mut producer_bytes = [0u8; 21];
        producer_bytes.copy_from_slice(&raw.witness_address);
        let producer = Address::from_raw(producer_bytes);
        let accts = AccountStore::new(state.accounts.clone());
        let dlg = DelegationStore::new(state.delegation.clone());

        // java `Manager.payReward` branches on allowChangeDelegation: the
        // post-fork brokerage / cycle-pool / standby split (5c-i..iii) runs
        // only when it is on; the pre-fork path (5c-pre below) sends the block
        // + tx-fee reward straight to the producer's allowance. Mainnet has
        // CHANGE_DELEGATION on, so 5c-pre is dead for a snapshot node — it
        // matters only for a from-genesis replay of the pre-fork window.
        let change_delegation = dp.allow_change_delegation();
        // 5c-i. Block-production reward to the producer.
        let block_pay = dp.witness_pay_per_block();
        if change_delegation && block_pay > 0 {
            let _ = tron_tvm::reward::pay_block_reward(
                &accts, &dlg, &dp, &producer, block_pay,
            );
        }

        // 5c-ii. Standby pool distribution to top-127 by vote_count.
        // We use the WitnessStore::all() scan because the standby set
        // is independent of the active witness rotation (which is
        // capped at 27).
        let standby_pay = dp.witness_127_pay_per_block();
        if change_delegation && standby_pay > 0 {
            let ws = WitnessStore::new(state.witnesses.clone());
            if let Ok(by_vote) = ws.all() {
                let ranked = top_standby_witnesses(
                    by_vote.into_iter().map(|(a, w)| (a, w.vote_count)).collect(),
                    dp.allow_consensus_logic_optimization(),
                );
                let _ =
                    tron_tvm::reward::pay_standby_witness(&accts, &dlg, &dp, &ranked);
            }
        }

        // 5c-iii. Transaction-fee reward to the producer.
        //
        // Mirrors java-tron's `Manager.payReward`: when the fee pool is
        // active, each block pays the producer `floorDiv(pool,
        // TRANSACTION_FEE_POOL_PERIOD)` then drains that amount from the
        // pool. `Constant.TRANSACTION_FEE_POOL_PERIOD == 1`, so the
        // producer receives the entire accumulated pool every block and
        // it resets to zero. The reward flows through the same brokerage
        // / cycle-pool split as the block reward. Without this, fees
        // charged into the pool (bandwidth/energy) accumulated forever
        // and witnesses never received their tx-fee share.
        if change_delegation && dp.support_transaction_fee_pool() {
            const TRANSACTION_FEE_POOL_PERIOD: i64 = 1;
            let pool = dp.transaction_fee_pool();
            let tx_fee_reward = pool / TRANSACTION_FEE_POOL_PERIOD;
            let _ = tron_tvm::reward::pay_transaction_fee_reward(
                &accts, &dlg, &dp, &producer, tx_fee_reward,
            );
            dp.save_transaction_fee_pool(pool - tx_fee_reward);
        }
        // 5c-pre. java payReward else-branch (pre-CHANGE_DELEGATION): the block
        // reward + tx-fee reward go straight to the producer's allowance (no
        // brokerage split, no cycle pool) and standby is NOT paid per-block
        // (legacy standby is paid at maintenance via IncentiveManager.reward).
        if !change_delegation {
            if let Ok(Some(mut acct)) = accts.get(&producer) {
                acct.allowance = acct.allowance.saturating_add(block_pay);
                if dp.support_transaction_fee_pool() {
                    let pool = dp.transaction_fee_pool();
                    acct.allowance = acct.allowance.saturating_add(pool);
                    dp.save_transaction_fee_pool(0);
                }
                let _ = accts.put(&producer, &acct);
            }
        }
    }

    // === 5d. Maintenance-period pass ===
    //
    // Mirrors `MaintenanceManager.applyBlock`: every block crossing
    // `next_maintenance_time` triggers a full cycle rollover —
    // Vi accumulation, vote tally + SR re-rank, isJobs flip, cycle
    // number increment, brokerage/vote snapshots for the next cycle.
    //
    // java-tron has a "block 1 special case" where the genesis block
    // skips doMaintenance but DOES advance next_maintenance_time; we
    // mirror that.
    let next_maintenance = dp.next_maintenance_time().unwrap_or(0);
    let mut maintenance_rotation: Option<MaintenanceRotation> = None;
    if tron_consensus::is_maintenance_boundary(raw.timestamp, next_maintenance) {
        // java `Manager.processBlock`: at every maintenance boundary, run the
        // proposal-activation pass BEFORE doMaintenance and before advancing
        // next_maintenance_time — an expiring proposal can change a parameter
        // (CHANGE_DELEGATION, MAINTENANCE_TIME_INTERVAL, fees, …) that this same
        // cycle's maintenance and the interval advance below then read. `now_ms`
        // is the PRE-bump `next_maintenance` (java tests
        // `hasExpired(getNextMaintenanceTime())` before updateNextMaintenanceTime).
        let same_token_name_before = dp.allow_same_token_name().unwrap_or(0);
        if let Some(sched_be) = state.witness_schedule.clone() {
            let schedule = tron_chainbase::WitnessScheduleStore::new(sched_be);
            if let Ok(Some(active)) = schedule.load_active() {
                let proposal_store = ProposalStore::new(state.proposals.clone());
                let _ = tron_consensus::activate_expired_proposals(
                    &proposal_store,
                    &dp,
                    next_maintenance,
                    &active,
                );
            }
        }
        // If the ALLOW_SAME_TOKEN_NAME proposal just activated, reconstruct each
        // account's id-keyed `asset_v2` map from its name-keyed `asset` map
        // before any flag=1 balance read (next block). java keeps the two maps
        // in lock-step at flag=0 and carries no migration; rebuilding from the
        // consensus-correct V1 balances reproduces the exact `asset_v2` it holds
        // at the flip — making an existing sync that did not dual-write every
        // flag=0 op correct without a re-sync. One-time, same maintenance pass.
        if same_token_name_before == 0 && dp.allow_same_token_name().unwrap_or(0) == 1 {
            let accts = AccountStore::new(state.accounts.clone());
            let av1 = AssetIssueStore::new(state.asset_v1.clone());
            match tron_consensus::rebuild_asset_v2_from_v1(&accts, &av1) {
                Ok(n) => tracing::info!(
                    accounts_rewritten = n,
                    "ALLOW_SAME_TOKEN_NAME activated: rebuilt asset_v2 from asset"
                ),
                Err(e) => {
                    tracing::error!("asset_v2 rebuild at ALLOW_SAME_TOKEN_NAME failed: {e}")
                }
            }
        }
        // Run doMaintenance for every block EXCEPT genesis. Java-tron's
        // check is `blockNum != 1`.
        if raw.number != 1 {
            use tron_chainbase::{DelegationStore, WitnessScheduleStore};
            let ws = tron_chainbase::WitnessStore::new(state.witnesses.clone());
            let vs = tron_chainbase::VotesStore::new(state.votes.clone());
            let sched_be = state.witness_schedule.clone();
            let accts = AccountStore::new(state.accounts.clone());
            let dlg = DelegationStore::new(state.delegation.clone());
            if let Some(sched_be) = sched_be {
                let schedule = WitnessScheduleStore::new(sched_be);
                if let Ok(outcome) = tron_consensus::apply_maintenance(
                    &ws, &vs, &schedule, &accts, &dlg, &dp,
                ) {
                    // Capture the rotation so the caller can update the
                    // shared SrEpochSnapshot. `next_maintenance` is the
                    // pre-bump value — exactly java-tron's
                    // `beforeMaintenanceTime`. The post-bump value is
                    // saved a few lines down.
                    maintenance_rotation = Some(MaintenanceRotation {
                        prev_active: outcome.prev_active,
                        new_active: outcome.new_active,
                        before_maintenance_time_ms: next_maintenance,
                    });
                    // Divergence-hunt instrument (env-gated, inert in
                    // production): emit each TRON_VOTELOG_TARGET witness's
                    // post-maintenance countVote with its block number, for a
                    // direct timeline diff against java-tron's MaintenanceManager
                    // log when a witness-schedule divergence is being chased.
                    if std::env::var_os("TRON_MAINT_VOTELOG").is_some() {
                        if let Ok(tgts) = std::env::var("TRON_VOTELOG_TARGET") {
                            for h in tgts.split(',') {
                                let h = h.trim();
                                match hex::decode(h) {
                                    Ok(b) if b.len() == 21 => {
                                        let mut a = [0u8; 21];
                                        a.copy_from_slice(&b);
                                        if let Ok(Some(w)) = ws.get(&Address::from_raw(a)) {
                                            eprintln!(
                                                "MAINTVOTE block={} witness={} count={}",
                                                raw.number, h, w.vote_count
                                            );
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
        }
        // Always advance next_maintenance_time past this block. java's
        // `updateNextMaintenanceTime` feeds `getNextMaintenanceTime()` (our
        // `next_maintenance`) verbatim, NOT max'd with the block time: the
        // result must stay on the interval grid anchored at the genesis seed.
        // Substituting the block time (e.g. when the boundary slot was skipped
        // and `raw.timestamp > next_maintenance`) shifts the anchor off-grid
        // permanently, so subsequent boundaries fire at the wrong heights.
        // Read the interval AFTER the proposal pass — a proposal applied above
        // may have changed MAINTENANCE_TIME_INTERVAL, which java reads here.
        let maintenance_interval = dp
            .maintenance_time_interval()
            .unwrap_or(tron_consensus::DEFAULT_MAINTENANCE_INTERVAL_MS);
        let new_next = tron_consensus::compute_next_maintenance_time(
            raw.timestamp,
            next_maintenance,
            maintenance_interval,
        );
        dp.save_next_maintenance_time(new_next);
        // java's `MaintenanceManager.applyBlock` records on EVERY block
        // whether it crossed the boundary (`saveStateFlag(flag ? 1 : 0)`).
        // The NEXT block's slot math reads this to skip
        // MAINTENANCE_SKIP_SLOTS when counting missed slots (step 5b).
        dp.save_state_flag(1);
    } else {
        dp.save_state_flag(0);
    }

    // === 6. AccountStateRoot verification (consensus-critical when
    //        ALLOW_ACCOUNT_STATE_ROOT == 1) ===
    //
    // Mainnet currently has this flag DISABLED (==0), so producers
    // leave `BlockHeader.raw_data.account_state_root` empty and this
    // arm is a no-op. We still wire it for the day mainnet enables
    // it, and for testnets that already have it on.
    //
    // Verification path: scan every account, RLP-encode the
    // Ethereum-style [nonce, balance, storageRoot, codeHash], drop
    // each into a Merkle-Patricia trie keyed by
    // `keccak256(addr[1..])`, compare the trie root to the block
    // header's `account_state_root`. Mismatch = consensus divergence
    // → reject the block.
    //
    // Cost: full-scan O(accounts + storage_rows). On mainnet (~tens of
    // millions of accounts) this is impractical per block — java-tron
    // uses an incremental trie keyed on touched-accounts only. We
    // defer that optimization until the flag actually activates.
    if !raw.account_state_root.is_empty()
        && dp.get_long(b"ALLOW_ACCOUNT_STATE_ROOT").unwrap_or(0) == 1
    {
        let computed = compute_state_root(state)?;
        if computed.as_slice() != raw.account_state_root.as_slice() {
            return Err(BlockExecError::StateRootMismatch {
                block_num: raw.number,
                expected: hex::encode(&raw.account_state_root),
                computed: hex::encode(computed),
            });
        }
    }

    Ok(BlockExecutionReport {
        block_id,
        tx_results,
        maintenance: maintenance_rotation,
        state_deltas: None,
    })
}

/// Compute the Ethereum-style state root over the current account set.
///
/// Full-scan implementation: enumerates every (address, account) pair
/// in `AccountStore`, looks up per-contract storage rows from
/// `StorageRowStore`, and folds them through
/// [`tron_types::compute_account_state_root_with_storage`].
///
/// Cost is O(accounts + storage_rows). Intended only for paths that
/// actually need the root — gated upstream on
/// `ALLOW_ACCOUNT_STATE_ROOT == 1` so the mainnet path (flag = 0)
/// pays nothing.
/// Apply `block` against `state`, compute the resulting
/// `account_state_root`, then **roll back** so `state` is left
/// untouched. Used by the SR runtime to fill in the
/// `BlockHeader.raw_data.account_state_root` field when
/// `ALLOW_ACCOUNT_STATE_ROOT == 1` is active. The dry-run uses a
/// fresh ephemeral `BlockUndoStore` so the real one (used by the
/// SyncDriver for reorg) isn't polluted.
///
/// Cost: one full block apply + one full state-root scan + one
/// rollback. For consensus-critical paths this happens at most once
/// per slot (3s on mainnet); the cost is amortized against the slot
/// budget.
pub fn dry_run_for_state_root(
    state: &StateBackends,
    block: &tron_proto::Block,
    expected_parent: Option<BlockId>,
) -> Result<[u8; 32], BlockExecError> {
    let ephemeral = tron_chainbase::BlockUndoStore::new(Arc::new(tron_chainbase::MemBackend::new()));
    // The block handed in here is UNSIGNED — the witness produces it,
    // dry-runs it through us to compute `account_state_root`, embeds the
    // root, then signs. Skip the signature gate accordingly; under the
    // default-strict `ExecConfig` we'd reject it for `MissingSignature`.
    execute_block_with_undo_and_config(
        state,
        block,
        expected_parent,
        &ephemeral,
        &ExecConfig::unsigned(),
        // Self-produced (unsigned dry-run) blocks are prost-canonical, so the
        // bandwidth charge needs no original-wire-size correction.
        None,
    )?;
    let root = compute_state_root(state)?;
    let raw = block
        .block_header
        .as_ref()
        .and_then(|h| h.raw_data.as_ref())
        .ok_or(BlockExecError::NoHeader)?;
    // Roll back so the dry-run leaves no trace. A failure here means
    // the state machine is internally inconsistent — propagate as a
    // StateRootMismatch since the contract of "dry-run leaves state
    // untouched" was violated.
    rollback_block(state, raw.number, &ephemeral).map_err(|e| {
        BlockExecError::StateRootMismatch {
            block_num: raw.number,
            expected: format!("dry-run rollback failure: {e}"),
            computed: hex::encode(root),
        }
    })?;
    Ok(root)
}

pub fn compute_state_root(state: &StateBackends) -> Result<[u8; 32], tron_chainbase::KvError> {
    use tron_crypto::address::Address;
    use tron_proto::Account;

    let storage_lookup = |addr: &Address| -> Option<[u8; 32]> {
        let rows_be = state.storage_row.as_ref()?;
        // Scan failures here are surfaced via the outer Result —
        // we treat any backend error during storage-root computation
        // as a panic-worthy condition for the per-contract path
        // since silently returning None would corrupt the root.
        let rows = tron_chainbase::StorageRowStore::new(rows_be.clone())
            .scan_for_contract(addr)
            .expect("storage_row.scan_for_contract failed in compute_state_root");
        if rows.is_empty() {
            None
        } else {
            let rows_owned: Vec<([u8; 32], Vec<u8>)> =
                rows.into_iter().collect();
            Some(tron_types::compute_storage_root(&rows_owned))
        }
    };

    let mut accounts: Vec<(Address, Account)> = Vec::new();
    for (key, value) in state.accounts.scan_all()? {
        if key.len() != 21 {
            continue;
        }
        let mut addr_bytes = [0u8; 21];
        addr_bytes.copy_from_slice(&key);
        let Ok(account) = <Account as prost::Message>::decode(value.as_slice()) else {
            continue;
        };
        accounts.push((Address::from_raw(addr_bytes), account));
    }
    Ok(tron_types::compute_account_state_root_with_storage(&accounts, storage_lookup))
}

/// Work gate for Block-STM: is this block heavy enough to amortize the fixed
/// parallel overhead (MvMemory init, per-tx versioned stores, rayon dispatch)?
/// A block with any contract call (large per-tx VM work) always is; a handful of
/// plain transfers is not. The sync driver AND-s this into `parallel_exec`, so it
/// only ever picks the faster of two byte-equivalent paths — never affects state.
pub fn block_worth_parallel(transactions: &[Transaction]) -> bool {
    const MIN_PARALLEL_TXS: usize = 16;
    transactions.len() >= MIN_PARALLEL_TXS || transactions.iter().any(tx_is_vm_bound)
}

/// True if a tx's first contract is VM-bound (TriggerSmartContract /
/// CreateSmartContract) — its per-tx work is large enough to always be worth
/// parallelizing. Cheap: reads the contract-type tag, decodes nothing.
fn tx_is_vm_bound(tx: &Transaction) -> bool {
    tx.raw_data
        .as_ref()
        .and_then(|r| r.contract.first())
        .and_then(|c| ContractType::try_from(c.r#type).ok())
        .is_some_and(|ty| {
            matches!(
                ty,
                ContractType::TriggerSmartContract | ContractType::CreateSmartContract
            )
        })
}

/// Serial entry point: fork a per-tx [`TxSession`] (copy-on-write overlay) over
/// `state`, then run the shared core. Failed txs revert the session; the next tx
/// starts fresh.
pub(crate) fn execute_one_tx(
    state: &StateBackends,
    tx: &Transaction,
    config: &ExecConfig,
    block_number: i64,
    block_timestamp_ms: i64,
    beneficiary: [u8; 20],
    now_slot: i64,
    head_block_time_ms: i64,
    precomputed_signers: &Result<Vec<Address>, String>,
    original_tx_size: Option<i64>,
) -> TxResult {
    let session = TxSession::fork(state);
    let view = session.view();
    execute_one_tx_isolated(
        &view,
        &TxIsolation::Session(&session),
        tx,
        config,
        block_number,
        block_timestamp_ms,
        beneficiary,
        now_slot,
        head_block_time_ms,
        precomputed_signers,
        original_tx_size,
    )
}

/// Block-STM entry point: run the shared core DIRECTLY over the versioned
/// backend `view` — no per-tx `TxSession` overlay. Per-tx isolation, read-your-
/// writes and revert are provided by the `VersionedBackend` capture itself
/// (`iso = Capture`): a failed tx clears its buffered writes/deltas. Removes a
/// whole copy-on-write overlay (and its ~24-backend fork) from every state op.
#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_one_tx_versioned(
    view: &StateBackends,
    capture: &tron_chainbase::blockstm::TxCaptureCell,
    tx: &Transaction,
    config: &ExecConfig,
    block_number: i64,
    block_timestamp_ms: i64,
    beneficiary: [u8; 20],
    now_slot: i64,
    head_block_time_ms: i64,
    precomputed_signers: &Result<Vec<Address>, String>,
    original_tx_size: Option<i64>,
) -> TxResult {
    execute_one_tx_isolated(
        view,
        &TxIsolation::Capture(capture),
        tx,
        config,
        block_number,
        block_timestamp_ms,
        beneficiary,
        now_slot,
        head_block_time_ms,
        precomputed_signers,
        original_tx_size,
    )
}

/// Shared per-tx execution core. Runs against an already-isolated `view`
/// (a serial session overlay OR the Block-STM versioned backend) and
/// commits/reverts via `iso`. Both callers go through this one body, so serial
/// and parallel are byte-identical by construction.
#[allow(clippy::too_many_arguments)]
fn execute_one_tx_isolated(
    view: &StateBackends,
    iso: &TxIsolation,
    tx: &Transaction,
    config: &ExecConfig,
    block_number: i64,
    block_timestamp_ms: i64,
    beneficiary: [u8; 20],
    now_slot: i64,
    head_block_time_ms: i64,
    precomputed_signers: &Result<Vec<Address>, String>,
    original_tx_size: Option<i64>,
) -> TxResult {
    let owners = SessionStoreOwners::from_state(view);
    let stores = owners.as_actuator_stores();

    let Some(raw) = &tx.raw_data else {
        // No state to revert — session is still empty.
        return TxResult {
            tx_id: [0u8; 32],
            contract_type: None,
            outcome: TxOutcome::MissingRawData,
                    ..TxResult::empty()
        };
    };
    let tx_id = sha256(&raw.encode_to_vec());

    // Resource receipt, filled as charges land (net side here, energy
    // side inside `execute_vm_tx`). Reject/revert paths return zeros —
    // a tx whose charges were rolled back consumed nothing.
    let mut receipt = TxReceipt::default();

    // === Transaction size limit (java `Manager.validateCommon`, lines 814-828). ===
    //
    // java rejects an over-size tx with `TooBigTransactionException` on TWO
    // checks (`Constant.TRANSACTION_MAX_BYTE_SIZE = 500 * 1024 = 512_000`):
    //
    //   1. `serializedSize(clearRet) + 2 * MAX_RESULT_SIZE_IN_TX > 512_000`
    //      — the serialized tx with its `ret` map cleared, plus headroom for
    //      two 64-byte result records (`MAX_RESULT_SIZE_IN_TX = 64`, doubled).
    //      Gated on `optimizeTxs` = `!isInBlock || allowConsensusLogicOptimization`.
    //      On the sync path (`isInBlock`) with the optimization active (mainnet
    //      for years) this branch runs; we keep it unconditional here because a
    //      canonical block's txs always pass it (no-op for valid txs) and the
    //      pre-optimization era is unreachable for a snapshot-synced node.
    //   2. `getData().length > 512_000` — the raw tx wire bytes. `getData()` is
    //      the full `Transaction.toByteArray()`, which for our purposes is the
    //      encoded tx; we use the `raw_data` serialized length as the closest
    //      equivalent the executor holds (signatures only add to it, so this is
    //      a conservative lower bound that still never trips a canonical tx).
    //
    // Both reject with the same reason. No-op for canonical txs (every tx in a
    // block java produced already passed).
    const TRANSACTION_MAX_BYTE_SIZE: i64 = 500 * 1024;
    const MAX_RESULT_SIZE_IN_TX: i64 = 64;
    let raw_serialized_len = raw.encoded_len() as i64;
    let general_bytes_size = raw_serialized_len + MAX_RESULT_SIZE_IN_TX + MAX_RESULT_SIZE_IN_TX;
    if general_bytes_size > TRANSACTION_MAX_BYTE_SIZE
        || raw_serialized_len > TRANSACTION_MAX_BYTE_SIZE
    {
        // No state mutated — the session is fresh, no revert needed.
        return TxResult {
            tx_id,
            contract_type: None,
            outcome: TxOutcome::TooBig {
                size_bytes: general_bytes_size,
                max_size: TRANSACTION_MAX_BYTE_SIZE,
            },
            ..TxResult::empty()
        };
    }

    // === Expiration check (java `Manager.validateCommon`, lines 829-841). ===
    //
    // Reject any tx whose `raw_data.expiration` is outside the accepted window
    // AS OF the block we're applying it under. The mempool path already
    // performs this check at submit time against wall-clock — but a block we
    // received from a peer (sync path) didn't go through the mempool, so
    // without this gate a stale (or absurdly future-dated) signed transaction
    // could be replayed inside a block at any time.
    //
    // java rejects with `TransactionExpirationException` iff:
    //   `expiration <= headBlockTime
    //       || expiration > headBlockTime + MAXIMUM_TIME_UNTIL_EXPIRATION`
    // where `MAXIMUM_TIME_UNTIL_EXPIRATION = 24 * 60 * 60 * 1000 = 86_400_000`
    // (`Constant.java:35`, one day) and `headBlockTime = getHeadBlockTimeStamp()`
    // — the COMMITTED head timestamp (block N-1), NOT the block being applied
    // (N). The head pointer only advances to block N AFTER the tx loop (see the
    // `save_latest_block_header_timestamp` call in `execute_block`), so during
    // this loop `head_block_time_ms` is block N-1's raw stored timestamp,
    // threaded down from the block level exactly like `now_slot`.
    //
    // Using block N's timestamp would wrongly expire any tx whose
    // `expiration == N.timestamp` (java accepts those, since `N.ts > (N-1).ts`).
    // `expiration == 0` is the "unset" sentinel; the lower-bound check still
    // applies to it (`0 <= headBlockTime` rejects), matching java which does
    // not special-case zero here. We retain the `> 0` guard only to avoid
    // dropping synthetic test fixtures that leave `expiration` unset; canonical
    // mainnet txs always carry a real expiration so this is a no-op there.
    const MAXIMUM_TIME_UNTIL_EXPIRATION_MS: i64 = 24 * 60 * 60 * 1_000;
    if raw.expiration > 0
        && (raw.expiration <= head_block_time_ms
            || raw.expiration > head_block_time_ms.saturating_add(MAXIMUM_TIME_UNTIL_EXPIRATION_MS))
    {
        // No state was mutated — the session is fresh, no revert needed.
        return TxResult {
            tx_id,
            contract_type: None,
            outcome: TxOutcome::Expired {
                expiration_ms: raw.expiration,
                block_timestamp_ms: head_block_time_ms,
            },
            ..TxResult::empty()
        };
    }

    // NOTE: ref_block / chain-id replay validation does NOT happen
    // here — per java-tron's `Manager.pushBlock` model, that gate
    // belongs at the sync layer (where the block enters) and the
    // mempool (where individual txs enter). The executor's contract
    // is to be a pure-execution engine that trusts its caller has
    // already gated on those policies. Sub-issue B of REVIEW.md ET-C4
    // tracks wiring the missing sync-layer + mempool-layer check.

    let Some(contract) = raw.contract.first() else {
        return TxResult {
            tx_id,
            contract_type: None,
            outcome: TxOutcome::NoContract,
                    ..TxResult::empty()
        };
    };

    let ty = match ContractType::try_from(contract.r#type) {
        Ok(t) => t,
        Err(_) => {
            return TxResult {
                tx_id,
                contract_type: None,
                outcome: TxOutcome::UnknownContractType(contract.r#type),
                            ..TxResult::empty()
            }
        }
    };

    let Some(parameter) = &contract.parameter else {
        return TxResult {
            tx_id,
            contract_type: Some(ty),
            outcome: TxOutcome::MissingParameter,
                    ..TxResult::empty()
        };
    };

    // Sighash is only meaningful for shielded transactions; for every
    // other contract type the actuators ignore the field. Mirrors
    // java-tron, which only calls `getShieldTransactionHashIgnore...`
    // when dispatching ShieldedTransferContract.
    let tx_ctx = if matches!(ty, ContractType::ShieldedTransferContract) {
        let dp = tron_chainbase::DynamicPropertiesStore::new(view.dyn_props.clone());
        let zen_token_id = dp
            .get_bytes(b"ZEN_TOKEN_ID")
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_else(|| "000000".to_string());
        match tron_actuator::shielded_transfer::compute_shielded_sighash(tx, &zen_token_id) {
            Ok(h) => tron_actuator::ActuatorTxCtx { sighash: h },
            Err(_) => {
                // Malformed shielded tx — fall through with a zero
                // sighash; the actuator will reject during validation
                // and the tx is consistently rejected rather than
                // panicking here.
                tron_actuator::ActuatorTxCtx::default()
            }
        }
    } else {
        tron_actuator::ActuatorTxCtx::default()
    };

    // === Permission / multi-sig check. ===
    // Verify the transaction's signers cover the active permission's
    // threshold for this contract type. Skipped for shielded contracts
    // (their owner is empty/transparent-only and the actuator has its
    // own verification path).
    if !matches!(ty, ContractType::ShieldedTransferContract) {
        if let Err(e) = check_transaction_permission_with_signers(
            stores.accounts,
            stores.dyn_props,
            tx,
            contract,
            ty,
            precomputed_signers,
        ) {
            iso.revert();
            return TxResult {
                tx_id,
                contract_type: Some(ty),
                outcome: TxOutcome::Invalid(ActuatorError::PermissionDenied(e.to_string())),
                            ..TxResult::empty()
            };
        }
    }

    // === Bandwidth charge. ===
    // The owner pays for this transaction's wire bytes via java-tron's
    // priority: useAssetAccountNet (TRC-10 only) → useAccountNet
    // (global-scaled frozen quota) → useFreeNet (daily 5kB free, with
    // chain-wide PUBLIC_NET tracking) → useTransactionFee (TRX
    // fallback). Shielded transactions skip this (their fee is handled
    // inside the actuator). VM-bound contracts (TriggerSmartContract /
    // CreateSmartContract) DO get bandwidth-charged here for the wire
    // bytes; the per-opcode energy is then charged separately inside
    // `execute_vm_tx` after the VM finishes.
    if !matches!(ty, ContractType::ShieldedTransferContract) {
        if let Ok(owner) = extract_owner_for_bandwidth(contract, ty) {
            // `now_slot` is hoisted to once-per-block by the caller — it
            // derives only from the genesis timestamp and the parent
            // block's header time, both fixed for the whole block.
            let bw_stores = bandwidth::BandwidthStores {
                accounts: stores.accounts,
                dyn_props: stores.dyn_props,
                asset_v1: stores.asset_v1,
                asset_v2: stores.asset_v2,
            };
            match bandwidth::consume_bandwidth(bw_stores, tx, contract, &owner, now_slot, original_tx_size) {
                Ok(bandwidth::BandwidthCharge::Free { bytes, .. }) => {
                    // Free-net path: PUBLIC_NET_USAGE/TIME writes were dropped by
                    // the versioned backend (parallel) to avoid serialising the
                    // block; record this tx's `bytes` so the exact serial fold is
                    // replayed at commit. No-op in the serial path.
                    iso.record_public_net_bytes(bytes);
                    receipt.net_usage = bytes;
                }
                Ok(bandwidth::BandwidthCharge::Frozen { bytes, .. })
                | Ok(bandwidth::BandwidthCharge::AssetIssuer { bytes, .. }) => {
                    // Quota-covered bytes land in netUsage, mirroring
                    // java-tron's BandwidthProcessor receipt writes.
                    receipt.net_usage = bytes;
                }
                Ok(bandwidth::BandwidthCharge::Fee { fee_sun, .. }) => {
                    receipt.net_fee = fee_sun;
                }
                Ok(bandwidth::BandwidthCharge::CreateNewAccountFrozen { net_cost, .. }) => {
                    // setNetBillForCreateNewAccount(netCost, 0): the
                    // special new-account cost IS the net bill.
                    receipt.net_usage = net_cost;
                }
                Ok(bandwidth::BandwidthCharge::CreateNewAccountFee { fee_sun }) => {
                    receipt.net_fee = fee_sun;
                }
                Err(e) => {
                    iso.revert();
                    return TxResult {
                        tx_id,
                        contract_type: Some(ty),
                        outcome: TxOutcome::Invalid(ActuatorError::PermissionDenied(format!(
                            "bandwidth: {e}"
                        ))),
                        ..TxResult::empty()
                    };
                }
            }
        }
    }

    // === Multi-sign + memo flat fees. ===
    // java-tron `Manager.processTransaction` charges these right after
    // bandwidth (`consumeMultiSignFee` / `consumeMemoFee`): a tx
    // carrying more than one signature pays MULTI_SIGN_FEE, and a tx
    // with a non-empty memo (`raw_data.data`) pays MEMO_FEE (0 until
    // the SR proposal sets it). Both debit the contract owner's
    // balance (skipping silently when the owner account doesn't exist
    // — the shielded case) and burn; an uncoverable fee rejects the tx.
    if tx.signature.len() > 1 {
        let fee = stores.dyn_props.multi_sign_fee();
        match charge_flat_fee(stores.accounts, stores.dyn_props, contract, ty, fee) {
            Ok(charged) => receipt.multi_sign_fee = charged,
            Err(msg) => {
                iso.revert();
                return TxResult {
                    tx_id,
                    contract_type: Some(ty),
                    outcome: TxOutcome::Invalid(ActuatorError::PermissionDenied(format!(
                        "multi-sign fee: {msg}"
                    ))),
                    ..TxResult::empty()
                };
            }
        }
    }
    if !raw.data.is_empty() {
        let fee = stores.dyn_props.memo_fee();
        if fee != 0 {
            match charge_flat_fee(stores.accounts, stores.dyn_props, contract, ty, fee) {
                Ok(charged) => receipt.memo_fee = charged,
                Err(msg) => {
                    iso.revert();
                    return TxResult {
                        tx_id,
                        contract_type: Some(ty),
                        outcome: TxOutcome::Invalid(ActuatorError::PermissionDenied(format!(
                            "memo fee: {msg}"
                        ))),
                        ..TxResult::empty()
                    };
                }
            }
        }
    }

    // === Smart-contract path ===
    //
    // VM-bound contracts (`TriggerSmartContract`, `CreateSmartContract`)
    // bypass the actuator dispatch and route through `tron-tvm` directly.
    // Bandwidth has already been charged above; `execute_vm_tx` adds
    // the post-VM energy charge.
    if matches!(
        ty,
        ContractType::TriggerSmartContract | ContractType::CreateSmartContract
    ) {
        // Block-recorded `OUT_OF_TIME` deferral (replay/validation only).
        //
        // java-tron terminates a VM tx that exceeds `maxCpuTimeOfOneTx` on
        // the producing SR with `OutOfTimeException`, reverting all its VM
        // contract-state changes and charging the full energy budget
        // (`spendAllEnergy`). That outcome is a wall-clock artifact of the
        // JVM — a non-JVM node can't reproduce it by timing — so when the
        // canonical block records a VM tx as `OUT_OF_TIME` we force that
        // outcome regardless of local execution. Without this, our node runs
        // the tx to SUCCESS/REVERT, COMMITTING (or rejecting) state java
        // never applied, silently diverging downstream. Only a block-recorded
        // result drives this (`tx.ret[0]`), so it never fires during block
        // production (no stored ret yet). See `execute_vm_tx`.
        let recorded_out_of_time = tx.ret.first().map(|r| r.contract_ret)
            == Some(tron_proto::transaction::result::ContractResult::OutOfTime as i32);
        return execute_vm_tx(
            view, iso, tx_id, ty, parameter, config, raw.fee_limit, block_number,
            block_timestamp_ms, beneficiary, recorded_out_of_time, receipt,
        );
    }

    // Validate. On reject: revert (drops any pending writes — though
    // validate shouldn't write, this is defence in depth) and report.
    if let Err(e) = dispatch_validate(&stores, &tx_ctx, ty, parameter) {
        iso.revert();
        return TxResult {
            tx_id,
            contract_type: Some(ty),
            outcome: TxOutcome::Invalid(e),
                    ..TxResult::empty()
        };
    }

    // Execute. On success: commit the session. On failure: revert
    // (this is the bit that fixes the old v1 limitation — partial
    // state mutations from a failed execute are NOT applied).
    match dispatch_execute(&stores, &tx_ctx, ty, parameter) {
        Ok(result) => {
            // Containment for the .expect():
            // * Production (`execute_block_with_undo_*`) path: TxSession's
            //   parent is a BlockSession-wrapped SessionBackend whose
            //   `write_batch` is an in-memory `HashMap::insert` — the
            //   only way it fails is lock poisoning, which is
            //   unrecoverable anyway.
            // * No-undo path (tests + dry-run tooling): parent is the
            //   raw backend. A real IO error there is a tooling-level
            //   failure; panicking surfaces it to the operator rather
            //   than silently dropping the tx's writes.
            iso.commit()
                .expect("db error in execute_one_tx: commit flush failed");
            TxResult {
                tx_id,
                contract_type: Some(ty),
                outcome: TxOutcome::Success,
                receipt,
                actuator_fee: result.fee,
                ret_extras: result.ret,
                ..TxResult::empty()
            }
        }
        Err(e) => {
            iso.revert();
            TxResult {
                tx_id,
                contract_type: Some(ty),
                outcome: TxOutcome::ExecutionFailed(e),
                            ..TxResult::empty()
            }
        }
    }
}

/// Route a `TriggerSmartContract` transaction through the TVM.
///
/// Returns [`TxOutcome::Invalid`] with an [`ActuatorError::NotImplemented`]
/// shape when the session was built without EVM stores attached, so the
/// failure mode is clear at the executor layer.
///
/// **Energy charging.** After the VM returns its `VmOutcome::Success`
/// (or `Revert`), this function calls
/// [`energy::consume_energy`] on the caller's account, deducting the
/// energy cost from their frozen-energy quota with a TRX-fee fallback.
/// On a revert, java-tron still charges the energy that ran before the
/// revert — we mirror that. On insufficient balance for the fee, the
/// whole session is reverted and the tx is marked
/// [`TxOutcome::ExecutionFailed`].
/// Cap when the strict gate is off: keeps synthetic test fixtures
/// (which build VM txs via `..Default::default()`, so `fee_limit = 0`)
/// running with a generous energy budget. Matches the historical
/// hardcode this fix replaces. NEVER reached in production —
/// `runtime.rs` sets `require_fee_limit = true`.
const TEST_FALLBACK_ENERGY_LIMIT: u64 = 10_000_000;

/// Absolute ceiling on the VM's per-tx energy budget. A mainnet block
/// caps total energy at ~150M; permitting a single tx to demand up
/// to 1B energy keeps the revm gas counter (a `u64`) well within
/// arithmetic safety while still being looser than any realistic tx.
/// A `fee_limit = i64::MAX` would otherwise saturate into a nonsense
/// budget downstream.
const MAX_VM_ENERGY_LIMIT: u64 = 1_000_000_000;

/// Derive the per-tx VM energy budget from `fee_limit` and
/// `energy_fee` per java-tron's `Manager.processTransaction` formula:
/// `energyLimit = feeLimit / energyFee`, clamped to a safety ceiling.
///
/// Returns `Err(TxOutcome::InvalidFeeLimit { .. })` when strict mode is on and
/// `fee_limit < 0 || fee_limit > max_fee_limit` — byte-for-byte java-tron's
/// `VMActuator.validate` gate (`feeLimit < 0 || feeLimit > getMaxFeeLimit()`).
/// Crucially `fee_limit == 0` is VALID in java (a caller who pays energy
/// entirely from staked resources needs no TRX burn cap); rejecting it (the
/// old `<= 0`) diverged from java, which executed the tx. Returns
/// [`TEST_FALLBACK_ENERGY_LIMIT`] when strict mode is off (the
/// `ExecConfig::unsigned()` escape hatch for tests / dry-run).
///
/// `energy_fee` defaults to `DEFAULT_ENERGY_FEE = 100` sun/energy on
/// mainnet; defensively, a misconfigured `<= 0` is clamped to 1 to
/// avoid division-by-zero (the production code paths read this from
/// `DynamicPropertiesStore::energy_fee()` which already saturates at
/// the documented default).
fn compute_vm_energy_limit(
    fee_limit: i64,
    energy_fee: i64,
    max_fee_limit: i64,
    require_fee_limit: bool,
) -> Result<u64, TxOutcome> {
    if !require_fee_limit {
        return Ok(TEST_FALLBACK_ENERGY_LIMIT);
    }
    if fee_limit < 0 || fee_limit > max_fee_limit {
        return Err(TxOutcome::InvalidFeeLimit { fee_limit });
    }
    let divisor = energy_fee.max(1) as u64;
    let derived = (fee_limit as u64) / divisor;
    Ok(derived.min(MAX_VM_ENERGY_LIMIT))
}

/// Real `TriggerSmartContract` VM energy budget — java
/// `VMActuator.getTotalEnergyLimit(creator, caller, ...)` (fix-ratio path).
/// Reads the caller's account + the contract row (for origin / percent /
/// origin_energy_limit) + the origin's account from the pre-execution `view`,
/// then delegates the arithmetic to [`energy::vm_energy_budget_trigger`].
/// Capped at [`MAX_VM_ENERGY_LIMIT`] for the revm `u64` gas counter. Returns 0
/// when the caller account is unrecoverable (the VM will preflight-fail, just
/// as java would have rejected at validate).
fn vm_energy_budget_for_trigger(
    view: &StateBackends,
    dp: &tron_chainbase::DynamicPropertiesStore,
    caller: Option<&Address>,
    contract_addr: Option<&Address>,
    call_value: i64,
    fee_limit: i64,
    now_slot: i64,
) -> u64 {
    // SELF-RENT FIX: one budget per VM tx, before execution — clear prior tx's
    // captured quotas so only this tx's caller is stored.
    energy::clear_pre_tx_energy_quota();
    let Some(caller) = caller else {
        return 0;
    };
    let accounts = tron_chainbase::AccountStore::new(view.accounts.clone() as _);
    let Ok(Some(caller_acct)) = accounts.get(caller) else {
        return 0;
    };
    // Resolve the contract's origin / consume_user_resource_percent /
    // origin_energy_limit. A missing contract row, or an origin equal to the
    // caller, collapses to the caller-only budget (creator = None).
    let (creator_acct, percent, raw_origin_energy_limit) = match contract_addr {
        Some(ca) => {
            let contracts = tron_chainbase::ContractStore::new(view.contracts.clone() as _);
            match contracts.get(ca) {
                Ok(Some(sc)) => {
                    // Keep the origin ADDRESS alongside its account row — the
                    // budget now persists the origin's pre-consume and must
                    // write it back keyed by address.
                    let creator = match address_from_proto(&sc.origin_address) {
                        Some(o) if &o != caller => accounts.get(&o).ok().flatten().map(|a| (o, a)),
                        _ => None,
                    };
                    (
                        creator,
                        sc.consume_user_resource_percent,
                        sc.origin_energy_limit,
                    )
                }
                _ => (None, 0, 0),
            }
        }
        None => (None, 0, 0),
    };
    let budget = energy::vm_energy_budget_trigger(
        &accounts,
        dp,
        caller,
        &caller_acct,
        creator_acct.as_ref().map(|(a, acc)| (a, acc)),
        percent,
        raw_origin_energy_limit,
        fee_limit,
        call_value,
        now_slot,
    );
    budget.max(0).min(MAX_VM_ENERGY_LIMIT as i64) as u64
}

/// Real `CreateSmartContract` VM energy budget — java
/// `getAccountEnergyLimitWithFixRatio(caller, feeLimit, callValue)` (the
/// creator IS the caller, so no origin split). Capped at
/// [`MAX_VM_ENERGY_LIMIT`].
fn vm_energy_budget_for_create(
    view: &StateBackends,
    dp: &tron_chainbase::DynamicPropertiesStore,
    caller: Option<&Address>,
    call_value: i64,
    fee_limit: i64,
    now_slot: i64,
) -> u64 {
    // SELF-RENT FIX: one budget per VM tx, before execution — clear prior tx's
    // captured quotas so only this tx's caller is stored.
    energy::clear_pre_tx_energy_quota();
    let Some(caller) = caller else {
        return 0;
    };
    let accounts = tron_chainbase::AccountStore::new(view.accounts.clone() as _);
    let Ok(Some(caller_acct)) = accounts.get(caller) else {
        return 0;
    };
    let budget =
        energy::vm_energy_budget_create(&accounts, dp, caller, &caller_acct, fee_limit, call_value, now_slot);
    budget.max(0).min(MAX_VM_ENERGY_LIMIT as i64) as u64
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
fn execute_vm_tx(
    view: &StateBackends,
    iso: &TxIsolation,
    tx_id: [u8; 32],
    ty: ContractType,
    parameter: &prost_types::Any,
    config: &ExecConfig,
    fee_limit: i64,
    // The EXECUTING block's number + timestamp (block N), for the VM's
    // NUMBER/TIMESTAMP opcodes. NOT the committed head (N-1): java's
    // ProgramInvokeFactory reads them straight off the block being processed,
    // while the dyn-props head pointer only advances after the tx loop. The
    // resource model still reads the head (N-1) via the dyn-props store.
    block_number: i64,
    block_timestamp_ms: i64,
    // 20-byte EVM-form address of the block's producing witness, surfaced to
    // the VM as the COINBASE (0x41) opcode (java reads `block.getWitnessAddress`
    // into the coinbase DataWord).
    beneficiary: [u8; 20],
    // When the canonical block records this VM tx's contractRet as
    // `OUT_OF_TIME`, force that outcome: skip VM execution, discard all VM
    // contract-state changes, and charge the full energy budget
    // (`spendAllEnergy`). A wall-clock artifact of java-tron's JVM that a
    // non-JVM node can't reproduce by timing, so on replay/validation we
    // defer to the recorded result. Always `false` during block production.
    recorded_out_of_time: bool,
    mut receipt: TxReceipt,
) -> TxResult {
    use tron_chainbase::{
        BlockIndexStore as BIS, CodeStore as CS, ContractStateStore as CtS,
        ContractStore as ConS, DelegatedResourceStore as DRS, DelegationStore as DelS,
        DynamicPropertiesStore as DPS, StorageRowStore as SRS, WitnessStore as WS,
    };

    // Require all four EVM-side stores; if any is missing we can't
    // safely run the VM.
    let (Some(code), Some(storage), Some(contract_state)) = (
        view.code.as_ref(),
        view.storage_row.as_ref(),
        view.contract_state.as_ref(),
    ) else {
        iso.revert();
        return TxResult {
            tx_id,
            contract_type: Some(ty),
            outcome: TxOutcome::Invalid(ActuatorError::NotImplemented(
                "VM-bound contract but executor was built without EVM stores attached",
            )),
                    ..TxResult::empty()
        };
    };

    // VM-frame isolation layer. Every backend the TVM (revm +
    // precompiles + TronHost staking + TRC-10 inspector) may write
    // to is wrapped in a second SessionBackend on top of the per-tx
    // session. After the VM returns we either commit this inner
    // layer (Success) or revert it (Revert/Halt/Timeout/etc.) —
    // mirrors java-tron's `Program.java` Deposit pattern, where
    // every nested VM frame runs against a child deposit that's
    // dropped on revert via stack unwind.
    //
    // The OUTER per-tx session keeps the bandwidth charge (applied
    // before this function) and the post-VM energy charge (applied
    // below via `pay_energy_bill`) intact regardless of VM outcome,
    // matching java-tron's consensus rule that energy is paid even
    // on revert.
    let vm_session = VmSession::wrap(
        view.accounts.clone(),
        code.clone(),
        storage.clone(),
        contract_state.clone(),
        view.votes.clone(),
        view.delegated_resources.clone(),
        view.delegated_resource_account_index.clone(),
        view.dyn_props.clone(),
        view.delegation.clone(),
    );

    let vm_stores = tron_tvm::execute::VmStores {
        accounts: Arc::new(AccountStore::new(vm_session.accounts.clone() as _)),
        code: Arc::new(CS::new(vm_session.code.clone() as _)),
        storage: Arc::new(SRS::new(vm_session.storage_row.clone() as _)),
        witnesses: Arc::new(WS::new(view.witnesses.clone() as _)),
        contract_state: Arc::new(CtS::new(vm_session.contract_state.clone() as _)),
        dynamic_properties: Arc::new(DPS::new(vm_session.dyn_props.clone() as _)),
        delegated_resources: Arc::new(DRS::new(vm_session.delegated_resources.clone() as _)),
        // DelegatedResourceAccountIndex — RPC-only bidirectional index the
        // DELEGATERESOURCE / UNDELEGATERESOURCE opcode bridges keep in sync
        // with java-tron. Routed through the inner `vm_session` so a reverted
        // VM frame discards the index writes for free (no journal needed).
        delegated_resource_account_index: vm_session
            .delegated_resource_account_index
            .as_ref()
            .map(|b| {
                Arc::new(tron_chainbase::DelegatedResourceAccountIndexStore::new(
                    b.clone() as _,
                ))
            }),
        // Routed through the inner `vm_session` so a WHOLE-tx VM revert discards
        // the begin/end-cycle + account-vote rows the TVM reward-settle writes
        // (java's frame-scoped delegationCache — committed only on success). The
        // staking journal's `Delegation` reverser covers the inner-frame-revert
        // variant; the two together mirror how votes / delegated-resources roll
        // back. NOTE: the precompiles + host hold an `Arc<DelegationStore>` over
        // the SAME `vm_session.delegation` backend, so a reward-balance read and
        // a settle write see one consistent overlay.
        delegation: Arc::new(DelS::new(vm_session.delegation.clone() as _)),
        // Attach BlockIndexStore so BLOCKHASH(n) returns real hashes
        // for the last 256 blocks (when the backend is configured).
        // Read-only from the VM's perspective — no inner-session
        // wrapping needed.
        block_index: view
            .block_index
            .as_ref()
            .map(|b| Arc::new(BIS::new(b.clone() as _))),
        // ContractStore lets the v1/v2 storage-key layout selector
        // read SmartContract.version. Read-only from the VM.
        contracts: Some(Arc::new(ConS::new(view.contracts.clone() as _))),
        // VotesStore feeds the VOTEWITNESS opcode bridge, which DOES
        // write (the corresponding `accounts` row plus the votes
        // row). Routed through the inner session so a reverted VM
        // frame doesn't leave votes persisted.
        votes: Some(Arc::new(VotesStore::new(vm_session.votes.clone() as _))),
        // reward-vi: read-only legacy-reward accumulator (no session
        // wrapping — never written by execution).
        reward_vi: view
            .reward_vi
            .as_ref()
            .map(|b| Arc::new(tron_chainbase::RewardViStore::new(b.clone()))),
        // abi: only deleted (SELFDESTRUCT cleanup) — routed through the
        // per-tx session like `contracts`, so a failed tx reverts it.
        abi: Some(Arc::new(tron_chainbase::AbiStore::new(view.abi.clone()))),
    };

    // `block_number` / `block_timestamp_ms` are the EXECUTING block's (passed
    // in) — used for the VM block env. The dyn-props head (N-1) is read
    // separately by the resource model inside the VM.
    let dp = DPS::new(view.dyn_props.clone() as _);

    let energy_limit = match compute_vm_energy_limit(
        fee_limit,
        dp.energy_fee(),
        dp.max_fee_limit(),
        config.require_fee_limit,
    ) {
        Ok(limit) => limit,
        Err(reason) => {
            iso.revert();
            return TxResult {
                tx_id,
                contract_type: Some(ty),
                outcome: reason,
                ..TxResult::empty()
            };
        }
    };

    let block_env = tron_tvm::execute::VmBlockEnv {
        block_number,
        block_timestamp_ms,
        beneficiary,
    };
    // Extract the caller (owner) and the contract's energy_limit budget.
    //
    // For energy charging we need: (a) the caller's address (so we can
    // debit their account); (b) the energy actually consumed by the VM
    // (taken from the `VmOutcome`); (c) the now_slot for windowed-decay.
    //
    // The fee_limit (TRX-denominated cap) gates how much energy the VM
    // is allowed to spend; this caps `energy_limit_for_vm = fee_limit /
    // energy_fee`. Until that flow lands we keep the 10M cap.
    let now_slot = head_slot(&dp);

    // For a block-recorded `OUT_OF_TIME` tx we still run the energy BUDGET
    // (it persists the caller/origin frozen pre-consume that the energy
    // charge bills against, exactly as java's `VMActuator.validate -> call/
    // create` does before `execute()`), but skip `VM.play()` and instead
    // `spendAllEnergy()` — `energy_used = energy_limit`. The whole VM frame
    // is discarded. `Some(limit)` here is the signal to take that path below.
    let mut out_of_time_energy: Option<u64> = None;
    let (caller_addr, trigger_contract_addr, outcome, vm_traces, energy_penalty) = match ty {
        ContractType::TriggerSmartContract => {
            // Decode the way java's generated parser does — skipping any field
            // whose tag matches no known field (e.g. call-data mis-encoded
            // under field 3 / `call_value`). A strict prost decode would
            // reject such a tx pre-VM (DEFAULT, no energy) whereas java skips
            // the stray field and runs an empty-data call to REVERT.
            let trigger: tron_proto::TriggerSmartContract =
                match tron_proto::decode_lenient(parameter.value.as_slice()) {
                    Ok(t) => t,
                    Err(e) => {
                        iso.revert();
                        return TxResult {
                            tx_id,
                            contract_type: Some(ty),
                            outcome: TxOutcome::Invalid(ActuatorError::Store(format!(
                                "decode TriggerSmartContract: {e}"
                            ))),
                                                    ..TxResult::empty()
                        };
                    }
                };
            let caller = address_from_proto(&trigger.owner_address);
            let contract_addr = address_from_proto(&trigger.contract_address);
            // Real VM energy budget (java `getTotalEnergyLimit`): the bare
            // `energy_limit` from the fee-limit gate is only the
            // `feeLimit/energyFee` term. In strict (consensus) mode replace it
            // with the full budget = caller's staked + balance-buyable energy
            // (capped by feeLimit) PLUS the contract creator's subsidy. Lenient
            // mode (unsigned/test) keeps the historical fallback.
            let energy_limit = if config.require_fee_limit {
                vm_energy_budget_for_trigger(
                    view,
                    &dp,
                    caller.as_ref(),
                    contract_addr.as_ref(),
                    trigger.call_value,
                    fee_limit,
                    now_slot,
                )
            } else {
                energy_limit
            };
            if recorded_out_of_time {
                // java `VMActuator.execute`: the producer-replay path
                // (`generatedByMyself && hasWitnessSignature && contractRet ==
                // OUT_OF_TIME`) calls `program.spendAllEnergy()` and throws
                // `OutOfTimeException` BEFORE `VM.play()` — the VM never runs,
                // so `energyUsed == energyLimit`. We mirror that here: no VM
                // call, full budget charged below.
                out_of_time_energy = Some(energy_limit);
                (caller, contract_addr, None, Vec::new(), 0)
            } else {
                let (outcome, traces, energy_penalty) =
                    tron_tvm::execute::execute_trigger_with_trace_tx_id(
                        &vm_stores,
                        block_env,
                        &trigger,
                        energy_limit,
                        tx_id,
                    );
                (caller, contract_addr, Some(outcome), traces, energy_penalty)
            }
        }
        ContractType::CreateSmartContract => {
            // Lenient decode (java's generated-parser skip-unknown semantics),
            // matching the TriggerSmartContract arm above.
            let create: tron_proto::CreateSmartContract =
                match tron_proto::decode_lenient(parameter.value.as_slice()) {
                    Ok(c) => c,
                    Err(e) => {
                        iso.revert();
                        return TxResult {
                            tx_id,
                            contract_type: Some(ty),
                            outcome: TxOutcome::Invalid(ActuatorError::Store(format!(
                                "decode CreateSmartContract: {e}"
                            ))),
                                                    ..TxResult::empty()
                        };
                    }
                };
            // Caller for CreateSmartContract lives on the inner
            // `new_contract.origin_address`.
            let caller = create
                .new_contract
                .as_ref()
                .and_then(|c| address_from_proto(&c.origin_address));
            // Real VM energy budget — caller-only (creator == caller for a
            // deploy), java `getAccountEnergyLimitWithFixRatio`. Strict mode
            // only; lenient keeps the fallback.
            let energy_limit = if config.require_fee_limit {
                let call_value = create
                    .new_contract
                    .as_ref()
                    .map(|c| c.call_value)
                    .unwrap_or(0);
                vm_energy_budget_for_create(view, &dp, caller.as_ref(), call_value, fee_limit, now_slot)
            } else {
                energy_limit
            };
            if recorded_out_of_time {
                // See the TriggerSmartContract arm: skip `VM.play()`, charge
                // the full budget (`spendAllEnergy`). caller IS the origin for
                // a create, so no origin split.
                out_of_time_energy = Some(energy_limit);
                (caller, None, None, Vec::new(), 0)
            } else {
                let (outcome, traces, energy_penalty) = tron_tvm::execute::execute_create_with_trace(
                    &vm_stores,
                    block_env,
                    &create,
                    &tx_id,
                    energy_limit,
                );
                // CreateSmartContract: caller IS the origin, so no origin
                // split applies. Pass `None` for the contract address so
                // the energy-charge path takes the caller-pays-all branch.
                (caller, None, Some(outcome), traces, energy_penalty)
            }
        }
        _ => unreachable!("execute_vm_tx invoked for non-VM contract type"),
    };

    // === VM-frame state isolation. ===
    //
    // Commit or revert the inner `vm_session` based on the VM's
    // outcome BEFORE applying the energy charge:
    //
    //   * `Success` → commit: VM writes flow into the per-tx session.
    //   * `Revert` / `Halt` / `Timeout` → revert: VM writes dropped
    //     (matches java-tron's "every revert unwinds the deposit").
    //   * `CallTokenIgnored` / `PreflightError` → revert: tx is
    //     consensus-invalid; nothing the VM may have touched (top-level
    //     CALLTOKEN debit, CREATE pre-installs, etc.) should persist.
    //
    // The per-tx outer session is untouched here — its bandwidth +
    // about-to-apply energy charge survive whichever branch fires.
    //
    // OUT_OF_TIME (`outcome == None`) takes the revert branch: java's
    // `OutOfTimeException` path never reaches `rootRepository.commit()`, so
    // the child deposit — every VM contract-state write — is discarded.
    match &outcome {
        Some(tron_tvm::execute::VmOutcome::Success { .. }) => vm_session
            .commit()
            .expect("db error in execute_vm_tx: VmSession::commit flush failed"),
        _ => vm_session.revert(),
    }

    // The budget pre-consumed the caller's (and origin's) frozen energy and
    // PERSISTED it before the VM so an in-VM UNDELEGATE/DELEGATE read the
    // un-decayed base. Now reconcile it like java `TransactionTrace.pay`:
    //   * SUCCESS → `resetAccountUsage(V2)`: give back the unused pre-consume so
    //     the charge bills off the post-decay base. Runs even when
    //     energy_used == 0 (java resets regardless), so it's OUTSIDE the
    //     `energy_used > 0` guard.
    //   * REVERT/HALT/etc. → UNDO the pre-consume: java never committed it (it
    //     lived in the discarded rootRepository cache), so the charge must decay
    //     from the ORIGINAL row. Our budget persisted to the outer session
    //     (survives the VM revert), so we restore the original fields here.
    // Gated on `require_fee_limit` — only strict (consensus) mode ran the budget
    // pre-consume; lenient/constant-call never captured, so skip (and avoid
    // reading a stale thread-local capture from a prior strict tx).
    if config.require_fee_limit {
        if let Some(caller) = caller_addr {
            let accounts = AccountStore::new(view.accounts.clone() as _);
            let dp_store = DynamicPropertiesStore::new(view.dyn_props.clone() as _);
            // Re-derive the distinct origin exactly as the pay block below.
            let origin = match &trigger_contract_addr {
                Some(contract_addr) => {
                    let contracts = ConS::new(view.contracts.clone() as _);
                    match contracts.get(contract_addr) {
                        Ok(Some(sc)) => {
                            address_from_proto(&sc.origin_address).filter(|o| *o != caller)
                        }
                        _ => None,
                    }
                }
                None => None,
            };
            // OUT_OF_TIME (`outcome == None`) takes the revert branch: java's
            // `TransactionTrace.pay` only runs `resetAccountUsage` when
            // `getException() == null && !isRevert()`, and the OutOfTimeException
            // leaves an exception set — so the pre-consume is NOT reset (it was
            // never committed in java's discarded rootRepository), and the energy
            // charge below decays from the original row.
            if matches!(&outcome, Some(tron_tvm::execute::VmOutcome::Success { .. })) {
                let _ =
                    energy::reset_energy_pre_consume(&accounts, &dp_store, &caller, origin.as_ref());
            } else {
                let _ = energy::revert_energy_pre_consume(
                    &accounts,
                    &dp_store,
                    &caller,
                    origin.as_ref(),
                );
            }
        }
    }

    // Charge energy for the caller. java-tron does this in
    // `TransactionTrace.pay()` after the VM finishes. Even on revert
    // the energy that ran is still charged — that's the consensus rule.
    //
    // If the caller isn't recoverable from the proto (malformed
    // address) we skip the charge — the tx would have hit a preflight
    // error inside the VM and the outcome arm below will reject it.
    // OUT_OF_TIME charges the FULL energy budget (java
    // `Program.spendAllEnergy` → `energyUsed = energyLimit`); the synthetic
    // `out_of_time_energy` carries that budget, overriding the per-outcome
    // read (which would be 0 for the `None` outcome).
    let (energy_used, vm_succeeded) = match (out_of_time_energy, &outcome) {
        (Some(limit), _) => (limit, false),
        (None, Some(tron_tvm::execute::VmOutcome::Success { energy_used, .. })) => {
            (*energy_used, true)
        }
        (None, Some(tron_tvm::execute::VmOutcome::Revert { energy_used, .. })) => {
            (*energy_used, false)
        }
        // A `TransferException` is `spendAllEnergy`-exempt (`VM.java` /
        // `VMActuator`): it charges only the energy consumed up to the throw,
        // exactly like a revert — NOT the full limit. So the energy comes
        // straight from the outcome, no spend-all override.
        (None, Some(tron_tvm::execute::VmOutcome::TransferFailed { energy_used })) => {
            (*energy_used, false)
        }
        (None, Some(tron_tvm::execute::VmOutcome::Halt { energy_used, .. })) => {
            (*energy_used, false)
        }
        _ => (0, false),
    };
    receipt.energy_usage_total = energy_used as i64;
    // java-tron: `TransactionTrace.setPenalty(programResult
    // .getEnergyPenaltyTotal())` → `receipt.energy_penalty_total`,
    // recorded for every executed VM tx (success, revert, and halt).
    receipt.energy_penalty_total = energy_penalty as i64;
    if let Some(caller) = caller_addr {
        if energy_used > 0 {
            let accounts = AccountStore::new(view.accounts.clone() as _);
            let dp_store = DynamicPropertiesStore::new(view.dyn_props.clone() as _);
            // For `TriggerSmartContract`, look up the contract row to
            // get the origin / `consume_user_resource_percent` /
            // `origin_energy_limit` triple that drives java-tron's
            // origin/caller energy split (`ReceiptCapsule.payEnergyBill`).
            // For `CreateSmartContract` (origin is the caller) or any
            // contract missing from `ContractStore`, the split
            // degenerates and `pay_energy_bill` charges the caller for
            // the whole bill.
            let (origin_opt, percent, origin_limit) = match trigger_contract_addr {
                Some(contract_addr) => {
                    let contracts = ConS::new(view.contracts.clone() as _);
                    match contracts.get(&contract_addr) {
                        Ok(Some(sc)) => {
                            let origin = address_from_proto(&sc.origin_address);
                            // java `ContractCapsule.getOriginEnergyLimit` remaps
                            // a stored 0 (old contracts) to the creator default
                            // (10M) — without it the origin can't subsidize and
                            // the caller is over-charged. Same remap the energy
                            // budget uses, so budget and charge stay consistent.
                            (
                                origin,
                                sc.consume_user_resource_percent,
                                energy::effective_origin_energy_limit(sc.origin_energy_limit),
                            )
                        }
                        _ => (None, 0, 0),
                    }
                }
                None => (None, 0, 0),
            };
            // Mirror java's OUT_OF_TIME fee-pool exclusion: record the tx's
            // result so `pay_energy_fee` routes an OUT_OF_TIME energy fee to the
            // blackhole instead of the transaction-fee pool.
            energy::set_tx_out_of_time(out_of_time_energy.is_some());
            match energy::pay_energy_bill(
                &accounts,
                &dp_store,
                &caller,
                origin_opt.as_ref(),
                origin_limit,
                percent,
                energy_used,
                now_slot,
            ) {
                Ok(bill) => {
                    // State updated in-place; mirror the split into the
                    // receipt (java-tron's ReceiptCapsule fields).
                    if let Some(o) = &bill.origin_charge {
                        receipt.origin_energy_usage = match o {
                            energy::EnergyCharge::Frozen { energy_used, .. }
                            | energy::EnergyCharge::Fee { energy_used, .. }
                            | energy::EnergyCharge::Mixed { energy_used, .. } => *energy_used,
                        };
                    }
                    match &bill.caller_charge {
                        energy::EnergyCharge::Frozen { energy_used, .. } => {
                            receipt.energy_usage = *energy_used;
                        }
                        energy::EnergyCharge::Fee { fee_sun, .. } => {
                            receipt.energy_fee = *fee_sun;
                        }
                        energy::EnergyCharge::Mixed {
                            energy_from_frozen, fee_sun, ..
                        } => {
                            receipt.energy_usage = *energy_from_frozen;
                            receipt.energy_fee = *fee_sun;
                        }
                    }
                }
                Err(e) => {
                    // Insufficient balance for fee, or account missing.
                    // Whole session reverts (which also undoes any VM
                    // state changes AND any origin-side debit
                    // `pay_energy_bill` may have applied before
                    // hitting the caller-side shortfall); tx marked
                    // as failed.
                    iso.revert();
                    return TxResult {
                        tx_id,
                        contract_type: Some(ty),
                        outcome: TxOutcome::ExecutionFailed(ActuatorError::Store(format!(
                            "energy: {e}"
                        ))),
                                            ..TxResult::empty()
                    };
                }
            }
        }
    }

    // Materialize VM-side internal-transaction traces into the proto
    // wire form once, so every outcome arm below can attach a clone (or
    // an empty vec if the arm wants to drop them). Gated by the
    // `vm.saveInternalTx` / `vm.vmTrace` config knobs — when both are
    // off (java-tron default), traces are dropped to match the persist-
    // nothing behavior of an unconfigured node.
    let proto_internal_txs: Vec<tron_proto::InternalTransaction> = if config.record_internal_txs() {
        vm_traces.iter().map(|t| t.to_proto(&tx_id)).collect()
    } else {
        Vec::new()
    };

    // OUT_OF_TIME outcome (block-recorded; VM was skipped). Mirrors java's
    // Revert-style settlement: the VM frame was already discarded by
    // `vm_session.revert()`, the bandwidth (pre-VM) and the full
    // `spendAllEnergy` charge (applied above) stay, so `iso.commit()` flushes
    // exactly those into the per-tx parent. `result = OUT_OF_TIME`, no logs,
    // no internal txs (java `rejectInternalTransactions`).
    if out_of_time_energy.is_some() {
        let _ = vm_succeeded;
        iso.commit()
            .expect("db error in execute_vm_tx: commit flush failed on OUT_OF_TIME");
        receipt.result =
            tron_proto::transaction::result::ContractResult::OutOfTime as i32;
        return TxResult {
            tx_id,
            contract_type: Some(ty),
            // OUT_OF_TIME is a failed VM outcome (state reverted); surface it
            // as an execution failure so callers that gate on `Success`
            // (e.g. the contractRet tripwire's success/failure axis) treat it
            // correctly. The receipt carries the precise OUT_OF_TIME code.
            outcome: TxOutcome::ExecutionFailed(ActuatorError::Store(
                "VM out of time (block-recorded)".to_string(),
            )),
            internal_transactions: Vec::new(),
            vm_logs: Vec::new(),
            receipt,
            vm_return_data: Vec::new(),
            actuator_fee: 0,
            ret_extras: tron_actuator::TransactionRetExtras::default(),
        };
    }

    // For every non-OUT_OF_TIME path the VM ran and produced a concrete
    // outcome (`Some`). The `None` case is OUT_OF_TIME, handled above, so the
    // `unreachable!` only fires on a logic error.
    let outcome = outcome.expect("VM outcome must be Some when not OUT_OF_TIME");

    match outcome {
        tron_tvm::execute::VmOutcome::Success { logs, return_data, .. } => {
            let _ = vm_succeeded;
            iso.commit()
                .expect("db error in execute_vm_tx: commit flush failed on VM Success");
            receipt.result =
                tron_proto::transaction::result::ContractResult::Success as i32;
            TxResult {
                tx_id,
                contract_type: Some(ty),
                outcome: TxOutcome::Success,
                internal_transactions: proto_internal_txs,
                vm_logs: logs,
                receipt,
                vm_return_data: return_data,
                actuator_fee: 0,
                ret_extras: tron_actuator::TransactionRetExtras::default(),
            }
        }
        tron_tvm::execute::VmOutcome::Revert { return_data, .. } => {
            // VM-side writes were already discarded by `vm_session.revert()`
            // above (the inner nested-session layer). All that remains
            // in the per-tx session is bandwidth (charged before the
            // VM) and the energy charge that `pay_energy_bill` applied
            // afterwards — both of which java-tron's consensus rule
            // says must survive a revert. `session.commit()` flushes
            // exactly those into the per-tx parent.
            iso.commit()
                .expect("db error in execute_vm_tx: commit flush failed on VM Revert");
            receipt.result =
                tron_proto::transaction::result::ContractResult::Revert as i32;
            TxResult {
                tx_id,
                contract_type: Some(ty),
                outcome: TxOutcome::ExecutionFailed(ActuatorError::Store(
                    "VM revert".to_string(),
                )),
                internal_transactions: proto_internal_txs,
                vm_logs: Vec::new(),
                receipt,
                vm_return_data: return_data,
                actuator_fee: 0,
                ret_extras: tron_actuator::TransactionRetExtras::default(),
            }
        }
        tron_tvm::execute::VmOutcome::TransferFailed { .. } => {
            // java-tron `Program.TransferException` (a `BytecodeExecution
            // Exception` mapped to `contractResult TRANSFER_FAILED` at
            // `RuntimeImpl.setResultCode`): a value-transfer validation failure
            // (endowment-out-of-long-range / transfer trx|trc10 failed /
            // self-transfer). Settled exactly like a revert — the VM frame was
            // already discarded by `vm_session.revert()`, bandwidth + the
            // consumed-only energy charge (NOT spend-all; a `TransferException`
            // is exempt) survive in the per-tx session, so `iso.commit()`
            // flushes those — only the recorded `contractResult` differs.
            iso.commit().expect(
                "db error in execute_vm_tx: commit flush failed on VM TransferFailed",
            );
            receipt.result =
                tron_proto::transaction::result::ContractResult::TransferFailed as i32;
            TxResult {
                tx_id,
                contract_type: Some(ty),
                outcome: TxOutcome::ExecutionFailed(ActuatorError::Store(
                    "VM transfer failed".to_string(),
                )),
                internal_transactions: proto_internal_txs,
                vm_logs: Vec::new(),
                receipt,
                vm_return_data: Vec::new(),
                actuator_fee: 0,
                ret_extras: tron_actuator::TransactionRetExtras::default(),
            }
        }
        tron_tvm::execute::VmOutcome::Halt { reason, result, .. } => {
            iso.commit()
                .expect("db error in execute_vm_tx: commit flush failed on VM Halt");
            // `result` is the structured java-tron `contractResult` the TVM
            // mapped from revm's `HaltReason` at the halt site
            // (`RuntimeImpl.setResultCode` parity) — OUT_OF_ENERGY /
            // ILLEGAL_OPERATION / BAD_JUMP_DESTINATION / STACK_TOO_SMALL /
            // STACK_TOO_LARGE / PRECOMPILED_CONTRACT / INVALID_CODE, or
            // UNKNOWN for halts java has no dedicated code for.
            receipt.result = result as i32;
            TxResult {
                tx_id,
                contract_type: Some(ty),
                outcome: TxOutcome::ExecutionFailed(ActuatorError::Store(format!(
                    "VM halt: {reason}"
                ))),
                internal_transactions: proto_internal_txs,
                vm_logs: Vec::new(),
                receipt,
                vm_return_data: Vec::new(),
                actuator_fee: 0,
                ret_extras: tron_actuator::TransactionRetExtras::default(),
            }
        }
        tron_tvm::execute::VmOutcome::CallTokenIgnored { .. } => {
            iso.revert();
            TxResult {
                tx_id,
                contract_type: Some(ty),
                outcome: TxOutcome::Invalid(ActuatorError::NotImplemented(
                    "CALLTOKEN opcode (TRC-10 transfer) — requires revm fork",
                )),
                ..TxResult::empty()
            }
        }
        tron_tvm::execute::VmOutcome::PreflightError(msg) => {
            iso.revert();
            TxResult {
                tx_id,
                contract_type: Some(ty),
                outcome: TxOutcome::Invalid(ActuatorError::Store(msg)),
                internal_transactions: proto_internal_txs,
                ..TxResult::empty()
            }
        }
        // Timeout is only produced by read-only RPC paths
        // (`execute_trigger_with_deadline`) that don't go through the
        // block executor. If somehow surfaced here it indicates a
        // wiring mistake — treat it as an execution failure so the tx
        // is rejected rather than silently committed.
        tron_tvm::execute::VmOutcome::Timeout { deadline_ms, .. } => {
            iso.revert();
            TxResult {
                tx_id,
                contract_type: Some(ty),
                outcome: TxOutcome::ExecutionFailed(ActuatorError::Store(format!(
                    "VM timeout ({deadline_ms}ms) — not expected on block-apply path"
                ))),
                internal_transactions: proto_internal_txs,
                ..TxResult::empty()
            }
        }
    }
}

/// Decode a 21-byte address slice into an [`Address`]. Returns `None`
/// for malformed lengths.
fn address_from_proto(bytes: &[u8]) -> Option<tron_crypto::address::Address> {
    if bytes.len() != 21 {
        return None;
    }
    let mut buf = [0u8; 21];
    buf.copy_from_slice(bytes);
    Some(tron_crypto::address::Address::from_raw(buf))
}

// =============================================================================
// Genesis allocations replay
// =============================================================================

/// Apply the mainnet genesis allocations + initial witnesses to live
/// state. Mirrors java-tron's `Manager::initAccount` + `initWitness`:
///
/// * For each `GenesisAsset`: write an Account row at its address
///   with `balance = asset.balance`, `type = Normal`. (java-tron
///   also writes the account name; our `GenesisAsset` doesn't carry
///   one — we leave the name empty.)
/// * For each `GenesisWitness`: upsert the Account at its address
///   with `is_witness = true` (creating a fresh `AssetIssue`-typed
///   one if missing), then write a Witness row with `vote_count`,
///   `url`, and `is_jobs = true`.
///
/// Idempotent — re-running against an already-bootstrapped chain
/// overwrites the same rows with identical values.
pub fn apply_genesis_allocations(
    state: &StateBackends,
    assets: &[tron_types::GenesisAsset],
    witnesses: &[tron_types::GenesisWitness],
) -> Result<(), tron_chainbase::StoreError> {
    use tron_crypto::address::Address;
    use tron_proto::{Account, AccountType, Witness};

    let accounts = AccountStore::new(state.accounts.clone());
    let name_index = AccountIndexStore::new(state.name_index.clone());
    let witnesses_store = WitnessStore::new(state.witnesses.clone());

    for asset in assets {
        let addr = Address::from_raw(asset.address);
        let existing = accounts.get(&addr)?;
        let acct = Account {
            address: asset.address.to_vec(),
            account_name: asset.name.as_bytes().to_vec(),
            balance: asset.balance,
            r#type: AccountType::Normal as i32,
            create_time: 0,
            // Preserve any pre-existing votes / asset balances etc.
            // from a re-run.
            ..existing.unwrap_or_default()
        };
        accounts.put(&addr, &acct)?;
        // Mirror java-tron's `Manager.initAccount`: also populate the
        // `account-index` store (name → address) so `getAccountByName`
        // works on genesis accounts. java-tron's
        // `AccountIndexStore.put(AccountCapsule)` writes
        // unconditionally; we skip when name is empty to avoid an
        // empty-key entry. AccountIdIndexStore (id → address) is not
        // populated at genesis — assets don't carry an accountId in
        // mainnet config.conf; the id only gets set via `setAccountId`.
        if !asset.name.is_empty() {
            name_index.put(asset.name.as_bytes(), &addr)?;
        }
    }

    for w in witnesses {
        let addr = Address::from_raw(w.address);
        let mut acct = accounts.get(&addr)?.unwrap_or(Account {
            address: w.address.to_vec(),
            balance: 0,
            // java-tron uses `AccountType::AssetIssue` for an
            // auto-created witness; mirrors that.
            r#type: AccountType::AssetIssue as i32,
            ..Default::default()
        });
        acct.is_witness = true;
        accounts.put(&addr, &acct)?;

        let witness = Witness {
            address: w.address.to_vec(),
            vote_count: w.vote_count,
            url: w.url.to_string(),
            total_produced: 0,
            total_missed: 0,
            latest_block_num: 0,
            latest_slot_num: 0,
            is_jobs: true,
            pub_key: Vec::new(),
        };
        witnesses_store.put(&addr, &witness)?;
    }

    // java `DposService.start` seeds the active-witness list at fresh genesis
    // (latestBlockHeaderNumber == 0): sort the genesis witnesses by vote_count
    // DESC, take the top 27, and `saveActiveWitnesses`. Without this our active
    // list stays empty until the first maintenance (~block 7200), so during that
    // window `total_missed` is never attributed (its bump is gated on a
    // non-empty active list) and the producer-validation gate short-circuits —
    // drifting witness-store counters vs java. The block schedule itself is
    // computed from the witness rows (not this list), so seeding does not change
    // block production; the first maintenance recomputes + overwrites the list.
    // Tie-break is immaterial: genesis has 27 witnesses, so the top-27 set is
    // all of them regardless of order, and that set is what the counters key on.
    if let Some(sched) = &state.witness_schedule {
        let schedule = tron_chainbase::WitnessScheduleStore::new(sched.clone());
        let mut ranked: Vec<(Address, i64)> = witnesses
            .iter()
            .map(|w| (Address::from_raw(w.address), w.vote_count))
            .collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| b.0.as_bytes().cmp(a.0.as_bytes())));
        let active: Vec<Address> = ranked.into_iter().take(27).map(|(a, _)| a).collect();
        schedule.save_active(&active)?;
    }

    Ok(())
}

// =============================================================================
// Bandwidth helpers
// =============================================================================

/// Pull the owner address from a contract for bandwidth charging.
/// Returns `Err(())` for contract types that have no obvious owner
/// (in which case the caller skips the charge).
/// Debit a flat fee (multi-sign / memo) from the contract owner's
/// balance, mirroring the body of java-tron's
/// `Manager.consumeMultiSignFee`: a missing owner account skips the
/// charge (`if (accountCapsule != null)` — the shielded case), an
/// insufficient balance is an error, and the fee burns via the
/// blackhole-optimization path. Notably java does NOT touch
/// `latest_operation_time` here, unlike its other fee debits. Returns
/// the amount actually charged.
fn charge_flat_fee(
    accounts: &AccountStore,
    dyn_props: &tron_chainbase::DynamicPropertiesStore,
    contract: &tron_proto::transaction::Contract,
    ty: ContractType,
    fee: i64,
) -> Result<i64, String> {
    let Ok(owner) = extract_owner_for_bandwidth(contract, ty) else {
        return Ok(0);
    };
    let Some(mut account) = accounts.get(&owner).map_err(|e| e.to_string())? else {
        return Ok(0);
    };
    if account.balance < fee {
        return Err(format!(
            "account balance {} cannot cover the {} sun fee",
            account.balance, fee
        ));
    }
    account.balance -= fee;
    accounts.put(&owner, &account).map_err(|e| e.to_string())?;
    bandwidth::dispose_fee(&accounts, dyn_props, fee).map_err(|e| e.to_string())?;
    Ok(fee)
}

fn extract_owner_for_bandwidth(
    contract: &tron_proto::transaction::Contract,
    ty: ContractType,
) -> Result<tron_crypto::address::Address, ()> {
    let parameter = contract.parameter.as_ref().ok_or(())?;
    // java decodes the contract message with the standard generated parser,
    // which skips fields whose tag matches no known field (including a known
    // field number with a mismatched wire type). Use the same lenient decode
    // so the owner — and the bandwidth charge — match java even on a
    // malformed-but-skippable parameter (see `tron_proto::decode_lenient`).
    macro_rules! unpack {
        ($T:ty) => {{
            let c = tron_proto::decode_lenient::<$T>(parameter.value.as_slice()).map_err(|_| ())?;
            c.owner_address
        }};
    }
    let bytes = match ty {
        ContractType::TransferContract => unpack!(tron_proto::TransferContract),
        ContractType::TransferAssetContract => unpack!(tron_proto::TransferAssetContract),
        ContractType::VoteWitnessContract => unpack!(tron_proto::VoteWitnessContract),
        ContractType::WitnessCreateContract => unpack!(tron_proto::WitnessCreateContract),
        ContractType::WitnessUpdateContract => unpack!(tron_proto::WitnessUpdateContract),
        ContractType::WithdrawBalanceContract => unpack!(tron_proto::WithdrawBalanceContract),
        ContractType::AccountCreateContract => unpack!(tron_proto::AccountCreateContract),
        ContractType::AccountUpdateContract => unpack!(tron_proto::AccountUpdateContract),
        ContractType::FreezeBalanceContract => unpack!(tron_proto::FreezeBalanceContract),
        ContractType::UnfreezeBalanceContract => unpack!(tron_proto::UnfreezeBalanceContract),
        ContractType::FreezeBalanceV2Contract => unpack!(tron_proto::FreezeBalanceV2Contract),
        ContractType::UnfreezeBalanceV2Contract => unpack!(tron_proto::UnfreezeBalanceV2Contract),
        ContractType::DelegateResourceContract => unpack!(tron_proto::DelegateResourceContract),
        ContractType::UnDelegateResourceContract => unpack!(tron_proto::UnDelegateResourceContract),
        ContractType::AccountPermissionUpdateContract => {
            unpack!(tron_proto::AccountPermissionUpdateContract)
        }
        ContractType::ProposalCreateContract => unpack!(tron_proto::ProposalCreateContract),
        ContractType::ProposalApproveContract => unpack!(tron_proto::ProposalApproveContract),
        ContractType::ProposalDeleteContract => unpack!(tron_proto::ProposalDeleteContract),
        // VM-bound contracts pay for their wire bytes like everything
        // else (java's TransactionCapsule.getOwner covers every type;
        // this match previously bailed for them, silently skipping the
        // bandwidth charge for ALL smart-contract transactions).
        ContractType::TriggerSmartContract => unpack!(tron_proto::TriggerSmartContract),
        ContractType::CreateSmartContract => {
            let c = tron_proto::decode_lenient::<tron_proto::CreateSmartContract>(
                parameter.value.as_slice(),
            )
            .map_err(|_| ())?;
            c.owner_address
        }
        ContractType::ParticipateAssetIssueContract => {
            unpack!(tron_proto::ParticipateAssetIssueContract)
        }
        ContractType::AssetIssueContract => unpack!(tron_proto::AssetIssueContract),
        ContractType::UpdateAssetContract => unpack!(tron_proto::UpdateAssetContract),
        ContractType::UnfreezeAssetContract => unpack!(tron_proto::UnfreezeAssetContract),
        ContractType::SetAccountIdContract => unpack!(tron_proto::SetAccountIdContract),
        ContractType::UpdateSettingContract => unpack!(tron_proto::UpdateSettingContract),
        ContractType::UpdateEnergyLimitContract => {
            unpack!(tron_proto::UpdateEnergyLimitContract)
        }
        ContractType::ClearAbiContract => unpack!(tron_proto::ClearAbiContract),
        ContractType::UpdateBrokerageContract => unpack!(tron_proto::UpdateBrokerageContract),
        ContractType::ExchangeCreateContract => unpack!(tron_proto::ExchangeCreateContract),
        ContractType::ExchangeInjectContract => unpack!(tron_proto::ExchangeInjectContract),
        ContractType::ExchangeWithdrawContract => {
            unpack!(tron_proto::ExchangeWithdrawContract)
        }
        ContractType::ExchangeTransactionContract => {
            unpack!(tron_proto::ExchangeTransactionContract)
        }
        ContractType::MarketSellAssetContract => unpack!(tron_proto::MarketSellAssetContract),
        ContractType::MarketCancelOrderContract => {
            unpack!(tron_proto::MarketCancelOrderContract)
        }
        ContractType::WithdrawExpireUnfreezeContract => {
            unpack!(tron_proto::WithdrawExpireUnfreezeContract)
        }
        ContractType::CancelAllUnfreezeV2Contract => {
            unpack!(tron_proto::CancelAllUnfreezeV2Contract)
        }
        ContractType::VoteAssetContract => unpack!(tron_proto::VoteAssetContract),
        // ShieldedTransfer is skipped by the caller; Custom/Get have no
        // owner shape.
        _ => return Err(()),
    };
    if bytes.len() != 21 {
        return Err(());
    }
    let mut buf = [0u8; 21];
    buf.copy_from_slice(&bytes);
    Ok(tron_crypto::address::Address::from_raw(buf))
}

/// Current head slot, used as `now_slot` for the windowed-average math.
/// Java-tron's `getHeadSlot()` =
/// `(latestBlockHeaderTimestamp - genesisBlockTimestamp) / BLOCK_PRODUCED_INTERVAL`.
///
/// This is **not** the block number: mainnet's genesis timestamp is 0, so a
/// head at ~1.75e12 ms yields a slot of ~5.8e8 — far above the ~8.3e7 block
/// height (the gap is every slot ever skipped). The per-account
/// `latest_consume_time(_for_energy)` values written by java-tron are in
/// these slot units, so the windowed-average decay must use the same formula
/// or it mixes unit systems and decays usage incorrectly.
fn head_slot(dyn_props_be: &tron_chainbase::DynamicPropertiesStore) -> i64 {
    dyn_props_be.head_slot()
}

/// Number of top witnesses (by vote) that share the per-block standby
/// reward pool — java-tron's standby-SR set size.
const STANDBY_WITNESS_COUNT: usize = 127;

/// Pick the top [`STANDBY_WITNESS_COUNT`] witnesses by `(vote_count desc,
/// address asc)`, returned in that order.
///
/// The comparator is a strict total order (witness addresses are unique
/// store keys → no ties), so this partial selection produces exactly the
/// same set and order as a full sort + truncate would — but it avoids
/// sorting the entire registered-witness candidate set (which can be
/// thousands of entries) on every single block. Pinned equal to the naive
/// sort in `standby_ranking_tests::top_standby_matches_full_sort`.
fn top_standby_witnesses(mut ranked: Vec<(Address, i64)>, sort_opt: bool) -> Vec<(Address, i64)> {
    // vote_count desc, then a tie-break gated on java
    // `allowWitnessSortOptimization()` (== `allowConsensusLogicOptimization()`,
    // proposal #88), exactly as `WitnessStore.sortWitnesses(list, isSortOpt)`:
    //   * flag ON  (post-#88) — `createReadableString` (hex) reversed, identical
    //     to address-bytes DESC;
    //   * flag OFF (pre-#88)  — `ByteString.hashCode()` DESC.
    // This per-block standby reward runs once `allowChangeDelegation` (#30) is
    // on, so a from-genesis sync exercises the OFF arm across the #30..#88
    // window, while a post-#88 snapshot only ever hits the ON arm. Mirrors the
    // gated active-SR sort in tron-consensus `update_active_witnesses` (shared
    // `bytestring_hash_code`).
    let cmp = |a: &(Address, i64), b: &(Address, i64)| {
        b.1.cmp(&a.1).then_with(|| {
            if sort_opt {
                b.0.as_bytes().cmp(a.0.as_bytes())
            } else {
                tron_consensus::bytestring_hash_code(b.0.as_bytes())
                    .cmp(&tron_consensus::bytestring_hash_code(a.0.as_bytes()))
            }
        })
    };
    // STABLE sort over the address-ascending input, then take the top 127 —
    // matching java's `Collections.sort` (TimSort) on the address-ordered
    // `getAllWitnesses()` list followed by `subList(0, 127)`. On a full tie
    // (vote_count AND the tie-break key both equal — possible only in the
    // flag-off `bytestring_hash_code` arm, which is not injective) a stable sort
    // keeps the lower-address witness ahead exactly as java does;
    // `select_nth_unstable` could reorder such a tie group across the 127
    // boundary and select a different subset.
    ranked.sort_by(cmp);
    ranked.truncate(STANDBY_WITNESS_COUNT);
    // java `getWitnessStandby` trims `voteCount < 1` AFTER taking the top
    // WITNESS_STANDBY_LENGTH — a zero/negative-vote witness that made the
    // top-127 earns no standby reward and must not dilute the per-vote split.
    // Benign on mainnet (vote counts are non-negative) but exact parity.
    ranked.retain(|(_, vote_count)| *vote_count >= 1);
    ranked
}

#[cfg(test)]
mod standby_ranking_tests {
    use super::{top_standby_witnesses, STANDBY_WITNESS_COUNT};
    use tron_crypto::address::Address;

    /// The pre-optimization ranking: full sort, truncate, then trim
    /// vote_count < 1 (java `getWitnessStandby`). Tie-break is address bytes
    /// DESCENDING (java's active `allowWitnessSortOptimization` hex-DESC
    /// tie-break), matching `top_standby_witnesses`.
    fn naive(mut v: Vec<(Address, i64)>) -> Vec<(Address, i64)> {
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| b.0.as_bytes().cmp(a.0.as_bytes())));
        v.truncate(STANDBY_WITNESS_COUNT);
        v.retain(|(_, vc)| *vc >= 1);
        v
    }

    fn addr(i: u32) -> Address {
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[1..5].copy_from_slice(&i.to_be_bytes());
        Address::from_raw(a)
    }

    #[test]
    fn top_standby_matches_full_sort() {
        // Cover counts below / at / above the 127 cutoff, with many ties on
        // vote_count (broken by the address tiebreak) to exercise the
        // boundary the partial selection has to reproduce exactly.
        for n in [0u32, 1, 50, 126, 127, 128, 200, 500] {
            let v: Vec<(Address, i64)> = (0..n)
                .map(|i| (addr(i), (i.wrapping_mul(2_654_435_761) % 37) as i64))
                .collect();
            assert_eq!(
                top_standby_witnesses(v.clone(), true),
                naive(v),
                "partial selection diverged from the full sort at n={n}"
            );
        }
    }

    #[test]
    fn tie_break_is_address_bytes_descending() {
        // On an exact vote_count tie, java's active witness-sort tie-break is
        // hex-string DESCENDING == address bytes DESCENDING, so the
        // higher-bytes address ranks first.
        let ranked = vec![(addr(1), 100i64), (addr(2), 100i64)];
        let out = top_standby_witnesses(ranked, true);
        assert_eq!(out[0].0, addr(2), "higher address bytes must rank first on a tie");
        assert_eq!(out[1].0, addr(1));
    }

    #[test]
    fn tie_break_pre_88_is_bytestring_hashcode_descending() {
        // With the #88 sort flag OFF (the from-genesis #30..#88 window), the
        // tie-break is java `ByteString.hashCode()` DESC, shared with
        // tron-consensus `update_active_witnesses`. The standby set must order a
        // vote_count tie the same way the active SR sort does.
        let a1 = addr(1);
        let a2 = addr(2);
        let out = top_standby_witnesses(vec![(a1, 100i64), (a2, 100i64)], false);
        let expected_first = if tron_consensus::bytestring_hash_code(a2.as_bytes())
            >= tron_consensus::bytestring_hash_code(a1.as_bytes())
        {
            a2
        } else {
            a1
        };
        assert_eq!(out[0].0, expected_first, "flag-off tie-break must be hashCode DESC");
    }
}
