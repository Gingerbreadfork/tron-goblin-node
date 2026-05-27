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
pub mod resource;

use std::sync::Arc;

use prost::Message;
use tron_actuator::{
    dispatch_execute, dispatch_validate, permission::check_transaction_permission, ActuatorError,
    ActuatorStores,
};
use tron_chainbase::{
    AbiStore, AccountIdIndexStore, AccountIndexStore, AccountStore, AssetIssueStore,
    AssetIssueV2Store, ContractStore, DelegatedResourceStore, DelegationStore,
    DynamicPropertiesStore, ExchangeStore, ExchangeV2Store, IncrementalMerkleTreeStore,
    KvBackend, MarketOrderStore, NullifierStore, ProposalStore, SessionBackend, VotesStore,
    WitnessStore,
};
use tron_crypto::hash::sha256;
use tron_proto::transaction::contract::ContractType;
use tron_proto::{Block, Transaction};
use tron_types::{
    block_id_from_block, verify_parent_link, verify_tx_trie_root, verify_witness_signature,
    BlockId, BlockValidateError,
};

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
        }
    }
}

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
    #[test]
    fn strict_mode_divides_fee_limit_by_energy_fee() {
        assert_eq!(compute_vm_energy_limit(1_000_000, 100, true), Ok(10_000));
        assert_eq!(compute_vm_energy_limit(100, 100, true), Ok(1));
        // Truncates toward zero (i.e. caller paid for partial energy
        // but doesn't get a full unit — matches java-tron's integer
        // division).
        assert_eq!(compute_vm_energy_limit(99, 100, true), Ok(0));
    }

    /// Strict mode rejects `fee_limit <= 0` (the proto default and the
    /// trivial misconfiguration). Mirrors java-tron's
    /// `validateFeeLimit` gate.
    #[test]
    fn strict_mode_rejects_zero_and_negative_fee_limit() {
        assert_eq!(
            compute_vm_energy_limit(0, 100, true),
            Err(TxOutcome::InvalidFeeLimit { fee_limit: 0 })
        );
        assert_eq!(
            compute_vm_energy_limit(-1, 100, true),
            Err(TxOutcome::InvalidFeeLimit { fee_limit: -1 })
        );
        assert_eq!(
            compute_vm_energy_limit(i64::MIN, 100, true),
            Err(TxOutcome::InvalidFeeLimit { fee_limit: i64::MIN })
        );
    }

    /// Lenient mode (`ExecConfig::unsigned()` / test fixtures): the
    /// fee_limit is ignored entirely and the historical 10M fallback
    /// is returned. Required so test fixtures built via
    /// `..Default::default()` (so `fee_limit = 0`) keep running.
    #[test]
    fn lenient_mode_always_returns_test_fallback() {
        assert_eq!(compute_vm_energy_limit(0, 100, false), Ok(TEST_FALLBACK_ENERGY_LIMIT));
        assert_eq!(compute_vm_energy_limit(-1, 100, false), Ok(TEST_FALLBACK_ENERGY_LIMIT));
        // Even a real-looking fee_limit is ignored in lenient mode —
        // the helper's job is to keep test fixtures predictable, not
        // to interpolate.
        assert_eq!(compute_vm_energy_limit(1_000_000, 100, false), Ok(TEST_FALLBACK_ENERGY_LIMIT));
    }

    /// Defensive clamp against a misconfigured `energy_fee = 0` (or
    /// negative). Division-by-zero would panic; the helper substitutes
    /// 1 sun/energy so the derived budget is large but finite.
    #[test]
    fn clamps_energy_fee_to_at_least_one() {
        // energy_fee = 0 → treated as 1 → energy_limit = fee_limit
        // (capped by MAX).
        assert_eq!(
            compute_vm_energy_limit(500, 0, true),
            Ok(500)
        );
        assert_eq!(
            compute_vm_energy_limit(500, -42, true),
            Ok(500)
        );
    }

    /// The safety ceiling fires when `fee_limit / energy_fee` would
    /// otherwise exceed 1B energy. Keeps the revm `u64` gas counter
    /// well within arithmetic safety bounds.
    #[test]
    fn safety_ceiling_caps_runaway_fee_limits() {
        // fee_limit = i64::MAX, energy_fee = 1 → would derive
        // i64::MAX-as-u64 = 9.2e18; expect clamp at 1B.
        assert_eq!(
            compute_vm_energy_limit(i64::MAX, 1, true),
            Ok(MAX_VM_ENERGY_LIMIT)
        );
        // Just over the ceiling → still clamped.
        let just_over = (MAX_VM_ENERGY_LIMIT + 1) as i64 * 100;
        assert_eq!(
            compute_vm_energy_limit(just_over, 100, true),
            Ok(MAX_VM_ENERGY_LIMIT)
        );
        // Exactly at the ceiling → returned unchanged.
        let at_cap = (MAX_VM_ENERGY_LIMIT as i64) * 100;
        assert_eq!(
            compute_vm_energy_limit(at_cap, 100, true),
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
    nullifiers: Arc<SessionBackend>,
    merkle_trees: Option<Arc<SessionBackend>>,
    /// EVM-side session-wrapped backends. `None` when the executor was
    /// built without EVM stores; VM-bound contracts then reject.
    code: Option<Arc<SessionBackend>>,
    storage_row: Option<Arc<SessionBackend>>,
    contract_state: Option<Arc<SessionBackend>>,
    block_index: Option<Arc<SessionBackend>>,
}

impl TxSession {
    fn fork(base: &StateBackends) -> Self {
        Self {
            accounts: Arc::new(SessionBackend::new(base.accounts.clone())),
            witnesses: Arc::new(SessionBackend::new(base.witnesses.clone())),
            votes: Arc::new(SessionBackend::new(base.votes.clone())),
            delegation: Arc::new(SessionBackend::new(base.delegation.clone())),
            delegated_resources: Arc::new(SessionBackend::new(base.delegated_resources.clone())),
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
        }
    }

    fn commit(&self) {
        self.accounts.commit();
        self.witnesses.commit();
        self.votes.commit();
        self.delegation.commit();
        self.delegated_resources.commit();
        self.dyn_props.commit();
        self.proposals.commit();
        self.name_index.commit();
        self.id_index.commit();
        self.asset_v1.commit();
        self.asset_v2.commit();
        self.contracts.commit();
        self.abi.commit();
        self.exchange_v1.commit();
        self.exchange_v2.commit();
        self.market_orders.commit();
        self.nullifiers.commit();
        if let Some(s) = &self.merkle_trees {
            s.commit();
        }
        if let Some(s) = &self.code {
            s.commit();
        }
        if let Some(s) = &self.storage_row {
            s.commit();
        }
        if let Some(s) = &self.contract_state {
            s.commit();
        }
        if let Some(s) = &self.block_index {
            s.commit();
        }
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
        self.nullifiers.revert();
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
    nullifiers: NullifierStore,
    merkle_trees: Option<IncrementalMerkleTreeStore>,
}

impl SessionStoreOwners {
    fn from_session(sess: &TxSession) -> Self {
        Self {
            accounts: AccountStore::new(sess.accounts.clone()),
            witnesses: WitnessStore::new(sess.witnesses.clone()),
            votes: VotesStore::new(sess.votes.clone()),
            delegation: DelegationStore::new(sess.delegation.clone()),
            delegated_resources: DelegatedResourceStore::new(sess.delegated_resources.clone()),
            dyn_props: DynamicPropertiesStore::new(sess.dyn_props.clone()),
            proposals: ProposalStore::new(sess.proposals.clone()),
            name_index: AccountIndexStore::new(sess.name_index.clone()),
            id_index: AccountIdIndexStore::new(sess.id_index.clone()),
            asset_v1: AssetIssueStore::new(sess.asset_v1.clone()),
            asset_v2: AssetIssueV2Store::new(sess.asset_v2.clone()),
            contracts: ContractStore::new(sess.contracts.clone()),
            abi: AbiStore::new(sess.abi.clone()),
            exchange_v1: ExchangeStore::new(sess.exchange_v1.clone()),
            exchange_v2: ExchangeV2Store::new(sess.exchange_v2.clone()),
            market_orders: MarketOrderStore::new(sess.market_orders.clone()),
            nullifiers: NullifierStore::new(sess.nullifiers.clone()),
            merkle_trees: sess
                .merkle_trees
                .as_ref()
                .map(|b| IncrementalMerkleTreeStore::new(b.clone())),
        }
    }

    fn as_actuator_stores(&self) -> ActuatorStores<'_> {
        ActuatorStores {
            accounts: &self.accounts,
            witnesses: &self.witnesses,
            votes: &self.votes,
            delegation: &self.delegation,
            delegated_resources: &self.delegated_resources,
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
            nullifiers: &self.nullifiers,
            merkle_trees: self.merkle_trees.as_ref(),
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
/// Backends the VM only READS (`dyn_props`, `witnesses`, `delegation`,
/// `block_index`, `contracts`) pass through unwrapped — nothing to
/// revert. The per-tx session's bandwidth + energy charge writes go
/// to the outer `TxSession` directly and survive regardless of
/// VM-side commit/revert (matches java-tron's "energy is paid even on
/// revert" rule).
struct VmSession {
    accounts: Arc<SessionBackend>,
    code: Arc<SessionBackend>,
    storage_row: Arc<SessionBackend>,
    contract_state: Arc<SessionBackend>,
    votes: Arc<SessionBackend>,
    delegated_resources: Arc<SessionBackend>,
}

impl VmSession {
    /// Wrap the per-tx session's VM-writeable backends in a fresh
    /// inner session. The four EVM-store handles (`code`, `storage`,
    /// `contract_state`) are required by the caller's gate above —
    /// `execute_vm_tx` rejects with `NotImplemented` if any of them
    /// is missing on the per-tx session.
    fn wrap(
        accounts: Arc<SessionBackend>,
        code: Arc<SessionBackend>,
        storage_row: Arc<SessionBackend>,
        contract_state: Arc<SessionBackend>,
        votes: Arc<SessionBackend>,
        delegated_resources: Arc<SessionBackend>,
    ) -> Self {
        Self {
            accounts: Arc::new(SessionBackend::new(accounts as Arc<dyn KvBackend>)),
            code: Arc::new(SessionBackend::new(code as Arc<dyn KvBackend>)),
            storage_row: Arc::new(SessionBackend::new(storage_row as Arc<dyn KvBackend>)),
            contract_state: Arc::new(SessionBackend::new(
                contract_state as Arc<dyn KvBackend>,
            )),
            votes: Arc::new(SessionBackend::new(votes as Arc<dyn KvBackend>)),
            delegated_resources: Arc::new(SessionBackend::new(
                delegated_resources as Arc<dyn KvBackend>,
            )),
        }
    }

    /// Flush every wrapped backend's pending writes into the per-tx
    /// session. Called once per VM frame on `VmOutcome::Success`.
    fn commit(&self) {
        self.accounts.commit();
        self.code.commit();
        self.storage_row.commit();
        self.contract_state.commit();
        self.votes.commit();
        self.delegated_resources.commit();
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
}

impl TxOutcome {
    pub fn is_success(&self) -> bool {
        matches!(self, TxOutcome::Success)
    }
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
    #[error("cross-store checkpoint flush failed: {0}")]
    Checkpoint(#[from] tron_chainbase::CheckpointError),
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
    execute_block_inner(state, block, expected_parent, None, None, &ExecConfig::default())
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
    execute_block_inner(state, block, expected_parent, None, None, config)
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
    execute_block_inner(state, block, expected_parent, Some(undo_store), None, &ExecConfig::default())
}

/// As [`execute_block_with_undo`], but with an explicit `ExecConfig`.
pub fn execute_block_with_undo_and_config(
    state: &StateBackends,
    block: &Block,
    expected_parent: Option<BlockId>,
    undo_store: &tron_chainbase::BlockUndoStore,
    config: &ExecConfig,
) -> Result<BlockExecutionReport, BlockExecError> {
    execute_block_inner(state, block, expected_parent, Some(undo_store), None, config)
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
) -> Result<BlockExecutionReport, BlockExecError> {
    execute_block_inner(
        state,
        block,
        expected_parent,
        Some(undo_store),
        Some(checkpoint),
        config,
    )
}

fn execute_block_inner(
    state: &StateBackends,
    block: &Block,
    expected_parent: Option<BlockId>,
    undo_store: Option<&tron_chainbase::BlockUndoStore>,
    checkpoint: Option<&tron_chainbase::CheckPointV2>,
    config: &ExecConfig,
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
        let block_session = BlockSession::wrap(state);
        let wrapped = block_session.as_state_backends();
        let report = execute_block_logic(&wrapped, block, expected_parent, config)?;
        let record = if let Some(checkpoint) = checkpoint {
            block_session
                .commit_with_checkpoint_and_undo(checkpoint, state)
                .map_err(BlockExecError::Checkpoint)?
        } else {
            block_session.commit_with_undo()
        };
        let block_num = block
            .block_header
            .as_ref()
            .and_then(|h| h.raw_data.as_ref())
            .map(|r| r.number)
            .unwrap_or(0);
        undo_store.put(block_num, &record);
        return Ok(report);
    }
    execute_block_logic(state, block, expected_parent, config)
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
    nullifiers: Arc<SessionBackend>,
    merkle_trees: Option<Arc<SessionBackend>>,
    code: Option<Arc<SessionBackend>>,
    storage_row: Option<Arc<SessionBackend>>,
    contract_state: Option<Arc<SessionBackend>>,
    block_index: Option<Arc<SessionBackend>>,
    witness_schedule: Option<Arc<SessionBackend>>,
}

impl BlockSession {
    fn wrap(state: &StateBackends) -> Self {
        Self {
            accounts: Arc::new(SessionBackend::new(state.accounts.clone())),
            witnesses: Arc::new(SessionBackend::new(state.witnesses.clone())),
            votes: Arc::new(SessionBackend::new(state.votes.clone())),
            delegation: Arc::new(SessionBackend::new(state.delegation.clone())),
            delegated_resources: Arc::new(SessionBackend::new(state.delegated_resources.clone())),
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
        }
    }

    /// Commit every store's overlay to its base backend, capturing
    /// `(store_id, key, before_image)` triples for each write. The
    /// result is one [`BlockUndoRecord`] suitable for persistence.
    fn commit_with_undo(self) -> tron_chainbase::BlockUndoRecord {
        use tron_chainbase::UndoStoreId as Id;
        let mut record = tron_chainbase::BlockUndoRecord::new();
        let mut push = |id: Id, undo: Vec<(Vec<u8>, Option<Vec<u8>>)>| {
            for (key, before) in undo {
                record.push(tron_chainbase::UndoEntry { store: id, key, before });
            }
        };
        push(Id::Accounts, self.accounts.commit_with_undo());
        push(Id::Witnesses, self.witnesses.commit_with_undo());
        push(Id::Votes, self.votes.commit_with_undo());
        push(Id::Delegation, self.delegation.commit_with_undo());
        push(Id::DelegatedResources, self.delegated_resources.commit_with_undo());
        push(Id::DynProps, self.dyn_props.commit_with_undo());
        push(Id::Proposals, self.proposals.commit_with_undo());
        push(Id::NameIndex, self.name_index.commit_with_undo());
        push(Id::IdIndex, self.id_index.commit_with_undo());
        push(Id::AssetV1, self.asset_v1.commit_with_undo());
        push(Id::AssetV2, self.asset_v2.commit_with_undo());
        push(Id::Contracts, self.contracts.commit_with_undo());
        push(Id::Abi, self.abi.commit_with_undo());
        push(Id::ExchangeV1, self.exchange_v1.commit_with_undo());
        push(Id::ExchangeV2, self.exchange_v2.commit_with_undo());
        push(Id::MarketOrders, self.market_orders.commit_with_undo());
        push(Id::Nullifiers, self.nullifiers.commit_with_undo());
        if let Some(s) = self.merkle_trees {
            push(Id::MerkleTrees, s.commit_with_undo());
        }
        if let Some(s) = self.code {
            push(Id::Code, s.commit_with_undo());
        }
        if let Some(s) = self.storage_row {
            push(Id::StorageRow, s.commit_with_undo());
        }
        if let Some(s) = self.contract_state {
            push(Id::ContractState, s.commit_with_undo());
        }
        if let Some(s) = self.block_index {
            push(Id::BlockIndex, s.commit_with_undo());
        }
        if let Some(s) = self.witness_schedule {
            push(Id::WitnessSchedule, s.commit_with_undo());
        }
        record
    }

    /// Commit every store's overlay to its base backend under one
    /// cross-store atomicity boundary: the [`CheckPointV2`] manifest.
    ///
    /// Mirrors java-tron's `SnapshotManager.flush`:
    ///   1. Drain each session into per-store `(ops, undo_pairs)`.
    ///   2. Build a flat manifest of every `(db_name, key, value)`.
    ///   3. Atomically write the manifest (tmp + rename + fsync).
    ///   4. Apply each per-store `write_batch` against the base
    ///      backend (skipping the session overlay — we already
    ///      drained it).
    ///   5. Delete the checkpoint.
    ///
    /// If the process crashes between (3) and (4) — or between (4)
    /// and (5) — the next startup runs [`replay_checkpoints`] which
    /// re-applies the manifest entries and deletes the checkpoint.
    /// (3)→(4) is the critical window: the manifest gives us a
    /// durable, atomic record of *all* the writes the block intended,
    /// so re-applying it restores the cross-store invariant. The
    /// (4)→(5) replay is harmless — re-applying writes that already
    /// landed produces the same state.
    fn commit_with_checkpoint_and_undo(
        self,
        checkpoint: &tron_chainbase::CheckPointV2,
        state: &StateBackends,
    ) -> Result<tron_chainbase::BlockUndoRecord, tron_chainbase::CheckpointError> {
        use tron_chainbase::{CheckpointEntry, KvBackend, UndoStoreId as Id, WriteOp};

        // (1) Drain every per-store session, capturing pre-images for
        //     undo. Pair each batch with the BASE backend we'll write
        //     it to in step (4). Order matters only for replay
        //     determinism; we use the variant order of StoreId.
        let mut drained: Vec<(Id, Arc<dyn KvBackend>, Vec<WriteOp>, Vec<(Vec<u8>, Option<Vec<u8>>)>)> = Vec::new();
        let mut take = |id: Id,
                        session: Arc<tron_chainbase::SessionBackend>,
                        base: Arc<dyn KvBackend>| {
            let (ops, undo) = session.drain_pending_with_undo();
            if !ops.is_empty() {
                drained.push((id, base, ops, undo));
            }
        };
        take(Id::Accounts, self.accounts, state.accounts.clone());
        take(Id::Witnesses, self.witnesses, state.witnesses.clone());
        take(Id::Votes, self.votes, state.votes.clone());
        take(Id::Delegation, self.delegation, state.delegation.clone());
        take(Id::DelegatedResources, self.delegated_resources, state.delegated_resources.clone());
        take(Id::DynProps, self.dyn_props, state.dyn_props.clone());
        take(Id::Proposals, self.proposals, state.proposals.clone());
        take(Id::NameIndex, self.name_index, state.name_index.clone());
        take(Id::IdIndex, self.id_index, state.id_index.clone());
        take(Id::AssetV1, self.asset_v1, state.asset_v1.clone());
        take(Id::AssetV2, self.asset_v2, state.asset_v2.clone());
        take(Id::Contracts, self.contracts, state.contracts.clone());
        take(Id::Abi, self.abi, state.abi.clone());
        take(Id::ExchangeV1, self.exchange_v1, state.exchange_v1.clone());
        take(Id::ExchangeV2, self.exchange_v2, state.exchange_v2.clone());
        take(Id::MarketOrders, self.market_orders, state.market_orders.clone());
        take(Id::Nullifiers, self.nullifiers, state.nullifiers.clone());
        if let (Some(s), Some(b)) = (self.merkle_trees, state.merkle_trees.clone()) {
            take(Id::MerkleTrees, s, b);
        }
        if let (Some(s), Some(b)) = (self.code, state.code.clone()) {
            take(Id::Code, s, b);
        }
        if let (Some(s), Some(b)) = (self.storage_row, state.storage_row.clone()) {
            take(Id::StorageRow, s, b);
        }
        if let (Some(s), Some(b)) = (self.contract_state, state.contract_state.clone()) {
            take(Id::ContractState, s, b);
        }
        if let (Some(s), Some(b)) = (self.block_index, state.block_index.clone()) {
            take(Id::BlockIndex, s, b);
        }
        if let (Some(s), Some(b)) = (self.witness_schedule, state.witness_schedule.clone()) {
            take(Id::WitnessSchedule, s, b);
        }

        // (2) Build the manifest. Empty block? Skip the manifest
        //     write entirely — there's nothing to make atomic and no
        //     point creating a checkpoint dir we'll immediately delete.
        let mut record = tron_chainbase::BlockUndoRecord::new();
        if drained.is_empty() {
            return Ok(record);
        }
        let mut entries: Vec<CheckpointEntry> = Vec::new();
        for (id, _, ops, _) in &drained {
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
        //     backend (not the drained session) and uses the parent's
        //     `write_batch` — RocksDB native WriteBatch under the hood.
        for (id, base, ops, undo) in drained {
            base.write_batch(&ops);
            for (key, before) in undo {
                record.push(tron_chainbase::UndoEntry { store: id, key, before });
            }
        }

        // (5) All per-store writes succeeded; the checkpoint is no
        //     longer needed. A crash here just leaves the dir for the
        //     next startup to replay idempotently.
        checkpoint.delete(checkpoint_id)?;
        Ok(record)
    }
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
    by_name.insert(Id::Nullifiers.db_name(), state.nullifiers.clone());
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
                    Some(v) => backend.put(&entry.key, v),
                    None => backend.delete(&entry.key),
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
        };
        match &entry.before {
            Some(v) => backend.put(&entry.key, v),
            None => backend.delete(&entry.key),
        }
    }
    undo_store.delete(block_num);
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
) -> Result<BlockExecutionReport, BlockExecError> {
    // === 1. Structural validation (read-only; safe to use base directly) ===
    if let Some(parent) = expected_parent {
        verify_parent_link(block, parent)?;
    }
    verify_tx_trie_root(block)?;
    // Witness-signature gate. `config.require_signature` defaults to
    // `true`; the block-production dry-run path (and a few tests that
    // build synthetic unsigned blocks) opt out via `ExecConfig::unsigned`.
    // The underlying `verify_witness_signature` returns
    // `BlockValidateError::MissingSignature` on an empty `witness_signature`
    // — so under strict mode an unsigned block is rejected here, not
    // silently applied.
    if config.require_signature {
        verify_witness_signature(block, None)?;
    }

    // Lift the header out once — needed both by the per-tx loop (for
    // `block_timestamp`, the reference frame for expiration checks) and
    // by the head-pointer update in step 3.
    let block_id = block_id_from_block(block).map_err(|_| BlockExecError::NoHeader)?;
    let header = block.block_header.as_ref().ok_or(BlockExecError::NoHeader)?;
    let raw = header.raw_data.as_ref().ok_or(BlockExecError::NoHeader)?;
    let block_timestamp_ms = raw.timestamp;

    // === 2. Per-tx atomic loop ===
    let mut tx_results = Vec::with_capacity(block.transactions.len());
    for tx in &block.transactions {
        tx_results.push(execute_one_tx(state, tx, config, block_timestamp_ms));
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
                ws.put(&addr, &w);
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
            let prev_ts = prev_block_ts.unwrap();
            // Absolute-slot calculation mirrors `DposSlot.getAbSlot`.
            let prev_abs = (prev_ts - genesis_ts) / BLOCK_INTERVAL_MS;
            let this_abs = (raw.timestamp - genesis_ts) / BLOCK_INTERVAL_MS;
            // For every slot strictly between the prev producer's
            // slot and this block's slot, look up the scheduled SR.
            // The scheduled-index formula mirrors `DposSlot
            // .getScheduledWitness` — `((slot - 1) % N)` where N is
            // the active witness count (SINGLE_REPEAT == 1 today).
            for missed_slot in (prev_abs + 1)..this_abs {
                if missed_slot < 1 {
                    continue;
                }
                let idx = ((missed_slot - 1).rem_euclid(active_witnesses.len() as i64))
                    as usize;
                let missed_addr = active_witnesses[idx];
                if let Ok(Some(mut w)) = ws.get(&missed_addr) {
                    w.total_missed = w.total_missed.saturating_add(1);
                    ws.put(&missed_addr, &w);
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

        // 5c-i. Block-production reward to the producer.
        let block_pay = dp.witness_pay_per_block();
        if block_pay > 0 {
            let _ = tron_tvm::reward::pay_block_reward(
                &accts, &dlg, &dp, &producer, block_pay,
            );
        }

        // 5c-ii. Standby pool distribution to top-127 by vote_count.
        // We use the WitnessStore::all() scan because the standby set
        // is independent of the active witness rotation (which is
        // capped at 27).
        let standby_pay = dp.witness_127_pay_per_block();
        if standby_pay > 0 {
            let ws = WitnessStore::new(state.witnesses.clone());
            if let Ok(mut by_vote) = ws.all() {
                let mut ranked: Vec<(Address, i64)> =
                    by_vote.drain(..).map(|(a, w)| (a, w.vote_count)).collect();
                ranked.sort_by(|a, b| {
                    b.1.cmp(&a.1).then_with(|| a.0.as_bytes().cmp(b.0.as_bytes()))
                });
                ranked.truncate(127);
                let _ =
                    tron_tvm::reward::pay_standby_witness(&accts, &dlg, &dp, &ranked);
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
    let maintenance_interval = dp
        .maintenance_time_interval()
        .unwrap_or(tron_consensus::DEFAULT_MAINTENANCE_INTERVAL_MS);
    let next_maintenance = dp.next_maintenance_time().unwrap_or(0);
    let mut maintenance_rotation: Option<MaintenanceRotation> = None;
    if tron_consensus::is_maintenance_boundary(raw.timestamp, next_maintenance) {
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
                }
            }
        }
        // Always advance next_maintenance_time past this block.
        let new_next = tron_consensus::compute_next_maintenance_time(
            raw.timestamp,
            next_maintenance.max(raw.timestamp), // first-time init
            maintenance_interval,
        );
        dp.save_next_maintenance_time(new_next);
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
        let computed = compute_state_root(state);
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
    )?;
    let root = compute_state_root(state);
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

pub fn compute_state_root(state: &StateBackends) -> [u8; 32] {
    use tron_crypto::address::Address;
    use tron_proto::Account;

    let storage_lookup = |addr: &Address| -> Option<[u8; 32]> {
        let rows_be = state.storage_row.as_ref()?;
        let rows = tron_chainbase::StorageRowStore::new(rows_be.clone())
            .scan_for_contract(addr);
        if rows.is_empty() {
            None
        } else {
            let rows_owned: Vec<([u8; 32], Vec<u8>)> =
                rows.into_iter().map(|(k, v)| (k, v)).collect();
            Some(tron_types::compute_storage_root(&rows_owned))
        }
    };

    let mut accounts: Vec<(Address, Account)> = Vec::new();
    for (key, value) in state.accounts.scan_all() {
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
    tron_types::compute_account_state_root_with_storage(&accounts, storage_lookup)
}

fn execute_one_tx(
    state: &StateBackends,
    tx: &Transaction,
    config: &ExecConfig,
    block_timestamp_ms: i64,
) -> TxResult {
    // Fork a fresh session for this tx — any writes here are confined
    // until we commit. Failed txs revert; the next tx starts fresh.
    let session = TxSession::fork(state);
    let owners = SessionStoreOwners::from_session(&session);
    let stores = owners.as_actuator_stores();

    let Some(raw) = &tx.raw_data else {
        // No state to revert — session is still empty.
        return TxResult {
            tx_id: [0u8; 32],
            contract_type: None,
            outcome: TxOutcome::MissingRawData,
                    internal_transactions: Vec::new(),
                    vm_logs: Vec::new(),
        };
    };
    let tx_id = sha256(&raw.encode_to_vec());

    // === Expiration check. ===
    //
    // Reject any tx whose `raw_data.expiration` has already passed AS OF
    // the block we're applying it under. The mempool path already
    // performs this check at submit time against wall-clock — but a
    // block we received from a peer (sync path) didn't go through the
    // mempool, so without this gate a stale, signed transaction could
    // be replayed inside a block at any time.
    //
    // Compared against the BLOCK timestamp (not wall-clock) so the
    // outcome is deterministic across replays of the same block and
    // matches what every other node will compute. `expiration == 0` is
    // the "unset" sentinel java-tron uses and we leave it untouched.
    if raw.expiration > 0 && raw.expiration <= block_timestamp_ms {
        // No state was mutated — the session is fresh, no revert needed.
        return TxResult {
            tx_id,
            contract_type: None,
            outcome: TxOutcome::Expired {
                expiration_ms: raw.expiration,
                block_timestamp_ms,
            },
            internal_transactions: Vec::new(),
            vm_logs: Vec::new(),
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
                    internal_transactions: Vec::new(),
                    vm_logs: Vec::new(),
        };
    };

    let ty = match ContractType::try_from(contract.r#type) {
        Ok(t) => t,
        Err(_) => {
            return TxResult {
                tx_id,
                contract_type: None,
                outcome: TxOutcome::UnknownContractType(contract.r#type),
                            internal_transactions: Vec::new(),
                    vm_logs: Vec::new(),
            }
        }
    };

    let Some(parameter) = &contract.parameter else {
        return TxResult {
            tx_id,
            contract_type: Some(ty),
            outcome: TxOutcome::MissingParameter,
                    internal_transactions: Vec::new(),
                    vm_logs: Vec::new(),
        };
    };

    // Sighash is only meaningful for shielded transactions; for every
    // other contract type the actuators ignore the field. Mirrors
    // java-tron, which only calls `getShieldTransactionHashIgnore...`
    // when dispatching ShieldedTransferContract.
    let tx_ctx = if matches!(ty, ContractType::ShieldedTransferContract) {
        let dp = tron_chainbase::DynamicPropertiesStore::new(state.dyn_props.clone());
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
        if let Err(e) =
            check_transaction_permission(stores.accounts, stores.dyn_props, tx, contract, ty)
        {
            session.revert();
            return TxResult {
                tx_id,
                contract_type: Some(ty),
                outcome: TxOutcome::Invalid(ActuatorError::PermissionDenied(e.to_string())),
                            internal_transactions: Vec::new(),
                    vm_logs: Vec::new(),
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
            let now_slot = head_slot(stores.dyn_props);
            let bw_stores = bandwidth::BandwidthStores {
                accounts: stores.accounts,
                dyn_props: stores.dyn_props,
                asset_v1: stores.asset_v1,
                asset_v2: stores.asset_v2,
            };
            if let Err(e) =
                bandwidth::consume_bandwidth(bw_stores, tx, contract, &owner, now_slot)
            {
                session.revert();
                return TxResult {
                    tx_id,
                    contract_type: Some(ty),
                    outcome: TxOutcome::Invalid(ActuatorError::PermissionDenied(format!(
                        "bandwidth: {e}"
                    ))),
                                    internal_transactions: Vec::new(),
                    vm_logs: Vec::new(),
                };
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
        return execute_vm_tx(&session, tx_id, ty, parameter, config, raw.fee_limit);
    }

    // Validate. On reject: revert (drops any pending writes — though
    // validate shouldn't write, this is defence in depth) and report.
    if let Err(e) = dispatch_validate(&stores, &tx_ctx, ty, parameter) {
        session.revert();
        return TxResult {
            tx_id,
            contract_type: Some(ty),
            outcome: TxOutcome::Invalid(e),
                    internal_transactions: Vec::new(),
                    vm_logs: Vec::new(),
        };
    }

    // Execute. On success: commit the session. On failure: revert
    // (this is the bit that fixes the old v1 limitation — partial
    // state mutations from a failed execute are NOT applied).
    match dispatch_execute(&stores, &tx_ctx, ty, parameter) {
        Ok(_result) => {
            session.commit();
            TxResult {
                tx_id,
                contract_type: Some(ty),
                outcome: TxOutcome::Success,
                            internal_transactions: Vec::new(),
                    vm_logs: Vec::new(),
            }
        }
        Err(e) => {
            session.revert();
            TxResult {
                tx_id,
                contract_type: Some(ty),
                outcome: TxOutcome::ExecutionFailed(e),
                            internal_transactions: Vec::new(),
                    vm_logs: Vec::new(),
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
/// Returns `Err(TxOutcome::InvalidFeeLimit { .. })` when strict mode
/// is on and `fee_limit <= 0` (matches java-tron's `validateFeeLimit`
/// gate; the proto default of 0 is rejected). Returns
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
    require_fee_limit: bool,
) -> Result<u64, TxOutcome> {
    if !require_fee_limit {
        return Ok(TEST_FALLBACK_ENERGY_LIMIT);
    }
    if fee_limit <= 0 {
        return Err(TxOutcome::InvalidFeeLimit { fee_limit });
    }
    let divisor = energy_fee.max(1) as u64;
    let derived = (fee_limit as u64) / divisor;
    Ok(derived.min(MAX_VM_ENERGY_LIMIT))
}

fn execute_vm_tx(
    session: &TxSession,
    tx_id: [u8; 32],
    ty: ContractType,
    parameter: &prost_types::Any,
    config: &ExecConfig,
    fee_limit: i64,
) -> TxResult {
    use tron_chainbase::{
        BlockIndexStore as BIS, CodeStore as CS, ContractStateStore as CtS,
        ContractStore as ConS, DelegatedResourceStore as DRS, DelegationStore as DelS,
        DynamicPropertiesStore as DPS, StorageRowStore as SRS, WitnessStore as WS,
    };

    // Require all four EVM-side stores; if any is missing we can't
    // safely run the VM.
    let (Some(code), Some(storage), Some(contract_state)) = (
        session.code.as_ref(),
        session.storage_row.as_ref(),
        session.contract_state.as_ref(),
    ) else {
        session.revert();
        return TxResult {
            tx_id,
            contract_type: Some(ty),
            outcome: TxOutcome::Invalid(ActuatorError::NotImplemented(
                "VM-bound contract but executor was built without EVM stores attached",
            )),
                    internal_transactions: Vec::new(),
                    vm_logs: Vec::new(),
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
        session.accounts.clone(),
        code.clone(),
        storage.clone(),
        contract_state.clone(),
        session.votes.clone(),
        session.delegated_resources.clone(),
    );

    let vm_stores = tron_tvm::execute::VmStores {
        accounts: Arc::new(AccountStore::new(vm_session.accounts.clone() as _)),
        code: Arc::new(CS::new(vm_session.code.clone() as _)),
        storage: Arc::new(SRS::new(vm_session.storage_row.clone() as _)),
        witnesses: Arc::new(WS::new(session.witnesses.clone() as _)),
        contract_state: Arc::new(CtS::new(vm_session.contract_state.clone() as _)),
        dynamic_properties: Arc::new(DPS::new(session.dyn_props.clone() as _)),
        delegated_resources: Arc::new(DRS::new(vm_session.delegated_resources.clone() as _)),
        delegation: Arc::new(DelS::new(session.delegation.clone() as _)),
        // Attach BlockIndexStore so BLOCKHASH(n) returns real hashes
        // for the last 256 blocks (when the backend is configured).
        // Read-only from the VM's perspective — no inner-session
        // wrapping needed.
        block_index: session
            .block_index
            .as_ref()
            .map(|b| Arc::new(BIS::new(b.clone() as _))),
        // ContractStore lets the v1/v2 storage-key layout selector
        // read SmartContract.version. Read-only from the VM.
        contracts: Some(Arc::new(ConS::new(session.contracts.clone() as _))),
        // VotesStore feeds the VOTEWITNESS opcode bridge, which DOES
        // write (the corresponding `accounts` row plus the votes
        // row). Routed through the inner session so a reverted VM
        // frame doesn't leave votes persisted.
        votes: Some(Arc::new(VotesStore::new(vm_session.votes.clone() as _))),
    };

    // Read current block number/time from the dyn-props session (so we
    // see this block's header if it's been written; otherwise the last
    // committed one).
    let dp = DPS::new(session.dyn_props.clone() as _);
    let block_number = dp.latest_block_header_number().unwrap_or(0);
    let block_timestamp_ms = dp.latest_block_header_timestamp().unwrap_or(0);

    let energy_limit = match compute_vm_energy_limit(
        fee_limit,
        dp.energy_fee(),
        config.require_fee_limit,
    ) {
        Ok(limit) => limit,
        Err(reason) => {
            session.revert();
            return TxResult {
                tx_id,
                contract_type: Some(ty),
                outcome: reason,
                internal_transactions: Vec::new(),
                vm_logs: Vec::new(),
            };
        }
    };

    let block_env = tron_tvm::execute::VmBlockEnv {
        block_number,
        block_timestamp_ms,
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
    let now_slot = dp.latest_block_header_number().unwrap_or(0);

    let (caller_addr, trigger_contract_addr, outcome, vm_traces) = match ty {
        ContractType::TriggerSmartContract => {
            let trigger: tron_proto::TriggerSmartContract =
                match prost::Message::decode(parameter.value.as_slice()) {
                    Ok(t) => t,
                    Err(e) => {
                        session.revert();
                        return TxResult {
                            tx_id,
                            contract_type: Some(ty),
                            outcome: TxOutcome::Invalid(ActuatorError::Store(format!(
                                "decode TriggerSmartContract: {e}"
                            ))),
                                                    internal_transactions: Vec::new(),
                    vm_logs: Vec::new(),
                        };
                    }
                };
            let caller = address_from_proto(&trigger.owner_address);
            let contract_addr = address_from_proto(&trigger.contract_address);
            let (outcome, traces) = tron_tvm::execute::execute_trigger_with_trace(
                &vm_stores,
                block_env,
                &trigger,
                energy_limit,
            );
            (caller, contract_addr, outcome, traces)
        }
        ContractType::CreateSmartContract => {
            let create: tron_proto::CreateSmartContract =
                match prost::Message::decode(parameter.value.as_slice()) {
                    Ok(c) => c,
                    Err(e) => {
                        session.revert();
                        return TxResult {
                            tx_id,
                            contract_type: Some(ty),
                            outcome: TxOutcome::Invalid(ActuatorError::Store(format!(
                                "decode CreateSmartContract: {e}"
                            ))),
                                                    internal_transactions: Vec::new(),
                    vm_logs: Vec::new(),
                        };
                    }
                };
            // Caller for CreateSmartContract lives on the inner
            // `new_contract.origin_address`.
            let caller = create
                .new_contract
                .as_ref()
                .and_then(|c| address_from_proto(&c.origin_address));
            let (outcome, traces) = tron_tvm::execute::execute_create_with_trace(
                &vm_stores,
                block_env,
                &create,
                &tx_id,
                energy_limit,
            );
            // CreateSmartContract: caller IS the origin, so no origin
            // split applies. Pass `None` for the contract address so
            // the energy-charge path takes the caller-pays-all branch.
            (caller, None, outcome, traces)
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
    match &outcome {
        tron_tvm::execute::VmOutcome::Success { .. } => vm_session.commit(),
        _ => vm_session.revert(),
    }

    // Charge energy for the caller. java-tron does this in
    // `TransactionTrace.pay()` after the VM finishes. Even on revert
    // the energy that ran is still charged — that's the consensus rule.
    //
    // If the caller isn't recoverable from the proto (malformed
    // address) we skip the charge — the tx would have hit a preflight
    // error inside the VM and the outcome arm below will reject it.
    let (energy_used, vm_succeeded) = match &outcome {
        tron_tvm::execute::VmOutcome::Success { energy_used, .. } => (*energy_used, true),
        tron_tvm::execute::VmOutcome::Revert { energy_used, .. } => (*energy_used, false),
        tron_tvm::execute::VmOutcome::Halt { energy_used, .. } => (*energy_used, false),
        _ => (0, false),
    };
    if let Some(caller) = caller_addr {
        if energy_used > 0 {
            let accounts = AccountStore::new(session.accounts.clone() as _);
            let dp_store = DynamicPropertiesStore::new(session.dyn_props.clone() as _);
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
                    let contracts = ConS::new(session.contracts.clone() as _);
                    match contracts.get(&contract_addr) {
                        Ok(Some(sc)) => {
                            let origin = address_from_proto(&sc.origin_address);
                            (
                                origin,
                                sc.consume_user_resource_percent,
                                sc.origin_energy_limit,
                            )
                        }
                        _ => (None, 0, 0),
                    }
                }
                None => (None, 0, 0),
            };
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
                Ok(_bill) => { /* state updated in-place */ }
                Err(e) => {
                    // Insufficient balance for fee, or account missing.
                    // Whole session reverts (which also undoes any VM
                    // state changes AND any origin-side debit
                    // `pay_energy_bill` may have applied before
                    // hitting the caller-side shortfall); tx marked
                    // as failed.
                    session.revert();
                    return TxResult {
                        tx_id,
                        contract_type: Some(ty),
                        outcome: TxOutcome::ExecutionFailed(ActuatorError::Store(format!(
                            "energy: {e}"
                        ))),
                                            internal_transactions: Vec::new(),
                    vm_logs: Vec::new(),
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

    match outcome {
        tron_tvm::execute::VmOutcome::Success { logs, .. } => {
            let _ = vm_succeeded;
            session.commit();
            TxResult {
                tx_id,
                contract_type: Some(ty),
                outcome: TxOutcome::Success,
                internal_transactions: proto_internal_txs,
                vm_logs: logs,
            }
        }
        tron_tvm::execute::VmOutcome::Revert { .. } => {
            // VM-side writes were already discarded by `vm_session.revert()`
            // above (the inner nested-session layer). All that remains
            // in the per-tx session is bandwidth (charged before the
            // VM) and the energy charge that `pay_energy_bill` applied
            // afterwards — both of which java-tron's consensus rule
            // says must survive a revert. `session.commit()` flushes
            // exactly those into the per-tx parent.
            session.commit();
            TxResult {
                tx_id,
                contract_type: Some(ty),
                outcome: TxOutcome::ExecutionFailed(ActuatorError::Store(
                    "VM revert".to_string(),
                )),
                internal_transactions: proto_internal_txs,
                vm_logs: Vec::new(),
            }
        }
        tron_tvm::execute::VmOutcome::Halt { reason, .. } => {
            session.commit();
            TxResult {
                tx_id,
                contract_type: Some(ty),
                outcome: TxOutcome::ExecutionFailed(ActuatorError::Store(format!(
                    "VM halt: {reason}"
                ))),
                internal_transactions: proto_internal_txs,
                vm_logs: Vec::new(),
            }
        }
        tron_tvm::execute::VmOutcome::CallTokenIgnored { .. } => {
            session.revert();
            TxResult {
                tx_id,
                contract_type: Some(ty),
                outcome: TxOutcome::Invalid(ActuatorError::NotImplemented(
                    "CALLTOKEN opcode (TRC-10 transfer) — requires revm fork",
                )),
                internal_transactions: Vec::new(),
                    vm_logs: Vec::new(),
            }
        }
        tron_tvm::execute::VmOutcome::PreflightError(msg) => {
            session.revert();
            TxResult {
                tx_id,
                contract_type: Some(ty),
                outcome: TxOutcome::Invalid(ActuatorError::Store(msg)),
                internal_transactions: proto_internal_txs,
                vm_logs: Vec::new(),
            }
        }
        // Timeout is only produced by read-only RPC paths
        // (`execute_trigger_with_deadline`) that don't go through the
        // block executor. If somehow surfaced here it indicates a
        // wiring mistake — treat it as an execution failure so the tx
        // is rejected rather than silently committed.
        tron_tvm::execute::VmOutcome::Timeout { deadline_ms, .. } => {
            session.revert();
            TxResult {
                tx_id,
                contract_type: Some(ty),
                outcome: TxOutcome::ExecutionFailed(ActuatorError::Store(format!(
                    "VM timeout ({deadline_ms}ms) — not expected on block-apply path"
                ))),
                internal_transactions: proto_internal_txs,
                vm_logs: Vec::new(),
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
) {
    use tron_crypto::address::Address;
    use tron_proto::{Account, AccountType, Witness};

    let accounts = AccountStore::new(state.accounts.clone());
    let name_index = AccountIndexStore::new(state.name_index.clone());
    let witnesses_store = WitnessStore::new(state.witnesses.clone());

    for asset in assets {
        let addr = Address::from_raw(asset.address);
        let existing = accounts.get(&addr).ok().flatten();
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
        accounts.put(&addr, &acct);
        // Mirror java-tron's `Manager.initAccount`: also populate the
        // `account-index` store (name → address) so `getAccountByName`
        // works on genesis accounts. java-tron's
        // `AccountIndexStore.put(AccountCapsule)` writes
        // unconditionally; we skip when name is empty to avoid an
        // empty-key entry. AccountIdIndexStore (id → address) is not
        // populated at genesis — assets don't carry an accountId in
        // mainnet config.conf; the id only gets set via `setAccountId`.
        if !asset.name.is_empty() {
            name_index.put(asset.name.as_bytes(), &addr);
        }
    }

    for w in witnesses {
        let addr = Address::from_raw(w.address);
        let mut acct = accounts.get(&addr).ok().flatten().unwrap_or(Account {
            address: w.address.to_vec(),
            balance: 0,
            // java-tron uses `AccountType::AssetIssue` for an
            // auto-created witness; mirrors that.
            r#type: AccountType::AssetIssue as i32,
            ..Default::default()
        });
        acct.is_witness = true;
        accounts.put(&addr, &acct);

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
        witnesses_store.put(&addr, &witness);
    }
}

// =============================================================================
// Bandwidth helpers
// =============================================================================

/// Pull the owner address from a contract for bandwidth charging.
/// Returns `Err(())` for contract types that have no obvious owner
/// (in which case the caller skips the charge).
fn extract_owner_for_bandwidth(
    contract: &tron_proto::transaction::Contract,
    ty: ContractType,
) -> Result<tron_crypto::address::Address, ()> {
    let parameter = contract.parameter.as_ref().ok_or(())?;
    macro_rules! unpack {
        ($T:ty) => {{
            let c = <$T as prost::Message>::decode(parameter.value.as_slice()).map_err(|_| ())?;
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
/// Java-tron's `getHeadSlot()`; we approximate as
/// `latest_block_header_number` (close enough — blocks are 1 slot
/// each on a healthy chain).
fn head_slot(dyn_props_be: &tron_chainbase::DynamicPropertiesStore) -> i64 {
    dyn_props_be.latest_block_header_number().unwrap_or(0)
}
