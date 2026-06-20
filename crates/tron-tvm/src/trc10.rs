//! TRC-10 transfer side effect for the `CALLTOKEN` opcode.
//!
//! The fork's `CALLTOKEN` handler decodes the stack args, sets up the
//! call frame with the token id/value on `CallInputs`, and triggers
//! revm's normal CALL machinery. The actual TRC-10 debit/credit
//! (`Account.asset_v2[tokenId]`) happens here, plumbed via revm's
//! [`Inspector`] trait so we get correct revert semantics for free:
//!
//! * `call()` hook — before the callee executes, debit caller and
//!   credit target. Push the pre-transfer snapshot to a stack.
//! * `call_end()` hook — pop the snapshot; if the call reverted/halted,
//!   restore the pre-transfer state.
//!
//! Calls can nest (CALLTOKEN inside a CALL inside a CALLTOKEN…), hence
//! the stack of pending snapshots. Snapshots are per-frame, not per-tx,
//! so a successful CALLTOKEN whose **parent** later reverts has its
//! transfer rolled back by the higher-level session — see
//! `tron-executor::TxSession`.

use revm::inspector::Inspector;
use revm::interpreter::interpreter::EthInterpreter;
use revm::interpreter::{
    CallInputs, CallOutcome, CreateInputs, CreateOutcome, InstructionResult, Interpreter,
};
use revm::primitives::{Address, U256};
use std::sync::Arc;
use std::time::Instant;
use tron_chainbase::{
    AccountStore, ContractStateStore, DelegatedResourceStore, DynamicPropertiesStore, VotesStore,
};
use tron_proto::ContractState;

use crate::database::evm_to_tron_address;
use crate::internal_tx::InternalTxTrace;
use crate::staking_journal::SharedStakingJournal;

/// One per active *interpreter* VM frame, pushed at `initialize_interp`
/// and popped at `call_end` / `create_end` (guarded by `interp_markers`
/// so precompile/no-code frames — which never run `initialize_interp` —
/// don't pop a parent's entry). Records which contract the frame's
/// exact base energy (`Gas::tron_base_spent`) belongs to: java-tron's
/// `addContextContractUsage(energyUsage)` target.
#[derive(Debug, Clone, Copy)]
struct DynEnergyFrame {
    target: tron_crypto::address::Address,
}

/// One pending transfer's pre-state. Pushed in `call`, popped in
/// `call_end`. The stack of these handles nested CALLTOKENs.
#[derive(Debug, Clone)]
struct PendingTransfer {
    /// The pre-transfer asset_v2 balance of the caller for `token_id`.
    /// `None` means the asset key wasn't in the map before — restoration
    /// removes the key entirely.
    caller_addr: tron_crypto::address::Address,
    caller_pre: Option<i64>,
    target_addr: tron_crypto::address::Address,
    target_pre: Option<i64>,
    token_id_key: String,
    /// Non-zero token value that was actually transferred.
    transferred: i64,
}

/// revm [`Inspector`] that performs the TRC-10 transfer for every CALL
/// whose `CallInputs.tron_token_value` is non-zero, and unwinds on
/// failure. Also records internal CALL/CREATE traces so the executor
/// can surface them on `TransactionInfo.internal_transactions`.
#[derive(Default)]
pub struct Trc10Inspector {
    /// Stack of pending transfers (one per active CALLTOKEN frame).
    pending: Vec<Option<PendingTransfer>>,
    /// CALLTOKEN transfers whose immediate callee SUCCEEDED but which are still
    /// revertible: a token transfer must be rolled back if ANY ancestor frame
    /// later reverts (java-tron rolls back the whole deposit), not only the
    /// CALLTOKEN's own callee. Each frame records `committed.len()` in
    /// `committed_starts` at entry; on a frame revert every transfer pushed
    /// within that frame's subtree is unwound (LIFO).
    committed: Vec<PendingTransfer>,
    /// Per-frame marker into `committed` (parallels `frame_starts`).
    committed_starts: Vec<usize>,
    /// Per-interpreter-frame snapshot of the frame target's `ContractState`
    /// row, taken at `initialize_interp` BEFORE this frame's `catch_up_to_cycle`
    /// + `add_energy_usage` writes. java attaches those writes to the nested
    /// frame's child deposit and discards them on revert/halt (only a frame
    /// whose whole ancestor chain succeeds keeps them). We restore the snapshot
    /// (LIFO) when the frame's subtree reverts, so a reverted subtree leaves no
    /// `energy_usage` / dynamic-factor drift. One snapshot per frame suffices —
    /// both writes target the same address, so restoring the pre-frame row
    /// undoes both; LIFO restore handles nested/recursive same-contract frames.
    cs_journal: Vec<(tron_crypto::address::Address, ContractState)>,
    /// Per-frame marker into `cs_journal` (parallels `committed_starts`).
    cs_journal_starts: Vec<usize>,
    /// Shared per-frame rollback log for the staking / SELFDESTRUCT opcode
    /// bridges (see [`crate::staking_journal`]). The host pushes a reversing
    /// entry before every staking/suicide write; the inspector records
    /// `len()` here at each frame entry (`staking_starts`) and, when a frame's
    /// subtree reverts, unwinds (LIFO) every entry pushed within it — so even
    /// an ANCESTOR revert undoes a succeeded descendant's writes, exactly as
    /// java discards the uncommitted child deposit. Mirrors the `cs_journal`
    /// mechanism. `None` (with the stores below also `None`) on read-only
    /// setups that never attach the staking bridge.
    staking_journal: Option<SharedStakingJournal>,
    /// Per-frame marker into the shared staking journal (parallels
    /// `cs_journal_starts`).
    staking_starts: Vec<usize>,
    /// Stores the staking-journal unwind writes back into (the same
    /// session-wrapped handles the host bridges use). `votes` is optional
    /// because VOTEWITNESS quietly no-ops without it.
    staking_votes: Option<Arc<VotesStore>>,
    staking_delegated_resources: Option<Arc<DelegatedResourceStore>>,
    accounts: Option<Arc<AccountStore>>,
    /// Optional per-contract dynamic-energy lookup. When set, the
    /// inspector reads the callee's factor at `initialize_interp` and
    /// installs it on the Interpreter's `Gas` tracker so every gas
    /// charge gets multiplied by `(10_000 + factor) / 10_000`.
    contract_state: Option<Arc<ContractStateStore>>,
    /// Optional `DynamicPropertiesStore` for catch-up parameters
    /// (`CURRENT_CYCLE_NUMBER`, `DYNAMIC_ENERGY_THRESHOLD`,
    /// `DYNAMIC_ENERGY_INCREASE_FACTOR`, `DYNAMIC_ENERGY_MAX_FACTOR`).
    /// When present, `initialize_interp` runs `catch_up_to_cycle` for
    /// the target contract (updating its on-disk factor) instead of just
    /// reading the stored value, and `*_end` calls `add_energy_usage`
    /// with the un-penalised base energy consumed in the frame.
    dyn_props: Option<Arc<DynamicPropertiesStore>>,
    /// Per-interpreter-frame usage-attribution records. Pushed at
    /// `initialize_interp`, popped at `call_end` / `create_end` when the
    /// matching `interp_markers` entry says an interpreter actually ran.
    dyn_energy_frames: Vec<DynEnergyFrame>,
    /// One entry per `call`/`create` (i.e. per frame revm *attempted*).
    /// Flipped to `true` by `initialize_interp` when a real interpreter
    /// frame was created. Precompile and no-code calls produce a
    /// `call_end` without `initialize_interp` — without this guard they
    /// would pop the PARENT's `dyn_energy_frames` entry and misattribute
    /// `ContractState.energy_usage`.
    interp_markers: Vec<bool>,
    /// Σ dynamic-energy penalties across every finished frame — java's
    /// `ProgramResult.energyPenaltyTotal` (merged unconditionally into
    /// the parent, even when the child reverted or halted). Lands on
    /// `receipt.energy_penalty_total` / `TransactionExtention
    /// .energy_penalty`.
    energy_penalty_total: u64,
    /// Top-level CALLTOKEN: token_id/value supplied by the
    /// transaction itself (not from a nested CALLTOKEN opcode). The
    /// inspector installs these onto the first frame's `InterpreterInput`
    /// so CALLTOKENVALUE / CALLTOKENID read the right numbers, then
    /// clears the slot — subsequent frames go through the normal
    /// nested-CALLTOKEN path.
    pending_top_level: Option<(i64, i64)>,
    /// Accumulated internal-transaction traces for this tx (every
    /// nested CALL / CREATE the EVM dispatched).
    internal_txs: Vec<InternalTxTrace>,
    /// Stack of frame-start indices into `internal_txs`. Pushed in
    /// `call`/`create`, popped in `call_end`/`create_end`. On
    /// revert/halt, every entry in `internal_txs[start..]` is marked
    /// `rejected = true` — matches java-tron's
    /// `ProgramResult.rejectInternalTransactions()`.
    frame_starts: Vec<usize>,
    /// Wall-clock deadline. When set, `step` halts the interpreter as
    /// soon as `Instant::now() >= deadline`. java-tron uses a
    /// thread-interrupt-flag scheme for the same purpose; the inspector
    /// path is cheaper (no extra task) and gives the same guarantee:
    /// no opcode runs past the deadline, the VM exits with a clean
    /// `FatalExternalError` halt, and the caller surfaces a timeout to
    /// the client. Used by read-only RPC paths (`eth_call`,
    /// `eth_estimateGas`, `triggerConstantContract`) when
    /// `vm.constantCallTimeoutMs > 0`.
    deadline: Option<Instant>,
    /// Counter for the deadline check throttle. `Instant::now()` is
    /// cheap (~tens of ns) but not free, so we skip the read on the
    /// vast majority of steps. `DEADLINE_CHECK_STRIDE` controls the
    /// throttle — picked so the worst-case overshoot at common gas
    /// prices stays under ~1ms.
    step_counter: u64,
    /// Set to `true` by `step` the first time the deadline trips. Used
    /// downstream to surface a "constant call timed out" message
    /// instead of the raw revm halt reason.
    deadline_exceeded: bool,
    /// Optional per-opcode + call-tree tracer for `debug_*` /
    /// `trace_*` JSON-RPC. When present, every Inspector hook also
    /// calls the matching hook on the tracer. Cheap to leave unset
    /// (just an `Option::None`).
    tracer: Option<crate::tracer::StructLogTracer>,
}

/// How many opcodes we let run between `Instant::now()` reads. A modern
/// CPU executes ~100M opcodes/sec under revm, so checking every 4096
/// caps overshoot at ~40µs — way under our finest practical budget
/// granularity (1ms). Picked to keep the check ≪ 1% of dispatch cost.
const DEADLINE_CHECK_STRIDE: u64 = 4096;

impl Trc10Inspector {
    /// Create an inspector that writes back into `accounts`. The
    /// AccountStore is the same Arc the rest of the EVM stack uses;
    /// our transfers go through the session-wrapped backend so the
    /// outer `TxSession::revert` reverts them on a tx-level failure.
    pub fn new(accounts: Arc<AccountStore>) -> Self {
        Self {
            pending: Vec::new(),
            committed: Vec::new(),
            committed_starts: Vec::new(),
            cs_journal: Vec::new(),
            cs_journal_starts: Vec::new(),
            staking_journal: None,
            staking_starts: Vec::new(),
            staking_votes: None,
            staking_delegated_resources: None,
            accounts: Some(accounts),
            contract_state: None,
            dyn_props: None,
            dyn_energy_frames: Vec::new(),
            interp_markers: Vec::new(),
            energy_penalty_total: 0,
            pending_top_level: None,
            internal_txs: Vec::new(),
            frame_starts: Vec::new(),
            deadline: None,
            step_counter: 0,
            deadline_exceeded: false,
            tracer: None,
        }
    }

    /// Attach a struct-log + call-tree tracer. After the VM run,
    /// retrieve the captured trace via [`Self::take_tracer`].
    pub fn with_tracer(mut self, tracer: crate::tracer::StructLogTracer) -> Self {
        self.tracer = Some(tracer);
        self
    }

    /// Pull the attached tracer back out, consuming the inspector.
    /// Returns `None` if no tracer was attached.
    pub fn take_tracer(&mut self) -> Option<crate::tracer::StructLogTracer> {
        self.tracer.take()
    }

    /// Restore both sides of a TRC-10 CALLTOKEN transfer to their pre-transfer
    /// `asset_v2` state. Used for an immediate-callee revert AND for unwinding a
    /// transfer discarded by an ancestor frame's revert.
    fn unwind_transfer(&self, t: &PendingTransfer) {
        let accounts = match &self.accounts {
            Some(a) => Arc::clone(a),
            None => return,
        };
        let mut caller_account = accounts
            .get(&t.caller_addr)
            .ok()
            .flatten()
            .unwrap_or_default();
        match t.caller_pre {
            Some(v) => {
                caller_account.asset_v2.insert(t.token_id_key.clone(), v);
            }
            None => {
                caller_account.asset_v2.remove(&t.token_id_key);
            }
        }
        accounts
            .put(&t.caller_addr, &caller_account)
            .expect("db error in Trc10Inspector unwinding caller account after revert");

        let mut target_account = accounts
            .get(&t.target_addr)
            .ok()
            .flatten()
            .unwrap_or_default();
        match t.target_pre {
            Some(v) => {
                target_account.asset_v2.insert(t.token_id_key.clone(), v);
            }
            None => {
                target_account.asset_v2.remove(&t.token_id_key);
            }
        }
        accounts
            .put(&t.target_addr, &target_account)
            .expect("db error in Trc10Inspector unwinding target account after revert");
        let _ = t.transferred;
    }

    /// Attach a wall-clock deadline. From this point on, `step` halts
    /// the interpreter the first time `Instant::now() >= deadline`.
    /// Used by read-only RPC paths to enforce `vm.constantCallTimeoutMs`
    /// mid-execution. Producers and block-apply paths leave this unset.
    pub fn with_deadline(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// Did `step` halt the interpreter because the deadline elapsed?
    /// Callers inspect this after the VM returns to distinguish a real
    /// `FatalExternalError` halt (e.g. database fault) from our
    /// deadline-induced halt and surface a clear timeout error to the
    /// client.
    pub fn deadline_exceeded(&self) -> bool {
        self.deadline_exceeded
    }

    /// Consume the inspector and return all internal-transaction traces
    /// captured during this run.
    pub fn into_internal_txs(self) -> Vec<InternalTxTrace> {
        self.internal_txs
    }

    /// Enable per-opcode dynamic-energy enforcement with the full
    /// java-tron lifecycle: `initialize_interp` calls
    /// `ContractStateStore::catch_up_to_cycle` (which may decay/grow the
    /// on-disk factor based on cycles elapsed and the previous cycle's
    /// usage) before installing the resulting factor on the Gas tracker.
    /// `call_end` / `create_end` record the frame's un-penalised energy
    /// usage via `add_energy_usage` so future catch-ups can decide
    /// whether to grow the factor.
    pub fn with_dynamic_energy(
        mut self,
        contract_state: Arc<ContractStateStore>,
        dyn_props: Arc<DynamicPropertiesStore>,
    ) -> Self {
        self.contract_state = Some(contract_state);
        self.dyn_props = Some(dyn_props);
        self
    }

    /// Attach the shared per-frame staking/suicide rollback journal (the same
    /// handle [`crate::database::TronDatabase`] holds) plus the stores it
    /// unwinds into. With this set, a reverted VM frame discards the staking
    /// writes its subtree made — the per-frame analogue of the per-tx
    /// `VmSession` rollback in `tron-executor`. The unwind needs `dyn_props`
    /// (the weight accumulators), which `with_dynamic_energy` already supplies;
    /// when dynamic-energy is off, the dyn_props handle is passed here too.
    pub fn with_staking_journal(
        mut self,
        journal: SharedStakingJournal,
        dyn_props: Arc<DynamicPropertiesStore>,
        votes: Option<Arc<VotesStore>>,
        delegated_resources: Arc<DelegatedResourceStore>,
    ) -> Self {
        self.staking_journal = Some(journal);
        // The unwind reverses TOTAL_*_WEIGHT deltas through `dyn_props`. Reuse
        // the one `with_dynamic_energy` set if present; otherwise install it so
        // the journal can reverse weight even with dynamic-energy disabled.
        if self.dyn_props.is_none() {
            self.dyn_props = Some(dyn_props);
        }
        self.staking_votes = votes;
        self.staking_delegated_resources = Some(delegated_resources);
        self
    }

    /// Carry a top-level transaction's `(token_id, token_value)` into
    /// the first interpreter frame. The TRC-10 debit/credit on
    /// asset_v2 must happen separately *before* calling the EVM — this
    /// only ensures `CALLTOKENVALUE` / `CALLTOKENID` opcodes inside
    /// the contract see the right numbers.
    pub fn with_top_level_token(mut self, token_id: i64, token_value: i64) -> Self {
        if token_id != 0 || token_value != 0 {
            self.pending_top_level = Some((token_id, token_value));
        }
        self
    }

    /// Pop this interpreter frame's attribution record, merge its
    /// penalty total, and (if the full lifecycle is enabled) add the
    /// exact un-penalised base energy to `ContractState.energy_usage`.
    ///
    /// `Gas::tron_base_spent` is the frame's Σ raw charges with
    /// forwarded child gas and code-deposit excluded — exactly
    /// java-tron's `energyUsage` (Σ `actualEnergy`) in `VM.play()`. No
    /// lossy back-out from the scaled total is needed.
    ///
    /// java-tron parity notes:
    /// - penalties merge into the tx total unconditionally
    ///   (`ProgramResult.merge` runs `addTotalPenalty` even for
    ///   reverted/halted children);
    /// - an exceptionally-halted frame throws PAST
    ///   `addContextContractUsage`, so its usage is never recorded
    ///   (REVERT exits the loop normally and IS recorded).
    fn record_frame_energy(&mut self, gas: &revm::interpreter::Gas, exceptional_halt: bool) {
        let Some(frame) = self.dyn_energy_frames.pop() else {
            return;
        };
        self.energy_penalty_total = self
            .energy_penalty_total
            .saturating_add(gas.tron_penalty_spent());
        let (Some(cs), true) = (&self.contract_state, self.dyn_props.is_some()) else {
            return;
        };
        if exceptional_halt {
            return;
        }
        let base = gas.tron_base_spent();
        if base > 0 {
            cs.add_energy_usage(&frame.target, base as i64).expect(
                "db error in Trc10Inspector::record_frame_energy writing energy usage",
            );
        }
    }

    /// Pop this frame's `cs_journal` marker. If the frame reverted/halted,
    /// restore (LIFO) every ContractState row its subtree snapshotted at
    /// `initialize_interp` — undoing the reverted subtree's `catch_up_to_cycle`
    /// + `add_energy_usage` writes, exactly as java discards the uncommitted
    /// child deposit. On success the entries stay (an ancestor frame may still
    /// revert and restore them); the top-level frame's success drops them.
    fn restore_cs_journal_if_reverted(&mut self, reverted: bool) {
        let Some(jstart) = self.cs_journal_starts.pop() else {
            return;
        };
        if !reverted {
            return;
        }
        if let Some(cs) = self.contract_state.clone() {
            while self.cs_journal.len() > jstart {
                if let Some((addr, row)) = self.cs_journal.pop() {
                    let _ = cs.put(&addr, &row);
                }
            }
        } else {
            self.cs_journal.truncate(jstart);
        }
    }

    /// Record the staking journal's current length as this frame's start
    /// marker. Always pushes a marker (even when no journal is attached) so the
    /// pop in `*_end` stays balanced with `call`/`create`.
    fn push_staking_start(&mut self) {
        let len = self
            .staking_journal
            .as_ref()
            .map(|j| j.lock().expect("staking journal mutex poisoned").len())
            .unwrap_or(0);
        self.staking_starts.push(len);
    }

    /// Pop this frame's staking-journal marker. If the frame reverted/halted,
    /// unwind (LIFO) every staking/suicide write its subtree recorded — exactly
    /// as java discards the uncommitted child deposit. On success the entries
    /// stay (an ancestor frame may still revert and unwind them); the top-level
    /// frame's revert unwinds the lot (the per-tx `VmSession` also discards
    /// them, so the unwind lands in an overlay that's about to be dropped —
    /// harmless and idempotent).
    fn unwind_staking_journal_if_reverted(&mut self, reverted: bool) {
        let Some(start) = self.staking_starts.pop() else {
            return;
        };
        let Some(journal) = self.staking_journal.clone() else {
            return;
        };
        if !reverted {
            return;
        }
        let (Some(accounts), Some(dyn_props), Some(delegated)) = (
            self.accounts.as_ref(),
            self.dyn_props.as_ref(),
            self.staking_delegated_resources.as_ref(),
        ) else {
            return;
        };
        journal
            .lock()
            .expect("staking journal mutex poisoned")
            .unwind_to(
                start,
                accounts,
                self.staking_votes.as_deref(),
                delegated,
                dyn_props,
            );
    }

    /// Σ dynamic-energy penalties across all finished frames — java's
    /// `ProgramResult.getEnergyPenaltyTotal()`. Read after the run for
    /// `receipt.energy_penalty_total` / constant-call `energy_penalty`.
    pub fn energy_penalty_total(&self) -> u64 {
        self.energy_penalty_total
    }
}

impl<CTX> Inspector<CTX, EthInterpreter> for Trc10Inspector {
    fn initialize_interp(&mut self, interp: &mut Interpreter<EthInterpreter>, _context: &mut CTX) {
        // TRON fork (1/2): if this is the top frame of a CALLTOKEN-bearing
        // transaction, install the token_id/value on the input so
        // CALLTOKENVALUE / CALLTOKENID opcodes inside the contract see
        // the right numbers. Only fires once per transaction (clears
        // the pending slot).
        if let Some((token_id, token_value)) = self.pending_top_level.take() {
            interp.input.tron_token_id = token_id;
            interp.input.tron_token_value = token_value;
        }

        // TRON fork (2/2): run the per-cycle factor catch-up for this
        // frame's target (mirrors `Program.updateContextContractFactor`)
        // and install the resulting factor on the Gas tracker so every
        // opcode charge gets the `(10_000 + factor) / 10_000` multiplier.
        //
        // The catch-up writes the updated `ContractState` back to disk.
        // We also push a frame record so `*_end` can compute the
        // un-penalised base energy and call `add_energy_usage`.
        let Some(cs) = self.contract_state.clone() else {
            return;
        };
        use revm::interpreter::interpreter_types::InputsTr;
        let target = interp.input.target_address();
        let tron_addr = evm_to_tron_address(&target);

        // Snapshot the target's ContractState row BEFORE this frame's
        // catch_up + add_energy_usage writes, so `*_end` can restore it if the
        // frame's subtree reverts (java discards the reverted child deposit).
        // One snapshot per frame covers both writes (same target); the marker
        // for this frame was pushed in `call`/`create`.
        if !self.cs_journal_starts.is_empty() {
            let prior = cs.get(&tron_addr).ok().flatten().unwrap_or_default();
            self.cs_journal.push((tron_addr, prior));
        }

        let factor = if let Some(dp) = &self.dyn_props {
            let current_cycle = dp.current_cycle_number();
            let threshold = dp.get_long(b"DYNAMIC_ENERGY_THRESHOLD").unwrap_or(0);
            let increase = dp.get_long(b"DYNAMIC_ENERGY_INCREASE_FACTOR").unwrap_or(0);
            let max_factor = dp.get_long(b"DYNAMIC_ENERGY_MAX_FACTOR").unwrap_or(0);
            cs.catch_up_to_cycle(&tron_addr, current_cycle, threshold, increase, max_factor)
                .unwrap_or(0)
        } else {
            cs.dynamic_energy_factor(&tron_addr).unwrap_or(0)
        };

        if factor != 0 {
            interp.gas.set_tron_dynamic_factor(factor);
        }
        // A real interpreter frame exists for the innermost attempted
        // call/create — flip its marker so `*_end` knows to pop the
        // record below. (Precompile/no-code frames never get here.)
        match self.interp_markers.last_mut() {
            Some(m) => *m = true,
            None => self.interp_markers.push(true),
        }
        // Record the frame even when factor == 0 so the pop in
        // call_end / create_end stays balanced — java-tron records
        // contract usage for un-penalised frames too.
        self.dyn_energy_frames.push(DynEnergyFrame { target: tron_addr });
    }

    fn step(&mut self, interp: &mut Interpreter<EthInterpreter>, _context: &mut CTX) {
        // Tracer hook (debug_*/trace_* JSON-RPC support). Runs
        // before the deadline check so a halted trace still has the
        // partial step recorded.
        if let Some(tracer) = self.tracer.as_mut() {
            <crate::tracer::StructLogTracer as Inspector<CTX, EthInterpreter>>::step(
                tracer, interp, _context,
            );
        }
        // Deadline check — only when configured (constant-call paths).
        // Throttled by DEADLINE_CHECK_STRIDE so the `Instant::now()` syscall
        // doesn't dominate dispatch cost on hot bytecode loops.
        let Some(deadline) = self.deadline else {
            return;
        };
        self.step_counter = self.step_counter.wrapping_add(1);
        if self.step_counter % DEADLINE_CHECK_STRIDE != 0 {
            return;
        }
        if Instant::now() >= deadline {
            self.deadline_exceeded = true;
            // Use OutOfGas to halt: the forked revm-handler in this
            // workspace panics on the `FatalExternalError` and
            // `InternalResult` flags (see `crates/revm-handler/src/
            // post_execution.rs` — they're documented as "internal
            // return flags", never reachable from a healthy run).
            // OutOfGas is the cleanest halt that the post-execution
            // path handles normally; `execute_trigger_inner` reads
            // our `deadline_exceeded` flag to surface a
            // `VmOutcome::Timeout` regardless of which halt reason
            // revm reports, so the OutOfGas reason never leaks to
            // the caller.
            interp.halt(InstructionResult::OutOfGas);
        }
    }

    fn step_end(&mut self, interp: &mut Interpreter<EthInterpreter>, _context: &mut CTX) {
        if let Some(tracer) = self.tracer.as_mut() {
            <crate::tracer::StructLogTracer as Inspector<CTX, EthInterpreter>>::step_end(
                tracer, interp, _context,
            );
        }
    }

    fn call(&mut self, _context: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        if let Some(tracer) = self.tracer.as_mut() {
            <crate::tracer::StructLogTracer as Inspector<CTX, EthInterpreter>>::call(
                tracer, _context, inputs,
            );
        }
        // Frame attempted — assume no interpreter until
        // `initialize_interp` proves otherwise (precompiles/no-code
        // targets produce a `call_end` without one).
        self.interp_markers.push(false);
        // Internal-tx trace — record one entry per nested CALL frame.
        // The top-level frame (depth == 0, the user-facing transaction
        // itself) is NOT an internal tx, so skip it.
        let depth = self.frame_starts.len();
        self.frame_starts.push(self.internal_txs.len());
        self.committed_starts.push(self.committed.len());
        self.cs_journal_starts.push(self.cs_journal.len());
        self.push_staking_start();
        if depth > 0 {
            let trx_value = match inputs.value {
                revm::interpreter::CallValue::Transfer(v) => v,
                revm::interpreter::CallValue::Apparent(_) => revm::primitives::U256::ZERO,
            };
            // CallInput::Bytes is the typical variant for nested calls;
            // SharedBuffer is used for memory-backed input. Materialize
            // both into a Vec<u8> for the trace.
            let data = match &inputs.input {
                revm::interpreter::CallInput::Bytes(b) => b.to_vec(),
                revm::interpreter::CallInput::SharedBuffer(range) => {
                    // Defensive copy of the range bounds; the trace
                    // doesn't need a live memory view.
                    let _ = range;
                    Vec::new()
                }
            };
            self.internal_txs.push(InternalTxTrace {
                caller_address: *evm_to_tron_address(&inputs.caller).as_bytes(),
                transfer_to_address: *evm_to_tron_address(&inputs.target_address).as_bytes(),
                call_value: trx_value,
                token_id: inputs.tron_token_id,
                token_value: inputs.tron_token_value,
                data,
                note: "call",
                rejected: false,
            });
        }

        // Non-CALLTOKEN calls: push a None on the stack so call_end
        // can pop unconditionally regardless of which variant.
        if inputs.tron_token_value == 0 {
            self.pending.push(None);
            return None;
        }
        let accounts = match &self.accounts {
            Some(a) => Arc::clone(a),
            None => {
                self.pending.push(None);
                return None;
            }
        };

        let caller_addr = evm_to_tron_address(&inputs.caller);
        let target_addr = evm_to_tron_address(&inputs.target_address);
        let token_id_key = inputs.tron_token_id.to_string();
        let transferred = inputs.tron_token_value;

        // Read pre-state from the AccountStore.
        let mut caller_account = accounts
            .get(&caller_addr)
            .ok()
            .flatten()
            .unwrap_or_else(|| tron_proto::Account {
                address: caller_addr.as_bytes().to_vec(),
                ..Default::default()
            });
        let target_existing = accounts.get(&target_addr).ok().flatten();
        let target_was_new = target_existing.is_none();
        let mut target_account = target_existing.unwrap_or_else(|| tron_proto::Account {
            address: target_addr.as_bytes().to_vec(),
            ..Default::default()
        });
        if target_was_new {
            // java createAccountIfNotExist stamps a freshly-created account's
            // create_time with the head-block timestamp (matching the commit
            // path + TransferActuator). Only on creation.
            target_account.create_time = self
                .dyn_props
                .as_ref()
                .and_then(|d| d.latest_block_header_timestamp())
                .unwrap_or(0);
        }

        // An asset-optimized account holds its TRC-10 balances in the separate
        // account-asset store, not inline; merge them before reading/mutating
        // so a nested CALLTOKEN sees the real balance (java getAssetV2 ->
        // importAsset). Without this an optimized caller reads 0 and the
        // transfer is silently skipped.
        tron_chainbase::import_all_asset(&mut caller_account);
        tron_chainbase::import_all_asset(&mut target_account);

        let caller_pre = caller_account.asset_v2.get(&token_id_key).copied();
        let target_pre = target_account.asset_v2.get(&token_id_key).copied();

        // Insufficient TRC-10 balance → java `Program.callToAddress` does
        // `stackPushZero(); refundEnergy(msg.getEnergy()); return;`: the
        // callee never runs, the CALL pushes 0 (failure), and the full
        // forwarded energy is refunded. Short-circuit the frame by returning
        // a CallOutcome rather than `None` (which would let revm execute the
        // callee with no transfer). Push `None` to `pending` first so the
        // unconditional `pending.pop()` in `call_end` stays balanced.
        //
        // `Revert` makes `insert_call_outcome` push 0 on the stack
        // (`is_ok()` is false) while still refunding the unspent gas
        // (`is_ok_or_revert()` is true → `gas.erase_cost(remaining)`).
        // Sizing the gas as `make_call_frame` would for this child —
        // regular = gas_limit, reservoir = inputs.reservoir, nothing spent —
        // refunds the full forwarded energy and preserves the reservoir.
        let caller_balance = caller_pre.unwrap_or(0);
        if caller_balance < transferred {
            self.pending.push(None);
            let gas = revm::interpreter::Gas::new_with_regular_gas_and_reservoir(
                inputs.gas_limit,
                inputs.reservoir,
            );
            return Some(CallOutcome::new(
                revm::interpreter::InterpreterResult {
                    result: InstructionResult::Revert,
                    output: revm::primitives::Bytes::new(),
                    gas,
                },
                inputs.return_memory_offset.clone(),
            ));
        }

        // Apply transfer.
        caller_account
            .asset_v2
            .insert(token_id_key.clone(), caller_balance - transferred);
        let new_target = target_pre.unwrap_or(0).saturating_add(transferred);
        target_account.asset_v2.insert(token_id_key.clone(), new_target);

        accounts
            .put(&caller_addr, &caller_account)
            .expect("db error in Trc10Inspector::call writing caller account for CALLTOKEN transfer");
        accounts
            .put(&target_addr, &target_account)
            .expect("db error in Trc10Inspector::call writing target account for CALLTOKEN transfer");

        self.pending.push(Some(PendingTransfer {
            caller_addr,
            caller_pre,
            target_addr,
            target_pre,
            token_id_key,
            transferred,
        }));
        None
    }

    fn call_end(
        &mut self,
        _context: &mut CTX,
        _inputs: &CallInputs,
        outcome: &mut CallOutcome,
    ) {
        if let Some(tracer) = self.tracer.as_mut() {
            <crate::tracer::StructLogTracer as Inspector<CTX, EthInterpreter>>::call_end(
                tracer, _context, _inputs, outcome,
            );
        }
        // Internal-tx trace: if this frame reverted/halted, mark every
        // trace entry recorded since this frame opened as rejected. The
        // children's own call_ends already ran (EVM unwinds bottom-up),
        // so this correctly propagates a parent-revert downward.
        if let Some(start) = self.frame_starts.pop() {
            if !outcome.result.result.is_ok() {
                for entry in &mut self.internal_txs[start..] {
                    entry.rejected = true;
                }
            }
        }
        // Only interpreter frames pushed a dyn-energy record; precompile
        // and no-code call_ends must not pop the parent's.
        if self.interp_markers.pop().unwrap_or(false) {
            self.record_frame_energy(&outcome.result.gas, outcome.result.result.is_halt());
        }

        let reverted = !outcome.result.result.is_ok();

        // This frame's own CALLTOKEN transfer (if it was a CALLTOKEN). If the
        // immediate callee reverted, roll it back now. If the callee succeeded,
        // the transfer is applied but still revertible by an ANCESTOR frame —
        // park it in `committed` so an ancestor revert can unwind it.
        if let Some(Some(transfer)) = self.pending.pop() {
            if reverted {
                self.unwind_transfer(&transfer);
            } else {
                self.committed.push(transfer);
            }
        }

        // If THIS frame reverted, roll back every CALLTOKEN transfer committed
        // within its subtree — nested CALLTOKENs whose callees succeeded but are
        // discarded by this frame's revert (java rolls back the whole deposit).
        // LIFO order so each transfer's recorded pre-value restores the exact
        // prior balance even when several touched the same account/token.
        if let Some(cstart) = self.committed_starts.pop() {
            if reverted {
                while self.committed.len() > cstart {
                    if let Some(t) = self.committed.pop() {
                        self.unwind_transfer(&t);
                    }
                }
            }
        }
        self.restore_cs_journal_if_reverted(reverted);
        self.unwind_staking_journal_if_reverted(reverted);
    }

    fn create(
        &mut self,
        _context: &mut CTX,
        inputs: &mut CreateInputs,
    ) -> Option<CreateOutcome> {
        if let Some(tracer) = self.tracer.as_mut() {
            <crate::tracer::StructLogTracer as Inspector<CTX, EthInterpreter>>::create(
                tracer, _context, inputs,
            );
        }
        // CREATE traces are always internal (the top-level frame in
        // both execute_trigger and execute_create is a CALL, never a
        // CREATE — TRON's contract-address derivation pre-installs the
        // contract code and then CALLs it). So every create() hook
        // here corresponds to a nested CREATE / CREATE2 opcode.
        let caller = evm_to_tron_address(&inputs.caller());
        // CreateInputs caches the created address; pre-nonce 0 is a
        // best-effort guess that yields the contract address for the
        // common CREATE2 path (where the address doesn't depend on
        // nonce) and a *predictable* address for plain CREATE. java-
        // tron stores the exact address from `Program.executeCreate`,
        // which the host computes from the actual nonce — we only have
        // access to nonce-0 here. The mismatch is informational only
        // (the address shows up on the trace but is not consensus-
        // critical because internal_transactions are read-only).
        let created = inputs.created_address(0);
        let target = evm_to_tron_address(&created);

        // Same marker protocol as `call` — a CREATE that fails before
        // frame creation (e.g. depth limit) ends without an interpreter.
        self.interp_markers.push(false);
        self.frame_starts.push(self.internal_txs.len());
        self.committed_starts.push(self.committed.len());
        self.cs_journal_starts.push(self.cs_journal.len());
        self.push_staking_start();
        self.internal_txs.push(InternalTxTrace {
            caller_address: *caller.as_bytes(),
            transfer_to_address: *target.as_bytes(),
            call_value: inputs.value(),
            token_id: 0,
            token_value: 0,
            data: inputs.init_code().to_vec(),
            note: "create",
            rejected: false,
        });
        None
    }

    fn create_end(
        &mut self,
        _context: &mut CTX,
        _inputs: &CreateInputs,
        outcome: &mut CreateOutcome,
    ) {
        if let Some(tracer) = self.tracer.as_mut() {
            <crate::tracer::StructLogTracer as Inspector<CTX, EthInterpreter>>::create_end(
                tracer, _context, _inputs, outcome,
            );
        }
        if let Some(start) = self.frame_starts.pop() {
            if !outcome.result.result.is_ok() {
                for entry in &mut self.internal_txs[start..] {
                    entry.rejected = true;
                }
            }
            // If revm computed a concrete address (CREATE2 always, plus
            // post-execution CREATE), prefer that over the nonce-0
            // guess we stored in `create()`.
            if let Some(addr) = outcome.address {
                if let Some(entry) = self.internal_txs.get_mut(start) {
                    let resolved = evm_to_tron_address(&addr);
                    entry.transfer_to_address = *resolved.as_bytes();
                }
            }
        }
        // Mirror the CALLTOKEN subtree-unwind for CREATE frames: a TRC-10
        // transfer committed inside a CREATE that reverts must roll back too.
        if let Some(cstart) = self.committed_starts.pop() {
            if !outcome.result.result.is_ok() {
                while self.committed.len() > cstart {
                    if let Some(t) = self.committed.pop() {
                        self.unwind_transfer(&t);
                    }
                }
            }
        }
        if self.interp_markers.pop().unwrap_or(false) {
            self.record_frame_energy(&outcome.result.gas, outcome.result.result.is_halt());
        }
        self.restore_cs_journal_if_reverted(!outcome.result.result.is_ok());
        self.unwind_staking_journal_if_reverted(!outcome.result.result.is_ok());
    }

    fn selfdestruct(&mut self, contract: Address, target: Address, value: U256) {
        // SELFDESTRUCT — record one internal-tx entry with note "suicide",
        // mirroring java-tron's `Program.suicide` which calls
        // `addInternalTx(null, owner, obtainer, balance, null, "suicide", ...)`.
        // The entry is inserted into the *current* frame's slice of
        // `internal_txs`; if the surrounding frame later reverts, the
        // `call_end` / `create_end` reject cascade will flip
        // `rejected = true` on it — same semantics as java-tron's
        // `rejectInternalTransactions`.
        let caller = evm_to_tron_address(&contract);
        let beneficiary = evm_to_tron_address(&target);
        self.internal_txs.push(InternalTxTrace {
            caller_address: *caller.as_bytes(),
            transfer_to_address: *beneficiary.as_bytes(),
            call_value: value,
            token_id: 0,
            token_value: 0,
            data: Vec::new(),
            note: "suicide",
            rejected: false,
        });
        if let Some(tracer) = self.tracer.as_mut() {
            <crate::tracer::StructLogTracer as Inspector<(), EthInterpreter>>::selfdestruct(
                tracer, contract, target, value,
            );
        }
    }
}
