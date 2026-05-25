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
use tron_chainbase::{AccountStore, ContractStateStore, DynamicPropertiesStore};

use crate::database::evm_to_tron_address;
use crate::internal_tx::InternalTxTrace;

/// One per active VM frame, pushed at `initialize_interp` and popped at
/// `call_end` / `create_end`. Captures the factor that was installed on
/// this frame's Gas tracker so we can back out the un-penalised base
/// energy at frame end (= the number java-tron records into
/// `ContractState.energy_usage`).
#[derive(Debug, Clone, Copy)]
struct DynEnergyFrame {
    target: tron_crypto::address::Address,
    /// Installed factor in units of `DYNAMIC_ENERGY_FACTOR_DECIMAL`.
    /// `0` = no penalty (and no need to record usage).
    factor: i64,
    /// Gas limit at frame start. `gas.spent() = limit - remaining`.
    gas_limit: u64,
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
    /// Per-frame (factor, gas_limit) so `*_end` can back out the base
    /// energy used. One entry per active frame; pushed at
    /// `initialize_interp`, popped at `call_end` / `create_end`.
    dyn_energy_frames: Vec<DynEnergyFrame>,
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
            accounts: Some(accounts),
            contract_state: None,
            dyn_props: None,
            dyn_energy_frames: Vec::new(),
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

    /// Pop this frame's `(target, factor, gas_limit)` and (if the full
    /// lifecycle is enabled and the factor was non-zero) add the
    /// un-penalised base energy used to `ContractState.energy_usage`.
    ///
    /// `base = spent × DECIMAL / (DECIMAL + factor)` reverses the
    /// multiplier `record_*_cost` applied. Mirrors java-tron's
    /// `addContextContractUsage(actualEnergy)` where `actualEnergy` is
    /// the pre-penalty cost summed inside `VM.play()`.
    fn record_frame_energy(&mut self, gas_limit: u64, gas_remaining: u64) {
        let Some(frame) = self.dyn_energy_frames.pop() else {
            return;
        };
        let (Some(cs), true) = (&self.contract_state, self.dyn_props.is_some()) else {
            return;
        };
        if frame.factor == 0 {
            // No penalty was applied → spent == base; java-tron still
            // calls addContextContractUsage in this case so the next
            // cycle's threshold check sees the activity.
            let spent = gas_limit.saturating_sub(gas_remaining);
            if spent > 0 {
                cs.add_energy_usage(&frame.target, spent as i64);
            }
            return;
        }
        // Sanity: `gas.limit()` on the outcome may have been reset by
        // revm in some halts. Prefer the captured limit when smaller —
        // the spent should never exceed the original limit.
        let limit = gas_limit.min(frame.gas_limit);
        let spent = limit.saturating_sub(gas_remaining) as i128;
        let decimal: i128 = 10_000;
        let base = spent * decimal / (decimal + frame.factor as i128);
        if base > 0 {
            cs.add_energy_usage(&frame.target, base as i64);
        }
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
        let Some(cs) = &self.contract_state else {
            return;
        };
        use revm::interpreter::interpreter_types::InputsTr;
        let target = interp.input.target_address();
        let tron_addr = evm_to_tron_address(&target);

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
        // Record the frame even when factor == 0 so the pop in
        // call_end / create_end stays balanced.
        self.dyn_energy_frames.push(DynEnergyFrame {
            target: tron_addr,
            factor,
            gas_limit: interp.gas.limit(),
        });
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
        // Internal-tx trace — record one entry per nested CALL frame.
        // The top-level frame (depth == 0, the user-facing transaction
        // itself) is NOT an internal tx, so skip it.
        let depth = self.frame_starts.len();
        self.frame_starts.push(self.internal_txs.len());
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
        let mut target_account = accounts
            .get(&target_addr)
            .ok()
            .flatten()
            .unwrap_or_else(|| tron_proto::Account {
                address: target_addr.as_bytes().to_vec(),
                ..Default::default()
            });

        let caller_pre = caller_account.asset_v2.get(&token_id_key).copied();
        let target_pre = target_account.asset_v2.get(&token_id_key).copied();

        // Insufficient balance → push None, return None to let revm run
        // the call without the side effect. The opcode itself doesn't
        // signal a stack-side error here; the contract typically checks
        // its own balance via TOKENBALANCE first.
        let caller_balance = caller_pre.unwrap_or(0);
        if caller_balance < transferred {
            self.pending.push(None);
            return None;
        }

        // Apply transfer.
        caller_account
            .asset_v2
            .insert(token_id_key.clone(), caller_balance - transferred);
        let new_target = target_pre.unwrap_or(0).saturating_add(transferred);
        target_account.asset_v2.insert(token_id_key.clone(), new_target);

        accounts.put(&caller_addr, &caller_account);
        accounts.put(&target_addr, &target_account);

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
        self.record_frame_energy(outcome.result.gas.limit(), outcome.result.gas.remaining());

        let Some(pending) = self.pending.pop() else {
            return;
        };
        let Some(pending) = pending else {
            return;
        };
        let accounts = match &self.accounts {
            Some(a) => Arc::clone(a),
            None => return,
        };

        // If the call succeeded, leave the transfer in place.
        if outcome.result.result.is_ok() {
            return;
        }

        // On revert/halt: restore both accounts' asset_v2 maps to their
        // pre-transfer state.
        let mut caller_account = accounts
            .get(&pending.caller_addr)
            .ok()
            .flatten()
            .unwrap_or_default();
        match pending.caller_pre {
            Some(v) => {
                caller_account
                    .asset_v2
                    .insert(pending.token_id_key.clone(), v);
            }
            None => {
                caller_account.asset_v2.remove(&pending.token_id_key);
            }
        }
        accounts.put(&pending.caller_addr, &caller_account);

        let mut target_account = accounts
            .get(&pending.target_addr)
            .ok()
            .flatten()
            .unwrap_or_default();
        match pending.target_pre {
            Some(v) => {
                target_account
                    .asset_v2
                    .insert(pending.token_id_key.clone(), v);
            }
            None => {
                target_account.asset_v2.remove(&pending.token_id_key);
            }
        }
        accounts.put(&pending.target_addr, &target_account);

        // Suppress unused-field warning while not used.
        let _ = pending.transferred;
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

        self.frame_starts.push(self.internal_txs.len());
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
        self.record_frame_energy(outcome.result.gas.limit(), outcome.result.gas.remaining());
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
