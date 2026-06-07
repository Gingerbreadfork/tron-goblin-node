//! High-level VM execution entry points.
//!
//! These functions are what the block executor (in `tron-executor`) will
//! eventually call for `TriggerSmartContract` and `CreateSmartContract`
//! transactions. The actuator layer can stay as-is; the executor branches
//! on contract type and routes VM-bound contracts here instead of through
//! the per-contract actuator dispatch.
//!
//! Each entry point:
//! 1. Decodes the contract proto and the relevant `TronAddress`es.
//! 2. Builds a fresh `TronDatabase` + `TronPrecompiles` over the supplied
//!    stores.
//! 3. Runs revm with the standard mainnet spec, committing state changes
//!    on success.
//! 4. Returns a [`VmOutcome`] describing what happened.
//!
//! **Out of scope for Phase 2** (deferred to a follow-up session):
//! * `CALLTOKEN` opcode — needs an `EthInstructions` extension. Until
//!   then, contracts that use `call_token_value` / `token_id` will run
//!   *as if those fields were zero* — the TRC-10 transfer doesn't fire.
//!   Returns [`VmOutcome::CallTokenIgnored`] when the fields are
//!   non-zero so the caller can reject the tx rather than silently
//!   diverging from java-tron.
//! * `feeLimit` → revm `gas_limit` conversion. java-tron's `feeLimit`
//!   is denominated in sun, with `gas_limit = feeLimit / energyFee`.
//!   We pass the supplied `energy_limit` through directly.

use std::sync::Arc;

use revm::context::{Context, Evm, FrameStack, TxEnv};
use revm::context_interface::result::ExecutionResult;
use revm::handler::instructions::EthInstructions;
use revm::inspector::InspectCommitEvm;
use revm::interpreter::interpreter::EthInterpreter;
use revm::primitives::{Address as EvmAddress, Bytes, TxKind, U256};
use revm::MainContext;
use tron_chainbase::{
    AccountStore, CodeStore, ContractStateStore, DelegatedResourceStore, DelegationStore,
    DynamicPropertiesStore, StorageRowStore, WitnessStore,
};
use tron_proto::{CreateSmartContract, TriggerSmartContract};

use crate::database::{evm_to_tron_address, TronDatabase};
use crate::evm::TronPrecompiles;

/// Returns true when the `ALLOW_DYNAMIC_ENERGY` proposal is active.
/// Mirrors java-tron's `VMConfig.allowDynamicEnergy()` gate: when off,
/// the per-contract `energy_factor` (even if non-zero in chainbase) must
/// NOT multiply opcode gas. See `actuator/.../vm/VM.java` line ~27.
fn dynamic_energy_active(dyn_props: &DynamicPropertiesStore) -> bool {
    dyn_props.get_long(b"ALLOW_DYNAMIC_ENERGY").unwrap_or(0) == 1
}

/// Borrowed (or `Arc`'d) handles to every store the EVM needs to see.
/// Constructed once per block by the executor; passed to every VM-bound
/// transaction in the block.
pub struct VmStores {
    pub accounts: Arc<AccountStore>,
    pub code: Arc<CodeStore>,
    pub storage: Arc<StorageRowStore>,
    pub witnesses: Arc<WitnessStore>,
    pub contract_state: Arc<ContractStateStore>,
    pub dynamic_properties: Arc<DynamicPropertiesStore>,
    pub delegated_resources: Arc<DelegatedResourceStore>,
    pub delegation: Arc<DelegationStore>,
    /// Optional — when present, `BLOCKHASH(n)` returns the canonical
    /// block hash for the last 256 blocks (EVM spec window); when
    /// absent, it returns zero.
    pub block_index: Option<Arc<tron_chainbase::BlockIndexStore>>,
    /// Optional — when present, storage-key composition uses the
    /// v1/v2 layout selector from `SmartContract.version`. When
    /// absent, every contract is treated as v2 (the common case).
    pub contracts: Option<Arc<tron_chainbase::ContractStore>>,
    /// VotesStore — required for VOTEWITNESS (0xd8). Optional so
    /// read-only callers (`eth_call` etc.) that don't trigger the
    /// state-mutating opcodes can omit it.
    pub votes: Option<Arc<tron_chainbase::VotesStore>>,
}

/// Per-block environment the EVM needs (BLOCKNUMBER, TIMESTAMP, ...).
#[derive(Debug, Clone, Copy)]
pub struct VmBlockEnv {
    pub block_number: i64,
    pub block_timestamp_ms: i64,
}

/// A single LOG opcode emission surfaced from the VM. Owns its bytes
/// so callers don't need to keep revm/alloy types alive.
#[derive(Debug, Clone)]
pub struct VmLog {
    /// 20-byte EVM address of the contract that emitted the log.
    /// Convert to the 21-byte TRON form by prepending `0x41` when
    /// presenting to consumers expecting TRON addresses.
    pub address: [u8; 20],
    /// LOG topics — 0..=4 entries, each a 32-byte word. `topics[0]` is
    /// the event signature hash for non-anonymous events.
    pub topics: Vec<[u8; 32]>,
    /// LOG data payload (the non-indexed event args, ABI-encoded).
    pub data: Vec<u8>,
}

/// What the VM produced. Mirrors revm's `ExecutionResult` but adds
/// TRON-specific outcomes (e.g. CallToken-not-yet-implemented).
#[derive(Debug)]
pub enum VmOutcome {
    /// Standard successful return.
    Success {
        return_data: Vec<u8>,
        energy_used: u64,
        /// Logs emitted by successful LOG opcodes during execution.
        /// Empty if the contract didn't emit anything. Reverted /
        /// halted txs DO NOT surface logs here, matching java-tron's
        /// `TransactionContext.getLogList()` only being read on
        /// success — `tron-eventer` only fires
        /// `ContractEvent`/`ContractLogEvent` for committed txs.
        logs: Vec<VmLog>,
    },
    /// Contract reverted (consumed all energy up to the revert point).
    Revert {
        return_data: Vec<u8>,
        energy_used: u64,
    },
    /// Halted (OOG, invalid opcode, etc.). All energy spent.
    Halt {
        reason: String,
        energy_used: u64,
    },
    /// The contract requested a TRC-10 transfer via `call_token_value` /
    /// `token_id` — that's the `CALLTOKEN` opcode path, which isn't
    /// implemented yet (Phase-2 follow-up). The transaction must be
    /// rejected at the executor level rather than executed without the
    /// transfer (which would diverge from java-tron).
    CallTokenIgnored {
        token_id: i64,
        call_token_value: i64,
    },
    /// Pre-flight failure — couldn't even build the EVM (malformed
    /// addresses, etc.).
    PreflightError(String),
    /// The VM was halted mid-execution because the wall-clock deadline
    /// configured by the caller (`vm.constantCallTimeoutMs`) elapsed.
    /// Distinct from `Halt` so the RPC layer can surface a clean
    /// timeout error to the client instead of a generic
    /// `FatalExternalError` message. Only produced by
    /// [`execute_trigger_with_deadline`].
    Timeout {
        /// Energy consumed up to the point the deadline tripped. Not
        /// charged anywhere (read-only paths only).
        energy_used: u64,
        /// Wall-clock budget that was exceeded, in milliseconds.
        deadline_ms: u64,
    },
}

/// Execute a `TriggerSmartContract` through the TVM (no trace).
///
/// `energy_limit` is the contract-side energy budget (java-tron's
/// `feeLimit / energyFee`). The EVM treats it as `gas_limit`.
///
/// For internal-transaction traces, use [`execute_trigger_with_trace`].
pub fn execute_trigger(
    stores: &VmStores,
    block: VmBlockEnv,
    contract: &TriggerSmartContract,
    energy_limit: u64,
) -> VmOutcome {
    execute_trigger_with_trace(stores, block, contract, energy_limit).0
}

/// Execute a `TriggerSmartContract` and return both the outcome and the
/// list of internal-transaction traces captured by the inspector.
pub fn execute_trigger_with_trace(
    stores: &VmStores,
    block: VmBlockEnv,
    contract: &TriggerSmartContract,
    energy_limit: u64,
) -> (VmOutcome, Vec<crate::internal_tx::InternalTxTrace>) {
    execute_trigger_inner(stores, block, contract, energy_limit, None, None)
}

/// Same as [`execute_trigger_with_trace`] plus a `tx_gas_limit_cap`
/// override on revm's `CfgEnv`. Required when callers want
/// `energy_limit > 16,777,216` (revm's default `eip7825::TX_GAS_LIMIT_CAP`),
/// which read-only `eth_call`s hitting heavy DEX simulations may need.
/// Producers must keep `gas_cap_override == None` so the consensus
/// path stays on the default cap.
pub fn execute_trigger_with_gas_cap(
    stores: &VmStores,
    block: VmBlockEnv,
    contract: &TriggerSmartContract,
    energy_limit: u64,
    gas_cap_override: u64,
) -> (VmOutcome, Vec<crate::internal_tx::InternalTxTrace>) {
    execute_trigger_inner(stores, block, contract, energy_limit, Some(gas_cap_override), None)
}

/// As [`execute_trigger_with_gas_cap`] plus an attached
/// [`crate::tracer::StructLogTracer`] that captures per-opcode logs
/// and the call tree. Used by `debug_traceCall` /
/// `debug_traceTransaction` / `trace_*` to surface EVM-level trace
/// data over JSON-RPC. Returns the trace alongside the outcome.
pub fn execute_trigger_with_tracer(
    stores: &VmStores,
    block: VmBlockEnv,
    contract: &TriggerSmartContract,
    energy_limit: u64,
    gas_cap_override: u64,
    tracer: crate::tracer::StructLogTracer,
) -> (
    VmOutcome,
    Vec<crate::internal_tx::InternalTxTrace>,
    crate::tracer::StructLogTracer,
) {
    execute_trigger_inner_with_tracer(
        stores,
        block,
        contract,
        energy_limit,
        Some(gas_cap_override),
        None,
        Some(tracer),
    )
}

/// As [`execute_trigger_with_gas_cap`] plus a wall-clock deadline.
/// The inspector polls `Instant::now()` periodically during execution
/// and halts the interpreter as soon as the deadline elapses. Returns
/// `VmOutcome::Timeout` when that happens. java-tron's
/// `vm.constantCallTimeoutMs` plumbing routes through this path.
///
/// `timeout_ms` is passed alongside the deadline so the `Timeout`
/// variant can report the budget that was exceeded — useful in the
/// JSON-RPC error message.
pub fn execute_trigger_with_deadline(
    stores: &VmStores,
    block: VmBlockEnv,
    contract: &TriggerSmartContract,
    energy_limit: u64,
    gas_cap_override: u64,
    deadline: std::time::Instant,
    timeout_ms: u64,
) -> (VmOutcome, Vec<crate::internal_tx::InternalTxTrace>) {
    execute_trigger_inner(
        stores,
        block,
        contract,
        energy_limit,
        Some(gas_cap_override),
        Some((deadline, timeout_ms)),
    )
}

fn execute_trigger_inner(
    stores: &VmStores,
    block: VmBlockEnv,
    contract: &TriggerSmartContract,
    energy_limit: u64,
    gas_cap_override: Option<u64>,
    deadline: Option<(std::time::Instant, u64)>,
) -> (VmOutcome, Vec<crate::internal_tx::InternalTxTrace>) {
    let owner_bytes = match parse_tron_address_to_evm(&contract.owner_address) {
        Ok(a) => a,
        Err(e) => return (VmOutcome::PreflightError(e), Vec::new()),
    };
    let target_bytes = match parse_tron_address_to_evm(&contract.contract_address) {
        Ok(a) => a,
        Err(e) => return (VmOutcome::PreflightError(e), Vec::new()),
    };

    // Top-level CALLTOKEN: perform the TRC-10 transfer (debit owner,
    // credit target) BEFORE the EVM runs. If the EVM later reverts /
    // halts, undo it. Mirrors java-tron's TVMContext setup.
    let top_level_token: Option<(i64, i64)> =
        if contract.call_token_value != 0 || contract.token_id != 0 {
            if contract.token_id <= 0 || contract.call_token_value < 0 {
                return (
                    VmOutcome::PreflightError(format!(
                        "invalid TRC-10 top-level token (id={}, value={})",
                        contract.token_id, contract.call_token_value
                    )),
                    Vec::new(),
                );
            }
            match apply_top_level_trc10(
                &stores.accounts,
                &contract.owner_address,
                &contract.contract_address,
                contract.token_id,
                contract.call_token_value,
            ) {
                Ok(_) => Some((contract.token_id, contract.call_token_value)),
                Err(e) => return (VmOutcome::PreflightError(e), Vec::new()),
            }
        } else {
            None
        };

    let mut tron_db = TronDatabase::new(
        Arc::clone(&stores.accounts),
        Arc::clone(&stores.code),
        Arc::clone(&stores.storage),
    );
    if let Some(idx) = &stores.block_index {
        tron_db = tron_db.with_block_index(Arc::clone(idx));
    }
    if let Some(c) = &stores.contracts {
        tron_db = tron_db.with_contracts(Arc::clone(c));
    }
    // Attach the staking stores so the state-mutating Stake 1.0 / 2.0
    // opcodes can write into them via the Host bridge. `votes` is the
    // only optional one — VOTEWITNESS quietly returns 0 when it's
    // missing; the other nine bridges depend on `dyn_props` /
    // `delegated_resources` which VmStores carries unconditionally.
    tron_db = tron_db.with_staking_stores(
        Arc::clone(&stores.dynamic_properties),
        stores.votes.as_ref().map(Arc::clone),
        Arc::clone(&stores.delegated_resources),
        Arc::clone(&stores.delegation),
    );
    let proposals = crate::proposals::ProposalSet::from_store(&stores.dynamic_properties);
    let spec = proposals.resolve_spec();
    let mut ctx = Context::mainnet()
        .with_db(tron_db)
        .modify_cfg_chained(|cfg| {
            cfg.spec = spec;
            // TRON fork: the opcode set comes from `spec` (proposal-resolved),
            // but the *energy* schedule is TRON's Frontier-era table with a
            // Frontier-pinned gas spec. Keep the two decoupled.
            cfg.gas_params = crate::tron_gas_params();
        });
    if let Some(cap) = gas_cap_override {
        ctx = ctx.modify_cfg_chained(|cfg| {
            cfg.tx_gas_limit_cap = Some(cap);
        });
    }
    let precompiles = TronPrecompiles::new(
        spec,
        Arc::clone(&stores.accounts),
        Arc::clone(&stores.witnesses),
        Arc::clone(&stores.contract_state),
        Arc::clone(&stores.dynamic_properties),
        Arc::clone(&stores.delegated_resources),
        Arc::clone(&stores.delegation),
        block.block_number,
        block.block_timestamp_ms,
        proposals,
    );
    let mut instructions = EthInstructions::<EthInterpreter, _>::new_mainnet_with_spec(spec);
    // TRON fork: replace the spec-adjusted static gas table with TRON's static
    // energy table (Frontier base — SLOAD 50, CALL 40, EXP base 10 … — with
    // MLOAD/MSTORE/MSTORE8 at base 1). Done before installing the TRON opcode
    // stubs so their gas entries (0xd0..0xd4) survive.
    *instructions.gas_table_mut() = crate::tron_static_gas_table();
    crate::evm::install_tron_opcode_stubs(&mut instructions, &proposals);
    let mut trc10_inspector = crate::trc10::Trc10Inspector::new(Arc::clone(&stores.accounts));
    if dynamic_energy_active(&stores.dynamic_properties) {
        trc10_inspector = trc10_inspector.with_dynamic_energy(
            Arc::clone(&stores.contract_state),
            Arc::clone(&stores.dynamic_properties),
        );
    }
    if let Some((id, val)) = top_level_token {
        trc10_inspector = trc10_inspector.with_top_level_token(id, val);
    }
    if let Some((dl, _)) = deadline {
        trc10_inspector = trc10_inspector.with_deadline(dl);
    }
    let mut evm = Evm {
        ctx,
        inspector: trc10_inspector,
        instruction: instructions,
        precompiles,
        frame_stack: FrameStack::new_prealloc(8),
    };

    let tx = match TxEnv::builder()
        .caller(owner_bytes)
        .kind(TxKind::Call(target_bytes))
        .value(U256::from(contract.call_value.max(0) as u64))
        .data(Bytes::from(contract.data.clone()))
        .gas_limit(energy_limit)
        .nonce(0)
        .gas_price(0)
        .build()
    {
        Ok(tx) => tx,
        Err(e) => return (VmOutcome::PreflightError(format!("TxEnv build: {e:?}")), Vec::new()),
    };

    let outcome = evm.inspect_tx_commit(tx);
    // If the EVM failed and we did a top-level TRC-10 transfer up front,
    // reverse it so the caller's asset_v2 balance is restored.
    let unwind_on_failure = |stores: &VmStores| {
        if let Some((id, val)) = top_level_token {
            let _ = apply_top_level_trc10(
                &stores.accounts,
                &contract.contract_address,
                &contract.owner_address,
                id,
                val,
            );
        }
    };
    // Deadline check has to happen before we move-out internal_txs from
    // the inspector, since `into_internal_txs` consumes it.
    let deadline_tripped = evm.inspector.deadline_exceeded();
    let timeout_budget_ms = deadline.map(|(_, ms)| ms).unwrap_or(0);
    let vm_outcome = match outcome {
        Ok(ExecutionResult::Success { output, gas, logs, .. }) => VmOutcome::Success {
            return_data: output.data().to_vec(),
            energy_used: gas.tx_gas_used(),
            logs: collect_vm_logs(logs),
        },
        Ok(ExecutionResult::Revert { output, gas, .. }) => {
            unwind_on_failure(stores);
            VmOutcome::Revert {
                return_data: output.to_vec(),
                energy_used: gas.tx_gas_used(),
            }
        }
        Ok(ExecutionResult::Halt { reason, gas, .. }) => {
            unwind_on_failure(stores);
            // If our inspector halted the VM because the deadline
            // elapsed, surface a clean Timeout outcome instead of the
            // generic FatalExternalError halt. This keeps the JSON-RPC
            // layer from having to interpret revm-specific halt strings.
            if deadline_tripped {
                VmOutcome::Timeout {
                    energy_used: gas.tx_gas_used(),
                    deadline_ms: timeout_budget_ms,
                }
            } else {
                VmOutcome::Halt {
                    reason: format!("{reason:?}"),
                    energy_used: gas.tx_gas_used(),
                }
            }
        }
        Err(e) => {
            unwind_on_failure(stores);
            VmOutcome::PreflightError(format!("{e:?}"))
        }
    };
    let traces = evm.inspector.into_internal_txs();
    (vm_outcome, traces)
}

/// Tracer-attached variant of [`execute_trigger_inner`]. Mirrors the
/// inner function but threads a [`crate::tracer::StructLogTracer`]
/// through and returns it alongside the outcome. Used only by the
/// debug/trace JSON-RPC paths.
fn execute_trigger_inner_with_tracer(
    stores: &VmStores,
    block: VmBlockEnv,
    contract: &TriggerSmartContract,
    energy_limit: u64,
    gas_cap_override: Option<u64>,
    deadline: Option<(std::time::Instant, u64)>,
    tracer: Option<crate::tracer::StructLogTracer>,
) -> (
    VmOutcome,
    Vec<crate::internal_tx::InternalTxTrace>,
    crate::tracer::StructLogTracer,
) {
    // We need a sentinel tracer when caller passes None so the
    // return type can stay non-Option. Callers that didn't ask for
    // tracing get an empty tracer back; cheap to discard.
    let tracer = tracer.unwrap_or_else(|| {
        crate::tracer::StructLogTracer::new(crate::tracer::TracerOptions::default())
    });
    let owner_bytes = match parse_tron_address_to_evm(&contract.owner_address) {
        Ok(a) => a,
        Err(e) => return (VmOutcome::PreflightError(e), Vec::new(), tracer),
    };
    let target_bytes = match parse_tron_address_to_evm(&contract.contract_address) {
        Ok(a) => a,
        Err(e) => return (VmOutcome::PreflightError(e), Vec::new(), tracer),
    };
    let top_level_token: Option<(i64, i64)> =
        if contract.call_token_value != 0 || contract.token_id != 0 {
            if contract.token_id <= 0 || contract.call_token_value < 0 {
                return (
                    VmOutcome::PreflightError(format!(
                        "invalid TRC-10 top-level token (id={}, value={})",
                        contract.token_id, contract.call_token_value
                    )),
                    Vec::new(),
                    tracer,
                );
            }
            match apply_top_level_trc10(
                &stores.accounts,
                &contract.owner_address,
                &contract.contract_address,
                contract.token_id,
                contract.call_token_value,
            ) {
                Ok(_) => Some((contract.token_id, contract.call_token_value)),
                Err(e) => return (VmOutcome::PreflightError(e), Vec::new(), tracer),
            }
        } else {
            None
        };

    let mut tron_db = TronDatabase::new(
        Arc::clone(&stores.accounts),
        Arc::clone(&stores.code),
        Arc::clone(&stores.storage),
    );
    if let Some(idx) = &stores.block_index {
        tron_db = tron_db.with_block_index(Arc::clone(idx));
    }
    if let Some(c) = &stores.contracts {
        tron_db = tron_db.with_contracts(Arc::clone(c));
    }
    // Attach the staking stores so the state-mutating Stake 1.0 / 2.0
    // opcodes can write into them via the Host bridge. `votes` is the
    // only optional one — VOTEWITNESS quietly returns 0 when it's
    // missing; the other nine bridges depend on `dyn_props` /
    // `delegated_resources` which VmStores carries unconditionally.
    tron_db = tron_db.with_staking_stores(
        Arc::clone(&stores.dynamic_properties),
        stores.votes.as_ref().map(Arc::clone),
        Arc::clone(&stores.delegated_resources),
        Arc::clone(&stores.delegation),
    );
    let proposals = crate::proposals::ProposalSet::from_store(&stores.dynamic_properties);
    let spec = proposals.resolve_spec();
    let mut ctx = Context::mainnet()
        .with_db(tron_db)
        .modify_cfg_chained(|cfg| {
            cfg.spec = spec;
            // TRON fork: the opcode set comes from `spec` (proposal-resolved),
            // but the *energy* schedule is TRON's Frontier-era table with a
            // Frontier-pinned gas spec. Keep the two decoupled.
            cfg.gas_params = crate::tron_gas_params();
        });
    if let Some(cap) = gas_cap_override {
        ctx = ctx.modify_cfg_chained(|cfg| {
            cfg.tx_gas_limit_cap = Some(cap);
        });
    }
    let precompiles = TronPrecompiles::new(
        spec,
        Arc::clone(&stores.accounts),
        Arc::clone(&stores.witnesses),
        Arc::clone(&stores.contract_state),
        Arc::clone(&stores.dynamic_properties),
        Arc::clone(&stores.delegated_resources),
        Arc::clone(&stores.delegation),
        block.block_number,
        block.block_timestamp_ms,
        proposals,
    );
    let mut instructions = EthInstructions::<EthInterpreter, _>::new_mainnet_with_spec(spec);
    // TRON fork: replace the spec-adjusted static gas table with TRON's static
    // energy table (Frontier base — SLOAD 50, CALL 40, EXP base 10 … — with
    // MLOAD/MSTORE/MSTORE8 at base 1). Done before installing the TRON opcode
    // stubs so their gas entries (0xd0..0xd4) survive.
    *instructions.gas_table_mut() = crate::tron_static_gas_table();
    crate::evm::install_tron_opcode_stubs(&mut instructions, &proposals);
    let mut trc10_inspector =
        crate::trc10::Trc10Inspector::new(Arc::clone(&stores.accounts)).with_tracer(tracer);
    if dynamic_energy_active(&stores.dynamic_properties) {
        trc10_inspector = trc10_inspector.with_dynamic_energy(
            Arc::clone(&stores.contract_state),
            Arc::clone(&stores.dynamic_properties),
        );
    }
    if let Some((id, val)) = top_level_token {
        trc10_inspector = trc10_inspector.with_top_level_token(id, val);
    }
    if let Some((dl, _)) = deadline {
        trc10_inspector = trc10_inspector.with_deadline(dl);
    }
    let mut evm = Evm {
        ctx,
        inspector: trc10_inspector,
        instruction: instructions,
        precompiles,
        frame_stack: FrameStack::new_prealloc(8),
    };

    let tx = match TxEnv::builder()
        .caller(owner_bytes)
        .kind(TxKind::Call(target_bytes))
        .value(U256::from(contract.call_value.max(0) as u64))
        .data(Bytes::from(contract.data.clone()))
        .gas_limit(energy_limit)
        .nonce(0)
        .gas_price(0)
        .build()
    {
        Ok(tx) => tx,
        Err(e) => {
            let captured = evm.inspector.take_tracer().unwrap_or_else(|| {
                crate::tracer::StructLogTracer::new(crate::tracer::TracerOptions::default())
            });
            return (
                VmOutcome::PreflightError(format!("TxEnv build: {e:?}")),
                Vec::new(),
                captured,
            );
        }
    };

    let outcome = evm.inspect_tx_commit(tx);
    let unwind_on_failure = |stores: &VmStores| {
        if let Some((id, val)) = top_level_token {
            let _ = apply_top_level_trc10(
                &stores.accounts,
                &contract.contract_address,
                &contract.owner_address,
                id,
                val,
            );
        }
    };
    let deadline_tripped = evm.inspector.deadline_exceeded();
    let timeout_budget_ms = deadline.map(|(_, ms)| ms).unwrap_or(0);
    let vm_outcome = match outcome {
        Ok(ExecutionResult::Success { output, gas, logs, .. }) => VmOutcome::Success {
            return_data: output.data().to_vec(),
            energy_used: gas.tx_gas_used(),
            logs: collect_vm_logs(logs),
        },
        Ok(ExecutionResult::Revert { output, gas, .. }) => {
            unwind_on_failure(stores);
            VmOutcome::Revert {
                return_data: output.to_vec(),
                energy_used: gas.tx_gas_used(),
            }
        }
        Ok(ExecutionResult::Halt { reason, gas, .. }) => {
            unwind_on_failure(stores);
            if deadline_tripped {
                VmOutcome::Timeout {
                    energy_used: gas.tx_gas_used(),
                    deadline_ms: timeout_budget_ms,
                }
            } else {
                VmOutcome::Halt {
                    reason: format!("{reason:?}"),
                    energy_used: gas.tx_gas_used(),
                }
            }
        }
        Err(e) => {
            unwind_on_failure(stores);
            VmOutcome::PreflightError(format!("{e:?}"))
        }
    };
    let captured_tracer = evm.inspector.take_tracer().unwrap_or_else(|| {
        crate::tracer::StructLogTracer::new(crate::tracer::TracerOptions::default())
    });
    let traces = evm.inspector.into_internal_txs();
    (vm_outcome, traces, captured_tracer)
}

/// Convert revm's `Vec<Log>` into our own [`VmLog`] form. Splits the
/// `LogData` accessor pattern off so callers never touch alloy types.
fn collect_vm_logs(logs: Vec<revm::primitives::Log>) -> Vec<VmLog> {
    logs.into_iter()
        .map(|log| {
            let address: [u8; 20] = log.address.into();
            let topics: Vec<[u8; 32]> = log.data.topics().iter().map(|t| t.0).collect();
            let data = log.data.data.to_vec();
            VmLog { address, topics, data }
        })
        .collect()
}

/// Debit `from`'s `asset_v2[token_id]` by `value` and credit `to`'s
/// by the same. Used for the top-level CALLTOKEN side effect. Errors
/// out if `from` doesn't have enough Zen-style asset balance.
fn apply_top_level_trc10(
    accounts: &Arc<tron_chainbase::AccountStore>,
    from: &[u8],
    to: &[u8],
    token_id: i64,
    value: i64,
) -> Result<(), String> {
    if value == 0 {
        return Ok(());
    }
    if from.len() != 21 || to.len() != 21 {
        return Err("CALLTOKEN addresses must be 21 bytes".into());
    }
    use tron_crypto::address::Address;
    let key = token_id.to_string();
    let mut from_buf = [0u8; 21];
    from_buf.copy_from_slice(from);
    let mut to_buf = [0u8; 21];
    to_buf.copy_from_slice(to);
    let from_addr = Address::from_raw(from_buf);
    let to_addr = Address::from_raw(to_buf);

    let mut from_acct = accounts
        .get(&from_addr)
        .map_err(|e| format!("read sender: {e:?}"))?
        .ok_or_else(|| "CALLTOKEN sender account missing".to_string())?;
    let from_balance = *from_acct.asset_v2.get(&key).unwrap_or(&0);
    if from_balance < value {
        return Err(format!(
            "CALLTOKEN sender has {from_balance} of token {token_id}, needs {value}"
        ));
    }
    from_acct.asset_v2.insert(key.clone(), from_balance - value);
    accounts
        .put(&from_addr, &from_acct)
        .map_err(|e| format!("write sender: {e:?}"))?;

    let mut to_acct = accounts
        .get(&to_addr)
        .map_err(|e| format!("read target: {e:?}"))?
        .unwrap_or_else(|| tron_proto::Account {
            address: to.to_vec(),
            ..Default::default()
        });
    let to_balance = *to_acct.asset_v2.get(&key).unwrap_or(&0);
    let new_to = to_balance
        .checked_add(value)
        .ok_or_else(|| "CALLTOKEN target balance overflow".to_string())?;
    to_acct.asset_v2.insert(key, new_to);
    accounts
        .put(&to_addr, &to_acct)
        .map_err(|e| format!("write target: {e:?}"))?;
    Ok(())
}

/// Execute a `CreateSmartContract` through the TVM.
///
/// TRON's contract-address derivation is `0x41 || keccak256(owner || tx_id)[12..]`.
/// This differs from Ethereum's `keccak256(rlp([sender, nonce]))[12..]`,
/// so we don't use revm's `TxKind::Create` directly — instead we:
///
/// 1. Compute the TRON contract address.
/// 2. Pre-install an `Account` at that address whose code is the init
///    bytecode. (During init-code execution the `ADDRESS` opcode must
///    return the contract's own address — placing the code there makes
///    that natural.)
/// 3. CALL that address with empty input. Init code runs; its `RETURN`
///    value is the runtime bytecode.
/// 4. Overwrite the account's code with the runtime bytecode and the
///    code-hash with `keccak256(runtime_code)`.
///
/// **Gas accounting**: EIP-170 per-byte code-deposit cost
/// (`200 × runtime_code.len()`) IS charged after init code returns —
/// see the `CODE_DEPOSIT_GAS_PER_BYTE` block below. Matches java-tron
/// + revm's standard CREATE path. If the deposit pushes total gas
/// past `energy_limit`, the deployment halts (`Halt`) and the
/// pre-installed account is deleted, mirroring EIP-3541-style cleanup.
pub fn execute_create(
    stores: &VmStores,
    block: VmBlockEnv,
    contract: &CreateSmartContract,
    tx_id: &[u8; 32],
    energy_limit: u64,
) -> VmOutcome {
    execute_create_with_trace(stores, block, contract, tx_id, energy_limit).0
}

/// Same as [`execute_create`], but also returns internal-transaction
/// traces captured by the inspector. The top-level frame is a CALL (we
/// pre-install init code and call it), so every CREATE/CREATE2 entry
/// in the returned trace is from a nested deployment.
pub fn execute_create_with_trace(
    stores: &VmStores,
    block: VmBlockEnv,
    contract: &CreateSmartContract,
    tx_id: &[u8; 32],
    energy_limit: u64,
) -> (VmOutcome, Vec<crate::internal_tx::InternalTxTrace>) {
    // Reject CALLTOKEN-on-CREATE for symmetry with execute_trigger.
    if contract.call_token_value != 0 || contract.token_id != 0 {
        return (
            VmOutcome::CallTokenIgnored {
                token_id: contract.token_id,
                call_token_value: contract.call_token_value,
            },
            Vec::new(),
        );
    }

    let Some(smart_contract) = &contract.new_contract else {
        return (
            VmOutcome::PreflightError("CreateSmartContract.new_contract missing".to_string()),
            Vec::new(),
        );
    };
    let owner_bytes = match parse_tron_address_to_evm(&contract.owner_address) {
        Ok(a) => a,
        Err(e) => return (VmOutcome::PreflightError(e), Vec::new()),
    };

    // Derive the TRON contract address from `owner_address || tx_id`.
    // java-tron: `Hash.sha3omit12(owner || tx_id)` → 20 bytes, prefixed 0x41.
    let mut hash_input = Vec::with_capacity(21 + 32);
    hash_input.extend_from_slice(&contract.owner_address);
    hash_input.extend_from_slice(tx_id);
    let h = tron_crypto::hash::keccak256(&hash_input);
    let mut tron_addr = [0u8; 21];
    tron_addr[0] = 0x41;
    tron_addr[1..].copy_from_slice(&h[12..]);
    let tron_contract_addr =
        tron_crypto::address::Address::from_raw(tron_addr);
    let evm_contract_addr = EvmAddress::from_slice(&tron_addr[1..]);

    // Pre-install Account at the TRON address with init code. Code is keyed by
    // ADDRESS (java-tron's `saveCode(address, ...)`), so `basic_ref` resolves
    // it during constructor execution.
    let init_code = &smart_contract.bytecode;
    let init_hash = tron_crypto::hash::keccak256(init_code);
    if let Err(e) = stores.code.put(tron_contract_addr.as_bytes(), init_code) {
        return (
            VmOutcome::PreflightError(format!("write init code: {e:?}")),
            Vec::new(),
        );
    }
    if let Err(e) = stores.accounts.put(
        &tron_contract_addr,
        &tron_proto::Account {
            address: tron_contract_addr.as_bytes().to_vec(),
            balance: smart_contract.call_value.max(0),
            code: init_code.clone(),
            code_hash: init_hash.to_vec(),
            ..Default::default()
        },
    ) {
        return (
            VmOutcome::PreflightError(format!("install contract account: {e:?}")),
            Vec::new(),
        );
    }

    // CALL the just-installed account; init code runs.
    let mut tron_db = TronDatabase::new(
        Arc::clone(&stores.accounts),
        Arc::clone(&stores.code),
        Arc::clone(&stores.storage),
    );
    if let Some(idx) = &stores.block_index {
        tron_db = tron_db.with_block_index(Arc::clone(idx));
    }
    if let Some(c) = &stores.contracts {
        tron_db = tron_db.with_contracts(Arc::clone(c));
    }
    // Attach the staking stores so the state-mutating Stake 1.0 / 2.0
    // opcodes can write into them via the Host bridge. `votes` is the
    // only optional one — VOTEWITNESS quietly returns 0 when it's
    // missing; the other nine bridges depend on `dyn_props` /
    // `delegated_resources` which VmStores carries unconditionally.
    tron_db = tron_db.with_staking_stores(
        Arc::clone(&stores.dynamic_properties),
        stores.votes.as_ref().map(Arc::clone),
        Arc::clone(&stores.delegated_resources),
        Arc::clone(&stores.delegation),
    );
    let proposals = crate::proposals::ProposalSet::from_store(&stores.dynamic_properties);
    let spec = proposals.resolve_spec();
    let ctx = Context::mainnet()
        .with_db(tron_db)
        .modify_cfg_chained(|cfg| {
            cfg.spec = spec;
            // TRON fork: the opcode set comes from `spec` (proposal-resolved),
            // but the *energy* schedule is TRON's Frontier-era table with a
            // Frontier-pinned gas spec. Keep the two decoupled.
            cfg.gas_params = crate::tron_gas_params();
        });
    let precompiles = TronPrecompiles::new(
        spec,
        Arc::clone(&stores.accounts),
        Arc::clone(&stores.witnesses),
        Arc::clone(&stores.contract_state),
        Arc::clone(&stores.dynamic_properties),
        Arc::clone(&stores.delegated_resources),
        Arc::clone(&stores.delegation),
        block.block_number,
        block.block_timestamp_ms,
        proposals,
    );
    let mut instructions = EthInstructions::<EthInterpreter, _>::new_mainnet_with_spec(spec);
    // TRON fork: replace the spec-adjusted static gas table with TRON's static
    // energy table (Frontier base — SLOAD 50, CALL 40, EXP base 10 … — with
    // MLOAD/MSTORE/MSTORE8 at base 1). Done before installing the TRON opcode
    // stubs so their gas entries (0xd0..0xd4) survive.
    *instructions.gas_table_mut() = crate::tron_static_gas_table();
    crate::evm::install_tron_opcode_stubs(&mut instructions, &proposals);
    let mut trc10 = crate::trc10::Trc10Inspector::new(Arc::clone(&stores.accounts));
    if dynamic_energy_active(&stores.dynamic_properties) {
        trc10 = trc10.with_dynamic_energy(
            Arc::clone(&stores.contract_state),
            Arc::clone(&stores.dynamic_properties),
        );
    }
    let mut evm = Evm {
        ctx,
        inspector: trc10,
        instruction: instructions,
        precompiles,
        frame_stack: FrameStack::new_prealloc(8),
    };
    let tx = match TxEnv::builder()
        .caller(owner_bytes)
        .kind(TxKind::Call(evm_contract_addr))
        .value(U256::from(smart_contract.call_value.max(0) as u64))
        .data(Bytes::new())
        .gas_limit(energy_limit)
        .nonce(0)
        .gas_price(0)
        .build()
    {
        Ok(tx) => tx,
        Err(e) => {
            return (
                VmOutcome::PreflightError(format!("TxEnv build: {e:?}")),
                Vec::new(),
            )
        }
    };

    let exec = match evm.inspect_tx_commit(tx) {
        Ok(r) => r,
        Err(e) => {
            let traces = evm.inspector.into_internal_txs();
            return (VmOutcome::PreflightError(format!("{e:?}")), traces);
        }
    };

    let vm_outcome = match exec {
        ExecutionResult::Success { output, gas, logs, .. } => {
            // The init code's RETURN value is the runtime bytecode.
            let runtime_code = output.data().to_vec();
            // EIP-170 per-byte storage cost for the runtime code: 200
            // gas × code_size. Charged AFTER init code returns. If the
            // remaining gas budget can't pay this, treat the deployment
            // as halted (EIP-3541-style) — matches java-tron's behaviour
            // and revm's standard CREATE path.
            const CODE_DEPOSIT_GAS_PER_BYTE: u64 = 200;
            let deposit_cost = (runtime_code.len() as u64)
                .saturating_mul(CODE_DEPOSIT_GAS_PER_BYTE);
            let already_used = gas.tx_gas_used();
            let total_with_deposit = already_used.saturating_add(deposit_cost);
            if total_with_deposit > energy_limit {
                stores
                    .accounts
                    .delete(&tron_contract_addr)
                    .expect("db error in execute_create cleaning up after code-deposit OOG");
                VmOutcome::Halt {
                    reason: format!(
                        "out of gas charging code-deposit ({} bytes × 200 = {} gas; \
                         {} already used, budget {})",
                        runtime_code.len(),
                        deposit_cost,
                        already_used,
                        energy_limit
                    ),
                    energy_used: energy_limit,
                }
            } else {
                let runtime_hash = if runtime_code.is_empty() {
                    vec![]
                } else {
                    tron_crypto::hash::keccak256(&runtime_code).to_vec()
                };
                if !runtime_code.is_empty() {
                    // Runtime code keyed by ADDRESS (overwrites the init code
                    // pre-installed at the same key), matching java-tron.
                    stores
                        .code
                        .put(tron_contract_addr.as_bytes(), &runtime_code)
                        .expect("db error in execute_create writing runtime code");
                }
                // Replace init code on the Account with the runtime code.
                if let Ok(Some(mut acct)) = stores.accounts.get(&tron_contract_addr) {
                    acct.code = runtime_code;
                    acct.code_hash = runtime_hash;
                    stores
                        .accounts
                        .put(&tron_contract_addr, &acct)
                        .expect("db error in execute_create finalizing contract account");
                }
                VmOutcome::Success {
                    return_data: tron_contract_addr.as_bytes().to_vec(),
                    energy_used: total_with_deposit,
                    logs: collect_vm_logs(logs),
                }
            }
        }
        ExecutionResult::Revert { output, gas, .. } => {
            // Init code reverted — clean up the pre-installed Account
            // so deployment doesn't leak.
            stores
                .accounts
                .delete(&tron_contract_addr)
                .expect("db error in execute_create cleaning up after Revert");
            VmOutcome::Revert {
                return_data: output.to_vec(),
                energy_used: gas.tx_gas_used(),
            }
        }
        ExecutionResult::Halt { reason, gas, .. } => {
            stores
                .accounts
                .delete(&tron_contract_addr)
                .expect("db error in execute_create cleaning up after Halt");
            VmOutcome::Halt {
                reason: format!("{reason:?}"),
                energy_used: gas.tx_gas_used(),
            }
        }
    };
    let traces = evm.inspector.into_internal_txs();
    (vm_outcome, traces)
}

/// Convert a raw TRON address (21 bytes with `0x41` prefix) into a
/// 20-byte EVM address. Errors on wrong length.
fn parse_tron_address_to_evm(raw: &[u8]) -> Result<EvmAddress, String> {
    if raw.len() != 21 {
        return Err(format!(
            "TRON address must be 21 bytes; got {}",
            raw.len()
        ));
    }
    if raw[0] != 0x41 {
        return Err(format!(
            "TRON address prefix must be 0x41; got 0x{:02x}",
            raw[0]
        ));
    }
    Ok(EvmAddress::from_slice(&raw[1..]))
}

/// Suppress unused-import warning until we add a `CreateSmartContract`
/// path in a follow-up.
#[allow(dead_code)]
fn _evm_addr_dance(a: EvmAddress) -> tron_crypto::address::Address {
    evm_to_tron_address(&a)
}
