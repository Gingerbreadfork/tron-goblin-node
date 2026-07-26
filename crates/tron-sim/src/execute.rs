//! The bundle executor — runs a [`SimRequest`] against a [`ForkOverlay`],
//! producing a [`SimResult`].
//!
//! Each synthetic block: apply the block's account overrides to the overlay,
//! derive the block env (overrides, else +1 block / +3s from the synthetic
//! head), then run the calls in order against the overlay's `VmStores`. Writes
//! accumulate in the overlay — call N sees call N-1's state, block N+1 sees
//! block N's — and nothing ever commits to disk. Every call gets a
//! deterministic synthetic tx id (`sha256(fork_id ‖ block_index ‖
//! call_index)`), so a replay of the same request over the same fork state is
//! byte-identical, and created addresses are deterministic.

use tron_crypto::address::Address;
use tron_crypto::hash::sha256;
use tron_proto::{CreateSmartContract, SmartContract, TriggerSmartContract};
use tron_tvm::execute::{
    derive_top_level_contract_address, execute_create_with_trace, execute_create_with_tracer,
    execute_trigger_with_gas_cap_tx_id, execute_trigger_with_tracer_tx_id, VmBlockEnv, VmLog,
    VmOutcome,
};
use tron_tvm::internal_tx::InternalTxTrace;
use tron_tvm::tracer::{CallFrame, StructLog, StructLogTracer, TracerOptions};

use crate::config::SimConfig;
use crate::diff::DecodedStateDiff;
use crate::error::SimError;
use crate::overlay::{BaseBlock, ForkOverlay};
use crate::request::{CallSpec, DiffLevel, SimRequest, TraceLevel};
use crate::result::{Basis, CallResult, CallStatus, SimBlockResult, SimResult, VmLogOut};

/// Run a bundle against `overlay`. `fork_id` seeds the deterministic
/// synthetic tx ids (use `[0u8; 16]` for an ephemeral one-shot fork; a named
/// fork session passes its uuid bytes). `start_head` is the synthetic head
/// `(number, timestamp_ms)` block numbering continues from — `None` starts
/// from the overlay's seed head (ephemeral bundles); a fork session passes
/// its advancing head so successive calls don't reuse block numbers.
pub fn run_bundle(
    overlay: &mut ForkOverlay,
    req: &SimRequest,
    cfg: &SimConfig,
    fork_id: [u8; 16],
    start_head: Option<(i64, i64)>,
) -> Result<SimResult, SimError> {
    if req.blocks.len() > cfg.max_blocks_per_bundle {
        return Err(SimError::Backend(format!(
            "bundle has {} blocks > cap {}",
            req.blocks.len(),
            cfg.max_blocks_per_bundle
        )));
    }
    let total_calls: usize = req.blocks.iter().map(|b| b.calls.len()).sum();
    if total_calls > cfg.max_calls_per_bundle {
        return Err(SimError::Backend(format!(
            "bundle has {total_calls} calls > cap {}",
            cfg.max_calls_per_bundle
        )));
    }

    let mut warnings = Vec::new();
    let (mut head_num, mut head_ts_ms) = start_head.unwrap_or_else(|| overlay.seed_head());
    let mut block_results = Vec::with_capacity(req.blocks.len());

    for block in &req.blocks {
        // Apply this block's account overrides to the current overlay top.
        {
            let vm = overlay.vm_stores();
            warnings.extend(block.overrides.apply(&vm, cfg.max_state_override_slots)?);
        }
        // Enforce the per-fork overlay cap right after applying overrides, so a
        // call-less block with large overrides can't bypass the per-call check.
        let keys = overlay.overlay_keys();
        if keys > cfg.max_overlay_keys {
            return Err(SimError::OverlayCapExceeded { keys, limit: cfg.max_overlay_keys });
        }

        // Block env: overrides, else +1 block / +3s (TRON block time).
        let bov = block.overrides.block;
        let number = bov.and_then(|b| b.number).unwrap_or_else(|| head_num.saturating_add(1));
        if number <= head_num {
            return Err(SimError::Backend(format!(
                "synthetic block numbers must strictly increase (got {number} after {head_num})"
            )));
        }
        let ts_ms = match bov.and_then(|b| b.time_s) {
            Some(s) => s.saturating_mul(1000),
            None => head_ts_ms.saturating_add(3000),
        };
        if ts_ms < head_ts_ms {
            warnings.push(format!(
                "synthetic block {number} timestamp ({}s) is earlier than the previous block",
                ts_ms / 1000
            ));
        }
        let beneficiary = bov.and_then(|b| b.coinbase).unwrap_or([0u8; 20]);
        let block_env = VmBlockEnv {
            block_number: number,
            block_timestamp_ms: ts_ms,
            beneficiary,
        };
        head_num = number;
        head_ts_ms = ts_ms;

        let mut call_results = Vec::with_capacity(block.calls.len());
        let mut block_energy: u64 = 0;
        for (ci, call) in block.calls.iter().enumerate() {
            // Enforce the per-fork overlay cap before growing it further.
            let keys = overlay.overlay_keys();
            if keys > cfg.max_overlay_keys {
                return Err(SimError::OverlayCapExceeded { keys, limit: cfg.max_overlay_keys });
            }

            let tx_id = synthetic_tx_id(&fork_id, number, ci);
            let requested = call_energy(call).or(req.energy_cap);
            let energy = cfg.resolve_energy(requested);

            // Per-call diff → checkpoint so we can diff just this call.
            let cp = if req.return_state_diff == DiffLevel::PerCall {
                Some(overlay.checkpoint())
            } else {
                None
            };
            let vm = overlay.vm_stores();
            let mut result = run_one_call(&vm, block_env, call, energy, req.trace, tx_id, cfg);
            block_energy = block_energy.saturating_add(result.energy_used);
            if let Some(cp) = cp {
                result.state_diff = Some(DecodedStateDiff::from_raw(overlay.diff_since(cp)?));
            }
            call_results.push(result);
        }

        block_results.push(SimBlockResult {
            number,
            timestamp_ms: ts_ms,
            energy_used: block_energy,
            calls: call_results,
        });
    }

    let state_diff = if req.return_state_diff != DiffLevel::None {
        Some(DecodedStateDiff::from_raw(overlay.cumulative_diff()?))
    } else {
        None
    };

    let base_block = match overlay.base() {
        BaseBlock::Height(h) => h,
        BaseBlock::Latest => overlay.seed_head().0,
    };
    // selfCheck (parity re-run vs recorded receipts) is performed by the RPC
    // layer, which holds the block + receipt stores; the engine only executes
    // the requested bundle.
    let basis = Basis {
        base_block,
        mode: "vm",
        // The caller (which holds the archive reader) fills coverage in.
        archive_coverage: None,
        granularity: "block-boundary",
        warnings: warnings.clone(),
    };

    Ok(SimResult { basis, blocks: block_results, state_diff, warnings })
}

/// `sha256(fork_id ‖ block_number_be ‖ call_index_be)` — deterministic per
/// (fork, synthetic block number, call). Using the synthetic block NUMBER
/// (which advances monotonically across a fork session's calls, since each
/// `forkCall` continues from the fork's head) rather than a bundle-local
/// index keeps ids unique across successive `forkCall`s — so two deploys in
/// different calls of the same session never collide on the derived contract
/// address. Ephemeral bundles still get identical ids on replay (same base ⇒
/// same block numbers).
fn synthetic_tx_id(fork_id: &[u8; 16], block_number: i64, call_index: usize) -> [u8; 32] {
    let mut buf = Vec::with_capacity(16 + 8 + 8);
    buf.extend_from_slice(fork_id);
    buf.extend_from_slice(&block_number.to_be_bytes());
    buf.extend_from_slice(&(call_index as u64).to_be_bytes());
    sha256(&buf)
}

fn call_energy(call: &CallSpec) -> Option<u64> {
    match call {
        CallSpec::Trigger { energy, .. } => *energy,
        CallSpec::Create { energy, .. } => *energy,
    }
}

fn run_one_call(
    vm: &tron_tvm::execute::VmStores,
    block_env: VmBlockEnv,
    call: &CallSpec,
    energy: u64,
    trace: TraceLevel,
    tx_id: [u8; 32],
    cfg: &SimConfig,
) -> CallResult {
    // Lift revm's tx-gas cap to at least the config ceiling so a large
    // energy budget isn't rejected (mirrors dispatch_constant_trigger).
    let gas_cap = energy.max(cfg.energy_cap);
    // Per-call wall-clock deadline (DoS guard) — belt-and-suspenders over the
    // energy cap. Applied to trigger calls (the runaway vector, arbitrary
    // contract code); creates are bounded by the energy budget. 0 disables it.
    let deadline = (cfg.call_timeout_ms > 0).then(|| {
        (
            std::time::Instant::now()
                + std::time::Duration::from_millis(cfg.call_timeout_ms),
            cfg.call_timeout_ms,
        )
    });
    match call {
        CallSpec::Trigger {
            from,
            to,
            value,
            data,
            token_id,
            token_value,
            ..
        } => {
            let trigger = TriggerSmartContract {
                owner_address: from.as_bytes().to_vec(),
                contract_address: to.as_bytes().to_vec(),
                call_value: *value,
                data: data.clone(),
                call_token_value: *token_value,
                token_id: *token_id,
            };
            match trace {
                TraceLevel::None => {
                    let (outcome, traces, penalty) = execute_trigger_with_gas_cap_tx_id(
                        vm, block_env, &trigger, energy, gas_cap, deadline, tx_id,
                    );
                    build_call_result(outcome, penalty, &traces, &tx_id, None, Vec::new(), Vec::new())
                }
                TraceLevel::CallTree | TraceLevel::Full => {
                    let tracer = StructLogTracer::new(tracer_options(trace, cfg));
                    let (outcome, traces, penalty, tracer) = execute_trigger_with_tracer_tx_id(
                        vm, block_env, &trigger, energy, gas_cap, deadline, tracer, tx_id,
                    );
                    let truncated = tracer.logs_truncated();
                    let (struct_logs, frames) = tracer.into_outputs();
                    let struct_logs = keep_struct_logs(trace, struct_logs);
                    let mut r =
                        build_call_result(outcome, penalty, &traces, &tx_id, None, frames, struct_logs);
                    r.struct_logs_truncated = truncated;
                    r
                }
            }
        }
        CallSpec::Create {
            from,
            init_code,
            value,
            consume_user_resource_percent,
            name,
            token_id,
            token_value,
            ..
        } => {
            let create = CreateSmartContract {
                owner_address: from.as_bytes().to_vec(),
                new_contract: Some(SmartContract {
                    origin_address: from.as_bytes().to_vec(),
                    bytecode: init_code.clone(),
                    call_value: *value,
                    consume_user_resource_percent: *consume_user_resource_percent,
                    name: name.clone(),
                    ..Default::default()
                }),
                call_token_value: *token_value,
                token_id: *token_id,
            };
            let contract_addr =
                Address::from_raw(derive_top_level_contract_address(&tx_id, from.as_bytes()));
            let mut result = match trace {
                TraceLevel::None => {
                    let (outcome, traces, penalty) =
                        execute_create_with_trace(vm, block_env, &create, &tx_id, energy);
                    build_call_result(
                        outcome,
                        penalty,
                        &traces,
                        &tx_id,
                        Some(contract_addr),
                        Vec::new(),
                        Vec::new(),
                    )
                }
                TraceLevel::CallTree | TraceLevel::Full => {
                    let tracer = StructLogTracer::new(tracer_options(trace, cfg));
                    let (outcome, traces, penalty, tracer) =
                        execute_create_with_tracer(vm, block_env, &create, &tx_id, energy, tracer);
                    let truncated = tracer.logs_truncated();
                    let (struct_logs, frames) = tracer.into_outputs();
                    let struct_logs = keep_struct_logs(trace, struct_logs);
                    let mut r = build_call_result(
                        outcome,
                        penalty,
                        &traces,
                        &tx_id,
                        Some(contract_addr),
                        frames,
                        struct_logs,
                    );
                    r.struct_logs_truncated = truncated;
                    r
                }
            };
            // A successful create returns the deployed address as its VM
            // return data; report the address via `contract_address` and blank
            // the return data (matching geth/eth_simulate's create shape).
            if result.status == CallStatus::Success {
                result.return_data.clear();
            }
            result
        }
    }
}

fn tracer_options(trace: TraceLevel, cfg: &SimConfig) -> TracerOptions {
    TracerOptions {
        call_tracer_only: matches!(trace, TraceLevel::CallTree),
        max_logs: cfg.max_struct_logs,
        ..Default::default()
    }
}

fn keep_struct_logs(trace: TraceLevel, logs: Vec<StructLog>) -> Vec<StructLog> {
    if matches!(trace, TraceLevel::Full) {
        logs
    } else {
        Vec::new()
    }
}

#[allow(clippy::too_many_arguments)]
fn build_call_result(
    outcome: VmOutcome,
    energy_penalty: u64,
    traces: &[InternalTxTrace],
    tx_id: &[u8; 32],
    contract_address: Option<Address>,
    call_frames: Vec<CallFrame>,
    struct_logs: Vec<StructLog>,
) -> CallResult {
    let internal_transactions = traces.iter().map(|t| t.to_proto(tx_id)).collect();
    let (status, return_data, energy_used, logs, error, addr) = match outcome {
        VmOutcome::Success { return_data, energy_used, logs } => {
            (CallStatus::Success, return_data, energy_used, map_logs(logs), None, contract_address)
        }
        VmOutcome::Revert { return_data, energy_used } => (
            CallStatus::Revert,
            return_data,
            energy_used,
            Vec::new(),
            Some("execution reverted".to_string()),
            None,
        ),
        VmOutcome::TransferFailed { energy_used } => (
            CallStatus::TransferFailed,
            Vec::new(),
            energy_used,
            Vec::new(),
            Some("execution reverted: transfer failed".to_string()),
            None,
        ),
        VmOutcome::Halt { reason, result, energy_used } => (
            CallStatus::Halt(format!("{result:?}")),
            Vec::new(),
            energy_used,
            Vec::new(),
            Some(reason),
            None,
        ),
        VmOutcome::PreflightError(msg) => {
            (CallStatus::Error, Vec::new(), 0, Vec::new(), Some(msg), None)
        }
        VmOutcome::Timeout { deadline_ms, energy_used } => (
            CallStatus::Timeout,
            Vec::new(),
            energy_used,
            Vec::new(),
            Some(format!("call timed out after {deadline_ms}ms")),
            None,
        ),
        VmOutcome::CallTokenIgnored { .. } => (
            CallStatus::Error,
            Vec::new(),
            0,
            Vec::new(),
            Some("top-level CALLTOKEN not executed".to_string()),
            None,
        ),
    };
    CallResult {
        status,
        return_data,
        energy_used,
        energy_penalty,
        logs,
        contract_address: addr,
        internal_transactions,
        call_frames,
        struct_logs,
        struct_logs_truncated: false,
        state_diff: None,
        error,
    }
}

fn map_logs(logs: Vec<VmLog>) -> Vec<VmLogOut> {
    logs.into_iter()
        .map(|l| VmLogOut { address: l.address, topics: l.topics, data: l.data })
        .collect()
}
