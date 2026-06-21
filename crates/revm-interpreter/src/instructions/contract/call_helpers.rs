use crate::{
    interpreter::Interpreter,
    interpreter_types::{InputsTr, InterpreterTypes as ITy, MemoryTr, RuntimeFlag, StackTr},
    InstructionContext as Ictx, InstructionResult,
};
use context_interface::{cfg::GasParams, host::LoadError, Host};
use core::{cmp::min, ops::Range};
use primitives::{
    hardfork::SpecId::{self, *},
    Address, B256, U256,
};
use state::Bytecode;

/// Gets memory input and output ranges for call instructions.
#[inline]
pub fn get_memory_input_and_out_ranges(
    interpreter: &mut Interpreter<impl ITy>,
    gas_params: &GasParams,
) -> Result<(Range<usize>, Range<usize>), InstructionResult> {
    popn!([in_offset, in_len, out_offset, out_len], interpreter);

    let mut in_range = resize_memory(interpreter, gas_params, in_offset, in_len)?;

    if !in_range.is_empty() {
        let offset = interpreter.memory.local_memory_offset();
        in_range = in_range.start.saturating_add(offset)..in_range.end.saturating_add(offset);
    }

    let ret_range = resize_memory(interpreter, gas_params, out_offset, out_len)?;
    Ok((in_range, ret_range))
}

/// Resize memory and return range of memory.
/// If `len` is 0 dont touch memory and return `usize::MAX` as offset and 0 as length.
#[inline]
pub fn resize_memory(
    interpreter: &mut Interpreter<impl ITy>,
    gas_params: &GasParams,
    offset: U256,
    len: U256,
) -> Result<Range<usize>, InstructionResult> {
    let len = as_usize_or_fail!(interpreter, len);
    let offset = if len != 0 {
        let offset = as_usize_or_fail!(interpreter, offset);
        interpreter.resize_memory(gas_params, offset, len)?;
        offset
    } else {
        usize::MAX // unrealistic value so we are sure it is not used
    };
    Ok(offset..offset + len)
}

/// Calculates gas cost and limit for call instructions.
///
/// The trailing bool in the returned tuple is `charged_new_account_state_gas`:
/// `true` iff this call upfront-charged EIP-8037 `new_account_state_gas`
/// (transfers value into a previously-empty account). Callers should propagate
/// it onto `CallInputs` so the parent can refund the charge if the resulting
/// frame reverts/halts.
#[inline(never)]
pub fn load_acc_and_calc_gas<H: Host + ?Sized>(
    context: &mut Ictx<'_, H, impl ITy>,
    to: Address,
    transfers_value: bool,
    create_empty_account: bool,
    stack_gas_limit: u64,
) -> Result<(u64, Bytecode, B256, bool), InstructionResult> {
    // Transfer value cost
    if transfers_value {
        gas!(
            context.interpreter,
            context.host.gas_params().transfer_value_cost()
        );
    }

    // load account delegated and deduct dynamic gas.
    let (gas, state_gas_cost, bytecode, code_hash) =
        load_account_delegated_handle_error(context, to, transfers_value, create_empty_account)?;
    let charged_new_account_state_gas = state_gas_cost > 0;
    let interpreter = &mut context.interpreter;

    // deduct dynamic gas.
    gas!(interpreter, gas);

    // deduct state gas (EIP-8037) if any.
    state_gas!(interpreter, state_gas_cost);

    let interpreter = &mut context.interpreter;
    let host = &mut context.host;

    // EIP-150: Gas cost changes for IO-heavy operations
    //
    // TRON fork: java's `Program.getCallEnergy` (`Program.java:1856`, called by
    // `EnergyCost.java:505`) retains the 1/64 ONLY when `allowTvmCompatibleEvm()
    // && getContractVersion() == 1`, keyed on the version of the frame
    // *executing* this CALL. So skip the retention exactly when the flag is on
    // but this frame's contract version is not 1 — a version-0 (legacy) frame
    // forwards ALL energy even with the flag on. With the flag off (Ethereum
    // hosts, or TRON before #66) we never skip, preserving the unconditional
    // EIP-150 retention. (When TRON's flag is off, `tron_gas_params_for(false)`
    // also sets the divisor to 0, so `call_stipend_reduction` is itself a no-op.)
    let tron_skip_retention =
        host.tron_allow_tvm_compatible_evm() && interpreter.input.tron_contract_version() != 1;
    let mut gas_limit = if interpreter.runtime_flag.spec_id().is_enabled_in(TANGERINE) {
        // java's `getCallEnergy(requested, available)` returns `min(requested,
        // available)`; the 1/64 only reduces `available` first, and only for a
        // version-1 frame. So `available` is the caller's remaining energy,
        // optionally 1/64-reduced; the forwarded gas is min(available, requested).
        let available = if tron_skip_retention {
            // version-0 (legacy) frame: forward ALL remaining energy (no 1/64),
            // but still cap to the caller's remaining + the requested amount.
            interpreter.gas.remaining()
        } else {
            // On mainnet this will take return 63/64 of gas_limit.
            host.gas_params()
                .call_stipend_reduction(interpreter.gas.remaining())
        };
        min(available, stack_gas_limit)
    } else {
        stack_gas_limit
    };
    // TRON fork: gas forwarded to the child frame is java-tron's
    // `adjustedCallEnergy` — never scaled by the parent's dynamic-energy
    // factor and excluded from the parent's contract-usage accounting
    // (`VM.play()` subtracts it from `actualEnergy`).
    if !interpreter.gas.record_unscaled_cost(gas_limit) {
        return Err(InstructionResult::OutOfGas);
    }

    // Add call stipend if there is value to be transferred.
    if transfers_value {
        gas_limit = gas_limit.saturating_add(host.gas_params().call_stipend());
    }

    Ok((
        gas_limit,
        bytecode,
        code_hash,
        charged_new_account_state_gas,
    ))
}

/// Loads accounts and its delegate account.
///
/// Returns `(regular_gas_cost, state_gas_cost, bytecode, code_hash)`.
#[inline]
pub fn load_account_delegated_handle_error<H: Host + ?Sized>(
    context: &mut Ictx<'_, H, impl ITy>,
    to: Address,
    transfers_value: bool,
    create_empty_account: bool,
) -> Result<(u64, u64, Bytecode, B256), InstructionResult> {
    // move this to static gas.
    let remaining_gas = context.interpreter.gas.remaining();
    // TRON fork: warm/cold (EIP-2929) and the new-account rule follow the *gas*
    // spec (Frontier for TRON), not the opcode spec. The 63/64 gas-forwarding
    // rule (EIP-150) stays on the opcode spec in `load_acc_and_calc_gas` — TRON
    // does apply it.
    let gas_spec = context.host.gas_params().spec();
    Ok(load_account_delegated(
        context.host,
        gas_spec,
        remaining_gas,
        to,
        transfers_value,
        create_empty_account,
    )?)
}

/// Loads accounts and its delegate account.
///
/// Assumption is that warm gas is already deducted.
///
/// Returns `(regular_gas_cost, state_gas_cost, bytecode, code_hash)`.
/// `state_gas_cost` is non-zero only when creating a new empty account (EIP-8037).
#[inline]
pub fn load_account_delegated<H: Host + ?Sized>(
    host: &mut H,
    spec: SpecId,
    remaining_gas: u64,
    address: Address,
    transfers_value: bool,
    create_empty_account: bool,
) -> Result<(u64, u64, Bytecode, B256), LoadError> {
    let mut cost = 0;
    let mut state_gas_cost = 0;
    let is_berlin = spec.is_enabled_in(SpecId::BERLIN);
    let is_spurious_dragon = spec.is_enabled_in(SpecId::SPURIOUS_DRAGON);

    let additional_cold_cost = host.gas_params().cold_account_additional_cost();
    let warm_storage_read_cost = host.gas_params().warm_storage_read_cost();

    let skip_cold_load = is_berlin && remaining_gas < additional_cold_cost;
    let account = host.load_account_info_skip_cold_load(address, true, skip_cold_load)?;
    if is_berlin && account.is_cold {
        cost += additional_cold_cost;
    }
    let mut bytecode = account.code.clone().unwrap_or_default();
    let mut code_hash = account.code_hash();
    // New account cost, as account is empty there is no delegated account and we can return early.
    if create_empty_account && account.is_empty {
        // TRON fork: java-tron's `EnergyCost.getCallCost` only charges the
        // `NEW_ACCT_CALL` (25000) top-up for a CALL to a dead account when the
        // call ALSO transfers value (`if (!value.isZero()) { ... if
        // (isDeadAccount(...)) energyCost += NEW_ACCT_CALL; }`). TRON pins its
        // *gas table* to Frontier, where `new_account_cost` would otherwise
        // charge the top-up unconditionally (pre-Spurious-Dragon). Frontier's
        // unconditional rule over-charges every zero-value CALL to an empty
        // account — e.g. the identity-precompile pattern (CALL 0x04, value 0)
        // a router uses for memory copies. java charges nothing for those.
        // Mirror java's value-gating by treating the new-account rule as
        // value-gated regardless of the (Frontier) gas spec.
        //
        // The account is EIP-161 `is_empty` here, but TRON's
        // `EnergyCost.isDeadAccount` keys on STORE EXISTENCE
        // (`getAccount(addr) == null`), not emptiness — and TRON never prunes
        // accounts, so an existing account with a zero balance is alive. Only
        // charge `NEW_ACCT_CALL` when the account is genuinely absent from the
        // store; otherwise a value-bearing CALL to an existing-but-empty
        // account over-charges 25000 energy vs java (default `false` →
        // upstream EVM keeps the pure `is_empty` behaviour).
        let _ = is_spurious_dragon;
        if transfers_value && !host.tron_account_exists(address) {
            cost += host.gas_params().new_account_cost(is_spurious_dragon, true);
            if host.is_amsterdam_eip8037_enabled() {
                state_gas_cost += host.gas_params().new_account_state_gas(host.cpsb());
            }
        }
        return Ok((cost, state_gas_cost, bytecode, code_hash));
    }

    // load delegate code if account is EIP-7702
    if let Some(address) = account.code.as_ref().and_then(Bytecode::eip7702_address) {
        // EIP-7702 is enabled after berlin hardfork.
        cost += warm_storage_read_cost;
        if cost > remaining_gas {
            return Err(LoadError::ColdLoadSkipped);
        }

        // skip cold load if there is enough gas to cover the cost.
        let skip_cold_load = remaining_gas < cost + additional_cold_cost;
        let delegate_account =
            host.load_account_info_skip_cold_load(address, true, skip_cold_load)?;

        if delegate_account.is_cold {
            cost += additional_cold_cost;
        }
        bytecode = delegate_account.code.clone().unwrap_or_default();
        code_hash = delegate_account.code_hash();
    }

    Ok((cost, state_gas_cost, bytecode, code_hash))
}
