mod call_helpers;

pub use call_helpers::{
    get_memory_input_and_out_ranges, load_acc_and_calc_gas, load_account_delegated,
    load_account_delegated_handle_error, resize_memory,
};

use crate::{
    instructions::utility::IntoAddress,
    interpreter_action::FrameInput,
    interpreter_types::{
        InputsTr, InterpreterTypes as ITy, LoopControl, MemoryTr, RuntimeFlag, StackTr,
    },
    CallInput, CallInputs, CallScheme, CallValue, CreateInputs, Host,
    InstructionExecResult as Result, InstructionResult, InterpreterAction,
};
use context_interface::CreateScheme;
use primitives::{hardfork::SpecId, Bytes, U256};
use std::boxed::Box;

use crate::InstructionContext as Ictx;

/// Implements the CREATE/CREATE2 instruction.
///
/// Creates a new contract with provided bytecode.
pub fn create<const IS_CREATE2: bool, IT: ITy, H: Host + ?Sized>(
    context: Ictx<'_, H, IT>,
) -> Result {
    // Static call check is before gas charging (unlike execution-specs where it's
    // inside generic_create). This is safe because CREATE in a static context is
    // always an error regardless of gas accounting.
    require_non_staticcall!(context.interpreter);

    // EIP-1014: Skinny CREATE2
    if IS_CREATE2 {
        check!(context.interpreter, PETERSBURG);
    }

    popn!([value, code_offset, len], context.interpreter);
    let len = as_usize_or_fail!(context.interpreter, len);

    let mut code = Bytes::new();
    if len != 0 {
        // EIP-3860: Limit and meter initcode.
        // TRON fork: this is a *gas* decision, so it follows the gas spec
        // (Frontier for TRON, which has no EIP-3860 initcode metering) rather
        // than the opcode spec. TRON enforces its own deployed-code size limit
        // separately at code deposit.
        if context
            .host
            .gas_params()
            .spec()
            .is_enabled_in(SpecId::SHANGHAI)
        {
            // Limit is set as double of max contract bytecode size
            if len > context.host.max_initcode_size() {
                return Err(InstructionResult::CreateInitCodeSizeLimit);
            }
            gas!(
                context.interpreter,
                context.host.gas_params().initcode_cost(len)
            );
        }

        let code_offset = as_usize_or_fail!(context.interpreter, code_offset);
        context
            .interpreter
            .resize_memory(context.host.gas_params(), code_offset, len)?;

        code = Bytes::copy_from_slice(
            context
                .interpreter
                .memory
                .slice_len(code_offset, len)
                .as_ref(),
        );
    }

    // EIP-1014: Skinny CREATE2
    let scheme = if IS_CREATE2 {
        popn!([salt], context.interpreter);
        // SAFETY: `len` is reasonable in size as gas for it is already deducted.
        gas!(
            context.interpreter,
            context.host.gas_params().create2_cost(len)
        );
        CreateScheme::Create2 { salt }
    } else {
        gas!(context.interpreter, context.host.gas_params().create_cost());
        CreateScheme::Create
    };

    // State gas for account creation + contract metadata (EIP-8037).
    // Charged upfront on the parent's tracker; `return_create` refunds the same
    // amount (derived from cfg) on entry and re-records it on a successful commit.
    if context.host.is_amsterdam_eip8037_enabled() {
        state_gas!(
            context.interpreter,
            context
                .host
                .gas_params()
                .create_state_gas(context.host.cpsb())
        );
    }

    let mut gas_limit = context.interpreter.gas.remaining();

    // EIP-150: Gas cost changes for IO-heavy operations
    if context
        .interpreter
        .runtime_flag
        .spec_id()
        .is_enabled_in(SpecId::TANGERINE)
    {
        // Take remaining gas and deduce l64 part of it.
        gas_limit = context.host.gas_params().call_stipend_reduction(gas_limit);
    }
    // TRON fork: forwarded child gas is never scaled by the parent's
    // dynamic-energy factor nor counted toward its contract usage (see
    // `load_acc_and_calc_gas` for the CALL-side rationale).
    if !context.interpreter.gas.record_unscaled_cost(gas_limit) {
        return Err(InstructionResult::OutOfGas);
    }

    // Call host to interact with target contract
    let create_inputs = CreateInputs::new(
        context.interpreter.input.target_address(),
        scheme,
        value,
        code,
        gas_limit,
        context.interpreter.gas.reservoir(),
    );
    context
        .interpreter
        .bytecode
        .set_action(InterpreterAction::NewFrame(FrameInput::Create(Box::new(
            create_inputs,
        ))));
    Err(InstructionResult::Suspend)
}

/// Implements the CALL, CALLCODE, DELEGATECALL, and STATICCALL instructions.
pub fn call<const KIND: u8, IT: ITy, H: Host + ?Sized>(mut context: Ictx<'_, H, IT>) -> Result {
    use bytecode::opcode::{CALL, CALLCODE, DELEGATECALL, STATICCALL};

    if !matches!(KIND, CALL | CALLCODE | DELEGATECALL | STATICCALL) {
        unreachable!("invalid call kind")
    }

    if KIND == DELEGATECALL {
        check!(context.interpreter, HOMESTEAD);
    } else if KIND == STATICCALL {
        check!(context.interpreter, BYZANTIUM);
    }

    let (local_gas_limit, to, value) = if matches!(KIND, CALL | CALLCODE) {
        popn!([local_gas_limit, to, value], context.interpreter);
        (local_gas_limit, to, value)
    } else {
        popn!([local_gas_limit, to], context.interpreter);
        (local_gas_limit, to, U256::ZERO)
    };
    let to = to.into_address();
    // Max gas limit is not possible in real ethereum situation.
    let local_gas_limit = u64::try_from(local_gas_limit).unwrap_or(u64::MAX);
    let has_transfer = !value.is_zero();

    if KIND == CALL && context.interpreter.runtime_flag.is_static() && has_transfer {
        return Err(InstructionResult::CallNotAllowedInsideStatic);
    }

    let (input, return_memory_offset) =
        get_memory_input_and_out_ranges(context.interpreter, context.host.gas_params())?;

    let is_call = KIND == CALL;
    let (gas_limit, bytecode, bytecode_hash, charged_new_account_state_gas) =
        load_acc_and_calc_gas(&mut context, to, has_transfer, is_call, local_gas_limit)?;

    let target_address = if matches!(KIND, CALLCODE | DELEGATECALL) {
        context.interpreter.input.target_address()
    } else {
        to
    };
    let caller = if KIND == DELEGATECALL {
        context.interpreter.input.caller_address()
    } else {
        context.interpreter.input.target_address()
    };
    let value = if KIND == DELEGATECALL {
        CallValue::Apparent(context.interpreter.input.call_value())
    } else {
        CallValue::Transfer(value)
    };
    let scheme = match KIND {
        CALL => CallScheme::Call,
        CALLCODE => CallScheme::CallCode,
        DELEGATECALL => CallScheme::DelegateCall,
        STATICCALL => CallScheme::StaticCall,
        _ => unreachable!(),
    };
    let is_static = context.interpreter.runtime_flag.is_static() || KIND == STATICCALL;

    // Call host to interact with target contract
    context
        .interpreter
        .bytecode
        .set_action(InterpreterAction::NewFrame(FrameInput::Call(Box::new(
            CallInputs {
                input: CallInput::SharedBuffer(input),
                gas_limit,
                target_address,
                caller,
                bytecode_address: to,
                known_bytecode: (bytecode_hash, bytecode),
                value,
                scheme,
                is_static,
                return_memory_offset,
                reservoir: context.interpreter.gas.reservoir(),
                charged_new_account_state_gas,
                // Standard CALL/CALLCODE/DELEGATECALL/STATICCALL never
                // carry TRC-10 transfer info. `call_token` (defined
                // alongside) sets these to non-zero values.
                tron_token_id: 0,
                tron_token_value: 0,
            },
        ))));
    Err(InstructionResult::Suspend)
}

// ============================================================================
// TRON fork: 0xd0..0xd4 opcode handlers
// ============================================================================

/// CALLTOKEN (opcode `0xd0`) — TRON's CALL variant that also transfers
/// a TRC-10 asset alongside the TRX value.
///
/// Stack (per java-tron's `CallTokenInstruction`, top of stack first):
///
/// ```text
///   [gas, to, callValue, tokenValue, tokenId, inOffset, inSize, outOffset, outSize]
/// ```
///
/// The TRX side of the call follows ordinary CALL semantics. The TRC-10
/// side effect (debit `caller.asset_v2[tokenId]` by `tokenValue`, credit
/// `target.asset_v2[tokenId]`) is applied by the host (`tron-tvm`)
/// **before** the new frame runs — see the precompile/inspector glue
/// for the wiring.
///
/// Why a fork-internal opcode and not a precompile: CALL semantics
/// (EIP-2929 access lists, value-transfer gas, new-account charge,
/// 63/64 gas forwarding, journal checkpoints) must remain intact. Doing
/// this outside the interpreter would require duplicating those rules.
pub fn call_token<IT: ITy, H: Host + ?Sized>(mut context: Ictx<'_, H, IT>) -> Result {
    // Static-call restriction: CALLTOKEN performs a balance-changing
    // side effect, so it follows the same rule as CALL+value=0.
    if context.interpreter.runtime_flag.is_static() {
        return Err(InstructionResult::CallNotAllowedInsideStatic);
    }

    // Pop 9 stack items.
    popn!(
        [
            local_gas_limit,
            to,
            value,
            token_value,
            token_id
        ],
        context.interpreter
    );
    let to = to.into_address();
    let local_gas_limit = u64::try_from(local_gas_limit).unwrap_or(u64::MAX);
    let has_transfer = !value.is_zero();

    let (input, return_memory_offset) =
        get_memory_input_and_out_ranges(context.interpreter, context.host.gas_params())?;

    // CALLTOKEN gas accounting follows CALL: cold/warm access, value-
    // transfer surcharge if non-zero TRX, new-account gas if applicable.
    let (gas_limit, bytecode, bytecode_hash, charged_new_account_state_gas) =
        load_acc_and_calc_gas(&mut context, to, has_transfer, /* is_call */ true, local_gas_limit)?;

    // Saturate the i128 stack words to i64. java-tron rejects out-of-i64
    // token id / value at the contract layer; the EVM keeps the truncated
    // value so an in-VM check inside the contract sees the same number.
    let token_id_i64 = u64_from_u256(&token_id) as i64;
    let token_value_i64 = u64_from_u256(&token_value) as i64;

    let caller = context.interpreter.input.target_address();
    let target_address = to;
    let scheme = CallScheme::Call;
    let is_static = false;
    let call_value = CallValue::Transfer(value);

    context
        .interpreter
        .bytecode
        .set_action(InterpreterAction::NewFrame(FrameInput::Call(Box::new(
            CallInputs {
                input: CallInput::SharedBuffer(input),
                gas_limit,
                target_address,
                caller,
                bytecode_address: to,
                known_bytecode: (bytecode_hash, bytecode),
                value: call_value,
                scheme,
                is_static,
                return_memory_offset,
                reservoir: context.interpreter.gas.reservoir(),
                charged_new_account_state_gas,
                // TRC-10 transfer parameters travel via CallInputs into
                // the new frame; the host reads them between the
                // checkpoint and the callee's first instruction to
                // perform the asset_v2 debit/credit.
                tron_token_id: token_id_i64,
                tron_token_value: token_value_i64,
            },
        ))));
    Err(InstructionResult::Suspend)
}

/// CALLTOKENVALUE (opcode `0xd2`) — pushes the TRC-10 token value of
/// the *current* CALLTOKEN frame onto the stack. Returns 0 for any
/// frame that wasn't a CALLTOKEN.
pub fn call_token_value<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    let v = context.interpreter.input.tron_token_value();
    push!(context.interpreter, U256::from(v.max(0) as u64));
    Ok(())
}

/// CALLTOKENID (opcode `0xd3`) — pushes the TRC-10 token id of the
/// current CALLTOKEN frame. Returns 0 for any frame that wasn't a
/// CALLTOKEN.
pub fn call_token_id<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    let v = context.interpreter.input.tron_token_id();
    push!(context.interpreter, U256::from(v.max(0) as u64));
    Ok(())
}

/// TOKENBALANCE (opcode `0xd1`) — `(address, tokenId) → balance`.
///
/// Stack (top first): `[tokenId, address]`. The balance is read from
/// the host's `asset_v2` map via a dedicated `Host::tron_token_balance`
/// method. Returns 0 for unknown account / token combinations.
///
/// The implementation here just decodes the stack args and asks the host;
/// the actual map lookup lives in `tron-tvm`'s host impl so we don't
/// add asset-store knowledge to the interpreter.
pub fn token_balance<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    popn!([token_id, address], context.interpreter);
    let addr = address.into_address();
    let id = u64_from_u256(&token_id) as i64;
    let bal = context.host.tron_token_balance(addr, id);
    push!(context.interpreter, U256::from(bal.max(0) as u64));
    Ok(())
}

/// ISCONTRACT (opcode `0xd4`) — `address → bool`. Pushes 1 if the
/// account at `address` has non-empty bytecode, 0 otherwise.
pub fn is_contract<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    popn!([address], context.interpreter);
    let addr = address.into_address();
    let is_c = context.host.tron_is_contract(addr);
    push!(context.interpreter, if is_c { U256::ONE } else { U256::ZERO });
    Ok(())
}

/// FREEZEEXPIRETIME (opcode `0xd7`) — Stake 1.0 read-only opcode.
///
/// Stack (top first): `[resourceType, targetAddress]`. `resourceType`
/// is `0` for bandwidth, `1` for energy. Returns the unfreezable-at
/// Unix timestamp **in seconds** (java-tron's `freezeExpireTimeAction`
/// divides the ms value by 1000 before pushing).
///
/// When `caller == target`, the lookup is on the caller's own frozen
/// entries; otherwise it's on the DelegatedResource row between caller
/// and target. Returns 0 when no matching frozen entry exists.
///
/// Decoding lives in the handler; the actual store lookup is the
/// host's `tron_freeze_expire_time` method (defined in
/// `revm-context-interface`), implemented in `tron-tvm`'s host so we
/// don't carry chainbase knowledge in the interpreter.
pub fn freeze_expire_time<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    popn!([resource_type, target_address], context.interpreter);
    let target = target_address.into_address();
    let caller = context.interpreter.input.target_address();
    let rc = u64_from_u256(&resource_type) as u32;
    let expire_ms = context.host.tron_freeze_expire_time(caller, target, rc);
    // Java pushes `expireTime / 1000` (ms → seconds). Replicate exactly.
    let seconds = expire_ms / 1000;
    push!(context.interpreter, U256::from(seconds.max(0) as u64));
    Ok(())
}

// ============================================================================
// Stake 1.0/2.0 state-mutating opcodes (0xd5..0xdf, minus 0xd7).
//
// Each handler matches java-tron's `OperationActions::xxxAction` stack
// shape exactly (verified against
// `actuator/src/main/java/org/tron/core/vm/OperationActions.java`).
// They pop the documented number of args (so the EVM doesn't
// underflow) and push the result (so subsequent ops see the right
// stack depth), then ask the Host. Default Host impls return 0, so
// contracts that invoke these opcodes get a graceful "operation
// failed" rather than a halt — matching the existing TOKENBALANCE /
// ISCONTRACT pattern. Real state mutations need actuator-primitive
// refactoring + a Host override (see `tron-tvm/src/tron_host.rs` for
// the full design note).
// ============================================================================

/// FREEZE (0xd5) — Stake 1.0 freeze. Stack (top first): `[resourceType,
/// frozenBalance, receiverAddress]`. Pushes `1`/`0` for success.
///
/// Post-`ALLOW_TVM_FREEZE_V2`, java-tron skips the freeze and pushes 0
/// (the opcode is deprecated). The default Host impl already returns
/// 0, so we get the same observable behavior without needing the
/// proposal-gating logic in the handler.
pub fn freeze<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    popn!(
        [resource_type, frozen_balance, receiver_address],
        context.interpreter
    );
    let caller = context.interpreter.input.target_address();
    // java-tron's `freeze` takes (receiver, balance, resource) and uses
    // `caller != receiver` to switch self vs delegated. We pass both;
    // Host treats them as a hint.
    let receiver = receiver_address.into_address();
    let result = context.host.tron_freeze(
        caller,
        u64_from_u256(&frozen_balance) as i64,
        // Stake 1.0 had no explicit duration arg from the stack —
        // java-tron derived it from chain params. Pass 0; Host can
        // re-derive.
        0,
        u64_from_u256(&resource_type) as u32,
        Some(receiver),
    );
    push!(context.interpreter, U256::from(result.max(0) as u64));
    Ok(())
}

/// UNFREEZE (0xd6) — Stake 1.0 unfreeze. Stack: `[resourceType,
/// receiverAddress]`. Pushes `1`/`0`.
pub fn unfreeze<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    popn!([resource_type, receiver_address], context.interpreter);
    let caller = context.interpreter.input.target_address();
    let receiver = receiver_address.into_address();
    let result = context.host.tron_unfreeze(
        caller,
        u64_from_u256(&resource_type) as u32,
        Some(receiver),
    );
    push!(context.interpreter, U256::from(result.max(0) as u64));
    Ok(())
}

/// VOTEWITNESS (0xd8) — cast votes for SR candidates. Stack:
/// `[amountArrayLength, amountArrayOffset, witnessArrayLength,
/// witnessArrayOffset]`. The two arrays live in EVM memory; we don't
/// decode them in the handler today (default Host returns 0 anyway).
/// When a real Host override lands, populate the address/amount pairs
/// from memory before passing.
pub fn vote_witness<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    popn!(
        [_amount_array_len, _amount_array_off, _witness_array_len, _witness_array_off],
        context.interpreter
    );
    let caller = context.interpreter.input.target_address();
    // Empty slice — the real impl must read memory at the popped
    // offsets to populate `(address, amount)` pairs.
    let result = context.host.tron_vote_witness(caller, &[]);
    push!(context.interpreter, U256::from(result.max(0) as u64));
    Ok(())
}

/// WITHDRAWREWARD (0xd9) — withdraw accumulated SR rewards. Stack
/// in=0, out=1. The pushed value is the withdrawn amount.
pub fn withdraw_reward<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    let caller = context.interpreter.input.target_address();
    let amount = context.host.tron_withdraw_reward(caller);
    push!(context.interpreter, U256::from(amount.max(0) as u64));
    Ok(())
}

/// FREEZEBALANCEV2 (0xda) — Stake 2.0 freeze. Stack: `[resourceType,
/// frozenBalance]`. Pushes `1`/`0`.
pub fn freeze_balance_v2<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    popn!([resource_type, frozen_balance], context.interpreter);
    let caller = context.interpreter.input.target_address();
    let result = context.host.tron_freeze_balance_v2(
        caller,
        u64_from_u256(&frozen_balance) as i64,
        u64_from_u256(&resource_type) as u32,
    );
    push!(context.interpreter, U256::from(result.max(0) as u64));
    Ok(())
}

/// UNFREEZEBALANCEV2 (0xdb) — Stake 2.0 unfreeze. Stack:
/// `[resourceType, unfreezeBalance]`. Pushes `1`/`0`.
pub fn unfreeze_balance_v2<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    popn!([resource_type, unfreeze_balance], context.interpreter);
    let caller = context.interpreter.input.target_address();
    let result = context.host.tron_unfreeze_balance_v2(
        caller,
        u64_from_u256(&unfreeze_balance) as i64,
        u64_from_u256(&resource_type) as u32,
    );
    push!(context.interpreter, U256::from(result.max(0) as u64));
    Ok(())
}

/// CANCELALLUNFREEZEV2 (0xdc) — cancel every pending unfreeze.
/// Stack in=0, out=1 (success bool).
pub fn cancel_all_unfreeze_v2<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    let caller = context.interpreter.input.target_address();
    let result = context.host.tron_cancel_all_unfreeze_v2(caller);
    push!(context.interpreter, U256::from(result.max(0) as u64));
    Ok(())
}

/// WITHDRAWEXPIREUNFREEZE (0xdd) — sweep matured unfreeze entries.
/// Stack in=0, out=1 (withdrawn amount).
pub fn withdraw_expire_unfreeze<IT: ITy, H: Host + ?Sized>(
    context: Ictx<'_, H, IT>,
) -> Result {
    let caller = context.interpreter.input.target_address();
    let amount = context.host.tron_withdraw_expire_unfreeze(caller);
    push!(context.interpreter, U256::from(amount.max(0) as u64));
    Ok(())
}

/// DELEGATERESOURCE (0xde) — delegate Stake 2.0 resource. Stack:
/// `[resourceType, delegateBalance, receiverAddress]`. Pushes `1`/`0`.
///
/// java-tron's `delegateResource(receiver, balance, resourceType)`
/// doesn't take `lock` / `lockPeriod` args from the stack — those flow
/// through the `delegateResourceLockable` extension which uses a
/// separate function. We mirror the basic signature; the Host method
/// accepts the lock flags so a fuller integration can use them.
pub fn delegate_resource<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    popn!(
        [resource_type, delegate_balance, receiver_address],
        context.interpreter
    );
    let caller = context.interpreter.input.target_address();
    let receiver = receiver_address.into_address();
    let result = context.host.tron_delegate_resource(
        caller,
        u64_from_u256(&delegate_balance) as i64,
        receiver,
        u64_from_u256(&resource_type) as u32,
        false,
        0,
    );
    push!(context.interpreter, U256::from(result.max(0) as u64));
    Ok(())
}

/// UNDELEGATERESOURCE (0xdf) — undelegate Stake 2.0 resource. Stack:
/// `[resourceType, unDelegateBalance, receiverAddress]`. Pushes `1`/`0`.
pub fn undelegate_resource<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    popn!(
        [resource_type, undelegate_balance, receiver_address],
        context.interpreter
    );
    let caller = context.interpreter.input.target_address();
    let receiver = receiver_address.into_address();
    let result = context.host.tron_undelegate_resource(
        caller,
        u64_from_u256(&undelegate_balance) as i64,
        receiver,
        u64_from_u256(&resource_type) as u32,
    );
    push!(context.interpreter, U256::from(result.max(0) as u64));
    Ok(())
}

/// Truncate a `U256` to its low 64 bits.
fn u64_from_u256(v: &U256) -> u64 {
    let words = v.as_limbs();
    words[0]
}
