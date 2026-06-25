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
        // TRON fork: java's `Program.getCreateEnergy` (`Program.java:1865`,
        // called via `EnergyCost.java:505`) retains the 1/64 ONLY when
        // `allowTvmCompatibleEvm() && getContractVersion() == 1`, keyed on the
        // version of the frame *executing* this CREATE. Skip the retention
        // exactly when the flag is on but this frame's version is not 1 (a
        // version-0 / legacy frame forwards ALL energy even with the flag on);
        // with the flag off (Ethereum hosts, or TRON before #66) keep the
        // unconditional EIP-150 retention.
        let tron_skip_retention = context.host.tron_allow_tvm_compatible_evm()
            && context.interpreter.input.tron_contract_version() != 1;
        if !tron_skip_retention {
            // Take remaining gas and deduce l64 part of it.
            gas_limit = context.host.gas_params().call_stipend_reduction(gas_limit);
        }
    }
    // TRON fork: forwarded child gas is never scaled by the parent's
    // dynamic-energy factor nor counted toward its contract usage (see
    // `load_acc_and_calc_gas` for the CALL-side rationale).
    if !context.interpreter.gas.record_unscaled_cost(gas_limit) {
        return Err(InstructionResult::OutOfGas);
    }

    // java `createContractImpl` (Program.java:821) reads the endowment with a
    // BARE `value.value().longValueExact()` — NO try/catch (unlike
    // `callToAddress`). A value DataWord exceeding i64::MAX throws
    // ArithmeticException which, not being a TransferException, propagates to
    // VM.java:100 -> `spendAllEnergy()`: the WHOLE tx fails consuming ALL
    // remaining energy with state reverted. This is the CREATE analogue of the
    // CALL endowment-range guard, but java's CREATE arm is spend-all, NOT the
    // consumed-only TransferException path — so map to the spend-all
    // `OutOfMemory` result (execute.rs), never `TransferFailed`. Ungated:
    // Program.java:821 is ungated and ALLOW_TVM_CONSTANTINOPLE already floors
    // these opcodes. (Effectively unreachable on canonical mainnet — a >i64 sun
    // endowment is ~9.2e12 TRX — but faithful to java for crafted bytecode.)
    if u256_to_i64_exact(&value).is_none() {
        return Err(InstructionResult::MemoryLimitOOG);
    }

    // Call host to interact with target contract. TRON fork: the created
    // contract's init frame inherits the parent's contract version
    // (`Program.java:915`), so stamp this frame's version onto the inputs.
    let mut create_inputs = CreateInputs::new(
        context.interpreter.input.target_address(),
        scheme,
        value,
        code,
        gas_limit,
        context.interpreter.gas.reservoir(),
    );
    create_inputs.set_tron_contract_version(context.interpreter.input.tron_contract_version());
    // TRON fork: pre-`ALLOW_TVM_ISTANBUL` (#41), CREATE2 derives the new
    // address from the CALLER of the executing frame, not the executing
    // contract — java `Program.createContract2`:
    // `senderAddress = allowTvmIstanbul() ? getContextAddress() : getCallerAddress()`.
    // Only the address changes (value/nonce stay on the caller field). CREATE2
    // exists only from Constantinople, so the affected window is #26..#41.
    if matches!(create_inputs.scheme(), CreateScheme::Create2 { .. })
        && !context
            .interpreter
            .runtime_flag
            .spec_id()
            .is_enabled_in(SpecId::ISTANBUL)
    {
        create_inputs.set_tron_create2_sender(Some(context.interpreter.input.caller_address()));
    }
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

    // TRON fork: the call value (endowment) must fit in a signed 64-bit long.
    // java-tron's `Program.callToAddress` evaluates `msg.getEndowment().value()
    // .longValueExact()` BEFORE any transfer/balance check (`Program.java`); a
    // value above `Long.MAX_VALUE` (2^63-1) throws `ArithmeticException`, caught
    // and rethrown as `TransferException("endowment out of long range")` after
    // `refundEnergy(msg.getEnergy())`. A balance can never reach that magnitude,
    // so upstream revm would instead let `transfer_loaded` fail with
    // `OutOfFunds`, push 0, and let the contract continue to its own REVERT —
    // diverging from java (`contractResult REVERT`, refund) where the whole tx
    // dies as `TRANSFER_FAILED` at this opcode. Mirror java: refund the
    // forwarded `gas_limit`, mark the transfer-failure, and return the tx-fatal
    // `TransferFailed` (consumed-only energy, no spend-all). Applies to the
    // value-bearing call opcodes (CALL/CALLCODE); DELEGATECALL/STATICCALL carry
    // no popped value. Only under the TRON VM (`tron_enabled`).
    if matches!(KIND, CALL | CALLCODE)
        && u256_to_i64_exact(&value).is_none()
        && context.host.tron_enabled()
    {
        context.interpreter.gas.erase_cost(gas_limit);
        context.host.tron_mark_transfer_failed();
        return Err(InstructionResult::TransferFailed);
    }

    // TRON fork: a CALL with non-zero TRX value to the executing contract's
    // OWN address is forbidden. java-tron's `Program.callToAddress` enters the
    // transfer block (its `senderAddress != contextAddress` guard is a
    // ByteString *reference* compare, always true for distinct objects) and
    // `VMUtils.validateForSmartContract` throws a `ContractValidateException`
    // ("Cannot transfer TRX to yourself"), which `callToAddress` rethrows as a
    // `TransferException` after `refundEnergy(msg.getEnergy())`. A
    // `TransferException` is exempt from `spendAllEnergy` (VM.java) and ends the
    // whole transaction as a failure (`TRANSFER_FAILED`), the forwarded energy
    // refunded. We mirror that here: refund the forwarded `gas_limit` (java's
    // `msg.getEnergy()`, which includes the value-transfer stipend), mark the
    // transfer-failure on the journal (→ `contractResult TRANSFER_FAILED`), and
    // return the tx-fatal `TransferFailed` — which, like a `TransferException`,
    // ends execution WITHOUT spending all energy (it settles consumed-only, the
    // same as a revert, via `last_frame_result`'s `is_ok_or_revert` branch) and
    // unwinds every frame (`frame_return_result` short-circuits it to the top).
    // Only fires under the TRON VM (`tron_enabled`); upstream EVM keeps the
    // legal `from == to` self-transfer. CALLCODE/DELEGATECALL/STATICCALL never
    // reach here: CALLCODE/DELEGATECALL keep the caller's own context (java sets
    // `contextAddress = senderAddress`, so its self-guard is false) and
    // STATICCALL carries no value.
    if KIND == CALL && has_transfer && to == context.interpreter.input.target_address()
        && context.host.tron_enabled()
    {
        context.interpreter.gas.erase_cost(gas_limit);
        context.host.tron_mark_transfer_failed();
        return Err(InstructionResult::TransferFailed);
    }

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

    // java-tron's `callTokenAction` pops exactly [gas, to, value, tokenId]
    // (exeCall then pops the in/out memory ranges) — 8 stack items, NOT 9.
    // `value` is the TRC-10 *token* amount paired with `tokenId`; the native
    // TRX call-value of a CALLTOKEN is always ZERO — `ProgramInvokeFactory`
    // builds the callee with native side `!isTokenTransfer ? callValue : ZERO`
    // and token side `callValue`, and `callToAddress` moves the asset via
    // `addTokenBalance` (never `MUtil.transfer`). The old code popped a phantom
    // 9th `token_value` and passed `value` as the native call-value, so the
    // callee saw `msg.value != 0` and any `require(msg.value == 0)` reverted
    // ("trx is not allowed") — and it also routed the wrong (shifted) tokenId.
    popn!([local_gas_limit, to, value, token_id], context.interpreter);
    let to = to.into_address();
    let local_gas_limit = u64::try_from(local_gas_limit).unwrap_or(u64::MAX);
    // `value` is the TRC-10 token amount; the value-transfer surcharge + 2300
    // stipend follow java's `callTokenAction` (keyed on a non-zero token amount).
    let has_transfer = !value.is_zero();

    let (input, return_memory_offset) =
        get_memory_input_and_out_ranges(context.interpreter, context.host.gas_params())?;

    // CALLTOKEN gas accounting follows CALL: cold/warm access, value-
    // transfer surcharge if non-zero TRX, new-account gas if applicable.
    let (gas_limit, bytecode, bytecode_hash, charged_new_account_state_gas) =
        load_acc_and_calc_gas(&mut context, to, has_transfer, /* is_call */ true, local_gas_limit)?;

    // TRON fork: a CALLTOKEN with non-zero TRC-10 value to the executing
    // contract's OWN address is forbidden — the token analogue of the native
    // value self-CALL above. java-tron's `Program.callToAddress` enters the
    // transfer block and `VMUtils.validateForSmartContract(... tokenId ...)`
    // throws "Cannot transfer asset to yourself", rethrown as a
    // `TransferException` after `refundEnergy(msg.getEnergy())`. Mirror it:
    // refund the forwarded `gas_limit`, mark the transfer-failure on the journal
    // (→ `contractResult TRANSFER_FAILED`), and return the tx-fatal
    // `TransferFailed` (consumed-only energy, no spend-all; unwinds every frame).
    // Doing this in the opcode handler — BEFORE the child frame is created —
    // also means `Trc10Inspector::call` never runs for a self-CALLTOKEN, so the
    // asset_v2 debit/credit (which would otherwise net-mint `value` to the
    // caller, since the caller and target rows are the same account) never
    // happens. CALLTOKEN is a TRON-only opcode, so no `tron_enabled` gate is
    // needed.
    if has_transfer && to == context.interpreter.input.target_address() {
        context.interpreter.gas.erase_cost(gas_limit);
        context.host.tron_mark_transfer_failed();
        return Err(InstructionResult::TransferFailed);
    }

    // java `checkTokenId` (Program.java:1046, 1812-1823): once ALLOW_MULTI_SIGN
    // (#20) is active, CALLTOKEN's tokenId must be > MIN_TOKEN_ID (1_000_000);
    // a tokenId in [0, 1_000_000] or outside signed-i64 range refunds the
    // forwarded energy and throws TransferException — the whole tx fails as
    // TRANSFER_FAILED (consumed-only energy, no spend-all). Honest contracts use
    // real ids (> 1_000_000); a crafted/buggy contract trips it. ALLOW_TVM_
    // CONSTANTINOPLE (which makes the result a TransferException rather than the
    // older spend-all) predates ALLOW_MULTI_SIGN on mainnet, so gating on
    // ALLOW_MULTI_SIGN suffices. The pre-ALLOW_MULTI_SIGN era (isTokenTransfer =
    // tokenId != 0, with distinct native-value semantics) is a separate gap.
    if context.host.tron_allow_multi_sign()
        && u256_to_i64_exact(&token_id).map_or(true, |id| id <= 1_000_000)
    {
        context.interpreter.gas.erase_cost(gas_limit);
        context.host.tron_mark_transfer_failed();
        return Err(InstructionResult::TransferFailed);
    }

    // Saturate the i128 stack words to i64. java-tron rejects out-of-i64
    // token id / value at the contract layer; the EVM keeps the truncated
    // value so an in-VM check inside the contract sees the same number.
    let token_id_i64 = u64_from_u256(&token_id) as i64;
    let token_value_i64 = u64_from_u256(&value) as i64;

    let caller = context.interpreter.input.target_address();
    let target_address = to;
    let scheme = CallScheme::Call;
    let is_static = false;
    // Native TRX value of a CALLTOKEN is always zero — the TRC-10 asset travels
    // via `tron_token_*` (the host applies the asset_v2 debit/credit before the
    // callee's first instruction). Mirrors java's `DataWord.ZERO()` native side.
    let call_value = CallValue::Transfer(U256::ZERO);

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
    // java `checkTokenIdInTokenBalance` (Program.java:1469, 1835-1853): once
    // ALLOW_MULTI_SIGN (#20) is active, a tokenId outside signed-i64 range
    // throws TransferException (whole tx TRANSFER_FAILED, consumed-only),
    // while a tokenId <= MIN_TOKEN_ID (1_000_000) throws
    // BytecodeExecutionException — a non-TransferException, so VM.java
    // spendAllEnergy (whole tx fatal, all energy). Pre-ALLOW_MULTI_SIGN the
    // opcode just queries the (usually absent) id and pushes 0.
    if context.host.tron_allow_multi_sign() {
        match u256_to_i64_exact(&token_id) {
            None => {
                context.host.tron_mark_transfer_failed();
                return Err(InstructionResult::TransferFailed);
            }
            Some(id) if id <= 1_000_000 => return Err(InstructionResult::MemoryLimitOOG),
            Some(_) => {}
        }
    }
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
/// Post-`ALLOW_TVM_FREEZE_V2` (wired to `supportUnfreezeDelay`, active on
/// mainnet since Stake 2.0), java-tron's `freezeAction` skips the freeze and
/// pushes 0 (the opcode is deprecated) with no weight change and no nonce
/// bump. That gate lives in the TronDatabase Host override (`tron-tvm`'s
/// `tron_freeze`), which returns 0 before any state change; the default Host
/// impl returns 0 unconditionally.
pub fn freeze<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    // java `freezeAction` (OperationActions.java:781) throws
    // StaticCallModificationException — BEFORE any stack pop / increaseNonce —
    // when `VMConfig.allowTvmVote() && program.isStaticCall()`. Unlike the Stake
    // 2.0 ops, FREEZE/UNFREEZE gate the guard on `allowTvmVote`. Firing here
    // (before the host bridge bumps the internal-tx nonce) keeps the nonce —
    // which seeds nested CREATE2 addresses — unchanged on a static-context call.
    if context.host.tron_allow_tvm_vote() {
        require_non_staticcall!(context.interpreter);
    }
    popn!(
        [resource_type, frozen_balance, receiver_address],
        context.interpreter
    );
    let caller = context.interpreter.input.target_address();
    // java-tron's `freeze` takes (receiver, balance, resource) and uses
    // `caller != receiver` to switch self vs delegated. We pass both;
    // Host treats them as a hint.
    let receiver = receiver_address.into_address();
    // java `EnergyCost.getFreezeCost` adds NEW_ACCT_CALL (25000) to the base
    // FREEZE (20000) when the receiver is a dead account (isDeadAccount =
    // getAccount(receiver) == null on the in-flight Repository). The full cost
    // is charged BEFORE op.execute, so it fires even in the Stake-2.0 era where
    // `tron_freeze` no-ops. FREEZE only exists under ALLOW_TVM_FREEZE (gated at
    // registration), so no extra flag check is needed; the journal-aware check
    // makes a same-tx-created receiver count as alive (no top-up).
    if !context.host.tron_account_exists_or_created(receiver) {
        gas!(context.interpreter, 25_000);
    }
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
    // java `unfreezeAction` (OperationActions.java:800): static-call guard gated
    // on `VMConfig.allowTvmVote()`, before any stack pop / increaseNonce.
    if context.host.tron_allow_tvm_vote() {
        require_non_staticcall!(context.interpreter);
    }
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

/// VOTEWITNESS (0xd8) — cast votes for SR candidates. Stack (top first):
/// `[amountArrayLength, amountArrayOffset, witnessArrayLength,
/// witnessArrayOffset]`.
///
/// Mirrors java-tron's `Program.voteWitness`
/// (`actuator/.../vm/program/Program.java`):
///
/// * State-modifying, so it is rejected inside a static call.
/// * Both arrays are ABI dynamic arrays: the word at `offset` is the
///   element count and the elements start one word later (`offset + 32`).
///   The length word must equal the length parameter for each array; a
///   mismatch is a `BytecodeExecutionException` that halts and consumes
///   all energy (`spendAllEnergy`), modelled here as `OutOfGas`.
/// * `witnessArrayLength != amountArrayLength` returns false (push 0)
///   without halting.
/// * Each witness word becomes a TRON address (`toTronAddress` =
///   `0x41 ++ last 20 bytes`); the 20-byte EVM address is built here and
///   the host prepends the `0x41` prefix. Each amount word is the signed
///   256-bit value (`sValue().longValueExact()`); a value outside the
///   `i64` range is java's `ArithmeticException`, caught as a `false`
///   return (no votes cast or cleared).
///
/// The witness/amount-count validation, SR-candidate existence check,
/// duplicate merge, total-vs-TRON-power check and the actual vote cast
/// live in the host's `tron_vote_witness` (java's
/// `VoteWitnessProcessor.validate`/`execute`), so a validation failure
/// returns 0 without mutating any votes.
pub fn vote_witness<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    require_non_staticcall!(context.interpreter);

    popn!(
        [amount_array_len, amount_array_off, witness_array_len, witness_array_off],
        context.interpreter
    );

    // java reads every offset/length through `DataWord.intValueSafe()`,
    // which saturates to `Integer.MAX_VALUE` when the word does not fit a
    // non-negative `int`.
    let witness_len = data_word_int_value_safe(&witness_array_len);
    let witness_off = data_word_int_value_safe(&witness_array_off);
    let amount_len = data_word_int_value_safe(&amount_array_len);
    let amount_off = data_word_int_value_safe(&amount_array_off);

    // Expand and charge memory for both arrays before reading. The span of
    // each ABI dynamic array is its length word PLUS its elements:
    // `memNeeded(offset, length*32 + 32)`. The trailing `+ 32` is the array's
    // LENGTH WORD and is REQUIRED for the length-word read at `offset` below —
    // revm faults (slice OOB) on an unexpanded read where java zero-extends.
    // NOTE (audit #20, deferred): java's pre-ALLOW_ENERGY_ADJUSTMENT (#81)
    // `getVoteWitnessCost` charges `length*32` (no +32) for ENERGY while still
    // needing the +32 expansion for the read; `adjustForFairEnergy` swaps to
    // `getVoteWitnessCost2` (`+32`) post-#81. Separating the energy cost from
    // the read-expansion is not expressible with the coupled `resize_memory`
    // here, so we keep the post-#81 (+32) charge — a <=1-word over-charge
    // pre-#81 on the barely-used opcode-vote path. Post-#81 (the 83M-validated
    // era) is exact. Charging both arrays yields the same high-water mark —
    // and memory energy — as java's single max-of-the-two charge.
    let witness_span = witness_len.saturating_mul(32).saturating_add(32);
    let amount_span = amount_len.saturating_mul(32).saturating_add(32);
    context
        .interpreter
        .resize_memory(context.host.gas_params(), witness_off, witness_span)?;
    context
        .interpreter
        .resize_memory(context.host.gas_params(), amount_off, amount_span)?;

    // Length-word check: the element count stored at each array's offset
    // must equal the supplied length parameter. java throws a
    // `BytecodeExecutionException` on mismatch, which halts execution and
    // spends all remaining energy.
    let witness_len_word = read_memory_word(&context.interpreter.memory, witness_off);
    let amount_len_word = read_memory_word(&context.interpreter.memory, amount_off);
    if data_word_int_value_safe(&witness_len_word) != witness_len
        || data_word_int_value_safe(&amount_len_word) != amount_len
    {
        return Err(InstructionResult::OutOfGas);
    }

    let caller = context.interpreter.input.target_address();

    // A length mismatch between the two arrays returns false without
    // halting.
    if witness_len != amount_len {
        push!(context.interpreter, U256::ZERO);
        return Ok(());
    }

    // Decode the element pairs. The amount word is read as a signed
    // 256-bit value that must fit in `i64`; an out-of-range amount is
    // java's `ArithmeticException` (`longValueExact`) → return false with
    // no votes cast or cleared.
    let mut votes: std::vec::Vec<(primitives::Address, i64)> =
        std::vec::Vec::with_capacity(witness_len);
    for i in 0..witness_len {
        let witness_word =
            read_memory_word(&context.interpreter.memory, witness_off + 32 + i * 32);
        let amount_word =
            read_memory_word(&context.interpreter.memory, amount_off + 32 + i * 32);
        let Some(amount) = u256_to_i64_exact(&amount_word) else {
            push!(context.interpreter, U256::ZERO);
            return Ok(());
        };
        votes.push((witness_word.into_address(), amount));
    }

    let result = context.host.tron_vote_witness(caller, &votes);
    push!(context.interpreter, U256::from(result.max(0) as u64));
    Ok(())
}

/// Reads a 32-byte word from interpreter memory at `offset`. Callers must
/// have expanded memory to cover `[offset, offset + 32)` first (mirrors
/// java's `Program.memoryLoad`, which only runs after the opcode's gas
/// function has charged the matching expansion).
#[inline]
fn read_memory_word<M: MemoryTr>(memory: &M, offset: usize) -> U256 {
    U256::try_from_be_slice(memory.slice_len(offset, 32).as_ref()).unwrap_or(U256::ZERO)
}

/// java `DataWord.intValueSafe()`: the word as a non-negative `int`, or
/// `Integer.MAX_VALUE` when it occupies more than four bytes or its low
/// 32 bits have the sign bit set. Returned as `usize` (always within
/// `0..=i32::MAX`) for use as a memory offset / element count.
#[inline]
fn data_word_int_value_safe(v: &U256) -> usize {
    let limbs = v.as_limbs();
    let low = limbs[0];
    let high_zero = limbs[1] == 0 && limbs[2] == 0 && limbs[3] == 0;
    // `> 4 bytes` ⇔ any bit above the low 32 set; `intValue < 0` ⇔ bit 31
    // set in the low 32 bits.
    if high_zero && (low >> 32) == 0 && (low >> 31) == 0 {
        low as usize
    } else {
        i32::MAX as usize
    }
}

/// WITHDRAWREWARD (0xd9) — withdraw accumulated SR rewards. Stack
/// in=0, out=1. The pushed value is the withdrawn amount.
pub fn withdraw_reward<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    // java `withdrawRewardAction` (OperationActions.java:911): unconditional
    // static-call guard, thrown before increaseNonce.
    require_non_staticcall!(context.interpreter);
    let caller = context.interpreter.input.target_address();
    let amount = context.host.tron_withdraw_reward(caller);
    push!(context.interpreter, U256::from(amount.max(0) as u64));
    Ok(())
}

/// FREEZEBALANCEV2 (0xda) — Stake 2.0 freeze. Stack: `[resourceType,
/// frozenBalance]`. Pushes `1`/`0`.
pub fn freeze_balance_v2<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    // java `freezeBalanceV2Action` (OperationActions.java:824): unconditional
    // static-call guard, thrown before increaseNonce.
    require_non_staticcall!(context.interpreter);
    popn!([resource_type, frozen_balance], context.interpreter);
    let caller = context.interpreter.input.target_address();
    let Some(frozen) = u256_to_i64_exact(&frozen_balance) else {
        push!(context.interpreter, U256::ZERO);
        return Ok(());
    };
    let result = context.host.tron_freeze_balance_v2(
        caller,
        frozen,
        u64_from_u256(&resource_type) as u32,
    );
    push!(context.interpreter, U256::from(result.max(0) as u64));
    Ok(())
}

/// UNFREEZEBALANCEV2 (0xdb) — Stake 2.0 unfreeze. Stack:
/// `[resourceType, unfreezeBalance]`. Pushes `1`/`0`.
pub fn unfreeze_balance_v2<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    // java `unfreezeBalanceV2Action` (OperationActions.java:836): unconditional
    // static-call guard, thrown before increaseNonce.
    require_non_staticcall!(context.interpreter);
    popn!([resource_type, unfreeze_balance], context.interpreter);
    let caller = context.interpreter.input.target_address();
    let Some(unfreeze) = u256_to_i64_exact(&unfreeze_balance) else {
        push!(context.interpreter, U256::ZERO);
        return Ok(());
    };
    let result = context.host.tron_unfreeze_balance_v2(
        caller,
        unfreeze,
        u64_from_u256(&resource_type) as u32,
    );
    push!(context.interpreter, U256::from(result.max(0) as u64));
    Ok(())
}

/// CANCELALLUNFREEZEV2 (0xdc) — cancel every pending unfreeze.
/// Stack in=0, out=1 (success bool).
pub fn cancel_all_unfreeze_v2<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    // java `cancelAllUnfreezeV2Action` (OperationActions.java:859): unconditional
    // static-call guard, thrown before increaseNonce.
    require_non_staticcall!(context.interpreter);
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
    // java `withdrawExpireUnfreezeAction` (OperationActions.java:849):
    // unconditional static-call guard, thrown before increaseNonce.
    require_non_staticcall!(context.interpreter);
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
    // java `delegateResourceAction` (OperationActions.java:869): unconditional
    // static-call guard, thrown before increaseNonce.
    require_non_staticcall!(context.interpreter);
    popn!(
        [resource_type, delegate_balance, receiver_address],
        context.interpreter
    );
    let caller = context.interpreter.input.target_address();
    let receiver = receiver_address.into_address();
    let Some(delegate) = u256_to_i64_exact(&delegate_balance) else {
        push!(context.interpreter, U256::ZERO);
        return Ok(());
    };
    let result = context.host.tron_delegate_resource(
        caller,
        delegate,
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
    // java `unDelegateResourceAction` (OperationActions.java:882): unconditional
    // static-call guard, thrown before increaseNonce.
    require_non_staticcall!(context.interpreter);
    popn!(
        [resource_type, undelegate_balance, receiver_address],
        context.interpreter
    );
    let caller = context.interpreter.input.target_address();
    let receiver = receiver_address.into_address();
    let Some(undelegate) = u256_to_i64_exact(&undelegate_balance) else {
        push!(context.interpreter, U256::ZERO);
        return Ok(());
    };
    let result = context.host.tron_undelegate_resource(
        caller,
        undelegate,
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

/// java `DataWord.sValue().longValueExact()`: the signed 256-bit value, or
/// `None` when it does not fit in a signed 64-bit integer. java throws
/// `ArithmeticException` there, which the staking opcodes catch and treat as a
/// no-op (push 0). Honest callers pass small non-negative amounts and agree
/// with the old `u64_from_u256(..) as i64`; only a crafted out-of-range word
/// is now rejected (as java does) instead of silently wrapping into a valid
/// amount that could slip past the host's balance check.
fn u256_to_i64_exact(v: &U256) -> Option<i64> {
    let limbs = v.as_limbs();
    let low = limbs[0];
    let high_zero = limbs[1] == 0 && limbs[2] == 0 && limbs[3] == 0;
    let high_ones = limbs[1] == u64::MAX && limbs[2] == u64::MAX && limbs[3] == u64::MAX;
    if high_zero && low >> 63 == 0 {
        Some(low as i64) // non-negative, fits in i64
    } else if high_ones && low >> 63 == 1 {
        Some(low as i64) // negative two's-complement, fits in i64
    } else {
        None
    }
}
