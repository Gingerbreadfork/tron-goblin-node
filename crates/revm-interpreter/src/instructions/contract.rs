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
    // `callToAddress`). A value DataWord outside signed-64-bit range throws
    // `ArithmeticException` which, not being a `TransferException`, propagates
    // to VM.java:100 -> `spendAllEnergy()`: the frame consumes ALL its
    // remaining energy and records `contractResult UNKNOWN`
    // (`RuntimeImpl.setResultCode` has no `ArithmeticException` arm). Ungated on
    // ALLOW_TVM_CONSTANTINOPLE — Program.java:821 has no branch on it, so this
    // is the spend-all flavour in every era, never the consumed-only
    // `TransferFailed`.
    //
    // `value()` is UNSIGNED (`new BigInteger(1, data)`), so the accepted set is
    // `[0, i64::MAX]` — the signed `sValue()` helper would wrongly admit the
    // two's-complement negative window.
    //
    // Depth: java checks `getCallDeep() == MAX_DEPTH` and answers by pushing
    // zero (`Program.createContract`, Program.java:799) BEFORE reaching
    // `createContractImpl`'s endowment read, so at the depth limit there is no
    // throw at all. CREATE2 is the exception — `Program.createContract2`
    // (Program.java:1639) gates its push-zero on `allowTvmCompatibleEvm()`, and
    // before that proposal it falls through to `createContractImpl` and DOES
    // hit the bare `longValueExact()`. When the depth refusal applies, skip the
    // guard and let frame construction produce java's push-zero.
    let depth_refuses_create = context.host.tron_call_depth_exhausted()
        && (!IS_CREATE2 || context.host.tron_allow_tvm_compatible_evm());
    if !depth_refuses_create && u256_to_i64_exact_unsigned(&value).is_none() {
        return Err(InstructionResult::TronBytecodeExecution);
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

    let (input, return_memory_offset, raw_return_offset) =
        get_memory_input_and_out_ranges(context.interpreter, context.host.gas_params())?;

    let is_call = KIND == CALL;
    let (gas_limit, bytecode, bytecode_hash, charged_new_account_state_gas) =
        load_acc_and_calc_gas(&mut context, to, has_transfer, is_call, local_gas_limit)?;

    // TRON fork: the call value (endowment) must fit in a signed 64-bit long.
    // java-tron's `Program.callToAddress` evaluates `msg.getEndowment().value()
    // .longValueExact()` (Program.java:1032-1041) BEFORE `checkTokenId` and
    // before any transfer/balance check. `DataWord.value()` is UNSIGNED
    // (`new BigInteger(1, data)`), so the accepted set is `[0, i64::MAX]` and
    // any word from 2^63 up throws `ArithmeticException`. A balance can never
    // reach that magnitude, so upstream revm would instead let `transfer_loaded`
    // fail with `OutOfFunds`, push 0, and let the contract continue to its own
    // REVERT — diverging from java, where the transaction dies at this opcode.
    // Applies to the value-bearing call opcodes (CALL/CALLCODE);
    // DELEGATECALL/STATICCALL carry no popped value. Only under the TRON VM
    // (`tron_enabled`).
    //
    // Depth first: java answers `getCallDeep() == MAX_DEPTH` with
    // `stackPushZero(); refundEnergy(...); return;` (Program.java:1002-1007)
    // before the endowment read, so at the limit there is no throw — skip the
    // guard and let frame construction produce that push-zero.
    //
    // Era: with ALLOW_TVM_CONSTANTINOPLE (#26) active java refunds the forwarded
    // energy and rethrows as `TransferException("endowment out of long range")`
    // — spend-all-exempt, `contractResult TRANSFER_FAILED`. Before #26 the raw
    // `ArithmeticException` propagates to VM.java:100, which runs
    // `spendAllEnergy()`, and `RuntimeImpl.setResultCode` has no arm for it →
    // `contractResult UNKNOWN`. The pre-#26 arm therefore neither refunds nor
    // marks a transfer failure.
    //
    // A PRECOMPILE target takes a different failure shape.
    // `OperationActions.exeCall:1033-1041` dispatches on the target address
    // alone — CALL and CALLCODE alike — and routes precompiles to
    // `callToPrecompiledAddress`, whose endowment read (`Program.java:1693`)
    // has NO try/catch in either era. The raw `ArithmeticException` therefore
    // always propagates: `VM.java:97-101` spends the frame's whole remaining
    // energy (only a `TransferException` is exempt) and
    // `RuntimeImpl.setResultCode` (RuntimeImpl.java:129-138) has no matching
    // arm, so the root frame records `contractResult UNKNOWN`. Ungated by
    // ALLOW_TVM_CONSTANTINOPLE, and CALLCODE is included: its
    // `contextAddress = senderAddress` (`Program.java:1687-1688`) only
    // neutralises the transfer block at `:1717`, five statements after the
    // throw.
    if matches!(KIND, CALL | CALLCODE)
        && context.host.tron_enabled()
        && !context.host.tron_call_depth_exhausted()
        && u256_to_i64_exact_unsigned(&value).is_none()
    {
        if context.host.tron_is_precompile(to) {
            return Err(InstructionResult::TronBytecodeExecution);
        }
        if context.host.tron_allow_tvm_constantinople() {
            context.interpreter.gas.erase_cost(gas_limit);
            return Err(InstructionResult::TransferFailed);
        }
        return Err(InstructionResult::TronBytecodeExecution);
    }

    // TRON fork: a CALL with non-zero TRX value to the executing contract's
    // OWN address is forbidden. java-tron's `Program.callToAddress` enters the
    // transfer block (its `senderAddress != contextAddress` guard is a
    // ByteString *reference* compare, always true for distinct objects) and
    // `VMUtils.validateForSmartContract` throws a `ContractValidateException`
    // ("Cannot transfer TRX to yourself", VMUtils.java:146-148). Only fires
    // under the TRON VM (`tron_enabled`); upstream EVM keeps the legal
    // `from == to` self-transfer. CALLCODE/DELEGATECALL/STATICCALL never reach
    // here: CALLCODE/DELEGATECALL keep the caller's own context (java sets
    // `contextAddress = senderAddress`, so its self-guard is false) and
    // STATICCALL carries no value.
    //
    // Two earlier java steps must be reproduced first, because both answer with
    // a push-zero rather than a throw and so PRE-EMPT this failure:
    //   * depth — `getCallDeep() == MAX_DEPTH` (Program.java:1002-1007);
    //   * sender balance — `if (senderBalance < endowment) { stackPushZero();
    //     refundEnergy(...); return; }` (Program.java:1049-1055), which runs
    //     before the transfer block. When the sender cannot fund the transfer,
    //     emitting the frame lets `transfer_loaded`'s `from == to` arm return
    //     `OutOfFunds`, which is that same push-zero.
    // The balance read targets the executing contract's own address, always
    // already warm, so it adds no access-list or gas side effect.
    //
    // Era: with ALLOW_TVM_CONSTANTINOPLE (#26) active `callToAddress` refunds
    // the forwarded energy (`msg.getEnergy()`, which includes the value-transfer
    // stipend) and rethrows as `TransferException` — spend-all-exempt,
    // `contractResult TRANSFER_FAILED`, settling consumed-only via
    // `last_frame_result`'s `is_ok_or_revert` branch. Before #26 it is a plain
    // `BytecodeExecutionException`, which VM.java:100 follows with
    // `spendAllEnergy()` and `RuntimeImpl` maps to `contractResult UNKNOWN`.
    if KIND == CALL
        && has_transfer
        && to == context.interpreter.input.target_address()
        && context.host.tron_enabled()
        && !context.host.tron_call_depth_exhausted()
        && context
            .host
            .balance(context.interpreter.input.target_address())
            .is_some_and(|b| b.data >= value)
    {
        if context.host.tron_allow_tvm_constantinople() {
            context.interpreter.gas.erase_cost(gas_limit);
            return Err(InstructionResult::TransferFailed);
        }
        return Err(InstructionResult::TronBytecodeExecution);
    }

    // TRON fork: before ALLOW_TVM_SOLIDITY_059 (#32) a contract may NOT create
    // the recipient of a value transfer. java's `Program.callToAddress` calls
    // `createAccountIfNotExist`, whose whole body is wrapped in
    // `if (VMConfig.allowTvmSolidity059())`; with the proposal inactive the
    // account is left absent and `VMUtils.validateForSmartContract` then throws
    // `ContractValidateException("Validate InternalTransfer error, no ToAccount.
    // And not allowed to create an account in a smartContract.")`. The catch in
    // `callToAddress` picks the failure flavour: with ALLOW_TVM_CONSTANTINOPLE
    // (#26) active it refunds the forwarded energy and throws a
    // `TransferException` (spend-all-exempt, `contractResult TRANSFER_FAILED`);
    // before #26 a plain `BytecodeExecutionException`, which `VMActuator`
    // follows with `spendAllEnergy()` and `RuntimeImpl` maps to `UNKNOWN`.
    // Both flavours are contained to this frame; only a root-frame throw
    // reaches the receipt.
    //
    // Ordering mirrors java exactly: the i64-endowment guard and the
    // self-transfer guard (both above) come first, because
    // `validateForSmartContract` checks `toAddress == ownerAddress` before it
    // looks the recipient up. The sender-balance term reproduces java's earlier
    // `if (senderBalance < endowment) { stackPushZero(); refundEnergy(...);
    // return; }` — an under-funded CALL must still push 0 and let the caller
    // continue, so the recipient is only consulted once the sender can afford
    // the transfer.
    //
    // Existence is the JOURNAL-AWARE check because java reads
    // `getContractState().newRepositoryChild()`, which layers same-tx writes.
    // Restricted to `KIND == CALL`: java sets `contextAddress = senderAddress`
    // for CALLCODE/DELEGATECALL so its `senderAddress != contextAddress`
    // reference compare skips the whole transfer block, and STATICCALL carries
    // no value. CREATE/CREATE2 are likewise excluded — `createContractImpl`
    // creates `newAddress` before validating (java's own
    // "TODO: unreachable exception").
    //
    // Precompile targets are excluded here, but for the opposite reason:
    // `callToPrecompiledAddress` NEVER reaches `createAccountIfNotExist`, so
    // its recipient is missing at every height, not only before #32, and its
    // failure is never converted to a `TransferException`. That case is handled
    // where the precompile frame is built, ungated and with spend-all energy.
    if KIND == CALL
        && has_transfer
        && context.host.tron_enabled()
        && !context.host.tron_call_depth_exhausted()
        && !context.host.tron_allow_tvm_solidity_059()
        && !context.host.tron_is_precompile(to)
        && !context.host.tron_account_exists_or_created(to)
        && context
            .host
            .balance(context.interpreter.input.target_address())
            .is_some_and(|b| b.data >= value)
    {
        context.interpreter.gas.erase_cost(gas_limit);
        if context.host.tron_allow_tvm_constantinople() {
            return Err(InstructionResult::TransferFailed);
        }
        // Pre-Constantinople java throws `BytecodeExecutionException`, which
        // `VM.play` catches for THIS frame: the frame spends all its energy and
        // halts, and the caller pushes zero and continues. Only a root-frame
        // throw reaches the receipt, as UNKNOWN.
        return Err(InstructionResult::TronBytecodeExecution);
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
                tron_token_id_word: U256::ZERO,
                tron_token_value: 0,
                tron_raw_return_offset: raw_return_offset,
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

    // Static-call restriction. java `callTokenAction` (OperationActions.java:
    // 973-987) throws `StaticCallModificationException` only for a CALLTOKEN
    // that actually carries a value: `if (program.isStaticCall() &&
    // !value.isZero())` — the same predicate `callAction` uses for CALL. A
    // zero-value CALLTOKEN moves nothing (the transfer block in
    // `Program.callToAddress` is gated on `endowment > 0`) and is permitted
    // inside a static context. The throw happens before `exeCall`, so it
    // precedes the endowment, `checkTokenId` and self-transfer checks below;
    // `CallNotAllowedInsideStatic` is a spend-all halt recording
    // `contractResult UNKNOWN`, matching java's `spendAllEnergy` +
    // `setRuntimeFailure` for a `BytecodeExecutionException` subclass.
    if context.interpreter.runtime_flag.is_static() && has_transfer {
        return Err(InstructionResult::CallNotAllowedInsideStatic);
    }

    let (input, return_memory_offset, raw_return_offset) =
        get_memory_input_and_out_ranges(context.interpreter, context.host.gas_params())?;

    // CALLTOKEN gas accounting follows CALL: cold/warm access, value-
    // transfer surcharge if non-zero TRX, new-account gas if applicable.
    let (gas_limit, bytecode, bytecode_hash, charged_new_account_state_gas) =
        load_acc_and_calc_gas(&mut context, to, has_transfer, /* is_call */ true, local_gas_limit)?;

    // java `Program.isTokenTransfer` (Program.java:1827-1833): a CALLTOKEN is a
    // TRC-10 transfer when ALLOW_MULTI_SIGN (#20) is active — `callTokenAction`
    // passes `VMConfig.allowMultiSign()` as `isTokenTransferMsg`, so post-#20 it
    // is unconditionally true — otherwise when `msg.getTokenId().longValue() !=
    // 0`. `DataWord.longValue()` (DataWord.java:237-245) is a LOW-64-BIT
    // truncation, not a whole-word test, so a word whose low 8 bytes are zero
    // takes the native path however its high bytes are set. When this is false
    // `value` is a NATIVE TRX call-value rather than a token amount.
    let is_token_transfer = context.host.tron_allow_multi_sign() || u64_from_u256(&token_id) != 0;

    // The asset-store key and the token amount java carries into the callee.
    // `Program.java:1059` derives the key as
    // `String.valueOf(msg.getTokenId().longValue())` — low-64 SIGNED decimal,
    // negatives included — which is what `u64_from_u256(..) as i64` reproduces.
    // On the native path java zeroes BOTH the token id and the token value it
    // hands to the child (`Program.java:1135-1136`,
    // `!isTokenTransfer ? DataWord.ZERO() : callValue` / `... : msg.getTokenId()`),
    // so the asset machinery must see nothing at all.
    let (token_id_i64, token_value_i64) = if is_token_transfer {
        (u64_from_u256(&token_id) as i64, u64_from_u256(&value) as i64)
    } else {
        (0, 0)
    };

    // java `Program.callToAddress` (Program.java:1030-1041) reads the endowment
    // as `msg.getEndowment().value().longValueExact()` before `checkTokenId` and
    // before any balance or self-transfer check. For CALLTOKEN the endowment IS
    // the popped `value`: `callTokenAction` (OperationActions.java:973-987)
    // hands it to `exeCall`, which builds `MessageCall(op, energy, codeAddress,
    // value, ...)` — the 4th constructor argument is `endowment`. `value()` is
    // UNSIGNED, so any word from 2^63 up throws `ArithmeticException`. Without
    // this guard the word is silently truncated to its low 64 bits below.
    //
    // Depth and era handling match the CALL/CALLCODE endowment guard: java's
    // `getCallDeep() == MAX_DEPTH` push-zero precedes the read, and
    // ALLOW_TVM_CONSTANTINOPLE (#26) selects `TransferException` (refund the
    // forwarded energy, consumed-only, TRANSFER_FAILED) over the older raw
    // `ArithmeticException` (spend-all, UNKNOWN).
    // A precompile target takes the same different shape as CALL/CALLCODE:
    // `callToPrecompiledAddress:1693` reads the endowment with no try/catch in
    // either era, so the `ArithmeticException` is always spend-all + UNKNOWN.
    // Reading it here also reproduces java's ordering — `:1693` precedes
    // `checkTokenId` at `:1697` — and stops the low-64-bit truncation above
    // from reaching the TRC-10 machinery with a wrapped or negative amount.
    if !context.host.tron_call_depth_exhausted() && u256_to_i64_exact_unsigned(&value).is_none() {
        if context.host.tron_is_precompile(to) {
            return Err(InstructionResult::TronBytecodeExecution);
        }
        if context.host.tron_allow_tvm_constantinople() {
            context.interpreter.gas.erase_cost(gas_limit);
            return Err(InstructionResult::TransferFailed);
        }
        return Err(InstructionResult::TronBytecodeExecution);
    }

    // java `checkTokenId` (Program.java:1046, 1799-1824): once ALLOW_MULTI_SIGN
    // (#20) is active, CALLTOKEN's tokenId must be > MIN_TOKEN_ID (1_000_000).
    // java's predicate is `(tokenId <= MIN_TOKEN_ID && tokenId != 0) ||
    // (tokenId == 0 && msg.isTokenTransferMsg())`; under ALLOW_MULTI_SIGN
    // `isTokenTransferMsg` is always true for CALLTOKEN, so the two arms
    // collapse to "reject everything <= MIN_TOKEN_ID". The id is read with the
    // SIGNED `sValue()` (Program.java:1804), so `u256_to_i64_exact` is the right
    // helper here — not the unsigned endowment form. Both of java's failure arms
    // fork the same way on ALLOW_TVM_CONSTANTINOPLE: `TransferException` with
    // the forwarded energy refunded from #26 on, otherwise a raw
    // `ArithmeticException` / `BytecodeExecutionException` that spends all
    // energy and records UNKNOWN.
    if context.host.tron_allow_multi_sign()
        && !context.host.tron_call_depth_exhausted()
        && u256_to_i64_exact(&token_id).map_or(true, |id| id <= 1_000_000)
    {
        if context.host.tron_allow_tvm_constantinople() {
            context.interpreter.gas.erase_cost(gas_limit);
            return Err(InstructionResult::TransferFailed);
        }
        return Err(InstructionResult::TronBytecodeExecution);
    }

    // TRON fork: a CALLTOKEN carrying value to the executing contract's OWN
    // address is forbidden on BOTH of java's branches. `Program.callToAddress`
    // enters the transfer block (its `senderAddress != contextAddress` guard is
    // a reference compare, always true for distinct arrays) and
    // `VMUtils.validateForSmartContract` rejects the self-transfer either way:
    // the TRX overload throws "Cannot transfer TRX to yourself"
    // (VMUtils.java:146-148) and the TRC-10 overload "Cannot transfer asset to
    // yourself" (VMUtils.java:201-203). The native path is therefore banned too,
    // which is why this check does not consult `is_token_transfer`.
    //
    // Returning here — BEFORE the child frame is created — also means
    // `Trc10Inspector::call` never runs for a self-CALLTOKEN, so the asset_v2
    // debit/credit (which would otherwise net-mint `value` to the caller, since
    // the caller and target rows are the same account) never happens. That
    // ordering must be preserved in both eras.
    //
    // java's earlier per-branch balance check answers with a push-zero rather
    // than a throw (`if (senderBalance < endowment) { stackPushZero();
    // refundEnergy(...); return; }`, Program.java:1049-1063) and so pre-empts
    // this failure. The balance source follows the branch java takes: the TOKEN
    // balance for a TRC-10 transfer, the TRX balance for a native one. When the
    // sender is short, emitting the frame reproduces the push-zero —
    // `Trc10Inspector::call` for the token case, `transfer_loaded`'s `from == to`
    // arm for the native one. Depth and era handling as above.
    if has_transfer
        && to == context.interpreter.input.target_address()
        && !context.host.tron_call_depth_exhausted()
        && if is_token_transfer {
            i128::from(
                context
                    .host
                    .tron_token_balance(context.interpreter.input.target_address(), token_id_i64),
            ) >= i128::from(token_value_i64)
        } else {
            context
                .host
                .balance(context.interpreter.input.target_address())
                .is_some_and(|b| b.data >= value)
        }
    {
        if context.host.tron_allow_tvm_constantinople() {
            context.interpreter.gas.erase_cost(gas_limit);
            return Err(InstructionResult::TransferFailed);
        }
        return Err(InstructionResult::TronBytecodeExecution);
    }

    // TRON fork: the TRC-10 arm of the pre-ALLOW_TVM_SOLIDITY_059 (#32)
    // "cannot create an account in a smart contract" rule. Same gate and same
    // two failure flavours as the native value CALL above, but the refusal text
    // comes from the TRC-10 overload of `VMUtils.validateForSmartContract`
    // ("no ToAccount. And not allowed to create account in smart contract").
    //
    // Ordering follows `Program.callToAddress`: `checkTokenId` (above), then the
    // sender's TOKEN balance — `if (senderBalance < endowment) { stackPushZero();
    // refundEnergy(...); return; }` on the `isTokenTransfer` branch — and only
    // then `createAccountIfNotExist`. The balance term is therefore a guard, not
    // a failure: an under-funded CALLTOKEN still pushes 0 and lets the caller
    // continue (`Trc10Inspector::call` produces that outcome).
    //
    // Restricted to `is_token_transfer`: when it is false (pre-ALLOW_MULTI_SIGN
    // with tokenId == 0) java treats `value` as a NATIVE TRX endowment and takes
    // the `!isTokenTransfer` arm, which the native self-transfer ban above and
    // the ordinary CALL machinery below already cover.
    //
    // Precompile targets are excluded: `callToPrecompiledAddress` never reaches
    // `createAccountIfNotExist`, so its TRC-10 recipient is missing at every
    // height and the failure is never converted to a `TransferException`. That
    // case is handled where the precompile frame is built, ungated and with
    // spend-all energy.
    if is_token_transfer
        && has_transfer
        && !context.host.tron_call_depth_exhausted()
        && !context.host.tron_allow_tvm_solidity_059()
        && !context.host.tron_is_precompile(to)
        && !context.host.tron_account_exists_or_created(to)
        && context
            .host
            .tron_token_balance(context.interpreter.input.target_address(), token_id_i64)
            >= token_value_i64
    {
        context.interpreter.gas.erase_cost(gas_limit);
        if context.host.tron_allow_tvm_constantinople() {
            return Err(InstructionResult::TransferFailed);
        }
        return Err(InstructionResult::TronBytecodeExecution);
    }

    let caller = context.interpreter.input.target_address();
    let target_address = to;
    let scheme = CallScheme::Call;
    // The callee inherits the caller's static context. java builds the child
    // invoke with `msg.getOpCode() == Op.STATICCALL || isStaticCall()`
    // (Program.java:1138); CALLTOKEN is never STATICCALL, so the child is static
    // exactly when the frame issuing the CALLTOKEN is. A zero-value CALLTOKEN is
    // reachable inside a static context, so this must propagate or the callee
    // could SSTORE/LOG/CREATE where java forbids it.
    let is_static = context.interpreter.runtime_flag.is_static();
    // java `ProgramInvokeFactory`: the callee's native side is
    // `!isTokenTransfer ? callValue : ZERO`. For a token transfer the native
    // value is ZERO and `value` travels as the TRC-10 amount via `tron_token_*`
    // (the host applies the asset_v2 debit/credit before the callee's first
    // instruction). For a pre-ALLOW_MULTI_SIGN CALLTOKEN with tokenId == 0
    // (`is_token_transfer == false`) `value` is the NATIVE TRX call-value.
    let call_value = if is_token_transfer {
        CallValue::Transfer(U256::ZERO)
    } else {
        CallValue::Transfer(value)
    };

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
                // `CALLTOKENID` inside the callee pushes the whole 32-byte word
                // java passed to `createProgramInvoke` (`msg.getTokenId()`,
                // Program.java:1136), which before ALLOW_MULTI_SIGN can carry
                // high bytes the low-64 asset key above does not. Zeroed on the
                // native path, matching java's `!isTokenTransfer ?
                // DataWord.ZERO() : msg.getTokenId()`.
                tron_token_id_word: if is_token_transfer {
                    token_id
                } else {
                    U256::ZERO
                },
                tron_token_value: token_value_i64,
                tron_raw_return_offset: raw_return_offset,
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
///
/// java pushes the id `DataWord` verbatim (`OperationActions.java:764-769`
/// `program.stackPush(program.getTokenId())` → `Program.java:1479-1480`
/// `invoke.getTokenId().clone()`), so the full 32-byte word the CALLTOKEN
/// carried is what reaches the callee — NOT the low-64-signed value used to key
/// the asset store. The two coincide once `checkTokenId` constrains the id to
/// `(1_000_000, i64::MAX]`, and can differ before ALLOW_MULTI_SIGN (#20).
pub fn call_token_id<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    let v = context.interpreter.input.tron_token_id_word();
    push!(context.interpreter, v);
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
    // java `checkTokenIdInTokenBalance` (Program.java:1469, 1838-1853): once
    // ALLOW_MULTI_SIGN (#20) is active the tokenId is read with the SIGNED
    // `sValue().longValueExact()` and two arms can fail. Pre-ALLOW_MULTI_SIGN
    // the opcode just queries the (usually absent) id and pushes 0.
    //
    // Out of signed-i64 range: gated on ALLOW_TVM_CONSTANTINOPLE (#26) —
    // `TransferException` from #26 on (consumed-only, TRANSFER_FAILED),
    // otherwise the raw `ArithmeticException` (spend-all, UNKNOWN).
    //
    // `<= MIN_TOKEN_ID` (1_000_000): `BytecodeExecutionException` in BOTH eras —
    // Program.java:1848-1851 has NO Constantinople branch on that arm — so it is
    // always spend-all with `contractResult UNKNOWN`.
    //
    // Neither arm refunds: unlike `checkTokenId`, `checkTokenIdInTokenBalance`
    // contains no `refundEnergy` call at all.
    if context.host.tron_allow_multi_sign() {
        match u256_to_i64_exact(&token_id) {
            None => {
                if context.host.tron_allow_tvm_constantinople() {
                    return Err(InstructionResult::TransferFailed);
                }
                return Err(InstructionResult::TronBytecodeExecution);
            }
            Some(id) if id <= 1_000_000 => {
                return Err(InstructionResult::TronBytecodeExecution)
            }
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
    // java `Program.freeze` reads the amount with `frozenBalance.sValue()
    // .longValueExact()` (Program.java:1947) INSIDE the try, so a word outside
    // signed-64 range throws `ArithmeticException` and the opcode pushes 0 —
    // but only AFTER `increaseNonce()` (Program.java:1934) has already run.
    // Substituting 0 reproduces both halves: the host bumps the internal-tx
    // nonce and then rejects at its `frozen_balance <= 0` guard before any
    // store write. An early return here would skip the nonce bump and shift
    // every later CREATE address in the transaction.
    //
    // The resource code keeps the truncating reading: java's v1
    // `parseResourceCode` (Program.java:2240) switches on `DataWord.intValue()`,
    // which accumulates all 32 bytes into an `int` and never throws.
    // The freezing account's IN-FLIGHT TRX balance. java's
    // `FreezeBalanceProcessor.validate` gates against the frame `Repository`,
    // which already holds TRX credited earlier in this same transaction
    // (top-level callValue is transferred pre-play, VMActuator.java:438-439;
    // inner-CALL endowments land in the child repository). The journal — not
    // the chainbase account store — is authoritative for it here, exactly as
    // for SELFDESTRUCT (host.rs).
    let owner_balance = context
        .host
        .balance(caller)
        .map(|b| i64::try_from(b.data).unwrap_or(i64::MAX))
        .unwrap_or(0);
    let result = context.host.tron_freeze(
        caller,
        u256_to_i64_exact(&frozen_balance).unwrap_or(0),
        // Stake 1.0 had no explicit duration arg from the stack —
        // java-tron derived it from chain params. Pass 0; Host can
        // re-derive.
        0,
        u64_from_u256(&resource_type) as u32,
        Some(receiver),
        owner_balance,
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
    // java bumps the internal-tx nonce (`increaseNonce`, Program.java:2035)
    // ABOVE the try that `sValue().longValueExact()` throws from
    // (Program.java:2044), so an out-of-range amount still advances the nonce.
    // Passing 0 keeps the host call — and therefore the bump — while the host's
    // `frozen_balance <= 0` guard reproduces java's rejection with no state
    // change. That nonce seeds `generateContractAddress` (Program.java:807), so
    // skipping it would move every later CREATE address in the transaction.
    // The freezing contract's IN-FLIGHT TRX balance. java's
    // `FreezeBalanceV2Processor.validate` (line 41) checks frozenBalance against
    // the frame `Repository`, which already holds TRX received earlier in this
    // same transaction (top-level callValue is credited pre-play,
    // VMActuator.java:438-439; inner-CALL endowments land in the child
    // repository). The journal — not the chainbase account store — is
    // authoritative for it here, exactly as for SELFDESTRUCT (host.rs).
    let owner_balance = context
        .host
        .balance(caller)
        .map(|b| i64::try_from(b.data).unwrap_or(i64::MAX))
        .unwrap_or(0);
    let result = context.host.tron_freeze_balance_v2(
        caller,
        u256_to_i64_exact(&frozen_balance).unwrap_or(0),
        resource_code_v2(&resource_type),
        owner_balance,
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
    // Nonce ordering as in `freeze_balance_v2` above: java's `increaseNonce`
    // (Program.java:2066) precedes the throwing `longValueExact`
    // (Program.java:2073), so the host must still be entered on an
    // out-of-range amount.
    let result = context.host.tron_unfreeze_balance_v2(
        caller,
        u256_to_i64_exact(&unfreeze_balance).unwrap_or(0),
        resource_code_v2(&resource_type),
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
    // Nonce ordering as in `freeze_balance_v2` above: java's `increaseNonce`
    // (Program.java:2176) precedes the throwing `longValueExact`
    // (Program.java:2187). The host rejects amount 0 at its
    // `balance < TRX_PRECISION` guard, after the bump and before any write.
    let result = context.host.tron_delegate_resource(
        caller,
        u256_to_i64_exact(&delegate_balance).unwrap_or(0),
        receiver,
        resource_code_v2(&resource_type),
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
    // Nonce ordering as in `freeze_balance_v2` above: java's `increaseNonce`
    // (Program.java:2210) precedes the throwing `longValueExact`
    // (Program.java:2221).
    let result = context.host.tron_undelegate_resource(
        caller,
        u256_to_i64_exact(&undelegate_balance).unwrap_or(0),
        receiver,
        resource_code_v2(&resource_type),
    );
    push!(context.interpreter, U256::from(result.max(0) as u64));
    Ok(())
}

/// Truncate a `U256` to its low 64 bits.
///
/// This is the reading java's *v1* resource-code path uses: `parseResourceCode`
/// (Program.java:2240) and `Program.freezeExpireTime` (Program.java:2000) both
/// switch on `DataWord.intValue()`, which accumulates all 32 bytes into an
/// `int` (`DataWord.java:208-216`) and therefore truncates to the low 32 bits
/// without ever throwing — its javadoc's `@throws ArithmeticException` is
/// wrong. The Stake-2.0 opcodes use [`resource_code_v2`] instead.
fn u64_from_u256(v: &U256) -> u64 {
    let words = v.as_limbs();
    words[0]
}

/// java `Program.parseResourceCodeV2` (Program.java:2250): `DataWord.sValue()
/// .byteValueExact()` switched to BANDWIDTH/ENERGY/TRON_POWER. Every other
/// 256-bit word yields `UNRECOGNIZED` — whether it overflows a signed byte
/// (java throws `ArithmeticException` and catches it, returning UNRECOGNIZED)
/// or simply falls outside `0..=2` — so only an exact 0, 1 or 2 across all 256
/// bits is a resource code. `sValue()` is the SIGNED reading
/// (`DataWord.java:259-261`), so large-negative words are rejected too.
///
/// Anything else is returned as `u32::MAX`, which every host bridge rejects
/// with its `resource_type > N` guard — after the internal-tx nonce bump and
/// before any store access, exactly as java's validate-throws path discards the
/// child `Repository`.
fn resource_code_v2(v: &U256) -> u32 {
    let limbs = v.as_limbs();
    if limbs[1] == 0 && limbs[2] == 0 && limbs[3] == 0 && limbs[0] <= 2 {
        limbs[0] as u32
    } else {
        u32::MAX
    }
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

/// java `DataWord.value().longValueExact()`: the UNSIGNED 256-bit value, or
/// `None` when it exceeds `i64::MAX`.
///
/// `DataWord.value()` is `new BigInteger(1, data)` (`DataWord.java:197-199`), so
/// the whole word is read as a MAGNITUDE and any bit at or above bit 63 puts it
/// outside signed 64-bit range, where `longValueExact()` throws
/// `ArithmeticException`. The accepted set is exactly `[0, i64::MAX]`.
///
/// This is the endowment form, used wherever java reads a call/create value:
/// `Program.java:821` (CREATE/CREATE2) and `Program.java:1034`
/// (CALL/CALLCODE/CALLTOKEN). [`u256_to_i64_exact`] mirrors the signed
/// `sValue()` and is the form the token-id and staking opcodes use; it
/// additionally accepts the two's-complement negative window
/// `[2^256 - 2^63, 2^256)`, which java's `value()` rejects.
fn u256_to_i64_exact_unsigned(v: &U256) -> Option<i64> {
    let limbs = v.as_limbs();
    if limbs[1] == 0 && limbs[2] == 0 && limbs[3] == 0 && limbs[0] >> 63 == 0 {
        Some(limbs[0] as i64)
    } else {
        None
    }
}

#[cfg(test)]
mod tron_endowment_predicate_tests {
    use super::{u256_to_i64_exact, u256_to_i64_exact_unsigned};
    use primitives::U256;

    /// The two predicates mirror java's two `DataWord` readings and must agree
    /// everywhere EXCEPT the two's-complement negative window
    /// `[2^256 - 2^63, 2^256)`, which `sValue()` accepts and `value()` rejects.
    /// Endowments are read with `value()`; token ids and staking amounts with
    /// `sValue()`.
    #[test]
    fn signed_and_unsigned_readings_differ_only_on_the_negative_window() {
        // Agreement on the non-negative range.
        for v in [
            U256::ZERO,
            U256::from(1u64),
            U256::from(1_000_001u64),
            U256::from(i64::MAX as u64),
        ] {
            assert_eq!(u256_to_i64_exact(&v), u256_to_i64_exact_unsigned(&v), "{v}");
            assert!(u256_to_i64_exact_unsigned(&v).is_some());
        }

        // 2^63 — one above i64::MAX — is out of range under BOTH readings.
        let two_63 = U256::from(1u64) << 63;
        assert_eq!(u256_to_i64_exact(&two_63), None);
        assert_eq!(u256_to_i64_exact_unsigned(&two_63), None);

        // The window the unsigned reading closes: all-ones is -1 signed.
        assert_eq!(u256_to_i64_exact(&U256::MAX), Some(-1));
        assert_eq!(u256_to_i64_exact_unsigned(&U256::MAX), None);

        // ... and its low end, two's-complement i64::MIN.
        let i64_min_word = U256::MAX - (U256::from(1u64) << 63) + U256::from(1u64);
        assert_eq!(u256_to_i64_exact(&i64_min_word), Some(i64::MIN));
        assert_eq!(u256_to_i64_exact_unsigned(&i64_min_word), None);

        // 2^64 has a ZERO low limb: a truncating reading would see 0.
        let two_64 = U256::from(1u64) << 64;
        assert_eq!(u256_to_i64_exact_unsigned(&two_64), None);
        assert_eq!(u256_to_i64_exact(&two_64), None);
    }
}

#[cfg(test)]
mod tron_resource_code_tests {
    use super::{resource_code_v2, u64_from_u256};
    use primitives::U256;

    /// java `parseResourceCodeV2` accepts a resource code only when
    /// `sValue().byteValueExact()` succeeds AND lands on 0, 1 or 2. Every other
    /// word — high limbs set, low limb above 2, or a large-negative
    /// two's-complement word — is `UNRECOGNIZED`, which the host bridges see as
    /// the out-of-range sentinel.
    #[test]
    fn resource_code_v2_accepts_only_exact_zero_one_two() {
        assert_eq!(resource_code_v2(&U256::ZERO), 0);
        assert_eq!(resource_code_v2(&U256::from(1u64)), 1);
        assert_eq!(resource_code_v2(&U256::from(2u64)), 2);

        // Above the switch's arms.
        assert_eq!(resource_code_v2(&U256::from(3u64)), u32::MAX);

        // High limbs set: a low-32 truncation would read these as 0 and 1.
        assert_eq!(resource_code_v2(&(U256::from(1u64) << 32)), u32::MAX);
        assert_eq!(resource_code_v2(&((U256::from(1u64) << 32) + U256::from(1u64))), u32::MAX);
        assert_eq!(resource_code_v2(&(U256::from(1u64) << 64)), u32::MAX);

        // Large-negative words: `sValue()` reads the whole 256 bits as signed,
        // so `byteValueExact()` throws. `…FF00000000` also truncates to 0.
        assert_eq!(resource_code_v2(&U256::MAX), u32::MAX);
        assert_eq!(
            resource_code_v2(&(U256::MAX - U256::from(0xFFFF_FFFFu64))),
            u32::MAX
        );
    }

    /// Regression guard for the three v1 sites (FREEZE 0xd5, UNFREEZE 0xd6,
    /// FREEZEEXPIRETIME 0xd7) that must KEEP the truncating reading: java's
    /// `parseResourceCode` / `Program.freezeExpireTime` switch on
    /// `DataWord.intValue()`, which never throws, so `2^32` legitimately is
    /// BANDWIDTH there. Applying [`resource_code_v2`] to them would introduce a
    /// divergence rather than remove one.
    #[test]
    fn u64_from_u256_still_truncates_for_v1_resource_codes() {
        assert_eq!(u64_from_u256(&(U256::from(1u64) << 32)) as u32, 0);
        assert_eq!(
            u64_from_u256(&((U256::from(1u64) << 32) + U256::from(1u64))) as u32,
            1
        );
        assert_eq!(u64_from_u256(&(U256::MAX - U256::from(0xFFFF_FFFFu64))) as u32, 0);
    }
}
