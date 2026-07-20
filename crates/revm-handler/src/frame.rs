use crate::{
    evm::FrameTr, item_or_result::FrameInitOrResult, precompile_provider::PrecompileProvider,
    CallFrame, CreateFrame, FrameData, FrameResult, ItemOrResult,
};
use context::{result::FromStringError, LocalContextTr};
use context_interface::{
    context::{take_error, ContextError},
    host::TRON_MAX_CALL_DEPTH,
    journaled_state::{account::JournaledAccountTr, JournalCheckpoint, JournalTr},
    local::{FrameToken, OutFrame},
    tron_address_word, Cfg, ContextTr, Database,
};
use core::cmp::min;
use derive_where::derive_where;
use interpreter::{
    interpreter::{num_words, EthInterpreter, ExtBytecode},
    interpreter_action::FrameInit,
    interpreter_types::ReturnData,
    interpreter_action::tron_create_address,
    CallInput, CallInputs, CallOutcome, CallScheme, CallValue, CreateInputs, CreateOutcome,
    CreateScheme,
    FrameInput, Gas, InputsImpl, InstructionResult, Interpreter, InterpreterAction,
    InterpreterResult, InterpreterTypes, SharedMemory,
};
use primitives::{
    hardfork::SpecId::{self, HOMESTEAD, LONDON, SPURIOUS_DRAGON},
    Address, Bytes, U256,
};
use state::Bytecode;
use std::{borrow::ToOwned, boxed::Box, vec::Vec};

/// Frame implementation for Ethereum.
#[derive_where(Clone, Debug; IW,
    <IW as InterpreterTypes>::Stack,
    <IW as InterpreterTypes>::Memory,
    <IW as InterpreterTypes>::Bytecode,
    <IW as InterpreterTypes>::ReturnData,
    <IW as InterpreterTypes>::Input,
    <IW as InterpreterTypes>::RuntimeFlag,
    <IW as InterpreterTypes>::Extend,
)]
pub struct EthFrame<IW: InterpreterTypes = EthInterpreter> {
    /// Frame-specific data (Call, Create, or EOFCreate).
    pub data: FrameData,
    /// Input data for the frame.
    pub input: FrameInput,
    /// Current call depth in the execution stack.
    pub depth: usize,
    /// Journal checkpoint for state reversion.
    pub checkpoint: JournalCheckpoint,
    /// Interpreter instance for executing bytecode.
    pub interpreter: Interpreter<IW>,
    /// Whether the frame has been finished its execution.
    /// Frame is considered finished if it has been called and returned a result.
    pub is_finished: bool,
}

impl<IT: InterpreterTypes> FrameTr for EthFrame<IT> {
    type FrameResult = FrameResult;
    type FrameInit = FrameInit;
}

impl Default for EthFrame<EthInterpreter> {
    fn default() -> Self {
        Self::do_default(Interpreter::default())
    }
}

impl EthFrame<EthInterpreter> {
    /// Creates an new invalid [`EthFrame`].
    pub fn invalid() -> Self {
        Self::do_default(Interpreter::invalid())
    }

    fn do_default(interpreter: Interpreter<EthInterpreter>) -> Self {
        Self {
            data: FrameData::Call(CallFrame {
                return_memory_range: 0..0,
            }),
            input: FrameInput::Empty,
            depth: 0,
            checkpoint: JournalCheckpoint::default(),
            interpreter,
            is_finished: false,
        }
    }

    /// Returns true if the frame has finished execution.
    pub const fn is_finished(&self) -> bool {
        self.is_finished
    }

    /// Sets the finished state of the frame.
    pub const fn set_finished(&mut self, finished: bool) {
        self.is_finished = finished;
    }
}

/// Type alias for database errors from a context.
pub type ContextTrDbError<CTX> = <<CTX as ContextTr>::Db as Database>::Error;

impl EthFrame<EthInterpreter> {
    /// Clear and initialize a frame.
    #[expect(clippy::too_many_arguments)]
    #[inline(always)]
    pub fn clear(
        &mut self,
        data: FrameData,
        input: FrameInput,
        depth: usize,
        memory: SharedMemory,
        bytecode: ExtBytecode,
        inputs: InputsImpl,
        is_static: bool,
        spec_id: SpecId,
        gas_limit: u64,
        reservoir_remaining_gas: u64,
        checkpoint: JournalCheckpoint,
    ) {
        let Self {
            data: data_ref,
            input: input_ref,
            depth: depth_ref,
            interpreter,
            checkpoint: checkpoint_ref,
            is_finished: is_finished_ref,
        } = self;
        *data_ref = data;
        *input_ref = input;
        *depth_ref = depth;
        *is_finished_ref = false;
        interpreter.clear(
            memory,
            bytecode,
            inputs,
            is_static,
            spec_id,
            gas_limit,
            reservoir_remaining_gas,
        );
        *checkpoint_ref = checkpoint;
    }

    /// Make call frame
    #[inline]
    pub fn make_call_frame<
        CTX: ContextTr,
        PRECOMPILES: PrecompileProvider<CTX, Output = InterpreterResult>,
        ERROR: From<ContextTrDbError<CTX>> + FromStringError,
    >(
        mut this: OutFrame<'_, Self>,
        ctx: &mut CTX,
        precompiles: &mut PRECOMPILES,
        depth: usize,
        memory: SharedMemory,
        inputs: Box<CallInputs>,
    ) -> Result<ItemOrResult<FrameToken, FrameResult>, ERROR> {
        let reservoir_remaining_gas = inputs.reservoir;
        let charged_new_account_state_gas = inputs.charged_new_account_state_gas;
        let gas =
            Gas::new_with_regular_gas_and_reservoir(inputs.gas_limit, reservoir_remaining_gas);
        let return_result = |instruction_result: InstructionResult| {
            Ok(ItemOrResult::Result(FrameResult::Call(CallOutcome {
                result: InterpreterResult {
                    result: instruction_result,
                    gas,
                    output: Bytes::new(),
                },
                memory_offset: inputs.return_memory_offset.clone(),
                was_precompile_called: false,
                precompile_call_logs: Vec::new(),
                charged_new_account_state_gas,
                tron_raw_return_offset: inputs.tron_raw_return_offset,
            })))
        };

        // Check depth
        if depth > TRON_MAX_CALL_DEPTH {
            return return_result(InstructionResult::CallTooDeep);
        }

        // Create subroutine checkpoint
        let checkpoint = ctx.journal_mut().checkpoint();

        // TRON fork: a value-bearing CALL / CALLTOKEN whose target is a
        // PRECOMPILE cannot create the recipient, and dies when the recipient
        // has no account row.
        //
        // java-tron dispatches such a call to `Program.callToPrecompiledAddress`
        // (`OperationActions.exeCall:1033-1041` picks it whenever
        // `PrecompiledContracts.getContractForAddress` is non-null). That method
        // never calls `createAccountIfNotExist` — unlike `callToAddress:1083` —
        // so its transfer block (`Program.java:1716-1732`) reaches
        // `MUtil.transfer` / `VMUtils.validateForSmartContract` with no
        // `toAccount`, which throws `ContractValidateException`
        // ("no ToAccount. And not allowed to create an account in a
        // smartContract", `VMUtils.java:155-159`; TRC-10 twin at `:239-243`).
        // Both catches rethrow `BytecodeExecutionException`
        // (`Program.java:1723`, `:1730`).
        //
        // UNGATED at every height: `createAccountIfNotExist` is behind
        // ALLOW_TVM_SOLIDITY_059 (#32) but is unreachable from this method in
        // any era, and this method has no ALLOW_TVM_CONSTANTINOPLE branch, so
        // the failure never becomes a `TransferException`. The only
        // height-dependence is WHICH addresses are precompiles, which
        // `tron_is_precompile` resolves from the live proposal flags.
        //
        // Scope is CALL (0xf1) and CALLTOKEN (0xd0) only. For CALLCODE and
        // DELEGATECALL java sets `contextAddress = senderAddress`
        // (`Program.java:1687-1688`) — the same array object — so the guard
        // `senderAddress != contextAddress` at line 1717 is a reference compare
        // that is FALSE, skipping the whole transfer block. STATICCALL carries
        // no value. `CallScheme::Call` covers exactly CALL and CALLTOKEN.
        //
        // Two java checks take precedence and answer with a push-zero rather
        // than a throw, so both must be evaluated first: the depth limit
        // (`Program.java:1677`, the `TRON_MAX_CALL_DEPTH` return above) and
        // `senderBalance < endowment` (`Program.java:1707`). When the sender
        // cannot fund the transfer this block falls through unchanged and
        // `transfer_loaded` yields `OutOfFunds`, a revert-family result the
        // parent turns into exactly that push-zero plus full energy refund.
        if ctx.tron_enabled()
            && matches!(inputs.scheme, CallScheme::Call)
            && ctx.tron_is_precompile(inputs.bytecode_address)
        {
            let trx_value = match inputs.value {
                CallValue::Transfer(v) => v,
                _ => U256::ZERO,
            };
            let token_value = inputs.tron_token_value;

            // Precompile-outcome shape: `was_precompile_called` marks this as
            // the frame that invoked the precompile, which is what stops the
            // caller-killing branch in `return_result` from cascading into the
            // grandparent when the halt bubbles up.
            let precompile_transfer_failure = || {
                Ok(ItemOrResult::Result(FrameResult::Call(CallOutcome {
                    result: InterpreterResult {
                        result: InstructionResult::TronPrecompileTransferFailure,
                        gas,
                        output: Bytes::new(),
                    },
                    memory_offset: inputs.return_memory_offset.clone(),
                    was_precompile_called: true,
                    precompile_call_logs: Vec::new(),
                    charged_new_account_state_gas,
                    tron_raw_return_offset: inputs.tron_raw_return_offset,
                })))
            };

            // `long endowment = msg.getEndowment().value().longValueExact()`
            // (`Program.java:1693`) is NOT wrapped in a try/catch here, unlike
            // `callToAddress:1033-1042`. `DataWord.value()` is unsigned, so any
            // word from 2^63 up throws a bare `ArithmeticException` — spend-all
            // and `contractResult UNKNOWN`, never the `TransferException`
            // (consumed-only, TRANSFER_FAILED) the regular-call path produces
            // from #26 on. java evaluates this BEFORE the balance check at line
            // 1707, and it fires whether or not the target row exists.
            //
            // The CALL/CALLCODE/CALLTOKEN opcode handlers raise this in the
            // interpreter, ahead of frame construction, because the TRC-10
            // rail carries its amount on `tron_token_value` and is claimed by
            // `Trc10Inspector::call` before `make_call_frame` ever runs. This
            // arm therefore covers only a `CallInputs` built outside the
            // opcode path; it is deliberately not extended to `CallCode` or
            // the token rail, both of which the opcode handles.
            if trx_value > U256::from(i64::MAX as u64) {
                ctx.journal_mut().checkpoint_revert(checkpoint);
                return precompile_transfer_failure();
            }

            // `msg.getEndowment().value().longValueExact() > 0` at line 1717.
            // A CALLTOKEN carries its amount on exactly one of the two rails:
            // the TRC-10 amount when java classifies it as a token transfer,
            // the native TRX value otherwise.
            let endowment_positive = !trx_value.is_zero() || token_value > 0;
            if endowment_positive {
                // `Program.java:1699-1706` reads the balance from the rail the
                // transfer will use, then line 1707 compares it against the
                // endowment.
                let sender_can_afford = if token_value > 0 {
                    i128::from(ctx.tron_token_balance(inputs.caller, inputs.tron_token_id))
                        >= i128::from(token_value)
                } else {
                    ctx.balance(inputs.caller)
                        .is_some_and(|b| b.data >= trx_value)
                };
                // Journal-aware existence: java reads through the in-flight
                // `Repository`, so an account created earlier in this same
                // transaction is a live `toAccount`.
                if sender_can_afford && !ctx.tron_account_exists_or_created(inputs.target_address) {
                    ctx.journal_mut().checkpoint_revert(checkpoint);
                    return precompile_transfer_failure();
                }
            }
        }

        // Touch address. For "EIP-158 State Clear", this will erase empty accounts.
        if let CallValue::Transfer(value) = inputs.value {
            // Transfer value from caller to called account
            // Target will get touched even if balance transferred is zero.
            if let Some(i) =
                ctx.journal_mut()
                    .transfer_loaded(inputs.caller, inputs.target_address, value)
            {
                ctx.journal_mut().checkpoint_revert(checkpoint);
                return return_result(i.into());
            }
        }

        // TRON fork: look up the per-contract dynamic-energy factor for
        // this frame's target. Default impl (non-TRON hosts) returns 0
        // → zero-overhead pass-through for upstream EVM behaviour.
        let tron_dynamic_factor = ctx.tron_dynamic_energy_factor(inputs.target_address);
        // TRON fork: the executing contract's `SmartContract.version`. java sets
        // a CALL child frame's version from the callee's deployed code address
        // (`Program.java:1146`: `getContract(codeAddress).getContractVersion()`)
        // — `bytecode_address` is that code address. The top-level trigger frame
        // gets the deployed contract's stored version (`VMActuator.java:531`),
        // and a top-level CREATE is forced to 1 via the host's per-tx override.
        // Governs the EIP-150 1/64 retention + GASPRICE (version-1 only).
        let tron_contract_version = ctx.tron_contract_version(inputs.bytecode_address);
        let interpreter_input = InputsImpl {
            target_address: inputs.target_address,
            caller_address: inputs.caller,
            bytecode_address: Some(inputs.bytecode_address),
            input: inputs.input.clone(),
            call_value: inputs.value.get(),
            tron_token_id: inputs.tron_token_id,
            tron_token_id_word: inputs.tron_token_id_word,
            tron_token_value: inputs.tron_token_value,
            tron_dynamic_factor,
            tron_contract_version,
        };
        let is_static = inputs.is_static;
        let gas_limit = inputs.gas_limit;

        if let Some(result) = precompiles.run(ctx, &inputs).map_err(ERROR::from_string)? {
            let mut logs = Vec::new();
            if result.result.is_ok() {
                // Preserve the reservoir on the result gas so it can be reimbursed.
                // Precompiles don't use reservoir gas, but the first frame carries it.
                ctx.journal_mut().checkpoint_commit();
            } else {
                // clone logs that precompile created, only possible with custom precompiles.
                // checkpoint.log_i will be always correct.
                logs = ctx.journal_mut().logs()[checkpoint.log_i..].to_vec();
                ctx.journal_mut().checkpoint_revert(checkpoint);
            }
            return Ok(ItemOrResult::Result(FrameResult::Call(CallOutcome {
                result,
                memory_offset: inputs.return_memory_offset.clone(),
                was_precompile_called: true,
                precompile_call_logs: logs,
                charged_new_account_state_gas,
                tron_raw_return_offset: inputs.tron_raw_return_offset,
            })));
        }

        // TRON fork: advance the per-tx internal-transaction nonce counter for a
        // regular (non-precompile) call — java-tron's `callToAddress` calls
        // `increaseNonce` after the depth + balance checks, before building the
        // child program, and does so even when the target has no code (an EOA /
        // empty account); `callToPrecompiledAddress` does NOT (handled by the
        // early return above). `depth == 0` is the transaction-entry frame,
        // which is not an internal transaction, so it never bumps. The value
        // matters only for a later nested CREATE's address.
        if depth >= 1 {
            ctx.tron_bump_create_nonce();
        }

        // Get bytecode and hash - either from known_bytecode or load from account
        let (bytecode_hash, bytecode) = inputs.known_bytecode.clone();

        // Returns success if bytecode is empty.
        if bytecode.is_empty() {
            ctx.journal_mut().checkpoint_commit();
            return return_result(InstructionResult::Stop);
        }

        // Create interpreter and executes call and push new CallStackFrame.
        this.get(EthFrame::invalid).clear(
            FrameData::Call(CallFrame {
                return_memory_range: inputs.return_memory_offset.clone(),
            }),
            FrameInput::Call(inputs),
            depth,
            memory,
            ExtBytecode::new_with_hash(bytecode, bytecode_hash),
            interpreter_input,
            is_static,
            ctx.cfg().spec().into(),
            gas_limit,
            reservoir_remaining_gas,
            checkpoint,
        );
        Ok(ItemOrResult::Item(this.consume()))
    }

    /// Make create frame.
    #[inline]
    pub fn make_create_frame<
        CTX: ContextTr,
        ERROR: From<ContextTrDbError<CTX>> + FromStringError,
    >(
        mut this: OutFrame<'_, Self>,
        context: &mut CTX,
        depth: usize,
        memory: SharedMemory,
        inputs: Box<CreateInputs>,
    ) -> Result<ItemOrResult<FrameToken, FrameResult>, ERROR> {
        let reservoir_remaining_gas = inputs.reservoir();
        let spec = context.cfg().spec().into();
        // EIP-8037 refund for the CREATE opcode's upfront `create_state_gas` is
        // applied uniformly in `return_result` when the create fails (revert,
        // halt, or early-fail with `address == None`), so early-fail results
        // only carry the reservoir they inherited from the parent.
        let return_error = |e| {
            Ok(ItemOrResult::Result(FrameResult::Create(CreateOutcome {
                result: InterpreterResult {
                    result: e,
                    gas: Gas::new_with_regular_gas_and_reservoir(
                        inputs.gas_limit(),
                        reservoir_remaining_gas,
                    ),
                    output: Bytes::new(),
                },
                address: None,
            })))
        };

        // Check depth
        if depth > TRON_MAX_CALL_DEPTH {
            return return_error(InstructionResult::CallTooDeep);
        }

        // Fetch balance of caller.
        let journal = context.journal_mut();
        let mut caller_info = journal.load_account_mut(inputs.caller())?;

        // Check if caller has enough balance to send to the created contract.
        // decrement of balance is done in the create_account_checkpoint.
        if *caller_info.balance() < inputs.value() {
            return return_error(InstructionResult::OutOfFunds);
        }

        // Increase nonce of caller and check if it overflows. TRON accounts
        // have no nonce, so this bump is journal-only (discarded at commit) and
        // its value is NOT used for the address — but keep it so revm's
        // collision/empty-account checkpoint logic behaves as upstream.
        if !caller_info.bump_nonce() {
            return return_error(InstructionResult::Return);
        };

        let init_code_hash = matches!(inputs.scheme(), CreateScheme::Create2 { .. })
            .then(|| inputs.init_code_hash());

        drop(caller_info); // Drop caller info to avoid borrow checker issues.

        // TRON fork: derive the contract address java-tron's way and advance the
        // per-tx internal-transaction nonce counter. java-tron's `increaseNonce`
        // fires here (after the depth + balance checks above, before the
        // collision check), so a balance/depth failure does NOT bump — matching
        // the early returns above. CREATE uses the nonce BEFORE its own bump
        // (`generateContractAddress(rootTxId, nonce)`); CREATE2 ignores it but
        // still bumps (`createContractImpl` always increments). The 20-byte
        // result is the EVM half; the `0x41` TRON prefix is reattached at commit.
        let (created_address, is_create2) = match inputs.scheme() {
            CreateScheme::Create => {
                let nonce = context.tron_bump_create_nonce();
                (tron_create_address(context.tron_root_tx_id(), nonce), false)
            }
            CreateScheme::Create2 { .. } => {
                let addr = inputs.created_address(0);
                context.tron_bump_create_nonce();
                (addr, true)
            }
            CreateScheme::Custom { address } => (address, false),
        };
        // TRON fork: record the nested deploy so commit can write the
        // `SmartContract` row + `CreatedByContract` account fields java-tron's
        // `createContractImpl` creates here. Recorded for every CREATE/CREATE2
        // (Custom is our pre-installed top-level path, handled in execute.rs);
        // a create that later reverts simply never reaches commit, so the
        // deferred write is dropped.
        if !matches!(inputs.scheme(), CreateScheme::Custom { .. }) {
            context.tron_record_created_contract(created_address, inputs.caller(), is_create2);
        }
        let journal = context.journal_mut();

        // warm load account.
        journal.load_account(created_address)?;

        // Create account, transfer funds and make the journal checkpoint.
        let checkpoint = match context.journal_mut().create_account_checkpoint(
            inputs.caller(),
            created_address,
            inputs.value(),
            spec,
        ) {
            Ok(checkpoint) => checkpoint,
            Err(e) => return return_error(e.into()),
        };

        let bytecode = ExtBytecode::new_with_optional_hash(
            Bytecode::new_legacy(inputs.init_code().clone()),
            init_code_hash,
        );

        // TRON fork: a freshly-created contract has no prior dynamic
        // factor (it hasn't been touched yet). Subsequent CALLs into
        // it will pick up whatever the ContractStateStore says.
        //
        // The init frame's contract version is inherited from the parent (java
        // `Program.java:915` — nested CREATE child copies the parent's version),
        // stamped onto `CreateInputs` by the CREATE opcode handler; a top-level
        // CREATE forces 1 (`VMActuator.java:415`). Governs the init code's
        // EIP-150 1/64 retention + GASPRICE.
        let tron_contract_version = inputs.tron_contract_version();
        let interpreter_input = InputsImpl {
            target_address: created_address,
            caller_address: inputs.caller(),
            bytecode_address: None,
            input: CallInput::Bytes(Bytes::new()),
            call_value: inputs.value(),
            tron_token_id: 0,
            tron_token_id_word: U256::ZERO,
            tron_token_value: 0,
            tron_dynamic_factor: 0,
            tron_contract_version,
        };
        let gas_limit = inputs.gas_limit();

        this.get(EthFrame::invalid).clear(
            FrameData::Create(CreateFrame { created_address }),
            FrameInput::Create(inputs),
            depth,
            memory,
            bytecode,
            interpreter_input,
            false,
            spec,
            gas_limit,
            reservoir_remaining_gas,
            checkpoint,
        );

        Ok(ItemOrResult::Item(this.consume()))
    }

    /// Initializes a frame with the given context and precompiles.
    pub fn init_with_context<
        CTX: ContextTr,
        PRECOMPILES: PrecompileProvider<CTX, Output = InterpreterResult>,
    >(
        this: OutFrame<'_, Self>,
        ctx: &mut CTX,
        precompiles: &mut PRECOMPILES,
        frame_init: FrameInit,
    ) -> Result<
        ItemOrResult<FrameToken, FrameResult>,
        ContextError<<<CTX as ContextTr>::Db as Database>::Error>,
    > {
        // TODO cleanup inner make functions
        let FrameInit {
            depth,
            memory,
            frame_input,
        } = frame_init;

        match frame_input {
            FrameInput::Call(inputs) => {
                Self::make_call_frame(this, ctx, precompiles, depth, memory, inputs)
            }
            FrameInput::Create(inputs) => Self::make_create_frame(this, ctx, depth, memory, inputs),
            FrameInput::Empty => unreachable!(),
        }
    }
}

impl EthFrame<EthInterpreter> {
    /// Processes the next interpreter action, either creating a new frame or returning a result.
    pub fn process_next_action<
        CTX: ContextTr,
        ERROR: From<ContextTrDbError<CTX>> + FromStringError,
    >(
        &mut self,
        context: &mut CTX,
        next_action: InterpreterAction,
    ) -> Result<FrameInitOrResult<Self>, ERROR> {
        // Run interpreter

        let mut interpreter_result = match next_action {
            InterpreterAction::NewFrame(frame_input) => {
                let depth = self.depth + 1;
                return Ok(ItemOrResult::Item(FrameInit {
                    frame_input,
                    depth,
                    memory: self.interpreter.memory.new_child_context(),
                }));
            }
            InterpreterAction::Return(result) => result,
        };

        // DIAGNOSTIC (gated on TRON_OP_TRACE_TX): per-frame consumed-energy
        // attribution. The op-trace `cost`
        // field is forwarded-gas for CALL/CREATE so it can't be summed; this
        // logs each returning frame's gas.total_gas_spent() (its own ops + sub-calls) and
        // the contract, to localize which frame over-charges energy vs java.
        if interpreter::op_trace_on() {
            use interpreter::interpreter_types::InputsTr;
            eprintln!(
                "FRAMETRACE depth={} addr={} spent={} limit={} ok={}",
                self.depth,
                self.interpreter.input.target_address(),
                interpreter_result.gas.total_gas_spent(),
                interpreter_result.gas.limit(),
                interpreter_result.result.is_ok(),
            );
        }

        // Handle return from frame
        let result = match &self.data {
            FrameData::Call(frame) => {
                // return_call
                // Revert changes or not.
                if interpreter_result.result.is_ok() {
                    context.journal_mut().checkpoint_commit();
                } else {
                    context.journal_mut().checkpoint_revert(self.checkpoint);
                }
                // Propagate EIP-8037 new-account state-gas flag from the frame
                // input so the parent can refund the upfront charge if the call
                // ends in revert/halt.
                let charged_new_account_state_gas = match &self.input {
                    FrameInput::Call(inputs) => inputs.charged_new_account_state_gas,
                    _ => false,
                };
                let tron_raw_return_offset = match &self.input {
                    FrameInput::Call(inputs) => inputs.tron_raw_return_offset,
                    _ => U256::ZERO,
                };
                let mut outcome =
                    CallOutcome::new(interpreter_result, frame.return_memory_range.clone());
                outcome.charged_new_account_state_gas = charged_new_account_state_gas;
                outcome.tron_raw_return_offset = tron_raw_return_offset;
                ItemOrResult::Result(FrameResult::Call(outcome))
            }
            FrameData::Create(frame) => {
                return_create(
                    context,
                    self.checkpoint,
                    &mut interpreter_result,
                    frame.created_address,
                );

                ItemOrResult::Result(FrameResult::Create(CreateOutcome::new(
                    interpreter_result,
                    Some(frame.created_address),
                )))
            }
        };

        Ok(result)
    }

    /// Processes a frame result and updates the interpreter state accordingly.
    pub fn return_result<CTX: ContextTr, ERROR: From<ContextTrDbError<CTX>> + FromStringError>(
        &mut self,
        ctx: &mut CTX,
        result: FrameResult,
    ) -> Result<(), ERROR> {
        self.interpreter.memory.free_child_context();
        take_error::<ERROR, _>(ctx.error())?;

        // Insert result to the top frame.
        match result {
            FrameResult::Call(outcome) => {
                let out_gas = outcome.gas();
                let ins_result = *outcome.instruction_result();
                let returned_len = outcome.result.output.len();
                let from_precompile = outcome.was_precompile_called;
                let outcome_raw_offset = outcome.tron_raw_return_offset;

                let interpreter = &mut self.interpreter;
                let mem_length = outcome.memory_length();
                let mem_start = outcome.memory_start();
                interpreter.return_data.set_buffer(outcome.result.output);

                let target_len = min(mem_length, returned_len);

                if ins_result == InstructionResult::FatalExternalError {
                    panic!("Fatal external error in insert_call_outcome");
                }

                // TRON fork: an uncaught throw inside a precompile does not
                // return to the caller at all. java-tron's `VM.java` catch runs
                // `program.spendAllEnergy()` on the frame that executed the CALL
                // and stops it, so this frame consumes its entire remaining
                // budget and terminates — no 0/1 pushed, no return data copied
                // into memory, no unspent gas returned, no reservoir handling.
                //
                // Gated on `was_precompile_called` so only the frame that
                // invoked the precompile dies. The same result arriving from a
                // CHILD frame that already halted this way is an ordinary
                // failed call: java's `Program.callToAddress` pushes zero and
                // lets the parent continue, which is the generic path below.
                if from_precompile && ins_result == InstructionResult::PrecompileThrow {
                    interpreter.gas.spend_all();
                    interpreter.halt(InstructionResult::PrecompileThrow);
                    return Ok(());
                }

                // TRON fork: same shape for the transfer validation that fails
                // inside `Program.callToPrecompiledAddress`. java runs a
                // precompile INLINE in the caller's frame, so the
                // `BytecodeExecutionException("transfer failure")` it throws is
                // caught by `VM.java:97-105`, which spends the CALLING frame's
                // entire remaining energy — not merely the energy forwarded to
                // the call — and stops it. No 0/1 is pushed, no unspent energy
                // returned, no return data written.
                //
                // Gated on `was_precompile_called` so the halt stays FRAME-fatal:
                // when it bubbles up, the grandparent sees an ordinary failed
                // call and takes the generic path below, which is java's
                // `Program.callToAddress` push-zero.
                if from_precompile
                    && ins_result == InstructionResult::TronPrecompileTransferFailure
                {
                    interpreter.gas.spend_all();
                    interpreter.halt(InstructionResult::TronPrecompileTransferFailure);
                    return Ok(());
                }

                let item = if ins_result.is_ok() {
                    U256::from(1)
                } else {
                    U256::ZERO
                };
                // Safe to push without stack limit check
                let _ = interpreter.stack.push(item);

                // Return unspend gas.
                //
                // TRON fork: java `Program.callToAddress` (Program.java:1157-1169)
                // splits the two failure kinds. A child whose `ProgramResult`
                // carries an EXCEPTION pushes zero and RETURNS immediately,
                // before the return-data write (:1186-1194) and before the
                // unspent-energy refund (:1197-1210), so the caller forfeits the
                // whole forwarded budget. A child that merely REVERTED falls
                // through and gets both. `TransferFailed` sits in the revert
                // group so a ROOT frame settles its energy consumed-only
                // (`spendAllEnergy`-exempt, VM.java:99-101), which is why it has
                // to be named here rather than moved out of that group.
                let child_returns_to_caller =
                    ins_result.is_ok_or_revert() && ins_result != InstructionResult::TransferFailed;
                if child_returns_to_caller {
                    interpreter.gas.erase_cost(out_gas.remaining());

                    // TRON fork: before ALLOW_TVM_SELFDESTRUCT_RESTRICTION (#94)
                    // a precompile's return data is written to memory in FULL,
                    // at the raw return offset, ignoring the return size.
                    // java-tron's `Program.callToPrecompiledAddress` picks its
                    // write overload on that proposal (`Program.java:1771-1775`):
                    // pre-#94 `memorySave(int addr, byte[] value)`, which is
                    // `memory.write(addr, value, value.length, false)` — the
                    // length is the OUTPUT's own length, `outDataSize` is never
                    // consulted, and `limited = false` routes through
                    // `Memory.extend`, which grows memory with no energy
                    // accounting whatsoever. From #94 it is `memorySave(int
                    // addr, int allocSize, byte[] value)`, which truncates to
                    // `min(outDataSize, value.length)` inside the already-paid
                    // return window — the generic branch below.
                    //
                    // Precompiles only: the regular-call path
                    // (`Program.callToAddress:1191`) uses `memorySaveLimited` in
                    // BOTH eras, which neither extends memory nor writes past
                    // the caller's window.
                    if from_precompile && ctx.journal().tron_precompile_full_output_write() {
                        let out_len = interpreter.return_data.buffer().len();
                        // `Memory.extend` returns immediately on `size <= 0`, so
                        // an empty output is a total no-op — no growth, no
                        // write — whatever the offset.
                        if out_len != 0 {
                            // java resolves the offset with `DataWord.intValue()`
                            // (DataWord.java:209-216), which accumulates all 32
                            // bytes into an `int`: the low 32 bits, signed. A
                            // word whose low 32 bits have the top bit set yields
                            // a NEGATIVE index, which reaches
                            // `chunks.get(negative)` and throws
                            // `IndexOutOfBoundsException`. That throw is
                            // uncaught inside `callToPrecompiledAddress`, so
                            // `VM.java:97-105` runs `program.spendAllEnergy();
                            // program.stop();` on this frame and `VM.java:117`
                            // records a runtime failure — the same shape as an
                            // uncaught throw from a precompile body. The stack
                            // push and energy refund above already happened in
                            // java too (they precede the write at line 1774);
                            // spending all energy supersedes them.
                            let off_i32 = (outcome_raw_offset.as_limbs()[0] as u32) as i32;
                            if off_i32 < 0 {
                                interpreter.gas.spend_all();
                                interpreter.halt(InstructionResult::PrecompileThrow);
                                return Ok(());
                            }
                            let off = off_i32 as usize;
                            let end = off.saturating_add(out_len);

                            // Deliberate bound with NO java counterpart:
                            // `Memory.extend` is unguarded. It exists because
                            // `EnergyCost.checkMemorySize` caps every PAID
                            // expansion at `MEM_LIMIT` (3 MiB,
                            // EnergyCost.java:26), so no energy-paying route can
                            // reach beyond it, and a contract that chained free
                            // precompile writes to force more would drive a java
                            // node into unbounded allocation rather than produce
                            // a block this node must reproduce.
                            const TRON_FREE_GROWTH_LIMIT: usize = 3 * 1024 * 1024;
                            if end > TRON_FREE_GROWTH_LIMIT {
                                interpreter.gas.spend_all();
                                interpreter.halt(InstructionResult::MemoryLimitOOG);
                                return Ok(());
                            }

                            let words = num_words(end);
                            if words > interpreter.gas.memory().words_num {
                                // Grow the buffer so MSIZE follows: java's
                                // `Memory.extend` raises `softSize`, and
                                // `Program.getMemSize()` — the MSIZE source —
                                // returns exactly `softSize` (Memory.java:174).
                                interpreter.memory.resize(words * 32);
                                // Advance the charging baseline WITHOUT charging.
                                // `calcMemEnergy` is always called with
                                // `oldMemSize = program.getMemSize()`, so the
                                // free growth permanently raises the baseline and
                                // java never re-bills it. Discarding the returned
                                // delta is what makes the expansion free;
                                // recording it would charge this frame for
                                // memory java gave away, and leaving `words_num`
                                // behind would make the next memory op re-charge
                                // for the same words.
                                let cost = ctx.cfg().gas_params().memory_cost(words);
                                let _ = interpreter.gas.memory_mut().set_words_num(words, cost);
                            }

                            interpreter
                                .memory
                                .set(off, &interpreter.return_data.buffer()[..out_len]);
                        }
                    } else {
                        interpreter
                            .memory
                            .set(mem_start, &interpreter.return_data.buffer()[..target_len]);
                    }
                }

                // handle reservoir remaining gas
                handle_reservoir_remaining_gas(ins_result, &mut interpreter.gas, &out_gas);

                if ins_result.is_ok() {
                    interpreter.gas.record_refund(out_gas.refunded());
                }
            }
            FrameResult::Create(outcome) => {
                let instruction_result = *outcome.instruction_result();
                let interpreter = &mut self.interpreter;

                if instruction_result == InstructionResult::Revert {
                    // Save data to return data buffer if the create reverted
                    interpreter
                        .return_data
                        .set_buffer(outcome.output().to_owned());
                } else {
                    // Otherwise clear it. Note that RETURN opcode should abort.
                    interpreter.return_data.clear();
                };

                assert_ne!(
                    instruction_result,
                    InstructionResult::FatalExternalError,
                    "Fatal external error in insert_eofcreate_outcome"
                );

                let this_gas = &mut interpreter.gas;
                // Refund unused gas for success and revert cases.
                //
                // TRON fork: java `createContractImpl` splits the two failure
                // kinds the same way `callToAddress` does — an init frame that
                // raised an exception takes the early `return` at
                // Program.java:963, skipping `refundEnergyAfterVM`, so the
                // caller forfeits the whole forwarded budget it was charged at
                // creation. Only a child that merely REVERTED reaches the
                // refund. `TransferFailed` sits in the revert group so a ROOT
                // frame settles consumed-only, which is why it is named here
                // rather than moved out of that group.
                if instruction_result.is_ok_or_revert()
                    && instruction_result != InstructionResult::TransferFailed
                {
                    this_gas.erase_cost(outcome.gas().remaining());
                }

                // handle reservoir remaining gas
                handle_reservoir_remaining_gas(instruction_result, this_gas, outcome.gas());

                // EIP-8037: The CREATE opcode charged `create_state_gas` upfront on
                // this frame's tracker. When the child fails to deploy a contract
                // (revert, halt, or early-fail paths that return `address == None`
                // such as nonce overflow, depth, OutOfFunds), refund the upfront
                // charge to the reservoir and undo it on `state_gas_spent` via
                // `refill_reservoir` (matching 0→x→0 storage restoration). The
                // nonce-overflow path reports `InstructionResult::Return` (ok)
                // with `address == None`, so gate on address rather than the result.
                let create_failed = outcome.address.is_none() || !instruction_result.is_ok();

                if create_failed && ctx.cfg().is_amsterdam_eip8037_enabled() {
                    let state_gas_charged =
                        ctx.cfg().gas_params().create_state_gas(ctx.local().cpsb());
                    this_gas.refill_reservoir(state_gas_charged);
                }

                let stack_item = if instruction_result.is_ok() {
                    this_gas.record_refund(outcome.gas().refunded());
                    let word = outcome.address.unwrap_or_default().into_word();
                    // TRON fork: java pushes the new contract address with
                    // `stackPush(new DataWord(newAddress))`, where `newAddress`
                    // is the 21-byte `Hash.sha3omit12` output — the prefix byte
                    // is already in place and nothing masks it. Applies to both
                    // CREATE and CREATE2, at every height: no proposal gates the
                    // success push.
                    if ctx.tron_enabled() {
                        tron_address_word(word).into()
                    } else {
                        word.into()
                    }
                } else {
                    U256::ZERO
                };

                // Safe to push without stack limit check
                let _ = interpreter.stack.push(stack_item);
            }
        }

        Ok(())
    }
}

/// Handles the remaining gas of the parent frame.
#[inline]
pub const fn handle_reservoir_remaining_gas(
    instruction_result: InstructionResult,
    parent_gas: &mut Gas,
    child_gas: &Gas,
) {
    if instruction_result.is_ok() {
        // On success: parent takes the child's final reservoir.
        parent_gas.set_reservoir(child_gas.reservoir());
        // Accumulate child's state gas into parent's total.
        // Parent may have already charged state gas (e.g., new_account + create) before
        // creating the child frame. Child starts with state_gas_spent=0, so we must add
        // rather than overwrite to preserve the parent's prior charges.
        //
        // `child.state_gas_spent()` can be negative (EIP-8037 issue #2) when the
        // child did more 0→x→0 restorations than 0→x creations; the negative
        // contribution is the parent's matching charge flowing back out.
        parent_gas.set_state_gas_spent(
            parent_gas
                .state_gas_spent()
                .saturating_add(child_gas.state_gas_spent()),
        );
    } else {
        // On revert/halt: the child's state changes are rolled back, so any
        // 0→x→0 refills the child (or its descendants) credited to the
        // reservoir must unwind too — the underlying clears no longer exist.
        //
        // Invariant when no reservoir→remaining spill happened in the child:
        //     pre_call_reservoir = child.reservoir + child.state_gas_spent
        // because every reservoir-funded `record_state_cost(c)` increments
        // state_gas_spent by `c` while decrementing reservoir by `c`, and every
        // `refill_reservoir(r)` does the opposite. Adding the (possibly negative)
        // state_gas_spent back to the final reservoir recovers the pre-call value
        // — discarding the negative branch (the old `.max(0)`) would leak
        // grandchild refill credits up through a reverting parent.
        parent_gas.set_reservoir(
            child_gas
                .reservoir()
                .saturating_add_signed(child_gas.state_gas_spent()),
        );
    }
}

/// Handles the result of a CREATE operation, including validation and state updates.
///
/// The EIP-8037 upfront CREATE state gas is charged on the parent's tracker by
/// the CREATE/CREATE2 opcode. On child failure (revert/halt/early-fail) it is
/// refunded to the parent in `return_result`. The child frame is NOT allowed to
/// borrow the upfront charge to pay for code deposit: it must cover code deposit
/// state gas from its own reservoir and remaining gas.
pub fn return_create<CTX: ContextTr>(
    context: &mut CTX,
    checkpoint: JournalCheckpoint,
    interpreter_result: &mut InterpreterResult,
    address: Address,
) {
    let (_, _, cfg, journal, _, local) = context.all_mut();

    let max_code_size = cfg.max_code_size();
    let is_eip3541_disabled = cfg.is_eip3541_disabled();
    let spec_id = cfg.spec().into();
    let is_amsterdam_eip8037 = cfg.is_amsterdam_eip8037_enabled();
    let cpsb = local.cpsb();
    let gas_params = cfg.gas_params();

    // If return is not ok revert and return.
    if !interpreter_result.result.is_ok() {
        journal.checkpoint_revert(checkpoint);
        return;
    }

    // EIP-170: Contract code size limit to 0x6000 (~25kb)
    // EIP-7954 increased this limit to 0x8000 (~32kb).
    // This must be checked BEFORE charging state gas for code deposit,
    // so that oversized code does not incur storage gas costs.
    if spec_id.is_enabled_in(SPURIOUS_DRAGON) && interpreter_result.output.len() > max_code_size {
        journal.checkpoint_revert(checkpoint);
        interpreter_result.result = InstructionResult::CreateContractSizeLimit;
        return;
    }

    // Host error if present on execution
    // If ok, check contract creation limit and calculate gas deduction on output len.
    //
    // EIP-3541: Reject new contract code starting with the 0xEF byte
    if !is_eip3541_disabled
        && spec_id.is_enabled_in(LONDON)
        && interpreter_result.output.first() == Some(&0xEF)
    {
        journal.checkpoint_revert(checkpoint);
        interpreter_result.result = InstructionResult::CreateContractStartingWithEF;
        return;
    }

    // regular gas for code deposit. It is zero in EIP-8037.
    //
    // TRON fork: java-tron spends `saveCodeEnergy` directly on the
    // result in `createContractImpl` — outside `VM.play()`'s op loop —
    // so it is never scaled by the dynamic-energy factor and never
    // counted toward the created contract's usage.
    let gas_for_code = gas_params.code_deposit_cost(interpreter_result.output.len());
    if !interpreter_result.gas.record_unscaled_cost(gas_for_code) {
        // Record code deposit gas cost and check if we are out of gas.
        // EIP-2 point 3: If contract creation does not have enough gas to pay for the
        // final gas fee for adding the contract code to the state, the contract
        // creation fails (i.e. goes out-of-gas) rather than leaving an empty contract.
        if spec_id.is_enabled_in(HOMESTEAD) {
            journal.checkpoint_revert(checkpoint);
            interpreter_result.result = InstructionResult::OutOfGas;
            return;
        } else {
            interpreter_result.output = Bytes::new();
        }
    }

    // EIP-8037: Hash cost for deployed bytecode (keccak256)
    // HASH_COST(L) = 6 × ceil(L / 32)
    // Both CREATE and CREATE2 must pay this cost: it covers hashing the deployed code
    // to compute the code_hash stored in the account. CREATE2's existing keccak256 charge
    // (in create2_cost) is for hashing the init code during address derivation, which is
    // a different hash.
    if is_amsterdam_eip8037 {
        let hash_cost = gas_params.keccak256_cost(interpreter_result.output.len());
        if !interpreter_result.gas.record_regular_cost(hash_cost) {
            journal.checkpoint_revert(checkpoint);
            interpreter_result.result = InstructionResult::OutOfGas;
            return;
        }
        // State gas for code deposit (EIP-8037).
        // Charged after size check: only code that passes validation incurs state gas cost.
        //
        // Note: This should be last operation before checkpoint commit as spending state before this messes
        // with refilling of state gas.
        let state_gas_for_code =
            gas_params.code_deposit_state_gas(interpreter_result.output.len(), cpsb);
        if state_gas_for_code > 0 && !interpreter_result.gas.record_state_cost(state_gas_for_code) {
            journal.checkpoint_revert(checkpoint);
            interpreter_result.result = InstructionResult::OutOfGas;
            return;
        }
    }

    // If we have enough gas we can commit changes.
    journal.checkpoint_commit();

    // Do analysis of bytecode straight away.
    let bytecode = Bytecode::new_legacy(interpreter_result.output.clone());

    // Set code
    journal.set_code(address, bytecode);

    interpreter_result.result = InstructionResult::Return;
}
