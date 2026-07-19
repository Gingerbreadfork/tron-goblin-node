use context_interface::{
    host::LoadError,
    journaled_state::TransferError,
    result::{HaltReason, OutOfGasError, SuccessReason},
};
use core::fmt::Debug;

/// Result type returned by instruction implementations.
///
/// `Ok(())` means the instruction completed normally and execution should continue.
/// `Err(result)` means execution should halt with the given [`InstructionResult`].
pub type InstructionExecResult<T = (), E = InstructionResult> = Result<T, E>;

/// Result of executing an EVM instruction.
///
/// This enum represents all possible outcomes when executing an instruction,
/// including successful execution, reverts, and various error conditions.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum InstructionResult {
    /// Encountered a `STOP` opcode
    #[default]
    Stop = 1, // Start at 1 so that `Result<(), _>::Ok(())` is 0.
    /// Return from the current call.
    Return,
    /// Self-destruct the current contract.
    SelfDestruct,
    /// Temporarily suspended, for CALL/CREATE.
    Suspend,

    // Revert Codes
    /// Revert the transaction.
    Revert = 0x10,
    /// Exceeded maximum call depth.
    CallTooDeep,
    /// Insufficient funds for transfer.
    OutOfFunds,
    /// Revert if `CREATE`/`CREATE2` starts with `0xEF00`.
    CreateInitCodeStartingEF00,
    /// Invalid EVM Object Format (EOF) init code.
    InvalidEOFInitCode,
    /// `ExtDelegateCall` calling a non EOF contract.
    InvalidExtDelegateCallTarget,
    /// TRON fork: a value-transfer operation (CALL/CALLCODE/CALLTOKEN) failed
    /// `Program.transfer` validation — java-tron raises a `TransferException`
    /// (`Program.java`: "transfer trx/trc10 failed", "endowment out of long
    /// range", "Cannot transfer … to yourself"). A `TransferException` is a
    /// `BytecodeExecutionException` that, unlike a plain halt, is EXEMPT from
    /// `spendAllEnergy` (`VM.java` / `VMActuator`) — so it charges only the
    /// energy consumed up to the throw (forwarded call energy refunded), the
    /// same as a revert — yet it terminates the WHOLE transaction (the
    /// exception unwinds every frame) and surfaces `contractResult
    /// TRANSFER_FAILED`. Grouped with the revert codes so its gas settles
    /// consumed-only; propagated tx-fatal by `frame_return_result` (it never
    /// reaches a parent's call-return push-0/1) and tagged on the journal so
    /// the executor records `TRANSFER_FAILED` rather than `REVERT`.
    TransferFailed,

    // Error Codes
    /// Out of gas error.
    OutOfGas = 0x20,
    /// Out of gas error encountered during memory expansion.
    MemoryOOG,
    /// The memory limit of the EVM has been exceeded.
    MemoryLimitOOG,
    /// Out of gas error encountered during the execution of a precompiled contract.
    PrecompileOOG,
    /// Out of gas error encountered while calling an invalid operand.
    InvalidOperandOOG,
    /// Out of gas error encountered while checking for reentrancy sentry.
    ReentrancySentryOOG,
    /// Unknown or invalid opcode.
    OpcodeNotFound,
    /// Invalid `CALL` with value transfer in static context.
    CallNotAllowedInsideStatic,
    /// Invalid state modification in static call.
    StateChangeDuringStaticCall,
    /// An undefined bytecode value encountered during execution.
    InvalidFEOpcode,
    /// Invalid jump destination. Dynamic jumps points to invalid not jumpdest opcode.
    InvalidJump,
    /// The feature or opcode is not activated in this version of the EVM.
    NotActivated,
    /// Attempting to pop a value from an empty stack.
    StackUnderflow,
    /// Attempting to push a value onto a full stack.
    StackOverflow,
    /// Invalid memory or storage offset.
    OutOfOffset,
    /// Address collision during contract creation.
    CreateCollision,
    /// Payment amount overflow.
    OverflowPayment,
    /// Error in precompiled contract execution.
    PrecompileError,
    /// Nonce overflow.
    NonceOverflow,
    /// Exceeded contract size limit during creation.
    CreateContractSizeLimit,
    /// Created contract starts with invalid bytes (`0xEF`).
    CreateContractStartingWithEF,
    /// Exceeded init code size limit (EIP-3860:  Limit and meter initcode).
    CreateInitCodeSizeLimit,
    /// Fatal external error. Returned by database.
    FatalExternalError,
    /// Invalid encoding of an instruction's immediate operand.
    InvalidImmediateEncoding,
    /// TRON fork: a precompile body raised an exception outside any
    /// try-block — java-tron's `ValidateMultiSign` reads `words[0..3]` and
    /// parses the signature array before its `try`, so a malformed input
    /// throws `ArrayIndexOutOfBoundsException`. `Program
    /// .callToPrecompiledAddress` does not wrap `contract.execute`, so the
    /// throw reaches `VM.java`, which runs `program.spendAllEnergy()` on the
    /// frame that executed the CALL and halts it. That frame therefore loses
    /// its ENTIRE remaining budget, not just the energy it forwarded.
    ///
    /// Not transaction-fatal: `VM.play`'s outer catch records it as a runtime
    /// failure, and a parent frame pushes zero and carries on
    /// (`Program.callToAddress`). At the root frame the transaction consumes
    /// its full energy limit and records `contractResult UNKNOWN`.
    PrecompileThrow,
    /// TRON fork: java-tron's `BytecodeExecutionException`, and the bare
    /// `ArithmeticException` an ungated `longValueExact()` throws. Raised by a
    /// transfer/token validation that fails BEFORE the
    /// `ALLOW_TVM_CONSTANTINOPLE` proposal (#26) converts these throws into a
    /// `TransferException`.
    ///
    /// Energy polarity is the opposite of [`InstructionResult::TransferFailed`]:
    /// `VM.java`'s per-opcode catch runs `program.spendAllEnergy()` for every
    /// exception that is NOT a `TransferException`, so the executing frame loses
    /// its whole remaining budget. `RuntimeImpl.setResultCode` has no arm for
    /// either exception type, so the recorded code is `contractResult UNKNOWN`.
    ///
    /// Not transaction-fatal by itself: like any halt it is contained to the
    /// frame that raised it, and a parent frame pushes zero and continues
    /// (`VM.play`'s outer catch records a runtime failure and
    /// `Program.callToAddress` does `stackPushZero(); return;`). Only a
    /// root-frame occurrence fails the transaction.
    TronBytecodeExecution,
    /// TRON fork: java-tron's `BytecodeExecutionException("transfer failure")`
    /// from `Program.callToPrecompiledAddress` (`Program.java:1723`, TRC-10
    /// twin at `:1730`) — a value-bearing CALL/CALLTOKEN whose target is a
    /// precompile with no account row.
    ///
    /// That method never calls `createAccountIfNotExist`, so
    /// `VMUtils.validateForSmartContract` finds no `toAccount`
    /// (`VMUtils.java:155-159`) and throws at every height — the behaviour is
    /// ungated. Two earlier java checks take precedence and push zero instead:
    /// `getCallDeep() == MAX_DEPTH` (`Program.java:1677`) and
    /// `senderBalance < endowment` (`Program.java:1707`).
    ///
    /// java runs the precompile INLINE in the caller's frame, so
    /// `spendAllEnergy()` burns the caller's whole remaining budget, not just
    /// the energy forwarded to the call. `Frame::return_result` reproduces that
    /// by halting the calling frame on this result rather than pushing zero.
    /// `RuntimeImpl.setResultCode` has no arm for it → `contractResult UNKNOWN`.
    TronPrecompileTransferFailure,
}

impl From<TransferError> for InstructionResult {
    fn from(e: TransferError) -> Self {
        match e {
            TransferError::OutOfFunds => InstructionResult::OutOfFunds,
            TransferError::OverflowPayment => InstructionResult::OverflowPayment,
            TransferError::CreateCollision => InstructionResult::CreateCollision,
        }
    }
}

impl From<SuccessReason> for InstructionResult {
    fn from(value: SuccessReason) -> Self {
        match value {
            SuccessReason::Return => InstructionResult::Return,
            SuccessReason::Stop => InstructionResult::Stop,
            SuccessReason::SelfDestruct => InstructionResult::SelfDestruct,
        }
    }
}

impl From<HaltReason> for InstructionResult {
    fn from(value: HaltReason) -> Self {
        match value {
            HaltReason::OutOfGas(error) => match error {
                OutOfGasError::Basic => Self::OutOfGas,
                OutOfGasError::InvalidOperand => Self::InvalidOperandOOG,
                OutOfGasError::Memory => Self::MemoryOOG,
                OutOfGasError::MemoryLimit => Self::MemoryLimitOOG,
                OutOfGasError::Precompile => Self::PrecompileOOG,
                OutOfGasError::ReentrancySentry => Self::ReentrancySentryOOG,
            },
            HaltReason::OpcodeNotFound => Self::OpcodeNotFound,
            HaltReason::InvalidFEOpcode => Self::InvalidFEOpcode,
            HaltReason::InvalidJump => Self::InvalidJump,
            HaltReason::NotActivated => Self::NotActivated,
            HaltReason::StackOverflow => Self::StackOverflow,
            HaltReason::StackUnderflow => Self::StackUnderflow,
            HaltReason::OutOfOffset => Self::OutOfOffset,
            HaltReason::CreateCollision => Self::CreateCollision,
            HaltReason::PrecompileError => Self::PrecompileError,
            HaltReason::PrecompileErrorWithContext(_) => Self::PrecompileError,
            HaltReason::PrecompileThrow => Self::PrecompileThrow,
            HaltReason::TronBytecodeExecution => Self::TronBytecodeExecution,
            HaltReason::TronPrecompileTransferFailure => Self::TronPrecompileTransferFailure,
            HaltReason::NonceOverflow => Self::NonceOverflow,
            HaltReason::CreateContractSizeLimit => Self::CreateContractSizeLimit,
            HaltReason::CreateContractStartingWithEF => Self::CreateContractStartingWithEF,
            HaltReason::CreateInitCodeSizeLimit => Self::CreateInitCodeSizeLimit,
            HaltReason::OverflowPayment => Self::OverflowPayment,
            HaltReason::StateChangeDuringStaticCall => Self::StateChangeDuringStaticCall,
            HaltReason::CallNotAllowedInsideStatic => Self::CallNotAllowedInsideStatic,
            HaltReason::OutOfFunds => Self::OutOfFunds,
            HaltReason::CallTooDeep => Self::CallTooDeep,
        }
    }
}

impl From<LoadError> for InstructionResult {
    fn from(error: LoadError) -> Self {
        match error {
            LoadError::ColdLoadSkipped => Self::OutOfGas,
            LoadError::DBError => Self::FatalExternalError,
        }
    }
}

/// Macro that matches all successful instruction results.
/// Used in pattern matching to handle all successful execution outcomes.
#[macro_export]
macro_rules! return_ok {
    () => {
        $crate::InstructionResult::Stop
            | $crate::InstructionResult::Return
            | $crate::InstructionResult::SelfDestruct
            | $crate::InstructionResult::Suspend
    };
}

/// Macro that matches all revert instruction results.
/// Used in pattern matching to handle all revert outcomes.
#[macro_export]
macro_rules! return_revert {
    () => {
        $crate::InstructionResult::Revert
            | $crate::InstructionResult::CallTooDeep
            | $crate::InstructionResult::OutOfFunds
            | $crate::InstructionResult::InvalidEOFInitCode
            | $crate::InstructionResult::CreateInitCodeStartingEF00
            | $crate::InstructionResult::InvalidExtDelegateCallTarget
            | $crate::InstructionResult::TransferFailed
    };
}

/// Macro that matches all error instruction results.
/// Used in pattern matching to handle all error outcomes.
#[macro_export]
macro_rules! return_error {
    () => {
        $crate::InstructionResult::OutOfGas
            | $crate::InstructionResult::MemoryOOG
            | $crate::InstructionResult::MemoryLimitOOG
            | $crate::InstructionResult::PrecompileOOG
            | $crate::InstructionResult::InvalidOperandOOG
            | $crate::InstructionResult::ReentrancySentryOOG
            | $crate::InstructionResult::OpcodeNotFound
            | $crate::InstructionResult::CallNotAllowedInsideStatic
            | $crate::InstructionResult::StateChangeDuringStaticCall
            | $crate::InstructionResult::InvalidFEOpcode
            | $crate::InstructionResult::InvalidJump
            | $crate::InstructionResult::NotActivated
            | $crate::InstructionResult::StackUnderflow
            | $crate::InstructionResult::StackOverflow
            | $crate::InstructionResult::OutOfOffset
            | $crate::InstructionResult::CreateCollision
            | $crate::InstructionResult::OverflowPayment
            | $crate::InstructionResult::PrecompileError
            | $crate::InstructionResult::NonceOverflow
            | $crate::InstructionResult::CreateContractSizeLimit
            | $crate::InstructionResult::CreateContractStartingWithEF
            | $crate::InstructionResult::CreateInitCodeSizeLimit
            | $crate::InstructionResult::FatalExternalError
            | $crate::InstructionResult::InvalidImmediateEncoding
            | $crate::InstructionResult::PrecompileThrow
            | $crate::InstructionResult::TronBytecodeExecution
            | $crate::InstructionResult::TronPrecompileTransferFailure
    };
}

impl InstructionResult {
    /// Returns whether the result is a success.
    #[inline]
    pub const fn is_ok(self) -> bool {
        matches!(self, return_ok!())
    }

    #[inline]
    /// Returns whether the result is a success or revert (not an error).
    pub const fn is_ok_or_revert(self) -> bool {
        matches!(self, return_ok!() | return_revert!())
    }

    /// Returns whether the result is a revert.
    #[inline]
    pub const fn is_revert(self) -> bool {
        matches!(self, return_revert!())
    }

    /// Returns whether the result is an error.
    #[inline]
    #[deprecated(note = "use `is_halt` instead")]
    pub const fn is_error(self) -> bool {
        self.is_halt()
    }

    /// Returns whether the result is a halt (error).
    #[inline]
    pub const fn is_halt(self) -> bool {
        matches!(self, return_error!())
    }
}

/// Internal results that are not exposed externally
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum InternalResult {
    /// Internal CREATE/CREATE starts with 0xEF00
    CreateInitCodeStartingEF00,
    /// Internal to ExtDelegateCall
    InvalidExtDelegateCallTarget,
    /// Execution suspended internally.
    Suspend,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
/// Represents the outcome of instruction execution, distinguishing between
/// success, revert, halt (error), fatal external errors, and internal results.
pub enum SuccessOrHalt<HaltReasonTr> {
    /// Successful execution with the specific success reason.
    Success(SuccessReason),
    /// Execution reverted.
    Revert,
    /// Execution halted due to an error.
    Halt(HaltReasonTr),
    /// Fatal external error occurred.
    FatalExternalError,
    /// Internal execution result not exposed externally.
    Internal(InternalResult),
}

impl<HaltReasonTr> SuccessOrHalt<HaltReasonTr> {
    /// Returns true if the transaction returned successfully without halts.
    #[inline]
    pub fn is_success(self) -> bool {
        matches!(self, SuccessOrHalt::Success(_))
    }

    /// Returns the [SuccessReason] value if this a successful result
    #[inline]
    pub fn to_success(self) -> Option<SuccessReason> {
        match self {
            SuccessOrHalt::Success(reason) => Some(reason),
            _ => None,
        }
    }

    /// Returns true if the transaction reverted.
    #[inline]
    pub fn is_revert(self) -> bool {
        matches!(self, SuccessOrHalt::Revert)
    }

    /// Returns true if the EVM has experienced an exceptional halt
    #[inline]
    pub fn is_halt(self) -> bool {
        matches!(self, SuccessOrHalt::Halt(_))
    }

    /// Returns the [HaltReason] value the EVM has experienced an exceptional halt
    #[inline]
    pub fn to_halt(self) -> Option<HaltReasonTr> {
        match self {
            SuccessOrHalt::Halt(reason) => Some(reason),
            _ => None,
        }
    }
}

impl<HALT: From<HaltReason>> From<HaltReason> for SuccessOrHalt<HALT> {
    fn from(reason: HaltReason) -> Self {
        SuccessOrHalt::Halt(reason.into())
    }
}

impl<HaltReasonTr: From<HaltReason>> From<InstructionResult> for SuccessOrHalt<HaltReasonTr> {
    fn from(result: InstructionResult) -> Self {
        match result {
            InstructionResult::Stop => Self::Success(SuccessReason::Stop),
            InstructionResult::Return => Self::Success(SuccessReason::Return),
            InstructionResult::SelfDestruct => Self::Success(SuccessReason::SelfDestruct),
            InstructionResult::Suspend => Self::Internal(InternalResult::Suspend),
            InstructionResult::Revert => Self::Revert,
            // TRON fork: a transfer-failed halt settles exactly like a revert
            // (consumed-only energy, state unwound) — java's `TransferException`
            // is `spendAllEnergy`-exempt. It maps to `Self::Revert` so the final
            // gas is consumed-only and the output empty; the executor
            // distinguishes it from a real REVERT (→ `contractResult
            // TRANSFER_FAILED`) via the journal's `tron_transfer_failed` flag.
            InstructionResult::TransferFailed => Self::Revert,
            InstructionResult::CreateInitCodeStartingEF00 => Self::Revert,
            InstructionResult::CallTooDeep => Self::Halt(HaltReason::CallTooDeep.into()), // not gonna happen for first call
            InstructionResult::OutOfFunds => Self::Halt(HaltReason::OutOfFunds.into()), // Check for first call is done separately.
            InstructionResult::OutOfGas => {
                Self::Halt(HaltReason::OutOfGas(OutOfGasError::Basic).into())
            }
            InstructionResult::MemoryLimitOOG => {
                Self::Halt(HaltReason::OutOfGas(OutOfGasError::MemoryLimit).into())
            }
            InstructionResult::MemoryOOG => {
                Self::Halt(HaltReason::OutOfGas(OutOfGasError::Memory).into())
            }
            InstructionResult::PrecompileOOG => {
                Self::Halt(HaltReason::OutOfGas(OutOfGasError::Precompile).into())
            }
            InstructionResult::InvalidOperandOOG => {
                Self::Halt(HaltReason::OutOfGas(OutOfGasError::InvalidOperand).into())
            }
            InstructionResult::ReentrancySentryOOG => {
                Self::Halt(HaltReason::OutOfGas(OutOfGasError::ReentrancySentry).into())
            }
            InstructionResult::OpcodeNotFound => Self::Halt(HaltReason::OpcodeNotFound.into()),
            InstructionResult::CallNotAllowedInsideStatic => {
                Self::Halt(HaltReason::CallNotAllowedInsideStatic.into())
            } // first call is not static call
            InstructionResult::StateChangeDuringStaticCall => {
                Self::Halt(HaltReason::StateChangeDuringStaticCall.into())
            }
            InstructionResult::InvalidFEOpcode => Self::Halt(HaltReason::InvalidFEOpcode.into()),
            InstructionResult::InvalidJump => Self::Halt(HaltReason::InvalidJump.into()),
            InstructionResult::NotActivated => Self::Halt(HaltReason::NotActivated.into()),
            InstructionResult::StackUnderflow => Self::Halt(HaltReason::StackUnderflow.into()),
            InstructionResult::StackOverflow => Self::Halt(HaltReason::StackOverflow.into()),
            InstructionResult::OutOfOffset => Self::Halt(HaltReason::OutOfOffset.into()),
            InstructionResult::CreateCollision => Self::Halt(HaltReason::CreateCollision.into()),
            InstructionResult::OverflowPayment => Self::Halt(HaltReason::OverflowPayment.into()), // Check for first call is done separately.
            InstructionResult::PrecompileError => Self::Halt(HaltReason::PrecompileError.into()),
            InstructionResult::NonceOverflow => Self::Halt(HaltReason::NonceOverflow.into()),
            InstructionResult::CreateContractSizeLimit => {
                Self::Halt(HaltReason::CreateContractSizeLimit.into())
            }
            InstructionResult::CreateContractStartingWithEF => {
                Self::Halt(HaltReason::CreateContractStartingWithEF.into())
            }
            InstructionResult::CreateInitCodeSizeLimit => {
                Self::Halt(HaltReason::CreateInitCodeSizeLimit.into())
            }
            // TODO : (EOF) Add proper Revert subtype.
            InstructionResult::InvalidEOFInitCode => Self::Revert,
            InstructionResult::FatalExternalError => Self::FatalExternalError,
            InstructionResult::InvalidExtDelegateCallTarget => {
                Self::Internal(InternalResult::InvalidExtDelegateCallTarget)
            }
            InstructionResult::InvalidImmediateEncoding => {
                Self::Halt(HaltReason::OpcodeNotFound.into())
            }
            // Deliberately NOT `HaltReason::PrecompileError`: that resolves to
            // `ContractResult::PrecompiledContract`, java's
            // `PrecompiledContractException`, which is a different fault. An
            // uncaught throw has no dedicated java code and lands on UNKNOWN.
            InstructionResult::PrecompileThrow => {
                Self::Halt(HaltReason::PrecompileThrow.into())
            }
            // Deliberately NOT an `OutOfGas` sub-kind: `MemoryLimit` resolves to
            // `ContractResult::OutOfMemory`, java's `OutOfMemoryException`,
            // which is a different fault. A `BytecodeExecutionException` has no
            // dedicated java result code and lands on UNKNOWN.
            InstructionResult::TronBytecodeExecution => {
                Self::Halt(HaltReason::TronBytecodeExecution.into())
            }
            // Deliberately NOT `TransferFailed`: that is java's
            // `TransferException`, which `VM.java:99` exempts from
            // `spendAllEnergy()` and `RuntimeImpl` records as TRANSFER_FAILED.
            // `callToPrecompiledAddress` throws a plain
            // `BytecodeExecutionException`, which is neither.
            InstructionResult::TronPrecompileTransferFailure => {
                Self::Halt(HaltReason::TronPrecompileTransferFailure.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::InstructionResult;

    #[test]
    fn exhaustiveness() {
        match InstructionResult::Stop {
            return_error!() => {}
            return_revert!() => {}
            return_ok!() => {}
        }
    }

    #[test]
    fn test_results() {
        let ok_results = [
            InstructionResult::Stop,
            InstructionResult::Return,
            InstructionResult::SelfDestruct,
        ];
        for result in ok_results {
            assert!(result.is_ok());
            assert!(!result.is_revert());
            assert!(!result.is_halt());
        }

        let revert_results = [
            InstructionResult::Revert,
            InstructionResult::CallTooDeep,
            InstructionResult::OutOfFunds,
        ];
        for result in revert_results {
            assert!(!result.is_ok());
            assert!(result.is_revert());
            assert!(!result.is_halt());
        }

        let error_results = [
            InstructionResult::OutOfGas,
            InstructionResult::MemoryOOG,
            InstructionResult::MemoryLimitOOG,
            InstructionResult::PrecompileOOG,
            InstructionResult::InvalidOperandOOG,
            InstructionResult::OpcodeNotFound,
            InstructionResult::CallNotAllowedInsideStatic,
            InstructionResult::StateChangeDuringStaticCall,
            InstructionResult::InvalidFEOpcode,
            InstructionResult::InvalidJump,
            InstructionResult::NotActivated,
            InstructionResult::StackUnderflow,
            InstructionResult::StackOverflow,
            InstructionResult::OutOfOffset,
            InstructionResult::CreateCollision,
            InstructionResult::OverflowPayment,
            InstructionResult::PrecompileError,
            InstructionResult::NonceOverflow,
            InstructionResult::CreateContractSizeLimit,
            InstructionResult::CreateContractStartingWithEF,
            InstructionResult::CreateInitCodeSizeLimit,
            InstructionResult::FatalExternalError,
            InstructionResult::PrecompileThrow,
            InstructionResult::TronBytecodeExecution,
            InstructionResult::TronPrecompileTransferFailure,
        ];
        for result in error_results {
            assert!(!result.is_ok());
            assert!(!result.is_revert());
            assert!(result.is_halt());
        }
    }

    /// TRON fork: an uncaught precompile throw is an ERROR result, never a
    /// success or a revert — `Frame::return_result` keys the "kill the calling
    /// frame" path off that classification, and `is_ok_or_revert()` being
    /// false is what suppresses the unspent-gas refund.
    #[test]
    fn precompile_throw_is_an_error_result() {
        let r = InstructionResult::PrecompileThrow;
        assert!(matches!(r, return_error!()));
        assert!(!r.is_ok());
        assert!(!r.is_ok_or_revert());
        assert!(!r.is_revert());
        assert!(r.is_halt());
    }

    /// It must map to its OWN halt reason. `HaltReason::PrecompileError`
    /// resolves to java's `PrecompiledContractException`, a different fault
    /// with a different `contractResult`.
    #[test]
    fn precompile_throw_maps_to_its_own_halt_reason() {
        use crate::SuccessOrHalt;
        use context_interface::result::HaltReason;
        let got: SuccessOrHalt<HaltReason> = InstructionResult::PrecompileThrow.into();
        assert_eq!(got, SuccessOrHalt::Halt(HaltReason::PrecompileThrow));
        // And the mapping round-trips.
        assert_eq!(
            InstructionResult::from(HaltReason::PrecompileThrow),
            InstructionResult::PrecompileThrow
        );
    }

    /// TRON fork: a `BytecodeExecutionException` is an ERROR result. That
    /// classification is what drives java's `spendAllEnergy()` polarity —
    /// `is_ok_or_revert()` being false suppresses the unspent-gas refund, so
    /// the frame settles having consumed its whole limit. This is the exact
    /// opposite of `TransferFailed`, which is a revert-class result.
    #[test]
    fn tron_bytecode_execution_is_an_error_result() {
        let r = InstructionResult::TronBytecodeExecution;
        assert!(matches!(r, return_error!()));
        assert!(!r.is_ok());
        assert!(!r.is_ok_or_revert());
        assert!(!r.is_revert());
        assert!(r.is_halt());

        // Contrast: `TransferException` is spend-all-exempt.
        let t = InstructionResult::TransferFailed;
        assert!(t.is_revert());
        assert!(t.is_ok_or_revert());
        assert!(!t.is_halt());
    }

    /// It must map to its OWN halt reason: an `OutOfGas(MemoryLimit)` mapping
    /// would record `contractResult OUT_OF_MEMORY` (java's
    /// `OutOfMemoryException`) instead of UNKNOWN.
    #[test]
    fn tron_bytecode_execution_maps_to_its_own_halt_reason() {
        use crate::SuccessOrHalt;
        use context_interface::result::HaltReason;
        let got: SuccessOrHalt<HaltReason> = InstructionResult::TronBytecodeExecution.into();
        assert_eq!(got, SuccessOrHalt::Halt(HaltReason::TronBytecodeExecution));
        assert_eq!(
            InstructionResult::from(HaltReason::TronBytecodeExecution),
            InstructionResult::TronBytecodeExecution
        );
    }
}
