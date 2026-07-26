//! Per-opcode + per-call EVM tracer for `debug_*` / `trace_*` JSON-RPC.
//!
//! Two complementary outputs:
//!
//! * **StructLog** — one entry per executed opcode. Equivalent to
//!   geth's default `debug.traceTransaction` output (a.k.a.
//!   `structLogger`). Each entry carries `pc`, `op`, `gas`,
//!   `gasCost`, `depth`, and a stack snapshot. Memory + storage
//!   snapshots are optionally captured — they're huge, so default
//!   off.
//! * **CallFrames** — the call/create tree (geth's `callTracer`).
//!   Each frame records `type`, `from`, `to`, `value`, `input`,
//!   `output`, `gas`, `gasUsed`, `error`, and a `calls` array of
//!   nested frames.
//!
//! Lifecycle: construct a `StructLogTracer` with the desired
//! options, install via `execute_trigger_with_tracer`, then call
//! `into_outputs()` to get the structured trace data + the
//! `VmOutcome`.

use revm::interpreter::interpreter::EthInterpreter;
use revm::interpreter::interpreter_types::Jumps;
use revm::interpreter::{
    CallInputs, CallOutcome, CreateInputs, CreateOutcome, Interpreter,
};
use revm::inspector::Inspector;
use revm::primitives::{Address as EvmAddress, U256};

/// One opcode executed. Field names match geth's
/// `debug.traceTransaction` JSON output so a downstream serializer
/// can pass these straight through.
#[derive(Debug, Clone)]
pub struct StructLog {
    pub pc: u64,
    pub op: u8,
    /// Stringified opcode name (`PUSH1`, `MLOAD`, etc.). Falls back
    /// to the hex form when revm doesn't know the name.
    pub op_name: String,
    pub gas: u64,
    /// Gas cost of THIS opcode (computed by diffing gas at `step`
    /// vs `step_end`).
    pub gas_cost: u64,
    /// Call depth at execution time. Top-level = 0.
    pub depth: u32,
    /// Stack snapshot, bottom→top. Each entry is a 32-byte word.
    pub stack: Vec<U256>,
    /// Populated if the opcode produced a halt/revert reason.
    pub error: Option<String>,
}

/// One CALL / CREATE / SELFDESTRUCT frame in the call tree.
#[derive(Debug, Clone)]
pub struct CallFrame {
    /// `"CALL"`, `"CALLCODE"`, `"DELEGATECALL"`, `"STATICCALL"`,
    /// `"CREATE"`, `"CREATE2"`, `"SELFDESTRUCT"`.
    pub call_type: &'static str,
    pub from: [u8; 20],
    /// `None` for SELFDESTRUCT-no-beneficiary edge cases.
    pub to: Option<[u8; 20]>,
    /// Value transferred (TRX, in sun). TRC-10 transfers live on
    /// `tron_token_value` — see `Trc10Inspector`. For the trace
    /// surface we report only the native value.
    pub value: U256,
    pub input: Vec<u8>,
    pub output: Vec<u8>,
    pub gas: u64,
    pub gas_used: u64,
    pub error: Option<String>,
    /// Nested calls in execution order.
    pub calls: Vec<CallFrame>,
}

/// Capture toggles. Stack capture defaults to `true` because geth's
/// default trace includes it; memory/storage default to `false`
/// because they balloon trace size.
#[derive(Debug, Clone, Copy)]
pub struct TracerOptions {
    pub disable_stack: bool,
    pub disable_memory: bool,
    pub disable_storage: bool,
    /// When set, skip the per-opcode log and only build the call
    /// tree (matches geth's `tracer: "callTracer"`).
    pub call_tracer_only: bool,
    /// Hard cap on the number of `StructLog` entries collected. `0` means
    /// unlimited (the default, for the feeLimit-bounded `debug_trace*`
    /// callers). Fork simulation sets this so an attacker running arbitrary
    /// bytecode under a large energy budget can't balloon memory with tens of
    /// millions of per-opcode logs — collection stops (and `logs_truncated`
    /// flips) once the cap is hit, before the per-step stack clone.
    pub max_logs: usize,
}

impl Default for TracerOptions {
    fn default() -> Self {
        Self {
            disable_stack: false,
            disable_memory: true,
            disable_storage: true,
            call_tracer_only: false,
            max_logs: 0,
        }
    }
}

/// Inspector implementing both per-opcode struct logging and a call
/// tree. Pluggable into revm via the standard `Inspector` trait.
pub struct StructLogTracer {
    options: TracerOptions,
    logs: Vec<StructLog>,
    /// Current depth (top-level = 0). Bumped on `call`/`create`,
    /// decremented on `*_end`. Used by struct logs and by the call
    /// tree's "I am inside frame N" bookkeeping.
    depth: u32,
    /// Open call-frame stack. The top entry is the frame currently
    /// executing. On `*_end` it pops and gets pushed into its
    /// parent's `calls` array. The root frame is constructed when
    /// the top-level `call` fires.
    open_frames: Vec<CallFrame>,
    /// Completed top-level call(s). Normally exactly one entry by
    /// the end of the run.
    completed: Vec<CallFrame>,
    /// Gas remaining captured at the start of the current opcode.
    /// Used in `step_end` to compute the per-opcode cost.
    last_step_gas: Option<u64>,
    /// Optional ERC-7562 validation-rule collector (bundler use). When set, the
    /// tracer records per-entity opcodes / storage touched inside UserOp
    /// validation subtrees. `None` for the debug-trace path (no behaviour change).
    validation: Option<ValidationCollect>,
    /// Set once the `max_logs` cap is hit and further per-opcode logs are
    /// dropped. Surfaced so callers can flag a truncated trace.
    logs_truncated: bool,
}

impl StructLogTracer {
    pub fn new(options: TracerOptions) -> Self {
        Self {
            options,
            logs: Vec::new(),
            depth: 0,
            open_frames: Vec::new(),
            completed: Vec::new(),
            last_step_gas: None,
            validation: None,
            logs_truncated: false,
        }
    }

    pub fn into_outputs(self) -> (Vec<StructLog>, Vec<CallFrame>) {
        (self.logs, self.completed)
    }

    /// True if the `max_logs` cap dropped one or more per-opcode logs.
    pub fn logs_truncated(&self) -> bool {
        self.logs_truncated
    }

    /// Attach an ERC-7562 validation collector. Pair with
    /// `TracerOptions { call_tracer_only: true, .. }` to skip the heavy struct
    /// logs — only the validation collection runs.
    pub fn with_validation(mut self, collect: ValidationCollect) -> Self {
        self.validation = Some(collect);
        self
    }

    /// Take the validation collector after a run (the collected opcodes/storage).
    pub fn take_validation(&mut self) -> Option<ValidationCollect> {
        self.validation.take()
    }
}

/// EntryPoint `validateUserOp(...)` selector (`0x19822f7c`).
const SEL_VALIDATE_USER_OP: [u8; 4] = [0x19, 0x82, 0x2f, 0x7c];
/// EntryPoint `validatePaymasterUserOp(...)` selector (`0x52b7512c`).
const SEL_VALIDATE_PAYMASTER: [u8; 4] = [0x52, 0xb7, 0x51, 0x2c];

/// Per-entity opcodes + storage slots touched while inside a UserOp VALIDATION
/// subtree, for ERC-7562 rule checking by the bundler. A subtree is "validation"
/// when the EntryPoint calls an entity's `validateUserOp` / `validatePaymaster-
/// UserOp`, or calls the configured account factory; everything nested under
/// such a call (the execution phase excepted) is recorded.
#[derive(Clone, Debug, Default)]
pub struct ValidationCollect {
    entry_point: [u8; 20],
    factory: Option<[u8; 20]>,
    /// Opcodes seen per executing contract address, validation frames only.
    pub opcodes: std::collections::HashMap<[u8; 20], std::collections::BTreeSet<u8>>,
    /// Storage slots (SLOAD/SSTORE) per address, validation frames only.
    pub storage: std::collections::HashMap<[u8; 20], std::collections::BTreeSet<[u8; 32]>>,
    /// Parallel to the open-frame stack: is this frame inside a validation subtree?
    in_validation: Vec<bool>,
    /// Parallel to the open-frame stack: the executing contract for each frame.
    addr_stack: Vec<[u8; 20]>,
}

impl ValidationCollect {
    pub fn new(entry_point: [u8; 20], factory: Option<[u8; 20]>) -> Self {
        Self { entry_point, factory, ..Default::default() }
    }

    fn is_validation_root(&self, caller: &[u8; 20], target: &[u8; 20], input: &[u8]) -> bool {
        if caller != &self.entry_point {
            return false;
        }
        if Some(*target) == self.factory {
            return true;
        }
        let sel = input.get(0..4);
        sel == Some(&SEL_VALIDATE_USER_OP[..]) || sel == Some(&SEL_VALIDATE_PAYMASTER[..])
    }

    /// A CALL/CREATE entered a frame. `input` is the calldata (empty for CREATE).
    fn on_frame_enter(&mut self, caller: [u8; 20], target: [u8; 20], input: &[u8]) {
        let parent = self.in_validation.last().copied().unwrap_or(false);
        let inside = parent || self.is_validation_root(&caller, &target, input);
        self.in_validation.push(inside);
        self.addr_stack.push(target);
    }

    fn on_frame_exit(&mut self) {
        self.in_validation.pop();
        self.addr_stack.pop();
    }

    /// One opcode executed. `slot` is `Some` for SLOAD/SSTORE.
    fn on_step(&mut self, op: u8, slot: Option<[u8; 32]>) {
        if self.in_validation.last().copied() != Some(true) {
            return;
        }
        let Some(&addr) = self.addr_stack.last() else { return };
        self.opcodes.entry(addr).or_default().insert(op);
        if let Some(s) = slot {
            self.storage.entry(addr).or_default().insert(s);
        }
    }
}

impl<CTX> Inspector<CTX, EthInterpreter> for StructLogTracer {
    fn step(&mut self, interp: &mut Interpreter<EthInterpreter>, _context: &mut CTX) {
        // ERC-7562 validation collector runs regardless of struct-log options.
        if self.validation.is_some() {
            let op = interp.bytecode.opcode();
            // SLOAD (0x54) / SSTORE (0x55) put the slot on the stack top.
            let slot = if op == 0x54 || op == 0x55 {
                interp.stack.data().last().map(|w| w.to_be_bytes::<32>())
            } else {
                None
            };
            if let Some(vc) = &mut self.validation {
                vc.on_step(op, slot);
            }
        }
        if self.options.call_tracer_only {
            return;
        }
        // Cap collection BEFORE the per-step stack clone (the memory hog).
        // Clearing `last_step_gas` makes the paired `step_end` skip, so the
        // last retained log keeps its correct `gas_cost`.
        if self.options.max_logs != 0 && self.logs.len() >= self.options.max_logs {
            self.logs_truncated = true;
            self.last_step_gas = None;
            return;
        }
        let pc = interp.bytecode.pc() as u64;
        let op = interp.bytecode.opcode();
        let gas = interp.gas.remaining();
        self.last_step_gas = Some(gas);
        let stack = if self.options.disable_stack {
            Vec::new()
        } else {
            interp.stack.data().to_vec()
        };
        self.logs.push(StructLog {
            pc,
            op,
            op_name: opcode_name(op).to_string(),
            gas,
            gas_cost: 0, // filled in step_end
            depth: self.depth,
            stack,
            error: None,
        });
    }

    fn step_end(&mut self, interp: &mut Interpreter<EthInterpreter>, _context: &mut CTX) {
        if self.options.call_tracer_only {
            return;
        }
        if let (Some(start), Some(last)) = (self.last_step_gas, self.logs.last_mut()) {
            let now = interp.gas.remaining();
            last.gas_cost = start.saturating_sub(now);
        }
    }

    fn call(
        &mut self,
        _context: &mut CTX,
        inputs: &mut CallInputs,
    ) -> Option<CallOutcome> {
        let call_type = match inputs.scheme {
            revm::interpreter::CallScheme::Call => "CALL",
            revm::interpreter::CallScheme::CallCode => "CALLCODE",
            revm::interpreter::CallScheme::DelegateCall => "DELEGATECALL",
            revm::interpreter::CallScheme::StaticCall => "STATICCALL",
        };
        let value = match inputs.value {
            revm::interpreter::CallValue::Transfer(v) => v,
            revm::interpreter::CallValue::Apparent(_) => U256::ZERO,
        };
        let input = match &inputs.input {
            revm::interpreter::CallInput::Bytes(b) => b.to_vec(),
            revm::interpreter::CallInput::SharedBuffer(_) => Vec::new(),
        };
        let caller = evm_addr_bytes(&inputs.caller);
        let target = evm_addr_bytes(&inputs.target_address);
        if let Some(vc) = &mut self.validation {
            vc.on_frame_enter(caller, target, &input);
        }
        self.open_frames.push(CallFrame {
            call_type,
            from: caller,
            to: Some(target),
            value,
            input,
            output: Vec::new(),
            gas: inputs.gas_limit,
            gas_used: 0,
            error: None,
            calls: Vec::new(),
        });
        self.depth += 1;
        None
    }

    fn call_end(
        &mut self,
        _context: &mut CTX,
        _inputs: &CallInputs,
        outcome: &mut CallOutcome,
    ) {
        if let Some(vc) = &mut self.validation {
            vc.on_frame_exit();
        }
        if let Some(mut frame) = self.open_frames.pop() {
            frame.gas_used = frame.gas.saturating_sub(outcome.result.gas.remaining());
            frame.output = outcome.result.output.to_vec();
            if !outcome.result.result.is_ok() {
                frame.error = Some(format!("{:?}", outcome.result.result));
            }
            self.attach_completed_frame(frame);
        }
        self.depth = self.depth.saturating_sub(1);
    }

    fn create(
        &mut self,
        _context: &mut CTX,
        inputs: &mut CreateInputs,
    ) -> Option<CreateOutcome> {
        let call_type = match inputs.scheme() {
            revm::interpreter::CreateScheme::Create => "CREATE",
            revm::interpreter::CreateScheme::Create2 { .. } => "CREATE2",
            _ => "CREATE",
        };
        // New contract address is unknown until create_end; attribute the
        // constructor's opcodes to the deployer (carries the parent's
        // validation flag, so a factory's CREATE is collected).
        let caller = evm_addr_bytes(&inputs.caller());
        if let Some(vc) = &mut self.validation {
            vc.on_frame_enter(caller, caller, &[]);
        }
        self.open_frames.push(CallFrame {
            call_type,
            from: caller,
            to: None,
            value: inputs.value(),
            input: inputs.init_code().to_vec(),
            output: Vec::new(),
            gas: inputs.gas_limit(),
            gas_used: 0,
            error: None,
            calls: Vec::new(),
        });
        self.depth += 1;
        None
    }

    fn create_end(
        &mut self,
        _context: &mut CTX,
        _inputs: &CreateInputs,
        outcome: &mut CreateOutcome,
    ) {
        if let Some(vc) = &mut self.validation {
            vc.on_frame_exit();
        }
        if let Some(mut frame) = self.open_frames.pop() {
            frame.gas_used = frame.gas.saturating_sub(outcome.result.gas.remaining());
            if let Some(addr) = outcome.address {
                frame.to = Some(evm_addr_bytes(&addr));
            }
            frame.output = outcome.result.output.to_vec();
            if !outcome.result.result.is_ok() {
                frame.error = Some(format!("{:?}", outcome.result.result));
            }
            self.attach_completed_frame(frame);
        }
        self.depth = self.depth.saturating_sub(1);
    }

    fn selfdestruct(&mut self, contract: EvmAddress, target: EvmAddress, value: U256) {
        // SELFDESTRUCT is in-frame; record as a child of the
        // currently-open frame.
        let frame = CallFrame {
            call_type: "SELFDESTRUCT",
            from: evm_addr_bytes(&contract),
            to: Some(evm_addr_bytes(&target)),
            value,
            input: Vec::new(),
            output: Vec::new(),
            gas: 0,
            gas_used: 0,
            error: None,
            calls: Vec::new(),
        };
        if let Some(parent) = self.open_frames.last_mut() {
            parent.calls.push(frame);
        } else {
            self.completed.push(frame);
        }
    }
}

impl StructLogTracer {
    fn attach_completed_frame(&mut self, frame: CallFrame) {
        if let Some(parent) = self.open_frames.last_mut() {
            parent.calls.push(frame);
        } else {
            self.completed.push(frame);
        }
    }
}

fn evm_addr_bytes(addr: &EvmAddress) -> [u8; 20] {
    let mut out = [0u8; 20];
    out.copy_from_slice(addr.as_slice());
    out
}

/// EVM opcode names used by `debug_traceTransaction`. Mirrors geth's
/// uppercase form so traces compare cleanly across implementations.
fn opcode_name(op: u8) -> &'static str {
    match op {
        0x00 => "STOP",
        0x01 => "ADD",
        0x02 => "MUL",
        0x03 => "SUB",
        0x04 => "DIV",
        0x05 => "SDIV",
        0x06 => "MOD",
        0x07 => "SMOD",
        0x08 => "ADDMOD",
        0x09 => "MULMOD",
        0x0a => "EXP",
        0x0b => "SIGNEXTEND",
        0x10 => "LT",
        0x11 => "GT",
        0x12 => "SLT",
        0x13 => "SGT",
        0x14 => "EQ",
        0x15 => "ISZERO",
        0x16 => "AND",
        0x17 => "OR",
        0x18 => "XOR",
        0x19 => "NOT",
        0x1a => "BYTE",
        0x1b => "SHL",
        0x1c => "SHR",
        0x1d => "SAR",
        0x20 => "KECCAK256",
        0x30 => "ADDRESS",
        0x31 => "BALANCE",
        0x32 => "ORIGIN",
        0x33 => "CALLER",
        0x34 => "CALLVALUE",
        0x35 => "CALLDATALOAD",
        0x36 => "CALLDATASIZE",
        0x37 => "CALLDATACOPY",
        0x38 => "CODESIZE",
        0x39 => "CODECOPY",
        0x3a => "GASPRICE",
        0x3b => "EXTCODESIZE",
        0x3c => "EXTCODECOPY",
        0x3d => "RETURNDATASIZE",
        0x3e => "RETURNDATACOPY",
        0x3f => "EXTCODEHASH",
        0x40 => "BLOCKHASH",
        0x41 => "COINBASE",
        0x42 => "TIMESTAMP",
        0x43 => "NUMBER",
        0x44 => "PREVRANDAO",
        0x45 => "GASLIMIT",
        0x46 => "CHAINID",
        0x47 => "SELFBALANCE",
        0x48 => "BASEFEE",
        0x50 => "POP",
        0x51 => "MLOAD",
        0x52 => "MSTORE",
        0x53 => "MSTORE8",
        0x54 => "SLOAD",
        0x55 => "SSTORE",
        0x56 => "JUMP",
        0x57 => "JUMPI",
        0x58 => "PC",
        0x59 => "MSIZE",
        0x5a => "GAS",
        0x5b => "JUMPDEST",
        0x5c => "TLOAD",
        0x5d => "TSTORE",
        0x5e => "MCOPY",
        0x5f => "PUSH0",
        0x60..=0x7f => "PUSHn",
        0x80..=0x8f => "DUPn",
        0x90..=0x9f => "SWAPn",
        0xa0..=0xa4 => "LOGn",
        0xd0 => "CALLTOKEN",
        0xd1 => "TOKENBALANCE",
        0xd2 => "CALLTOKENVALUE",
        0xd3 => "CALLTOKENID",
        0xd4 => "ISCONTRACT",
        0xd5 => "STAKE",
        0xd6 => "UNSTAKE",
        0xd7 => "WITHDRAWREWARD",
        0xd8 => "REWARDBALANCE",
        0xd9 => "ISSRCANDIDATE",
        0xda => "TOKENISSUE",
        0xdb => "UPDATEASSET",
        0xdc => "FREEZE",
        0xdd => "UNFREEZE",
        0xde => "FREEZEEXPIRETIME",
        0xdf => "VOTEWITNESS",
        0xf0 => "CREATE",
        0xf1 => "CALL",
        0xf2 => "CALLCODE",
        0xf3 => "RETURN",
        0xf4 => "DELEGATECALL",
        0xf5 => "CREATE2",
        0xfa => "STATICCALL",
        0xfd => "REVERT",
        0xfe => "INVALID",
        0xff => "SELFDESTRUCT",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod validation_tests {
    use super::*;

    #[test]
    fn collects_only_inside_validation_subtree() {
        let ep = [0xee; 20];
        let factory = [0xfa; 20];
        let acct = [0xac; 20];
        let mut vc = ValidationCollect::new(ep, Some(factory));
        // top-level EntryPoint frame (caller != EntryPoint -> not validation)
        vc.on_frame_enter([0x00; 20], ep, &[]);
        vc.on_step(0x42, None); // TIMESTAMP in EntryPoint itself -> NOT collected
        // EntryPoint -> account.validateUserOp (validation root by selector)
        vc.on_frame_enter(ep, acct, &SEL_VALIDATE_USER_OP[..]);
        vc.on_step(0x42, None); // TIMESTAMP during validation -> collected
        vc.on_step(0x54, Some([0x11; 32])); // SLOAD slot
        vc.on_frame_exit();
        // EntryPoint -> account execution (non-validation selector)
        vc.on_frame_enter(ep, acct, &[0xab, 0xcd, 0xef, 0x01]);
        vc.on_step(0x44, None); // PREVRANDAO during EXECUTION -> NOT collected
        vc.on_frame_exit();
        vc.on_frame_exit();

        assert!(vc.opcodes.get(&acct).unwrap().contains(&0x42), "validation op collected");
        assert!(!vc.opcodes.get(&acct).unwrap().contains(&0x44), "execution op excluded");
        assert!(vc.opcodes.get(&ep).is_none(), "EntryPoint's own op not collected");
        assert!(vc.storage.get(&acct).unwrap().contains(&[0x11; 32]), "SLOAD slot collected");
    }

    #[test]
    fn factory_subtree_is_validation() {
        let ep = [0xee; 20];
        let factory = [0xfa; 20];
        let mut vc = ValidationCollect::new(ep, Some(factory));
        vc.on_frame_enter([0; 20], ep, &[]); // EntryPoint
        vc.on_frame_enter(ep, factory, &[0x12, 0x34, 0x56, 0x78]); // root: target == factory
        vc.on_step(0xf0, None); // CREATE inside factory -> collected
        vc.on_frame_exit();
        vc.on_frame_exit();
        assert!(vc.opcodes.get(&factory).unwrap().contains(&0xf0));
    }

    #[test]
    fn nested_frame_inherits_validation_flag() {
        let ep = [0xee; 20];
        let acct = [0xac; 20];
        let helper = [0x77; 20];
        let mut vc = ValidationCollect::new(ep, None);
        vc.on_frame_enter([0; 20], ep, &[]);
        vc.on_frame_enter(ep, acct, &SEL_VALIDATE_PAYMASTER[..]); // validation root
        vc.on_frame_enter(acct, helper, &[0x00, 0x00, 0x00, 0x00]); // nested call by acct
        vc.on_step(0x32, None); // ORIGIN in a helper CALLED during validation -> collected
        vc.on_frame_exit();
        vc.on_frame_exit();
        vc.on_frame_exit();
        assert!(vc.opcodes.get(&helper).unwrap().contains(&0x32), "nested validation op collected");
    }
}
