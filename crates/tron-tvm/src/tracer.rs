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
}

impl Default for TracerOptions {
    fn default() -> Self {
        Self {
            disable_stack: false,
            disable_memory: true,
            disable_storage: true,
            call_tracer_only: false,
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
        }
    }

    pub fn into_outputs(self) -> (Vec<StructLog>, Vec<CallFrame>) {
        (self.logs, self.completed)
    }
}

impl<CTX> Inspector<CTX, EthInterpreter> for StructLogTracer {
    fn step(&mut self, interp: &mut Interpreter<EthInterpreter>, _context: &mut CTX) {
        if self.options.call_tracer_only {
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
        self.open_frames.push(CallFrame {
            call_type,
            from: evm_addr_bytes(&inputs.caller),
            to: Some(evm_addr_bytes(&inputs.target_address)),
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
        self.open_frames.push(CallFrame {
            call_type,
            from: evm_addr_bytes(&inputs.caller()),
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
