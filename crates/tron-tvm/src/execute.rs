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
//! **Top-level TRC-10 transfers.** A `call_token_value` / `token_id`-bearing
//! `TriggerSmartContract` or `CreateSmartContract` moves the TRC-10 from the
//! caller to the target (the called contract, or the new contract address for
//! a deploy) before the EVM runs, gated on `allowTvmTransferTrc10`, and
//! reverses it if the frame fails — mirroring java's `VMActuator.call()` /
//! `.create()` plus the `CALLTOKENVALUE` / `CALLTOKENID` opcode invoke.
//! `VmOutcome::CallTokenIgnored` is retained only for its non-VM RPC
//! consumers; the VM entry points no longer emit it.
//!
//! **Out of scope** (deferred):
//! * `feeLimit` → revm `gas_limit` conversion. java-tron's `feeLimit`
//!   is denominated in sun, with `gas_limit = feeLimit / energyFee`.
//!   We pass the supplied `energy_limit` through directly.

use std::sync::Arc;

use revm::context::{Context, Evm, FrameStack, TxEnv};
use revm::context_interface::result::{ExecutionResult, HaltReason};
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
/// Mainnet burn account (`TLsV52sRDL79HXGGm9yzwKibb6BeruhUzy`) as a
/// 20-byte EVM address -- the journal's self-target SELFDESTRUCT
/// redirect (java `Repository.getBlackHoleAddress()`).
const BLACKHOLE_EVM_ADDRESS: [u8; 20] = [
    0x77, 0x94, 0x4d, 0x19, 0xc0, 0x52, 0xb7, 0x3e, 0xe2, 0x28, 0x68, 0x23, 0xaa, 0x83, 0xf8,
    0x13, 0x8c, 0xb7, 0x03, 0x2f,
];

fn dynamic_energy_active(dyn_props: &DynamicPropertiesStore) -> bool {
    dyn_props.get_long(b"ALLOW_DYNAMIC_ENERGY").unwrap_or(0) == 1
}

/// Map a revm [`HaltReason`] to the java-tron `contractResult` code.
///
/// Mirrors `RuntimeImpl.setResultCode` (framework
/// `common/runtime/RuntimeImpl.java`): each VM exception maps to a specific
/// `contractResult`, and anything unrecognised falls through to `UNKNOWN`.
/// The success/revert/out-of-time cases are handled before the VM produces a
/// `Halt`, so they are not represented here.
///
/// revm's halt taxonomy is finer-grained than java's exception hierarchy, so
/// several revm halts that java has no dedicated exception for (out-of-offset
/// RETURNDATACOPY, static-call state changes, disallowed calls, create
/// collisions, etc.) map to `UNKNOWN`, exactly as java leaves them.
fn halt_reason_to_contract_result(
    reason: &HaltReason,
) -> tron_proto::transaction::result::ContractResult {
    use revm::context_interface::result::OutOfGasError;
    use tron_proto::transaction::result::ContractResult;
    match reason {
        // java-tron's `EnergyCost.checkMemorySize` (EnergyCost.java:543-547)
        // takes `newMemSize = memNeeded(offset, size)` as an UNBOUNDED
        // BigInteger and throws `Program.Exception.memoryOverflow`
        // (`OutOfMemoryException`, Program.java:2559) whenever it exceeds
        // `MEM_LIMIT` (the 3 MiB cap), recorded as `OUT_OF_MEMORY` -- not
        // `OUT_OF_ENERGY`. Because that check is on a BigInteger, a too-large
        // memory operand is the same fault whether it fits usize (just over the
        // 3 MiB cap) or not. revm splits the two: the former surfaces as
        // `MemoryLimitOOG` -> `OutOfGas(MemoryLimit)`, the latter as
        // `InvalidOperandOOG` -> `OutOfGas(InvalidOperand)` from
        // `as_usize_or_fail` on a memory offset/size (its only callers). Both
        // are java's `OutOfMemoryException`. State + fees are identical to any
        // other OOG halt (spend-all-energy + revert); only the recorded
        // `contractResult` differs, which the contractRet tripwire checks.
        HaltReason::OutOfGas(OutOfGasError::MemoryLimit | OutOfGasError::InvalidOperand) => {
            ContractResult::OutOfMemory
        }
        // `OutOfEnergyException` -> OUT_OF_ENERGY. Every other OOG sub-kind
        // (basic, ordinary memory-expansion energy cost, precompile, reentrancy
        // sentry) is the TRON energy fault.
        HaltReason::OutOfGas(_) => ContractResult::OutOfEnergy,
        // `IllegalOperationException` — unknown / disabled opcode (revm's
        // 0xFE designated-invalid is the same fault class in java).
        HaltReason::OpcodeNotFound | HaltReason::InvalidFEOpcode => {
            ContractResult::IllegalOperation
        }
        // `BadJumpDestinationException`.
        HaltReason::InvalidJump => ContractResult::BadJumpDestination,
        // `StackTooSmallException` (pop from empty stack).
        HaltReason::StackUnderflow => ContractResult::StackTooSmall,
        // `StackTooLargeException` (push past the 1024-deep limit).
        HaltReason::StackOverflow => ContractResult::StackTooLarge,
        // `PrecompiledContractException`.
        HaltReason::PrecompileError | HaltReason::PrecompileErrorWithContext(_) => {
            ContractResult::PrecompiledContract
        }
        // Everything else java has no dedicated code for → UNKNOWN.
        _ => ContractResult::Unknown,
    }
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
    /// `DelegatedResourceAccountIndex` — the bidirectional `(from, to)`
    /// delegation index that the DELEGATERESOURCE / UNDELEGATERESOURCE opcode
    /// bridges keep in sync with java-tron. RPC-only (never read into any
    /// balance/usage/energy/consensus computation), so it is `Option`: the
    /// production node attaches the session-wrapped store, read-only callers
    /// (`eth_call`) and unit tests leave it `None` and the bridges then skip
    /// the index write.
    pub delegated_resource_account_index:
        Option<Arc<tron_chainbase::DelegatedResourceAccountIndexStore>>,
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
    /// `reward-vi` store — the `ALLOW_OLD_REWARD_OPT` legacy-reward fast
    /// path consulted by the RewardBalance precompile and by reward
    /// settlement inside the staking opcode bridges. Optional; only
    /// voters whose reward window predates the new reward algorithm
    /// read it.
    pub reward_vi: Option<Arc<tron_chainbase::RewardViStore>>,
    /// ABI store — SELFDESTRUCT contract-row cleanup (java's
    /// `deleteContract` drops the abi row alongside account/code/
    /// contract). Optional; read-only callers skip it.
    pub abi: Option<Arc<tron_chainbase::AbiStore>>,
}

/// Per-block environment the EVM needs (BLOCKNUMBER, TIMESTAMP, ...).
#[derive(Debug, Clone, Copy, Default)]
pub struct VmBlockEnv {
    pub block_number: i64,
    pub block_timestamp_ms: i64,
    /// 20-byte EVM-form address of the block's producing witness (the TRON
    /// `0x41` prefix stripped), surfaced to the VM as COINBASE (0x41). java
    /// builds the coinbase DataWord via `new DataWord(witnessAddress)` exactly
    /// like ADDRESS/CALLER, which we already carry in 20-byte EVM form. Zero
    /// for read-only / simulation callers (eth_call, estimate) that have no
    /// real producer.
    pub beneficiary: [u8; 20],
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
    /// A value-transfer operation raised a `TransferException` (java-tron):
    /// `Program.transfer` / endowment-out-of-long-range / self-transfer
    /// validation failure (`Program.java` lines 491/563/1038/1091/1104/…).
    /// Unlike a plain revert this surfaces `contractResult TRANSFER_FAILED`,
    /// but energetically it is identical — a `TransferException` is exempt from
    /// `spendAllEnergy` (`VM.java` / `VMActuator`), so `energy_used` is the
    /// energy consumed up to the throw (forwarded call energy refunded), NOT
    /// the full limit. Distinct from `Halt` (which DOES spend-all). The VM
    /// state is unwound exactly like a revert.
    TransferFailed {
        energy_used: u64,
    },
    /// Halted (OOG, invalid opcode, etc.). All energy spent.
    Halt {
        /// Human-readable halt reason (revm `HaltReason` `Debug`/`Display`
        /// form, or a manual CREATE-failure message). Surfaced in RPC/gRPC
        /// error messages; NOT consensus-relevant.
        reason: String,
        /// java-tron `contractResult` code for this halt, mapped from the
        /// structured revm `HaltReason` at the site the halt is known
        /// (`RuntimeImpl.setResultCode`). Carried here so the executor
        /// records the precise code instead of string-matching `reason`.
        result: tron_proto::transaction::result::ContractResult,
        energy_used: u64,
    },
    /// Retained for non-VM RPC consumers (`trigger`/`call` previews in
    /// `tron-grpc` / `tron-rpc`) that still match on it. The VM entry
    /// points NO LONGER emit this: top-level token-funded
    /// `TriggerSmartContract` and `CreateSmartContract` now perform the
    /// TRC-10 transfer and execute (java parity), so a token-bearing tx
    /// runs rather than being rejected.
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

/// Third tuple element on the `*_with_trace` / `*_with_gas_cap` /
/// `*_with_deadline` variants: the run's dynamic-energy penalty total
/// (java-tron `ProgramResult.energyPenaltyTotal`), for
/// `receipt.energy_penalty_total` / constant-call `energy_penalty`.

/// Execute a `TriggerSmartContract` and return both the outcome and the
/// list of internal-transaction traces captured by the inspector.
pub fn execute_trigger_with_trace(
    stores: &VmStores,
    block: VmBlockEnv,
    contract: &TriggerSmartContract,
    energy_limit: u64,
) -> (VmOutcome, Vec<crate::internal_tx::InternalTxTrace>, u64) {
    execute_trigger_inner(stores, block, contract, energy_limit, None, None, None)
}

/// As [`execute_trigger_with_trace`] but threads the real root transaction id
/// (`sha256(raw_data)`) so nested `CREATE` opcodes derive consensus-correct
/// addresses (`0x41 || sha3omit12(rootTxId || nonce_be8)`). The consensus
/// executor MUST use this variant; read-only RPC paths that never persist a
/// nested deploy can stay on the tx-id-less wrapper.
pub fn execute_trigger_with_trace_tx_id(
    stores: &VmStores,
    block: VmBlockEnv,
    contract: &TriggerSmartContract,
    energy_limit: u64,
    tx_id: [u8; 32],
) -> (VmOutcome, Vec<crate::internal_tx::InternalTxTrace>, u64) {
    execute_trigger_inner(stores, block, contract, energy_limit, None, None, Some(tx_id))
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
) -> (VmOutcome, Vec<crate::internal_tx::InternalTxTrace>, u64) {
    execute_trigger_inner(
        stores,
        block,
        contract,
        energy_limit,
        Some(gas_cap_override),
        None,
        None,
    )
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
        None,
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
) -> (VmOutcome, Vec<crate::internal_tx::InternalTxTrace>, u64) {
    execute_trigger_inner(
        stores,
        block,
        contract,
        energy_limit,
        Some(gas_cap_override),
        Some((deadline, timeout_ms)),
        None,
    )
}

/// TRON's `CHAINID` opcode value (java `Program.getChainId`): the genesis
/// block id, truncated to its last 4 bytes when
/// `ALLOW_OPTIMIZED_RETURN_VALUE_OF_CHAINID` or `ALLOW_TVM_COMPATIBLE_EVM` is
/// active — both true on current mainnet, giving `0x2b6653dc` (728126428).
/// Every EIP-712 signature (meta-tx forwarders, ERC-20 `permit`, …) folds this
/// into its domain separator, so a wrong value makes `ecrecover` return the
/// wrong signer and the contract revert. The non-truncated 32-byte form is
/// pre-proposal history we never re-execute from a snapshot (and can't fit a
/// `u64`), so we always truncate. Returns 0 when no block index is attached
/// (read-only setups that never touch CHAINID).
fn chain_id_from_genesis(genesis: &[u8; 32]) -> u64 {
    u32::from_be_bytes([genesis[28], genesis[29], genesis[30], genesis[31]]) as u64
}

fn tron_chain_id(stores: &VmStores) -> u64 {
    stores
        .block_index
        .as_ref()
        .and_then(|bi| bi.get(0).ok())
        .map(|g| chain_id_from_genesis(g.as_bytes()))
        .unwrap_or(0)
}

/// The full 256-bit value the `CHAINID` opcode must push (VM-2). java
/// `Program.getChainId`: the genesis block id, TRUNCATED to its last 4 bytes
/// once `ALLOW_TVM_COMPATIBLE_EVM` (#60) or
/// `ALLOW_OPTIMIZED_RETURN_VALUE_OF_CHAIN_ID` (#71) is active, but the FULL
/// 32-byte genesis id in the Istanbul(#41)..#60 window. Both flags are active on
/// the 83M snapshot, so this reduces to the truncated `tron_chain_id` there.
fn chain_id_word_from_genesis(genesis: &[u8; 32], truncate: bool) -> revm::primitives::U256 {
    use revm::primitives::U256;
    if truncate {
        U256::from(u32::from_be_bytes([
            genesis[28],
            genesis[29],
            genesis[30],
            genesis[31],
        ]))
    } else {
        U256::from_be_bytes(*genesis)
    }
}

fn tron_chain_id_word(stores: &VmStores) -> revm::primitives::U256 {
    let Some(genesis) = stores.block_index.as_ref().and_then(|bi| bi.get(0).ok()) else {
        return revm::primitives::U256::ZERO;
    };
    let dp = &stores.dynamic_properties;
    let truncate = dp.get_long(b"ALLOW_TVM_COMPATIBLE_EVM") == Some(1)
        || dp.get_long(b"ALLOW_OPTIMIZED_RETURN_VALUE_OF_CHAIN_ID") == Some(1);
    chain_id_word_from_genesis(genesis.as_bytes(), truncate)
}

fn execute_trigger_inner(
    stores: &VmStores,
    block: VmBlockEnv,
    contract: &TriggerSmartContract,
    energy_limit: u64,
    gas_cap_override: Option<u64>,
    deadline: Option<(std::time::Instant, u64)>,
    root_tx_id: Option<[u8; 32]>,
) -> (VmOutcome, Vec<crate::internal_tx::InternalTxTrace>, u64) {
    let owner_bytes = match parse_tron_address_to_evm(&contract.owner_address) {
        Ok(a) => a,
        Err(e) => return (VmOutcome::PreflightError(e), Vec::new(), 0),
    };
    let target_bytes = match parse_tron_address_to_evm(&contract.contract_address) {
        Ok(a) => a,
        Err(e) => return (VmOutcome::PreflightError(e), Vec::new(), 0),
    };

    // Top-level CALLTOKEN: perform the TRC-10 transfer (debit owner,
    // credit target) BEFORE the EVM runs. If the EVM later reverts /
    // halts, undo it. Mirrors java-tron's TVMContext setup.
    // java VMActuator.call (lines 478-483, 548): the top-level token value/id
    // are read and the TRC-10 transfer performed ONLY when
    // allowTvmTransferTrc10() (proposal #15). Pre-activation the proto's token
    // fields are ignored and no transfer occurs — a pre-#15 VM tx carrying a
    // nonzero token must NOT be rejected or moved here. Matches the CREATE-path
    // gate. (ProposalSet is re-read here cheaply; it is bound again downstream.)
    let top_level_token: Option<(i64, i64)> =
        if crate::proposals::ProposalSet::from_store(&stores.dynamic_properties)
            .allow_tvm_transfer_trc10
            && (contract.call_token_value != 0 || contract.token_id != 0)
        {
            if contract.token_id <= 0 || contract.call_token_value < 0 {
                return (
                    VmOutcome::PreflightError(format!(
                        "invalid TRC-10 top-level token (id={}, value={})",
                        contract.token_id, contract.call_token_value
                    )),
                    Vec::new(),
                    0,
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
                Err(e) => return (VmOutcome::PreflightError(e), Vec::new(), 0),
            }
        } else {
            None
        };

    let mut tron_db = TronDatabase::new(
        Arc::clone(&stores.accounts),
        Arc::clone(&stores.code),
        Arc::clone(&stores.storage),
    );
    if let Some(tx_id) = root_tx_id {
        tron_db = tron_db.with_root_tx_id(tx_id);
    }
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
    // RPC-only DelegatedResourceAccountIndex: the DELEGATERESOURCE /
    // UNDELEGATERESOURCE bridges keep it in sync with java-tron when attached.
    if let Some(idx) = &stores.delegated_resource_account_index {
        tron_db = tron_db.with_delegated_resource_index(Arc::clone(idx));
    }
    // Per-frame staking/suicide rollback journal, shared between the host
    // (records reversing entries as it writes) and the inspector (unwinds a
    // reverted frame's subtree). Mirrors java's per-frame child Repository: a
    // staking op in an inner frame that reverts leaves no trace even when the
    // top-level tx succeeds.
    let staking_journal = crate::staking_journal::StakingJournal::new_shared();
    tron_db = tron_db.with_staking_journal(Arc::clone(&staking_journal));
    // Witness registry backs the VOTEWITNESS bridge's SR-candidate check.
    tron_db = tron_db.with_witnesses(Arc::clone(&stores.witnesses));
    if let Some(rv) = stores.reward_vi.clone() {
        tron_db = tron_db.with_reward_vi(rv);
    }
    if let Some(abi) = stores.abi.clone() {
        tron_db = tron_db.with_abi(abi);
    }
    let proposals = crate::proposals::ProposalSet::from_store(&stores.dynamic_properties);
    let spec = proposals.resolve_spec();
    let chain_id = tron_chain_id(stores);
    let mut ctx = Context::mainnet()
        .with_db(tron_db)
        .modify_cfg_chained(|cfg| {
            cfg.spec = spec;
            // TRON caps VM memory at java's `EnergyCost.MEM_LIMIT` (3 MiB);
            // exceeding it yields MemoryLimitOOG — all energy consumed — matching
            // java's OutOfMemoryException → spendAllEnergy. revm's default is
            // ~4 GiB, so without this a >3 MiB-memory tx with a large feeLimit
            // would SUCCEED here while java faults (a contractRet flip).
            cfg.memory_limit = 3 * 1024 * 1024;
            // TRON fork: the opcode set comes from `spec` (proposal-resolved),
            // but the *energy* schedule is TRON's Frontier-era table with a
            // Frontier-pinned gas spec. Keep the two decoupled.
            cfg.gas_params = crate::tron_gas_params_for(proposals.allow_tvm_compatible_evm);
            // TRON fork: CHAINID is the genesis-block-id-derived value, NOT an
            // EIP-155 chain id — EIP-712 domain separators depend on it. TRON
            // transactions carry no EIP-155 chain id, so the tx-level chain-id
            // check must stay OFF (else every tx is rejected InvalidChainId).
            cfg.chain_id = chain_id;
            cfg.tx_chain_id_check = false;
            // TRON fork: java-tron enforces NO contract-code-size limit on
            // deployment. `Program.createContractImpl` only checks there is
            // enough energy to pay `saveCodeEnergy = code_len * getCreateData()`
            // (200/byte) — there is no EIP-170 (24 KiB) byte cap. revm would
            // otherwise reject any runtime code > 24576 bytes with
            // `CreateContractSizeLimit`; and because TRON forwards ALL gas to a
            // CREATE frame (no EIP-150 1/64 retention), that rejection burns the
            // entire forwarded budget and OOGs the caller — e.g. a ~34 KiB
            // SunSwap-V3 pool deployed via the factory's nested CREATE2 (block
            // 83,349,051), which then cascades into thousands of downstream
            // divergences. Lift the cap (and with it the EIP-3860 2× init-code
            // cap) so deployment is bounded only by energy + tx size, as in java.
            cfg.limit_contract_code_size = Some(usize::MAX);
        })
        .modify_block_chained(|b| {
            // VM block context = the block being executed (java's
            // ProgramInvokeFactory reads `block.number` and
            // `block.timestamp / 1000`). Without this the revm BlockEnv
            // defaults to number=0 / timestamp=1, so every contract reading
            // `block.timestamp` got `1` and any `block.timestamp - t`
            // underflowed.
            b.number = U256::from(block.block_number.max(0) as u64);
            b.timestamp = U256::from((block.block_timestamp_ms / 1000).max(0) as u64);
            // COINBASE (0x41): the block's producing witness in 20-byte EVM
            // form. java loads `block.getWitnessAddress()` into the coinbase
            // DataWord the same way it builds ADDRESS/CALLER.
            b.beneficiary = EvmAddress::from(block.beneficiary);
            // GASLIMIT (0x45) pushes 0 and BASEFEE (0x48) pushes
            // `getEnergyFee()` (java `gasLimitAction` / `baseFeeAction`); both
            // are handled in the opcode handlers (block_info.rs) reading the
            // host, NOT via BlockEnv — setting BlockEnv.gas_limit=0 would make
            // revm reject the tx (gas_limit > block limit) and setting
            // BlockEnv.basefee would trip the legacy `gas_price >= basefee`
            // check.
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
    )
    .with_reward_vi(stores.reward_vi.clone());
    let mut instructions = EthInstructions::<EthInterpreter, _>::new_mainnet_with_spec(spec);
    // TRON fork: replace the spec-adjusted static gas table with TRON's static
    // energy table (Frontier base — SLOAD 50, CALL 40, EXP base 10 … — with
    // MLOAD/MSTORE/MSTORE8 at base 1). Done before installing the TRON opcode
    // stubs so their gas entries (0xd0..0xd4) survive.
    *instructions.gas_table_mut() =
        crate::tron_static_gas_table(proposals.allow_higher_limit_for_max_cpu_time_of_one_tx);
    crate::evm::install_tron_opcode_stubs(&mut instructions, &proposals);
    let mut trc10_inspector = crate::trc10::Trc10Inspector::new(Arc::clone(&stores.accounts));
    if dynamic_energy_active(&stores.dynamic_properties) {
        trc10_inspector = trc10_inspector.with_dynamic_energy(
            Arc::clone(&stores.contract_state),
            Arc::clone(&stores.dynamic_properties),
        );
    }
    // Same shared journal the host writes into — lets the inspector unwind a
    // reverted frame's staking/suicide writes (per-frame analogue of the
    // executor's per-tx VmSession).
    trc10_inspector = trc10_inspector.with_staking_journal(
        Arc::clone(&staking_journal),
        Arc::clone(&stores.dynamic_properties),
        stores.votes.as_ref().map(Arc::clone),
        Arc::clone(&stores.delegated_resources),
    );
    if let Some((id, val)) = top_level_token {
        trc10_inspector = trc10_inspector.with_top_level_token(id, val);
    }
    if let Some((dl, _)) = deadline {
        trc10_inspector = trc10_inspector.with_deadline(dl);
    }
    // TRON SELFDESTRUCT semantics: the journal's destroy rule follows
    // proposal #94 (not the Cancun opcode spec), and a self-target
    // destroy credits the burn account when TRC-10 transfers are live.
    {
        use revm::context_interface::JournalTr as _;
        ctx.journaled_state.set_tron_selfdestruct_overrides(
            Some(proposals.allow_tvm_selfdestruct_restriction),
            proposals
                .allow_tvm_transfer_trc10
                .then(|| EvmAddress::from_slice(&BLACKHOLE_EVM_ADDRESS)),
            Some(proposals.allow_energy_adjustment),
        );
        ctx.journaled_state
            .set_tron_chain_id_word(Some(tron_chain_id_word(stores)));
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
        Err(e) => return (VmOutcome::PreflightError(format!("TxEnv build: {e:?}")), Vec::new(), 0),
    };

    // Env-gated diagnostic: per-opcode gas trace for target tx(s) (env
    // TRON_OP_TRACE_TX = one or more hex tx ids, comma/space-separated). Emits
    // `OPTRACE …` lines on stderr from the core interpreter (reliable, unlike
    // the inspector trace). Off by default.
    let op_trace = root_tx_id
        .and_then(|id| {
            std::env::var("TRON_OP_TRACE_TX").ok().map(|want| {
                let got: String = id.iter().map(|b| format!("{b:02x}")).collect();
                want.split([',', ' ', '\n', '\t'])
                    .map(|s| s.trim().trim_start_matches("0x"))
                    .filter(|s| !s.is_empty())
                    .any(|s| s == got)
            })
        })
        .unwrap_or(false);
    if op_trace {
        let id: String = root_tx_id
            .map(|id| id.iter().map(|b| format!("{b:02x}")).collect())
            .unwrap_or_default();
        eprintln!("OPTRACE_TX_BEGIN {id}");
        revm::interpreter::set_op_trace(true);
    }
    let outcome = evm.inspect_tx_commit(tx);
    if op_trace {
        revm::interpreter::set_op_trace(false);
        eprintln!("OPTRACE_TX_END");
    }
    // TRON fork: did a value-transfer raise a `TransferException`? The
    // CALL/CALLTOKEN opcode handler sets this on the journal before returning
    // `InstructionResult::TransferFailed`. A `TransferException` settles its
    // gas exactly like a revert (consumed-only, `spendAllEnergy`-exempt) and so
    // surfaces from revm as `ExecutionResult::Revert` — but it must record
    // `contractResult TRANSFER_FAILED`, so we relabel the Revert outcome below.
    let transfer_failed = {
        use revm::context_interface::JournalTr as _;
        evm.ctx.journaled_state.tron_transfer_failed()
    };
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
    let energy_penalty = evm.inspector.energy_penalty_total();
    let timeout_budget_ms = deadline.map(|(_, ms)| ms).unwrap_or(0);
    let vm_outcome = match outcome {
        Ok(ExecutionResult::Success { output, gas, logs, .. }) => VmOutcome::Success {
            return_data: output.data().to_vec(),
            energy_used: gas.tx_gas_used(),
            logs: collect_vm_logs(logs),
        },
        Ok(ExecutionResult::Revert { output, gas, .. }) => {
            unwind_on_failure(stores);
            if transfer_failed {
                // A `TransferException` unwound the whole tx at a value-transfer
                // opcode. State is reverted just like a normal REVERT; only the
                // recorded `contractResult` differs (TRANSFER_FAILED). Energy is
                // the consumed total (spend-all-exempt), already in `gas`.
                VmOutcome::TransferFailed {
                    energy_used: gas.tx_gas_used(),
                }
            } else {
                VmOutcome::Revert {
                    return_data: output.to_vec(),
                    energy_used: gas.tx_gas_used(),
                }
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
                    result: halt_reason_to_contract_result(&reason),
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
    (vm_outcome, traces, energy_penalty)
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
    root_tx_id: Option<[u8; 32]>,
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
    // java VMActuator.call (lines 478-483, 548): the top-level token value/id
    // are read and the TRC-10 transfer performed ONLY when
    // allowTvmTransferTrc10() (proposal #15). Pre-activation the proto's token
    // fields are ignored and no transfer occurs — a pre-#15 VM tx carrying a
    // nonzero token must NOT be rejected or moved here. Matches the CREATE-path
    // gate. (ProposalSet is re-read here cheaply; it is bound again downstream.)
    let top_level_token: Option<(i64, i64)> =
        if crate::proposals::ProposalSet::from_store(&stores.dynamic_properties)
            .allow_tvm_transfer_trc10
            && (contract.call_token_value != 0 || contract.token_id != 0)
        {
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
    if let Some(tx_id) = root_tx_id {
        tron_db = tron_db.with_root_tx_id(tx_id);
    }
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
    // RPC-only DelegatedResourceAccountIndex: the DELEGATERESOURCE /
    // UNDELEGATERESOURCE bridges keep it in sync with java-tron when attached.
    if let Some(idx) = &stores.delegated_resource_account_index {
        tron_db = tron_db.with_delegated_resource_index(Arc::clone(idx));
    }
    // Per-frame staking/suicide rollback journal, shared between the host
    // (records reversing entries as it writes) and the inspector (unwinds a
    // reverted frame's subtree). Mirrors java's per-frame child Repository: a
    // staking op in an inner frame that reverts leaves no trace even when the
    // top-level tx succeeds.
    let staking_journal = crate::staking_journal::StakingJournal::new_shared();
    tron_db = tron_db.with_staking_journal(Arc::clone(&staking_journal));
    // Witness registry backs the VOTEWITNESS bridge's SR-candidate check.
    tron_db = tron_db.with_witnesses(Arc::clone(&stores.witnesses));
    if let Some(rv) = stores.reward_vi.clone() {
        tron_db = tron_db.with_reward_vi(rv);
    }
    if let Some(abi) = stores.abi.clone() {
        tron_db = tron_db.with_abi(abi);
    }
    let proposals = crate::proposals::ProposalSet::from_store(&stores.dynamic_properties);
    let spec = proposals.resolve_spec();
    let chain_id = tron_chain_id(stores);
    let mut ctx = Context::mainnet()
        .with_db(tron_db)
        .modify_cfg_chained(|cfg| {
            cfg.spec = spec;
            // TRON caps VM memory at java's `EnergyCost.MEM_LIMIT` (3 MiB);
            // exceeding it yields MemoryLimitOOG — all energy consumed — matching
            // java's OutOfMemoryException → spendAllEnergy. revm's default is
            // ~4 GiB, so without this a >3 MiB-memory tx with a large feeLimit
            // would SUCCEED here while java faults (a contractRet flip).
            cfg.memory_limit = 3 * 1024 * 1024;
            // TRON fork: the opcode set comes from `spec` (proposal-resolved),
            // but the *energy* schedule is TRON's Frontier-era table with a
            // Frontier-pinned gas spec. Keep the two decoupled.
            cfg.gas_params = crate::tron_gas_params_for(proposals.allow_tvm_compatible_evm);
            // TRON fork: CHAINID is the genesis-block-id-derived value, NOT an
            // EIP-155 chain id — EIP-712 domain separators depend on it. TRON
            // transactions carry no EIP-155 chain id, so the tx-level chain-id
            // check must stay OFF (else every tx is rejected InvalidChainId).
            cfg.chain_id = chain_id;
            cfg.tx_chain_id_check = false;
            // TRON fork: java-tron enforces NO contract-code-size limit on
            // deployment. `Program.createContractImpl` only checks there is
            // enough energy to pay `saveCodeEnergy = code_len * getCreateData()`
            // (200/byte) — there is no EIP-170 (24 KiB) byte cap. revm would
            // otherwise reject any runtime code > 24576 bytes with
            // `CreateContractSizeLimit`; and because TRON forwards ALL gas to a
            // CREATE frame (no EIP-150 1/64 retention), that rejection burns the
            // entire forwarded budget and OOGs the caller — e.g. a ~34 KiB
            // SunSwap-V3 pool deployed via the factory's nested CREATE2 (block
            // 83,349,051), which then cascades into thousands of downstream
            // divergences. Lift the cap (and with it the EIP-3860 2× init-code
            // cap) so deployment is bounded only by energy + tx size, as in java.
            cfg.limit_contract_code_size = Some(usize::MAX);
        })
        .modify_block_chained(|b| {
            // VM block context = the block being executed (java's
            // ProgramInvokeFactory reads `block.number` and
            // `block.timestamp / 1000`). Without this the revm BlockEnv
            // defaults to number=0 / timestamp=1, so every contract reading
            // `block.timestamp` got `1` and any `block.timestamp - t`
            // underflowed.
            b.number = U256::from(block.block_number.max(0) as u64);
            b.timestamp = U256::from((block.block_timestamp_ms / 1000).max(0) as u64);
            // COINBASE (0x41): the block's producing witness in 20-byte EVM
            // form. java loads `block.getWitnessAddress()` into the coinbase
            // DataWord the same way it builds ADDRESS/CALLER.
            b.beneficiary = EvmAddress::from(block.beneficiary);
            // GASLIMIT (0x45) pushes 0 and BASEFEE (0x48) pushes
            // `getEnergyFee()` (java `gasLimitAction` / `baseFeeAction`); both
            // are handled in the opcode handlers (block_info.rs) reading the
            // host, NOT via BlockEnv — setting BlockEnv.gas_limit=0 would make
            // revm reject the tx (gas_limit > block limit) and setting
            // BlockEnv.basefee would trip the legacy `gas_price >= basefee`
            // check.
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
    )
    .with_reward_vi(stores.reward_vi.clone());
    let mut instructions = EthInstructions::<EthInterpreter, _>::new_mainnet_with_spec(spec);
    // TRON fork: replace the spec-adjusted static gas table with TRON's static
    // energy table (Frontier base — SLOAD 50, CALL 40, EXP base 10 … — with
    // MLOAD/MSTORE/MSTORE8 at base 1). Done before installing the TRON opcode
    // stubs so their gas entries (0xd0..0xd4) survive.
    *instructions.gas_table_mut() =
        crate::tron_static_gas_table(proposals.allow_higher_limit_for_max_cpu_time_of_one_tx);
    crate::evm::install_tron_opcode_stubs(&mut instructions, &proposals);
    let mut trc10_inspector =
        crate::trc10::Trc10Inspector::new(Arc::clone(&stores.accounts)).with_tracer(tracer);
    if dynamic_energy_active(&stores.dynamic_properties) {
        trc10_inspector = trc10_inspector.with_dynamic_energy(
            Arc::clone(&stores.contract_state),
            Arc::clone(&stores.dynamic_properties),
        );
    }
    // Same shared journal the host writes into — lets the inspector unwind a
    // reverted frame's staking/suicide writes.
    trc10_inspector = trc10_inspector.with_staking_journal(
        Arc::clone(&staking_journal),
        Arc::clone(&stores.dynamic_properties),
        stores.votes.as_ref().map(Arc::clone),
        Arc::clone(&stores.delegated_resources),
    );
    if let Some((id, val)) = top_level_token {
        trc10_inspector = trc10_inspector.with_top_level_token(id, val);
    }
    if let Some((dl, _)) = deadline {
        trc10_inspector = trc10_inspector.with_deadline(dl);
    }
    // TRON SELFDESTRUCT semantics: the journal's destroy rule follows
    // proposal #94 (not the Cancun opcode spec), and a self-target
    // destroy credits the burn account when TRC-10 transfers are live.
    {
        use revm::context_interface::JournalTr as _;
        ctx.journaled_state.set_tron_selfdestruct_overrides(
            Some(proposals.allow_tvm_selfdestruct_restriction),
            proposals
                .allow_tvm_transfer_trc10
                .then(|| EvmAddress::from_slice(&BLACKHOLE_EVM_ADDRESS)),
            Some(proposals.allow_energy_adjustment),
        );
        ctx.journaled_state
            .set_tron_chain_id_word(Some(tron_chain_id_word(stores)));
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
    // See `execute_trigger_inner`: a `TransferException` settles like a revert
    // but records `contractResult TRANSFER_FAILED`.
    let transfer_failed = {
        use revm::context_interface::JournalTr as _;
        evm.ctx.journaled_state.tron_transfer_failed()
    };
    let timeout_budget_ms = deadline.map(|(_, ms)| ms).unwrap_or(0);
    let vm_outcome = match outcome {
        Ok(ExecutionResult::Success { output, gas, logs, .. }) => VmOutcome::Success {
            return_data: output.data().to_vec(),
            energy_used: gas.tx_gas_used(),
            logs: collect_vm_logs(logs),
        },
        Ok(ExecutionResult::Revert { output, gas, .. }) => {
            unwind_on_failure(stores);
            if transfer_failed {
                VmOutcome::TransferFailed {
                    energy_used: gas.tx_gas_used(),
                }
            } else {
                VmOutcome::Revert {
                    return_data: output.to_vec(),
                    energy_used: gas.tx_gas_used(),
                }
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
                    result: halt_reason_to_contract_result(&reason),
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
    // java-tron reads TRC-10 balances through AccountCapsule.getAssetV2 ->
    // AssetUtil.importAsset: an asset-optimized account keeps its balances in
    // the separate account-asset store, NOT inline in the Account proto. Merge
    // them before the sender-balance check — without this an optimized sender
    // reads 0 and a valid CALLTOKEN wrongly fails (the actuator paths in
    // tron-actuator already do this; the VM paths must too).
    tron_chainbase::import_all_asset(&mut from_acct);
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
    // Same import-before-read for the recipient: an existing optimized target
    // holds its balance in the account-asset store (a freshly-created default
    // account is not optimized, so this is a no-op for it).
    tron_chainbase::import_all_asset(&mut to_acct);
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

/// Reverse a token-funded deploy's up-front TRC-10 transfer (credit the
/// caller, debit the new contract address) when the deploy fails before
/// committing. Mirrors the trigger path's `unwind_on_failure`: java's
/// reverted `rootRepository` deposit never reaches `commit()`, so the
/// transfer must not persist. No-op when no transfer was applied
/// (`token` is `None`, or its value is `0`). Errors are swallowed — the
/// caller is already on a failure path and the per-tx session will be
/// discarded on the consensus path.
fn unwind_create_token(
    stores: &VmStores,
    contract: &CreateSmartContract,
    contract_addr: &[u8],
    token: Option<(i64, i64)>,
) {
    if let Some((id, val)) = token {
        // `apply_top_level_trc10` returns early when `val == 0`, so the
        // id-only case (token_value == 0) is a harmless no-op here.
        let _ = apply_top_level_trc10(
            &stores.accounts,
            contract_addr,
            &contract.owner_address,
            id,
            val,
        );
    }
}

/// Derive a top-level `CreateSmartContract`'s contract address.
///
/// java-tron `WalletUtil.generateContractAddress(Transaction)`:
/// `0x41 || sha3omit12(txRawDataHash(32) ++ ownerAddress(21))`. The hash
/// input is the tx id FIRST, then the 21-byte owner — verified against
/// mainnet (factory `TEo47ug…`, its creator, and the deploy tx reproduce
/// the on-chain address only in this order; owner-first does not).
pub fn derive_top_level_contract_address(tx_id: &[u8; 32], owner_address: &[u8]) -> [u8; 21] {
    let mut hash_input = Vec::with_capacity(32 + owner_address.len());
    hash_input.extend_from_slice(tx_id);
    hash_input.extend_from_slice(owner_address);
    let h = tron_crypto::hash::keccak256(&hash_input);
    let mut tron_addr = [0u8; 21];
    tron_addr[0] = 0x41;
    tron_addr[1..].copy_from_slice(&h[12..]);
    tron_addr
}

/// Execute a `CreateSmartContract` through the TVM.
///
/// TRON's contract-address derivation is `0x41 || keccak256(tx_id || owner)[12..]`.
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

/// java `ProgramPrecompile.getCode` (ProgramPrecompile.java:31-54) — the
/// pre-`ALLOW_TVM_CONSTANTINOPLE` deploy-time deployed-code derivation. Walks
/// the init bytecode skipping PUSH1..PUSH32 immediates; on the first
/// `RETURN(0xf3)` immediately followed by `STOP(0x00)` it returns the bytes
/// AFTER the STOP. With no such pair it falls back to a 32-byte zero word — the
/// pre-Constantinople fallback (`new byte[DataWord.WORD_SIZE]`); java only ever
/// calls this when `allowTvmConstantinople()` is false, so the post-fork empty
/// fallback is unreachable here.
fn program_precompile_get_code(ops: &[u8]) -> Vec<u8> {
    let mut i = 0usize;
    while i < ops.len() {
        let op = ops[i];
        // RETURN(0xf3) immediately followed by STOP(0x00): take everything after
        // the STOP (java advances `i` to the STOP, then copies `ops[i+1..]`).
        if op == 0xf3 && i + 1 < ops.len() && ops[i + 1] == 0x00 {
            return ops.get(i + 2..).map(<[u8]>::to_vec).unwrap_or_default();
        }
        // PUSH1..PUSH32 carry 1..32 immediate bytes that must not be scanned.
        if (0x60..=0x7f).contains(&op) {
            i += (op - 0x60) as usize + 1;
        }
        i += 1;
    }
    vec![0u8; 32]
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
) -> (VmOutcome, Vec<crate::internal_tx::InternalTxTrace>, u64) {
    let Some(smart_contract) = &contract.new_contract else {
        return (
            VmOutcome::PreflightError("CreateSmartContract.new_contract missing".to_string()),
            Vec::new(),
            0,
        );
    };
    let owner_bytes = match parse_tron_address_to_evm(&contract.owner_address) {
        Ok(a) => a,
        Err(e) => return (VmOutcome::PreflightError(e), Vec::new(), 0),
    };

    let tron_addr = derive_top_level_contract_address(tx_id, &contract.owner_address);
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
            0,
        );
    }
    if let Err(e) = stores.accounts.put(
        &tron_contract_addr,
        &tron_proto::Account {
            address: tron_contract_addr.as_bytes().to_vec(),
            balance: smart_contract.call_value.max(0),
            code: init_code.clone(),
            code_hash: init_hash.to_vec(),
            // java stamps create_time on contract creation (= head-block
            // timestamp). The commit path sees this pre-installed account as
            // existing, so create_time must be set here or it stays 0.
            create_time: stores
                .dynamic_properties
                .latest_block_header_timestamp()
                .unwrap_or(0),
            ..Default::default()
        },
    ) {
        return (
            VmOutcome::PreflightError(format!("install contract account: {e:?}")),
            Vec::new(),
            0,
        );
    }

    // CALL the just-installed account; init code runs.
    let mut tron_db = TronDatabase::new(
        Arc::clone(&stores.accounts),
        Arc::clone(&stores.code),
        Arc::clone(&stores.storage),
    )
    .with_root_tx_id(*tx_id);
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
    // RPC-only DelegatedResourceAccountIndex: the DELEGATERESOURCE /
    // UNDELEGATERESOURCE bridges keep it in sync with java-tron when attached.
    if let Some(idx) = &stores.delegated_resource_account_index {
        tron_db = tron_db.with_delegated_resource_index(Arc::clone(idx));
    }
    // Per-frame staking/suicide rollback journal, shared between the host
    // (records reversing entries as it writes) and the inspector (unwinds a
    // reverted frame's subtree). Mirrors java's per-frame child Repository: a
    // staking op in an inner frame that reverts leaves no trace even when the
    // top-level tx succeeds.
    let staking_journal = crate::staking_journal::StakingJournal::new_shared();
    tron_db = tron_db.with_staking_journal(Arc::clone(&staking_journal));
    // Witness registry backs the VOTEWITNESS bridge's SR-candidate check.
    tron_db = tron_db.with_witnesses(Arc::clone(&stores.witnesses));
    if let Some(rv) = stores.reward_vi.clone() {
        tron_db = tron_db.with_reward_vi(rv);
    }
    if let Some(abi) = stores.abi.clone() {
        tron_db = tron_db.with_abi(abi);
    }
    let proposals = crate::proposals::ProposalSet::from_store(&stores.dynamic_properties);
    let spec = proposals.resolve_spec();
    let chain_id = tron_chain_id(stores);

    // java VMActuator.create() forces a brand-new contract's program frame to
    // version 1 under `ALLOW_TVM_COMPATIBLE_EVM` (VMActuator.java:325,415); with
    // the flag off it clears the version (0). The deploy's `SmartContract` row
    // isn't written until commit, so tell the db to report this version for the
    // deploy address during the init-code run — that drives the per-frame
    // EIP-150 1/64 retention + GASPRICE for any CALL/CREATE the init code makes.
    let deploy_version = if proposals.allow_tvm_compatible_evm { 1 } else { 0 };
    tron_db = tron_db.with_top_level_deploy_version(evm_contract_addr, deploy_version);

    // Top-level token-funded deploy: java VMActuator.create() reads
    // `tokenValue`/`tokenId` from the contract ONLY when
    // `allowTvmTransferTrc10()` is active (lines 358-361), and then transfers
    // the TRC-10 from the caller to the NEW contract address
    // (`MUtil.transferToken`, lines 441-443) before init code runs. When the
    // flag is OFF the values stay 0 — the deploy proceeds with NO token move
    // and is NOT rejected. We mirror that: the debit/credit happens here,
    // after the contract account is pre-installed (so the credit lands on the
    // real account row, not a row the pre-install would overwrite) and before
    // the EVM runs; on a failed deploy it is reversed alongside the
    // pre-installed account cleanup. `with_top_level_token` (below) feeds the
    // same numbers to the init code's CALLTOKENVALUE / CALLTOKENID opcodes,
    // matching java's `createProgramInvoke(..., tokenValue, tokenId, ...)`.
    let top_level_token: Option<(i64, i64)> = if proposals.allow_tvm_transfer_trc10
        && (contract.call_token_value != 0 || contract.token_id != 0)
    {
        if contract.token_id <= 0 || contract.call_token_value < 0 {
            // java `checkTokenValueAndId`: tokenValue > 0 with tokenId == 0
            // (or a non-positive id) is a ContractValidateException. Clean up
            // the pre-installed account so a rejected deploy leaves no trace.
            let _ = stores.accounts.delete(&tron_contract_addr);
            return (
                VmOutcome::PreflightError(format!(
                    "invalid TRC-10 top-level token on CREATE (id={}, value={})",
                    contract.token_id, contract.call_token_value
                )),
                Vec::new(),
                0,
            );
        }
        if contract.call_token_value > 0 {
            match apply_top_level_trc10(
                &stores.accounts,
                &contract.owner_address,
                tron_contract_addr.as_bytes(),
                contract.token_id,
                contract.call_token_value,
            ) {
                Ok(_) => Some((contract.token_id, contract.call_token_value)),
                Err(e) => {
                    let _ = stores.accounts.delete(&tron_contract_addr);
                    return (VmOutcome::PreflightError(e), Vec::new(), 0);
                }
            }
        } else {
            // tokenValue == 0 (tokenId may be set): no transfer, but the
            // opcodes still see the id (java passes both into the invoke).
            Some((contract.token_id, contract.call_token_value))
        }
    } else {
        None
    };

    let mut ctx = Context::mainnet()
        .with_db(tron_db)
        .modify_cfg_chained(|cfg| {
            cfg.spec = spec;
            // TRON caps VM memory at java's `EnergyCost.MEM_LIMIT` (3 MiB);
            // exceeding it yields MemoryLimitOOG — all energy consumed — matching
            // java's OutOfMemoryException → spendAllEnergy. revm's default is
            // ~4 GiB, so without this a >3 MiB-memory tx with a large feeLimit
            // would SUCCEED here while java faults (a contractRet flip).
            cfg.memory_limit = 3 * 1024 * 1024;
            // TRON fork: the opcode set comes from `spec` (proposal-resolved),
            // but the *energy* schedule is TRON's Frontier-era table with a
            // Frontier-pinned gas spec. Keep the two decoupled.
            cfg.gas_params = crate::tron_gas_params_for(proposals.allow_tvm_compatible_evm);
            // TRON fork: CHAINID is the genesis-block-id-derived value, NOT an
            // EIP-155 chain id — EIP-712 domain separators depend on it. TRON
            // transactions carry no EIP-155 chain id, so the tx-level chain-id
            // check must stay OFF (else every tx is rejected InvalidChainId).
            cfg.chain_id = chain_id;
            cfg.tx_chain_id_check = false;
            // TRON fork: java-tron enforces NO contract-code-size limit on
            // deployment. `Program.createContractImpl` only checks there is
            // enough energy to pay `saveCodeEnergy = code_len * getCreateData()`
            // (200/byte) — there is no EIP-170 (24 KiB) byte cap. revm would
            // otherwise reject any runtime code > 24576 bytes with
            // `CreateContractSizeLimit`; and because TRON forwards ALL gas to a
            // CREATE frame (no EIP-150 1/64 retention), that rejection burns the
            // entire forwarded budget and OOGs the caller — e.g. a ~34 KiB
            // SunSwap-V3 pool deployed via the factory's nested CREATE2 (block
            // 83,349,051), which then cascades into thousands of downstream
            // divergences. Lift the cap (and with it the EIP-3860 2× init-code
            // cap) so deployment is bounded only by energy + tx size, as in java.
            cfg.limit_contract_code_size = Some(usize::MAX);
        })
        .modify_block_chained(|b| {
            // VM block context = the block being executed (java's
            // ProgramInvokeFactory reads `block.number` and
            // `block.timestamp / 1000`). Without this the revm BlockEnv
            // defaults to number=0 / timestamp=1, so every contract reading
            // `block.timestamp` got `1` and any `block.timestamp - t`
            // underflowed.
            b.number = U256::from(block.block_number.max(0) as u64);
            b.timestamp = U256::from((block.block_timestamp_ms / 1000).max(0) as u64);
            // COINBASE (0x41): the block's producing witness in 20-byte EVM
            // form. java loads `block.getWitnessAddress()` into the coinbase
            // DataWord the same way it builds ADDRESS/CALLER.
            b.beneficiary = EvmAddress::from(block.beneficiary);
            // GASLIMIT (0x45) pushes 0 and BASEFEE (0x48) pushes `getEnergyFee()`
            // via the opcode handlers (block_info.rs) reading the host, NOT via
            // BlockEnv (see the trigger build sites for why).
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
    )
    .with_reward_vi(stores.reward_vi.clone());
    let mut instructions = EthInstructions::<EthInterpreter, _>::new_mainnet_with_spec(spec);
    // TRON fork: replace the spec-adjusted static gas table with TRON's static
    // energy table (Frontier base — SLOAD 50, CALL 40, EXP base 10 … — with
    // MLOAD/MSTORE/MSTORE8 at base 1). Done before installing the TRON opcode
    // stubs so their gas entries (0xd0..0xd4) survive.
    *instructions.gas_table_mut() =
        crate::tron_static_gas_table(proposals.allow_higher_limit_for_max_cpu_time_of_one_tx);
    crate::evm::install_tron_opcode_stubs(&mut instructions, &proposals);
    let mut trc10 = crate::trc10::Trc10Inspector::new(Arc::clone(&stores.accounts));
    if dynamic_energy_active(&stores.dynamic_properties) {
        trc10 = trc10.with_dynamic_energy(
            Arc::clone(&stores.contract_state),
            Arc::clone(&stores.dynamic_properties),
        );
    }
    // Same shared journal the host writes into — lets the inspector unwind a
    // reverted frame's staking/suicide writes.
    trc10 = trc10.with_staking_journal(
        Arc::clone(&staking_journal),
        Arc::clone(&stores.dynamic_properties),
        stores.votes.as_ref().map(Arc::clone),
        Arc::clone(&stores.delegated_resources),
    );
    // Feed a token-funded deploy's (token_id, token_value) into the init
    // code's CALLTOKENVALUE / CALLTOKENID opcodes (the asset_v2 transfer was
    // already applied above), matching java's
    // `createProgramInvoke(..., tokenValue, tokenId, ...)`.
    if let Some((id, val)) = top_level_token {
        trc10 = trc10.with_top_level_token(id, val);
    }
    // TRON SELFDESTRUCT semantics: the journal's destroy rule follows
    // proposal #94 (not the Cancun opcode spec), and a self-target
    // destroy credits the burn account when TRC-10 transfers are live.
    {
        use revm::context_interface::JournalTr as _;
        ctx.journaled_state.set_tron_selfdestruct_overrides(
            Some(proposals.allow_tvm_selfdestruct_restriction),
            proposals
                .allow_tvm_transfer_trc10
                .then(|| EvmAddress::from_slice(&BLACKHOLE_EVM_ADDRESS)),
            Some(proposals.allow_energy_adjustment),
        );
        ctx.journaled_state
            .set_tron_chain_id_word(Some(tron_chain_id_word(stores)));
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
            // TxEnv build failure: reverse the up-front TRC-10 transfer so the
            // caller's asset_v2 is restored (the VM never ran). The pre-
            // installed account is left as-is, matching the prior (token-free)
            // failure behaviour — on the consensus path the per-tx session is
            // reverted, discarding it.
            unwind_create_token(stores, contract, tron_contract_addr.as_bytes(), top_level_token);
            return (
                VmOutcome::PreflightError(format!("TxEnv build: {e:?}")),
                Vec::new(),
                0,
            )
        }
    };

    let exec = match evm.inspect_tx_commit(tx) {
        Ok(r) => r,
        Err(e) => {
            unwind_create_token(stores, contract, tron_contract_addr.as_bytes(), top_level_token);
            let energy_penalty = evm.inspector.energy_penalty_total();
            let traces = evm.inspector.into_internal_txs();
            return (VmOutcome::PreflightError(format!("{e:?}")), traces, energy_penalty);
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
            // EIP-3541 (allowTvmLondon): deployed runtime code may not begin
            // with the 0xEF byte. java VMActuator throws InvalidCodeException →
            // spendAllEnergy → failure. Nested CREATE/CREATE2 are covered by
            // revm's CreateContractStartingWithEF; this guards the top-level
            // manual deposit path. Both this and the code-deposit OOG spend all
            // energy and discard the pre-installed account.
            let ef_invalid =
                proposals.allow_tvm_london && runtime_code.first() == Some(&0xEF);
            if total_with_deposit > energy_limit || ef_invalid {
                // Reverse the up-front TRC-10 transfer (restore the caller's
                // asset_v2) before dropping the pre-installed account, so a
                // failed deploy moves no token — matching java's discarded
                // rootRepository deposit.
                unwind_create_token(stores, contract, tron_contract_addr.as_bytes(), top_level_token);
                stores
                    .accounts
                    .delete(&tron_contract_addr)
                    .expect("db error in execute_create cleaning up after failed deployment");
                VmOutcome::Halt {
                    reason: if ef_invalid {
                        "deployed runtime code starts with 0xEF (EIP-3541)".to_string()
                    } else {
                        format!(
                            "out of gas charging code-deposit ({} bytes × 200 = {} gas; \
                             {} already used, budget {})",
                            runtime_code.len(),
                            deposit_cost,
                            already_used,
                            energy_limit
                        )
                    },
                    // java VMActuator: the EF-prefixed runtime throws
                    // `InvalidCodeException` (line ~204-207) → INVALID_CODE; the
                    // code-deposit shortfall throws `notEnoughSpendEnergy`
                    // (line ~209-216) → OUT_OF_ENERGY.
                    result: if ef_invalid {
                        tron_proto::transaction::result::ContractResult::InvalidCode
                    } else {
                        tron_proto::transaction::result::ContractResult::OutOfEnergy
                    },
                    energy_used: energy_limit,
                }
            } else {
                // java-tron derives the STORED deployed code differently across
                // ALLOW_TVM_CONSTANTINOPLE (proposal #26, mainnet ~block 5.89M):
                //  - post-Constantinople (VMActuator.java:219-221): the init-code
                //    RETURN value (`getHReturn()`), saved post-execution.
                //  - pre-Constantinople (VMActuator.java:433-435): the STATIC
                //    `ProgramPrecompile.getCode(initCode)` computed at DEPLOY
                //    time from the init bytecode (NOT the executed return).
                // Energy (`runtime_code.len() * 200`) and the EF/OOG checks above
                // always use the RETURN value in BOTH eras (matching java
                // VMActuator.java:203,209) — only the STORED bytes branch here.
                let stored_code: Vec<u8> = if proposals.allow_tvm_constantinople {
                    runtime_code.clone()
                } else {
                    program_precompile_get_code(init_code)
                };
                let runtime_hash = if stored_code.is_empty() {
                    vec![]
                } else {
                    tron_crypto::hash::keccak256(&stored_code).to_vec()
                };
                if !stored_code.is_empty() {
                    // Deployed code keyed by ADDRESS (overwrites the init code
                    // pre-installed at the same key), matching java-tron.
                    stores
                        .code
                        .put(tron_contract_addr.as_bytes(), &stored_code)
                        .expect("db error in execute_create writing runtime code");
                }
                // Replace init code on the Account with the deployed code, and
                // mark it a contract account. java-tron VMActuator:
                // `createAccount(addr, newSmartContract.getName(), Contract)` —
                // the account carries the DECLARED contract name (not
                // "CreatedByContract", which is the nested-create marker) and
                // `AccountType.Contract` (consensus-relevant: TransferActuator
                // rejects plain TRX transfers to Contract-type accounts).
                if let Ok(Some(mut acct)) = stores.accounts.get(&tron_contract_addr) {
                    acct.code = stored_code;
                    acct.code_hash = runtime_hash.clone();
                    acct.r#type = tron_proto::AccountType::Contract as i32;
                    if acct.account_name.is_empty() {
                        acct.account_name = smart_contract.name.clone().into_bytes();
                    }
                    stores
                        .accounts
                        .put(&tron_contract_addr, &acct)
                        .expect("db error in execute_create finalizing contract account");
                }
                // Persist the `SmartContract` row + ABI. java-tron
                // `rootRepository.createContract(addr, ContractCapsule(newSmartContract))`
                // where `newSmartContract` is the tx's `new_contract` with
                // `contractAddress` set and `version` per ALLOW_TVM_COMPATIBLE_EVM
                // (currently OFF on mainnet → version stays as sent, 0). Without
                // this the later energy split (origin / consumeUserResourcePercent
                // / originEnergyLimit) degenerates and `getcontract` returns null.
                // `ContractStore::put` strips the ABI; we store it separately.
                if let Some(contracts) = &stores.contracts {
                    let mut row = smart_contract.clone();
                    row.contract_address = tron_contract_addr.as_bytes().to_vec();
                    // ALLOW_TVM_COMPATIBLE_EVM is OFF on mainnet → java
                    // `clearVersion()` (version 0); don't let a tx-supplied
                    // version persist (it would also flip the storage layout).
                    row.version = 0;
                    // java `RepositoryImpl.saveCode` (reached from
                    // `VMActuator` after init code returns, ALLOW_TVM_CONSTANTINOPLE
                    // ON on mainnet) eagerly sets the contract row's
                    // `code_hash = Hash.sha3(code)` = keccak256(runtime_code).
                    // `runtime_hash` above is exactly that. No VM impact
                    // (EXTCODEHASH recomputes from the code bytes) — state-byte
                    // + `getcontract` RPC fidelity.
                    row.code_hash = runtime_hash.clone();
                    contracts
                        .put(&tron_contract_addr, &row)
                        .expect("db error in execute_create writing contract row");
                }
                if let (Some(abi_store), Some(abi)) = (&stores.abi, &smart_contract.abi) {
                    abi_store
                        .put(&tron_contract_addr, abi)
                        .expect("db error in execute_create writing contract abi");
                }
                VmOutcome::Success {
                    return_data: tron_contract_addr.as_bytes().to_vec(),
                    energy_used: total_with_deposit,
                    logs: collect_vm_logs(logs),
                }
            }
        }
        ExecutionResult::Revert { output, gas, .. } => {
            // Init code reverted — reverse the up-front TRC-10 transfer and
            // clean up the pre-installed Account so deployment doesn't leak.
            unwind_create_token(stores, contract, tron_contract_addr.as_bytes(), top_level_token);
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
            unwind_create_token(stores, contract, tron_contract_addr.as_bytes(), top_level_token);
            stores
                .accounts
                .delete(&tron_contract_addr)
                .expect("db error in execute_create cleaning up after Halt");
            VmOutcome::Halt {
                reason: format!("{reason:?}"),
                result: halt_reason_to_contract_result(&reason),
                energy_used: gas.tx_gas_used(),
            }
        }
    };
    let energy_penalty = evm.inspector.energy_penalty_total();
    let traces = evm.inspector.into_internal_txs();
    (vm_outcome, traces, energy_penalty)
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

#[cfg(test)]
mod halt_result_tests {
    use super::halt_reason_to_contract_result;
    use revm::context_interface::result::{HaltReason, OutOfGasError};
    use tron_proto::transaction::result::ContractResult;

    /// `RuntimeImpl.setResultCode` parity: every revm `HaltReason` must map to
    /// java-tron's specific `contractResult`, and unmapped halts to UNKNOWN.
    #[test]
    fn maps_each_halt_to_javas_contract_result() {
        // OutOfGas sub-kinds -> OUT_OF_ENERGY (OutOfEnergyException), EXCEPT the
        // two memory-overflow kinds (`MemoryLimit`, `InvalidOperand`), which are
        // java's `OutOfMemoryException` -> OUT_OF_MEMORY (asserted below).
        for oog in [
            OutOfGasError::Basic,
            OutOfGasError::Memory,
            OutOfGasError::Precompile,
            OutOfGasError::ReentrancySentry,
        ] {
            assert_eq!(
                halt_reason_to_contract_result(&HaltReason::OutOfGas(oog)),
                ContractResult::OutOfEnergy,
                "OutOfGas({oog:?}) must map to OUT_OF_ENERGY"
            );
        }

        // Both memory-overflow halts are java's `EnergyCost.checkMemorySize`
        // `OutOfMemoryException` -> OUT_OF_MEMORY (a too-large memory operand,
        // whether it fits usize but exceeds the 3 MiB cap, or trips
        // `as_usize_or_fail`), NOT OUT_OF_ENERGY.
        for oog in [OutOfGasError::MemoryLimit, OutOfGasError::InvalidOperand] {
            assert_eq!(
                halt_reason_to_contract_result(&HaltReason::OutOfGas(oog)),
                ContractResult::OutOfMemory,
                "OutOfGas({oog:?}) must map to OUT_OF_MEMORY"
            );
        }

        // Unknown / disabled / designated-invalid opcode → ILLEGAL_OPERATION.
        assert_eq!(
            halt_reason_to_contract_result(&HaltReason::OpcodeNotFound),
            ContractResult::IllegalOperation
        );
        assert_eq!(
            halt_reason_to_contract_result(&HaltReason::InvalidFEOpcode),
            ContractResult::IllegalOperation
        );

        // Jump / stack faults.
        assert_eq!(
            halt_reason_to_contract_result(&HaltReason::InvalidJump),
            ContractResult::BadJumpDestination
        );
        assert_eq!(
            halt_reason_to_contract_result(&HaltReason::StackUnderflow),
            ContractResult::StackTooSmall
        );
        assert_eq!(
            halt_reason_to_contract_result(&HaltReason::StackOverflow),
            ContractResult::StackTooLarge
        );

        // Precompile faults (unit + with-context) → PRECOMPILED_CONTRACT.
        assert_eq!(
            halt_reason_to_contract_result(&HaltReason::PrecompileError),
            ContractResult::PrecompiledContract
        );
        assert_eq!(
            halt_reason_to_contract_result(&HaltReason::PrecompileErrorWithContext(
                "boom".to_string()
            )),
            ContractResult::PrecompiledContract
        );

        // Anything java has no dedicated code for → UNKNOWN (java fall-through).
        for unmapped in [
            HaltReason::OutOfOffset,
            HaltReason::StateChangeDuringStaticCall,
            HaltReason::CallNotAllowedInsideStatic,
            HaltReason::CreateCollision,
            HaltReason::NonceOverflow,
            HaltReason::CreateContractSizeLimit,
            HaltReason::CreateInitCodeSizeLimit,
            HaltReason::NotActivated,
            HaltReason::OverflowPayment,
            HaltReason::OutOfFunds,
            HaltReason::CallTooDeep,
        ] {
            assert_eq!(
                halt_reason_to_contract_result(&unmapped),
                ContractResult::Unknown,
                "{unmapped:?} must fall through to UNKNOWN"
            );
        }
    }
}

#[cfg(test)]
mod chain_id_tests {
    use super::chain_id_from_genesis;

    /// Mainnet ground truth: the genesis block id is
    /// `00000000000000001ebf88508a03865c71d452e25f4d51194196a1d22b6653dc`; java
    /// `Program.getChainId` truncates to the last 4 bytes (ALLOW_OPTIMIZED…/
    /// ALLOW_TVM_COMPATIBLE_EVM active on mainnet) → `0x2b6653dc` (728126428),
    /// the value every TRON EIP-712 signature folds into its domain separator.
    #[test]
    fn mainnet_chain_id_is_genesis_last_four_bytes() {
        let mut genesis = [0u8; 32];
        for (i, byte) in genesis.iter_mut().enumerate() {
            let s = "00000000000000001ebf88508a03865c71d452e25f4d51194196a1d22b6653dc";
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        assert_eq!(chain_id_from_genesis(&genesis), 0x2b6653dc);
        assert_eq!(chain_id_from_genesis(&genesis), 728126428);
    }

    /// VM-2: pre-#60/#71 the CHAINID word is the FULL 32-byte genesis id; once
    /// ALLOW_TVM_COMPATIBLE_EVM (#60) / ALLOW_OPTIMIZED_RETURN_VALUE_OF_CHAIN_ID
    /// (#71) is active it truncates to the last 4 bytes (mainnet 0x2b6653dc).
    #[test]
    fn chain_id_word_full_pre_60_then_truncated() {
        use super::chain_id_word_from_genesis;
        use revm::primitives::U256;
        let mut genesis = [0u8; 32];
        let s = "00000000000000001ebf88508a03865c71d452e25f4d51194196a1d22b6653dc";
        for (i, byte) in genesis.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        // Post-#60/#71 (mainnet snapshot): truncated to the last 4 bytes.
        assert_eq!(
            chain_id_word_from_genesis(&genesis, true),
            U256::from(0x2b6653dc_u64)
        );
        // Istanbul..#60 window: the FULL 32-byte genesis id.
        assert_eq!(
            chain_id_word_from_genesis(&genesis, false),
            U256::from_be_bytes(genesis)
        );
        assert_ne!(
            chain_id_word_from_genesis(&genesis, false),
            chain_id_word_from_genesis(&genesis, true),
            "the full genesis id must differ from the 4-byte truncation"
        );
    }
}

#[cfg(test)]
mod address_derivation_tests {
    use super::derive_top_level_contract_address;

    fn hex21(s: &str) -> [u8; 21] {
        let v = hex_to_vec(s);
        let mut a = [0u8; 21];
        a.copy_from_slice(&v);
        a
    }
    fn hex_to_vec(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Mainnet ground truth: the deposit-shell factory `TEo47ugrPSLShwhZ…`
    /// (`4134ed0e191531d0410613527d3d491dda030d8b5c`) was deployed by creator
    /// `TPjPdMafdiYxyWdaGiMe2ZHjZsi85JmXMX`
    /// (`4196f4ceb72e6573a3e0042ecd6d2e6dacd4265e53`) in tx
    /// `9e3e34b3ab07c8b6918b7d1e84624895cd105a16d13817864e4721c90fcc8784`.
    /// `0x41 || sha3omit12(tx_id || owner)` must reproduce the on-chain address.
    #[test]
    fn top_level_create_matches_mainnet_ground_truth() {
        let mut tx_id = [0u8; 32];
        tx_id.copy_from_slice(&hex_to_vec(
            "9e3e34b3ab07c8b6918b7d1e84624895cd105a16d13817864e4721c90fcc8784",
        ));
        let owner = hex_to_vec("4196f4ceb72e6573a3e0042ecd6d2e6dacd4265e53");
        let got = derive_top_level_contract_address(&tx_id, &owner);
        assert_eq!(got, hex21("4134ed0e191531d0410613527d3d491dda030d8b5c"));
    }

    /// Owner-first (the old, wrong order) must NOT match — guards against a
    /// regression that swaps the operands back.
    #[test]
    fn owner_first_order_does_not_match() {
        let mut tx_id = [0u8; 32];
        tx_id.copy_from_slice(&hex_to_vec(
            "9e3e34b3ab07c8b6918b7d1e84624895cd105a16d13817864e4721c90fcc8784",
        ));
        let owner = hex_to_vec("4196f4ceb72e6573a3e0042ecd6d2e6dacd4265e53");
        // Reconstruct the old owner-first hash and confirm it differs.
        let mut wrong = Vec::new();
        wrong.extend_from_slice(&owner);
        wrong.extend_from_slice(&tx_id);
        let h = tron_crypto::hash::keccak256(&wrong);
        let mut wrong_addr = [0u8; 21];
        wrong_addr[0] = 0x41;
        wrong_addr[1..].copy_from_slice(&h[12..]);
        assert_ne!(wrong_addr, hex21("4134ed0e191531d0410613527d3d491dda030d8b5c"));
    }
}

#[cfg(test)]
mod program_precompile_tests {
    use super::program_precompile_get_code;

    // Byte-for-byte against java `ProgramPrecompile.getCode` (pre-#26 deploy
    // code derivation). RETURN=0xf3, STOP=0x00, PUSH1=0x60, PUSH2=0x61.

    #[test]
    fn extracts_bytes_after_first_return_stop() {
        // PUSH1 0x01 ; RETURN ; STOP ; <runtime>
        let init = [0x60, 0x01, 0xf3, 0x00, 0xde, 0xad, 0xbe, 0xef];
        assert_eq!(program_precompile_get_code(&init), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn typical_constructor_without_trailing_stop_falls_back_to_word() {
        // A normal constructor ends with RETURN and NO following STOP → java
        // returns a 32-byte zero word (DataWord.WORD_SIZE) pre-Constantinople.
        let init = [0x60, 0x20, 0x60, 0x00, 0xf3];
        assert_eq!(program_precompile_get_code(&init), vec![0u8; 32]);
    }

    #[test]
    fn push_immediates_are_not_scanned_as_opcodes() {
        // PUSH2 carries 0xf3 0x00 as DATA (must not match RETURN;STOP); the real
        // RETURN;STOP follows and yields the trailing 0x42.
        let init = [0x61, 0xf3, 0x00, 0xf3, 0x00, 0x42];
        assert_eq!(program_precompile_get_code(&init), vec![0x42]);
    }

    #[test]
    fn return_stop_at_end_yields_empty() {
        let init = [0x60, 0x00, 0xf3, 0x00];
        assert_eq!(program_precompile_get_code(&init), Vec::<u8>::new());
    }

    #[test]
    fn empty_input_falls_back_to_word() {
        assert_eq!(program_precompile_get_code(&[]), vec![0u8; 32]);
    }

    #[test]
    fn trailing_push_past_end_falls_back_without_panic() {
        // PUSH32 near the end claims more immediate bytes than remain — must not
        // panic, and finds no RETURN;STOP → fallback.
        let init = [0x60, 0x01, 0x7f, 0xf3, 0x00];
        assert_eq!(program_precompile_get_code(&init), vec![0u8; 32]);
    }
}
