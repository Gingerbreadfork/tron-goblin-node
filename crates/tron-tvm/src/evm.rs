//! EVM glue — wires our [`PrecompileImpl`] registry into revm via the
//! [`PrecompileProvider`] extension point, and provides a builder that
//! produces a fully-configured `MainnetEvm` ready to execute TRON
//! transactions.
//!
//! The standard Ethereum precompiles at addresses `0x01..=0x08` flow
//! through revm's built-in [`EthPrecompiles`]. TRON-specific addresses
//! (`0x09`, `0x0a`, `0x01000005..0x01000015`, plus the
//! Ethereum-compat extras `0x0002_0003`, `0x0002_0009`, `0x0000_0100`)
//! route into [`PrecompileImpl::execute`] with a [`TronEvmContext`]
//! that wraps the chainbase stores.
//!
//! What we don't do here:
//! * **CALLTOKEN opcode** — needs an `EthInstructions` extension (revm's
//!   opcode table customization). Stubbed for a follow-up; the
//!   precompile registry is fully usable today.
//!
//! Per-contract dynamic-energy enforcement at the opcode level IS wired:
//! `Trc10Inspector::initialize_interp` reads the callee's factor from
//! `ContractStateStore` and installs it on the frame's `Gas` tracker
//! before the first opcode runs, gated by `ALLOW_DYNAMIC_ENERGY` in
//! `execute.rs::dynamic_energy_active`. See
//! `crates/tron-tvm/tests/dynamic_energy.rs` for the 2×/+50% proof.

use std::sync::Arc;

use revm::context::{Cfg, ContextTr};
use revm::handler::{precompile_output_to_interpreter_result, EthPrecompiles, PrecompileProvider};
use revm::interpreter::{CallInputs, InterpreterResult};
use revm::precompile::{PrecompileOutput, PrecompileSpecId, PrecompileStatus};
use revm::primitives::{
    hardfork::SpecId, Address as EvmAddress, AddressSet, Bytes,
};

/// TRON-specific EVM opcodes outside the standard Ethereum range.
/// Pinned from java-tron's `org.tron.core.vm.OpCode`.
pub mod opcode {
    pub const SELFDESTRUCT: u8 = 0xff;
    pub const CALLTOKEN: u8 = 0xd0;
    pub const TOKENBALANCE: u8 = 0xd1;
    pub const CALLTOKENVALUE: u8 = 0xd2;
    pub const CALLTOKENID: u8 = 0xd3;
    pub const ISCONTRACT: u8 = 0xd4;
    // Stake 1.0
    pub const FREEZE: u8 = 0xd5;
    pub const UNFREEZE: u8 = 0xd6;
    pub const FREEZEEXPIRETIME: u8 = 0xd7;
    pub const VOTEWITNESS: u8 = 0xd8;
    pub const WITHDRAWREWARD: u8 = 0xd9;
    // Stake 2.0
    pub const FREEZEBALANCEV2: u8 = 0xda;
    pub const UNFREEZEBALANCEV2: u8 = 0xdb;
    pub const CANCELALLUNFREEZEV2: u8 = 0xdc;
    pub const WITHDRAWEXPIREUNFREEZE: u8 = 0xdd;
    pub const DELEGATERESOURCE: u8 = 0xde;
    pub const UNDELEGATERESOURCE: u8 = 0xdf;
}
use tron_chainbase::{
    AccountStore, ContractStateStore, DelegatedResourceStore, DelegationStore,
    DynamicPropertiesStore, WitnessStore,
};
use tron_crypto::address::Address as TronAddress;

use crate::context::{EvmContext, EvmContextError};
use crate::database::evm_to_tron_address;
use crate::precompiles::{PrecompileError, PrecompileImpl};

/// Stores + per-call data needed to execute the TRON precompiles.
/// Constructed fresh for every revm call into a TRON precompile so the
/// `caller` / `callee` reflect the current frame.
struct TronEvmContext {
    accounts: Arc<AccountStore>,
    witnesses: Arc<WitnessStore>,
    contract_state: Arc<ContractStateStore>,
    dynamic_properties: Arc<DynamicPropertiesStore>,
    delegated_resources: Arc<DelegatedResourceStore>,
    delegation: Arc<DelegationStore>,
    reward_vi: Option<Arc<tron_chainbase::RewardViStore>>,
    caller: TronAddress,
    callee: TronAddress,
    block_number: i64,
    block_timestamp_ms: i64,
}

impl EvmContext for TronEvmContext {
    fn caller(&self) -> TronAddress {
        self.caller
    }
    fn callee(&self) -> TronAddress {
        self.callee
    }
    fn get_account(
        &self,
        address: &TronAddress,
    ) -> Result<Option<tron_proto::Account>, EvmContextError> {
        Ok(self.accounts.get(address)?)
    }
    fn get_witness(
        &self,
        address: &TronAddress,
    ) -> Result<Option<tron_proto::Witness>, EvmContextError> {
        Ok(self.witnesses.get(address)?)
    }
    fn chain_parameter_long(&self, key: &[u8]) -> Result<Option<i64>, EvmContextError> {
        // Returns Ok(None) if the key isn't set. We use the public
        // `get_long` accessor that DynamicPropertiesStore exposes.
        Ok(self.dynamic_properties.get_long(key))
    }
    fn block_number(&self) -> i64 {
        self.block_number
    }
    fn block_timestamp_ms(&self) -> i64 {
        self.block_timestamp_ms
    }
    fn all_witnesses(&self) -> Result<Vec<tron_proto::Witness>, EvmContextError> {
        Ok(self
            .witnesses
            .all()?
            .into_iter()
            .map(|(_, w)| w)
            .collect())
    }
    fn get_delegated_resource(
        &self,
        from: &TronAddress,
        to: &TronAddress,
    ) -> Result<Option<tron_proto::DelegatedResource>, EvmContextError> {
        // DelegatedResourceStore uses a `from || to` composite key.
        // We try v2 unlocked first (the common modern case); a fuller
        // resolver would also try v2 locked + v1 in order, but for the
        // precompiles that read this (CheckUnDelegateResource), v2
        // unlocked is what java-tron consults first.
        let key = tron_chainbase::DelegatedResourceStore::v2_unlocked_key(from, to);
        Ok(self.delegated_resources.get_raw(&key)?)
    }
    fn dynamic_energy_factor(&self, contract: &TronAddress) -> Result<i64, EvmContextError> {
        Ok(self.contract_state.dynamic_energy_factor(contract)?)
    }
    fn query_reward(&self, voter: &TronAddress) -> Result<i64, EvmContextError> {
        Ok(crate::reward::query_reward(
            voter,
            &self.accounts,
            &self.delegation,
            &self.dynamic_properties,
            self.reward_vi.as_deref(),
        )?)
    }
}

/// `PrecompileProvider` implementation that dispatches the TRON-specific
/// addresses to [`PrecompileImpl::execute`] and falls back to revm's
/// built-in Ethereum precompiles for the rest.
pub struct TronPrecompiles {
    eth: EthPrecompiles,
    /// Warm addresses = standard precompiles ∪ TRON-specific precompiles.
    /// EIP-2929 access-list logic reads this so the addresses get the
    /// "already-warm" cold-access discount.
    warm: AddressSet,
    accounts: Arc<AccountStore>,
    witnesses: Arc<WitnessStore>,
    contract_state: Arc<ContractStateStore>,
    dynamic_properties: Arc<DynamicPropertiesStore>,
    delegated_resources: Arc<DelegatedResourceStore>,
    delegation: Arc<DelegationStore>,
    reward_vi: Option<Arc<tron_chainbase::RewardViStore>>,
    block_number: i64,
    block_timestamp_ms: i64,
    /// Per-tx hard-fork proposal snapshot. `dispatch_tron` consults
    /// this to gate each precompile by its java-tron `ALLOW_*` flag,
    /// matching `PrecompiledContracts.getContractForAddress`.
    proposals: crate::proposals::ProposalSet,
}

impl TronPrecompiles {
    pub fn new(
        spec: SpecId,
        accounts: Arc<AccountStore>,
        witnesses: Arc<WitnessStore>,
        contract_state: Arc<ContractStateStore>,
        dynamic_properties: Arc<DynamicPropertiesStore>,
        delegated_resources: Arc<DelegatedResourceStore>,
        delegation: Arc<DelegationStore>,
        block_number: i64,
        block_timestamp_ms: i64,
        proposals: crate::proposals::ProposalSet,
    ) -> Self {
        let eth = EthPrecompiles::new(spec);
        let mut warm = AddressSet::default();
        warm.clone_from(eth.warm_addresses());
        // Insert every TRON-specific precompile address. The standard
        // Ethereum addresses (0x01..0x08) are already in `warm` via
        // `eth`. Warm-listing addresses that turn out to be disabled
        // by proposal is harmless: it only affects EIP-2929
        // cold/warm gas pricing (a no-op for calls to addresses with
        // no precompile body and no deployed code).
        for p in crate::precompiles::ALL_PRECOMPILES {
            // Convert our 20-byte PrecompileAddress to revm's Address.
            let addr = EvmAddress::from_slice(&p.address());
            warm.insert(addr);
        }
        Self {
            eth,
            warm,
            accounts,
            witnesses,
            contract_state,
            dynamic_properties,
            delegated_resources,
            delegation,
            reward_vi: None,
            block_number,
            block_timestamp_ms,
            proposals,
        }
    }

    /// Attach the `reward-vi` store so the RewardBalance precompile's
    /// `query_reward` covers voters whose window predates the new
    /// reward algorithm (`ALLOW_OLD_REWARD_OPT` fast path).
    pub fn with_reward_vi(
        mut self,
        reward_vi: Option<Arc<tron_chainbase::RewardViStore>>,
    ) -> Self {
        self.reward_vi = reward_vi;
        self
    }

    /// Returns true iff the given TRON precompile is enabled under the
    /// active proposal set. Mirrors java-tron's
    /// `PrecompiledContracts.getContractForAddress` — every `if
    /// (VMConfig.allowXyz())` short-circuit becomes a row here. Standard
    /// EVM precompiles (0x01..0x08) are handled by the `eth` fallback
    /// and are NOT consulted here.
    fn precompile_enabled(&self, pre: PrecompileImpl) -> bool {
        use PrecompileImpl::*;
        match pre {
            // Standard EVM — handled by eth fallback, dispatch_tron
            // already filters these out earlier. Treat as always-on so
            // future use of this method is safe.
            EcRecover | Sha256 | Ripemd160 | Identity | ModExp | Bn128Add | Bn128Mul
            | Bn128Pairing => true,
            // TRON multi-sig — both behind ALLOW_TVM_SOLIDITY_059.
            BatchValidateSign | ValidateMultiSign => self.proposals.allow_tvm_solidity_059,
            // Shielded — behind ALLOW_SHIELDED_TRC20_TRANSACTION.
            VerifyMintProof | VerifyTransferProof | VerifyBurnProof | MerkleHash => {
                self.proposals.allow_shielded_trc20_transaction
            }
            // Vote / SR queries — behind ALLOW_TVM_VOTE.
            RewardBalance | IsSrCandidate | VoteCount | UsedVoteCount | ReceivedVoteCount
            | TotalVoteCount => self.proposals.allow_tvm_vote,
            // FreezeV2 / chain queries — behind ALLOW_TVM_FREEZE_V2.
            // `GetChainParameter` ships with the v2 batch in
            // `PrecompiledContracts.java:300` (`if
            // (VMConfig.allowTvmFreezeV2())` covers the whole block).
            GetChainParameter | AvailableUnfreezeV2Size | UnfreezableBalanceV2
            | ExpireUnfreezeBalanceV2 | DelegatableResource | ResourceV2
            | CheckUnDelegateResource | ResourceUsage | TotalResource
            | TotalDelegatedResource | TotalAcquiredResource => {
                self.proposals.allow_tvm_freeze_v2
            }
            // Ethereum-compat extras — behind ALLOW_TVM_COMPATIBLE_EVM.
            EthRipemd160 | Blake2F => self.proposals.allow_tvm_compatible_evm,
            // P256Verify ships with ALLOW_TVM_OSAKA in java-tron. We
            // don't model OSAKA on the spec resolver yet (TRON's Osaka
            // proposal isn't activated on any live chain), so we hide
            // P256Verify entirely until that proposal lands. Treat as
            // off → falls through to an EOA-like call (no precompile
            // dispatch), matching java-tron's `getContractForAddress`
            // returning null.
            P256Verify => self.proposals.allow_tvm_osaka,
        }
    }

    /// Try to dispatch the call to a TRON-specific precompile. Returns
    /// `Some(result)` if the address matches a TRON precompile, `None`
    /// otherwise. Standard EVM precompiles 0x01..0x08 always return
    /// `None` here because they're handled by the `eth` fallback.
    fn dispatch_tron(&self, inputs: &CallInputs, input_bytes: &[u8]) -> Option<InterpreterResult> {
        let pre_addr: [u8; 20] = inputs.bytecode_address.into();
        let pre = PrecompileImpl::from_address(&pre_addr)?;

        // Standard EVM precompiles report `HandledByInterpreter` from
        // our registry — defer to the `eth` fallback for those.
        if matches!(
            pre,
            PrecompileImpl::EcRecover
                | PrecompileImpl::Sha256
                | PrecompileImpl::Ripemd160
                | PrecompileImpl::Identity
                | PrecompileImpl::ModExp
                | PrecompileImpl::Bn128Add
                | PrecompileImpl::Bn128Mul
                | PrecompileImpl::Bn128Pairing
                | PrecompileImpl::EthRipemd160
        ) {
            return None;
        }

        // Per-tx proposal gating. A call to a TRON-precompile address
        // whose `ALLOW_*` proposal is off must NOT dispatch — fall
        // through (`None`) so revm treats it as a plain CALL to an EOA
        // (success, empty return). Matches java-tron's
        // `PrecompiledContracts.getContractForAddress` returning null
        // when the gate is off.
        if !self.precompile_enabled(pre) {
            return None;
        }

        let ctx = TronEvmContext {
            accounts: Arc::clone(&self.accounts),
            witnesses: Arc::clone(&self.witnesses),
            contract_state: Arc::clone(&self.contract_state),
            dynamic_properties: Arc::clone(&self.dynamic_properties),
            delegated_resources: Arc::clone(&self.delegated_resources),
            delegation: Arc::clone(&self.delegation),
            reward_vi: self.reward_vi.clone(),
            caller: evm_to_tron_address(&inputs.caller),
            callee: evm_to_tron_address(&inputs.target_address),
            block_number: self.block_number,
            block_timestamp_ms: self.block_timestamp_ms,
        };

        // Compute the effective energy cost (incl. dynamic-energy penalty).
        let energy_cost = match pre.effective_energy_cost(input_bytes, &ctx) {
            Ok(g) => g,
            Err(_) => {
                return Some(make_halt(inputs.gas_limit, "energy overflow"));
            }
        };

        let exec_result = pre.execute(input_bytes, &ctx);
        let (status, bytes, gas_used) = match exec_result {
            Ok(out) => (PrecompileStatus::Success, Bytes::from(out), energy_cost),
            Err(PrecompileError::NotImplemented(_))
            | Err(PrecompileError::HandledByInterpreter) => {
                // Shouldn't reach HandledByInterpreter (caught above), but
                // be defensive.
                (PrecompileStatus::Revert, Bytes::new(), 0)
            }
            Err(_) => (PrecompileStatus::Revert, Bytes::new(), 0),
        };

        let output = PrecompileOutput {
            status,
            gas_used,
            gas_refunded: 0,
            state_gas_used: 0,
            reservoir: inputs.reservoir,
            bytes,
        };
        Some(precompile_output_to_interpreter_result(
            output,
            inputs.gas_limit,
        ))
    }
}

/// Install TRON-extended opcode handlers (0xd0..0xdf) into a revm
/// `EthInstructions` table, gating each opcode by its java-tron
/// proposal. Opcodes whose proposal is off are NOT installed — the
/// interpreter falls through to revm's default empty slot which halts
/// with `OpcodeNotFound`, matching java-tron's
/// `OperationRegistry`/`isEnabled` behavior.
///
/// Proposal-to-opcode mapping (mirrors
/// `actuator/.../vm/OperationRegistry.java`):
///
/// | Opcodes                                              | Proposal                       |
/// |------------------------------------------------------|--------------------------------|
/// | CALLTOKEN, TOKENBALANCE, CALLTOKENVALUE, CALLTOKENID | `ALLOW_TVM_TRANSFER_TRC10`     |
/// | ISCONTRACT                                           | `ALLOW_TVM_SOLIDITY_059`       |
/// | FREEZE, UNFREEZE, FREEZEEXPIRETIME                   | `ALLOW_TVM_FREEZE`             |
/// | VOTEWITNESS, WITHDRAWREWARD                          | `ALLOW_TVM_VOTE`               |
/// | FREEZEBALANCEV2, UNFREEZEBALANCEV2,                  | `ALLOW_TVM_FREEZE_V2`          |
/// | CANCELALLUNFREEZEV2, WITHDRAWEXPIREUNFREEZE,         |                                |
/// | DELEGATERESOURCE, UNDELEGATERESOURCE                 |                                |
///
/// Gas costs come from java-tron's `EnergyCost.java`. State-mutating
/// ops still no-op at the Host bridge (separate parity gap on the
/// actuator-primitive extraction) but enabling them now gates the
/// opcode existence correctly so contracts compiled against
/// e.g. Stake 1.0 don't run on a chain where the proposal is off.
pub fn install_tron_opcode_stubs<IT, H>(
    instructions: &mut revm::handler::instructions::EthInstructions<IT, H>,
    proposals: &crate::proposals::ProposalSet,
) where
    IT: revm::interpreter::InterpreterTypes,
    H: revm::interpreter::Host,
{
    use revm::interpreter::instructions::contract;
    use revm::interpreter::Instruction;

    // ---- SELFDESTRUCT (0xff) -- always the TRON variant ----
    //
    // java-tron's `suicideAction` / `suicideAction2`: chainbase
    // side-effects (reward settlement + vote cancellation, TRC-10 sweep,
    // frozen transfers -- each internally gated by its own proposal) +
    // `canSuicide` validation + the #94 destroy rule and SUICIDE_V2
    // energy. With every proposal off it degrades to the standard
    // pre-Cancun selfdestruct.
    instructions.insert_instruction(
        opcode::SELFDESTRUCT,
        Instruction::new(revm::interpreter::instructions::host::tron_selfdestruct::<IT, H>),
        0,
    );

    // ---- ALLOW_TVM_TRANSFER_TRC10 (0xd0..0xd3) ----
    if proposals.allow_tvm_transfer_trc10 {
        instructions.insert_instruction(
            opcode::CALLTOKEN,
            Instruction::new(contract::call_token::<IT, H>),
            0,
        );
        instructions.insert_instruction(
            opcode::TOKENBALANCE,
            Instruction::new(contract::token_balance::<IT, H>),
            700,
        );
        instructions.insert_instruction(
            opcode::CALLTOKENVALUE,
            Instruction::new(contract::call_token_value::<IT, H>),
            2,
        );
        instructions.insert_instruction(
            opcode::CALLTOKENID,
            Instruction::new(contract::call_token_id::<IT, H>),
            2,
        );
    }

    // ---- ALLOW_TVM_SOLIDITY_059 (0xd4) ----
    if proposals.allow_tvm_solidity_059 {
        instructions.insert_instruction(
            opcode::ISCONTRACT,
            Instruction::new(contract::is_contract::<IT, H>),
            700,
        );
    }

    // ---- ALLOW_TVM_FREEZE (Stake 1.0, 0xd5..0xd7) ----
    if proposals.allow_tvm_freeze {
        instructions.insert_instruction(
            opcode::FREEZE,
            Instruction::new(contract::freeze::<IT, H>),
            20_000,
        );
        instructions.insert_instruction(
            opcode::UNFREEZE,
            Instruction::new(contract::unfreeze::<IT, H>),
            20_000,
        );
        instructions.insert_instruction(
            opcode::FREEZEEXPIRETIME,
            Instruction::new(contract::freeze_expire_time::<IT, H>),
            50,
        );
    }

    // ---- ALLOW_TVM_VOTE (0xd8, 0xd9) ----
    if proposals.allow_tvm_vote {
        instructions.insert_instruction(
            opcode::VOTEWITNESS,
            Instruction::new(contract::vote_witness::<IT, H>),
            // java-tron computes `voteCount * BASE + array memory`; we
            // use the base. Real memory-charge applies inside the Host
            // once wired.
            30_000,
        );
        instructions.insert_instruction(
            opcode::WITHDRAWREWARD,
            Instruction::new(contract::withdraw_reward::<IT, H>),
            20_000,
        );
    }

    // ---- ALLOW_TVM_FREEZE_V2 (Stake 2.0, 0xda..0xdf) ----
    if proposals.allow_tvm_freeze_v2 {
        instructions.insert_instruction(
            opcode::FREEZEBALANCEV2,
            Instruction::new(contract::freeze_balance_v2::<IT, H>),
            10_000,
        );
        instructions.insert_instruction(
            opcode::UNFREEZEBALANCEV2,
            Instruction::new(contract::unfreeze_balance_v2::<IT, H>),
            10_000,
        );
        instructions.insert_instruction(
            opcode::CANCELALLUNFREEZEV2,
            Instruction::new(contract::cancel_all_unfreeze_v2::<IT, H>),
            10_000,
        );
        instructions.insert_instruction(
            opcode::WITHDRAWEXPIREUNFREEZE,
            Instruction::new(contract::withdraw_expire_unfreeze::<IT, H>),
            10_000,
        );
        instructions.insert_instruction(
            opcode::DELEGATERESOURCE,
            Instruction::new(contract::delegate_resource::<IT, H>),
            10_000,
        );
        instructions.insert_instruction(
            opcode::UNDELEGATERESOURCE,
            Instruction::new(contract::undelegate_resource::<IT, H>),
            10_000,
        );
    }

    // ---- BLOBHASH / BLOBBASEFEE override when ALLOW_TVM_BLOB is off ----
    //
    // revm installs BLOBHASH (0x49) and BLOBBASEFEE (0x4a) automatically
    // whenever the spec is CANCUN or later. java-tron splits these
    // behind `ALLOW_TVM_BLOB` (separate from `ALLOW_TVM_CANCUN`). When
    // CANCUN is on but BLOB is off, force the two opcodes back to
    // `OpcodeNotFound` so contracts using them halt the same way they
    // would on java-tron.
    if proposals.allow_tvm_cancun && !proposals.allow_tvm_blob {
        use revm::interpreter::instructions::control;
        // 0x49 BLOBHASH and 0x4a BLOBBASEFEE — gas table entries stay 0
        // because the unknown handler halts before any charge.
        instructions.insert_instruction(0x49, Instruction::new(control::unknown::<IT, H>), 0);
        instructions.insert_instruction(0x4a, Instruction::new(control::unknown::<IT, H>), 0);
    }
}

fn make_halt(gas_limit: u64, _msg: &'static str) -> InterpreterResult {
    let output = PrecompileOutput {
        status: PrecompileStatus::Revert,
        gas_used: gas_limit,
        gas_refunded: 0,
        state_gas_used: 0,
        reservoir: 0,
        bytes: Bytes::new(),
    };
    precompile_output_to_interpreter_result(output, gas_limit)
}

impl<CTX> PrecompileProvider<CTX> for TronPrecompiles
where
    CTX: ContextTr<Cfg: Cfg<Spec = SpecId>>,
{
    type Output = InterpreterResult;

    fn set_spec(&mut self, spec: <CTX::Cfg as Cfg>::Spec) -> bool {
        let spec: SpecId = spec.into();
        let changed = <EthPrecompiles as PrecompileProvider<CTX>>::set_spec(&mut self.eth, spec);
        // Rebuild warm set since standard precompile set may have changed.
        self.warm.clone_from(self.eth.warm_addresses());
        for p in crate::precompiles::ALL_PRECOMPILES {
            let addr = EvmAddress::from_slice(&p.address());
            self.warm.insert(addr);
        }
        // Suppress the `spec` variable - PrecompileSpecId::from_spec_id is internal
        // use only and not needed here; just acknowledge it for the API contract.
        let _ = PrecompileSpecId::from_spec_id(spec);
        changed
    }

    fn run(
        &mut self,
        context: &mut CTX,
        inputs: &CallInputs,
    ) -> Result<Option<Self::Output>, std::string::String> {
        // Resolve the calldata into a byte slice once; both branches need it.
        let input_bytes_owned: Bytes = match &inputs.input {
            revm::interpreter::CallInput::Bytes(b) => b.clone(),
            revm::interpreter::CallInput::SharedBuffer(_) => {
                // Defer to revm's helper that resolves shared-buffer
                // calldata against the local context. We need the
                // resolved bytes; ask revm for them via the same path
                // the standard precompiles use.
                let owned: Vec<u8> = inputs.input.as_bytes(context).to_vec();
                Bytes::from(owned)
            }
        };

        // First try TRON-specific dispatch.
        if let Some(result) = self.dispatch_tron(inputs, &input_bytes_owned) {
            return Ok(Some(result));
        }

        // Fall through to standard Ethereum precompiles.
        <EthPrecompiles as PrecompileProvider<CTX>>::run(&mut self.eth, context, inputs)
    }

    fn warm_addresses(&self) -> &AddressSet {
        &self.warm
    }
}
