use crate::{interpreter_types::InputsTr, CallInput};
use primitives::{Address, U256};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Inputs for the interpreter that are used for execution of the call.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InputsImpl {
    /// Storage of this account address is being used.
    pub target_address: Address,
    /// Address of the bytecode that is being executed. This field is not used inside Interpreter but it is used
    /// by dependent projects that would need to know the address of the bytecode.
    pub bytecode_address: Option<Address>,
    /// Address of the caller of the call.
    pub caller_address: Address,
    /// Input data for the call.
    pub input: CallInput,
    /// Value of the call.
    pub call_value: U256,
    // ====================================================================
    // TRON fork extension. Populated when the parent frame was a
    // `CALLTOKEN` (0xd0); read by `CALLTOKENVALUE` (0xd2) /
    // `CALLTOKENID` (0xd3) inside the callee frame. Zero for every
    // standard CALL / CREATE / top-of-tx invocation.
    // ====================================================================
    /// TRC-10 token id from the originating CALLTOKEN.
    pub tron_token_id: i64,
    /// TRC-10 token value from the originating CALLTOKEN.
    pub tron_token_value: i64,
    /// **TRON fork** — per-contract dynamic-energy factor for *this*
    /// frame's target. Multiplies every gas charge by `(10_000 + f) /
    /// 10_000`. Read by `Interpreter::clear` which forwards it to the
    /// `Gas` tracker before the first opcode runs. Default `0` = no
    /// penalty (zero-overhead path).
    pub tron_dynamic_factor: i64,
    /// **TRON fork** — the deployed `SmartContract.version` (0 or 1) of the
    /// contract whose code *this* frame executes (java `Program.contractVersion`,
    /// `getContractVersion()`). Set when the frame is built: a CALL child gets
    /// the callee/bytecode address's stored version (`Program.java:1146`); a
    /// CREATE child inherits the parent's (`Program.java:915`); a top-level
    /// CREATE is forced to 1 (`VMActuator.java:415`). java gates the EIP-150
    /// 1/64 gas retention (`getCallEnergy`/`getCreateEnergy`) and the GASPRICE
    /// push (`gasPriceAction`) on `allowTvmCompatibleEvm() && version == 1`.
    /// Default `0` (legacy contract / non-TRON host).
    pub tron_contract_version: i32,
}

impl InputsTr for InputsImpl {
    fn target_address(&self) -> Address {
        self.target_address
    }

    fn caller_address(&self) -> Address {
        self.caller_address
    }

    fn bytecode_address(&self) -> Option<&Address> {
        self.bytecode_address.as_ref()
    }

    fn input(&self) -> &CallInput {
        &self.input
    }

    fn call_value(&self) -> U256 {
        self.call_value
    }

    fn tron_token_id(&self) -> i64 {
        self.tron_token_id
    }

    fn tron_token_value(&self) -> i64 {
        self.tron_token_value
    }

    fn tron_contract_version(&self) -> i32 {
        self.tron_contract_version
    }
}
