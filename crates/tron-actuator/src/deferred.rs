//! Stub used by the dispatcher for one contract-type family that the
//! actuator-layer entry point can't safely service:
//!
//! * **`VMActuator`** (handles `CreateSmartContract` /
//!   `TriggerSmartContract`) is wired in `tron-executor::execute_vm_tx`,
//!   not the dispatcher. The executor bypasses `dispatch_execute` for
//!   VM-bound contracts and constructs a `tron_tvm::execute::VmStores`
//!   directly from session backends. The stub below is only reached
//!   when something calls `dispatch_validate` / `dispatch_execute` on
//!   a smart-contract type without going through the executor — a
//!   misuse, since the EVM needs `code`, `storage_row`,
//!   `contract_state`, and `block_index` stores that
//!   `ActuatorStores` doesn't carry.
//!
//! `ShieldedTransferContract` is NOT stubbed here — `dispatch.rs`
//! calls `crate::shielded_transfer::{validate,execute}_shielded_transfer`
//! directly, passing the sighash via `ActuatorTxCtx`.

use crate::transfer::ExecutionResult;
use crate::ActuatorError;

pub fn validate_vm() -> Result<(), ActuatorError> {
    Err(ActuatorError::NotImplemented(
        "VMActuator routed via tron-executor::execute_vm_tx; call sites \
         must use that path, not dispatch_validate",
    ))
}

pub fn execute_vm() -> Result<ExecutionResult, ActuatorError> {
    Err(ActuatorError::NotImplemented(
        "VMActuator routed via tron-executor::execute_vm_tx; call sites \
         must use that path, not dispatch_execute",
    ))
}
