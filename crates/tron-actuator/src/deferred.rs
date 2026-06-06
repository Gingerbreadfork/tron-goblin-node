//! Stub for the one VM contract path the actuator layer can't service:
//! *execution*.
//!
//! **`VMActuator`** (handles `CreateSmartContract` / `TriggerSmartContract`)
//! is executed in `tron-executor::execute_vm_tx`, not the dispatcher. The
//! executor bypasses `dispatch_execute` for VM-bound contracts and builds a
//! `tron_tvm::execute::VmStores` directly from session backends. The stub
//! below is only reached if something calls `dispatch_execute` on a
//! smart-contract type without going through the executor — a misuse, since
//! the EVM needs `code`, `storage_row`, `contract_state`, and `block_index`
//! stores that `ActuatorStores` doesn't carry.
//!
//! *Validation* (the admission-time precondition gate) does NOT need those
//! stores and is implemented in [`crate::vm`]; `dispatch_validate` routes
//! VM types there. Only `execute` remains stubbed.
//!
//! `ShieldedTransferContract` is NOT stubbed — `dispatch.rs` calls
//! `crate::shielded_transfer::{validate,execute}_shielded_transfer`
//! directly, passing the sighash via `ActuatorTxCtx`.

use crate::transfer::ExecutionResult;
use crate::ActuatorError;

pub fn execute_vm() -> Result<ExecutionResult, ActuatorError> {
    Err(ActuatorError::NotImplemented(
        "VMActuator routed via tron-executor::execute_vm_tx; call sites \
         must use that path, not dispatch_execute",
    ))
}
