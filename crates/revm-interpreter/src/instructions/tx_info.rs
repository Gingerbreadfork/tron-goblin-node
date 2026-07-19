use crate::{
    interpreter_types::{InputsTr, InterpreterTypes as ITy, RuntimeFlag, StackTr},
    Host, InstructionContext as Ictx, InstructionExecResult as Result,
};
use context_interface::tron_address_word;
use primitives::U256;

/// Implements the GASPRICE instruction.
///
/// Gets the gas price of the originating transaction.
///
/// TRON fork: java's `gasPriceAction` (`OperationActions.java:431`) pushes
/// `DataWord.ZERO()` UNLESS `allowTvmCompatibleEvm() && getContractVersion()
/// == 1`, in which case it pushes `dynamicPropertiesStore.getEnergyFee()`
/// (the same value `baseFeeAction` pushes). A version-0 (legacy) frame, or the
/// flag being off (which forces version 0 on a top-level CREATE), pushes 0.
/// Ethereum-only hosts keep `effective_gas_price`.
pub fn gasprice<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    if context.host.tron_enabled() {
        let price = if context.host.tron_allow_tvm_compatible_evm()
            && context.interpreter.input.tron_contract_version() == 1
        {
            context.host.tron_energy_fee()
        } else {
            U256::ZERO
        };
        push!(context.interpreter, price);
        return Ok(());
    }
    push!(context.interpreter, context.host.effective_gas_price());
    Ok(())
}

/// Implements the ORIGIN instruction.
///
/// Gets the execution origination address.
pub fn origin<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    let word = context.host.caller().into_word();
    // TRON fork: java `originAction` masks the origin DataWord to 20 bytes only
    // once ALLOW_MULTI_SIGN is active, matching `addressAction`. The origin is
    // the 21-byte transaction owner and inner frames inherit it unchanged, so
    // pre-activation the prefix byte reaches the stack at every depth.
    let word = if context.host.tron_enabled() && !context.host.tron_allow_multi_sign() {
        tron_address_word(word)
    } else {
        word
    };
    push!(context.interpreter, word.into());
    Ok(())
}

/// Implements the BLOBHASH instruction.
///
/// EIP-4844: Shard Blob Transactions - gets the hash of a transaction blob.
pub fn blob_hash<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    check!(context.interpreter, CANCUN);
    popn_top!([], index, context.interpreter);
    let i = as_usize_saturated!(*index);
    *index = context.host.blob_hash(i).unwrap_or_default();
    Ok(())
}
