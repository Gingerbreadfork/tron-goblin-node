use context_interface::tron_address_word;

use crate::{
    interpreter_types::{InterpreterTypes as ITy, RuntimeFlag, StackTr},
    Host, InstructionExecResult as Result,
};
use primitives::hardfork::SpecId::*;
use primitives::U256;

use crate::InstructionContext as Ictx;

/// EIP-1344: ChainID opcode
pub fn chainid<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    check!(context.interpreter, ISTANBUL);
    // TRON fork: in the Istanbul(#41)..#60 window CHAINID pushes the FULL 32-byte
    // genesis id, not the truncated chain id. `tron_chain_id_word` carries the
    // precomputed value and defaults to `chain_id()` for non-TRON / post-#60.
    push!(context.interpreter, context.host.tron_chain_id_word());
    Ok(())
}

/// Implements the COINBASE instruction.
///
/// Pushes the current block's beneficiary address onto the stack.
pub fn coinbase<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    let word = context.host.beneficiary().into_word();
    // TRON fork: java `coinBaseAction` pushes the invoke's coinbase DataWord
    // unmasked at every height — no proposal gates it — so the producing
    // witness keeps its 21-byte form and the prefix byte reaches the stack.
    // Contracts that fold `block.coinbase` into a hash preimage without
    // masking (2018-era dice RNGs) observe the difference.
    //
    // Constant calls carry no block context: java's `ET_CONSTANT_TYPE` leaves
    // the coinbase null, which becomes the zero word. An absent beneficiary
    // stays zero rather than gaining a prefix.
    let word = if context.host.tron_enabled() && !word.is_zero() {
        tron_address_word(word)
    } else {
        word
    };
    push!(context.interpreter, word.into());
    Ok(())
}

/// Implements the TIMESTAMP instruction.
///
/// Pushes the current block's timestamp onto the stack.
pub fn timestamp<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    push!(context.interpreter, context.host.timestamp());
    Ok(())
}

/// Implements the NUMBER instruction.
///
/// Pushes the current block number onto the stack.
pub fn block_number<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    push!(context.interpreter, context.host.block_number());
    Ok(())
}

/// Implements the DIFFICULTY/PREVRANDAO instruction.
///
/// Pushes the block difficulty (pre-merge) or prevrandao (post-merge) onto the stack.
pub fn difficulty<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    if context
        .interpreter
        .runtime_flag
        .spec_id()
        .is_enabled_in(MERGE)
    {
        // Unwrap is safe as this fields is checked in validation handler.
        push!(context.interpreter, context.host.prevrandao().unwrap());
    } else {
        push!(context.interpreter, context.host.difficulty());
    }
    Ok(())
}

/// Implements the GASLIMIT instruction.
///
/// Pushes the current block's gas limit onto the stack.
///
/// TRON fork: java's `gasLimitAction` (OperationActions.java:517) pushes
/// `DataWord.ZERO()` unconditionally — TRON has no block gas limit. We push 0
/// here (rather than zeroing `BlockEnv.gas_limit`, which would make revm reject
/// any tx whose `gas_limit` exceeds the block limit). Ethereum-only hosts keep
/// the real block gas limit.
pub fn gaslimit<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    if context.host.tron_enabled() {
        push!(context.interpreter, primitives::U256::ZERO);
        return Ok(());
    }
    push!(context.interpreter, context.host.gas_limit());
    Ok(())
}

/// EIP-3198: BASEFEE opcode
///
/// TRON fork: java's `baseFeeAction` (OperationActions.java:538, registered
/// under `allowTvmLondon`) pushes `dynamicPropertiesStore.getEnergyFee()` —
/// NOT a London-style block base fee. We push the energy fee via the host
/// (rather than `BlockEnv.basefee`, which would trip revm's legacy
/// `gas_price >= basefee` tx-validation). Ethereum-only hosts push the real
/// block base fee. The LONDON spec check (≈ TRON's `allowTvmLondon` gate)
/// stays — the opcode is only reachable when London is active.
pub fn basefee<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    check!(context.interpreter, LONDON);
    if context.host.tron_enabled() {
        push!(context.interpreter, context.host.tron_energy_fee());
        return Ok(());
    }
    push!(context.interpreter, context.host.basefee());
    Ok(())
}

/// EIP-7516: BLOBBASEFEE opcode
///
/// TRON fork: java's `blobBaseFeeAction` (OperationActions.java:686,
/// registered under `allowTvmBlob`) pushes `DataWord.ZERO()`
/// unconditionally — TRON has no blob market, so there is no blob base fee
/// to report. Ethereum-only hosts push the real blob gas price, which is
/// never zero (`MIN_BLOB_GASPRICE` is 1). The CANCUN spec check stays: the
/// `ALLOW_TVM_BLOB` gate is layered on top of Cancun availability, and java
/// registers no BLOBBASEFEE operation below it.
pub fn blob_basefee<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    check!(context.interpreter, CANCUN);
    if context.host.tron_enabled() {
        push!(context.interpreter, U256::ZERO);
        return Ok(());
    }
    push!(context.interpreter, context.host.blob_gasprice());
    Ok(())
}

/// EIP-7843: SLOTNUM opcode
pub fn slot_num<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    check!(context.interpreter, AMSTERDAM);
    push!(context.interpreter, context.host.slot_num());
    Ok(())
}
