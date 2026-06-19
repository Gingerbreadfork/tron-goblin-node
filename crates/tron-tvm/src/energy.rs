//! Energy model — TRON's analog of EVM gas, with TRX-denominated fees.
//!
//! Three numbers an EVM execution needs to track:
//!
//! 1. **Gas**, the EVM unit. Standard opcodes have gas costs (e.g.
//!    `ADD` = 3 gas).
//! 2. **Energy**, TRON's unit. The conversion is **1 energy = 1 gas**
//!    at the precompile level — the names are interchangeable inside
//!    the interpreter. The distinction matters at the fee boundary.
//! 3. **Sun**, the smallest TRX unit (1 TRX = 1,000,000 sun). Fees
//!    are charged in sun via the `ENERGY_FEE` parameter:
//!    `fee_sun = energy_used * energy_fee_in_sun_per_energy`.
//!
//! Source: `org.tron.core.vm.config.VMConfig` +
//! `org.tron.core.actuator.VMActuator`.

use std::sync::OnceLock;

use revm::context_interface::cfg::gas_params::{GasId, GasParams};
use revm::primitives::hardfork::SpecId;
use thiserror::Error;

/// Builds TRON's TVM energy schedule as a revm [`GasParams`].
///
/// TRON froze its energy costs at Ethereum's **Frontier** gas schedule
/// (SLOAD 50, CALL 40, SSTORE 20000/5000, EXP 10/byte, SELFDESTRUCT base 0,
/// no EIP-2929 warm/cold) while *separately* adopting modern opcodes
/// (CREATE2, PUSH0, transient storage, …). No single revm `SpecId` expresses
/// "Frontier gas + modern opcodes", so we build the dynamic gas table from
/// `FRONTIER` and pin the *gas* spec ([`GasParams::spec`]) to `FRONTIER`. The
/// interpreter then applies Frontier gas *logic* — simple SET/CLEAR/RESET
/// SSTORE metering, no EIP-2200 stipend sentry, no warm/cold cost — regardless
/// of the opcode spec carried in `Cfg::spec`.
///
/// On top of Frontier we apply TRON's handful of deltas:
/// * **No energy refunds.** TRON has neither the SSTORE-clear (15000) nor the
///   SELFDESTRUCT (24000) refund (confirmed against `EnergyCost.java`).
/// * **SELFDESTRUCT to a dead account costs `NEW_ACCT_CALL` (25000).** Frontier
///   charges nothing for this; TRON charges the new-account topup.
/// * **Energy is execution-only.** There is no 21000 per-transaction base and
///   no calldata token cost in energy — those are charged as bandwidth (net),
///   not energy — so the intrinsic is zeroed.
fn build_tron_gas_params() -> GasParams {
    let mut gp = GasParams::new_spec(SpecId::FRONTIER);
    gp.override_gas(
        [
            // TRON has no energy refunds.
            (GasId::sstore_clearing_slot_refund(), 0),
            (GasId::selfdestruct_refund(), 0),
            // SELFDESTRUCT to a non-existent (dead) account: NEW_ACCT_CALL.
            (GasId::new_account_cost_for_selfdestruct(), 25_000),
            // Energy excludes the per-tx 21000 base and the calldata token cost
            // (both are charged as bandwidth, not energy).
            (GasId::tx_base_stipend(), 0),
            (GasId::tx_token_cost(), 0),
        ]
        .into_iter(),
    );
    gp
}

/// TRON's TVM energy schedule (see [`build_tron_gas_params`]), cached. Cloning
/// is cheap — the 256-entry cost table is shared behind an `Arc`.
pub fn tron_gas_params() -> GasParams {
    static CACHE: OnceLock<GasParams> = OnceLock::new();
    CACHE.get_or_init(build_tron_gas_params).clone()
}

/// TRON's energy schedule, selecting whether CALL/CREATE gas-forwarding retains
/// 1/64 (EIP-150).
///
/// java-tron's `Program.getCallEnergy` retains the 1/64 ONLY when
/// `allowTvmCompatibleEvm() && getContractVersion() == 1`. With
/// `ALLOW_TVM_COMPATIBLE_EVM` off — true for all of mainnet to date, where
/// every live contract is version 0 — it forwards ALL available energy to the
/// child frame. revm's interpreter otherwise applies the 1/64 retention
/// unconditionally (its opcode spec is ≥ Tangerine), which starves a sub-call
/// sitting near the energy limit and OOGs it where java completes (e.g. a
/// BatchTransfer wrapping a USDT transfer at a tight `fee_limit`). We encode
/// "no retention" as a 0 divisor in the `call_stipend_reduction` slot.
///
/// NOTE: when the flag IS active, java retains only for version-1 (post-fork)
/// contracts; this per-execution selector would retain for ALL contracts. That
/// case is unreachable on mainnet (flag off) — refine with per-frame contract
/// version if the proposal ever activates.
pub fn tron_gas_params_for(retain_call_gas_64th: bool) -> GasParams {
    if retain_call_gas_64th {
        return tron_gas_params();
    }
    static NO_RETAIN: OnceLock<GasParams> = OnceLock::new();
    NO_RETAIN
        .get_or_init(|| {
            let mut gp = build_tron_gas_params();
            gp.override_gas([(GasId::call_stipend_reduction(), 0)].into_iter());
            gp
        })
        .clone()
}

/// TRON's static (per-opcode) energy table.
///
/// revm's Frontier static table already matches TRON's per-opcode costs
/// (SLOAD 50, CALL 40, EXP base 10, JUMPI 10, …). TRON has two deviations:
///
/// 1. **MLOAD / MSTORE / MSTORE8 carry a base of 1** (plus memory expansion),
///    not Ethereum's VERY_LOW tier (3). Verified against java-tron via
///    `triggerconstantcontract` — with base 3 our `energy_used` ran exactly
///    `2 × (#MLOAD + #MSTORE)` high on every call (decimals +8, balanceOf +12,
///    string returns +30); base 1 makes it match exactly.
///
/// 2. **CODECOPY / CALLDATACOPY / RETURNDATACOPY carry NO base** (just memory
///    expansion + the 3-per-word copy cost), not Ethereum's VERY_LOW tier (3).
///    java-tron registers these with `EnergyCost::get{Code,CallData,ReturnData}
///    CopyCost`, each of which returns *only* `calcMemEnergy(...)` (mem + copy)
///    with no tier added — `OperationRegistry`'s `(opcode, 3, 0, …)` numbers are
///    the stack in/out arity, not a base. Literal EVM/revm bills a VERY_LOW(3)
///    base on top, so every copy op ran exactly +3 high: a clean multiple-of-3
///    `energy_usage_total` over-charge across the mainnet window (1 copy → +3,
///    11 copies → +33, 300 → +900) that desyncs energy-tight txs. Note the
///    asymmetry: EXTCODECOPY keeps its base (java `EXT_CODE_COPY = 20`) and
///    MCOPY keeps VERY_LOW (java `getMCopyCost = VERY_LOW_TIER + calcMemEnergy`),
///    so only the three bare copies are zeroed here.
pub fn tron_static_gas_table() -> [u16; 256] {
    // Opcodes: MLOAD=0x51, MSTORE=0x52, MSTORE8=0x53.
    const MLOAD: usize = 0x51;
    const MSTORE: usize = 0x52;
    const MSTORE8: usize = 0x53;
    // Bare copy opcodes (no base tier in java-tron): CALLDATACOPY=0x37,
    // CODECOPY=0x39, RETURNDATACOPY=0x3e.
    const CALLDATACOPY: usize = 0x37;
    const CODECOPY: usize = 0x39;
    const RETURNDATACOPY: usize = 0x3e;
    let mut table = revm::interpreter::gas_table();
    table[MLOAD] = 1;
    table[MSTORE] = 1;
    table[MSTORE8] = 1;
    table[CALLDATACOPY] = 0;
    table[CODECOPY] = 0;
    table[RETURNDATACOPY] = 0;
    table
}

/// `ENERGY_FEE` is stored in `DynamicPropertiesStore` under this
/// canonical key. Mainnet default is currently 210 sun per energy unit.
pub const ENERGY_FEE_KEY: &[u8] = b"ENERGY_FEE";
pub const DEFAULT_ENERGY_FEE_PER_UNIT: i64 = 210;

/// `ALLOW_DYNAMIC_ENERGY` is a proposal flag. When set to 1, each
/// per-contract energy charge is scaled up by a penalty factor that
/// grows with contract usage. The factor divisor:
///
/// ```text
/// effective_energy = base_energy * (1 + factor / DECIMAL)
/// ```
///
/// where `DECIMAL = 10_000`. java-tron's source:
/// `actuator/src/main/java/org/tron/core/vm/config/VMConfig.java`.
pub const DYNAMIC_ENERGY_FACTOR_DECIMAL: i64 = 10_000;

/// Convert from EVM gas units to TRON energy units. Currently 1:1.
/// Kept as a function so a future divergence (e.g. a fork that
/// renormalises) lives in exactly one place.
#[inline]
pub const fn gas_to_energy(gas: u64) -> u64 {
    gas
}

#[inline]
pub const fn energy_to_gas(energy: u64) -> u64 {
    energy
}

/// Compute the TRX fee in sun for `energy_used` energy at `fee_per_unit`
/// sun-per-energy.
#[inline]
pub fn energy_fee_in_sun(energy_used: u64, fee_per_unit_sun: i64) -> Result<i64, EnergyError> {
    if fee_per_unit_sun < 0 {
        return Err(EnergyError::NegativeFee);
    }
    let used_signed = i64::try_from(energy_used).map_err(|_| EnergyError::Overflow)?;
    used_signed
        .checked_mul(fee_per_unit_sun)
        .ok_or(EnergyError::Overflow)
}

/// Apply the `ALLOW_DYNAMIC_ENERGY` penalty to a base energy cost.
///
/// `factor` is the per-contract penalty factor in units of
/// [`DYNAMIC_ENERGY_FACTOR_DECIMAL`] (so `factor = 10_000` doubles the
/// cost; `factor = 5_000` adds 50%). Pass `0` for no penalty.
///
/// Source: `actuator/src/main/java/org/tron/core/vm/VM.java` (~line 74) —
/// the factor scales the base energy linearly:
///
/// ```text
/// effective_energy = energy * (DYNAMIC_ENERGY_FACTOR_DECIMAL + factor)
///                    / DYNAMIC_ENERGY_FACTOR_DECIMAL
/// ```
///
/// Pinned by a test below.
pub fn energy_with_dynamic_penalty(base_energy: u64, factor: i64) -> Result<u64, EnergyError> {
    if factor < 0 {
        return Err(EnergyError::NegativeFactor);
    }
    if factor == 0 {
        return Ok(base_energy);
    }
    let total: u128 = (base_energy as u128)
        .checked_mul((DYNAMIC_ENERGY_FACTOR_DECIMAL as u128) + (factor as u128))
        .ok_or(EnergyError::Overflow)?
        / (DYNAMIC_ENERGY_FACTOR_DECIMAL as u128);
    u64::try_from(total).map_err(|_| EnergyError::Overflow)
}

/// Apply the dynamic-energy penalty *if* the chain has activated it.
///
/// Returns `base_energy` unchanged when `allow_dynamic_energy` is `false`
/// or when the factor is `0`. Otherwise scales by
/// `(DECIMAL + factor) / DECIMAL`.
///
/// This is the precompile/opcode-level seam: every energy charge made by
/// the interpreter goes through here so per-contract penalties apply
/// uniformly. Callers pass the active contract's factor (read from
/// [`tron_chainbase::ContractStateStore`] via the [`crate::EvmContext`]).
pub fn effective_energy_cost(
    base_energy: u64,
    factor: i64,
    allow_dynamic_energy: bool,
) -> Result<u64, EnergyError> {
    if !allow_dynamic_energy || factor == 0 {
        return Ok(base_energy);
    }
    energy_with_dynamic_penalty(base_energy, factor)
}

/// Parameters needed to compute the final per-tx fee.
#[derive(Debug, Clone, Copy)]
pub struct EnergyParams {
    pub energy_fee_per_unit_sun: i64,
    pub dynamic_energy_factor: i64,
    pub allow_dynamic_energy: bool,
}

impl Default for EnergyParams {
    fn default() -> Self {
        Self {
            energy_fee_per_unit_sun: DEFAULT_ENERGY_FEE_PER_UNIT,
            dynamic_energy_factor: 0,
            allow_dynamic_energy: false,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EnergyError {
    #[error("energy fee cannot be negative")]
    NegativeFee,
    #[error("dynamic energy factor cannot be negative")]
    NegativeFactor,
    #[error("arithmetic overflow")]
    Overflow,
}

#[cfg(test)]
mod call_gas_forwarding_tests {
    use super::{tron_gas_params, tron_gas_params_for};

    /// java-tron retains the EIP-150 1/64 on CALL only when
    /// `allowTvmCompatibleEvm && version==1`. With the flag OFF (mainnet) it
    /// forwards ALL available energy; with it ON it keeps the 63/64.
    #[test]
    fn call_gas_retention_follows_tvm_compatible_evm_flag() {
        let g = 64_000u64;
        // flag off → no retention (forward all). This is the fix that lets a
        // BatchTransfer→USDT sub-call complete instead of OOG-ing 1/64 short.
        assert_eq!(tron_gas_params_for(false).call_stipend_reduction(g), g);
        // flag on → classic 63/64 retention (g - g/64).
        assert_eq!(
            tron_gas_params_for(true).call_stipend_reduction(g),
            g - g / 64
        );
        // the default params retain (back-compat with non-execute callers).
        assert_eq!(tron_gas_params().call_stipend_reduction(g), g - g / 64);
    }
}

#[cfg(test)]
mod sstore_parity_tests {
    use super::tron_gas_params;
    use revm::context_interface::context::SStoreResult;
    use revm::primitives::U256;

    /// Full TRON SSTORE energy for a `(original, present, new)` transition:
    /// `sstore_static + sstore_dynamic`. The gas spec is `FRONTIER`, so the
    /// interpreter passes `is_istanbul = false`.
    fn sstore_cost(orig: u64, present: u64, new: u64) -> u64 {
        sstore_cost_w(orig, present, new, false)
    }

    /// As [`sstore_cost`], with `prev_written` = slot already written this tx.
    fn sstore_cost_w(orig: u64, present: u64, new: u64, prev_written: bool) -> u64 {
        let gp = tron_gas_params();
        let vals = SStoreResult {
            original_value: U256::from(orig),
            present_value: U256::from(present),
            new_value: U256::from(new),
            prev_written_this_tx: prev_written,
        };
        // `is_cold` is ignored on the Frontier branch (no warm/cold split).
        gp.sstore_static_gas() + gp.sstore_dynamic_gas(false, &vals, false)
    }

    const SET: u64 = 20_000; // java SET_SSTORE
    const RESET: u64 = 5_000; // java RESET_SSTORE == CLEAR_SSTORE

    /// Pin the two TRON SSTORE costs so a future schedule edit can't silently
    /// drift them away from java-tron's `EnergyCost` constants.
    #[test]
    fn sstore_set_and_reset_constants() {
        assert_eq!(sstore_cost(0, 0, 7), SET);
        assert_eq!(sstore_cost(9, 9, 7), RESET);
    }

    /// Mirror java-tron `EnergyCost.getSstoreCost`: SET (20000) is charged only
    /// when `storageLoad(key) == null` — i.e. the slot has no storage row
    /// (DB-absent and unwritten this tx). Every other transition is 5000.
    #[test]
    fn sstore_matches_java_null_model() {
        // 1. First write to a truly-absent slot (java null) -> SET.
        assert_eq!(sstore_cost(0, 0, 7), SET);
        // 2. Writing zero to an absent slot -> new==0 -> 5000.
        assert_eq!(sstore_cost(0, 0, 0), RESET);
        // 3. DB-present nonzero, overwritten nonzero (java non-null) -> RESET.
        assert_eq!(sstore_cost(9, 9, 7), RESET);
        // 4. DB-present nonzero, cleared to zero (java CLEAR) -> 5000.
        assert_eq!(sstore_cost(9, 9, 0), RESET);
        // 5. THE FIX — nonzero slot cleared earlier this tx, re-set nonzero.
        //    `original != 0`, so RESET. Literal Frontier (`present == 0`) would
        //    bill SET (20000); java bills 5000 (the row is cached/non-null).
        assert_eq!(sstore_cost(9, 0, 7), RESET);
        // 6. THE FIX — absent slot set nonzero earlier this tx, re-set nonzero.
        //    `present != 0`, so RESET.
        assert_eq!(sstore_cost(0, 5, 7), RESET);
        // 5b/6b — the same re-sets but clearing to zero are always 5000.
        assert_eq!(sstore_cost(9, 0, 0), RESET);
        assert_eq!(sstore_cost(0, 5, 0), RESET);
    }

    /// THE case-4 fix — an absent slot (`original == 0`) set to 0 then re-set
    /// nonzero in the same tx reads `original == present == 0`, so the value-only
    /// rule mis-bills SET (20000). `prev_written_this_tx` (a prior journal
    /// `StorageChanged` on the slot) forces RESET (5000) to match java's cached
    /// row. Proven live on SmartExchangeRouter slot …c894b01f
    /// (nonzero→0→nonzero), which was billed +15000 before this fix.
    #[test]
    fn sstore_prev_written_forces_reset() {
        // pristine absent slot, never written this tx -> SET.
        assert_eq!(sstore_cost_w(0, 0, 7, false), SET);
        // same transition, but the slot was already written this tx -> RESET.
        assert_eq!(sstore_cost_w(0, 0, 7, true), RESET);
        // prev_written is irrelevant when not the SET-eligible transition.
        assert_eq!(sstore_cost_w(9, 9, 7, true), RESET);
        assert_eq!(sstore_cost_w(0, 0, 0, true), RESET);
    }
}

#[cfg(test)]
mod static_table_parity_tests {
    use super::tron_static_gas_table;

    /// Pin the per-opcode static bases against java-tron's energy schedule.
    /// CODECOPY/CALLDATACOPY/RETURNDATACOPY have NO base (their cost is purely
    /// `mem + 3×words`); EXTCODECOPY keeps `EXT_CODE_COPY = 20`; MCOPY keeps
    /// VERY_LOW = 3; MLOAD/MSTORE/MSTORE8 are 1.
    #[test]
    fn copy_opcode_bases_match_java() {
        let t = tron_static_gas_table();
        assert_eq!(t[0x37], 0, "CALLDATACOPY base must be 0");
        assert_eq!(t[0x39], 0, "CODECOPY base must be 0");
        assert_eq!(t[0x3e], 0, "RETURNDATACOPY base must be 0");
        assert_eq!(t[0x3c], 20, "EXTCODECOPY keeps EXT_CODE_COPY=20");
        assert_eq!(t[0x5e], 3, "MCOPY keeps VERY_LOW=3");
        assert_eq!(t[0x51], 1, "MLOAD base 1");
        assert_eq!(t[0x52], 1, "MSTORE base 1");
        assert_eq!(t[0x53], 1, "MSTORE8 base 1");
        // sanity: a normal VERY_LOW op is untouched.
        assert_eq!(t[0x01], 3, "ADD stays VERY_LOW=3");
    }
}
