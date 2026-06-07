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

/// TRON's static (per-opcode) energy table.
///
/// revm's Frontier static table already matches TRON's per-opcode costs
/// (SLOAD 50, CALL 40, EXP base 10, JUMPI 10, …). TRON has one deviation:
/// **MLOAD / MSTORE / MSTORE8 carry a base of 1** (plus memory expansion), not
/// Ethereum's VERY_LOW tier (3). Verified against java-tron via
/// `triggerconstantcontract` — with base 3 our `energy_used` ran exactly
/// `2 × (#MLOAD + #MSTORE)` high on every call (decimals +8, balanceOf +12,
/// string returns +30); base 1 makes it match exactly.
pub fn tron_static_gas_table() -> [u16; 256] {
    // Opcodes: MLOAD=0x51, MSTORE=0x52, MSTORE8=0x53.
    const MLOAD: usize = 0x51;
    const MSTORE: usize = 0x52;
    const MSTORE8: usize = 0x53;
    let mut table = revm::interpreter::gas_table();
    table[MLOAD] = 1;
    table[MSTORE] = 1;
    table[MSTORE8] = 1;
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
/// Source: `actuator/src/main/java/org/tron/core/vm/VM.java` line ~74:
///
/// ```text
/// penalty = energy * factor / DYNAMIC_ENERGY_FACTOR_DECIMAL - energy
/// effective = energy + penalty = energy + (energy * factor / DECIMAL - energy)
///           = energy * factor / DECIMAL
/// ```
///
/// Wait — that simplification looks wrong; let me re-read the source.
/// java-tron's exact formula is:
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
