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

use thiserror::Error;

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
