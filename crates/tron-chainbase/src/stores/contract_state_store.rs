//! ContractStateStore — directory name `contract-state`.
//!
//! Per-contract execution-state metadata (energy usage windows etc.).
//! Distinct from [`super::ContractStore`] (which holds the deployed
//! SmartContract proto) and [`super::StorageRowStore`] (which holds
//! per-slot EVM storage).
//!
//! Key:   21-byte contract address.
//! Value: protobuf-encoded `ContractState` message.

use std::sync::Arc;

use prost::Message;
use tron_crypto::address::Address;
use tron_proto::ContractState;

use crate::backend::KvBackend;
use crate::stores::StoreError;

pub const DB_NAME: &str = "contract-state";

pub struct ContractStateStore {
    backend: Arc<dyn KvBackend>,
}

impl ContractStateStore {
    pub const DB_NAME: &'static str = DB_NAME;

    pub fn new(backend: Arc<dyn KvBackend>) -> Self {
        Self { backend }
    }

    pub fn put(&self, address: &Address, state: &ContractState) -> Result<(), StoreError> {
        self.backend.put(address.as_bytes(), &state.encode_to_vec())?;
        Ok(())
    }

    pub fn get(&self, address: &Address) -> Result<Option<ContractState>, StoreError> {
        let Some(bytes) = self.backend.get(address.as_bytes())? else {
            return Ok(None);
        };
        Ok(Some(ContractState::decode(bytes.as_slice())?))
    }

    /// Per-contract dynamic energy penalty factor (consensus-critical).
    /// Returns `0` for any contract without a stored state record,
    /// matching java-tron's `ContractStateStore.getDynamicEnergyFactor`
    /// which falls back to `0` for never-touched contracts.
    ///
    /// The value is in units of `DYNAMIC_ENERGY_FACTOR_DECIMAL = 10_000`,
    /// so `5_000` means +50%. Pinned by tests in `tron-tvm`.
    pub fn dynamic_energy_factor(&self, address: &Address) -> Result<i64, StoreError> {
        Ok(self.get(address)?.map(|s| s.energy_factor).unwrap_or(0))
    }

    /// Update the stored `ContractState` for `address` to reflect cycles
    /// elapsed since `update_cycle`, returning the post-update factor.
    /// Mirrors `ContractStateCapsule.catchUpToCycle` in java-tron:
    ///
    /// 1. If the previous cycle's `energy_usage` exceeded `threshold`,
    ///    grow the factor by `(1 + increase_factor / DECIMAL)`, capped
    ///    at `max_factor`. Consumes one cycle.
    /// 2. Decay the factor across the remaining cycles by
    ///    `(1 - increase_factor / DECREASE_DIVISION / DECIMAL)^n`, floored
    ///    at 0.
    /// 3. Reset `energy_usage` to 0 and stamp `update_cycle = new_cycle`.
    ///
    /// Idempotent within a single cycle. Initialises a fresh record when
    /// the contract has none yet. Strict-math / `Math.pow` flag handling
    /// is deferred — we always use `f64::powf`; differences vs java-tron
    /// surface only at the LSBs of the resulting factor for very long
    /// idle gaps.
    pub fn catch_up_to_cycle(
        &self,
        address: &Address,
        new_cycle: i64,
        threshold: i64,
        increase_factor: i64,
        max_factor: i64,
    ) -> Result<i64, StoreError> {
        let (state, changed) =
            Self::caught_up(self.get(address)?, new_cycle, threshold, increase_factor, max_factor);
        if changed {
            self.put(address, &state)?;
        }
        Ok(state.energy_factor)
    }

    /// Read-only caught-up view of a contract's state — what java-tron's
    /// `getContractInfo` serves: `catchUpToCycle` is run on the capsule
    /// for display but never written back. A missing record yields a
    /// fresh `{update_cycle: new_cycle}` (java builds
    /// `new ContractStateCapsule(currentCycleNumber)`).
    pub fn caught_up_view(
        &self,
        address: &Address,
        new_cycle: i64,
        threshold: i64,
        increase_factor: i64,
        max_factor: i64,
    ) -> Result<ContractState, StoreError> {
        Ok(Self::caught_up(self.get(address)?, new_cycle, threshold, increase_factor, max_factor).0)
    }

    /// Pure catch-up transform shared by the consensus write path
    /// ([`Self::catch_up_to_cycle`]) and the RPC view
    /// ([`Self::caught_up_view`]). Returns the post-catch-up state and
    /// whether it differs from what's stored (i.e. needs a write).
    fn caught_up(
        stored: Option<ContractState>,
        new_cycle: i64,
        threshold: i64,
        increase_factor: i64,
        max_factor: i64,
    ) -> (ContractState, bool) {
        const DECIMAL: i64 = 10_000;
        const DECREASE_DIVISION: i64 = 4;

        let Some(state) = stored else {
            return (
                ContractState {
                    update_cycle: new_cycle,
                    ..Default::default()
                },
                true,
            );
        };

        if state.update_cycle == new_cycle {
            return (state, false);
        }
        if state.update_cycle > new_cycle || state.update_cycle == 0 {
            return (
                ContractState {
                    update_cycle: new_cycle,
                    ..Default::default()
                },
                true,
            );
        }

        let mut current_factor = state.energy_factor;
        let mut effective_last = state.update_cycle;

        if state.energy_usage > threshold {
            effective_last += 1;
            let increase_percent = 1.0 + (increase_factor as f64) / (DECIMAL as f64);
            let new_factor =
                ((current_factor + DECIMAL) as f64 * increase_percent) as i64 - DECIMAL;
            current_factor = new_factor.min(max_factor);
        }

        let cycle_count = new_cycle - effective_last;
        if cycle_count > 0 {
            let base = 1.0
                - (increase_factor as f64) / (DECREASE_DIVISION as f64) / (DECIMAL as f64);
            let decrease_percent = base.powf(cycle_count as f64);
            current_factor =
                ((current_factor + DECIMAL) as f64 * decrease_percent) as i64 - DECIMAL;
            if current_factor < 0 {
                current_factor = 0;
            }
        }

        (
            ContractState {
                update_cycle: new_cycle,
                energy_factor: current_factor,
                energy_usage: 0,
            },
            true,
        )
    }

    /// Record additional energy consumption against the contract's
    /// `energy_usage` counter for the current cycle. Mirrors java-tron's
    /// `addContextContractUsage` (called once per frame after VM exit
    /// when `ALLOW_DYNAMIC_ENERGY` is on). A missing record is treated
    /// as fresh — usage starts at `amount`. No cycle stamp here; the
    /// next `catch_up_to_cycle` does that.
    pub fn add_energy_usage(&self, address: &Address, amount: i64) -> Result<(), StoreError> {
        let mut state = self.get(address).ok().flatten().unwrap_or_default();
        state.energy_usage = state.energy_usage.saturating_add(amount);
        self.put(address, &state)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MemBackend;

    fn store() -> ContractStateStore {
        ContractStateStore::new(Arc::new(MemBackend::new()))
    }

    fn addr(b: u8) -> Address {
        let mut raw = [0u8; 21];
        raw[0] = 0x41;
        raw[1..].fill(b);
        Address::from_raw(raw)
    }

    #[test]
    fn catch_up_initialises_fresh_record() {
        let s = store();
        let a = addr(0x11);
        let factor = s.catch_up_to_cycle(&a, 100, 1_000_000, 50, 100_000).unwrap();
        assert_eq!(factor, 0);
        let stored = s.get(&a).unwrap().unwrap();
        assert_eq!(stored.update_cycle, 100);
        assert_eq!(stored.energy_factor, 0);
        assert_eq!(stored.energy_usage, 0);
    }

    #[test]
    fn catch_up_same_cycle_is_noop() {
        let s = store();
        let a = addr(0x22);
        s.put(
            &a,
            &ContractState {
                update_cycle: 50,
                energy_factor: 3_000,
                energy_usage: 42,
            },
        ).unwrap();
        let factor = s.catch_up_to_cycle(&a, 50, 1_000_000, 50, 100_000).unwrap();
        assert_eq!(factor, 3_000);
        let stored = s.get(&a).unwrap().unwrap();
        assert_eq!(stored.energy_usage, 42, "usage must not be cleared on no-op");
    }

    #[test]
    fn catch_up_grows_when_usage_exceeded_threshold() {
        let s = store();
        let a = addr(0x33);
        // Previous cycle: usage 2_000_000 vs threshold 1_000_000 → grow once.
        s.put(
            &a,
            &ContractState {
                update_cycle: 99,
                energy_factor: 0,
                energy_usage: 2_000_000,
            },
        ).unwrap();
        // newCycle = 100 (one cycle gap). Increase by 50 / 10_000 = 0.5%.
        // (0 + 10000) * 1.005 = 10049.999... (IEEE 754), truncates to
        // 10049; minus 10000 → 49. Java-tron does the same `(long)` cast.
        let factor = s.catch_up_to_cycle(&a, 100, 1_000_000, 50, 100_000).unwrap();
        assert_eq!(factor, 49);
        let stored = s.get(&a).unwrap().unwrap();
        assert_eq!(stored.update_cycle, 100);
        assert_eq!(stored.energy_usage, 0, "usage resets after catch-up");
    }

    #[test]
    fn catch_up_decays_after_idle_cycles() {
        let s = store();
        let a = addr(0x44);
        // Stored factor 10_000 (+100%) from cycle 50; usage was 0 last cycle.
        s.put(
            &a,
            &ContractState {
                update_cycle: 50,
                energy_factor: 10_000,
                energy_usage: 0,
            },
        ).unwrap();
        // Jump to cycle 60: 10 idle cycles, no growth, only decay.
        let factor = s.catch_up_to_cycle(&a, 60, 1_000_000, 50, 100_000).unwrap();
        // base = 1 - 50/4/10000 = 0.99875; 0.99875^10 ≈ 0.98758
        // (10000 + 10000) * 0.98758 ≈ 19751.6; - 10000 = 9751.
        assert!(
            (9_700..=9_800).contains(&factor),
            "expected decay to ~9_750, got {factor}"
        );
    }

    #[test]
    fn add_energy_usage_accumulates() {
        let s = store();
        let a = addr(0x55);
        s.add_energy_usage(&a, 1_000).unwrap();
        s.add_energy_usage(&a, 500).unwrap();
        let stored = s.get(&a).unwrap().unwrap();
        assert_eq!(stored.energy_usage, 1_500);
    }
}
