//! E2E test that the per-opcode dynamic-energy factor is actually
//! applied by the forked Gas tracker.
//!
//! Approach:
//! 1. Deploy a contract whose runtime code does a known amount of gas work
//!    (a long sequence of cheap opcodes), then `RETURN` 0 bytes.
//! 2. Execute it twice with the same `gas_limit`: once with no dynamic
//!    factor, once with a `+100%` factor (`factor == DECIMAL`).
//! 3. The `+100%` run must consume ~2× the gas of the baseline run.
//!
//! This proves the multiplier flows: `tron-tvm::execute_trigger` →
//! `Trc10Inspector::initialize_interp` →
//! `Gas::set_tron_dynamic_factor` → `record_*_cost` math →
//! observable gas usage diff.

use std::sync::Arc;

use tron_chainbase::{
    AccountStore, CodeStore, ContractStateStore, DelegatedResourceStore, DelegationStore,
    DynamicPropertiesStore, KvBackend, MemBackend, StorageRowStore, WitnessStore,
};
use tron_crypto::address::Address;
use tron_proto::{Account, ContractState, TriggerSmartContract};
use tron_tvm::database::code_hash;
use tron_tvm::execute::{execute_trigger, VmBlockEnv, VmOutcome, VmStores};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn fresh_stores() -> VmStores {
    VmStores {
        accounts: Arc::new(AccountStore::new(mem())),
        code: Arc::new(CodeStore::new(mem())),
        storage: Arc::new(StorageRowStore::new(mem())),
        witnesses: Arc::new(WitnessStore::new(mem())),
        contract_state: Arc::new(ContractStateStore::new(mem())),
        dynamic_properties: Arc::new(DynamicPropertiesStore::new(mem())),
        delegated_resources: Arc::new(DelegatedResourceStore::new(mem())),
        delegation: Arc::new(DelegationStore::new(mem())),
        block_index: None,
        contracts: None,
        votes: None,
    }
}

fn install(stores: &VmStores, prefix: u8, code: &[u8]) -> [u8; 21] {
    let mut addr = [0u8; 21];
    addr[0] = 0x41;
    addr[1..].fill(prefix);
    let tron = Address::from_raw(addr);
    let hash = code_hash(code);
    stores.code.put(hash.as_slice(), code).unwrap();
    stores.accounts.put(
        &tron,
        &Account {
            address: addr.to_vec(),
            balance: 0,
            code: code.to_vec(),
            code_hash: hash.as_slice().to_vec(),
            ..Default::default()
        },
    ).unwrap();
    addr
}

fn fund_user(stores: &VmStores, prefix: u8) -> [u8; 21] {
    let mut addr = [0u8; 21];
    addr[0] = 0x41;
    addr[1..].fill(prefix);
    stores.accounts.put(
        &Address::from_raw(addr),
        &Account {
            address: addr.to_vec(),
            balance: 1_000_000_000,
            ..Default::default()
        },
    ).unwrap();
    addr
}

/// A contract that does 100 `ADD` ops on stack (3 gas each = 300 baseline),
/// then RETURNs empty.
///
/// Bytecode:
///   * 100× `PUSH1 0x01 PUSH1 0x01 ADD POP` — each iteration: 3+3+3+2 = 11 gas
///     (but POP costs 2). 100 iterations = 1100 gas of opcode work.
///   * `STOP` to terminate cleanly.
fn make_workload(iters: usize) -> Vec<u8> {
    let mut bc = Vec::with_capacity(iters * 6 + 1);
    for _ in 0..iters {
        bc.push(0x60); // PUSH1
        bc.push(0x01);
        bc.push(0x60); // PUSH1
        bc.push(0x01);
        bc.push(0x01); // ADD
        bc.push(0x50); // POP
    }
    bc.push(0x00); // STOP
    bc
}

fn run(stores: &VmStores, owner: [u8; 21], contract: [u8; 21]) -> u64 {
    let trigger = TriggerSmartContract {
        owner_address: owner.to_vec(),
        contract_address: contract.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };
    let outcome = execute_trigger(
        stores,
        VmBlockEnv {
            block_number: 1,
            block_timestamp_ms: 0,
        },
        &trigger,
        10_000_000,
    );
    match outcome {
        VmOutcome::Success { energy_used, .. } => energy_used,
        other => panic!("expected Success, got {other:?}"),
    }
}

#[test]
fn dynamic_factor_zero_matches_baseline() {
    let stores = fresh_stores();
    stores.dynamic_properties.put_long(b"ALLOW_DYNAMIC_ENERGY", 1);
    let owner = fund_user(&stores, 0xa0);
    let contract = install(&stores, 0xc0, &make_workload(50));

    // No factor stored → 0 → no penalty.
    let baseline = run(&stores, owner, contract);
    // Setting an explicit `factor=0` must produce the identical result.
    stores.contract_state.put(
        &Address::from_raw(contract),
        &ContractState {
            energy_usage: 0,
            energy_factor: 0,
            update_cycle: 0,
        },
    ).unwrap();
    let explicit_zero = run(&stores, owner, contract);
    assert_eq!(
        baseline, explicit_zero,
        "factor=0 must be indistinguishable from no factor stored"
    );
}

#[test]
fn dynamic_factor_decimal_doubles_gas_consumption() {
    // Run 1: baseline (no factor).
    let baseline = {
        let stores = fresh_stores();
        stores.dynamic_properties.put_long(b"ALLOW_DYNAMIC_ENERGY", 1);
        let owner = fund_user(&stores, 0xa1);
        let contract = install(&stores, 0xc1, &make_workload(100));
        run(&stores, owner, contract)
    };

    // Run 2: factor = TRON_DYNAMIC_DECIMAL (10_000) → +100% multiplier.
    let doubled = {
        let stores = fresh_stores();
        stores.dynamic_properties.put_long(b"ALLOW_DYNAMIC_ENERGY", 1);
        let owner = fund_user(&stores, 0xa1);
        let contract = install(&stores, 0xc1, &make_workload(100));
        stores.contract_state.put(
            &Address::from_raw(contract),
            &ContractState {
                energy_usage: 0,
                energy_factor: 10_000, // = DECIMAL → 2× multiplier
                update_cycle: 0,
            },
        ).unwrap();
        run(&stores, owner, contract)
    };

    // Account for the fixed 21_000-gas transaction base that doesn't
    // scale with the dynamic factor (it's charged before the
    // interpreter runs). Compare only the in-contract portion.
    const TX_BASE: u64 = 21_000;
    let baseline_contract = baseline.saturating_sub(TX_BASE);
    let doubled_contract = doubled.saturating_sub(TX_BASE);

    // The in-contract work should approximately double. Allow ±5%
    // because some bookkeeping bytes (memory expansion thresholds,
    // intrinsic charges) may not all flow through the multiplier on
    // this revm version. The key invariant is the ~2× factor.
    let ratio = doubled_contract as f64 / baseline_contract.max(1) as f64;
    assert!(
        ratio >= 1.90 && ratio <= 2.10,
        "expected ~2× gas with factor=DECIMAL; baseline_contract={baseline_contract}, \
         doubled_contract={doubled_contract}, ratio={ratio:.3}"
    );
}

#[test]
fn dynamic_factor_half_decimal_adds_50_percent() {
    let baseline = {
        let stores = fresh_stores();
        stores.dynamic_properties.put_long(b"ALLOW_DYNAMIC_ENERGY", 1);
        let owner = fund_user(&stores, 0xa2);
        let contract = install(&stores, 0xc2, &make_workload(80));
        run(&stores, owner, contract)
    };

    let plus_half = {
        let stores = fresh_stores();
        stores.dynamic_properties.put_long(b"ALLOW_DYNAMIC_ENERGY", 1);
        let owner = fund_user(&stores, 0xa2);
        let contract = install(&stores, 0xc2, &make_workload(80));
        stores.contract_state.put(
            &Address::from_raw(contract),
            &ContractState {
                energy_usage: 0,
                energy_factor: 5_000, // 0.5 × DECIMAL → +50%
                update_cycle: 0,
            },
        ).unwrap();
        run(&stores, owner, contract)
    };

    const TX_BASE: u64 = 21_000;
    let baseline_c = baseline.saturating_sub(TX_BASE) as f64;
    let plus_half_c = plus_half.saturating_sub(TX_BASE) as f64;
    let ratio = plus_half_c / baseline_c.max(1.0);
    // Wider window than the 2× case because some gas charges (e.g.,
    // EVM intrinsic gas charged before the interpreter starts; certain
    // EIP-3529 refund accounting) bypass our `record_*_cost` hooks.
    // The 2× test confirms the multiplier is wired correctly; this
    // test confirms it scales monotonically with the factor.
    assert!(
        ratio > 1.30 && ratio < 1.55,
        "expected scaling 1.3–1.55× with factor=DECIMAL/2; \
         baseline_c={baseline_c}, plus_half_c={plus_half_c}, ratio={ratio:.3}"
    );
}

#[test]
fn frame_records_energy_usage_then_next_cycle_grows_factor() {
    // End-to-end: prove the catchUpToCycle + addContextContractUsage
    // lifecycle works through the VM. After running the workload once,
    // the contract's `energy_usage` is non-zero. After advancing the
    // cycle counter and running again, the catch-up logic grows the
    // stored factor because last cycle's usage exceeded the threshold.

    let stores = fresh_stores();
    stores.dynamic_properties.put_long(b"ALLOW_DYNAMIC_ENERGY", 1);
    stores.dynamic_properties.put_long(b"DYNAMIC_ENERGY_THRESHOLD", 1); // tiny → any run exceeds
    stores.dynamic_properties.put_long(b"DYNAMIC_ENERGY_INCREASE_FACTOR", 10_000); // +100%/cycle
    stores.dynamic_properties.put_long(b"DYNAMIC_ENERGY_MAX_FACTOR", 100_000); // 10×
    stores.dynamic_properties.save_current_cycle_number(5);

    let owner = fund_user(&stores, 0xa4);
    let contract = install(&stores, 0xc4, &make_workload(40));
    let contract_addr = Address::from_raw(contract);

    // Run 1: contract has no stored state. catch_up_to_cycle initialises
    // it at cycle 5, factor=0. After the frame ends, energy_usage is
    // recorded.
    let _ = run(&stores, owner, contract);
    let state_after_first = stores
        .contract_state
        .get(&contract_addr)
        .unwrap()
        .expect("ContractState must exist after first VM run");
    assert_eq!(state_after_first.update_cycle, 5);
    assert_eq!(state_after_first.energy_factor, 0);
    assert!(
        state_after_first.energy_usage > 0,
        "frame must have recorded usage, got {}",
        state_after_first.energy_usage
    );

    // Advance cycle counter. Now run 2's initialize_interp will see
    // last_cycle=5, new_cycle=6, usage=N>threshold → factor grows by
    // increase percent (+100% per java-tron arithmetic → ~10_000).
    stores.dynamic_properties.save_current_cycle_number(6);
    let _ = run(&stores, owner, contract);

    let state_after_second = stores
        .contract_state
        .get(&contract_addr)
        .unwrap()
        .expect("ContractState must still exist");
    assert_eq!(state_after_second.update_cycle, 6);
    // (10_000 * 2.0) - 10_000 in IEEE 754 double, then min(maxFactor) ≈
    // 9_999 or 10_000 depending on LSB rounding. Either way, the factor
    // must be well within the grown range.
    assert!(
        (9_000..=10_001).contains(&state_after_second.energy_factor),
        "factor must grow to ~10_000 after one over-threshold cycle, got {}",
        state_after_second.energy_factor
    );
}

#[test]
fn allow_dynamic_energy_off_skips_penalty_even_with_stored_factor() {
    // A stored `energy_factor = 10_000` (would double gas) must NOT
    // apply when the `ALLOW_DYNAMIC_ENERGY` chain parameter is off.
    // Mirrors java-tron's `VMConfig.allowDynamicEnergy()` gate in
    // `actuator/.../vm/VM.java` line ~27.
    let with_flag = {
        let stores = fresh_stores();
        stores.dynamic_properties.put_long(b"ALLOW_DYNAMIC_ENERGY", 1);
        let owner = fund_user(&stores, 0xa3);
        let contract = install(&stores, 0xc3, &make_workload(60));
        stores.contract_state.put(
            &Address::from_raw(contract),
            &ContractState {
                energy_usage: 0,
                energy_factor: 10_000,
                update_cycle: 0,
            },
        ).unwrap();
        run(&stores, owner, contract)
    };

    let without_flag = {
        let stores = fresh_stores();
        // Flag deliberately unset — stays at default 0.
        let owner = fund_user(&stores, 0xa3);
        let contract = install(&stores, 0xc3, &make_workload(60));
        stores.contract_state.put(
            &Address::from_raw(contract),
            &ContractState {
                energy_usage: 0,
                energy_factor: 10_000, // present but must be ignored
                update_cycle: 0,
            },
        ).unwrap();
        run(&stores, owner, contract)
    };

    let no_factor_baseline = {
        let stores = fresh_stores();
        let owner = fund_user(&stores, 0xa3);
        let contract = install(&stores, 0xc3, &make_workload(60));
        run(&stores, owner, contract)
    };

    // With the flag off, the factor must be skipped — gas equals the
    // bare-baseline run that has no factor stored at all.
    assert_eq!(
        without_flag, no_factor_baseline,
        "ALLOW_DYNAMIC_ENERGY=0 must skip the per-contract factor"
    );
    // Sanity: with the flag on, the same stored factor *does* take
    // effect (gas is materially higher).
    assert!(
        with_flag > without_flag + 500,
        "with the flag on, the factor must produce visibly more gas: \
         with_flag={with_flag}, without_flag={without_flag}"
    );
}
