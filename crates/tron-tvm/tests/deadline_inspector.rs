//! Proves the deadline inspector preempts the EVM mid-execution.
//!
//! Setup: a contract whose bytecode is an unbounded loop (JUMP back to
//! the start). Without a deadline, the call eventually halts on
//! out-of-gas. With a deadline tight enough to fire before the gas
//! budget is exhausted, the call halts with `VmOutcome::Timeout`.
//!
//! The check is throttled (`DEADLINE_CHECK_STRIDE = 4096`) so worst-case
//! overshoot is ~4096 × ~10ns ≈ 40µs. Test budgets are large enough
//! (100ms+) that the throttle never causes a missed deadline.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tron_chainbase::{
    AccountStore, CodeStore, ContractStateStore, DelegatedResourceStore, DelegationStore,
    DynamicPropertiesStore, KvBackend, MemBackend, StorageRowStore, WitnessStore,
};
use tron_crypto::address::Address;
use tron_proto::{Account, TriggerSmartContract};
use tron_tvm::database::code_hash;
use tron_tvm::execute::{
    execute_trigger_with_deadline, execute_trigger_with_gas_cap, VmBlockEnv, VmOutcome, VmStores,
};

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

fn tron_addr(byte: u8) -> [u8; 21] {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(byte);
    a
}

/// Build a contract that loops forever:
///   JUMPDEST          ; offset 0
///   PUSH1 0x00        ; push the JUMPDEST offset
///   JUMP              ; back to offset 0
fn infinite_loop_bytecode() -> Vec<u8> {
    vec![
        0x5b,             // JUMPDEST  (offset 0)
        0x60, 0x00,       // PUSH1 0
        0x56,             // JUMP
    ]
}

fn install_contract(stores: &VmStores, addr: [u8; 21], bytecode: Vec<u8>) {
    let hash = code_hash(&bytecode).to_vec();
    stores.code.put(&hash, &bytecode).unwrap();
    stores.accounts.put(
        &Address::from_raw(addr),
        &Account {
            address: addr.to_vec(),
            balance: 0,
            code: bytecode,
            code_hash: hash,
            ..Default::default()
        },
    ).unwrap();
}

fn caller(addr: [u8; 21]) -> Account {
    Account {
        address: addr.to_vec(),
        balance: 1_000_000_000,
        ..Default::default()
    }
}

fn trigger(from: [u8; 21], to: [u8; 21]) -> TriggerSmartContract {
    TriggerSmartContract {
        owner_address: from.to_vec(),
        contract_address: to.to_vec(),
        call_value: 0,
        data: Vec::new(),
        call_token_value: 0,
        token_id: 0,
    }
}

#[test]
fn infinite_loop_without_deadline_halts_on_out_of_gas() {
    // Baseline: with no deadline, the loop eventually runs out of gas
    // and the VM returns Halt(OutOfGas, ...). This pins the control
    // sample so the deadline test below isn't comparing apples to
    // oranges — both tests run the same bytecode; only the entry
    // point differs.
    let stores = fresh_stores();
    let caller_addr = tron_addr(0xa1);
    let contract_addr = tron_addr(0xb1);
    stores
        .accounts
        .put(&Address::from_raw(caller_addr), &caller(caller_addr)).unwrap();
    install_contract(&stores, contract_addr, infinite_loop_bytecode());

    let block = VmBlockEnv {
        block_number: 1,
        block_timestamp_ms: 1_700_000_000_000,
    };
    let (outcome, _) = execute_trigger_with_gas_cap(
        &stores,
        block,
        &trigger(caller_addr, contract_addr),
        100_000, // small enough to halt fast
        50_000_000,
    );
    assert!(
        matches!(outcome, VmOutcome::Halt { .. }),
        "expected Halt(OutOfGas), got: {:?}",
        outcome
    );
}

#[test]
fn infinite_loop_with_tight_deadline_returns_timeout() {
    // A generous energy budget would let the loop run for many seconds
    // before exhausting; the deadline must trip first.
    let stores = fresh_stores();
    let caller_addr = tron_addr(0xa2);
    let contract_addr = tron_addr(0xb2);
    stores
        .accounts
        .put(&Address::from_raw(caller_addr), &caller(caller_addr)).unwrap();
    install_contract(&stores, contract_addr, infinite_loop_bytecode());

    let block = VmBlockEnv {
        block_number: 1,
        block_timestamp_ms: 1_700_000_000_000,
    };
    let timeout_ms: u64 = 100;
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let started = Instant::now();
    // Headroom sizing: each loop iter is JUMPDEST+PUSH1+JUMP = 12 gas.
    // At release-mode dispatch speed (~45M iters/sec on a modern CPU)
    // we burn ~540M gas in 100ms — the previous 50_000_000 limit was
    // marginal and OOG'd before the deadline on fast hardware (~4%
    // failure rate in release). Pick a budget 10× the 100ms-window
    // burn rate so the deadline wins by an order of magnitude even on
    // a 5× faster future CPU. Both args must be raised: `energy_limit`
    // is the sun-paid allowance, `gas_cap_override` is the per-tx VM
    // cap, and the effective limit is `min(energy_limit, cap)`.
    let (outcome, _) = execute_trigger_with_deadline(
        &stores,
        block,
        &trigger(caller_addr, contract_addr),
        5_000_000_000,
        5_000_000_000,
        deadline,
        timeout_ms,
    );
    let elapsed = started.elapsed();

    match outcome {
        VmOutcome::Timeout {
            deadline_ms,
            energy_used,
        } => {
            assert_eq!(deadline_ms, timeout_ms);
            assert!(
                energy_used > 0,
                "Timeout should report the energy spent up to the deadline"
            );
            // Allow generous slack — deadline check stride is 4096
            // opcodes, host scheduler can add ms-level noise, and CI
            // boxes can be slow. The point is the call DID return in
            // sub-second time, not 50_000_000-gas time (~10s).
            assert!(
                elapsed < Duration::from_millis(2_000),
                "VM should have preempted well before exhausting gas; elapsed={:?}",
                elapsed
            );
        }
        other => panic!("expected Timeout, got: {other:?}"),
    }
}

#[test]
fn already_elapsed_deadline_halts_essentially_immediately() {
    // Deadline that's already in the past — the first deadline check
    // must trip and halt before any meaningful work runs.
    let stores = fresh_stores();
    let caller_addr = tron_addr(0xa3);
    let contract_addr = tron_addr(0xb3);
    stores
        .accounts
        .put(&Address::from_raw(caller_addr), &caller(caller_addr)).unwrap();
    install_contract(&stores, contract_addr, infinite_loop_bytecode());

    let block = VmBlockEnv {
        block_number: 1,
        block_timestamp_ms: 1_700_000_000_000,
    };
    let deadline = Instant::now() - Duration::from_secs(1);
    let started = Instant::now();
    let (outcome, _) = execute_trigger_with_deadline(
        &stores,
        block,
        &trigger(caller_addr, contract_addr),
        50_000_000,
        50_000_000,
        deadline,
        0,
    );
    let elapsed = started.elapsed();
    assert!(
        matches!(outcome, VmOutcome::Timeout { .. }),
        "expected Timeout for already-past deadline; got: {:?}",
        outcome
    );
    // Should return within the first stride (~tens of µs). Allow 50ms
    // for slow CI.
    assert!(
        elapsed < Duration::from_millis(50),
        "Past deadline must trip on the first stride check; elapsed={:?}",
        elapsed
    );
}

#[test]
fn deadline_in_the_future_does_not_trip_for_short_call() {
    // A trivial successful contract (just STOP) with a generous
    // deadline must complete normally with VmOutcome::Success. Proves
    // we didn't break the happy path by adding the deadline check.
    let stores = fresh_stores();
    let caller_addr = tron_addr(0xa4);
    let contract_addr = tron_addr(0xb4);
    stores
        .accounts
        .put(&Address::from_raw(caller_addr), &caller(caller_addr)).unwrap();
    install_contract(&stores, contract_addr, vec![0x00]); // STOP

    let block = VmBlockEnv {
        block_number: 1,
        block_timestamp_ms: 1_700_000_000_000,
    };
    let deadline = Instant::now() + Duration::from_secs(60);
    let (outcome, _) = execute_trigger_with_deadline(
        &stores,
        block,
        &trigger(caller_addr, contract_addr),
        50_000_000,
        50_000_000,
        deadline,
        60_000,
    );
    assert!(
        matches!(outcome, VmOutcome::Success { .. }),
        "short STOP under generous deadline must succeed; got: {:?}",
        outcome
    );
}
