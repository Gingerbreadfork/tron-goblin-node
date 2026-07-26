//! Fork-session registry: lifecycle, snapshot/revert, head advancement,
//! LRU eviction, and id round-trip.

use std::sync::Arc;

use tron_chainbase::{KvBackend, MemBackend};
use tron_crypto::address::Address;

use tron_sim::{
    fork_id_from_hex, fork_id_hex, AccountOverride, BlockSpec, CallSpec, ForkBackends, ForkOverlay,
    OverrideSet, SimConfig, SimRequest, SimState,
};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn fork() -> ForkOverlay {
    let fb = ForkBackends {
        accounts: mem(),
        code: mem(),
        storage: mem(),
        witnesses: mem(),
        contract_state: mem(),
        dyn_props: mem(),
        delegated_resources: mem(),
        delegation: mem(),
        contracts: mem(),
        votes: Some(mem()),
        abi: Some(mem()),
        block_index: Some(mem()),
    };
    ForkOverlay::new(&fb, None).unwrap()
}

fn addr(n: u8) -> Address {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[20] = n;
    Address::from_raw(a)
}

/// A bundle: one block that sets `who`'s balance to `bal`, no calls.
fn set_balance(who: Address, bal: i64) -> SimRequest {
    let mut ovr = OverrideSet::default();
    ovr.accounts.insert(who, AccountOverride { balance: Some(bal), ..Default::default() });
    SimRequest {
        blocks: vec![BlockSpec { overrides: ovr, calls: Vec::new() }],
        ..Default::default()
    }
}

#[test]
fn fork_id_hex_round_trips() {
    let id = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let hex = fork_id_hex(&id);
    assert_eq!(hex.len(), 32);
    assert_eq!(fork_id_from_hex(&hex), Some(id));
    assert_eq!(fork_id_from_hex(&format!("0x{hex}")), Some(id));
    assert_eq!(fork_id_from_hex("nope"), None);
}

#[test]
fn create_get_delete_lifecycle() {
    let ss = SimState::new(SimConfig::default());
    let id = ss.create(fork());
    assert!(ss.get(&id).is_some());
    assert_eq!(ss.list().len(), 1);
    assert!(ss.delete(&id));
    assert!(ss.get(&id).is_none());
    assert!(!ss.delete(&id));
}

#[test]
fn successive_calls_advance_the_head() {
    let ss = SimState::new(SimConfig::default());
    let id = ss.create(fork());
    let f = ss.get(&id).unwrap();
    let cfg = SimConfig::default();

    let mut g = f.lock().unwrap();
    let r1 = g.run(&set_balance(addr(1), 10), &cfg).unwrap();
    let n1 = r1.blocks[0].number;
    let r2 = g.run(&set_balance(addr(1), 20), &cfg).unwrap();
    let n2 = r2.blocks[0].number;
    assert!(n2 > n1, "second call must continue numbering: {n1} then {n2}");
}

#[test]
fn snapshot_and_revert_restore_state() {
    let ss = SimState::new(SimConfig::default());
    let id = ss.create(fork());
    let f = ss.get(&id).unwrap();
    let cfg = SimConfig::default();
    let x = addr(2);

    let mut g = f.lock().unwrap();
    g.run(&set_balance(x, 100), &cfg).unwrap();
    let snap = g.snapshot();
    g.run(&set_balance(x, 999), &cfg).unwrap();

    // Before revert: balance is 999.
    let d = g.state_diff().unwrap();
    let after = d
        .accounts
        .iter()
        .find(|a| a.address == Some(x))
        .and_then(|a| a.after.as_ref())
        .map(|acct| acct.balance);
    assert_eq!(after, Some(999));

    g.revert(snap).unwrap();

    // After revert: back to 100.
    let d = g.state_diff().unwrap();
    let after = d
        .accounts
        .iter()
        .find(|a| a.address == Some(x))
        .and_then(|a| a.after.as_ref())
        .map(|acct| acct.balance);
    assert_eq!(after, Some(100));

    // The consumed snapshot can't be reverted to again.
    assert!(g.revert(snap).is_err());
}

#[test]
fn fork_id_from_hex_rejects_non_ascii_without_panic() {
    // 32 BYTES but with a multi-byte UTF-8 char: must return None, never panic
    // on a non-char-boundary slice.
    let s = format!("a\u{0800}{}", "b".repeat(28)); // 1 + 3 + 28 = 32 bytes
    assert_eq!(s.len(), 32);
    assert_eq!(fork_id_from_hex(&s), None);
    // A valid all-ASCII id still round-trips.
    let id = [9u8; 16];
    assert_eq!(fork_id_from_hex(&fork_id_hex(&id)), Some(id));
}

#[test]
fn fork_session_deploys_get_distinct_addresses_across_calls() {
    // Regression: two Create calls in SEPARATE forkCalls on the same session
    // must derive DIFFERENT contract addresses (tx-id folds the advancing
    // synthetic block number, not a bundle-local index).
    let ss = SimState::new(SimConfig { enabled: true, ..Default::default() });
    let id = ss.create(fork());
    let f = ss.get(&id).unwrap();
    let cfg = SimConfig::default();
    let deployer = addr(0x30);

    let deploy = || {
        let mut o = OverrideSet::default();
        o.accounts
            .insert(deployer, AccountOverride { balance: Some(1_000_000_000), ..Default::default() });
        SimRequest {
            blocks: vec![BlockSpec {
                overrides: o,
                calls: vec![CallSpec::Create {
                    from: deployer,
                    init_code: vec![0x60, 0x00, 0x60, 0x00, 0x52, 0x60, 0x01, 0x60, 0x1f, 0xf3],
                    value: 0,
                    energy: Some(2_000_000),
                    consume_user_resource_percent: 100,
                    name: String::new(),
                    token_id: 0,
                    token_value: 0,
                }],
            }],
            ..Default::default()
        }
    };

    let mut g = f.lock().unwrap();
    let a1 = g.run(&deploy(), &cfg).unwrap().blocks[0].calls[0].contract_address;
    let a2 = g.run(&deploy(), &cfg).unwrap().blocks[0].calls[0].contract_address;
    assert!(a1.is_some() && a2.is_some(), "both deploys must succeed");
    assert_ne!(a1, a2, "deploys in separate forkCalls must not collide on an address");
}

#[test]
fn lru_eviction_at_capacity() {
    let ss = SimState::new(SimConfig { max_forks: 2, ..Default::default() });
    let a = ss.create(fork());
    let _b = ss.create(fork());
    let c = ss.create(fork());
    // Capacity 2: creating the third evicts the least-recently-used (a).
    assert_eq!(ss.list().len(), 2);
    assert!(ss.get(&c).is_some());
    assert!(ss.get(&a).is_none(), "the oldest fork should have been evicted");
}
