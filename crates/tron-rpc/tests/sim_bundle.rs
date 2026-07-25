//! Chronos JSON-RPC integration: `tron_simulateBundle` and the `tron_fork*`
//! lifecycle over a MemBackend-backed archive + fork registry.

use std::sync::Arc;

use serde_json::{json, Value};
use tron_chainbase::{KvBackend, MemBackend, UndoStoreId};
use tron_crypto::address::Address;
use tron_index::ArchiveWriter;
use tron_rpc::{ArchiveApiState, RpcState};
use tron_sim::{SimConfig, SimState};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn addr58(n: u8) -> String {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[20] = n;
    tron_crypto::base58check::encode_address(&Address::from_raw(a))
}

/// RpcState with a full-store archive (latest base needs no coverage) and an
/// enabled Chronos registry.
fn state(sim_enabled: bool) -> RpcState {
    use UndoStoreId as Id;
    let accounts = mem();
    let dyn_props = mem();
    let backends: Vec<(UndoStoreId, Arc<dyn KvBackend>)> = vec![
        (Id::Accounts, accounts.clone()),
        (Id::Code, mem()),
        (Id::StorageRow, mem()),
        (Id::Witnesses, mem()),
        (Id::ContractState, mem()),
        (Id::DynProps, dyn_props.clone()),
        (Id::DelegatedResources, mem()),
        (Id::Delegation, mem()),
        (Id::Contracts, mem()),
        (Id::Votes, mem()),
        (Id::Abi, mem()),
        (Id::BlockIndex, mem()),
    ];
    let writer = ArchiveWriter::new(mem(), None, backends.clone());
    writer.check_or_init().unwrap();

    let mut st = RpcState::new(accounts, mem(), mem(), mem(), dyn_props, 11_111)
        .with_archive(ArchiveApiState::new(writer.reader(), backends));
    if sim_enabled {
        let sim = Arc::new(SimState::new(SimConfig { enabled: true, ..Default::default() }));
        st = st.with_sim(sim);
    }
    st
}

/// A bundle payload: fund `caller`, install SSTORE(0,0x2a) code on `contract`,
/// then trigger it.
fn sstore_bundle(caller: &str, contract: &str) -> Value {
    json!([{
        "base": { "tag": "latest" },
        "trace": "full",
        "returnStateDiff": "final",
        "blocks": [{
            "overrides": {
                "accounts": {
                    caller: { "balance": 1_000_000_000i64 },
                    contract: { "code": "0x602a60005500" }
                }
            },
            "calls": [
                { "type": "trigger", "ownerAddress": caller, "contractAddress": contract,
                  "data": "0x", "energy": 1_000_000 }
            ]
        }]
    }])
}

#[test]
fn simulate_bundle_runs_mutating_call_and_diffs() {
    let st = state(true);
    let params = sstore_bundle(&addr58(0x11), &addr58(0x10));
    let res = tron_rpc::sim::tron_simulate_bundle(&params, &st).expect("bundle ok");

    assert_eq!(res["basis"]["mode"], "vm");
    assert_eq!(res["basis"]["granularity"], "block-boundary");
    let call = &res["blocks"][0]["calls"][0];
    assert_eq!(call["status"], "SUCCESS", "call: {call}");
    // Full trace populated.
    assert!(call["structLogs"].as_array().map(|a| !a.is_empty()).unwrap_or(false));
    // Storage diff shows the SSTORE of 0x2a.
    let storage = res["stateDiff"]["storage"].as_array().unwrap();
    assert!(
        storage.iter().any(|s| s["after"].as_str().map(|x| x.ends_with("2a")).unwrap_or(false)),
        "expected SSTORE 0x2a in {storage:?}"
    );
}

#[test]
fn simulate_bundle_disabled_errors() {
    let st = state(false);
    let params = sstore_bundle(&addr58(0x11), &addr58(0x10));
    let err = tron_rpc::sim::tron_simulate_bundle(&params, &st).unwrap_err();
    assert!(err.message.to_lowercase().contains("not available"), "msg: {}", err.message);
}

#[test]
fn fork_lifecycle_create_call_snapshot_revert_delete() {
    let st = state(true);
    let caller = addr58(0x21);
    let contract = addr58(0x20);

    // Create a fork.
    let created = tron_rpc::sim::tron_fork_create(&json!([{ "base": { "tag": "latest" } }]), &st)
        .expect("create");
    let fork_id = created["forkId"].as_str().unwrap().to_string();

    // Call it: install code + run SSTORE.
    let call_body = json!([fork_id, {
        "trace": "none",
        "returnStateDiff": "final",
        "blocks": [{
            "overrides": { "accounts": {
                caller.clone(): { "balance": 1_000_000_000i64 },
                contract.clone(): { "code": "0x602a60005500" }
            }},
            "calls": [{ "type": "trigger", "ownerAddress": caller, "contractAddress": contract,
                        "data": "0x", "energy": 1_000_000 }]
        }]
    }]);
    let r = tron_rpc::sim::tron_fork_call(&call_body, &st).expect("call");
    assert_eq!(r["blocks"][0]["calls"][0]["status"], "SUCCESS");

    // Snapshot, then check the diff is non-empty via forkStateDiff.
    let snap = tron_rpc::sim::tron_fork_snapshot(&json!([fork_id]), &st).expect("snapshot");
    let snap_id = snap["snapshotId"].as_u64().unwrap();

    let diff_before = tron_rpc::sim::tron_fork_state_diff(&json!([fork_id]), &st).expect("diff");
    assert!(diff_before["totalChangedKeys"].as_u64().unwrap() > 0);

    // Revert to the snapshot (nothing was written after it, but it must succeed).
    let reverted = tron_rpc::sim::tron_fork_revert(&json!([fork_id, snap_id]), &st).expect("revert");
    assert_eq!(reverted["reverted"], true);

    // List shows the fork; delete removes it.
    let list = tron_rpc::sim::tron_fork_list(&json!([]), &st).expect("list");
    assert_eq!(list.as_array().unwrap().len(), 1);
    let del = tron_rpc::sim::tron_fork_delete(&json!([fork_id]), &st).expect("delete");
    assert_eq!(del["deleted"], true);
    // Calling a deleted fork errors.
    assert!(tron_rpc::sim::tron_fork_call(&call_body, &st).is_err());
}

#[test]
fn historical_base_out_of_coverage_is_rejected() {
    let st = state(true);
    // No blocks were applied to the archive → any historical height is
    // out of coverage.
    let params = json!([{ "base": { "block": 5 }, "blocks": [{ "calls": [] }] }]);
    let err = tron_rpc::sim::tron_simulate_bundle(&params, &st).unwrap_err();
    let m = err.message.to_lowercase();
    assert!(m.contains("coverage"), "msg: {}", err.message);
}
