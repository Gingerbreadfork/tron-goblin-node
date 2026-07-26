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

fn self_check_case(contract_code: &[u8], recorded_ret: i32) -> serde_json::Value {
    use prost::Message;
    use tron_chainbase::{AccountStore, BlockIndexStore, BlockStore};
    use tron_proto::transaction::{contract::ContractType, Contract as TxContract, Raw as TxRaw};
    use tron_proto::{Account, Block, BlockHeader, Transaction, TriggerSmartContract};
    use tron_types::BlockId;

    use UndoStoreId as Id;
    let base = 100i64;

    // Live backends.
    let accounts = mem();
    let code = mem();
    let dyn_props = mem();
    let blocks_be = mem();
    let block_index_be = mem();

    let mut caller = [0u8; 21];
    caller[0] = 0x41;
    caller[20] = 0x41;
    let mut contract = [0u8; 21];
    contract[0] = 0x41;
    contract[20] = 0x40;

    // Contract code — live; the at-height read falls through since it was
    // never captured as a delta.
    code.put(&contract, contract_code).unwrap();
    // Caller account with balance.
    let caller_acct = Account { address: caller.to_vec(), balance: 1_000_000_000, ..Default::default() };
    AccountStore::new(accounts.clone())
        .put(&tron_crypto::address::Address::from_raw(caller), &caller_acct)
        .unwrap();
    // Contract ACCOUNT row — a real contract has one; without it basic_ref
    // returns None and the CALL runs empty code (trivial success). This is
    // what makes the re-run actually execute `contract_code`.
    let contract_acct = Account {
        address: contract.to_vec(),
        code_hash: tron_crypto::hash::keccak256(contract_code).to_vec(),
        r#type: tron_proto::AccountType::Contract as i32,
        ..Default::default()
    };
    AccountStore::new(accounts.clone())
        .put(&tron_crypto::address::Address::from_raw(contract), &contract_acct)
        .unwrap();

    // Archive: full store set + coverage established at `base` (a caller delta).
    let backends: Vec<(UndoStoreId, Arc<dyn KvBackend>)> = vec![
        (Id::Accounts, accounts.clone()),
        (Id::Code, code.clone()),
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
    let caller_bytes = caller_acct.encode_to_vec();
    writer
        .on_block_applied(
            base,
            Some(&[tron_index::DeltaRef {
                store: Id::Accounts,
                key: &caller,
                before: None,
                after: Some(&caller_bytes),
            }]),
        )
        .unwrap();

    // Block N+1 with an index-0 TriggerSmartContract calling the contract,
    // recorded as SUCCESS (contract_ret = 1).
    let trigger = TriggerSmartContract {
        owner_address: caller.to_vec(),
        contract_address: contract.to_vec(),
        data: vec![],
        call_value: 0,
        call_token_value: 0,
        token_id: 0,
    };
    let tx = Transaction {
        raw_data: Some(TxRaw {
            contract: vec![TxContract {
                r#type: ContractType::TriggerSmartContract as i32,
                parameter: Some(prost_types::Any {
                    type_url: "type.googleapis.com/protocol.TriggerSmartContract".into(),
                    value: trigger.encode_to_vec(),
                }),
                ..Default::default()
            }],
            fee_limit: 1_000_000_000,
            timestamp: 1_700_000_000_000,
            ..Default::default()
        }),
        signature: vec![],
        ret: vec![tron_proto::transaction::Result {
            contract_ret: recorded_ret,
            ..Default::default()
        }],
        unparsed_field10: None,
    };
    let block = Block {
        transactions: vec![tx],
        block_header: Some(BlockHeader {
            raw_data: Some(tron_proto::block_header::Raw {
                number: base + 1,
                timestamp: 1_700_000_000_000,
                ..Default::default()
            }),
            witness_signature: vec![],
        }),
    };
    let bid = BlockId::from_hash_and_num(&[7u8; 32], (base + 1) as u64);
    BlockStore::new(blocks_be.clone()).put(&bid, &block).unwrap();
    BlockIndexStore::new(block_index_be.clone()).put(&bid).unwrap();

    let sim = Arc::new(SimState::new(SimConfig { enabled: true, ..Default::default() }));
    let st = RpcState::new(accounts, blocks_be, block_index_be, mem(), dyn_props, 11_111)
        .with_archive(ArchiveApiState::new(writer.reader(), backends))
        .with_sim(sim);

    let params = json!([{ "base": { "block": base }, "selfCheck": true, "blocks": [{ "calls": [] }] }]);
    let res = tron_rpc::sim::tron_simulate_bundle(&params, &st).expect("bundle");
    res["selfCheck"].clone()
}

#[test]
fn self_check_matches_success() {
    // SSTORE 0x2a @ slot 0 → SUCCESS, recorded SUCCESS.
    let sc = self_check_case(
        &[0x60, 0x2a, 0x60, 0x00, 0x55, 0x00],
        tron_proto::transaction::result::ContractResult::Success as i32,
    );
    assert_eq!(sc["checked"], 1, "selfCheck: {sc}");
    assert_eq!(sc["matched"], true, "selfCheck: {sc}");
    assert_eq!(sc["ourStatus"], "SUCCESS");
    assert_eq!(sc["recordedContractRet"], "SUCCESS");
}

#[test]
fn self_check_matches_revert_class() {
    // PUSH1 0 PUSH1 0 REVERT → REVERT, recorded REVERT — class parity, not
    // collapsed into a generic "failure" bucket.
    let sc = self_check_case(
        &[0x60, 0x00, 0x60, 0x00, 0xfd],
        tron_proto::transaction::result::ContractResult::Revert as i32,
    );
    assert_eq!(sc["checked"], 1, "selfCheck: {sc}");
    assert_eq!(sc["matched"], true, "selfCheck: {sc}");
    assert_eq!(sc["ourStatus"], "REVERT");
    assert_eq!(sc["recordedContractRet"], "REVERT");
}

fn eth20(n: u8) -> String {
    let mut b = [0u8; 20];
    b[19] = n;
    format!("0x{}", hex::encode(b))
}

#[test]
fn eth_simulate_v1_supports_code_override_and_creation() {
    let st = state(true);
    let contract = eth20(0x30);
    let caller = eth20(0x31);
    let params = json!([
        {
            "blockStateCalls": [{
                "stateOverrides": {
                    caller.clone(): { "balance": "0x3b9aca00" },
                    contract.clone(): { "code": "0x602a60005500" }
                },
                "calls": [
                    { "from": caller.clone(), "to": contract, "input": "0x", "gas": "0xf4240" },
                    // No `to` => contract creation (init returns a 0x00 runtime).
                    { "from": caller, "input": "0x60006000526001601ff3", "gas": "0x1e8480" }
                ]
            }]
        },
        "latest"
    ]);
    let res = tron_rpc::eth_simulate::eth_simulate_v1(&params, &st).expect("eth_simulateV1");
    let calls = res[0]["calls"].as_array().unwrap();
    assert_eq!(calls[0]["status"], "0x1", "override+trigger: {}", calls[0]);
    assert_eq!(calls[1]["status"], "0x1", "creation: {}", calls[1]);
    assert!(calls[1]["contractAddress"].is_string(), "creation must report contractAddress");
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
