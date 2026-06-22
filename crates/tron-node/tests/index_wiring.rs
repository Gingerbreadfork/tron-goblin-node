//! End-to-end wiring test for the address-history index: a block with
//! a real VM Transfer-log execution flows through `SyncDriver` with
//! the index hook attached → the hook persists `TransactionRet` →
//! the index engine derives rows from the stores → the reader serves
//! them. This is the production data path (store-as-the-queue), minus
//! the network.

use std::sync::Arc;
use std::time::Duration;

use prost::Message;
use prost_types::Any;
use tron_chainbase::{
    AccountStore, CodeStore, ContractStore, KvBackend, MemBackend, TransactionRetStore,
    WitnessScheduleStore,
};
use tron_crypto::address::Address;
use tron_executor::StateBackends;
use tron_index::{CaptureSet, EngineOptions, IndexDb, IndexEngine, IndexReader, PageQuery, Tick};
use tron_node::index_hook::IndexHook;
use tron_node::sync::{AcceptOutcome, SyncConfig, SyncDriver};
use tron_proto::{
    transaction::{contract::ContractType, Contract as TxContract, Raw as TxRaw},
    Account, Block, BlockHeader, SmartContract, Transaction, TriggerSmartContract,
};
use tron_types::{block_id_from_block, sign_block};

const TRANSFER_TOPIC0: [u8; 32] = [
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d, 0xaa,
    0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef,
];

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn caller_keypair(seed: u8) -> ([u8; 32], [u8; 21]) {
    use tron_crypto::signature::RecoverableSignature;
    let mut priv_key = [0u8; 32];
    priv_key[0] = 0x10;
    priv_key[31] = seed;
    let dummy_hash = [0x42u8; 32];
    let sig = RecoverableSignature::sign_prehash(&priv_key, &dummy_hash).expect("sign");
    let pub_key = sig.recover_uncompressed_pubkey(&dummy_hash).expect("recover");
    let h = tron_crypto::hash::keccak256(&pub_key[1..]);
    let mut addr = [0u8; 21];
    addr[0] = 0x41;
    addr[1..].copy_from_slice(&h[12..]);
    (priv_key, addr)
}

fn fresh_state() -> (StateBackends, Arc<dyn KvBackend>) {
    let blocks_be = mem();
    let dyn_props_be = mem();
    // Seed the committed head (genesis/block 0) timestamp so the per-tx
    // expiration window (`Manager.validateCommon`: `expiration <= headTime`
    // and `expiration > headTime + 24h` both reject) has a realistic
    // reference when block 1 is applied. The test txs carry
    // `expiration = base + 86_400_000`, which sits exactly at the accepted
    // upper bound for `base = 1_700_000_000_000` (the `>` check is strict).
    tron_chainbase::DynamicPropertiesStore::new(dyn_props_be.clone())
        .save_latest_block_header_timestamp(1_700_000_000_000);
    (
        StateBackends {
            accounts: mem(),
            witnesses: mem(),
            votes: mem(),
            delegation: mem(),
            delegated_resources: mem(),
            delegated_resource_account_index: None,
            dyn_props: dyn_props_be,
            proposals: mem(),
            name_index: mem(),
            id_index: mem(),
            asset_v1: mem(),
            asset_v2: mem(),
            contracts: mem(),
            abi: mem(),
            exchange_v1: mem(),
            exchange_v2: mem(),
            market_orders: mem(),
            market_account: mem(),
            nullifiers: mem(),
            merkle_trees: None,
            code: Some(mem()),
            storage_row: Some(mem()),
            contract_state: Some(mem()),
            block_index: Some(mem()),
            witness_schedule: Some(mem()),
            reward_vi: None,
    },
        blocks_be,
    )
}

/// Runtime bytecode: LOG3 `Transfer(0x..11 → 0x..22, 1000)` then STOP.
fn transfer_log_bytecode() -> Vec<u8> {
    let mut from_padded = [0u8; 32];
    from_padded[12..].copy_from_slice(&[0x11u8; 20]);
    let mut to_padded = [0u8; 32];
    to_padded[12..].copy_from_slice(&[0x22u8; 20]);
    let mut value_padded = [0u8; 32];
    value_padded[30] = 0x03;
    value_padded[31] = 0xe8;

    let mut bc = Vec::new();
    bc.push(0x7f);
    bc.extend_from_slice(&value_padded);
    bc.extend_from_slice(&[0x60, 0x00, 0x52]); // PUSH1 0; MSTORE
    bc.push(0x7f);
    bc.extend_from_slice(&to_padded);
    bc.push(0x7f);
    bc.extend_from_slice(&from_padded);
    bc.push(0x7f);
    bc.extend_from_slice(&TRANSFER_TOPIC0);
    bc.extend_from_slice(&[0x60, 0x20, 0x60, 0x00, 0xa3, 0x00]); // LOG3; STOP
    bc
}

fn build_trigger_tx(caller_priv: &[u8; 32], caller: [u8; 21], contract: [u8; 21]) -> Transaction {
    let trigger = TriggerSmartContract {
        owner_address: caller.to_vec(),
        contract_address: contract.to_vec(),
        ..Default::default()
    };
    let mut tx = Transaction {
        raw_data: Some(TxRaw {
            contract: vec![TxContract {
                r#type: ContractType::TriggerSmartContract as i32,
                parameter: Some(Any {
                    type_url: "type.googleapis.com/protocol.TriggerSmartContract".into(),
                    value: trigger.encode_to_vec(),
                }),
                ..Default::default()
            }],
            timestamp: 1_700_000_000_000,
            fee_limit: 100_000_000,
            ..Default::default()
        }),
        signature: Vec::new(),
        // Real producer blocks carry the contractRet verdict on the
        // included tx (it's part of the wire bytes the trie root
        // covers); the index's `success` flag reads it.
        ret: vec![tron_proto::transaction::Result {
            contract_ret: tron_proto::transaction::result::ContractResult::Success as i32,
            ..Default::default()
        }],
        unparsed_field10: None,
    };
    tron_types::sign_transaction(&mut tx, caller_priv).expect("sign");
    tx
}

fn build_block(
    num: i64,
    parent: [u8; 32],
    witness: [u8; 21],
    witness_priv: &[u8; 32],
    txs: Vec<Transaction>,
) -> Block {
    let mut block = Block {
        block_header: Some(BlockHeader {
            raw_data: Some(tron_proto::block_header::Raw {
                number: num,
                parent_hash: parent.to_vec(),
                timestamp: 1_700_000_000_000 + num * 3000,
                tx_trie_root: tron_types::calc_tx_trie_root(&txs)
                    .map(|h| h.to_vec())
                    .unwrap_or_default(),
                witness_address: witness.to_vec(),
                witness_id: 0,
                version: 28,
                account_state_root: Vec::new(),
            }),
            witness_signature: Vec::new(),
        }),
        transactions: txs,
    };
    sign_block(&mut block, witness_priv).expect("sign block");
    block
}

#[test]
fn applied_block_flows_through_hook_engine_and_reader() {
    let (caller_priv, caller) = caller_keypair(0xc4);
    let mut contract_addr = [0u8; 21];
    contract_addr[0] = 0x41;
    contract_addr[1..].fill(0xd1);

    let (state, blocks_be) = fresh_state();
    AccountStore::new(state.accounts.clone())
        .put(
            &Address::from_raw(caller),
            &Account { address: caller.to_vec(), balance: 1_000_000_000, ..Default::default() },
        )
        .unwrap();
    let bytecode = transfer_log_bytecode();
    let code_hash = tron_crypto::hash::keccak256(&bytecode);
    CodeStore::new(state.code.as_ref().unwrap().clone())
        .put(&code_hash, &bytecode)
        .unwrap();
    AccountStore::new(state.accounts.clone())
        .put(
            &Address::from_raw(contract_addr),
            &Account {
                address: contract_addr.to_vec(),
                code: bytecode.clone(),
                code_hash: code_hash.to_vec(),
                ..Default::default()
            },
        )
        .unwrap();
    ContractStore::new(state.contracts.clone())
        .put(
            &Address::from_raw(contract_addr),
            &SmartContract {
                origin_address: caller.to_vec(),
                contract_address: contract_addr.to_vec(),
                ..Default::default()
            },
        )
        .unwrap();
    WitnessScheduleStore::new(state.witness_schedule.as_ref().unwrap().clone())
        .save_active(&[Address::from_raw(caller)])
        .unwrap();

    // The hook (what runtime.rs attaches when [index] enable = true).
    let txret_be = mem();
    let hook = Arc::new(IndexHook::new(txret_be.clone()));

    let cfg = SyncConfig {
        peers: vec![],
        max_blocks: None,
        tail_interval: Duration::from_millis(1),
        initial_backoff: Duration::from_millis(1),
        blocks_backend: blocks_be.clone(),
        progress_log_interval: 0,
        advertise_port: 18_888,
        tip_test: false,
        p2p_rate_limits: Default::default(),
        fetch_block_timeout: Duration::from_millis(200),
        fetch_inflight_per_peer: 64,
        peer_is_fast_forward: false,
        follow_tip: false,
    };
    let block_index_be = state.block_index.as_ref().unwrap().clone();
    let dyn_props_be = state.dyn_props.clone();
    let mut driver = SyncDriver::new(state, cfg).with_index_hook(hook.clone());

    let tx = build_trigger_tx(&caller_priv, caller, contract_addr);
    let block = build_block(1, [0u8; 32], caller, &caller_priv, vec![tx]);
    let id = block_id_from_block(&block).unwrap();
    let outcome = driver.accept_block(&block, None);
    assert!(matches!(outcome, AcceptOutcome::Accepted(_)), "got {outcome:?}");

    // 1. The hook persisted the block's transaction-info with the
    //    decoded Transfer log.
    let ret = TransactionRetStore::new(txret_be.clone())
        .get(1)
        .unwrap()
        .expect("txinfo persisted at apply");
    assert_eq!(ret.transactioninfo.len(), 1);
    let info = &ret.transactioninfo[0];
    assert_eq!(info.block_number, 1);
    assert_eq!(info.log.len(), 1, "the VM Transfer log is in stored txinfo");
    assert_eq!(info.log[0].topics[0], TRANSFER_TOPIC0.to_vec());
    // The resource receipt is captured from real execution: the wire
    // bytes were quota/fee charged (net side) and the VM's energy was
    // billed to the caller (no frozen energy → TRX fee path).
    let receipt = info.receipt.as_ref().expect("receipt captured at execution");
    assert!(receipt.energy_usage_total > 0, "VM consumed energy: {receipt:?}");
    assert!(receipt.energy_fee > 0, "caller paid the energy in TRX: {receipt:?}");
    assert!(receipt.net_usage > 0, "VM txs pay bandwidth for their wire bytes: {receipt:?}");
    assert_eq!(
        receipt.result,
        tron_proto::transaction::result::ContractResult::Success as i32
    );
    assert_eq!(info.fee, receipt.net_fee + receipt.energy_fee);

    // 2. The engine (over the very same stores) indexes the block.
    let caps = CaptureSet { native: true, trc20: true, trc721: true, internal: true, logs: false, callee_contract: false };
    let opts = EngineOptions { head_first: false, ..Default::default() };
    let index_be = mem();
    let db = IndexDb::new(index_be.clone());
    db.check_or_init(caps.fingerprint(0)).unwrap();
    let engine = IndexEngine::new(
        db.clone(),
        blocks_be.clone(),
        block_index_be.clone(),
        txret_be,
        dyn_props_be.clone(),
        caps,
        opts,
    );
    for _ in 0..100 {
        if matches!(engine.tick().unwrap(), Tick::Parked) {
            break;
        }
    }
    let status = engine.status();
    assert_eq!(status.cursor, Some(1));
    assert!(status.at_tip && status.backfill_complete);

    // 3. The reader serves the caller's native history and the log
    //    parties' TRC20 history.
    let reader = IndexReader::new(db, blocks_be, block_index_be, dyn_props_be);
    let native = reader
        .native_page(&caller, &PageQuery { limit: 10, ..Default::default() })
        .unwrap();
    assert_eq!(native.rows.len(), 1);
    assert_eq!(native.rows[0].row.txid.len(), 32);
    assert_eq!(
        native.rows[0].row.contract_type,
        ContractType::TriggerSmartContract as i32
    );
    assert!(native.rows[0].row.success);

    let mut log_from = [0u8; 21];
    log_from[0] = 0x41;
    log_from[1..].fill(0x11);
    let trc20 = reader
        .trc20_page(&log_from, &PageQuery { limit: 10, ..Default::default() })
        .unwrap();
    assert_eq!(trc20.rows.len(), 1, "Transfer log indexed under the from-party");
    assert_eq!(trc20.rows[0].row.token, contract_addr.to_vec());
    assert_eq!(trc20.rows[0].row.direction, tron_index::DIR_FROM);
    // amount = 1000 (0x3e8), raw 32-byte BE.
    assert_eq!(trc20.rows[0].row.amount[30..], [0x03, 0xe8]);

    let _ = id;
}

/// The by-id RPC fallbacks over the hook-written stores: the hook
/// persists tx-id → block-num refs (`trans`) and the block-keyed
/// `TransactionRet`; an `RpcState` with no tx-history store then
/// resolves `gettransactioninfobyid` through BlockRef → ret store,
/// serves `gettransactioninfobyblocknum` straight from the ret store,
/// and hydrates `gettransactionbyid`'s full body from the canonical
/// block instead of the block-ref stub.
#[test]
fn rpc_by_id_fallbacks_resolve_through_hook_written_stores() {
    use serde_json::{json, Value};
    use tron_rpc::methods;

    let (caller_priv, caller) = caller_keypair(0xc7);
    let mut contract_addr = [0u8; 21];
    contract_addr[0] = 0x41;
    contract_addr[1..].fill(0xd2);

    let (state, blocks_be) = fresh_state();
    AccountStore::new(state.accounts.clone())
        .put(
            &Address::from_raw(caller),
            &Account { address: caller.to_vec(), balance: 1_000_000_000, ..Default::default() },
        )
        .unwrap();
    let bytecode = transfer_log_bytecode();
    let code_hash = tron_crypto::hash::keccak256(&bytecode);
    CodeStore::new(state.code.as_ref().unwrap().clone())
        .put(&code_hash, &bytecode)
        .unwrap();
    AccountStore::new(state.accounts.clone())
        .put(
            &Address::from_raw(contract_addr),
            &Account {
                address: contract_addr.to_vec(),
                code: bytecode.clone(),
                code_hash: code_hash.to_vec(),
                ..Default::default()
            },
        )
        .unwrap();
    ContractStore::new(state.contracts.clone())
        .put(
            &Address::from_raw(contract_addr),
            &SmartContract {
                origin_address: caller.to_vec(),
                contract_address: contract_addr.to_vec(),
                ..Default::default()
            },
        )
        .unwrap();
    WitnessScheduleStore::new(state.witness_schedule.as_ref().unwrap().clone())
        .save_active(&[Address::from_raw(caller)])
        .unwrap();

    // The production hook wiring: ret store AND tx block-refs.
    let txret_be = mem();
    let trans_be = mem();
    let hook = Arc::new(IndexHook::new(txret_be.clone()).with_tx_refs(trans_be.clone()));

    let cfg = SyncConfig {
        peers: vec![],
        max_blocks: None,
        tail_interval: Duration::from_millis(1),
        initial_backoff: Duration::from_millis(1),
        blocks_backend: blocks_be.clone(),
        progress_log_interval: 0,
        advertise_port: 18_888,
        tip_test: false,
        p2p_rate_limits: Default::default(),
        fetch_block_timeout: Duration::from_millis(200),
        fetch_inflight_per_peer: 64,
        peer_is_fast_forward: false,
        follow_tip: false,
    };
    let accounts_be = state.accounts.clone();
    let block_index_be = state.block_index.as_ref().unwrap().clone();
    let dyn_props_be = state.dyn_props.clone();
    let mut driver = SyncDriver::new(state, cfg).with_index_hook(hook);

    let tx = build_trigger_tx(&caller_priv, caller, contract_addr);
    let tx_id =
        tron_crypto::hash::sha256(&tx.raw_data.as_ref().unwrap().encode_to_vec());
    let block = build_block(1, [0u8; 32], caller, &caller_priv, vec![tx]);
    assert!(matches!(driver.accept_block(&block, None), AcceptOutcome::Accepted(_)));

    // RpcState over the same backends, deliberately WITHOUT a
    // tx-history store — the fallback paths are all that can answer.
    let rpc = tron_rpc::RpcState::new(
        accounts_be,
        blocks_be,
        block_index_be,
        trans_be,
        dyn_props_be,
        728_126_428,
    )
    .with_transaction_ret(txret_be);
    let bare_id: String = tx_id.iter().map(|b| format!("{b:02x}")).collect();
    let hex_id = format!("0x{bare_id}");

    // 1. gettransactioninfobyid: trans-store BlockRef → ret store.
    //    Rendered java-JsonFormat style (STATE-3): bare-hex id, proto
    //    field names, omit-defaults.
    let info = methods::get_transaction_info_by_id(&json!([hex_id]), &rpc).unwrap();
    assert_eq!(info["id"], json!(bare_id), "info resolved via block-ref fallback: {info}");
    assert_eq!(info["blockNumber"], json!(1));
    assert!(
        info["receipt"]["energy_usage_total"].as_i64().unwrap() > 0,
        "receipt rode through the fallback: {info}"
    );
    assert_eq!(info["log"].as_array().unwrap().len(), 1, "VM log served: {info}");

    // 2. gettransactioninfobyblocknum: whole block from the ret store.
    let infos = methods::get_transaction_info_by_block_num(&json!([1]), &rpc).unwrap();
    let infos = infos.as_array().expect("array");
    assert_eq!(infos.len(), 1);
    assert_eq!(infos[0]["id"], json!(bare_id));

    // 3. gettransactionbyid: BlockRef hydrates the full body from the
    //    canonical block — not the "block_ref_only" stub.
    let tx_json = methods::get_transaction_by_id(&json!([hex_id]), &rpc).unwrap();
    assert_eq!(tx_json["txID"], json!(hex_id));
    assert!(tx_json.get("status").is_none(), "full body, not the stub: {tx_json}");
    assert_eq!(
        tx_json["raw_data"]["contract"][0]["type"],
        json!(ContractType::TriggerSmartContract.as_str_name())
    );
    // Contract is decoded to the full java/TronGrid shape, not a lossy summary.
    assert!(
        tx_json["raw_data"]["contract"][0]["parameter"]["value"].is_object(),
        "decoded parameter.value present: {tx_json}"
    );
    assert!(!tx_json["signature"].as_array().unwrap().is_empty());

    // 4. Unknown id stays null/empty rather than erroring.
    let missing = format!("0x{}", "ee".repeat(32));
    assert_eq!(methods::get_transaction_info_by_id(&json!([missing.clone()]), &rpc).unwrap(), Value::Null);
    assert_eq!(methods::get_transaction_by_id(&json!([missing]), &rpc).unwrap(), Value::Null);
}

/// P2 end-to-end: real TransferContract blocks flow through
/// SyncDriver (with `capture_state_deltas` on) → hook → archive
/// writer, and historical balances read back exactly at every height
/// through the at-height backend view.
#[test]
fn applied_blocks_archive_historical_state_exactly() {
    use tron_chainbase::{AccountStore, BlockUndoStore, DynamicPropertiesStore, UndoStoreId};
    use tron_index::{ArchiveAtBackend, ArchiveWriter};

    let (alice_priv, alice) = caller_keypair(0xa7);
    let (_bob_priv, bob) = caller_keypair(0xb8);

    let (state, blocks_be) = fresh_state();
    AccountStore::new(state.accounts.clone())
        .put(
            &Address::from_raw(alice),
            &tron_proto::Account {
                address: alice.to_vec(),
                balance: 1_000_000,
                ..Default::default()
            },
        )
        .unwrap();
    WitnessScheduleStore::new(state.witness_schedule.as_ref().unwrap().clone())
        .save_active(&[Address::from_raw(alice)])
        .unwrap();

    // Archive writer fed by the hook, exactly as runtime.rs wires it.
    let undo_be = mem();
    let archive_be = mem();
    let writer = Arc::new(ArchiveWriter::new(
        archive_be,
        Some(BlockUndoStore::new(undo_be.clone())),
        vec![
            (UndoStoreId::Accounts, state.accounts.clone()),
            (UndoStoreId::DynProps, state.dyn_props.clone()),
        ],
    ));
    writer.check_or_init().unwrap();
    let hook = Arc::new(IndexHook::new(mem()).with_archive(writer.clone()));

    let cfg = SyncConfig {
        peers: vec![],
        max_blocks: None,
        tail_interval: Duration::from_millis(1),
        initial_backoff: Duration::from_millis(1),
        blocks_backend: blocks_be.clone(),
        progress_log_interval: 0,
        advertise_port: 18_888,
        tip_test: false,
        p2p_rate_limits: Default::default(),
        fetch_block_timeout: Duration::from_millis(200),
        fetch_inflight_per_peer: 64,
        peer_is_fast_forward: false,
        follow_tip: false,
    };
    let accounts_be = state.accounts.clone();
    let dyn_props_be = state.dyn_props.clone();
    let mut driver = SyncDriver::new(state, cfg)
        .with_index_hook(hook)
        .with_undo_store(BlockUndoStore::new(undo_be))
        .with_exec_config(tron_executor::ExecConfig {
            capture_state_deltas: true,
            ..Default::default()
        });

    fn transfer(priv_key: &[u8; 32], from: [u8; 21], to: [u8; 21], amount: i64, salt: u8) -> Transaction {
        let c = tron_proto::TransferContract {
            owner_address: from.to_vec(),
            to_address: to.to_vec(),
            amount,
        };
        let mut tx = Transaction {
            raw_data: Some(TxRaw {
                contract: vec![TxContract {
                    r#type: ContractType::TransferContract as i32,
                    parameter: Some(Any {
                        type_url: "type.googleapis.com/protocol.TransferContract".into(),
                        value: c.encode_to_vec(),
                    }),
                    ..Default::default()
                }],
                timestamp: 1_700_000_000_000,
                expiration: 1_700_000_000_000 + 86_400_000,
                data: vec![salt],
                ..Default::default()
            }),
            signature: Vec::new(),
            ret: vec![tron_proto::transaction::Result {
                contract_ret: tron_proto::transaction::result::ContractResult::Success as i32,
                ..Default::default()
            }],
            unparsed_field10: None,
        };
        tron_types::sign_transaction(&mut tx, priv_key).expect("sign");
        tx
    }

    // Three blocks: two transfers and an empty one.
    let b1 = build_block(1, [0u8; 32], alice, &alice_priv, vec![transfer(&alice_priv, alice, bob, 100_000, 1)]);
    let id1 = block_id_from_block(&b1).unwrap();
    assert!(matches!(driver.accept_block(&b1, None), AcceptOutcome::Accepted(_)));
    let b2 = build_block(2, *id1.as_bytes(), alice, &alice_priv, vec![transfer(&alice_priv, alice, bob, 50_000, 2)]);
    let id2 = block_id_from_block(&b2).unwrap();
    assert!(matches!(driver.accept_block(&b2, None), AcceptOutcome::Accepted(_)));
    let b3 = build_block(3, *id2.as_bytes(), alice, &alice_priv, vec![]);
    assert!(matches!(driver.accept_block(&b3, None), AcceptOutcome::Accepted(_)));

    assert_eq!(writer.reader().coverage().unwrap(), Some((0, 3)));

    // Historical balances through the at-height view, decoded by the
    // ordinary typed store — the exact read path /v1/archive uses.
    let balance_at = |who: [u8; 21], h: i64| -> Option<i64> {
        let view = ArchiveAtBackend::new(
            accounts_be.clone(),
            writer.reader(),
            UndoStoreId::Accounts,
            h,
        );
        AccountStore::new(Arc::new(view))
            .get(&Address::from_raw(who))
            .unwrap()
            .map(|a| a.balance)
    };
    // Height 0 (base): pre-capture state.
    assert_eq!(balance_at(alice, 0), Some(1_000_000));
    assert_eq!(balance_at(bob, 0), None, "bob's account didn't exist at the base");
    // Bob's balance steps up per block; alice's down (minus any fees —
    // compare against the actually-recorded post-images, so assert
    // bob's exact receive side which has no fee ambiguity).
    assert_eq!(balance_at(bob, 1), Some(100_000));
    assert_eq!(balance_at(bob, 2), Some(150_000));
    assert_eq!(balance_at(bob, 3), Some(150_000), "empty block leaves balances unchanged");
    let alice_1 = balance_at(alice, 1).unwrap();
    let alice_2 = balance_at(alice, 2).unwrap();
    // h1 creates bob's account: alice pays 100_000 transfer + the flat
    // 0.1-TRX create-account fee (java consumeFeeForCreateNewAccount)
    // → exactly 800_000 when no other fees apply.
    assert!(alice_1 <= 900_000 && alice_1 >= 800_000, "alice at h1: {alice_1}");
    assert!(alice_2 <= alice_1 - 50_000, "alice at h2: {alice_2}");

    // The archived dyn-props give each height's own head pointer —
    // what makes constant-calls-at-H see block H's number/timestamp.
    let dp_at = |h: i64| {
        let view = ArchiveAtBackend::new(
            dyn_props_be.clone(),
            writer.reader(),
            UndoStoreId::DynProps,
            h,
        );
        DynamicPropertiesStore::new(Arc::new(view))
    };
    assert_eq!(dp_at(1).latest_block_header_number(), Some(1));
    assert_eq!(dp_at(2).latest_block_header_number(), Some(2));
    assert_eq!(dp_at(1).latest_block_header_timestamp(), Some(1_700_000_000_000 + 3000));
}
