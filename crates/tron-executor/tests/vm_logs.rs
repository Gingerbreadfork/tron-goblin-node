//! End-to-end test confirming that LOG opcodes surface in
//! `TxResult.vm_logs` after the executor runs a smart contract.
//!
//! Without this, downstream consumers (eventer, logsfilter, gRPC
//! `getTransactionInfoById`) would never see contract events.

use std::sync::Arc;

use prost::Message;
use prost_types::Any;
use tron_chainbase::{
    AccountStore, CodeStore, KvBackend, MemBackend, StorageRowStore,
};
use tron_crypto::address::Address;
use tron_executor::{execute_block, StateBackends, TxOutcome};
use tron_proto::{
    transaction::{contract::ContractType, Contract as TxContract, Raw as TxRaw},
    Account, Block, BlockHeader, Transaction, TriggerSmartContract,
};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn addr_with_byte(byte: u8) -> [u8; 21] {
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].fill(byte);
    a
}

fn caller_keypair(seed: u8) -> ([u8; 32], [u8; 21]) {
    use tron_crypto::signature::RecoverableSignature;
    let mut priv_key = [0u8; 32];
    priv_key[0] = 0x10;
    priv_key[31] = seed;
    let dummy_hash = [0x42u8; 32];
    let sig = RecoverableSignature::sign_prehash(&priv_key, &dummy_hash).expect("sign");
    let pub_key = sig
        .recover_uncompressed_pubkey(&dummy_hash)
        .expect("recover");
    let h = tron_crypto::hash::keccak256(&pub_key[1..]);
    let mut addr = [0u8; 21];
    addr[0] = 0x41;
    addr[1..].copy_from_slice(&h[12..]);
    (priv_key, addr)
}

fn build_state() -> StateBackends {
    StateBackends {
        accounts: mem(),
        witnesses: mem(),
        votes: mem(),
        delegation: mem(),
        delegated_resources: mem(),
        dyn_props: mem(),
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
        nullifiers: mem(),
        merkle_trees: None,
        code: Some(mem()),
        storage_row: Some(mem()),
        contract_state: Some(mem()),
        block_index: Some(mem()),
        witness_schedule: Some(mem()),
    }
}

fn make_block(num: i64, parent: [u8; 32], txs: Vec<Transaction>) -> Block {
    Block {
        block_header: Some(BlockHeader {
            raw_data: Some(tron_proto::block_header::Raw {
                number: num,
                parent_hash: parent.to_vec(),
                timestamp: 1_700_000_000_000,
                tx_trie_root: tron_types::calc_tx_trie_root(&txs)
                    .map(|h| h.to_vec())
                    .unwrap_or_default(),
                ..Default::default()
            }),
            ..Default::default()
        }),
        transactions: txs,
    }
}

fn install_contract(state: &StateBackends, addr: [u8; 21], bytecode: &[u8]) {
    let accounts = AccountStore::new(state.accounts.clone());
    let code = CodeStore::new(state.code.as_ref().unwrap().clone());
    let hash = tron_crypto::hash::keccak256(bytecode);
    code.put(&hash, bytecode);
    accounts.put(
        &Address::from_raw(addr),
        &Account {
            address: addr.to_vec(),
            balance: 0,
            code: bytecode.to_vec(),
            code_hash: hash.to_vec(),
            ..Default::default()
        },
    );
}

fn install_caller(state: &StateBackends, addr: [u8; 21]) {
    AccountStore::new(state.accounts.clone()).put(
        &Address::from_raw(addr),
        &Account {
            address: addr.to_vec(),
            balance: 1_000_000_000,
            ..Default::default()
        },
    );
}

fn build_trigger_tx(
    caller_priv: &[u8; 32],
    caller: [u8; 21],
    contract: [u8; 21],
) -> Transaction {
    let trigger = TriggerSmartContract {
        owner_address: caller.to_vec(),
        contract_address: contract.to_vec(),
        call_value: 0,
        data: vec![],
        call_token_value: 0,
        token_id: 0,
    };
    let any = Any {
        type_url: "type.googleapis.com/protocol.TriggerSmartContract".into(),
        value: trigger.encode_to_vec(),
    };
    let mut tx = Transaction {
        raw_data: Some(TxRaw {
            contract: vec![TxContract {
                r#type: ContractType::TriggerSmartContract as i32,
                parameter: Some(any),
                ..Default::default()
            }],
            timestamp: 1_700_000_000_000,
            ..Default::default()
        }),
        signature: Vec::new(),
        ret: Vec::new(),
    };
    tron_types::sign_transaction(&mut tx, caller_priv).expect("sign tx");
    tx
}

// `keccak256("Transfer(address,address,uint256)")`.
const TRANSFER_TOPIC0: [u8; 32] = [
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d, 0xaa,
    0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef,
];

/// Bytecode that emits a Transfer(from, to, value) LOG3 then STOPs.
/// Topics: [Transfer-sig, from=0x...11, to=0x...22]; data: 1000.
fn transfer_log_bytecode() -> Vec<u8> {
    let from_padded: [u8; 32] = {
        let mut b = [0u8; 32];
        b[31 - 19..].copy_from_slice(&[0x11; 20]); // last 20 bytes
        b
    };
    let to_padded: [u8; 32] = {
        let mut b = [0u8; 32];
        b[31 - 19..].copy_from_slice(&[0x22; 20]);
        b
    };
    let value_padded: [u8; 32] = {
        let mut b = [0u8; 32];
        // Encode 1000 = 0x03e8 in the low 2 bytes.
        b[30] = 0x03;
        b[31] = 0xe8;
        b
    };

    let mut bc = Vec::new();
    // Store value at mem[0..32].
    bc.push(0x7f); // PUSH32
    bc.extend_from_slice(&value_padded);
    bc.push(0x60); // PUSH1
    bc.push(0x00);
    bc.push(0x52); // MSTORE

    // LOG3 args (pushed in reverse order so offset is on top of stack):
    // topic3 (to), topic2 (from), topic1 (signature), then size, offset.
    bc.push(0x7f); // PUSH32 topic2 = to
    bc.extend_from_slice(&to_padded);
    bc.push(0x7f); // PUSH32 topic1 = from
    bc.extend_from_slice(&from_padded);
    bc.push(0x7f); // PUSH32 topic0 = Transfer signature
    bc.extend_from_slice(&TRANSFER_TOPIC0);
    bc.push(0x60); // PUSH1 32 (size)
    bc.push(0x20);
    bc.push(0x60); // PUSH1 0 (offset)
    bc.push(0x00);
    bc.push(0xa3); // LOG3
    bc.push(0x00); // STOP
    bc
}

#[test]
fn vm_logs_surface_on_tx_result_for_successful_trigger() {
    let state = build_state();
    let (caller_priv, caller) = caller_keypair(0xb1);
    let contract = addr_with_byte(0xd1);

    install_caller(&state, caller);
    install_contract(&state, contract, &transfer_log_bytecode());

    let tx = build_trigger_tx(&caller_priv, caller, contract);
    let block = make_block(1, [0u8; 32], vec![tx]);
    let report = execute_block(&state, &block, None).expect("execute_block");

    let result = &report.tx_results[0];
    assert!(
        matches!(result.outcome, TxOutcome::Success),
        "trigger must succeed; got {:?}",
        result.outcome
    );
    assert_eq!(
        result.vm_logs.len(),
        1,
        "expected exactly one LOG3 emission, got {}",
        result.vm_logs.len()
    );

    let log = &result.vm_logs[0];
    // Address is the contract's 20-byte EVM form (last 20 bytes of the
    // 21-byte TRON form).
    assert_eq!(log.address, contract[1..]);
    assert_eq!(log.topics.len(), 3, "LOG3 must record 3 topics");
    assert_eq!(log.topics[0], TRANSFER_TOPIC0);
    // Data is the 32-byte value 1000.
    assert_eq!(log.data.len(), 32);
    assert_eq!(log.data[30], 0x03);
    assert_eq!(log.data[31], 0xe8);
}

#[test]
fn vm_logs_are_empty_for_reverted_tx() {
    let state = build_state();
    let (caller_priv, caller) = caller_keypair(0xb2);
    let contract = addr_with_byte(0xd2);

    // Emit a log first, then REVERT. java-tron's logsfilter drops the
    // log because the tx reverted — we mirror that by surfacing logs
    // only on TxOutcome::Success.
    let mut bc = transfer_log_bytecode();
    // Replace the trailing STOP with REVERT(0, 0).
    bc.pop(); // pop STOP
    bc.push(0x60); // PUSH1 0 (size)
    bc.push(0x00);
    bc.push(0x60); // PUSH1 0 (offset)
    bc.push(0x00);
    bc.push(0xfd); // REVERT

    install_caller(&state, caller);
    install_contract(&state, contract, &bc);

    let tx = build_trigger_tx(&caller_priv, caller, contract);
    let block = make_block(1, [0u8; 32], vec![tx]);
    let report = execute_block(&state, &block, None).expect("execute_block");
    let result = &report.tx_results[0];
    assert!(
        !matches!(result.outcome, TxOutcome::Success),
        "tx must NOT be marked Success (it reverted), got {:?}",
        result.outcome
    );
    assert!(
        result.vm_logs.is_empty(),
        "reverted tx must not surface logs, got {}",
        result.vm_logs.len()
    );
}

#[test]
fn vm_logs_are_empty_for_non_vm_contract() {
    // A non-VM contract (e.g. TransferContract) must always produce
    // empty vm_logs — the field defaults to Vec::new() for every
    // non-VM TxResult arm.
    let state = build_state();
    let (caller_priv, caller) = caller_keypair(0xb3);
    let recipient = addr_with_byte(0xb4);

    install_caller(&state, caller);

    let transfer = tron_proto::TransferContract {
        owner_address: caller.to_vec(),
        to_address: recipient.to_vec(),
        amount: 1_000,
    };
    let any = Any {
        type_url: "type.googleapis.com/protocol.TransferContract".into(),
        value: transfer.encode_to_vec(),
    };
    let mut tx = Transaction {
        raw_data: Some(TxRaw {
            contract: vec![TxContract {
                r#type: ContractType::TransferContract as i32,
                parameter: Some(any),
                ..Default::default()
            }],
            timestamp: 1_700_000_000_000,
            ..Default::default()
        }),
        signature: Vec::new(),
        ret: Vec::new(),
    };
    tron_types::sign_transaction(&mut tx, &caller_priv).expect("sign");

    let block = make_block(1, [0u8; 32], vec![tx]);
    let report = execute_block(&state, &block, None).expect("execute_block");
    let result = &report.tx_results[0];
    assert!(
        result.vm_logs.is_empty(),
        "non-VM contract must not produce vm_logs"
    );
    // The unused `StorageRowStore` import would warn — drop it.
    let _ = StorageRowStore::new(state.storage_row.unwrap());
}
