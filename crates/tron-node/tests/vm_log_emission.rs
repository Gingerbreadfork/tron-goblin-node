//! End-to-end test for the executor → eventer log-emission path.
//!
//! Sets up a [`SyncDriver`] with a [`ChannelListener`] attached, pre-
//! deploys a contract whose runtime code emits a `Transfer` LOG3, and
//! drives the contract via `accept_block`. Verifies that the eventer
//! bus surfaces a decoded [`ContractEvent`] (with `eventName=Transfer`
//! and decoded `from`/`to`/`value` params) — not just a raw log — by
//! way of `tron-node`'s ABI-decoder bridge.
//!
//! Also covers the missing-ABI fallback: when the contract has no
//! ABI on disk, the bus surfaces a [`ContractLogEvent`] (raw topics +
//! data) instead. java-tron's logsfilter does the same.

use std::sync::Arc;
use std::time::Duration;

use prost::Message;
use prost_types::Any;
use tron_chainbase::{
    AbiStore, AccountStore, CodeStore, ContractStore, DynamicPropertiesStore, KvBackend,
    MemBackend, WitnessScheduleStore,
};
use tron_crypto::address::Address;
use tron_eventer::listeners::{ChannelListener, TriggerMessage};
use tron_eventer::EventBus;
use tron_executor::StateBackends;
use tron_node::sync::{AcceptOutcome, SyncConfig, SyncDriver};
use tron_proto::smart_contract::abi::entry::{EntryType, Param};
use tron_proto::smart_contract::abi::Entry;
use tron_proto::smart_contract::Abi;
use tron_proto::{
    transaction::{contract::ContractType, Contract as TxContract, Raw as TxRaw},
    Account, Block, BlockHeader, SmartContract, Transaction, TriggerSmartContract,
};
use tron_types::{block_id_from_block, sign_block};

// `keccak256("Transfer(address,address,uint256)")` — pinned constant
// so the test doesn't depend on the runtime's keccak.
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
    let pub_key = sig
        .recover_uncompressed_pubkey(&dummy_hash)
        .expect("recover");
    let h = tron_crypto::hash::keccak256(&pub_key[1..]);
    let mut addr = [0u8; 21];
    addr[0] = 0x41;
    addr[1..].copy_from_slice(&h[12..]);
    (priv_key, addr)
}

fn fresh_state() -> (StateBackends, Arc<dyn KvBackend>) {
    let blocks_be = mem();
    (
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
        },
        blocks_be,
    )
}

fn install_caller(state: &StateBackends, caller: [u8; 21]) {
    AccountStore::new(state.accounts.clone()).put(
        &Address::from_raw(caller),
        &Account {
            address: caller.to_vec(),
            balance: 1_000_000_000,
            ..Default::default()
        },
    );
}

fn install_contract(
    state: &StateBackends,
    addr: [u8; 21],
    bytecode: &[u8],
    deployer: [u8; 21],
) {
    let hash = tron_crypto::hash::keccak256(bytecode);
    CodeStore::new(state.code.as_ref().unwrap().clone()).put(&hash, bytecode);
    AccountStore::new(state.accounts.clone()).put(
        &Address::from_raw(addr),
        &Account {
            address: addr.to_vec(),
            balance: 0,
            code: bytecode.to_vec(),
            code_hash: hash.to_vec(),
            ..Default::default()
        },
    );
    // SmartContract record so the decoder's creator-address lookup
    // finds `origin_address`.
    ContractStore::new(state.contracts.clone()).put(
        &Address::from_raw(addr),
        &SmartContract {
            origin_address: deployer.to_vec(),
            contract_address: addr.to_vec(),
            ..Default::default()
        },
    );
}

fn install_transfer_abi(state: &StateBackends, addr: [u8; 21]) {
    AbiStore::new(state.abi.clone()).put(
        &Address::from_raw(addr),
        &Abi {
            entrys: vec![Entry {
                anonymous: false,
                constant: false,
                name: "Transfer".into(),
                inputs: vec![
                    Param {
                        indexed: true,
                        name: "from".into(),
                        r#type: "address".into(),
                    },
                    Param {
                        indexed: true,
                        name: "to".into(),
                        r#type: "address".into(),
                    },
                    Param {
                        indexed: false,
                        name: "value".into(),
                        r#type: "uint256".into(),
                    },
                ],
                outputs: vec![],
                r#type: EntryType::Event as i32,
                payable: false,
                state_mutability: 0,
            }],
        },
    );
}

/// LOG3 with the Transfer event signature: emits Transfer(from=0x...11,
/// to=0x...22, value=1000) then STOPs.
fn transfer_log_bytecode() -> Vec<u8> {
    let from_padded: [u8; 32] = {
        let mut b = [0u8; 32];
        b[12..].copy_from_slice(&[0x11u8; 20]);
        b
    };
    let to_padded: [u8; 32] = {
        let mut b = [0u8; 32];
        b[12..].copy_from_slice(&[0x22u8; 20]);
        b
    };
    let value_padded: [u8; 32] = {
        let mut b = [0u8; 32];
        b[30] = 0x03;
        b[31] = 0xe8;
        b
    };

    let mut bc = Vec::new();
    bc.push(0x7f); // PUSH32 value
    bc.extend_from_slice(&value_padded);
    bc.push(0x60); // PUSH1 0 (mstore offset)
    bc.push(0x00);
    bc.push(0x52); // MSTORE

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
            // 100 TRX (= 100 × 1_000_000 sun) → 1_000_000 energy at
            // the default fee of 100 sun/energy. The contract's bytecode
            // is a single Transfer-event emit, well under this budget.
            // Required since the ET-C3 fix: the executor now derives
            // the VM's per-tx energy budget from `fee_limit` rather
            // than a hardcoded 10M fallback.
            fee_limit: 100_000_000,
            ..Default::default()
        }),
        signature: Vec::new(),
        ret: Vec::new(),
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

fn make_driver(
    state: StateBackends,
    blocks_be: Arc<dyn KvBackend>,
    bus: EventBus,
) -> SyncDriver {
    let cfg = SyncConfig {
        peers: vec![],
        max_blocks: None,
        tail_interval: Duration::from_millis(1),
        initial_backoff: Duration::from_millis(1),
        blocks_backend: blocks_be,
        progress_log_interval: 0,
        advertise_port: 18_888,
        tip_test: false,
        p2p_rate_limits: Default::default(),
        fetch_block_timeout: Duration::from_millis(200),
        peer_is_fast_forward: false,
    };
    SyncDriver::new(state, cfg).with_event_bus(bus)
}

fn seed_witness_schedule(state: &StateBackends, witness: [u8; 21]) {
    // The block validator looks up the active witness via
    // WitnessScheduleStore. Seed a single-witness schedule so our
    // hand-rolled block passes validation.
    let schedule = WitnessScheduleStore::new(state.witness_schedule.as_ref().unwrap().clone());
    schedule.save_active(&[Address::from_raw(witness)]);
}

#[tokio::test]
async fn contract_event_with_abi_decoded_via_bus() {
    let (caller_priv, caller) = caller_keypair(0xb1);
    let mut contract_addr = [0u8; 21];
    contract_addr[0] = 0x41;
    contract_addr[1..].fill(0xd1);

    let (state, blocks_be) = fresh_state();
    install_caller(&state, caller);
    install_contract(&state, contract_addr, &transfer_log_bytecode(), caller);
    install_transfer_abi(&state, contract_addr);
    seed_witness_schedule(&state, caller);

    // Set a latest_solidified_block_num just so the trigger struct's
    // field is populated with something meaningful.
    let dp = DynamicPropertiesStore::new(state.dyn_props.clone());
    dp.put_long(b"LATEST_SOLIDIFIED_BLOCK_NUM", 0);

    let (listener, mut rx) = ChannelListener::pair(16);
    let bus = EventBus::builder().add(listener).build();
    let mut driver = make_driver(state, blocks_be, bus);

    let tx = build_trigger_tx(&caller_priv, caller, contract_addr);
    let block = build_block(1, [0u8; 32], caller, &caller_priv, vec![tx]);
    let _ = block_id_from_block(&block).expect("block id");
    let outcome = driver.accept_block(&block, None);
    assert!(
        matches!(outcome, AcceptOutcome::Accepted(_)),
        "block must be accepted; got {outcome:?}"
    );

    // Drain triggers — we expect Block, Transaction, ContractEvent.
    let mut saw_block = false;
    let mut saw_transaction = false;
    let mut saw_event: Option<tron_eventer::ContractEvent> = None;
    for _ in 0..3 {
        match rx.recv().await {
            Some(TriggerMessage::Block(_)) => saw_block = true,
            Some(TriggerMessage::Transaction(_)) => saw_transaction = true,
            Some(TriggerMessage::ContractEvent(ev)) => saw_event = Some(ev),
            Some(other) => panic!("unexpected trigger: {other:?}"),
            None => break,
        }
    }
    assert!(saw_block, "Block trigger missing");
    assert!(saw_transaction, "Transaction trigger missing");

    let ev = saw_event.expect("ContractEvent missing");
    assert_eq!(ev.event_name, "Transfer");
    assert_eq!(ev.event_signature, hex::encode(TRANSFER_TOPIC0));
    assert!(
        ev.event_signature_full.contains("address")
            && ev.event_signature_full.contains("uint256"),
        "event_signature_full should expose param types, got: {}",
        ev.event_signature_full
    );
    assert_eq!(
        ev.topic_map.len(),
        2,
        "Transfer has 2 indexed params (from, to), got: {:?}",
        ev.topic_map
    );
    assert!(ev.topic_map.contains_key("from"));
    assert!(ev.topic_map.contains_key("to"));
    assert_eq!(ev.data_map.len(), 1, "Transfer has 1 data param (value)");
    assert!(ev.data_map.contains_key("value"));

    // Contract address is the 21-byte TRON form (0x41 prefix + 20 bytes).
    assert_eq!(ev.contract_address, hex::encode(contract_addr));
    // Origin = the tx signer (the caller). caller_address matches for
    // the top-level frame.
    assert_eq!(ev.origin_address, hex::encode(caller));
    // Creator = the contract's deployer per the SmartContract record we
    // installed above.
    assert_eq!(ev.creator_address, hex::encode(caller));
}

#[tokio::test]
async fn contract_log_falls_back_when_no_abi_registered() {
    // Same setup but skip the ABI install. The decoder must fall back
    // to a raw ContractLogEvent.
    let (caller_priv, caller) = caller_keypair(0xb2);
    let mut contract_addr = [0u8; 21];
    contract_addr[0] = 0x41;
    contract_addr[1..].fill(0xd2);

    let (state, blocks_be) = fresh_state();
    install_caller(&state, caller);
    install_contract(&state, contract_addr, &transfer_log_bytecode(), caller);
    // No install_transfer_abi — decoder must produce a raw log.
    seed_witness_schedule(&state, caller);

    let (listener, mut rx) = ChannelListener::pair(16);
    let bus = EventBus::builder().add(listener).build();
    let mut driver = make_driver(state, blocks_be, bus);

    let tx = build_trigger_tx(&caller_priv, caller, contract_addr);
    let block = build_block(1, [0u8; 32], caller, &caller_priv, vec![tx]);
    let outcome = driver.accept_block(&block, None);
    assert!(
        matches!(outcome, AcceptOutcome::Accepted(_)),
        "block must be accepted; got {outcome:?}"
    );

    let mut saw_log: Option<tron_eventer::ContractLogEvent> = None;
    let mut saw_event_unexpected = false;
    for _ in 0..3 {
        match rx.recv().await {
            Some(TriggerMessage::Block(_)) => {}
            Some(TriggerMessage::Transaction(_)) => {}
            Some(TriggerMessage::ContractLog(log)) => saw_log = Some(log),
            Some(TriggerMessage::ContractEvent(_)) => saw_event_unexpected = true,
            Some(other) => panic!("unexpected trigger: {other:?}"),
            None => break,
        }
    }
    assert!(
        !saw_event_unexpected,
        "ContractEvent must NOT fire without an ABI on disk"
    );
    let log = saw_log.expect("ContractLogEvent missing");
    assert_eq!(log.topic_list.len(), 3, "LOG3 has 3 topics");
    assert_eq!(log.topic_list[0], hex::encode(TRANSFER_TOPIC0));
    assert_eq!(log.contract_address, hex::encode(contract_addr));
}
