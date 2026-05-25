//! End-to-end tests for the four remaining shielded scanners:
//!   * `scan_note_by_ovk`               — Sapling OVK output recovery
//!   * `scan_and_mark_note_by_ivk`      — IVK decrypt + nullifier check
//!   * `scan_shielded_trc20_notes_by_ivk` — TRC-20 event scan via IVK
//!   * `scan_shielded_trc20_notes_by_ovk` — TRC-20 event scan via OVK

#![allow(deprecated)] // `events: vec![]` for the deprecated proto field

use std::sync::Arc;
use std::time::Duration;

use prost::Message as _;
use tokio::sync::oneshot;
use tron_chainbase::{
    BlockIndexStore, BlockStore, DynamicPropertiesStore, KvBackend, MemBackend,
    TransactionHistoryStore,
};
use tron_grpc::proto::wallet_client::WalletClient;
use tron_proto::protocol::{
    IvkDecryptAndMarkParameters, IvkDecryptTrc20Parameters, OvkDecryptParameters,
    OvkDecryptTrc20Parameters,
};
use tron_proto::transaction::contract::ContractType;
use tron_proto::transaction::{Contract as TxContract, Raw as TxRaw};
use tron_proto::transaction_info::Log as TxInfoLog;
use tron_proto::{
    block_header::Raw as BlockHeaderRaw, Block, BlockHeader, ReceiveDescription,
    ShieldedTransferContract, Transaction, TransactionInfo,
};
use tron_rpc::RpcState;

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

async fn spawn_server(
    state: RpcState,
) -> (
    std::net::SocketAddr,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let shut = async move {
            let _ = shutdown_rx.await;
        };
        tron_grpc::start_server(state, addr, shut).await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, shutdown_tx, server)
}

/// Build a Sapling keypair + encrypted note for testing.
/// Returns `(ovk_bytes, ivk_bytes, ak_bytes, nk_bytes, expected_value,
/// receive_description)`.
fn build_note_and_receive_desc(
    value: u64,
) -> ([u8; 32], [u8; 32], Vec<u8>, Vec<u8>, u64, ReceiveDescription) {
    use group::GroupEncoding;
    use rand::SeedableRng;
    use sapling_crypto::keys::{Diversifier, ExpandedSpendingKey};
    use sapling_crypto::note::Rseed;
    use sapling_crypto::note_encryption::sapling_note_encryption;
    use sapling_crypto::value::{NoteValue, ValueCommitTrapdoor, ValueCommitment};
    use sapling_crypto::Note as SaplingNote;

    let mut rng = rand::rngs::StdRng::seed_from_u64(13);
    let sk_bytes = [0x11u8; 32];
    let esk = ExpandedSpendingKey::from_spending_key(&sk_bytes);
    let vk = esk.proof_generation_key().to_viewing_key();
    let ivk = vk.ivk();
    let ivk_bytes_repr = ivk.to_repr();
    let ovk_bytes = esk.ovk.0;
    let ak_bytes = vk.ak.to_bytes().to_vec();
    let nk_bytes = vk.nk.0.to_bytes().to_vec();

    let payment_addr = (0u8..255)
        .find_map(|seed| {
            let mut d = [0u8; 11];
            d[0] = seed;
            ivk.to_payment_address(Diversifier(d))
        })
        .unwrap();
    let value_obj = NoteValue::from_raw(value);
    let mut rseed_bytes = [0u8; 32];
    use rand::RngCore as _;
    rng.fill_bytes(&mut rseed_bytes);
    let note = SaplingNote::from_parts(payment_addr, value_obj, Rseed::AfterZip212(rseed_bytes));

    // Derive the typed value commitment for OVK encryption.
    let rcv = ValueCommitTrapdoor::random(&mut rng);
    let cv = ValueCommitment::derive(value_obj, rcv);
    let cmu = note.cmu();

    let encryption =
        sapling_note_encryption(Some(esk.ovk), note.clone(), [0u8; 512], &mut rng);
    let c_enc = encryption.encrypt_note_plaintext();
    let c_out = encryption.encrypt_outgoing_plaintext(&cv, &cmu, &mut rng);
    let epk_bytes = {
        use sapling_crypto::note_encryption::SaplingDomain;
        use zcash_note_encryption::Domain as _;
        SaplingDomain::epk_bytes(encryption.epk()).0.to_vec()
    };
    let cmu_bytes = cmu.to_bytes();
    let cv_bytes = cv.to_bytes();
    let rd = ReceiveDescription {
        value_commitment: cv_bytes.to_vec(),
        note_commitment: cmu_bytes.to_vec(),
        epk: epk_bytes,
        c_enc: c_enc.to_vec(),
        c_out: c_out.to_vec(),
        zkproof: vec![0u8; 192],
    };
    (ovk_bytes, ivk_bytes_repr, ak_bytes, nk_bytes, value, rd)
}

fn put_block_with_shielded_tx(
    blocks_be: &Arc<dyn KvBackend>,
    block_index_be: &Arc<dyn KvBackend>,
    dp: &DynamicPropertiesStore,
    block_num: i64,
    parent_hash: Vec<u8>,
    receive_descriptions: Vec<ReceiveDescription>,
) -> [u8; 32] {
    let stc = ShieldedTransferContract {
        transparent_from_address: vec![],
        from_amount: 0,
        transparent_to_address: vec![],
        to_amount: 0,
        binding_signature: vec![0u8; 64],
        spend_description: vec![],
        receive_description: receive_descriptions,
    };
    let mut any_value = Vec::with_capacity(stc.encoded_len());
    stc.encode(&mut any_value).unwrap();
    let any = prost_types::Any {
        type_url: "type.googleapis.com/protocol.ShieldedTransferContract".into(),
        value: any_value,
    };
    let raw = TxRaw {
        contract: vec![TxContract {
            r#type: ContractType::ShieldedTransferContract as i32,
            parameter: Some(any),
            ..Default::default()
        }],
        timestamp: 1_700_000_000_000 + block_num,
        ..Default::default()
    };
    let tx_id = tron_crypto::hash::sha256(&raw.encode_to_vec());
    let tx = Transaction {
        raw_data: Some(raw),
        signature: vec![],
        ret: vec![],
    };
    let block = Block {
        block_header: Some(BlockHeader {
            raw_data: Some(BlockHeaderRaw {
                number: block_num,
                parent_hash,
                timestamp: 1_700_000_000_000 + block_num,
                witness_address: vec![0x41u8; 21],
                ..Default::default()
            }),
            witness_signature: vec![],
        }),
        transactions: vec![tx],
    };
    let block_id = tron_types::block_id_from_block(&block).unwrap();
    BlockStore::new(blocks_be.clone()).put(&block_id, &block);
    BlockIndexStore::new(block_index_be.clone()).put(&block_id);
    dp.save_latest_block_header_number(block_num);
    dp.save_latest_block_header_hash(block_id.as_bytes());
    tx_id
}

// ============================================================
// scan_note_by_ovk
// ============================================================

#[tokio::test]
async fn scan_note_by_ovk_recovers_sender_owned_note() {
    let (ovk_bytes, _ivk, _ak, _nk, value, rd) = build_note_and_receive_desc(1234);
    let blocks_be = mem();
    let block_index_be = mem();
    let dp_be = mem();
    let dp = DynamicPropertiesStore::new(dp_be.clone());
    put_block_with_shielded_tx(&blocks_be, &block_index_be, &dp, 1, vec![0u8; 32], vec![rd]);
    let state = RpcState::new(mem(), blocks_be, block_index_be, mem(), dp_be, 11_111);

    let (addr, _shutdown, _server) = spawn_server(state).await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let resp = client
        .scan_note_by_ovk(OvkDecryptParameters {
            start_block_index: 1,
            end_block_index: 2,
            ovk: ovk_bytes.to_vec(),
        })
        .await
        .expect("rpc")
        .into_inner();
    assert_eq!(resp.note_txs.len(), 1, "expected 1 hit, got {:?}", resp);
    assert_eq!(resp.note_txs[0].note.as_ref().unwrap().value, value as i64);
}

#[tokio::test]
async fn scan_note_by_ovk_returns_empty_for_wrong_key() {
    let (_ovk, _ivk, _ak, _nk, _v, rd) = build_note_and_receive_desc(1234);
    let blocks_be = mem();
    let block_index_be = mem();
    let dp_be = mem();
    let dp = DynamicPropertiesStore::new(dp_be.clone());
    put_block_with_shielded_tx(&blocks_be, &block_index_be, &dp, 1, vec![0u8; 32], vec![rd]);
    let state = RpcState::new(mem(), blocks_be, block_index_be, mem(), dp_be, 11_111);
    let (addr, _shutdown, _server) = spawn_server(state).await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let resp = client
        .scan_note_by_ovk(OvkDecryptParameters {
            start_block_index: 1,
            end_block_index: 2,
            ovk: vec![0xffu8; 32],
        })
        .await
        .expect("rpc")
        .into_inner();
    assert!(resp.note_txs.is_empty());
}

#[tokio::test]
async fn scan_note_by_ovk_rejects_bad_ovk_length() {
    let state = RpcState::new(mem(), mem(), mem(), mem(), mem(), 11_111);
    let (addr, _shutdown, _server) = spawn_server(state).await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let err = client
        .scan_note_by_ovk(OvkDecryptParameters {
            start_block_index: 0,
            end_block_index: 1,
            ovk: vec![0u8; 16],
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("ovk"));
}

// ============================================================
// scan_and_mark_note_by_ivk
// ============================================================

#[tokio::test]
async fn scan_and_mark_marks_unspent_when_nullifier_absent() {
    let (_ovk, ivk, ak, nk, _value, rd) = build_note_and_receive_desc(5555);
    let blocks_be = mem();
    let block_index_be = mem();
    let dp_be = mem();
    let nullifiers_be = mem();
    let dp = DynamicPropertiesStore::new(dp_be.clone());
    put_block_with_shielded_tx(&blocks_be, &block_index_be, &dp, 1, vec![0u8; 32], vec![rd]);
    let state = RpcState::new(mem(), blocks_be, block_index_be, mem(), dp_be, 11_111)
        .with_nullifiers(nullifiers_be);
    let (addr, _shutdown, _server) = spawn_server(state).await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let resp = client
        .scan_and_mark_note_by_ivk(IvkDecryptAndMarkParameters {
            start_block_index: 1,
            end_block_index: 2,
            ivk: ivk.to_vec(),
            ak,
            nk,
        })
        .await
        .expect("rpc")
        .into_inner();
    assert_eq!(resp.note_txs.len(), 1);
    assert_eq!(resp.note_txs[0].is_spend, false);
}

#[tokio::test]
async fn scan_and_mark_marks_spent_when_nullifier_in_store() {
    use group::GroupEncoding;
    use sapling_crypto::keys::NullifierDerivingKey;
    use sapling_crypto::note_encryption::{
        try_sapling_note_decryption, PreparedIncomingViewingKey, Zip212Enforcement,
    };
    use sapling_crypto::SaplingIvk;

    let (_ovk, ivk, ak, nk, _value, rd) = build_note_and_receive_desc(5555);
    let blocks_be = mem();
    let block_index_be = mem();
    let dp_be = mem();
    let nullifiers_be = mem();
    let dp = DynamicPropertiesStore::new(dp_be.clone());
    put_block_with_shielded_tx(&blocks_be, &block_index_be, &dp, 1, vec![0u8; 32], vec![rd.clone()]);
    let state = RpcState::new(mem(), blocks_be, block_index_be, mem(), dp_be, 11_111)
        .with_nullifiers(nullifiers_be.clone());

    // Compute the expected nullifier independently and pre-insert it.
    // Recover the note via IVK to get the typed sapling Note, then
    // derive nf with nk + position 0.
    use group::ff::PrimeField;
    let ivk_scalar = jubjub::Fr::from_repr(ivk).unwrap();
    let prepared = PreparedIncomingViewingKey::new(&SaplingIvk(ivk_scalar));
    // Build the same ShieldedOutput view the scanner uses.
    struct V<'a> {
        epk: [u8; 32],
        cmu: [u8; 32],
        c_enc: &'a [u8],
    }
    impl<'a> zcash_note_encryption::ShieldedOutput<sapling_crypto::note_encryption::SaplingDomain, 580>
        for V<'a>
    {
        fn ephemeral_key(&self) -> zcash_note_encryption::EphemeralKeyBytes {
            zcash_note_encryption::EphemeralKeyBytes(self.epk)
        }
        fn cmstar_bytes(&self) -> [u8; 32] {
            self.cmu
        }
        fn enc_ciphertext(&self) -> &[u8; 580] {
            self.c_enc.try_into().unwrap()
        }
    }
    let mut epk = [0u8; 32];
    epk.copy_from_slice(&rd.epk);
    let mut cmu = [0u8; 32];
    cmu.copy_from_slice(&rd.note_commitment);
    let view = V {
        epk,
        cmu,
        c_enc: &rd.c_enc,
    };
    let (note, _pa, _memo) =
        try_sapling_note_decryption(&prepared, &view, Zip212Enforcement::GracePeriod)
            .expect("note decrypts");
    let nk_arr: [u8; 32] = nk.as_slice().try_into().unwrap();
    let nk_point = jubjub::SubgroupPoint::from_bytes(&nk_arr).unwrap();
    let nf = note.nf(&NullifierDerivingKey(nk_point), 0);
    // Insert into nullifier backend before launching server.
    tron_chainbase::NullifierStore::new(nullifiers_be).put(&nf.0);

    let (addr, _shutdown, _server) = spawn_server(state).await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let resp = client
        .scan_and_mark_note_by_ivk(IvkDecryptAndMarkParameters {
            start_block_index: 1,
            end_block_index: 2,
            ivk: ivk.to_vec(),
            ak,
            nk,
        })
        .await
        .expect("rpc")
        .into_inner();
    assert_eq!(resp.note_txs.len(), 1);
    assert_eq!(resp.note_txs[0].is_spend, true);
}

#[tokio::test]
async fn scan_and_mark_rejects_when_no_nullifier_store() {
    let state = RpcState::new(mem(), mem(), mem(), mem(), mem(), 11_111);
    let (addr, _shutdown, _server) = spawn_server(state).await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let err = client
        .scan_and_mark_note_by_ivk(IvkDecryptAndMarkParameters {
            start_block_index: 0,
            end_block_index: 1,
            ivk: vec![0u8; 32],
            ak: vec![0u8; 32],
            nk: vec![0u8; 32],
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
}

// ============================================================
// scan_shielded_trc20_notes_by_ivk / by_ovk
// ============================================================

/// Build a single shielded-TRC-20 note event payload from a
/// pre-encrypted note.
fn trc20_event_data(rd: &ReceiveDescription, position: u64) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&position.to_be_bytes());
    out.extend_from_slice(&rd.epk);
    out.extend_from_slice(&rd.note_commitment);
    out.extend_from_slice(&rd.value_commitment); // cv (optional, present here)
    out.extend_from_slice(&rd.c_enc);
    out.extend_from_slice(&rd.c_out);
    out
}

fn put_trc20_event_tx(
    blocks_be: &Arc<dyn KvBackend>,
    block_index_be: &Arc<dyn KvBackend>,
    dp: &DynamicPropertiesStore,
    tx_history: &TransactionHistoryStore,
    block_num: i64,
    contract_addr_21: &[u8],
    event_data: Vec<u8>,
) -> [u8; 32] {
    // Build a transaction that's NOT a ShieldedTransferContract;
    // any tx type that produces logs is fine. We use a dummy
    // contract type but the scanner doesn't care about the tx body —
    // it consults TransactionInfo for logs.
    let raw = TxRaw {
        contract: vec![TxContract {
            r#type: ContractType::TriggerSmartContract as i32,
            parameter: None,
            ..Default::default()
        }],
        timestamp: 1_700_000_000_000 + block_num,
        ..Default::default()
    };
    let tx_id = tron_crypto::hash::sha256(&raw.encode_to_vec());
    let tx = Transaction {
        raw_data: Some(raw),
        signature: vec![],
        ret: vec![],
    };
    let block = Block {
        block_header: Some(BlockHeader {
            raw_data: Some(BlockHeaderRaw {
                number: block_num,
                parent_hash: vec![0u8; 32],
                timestamp: 1_700_000_000_000 + block_num,
                witness_address: vec![0x41u8; 21],
                ..Default::default()
            }),
            witness_signature: vec![],
        }),
        transactions: vec![tx],
    };
    let block_id = tron_types::block_id_from_block(&block).unwrap();
    BlockStore::new(blocks_be.clone()).put(&block_id, &block);
    BlockIndexStore::new(block_index_be.clone()).put(&block_id);
    dp.save_latest_block_header_number(block_num);
    dp.save_latest_block_header_hash(block_id.as_bytes());

    // Logs in TVM use 20-byte Ethereum-style addresses.
    let log_address = &contract_addr_21[1..]; // strip 0x41 prefix
    let info = TransactionInfo {
        id: tx_id.to_vec(),
        log: vec![TxInfoLog {
            address: log_address.to_vec(),
            topics: vec![],
            data: event_data,
        }],
        ..Default::default()
    };
    tx_history.put(&tx_id, &info);
    tx_id
}

#[tokio::test]
async fn scan_trc20_by_ivk_recovers_note_from_event() {
    let (_ovk, ivk, ak, nk, value, rd) = build_note_and_receive_desc(7777);
    let blocks_be = mem();
    let block_index_be = mem();
    let dp_be = mem();
    let tx_history_be = mem();
    let dp = DynamicPropertiesStore::new(dp_be.clone());
    let tx_history = TransactionHistoryStore::new(tx_history_be.clone());
    let mut contract_addr = [0u8; 21];
    contract_addr[0] = 0x41;
    contract_addr[1..].fill(0xc0);
    let event_data = trc20_event_data(&rd, 42);
    put_trc20_event_tx(
        &blocks_be,
        &block_index_be,
        &dp,
        &tx_history,
        1,
        &contract_addr,
        event_data,
    );
    let state = RpcState::new(mem(), blocks_be, block_index_be, mem(), dp_be, 11_111)
        .with_tx_history(tx_history_be);

    let (addr, _shutdown, _server) = spawn_server(state).await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let resp = client
        .scan_shielded_trc20_notes_by_ivk(IvkDecryptTrc20Parameters {
            start_block_index: 1,
            end_block_index: 2,
            shielded_trc20_contract_address: contract_addr.to_vec(),
            ivk: ivk.to_vec(),
            ak,
            nk,
            events: vec![],
        })
        .await
        .expect("rpc")
        .into_inner();
    assert_eq!(resp.note_txs.len(), 1);
    assert_eq!(resp.note_txs[0].position, 42);
    assert_eq!(resp.note_txs[0].note.as_ref().unwrap().value, value as i64);
}

#[tokio::test]
async fn scan_trc20_by_ivk_returns_empty_for_wrong_contract_address() {
    let (_ovk, ivk, ak, nk, _value, rd) = build_note_and_receive_desc(7777);
    let blocks_be = mem();
    let block_index_be = mem();
    let dp_be = mem();
    let tx_history_be = mem();
    let dp = DynamicPropertiesStore::new(dp_be.clone());
    let tx_history = TransactionHistoryStore::new(tx_history_be.clone());
    let mut contract_addr = [0u8; 21];
    contract_addr[0] = 0x41;
    contract_addr[1..].fill(0xc0);
    put_trc20_event_tx(
        &blocks_be,
        &block_index_be,
        &dp,
        &tx_history,
        1,
        &contract_addr,
        trc20_event_data(&rd, 0),
    );
    let state = RpcState::new(mem(), blocks_be, block_index_be, mem(), dp_be, 11_111)
        .with_tx_history(tx_history_be);
    let (addr, _shutdown, _server) = spawn_server(state).await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let mut wrong = [0u8; 21];
    wrong[0] = 0x41;
    wrong[1..].fill(0xee);
    let resp = client
        .scan_shielded_trc20_notes_by_ivk(IvkDecryptTrc20Parameters {
            start_block_index: 1,
            end_block_index: 2,
            shielded_trc20_contract_address: wrong.to_vec(),
            ivk: ivk.to_vec(),
            ak,
            nk,
            events: vec![],
        })
        .await
        .expect("rpc")
        .into_inner();
    assert!(resp.note_txs.is_empty());
}

#[tokio::test]
async fn scan_trc20_by_ovk_recovers_sender_owned_note() {
    let (ovk_bytes, _ivk, _ak, _nk, value, rd) = build_note_and_receive_desc(8888);
    let blocks_be = mem();
    let block_index_be = mem();
    let dp_be = mem();
    let tx_history_be = mem();
    let dp = DynamicPropertiesStore::new(dp_be.clone());
    let tx_history = TransactionHistoryStore::new(tx_history_be.clone());
    let mut contract_addr = [0u8; 21];
    contract_addr[0] = 0x41;
    contract_addr[1..].fill(0xcd);
    put_trc20_event_tx(
        &blocks_be,
        &block_index_be,
        &dp,
        &tx_history,
        1,
        &contract_addr,
        trc20_event_data(&rd, 7),
    );
    let state = RpcState::new(mem(), blocks_be, block_index_be, mem(), dp_be, 11_111)
        .with_tx_history(tx_history_be);
    let (addr, _shutdown, _server) = spawn_server(state).await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let resp = client
        .scan_shielded_trc20_notes_by_ovk(OvkDecryptTrc20Parameters {
            start_block_index: 1,
            end_block_index: 2,
            ovk: ovk_bytes.to_vec(),
            shielded_trc20_contract_address: contract_addr.to_vec(),
            events: vec![],
        })
        .await
        .expect("rpc")
        .into_inner();
    assert_eq!(resp.note_txs.len(), 1);
    assert_eq!(resp.note_txs[0].position, 7);
    assert_eq!(resp.note_txs[0].note.as_ref().unwrap().value, value as i64);
}

#[tokio::test]
async fn scan_trc20_by_ivk_rejects_bad_inputs() {
    let state = RpcState::new(mem(), mem(), mem(), mem(), mem(), 11_111);
    let (addr, _shutdown, _server) = spawn_server(state).await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    // Wrong contract address length.
    let err = client
        .scan_shielded_trc20_notes_by_ivk(IvkDecryptTrc20Parameters {
            start_block_index: 0,
            end_block_index: 1,
            shielded_trc20_contract_address: vec![0u8; 8],
            ivk: vec![0u8; 32],
            ak: vec![0u8; 32],
            nk: vec![0u8; 32],
            events: vec![],
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("21 bytes"));
}

#[tokio::test]
async fn scan_trc20_rejects_when_no_tx_history_store() {
    // No `with_tx_history(...)` → FailedPrecondition.
    let state = RpcState::new(mem(), mem(), mem(), mem(), mem(), 11_111);
    let (addr, _shutdown, _server) = spawn_server(state).await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let mut contract_addr = [0u8; 21];
    contract_addr[0] = 0x41;
    contract_addr[1..].fill(0xee);
    let err = client
        .scan_shielded_trc20_notes_by_ivk(IvkDecryptTrc20Parameters {
            start_block_index: 0,
            end_block_index: 1,
            shielded_trc20_contract_address: contract_addr.to_vec(),
            ivk: vec![0u8; 32],
            ak: vec![0u8; 32],
            nk: vec![0u8; 32],
            events: vec![],
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
}
