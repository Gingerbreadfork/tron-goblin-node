//! End-to-end tests for `is_spend` over gRPC.
//!
//! `is_spend` answers: "given a note and the on-chain output point
//! `(txid, index)` it sits at, has it been spent?" The algorithm
//! locates the output's leaf position by walking the chain, derives
//! the Sapling nullifier under `(note, nk, position)`, and checks the
//! `NullifierStore`. We exercise all three outcomes:
//!   * "does not exist" → output point isn't in chain history
//!   * "not spent"      → output exists but nullifier isn't recorded
//!   * "spent"          → output exists AND nullifier is in the store

use std::sync::Arc;
use std::time::Duration;

use prost::Message as _;
use tokio::sync::oneshot;
use tron_chainbase::{
    BlockIndexStore, BlockStore, DynamicPropertiesStore, KvBackend, MemBackend,
};
use tron_grpc::proto::wallet_client::WalletClient;
use tron_proto::protocol::{NoteParameters, Note};
use tron_proto::transaction::contract::ContractType;
use tron_proto::transaction::{Contract as TxContract, Raw as TxRaw};
use tron_proto::{
    block_header::Raw as BlockHeaderRaw, Block, BlockHeader, ReceiveDescription,
    ShieldedTransferContract, Transaction,
};
use tron_rpc::RpcState;

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

/// Build a Sapling Note + matching `(nk_bytes, payment_address_hex,
/// rcm_bytes, value)` and the resulting nullifier at the given
/// position. Lets the test reuse the same derivation the gRPC
/// implementation runs.
fn build_test_note_and_nullifier(
    value: u64,
    position: u64,
) -> (
    /* payment_address_hex */ String,
    /* rcm_bytes */ Vec<u8>,
    /* nk_bytes */ Vec<u8>,
    /* ak_bytes (unused) */ Vec<u8>,
    /* expected_nullifier */ [u8; 32],
) {
    use group::{Group, GroupEncoding};
    use sapling_crypto::keys::{NullifierDerivingKey, SaplingIvk};
    use sapling_crypto::note::Rseed;
    use sapling_crypto::value::NoteValue;
    use sapling_crypto::{Diversifier, Note as SaplingNote};

    let ivk_scalar = jubjub::Fr::from(0x12345678u64);
    let ivk = SaplingIvk(ivk_scalar);
    let mut d_bytes = [0u8; 11];
    let mut payment_address = None;
    for i in 0..=255u8 {
        d_bytes[0] = i;
        if let Some(pa) = ivk.to_payment_address(Diversifier(d_bytes)) {
            payment_address = Some(pa);
            break;
        }
    }
    let pa = payment_address.unwrap();
    let pa_hex = hex::encode(pa.to_bytes());

    // nk = arbitrary subgroup point.
    let nk_point = jubjub::SubgroupPoint::generator() * jubjub::Fr::from(11u64);
    let nk_bytes = nk_point.to_bytes().to_vec();
    let nk = NullifierDerivingKey(nk_point);

    let rcm_scalar = jubjub::Fr::from(99u64);
    let rcm_bytes = rcm_scalar.to_bytes().to_vec();

    let note = SaplingNote::from_parts(
        pa,
        NoteValue::from_raw(value),
        Rseed::BeforeZip212(rcm_scalar),
    );
    let nf = note.nf(&nk, position);
    (pa_hex, rcm_bytes, nk_bytes, vec![0u8; 32], nf.0)
}

/// Build a state with a single block at height 1 containing one
/// ShieldedTransferContract with `output_count` receive descriptions.
/// Returns the resulting (state, tx_id) so tests can address output
/// points within it.
fn build_state_with_n_outputs(output_count: usize) -> (RpcState, [u8; 32]) {
    let receive_descriptions: Vec<ReceiveDescription> = (0..output_count)
        .map(|i| ReceiveDescription {
            value_commitment: vec![0u8; 32],
            note_commitment: {
                let mut cm = vec![0u8; 32];
                cm[0] = 0xa0 + i as u8;
                cm
            },
            epk: vec![0u8; 32],
            c_enc: vec![0u8; 580],
            c_out: vec![0u8; 80],
            zkproof: vec![0u8; 192],
        })
        .collect();
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
        timestamp: 1_700_000_000_000,
        ..Default::default()
    };
    let tx_id = tron_crypto::hash::sha256(&raw.encode_to_vec());
    let tx = Transaction {
        raw_data: Some(raw),
        signature: vec![],
        ret: vec![],
        unparsed_field10: None,
    };
    let block = Block {
        block_header: Some(BlockHeader {
            raw_data: Some(BlockHeaderRaw {
                number: 1,
                parent_hash: vec![0u8; 32],
                timestamp: 1_700_000_000_000,
                witness_address: vec![0x41u8; 21],
                ..Default::default()
            }),
            witness_signature: vec![],
        }),
        transactions: vec![tx],
    };
    let block_id = tron_types::block_id_from_block(&block).unwrap();

    let blocks_be = mem();
    let block_index_be = mem();
    let dp_be = mem();
    let nullifiers_be = mem();
    BlockStore::new(blocks_be.clone()).put(&block_id, &block).unwrap();
    BlockIndexStore::new(block_index_be.clone()).put(&block_id).unwrap();
    let dp = DynamicPropertiesStore::new(dp_be.clone());
    dp.save_latest_block_header_number(1);
    dp.save_latest_block_header_hash(block_id.as_bytes());

    let state = RpcState::new(mem(), blocks_be, block_index_be, mem(), dp_be, 11_111)
        .with_nullifiers(nullifiers_be);
    (state, tx_id)
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

#[tokio::test]
async fn is_spend_reports_does_not_exist_for_unknown_txid() {
    let (state, _real_tx_id) = build_state_with_n_outputs(1);
    let (addr, _shutdown, _server) = spawn_server(state).await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let (pa, rcm, nk, ak, _) = build_test_note_and_nullifier(1234, 0);
    let params = NoteParameters {
        ak,
        nk,
        note: Some(Note {
            value: 1234,
            payment_address: pa,
            rcm,
            memo: Vec::new(),
        }),
        txid: vec![0xffu8; 32], // not in chain
        index: 0,
    };
    let resp = client
        .is_spend(params)
        .await
        .expect("rpc")
        .into_inner();
    assert_eq!(resp.result, false);
    assert!(
        resp.message.contains("does not exist"),
        "got: {}",
        resp.message
    );
}

#[tokio::test]
async fn is_spend_reports_not_spent_when_nullifier_absent_from_store() {
    let (state, tx_id) = build_state_with_n_outputs(1);
    let (addr, _shutdown, _server) = spawn_server(state).await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let (pa, rcm, nk, ak, _expected_nf) = build_test_note_and_nullifier(1234, 0);
    let params = NoteParameters {
        ak,
        nk,
        note: Some(Note {
            value: 1234,
            payment_address: pa,
            rcm,
            memo: Vec::new(),
        }),
        txid: tx_id.to_vec(),
        index: 0,
    };
    let resp = client.is_spend(params).await.expect("rpc").into_inner();
    assert_eq!(resp.result, false);
    assert!(
        resp.message.contains("not spent"),
        "got: {}",
        resp.message
    );
}

#[tokio::test]
async fn is_spend_reports_spent_when_nullifier_in_store() {
    let (state, tx_id) = build_state_with_n_outputs(2);
    // Pre-derive the expected nullifier and pre-insert it.
    let (pa, rcm, nk, ak, expected_nf) = build_test_note_and_nullifier(1234, 1);
    // Insert via the nullifier backend on the state directly. Borrow
    // the underlying backend via RpcState's nullifiers Arc, write the
    // nullifier, and re-use the *same state* (since the Arc shares the
    // backend across clones).
    let nullifiers = state.nullifiers.clone().expect("nullifiers attached");
    nullifiers.put(&expected_nf).unwrap();

    let (addr, _shutdown, _server) = spawn_server(state).await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let params = NoteParameters {
        ak,
        nk,
        note: Some(Note {
            value: 1234,
            payment_address: pa,
            rcm,
            memo: Vec::new(),
        }),
        txid: tx_id.to_vec(),
        index: 1, // second output → position 1
    };
    let resp = client.is_spend(params).await.expect("rpc").into_inner();
    assert_eq!(resp.result, true, "expected spent, got: {}", resp.message);
    assert!(
        resp.message.contains("has been spent"),
        "got: {}",
        resp.message
    );
}

#[tokio::test]
async fn is_spend_rejects_bad_txid_length() {
    let (state, _) = build_state_with_n_outputs(1);
    let (addr, _shutdown, _server) = spawn_server(state).await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let (pa, rcm, nk, ak, _) = build_test_note_and_nullifier(1, 0);
    let params = NoteParameters {
        ak,
        nk,
        note: Some(Note {
            value: 1,
            payment_address: pa,
            rcm,
            memo: Vec::new(),
        }),
        txid: vec![0u8; 16],
        index: 0,
    };
    let err = client.is_spend(params).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("txid"));
}

#[tokio::test]
async fn is_spend_rejects_negative_index() {
    let (state, tx_id) = build_state_with_n_outputs(1);
    let (addr, _shutdown, _server) = spawn_server(state).await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let (pa, rcm, nk, ak, _) = build_test_note_and_nullifier(1, 0);
    let params = NoteParameters {
        ak,
        nk,
        note: Some(Note {
            value: 1,
            payment_address: pa,
            rcm,
            memo: Vec::new(),
        }),
        txid: tx_id.to_vec(),
        index: -1,
    };
    let err = client.is_spend(params).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn is_spend_rejects_missing_note() {
    let (state, tx_id) = build_state_with_n_outputs(1);
    let (addr, _shutdown, _server) = spawn_server(state).await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let params = NoteParameters {
        ak: vec![0u8; 32],
        nk: vec![0u8; 32],
        note: None,
        txid: tx_id.to_vec(),
        index: 0,
    };
    let err = client.is_spend(params).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("missing note"));
}

#[tokio::test]
async fn is_spend_reports_failed_precondition_when_no_nullifier_store() {
    // Build a state WITHOUT calling with_nullifiers — emulates a
    // node configured to not maintain the shielded subsystem.
    let blocks_be = mem();
    let block_index_be = mem();
    let dp_be = mem();
    let state =
        RpcState::new(mem(), blocks_be, block_index_be, mem(), dp_be, 11_111);
    let (addr, _shutdown, _server) = spawn_server(state).await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let (pa, rcm, nk, ak, _) = build_test_note_and_nullifier(1, 0);
    let params = NoteParameters {
        ak,
        nk,
        note: Some(Note {
            value: 1,
            payment_address: pa,
            rcm,
            memo: Vec::new(),
        }),
        txid: vec![0u8; 32],
        index: 0,
    };
    let err = client.is_spend(params).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(err.message().contains("NullifierStore"));
}
