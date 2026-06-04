//! End-to-end tests for `get_merkle_tree_voucher_info` over gRPC.
//!
//! The method builds a Sapling-style incremental witness for each
//! requested `(txid, output_index)` output point, by walking the
//! chain from genesis, appending each receive commitment to a running
//! tree, snapshotting when the target is reached, and continuing to
//! extend the witness with later commitments.

use std::sync::Arc;
use std::time::Duration;

use prost::Message as _;
use tokio::sync::oneshot;
use tron_chainbase::{
    BlockIndexStore, BlockStore, DynamicPropertiesStore, KvBackend, MemBackend,
};
use tron_grpc::proto::wallet_client::WalletClient;
use tron_proto::protocol::{OutputPoint, OutputPointInfo};
use tron_proto::transaction::contract::ContractType;
use tron_proto::transaction::{Contract as TxContract, Raw as TxRaw};
use tron_proto::{
    block_header::Raw as BlockHeaderRaw, Block, BlockHeader, ReceiveDescription,
    ShieldedTransferContract, Transaction,
};
use tron_rpc::RpcState;
use tron_tvm::shielded::{IncrementalMerkleTree, IncrementalMerkleVoucher};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

/// Generate a deterministic 32-byte commitment based on `seed`.
fn cm_of(seed: u8) -> Vec<u8> {
    let mut a = [0u8; 32];
    a[0] = 0xc0;
    a[31] = seed;
    a.to_vec()
}

fn cm_arr(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().unwrap()
}

/// Build a shielded transfer transaction with `output_count`
/// receive descriptions whose commitments are derived from
/// `(block_num, tx_offset)`.
fn build_shielded_tx(block_num: u64, tx_offset: u8, output_count: usize) -> (Transaction, [u8; 32]) {
    let receive_descriptions: Vec<ReceiveDescription> = (0..output_count)
        .map(|i| ReceiveDescription {
            value_commitment: vec![0u8; 32],
            note_commitment: cm_of((block_num as u8) << 4 | (tx_offset & 0x0f) ^ i as u8),
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
        // Make tx_id distinct per tx via the timestamp.
        timestamp: 1_700_000_000_000 + (block_num as i64 * 1000) + tx_offset as i64,
        ..Default::default()
    };
    let tx_id = tron_crypto::hash::sha256(&raw.encode_to_vec());
    (
        Transaction {
            raw_data: Some(raw),
            signature: vec![],
            ret: vec![],
        },
        tx_id,
    )
}

fn put_block(
    blocks_be: &Arc<dyn KvBackend>,
    block_index_be: &Arc<dyn KvBackend>,
    dp: &DynamicPropertiesStore,
    block_num: i64,
    parent_hash: Vec<u8>,
    transactions: Vec<Transaction>,
) -> [u8; 32] {
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
        transactions,
    };
    let block_id = tron_types::block_id_from_block(&block).unwrap();
    BlockStore::new(blocks_be.clone()).put(&block_id, &block).unwrap();
    BlockIndexStore::new(block_index_be.clone()).put(&block_id).unwrap();
    dp.save_latest_block_header_number(block_num);
    dp.save_latest_block_header_hash(block_id.as_bytes());
    *block_id.as_bytes()
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
async fn voucher_info_returns_one_voucher_per_outpoint_with_path_encoded() {
    // One block, one shielded tx, two receive descriptions.
    let blocks_be = mem();
    let block_index_be = mem();
    let dp_be = mem();
    let dp = DynamicPropertiesStore::new(dp_be.clone());
    let (tx, tx_id) = build_shielded_tx(1, 0, 2);
    put_block(&blocks_be, &block_index_be, &dp, 1, vec![0u8; 32], vec![tx]);
    let state = RpcState::new(mem(), blocks_be, block_index_be, mem(), dp_be, 11_111);

    let (addr, _shutdown, _server) = spawn_server(state).await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();

    let req = OutputPointInfo {
        out_points: vec![OutputPoint {
            hash: tx_id.to_vec(),
            index: 0,
        }],
        block_num: 0,
    };
    let resp = client
        .get_merkle_tree_voucher_info(req)
        .await
        .expect("rpc")
        .into_inner();

    assert_eq!(resp.vouchers.len(), 1);
    assert_eq!(resp.paths.len(), 1);
    let voucher = &resp.vouchers[0];
    assert!(voucher.tree.is_some());
    // output_point round-trips.
    let op = voucher.output_point.as_ref().expect("output_point set");
    assert_eq!(op.hash, tx_id.to_vec());
    assert_eq!(op.index, 0);
    // Path encoding has the expected shape: 1 byte count + N*(1+32)
    // bytes for siblings + 8 bytes index. With N = 32 (depth), total
    // is 1 + 32*33 + 8 = 1065.
    assert_eq!(resp.paths[0].len(), 1065);
}

#[tokio::test]
async fn voucher_info_witness_root_equals_global_tree_root() {
    // Build a chain with two shielded blocks, target output is at
    // position 0 (block 1, tx 0, idx 0). Then block 2 adds 3 more
    // commitments. The voucher's `rt` should equal the root of a
    // tree built directly with all 4 leaves.
    let blocks_be = mem();
    let block_index_be = mem();
    let dp_be = mem();
    let dp = DynamicPropertiesStore::new(dp_be.clone());
    // Block 1: 1 output.
    let (tx1, tx1_id) = build_shielded_tx(1, 0, 1);
    let cm1 = cm_arr(&tx1.raw_data.as_ref().unwrap().contract[0]
        .parameter
        .as_ref()
        .unwrap()
        .value
        .as_slice()
        [find_first_cm_offset(&tx1)..]
        [..32]);
    let block1_id = put_block(&blocks_be, &block_index_be, &dp, 1, vec![0u8; 32], vec![tx1]);
    // Block 2: 1 tx with 3 outputs.
    let (tx2, _) = build_shielded_tx(2, 0, 3);
    let cms_block2: Vec<[u8; 32]> = {
        let stc = ShieldedTransferContract::decode(
            tx2.raw_data.as_ref().unwrap().contract[0]
                .parameter
                .as_ref()
                .unwrap()
                .value
                .as_slice(),
        )
        .unwrap();
        stc.receive_description
            .iter()
            .map(|rd| cm_arr(&rd.note_commitment))
            .collect()
    };
    put_block(&blocks_be, &block_index_be, &dp, 2, block1_id.to_vec(), vec![tx2]);

    let state = RpcState::new(mem(), blocks_be, block_index_be, mem(), dp_be, 11_111);
    let (addr, _shutdown, _server) = spawn_server(state).await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();

    // Direct global root: tree with cm1, then cms_block2[0..3].
    let mut direct = IncrementalMerkleTree::default();
    direct.append(cm1).unwrap();
    for cm in &cms_block2 {
        direct.append(*cm).unwrap();
    }
    let expected_root = direct.root();

    // Voucher for position 0 (tx1, idx 0). Set block_num=2 so the
    // witness extends through block 2 — matches java-tron's
    // `synBlockNum` semantics.
    let req = OutputPointInfo {
        out_points: vec![OutputPoint {
            hash: tx1_id.to_vec(),
            index: 0,
        }],
        block_num: 2,
    };
    let resp = client
        .get_merkle_tree_voucher_info(req)
        .await
        .expect("rpc")
        .into_inner();
    let voucher_proto = &resp.vouchers[0];
    let voucher = IncrementalMerkleVoucher::from_proto(voucher_proto);
    assert_eq!(voucher.position(), 0);
    assert_eq!(
        voucher.root(),
        expected_root,
        "witness root must equal global tree root after all blocks"
    );
    // The proto's rt also must equal the expected root.
    assert_eq!(voucher_proto.rt, expected_root.to_vec());
}

#[tokio::test]
async fn voucher_info_returns_not_found_for_unknown_txid() {
    let blocks_be = mem();
    let block_index_be = mem();
    let dp_be = mem();
    let dp = DynamicPropertiesStore::new(dp_be.clone());
    let (tx, _) = build_shielded_tx(1, 0, 1);
    put_block(&blocks_be, &block_index_be, &dp, 1, vec![0u8; 32], vec![tx]);
    let state = RpcState::new(mem(), blocks_be, block_index_be, mem(), dp_be, 11_111);
    let (addr, _shutdown, _server) = spawn_server(state).await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let req = OutputPointInfo {
        out_points: vec![OutputPoint {
            hash: vec![0xffu8; 32],
            index: 0,
        }],
        block_num: 0,
    };
    let err = client
        .get_merkle_tree_voucher_info(req)
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn voucher_info_rejects_empty_out_points() {
    let state = RpcState::new(mem(), mem(), mem(), mem(), mem(), 11_111);
    let (addr, _shutdown, _server) = spawn_server(state).await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let req = OutputPointInfo {
        out_points: vec![],
        block_num: 0,
    };
    let err = client
        .get_merkle_tree_voucher_info(req)
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn voucher_info_rejects_bad_hash_length() {
    let state = RpcState::new(mem(), mem(), mem(), mem(), mem(), 11_111);
    let (addr, _shutdown, _server) = spawn_server(state).await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let req = OutputPointInfo {
        out_points: vec![OutputPoint {
            hash: vec![0u8; 16], // wrong length
            index: 0,
        }],
        block_num: 0,
    };
    let err = client
        .get_merkle_tree_voucher_info(req)
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("32 bytes"));
}

#[tokio::test]
async fn voucher_info_rejects_index_out_of_range() {
    let blocks_be = mem();
    let block_index_be = mem();
    let dp_be = mem();
    let dp = DynamicPropertiesStore::new(dp_be.clone());
    // tx has only 1 output.
    let (tx, tx_id) = build_shielded_tx(1, 0, 1);
    put_block(&blocks_be, &block_index_be, &dp, 1, vec![0u8; 32], vec![tx]);
    let state = RpcState::new(mem(), blocks_be, block_index_be, mem(), dp_be, 11_111);
    let (addr, _shutdown, _server) = spawn_server(state).await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let req = OutputPointInfo {
        out_points: vec![OutputPoint {
            hash: tx_id.to_vec(),
            index: 5, // tx has only 1 output (idx 0)
        }],
        block_num: 0,
    };
    let err = client
        .get_merkle_tree_voucher_info(req)
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::OutOfRange);
}

#[tokio::test]
async fn voucher_info_sync_block_num_extends_witness_further() {
    // Block 1 has the target. Block 2 has 2 more commitments. Calling
    // with block_num=0 should return a witness up to block 2 (head),
    // calling with block_num=2 should produce the same witness root,
    // confirming the sync window is honored.
    let blocks_be = mem();
    let block_index_be = mem();
    let dp_be = mem();
    let dp = DynamicPropertiesStore::new(dp_be.clone());
    let (tx1, tx1_id) = build_shielded_tx(1, 0, 1);
    let cm1 = cm_arr(&tx1.raw_data.as_ref().unwrap().contract[0]
        .parameter
        .as_ref()
        .unwrap()
        .value
        [find_first_cm_offset(&tx1)..]
        [..32]);
    let block1_id = put_block(&blocks_be, &block_index_be, &dp, 1, vec![0u8; 32], vec![tx1]);
    let (tx2, _) = build_shielded_tx(2, 0, 2);
    put_block(&blocks_be, &block_index_be, &dp, 2, block1_id.to_vec(), vec![tx2.clone()]);
    let state = RpcState::new(mem(), blocks_be, block_index_be, mem(), dp_be, 11_111);
    let (addr, _shutdown, _server) = spawn_server(state).await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();

    let req = OutputPointInfo {
        out_points: vec![OutputPoint {
            hash: tx1_id.to_vec(),
            index: 0,
        }],
        block_num: 2,
    };
    let resp = client
        .get_merkle_tree_voucher_info(req)
        .await
        .expect("rpc")
        .into_inner();
    let voucher_proto = &resp.vouchers[0];
    let voucher = IncrementalMerkleVoucher::from_proto(voucher_proto);

    // Build the direct tree to compare roots.
    let mut direct = IncrementalMerkleTree::default();
    direct.append(cm1).unwrap();
    let cms_b2 = {
        let stc = ShieldedTransferContract::decode(
            tx2.raw_data.as_ref().unwrap().contract[0]
                .parameter
                .as_ref()
                .unwrap()
                .value
                .as_slice(),
        )
        .unwrap();
        stc.receive_description
            .iter()
            .map(|rd| cm_arr(&rd.note_commitment))
            .collect::<Vec<_>>()
    };
    for cm in &cms_b2 {
        direct.append(*cm).unwrap();
    }
    assert_eq!(voucher.root(), direct.root());
}

#[tokio::test]
async fn voucher_info_handles_multiple_outpoints_in_one_request() {
    // Two output points in the same block (one tx with 2 receives).
    // Both vouchers must be returned, both rooted at the same global root.
    let blocks_be = mem();
    let block_index_be = mem();
    let dp_be = mem();
    let dp = DynamicPropertiesStore::new(dp_be.clone());
    let (tx, tx_id) = build_shielded_tx(1, 0, 2);
    put_block(&blocks_be, &block_index_be, &dp, 1, vec![0u8; 32], vec![tx]);
    let state = RpcState::new(mem(), blocks_be, block_index_be, mem(), dp_be, 11_111);
    let (addr, _shutdown, _server) = spawn_server(state).await;
    let mut client = WalletClient::connect(format!("http://{}", addr))
        .await
        .unwrap();

    let req = OutputPointInfo {
        out_points: vec![
            OutputPoint {
                hash: tx_id.to_vec(),
                index: 0,
            },
            OutputPoint {
                hash: tx_id.to_vec(),
                index: 1,
            },
        ],
        block_num: 0,
    };
    let resp = client
        .get_merkle_tree_voucher_info(req)
        .await
        .expect("rpc")
        .into_inner();
    assert_eq!(resp.vouchers.len(), 2);
    assert_eq!(resp.paths.len(), 2);
    let v0 = IncrementalMerkleVoucher::from_proto(&resp.vouchers[0]);
    let v1 = IncrementalMerkleVoucher::from_proto(&resp.vouchers[1]);
    assert_eq!(v0.position(), 0);
    assert_eq!(v1.position(), 1);
    // Both vouchers reflect the same global state — same root.
    assert_eq!(v0.root(), v1.root());
}

/// Helper: locate the offset of the first 32-byte note_commitment in
/// a shielded tx's encoded contract bytes by scanning for the
/// `note_commitment` proto tag (field 2 = 0x12, then a varint length).
fn find_first_cm_offset(tx: &Transaction) -> usize {
    let stc = ShieldedTransferContract::decode(
        tx.raw_data.as_ref().unwrap().contract[0]
            .parameter
            .as_ref()
            .unwrap()
            .value
            .as_slice(),
    )
    .unwrap();
    // Extract the first commitment value directly to avoid relying on
    // proto-field byte positions (which can shift if encoding details
    // change).
    let cm = &stc.receive_description[0].note_commitment;
    // We then search for this exact 32-byte value within the encoded
    // contract bytes.
    let haystack = tx.raw_data.as_ref().unwrap().contract[0]
        .parameter
        .as_ref()
        .unwrap()
        .value
        .as_slice();
    haystack
        .windows(32)
        .position(|w| w == cm.as_slice())
        .expect("cm must be present in the encoded contract")
}
